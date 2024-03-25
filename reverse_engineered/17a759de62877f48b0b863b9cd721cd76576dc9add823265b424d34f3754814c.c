typedef unsigned char   undefined;

typedef unsigned long long    GUID;
typedef pointer32 ImageBaseOffset32;

typedef unsigned char    bool;
typedef unsigned char    byte;
typedef unsigned int    dword;
typedef unsigned char    uchar;
typedef unsigned int    uint;
typedef unsigned long    ulong;
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

typedef struct tagMENUITEMINFOW tagMENUITEMINFOW, *PtagMENUITEMINFOW;

typedef struct tagMENUITEMINFOW *LPMENUITEMINFOW;

typedef uint UINT;

typedef struct HMENU__ HMENU__, *PHMENU__;

typedef struct HMENU__ *HMENU;

typedef struct HBITMAP__ HBITMAP__, *PHBITMAP__;

typedef struct HBITMAP__ *HBITMAP;

typedef ulong ULONG_PTR;

typedef wchar_t WCHAR;

typedef WCHAR *LPWSTR;

struct HMENU__ {
    int unused;
};

struct HBITMAP__ {
    int unused;
};

struct tagMENUITEMINFOW {
    UINT cbSize;
    UINT fMask;
    UINT fType;
    UINT fState;
    UINT wID;
    HMENU hSubMenu;
    HBITMAP hbmpChecked;
    HBITMAP hbmpUnchecked;
    ULONG_PTR dwItemData;
    LPWSTR dwTypeData;
    UINT cch;
    HBITMAP hbmpItem;
};

typedef struct tagMSGBOXPARAMSW tagMSGBOXPARAMSW, *PtagMSGBOXPARAMSW;

typedef struct tagMSGBOXPARAMSW MSGBOXPARAMSW;

typedef struct HWND__ HWND__, *PHWND__;

typedef struct HWND__ *HWND;

typedef struct HINSTANCE__ HINSTANCE__, *PHINSTANCE__;

typedef struct HINSTANCE__ *HINSTANCE;

typedef WCHAR *LPCWSTR;

typedef ulong DWORD;

typedef ULONG_PTR DWORD_PTR;

typedef struct tagHELPINFO tagHELPINFO, *PtagHELPINFO;

typedef struct tagHELPINFO *LPHELPINFO;

typedef void (*MSGBOXCALLBACK)(LPHELPINFO);

typedef void *HANDLE;

typedef struct tagPOINT tagPOINT, *PtagPOINT;

typedef struct tagPOINT POINT;

typedef long LONG;

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

struct HWND__ {
    int unused;
};

typedef struct tagMSG tagMSG, *PtagMSG;

typedef struct tagMSG *LPMSG;

typedef uint UINT_PTR;

typedef UINT_PTR WPARAM;

typedef long LONG_PTR;

typedef LONG_PTR LPARAM;

struct tagMSG {
    HWND hwnd;
    UINT message;
    WPARAM wParam;
    LPARAM lParam;
    DWORD time;
    POINT pt;
};

typedef void MENUTEMPLATEA;

typedef struct tagACCEL tagACCEL, *PtagACCEL;

typedef uchar BYTE;

typedef ushort WORD;

struct tagACCEL {
    BYTE fVirt;
    WORD key;
    WORD cmd;
};

typedef struct DLGTEMPLATE DLGTEMPLATE, *PDLGTEMPLATE;

struct DLGTEMPLATE {
    DWORD style;
    DWORD dwExtendedStyle;
    WORD cdit;
    short x;
    short y;
    short cx;
    short cy;
};

typedef int INT_PTR;

typedef INT_PTR (*DLGPROC)(HWND, UINT, WPARAM, LPARAM);

typedef struct tagACCEL *LPACCEL;

typedef struct DLGTEMPLATE *LPCDLGTEMPLATEW;

typedef struct _GUID _GUID, *P_GUID;

struct _GUID {
    ulong Data1;
    ushort Data2;
    ushort Data3;
    uchar Data4[8];
};


// WARNING! conflicting data type names: /guiddef.h/GUID - /GUID

typedef GUID IID;

typedef GUID CLSID;

typedef DWORD CALID;

typedef DWORD CALTYPE;

typedef struct tagPALETTEENTRY tagPALETTEENTRY, *PtagPALETTEENTRY;

typedef struct tagPALETTEENTRY PALETTEENTRY;

struct tagPALETTEENTRY {
    BYTE peRed;
    BYTE peGreen;
    BYTE peBlue;
    BYTE peFlags;
};

typedef struct tagCHARSETINFO tagCHARSETINFO, *PtagCHARSETINFO;

typedef struct tagCHARSETINFO *LPCHARSETINFO;

typedef struct tagFONTSIGNATURE tagFONTSIGNATURE, *PtagFONTSIGNATURE;

typedef struct tagFONTSIGNATURE FONTSIGNATURE;

struct tagFONTSIGNATURE {
    DWORD fsUsb[4];
    DWORD fsCsb[2];
};

struct tagCHARSETINFO {
    UINT ciCharset;
    UINT ciACP;
    FONTSIGNATURE fs;
};

typedef struct _devicemodeW _devicemodeW, *P_devicemodeW;

typedef union _union_660 _union_660, *P_union_660;

typedef union _union_663 _union_663, *P_union_663;

typedef struct _struct_661 _struct_661, *P_struct_661;

typedef struct _struct_662 _struct_662, *P_struct_662;

typedef struct _POINTL _POINTL, *P_POINTL;

typedef struct _POINTL POINTL;

struct _POINTL {
    LONG x;
    LONG y;
};

union _union_663 {
    DWORD dmDisplayFlags;
    DWORD dmNup;
};

struct _struct_662 {
    POINTL dmPosition;
    DWORD dmDisplayOrientation;
    DWORD dmDisplayFixedOutput;
};

struct _struct_661 {
    short dmOrientation;
    short dmPaperSize;
    short dmPaperLength;
    short dmPaperWidth;
    short dmScale;
    short dmCopies;
    short dmDefaultSource;
    short dmPrintQuality;
};

union _union_660 {
    struct _struct_661 field0;
    struct _struct_662 field1;
};

struct _devicemodeW {
    WCHAR dmDeviceName[32];
    WORD dmSpecVersion;
    WORD dmDriverVersion;
    WORD dmSize;
    WORD dmDriverExtra;
    DWORD dmFields;
    union _union_660 field6_0x4c;
    short dmColor;
    short dmDuplex;
    short dmYResolution;
    short dmTTOption;
    short dmCollate;
    WCHAR dmFormName[32];
    WORD dmLogPixels;
    DWORD dmBitsPerPel;
    DWORD dmPelsWidth;
    DWORD dmPelsHeight;
    union _union_663 field17_0xb4;
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

typedef struct _devicemodeW DEVMODEW;

typedef struct tagENHMETAHEADER tagENHMETAHEADER, *PtagENHMETAHEADER;

typedef struct _RECTL _RECTL, *P_RECTL;

typedef struct _RECTL RECTL;

typedef struct tagSIZE tagSIZE, *PtagSIZE;

typedef struct tagSIZE SIZE;

typedef SIZE SIZEL;

struct tagSIZE {
    LONG cx;
    LONG cy;
};

struct _RECTL {
    LONG left;
    LONG top;
    LONG right;
    LONG bottom;
};

struct tagENHMETAHEADER {
    DWORD iType;
    DWORD nSize;
    RECTL rclBounds;
    RECTL rclFrame;
    DWORD dSignature;
    DWORD nVersion;
    DWORD nBytes;
    DWORD nRecords;
    WORD nHandles;
    WORD sReserved;
    DWORD nDescription;
    DWORD offDescription;
    DWORD nPalEntries;
    SIZEL szlDevice;
    SIZEL szlMillimeters;
    DWORD cbPixelFormat;
    DWORD offPixelFormat;
    DWORD bOpenGL;
    SIZEL szlMicrometers;
};

typedef void *LPVOID;

typedef int (*GOBJENUMPROC)(LPVOID, LPARAM);

typedef struct tagENHMETAHEADER *LPENHMETAHEADER;

typedef struct _SECURITY_ATTRIBUTES _SECURITY_ATTRIBUTES, *P_SECURITY_ATTRIBUTES;

typedef int BOOL;

struct _SECURITY_ATTRIBUTES {
    DWORD nLength;
    LPVOID lpSecurityDescriptor;
    BOOL bInheritHandle;
};

typedef struct _SECURITY_ATTRIBUTES SECURITY_ATTRIBUTES;

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

typedef struct _EXCEPTION_POINTERS _EXCEPTION_POINTERS, *P_EXCEPTION_POINTERS;

typedef LONG (*PTOP_LEVEL_EXCEPTION_FILTER)(struct _EXCEPTION_POINTERS *);

typedef struct _EXCEPTION_RECORD _EXCEPTION_RECORD, *P_EXCEPTION_RECORD;

typedef struct _EXCEPTION_RECORD EXCEPTION_RECORD;

typedef EXCEPTION_RECORD *PEXCEPTION_RECORD;

typedef struct _CONTEXT _CONTEXT, *P_CONTEXT;

typedef struct _CONTEXT CONTEXT;

typedef CONTEXT *PCONTEXT;

typedef void *PVOID;

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

typedef union _ULARGE_INTEGER _ULARGE_INTEGER, *P_ULARGE_INTEGER;

typedef union _ULARGE_INTEGER ULARGE_INTEGER;

typedef struct _struct_22 _struct_22, *P_struct_22;

typedef struct _struct_23 _struct_23, *P_struct_23;

typedef double ULONGLONG;

struct _struct_23 {
    DWORD LowPart;
    DWORD HighPart;
};

struct _struct_22 {
    DWORD LowPart;
    DWORD HighPart;
};

union _ULARGE_INTEGER {
    struct _struct_22 s;
    struct _struct_23 u;
    ULONGLONG QuadPart;
};

typedef char CHAR;

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

typedef CHAR *LPSTR;

typedef long HRESULT;

typedef CHAR *LPCSTR;

typedef struct _OSVERSIONINFOA _OSVERSIONINFOA, *P_OSVERSIONINFOA;

struct _OSVERSIONINFOA {
    DWORD dwOSVersionInfoSize;
    DWORD dwMajorVersion;
    DWORD dwMinorVersion;
    DWORD dwBuildNumber;
    DWORD dwPlatformId;
    CHAR szCSDVersion[128];
};

typedef union _LARGE_INTEGER LARGE_INTEGER;

typedef struct _OSVERSIONINFOA *LPOSVERSIONINFOA;

typedef short SHORT;

typedef DWORD ACCESS_MASK;

typedef DWORD LCID;

typedef CHAR *PCNZCH;

typedef struct IBindCtx IBindCtx, *PIBindCtx;

typedef struct IBindCtxVtbl IBindCtxVtbl, *PIBindCtxVtbl;

typedef DWORD ULONG;

typedef struct IUnknown IUnknown, *PIUnknown;

typedef struct tagBIND_OPTS tagBIND_OPTS, *PtagBIND_OPTS;

typedef struct tagBIND_OPTS BIND_OPTS;

typedef struct IRunningObjectTable IRunningObjectTable, *PIRunningObjectTable;

typedef WCHAR OLECHAR;

typedef OLECHAR *LPOLESTR;

typedef struct IEnumString IEnumString, *PIEnumString;

typedef struct IUnknownVtbl IUnknownVtbl, *PIUnknownVtbl;

typedef struct IRunningObjectTableVtbl IRunningObjectTableVtbl, *PIRunningObjectTableVtbl;

typedef struct IMoniker IMoniker, *PIMoniker;

typedef struct _FILETIME _FILETIME, *P_FILETIME;

typedef struct _FILETIME FILETIME;

typedef struct IEnumMoniker IEnumMoniker, *PIEnumMoniker;

typedef struct IEnumStringVtbl IEnumStringVtbl, *PIEnumStringVtbl;

typedef struct IMonikerVtbl IMonikerVtbl, *PIMonikerVtbl;

typedef struct IStream IStream, *PIStream;

typedef struct IEnumMonikerVtbl IEnumMonikerVtbl, *PIEnumMonikerVtbl;

typedef struct IStreamVtbl IStreamVtbl, *PIStreamVtbl;

typedef struct tagSTATSTG tagSTATSTG, *PtagSTATSTG;

typedef struct tagSTATSTG STATSTG;

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

struct _FILETIME {
    DWORD dwLowDateTime;
    DWORD dwHighDateTime;
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

struct IMoniker {
    struct IMonikerVtbl *lpVtbl;
};

struct IEnumString {
    struct IEnumStringVtbl *lpVtbl;
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

struct tagBIND_OPTS {
    DWORD cbStruct;
    DWORD grfFlags;
    DWORD grfMode;
    DWORD dwTickCountDeadline;
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

struct IEnumMoniker {
    struct IEnumMonikerVtbl *lpVtbl;
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

typedef union _union_2260 _union_2260, *P_union_2260;

typedef void *HMETAFILEPICT;

typedef struct HENHMETAFILE__ HENHMETAFILE__, *PHENHMETAFILE__;

typedef struct HENHMETAFILE__ *HENHMETAFILE;

typedef HANDLE HGLOBAL;

typedef struct IStorage IStorage, *PIStorage;

typedef struct IStorageVtbl IStorageVtbl, *PIStorageVtbl;

typedef LPOLESTR *SNB;

typedef struct IEnumSTATSTG IEnumSTATSTG, *PIEnumSTATSTG;

typedef struct IEnumSTATSTGVtbl IEnumSTATSTGVtbl, *PIEnumSTATSTGVtbl;

union _union_2260 {
    HBITMAP hBitmap;
    HMETAFILEPICT hMetaFilePict;
    HENHMETAFILE hEnhMetaFile;
    HGLOBAL hGlobal;
    LPOLESTR lpszFileName;
    struct IStream *pstm;
    struct IStorage *pstg;
};

struct IStorageVtbl {
    HRESULT (*QueryInterface)(struct IStorage *, IID *, void **);
    ULONG (*AddRef)(struct IStorage *);
    ULONG (*Release)(struct IStorage *);
    HRESULT (*CreateStream)(struct IStorage *, OLECHAR *, DWORD, DWORD, DWORD, struct IStream **);
    HRESULT (*OpenStream)(struct IStorage *, OLECHAR *, void *, DWORD, DWORD, struct IStream **);
    HRESULT (*CreateStorage)(struct IStorage *, OLECHAR *, DWORD, DWORD, DWORD, struct IStorage **);
    HRESULT (*OpenStorage)(struct IStorage *, OLECHAR *, struct IStorage *, DWORD, SNB, DWORD, struct IStorage **);
    HRESULT (*CopyTo)(struct IStorage *, DWORD, IID *, SNB, struct IStorage *);
    HRESULT (*MoveElementTo)(struct IStorage *, OLECHAR *, struct IStorage *, OLECHAR *, DWORD);
    HRESULT (*Commit)(struct IStorage *, DWORD);
    HRESULT (*Revert)(struct IStorage *);
    HRESULT (*EnumElements)(struct IStorage *, DWORD, void *, DWORD, struct IEnumSTATSTG **);
    HRESULT (*DestroyElement)(struct IStorage *, OLECHAR *);
    HRESULT (*RenameElement)(struct IStorage *, OLECHAR *, OLECHAR *);
    HRESULT (*SetElementTimes)(struct IStorage *, OLECHAR *, FILETIME *, FILETIME *, FILETIME *);
    HRESULT (*SetClass)(struct IStorage *, IID *);
    HRESULT (*SetStateBits)(struct IStorage *, DWORD, DWORD);
    HRESULT (*Stat)(struct IStorage *, STATSTG *, DWORD);
};

struct IStorage {
    struct IStorageVtbl *lpVtbl;
};

struct IEnumSTATSTGVtbl {
    HRESULT (*QueryInterface)(struct IEnumSTATSTG *, IID *, void **);
    ULONG (*AddRef)(struct IEnumSTATSTG *);
    ULONG (*Release)(struct IEnumSTATSTG *);
    HRESULT (*Next)(struct IEnumSTATSTG *, ULONG, STATSTG *, ULONG *);
    HRESULT (*Skip)(struct IEnumSTATSTG *, ULONG);
    HRESULT (*Reset)(struct IEnumSTATSTG *);
    HRESULT (*Clone)(struct IEnumSTATSTG *, struct IEnumSTATSTG **);
};

struct IEnumSTATSTG {
    struct IEnumSTATSTGVtbl *lpVtbl;
};

struct HENHMETAFILE__ {
    int unused;
};

typedef struct tagFORMATETC tagFORMATETC, *PtagFORMATETC;

typedef WORD CLIPFORMAT;

typedef struct tagDVTARGETDEVICE tagDVTARGETDEVICE, *PtagDVTARGETDEVICE;

typedef struct tagDVTARGETDEVICE DVTARGETDEVICE;

struct tagFORMATETC {
    CLIPFORMAT cfFormat;
    DVTARGETDEVICE *ptd;
    DWORD dwAspect;
    LONG lindex;
    DWORD tymed;
};

struct tagDVTARGETDEVICE {
    DWORD tdSize;
    WORD tdDriverNameOffset;
    WORD tdDeviceNameOffset;
    WORD tdPortNameOffset;
    WORD tdExtDevmodeOffset;
    BYTE tdData[1];
};

typedef struct IEnumFORMATETCVtbl IEnumFORMATETCVtbl, *PIEnumFORMATETCVtbl;

typedef struct IEnumFORMATETC IEnumFORMATETC, *PIEnumFORMATETC;

typedef struct tagFORMATETC FORMATETC;

struct IEnumFORMATETC {
    struct IEnumFORMATETCVtbl *lpVtbl;
};

struct IEnumFORMATETCVtbl {
    HRESULT (*QueryInterface)(struct IEnumFORMATETC *, IID *, void **);
    ULONG (*AddRef)(struct IEnumFORMATETC *);
    ULONG (*Release)(struct IEnumFORMATETC *);
    HRESULT (*Next)(struct IEnumFORMATETC *, ULONG, FORMATETC *, ULONG *);
    HRESULT (*Skip)(struct IEnumFORMATETC *, ULONG);
    HRESULT (*Reset)(struct IEnumFORMATETC *);
    HRESULT (*Clone)(struct IEnumFORMATETC *, struct IEnumFORMATETC **);
};

typedef struct tagSTGMEDIUM tagSTGMEDIUM, *PtagSTGMEDIUM;

typedef struct tagSTGMEDIUM uSTGMEDIUM;

typedef uSTGMEDIUM STGMEDIUM;

struct tagSTGMEDIUM {
    DWORD tymed;
    union _union_2260 u;
    struct IUnknown *pUnkForRelease;
};

typedef struct IBindCtx *LPBC;

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

typedef OLECHAR *BSTR;

typedef struct IDispatch IDispatch, *PIDispatch;

typedef struct tagSAFEARRAY tagSAFEARRAY, *PtagSAFEARRAY;

typedef struct tagSAFEARRAY SAFEARRAY;

typedef int INT;

typedef struct __tagBRECORD __tagBRECORD, *P__tagBRECORD;

typedef struct _struct_1696 _struct_1696, *P_struct_1696;

typedef struct _struct_1698 _struct_1698, *P_struct_1698;

typedef struct _struct_1693 _struct_1693, *P_struct_1693;

typedef struct IDispatchVtbl IDispatchVtbl, *PIDispatchVtbl;

typedef struct ITypeInfo ITypeInfo, *PITypeInfo;

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

struct IDispatchVtbl {
    HRESULT (*QueryInterface)(struct IDispatch *, IID *, void **);
    ULONG (*AddRef)(struct IDispatch *);
    ULONG (*Release)(struct IDispatch *);
    HRESULT (*GetTypeInfoCount)(struct IDispatch *, UINT *);
    HRESULT (*GetTypeInfo)(struct IDispatch *, UINT, LCID, struct ITypeInfo **);
    HRESULT (*GetIDsOfNames)(struct IDispatch *, IID *, LPOLESTR *, UINT, LCID, DISPID *);
    HRESULT (*Invoke)(struct IDispatch *, DISPID, IID *, LCID, WORD, DISPPARAMS *, VARIANT *, EXCEPINFO *, UINT *);
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

typedef ULONG_PTR SIZE_T;

typedef struct HKL__ HKL__, *PHKL__;

struct HKL__ {
    int unused;
};

typedef struct HKEY__ HKEY__, *PHKEY__;

struct HKEY__ {
    int unused;
};

typedef struct HACCEL__ HACCEL__, *PHACCEL__;

typedef struct HACCEL__ *HACCEL;

struct HACCEL__ {
    int unused;
};

typedef struct tagRECT tagRECT, *PtagRECT;

typedef struct tagRECT RECT;

typedef RECT *LPCRECT;

struct tagRECT {
    LONG left;
    LONG top;
    LONG right;
    LONG bottom;
};

typedef struct HMONITOR__ HMONITOR__, *PHMONITOR__;

typedef struct HMONITOR__ *HMONITOR;

struct HMONITOR__ {
    int unused;
};

typedef uint *PUINT;

typedef struct HPALETTE__ HPALETTE__, *PHPALETTE__;

struct HPALETTE__ {
    int unused;
};

typedef HINSTANCE HMODULE;

typedef HANDLE HLOCAL;

typedef struct HDESK__ HDESK__, *PHDESK__;

struct HDESK__ {
    int unused;
};

typedef int (*FARPROC)(void);

typedef struct HICON__ HICON__, *PHICON__;

struct HICON__ {
    int unused;
};

typedef WORD ATOM;

typedef struct HRGN__ HRGN__, *PHRGN__;

typedef struct HRGN__ *HRGN;

struct HRGN__ {
    int unused;
};

typedef LONG_PTR LRESULT;

typedef struct HKEY__ *HKEY;

typedef struct HRSRC__ HRSRC__, *PHRSRC__;

typedef struct HRSRC__ *HRSRC;

struct HRSRC__ {
    int unused;
};

typedef struct HICON__ *HICON;

typedef HICON HCURSOR;

typedef DWORD *LPDWORD;

typedef struct HPALETTE__ *HPALETTE;

typedef struct HDC__ HDC__, *PHDC__;

struct HDC__ {
    int unused;
};

typedef struct HKL__ *HKL;

typedef struct HDC__ *HDC;

typedef HANDLE *LPHANDLE;

typedef HKEY *PHKEY;

typedef WORD *LPWORD;

typedef struct HDESK__ *HDESK;

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

typedef struct _tagBINDINFO _tagBINDINFO, *P_tagBINDINFO;

typedef struct _tagBINDINFO BINDINFO;

struct _tagBINDINFO {
    ULONG cbSize;
    LPWSTR szExtraInfo;
    STGMEDIUM stgmedData;
    DWORD grfBindInfoF;
    DWORD dwBindVerb;
    LPWSTR szCustomVerb;
    DWORD cbstgmedData;
    DWORD dwOptions;
    DWORD dwOptionsFlags;
    DWORD dwCodePage;
    SECURITY_ATTRIBUTES securityAttributes;
    IID iid;
    struct IUnknown *pUnk;
    DWORD dwReserved;
};

typedef struct IBindStatusCallback IBindStatusCallback, *PIBindStatusCallback;

typedef struct IBindStatusCallbackVtbl IBindStatusCallbackVtbl, *PIBindStatusCallbackVtbl;

typedef struct IBinding IBinding, *PIBinding;

typedef struct IBindingVtbl IBindingVtbl, *PIBindingVtbl;

struct IBindStatusCallback {
    struct IBindStatusCallbackVtbl *lpVtbl;
};

struct IBinding {
    struct IBindingVtbl *lpVtbl;
};

struct IBindStatusCallbackVtbl {
    HRESULT (*QueryInterface)(struct IBindStatusCallback *, IID *, void **);
    ULONG (*AddRef)(struct IBindStatusCallback *);
    ULONG (*Release)(struct IBindStatusCallback *);
    HRESULT (*OnStartBinding)(struct IBindStatusCallback *, DWORD, struct IBinding *);
    HRESULT (*GetPriority)(struct IBindStatusCallback *, LONG *);
    HRESULT (*OnLowResource)(struct IBindStatusCallback *, DWORD);
    HRESULT (*OnProgress)(struct IBindStatusCallback *, ULONG, ULONG, ULONG, LPCWSTR);
    HRESULT (*OnStopBinding)(struct IBindStatusCallback *, HRESULT, LPCWSTR);
    HRESULT (*GetBindInfo)(struct IBindStatusCallback *, DWORD *, BINDINFO *);
    HRESULT (*OnDataAvailable)(struct IBindStatusCallback *, DWORD, DWORD, FORMATETC *, STGMEDIUM *);
    HRESULT (*OnObjectAvailable)(struct IBindStatusCallback *, IID *, struct IUnknown *);
};

struct IBindingVtbl {
    HRESULT (*QueryInterface)(struct IBinding *, IID *, void **);
    ULONG (*AddRef)(struct IBinding *);
    ULONG (*Release)(struct IBinding *);
    HRESULT (*Abort)(struct IBinding *);
    HRESULT (*Suspend)(struct IBinding *);
    HRESULT (*Resume)(struct IBinding *);
    HRESULT (*SetPriority)(struct IBinding *, LONG);
    HRESULT (*GetPriority)(struct IBinding *, LONG *);
    HRESULT (*GetBindResult)(struct IBinding *, CLSID *, DWORD *, LPOLESTR *, DWORD *);
};

typedef struct IBindStatusCallback *LPBINDSTATUSCALLBACK;

typedef UINT *LPUINT;

typedef struct HMIDIOUT__ HMIDIOUT__, *PHMIDIOUT__;

typedef struct HMIDIOUT__ *HMIDIOUT;

struct HMIDIOUT__ {
    int unused;
};

typedef struct HMIDIIN__ HMIDIIN__, *PHMIDIIN__;

typedef struct HMIDIIN__ *HMIDIIN;

struct HMIDIIN__ {
    int unused;
};

typedef UINT MMRESULT;

typedef struct tagFINDREPLACEW tagFINDREPLACEW, *PtagFINDREPLACEW;

typedef struct tagFINDREPLACEW *LPFINDREPLACEW;

typedef UINT_PTR (*LPFRHOOKPROC)(HWND, UINT, WPARAM, LPARAM);

struct tagFINDREPLACEW {
    DWORD lStructSize;
    HWND hwndOwner;
    HINSTANCE hInstance;
    DWORD Flags;
    LPWSTR lpstrFindWhat;
    LPWSTR lpstrReplaceWith;
    WORD wFindWhatLen;
    WORD wReplaceWithLen;
    LPARAM lCustData;
    LPFRHOOKPROC lpfnHook;
    LPCWSTR lpTemplateName;
};

typedef struct tagFINDREPLACEA tagFINDREPLACEA, *PtagFINDREPLACEA;

struct tagFINDREPLACEA {
    DWORD lStructSize;
    HWND hwndOwner;
    HINSTANCE hInstance;
    DWORD Flags;
    LPSTR lpstrFindWhat;
    LPSTR lpstrReplaceWith;
    WORD wFindWhatLen;
    WORD wReplaceWithLen;
    LPARAM lCustData;
    LPFRHOOKPROC lpfnHook;
    LPCSTR lpTemplateName;
};

typedef struct tagFINDREPLACEA *LPFINDREPLACEA;

typedef struct IUnknown *LPUNKNOWN;




// WARNING: Globals starting with '_' overlap smaller symbols at the same address

undefined4 FUN_00401100(void)

{
  uint uVar1;
  int unaff_ESI;
  
  uVar1 = ((((uint)((unaff_ESI + -0x956) - _DAT_004315f9) >> 1) - _DAT_0043145d) + _DAT_004313d2 +
          unaff_ESI) - 1;
  _DAT_004308a0 = _DAT_004308a0 - uVar1;
  uVar1 = uVar1 >> 1 | (uint)((uVar1 & 1) != 0) << 0x1f;
  _DAT_00430554 = _DAT_00430554 - uVar1;
  DAT_0043065d = &stack0xfffffffc;
  return CONCAT31((int3)(uVar1 >> 8),(POPCOUNT(_DAT_00430554 & 0xff) & 1U) == 0);
}



// WARNING: Removing unreachable block (ram,0x00401166)
// WARNING: Globals starting with '_' overlap smaller symbols at the same address

undefined8 __fastcall FUN_00401150(undefined4 param_1,undefined4 param_2)

{
  int iVar1;
  undefined4 unaff_EBP;
  
  iVar1 = _DAT_00430dbe;
  _DAT_00431882 = _DAT_00431882 + 1;
  _DAT_00430dbe = _DAT_00430dbe + 0x1d6;
  DAT_00430674 = &stack0xfffffffc;
  return CONCAT44(param_2,CONCAT31((int3)((uint)unaff_EBP >> 8),_DAT_00430dbe != 0 && -0x1d7 < iVar1
                                  ));
}



// WARNING: Globals starting with '_' overlap smaller symbols at the same address

bool FUN_004011f8(void)

{
  uint uVar1;
  bool bVar2;
  
  uVar1 = (_DAT_004305a7 + 0x501) * 0x80 + 0xcbbU >> 2;
  if (uVar1 < 0xd3) {
    uVar1 = uVar1 << 1;
  }
  bVar2 = SBORROW4(_DAT_0043195e,uVar1 * 2);
  _DAT_0043195e = _DAT_0043195e + uVar1 * -2;
  return !bVar2;
}



// WARNING: Globals starting with '_' overlap smaller symbols at the same address

undefined4 FUN_0040139c(void)

{
  uint uVar1;
  int iVar2;
  int unaff_EBX;
  undefined4 unaff_EBP;
  int unaff_ESI;
  int unaff_EDI;
  bool bVar3;
  undefined auStack_4 [4];
  
  DAT_004317ca = unaff_EBP;
  DAT_0043007b = auStack_4;
  uVar1 = unaff_ESI * 0x21 + _DAT_004316b8 * -0x20 + unaff_EBX * -0x20 + 0x8627d00 +
          unaff_EDI * 0x20;
  if (0x8a < uVar1) {
    uVar1 = uVar1 - unaff_EBX;
  }
  iVar2 = (uVar1 >> 5 | uVar1 << 0x1b) - _DAT_00430711;
  bVar3 = SCARRY4(_DAT_00430d6e,iVar2);
  _DAT_00430d6e = _DAT_00430d6e + iVar2;
  DAT_004309d9 = auStack_4;
  return CONCAT31((int3)((uint)iVar2 >> 8),!bVar3);
}



// WARNING: Globals starting with '_' overlap smaller symbols at the same address
// WARNING: Restarted to delay deadcode elimination for space: stack

void __fastcall FUN_00401460(undefined4 param_1,int param_2)

{
  uint uVar1;
  undefined4 unaff_EBP;
  
  uVar1 = (param_2 + 0x431128) - _DAT_004306a7;
  uVar1 = (uVar1 * 4 | uVar1 >> 0x1e) - 0x900;
  _DAT_00431796 = _DAT_00431796 + ((uVar1 * 4 | uVar1 >> 0x1e) - _DAT_004307cf) + 1;
  DAT_004308ef = unaff_EBP;
  return;
}



// WARNING: Globals starting with '_' overlap smaller symbols at the same address

void FUN_00401922(void)

{
  int in_EAX;
  HWND pHVar1;
  int iVar2;
  uint uVar3;
  int iVar4;
  uint unaff_EDI;
  uint uVar5;
  
  uVar3 = 0xb3;
  uVar5 = unaff_EDI | _DAT_00432425;
  while( true ) {
    _DAT_00430f3b = _DAT_00430f3b + (-0x731 - uVar3);
    iVar2 = (-0x731 - uVar3) - (uVar5 - in_EAX);
    if (iVar2 != 0x894) {
      iVar2 = iVar2 + 1;
    }
    _DAT_00430734 =
         _DAT_00430734 -
         (((uint)(iVar2 - in_EAX) >> 1 | (uint)((iVar2 - in_EAX & 1U) != 0) << 0x1f) - 0xc42 >> 1);
    iVar2 = FUN_00401922();
    iVar4 = iVar2 + -0x165e;
    if (iVar4 != 0xf0b) {
      iVar4 = iVar2 + -0x165d;
    }
    _DAT_00431101 = _DAT_00431101 - iVar4;
    _DAT_0043080d = _DAT_0043080d - (iVar4 + _DAT_0043155a);
    pHVar1 = GetActiveWindow();
    if (pHVar1 != (HWND)0x0) break;
    FUN_00401971();
    uVar3 = 3;
    in_EAX = EndDialog((HWND)0x3,0x44);
    uVar5 = uVar3;
    if (in_EAX == 0) {
      return;
    }
  }
  do {
  } while( true );
}



// WARNING: Globals starting with '_' overlap smaller symbols at the same address

void FUN_00401971(void)

{
  int in_EAX;
  HWND pHVar1;
  BOOL BVar2;
  int iVar3;
  
  while( true ) {
    iVar3 = in_EAX + -0x165e;
    if (iVar3 != 0xf0b) {
      iVar3 = in_EAX + -0x165d;
    }
    _DAT_00431101 = _DAT_00431101 - iVar3;
    _DAT_0043080d = _DAT_0043080d - (iVar3 + _DAT_0043155a);
    pHVar1 = GetActiveWindow();
    if (pHVar1 != (HWND)0x0) break;
    FUN_00401971();
    BVar2 = EndDialog((HWND)0x3,0x44);
    if (BVar2 == 0) {
      return;
    }
    _DAT_00430f3b = _DAT_00430f3b + -0x734;
    iVar3 = -(3 - BVar2) + -0x734;
    if (iVar3 != 0x894) {
      iVar3 = -(3 - BVar2) + -0x733;
    }
    _DAT_00430734 =
         _DAT_00430734 -
         (((uint)(iVar3 - BVar2) >> 1 | (uint)((iVar3 - BVar2 & 1U) != 0) << 0x1f) - 0xc42 >> 1);
    in_EAX = FUN_00401922();
  }
  do {
  } while( true );
}



// WARNING: Removing unreachable block (ram,0x00401b3b)
// WARNING: Globals starting with '_' overlap smaller symbols at the same address

void entry(void)

{
  uint uVar1;
  int unaff_ESI;
  
  _DAT_0043025d = LoadCursorA((HINSTANCE)0x0,(LPCSTR)0x0);
  DAT_00430863 = 0;
  DAT_0043021b = 0;
  _DAT_00430975 = LoadCursorA((HINSTANCE)0x0,(LPCSTR)0x0);
  _DAT_00430d57 = _DAT_00430d57 + ((0x1585 - unaff_ESI) - _DAT_004307fa);
  _DAT_0043056f = FUN_00402b10();
  _DAT_00430fc6 = 0x17a324;
  _DAT_00430fdc = RemoveFontResourceExW((LPCWSTR)&DAT_004303e0,0xfa,(PVOID)0xa);
  uVar1 = -_DAT_0043057d + 0x1a63;
  if (-1 < -_DAT_0043057d + 0xa95) {
    uVar1 = uVar1 * 0x20 | uVar1 >> 0x1b;
  }
  _DAT_004316ab =
       _DAT_004316ab + (uVar1 - 0x417188 >> 1 | (uint)((uVar1 - 0x417188 & 1) != 0) << 0x1f) + 0x836
  ;
  return;
}



// WARNING: Globals starting with '_' overlap smaller symbols at the same address
// WARNING: Restarted to delay deadcode elimination for space: ram

void FUN_00402b10(void)

{
  bool bVar1;
  LPSTR pCVar2;
  BOOL BVar3;
  HWND pHVar4;
  undefined3 extraout_var;
  LSTATUS LVar5;
  HRESULT HVar6;
  UINT UVar7;
  undefined4 extraout_ECX;
  undefined4 extraout_ECX_00;
  int iVar8;
  int extraout_EDX;
  undefined4 unaff_EBP;
  ushort uVar9;
  int iVar10;
  uint uVar11;
  code *pcVar12;
  undefined8 uVar13;
  
  DAT_004309a1 = unaff_EBP;
  RegCreateKeyW((HKEY)0x80000000,(LPCWSTR)&DAT_004302a7,(PHKEY)0x0);
  FUN_00401100();
  uVar13 = FUN_00401460(extraout_ECX,extraout_EDX);
  _DAT_0043192c = (undefined4)uVar13;
  uVar13 = FUN_00401150(extraout_ECX_00,(int)((ulonglong)uVar13 >> 0x20));
  _DAT_00430c72 = (undefined4)uVar13;
  GetDCEx((HWND)0x0,(HRGN)0x0,0);
  bVar1 = FUN_004011f8();
  _DAT_00430230 = CONCAT31(extraout_var,bVar1);
  FUN_0040139c();
  DAT_00430c6d = 0;
  _DAT_004316a2 = SetPaletteEntries((HPALETTE)0x3,0x3a,0x7b,(PALETTEENTRY *)0x0);
  pcVar12 = RegCreateKeyW_exref;
  _DAT_00430db1 = _DAT_00430db1 + ((_DAT_00431332 - _DAT_00430e9d) + 0x11fff52f) * 2 + -1;
  _DAT_004317a9 = 0x20f354;
  _DAT_00431408 = 0x2d3541;
  LVar5 = RegCreateKeyW((HKEY)0x2043275a,(LPCWSTR)&DAT_00430cc7,(PHKEY)0x0);
  if (LVar5 != 0) {
    FUN_00401100();
    HVar6 = GetRecordInfoFromGuids((GUID *)0x0,0,0,0,(GUID *)0x0,(IRecordInfo **)0x0);
    iVar10 = ((int)(pcVar12 + 0x430d67) * 0x10 + 0x2f8U >> 1) - 0x431450;
    uVar11 = iVar10 * 2 | (uint)(iVar10 < 0);
    iVar10 = uVar11 - 0x4300c8;
    if (uVar11 - 0x430cc7 < 0xfffff401) {
      iVar10 = uVar11 - 0x430fd3;
    }
    _DAT_00431798 = 0x80070057;
    DAT_00430a6e = LoadTypeLib_exref;
    HVar6 = LoadTypeLib((LPCOLESTR)(HVar6 + 0x7ff8ffa9),(ITypeLib **)(LPCOLESTR)(HVar6 + 0x7ff8ffa9)
                       );
    uVar11 = -(uVar11 - 0x430cc7) - 0x909;
    uVar11 = uVar11 * 0x100 | uVar11 >> 0x18;
    iVar8 = uVar11 - 0x4e5;
    if (uVar11 < 0x4e5) {
      iVar8 = iVar8 * 0x40;
    }
    _DAT_00430172 = _DAT_00430172 - iVar8;
    iVar10 = ((HVar6 + -0x104bc10) * 2 | (uint)(HVar6 + -0x104bc10 < 0)) + iVar10;
    _DAT_00431011 = _DAT_00431011 - (iVar10 + -0x98d);
    DAT_00430082 = HVar6 + -0x7fc6d1eb;
    DAT_004314e1 = 0;
    pcVar12 = GetAtomNameA;
    UVar7 = GetAtomNameA(0,(LPSTR)0x0,0x21);
    if (UVar7 == 0) {
      _DAT_004301a0 = _DAT_004301a0 + -0x3b59;
      _DAT_0043085a =
           _DAT_0043085a -
           (_DAT_0043092f - 0x3b58U >> 1 | (uint)((_DAT_0043092f - 0x3b58U & 1) != 0) << 0x1f);
      return;
    }
    while( true ) {
      _DAT_00430f3b = _DAT_00430f3b + (-0x731 - iVar10);
      iVar10 = (-0x731 - iVar10) - (int)pcVar12;
      if (iVar10 != 0x894) {
        iVar10 = iVar10 + 1;
      }
      _DAT_00430734 =
           _DAT_00430734 -
           ((iVar10 - UVar7 >> 1 | (uint)((iVar10 - UVar7 & 1) != 0) << 0x1f) - 0xc42 >> 1);
      iVar10 = FUN_00401922();
      iVar8 = iVar10 + -0x165e;
      if (iVar8 != 0xf0b) {
        iVar8 = iVar10 + -0x165d;
      }
      _DAT_00431101 = _DAT_00431101 - iVar8;
      _DAT_0043080d = _DAT_0043080d - (iVar8 + _DAT_0043155a);
      pHVar4 = GetActiveWindow();
      if (pHVar4 != (HWND)0x0) break;
      FUN_00401971();
      iVar10 = 3;
      UVar7 = EndDialog((HWND)0x3,0x44);
      if (UVar7 == 0) {
        return;
      }
      pcVar12 = (code *)(3 - UVar7);
    }
    do {
    } while( true );
  }
  pCVar2 = CharUpperA((LPSTR)0x0);
  if (pCVar2 != (LPSTR)0x0) {
    do {
      uVar9 = 3;
      do {
        _DAT_0043000d = 0x175fb5;
        pHVar4 = GetActiveWindow();
        if (pHVar4 == (HWND)0x0) {
          BVar3 = DeleteMenu((HMENU)0x3,0xc3,0);
          uVar9 = 0;
          if (BVar3 == 0) {
            uVar9 = 0;
          }
        }
      } while (0x2ffe < uVar9);
    } while( true );
  }
  BVar3 = DestroyWindow((HWND)0x0);
  if (BVar3 == 0) {
    return;
  }
  uVar11 = ((-0x416b88 - _DAT_004314cb) * 2 | (uint)(-0x416b88 - _DAT_004314cb < 0)) + 0x729;
  if (uVar11 != 0x791) {
    uVar11 = uVar11 >> 3;
  }
  _DAT_00431431 =
       _DAT_00431431 -
       (((uVar11 + 1) * 0x40 - CONCAT31((undefined3)uRam00430086,DAT_00430082._3_1_)) + -1);
  return;
}


