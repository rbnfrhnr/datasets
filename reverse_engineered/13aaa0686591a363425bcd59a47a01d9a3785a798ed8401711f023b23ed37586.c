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
typedef unsigned long long    ulonglong;
typedef unsigned char    undefined1;
typedef unsigned short    undefined2;
typedef unsigned int    undefined4;
typedef unsigned long long    undefined6;
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

typedef ulonglong __uint64;

typedef struct _devicemodeW _devicemodeW, *P_devicemodeW;

typedef wchar_t WCHAR;

typedef ushort WORD;

typedef ulong DWORD;

typedef union _union_660 _union_660, *P_union_660;

typedef union _union_663 _union_663, *P_union_663;

typedef struct _struct_661 _struct_661, *P_struct_661;

typedef struct _struct_662 _struct_662, *P_struct_662;

typedef struct _POINTL _POINTL, *P_POINTL;

typedef struct _POINTL POINTL;

typedef long LONG;

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

typedef struct _devicemodeW *PDEVMODEW;


// WARNING! conflicting data type names: /guiddef.h/GUID - /GUID

typedef GUID IID;

typedef struct _GUID _GUID, *P_GUID;

struct _GUID {
    ulong Data1;
    ushort Data2;
    ushort Data3;
    uchar Data4[8];
};

typedef struct _CONTEXT _CONTEXT, *P_CONTEXT;

typedef struct _CONTEXT CONTEXT;

typedef struct _FLOATING_SAVE_AREA _FLOATING_SAVE_AREA, *P_FLOATING_SAVE_AREA;

typedef struct _FLOATING_SAVE_AREA FLOATING_SAVE_AREA;

typedef uchar BYTE;

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

typedef void *PVOID;

typedef ulong ULONG_PTR;

struct _EXCEPTION_RECORD {
    DWORD ExceptionCode;
    DWORD ExceptionFlags;
    struct _EXCEPTION_RECORD *ExceptionRecord;
    PVOID ExceptionAddress;
    DWORD NumberParameters;
    ULONG_PTR ExceptionInformation[15];
};

typedef long HRESULT;

typedef char CHAR;

typedef CHAR *LPCSTR;

typedef struct _IMAGE_SECTION_HEADER _IMAGE_SECTION_HEADER, *P_IMAGE_SECTION_HEADER;

typedef union _union_226 _union_226, *P_union_226;

union _union_226 {
    DWORD PhysicalAddress;
    DWORD VirtualSize;
};

struct _IMAGE_SECTION_HEADER {
    BYTE Name[8];
    union _union_226 Misc;
    DWORD VirtualAddress;
    DWORD SizeOfRawData;
    DWORD PointerToRawData;
    DWORD PointerToRelocations;
    DWORD PointerToLinenumbers;
    WORD NumberOfRelocations;
    WORD NumberOfLinenumbers;
    DWORD Characteristics;
};

typedef CHAR *LPSTR;

typedef WCHAR *LPWSTR;

typedef CONTEXT *PCONTEXT;

typedef struct _IMAGE_SECTION_HEADER *PIMAGE_SECTION_HEADER;

typedef WCHAR *LPCWSTR;

typedef void *HANDLE;

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

typedef ULONG_PTR SIZE_T;

typedef uint UINT_PTR;

typedef long LONG_PTR;

typedef struct _EXCEPTION_POINTERS _EXCEPTION_POINTERS, *P_EXCEPTION_POINTERS;

struct _EXCEPTION_POINTERS {
    PEXCEPTION_RECORD ExceptionRecord;
    PCONTEXT ContextRecord;
};

typedef DWORD ULONG;

typedef struct DotNetPdbInfo DotNetPdbInfo, *PDotNetPdbInfo;

struct DotNetPdbInfo {
    char signature[4];
    GUID guid;
    dword age;
    char pdbpath[52];
};

typedef struct _strflt _strflt, *P_strflt;

struct _strflt {
    int sign;
    int decpt;
    int flag;
    char *mantissa;
};

typedef enum enum_3272 {
    INTRNCVT_OK=0,
    INTRNCVT_OVERFLOW=1,
    INTRNCVT_UNDERFLOW=2
} enum_3272;

typedef enum enum_3272 INTRNCVT_STATUS;

typedef struct _strflt *STRFLT;

typedef int (*FARPROC)(void);

typedef struct HDC__ HDC__, *PHDC__;

typedef struct HDC__ *HDC;

struct HDC__ {
    int unused;
};

typedef struct HKEY__ HKEY__, *PHKEY__;

struct HKEY__ {
    int unused;
};

typedef UINT_PTR WPARAM;

typedef WORD *LPWORD;

typedef DWORD *LPDWORD;

typedef int INT;

typedef struct HMENU__ HMENU__, *PHMENU__;

struct HMENU__ {
    int unused;
};

typedef struct HINSTANCE__ HINSTANCE__, *PHINSTANCE__;

struct HINSTANCE__ {
    int unused;
};

typedef LONG_PTR LRESULT;

typedef struct HKEY__ *HKEY;

typedef void *HGDIOBJ;

typedef BYTE *PBYTE;

typedef struct HINSTANCE__ *HINSTANCE;

typedef struct HWND__ HWND__, *PHWND__;

typedef struct HWND__ *HWND;

struct HWND__ {
    int unused;
};

typedef void *LPVOID;

typedef HINSTANCE HMODULE;

typedef int BOOL;

typedef BYTE *LPBYTE;

typedef struct HMENU__ *HMENU;

typedef uint UINT;

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

typedef char *va_list;

typedef uint uintptr_t;

typedef struct tagPOINT tagPOINT, *PtagPOINT;

struct tagPOINT { // PlaceHolder Structure
};

typedef struct CDC CDC, *PCDC;

struct CDC { // PlaceHolder Structure
};

typedef struct CRuntimeClass CRuntimeClass, *PCRuntimeClass;

struct CRuntimeClass { // PlaceHolder Structure
};

typedef struct CWinApp CWinApp, *PCWinApp;

struct CWinApp { // PlaceHolder Structure
};

typedef struct AFX_MODULE_STATE AFX_MODULE_STATE, *PAFX_MODULE_STATE;

struct AFX_MODULE_STATE { // PlaceHolder Structure
};

typedef struct _s_HandlerType _s_HandlerType, *P_s_HandlerType;

struct _s_HandlerType { // PlaceHolder Structure
};

typedef struct EHExceptionRecord EHExceptionRecord, *PEHExceptionRecord;

struct EHExceptionRecord { // PlaceHolder Structure
};

typedef struct CMenu CMenu, *PCMenu;

struct CMenu { // PlaceHolder Structure
};

typedef struct _s_ESTypeList _s_ESTypeList, *P_s_ESTypeList;

struct _s_ESTypeList { // PlaceHolder Structure
};

typedef struct __POSITION __POSITION, *P__POSITION;

struct __POSITION { // PlaceHolder Structure
};

typedef struct CArchive CArchive, *PCArchive;

struct CArchive { // PlaceHolder Structure
};

typedef struct AFX_MSGMAP_ENTRY AFX_MSGMAP_ENTRY, *PAFX_MSGMAP_ENTRY;

struct AFX_MSGMAP_ENTRY { // PlaceHolder Structure
};

typedef struct CProcessLocalObject CProcessLocalObject, *PCProcessLocalObject;

struct CProcessLocalObject { // PlaceHolder Structure
};

typedef struct tagDRAWITEMSTRUCT tagDRAWITEMSTRUCT, *PtagDRAWITEMSTRUCT;

struct tagDRAWITEMSTRUCT { // PlaceHolder Structure
};

typedef struct EHRegistrationNode EHRegistrationNode, *PEHRegistrationNode;

struct EHRegistrationNode { // PlaceHolder Structure
};

typedef struct HBRUSH__ HBRUSH__, *PHBRUSH__;

struct HBRUSH__ { // PlaceHolder Structure
};

typedef struct _s_TryBlockMapEntry _s_TryBlockMapEntry, *P_s_TryBlockMapEntry;

struct _s_TryBlockMapEntry { // PlaceHolder Structure
};

typedef struct tagDELETEITEMSTRUCT tagDELETEITEMSTRUCT, *PtagDELETEITEMSTRUCT;

struct tagDELETEITEMSTRUCT { // PlaceHolder Structure
};

typedef struct _s_CatchableType _s_CatchableType, *P_s_CatchableType;

struct _s_CatchableType { // PlaceHolder Structure
};

typedef enum eActCtxResult {
} eActCtxResult;

typedef struct type_info type_info, *Ptype_info;

struct type_info { // PlaceHolder Structure
};

typedef struct _s_FuncInfo _s_FuncInfo, *P_s_FuncInfo;

struct _s_FuncInfo { // PlaceHolder Structure
};

typedef struct tagDISPPARAMS tagDISPPARAMS, *PtagDISPPARAMS;

struct tagDISPPARAMS { // PlaceHolder Structure
};

typedef struct HRSRC__ HRSRC__, *PHRSRC__;

struct HRSRC__ { // PlaceHolder Structure
};

typedef struct tagMEASUREITEMSTRUCT tagMEASUREITEMSTRUCT, *PtagMEASUREITEMSTRUCT;

struct tagMEASUREITEMSTRUCT { // PlaceHolder Structure
};

typedef struct AFX_MAINTAIN_STATE2 AFX_MAINTAIN_STATE2, *PAFX_MAINTAIN_STATE2;

struct AFX_MAINTAIN_STATE2 { // PlaceHolder Structure
};

typedef struct tagVARIANT tagVARIANT, *PtagVARIANT;

struct tagVARIANT { // PlaceHolder Structure
};

typedef struct IDispatch IDispatch, *PIDispatch;

struct IDispatch { // PlaceHolder Structure
};

typedef struct CWnd CWnd, *PCWnd;

struct CWnd { // PlaceHolder Structure
};

typedef struct tagEXCEPINFO tagEXCEPINFO, *PtagEXCEPINFO;

struct tagEXCEPINFO { // PlaceHolder Structure
};

typedef struct CException CException, *PCException;

struct CException { // PlaceHolder Structure
};

typedef struct tagCOMPAREITEMSTRUCT tagCOMPAREITEMSTRUCT, *PtagCOMPAREITEMSTRUCT;

struct tagCOMPAREITEMSTRUCT { // PlaceHolder Structure
};

typedef struct CFixedAllocNoSync CFixedAllocNoSync, *PCFixedAllocNoSync;

struct CFixedAllocNoSync { // PlaceHolder Structure
};

typedef struct COleException COleException, *PCOleException;

struct COleException { // PlaceHolder Structure
};

typedef struct tagMSG tagMSG, *PtagMSG;

struct tagMSG { // PlaceHolder Structure
};

typedef struct CCmdTarget CCmdTarget, *PCCmdTarget;

struct CCmdTarget { // PlaceHolder Structure
};

typedef struct tagINITCOMMONCONTROLSEX tagINITCOMMONCONTROLSEX, *PtagINITCOMMONCONTROLSEX;

struct tagINITCOMMONCONTROLSEX { // PlaceHolder Structure
};

typedef struct CPlex CPlex, *PCPlex;

struct CPlex { // PlaceHolder Structure
};

typedef struct CObject CObject, *PCObject;

struct CObject { // PlaceHolder Structure
};

typedef struct tagWNDCLASSA tagWNDCLASSA, *PtagWNDCLASSA;

struct tagWNDCLASSA { // PlaceHolder Structure
};

typedef struct CSimpleList CSimpleList, *PCSimpleList;

struct CSimpleList { // PlaceHolder Structure
};

typedef struct CMapPtrToPtr CMapPtrToPtr, *PCMapPtrToPtr;

struct CMapPtrToPtr { // PlaceHolder Structure
};

typedef struct tagRECT tagRECT, *PtagRECT;

struct tagRECT { // PlaceHolder Structure
};

typedef struct _LocaleUpdate _LocaleUpdate, *P_LocaleUpdate;

struct _LocaleUpdate { // PlaceHolder Structure
};

typedef struct CAfxStringMgr CAfxStringMgr, *PCAfxStringMgr;

struct CAfxStringMgr { // PlaceHolder Structure
};

typedef struct CHandleMap CHandleMap, *PCHandleMap;

struct CHandleMap { // PlaceHolder Structure
};

typedef struct CByteArray CByteArray, *PCByteArray;

struct CByteArray { // PlaceHolder Structure
};

typedef struct CGdiObject CGdiObject, *PCGdiObject;

struct CGdiObject { // PlaceHolder Structure
};

typedef struct CArray<enum_CArchive::LoadArrayObjType,enum_CArchive::LoadArrayObjType_const&> CArray<enum_CArchive::LoadArrayObjType,enum_CArchive::LoadArrayObjType_const&>, *PCArray<enum_CArchive::LoadArrayObjType,enum_CArchive::LoadArrayObjType_const&>;

struct CArray<enum_CArchive::LoadArrayObjType,enum_CArchive::LoadArrayObjType_const&> { // PlaceHolder Structure
};

typedef struct CThreadSlotData CThreadSlotData, *PCThreadSlotData;

struct CThreadSlotData { // PlaceHolder Structure
};

typedef struct CSimpleException CSimpleException, *PCSimpleException;

struct CSimpleException { // PlaceHolder Structure
};

typedef struct CCmdUI CCmdUI, *PCCmdUI;

struct CCmdUI { // PlaceHolder Structure
};

typedef struct CInternalGlobalLock CInternalGlobalLock, *PCInternalGlobalLock;

struct CInternalGlobalLock { // PlaceHolder Structure
};

typedef struct CObArray CObArray, *PCObArray;

struct CObArray { // PlaceHolder Structure
};

typedef struct CSimpleStringT<wchar_t,0> CSimpleStringT<wchar_t,0>, *PCSimpleStringT<wchar_t,0>;

struct CSimpleStringT<wchar_t,0> { // PlaceHolder Structure
};

typedef struct ATLSTRINGRESOURCEIMAGE ATLSTRINGRESOURCEIMAGE, *PATLSTRINGRESOURCEIMAGE;

struct ATLSTRINGRESOURCEIMAGE { // PlaceHolder Structure
};

typedef struct CStringT<wchar_t,class_StrTraitMFC<wchar_t,class_ATL::ChTraitsCRT<wchar_t>_>_> CStringT<wchar_t,class_StrTraitMFC<wchar_t,class_ATL::ChTraitsCRT<wchar_t>_>_>, *PCStringT<wchar_t,class_StrTraitMFC<wchar_t,class_ATL::ChTraitsCRT<wchar_t>_>_>;

struct CStringT<wchar_t,class_StrTraitMFC<wchar_t,class_ATL::ChTraitsCRT<wchar_t>_>_> { // PlaceHolder Structure
};

typedef struct CStringData CStringData, *PCStringData;

struct CStringData { // PlaceHolder Structure
};

typedef struct _ATL_INTMAP_ENTRY _ATL_INTMAP_ENTRY, *P_ATL_INTMAP_ENTRY;

struct _ATL_INTMAP_ENTRY { // PlaceHolder Structure
};

typedef struct exception exception, *Pexception;

struct exception { // PlaceHolder Structure
};

typedef enum LoadArrayObjType {
} LoadArrayObjType;

typedef struct _LDBL12 _LDBL12, *P_LDBL12;

struct _LDBL12 {
    uchar ld12[12];
};

typedef struct _CRT_FLOAT _CRT_FLOAT, *P_CRT_FLOAT;

struct _CRT_FLOAT {
    float f;
};

typedef struct _CRT_DOUBLE _CRT_DOUBLE, *P_CRT_DOUBLE;

struct _CRT_DOUBLE {
    double x;
};

typedef struct lconv lconv, *Plconv;

struct lconv {
    char *decimal_point;
    char *thousands_sep;
    char *grouping;
    char *int_curr_symbol;
    char *currency_symbol;
    char *mon_decimal_point;
    char *mon_thousands_sep;
    char *mon_grouping;
    char *positive_sign;
    char *negative_sign;
    char int_frac_digits;
    char frac_digits;
    char p_cs_precedes;
    char p_sep_by_space;
    char n_cs_precedes;
    char n_sep_by_space;
    char p_sign_posn;
    char n_sign_posn;
    wchar_t *_W_decimal_point;
    wchar_t *_W_thousands_sep;
    wchar_t *_W_int_curr_symbol;
    wchar_t *_W_currency_symbol;
    wchar_t *_W_mon_decimal_point;
    wchar_t *_W_mon_thousands_sep;
    wchar_t *_W_positive_sign;
    wchar_t *_W_negative_sign;
};

typedef ushort wint_t;

typedef struct threadlocaleinfostruct threadlocaleinfostruct, *Pthreadlocaleinfostruct;

typedef struct threadlocaleinfostruct *pthreadlocinfo;

typedef struct localerefcount localerefcount, *Plocalerefcount;

typedef struct localerefcount locrefcount;

typedef struct __lc_time_data __lc_time_data, *P__lc_time_data;

struct localerefcount {
    char *locale;
    wchar_t *wlocale;
    int *refcount;
    int *wrefcount;
};

struct threadlocaleinfostruct {
    int refcount;
    uint lc_codepage;
    uint lc_collate_cp;
    uint lc_time_cp;
    locrefcount lc_category[6];
    int lc_clike;
    int mb_cur_max;
    int *lconv_intl_refcount;
    int *lconv_num_refcount;
    int *lconv_mon_refcount;
    struct lconv *lconv;
    int *ctype1_refcount;
    ushort *ctype1;
    ushort *pctype;
    uchar *pclmap;
    uchar *pcumap;
    struct __lc_time_data *lc_time_curr;
    wchar_t *locale_name[6];
};

struct __lc_time_data {
    char *wday_abbr[7];
    char *wday[7];
    char *month_abbr[12];
    char *month[12];
    char *ampm[2];
    char *ww_sdatefmt;
    char *ww_ldatefmt;
    char *ww_timefmt;
    int ww_caltype;
    int refcount;
    wchar_t *_W_wday_abbr[7];
    wchar_t *_W_wday[7];
    wchar_t *_W_month_abbr[12];
    wchar_t *_W_month[12];
    wchar_t *_W_ampm[2];
    wchar_t *_W_ww_sdatefmt;
    wchar_t *_W_ww_ldatefmt;
    wchar_t *_W_ww_timefmt;
    wchar_t *_W_ww_locale_name;
};

typedef uint size_t;

typedef size_t rsize_t;

typedef int errno_t;

typedef struct localeinfo_struct localeinfo_struct, *Plocaleinfo_struct;

typedef struct threadmbcinfostruct threadmbcinfostruct, *Pthreadmbcinfostruct;

typedef struct threadmbcinfostruct *pthreadmbcinfo;

struct threadmbcinfostruct {
    int refcount;
    int mbcodepage;
    int ismbcodepage;
    ushort mbulinfo[6];
    uchar mbctype[257];
    uchar mbcasemap[256];
    wchar_t *mblocalename;
};

struct localeinfo_struct {
    pthreadlocinfo locinfo;
    pthreadmbcinfo mbcinfo;
};

typedef int intptr_t;

typedef struct localeinfo_struct *_locale_t;

typedef ushort wctype_t;

typedef struct IUnknownVtbl IUnknownVtbl, *PIUnknownVtbl;

typedef struct IUnknown IUnknown, *PIUnknown;

struct IUnknownVtbl {
    HRESULT (*QueryInterface)(struct IUnknown *, IID *, void **);
    ULONG (*AddRef)(struct IUnknown *);
    ULONG (*Release)(struct IUnknown *);
};

struct IUnknown {
    struct IUnknownVtbl *lpVtbl;
};

typedef struct IUnknown *LPUNKNOWN;




void FUN_00401004(void)

{
  undefined4 local_124;
  int local_120 [31];
  undefined local_a4 [156];
  uint local_8;
  
  local_8 = DAT_00431c20 ^ (uint)local_a4;
  func_0x3b8211e7(local_120,0,0x118);
  local_124 = 0x11c;
  (*DAT_00428240)(&local_124);
  func_0x485e124e();
  return;
}



// WARNING: Control flow encountered bad instruction data

void FUN_004010a0(void)

{
  short sVar1;
  short sVar2;
  code *pcVar3;
  code *pcVar4;
  int iVar5;
  int iVar6;
  short *psVar7;
  int iVar8;
  undefined2 uVar9;
  undefined4 *puVar10;
  undefined4 *puVar11;
  int local_1c4c;
  int local_1c38;
  short asStackY_1c30 [64];
  short local_1bb0;
  short asStackY_1bae [80];
  undefined2 local_1b0e;
  undefined local_1a34 [8];
  undefined4 local_1a2c;
  undefined2 local_1930;
  short local_192a;
  short asStackY_1926 [149];
  int local_17fc;
  short local_17f8 [64];
  short local_1778;
  short local_1776 [16];
  int local_1756 [32];
  undefined2 local_16d6;
  short local_16d4;
  short local_16b4;
  short local_1694;
  int local_1674 [8];
  int local_1654 [8];
  undefined4 local_1634;
  undefined4 local_1630;
  undefined2 local_15fc;
  int local_15fa [511];
  undefined2 local_dfc [260];
  short local_bf4 [259];
  undefined4 uStackY_9ee;
  short local_7e4 [260];
  short local_5dc [260];
  short local_3d4;
  undefined local_3d2 [518];
  short local_1cc [64];
  short local_14c [64];
  short local_cc [56];
  undefined4 uStackY_5c;
  undefined4 uStackY_58;
  undefined4 uStackY_54;
  short *psStackY_50;
  undefined *puStackY_4c;
  undefined local_48 [2];
  undefined local_46 [6];
  short *psStackY_40;
  int iStackY_3c;
  short *psStackY_38;
  undefined *puStackY_34;
  int *piStackY_30;
  short *psStackY_2c;
  
  func_0xeba61263();
  local_3d4 = 0;
  local_1c4c = 0;
  func_0x3b821294();
  local_dfc[0] = 0;
  func_0x3b8212ae();
  local_bf4[0] = 0;
  func_0x3b8212c8();
  puVar10 = (undefined4 *)&stack0xffffffda;
  for (iVar8 = 7; iVar8 != 0; iVar8 = iVar8 + -1) {
    *puVar10 = 0;
    puVar10 = puVar10 + 1;
  }
  *(undefined2 *)puVar10 = 0;
  local_1cc[0] = 0;
  func_0x3b8212f3();
  local_cc[0] = 0;
  func_0x3b82130e();
  local_14c[0] = 0;
  func_0x3b82132f();
  local_7e4[0] = 0;
  func_0x3b82134f();
  _local_48 = (short *)((uint)(ushort)local_46._0_2_ << 0x10);
  puVar10 = (undefined4 *)(local_48 + 2);
  for (iVar8 = 7; iVar8 != 0; iVar8 = iVar8 + -1) {
    *puVar10 = 0;
    puVar10 = puVar10 + 1;
  }
  *(undefined2 *)puVar10 = 0;
  local_1c38 = 0;
  local_5dc[0] = 0;
  func_0x3b82137f();
  uStackY_9ee._2_2_ = 0;
  func_0x3b821399();
  func_0x3b8213ae();
  iVar8 = FUN_004019e0(1);
  iVar5 = func_0xd74912d1();
  (*DAT_00428238)();
  (*DAT_00428234)();
  piStackY_30 = (int *)&local_3d4;
  psStackY_2c = (short *)0x104;
  puStackY_34 = (undefined *)0x401256;
  func_0x575e140c();
  pcVar4 = DAT_00428230;
  psVar7 = &local_3d4;
  do {
    sVar1 = *psVar7;
    psVar7 = psVar7 + 1;
  } while (sVar1 != 0);
  if ((int)psVar7 - (int)local_3d2 >> 1 != 0) {
    psStackY_2c = (short *)0x401281;
    iVar6 = (*DAT_00428230)();
    if (iVar6 != -1) {
      psStackY_2c = (short *)0x401293;
      (*DAT_0042822c)();
    }
  }
  if (iVar8 == 0) {
    sVar1 = 0;
    uVar9 = 0;
    if (DAT_00432fc0 == 3) {
      piStackY_30 = (int *)local_1a34;
      psStackY_2c = (short *)0x0;
      puStackY_34 = (undefined *)0x4014c8;
      func_0x3b82167e();
      psStackY_2c = (short *)0x4014d7;
      local_1c4c = func_0x184e158d();
      if (local_1c4c != 0) {
        iVar8 = 0;
        do {
          psVar7 = (short *)((int)asStackY_1926 + iVar8);
          *(short *)((int)local_1cc + iVar8) = *psVar7;
          iVar8 = iVar8 + 2;
        } while (*psVar7 != 0);
        func_0x035115c2();
        func_0x035115e0();
        local_1c38 = local_1a2c;
        piStackY_30 = (int *)&stack0xffffffd8;
        psStackY_2c = (short *)0x10;
        puStackY_34 = (undefined *)0x401555;
        func_0xd45e170b();
        sVar1 = local_192a;
        uVar9 = local_1930;
      }
    }
    if (iVar5 != 0) {
      iVar8 = 0;
      do {
        psVar7 = (short *)((int)asStackY_1bae + iVar8);
        *(short *)((int)local_1cc + iVar8) = *psVar7;
        iVar8 = iVar8 + 2;
      } while (*psVar7 != 0);
      iVar8 = 0;
      do {
        psVar7 = (short *)((int)asStackY_1c30 + iVar8);
        *(short *)((int)local_cc + iVar8) = *psVar7;
        iVar8 = iVar8 + 2;
      } while (*psVar7 != 0);
      iVar8 = 0;
      do {
        sVar1 = *(short *)((int)&DAT_0042b7b0 + iVar8);
        *(short *)((int)local_14c + iVar8) = sVar1;
        iVar8 = iVar8 + 2;
      } while (sVar1 != 0);
      local_1c38 = 5;
      psStackY_2c = local_7e4;
      if (DAT_00432fc0 == 3) {
        piStackY_30 = (int *)0x4015ed;
        (*DAT_00428214)();
        piStackY_30 = (int *)&DAT_0042b8a8;
        psStackY_38 = local_7e4;
        puStackY_34 = (undefined *)0x104;
        iStackY_3c = 0x4015ff;
        func_0x575e17b5();
      }
      else {
        psStackY_2c = (short *)0x104;
        piStackY_30 = (int *)0x4015e3;
        (*DAT_00428234)();
      }
      iVar8 = 0;
      do {
        psVar7 = (short *)((int)local_7e4 + iVar8);
        *(short *)((int)local_bf4 + iVar8) = *psVar7;
        iVar8 = iVar8 + 2;
      } while (*psVar7 != 0);
      piStackY_30 = (int *)&DAT_0042b7cc;
      psStackY_38 = local_bf4;
      puStackY_34 = (undefined *)0x104;
      iStackY_3c = 0x40162d;
      func_0x575e17e3();
      piStackY_30 = (int *)local_bf4;
      puStackY_34 = (undefined *)0x40163d;
      (*DAT_0042822c)();
      sVar1 = local_1bb0;
      uVar9 = local_1b0e;
    }
    piStackY_30 = &local_17fc;
    psStackY_2c = (short *)0x0;
    puStackY_34 = (undefined *)0x401657;
    func_0x3b82180d();
    local_1778 = 0x51;
    local_17fc = 0x504d534d;
    iVar8 = 0;
    do {
      sVar2 = *(short *)((int)&DAT_0042b7e4 + iVar8);
      *(short *)((int)local_17f8 + iVar8) = sVar2;
      iVar8 = iVar8 + 2;
    } while (sVar2 != 0);
    local_16d6 = 0x2b70;
    iVar8 = 0;
    do {
      sVar2 = *(short *)((int)&DAT_0042b7b0 + iVar8);
      *(short *)((int)local_1756 + iVar8) = sVar2;
      iVar8 = iVar8 + 2;
    } while (sVar2 != 0);
    iVar8 = 0;
    do {
      sVar2 = *(short *)((int)&DAT_0042b800 + iVar8);
      *(short *)((int)local_1776 + iVar8) = sVar2;
      iVar8 = iVar8 + 2;
    } while (sVar2 != 0);
    if ((local_1c4c != 0) || (iVar5 != 0)) {
      piStackY_30 = (int *)local_1776;
      psStackY_2c = (short *)0x10;
      puStackY_34 = (undefined *)0x4016fb;
      func_0xd45e18b1();
      piStackY_30 = (int *)local_17f8;
      psStackY_2c = (short *)0x40;
      puStackY_34 = (undefined *)0x401713;
      func_0xd45e18c9();
      piStackY_30 = local_1756;
      psStackY_2c = (short *)0x40;
      puStackY_34 = (undefined *)0x401739;
      local_1778 = sVar1;
      func_0xd45e18ef();
      local_1634 = local_1c38;
      local_16d6 = uVar9;
    }
    if ((local_17f8[0] != 0) && (local_1778 != 0)) {
      local_17fc = 0x504d534d;
      (*DAT_00428218)();
      psStackY_2c = (short *)0x401792;
      func_0x435f1948();
      local_15fc = 0;
      piStackY_30 = local_15fa;
      psStackY_2c = (short *)0x0;
      puStackY_34 = (undefined *)0x4017af;
      func_0x3b821965();
      if (local_16d4 == 0) {
        psStackY_2c = (short *)0x4017c7;
        func_0x6851187d();
        piStackY_30 = (int *)&local_16d4;
        psStackY_2c = (short *)0x10;
        puStackY_34 = (undefined *)0x4017dc;
        func_0xd45e1992();
      }
      if (local_16b4 == 0) {
        psStackY_2c = (short *)0x4017f4;
        func_0x685118aa();
        piStackY_30 = (int *)&local_16b4;
        psStackY_2c = (short *)0x10;
        puStackY_34 = (undefined *)0x401809;
        func_0xd45e19bf();
      }
      psVar7 = (short *)local_48;
      do {
        sVar1 = *psVar7;
        psVar7 = psVar7 + 1;
      } while (sVar1 != 0);
      if ((int)psVar7 - (int)(local_48 + 2) >> 1 != 0) {
        psStackY_2c = (short *)0x0;
        piStackY_30 = (int *)0x20000;
        puStackY_34 = (undefined *)0x401832;
        iVar8 = (*DAT_00428228)();
        if (iVar8 != 0) {
          piStackY_30 = local_1674;
          psStackY_2c = (short *)0x10;
          puStackY_34 = (undefined *)0x401847;
          func_0xd45e19fd();
        }
      }
      if ((short)local_1674[0] == 0) {
        psStackY_2c = (short *)0x40185f;
        func_0x68511915();
        piStackY_30 = local_1674;
        psStackY_2c = (short *)0x10;
        puStackY_34 = (undefined *)0x401874;
        func_0xd45e1a2a();
      }
      if ((short)local_1654[0] == 0) {
        psStackY_2c = (short *)0x40188c;
        func_0x68511942();
        piStackY_30 = local_1654;
        psStackY_2c = (short *)0x10;
        puStackY_34 = (undefined *)0x4018a1;
        func_0xd45e1a57();
        psVar7 = (short *)&stack0xffffffd8;
        do {
          sVar1 = *psVar7;
          psVar7 = psVar7 + 1;
        } while (sVar1 != 0);
        if ((int)psVar7 - (int)&stack0xffffffda >> 1 != 0) {
          piStackY_30 = local_1654;
          psStackY_2c = (short *)0x10;
          puStackY_34 = (undefined *)0x4018cb;
          func_0xd45e1a81();
        }
      }
      if (local_1694 == 0) {
        psStackY_2c = (short *)0x4018e3;
        func_0x68511999();
        piStackY_30 = (int *)&local_1694;
        psStackY_2c = (short *)0x10;
        puStackY_34 = (undefined *)0x4018f8;
        func_0xd45e1aae();
      }
      local_1630 = 0x1000267;
      psStackY_2c = (short *)0x401923;
      iVar8 = FUN_0040221d(&local_17fc);
      if (iVar8 != 0) {
        psVar7 = &local_3d4;
        FUN_00401c2b();
        psStackY_2c = local_dfc;
        piStackY_30 = (int *)0x40194c;
        func_0x5d531a02();
        psStackY_2c = (short *)0x3;
        piStackY_30 = (int *)0x0;
        puStackY_34 = &DAT_0042b810;
        psStackY_38 = (short *)0x80000001;
        iStackY_3c = 0x401970;
        iVar8 = (*(code *)s_InitCommonControls_00428003._9_4_)();
        if (iVar8 == 0) {
          do {
            sVar1 = *psVar7;
            psVar7 = psVar7 + 1;
          } while (sVar1 != 0);
          iStackY_3c = ((int)psVar7 - (int)local_3d2 >> 1) * 2 + 2;
          psStackY_40 = &local_3d4;
          local_46._2_4_ = 1;
          _local_48 = (short *)0x0;
          puStackY_4c = &DAT_0042b87c;
          psStackY_50 = (short *)0x0;
          uStackY_54 = 0x4019a7;
          iVar8 = (*(code *)s_InitCommonControls_00428003._5_4_)();
          if (iVar8 == 0) {
            iStackY_3c = 0;
            psStackY_40 = (short *)0x4019b7;
            (*(code *)s_InitCommonControls_00428003._1_4_)();
          }
        }
        iStackY_3c = 1;
        psStackY_40 = (short *)0x0;
        local_46._2_4_ = &DAT_0042b9c8;
        _local_48 = &local_3d4;
        puStackY_4c = (undefined *)0x0;
        psStackY_50 = (short *)0x0;
        uStackY_54 = 0x4019ce;
        (*DAT_00428264)();
      }
    }
    func_0x485e1b94();
    return;
  }
  psStackY_2c = (short *)0x104;
  piStackY_30 = (int *)0x4012ad;
  (*DAT_00428234)();
  piStackY_30 = local_1674;
  psStackY_38 = &local_3d4;
  puStackY_34 = (undefined *)0x104;
  iStackY_3c = 0x4012c1;
  func_0x575e1477();
  piStackY_30 = (int *)&DAT_0042b798;
  psStackY_38 = &local_3d4;
  puStackY_34 = (undefined *)0x104;
  iStackY_3c = 0x4012d6;
  func_0x575e148c();
  psVar7 = &local_3d4;
  do {
    sVar1 = *psVar7;
    psVar7 = psVar7 + 1;
  } while (sVar1 != 0);
  if ((int)psVar7 - (int)local_3d2 >> 1 != 0) {
    piStackY_30 = (int *)&local_3d4;
    puStackY_34 = (undefined *)0x4012fb;
    iVar8 = (*pcVar4)();
    if (iVar8 != -1) {
      piStackY_30 = (int *)&local_3d4;
      puStackY_34 = (undefined *)0x40130d;
      (*DAT_0042822c)();
    }
  }
  piStackY_30 = local_1654;
  psStackY_38 = (short *)&stack0xffffffd8;
  puStackY_34 = (undefined *)0x10;
  iStackY_3c = 0x40131f;
  func_0xd45e14d5();
  piStackY_30 = (int *)0x401333;
  FUN_00401c2b();
  piStackY_30 = (int *)0x40133a;
  iVar8 = func_0xb74c13f0();
  pcVar4 = DAT_00428228;
  if (iVar8 != 1) {
    iVar8 = 0;
    do {
      psVar7 = (short *)((int)local_1654 + iVar8);
      *(short *)((int)local_5dc + iVar8) = *psVar7;
      iVar8 = iVar8 + 2;
    } while (*psVar7 != 0);
    iVar8 = 0;
    do {
      sVar1 = *(short *)((int)local_1654 + iVar8);
      *(short *)((int)&uStackY_9ee + iVar8 + 2) = sVar1;
      iVar8 = iVar8 + 2;
    } while (sVar1 != 0);
    puVar10 = &uStackY_9ee;
    do {
      puVar11 = puVar10;
      puVar10 = (undefined4 *)((int)puVar11 + 2);
    } while (*(short *)((int)puVar11 + 2) != 0);
    *(undefined4 *)((int)puVar11 + 2) = DAT_0042b7a4;
    *(undefined4 *)((int)puVar11 + 6) = DAT_0042b7a8;
    piStackY_30 = (int *)local_5dc;
    puStackY_34 = (undefined *)0x0;
    *(undefined4 *)((int)puVar11 + 10) = DAT_0042b7ac;
    psStackY_38 = (short *)0x20000;
    iStackY_3c = 0x4013aa;
    iStackY_3c = (*DAT_00428228)();
    pcVar3 = DAT_00428224;
    if (iStackY_3c != 0) {
      psStackY_40 = (short *)0x4013b7;
      (*DAT_00428224)();
      psStackY_40 = (short *)((int)&uStackY_9ee + 2);
      local_46._2_4_ = (undefined *)0x0;
      _local_48 = (short *)0x0;
      puStackY_4c = (undefined *)0x0;
      psStackY_50 = (short *)0x4013c9;
      (*DAT_00428220)();
      local_1c38 = 0;
      while( true ) {
        psStackY_50 = local_5dc;
        uStackY_54 = 0;
        uStackY_58 = 0x20000;
        uStackY_5c = 0x4013fb;
        iStackY_3c = (*pcVar4)();
        if ((iStackY_3c == 0) || (4 < local_1c38)) break;
        psStackY_40 = (short *)0x4013de;
        (*pcVar3)();
        local_1c38 = local_1c38 + 1;
        psStackY_40 = (short *)0x1f4;
        local_46._2_4_ = (undefined *)0x4013ef;
        (*DAT_0042821c)();
      }
    }
    iStackY_3c = 1000;
    psStackY_40 = (short *)0x40140a;
    (*DAT_0042821c)();
    psStackY_40 = &local_3d4;
    local_46._2_4_ = 0x401417;
    (*DAT_0042822c)();
    iVar8 = 0;
    do {
      psVar7 = (short *)((int)local_1776 + iVar8);
      *(short *)((int)local_1cc + iVar8) = *psVar7;
      iVar8 = iVar8 + 2;
    } while (*psVar7 != 0);
    iVar8 = 0;
    do {
      psVar7 = (short *)((int)local_17f8 + iVar8);
      *(short *)((int)local_cc + iVar8) = *psVar7;
      iVar8 = iVar8 + 2;
    } while (*psVar7 != 0);
    iVar8 = 0;
    do {
      psVar7 = (short *)((int)local_1756 + iVar8);
      *(short *)((int)local_14c + iVar8) = *psVar7;
      iVar8 = iVar8 + 2;
    } while (*psVar7 != 0);
    local_46._2_4_ = local_1674;
    puStackY_4c = local_48;
    _local_48 = (short *)0x10;
    psStackY_50 = (short *)0x40149a;
    func_0xd45e1650();
                    // WARNING: Bad instruction - Truncating control flow here
    halt_baddata();
  }
                    // WARNING: Bad instruction - Truncating control flow here
  halt_baddata();
}



void __cdecl FUN_004019e0(int param_1)

{
  int iVar1;
  uint uVar2;
  int unaff_EDI;
  int local_210 [129];
  uint local_c;
  
  local_c = DAT_00431c20 ^ (uint)&stack0xfffffffc;
  if (unaff_EDI != 0) {
    func_0x3b821bc7(local_210,0,0x200);
    if (param_1 == 0) {
      iVar1 = func_0x2e4b1ae2();
    }
    else {
      iVar1 = func_0x634a1adb();
    }
    if (iVar1 != 0) {
      uVar2 = 0;
      do {
        *(byte *)((int)local_210 + uVar2) = ~*(byte *)((int)local_210 + uVar2);
        uVar2 = uVar2 + 1;
      } while (uVar2 < 0x200);
      if (local_210[0] == 0x504d534d) {
        func_0x8b5f1c0e();
      }
    }
  }
  func_0x485e1c20();
  return;
}



void FUN_00401c2b(void)

{
  undefined2 local_210;
  undefined local_20e [518];
  uint local_8;
  
  local_8 = DAT_00431c20 ^ (uint)&stack0xfffffffc;
  local_210 = 0;
  func_0x3b821e0f(local_20e,0,0x206);
  if (DAT_00432fc0 == 3) {
    (*DAT_00428214)(&local_210,0x104);
    func_0x575e1e41(&local_210,0x104,&DAT_0042b8a8);
  }
  else {
    (*DAT_00428234)(0x104,&local_210);
  }
  (*DAT_00428360)();
  func_0x485e1e74();
  return;
}



void FUN_00401cc0(void)

{
  int iVar1;
  undefined4 *puVar2;
  undefined2 local_238;
  undefined local_236 [518];
  undefined2 local_30;
  undefined4 local_2e [9];
  uint local_8;
  
  local_8 = DAT_00431c20 ^ (uint)&stack0xfffffffc;
  local_238 = 0;
  func_0x3b821ea8(local_236,0,0x206);
  local_30 = 0;
  puVar2 = local_2e;
  for (iVar1 = 9; iVar1 != 0; iVar1 = iVar1 + -1) {
    *puVar2 = 0;
    puVar2 = puVar2 + 1;
  }
  *(undefined2 *)puVar2 = 0;
  func_0xd45e1ec4(&local_30,0x14);
  func_0x575e1ed4(&local_30,0x14,&DAT_0042b798);
  (*DAT_00428238)(0,&local_238,0x104);
  func_0xb9671efa(&local_238,&local_30);
  func_0x485e1f0f();
  return;
}



undefined4 __cdecl FUN_00401d5b(undefined4 *param_1)

{
  short sVar1;
  int in_EAX;
  undefined4 *puVar2;
  int iVar3;
  short *psVar4;
  undefined4 *puVar5;
  undefined4 local_8;
  
  local_8 = 0;
  if (in_EAX == -1) {
    return 0;
  }
  puVar2 = (undefined4 *)func_0x0aba1e33(0x400);
  func_0x3b821f3f(puVar2,0,0x400);
  func_0x0f4f1e48();
  iVar3 = func_0xc84f1e51();
  if (iVar3 == 0) goto LAB_00401e0e;
  if (puVar2[1] == DAT_0042b8c0) {
    psVar4 = (short *)((int)puVar2 + 0x10e);
    do {
      sVar1 = *psVar4;
      psVar4 = psVar4 + 1;
    } while (sVar1 != 0);
    if ((int)psVar4 - (int)(puVar2 + 0x44) >> 1 == 0) goto LAB_00401dc9;
  }
  else {
LAB_00401dc9:
    iVar3 = func_0xc84f1e88();
    if ((iVar3 == 0) || (puVar2[1] != DAT_0042b8c0)) goto LAB_00401e0e;
    psVar4 = (short *)((int)puVar2 + 0x10e);
    do {
      sVar1 = *psVar4;
      psVar4 = psVar4 + 1;
    } while (sVar1 != 0);
    if ((int)psVar4 - (int)(puVar2 + 0x44) >> 1 == 0) goto LAB_00401e0e;
  }
  puVar5 = puVar2;
  for (iVar3 = 0x8d; iVar3 != 0; iVar3 = iVar3 + -1) {
    *param_1 = *puVar5;
    puVar5 = puVar5 + 1;
    param_1 = param_1 + 1;
  }
  *(undefined2 *)param_1 = *(undefined2 *)puVar5;
  local_8 = 1;
LAB_00401e0e:
  if (puVar2 != (undefined4 *)0x0) {
    func_0x15ba1ece(puVar2);
  }
  return local_8;
}



void __cdecl FUN_00401e21(undefined4 param_1)

{
  int iVar1;
  undefined4 *puVar2;
  undefined4 *puVar3;
  int local_254;
  short local_250;
  undefined local_24e [518];
  undefined4 local_48 [9];
  undefined4 local_24;
  undefined2 local_20;
  undefined4 local_1e;
  undefined4 uStack_1a;
  undefined4 uStack_16;
  undefined4 uStack_12;
  undefined2 uStack_e;
  uint local_c;
  
  local_c = DAT_00431c20 ^ (uint)&stack0xfffffffc;
  local_250 = 0;
  func_0x3b822013(local_24e,0,0x206);
  local_254 = 0;
  (*DAT_00428214)(&local_250,0x104);
  FUN_0040201f(local_250 + -0x41,&local_254);
  puVar2 = &DAT_0042b8c8;
  puVar3 = local_48;
  for (iVar1 = 9; iVar1 != 0; iVar1 = iVar1 + -1) {
    *puVar3 = *puVar2;
    puVar2 = puVar2 + 1;
    puVar3 = puVar3 + 1;
  }
  local_24 = 0;
  local_20 = 0;
  local_1e = 0;
  uStack_1a = 0;
  uStack_16 = 0;
  uStack_12 = 0;
  uStack_e = 0;
  if (-1 < local_254) {
    func_0xc3742082(local_254,&local_20,10,10);
    func_0x575e2091(local_48,0x14,&local_20);
    iVar1 = (*DAT_00428210)(local_48,0x80000000,3,0,3,0,0);
    if (iVar1 != -1) {
      func_0x524d1fbe(param_1);
    }
  }
  func_0x485e20cc();
  return;
}



undefined4 __cdecl FUN_00401f18(int param_1)

{
  uint uVar1;
  int iVar2;
  uint *puVar3;
  uint uVar4;
  uint uVar5;
  uint local_1c;
  uint local_18;
  undefined local_10 [4];
  undefined4 local_c;
  int local_8;
  
  (*DAT_0042821c)(100);
  uVar5 = 0;
  uVar4 = 0;
  local_c = 0;
  local_1c = 0;
  local_18 = 0;
  if (param_1 != -1) {
    local_8 = func_0x0aba2001(0xb69);
    iVar2 = (*DAT_0042820c)(param_1,0x70050,0,0,local_8,0xb69,local_10,0);
    if (iVar2 != 0) {
      puVar3 = (uint *)(local_8 + 0x30);
      iVar2 = 4;
      do {
        uVar1 = puVar3[1];
        if (((int)local_18 <= (int)uVar1) && (((int)local_18 < (int)uVar1 || (local_1c < *puVar3))))
        {
          uVar4 = puVar3[2];
          uVar5 = puVar3[3];
          local_1c = *puVar3;
          local_18 = uVar1;
        }
        puVar3 = (uint *)((int)puVar3 + 0x89);
        iVar2 = iVar2 + -1;
      } while (iVar2 != 0);
      local_c = func_0x4ba02165(uVar4 + local_1c,uVar5 + local_18 + (uint)CARRY4(uVar4,local_1c),
                                0x200,0);
    }
    if (local_8 != 0) {
      func_0x15ba2076(local_8);
    }
  }
  (*DAT_0042821c)(100);
  return local_c;
}



undefined4 __cdecl FUN_00401fd1(int param_1,uint param_2,undefined4 param_3)

{
  undefined4 uVar1;
  undefined4 local_1c;
  undefined4 local_18;
  undefined8 local_14;
  undefined4 uStack_c;
  undefined4 local_8;
  
  uVar1 = 0;
  local_1c = 0;
  local_18 = 0;
  uStack_c = 0;
  local_8 = 0;
  if (param_1 != -1) {
    local_14 = (ulonglong)param_2 * 0x200;
    uVar1 = (*DAT_00428208)(param_1,param_3,0x400,&local_8,&local_1c);
  }
  return uVar1;
}



void __cdecl FUN_0040201f(short param_1,undefined4 *param_2)

{
  int iVar1;
  int iVar2;
  undefined4 *puVar3;
  undefined local_444 [4];
  undefined4 *local_440;
  undefined4 local_43c;
  undefined local_438 [4];
  undefined4 local_434;
  undefined4 local_430;
  undefined4 local_42c;
  undefined2 local_38;
  undefined4 local_36 [9];
  undefined4 local_10;
  undefined2 uStack_c;
  uint local_8;
  
  local_8 = DAT_00431c20 ^ (uint)&stack0xfffffffc;
  local_10 = DAT_0042b8ec;
  local_440 = param_2;
  uStack_c = DAT_0042b8f0;
  local_38 = 0;
  puVar3 = local_36;
  for (iVar2 = 9; iVar2 != 0; iVar2 = iVar2 + -1) {
    *puVar3 = 0;
    puVar3 = puVar3 + 1;
  }
  *(undefined2 *)puVar3 = 0;
  local_10 = CONCAT22(local_10._2_2_,(short)local_10 + param_1);
  local_43c = 0;
  func_0x1c712131(&local_38,&DAT_0042b8f4,&local_10);
  iVar2 = (*DAT_00428210)(&local_38,0x80000000,3,0,3,0,0);
  if (iVar2 != -1) {
    iVar1 = (*DAT_0042820c)(iVar2,0x560000,0,0,local_438,0x400,local_444,0);
    if (iVar1 != 0) {
      local_43c = func_0x4ba0228e(local_430,local_42c,0x200,0);
      *local_440 = local_434;
    }
  }
  if (iVar2 != 0) {
    (*DAT_00428224)(iVar2);
  }
  func_0x485e22c0();
  return;
}



void __fastcall FUN_0040210c(undefined4 param_1,uint param_2)

{
  int iVar1;
  undefined4 *puVar2;
  undefined2 local_28;
  undefined4 local_26 [7];
  uint local_8;
  
  local_8 = DAT_00431c20 ^ (uint)&stack0xfffffffc;
  local_28 = 0;
  puVar2 = local_26;
  for (iVar1 = 7; iVar1 != 0; iVar1 = iVar1 + -1) {
    *puVar2 = 0;
    puVar2 = puVar2 + 1;
  }
  *(undefined2 *)puVar2 = 0;
  func_0x3471220b(&local_28,&DAT_0042b904,param_2 >> 0x18,param_2 >> 0x10 & 0xff,param_2 >> 8 & 0xff
                  ,param_2 & 0xff);
  func_0xd45e2317();
  func_0x485e2325();
  return;
}



void __cdecl FUN_00402171(int param_1)

{
  int iVar1;
  int iVar2;
  uint uVar3;
  int *piVar4;
  int iVar5;
  int local_78 [4];
  undefined4 local_68;
  undefined4 local_58;
  undefined4 local_40;
  undefined4 local_28;
  undefined4 local_18;
  int local_c;
  
  piVar4 = local_78;
  for (iVar2 = 0x1a; iVar2 != 0; iVar2 = iVar2 + -1) {
    *piVar4 = -1;
    piVar4 = piVar4 + 1;
  }
  local_18 = 1;
  local_28 = 1;
  local_40 = 1;
  local_58 = 1;
  local_68 = 1;
  local_78[0] = 1;
  local_c = func_0xe651225a(5);
  iVar5 = 0;
  iVar2 = 0;
  if (0 < local_c) {
    do {
      iVar1 = func_0xe6512270(0);
      while (uVar3 = local_78[iVar1] + iVar5 >> 0x1f,
            1 < (int)((local_78[iVar1] + iVar5 ^ uVar3) - uVar3)) {
        iVar1 = iVar1 + 1;
        if (iVar1 == 0x1a) {
          iVar1 = 0;
        }
      }
      iVar5 = iVar5 + local_78[iVar1];
      *(short *)(param_1 + iVar2 * 2) = (short)iVar1 + 0x61;
      iVar2 = iVar2 + 1;
    } while (iVar2 < local_c);
  }
  return;
}



void FUN_004021ef(undefined4 param_1)

{
  func_0x555f23b1();
  func_0x5b9f23d0();
  return;
}



void __cdecl FUN_0040221d(int *param_1)

{
  uint uVar1;
  byte local_210 [516];
  uint local_c;
  
  local_c = DAT_00431c20 ^ (uint)&stack0xfffffffc;
  if ((param_1 != (int *)0x0) && (*param_1 == 0x504d534d)) {
    func_0x8b5f240e(local_210,param_1,0x200);
    uVar1 = 0;
    do {
      local_210[uVar1] = ~local_210[uVar1];
      uVar1 = uVar1 + 1;
    } while (uVar1 < 0x200);
    func_0x7f52232a();
  }
  func_0x485e243c();
  return;
}



// WARNING: Control flow encountered bad instruction data

undefined4 __cdecl FUN_00402366(undefined4 param_1,undefined4 param_2)

{
  int iVar1;
  undefined4 uVar2;
  int iVar3;
  undefined4 local_8;
  
  local_8 = 0;
  iVar1 = func_0xb6632538(&local_8,param_1,&DAT_0042b8a0);
  if (iVar1 == 0) {
    func_0x886a2553(local_8,0,2);
    iVar1 = func_0xaa6c255b(local_8);
    func_0x886a2567(local_8,0,0);
    uVar2 = func_0x676d2573(iVar1 + 0x32);
    func_0xa9662581(uVar2,iVar1,1,local_8);
    func_0x3d672589(local_8);
    func_0x0d542493(0x32);
    iVar3 = func_0xb66325a4(&local_8,param_2,&DAT_0042b91c);
    if (iVar3 == 0) {
      func_0x7c6925bb(uVar2,iVar1 + 0x32,1,local_8);
      func_0x3d6725c3(local_8);
      return 1;
    }
  }
                    // WARNING: Bad instruction - Truncating control flow here
  halt_baddata();
}



// WARNING: Globals starting with '_' overlap smaller symbols at the same address

void FUN_004025d1(void)

{
  short sVar1;
  undefined4 *puVar2;
  int iVar3;
  undefined4 *puVar4;
  undefined local_3dc [400];
  short local_24c;
  undefined local_24a [518];
  short local_44;
  undefined local_42 [58];
  uint local_8;
  
  local_8 = DAT_00431c20 ^ (uint)&stack0xfffffffc;
  local_24c = 0;
  func_0x3b8227ba(local_24a,0,0x206);
  (*DAT_004283fc)(0x101,local_3dc);
  iVar3 = func_0xd74926db(1);
  if (iVar3 == 0) {
    local_44 = 0;
    func_0x3b8227f7(local_42,0,0x3a);
    func_0x75572702();
    iVar3 = 0;
    do {
      sVar1 = *(short *)(local_42 + iVar3 + -2);
      *(short *)((int)&DAT_00436628 + iVar3) = sVar1;
      iVar3 = iVar3 + 2;
    } while (sVar1 != 0);
    func_0xd45e2828(&LAB_00436484,0x40,&DAT_0042b938);
    _DAT_00436504 = 0x51;
    func_0xd45e2845(&DAT_00436506,0x10,&DAT_0042b800);
    func_0xd45e2859(&DAT_00436526,0x40,&DAT_0042b7b0);
    _DAT_004365a6 = 0x2b66;
    iVar3 = 0;
    do {
      sVar1 = *(short *)(local_42 + iVar3 + -2);
      *(short *)((int)&DAT_00436608 + iVar3) = sVar1;
      iVar3 = iVar3 + 2;
    } while (sVar1 != 0);
    puVar2 = (undefined4 *)0x436606;
    do {
      puVar4 = puVar2;
      puVar2 = (undefined4 *)((int)puVar4 + 2);
    } while (*(short *)((int)puVar4 + 2) != 0);
    *(undefined4 *)((int)puVar4 + 2) = DAT_0042b954;
    *(undefined2 *)((int)puVar4 + 6) = DAT_0042b958;
    _DAT_00436648 = 5;
  }
  func_0x035827a7();
  func_0x755727b2();
  iVar3 = 0;
  do {
    sVar1 = *(short *)(local_24a + iVar3 + -2);
    *(short *)((int)&DAT_004368b8 + iVar3) = sVar1;
    iVar3 = iVar3 + 2;
  } while (sVar1 != 0);
  iVar3 = (*DAT_00428228)(0x20000,0,&DAT_004368b8);
  if (iVar3 == 0) {
    iVar3 = (*DAT_00428220)(0,0,0,&DAT_004368b8);
    if (iVar3 != 0) {
      func_0xea592803();
      _DAT_00436940 = DAT_0043664c;
      _DAT_00432fc4 = (*DAT_004281f4)(0,0,0x402e65,0,0,0);
    }
  }
  else {
    (*DAT_00428224)(iVar3);
  }
  func_0x485e2932();
  return;
}



void FUN_0040277e(void)

{
  short sVar1;
  undefined2 *puVar2;
  short *psVar3;
  int iVar4;
  int unaff_EDI;
  undefined2 local_210;
  undefined local_20e [518];
  uint local_8;
  
  local_8 = DAT_00431c20 ^ (uint)&stack0xfffffffc;
  local_210 = 0;
  func_0x3b822963(local_20e,0,0x206);
  (*DAT_00428238)(0,&local_210,0x104);
  puVar2 = (undefined2 *)func_0xe66e2988(&local_210,0x5c);
  *puVar2 = 0;
  psVar3 = puVar2 + 1;
  puVar2 = (undefined2 *)func_0xe66e2999(psVar3,0x2e);
  *puVar2 = 0;
  iVar4 = unaff_EDI - (int)psVar3;
  do {
    sVar1 = *psVar3;
    *(short *)(iVar4 + (int)psVar3) = sVar1;
    psVar3 = psVar3 + 1;
  } while (sVar1 != 0);
  func_0x485e29c0();
  return;
}



uint FUN_00402895(undefined4 param_1)

{
  undefined4 *puVar1;
  uint uVar2;
  uint uVar3;
  int iVar4;
  int iVar5;
  int local_1c [4];
  uint local_c;
  undefined local_8 [4];
  
  iVar5 = 0;
  local_1c[0] = 0;
  local_1c[1] = 0;
  local_1c[2] = 0;
  local_1c[3] = 0;
  do {
    puVar1 = (undefined4 *)func_0x0aba2967(0x20);
    local_1c[iVar5] = (int)puVar1;
    iVar5 = iVar5 + 1;
    for (iVar4 = 8; iVar4 != 0; iVar4 = iVar4 + -1) {
      *puVar1 = 0;
      puVar1 = puVar1 + 1;
    }
  } while (iVar5 < 4);
  iVar5 = func_0x44592987(local_1c);
  if (iVar5 == 4) {
    iVar5 = FUN_00414256(local_1c[0],local_8,10);
    uVar3 = func_0x4d722ab1(local_1c[1],local_8,10);
    local_c = func_0x4d722ac0(local_1c[2],local_8,10);
    uVar2 = func_0x4d722ad0(local_1c[3],local_8,10);
    uVar2 = uVar2 | ((iVar5 << 8 | uVar3) << 8 | local_c) << 8;
    iVar5 = 0;
    do {
      if (local_1c[iVar5] != 0) {
        func_0x15ba29f6(local_1c[iVar5]);
      }
      iVar5 = iVar5 + 1;
    } while (iVar5 < 4);
  }
  else {
    uVar2 = 0;
  }
  return uVar2;
}



int __cdecl FUN_0040294d(int param_1)

{
  int *piVar1;
  short sVar2;
  short *in_EAX;
  short *psVar3;
  int iVar4;
  int iVar5;
  int iVar6;
  
  iVar5 = 0;
  psVar3 = in_EAX;
  do {
    sVar2 = *psVar3;
    psVar3 = psVar3 + 1;
  } while (sVar2 != 0);
  if ((int)psVar3 - (int)(in_EAX + 1) >> 1 == 0) {
    iVar5 = 0;
  }
  else {
    iVar4 = func_0xb9672b39();
    while (iVar4 != 0) {
      iVar6 = iVar4 - (int)in_EAX >> 1;
      if (0xf < iVar6) {
        iVar6 = 0xf;
      }
      piVar1 = (int *)(param_1 + iVar5 * 4);
      func_0x78722b67(*piVar1,in_EAX,iVar6);
      in_EAX = (short *)(iVar4 + 2);
      iVar5 = iVar5 + 1;
      *(undefined2 *)(*piVar1 + iVar6 * 2) = 0;
      iVar4 = func_0xb9672b82(in_EAX,&DAT_0042b95c);
    }
    func_0xd45e2b9e(*(undefined4 *)(param_1 + iVar5 * 4),0xf,in_EAX);
    iVar5 = iVar5 + 1;
  }
  return iVar5;
}



void __fastcall FUN_00402b20(int param_1)

{
  undefined4 *puVar1;
  undefined4 uVar2;
  int iVar3;
  undefined4 local_78 [10];
  int local_50;
  int local_4c;
  undefined2 local_48;
  undefined local_46 [62];
  uint local_8;
  
  local_8 = DAT_00431c20 ^ (uint)&stack0xfffffffc;
  puVar1 = local_78;
  local_78[0] = 0;
  for (iVar3 = 9; puVar1 = puVar1 + 1, iVar3 != 0; iVar3 = iVar3 + -1) {
    *puVar1 = 0;
  }
  local_50 = 0;
  func_0x3b822d09(param_1,0,0x9a);
  local_4c = 0;
  do {
    puVar1 = (undefined4 *)func_0x0aba2c16(0x20);
    local_78[local_4c] = puVar1;
    local_4c = local_4c + 1;
    for (iVar3 = 8; iVar3 != 0; iVar3 = iVar3 + -1) {
      *puVar1 = 0;
      puVar1 = puVar1 + 1;
    }
  } while (local_4c < 10);
  func_0xe15b2c41(param_1 + 0x4a,local_78,&local_50);
  if (0 < local_50) {
    uVar2 = func_0x8c582c51(local_78[0]);
    *(undefined4 *)(param_1 + 0x50) = uVar2;
    local_48 = 0;
    func_0x3b822d66(local_46,0,0x3e);
    iVar3 = func_0x325d2c72(local_78[0],&local_48);
    if (iVar3 == 1) {
      func_0xd45e2d89(param_1 + 0x58,0x21,&local_48);
    }
  }
  func_0x485e2d9e();
  return;
}



void __cdecl FUN_00402bea(undefined4 *param_1,int param_2,int *param_3)

{
  char cVar1;
  int iVar2;
  undefined4 *puVar3;
  int iVar4;
  int iVar5;
  undefined4 *puVar6;
  bool bVar7;
  undefined4 local_38;
  undefined4 *local_34;
  int local_30;
  undefined4 *local_2c;
  short local_28;
  undefined4 local_26 [7];
  uint local_8;
  
  local_8 = DAT_00431c20 ^ (uint)&stack0xfffffffc;
  local_30 = -1;
  local_28 = 0;
  puVar6 = local_26;
  for (iVar4 = 7; iVar4 != 0; iVar4 = iVar4 + -1) {
    *puVar6 = 0;
    puVar6 = puVar6 + 1;
  }
  *(undefined2 *)puVar6 = 0;
  iVar4 = 0;
  local_2c = (undefined4 *)func_0x676d2de6(0x288);
  local_38 = 0x288;
  iVar2 = func_0x69962ef7(local_2c,&local_38);
  if (iVar2 == 0x6f) {
    func_0xc2722e04(local_2c);
    local_2c = (undefined4 *)func_0x676d2e0c(local_38);
  }
  iVar2 = func_0x69962f1d(local_2c,&local_38);
  puVar6 = local_2c;
  if (iVar2 == 0) {
    while (local_34 = puVar6, local_34 != (undefined4 *)0x0) {
      local_30 = local_30 + 1;
      if (param_1 != (undefined4 *)0x0) {
        *param_1 = local_34[0x65];
        *(undefined2 *)(param_1 + 1) = *(undefined2 *)(local_34 + 0x66);
      }
      for (puVar6 = local_34 + 0x6b; puVar6 != (undefined4 *)0x0; puVar6 = (undefined4 *)*puVar6) {
        puVar3 = puVar6 + 1;
        do {
          cVar1 = *(char *)puVar3;
          puVar3 = (undefined4 *)((int)puVar3 + 1);
        } while (cVar1 != '\0');
        iVar2 = (int)puVar3 - ((int)puVar6 + 5);
        if (0x10 < iVar2) {
          iVar2 = 0x10;
        }
        iVar5 = 0;
        if (-1 < iVar2) {
          bVar7 = iVar2 == 0;
          do {
            if (bVar7) {
              *(undefined2 *)((int)local_26 + iVar5 * 2 + -2) = 0;
            }
            *(short *)((int)local_26 + iVar5 * 2 + -2) = (short)*(char *)((int)(puVar6 + 1) + iVar5)
            ;
            iVar5 = iVar5 + 1;
            bVar7 = iVar5 == iVar2;
          } while (iVar5 <= iVar2);
        }
        iVar2 = func_0x8c582d97(&local_28);
        if (iVar2 != 0) {
          func_0xd45e2ead(*(undefined4 *)(param_2 + iVar4 * 4),0x10,&local_28);
        }
        iVar4 = iVar4 + 1;
      }
      if (0 < iVar4) break;
      puVar6 = (undefined4 *)*local_34;
    }
  }
  *param_3 = iVar4;
  if (local_2c != (undefined4 *)0x0) {
    func_0xc2722ee1(local_2c);
  }
  func_0x485e2eef();
  return;
}



// WARNING: Type propagation algorithm not settling

undefined4 __cdecl FUN_00402d3b(short *param_1,undefined4 param_2)

{
  short sVar1;
  undefined4 *puVar2;
  short *psVar3;
  undefined4 uVar4;
  int iVar5;
  int iVar6;
  undefined4 local_38 [11];
  undefined4 local_c;
  int local_8;
  
  puVar2 = local_38;
  local_38[0] = 0;
  for (iVar5 = 9; puVar2 = puVar2 + 1, iVar5 != 0; iVar5 = iVar5 + -1) {
    *puVar2 = 0;
  }
  local_8 = 0;
  iVar5 = 0;
  do {
    puVar2 = (undefined4 *)func_0x0aba2e15(0x20);
    local_38[iVar5] = puVar2;
    iVar5 = iVar5 + 1;
    for (iVar6 = 8; iVar6 != 0; iVar6 = iVar6 + -1) {
      *puVar2 = 0;
      puVar2 = puVar2 + 1;
    }
  } while (iVar5 < 10);
  psVar3 = param_1;
  do {
    sVar1 = *psVar3;
    psVar3 = psVar3 + 1;
  } while (sVar1 != 0);
  if (((int)psVar3 - (int)(param_1 + 1) >> 1 == 0) || (param_1 == (short *)0x0)) {
    func_0xe15b2e9b(0,local_38,&local_8);
    if (local_8 == 0) {
      return 0;
    }
  }
  else {
    func_0xd45e2f51(local_38[0],0x10,param_1);
  }
  uVar4 = func_0x8c582e5c(local_38[0]);
  local_c = (*DAT_004283f8)(uVar4);
  puVar2 = (undefined4 *)(*DAT_004283f4)(&local_c,4,2);
  if (puVar2 == (undefined4 *)0x0) {
    return 0;
  }
  func_0xe85d2e83(*puVar2,param_2);
  return 1;
}



undefined2 * __cdecl FUN_00402df1(char *param_1,undefined2 *param_2)

{
  char cVar1;
  code *pcVar2;
  char *pcVar3;
  int iVar4;
  int local_8;
  
  pcVar2 = DAT_004281f0;
  iVar4 = 0x20;
  pcVar3 = param_1;
  do {
    cVar1 = *pcVar3;
    pcVar3 = pcVar3 + 1;
  } while (cVar1 != '\0');
  local_8 = (int)pcVar3 - (int)(param_1 + 1);
  if (param_2 == (undefined2 *)0x0) {
    iVar4 = (*DAT_004281f0)(0,0,param_1,0xffffffff,0,0);
    param_2 = (undefined2 *)func_0x676d2fe6(iVar4 * 2);
  }
  if (local_8 == 0) {
    *param_2 = 0;
  }
  else {
    if ((0 < iVar4) && (iVar4 + -1 < local_8)) {
      local_8 = iVar4 + -1;
    }
    (*pcVar2)(0,0,param_1,0xffffffff,param_2,local_8 + 1);
  }
  return param_2;
}



void FUN_00402e69(void)

{
  short sVar1;
  code *pcVar2;
  undefined4 *puVar3;
  int iVar4;
  undefined4 *puVar5;
  short local_208;
  undefined local_206 [510];
  uint local_8;
  
  local_8 = DAT_00431c20 ^ (uint)&stack0xfffffffc;
  local_208 = 0;
  func_0x3b82304f(local_206,0,0x1fe);
  iVar4 = 0;
  do {
    sVar1 = *(short *)((int)&DAT_004368b8 + iVar4);
    *(short *)(local_206 + iVar4 + -2) = sVar1;
    iVar4 = iVar4 + 2;
  } while (sVar1 != 0);
  puVar3 = (undefined4 *)&stack0xfffffdf6;
  do {
    puVar5 = puVar3;
    puVar3 = (undefined4 *)((int)puVar5 + 2);
  } while (*(short *)((int)puVar5 + 2) != 0);
  *(undefined4 *)((int)puVar5 + 2) = DAT_0042b7a4;
  *(undefined4 *)((int)puVar5 + 6) = DAT_0042b7a8;
  *(undefined4 *)((int)puVar5 + 10) = DAT_0042b7ac;
  do {
    iVar4 = (*DAT_00428228)(0x20000,0,&local_208);
    (*DAT_0042821c)(200);
  } while (iVar4 == 0);
  (*DAT_00428224)(iVar4);
  (*DAT_004281ec)(0);
  pcVar2 = (code *)swi(3);
  (*pcVar2)();
  return;
}



void __fastcall FUN_00402f04(uint param_1)

{
  undefined local_18;
  undefined4 local_17;
  undefined4 uStack_13;
  undefined4 uStack_f;
  undefined2 uStack_b;
  undefined uStack_9;
  uint local_8;
  
  local_8 = DAT_00431c20 ^ (uint)&stack0xfffffffc;
  local_18 = 0;
  local_17 = 0;
  uStack_13 = 0;
  uStack_f = 0;
  uStack_b = 0;
  uStack_9 = 0;
  func_0x4c713002(&local_18,&DAT_0042b960,param_1 >> 0x18,param_1 >> 0x10 & 0xff,param_1 >> 8 & 0xff
                  ,param_1 & 0xff);
  func_0x316e310e();
  func_0x485e311c();
  return;
}



void FUN_00402f68(void)

{
  undefined2 *puVar1;
  undefined local_210 [520];
  uint local_8;
  
  local_8 = DAT_00431c20 ^ (uint)&stack0xfffffffc;
  (*DAT_00428238)(0,local_210,0x104);
  puVar1 = (undefined2 *)func_0xe66e3155(local_210,0x5c);
  *puVar1 = 0;
  func_0xd45e3168();
  func_0x485e3176();
  return;
}



void FUN_00402fc4(void)

{
  int iVar1;
  int iVar2;
  int iVar3;
  undefined4 uVar4;
  undefined uVar5;
  
  uVar5 = 0;
  iVar1 = func_0x7a6030ad(DAT_00432fb4);
  if (iVar1 != 0) {
    if (DAT_00432fc0 == 3) {
      uVar4 = 0x2bac;
    }
    else {
      uVar4 = 0x2ba2;
    }
    iVar2 = func_0x7a6030d7(uVar4);
    if (iVar2 != 0) {
      if (DAT_00436786 != 0) {
        func_0xfb5e30f1();
      }
      iVar3 = func_0x7a603102(DAT_00432fb4);
      if ((((iVar3 != 0) && (iVar1 == 1)) && (iVar2 == 1)) && (iVar3 == 1)) {
        func_0x7a60312a(DAT_00432fb4);
      }
    }
  }
  func_0x485e3237(uVar5);
  return;
}



void __thiscall FUN_00403083(void *this,undefined4 param_1)

{
  int iVar1;
  int iVar2;
  short *psVar3;
  int *piVar4;
  int *piVar5;
  bool bVar6;
  short local_42c;
  undefined local_42a [258];
  int local_328 [65];
  undefined2 local_224;
  undefined local_222 [518];
  undefined local_1c;
  undefined4 local_1b;
  undefined4 uStack_17;
  undefined4 uStack_13;
  undefined4 uStack_f;
  undefined2 uStack_b;
  undefined uStack_9;
  uint local_8;
  
  local_8 = DAT_00431c20 ^ (uint)&stack0xfffffffc;
  iVar1 = func_0xeb61315a(param_1,this);
  if (iVar1 == 0) {
    local_224 = 0;
    func_0x3b823286(local_222,0,0x206);
    local_42c = 0;
    func_0x3b82329d(local_42a,0,0x206);
    func_0x5f5f31a8();
    func_0x575e32bb(&local_224,0x104,&DAT_0042b8a8);
    local_1c = 0;
    local_1b = 0;
    uStack_17 = 0;
    uStack_13 = 0;
    uStack_f = 0;
    uStack_b = 0;
    uStack_9 = 0;
    psVar3 = &DAT_00435b68;
    do {
      if (*psVar3 != 0) {
        func_0xd45e32ed(&local_42c,0x104,&local_224);
        func_0x575e32fb(&local_42c,0x104,psVar3);
        psVar3 = &local_42c;
        if (CONCAT31((int3)((uint)psVar3 >> 8),(byte)psVar3 ^ (byte)local_42c) != 0) {
          iVar2 = 5;
          bVar6 = true;
          piVar4 = (int *)&local_1c;
          piVar5 = local_328;
          do {
            if (iVar2 == 0) break;
            iVar2 = iVar2 + -1;
            bVar6 = *piVar4 == *piVar5;
            piVar4 = piVar4 + 1;
            piVar5 = piVar5 + 1;
          } while (bVar6);
          if (bVar6) {
            local_42c = 0;
          }
        }
      }
      psVar3 = psVar3 + 0x8c;
    } while ((int)psVar3 < 0x4360e0);
    psVar3 = &DAT_00435b68;
    do {
      if (*psVar3 != 0) {
        func_0x6f693254(this,param_1);
      }
      psVar3 = psVar3 + 0x8c;
    } while ((int)psVar3 < 0x4360e0);
    func_0x575e3376(&local_224,0x104,&DAT_00436b38);
    iVar2 = (*DAT_00428230)(&local_224);
    if (iVar2 == -1) {
      iVar1 = 2;
    }
  }
  func_0x485e33a8(this,iVar1);
  return;
}



// WARNING: Control flow encountered bad instruction data

void __thiscall FUN_004033cb(void *this,undefined4 param_1)

{
  undefined2 *puVar1;
  int iVar2;
  int *unaff_ESI;
  undefined4 local_9ac;
  undefined local_9a8 [400];
  undefined2 local_818;
  undefined2 local_816;
  undefined4 local_814;
  undefined2 local_808 [1024];
  uint local_8;
  
  local_8 = DAT_00431c20 ^ (uint)&stack0xfffffffc;
  puVar1 = local_808;
  if (this != (void *)0x0) {
    puVar1 = (undefined2 *)this;
  }
  *puVar1 = 0;
  local_9ac = 0;
  iVar2 = (*DAT_004283fc)(0x101,local_9a8);
  if (iVar2 != 0) {
                    // WARNING: Bad instruction - Truncating control flow here
    halt_baddata();
  }
  iVar2 = (*DAT_004283f0)(2,1,6);
  *unaff_ESI = iVar2;
  if (iVar2 == -1) {
    return;
  }
  iVar2 = (*DAT_004283ec)();
  if (iVar2 == 0) {
    local_9ac = (*DAT_004283e8)();
    iVar2 = (*DAT_004283f4)(&local_9ac,4,2);
    if (iVar2 != 0) goto LAB_00403455;
  }
  else {
LAB_00403455:
    local_814 = *(undefined4 *)**(undefined4 **)(iVar2 + 0xc);
    local_818 = 2;
    local_816 = (*DAT_004283e4)(param_1);
    iVar2 = (*DAT_004283e0)(*unaff_ESI,&local_818,0x10);
    if (iVar2 == 0) goto LAB_004034a5;
  }
  if (*unaff_ESI != 0) {
    (*DAT_004283dc)(*unaff_ESI);
    *unaff_ESI = 0;
  }
LAB_004034a5:
  func_0x485e3668();
  return;
}



undefined4 __cdecl FUN_004035e0(int *param_1,int param_2,int param_3)

{
  int *piVar1;
  int iVar2;
  int iVar3;
  undefined4 local_c;
  
  iVar3 = 0;
  local_c = 0;
  if (*param_1 != 0) {
    if (0 < param_3) {
      do {
        *(byte *)(param_2 + iVar3) = ~*(byte *)(param_2 + iVar3);
        iVar3 = iVar3 + 1;
      } while (iVar3 < param_3);
    }
    iVar3 = param_3 + 7;
    piVar1 = (int *)func_0x0aba36c9(iVar3);
    *(short *)piVar1 = (short)param_3 + 5;
    *(undefined4 *)((int)piVar1 + 2) = DAT_00433040;
    *(undefined *)((int)piVar1 + 6) = DAT_00433044;
    func_0xfbcc37ea((int)piVar1 + 7,param_2,param_3);
    iVar2 = (*DAT_004283d8)(*param_1,piVar1,iVar3,0);
    param_1 = piVar1;
    if ((iVar2 != -1) && (iVar2 == iVar3)) {
      local_c = 1;
    }
  }
  if (param_1 != (int *)0x0) {
    func_0x15ba3720(param_1);
  }
  return local_c;
}



// WARNING: Control flow encountered bad instruction data
// WARNING: Globals starting with '_' overlap smaller symbols at the same address

void FUN_00403c56(void)

{
  short sVar1;
  undefined4 *puVar2;
  int iVar3;
  short *psVar4;
  int iVar5;
  undefined4 *puVar6;
  undefined4 local_24c;
  undefined4 local_248;
  undefined4 local_244;
  undefined4 local_240;
  undefined2 local_23c;
  undefined local_23a [522];
  short local_30;
  undefined4 local_2e [9];
  uint local_8;
  
  local_8 = DAT_00431c20 ^ (uint)&stack0xfffffffc;
  local_23c = 0;
  func_0x3b823e3f(local_23a,0,0x206);
  local_30 = 0;
  puVar6 = local_2e;
  for (iVar5 = 9; iVar5 != 0; iVar5 = iVar5 + -1) {
    *puVar6 = 0;
    puVar6 = puVar6 + 1;
  }
  *(undefined2 *)puVar6 = 0;
  local_248 = 0;
  local_24c = 0x104;
  puVar6 = &DAT_00436608;
  do {
    puVar2 = puVar6;
    puVar6 = (undefined4 *)((int)puVar2 + 2);
  } while (*(short *)puVar2 != 0);
  if (((int)(puVar2 + -0x10d982) >> 1 == 0) ||
     (iVar5 = (*DAT_00428228)(0x20000,0,&DAT_00436608), iVar5 == 0)) {
    iVar5 = (*(code *)s_InitCommonControls_00428003._9_4_)
                      (0x80000001,&DAT_0042b810,0,0xf003f,&local_240);
    if (iVar5 == 0) {
      iVar5 = (*_DAT_00428000)(local_240,&DAT_0042b98c,0,&local_248,&local_30,&local_24c);
      if ((iVar5 == 0) && (iVar5 = (*DAT_00428228)(0x20000,0,&local_30), iVar5 != 0)) {
        (*(code *)s_InitCommonControls_00428003._1_4_)(local_240);
                    // WARNING: Bad instruction - Truncating control flow here
        halt_baddata();
      }
      (*(code *)s_InitCommonControls_00428003._1_4_)(local_240);
    }
    local_244 = 0;
    (*DAT_00428234)(0x104,&local_23c);
    puVar6 = &DAT_00436608;
    do {
      puVar2 = puVar6;
      puVar6 = (undefined4 *)((int)puVar2 + 2);
    } while (*(short *)puVar2 != 0);
    if ((int)(puVar2 + -0x10d982) >> 1 == 0) {
      func_0x575e3f47(&local_23c,0x104,&DAT_0042b99c);
      iVar5 = 0;
      do {
        sVar1 = *(short *)((int)&DAT_0042b99c + iVar5);
        *(short *)((int)local_2e + iVar5 + -2) = sVar1;
        iVar5 = iVar5 + 2;
      } while (sVar1 != 0);
    }
    else {
      func_0x575e3f69(&local_23c,0x104,&DAT_00436608);
      iVar5 = 0;
      do {
        sVar1 = *(short *)((int)&DAT_00436608 + iVar5);
        *(short *)((int)local_2e + iVar5 + -2) = sVar1;
        iVar5 = iVar5 + 2;
      } while (sVar1 != 0);
    }
    func_0x575e3f93(&local_23c,0x104,&DAT_0042b798);
    iVar5 = func_0x9a6e3ea2(&local_244);
    if (iVar5 != 0) {
      func_0x046f3ec0(&local_23c,iVar5,local_244);
      (*DAT_0042821c)(100);
      (*DAT_00428264)(0,0,&local_23c,&DAT_0042b9c8,0,1);
      iVar3 = (*(code *)s_InitCommonControls_00428003._9_4_)
                        (0x80000001,&DAT_0042b810,0,3,&local_240);
      if (iVar3 == 0) {
        psVar4 = &local_30;
        do {
          sVar1 = *psVar4;
          psVar4 = psVar4 + 1;
        } while (sVar1 != 0);
        iVar3 = (*(code *)s_InitCommonControls_00428003._5_4_)
                          (local_240,&DAT_0042b98c,0,1,&local_30,
                           ((int)psVar4 - (int)local_2e >> 1) * 2 + 2);
        if (iVar3 == 0) {
          (*(code *)s_InitCommonControls_00428003._1_4_)(local_240);
        }
      }
      func_0x15ba3f47(iVar5);
    }
  }
  func_0x485e4057();
  return;
}



bool __cdecl FUN_00403f0d(undefined4 param_1,undefined4 param_2,int param_3)

{
  int iVar1;
  undefined4 uVar2;
  undefined4 uVar3;
  bool bVar4;
  
  bVar4 = false;
  iVar1 = (*DAT_00428230)(param_1);
  if ((iVar1 != -1) && (iVar1 = func_0xa46f3fe3(param_1), iVar1 == param_3)) {
    return true;
  }
  uVar2 = func_0x676d40f7(0x200000);
  iVar1 = func_0xf96f400c(param_2,param_3,uVar2);
  if (iVar1 != 0) {
    uVar3 = (*DAT_00428218)();
    func_0x435f411f(uVar3);
    iVar1 = func_0xe651402c(0x32);
    func_0x0d54403c(iVar1);
    iVar1 = func_0x6770404a(param_1,uVar2,iVar1 + 0x200000);
    bVar4 = iVar1 == 1;
  }
  func_0xc272415b(uVar2);
  return bVar4;
}



undefined8 __cdecl FUN_00403fad(undefined4 param_1)

{
  int iVar1;
  int iVar2;
  undefined4 uVar3;
  undefined4 uVar4;
  undefined4 local_10;
  undefined4 local_c;
  
  uVar4 = 0xffffffff;
  iVar1 = (*DAT_00428210)(param_1,0x80000000,3,0,3,0,0);
  if (iVar1 == -1) {
    uVar3 = 0xffffffff;
  }
  else {
    iVar2 = (*DAT_004281d4)(iVar1,&local_10);
    uVar3 = 0xffffffff;
    if (iVar2 == 1) {
      uVar3 = local_c;
      uVar4 = local_10;
    }
    (*DAT_00428224)(iVar1);
  }
  return CONCAT44(uVar3,uVar4);
}



void __cdecl FUN_00404002(undefined4 param_1,undefined4 param_2,undefined4 param_3)

{
  int iVar1;
  undefined4 *unaff_EDI;
  undefined4 local_14;
  
  iVar1 = func_0x68b840d8(param_1,param_2);
  if (iVar1 != 0) {
    func_0x0ab940ed(0xffffffff);
    func_0x0ab940fd(0);
    func_0x4ab9410a(param_3,*unaff_EDI);
    *unaff_EDI = local_14;
    func_0x7bb94116();
  }
  func_0x485e4224();
  return;
}



bool __cdecl FUN_00404070(undefined4 param_1,uint param_2,uint param_3)

{
  int iVar1;
  int iVar2;
  bool bVar3;
  
  bVar3 = false;
  iVar1 = (*DAT_00428230)(param_1);
  if (((iVar1 == -1) || (iVar1 = func_0xd2704142(), iVar1 != 0)) &&
     (iVar1 = (*DAT_00428210)(param_1,0x40000000,1,0,2,0,0), iVar1 != -1)) {
    iVar2 = (*DAT_004281f8)(iVar1,param_2,param_3,&param_2,0);
    bVar3 = (-(uint)(iVar2 != 0) & param_2) == param_3;
    (*DAT_00428224)(iVar1);
  }
  return bVar3;
}



// WARNING: Control flow encountered bad instruction data
// WARNING: Globals starting with '_' overlap smaller symbols at the same address

void FUN_0040416d(undefined4 param_1,undefined4 param_2,short *param_3)

{
  short *psVar1;
  short sVar2;
  int iVar3;
  uint uVar4;
  undefined4 uStack_24c;
  undefined4 uStack_248;
  undefined4 uStack_244;
  undefined4 uStack_240;
  undefined4 uStack_23c;
  undefined4 uStack_238;
  undefined4 uStack_234;
  undefined4 uStack_230;
  undefined4 uStack_22c;
  undefined auStack_21c [528];
  uint local_c;
  
  local_c = DAT_00431c20 ^ (uint)auStack_21c;
  iVar3 = 0;
  do {
    psVar1 = (short *)((int)&DAT_0042b9cc + iVar3);
    *(short *)((int)&DAT_004361a8 + iVar3) = *psVar1;
    iVar3 = iVar3 + 2;
  } while (*psVar1 != 0);
  iVar3 = 0;
  do {
    psVar1 = (short *)((int)&DAT_0042b9dc + iVar3);
    *(short *)((int)&DAT_004360e0 + iVar3) = *psVar1;
    iVar3 = iVar3 + 2;
  } while (*psVar1 != 0);
  uStack_22c = 0x4041c4;
  func_0x2e73427a();
  iVar3 = (int)&DAT_00436278 - (int)param_3;
  do {
    sVar2 = *param_3;
    *(short *)(iVar3 + (int)param_3) = sVar2;
    param_3 = param_3 + 1;
  } while (sVar2 != 0);
  uStack_22c = 0x4041e1;
  DAT_00432fc0 = FUN_00401004();
  uStack_22c = 2000;
  uStack_230 = 0x4041f1;
  (*DAT_0042821c)();
  uStack_230 = 0x4041f6;
  iVar3 = func_0x974042ac();
  if (iVar3 != 0) {
    uStack_230 = 0x4041ff;
    func_0x4f5442b5();
    uStack_230 = 0;
    uStack_234 = 0x404206;
    (*DAT_004281ec)();
  }
  uStack_230 = 0;
  uStack_234 = param_1;
  uStack_238 = 0;
  uStack_23c = 0;
  uStack_240 = 0;
  uStack_244 = 0x80000000;
  uStack_248 = 0;
  uStack_24c = 0x80000000;
  _DAT_00436270 = param_1;
  iVar3 = (*DAT_0042838c)(0,&DAT_004360e0,&DAT_004361a8,0xcf0000);
  if (iVar3 != 0) {
    iVar3 = func_0xc85542ee();
    if (iVar3 != 0) {
      uStack_24c = uStack_24c & 0xffff0000;
      func_0x3b824422((int)&uStack_24c + 2,0,0x206);
      if ((DAT_00436780 != 0) && (DAT_00436784 != 0)) {
        func_0xfb5e4342();
        DAT_00432fb4 = DAT_00436784;
      }
      uVar4 = (*DAT_00428218)();
      func_0x10744374(&DAT_00436b38,&DAT_0042b9ec,(int)(((ulonglong)uVar4 / 1000) % 1000));
      func_0xbb5f437c();
      func_0x5f5f4385();
      func_0x575e4498(&uStack_24c,0x104,&DAT_0042b8a8);
      func_0x575e44a5(&uStack_24c,0x104,&DAT_00436b38);
      iVar3 = (*DAT_00428230)(&uStack_24c);
      if (iVar3 != -1) {
        (*DAT_0042821c)(500);
        (*DAT_00428264)(0,0,&uStack_24c,&DAT_0042b9c8,0,1);
      }
      (*DAT_0042821c)(5000);
      func_0x4d6c43e6();
                    // WARNING: Bad instruction - Truncating control flow here
      halt_baddata();
    }
  }
  func_0x485e4405();
  return;
}



void FUN_00404337(void)

{
  code *pcVar1;
  undefined4 in_EAX;
  undefined4 local_34;
  undefined4 local_30;
  undefined4 local_2c;
  undefined4 local_28;
  undefined4 local_24;
  undefined4 local_20;
  undefined4 local_1c;
  undefined4 local_18;
  undefined4 local_14;
  undefined *local_10;
  undefined2 *local_c;
  undefined4 local_8;
  
  pcVar1 = DAT_00428364;
  local_28 = 0;
  local_24 = 0;
  local_34 = 0x30;
  local_30 = 3;
  local_2c = 0x4043a4;
  local_20 = in_EAX;
  local_1c = (*DAT_00428364)();
  local_18 = (*DAT_00428368)(0,0x7f00);
  local_14 = 6;
  local_10 = &DAT_0042ba04;
  local_c = &DAT_004360e0;
  local_8 = (*pcVar1)(local_20,0x6c);
  (*DAT_0042836c)(&local_34);
  return;
}



void FUN_004043a8(undefined4 param_1,int param_2,undefined4 param_3,undefined4 param_4)

{
  undefined local_4c [68];
  uint local_8;
  
  local_8 = DAT_00431c20 ^ (uint)&stack0xfffffffc;
  if (param_2 == 2) {
    (*DAT_0042839c)(0);
  }
  else if (param_2 == 0xf) {
    (*DAT_00428394)(param_1,local_4c);
    (*DAT_00428398)(param_1,local_4c);
  }
  else {
    if (param_2 == 0x111) {
      param_2 = 0x111;
    }
    (*DAT_00428390)(param_1,param_2,param_3,param_4);
  }
  func_0x485e45cb();
  return;
}



void FUN_00404434(void)

{
  int in_EAX;
  uint uVar1;
  uint uVar2;
  uint uVar3;
  uint uVar4;
  uint uVar5;
  uint uVar6;
  uint uVar7;
  uint uVar8;
  
  uVar2 = *(uint *)(in_EAX + 8);
  uVar3 = *(uint *)(in_EAX + 0xc);
  uVar8 = uVar3 >> 2 | uVar3 << 0x1e;
  uVar3 = (uVar2 >> 0x1b | uVar2 << 5) +
          ((*(uint *)(in_EAX + 0x14) ^ *(uint *)(in_EAX + 0x10)) & uVar3 ^ *(uint *)(in_EAX + 0x14))
          + *(int *)(in_EAX + 0x18) + 0x5a827999 + *(int *)(in_EAX + 0x1c);
  uVar1 = uVar2 >> 2 | uVar2 << 0x1e;
  uVar2 = *(int *)(in_EAX + 0x14) + 0x5a827999 +
          (uVar3 >> 0x1b | uVar3 * 0x20) +
          ((*(uint *)(in_EAX + 0x10) ^ uVar8) & uVar2 ^ *(uint *)(in_EAX + 0x10)) +
          *(int *)(in_EAX + 0x20);
  uVar4 = *(int *)(in_EAX + 0x10) + 0x5a827999 +
          ((uVar8 ^ uVar1) & uVar3 ^ uVar8) +
          (uVar2 >> 0x1b | uVar2 * 0x20) + *(int *)(in_EAX + 0x24);
  uVar6 = uVar3 >> 2 | uVar3 * 0x40000000;
  uVar5 = uVar2 >> 2 | uVar2 * 0x40000000;
  uVar3 = uVar8 + 0x5a827999 +
          (uVar4 >> 0x1b | uVar4 * 0x20) + ((uVar6 ^ uVar1) & uVar2 ^ uVar1) +
          *(int *)(in_EAX + 0x28);
  uVar8 = uVar4 >> 2 | uVar4 * 0x40000000;
  uVar2 = uVar1 + 0x5a827999 +
          (uVar3 >> 0x1b | uVar3 * 0x20) + ((uVar6 ^ uVar5) & uVar4 ^ uVar6) +
          *(int *)(in_EAX + 0x2c);
  uVar1 = uVar3 >> 2 | uVar3 * 0x40000000;
  uVar3 = uVar6 + 0x5a827999 +
          (uVar2 >> 0x1b | uVar2 * 0x20) + ((uVar5 ^ uVar8) & uVar3 ^ uVar5) +
          *(int *)(in_EAX + 0x30);
  uVar4 = uVar5 + 0x5a827999 +
          (uVar3 >> 0x1b | uVar3 * 0x20) + ((uVar8 ^ uVar1) & uVar2 ^ uVar8) +
          *(int *)(in_EAX + 0x34);
  uVar6 = uVar2 >> 2 | uVar2 * 0x40000000;
  uVar2 = uVar8 + 0x5a827999 +
          (uVar4 >> 0x1b | uVar4 * 0x20) + ((uVar1 ^ uVar6) & uVar3 ^ uVar1) +
          *(int *)(in_EAX + 0x38);
  uVar7 = uVar3 >> 2 | uVar3 * 0x40000000;
  uVar5 = uVar4 >> 2 | uVar4 * 0x40000000;
  uVar3 = uVar1 + 0x5a827999 +
          ((uVar7 ^ uVar6) & uVar4 ^ uVar6) +
          (uVar2 >> 0x1b | uVar2 * 0x20) + *(int *)(in_EAX + 0x3c);
  uVar4 = uVar2 >> 2 | uVar2 * 0x40000000;
  uVar2 = uVar6 + 0x5a827999 +
          (uVar3 >> 0x1b | uVar3 * 0x20) + ((uVar7 ^ uVar5) & uVar2 ^ uVar7) +
          *(int *)(in_EAX + 0x40);
  uVar8 = uVar3 >> 2 | uVar3 * 0x40000000;
  uVar3 = uVar7 + 0x5a827999 +
          (uVar2 >> 0x1b | uVar2 * 0x20) + ((uVar5 ^ uVar4) & uVar3 ^ uVar5) +
          *(int *)(in_EAX + 0x44);
  uVar1 = uVar2 >> 2 | uVar2 * 0x40000000;
  uVar2 = uVar5 + 0x5a827999 +
          (uVar3 >> 0x1b | uVar3 * 0x20) + ((uVar4 ^ uVar8) & uVar2 ^ uVar4) +
          *(int *)(in_EAX + 0x48);
  uVar6 = uVar3 >> 2 | uVar3 * 0x40000000;
  uVar3 = uVar4 + 0x5a827999 +
          (uVar2 >> 0x1b | uVar2 * 0x20) + ((uVar8 ^ uVar1) & uVar3 ^ uVar8) +
          *(int *)(in_EAX + 0x4c);
  uVar4 = uVar8 + 0x5a827999 +
          ((uVar6 ^ uVar1) & uVar2 ^ uVar1) +
          (uVar3 >> 0x1b | uVar3 * 0x20) + *(uint *)(in_EAX + 0x50);
  uVar7 = uVar2 >> 2 | uVar2 * 0x40000000;
  uVar5 = uVar3 >> 2 | uVar3 * 0x40000000;
  uVar2 = *(uint *)(in_EAX + 0x50) ^ *(uint *)(in_EAX + 0x3c) ^ *(uint *)(in_EAX + 0x24) ^
          *(uint *)(in_EAX + 0x1c);
  uVar3 = uVar1 + 0x5a827999 +
          (uVar4 >> 0x1b | uVar4 * 0x20) + ((uVar6 ^ uVar7) & uVar3 ^ uVar6) +
          *(int *)(in_EAX + 0x54);
  uVar8 = uVar4 >> 2 | uVar4 * 0x40000000;
  uVar1 = uVar2 << 1 | (uint)((int)uVar2 < 0);
  uVar2 = uVar6 + 0x5a827999 +
          (uVar3 >> 0x1b | uVar3 * 0x20) + ((uVar7 ^ uVar5) & uVar4 ^ uVar7) +
          *(int *)(in_EAX + 0x58);
  *(uint *)(in_EAX + 0x1c) = uVar1;
  uVar4 = uVar7 + 0x5a827999 +
          ((uVar5 ^ uVar8) & uVar3 ^ uVar5) + (uVar2 >> 0x1b | uVar2 * 0x20) + uVar1;
  uVar6 = uVar3 >> 2 | uVar3 * 0x40000000;
  uVar3 = *(uint *)(in_EAX + 0x40) ^ *(uint *)(in_EAX + 0x54) ^ *(uint *)(in_EAX + 0x28) ^
          *(uint *)(in_EAX + 0x20);
  uVar3 = uVar3 << 1 | (uint)((int)uVar3 < 0);
  *(uint *)(in_EAX + 0x20) = uVar3;
  uVar1 = uVar2 >> 2 | uVar2 * 0x40000000;
  uVar3 = uVar5 + 0x5a827999 +
          ((uVar8 ^ uVar6) & uVar2 ^ uVar8) + (uVar4 >> 0x1b | uVar4 * 0x20) + uVar3;
  uVar2 = *(uint *)(in_EAX + 0x58) ^ *(uint *)(in_EAX + 0x44) ^ *(uint *)(in_EAX + 0x2c) ^
          *(uint *)(in_EAX + 0x24);
  uVar2 = uVar2 << 1 | (uint)((int)uVar2 < 0);
  uVar5 = uVar4 >> 2 | uVar4 * 0x40000000;
  *(uint *)(in_EAX + 0x24) = uVar2;
  uVar2 = uVar8 + 0x5a827999 +
          ((uVar1 ^ uVar6) & uVar4 ^ uVar6) + (uVar3 >> 0x1b | uVar3 * 0x20) + uVar2;
  uVar4 = *(uint *)(in_EAX + 0x48) ^ *(uint *)(in_EAX + 0x30) ^ *(uint *)(in_EAX + 0x1c) ^
          *(uint *)(in_EAX + 0x28);
  uVar4 = uVar4 << 1 | (uint)((int)uVar4 < 0);
  *(uint *)(in_EAX + 0x28) = uVar4;
  uVar8 = uVar3 >> 2 | uVar3 * 0x40000000;
  uVar3 = uVar6 + 0x5a827999 +
          ((uVar1 ^ uVar5) & uVar3 ^ uVar1) + (uVar2 >> 0x1b | uVar2 * 0x20) + uVar4;
  uVar4 = *(uint *)(in_EAX + 0x4c) ^ *(uint *)(in_EAX + 0x34) ^ *(uint *)(in_EAX + 0x2c) ^
          *(uint *)(in_EAX + 0x20);
  uVar4 = uVar4 << 1 | (uint)((int)uVar4 < 0);
  *(uint *)(in_EAX + 0x2c) = uVar4;
  uVar4 = uVar1 + 0x6ed9eba1 + (uVar5 ^ uVar8 ^ uVar2) + (uVar3 >> 0x1b | uVar3 * 0x20) + uVar4;
  uVar1 = uVar2 >> 2 | uVar2 * 0x40000000;
  uVar2 = *(uint *)(in_EAX + 0x50) ^ *(uint *)(in_EAX + 0x38) ^ *(uint *)(in_EAX + 0x30) ^
          *(uint *)(in_EAX + 0x24);
  uVar2 = uVar2 << 1 | (uint)((int)uVar2 < 0);
  *(uint *)(in_EAX + 0x30) = uVar2;
  uVar2 = uVar5 + 0x6ed9eba1 + (uVar8 ^ uVar1 ^ uVar3) + (uVar4 >> 0x1b | uVar4 * 0x20) + uVar2;
  uVar5 = *(uint *)(in_EAX + 0x54) ^ *(uint *)(in_EAX + 0x3c) ^ *(uint *)(in_EAX + 0x34) ^
          *(uint *)(in_EAX + 0x28);
  uVar6 = uVar3 >> 2 | uVar3 * 0x40000000;
  uVar3 = uVar5 << 1 | (uint)((int)uVar5 < 0);
  uVar5 = uVar4 >> 2 | uVar4 * 0x40000000;
  *(uint *)(in_EAX + 0x34) = uVar3;
  uVar3 = uVar8 + 0x6ed9eba1 + (uVar4 ^ uVar1 ^ uVar6) + (uVar2 >> 0x1b | uVar2 * 0x20) + uVar3;
  uVar4 = *(uint *)(in_EAX + 0x58) ^ *(uint *)(in_EAX + 0x40) ^ *(uint *)(in_EAX + 0x38) ^
          *(uint *)(in_EAX + 0x2c);
  uVar4 = uVar4 << 1 | (uint)((int)uVar4 < 0);
  uVar8 = uVar2 >> 2 | uVar2 * 0x40000000;
  *(uint *)(in_EAX + 0x38) = uVar4;
  uVar2 = uVar1 + 0x6ed9eba1 + (uVar5 ^ uVar2 ^ uVar6) + (uVar3 >> 0x1b | uVar3 * 0x20) + uVar4;
  uVar4 = *(uint *)(in_EAX + 0x30) ^ *(uint *)(in_EAX + 0x44) ^ *(uint *)(in_EAX + 0x3c) ^
          *(uint *)(in_EAX + 0x1c);
  uVar4 = uVar4 << 1 | (uint)((int)uVar4 < 0);
  *(uint *)(in_EAX + 0x3c) = uVar4;
  uVar4 = uVar6 + 0x6ed9eba1 + (uVar5 ^ uVar8 ^ uVar3) + (uVar2 >> 0x1b | uVar2 * 0x20) + uVar4;
  uVar1 = uVar3 >> 2 | uVar3 * 0x40000000;
  uVar3 = *(uint *)(in_EAX + 0x48) ^ *(uint *)(in_EAX + 0x40) ^ *(uint *)(in_EAX + 0x34) ^
          *(uint *)(in_EAX + 0x20);
  uVar3 = uVar3 << 1 | (uint)((int)uVar3 < 0);
  *(uint *)(in_EAX + 0x40) = uVar3;
  uVar3 = uVar5 + 0x6ed9eba1 + (uVar8 ^ uVar1 ^ uVar2) + (uVar4 >> 0x1b | uVar4 * 0x20) + uVar3;
  uVar5 = uVar2 >> 2 | uVar2 * 0x40000000;
  uVar2 = *(uint *)(in_EAX + 0x38) ^ *(uint *)(in_EAX + 0x4c) ^ *(uint *)(in_EAX + 0x44) ^
          *(uint *)(in_EAX + 0x24);
  uVar2 = uVar2 << 1 | (uint)((int)uVar2 < 0);
  *(uint *)(in_EAX + 0x44) = uVar2;
  uVar2 = uVar8 + 0x6ed9eba1 + (uVar1 ^ uVar5 ^ uVar4) + (uVar3 >> 0x1b | uVar3 * 0x20) + uVar2;
  uVar8 = *(uint *)(in_EAX + 0x50) ^ *(uint *)(in_EAX + 0x48) ^ *(uint *)(in_EAX + 0x3c) ^
          *(uint *)(in_EAX + 0x28);
  uVar6 = uVar4 >> 2 | uVar4 * 0x40000000;
  uVar8 = uVar8 << 1 | (uint)((int)uVar8 < 0);
  uVar4 = uVar3 >> 2 | uVar3 * 0x40000000;
  *(uint *)(in_EAX + 0x48) = uVar8;
  uVar3 = uVar1 + 0x6ed9eba1 + (uVar3 ^ uVar5 ^ uVar6) + (uVar2 >> 0x1b | uVar2 * 0x20) + uVar8;
  uVar8 = *(uint *)(in_EAX + 0x40) ^ *(uint *)(in_EAX + 0x54) ^ *(uint *)(in_EAX + 0x4c) ^
          *(uint *)(in_EAX + 0x2c);
  uVar1 = uVar8 << 1 | (uint)((int)uVar8 < 0);
  uVar8 = uVar2 >> 2 | uVar2 * 0x40000000;
  *(uint *)(in_EAX + 0x4c) = uVar1;
  uVar2 = uVar5 + 0x6ed9eba1 + (uVar4 ^ uVar2 ^ uVar6) + (uVar3 >> 0x1b | uVar3 * 0x20) + uVar1;
  uVar5 = *(uint *)(in_EAX + 0x58) ^ *(uint *)(in_EAX + 0x50) ^ *(uint *)(in_EAX + 0x30) ^
          *(uint *)(in_EAX + 0x44);
  uVar1 = uVar5 << 1 | (uint)((int)uVar5 < 0);
  uVar5 = uVar3 >> 2 | uVar3 * 0x40000000;
  *(uint *)(in_EAX + 0x50) = uVar1;
  uVar3 = uVar6 + 0x6ed9eba1 + (uVar4 ^ uVar8 ^ uVar3) + (uVar2 >> 0x1b | uVar2 * 0x20) + uVar1;
  uVar1 = *(uint *)(in_EAX + 0x48) ^ *(uint *)(in_EAX + 0x54) ^ *(uint *)(in_EAX + 0x34) ^
          *(uint *)(in_EAX + 0x1c);
  uVar6 = uVar1 << 1 | (uint)((int)uVar1 < 0);
  *(uint *)(in_EAX + 0x54) = uVar6;
  uVar1 = uVar2 >> 2 | uVar2 * 0x40000000;
  uVar2 = uVar4 + 0x6ed9eba1 + (uVar8 ^ uVar5 ^ uVar2) + (uVar3 >> 0x1b | uVar3 * 0x20) + uVar6;
  uVar4 = *(uint *)(in_EAX + 0x58) ^ *(uint *)(in_EAX + 0x38) ^ *(uint *)(in_EAX + 0x4c) ^
          *(uint *)(in_EAX + 0x20);
  uVar4 = uVar4 << 1 | (uint)((int)uVar4 < 0);
  *(uint *)(in_EAX + 0x58) = uVar4;
  uVar4 = uVar8 + 0x6ed9eba1 + (uVar5 ^ uVar1 ^ uVar3) + (uVar2 >> 0x1b | uVar2 * 0x20) + uVar4;
  uVar8 = *(uint *)(in_EAX + 0x50) ^ *(uint *)(in_EAX + 0x3c) ^ *(uint *)(in_EAX + 0x1c) ^
          *(uint *)(in_EAX + 0x24);
  uVar6 = uVar3 >> 2 | uVar3 * 0x40000000;
  uVar3 = uVar8 << 1 | (uint)((int)uVar8 < 0);
  *(uint *)(in_EAX + 0x1c) = uVar3;
  uVar8 = uVar2 >> 2 | uVar2 * 0x40000000;
  uVar3 = uVar5 + 0x6ed9eba1 + (uVar2 ^ uVar1 ^ uVar6) + (uVar4 >> 0x1b | uVar4 * 0x20) + uVar3;
  uVar2 = *(uint *)(in_EAX + 0x40) ^ *(uint *)(in_EAX + 0x54) ^ *(uint *)(in_EAX + 0x28) ^
          *(uint *)(in_EAX + 0x20);
  uVar2 = uVar2 << 1 | (uint)((int)uVar2 < 0);
  uVar5 = uVar4 >> 2 | uVar4 * 0x40000000;
  *(uint *)(in_EAX + 0x20) = uVar2;
  uVar2 = uVar1 + 0x6ed9eba1 + (uVar8 ^ uVar4 ^ uVar6) + (uVar3 >> 0x1b | uVar3 * 0x20) + uVar2;
  uVar4 = *(uint *)(in_EAX + 0x58) ^ *(uint *)(in_EAX + 0x44) ^ *(uint *)(in_EAX + 0x2c) ^
          *(uint *)(in_EAX + 0x24);
  uVar4 = uVar4 << 1 | (uint)((int)uVar4 < 0);
  *(uint *)(in_EAX + 0x24) = uVar4;
  uVar1 = uVar3 >> 2 | uVar3 * 0x40000000;
  uVar3 = uVar6 + 0x6ed9eba1 + (uVar8 ^ uVar5 ^ uVar3) + (uVar2 >> 0x1b | uVar2 * 0x20) + uVar4;
  uVar4 = *(uint *)(in_EAX + 0x48) ^ *(uint *)(in_EAX + 0x30) ^ *(uint *)(in_EAX + 0x1c) ^
          *(uint *)(in_EAX + 0x28);
  uVar4 = uVar4 << 1 | (uint)((int)uVar4 < 0);
  *(uint *)(in_EAX + 0x28) = uVar4;
  uVar6 = uVar2 >> 2 | uVar2 * 0x40000000;
  uVar2 = uVar8 + 0x6ed9eba1 + (uVar5 ^ uVar1 ^ uVar2) + (uVar3 >> 0x1b | uVar3 * 0x20) + uVar4;
  uVar4 = *(uint *)(in_EAX + 0x4c) ^ *(uint *)(in_EAX + 0x34) ^ *(uint *)(in_EAX + 0x2c) ^
          *(uint *)(in_EAX + 0x20);
  uVar4 = uVar4 << 1 | (uint)((int)uVar4 < 0);
  *(uint *)(in_EAX + 0x2c) = uVar4;
  uVar4 = uVar5 + 0x6ed9eba1 + (uVar1 ^ uVar6 ^ uVar3) + (uVar2 >> 0x1b | uVar2 * 0x20) + uVar4;
  uVar5 = *(uint *)(in_EAX + 0x50) ^ *(uint *)(in_EAX + 0x38) ^ *(uint *)(in_EAX + 0x30) ^
          *(uint *)(in_EAX + 0x24);
  uVar7 = uVar3 >> 2 | uVar3 * 0x40000000;
  uVar3 = uVar5 << 1 | (uint)((int)uVar5 < 0);
  *(uint *)(in_EAX + 0x30) = uVar3;
  uVar5 = uVar2 >> 2 | uVar2 * 0x40000000;
  uVar3 = uVar1 + 0x6ed9eba1 + (uVar2 ^ uVar6 ^ uVar7) + (uVar4 >> 0x1b | uVar4 * 0x20) + uVar3;
  uVar2 = *(uint *)(in_EAX + 0x54) ^ *(uint *)(in_EAX + 0x3c) ^ *(uint *)(in_EAX + 0x34) ^
          *(uint *)(in_EAX + 0x28);
  uVar2 = uVar2 << 1 | (uint)((int)uVar2 < 0);
  *(uint *)(in_EAX + 0x34) = uVar2;
  uVar8 = uVar4 >> 2 | uVar4 * 0x40000000;
  uVar2 = uVar6 + 0x6ed9eba1 + (uVar5 ^ uVar4 ^ uVar7) + (uVar3 >> 0x1b | uVar3 * 0x20) + uVar2;
  uVar4 = *(uint *)(in_EAX + 0x58) ^ *(uint *)(in_EAX + 0x40) ^ *(uint *)(in_EAX + 0x38) ^
          *(uint *)(in_EAX + 0x2c);
  uVar1 = uVar4 << 1 | (uint)((int)uVar4 < 0);
  *(uint *)(in_EAX + 0x38) = uVar1;
  uVar4 = uVar3 >> 2 | uVar3 * 0x40000000;
  uVar6 = *(uint *)(in_EAX + 0x30) ^ *(uint *)(in_EAX + 0x44) ^ *(uint *)(in_EAX + 0x3c) ^
          *(uint *)(in_EAX + 0x1c);
  uVar3 = uVar7 + 0x6ed9eba1 + (uVar5 ^ uVar8 ^ uVar3) + (uVar2 >> 0x1b | uVar2 * 0x20) + uVar1;
  uVar6 = uVar6 << 1 | (uint)((int)uVar6 < 0);
  *(uint *)(in_EAX + 0x3c) = uVar6;
  uVar1 = uVar2 >> 2 | uVar2 * 0x40000000;
  uVar7 = *(uint *)(in_EAX + 0x48) ^ *(uint *)(in_EAX + 0x40) ^ *(uint *)(in_EAX + 0x34) ^
          *(uint *)(in_EAX + 0x20);
  uVar7 = uVar7 << 1 | (uint)((int)uVar7 < 0);
  uVar2 = ((uVar4 ^ uVar2) & uVar8 | uVar4 & uVar2) + uVar6 + uVar5 + -0x70e44324 +
          (uVar3 >> 0x1b | uVar3 * 0x20);
  *(uint *)(in_EAX + 0x40) = uVar7;
  uVar5 = uVar3 >> 2 | uVar3 * 0x40000000;
  uVar6 = *(uint *)(in_EAX + 0x38) ^ *(uint *)(in_EAX + 0x4c) ^ *(uint *)(in_EAX + 0x44) ^
          *(uint *)(in_EAX + 0x24);
  uVar3 = ((uVar1 ^ uVar3) & uVar4 | uVar1 & uVar3) + uVar7 + uVar8 + -0x70e44324 +
          (uVar2 >> 0x1b | uVar2 * 0x20);
  uVar8 = uVar6 << 1 | (uint)((int)uVar6 < 0);
  *(uint *)(in_EAX + 0x44) = uVar8;
  uVar6 = *(uint *)(in_EAX + 0x50) ^ *(uint *)(in_EAX + 0x48) ^ *(uint *)(in_EAX + 0x3c) ^
          *(uint *)(in_EAX + 0x28);
  uVar4 = ((uVar2 ^ uVar5) & uVar1 | uVar2 & uVar5) + uVar8 + uVar4 + -0x70e44324 +
          (uVar3 >> 0x1b | uVar3 * 0x20);
  uVar7 = uVar2 >> 2 | uVar2 * 0x40000000;
  uVar2 = uVar6 << 1 | (uint)((int)uVar6 < 0);
  *(uint *)(in_EAX + 0x48) = uVar2;
  uVar8 = uVar3 >> 2 | uVar3 * 0x40000000;
  uVar6 = *(uint *)(in_EAX + 0x40) ^ *(uint *)(in_EAX + 0x54) ^ *(uint *)(in_EAX + 0x4c) ^
          *(uint *)(in_EAX + 0x2c);
  uVar3 = ((uVar7 ^ uVar3) & uVar5 | uVar7 & uVar3) + uVar2 + uVar1 + -0x70e44324 +
          (uVar4 >> 0x1b | uVar4 * 0x20);
  uVar2 = uVar6 << 1 | (uint)((int)uVar6 < 0);
  *(uint *)(in_EAX + 0x4c) = uVar2;
  uVar1 = uVar4 >> 2 | uVar4 * 0x40000000;
  uVar2 = ((uVar8 ^ uVar4) & uVar7 | uVar8 & uVar4) + uVar2 + uVar5 + -0x70e44324 +
          (uVar3 >> 0x1b | uVar3 * 0x20);
  uVar4 = *(uint *)(in_EAX + 0x58) ^ *(uint *)(in_EAX + 0x50) ^ *(uint *)(in_EAX + 0x30) ^
          *(uint *)(in_EAX + 0x44);
  uVar4 = uVar4 << 1 | (uint)((int)uVar4 < 0);
  *(uint *)(in_EAX + 0x50) = uVar4;
  uVar5 = uVar3 >> 2 | uVar3 * 0x40000000;
  uVar6 = *(uint *)(in_EAX + 0x48) ^ *(uint *)(in_EAX + 0x54) ^ *(uint *)(in_EAX + 0x34) ^
          *(uint *)(in_EAX + 0x1c);
  uVar3 = ((uVar1 ^ uVar3) & uVar8 | uVar1 & uVar3) + uVar4 + uVar7 + -0x70e44324 +
          (uVar2 >> 0x1b | uVar2 * 0x20);
  uVar4 = uVar6 << 1 | (uint)((int)uVar6 < 0);
  *(uint *)(in_EAX + 0x54) = uVar4;
  uVar6 = uVar2 >> 2 | uVar2 * 0x40000000;
  uVar7 = *(uint *)(in_EAX + 0x58) ^ *(uint *)(in_EAX + 0x38) ^ *(uint *)(in_EAX + 0x4c) ^
          *(uint *)(in_EAX + 0x20);
  uVar2 = ((uVar5 ^ uVar2) & uVar1 | uVar5 & uVar2) + uVar4 + uVar8 + -0x70e44324 +
          (uVar3 >> 0x1b | uVar3 * 0x20);
  uVar4 = uVar7 << 1 | (uint)((int)uVar7 < 0);
  *(uint *)(in_EAX + 0x58) = uVar4;
  uVar8 = *(uint *)(in_EAX + 0x50) ^ *(uint *)(in_EAX + 0x3c) ^ *(uint *)(in_EAX + 0x1c) ^
          *(uint *)(in_EAX + 0x24);
  uVar4 = ((uVar3 ^ uVar6) & uVar5 | uVar3 & uVar6) + uVar4 + uVar1 + -0x70e44324 +
          (uVar2 >> 0x1b | uVar2 * 0x20);
  uVar7 = uVar3 >> 2 | uVar3 * 0x40000000;
  uVar3 = uVar8 << 1 | (uint)((int)uVar8 < 0);
  *(uint *)(in_EAX + 0x1c) = uVar3;
  uVar8 = uVar2 >> 2 | uVar2 * 0x40000000;
  uVar3 = ((uVar7 ^ uVar2) & uVar6 | uVar7 & uVar2) + uVar3 + uVar5 + -0x70e44324 +
          (uVar4 >> 0x1b | uVar4 * 0x20);
  uVar2 = *(uint *)(in_EAX + 0x40) ^ *(uint *)(in_EAX + 0x54) ^ *(uint *)(in_EAX + 0x28) ^
          *(uint *)(in_EAX + 0x20);
  uVar2 = uVar2 << 1 | (uint)((int)uVar2 < 0);
  *(uint *)(in_EAX + 0x20) = uVar2;
  uVar5 = uVar4 >> 2 | uVar4 * 0x40000000;
  uVar1 = *(uint *)(in_EAX + 0x58) ^ *(uint *)(in_EAX + 0x44) ^ *(uint *)(in_EAX + 0x2c) ^
          *(uint *)(in_EAX + 0x24);
  uVar2 = ((uVar8 ^ uVar4) & uVar7 | uVar8 & uVar4) + uVar2 + uVar6 + -0x70e44324 +
          (uVar3 >> 0x1b | uVar3 * 0x20);
  uVar1 = uVar1 << 1 | (uint)((int)uVar1 < 0);
  *(uint *)(in_EAX + 0x24) = uVar1;
  uVar6 = *(uint *)(in_EAX + 0x48) ^ *(uint *)(in_EAX + 0x30) ^ *(uint *)(in_EAX + 0x1c) ^
          *(uint *)(in_EAX + 0x28);
  uVar4 = uVar3 >> 2 | uVar3 * 0x40000000;
  uVar3 = ((uVar5 ^ uVar3) & uVar8 | uVar5 & uVar3) + uVar1 + uVar7 + -0x70e44324 +
          (uVar2 >> 0x1b | uVar2 * 0x20);
  uVar6 = uVar6 << 1 | (uint)((int)uVar6 < 0);
  *(uint *)(in_EAX + 0x28) = uVar6;
  uVar1 = uVar2 >> 2 | uVar2 * 0x40000000;
  uVar7 = *(uint *)(in_EAX + 0x4c) ^ *(uint *)(in_EAX + 0x34) ^ *(uint *)(in_EAX + 0x2c) ^
          *(uint *)(in_EAX + 0x20);
  uVar2 = ((uVar4 ^ uVar2) & uVar5 | uVar4 & uVar2) + uVar6 + uVar8 + -0x70e44324 +
          (uVar3 >> 0x1b | uVar3 * 0x20);
  uVar8 = uVar7 << 1 | (uint)((int)uVar7 < 0);
  *(uint *)(in_EAX + 0x2c) = uVar8;
  uVar6 = *(uint *)(in_EAX + 0x50) ^ *(uint *)(in_EAX + 0x38) ^ *(uint *)(in_EAX + 0x30) ^
          *(uint *)(in_EAX + 0x24);
  uVar7 = uVar3 >> 2 | uVar3 * 0x40000000;
  uVar3 = ((uVar3 ^ uVar1) & uVar4 | uVar3 & uVar1) + uVar8 + uVar5 + -0x70e44324 +
          (uVar2 >> 0x1b | uVar2 * 0x20);
  uVar8 = uVar6 << 1 | (uint)((int)uVar6 < 0);
  *(uint *)(in_EAX + 0x30) = uVar8;
  uVar5 = uVar2 >> 2 | uVar2 * 0x40000000;
  uVar2 = ((uVar7 ^ uVar2) & uVar1 | uVar7 & uVar2) + uVar8 + uVar4 + -0x70e44324 +
          (uVar3 >> 0x1b | uVar3 * 0x20);
  uVar4 = *(uint *)(in_EAX + 0x54) ^ *(uint *)(in_EAX + 0x3c) ^ *(uint *)(in_EAX + 0x34) ^
          *(uint *)(in_EAX + 0x28);
  uVar8 = uVar4 << 1 | (uint)((int)uVar4 < 0);
  *(uint *)(in_EAX + 0x34) = uVar8;
  uVar4 = uVar3 >> 2 | uVar3 * 0x40000000;
  uVar6 = *(uint *)(in_EAX + 0x58) ^ *(uint *)(in_EAX + 0x40) ^ *(uint *)(in_EAX + 0x38) ^
          *(uint *)(in_EAX + 0x2c);
  uVar3 = ((uVar5 ^ uVar3) & uVar7 | uVar5 & uVar3) + uVar8 + uVar1 + -0x70e44324 +
          (uVar2 >> 0x1b | uVar2 * 0x20);
  uVar1 = uVar6 << 1 | (uint)((int)uVar6 < 0);
  *(uint *)(in_EAX + 0x38) = uVar1;
  uVar6 = *(uint *)(in_EAX + 0x30) ^ *(uint *)(in_EAX + 0x44) ^ *(uint *)(in_EAX + 0x3c) ^
          *(uint *)(in_EAX + 0x1c);
  uVar8 = uVar2 >> 2 | uVar2 * 0x40000000;
  uVar2 = ((uVar4 ^ uVar2) & uVar5 | uVar4 & uVar2) + uVar1 + uVar7 + -0x70e44324 +
          (uVar3 >> 0x1b | uVar3 * 0x20);
  uVar6 = uVar6 << 1 | (uint)((int)uVar6 < 0);
  *(uint *)(in_EAX + 0x3c) = uVar6;
  uVar1 = uVar3 >> 2 | uVar3 * 0x40000000;
  uVar7 = *(uint *)(in_EAX + 0x48) ^ *(uint *)(in_EAX + 0x40) ^ *(uint *)(in_EAX + 0x34) ^
          *(uint *)(in_EAX + 0x20);
  uVar3 = ((uVar8 ^ uVar3) & uVar4 | uVar8 & uVar3) + uVar6 + uVar5 + -0x70e44324 +
          (uVar2 >> 0x1b | uVar2 * 0x20);
  uVar5 = uVar7 << 1 | (uint)((int)uVar7 < 0);
  *(uint *)(in_EAX + 0x40) = uVar5;
  uVar4 = ((uVar2 ^ uVar1) & uVar8 | uVar2 & uVar1) + uVar5 + uVar4 + -0x70e44324 +
          (uVar3 >> 0x1b | uVar3 * 0x20);
  uVar7 = uVar2 >> 2 | uVar2 * 0x40000000;
  uVar2 = *(uint *)(in_EAX + 0x38) ^ *(uint *)(in_EAX + 0x4c) ^ *(uint *)(in_EAX + 0x44) ^
          *(uint *)(in_EAX + 0x24);
  uVar2 = uVar2 << 1 | (uint)((int)uVar2 < 0);
  *(uint *)(in_EAX + 0x44) = uVar2;
  uVar5 = uVar3 >> 2 | uVar3 * 0x40000000;
  uVar6 = *(uint *)(in_EAX + 0x50) ^ *(uint *)(in_EAX + 0x48) ^ *(uint *)(in_EAX + 0x3c) ^
          *(uint *)(in_EAX + 0x28);
  uVar3 = ((uVar7 ^ uVar3) & uVar1 | uVar7 & uVar3) + uVar2 + uVar8 + -0x70e44324 +
          (uVar4 >> 0x1b | uVar4 * 0x20);
  uVar2 = uVar6 << 1 | (uint)((int)uVar6 < 0);
  *(uint *)(in_EAX + 0x48) = uVar2;
  uVar6 = *(uint *)(in_EAX + 0x40) ^ *(uint *)(in_EAX + 0x54) ^ *(uint *)(in_EAX + 0x4c) ^
          *(uint *)(in_EAX + 0x2c);
  uVar8 = uVar4 >> 2 | uVar4 * 0x40000000;
  uVar2 = ((uVar5 ^ uVar4) & uVar7 | uVar5 & uVar4) + uVar2 + uVar1 + -0x70e44324 +
          (uVar3 >> 0x1b | uVar3 * 0x20);
  uVar4 = uVar6 << 1 | (uint)((int)uVar6 < 0);
  *(uint *)(in_EAX + 0x4c) = uVar4;
  uVar6 = *(uint *)(in_EAX + 0x58) ^ *(uint *)(in_EAX + 0x50) ^ *(uint *)(in_EAX + 0x30) ^
          *(uint *)(in_EAX + 0x44);
  uVar1 = uVar3 >> 2 | uVar3 * 0x40000000;
  uVar3 = (uVar5 ^ uVar8 ^ uVar3) + uVar4 + uVar7 + -0x359d3e2a + (uVar2 >> 0x1b | uVar2 * 0x20);
  uVar4 = uVar6 << 1 | (uint)((int)uVar6 < 0);
  *(uint *)(in_EAX + 0x50) = uVar4;
  uVar7 = *(uint *)(in_EAX + 0x48) ^ *(uint *)(in_EAX + 0x54) ^ *(uint *)(in_EAX + 0x34) ^
          *(uint *)(in_EAX + 0x1c);
  uVar6 = uVar2 >> 2 | uVar2 * 0x40000000;
  uVar2 = (uVar8 ^ uVar1 ^ uVar2) + uVar4 + uVar5 + -0x359d3e2a + (uVar3 >> 0x1b | uVar3 * 0x20);
  uVar4 = uVar7 << 1 | (uint)((int)uVar7 < 0);
  *(uint *)(in_EAX + 0x54) = uVar4;
  uVar4 = (uVar3 ^ uVar1 ^ uVar6) + uVar4 + uVar8 + -0x359d3e2a + (uVar2 >> 0x1b | uVar2 * 0x20);
  uVar7 = uVar3 >> 2 | uVar3 * 0x40000000;
  uVar3 = *(uint *)(in_EAX + 0x58) ^ *(uint *)(in_EAX + 0x38) ^ *(uint *)(in_EAX + 0x4c) ^
          *(uint *)(in_EAX + 0x20);
  uVar3 = uVar3 << 1 | (uint)((int)uVar3 < 0);
  *(uint *)(in_EAX + 0x58) = uVar3;
  uVar5 = uVar2 >> 2 | uVar2 * 0x40000000;
  uVar8 = *(uint *)(in_EAX + 0x50) ^ *(uint *)(in_EAX + 0x3c) ^ *(uint *)(in_EAX + 0x1c) ^
          *(uint *)(in_EAX + 0x24);
  uVar3 = (uVar7 ^ uVar2 ^ uVar6) + uVar3 + uVar1 + -0x359d3e2a + (uVar4 >> 0x1b | uVar4 * 0x20);
  uVar2 = uVar8 << 1 | (uint)((int)uVar8 < 0);
  *(uint *)(in_EAX + 0x1c) = uVar2;
  uVar8 = uVar4 >> 2 | uVar4 * 0x40000000;
  uVar2 = (uVar7 ^ uVar5 ^ uVar4) + uVar2 + uVar6 + -0x359d3e2a + (uVar3 >> 0x1b | uVar3 * 0x20);
  uVar4 = *(uint *)(in_EAX + 0x40) ^ *(uint *)(in_EAX + 0x54) ^ *(uint *)(in_EAX + 0x28) ^
          *(uint *)(in_EAX + 0x20);
  uVar4 = uVar4 << 1 | (uint)((int)uVar4 < 0);
  *(uint *)(in_EAX + 0x20) = uVar4;
  uVar6 = *(uint *)(in_EAX + 0x58) ^ *(uint *)(in_EAX + 0x44) ^ *(uint *)(in_EAX + 0x2c) ^
          *(uint *)(in_EAX + 0x24);
  uVar1 = uVar3 >> 2 | uVar3 * 0x40000000;
  uVar3 = (uVar5 ^ uVar8 ^ uVar3) + uVar4 + uVar7 + -0x359d3e2a + (uVar2 >> 0x1b | uVar2 * 0x20);
  uVar4 = uVar6 << 1 | (uint)((int)uVar6 < 0);
  *(uint *)(in_EAX + 0x24) = uVar4;
  uVar7 = *(uint *)(in_EAX + 0x48) ^ *(uint *)(in_EAX + 0x30) ^ *(uint *)(in_EAX + 0x1c) ^
          *(uint *)(in_EAX + 0x28);
  uVar6 = uVar2 >> 2 | uVar2 * 0x40000000;
  uVar2 = (uVar8 ^ uVar1 ^ uVar2) + uVar4 + uVar5 + -0x359d3e2a + (uVar3 >> 0x1b | uVar3 * 0x20);
  uVar4 = uVar7 << 1 | (uint)((int)uVar7 < 0);
  *(uint *)(in_EAX + 0x28) = uVar4;
  uVar4 = (uVar3 ^ uVar1 ^ uVar6) + uVar4 + uVar8 + -0x359d3e2a + (uVar2 >> 0x1b | uVar2 * 0x20);
  uVar5 = *(uint *)(in_EAX + 0x4c) ^ *(uint *)(in_EAX + 0x34) ^ *(uint *)(in_EAX + 0x2c) ^
          *(uint *)(in_EAX + 0x20);
  uVar7 = uVar3 >> 2 | uVar3 * 0x40000000;
  uVar3 = uVar5 << 1 | (uint)((int)uVar5 < 0);
  *(uint *)(in_EAX + 0x2c) = uVar3;
  uVar5 = uVar2 >> 2 | uVar2 * 0x40000000;
  uVar3 = (uVar7 ^ uVar2 ^ uVar6) + uVar3 + uVar1 + -0x359d3e2a + (uVar4 >> 0x1b | uVar4 * 0x20);
  uVar2 = *(uint *)(in_EAX + 0x50) ^ *(uint *)(in_EAX + 0x38) ^ *(uint *)(in_EAX + 0x30) ^
          *(uint *)(in_EAX + 0x24);
  uVar2 = uVar2 << 1 | (uint)((int)uVar2 < 0);
  *(uint *)(in_EAX + 0x30) = uVar2;
  uVar1 = *(uint *)(in_EAX + 0x54) ^ *(uint *)(in_EAX + 0x3c) ^ *(uint *)(in_EAX + 0x34) ^
          *(uint *)(in_EAX + 0x28);
  uVar8 = uVar4 >> 2 | uVar4 * 0x40000000;
  uVar2 = (uVar7 ^ uVar5 ^ uVar4) + uVar2 + uVar6 + -0x359d3e2a + (uVar3 >> 0x1b | uVar3 * 0x20);
  uVar4 = uVar1 << 1 | (uint)((int)uVar1 < 0);
  *(uint *)(in_EAX + 0x34) = uVar4;
  uVar6 = *(uint *)(in_EAX + 0x58) ^ *(uint *)(in_EAX + 0x40) ^ *(uint *)(in_EAX + 0x38) ^
          *(uint *)(in_EAX + 0x2c);
  uVar1 = uVar3 >> 2 | uVar3 * 0x40000000;
  uVar3 = (uVar5 ^ uVar8 ^ uVar3) + uVar4 + uVar7 + -0x359d3e2a + (uVar2 >> 0x1b | uVar2 * 0x20);
  uVar4 = uVar6 << 1 | (uint)((int)uVar6 < 0);
  *(uint *)(in_EAX + 0x38) = uVar4;
  uVar7 = *(uint *)(in_EAX + 0x30) ^ *(uint *)(in_EAX + 0x44) ^ *(uint *)(in_EAX + 0x3c) ^
          *(uint *)(in_EAX + 0x1c);
  uVar6 = uVar2 >> 2 | uVar2 * 0x40000000;
  uVar2 = (uVar8 ^ uVar1 ^ uVar2) + uVar4 + uVar5 + -0x359d3e2a + (uVar3 >> 0x1b | uVar3 * 0x20);
  uVar4 = uVar7 << 1 | (uint)((int)uVar7 < 0);
  *(uint *)(in_EAX + 0x3c) = uVar4;
  uVar4 = (uVar3 ^ uVar1 ^ uVar6) + uVar4 + uVar8 + -0x359d3e2a + (uVar2 >> 0x1b | uVar2 * 0x20);
  uVar5 = *(uint *)(in_EAX + 0x48) ^ *(uint *)(in_EAX + 0x40) ^ *(uint *)(in_EAX + 0x34) ^
          *(uint *)(in_EAX + 0x20);
  uVar7 = uVar3 >> 2 | uVar3 * 0x40000000;
  uVar8 = uVar5 << 1 | (uint)((int)uVar5 < 0);
  uVar5 = uVar2 >> 2 | uVar2 * 0x40000000;
  uVar3 = (uVar7 ^ uVar2 ^ uVar6) + uVar8 + uVar1 + -0x359d3e2a + (uVar4 >> 0x1b | uVar4 * 0x20);
  *(uint *)(in_EAX + 0x40) = uVar8;
  uVar2 = *(uint *)(in_EAX + 0x38) ^ *(uint *)(in_EAX + 0x4c) ^ *(uint *)(in_EAX + 0x44) ^
          *(uint *)(in_EAX + 0x24);
  uVar2 = uVar2 << 1 | (uint)((int)uVar2 < 0);
  *(uint *)(in_EAX + 0x44) = uVar2;
  uVar8 = uVar4 >> 2 | uVar4 * 0x40000000;
  uVar1 = *(uint *)(in_EAX + 0x50) ^ *(uint *)(in_EAX + 0x48) ^ *(uint *)(in_EAX + 0x3c) ^
          *(uint *)(in_EAX + 0x28);
  uVar2 = (uVar7 ^ uVar5 ^ uVar4) + uVar2 + uVar6 + -0x359d3e2a + (uVar3 >> 0x1b | uVar3 * 0x20);
  uVar1 = uVar1 << 1 | (uint)((int)uVar1 < 0);
  *(uint *)(in_EAX + 0x48) = uVar1;
  uVar6 = *(uint *)(in_EAX + 0x40) ^ *(uint *)(in_EAX + 0x54) ^ *(uint *)(in_EAX + 0x4c) ^
          *(uint *)(in_EAX + 0x2c);
  uVar4 = uVar3 >> 2 | uVar3 * 0x40000000;
  uVar3 = (uVar5 ^ uVar8 ^ uVar3) + uVar1 + uVar7 + -0x359d3e2a + (uVar2 >> 0x1b | uVar2 * 0x20);
  uVar6 = uVar6 << 1 | (uint)((int)uVar6 < 0);
  *(uint *)(in_EAX + 0x4c) = uVar6;
  uVar7 = *(uint *)(in_EAX + 0x58) ^ *(uint *)(in_EAX + 0x50) ^ *(uint *)(in_EAX + 0x30) ^
          *(uint *)(in_EAX + 0x44);
  uVar1 = uVar2 >> 2 | uVar2 * 0x40000000;
  uVar7 = uVar7 << 1 | (uint)((int)uVar7 < 0);
  *(uint *)(in_EAX + 0x50) = uVar7;
  uVar2 = (uVar8 ^ uVar4 ^ uVar2) + uVar6 + uVar5 + -0x359d3e2a + (uVar3 >> 0x1b | uVar3 * 0x20);
  uVar5 = *(uint *)(in_EAX + 0x48) ^ *(uint *)(in_EAX + 0x54) ^ *(uint *)(in_EAX + 0x34) ^
          *(uint *)(in_EAX + 0x1c);
  uVar6 = uVar3 >> 2 | uVar3 * 0x40000000;
  uVar5 = uVar5 << 1 | (uint)((int)uVar5 < 0);
  *(uint *)(in_EAX + 0x54) = uVar5;
  uVar3 = (uVar3 ^ uVar4 ^ uVar1) + uVar7 + uVar8 + -0x359d3e2a + (uVar2 >> 0x1b | uVar2 * 0x20);
  uVar4 = (uVar6 ^ uVar2 ^ uVar1) + uVar5 + uVar4 + -0x359d3e2a + (uVar3 >> 0x1b | uVar3 * 0x20);
  uVar5 = uVar2 >> 2 | uVar2 * 0x40000000;
  uVar2 = *(uint *)(in_EAX + 0x58) ^ *(uint *)(in_EAX + 0x38) ^ *(uint *)(in_EAX + 0x4c) ^
          *(uint *)(in_EAX + 0x20);
  uVar2 = uVar2 << 1 | (uint)((int)uVar2 < 0);
  *(uint *)(in_EAX + 0x58) = uVar2;
  *(int *)(in_EAX + 0x14) = *(int *)(in_EAX + 0x14) + uVar5;
  *(int *)(in_EAX + 8) =
       *(int *)(in_EAX + 8) +
       (uVar6 ^ uVar5 ^ uVar3) + uVar2 + uVar1 + -0x359d3e2a + (uVar4 >> 0x1b | uVar4 * 0x20);
  *(int *)(in_EAX + 0xc) = *(int *)(in_EAX + 0xc) + uVar4;
  *(int *)(in_EAX + 0x10) = *(int *)(in_EAX + 0x10) + (uVar3 >> 2 | uVar3 * 0x40000000);
  *(int *)(in_EAX + 0x18) = *(int *)(in_EAX + 0x18) + uVar6;
  return;
}



void __thiscall FUN_00405324(void *this,uint param_1)

{
  uint uVar1;
  uint *puVar2;
  uint uVar3;
  uint uVar4;
  uint *unaff_EDI;
  int local_c;
  void *local_8;
  
  uVar4 = *unaff_EDI & 0x3f;
  uVar1 = *unaff_EDI + param_1;
  uVar3 = 0x40 - uVar4;
  *unaff_EDI = uVar1;
  if (uVar1 < param_1) {
    unaff_EDI[1] = unaff_EDI[1] + 1;
  }
  local_8 = this;
  if (uVar3 <= param_1) {
    do {
      func_0xfbcc5510((int)unaff_EDI + uVar4 + 0x1c,local_8,uVar3);
      local_8 = (void *)((int)local_8 + uVar3);
      param_1 = param_1 - uVar3;
      uVar3 = 0x40;
      puVar2 = unaff_EDI + 0x17;
      uVar4 = 0;
      local_c = 0x10;
      do {
        local_c = local_c + -1;
        puVar2 = puVar2 + -1;
        uVar1 = *puVar2;
        *puVar2 = uVar1 >> 0x18 | (uVar1 & 0xff00) << 8 | uVar1 >> 8 & 0xff00ff00 | uVar1 << 0x18;
      } while (local_c != 0);
      func_0x2b745456();
    } while (0x3f < param_1);
  }
  func_0xfbcc556c(uVar4 + 0x1c + (int)unaff_EDI,local_8,param_1);
  return;
}



int __cdecl FUN_00405592(int param_1)

{
  undefined4 uVar1;
  uint uVar2;
  uint uVar3;
  uint uVar4;
  int unaff_ESI;
  int unaff_EDI;
  int local_c;
  uint local_8;
  
  local_8 = *(uint *)(unaff_ESI + 0x30);
  local_c = *(int *)(unaff_EDI + 0xc);
  uVar2 = *(uint *)(unaff_ESI + 0x34);
  if (uVar2 < local_8) {
    uVar2 = *(uint *)(unaff_ESI + 0x2c);
  }
  uVar4 = *(uint *)(unaff_EDI + 0x10);
  uVar3 = uVar2 - local_8;
  if (uVar4 < uVar2 - local_8) {
    uVar3 = uVar4;
  }
  if ((uVar3 != 0) && (param_1 == -5)) {
    param_1 = 0;
  }
  *(int *)(unaff_EDI + 0x14) = *(int *)(unaff_EDI + 0x14) + uVar3;
  *(uint *)(unaff_EDI + 0x10) = uVar4 - uVar3;
  if (*(code **)(unaff_ESI + 0x38) != (code *)0x0) {
    uVar1 = (**(code **)(unaff_ESI + 0x38))(*(undefined4 *)(unaff_ESI + 0x3c),local_8,uVar3);
    *(undefined4 *)(unaff_ESI + 0x3c) = uVar1;
    *(undefined4 *)(unaff_EDI + 0x30) = uVar1;
  }
  if (uVar3 != 0) {
    func_0xfbcc57ac(local_c,local_8,uVar3);
    local_c = local_c + uVar3;
    local_8 = local_8 + uVar3;
  }
  if (local_8 == *(uint *)(unaff_ESI + 0x2c)) {
    local_8 = *(uint *)(unaff_ESI + 0x28);
    if (*(uint *)(unaff_ESI + 0x34) == *(uint *)(unaff_ESI + 0x2c)) {
      *(uint *)(unaff_ESI + 0x34) = local_8;
    }
    uVar2 = *(uint *)(unaff_EDI + 0x10);
    uVar4 = *(int *)(unaff_ESI + 0x34) - local_8;
    if (uVar2 < uVar4) {
      uVar4 = uVar2;
    }
    if ((uVar4 != 0) && (param_1 == -5)) {
      param_1 = 0;
    }
    *(int *)(unaff_EDI + 0x14) = *(int *)(unaff_EDI + 0x14) + uVar4;
    *(uint *)(unaff_EDI + 0x10) = uVar2 - uVar4;
    if (*(code **)(unaff_ESI + 0x38) != (code *)0x0) {
      uVar1 = (**(code **)(unaff_ESI + 0x38))(*(undefined4 *)(unaff_ESI + 0x3c),local_8,uVar4);
      *(undefined4 *)(unaff_ESI + 0x3c) = uVar1;
      *(undefined4 *)(unaff_EDI + 0x30) = uVar1;
    }
    if (uVar4 != 0) {
      func_0xfbcc5816(local_c,local_8,uVar4);
      local_c = local_c + uVar4;
      local_8 = local_8 + uVar4;
    }
  }
  *(int *)(unaff_EDI + 0xc) = local_c;
  *(uint *)(unaff_ESI + 0x30) = local_8;
  return param_1;
}



// WARNING: Control flow encountered bad instruction data
// WARNING: Instruction at (ram,0x004059c2) overlaps instruction at (ram,0x004059be)
// 

void __cdecl FUN_004056ac(undefined4 param_1)

{
  byte bVar1;
  char **ppcVar2;
  char *pcVar3;
  int in_EAX;
  int iVar4;
  uint uVar5;
  char *pcVar6;
  byte *pbVar7;
  char *pcVar8;
  byte **unaff_EBX;
  char *local_20;
  char *local_18;
  byte *local_14;
  byte *local_10;
  uint local_c;
  char *local_8;
  
  local_10 = *unaff_EBX;
  pcVar8 = *(char **)(in_EAX + 0x34);
  local_14 = unaff_EBX[1];
  local_c = *(uint *)(in_EAX + 0x20);
  ppcVar2 = *(char ***)(in_EAX + 4);
  local_8 = *(char **)(in_EAX + 0x1c);
  if (pcVar8 < *(char **)(in_EAX + 0x30)) {
    local_18 = *(char **)(in_EAX + 0x30) + (-1 - (int)pcVar8);
  }
  else {
    local_18 = (char *)(*(int *)(in_EAX + 0x2c) - (int)pcVar8);
  }
  local_20 = *ppcVar2;
  if ((char *)0x9 < local_20) {
    *(uint *)(in_EAX + 0x20) = local_c;
    *(char **)(in_EAX + 0x1c) = local_8;
    unaff_EBX[1] = local_14;
    pbVar7 = *unaff_EBX;
    *unaff_EBX = local_10;
    unaff_EBX[2] = unaff_EBX[2] + ((int)local_10 - (int)pbVar7);
    *(char **)(in_EAX + 0x34) = pcVar8;
    func_0x898557d1(0xfffffffe);
    return;
  }
  do {
    pcVar6 = local_18;
    switch(local_20) {
    case (char *)0x0:
                    // WARNING: Bad instruction - Truncating control flow here
      halt_baddata();
    case (char *)0x1:
      *(undefined *)(unaff_EBX + 0x10) = *(undefined *)(unaff_EBX + 0x10);
      if (((char *)0x101 < local_18) && ((byte *)0x9 < local_14)) {
        *(uint *)(in_EAX + 0x20) = local_c;
        *(char **)(in_EAX + 0x1c) = local_8;
        unaff_EBX[1] = local_14;
        pbVar7 = *unaff_EBX;
        *unaff_EBX = local_10;
        unaff_EBX[2] = unaff_EBX[2] + ((int)local_10 - (int)pbVar7);
        *(char **)(in_EAX + 0x34) = pcVar8;
        iVar4 = func_0xea995832(*(undefined *)(ppcVar2 + 4),*(undefined *)((int)ppcVar2 + 0x11),
                                *(undefined4 *)((int)ppcVar2 + 0x12),
                                *(undefined4 *)((int)ppcVar2 + 0x16));
        local_10 = *unaff_EBX;
        local_14 = unaff_EBX[1];
        local_c = *(uint *)(in_EAX + 0x20);
        local_8 = *(char **)(in_EAX + 0x1c);
        if (iVar4 != 0) {
          *ppcVar2 = (char *)((uint)(iVar4 != 1) * 2 + 7);
                    // WARNING: Bad instruction - Truncating control flow here
          halt_baddata();
        }
      }
      ppcVar2[3] = (char *)(uint)*(byte *)(ppcVar2 + 4);
      ppcVar2[2] = *(char **)((int)ppcVar2 + 0x12);
      *ppcVar2 = (char *)0x1;
      goto code_r0x0040580b;
    case (char *)0x2:
      goto switchD_00405723_caseD_2;
    case (char *)0x3:
      goto switchD_00405723_caseD_3;
    case (char *)0x4:
      goto switchD_00405723_caseD_4;
    case (char *)0x5:
      while( true ) {
        local_8 = local_8 + 8;
        pcVar6 = ppcVar2[2];
        if (pcVar6 <= local_8) break;
        if (local_14 == (byte *)0x0) goto LAB_00405b33;
        param_1 = 0;
        local_14 = local_14 + -1;
        local_c = local_c | (uint)*local_10 << ((byte)local_8 & 0x1f);
        local_10 = local_10 + 1;
      }
      uVar5 = *(uint *)(&DAT_0042bac8 + (int)pcVar6 * 4) & local_c;
      local_c = local_c >> ((byte)pcVar6 & 0x1f);
      ppcVar2[3] = ppcVar2[3] + uVar5;
      local_8 = local_8 + -(int)pcVar6;
      *ppcVar2 = (char *)0x5;
      pcVar6 = *(char **)(in_EAX + 0x28);
      local_20 = pcVar8 + -(int)ppcVar2[3];
    case (char *)0x6:
      local_20 = local_20 + -0x75000000;
      *(char *)((int)unaff_EBX + 0xc472bc2) = *(char *)((int)unaff_EBX + 0xc472bc2) - (char)pcVar6;
      if (local_20 < pcVar6) {
        do {
          local_20 = local_20 + (*(int *)(in_EAX + 0x2b) - (int)pcVar6);
        } while (local_20 < *(char **)(in_EAX + 0x27));
      }
      while (ppcVar2[1] != (char *)0x0) {
        pcVar6 = pcVar8;
        if (local_18 == (char *)0x0) {
          if (pcVar8 == *(char **)(in_EAX + 0x2b)) {
            local_18 = *(char **)(in_EAX + 0x2f);
            pcVar6 = *(char **)(in_EAX + 0x27);
            if (local_18 != pcVar6) {
              if (pcVar6 < local_18) {
                local_18 = local_18 + (-1 - (int)pcVar6);
              }
              else {
                local_18 = (char *)(*(int *)(in_EAX + 0x2b) - (int)pcVar6);
              }
              pcVar8 = pcVar6;
              if (local_18 != (char *)0x0) goto LAB_00405a6f;
            }
          }
          *(char **)(in_EAX + 0x33) = pcVar8;
          func_0x89855ae0(param_1);
          pcVar6 = *(char **)(in_EAX + 0x33);
          pcVar8 = *(char **)(in_EAX + 0x2f);
          if (pcVar6 < pcVar8) {
            local_18 = pcVar8 + (-1 - (int)pcVar6);
          }
          else {
            local_18 = (char *)(*(int *)(in_EAX + 0x2b) - (int)pcVar6);
          }
          if ((pcVar6 == *(char **)(in_EAX + 0x2b)) &&
             (pcVar3 = *(char **)(in_EAX + 0x27), pcVar8 != pcVar3)) {
            pcVar6 = pcVar3;
            if (pcVar3 < pcVar8) {
              local_18 = pcVar8 + (-1 - (int)pcVar3);
            }
            else {
              local_18 = (char *)(*(int *)(in_EAX + 0x2b) - (int)pcVar3);
            }
          }
          if (local_18 == (char *)0x0) {
                    // WARNING: Bad instruction - Truncating control flow here
            halt_baddata();
          }
        }
LAB_00405a6f:
        param_1 = 0;
        *pcVar6 = *local_20;
        pcVar8 = pcVar6 + 1;
        local_20 = local_20 + 1;
        local_18 = local_18 + -1;
        if (local_20 == *(char **)(in_EAX + 0x2b)) {
          local_20 = *(char **)(in_EAX + 0x27);
        }
        ppcVar2[1] = ppcVar2[1] + -1;
      }
      *ppcVar2 = (char *)0x0;
      local_20 = *ppcVar2;
      in_EAX = in_EAX + -1;
      if ((char *)0x9 < local_20) {
                    // WARNING: Bad instruction - Truncating control flow here
        halt_baddata();
      }
      break;
    case (char *)0x7:
                    // WARNING: Bad instruction - Truncating control flow here
      halt_baddata();
    case (char *)0x8:
      *local_20 = *local_20 + (char)local_20;
                    // WARNING: Bad instruction - Truncating control flow here
      halt_baddata();
    case (char *)0x9:
      pcVar8[1] = pcVar8[1] + (char)((uint)local_18 >> 8);
                    // WARNING: Bad instruction - Truncating control flow here
      halt_baddata();
    }
  } while( true );
switchD_00405723_caseD_3:
  local_8 = local_8 + 8;
  pcVar6 = ppcVar2[2];
  if (pcVar6 <= local_8) goto code_r0x004058c0;
  if (local_14 == (byte *)0x0) goto LAB_00405b33;
  local_14 = local_14 + -1;
  local_c = local_c | (uint)*local_10 << ((byte)local_8 & 0x1f);
  local_10 = local_10 + 1;
  goto switchD_00405723_caseD_3;
code_r0x0040580b:
  if (ppcVar2[3] <= local_8) goto code_r0x00405813;
  if (local_14 == (byte *)0x0) {
LAB_00405b33:
    *(uint *)(in_EAX + 0x20) = local_c;
    *(char **)(in_EAX + 0x1c) = local_8;
    unaff_EBX[1] = (byte *)0x0;
                    // WARNING: Bad instruction - Truncating control flow here
    halt_baddata();
  }
  local_14 = local_14 + -1;
  local_c = local_c | (uint)*local_10 << ((byte)local_8 & 0x1f);
  local_10 = local_10 + 1;
switchD_00405723_caseD_2:
  local_8 = local_8 + 8;
  goto code_r0x0040580b;
code_r0x00405813:
  pbVar7 = (byte *)(ppcVar2[2] + (*(uint *)(&DAT_0042bac8 + (int)ppcVar2[3] * 4) & local_c) * 8);
  bVar1 = *pbVar7;
  pcVar6 = (char *)(uint)bVar1;
  if (pcVar6 == (char *)0x0) {
    pbVar7 = *(byte **)(pbVar7 + 4);
    *ppcVar2 = (char *)0x6;
    goto LAB_0040584a;
  }
  if ((bVar1 & 0x10) != 0) {
    ppcVar2[2] = (char *)((uint)pcVar6 & 0xf);
    ppcVar2[1] = *(char **)(pbVar7 + 4);
    *ppcVar2 = (char *)0x2;
    return;
  }
  if ((bVar1 & 0x40) != 0) {
    if ((bVar1 & 0x20) != 0) {
      *ppcVar2 = &DAT_00000007;
      return;
    }
    *(byte *)ppcVar2 = *(char *)ppcVar2 + (byte)ppcVar2;
    *(char *)((int)ppcVar2 + 0x6a0042d2) =
         *(char *)((int)ppcVar2 + 0x6a0042d2) - CARRY1((byte)((uint)unaff_EBX >> 8),(byte)ppcVar2);
                    // WARNING: Bad instruction - Truncating control flow here
    halt_baddata();
  }
  goto LAB_00405876;
code_r0x004058c0:
  uVar5 = *(uint *)(&DAT_0042bac8 + (int)pcVar6 * 4) & local_c;
  local_c = local_c >> ((byte)pcVar6 & 0x1f);
  ppcVar2[1] = ppcVar2[1] + uVar5;
  ppcVar2[3] = (char *)(uint)*(byte *)((int)ppcVar2 + 0x11);
  ppcVar2[2] = *(char **)((int)ppcVar2 + 0x16);
  *ppcVar2 = (char *)0x3;
  for (local_8 = local_8 + -(int)pcVar6; local_8 < ppcVar2[3]; local_8 = local_8 + 8) {
    if (local_14 == (byte *)0x0) goto LAB_00405b33;
    local_14 = local_14 + -1;
    local_c = local_c | (uint)*local_10 << ((byte)local_8 & 0x1f);
    local_10 = local_10 + 1;
switchD_00405723_caseD_4:
  }
  pbVar7 = (byte *)(ppcVar2[2] + (*(uint *)(&DAT_0042bac8 + (int)ppcVar2[3] * 4) & local_c) * 8);
  bVar1 = *pbVar7;
  pcVar6 = (char *)(uint)bVar1;
  if ((bVar1 & 0x10) != 0) {
    ppcVar2[2] = (char *)((uint)pcVar6 & 0xf);
    ppcVar2[3] = *(char **)(pbVar7 + 4);
    *ppcVar2 = (char *)0x4;
                    // WARNING: Bad instruction - Truncating control flow here
    halt_baddata();
  }
  if ((bVar1 & 0x40) != 0) {
    pbVar7 = (byte *)(CONCAT22((short)((uint)pcVar8 >> 0x10),CONCAT11(9,(char)pcVar8)) + -1);
    *ppcVar2 = *ppcVar2 + -(int)ppcVar2;
    *pbVar7 = *pbVar7 << (bVar1 & 7) | *pbVar7 >> 8 - (bVar1 & 7);
                    // WARNING: Bad instruction - Truncating control flow here
    halt_baddata();
  }
LAB_00405876:
  ppcVar2[3] = pcVar6;
  pbVar7 = pbVar7 + *(int *)(pbVar7 + 4) * 8;
LAB_0040584a:
  ppcVar2[2] = (char *)pbVar7;
                    // WARNING: Bad instruction - Truncating control flow here
  halt_baddata();
}



// WARNING: Control flow encountered bad instruction data
// WARNING: Instruction at (ram,0x00405d46) overlaps instruction at (ram,0x00405d43)
// 

void __fastcall FUN_00405cc7(undefined4 param_1,byte *param_2,byte **param_3,undefined4 param_4)

{
  byte **ppbVar1;
  byte bVar2;
  code *pcVar3;
  byte bVar4;
  int *in_EAX;
  byte *pbVar6;
  int iVar7;
  byte *extraout_ECX;
  uint uVar8;
  byte *extraout_EDX;
  byte *extraout_EDX_00;
  undefined *puVar9;
  undefined *puVar10;
  byte *unaff_EDI;
  byte *pbVar11;
  byte *local_1c;
  byte **local_18;
  undefined4 local_14;
  undefined4 local_10;
  undefined4 local_c;
  undefined4 local_8;
  byte *pbVar5;
  
  puVar9 = &stack0xfffffffc;
  pbVar6 = param_3[0xd];
  local_10 = (byte *)in_EAX[1];
  local_18 = (byte **)*in_EAX;
  local_c = param_3[8];
  local_8 = param_3[7];
  if (pbVar6 < param_3[0xc]) {
    local_1c = param_3[0xc] + (-1 - (int)pbVar6);
  }
  else {
    local_1c = param_3[0xb] + -(int)pbVar6;
  }
  pbVar5 = *param_3;
  local_14 = pbVar6;
  if ((byte *)0x9 < pbVar5) {
    param_3[8] = local_c;
    param_3[7] = param_3[7];
    in_EAX[1] = (int)local_10;
    iVar7 = *in_EAX;
    *in_EAX = (int)local_18;
    in_EAX[2] = (int)local_18 + (in_EAX[2] - iVar7);
    param_3[0xd] = pbVar6;
    func_0x89855df0(0xfffffffe);
    return;
  }
  do {
    bVar4 = (byte)pbVar5;
    pbVar11 = unaff_EDI;
    switch(pbVar5) {
    case (byte *)0x0:
                    // WARNING: Bad instruction - Truncating control flow here
      halt_baddata();
    case (byte *)0x1:
      param_2[3] = param_2[3] + (char)((uint)pbVar6 >> 8);
      for (; local_8 < unaff_EDI; local_8 = local_8 + 8) {
        puVar10 = &stack0xfffffffc;
        if (local_10 == (byte *)0x0) goto LAB_00406307;
        param_4 = 0;
        local_10 = local_10 + -1;
        local_c = (byte *)((uint)local_c | (uint)*(byte *)local_18 << ((byte)local_8 & 0x1f));
        local_18 = (byte **)((int)local_18 + 1);
      }
      pbVar6 = (byte *)((uint)local_c & 1);
      uVar8 = ((uint)local_c & 7) >> 1;
      param_3[6] = pbVar6;
      if (uVar8 == 0) {
        *param_3 = (byte *)0x1;
                    // WARNING: Bad instruction - Truncating control flow here
        halt_baddata();
      }
      if (uVar8 == 1) {
        pbVar6 = (byte *)func_0x72865e98(9,5,0x42bb38,0x42cb38);
        param_3[1] = pbVar6;
        if (pbVar6 == (byte *)0x0) {
          return;
        }
        *param_3 = (byte *)0x6;
                    // WARNING: Bad instruction - Truncating control flow here
        halt_baddata();
      }
      if (uVar8 == 2) {
        *param_3 = unaff_EDI;
                    // WARNING: Bad instruction - Truncating control flow here
        halt_baddata();
      }
      if (uVar8 == 3) {
        *param_3 = (byte *)0x9;
        in_EAX[6] = 0x42d2dc;
        param_3[8] = (byte *)((uint)local_c >> 3);
                    // WARNING: Bad instruction - Truncating control flow here
        halt_baddata();
      }
      break;
    case (byte *)0x2:
      *pbVar5 = *pbVar5 + bVar4;
      out((short)param_2,bVar4);
      for (; local_8 < (byte *)0x20; local_8 = local_8 + 8) {
        if (local_10 == (byte *)0x0) {
          param_3[8] = local_c;
          param_3[7] = local_8;
                    // WARNING: Bad instruction - Truncating control flow here
          halt_baddata();
        }
        local_10 = local_10 + -1;
        local_c = (byte *)((uint)local_c | (uint)*(byte *)local_18 << ((byte)local_8 & 0x1f));
        local_18 = (byte **)((int)local_18 + 1);
      }
      if ((byte *)(~(uint)local_c >> 0x10) != (byte *)((uint)local_c & 0xffff)) {
        *param_3 = (byte *)0x9;
        in_EAX[6] = (int)&DAT_0042d2f0;
        return;
      }
      param_3[1] = (byte *)((uint)local_c & 0xffff);
      if (param_3[1] == (byte *)0x0) {
        pbVar6 = (byte *)(-(uint)(param_3[6] != (byte *)0x0) & 7);
      }
      else {
        pbVar6 = (byte *)0x2;
      }
      *param_3 = pbVar6;
                    // WARNING: Bad instruction - Truncating control flow here
      halt_baddata();
    case (byte *)0x3:
      *pbVar5 = *pbVar5 + bVar4;
      out((short)param_2,bVar4);
      puVar10 = &stack0xfffffffc;
      if (local_10 == (byte *)0x0) goto LAB_00406307;
      if (local_1c == (byte *)0x0) {
        if ((local_14 == param_3[0xb]) && (param_3[10] != param_3[0xc])) {
          pcVar3 = (code *)swi(3);
          (*pcVar3)();
          return;
        }
        param_3[0xd] = local_14;
        func_0x89855f90(param_4);
        goto code_r0x00405ef6;
      }
      param_4 = 0;
      pbVar6 = param_3[1];
      if (local_10 < param_3[1]) {
        pbVar6 = local_10;
      }
      if (local_1c < pbVar6) {
        pbVar6 = local_1c;
      }
      func_0xfbcc60fd(local_14,local_18,pbVar6,param_2);
      local_18 = (byte **)((int)local_18 + (int)pbVar6);
      local_10 = local_10 + -(int)pbVar6;
      local_14 = local_14 + (int)pbVar6;
      local_1c = local_1c + -(int)pbVar6;
      ppbVar1 = param_3 + 1;
      *ppbVar1 = *ppbVar1 + -(int)pbVar6;
      pbVar6 = extraout_ECX;
      unaff_EDI = extraout_EDX;
      if (*ppbVar1 == (byte *)0x0) {
                    // WARNING: Bad instruction - Truncating control flow here
        halt_baddata();
      }
      break;
    case (byte *)0x4:
      bVar2 = *pbVar5;
      *pbVar5 = *pbVar5 + bVar4;
      local_18 = (byte **)((int)local_18 + -1);
      if (CARRY1(bVar2,bVar4)) {
code_r0x00405ef6:
        pcVar3 = (code *)swi(3);
        (*pcVar3)();
        return;
      }
      puVar9 = (undefined *)((int)&local_8 + 3);
      while( true ) {
        if ((byte *)0xd < pbVar6) {
          pbVar6 = (byte *)(CONCAT31((undefined3)local_c,local_10._3_1_) & 0x3fff);
          param_3[1] = pbVar6;
          if ((0x1d < (local_10._3_1_ & 0x1f)) || (uVar8 = (uint)pbVar6 >> 5 & 0x1f, 0x1d < uVar8))
          {
            *param_3 = (byte *)0x9;
            in_EAX[6] = (int)&DAT_0042d310;
                    // WARNING: Bad instruction - Truncating control flow here
            halt_baddata();
          }
          pbVar6 = (byte *)(*(code *)in_EAX[8])
                                     (in_EAX[10],uVar8 + 0x102 + (local_10._3_1_ & 0x1f),4);
          param_3[3] = pbVar6;
          if (pbVar6 == (byte *)0x0) {
                    // WARNING: Bad instruction - Truncating control flow here
            halt_baddata();
          }
          local_8._0_3_ =
               (undefined3)((uint)(CONCAT31((undefined3)local_8,local_c._3_1_) + -0xe) >> 8);
          param_3[2] = (byte *)0x0;
          *param_3 = (byte *)0x4;
          do {
            if ((byte *)(((uint)param_3[1] >> 10) + 4) <= param_3[2]) {
              while (param_3[2] < (byte *)0x13) {
                *(undefined4 *)(param_3[3] + *(int *)(&DAT_0042cc38 + (int)param_3[2] * 4) * 4) = 0;
                param_3[2] = param_3[2] + 1;
              }
              param_3[4] = &DAT_00000007;
              iVar7 = func_0x4e986134(param_3[3],param_3 + 4,param_3 + 5,param_3[9]);
              if (iVar7 == 0) {
                param_3[2] = (byte *)0x0;
                *param_3 = (byte *)0x5;
                    // WARNING: Bad instruction - Truncating control flow here
                halt_baddata();
              }
              if (iVar7 == -3) {
                (*(code *)in_EAX[9])(in_EAX[10],param_3[3]);
                *param_3 = (byte *)0x9;
              }
                    // WARNING: Bad instruction - Truncating control flow here
              halt_baddata();
            }
            uVar8 = *(uint *)(puVar9 + -4);
            while (uVar8 < 3) {
              puVar10 = puVar9;
              if (*(int *)(puVar9 + -0xc) == 0) goto LAB_00406307;
              bVar4 = *(byte *)local_18;
              *(undefined4 *)(puVar9 + 0xc) = 0;
              *(int *)(puVar9 + -0xc) = *(int *)(puVar9 + -0xc) + -1;
              *(uint *)(puVar9 + -8) = *(uint *)(puVar9 + -8) | (uint)bVar4 << ((byte)uVar8 & 0x1f);
              local_18 = (byte **)((int)local_18 + 1);
              uVar8 = uVar8 + 8;
              *(byte ***)(puVar9 + -0x14) = local_18;
              *(uint *)(puVar9 + -4) = uVar8;
            }
            uVar8 = *(uint *)(puVar9 + -8);
            iVar7 = *(int *)(&DAT_0042cc38 + (int)param_3[2] * 4);
            pbVar6 = param_3[3];
            *(uint *)(puVar9 + -8) = *(uint *)(puVar9 + -8) >> 3;
            *(uint *)(pbVar6 + iVar7 * 4) = uVar8 & 7;
            param_3[2] = param_3[2] + 1;
switchD_00405d43_caseD_5:
            *(int *)(puVar9 + -4) = *(int *)(puVar9 + -4) + -3;
          } while( true );
        }
        puVar10 = puVar9;
        if (CONCAT31((undefined3)local_10,local_14._3_1_) == 0) break;
        iVar7 = CONCAT31((undefined3)local_10,local_14._3_1_) + -1;
        local_14 = (byte *)(iVar7 * 0x1000000);
        local_10._0_3_ = (undefined3)((uint)iVar7 >> 8);
        uVar8 = CONCAT31((undefined3)local_c,local_10._3_1_) |
                (uint)*(byte *)local_18 << ((byte)pbVar6 & 0x1f);
        local_10._3_1_ = (byte)uVar8;
        local_18 = (byte **)((int)local_18 + 1);
        pbVar6 = pbVar6 + 8;
        local_c._3_1_ = SUB41(pbVar6,0);
        local_c = (byte *)CONCAT13(local_c._3_1_,(int3)(uVar8 >> 8));
        local_8._0_3_ = (undefined3)((uint)pbVar6 >> 8);
      }
LAB_00406307:
      param_3[8] = *(byte **)(puVar10 + -8);
      param_3[7] = *(byte **)(puVar10 + -4);
      in_EAX[1] = 0;
                    // WARNING: Bad instruction - Truncating control flow here
      halt_baddata();
    case (byte *)0x5:
      goto switchD_00405d43_caseD_5;
    case (byte *)0x6:
      do {
                    // WARNING: Do nothing block with infinite loop
      } while( true );
    case (byte *)0x7:
      param_3[8] = local_c;
      param_3[7] = local_8;
      in_EAX[1] = (int)local_10;
      iVar7 = *in_EAX;
      *in_EAX = (int)local_18;
      in_EAX[2] = (int)local_18 + (in_EAX[2] - iVar7);
      param_3[0xd] = local_14;
      iVar7 = func_0xa3866355(param_4);
      if (iVar7 != 1) {
                    // WARNING: Bad instruction - Truncating control flow here
        halt_baddata();
      }
      pbVar11 = param_3[1];
      param_4 = 0;
      (*(code *)in_EAX[9])(in_EAX[10]);
      local_18 = (byte **)*in_EAX;
      local_10 = (byte *)in_EAX[1];
      local_c = param_3[8];
      pbVar6 = param_3[0xd];
      local_8 = param_3[7];
      if (pbVar6 < param_3[0xc]) {
        local_1c = param_3[0xc] + (-1 - (int)pbVar6);
      }
      else {
        local_1c = param_3[0xb] + -(int)pbVar6;
      }
      local_14 = pbVar6;
      if (param_3[6] != (byte *)0x0) {
        *param_3 = &DAT_00000007;
        goto code_r0x00406470;
      }
      *param_3 = (byte *)0x0;
      unaff_EDI = extraout_EDX_00;
      break;
    case (byte *)0x8:
      *pbVar5 = *pbVar5 + bVar4;
      param_3 = local_18;
code_r0x00406470:
      param_3[0xd] = local_14;
      func_0x89856538(param_4);
      pbVar6 = param_3[0xd];
      if (param_3[0xc] == pbVar6) {
        *param_3 = (byte *)0x8;
                    // WARNING: Bad instruction - Truncating control flow here
        halt_baddata();
      }
      param_3[8] = local_c;
      param_3[7] = local_8;
      in_EAX[1] = (int)local_10;
      iVar7 = *in_EAX;
      *in_EAX = (int)local_18;
      in_EAX[2] = (int)local_18 + (in_EAX[2] - iVar7);
      param_3[0xd] = pbVar6;
                    // WARNING: Bad instruction - Truncating control flow here
      halt_baddata();
    case (byte *)0x9:
      *pbVar5 = *pbVar5 | bVar4;
      *pbVar5 = *pbVar5 + bVar4;
      return;
    }
    pbVar5 = *param_3;
    param_2 = unaff_EDI;
    unaff_EDI = pbVar11;
    if ((byte *)0x9 < pbVar5) {
                    // WARNING: Bad instruction - Truncating control flow here
      halt_baddata();
    }
  } while( true );
}



int __cdecl FUN_00406857(undefined4 param_1,int *param_2,undefined4 param_3,undefined4 param_4)

{
  int iVar1;
  int iVar2;
  int unaff_ESI;
  undefined4 local_8;
  
  local_8 = 0;
  iVar1 = (**(code **)(unaff_ESI + 0x20))(*(undefined4 *)(unaff_ESI + 0x28),0x13,4);
  if (iVar1 == 0) {
    iVar2 = -4;
  }
  else {
    iVar2 = func_0xbe94694f(param_1,0x13,0x13,0,0,param_3,param_4,&local_8,iVar1);
    if (iVar2 == -3) {
      *(undefined **)(unaff_ESI + 0x18) = &DAT_0042d350;
    }
    else if ((iVar2 == -5) || (*param_2 == 0)) {
      *(undefined **)(unaff_ESI + 0x18) = &DAT_0042d378;
      iVar2 = -3;
    }
    (**(code **)(unaff_ESI + 0x24))(*(undefined4 *)(unaff_ESI + 0x28),iVar1);
  }
  return iVar2;
}



// WARNING: Control flow encountered bad instruction data

int __cdecl
FUN_004068d3(undefined4 param_1,int *param_2,int *param_3,undefined4 param_4,undefined4 param_5,
            undefined4 param_6)

{
  int in_EAX;
  int iVar1;
  uint unaff_EBX;
  int unaff_ESI;
  int local_10;
  undefined4 local_c;
  int local_8;
  
  local_c = 0;
  local_8 = (**(code **)(unaff_ESI + 0x20))(*(undefined4 *)(unaff_ESI + 0x28),0x120,4);
  if (local_8 == 0) {
                    // WARNING: Bad instruction - Truncating control flow here
    halt_baddata();
  }
  local_10 = func_0xbe9469d9();
  if (local_10 == 0) {
    if (*param_2 != 0) {
      iVar1 = func_0xbe946a1e(in_EAX + unaff_EBX * 4,param_1,0,&DAT_0042cdb8,&DAT_0042ce30,param_5,
                              param_6,&local_c,local_8);
      if (iVar1 == 0) {
        if ((*param_3 != 0) || (unaff_EBX < 0x102)) {
          (**(code **)(unaff_ESI + 0x24))(*(undefined4 *)(unaff_ESI + 0x28),local_8);
          return 0;
        }
      }
      else {
        if (iVar1 == -3) {
          *(undefined **)(unaff_ESI + 0x18) = &DAT_0042d3e0;
          goto LAB_004069b9;
        }
        if (iVar1 == -5) {
          *(undefined **)(unaff_ESI + 0x18) = &DAT_0042d400;
          iVar1 = -3;
          goto LAB_004069b9;
        }
        if (iVar1 == -4) goto LAB_004069b9;
      }
      *(undefined **)(unaff_ESI + 0x18) = &DAT_0042d41c;
      iVar1 = -3;
LAB_004069b9:
      (**(code **)(unaff_ESI + 0x24))(*(undefined4 *)(unaff_ESI + 0x28),local_8);
      return iVar1;
    }
  }
  else {
    if (local_10 == -3) {
      *(undefined **)(unaff_ESI + 0x18) = &DAT_0042d39c;
      goto LAB_004069e2;
    }
    if (local_10 == -4) goto LAB_004069e2;
  }
  *(undefined **)(unaff_ESI + 0x18) = &DAT_0042d3c0;
  local_10 = -3;
LAB_004069e2:
  (**(code **)(unaff_ESI + 0x24))(*(undefined4 *)(unaff_ESI + 0x28),local_8);
  return local_10;
}



// WARNING: Control flow encountered bad instruction data

uint __fastcall
FUN_004069f3(undefined4 param_1,byte **param_2,uint param_3,int param_4,int param_5,int param_6)

{
  byte bVar1;
  uint uVar2;
  byte *pbVar3;
  byte *pbVar4;
  uint uVar5;
  uint uVar6;
  uint uVar7;
  uint uVar8;
  uint uVar9;
  int unaff_EDI;
  byte *local_18;
  byte *local_14;
  uint local_10;
  byte *local_c;
  byte *local_8;
  
  local_8 = *param_2;
  local_14 = *(byte **)(unaff_EDI + 0x34);
  local_c = param_2[1];
  local_10 = *(uint *)(unaff_EDI + 0x20);
  uVar9 = *(uint *)(unaff_EDI + 0x1c);
  if (local_14 < *(byte **)(unaff_EDI + 0x30)) {
    local_18 = *(byte **)(unaff_EDI + 0x30) + (-1 - (int)local_14);
  }
  else {
    local_18 = (byte *)(*(int *)(unaff_EDI + 0x2c) - (int)local_14);
  }
  uVar5 = *(uint *)(&DAT_0042bac8 + param_3 * 4);
  uVar2 = *(uint *)(&DAT_0042bac8 + param_4 * 4);
  do {
    for (; uVar9 < 0x14; uVar9 = uVar9 + 8) {
      local_c = local_c + -1;
      local_10 = local_10 | (uint)*local_8 << ((byte)uVar9 & 0x1f);
      local_8 = local_8 + 1;
    }
    pbVar4 = (byte *)(param_5 + (uVar5 & local_10) * 8);
    bVar1 = *pbVar4;
LAB_00406a91:
    uVar6 = (uint)bVar1;
    if (uVar6 != 0) {
      local_10 = local_10 >> (pbVar4[1] & 0x1f);
      uVar9 = uVar9 - pbVar4[1];
      if ((bVar1 & 0x10) == 0) {
        if ((bVar1 & 0x40) == 0) break;
        if ((bVar1 & 0x20) == 0) {
          param_2[6] = &DAT_0042d2a8;
          uVar5 = (int)param_2[1] - (int)local_c;
          if (uVar9 >> 3 < (uint)((int)param_2[1] - (int)local_c)) {
            uVar5 = uVar9 >> 3;
          }
          *(uint *)(unaff_EDI + 0x20) = local_10;
          *(uint *)(unaff_EDI + 0x1c) = uVar9 + uVar5 * -8;
          param_2[1] = local_c + uVar5;
          pbVar4 = *param_2;
          *param_2 = local_8 + -uVar5;
          param_2[2] = param_2[2] + ((int)(local_8 + -uVar5) - (int)pbVar4);
          *(byte **)(unaff_EDI + 0x34) = local_14;
          return 0xfffffffd;
        }
        uVar5 = (int)param_2[1] - (int)local_c;
        if (uVar9 >> 3 < (uint)((int)param_2[1] - (int)local_c)) {
          uVar5 = uVar9 >> 3;
        }
        param_3 = 1;
      }
      else {
        uVar6 = uVar6 & 0xf;
        uVar7 = (*(uint *)(&DAT_0042bac8 + uVar6 * 4) & local_10) + *(int *)(pbVar4 + 4);
        local_10 = local_10 >> (sbyte)uVar6;
        for (uVar9 = uVar9 - uVar6; uVar9 < 0xf; uVar9 = uVar9 + 8) {
          local_c = local_c + -1;
          local_10 = local_10 | (uint)*local_8 << ((byte)uVar9 & 0x1f);
          local_8 = local_8 + 1;
        }
        pbVar4 = (byte *)(param_6 + (uVar2 & local_10) * 8);
        bVar1 = *pbVar4;
        local_10 = local_10 >> (pbVar4[1] & 0x1f);
        uVar9 = uVar9 - pbVar4[1];
        while( true ) {
          param_3 = (uint)bVar1;
          if ((bVar1 & 0x10) != 0) {
            uVar6 = param_3 & 0xf;
            for (; uVar9 < uVar6; uVar9 = uVar9 + 8) {
              local_c = local_c + -1;
              local_10 = local_10 | (uint)*local_8 << ((byte)uVar9 & 0x1f);
              local_8 = local_8 + 1;
            }
            uVar8 = *(uint *)(&DAT_0042bac8 + uVar6 * 4) & local_10;
            local_10 = local_10 >> (sbyte)uVar6;
            local_18 = local_18 + -uVar7;
            uVar9 = uVar9 - uVar6;
            pbVar3 = local_14 + -(uVar8 + *(int *)(pbVar4 + 4));
            pbVar4 = *(byte **)(unaff_EDI + 0x28);
            if (pbVar3 < pbVar4) {
              do {
                pbVar3 = pbVar3 + (*(int *)(unaff_EDI + 0x2c) - (int)pbVar4);
              } while (pbVar3 < pbVar4);
              param_3 = *(int *)(unaff_EDI + 0x2c) - (int)pbVar3;
              if (param_3 < uVar7) {
                param_4 = uVar7 - param_3;
                do {
                  *local_14 = *pbVar3;
                  local_14 = local_14 + 1;
                  pbVar3 = pbVar3 + 1;
                  param_3 = param_3 - 1;
                } while (param_3 != 0);
                pbVar4 = *(byte **)(unaff_EDI + 0x28);
                do {
                  *local_14 = *pbVar4;
                  local_14 = local_14 + 1;
                  pbVar4 = pbVar4 + 1;
                  param_4 = param_4 + -1;
                } while (param_4 != 0);
              }
              else {
                *local_14 = *pbVar3;
                local_14[1] = pbVar3[1];
                local_14 = local_14 + 2;
                pbVar3 = pbVar3 + 2;
                param_4 = uVar7 - 2;
                do {
                  *local_14 = *pbVar3;
                  local_14 = local_14 + 1;
                  pbVar3 = pbVar3 + 1;
                  param_4 = param_4 + -1;
                } while (param_4 != 0);
              }
            }
            else {
              *local_14 = *pbVar3;
              local_14[1] = pbVar3[1];
              local_14 = local_14 + 2;
              pbVar3 = pbVar3 + 2;
              param_4 = uVar7 - 2;
              do {
                *local_14 = *pbVar3;
                local_14 = local_14 + 1;
                pbVar3 = pbVar3 + 1;
                param_4 = param_4 + -1;
              } while (param_4 != 0);
            }
            goto LAB_00406c12;
          }
          if ((bVar1 & 0x40) != 0) break;
          pbVar4 = pbVar4 + ((*(uint *)(&DAT_0042bac8 + param_3 * 4) & local_10) +
                            *(int *)(pbVar4 + 4)) * 8;
          bVar1 = *pbVar4;
          local_10 = local_10 >> (pbVar4[1] & 0x1f);
          uVar9 = uVar9 - pbVar4[1];
        }
        param_2[6] = &DAT_0042d2c4;
        uVar5 = (int)param_2[1] - (int)local_c;
        if (uVar9 >> 3 < (uint)((int)param_2[1] - (int)local_c)) {
          uVar5 = uVar9 >> 3;
        }
        param_3 = 0xfffffffd;
      }
      *(uint *)(unaff_EDI + 0x20) = local_10;
      *(uint *)(unaff_EDI + 0x1c) = uVar9 + uVar5 * -8;
      param_2[1] = local_c + uVar5;
      pbVar4 = *param_2;
      *param_2 = local_8 + -uVar5;
      param_2[2] = param_2[2] + ((int)(local_8 + -uVar5) - (int)pbVar4);
      *(byte **)(unaff_EDI + 0x34) = local_14;
      return param_3;
    }
    local_10 = local_10 >> (pbVar4[1] & 0x1f);
    uVar9 = uVar9 - pbVar4[1];
    *local_14 = pbVar4[4];
    local_14 = local_14 + 1;
    local_18 = local_18 + -1;
LAB_00406c12:
    if ((local_18 < (byte *)0x102) || (local_c < (byte *)0xa)) {
      uVar5 = (int)param_2[1] - (int)local_c;
      if (uVar9 >> 3 < (uint)((int)param_2[1] - (int)local_c)) {
        uVar5 = uVar9 >> 3;
      }
      *(uint *)(unaff_EDI + 0x20) = local_10;
      *(uint *)(unaff_EDI + 0x1c) = uVar9 + uVar5 * -8;
      param_2[1] = local_c + uVar5;
      pbVar4 = *param_2;
      *param_2 = local_8 + -uVar5;
      param_2[2] = param_2[2] + ((int)(local_8 + -uVar5) - (int)pbVar4);
      *(byte **)(unaff_EDI + 0x34) = local_14;
                    // WARNING: Bad instruction - Truncating control flow here
      halt_baddata();
    }
  } while( true );
  pbVar4 = pbVar4 + ((*(uint *)(&DAT_0042bac8 + uVar6 * 4) & local_10) + *(int *)(pbVar4 + 4)) * 8;
  bVar1 = *pbVar4;
  goto LAB_00406a91;
}



// WARNING: Control flow encountered bad instruction data

uint __cdecl FUN_00406e3f(uint param_1,byte *param_2,uint param_3)

{
  uint uVar1;
  uint uVar2;
  uint uVar3;
  int iVar4;
  int iVar5;
  int iVar6;
  int iVar7;
  int iVar8;
  int iVar9;
  int iVar10;
  int iVar11;
  int iVar12;
  int iVar13;
  int iVar14;
  int iVar15;
  int iVar16;
  int iVar17;
  int iVar18;
  uint uVar19;
  
  uVar3 = param_1 & 0xffff;
  uVar19 = param_1 >> 0x10;
  if (param_2 == (byte *)0x0) {
                    // WARNING: Bad instruction - Truncating control flow here
    halt_baddata();
  }
  if (param_3 != 0) {
    do {
      uVar2 = 0x15b0;
      if (param_3 < 0x15b0) {
        uVar2 = param_3;
      }
      param_3 = param_3 - uVar2;
      if (0xf < (int)uVar2) {
        uVar1 = uVar2 >> 4;
        uVar2 = uVar2 + uVar1 * -0x10;
        do {
          iVar4 = uVar3 + *param_2;
          iVar5 = iVar4 + (uint)param_2[1];
          iVar6 = iVar5 + (uint)param_2[2];
          iVar7 = iVar6 + (uint)param_2[3];
          iVar8 = iVar7 + (uint)param_2[4];
          iVar9 = iVar8 + (uint)param_2[5];
          iVar10 = iVar9 + (uint)param_2[6];
          iVar11 = iVar10 + (uint)param_2[7];
          iVar12 = iVar11 + (uint)param_2[8];
          iVar13 = iVar12 + (uint)param_2[9];
          iVar14 = iVar13 + (uint)param_2[10];
          iVar15 = iVar14 + (uint)param_2[0xb];
          iVar16 = iVar15 + (uint)param_2[0xc];
          iVar17 = iVar16 + (uint)param_2[0xd];
          iVar18 = iVar17 + (uint)param_2[0xe];
          uVar3 = iVar18 + (uint)param_2[0xf];
          uVar19 = uVar19 + iVar4 + iVar5 + iVar6 + iVar7 + iVar8 + iVar9 + iVar10 + iVar11 + iVar12
                   + iVar13 + iVar14 + iVar15 + iVar16 + iVar17 + iVar18 + uVar3;
          param_2 = param_2 + 0x10;
          uVar1 = uVar1 - 1;
        } while (uVar1 != 0);
      }
      for (; uVar2 != 0; uVar2 = uVar2 - 1) {
        uVar3 = uVar3 + *param_2;
        param_2 = param_2 + 1;
        uVar19 = uVar19 + uVar3;
      }
      uVar3 = uVar3 % 0xfff1;
      uVar19 = uVar19 % 0xfff1;
    } while (param_3 != 0);
  }
  return uVar19 << 0x10 | uVar3;
}



uint __cdecl FUN_0040746e(undefined4 param_1,uint param_2,uint param_3)

{
  int iVar1;
  char *unaff_ESI;
  uint uVar2;
  
  uVar2 = param_2 * param_3;
  if (*unaff_ESI == '\0') {
    iVar1 = *(int *)(unaff_ESI + 0x14);
    if (*(uint *)(unaff_ESI + 0x10) < iVar1 + uVar2) {
      uVar2 = *(uint *)(unaff_ESI + 0x10) - iVar1;
    }
    func_0xfbcc7674(param_1,*(int *)(unaff_ESI + 0xc) + iVar1,uVar2);
    *(uint *)(unaff_ESI + 0x14) = *(int *)(unaff_ESI + 0x14) + uVar2;
    param_3 = uVar2;
  }
  else {
    iVar1 = (*DAT_00428208)(*(undefined4 *)(unaff_ESI + 2),param_1,uVar2,&param_3,0);
    if (iVar1 == 0) {
      unaff_ESI[6] = '\x01';
    }
  }
  return param_3 / param_2;
}



undefined4 __cdecl FUN_004074ce(uint *param_1)

{
  char *in_EAX;
  int iVar1;
  byte local_5;
  
  iVar1 = func_0x65a47598(&local_5,1,1);
  if (iVar1 == 1) {
    *param_1 = (uint)local_5;
  }
  else if ((*in_EAX != '\0') && (in_EAX[6] != '\0')) {
    return 0xffffffff;
  }
  return 0;
}



void FUN_00407508(undefined4 param_1)

{
  int iVar1;
  int iVar2;
  int *unaff_EDI;
  int local_8;
  
  iVar2 = func_0xc5a475cf(&local_8);
  iVar1 = local_8;
  if ((iVar2 == 0) && (iVar2 = func_0xc5a475e3(&local_8), iVar2 == 0)) {
    *unaff_EDI = local_8 * 0x100 + iVar1;
    return;
  }
  *unaff_EDI = 0;
  return;
}



void FUN_00407544(void)

{
  int iVar1;
  int iVar2;
  int iVar3;
  int iVar4;
  int *unaff_EBX;
  int local_8;
  
  iVar2 = func_0xc5a4760a(&local_8);
  iVar1 = local_8;
  if (iVar2 == 0) {
    iVar2 = func_0xc5a4761d(&local_8);
  }
  iVar3 = local_8 * 0x100;
  if (iVar2 == 0) {
    iVar2 = func_0xc5a47635(&local_8);
  }
  iVar4 = local_8 * 0x10000;
  if ((iVar2 == 0) && (iVar2 = func_0xc5a4764d(&local_8), iVar2 == 0)) {
    *unaff_EBX = local_8 * 0x1000000 + iVar1 + iVar3 + iVar4;
    return;
  }
  *unaff_EBX = 0;
  return;
}



// WARNING: Control flow encountered bad instruction data
// WARNING: Globals starting with '_' overlap smaller symbols at the same address

int __cdecl FUN_004075ae(char *param_1)

{
  int iVar1;
  uint uVar2;
  uint uVar3;
  int iVar4;
  int iVar5;
  int local_18;
  uint local_10;
  uint local_c;
  uint local_8;
  
  iVar1 = func_0x06a4767b();
  if (iVar1 != 0) {
                    // WARNING: Bad instruction - Truncating control flow here
    halt_baddata();
  }
  if (*param_1 == '\0') {
    local_8 = *(uint *)(param_1 + 0x14);
  }
  else if (param_1[1] == '\0') {
    local_8 = 0;
  }
  else {
    iVar1 = (*ram0x004281c8)(*(undefined4 *)(param_1 + 2),0,0,1);
    local_8 = iVar1 - *(int *)(param_1 + 7);
  }
  local_c = 0xffff;
  if (local_8 < 0xffff) {
    local_c = local_8;
  }
  iVar1 = func_0x676d77d7(0x404);
  if (iVar1 == 0) {
                    // WARNING: Bad instruction - Truncating control flow here
    halt_baddata();
  }
  local_18 = -1;
  local_10 = 4;
  if (4 < local_c) {
    while( true ) {
      uVar2 = local_10 + 0x400;
      local_10 = local_c;
      if (uVar2 <= local_c) {
        local_10 = uVar2;
      }
      uVar3 = local_8 - (local_8 - local_10);
      uVar2 = 0x404;
      if (uVar3 < 0x405) {
        uVar2 = uVar3;
      }
      iVar4 = func_0x06a47731();
      if ((iVar4 != 0) || (iVar4 = func_0x65a47743(iVar1,uVar2,1), iVar4 != 1)) break;
      iVar4 = uVar2 - 3;
      do {
        iVar5 = iVar4;
        if (iVar5 < 0) goto LAB_004076c4;
        iVar4 = iVar5 + -1;
      } while ((((*(char *)(iVar4 + iVar1) != 'P') || (*(char *)(iVar5 + iVar1) != 'K')) ||
               (*(char *)(iVar5 + 1 + iVar1) != '\x05')) || (*(char *)(iVar5 + 2 + iVar1) != '\x06')
              );
      local_18 = iVar4 + (local_8 - local_10);
LAB_004076c4:
      if ((local_18 != 0) || (local_c <= local_10)) break;
    }
  }
  func_0xc2727894(iVar1);
  return local_18;
}



// WARNING: Control flow encountered bad instruction data

int * __cdecl FUN_004076e7(int param_1)

{
  int iVar1;
  int *piVar2;
  int *piVar3;
  int *piVar4;
  int local_98 [7];
  int local_7c;
  int local_78;
  int local_74;
  undefined4 local_1c;
  int local_18;
  int local_14;
  int local_10;
  int local_c;
  
  if (param_1 == 0) {
                    // WARNING: Bad instruction - Truncating control flow here
    halt_baddata();
  }
  local_c = 0;
  local_14 = func_0xa5a577c1(param_1);
  if (local_14 == -1) {
    local_c = -1;
  }
  iVar1 = func_0x06a477d8();
  if (iVar1 != 0) {
    local_c = -1;
  }
  iVar1 = func_0x3ba577e8();
  if (iVar1 != 0) {
    local_c = -1;
  }
  iVar1 = func_0xffa477fb(param_1);
  if (iVar1 != 0) {
    local_c = -1;
  }
  iVar1 = func_0xffa4780d(param_1);
  if (iVar1 != 0) {
    local_c = -1;
  }
  iVar1 = func_0xffa47822(param_1);
  if (iVar1 != 0) {
    local_c = -1;
  }
  iVar1 = func_0xffa47834(param_1);
  if (iVar1 != 0) {
    local_c = -1;
  }
  if (((param_1 != local_98[1]) || (local_18 != 0)) || (local_10 != 0)) {
    local_c = -0x67;
  }
  iVar1 = func_0x3ba57865();
  if (iVar1 != 0) {
    local_c = -1;
  }
  iVar1 = func_0x3ba57875();
  if (iVar1 != 0) {
    local_c = -1;
  }
  iVar1 = func_0xffa47889(param_1);
  if (iVar1 != 0) {
    local_c = -1;
  }
  if ((uint)(*(int *)(param_1 + 7) + local_14) < (uint)(local_78 + local_74)) {
    if (local_c != 0) goto LAB_00407805;
    local_c = -0x67;
  }
  if (local_c == 0) {
    local_98[3] = ((*(int *)(param_1 + 7) - local_78) - local_74) + local_14;
    local_98[0] = param_1;
    local_7c = local_14;
    local_1c = 0;
    *(undefined4 *)(param_1 + 7) = 0;
    piVar2 = (int *)_malloc(0x80);
    piVar3 = local_98;
    piVar4 = piVar2;
    for (iVar1 = 0x20; iVar1 != 0; iVar1 = iVar1 + -1) {
      *piVar4 = *piVar3;
      piVar3 = piVar3 + 1;
      piVar4 = piVar4 + 1;
    }
    func_0x6daa7902();
    return piVar2;
  }
LAB_00407805:
  func_0xe5a378c0();
                    // WARNING: Bad instruction - Truncating control flow here
  halt_baddata();
}



// WARNING: Control flow encountered bad instruction data

int __cdecl
FUN_00407853(undefined4 *param_1,undefined4 *param_2,undefined4 *param_3,int param_4,uint param_5)

{
  int iVar1;
  uint uVar2;
  undefined4 *puVar3;
  undefined4 local_60 [4];
  uint local_50;
  uint local_40;
  int local_28;
  uint local_24;
  uint local_20;
  uint local_1c;
  int local_18;
  int local_14;
  int local_10;
  int local_c;
  
  local_c = 0;
  if (param_1 == (undefined4 *)0x0) {
                    // WARNING: Bad instruction - Truncating control flow here
    halt_baddata();
  }
  iVar1 = func_0x06a47934();
  if (iVar1 == 0) {
    iVar1 = func_0x3ba57948();
    if (iVar1 == 0) {
      if (local_10 != 0x2014b50) {
        local_c = -0x67;
      }
    }
    else {
      local_c = -1;
    }
  }
  else {
    local_c = -1;
  }
  iVar1 = func_0xffa4796f(*param_1);
  if (iVar1 != 0) {
    local_c = -1;
  }
  iVar1 = func_0xffa47985(*param_1);
  if (iVar1 != 0) {
    local_c = -1;
  }
  iVar1 = func_0xffa47998(*param_1);
  if (iVar1 != 0) {
    local_c = -1;
  }
  iVar1 = func_0xffa479ab(*param_1);
  if (iVar1 != 0) {
    local_c = -1;
  }
  iVar1 = func_0x3ba579be();
  if (iVar1 != 0) {
    local_c = -1;
  }
  local_1c = local_50 >> 0x10 & 0x1f;
  local_14 = (local_50 >> 0x19) + 0x7bc;
  local_20 = local_50 >> 0xb & 0x1f;
  local_18 = (local_50 >> 0x15 & 0xf) - 1;
  local_24 = local_50 >> 5 & 0x3f;
  local_28 = (local_50 & 0x1f) * 2;
  iVar1 = func_0x3ba57a18();
  if (iVar1 != 0) {
    local_c = -1;
  }
  iVar1 = func_0x3ba57a2a();
  if (iVar1 != 0) {
    local_c = -1;
  }
  iVar1 = func_0x3ba57a3c();
  if (iVar1 != 0) {
    local_c = -1;
  }
  iVar1 = func_0xffa47a4e(*param_1);
  if (iVar1 != 0) {
    local_c = -1;
  }
  iVar1 = func_0xffa47a61(*param_1);
  if (iVar1 != 0) {
    local_c = -1;
  }
  iVar1 = func_0xffa47a74(*param_1);
  if (iVar1 != 0) {
    local_c = -1;
  }
  iVar1 = func_0xffa47a87(*param_1);
  if (iVar1 != 0) {
    local_c = -1;
  }
  iVar1 = func_0xffa47a9a(*param_1);
  if (iVar1 != 0) {
    local_c = -1;
  }
  iVar1 = func_0x3ba57aad();
  if (iVar1 != 0) {
    local_c = -1;
  }
  iVar1 = func_0x3ba57abf();
  if (iVar1 != 0) {
    local_c = -1;
  }
  if (local_c == 0) {
    if (param_4 != 0) {
      uVar2 = param_5;
      if (local_40 < param_5) {
        *(undefined *)(local_40 + param_4) = 0;
        uVar2 = local_40;
      }
      if (((local_40 != 0) && (param_5 != 0)) &&
         (iVar1 = func_0x65a47afb(param_4,uVar2,1), iVar1 != 1)) {
        return -1;
      }
    }
    if (param_2 != (undefined4 *)0x0) {
      puVar3 = local_60;
      for (iVar1 = 0x14; iVar1 != 0; iVar1 = iVar1 + -1) {
        *param_2 = *puVar3;
        puVar3 = puVar3 + 1;
        param_2 = param_2 + 1;
      }
    }
    if (param_3 != (undefined4 *)0x0) {
      *param_3 = param_1;
    }
  }
  return local_c;
}



// WARNING: Control flow encountered bad instruction data

int __cdecl FUN_00407afc(undefined4 *param_1,int *param_2,int *param_3,int **param_4)

{
  undefined4 uVar1;
  int iVar2;
  uint local_10;
  int local_c;
  int local_8;
  
  *param_2 = 0;
  *param_3 = 0;
  local_8 = 0;
  *param_4 = (int *)0x0;
  iVar2 = func_0x06a47be0();
  if (iVar2 != 0) {
                    // WARNING: Bad instruction - Truncating control flow here
    halt_baddata();
  }
  iVar2 = func_0x3ba57bf7();
  if (iVar2 == 0) {
    if (local_10 != 0x4034b50) {
      local_8 = -0x67;
    }
  }
  else {
    local_8 = -1;
  }
  iVar2 = func_0xffa47c1e(*param_1);
  if (iVar2 != 0) {
    local_8 = -1;
  }
  iVar2 = func_0xffa47c31(*param_1);
  if (iVar2 != 0) {
    local_8 = -1;
  }
  iVar2 = func_0xffa47c44(*param_1);
  if (iVar2 == 0) {
    if ((local_8 == 0) &&
       ((iVar2 = param_1[0xd], local_c != iVar2 || ((iVar2 != 0 && (iVar2 != 8)))))) {
      local_8 = -0x67;
    }
  }
  else {
    local_8 = -1;
  }
  iVar2 = func_0x3ba57c77();
  if (iVar2 != 0) {
    local_8 = -1;
  }
  iVar2 = func_0x3ba57c89();
  if (iVar2 == 0) {
    if (((local_8 == 0) && (local_c != param_1[0xf])) && ((local_10 & 8) == 0)) {
      local_8 = -0x67;
    }
  }
  else {
    local_8 = -1;
  }
  iVar2 = func_0x3ba57cb8();
  if (iVar2 == 0) {
    if (((local_8 == 0) && (local_c != param_1[0x10])) && ((local_10 & 8) == 0)) {
      local_8 = -0x67;
    }
  }
  else {
    local_8 = -1;
  }
  iVar2 = func_0x3ba57ce7();
  if (iVar2 == 0) {
    if (((local_8 == 0) && (local_c != param_1[0x11])) && ((local_10 & 8) == 0)) {
      local_8 = -0x67;
    }
  }
  else {
    local_8 = -1;
  }
  iVar2 = func_0xffa47d16(*param_1);
  if (iVar2 == 0) {
    if ((local_8 == 0) && (local_10 != param_1[0x12])) {
      local_8 = -0x67;
    }
  }
  else {
    local_8 = -1;
  }
  uVar1 = *param_1;
  *param_2 = *param_2 + local_10;
  iVar2 = func_0xffa47d4b(uVar1);
  if (iVar2 != 0) {
    local_8 = -1;
  }
  *param_3 = param_1[0x1e] + 0x1e + local_10;
  *param_2 = *param_2 + (int)param_2;
  *param_4 = param_2;
  return local_8;
}



// WARNING: Control flow encountered bad instruction data

undefined4 __cdecl FUN_00407cbf(char *param_1)

{
  undefined uVar1;
  int iVar2;
  int *piVar3;
  int *unaff_EBX;
  int local_10;
  int local_c;
  char *local_8;
  
  if ((unaff_EBX == (int *)0x0) || (unaff_EBX[6] == 0)) {
                    // WARNING: Bad instruction - Truncating control flow here
    halt_baddata();
  }
  if (unaff_EBX[0x1f] != 0) {
    func_0x34b07d9c();
  }
  iVar2 = func_0xf3aa7dae();
  if ((iVar2 == 0) && (piVar3 = (int *)func_0x676d7ec0(0x7e), piVar3 != (int *)0x0)) {
    iVar2 = func_0x676d7ed1(0x4000);
    piVar3[0x11] = (int)local_8;
    *piVar3 = iVar2;
    piVar3[0x12] = local_c;
    piVar3[0x13] = 0;
    if (iVar2 != 0) {
      piVar3[0x10] = 0;
      iVar2 = unaff_EBX[0xd];
      piVar3[0x15] = unaff_EBX[0xf];
      piVar3[0x14] = 0;
      piVar3[0x19] = unaff_EBX[0xd];
      piVar3[0x18] = *unaff_EBX;
      piVar3[0x1a] = unaff_EBX[3];
      piVar3[6] = 0;
      if (iVar2 != 0) {
        piVar3[9] = 0;
        piVar3[10] = 0;
        piVar3[0xb] = 0;
        iVar2 = func_0xf89f7e33();
        if (iVar2 == 0) {
          piVar3[0x10] = 1;
        }
      }
      piVar3[0x16] = unaff_EBX[0x10];
      piVar3[0x17] = unaff_EBX[0x11];
      *(byte *)(piVar3 + 0x1b) = *(byte *)(unaff_EBX + 0xc) & 1;
      if (((uint)unaff_EBX[0xc] >> 3 & 1) == 0) {
        uVar1 = *(undefined *)((int)unaff_EBX + 0x3f);
      }
      else {
        uVar1 = *(undefined *)((int)unaff_EBX + 0x39);
      }
      *(undefined *)((int)piVar3 + 0x7d) = uVar1;
      *(uint *)((int)piVar3 + 0x79) = -(uint)(*(char *)(piVar3 + 0x1b) != '\0') & 0xc;
      *(undefined4 *)((int)piVar3 + 0x6d) = 0x12345678;
      *(undefined4 *)((int)piVar3 + 0x71) = 0x23456789;
      *(undefined4 *)((int)piVar3 + 0x75) = 0x34567890;
      local_8 = param_1;
      if (param_1 != (char *)0x0) {
        do {
          if (*local_8 == '\0') break;
          func_0xf09d7ea6();
          local_8 = local_8 + 1;
        } while (local_8 != (char *)0x0);
      }
      piVar3[0xf] = unaff_EBX[0x1e] + 0x1e + local_10;
      piVar3[2] = 0;
      unaff_EBX[0x1f] = (int)piVar3;
      return 0;
    }
    func_0xc2727eed(piVar3);
  }
                    // WARNING: Bad instruction - Truncating control flow here
  halt_baddata();
}



// WARNING: Control flow encountered bad instruction data

int __thiscall FUN_00407e0e(void *this,int param_1,undefined *param_2)

{
  int *piVar1;
  byte bVar2;
  char cVar3;
  int *piVar4;
  int in_EAX;
  int iVar5;
  uint uVar6;
  uint uVar7;
  int iVar8;
  int iVar9;
  int extraout_ECX;
  uint local_14;
  uint local_10;
  int local_c;
  int local_8;
  
  local_c = 0;
  local_8 = 0;
  if (param_2 != (undefined *)0x0) {
    *param_2 = 0;
  }
  if (((in_EAX != 0) && (piVar4 = *(int **)(in_EAX + 0x7c), piVar4 != (int *)0x0)) && (*piVar4 != 0)
     ) {
    if (this == (void *)0x0) {
                    // WARNING: Bad instruction - Truncating control flow here
      halt_baddata();
    }
    piVar4[4] = param_1;
    piVar4[5] = (int)this;
    if ((void *)piVar4[0x17] < this) {
      piVar4[5] = (int)(void *)piVar4[0x17];
    }
    if (piVar4[5] != 0) {
      do {
        if ((piVar4[2] == 0) && (uVar6 = piVar4[0x16], uVar6 != 0)) {
          local_14 = 0x4000;
          if ((uVar6 < 0x4000) && (local_14 = uVar6, uVar6 == 0)) {
            if (param_2 != (undefined *)0x0) {
              *param_2 = 1;
                    // WARNING: Bad instruction - Truncating control flow here
              halt_baddata();
            }
            return;
          }
          iVar5 = func_0x06a47f64();
          if ((iVar5 != 0) || (iVar5 = func_0x65a47f79(*piVar4,local_14,1), iVar5 != 1)) {
            return -1;
          }
          piVar4[0xf] = piVar4[0xf] + local_14;
          piVar4[0x16] = piVar4[0x16] - local_14;
          iVar5 = *piVar4;
          piVar4[1] = iVar5;
          piVar4[2] = local_14;
          if ((*(char *)(piVar4 + 0x1b) != '\0') && (local_10 = 0, local_14 != 0)) {
            iVar8 = (int)piVar4 + 0x6d;
            do {
              uVar6 = *(uint *)(iVar8 + 8) & 0xfffd | 2;
              bVar2 = *(byte *)(local_10 + iVar5);
              func_0xf09d7fc7();
              *(byte *)(local_10 + iVar5) = (byte)((uVar6 ^ 1) * uVar6 >> 8) ^ bVar2;
              local_10 = local_10 + 1;
              iVar8 = extraout_ECX;
            } while (local_10 < local_14);
          }
        }
        uVar6 = piVar4[2];
        uVar7 = *(uint *)((int)piVar4 + 0x79);
        if (uVar6 < *(uint *)((int)piVar4 + 0x79)) {
          uVar7 = uVar6;
        }
        if (uVar7 != 0) {
          cVar3 = *(char *)(piVar4[1] + uVar7 + -1);
          piVar4[0x17] = piVar4[0x17] - uVar7;
          piVar1 = (int *)((int)piVar4 + 0x79);
          *piVar1 = *piVar1 - uVar7;
          piVar4[2] = uVar6 - uVar7;
          piVar4[1] = piVar4[1] + uVar7;
          if ((*piVar1 == 0) && (cVar3 != *(char *)((int)piVar4 + 0x7d))) {
                    // WARNING: Bad instruction - Truncating control flow here
            halt_baddata();
          }
        }
        if (piVar4[0x19] == 0) {
          uVar6 = piVar4[2];
          if ((uint)piVar4[5] < (uint)piVar4[2]) {
            uVar6 = piVar4[5];
          }
          uVar7 = 0;
          if (uVar6 != 0) {
            do {
              *(undefined *)(uVar7 + piVar4[4]) = *(undefined *)(uVar7 + piVar4[1]);
              uVar7 = uVar7 + 1;
            } while (uVar7 < uVar6);
          }
          iVar5 = piVar4[4];
          iVar8 = func_0x159d8040();
          piVar4[0x17] = piVar4[0x17] - uVar6;
          piVar4[2] = piVar4[2] - uVar6;
          piVar4[5] = piVar4[5] - uVar6;
          piVar4[1] = piVar4[1] + uVar6;
          piVar4[6] = piVar4[6] + uVar6;
          local_8 = local_8 + uVar6;
          piVar4[0x14] = iVar8;
          piVar4[4] = iVar5 + uVar6;
          if ((piVar4[0x17] == 0) && (param_2 != (undefined *)0x0)) {
            *param_2 = 1;
          }
        }
        else {
          iVar5 = piVar4[6];
          local_c = func_0x95a0807f();
          iVar8 = piVar4[6];
          iVar9 = func_0x159d8094();
          piVar4[0x17] = piVar4[0x17] - (iVar8 - iVar5);
          local_8 = local_8 + (iVar8 - iVar5);
          piVar4[0x14] = iVar9;
          if ((local_c == 1) || (piVar4[0x17] == 0)) {
            if (param_2 == (undefined *)0x0) {
              return local_8;
            }
            *param_2 = 1;
            return local_8;
          }
          if (local_c != 0) {
            return local_c;
          }
        }
      } while (piVar4[5] != 0);
      if (local_c != 0) {
        return local_c;
      }
    }
    return local_8;
  }
                    // WARNING: Bad instruction - Truncating control flow here
  halt_baddata();
}



undefined8 __fastcall FUN_004080b7(uint param_1)

{
  uint in_EAX;
  short local_1c;
  ushort local_1a;
  ushort local_16;
  ushort local_14;
  ushort local_12;
  short local_10;
  undefined2 local_e;
  undefined8 local_c;
  
  local_1c = ((ushort)param_1 >> 9) + 0x7bc;
  local_16 = (ushort)param_1 & 0x1f;
  local_14 = (ushort)in_EAX >> 0xb;
  local_10 = ((ushort)in_EAX & 0x1f) * 2;
  local_e = 0;
  local_1a = (ushort)(param_1 >> 5) & 0xf;
  local_12 = (ushort)(in_EAX >> 5) & 0x3f;
  (*(code *)u_f__dd_vctools_vc7libs_ship_atlmf_0042815f._101_4_)(&local_1c,&local_c);
  return local_c;
}



// WARNING: Control flow encountered bad instruction data

void __thiscall FUN_0040821e(void *this,int param_1)

{
  short sVar1;
  byte bVar2;
  uint uVar3;
  short *psVar4;
  byte bVar5;
  int iVar6;
  byte bVar7;
  uint uVar8;
  int *unaff_EBX;
  int *piVar9;
  char *pcVar10;
  char *pcVar11;
  bool bVar12;
  undefined8 uVar13;
  uint local_398 [4];
  uint local_388;
  int local_380;
  int local_37c;
  uint local_364;
  undefined8 local_348;
  int local_340;
  int local_33c;
  char local_338 [4];
  uint local_334;
  int *local_330;
  int local_32c;
  uint local_328;
  byte local_322;
  byte local_321;
  short local_320 [260];
  undefined local_118 [268];
  uint local_c;
  
  local_c = DAT_00431c20 ^ (uint)&stack0xfffffffc;
  local_330 = (int *)this;
                    // WARNING: Load size is inaccurate
  if ((param_1 < -1) || (*(int *)(*this + 4) <= param_1)) {
    func_0x485e8915();
    return;
  }
  if (*(int *)((int)this + 4) != -1) {
    func_0x34b08313();
  }
  *(undefined4 *)((int)this + 4) = 0xffffffff;
  if (param_1 == *(int *)((int)this + 0x238)) {
    if (param_1 != -1) {
      piVar9 = (int *)((int)this + 8);
      for (iVar6 = 0x8c; iVar6 != 0; iVar6 = iVar6 + -1) {
        *unaff_EBX = *piVar9;
        piVar9 = piVar9 + 1;
        unaff_EBX = unaff_EBX + 1;
      }
      return;
    }
  }
  else if (param_1 != -1) {
                    // WARNING: Load size is inaccurate
    if (param_1 < *(int *)(*this + 0x10)) {
      func_0x6daa8392();
      this = local_330;
    }
                    // WARNING: Load size is inaccurate
    iVar6 = *(int *)(*this + 0x10);
    while (iVar6 < param_1) {
      func_0xa2aa83a9();
      this = local_330;
      iVar6 = *(int *)(*local_330 + 0x10);
    }
                    // WARNING: Load size is inaccurate
    func_0x4aa883dc(*this,local_398,0,local_118,0x104);
                    // WARNING: Load size is inaccurate
    iVar6 = func_0xf3aa83fb(*this,&local_32c,&local_328,&local_334);
    if (iVar6 != 0) {
                    // WARNING: Bad instruction - Truncating control flow here
      halt_baddata();
    }
    iVar6 = func_0x06a4841d();
    if (iVar6 == 0) {
      local_32c = func_0x0aba8436(local_334);
      uVar3 = func_0x65a48455(local_32c,1,local_334);
      if (uVar3 == local_334) {
        *unaff_EBX = *(int *)(*local_330 + 0x10);
        (*DAT_004281f0)(0xfde9,0,local_118,0xffffffff,local_320,0x104);
        psVar4 = local_320;
        while( true ) {
          while( true ) {
            for (; (sVar1 = *psVar4, sVar1 != 0 && (psVar4[1] == 0x3a)); psVar4 = psVar4 + 2) {
            }
            if ((sVar1 != 0x5c) && (sVar1 != 0x2f)) break;
            psVar4 = psVar4 + 1;
          }
          iVar6 = func_0xb96785d1(psVar4,&DAT_0042d4a0);
          if ((iVar6 == 0) &&
             (((iVar6 = func_0xb96785e2(psVar4,&DAT_0042d4ac), iVar6 == 0 &&
               (iVar6 = func_0xb96785f3(psVar4,&DAT_0042d4b8), iVar6 == 0)) &&
              (iVar6 = func_0xb9678604(psVar4,&DAT_0042d4c4), iVar6 == 0)))) break;
          psVar4 = (short *)(iVar6 + 8);
        }
        iVar6 = 4 - (int)psVar4;
        do {
          sVar1 = *psVar4;
          *(short *)((int)unaff_EBX + iVar6 + (int)psVar4) = sVar1;
          psVar4 = psVar4 + 1;
        } while (sVar1 != 0);
        bVar5 = ~(byte)(local_364 >> 0x17);
        local_398[0] = local_398[0] >> 8;
        bVar2 = (byte)(local_364 >> 0x1e);
        local_321 = 0;
        local_322 = 0;
        bVar7 = 1;
        if (((local_398[0] == 0) || (local_398[0] == 7)) ||
           ((local_398[0] == 0xb || (local_398[0] == 0xe)))) {
          local_321 = (byte)(local_364 >> 1) & 1;
          local_322 = (byte)(local_364 >> 2) & 1;
          bVar5 = (byte)local_364;
          bVar2 = (byte)(local_364 >> 4);
          bVar7 = (byte)(local_364 >> 5) & 1;
        }
        unaff_EBX[0x83] = 0;
        if ((bVar2 & 1) != 0) {
          unaff_EBX[0x83] = 0x10;
        }
        if (bVar7 != 0) {
          unaff_EBX[0x83] = unaff_EBX[0x83] | 0x20;
        }
        if (local_321 != 0) {
          unaff_EBX[0x83] = unaff_EBX[0x83] | 2;
        }
        if ((bVar5 & 1) != 0) {
          unaff_EBX[0x83] = unaff_EBX[0x83] | 1;
        }
        if (local_322 != 0) {
          unaff_EBX[0x83] = unaff_EBX[0x83] | 4;
        }
        unaff_EBX[0x8a] = local_380;
        unaff_EBX[0x8b] = local_37c;
        local_348 = FUN_004080b7(local_388 >> 0x10);
        (*(code *)u_f__dd_vctools_vc7libs_ship_atlmf_0042815f._93_4_)(&local_348,&local_340);
        uVar3 = 0;
        unaff_EBX[0x84] = local_340;
        unaff_EBX[0x85] = local_33c;
        unaff_EBX[0x86] = local_340;
        unaff_EBX[0x87] = local_33c;
        unaff_EBX[0x88] = local_340;
        unaff_EBX[0x89] = local_33c;
        if (local_334 < 5) {
LAB_00408713:
          if (local_32c != 0) {
            func_0x15ba87dd(local_32c);
          }
          piVar9 = local_330 + 2;
          for (iVar6 = 0x8c; iVar6 != 0; iVar6 = iVar6 + -1) {
            *piVar9 = *unaff_EBX;
            unaff_EBX = unaff_EBX + 1;
            piVar9 = piVar9 + 1;
          }
          local_330[0x8e] = param_1;
                    // WARNING: Bad instruction - Truncating control flow here
          halt_baddata();
        }
        local_338[2] = 0;
        do {
          local_338[0] = *(char *)(uVar3 + local_32c);
          local_338[1] = *(undefined *)(local_32c + 1 + uVar3);
          iVar6 = 3;
          bVar12 = true;
          pcVar10 = local_338;
          pcVar11 = &DAT_0042d4d0;
          do {
            if (iVar6 == 0) break;
            iVar6 = iVar6 + -1;
            bVar12 = *pcVar10 == *pcVar11;
            pcVar10 = pcVar10 + 1;
            pcVar11 = pcVar11 + 1;
          } while (bVar12);
          if (bVar12) {
            bVar5 = *(byte *)(uVar3 + 4 + local_32c);
            local_328 = (uint)bVar5;
            local_322 = bVar5 >> 1 & 1;
            local_321 = bVar5 >> 2 & 1;
            uVar8 = uVar3 + 5;
            if ((bVar5 & 1) != 0) {
              local_328 = uVar3 + 9;
              uVar13 = func_0x91b0872b();
              *(undefined8 *)(unaff_EBX + 0x88) = uVar13;
              uVar8 = local_328;
            }
            if (local_322 != 0) {
              local_328 = uVar8 + 4;
              uVar13 = func_0x91b08776();
              *(undefined8 *)(unaff_EBX + 0x84) = uVar13;
            }
            if (local_321 != 0) {
              uVar13 = func_0x91b087bd();
              *(undefined8 *)(unaff_EBX + 0x86) = uVar13;
            }
            goto LAB_00408713;
          }
          uVar3 = uVar3 + 4 + (uint)*(byte *)(uVar3 + 2 + local_32c);
          local_328 = uVar3;
          if (local_334 <= uVar3 + 4) {
                    // WARNING: Bad instruction - Truncating control flow here
            halt_baddata();
          }
        } while( true );
      }
      func_0x15ba846b(local_32c);
    }
                    // WARNING: Bad instruction - Truncating control flow here
    halt_baddata();
  }
                    // WARNING: Load size is inaccurate
  *unaff_EBX = *(int *)(*this + 4);
  *(undefined2 *)(unaff_EBX + 1) = 0;
  unaff_EBX[0x83] = 0;
  unaff_EBX[0x84] = 0;
  unaff_EBX[0x85] = 0;
  unaff_EBX[0x86] = 0;
  unaff_EBX[0x87] = 0;
  unaff_EBX[0x88] = 0;
  unaff_EBX[0x89] = 0;
  unaff_EBX[0x8a] = 0;
  unaff_EBX[0x8b] = 0;
                    // WARNING: Bad instruction - Truncating control flow here
  halt_baddata();
}



void __thiscall FUN_00408763(void *this,undefined4 param_1,undefined4 param_2)

{
  int iVar1;
  char local_9;
  uint local_8;
  
  local_8 = DAT_00431c20 ^ (uint)&stack0xfffffffc;
  if (*(int *)((int)this + 4) != 0) {
    if (*(int *)((int)this + 4) != -1) {
      func_0x34b0884a();
    }
                    // WARNING: Load size is inaccurate
    *(undefined4 *)((int)this + 4) = 0xffffffff;
    if (*(int *)(*this + 4) < 1) goto LAB_00408826;
    if (0 < *(int *)(*this + 0x10)) {
      func_0x6daa8868();
    }
                    // WARNING: Load size is inaccurate
    while (*(int *)(*this + 0x10) < 0) {
      func_0xa2aa8871();
    }
    func_0xb6ac8886(*(undefined4 *)((int)this + 0x23c));
    *(undefined4 *)((int)this + 4) = 0;
  }
  iVar1 = func_0x05ae88a1(param_1,&local_9);
  if (iVar1 < 1) {
    func_0x34b088b0();
    *(undefined4 *)((int)this + 4) = 0xffffffff;
  }
LAB_00408826:
  func_0x485e89e9();
  return;
}



undefined4 FUN_004089cd(undefined4 param_1)

{
  undefined4 uVar1;
  
  uVar1 = DAT_00431000;
  DAT_00431000 = param_1;
  return uVar1;
}



// Library Function - Single Match
//  void * __cdecl operator new(unsigned int)
// 
// Libraries: Visual Studio 2008 Release, Visual Studio 2010 Release, Visual Studio 2012 Release

void * __cdecl operator_new(uint param_1)

{
  int iVar1;
  void *pvVar2;
  
  while( true ) {
    pvVar2 = (void *)func_0x676d8bbd(param_1);
    if (pvVar2 != (void *)0x0) {
      return pvVar2;
    }
    if (DAT_00431000 == (code *)0x0) break;
    iVar1 = (*DAT_00431000)(param_1);
    if (iVar1 == 0) {
      return (void *)0x0;
    }
  }
  return (void *)0x0;
}



// WARNING: Control flow encountered bad instruction data

void FUN_00408a13(void)

{
                    // WARNING: Bad instruction - Truncating control flow here
  halt_baddata();
}



// WARNING: Control flow encountered bad instruction data

void FUN_00408a1e(void)

{
                    // WARNING: Bad instruction - Truncating control flow here
  halt_baddata();
}



// Library Function - Single Match
//  public: int __thiscall CRuntimeClass::IsDerivedFrom(struct CRuntimeClass const *)const 
// 
// Libraries: Visual Studio 2008 Release, Visual Studio 2010 Release

int __thiscall CRuntimeClass::IsDerivedFrom(CRuntimeClass *this,CRuntimeClass *param_1)

{
  if (this != (CRuntimeClass *)0x0) goto LAB_00408a89;
  do {
    this = (CRuntimeClass *)func_0xecbb8b3f();
LAB_00408a89:
  } while (param_1 == (CRuntimeClass *)0x0);
  do {
    if (this == param_1) {
      return 1;
    }
    this = *(CRuntimeClass **)(this + 0x10);
  } while (this != (CRuntimeClass *)0x0);
  return 0;
}



// WARNING: Control flow encountered bad instruction data

void __fastcall FUN_00408aa4(undefined4 *param_1)

{
  int iVar1;
  undefined4 *extraout_ECX;
  
  if (param_1 != (undefined4 *)0x0) goto LAB_00408ab2;
  do {
    func_0xecbb8b68();
    param_1 = extraout_ECX;
LAB_00408ab2:
    iVar1 = (**(code **)*param_1)();
  } while (iVar1 == 0);
                    // WARNING: Bad instruction - Truncating control flow here
  halt_baddata();
}



void FUN_00408ac2(undefined4 param_1)

{
  func_0x59d08b83();
  func_0xa5c28b8c(0);
  func_0xaabe8b97(param_1);
  func_0x17c38b9e(0);
  return;
}



void __fastcall FUN_00408afb(int *param_1)

{
                    // WARNING: Could not recover jumptable at 0x00408b03. Too many branches
                    // WARNING: Treating indirect jump as call
  (**(code **)(*param_1 + 0x10))();
  return;
}



void FUN_00408bbd(void)

{
  code *pcVar1;
  undefined *local_8;
  
  local_8 = &DAT_00431198;
  func_0xa57f8d8e(&local_8,&DAT_0042e600);
  pcVar1 = (code *)swi(3);
  (*pcVar1)();
  return;
}



void FUN_00408bd9(void)

{
  code *pcVar1;
  char *local_8;
  
  local_8 = s_ABCDEFGHIJKLMNOPQRSTUVWXYZ_00431299 + 0x17;
  func_0xa57f8daa(&local_8,&DAT_0042e6b4);
  pcVar1 = (code *)swi(3);
  (*pcVar1)();
  return;
}



void FUN_00408bf5(void)

{
  code *pcVar1;
  undefined *local_8;
  
  local_8 = &DAT_004313c8;
  func_0xa57f8dc6(&local_8,&DAT_0042e6f8);
  pcVar1 = (code *)swi(3);
  (*pcVar1)();
  return;
}



// WARNING: Control flow encountered bad instruction data
// Library Function - Single Match
//  int __cdecl AfxCrtErrorCheck(int)
// 
// Libraries: Visual Studio 2008 Release, Visual Studio 2010 Release, Visual Studio 2012 Release,
// Visual Studio 2015 Release

int __cdecl AfxCrtErrorCheck(int param_1)

{
  if (param_1 != 0) {
    if (param_1 == 0xc) {
                    // WARNING: Bad instruction - Truncating control flow here
      halt_baddata();
    }
    if (((param_1 == 0x16) || (param_1 == 0x22)) || (param_1 != 0x50)) {
                    // WARNING: Bad instruction - Truncating control flow here
      halt_baddata();
    }
  }
  return param_1;
}



void __cdecl
FUN_00408c6c(undefined4 param_1,undefined4 param_2,undefined4 param_3,undefined4 param_4)

{
  undefined4 uVar1;
  
  uVar1 = func_0xf17f8e38(param_1,param_2,param_3,param_4);
  func_0x37bc8d3e(uVar1);
  return;
}



void __thiscall FUN_00408c97(void *this,undefined4 param_1)

{
  *(undefined4 *)((int)this + 4) = param_1;
  return;
}



// Library Function - Single Match
//  public: virtual int __thiscall CSimpleException::GetErrorMessage(wchar_t *,unsigned int,unsigned
// int *)const 
// 
// Library: Visual Studio 2008 Release

int __thiscall
CSimpleException::GetErrorMessage
          (CSimpleException *this,wchar_t *param_1,uint param_2,uint *param_3)

{
  int iVar1;
  
  if ((param_1 == (wchar_t *)0x0) || (param_2 == 0)) {
    iVar1 = 0;
  }
  else {
    if (param_3 != (uint *)0x0) {
      *param_3 = 0;
    }
    if (*(int *)(this + 0xc) == 0) {
      func_0x89bb8d89();
    }
    if (*(int *)(this + 0x10) == 0) {
      *param_1 = L'\0';
    }
    else {
      func_0x63bc8d9e(param_1,param_2,this + 0x14,0xffffffff);
    }
    iVar1 = *(int *)(this + 0x10);
  }
  return iVar1;
}



void FUN_00408cff(undefined4 param_1)

{
  func_0x15ba8dc2(param_1);
  return;
}



undefined4 * __thiscall FUN_00408d11(void *this,byte param_1)

{
  *(int *)this = (int)u_ole32_dll_00428631 + 7;
  if ((param_1 & 1) != 0) {
    func_0x15ba8de1(this);
  }
  return (undefined4 *)this;
}



void FUN_00408d33(undefined4 param_1)

{
  int iVar1;
  
  iVar1 = (*(code *)u_f__dd_vctools_vc7libs_ship_atlmf_0042815f._73_4_)(0x40,param_1);
  if (iVar1 == 0) {
    func_0xb4bb8e02();
  }
  return;
}



void FUN_00408d50(int param_1)

{
  if (param_1 != 0) {
                    // WARNING: Could not recover jumptable at 0x00408d5c. Too many branches
                    // WARNING: Treating indirect jump as call
    (*(code *)u_f__dd_vctools_vc7libs_ship_atlmf_0042815f._69_4_)();
    return;
  }
  return;
}



// Library Function - Single Match
//  public: void * __thiscall CThreadSlotData::GetThreadValue(int)
// 
// Libraries: Visual Studio 2008 Release, Visual Studio 2010 Release

void * __thiscall CThreadSlotData::GetThreadValue(CThreadSlotData *this,int param_1)

{
  CThreadSlotData *pCVar1;
  void *pvVar2;
  int iVar3;
  
  pCVar1 = this + 0x1c;
  (*(code *)u_f__dd_vctools_vc7libs_ship_atlmf_0042815f._57_4_)(pCVar1);
  if ((((0 < param_1) && (param_1 < *(int *)(this + 0xc))) &&
      (iVar3 = (*(code *)u_f__dd_vctools_vc7libs_ship_atlmf_0042815f._61_4_)(*(undefined4 *)this),
      iVar3 != 0)) && (param_1 < *(int *)(iVar3 + 8))) {
    pvVar2 = *(void **)(*(int *)(iVar3 + 0xc) + param_1 * 4);
    (*(code *)u_f__dd_vctools_vc7libs_ship_atlmf_0042815f._65_4_)(pCVar1);
    return pvVar2;
  }
  (*(code *)u_f__dd_vctools_vc7libs_ship_atlmf_0042815f._65_4_)(pCVar1);
  return (void *)0x0;
}



// Library Function - Single Match
//  public: __thiscall CProcessLocalObject::~CProcessLocalObject(void)
// 
// Libraries: Visual Studio 2005 Release, Visual Studio 2008 Release, Visual Studio 2010 Release

void __thiscall CProcessLocalObject::~CProcessLocalObject(CProcessLocalObject *this)

{
  if (*(int *)this != 0) {
    if (*(undefined4 **)this != (undefined4 *)0x0) {
      (**(code **)**(undefined4 **)this)(1);
    }
  }
  return;
}



// Library Function - Multiple Matches With Same Base Name
//  long __cdecl ATL::AtlMultiply<unsigned int>(unsigned int *,unsigned int,unsigned int)
//  long __cdecl ATL::AtlMultiply<unsigned long>(unsigned long *,unsigned long,unsigned long)
// 
// Library: Visual Studio 2008 Release

undefined4 __cdecl AtlMultiply<>(undefined4 *param_1,uint param_2,uint param_3)

{
  if ((int)((ulonglong)param_2 * (ulonglong)param_3 >> 0x20) != 0) {
    return 0x80070057;
  }
  *param_1 = (int)((ulonglong)param_2 * (ulonglong)param_3);
  return 0;
}



void FUN_00408e56(int param_1)

{
  code *pcVar1;
  
  if (param_1 == -0x7ff8fff2) {
    func_0xb4bb8f1f();
  }
  func_0x44d58f27(param_1);
  pcVar1 = (code *)swi(3);
  (*pcVar1)();
  return;
}



int __thiscall FUN_00408e72(void *this,int param_1)

{
  void *extraout_ECX;
  
  if (param_1 == 0) {
    func_0xecbb8f38();
    this = extraout_ECX;
  }
  return *(int *)((int)this + 4) + param_1;
}



undefined4 __cdecl FUN_00408e8c(undefined4 param_1,undefined4 param_2)

{
  int iVar1;
  undefined4 local_8;
  
  iVar1 = func_0x29be8f57(&local_8,param_1,param_2);
  if (iVar1 < 0) {
    func_0x4dbe8f64(iVar1);
  }
  return local_8;
}



// Library Function - Single Match
//  public: void __thiscall CSimpleList::AddHead(void *)
// 
// Library: Visual Studio 2008 Release

void __thiscall CSimpleList::AddHead(CSimpleList *this,void *param_1)

{
  undefined4 *puVar1;
  
  puVar1 = (undefined4 *)func_0x69be8f7b(param_1);
  *puVar1 = *(undefined4 *)this;
  *(void **)this = param_1;
  return;
}



// Library Function - Single Match
//  public: int __thiscall CThreadSlotData::AllocSlot(void)
// 
// Libraries: Visual Studio 2008 Release, Visual Studio 2010 Release

int __thiscall CThreadSlotData::AllocSlot(CThreadSlotData *this)

{
  CThreadSlotData *pCVar1;
  uint *puVar2;
  byte *pbVar3;
  undefined4 uVar4;
  int iVar5;
  undefined4 uVar6;
  int iVar7;
  int iVar8;
  
  pCVar1 = this + 0x1c;
  (*(code *)u_f__dd_vctools_vc7libs_ship_atlmf_0042815f._57_4_)(pCVar1);
  iVar7 = *(int *)(this + 4);
  iVar8 = *(int *)(this + 8);
  if ((iVar7 <= iVar8) || ((*(byte *)(*(int *)(this + 0x10) + iVar8 * 8) & 1) != 0)) {
    iVar8 = 1;
    if (1 < iVar7) {
      pbVar3 = *(byte **)(this + 0x10);
      do {
        pbVar3 = pbVar3 + 8;
        if ((*pbVar3 & 1) == 0) break;
        iVar8 = iVar8 + 1;
      } while (iVar8 < iVar7);
      if (iVar8 < iVar7) goto LAB_00408fbf;
    }
    iVar7 = iVar7 + 0x20;
    if (*(int *)(this + 0x10) == 0) {
      uVar4 = func_0x83be8feb(iVar7,8);
      iVar5 = (*(code *)u_f__dd_vctools_vc7libs_ship_atlmf_0042815f._37_4_)(2,uVar4);
    }
    else {
      uVar4 = (*(code *)u_f__dd_vctools_vc7libs_ship_atlmf_0042815f._41_4_)(*(int *)(this + 0x10));
      (*(code *)u_f__dd_vctools_vc7libs_ship_atlmf_0042815f._45_4_)(uVar4);
      uVar6 = func_0x83be9016(iVar7,8,0x2002);
      iVar5 = (*(code *)u_f__dd_vctools_vc7libs_ship_atlmf_0042815f._49_4_)(uVar4,uVar6);
    }
    if (iVar5 == 0) {
      this = *(CThreadSlotData **)(this + 0x10);
      if (this != (CThreadSlotData *)0x0) {
        uVar4 = (*(code *)u_f__dd_vctools_vc7libs_ship_atlmf_0042815f._41_4_)(this);
        (*(code *)u_f__dd_vctools_vc7libs_ship_atlmf_0042815f._53_4_)(uVar4);
      }
      (*(code *)u_f__dd_vctools_vc7libs_ship_atlmf_0042815f._65_4_)(pCVar1);
      iVar5 = func_0xb4bb9049();
    }
    iVar5 = (*(code *)u_f__dd_vctools_vc7libs_ship_atlmf_0042815f._53_4_)(iVar5);
    func_0x3b829169(iVar5 + *(int *)(this + 4) * 8,0,(iVar7 - *(int *)(this + 4)) * 8);
    *(int *)(this + 4) = iVar7;
    *(int *)(this + 0x10) = iVar5;
  }
LAB_00408fbf:
  if (*(int *)(this + 0xc) <= iVar8) {
    *(int *)(this + 0xc) = iVar8 + 1;
  }
  puVar2 = (uint *)(*(int *)(this + 0x10) + iVar8 * 8);
  *puVar2 = *puVar2 | 1;
  *(int *)(this + 8) = iVar8 + 1;
  (*(code *)u_f__dd_vctools_vc7libs_ship_atlmf_0042815f._65_4_)(pCVar1);
  return iVar8;
}



// Library Function - Single Match
//  public: void __thiscall CThreadSlotData::FreeSlot(int)
// 
// Libraries: Visual Studio 2008 Release, Visual Studio 2010 Release

void __thiscall CThreadSlotData::FreeSlot(CThreadSlotData *this,int param_1)

{
  uint *puVar1;
  undefined4 *puVar2;
  int iVar3;
  
  (*(code *)u_f__dd_vctools_vc7libs_ship_atlmf_0042815f._57_4_)(this + 0x1c);
  if ((0 < param_1) && (param_1 < *(int *)(this + 0xc))) {
    for (iVar3 = *(int *)(this + 0x14); iVar3 != 0; iVar3 = *(int *)(iVar3 + 4)) {
      if (param_1 < *(int *)(iVar3 + 8)) {
        puVar2 = *(undefined4 **)(*(int *)(iVar3 + 0xc) + param_1 * 4);
        if (puVar2 != (undefined4 *)0x0) {
          (**(code **)*puVar2)(1);
        }
        *(undefined4 *)(*(int *)(iVar3 + 0xc) + param_1 * 4) = 0;
      }
    }
    puVar1 = (uint *)(*(int *)(this + 0x10) + param_1 * 8);
    *puVar1 = *puVar1 & 0xfffffffe;
  }
  (*(code *)u_f__dd_vctools_vc7libs_ship_atlmf_0042815f._65_4_)(this + 0x1c);
  return;
}



void * __thiscall FUN_004091c5(void *this,byte param_1)

{
  if ((param_1 & 1) != 0) {
    func_0x47bd928f(this);
  }
  return this;
}



// Library Function - Single Match
//  void __stdcall AfxLockGlobals(int)
// 
// Libraries: Visual Studio 2008 Release, Visual Studio 2010 Release

void AfxLockGlobals(int param_1)

{
  int *piVar1;
  undefined4 uVar2;
  
  if (0x10 < (uint)param_1) {
    func_0xecbb9379();
  }
  if (DAT_004330e0 == 0) {
    func_0x81c29387();
  }
  uVar2 = u_f__dd_vctools_vc7libs_ship_atlmf_0042815f._57_4_;
  piVar1 = (int *)(&DAT_00433298 + param_1 * 4);
  if (*piVar1 == 0) {
    (*(code *)u_f__dd_vctools_vc7libs_ship_atlmf_0042815f._57_4_)(&DAT_00433280);
    if (*piVar1 == 0) {
      (*(code *)u_f__dd_vctools_vc7libs_ship_atlmf_0042815f._33_4_)(&DAT_004330e8 + param_1 * 0x18);
      *piVar1 = *piVar1 + 1;
    }
    (*(code *)u_f__dd_vctools_vc7libs_ship_atlmf_0042815f._65_4_)(&DAT_00433280);
  }
  (*(code *)uVar2)(&DAT_004330e8 + param_1 * 0x18);
  return;
}



void FUN_00409320(uint param_1)

{
  if (0x10 < param_1) {
    param_1 = func_0xecbb93e8();
  }
  (*(code *)u_f__dd_vctools_vc7libs_ship_atlmf_0042815f._65_4_)(&DAT_004330e8 + param_1 * 0x18);
  return;
}



void FUN_0040934a(void)

{
  if (DAT_004332e0 != (code *)0x0) {
                    // WARNING: Could not recover jumptable at 0x00409359. Too many branches
                    // WARNING: Treating indirect jump as call
    (*DAT_004332e0)();
    return;
  }
  return;
}



undefined4 FUN_0040935f(void)

{
  undefined4 uVar1;
  
  if (DAT_004332e4 != (code *)0x0) {
                    // WARNING: Could not recover jumptable at 0x0040936e. Too many branches
                    // WARNING: Treating indirect jump as call
    uVar1 = (*DAT_004332e4)();
    return uVar1;
  }
  return 0;
}



undefined4 FUN_00409376(void)

{
  undefined4 uVar1;
  
  if (DAT_004332e8 != (code *)0x0) {
                    // WARNING: Could not recover jumptable at 0x00409385. Too many branches
                    // WARNING: Treating indirect jump as call
    uVar1 = (*DAT_004332e8)();
    return uVar1;
  }
  return 0;
}



// Library Function - Single Match
//  enum eActCtxResult __stdcall AfxActivateActCtxWrapper(void *,unsigned long *)
// 
// Library: Visual Studio 2008 Release

eActCtxResult AfxActivateActCtxWrapper(void *param_1,ulong *param_2)

{
  int iVar1;
  eActCtxResult eVar2;
  
  if (param_2 == (ulong *)0x0) {
    func_0xecbb9453();
  }
  if (DAT_004332e4 == 0) {
    eVar2 = 2;
  }
  else {
    iVar1 = func_0x56c39467(param_1,param_2);
    eVar2 = (eActCtxResult)(iVar1 != 0);
  }
  return eVar2;
}



void __cdecl FUN_004093c0(undefined4 param_1,int param_2,undefined4 param_3,int param_4)

{
  func_0x50739592(param_1,param_2 * 2,param_3,param_4 * 2);
  return;
}



void __cdecl
FUN_004093e1(undefined4 param_1,undefined4 param_2,undefined4 param_3,undefined4 param_4)

{
  undefined4 uVar1;
  
  uVar1 = func_0xb7c394ad(param_1,param_2,param_3,param_4);
  func_0x37bc94b3(uVar1);
  return;
}



// Library Function - Single Match
//  struct ATL::ATLSTRINGRESOURCEIMAGE const * __cdecl ATL::_AtlGetStringResourceImage(struct
// HINSTANCE__ *,struct HRSRC__ *,unsigned int)
// 
// Libraries: Visual Studio 2008 Release, Visual Studio 2010 Release

ATLSTRINGRESOURCEIMAGE * __cdecl
ATL::_AtlGetStringResourceImage(HINSTANCE__ *param_1,HRSRC__ *param_2,uint param_3)

{
  int iVar1;
  ushort *puVar2;
  ushort *puVar3;
  uint uVar4;
  
  iVar1 = (*DAT_004281dc)(param_1,param_2);
  if (iVar1 == 0) {
    return (ATLSTRINGRESOURCEIMAGE *)0x0;
  }
  puVar2 = (ushort *)(*DAT_004281d8)(iVar1);
  if (puVar2 != (ushort *)0x0) {
    iVar1 = (*DAT_004281e0)(param_1,param_2);
    puVar3 = (ushort *)(iVar1 + (int)puVar2);
    for (uVar4 = param_3 & 0xf; uVar4 != 0; uVar4 = uVar4 - 1) {
      if (puVar3 <= puVar2) {
        return (ATLSTRINGRESOURCEIMAGE *)0x0;
      }
      puVar2 = puVar2 + *puVar2 + 1;
    }
    if (puVar2 < puVar3) {
      return (ATLSTRINGRESOURCEIMAGE *)(-(uint)(*puVar2 != 0) & (uint)puVar2);
    }
  }
  return (ATLSTRINGRESOURCEIMAGE *)0x0;
}



// Library Function - Single Match
//  struct ATL::ATLSTRINGRESOURCEIMAGE const * __cdecl ATL::AtlGetStringResourceImage(struct
// HINSTANCE__ *,unsigned int)
// 
// Libraries: Visual Studio 2008 Release, Visual Studio 2010 Release, Visual Studio 2012 Release

ATLSTRINGRESOURCEIMAGE * __cdecl ATL::AtlGetStringResourceImage(HINSTANCE__ *param_1,uint param_2)

{
  int iVar1;
  ATLSTRINGRESOURCEIMAGE *pAVar2;
  
  iVar1 = (*DAT_004281e4)(param_1,(param_2 >> 4) + 1 & 0xffff,6);
  if (iVar1 == 0) {
    return (ATLSTRINGRESOURCEIMAGE *)0x0;
  }
  pAVar2 = (ATLSTRINGRESOURCEIMAGE *)func_0xf9c39542(param_1,iVar1,param_2);
  return pAVar2;
}



// Library Function - Single Match
//  public: static void __cdecl ATL::ChTraitsCRT<wchar_t>::ConvertToBaseType(wchar_t *,int,wchar_t
// const *,int)
// 
// Libraries: Visual Studio 2005 Release, Visual Studio 2008 Release, Visual Studio 2010 Release

void __cdecl
ATL::ChTraitsCRT<wchar_t>::ConvertToBaseType
          (wchar_t *param_1,int param_2,wchar_t *param_3,int param_4)

{
  int iVar1;
  
  if (param_4 == -1) {
    iVar1 = func_0xb5829676(param_3);
    param_4 = iVar1 + 1;
  }
  func_0xd8c39587(param_1,param_2,param_3,param_4);
  return;
}



// Library Function - Single Match
//  private: void __thiscall ATL::CSimpleStringT<wchar_t,0>::SetLength(int)
// 
// Library: Visual Studio 2008 Release

void __thiscall
ATL::CSimpleStringT<wchar_t,0>::SetLength(CSimpleStringT<wchar_t,0> *this,int param_1)

{
  code *pcVar1;
  
  if ((-1 < param_1) && (param_1 <= *(int *)(*(int *)this + -8))) {
    *(int *)(*(int *)this + -0xc) = param_1;
    *(undefined2 *)(*(int *)this + param_1 * 2) = 0;
    return;
  }
  func_0x4dbe95b8(0x80070057);
  pcVar1 = (code *)swi(3);
  (*pcVar1)();
  return;
}



// Library Function - Single Match
//  private: static struct ATL::CStringData * __cdecl
// ATL::CSimpleStringT<wchar_t,0>::CloneData(struct ATL::CStringData *)
// 
// Libraries: Visual Studio 2008 Release, Visual Studio 2010 Release

CStringData * __cdecl ATL::CSimpleStringT<wchar_t,0>::CloneData(CStringData *param_1)

{
  int *piVar1;
  undefined4 *puVar2;
  CStringData *pCVar3;
  
  puVar2 = (undefined4 *)(**(code **)(**(int **)param_1 + 0x10))();
  piVar1 = (int *)(param_1 + 0xc);
  if ((*piVar1 < 0) || (puVar2 != *(undefined4 **)param_1)) {
    pCVar3 = (CStringData *)(**(code **)*puVar2)(*(undefined4 *)(param_1 + 4),2);
    if (pCVar3 == (CStringData *)0x0) {
      func_0xfac49602();
    }
    *(undefined4 *)(pCVar3 + 4) = *(undefined4 *)(param_1 + 4);
    func_0xb7c3961b(pCVar3 + 0x10,*(int *)(param_1 + 4) + 1,param_1 + 0x10,*(int *)(param_1 + 4) + 1
                   );
  }
  else {
    LOCK();
    *piVar1 = *piVar1 + 1;
    UNLOCK();
    pCVar3 = param_1;
  }
  return pCVar3;
}



void __cdecl FUN_0040956e(undefined4 param_1,int param_2,undefined4 param_3,int param_4)

{
  func_0xcf829740(param_1,param_2 * 2,param_3,param_4 * 2);
  return;
}



// WARNING: Control flow encountered bad instruction data

undefined4 __cdecl FUN_0040958f(int param_1)

{
  if (param_1 == 0) {
    return 0;
  }
                    // WARNING: Bad instruction - Truncating control flow here
  halt_baddata();
}



// Library Function - Single Match
//  private: void __thiscall ATL::CSimpleStringT<wchar_t,0>::Fork(int)
// 
// Libraries: Visual Studio 2005 Release, Visual Studio 2008 Release

void __thiscall ATL::CSimpleStringT<wchar_t,0>::Fork(CSimpleStringT<wchar_t,0> *this,int param_1)

{
  int iVar1;
  int iVar2;
  undefined4 *puVar3;
  int iVar4;
  
  iVar1 = *(int *)this;
  iVar2 = *(int *)(iVar1 + -0xc);
  puVar3 = (undefined4 *)(**(code **)(**(int **)(iVar1 + -0x10) + 0x10))();
  iVar4 = (**(code **)*puVar3)(param_1,2);
  if (iVar4 == 0) {
    func_0xfac4968f();
  }
  if (iVar2 < param_1) {
    param_1 = iVar2;
  }
  func_0xb7c396a8(iVar4 + 0x10,param_1 + 1,iVar1,param_1 + 1);
  *(int *)(iVar4 + 4) = iVar2;
  func_0x88c496b8();
  *(int *)this = iVar4 + 0x10;
  return;
}



// Library Function - Single Match
//  private: void __thiscall ATL::CSimpleStringT<wchar_t,0>::Reallocate(int)
// 
// Library: Visual Studio 2008 Release

void __thiscall
ATL::CSimpleStringT<wchar_t,0>::Reallocate(CSimpleStringT<wchar_t,0> *this,int param_1)

{
  int **ppiVar1;
  int iVar2;
  
  ppiVar1 = (int **)(*(int *)this + -0x10);
  if ((*(int *)(*(int *)this + -8) < param_1) && (0 < param_1)) {
    iVar2 = (**(code **)(**ppiVar1 + 8))(ppiVar1,param_1,2);
    if (iVar2 != 0) goto LAB_0040963d;
  }
  iVar2 = func_0xfac496f3();
LAB_0040963d:
  *(int *)this = iVar2 + 0x10;
  return;
}



// Library Function - Multiple Matches With Same Base Name
//  public: __thiscall ATL::CSimpleStringT<char,0>::CSimpleStringT<char,0>(struct ATL::IAtlStringMgr
// *)
//  public: __thiscall ATL::CSimpleStringT<wchar_t,0>::CSimpleStringT<wchar_t,0>(struct
// ATL::IAtlStringMgr *)
// 
// Libraries: Visual Studio 2008 Release, Visual Studio 2010 Release

int * __thiscall CSimpleStringT<>(void *this,int *param_1)

{
  int iVar1;
  int *extraout_ECX;
  
  if (param_1 == (int *)0x0) {
    func_0x4dbe9814(0x80004005);
    param_1 = extraout_ECX;
  }
  iVar1 = (**(code **)(*param_1 + 0xc))();
  *(int *)this = iVar1 + 0x10;
  return (int *)this;
}



int * __thiscall FUN_0040976f(void *this,int *param_1)

{
  int iVar1;
  
  iVar1 = func_0x05c5983b(*param_1 + -0x10);
  *(int *)this = iVar1 + 0x10;
  return (int *)this;
}



// Library Function - Multiple Matches With Same Base Name
//  private: void __thiscall ATL::CSimpleStringT<char,0>::PrepareWrite2(int)
//  private: void __thiscall ATL::CSimpleStringT<wchar_t,0>::PrepareWrite2(int)
// 
// Library: Visual Studio 2008 Release

void __thiscall PrepareWrite2(void *this,int param_1)

{
  int iVar1;
  
                    // WARNING: Load size is inaccurate
  iVar1 = *this;
  if (param_1 < *(int *)(iVar1 + -0xc)) {
    param_1 = *(int *)(iVar1 + -0xc);
  }
  if (*(int *)(iVar1 + -4) < 2) {
    iVar1 = *(int *)(iVar1 + -8);
    if (iVar1 < param_1) {
      if (iVar1 < 0x401) {
        iVar1 = iVar1 * 2;
      }
      else {
        iVar1 = iVar1 + 0x400;
      }
      if (iVar1 < param_1) {
        iVar1 = param_1;
      }
      func_0x05c698c8(iVar1);
    }
  }
  else {
    func_0x9bc598a2(param_1);
  }
  return;
}



void * __thiscall FUN_00409817(void *this,byte param_1)

{
  func_0x57c698da();
  if ((param_1 & 1) != 0) {
    func_0x47bd98e6(this);
  }
  return this;
}



void * __thiscall FUN_00409861(void *this,byte param_1)

{
  func_0x8ec69924();
  if ((param_1 & 1) != 0) {
    func_0x47bd9930(this);
  }
  return this;
}



void * __thiscall FUN_004098ac(void *this,undefined4 param_1)

{
  func_0x66c79972(param_1);
  return this;
}



// Library Function - Multiple Matches With Same Base Name
//  private: char * __thiscall ATL::CSimpleStringT<char,0>::PrepareWrite(int)
//  private: wchar_t * __thiscall ATL::CSimpleStringT<wchar_t,0>::PrepareWrite(int)
// 
// Library: Visual Studio 2008 Release

int __thiscall PrepareWrite(void *this,int param_1)

{
                    // WARNING: Load size is inaccurate
  if ((int)(1U - *(int *)(*this + -4) | *(int *)(*this + -8) - param_1) < 0) {
    func_0xc0c799aa(param_1);
  }
                    // WARNING: Load size is inaccurate
  return *this;
}



// Library Function - Multiple Matches With Same Base Name
//  public: __thiscall CDllIsolationWrapperBase::CDllIsolationWrapperBase(class
// ATL::CStringT<char,class StrTraitMFC<char,class ATL::ChTraitsCRT<char> > > const &)
//  public: __thiscall CDllIsolationWrapperBase::CDllIsolationWrapperBase(class
// ATL::CStringT<wchar_t,class StrTraitMFC<wchar_t,class ATL::ChTraitsCRT<wchar_t> > > const &)
// 
// Library: Visual Studio 2008 Release

undefined4 * __thiscall CDllIsolationWrapperBase(void *this,undefined4 param_1)

{
  *(undefined **)this = &DAT_004286c8;
  func_0xa3c89a9a(param_1);
  *(undefined4 *)((int)this + 4) = 0;
  *(undefined *)((int)this + 8) = 0;
  return (undefined4 *)this;
}



// Library Function - Multiple Matches With Different Base Names
//  public: int __thiscall ATL::CStringT<wchar_t,class StrTraitMFC<wchar_t,class
// ATL::ChTraitsCRT<wchar_t> > >::LoadStringA(struct HINSTANCE__ *,unsigned int)
//  public: int __thiscall ATL::CStringT<wchar_t,class StrTraitMFC<wchar_t,class
// ATL::ChTraitsCRT<wchar_t> > >::LoadStringW(struct HINSTANCE__ *,unsigned int)
// 
// Libraries: Visual Studio 2008 Release, Visual Studio 2010 Release

int FID_conflict_LoadStringW(HINSTANCE hInstance,UINT uID,LPWSTR lpBuffer,int cchBufferMax)

{
  undefined2 uVar1;
  undefined2 *puVar2;
  undefined4 uVar3;
  
  puVar2 = (undefined2 *)func_0x56c49ae3(hInstance,uID);
  if (puVar2 != (undefined2 *)0x0) {
    uVar1 = *puVar2;
    uVar3 = func_0xc4c89af7(uVar1);
    func_0xa2c49b06(uVar3,uVar1,puVar2 + 1,*puVar2);
    func_0xcdc49b11(uVar1);
    puVar2 = (undefined2 *)0x1;
  }
  return (int)puVar2;
}



// Library Function - Single Match
//  public: void __thiscall ATL::CSimpleStringT<wchar_t,0>::SetString(wchar_t const *,int)
// 
// Libraries: Visual Studio 2008 Release, Visual Studio 2010 Release

void __thiscall
ATL::CSimpleStringT<wchar_t,0>::SetString
          (CSimpleStringT<wchar_t,0> *this,wchar_t *param_1,int param_2)

{
  uint uVar1;
  int iVar2;
  uint uVar3;
  
  if (param_2 == 0) {
    func_0x89c79b2e();
  }
  else {
    if (param_1 == (wchar_t *)0x0) {
      func_0x4dbe9b42(0x80070057);
    }
    uVar1 = *(uint *)(*(int *)this + -0xc);
    uVar3 = (int)param_1 - *(int *)this >> 1;
    iVar2 = func_0xc4c89b54(param_2);
    if (uVar1 < uVar3) {
      func_0xb7c39b7b(iVar2,*(undefined4 *)(*(int *)this + -8),param_1,param_2);
    }
    else {
      func_0x65c59b6b(iVar2,*(undefined4 *)(*(int *)this + -8),iVar2 + uVar3 * 2);
    }
    func_0xcdc49b88(param_2);
  }
  return;
}



void * __thiscall FUN_00409ad8(void *this,byte param_1)

{
  func_0x0bc99b9b();
  if ((param_1 & 1) != 0) {
    func_0x47bd9ba7(this);
  }
  return this;
}



void FUN_00409af8(undefined4 param_1)

{
  int iVar1;
  
  iVar1 = func_0xf1d49bbe(param_1);
  if (iVar1 != 0) {
    func_0x10ca9bcd(iVar1,param_1);
  }
  return;
}



// Library Function - Multiple Matches With Same Base Name
//  private: bool __thiscall ATL::CStringT<char,class StrTraitMFC<char,class ATL::ChTraitsCRT<char>
// > >::CheckImplicitLoad(void const *)
//  private: bool __thiscall ATL::CStringT<wchar_t,class StrTraitMFC<wchar_t,class
// ATL::ChTraitsCRT<wchar_t> > >::CheckImplicitLoad(void const *)
// 
// Libraries: Visual Studio 2008 Release, Visual Studio 2010 Release

undefined4 CheckImplicitLoad(uint param_1)

{
  undefined4 uVar1;
  
  uVar1 = 0;
  if ((param_1 != 0) && ((param_1 & 0xffff0000) == 0)) {
    uVar1 = func_0xefca9bf1(param_1 & 0xffff);
    uVar1 = CONCAT31((int3)((uint)uVar1 >> 8),1);
  }
  return uVar1;
}



void FUN_00409b41(undefined4 param_1)

{
  undefined4 uVar1;
  
  uVar1 = func_0x86c59c07(param_1);
  func_0x5cca9c13(param_1,uVar1);
  return;
}



void * __thiscall FUN_00409b62(void *this,undefined4 param_1)

{
  func_0x38cb9c28(param_1);
  return this;
}



void * __thiscall FUN_00409b79(void *this,undefined4 param_1)

{
  func_0x59cb9c3f(param_1);
  return this;
}



void * __thiscall FUN_00409df8(void *this,byte param_1)

{
  func_0xeac99ebb();
  if ((param_1 & 1) != 0) {
    func_0x47bd9ec7(this);
  }
  return this;
}



// Library Function - Single Match
//  public: __thiscall AFX_MAINTAIN_STATE2::AFX_MAINTAIN_STATE2(class AFX_MODULE_STATE *)
// 
// Library: Visual Studio 2008 Release

AFX_MAINTAIN_STATE2 * __thiscall
AFX_MAINTAIN_STATE2::AFX_MAINTAIN_STATE2(AFX_MAINTAIN_STATE2 *this,AFX_MODULE_STATE *param_1)

{
  int iVar1;
  undefined4 uVar2;
  
  iVar1 = func_0x59d0a171();
  if ((*(int *)(iVar1 + 0x7c) == 0) || (*(int *)(param_1 + 0x80) == -1)) {
    *(undefined4 *)(this + 4) = 0;
  }
  else {
    uVar2 = func_0x56c3a18c(*(int *)(param_1 + 0x80),this);
    *(undefined4 *)(this + 4) = uVar2;
  }
  return this;
}



// Library Function - Single Match
//  public: static void __cdecl CWinApp::DoEnableModeless(int)
// 
// Library: Visual Studio 2008 Release

void __cdecl CWinApp::DoEnableModeless(int param_1)

{
  int *piVar1;
  int iVar2;
  
  piVar1 = (int *)func_0x80d1a25d();
  if (piVar1 != (int *)0x0) {
    iVar2 = (**(code **)(*piVar1 + 0x128))();
    if ((iVar2 != 0) && ((int *)piVar1[0x20] != (int *)0x0)) {
      (**(code **)(*(int *)piVar1[0x20] + 100))(param_1);
    }
  }
  return;
}



// Library Function - Single Match
//  public: static struct HWND__ * __stdcall CWnd::GetSafeOwner_(struct HWND__ *,struct HWND__ * *)
// 
// Libraries: Visual Studio 2008 Release, Visual Studio 2010 Release

HWND__ * CWnd::GetSafeOwner_(HWND__ *param_1,HWND__ **param_2)

{
  HWND__ *pHVar1;
  code *pcVar2;
  int iVar3;
  uint uVar4;
  HWND__ *pHVar5;
  HWND__ *pHVar6;
  HWND__ *pHVar7;
  
  pcVar2 = DAT_00428384;
  pHVar7 = param_1;
  if (param_1 != (HWND__ *)0x0) goto LAB_0040a205;
  iVar3 = func_0xddd0a2a5();
  if ((iVar3 == 0) && (iVar3 = func_0x80d1a2ae(), iVar3 == 0)) {
    pHVar7 = (HWND__ *)0x0;
    pHVar5 = pHVar7;
    pHVar6 = pHVar7;
  }
  else {
    for (pHVar7 = *(HWND__ **)(iVar3 + 0x20); pHVar5 = pHVar7, pHVar6 = pHVar7,
        pHVar7 != (HWND__ *)0x0; pHVar7 = (HWND__ *)(*pcVar2)(pHVar7)) {
LAB_0040a205:
      uVar4 = (*DAT_004283b4)(pHVar7,0xfffffff0);
      pHVar5 = pHVar7;
      pHVar6 = pHVar7;
      if ((uVar4 & 0x40000000) == 0) break;
    }
  }
  while (pHVar1 = pHVar5, pHVar1 != (HWND__ *)0x0) {
    pHVar5 = (HWND__ *)(*pcVar2)(pHVar1);
    pHVar7 = pHVar1;
  }
  if ((param_1 == (HWND__ *)0x0) && (pHVar6 != (HWND__ *)0x0)) {
    pHVar6 = (HWND__ *)(*DAT_004283b8)(pHVar6);
  }
  if (param_2 != (HWND__ **)0x0) {
    if (((pHVar7 == (HWND__ *)0x0) || (iVar3 = (*DAT_004283bc)(pHVar7), iVar3 == 0)) ||
       (pHVar7 == pHVar6)) {
      *param_2 = (HWND__ *)0x0;
    }
    else {
      *param_2 = pHVar7;
      (*DAT_004283b0)(pHVar7,0);
    }
  }
  return pHVar6;
}



// Library Function - Single Match
//  public: static int __cdecl CWinApp::ShowAppMessageBox(class CWinApp *,wchar_t const *,unsigned
// int,unsigned int)
// 
// Library: Visual Studio 2008 Release

int __cdecl CWinApp::ShowAppMessageBox(CWinApp *param_1,wchar_t *param_2,uint param_3,uint param_4)

{
  int iVar1;
  int iVar2;
  int *piVar3;
  undefined2 *puVar4;
  int local_21c;
  int local_218;
  int local_214;
  undefined2 local_210 [259];
  undefined2 local_a;
  uint local_8;
  
  local_8 = DAT_00431c20 ^ (uint)&stack0xfffffffc;
  func_0x93d1a357(0);
  iVar1 = func_0xccd1a365(0,&local_214);
  if (iVar1 != local_214) {
    (*DAT_004283b0)(iVar1,1);
  }
  local_21c = 0;
  (*DAT_0042837c)(iVar1,&local_21c);
  if ((((iVar1 == 0) || (iVar2 = (*DAT_004280dc)(), local_21c != iVar2)) ||
      (piVar3 = (int *)(*DAT_00428380)(iVar1,0x376,0,0), piVar3 == (int *)0x0)) &&
     (piVar3 = (int *)0x0, param_1 != (CWinApp *)0x0)) {
    piVar3 = (int *)(param_1 + 0x78);
  }
  local_218 = 0;
  if ((piVar3 != (int *)0x0) && (local_218 = *piVar3, param_4 != 0)) {
    *piVar3 = param_4 + 0x30000;
  }
  if ((param_3 & 0xf0) == 0) {
    if ((param_3 & 0xf) < 2) {
      param_3 = param_3 | 0x30;
    }
    else if ((param_3 & 0xf) - 3 < 2) {
      param_3 = param_3 | 0x20;
    }
  }
  local_210[0] = 0;
  if (param_1 == (CWinApp *)0x0) {
    puVar4 = local_210;
    iVar2 = (*DAT_00428238)(0,puVar4,0x104);
    if (iVar2 == 0x104) {
      local_a = 0;
    }
  }
  else {
    puVar4 = *(undefined2 **)(param_1 + 0x50);
  }
  func_0xe9d0a44f(iVar1,param_2,puVar4,param_3);
  if (piVar3 != (int *)0x0) {
    *piVar3 = local_218;
  }
  if (local_214 != 0) {
    (*DAT_004283b0)(local_214,1);
  }
  func_0x93d1a47e(1);
  iVar1 = func_0x485ea58e();
  return iVar1;
}



// Library Function - Multiple Matches With Same Base Name
//  int __stdcall AfxMessageBox(char const *,unsigned int,unsigned int)
//  int __stdcall AfxMessageBox(wchar_t const *,unsigned int,unsigned int)
// 
// Libraries: Visual Studio 2005 Release, Visual Studio 2008 Release

void AfxMessageBox(undefined4 param_1,undefined4 param_2,undefined4 param_3)

{
  int iVar1;
  
  iVar1 = func_0x59d0a49a();
  if (*(int **)(iVar1 + 4) != (int *)0x0) {
                    // WARNING: Could not recover jumptable at 0x0040a3f0. Too many branches
                    // WARNING: Treating indirect jump as call
    (**(code **)(**(int **)(iVar1 + 4) + 0x98))();
    return;
  }
  func_0x6cd2a4bc(0,param_1,param_2,param_3);
  return;
}



void __cdecl
FUN_0040a45c(undefined4 param_1,undefined4 param_2,undefined4 param_3,undefined4 param_4)

{
  undefined4 uVar1;
  
  uVar1 = func_0x5073a628(param_1,param_2,param_3,param_4);
  func_0x37bca52e(uVar1);
  return;
}



// WARNING: Control flow encountered bad instruction data

undefined4 __cdecl FUN_0040a47d(int param_1)

{
  if (param_1 == 0) {
    return 0;
  }
                    // WARNING: Bad instruction - Truncating control flow here
  halt_baddata();
}



// WARNING: Control flow encountered bad instruction data

void FUN_0040a492(undefined4 param_1,int param_2,int param_3)

{
  code *pcVar1;
  char *in_EAX;
  
  if ((param_2 != 0) && (param_3 != 0)) {
    *in_EAX = *in_EAX + (char)in_EAX;
                    // WARNING: Bad instruction - Truncating control flow here
    halt_baddata();
  }
  func_0xecbba5af();
  pcVar1 = (code *)swi(3);
  (*pcVar1)();
  return;
}



// Library Function - Multiple Matches With Same Base Name
//  public: void __thiscall ATL::CSimpleStringT<char,0>::ReleaseBuffer(int)
//  public: void __thiscall ATL::CSimpleStringT<wchar_t,0>::ReleaseBuffer(int)
// 
// Library: Visual Studio 2008 Release

void __thiscall ReleaseBuffer(void *this,int param_1)

{
  if (param_1 == -1) {
                    // WARNING: Load size is inaccurate
    param_1 = func_0x74d4a5d6(*this,*(undefined4 *)(*this + -8));
  }
  func_0xcdc4a5e0(param_1);
  return;
}



// Library Function - Single Match
//  public: virtual int __thiscall COleException::GetErrorMessage(wchar_t *,unsigned int,unsigned
// int *)const 
// 
// Library: Visual Studio 2008 Release

int __thiscall
COleException::GetErrorMessage(COleException *this,wchar_t *param_1,uint param_2,uint *param_3)

{
  int iVar1;
  
  if (param_3 != (uint *)0x0) {
    *param_3 = 0;
  }
  iVar1 = (*DAT_00428080)(0x1100,0,*(undefined4 *)(this + 8),0x800,&param_3,0,0);
  if (iVar1 != 0) {
    func_0x63bca68c(param_1,param_2,param_3,0xffffffff);
    (*(code *)u_f__dd_vctools_vc7libs_ship_atlmf_0042815f._69_4_)(param_3);
  }
  else {
    *param_1 = L'\0';
  }
  return (uint)(iVar1 != 0);
}



undefined4 * __thiscall FUN_0040a5e9(void *this,byte param_1)

{
  *(int *)this = (int)u_CLSID__1_AuxUserType_3_00428743 + 0x29;
  if ((param_1 & 1) != 0) {
    func_0x15baa6b9(this);
  }
  return (undefined4 *)this;
}



// Library Function - Single Match
//  public: void __thiscall ATL::CSimpleStringT<wchar_t,0>::AppendChar(wchar_t)
// 
// Libraries: Visual Studio 2008 Release, Visual Studio 2010 Release

void __thiscall
ATL::CSimpleStringT<wchar_t,0>::AppendChar(CSimpleStringT<wchar_t,0> *this,wchar_t param_1)

{
  int iVar1;
  int iVar2;
  int iVar3;
  
  iVar2 = *(int *)(*(int *)this + -0xc);
  iVar1 = iVar2 + 1;
  iVar3 = func_0xc4c8a6d9(iVar1);
  *(wchar_t *)(iVar3 + iVar2 * 2) = param_1;
  func_0xcdc4a6e9(iVar1);
  return;
}



void * __thiscall FUN_0040a63a(void *this,char param_1)

{
  func_0x02d6a706((short)param_1);
  return this;
}



void __thiscall FUN_0040a657(void *this,int param_1,int param_2)

{
  uint uVar1;
  int iVar2;
  int iVar3;
  uint uVar4;
  int iVar5;
  
                    // WARNING: Load size is inaccurate
  uVar1 = *(uint *)(*this + -0xc);
  uVar4 = param_1 - *this >> 1;
  if (-1 < param_2) goto LAB_0040a67f;
  do {
    func_0x4dbea735(0x80070057);
LAB_0040a67f:
    iVar2 = func_0x74d4a740(param_1,param_2);
  } while (0x7fffffff - iVar2 < (int)uVar1);
  iVar3 = func_0xc4c8a75e(uVar1 + iVar2);
  iVar5 = iVar3 + uVar4 * 2;
  if (uVar1 < uVar4) {
    iVar5 = param_1;
  }
  func_0xb7c3a774(iVar3 + uVar1 * 2,iVar2,iVar5,iVar2);
  func_0xcdc4a782(uVar1 + iVar2);
  return;
}



void FUN_0040a6d3(undefined4 param_1)

{
  undefined4 uVar1;
  
  uVar1 = func_0x86c5a799(param_1);
  func_0x4ed6a7a5(param_1,uVar1);
  return;
}



void * __thiscall FUN_0040a6f4(void *this,undefined4 param_1)

{
  func_0xcad6a7ba(param_1);
  return this;
}



void * __thiscall FUN_0040a70b(void *this,undefined4 param_1)

{
  func_0xebd6a7d1(param_1);
  return this;
}



// Library Function - Multiple Matches With Same Base Name
//  public: void __thiscall CMapPtrToPtr::InitHashTable(unsigned int,int)
//  public: void __thiscall CMapPtrToWord::InitHashTable(unsigned int,int)
//  public: void __thiscall CMapStringToOb::InitHashTable(unsigned int,int)
//  public: void __thiscall CMapStringToPtr::InitHashTable(unsigned int,int)
//   7 names - too many to list
// 
// Libraries: Visual Studio 2008 Release, Visual Studio 2010 Release

void __thiscall InitHashTable(void *this,uint param_1,int param_2)

{
  undefined4 uVar1;
  
  if (param_1 == 0) {
    param_1 = 0x11;
  }
  if (*(int *)((int)this + 4) != 0) {
    func_0x15baa7f8(*(int *)((int)this + 4));
    *(undefined4 *)((int)this + 4) = 0;
  }
  if (param_2 != 0) {
    uVar1 = func_0xdbb9a819(-(uint)((int)((ulonglong)param_1 * 4 >> 0x20) != 0) |
                            (uint)((ulonglong)param_1 * 4));
    *(undefined4 *)((int)this + 4) = uVar1;
    func_0x3b82a92a(uVar1,0,param_1 << 2);
  }
  *(uint *)((int)this + 8) = param_1;
  return;
}



void __thiscall FUN_0040a7ad(void *this,undefined4 *param_1)

{
  int *piVar1;
  
  *param_1 = *(undefined4 *)((int)this + 0x10);
  piVar1 = (int *)((int)this + 0xc);
  *piVar1 = *piVar1 + -1;
  *(undefined4 **)((int)this + 0x10) = param_1;
  if (*piVar1 == 0) {
    func_0x77d7a87d();
  }
  return;
}



// Library Function - Multiple Matches With Same Base Name
//  protected: struct CMapPtrToPtr::CAssoc * __thiscall CMapPtrToPtr::GetAssocAt(void *,unsigned int
// &,unsigned int &)const 
//  protected: struct CMapPtrToWord::CAssoc * __thiscall CMapPtrToWord::GetAssocAt(void *,unsigned
// int &,unsigned int &)const 
// 
// Library: Visual Studio 2008 Release

undefined4 * __thiscall GetAssocAt(void *this,uint param_1,uint *param_2,uint *param_3)

{
  undefined4 *puVar1;
  uint uVar2;
  
  *param_3 = param_1 >> 4;
  uVar2 = (param_1 >> 4) % *(uint *)((int)this + 8);
  *param_2 = uVar2;
  if (*(int *)((int)this + 4) != 0) {
    for (puVar1 = *(undefined4 **)(*(int *)((int)this + 4) + uVar2 * 4); puVar1 != (undefined4 *)0x0
        ; puVar1 = (undefined4 *)*puVar1) {
      if (puVar1[1] == param_1) {
        return puVar1;
      }
    }
  }
  return (undefined4 *)0x0;
}



// Library Function - Single Match
//  public: void * __thiscall CMapPtrToPtr::GetValueAt(void *)const 
// 
// Library: Visual Studio 2008 Release

void * __thiscall CMapPtrToPtr::GetValueAt(CMapPtrToPtr *this,void *param_1)

{
  CMapPtrToPtr *extraout_ECX;
  undefined4 *puVar1;
  
  if (this == (CMapPtrToPtr *)0x0) {
    func_0xecbba8ca();
    this = extraout_ECX;
  }
  if (*(int *)(this + 4) != 0) {
    for (puVar1 = *(undefined4 **)
                   (*(int *)(this + 4) + (((uint)param_1 >> 4) % *(uint *)(this + 8)) * 4);
        puVar1 != (undefined4 *)0x0; puVar1 = (undefined4 *)*puVar1) {
      if ((void *)puVar1[1] == param_1) {
        return (void *)puVar1[2];
      }
    }
  }
  return (void *)0x0;
}



int FUN_0040a84b(undefined4 param_1,undefined4 *param_2)

{
  int iVar1;
  undefined local_8 [4];
  
  iVar1 = func_0xc2d7a917(param_1,local_8,&param_1);
  if (iVar1 != 0) {
    *param_2 = *(undefined4 *)(iVar1 + 8);
    iVar1 = 1;
  }
  return iVar1;
}



// Library Function - Multiple Matches With Same Base Name
//  public: int __thiscall CMapPtrToPtr::RemoveKey(void *)
//  public: int __thiscall CMapPtrToWord::RemoveKey(void *)
// 
// Library: Visual Studio 2008 Release

undefined4 * __thiscall RemoveKey(void *this,uint param_1)

{
  undefined4 *puVar1;
  undefined4 *puVar2;
  undefined4 *puVar3;
  
  if (*(int *)((int)this + 4) == 0) {
    puVar2 = (undefined4 *)0x0;
  }
  else {
    puVar3 = (undefined4 *)
             (*(int *)((int)this + 4) + ((param_1 >> 4) % *(uint *)((int)this + 8)) * 4);
    puVar1 = (undefined4 *)*puVar3;
    while (puVar2 = puVar1, puVar2 != (undefined4 *)0x0) {
      if (puVar2[1] == param_1) {
        *puVar3 = *puVar2;
        func_0xa4d7a96d(puVar2);
        return (undefined4 *)0x1;
      }
      puVar3 = puVar2;
      puVar1 = (undefined4 *)*puVar2;
    }
  }
  return puVar2;
}



// Library Function - Single Match
//  public: void __thiscall CMapPtrToPtr::GetNextAssoc(struct __POSITION * &,void * &,void * &)const
// 
// 
// Library: Visual Studio 2008 Release

void __thiscall
CMapPtrToPtr::GetNextAssoc(CMapPtrToPtr *this,__POSITION **param_1,void **param_2,void **param_3)

{
  int **ppiVar1;
  __POSITION **pp_Var2;
  CMapPtrToPtr *extraout_ECX;
  uint uVar3;
  __POSITION **pp_Var4;
  uint uVar5;
  __POSITION *p_Var6;
  
  pp_Var4 = (__POSITION **)*param_1;
  if (pp_Var4 != (__POSITION **)0x0) {
    if (pp_Var4 == (__POSITION **)0xffffffff) {
      uVar5 = 0;
      if (*(uint *)(this + 8) != 0) {
        ppiVar1 = *(int ***)(this + 4);
        do {
          pp_Var4 = (__POSITION **)*ppiVar1;
          if (pp_Var4 != (__POSITION **)0x0) goto LAB_0040a8f0;
          uVar5 = uVar5 + 1;
          ppiVar1 = ppiVar1 + 1;
        } while (uVar5 < *(uint *)(this + 8));
        func_0xecbba9a6();
        this = extraout_ECX;
      }
    }
LAB_0040a8f0:
    p_Var6 = *pp_Var4;
    if (p_Var6 == (__POSITION *)0x0) {
      uVar5 = *(uint *)(this + 8);
      uVar3 = ((uint)pp_Var4[1] >> 4) % uVar5 + 1;
      if (uVar3 < uVar5) {
        pp_Var2 = (__POSITION **)(*(int *)(this + 4) + uVar3 * 4);
        do {
          p_Var6 = *pp_Var2;
          if (p_Var6 != (__POSITION *)0x0) break;
          uVar3 = uVar3 + 1;
          pp_Var2 = pp_Var2 + 1;
        } while (uVar3 < uVar5);
      }
    }
    *param_1 = p_Var6;
    *param_2 = pp_Var4[1];
    *param_3 = pp_Var4[2];
  }
  return;
}



void __thiscall FUN_0040a93f(void *this,int param_1)

{
  *(int *)this = (int)u_CLSID__1_MiscStatus_004287af + 5;
  if (param_1 < 1) {
    param_1 = 10;
  }
  *(undefined4 *)((int)this + 4) = 0;
  *(undefined4 *)((int)this + 8) = 0x11;
  *(undefined4 *)((int)this + 0xc) = 0;
  *(undefined4 *)((int)this + 0x10) = 0;
  *(undefined4 *)((int)this + 0x14) = 0;
  *(int *)((int)this + 0x18) = param_1;
  return;
}



// Library Function - Multiple Matches With Different Base Names
//  public: void * & __thiscall CMapPtrToPtr::operator[](void *)
//  public: unsigned short & __thiscall CMapPtrToWord::operator[](void *)
// 
// Libraries: Visual Studio 2003 Release, Visual Studio 2005 Release, Visual Studio 2008 Release

undefined4 * __thiscall FID_conflict_operator__(void *this,int param_1)

{
  int iVar1;
  undefined4 *puVar2;
  void *local_8;
  
  iVar1 = param_1;
  local_8 = this;
  puVar2 = (undefined4 *)func_0xc2d7aa9e(param_1,&param_1,&local_8);
  if (puVar2 == (undefined4 *)0x0) {
    if (*(int *)((int)this + 4) == 0) {
      func_0x19d7aab3(*(undefined4 *)((int)this + 8),1);
    }
    puVar2 = (undefined4 *)func_0x74d9aaba();
    puVar2[1] = iVar1;
    *puVar2 = *(undefined4 *)(param_1 * 4 + *(int *)((int)this + 4));
    *(undefined4 **)(param_1 * 4 + *(int *)((int)this + 4)) = puVar2;
  }
  return puVar2 + 2;
}



undefined4 * __thiscall FUN_0040aa24(void *this,byte param_1)

{
  *(int *)this = (int)u_CLSID__1_MiscStatus_004287af + 5;
  func_0x77d7aaed();
  if ((param_1 & 1) != 0) {
    func_0x15baaaf9(this);
  }
  return (undefined4 *)this;
}



// Library Function - Single Match
//  public: virtual struct ATL::CStringData * __thiscall CAfxStringMgr::Allocate(int,int)
// 
// Library: Visual Studio 2008 Release

CStringData * __thiscall CAfxStringMgr::Allocate(CAfxStringMgr *this,int param_1,int param_2)

{
  CAfxStringMgr **ppCVar1;
  
  if ((-1 < param_1) &&
     (ppCVar1 = (CAfxStringMgr **)func_0x676dac2b((param_1 + 1) * param_2 + 0x10),
     ppCVar1 != (CAfxStringMgr **)0x0)) {
    ppCVar1[1] = (CAfxStringMgr *)0x0;
    *ppCVar1 = this;
    ppCVar1[3] = (CAfxStringMgr *)0x1;
    ppCVar1[2] = (CAfxStringMgr *)param_1;
    return (CStringData *)ppCVar1;
  }
  return (CStringData *)0x0;
}



void FUN_0040aa90(undefined4 param_1)

{
  func_0xc272ac53(param_1);
  return;
}



// Library Function - Single Match
//  public: virtual struct ATL::CStringData * __thiscall CAfxStringMgr::Reallocate(struct
// ATL::CStringData *,int,int)
// 
// Library: Visual Studio 2008 Release

CStringData * __thiscall
CAfxStringMgr::Reallocate(CAfxStringMgr *this,CStringData *param_1,int param_2,int param_3)

{
  CStringData *pCVar1;
  
  if ((-1 < param_2) &&
     (pCVar1 = (CStringData *)func_0xc185ac7c(param_1,(param_2 + 1) * param_3 + 0x10),
     pCVar1 != (CStringData *)0x0)) {
    *(int *)(pCVar1 + 8) = param_2;
    return pCVar1;
  }
  return (CStringData *)0x0;
}



// Library Function - Multiple Matches With Same Base Name
//  protected: void __thiscall CObList::FreeNode(struct CObList::CNode *)
//  protected: void __thiscall CPtrList::FreeNode(struct CPtrList::CNode *)
// 
// Libraries: Visual Studio 2008 Release, Visual Studio 2010 Release

void __thiscall FreeNode(void *this,undefined4 *param_1)

{
  int *piVar1;
  void *extraout_ECX;
  
  if (param_1 == (undefined4 *)0x0) {
    param_1 = (undefined4 *)func_0xecbbabf1();
    this = extraout_ECX;
  }
  *param_1 = *(undefined4 *)((int)this + 0x10);
  piVar1 = (int *)((int)this + 0xc);
  *piVar1 = *piVar1 + -1;
  *(undefined4 **)((int)this + 0x10) = param_1;
  if (*piVar1 == 0) {
    func_0xffdaac03();
  }
  return;
}



// Library Function - Single Match
//  long __stdcall AfxInternalProcessWndProcException(class CException *,struct tagMSG const *)
// 
// Libraries: Visual Studio 2008 Release, Visual Studio 2010 Release

long AfxInternalProcessWndProcException(CException *param_1,tagMSG *param_2)

{
  long lVar1;
  
  if (*(int *)(param_2 + 4) == 1) {
    lVar1 = -1;
  }
  else {
    if (*(int *)(param_2 + 4) == 0xf) {
      (*DAT_00428358)(*(undefined4 *)param_2,0);
    }
    lVar1 = 0;
  }
  return lVar1;
}



// WARNING: Control flow encountered bad instruction data

void FUN_0040abb5(void)

{
  int iVar1;
  
  iVar1 = func_0x8cd0ac75();
  if (*(int **)(iVar1 + 4) != (int *)0x0) {
                    // WARNING: Could not recover jumptable at 0x0040abc9. Too many branches
                    // WARNING: Treating indirect jump as call
    (**(code **)(**(int **)(iVar1 + 4) + 0x6c))();
    return;
  }
                    // WARNING: Bad instruction - Truncating control flow here
  halt_baddata();
}



void __thiscall FUN_0040abd2(void *this,undefined4 param_1,undefined4 param_2,undefined4 param_3)

{
  (*DAT_00428380)(*(undefined4 *)((int)this + 0x20),param_1,param_2,param_3);
  return;
}



// Library Function - Single Match
//  public: struct IUnknown * __thiscall CCmdTarget::GetInterface(void const *)
// 
// Libraries: Visual Studio 2008 Release, Visual Studio 2010 Release

IUnknown * __thiscall CCmdTarget::GetInterface(CCmdTarget *this,void *param_1)

{
  IUnknown *pIVar1;
  int **ppiVar2;
  int *piVar3;
  int **ppiVar4;
  
  pIVar1 = (IUnknown *)(**(code **)(*(int *)this + 0x44))(param_1);
  if (pIVar1 == (IUnknown *)0x0) {
    ppiVar2 = (int **)(**(code **)(*(int *)this + 0x38))();
                    // WARNING: Load size is inaccurate
    if ((((DAT_0042b760 == *param_1) && (*(int *)((int)param_1 + 4) == DAT_0042b764)) &&
        (*(int *)((int)param_1 + 8) == DAT_0042b768)) &&
       (*(int *)((int)param_1 + 0xc) == DAT_0042b76c)) {
      do {
        for (piVar3 = ppiVar2[1]; *piVar3 != 0; piVar3 = piVar3 + 2) {
          if (((IUnknown *)(this + piVar3[1]))->lpVtbl != (IUnknownVtbl *)0x0) {
            return (IUnknown *)(this + piVar3[1]);
          }
        }
        ppiVar2 = (int **)*ppiVar2;
      } while (ppiVar2 != (int **)0x0);
    }
    else {
      do {
        for (ppiVar4 = (int **)ppiVar2[1]; piVar3 = *ppiVar4, piVar3 != (int *)0x0;
            ppiVar4 = ppiVar4 + 2) {
                    // WARNING: Load size is inaccurate
          if (((*piVar3 == *param_1) && (piVar3[1] == *(int *)((int)param_1 + 4))) &&
             ((piVar3[2] == *(int *)((int)param_1 + 8) &&
              ((piVar3[3] == *(int *)((int)param_1 + 0xc) &&
               (((IUnknown *)((int)ppiVar4[1] + (int)this))->lpVtbl != (IUnknownVtbl *)0x0)))))) {
            return (IUnknown *)((int)ppiVar4[1] + (int)this);
          }
        }
        ppiVar2 = (int **)*ppiVar2;
      } while (ppiVar2 != (int **)0x0);
    }
    pIVar1 = (IUnknown *)0x0;
  }
  return pIVar1;
}



// Library Function - Single Match
//  public: struct IUnknown * __thiscall CCmdTarget::QueryAggregates(void const *)
// 
// Libraries: Visual Studio 2003 Release, Visual Studio 2005 Release, Visual Studio 2008 Release,
// Visual Studio 2010 Release

IUnknown * __thiscall CCmdTarget::QueryAggregates(CCmdTarget *this,void *param_1)

{
  undefined4 *puVar1;
  int *piVar2;
  int *piVar3;
  int iVar4;
  IUnknown *local_8;
  
  local_8 = (IUnknown *)this;
  piVar2 = (int *)(**(code **)(*(int *)this + 0x38))();
  do {
    for (piVar3 = (int *)piVar2[1]; *piVar3 != 0; piVar3 = piVar3 + 2) {
    }
    for (piVar3 = piVar3 + 1; *piVar3 != -1; piVar3 = piVar3 + 2) {
      puVar1 = *(undefined4 **)(this + *piVar3);
      if (puVar1 != (undefined4 *)0x0) {
        local_8 = (IUnknown *)0x0;
        iVar4 = (**(code **)*puVar1)(puVar1,param_1,&local_8);
        if ((iVar4 == 0) && (local_8 != (IUnknown *)0x0)) {
          return local_8;
        }
      }
    }
    piVar2 = (int *)*piVar2;
    if (piVar2 == (int *)0x0) {
      return (IUnknown *)0x0;
    }
  } while( true );
}



bool __cdecl FUN_0040ad02(undefined4 param_1,undefined4 param_2)

{
  int iVar1;
  
  iVar1 = func_0xdc87aeca(param_1,param_2,0x10);
  return (bool)('\x01' - (iVar1 != 0));
}



// Library Function - Single Match
//  public: unsigned long __thiscall CCmdTarget::InternalQueryInterface(void const *,void * *)
// 
// Libraries: Visual Studio 2008 Release, Visual Studio 2010 Release

ulong __thiscall CCmdTarget::InternalQueryInterface(CCmdTarget *this,void *param_1,void **param_2)

{
  void *pvVar1;
  ulong uVar2;
  
  pvVar1 = (void *)func_0xe4dbae7b(param_1);
  *param_2 = pvVar1;
  if (pvVar1 == (void *)0x0) {
    pvVar1 = (void *)func_0x97dcae97(param_1);
    *param_2 = pvVar1;
    uVar2 = (-(uint)(pvVar1 != (void *)0x0) & 0x7fffbffe) + 0x80004002;
  }
  else {
    func_0x25ddae8b();
    uVar2 = 0;
  }
  return uVar2;
}



// WARNING: Control flow encountered bad instruction data
// Library Function - Single Match
//  public: unsigned long __thiscall CCmdTarget::ExternalQueryInterface(void const *,void * *)
// 
// Libraries: Visual Studio 2008 Release, Visual Studio 2010 Release

ulong __thiscall CCmdTarget::ExternalQueryInterface(CCmdTarget *this,void *param_1,void **param_2)

{
  ulong uVar1;
  
  if (*(int *)(this + 8) != 0) {
    uVar1 = (**(code **)**(undefined4 **)(this + 8))(*(undefined4 **)(this + 8),param_1,param_2);
    return uVar1;
  }
                    // WARNING: Bad instruction - Truncating control flow here
  halt_baddata();
}



// Library Function - Multiple Matches With Same Base Name
//  public: void __thiscall ATL::CStringT<char,class StrTraitMFC<char,class ATL::ChTraitsCRT<char> >
// >::FormatV(char const *,char *)
//  public: void __thiscall ATL::CStringT<wchar_t,class StrTraitMFC<wchar_t,class
// ATL::ChTraitsCRT<wchar_t> > >::FormatV(wchar_t const *,char *)
// 
// Libraries: Visual Studio 2005 Release, Visual Studio 2008 Release

void FormatV(int param_1,undefined4 param_2)

{
  int iVar1;
  undefined4 uVar2;
  
  if (param_1 == 0) {
    func_0x4dbeafd4(0x80070057);
  }
  iVar1 = func_0xb39eb0df(param_1,param_2);
  uVar2 = func_0xc4c8afeb(iVar1);
  func_0x7276b0fb(uVar2,iVar1 + 1,param_1,param_2);
  func_0xcdc4b006(iVar1);
  return;
}



void __cdecl FUN_0040af56(undefined4 param_1,undefined4 param_2,undefined param_3)

{
  func_0xfcdeb020(param_2,&param_3);
  return;
}



void __cdecl FUN_0040b031(undefined4 param_1,undefined4 param_2,undefined4 param_3)

{
  undefined4 uVar1;
  
  uVar1 = func_0xd45eb1fa(param_1,param_2,param_3);
  func_0x37bcb100(uVar1);
  return;
}



// Library Function - Single Match
//  public: static struct CPlex * __stdcall CPlex::Create(struct CPlex * &,unsigned int,unsigned
// int)
// 
// Libraries: Visual Studio 2008 Release, Visual Studio 2010 Release

CPlex * CPlex::Create(CPlex **param_1,uint param_2,uint param_3)

{
  code *pcVar1;
  CPlex **ppCVar2;
  CPlex *pCVar3;
  
  if ((param_2 != 0) && (param_3 != 0)) {
    ppCVar2 = (CPlex **)func_0xdbb9b124(param_2 * param_3 + 4);
    *ppCVar2 = *param_1;
    *param_1 = (CPlex *)ppCVar2;
    return (CPlex *)ppCVar2;
  }
  func_0xecbbb137();
  pcVar1 = (code *)swi(3);
  pCVar3 = (CPlex *)(*pcVar1)();
  return pCVar3;
}



bool FUN_0040b098(int param_1)

{
  return param_1 != 0;
}



void __cdecl
FUN_0040b0a9(undefined4 param_1,undefined4 param_2,undefined4 param_3,undefined4 param_4)

{
  undefined4 uVar1;
  
  uVar1 = func_0xcf82b275(param_1,param_2,param_3,param_4);
  func_0x37bcb17b(uVar1);
  return;
}



// WARNING: Control flow encountered bad instruction data
// Library Function - Single Match
//  public: unsigned int __thiscall CArchive::Read(void *,unsigned int)
// 
// Library: Visual Studio 2008 Release

uint __thiscall CArchive::Read(CArchive *this,void *param_1,uint param_2)

{
  int iVar1;
  uint uVar2;
  int iVar3;
  uint uVar4;
  int local_c;
  uint local_8;
  
  if ((param_2 == 0) || (param_1 == (void *)0x0)) {
                    // WARNING: Bad instruction - Truncating control flow here
    halt_baddata();
  }
  if (((byte)this[0x18] & 1) == 0) {
    func_0xe1e7b1af(4,*(undefined4 *)(this + 0x14));
  }
  uVar2 = *(int *)(this + 0x2c) - *(int *)(this + 0x28);
  if (param_2 < uVar2) {
    uVar2 = param_2;
  }
  func_0x53d4b1c9(param_1,param_2,*(int *)(this + 0x28),uVar2);
  *(uint *)(this + 0x28) = *(int *)(this + 0x28) + uVar2;
  param_1 = (void *)((int)param_1 + uVar2);
  uVar2 = param_2 - uVar2;
  if (uVar2 != 0) {
    iVar3 = uVar2 - uVar2 % *(uint *)(this + 0x20);
    local_c = 0;
    local_8 = iVar3;
    do {
      iVar1 = (**(code **)(**(int **)(this + 0x24) + 0x34))(param_1,local_8);
      param_1 = (void *)((int)param_1 + iVar1);
      local_c = local_c + iVar1;
      local_8 = local_8 - iVar1;
      if (iVar1 == 0) break;
    } while (local_8 != 0);
    uVar2 = uVar2 - local_c;
    if ((uVar2 != 0) && (local_c == iVar3)) {
      uVar4 = 0;
      if (*(int *)(this + 8) == 0) {
        if ((*(int *)(this + 0xc) != 0) ||
           (local_8 = *(uint *)(this + 0x20), *(uint *)(this + 0x20) < uVar2)) {
          local_8 = uVar2;
        }
        local_c = *(int *)(this + 0x30);
        do {
          iVar3 = (**(code **)(**(int **)(this + 0x24) + 0x34))(local_c,local_8);
          local_c = local_c + iVar3;
          local_8 = local_8 - iVar3;
          uVar4 = uVar4 + iVar3;
          if ((iVar3 == 0) || (local_8 == 0)) break;
        } while (uVar4 < uVar2);
        iVar3 = *(int *)(this + 0x30);
        *(uint *)(this + 0x2c) = iVar3 + uVar4;
      }
      else {
        (**(code **)(**(int **)(this + 0x24) + 0x50))
                  (0,*(undefined4 *)(this + 0x20),this + 0x30,this + 0x2c);
        iVar3 = *(int *)(this + 0x30);
      }
      *(int *)(this + 0x28) = iVar3;
      uVar4 = *(int *)(this + 0x2c) - iVar3;
      if (uVar2 < (uint)(*(int *)(this + 0x2c) - iVar3)) {
        uVar4 = uVar2;
      }
      func_0x53d4b29d(param_1,uVar2,iVar3,uVar4);
      *(uint *)(this + 0x28) = *(int *)(this + 0x28) + uVar4;
      uVar2 = uVar2 - uVar4;
    }
  }
  return param_2 - uVar2;
}



// WARNING: Control flow encountered bad instruction data
// Library Function - Single Match
//  public: void __thiscall CArchive::FillBuffer(unsigned int)
// 
// Library: Visual Studio 2008 Release

void __thiscall CArchive::FillBuffer(CArchive *this,uint param_1)

{
  int *piVar1;
  uint uVar2;
  uint uVar3;
  uint uVar4;
  int iVar5;
  int iVar6;
  uint local_8;
  
  if (((byte)this[0x18] & 1) == 0) {
    func_0xe1e7b345(4,*(undefined4 *)(this + 0x14));
  }
  uVar2 = *(uint *)(this + 0x28);
  piVar1 = (int *)(this + 0x2c);
  local_8 = *piVar1 - uVar2;
  uVar3 = param_1 + local_8;
  if (*(int *)(this + 8) == 0) {
    uVar4 = *(uint *)(this + 0x30);
    if (uVar4 < uVar2) {
      if (0 < (int)local_8) {
        func_0xa0e0b379(uVar4,*piVar1 - uVar4,uVar2,local_8);
        uVar4 = *(uint *)(this + 0x30);
        *(uint *)(this + 0x28) = uVar4;
        *piVar1 = uVar4 + local_8;
      }
      if (*(int *)(this + 0xc) == 0) {
        param_1 = *(uint *)(this + 0x20);
      }
      param_1 = param_1 - local_8;
      iVar6 = local_8 + uVar4;
      do {
        iVar5 = (**(code **)(**(int **)(this + 0x24) + 0x34))(iVar6,param_1);
        local_8 = local_8 + iVar5;
        param_1 = param_1 - iVar5;
        iVar6 = iVar6 + iVar5;
        if ((iVar5 == 0) || (param_1 == 0)) break;
      } while (local_8 < uVar3);
      *(int *)(this + 0x28) = *(int *)(this + 0x30);
      *piVar1 = *(int *)(this + 0x30) + local_8;
    }
  }
  else {
    if (local_8 != 0) {
      (**(code **)(**(int **)(this + 0x24) + 0x28))(-local_8,(int)-local_8 >> 0x1f,1);
    }
    (**(code **)(**(int **)(this + 0x24) + 0x50))(0,*(undefined4 *)(this + 0x20),this + 0x30,piVar1)
    ;
    *(undefined4 *)(this + 0x28) = *(undefined4 *)(this + 0x30);
  }
  if ((uint)(*piVar1 - *(int *)(this + 0x28)) < uVar3) {
                    // WARNING: Bad instruction - Truncating control flow here
    halt_baddata();
  }
  return;
}



// Library Function - Single Match
//  public: class CArchive & __thiscall CArchive::operator<<(unsigned short)
// 
// Library: Visual Studio 2008 Release

CArchive * __thiscall CArchive::operator<<(CArchive *this,ushort param_1)

{
  if ((~*(uint *)(this + 0x18) & 1) == 0) {
    func_0xe1e7b433(2,*(undefined4 *)(this + 0x14));
  }
  if (*(uint *)(this + 0x2c) < *(int *)(this + 0x28) + 2U) {
    func_0xf2e1b442();
  }
  **(ushort **)(this + 0x28) = param_1;
  *(int *)(this + 0x28) = *(int *)(this + 0x28) + 2;
  return this;
}



// Library Function - Multiple Matches With Same Base Name
//  public: class CArchive & __thiscall CArchive::operator<<(long)
//  public: class CArchive & __thiscall CArchive::operator<<(unsigned long)
// 
// Libraries: Visual Studio 2008 Release, Visual Studio 2010 Release

int __thiscall CArchive__operator<<(void *this,undefined4 param_1)

{
  if ((~*(uint *)((int)this + 0x18) & 1) == 0) {
    func_0xe1e7b472(2,*(undefined4 *)((int)this + 0x14));
  }
  if (*(uint *)((int)this + 0x2c) < *(int *)((int)this + 0x28) + 4U) {
    func_0xf2e1b482();
  }
  **(undefined4 **)((int)this + 0x28) = param_1;
  *(int *)((int)this + 0x28) = *(int *)((int)this + 0x28) + 4;
  return (int)this;
}



// Library Function - Single Match
//  public: class CArchive & __thiscall CArchive::operator>>(unsigned short &)
// 
// Library: Visual Studio 2008 Release

CArchive * __thiscall CArchive::operator>>(CArchive *this,ushort *param_1)

{
  if (((byte)this[0x18] & 1) == 0) {
    func_0xe1e7b4ad(4,*(undefined4 *)(this + 0x14));
  }
  if (*(uint *)(this + 0x2c) < *(int *)(this + 0x28) + 2U) {
    func_0x6ae2b4c6((*(int *)(this + 0x28) - *(uint *)(this + 0x2c)) + 2);
  }
  *param_1 = **(ushort **)(this + 0x28);
  *(int *)(this + 0x28) = *(int *)(this + 0x28) + 2;
  return this;
}



// Library Function - Multiple Matches With Same Base Name
//  public: class CArchive & __thiscall CArchive::operator>>(long &)
//  public: class CArchive & __thiscall CArchive::operator>>(unsigned long &)
// 
// Libraries: Visual Studio 2008 Release, Visual Studio 2010 Release

int __thiscall CArchive__operator>>(void *this,undefined4 *param_1)

{
  if ((*(byte *)((int)this + 0x18) & 1) == 0) {
    func_0xe1e7b4f5(4,*(undefined4 *)((int)this + 0x14));
  }
  if (*(uint *)((int)this + 0x2c) < *(int *)((int)this + 0x28) + 4U) {
    func_0x6ae2b50f((*(int *)((int)this + 0x28) - *(uint *)((int)this + 0x2c)) + 4);
  }
  *param_1 = **(undefined4 **)((int)this + 0x28);
  *(int *)((int)this + 0x28) = *(int *)((int)this + 0x28) + 4;
  return (int)this;
}



// Library Function - Single Match
//  public: static struct CRuntimeClass * __stdcall CRuntimeClass::FromName(char const *)
// 
// Libraries: Visual Studio 2008 Release, Visual Studio 2010 Release

CRuntimeClass * CRuntimeClass::FromName(char *param_1)

{
  int iVar1;
  undefined4 *puVar2;
  
  if (param_1 == (char *)0x0) {
    func_0xecbbb534();
  }
  iVar1 = func_0x59d0b53a();
  func_0xa5c2b543(0);
  puVar2 = *(undefined4 **)(iVar1 + 0x1c);
  while( true ) {
    if (puVar2 == (undefined4 *)0x0) {
      func_0x17c3b564(0);
      return (CRuntimeClass *)0x0;
    }
    iVar1 = (*DAT_0042808c)(param_1,*puVar2);
    if (iVar1 == 0) break;
    puVar2 = (undefined4 *)puVar2[5];
  }
  func_0x17c3b572(0);
  return (CRuntimeClass *)puVar2;
}



// Library Function - Single Match
//  public: static struct CRuntimeClass * __stdcall CRuntimeClass::Load(class CArchive &,unsigned
// int *)
// 
// Libraries: Visual Studio 2008 Release, Visual Studio 2010 Release

CRuntimeClass * CRuntimeClass::Load(CArchive *param_1,uint *param_2)

{
  uint uVar1;
  CRuntimeClass *pCVar2;
  uint uVar3;
  ushort local_4c [2];
  undefined local_48 [64];
  uint local_8;
  
  local_8 = DAT_00431c20 ^ (uint)&stack0xfffffffc;
  if (param_2 != (uint *)0x0) {
    func_0xd6e3b59f(local_4c);
    *param_2 = (uint)local_4c[0];
    func_0xd6e3b5b0(local_4c);
    if (local_4c[0] < 0x40) {
      uVar3 = (uint)local_4c[0];
      uVar1 = func_0xc1e0b5c7(local_48,uVar3);
      if (uVar1 == uVar3) {
        local_48[uVar3] = 0;
        func_0x65e4b5d9(local_48);
      }
    }
  }
  pCVar2 = (CRuntimeClass *)func_0x485eb6e9();
  return pCVar2;
}



// Library Function - Single Match
//  public: void __thiscall CArchive::Write(void const *,unsigned int)
// 
// Library: Visual Studio 2008 Release

void __thiscall CArchive::Write(CArchive *this,void *param_1,uint param_2)

{
  uint uVar1;
  uint uVar2;
  int iVar3;
  
  if ((param_2 != 0) && (param_1 != (void *)0x0)) {
    if ((~*(uint *)(this + 0x18) & 1) == 0) {
      func_0xe1e7b61e(2,*(undefined4 *)(this + 0x14));
    }
    uVar1 = *(int *)(this + 0x2c) - *(int *)(this + 0x28);
    uVar2 = param_2;
    if (uVar1 <= param_2) {
      uVar2 = uVar1;
    }
    func_0x53d4b63a(*(int *)(this + 0x28),uVar1,param_1,uVar2);
    *(uint *)(this + 0x28) = *(int *)(this + 0x28) + uVar2;
    uVar1 = param_2 - uVar2;
    if (uVar1 != 0) {
      func_0xf2e1b64e();
      iVar3 = uVar1 - uVar1 % *(uint *)(this + 0x20);
      (**(code **)(**(int **)(this + 0x24) + 0x38))((int)param_1 + uVar2,iVar3);
      uVar1 = uVar1 - iVar3;
      if (*(int *)(this + 8) != 0) {
        (**(code **)(**(int **)(this + 0x24) + 0x50))
                  (1,*(undefined4 *)(this + 0x20),this + 0x30,this + 0x2c);
        *(undefined4 *)(this + 0x28) = *(undefined4 *)(this + 0x30);
      }
      if (uVar1 < *(uint *)(this + 0x20)) goto LAB_0040b5de;
      do {
        func_0xecbbb694();
LAB_0040b5de:
      } while (*(int *)(this + 0x28) != *(int *)(this + 0x30));
      func_0x53d4b6a7(*(int *)(this + 0x28),uVar1,(int)param_1 + uVar2 + iVar3,uVar1);
      *(uint *)(this + 0x28) = *(int *)(this + 0x28) + uVar1;
    }
  }
  return;
}



// Library Function - Single Match
//  public: void __thiscall CArchive::WriteCount(unsigned long)
// 
// Libraries: Visual Studio 2008 Release, Visual Studio 2010 Release, Visual Studio 2012 Release,
// Visual Studio 2015 Release

void __thiscall CArchive::WriteCount(CArchive *this,ulong param_1)

{
  if (param_1 < 0xffff) {
    func_0x59e3b6ce(param_1);
  }
  else {
    func_0x59e3b6d6(0xffff);
    func_0x98e3b6e0(param_1);
  }
  return;
}



// Library Function - Single Match
//  public: unsigned long __thiscall CArchive::ReadCount(void)
// 
// Libraries: Visual Studio 2008 Release, Visual Studio 2010 Release

ulong __thiscall CArchive::ReadCount(CArchive *this)

{
  CArchive *local_8;
  
  local_8 = this;
  func_0xd6e3b6f7(&local_8);
  if ((short)local_8 == -1) {
    func_0x1ee4b713(&local_8);
  }
  else {
    local_8 = (CArchive *)((uint)local_8 & 0xffff);
  }
  return (ulong)local_8;
}



// Library Function - Single Match
//  public: void __thiscall CRuntimeClass::Store(class CArchive &)const 
// 
// Library: Visual Studio 2008 Release

void __thiscall CRuntimeClass::Store(CRuntimeClass *this,CArchive *param_1)

{
  undefined2 uVar1;
  
  uVar1 = (*DAT_00428090)(*(undefined4 *)this);
  func_0x59e3b73b(*(undefined2 *)(this + 8),uVar1);
  func_0x59e3b742();
  func_0x2ee5b750(*(undefined4 *)this,uVar1);
  return;
}



void FUN_0040b6a0(undefined4 param_1,int param_2)

{
  int iVar1;
  
  iVar1 = func_0xc1e0b766(param_1,param_2);
  if (iVar1 != param_2) {
    func_0xe1e7b774(3,0);
  }
  return;
}



undefined4 * __thiscall FUN_0040b7bd(void *this,byte param_1)

{
  *(undefined **)this = &DAT_004288f0;
  func_0x88c4b88c();
  if ((param_1 & 1) != 0) {
    func_0x15bab898(this);
  }
  return (undefined4 *)this;
}



// WARNING: Control flow encountered bad instruction data
// WARNING: Instruction at (ram,0x0040b933) overlaps instruction at (ram,0x0040b931)
// 

uint __fastcall
FUN_0040b82d(undefined4 param_1,undefined2 param_2,int param_3,uint param_4,int param_5,
            undefined *param_6,undefined4 *param_7,int param_8,int *param_9)

{
  byte *pbVar1;
  char *pcVar2;
  byte bVar3;
  char cVar4;
  undefined4 *puVar5;
  undefined3 uVar10;
  int iVar6;
  int iVar7;
  uint uVar8;
  code **ppcVar9;
  int extraout_ECX;
  undefined2 extraout_DX;
  undefined4 unaff_EBX;
  undefined4 uVar11;
  undefined4 *unaff_ESI;
  int *piVar12;
  uint unaff_EDI;
  uint uVar13;
  
  iVar6 = param_3;
  uVar11 = unaff_EBX;
  if (param_3 != 0) goto LAB_0040b83e;
LAB_0040b839:
  do {
    func_0xecbbb8f4();
    iVar6 = extraout_ECX;
    uVar11 = unaff_EBX;
    param_2 = extraout_DX;
LAB_0040b83e:
    unaff_EBX = 1;
    if (param_9 != (int *)0x0) {
      *param_9 = iVar6;
      param_9[1] = (int)param_6;
                    // WARNING: Bad instruction - Truncating control flow here
      halt_baddata();
    }
    puVar5 = (undefined4 *)(param_8 + -0x39);
    if ((undefined4 *)0xb < puVar5) {
      return 0;
    }
    cVar4 = (char)puVar5;
    uVar10 = (undefined3)((uint)puVar5 >> 8);
    switch(puVar5) {
    case (undefined4 *)0x0:
                    // WARNING: Bad instruction - Truncating control flow here
      halt_baddata();
    case (undefined4 *)0x1:
      *(uint *)(iVar6 + 0x55ff0040) = *(uint *)(iVar6 + 0x55ff0040) ^ unaff_EDI;
      puVar5 = (undefined4 *)CONCAT31(uVar10,cVar4 + -0x17);
    case (undefined4 *)0x2:
      *(char *)puVar5 = *(char *)puVar5 + (char)puVar5;
                    // WARNING: Bad instruction - Truncating control flow here
      halt_baddata();
    case (undefined4 *)0x3:
      *(char *)puVar5 = *(char *)puVar5 + cVar4;
      (*(code *)param_6)();
                    // WARNING: Bad instruction - Truncating control flow here
      halt_baddata();
    case (undefined4 *)0x4:
      *(char *)puVar5 = *(char *)puVar5 + cVar4;
                    // WARNING: Bad instruction - Truncating control flow here
      halt_baddata();
    case (undefined4 *)0x5:
      *(char *)puVar5 = *(char *)puVar5 + cVar4;
      if (puVar5 != (undefined4 *)0x0) {
        (*(code *)param_6)(*(undefined4 *)(param_8 + -0x35),*puVar5);
                    // WARNING: Bad instruction - Truncating control flow here
        halt_baddata();
      }
      break;
    case (undefined4 *)0x6:
      *(char *)puVar5 = *(char *)puVar5 + cVar4;
      if (puVar5 != (undefined4 *)0x0) {
        uVar8 = (*(code *)param_6)(*(undefined4 *)(param_8 + -0x35),*puVar5);
        return uVar8;
      }
      break;
    case (undefined4 *)0x7:
      out(*unaff_ESI,param_2);
      unaff_ESI = unaff_ESI + 1;
      if (param_7 != (undefined4 *)0x0) {
        (*(code *)param_6)(param_4,param_7[1],*param_7,&stack0xfffffffc);
        return 1;
      }
      break;
    case (undefined4 *)0x8:
      if (param_7 != (undefined4 *)0x0) {
        uVar8 = (*(code *)param_6)(param_4,param_7[1],*param_7);
        return uVar8;
      }
      break;
    case (undefined4 *)0x9:
      goto switchD_0040b868_caseD_9;
    case (undefined4 *)0xa:
      param_7 = unaff_ESI;
      goto code_r0x0040b8f3;
    case (undefined4 *)0xb:
      cVar4 = cVar4 + -0x15 + (puVar5 < (undefined4 *)0xb);
      if (cVar4 == '\0') {
                    // WARNING: Bad instruction - Truncating control flow here
        halt_baddata();
      }
      pbVar1 = (byte *)(CONCAT31(uVar10,cVar4) + 0x40b86b);
      bVar3 = *pbVar1;
      *pbVar1 = *pbVar1 + (byte)param_2;
      param_7 = unaff_ESI;
      if (CARRY1(bVar3,(byte)param_2)) {
        *(char *)(unaff_ESI + -0x1c7fefd2) = *(char *)(unaff_ESI + -0x1c7fefd2) + cVar4 + '\x02';
        cRamcb0040b9 = cRamcb0040b9 + (char)((ushort)param_2 >> 8);
        cRamb8e30041 = cRamb8e30041 + 'A';
        pcVar2 = (char *)(unaff_EDI * 4 + -0x46ebffc0);
        *pcVar2 = *pcVar2 + '\x01';
        cRamec8b5600 = cRamec8b5600 + '@';
        if (param_4 == 0xfffffffe) {
          iVar6 = func_0x59d0ba30(1,&stack0xfffffffc,unaff_ESI,uVar11);
          if (*(int *)(iVar6 + 0x3c) != 0) goto code_r0x0040b985;
        }
        else {
          if (param_4 != 0xfffffffd) {
            if (param_4 != 0xffffffff) {
              uVar8 = param_4 & 0xffff;
              uVar13 = param_4 >> 0x10;
              param_4 = uVar8;
              if (uVar13 != 0) goto code_r0x0040ba3d;
            }
            uVar13 = 0x111;
code_r0x0040ba3d:
            ppcVar9 = (code **)(**(code **)(iRamb9140040 + 0x28))();
            while( true ) {
              if (*ppcVar9 == (code *)0x0) {
                return 0;
              }
              iVar6 = func_0x29fbbb09(ppcVar9[1],uVar13,param_4,param_3);
              if (iVar6 != 0) break;
              ppcVar9 = (code **)(**ppcVar9)();
            }
            uVar8 = func_0x24e8bb37(0xb9140040,param_3,param_4,*(undefined4 *)(iVar6 + 0x14),param_5
                                    ,*(undefined4 *)(iVar6 + 0x10),param_6);
            return uVar8;
          }
          param_4 = 0;
          if (param_5 != 0) {
            iVar6 = *(int *)(param_5 + 0x30);
            puVar5 = (undefined4 *)(**(code **)(iRamb9140040 + 0x2c))();
            do {
              if (puVar5 == (undefined4 *)0x0) {
                return param_4;
              }
              if (param_4 != 0) {
                return param_4;
              }
              piVar12 = (int *)puVar5[1];
              while (((piVar12[1] != 0 && (piVar12[2] != 0)) && (param_4 == 0))) {
                if (param_3 == piVar12[1]) {
                  if (iVar6 == 0) {
                    if (*piVar12 == 0) {
code_r0x0040ba02:
                      *(int *)(param_5 + 4) = piVar12[2];
                      param_4 = 1;
                    }
                  }
                  else if ((*piVar12 != 0) && (iVar7 = func_0xf9dcbab2(iVar6,*piVar12), iVar7 != 0))
                  goto code_r0x0040ba02;
                }
                piVar12 = piVar12 + 3;
              }
              puVar5 = (undefined4 *)*puVar5;
            } while( true );
          }
        }
        func_0xecbbba3b();
code_r0x0040b985:
        iVar6 = func_0x59d0ba40();
        (**(code **)(**(int **)(iVar6 + 0x3c) + 4))(0xb9140040,param_3,param_5,param_6);
                    // WARNING: Bad instruction - Truncating control flow here
        halt_baddata();
      }
      goto code_r0x0040b8f3;
    }
  } while( true );
switchD_0040b868_caseD_9:
  unaff_ESI = param_7;
  if (param_7 != (undefined4 *)0x0) {
code_r0x0040b8f3:
    (*(code *)param_6)();
    iVar6 = param_7[7];
    param_7[7] = 0;
    return (uint)(iVar6 == 0);
  }
  goto LAB_0040b839;
}



void __thiscall FUN_0040bad9(void *this,undefined4 param_1,undefined4 param_2)

{
  (*DAT_00428328)(*(undefined4 *)((int)this + 4),param_1,param_2);
  return;
}



void __thiscall FUN_0040baf1(void *this,undefined4 param_1,undefined4 param_2)

{
  (*DAT_00428324)(*(undefined4 *)((int)this + 4),param_1,param_2);
  return;
}



void __thiscall
FUN_0040bb09(void *this,undefined4 param_1,undefined4 param_2,undefined4 param_3,undefined4 param_4)

{
  (*DAT_00428320)(*(undefined4 *)((int)this + 4),param_1,param_2,param_3,param_4);
  return;
}



// Library Function - Single Match
//  public: virtual void __thiscall CCmdUI::Enable(int)
// 
// Library: Visual Studio 2008 Release

void __thiscall CCmdUI::Enable(CCmdUI *this,int param_1)

{
  uint uVar1;
  int iVar2;
  undefined4 uVar3;
  int iVar4;
  
  if (*(int *)(this + 0xc) == 0) {
    if (*(int *)(this + 0x14) != 0) {
      if (param_1 == 0) {
        iVar4 = *(int *)(this + 0x14);
        iVar2 = (*DAT_0042831c)();
        if (iVar2 == *(int *)(iVar4 + 0x20)) {
          uVar3 = (*DAT_00428384)(*(undefined4 *)(iVar4 + 0x20));
          iVar4 = func_0xf614bcae(uVar3);
          (*DAT_00428380)(*(undefined4 *)(iVar4 + 0x20),0x28,0,0);
        }
      }
      func_0x0c40bdc7(param_1);
      goto LAB_0040bc11;
    }
LAB_0040bbaf:
    uVar1 = func_0xecbbbc6a();
  }
  else {
    if (*(int *)(this + 0x10) != 0) {
      return;
    }
    uVar1 = *(uint *)(this + 8);
    if (*(uint *)(this + 0x20) <= uVar1) goto LAB_0040bbaf;
  }
  func_0xe8eabc84(uVar1,(-(uint)(param_1 != 0) & 0xfffffffd) + 3 | 0x400);
LAB_0040bc11:
  *(undefined4 *)(this + 0x18) = 1;
  return;
}



// Library Function - Single Match
//  public: virtual void __thiscall CCmdUI::SetCheck(int)
// 
// Library: Visual Studio 2008 Release

void __thiscall CCmdUI::SetCheck(CCmdUI *this,int param_1)

{
  code *pcVar1;
  uint uVar2;
  
  pcVar1 = DAT_00428380;
  if (*(int *)(this + 0xc) == 0) {
    if (*(int *)(this + 0x14) != 0) {
      uVar2 = (*DAT_00428380)(*(undefined4 *)(*(int *)(this + 0x14) + 0x20),0x87,0,0);
      if ((uVar2 & 0x2000) == 0) {
        return;
      }
      (*pcVar1)(*(undefined4 *)(*(int *)(this + 0x14) + 0x20),0xf1,param_1,0);
      return;
    }
  }
  else {
    if (*(int *)(this + 0x10) != 0) {
      return;
    }
    uVar2 = *(uint *)(this + 8);
    if (uVar2 < *(uint *)(this + 0x20)) goto LAB_0040bc40;
  }
  uVar2 = func_0xecbbbcf6();
LAB_0040bc40:
  func_0xd0eabd0d(uVar2,-(uint)(param_1 != 0) & 8 | 0x400);
  return;
}



// Library Function - Multiple Matches With Same Base Name
//  public: virtual void __thiscall CCmdUI::SetText(char const *)
//  public: virtual void __thiscall CCmdUI::SetText(wchar_t const *)
// 
// Library: Visual Studio 2008 Release

void __thiscall SetText(void *this,int param_1)

{
  uint uVar1;
  undefined4 unaff_EDI;
  
  if (param_1 != 0) goto LAB_0040bca7;
  do {
    while( true ) {
      func_0xecbbbd5d();
LAB_0040bca7:
      if (*(int *)((int)this + 0xc) != 0) break;
      this = *(void **)((int)this + 0x14);
      if (this != (void *)0x0) {
        func_0xb540beb2(*(undefined4 *)((int)this + 0x20),param_1);
        return;
      }
    }
    if (*(int *)((int)this + 0x10) != 0) {
      return;
    }
    uVar1 = (*DAT_0042835c)(*(undefined4 *)(*(int *)((int)this + 0xc) + 4),
                            *(undefined4 *)((int)this + 8),0x400,unaff_EDI);
    unaff_EDI = 0x400;
  } while (*(uint *)((int)this + 0x20) <= *(uint *)((int)this + 8));
  func_0x00ebbd9d(*(uint *)((int)this + 8),uVar1 & 0xfffff6fb | 0x400,*(undefined4 *)((int)this + 4)
                  ,param_1);
  return;
}



// Library Function - Single Match
//  void __stdcall _AfxLoadDotBitmap(void)
// 
// Library: Visual Studio 2008 Release

void _AfxLoadDotBitmap(void)

{
  byte bVar1;
  undefined4 uVar2;
  undefined *puVar3;
  int extraout_ECX;
  byte *pbVar4;
  ushort uVar5;
  int iVar6;
  int iVar7;
  int local_94;
  int local_90;
  int local_8c;
  undefined local_88 [128];
  uint local_8;
  
  local_8 = DAT_00431c20 ^ (uint)&stack0xfffffffc;
  uVar2 = (*DAT_00428314)();
  local_90 = (int)(short)uVar2;
  local_8c = (int)(short)((uint)uVar2 >> 0x10);
  if ((local_90 < 5) || (iVar7 = local_90, local_8c < 6)) {
    func_0xecbbbdf9();
    iVar7 = extraout_ECX;
  }
  if (0x20 < iVar7) {
    iVar7 = 0x20;
    local_90 = 0x20;
  }
  iVar6 = iVar7 + 0xf >> 4;
  iVar7 = ((iVar7 + -4) / 2 + iVar6 * 0x10) - iVar7;
  if (0xc < iVar7) {
    iVar7 = 0xc;
  }
  if (0x20 < local_8c) {
    local_8c = 0x20;
  }
  func_0x3b82bf4c(local_88,0xff,0x80);
  puVar3 = local_88 + (local_8c + -6 >> 1) * iVar6 * 2;
  pbVar4 = &DAT_004289b4;
  local_94 = 5;
  do {
    bVar1 = *pbVar4;
    pbVar4 = pbVar4 + 1;
    uVar5 = ~((ushort)bVar1 << ((byte)iVar7 & 0x1f));
    *puVar3 = (char)(uVar5 >> 8);
    puVar3[1] = (char)uVar5;
    puVar3 = puVar3 + iVar6 * 2;
    local_94 = local_94 + -1;
  } while (local_94 != 0);
  DAT_00433360 = (*(code *)s_InitCommonControlsEx_00428017._5_4_)(local_90,local_8c,1,1,local_88);
  if (DAT_00433360 == 0) {
    DAT_00433360 = (*DAT_00428318)(0,0x7fe3);
  }
  func_0x485ebfd7();
  return;
}



// Library Function - Single Match
//  public: virtual void __thiscall CCmdUI::SetRadio(int)
// 
// Libraries: Visual Studio 2008 Release, Visual Studio 2010 Release

void __thiscall CCmdUI::SetRadio(CCmdUI *this,int param_1)

{
  (**(code **)(*(int *)this + 4))(param_1 != 0);
  if ((*(int *)(this + 0xc) != 0) && (*(int *)(this + 0x10) == 0)) {
    if (*(uint *)(this + 0x20) <= *(uint *)(this + 8)) {
      func_0xecbbbf0b();
    }
    if ((DAT_00433360 == 0) && (func_0xf8ecbf18(), DAT_00433360 == 0)) {
      return;
    }
    (*DAT_00428310)(*(undefined4 *)(*(int *)(this + 0xc) + 4),*(undefined4 *)(this + 8),0x400,0,
                    DAT_00433360);
  }
  return;
}



// Library Function - Single Match
//  public: void __thiscall CHandleMap::DeleteTemp(void)
// 
// Libraries: Visual Studio 2003 Release, Visual Studio 2005 Release, Visual Studio 2008 Release

void __thiscall CHandleMap::DeleteTemp(CHandleMap *this)

{
  int iVar1;
  undefined local_10 [4];
  int local_c;
  int local_8;
  
  if (this != (CHandleMap *)0x0) {
    local_c = -(uint)(*(int *)(this + 0x44) != 0);
    while (local_c != 0) {
      func_0xb3d8c0af(&local_c,local_10,&local_8);
      iVar1 = *(int *)(this + 0x58);
      *(undefined4 *)(iVar1 + local_8) = 0;
      if (*(int *)(this + 0x5c) == 2) {
        ((undefined4 *)(iVar1 + local_8))[1] = 0;
      }
      (**(code **)(this + 0x18))(local_8);
    }
    func_0x77d7c0d7();
    func_0x4846c1df();
  }
  return;
}



void * __thiscall FUN_0040c079(void *this,byte param_1)

{
  func_0x23f0c13c();
  if ((param_1 & 1) != 0) {
    func_0x15bac148(this);
  }
  return this;
}



// Library Function - Single Match
//  _IsPlatformNT
// 
// Libraries: Visual Studio 2005 Release, Visual Studio 2008 Release

void _IsPlatformNT(void)

{
  undefined4 local_9c;
  undefined local_98 [144];
  uint local_8;
  
  local_8 = DAT_00431c20 ^ (uint)&stack0xfffffffc;
  func_0x3b82c278(local_98,0,0x90);
  local_9c = 0x94;
  (*DAT_00428094)(&local_9c);
  func_0x485ec2a8();
  return;
}



// WARNING: Globals starting with '_' overlap smaller symbols at the same address
// Library Function - Single Match
//  _xMonitorFromRect@8
// 
// Library: Visual Studio 2008 Release

undefined4 _xMonitorFromRect_8(int *param_1,byte param_2)

{
  code *pcVar1;
  int iVar2;
  undefined4 uVar3;
  
  iVar2 = func_0xebf0c2be();
  pcVar1 = DAT_00428330;
  if (iVar2 != 0) {
                    // WARNING: Could not recover jumptable at 0x0040c20d. Too many branches
                    // WARNING: Treating indirect jump as call
    uVar3 = (*_DAT_00434b78)();
    return uVar3;
  }
  if ((param_2 & 3) == 0) {
    if ((0 < param_1[2]) && (0 < param_1[3])) {
      iVar2 = (*DAT_00428330)(0);
      if (*param_1 < iVar2) {
        iVar2 = (*pcVar1)(1);
        if (param_1[1] < iVar2) goto LAB_0040c244;
      }
    }
    uVar3 = 0;
  }
  else {
LAB_0040c244:
    uVar3 = 0x12340042;
  }
  return uVar3;
}



// Library Function - Single Match
//  _xMonitorFromWindow@8
// 
// Libraries: Visual Studio 2003 Release, Visual Studio 2005 Release, Visual Studio 2008 Release

undefined4 _xMonitorFromWindow_8(undefined4 param_1,uint param_2)

{
  int iVar1;
  undefined4 uVar2;
  undefined local_30 [28];
  undefined local_14 [16];
  
  iVar1 = func_0xebf0c312();
  if (iVar1 == 0) {
    if ((param_2 & 3) == 0) {
      iVar1 = (*DAT_00428300)(param_1);
      if (iVar1 == 0) {
        iVar1 = (*DAT_00428308)(param_1,local_14);
      }
      else {
        iVar1 = (*DAT_00428304)(param_1,local_30);
      }
      if (iVar1 == 0) {
        uVar2 = 0;
      }
      else {
        uVar2 = func_0xf5f1c36a(local_14,param_2);
      }
    }
    else {
      uVar2 = 0x12340042;
    }
  }
  else {
    uVar2 = (*DAT_00434b74)(param_1,param_2);
  }
  return uVar2;
}



// Library Function - Single Match
//  _xGetMonitorInfo@8
// 
// Libraries: Visual Studio 2003 Release, Visual Studio 2005 Release, Visual Studio 2008 Release

int _xGetMonitorInfo_8(int param_1,uint *param_2)

{
  code *pcVar1;
  int iVar2;
  uint uVar3;
  uint local_14;
  uint uStack_10;
  uint uStack_c;
  uint uStack_8;
  
  iVar2 = func_0xebf0c381();
  if (iVar2 == 0) {
    if (((param_1 == 0x12340042) && (param_2 != (uint *)0x0)) &&
       ((0x27 < *param_2 && (iVar2 = (*DAT_004282fc)(0x30,0,&local_14,0), iVar2 != 0)))) {
      param_2[1] = 0;
      param_2[2] = 0;
      pcVar1 = DAT_00428330;
      uVar3 = (*DAT_00428330)(0);
      param_2[3] = uVar3;
      uVar3 = (*pcVar1)(1);
      param_2[5] = local_14;
      param_2[6] = uStack_10;
      param_2[7] = uStack_c;
      param_2[8] = uStack_8;
      iVar2 = 1;
      param_2[4] = uVar3;
      param_2[9] = 1;
      if (0x67 < *param_2) {
        (*DAT_004281f0)(0,0,&DAT_00428bb8,0xffffffff,param_2 + 10,0x20);
      }
    }
    else {
      iVar2 = 0;
    }
  }
  else {
    iVar2 = (*DAT_00434b80)(param_1,param_2);
    if (((iVar2 != 0) && (DAT_00434b90 == 0)) && (0x67 < *param_2)) {
      (*DAT_004281f0)(0,0,param_2 + 10,0xffffffff,param_2 + 10,0x20);
    }
  }
  return iVar2;
}



// WARNING: Control flow encountered bad instruction data
// WARNING: Instruction at (ram,0x0040c8bd) overlaps instruction at (ram,0x0040c8bc)
// 
// WARNING: Unable to track spacebase fully for stack
// WARNING: This function may have set the stack pointer
// WARNING: Globals starting with '_' overlap smaller symbols at the same address

char * FUN_0040c382(int *param_1,int param_2,undefined4 param_3,undefined4 param_4,uint param_5,
                   uint *param_6,undefined2 *param_7,undefined param_8,undefined4 *param_9)

{
  ushort uVar1;
  int *piVar2;
  undefined4 uVar3;
  code *pcVar4;
  int *piVar5;
  uint *puVar6;
  char cVar7;
  undefined uVar8;
  char *pcVar9;
  undefined4 *puVar10;
  undefined *puVar11;
  int iVar12;
  undefined4 extraout_ECX;
  int iVar13;
  int *piVar14;
  undefined *puVar15;
  undefined *puVar16;
  undefined *puVar17;
  undefined4 *local_48;
  undefined4 *local_44;
  undefined3 uStack_43;
  undefined uStack_40;
  undefined4 *local_38;
  undefined4 local_34;
  undefined4 uStack_30;
  undefined4 uStack_2c;
  undefined4 uStack_28;
  undefined2 local_24 [8];
  undefined4 local_14;
  undefined4 local_10;
  undefined4 local_c;
  undefined4 local_8;
  
  puVar6 = param_6;
  piVar5 = param_1;
  puVar11 = &stack0xfffffffc;
  puVar16 = &stack0xfffffffc;
  iVar13 = 0;
  local_24[0] = 0;
  if (param_1 == (int *)0x0) {
                    // WARNING: Bad instruction - Truncating control flow here
    halt_baddata();
  }
  if (param_6 == (uint *)0x0) {
                    // WARNING: Bad instruction - Truncating control flow here
    halt_baddata();
  }
  piVar14 = (int *)param_6[2];
  if ((int *)0x5 < piVar14) {
                    // WARNING: Bad instruction - Truncating control flow here
    halt_baddata();
  }
  param_1 = (int *)0x0;
  if (param_6[3] != 0) {
    param_6 = (uint *)param_6[1];
    do {
      piVar2 = (int *)*param_6;
      if (piVar14 <= piVar2) {
        return;
      }
      param_6 = param_6 + 1;
      param_1 = (int *)((int)param_1 + 1);
      (&local_48)[(int)piVar2] = (undefined4 *)(*puVar6 + iVar13);
      iVar13 = iVar13 + 0x10;
    } while (param_1 < (int *)puVar6[3]);
  }
  if (param_1 < piVar14) {
    iVar13 = (int)param_1 * 0x10 + *puVar6;
    iVar12 = (int)piVar14 - (int)param_1;
    piVar14 = (int *)(&stack0xffffffb4 + ((int)piVar14 - (int)param_1) * 4);
    do {
      *piVar14 = iVar13;
      iVar13 = iVar13 + 0x10;
      piVar14 = piVar14 + -1;
      iVar12 = iVar12 + -1;
    } while (iVar12 != 0);
  }
  if (param_9 == (undefined4 *)0x0) {
    param_9 = &param_5;
  }
  if (param_7 == (undefined2 *)0x0) {
    param_7 = local_24;
  }
  (*DAT_0042825c)(&local_14);
  pcVar9 = (char *)(param_2 + 0x139a);
  iVar13 = CONCAT31((int3)((uint)extraout_ECX >> 8),(byte)param_5);
  cVar7 = (char)pcVar9;
  puVar17 = &stack0xfffffffc;
  switch(pcVar9) {
  case (char *)0x0:
                    // WARNING: Bad instruction - Truncating control flow here
    halt_baddata();
  case (char *)0x1:
    *(char *)((int)piVar5 + 0xf01087f) = *(char *)((int)piVar5 + 0xf01087f) + cVar7;
    *(char *)((int)piVar5 + 0x38bbc75) = *(char *)((int)piVar5 + 0x38bbc75) + (byte)param_5;
    (**(code **)(CONCAT31((int3)((uint)pcVar9 >> 8),cVar7 + -1) + 0x65))
              (piVar5,_DAT_80020003,_DAT_80020007,_DAT_8002000b,_DAT_8002000f);
                    // WARNING: Bad instruction - Truncating control flow here
    halt_baddata();
  case (char *)0x2:
    *pcVar9 = *pcVar9 + cVar7;
    puVar10 = (undefined4 *)&DAT_087f838a;
    *(char *)((int)piVar5 + -0x7c9943bb) =
         *(char *)((int)piVar5 + -0x7c9943bb) + (byte)param_5 + *(char *)puVar6;
    pcVar4 = DAT_00428258;
    if (*(char *)piVar5 != -0x76) {
      iVar13 = (*DAT_00428258)(&local_14,&DAT_087f838a,0,3);
      if (iVar13 < 0) {
LAB_0040c688:
        **(undefined4 **)(puVar16 + 0x28) = 0;
                    // WARNING: Bad instruction - Truncating control flow here
        halt_baddata();
      }
      puVar10 = &local_14;
    }
    param_5 = puVar10[2];
    if (*(short *)local_44 == 3) {
LAB_0040c4dc:
      (**(code **)(*piVar5 + 0x60))(piVar5,param_5,local_44[2],param_7);
                    // WARNING: Bad instruction - Truncating control flow here
      halt_baddata();
    }
    pcVar9 = (char *)(*pcVar4)(&local_14,local_44,0,3);
    if (-1 < (int)pcVar9) {
      local_44 = &local_14;
      goto LAB_0040c4dc;
    }
LAB_0040c86f:
    *param_9 = 1;
    puVar17 = &stack0xfffffffc;
    break;
  case (char *)0x3:
    *pcVar9 = *pcVar9 + cVar7;
    puVar11 = &DAT_087f838a;
    puVar16 = &stack0xfffffffd;
    puVar15 = (undefined *)0x3388366;
    if (puVar16 != (undefined *)0x0) {
      uRam03388362 = 3;
      uRam0338835e = 0;
      puRam0338835a = &DAT_087f838a;
      iRam03388356 = (int)&local_14 + 1;
      puVar15 = (undefined *)0x3388352;
      uRam03388352 = 0x40c513;
      iVar13 = (*DAT_00428258)();
      if (iVar13 < 0) goto LAB_0040c688;
      puVar11 = (undefined *)((int)&local_14 + 1);
    }
    *(uint *)(puVar15 + -4) = CONCAT13(param_8,param_7._1_3_);
    puVar10 = (undefined4 *)CONCAT13(uStack_40,uStack_43);
    uVar3 = *(undefined4 *)(puVar11 + 8);
    iVar13 = *piVar5;
    *(undefined4 *)(puVar15 + -0x14) = *puVar10;
    *(undefined4 *)(puVar15 + -0x10) = puVar10[1];
    *(undefined4 *)(puVar15 + -0xc) = puVar10[2];
    *(undefined4 *)(puVar15 + -0x18) = uVar3;
    *(int **)(puVar15 + -0x1c) = piVar5;
    *(undefined4 *)(puVar15 + -8) = puVar10[3];
    pcVar4 = *(code **)(iVar13 + 0x5c);
    *(undefined4 *)(puVar15 + -0x20) = 0x40c539;
    (*pcVar4)();
                    // WARNING: Bad instruction - Truncating control flow here
    halt_baddata();
  case (char *)0x4:
    *pcVar9 = *pcVar9 + cVar7;
    DAT_0bd50899 = DAT_0bd50899 + -0x67;
    while ((uVar1 = *(ushort *)local_48, (uVar1 & 0x4000) != 0 && ((uVar1 & 0xf) != 0))) {
      if ((uVar1 & 0xc) == 0) {
        local_14 = local_48[2];
      }
      else {
        (*DAT_00428254)(local_48[2]);
        *(undefined2 *)local_48[2] = 3;
        local_14 = local_48[2] + 8;
      }
    }
    *param_9 = 0;
    (**(code **)(*piVar5 + 0x58))
              (piVar5,local_14,local_10,local_c,local_8,*local_38,local_38[1],local_38[2],
               local_38[3]);
                    // WARNING: Bad instruction - Truncating control flow here
    halt_baddata();
  case (char *)0x5:
    *pcVar9 = *pcVar9 + cVar7;
    cVar7 = DAT_087f838a + -0x76;
    puVar10 = (undefined4 *)CONCAT31(0x87f83,cVar7);
    *(char *)((int)piVar5 + -0x7c9943bb) =
         *(char *)((int)piVar5 + -0x7c9943bb) + (byte)param_5 + *(char *)puVar6;
    if (*(char *)piVar5 != cVar7) {
      iVar13 = (*DAT_00428258)(&local_14,puVar10,0,3);
      puVar16 = &stack0xfffffffc;
      if (iVar13 < 0) goto LAB_0040c688;
      puVar10 = &local_14;
    }
    (**(code **)(*piVar5 + 0x54))(piVar5,puVar10[2],*local_44,local_44[1],local_44[2],local_44[3]);
                    // WARNING: Bad instruction - Truncating control flow here
    halt_baddata();
  case (char *)0x6:
    *pcVar9 = *pcVar9 + cVar7;
    *puVar6 = *puVar6 + iVar13;
    *(byte *)((int)piVar5 + 0x38bbc75) = *(byte *)((int)piVar5 + 0x38bbc75) & (byte)param_5;
    pcVar9 = (char *)(*_DAT_087f83da)(piVar5,_DAT_80020003,_DAT_80020007,_DAT_8002000b,_DAT_8002000f
                                      ,iVar13 + 8);
    puVar11 = (undefined *)((int)&local_8 + 3);
    goto LAB_0040c616;
  case (char *)0x7:
    *pcVar9 = *pcVar9 + cVar7;
    (**(code **)(*piVar5 + 0x4c))(piVar5);
                    // WARNING: Bad instruction - Truncating control flow here
    halt_baddata();
  case (char *)0x8:
    *pcVar9 = *pcVar9 + cVar7;
    (**(code **)(*piVar5 + 0x48))(piVar5);
                    // WARNING: Bad instruction - Truncating control flow here
    halt_baddata();
  case (char *)0x9:
    *pcVar9 = *pcVar9 + cVar7;
    *puVar6 = *puVar6 + iVar13;
    DAT_087f838a = DAT_087f838a + -0x76;
    pcVar9 = (char *)(**(code **)(*piVar5 + 0x44))
                               (piVar5,*local_48,local_48[1],local_48[2],local_48[3],param_7 + 4);
    goto LAB_0040c616;
  case (char *)0xa:
    puVar11 = &stack0xfffffffc;
LAB_0040c616:
    puVar17 = puVar11;
    if (-1 < (int)pcVar9) {
                    // WARNING: Bad instruction - Truncating control flow here
      halt_baddata();
    }
    break;
  case (char *)0xb:
    *pcVar9 = *pcVar9 + cVar7;
    *puVar6 = *puVar6 + iVar13;
    *(byte *)((int)piVar5 + 0x38bbc75) = *(byte *)((int)piVar5 + 0x38bbc75) & (byte)param_5;
    (*_DAT_087f8419)(piVar5,_DAT_80020003,_DAT_80020007,_DAT_8002000b,_DAT_8002000f,iVar13 + 8);
                    // WARNING: Bad instruction - Truncating control flow here
    halt_baddata();
  case (char *)0xc:
    *pcVar9 = *pcVar9 + cVar7;
    if (puVar6[2] == 1) {
      (**(code **)(*piVar5 + 0x38))(piVar5,*local_48,local_48[1],local_48[2],local_48[3],param_7);
                    // WARNING: Bad instruction - Truncating control flow here
      halt_baddata();
    }
    goto LAB_0040c89d;
  case (char *)0xd:
    *pcVar9 = *pcVar9 + cVar7;
    *puVar6 = *puVar6 + iVar13;
    DAT_087f838a = DAT_087f838a + -0x76;
    (**(code **)(*piVar5 + 0x34))(piVar5,*local_48,local_48[1],local_48[2],local_48[3],param_7);
                    // WARNING: Bad instruction - Truncating control flow here
    halt_baddata();
  case (char *)0xe:
    *pcVar9 = *pcVar9 + cVar7;
    *puVar6 = *puVar6 + iVar13;
    puVar11 = &DAT_087f838a + CONCAT22(uRam087f838c,CONCAT11(uRam087f838b,DAT_087f838a));
    DAT_087f838a = (char)puVar11;
    uRam087f838b = (undefined)((uint)puVar11 >> 8);
    uRam087f838c = (undefined2)((uint)puVar11 >> 0x10);
    *(char *)((int)piVar5 + 0x758b204d) = *(char *)((int)piVar5 + 0x758b204d) + (byte)param_5;
    *(byte *)(iVar13 + -0x7d) = *(byte *)(iVar13 + -0x7d) | 2;
    uVar8 = in(2);
    *(byte *)(piVar5 + -0x16969681) = *(char *)(piVar5 + -0x16969681) + (byte)param_5;
    piRamc1830387 = piVar5;
    *puVar6 = _DAT_80020003;
    uRamc1830383 = 0x40c793;
    (**(code **)(CONCAT31(0x87f83,uVar8) + 0x30))();
                    // WARNING: Bad instruction - Truncating control flow here
    halt_baddata();
  case (char *)0xf:
    *pcVar9 = *pcVar9 + cVar7;
    if ((param_5 & 2) == 0) {
      if ((param_5 & 4) == 0) {
        if ((param_5 & 2) == 0) {
          if ((param_5 & 4) == 0) {
            if (puVar6[2] == 1) {
              pcVar9 = (char *)(**(code **)(*piVar5 + 0x24))
                                         (piVar5,*local_48,local_48[1],local_48[2],local_48[3],
                                          param_7 + 4);
              puVar17 = &stack0xfffffffc;
              if (-1 < (int)pcVar9) {
                *param_7 = 9;
                puVar17 = &stack0xfffffffc;
              }
              break;
            }
          }
          else if (puVar6[2] == 0xd02) {
            local_34 = *local_48;
            uStack_30 = local_48[1];
            uStack_2c = local_48[2];
            uStack_28 = local_48[3];
            if (*(short *)local_44 != 8) {
              pcVar9 = (char *)(*DAT_00428258)(&local_14,local_44,0,3);
              if ((int)pcVar9 < 0) goto LAB_0040c86f;
              local_44 = &local_14;
            }
            pcVar9 = (char *)(**(code **)(*piVar5 + 0x68))
                                       (piVar5,local_34,uStack_30,uStack_2c,uStack_28,local_44[2]);
            puVar17 = &stack0xfffffffc;
            break;
          }
        }
        else if (puVar6[2] == 1) {
          (**(code **)(*piVar5 + 0x28))
                    (piVar5,*local_48,local_48[1],local_48[2],local_48[3],param_7 + 4);
                    // WARNING: Bad instruction - Truncating control flow here
          halt_baddata();
        }
      }
      else if (puVar6[2] == 0xd02) {
        local_34 = *local_48;
        uStack_30 = local_48[1];
        uStack_2c = local_48[2];
        uStack_28 = local_48[3];
        if (*(short *)local_44 != 8) {
          pcVar9 = (char *)(*DAT_00428258)(&local_14,local_44,0,3);
          if ((int)pcVar9 < 0) goto LAB_0040c86f;
          local_44 = &local_14;
        }
        pcVar9 = (char *)(**(code **)(*piVar5 + 0x6c))
                                   (piVar5,local_34,uStack_30,uStack_2c,uStack_28,local_44[2]);
        puVar17 = &stack0xfffffffc;
        break;
      }
    }
    else if (puVar6[2] == 1) {
      (**(code **)(*piVar5 + 0x2c))
                (piVar5,*local_48,local_48[1],local_48[2],local_48[3],param_7 + 4);
                    // WARNING: Bad instruction - Truncating control flow here
      halt_baddata();
    }
LAB_0040c89d:
    pcVar9 = (char *)0x8002000e;
    puVar17 = &stack0xfffffffc;
    break;
  case (char *)0x10:
    uVar8 = in(2);
    *(undefined *)puVar6 = uVar8;
    puVar17 = &stack0xfffffffc;
    break;
  case (char *)0x12:
    (**(code **)(*piVar5 + 0x20))(piVar5,param_7 + 4);
                    // WARNING: Bad instruction - Truncating control flow here
    halt_baddata();
  }
  (*DAT_00428254)(puVar17 + -0x10);
  return pcVar9;
}



// Library Function - Single Match
//  private: __thiscall CWnd::CWnd(struct HWND__ *)
// 
// Library: Visual Studio 2008 Release

CWnd * __thiscall CWnd::CWnd(CWnd *this,HWND__ *param_1)

{
  func_0x1eebca73();
  *(int *)this = (int)u_UTF_16LE_00428e2b + 1;
  *(int *)(this + 0x30) = (int)u_mscoree_dll_00428d8f + 0xd;
  *(char **)(this + 0x34) = s_FlsAlloc_00428e0b + 5;
  *(HWND__ **)(this + 0x20) = param_1;
  this[0x24] = (CWnd)0x0;
  *(undefined4 *)(this + 0x2c) = 0;
  *(undefined4 *)(this + 0x38) = 0;
  *(undefined4 *)(this + 0x3c) = 0;
  *(undefined4 *)(this + 0x40) = 0;
  *(undefined4 *)(this + 0x44) = 0;
  *(undefined4 *)(this + 0x48) = 0;
  *(undefined4 *)(this + 0x4c) = 0;
  *(undefined4 *)(this + 0x50) = 0;
  return this;
}



// Library Function - Single Match
//  public: virtual int __thiscall CWnd::PreTranslateMessage(struct tagMSG *)
// 
// Libraries: Visual Studio 2008 Release, Visual Studio 2010 Release, Visual Studio 2012 Release

int __thiscall CWnd::PreTranslateMessage(CWnd *this,tagMSG *param_1)

{
  int iVar1;
  
  iVar1 = func_0x59d0cb2c();
  if (*(code **)(iVar1 + 0x38) != (code *)0x0) {
    (**(code **)(iVar1 + 0x38))(param_1,this);
  }
  return 0;
}



// Library Function - Multiple Matches With Same Base Name
//  public: virtual int __thiscall CWnd::OnToolHitTest(class CPoint,struct tagTOOLINFOA *)const 
//  public: virtual int __thiscall CWnd::OnToolHitTest(class CPoint,struct tagTOOLINFOW *)const 
// 
// Libraries: Visual Studio 2008 Release, Visual Studio 2010 Release

undefined4 __thiscall OnToolHitTest(void *this,undefined4 param_1,undefined4 param_2,uint *param_3)

{
  uint uVar1;
  uint uVar2;
  undefined4 uVar3;
  
  uVar2 = FUN_0042cc58((char *)this);
  if (uVar2 == 0) {
    uVar3 = 0xffffffff;
  }
  else {
    uVar3 = (*DAT_004282e0)(uVar2);
    if ((param_3 != (uint *)0x0) && (0x2b < *param_3)) {
      uVar1 = *(uint *)((int)this + 0x20);
      param_3[1] = param_3[1] | 1;
      param_3[9] = 0xffffffff;
      param_3[2] = uVar1;
      param_3[3] = uVar2;
      uVar2 = (*DAT_00428380)(uVar2,0x87,0,0);
      if ((uVar2 & 0x2000) == 0) {
        param_3[1] = param_3[1] | 0x80000002;
      }
    }
  }
  return uVar3;
}



void * __thiscall FUN_0040cb12(void *this,byte param_1)

{
  func_0xf4facbd5();
  if ((param_1 & 1) != 0) {
    func_0x47bdcbe1(this);
  }
  return this;
}



// Library Function - Single Match
//  struct AFX_MSGMAP_ENTRY const * __stdcall AfxFindMessageEntry(struct AFX_MSGMAP_ENTRY const
// *,unsigned int,unsigned int,unsigned int)
// 
// Library: Visual Studio

AFX_MSGMAP_ENTRY *
AfxFindMessageEntry(AFX_MSGMAP_ENTRY *param_1,uint param_2,uint param_3,uint param_4)

{
  while( true ) {
    if (*(uint *)((int)param_1 + 0x10) == 0) {
      return (AFX_MSGMAP_ENTRY *)0x0;
    }
    if ((((param_2 == *(uint *)param_1) && (param_3 == *(uint *)((int)param_1 + 4))) &&
        (*(uint *)((int)param_1 + 8) <= param_4)) && (param_4 <= *(uint *)((int)param_1 + 0xc)))
    break;
    param_1 = (AFX_MSGMAP_ENTRY *)((int)param_1 + 0x18);
  }
  return (AFX_MSGMAP_ENTRY *)(uint *)param_1;
}



// Library Function - Single Match
//  protected: virtual long __thiscall CWnd::WindowProc(unsigned int,unsigned int,long)
// 
// Libraries: Visual Studio 2003 Release, Visual Studio 2005 Release, Visual Studio 2008 Release,
// Visual Studio 2010 Release

long __thiscall CWnd::WindowProc(CWnd *this,uint param_1,uint param_2,long param_3)

{
  int iVar1;
  long local_8;
  
  local_8 = 0;
  iVar1 = (**(code **)(*(int *)this + 0x114))(param_1,param_2,param_3,&local_8);
  if (iVar1 == 0) {
    local_8 = (**(code **)(*(int *)this + 0x118))(param_1,param_2,param_3);
  }
  return local_8;
}



void __thiscall FUN_0040cbd5(void *this,undefined4 param_1)

{
  *(undefined4 *)((int)this + 0x28) = param_1;
  *(undefined4 *)((int)this + 0x18) = 1;
  return;
}



void FUN_0040cbee(undefined4 param_1)

{
  func_0x15baccb1(param_1);
  return;
}



// Library Function - Single Match
//  public: virtual void __thiscall CWnd::CalcWindowRect(struct tagRECT *,unsigned int)
// 
// Libraries: Visual Studio 2008 Release, Visual Studio 2010 Release, Visual Studio 2012 Release,
// Visual Studio 2015 Release

void __thiscall CWnd::CalcWindowRect(CWnd *this,tagRECT *param_1,uint param_2)

{
  uint uVar1;
  undefined4 uVar2;
  
  uVar1 = func_0xd83fccc8();
  if (param_2 == 0) {
    uVar1 = uVar1 & 0xfffffdff;
  }
  uVar2 = func_0xbe3fccdd(0,uVar1);
  (*DAT_004282dc)(param_1,uVar2);
  return;
}



void FUN_0040cc3c(undefined4 param_1,undefined4 param_2,undefined4 param_3,undefined4 param_4,
                 undefined4 param_5,undefined4 param_6)

{
  func_0x45f9cd0b(param_2,param_3,param_4,param_5,param_6);
  return;
}



undefined4 FUN_0040cc59(undefined4 param_1,undefined4 *param_2)

{
  undefined4 uVar1;
  
  if (param_2 == (undefined4 *)0x0) {
    uVar1 = 0x80004003;
  }
  else {
    *param_2 = 1;
    uVar1 = 0;
  }
  return uVar1;
}



undefined4 FUN_0040cc80(undefined4 param_1,undefined4 *param_2)

{
  undefined4 uVar1;
  
  if (param_2 == (undefined4 *)0x0) {
    uVar1 = 0x80004003;
  }
  else {
    *param_2 = 0;
    uVar1 = 0x80004001;
  }
  return uVar1;
}



void __thiscall FUN_0040ccbe(void *this,undefined4 param_1)

{
  (**(code **)(**(int **)((int)this + 0x28) + 0x1c))(*(int **)((int)this + 0x28),param_1);
  return;
}



void __thiscall FUN_0040ccd3(void *this,undefined4 param_1)

{
  (**(code **)(**(int **)((int)this + 0x28) + 0x20))(*(int **)((int)this + 0x28),param_1);
  return;
}



// Library Function - Single Match
//  public: virtual long __thiscall CWnd::get_accChild(struct tagVARIANT,struct IDispatch * *)
// 
// Libraries: Visual Studio 2008 Release, Visual Studio 2010 Release, Visual Studio 2012 Release

long __thiscall
CWnd::get_accChild(CWnd *this,undefined4 param_1,undefined4 param_2,undefined4 param_3,
                  undefined4 param_4,undefined4 param_5)

{
  long lVar1;
  
  lVar1 = (**(code **)(**(int **)(this + 0x28) + 0x24))
                    (*(int **)(this + 0x28),param_1,param_2,param_3,param_4,param_5);
  return lVar1;
}



// Library Function - Single Match
//  public: virtual long __thiscall CWnd::get_accName(struct tagVARIANT,wchar_t * *)
// 
// Libraries: Visual Studio 2008 Release, Visual Studio 2010 Release, Visual Studio 2012 Release

long __thiscall
CWnd::get_accName(CWnd *this,undefined4 param_1,undefined4 param_2,undefined4 param_3,
                 undefined4 param_4,undefined4 param_5)

{
  long lVar1;
  
  lVar1 = (**(code **)(**(int **)(this + 0x28) + 0x28))
                    (*(int **)(this + 0x28),param_1,param_2,param_3,param_4,param_5);
  return lVar1;
}



// Library Function - Single Match
//  public: virtual long __thiscall CWnd::get_accValue(struct tagVARIANT,wchar_t * *)
// 
// Libraries: Visual Studio 2008 Release, Visual Studio 2010 Release, Visual Studio 2012 Release

long __thiscall
CWnd::get_accValue(CWnd *this,undefined4 param_1,undefined4 param_2,undefined4 param_3,
                  undefined4 param_4,undefined4 param_5)

{
  long lVar1;
  
  lVar1 = (**(code **)(**(int **)(this + 0x28) + 0x2c))
                    (*(int **)(this + 0x28),param_1,param_2,param_3,param_4,param_5);
  return lVar1;
}



// Library Function - Single Match
//  public: virtual long __thiscall CWnd::get_accDescription(struct tagVARIANT,wchar_t * *)
// 
// Libraries: Visual Studio 2008 Release, Visual Studio 2010 Release, Visual Studio 2012 Release

long __thiscall
CWnd::get_accDescription
          (CWnd *this,undefined4 param_1,undefined4 param_2,undefined4 param_3,undefined4 param_4,
          undefined4 param_5)

{
  long lVar1;
  
  lVar1 = (**(code **)(**(int **)(this + 0x28) + 0x30))
                    (*(int **)(this + 0x28),param_1,param_2,param_3,param_4,param_5);
  return lVar1;
}



// Library Function - Single Match
//  public: virtual long __thiscall CWnd::get_accRole(struct tagVARIANT,struct tagVARIANT *)
// 
// Libraries: Visual Studio 2008 Release, Visual Studio 2010 Release, Visual Studio 2012 Release

long __thiscall
CWnd::get_accRole(CWnd *this,undefined4 param_1,undefined4 param_2,undefined4 param_3,
                 undefined4 param_4,undefined4 param_5)

{
  long lVar1;
  
  lVar1 = (**(code **)(**(int **)(this + 0x28) + 0x34))
                    (*(int **)(this + 0x28),param_1,param_2,param_3,param_4,param_5);
  return lVar1;
}



// Library Function - Single Match
//  public: virtual long __thiscall CWnd::get_accState(struct tagVARIANT,struct tagVARIANT *)
// 
// Libraries: Visual Studio 2008 Release, Visual Studio 2010 Release, Visual Studio 2012 Release

long __thiscall
CWnd::get_accState(CWnd *this,undefined4 param_1,undefined4 param_2,undefined4 param_3,
                  undefined4 param_4,undefined4 param_5)

{
  long lVar1;
  
  lVar1 = (**(code **)(**(int **)(this + 0x28) + 0x38))
                    (*(int **)(this + 0x28),param_1,param_2,param_3,param_4,param_5);
  return lVar1;
}



// Library Function - Single Match
//  public: virtual long __thiscall CWnd::get_accHelp(struct tagVARIANT,wchar_t * *)
// 
// Libraries: Visual Studio 2008 Release, Visual Studio 2010 Release, Visual Studio 2012 Release

long __thiscall
CWnd::get_accHelp(CWnd *this,undefined4 param_1,undefined4 param_2,undefined4 param_3,
                 undefined4 param_4,undefined4 param_5)

{
  long lVar1;
  
  lVar1 = (**(code **)(**(int **)(this + 0x28) + 0x3c))
                    (*(int **)(this + 0x28),param_1,param_2,param_3,param_4,param_5);
  return lVar1;
}



// Library Function - Single Match
//  public: virtual long __thiscall CWnd::get_accHelpTopic(wchar_t * *,struct tagVARIANT,long *)
// 
// Libraries: Visual Studio 2008 Release, Visual Studio 2010 Release

long __thiscall
CWnd::get_accHelpTopic
          (CWnd *this,undefined4 param_1,undefined4 param_2,undefined4 param_3,undefined4 param_4,
          undefined4 param_5,undefined4 param_6)

{
  long lVar1;
  
  lVar1 = (**(code **)(**(int **)(this + 0x28) + 0x40))
                    (*(int **)(this + 0x28),param_1,param_2,param_3,param_4,param_5,param_6);
  return lVar1;
}



// Library Function - Single Match
//  public: virtual long __thiscall CWnd::get_accKeyboardShortcut(struct tagVARIANT,wchar_t * *)
// 
// Libraries: Visual Studio 2008 Release, Visual Studio 2010 Release, Visual Studio 2012 Release

long __thiscall
CWnd::get_accKeyboardShortcut
          (CWnd *this,undefined4 param_1,undefined4 param_2,undefined4 param_3,undefined4 param_4,
          undefined4 param_5)

{
  long lVar1;
  
  lVar1 = (**(code **)(**(int **)(this + 0x28) + 0x44))
                    (*(int **)(this + 0x28),param_1,param_2,param_3,param_4,param_5);
  return lVar1;
}



void __thiscall FUN_0040ce38(void *this,undefined4 param_1)

{
  (**(code **)(**(int **)((int)this + 0x28) + 0x48))(*(int **)((int)this + 0x28),param_1);
  return;
}



void __thiscall FUN_0040ce4d(void *this,undefined4 param_1)

{
  (**(code **)(**(int **)((int)this + 0x28) + 0x4c))(*(int **)((int)this + 0x28),param_1);
  return;
}



// Library Function - Single Match
//  public: virtual long __thiscall CWnd::get_accDefaultAction(struct tagVARIANT,wchar_t * *)
// 
// Libraries: Visual Studio 2008 Release, Visual Studio 2010 Release, Visual Studio 2012 Release

long __thiscall
CWnd::get_accDefaultAction
          (CWnd *this,undefined4 param_1,undefined4 param_2,undefined4 param_3,undefined4 param_4,
          undefined4 param_5)

{
  long lVar1;
  
  lVar1 = (**(code **)(**(int **)(this + 0x28) + 0x50))
                    (*(int **)(this + 0x28),param_1,param_2,param_3,param_4,param_5);
  return lVar1;
}



// Library Function - Single Match
//  public: virtual long __thiscall CWnd::accSelect(long,struct tagVARIANT)
// 
// Libraries: Visual Studio 2008 Release, Visual Studio 2010 Release

long __thiscall
CWnd::accSelect(CWnd *this,undefined4 param_1,undefined4 param_2,undefined4 param_3,
               undefined4 param_4,undefined4 param_5)

{
  long lVar1;
  
  lVar1 = (**(code **)(**(int **)(this + 0x28) + 0x54))
                    (*(int **)(this + 0x28),param_1,param_2,param_3,param_4,param_5);
  return lVar1;
}



// Library Function - Single Match
//  public: virtual long __thiscall CWnd::accLocation(long *,long *,long *,long *,struct tagVARIANT)
// 
// Libraries: Visual Studio 2005 Release, Visual Studio 2008 Release, Visual Studio 2010 Release,
// Visual Studio 2012 Release

long __thiscall
CWnd::accLocation(CWnd *this,undefined4 param_1,undefined4 param_2,undefined4 param_3,
                 undefined4 param_4,undefined4 param_5,undefined4 param_6,undefined4 param_7,
                 undefined4 param_8)

{
  long lVar1;
  
  lVar1 = (**(code **)(**(int **)(this + 0x28) + 0x58))
                    (*(int **)(this + 0x28),param_1,param_2,param_3,param_4,param_5,param_6,param_7,
                     param_8);
  return lVar1;
}



// Library Function - Single Match
//  public: virtual long __thiscall CWnd::accNavigate(long,struct tagVARIANT,struct tagVARIANT *)
// 
// Libraries: Visual Studio 2008 Release, Visual Studio 2010 Release

long __thiscall
CWnd::accNavigate(CWnd *this,undefined4 param_1,undefined4 param_2,undefined4 param_3,
                 undefined4 param_4,undefined4 param_5,undefined4 param_6)

{
  long lVar1;
  
  lVar1 = (**(code **)(**(int **)(this + 0x28) + 0x5c))
                    (*(int **)(this + 0x28),param_1,param_2,param_3,param_4,param_5,param_6);
  return lVar1;
}



void __thiscall FUN_0040cf02(void *this,undefined4 param_1,undefined4 param_2,undefined4 param_3)

{
  (**(code **)(**(int **)((int)this + 0x28) + 0x60))
            (*(int **)((int)this + 0x28),param_1,param_2,param_3);
  return;
}



// Library Function - Single Match
//  public: virtual long __thiscall CWnd::accDoDefaultAction(struct tagVARIANT)
// 
// Libraries: Visual Studio 2008 Release, Visual Studio 2010 Release

long __thiscall
CWnd::accDoDefaultAction
          (CWnd *this,undefined4 param_1,undefined4 param_2,undefined4 param_3,undefined4 param_4)

{
  long lVar1;
  
  lVar1 = (**(code **)(**(int **)(this + 0x28) + 100))
                    (*(int **)(this + 0x28),param_1,param_2,param_3,param_4);
  return lVar1;
}



void __thiscall
FUN_0040cf3f(void *this,undefined4 param_1,undefined4 param_2,undefined4 param_3,undefined4 param_4,
            undefined4 param_5)

{
  (**(code **)(**(int **)((int)this + 0x28) + 0x68))
            (*(int **)((int)this + 0x28),param_1,param_2,param_3,param_4,param_5);
  return;
}



undefined4 __thiscall FUN_0040cf64(void *this,undefined4 param_1)

{
  *(undefined4 *)((int)this + 0x2c) = param_1;
  return 0;
}



undefined4 FUN_0040cf7f(undefined4 *param_1)

{
  if (param_1 == (undefined4 *)0x0) {
    param_1 = (undefined4 *)func_0xecbbd046();
  }
  *param_1 = 0;
  return 1;
}



undefined4 FUN_0040cf9a(undefined4 param_1,undefined4 *param_2)

{
  if (param_2 == (undefined4 *)0x0) {
    param_2 = (undefined4 *)func_0xecbbd061();
  }
  *param_2 = 0;
  return 1;
}



void FUN_0040cfbb(int *param_1)

{
  (**(code **)(*param_1 + 4))(0);
  return;
}



void FUN_0040cfce(undefined4 *param_1,undefined4 param_2)

{
  (**(code **)*param_1)(param_1,s_R6033___Attempt_to_use_MSIL_code_00428f37 + 0x5d,param_2);
  return;
}



void __thiscall FUN_0040d2de(void *this,undefined4 param_1)

{
  (*DAT_00428370)(*(undefined4 *)((int)this + 4),param_1);
  return;
}



void __thiscall FUN_0040d2f3(void *this,undefined4 param_1)

{
  undefined4 uVar1;
  
  uVar1 = (*DAT_00428378)(*(undefined4 *)((int)this + 4),param_1);
  func_0x5447d4c0(uVar1);
  return;
}



void __thiscall FUN_0040d30e(void *this,undefined4 param_1)

{
  (*DAT_00428308)(*(undefined4 *)((int)this + 0x20),param_1);
  return;
}



// Library Function - Single Match
//  public: void __thiscall CInternalGlobalLock::Lock(int)
// 
// Libraries: Visual Studio 2008 Release, Visual Studio 2010 Release

void __thiscall CInternalGlobalLock::Lock(CInternalGlobalLock *this,int param_1)

{
  int iVar1;
  int iVar2;
  int *extraout_ECX;
  int unaff_ESI;
  
  iVar2 = 0x7fffffff;
  iVar1 = unaff_ESI;
  if (param_1 == 0x7fffffff) goto LAB_0040d374;
  if (*(int *)this == 0x7fffffff) goto LAB_0040d372;
  if (*(int *)this == param_1) goto LAB_0040d372;
  do {
    iVar2 = func_0xecbbd428();
    this = (CInternalGlobalLock *)extraout_ECX;
LAB_0040d372:
    *(int *)this = param_1;
    iVar1 = unaff_ESI;
LAB_0040d374:
    param_1 = iVar1;
    unaff_ESI = param_1;
  } while (*(int *)this == iVar2);
  func_0xa5c2d437(*(int *)this);
  return;
}



void FUN_0040d3a1(undefined4 param_1,undefined4 param_2)

{
  undefined4 *puVar1;
  
  puVar1 = (undefined4 *)func_0xc4d9d467(param_1);
  *puVar1 = param_2;
  return;
}



void FUN_0040d3ff(undefined4 param_1,undefined4 param_2,undefined4 *param_3)

{
  undefined4 uVar1;
  
  func_0x0603d4c5(param_2);
  uVar1 = func_0xbe3fd4cd();
  *param_3 = uVar1;
  return;
}



void __thiscall FUN_0040d420(void *this,int param_1)

{
  if (param_1 != 0) {
    param_1 = *(int *)(param_1 + 4);
  }
  (*DAT_004282c4)(*(undefined4 *)((int)this + 0x20),param_1);
  return;
}



// Library Function - Multiple Matches With Same Base Name
//  public: virtual int __thiscall CWnd::CreateEx(unsigned long,char const *,char const *,unsigned
// long,struct tagRECT const &,class CWnd *,unsigned int,void *)
//  public: virtual int __thiscall CWnd::CreateEx(unsigned long,wchar_t const *,wchar_t const
// *,unsigned long,struct tagRECT const &,class CWnd *,unsigned int,void *)
// 
// Libraries: Visual Studio 2008 Release, Visual Studio 2010 Release

void __thiscall
CreateEx(void *this,undefined4 param_1,undefined4 param_2,undefined4 param_3,undefined4 param_4,
        int *param_5,int param_6,undefined4 param_7,undefined4 param_8)

{
  undefined4 uVar1;
  
  if (param_6 == 0) {
    uVar1 = 0;
  }
  else {
    uVar1 = *(undefined4 *)(param_6 + 0x20);
  }
                    // WARNING: Load size is inaccurate
  (**(code **)(*this + 0x5c))
            (param_1,param_2,param_3,param_4,*param_5,param_5[1],param_5[2] - *param_5,
             param_5[3] - param_5[1],uVar1,param_7,param_8);
  return;
}



// Library Function - Multiple Matches With Same Base Name
//  public: virtual int __thiscall CWnd::Create(char const *,char const *,unsigned long,struct
// tagRECT const &,class CWnd *,unsigned int,struct CCreateContext *)
//  public: virtual int __thiscall CWnd::Create(wchar_t const *,wchar_t const *,unsigned long,struct
// tagRECT const &,class CWnd *,unsigned int,struct CCreateContext *)
// 
// Libraries: Visual Studio 2008 Release, Visual Studio 2010 Release

void __thiscall
Create(void *this,undefined4 param_1,undefined4 param_2,uint param_3,int *param_4,int param_5,
      undefined4 param_6,undefined4 param_7)

{
  undefined4 uVar1;
  
  if (param_5 == 0) {
    uVar1 = 0;
  }
  else {
    uVar1 = *(undefined4 *)(param_5 + 0x20);
  }
                    // WARNING: Load size is inaccurate
  (**(code **)(*this + 0x5c))
            (0,param_1,param_2,param_3 | 0x40000000,*param_4,param_4[1],param_4[2] - *param_4,
             param_4[3] - param_4[1],uVar1,param_6,param_7);
  return;
}



// Library Function - Single Match
//  public: static void __stdcall CWnd::CancelToolTips(int)
// 
// Library: Visual Studio 2008 Release

void CWnd::CancelToolTips(int param_1)

{
  int iVar1;
  int *piVar2;
  short sVar3;
  int iVar4;
  
  iVar4 = func_0x8cd0d599();
  if ((*(int *)(iVar4 + 0x3c) != 0) && (iVar1 = *(int *)(*(int *)(iVar4 + 0x3c) + 0x20), iVar1 != 0)
     ) {
    (*DAT_00428380)(iVar1,0x401,0,0);
  }
  piVar2 = *(int **)(iVar4 + 0x50);
  if ((param_1 != 0) && (piVar2 != (int *)0x0)) {
    sVar3 = (*DAT_00428350)(1);
    if (-1 < sVar3) {
      (**(code **)(*piVar2 + 0x178))(0xffffffff);
    }
  }
  return;
}



// Library Function - Single Match
//  class CMenu * __stdcall _AfxFindPopupMenuFromID(class CMenu *,unsigned int)
// 
// Library: Visual Studio 2008 Release

CMenu * _AfxFindPopupMenuFromID(CMenu *param_1,uint param_2)

{
  int iVar1;
  int iVar2;
  CMenu *pCVar3;
  uint uVar4;
  int iVar5;
  
  if (param_1 == (CMenu *)0x0) {
    func_0xecbbd5f8();
  }
  iVar1 = (*DAT_00428374)(*(undefined4 *)(param_1 + 4));
  iVar5 = 0;
  if (0 < iVar1) {
    do {
      iVar2 = func_0xeb02d615(iVar5);
      if (iVar2 == 0) {
        uVar4 = func_0xd602d633(iVar5);
        if (uVar4 == param_2) goto LAB_0040d590;
      }
      else {
        if (*(uint *)(iVar2 + 4) == param_2) {
LAB_0040d590:
          pCVar3 = (CMenu *)func_0x6847d74e(*(undefined4 *)(param_1 + 4));
          return pCVar3;
        }
        pCVar3 = (CMenu *)func_0x2605d625(iVar2,param_2);
        if (pCVar3 != (CMenu *)0x0) {
          return pCVar3;
        }
      }
      iVar5 = iVar5 + 1;
    } while (iVar5 < iVar1);
  }
  return (CMenu *)0x0;
}



// Library Function - Single Match
//  public: virtual void __thiscall CWnd::WinHelpInternal(unsigned long,unsigned int)
// 
// Library: Visual Studio 2008 Release

void __thiscall CWnd::WinHelpInternal(CWnd *this,ulong param_1,uint param_2)

{
  int iVar1;
  
  iVar1 = func_0x59d0d65d();
  if (*(int *)(*(int *)(iVar1 + 4) + 0x6c) == 1) {
    if (param_2 == 1) {
      param_2 = 0xf;
    }
    else if (param_2 == 3) {
      param_2 = 1;
    }
    else if (param_2 == 0xb) {
      param_2 = 0;
    }
    (**(code **)(*(int *)this + 0x80))(param_1,param_2);
  }
  else {
    (**(code **)(*(int *)this + 0x7c))(param_1,param_2);
  }
  return;
}



// Library Function - Single Match
//  protected: long __thiscall CWnd::OnActivateTopLevel(unsigned int,long)
// 
// Libraries: Visual Studio 2008 Release, Visual Studio 2010 Release, Visual Studio 2012 Release,
// Visual Studio 2015 Release

long __thiscall CWnd::OnActivateTopLevel(CWnd *this,uint param_1,long param_2)

{
  int iVar1;
  
  if ((short)param_1 == 0) {
    iVar1 = func_0x8cd0d6b7();
    if ((*(int *)(iVar1 + 0x48) != 0) && ((*(uint *)(*(int *)(iVar1 + 0x48) + 4) & 0x40000000) == 0)
       ) {
      func_0xd004d6ce(1);
    }
  }
  return 0;
}



// Library Function - Single Match
//  public: virtual long __stdcall CWnd::XAccessibleServer::GetHWND(struct HWND__ * *)
// 
// Libraries: Visual Studio 2005 Release, Visual Studio 2008 Release

long CWnd::XAccessibleServer::GetHWND(HWND__ **param_1)

{
  long lVar1;
  HWND__ **in_stack_00000008;
  undefined4 local_c;
  int local_8;
  
  if (in_stack_00000008 == (HWND__ **)0x0) {
    lVar1 = -0x7fffbffd;
  }
  else {
    AFX_MAINTAIN_STATE2::AFX_MAINTAIN_STATE2
              ((AFX_MAINTAIN_STATE2 *)&local_c,(AFX_MODULE_STATE *)param_1[-6]);
    *in_stack_00000008 = param_1[-5];
    if (local_8 != 0) {
      func_0x6dc3e0ad(0,local_c);
    }
    lVar1 = 0;
  }
  return lVar1;
}



// Library Function - Single Match
//  public: void __thiscall CWnd::CenterWindow(class CWnd *)
// 
// Library: Visual Studio 2008 Release

void __thiscall CWnd::CenterWindow(CWnd *this,CWnd *param_1)

{
  code *pcVar1;
  uint uVar2;
  undefined4 uVar3;
  int iVar4;
  int iVar5;
  undefined4 local_64 [5];
  undefined local_50 [20];
  int local_3c;
  int local_38;
  int local_34;
  int local_30;
  int local_2c;
  int local_28;
  int local_24;
  int local_20;
  int local_1c;
  int local_18;
  int local_14;
  int local_10;
  CWnd *local_c;
  uint local_8;
  
  local_c = this;
  local_8 = func_0xbe3fe0d5();
  if (param_1 == (CWnd *)0x0) {
    if ((local_8 & 0x40000000) == 0) {
      iVar5 = (*DAT_0042830c)(*(undefined4 *)(this + 0x20),4);
    }
    else {
      iVar5 = (*DAT_00428384)(*(undefined4 *)(this + 0x20));
    }
    if (iVar5 != 0) {
      iVar4 = (*DAT_00428380)(iVar5,0x36b,0,0);
      if (iVar4 != 0) {
        iVar5 = iVar4;
      }
    }
  }
  else {
    iVar5 = *(int *)(param_1 + 0x20);
  }
  pcVar1 = DAT_00428308;
  (*DAT_00428308)(*(undefined4 *)(this + 0x20),&local_3c);
  if ((local_8 & 0x40000000) == 0) {
    if (iVar5 != 0) {
      uVar2 = (*DAT_004283b4)(iVar5,0xfffffff0);
      if (((uVar2 & 0x10000000) == 0) || ((uVar2 & 0x20000000) != 0)) {
        iVar5 = 0;
      }
    }
    local_64[0] = 0x28;
    if (iVar5 == 0) {
      iVar5 = func_0x80d1e169();
      if (iVar5 != 0) {
        iVar5 = *(int *)(iVar5 + 0x20);
      }
      uVar3 = func_0x46f2e17c(iVar5,1,local_64);
      func_0xb3f2e182(uVar3);
      pcVar1 = DAT_004282e8;
      (*DAT_004282e8)(&local_2c,local_50);
      (*pcVar1)(&local_1c,local_50);
    }
    else {
      (*pcVar1)(iVar5,&local_2c);
      uVar3 = func_0x46f2e1b1(iVar5,2,local_64);
      func_0xb3f2e1b7(uVar3);
      (*DAT_004282e8)(&local_1c,local_50);
    }
  }
  else {
    uVar3 = (*DAT_00428384)(*(undefined4 *)(this + 0x20));
    pcVar1 = DAT_004282c8;
    (*DAT_004282c8)(uVar3,&local_1c);
    (*pcVar1)(iVar5,&local_2c);
    (*DAT_004282c0)(iVar5,uVar3,&local_2c,2);
  }
  iVar5 = (local_2c + local_24) / 2 - (local_34 - local_3c) / 2;
  iVar4 = (local_28 + local_20) / 2 - (local_30 - local_38) / 2;
  if (local_14 < (local_34 - local_3c) + iVar5) {
    iVar5 = (local_3c - local_34) + local_14;
  }
  if (iVar5 < local_1c) {
    iVar5 = local_1c;
  }
  if (local_10 < (local_30 - local_38) + iVar4) {
    iVar4 = (local_38 - local_30) + local_10;
  }
  if (iVar4 < local_18) {
    iVar4 = local_18;
  }
  func_0x3340e37b(0,iVar5,iVar4,0xffffffff,0xffffffff,0x15);
  return;
}



// Library Function - Single Match
//  public: virtual void __thiscall CWnd::EndModalLoop(int)
// 
// Library: Visual Studio 2008 Release

void __thiscall CWnd::EndModalLoop(CWnd *this,int param_1)

{
  *(int *)(this + 0x44) = param_1;
  if ((*(uint *)(this + 0x3c) & 0x10) != 0) {
    *(uint *)(this + 0x3c) = *(uint *)(this + 0x3c) & 0xffffffef;
    (*DAT_004282cc)(*(undefined4 *)(this + 0x20),0,0,0);
  }
  return;
}



void __thiscall FUN_0040e27d(void *this,undefined4 *param_1)

{
  undefined4 uVar1;
  
  if (*(int *)((int)this + 0x10) == 0) {
    uVar1 = func_0x4112e34b(s_R6033___Attempt_to_use_MSIL_code_00428f37 + 0x6d);
    uVar1 = (*(code *)u_f__dd_vctools_vc7libs_ship_atlmf_0042815f._5_4_)(uVar1);
    *(undefined4 *)((int)this + 0x10) = uVar1;
  }
  *param_1 = *(undefined4 *)((int)this + 0x10);
  return;
}



void __thiscall FUN_0040e320(void *this,undefined4 *param_1)

{
  undefined4 uVar1;
  
  if (*(int *)((int)this + 0x14) == 0) {
    uVar1 = func_0x4112e3ee(s_R6033___Attempt_to_use_MSIL_code_00428f37 + 0x81);
    uVar1 = (*(code *)u_f__dd_vctools_vc7libs_ship_atlmf_0042815f._5_4_)(uVar1);
    *(undefined4 *)((int)this + 0x14) = uVar1;
  }
  *param_1 = *(undefined4 *)((int)this + 0x14);
  return;
}



void FUN_0040e3fa(undefined4 param_1)

{
  func_0x59d0e4bd(param_1);
  func_0x4713e4c7();
  return;
}



// Library Function - Single Match
//  public: static class CWnd * __stdcall CWnd::FromHandle(struct HWND__ *)
// 
// Libraries: Visual Studio 2008 Release, Visual Studio 2010 Release

CWnd * CWnd::FromHandle(HWND__ *param_1)

{
  undefined4 uVar1;
  CWnd *pCVar2;
  
  uVar1 = func_0x8214e5c2(1);
  pCVar2 = (CWnd *)func_0x0befe5ce(param_1);
  func_0x7140e6d8(uVar1);
  return pCVar2;
}



// WARNING: Control flow encountered bad instruction data

undefined4 FUN_0040e52a(void)

{
  int iVar1;
  
  iVar1 = func_0x8214e5ec(0);
  if (iVar1 != 0) {
                    // WARNING: Bad instruction - Truncating control flow here
    halt_baddata();
  }
  return 0;
}



// Library Function - Single Match
//  public: int __thiscall CWnd::Attach(struct HWND__ *)
// 
// Library: Visual Studio 2008 Release

int __thiscall CWnd::Attach(CWnd *this,HWND__ *param_1)

{
  undefined4 uVar1;
  
  if (param_1 != (HWND__ *)0x0) {
    uVar1 = func_0x8214e61d(1);
    *(HWND__ **)(this + 0x20) = param_1;
    func_0x9903e62b(param_1,this);
    func_0x7140e733(uVar1);
  }
  return (uint)(param_1 != (HWND__ *)0x0);
}



// Library Function - Single Match
//  protected: void __thiscall CWnd::OnNcDestroy(void)
// 
// Library: Visual Studio 2008 Release

void __thiscall CWnd::OnNcDestroy(CWnd *this)

{
  code *pcVar1;
  int iVar2;
  int iVar3;
  int *piVar4;
  undefined4 local_34;
  undefined4 local_30;
  undefined4 local_2c;
  undefined4 local_28;
  
  iVar2 = func_0x79dbe709();
  if (iVar2 == 0) goto LAB_0040e68e;
  if (*(CWnd **)(iVar2 + 0x20) == this) {
    iVar3 = func_0x59d0e71b();
    if (*(char *)(iVar3 + 0x14) == '\0') {
      iVar3 = func_0x59d0e725();
      if (iVar2 == *(int *)(iVar3 + 4)) {
        iVar3 = func_0xa050e82f();
        if (iVar3 == 0) goto LAB_0040e683;
      }
      func_0xdd4fe839(0);
    }
LAB_0040e683:
    *(undefined4 *)(iVar2 + 0x20) = 0;
  }
  if (*(CWnd **)(iVar2 + 0x24) == this) {
    *(undefined4 *)(iVar2 + 0x24) = 0;
  }
LAB_0040e68e:
  if (*(int **)(this + 0x48) != (int *)0x0) {
    (**(code **)(**(int **)(this + 0x48) + 0x50))();
    *(undefined4 *)(this + 0x48) = 0;
  }
  if (*(int **)(this + 0x4c) != (int *)0x0) {
    (**(code **)(**(int **)(this + 0x4c) + 4))(1);
  }
  *(undefined4 *)(this + 0x4c) = 0;
  if (((byte)this[0x3c] & 1) != 0) {
    iVar2 = func_0x8cd0e771();
    iVar2 = *(int *)(iVar2 + 0x3c);
    if ((iVar2 != 0) && (*(int *)(iVar2 + 0x20) != 0)) {
      func_0x3b82e88b(&local_34,0,0x30);
      local_2c = *(undefined4 *)(this + 0x20);
      local_34 = 0x2c;
      local_30 = 1;
      local_28 = local_2c;
      (*DAT_00428380)(*(undefined4 *)(iVar2 + 0x20),0x433,0,&local_34);
    }
  }
  pcVar1 = DAT_004283b4;
  iVar2 = (*DAT_004283b4)(*(undefined4 *)(this + 0x20),0xfffffffc);
  func_0x5014e7cc();
  iVar3 = (*pcVar1)(*(undefined4 *)(this + 0x20),0xfffffffc);
  if (iVar3 == iVar2) {
    piVar4 = (int *)(**(code **)(*(int *)this + 0xf8))();
    if (*piVar4 != 0) {
      (*DAT_004282f4)(*(undefined4 *)(this + 0x20),0xfffffffc,*piVar4);
    }
  }
  func_0x7f15e7fb();
  (**(code **)(*(int *)this + 0x11c))();
  return;
}



// Library Function - Single Match
//  protected: long __thiscall CWnd::OnNTCtlColor(unsigned int,long)
// 
// Libraries: Visual Studio 2005 Release, Visual Studio 2008 Release, Visual Studio 2010 Release

long __thiscall CWnd::OnNTCtlColor(CWnd *this,uint param_1,long param_2)

{
  int iVar1;
  long lVar2;
  long local_10;
  uint local_c;
  int local_8;
  
  local_c = param_1;
  local_10 = param_2;
  iVar1 = func_0xd7c1e88f(0x408c0d);
  if (iVar1 == 0) {
    iVar1 = func_0xecbbe898();
  }
  local_8 = *(int *)(iVar1 + 0x5c) + -0x132;
  lVar2 = (**(code **)(*(int *)this + 0x110))(0x19,0,&local_10);
  return lVar2;
}



// Library Function - Single Match
//  public: static class CWnd * __stdcall CWnd::GetDescendantWindow(struct HWND__ *,int,int)
// 
// Libraries: Visual Studio 2003 Release, Visual Studio 2005 Release, Visual Studio 2008 Release,
// Visual Studio 2010 Release

CWnd * CWnd::GetDescendantWindow(HWND__ *param_1,int param_2,int param_3)

{
  code *pcVar1;
  int iVar2;
  int iVar3;
  CWnd *pCVar4;
  
  iVar2 = (*DAT_004282ac)(param_1,param_2);
  pcVar1 = DAT_004282b0;
  if (iVar2 != 0) {
    iVar3 = (*DAT_004282b0)(iVar2);
    if ((iVar3 != 0) &&
       (pCVar4 = (CWnd *)func_0xfc17e8ec(iVar2,param_2,param_3), pCVar4 != (CWnd *)0x0)) {
      return pCVar4;
    }
    if (param_3 == 0) {
      pCVar4 = (CWnd *)func_0xf614e8fc();
      return pCVar4;
    }
    pCVar4 = (CWnd *)func_0x2215e903(iVar2);
    if (pCVar4 != (CWnd *)0x0) {
      return pCVar4;
    }
  }
  iVar2 = (*pcVar1)(param_1);
  while( true ) {
    if (iVar2 == 0) {
      return (CWnd *)0x0;
    }
    pCVar4 = (CWnd *)func_0xfc17e91a(iVar2,param_2,param_3);
    if (pCVar4 != (CWnd *)0x0) break;
    iVar2 = (*DAT_0042830c)(iVar2,2);
  }
  return pCVar4;
}



// Library Function - Single Match
//  public: int __thiscall CWnd::SendChildNotifyLastMsg(long *)
// 
// Libraries: Visual Studio 2008 Release, Visual Studio 2010 Release

int __thiscall CWnd::SendChildNotifyLastMsg(CWnd *this,long *param_1)

{
  int iVar1;
  
  iVar1 = func_0xd7c1e94a(0x408c0d);
  if (iVar1 == 0) {
    iVar1 = func_0xecbbe953();
  }
  iVar1 = (**(code **)(*(int *)this + 0x120))
                    (*(undefined4 *)(iVar1 + 0x5c),*(undefined4 *)(iVar1 + 0x60),
                     *(undefined4 *)(iVar1 + 100),param_1);
  return iVar1;
}



// Library Function - Single Match
//  protected: long __thiscall CWnd::OnGetObject(unsigned int,long)
// 
// Library: Visual Studio 2008 Release

long __thiscall CWnd::OnGetObject(CWnd *this,uint param_1,long param_2)

{
  long lVar1;
  int iVar2;
  CWnd *local_8;
  
  local_8 = this;
  if (this[0x24] != (CWnd)0x0) {
    local_8 = (CWnd *)0x0;
    iVar2 = (**(code **)(*(int *)this + 0xec))(param_1,param_2,&local_8);
    if (-1 < iVar2) {
      return (long)local_8;
    }
  }
  lVar1 = func_0x5014ea13();
  return lVar1;
}



void FUN_0040e987(undefined4 param_1,undefined4 param_2,int param_3)

{
  int iVar1;
  
  if ((param_3 != 0) && (iVar1 = func_0x7518ea53(0), iVar1 != 0)) {
    return;
  }
  func_0x5014ea5e();
  return;
}



// Library Function - Single Match
//  protected: void __thiscall CWnd::OnEnterIdle(unsigned int,class CWnd *)
// 
// Libraries: Visual Studio 2005 Release, Visual Studio 2008 Release, Visual Studio 2010 Release

void __thiscall CWnd::OnEnterIdle(CWnd *this,uint param_1,CWnd *param_2)

{
  code *pcVar1;
  int iVar2;
  undefined local_20 [28];
  
  pcVar1 = DAT_00428354;
  while( true ) {
    iVar2 = (*pcVar1)(local_20,0,0x121,0x121,1);
    if (iVar2 == 0) break;
    (*DAT_0042834c)(local_20);
  }
  func_0x5014ea9e();
  return;
}



// Library Function - Single Match
//  protected: struct HBRUSH__ * __thiscall CWnd::OnCtlColor(class CDC *,class CWnd *,unsigned int)
// 
// Libraries: Visual Studio 2003 Release, Visual Studio 2005 Release, Visual Studio 2008 Release,
// Visual Studio 2010 Release

HBRUSH__ * __thiscall CWnd::OnCtlColor(CWnd *this,CDC *param_1,CWnd *param_2,uint param_3)

{
  int iVar1;
  
  iVar1 = func_0x7518eab9(&param_2);
  if (iVar1 == 0) {
    param_2 = (CWnd *)func_0x5014eac9();
  }
  return (HBRUSH__ *)param_2;
}



// Library Function - Single Match
//  long __stdcall _AfxInitCommonControls(struct tagINITCOMMONCONTROLSEX *,long)
// 
// Libraries: Visual Studio 2005 Release, Visual Studio 2008 Release

long _AfxInitCommonControls(tagINITCOMMONCONTROLSEX *param_1,long param_2)

{
  int *piVar1;
  int iVar2;
  long lVar3;
  undefined local_8 [4];
  
  lVar3 = 0;
  func_0x59d0eae0(local_8);
  piVar1 = (int *)func_0x1813eaea();
  if (*piVar1 == 0) {
    if ((param_2 & 0x3fc0U) == param_2) {
      func_0x59d0eb11();
      func_0xa412eb1b();
      lVar3 = 0x3fc0;
    }
  }
  else {
    iVar2 = func_0xf213eaf6(param_1);
    if (iVar2 != 0) {
      lVar3 = param_2;
    }
  }
  return lVar3;
}



// Library Function - Single Match
//  public: virtual long __stdcall ATL::IAccessibleProxyImpl<class
// ATL::CAccessibleProxy>::get_accParent(struct IDispatch * *)
// 
// Libraries: Visual Studio 2008 Release, Visual Studio 2010 Release

long ATL::IAccessibleProxyImpl<class_ATL::CAccessibleProxy>::get_accParent(IDispatch **param_1)

{
  long lVar1;
  int in_stack_00000008;
  
  if (param_1[2] == (IDispatch *)0x0) {
    lVar1 = -0x7ffefef8;
  }
  else if (in_stack_00000008 == 0) {
    lVar1 = -0x7fffbffd;
  }
  else {
    lVar1 = (**(code **)(*(int *)param_1[2] + 0x1c))(param_1[2]);
  }
  return lVar1;
}



// Library Function - Single Match
//  public: virtual long __stdcall ATL::IAccessibleProxyImpl<class
// ATL::CAccessibleProxy>::get_accChildCount(long *)
// 
// Libraries: Visual Studio 2008 Release, Visual Studio 2010 Release

long ATL::IAccessibleProxyImpl<class_ATL::CAccessibleProxy>::get_accChildCount(long *param_1)

{
  long lVar1;
  int in_stack_00000008;
  
  if (param_1[2] == 0) {
    lVar1 = -0x7ffefef8;
  }
  else if (in_stack_00000008 == 0) {
    lVar1 = -0x7fffbffd;
  }
  else {
    lVar1 = (**(code **)(*(int *)param_1[2] + 0x20))((int *)param_1[2]);
  }
  return lVar1;
}



// Library Function - Single Match
//  public: virtual long __stdcall ATL::IAccessibleProxyImpl<class
// ATL::CAccessibleProxy>::get_accChild(struct tagVARIANT,struct IDispatch * *)
// 
// Libraries: Visual Studio 2008 Release, Visual Studio 2010 Release

undefined4
ATL::IAccessibleProxyImpl<class_ATL::CAccessibleProxy>::get_accChild
          (int param_1,undefined4 param_2,undefined4 param_3,undefined4 param_4,undefined4 param_5,
          int param_6)

{
  int *piVar1;
  undefined4 uVar2;
  
  piVar1 = *(int **)(param_1 + 8);
  if (piVar1 == (int *)0x0) {
    uVar2 = 0x80010108;
  }
  else if (param_6 == 0) {
    uVar2 = 0x80004003;
  }
  else {
    uVar2 = (**(code **)(*piVar1 + 0x24))(piVar1,param_2,param_3,param_4,param_5,param_6);
  }
  return uVar2;
}



// Library Function - Single Match
//  public: virtual long __stdcall ATL::IAccessibleProxyImpl<class
// ATL::CAccessibleProxy>::get_accName(struct tagVARIANT,wchar_t * *)
// 
// Libraries: Visual Studio 2008 Release, Visual Studio 2010 Release

undefined4
ATL::IAccessibleProxyImpl<class_ATL::CAccessibleProxy>::get_accName
          (int param_1,undefined4 param_2,undefined4 param_3,undefined4 param_4,undefined4 param_5,
          int param_6)

{
  int *piVar1;
  undefined4 uVar2;
  
  piVar1 = *(int **)(param_1 + 8);
  if (piVar1 == (int *)0x0) {
    uVar2 = 0x80010108;
  }
  else if (param_6 == 0) {
    uVar2 = 0x80004003;
  }
  else {
    uVar2 = (**(code **)(*piVar1 + 0x28))(piVar1,param_2,param_3,param_4,param_5,param_6);
  }
  return uVar2;
}



// Library Function - Single Match
//  public: virtual long __stdcall ATL::IAccessibleProxyImpl<class
// ATL::CAccessibleProxy>::get_accValue(struct tagVARIANT,wchar_t * *)
// 
// Libraries: Visual Studio 2008 Release, Visual Studio 2010 Release

undefined4
ATL::IAccessibleProxyImpl<class_ATL::CAccessibleProxy>::get_accValue
          (int param_1,undefined4 param_2,undefined4 param_3,undefined4 param_4,undefined4 param_5,
          int param_6)

{
  int *piVar1;
  undefined4 uVar2;
  
  piVar1 = *(int **)(param_1 + 8);
  if (piVar1 == (int *)0x0) {
    uVar2 = 0x80010108;
  }
  else if (param_6 == 0) {
    uVar2 = 0x80004003;
  }
  else {
    uVar2 = (**(code **)(*piVar1 + 0x2c))(piVar1,param_2,param_3,param_4,param_5,param_6);
  }
  return uVar2;
}



// Library Function - Single Match
//  public: virtual long __stdcall ATL::IAccessibleProxyImpl<class
// ATL::CAccessibleProxy>::get_accDescription(struct tagVARIANT,wchar_t * *)
// 
// Libraries: Visual Studio 2008 Release, Visual Studio 2010 Release

undefined4
ATL::IAccessibleProxyImpl<class_ATL::CAccessibleProxy>::get_accDescription
          (int param_1,undefined4 param_2,undefined4 param_3,undefined4 param_4,undefined4 param_5,
          int param_6)

{
  int *piVar1;
  undefined4 uVar2;
  
  piVar1 = *(int **)(param_1 + 8);
  if (piVar1 == (int *)0x0) {
    uVar2 = 0x80010108;
  }
  else if (param_6 == 0) {
    uVar2 = 0x80004003;
  }
  else {
    uVar2 = (**(code **)(*piVar1 + 0x30))(piVar1,param_2,param_3,param_4,param_5,param_6);
  }
  return uVar2;
}



// Library Function - Single Match
//  public: virtual long __stdcall ATL::IAccessibleProxyImpl<class
// ATL::CAccessibleProxy>::get_accRole(struct tagVARIANT,struct tagVARIANT *)
// 
// Libraries: Visual Studio 2008 Release, Visual Studio 2010 Release

undefined4
ATL::IAccessibleProxyImpl<class_ATL::CAccessibleProxy>::get_accRole
          (int param_1,undefined4 param_2,undefined4 param_3,undefined4 param_4,undefined4 param_5,
          int param_6)

{
  int *piVar1;
  undefined4 uVar2;
  
  piVar1 = *(int **)(param_1 + 8);
  if (piVar1 == (int *)0x0) {
    uVar2 = 0x80010108;
  }
  else if (param_6 == 0) {
    uVar2 = 0x80004003;
  }
  else {
    uVar2 = (**(code **)(*piVar1 + 0x34))(piVar1,param_2,param_3,param_4,param_5,param_6);
  }
  return uVar2;
}



// Library Function - Single Match
//  public: virtual long __stdcall ATL::IAccessibleProxyImpl<class
// ATL::CAccessibleProxy>::get_accState(struct tagVARIANT,struct tagVARIANT *)
// 
// Libraries: Visual Studio 2008 Release, Visual Studio 2010 Release

undefined4
ATL::IAccessibleProxyImpl<class_ATL::CAccessibleProxy>::get_accState
          (int param_1,undefined4 param_2,undefined4 param_3,undefined4 param_4,undefined4 param_5,
          int param_6)

{
  int *piVar1;
  undefined4 uVar2;
  
  piVar1 = *(int **)(param_1 + 8);
  if (piVar1 == (int *)0x0) {
    uVar2 = 0x80010108;
  }
  else if (param_6 == 0) {
    uVar2 = 0x80004003;
  }
  else {
    uVar2 = (**(code **)(*piVar1 + 0x38))(piVar1,param_2,param_3,param_4,param_5,param_6);
  }
  return uVar2;
}



// Library Function - Single Match
//  public: virtual long __stdcall ATL::IAccessibleProxyImpl<class
// ATL::CAccessibleProxy>::get_accHelp(struct tagVARIANT,wchar_t * *)
// 
// Libraries: Visual Studio 2008 Release, Visual Studio 2010 Release

undefined4
ATL::IAccessibleProxyImpl<class_ATL::CAccessibleProxy>::get_accHelp
          (int param_1,undefined4 param_2,undefined4 param_3,undefined4 param_4,undefined4 param_5,
          int param_6)

{
  int *piVar1;
  undefined4 uVar2;
  
  piVar1 = *(int **)(param_1 + 8);
  if (piVar1 == (int *)0x0) {
    uVar2 = 0x80010108;
  }
  else if (param_6 == 0) {
    uVar2 = 0x80004003;
  }
  else {
    uVar2 = (**(code **)(*piVar1 + 0x3c))(piVar1,param_2,param_3,param_4,param_5,param_6);
  }
  return uVar2;
}



// Library Function - Single Match
//  public: virtual long __stdcall ATL::IAccessibleProxyImpl<class
// ATL::CAccessibleProxy>::get_accHelpTopic(wchar_t * *,struct tagVARIANT,long *)
// 
// Libraries: Visual Studio 2008 Release, Visual Studio 2010 Release

undefined4
ATL::IAccessibleProxyImpl<class_ATL::CAccessibleProxy>::get_accHelpTopic
          (int param_1,int param_2,undefined4 param_3,undefined4 param_4,undefined4 param_5,
          undefined4 param_6,int param_7)

{
  int *piVar1;
  undefined4 uVar2;
  
  piVar1 = *(int **)(param_1 + 8);
  if (piVar1 == (int *)0x0) {
    uVar2 = 0x80010108;
  }
  else if ((param_2 == 0) || (param_7 == 0)) {
    uVar2 = 0x80004003;
  }
  else {
    uVar2 = (**(code **)(*piVar1 + 0x40))(piVar1,param_2,param_3,param_4,param_5,param_6,param_7);
  }
  return uVar2;
}



// Library Function - Single Match
//  public: virtual long __stdcall ATL::IAccessibleProxyImpl<class
// ATL::CAccessibleProxy>::get_accKeyboardShortcut(struct tagVARIANT,wchar_t * *)
// 
// Libraries: Visual Studio 2008 Release, Visual Studio 2010 Release

undefined4
ATL::IAccessibleProxyImpl<class_ATL::CAccessibleProxy>::get_accKeyboardShortcut
          (int param_1,undefined4 param_2,undefined4 param_3,undefined4 param_4,undefined4 param_5,
          int param_6)

{
  int *piVar1;
  undefined4 uVar2;
  
  piVar1 = *(int **)(param_1 + 8);
  if (piVar1 == (int *)0x0) {
    uVar2 = 0x80010108;
  }
  else if (param_6 == 0) {
    uVar2 = 0x80004003;
  }
  else {
    uVar2 = (**(code **)(*piVar1 + 0x44))(piVar1,param_2,param_3,param_4,param_5,param_6);
  }
  return uVar2;
}



// Library Function - Single Match
//  public: virtual long __stdcall ATL::IAccessibleProxyImpl<class
// ATL::CAccessibleProxy>::get_accFocus(struct tagVARIANT *)
// 
// Libraries: Visual Studio 2008 Release, Visual Studio 2010 Release

long ATL::IAccessibleProxyImpl<class_ATL::CAccessibleProxy>::get_accFocus(tagVARIANT *param_1)

{
  long lVar1;
  int in_stack_00000008;
  
  if (*(int *)(param_1 + 8) == 0) {
    lVar1 = -0x7ffefef8;
  }
  else if (in_stack_00000008 == 0) {
    lVar1 = -0x7fffbffd;
  }
  else {
    lVar1 = (**(code **)(**(int **)(param_1 + 8) + 0x48))(*(int **)(param_1 + 8));
  }
  return lVar1;
}



// Library Function - Single Match
//  public: virtual long __stdcall ATL::IAccessibleProxyImpl<class
// ATL::CAccessibleProxy>::get_accSelection(struct tagVARIANT *)
// 
// Libraries: Visual Studio 2008 Release, Visual Studio 2010 Release

long ATL::IAccessibleProxyImpl<class_ATL::CAccessibleProxy>::get_accSelection(tagVARIANT *param_1)

{
  long lVar1;
  int in_stack_00000008;
  
  if (*(int *)(param_1 + 8) == 0) {
    lVar1 = -0x7ffefef8;
  }
  else if (in_stack_00000008 == 0) {
    lVar1 = -0x7fffbffd;
  }
  else {
    lVar1 = (**(code **)(**(int **)(param_1 + 8) + 0x4c))(*(int **)(param_1 + 8));
  }
  return lVar1;
}



// Library Function - Single Match
//  public: virtual long __stdcall ATL::IAccessibleProxyImpl<class
// ATL::CAccessibleProxy>::get_accDefaultAction(struct tagVARIANT,wchar_t * *)
// 
// Libraries: Visual Studio 2008 Release, Visual Studio 2010 Release

undefined4
ATL::IAccessibleProxyImpl<class_ATL::CAccessibleProxy>::get_accDefaultAction
          (int param_1,undefined4 param_2,undefined4 param_3,undefined4 param_4,undefined4 param_5,
          int param_6)

{
  int *piVar1;
  undefined4 uVar2;
  
  piVar1 = *(int **)(param_1 + 8);
  if (piVar1 == (int *)0x0) {
    uVar2 = 0x80010108;
  }
  else if (param_6 == 0) {
    uVar2 = 0x80004003;
  }
  else {
    uVar2 = (**(code **)(*piVar1 + 0x50))(piVar1,param_2,param_3,param_4,param_5,param_6);
  }
  return uVar2;
}



// Library Function - Single Match
//  public: virtual long __stdcall ATL::IAccessibleProxyImpl<class
// ATL::CAccessibleProxy>::accSelect(long,struct tagVARIANT)
// 
// Libraries: Visual Studio 2008 Release, Visual Studio 2010 Release

undefined4
ATL::IAccessibleProxyImpl<class_ATL::CAccessibleProxy>::accSelect
          (int param_1,undefined4 param_2,undefined4 param_3,undefined4 param_4,undefined4 param_5,
          undefined4 param_6)

{
  int *piVar1;
  undefined4 uVar2;
  
  piVar1 = *(int **)(param_1 + 8);
  if (piVar1 == (int *)0x0) {
    uVar2 = 0x80010108;
  }
  else {
    uVar2 = (**(code **)(*piVar1 + 0x54))(piVar1,param_2,param_3,param_4,param_5,param_6);
  }
  return uVar2;
}



// Library Function - Single Match
//  public: virtual long __stdcall ATL::IAccessibleProxyImpl<class
// ATL::CAccessibleProxy>::accLocation(long *,long *,long *,long *,struct tagVARIANT)
// 
// Libraries: Visual Studio 2008 Release, Visual Studio 2010 Release

undefined4
ATL::IAccessibleProxyImpl<class_ATL::CAccessibleProxy>::accLocation
          (int param_1,int param_2,int param_3,int param_4,int param_5,undefined4 param_6,
          undefined4 param_7,undefined4 param_8,undefined4 param_9)

{
  int *piVar1;
  undefined4 uVar2;
  
  piVar1 = *(int **)(param_1 + 8);
  if (piVar1 == (int *)0x0) {
    uVar2 = 0x80010108;
  }
  else if ((((param_2 == 0) || (param_3 == 0)) || (param_4 == 0)) || (param_5 == 0)) {
    uVar2 = 0x80004003;
  }
  else {
    uVar2 = (**(code **)(*piVar1 + 0x58))
                      (piVar1,param_2,param_3,param_4,param_5,param_6,param_7,param_8,param_9);
  }
  return uVar2;
}



// Library Function - Single Match
//  public: virtual long __stdcall ATL::IAccessibleProxyImpl<class
// ATL::CAccessibleProxy>::accNavigate(long,struct tagVARIANT,struct tagVARIANT *)
// 
// Libraries: Visual Studio 2008 Release, Visual Studio 2010 Release

undefined4
ATL::IAccessibleProxyImpl<class_ATL::CAccessibleProxy>::accNavigate
          (int param_1,undefined4 param_2,undefined4 param_3,undefined4 param_4,undefined4 param_5,
          undefined4 param_6,int param_7)

{
  int *piVar1;
  undefined4 uVar2;
  
  piVar1 = *(int **)(param_1 + 8);
  if (piVar1 == (int *)0x0) {
    uVar2 = 0x80010108;
  }
  else if (param_7 == 0) {
    uVar2 = 0x80004003;
  }
  else {
    uVar2 = (**(code **)(*piVar1 + 0x5c))(piVar1,param_2,param_3,param_4,param_5,param_6,param_7);
  }
  return uVar2;
}



// Library Function - Single Match
//  public: virtual long __stdcall ATL::IAccessibleProxyImpl<class
// ATL::CAccessibleProxy>::accHitTest(long,long,struct tagVARIANT *)
// 
// Libraries: Visual Studio 2003 Release, Visual Studio 2005 Release, Visual Studio 2008 Release,
// Visual Studio 2010 Release

long ATL::IAccessibleProxyImpl<class_ATL::CAccessibleProxy>::accHitTest
               (long param_1,long param_2,tagVARIANT *param_3)

{
  long lVar1;
  int in_stack_00000010;
  
  if (*(int *)(param_1 + 8) == 0) {
    lVar1 = -0x7ffefef8;
  }
  else if (in_stack_00000010 == 0) {
    lVar1 = -0x7fffbffd;
  }
  else {
    lVar1 = (**(code **)(**(int **)(param_1 + 8) + 0x60))(*(int **)(param_1 + 8),param_2,param_3);
  }
  return lVar1;
}



// Library Function - Single Match
//  public: virtual long __stdcall ATL::IAccessibleProxyImpl<class
// ATL::CAccessibleProxy>::accDoDefaultAction(struct tagVARIANT)
// 
// Libraries: Visual Studio 2008 Release, Visual Studio 2010 Release

undefined4
ATL::IAccessibleProxyImpl<class_ATL::CAccessibleProxy>::accDoDefaultAction
          (int param_1,undefined4 param_2,undefined4 param_3,undefined4 param_4,undefined4 param_5)

{
  int *piVar1;
  undefined4 uVar2;
  
  piVar1 = *(int **)(param_1 + 8);
  if (piVar1 == (int *)0x0) {
    uVar2 = 0x80010108;
  }
  else {
    uVar2 = (**(code **)(*piVar1 + 100))(piVar1,param_2,param_3,param_4,param_5);
  }
  return uVar2;
}



int FUN_0040eef9(int param_1)

{
  return (-(uint)(*(int *)(param_1 + 8) != 0) & 0xffff3ef9) + 0x80010108;
}



undefined4 FUN_0040ef16(int param_1,undefined4 param_2,undefined4 param_3)

{
  *(undefined4 *)(param_1 + 4) = param_2;
  *(undefined4 *)(param_1 + 8) = param_3;
  return 0;
}



// Library Function - Single Match
//  public: virtual long __stdcall ATL::IAccessibleProxyImpl<class
// ATL::CAccessibleProxy>::Invoke(long,struct _GUID const &,unsigned long,unsigned short,struct
// tagDISPPARAMS *,struct tagVARIANT *,struct tagEXCEPINFO *,unsigned int *)
// 
// Libraries: Visual Studio 2003 Release, Visual Studio 2005 Release, Visual Studio 2008 Release,
// Visual Studio 2010 Release

long ATL::IAccessibleProxyImpl<class_ATL::CAccessibleProxy>::Invoke
               (long param_1,_GUID *param_2,ulong param_3,ushort param_4,tagDISPPARAMS *param_5,
               tagVARIANT *param_6,tagEXCEPINFO *param_7,uint *param_8)

{
  long lVar1;
  undefined2 in_stack_00000012;
  
  if (*(int *)(param_1 + 8) == 0) {
    lVar1 = -0x7ffefef8;
  }
  else {
    lVar1 = (**(code **)(**(int **)(param_1 + 8) + 0x18))
                      (*(int **)(param_1 + 8),param_2,param_3,_param_4,param_5,param_6,param_7,
                       param_8);
  }
  return lVar1;
}



// Library Function - Single Match
//  public: virtual long __stdcall ATL::IAccessibleProxyImpl<class
// ATL::CAccessibleProxy>::GetIDsOfNames(struct _GUID const &,wchar_t * *,unsigned int,unsigned
// long,long *)
// 
// Libraries: Visual Studio 2003 Release, Visual Studio 2005 Release, Visual Studio 2008 Release,
// Visual Studio 2010 Release

long ATL::IAccessibleProxyImpl<class_ATL::CAccessibleProxy>::GetIDsOfNames
               (_GUID *param_1,wchar_t **param_2,uint param_3,ulong param_4,long *param_5)

{
  long lVar1;
  
  if (*(int *)param_1->Data4 == 0) {
    lVar1 = -0x7ffefef8;
  }
  else {
    lVar1 = (**(code **)(**(int **)param_1->Data4 + 0x14))
                      (*(int **)param_1->Data4,param_2,param_3,param_4,param_5);
  }
  return lVar1;
}



// Library Function - Single Match
//  public: virtual long __stdcall ATL::IAccessibleProxyImpl<class
// ATL::CAccessibleProxy>::GetTypeInfoCount(unsigned int *)
// 
// Libraries: Visual Studio 2008 Release, Visual Studio 2010 Release

long ATL::IAccessibleProxyImpl<class_ATL::CAccessibleProxy>::GetTypeInfoCount(uint *param_1)

{
  long lVar1;
  
  if (param_1[2] == 0) {
    lVar1 = -0x7ffefef8;
  }
  else {
    lVar1 = (**(code **)(*(int *)param_1[2] + 0xc))((int *)param_1[2]);
  }
  return lVar1;
}



undefined4 FUN_0040efc0(int param_1,undefined4 param_2,undefined4 param_3,undefined4 param_4)

{
  undefined4 uVar1;
  
  if (*(int *)(param_1 + 8) == 0) {
    uVar1 = 0x80010108;
  }
  else {
    uVar1 = (**(code **)(**(int **)(param_1 + 8) + 0x10))
                      (*(int **)(param_1 + 8),param_2,param_3,param_4);
  }
  return uVar1;
}



void __thiscall FUN_0040f000(void *this,undefined4 param_1)

{
  undefined4 uVar1;
  
  uVar1 = (*DAT_0042830c)(*(undefined4 *)((int)this + 0x20),param_1);
  func_0xf614f0cd(uVar1);
  return;
}



// Library Function - Single Match
//  void __stdcall _AfxPostInitDialog(class CWnd *,struct tagRECT const &,unsigned long)
// 
// Library: Visual Studio 2008 Release

void _AfxPostInitDialog(CWnd *param_1,tagRECT *param_2,ulong param_3)

{
  uint uVar1;
  int iVar2;
  int local_14;
  int local_10;
  
  if ((((((param_3 & 0x10000000) == 0) && (uVar1 = func_0xbe3ff0ed(), (uVar1 & 0x50000000) == 0)) &&
       ((*DAT_00428308)(*(undefined4 *)(param_1 + 0x20),&local_14), *(int *)param_2 == local_14)) &&
      ((*(int *)(param_2 + 4) == local_10 &&
       ((iVar2 = func_0xf81ff11c(4), iVar2 == 0 || (iVar2 = func_0xf23ff127(), iVar2 == 0)))))) &&
     (iVar2 = (**(code **)(*(int *)param_1 + 0x124))(), iVar2 != 0)) {
    func_0x0310f142(0);
  }
  return;
}



// Library Function - Single Match
//  long __stdcall AfxWndProc(struct HWND__ *,unsigned int,unsigned int,long)
// 
// Library: Visual Studio

long AfxWndProc(HWND__ *param_1,uint param_2,uint param_3,long param_4)

{
  long lVar1;
  int iVar2;
  
  if (param_2 == 0x360) {
    lVar1 = 1;
  }
  else {
    iVar2 = func_0x2215f257(param_1);
    if ((iVar2 == 0) || (*(HWND__ **)(iVar2 + 0x20) != param_1)) {
      lVar1 = (*DAT_00428390)(param_1,param_2,param_3,param_4);
    }
    else {
      lVar1 = func_0x8920f270(iVar2,param_1,param_2,param_3,param_4);
    }
  }
  return lVar1;
}



int FUN_0040f246(undefined4 param_1,int param_2)

{
  int iVar1;
  
  if ((param_2 == 0) || (iVar1 = func_0x7518f314(&param_2), iVar1 == 0)) {
    param_2 = func_0x5014f324();
  }
  return param_2;
}



// Library Function - Single Match
//  protected: void __thiscall CWnd::OnMeasureItem(int,struct tagMEASUREITEMSTRUCT *)
// 
// Libraries: Visual Studio 2008 Release, Visual Studio 2010 Release

void __thiscall CWnd::OnMeasureItem(CWnd *this,int param_1,tagMEASUREITEMSTRUCT *param_2)

{
  int iVar1;
  int *piVar2;
  
  if (*(int *)param_2 == 1) {
    iVar1 = func_0xd7c1f349(0x408c0d);
    if (iVar1 != 0) goto LAB_0040f29c;
    do {
      iVar1 = func_0xecbbf352();
LAB_0040f29c:
      if (*(int *)(iVar1 + 0x74) == *(int *)(this + 0x20)) {
        iVar1 = func_0x5447f462(*(undefined4 *)(iVar1 + 0x78));
      }
      else {
        iVar1 = (**(code **)(*(int *)this + 0x6c))();
      }
    } while (iVar1 == 0);
    piVar2 = (int *)func_0x2605f378(iVar1,*(undefined4 *)(param_2 + 8));
    if (piVar2 != (int *)0x0) {
      (**(code **)(*piVar2 + 0x10))(param_2);
    }
  }
  else {
    iVar1 = func_0xfc17f394(*(undefined4 *)(this + 0x20),*(undefined4 *)(param_2 + 4),1);
    if ((iVar1 != 0) && (iVar1 = func_0x7518f3a1(0), iVar1 != 0)) {
      return;
    }
  }
  func_0x5014f3ac();
  return;
}



// Library Function - Single Match
//  public: static void __stdcall CWnd::SendMessageToDescendants(struct HWND__ *,unsigned
// int,unsigned int,long,int,int)
// 
// Libraries: Visual Studio 2005 Release, Visual Studio 2008 Release, Visual Studio 2010 Release

void CWnd::SendMessageToDescendants
               (HWND__ *param_1,uint param_2,uint param_3,long param_4,int param_5,int param_6)

{
  code *pcVar1;
  int iVar2;
  int iVar3;
  
  pcVar1 = DAT_004282b0;
  for (iVar2 = (*DAT_004282b0)(param_1); iVar2 != 0; iVar2 = (*DAT_0042830c)(iVar2,2)) {
    if (param_6 == 0) {
      (*DAT_00428380)(iVar2,param_2,param_3,param_4);
    }
    else {
      iVar3 = func_0x2215f3d2(iVar2);
      if (iVar3 != 0) {
        func_0x8920f3e8(iVar3,*(undefined4 *)(iVar3 + 0x20),param_2,param_3,param_4);
      }
    }
    if (param_5 != 0) {
      iVar3 = (*pcVar1)(iVar2);
      if (iVar3 != 0) {
        func_0xf422f41c(iVar2,param_2,param_3,param_4,param_5,param_6);
      }
    }
  }
  return;
}



// Library Function - Single Match
//  protected: void __thiscall CWnd::OnParentNotify(unsigned int,long)
// 
// Libraries: Visual Studio 2008 Release, Visual Studio 2010 Release, Visual Studio 2012 Release,
// Visual Studio 2015 Release

void __thiscall CWnd::OnParentNotify(CWnd *this,uint param_1,long param_2)

{
  int iVar1;
  
  if ((((short)param_1 == 1) || ((short)param_1 == 2)) &&
     (iVar1 = func_0x7323f4f1(param_2,0), iVar1 != 0)) {
    return;
  }
  func_0x5014f4fc();
  return;
}



// Library Function - Single Match
//  protected: long __thiscall CWnd::OnDragList(unsigned int,long)
// 
// Libraries: Visual Studio 2003 Release, Visual Studio 2005 Release, Visual Studio 2008 Release,
// Visual Studio 2010 Release

long __thiscall CWnd::OnDragList(CWnd *this,uint param_1,long param_2)

{
  int iVar1;
  
  iVar1 = func_0x7323f518(*(undefined4 *)(param_2 + 4),&param_2);
  if (iVar1 == 0) {
    param_2 = func_0x5014f528();
  }
  return param_2;
}



undefined4 __cdecl FUN_0040f4a4(int *param_1,int *param_2)

{
  if ((((*param_1 == *param_2) && (param_1[1] == param_2[1])) && (param_1[2] == param_2[2])) &&
     (param_1[3] == param_2[3])) {
    return 1;
  }
  return 0;
}



// Library Function - Single Match
//  int __stdcall ATL::InlineIsEqualUnknown(struct _GUID const &)
// 
// Libraries: Visual Studio 2008 Release, Visual Studio 2010 Release

int ATL::InlineIsEqualUnknown(_GUID *param_1)

{
  int iVar1;
  
  if ((((param_1->Data1 == 0) &&
       (iVar1._0_2_ = param_1->Data2, iVar1._2_2_ = param_1->Data3, iVar1 == 0)) &&
      (*(int *)param_1->Data4 == 0xc0)) && (*(int *)(param_1->Data4 + 4) == 0x46000000)) {
    iVar1 = 1;
  }
  else {
    iVar1 = 0;
  }
  return iVar1;
}



// Library Function - Single Match
//  long __stdcall ATL::AtlInternalQueryInterface(void *,struct ATL::_ATL_INTMAP_ENTRY const
// *,struct _GUID const &,void * *)
// 
// Library: Visual Studio 2008 Release

long ATL::AtlInternalQueryInterface
               (void *param_1,_ATL_INTMAP_ENTRY *param_2,_GUID *param_3,void **param_4)

{
  code *pcVar1;
  long lVar2;
  int iVar3;
  int iVar4;
  int *piVar5;
  
  if ((param_1 == (void *)0x0) || (param_2 == (_ATL_INTMAP_ENTRY *)0x0)) {
    lVar2 = -0x7ff8ffa9;
  }
  else if (param_4 == (void **)0x0) {
    lVar2 = -0x7fffbffd;
  }
  else {
    *param_4 = (void *)0x0;
    iVar3 = func_0xf024f610(param_3);
    if (iVar3 == 0) {
      for (; pcVar1 = *(code **)((int)param_2 + 8), pcVar1 != (code *)0x0;
          param_2 = (_ATL_INTMAP_ENTRY *)((int)param_2 + 0xc)) {
        iVar3 = *(int *)param_2;
        if ((iVar3 == 0) || (iVar4 = func_0x9c24f63f(iVar3,param_3), iVar4 != 0)) {
          if (pcVar1 == (code *)0x1) goto LAB_0040f55e;
          iVar4 = (*pcVar1)(param_1,param_3,param_4,*(int *)((int)param_2 + 4));
          if (iVar4 == 0) {
            return 0;
          }
          if ((iVar3 != 0) && (iVar4 < 0)) {
            return iVar4;
          }
        }
      }
      lVar2 = -0x7fffbffe;
    }
    else {
LAB_0040f55e:
      piVar5 = (int *)(*(int *)((int)param_2 + 4) + (int)param_1);
      (**(code **)(*piVar5 + 4))(piVar5);
      *param_4 = piVar5;
      lVar2 = 0;
    }
  }
  return lVar2;
}



void __thiscall FUN_0040f5cb(void *this,undefined4 param_1,undefined4 param_2)

{
  func_0x2025f697(this,s_R6031___Attempt_to_initialize_th_00429067 + 0x11,param_1,param_2);
  return;
}



undefined4 FUN_0040f60a(int param_1)

{
  *(int *)(param_1 + 0x14) = *(int *)(param_1 + 0x14) + 1;
  return *(undefined4 *)(param_1 + 0x14);
}



// Library Function - Single Match
//  public: virtual unsigned long __stdcall CMFCComObject<class
// ATL::CAccessibleProxy>::Release(void)
// 
// Libraries: Visual Studio 2008 Release, Visual Studio 2010 Release

ulong CMFCComObject<class_ATL::CAccessibleProxy>::Release(void)

{
  int *piVar1;
  ulong uVar2;
  int *in_stack_00000004;
  
  piVar1 = in_stack_00000004 + 5;
  *piVar1 = *piVar1 + -1;
  uVar2 = in_stack_00000004[5];
  if ((*piVar1 == 0) && (in_stack_00000004 != (int *)0x0)) {
    (**(code **)(*in_stack_00000004 + 0x70))(1);
  }
  return uVar2;
}



void FUN_0040f63f(undefined4 param_1,undefined4 param_2,undefined4 param_3)

{
  func_0xc325f708(param_2,param_3);
  return;
}



void * __thiscall FUN_0040f656(void *this,byte param_1)

{
  func_0xdd25f719();
  if ((param_1 & 1) != 0) {
    func_0x15baf725(this);
  }
  return this;
}



void * __thiscall FUN_0040f6ca(void *this,byte param_1)

{
  func_0xc921f78d();
  if ((param_1 & 1) != 0) {
    func_0x15baf799(this);
  }
  return this;
}



// Library Function - Single Match
//  protected: void __thiscall CWnd::OnDrawItem(int,struct tagDRAWITEMSTRUCT *)
// 
// Libraries: Visual Studio 2008 Release, Visual Studio 2010 Release

void __thiscall CWnd::OnDrawItem(CWnd *this,int param_1,tagDRAWITEMSTRUCT *param_2)

{
  int *piVar1;
  int iVar2;
  
  if ((*(int *)param_2 == 1) &&
     (piVar1 = (int *)func_0x6847f8ba(*(undefined4 *)(param_2 + 0x14)), piVar1 != (int *)0x0)) {
    (**(code **)(*piVar1 + 0xc))(param_2);
    return;
  }
  iVar2 = func_0x7323f7d2(*(undefined4 *)(param_2 + 0x14),0);
  if (iVar2 == 0) {
    func_0x5014f7dd();
  }
  return;
}



// Library Function - Single Match
//  protected: int __thiscall CWnd::OnCompareItem(int,struct tagCOMPAREITEMSTRUCT *)
// 
// Libraries: Visual Studio 2003 Release, Visual Studio 2005 Release, Visual Studio 2008 Release,
// Visual Studio 2010 Release

int __thiscall CWnd::OnCompareItem(CWnd *this,int param_1,tagCOMPAREITEMSTRUCT *param_2)

{
  int iVar1;
  
  iVar1 = func_0x7323f7fa(*(undefined4 *)(param_2 + 8),&param_2);
  if (iVar1 == 0) {
    param_2 = (tagCOMPAREITEMSTRUCT *)func_0x5014f80a();
  }
  return (int)param_2;
}



// Library Function - Single Match
//  protected: void __thiscall CWnd::OnDeleteItem(int,struct tagDELETEITEMSTRUCT *)
// 
// Libraries: Visual Studio 2008 Release, Visual Studio 2010 Release, Visual Studio 2012 Release

void __thiscall CWnd::OnDeleteItem(CWnd *this,int param_1,tagDELETEITEMSTRUCT *param_2)

{
  int iVar1;
  
  iVar1 = func_0x7323f824(*(undefined4 *)(param_2 + 0xc),0);
  if (iVar1 == 0) {
    func_0x5014f82f();
  }
  return;
}



// Library Function - Multiple Matches With Same Base Name
//  struct HWND__ * __stdcall AfxHtmlHelp(struct HWND__ *,char const *,unsigned int,unsigned long)
//  struct HWND__ * __stdcall AfxHtmlHelp(struct HWND__ *,wchar_t const *,unsigned int,unsigned
// long)
// 
// Libraries: Visual Studio 2008 Release, Visual Studio 2010 Release

undefined4 AfxHtmlHelp(undefined4 param_1,undefined4 param_2,undefined4 param_3,undefined4 param_4)

{
  int iVar1;
  int iVar2;
  undefined4 uVar3;
  
  func_0xa5c2f841(0xc);
  iVar1 = func_0xb0bdf850(0x40efe7);
  if (iVar1 == 0) {
    func_0xecbbf85b();
  }
  if (*(int *)(iVar1 + 8) == 0) {
    iVar2 = func_0x4802f86b(s_R6030___CRT_not_initialized_004290cb + 0x15);
    *(int *)(iVar1 + 4) = iVar2;
    if (iVar2 != 0) {
      iVar2 = (*(code *)u_f__dd_vctools_vc7libs_ship_atlmf_0042815f._5_4_)
                        (iVar2,s_R6030___CRT_not_initialized_004290cb + 9);
      *(int *)(iVar1 + 8) = iVar2;
      if (iVar2 != 0) goto LAB_0040f7e3;
      (*(code *)u_f__dd_vctools_vc7libs_ship_atlmf_0042815f._85_4_)(*(undefined4 *)(iVar1 + 4));
      *(undefined4 *)(iVar1 + 4) = 0;
    }
    uVar3 = 0;
  }
  else {
LAB_0040f7e3:
    func_0x17c3f8a0(0xc);
    uVar3 = (**(code **)(iVar1 + 8))(param_1,param_2,param_3,param_4);
  }
  return uVar3;
}



// Library Function - Single Match
//  protected: virtual int __thiscall CWnd::OnCommand(unsigned int,long)
// 
// Libraries: Visual Studio 2008 Release, Visual Studio 2010 Release

int __thiscall CWnd::OnCommand(CWnd *this,uint param_1,long param_2)

{
  int iVar1;
  uint uVar2;
  undefined local_30 [4];
  uint local_2c;
  int local_8;
  
  uVar2 = param_1 & 0xffff;
  param_1 = param_1 >> 0x10;
  if (param_2 == 0) {
    if (uVar2 == 0) {
      return 0;
    }
    func_0xb1fbf8e4();
    local_2c = uVar2;
    (**(code **)(*(int *)this + 0xc))(uVar2,0xffffffff,local_30,0);
    if (local_8 != 0) {
      param_1 = 0;
LAB_0040f883:
      iVar1 = (**(code **)(*(int *)this + 0xc))(uVar2,param_1,0,0);
      return iVar1;
    }
  }
  else {
    iVar1 = func_0xd7c1f914(0x408c0d);
    if (iVar1 == 0) {
      iVar1 = func_0xecbbf91d();
    }
    if ((*(int *)(iVar1 + 0x13c) != *(int *)(this + 0x20)) &&
       (iVar1 = func_0x7323f931(param_2,0), iVar1 == 0)) {
      if (uVar2 == 0) {
        return 0;
      }
      goto LAB_0040f883;
    }
  }
  return 1;
}



// Library Function - Single Match
//  protected: virtual int __thiscall CWnd::OnNotify(unsigned int,long,long *)
// 
// Libraries: Visual Studio 2008 Release, Visual Studio 2010 Release

int __thiscall CWnd::OnNotify(CWnd *this,uint param_1,long param_2,long *param_3)

{
  undefined4 uVar1;
  uint uVar2;
  int iVar3;
  long *local_10;
  long local_c;
  undefined4 local_8;
  
  uVar1 = *(undefined4 *)param_2;
  local_8 = (*DAT_004282e0)(uVar1);
  uVar2 = *(uint *)(param_2 + 8);
  iVar3 = func_0xd7c1f97e(0x408c0d);
  if (iVar3 == 0) {
    iVar3 = func_0xecbbf987();
  }
  if ((*(int *)(iVar3 + 0x13c) != *(int *)(this + 0x20)) &&
     (iVar3 = func_0x7323f9a0(uVar1,param_3), iVar3 == 0)) {
    local_10 = param_3;
    local_c = param_2;
    iVar3 = (**(code **)(*(int *)this + 0xc))(local_8,uVar2 & 0xffff | 0x4e0000,&local_10,0);
    return iVar3;
  }
  return 1;
}



// Library Function - Single Match
//  struct HWND__ * __stdcall AfxGetParentOwner(struct HWND__ *)
// 
// Libraries: Visual Studio 2008 Release, Visual Studio 2010 Release

HWND__ * AfxGetParentOwner(HWND__ *param_1)

{
  int iVar1;
  HWND__ *pHVar2;
  uint uVar3;
  
  iVar1 = func_0x2215f9de(param_1);
  if (iVar1 == 0) {
    uVar3 = (*DAT_004283b4)(param_1,0xfffffff0);
    if ((uVar3 & 0x40000000) == 0) {
      pHVar2 = (HWND__ *)(*DAT_0042830c)(param_1,4);
    }
    else {
      pHVar2 = (HWND__ *)(*DAT_00428384)(param_1);
    }
  }
  else {
    pHVar2 = (HWND__ *)func_0xab26f9e9();
    if (pHVar2 != (HWND__ *)0x0) {
      pHVar2 = (HWND__ *)pHVar2[8].unused;
    }
  }
  return pHVar2;
}



// Library Function - Multiple Matches With Same Base Name
//  protected: void __thiscall CWnd::OnDevModeChange(char *)
//  protected: void __thiscall CWnd::OnDevModeChange(wchar_t *)
// 
// Libraries: Visual Studio 2008 Release, Visual Studio 2010 Release

void __thiscall OnDevModeChange(void *this,undefined4 param_1)

{
  int iVar1;
  uint uVar2;
  
  iVar1 = func_0x59d0fa96();
  if ((*(int *)(iVar1 + 4) != 0) && (*(void **)(*(int *)(iVar1 + 4) + 0x20) == this)) {
    func_0xff4ffbac(param_1);
  }
  uVar2 = func_0xbe3ffab3();
  if ((uVar2 & 0x40000000) == 0) {
    iVar1 = func_0x1214fabf();
    func_0xf422fad4(*(undefined4 *)((int)this + 0x20),*(undefined4 *)(iVar1 + 4),
                    *(undefined4 *)(iVar1 + 8),*(undefined4 *)(iVar1 + 0xc),1,1);
  }
  return;
}



// Library Function - Single Match
//  void __stdcall _AfxHandleActivate(class CWnd *,unsigned int,class CWnd *)
// 
// Libraries: Visual Studio 2008 Release, Visual Studio 2010 Release

void _AfxHandleActivate(CWnd *param_1,uint param_2,CWnd *param_3)

{
  uint uVar1;
  int iVar2;
  int iVar3;
  undefined4 local_c;
  undefined4 local_8;
  
  uVar1 = func_0xbe3ffba8();
  if ((((uVar1 & 0x40000000) == 0) && (iVar2 = func_0x5b29fbb7(), iVar2 != 0)) &&
     ((param_3 == (CWnd *)0x0 ||
      ((iVar3 = (*DAT_004282a4)(*(undefined4 *)(param_3 + 0x20)), iVar3 == 0 ||
       (iVar3 = func_0x5b29fbd9(), iVar2 != iVar3)))))) {
    local_c = *(undefined4 *)(param_1 + 0x20);
    if (param_3 == (CWnd *)0x0) {
      local_8 = 0;
    }
    else {
      local_8 = *(undefined4 *)(param_3 + 0x20);
    }
    (*DAT_00428380)(*(undefined4 *)(iVar2 + 0x20),0x36e,param_2,&local_c);
  }
  return;
}



// Library Function - Single Match
//  int __stdcall _AfxHandleSetCursor(class CWnd *,unsigned int,unsigned int)
// 
// Library: Visual Studio

int _AfxHandleSetCursor(CWnd *param_1,uint param_2,uint param_3)

{
  int iVar1;
  undefined4 uVar2;
  int iVar3;
  
  if (((param_2 == 0xfffffffe) && (((param_3 == 0x201 || (param_3 == 0x207)) || (param_3 == 0x204)))
      ) && (iVar1 = func_0x5b29fc3d(), iVar1 != 0)) {
    uVar2 = (*DAT_004283b8)(*(undefined4 *)(iVar1 + 0x20));
    iVar1 = func_0xf614fc50(uVar2);
    if (iVar1 != 0) {
      uVar2 = (*DAT_004282a8)();
      iVar3 = func_0xf614fc62(uVar2);
      if ((iVar1 != iVar3) && (iVar3 = func_0xf23ffc6d(), iVar3 != 0)) {
        (*DAT_004283a4)(*(undefined4 *)(iVar1 + 0x20));
        return 1;
      }
    }
  }
  return 0;
}



// Library Function - Single Match
//  void __stdcall AfxHookWindowCreate(class CWnd *)
// 
// Libraries: Visual Studio 2008 Release, Visual Studio 2010 Release

void AfxHookWindowCreate(CWnd *param_1)

{
  int iVar1;
  undefined4 uVar2;
  int iVar3;
  
  iVar1 = func_0xd7c20009(0x408c0d);
  if (iVar1 == 0) {
    func_0xecbc0014();
  }
  if (*(CWnd **)(iVar1 + 0x14) != param_1) {
    if (*(int *)(iVar1 + 0x28) == 0) {
      uVar2 = (*DAT_00428084)();
      iVar3 = (*DAT_00428344)(5,&DAT_0040fd19,0,uVar2);
      *(int *)(iVar1 + 0x28) = iVar3;
      if (iVar3 == 0) {
        func_0xb4bc0044();
      }
    }
    *(CWnd **)(iVar1 + 0x14) = param_1;
  }
  return;
}



// Library Function - Multiple Matches With Same Base Name
//  public: virtual int __thiscall CWnd::CreateEx(unsigned long,char const *,char const *,unsigned
// long,int,int,int,int,struct HWND__ *,struct HMENU__ *,void *)
//  public: virtual int __thiscall CWnd::CreateEx(unsigned long,wchar_t const *,wchar_t const
// *,unsigned long,int,int,int,int,struct HWND__ *,struct HMENU__ *,void *)
// 
// Libraries: Visual Studio 2008 Release, Visual Studio 2010 Release

bool __thiscall
CreateEx(void *this,undefined4 param_1,undefined4 param_2,int param_3,undefined4 param_4,
        undefined4 param_5,undefined4 param_6,undefined4 param_7,undefined4 param_8,
        undefined4 param_9,undefined4 param_10,undefined4 param_11)

{
  int iVar1;
  int iVar2;
  bool bVar3;
  undefined4 local_34;
  undefined4 local_30;
  undefined4 local_2c;
  undefined4 local_28;
  undefined4 local_24;
  undefined4 local_20;
  undefined4 local_1c;
  undefined4 local_18;
  undefined4 local_14;
  int local_10;
  undefined4 local_c;
  undefined4 local_8;
  
  if (param_3 != 0) {
    iVar1 = func_0x8fe10068(param_3,0xffffffff);
    if (iVar1 == 0) {
      func_0xecbc0071();
    }
  }
  local_8 = param_1;
  local_c = param_2;
  local_14 = param_4;
  local_18 = param_5;
  local_1c = param_6;
  local_20 = param_7;
  local_24 = param_8;
  local_28 = param_9;
  local_10 = param_3;
  local_2c = param_10;
  iVar1 = func_0x59d100af();
  local_30 = *(undefined4 *)(iVar1 + 8);
  local_34 = param_11;
                    // WARNING: Load size is inaccurate
  iVar1 = (**(code **)(*this + 100))(&local_34);
  if (iVar1 == 0) {
                    // WARNING: Load size is inaccurate
    (**(code **)(*this + 0x11c))();
    bVar3 = false;
  }
  else {
    func_0x353000de(this);
    iVar1 = func_0x99020107(local_8,local_c,local_10,local_14,local_18,local_1c,local_20,local_24,
                            local_28,local_2c,local_30,local_34);
    iVar2 = func_0xaf160111();
    if (iVar2 == 0) {
                    // WARNING: Load size is inaccurate
      (**(code **)(*this + 0x11c))();
    }
    bVar3 = iVar1 != 0;
  }
  return bVar3;
}



// WARNING: Control flow encountered bad instruction data
// Library Function - Single Match
//  protected: virtual int __thiscall CWnd::OnChildNotify(unsigned int,unsigned int,long,long *)
// 
// Library: Visual Studio 2008 Release

int __thiscall CWnd::OnChildNotify(CWnd *this,uint param_1,uint param_2,long param_3,long *param_4)

{
  int iVar1;
  
  if (*(int *)(this + 0x50) != 0) {
    iVar1 = func_0xc9dc0c58(param_1 + 0x2000,param_2,param_3);
    if ((6 < param_1 - 0x132) || (iVar1 != 0)) {
      if (param_4 != (long *)0x0) {
        *param_4 = iVar1;
      }
      iVar1 = 1;
    }
    return iVar1;
  }
                    // WARNING: Bad instruction - Truncating control flow here
  halt_baddata();
}



// Library Function - Single Match
//  int __stdcall _AfxRegisterWithIcon(struct tagWNDCLASSA *,char const *,unsigned int)
// 
// Library: Visual Studio 2008 Release

int _AfxRegisterWithIcon(tagWNDCLASSA *param_1,char *param_2,uint param_3)

{
  code *pcVar1;
  int iVar2;
  undefined4 uVar3;
  
  *(char **)(param_1 + 0x24) = param_2;
  iVar2 = func_0x59d10d28();
  pcVar1 = DAT_00428364;
  iVar2 = (*DAT_00428364)(*(undefined4 *)(iVar2 + 0xc),param_3 & 0xffff);
  *(int *)(param_1 + 0x14) = iVar2;
  if (iVar2 == 0) {
    uVar3 = (*pcVar1)(0,0x7f00);
    *(undefined4 *)(param_1 + 0x14) = uVar3;
  }
  iVar2 = func_0xc83c0d51(param_1);
  return iVar2;
}



// WARNING: Control flow encountered bad instruction data
// Library Function - Single Match
//  int __stdcall AfxEndDeferRegisterClass(long)
// 
// Library: Visual Studio 2008 Release

int AfxEndDeferRegisterClass(long param_1)

{
  int iVar1;
  uint uVar2;
  uint uVar3;
  uint local_38;
  undefined4 local_34;
  undefined4 local_28;
  undefined4 local_20;
  undefined4 local_1c;
  undefined *local_14;
  undefined4 local_10;
  undefined4 local_c;
  int local_8;
  
  local_8 = func_0x59d10d64();
  param_1 = param_1 & ~*(uint *)(local_8 + 0x18);
  if (param_1 == 0) {
                    // WARNING: Bad instruction - Truncating control flow here
    halt_baddata();
  }
  uVar3 = 0;
  func_0x3b830e8c(&local_38,0,0x28);
  local_34 = DAT_00428390;
  iVar1 = func_0x59d10d9c();
  local_28 = *(undefined4 *)(iVar1 + 8);
  local_20 = DAT_00433350;
  local_10 = 8;
  if ((param_1 & 1U) != 0) {
    local_38 = 0xb;
    local_14 = &DAT_00428a24;
    iVar1 = func_0xc83c0dcd(&local_38);
    if (iVar1 != 0) {
      uVar3 = 1;
    }
  }
  if ((param_1 & 0x20U) != 0) {
    local_38 = local_38 | 0x8b;
    local_14 = &DAT_00428aa8;
    iVar1 = func_0xc83c0def(&local_38);
    if (iVar1 != 0) {
      uVar3 = uVar3 | 0x20;
    }
  }
  if ((param_1 & 2U) != 0) {
    local_38 = 0;
    local_14 = &DAT_00428a3c;
    local_1c = 0x62fd00b6;
    iVar1 = func_0xc83c0e16(&local_38);
    if (iVar1 != 0) {
      uVar3 = uVar3 | 2;
    }
  }
  if ((param_1 & 4U) != 0) {
    local_38 = 8;
    local_1c = 0;
    iVar1 = _AfxRegisterWithIcon((tagWNDCLASSA *)&local_38,s_CByteArray_00428a5b + 5,0x7a01);
    if (iVar1 != 0) {
      uVar3 = uVar3 | 4;
    }
  }
  if ((param_1 & 8U) != 0) {
    local_38 = 0xb;
    local_1c = 0xabfd00b6;
    iVar1 = func_0x553d0e69(&local_38,&DAT_00428a80,0x7a02);
    if (iVar1 != 0) {
      uVar3 = uVar3 | 8;
    }
  }
  if ((param_1 & 0x10U) != 0) {
    local_c = 0xff;
    uVar2 = func_0x101b0e8a(&local_10,0x3fc0);
    uVar3 = uVar3 | uVar2;
    param_1 = param_1 & 0xffffc03f;
  }
  if ((param_1 & 0x40U) != 0) {
    local_c = 0x10;
    uVar2 = func_0x101b0eab(&local_10,0x40);
    uVar3 = uVar3 | uVar2;
  }
  if ((param_1 & 0x80U) != 0) {
    local_c = 2;
    uVar2 = func_0x101b0ec8(&local_10,0x80);
    uVar3 = uVar3 | uVar2;
  }
  if ((param_1 & 0x100U) != 0) {
    local_c = 8;
    uVar2 = func_0x101b0ee1(&local_10,0x100);
    uVar3 = uVar3 | uVar2;
  }
  if ((param_1 & 0x200U) != 0) {
    local_c = 0x20;
    uVar2 = func_0x101b0efe(&local_10,0x200);
    uVar3 = uVar3 | uVar2;
  }
  if ((param_1 & 0x400U) != 0) {
    local_c = 1;
    uVar2 = func_0x101b0f1b(&local_10,0x400);
    uVar3 = uVar3 | uVar2;
  }
  if ((param_1 & 0x800U) != 0) {
    local_c = 0x40;
    uVar2 = func_0x101b0f38(&local_10,0x800);
    uVar3 = uVar3 | uVar2;
  }
  if ((param_1 & 0x1000U) != 0) {
    local_c = 4;
    uVar2 = func_0x101b0f55(&local_10,0x1000);
    uVar3 = uVar3 | uVar2;
  }
  if ((param_1 & 0x2000U) != 0) {
    local_c = 0x80;
    uVar2 = func_0x101b0f72(&local_10,0x2000);
    uVar3 = uVar3 | uVar2;
  }
  if ((param_1 & 0x4000U) != 0) {
    local_c = 0x800;
    uVar2 = func_0x101b0f8b(&local_10,0x4000);
    uVar3 = uVar3 | uVar2;
  }
  if ((param_1 & 0x8000U) != 0) {
    local_c = 0x400;
    uVar2 = func_0x101b0fa4(&local_10,0x8000);
    uVar3 = uVar3 | uVar2;
  }
  if ((param_1 & 0x10000U) != 0) {
    local_c = 0x200;
    uVar2 = func_0x101b0fc1(&local_10,0x10000);
    uVar3 = uVar3 | uVar2;
  }
  if ((param_1 & 0x20000U) != 0) {
    local_c = 0x100;
    uVar2 = func_0x101b0fde(&local_10,0x20000);
    uVar3 = uVar3 | uVar2;
  }
  if ((param_1 & 0x40000U) != 0) {
    local_c = 0x8000;
    uVar2 = func_0x101b0ff7(&local_10,0x40000);
    uVar3 = uVar3 | uVar2;
  }
  if ((param_1 & 0x80000U) != 0) {
    local_c = 0x1000;
    uVar2 = func_0x101b1014(&local_10,0x80000);
    uVar3 = uVar3 | uVar2;
  }
  *(uint *)(local_8 + 0x18) = *(uint *)(local_8 + 0x18) | uVar3;
  if ((*(uint *)(local_8 + 0x18) & 0x3fc0) == 0x3fc0) {
    *(uint *)(local_8 + 0x18) = *(uint *)(local_8 + 0x18) | 0x10;
    uVar3 = uVar3 | 0x10;
  }
  return (uint)((uVar3 & param_1) == param_1);
}



// Library Function - Multiple Matches With Same Base Name
//  public: virtual int __thiscall CWnd::PreCreateWindow(struct tagCREATESTRUCTA &)
//  public: virtual int __thiscall CWnd::PreCreateWindow(struct tagCREATESTRUCTW &)
// 
// Library: Visual Studio 2008 Release

undefined4 PreCreateWindow(int param_1)

{
  if (*(int *)(param_1 + 0x28) == 0) {
    func_0x993d105f(1);
    *(undefined **)(param_1 + 0x28) = &DAT_00428a24;
  }
  return 1;
}



void __fastcall FUN_00410fb8(int param_1)

{
                    // WARNING: Could not recover jumptable at 0x00410fc3. Too many branches
                    // WARNING: Treating indirect jump as call
  (**(code **)(**(int **)(param_1 + 0x4c) + 0x58))();
  return;
}



// Library Function - Single Match
//  void __stdcall AfxSetWindowText(struct HWND__ *,wchar_t const *)
// 
// Libraries: Visual Studio 2008 Release, Visual Studio 2010 Release

void AfxSetWindowText(HWND__ *param_1,wchar_t *param_2)

{
  uint uVar1;
  uint uVar2;
  int iVar3;
  undefined2 local_208;
  undefined local_206 [510];
  uint local_8;
  
  local_8 = DAT_00431c20 ^ (uint)&stack0xfffffffc;
  if (param_1 != (HWND__ *)0x0) goto LAB_004110e5;
  do {
    func_0xecbc119b();
LAB_004110e5:
  } while (param_2 == (wchar_t *)0x0);
  uVar1 = (*DAT_0042807c)(param_2);
  local_208 = 0;
  func_0x3b8312c3(local_206,0,0x1fe);
  if (uVar1 < 0x101) {
    uVar2 = (*DAT_0042832c)(param_1,&local_208,0x100);
    if (uVar2 == uVar1) {
      iVar3 = (*DAT_00428098)(&local_208,param_2);
      if (iVar3 == 0) goto LAB_00411146;
    }
  }
  (*DAT_004283a0)(param_1,param_2);
LAB_00411146:
  func_0x485f1309();
  return;
}



// Library Function - Single Match
//  void __stdcall AfxDeleteObject(void * *)
// 
// Libraries: Visual Studio 2008 Release, Visual Studio 2010 Release

void AfxDeleteObject(void **param_1)

{
  if (param_1 == (void **)0x0) {
    func_0xecbc121f();
  }
  if (*param_1 != (void *)0x0) {
    (*DAT_0042802c)(*param_1);
    *param_1 = (void *)0x0;
  }
  return;
}



// Library Function - Single Match
//  void __stdcall AfxGlobalFree(void *)
// 
// Library: Visual Studio 2008 Release

void AfxGlobalFree(void *param_1)

{
  uint uVar1;
  
  if (param_1 != (void *)0x0) {
    uVar1 = (*DAT_004280b0)(param_1);
    for (uVar1 = uVar1 & 0xff; uVar1 != 0; uVar1 = uVar1 - 1) {
      (*(code *)u_f__dd_vctools_vc7libs_ship_atlmf_0042815f._45_4_)(param_1);
    }
    (*(code *)u_f__dd_vctools_vc7libs_ship_atlmf_0042815f._13_4_)(param_1);
  }
  return;
}



// Library Function - Single Match
//  int __cdecl AfxCriticalNewHandler(unsigned int)
// 
// Libraries: Visual Studio 2008 Release, Visual Studio 2010 Release

int __cdecl AfxCriticalNewHandler(uint param_1)

{
  code *pcVar1;
  int iVar2;
  uint uVar3;
  
  iVar2 = func_0xf2c91277();
  if ((iVar2 != 0) && (*(int *)(iVar2 + 0xc) != 0)) {
    uVar3 = func_0xf5a1138a(*(int *)(iVar2 + 0xc));
    if (param_1 + 4 < uVar3) {
      func_0x4ea313b1(*(undefined4 *)(iVar2 + 0xc),(uVar3 - param_1) + -4);
    }
    else {
      func_0xc273139d(*(undefined4 *)(iVar2 + 0xc));
      *(undefined4 *)(iVar2 + 0xc) = 0;
    }
    return 1;
  }
  func_0xb4bc12be();
  pcVar1 = (code *)swi(3);
  iVar2 = (*pcVar1)();
  return iVar2;
}



// Library Function - Single Match
//  struct HWND__ * __stdcall _AfxChildWindowFromPoint(struct HWND__ *,struct tagPOINT)
// 
// Library: Visual Studio 2008 Release

int _AfxChildWindowFromPoint(int param_1,undefined4 param_2,undefined4 param_3)

{
  code *pcVar1;
  int iVar2;
  uint uVar3;
  undefined4 uVar4;
  undefined local_14 [16];
  
  (*DAT_00428388)(param_1,&param_2);
  pcVar1 = DAT_0042830c;
  uVar4 = 5;
  do {
    param_1 = (*pcVar1)(param_1,uVar4);
    if (param_1 == 0) {
      return 0;
    }
    iVar2 = (*DAT_004282e0)(param_1);
    if ((iVar2 != 0xffff) &&
       (uVar3 = (*DAT_004283b4)(param_1,0xfffffff0), (uVar3 & 0x10000000) != 0)) {
      (*DAT_00428308)(param_1,local_14);
      iVar2 = (*DAT_004282ec)(local_14,param_2,param_3);
      if (iVar2 != 0) {
        return param_1;
      }
    }
    uVar4 = 2;
  } while( true );
}



// WARNING: Control flow encountered bad instruction data
// Library Function - Single Match
//  public: void __thiscall CByteArray::SetSize(int,int)
// 
// Libraries: Visual Studio 2005 Release, Visual Studio 2008 Release

void __thiscall CByteArray::SetSize(CByteArray *this,int param_1,int param_2)

{
  int iVar1;
  undefined4 uVar2;
  int iVar3;
  int iVar4;
  
  iVar1 = param_1;
  iVar4 = 0;
  if (-1 < param_1) goto LAB_004112c4;
  do {
    func_0xecbc137a();
LAB_004112c4:
    if (iVar4 <= param_2) {
      *(int *)(this + 0x10) = param_2;
    }
    if (iVar1 == iVar4) {
      func_0x15bb1390(*(undefined4 *)(this + 4));
      *(int *)(this + 0xc) = iVar4;
      *(int *)(this + 8) = iVar4;
                    // WARNING: Bad instruction - Truncating control flow here
      halt_baddata();
    }
    if (*(int *)(this + 4) == iVar4) {
      uVar2 = func_0xdbba13ae(iVar1);
      *(undefined4 *)(this + 4) = uVar2;
      func_0x3b8314b9(uVar2,iVar4,iVar1);
      *(int *)(this + 0xc) = iVar1;
LAB_0041132b:
      *(int *)(this + 8) = iVar1;
                    // WARNING: Bad instruction - Truncating control flow here
      halt_baddata();
    }
    iVar4 = *(int *)(this + 0xc);
    if (iVar1 <= iVar4) {
      iVar4 = *(int *)(this + 8);
      if (iVar4 < iVar1) {
        func_0x3b8314de(iVar4 + *(int *)(this + 4),0,iVar1 - iVar4);
      }
      goto LAB_0041132b;
    }
    iVar3 = *(int *)(this + 0x10);
    if (iVar3 == 0) {
      iVar3 = (int)(*(int *)(this + 8) + (*(int *)(this + 8) >> 0x1f & 7U)) >> 3;
      if (iVar3 < 4) {
LAB_0041135d:
        iVar3 = 4;
      }
      else if (iVar3 < 0x401) {
        if (iVar3 < 4) goto LAB_0041135d;
      }
      else {
        iVar3 = 0x400;
      }
    }
    param_1 = iVar3 + iVar4;
    if (iVar3 + iVar4 <= iVar1) {
      param_1 = iVar1;
    }
    if (iVar4 <= param_1) {
      iVar4 = func_0xdbba1433(param_1);
      func_0x53d51444(iVar4,param_1,*(undefined4 *)(this + 4),*(undefined4 *)(this + 8));
      func_0x3b831556(*(int *)(this + 8) + iVar4,0,iVar1 - *(int *)(this + 8));
      func_0x15bb145e(*(undefined4 *)(this + 4));
      *(int *)(this + 8) = iVar1;
      *(int *)(this + 0xc) = param_1;
      *(int *)(this + 4) = iVar4;
      return;
    }
  } while( true );
}



// Library Function - Single Match
//  public: virtual void __thiscall CByteArray::Serialize(class CArchive &)
// 
// Library: Visual Studio 2008 Release

void __thiscall CByteArray::Serialize(CByteArray *this,CArchive *param_1)

{
  undefined4 uVar1;
  int iVar2;
  uint uVar3;
  uint uVar4;
  
  if ((~*(uint *)(param_1 + 0x18) & 1) == 0) {
    uVar1 = func_0x26e714be();
    func_0xa34315c8(uVar1,0xffffffff);
    iVar2 = *(int *)(this + 4);
    for (uVar4 = *(uint *)(this + 8); uVar4 != 0; uVar4 = uVar4 - uVar3) {
      uVar3 = 0x7fffffff;
      if (uVar4 < 0x7fffffff) {
        uVar3 = uVar4;
      }
      func_0x97e714e7(iVar2,uVar3);
      iVar2 = iVar2 + uVar3;
    }
  }
  else {
    func_0xf5e61492(*(undefined4 *)(this + 8));
    iVar2 = *(int *)(this + 4);
    for (uVar4 = *(uint *)(this + 8); uVar4 != 0; uVar4 = uVar4 - uVar3) {
      uVar3 = 0x7fffffff;
      if (uVar4 < 0x7fffffff) {
        uVar3 = uVar4;
      }
      func_0x2ee614b1(iVar2,uVar3);
      iVar2 = iVar2 + uVar3;
    }
  }
  return;
}



void * __thiscall FUN_00411454(void *this,byte param_1)

{
  func_0x93431617();
  if ((param_1 & 1) != 0) {
    func_0x15bb1523(this);
  }
  return this;
}



// Library Function - Single Match
//  void __stdcall AfxFormatStrings(class ATL::CStringT<wchar_t,class StrTraitMFC<wchar_t,class
// ATL::ChTraitsCRT<wchar_t> > > &,wchar_t const *,wchar_t const * const *,int)
// 
// Library: Visual Studio 2008 Release

void AfxFormatStrings(CStringT<wchar_t,class_StrTraitMFC<wchar_t,class_ATL::ChTraitsCRT<wchar_t>_>_>
                      *param_1,wchar_t *param_2,wchar_t **param_3,int param_4)

{
  wchar_t wVar1;
  wchar_t *pwVar2;
  int iVar3;
  wchar_t *pwVar4;
  int iVar5;
  wchar_t *pwVar6;
  
  pwVar6 = param_2;
  if (param_2 != (wchar_t *)0x0) goto LAB_0041148a;
  do {
    func_0xecbc1540();
LAB_0041148a:
  } while (param_3 == (wchar_t **)0x0);
  param_2 = (wchar_t *)0x0;
  wVar1 = *pwVar6;
  pwVar4 = pwVar6;
  while (wVar1 != L'\0') {
    if (*pwVar4 == L'%') {
      wVar1 = pwVar4[1];
      if (((ushort)wVar1 < 0x31) || (0x39 < (ushort)wVar1)) {
        if (((ushort)wVar1 < 0x41) || (0x5a < (ushort)wVar1)) goto LAB_004114ee;
        if ((ushort)wVar1 < 0x3a) goto LAB_004114cd;
        iVar3 = (ushort)wVar1 - 0x38;
      }
      else {
LAB_004114cd:
        iVar3 = (ushort)wVar1 - 0x31;
      }
      pwVar4 = pwVar4 + 2;
      if (param_4 <= iVar3) goto LAB_004114f0;
      if (param_3[iVar3] != (wchar_t *)0x0) {
        iVar3 = (*DAT_0042807c)(param_3[iVar3]);
        param_2 = (wchar_t *)((int)param_2 + iVar3);
      }
    }
    else {
LAB_004114ee:
      pwVar4 = pwVar4 + 1;
LAB_004114f0:
      param_2 = (wchar_t *)((int)param_2 + 1);
    }
    wVar1 = *pwVar4;
  }
  pwVar4 = (wchar_t *)func_0xc4c915bc(param_2);
  wVar1 = *pwVar6;
  do {
    if (wVar1 == L'\0') {
      func_0xfcd51667((int)pwVar4 - *(int *)param_1 >> 1);
      return;
    }
    if (*pwVar6 == L'%') {
      wVar1 = pwVar6[1];
      if (((ushort)wVar1 < 0x31) || (0x39 < (ushort)wVar1)) {
        if (((ushort)wVar1 < 0x41) || (0x5a < (ushort)wVar1)) goto LAB_00411590;
        if ((ushort)wVar1 < 0x3a) goto LAB_00411545;
        iVar3 = (ushort)wVar1 - 0x38;
      }
      else {
LAB_00411545:
        iVar3 = (ushort)wVar1 - 0x31;
      }
      pwVar6 = pwVar6 + 2;
      if (param_4 <= iVar3) {
        *pwVar4 = L'?';
        goto LAB_00411597;
      }
      pwVar2 = param_3[iVar3];
      if (pwVar2 != (wchar_t *)0x0) {
        iVar5 = (*DAT_0042807c)(pwVar2);
        func_0x28e11638(pwVar4,(int)param_2 + 1,param_3[iVar3]);
        param_2 = (wchar_t *)((int)param_2 - iVar5);
        pwVar4 = pwVar4 + iVar5;
      }
    }
    else {
LAB_00411590:
      *pwVar4 = *pwVar6;
      pwVar6 = pwVar6 + 1;
LAB_00411597:
      pwVar4 = pwVar4 + 1;
      param_2 = (wchar_t *)((int)param_2 + -1);
    }
    wVar1 = *pwVar6;
  } while( true );
}



void FUN_00411609(undefined4 param_1,undefined4 param_2,undefined param_3)

{
  func_0xaf4617d5(param_1,param_2,&param_3,1);
  return;
}



// Library Function - Single Match
//  public: __thiscall CFixedAllocNoSync::CFixedAllocNoSync(unsigned int,unsigned int)
// 
// Libraries: Visual Studio 2008 Release, Visual Studio 2010 Release

void __thiscall
CFixedAllocNoSync::CFixedAllocNoSync(CFixedAllocNoSync *this,uint param_1,uint param_2)

{
  if (param_1 < 4) {
    param_1 = 4;
  }
  if (param_2 < 2) {
    param_2 = 0x40;
  }
  *(undefined4 *)(this + 0xc) = 0;
  *(undefined4 *)(this + 8) = 0;
  *(uint *)this = param_1;
  *(uint *)(this + 4) = param_2;
  return;
}



void FUN_004116cf(undefined4 *param_1)

{
  if (param_1 != (undefined4 *)0x0) {
    param_1[1] = 0;
    *param_1 = &DAT_00429a50;
  }
  return;
}



// WARNING: Control flow encountered bad instruction data

void FUN_0041175d(void)

{
  func_0xe047191f(1);
                    // WARNING: Bad instruction - Truncating control flow here
  halt_baddata();
}



// WARNING: Control flow encountered bad instruction data

undefined4 FUN_00411771(void)

{
  int iVar1;
  
  iVar1 = func_0xe0471933(0);
  if (iVar1 != 0) {
                    // WARNING: Bad instruction - Truncating control flow here
    halt_baddata();
  }
  return 0;
}



undefined4 * __thiscall FUN_004117d4(void *this,byte param_1)

{
  *(undefined **)this = &DAT_00429a50;
  func_0xb548199d();
  if ((param_1 & 1) != 0) {
    func_0x15bb18a9(this);
  }
  return (undefined4 *)this;
}



void * __thiscall FUN_004118c0(void *this,byte param_1)

{
  func_0xf2481a83();
  if ((param_1 & 1) != 0) {
    func_0x15bb198f(this);
  }
  return this;
}



void __thiscall FUN_004118e1(void *this,undefined4 param_1)

{
  *(undefined4 *)((int)this + 8) = param_1;
  return;
}



void __thiscall FUN_004118f0(void *this,undefined4 param_1)

{
  *(undefined4 *)((int)this + 4) = param_1;
  return;
}



// Library Function - Single Match
//  public: virtual int __thiscall CDC::RestoreDC(int)
// 
// Libraries: Visual Studio 2008 Release, Visual Studio 2010 Release

int __thiscall CDC::RestoreDC(CDC *this,int param_1)

{
  code *pcVar1;
  int iVar2;
  
  pcVar1 = DAT_00428040;
  iVar2 = 1;
  if (*(int *)(this + 4) != *(int *)(this + 8)) {
    iVar2 = (*DAT_00428040)(*(int *)(this + 4),param_1);
  }
  if (*(int *)(this + 8) != 0) {
    if ((iVar2 != 0) && (iVar2 = (*pcVar1)(*(int *)(this + 8),param_1), iVar2 != 0)) {
      return 1;
    }
    iVar2 = 0;
  }
  return iVar2;
}



undefined4 __thiscall FUN_0041197e(void *this,undefined4 param_1)

{
  undefined4 uVar1;
  undefined4 uVar2;
  
  uVar1 = s_InitCommonControlsEx_00428017._17_4_;
  uVar2 = 0xffffffff;
  if (*(int *)((int)this + 4) != *(int *)((int)this + 8)) {
    uVar2 = (*(code *)s_InitCommonControlsEx_00428017._17_4_)(*(int *)((int)this + 4),param_1);
  }
  if (*(int *)((int)this + 8) != 0) {
    uVar2 = (*(code *)uVar1)(*(int *)((int)this + 8),param_1);
  }
  return uVar2;
}



undefined4 __thiscall FUN_004119b1(void *this,undefined4 param_1)

{
  undefined4 uVar1;
  undefined4 uVar2;
  
  uVar1 = s_InitCommonControlsEx_00428017._13_4_;
  uVar2 = 0xffffffff;
  if (*(int *)((int)this + 4) != *(int *)((int)this + 8)) {
    uVar2 = (*(code *)s_InitCommonControlsEx_00428017._13_4_)(*(int *)((int)this + 4),param_1);
  }
  if (*(int *)((int)this + 8) != 0) {
    uVar2 = (*(code *)uVar1)(*(int *)((int)this + 8),param_1);
  }
  return uVar2;
}



undefined4 __thiscall FUN_004119e4(void *this,undefined4 param_1)

{
  code *pcVar1;
  undefined4 uVar2;
  
  pcVar1 = DAT_00428044;
  uVar2 = 0;
  if (*(int *)((int)this + 4) != *(int *)((int)this + 8)) {
    uVar2 = (*DAT_00428044)(*(int *)((int)this + 4),param_1);
  }
  if (*(int *)((int)this + 8) != 0) {
    uVar2 = (*pcVar1)(*(int *)((int)this + 8),param_1);
  }
  return uVar2;
}



void __thiscall FUN_00411a16(void *this,undefined4 param_1)

{
  (*(code *)s_InitCommonControlsEx_00428017._9_4_)(*(undefined4 *)((int)this + 4),param_1);
  return;
}



void __thiscall FUN_00411a57(void *this,undefined4 param_1,undefined4 param_2)

{
  (*DAT_00428068)(*(undefined4 *)((int)this + 4),param_1,param_2);
  return;
}



void __thiscall FUN_00411a6f(void *this,undefined4 param_1)

{
  (*DAT_00428060)(*(undefined4 *)((int)this + 4),param_1);
  return;
}



void __thiscall
FUN_00411a84(void *this,undefined4 param_1,undefined4 param_2,undefined4 param_3,undefined4 param_4)

{
  (*DAT_0042806c)(*(undefined4 *)((int)this + 4),param_1,param_2,param_3,param_4);
  return;
}



void __thiscall
FUN_00411aa2(void *this,undefined4 param_1,undefined4 param_2,undefined4 param_3,undefined4 param_4,
            undefined4 param_5,undefined4 param_6,undefined4 param_7)

{
  (*DAT_00428038)(*(undefined4 *)((int)this + 4),param_1,param_2,param_3,param_4,param_5,param_6,
                  param_7);
  return;
}



int * __thiscall
FUN_00411ac9(void *this,int *param_1,undefined4 param_2,undefined4 param_3,undefined4 param_4,
            undefined4 param_5,undefined4 param_6,undefined4 param_7,undefined4 param_8)

{
  undefined4 uVar1;
  
  uVar1 = (*DAT_00428274)(*(undefined4 *)((int)this + 4),param_2,param_3,param_4,param_5,param_6,
                          param_7,param_8);
  param_1[1] = (int)(short)((uint)uVar1 >> 0x10);
  *param_1 = (int)(short)uVar1;
  return param_1;
}



void __thiscall
FUN_00411b01(void *this,undefined4 param_1,undefined4 param_2,undefined4 param_3,undefined4 param_4)

{
  (*DAT_00428278)(*(undefined4 *)((int)this + 4),param_1,param_2,param_3,param_4);
  return;
}



void __thiscall
FUN_00411b1f(void *this,undefined4 param_1,undefined4 param_2,undefined4 param_3,undefined4 param_4,
            undefined4 param_5)

{
  (*DAT_0042827c)(*(undefined4 *)((int)this + 4),param_1,param_2,param_3,param_4,param_5);
  return;
}



void __thiscall
FUN_00411b40(void *this,int param_1,undefined4 param_2,undefined4 param_3,undefined4 param_4,
            undefined4 param_5,undefined4 param_6,undefined4 param_7,undefined4 param_8)

{
  if (param_1 != 0) {
    param_1 = *(int *)(param_1 + 4);
  }
  (*DAT_00428280)(*(undefined4 *)((int)this + 4),param_1,param_2,param_3,param_4,param_5,param_6,
                  param_7,param_8);
  return;
}



void __thiscall
FUN_00411b72(void *this,undefined4 param_1,undefined4 param_2,undefined4 param_3,undefined4 param_4)

{
  (*DAT_0042805c)(*(undefined4 *)((int)this + 4),param_1,param_2,param_3,param_4);
  return;
}



// Library Function - Multiple Matches With Different Base Names
//  public: class CPoint __thiscall CDC::MoveTo(int,int)
//  public: virtual class CPoint __thiscall CDC::OffsetViewportOrg(int,int)
//  public: class CPoint __thiscall CDC::OffsetWindowOrg(int,int)
//  public: virtual class CSize __thiscall CDC::SetViewportExt(int,int)
//   7 names - too many to list
// 
// Library: Visual Studio 2008 Release

undefined4 __thiscall
FID_conflict_OffsetWindowOrg(void *this,undefined4 param_1,undefined4 param_2,undefined4 param_3)

{
  code *pcVar1;
  
  pcVar1 = DAT_00428054;
  if (*(int *)((int)this + 4) != *(int *)((int)this + 8)) {
    (*DAT_00428054)(*(int *)((int)this + 4),param_2,param_3,param_1);
  }
  if (*(int *)((int)this + 8) != 0) {
    (*pcVar1)(*(int *)((int)this + 8),param_2,param_3,param_1);
  }
  return param_1;
}



// Library Function - Multiple Matches With Different Base Names
//  public: class CPoint __thiscall CDC::MoveTo(int,int)
//  public: virtual class CPoint __thiscall CDC::OffsetViewportOrg(int,int)
//  public: class CPoint __thiscall CDC::OffsetWindowOrg(int,int)
//  public: virtual class CSize __thiscall CDC::SetViewportExt(int,int)
//   7 names - too many to list
// 
// Library: Visual Studio 2008 Release

undefined4 __thiscall
FID_conflict_OffsetWindowOrg(void *this,undefined4 param_1,undefined4 param_2,undefined4 param_3)

{
  code *pcVar1;
  
  pcVar1 = DAT_00428050;
  if (*(int *)((int)this + 4) != *(int *)((int)this + 8)) {
    (*DAT_00428050)(*(int *)((int)this + 4),param_2,param_3,param_1);
  }
  if (*(int *)((int)this + 8) != 0) {
    (*pcVar1)(*(int *)((int)this + 8),param_2,param_3,param_1);
  }
  return param_1;
}



// Library Function - Multiple Matches With Different Base Names
//  public: class CPoint __thiscall CDC::MoveTo(int,int)
//  public: virtual class CPoint __thiscall CDC::OffsetViewportOrg(int,int)
//  public: class CPoint __thiscall CDC::OffsetWindowOrg(int,int)
//  public: virtual class CSize __thiscall CDC::SetViewportExt(int,int)
//   7 names - too many to list
// 
// Library: Visual Studio 2008 Release

undefined4 __thiscall
FID_conflict_OffsetWindowOrg(void *this,undefined4 param_1,undefined4 param_2,undefined4 param_3)

{
  code *pcVar1;
  
  pcVar1 = DAT_0042804c;
  if (*(int *)((int)this + 4) != *(int *)((int)this + 8)) {
    (*DAT_0042804c)(*(int *)((int)this + 4),param_2,param_3,param_1);
  }
  if (*(int *)((int)this + 8) != 0) {
    (*pcVar1)(*(int *)((int)this + 8),param_2,param_3,param_1);
  }
  return param_1;
}



// Library Function - Multiple Matches With Different Base Names
//  public: virtual class CSize __thiscall CDC::ScaleViewportExt(int,int,int,int)
//  public: virtual class CSize __thiscall CDC::ScaleWindowExt(int,int,int,int)
// 
// Library: Visual Studio 2008 Release

undefined4 __thiscall
FID_conflict_ScaleWindowExt
          (void *this,undefined4 param_1,undefined4 param_2,undefined4 param_3,undefined4 param_4,
          undefined4 param_5)

{
  code *pcVar1;
  
  pcVar1 = DAT_00428034;
  if (*(int *)((int)this + 4) != *(int *)((int)this + 8)) {
    (*DAT_00428034)(*(int *)((int)this + 4),param_2,param_3,param_4,param_5,param_1);
  }
  if (*(int *)((int)this + 8) != 0) {
    (*pcVar1)(*(int *)((int)this + 8),param_2,param_3,param_4,param_5,param_1);
  }
  return param_1;
}



// Library Function - Multiple Matches With Different Base Names
//  public: class CPoint __thiscall CDC::MoveTo(int,int)
//  public: virtual class CPoint __thiscall CDC::OffsetViewportOrg(int,int)
//  public: class CPoint __thiscall CDC::OffsetWindowOrg(int,int)
//  public: virtual class CSize __thiscall CDC::SetViewportExt(int,int)
//   7 names - too many to list
// 
// Library: Visual Studio 2008 Release

undefined4 __thiscall
FID_conflict_OffsetWindowOrg(void *this,undefined4 param_1,undefined4 param_2,undefined4 param_3)

{
  code *pcVar1;
  
  pcVar1 = DAT_00428030;
  if (*(int *)((int)this + 4) != *(int *)((int)this + 8)) {
    (*DAT_00428030)(*(int *)((int)this + 4),param_2,param_3,param_1);
  }
  if (*(int *)((int)this + 8) != 0) {
    (*pcVar1)(*(int *)((int)this + 8),param_2,param_3,param_1);
  }
  return param_1;
}



// Library Function - Multiple Matches With Different Base Names
//  public: virtual class CSize __thiscall CDC::ScaleViewportExt(int,int,int,int)
//  public: virtual class CSize __thiscall CDC::ScaleWindowExt(int,int,int,int)
// 
// Library: Visual Studio 2008 Release

undefined4 __thiscall
FID_conflict_ScaleWindowExt
          (void *this,undefined4 param_1,undefined4 param_2,undefined4 param_3,undefined4 param_4,
          undefined4 param_5)

{
  code *pcVar1;
  
  pcVar1 = DAT_00428048;
  if (*(int *)((int)this + 4) != *(int *)((int)this + 8)) {
    (*DAT_00428048)(*(int *)((int)this + 4),param_2,param_3,param_4,param_5,param_1);
  }
  if (*(int *)((int)this + 8) != 0) {
    (*pcVar1)(*(int *)((int)this + 8),param_2,param_3,param_4,param_5,param_1);
  }
  return param_1;
}



// Library Function - Single Match
//  public: static void __stdcall ConstructDestruct<class CDC>::Construct(class CObject *)
// 
// Libraries: Visual Studio 2008 Release, Visual Studio 2010 Release

void ConstructDestruct<class_CDC>::Construct(CObject *param_1)

{
  if (param_1 != (CObject *)0x0) {
    *(undefined **)param_1 = &DAT_00429bb4;
    *(undefined4 *)(param_1 + 4) = 0;
    *(undefined4 *)(param_1 + 8) = 0;
    *(undefined4 *)(param_1 + 0xc) = 0;
  }
  return;
}



void FUN_00411d7e(undefined4 *param_1)

{
  if (param_1 != (undefined4 *)0x0) {
    param_1[1] = 0;
    *param_1 = &DAT_00429a40;
  }
  return;
}



// WARNING: Control flow encountered bad instruction data

void FUN_00411e0c(void)

{
  func_0x8f4e1fce(1);
                    // WARNING: Bad instruction - Truncating control flow here
  halt_baddata();
}



// WARNING: Control flow encountered bad instruction data

void FUN_00411ee0(void)

{
  func_0x634f20a2(1);
                    // WARNING: Bad instruction - Truncating control flow here
  halt_baddata();
}



void * __thiscall FUN_00411f36(void *this,byte param_1)

{
  func_0x4a4f20f9();
  if ((param_1 & 1) != 0) {
    func_0x15bb2005(this);
  }
  return this;
}



// Library Function - Single Match
//  public: virtual class CGdiObject * __thiscall CDC::SelectStockObject(int)
// 
// Libraries: Visual Studio 2008 Release, Visual Studio 2010 Release

CGdiObject * __thiscall CDC::SelectStockObject(CDC *this,int param_1)

{
  code *pcVar1;
  undefined4 uVar2;
  undefined4 uVar3;
  CGdiObject *pCVar4;
  
  uVar2 = (*(code *)s_InitCommonControlsEx_00428017._1_4_)(param_1);
  pcVar1 = DAT_00428058;
  uVar3 = 0;
  if (*(int *)(this + 4) != *(int *)(this + 8)) {
    uVar3 = (*DAT_00428058)(*(int *)(this + 4),uVar2);
  }
  if (*(int *)(this + 8) != 0) {
    uVar3 = (*pcVar1)(*(int *)(this + 8),uVar2);
  }
  pCVar4 = (CGdiObject *)func_0xd74f2147(uVar3);
  return pCVar4;
}



// Library Function - Multiple Matches With Same Base Name
//  public: class CBrush * __thiscall CDC::SelectObject(class CBrush *)
//  public: class CPen * __thiscall CDC::SelectObject(class CPen *)
//  public: virtual class CFont * __thiscall CDC::SelectObject(class CFont *)
// 
// Libraries: Visual Studio 2008 Release, Visual Studio 2010 Release

HGDIOBJ SelectObject(HDC hdc,HGDIOBJ h)

{
  code *pcVar1;
  int iVar2;
  HGDIOBJ pvVar3;
  int in_ECX;
  
  pcVar1 = DAT_00428058;
  iVar2 = 0;
  if (*(int *)(in_ECX + 4) != *(int *)(in_ECX + 8)) {
    if (hdc != (HDC)0x0) {
      iVar2 = hdc[1].unused;
    }
    iVar2 = (*DAT_00428058)(*(int *)(in_ECX + 4),iVar2);
  }
  if (*(int *)(in_ECX + 8) != 0) {
    if (hdc == (HDC)0x0) {
      iVar2 = 0;
    }
    else {
      iVar2 = hdc[1].unused;
    }
    iVar2 = (*pcVar1)(*(int *)(in_ECX + 8),iVar2);
  }
  pvVar3 = (HGDIOBJ)func_0xd74f2192(iVar2);
  return pvVar3;
}



void FUN_00411fe6(void)

{
  int iVar1;
  
  iVar1 = func_0x79dc20a6();
  if ((iVar1 != 0) && (*(code **)(iVar1 + 0x3c) != (code *)0x0)) {
    (**(code **)(iVar1 + 0x3c))(1,1);
  }
                    // WARNING: Could not recover jumptable at 0x00412002. Too many branches
                    // WARNING: Treating indirect jump as call
  (*DAT_0042839c)();
  return;
}



void FUN_004120c9(undefined4 param_1)

{
  int iVar1;
  
  iVar1 = func_0x59d12189();
  *(undefined4 *)(iVar1 + 0x30) = param_1;
  return;
}



int __thiscall FUN_00412142(void *this,int param_1)

{
  code *pcVar1;
  int iVar2;
  
  if ((-1 < param_1) && (param_1 < *(int *)((int)this + 8))) {
    return *(int *)((int)this + 4) + param_1 * 4;
  }
  func_0xecbc2218();
  pcVar1 = (code *)swi(3);
  iVar2 = (*pcVar1)();
  return iVar2;
}



undefined4 __thiscall FUN_00412163(void *this,int param_1)

{
  code *pcVar1;
  undefined4 uVar2;
  
  if ((-1 < param_1) && (param_1 < *(int *)((int)this + 8))) {
    return *(undefined4 *)(*(int *)((int)this + 4) + param_1 * 4);
  }
  func_0xecbc2239();
  pcVar1 = (code *)swi(3);
  uVar2 = (*pcVar1)();
  return uVar2;
}



// WARNING: Control flow encountered bad instruction data
// Library Function - Multiple Matches With Same Base Name
//  public: void __thiscall CArray<int,int const &>::SetSize(int,int)
//  public: void __thiscall CArray<struct HWND__ *,struct HWND__ *>::SetSize(int,int)
//  public: void __thiscall CArray<enum CArchive::LoadArrayObjType,enum CArchive::LoadArrayObjType
// const &>::SetSize(int,int)
// 
// Library: Visual Studio 2008 Release

void __thiscall SetSize(void *this,int param_1,int param_2)

{
  int iVar1;
  undefined4 uVar2;
  int iVar3;
  int iVar4;
  int unaff_EDI;
  
  iVar1 = param_1;
  iVar4 = unaff_EDI;
  if (-1 < param_1) goto LAB_004121c4;
  while( true ) {
    func_0xecbc227a();
    iVar4 = unaff_EDI;
LAB_004121c4:
    if (-1 < param_2) {
      *(int *)((int)this + 0x10) = param_2;
    }
    if (iVar1 == 0) {
      if (*(int *)((int)this + 4) != 0) {
        func_0x15bb2295(*(int *)((int)this + 4));
        *(undefined4 *)((int)this + 4) = 0;
      }
      *(undefined4 *)((int)this + 0xc) = 0;
      *(undefined4 *)((int)this + 8) = 0;
                    // WARNING: Bad instruction - Truncating control flow here
      halt_baddata();
    }
    if (*(int *)((int)this + 4) == 0) {
      iVar4 = *(int *)((int)this + 0x10);
      if (*(int *)((int)this + 0x10) < iVar1) {
        iVar4 = iVar1;
      }
      uVar2 = func_0xdbba22c2(iVar4 << 2);
      *(undefined4 *)((int)this + 4) = uVar2;
      func_0x3b8323d3(uVar2,0,iVar4 << 2);
      *(int *)((int)this + 0xc) = iVar4;
                    // WARNING: Bad instruction - Truncating control flow here
      halt_baddata();
    }
    unaff_EDI = *(int *)((int)this + 0xc);
    if (iVar1 <= unaff_EDI) break;
    iVar3 = *(int *)((int)this + 0x10);
    if (iVar3 == 0) {
      iVar3 = (int)(*(int *)((int)this + 8) + (*(int *)((int)this + 8) >> 0x1f & 7U)) >> 3;
      if (iVar3 < 4) {
        iVar3 = 4;
      }
      else if (0x400 < iVar3) {
        iVar3 = 0x400;
      }
    }
    param_1 = iVar3 + unaff_EDI;
    if (iVar3 + unaff_EDI <= iVar1) {
      param_1 = iVar1;
    }
    if (unaff_EDI <= param_1) {
      iVar4 = func_0xdbba2353(param_1 << 2,iVar4);
      func_0x53d5236c(iVar4,param_1 << 2,*(undefined4 *)((int)this + 4),*(int *)((int)this + 8) << 2
                     );
      func_0x3b832482(iVar4 + *(int *)((int)this + 8) * 4,0,(iVar1 - *(int *)((int)this + 8)) * 4);
      func_0x15bb238a(*(undefined4 *)((int)this + 4));
      *(int *)((int)this + 4) = iVar4;
      *(int *)((int)this + 0xc) = param_1;
LAB_004122e0:
      *(int *)((int)this + 8) = iVar1;
      return;
    }
  }
  iVar4 = *(int *)((int)this + 8);
  if (iVar4 < iVar1) {
    func_0x3b832403(*(int *)((int)this + 4) + iVar4 * 4,0,(iVar1 - iVar4) * 4);
                    // WARNING: Bad instruction - Truncating control flow here
    halt_baddata();
  }
  goto LAB_004122e0;
}



// Library Function - Single Match
//  public: void __thiscall CArray<enum CArchive::LoadArrayObjType,enum CArchive::LoadArrayObjType
// const &>::InsertAt(int,enum CArchive::LoadArrayObjType const &,int)
// 
// Library: Visual Studio 2008 Release

void __thiscall
CArray<enum_CArchive::LoadArrayObjType,enum_CArchive::LoadArrayObjType_const&>::InsertAt
          (CArray<enum_CArchive::LoadArrayObjType,enum_CArchive::LoadArrayObjType_const&> *this,
          int param_1,LoadArrayObjType *param_2,int param_3)

{
  code *pcVar1;
  int iVar2;
  
  if ((-1 < param_1) && (0 < param_3)) {
    if (param_1 < *(int *)(this + 8)) {
      iVar2 = *(int *)(this + 8);
      func_0xa65224da(iVar2 + param_3,0xffffffff);
      iVar2 = (iVar2 - param_1) * 4;
      func_0xa0e12402(*(int *)(this + 4) + (param_1 + param_3) * 4,iVar2,
                      *(int *)(this + 4) + param_1 * 4,iVar2);
      func_0x3b832515(*(int *)(this + 4) + param_1 * 4,0,param_3 << 2);
    }
    else {
      func_0xa65224cc(param_1 + param_3);
    }
    iVar2 = param_1 << 2;
    do {
      param_3 = param_3 + -1;
      *(LoadArrayObjType *)(iVar2 + *(int *)(this + 4)) = *param_2;
      iVar2 = iVar2 + 4;
    } while (param_3 != 0);
    return;
  }
  func_0xecbc243f();
  pcVar1 = (code *)swi(3);
  (*pcVar1)();
  return;
}



void * __thiscall FUN_0041239f(void *this,byte param_1)

{
  func_0x81542562();
  if ((param_1 & 1) != 0) {
    func_0x15bb246e(this);
  }
  return this;
}



// Library Function - Multiple Matches With Same Base Name
//  void __stdcall SerializeElements<int>(class CArchive &,int *,int)
//  void __stdcall SerializeElements<struct HWND__ *>(class CArchive &,struct HWND__ * *,int)
//  void __stdcall SerializeElements<class IControlSiteFactory *>(class CArchive &,class
// IControlSiteFactory * *,int)
//  void __stdcall SerializeElements<enum CArchive::LoadArrayObjType>(class CArchive &,enum
// CArchive::LoadArrayObjType *,int)
// 
// Library: Visual Studio 2008 Release

void SerializeElements<>(int param_1,int param_2,uint param_3)

{
  int extraout_ECX;
  uint uVar1;
  
  if ((param_3 != 0) && (param_2 == 0)) {
    param_3 = func_0xecbc248e();
    param_2 = extraout_ECX;
  }
  if ((~*(uint *)(param_1 + 0x18) & 1) == 0) {
    for (; param_3 != 0; param_3 = param_3 - uVar1) {
      uVar1 = 0x1fffffff;
      if (param_3 < 0x1fffffff) {
        uVar1 = param_3;
      }
      func_0x97e724ee(param_2,uVar1 * 4);
      param_2 = param_2 + uVar1 * 4;
    }
  }
  else {
    for (; param_3 != 0; param_3 = param_3 - uVar1) {
      uVar1 = 0x1fffffff;
      if (param_3 < 0x1fffffff) {
        uVar1 = param_3;
      }
      func_0x2ee624c3(param_2,uVar1 * 4);
      param_2 = param_2 + uVar1 * 4;
    }
  }
  return;
}



// Library Function - Single Match
//  public: void __thiscall CArchive::WriteClass(struct CRuntimeClass const *)
// 
// Library: Visual Studio 2008 Release

void __thiscall CArchive::WriteClass(CArchive *this,CRuntimeClass *param_1)

{
  uint uVar1;
  uint *puVar2;
  undefined4 *puVar3;
  undefined4 uVar4;
  undefined4 uVar5;
  
  if (param_1 != (CRuntimeClass *)0x0) goto LAB_00412676;
  uVar5 = *(undefined4 *)(this + 0x14);
  uVar4 = 6;
  while( true ) {
    func_0xe1e8272c(uVar4,uVar5);
LAB_00412676:
    if ((~*(uint *)(this + 0x18) & 1) != 0) break;
    uVar5 = *(undefined4 *)(this + 0x14);
    uVar4 = 1;
  }
  if (*(int *)(param_1 + 8) == 0xffff) {
    func_0xd0bc274a();
  }
  func_0x13562851(0);
  puVar2 = (uint *)func_0xc4da275a(param_1);
  uVar1 = *puVar2;
  if (uVar1 == 0) {
    func_0x59e42799(0xffff);
    func_0x5ae727a1(this);
    func_0x7b5228a8();
    puVar3 = (undefined4 *)func_0xc4da27b1(param_1);
    *puVar3 = *(undefined4 *)(this + 0x34);
    *(int *)(this + 0x34) = *(int *)(this + 0x34) + 1;
  }
  else if (uVar1 < 0x7fff) {
    func_0x59e42777(uVar1 | 0x8000);
  }
  else {
    func_0x59e4277f(0x7fff);
    func_0x98e4278d(uVar1 | 0x80000000);
  }
  return;
}



// WARNING: Control flow encountered bad instruction data
// Library Function - Single Match
//  public: struct CRuntimeClass * __thiscall CArchive::ReadClass(struct CRuntimeClass const
// *,unsigned int *,unsigned long *)
// 
// Library: Visual Studio 2008 Release

CRuntimeClass * __thiscall
CArchive::ReadClass(CArchive *this,CRuntimeClass *param_1,uint *param_2,ulong *param_3)

{
  uint *puVar1;
  int *piVar2;
  int iVar3;
  CRuntimeClass *pCVar4;
  uint uVar5;
  undefined4 uVar6;
  undefined4 uVar7;
  int local_14;
  uint local_10;
  uint local_c;
  uint local_8;
  
  if (((byte)this[0x18] & 1) != 0) goto LAB_00412727;
  uVar7 = *(undefined4 *)(this + 0x14);
  uVar6 = 1;
  do {
    func_0xe1e827dd(uVar6,uVar7);
LAB_00412727:
    pCVar4 = (CRuntimeClass *)0xffff;
    if ((param_1 != (CRuntimeClass *)0x0) && (*(int *)(param_1 + 8) == 0xffff)) {
      func_0xd0bc27f3();
    }
    func_0x135628fa(0);
    func_0xd6e42805(&local_8);
    if ((short)local_8 == 0x7fff) {
      func_0x1ee5281b(&local_10);
    }
    else {
      local_10 = (local_8 & 0x8000) << 0x10 | local_8 & 0x7fff;
    }
    if ((local_10 & 0x80000000) == 0) {
      if (param_3 != (ulong *)0x0) {
        *param_3 = local_10;
                    // WARNING: Bad instruction - Truncating control flow here
        halt_baddata();
      }
    }
    else {
      if ((short)local_8 == -1) {
        pCVar4 = (CRuntimeClass *)func_0xb7e5286c(this,&local_c);
        if (pCVar4 == (CRuntimeClass *)0x0) {
          return;
        }
        if ((*(uint *)(pCVar4 + 8) & 0x7fffffff) != local_c) {
          if ((*(uint *)(pCVar4 + 8) & 0x80000000) == 0) {
                    // WARNING: Bad instruction - Truncating control flow here
            halt_baddata();
          }
          func_0x3f5529a3(0);
          uVar5 = local_c;
          puVar1 = (uint *)func_0xc4da28af(pCVar4);
          *puVar1 = uVar5;
        }
        func_0x7b5229b8();
        uVar5 = 1;
        func_0x805d29c8(*(undefined4 *)(this + 0x34),pCVar4,1);
        local_14 = 0;
        func_0x42d928d9(1,&local_14);
        if (local_14 == 0) {
LAB_0041282a:
          func_0xecbc28e5();
        }
        local_8 = uVar5;
        func_0xe15329f5(*(undefined4 *)(this + 0x34),&local_8,uVar5);
        *(int *)(this + 0x34) = *(int *)(this + 0x34) + 1;
LAB_004128c0:
        if ((param_1 != (CRuntimeClass *)0x0) && (iVar3 = func_0x70bb2986(param_1), iVar3 == 0)) {
                    // WARNING: Bad instruction - Truncating control flow here
          halt_baddata();
        }
        if (param_2 == (uint *)0x0) {
          *(uint *)(this + 0x10) = local_c;
        }
        else {
          *param_2 = local_c;
        }
        if (param_3 != (ulong *)0x0) {
          *param_3 = local_10;
        }
        return pCVar4;
      }
      uVar5 = local_10 & 0x7fffffff;
      if ((uVar5 != 0) && (uVar5 <= *(int *)(*(int *)(this + 0x38) + 8) - 1U)) {
        local_8 = 0;
        func_0x42d9292c(1,&local_8);
        if (local_8 == 0) goto LAB_0041282a;
        piVar2 = (int *)func_0x39522a39(uVar5);
        if (*piVar2 != 2) {
          pCVar4 = (CRuntimeClass *)func_0x5a522a4b(uVar5);
          local_c = 0;
          if ((*(int *)(this + 0x3c) == 0) ||
             (iVar3 = func_0x42d92962(pCVar4,&local_8), local_c = local_8, iVar3 == 0)) {
            local_c = *(uint *)(pCVar4 + 8) & 0x7fffffff;
          }
          goto LAB_004128c0;
        }
      }
    }
    uVar7 = *(undefined4 *)(this + 0x14);
    uVar6 = 5;
  } while( true );
}



// Library Function - Multiple Matches With Same Base Name
//  public: virtual void __thiscall CArray<int,int const &>::Serialize(class CArchive &)
//  public: virtual void __thiscall CArray<int,int>::Serialize(class CArchive &)
//  public: virtual void __thiscall CArray<unsigned int,unsigned int>::Serialize(class CArchive &)
//  public: virtual void __thiscall CArray<long,long>::Serialize(class CArchive &)
//   24 names - too many to list
// 
// Libraries: Visual Studio 2008 Release, Visual Studio 2010 Release

void __thiscall Serialize(void *this,int param_1)

{
  undefined4 uVar1;
  
  if ((~*(uint *)(param_1 + 0x18) & 1) == 0) {
    uVar1 = func_0x26e729da();
    func_0xa6522ae4(uVar1,0xffffffff);
  }
  else {
    func_0xf5e629d3(*(undefined4 *)((int)this + 8));
  }
  func_0xb7542af0(param_1,*(undefined4 *)((int)this + 4),*(undefined4 *)((int)this + 8));
  return;
}



// Library Function - Single Match
//  public: void __thiscall CArchive::WriteObject(class CObject const *)
// 
// Library: Visual Studio 2008 Release

void __thiscall CArchive::WriteObject(CArchive *this,CObject *param_1)

{
  uint uVar1;
  uint *puVar2;
  undefined4 uVar3;
  undefined4 *puVar4;
  
  if ((~*(uint *)(this + 0x18) & 1) == 0) {
    func_0xe1e82a12(2,*(undefined4 *)(this + 0x14));
  }
  func_0x13562b19(0);
  if (param_1 == (CObject *)0x0) {
    func_0x59e42a28(0);
  }
  else {
    puVar2 = (uint *)func_0xc4da2a34(param_1);
    uVar1 = *puVar2;
    if (uVar1 == 0) {
      uVar3 = (***(code ***)param_1)();
      func_0x52572b6b(uVar3);
      func_0x7b522b72();
      puVar4 = (undefined4 *)func_0xc4da2a7b(param_1);
      *puVar4 = *(undefined4 *)(this + 0x34);
      *(int *)(this + 0x34) = *(int *)(this + 0x34) + 1;
      (**(code **)(*(int *)param_1 + 8))(this);
    }
    else if (uVar1 < 0x7fff) {
      func_0x59e42a4b(uVar1);
    }
    else {
      func_0x59e42a53(0x7fff);
      func_0x98e42a5b(uVar1);
    }
  }
  return;
}



// WARNING: Control flow encountered bad instruction data
// Library Function - Multiple Matches With Same Base Name
//  public: void __thiscall CDWordArray::SetSize(int,int)
//  public: void __thiscall CObArray::SetSize(int,int)
//  public: void __thiscall CPtrArray::SetSize(int,int)
//  public: void __thiscall CUIntArray::SetSize(int,int)
// 
// Libraries: Visual Studio 2005 Release, Visual Studio 2008 Release

void __thiscall SetSize(void *this,int param_1,int param_2)

{
  int iVar1;
  undefined4 uVar2;
  int iVar3;
  int iVar4;
  
  iVar1 = param_1;
  iVar4 = 0;
  if (-1 < param_1) goto LAB_00412b7b;
  do {
    func_0xecbc2c31();
LAB_00412b7b:
    if (iVar4 <= param_2) {
      *(int *)((int)this + 0x10) = param_2;
    }
    if (iVar1 == iVar4) {
      func_0x15bb2c47(*(undefined4 *)((int)this + 4));
      *(int *)((int)this + 0xc) = iVar4;
      *(int *)((int)this + 8) = iVar4;
                    // WARNING: Bad instruction - Truncating control flow here
      halt_baddata();
    }
    if (*(int *)((int)this + 4) == iVar4) {
      uVar2 = func_0xdbba2c65(iVar1 << 2);
      *(undefined4 *)((int)this + 4) = uVar2;
      func_0x3b832d71(uVar2,0,iVar1 << 2);
      *(int *)((int)this + 0xc) = iVar1;
LAB_00412be7:
      *(int *)((int)this + 8) = iVar1;
                    // WARNING: Bad instruction - Truncating control flow here
      halt_baddata();
    }
    iVar4 = *(int *)((int)this + 0xc);
    if (iVar1 <= iVar4) {
      iVar4 = *(int *)((int)this + 8);
      if (iVar4 < iVar1) {
        func_0x3b832d9a(*(int *)((int)this + 4) + iVar4 * 4,0,(iVar1 - iVar4) * 4);
      }
      goto LAB_00412be7;
    }
    iVar3 = *(int *)((int)this + 0x10);
    if (iVar3 == 0) {
      iVar3 = (int)(*(int *)((int)this + 8) + (*(int *)((int)this + 8) >> 0x1f & 7U)) >> 3;
      if (iVar3 < 4) {
LAB_00412c19:
        iVar3 = 4;
      }
      else if (iVar3 < 0x401) {
        if (iVar3 < 4) goto LAB_00412c19;
      }
      else {
        iVar3 = 0x400;
      }
    }
    param_1 = iVar3 + iVar4;
    if (iVar3 + iVar4 <= iVar1) {
      param_1 = iVar1;
    }
    if (iVar4 <= param_1) {
      iVar4 = func_0xdbba2cf2(param_1 << 2);
      func_0x53d52d0b(iVar4,param_1 << 2,*(undefined4 *)((int)this + 4),*(int *)((int)this + 8) << 2
                     );
      func_0x3b832e21(iVar4 + *(int *)((int)this + 8) * 4,0,(iVar1 - *(int *)((int)this + 8)) * 4);
      func_0x15bb2d29(*(undefined4 *)((int)this + 4));
      *(int *)((int)this + 8) = iVar1;
      *(int *)((int)this + 0xc) = param_1;
      *(int *)((int)this + 4) = iVar4;
      return;
    }
  } while( true );
}



// Library Function - Multiple Matches With Same Base Name
//  public: void __thiscall CDWordArray::InsertAt(int,unsigned long,int)
//  public: void __thiscall CObArray::InsertAt(int,class CObject *,int)
//  public: void __thiscall CPtrArray::InsertAt(int,void *,int)
//  public: void __thiscall CUIntArray::InsertAt(int,unsigned int,int)
// 
// Library: Visual Studio 2008 Release

void __thiscall InsertAt(void *this,int param_1,undefined4 param_2,int param_3)

{
  code *pcVar1;
  int iVar2;
  
  if ((-1 < param_1) && (0 < param_3)) {
    if (param_1 < *(int *)((int)this + 8)) {
      iVar2 = *(int *)((int)this + 8);
      func_0x5a5c2e7d(iVar2 + param_3,0xffffffff);
      func_0xa0e12da3(*(int *)((int)this + 4) + (param_1 + param_3) * 4,
                      ((*(int *)((int)this + 8) - param_1) - param_3) * 4,
                      *(int *)((int)this + 4) + param_1 * 4,(iVar2 - param_1) * 4);
      func_0x3b832ebc(*(int *)((int)this + 4) + param_1 * 4,0,param_3 << 2);
    }
    else {
      func_0x5a5c2e6f(param_1 + param_3);
    }
    iVar2 = param_1 << 2;
    do {
      param_3 = param_3 + -1;
      *(undefined4 *)(iVar2 + *(int *)((int)this + 4)) = param_2;
      iVar2 = iVar2 + 4;
    } while (param_3 != 0);
    return;
  }
  func_0xecbc2de4();
  pcVar1 = (code *)swi(3);
  (*pcVar1)();
  return;
}



void * __thiscall FUN_00412d2f(void *this,byte param_1)

{
  func_0x4a5c2ef2();
  if ((param_1 & 1) != 0) {
    func_0x15bb2dfe(this);
  }
  return this;
}



undefined4 FUN_00412d56(undefined4 param_1,undefined4 param_2)

{
  func_0x375a2f1c(param_2);
  return param_1;
}



undefined4 FUN_00412d6d(undefined4 param_1,undefined4 *param_2)

{
  undefined4 uVar1;
  
  uVar1 = func_0xd35a2f32(0);
  *param_2 = uVar1;
  return param_1;
}



// Library Function - Single Match
//  public: virtual void __thiscall CObArray::Serialize(class CArchive &)
// 
// Library: Visual Studio 2008 Release

void __thiscall CObArray::Serialize(CObArray *this,CArchive *param_1)

{
  undefined4 uVar1;
  int iVar2;
  
  if ((~*(uint *)(param_1 + 0x18) & 1) == 0) {
    uVar1 = func_0x26e72ea5();
    func_0x5a5c2faf(uVar1,0xffffffff);
    iVar2 = 0;
    if (0 < *(int *)(this + 8)) {
      do {
        func_0x645e2fc3(param_1,*(int *)(this + 4) + iVar2 * 4);
        iVar2 = iVar2 + 1;
      } while (iVar2 < *(int *)(this + 8));
    }
  }
  else {
    func_0xf5e62e85(*(undefined4 *)(this + 8));
    iVar2 = 0;
    if (0 < *(int *)(this + 8)) {
      do {
        func_0x4d5e2f98(param_1,*(undefined4 *)(*(int *)(this + 4) + iVar2 * 4));
        iVar2 = iVar2 + 1;
      } while (iVar2 < *(int *)(this + 8));
    }
  }
  return;
}



void * __thiscall FUN_00412e30(void *this,byte param_1)

{
  func_0x965e2ff3();
  if ((param_1 & 1) != 0) {
    func_0x15bb2eff(this);
  }
  return this;
}



// Library Function - Single Match
//  _wcscat_s
// 
// Library: Visual Studio 2008 Release

errno_t __cdecl _wcscat_s(wchar_t *_Dst,rsize_t _SizeInWords,wchar_t *_Src)

{
  wchar_t wVar1;
  undefined4 *puVar2;
  wchar_t *pwVar3;
  errno_t eVar4;
  
  if ((_Dst != (wchar_t *)0x0) && (_SizeInWords != 0)) {
    pwVar3 = _Dst;
    if (_Src != (wchar_t *)0x0) {
      do {
        if (*pwVar3 == L'\0') break;
        pwVar3 = pwVar3 + 1;
        _SizeInWords = _SizeInWords - 1;
      } while (_SizeInWords != 0);
      if (_SizeInWords != 0) {
        do {
          wVar1 = *_Src;
          *pwVar3 = wVar1;
          pwVar3 = pwVar3 + 1;
          _Src = _Src + 1;
          if (wVar1 == L'\0') break;
          _SizeInWords = _SizeInWords - 1;
        } while (_SizeInWords != 0);
        if (_SizeInWords != 0) {
          return 0;
        }
        *_Dst = L'\0';
        puVar2 = (undefined4 *)func_0x7886308a();
        eVar4 = 0x22;
        *puVar2 = 0x22;
        goto LAB_00412e82;
      }
    }
    *_Dst = L'\0';
  }
  puVar2 = (undefined4 *)func_0x78863033();
  eVar4 = 0x16;
  *puVar2 = 0x16;
LAB_00412e82:
  func_0x53aa3042(0,0,0,0,0);
  return eVar4;
}



// Library Function - Single Match
//  _wcscpy_s
// 
// Library: Visual Studio 2008 Release

errno_t __cdecl _wcscpy_s(wchar_t *_Dst,rsize_t _SizeInWords,wchar_t *_Src)

{
  wchar_t wVar1;
  undefined4 *puVar2;
  wchar_t *pwVar3;
  errno_t eVar4;
  
  if ((_Dst != (wchar_t *)0x0) && (_SizeInWords != 0)) {
    pwVar3 = _Dst;
    if (_Src != (wchar_t *)0x0) {
      do {
        wVar1 = *_Src;
        *pwVar3 = wVar1;
        _Src = _Src + 1;
        if (wVar1 == L'\0') break;
        _SizeInWords = _SizeInWords - 1;
        pwVar3 = pwVar3 + 1;
      } while (_SizeInWords != 0);
      if (_SizeInWords != 0) {
        return 0;
      }
      *_Dst = L'\0';
      puVar2 = (undefined4 *)func_0x788630f9();
      eVar4 = 0x22;
      *puVar2 = 0x22;
      goto LAB_00412eff;
    }
    *_Dst = L'\0';
  }
  puVar2 = (undefined4 *)func_0x788630b0();
  eVar4 = 0x16;
  *puVar2 = 0x16;
LAB_00412eff:
  func_0x53aa30bf(0,0,0,0,0);
  return eVar4;
}



void __cdecl FUN_00412f4c(undefined4 param_1)

{
  int iVar1;
  
  iVar1 = func_0x40ad310c();
  *(undefined4 *)(iVar1 + 0x14) = param_1;
  return;
}



// WARNING: Control flow encountered bad instruction data
// WARNING: Globals starting with '_' overlap smaller symbols at the same address

undefined4 * __cdecl FUN_00412f94(undefined4 *param_1,undefined4 *param_2,uint param_3)

{
  uint *puVar1;
  undefined4 *puVar2;
  uint uVar3;
  undefined4 *puVar4;
  uint uVar5;
  uint uVar6;
  undefined *unaff_EBX;
  undefined4 *puVar7;
  undefined4 *puVar8;
  
  puVar2 = (undefined4 *)(param_3 + (int)param_2);
  if ((param_2 < param_1) && (param_1 < puVar2)) {
    puVar7 = (undefined4 *)((param_3 - 4) + (int)param_2);
    puVar8 = (undefined4 *)((param_3 - 4) + (int)param_1);
    if (((uint)puVar8 & 3) == 0) {
      uVar6 = param_3 >> 2;
      uVar5 = param_3 & 3;
      if (7 < uVar6) {
        for (; uVar6 != 0; uVar6 = uVar6 - 1) {
          *puVar8 = *puVar7;
          puVar7 = puVar7 + -1;
          puVar8 = puVar8 + -1;
        }
        param_3 = 0;
        puVar8 = puVar2;
        switch(uVar5) {
        case 0:
          return;
        case 2:
          goto code_r0x004132b9;
        case 3:
          goto switchD_00413177_caseD_3;
        }
        goto switchD_00413177_caseD_1;
      }
    }
    else {
      uVar5 = 3;
      switch(param_3) {
      case 0:
        goto switchD_00412ff0_caseD_0;
      case 1:
        goto switchD_00413177_caseD_1;
      case 2:
        goto code_r0x004132b9;
      case 3:
        goto switchD_00413177_caseD_3;
      default:
        puVar2 = (undefined4 *)((uint)puVar8 & 3);
        switch(puVar2) {
        case (undefined4 *)0x1:
                    // WARNING: Bad instruction - Truncating control flow here
          halt_baddata();
        case (undefined4 *)0x3:
          puVar1 = (uint *)((int)puVar2 + 0x468a0347);
          *puVar1 = *puVar1 >> 1 | (uint)((*puVar1 & 1) != 0) << 0x1f;
                    // WARNING: Bad instruction - Truncating control flow here
          halt_baddata();
        }
        uVar6 = (param_3 - (int)puVar2) + 1;
        DAT_d1230349 = DAT_d1230349 + (char)uVar6;
        *(char *)((int)puVar8 + 3) = (char)puVar2;
        puVar7 = (undefined4 *)((int)puVar7 + -1);
        uVar6 = uVar6 >> 2;
        puVar8 = (undefined4 *)((int)puVar8 - 1);
        if (7 < uVar6) {
          for (; uVar6 != 0; uVar6 = uVar6 - 1) {
            *puVar8 = *puVar7;
            puVar7 = puVar7 + -1;
            puVar8 = puVar8 + -1;
          }
          return puVar2;
        }
      }
    }
    param_3 = -uVar6;
                    // WARNING (jumptable): Sanity check requires truncation of jumptable
    puVar4 = puVar2;
    switch((&UINT_00413250)[-uVar6]) {
    case 0x413254:
      puVar4 = (undefined4 *)puVar7[7 - uVar6];
      puVar8 = puVar2;
    case 0x41325c:
      puVar8[7 - uVar6] = puVar4;
      puVar2 = (undefined4 *)puVar7[6 - uVar6];
    case 0x413264:
      puVar8[6 - uVar6] = puVar2;
      puVar2 = (undefined4 *)puVar7[5 - uVar6];
    case 0x41326c:
      puVar8[5 - uVar6] = puVar2;
      puVar2 = (undefined4 *)puVar7[4 - uVar6];
    case 0x413274:
      puVar8[4 - uVar6] = puVar2;
      puVar2 = (undefined4 *)puVar7[3 - uVar6];
    case 0x41327c:
      puVar8[3 - uVar6] = puVar2;
      puVar2 = (undefined4 *)puVar7[2 - uVar6];
    }
    puVar8[2 - uVar6] = puVar2;
    puVar8[1 - uVar6] = puVar7[1 - uVar6];
    puVar8 = (undefined4 *)(uVar6 * -4);
    switch(uVar5) {
    case 0:
      goto switchD_00412ff0_caseD_0;
    case 1:
switchD_00413177_caseD_1:
      unaff_EBX[0x5f5e0845] = unaff_EBX[0x5f5e0845] + (char)param_3 + '\x01';
      return puVar8;
    case 2:
code_r0x004132b9:
      return puVar8;
    default:
switchD_00413177_caseD_3:
      return puVar8;
    }
  }
  if (((0xff < param_3) && (DAT_00437ea4 != 0)) && (((uint)param_1 & 0xf) == ((uint)param_2 & 0xf)))
  {
                    // WARNING: Bad instruction - Truncating control flow here
    halt_baddata();
  }
  if (((uint)param_1 & 3) == 0) {
    uVar5 = param_3 >> 2;
    uVar6 = param_3 & 3;
    puVar8 = param_1;
    if (7 < uVar5) {
      for (; uVar5 != 0; uVar5 = uVar5 - 1) {
        *param_1 = *param_2;
        param_2 = param_2 + 1;
        param_1 = param_1 + 1;
      }
      uVar5 = 0;
      param_1 = puVar2;
      switch(uVar6) {
      case 0:
        return;
      case 2:
        goto code_r0x0041311d;
      case 3:
        goto switchD_00412ff0_caseD_3;
      }
      goto switchD_00412ff0_caseD_1;
    }
  }
  else {
    uVar6 = 3;
    uVar5 = param_3 - 4;
    switch(param_3) {
    case 0:
      goto switchD_00412ff0_caseD_0;
    case 1:
switchD_00412ff0_caseD_1:
      unaff_EBX[0x5f5e0845] = unaff_EBX[0x5f5e0845] + (char)uVar5 + '\x01';
      return param_1;
    case 2:
      goto code_r0x0041311d;
    case 3:
      goto switchD_00412ff0_caseD_3;
    default:
      uVar3 = (uint)param_1 & 3;
      uVar5 = uVar5 + uVar3;
      switch(uVar3) {
      case 1:
                    // WARNING: Bad instruction - Truncating control flow here
        halt_baddata();
      case 2:
        if (-1 < (int)uVar5) {
          *unaff_EBX = *unaff_EBX;
          _DAT_8a078809 = _DAT_8a078809 >> 1 | (uint)((_DAT_8a078809 & 1) != 0) << 0x1f;
          *(int *)(uVar3 + 0x468a0147) = *(int *)(uVar3 + 0x468a0147) + uVar5 + 1;
                    // WARNING: Bad instruction - Truncating control flow here
          halt_baddata();
        }
        break;
      case 3:
      }
      *(undefined *)param_1 = *(undefined *)param_2;
      puVar2 = (undefined4 *)(uint)*(byte *)((int)param_2 + 1);
      uVar5 = uVar5 >> 2;
      *(byte *)((int)param_1 + 1) = *(byte *)((int)param_2 + 1);
      param_2 = (undefined4 *)((int)param_2 + 2);
      puVar8 = (undefined4 *)((int)param_1 + 2);
      if (7 < uVar5) {
        for (; uVar5 != 0; uVar5 = uVar5 - 1) {
          *puVar8 = *param_2;
          param_2 = param_2 + 1;
          puVar8 = puVar8 + 1;
        }
        return puVar2;
      }
    }
  }
  param_1 = puVar2;
  switch((&switchD_00413018::switchdataD_00413098)[uVar5]) {
  case (undefined *)0x4130c0:
    puVar8[uVar5 - 7] = puVar2;
    puVar2 = (undefined4 *)param_2[uVar5 - 6];
  case (undefined *)0x4130c8:
    puVar8[uVar5 - 6] = puVar2;
    puVar2 = (undefined4 *)param_2[uVar5 - 5];
  case (undefined *)0x4130d0:
    puVar8[uVar5 - 5] = puVar2;
    puVar2 = (undefined4 *)param_2[uVar5 - 4];
  case (undefined *)0x4130d8:
    puVar8[uVar5 - 4] = puVar2;
    puVar2 = (undefined4 *)param_2[uVar5 - 3];
  case (undefined *)0x4130e0:
    puVar8[uVar5 - 3] = puVar2;
    puVar2 = (undefined4 *)param_2[uVar5 - 2];
  case (undefined *)0x4130e8:
    puVar8[uVar5 - 2] = puVar2;
    puVar8[uVar5 - 1] = param_2[uVar5 - 1];
    param_1 = (undefined4 *)(uVar5 * 4);
    break;
  case (undefined *)0x498d00:
                    // WARNING: Bad instruction - Truncating control flow here
    halt_baddata();
  }
  switch(uVar6) {
  case 0:
switchD_00412ff0_caseD_0:
                    // WARNING: Bad instruction - Truncating control flow here
    halt_baddata();
  case 1:
    goto switchD_00412ff0_caseD_1;
  case 2:
code_r0x0041311d:
    return param_1;
  default:
switchD_00412ff0_caseD_3:
    return param_1;
  }
}



// Library Function - Multiple Matches With Different Base Names
//  __wfopen_s
//  _fopen_s
// 
// Library: Visual Studio 2008 Release

errno_t __cdecl FID_conflict__fopen_s(FILE **_File,char *_Filename,char *_Mode)

{
  undefined4 *puVar1;
  FILE *pFVar2;
  errno_t eVar3;
  errno_t *peVar4;
  
  if (_File == (FILE **)0x0) {
    puVar1 = (undefined4 *)func_0x7886358a();
    eVar3 = 0x16;
    *puVar1 = 0x16;
    func_0x53aa3599(0,0,0,0,0);
  }
  else {
    pFVar2 = (FILE *)func_0xf06335b0(_Filename,_Mode,0x80);
    *_File = pFVar2;
    if (pFVar2 == (FILE *)0x0) {
      peVar4 = (errno_t *)func_0x788635c2();
      eVar3 = *peVar4;
    }
    else {
      eVar3 = 0;
    }
  }
  return eVar3;
}



// WARNING: Control flow encountered bad instruction data
// Library Function - Single Match
//  __fread_nolock_s
// 
// Library: Visual Studio 2008 Release

size_t __cdecl
__fread_nolock_s(void *_DstBuf,size_t _DstSize,size_t _ElementSize,size_t _Count,FILE *_File)

{
  undefined *puVar1;
  undefined4 *puVar2;
  uint uVar3;
  undefined4 uVar4;
  int iVar5;
  int iVar6;
  uint uVar7;
  uint uVar8;
  uint local_10;
  undefined *local_c;
  uint local_8;
  
  if ((_ElementSize != 0) && (_Count != 0)) {
    if (_DstBuf != (void *)0x0) {
      if ((_File != (FILE *)0x0) && (_Count <= (uint)(0xffffffff / (ulonglong)_ElementSize))) {
LAB_0041348d:
        uVar8 = _ElementSize * _Count;
        puVar1 = (undefined *)_DstBuf;
        local_8 = _DstSize;
        if ((_File->_flag & 0x10cU) == 0) {
          local_10 = 0x1000;
        }
        else {
          local_10 = _File->_bufsiz;
        }
        do {
          if (uVar8 == 0) {
                    // WARNING: Bad instruction - Truncating control flow here
            halt_baddata();
          }
          if ((_File->_flag & 0x10cU) != 0) {
            uVar3 = _File->_cnt;
            if (uVar3 != 0) {
              if (-1 < (int)uVar3) {
                if (uVar3 <= uVar8) {
                  uVar8 = uVar3;
                }
                if (local_8 < uVar8) {
                  if (_DstSize != 0xffffffff) {
                    func_0x3b833775(_DstBuf,0,_DstSize);
                  }
                  puVar2 = (undefined4 *)func_0x7886377d();
                  *puVar2 = 0x22;
                    // WARNING: Bad instruction - Truncating control flow here
                  halt_baddata();
                }
                func_0x507436a4(puVar1,local_8,_File->_ptr,uVar8);
                _File->_cnt = _File->_cnt - uVar8;
                _File->_ptr = _File->_ptr + uVar8;
                    // WARNING: Bad instruction - Truncating control flow here
                halt_baddata();
              }
              goto LAB_00413604;
            }
          }
          if (uVar8 < local_10) {
            iVar6 = func_0x36b9372f(_File);
            if (iVar6 == -1) {
              return;
            }
            if (local_8 == 0) goto LAB_004135d7;
            local_c = puVar1 + 1;
            *puVar1 = (char)iVar6;
            local_10 = _File->_bufsiz;
            iVar6 = -1;
            local_8 = local_8 - 1;
          }
          else {
            if (local_10 == 0) {
              uVar3 = 0x7fffffff;
              if (uVar8 < 0x80000000) {
                uVar3 = uVar8;
              }
            }
            else {
              if (uVar8 < 0x80000000) {
                uVar7 = uVar8 % local_10;
                uVar3 = uVar8;
              }
              else {
                uVar7 = (uint)(0x7fffffff % (ulonglong)local_10);
                uVar3 = 0x7fffffff;
              }
              uVar3 = uVar3 - uVar7;
            }
            if (local_8 < uVar3) {
LAB_004135d7:
              if (_DstSize != 0xffffffff) {
                func_0x3b8337a0(_DstBuf,0,_DstSize);
              }
              puVar2 = (undefined4 *)func_0x788637a8();
              *puVar2 = 0x22;
                    // WARNING: Bad instruction - Truncating control flow here
              halt_baddata();
            }
            uVar4 = func_0x20c13704(_File,puVar1,uVar3);
            iVar5 = func_0x23c0370b(uVar4);
            if (iVar5 == 0) {
              _File->_flag = _File->_flag | 0x10;
              return;
            }
            if (iVar5 == -1) {
LAB_00413604:
              _File->_flag = _File->_flag | 0x20;
                    // WARNING: Bad instruction - Truncating control flow here
              halt_baddata();
            }
            local_c = puVar1 + iVar5;
            iVar6 = -iVar5;
            local_8 = local_8 - iVar5;
          }
          uVar8 = uVar8 + iVar6;
          puVar1 = local_c;
        } while( true );
      }
      if (_DstSize != 0xffffffff) {
        func_0x3b83362f(_DstBuf,0,_DstSize);
      }
      if ((_File != (FILE *)0x0) && (_Count <= (uint)(0xffffffff / (ulonglong)_ElementSize)))
      goto LAB_0041348d;
    }
    puVar2 = (undefined4 *)func_0x788635f4();
    *puVar2 = 0x16;
    func_0x53aa3604(0,0,0,0,0);
  }
  return 0;
}



void __cdecl
FUN_004136b2(undefined4 param_1,undefined4 param_2,undefined4 param_3,undefined4 param_4)

{
  func_0x13673880(param_1,0xffffffff,param_2,param_3,param_4);
  return;
}



// Library Function - Single Match
//  __fclose_nolock
// 
// Library: Visual Studio 2008 Release

int __cdecl __fclose_nolock(FILE *_File)

{
  undefined4 *puVar1;
  undefined4 uVar2;
  int iVar3;
  int iVar4;
  
  iVar4 = -1;
  if (_File == (FILE *)0x0) {
    puVar1 = (undefined4 *)func_0x7886389e();
    *puVar1 = 0x16;
    func_0x53aa38ae(0,0,0,0,0);
    iVar4 = -1;
  }
  else {
    if ((*(byte *)&_File->_flag & 0x83) != 0) {
      iVar4 = func_0xecc238c1(_File);
      func_0xbbc238c9(_File);
      uVar2 = func_0x20c138cf(_File);
      iVar3 = func_0xeec138d5(uVar2);
      if (iVar3 < 0) {
        iVar4 = -1;
      }
      else if (_File->_tmpfname != (char *)0x0) {
        func_0xc27338ee(_File->_tmpfname);
        _File->_tmpfname = (char *)0x0;
      }
    }
    _File->_flag = 0;
  }
  return iVar4;
}



// Library Function - Single Match
//  _wcsstr
// 
// Library: Visual Studio 2008 Release

wchar_t * __cdecl _wcsstr(wchar_t *_Str,wchar_t *_SubStr)

{
  wchar_t wVar1;
  wchar_t *pwVar2;
  int iVar3;
  
  if (*_SubStr != L'\0') {
    wVar1 = *_Str;
    if (wVar1 != L'\0') {
      iVar3 = (int)_Str - (int)_SubStr;
      pwVar2 = _SubStr;
joined_r0x004137ea:
      do {
        if (wVar1 != L'\0') {
          if (*pwVar2 == L'\0') {
            return _Str;
          }
          if (*(wchar_t *)(iVar3 + (int)pwVar2) == *pwVar2) {
            wVar1 = *(wchar_t *)(iVar3 + (int)(pwVar2 + 1));
            pwVar2 = pwVar2 + 1;
            goto joined_r0x004137ea;
          }
        }
        if (*pwVar2 == L'\0') {
          return _Str;
        }
        _Str = _Str + 1;
        wVar1 = *_Str;
        iVar3 = iVar3 + 2;
        pwVar2 = _SubStr;
      } while (wVar1 != L'\0');
    }
    _Str = (wchar_t *)0x0;
  }
  return _Str;
}



// WARNING: Control flow encountered bad instruction data
// Library Function - Single Match
//  __fwrite_nolock
// 
// Library: Visual Studio 2008 Release

size_t __cdecl __fwrite_nolock(void *_DstBuf,size_t _Size,size_t _Count,FILE *_File)

{
  undefined4 *puVar1;
  int iVar2;
  undefined4 uVar3;
  uint uVar4;
  uint uVar5;
  uint uVar6;
  uint uVar7;
  uint local_c;
  char *local_8;
  
  if ((_Size != 0) && (_Count != 0)) {
    if ((_File != (FILE *)0x0) &&
       ((_DstBuf != (void *)0x0 && (_Count <= (uint)(0xffffffff / (ulonglong)_Size))))) {
      uVar7 = _Size * _Count;
      if ((_File->_flag & 0x10cU) == 0) {
        local_c = 0x1000;
      }
      else {
        local_c = _File->_bufsiz;
      }
      do {
        while( true ) {
          if (uVar7 == 0) {
                    // WARNING: Bad instruction - Truncating control flow here
            halt_baddata();
          }
          uVar5 = _File->_flag & 0x108;
          if (uVar5 == 0) break;
          uVar4 = _File->_cnt;
          if (uVar4 == 0) break;
          if ((int)uVar4 < 0) {
            _File->_flag = _File->_flag | 0x20;
            return;
          }
          uVar6 = uVar7;
          if (uVar4 <= uVar7) {
            uVar6 = uVar4;
          }
          func_0xfbcd3a84(_File->_ptr,_DstBuf,uVar6);
          _File->_cnt = _File->_cnt - uVar6;
          _File->_ptr = _File->_ptr + uVar6;
LAB_0041392c:
          local_8 = (char *)((int)_DstBuf + uVar6);
          uVar7 = uVar7 - uVar6;
          _DstBuf = local_8;
        }
        if (local_c <= uVar7) {
          if ((uVar5 != 0) && (iVar2 = func_0xecc23aa2(_File), iVar2 != 0)) {
            return;
          }
          uVar5 = uVar7;
          if (local_c != 0) {
            uVar5 = uVar7 - uVar7 % local_c;
          }
          uVar3 = func_0x20c13ac2(_File,_DstBuf,uVar5);
          uVar4 = func_0x16cd3ac9(uVar3);
          if (uVar4 == 0xffffffff) {
LAB_0041397c:
            _File->_flag = _File->_flag | 0x20;
                    // WARNING: Bad instruction - Truncating control flow here
            halt_baddata();
          }
          uVar6 = uVar5;
          if (uVar4 <= uVar5) {
            uVar6 = uVar4;
          }
          if (uVar4 < uVar5) goto LAB_0041397c;
          goto LAB_0041392c;
        }
                    // WARNING: Load size is inaccurate
        iVar2 = func_0x7fc43af4((int)*_DstBuf,_File);
        if (iVar2 == -1) {
          return;
        }
        _DstBuf = (void *)((int)_DstBuf + 1);
        local_c = _File->_bufsiz;
        uVar7 = uVar7 - 1;
        if ((int)local_c < 1) {
          local_c = 1;
        }
      } while( true );
    }
    puVar1 = (undefined4 *)func_0x788639fc();
    *puVar1 = 0x16;
    func_0x53aa3a0c(0,0,0,0,0);
  }
  return 0;
}



// Library Function - Single Match
//  __fseek_nolock
// 
// Library: Visual Studio 2008 Release

int __cdecl __fseek_nolock(FILE *_File,long _Offset,int _Origin)

{
  uint uVar1;
  undefined4 *puVar2;
  int iVar3;
  undefined4 uVar4;
  
  if ((_File->_flag & 0x83U) == 0) {
    puVar2 = (undefined4 *)func_0x78863bd2();
    *puVar2 = 0x16;
    iVar3 = -1;
  }
  else {
    _File->_flag = _File->_flag & 0xffffffef;
    if (_Origin == 1) {
      iVar3 = func_0x0d6c3bef(_File);
      _Offset = _Offset + iVar3;
      _Origin = 0;
    }
    func_0xecc23bfd(_File);
    uVar1 = _File->_flag;
    if ((char)uVar1 < '\0') {
      _File->_flag = uVar1 & 0xfffffffc;
    }
    else if ((((uVar1 & 1) != 0) && ((uVar1 & 8) != 0)) && ((uVar1 & 0x400) == 0)) {
      _File->_bufsiz = 0x200;
    }
    uVar4 = func_0x20c13c2f(_File,_Offset,_Origin);
    iVar3 = func_0xd5d13c36(uVar4);
    iVar3 = (iVar3 != -1) - 1;
  }
  return iVar3;
}



// WARNING: Control flow encountered bad instruction data
// Library Function - Single Match
//  __ftell_nolock
// 
// Library: Visual Studio 2008 Release

long __cdecl __ftell_nolock(FILE *_File)

{
  uint uVar1;
  char *pcVar2;
  undefined4 *puVar3;
  uint uVar4;
  FILE *pFVar5;
  int iVar6;
  char *pcVar7;
  FILE *pFVar8;
  char *pcVar9;
  int iVar10;
  bool bVar11;
  int local_10;
  int local_c;
  
  pFVar8 = _File;
  if (_File == (FILE *)0x0) {
    puVar3 = (undefined4 *)func_0x78863ce4();
    *puVar3 = 0x16;
    func_0x53aa3cf4(0,0,0,0,0);
                    // WARNING: Bad instruction - Truncating control flow here
    halt_baddata();
  }
  uVar4 = func_0x20c13d05(_File);
  if (_File->_cnt < 0) {
    _File->_cnt = 0;
  }
  local_c = func_0xd5d13d1a(uVar4,0,1);
  if (local_c < 0) {
    return;
  }
  uVar1 = _File->_flag;
  if ((uVar1 & 0x108) == 0) {
                    // WARNING: Bad instruction - Truncating control flow here
    halt_baddata();
  }
  pcVar7 = _File->_ptr;
  pcVar9 = _File->_base;
  local_10 = (int)pcVar7 - (int)pcVar9;
  if ((uVar1 & 3) == 0) {
    if (-1 < (char)uVar1) {
      puVar3 = (undefined4 *)func_0x78863d93();
      *puVar3 = 0x16;
                    // WARNING: Bad instruction - Truncating control flow here
      halt_baddata();
    }
  }
  else {
    pcVar2 = pcVar9;
    if ((*(byte *)((&DAT_00436d80)[(int)uVar4 >> 5] + 4 + (uVar4 & 0x1f) * 0x40) & 0x80) != 0) {
      for (; pcVar2 < pcVar7; pcVar2 = pcVar2 + 1) {
        if (*pcVar2 == '\n') {
          local_10 = local_10 + 1;
        }
      }
    }
  }
  if (local_c != 0) {
    if ((*(byte *)&_File->_flag & 1) != 0) {
      if (_File->_cnt == 0) {
                    // WARNING: Bad instruction - Truncating control flow here
        halt_baddata();
      }
      pFVar5 = (FILE *)(pcVar7 + (_File->_cnt - (int)pcVar9));
      iVar10 = (uVar4 & 0x1f) * 0x40;
      if ((*(byte *)((&DAT_00436d80)[(int)uVar4 >> 5] + 4 + iVar10) & 0x80) != 0) {
        iVar6 = func_0xd5d13de9(uVar4,0,2);
        if (iVar6 == local_c) {
          pcVar7 = _File->_base;
          pcVar9 = pcVar7 + (int)&pFVar5->_ptr;
          _File = pFVar5;
          for (; pcVar7 < pcVar9; pcVar7 = pcVar7 + 1) {
            if (*pcVar7 == '\n') {
              _File = (FILE *)((int)&_File->_ptr + 1);
            }
          }
          bVar11 = (pFVar8->_flag & 0x2000U) == 0;
        }
        else {
          iVar6 = func_0xd5d13e1e(uVar4,local_c,0);
          if (iVar6 < 0) {
            return -1;
          }
          pFVar8 = (FILE *)0x200;
          if ((((FILE *)0x200 < pFVar5) || ((_File->_flag & 8U) == 0)) ||
             ((_File->_flag & 0x400U) != 0)) {
            pFVar8 = (FILE *)_File->_bufsiz;
          }
          bVar11 = (*(byte *)((&DAT_00436d80)[(int)uVar4 >> 5] + 4 + iVar10) & 4) == 0;
          _File = pFVar8;
        }
        pFVar5 = _File;
        if (!bVar11) {
          pFVar5 = (FILE *)((int)&_File->_ptr + 1);
        }
      }
      _File = pFVar5;
      local_c = local_c - (int)_File;
    }
    return local_10 + local_c;
  }
                    // WARNING: Bad instruction - Truncating control flow here
  halt_baddata();
}



// WARNING: Control flow encountered bad instruction data
// Library Function - Single Match
//  _malloc
// 
// Library: Visual Studio 2008 Release

void * __cdecl _malloc(size_t _Size)

{
  code *pcVar1;
  void *pvVar2;
  int iVar3;
  undefined4 *puVar4;
  size_t sVar5;
  uint uVar6;
  
  pcVar1 = DAT_004280c4;
  if (0xffffffe0 < _Size) {
    func_0x9be33fdf(_Size);
    puVar4 = (undefined4 *)func_0x78863fe5();
    *puVar4 = 0xc;
    return (void *)0x0;
  }
  if (DAT_00435454 == 0) {
    func_0x53e33f4e();
    func_0xa8e13f55(0x1e);
    func_0x12a53f5f(0xff);
  }
  if (DAT_00436d4c == 1) {
    uVar6 = _Size;
    if (_Size == 0) {
      uVar6 = 1;
    }
  }
  else {
    if ((DAT_00436d4c == 3) && (pvVar2 = (void *)func_0x186e3f84(_Size), pvVar2 != (void *)0x0))
    goto LAB_00413de9;
    sVar5 = _Size;
    if (_Size == 0) {
      sVar5 = 1;
    }
    uVar6 = sVar5 + 0xf & 0xfffffff0;
  }
  pvVar2 = (void *)(*pcVar1)(DAT_00435454,0,uVar6);
LAB_00413de9:
  if (pvVar2 == (void *)0x0) {
    if (DAT_00435770 == 0) {
      puVar4 = (undefined4 *)func_0x78863fca();
      *puVar4 = 0xc;
    }
    else {
      iVar3 = func_0x9be33fb8(_Size);
      if (iVar3 != 0) {
                    // WARNING: Bad instruction - Truncating control flow here
        halt_baddata();
      }
    }
    puVar4 = (undefined4 *)func_0x78863fd1();
    *puVar4 = 0xc;
  }
  return pvVar2;
}



// Library Function - Single Match
//  _strcpy_s
// 
// Library: Visual Studio 2008 Release

errno_t __cdecl _strcpy_s(char *_Dst,rsize_t _SizeInBytes,char *_Src)

{
  char cVar1;
  undefined4 *puVar2;
  char *pcVar3;
  errno_t eVar4;
  
  if ((_Dst != (char *)0x0) && (_SizeInBytes != 0)) {
    pcVar3 = _Dst;
    if (_Src != (char *)0x0) {
      do {
        cVar1 = *_Src;
        *pcVar3 = cVar1;
        _Src = _Src + 1;
        if (cVar1 == '\0') break;
        _SizeInBytes = _SizeInBytes - 1;
        pcVar3 = pcVar3 + 1;
      } while (_SizeInBytes != 0);
      if (_SizeInBytes != 0) {
        return 0;
      }
      *_Dst = '\0';
      puVar2 = (undefined4 *)func_0x78864048();
      eVar4 = 0x22;
      *puVar2 = 0x22;
      goto LAB_00413e5c;
    }
    *_Dst = '\0';
  }
  puVar2 = (undefined4 *)func_0x7886400d();
  eVar4 = 0x16;
  *puVar2 = 0x16;
LAB_00413e5c:
  func_0x53aa401c(0,0,0,0,0);
  return eVar4;
}



// Library Function - Single Match
//  _strrchr
// 
// Library: Visual Studio

char * __cdecl _strrchr(char *_Str,int _Ch)

{
  char cVar1;
  int iVar2;
  char *pcVar3;
  char *pcVar4;
  
  iVar2 = -1;
  do {
    pcVar4 = _Str;
    if (iVar2 == 0) break;
    iVar2 = iVar2 + -1;
    pcVar4 = _Str + 1;
    cVar1 = *_Str;
    _Str = pcVar4;
  } while (cVar1 != '\0');
  iVar2 = -(iVar2 + 1);
  pcVar4 = pcVar4 + -1;
  do {
    pcVar3 = pcVar4;
    if (iVar2 == 0) break;
    iVar2 = iVar2 + -1;
    pcVar3 = pcVar4 + -1;
    cVar1 = *pcVar4;
    pcVar4 = pcVar3;
  } while ((char)_Ch != cVar1);
  pcVar3 = pcVar3 + 1;
  if (*pcVar3 != (char)_Ch) {
    pcVar3 = (char *)0x0;
  }
  return pcVar3;
}



void __cdecl
FUN_00413ed1(undefined4 param_1,undefined4 param_2,undefined4 param_3,undefined param_4)

{
  func_0xcf7840a0(param_1,param_2,param_3,0,&param_4);
  return;
}



// Library Function - Single Match
//  _wcsrchr
// 
// Library: Visual Studio 2008 Release

wchar_t * __cdecl _wcsrchr(wchar_t *_Str,wchar_t _Ch)

{
  wchar_t wVar1;
  wchar_t *pwVar2;
  
  pwVar2 = _Str;
  do {
    wVar1 = *pwVar2;
    pwVar2 = pwVar2 + 1;
  } while (wVar1 != L'\0');
  do {
    pwVar2 = pwVar2 + -1;
    if (pwVar2 == _Str) break;
  } while (*pwVar2 != _Ch);
  if (*pwVar2 != _Ch) {
    pwVar2 = (wchar_t *)0x0;
  }
  return pwVar2;
}



// Library Function - Single Match
//  public: __thiscall _LocaleUpdate::_LocaleUpdate(struct localeinfo_struct *)
// 
// Libraries: Visual Studio 2008 Release, Visual Studio 2010 Release

_LocaleUpdate * __thiscall
_LocaleUpdate::_LocaleUpdate(_LocaleUpdate *this,localeinfo_struct *param_1)

{
  uint *puVar1;
  int iVar2;
  undefined4 uVar3;
  
  this[0xc] = (_LocaleUpdate)0x0;
  if (param_1 == (localeinfo_struct *)0x0) {
    iVar2 = func_0x40ad40e9();
    *(int *)(this + 8) = iVar2;
    *(undefined4 *)this = *(undefined4 *)(iVar2 + 0x6c);
    *(undefined4 *)(this + 4) = *(undefined4 *)(iVar2 + 0x68);
    if ((*(int *)this != DAT_00432980) && ((*(uint *)(iVar2 + 0x70) & DAT_0043289c) == 0)) {
      uVar3 = func_0x55ed4111();
      *(undefined4 *)this = uVar3;
    }
    if ((*(int *)(this + 4) != DAT_004327a0) &&
       ((*(uint *)(*(int *)(this + 8) + 0x70) & DAT_0043289c) == 0)) {
      uVar3 = func_0xe9e54131();
      *(undefined4 *)(this + 4) = uVar3;
    }
    if ((*(byte *)(*(int *)(this + 8) + 0x70) & 2) == 0) {
      puVar1 = (uint *)(*(int *)(this + 8) + 0x70);
      *puVar1 = *puVar1 | 2;
      this[0xc] = (_LocaleUpdate)0x1;
    }
  }
  else {
    *(pthreadlocinfo *)this = param_1->locinfo;
    *(pthreadmbcinfo *)(this + 4) = param_1->mbcinfo;
  }
  return this;
}



// WARNING: Control flow encountered bad instruction data
// WARNING: Removing unreachable block (ram,0x0041412a)
// Library Function - Single Match
//  unsigned __int64 __cdecl wcstoxq(struct localeinfo_struct *,wchar_t const *,wchar_t const *
// *,int,int)
// 
// Library: Visual Studio 2008 Release

__uint64 __cdecl
wcstoxq(localeinfo_struct *param_1,wchar_t *param_2,wchar_t **param_3,int param_4,int param_5)

{
  wchar_t wVar1;
  wchar_t *pwVar2;
  undefined4 *puVar3;
  int iVar4;
  uint uVar5;
  uint extraout_ECX;
  ushort uVar6;
  uint uVar7;
  wchar_t *pwVar8;
  bool bVar9;
  undefined local_34 [8];
  int local_2c;
  char local_28;
  int local_24;
  int local_20;
  uint local_1c;
  int local_18;
  undefined8 local_14;
  int local_c;
  uint local_8;
  
  func_0x1270416d(param_1);
  if (param_3 != (wchar_t **)0x0) {
    *param_3 = param_2;
  }
  if ((param_2 == (wchar_t *)0x0) || ((param_4 != 0 && ((param_4 < 2 || (0x24 < param_4)))))) {
    puVar3 = (undefined4 *)func_0x78864184();
    *puVar3 = 0x16;
    func_0x53aa4194(0,0,0,0,0);
    if (local_28 != '\0') {
      *(uint *)(local_2c + 0x70) = *(uint *)(local_2c + 0x70) & 0xfffffffd;
    }
                    // WARNING: Bad instruction - Truncating control flow here
    halt_baddata();
  }
  local_c = 0;
  local_8 = 0;
  wVar1 = *param_2;
  pwVar2 = param_2;
  while( true ) {
    pwVar8 = pwVar2 + 1;
    uVar7 = (uint)(ushort)wVar1;
    iVar4 = func_0xa6ef41de(uVar7,8,local_34);
    if (iVar4 == 0) break;
    wVar1 = *pwVar8;
    pwVar2 = pwVar8;
  }
  if (wVar1 == L'-') {
    param_5 = param_5 | 2;
LAB_00414041:
    uVar7 = (uint)(ushort)*pwVar8;
    pwVar8 = pwVar2 + 2;
  }
  else if (wVar1 == L'+') goto LAB_00414041;
  if (((param_4 < 0) || (param_4 == 1)) || (0x24 < param_4)) {
    if (param_3 != (wchar_t **)0x0) {
      *param_3 = param_2;
    }
    if (local_28 != '\0') {
      *(uint *)(local_2c + 0x70) = *(uint *)(local_2c + 0x70) & 0xfffffffd;
    }
    local_c = 0;
    local_8 = 0;
    goto LAB_00414251;
  }
  if (param_4 == 0) {
    iVar4 = func_0xcbed4226(uVar7);
    if (iVar4 == 0) {
      if ((*pwVar8 == L'x') || (*pwVar8 == L'X')) {
        param_4 = 0x10;
        goto LAB_00414099;
      }
      param_4 = 8;
    }
    else {
      param_4 = 10;
    }
  }
  else {
LAB_00414099:
    if (((param_4 == 0x10) && (iVar4 = func_0xcbed425a(uVar7), iVar4 == 0)) &&
       ((*pwVar8 == L'x' || (*pwVar8 == L'X')))) {
      uVar7 = (uint)(ushort)pwVar8[1];
      pwVar8 = pwVar8 + 2;
    }
  }
  local_20 = param_4 >> 0x1f;
  local_24 = param_4;
  local_14 = func_0x3bf0428a(0xffffffff,0xffffffff,param_4,local_20);
  local_18 = 0x10;
  local_1c = extraout_ECX;
  uVar5 = func_0xcbed429c(uVar7);
  if (uVar5 == 0xffffffff) {
    uVar6 = (ushort)uVar7;
    if (((0x40 < uVar6) && (uVar6 < 0x5b)) || ((ushort)(uVar6 - 0x61) < 0x1a)) {
      if ((ushort)(uVar6 - 0x61) < 0x1a) {
        uVar7 = uVar7 - 0x20;
      }
      uVar5 = uVar7 - 0x37;
      goto LAB_00414117;
    }
  }
  else {
LAB_00414117:
    if (uVar5 < (uint)param_4) {
      if ((CONCAT44(local_8,local_c) < local_14) ||
         ((local_14 == CONCAT44(local_8,local_c) && ((local_18 != 0 || (uVar5 <= local_1c)))))) {
        func_0x0ba1433a(local_24,local_20,local_c,local_8);
                    // WARNING: Bad instruction - Truncating control flow here
        halt_baddata();
      }
      param_5 = param_5 | 0xc;
      if (param_3 != (wchar_t **)0x0) {
        return;
      }
    }
  }
  if ((param_5 & 8U) == 0) {
                    // WARNING: Bad instruction - Truncating control flow here
    halt_baddata();
  }
  if (((param_5 & 4U) != 0) ||
     (((param_5 & 1U) == 0 &&
      ((((param_5 & 2U) != 0 &&
        ((0x80000000 < local_8 || ((0x7fffffff < local_8 && (local_c != 0)))))) ||
       (((param_5 & 2U) == 0 && ((0x7ffffffe < local_8 && (0x7fffffff < local_8)))))))))) {
    puVar3 = (undefined4 *)func_0x7886438a();
    *puVar3 = 0x22;
    if ((param_5 & 1U) == 0) {
      if ((param_5 & 2U) == 0) {
        local_c = -1;
        local_8 = 0x7fffffff;
      }
      else {
        local_c = 0;
        local_8 = 0x80000000;
      }
    }
    else {
      local_c = -1;
      local_8 = 0xffffffff;
    }
  }
  if (param_3 != (wchar_t **)0x0) {
    *param_3 = pwVar8 + -1;
  }
  if ((param_5 & 2U) != 0) {
    bVar9 = local_c != 0;
    local_c = -local_c;
    local_8 = -(local_8 + bVar9);
  }
  if (local_28 != '\0') {
    *(uint *)(local_2c + 0x70) = *(uint *)(local_2c + 0x70) & 0xfffffffd;
  }
LAB_00414251:
  return CONCAT44(local_8,local_c);
}



void __cdecl FUN_00414256(undefined4 param_1,undefined4 param_2,undefined4 param_3)

{
  undefined *puVar1;
  
  if (DAT_00435790 == 0) {
    puVar1 = &DAT_00432988;
  }
  else {
    puVar1 = (undefined *)0x0;
  }
  func_0x99704432(puVar1,param_1,param_2,param_3,0);
  return;
}



// Library Function - Single Match
//  _wcsncpy
// 
// Library: Visual Studio 2008 Release

wchar_t * __cdecl _wcsncpy(wchar_t *_Dest,wchar_t *_Source,size_t _Count)

{
  wchar_t wVar1;
  uint uVar2;
  uint uVar3;
  undefined4 *puVar4;
  
  puVar4 = (undefined4 *)_Dest;
  if (_Count != 0) {
    do {
      wVar1 = *_Source;
      *(wchar_t *)puVar4 = wVar1;
      puVar4 = (undefined4 *)((int)puVar4 + 2);
      _Source = _Source + 1;
      if (wVar1 == L'\0') break;
      _Count = _Count - 1;
    } while (_Count != 0);
    if ((_Count != 0) && (uVar2 = _Count - 1, uVar2 != 0)) {
      for (uVar3 = uVar2 >> 1; uVar3 != 0; uVar3 = uVar3 - 1) {
        *puVar4 = 0;
        puVar4 = puVar4 + 1;
      }
      for (uVar2 = (uint)((uVar2 & 1) != 0); uVar2 != 0; uVar2 = uVar2 - 1) {
        *(undefined2 *)puVar4 = 0;
        puVar4 = (undefined4 *)((int)puVar4 + 2);
      }
    }
  }
  return _Dest;
}



// Library Function - Single Match
//  _memcpy_s
// 
// Libraries: Visual Studio 2005 Release, Visual Studio 2008 Release

errno_t __cdecl _memcpy_s(void *_Dst,rsize_t _DstSize,void *_Src,rsize_t _MaxCount)

{
  errno_t eVar1;
  undefined4 *puVar2;
  
  if (_MaxCount == 0) {
LAB_00414369:
    eVar1 = 0;
  }
  else {
    if (_Dst == (void *)0x0) {
LAB_00414372:
      puVar2 = (undefined4 *)func_0x7886452d();
      eVar1 = 0x16;
      *puVar2 = 0x16;
    }
    else {
      if ((_Src != (void *)0x0) && (_MaxCount <= _DstSize)) {
        func_0xfbcd4559(_Dst,_Src,_MaxCount);
        goto LAB_00414369;
      }
      func_0x3b83456a(_Dst,0,_DstSize);
      if (_Src == (void *)0x0) goto LAB_00414372;
      if (_MaxCount <= _DstSize) {
        return 0x16;
      }
      puVar2 = (undefined4 *)func_0x7886457c();
      eVar1 = 0x22;
      *puVar2 = 0x22;
    }
    func_0x53aa453c(0,0,0,0,0);
  }
  return eVar1;
}



// WARNING: Control flow encountered bad instruction data
// Library Function - Single Match
//  _xtow_s@20
// 
// Library: Visual Studio 2008 Release

undefined4 _xtow_s_20(uint param_1,uint param_2,uint param_3,int param_4)

{
  short *psVar1;
  short *in_EAX;
  undefined4 *puVar2;
  short *psVar3;
  short *psVar4;
  short sVar5;
  undefined4 uVar6;
  uint local_8;
  
  if (in_EAX == (short *)0x0) {
    puVar2 = (undefined4 *)func_0x788645a1();
    *puVar2 = 0x16;
    func_0x53aa45b0(0,0,0,0,0);
                    // WARNING: Bad instruction - Truncating control flow here
    halt_baddata();
  }
  if (param_2 == 0) {
LAB_0041440a:
    puVar2 = (undefined4 *)func_0x788645c5();
    uVar6 = 0x16;
  }
  else {
    *in_EAX = 0;
    if ((param_4 != 0) + 1 < param_2) {
      if (0x22 < param_3 - 2) goto LAB_0041440a;
      psVar3 = in_EAX;
      if (param_4 != 0) {
        param_1 = -param_1;
        *in_EAX = 0x2d;
        psVar3 = in_EAX + 1;
      }
      local_8 = (uint)(param_4 != 0);
      psVar1 = psVar3;
      do {
        psVar4 = psVar1;
        sVar5 = (short)(param_1 % param_3);
        if (param_1 % param_3 < 10) {
          sVar5 = sVar5 + 0x30;
        }
        else {
          sVar5 = sVar5 + 0x57;
        }
        *psVar4 = sVar5;
        local_8 = local_8 + 1;
      } while ((param_1 / param_3 != 0) &&
              (psVar1 = psVar4 + 1, param_1 = param_1 / param_3, local_8 < param_2));
      if (local_8 < param_2) {
        psVar4[1] = 0;
        do {
          sVar5 = *psVar4;
          *psVar4 = *psVar3;
          *psVar3 = sVar5;
          psVar4 = psVar4 + -1;
          psVar3 = psVar3 + 1;
        } while (psVar3 < psVar4);
        return 0;
      }
      *in_EAX = 0;
    }
    puVar2 = (undefined4 *)func_0x788645f4();
    uVar6 = 0x22;
  }
  *puVar2 = uVar6;
  func_0x53aa45d4(0,0,0,0,0);
                    // WARNING: Bad instruction - Truncating control flow here
  halt_baddata();
}



// Library Function - Single Match
//  __itow_s
// 
// Libraries: Visual Studio 2005 Release, Visual Studio 2008 Release

errno_t __cdecl __itow_s(int _Val,wchar_t *_DstBuf,size_t _SizeInWords,int _Radix)

{
  errno_t eVar1;
  undefined4 uVar2;
  
  if ((_Radix == 10) && (_Val < 0)) {
    uVar2 = 1;
    _Radix = 10;
  }
  else {
    uVar2 = 0;
  }
  eVar1 = func_0xcd7446ac(_Val,_SizeInWords,_Radix,uVar2);
  return eVar1;
}



// WARNING: Control flow encountered bad instruction data
// Library Function - Single Match
//  __vswprintf_helper
// 
// Library: Visual Studio 2008 Release

int __cdecl
__vswprintf_helper(undefined *param_1,undefined *param_2,uint param_3,int param_4,undefined4 param_5
                  ,undefined4 param_6)

{
  undefined4 *puVar1;
  int iVar2;
  int iVar3;
  undefined *local_24;
  int local_20;
  undefined *local_1c;
  undefined4 local_18;
  
  if (param_4 == 0) {
    puVar1 = (undefined4 *)func_0x788646c3();
    *puVar1 = 0x16;
    func_0x53aa46d3(0,0,0,0,0);
                    // WARNING: Bad instruction - Truncating control flow here
    halt_baddata();
  }
  if ((param_3 != 0) && (param_2 == (undefined *)0x0)) {
    puVar1 = (undefined4 *)func_0x788646f3();
    *puVar1 = 0x16;
    func_0x53aa4703(0,0,0,0,0);
                    // WARNING: Bad instruction - Truncating control flow here
    halt_baddata();
  }
  local_18 = 0x42;
  local_1c = param_2;
  local_24 = param_2;
  if (param_3 < 0x40000000) {
    local_20 = param_3 * 2;
  }
  else {
    local_20 = 0x7fffffff;
  }
  iVar2 = (*(code *)param_1)(&local_24,param_4,param_5,param_6);
  if (param_2 == (undefined *)0x0) {
    return iVar2;
  }
  if (-1 < iVar2) {
    local_20 = local_20 + -1;
    if (local_20 < 0) {
      iVar3 = func_0x7fc44769(0,&local_24);
      if (iVar3 == -1) goto LAB_004145dc;
    }
    else {
      *local_24 = 0;
      local_24 = local_24 + 1;
    }
    local_20 = local_20 + -1;
    if (-1 < local_20) {
      *local_24 = 0;
      return iVar2;
    }
    iVar3 = func_0x7fc44786(0,&local_24);
    if (iVar3 != -1) {
      return iVar2;
    }
  }
LAB_004145dc:
  *(undefined2 *)(param_2 + param_3 * 2 + -2) = 0;
  return (-1 < local_20) - 2;
}



// Library Function - Single Match
//  __vswprintf_s_l
// 
// Library: Visual Studio 2008 Release

int __cdecl
__vswprintf_s_l(wchar_t *_DstBuf,size_t _DstSize,wchar_t *_Format,_locale_t _Locale,va_list _ArgList
               )

{
  undefined4 *puVar1;
  int iVar2;
  
  if (_Format == (wchar_t *)0x0) {
    puVar1 = (undefined4 *)func_0x788647b8();
    *puVar1 = 0x16;
    func_0x53aa47c8(0,0,0,0,0);
  }
  else {
    if ((_DstBuf == (wchar_t *)0x0) || (_DstSize == 0)) {
      puVar1 = (undefined4 *)func_0x788647e2();
      *puVar1 = 0x16;
    }
    else {
      iVar2 = func_0xef754801(0x41cc15,_DstBuf,_DstSize,_Format,_Locale,_ArgList);
      if (iVar2 < 0) {
        *_DstBuf = L'\0';
      }
      if (iVar2 != -2) {
        return iVar2;
      }
      puVar1 = (undefined4 *)func_0x78864817();
      *puVar1 = 0x22;
    }
    func_0x53aa4827(0,0,0,0,0);
  }
  return -1;
}



void __cdecl
FUN_0041467b(undefined4 param_1,undefined4 param_2,undefined4 param_3,undefined4 param_4)

{
  func_0xe7764849(param_1,param_2,param_3,0,param_4);
  return;
}



// Library Function - Single Match
//  _strcat_s
// 
// Library: Visual Studio 2008 Release

errno_t __cdecl _strcat_s(char *_Dst,rsize_t _SizeInBytes,char *_Src)

{
  char cVar1;
  undefined4 *puVar2;
  char *pcVar3;
  errno_t eVar4;
  
  if ((_Dst != (char *)0x0) && (_SizeInBytes != 0)) {
    pcVar3 = _Dst;
    if (_Src != (char *)0x0) {
      do {
        if (*pcVar3 == '\0') break;
        pcVar3 = pcVar3 + 1;
        _SizeInBytes = _SizeInBytes - 1;
      } while (_SizeInBytes != 0);
      if (_SizeInBytes != 0) {
        do {
          cVar1 = *_Src;
          *pcVar3 = cVar1;
          pcVar3 = pcVar3 + 1;
          _Src = _Src + 1;
          if (cVar1 == '\0') break;
          _SizeInBytes = _SizeInBytes - 1;
        } while (_SizeInBytes != 0);
        if (_SizeInBytes != 0) {
          return 0;
        }
        *_Dst = '\0';
        puVar2 = (undefined4 *)func_0x788648b2();
        eVar4 = 0x22;
        *puVar2 = 0x22;
        goto LAB_004146ba;
      }
    }
    *_Dst = '\0';
  }
  puVar2 = (undefined4 *)func_0x7886486b();
  eVar4 = 0x16;
  *puVar2 = 0x16;
LAB_004146ba:
  func_0x53aa487a(0,0,0,0,0);
  return eVar4;
}



// WARNING: Control flow encountered bad instruction data
// Library Function - Single Match
//  __vsnprintf_helper
// 
// Library: Visual Studio 2008 Release

int __cdecl
__vsnprintf_helper(undefined *param_1,undefined *param_2,uint param_3,int param_4,undefined4 param_5
                  ,undefined4 param_6)

{
  undefined4 *puVar1;
  int iVar2;
  int iVar3;
  undefined *local_24;
  uint local_20;
  undefined *local_1c;
  undefined4 local_18;
  
  if (param_4 == 0) {
    puVar1 = (undefined4 *)func_0x788648d7();
    *puVar1 = 0x16;
    func_0x53aa48e7(0,0,0,0,0);
                    // WARNING: Bad instruction - Truncating control flow here
    halt_baddata();
  }
  if ((param_3 == 0) || (param_2 != (undefined *)0x0)) {
    local_20 = 0x7fffffff;
    if (param_3 < 0x80000000) {
      local_20 = param_3;
    }
    local_18 = 0x42;
    local_1c = param_2;
    local_24 = param_2;
    iVar2 = (*(code *)param_1)(&local_24,param_4,param_5,param_6);
    if (param_2 != (undefined *)0x0) {
      if (-1 < iVar2) {
        local_20 = local_20 - 1;
        if (-1 < (int)local_20) {
          *local_24 = 0;
          return iVar2;
        }
        iVar3 = func_0x7fc4496f(0,&local_24);
        if (iVar3 != -1) {
          return iVar2;
        }
      }
      param_2[param_3 - 1] = 0;
      iVar2 = (-1 < (int)local_20) - 2;
    }
  }
  else {
    puVar1 = (undefined4 *)func_0x78864907();
    *puVar1 = 0x16;
    func_0x53aa4917(0,0,0,0,0);
    iVar2 = -1;
  }
  return iVar2;
}



// Library Function - Single Match
//  __vsprintf_s_l
// 
// Libraries: Visual Studio 2005 Release, Visual Studio 2008 Release

int __cdecl
__vsprintf_s_l(char *_DstBuf,size_t _DstSize,char *_Format,_locale_t _Locale,va_list _ArgList)

{
  undefined4 *puVar1;
  int iVar2;
  
  if (_Format == (char *)0x0) {
    puVar1 = (undefined4 *)func_0x788649a0();
    *puVar1 = 0x16;
    func_0x53aa49b0(0,0,0,0,0);
  }
  else {
    if ((_DstBuf == (char *)0x0) || (_DstSize == 0)) {
      puVar1 = (undefined4 *)func_0x788649ca();
      *puVar1 = 0x16;
    }
    else {
      iVar2 = func_0x037849e9(0x41d85b,_DstBuf,_DstSize,_Format,_Locale,_ArgList);
      if (iVar2 < 0) {
        *_DstBuf = '\0';
      }
      if (iVar2 != -2) {
        return iVar2;
      }
      puVar1 = (undefined4 *)func_0x788649fc();
      *puVar1 = 0x22;
    }
    func_0x53aa4a0c(0,0,0,0,0);
  }
  return -1;
}



void __cdecl
FUN_00414860(undefined4 param_1,undefined4 param_2,undefined4 param_3,undefined4 param_4)

{
  func_0xcf784a2e(param_1,param_2,param_3,0,param_4);
  return;
}



void * __thiscall FUN_0041488d(void *this,byte param_1)

{
  func_0x74794a50();
  if ((param_1 & 1) != 0) {
    func_0x15bb495c(this);
  }
  return this;
}



// Library Function - Single Match
//  public: bool __thiscall type_info::operator==(class type_info const &)const 
// 
// Libraries: Visual Studio 2008 Release, Visual Studio 2010 Release

bool __thiscall type_info::operator==(type_info *this,type_info *param_1)

{
  int iVar1;
  
  iVar1 = func_0x9c154a79(param_1 + 9,this + 9);
  return (bool)('\x01' - (iVar1 != 0));
}



// Library Function - Single Match
//  _calloc
// 
// Libraries: Visual Studio 2008 Release, Visual Studio 2010 Release, Visual Studio 2012 Release

void * __cdecl _calloc(size_t _Count,size_t _Size)

{
  void *pvVar1;
  int iVar2;
  int *piVar3;
  int local_8;
  
  local_8 = 0;
  pvVar1 = (void *)func_0x24164a9e(_Count,_Size,&local_8);
  if ((pvVar1 == (void *)0x0) && (local_8 != 0)) {
    iVar2 = func_0x78864ab1();
    if (iVar2 != 0) {
      piVar3 = (int *)func_0x78864aba();
      *piVar3 = local_8;
    }
  }
  return pvVar1;
}



void __cdecl FUN_0041490e(undefined4 param_1)

{
  if (DAT_00434f78 == 1) {
    func_0x53e34ad7();
  }
  func_0xa8e14adf(param_1);
  func_0x12a54ae9(0xff);
  return;
}



// WARNING (jumptable): Unable to track spacebase fully for stack
// WARNING: Globals starting with '_' overlap smaller symbols at the same address

undefined4 __fastcall entry(undefined4 param_1,int param_2)

{
  undefined2 *puVar1;
  undefined4 uVar2;
  int unaff_EBX;
  int unaff_EBP;
  undefined4 *unaff_ESI;
  undefined4 *unaff_EDI;
  
  out(*unaff_ESI,(short)param_2);
  uVar2 = in((short)param_2);
  _DAT_00000000 = param_1;
  *unaff_EDI = uVar2;
  if (!SCARRY4(unaff_EBX,1)) {
    puVar1 = (undefined2 *)((int)unaff_ESI + param_2 + 4);
    *puVar1 = *puVar1;
    ExceptionList = *(void **)(unaff_EBX + 1);
                    // WARNING: Could not recover jumptable at 0x00414ae9. Too many branches
                    // WARNING: Treating indirect jump as call
    uVar2 = (**(code **)(unaff_EBP + 9))();
    return uVar2;
  }
  ExceptionList = *(void **)(unaff_EBP + -3);
  *(undefined4 *)ExceptionList = _DAT_00000000;
  return 100;
}



// Library Function - Multiple Matches With Different Base Names
//  ___CxxFrameHandler
//  ___CxxFrameHandler2
//  ___CxxFrameHandler3
// 
// Library: Visual Studio

undefined4 __cdecl
FID_conflict____CxxFrameHandler3
          (undefined4 param_1,undefined4 param_2,undefined4 param_3,undefined4 param_4)

{
  undefined4 uVar1;
  
  uVar1 = func_0x27294d27(param_1,param_2,param_3,param_4);
  return uVar1;
}



void __cdecl FUN_00414b81(undefined4 param_1,int param_2,undefined4 param_3)

{
  func_0x485f4d4b();
  func_0x27294d64(param_1,*(undefined4 *)(param_2 + 0x10),param_3,0,*(undefined4 *)(param_2 + 0xc),
                  *(undefined4 *)(param_2 + 0x14),param_2,0);
  return;
}



// WARNING: Control flow encountered bad instruction data
// Library Function - Single Match
//  int __cdecl _CallSETranslator(struct EHExceptionRecord *,struct EHRegistrationNode *,void *,void
// *,struct _s_FuncInfo const *,int,struct EHRegistrationNode *)
// 
// Libraries: Visual Studio 2005 Release, Visual Studio 2008 Release, Visual Studio 2010 Release,
// Visual Studio 2012 Release

int __cdecl
_CallSETranslator(EHExceptionRecord *param_1,EHRegistrationNode *param_2,void *param_3,void *param_4
                 ,_s_FuncInfo *param_5,int param_6,EHRegistrationNode *param_7)

{
  int iVar1;
  EHExceptionRecord *local_38;
  void *local_34;
  code *local_30;
  undefined4 *local_2c;
  undefined4 local_28;
  uint local_24;
  _s_FuncInfo *local_20;
  EHRegistrationNode *local_1c;
  int local_18;
  EHRegistrationNode *local_14;
  undefined *local_10;
  undefined *local_c;
  int local_8;
  
  local_c = &stack0xfffffffc;
  local_10 = &stack0xffffffc0;
  if (param_1 != (EHExceptionRecord *)0x123) {
    local_28 = 0x414c87;
    local_24 = DAT_00431c20 ^ (uint)&local_2c;
    local_20 = param_5;
    local_1c = param_2;
    local_18 = param_6;
    local_14 = param_7;
    local_8 = 0;
    local_2c = (undefined4 *)ExceptionList;
    ExceptionList = &local_2c;
    local_38 = param_1;
    local_34 = param_3;
    iVar1 = func_0x40ad4dfa();
    local_30 = *(code **)(iVar1 + 0x80);
    (*local_30)(*(undefined4 *)param_1,&local_38);
    if (local_8 != 0) {
                    // WARNING: Load size is inaccurate
      *local_2c = *ExceptionList;
    }
    ExceptionList = local_2c;
    return 0;
  }
  *(undefined4 *)param_2 = 0x414c5b;
                    // WARNING: Bad instruction - Truncating control flow here
  halt_baddata();
}



// Library Function - Multiple Matches With Different Base Names
//  enum _EXCEPTION_DISPOSITION __cdecl TranslatorGuardHandler(struct EHExceptionRecord *,struct
// TranslatorGuardRN *,void *,void *)
//  __TranslatorGuardHandler
// 
// Library: Visual Studio

undefined4 __cdecl FID_conflict_TranslatorGuardHandler(int param_1,int param_2,undefined4 param_3)

{
  undefined4 uVar1;
  code *local_8;
  
  func_0x485f4e57();
  if ((*(uint *)(param_1 + 4) & 0x66) != 0) {
    *(undefined4 *)(param_2 + 0x24) = 1;
    return 1;
  }
  func_0x27294e9a(param_1,*(undefined4 *)(param_2 + 0x10),param_3,0,*(undefined4 *)(param_2 + 0xc),
                  *(undefined4 *)(param_2 + 0x14),*(undefined4 *)(param_2 + 0x18),1);
  if (*(int *)(param_2 + 0x24) == 0) {
    func_0xee7b4eb1(param_2,param_1);
  }
  func_0xab7c4ec9(0x123,&local_8,0,0,0,0,0);
                    // WARNING: Could not recover jumptable at 0x00414d22. Too many branches
                    // WARNING: Treating indirect jump as call
  uVar1 = (*local_8)();
  return uVar1;
}



// Library Function - Single Match
//  struct _s_TryBlockMapEntry const * __cdecl _GetRangeOfTrysToCheck(struct _s_FuncInfo const
// *,int,int,unsigned int *,unsigned int *)
// 
// Libraries: Visual Studio 2005 Release, Visual Studio 2008 Release

_s_TryBlockMapEntry * __cdecl
_GetRangeOfTrysToCheck(_s_FuncInfo *param_1,int param_2,int param_3,uint *param_4,uint *param_5)

{
  int iVar1;
  uint uVar2;
  int iVar3;
  uint uVar4;
  uint uVar5;
  uint uVar6;
  
  iVar1 = *(int *)(param_1 + 0x10);
  uVar6 = *(uint *)(param_1 + 0xc);
  uVar2 = uVar6;
  uVar4 = uVar6;
  while (uVar5 = uVar2, -1 < param_2) {
    if (uVar6 == 0xffffffff) {
      func_0x592a4f03();
    }
    uVar6 = uVar6 - 1;
    iVar3 = uVar6 * 0x14 + iVar1;
    if (((*(int *)(iVar3 + 4) < param_3) && (param_3 <= *(int *)(iVar3 + 8))) ||
       (uVar2 = uVar5, uVar6 == 0xffffffff)) {
      param_2 = param_2 + -1;
      uVar2 = uVar6;
      uVar4 = uVar5;
    }
  }
  uVar6 = uVar6 + 1;
  *param_4 = uVar6;
  *param_5 = uVar4;
  if ((*(uint *)(param_1 + 0xc) < uVar4) || (uVar4 < uVar6)) {
    func_0x592a4f48();
  }
  return (_s_TryBlockMapEntry *)(uVar6 * 0x14 + iVar1);
}



// Library Function - Single Match
//  __CreateFrameInfo
// 
// Libraries: Visual Studio 2008 Release, Visual Studio 2010 Release

undefined4 * __cdecl __CreateFrameInfo(undefined4 *param_1,undefined4 param_2)

{
  int iVar1;
  
  *param_1 = param_2;
  iVar1 = func_0x40ad4f68();
  param_1[1] = *(undefined4 *)(iVar1 + 0x98);
  iVar1 = func_0x40ad4f76();
  *(undefined4 **)(iVar1 + 0x98) = param_1;
  return param_1;
}



// Library Function - Single Match
//  __IsExceptionObjectToBeDestroyed
// 
// Libraries: Visual Studio 2008 Release, Visual Studio 2010 Release

undefined4 __cdecl __IsExceptionObjectToBeDestroyed(int param_1)

{
  int iVar1;
  int *piVar2;
  
  iVar1 = func_0x40ad4f8b();
  piVar2 = *(int **)(iVar1 + 0x98);
  while( true ) {
    if (piVar2 == (int *)0x0) {
      return 1;
    }
    if (*piVar2 == param_1) break;
    piVar2 = (int *)piVar2[1];
  }
  return 0;
}



// WARNING: Control flow encountered bad instruction data
// Library Function - Single Match
//  __FindAndUnlinkFrame
// 
// Libraries: Visual Studio 2008 Release, Visual Studio 2010 Release

void __cdecl __FindAndUnlinkFrame(int param_1)

{
  int iVar1;
  int iVar2;
  
  iVar1 = func_0x40ad4fb3();
  if (param_1 == *(int *)(iVar1 + 0x98)) {
    iVar1 = func_0x40ad4fc3();
    *(undefined4 *)(iVar1 + 0x98) = *(undefined4 *)(param_1 + 4);
  }
  else {
    iVar1 = func_0x40ad4fd4();
    iVar1 = *(int *)(iVar1 + 0x98);
    do {
      iVar2 = iVar1;
      if (*(int *)(iVar2 + 4) == 0) {
                    // WARNING: Bad instruction - Truncating control flow here
        halt_baddata();
      }
      iVar1 = *(int *)(iVar2 + 4);
    } while (param_1 != *(int *)(iVar2 + 4));
    *(undefined4 *)(iVar2 + 4) = *(undefined4 *)(param_1 + 4);
  }
  return;
}



int __cdecl
FUN_00414e44(undefined4 param_1,undefined4 param_2,undefined4 param_3,int param_4,undefined4 param_5
            )

{
  int iVar1;
  char cVar2;
  char *local_1c;
  undefined4 local_18;
  uint local_14;
  undefined4 local_10;
  undefined4 local_c;
  int local_8;
  
  local_14 = DAT_00431c20 ^ (uint)&local_1c;
  local_10 = param_2;
  local_8 = param_4 + 1;
  cVar2 = local_8 == 0;
  local_18 = 0x414b7d;
  local_c = param_1;
  local_1c = (char *)ExceptionList;
  ExceptionList = &local_1c;
  iVar1 = func_0xac2a504b(param_3,param_1,param_5);
  do {
    iVar1 = iVar1 + -1;
  } while (iVar1 != 0 && cVar2 != '\0');
  *local_1c = *local_1c + (char)local_1c;
  return iVar1;
}



// WARNING: This is an inlined function
// Library Function - Single Match
//  __EH_epilog3
// 
// Libraries: Visual Studio 2005, Visual Studio 2008, Visual Studio 2010, Visual Studio 2012

void __EH_epilog3(void)

{
  undefined4 *unaff_EBP;
  undefined4 unaff_retaddr;
  
  ExceptionList = (void *)unaff_EBP[-3];
  *unaff_EBP = unaff_retaddr;
  return;
}



void __CxxThrowException_8(undefined4 param_1,byte *param_2)

{
  int iVar1;
  undefined4 *puVar2;
  undefined4 *puVar3;
  undefined4 auStack_24 [4];
  undefined4 uStack_14;
  undefined4 uStack_10;
  undefined4 uStack_c;
  byte *pbStack_8;
  
  puVar2 = &DAT_00429cdc;
  puVar3 = auStack_24;
  for (iVar1 = 8; iVar1 != 0; iVar1 = iVar1 + -1) {
    *puVar3 = *puVar2;
    puVar2 = puVar2 + 1;
    puVar3 = puVar3 + 1;
  }
  uStack_c = param_1;
  pbStack_8 = param_2;
  if ((param_2 != (byte *)0x0) && ((*param_2 & 8) != 0)) {
    uStack_10 = 0x1994000;
  }
  (*DAT_004280d4)(auStack_24[0],auStack_24[1],uStack_14,&uStack_10);
  return;
}



// WARNING: Control flow encountered bad instruction data
// Library Function - Single Match
//  _wcsncpy_s
// 
// Library: Visual Studio 2008 Release

errno_t __cdecl _wcsncpy_s(wchar_t *_Dst,rsize_t _SizeInWords,wchar_t *_Src,rsize_t _MaxCount)

{
  wchar_t wVar1;
  errno_t eVar2;
  undefined4 *puVar3;
  wchar_t *pwVar4;
  rsize_t rVar5;
  
  if (_MaxCount == 0) {
    if (_Dst == (wchar_t *)0x0) {
      if (_SizeInWords != 0) goto LAB_00415027;
    }
    else {
LAB_00415020:
      if (_SizeInWords == 0) goto LAB_00415027;
      if (_MaxCount == 0) {
        *_Dst = L'\0';
      }
      else {
        if (_Src == (wchar_t *)0x0) {
          *_Dst = L'\0';
          goto LAB_00415027;
        }
        pwVar4 = _Dst;
        rVar5 = _SizeInWords;
        if (_MaxCount == 0xffffffff) {
          do {
            wVar1 = *_Src;
            *pwVar4 = wVar1;
            pwVar4 = pwVar4 + 1;
            _Src = _Src + 1;
            if (wVar1 == L'\0') break;
            rVar5 = rVar5 - 1;
          } while (rVar5 != 0);
        }
        else {
          do {
            wVar1 = *_Src;
            *pwVar4 = wVar1;
            pwVar4 = pwVar4 + 1;
            _Src = _Src + 1;
            if ((wVar1 == L'\0') || (rVar5 = rVar5 - 1, rVar5 == 0)) break;
            _MaxCount = _MaxCount - 1;
          } while (_MaxCount != 0);
          if (_MaxCount == 0) {
            *pwVar4 = L'\0';
          }
        }
        if (rVar5 == 0) {
          if (_MaxCount != 0xffffffff) {
            *_Dst = L'\0';
            puVar3 = (undefined4 *)func_0x78865277();
            *puVar3 = 0x22;
                    // WARNING: Bad instruction - Truncating control flow here
            halt_baddata();
          }
          _Dst[_SizeInWords - 1] = L'\0';
                    // WARNING: Bad instruction - Truncating control flow here
          halt_baddata();
        }
      }
    }
    eVar2 = 0;
  }
  else {
    if (_Dst != (wchar_t *)0x0) goto LAB_00415020;
LAB_00415027:
    puVar3 = (undefined4 *)func_0x788651e2();
    eVar2 = 0x16;
    *puVar3 = 0x16;
    func_0x53aa51f1(0,0,0,0,0);
  }
  return eVar2;
}



// Library Function - Single Match
//  __onexit_nolock
// 
// Library: Visual Studio 2008 Release

undefined4 __cdecl __onexit_nolock(undefined4 param_1)

{
  undefined4 *puVar1;
  undefined4 *puVar2;
  uint uVar3;
  uint uVar4;
  int iVar5;
  undefined4 uVar6;
  int iVar7;
  
  puVar1 = (undefined4 *)func_0xf4aa52c1(DAT_00437eb0);
  puVar2 = (undefined4 *)func_0xf4aa52d1(DAT_00437eac);
  if ((puVar2 < puVar1) || (iVar7 = (int)puVar2 - (int)puVar1, iVar7 + 4U < 4)) {
    return 0;
  }
  uVar3 = func_0xf5a152ef(puVar1);
  if (uVar3 < iVar7 + 4U) {
    uVar4 = 0x800;
    if (uVar3 < 0x800) {
      uVar4 = uVar3;
    }
    if ((uVar4 + uVar3 < uVar3) || (iVar5 = func_0xd02c5313(puVar1,uVar4 + uVar3), iVar5 == 0)) {
      if (uVar3 + 0x10 < uVar3) {
        return 0;
      }
      iVar5 = func_0xd02c5329(puVar1,uVar3 + 0x10);
      if (iVar5 == 0) {
        return 0;
      }
    }
    puVar2 = (undefined4 *)(iVar5 + (iVar7 >> 2) * 4);
    DAT_00437eb0 = func_0x79aa533b(iVar5);
  }
  uVar6 = func_0x79aa5349(param_1);
  *puVar2 = uVar6;
  DAT_00437eac = func_0x79aa5354(puVar2 + 1);
  return param_1;
}



int __cdecl FUN_0041521e(undefined4 param_1)

{
  int iVar1;
  
  iVar1 = func_0xd98253e1(param_1);
  return (iVar1 != 0) - 1;
}



int __cdecl FUN_004152be(short *param_1)

{
  short sVar1;
  short *psVar2;
  
  psVar2 = param_1;
  do {
    sVar1 = *psVar2;
    psVar2 = psVar2 + 1;
  } while (sVar1 != 0);
  return ((int)psVar2 - (int)param_1 >> 1) + -1;
}



// Library Function - Single Match
//  _memmove_s
// 
// Libraries: Visual Studio 2005 Release, Visual Studio 2008 Release

errno_t __cdecl _memmove_s(void *_Dst,rsize_t _DstSize,void *_Src,rsize_t _MaxCount)

{
  undefined4 *puVar1;
  errno_t eVar2;
  
  if (_MaxCount == 0) {
LAB_0041532f:
    eVar2 = 0;
  }
  else {
    if ((_Dst == (void *)0x0) || (_Src == (void *)0x0)) {
      puVar1 = (undefined4 *)func_0x788654a8();
      eVar2 = 0x16;
      *puVar1 = 0x16;
    }
    else {
      if (_MaxCount <= _DstSize) {
        func_0x8b6054e2(_Dst,_Src,_MaxCount);
        goto LAB_0041532f;
      }
      puVar1 = (undefined4 *)func_0x788654cd();
      eVar2 = 0x22;
      *puVar1 = 0x22;
    }
    func_0x53aa54b7(0,0,0,0,0);
  }
  return eVar2;
}



// WARNING: This is an inlined function
// Library Function - Single Match
//  __SEH_epilog4
// 
// Library: Visual Studio

void __SEH_epilog4(void)

{
  undefined4 *unaff_EBP;
  undefined4 unaff_retaddr;
  
  ExceptionList = (void *)unaff_EBP[-4];
  *unaff_EBP = unaff_retaddr;
  return;
}



// WARNING: Control flow encountered bad instruction data
// Library Function - Single Match
//  __except_handler4
// 
// Library: Visual Studio 2008 Release

undefined4 __cdecl __except_handler4(int *param_1,int param_2,undefined4 param_3)

{
  int iVar1;
  int iVar2;
  int *piVar3;
  int *local_1c;
  undefined4 local_18;
  int *local_14;
  undefined4 local_10;
  int local_c;
  char local_5;
  
  piVar3 = (int *)(*(uint *)(param_2 + 8) ^ DAT_00431c20);
  local_5 = '\0';
  local_10 = 1;
  if (*piVar3 != -2) {
    func_0x485f5583();
  }
  func_0x485f5593();
  iVar2 = param_2;
  if ((*(byte *)(param_1 + 1) & 0x66) == 0) {
    *(int ***)(param_2 + -4) = &local_1c;
    iVar2 = *(int *)(param_2 + 0xc);
    local_1c = param_1;
    local_18 = param_3;
    if (iVar2 != -2) {
      do {
        local_14 = piVar3 + iVar2 * 3 + 4;
        local_c = *local_14;
        if (piVar3[iVar2 * 3 + 5] != 0) {
          iVar1 = func_0xd5b855d8();
          local_5 = '\x01';
          if (iVar1 < 0) {
            local_10 = 0;
            goto LAB_0041543c;
          }
          if (0 < iVar1) {
            if (((*param_1 == -0x1f928c9d) && (s___fastcall_0042a58f._1_4_ != 0)) &&
               (iVar1 = func_0x9c2e5647(s___fastcall_0042a58f + 1), iVar1 != 0)) {
              (*(code *)s___fastcall_0042a58f._1_4_)(param_1,1);
            }
            func_0x05b95665();
            if (*(int *)(param_2 + 0xc) != iVar2) {
              func_0x1fb9567c(param_2 + 0x10,&DAT_00431c20);
            }
            *(int *)(param_2 + 0xc) = local_c;
            if (*piVar3 != -2) {
              func_0x485f5699();
            }
            func_0x485f56a9();
            func_0xecb856b6();
            goto LAB_00415500;
          }
        }
        iVar2 = local_c;
      } while (local_c != -2);
      if (local_5 != '\0') {
LAB_0041543c:
        if (*piVar3 != -2) {
          func_0x485f5606();
        }
        func_0x485f5616();
      }
    }
  }
  else {
LAB_00415500:
    if (*(int *)(iVar2 + 0xc) != -2) {
      func_0x1fb956d1(param_2 + 0x10,&DAT_00431c20);
                    // WARNING: Bad instruction - Truncating control flow here
      halt_baddata();
    }
  }
  return local_10;
}



// Library Function - Single Match
//  _wcsnlen
// 
// Library: Visual Studio 2008 Release

size_t __cdecl _wcsnlen(wchar_t *_Src,size_t _MaxCount)

{
  uint uVar1;
  
  uVar1 = 0;
  if (_MaxCount != 0) {
    do {
      if (*_Src == L'\0') {
        return uVar1;
      }
      uVar1 = uVar1 + 1;
      _Src = _Src + 1;
    } while (uVar1 < _MaxCount);
  }
  return uVar1;
}



// Library Function - Single Match
//  __get_errno_from_oserr
// 
// Libraries: Visual Studio 2008 Release, Visual Studio 2010 Release

int __cdecl __get_errno_from_oserr(ulong param_1)

{
  uint uVar1;
  
  uVar1 = 0;
  do {
    if (param_1 == (&DAT_00431c30)[uVar1 * 2]) {
      return (&DAT_00431c34)[uVar1 * 2];
    }
    uVar1 = uVar1 + 1;
  } while (uVar1 < 0x2d);
  if (param_1 - 0x13 < 0x12) {
    return 0xd;
  }
  return (-(uint)(0xe < param_1 - 0xbc) & 0xe) + 8;
}



void __cdecl FUN_004155a7(undefined4 param_1)

{
  undefined4 *puVar1;
  undefined4 uVar2;
  
  puVar1 = (undefined4 *)func_0x8b865768();
  *puVar1 = param_1;
  uVar2 = func_0x36865773(param_1);
  puVar1 = (undefined4 *)func_0x7886577b();
  *puVar1 = uVar2;
  return;
}



// WARNING: Control flow encountered bad instruction data

int __cdecl FUN_004157e5(byte *param_1,byte *param_2,int param_3)

{
  byte bVar1;
  byte bVar2;
  uint uVar3;
  int iVar4;
  uint uVar5;
  
  if (param_3 == 0) {
    iVar4 = 0;
  }
  else {
    if (param_3 == 1) {
                    // WARNING: Bad instruction - Truncating control flow here
      halt_baddata();
    }
    if (param_3 == 2) {
      uVar3 = (uint)*param_1;
      uVar5 = (uint)*param_2;
      if ((uVar3 == uVar5) ||
         (iVar4 = (uint)(uVar3 != uVar5 && -1 < (int)(uVar3 - uVar5)) * 2 + -1, iVar4 == 0)) {
                    // WARNING: Bad instruction - Truncating control flow here
        halt_baddata();
      }
    }
    else {
      if (param_3 == 3) {
        uVar3 = (uint)*param_1;
        uVar5 = (uint)*param_2;
        if ((uVar3 != uVar5) &&
           (iVar4 = (uint)(uVar3 != uVar5 && -1 < (int)(uVar3 - uVar5)) * 2 + -1, iVar4 != 0)) {
          return iVar4;
        }
        uVar3 = (uint)param_1[1];
        uVar5 = (uint)param_2[1];
        if ((uVar3 != uVar5) &&
           (iVar4 = (uint)(uVar3 != uVar5 && -1 < (int)(uVar3 - uVar5)) * 2 + -1, iVar4 != 0)) {
          return iVar4;
        }
        bVar1 = param_1[2];
        bVar2 = param_2[2];
      }
      else {
        if (param_3 != 4) {
                    // WARNING: Bad instruction - Truncating control flow here
          halt_baddata();
        }
        uVar3 = (uint)*param_1;
        uVar5 = (uint)*param_2;
        if ((uVar3 != uVar5) &&
           (iVar4 = (uint)(uVar3 != uVar5 && -1 < (int)(uVar3 - uVar5)) * 2 + -1, iVar4 != 0)) {
          return iVar4;
        }
        uVar3 = (uint)param_1[1];
        uVar5 = (uint)param_2[1];
        if ((uVar3 != uVar5) &&
           (iVar4 = (uint)(uVar3 != uVar5 && -1 < (int)(uVar3 - uVar5)) * 2 + -1, iVar4 != 0)) {
          return iVar4;
        }
        uVar3 = (uint)param_1[2];
        uVar5 = (uint)param_2[2];
        if ((uVar3 != uVar5) &&
           (iVar4 = (uint)(uVar3 != uVar5 && -1 < (int)(uVar3 - uVar5)) * 2 + -1, iVar4 != 0)) {
          return iVar4;
        }
        bVar1 = param_1[3];
        bVar2 = param_2[3];
      }
      iVar4 = (uint)bVar1 - (uint)bVar2;
      if (iVar4 != 0) {
                    // WARNING: Bad instruction - Truncating control flow here
        halt_baddata();
      }
    }
  }
  return iVar4;
}



void __cdecl FUN_00416ebc(undefined4 param_1,undefined4 param_2)

{
  func_0x5c9f7089(0x41c027,param_1,0,param_2);
  return;
}



// WARNING: Globals starting with '_' overlap smaller symbols at the same address

void __cdecl FUN_00416f38(int param_1)

{
  func_0xcf9f70f8();
  _DAT_00434f80 = func_0xbe3a70fd();
  if (param_1 != 0) {
    func_0x553a710d();
  }
  return;
}



// Library Function - Single Match
//  _wcscmp
// 
// Library: Visual Studio 2008 Release

int __cdecl _wcscmp(wchar_t *_Str1,wchar_t *_Str2)

{
  int iVar1;
  
  while( true ) {
    iVar1 = (uint)(ushort)*_Str1 - (uint)(ushort)*_Str2;
    if ((iVar1 != 0) || (*_Str2 == L'\0')) break;
    _Str1 = _Str1 + 1;
    _Str2 = _Str2 + 1;
  }
  if (iVar1 < 0) {
    return -1;
  }
  if (0 < iVar1) {
    iVar1 = 1;
  }
  return iVar1;
}



// Library Function - Single Match
//  __is_LFH_enabled
// 
// Library: Visual Studio 2008 Release

undefined4 __is_LFH_enabled(void)

{
  int iVar1;
  undefined4 uVar2;
  code *pcVar3;
  int local_8;
  
  local_8 = -1;
  if (DAT_00434f84 == 0) {
    iVar1 = (*DAT_004281e8)(&LAB_00429c2c);
    if (iVar1 != 0) {
      uVar2 = (*(code *)u_f__dd_vctools_vc7libs_ship_atlmf_0042815f._5_4_)(iVar1,&DAT_00429d08);
      DAT_00434f88 = func_0x79aa73c2(uVar2);
    }
    DAT_00434f84 = 1;
  }
  iVar1 = func_0xebaa73d7();
  if (DAT_00434f88 != iVar1) {
    pcVar3 = (code *)func_0xf4aa73f7(DAT_00434f88,DAT_00435454,0,&local_8,4,0);
    iVar1 = (*pcVar3)();
    if ((iVar1 != 0) && (local_8 == 2)) {
      return 1;
    }
  }
  return 0;
}



// Library Function - Single Match
//  __crt_waiting_on_module_handle
// 
// Library: Visual Studio 2008 Release

void __cdecl __crt_waiting_on_module_handle(undefined4 param_1)

{
  int iVar1;
  uint uVar2;
  
  uVar2 = 1000;
  do {
    (*DAT_0042821c)(uVar2);
    iVar1 = (*DAT_004281e8)(param_1);
    uVar2 = uVar2 + 1000;
    if (60000 < uVar2) {
      return;
    }
  } while (iVar1 == 0);
  return;
}



void __cdecl FUN_004173c7(undefined4 param_1)

{
  code *pcVar1;
  
  func_0x53e37587();
  func_0xa8e1758f(param_1);
  pcVar1 = (code *)func_0xf4aa759a(DAT_00431db0);
  (*pcVar1)(0xff);
  return;
}



void __cdecl FUN_004173f0(undefined4 param_1)

{
  int iVar1;
  code *pcVar2;
  
  iVar1 = (*DAT_004281e8)(&DAT_00429d30);
  if (iVar1 != 0) {
    pcVar2 = (code *)(*(code *)u_f__dd_vctools_vc7libs_ship_atlmf_0042815f._5_4_)
                               (iVar1,&DAT_00429d20);
    if (pcVar2 != (code *)0x0) {
      (*pcVar2)(param_1);
    }
  }
  return;
}



void FUN_0041741b(undefined4 param_1)

{
  code *pcVar1;
  
  func_0xe7a475de(param_1);
  (*DAT_004281ec)(param_1);
  pcVar1 = (code *)swi(3);
  (*pcVar1)();
  return;
}



// Library Function - Single Match
//  __initterm
// 
// Libraries: Visual Studio 2008 Release, Visual Studio 2010 Release

void __cdecl __initterm(undefined **param_1)

{
  code **in_EAX;
  
  for (; in_EAX < param_1; in_EAX = in_EAX + 1) {
    if (*in_EAX != (code *)0x0) {
      (**in_EAX)();
    }
  }
  return;
}



// Library Function - Single Match
//  __initterm_e
// 
// Libraries: Visual Studio 2008 Release, Visual Studio 2010 Release, Visual Studio 2012 Release

void __cdecl __initterm_e(undefined **param_1,undefined **param_2)

{
  int iVar1;
  
  iVar1 = 0;
  while ((param_1 < param_2 && (iVar1 == 0))) {
    if ((code *)*param_1 != (code *)0x0) {
      iVar1 = (*(code *)*param_1)();
    }
    param_1 = (code **)param_1 + 1;
  }
  return;
}



// Library Function - Single Match
//  __cinit
// 
// Library: Visual Studio 2008 Release

int __cdecl __cinit(int param_1)

{
  int iVar1;
  
  if (DAT_00429cfc != (code *)0x0) {
    iVar1 = func_0x9c2e7654(&DAT_00429cfc);
    if (iVar1 != 0) {
      (*DAT_00429cfc)(param_1);
    }
  }
  func_0x343a7668();
  iVar1 = func_0x59a57677(&DAT_00428458,&DAT_00428470);
  if (iVar1 == 0) {
    func_0x15837687(&DAT_0041eb9c);
    func_0x3ca57698(&DAT_00428454);
    if (DAT_00437eb8 != (code *)0x0) {
      iVar1 = func_0x9c2e76ac(&DAT_00437eb8);
      if (iVar1 != 0) {
        (*DAT_00437eb8)(0,2,0);
      }
    }
    iVar1 = 0;
  }
  return iVar1;
}



void __cdecl FUN_00417637(undefined4 param_1)

{
  func_0x02a677fe(param_1,0,0);
  return;
}



void __cdecl FUN_0041764d(undefined4 param_1)

{
  func_0x02a67814(param_1,1,0);
  return;
}



// WARNING: This is an inlined function

void __alloca_probe(void)

{
  undefined *in_EAX;
  undefined4 *puVar1;
  undefined4 *puVar2;
  undefined4 unaff_retaddr;
  undefined auStack_4 [4];
  
  puVar2 = (undefined4 *)((int)&stack0x00000000 - (int)in_EAX & ~-(uint)(&stack0x00000000 < in_EAX))
  ;
  for (puVar1 = (undefined4 *)((uint)auStack_4 & 0xfffff000); puVar2 < puVar1;
      puVar1 = puVar1 + -0x400) {
  }
  *puVar2 = unaff_retaddr;
  return;
}



// WARNING: Globals starting with '_' overlap smaller symbols at the same address
// Library Function - Single Match
//  ___report_gsfailure
// 
// Libraries: Visual Studio 2005 Release, Visual Studio 2008 Release, Visual Studio 2010 Release

void __cdecl ___report_gsfailure(void)

{
  undefined4 in_EAX;
  undefined4 uVar1;
  undefined4 in_ECX;
  undefined4 in_EDX;
  undefined4 unaff_EBX;
  undefined4 unaff_EBP;
  undefined4 unaff_ESI;
  undefined4 unaff_EDI;
  undefined2 in_ES;
  undefined2 in_CS;
  undefined2 in_SS;
  undefined2 in_DS;
  undefined2 in_FS;
  undefined2 in_GS;
  byte in_AF;
  byte in_TF;
  byte in_IF;
  byte in_NT;
  byte in_AC;
  byte in_VIF;
  byte in_VIP;
  byte in_ID;
  undefined4 unaff_retaddr;
  undefined4 local_32c;
  undefined4 local_328;
  
  _DAT_004350d8 =
       (uint)(in_NT & 1) * 0x4000 | (uint)SBORROW4((int)&stack0xfffffffc,0x328) * 0x800 |
       (uint)(in_IF & 1) * 0x200 | (uint)(in_TF & 1) * 0x100 | (uint)((int)&local_32c < 0) * 0x80 |
       (uint)(&stack0x00000000 == (undefined *)0x32c) * 0x40 | (uint)(in_AF & 1) * 0x10 |
       (uint)((POPCOUNT((uint)&local_32c & 0xff) & 1U) == 0) * 4 |
       (uint)(&stack0xfffffffc < (undefined *)0x328) | (uint)(in_ID & 1) * 0x200000 |
       (uint)(in_VIP & 1) * 0x100000 | (uint)(in_VIF & 1) * 0x80000 | (uint)(in_AC & 1) * 0x40000;
  _DAT_004350dc = &stack0x00000004;
  _DAT_00435018 = 0x10001;
  _DAT_00434fc0 = 0xc0000409;
  _DAT_00434fc4 = 1;
  local_32c = DAT_00431c20;
  local_328 = DAT_00431c24;
  _DAT_00434fcc = unaff_retaddr;
  _DAT_004350a4 = in_GS;
  _DAT_004350a8 = in_FS;
  _DAT_004350ac = in_ES;
  _DAT_004350b0 = in_DS;
  _DAT_004350b4 = unaff_EDI;
  _DAT_004350b8 = unaff_ESI;
  _DAT_004350bc = unaff_EBX;
  _DAT_004350c0 = in_EDX;
  _DAT_004350c4 = in_ECX;
  _DAT_004350c8 = in_EAX;
  _DAT_004350cc = unaff_EBP;
  DAT_004350d0 = unaff_retaddr;
  _DAT_004350d4 = in_CS;
  _DAT_004350e0 = in_SS;
  DAT_00435010 = (*DAT_004280ec)();
  func_0x2e3e79a2(1);
  (*DAT_004280e8)(0);
  (*DAT_004280e4)(&DAT_00429d48);
  if (DAT_00435010 == 0) {
    func_0x2e3e79c6(1);
  }
  uVar1 = (*DAT_004280bc)(0xc0000409);
  (*DAT_004280e0)(uVar1);
  return;
}



void __cdecl FUN_00417825(undefined4 param_1)

{
  DAT_004352e4 = param_1;
  return;
}



// Library Function - Single Match
//  __invoke_watson
// 
// Library: Visual Studio 2008 Release

void __cdecl
__invoke_watson(wchar_t *param_1,wchar_t *param_2,wchar_t *param_3,uint param_4,uintptr_t param_5)

{
  int iVar1;
  int iVar2;
  undefined4 uVar3;
  undefined4 local_32c;
  undefined4 local_328;
  undefined4 *local_2dc;
  undefined4 *local_2d8;
  undefined4 local_2d4 [39];
  
  local_32c = 0;
  func_0x3b837a17();
  local_2dc = &local_32c;
  local_2d8 = local_2d4;
  local_2d4[0] = 0x10001;
  local_32c = 0xc0000417;
  local_328 = 1;
  iVar1 = (*DAT_004280ec)();
  (*DAT_004280e8)();
  iVar2 = (*DAT_004280e4)();
  if ((iVar2 == 0) && (iVar1 == 0)) {
    func_0x2e3e7af2();
  }
  uVar3 = (*DAT_004280bc)();
  (*DAT_004280e0)(uVar3);
  func_0x485f7b10();
  return;
}



// WARNING: Control flow encountered bad instruction data

void FUN_0041795c(void)

{
  code *UNRECOVERED_JUMPTABLE;
  
  UNRECOVERED_JUMPTABLE = (code *)func_0xf4aa7b22(DAT_004352e4);
  if (UNRECOVERED_JUMPTABLE != (code *)0x0) {
                    // WARNING: Could not recover jumptable at 0x00417972. Too many branches
                    // WARNING: Treating indirect jump as call
    (*UNRECOVERED_JUMPTABLE)();
    return;
  }
  func_0x2e3e7b31(2);
                    // WARNING: Bad instruction - Truncating control flow here
  halt_baddata();
}



// Library Function - Multiple Matches With Different Base Names
//  __decode_pointer
//  __encode_pointer
// 
// Library: Visual Studio 2008 Release

undefined4 __cdecl FID_conflict___decode_pointer(undefined4 param_1)

{
  undefined4 uVar1;
  int iVar2;
  code *pcVar3;
  
  uVar1 = u_f__dd_vctools_vc7libs_ship_atlmf_0042815f._61_4_;
  iVar2 = (*(code *)u_f__dd_vctools_vc7libs_ship_atlmf_0042815f._61_4_)(u_WinVista_00431dbb._9_4_);
  if ((iVar2 != 0) && (u_WinVista_00431dbb._5_4_ != -1)) {
    pcVar3 = (code *)(*(code *)uVar1)(u_WinVista_00431dbb._9_4_,u_WinVista_00431dbb._5_4_);
    iVar2 = (*pcVar3)();
    if (iVar2 != 0) {
      pcVar3 = *(code **)(iVar2 + 0x1f8);
      goto LAB_004179e2;
    }
  }
  iVar2 = (*DAT_004281e8)(&DAT_00429d60);
  if ((iVar2 == 0) && (iVar2 = func_0x8ea47b87(&DAT_00429d60), iVar2 == 0)) {
    return param_1;
  }
  pcVar3 = (code *)(*(code *)u_f__dd_vctools_vc7libs_ship_atlmf_0042815f._5_4_)(iVar2,&DAT_00429d50)
  ;
LAB_004179e2:
  if (pcVar3 != (code *)0x0) {
    param_1 = (*pcVar3)(param_1);
  }
  return param_1;
}



// Library Function - Multiple Matches With Different Base Names
//  __decode_pointer
//  __encode_pointer
// 
// Library: Visual Studio 2008 Release

undefined4 __cdecl FID_conflict___decode_pointer(undefined4 param_1)

{
  undefined4 uVar1;
  int iVar2;
  code *pcVar3;
  
  uVar1 = u_f__dd_vctools_vc7libs_ship_atlmf_0042815f._61_4_;
  iVar2 = (*(code *)u_f__dd_vctools_vc7libs_ship_atlmf_0042815f._61_4_)(u_WinVista_00431dbb._9_4_);
  if ((iVar2 != 0) && (u_WinVista_00431dbb._5_4_ != -1)) {
    pcVar3 = (code *)(*(code *)uVar1)(u_WinVista_00431dbb._9_4_,u_WinVista_00431dbb._5_4_);
    iVar2 = (*pcVar3)();
    if (iVar2 != 0) {
      pcVar3 = *(code **)(iVar2 + 0x1fc);
      goto LAB_00417a5d;
    }
  }
  iVar2 = (*DAT_004281e8)(&DAT_00429d60);
  if ((iVar2 == 0) && (iVar2 = func_0x8ea47c02(&DAT_00429d60), iVar2 == 0)) {
    return param_1;
  }
  pcVar3 = (code *)(*(code *)u_f__dd_vctools_vc7libs_ship_atlmf_0042815f._5_4_)(iVar2,&DAT_00429d7c)
  ;
LAB_00417a5d:
  if (pcVar3 != (code *)0x0) {
    param_1 = (*pcVar3)(param_1);
  }
  return param_1;
}



// Library Function - Single Match
//  _fastcopy_I
// 
// Libraries: Visual Studio 2005, Visual Studio 2008, Visual Studio 2019

void __cdecl _fastcopy_I(undefined4 *param_1,undefined4 *param_2,uint param_3)

{
  undefined4 uVar1;
  undefined4 uVar2;
  undefined4 uVar3;
  undefined4 uVar4;
  undefined4 uVar5;
  undefined4 uVar6;
  undefined4 uVar7;
  undefined4 uVar8;
  undefined4 uVar9;
  undefined4 uVar10;
  undefined4 uVar11;
  undefined4 uVar12;
  undefined4 uVar13;
  undefined4 uVar14;
  undefined4 uVar15;
  uint uVar16;
  
  uVar16 = param_3 >> 7;
  do {
    uVar1 = param_2[1];
    uVar2 = param_2[2];
    uVar3 = param_2[3];
    uVar4 = param_2[4];
    uVar5 = param_2[5];
    uVar6 = param_2[6];
    uVar7 = param_2[7];
    uVar8 = param_2[8];
    uVar9 = param_2[9];
    uVar10 = param_2[10];
    uVar11 = param_2[0xb];
    uVar12 = param_2[0xc];
    uVar13 = param_2[0xd];
    uVar14 = param_2[0xe];
    uVar15 = param_2[0xf];
    *param_1 = *param_2;
    param_1[1] = uVar1;
    param_1[2] = uVar2;
    param_1[3] = uVar3;
    param_1[4] = uVar4;
    param_1[5] = uVar5;
    param_1[6] = uVar6;
    param_1[7] = uVar7;
    param_1[8] = uVar8;
    param_1[9] = uVar9;
    param_1[10] = uVar10;
    param_1[0xb] = uVar11;
    param_1[0xc] = uVar12;
    param_1[0xd] = uVar13;
    param_1[0xe] = uVar14;
    param_1[0xf] = uVar15;
    uVar1 = param_2[0x11];
    uVar2 = param_2[0x12];
    uVar3 = param_2[0x13];
    uVar4 = param_2[0x14];
    uVar5 = param_2[0x15];
    uVar6 = param_2[0x16];
    uVar7 = param_2[0x17];
    uVar8 = param_2[0x18];
    uVar9 = param_2[0x19];
    uVar10 = param_2[0x1a];
    uVar11 = param_2[0x1b];
    uVar12 = param_2[0x1c];
    uVar13 = param_2[0x1d];
    uVar14 = param_2[0x1e];
    uVar15 = param_2[0x1f];
    param_1[0x10] = param_2[0x10];
    param_1[0x11] = uVar1;
    param_1[0x12] = uVar2;
    param_1[0x13] = uVar3;
    param_1[0x14] = uVar4;
    param_1[0x15] = uVar5;
    param_1[0x16] = uVar6;
    param_1[0x17] = uVar7;
    param_1[0x18] = uVar8;
    param_1[0x19] = uVar9;
    param_1[0x1a] = uVar10;
    param_1[0x1b] = uVar11;
    param_1[0x1c] = uVar12;
    param_1[0x1d] = uVar13;
    param_1[0x1e] = uVar14;
    param_1[0x1f] = uVar15;
    param_2 = param_2 + 0x20;
    param_1 = param_1 + 0x20;
    uVar16 = uVar16 - 1;
  } while (uVar16 != 0);
  return;
}



// Library Function - Single Match
//  __VEC_memcpy
// 
// Libraries: Visual Studio 2005, Visual Studio 2008, Visual Studio 2019

undefined4 * __cdecl __VEC_memcpy(undefined4 *param_1,undefined4 *param_2,uint param_3)

{
  int iVar1;
  int iVar2;
  uint uVar3;
  uint uVar4;
  undefined *puVar5;
  undefined4 *puVar6;
  undefined *puVar7;
  undefined4 *puVar8;
  
  uVar3 = (int)param_2 >> 0x1f;
  uVar3 = (((uint)param_2 ^ uVar3) - uVar3 & 0xf ^ uVar3) - uVar3;
  uVar4 = (int)param_1 >> 0x1f;
  uVar4 = (((uint)param_1 ^ uVar4) - uVar4 & 0xf ^ uVar4) - uVar4;
  if ((uVar3 | uVar4) == 0) {
    uVar3 = param_3 & 0x7f;
    if (param_3 != uVar3) {
      func_0x16b081ae(param_1,param_2,param_3 - uVar3);
    }
    if (uVar3 != 0) {
      puVar5 = (undefined *)((int)param_2 + (param_3 - uVar3));
      puVar7 = (undefined *)((int)param_1 + (param_3 - uVar3));
      for (; uVar3 != 0; uVar3 = uVar3 - 1) {
        *puVar7 = *puVar5;
        puVar5 = puVar5 + 1;
        puVar7 = puVar7 + 1;
      }
    }
  }
  else if (uVar3 == uVar4) {
    iVar1 = 0x10 - uVar3;
    puVar6 = param_2;
    puVar8 = param_1;
    for (iVar2 = iVar1; iVar2 != 0; iVar2 = iVar2 + -1) {
      *(undefined *)puVar8 = *(undefined *)puVar6;
      puVar6 = (undefined4 *)((int)puVar6 + 1);
      puVar8 = (undefined4 *)((int)puVar8 + 1);
    }
    func_0x9db08210((int)param_1 + iVar1,(int)param_2 + iVar1,param_3 - iVar1);
  }
  else {
    puVar6 = param_1;
    for (uVar3 = param_3 >> 2; uVar3 != 0; uVar3 = uVar3 - 1) {
      *puVar6 = *param_2;
      param_2 = param_2 + 1;
      puVar6 = puVar6 + 1;
    }
    for (uVar3 = param_3 & 3; uVar3 != 0; uVar3 = uVar3 - 1) {
      *(undefined *)puVar6 = *(undefined *)param_2;
      param_2 = (undefined4 *)((int)param_2 + 1);
      puVar6 = (undefined4 *)((int)puVar6 + 1);
    }
  }
  return param_1;
}



// WARNING: Removing unreachable block (ram,0x00418116)
// WARNING: Removing unreachable block (ram,0x00418103)
// Library Function - Single Match
//  __get_sse2_info
// 
// Libraries: Visual Studio 2005 Release, Visual Studio 2008 Release

undefined4 __get_sse2_info(void)

{
  uint uVar1;
  int iVar2;
  undefined4 uVar3;
  byte in_AF;
  byte in_TF;
  byte in_IF;
  byte in_NT;
  byte in_AC;
  byte in_VIF;
  byte in_VIP;
  byte in_ID;
  uint uVar4;
  uint local_8;
  
  local_8 = 0;
  uVar4 = (uint)(in_NT & 1) * 0x4000 | (uint)(in_IF & 1) * 0x200 | (uint)(in_TF & 1) * 0x100 | 0x40
          | (uint)(in_AF & 1) * 0x10 | 4 | (uint)(in_ID & 1) * 0x200000 |
          (uint)(in_VIP & 1) * 0x100000 | (uint)(in_VIF & 1) * 0x80000 | (uint)(in_AC & 1) * 0x40000
  ;
  uVar1 = uVar4 ^ 0x200000;
  if (((uint)((uVar1 & 0x4000) != 0) * 0x4000 | (uint)((uVar1 & 0x400) != 0) * 0x400 |
       (uint)((uVar1 & 0x200) != 0) * 0x200 | (uint)((uVar1 & 0x100) != 0) * 0x100 |
       (uint)((uVar1 & 0x40) != 0) * 0x40 | (uint)((uVar1 & 0x10) != 0) * 0x10 |
       (uint)((uVar1 & 4) != 0) * 4 | (uint)((uVar1 & 0x200000) != 0) * 0x200000 |
      (uint)((uVar1 & 0x40000) != 0) * 0x40000) != uVar4) {
    cpuid_basic_info(0);
    iVar2 = cpuid_Version_info(1);
    local_8 = *(uint *)(iVar2 + 8);
  }
  if (((local_8 & 0x4000000) == 0) || (iVar2 = func_0x80b182e3(), iVar2 == 0)) {
    uVar3 = 0;
  }
  else {
    uVar3 = 1;
  }
  return uVar3;
}



// Library Function - Single Match
//  __lock_file
// 
// Libraries: Visual Studio 2008 Release, Visual Studio 2010 Release

void __cdecl __lock_file(FILE *_File)

{
  if ((_File < (FILE *)((int)u_WinVista_00431dbb + 0xdU)) || ((FILE *)&DAT_00432028 < _File)) {
    (*(code *)u_f__dd_vctools_vc7libs_ship_atlmf_0042815f._57_4_)(_File + 1);
  }
  else {
    func_0x81d683ff(((int)&_File[-0x218ef]._bufsiz >> 5) + 0x10);
    _File->_flag = _File->_flag | 0x8000;
  }
  return;
}



// Library Function - Single Match
//  __lock_file2
// 
// Libraries: Visual Studio 2008 Release, Visual Studio 2010 Release

void __cdecl __lock_file2(int _Index,void *_File)

{
  if (_Index < 0x14) {
    func_0x81d6842c(_Index + 0x10);
    *(uint *)((int)_File + 0xc) = *(uint *)((int)_File + 0xc) | 0x8000;
    return;
  }
  (*(code *)u_f__dd_vctools_vc7libs_ship_atlmf_0042815f._57_4_)((int)_File + 0x20);
  return;
}



// Library Function - Single Match
//  __unlock_file
// 
// Libraries: Visual Studio 2008 Release, Visual Studio 2010 Release, Visual Studio 2012 Release

void __cdecl __unlock_file(FILE *_File)

{
  if (((FILE *)(u_WinVista_00431dbb + 6) < _File) && (_File < (FILE *)0x432029)) {
    _File->_flag = _File->_flag & 0xffff7fff;
    func_0xa7d58475(((int)&_File[-0x218ef]._bufsiz >> 5) + 0x10);
    return;
  }
  (*(code *)u_f__dd_vctools_vc7libs_ship_atlmf_0042815f._65_4_)(_File + 1);
  return;
}



// Library Function - Single Match
//  __unlock_file2
// 
// Library: Visual Studio 2008 Release

void __cdecl __unlock_file2(int _Index,void *_File)

{
  if (_Index < 0x14) {
    *(uint *)((int)_File + 0xc) = *(uint *)((int)_File + 0xc) & 0xffff7fff;
    func_0xa7d584a4(_Index + 0x10);
    return;
  }
  (*(code *)u_f__dd_vctools_vc7libs_ship_atlmf_0042815f._65_4_)((int)_File + 0x20);
  return;
}



// WARNING: Control flow encountered bad instruction data
// WARNING: Removing unreachable block (ram,0x004184b8)
// WARNING: Removing unreachable block (ram,0x004184bc)
// WARNING: Removing unreachable block (ram,0x004184ba)
// WARNING: Removing unreachable block (ram,0x004184c2)
// WARNING: Removing unreachable block (ram,0x004184da)
// WARNING: Removing unreachable block (ram,0x004184e4)
// WARNING: Removing unreachable block (ram,0x004184e2)
// WARNING: Removing unreachable block (ram,0x004184e9)
// WARNING: Removing unreachable block (ram,0x004184f3)
// WARNING: Removing unreachable block (ram,0x004184fa)
// WARNING: Removing unreachable block (ram,0x00418519)
// WARNING: Removing unreachable block (ram,0x00418538)
// WARNING: Removing unreachable block (ram,0x00418550)
// WARNING: Removing unreachable block (ram,0x0041852d)
// WARNING: Removing unreachable block (ram,0x0041850e)
// WARNING: Globals starting with '_' overlap smaller symbols at the same address
// Library Function - Single Match
//  __wopenfile
// 
// Library: Visual Studio 2008 Release

FILE * __cdecl __wopenfile(wchar_t *_Filename,wchar_t *_Mode,int _ShFlag,FILE *_File)

{
  wchar_t wVar1;
  bool bVar2;
  bool bVar3;
  bool bVar4;
  undefined4 *puVar5;
  int iVar6;
  uint uVar7;
  wchar_t *pwVar8;
  uint local_8;
  
  bVar4 = false;
  bVar3 = false;
  for (pwVar8 = _Mode; *pwVar8 == L' '; pwVar8 = pwVar8 + 1) {
  }
  wVar1 = *pwVar8;
  if (wVar1 == L'a') {
    uVar7 = 0x109;
LAB_0041836d:
    local_8 = DAT_00435ab8 | 2;
  }
  else {
    if (wVar1 != L'r') {
      if (wVar1 != L'w') goto LAB_0041833a;
      uVar7 = 0x301;
      goto LAB_0041836d;
    }
    uVar7 = 0;
    local_8 = DAT_00435ab8 | 1;
  }
  bVar2 = true;
  pwVar8 = pwVar8 + 1;
  wVar1 = *pwVar8;
  while ((wVar1 != L'\0' && (bVar2))) {
    if ((ushort)wVar1 < 0x54) {
      if (wVar1 == L'S') {
        if (bVar3) goto LAB_0041849b;
        bVar3 = true;
        uVar7 = uVar7 | 0x20;
      }
      else if (wVar1 != L' ') {
        if (wVar1 == L'+') {
          if ((uVar7 & 2) == 0) {
            uVar7 = uVar7 & 0xfffffffe | 2;
            local_8 = local_8 & 0xfffffffc | 0x80;
            goto LAB_004184a1;
          }
        }
        else {
          if (wVar1 == L',') {
                    // WARNING: Bad instruction - Truncating control flow here
            halt_baddata();
          }
          if (wVar1 == L'D') {
                    // WARNING: Bad instruction - Truncating control flow here
            halt_baddata();
          }
          if (wVar1 == L'N') {
                    // WARNING: Bad instruction - Truncating control flow here
            halt_baddata();
          }
          if (wVar1 != L'R') goto LAB_0041833a;
          if (!bVar3) {
                    // WARNING: Bad instruction - Truncating control flow here
            halt_baddata();
          }
        }
LAB_0041849b:
        bVar2 = false;
      }
    }
    else if (wVar1 == L'T') {
      if ((uVar7 & 0x1000) != 0) goto LAB_0041849b;
      uVar7 = uVar7 | 0x1000;
    }
    else if (wVar1 == L'b') {
      if ((uVar7 & 0xc000) != 0) goto LAB_0041849b;
      uVar7 = uVar7 | 0x8000;
    }
    else if (wVar1 == L'c') {
      if (bVar4) goto LAB_0041849b;
      local_8 = local_8 | 0x4000;
      bVar4 = true;
    }
    else if (wVar1 == L'n') {
      if (bVar4) goto LAB_0041849b;
      local_8 = local_8 & 0xffffbfff;
      bVar4 = true;
    }
    else {
      if (wVar1 != L't') goto LAB_0041833a;
      if ((uVar7 & 0xc000) != 0) goto LAB_0041849b;
      uVar7 = uVar7 | 0x4000;
    }
LAB_004184a1:
    pwVar8 = pwVar8 + 1;
    wVar1 = *pwVar8;
  }
  for (; *pwVar8 == L' '; pwVar8 = pwVar8 + 1) {
  }
  if (*pwVar8 == L'\0') {
    iVar6 = func_0xc0468837(&_Mode,_Filename,uVar7,_ShFlag,0x180);
    if (iVar6 != 0) {
      return;
    }
    _DAT_004352f8 = _DAT_004352f8 + 1;
    _File->_flag = local_8;
    _File->_cnt = 0;
    _File->_ptr = (char *)0x0;
    _File->_base = (char *)0x0;
    _File->_tmpfname = (char *)0x0;
    _File->_file = (int)_Mode;
    return _File;
  }
LAB_0041833a:
  puVar5 = (undefined4 *)func_0x788684f5();
  *puVar5 = 0x16;
  func_0x53aa8505(0,0,0,0,0);
                    // WARNING: Bad instruction - Truncating control flow here
  halt_baddata();
}



// Library Function - Single Match
//  __local_unwind4
// 
// Library: Visual Studio

void __cdecl __local_unwind4(uint *param_1,int param_2,uint param_3)

{
  undefined4 *puVar1;
  uint uVar2;
  void *pvStack_28;
  undefined4 uStack_24;
  uint local_20;
  uint uStack_1c;
  int iStack_18;
  uint *puStack_14;
  
  puStack_14 = param_1;
  iStack_18 = param_2;
  uStack_1c = param_3;
  uStack_24 = 0x418778;
  pvStack_28 = ExceptionList;
  local_20 = DAT_00431c20 ^ (uint)&pvStack_28;
  ExceptionList = &pvStack_28;
  while( true ) {
    uVar2 = *(uint *)(param_2 + 0xc);
    if ((uVar2 == 0xfffffffe) || ((param_3 != 0xfffffffe && (uVar2 <= param_3)))) break;
    puVar1 = (undefined4 *)((*(uint *)(param_2 + 8) ^ *param_1) + 0x10 + uVar2 * 0xc);
    *(undefined4 *)(param_2 + 0xc) = *puVar1;
    if (puVar1[1] == 0) {
      func_0xbc498a15(0x101);
      func_0xdb498a22();
    }
  }
  ExceptionList = pvStack_28;
  return;
}



// WARNING: Control flow encountered bad instruction data
// Library Function - Single Match
//  __filbuf
// 
// Library: Visual Studio 2008 Release

int __cdecl __filbuf(FILE *_File)

{
  byte bVar1;
  undefined4 *puVar2;
  undefined4 uVar3;
  int iVar4;
  uint uVar5;
  undefined *puVar6;
  
  if (_File == (FILE *)0x0) {
    puVar2 = (undefined4 *)func_0x78868a0a();
    *puVar2 = 0x16;
    func_0x53aa8a1a(0,0,0,0,0);
                    // WARNING: Bad instruction - Truncating control flow here
    halt_baddata();
  }
  uVar5 = _File->_flag;
  if (((uVar5 & 0x83) != 0) && ((uVar5 & 0x40) == 0)) {
    if ((uVar5 & 2) != 0) {
      _File->_flag = uVar5 | 0x20;
                    // WARNING: Bad instruction - Truncating control flow here
      halt_baddata();
    }
    _File->_flag = uVar5 | 1;
    if ((uVar5 & 0x10c) == 0) {
      func_0xde498b57(_File);
    }
    else {
      _File->_ptr = _File->_base;
    }
    uVar3 = func_0x20c18a6b(_File,_File->_base,_File->_bufsiz);
    iVar4 = func_0x23c08a72(uVar3);
    _File->_cnt = iVar4;
    if ((iVar4 != 0) && (iVar4 != -1)) {
      if ((*(byte *)&_File->_flag & 0x82) == 0) {
        iVar4 = func_0x20c18a95(_File);
        if ((iVar4 == -1) || (iVar4 = func_0x20c18aa1(_File), iVar4 == -2)) {
          puVar6 = &DAT_00432150;
        }
        else {
          iVar4 = func_0x20c18aad(_File);
          uVar5 = func_0x20c18abd(_File);
          puVar6 = (undefined *)((uVar5 & 0x1f) * 0x40 + (&DAT_00436d80)[iVar4 >> 5]);
        }
        if ((puVar6[4] & 0x82) == 0x82) {
          _File->_flag = _File->_flag | 0x2000;
        }
      }
      if (((_File->_bufsiz == 0x200) && ((_File->_flag & 8U) != 0)) &&
         ((_File->_flag & 0x400U) == 0)) {
        _File->_bufsiz = 0x1000;
      }
      _File->_cnt = _File->_cnt + -1;
      bVar1 = *_File->_ptr;
      _File->_ptr = _File->_ptr + 1;
      return (uint)bVar1;
    }
    _File->_flag = _File->_flag | (-(uint)(iVar4 != 0) & 0x10) + 0x10;
    _File->_cnt = 0;
  }
  return -1;
}



// WARNING: Control flow encountered bad instruction data
// Library Function - Single Match
//  __read_nolock
// 
// Library: Visual Studio 2008 Release

int __cdecl __read_nolock(int _FileHandle,void *_DstBuf,uint _MaxCharCount)

{
  int *piVar1;
  byte *pbVar2;
  byte bVar3;
  char cVar4;
  short sVar5;
  uint uVar6;
  undefined4 *puVar7;
  uint uVar8;
  short *psVar9;
  int iVar10;
  int iVar11;
  short *psVar12;
  int iVar13;
  bool bVar14;
  undefined8 uVar15;
  uint local_1c;
  int local_18;
  short *local_14;
  short *local_10;
  undefined2 local_c;
  char local_6;
  char local_5;
  
  uVar6 = _MaxCharCount;
  local_18 = -2;
  if (_FileHandle == -2) {
    puVar7 = (undefined4 *)func_0x8b868b41();
    *puVar7 = 0;
    puVar7 = (undefined4 *)func_0x78868b49();
    *puVar7 = 9;
                    // WARNING: Bad instruction - Truncating control flow here
    halt_baddata();
  }
  if ((_FileHandle < 0) || (DAT_00436d68 <= (uint)_FileHandle)) {
    puVar7 = (undefined4 *)func_0x8b868b6b();
    *puVar7 = 0;
    puVar7 = (undefined4 *)func_0x78868b72();
    *puVar7 = 9;
    func_0x53aa8b82(0,0,0,0,0);
                    // WARNING: Bad instruction - Truncating control flow here
    halt_baddata();
  }
  piVar1 = &DAT_00436d80 + (_FileHandle >> 5);
  iVar13 = (_FileHandle & 0x1fU) * 0x40;
  bVar3 = *(byte *)(*piVar1 + iVar13 + 4);
  if ((bVar3 & 1) == 0) {
    puVar7 = (undefined4 *)func_0x8b868bb1();
    *puVar7 = 0;
    puVar7 = (undefined4 *)func_0x78868bb8();
    *puVar7 = 9;
    goto LAB_00418a74;
  }
  if (_MaxCharCount < 0x80000000) {
    local_14 = (short *)0x0;
    if ((_MaxCharCount == 0) || ((bVar3 & 2) != 0)) {
      return 0;
    }
    if (_DstBuf != (void *)0x0) {
      local_6 = (char)(*(char *)(*piVar1 + iVar13 + 0x24) * '\x02') >> 1;
      if (local_6 == '\x01') {
        if ((~_MaxCharCount & 1) != 0) {
          uVar8 = _MaxCharCount >> 1;
          _MaxCharCount = 4;
          if (3 < uVar8) {
            _MaxCharCount = uVar8;
          }
          local_10 = (short *)func_0x3f2c8c4f(_MaxCharCount);
          if (local_10 == (short *)0x0) {
            puVar7 = (undefined4 *)func_0x78868c5c();
            *puVar7 = 0xc;
            puVar7 = (undefined4 *)func_0x8b868c67();
            *puVar7 = 8;
            return;
          }
          uVar15 = func_0x274a8d81(_FileHandle,0,0,1);
          iVar10 = *piVar1;
          *(int *)(iVar13 + 0x28 + iVar10) = (int)uVar15;
          *(int *)(iVar13 + 0x2c + iVar10) = (int)((ulonglong)uVar15 >> 0x20);
          psVar9 = local_10;
          uVar8 = _MaxCharCount;
          if ((((*(byte *)(*piVar1 + iVar13 + 4) & 0x48) != 0) &&
              (cVar4 = *(char *)(*piVar1 + iVar13 + 5), cVar4 != '\n')) && (_MaxCharCount != 0)) {
            *(char *)local_10 = cVar4;
            psVar9 = (short *)((int)local_10 + 1);
            uVar8 = _MaxCharCount - 1;
            local_14 = (short *)0x1;
            *(undefined *)(iVar13 + 5 + *piVar1) = 10;
            if (((local_6 != '\0') && (cVar4 = *(char *)(iVar13 + 0x25 + *piVar1), cVar4 != '\n'))
               && (uVar8 != 0)) {
              *(char *)psVar9 = cVar4;
              psVar9 = local_10 + 1;
              uVar8 = _MaxCharCount - 2;
              local_14 = (short *)0x2;
              *(undefined *)(iVar13 + 0x25 + *piVar1) = 10;
              if (((local_6 == '\x01') &&
                  (cVar4 = *(char *)(iVar13 + 0x26 + *piVar1), cVar4 != '\n')) && (uVar8 != 0)) {
                *(char *)psVar9 = cVar4;
                psVar9 = (short *)((int)local_10 + 3);
                local_14 = (short *)0x3;
                *(undefined *)(iVar13 + 0x26 + *piVar1) = 10;
                uVar8 = _MaxCharCount - 3;
              }
            }
          }
          _MaxCharCount = uVar8;
          iVar10 = (*DAT_00428208)(*(undefined4 *)(iVar13 + *piVar1),psVar9,_MaxCharCount,&local_1c,
                                   0);
          if (((iVar10 == 0) || ((int)local_1c < 0)) || (_MaxCharCount < local_1c)) {
            iVar13 = (*DAT_004281cc)();
            if (iVar13 == 5) {
              puVar7 = (undefined4 *)func_0x788690b8();
              *puVar7 = 9;
              puVar7 = (undefined4 *)func_0x8b8690c3();
              *puVar7 = 5;
                    // WARNING: Bad instruction - Truncating control flow here
              halt_baddata();
            }
            if (iVar13 == 0x6d) {
                    // WARNING: Bad instruction - Truncating control flow here
              halt_baddata();
            }
LAB_00418d76:
            func_0x9e868f32(iVar13);
          }
          else {
            local_14 = (short *)((int)local_14 + local_1c);
            pbVar2 = (byte *)(iVar13 + 4 + *piVar1);
            if ((*pbVar2 & 0x80) == 0) goto LAB_00418d81;
            if (local_6 == '\x02') {
              if ((local_1c == 0) || (*local_10 != 10)) {
                *pbVar2 = *pbVar2 & 0xfb;
              }
              else {
                *pbVar2 = *pbVar2 | 4;
              }
              local_14 = (short *)((int)local_14 + (int)local_10);
              _MaxCharCount = (uint)local_10;
              psVar9 = local_10;
              if (local_10 < local_14) {
                do {
                  sVar5 = *(short *)_MaxCharCount;
                  if (sVar5 == 0x1a) {
                    pbVar2 = (byte *)(iVar13 + 4 + *piVar1);
                    if ((*pbVar2 & 0x40) == 0) {
                      *pbVar2 = *pbVar2 | 2;
                      return;
                    }
                    *psVar9 = *(short *)_MaxCharCount;
                    return;
                  }
                  if (sVar5 != 0xd) {
                    *psVar9 = sVar5;
                    // WARNING: Bad instruction - Truncating control flow here
                    halt_baddata();
                  }
                  if (_MaxCharCount < local_14 + -1) {
                    if (*(short *)(_MaxCharCount + 2) == 10) {
                      return;
                    }
                    // WARNING: Bad instruction - Truncating control flow here
                    halt_baddata();
                  }
                  _MaxCharCount = _MaxCharCount + 2;
                  iVar10 = (*DAT_00428208)(*(undefined4 *)(iVar13 + *piVar1),&local_c,2,&local_1c,0)
                  ;
                  if (((iVar10 == 0) && (iVar10 = (*DAT_004281cc)(), iVar10 != 0)) ||
                     (local_1c == 0)) {
LAB_00418eb7:
                    *psVar9 = 0xd;
LAB_00418ebd:
                    psVar9 = psVar9 + 1;
                  }
                  else {
                    if ((*(byte *)(iVar13 + 4 + *piVar1) & 0x48) != 0) {
                      if (local_c == 10) {
                        return;
                      }
                      *psVar9 = 0xd;
                      *(undefined *)(iVar13 + 5 + *piVar1) = (undefined)local_c;
                      *(undefined *)(iVar13 + 0x25 + *piVar1) = local_c._1_1_;
                      *(undefined *)(iVar13 + 0x26 + *piVar1) = 10;
                      goto LAB_00418ebd;
                    }
                    if ((psVar9 == local_10) && (local_c == 10)) {
                    // WARNING: Bad instruction - Truncating control flow here
                      halt_baddata();
                    }
                    func_0x274a9163(_FileHandle,0xfffffffe,0xffffffff,1);
                    if (local_c != 10) goto LAB_00418eb7;
                  }
                } while (_MaxCharCount < local_14);
              }
                    // WARNING: Bad instruction - Truncating control flow here
              halt_baddata();
            }
            if ((local_1c == 0) || (*(char *)local_10 != '\n')) {
              *pbVar2 = *pbVar2 & 0xfb;
            }
            else {
              *pbVar2 = *pbVar2 | 4;
            }
            local_14 = (short *)((int)local_14 + (int)local_10);
            _MaxCharCount = (uint)local_10;
            psVar9 = local_10;
            if (local_10 < local_14) {
              do {
                cVar4 = *(char *)_MaxCharCount;
                if (cVar4 == '\x1a') {
                  pbVar2 = (byte *)(iVar13 + 4 + *piVar1);
                  if ((*pbVar2 & 0x40) == 0) {
                    *pbVar2 = *pbVar2 | 2;
                  }
                  else {
                    *(undefined *)psVar9 = *(undefined *)_MaxCharCount;
                    psVar9 = (short *)((int)psVar9 + 1);
                  }
                  break;
                }
                if (cVar4 != '\r') {
                  *(char *)psVar9 = cVar4;
                    // WARNING: Bad instruction - Truncating control flow here
                  halt_baddata();
                }
                if (_MaxCharCount < (undefined *)((int)local_14 + -1)) {
                  if (*(char *)(_MaxCharCount + 1) == '\n') {
                    uVar8 = _MaxCharCount + 2;
                    goto LAB_00418c01;
                  }
LAB_00418c78:
                  _MaxCharCount = _MaxCharCount + 1;
                  *(undefined *)psVar9 = 0xd;
LAB_00418c7b:
                  psVar9 = (short *)((int)psVar9 + 1);
                  uVar8 = _MaxCharCount;
                }
                else {
                  uVar8 = _MaxCharCount + 1;
                  iVar10 = (*DAT_00428208)(*(undefined4 *)(iVar13 + *piVar1),&local_5,1,&local_1c,0)
                  ;
                  if (((iVar10 == 0) && (iVar10 = (*DAT_004281cc)(), iVar10 != 0)) ||
                     (local_1c == 0)) goto LAB_00418c78;
                  if ((*(byte *)(iVar13 + 4 + *piVar1) & 0x48) != 0) {
                    if (local_5 == '\n') goto LAB_00418c01;
                    *(undefined *)psVar9 = 0xd;
                    *(char *)(iVar13 + 5 + *piVar1) = local_5;
                    _MaxCharCount = uVar8;
                    goto LAB_00418c7b;
                  }
                  if ((psVar9 == local_10) && (local_5 == '\n')) {
LAB_00418c01:
                    _MaxCharCount = uVar8;
                    *(undefined *)psVar9 = 10;
                    goto LAB_00418c7b;
                  }
                  func_0x274a8f25(_FileHandle,0xffffffff,0xffffffff,1);
                  if (local_5 != '\n') goto LAB_00418c78;
                }
                _MaxCharCount = uVar8;
              } while (_MaxCharCount < local_14);
            }
            local_14 = (short *)((int)psVar9 - (int)local_10);
            if ((local_6 != '\x01') || (local_14 == (short *)0x0)) goto LAB_00418d81;
            psVar9 = (short *)((int)psVar9 + -1);
            bVar3 = *(byte *)psVar9;
            if (-1 < (char)bVar3) {
                    // WARNING: Bad instruction - Truncating control flow here
              halt_baddata();
            }
            iVar10 = 1;
            while (((*(char *)(bVar3 + 0x432048) == '\0' && (iVar10 < 5)) && (local_10 <= psVar9)))
            {
              psVar9 = (short *)((int)psVar9 + -1);
              bVar3 = *(byte *)psVar9;
              iVar10 = iVar10 + 1;
            }
            iVar11 = (int)*(char *)(*(byte *)psVar9 + 0x432048);
            if (iVar11 != 0) {
              if (iVar11 + 1 == iVar10) {
                psVar9 = (short *)((int)psVar9 + iVar10);
              }
              else if ((*(byte *)(*piVar1 + iVar13 + 4) & 0x48) == 0) {
                func_0x274a8fff(_FileHandle,-iVar10,-iVar10 >> 0x1f,1);
              }
              else {
                psVar12 = (short *)((int)psVar9 + 1);
                *(byte *)(*piVar1 + iVar13 + 5) = *(byte *)psVar9;
                if (1 < iVar10) {
                  *(undefined *)(iVar13 + 0x25 + *piVar1) = *(undefined *)psVar12;
                  psVar12 = psVar9 + 1;
                }
                if (iVar10 == 3) {
                  *(undefined *)(iVar13 + 0x26 + *piVar1) = *(undefined *)psVar12;
                  psVar12 = (short *)((int)psVar12 + 1);
                }
                psVar9 = (short *)((int)psVar12 - iVar10);
              }
              iVar10 = (int)psVar9 - (int)local_10;
              local_14 = (short *)(*DAT_004281f0)(0xfde9,0,local_10,iVar10,_DstBuf,uVar6 >> 1);
              if (local_14 != (short *)0x0) {
                bVar14 = local_14 != (short *)iVar10;
                local_14 = (short *)((int)local_14 * 2);
                *(uint *)(iVar13 + 0x30 + *piVar1) = (uint)bVar14;
                goto LAB_00418d81;
              }
              iVar13 = (*DAT_004281cc)();
              goto LAB_00418d76;
            }
            puVar7 = (undefined4 *)func_0x78868eb1();
            *puVar7 = 0x2a;
          }
          local_18 = -1;
LAB_00418d81:
          if (local_10 != (short *)_DstBuf) {
            func_0xc2738f45(local_10);
          }
          if (local_18 != -2) {
            return local_18;
          }
                    // WARNING: Bad instruction - Truncating control flow here
          halt_baddata();
        }
      }
      else if ((local_6 != '\x02') || ((~_MaxCharCount & 1) != 0)) {
                    // WARNING: Bad instruction - Truncating control flow here
        halt_baddata();
      }
    }
  }
  puVar7 = (undefined4 *)func_0x8b868c1d();
  *puVar7 = 0;
  puVar7 = (undefined4 *)func_0x78868c24();
  *puVar7 = 0x16;
LAB_00418a74:
  func_0x53aa8c34(0,0,0,0,0);
                    // WARNING: Bad instruction - Truncating control flow here
  halt_baddata();
}



// Library Function - Single Match
//  __fileno
// 
// Library: Visual Studio 2008 Release

int __cdecl __fileno(FILE *_File)

{
  undefined4 *puVar1;
  int iVar2;
  
  if (_File == (FILE *)0x0) {
    puVar1 = (undefined4 *)func_0x788691f3();
    *puVar1 = 0x16;
    func_0x53aa9203(0,0,0,0,0);
    iVar2 = -1;
  }
  else {
    iVar2 = _File->_file;
  }
  return iVar2;
}



// Library Function - Single Match
//  __close_nolock
// 
// Libraries: Visual Studio 2008 Release, Visual Studio 2010 Release

int __cdecl __close_nolock(int _FileHandle)

{
  int iVar1;
  int iVar2;
  undefined4 uVar3;
  
  iVar1 = func_0xcc4c9321(_FileHandle);
  if (iVar1 != -1) {
    if (((_FileHandle == 1) && ((*(byte *)(DAT_00436d80 + 0x84) & 1) != 0)) ||
       ((_FileHandle == 2 && ((*(byte *)(DAT_00436d80 + 0x44) & 1) != 0)))) {
      iVar1 = func_0xcc4c934c(2);
      iVar2 = func_0xcc4c9355(1);
      if (iVar2 == iVar1) goto LAB_004190c1;
    }
    uVar3 = func_0xcc4c9361(_FileHandle);
    iVar1 = (*DAT_00428224)(uVar3);
    if (iVar1 == 0) {
      iVar1 = (*DAT_004281cc)();
      goto LAB_004190c3;
    }
  }
LAB_004190c1:
  iVar1 = 0;
LAB_004190c3:
  func_0x464c937f(_FileHandle);
  *(undefined *)((&DAT_00436d80)[_FileHandle >> 5] + 4 + (_FileHandle & 0x1fU) * 0x40) = 0;
  if (iVar1 == 0) {
    iVar1 = 0;
  }
  else {
    func_0x9e8692a1(iVar1);
    iVar1 = -1;
  }
  return iVar1;
}



// Library Function - Single Match
//  __freebuf
// 
// Libraries: Visual Studio 2008 Release, Visual Studio 2010 Release

void __cdecl __freebuf(FILE *_File)

{
  if (((_File->_flag & 0x83U) != 0) && ((_File->_flag & 8U) != 0)) {
    func_0xc2739396(_File->_base);
    _File->_flag = _File->_flag & 0xfffffbf7;
    _File->_ptr = (char *)0x0;
    _File->_base = (char *)0x0;
    _File->_cnt = 0;
  }
  return;
}



// Library Function - Single Match
//  __flush
// 
// Libraries: Visual Studio 2008 Release, Visual Studio 2010 Release

int __cdecl __flush(FILE *_File)

{
  undefined4 uVar1;
  int iVar2;
  int iVar3;
  int iVar4;
  
  iVar3 = 0;
  if ((((byte)_File->_flag & 3) == 2) && ((_File->_flag & 0x108U) != 0)) {
    iVar4 = (int)_File->_ptr - (int)_File->_base;
    if (0 < iVar4) {
      uVar1 = func_0x20c193df(_File,_File->_base,iVar4);
      iVar2 = func_0x16cd93e6(uVar1);
      if (iVar2 == iVar4) {
        if ((char)_File->_flag < '\0') {
          _File->_flag = _File->_flag & 0xfffffffd;
        }
      }
      else {
        _File->_flag = _File->_flag | 0x20;
        iVar3 = -1;
      }
    }
  }
  _File->_cnt = 0;
  _File->_ptr = _File->_base;
  return iVar3;
}



// Library Function - Single Match
//  __fflush_nolock
// 
// Libraries: Visual Studio 2008 Release, Visual Studio 2010 Release, Visual Studio 2012 Release

int __cdecl __fflush_nolock(FILE *_File)

{
  int iVar1;
  undefined4 uVar2;
  
  if (_File == (FILE *)0x0) {
    iVar1 = func_0x9cc39426(0);
  }
  else {
    iVar1 = func_0xecc2942f(_File);
    if (iVar1 == 0) {
      if ((_File->_flag & 0x4000U) == 0) {
        iVar1 = 0;
      }
      else {
        uVar2 = func_0x20c19448(_File);
        iVar1 = func_0xa44f954e(uVar2);
        iVar1 = -(uint)(iVar1 != 0);
      }
    }
    else {
      iVar1 = -1;
    }
  }
  return iVar1;
}



// WARNING: Control flow encountered bad instruction data
// Library Function - Single Match
//  __flsbuf
// 
// Library: Visual Studio 2008 Release

int __cdecl __flsbuf(int _Ch,FILE *_File)

{
  uint uVar1;
  char *pcVar2;
  char *pcVar3;
  FILE *pFVar4;
  undefined4 *puVar5;
  int iVar6;
  undefined *puVar7;
  longlong lVar8;
  int local_8;
  
  pFVar4 = _File;
  _File = (FILE *)func_0x20c1954e(_File);
  uVar1 = pFVar4->_flag;
  if ((uVar1 & 0x82) == 0) {
    puVar5 = (undefined4 *)func_0x7886955e();
    *puVar5 = 9;
LAB_004193ae:
    pFVar4->_flag = pFVar4->_flag | 0x20;
                    // WARNING: Bad instruction - Truncating control flow here
    halt_baddata();
  }
  if ((uVar1 & 0x40) != 0) {
    puVar5 = (undefined4 *)func_0x78869579();
    *puVar5 = 0x22;
    goto LAB_004193ae;
  }
  if ((uVar1 & 1) != 0) {
    pFVar4->_cnt = 0;
    if ((uVar1 & 0x10) == 0) {
      pFVar4->_flag = uVar1 | 0x20;
      return -1;
    }
    pFVar4->_ptr = pFVar4->_base;
    pFVar4->_flag = uVar1 & 0xfffffffe;
  }
  uVar1 = pFVar4->_flag;
  pFVar4->_flag = uVar1 & 0xffffffef | 2;
  pFVar4->_cnt = 0;
  local_8 = 0;
  if (((uVar1 & 0x10c) == 0) &&
     (((iVar6 = func_0x3fb295bc(), pFVar4 != (FILE *)(iVar6 + 0x20) &&
       (iVar6 = func_0x3fb295c8(), pFVar4 != (FILE *)(iVar6 + 0x40))) ||
      (iVar6 = func_0x855096d7(_File), iVar6 == 0)))) {
    func_0xde4996e2(pFVar4);
  }
  if ((pFVar4->_flag & 0x108U) == 0) {
    iVar6 = 1;
    local_8 = func_0x16cd9681(_File,&_Ch,1);
  }
  else {
    pcVar2 = pFVar4->_base;
    pcVar3 = pFVar4->_ptr;
    pFVar4->_ptr = pcVar2 + 1;
    iVar6 = (int)pcVar3 - (int)pcVar2;
    pFVar4->_cnt = pFVar4->_bufsiz + -1;
    if (iVar6 < 1) {
      if ((_File == (FILE *)0xffffffff) || (_File == (FILE *)0xfffffffe)) {
        puVar7 = &DAT_00432150;
      }
      else {
        puVar7 = (undefined *)(((uint)_File & 0x1f) * 0x40 + (&DAT_00436d80)[(int)_File >> 5]);
      }
      if (((puVar7[4] & 0x20) != 0) && (lVar8 = func_0xac4a975d(_File,0,0,2), lVar8 == -1))
      goto LAB_004194d6;
    }
    else {
      local_8 = func_0x16cd9612(_File,pcVar2,iVar6);
    }
    *pFVar4->_base = (char)_Ch;
  }
  if (local_8 == iVar6) {
    return _Ch & 0xff;
  }
LAB_004194d6:
  pFVar4->_flag = pFVar4->_flag | 0x20;
  return -1;
}



// WARNING: Control flow encountered bad instruction data
// WARNING: Type propagation algorithm not settling
// Library Function - Single Match
//  __write_nolock
// 
// Library: Visual Studio 2008 Release

int __cdecl __write_nolock(int _FileHandle,void *_Buf,uint _MaxCharCount)

{
  ushort uVar1;
  short sVar2;
  undefined4 *puVar3;
  int iVar4;
  undefined4 **ppuVar5;
  undefined4 ******ppppppuVar6;
  int iVar7;
  uint uVar8;
  char cVar9;
  undefined4 *******pppppppuVar10;
  int *piVar11;
  char *pcVar12;
  int iVar13;
  undefined4 local_1ae8;
  uint local_1ae4;
  char local_1add;
  int *local_1adc;
  undefined4 ******local_1ad8;
  int local_1ad4;
  undefined4 *******local_1ad0;
  undefined4 ******local_1acc;
  undefined4 *******local_1ac8;
  undefined4 *local_1ac4;
  undefined4 *******local_1ac0;
  undefined4 ******local_1abc [426];
  undefined4 ******local_1414 [854];
  undefined4 *local_6bc [418];
  undefined4 uStack_34;
  undefined4 uStack_30;
  undefined4 uStack_2c;
  undefined4 **ppuStack_28;
  int iStack_24;
  undefined4 *******pppppppuStack_20;
  undefined4 **ppuStack_1c;
  undefined4 *******pppppppuStack_18;
  undefined4 *puStack_14;
  
  func_0xeba796b1();
  local_1ad0 = (undefined4 *******)_Buf;
  local_1acc = (undefined4 ******)0x0;
  local_1ad4 = 0;
  if (_MaxCharCount == 0) {
                    // WARNING: Bad instruction - Truncating control flow here
    halt_baddata();
  }
  if (_Buf == (void *)0x0) {
    puVar3 = (undefined4 *)func_0x8b8696e8();
    *puVar3 = 0;
    puVar3 = (undefined4 *)func_0x788696ef();
    puStack_14 = (undefined4 *)0x0;
    pppppppuStack_18 = (undefined4 *******)0x0;
    ppuStack_1c = (undefined4 **)0x0;
    *puVar3 = 0x16;
    pppppppuStack_20 = (undefined4 *******)0x419549;
    func_0x53aa96ff();
                    // WARNING: Bad instruction - Truncating control flow here
    halt_baddata();
  }
  piVar11 = &DAT_00436d80 + (_FileHandle >> 5);
  iVar13 = (_FileHandle & 0x1fU) * 0x40;
  cVar9 = (char)(*(char *)(*piVar11 + iVar13 + 0x24) * '\x02') >> 1;
  local_1add = cVar9;
  local_1adc = piVar11;
  if (((cVar9 == '\x02') || (cVar9 == '\x01')) && ((~_MaxCharCount & 1) == 0)) {
    puStack_14 = (undefined4 *)0x41959b;
    puVar3 = (undefined4 *)func_0x8b869751();
    *puVar3 = 0;
    puStack_14 = (undefined4 *)0x4195a4;
    puVar3 = (undefined4 *)func_0x7886975a();
    puStack_14 = (undefined4 *)0x0;
    pppppppuStack_18 = (undefined4 *******)0x0;
    ppuStack_1c = (undefined4 **)0x0;
    pppppppuStack_20 = (undefined4 *******)0x0;
    iStack_24 = 0;
    *puVar3 = 0x16;
    ppuStack_28 = (undefined4 **)0x4195b4;
    func_0x53aa976a();
                    // WARNING: Bad instruction - Truncating control flow here
    halt_baddata();
  }
  if ((*(byte *)(*piVar11 + iVar13 + 4) & 0x20) != 0) {
    puStack_14 = (undefined4 *)0x2;
    pppppppuStack_18 = (undefined4 *******)0x0;
    ppuStack_1c = (undefined4 **)0x0;
    pppppppuStack_20 = (undefined4 *******)_FileHandle;
    iStack_24 = 0x4195d0;
    func_0x274a9886();
  }
  puStack_14 = (undefined4 *)_FileHandle;
  pppppppuStack_18 = (undefined4 *******)0x4195db;
  iVar4 = func_0x85509891();
  if ((iVar4 == 0) || ((*(byte *)(iVar13 + 4 + *piVar11) & 0x80) == 0)) {
LAB_00419883:
    if ((*(byte *)((int *)(*piVar11 + iVar13) + 1) & 0x80) == 0) {
      puStack_14 = (undefined4 *)0x0;
      pppppppuStack_18 = &local_1ad8;
      ppuStack_1c = (undefined4 **)_MaxCharCount;
      pppppppuStack_20 = local_1ad0;
      iStack_24 = *(int *)(*piVar11 + iVar13);
      ppuStack_28 = (undefined4 **)0x419b6a;
      iVar4 = (*DAT_004281f8)();
      if (iVar4 == 0) {
LAB_00419b83:
        puStack_14 = (undefined4 *)0x419b89;
        local_1ac4 = (undefined4 *)(*DAT_004281cc)();
      }
      else {
        local_1ac4 = (undefined4 *)0x0;
        local_1acc = local_1ad8;
      }
LAB_00419b8f:
      if (local_1acc != (undefined4 ******)0x0) goto LAB_00419c10;
      goto LAB_00419b98;
    }
    local_1ac4 = (undefined4 *)0x0;
    if (cVar9 == '\0') {
      local_1ac8 = local_1ad0;
      if (_MaxCharCount != 0) {
        do {
          local_1ac0 = (undefined4 *******)0x0;
          uVar8 = (int)local_1ac8 - (int)local_1ad0;
          ppppppuVar6 = local_1abc;
          do {
            if (_MaxCharCount <= uVar8) break;
            pppppppuVar10 = (undefined4 *******)((int)local_1ac8 + 1);
            cVar9 = *(char *)local_1ac8;
            uVar8 = uVar8 + 1;
            if (cVar9 == '\n') {
              local_1ad4 = local_1ad4 + 1;
              *(char *)ppppppuVar6 = '\r';
              ppppppuVar6 = (undefined4 ******)((int)ppppppuVar6 + 1);
              local_1ac0 = (undefined4 *******)((int)local_1ac0 + 1);
            }
            *(char *)ppppppuVar6 = cVar9;
            ppppppuVar6 = (undefined4 ******)((int)ppppppuVar6 + 1);
            local_1ac0 = (undefined4 *******)((int)local_1ac0 + 1);
            local_1ac8 = pppppppuVar10;
          } while (local_1ac0 < (undefined4 *******)0x13ff);
          puStack_14 = (undefined4 *)0x0;
          pppppppuStack_18 = &local_1ad8;
          pppppppuStack_20 = local_1abc;
          iStack_24 = *(int *)(iVar13 + *piVar11);
          ppuStack_28 = (undefined4 **)0x419939;
          ppuStack_1c = (undefined4 **)((int)ppppppuVar6 - (int)local_1abc);
          iVar4 = (*DAT_004281f8)();
          if (iVar4 == 0) goto LAB_00419b83;
          local_1acc = (undefined4 ******)((int)local_1acc + (int)local_1ad8);
          if ((int)local_1ad8 < (int)(undefined4 **)((int)ppppppuVar6 - (int)local_1abc))
          goto LAB_00419b8f;
          piVar11 = local_1adc;
          if (_MaxCharCount <= (uint)((int)local_1ac8 - (int)local_1ad0)) {
                    // WARNING: Bad instruction - Truncating control flow here
            halt_baddata();
          }
        } while( true );
      }
    }
    else {
      local_1ac0 = local_1ad0;
      if (cVar9 == '\x02') {
        if (_MaxCharCount != 0) {
          do {
            local_1ac8 = (undefined4 *******)0x0;
            uVar8 = (int)local_1ac0 - (int)local_1ad0;
            ppppppuVar6 = local_1abc;
            do {
              if (_MaxCharCount <= uVar8) break;
              pppppppuVar10 = (undefined4 *******)((int)local_1ac0 + 2);
              uVar1 = *(ushort *)local_1ac0;
              uVar8 = uVar8 + 2;
              if (uVar1 == 10) {
                local_1ad4 = local_1ad4 + 2;
                *(ushort *)ppppppuVar6 = 0xd;
                ppppppuVar6 = (undefined4 ******)((int)ppppppuVar6 + 2);
                local_1ac8 = (undefined4 *******)((int)local_1ac8 + 2);
              }
              local_1ac8 = (undefined4 *******)((int)local_1ac8 + 2);
              *(ushort *)ppppppuVar6 = uVar1;
              ppppppuVar6 = (undefined4 ******)((int)ppppppuVar6 + 2);
              local_1ac0 = pppppppuVar10;
            } while (local_1ac8 < (undefined4 *******)0x13fe);
            puStack_14 = (undefined4 *)0x0;
            pppppppuStack_18 = &local_1ad8;
            pppppppuStack_20 = local_1abc;
            iStack_24 = *(int *)(iVar13 + *piVar11);
            ppuStack_28 = (undefined4 **)0x419a19;
            ppuStack_1c = (undefined4 **)((int)ppppppuVar6 - (int)local_1abc);
            iVar4 = (*DAT_004281f8)();
            if (iVar4 == 0) goto LAB_00419b83;
            local_1acc = (undefined4 ******)((int)local_1acc + (int)local_1ad8);
            if ((int)local_1ad8 < (int)(undefined4 **)((int)ppppppuVar6 - (int)local_1abc))
            goto LAB_00419b8f;
            piVar11 = local_1adc;
            if (_MaxCharCount <= (uint)((int)local_1ac0 - (int)local_1ad0)) {
                    // WARNING: Bad instruction - Truncating control flow here
              halt_baddata();
            }
          } while( true );
        }
      }
      else if (_MaxCharCount != 0) {
        do {
          local_1ac8 = (undefined4 *******)0x0;
          uVar8 = (int)local_1ac0 - (int)local_1ad0;
          ppuVar5 = local_6bc;
          do {
            if (_MaxCharCount <= uVar8) break;
            uVar1 = *(ushort *)local_1ac0;
            local_1ac0 = (undefined4 *******)((int)local_1ac0 + 2);
            uVar8 = uVar8 + 2;
            if (uVar1 == 10) {
              *(ushort *)ppuVar5 = 0xd;
              ppuVar5 = (undefined4 **)((int)ppuVar5 + 2);
              local_1ac8 = (undefined4 *******)((int)local_1ac8 + 2);
            }
            local_1ac8 = (undefined4 *******)((int)local_1ac8 + 2);
            *(ushort *)ppuVar5 = uVar1;
            ppuVar5 = (undefined4 **)((int)ppuVar5 + 2);
          } while (local_1ac8 < (undefined4 *******)0x6a8);
          pcVar12 = (char *)0x0;
          puStack_14 = (undefined4 *)0x0;
          pppppppuStack_18 = (undefined4 *******)0x0;
          ppuStack_1c = (undefined4 **)0xd55;
          pppppppuStack_20 = local_1414;
          ppuStack_28 = local_6bc;
          iStack_24 = ((int)ppuVar5 - (int)ppuStack_28) / 2;
          uStack_2c = 0;
          uStack_30 = 0xfde9;
          uStack_34 = 0x419ae2;
          iVar4 = (*(code *)u_f__dd_vctools_vc7libs_ship_atlmf_0042815f._89_4_)();
          if (iVar4 == 0) goto LAB_00419b83;
          do {
            puStack_14 = (undefined4 *)0x0;
            pppppppuStack_18 = &local_1ad8;
            ppuStack_1c = (undefined4 **)(iVar4 - (int)pcVar12);
            pppppppuStack_20 = (undefined4 *******)((int)local_1414 + (int)pcVar12);
            iStack_24 = *(int *)(iVar13 + *local_1adc);
            ppuStack_28 = (undefined4 **)0x419b13;
            iVar7 = (*DAT_004281f8)();
            if (iVar7 == 0) {
              puStack_14 = (undefined4 *)0x419b29;
              local_1ac4 = (undefined4 *)(*DAT_004281cc)();
              break;
            }
            pcVar12 = pcVar12 + (int)local_1ad8;
          } while ((int)pcVar12 < iVar4);
        } while ((iVar4 <= (int)pcVar12) &&
                (local_1acc = (undefined4 ******)((int)local_1ac0 - (int)local_1ad0),
                local_1acc < _MaxCharCount));
        goto LAB_00419b8f;
      }
    }
  }
  else {
    puStack_14 = (undefined4 *)0x4195f6;
    iVar4 = func_0x40ad97ac();
    puStack_14 = &local_1ae8;
    local_1ae4 = (uint)(*(int *)(*(int *)(iVar4 + 0x6c) + 0x14) == 0);
    pppppppuStack_18 = *(undefined4 ********)(iVar13 + *piVar11);
    ppuStack_1c = (undefined4 **)0x419619;
    iVar4 = (*DAT_004280f4)();
    if ((iVar4 == 0) || ((local_1ae4 != 0 && (cVar9 == '\0')))) goto LAB_00419883;
    puStack_14 = (undefined4 *)0x419639;
    local_1ae8 = (*DAT_004280f0)();
    local_1ac8 = (undefined4 *******)0x0;
    if (_MaxCharCount != 0) {
      local_1ac0 = (undefined4 *******)0x0;
      pppppppuVar10 = local_1ad0;
      do {
        piVar11 = local_1adc;
        if (local_1add == '\0') {
          local_1ae4 = (uint)(*(char *)pppppppuVar10 == '\n');
          if (*(int *)(*local_1adc + iVar13 + 0x38) == 0) {
            puStack_14 = (undefined4 *)(int)*(char *)pppppppuVar10;
            pppppppuStack_18 = (undefined4 *******)0x4196a8;
            iVar4 = func_0x1753995e();
            pppppppuStack_18 = pppppppuVar10;
            if (iVar4 == 0) {
              puStack_14 = (undefined4 *)0x1;
              goto LAB_004196ea;
            }
            if ((char *)((int)local_1ad0 + (_MaxCharCount - (int)pppppppuVar10)) < (char *)0x2) {
              *(char *)(iVar13 + 0x34 + *piVar11) = *(char *)pppppppuVar10;
              *(undefined4 *)(iVar13 + 0x38 + *piVar11) = 1;
                    // WARNING: Bad instruction - Truncating control flow here
              halt_baddata();
            }
            puStack_14 = (undefined4 *)0x2;
            ppuStack_1c = &local_1ac4;
            pppppppuStack_20 = (undefined4 *******)0x4196d2;
            iVar4 = func_0xc5529988();
            if (iVar4 == -1) goto LAB_00419b8f;
            pppppppuVar10 = (undefined4 *******)((int)pppppppuVar10 + 1);
            local_1ac0 = (undefined4 *******)((int)local_1ac0 + 1);
          }
          else {
            *(undefined4 *)(*local_1adc + iVar13 + 0x38) = 0;
            puStack_14 = (undefined4 *)0x2;
            pppppppuStack_18 = (undefined4 *******)&stack0xfffffff0;
LAB_004196ea:
            ppuStack_1c = &local_1ac4;
            pppppppuStack_20 = (undefined4 *******)0x4196f6;
            iVar4 = func_0xc55299ac();
            if (iVar4 == -1) goto LAB_00419b8f;
          }
          puStack_14 = (undefined4 *)0x0;
          pppppppuStack_18 = (undefined4 *******)0x0;
          ppuStack_1c = (undefined4 **)0x5;
          pppppppuStack_20 = (undefined4 *******)&stack0xfffffff0;
          iStack_24 = 1;
          ppuStack_28 = &local_1ac4;
          uStack_2c = 0;
          uStack_30 = local_1ae8;
          pppppppuVar10 = (undefined4 *******)((int)pppppppuVar10 + 1);
          local_1ac0 = (undefined4 *******)((int)local_1ac0 + 1);
          uStack_34 = 0x419729;
          ppuVar5 = (undefined4 **)(*(code *)u_f__dd_vctools_vc7libs_ship_atlmf_0042815f._89_4_)();
          if (ppuVar5 == (undefined4 **)0x0) goto LAB_00419b8f;
          puStack_14 = (undefined4 *)0x0;
          pppppppuStack_18 = &local_1ac8;
          pppppppuStack_20 = (undefined4 *******)&stack0xfffffff0;
          iStack_24 = *(int *)(iVar13 + *local_1adc);
          ppuStack_28 = (undefined4 **)0x419752;
          ppuStack_1c = ppuVar5;
          iVar4 = (*DAT_004281f8)();
          if (iVar4 == 0) goto LAB_00419b83;
          local_1acc = (undefined4 ******)((int)local_1ac0 + local_1ad4);
          if ((int)local_1ac8 < (int)ppuVar5) goto LAB_00419b8f;
          if (local_1ae4 != 0) {
            puStack_14 = (undefined4 *)0x0;
            pppppppuStack_18 = &local_1ac8;
            ppuStack_1c = (undefined4 **)0x1;
            pppppppuStack_20 = (undefined4 *******)&stack0xfffffff0;
            iStack_24 = *(int *)(iVar13 + *local_1adc);
            ppuStack_28 = (undefined4 **)0x4197ab;
            iVar4 = (*DAT_004281f8)();
            if (iVar4 == 0) goto LAB_00419b83;
            if (0 < (int)local_1ac8) {
                    // WARNING: Bad instruction - Truncating control flow here
              halt_baddata();
            }
            goto LAB_00419b8f;
          }
        }
        else {
          if ((local_1add == '\x01') || (local_1add == '\x02')) {
            local_1ac4 = (undefined4 *)(uint)*(ushort *)pppppppuVar10;
            local_1ae4 = (uint)(*(ushort *)pppppppuVar10 == 10);
            pppppppuVar10 = (undefined4 *******)((int)pppppppuVar10 + 2);
            local_1ac0 = (undefined4 *******)((int)local_1ac0 + 2);
          }
          if ((local_1add == '\x01') || (local_1add == '\x02')) {
            puStack_14 = local_1ac4;
            pppppppuStack_18 = (undefined4 *******)0x41980d;
            sVar2 = func_0xe9509ac3();
            if (sVar2 != (short)local_1ac4) goto LAB_00419b83;
            local_1acc = (undefined4 ******)((int)local_1acc + 2);
            if (local_1ae4 != 0) {
              puStack_14 = (undefined4 *)0xd;
              local_1ac4 = (undefined4 *)0xd;
              pppppppuStack_18 = (undefined4 *******)0x41983a;
              sVar2 = func_0xe9509af0();
              if (sVar2 != (short)local_1ac4) goto LAB_00419b83;
              local_1acc = (undefined4 ******)((int)local_1acc + 1);
              local_1ad4 = local_1ad4 + 1;
            }
          }
        }
        if (_MaxCharCount <= local_1ac0) {
                    // WARNING: Bad instruction - Truncating control flow here
          halt_baddata();
        }
      } while( true );
    }
LAB_00419b98:
    piVar11 = local_1adc;
    if (local_1ac4 != (undefined4 *)0x0) {
      if (local_1ac4 == (undefined4 *)0x5) {
        puStack_14 = (undefined4 *)0x419bb1;
        puVar3 = (undefined4 *)func_0x78869d67();
        *puVar3 = 9;
        puStack_14 = (undefined4 *)0x419bbc;
        puVar3 = (undefined4 *)func_0x8b869d72();
        *puVar3 = 5;
      }
      else {
        puStack_14 = local_1ac4;
        pppppppuStack_18 = (undefined4 *******)0x419bcb;
        func_0x9e869d81();
      }
      goto LAB_00419c10;
    }
  }
  if (((*(byte *)(iVar13 + 4 + *piVar11) & 0x40) == 0) || (*(char *)local_1ad0 != '\x1a')) {
    puStack_14 = (undefined4 *)0x419bf1;
    puVar3 = (undefined4 *)func_0x78869da7();
    *puVar3 = 0x1c;
    puStack_14 = (undefined4 *)0x419bfc;
    puVar3 = (undefined4 *)func_0x8b869db2();
    *puVar3 = 0;
  }
LAB_00419c10:
  iVar13 = func_0x485f9dd3();
  return iVar13;
}



// WARNING: Control flow encountered bad instruction data
// WARNING: Globals starting with '_' overlap smaller symbols at the same address

void FUN_00419c1f(void)

{
  uint uVar1;
  char *pcVar2;
  undefined4 *puVar3;
  undefined4 uVar4;
  int unaff_EBP;
  int iVar5;
  
  func_0x2f849de1(s_GetModuleHandleA_0042f41f + 1,0x10);
  uVar1 = *(uint *)(unaff_EBP + 8);
  if (uVar1 == 0xfffffffe) {
    puVar3 = (undefined4 *)func_0x8b869dee();
    *puVar3 = 0;
    puVar3 = (undefined4 *)func_0x78869df6();
    *puVar3 = 9;
  }
  else {
    if ((-1 < (int)uVar1) && (uVar1 < DAT_00436d68)) {
      iVar5 = (uVar1 & 0x1f) * 0x40;
      if ((((char *)(&DAT_00436d80)[(int)uVar1 >> 5])[iVar5 + 4] & 1U) != 0) {
        func_0x434d9f59(uVar1);
        *(undefined4 *)(unaff_EBP + -4) = 0;
        pcVar2 = (char *)(&DAT_00436d80)[(int)uVar1 >> 5];
        if ((pcVar2[iVar5 + 4] & 1U) == 0) {
          *pcVar2 = *pcVar2 + (char)pcVar2;
          uVar1 = _DAT_00c7ffff | 0xc7ffff;
          DAT_00c7ffff = (char)uVar1;
          _DAT_00c7ffff = CONCAT31((int3)(uVar1 >> 8),DAT_00c7ffff + -1);
          puVar3 = (undefined4 *)func_0x8b869e8c();
          *puVar3 = 0;
          *(undefined4 *)(unaff_EBP + -0x1c) = 0xffffffff;
        }
        else {
          uVar4 = func_0xe3c59e74(*(undefined4 *)(unaff_EBP + 8),*(undefined4 *)(unaff_EBP + 0xc),
                                  *(undefined4 *)(unaff_EBP + 0x10));
          *(undefined4 *)(unaff_EBP + -0x1c) = uVar4;
        }
        *(undefined4 *)(unaff_EBP + -4) = 0xfffffffe;
        func_0xe8cd9e9e();
        func_0x74849ea6();
        return;
      }
    }
    puVar3 = (undefined4 *)func_0x8b869e17();
    *puVar3 = 0;
    puVar3 = (undefined4 *)func_0x78869e1e();
    *puVar3 = 9;
    func_0x53aa9e2e(0,0,0,0,0);
  }
                    // WARNING: Bad instruction - Truncating control flow here
  halt_baddata();
}



// WARNING: Control flow encountered bad instruction data
// WARNING: Instruction at (ram,0x00419fcc) overlaps instruction at (ram,0x00419fca)
// 

undefined4 * __cdecl FUN_00419d04(undefined4 *param_1,undefined4 *param_2,uint param_3)

{
  uint *puVar1;
  int *piVar2;
  undefined uVar3;
  undefined4 *puVar4;
  uint uVar5;
  int extraout_ECX;
  uint uVar6;
  int unaff_EBX;
  undefined4 *puVar7;
  undefined4 *puVar8;
  undefined8 uVar9;
  
  puVar4 = (undefined4 *)(param_3 + (int)param_2);
  if ((param_2 < param_1) && (param_1 < puVar4)) {
    puVar7 = (undefined4 *)((param_3 - 4) + (int)param_2);
    puVar8 = (undefined4 *)((param_3 - 4) + (int)param_1);
    if (((uint)puVar8 & 3) == 0) {
      uVar6 = param_3 >> 2;
      uVar5 = param_3 & 3;
      if (7 < uVar6) {
        for (; uVar6 != 0; uVar6 = uVar6 - 1) {
          *puVar8 = *puVar7;
          puVar7 = puVar7 + -1;
          puVar8 = puVar8 + -1;
        }
        puVar8 = puVar4;
        switch(uVar5) {
        case 0:
          return;
        case 2:
          goto code_r0x0041a029;
        case 3:
          goto switchD_00419ee7_caseD_3;
        }
        goto switchD_00419ee7_caseD_1;
      }
    }
    else {
      uVar5 = 3;
      switch(param_3) {
      case 0:
        goto switchD_00412ff0_caseD_0;
      case 1:
        goto switchD_00419ee7_caseD_1;
      case 2:
        goto code_r0x0041a029;
      case 3:
        goto switchD_00419ee7_caseD_3;
      default:
        puVar4 = (undefined4 *)((uint)puVar8 & 3);
        switch(puVar4) {
        case (undefined4 *)0x1:
                    // WARNING: Bad instruction - Truncating control flow here
          halt_baddata();
        case (undefined4 *)0x3:
          puVar1 = (uint *)((int)puVar4 + 0x468a0347);
          *puVar1 = *puVar1 >> 1 | (uint)((*puVar1 & 1) != 0) << 0x1f;
                    // WARNING: Bad instruction - Truncating control flow here
          halt_baddata();
        }
        if (SBORROW4(param_3,(int)puVar4)) {
          return puVar4;
        }
        uVar6 = (param_3 - (int)puVar4) + 1;
        DAT_d1230349 = DAT_d1230349 + (char)uVar6;
        *(char *)((int)puVar8 + 3) = (char)puVar4;
        puVar7 = (undefined4 *)((int)puVar7 + -1);
        uVar6 = uVar6 >> 2;
        puVar8 = (undefined4 *)((int)puVar8 - 1);
        if (7 < uVar6) {
          for (; uVar6 != 0; uVar6 = uVar6 - 1) {
            *puVar8 = *puVar7;
            puVar7 = puVar7 + -1;
            puVar8 = puVar8 + -1;
          }
          return puVar4;
        }
      }
    }
                    // WARNING (jumptable): Sanity check requires truncation of jumptable
    switch((&UINT_00419fc0)[-uVar6]) {
    case 0x419fc4:
                    // WARNING: Bad instruction - Truncating control flow here
      halt_baddata();
    case 0x419fcc:
      puVar8[7 - uVar6] = puVar4;
      puVar4 = (undefined4 *)puVar7[6 - uVar6];
    case 0x419fd4:
      puVar8[6 - uVar6] = puVar4;
      puVar4 = (undefined4 *)puVar7[5 - uVar6];
    case 0x419fdc:
      puVar8[5 - uVar6] = puVar4;
      puVar4 = (undefined4 *)puVar7[4 - uVar6];
    case 0x419fe4:
      puVar8[4 - uVar6] = puVar4;
      puVar4 = (undefined4 *)puVar7[3 - uVar6];
    case 0x419fec:
      puVar8[3 - uVar6] = puVar4;
      puVar4 = (undefined4 *)puVar7[2 - uVar6];
    }
    puVar8[2 - uVar6] = puVar4;
    puVar8[1 - uVar6] = puVar7[1 - uVar6];
    puVar8 = (undefined4 *)(uVar6 * -4);
    puVar7 = puVar7 + -uVar6;
    switch(uVar5) {
    case 0:
      goto switchD_00412ff0_caseD_0;
    case 1:
switchD_00419ee7_caseD_1:
      puVar4 = (undefined4 *)CONCAT31((int3)((uint)puVar8 >> 8),DAT_458b0041);
      *(byte *)((int)puVar7 + 0x5f) = *(byte *)((int)puVar7 + 0x5f) | (byte)unaff_EBX;
      return puVar4;
    case 2:
code_r0x0041a029:
      return puVar8;
    default:
switchD_00419ee7_caseD_3:
      return puVar8;
    }
  }
  if (((0xff < param_3) && (DAT_00437ea4 != 0)) && (((uint)param_1 & 0xf) == ((uint)param_2 & 0xf)))
  {
                    // WARNING: Bad instruction - Truncating control flow here
    halt_baddata();
  }
  if (((uint)param_1 & 3) == 0) {
    uVar5 = param_3 >> 2;
    uVar6 = param_3 & 3;
    puVar8 = param_1;
    if (7 < uVar5) {
      for (; uVar5 != 0; uVar5 = uVar5 - 1) {
        *param_1 = *param_2;
        param_2 = param_2 + 1;
        param_1 = param_1 + 1;
      }
      uVar5 = 0;
      param_1 = puVar4;
      switch(uVar6) {
      case 0:
        return;
      case 2:
        goto code_r0x00419e8d;
      case 3:
        goto switchD_00419d60_caseD_3;
      }
      goto switchD_00419d60_caseD_1;
    }
  }
  else {
    uVar6 = 3;
    uVar5 = param_3 - 4;
    switch(param_3) {
    case 0:
      goto switchD_00412ff0_caseD_0;
    case 1:
switchD_00419d60_caseD_1:
      uVar3 = *(undefined *)param_2;
      *(char *)(unaff_EBX + 0x5f5e0845) = *(char *)(unaff_EBX + 0x5f5e0845) + (char)uVar5 + '\x01';
      return (undefined4 *)CONCAT31((int3)((uint)param_1 >> 8),uVar3);
    case 2:
      goto code_r0x00419e8d;
    case 3:
      goto switchD_00419d60_caseD_3;
    default:
      switch((uint)param_1 & 3) {
      case 1:
                    // WARNING: Bad instruction - Truncating control flow here
        halt_baddata();
      case 2:
        uVar9 = func_0x2341df3a();
        puVar1 = (uint *)((int)((ulonglong)uVar9 >> 0x20) + -0x75f877fa);
        *puVar1 = *puVar1 >> 1 | (uint)((*puVar1 & 1) != 0) << 0x1f;
        piVar2 = (int *)((int)uVar9 + 0x468a0147);
        *piVar2 = *piVar2 + extraout_ECX;
                    // WARNING: Bad instruction - Truncating control flow here
        halt_baddata();
      }
      *(undefined *)param_1 = *(undefined *)param_2;
      puVar4 = (undefined4 *)(uint)*(byte *)((int)param_2 + 1);
      uVar5 = uVar5 + ((uint)param_1 & 3) >> 2;
      *(byte *)((int)param_1 + 1) = *(byte *)((int)param_2 + 1);
      param_2 = (undefined4 *)((int)param_2 + 2);
      puVar8 = (undefined4 *)((int)param_1 + 2);
      if (7 < uVar5) {
        for (; uVar5 != 0; uVar5 = uVar5 - 1) {
          *puVar8 = *param_2;
          param_2 = param_2 + 1;
          puVar8 = puVar8 + 1;
        }
        return puVar4;
      }
    }
  }
  param_1 = puVar4;
  switch((&switchD_00419d88::switchdataD_00419e08)[uVar5]) {
  case (undefined *)0x419e30:
    puVar8[uVar5 - 7] = puVar4;
    puVar4 = (undefined4 *)param_2[uVar5 - 6];
  case (undefined *)0x419e38:
    puVar8[uVar5 - 6] = puVar4;
    puVar4 = (undefined4 *)param_2[uVar5 - 5];
  case (undefined *)0x419e40:
    puVar8[uVar5 - 5] = puVar4;
    puVar4 = (undefined4 *)param_2[uVar5 - 4];
  case (undefined *)0x419e48:
    puVar8[uVar5 - 4] = puVar4;
    puVar4 = (undefined4 *)param_2[uVar5 - 3];
  case (undefined *)0x419e50:
    puVar8[uVar5 - 3] = puVar4;
    puVar4 = (undefined4 *)param_2[uVar5 - 2];
  case (undefined *)0x419e58:
    puVar8[uVar5 - 2] = puVar4;
    puVar8[uVar5 - 1] = param_2[uVar5 - 1];
    param_1 = (undefined4 *)(uVar5 * 4);
    break;
  case (undefined *)0x498d00:
                    // WARNING: Bad instruction - Truncating control flow here
    halt_baddata();
  }
  param_2 = (undefined4 *)((int)param_2 + (int)param_1);
  switch(uVar6) {
  case 0:
switchD_00412ff0_caseD_0:
                    // WARNING: Bad instruction - Truncating control flow here
    halt_baddata();
  case 1:
    goto switchD_00419d60_caseD_1;
  case 2:
code_r0x00419e8d:
    return param_1;
  default:
switchD_00419d60_caseD_3:
    return param_1;
  }
}



// WARNING: Globals starting with '_' overlap smaller symbols at the same address
// Library Function - Single Match
//  __lseek_nolock
// 
// Libraries: Visual Studio 2008 Release, Visual Studio 2010 Release

long __cdecl __lseek_nolock(int _FileHandle,long _Offset,int _Origin)

{
  byte *pbVar1;
  int iVar2;
  undefined4 *puVar3;
  long lVar4;
  
  iVar2 = func_0xcc4ca32e(_FileHandle);
  if (iVar2 == -1) {
    puVar3 = (undefined4 *)func_0x7886a239();
    *puVar3 = 9;
    lVar4 = -1;
  }
  else {
    lVar4 = (*ram0x004281c8)(iVar2,_Offset,0,_Origin);
    if (lVar4 == -1) {
      iVar2 = (*DAT_004281cc)();
    }
    else {
      iVar2 = 0;
    }
    if (iVar2 == 0) {
      pbVar1 = (byte *)((&DAT_00436d80)[_FileHandle >> 5] + 4 + (_FileHandle & 0x1fU) * 0x40);
      *pbVar1 = *pbVar1 & 0xfd;
    }
    else {
      func_0x9e86a26f(iVar2);
      lVar4 = -1;
    }
  }
  return lVar4;
}



void __cdecl FUN_0041a4b0(int param_1)

{
  (*(code *)u_f__dd_vctools_vc7libs_ship_atlmf_0042815f._65_4_)
            (*(undefined4 *)(&DAT_00432190 + param_1 * 8));
  return;
}



// Library Function - Single Match
//  __lock
// 
// Libraries: Visual Studio 2008 Release, Visual Studio 2010 Release

void __cdecl __lock(int _File)

{
  int iVar1;
  
  if (*(int *)(&DAT_00432190 + _File * 8) == 0) {
    iVar1 = func_0xbed5a75b(_File);
    if (iVar1 == 0) {
      func_0xbea4a767(0x11);
    }
  }
  (*(code *)u_f__dd_vctools_vc7libs_ship_atlmf_0042815f._57_4_)(*(int *)(&DAT_00432190 + _File * 8))
  ;
  return;
}



// Library Function - Single Match
//  ___sbh_find_block
// 
// Library: Visual Studio 2008 Release

uint __cdecl ___sbh_find_block(int param_1)

{
  uint uVar1;
  
  uVar1 = DAT_00436d54;
  while( true ) {
    if (DAT_00436d50 * 0x14 + DAT_00436d54 <= uVar1) {
      return 0;
    }
    if ((uint)(param_1 - *(int *)(uVar1 + 0xc)) < 0x100000) break;
    uVar1 = uVar1 + 0x14;
  }
  return uVar1;
}



// Library Function - Single Match
//  ___sbh_free_block
// 
// Library: Visual Studio 2008 Release

void __cdecl ___sbh_free_block(uint *param_1,int param_2)

{
  int *piVar1;
  char *pcVar2;
  uint *puVar3;
  int *piVar4;
  char cVar5;
  uint uVar6;
  uint uVar7;
  code *pcVar8;
  byte bVar9;
  uint uVar10;
  uint *puVar11;
  uint *puVar12;
  uint *puVar13;
  uint uVar14;
  uint uVar15;
  uint local_8;
  
  uVar6 = param_1[4];
  puVar13 = (uint *)(param_2 + -4);
  uVar15 = param_2 - param_1[3] >> 0xf;
  piVar4 = (int *)(uVar15 * 0x204 + 0x144 + uVar6);
  local_8 = *puVar13 - 1;
  if ((local_8 & 1) == 0) {
    puVar11 = (uint *)(local_8 + (int)puVar13);
    uVar14 = *puVar11;
    uVar7 = *(uint *)(param_2 + -8);
    if ((uVar14 & 1) == 0) {
      uVar10 = ((int)uVar14 >> 4) - 1;
      if (0x3f < uVar10) {
        uVar10 = 0x3f;
      }
      if (puVar11[1] == puVar11[2]) {
        if (uVar10 < 0x20) {
          pcVar2 = (char *)(uVar10 + 4 + uVar6);
          uVar10 = ~(0x80000000U >> ((byte)uVar10 & 0x1f));
          puVar12 = (uint *)(uVar6 + 0x44 + uVar15 * 4);
          *puVar12 = *puVar12 & uVar10;
          *pcVar2 = *pcVar2 + -1;
          if (*pcVar2 == '\0') {
            *param_1 = *param_1 & uVar10;
          }
        }
        else {
          pcVar2 = (char *)(uVar10 + 4 + uVar6);
          uVar10 = ~(0x80000000U >> ((byte)uVar10 - 0x20 & 0x1f));
          puVar12 = (uint *)(uVar6 + 0xc4 + uVar15 * 4);
          *puVar12 = *puVar12 & uVar10;
          *pcVar2 = *pcVar2 + -1;
          if (*pcVar2 == '\0') {
            param_1[1] = param_1[1] & uVar10;
          }
        }
      }
      local_8 = local_8 + uVar14;
      *(uint *)(puVar11[2] + 4) = puVar11[1];
      *(uint *)(puVar11[1] + 8) = puVar11[2];
    }
    puVar11 = (uint *)(((int)local_8 >> 4) - 1);
    if ((uint *)0x3f < puVar11) {
      puVar11 = (uint *)0x3f;
    }
    puVar12 = param_1;
    if ((uVar7 & 1) == 0) {
      puVar13 = (uint *)((int)puVar13 - uVar7);
      puVar12 = (uint *)(((int)uVar7 >> 4) - 1);
      if ((uint *)0x3f < puVar12) {
        puVar12 = (uint *)0x3f;
      }
      local_8 = local_8 + uVar7;
      puVar11 = (uint *)(((int)local_8 >> 4) - 1);
      if ((uint *)0x3f < puVar11) {
        puVar11 = (uint *)0x3f;
      }
      if (puVar12 != puVar11) {
        if (puVar13[1] == puVar13[2]) {
          if (puVar12 < (uint *)0x20) {
            uVar14 = ~(0x80000000U >> ((byte)puVar12 & 0x1f));
            puVar3 = (uint *)(uVar6 + 0x44 + uVar15 * 4);
            *puVar3 = *puVar3 & uVar14;
            pcVar2 = (char *)((int)puVar12 + uVar6 + 4);
            *pcVar2 = *pcVar2 + -1;
            if (*pcVar2 == '\0') {
              *param_1 = *param_1 & uVar14;
            }
          }
          else {
            uVar14 = ~(0x80000000U >> ((byte)puVar12 - 0x20 & 0x1f));
            puVar3 = (uint *)(uVar6 + 0xc4 + uVar15 * 4);
            *puVar3 = *puVar3 & uVar14;
            pcVar2 = (char *)((int)puVar12 + uVar6 + 4);
            *pcVar2 = *pcVar2 + -1;
            if (*pcVar2 == '\0') {
              param_1[1] = param_1[1] & uVar14;
            }
          }
        }
        *(uint *)(puVar13[2] + 4) = puVar13[1];
        *(uint *)(puVar13[1] + 8) = puVar13[2];
      }
    }
    if (((uVar7 & 1) != 0) || (puVar12 != puVar11)) {
      piVar1 = piVar4 + (int)puVar11 * 2;
      uVar14 = piVar1[1];
      puVar13[2] = (uint)piVar1;
      puVar13[1] = uVar14;
      piVar1[1] = (int)puVar13;
      *(uint **)(puVar13[1] + 8) = puVar13;
      if (puVar13[1] == puVar13[2]) {
        cVar5 = *(char *)((int)puVar11 + uVar6 + 4);
        *(char *)((int)puVar11 + uVar6 + 4) = cVar5 + '\x01';
        bVar9 = (byte)puVar11;
        if (puVar11 < (uint *)0x20) {
          if (cVar5 == '\0') {
            *param_1 = *param_1 | 0x80000000U >> (bVar9 & 0x1f);
          }
          puVar11 = (uint *)(uVar6 + 0x44 + uVar15 * 4);
          *puVar11 = *puVar11 | 0x80000000U >> (bVar9 & 0x1f);
        }
        else {
          if (cVar5 == '\0') {
            param_1[1] = param_1[1] | 0x80000000U >> (bVar9 - 0x20 & 0x1f);
          }
          puVar11 = (uint *)(uVar6 + 0xc4 + uVar15 * 4);
          *puVar11 = *puVar11 | 0x80000000U >> (bVar9 - 0x20 & 0x1f);
        }
      }
    }
    *puVar13 = local_8;
    *(uint *)((local_8 - 4) + (int)puVar13) = local_8;
    *piVar4 = *piVar4 + -1;
    pcVar8 = DAT_00428108;
    if (*piVar4 == 0) {
      if (DAT_00435450 != (uint *)0x0) {
        (*DAT_00428108)(DAT_00436d64 * 0x8000 + DAT_00435450[3],0x8000,0x4000);
        DAT_00435450[2] = DAT_00435450[2] | 0x80000000U >> ((byte)DAT_00436d64 & 0x1f);
        *(undefined4 *)(DAT_00435450[4] + 0xc4 + DAT_00436d64 * 4) = 0;
        *(char *)(DAT_00435450[4] + 0x43) = *(char *)(DAT_00435450[4] + 0x43) + -1;
        if (*(char *)(DAT_00435450[4] + 0x43) == '\0') {
          DAT_00435450[1] = DAT_00435450[1] & 0xfffffffe;
        }
        if (DAT_00435450[2] == 0xffffffff) {
          (*pcVar8)(DAT_00435450[3],0,0x8000);
          (*DAT_004280c8)(DAT_00435454,0,DAT_00435450[4]);
          func_0x8b60aa84(DAT_00435450,DAT_00435450 + 5,
                          (DAT_00436d50 * 0x14 - (int)DAT_00435450) + -0x14 + DAT_00436d54);
          DAT_00436d50 = DAT_00436d50 + -1;
          if (DAT_00435450 < param_1) {
            param_1 = param_1 + -5;
          }
          DAT_00436d5c = DAT_00436d54;
        }
      }
      DAT_00435450 = param_1;
      DAT_00436d64 = uVar15;
    }
  }
  return;
}



// WARNING: Control flow encountered bad instruction data
// Library Function - Single Match
//  ___sbh_alloc_new_group
// 
// Library: Visual Studio 2008 Release

int __cdecl ___sbh_alloc_new_group(int param_1)

{
  char cVar1;
  int iVar2;
  int iVar3;
  int iVar4;
  int *piVar5;
  int iVar6;
  int iVar7;
  uint uVar8;
  
  iVar2 = *(int *)(param_1 + 0x10);
  iVar7 = 0;
  for (iVar3 = *(int *)(param_1 + 8); -1 < iVar3; iVar3 = iVar3 * 2) {
    iVar7 = iVar7 + 1;
  }
  iVar3 = iVar7 * 0x204 + 0x144 + iVar2;
  iVar6 = 0x3f;
  iVar4 = iVar3;
  do {
    *(int *)(iVar4 + 8) = iVar4;
    *(int *)(iVar4 + 4) = iVar4;
    iVar4 = iVar4 + 8;
    iVar6 = iVar6 + -1;
  } while (iVar6 != 0);
  uVar8 = iVar7 * 0x8000 + *(int *)(param_1 + 0xc);
  iVar6 = (*DAT_0042810c)(uVar8,0x8000,0x1000,4);
  if (iVar6 != 0) {
    if (uVar8 <= uVar8 + 0x7000) {
      piVar5 = (int *)(uVar8 + 0x10);
      iVar6 = ((uVar8 + 0x7000) - uVar8 >> 0xc) + 1;
      do {
        piVar5[-2] = -1;
        piVar5[0x3fb] = -1;
        *piVar5 = (int)(piVar5 + 0x3ff);
        piVar5[-1] = 0xff0;
        piVar5[1] = (int)(piVar5 + -0x401);
        piVar5[0x3fa] = 0xff0;
        piVar5 = piVar5 + 0x400;
        iVar6 = iVar6 + -1;
      } while (iVar6 != 0);
    }
    *(uint *)(iVar3 + 0x1fc) = uVar8 + 0xc;
    *(int *)(uVar8 + 0x14) = iVar3 + 0x1f8;
    *(uint *)(iVar3 + 0x200) = uVar8 + 0x700c;
    *(int *)(uVar8 + 0x7010) = iVar3 + 0x1f8;
    *(undefined4 *)(iVar2 + 0x44 + iVar7 * 4) = 0;
    *(undefined4 *)(iVar2 + 0xc4 + iVar7 * 4) = 1;
    cVar1 = *(char *)(iVar2 + 0x43);
    *(char *)(iVar2 + 0x43) = cVar1 + '\x01';
    if (cVar1 == '\0') {
      *(uint *)(param_1 + 4) = *(uint *)(param_1 + 4) | 1;
    }
    *(uint *)(param_1 + 8) = *(uint *)(param_1 + 8) & ~(0x80000000U >> ((byte)iVar7 & 0x1f));
    return iVar7;
  }
                    // WARNING: Bad instruction - Truncating control flow here
  halt_baddata();
}



// WARNING: Control flow encountered bad instruction data
// Library Function - Single Match
//  ___sbh_resize_block
// 
// Library: Visual Studio 2008 Release

undefined4 __cdecl ___sbh_resize_block(uint *param_1,int param_2,int param_3)

{
  char *pcVar1;
  uint *puVar2;
  int iVar3;
  int *piVar4;
  int iVar5;
  char cVar6;
  uint uVar7;
  uint *puVar8;
  int iVar9;
  uint uVar10;
  uint uVar11;
  uint uVar12;
  uint uVar13;
  uint local_c;
  
  uVar7 = param_1[4];
  uVar10 = param_2 - param_1[3] >> 0xf;
  iVar5 = uVar10 * 0x204 + 0x144 + uVar7;
  uVar12 = param_3 + 0x17U & 0xfffffff0;
  iVar9 = *(int *)(param_2 + -4) + -1;
  puVar8 = (uint *)(*(int *)(param_2 + -4) + -5 + param_2);
  uVar13 = *puVar8;
  if ((int)uVar12 <= iVar9) {
    if ((int)uVar12 < iVar9) {
      param_3 = iVar9 - uVar12;
      *(uint *)(param_2 + -4) = uVar12 + 1;
      piVar4 = (int *)(param_2 + -4 + uVar12);
      uVar11 = (param_3 >> 4) - 1;
      piVar4[-1] = uVar12 + 1;
      if (0x3f < uVar11) {
        uVar11 = 0x3f;
      }
      if ((uVar13 & 1) == 0) {
        uVar12 = ((int)uVar13 >> 4) - 1;
        if (0x3f < uVar12) {
          uVar12 = 0x3f;
        }
        if (puVar8[1] == puVar8[2]) {
          if (uVar12 < 0x20) {
            pcVar1 = (char *)(uVar12 + 4 + uVar7);
            uVar12 = ~(0x80000000U >> ((byte)uVar12 & 0x1f));
            puVar2 = (uint *)(uVar7 + 0x44 + uVar10 * 4);
            *puVar2 = *puVar2 & uVar12;
            *pcVar1 = *pcVar1 + -1;
            if (*pcVar1 == '\0') {
              *param_1 = *param_1 & uVar12;
            }
          }
          else {
            pcVar1 = (char *)(uVar12 + 4 + uVar7);
            uVar12 = ~(0x80000000U >> ((byte)uVar12 - 0x20 & 0x1f));
            puVar2 = (uint *)(uVar7 + 0xc4 + uVar10 * 4);
            *puVar2 = *puVar2 & uVar12;
            *pcVar1 = *pcVar1 + -1;
            if (*pcVar1 == '\0') {
              param_1[1] = param_1[1] & uVar12;
            }
          }
        }
        *(uint *)(puVar8[2] + 4) = puVar8[1];
        *(uint *)(puVar8[1] + 8) = puVar8[2];
        param_3 = param_3 + uVar13;
        uVar11 = (param_3 >> 4) - 1;
        if (0x3f < uVar11) {
          uVar11 = 0x3f;
        }
      }
      iVar5 = iVar5 + uVar11 * 8;
      iVar9 = *(int *)(iVar5 + 4);
      piVar4[2] = iVar5;
      piVar4[1] = iVar9;
      *(int **)(iVar5 + 4) = piVar4;
      *(int **)(piVar4[1] + 8) = piVar4;
      if (piVar4[1] == piVar4[2]) {
        cVar6 = *(char *)(uVar11 + 4 + uVar7);
        *(char *)(uVar11 + 4 + uVar7) = cVar6 + '\x01';
        if (uVar11 < 0x20) {
          if (cVar6 == '\0') {
            *param_1 = *param_1 | 0x80000000U >> ((byte)uVar11 & 0x1f);
          }
          puVar8 = (uint *)(uVar7 + 0x44 + uVar10 * 4);
        }
        else {
          if (cVar6 == '\0') {
            param_1[1] = param_1[1] | 0x80000000U >> ((byte)uVar11 - 0x20 & 0x1f);
          }
          puVar8 = (uint *)(uVar7 + 0xc4 + uVar10 * 4);
          uVar11 = uVar11 - 0x20;
        }
        *puVar8 = *puVar8 | 0x80000000U >> ((byte)uVar11 & 0x1f);
      }
      *piVar4 = param_3;
      *(int *)(param_3 + -4 + (int)piVar4) = param_3;
    }
    return 1;
  }
  if (((uVar13 & 1) == 0) && ((int)uVar12 <= (int)(uVar13 + iVar9))) {
    local_c = ((int)uVar13 >> 4) - 1;
    if (0x3f < local_c) {
      local_c = 0x3f;
    }
    if (puVar8[1] == puVar8[2]) {
      if (local_c < 0x20) {
        pcVar1 = (char *)(local_c + 4 + uVar7);
        uVar11 = ~(0x80000000U >> ((byte)local_c & 0x1f));
        puVar2 = (uint *)(uVar7 + 0x44 + uVar10 * 4);
        *puVar2 = *puVar2 & uVar11;
        *pcVar1 = *pcVar1 + -1;
        if (*pcVar1 == '\0') {
          *param_1 = *param_1 & uVar11;
        }
      }
      else {
        pcVar1 = (char *)(local_c + 4 + uVar7);
        uVar11 = ~(0x80000000U >> ((byte)local_c - 0x20 & 0x1f));
        puVar2 = (uint *)(uVar7 + 0xc4 + uVar10 * 4);
        *puVar2 = *puVar2 & uVar11;
        *pcVar1 = *pcVar1 + -1;
        if (*pcVar1 == '\0') {
          param_1[1] = param_1[1] & uVar11;
        }
      }
    }
    *(uint *)(puVar8[2] + 4) = puVar8[1];
    *(uint *)(puVar8[1] + 8) = puVar8[2];
    iVar9 = uVar13 + (iVar9 - uVar12);
    if (0 < iVar9) {
      uVar13 = (iVar9 >> 4) - 1;
      iVar3 = param_2 + -4 + uVar12;
      if (0x3f < uVar13) {
        uVar13 = 0x3f;
      }
      iVar5 = iVar5 + uVar13 * 8;
      *(undefined4 *)(iVar3 + 4) = *(undefined4 *)(iVar5 + 4);
      *(int *)(iVar3 + 8) = iVar5;
      *(int *)(iVar5 + 4) = iVar3;
      *(int *)(*(int *)(iVar3 + 4) + 8) = iVar3;
      if (*(int *)(iVar3 + 4) == *(int *)(iVar3 + 8)) {
        cVar6 = *(char *)(uVar13 + 4 + uVar7);
        *(char *)(uVar13 + 4 + uVar7) = cVar6 + '\x01';
        if (uVar13 < 0x20) {
          if (cVar6 == '\0') {
            *param_1 = *param_1 | 0x80000000U >> ((byte)uVar13 & 0x1f);
          }
          puVar8 = (uint *)(uVar7 + 0x44 + uVar10 * 4);
        }
        else {
          if (cVar6 == '\0') {
            param_1[1] = param_1[1] | 0x80000000U >> ((byte)uVar13 - 0x20 & 0x1f);
          }
          puVar8 = (uint *)(uVar7 + 0xc4 + uVar10 * 4);
          uVar13 = uVar13 - 0x20;
        }
        *puVar8 = *puVar8 | 0x80000000U >> ((byte)uVar13 & 0x1f);
      }
      piVar4 = (int *)(param_2 + -4 + uVar12);
      *piVar4 = iVar9;
      *(int *)(iVar9 + -4 + (int)piVar4) = iVar9;
    }
    *(uint *)(param_2 + -4) = uVar12 + 1;
    *(uint *)(param_2 + -8 + uVar12) = uVar12 + 1;
                    // WARNING: Bad instruction - Truncating control flow here
    halt_baddata();
  }
                    // WARNING: Bad instruction - Truncating control flow here
  halt_baddata();
}



// WARNING: Control flow encountered bad instruction data
// Library Function - Single Match
//  ___sbh_alloc_block
// 
// Library: Visual Studio 2008 Release

int * __cdecl ___sbh_alloc_block(uint *param_1)

{
  int *piVar1;
  char *pcVar2;
  int *piVar3;
  char cVar4;
  int *piVar5;
  undefined4 uVar6;
  byte bVar7;
  uint uVar8;
  int iVar9;
  uint *puVar10;
  int iVar11;
  uint uVar12;
  int *piVar13;
  uint *puVar14;
  uint *puVar15;
  uint uVar16;
  int iVar17;
  uint local_c;
  int local_8;
  
  puVar10 = DAT_00436d54 + DAT_00436d50 * 5;
  uVar8 = (int)param_1 + 0x17U & 0xfffffff0;
  iVar9 = ((int)((int)param_1 + 0x17U) >> 4) + -1;
  bVar7 = (byte)iVar9;
  param_1 = DAT_00436d5c;
  if (iVar9 < 0x20) {
    uVar16 = 0xffffffff >> (bVar7 & 0x1f);
    local_c = 0xffffffff;
  }
  else {
    uVar16 = 0;
    local_c = 0xffffffff >> (bVar7 - 0x20 & 0x1f);
  }
  for (; (param_1 < puVar10 && ((param_1[1] & local_c | *param_1 & uVar16) == 0));
      param_1 = param_1 + 5) {
  }
  puVar14 = DAT_00436d54;
  if (param_1 == puVar10) {
    for (; (puVar14 < DAT_00436d5c && ((puVar14[1] & local_c | *puVar14 & uVar16) == 0));
        puVar14 = puVar14 + 5) {
    }
    param_1 = puVar14;
    if (puVar14 == DAT_00436d5c) {
      for (; (puVar14 < puVar10 && (puVar14[2] == 0)); puVar14 = puVar14 + 5) {
      }
      puVar15 = DAT_00436d54;
      param_1 = puVar14;
      if (puVar14 == puVar10) {
        for (; (puVar15 < DAT_00436d5c && (puVar15[2] == 0)); puVar15 = puVar15 + 5) {
        }
        param_1 = puVar15;
        if ((puVar15 == DAT_00436d5c) &&
           (param_1 = (uint *)func_0xfad9b019(), param_1 == (uint *)0x0)) {
          return;
        }
      }
      uVar6 = func_0xaadab02f(param_1);
      *(undefined4 *)param_1[4] = uVar6;
      if (*(int *)param_1[4] == -1) {
                    // WARNING: Bad instruction - Truncating control flow here
        halt_baddata();
      }
    }
  }
  piVar5 = (int *)param_1[4];
  local_8 = *piVar5;
  if ((local_8 == -1) || ((piVar5[local_8 + 0x31] & local_c | piVar5[local_8 + 0x11] & uVar16) == 0)
     ) {
    local_8 = 0;
    puVar10 = (uint *)(piVar5 + 0x11);
    uVar12 = piVar5[0x31];
    while ((uVar12 & local_c | *puVar10 & uVar16) == 0) {
      local_8 = local_8 + 1;
      puVar14 = puVar10 + 0x21;
      puVar10 = puVar10 + 1;
      uVar12 = *puVar14;
    }
  }
  piVar3 = piVar5 + local_8 * 0x81 + 0x51;
  iVar9 = 0;
  uVar16 = piVar5[local_8 + 0x11] & uVar16;
  if (uVar16 == 0) {
    uVar16 = piVar5[local_8 + 0x31] & local_c;
    iVar9 = 0x20;
  }
  for (; -1 < (int)uVar16; uVar16 = uVar16 * 2) {
    iVar9 = iVar9 + 1;
  }
  piVar13 = (int *)piVar3[iVar9 * 2 + 1];
  iVar11 = *piVar13 - uVar8;
  iVar17 = (iVar11 >> 4) + -1;
  if (0x3f < iVar17) {
    iVar17 = 0x3f;
  }
  DAT_00436d5c = param_1;
  if (iVar17 != iVar9) {
    if (piVar13[1] == piVar13[2]) {
      if (iVar9 < 0x20) {
        pcVar2 = (char *)((int)piVar5 + iVar9 + 4);
        uVar16 = ~(0x80000000U >> ((byte)iVar9 & 0x1f));
        piVar5[local_8 + 0x11] = uVar16 & piVar5[local_8 + 0x11];
        *pcVar2 = *pcVar2 + -1;
        if (*pcVar2 == '\0') {
          *param_1 = *param_1 & uVar16;
        }
      }
      else {
        pcVar2 = (char *)((int)piVar5 + iVar9 + 4);
        uVar16 = ~(0x80000000U >> ((byte)iVar9 - 0x20 & 0x1f));
        piVar5[local_8 + 0x31] = piVar5[local_8 + 0x31] & uVar16;
        *pcVar2 = *pcVar2 + -1;
        if (*pcVar2 == '\0') {
          param_1[1] = param_1[1] & uVar16;
        }
      }
    }
    *(int *)(piVar13[2] + 4) = piVar13[1];
    *(int *)(piVar13[1] + 8) = piVar13[2];
    if (iVar11 == 0) goto LAB_0041b03e;
    piVar1 = piVar3 + iVar17 * 2;
    iVar9 = piVar1[1];
    piVar13[2] = (int)piVar1;
    piVar13[1] = iVar9;
    piVar1[1] = (int)piVar13;
    *(int **)(piVar13[1] + 8) = piVar13;
    if (piVar13[1] == piVar13[2]) {
      cVar4 = *(char *)(iVar17 + 4 + (int)piVar5);
      *(char *)(iVar17 + 4 + (int)piVar5) = cVar4 + '\x01';
      bVar7 = (byte)iVar17;
      if (iVar17 < 0x20) {
        if (cVar4 == '\0') {
          *param_1 = *param_1 | 0x80000000U >> (bVar7 & 0x1f);
        }
        piVar5[local_8 + 0x11] = piVar5[local_8 + 0x11] | 0x80000000U >> (bVar7 & 0x1f);
      }
      else {
        if (cVar4 == '\0') {
          param_1[1] = param_1[1] | 0x80000000U >> (bVar7 - 0x20 & 0x1f);
        }
        piVar5[local_8 + 0x31] = piVar5[local_8 + 0x31] | 0x80000000U >> (bVar7 - 0x20 & 0x1f);
      }
    }
  }
  if (iVar11 != 0) {
    *piVar13 = iVar11;
    *(int *)(iVar11 + -4 + (int)piVar13) = iVar11;
  }
LAB_0041b03e:
  piVar13 = (int *)((int)piVar13 + iVar11);
  *piVar13 = uVar8 + 1;
  *(uint *)((int)piVar13 + (uVar8 - 4)) = uVar8 + 1;
  iVar9 = *piVar3;
  *piVar3 = iVar9 + 1;
  if (((iVar9 == 0) && (param_1 == DAT_00435450)) && (local_8 == DAT_00436d64)) {
    DAT_00435450 = (uint *)0x0;
  }
  *piVar5 = local_8;
  return piVar13 + 1;
}



// Library Function - Single Match
//  __heap_init
// 
// Library: Visual Studio 2008 Release

int __cdecl __heap_init(void)

{
  int in_stack_00000004;
  
  DAT_00435454 = (*DAT_00428110)(in_stack_00000004 == 0,0x1000,0);
  if (DAT_00435454 == 0) {
    return 0;
  }
  DAT_00436d4c = 1;
  return 1;
}



// Library Function - Single Match
//  __NMSG_WRITE
// 
// Library: Visual Studio 2008 Release

void __cdecl __NMSG_WRITE(int param_1)

{
  undefined4 *puVar1;
  uint uVar2;
  int iVar3;
  undefined4 uVar4;
  undefined local_c [4];
  uint local_8;
  
  local_8 = 0;
  do {
    if (param_1 == (&DAT_004322b8)[local_8 * 2]) break;
    local_8 = local_8 + 1;
  } while (local_8 < 0x17);
  uVar2 = local_8;
  if (local_8 < 0x17) {
    iVar3 = func_0xd655b39d(3);
    if ((iVar3 == 1) || ((iVar3 = func_0xd655b3ae(3), iVar3 == 0 && (DAT_00431c1c == 1)))) {
      iVar3 = (*DAT_004280fc)(0xfffffff4);
      if ((iVar3 != 0) && (iVar3 != -1)) {
        puVar1 = (undefined4 *)(uVar2 * 8 + 0x4322bc);
        uVar4 = func_0x4b55b502(*puVar1,local_c,0);
        (*DAT_004281f8)(iVar3,*puVar1,uVar4);
      }
    }
    else if (param_1 != 0xfc) {
      iVar3 = func_0x316fb2e2(&DAT_00435458,0x314,s__vector_vbase_constructor_iterat_0042a38b + 0xd)
      ;
      if (iVar3 != 0) {
        func_0x2ba9b2f3(0,0,0,0,0);
      }
      DAT_00435575 = 0;
      iVar3 = (*DAT_00428200)(0,&LAB_00435471,0x104);
      if ((iVar3 == 0) &&
         (iVar3 = func_0x316fb324(&LAB_00435471,0x2fb,s__virtual_displacement_map__0042a36f + 0x11),
         iVar3 != 0)) {
        func_0x2ba9b337(0,0,0,0,0);
      }
      iVar3 = func_0x4b55b440(&LAB_00435471);
      if (0x3c < iVar3 + 1U) {
        iVar3 = func_0x4b55b44d(&LAB_00435471);
        iVar3 = func_0x9354b467(iVar3 + 0x435436,(int)&DAT_0043576c - (iVar3 + 0x435436),
                                s__virtual_displacement_map__0042a36f + 0xd,3);
        if (iVar3 != 0) {
          func_0x2ba9b37a(0,0,0,0,0);
        }
      }
      iVar3 = func_0x8f77b38d(&DAT_00435458,0x314,s__virtual_displacement_map__0042a36f + 9);
      if (iVar3 != 0) {
        func_0x2ba9b39e(0,0,0,0,0);
      }
      iVar3 = func_0x8f77b3b2(&DAT_00435458,0x314,*(undefined4 *)(local_8 * 8 + 0x4322bc));
      if (iVar3 != 0) {
        func_0x2ba9b3c3(0,0,0,0,0);
      }
      func_0x2a53b4d6(&DAT_00435458,s__eh_vector_constructor_iterator__0042a34b + 5,0x12010);
    }
  }
  return;
}



void __cdecl FUN_0041b295(undefined4 param_1)

{
  DAT_0043576c = param_1;
  return;
}



// Library Function - Single Match
//  __callnewh
// 
// Library: Visual Studio 2008 Release

int __cdecl __callnewh(size_t _Size)

{
  code *pcVar1;
  int iVar2;
  
  pcVar1 = (code *)func_0xf4aab46a(DAT_0043576c);
  if (pcVar1 != (code *)0x0) {
    iVar2 = (*pcVar1)(_Size);
    if (iVar2 != 0) {
      return 1;
    }
  }
  return 0;
}



// Library Function - Single Match
//  void __cdecl setSBUpLow(struct threadmbcinfostruct *)
// 
// Library: Visual Studio 2008 Release

void __cdecl setSBUpLow(threadmbcinfostruct *param_1)

{
  char *pcVar1;
  int iVar2;
  uint uVar3;
  undefined uVar4;
  char cVar5;
  byte *pbVar6;
  int unaff_ESI;
  undefined local_51c [6];
  byte local_516;
  byte local_515 [13];
  ushort local_508 [256];
  undefined local_308 [256];
  undefined local_208 [256];
  undefined local_108 [256];
  uint local_8;
  
  local_8 = DAT_00431c20 ^ (uint)&stack0xfffffffc;
  iVar2 = (*DAT_00428114)(*(undefined4 *)(unaff_ESI + 4),local_51c);
  if (iVar2 == 0) {
    uVar3 = 0;
    do {
      pcVar1 = (char *)(unaff_ESI + 0x11d + uVar3);
      if (pcVar1 + (-0x61 - (unaff_ESI + 0x11d)) + 0x20 < (char *)0x1a) {
        pbVar6 = (byte *)(unaff_ESI + 0x1d + uVar3);
        *pbVar6 = *pbVar6 | 0x10;
        cVar5 = (char)uVar3 + ' ';
LAB_0041b4d8:
        *pcVar1 = cVar5;
      }
      else {
        if (pcVar1 + (-0x61 - (unaff_ESI + 0x11d)) < (char *)0x1a) {
          pbVar6 = (byte *)(unaff_ESI + 0x1d + uVar3);
          *pbVar6 = *pbVar6 | 0x20;
          cVar5 = (char)uVar3 + -0x20;
          goto LAB_0041b4d8;
        }
        *pcVar1 = '\0';
      }
      uVar3 = uVar3 + 1;
    } while (uVar3 < 0x100);
  }
  else {
    uVar3 = 0;
    do {
      local_108[uVar3] = (char)uVar3;
      uVar3 = uVar3 + 1;
    } while (uVar3 < 0x100);
    local_108[0] = 0x20;
    if (local_516 != 0) {
      pbVar6 = local_515;
      do {
        uVar3 = (uint)local_516;
        if (uVar3 <= *pbVar6) {
          func_0x3b83b58b(local_108 + uVar3,0x20,(*pbVar6 - uVar3) + 1);
        }
        local_516 = pbVar6[1];
        pbVar6 = pbVar6 + 2;
      } while (local_516 != 0);
    }
    func_0x845db6b6(0,1,local_108,0x100,local_508,*(undefined4 *)(unaff_ESI + 4),
                    *(undefined4 *)(unaff_ESI + 0xc),0);
    func_0x855bb6d6(0,*(undefined4 *)(unaff_ESI + 0xc),0x100,local_108,0x100,local_208,0x100,
                    *(undefined4 *)(unaff_ESI + 4),0);
    func_0x855bb6fb(0,*(undefined4 *)(unaff_ESI + 0xc),0x200,local_108,0x100,local_308,0x100,
                    *(undefined4 *)(unaff_ESI + 4),0);
    uVar3 = 0;
    do {
      if ((local_508[uVar3] & 1) == 0) {
        if ((local_508[uVar3] & 2) != 0) {
          pbVar6 = (byte *)(unaff_ESI + 0x1d + uVar3);
          *pbVar6 = *pbVar6 | 0x20;
          uVar4 = local_308[uVar3];
          goto LAB_0041b476;
        }
        *(undefined *)(unaff_ESI + 0x11d + uVar3) = 0;
      }
      else {
        pbVar6 = (byte *)(unaff_ESI + 0x1d + uVar3);
        *pbVar6 = *pbVar6 | 0x10;
        uVar4 = local_208[uVar3];
LAB_0041b476:
        *(undefined *)(unaff_ESI + 0x11d + uVar3) = uVar4;
      }
      uVar3 = uVar3 + 1;
    } while (uVar3 < 0x100);
  }
  func_0x485fb6a6();
  return;
}



// Library Function - Single Match
//  int __cdecl getSystemCP(int)
// 
// Libraries: Visual Studio 2008 Release, Visual Studio 2010 Release

int __cdecl getSystemCP(int param_1)

{
  int iVar1;
  int unaff_ESI;
  int local_14;
  int local_c;
  char local_8;
  
  func_0x1270b760(0);
  DAT_00435774 = 0;
  if (unaff_ESI == -2) {
    DAT_00435774 = 1;
    iVar1 = (*DAT_0042811c)();
  }
  else if (unaff_ESI == -3) {
    DAT_00435774 = 1;
    iVar1 = (*DAT_00428118)();
  }
  else {
    if (unaff_ESI != -4) {
      if (local_8 == '\0') {
        DAT_00435774 = 0;
        return unaff_ESI;
      }
      *(uint *)(local_c + 0x70) = *(uint *)(local_c + 0x70) & 0xfffffffd;
      return unaff_ESI;
    }
    iVar1 = *(int *)(local_14 + 4);
    DAT_00435774 = 1;
  }
  if (local_8 != '\0') {
    *(uint *)(local_c + 0x70) = *(uint *)(local_c + 0x70) & 0xfffffffd;
  }
  return iVar1;
}



// WARNING: Control flow encountered bad instruction data

void __cdecl FUN_0041b612(undefined4 param_1,int param_2)

{
  byte *pbVar1;
  byte bVar2;
  char cVar3;
  uint uVar4;
  uint uVar5;
  int iVar6;
  undefined4 uVar7;
  undefined2 *puVar9;
  byte *pbVar10;
  int extraout_ECX;
  undefined2 *puVar11;
  undefined8 uVar12;
  uint local_24;
  byte *local_20;
  undefined local_1c [6];
  char local_16;
  char local_15;
  uint local_8;
  char *pcVar8;
  
  local_8 = DAT_00431c20 ^ (uint)&stack0xfffffffc;
  uVar4 = func_0x8de6b7e8();
  if (uVar4 == 0) {
LAB_0041b63d:
    func_0xf2e3b7fa();
                    // WARNING: Bad instruction - Truncating control flow here
    halt_baddata();
  }
  local_20 = (byte *)0x0;
  uVar5 = 0;
  do {
    if (*(uint *)((int)&DAT_004327a8 + uVar5) == uVar4) {
      func_0x3b83b8b2(param_2 + 0x1c,0,0x101);
      local_24 = 0;
      pbVar10 = &DAT_004327b8 + (int)local_20 * 0x30;
      local_20 = pbVar10;
      do {
        for (; (*pbVar10 != 0 && (bVar2 = pbVar10[1], bVar2 != 0)); pbVar10 = pbVar10 + 2) {
          for (uVar5 = (uint)*pbVar10; uVar5 <= bVar2; uVar5 = uVar5 + 1) {
            pbVar1 = (byte *)(param_2 + 0x1d + uVar5);
            *pbVar1 = *pbVar1 | (&DAT_004327a4)[local_24];
            bVar2 = pbVar10[1];
          }
        }
        local_24 = local_24 + 1;
        pbVar10 = local_20 + 8;
        local_20 = pbVar10;
      } while (local_24 < 4);
      *(uint *)(param_2 + 4) = uVar4;
      *(undefined4 *)(param_2 + 8) = 1;
      uVar7 = func_0xc3e3b91b();
      *(undefined4 *)(param_2 + 0xc) = uVar7;
      puVar9 = (undefined2 *)(param_2 + 0x10);
      puVar11 = (undefined2 *)(&DAT_004327ac + extraout_ECX);
      iVar6 = 6;
      do {
        *puVar9 = *puVar11;
        puVar11 = puVar11 + 1;
        puVar9 = puVar9 + 1;
        iVar6 = iVar6 + -1;
      } while (iVar6 != 0);
      goto LAB_0041b781;
    }
    local_20 = (byte *)((int)local_20 + 1);
    uVar5 = uVar5 + 0x30;
  } while (uVar5 < 0xf0);
  if ((uVar4 != 65000) && (uVar4 != 0xfde9)) {
    iVar6 = (*DAT_00428120)(uVar4 & 0xffff);
    if (iVar6 != 0) {
      iVar6 = (*DAT_00428114)(uVar4,local_1c);
      if (iVar6 != 0) {
        uVar7 = func_0x3b83b86b(param_2 + 0x1c,0,0x101);
        *(uint *)(param_2 + 4) = uVar4;
        *(undefined4 *)(param_2 + 0xc) = 0;
        cVar3 = (char)uVar7 + '2';
        pcVar8 = (char *)CONCAT31((int3)((uint)uVar7 >> 8),cVar3);
        *pcVar8 = *pcVar8 + cVar3;
        if ((local_16 != '\0') && (local_15 != '\0')) {
                    // WARNING: Bad instruction - Truncating control flow here
          halt_baddata();
        }
        pbVar10 = (byte *)(param_2 + 0x1e);
        iVar6 = 0xfe;
        do {
          *pbVar10 = *pbVar10 | 8;
          pbVar10 = pbVar10 + 1;
          iVar6 = iVar6 + -1;
        } while (iVar6 != 0);
        uVar12 = func_0xc3e3b970();
        *(int *)(param_2 + 0xc) = (int)uVar12;
        *(int *)(param_2 + 8) = (int)((ulonglong)uVar12 >> 0x20);
        *(undefined4 *)(param_2 + 0x10) = 0;
        *(undefined4 *)(param_2 + 0x14) = 0;
        *(undefined4 *)(param_2 + 0x18) = 0;
LAB_0041b781:
        func_0x56e4b93e();
                    // WARNING: Bad instruction - Truncating control flow here
        halt_baddata();
      }
      if (DAT_00435774 != 0) goto LAB_0041b63d;
    }
  }
  func_0x485fb9ab();
  return;
}



// Library Function - Single Match
//  ___freetlocinfo
// 
// Library: Visual Studio 2008 Release

void __cdecl ___freetlocinfo(int param_1)

{
  int *piVar1;
  undefined *puVar2;
  int iVar3;
  int **ppiVar4;
  
  iVar3 = param_1;
  if ((((*(undefined4 **)(param_1 + 0xbc) != (undefined4 *)0x0) &&
       (*(undefined4 **)(param_1 + 0xbc) != &DAT_00432c28)) &&
      (*(int **)(param_1 + 0xb0) != (int *)0x0)) && (**(int **)(param_1 + 0xb0) == 0)) {
    piVar1 = *(int **)(param_1 + 0xb8);
    if ((piVar1 != (int *)0x0) && (*piVar1 == 0)) {
      func_0xc273bba5(piVar1);
      func_0xa05fbcb0(*(undefined4 *)(param_1 + 0xbc));
    }
    piVar1 = *(int **)(param_1 + 0xb4);
    if ((piVar1 != (int *)0x0) && (*piVar1 == 0)) {
      func_0xc273bbc6(piVar1);
      func_0x5b5fbcd1(*(undefined4 *)(param_1 + 0xbc));
    }
    func_0xc273bbde(*(undefined4 *)(param_1 + 0xb0));
    func_0xc273bbe9(*(undefined4 *)(param_1 + 0xbc));
  }
  if ((*(int **)(param_1 + 0xc0) != (int *)0x0) && (**(int **)(param_1 + 0xc0) == 0)) {
    func_0xc273bc0a(*(int *)(param_1 + 0xc4) + -0xfe);
    func_0xc273bc1d(*(int *)(param_1 + 0xcc) + -0x80);
    func_0xc273bc2b(*(int *)(param_1 + 0xd0) + -0x80);
    func_0xc273bc36(*(undefined4 *)(param_1 + 0xc0));
  }
  puVar2 = *(undefined **)(undefined4 *)(param_1 + 0xd4);
  if ((puVar2 != &DAT_00432b68) && (*(int *)(puVar2 + 0xb4) == 0)) {
    func_0xc65dbd56(puVar2);
    func_0xc273bc5d(*(undefined4 *)(param_1 + 0xd4));
  }
  ppiVar4 = (int **)(param_1 + 0x50);
  param_1 = 6;
  do {
    if (((ppiVar4[-2] != (int *)&DAT_004328a0) && (piVar1 = *ppiVar4, piVar1 != (int *)0x0)) &&
       (*piVar1 == 0)) {
      func_0xc273bc82(piVar1);
    }
    if (((ppiVar4[-1] != (int *)0x0) && (piVar1 = ppiVar4[1], piVar1 != (int *)0x0)) &&
       (*piVar1 == 0)) {
      func_0xc273bc99(piVar1);
    }
    ppiVar4 = ppiVar4 + 4;
    param_1 = param_1 + -1;
  } while (param_1 != 0);
  func_0xc273bca8(iVar3);
  return;
}



// Library Function - Single Match
//  ___addlocaleref
// 
// Libraries: Visual Studio 2008 Release, Visual Studio 2010 Release

void __cdecl ___addlocaleref(int param_1)

{
  code *pcVar1;
  int iVar2;
  int *piVar3;
  
  iVar2 = param_1;
  pcVar1 = DAT_00428088;
  (*DAT_00428088)(param_1);
  if (*(int *)(param_1 + 0xb0) != 0) {
    (*pcVar1)(*(int *)(param_1 + 0xb0));
  }
  if (*(int *)(param_1 + 0xb8) != 0) {
    (*pcVar1)(*(int *)(param_1 + 0xb8));
  }
  if (*(int *)(param_1 + 0xb4) != 0) {
    (*pcVar1)(*(int *)(param_1 + 0xb4));
  }
  if (*(int *)(param_1 + 0xc0) != 0) {
    (*pcVar1)(*(int *)(param_1 + 0xc0));
  }
  piVar3 = (int *)(param_1 + 0x50);
  param_1 = 6;
  do {
    if (((undefined *)piVar3[-2] != &DAT_004328a0) && (*piVar3 != 0)) {
      (*pcVar1)(*piVar3);
    }
    if ((piVar3[-1] != 0) && (piVar3[1] != 0)) {
      (*pcVar1)(piVar3[1]);
    }
    piVar3 = piVar3 + 4;
    param_1 = param_1 + -1;
  } while (param_1 != 0);
  (*pcVar1)(*(int *)(iVar2 + 0xd4) + 0xb4);
  return;
}



// Library Function - Single Match
//  ___removelocaleref
// 
// Libraries: Visual Studio 2008 Release, Visual Studio 2010 Release

int __cdecl ___removelocaleref(int param_1)

{
  code *pcVar1;
  int iVar2;
  int *piVar3;
  
  iVar2 = param_1;
  pcVar1 = DAT_004280b4;
  if (param_1 != 0) {
    (*DAT_004280b4)(param_1);
    if (*(int *)(param_1 + 0xb0) != 0) {
      (*pcVar1)(*(int *)(param_1 + 0xb0));
    }
    if (*(int *)(param_1 + 0xb8) != 0) {
      (*pcVar1)(*(int *)(param_1 + 0xb8));
    }
    if (*(int *)(param_1 + 0xb4) != 0) {
      (*pcVar1)(*(int *)(param_1 + 0xb4));
    }
    if (*(int *)(param_1 + 0xc0) != 0) {
      (*pcVar1)(*(int *)(param_1 + 0xc0));
    }
    piVar3 = (int *)(param_1 + 0x50);
    param_1 = 6;
    do {
      if (((undefined *)piVar3[-2] != &DAT_004328a0) && (*piVar3 != 0)) {
        (*pcVar1)(*piVar3);
      }
      if ((piVar3[-1] != 0) && (piVar3[1] != 0)) {
        (*pcVar1)(piVar3[1]);
      }
      piVar3 = piVar3 + 4;
      param_1 = param_1 + -1;
    } while (param_1 != 0);
    (*pcVar1)(*(int *)(iVar2 + 0xd4) + 0xb4);
  }
  return iVar2;
}



// Library Function - Single Match
//  __wchartodigit
// 
// Library: Visual Studio 2008 Release

int __cdecl __wchartodigit(ushort param_1)

{
  int iVar1;
  ushort uVar2;
  
  if (param_1 < 0x30) {
    return -1;
  }
  if (param_1 < 0x3a) {
    return param_1 - 0x30;
  }
  iVar1 = 0xff10;
  if (param_1 < 0xff10) {
    iVar1 = 0x660;
    if (param_1 < 0x660) {
      return -1;
    }
    if (param_1 < 0x66a) goto LAB_0041bd20;
    iVar1 = 0x6f0;
    if (param_1 < 0x6f0) {
      return -1;
    }
    if (param_1 < 0x6fa) goto LAB_0041bd20;
    iVar1 = 0x966;
    if (param_1 < 0x966) {
      return -1;
    }
    if (param_1 < 0x970) goto LAB_0041bd20;
    iVar1 = 0x9e6;
    if (param_1 < 0x9e6) {
      return -1;
    }
    if (param_1 < 0x9f0) goto LAB_0041bd20;
    iVar1 = 0xa66;
    if (param_1 < 0xa66) {
      return -1;
    }
    if (param_1 < 0xa70) goto LAB_0041bd20;
    iVar1 = 0xae6;
    if (param_1 < 0xae6) {
      return -1;
    }
    if (param_1 < 0xaf0) goto LAB_0041bd20;
    iVar1 = 0xb66;
    if (param_1 < 0xb66) {
      return -1;
    }
    if (param_1 < 0xb70) goto LAB_0041bd20;
    iVar1 = 0xc66;
    if (param_1 < 0xc66) {
      return -1;
    }
    if (param_1 < 0xc70) goto LAB_0041bd20;
    iVar1 = 0xce6;
    if (param_1 < 0xce6) {
      return -1;
    }
    if (param_1 < 0xcf0) goto LAB_0041bd20;
    iVar1 = 0xd66;
    if (param_1 < 0xd66) {
      return -1;
    }
    if (param_1 < 0xd70) goto LAB_0041bd20;
    iVar1 = 0xe50;
    if (param_1 < 0xe50) {
      return -1;
    }
    if (param_1 < 0xe5a) goto LAB_0041bd20;
    iVar1 = 0xed0;
    if (param_1 < 0xed0) {
      return -1;
    }
    if (param_1 < 0xeda) goto LAB_0041bd20;
    iVar1 = 0xf20;
    if (param_1 < 0xf20) {
      return -1;
    }
    if (param_1 < 0xf2a) goto LAB_0041bd20;
    iVar1 = 0x1040;
    if (param_1 < 0x1040) {
      return -1;
    }
    if (param_1 < 0x104a) goto LAB_0041bd20;
    iVar1 = 0x17e0;
    if (param_1 < 0x17e0) {
      return -1;
    }
    if (param_1 < 0x17ea) goto LAB_0041bd20;
    iVar1 = 0x1810;
    if (param_1 < 0x1810) {
      return -1;
    }
    uVar2 = 0x181a;
  }
  else {
    uVar2 = 0xff1a;
  }
  if (uVar2 <= param_1) {
    return -1;
  }
LAB_0041bd20:
  return (uint)param_1 - iVar1;
}



// Library Function - Single Match
//  __iswctype_l
// 
// Library: Visual Studio 2008 Release

int __cdecl __iswctype_l(wint_t _C,wctype_t _Type,_locale_t _Locale)

{
  int iVar1;
  int local_18 [2];
  int local_10;
  char local_c;
  ushort local_8 [2];
  
  if (_C == 0xffff) {
    local_8[0] = 0;
  }
  else if (_C < 0x100) {
    local_8[0] = *(ushort *)(DAT_00432b64 + (uint)_C * 2) & _Type;
  }
  else {
    func_0x1270c0ae(_Locale);
    iVar1 = func_0xcb60c1cc(local_18,1,&_C,1,local_8,*(undefined4 *)(local_18[0] + 4),
                            *(undefined4 *)(local_18[0] + 0x14));
    if (iVar1 == 0) {
      local_8[0] = 0;
    }
    if (local_c != '\0') {
      *(uint *)(local_10 + 0x70) = *(uint *)(local_10 + 0x70) & 0xfffffffd;
    }
  }
  return (uint)(local_8[0] & _Type);
}



// Library Function - Single Match
//  _write_string
// 
// Library: Visual Studio 2008 Release

void __thiscall _write_string(void *this,int param_1)

{
  int *in_EAX;
  int *piVar1;
  int unaff_EDI;
  
  if (((*(byte *)(unaff_EDI + 0xc) & 0x40) == 0) || (*(int *)(unaff_EDI + 8) != 0)) {
    while (0 < param_1) {
                    // WARNING: Load size is inaccurate
      param_1 = param_1 + -1;
      func_0xbafcc1bb(*this);
      this = (void *)((int)this + 2);
      if (*in_EAX == -1) {
        piVar1 = (int *)func_0x7886c1c8();
        if (*piVar1 != 0x2a) {
          return;
        }
        func_0xbafcc1d6(0x3f);
      }
    }
  }
  else {
    *in_EAX = *in_EAX + param_1;
  }
  return;
}



// WARNING: Control flow encountered bad instruction data
// WARNING: Instruction at (ram,0x0041c148) overlaps instruction at (ram,0x0041c145)
// 
// WARNING: Globals starting with '_' overlap smaller symbols at the same address

void __cdecl FUN_0041c02b(int param_1,ushort *param_2,undefined4 param_3)

{
  ushort uVar1;
  ushort uVar2;
  char cVar3;
  undefined4 *puVar4;
  uint uVar5;
  ushort *puVar6;
  int local_454;
  char local_450;
  
  func_0x1270c248(param_3);
  if ((param_1 == 0) || (param_2 == (ushort *)0x0)) {
    puVar4 = (undefined4 *)func_0x7886c255();
    *puVar4 = 0x16;
    func_0x53aac265(0,0,0,0,0);
    if (local_450 != '\0') {
      *(uint *)(local_454 + 0x70) = *(uint *)(local_454 + 0x70) & 0xfffffffd;
    }
                    // WARNING: Bad instruction - Truncating control flow here
    halt_baddata();
  }
  uVar1 = *param_2;
  if (uVar1 != 0) {
    puVar6 = param_2 + 1;
    if ((ushort)(uVar1 - 0x20) < 0x59) {
      uVar5 = (int)s__vector_destructor_iterator__0042a3af[uVar1 + 1] & 0xf;
    }
    else {
      uVar5 = 0;
    }
    uVar5 = (int)s__vector_constructor_iterator__0042a3cf[uVar5 * 8 + 1] >> 4;
    if (uVar5 < 8) {
      cVar3 = (char)uVar5;
      switch(uVar5) {
      case 0:
                    // WARNING: Bad instruction - Truncating control flow here
        halt_baddata();
      case 1:
                    // WARNING: Bad instruction - Truncating control flow here
        halt_baddata();
      case 2:
        return;
      case 3:
        DAT_00000007 = DAT_00000007 + cVar3;
        if (uVar5 == 0x20) {
                    // WARNING: Bad instruction - Truncating control flow here
          halt_baddata();
        }
        if (uVar5 == 0x23) {
                    // WARNING: Bad instruction - Truncating control flow here
          halt_baddata();
        }
        if (uVar5 == 0x2b) {
                    // WARNING: Bad instruction - Truncating control flow here
          halt_baddata();
        }
        if (uVar5 == 0x2d) {
                    // WARNING: Bad instruction - Truncating control flow here
          halt_baddata();
        }
        if (uVar5 == 0x30) {
                    // WARNING: Bad instruction - Truncating control flow here
          halt_baddata();
        }
        break;
      case 4:
        DAT_00000007 = DAT_00000007 + cVar3;
        if (_DAT_fa836631 < 0) {
                    // WARNING: Bad instruction - Truncating control flow here
          halt_baddata();
        }
        break;
      case 5:
        DAT_00000007 = DAT_00000007 + cVar3;
                    // WARNING: Bad instruction - Truncating control flow here
        halt_baddata();
      case 6:
        DAT_00000007 = DAT_00000007 + cVar3;
        if (_DAT_fa836631 < 0) {
                    // WARNING: Bad instruction - Truncating control flow here
          halt_baddata();
        }
        break;
      case 7:
        DAT_00000007 = DAT_00000007 + cVar3;
        if (uVar5 == 0x49) {
          uVar2 = *puVar6;
          if ((uVar2 == 0x36) && (param_2[2] == 0x34)) {
                    // WARNING: Bad instruction - Truncating control flow here
            halt_baddata();
          }
          if ((uVar2 == 0x33) && (param_2[2] == 0x32)) {
                    // WARNING: Bad instruction - Truncating control flow here
            halt_baddata();
          }
          if ((((uVar2 != 100) && (uVar2 != 0x69)) && (uVar2 != 0x6f)) &&
             (((uVar2 != 0x75 && (uVar2 != 0x78)) && (uVar2 != 0x58)))) {
            func_0xbafcc53c(uVar1);
                    // WARNING: Bad instruction - Truncating control flow here
            halt_baddata();
          }
        }
        else {
          if (uVar5 == 0x68) {
                    // WARNING: Bad instruction - Truncating control flow here
            halt_baddata();
          }
          if (uVar5 == 0x6c) {
            if (*puVar6 != 0x6c) {
                    // WARNING: Bad instruction - Truncating control flow here
              halt_baddata();
            }
                    // WARNING: Bad instruction - Truncating control flow here
            halt_baddata();
          }
          if (uVar5 == 0x77) {
                    // WARNING: Bad instruction - Truncating control flow here
            halt_baddata();
          }
        }
      }
    }
    if (*puVar6 != 0) {
                    // WARNING: Bad instruction - Truncating control flow here
      halt_baddata();
    }
  }
  if (local_450 != '\0') {
    *(uint *)(local_454 + 0x70) = *(uint *)(local_454 + 0x70) & 0xfffffffd;
  }
  func_0x485fcd54();
  return;
}



// Library Function - Single Match
//  _write_multi_char
// 
// Libraries: Visual Studio 2003 Release, Visual Studio 2005 Release, Visual Studio 2008 Release,
// Visual Studio 2010 Release

void __cdecl _write_multi_char(undefined4 param_1,int param_2)

{
  int *in_EAX;
  
  do {
    if (param_2 < 1) {
      return;
    }
    param_2 = param_2 + -1;
    func_0xbafccdc0(param_1);
  } while (*in_EAX != -1);
  return;
}



// WARNING: Control flow encountered bad instruction data
// WARNING: Instruction at (ram,0x0041cd5d) overlaps instruction at (ram,0x0041cd5a)
// 

void __cdecl FUN_0041cc19(int param_1,ushort *param_2,undefined4 param_3,undefined *param_4)

{
  byte *pbVar1;
  ushort uVar2;
  byte bVar3;
  undefined4 *puVar4;
  uint uVar5;
  char *pcVar6;
  int local_448;
  char local_444;
  
  func_0x1270ce36(param_3);
  if (param_1 == 0) {
switchD_0041cd5a_caseD_9:
    puVar4 = (undefined4 *)func_0x7886ce3f();
    *puVar4 = 0x16;
  }
  else {
    if (param_2 != (ushort *)0x0) {
      uVar2 = *param_2;
      pcVar6 = (char *)(uint)uVar2;
      if (uVar2 == 0) {
LAB_0041d76f:
        if (local_444 != '\0') {
          *(uint *)(local_448 + 0x70) = *(uint *)(local_448 + 0x70) & 0xfffffffd;
        }
        func_0x485fd94b();
        return;
      }
      if ((ushort)(uVar2 - 0x20) < 0x59) {
        uVar5 = (byte)(&DAT_0042a498)[uVar2] & 0xf;
      }
      else {
        uVar5 = 0;
      }
      bVar3 = (byte)(&DAT_0042a4b8)[uVar5 * 9] >> 4;
      switch(bVar3) {
      case 0:
                    // WARNING: Bad instruction - Truncating control flow here
        halt_baddata();
      case 1:
                    // WARNING: Bad instruction - Truncating control flow here
        halt_baddata();
      case 2:
        *param_4 = *param_4;
        pbVar1 = param_4 + -0x40b73;
        *pbVar1 = *pbVar1 << 7 | *pbVar1 >> 1;
        *(int *)(pcVar6 + -0x45b7a) = *(int *)(pcVar6 + -0x45b7a) + -1;
        *(int *)(pcVar6 + -0x44f7a) = *(int *)(pcVar6 + -0x44f7a) + -1;
        *(int *)(pcVar6 + -0x42b7a) = *(int *)(pcVar6 + -0x42b7a) + -1;
        *(int *)(pcVar6 + -0x4237a) = *(int *)(pcVar6 + -0x4237a) + -1;
        *(int *)(pcVar6 + -0x4077a) = *(int *)(pcVar6 + -0x4077a) + -1;
        *(int *)(pcVar6 + -0x4277a) = *(int *)(pcVar6 + -0x4277a) + -1;
                    // WARNING: Bad instruction - Truncating control flow here
        halt_baddata();
      case 3:
        *pcVar6 = *pcVar6 + bVar3;
                    // WARNING: Bad instruction - Truncating control flow here
        halt_baddata();
      case 4:
        *pcVar6 = *pcVar6 + bVar3;
                    // WARNING: Bad instruction - Truncating control flow here
        halt_baddata();
      case 5:
        *pcVar6 = *pcVar6 + bVar3;
                    // WARNING: Bad instruction - Truncating control flow here
        halt_baddata();
      case 6:
        *pcVar6 = *pcVar6 + bVar3;
                    // WARNING: Bad instruction - Truncating control flow here
        halt_baddata();
      case 7:
        *pcVar6 = *pcVar6 + bVar3;
                    // WARNING: Bad instruction - Truncating control flow here
        halt_baddata();
      case 0xbad1abe1:
        if (param_2[1] != 0) {
                    // WARNING: Bad instruction - Truncating control flow here
          halt_baddata();
        }
        if ((bVar3 == 0) || (bVar3 == 7)) goto LAB_0041d76f;
        break;
      default:
        goto switchD_0041cd5a_caseD_9;
      }
    }
    puVar4 = (undefined4 *)func_0x7886ce7a();
    *puVar4 = 0x16;
  }
  func_0x53aace51(0,0,0,0,0);
  if (local_444 != '\0') {
    *(uint *)(local_448 + 0x70) = *(uint *)(local_448 + 0x70) & 0xfffffffd;
  }
                    // WARNING: Bad instruction - Truncating control flow here
  halt_baddata();
}



// Library Function - Single Match
//  _write_multi_char
// 
// Libraries: Visual Studio 2003 Release, Visual Studio 2005 Release, Visual Studio 2008 Release,
// Visual Studio 2010 Release

void __cdecl _write_multi_char(undefined4 param_1,int param_2)

{
  int *in_EAX;
  
  do {
    if (param_2 < 1) {
      return;
    }
    param_2 = param_2 + -1;
    func_0xb108d9ba();
  } while (*in_EAX != -1);
  return;
}



// Library Function - Single Match
//  _write_string
// 
// Library: Visual Studio 2008 Release

void __cdecl _write_string(int param_1)

{
  int *in_EAX;
  int *piVar1;
  int unaff_EDI;
  
  if (((*(byte *)(unaff_EDI + 0xc) & 0x40) == 0) || (*(int *)(unaff_EDI + 8) != 0)) {
    while (0 < param_1) {
      param_1 = param_1 + -1;
      func_0xb108d9f2();
      if (*in_EAX == -1) {
        piVar1 = (int *)func_0x7886d9fd();
        if (*piVar1 != 0x2a) {
          return;
        }
        func_0xb108da0b();
      }
    }
  }
  else {
    *in_EAX = *in_EAX + param_1;
  }
  return;
}



// WARNING: Control flow encountered bad instruction data
// WARNING: Instruction at (ram,0x0041db2a) overlaps instruction at (ram,0x0041db29)
// 
// WARNING: Globals starting with '_' overlap smaller symbols at the same address

void __cdecl FUN_0041d85f(int param_1,char *param_2,undefined4 param_3,int *param_4)

{
  byte *pbVar1;
  undefined uVar2;
  char cVar3;
  code *pcVar4;
  byte bVar5;
  undefined4 *puVar6;
  uint uVar7;
  int iVar8;
  undefined *puVar9;
  undefined *extraout_EDX;
  undefined *puVar10;
  char *pcVar11;
  undefined local_254 [8];
  int local_24c;
  char local_248;
  char *local_244;
  char *local_240;
  undefined4 local_23c;
  undefined4 local_238;
  undefined4 local_234;
  undefined4 local_22c;
  int *local_228;
  undefined4 local_224;
  int local_21c;
  char local_215;
  undefined4 local_214;
  uint local_8;
  
  local_8 = DAT_00431c20 ^ (uint)&stack0xfffffffc;
  local_228 = param_4;
  local_214 = 0;
  local_238 = 0;
  local_21c = 0;
  local_234 = 0;
  local_23c = 0;
  func_0x1270da7c(param_3);
  if (param_1 == 0) goto LAB_0041d8ca;
  puVar10 = extraout_EDX;
  if ((*(byte *)(param_1 + 0xc) & 0x40) == 0) {
    uVar7 = func_0x20c1dac1(param_1);
    puVar10 = &DAT_00432150;
    if ((uVar7 == 0xffffffff) || (uVar7 == 0xfffffffe)) {
      puVar9 = &DAT_00432150;
    }
    else {
      puVar9 = (undefined *)((uVar7 & 0x1f) * 0x40 + (&DAT_00436d80)[(int)uVar7 >> 5]);
    }
    if ((puVar9[0x24] & 0x7f) != 0) goto LAB_0041d8ca;
    if ((uVar7 == 0xffffffff) || (uVar7 == 0xfffffffe)) {
      puVar9 = &DAT_00432150;
    }
    else {
      puVar9 = (undefined *)((uVar7 & 0x1f) * 0x40 + (&DAT_00436d80)[(int)uVar7 >> 5]);
    }
    if ((puVar9[0x24] & 0x80) != 0) goto LAB_0041d8ca;
  }
  if (param_2 == (char *)0x0) {
LAB_0041d8ca:
    puVar6 = (undefined4 *)func_0x7886da85();
    *puVar6 = 0x16;
    func_0x53aada97(0,0,0,0,0);
    if (local_248 != '\0') {
      *(uint *)(local_24c + 0x70) = *(uint *)(local_24c + 0x70) & 0xfffffffd;
    }
                    // WARNING: Bad instruction - Truncating control flow here
    halt_baddata();
  }
  local_215 = *param_2;
  local_22c = 0;
  local_224 = 0;
  local_244 = (char *)0x0;
  cVar3 = local_215;
  if (local_215 == '\0') goto LAB_0041e3e5;
  pcVar11 = param_2 + 1;
  uVar7 = 0;
  if ((byte)(local_215 - 0x20U) < 0x59) {
    uVar7 = (byte)(&DAT_0042a498)[local_215] & 0xf;
  }
  bVar5 = (byte)(&DAT_0042a4b8)[uVar7 * 9] >> 4;
  local_244 = (char *)(uint)bVar5;
  local_240 = pcVar11;
  if (local_244 == (char *)0x8) goto LAB_0041d8ca;
  if (local_244 < &DAT_00000007 || local_244 + -7 == (char *)0x0) {
                    // WARNING: Could not find normalized switch variable to match jumptable
    switch(bVar5) {
    case 0:
                    // WARNING: Bad instruction - Truncating control flow here
      halt_baddata();
    case 1:
                    // WARNING: Bad instruction - Truncating control flow here
      halt_baddata();
    case 2:
      *pcVar11 = *pcVar11 + (char)((uint)puVar10 >> 8);
      pbVar1 = (byte *)(param_2 + 0x1b6e88e);
      *pbVar1 = *pbVar1 << 1 | *pbVar1 >> 7;
                    // WARNING: Bad instruction - Truncating control flow here
      halt_baddata();
    case 3:
      DAT_00000007 = DAT_00000007 + bVar5;
      func_0x838a4e53();
      func_0x2b764e3b();
                    // WARNING: Bad instruction - Truncating control flow here
      halt_baddata();
    case 4:
      DAT_00000007 = DAT_00000007 + bVar5;
      _DAT_00000023 = 0xfffddcbd;
      *(int *)(param_2 + -0x42760380) = *(int *)(param_2 + -0x42760380) + -1;
      pcVar4 = (code *)swi(3);
      (*pcVar4)();
      return;
    case 5:
      DAT_00000007 = DAT_00000007 + bVar5;
                    // WARNING: Bad instruction - Truncating control flow here
      halt_baddata();
    case 6:
      DAT_00000007 = DAT_00000007 + bVar5;
      local_228 = param_4 + 1;
      local_21c = *param_4;
      if (local_21c < 0) {
                    // WARNING: Bad instruction - Truncating control flow here
        halt_baddata();
      }
      break;
    case 7:
      if ((POPCOUNT((uint)(local_244 + -7) & 0xff) & 1U) == 0) {
        uVar2 = in((short)CONCAT31((int3)((uint)puVar10 >> 8),local_215));
        *(undefined *)param_4 = uVar2;
      }
      else {
        *local_244 = *local_244 + bVar5;
        if (local_215 == 'I') {
          cVar3 = *pcVar11;
          if ((cVar3 == '6') && (param_2[2] == '4')) {
                    // WARNING: Bad instruction - Truncating control flow here
            halt_baddata();
          }
          if ((cVar3 == '3') && (param_2[2] == '2')) {
                    // WARNING: Bad instruction - Truncating control flow here
            halt_baddata();
          }
          if (((((cVar3 != 'd') && (cVar3 != 'i')) && (cVar3 != 'o')) &&
              ((cVar3 != 'u' && (cVar3 != 'x')))) && (cVar3 != 'X')) {
            local_244 = (char *)0x0;
            local_23c = 0;
            iVar8 = func_0xdf52dec6(0x49,local_254);
            if (iVar8 != 0) {
              func_0xb108dde3();
              local_240 = param_2 + 2;
              if (*pcVar11 == '\0') goto LAB_0041d8ca;
            }
            func_0xb108de05();
                    // WARNING: Bad instruction - Truncating control flow here
            halt_baddata();
          }
          break;
        }
        if (local_215 == 'h') {
                    // WARNING: Bad instruction - Truncating control flow here
          halt_baddata();
        }
      }
      if (local_215 == 'l') {
        if (*pcVar11 != 'l') {
                    // WARNING: Bad instruction - Truncating control flow here
          halt_baddata();
        }
                    // WARNING: Bad instruction - Truncating control flow here
        halt_baddata();
      }
      if (local_215 == 'w') {
                    // WARNING: Bad instruction - Truncating control flow here
        halt_baddata();
      }
    }
  }
  local_215 = *pcVar11;
  if (local_215 != '\0') {
                    // WARNING: Bad instruction - Truncating control flow here
    halt_baddata();
  }
  cVar3 = '\0';
  if ((local_244 != (char *)0x0) && (local_244 != &DAT_00000007)) {
    puVar6 = (undefined4 *)func_0x7886e58b();
    *puVar6 = 0x16;
                    // WARNING: Bad instruction - Truncating control flow here
    halt_baddata();
  }
LAB_0041e3e5:
  local_215 = cVar3;
  if (local_248 != '\0') {
    *(uint *)(local_24c + 0x70) = *(uint *)(local_24c + 0x70) & 0xfffffffd;
  }
  func_0x485fe5c1();
  return;
}



// Library Function - Single Match
//  long __stdcall __CxxUnhandledExceptionFilter(struct _EXCEPTION_POINTERS *)
// 
// Libraries: Visual Studio 2008 Release, Visual Studio 2010 Release

long __CxxUnhandledExceptionFilter(_EXCEPTION_POINTERS *param_1)

{
  PEXCEPTION_RECORD pEVar1;
  ULONG_PTR UVar2;
  
  pEVar1 = param_1->ExceptionRecord;
  if (((pEVar1->ExceptionCode == 0xe06d7363) && (pEVar1->NumberParameters == 3)) &&
     ((UVar2 = pEVar1->ExceptionInformation[0], UVar2 == 0x19930520 ||
      (((UVar2 == 0x19930521 || (UVar2 == 0x19930522)) || (UVar2 == 0x1994000)))))) {
    func_0x0d2ae83c();
  }
  return 0;
}



// WARNING: Control flow encountered bad instruction data
// Library Function - Single Match
//  __XcptFilter
// 
// Library: Visual Studio 2008 Release

int __cdecl __XcptFilter(ulong _ExceptionNum,_EXCEPTION_POINTERS *_ExceptionPtr)

{
  ulong *puVar1;
  code *pcVar2;
  undefined4 uVar3;
  ulong uVar4;
  undefined4 uVar5;
  int iVar6;
  ulong *puVar7;
  int iVar8;
  int iVar9;
  
  iVar6 = func_0xc7ace85d();
  if (iVar6 != 0) {
    puVar1 = *(ulong **)(iVar6 + 0x5c);
    puVar7 = puVar1;
    do {
      if (*puVar7 == _ExceptionNum) break;
      puVar7 = puVar7 + 3;
    } while (puVar7 < puVar1 + DAT_004329ac * 3);
    if ((puVar1 + DAT_004329ac * 3 <= puVar7) || (*puVar7 != _ExceptionNum)) {
      puVar7 = (ulong *)0x0;
    }
    if ((puVar7 == (ulong *)0x0) || (pcVar2 = (code *)puVar7[2], pcVar2 == (code *)0x0)) {
                    // WARNING: Bad instruction - Truncating control flow here
      halt_baddata();
    }
    if (pcVar2 == (code *)0x5) {
      puVar7[2] = 0;
                    // WARNING: Bad instruction - Truncating control flow here
      halt_baddata();
    }
    if (pcVar2 != (code *)0x1) {
      uVar3 = *(undefined4 *)(iVar6 + 0x60);
      *(_EXCEPTION_POINTERS **)(iVar6 + 0x60) = _ExceptionPtr;
      if (puVar7[1] == 8) {
        if (DAT_004329a0 < DAT_004329a4 + DAT_004329a0) {
          iVar8 = DAT_004329a0 * 0xc;
          iVar9 = DAT_004329a0;
          do {
            *(undefined4 *)(iVar8 + 8 + *(int *)(iVar6 + 0x5c)) = 0;
            iVar9 = iVar9 + 1;
            iVar8 = iVar8 + 0xc;
          } while (iVar9 < DAT_004329a4 + DAT_004329a0);
        }
        uVar4 = *puVar7;
        uVar5 = *(undefined4 *)(iVar6 + 100);
        if (uVar4 == 0xc000008e) {
          *(undefined4 *)(iVar6 + 100) = 0x83;
        }
        else if (uVar4 == 0xc0000090) {
          *(undefined4 *)(iVar6 + 100) = 0x81;
        }
        else if (uVar4 == 0xc0000091) {
          *(undefined4 *)(iVar6 + 100) = 0x84;
        }
        else if (uVar4 == 0xc0000093) {
          *(undefined4 *)(iVar6 + 100) = 0x85;
        }
        else if (uVar4 == 0xc000008d) {
          *(undefined4 *)(iVar6 + 100) = 0x82;
        }
        else if (uVar4 == 0xc000008f) {
          *(undefined4 *)(iVar6 + 100) = 0x86;
        }
        else if (uVar4 == 0xc0000092) {
          *(undefined4 *)(iVar6 + 100) = 0x8a;
        }
        (*pcVar2)(8,*(undefined4 *)(iVar6 + 100));
        *(undefined4 *)(iVar6 + 100) = uVar5;
      }
      else {
        puVar7[2] = 0;
        (*pcVar2)(puVar7[1]);
      }
      *(undefined4 *)(iVar6 + 0x60) = uVar3;
    }
    iVar6 = -1;
  }
  return iVar6;
}



// WARNING: Control flow encountered bad instruction data
// Library Function - Single Match
//  _wparse_cmdline
// 
// Library: Visual Studio 2008 Release

void __thiscall _wparse_cmdline(void *this,short **param_1,int *param_2)

{
  bool bVar1;
  bool bVar2;
  short *in_EAX;
  short *psVar3;
  short sVar4;
  uint uVar5;
  int *unaff_EBX;
  
  bVar1 = false;
  *unaff_EBX = 0;
  *param_2 = 1;
  if (param_1 != (short **)0x0) {
    *param_1 = (short *)this;
    param_1 = param_1 + 1;
  }
  do {
    if (*in_EAX == 0x22) {
      bVar1 = !bVar1;
      sVar4 = 0x22;
    }
    else {
      *unaff_EBX = *unaff_EBX + 1;
      if ((short *)this != (short *)0x0) {
        *(short *)this = *in_EAX;
        this = (void *)((int)this + 2);
      }
      sVar4 = *in_EAX;
      if (sVar4 == 0) goto LAB_0041e98e;
    }
    in_EAX = in_EAX + 1;
  } while ((bVar1) || ((sVar4 != 0x20 && (sVar4 != 9))));
  if ((short *)this != (short *)0x0) {
    *(short *)((int)this + -2) = 0;
  }
LAB_0041e98e:
  bVar1 = false;
  if (*in_EAX != 0) {
    for (; (*in_EAX == 0x20 || (*in_EAX == 9)); in_EAX = in_EAX + 1) {
    }
    if (*in_EAX != 0) {
      if (param_1 != (short **)0x0) {
        *param_1 = (short *)this;
      }
      *param_2 = *param_2 + 1;
      while( true ) {
        bVar2 = true;
        uVar5 = 0;
        for (; *in_EAX == 0x5c; in_EAX = in_EAX + 1) {
          uVar5 = uVar5 + 1;
        }
        psVar3 = in_EAX;
        if (*in_EAX == 0x22) {
          if (((uVar5 & 1) == 0) && ((!bVar1 || (psVar3 = in_EAX + 1, *psVar3 != 0x22)))) {
            bVar2 = false;
            bVar1 = !bVar1;
            psVar3 = in_EAX;
          }
          uVar5 = uVar5 >> 1;
        }
        while (uVar5 != 0) {
          uVar5 = uVar5 - 1;
          if ((short *)this != (short *)0x0) {
            *(short *)this = 0x5c;
            this = (void *)((int)this + 2);
          }
          *unaff_EBX = *unaff_EBX + 1;
        }
        sVar4 = *psVar3;
        if ((sVar4 == 0) || ((!bVar1 && ((sVar4 == 0x20 || (sVar4 == 9)))))) break;
        if (bVar2) {
          if ((short *)this != (short *)0x0) {
            *(short *)this = sVar4;
            this = (void *)((int)this + 2);
          }
          *unaff_EBX = *unaff_EBX + 1;
        }
        in_EAX = psVar3 + 1;
      }
      if ((short *)this != (short *)0x0) {
        *(short *)this = 0;
      }
      *unaff_EBX = *unaff_EBX + 1;
                    // WARNING: Bad instruction - Truncating control flow here
      halt_baddata();
    }
  }
  if (param_1 != (short **)0x0) {
    *param_1 = (short *)0x0;
  }
  *param_2 = *param_2 + 1;
  return;
}



// WARNING: Globals starting with '_' overlap smaller symbols at the same address
// Library Function - Single Match
//  __wsetargv
// 
// Libraries: Visual Studio 2008 Release, Visual Studio 2010 Release

int __cdecl __wsetargv(void)

{
  uint uVar1;
  int iVar2;
  int iVar3;
  uint in_ECX;
  uint local_8;
  
  _DAT_004359c8 = 0;
  local_8 = in_ECX;
  (*DAT_00428238)(0,&DAT_004357c0,0x104);
  _DAT_00434fb0 = &DAT_004357c0;
  func_0x161aec74(0,&local_8);
  if ((((local_8 < 0x3fffffff) && (in_ECX < 0x7fffffff)) &&
      (uVar1 = (in_ECX + local_8 * 2) * 2, in_ECX * 2 <= uVar1)) &&
     (iVar2 = func_0x3f2cec9d(uVar1), iVar2 != 0)) {
    func_0x161aecb6(iVar2,&local_8);
    _DAT_00434f90 = local_8 - 1;
    iVar3 = 0;
    _DAT_00434f98 = iVar2;
  }
  else {
    iVar3 = -1;
  }
  return iVar3;
}



void FUN_0041eb5a(void)

{
  (*DAT_00428124)();
  return;
}



void FUN_0041eb67(void)

{
  func_0xfbcded25();
  FUN_0041eb5a();
  return;
}



// Library Function - Single Match
//  ___security_init_cookie
// 
// Library: Visual Studio 2008 Release

void __cdecl ___security_init_cookie(void)

{
  uint uVar1;
  uint uVar2;
  uint uVar3;
  uint uVar4;
  uint local_14;
  uint local_10;
  uint local_c;
  uint local_8;
  
  local_c = 0;
  local_8 = 0;
  if ((DAT_00431c20 == 0xbb40e64e) || ((DAT_00431c20 & 0xffff0000) == 0)) {
    (*DAT_00428134)(&local_c);
    uVar4 = local_8 ^ local_c;
    uVar1 = (*DAT_004280dc)();
    uVar2 = (*DAT_00428084)();
    uVar3 = (*DAT_00428218)();
    (*DAT_00428130)(&local_14);
    DAT_00431c20 = uVar4 ^ uVar1 ^ uVar2 ^ uVar3 ^ local_10 ^ local_14;
    if (DAT_00431c20 == 0xbb40e64e) {
      DAT_00431c20 = 0xbb40e64f;
    }
    else if ((DAT_00431c20 & 0xffff0000) == 0) {
      DAT_00431c20 = DAT_00431c20 | DAT_00431c20 << 0x10;
    }
    DAT_00431c24 = ~DAT_00431c20;
  }
  else {
    DAT_00431c24 = ~DAT_00431c20;
  }
  return;
}



undefined4 * __fastcall FUN_0041ec5c(undefined4 *param_1,undefined param_2,undefined param_3)

{
  func_0xea64ef23(&param_3);
  *param_1 = s___fastcall_0042a58f + 9;
  return param_1;
}



undefined4 * __thiscall FUN_0041ec85(void *this,byte param_1)

{
  *(char **)this = s___fastcall_0042a58f + 9;
  func_0x9a65ef4e();
  if ((param_1 & 1) != 0) {
    func_0x15bbed5a(this);
  }
  return (undefined4 *)this;
}



// Library Function - Single Match
//  ___TypeMatch
// 
// Libraries: Visual Studio 2008 Release, Visual Studio 2010 Release

undefined4 __cdecl ___TypeMatch(byte *param_1,byte *param_2,uint *param_3)

{
  int iVar1;
  undefined4 uVar2;
  
  iVar1 = *(int *)(param_1 + 4);
  if ((iVar1 == 0) || (*(char *)(iVar1 + 8) == '\0')) {
LAB_0041ed04:
    uVar2 = 1;
  }
  else {
    if (iVar1 == *(int *)(param_2 + 4)) {
LAB_0041ece3:
      if (((((*param_2 & 2) == 0) || ((*param_1 & 8) != 0)) &&
          (((*param_3 & 1) == 0 || ((*param_1 & 1) != 0)))) &&
         (((*param_3 & 2) == 0 || ((*param_1 & 2) != 0)))) goto LAB_0041ed04;
    }
    else {
      iVar1 = func_0x9c15ee8f((char *)(iVar1 + 8),*(int *)(param_2 + 4) + 8);
      if (iVar1 == 0) goto LAB_0041ece3;
    }
    uVar2 = 0;
  }
  return uVar2;
}



// WARNING: Control flow encountered bad instruction data
// Library Function - Single Match
//  ___FrameUnwindFilter
// 
// Library: Visual Studio 2008 Release

undefined4 __cdecl ___FrameUnwindFilter(int **param_1)

{
  int iVar1;
  
  if (**param_1 == -0x1fbcb0b3) {
    iVar1 = func_0x40adeef1();
    if (0 < *(int *)(iVar1 + 0x90)) {
      iVar1 = func_0x40adeeff();
      *(int *)(iVar1 + 0x90) = *(int *)(iVar1 + 0x90) + -1;
    }
  }
  else if (**param_1 == -0x1f928c9d) {
    iVar1 = func_0x40adeee0();
    *(undefined4 *)(iVar1 + 0x90) = 0;
                    // WARNING: Bad instruction - Truncating control flow here
    halt_baddata();
  }
  return 0;
}



// Library Function - Single Match
//  ___AdjustPointer
// 
// Libraries: Visual Studio 2008 Release, Visual Studio 2010 Release

int __cdecl ___AdjustPointer(int param_1,int *param_2)

{
  int iVar1;
  
  iVar1 = *param_2 + param_1;
  if (-1 < param_2[1]) {
    iVar1 = iVar1 + *(int *)(*(int *)(param_2[1] + param_1) + param_2[2]) + param_2[1];
  }
  return iVar1;
}



// Library Function - Single Match
//  unsigned char __cdecl IsInExceptionSpec(struct EHExceptionRecord *,struct _s_ESTypeList const *)
// 
// Libraries: Visual Studio 2008 Release, Visual Studio 2010 Release

uchar __cdecl IsInExceptionSpec(EHExceptionRecord *param_1,_s_ESTypeList *param_2)

{
  int iVar1;
  int iVar2;
  int *piVar3;
  int *unaff_EDI;
  int local_c;
  uchar local_5;
  
  if (unaff_EDI == (int *)0x0) {
    func_0x592af0bf();
    func_0x0d2af0c4();
  }
  local_c = 0;
  local_5 = '\0';
  if (0 < *unaff_EDI) {
    do {
      piVar3 = *(int **)(*(int *)(param_1 + 0x1c) + 0xc);
      iVar2 = *piVar3;
      if (0 < iVar2) {
        do {
          piVar3 = piVar3 + 1;
          iVar1 = func_0xa41df103(unaff_EDI[1] + local_c * 0x10,*piVar3,
                                  *(undefined4 *)(param_1 + 0x1c));
          if (iVar1 != 0) {
            local_5 = '\x01';
            break;
          }
          iVar2 = iVar2 + -1;
        } while (0 < iVar2);
      }
      local_c = local_c + 1;
    } while (local_c < *unaff_EDI);
  }
  return local_5;
}



// Library Function - Single Match
//  void __cdecl CatchIt(struct EHExceptionRecord *,struct EHRegistrationNode *,struct _CONTEXT
// *,void *,struct _s_FuncInfo const *,struct _s_HandlerType const *,struct _s_CatchableType const
// *,struct _s_TryBlockMapEntry const *,int,struct EHRegistrationNode *,unsigned char)
// 
// Libraries: Visual Studio 2005 Release, Visual Studio 2008 Release, Visual Studio 2010 Release

void __cdecl
CatchIt(EHExceptionRecord *param_1,EHRegistrationNode *param_2,_CONTEXT *param_3,void *param_4,
       _s_FuncInfo *param_5,_s_HandlerType *param_6,_s_CatchableType *param_7,
       _s_TryBlockMapEntry *param_8,int param_9,EHRegistrationNode *param_10,uchar param_11)

{
  int iVar1;
  int unaff_ESI;
  int unaff_EDI;
  
  if (param_5 != (_s_FuncInfo *)0x0) {
    func_0xcf23f537(param_1);
  }
  func_0xee7bf54e();
  func_0x4c1ef55c();
  *(int *)(unaff_ESI + 8) = *(int *)(unaff_EDI + 4) + 1;
  iVar1 = func_0xb420f57d(param_1);
  if (iVar1 != 0) {
    func_0xb57bf58b(iVar1);
  }
  return;
}



// Library Function - Single Match
//  void __cdecl FindHandlerForForeignException(struct EHExceptionRecord *,struct EHRegistrationNode
// *,struct _CONTEXT *,void *,struct _s_FuncInfo const *,int,int,struct EHRegistrationNode *)
// 
// Libraries: Visual Studio 2005 Release, Visual Studio 2008 Release

void __cdecl
FindHandlerForForeignException
          (EHExceptionRecord *param_1,EHRegistrationNode *param_2,_CONTEXT *param_3,void *param_4,
          _s_FuncInfo *param_5,int param_6,int param_7,EHRegistrationNode *param_8)

{
  int iVar1;
  int iVar2;
  int *piVar3;
  uint local_c;
  uint local_8;
  
  if (*(int *)param_1 != -0x7ffffffd) {
    iVar1 = func_0x40adf5aa();
    if (*(int *)(iVar1 + 0x80) != 0) {
      iVar1 = func_0x40adf5b8();
      iVar2 = func_0xebaaf5c3();
      if (((*(int *)(iVar1 + 0x80) != iVar2) && (*(int *)param_1 != -0x1fbcb0b3)) &&
         (iVar1 = func_0xab7cf5e7(param_1,param_2,param_3,param_4,param_5,param_7,param_8),
         iVar1 != 0)) {
        return;
      }
    }
    if (*(int *)(param_5 + 0xc) == 0) {
      func_0x592af600();
    }
    piVar3 = (int *)func_0x217ef615(param_5,param_7,param_6,&local_8,&local_c);
    if (local_8 < local_c) {
      do {
        if ((*piVar3 <= param_6) && (param_6 <= piVar3[1])) {
          iVar2 = piVar3[3] * 0x10 + piVar3[4];
          iVar1 = *(int *)(iVar2 + -0xc);
          if (((iVar1 == 0) || (*(char *)(iVar1 + 8) == '\0')) &&
             ((*(byte *)(iVar2 + -0x10) & 0x40) == 0)) {
            func_0x6124f668(param_1,param_3,param_4,param_5,0,param_7,param_8);
          }
        }
        local_8 = local_8 + 1;
        piVar3 = piVar3 + 5;
      } while (local_8 < local_c);
    }
  }
  return;
}



// WARNING: Control flow encountered bad instruction data
// Library Function - Single Match
//  void __cdecl FindHandler(struct EHExceptionRecord *,struct EHRegistrationNode *,struct _CONTEXT
// *,void *,struct _s_FuncInfo const *,unsigned char,int,struct EHRegistrationNode *)
// 
// Library: Visual Studio 2008 Release

void __cdecl
FindHandler(EHExceptionRecord *param_1,EHRegistrationNode *param_2,_CONTEXT *param_3,void *param_4,
           _s_FuncInfo *param_5,uchar param_6,int param_7,EHRegistrationNode *param_8)

{
  _s_FuncInfo *p_Var1;
  char cVar2;
  int iVar3;
  int *piVar4;
  _s_FuncInfo *p_Var5;
  int iVar6;
  _s_FuncInfo *p_Var7;
  EHRegistrationNode *pEVar8;
  undefined local_30 [12];
  int local_24;
  uint local_20;
  int local_1c;
  int local_18;
  uint local_14;
  int local_10;
  int local_c;
  char local_5;
  
  local_5 = '\0';
  if (*(int *)(param_5 + 4) < 0x81) {
    local_c = (int)(char)param_2[8];
  }
  else {
    local_c = *(int *)(param_2 + 8);
  }
  if ((local_c < -1) || (*(int *)(param_5 + 4) <= local_c)) {
    func_0x592af6ba();
  }
  p_Var7 = (_s_FuncInfo *)param_1;
  if (*(int *)param_1 != -0x1f928c9d) goto LAB_0041f7ce;
  p_Var5 = (_s_FuncInfo *)0x19930520;
  if (*(int *)(param_1 + 0x10) != 3) goto LAB_0041f63b;
  iVar3 = *(int *)(param_1 + 0x14);
  if (((iVar3 != 0x19930520) && (iVar3 != 0x19930521)) && (iVar3 != 0x19930522)) goto LAB_0041f63b;
  if (*(int *)(param_1 + 0x1c) != 0) goto LAB_0041f63b;
  iVar3 = func_0x40adf701();
  if (*(int *)(iVar3 + 0x88) != 0) {
    iVar3 = func_0x40adf713();
    param_1 = *(EHExceptionRecord **)(iVar3 + 0x88);
    iVar3 = func_0x40adf721();
    param_3 = *(_CONTEXT **)(iVar3 + 0x8c);
    iVar3 = func_0xde65f832(param_1,1);
    if (iVar3 == 0) {
      func_0x592af73d();
    }
    if ((((*(int *)param_1 == -0x1f928c9d) && (*(int *)((int)param_1 + 0x10) == 3)) &&
        ((iVar3 = *(int *)((int)param_1 + 0x14), iVar3 == 0x19930520 ||
         ((iVar3 == 0x19930521 || (iVar3 == 0x19930522)))))) && (*(int *)((int)param_1 + 0x1c) == 0)
       ) {
      func_0x592af767();
    }
    iVar3 = func_0x40adf76c();
    if (*(int *)(iVar3 + 0x94) == 0) goto LAB_0041f63b;
    iVar3 = func_0x40adf77a();
    piVar4 = *(int **)(iVar3 + 0x94);
    iVar3 = func_0x40adf785();
    iVar6 = 0;
    *(undefined4 *)(iVar3 + 0x94) = 0;
    cVar2 = func_0xf01ff795(param_1);
    if (cVar2 != '\0') goto LAB_0041f63b;
    p_Var5 = (_s_FuncInfo *)0x0;
    if (0 < *piVar4) {
      do {
        cVar2 = func_0xa579f7b1(&DAT_004329b4);
        if (cVar2 != '\0') goto LAB_0041f60c;
        iVar6 = iVar6 + 1;
        p_Var5 = p_Var5 + 0x10;
      } while (iVar6 < *piVar4);
    }
    do {
      func_0x0d2af7c2();
LAB_0041f60c:
      func_0x721ff7cc(param_1,1);
      func_0x541df7db(s___thiscall_0042a59b + 5);
      func_0xa580f7e9(local_30,s_InitializeCriticalSectionAndSpin_0042f635 + 0xf);
LAB_0041f63b:
      p_Var7 = (_s_FuncInfo *)param_1;
      if (((*(int *)param_1 == -0x1f928c9d) && (*(int *)(param_1 + 0x10) == 3)) &&
         ((p_Var1 = *(_s_FuncInfo **)(param_1 + 0x14), p_Var1 == p_Var5 ||
          ((p_Var1 == (_s_FuncInfo *)0x19930521 || (p_Var1 == (_s_FuncInfo *)0x19930522)))))) {
        if ((*(int *)(param_5 + 0xc) != 0) &&
           (piVar4 = (int *)func_0x217ef83d(param_5,param_7,local_c,&local_14,&local_20),
           local_14 < local_20)) {
          if ((*piVar4 <= local_c) && (local_c <= piVar4[1])) {
            local_10 = piVar4[4];
            for (local_1c = piVar4[3]; 0 < local_1c; local_1c = local_1c + -1) {
              piVar4 = *(int **)(*(int *)(param_1 + 0x1c) + 0xc);
              for (local_18 = *piVar4; 0 < local_18; local_18 = local_18 + -1) {
                piVar4 = piVar4 + 1;
                local_24 = *piVar4;
                iVar3 = func_0xa41df891(local_10,local_24,*(undefined4 *)(param_1 + 0x1c));
                if (iVar3 != 0) {
                  local_5 = 1;
                  func_0x6124f8d4(param_1,param_3,param_4,param_5,local_24,param_7,param_8);
                  return;
                }
              }
              local_10 = local_10 + 0x10;
            }
          }
                    // WARNING: Bad instruction - Truncating control flow here
          halt_baddata();
        }
        if (param_6 != '\0') {
          func_0x721ff8f6(param_1,1);
        }
        if ((((local_5 != '\0') || ((*(uint *)param_5 & 0x1fffffff) < 0x19930521)) ||
            (*(int *)(param_5 + 0x1c) == 0)) || (cVar2 = func_0xf01ff925(param_1), cVar2 != '\0'))
        goto LAB_0041f7fa;
        func_0x40adf933();
        func_0x40adf938();
        iVar3 = func_0x40adf93d();
        *(EHExceptionRecord **)(iVar3 + 0x88) = param_1;
        iVar3 = func_0x40adf948();
        *(_CONTEXT **)(iVar3 + 0x8c) = param_3;
        pEVar8 = param_8;
        if (param_8 == (EHRegistrationNode *)0x0) {
          pEVar8 = param_2;
        }
        func_0xee7bf965(pEVar8,param_1);
        func_0x4c1ef976(param_2,param_4,param_5,0xffffffff);
        func_0x6b20f981(*(undefined4 *)(param_5 + 0x1c));
        p_Var7 = param_5;
      }
LAB_0041f7ce:
      if (*(int *)(param_5 + 0xc) == 0) goto LAB_0041f7fa;
      p_Var5 = param_5;
    } while (param_6 != '\0');
    func_0xcf24f9ad(p_Var7,param_2,param_3,param_4,param_5,local_c,param_7,param_8);
LAB_0041f7fa:
    iVar3 = func_0x40adf9b5();
    if (*(int *)(iVar3 + 0x94) != 0) {
      func_0x592af9c3();
    }
  }
  return;
}



undefined4 * __thiscall FUN_0041f812(void *this,undefined4 param_1)

{
  func_0x3d65fad8(param_1);
  *(char **)this = s___fastcall_0042a58f + 9;
  return (undefined4 *)this;
}



undefined4 __cdecl
FUN_0041f82f(int *param_1,undefined4 param_2,undefined4 param_3,undefined4 param_4,uint *param_5,
            int param_6,undefined4 param_7,uint param_8)

{
  int iVar1;
  undefined4 uVar2;
  
  iVar1 = func_0x40adf9f2();
  if ((((*(int *)(iVar1 + 0x20c) != 0) || (*param_1 == -0x1f928c9d)) || (*param_1 == -0x7fffffda))
     || (((*param_5 & 0x1fffffff) < 0x19930522 || ((*(byte *)(param_5 + 8) & 1) == 0)))) {
    if ((*(byte *)(param_1 + 1) & 0x66) == 0) {
      if ((param_5[3] != 0) || ((0x19930520 < (*param_5 & 0x1fffffff) && (param_5[7] != 0)))) {
        if ((*param_1 == -0x1f928c9d) &&
           (((2 < (uint)param_1[4] && (0x19930522 < (uint)param_1[5])) &&
            (*(code **)(param_1[7] + 8) != (code *)0x0)))) {
          uVar2 = (**(code **)(param_1[7] + 8))
                            (param_1,param_2,param_3,param_4,param_5,param_6,param_7,param_8 & 0xff)
          ;
          return uVar2;
        }
        func_0xc325fac0(param_1,param_2,param_3,param_4,param_5,param_8,param_6,param_7);
      }
    }
    else if ((param_5[1] != 0) && (param_6 == 0)) {
      *(char *)param_5 = *(char *)param_5 + (char)param_5;
      do {
                    // WARNING: Do nothing block with infinite loop
      } while( true );
    }
  }
  return 1;
}



// Library Function - Single Match
//  __CallSettingFrame@12
// 
// Library: Visual Studio

void __thiscall __CallSettingFrame_12(void *this,undefined4 param_1,undefined4 param_2,int param_3)

{
  code *pcVar1;
  int iVar2;
  
  pcVar1 = (code *)func_0xb349fc8d(param_3,&stack0xfffffffc,this);
  (*pcVar1)();
  iVar2 = *(int *)(param_3 + 0x10);
  if (iVar2 == 0x100) {
    iVar2 = 2;
  }
  func_0xb349fcaf(iVar2,param_3);
  return;
}



// Library Function - Single Match
//  _abort
// 
// Library: Visual Studio 2008 Release

void __cdecl _abort(void)

{
  code *pcVar1;
  int iVar2;
  undefined4 local_32c [20];
  undefined4 *local_2dc;
  undefined4 *local_2d8;
  undefined4 local_2d4 [39];
  
  if (((byte)DAT_004329f0 & 1) != 0) {
    func_0xa8e1fbdc(10);
  }
  iVar2 = func_0x3c3bfbe2();
  if (iVar2 != 0) {
    func_0x493bfbed(0x16);
  }
  if (((byte)DAT_004329f0 & 2) != 0) {
    local_2d4[0] = 0x10001;
    func_0x3b83fc85(local_32c,0,0x50);
    local_2dc = local_32c;
    local_2d8 = local_2d4;
    local_32c[0] = 0x40000015;
    (*DAT_004280e8)(0);
    (*DAT_004280e4)(&local_2dc);
  }
  func_0x44a7fccc(3);
  pcVar1 = (code *)swi(3);
  (*pcVar1)();
  return;
}



void __cdecl FUN_0041fb17(uint param_1,uint param_2)

{
  DAT_004329f0 = ~param_2 & DAT_004329f0 | param_1 & param_2;
  return;
}



// WARNING: Globals starting with '_' overlap smaller symbols at the same address

void __cdecl FUN_0041fb38(undefined4 param_1)

{
  _DAT_004359d8 = param_1;
  return;
}



// Library Function - Single Match
//  __malloc_crt
// 
// Libraries: Visual Studio 2008 Release, Visual Studio 2010 Release

void * __cdecl __malloc_crt(size_t _Size)

{
  void *pvVar1;
  uint uVar2;
  
  uVar2 = 0;
  while( true ) {
    pvVar1 = (void *)func_0x676efd0e(_Size);
    if (pvVar1 != (void *)0x0) {
      return pvVar1;
    }
    if (DAT_004359dc == 0) break;
    (*DAT_0042821c)(uVar2);
    uVar2 = uVar2 + 1000;
    if (DAT_004359dc < uVar2) {
      uVar2 = 0xffffffff;
    }
    if (uVar2 == 0xffffffff) {
      return (void *)0x0;
    }
  }
  return (void *)0x0;
}



// Library Function - Single Match
//  __calloc_crt
// 
// Libraries: Visual Studio 2008 Release, Visual Studio 2010 Release

void * __cdecl __calloc_crt(size_t _Count,size_t _Size)

{
  void *pvVar1;
  uint uVar2;
  
  uVar2 = 0;
  while( true ) {
    pvVar1 = (void *)func_0x2416fd58(_Count,_Size,0);
    if (pvVar1 != (void *)0x0) {
      return pvVar1;
    }
    if (DAT_004359dc == 0) break;
    (*DAT_0042821c)(uVar2);
    uVar2 = uVar2 + 1000;
    if (DAT_004359dc < uVar2) {
      uVar2 = 0xffffffff;
    }
    if (uVar2 == 0xffffffff) {
      return (void *)0x0;
    }
  }
  return (void *)0x0;
}



// Library Function - Single Match
//  __realloc_crt
// 
// Libraries: Visual Studio 2008 Release, Visual Studio 2010 Release

void * __cdecl __realloc_crt(void *_Ptr,size_t _NewSize)

{
  void *pvVar1;
  uint uVar2;
  
  uVar2 = 0;
  do {
    pvVar1 = (void *)func_0xc186fda2(_Ptr,_NewSize);
    if (pvVar1 != (void *)0x0) {
      return pvVar1;
    }
    if (_NewSize == 0) {
      return (void *)0x0;
    }
    if (DAT_004359dc == 0) {
      return (void *)0x0;
    }
    (*DAT_0042821c)(uVar2);
    uVar2 = uVar2 + 1000;
    if (DAT_004359dc < uVar2) {
      uVar2 = 0xffffffff;
    }
  } while (uVar2 != 0xffffffff);
  return (void *)0x0;
}



// Library Function - Single Match
//  _fastzero_I
// 
// Libraries: Visual Studio 2005, Visual Studio 2008, Visual Studio 2019

void __cdecl _fastzero_I(undefined (*param_1) [16],uint param_2)

{
  uint uVar1;
  
  uVar1 = param_2 >> 7;
  do {
    *param_1 = (undefined  [16])0x0;
    param_1[1] = (undefined  [16])0x0;
    param_1[2] = (undefined  [16])0x0;
    param_1[3] = (undefined  [16])0x0;
    param_1[4] = (undefined  [16])0x0;
    param_1[5] = (undefined  [16])0x0;
    param_1[6] = (undefined  [16])0x0;
    param_1[7] = (undefined  [16])0x0;
    param_1 = param_1 + 8;
    uVar1 = uVar1 - 1;
  } while (uVar1 != 0);
  return;
}



// Library Function - Single Match
//  __VEC_memzero
// 
// Libraries: Visual Studio 2005, Visual Studio 2008, Visual Studio 2019

undefined * __cdecl __VEC_memzero(undefined *param_1,undefined4 param_2,uint param_3)

{
  int iVar1;
  uint uVar2;
  int iVar3;
  undefined *puVar4;
  
  uVar2 = (int)param_1 >> 0x1f;
  iVar3 = (((uint)param_1 ^ uVar2) - uVar2 & 0xf ^ uVar2) - uVar2;
  if (iVar3 == 0) {
    uVar2 = param_3 & 0x7f;
    if (param_3 != uVar2) {
      func_0x1e2dfe69(param_1,param_3 - uVar2);
    }
    if (uVar2 != 0) {
      puVar4 = param_1 + (param_3 - uVar2);
      for (; uVar2 != 0; uVar2 = uVar2 - 1) {
        *puVar4 = 0;
        puVar4 = puVar4 + 1;
      }
    }
  }
  else {
    iVar3 = 0x10 - iVar3;
    puVar4 = param_1;
    for (iVar1 = iVar3; iVar1 != 0; iVar1 = iVar1 + -1) {
      *puVar4 = 0;
      puVar4 = puVar4 + 1;
    }
    func_0x752dfeb5(param_1 + iVar3,0,param_3 - iVar3);
  }
  return param_1;
}



// Library Function - Single Match
//  __ValidateImageBase
// 
// Libraries: Visual Studio 2008 Release, Visual Studio 2010 Release

BOOL __cdecl __ValidateImageBase(PBYTE pImageBase)

{
  if ((*(short *)pImageBase == 0x5a4d) &&
     (*(int *)(pImageBase + *(int *)(pImageBase + 0x3c)) == 0x4550)) {
    return (uint)(*(short *)((int)(pImageBase + *(int *)(pImageBase + 0x3c)) + 0x18) == 0x10b);
  }
  return 0;
}



// Library Function - Single Match
//  __FindPESection
// 
// Library: Visual Studio 2008 Release

PIMAGE_SECTION_HEADER __cdecl __FindPESection(PBYTE pImageBase,DWORD_PTR rva)

{
  int iVar1;
  PIMAGE_SECTION_HEADER p_Var2;
  uint uVar3;
  
  iVar1 = *(int *)(pImageBase + 0x3c);
  uVar3 = 0;
  p_Var2 = (PIMAGE_SECTION_HEADER)
           (pImageBase + *(ushort *)(pImageBase + iVar1 + 0x14) + 0x18 + iVar1);
  if (*(ushort *)(pImageBase + iVar1 + 6) != 0) {
    do {
      if ((p_Var2->VirtualAddress <= rva) &&
         (rva < (p_Var2->Misc).PhysicalAddress + p_Var2->VirtualAddress)) {
        return p_Var2;
      }
      uVar3 = uVar3 + 1;
      p_Var2 = p_Var2 + 1;
    } while (uVar3 < *(ushort *)(pImageBase + iVar1 + 6));
  }
  return (PIMAGE_SECTION_HEADER)0x0;
}



uint __fastcall FUN_0041fda4(undefined4 param_1,undefined param_2,int param_3)

{
  uint uVar1;
  int iVar2;
  uint unaff_EBX;
  undefined4 local_14;
  undefined4 uStack_10;
  uint local_c;
  undefined4 local_8;
  
  local_8 = 0xfffffffe;
  uStack_10 = 0x415390;
  local_c = DAT_00431c20 ^ 0x42f6d8;
  local_14._0_1_ = (char)ExceptionList;
  local_14 = (void *)CONCAT31((int3)((uint)ExceptionList >> 8),(char)local_14 + (char)&local_14);
  uVar1 = in(CONCAT11(1,param_2));
  if ((uVar1 | *(uint *)((unaff_EBX ^ *(uint *)(unaff_EBX + 0x68000000)) + 0xc08504c4)) != 0) {
    ExceptionList = &local_14;
    iVar2 = func_0x4c2effba(0x400000,param_3 + -0x400000);
    if (iVar2 != 0) {
      ExceptionList = local_14;
      return ~(*(uint *)(iVar2 + 0x24) >> 0x1f) & 1;
    }
  }
  ExceptionList = local_14;
  return 0;
}



// Library Function - Single Match
//  __forcdecpt_l
// 
// Library: Visual Studio 2008 Release

void __cdecl __forcdecpt_l(char *_Buf,_locale_t _Locale)

{
  char cVar1;
  char cVar2;
  int iVar3;
  bool bVar4;
  int local_14;
  int local_c;
  char local_8;
  
  func_0x1271002b(_Locale);
  iVar3 = func_0x84680137((int)*_Buf);
  bVar4 = iVar3 == 0x65;
  while (!bVar4) {
    _Buf = _Buf + 1;
    iVar3 = func_0x41670146(*_Buf);
    bVar4 = iVar3 == 0;
  }
  iVar3 = func_0x84680154((int)*_Buf);
  if (iVar3 == 0x78) {
    _Buf = _Buf + 2;
  }
  cVar2 = *_Buf;
  *_Buf = ***(char ***)(local_14 + 0xbc);
  do {
    _Buf = _Buf + 1;
    cVar1 = *_Buf;
    *_Buf = cVar2;
    cVar2 = cVar1;
  } while (*_Buf != '\0');
  if (local_8 != '\0') {
    *(uint *)(local_c + 0x70) = *(uint *)(local_c + 0x70) & 0xfffffffd;
  }
  return;
}



// Library Function - Single Match
//  __cropzeros_l
// 
// Libraries: Visual Studio 2008 Release, Visual Studio 2010 Release

void __cdecl __cropzeros_l(char *_Buf,_locale_t _Locale)

{
  char *pcVar1;
  char cVar3;
  int local_14;
  int local_c;
  char local_8;
  char *pcVar2;
  
  func_0x1271009e(_Locale);
  cVar3 = *_Buf;
  if (cVar3 != '\0') {
    do {
      if (cVar3 == ***(char ***)(local_14 + 0xbc)) break;
      _Buf = _Buf + 1;
      cVar3 = *_Buf;
    } while (cVar3 != '\0');
  }
  if (*_Buf != '\0') {
    do {
      _Buf = _Buf + 1;
      cVar3 = *_Buf;
      pcVar1 = _Buf;
      if ((cVar3 == '\0') || (cVar3 == 'e')) break;
    } while (cVar3 != 'E');
    do {
      pcVar2 = pcVar1;
      pcVar1 = pcVar2 + -1;
    } while (*pcVar1 == '0');
    if (*pcVar1 == ***(char ***)(local_14 + 0xbc)) {
      pcVar1 = pcVar2 + -2;
    }
    do {
      cVar3 = *_Buf;
      pcVar1 = pcVar1 + 1;
      _Buf = _Buf + 1;
      *pcVar1 = cVar3;
    } while (cVar3 != '\0');
  }
  if (local_8 != '\0') {
    *(uint *)(local_c + 0x70) = *(uint *)(local_c + 0x70) & 0xfffffffd;
  }
  return;
}



// Library Function - Single Match
//  __positive
// 
// Libraries: Visual Studio 2008 Release, Visual Studio 2010 Release

int __cdecl __positive(double *arg)

{
  if (0.0 < *arg != (*arg == 0.0)) {
    return 1;
  }
  return 0;
}



// Library Function - Single Match
//  __fassign_l
// 
// Libraries: Visual Studio 2005 Release, Visual Studio 2008 Release, Visual Studio 2010 Release

void __cdecl __fassign_l(int flag,char *argument,char *number,_locale_t param_4)

{
  undefined4 local_c;
  undefined4 local_8;
  
  if (flag == 0) {
    func_0x5869025d(&flag,number,param_4);
    *(int *)argument = flag;
  }
  else {
    func_0xb0680244(&local_c);
    *(undefined4 *)argument = local_c;
    *(undefined4 *)(argument + 4) = local_8;
  }
  return;
}



void __cdecl FUN_0041ffb4(undefined4 param_1,undefined4 param_2,undefined4 param_3)

{
  func_0x6a31017f(param_1,param_2,param_3,0);
  return;
}



void __cdecl FUN_0041ffed(undefined4 param_1)

{
  func_0x593001b2(param_1,0);
  return;
}



void __cdecl FUN_00420000(undefined4 param_1)

{
  func_0xcc3001c5(param_1,0);
  return;
}



// WARNING: Control flow encountered bad instruction data
// Library Function - Single Match
//  __cftoe2_l
// 
// Library: Visual Studio 2008 Release

undefined4 __cdecl
__cftoe2_l(uint param_1,int param_2,int param_3,int *param_4,char param_5,undefined4 param_6)

{
  undefined *in_EAX;
  undefined4 *puVar1;
  int iVar2;
  int iVar3;
  undefined *puVar4;
  undefined *puVar5;
  undefined4 uVar6;
  int local_14;
  int local_c;
  char local_8;
  
  func_0x127101e1(param_6);
  if ((in_EAX == (undefined *)0x0) || (param_1 == 0)) {
    puVar1 = (undefined4 *)func_0x788701ec();
    uVar6 = 0x16;
  }
  else {
    iVar2 = param_2;
    if (param_2 < 1) {
      iVar2 = 0;
    }
    if (iVar2 + 9U < param_1) {
      if (param_5 != '\0') {
        func_0xc6310258();
      }
      puVar4 = in_EAX;
      if (*param_4 == 0x2d) {
        *in_EAX = 0x2d;
        puVar4 = in_EAX + 1;
      }
      puVar5 = puVar4;
      if (0 < param_2) {
        puVar5 = puVar4 + 1;
        *puVar4 = *puVar5;
        *puVar5 = *(undefined *)**(undefined4 **)(local_14 + 0xbc);
      }
      puVar5 = puVar5 + (uint)(param_5 == '\0') + param_2;
      if (param_1 == 0xffffffff) {
        puVar4 = (undefined *)0xffffffff;
      }
      else {
        puVar4 = in_EAX + (param_1 - (int)puVar5);
      }
      iVar2 = func_0x317002af(puVar5,puVar4,s___stdcall_0042a5a7 + 9);
      if (iVar2 != 0) {
        func_0x2baa02c2(0,0,0,0,0);
      }
      if (param_3 != 0) {
        *puVar5 = 0x45;
      }
      if (*(char *)param_4[3] != '0') {
        iVar2 = param_4[1] + -1;
        if (iVar2 < 0) {
          iVar2 = -iVar2;
          puVar5[1] = 0x2d;
        }
        if (99 < iVar2) {
          iVar3 = iVar2 / 100;
          iVar2 = iVar2 % 100;
          puVar5[2] = puVar5[2] + (char)iVar3;
        }
        if (9 < iVar2) {
          iVar3 = iVar2 / 10;
          iVar2 = iVar2 % 10;
          puVar5[3] = puVar5[3] + (char)iVar3;
        }
        puVar5[4] = puVar5[4] + (char)iVar2;
      }
      if (((DAT_00435b1c & 1) != 0) && (puVar5[2] == '0')) {
        func_0x8b610321(puVar5 + 2,puVar5 + 3,3);
      }
      if (local_8 != '\0') {
        *(uint *)(local_c + 0x70) = *(uint *)(local_c + 0x70) & 0xfffffffd;
      }
      return 0;
    }
    puVar1 = (undefined4 *)func_0x78870230();
    uVar6 = 0x22;
  }
  *puVar1 = uVar6;
  func_0x53ab01fb(0,0,0,0,0);
  if (local_8 != '\0') {
    *(uint *)(local_c + 0x70) = *(uint *)(local_c + 0x70) & 0xfffffffd;
  }
                    // WARNING: Bad instruction - Truncating control flow here
  halt_baddata();
}



// Library Function - Single Match
//  __cftoe_l
// 
// Library: Visual Studio 2008 Release

void __cdecl
__cftoe_l(undefined4 *param_1,undefined *param_2,int param_3,int param_4,undefined4 param_5,
         undefined4 param_6)

{
  undefined4 *puVar1;
  int iVar2;
  int local_30 [4];
  undefined local_20 [24];
  uint local_8;
  
  local_8 = DAT_00431c20 ^ (uint)&stack0xfffffffc;
  func_0x7c6b0469(*param_1,param_1[1],local_30,local_20,0x16);
  if ((param_2 == (undefined *)0x0) || (param_3 == 0)) {
    puVar1 = (undefined4 *)func_0x78870377();
    *puVar1 = 0x16;
    func_0x53ab0383(0,0,0,0,0);
  }
  else {
    if (param_3 == -1) {
      iVar2 = -1;
    }
    else {
      iVar2 = (param_3 - (uint)(local_30[0] == 0x2d)) - (uint)(0 < param_4);
    }
    iVar2 = func_0x006a04d5(param_2 + (uint)(0 < param_4) + (uint)(local_30[0] == 0x2d),iVar2,
                            param_4 + 1,local_30);
    if (iVar2 == 0) {
      func_0x0b3203f6(param_3,param_4,param_5,local_30,0,param_6);
    }
    else {
      *param_2 = 0;
    }
  }
  func_0x48600406();
  return;
}



void __cdecl
FUN_00420252(undefined4 param_1,undefined4 param_2,undefined4 param_3,undefined4 param_4,
            undefined4 param_5)

{
  func_0x7a330423(param_1,param_2,param_3,param_4,param_5,0);
  return;
}



// WARNING: Control flow encountered bad instruction data
// WARNING: Instruction at (ram,0x0042034e) overlaps instruction at (ram,0x00420349)
// 

undefined4 __cdecl
FUN_00420272(uint *param_1,undefined *param_2,uint param_3,int param_4,int param_5,
            undefined4 param_6)

{
  short sVar1;
  char cVar2;
  short sVar3;
  ushort uVar4;
  undefined4 *puVar5;
  int iVar6;
  int iVar7;
  char *pcVar8;
  char *pcVar9;
  uint uVar10;
  uint uVar11;
  char cVar12;
  int extraout_ECX;
  uint extraout_ECX_00;
  uint extraout_ECX_01;
  uint extraout_ECX_02;
  short sVar13;
  char *pcVar14;
  char *pcVar15;
  bool bVar16;
  undefined4 uVar17;
  char *local_28;
  int local_20;
  char local_1c;
  uint local_18;
  
  local_18 = 0x3ff;
  sVar1 = 0x30;
  func_0x1271044d(param_6);
  if (param_4 < 0) {
    param_4 = 0;
  }
  if ((param_2 == (undefined *)0x0) || (param_3 == 0)) {
    puVar5 = (undefined4 *)func_0x78870461();
    uVar17 = 0x16;
LAB_004202ad:
    *puVar5 = uVar17;
    func_0x53ab0470(0,0,0,0,0);
    if (local_1c != '\0') {
      *(uint *)(local_20 + 0x70) = *(uint *)(local_20 + 0x70) & 0xfffffffd;
    }
                    // WARNING: Bad instruction - Truncating control flow here
    halt_baddata();
  }
  *param_2 = 0;
  if (param_3 <= param_4 + 0xbU) {
    puVar5 = (undefined4 *)func_0x7887049f();
    uVar17 = 0x22;
    goto LAB_004202ad;
  }
  if ((param_1[1] >> 0x14 & 0x7ff) == 0x7ff) {
    if (param_3 == 0xffffffff) {
      iVar6 = -1;
    }
    else {
      iVar6 = param_3 - 2;
    }
    pcVar8 = param_2 + 2;
    iVar7 = func_0x4a3404ec(param_1,pcVar8,iVar6,param_4,0);
    iVar6 = extraout_ECX;
    if (iVar7 != 0) {
      do {
        *(byte *)(iVar6 + -0x697bf0c5) = *(byte *)(iVar6 + -0x697bf0c5) | (byte)((uint)pcVar8 >> 8);
        pcVar8 = pcVar8 + 0x6183e44d;
        cVar2 = *pcVar8;
        cVar12 = (char)iVar6;
        *pcVar8 = *pcVar8 + cVar12;
        iVar6 = local_20;
        pcVar8 = local_28;
      } while (SCARRY1(cVar2,cVar12));
                    // WARNING: Bad instruction - Truncating control flow here
      halt_baddata();
    }
    if (*pcVar8 == '-') {
      *param_2 = 0x2d;
      param_2 = param_2 + 1;
    }
    *param_2 = 0x30;
    param_2[1] = ((param_5 == 0) - 1U & 0xe0) + 0x78;
    pcVar8 = (char *)func_0x9b700531(param_2 + 2,0x65);
    if (pcVar8 != (char *)0x0) {
      *pcVar8 = ((param_5 == 0) - 1U & 0xe0) + 0x70;
      pcVar8[3] = '\0';
                    // WARNING: Bad instruction - Truncating control flow here
      halt_baddata();
    }
    goto LAB_004205d1;
  }
  if ((param_1[1] & 0x80000000) != 0) {
    *param_2 = 0x2d;
    param_2 = param_2 + 1;
  }
  *param_2 = 0x30;
  param_2[1] = ((param_5 == 0) - 1U & 0xe0) + 0x78;
  sVar13 = (-(ushort)(param_5 != 0) & 0xffe0) + 0x27;
  if ((param_1[1] & 0x7ff00000) == 0) {
    param_2[2] = 0x30;
    if ((*param_1 | param_1[1] & 0xfffff) == 0) {
      local_18 = 0;
    }
    else {
      local_18 = 0x3fe;
    }
  }
  else {
    param_2[2] = 0x31;
  }
  pcVar15 = param_2 + 3;
  pcVar8 = param_2 + 4;
  if (param_4 == 0) {
    *pcVar15 = '\0';
  }
  else {
    *pcVar15 = ***(char ***)(local_28 + 0xbc);
  }
  if (((param_1[1] & 0xfffff) != 0) || (*param_1 != 0)) {
    do {
      if (param_4 < 1) break;
      sVar3 = func_0xfb6c0719();
      uVar4 = sVar3 + 0x30;
      if (0x39 < uVar4) {
        uVar4 = uVar4 + sVar13;
      }
      sVar1 = sVar1 + -4;
      *pcVar8 = (char)uVar4;
      pcVar8 = pcVar8 + 1;
      param_4 = param_4 + -1;
    } while (-1 < sVar1);
    if ((-1 < sVar1) && (uVar4 = func_0xfb6c076d(), pcVar14 = pcVar8, 8 < uVar4)) {
      while( true ) {
        pcVar9 = pcVar14 + -1;
        if ((*pcVar9 != 'f') && (*pcVar9 != 'F')) break;
        *pcVar9 = '0';
        pcVar14 = pcVar9;
      }
      if (pcVar9 == pcVar15) {
        pcVar14[-2] = pcVar14[-2] + '\x01';
      }
      else if (*pcVar9 == '9') {
        *pcVar9 = (char)sVar13 + ':';
      }
      else {
        *pcVar9 = *pcVar9 + '\x01';
      }
    }
  }
  if (0 < param_4) {
    func_0x3b8406b5(pcVar8,0x30,param_4);
    pcVar8 = pcVar8 + param_4;
  }
  if (*pcVar15 == '\0') {
    pcVar8 = pcVar15;
  }
  *pcVar8 = ((param_5 == 0) - 1U & 0xe0) + 0x70;
  uVar10 = func_0xfb6c07e1();
  uVar11 = (uVar10 & 0x7ff) - local_18;
  uVar10 = (uint)((uVar10 & 0x7ff) < local_18);
  iVar6 = -uVar10;
  if (uVar10 == 0) {
    pcVar8[1] = '+';
  }
  else {
    pcVar8[1] = '-';
    bVar16 = uVar11 != 0;
    uVar11 = -uVar11;
    iVar6 = -(iVar6 + (uint)bVar16);
  }
  pcVar14 = pcVar8 + 2;
  *pcVar14 = '0';
  pcVar15 = pcVar14;
  if ((iVar6 < 0) || ((iVar6 < 1 && (uVar11 < 1000)))) {
LAB_00420580:
    if ((-1 < iVar6) && ((0 < iVar6 || (99 < uVar11)))) goto LAB_0042058b;
  }
  else {
    cVar2 = func_0x1b6c0826(uVar11,iVar6,1000,0);
    *pcVar14 = cVar2 + '0';
    pcVar15 = pcVar8 + 3;
    iVar6 = 0;
    uVar11 = extraout_ECX_00;
    if (pcVar15 == pcVar14) goto LAB_00420580;
LAB_0042058b:
    cVar2 = func_0x1b6c084c(uVar11,iVar6,100,0);
    *pcVar15 = cVar2 + '0';
    pcVar15 = pcVar15 + 1;
    iVar6 = 0;
    uVar11 = extraout_ECX_01;
  }
  if ((pcVar15 != pcVar14) || ((-1 < iVar6 && ((0 < iVar6 || (9 < uVar11)))))) {
    cVar2 = func_0x1b6c0872(uVar11,iVar6,10,0);
    *pcVar15 = cVar2 + '0';
    pcVar15 = pcVar15 + 1;
    uVar11 = extraout_ECX_02;
  }
  *pcVar15 = (char)uVar11 + '0';
  pcVar15[1] = '\0';
LAB_004205d1:
  if (local_1c != '\0') {
    *(uint *)(local_20 + 0x70) = *(uint *)(local_20 + 0x70) & 0xfffffffd;
  }
  return 0;
}



// WARNING: Control flow encountered bad instruction data
// Library Function - Single Match
//  __cftof2_l
// 
// Libraries: Visual Studio 2005 Release, Visual Studio 2008 Release

undefined4 __thiscall __cftof2_l(void *this,int param_1,int param_2,char param_3,undefined4 param_4)

{
  int iVar1;
  int *in_EAX;
  undefined4 *puVar2;
  undefined *puVar3;
  int local_14;
  int local_c;
  char local_8;
  
  iVar1 = in_EAX[1];
  func_0x127107b9(param_4);
  if ((this != (void *)0x0) && (param_1 != 0)) {
    if ((param_3 != '\0') && (iVar1 + -1 == param_2)) {
      puVar3 = (undefined *)((uint)(*in_EAX == 0x2d) + iVar1 + -1 + (int)this);
      *puVar3 = 0x30;
      puVar3[1] = 0;
    }
    if (*in_EAX == 0x2d) {
      *(undefined *)this = 0x2d;
      this = (void *)((int)this + 1);
    }
    if (in_EAX[1] < 1) {
      func_0xc631082c();
      *(undefined *)this = 0x30;
      puVar3 = (undefined *)((int)this + 1);
    }
    else {
      puVar3 = (undefined *)((int)this + in_EAX[1]);
    }
    if (0 < param_2) {
      func_0xc6310841();
      *puVar3 = *(undefined *)**(undefined4 **)(local_14 + 0xbc);
      iVar1 = in_EAX[1];
      if (iVar1 < 0) {
        if ((param_3 != '\0') || (SBORROW4(param_2,-iVar1) == param_2 + iVar1 < 0)) {
          param_2 = -iVar1;
        }
        func_0xc6310872();
        func_0x3b84087b(puVar3 + 1,0x30,param_2);
      }
    }
    if (local_8 != '\0') {
      *(uint *)(local_c + 0x70) = *(uint *)(local_c + 0x70) & 0xfffffffd;
    }
    return 0;
  }
  puVar2 = (undefined4 *)func_0x788707c2();
  *puVar2 = 0x16;
  func_0x53ab07d3(0,0,0,0,0);
  if (local_8 != '\0') {
    *(uint *)(local_c + 0x70) = *(uint *)(local_c + 0x70) & 0xfffffffd;
  }
                    // WARNING: Bad instruction - Truncating control flow here
  halt_baddata();
}



// Library Function - Single Match
//  __cftof_l
// 
// Libraries: Visual Studio 2005 Release, Visual Studio 2008 Release

void __cdecl
__cftof_l(undefined4 *param_1,undefined *param_2,int param_3,int param_4,undefined4 param_5)

{
  undefined4 *puVar1;
  int iVar2;
  int local_30;
  int local_2c;
  undefined local_20 [24];
  uint local_8;
  
  local_8 = DAT_00431c20 ^ (uint)&stack0xfffffffc;
  func_0x7c6b09c3(*param_1,param_1[1],&local_30,local_20,0x16);
  if ((param_2 == (undefined *)0x0) || (param_3 == 0)) {
    puVar1 = (undefined4 *)func_0x788708d1();
    *puVar1 = 0x16;
    func_0x53ab08dd(0,0,0,0,0);
  }
  else {
    if (param_3 == -1) {
      iVar2 = -1;
    }
    else {
      iVar2 = param_3 - (uint)(local_30 == 0x2d);
    }
    iVar2 = func_0x006a0a1e(param_2 + (local_30 == 0x2d),iVar2,local_2c + param_4,&local_30);
    if (iVar2 == 0) {
      func_0xdd37093b(param_3,param_4,0,param_5);
    }
    else {
      *param_2 = 0;
    }
  }
  func_0x4860094b();
  return;
}



// WARNING: Control flow encountered bad instruction data
// Library Function - Single Match
//  __cftog_l
// 
// Library: Visual Studio 2008 Release

void __cdecl
__cftog_l(undefined4 *param_1,undefined *param_2,int param_3,int param_4,undefined4 param_5,
         undefined4 param_6)

{
  char *pcVar1;
  undefined4 *puVar2;
  int iVar3;
  char *pcVar4;
  int local_34;
  int local_30;
  int local_24;
  undefined local_20 [24];
  uint local_8;
  
  local_8 = DAT_00431c20 ^ (uint)&stack0xfffffffc;
  func_0x7c6b0a7e(*param_1,param_1[1],&local_34,local_20,0x16);
  if ((param_2 != (undefined *)0x0) && (param_3 != 0)) {
    local_24 = local_30 + -1;
    if (param_3 == -1) {
      iVar3 = -1;
    }
    else {
      iVar3 = param_3 - (uint)(local_34 == 0x2d);
    }
    iVar3 = func_0x006a0ad5(param_2 + (local_34 == 0x2d),iVar3,param_4,&local_34);
    if (iVar3 == 0) {
      local_30 = local_30 + -1;
      if ((local_30 < -4) || (param_4 <= local_30)) {
        func_0x0b320a35(param_3,param_4,param_5,&local_34,1,param_6);
      }
      else {
        pcVar1 = param_2 + (local_34 == 0x2d);
        if (local_24 < local_30) {
          do {
            pcVar4 = pcVar1;
            pcVar1 = pcVar4 + 1;
          } while (*pcVar4 != '\0');
          pcVar4[-1] = '\0';
        }
        func_0xdd370a17(param_3,param_4,1,param_6);
      }
    }
    else {
      *param_2 = 0;
    }
    func_0x48600a45();
    return;
  }
  puVar2 = (undefined4 *)func_0x7887098c();
  *puVar2 = 0x16;
  func_0x53ab0998(0,0,0,0,0);
                    // WARNING: Bad instruction - Truncating control flow here
  halt_baddata();
}



// Library Function - Single Match
//  __cfltcvt_l
// 
// Libraries: Visual Studio 2005 Release, Visual Studio 2008 Release, Visual Studio 2010 Release,
// Visual Studio 2012 Release

errno_t __cdecl
__cfltcvt_l(double *arg,char *buffer,size_t sizeInBytes,int format,int precision,int caps,
           _locale_t plocinfo)

{
  errno_t eVar1;
  
  if ((format == 0x65) || (format == 0x45)) {
    eVar1 = func_0x7a330aca(arg,buffer,sizeInBytes,precision,caps,plocinfo);
  }
  else {
    if (format == 0x66) {
      eVar1 = func_0xd4380a72(arg,buffer,sizeInBytes,precision,plocinfo);
      return eVar1;
    }
    if ((format == 0x61) || (format == 0x41)) {
      eVar1 = func_0x6a340ab1(arg,buffer,sizeInBytes,precision,caps,plocinfo);
    }
    else {
      eVar1 = func_0x8f390a98(arg,buffer,sizeInBytes,precision,caps,plocinfo);
    }
  }
  return eVar1;
}



void __cdecl
FUN_00420919(undefined4 param_1,undefined4 param_2,undefined4 param_3,undefined4 param_4,
            undefined4 param_5,undefined4 param_6)

{
  func_0x893a0aed(param_1,param_2,param_3,param_4,param_5,param_6,0);
  return;
}



// WARNING: Globals starting with '_' overlap smaller symbols at the same address
// Library Function - Single Match
//  __ms_p5_test_fdiv
// 
// Libraries: Visual Studio 2005 Release, Visual Studio 2008 Release

undefined4 __ms_p5_test_fdiv(void)

{
  double dVar1;
  
  dVar1 = ram0x0042a5b8 - (ram0x0042a5b8 / ram0x0042a5c0) * ram0x0042a5c0;
  if (1.0 < dVar1 != NAN(dVar1)) {
    return 1;
  }
  return 0;
}



// WARNING: Globals starting with '_' overlap smaller symbols at the same address

void __cdecl FUN_004209ef(undefined4 param_1)

{
  _DAT_004359e0 = param_1;
  _DAT_004359e4 = param_1;
  _DAT_004359e8 = param_1;
  _DAT_004359ec = param_1;
  return;
}



// Library Function - Single Match
//  _siglookup
// 
// Libraries: Visual Studio 2008 Release, Visual Studio 2010 Release

uint __fastcall _siglookup(undefined4 param_1,int param_2,uint param_3)

{
  uint uVar1;
  
  uVar1 = param_3;
  do {
    if (*(int *)(uVar1 + 4) == param_2) break;
    uVar1 = uVar1 + 0xc;
  } while (uVar1 < DAT_004329ac * 0xc + param_3);
  if ((DAT_004329ac * 0xc + param_3 <= uVar1) || (*(int *)(uVar1 + 4) != param_2)) {
    uVar1 = 0;
  }
  return uVar1;
}



// WARNING: Globals starting with '_' overlap smaller symbols at the same address

void __cdecl FUN_00420c01(undefined4 param_1)

{
  _DAT_004359f4 = param_1;
  return;
}



// WARNING: Globals starting with '_' overlap smaller symbols at the same address

void __cdecl FUN_00420c10(undefined4 param_1)

{
  _DAT_004359f8 = param_1;
  return;
}



// WARNING: Control flow encountered bad instruction data
// Library Function - Single Match
//  __tsopen_nolock
// 
// Library: Visual Studio 2008 Release

undefined4 __cdecl
__tsopen_nolock(undefined4 *param_1,undefined4 param_2,uint param_3,int param_4,byte param_5)

{
  byte *pbVar1;
  byte bVar2;
  code *pcVar3;
  uint *in_EAX;
  int iVar4;
  uint uVar5;
  undefined4 *puVar6;
  undefined4 uVar7;
  int *piVar8;
  int iVar9;
  byte bVar10;
  bool bVar11;
  longlong lVar12;
  undefined8 uVar13;
  undefined4 local_38;
  undefined4 local_34;
  uint local_30;
  undefined4 local_28;
  uint local_24;
  int local_20;
  uint local_1c;
  uint local_18;
  uint local_14;
  uint local_10;
  uint local_c;
  byte local_7;
  byte local_6;
  byte local_5;
  
  bVar11 = (param_3 & 0x80) == 0;
  local_24 = 0;
  local_6 = 0;
  local_38 = 0xc;
  local_34 = 0;
  if (bVar11) {
    local_5 = 0;
  }
  else {
    local_5 = 0x10;
  }
  local_30 = (uint)bVar11;
  iVar4 = func_0x177010d4(&local_24);
  if (iVar4 != 0) {
    func_0x2baa0fe3(0,0,0,0,0);
  }
  if (((param_3 & 0x8000) == 0) && (((param_3 & 0x74000) != 0 || (local_24 != 0x8000)))) {
    local_5 = local_5 | 0x80;
  }
  uVar5 = param_3 & 3;
  if (uVar5 == 0) {
    local_c = 0x80000000;
  }
  else {
    if (uVar5 == 1) {
      if (((param_3 & 8) == 0) || ((param_3 & 0x70000) == 0)) {
        local_c = 0x40000000;
        goto LAB_00420eaa;
      }
    }
    else if (uVar5 != 2) goto LAB_00420e66;
    local_c = 0xc0000000;
  }
LAB_00420eaa:
  if (param_4 == 0x10) {
    local_14 = 0;
  }
  else if (param_4 == 0x20) {
    local_14 = 1;
  }
  else if (param_4 == 0x30) {
    local_14 = 2;
  }
  else if (param_4 == 0x40) {
    local_14 = 3;
  }
  else {
    if (param_4 != 0x80) goto LAB_00420e66;
    local_14 = (uint)(local_c == 0x80000000);
  }
  uVar5 = param_3 & 0x700;
  if (uVar5 < 0x401) {
    if ((uVar5 == 0x400) || (uVar5 == 0)) {
      local_18 = 3;
    }
    else if (uVar5 == 0x100) {
      local_18 = 4;
    }
    else {
      if (uVar5 == 0x200) goto LAB_00420faf;
      if (uVar5 != 0x300) goto LAB_00420e66;
      local_18 = 2;
    }
  }
  else {
    if (uVar5 != 0x500) {
      if (uVar5 == 0x600) {
LAB_00420faf:
        local_18 = 5;
        goto LAB_00420f5e;
      }
      if (uVar5 != 0x700) {
LAB_00420e66:
        puVar6 = (undefined4 *)func_0x8b871021();
        *puVar6 = 0;
        *in_EAX = 0xffffffff;
        puVar6 = (undefined4 *)func_0x7887102b();
        *puVar6 = 0x16;
        func_0x53ab103a(0,0,0,0,0);
                    // WARNING: Bad instruction - Truncating control flow here
        halt_baddata();
      }
    }
    local_18 = 1;
  }
LAB_00420f5e:
  local_10 = 0x80;
  if (((param_3 & 0x100) != 0) && (-1 < (char)(~(byte)DAT_00434f8c & param_5))) {
    local_10 = 1;
  }
  if ((param_3 & 0x40) != 0) {
    local_10 = local_10 | 0x4000000;
    local_c = local_c | 0x10000;
    local_14 = local_14 | 4;
  }
  if ((param_3 & 0x1000) != 0) {
    local_10 = local_10 | 0x100;
  }
  if ((param_3 & 0x20) == 0) {
    if ((param_3 & 0x10) != 0) {
      local_10 = local_10 | 0x10000000;
    }
  }
  else {
    local_10 = local_10 | 0x8000000;
  }
  uVar5 = func_0x0a4f127e();
  *in_EAX = uVar5;
  pcVar3 = DAT_00428210;
  if (uVar5 == 0xffffffff) {
    puVar6 = (undefined4 *)func_0x8b87118a();
    *puVar6 = 0;
    *in_EAX = 0xffffffff;
    puVar6 = (undefined4 *)func_0x78871194();
    *puVar6 = 0x18;
                    // WARNING: Bad instruction - Truncating control flow here
    halt_baddata();
  }
  *param_1 = 1;
  local_20 = (*pcVar3)(param_2,local_c,local_14,&local_38,local_18,local_10,0);
  if (local_20 == -1) {
    if (((local_c & 0xc0000000) == 0xc0000000) && ((param_3 & 1) != 0)) {
      local_c = local_c & 0x7fffffff;
      local_20 = (*pcVar3)(param_2,local_c,local_14,&local_38,local_18,local_10,0);
      if (local_20 != -1) goto LAB_00421083;
    }
    pbVar1 = (byte *)((&DAT_00436d80)[(int)*in_EAX >> 5] + 4 + (*in_EAX & 0x1f) * 0x40);
    *pbVar1 = *pbVar1 & 0xfe;
    uVar7 = (*DAT_004281cc)();
    func_0x9e87122c(uVar7);
LAB_00421077:
    func_0x78871232();
                    // WARNING: Bad instruction - Truncating control flow here
    halt_baddata();
  }
LAB_00421083:
  iVar4 = (*DAT_00428100)(local_20);
  if (iVar4 == 0) {
    pbVar1 = (byte *)((&DAT_00436d80)[(int)*in_EAX >> 5] + 4 + (*in_EAX & 0x1f) * 0x40);
    *pbVar1 = *pbVar1 & 0xfe;
    iVar4 = (*DAT_004281cc)();
    func_0x9e87126f(iVar4);
    (*DAT_00428224)(local_20);
    if (iVar4 == 0) {
      puVar6 = (undefined4 *)func_0x78871282();
      *puVar6 = 0xd;
    }
    goto LAB_00421077;
  }
  if (iVar4 == 2) {
    local_5 = local_5 | 0x40;
  }
  else if (iVar4 == 3) {
    local_5 = local_5 | 8;
  }
  func_0xc54c13a8(*in_EAX,local_20);
  bVar10 = local_5 | 1;
  *(byte *)((&DAT_00436d80)[(int)*in_EAX >> 5] + 4 + (*in_EAX & 0x1f) * 0x40) = bVar10;
  pbVar1 = (byte *)((&DAT_00436d80)[(int)*in_EAX >> 5] + 0x24 + (*in_EAX & 0x1f) * 0x40);
  *pbVar1 = *pbVar1 & 0x80;
  local_7 = local_5 & 0x48;
  if (local_7 == 0) {
    bVar2 = local_5 & 0x80;
    local_5 = bVar10;
    if (bVar2 == 0) goto LAB_004213f8;
    if ((param_3 & 2) != 0) {
      local_1c = func_0x60d2130f(*in_EAX,0xffffffff,2);
      if (local_1c == 0xffffffff) {
        piVar8 = (int *)func_0x8b87131e();
        bVar10 = local_5;
        if (*piVar8 != 0x83) goto LAB_00421170;
      }
      else {
        local_28 = 0;
        iVar4 = func_0x61bb1342(*in_EAX,&local_28,1);
        if ((iVar4 == 0) && ((short)local_28 == 0x1a)) {
          iVar4 = func_0xa56d145d(*in_EAX,local_1c,(int)local_1c >> 0x1f);
          if (iVar4 == -1) goto LAB_00421170;
        }
        iVar4 = func_0x60d2136d(*in_EAX,0,0);
        bVar10 = local_5;
        if (iVar4 == -1) goto LAB_00421170;
      }
    }
  }
  local_5 = bVar10;
  if ((local_5 & 0x80) == 0) goto LAB_004213f8;
  if ((param_3 & 0x74000) == 0) {
    if ((local_24 & 0x74000) == 0) {
      param_3 = param_3 | 0x4000;
    }
    else {
      param_3 = param_3 | local_24 & 0x74000;
    }
  }
  uVar5 = param_3 & 0x74000;
  if (uVar5 == 0x4000) {
    local_6 = 0;
  }
  else if ((uVar5 == 0x10000) || (uVar5 == 0x14000)) {
    if ((param_3 & 0x301) == 0x301) goto LAB_0042122d;
  }
  else if ((uVar5 == 0x20000) || (uVar5 == 0x24000)) {
LAB_0042122d:
    local_6 = 2;
  }
  else if ((uVar5 == 0x40000) || (uVar5 == 0x44000)) {
    local_6 = 1;
  }
  if (((param_3 & 0x70000) == 0) || (local_1c = 0, (local_5 & 0x40) != 0)) goto LAB_004213f8;
  uVar5 = local_c & 0xc0000000;
  if (uVar5 == 0x40000000) {
    if (local_18 == 0) goto LAB_004213f8;
    if (2 < local_18) {
      if (local_18 < 5) {
        lVar12 = func_0x274b15fa(*in_EAX,0,0,2);
        if (lVar12 != 0) {
          uVar13 = func_0x274b160f(*in_EAX,0,0,0);
          uVar5 = (uint)uVar13 & (uint)((ulonglong)uVar13 >> 0x20);
          goto LAB_0042135e;
        }
      }
      else {
LAB_00421289:
        if (local_18 != 5) goto LAB_004213f8;
      }
    }
LAB_00421292:
    iVar4 = 0;
    if (local_6 == 1) {
      local_1c = 0xb2bfc1b6;
      local_18 = 3;
      do {
        iVar9 = FUN_00419c1f();
        if (iVar9 == -1) goto LAB_00421170;
        iVar4 = iVar4 + iVar9;
      } while (iVar4 < (int)local_18);
    }
    else if (local_6 == 2) {
                    // WARNING: Bad instruction - Truncating control flow here
      halt_baddata();
    }
  }
  else {
    if (uVar5 != 0x80000000) {
      if ((uVar5 != 0xc0000000) || (local_18 == 0)) goto LAB_004213f8;
      if (2 < local_18) {
        if (4 < local_18) goto LAB_00421289;
        lVar12 = func_0x274b157a(*in_EAX,0,0,2);
        if (lVar12 != 0) {
          lVar12 = func_0x274b158b(*in_EAX,0,0,0);
          if (lVar12 == -1) goto LAB_00421170;
          goto LAB_004212e3;
        }
      }
      goto LAB_00421292;
    }
LAB_004212e3:
    iVar4 = __read_nolock(*in_EAX,&local_1c,3);
    if (iVar4 == -1) goto LAB_00421170;
    if (iVar4 == 2) {
LAB_0042136c:
      if ((local_1c & 0xffff) == 0xfffe) {
        func_0x52c21538(*in_EAX);
        puVar6 = (undefined4 *)func_0x7887153e();
        *puVar6 = 0x16;
                    // WARNING: Bad instruction - Truncating control flow here
        halt_baddata();
      }
      if ((local_1c & 0xffff) == 0xfeff) {
        iVar4 = func_0x60d2155b(*in_EAX,2,0);
        if (iVar4 == -1) {
LAB_00421170:
          func_0x52c2132d(*in_EAX);
                    // WARNING: Bad instruction - Truncating control flow here
          halt_baddata();
        }
        local_6 = 2;
        goto LAB_004213f8;
      }
    }
    else if (iVar4 == 3) {
      if (local_1c == 0xf7bec1b6) {
                    // WARNING: Bad instruction - Truncating control flow here
        halt_baddata();
      }
      goto LAB_0042136c;
    }
    uVar5 = func_0x60d21576(*in_EAX,0,0);
LAB_0042135e:
    if (uVar5 == 0xffffffff) {
                    // WARNING: Bad instruction - Truncating control flow here
      halt_baddata();
    }
  }
LAB_004213f8:
  uVar5 = local_c;
  pbVar1 = (byte *)((&DAT_00436d80)[(int)*in_EAX >> 5] + 0x24 + (*in_EAX & 0x1f) * 0x40);
  *pbVar1 = *pbVar1 ^ (*pbVar1 ^ local_6) & 0x7f;
  pbVar1 = (byte *)((&DAT_00436d80)[(int)*in_EAX >> 5] + 0x24 + (*in_EAX & 0x1f) * 0x40);
  *pbVar1 = (char)(param_3 >> 0x10) << 7 | *pbVar1 & 0x7f;
  if ((local_7 == 0) && ((param_3 & 8) != 0)) {
    pbVar1 = (byte *)((&DAT_00436d80)[(int)*in_EAX >> 5] + 4 + (*in_EAX & 0x1f) * 0x40);
    *pbVar1 = *pbVar1 | 0x20;
  }
  if (((local_c & 0xc0000000) == 0xc0000000) && ((param_3 & 1) != 0)) {
    (*DAT_00428224)(local_20);
    iVar4 = (*DAT_00428210)(param_2,uVar5 & 0x7fffffff,local_14,&local_38,3,local_10,0);
    if (iVar4 == -1) {
      uVar7 = (*DAT_004281cc)();
      func_0x9e87166d(uVar7);
      pbVar1 = (byte *)((&DAT_00436d80)[(int)*in_EAX >> 5] + 4 + (*in_EAX & 0x1f) * 0x40);
      *pbVar1 = *pbVar1 & 0xfe;
      func_0x464d178f(*in_EAX);
                    // WARNING: Bad instruction - Truncating control flow here
      halt_baddata();
    }
    *(int *)((*in_EAX & 0x1f) * 0x40 + (&DAT_00436d80)[(int)*in_EAX >> 5]) = iVar4;
  }
  return 0;
}



void __cdecl
FUN_004215c9(undefined4 param_1,undefined4 param_2,undefined4 param_3,undefined4 param_4,
            undefined4 param_5)

{
  func_0xf446189a(param_2,param_3,param_4,param_5,param_1,1);
  return;
}



// WARNING: Control flow encountered bad instruction data
// Library Function - Single Match
//  __wcsnicmp_l
// 
// Library: Visual Studio 2008 Release

int __cdecl __wcsnicmp_l(wchar_t *_Str1,wchar_t *_Str2,size_t _MaxCount,_locale_t _Locale)

{
  wchar_t wVar1;
  wchar_t wVar2;
  ushort uVar3;
  ushort uVar4;
  int iVar5;
  undefined4 *puVar6;
  uint uVar7;
  uint uVar8;
  int local_14 [2];
  int local_c;
  char local_8;
  
  iVar5 = 0;
  if (_MaxCount != 0) {
    if ((_Str1 == (wchar_t *)0x0) || (_Str2 == (wchar_t *)0x0)) {
      puVar6 = (undefined4 *)func_0x788717c3();
      *puVar6 = 0x16;
      func_0x53ab17d3(0,0,0,0,0);
                    // WARNING: Bad instruction - Truncating control flow here
      halt_baddata();
    }
    func_0x127117f2(_Locale);
    if (*(int *)(local_14[0] + 0x14) == 0) {
      do {
        wVar1 = *_Str1;
        if ((0x40 < (ushort)wVar1) && ((ushort)wVar1 < 0x5b)) {
          wVar1 = wVar1 + L' ';
        }
        uVar8 = (uint)(ushort)wVar1;
        wVar2 = *_Str2;
        if ((0x40 < (ushort)wVar2) && ((ushort)wVar2 < 0x5b)) {
          wVar2 = wVar2 + L' ';
        }
        _Str1 = _Str1 + 1;
        _Str2 = _Str2 + 1;
        _MaxCount = _MaxCount - 1;
        uVar7 = (uint)(ushort)wVar2;
      } while (((_MaxCount != 0) && (wVar1 != L'\0')) && (wVar1 == wVar2));
    }
    else {
      do {
        uVar3 = func_0x50701946(*_Str1,local_14);
        uVar8 = (uint)uVar3;
        uVar4 = func_0x50701956(*_Str2,local_14);
        _Str1 = _Str1 + 1;
        _Str2 = _Str2 + 1;
        _MaxCount = _MaxCount - 1;
        uVar7 = (uint)uVar4;
        if ((_MaxCount == 0) || (uVar3 == 0)) break;
      } while (uVar3 == uVar4);
    }
    iVar5 = uVar8 - uVar7;
    if (local_8 != '\0') {
      *(uint *)(local_c + 0x70) = *(uint *)(local_c + 0x70) & 0xfffffffd;
    }
  }
  return iVar5;
}



// Library Function - Single Match
//  __wcsnicmp
// 
// Library: Visual Studio 2008 Release

int __cdecl __wcsnicmp(wchar_t *_Str1,wchar_t *_Str2,size_t _MaxCount)

{
  wchar_t wVar1;
  wchar_t wVar2;
  int iVar3;
  undefined4 *puVar4;
  
  if (DAT_00435790 == 0) {
    iVar3 = 0;
    if (_MaxCount != 0) {
      if ((_Str1 == (wchar_t *)0x0) || (_Str2 == (wchar_t *)0x0)) {
        puVar4 = (undefined4 *)func_0x788718b1();
        *puVar4 = 0x16;
        func_0x53ab18c1(0,0,0,0,0);
        iVar3 = 0x7fffffff;
      }
      else {
        do {
          wVar1 = *_Str1;
          if ((0x40 < (ushort)wVar1) && ((ushort)wVar1 < 0x5b)) {
            wVar1 = wVar1 + L' ';
          }
          wVar2 = *_Str2;
          if ((0x40 < (ushort)wVar2) && ((ushort)wVar2 < 0x5b)) {
            wVar2 = wVar2 + L' ';
          }
          _Str1 = _Str1 + 1;
          _Str2 = _Str2 + 1;
          _MaxCount = _MaxCount - 1;
        } while (((_MaxCount != 0) && (wVar1 != L'\0')) && (wVar1 == wVar2));
        iVar3 = (uint)(ushort)wVar1 - (uint)(ushort)wVar2;
      }
    }
  }
  else {
    iVar3 = func_0xe0471a28(_Str1,_Str2,_MaxCount,0);
  }
  return iVar3;
}



// Library Function - Single Match
//  _wcsncmp
// 
// Libraries: Visual Studio 2005 Release, Visual Studio 2008 Release

int __cdecl _wcsncmp(wchar_t *_Str1,wchar_t *_Str2,size_t _MaxCount)

{
  if (_MaxCount != 0) {
    for (; ((_MaxCount = _MaxCount - 1, _MaxCount != 0 && (*_Str1 != L'\0')) && (*_Str1 == *_Str2));
        _Str1 = _Str1 + 1) {
      _Str2 = _Str2 + 1;
    }
    return (uint)(ushort)*_Str1 - (uint)(ushort)*_Str2;
  }
  return 0;
}



// Library Function - Single Match
//  __global_unwind2
// 
// Library: Visual Studio

void __cdecl __global_unwind2(undefined4 param_1)

{
  func_0x6f991a7e(param_1,0x4217c4,0,0,&stack0xfffffffc);
  return;
}



// Library Function - Single Match
//  __local_unwind2
// 
// Library: Visual Studio

void __cdecl __local_unwind2(int param_1,uint param_2)

{
  uint uVar1;
  uint uVar2;
  void *local_20;
  undefined4 uStack_1c;
  undefined4 local_18;
  int iStack_14;
  
  iStack_14 = param_1;
  uStack_1c = 0x4217cc;
  local_20 = ExceptionList;
  uVar2 = DAT_00431c20 ^ (uint)&local_20;
  ExceptionList = &local_20;
  while( true ) {
    uVar1 = *(uint *)(param_1 + 0xc);
    if ((uVar1 == 0xffffffff) || ((param_2 != 0xffffffff && (uVar1 <= param_2)))) break;
    local_18 = *(undefined4 *)(*(int *)(param_1 + 8) + uVar1 * 0xc);
    *(undefined4 *)(param_1 + 0xc) = local_18;
    if (*(int *)(*(int *)(param_1 + 8) + 4 + uVar1 * 0xc) == 0) {
      func_0xbc4a1b32(0x101,uVar2);
      func_0xdb4a1b3b();
    }
  }
  ExceptionList = local_20;
  return;
}



// WARNING: Globals starting with '_' overlap smaller symbols at the same address
// Library Function - Single Match
//  __getbuf
// 
// Libraries: Visual Studio 2008 Release, Visual Studio 2010 Release

void __cdecl __getbuf(FILE *_File)

{
  char *pcVar1;
  
  _DAT_004352f8 = _DAT_004352f8 + 1;
  pcVar1 = (char *)func_0x3f2d1ab2(0x1000);
  _File->_base = pcVar1;
  if (pcVar1 == (char *)0x0) {
    _File->_flag = _File->_flag | 4;
    _File->_base = (char *)&_File->_charbuf;
    _File->_bufsiz = 2;
  }
  else {
    _File->_flag = _File->_flag | 8;
    _File->_bufsiz = 0x1000;
  }
  _File->_cnt = 0;
  _File->_ptr = _File->_base;
  return;
}



// WARNING: Globals starting with '_' overlap smaller symbols at the same address
// Library Function - Single Match
//  __lseeki64_nolock
// 
// Library: Visual Studio 2008 Release

longlong __cdecl __lseeki64_nolock(int _FileHandle,longlong _Offset,int _Origin)

{
  byte *pbVar1;
  int iVar2;
  undefined4 *puVar3;
  int iVar4;
  undefined4 in_stack_00000008;
  undefined4 local_8;
  
  local_8 = (undefined4)_Offset;
  iVar2 = func_0xcc4d1c04(_FileHandle);
  if (iVar2 == -1) {
    puVar3 = (undefined4 *)func_0x78871b11();
    *puVar3 = 9;
LAB_00421961:
    iVar2 = -1;
    local_8 = 0xffffffff;
  }
  else {
    iVar2 = (*ram0x004281c8)(iVar2,in_stack_00000008,&local_8,_Offset._4_4_);
    if (iVar2 == -1) {
      iVar4 = (*DAT_004281cc)();
      if (iVar4 != 0) {
        func_0x9e871b45(iVar4);
        goto LAB_00421961;
      }
    }
    pbVar1 = (byte *)((&DAT_00436d80)[_FileHandle >> 5] + 4 + (_FileHandle & 0x1fU) * 0x40);
    *pbVar1 = *pbVar1 & 0xfd;
  }
  return CONCAT44(local_8,iVar2);
}



// Library Function - Single Match
//  __set_osfhnd
// 
// Library: Visual Studio 2008 Release

int __cdecl __set_osfhnd(int param_1,intptr_t param_2)

{
  undefined4 *puVar1;
  int iVar2;
  undefined4 uVar3;
  
  if ((-1 < param_1) && ((uint)param_1 < DAT_00436d68)) {
    iVar2 = (param_1 & 0x1fU) * 0x40;
    if (*(int *)(iVar2 + (&DAT_00436d80)[param_1 >> 5]) == -1) {
      if (DAT_00431c1c == 1) {
        if (param_1 == 0) {
          uVar3 = 0xfffffff6;
        }
        else if (param_1 == 1) {
          uVar3 = 0xfffffff5;
        }
        else {
          if (param_1 != 2) goto LAB_00421b2b;
          uVar3 = 0xfffffff4;
        }
        (*DAT_0042813c)(uVar3,param_2);
      }
LAB_00421b2b:
      *(intptr_t *)(iVar2 + (&DAT_00436d80)[param_1 >> 5]) = param_2;
      return 0;
    }
  }
  puVar1 = (undefined4 *)func_0x78871cf0();
  *puVar1 = 9;
  puVar1 = (undefined4 *)func_0x8b871cfb();
  *puVar1 = 0;
  return -1;
}



// Library Function - Single Match
//  __free_osfhnd
// 
// Library: Visual Studio 2008 Release

int __cdecl __free_osfhnd(int param_1)

{
  int *piVar1;
  undefined4 *puVar2;
  int iVar3;
  undefined4 uVar4;
  
  if ((-1 < param_1) && ((uint)param_1 < DAT_00436d68)) {
    iVar3 = (param_1 & 0x1fU) * 0x40;
    piVar1 = (int *)((&DAT_00436d80)[param_1 >> 5] + iVar3);
    if (((*(byte *)(piVar1 + 1) & 1) != 0) && (*piVar1 != -1)) {
      if (DAT_00431c1c == 1) {
        if (param_1 == 0) {
          uVar4 = 0xfffffff6;
        }
        else if (param_1 == 1) {
          uVar4 = 0xfffffff5;
        }
        else {
          if (param_1 != 2) goto LAB_00421bb1;
          uVar4 = 0xfffffff4;
        }
        (*DAT_0042813c)(uVar4,0);
      }
LAB_00421bb1:
      *(undefined4 *)(iVar3 + (&DAT_00436d80)[param_1 >> 5]) = 0xffffffff;
      return 0;
    }
  }
  puVar2 = (undefined4 *)func_0x78871d76();
  *puVar2 = 9;
  puVar2 = (undefined4 *)func_0x8b871d81();
  *puVar2 = 0;
  return -1;
}



// Library Function - Single Match
//  __get_osfhandle
// 
// Library: Visual Studio 2008 Release

intptr_t __cdecl __get_osfhandle(int _FileHandle)

{
  undefined4 *puVar1;
  intptr_t *piVar2;
  intptr_t iVar3;
  
  if (_FileHandle == -2) {
    puVar1 = (undefined4 *)func_0x8b871d9d();
    *puVar1 = 0;
    puVar1 = (undefined4 *)func_0x78871da5();
    *puVar1 = 9;
    return -1;
  }
  if (((_FileHandle < 0) || (DAT_00436d68 <= (uint)_FileHandle)) ||
     (piVar2 = (intptr_t *)((_FileHandle & 0x1fU) * 0x40 + (&DAT_00436d80)[_FileHandle >> 5]),
     (*(byte *)(piVar2 + 1) & 1) == 0)) {
    puVar1 = (undefined4 *)func_0x8b871dde();
    *puVar1 = 0;
    puVar1 = (undefined4 *)func_0x78871de5();
    *puVar1 = 9;
    func_0x53ab1df5(0,0,0,0,0);
    iVar3 = -1;
  }
  else {
    iVar3 = *piVar2;
  }
  return iVar3;
}



void __cdecl FUN_00421cec(uint param_1)

{
  (*(code *)u_f__dd_vctools_vc7libs_ship_atlmf_0042815f._65_4_)
            ((&DAT_00436d80)[(int)param_1 >> 5] + 0xc + (param_1 & 0x1f) * 0x40);
  return;
}



// Library Function - Single Match
//  __isatty
// 
// Library: Visual Studio 2008 Release

int __cdecl __isatty(int _FileHandle)

{
  undefined4 *puVar1;
  uint uVar2;
  
  if (_FileHandle == -2) {
    puVar1 = (undefined4 *)func_0x78872156();
    *puVar1 = 9;
    return 0;
  }
  if ((_FileHandle < 0) || (DAT_00436d68 <= (uint)_FileHandle)) {
    puVar1 = (undefined4 *)func_0x78872174();
    *puVar1 = 9;
    func_0x53ab2184(0,0,0,0,0);
    uVar2 = 0;
  }
  else {
    uVar2 = (int)*(char *)((&DAT_00436d80)[_FileHandle >> 5] + 4 + (_FileHandle & 0x1fU) * 0x40) &
            0x40;
  }
  return uVar2;
}



// Library Function - Single Match
//  __putwch_nolock
// 
// Library: Visual Studio 2008 Release

wint_t __cdecl __putwch_nolock(wchar_t _WCh)

{
  wint_t wVar1;
  int iVar2;
  undefined4 uVar3;
  undefined local_14 [4];
  undefined local_10 [8];
  uint local_8;
  
  local_8 = DAT_00431c20 ^ (uint)&stack0xfffffffc;
  if (DAT_00432b50 != 0) {
    if (DAT_00432c84 == -2) {
      func_0x057122d3();
    }
    if (DAT_00432c84 == -1) goto LAB_0042209e;
    iVar2 = (*DAT_00428148)(DAT_00432c84,&_WCh,1,local_14,0);
    if (iVar2 != 0) {
      DAT_00432b50 = 1;
      goto LAB_0042209e;
    }
    if ((DAT_00432b50 != 2) || (iVar2 = (*DAT_004281cc)(), iVar2 != 0x78)) goto LAB_0042209e;
    DAT_00432b50 = 0;
  }
  uVar3 = (*DAT_00428144)(0,&_WCh,1,local_10,5,0,0);
  uVar3 = (*(code *)u_f__dd_vctools_vc7libs_ship_atlmf_0042815f._89_4_)(uVar3);
  if (DAT_00432c84 != -1) {
    (*DAT_00428140)(DAT_00432c84,local_10,uVar3,local_14,0);
  }
LAB_0042209e:
  wVar1 = func_0x4860225f();
  return wVar1;
}



// WARNING: Control flow encountered bad instruction data
// Library Function - Single Match
//  __mbtowc_l
// 
// Library: Visual Studio 2008 Release

int __cdecl __mbtowc_l(wchar_t *_DstCh,char *_SrcCh,size_t _SrcSizeInBytes,_locale_t _Locale)

{
  int iVar1;
  undefined4 *puVar2;
  int local_14 [2];
  int local_c;
  char local_8;
  
  if ((_SrcCh != (char *)0x0) && (_SrcSizeInBytes != 0)) {
    if (*_SrcCh != '\0') {
      func_0x127122a6(_Locale);
      if (*(int *)(local_14[0] + 0x14) == 0) {
        if (_DstCh != (wchar_t *)0x0) {
          *_DstCh = (ushort)(byte)*_SrcCh;
        }
LAB_00422106:
        if (local_8 != '\0') {
          *(uint *)(local_c + 0x70) = *(uint *)(local_c + 0x70) & 0xfffffffd;
        }
        return 1;
      }
      iVar1 = func_0xdf5323da(*_SrcCh,local_14);
      if (iVar1 == 0) {
        iVar1 = (*DAT_004281f0)(*(undefined4 *)(local_14[0] + 4),9,_SrcCh,1,_DstCh,
                                _DstCh != (wchar_t *)0x0);
        if (iVar1 != 0) goto LAB_00422106;
      }
      else {
        iVar1 = *(int *)(local_14[0] + 0xac);
        if ((((1 < iVar1) && (iVar1 <= (int)_SrcSizeInBytes)) &&
            (iVar1 = (*DAT_004281f0)(*(undefined4 *)(local_14[0] + 4),9,_SrcCh,iVar1,_DstCh,
                                     _DstCh != (wchar_t *)0x0), iVar1 != 0)) ||
           ((*(uint *)(local_14[0] + 0xac) <= _SrcSizeInBytes && (_SrcCh[1] != '\0')))) {
          if (local_8 == '\0') {
            return *(int *)(local_14[0] + 0xac);
          }
          *(uint *)(local_c + 0x70) = *(uint *)(local_c + 0x70) & 0xfffffffd;
                    // WARNING: Bad instruction - Truncating control flow here
          halt_baddata();
        }
      }
      puVar2 = (undefined4 *)func_0x78872343();
      *puVar2 = 0x2a;
      if (local_8 != '\0') {
        *(uint *)(local_c + 0x70) = *(uint *)(local_c + 0x70) & 0xfffffffd;
      }
                    // WARNING: Bad instruction - Truncating control flow here
      halt_baddata();
    }
    if (_DstCh != (wchar_t *)0x0) {
      *_DstCh = L'\0';
    }
  }
  return 0;
}



void __cdecl FUN_004221ce(undefined4 param_1,undefined4 param_2,undefined4 param_3)

{
  func_0xae522499(param_1,param_2,param_3,0);
  return;
}



// Library Function - Single Match
//  __isleadbyte_l
// 
// Libraries: Visual Studio 2005 Release, Visual Studio 2008 Release, Visual Studio 2010 Release

int __cdecl __isleadbyte_l(int _C,_locale_t _Locale)

{
  ushort uVar1;
  int local_14;
  int local_c;
  char local_8;
  
  func_0x127123b1(_Locale);
  uVar1 = *(ushort *)(*(int *)(local_14 + 200) + (_C & 0xffU) * 2);
  if (local_8 != '\0') {
    *(uint *)(local_c + 0x70) = *(uint *)(local_c + 0x70) & 0xfffffffd;
  }
  return uVar1 & 0x8000;
}



void __cdecl FUN_00422220(undefined4 param_1)

{
  func_0xdf5324e5(param_1,0);
  return;
}



// Library Function - Multiple Matches With Different Base Names
//  ___crtMessageBoxA
//  ___crtMessageBoxW
// 
// Library: Visual Studio 2008 Release

int __cdecl FID_conflict____crtMessageBoxW(LPCSTR _LpText,LPCSTR _LpCaption,UINT _UType)

{
  int iVar1;
  int iVar2;
  int iVar3;
  undefined4 uVar4;
  undefined4 uVar5;
  code *pcVar6;
  code *pcVar7;
  undefined local_18 [8];
  byte local_10;
  undefined local_c [4];
  int local_8;
  
  iVar1 = func_0xebab23f9();
  local_8 = 0;
  if (DAT_00435abc == 0) {
    iVar2 = (*DAT_0042809c)(&DAT_0042a694);
    uVar5 = u_f__dd_vctools_vc7libs_ship_atlmf_0042815f._5_4_;
    if (iVar2 == 0) {
      return 0;
    }
    iVar3 = (*(code *)u_f__dd_vctools_vc7libs_ship_atlmf_0042815f._5_4_)(iVar2,&DAT_0042a688);
    if (iVar3 == 0) {
      return 0;
    }
    DAT_00435abc = func_0x79ab243d(iVar3);
    uVar4 = (*(code *)uVar5)(iVar2,&DAT_0042a678);
    DAT_00435ac0 = func_0x79ab2452(uVar4);
    uVar4 = (*(code *)uVar5)(iVar2,&DAT_0042a664);
    DAT_00435ac4 = func_0x79ab2467(uVar4);
    uVar4 = (*(code *)uVar5)(iVar2,&DAT_0042a648);
    DAT_00435acc = func_0x79ab247c(uVar4);
    if (DAT_00435acc != 0) {
      uVar5 = (*(code *)uVar5)(iVar2,&DAT_0042a630);
      DAT_00435ac8 = func_0x79ab2494(uVar5);
    }
  }
  if ((DAT_00435ac8 != iVar1) && (DAT_00435acc != iVar1)) {
    pcVar6 = (code *)func_0xf4ab24b1(DAT_00435ac8);
    pcVar7 = (code *)func_0xf4ab24be(DAT_00435acc);
    if (((pcVar6 != (code *)0x0) && (pcVar7 != (code *)0x0)) &&
       (((iVar2 = (*pcVar6)(), iVar2 == 0 ||
         (iVar2 = (*pcVar7)(iVar2,1,local_18,0xc,local_c), iVar2 == 0)) || ((local_10 & 1) == 0))))
    {
      _UType = _UType | 0x200000;
      goto LAB_00422375;
    }
  }
  if ((((DAT_00435ac0 != iVar1) &&
       (pcVar6 = (code *)func_0xf4ab2501(DAT_00435ac0), pcVar6 != (code *)0x0)) &&
      (local_8 = (*pcVar6)(), local_8 != 0)) &&
     ((DAT_00435ac4 != iVar1 &&
      (pcVar6 = (code *)func_0xf4ab251e(DAT_00435ac4), pcVar6 != (code *)0x0)))) {
    local_8 = (*pcVar6)(local_8);
  }
LAB_00422375:
  pcVar6 = (code *)func_0xf4ab2536(DAT_00435abc);
  if (pcVar6 == (code *)0x0) {
    return 0;
  }
  iVar1 = (*pcVar6)(local_8,_LpText,_LpCaption,_UType);
  return iVar1;
}



// WARNING: Control flow encountered bad instruction data
// Library Function - Single Match
//  _strncpy_s
// 
// Library: Visual Studio 2008 Release

errno_t __cdecl _strncpy_s(char *_Dst,rsize_t _SizeInBytes,char *_Src,rsize_t _MaxCount)

{
  char cVar1;
  undefined4 *puVar2;
  char *pcVar3;
  rsize_t rVar4;
  errno_t eVar5;
  
  if (_MaxCount == 0) {
    if (_Dst == (char *)0x0) {
      if (_SizeInBytes == 0) {
        return 0;
      }
    }
    else {
LAB_004223c2:
      if (_SizeInBytes != 0) {
        if (_MaxCount == 0) {
          *_Dst = '\0';
          return 0;
        }
        if (_Src != (char *)0x0) {
          pcVar3 = _Dst;
          rVar4 = _SizeInBytes;
          if (_MaxCount == 0xffffffff) {
            do {
              cVar1 = *_Src;
              *pcVar3 = cVar1;
              pcVar3 = pcVar3 + 1;
              _Src = _Src + 1;
              if (cVar1 == '\0') break;
              rVar4 = rVar4 - 1;
            } while (rVar4 != 0);
          }
          else {
            do {
              cVar1 = *_Src;
              *pcVar3 = cVar1;
              pcVar3 = pcVar3 + 1;
              _Src = _Src + 1;
              if ((cVar1 == '\0') || (rVar4 = rVar4 - 1, rVar4 == 0)) break;
              _MaxCount = _MaxCount - 1;
            } while (_MaxCount != 0);
            if (_MaxCount == 0) {
              *pcVar3 = '\0';
            }
          }
          if (rVar4 != 0) {
            return 0;
          }
          if (_MaxCount == 0xffffffff) {
            _Dst[_SizeInBytes - 1] = '\0';
                    // WARNING: Bad instruction - Truncating control flow here
            halt_baddata();
          }
          *_Dst = '\0';
          puVar2 = (undefined4 *)func_0x788725fe();
          eVar5 = 0x22;
          *puVar2 = 0x22;
          goto LAB_004223d3;
        }
        *_Dst = '\0';
      }
    }
  }
  else if (_Dst != (char *)0x0) goto LAB_004223c2;
  puVar2 = (undefined4 *)func_0x78872584();
  eVar5 = 0x16;
  *puVar2 = 0x16;
LAB_004223d3:
  func_0x53ab2593(0,0,0,0,0);
  return eVar5;
}



// Library Function - Single Match
//  __set_error_mode
// 
// Library: Visual Studio 2008 Release

int __cdecl __set_error_mode(int _Mode)

{
  undefined4 *puVar1;
  int iVar2;
  
  if (-1 < _Mode) {
    if (_Mode < 3) {
      iVar2 = DAT_00434f78;
      DAT_00434f78 = _Mode;
      return iVar2;
    }
    if (_Mode == 3) {
      return DAT_00434f78;
    }
  }
  puVar1 = (undefined4 *)func_0x788726c7();
  *puVar1 = 0x16;
  func_0x53ab26d7(0,0,0,0,0);
  return -1;
}



// WARNING: Control flow encountered bad instruction data
// Library Function - Single Match
//  __wctomb_s_l
// 
// Library: Visual Studio 2008 Release

errno_t __cdecl
__wctomb_s_l(int *_SizeConverted,char *_MbCh,size_t _SizeInBytes,wchar_t _WCh,_locale_t _Locale)

{
  errno_t eVar1;
  char *pcVar2;
  size_t sVar3;
  undefined4 *puVar4;
  errno_t *peVar5;
  int iVar6;
  int local_14;
  int local_c;
  char local_8;
  
  sVar3 = _SizeInBytes;
  pcVar2 = _MbCh;
  if ((_MbCh == (char *)0x0) && (_SizeInBytes != 0)) {
    if (_SizeConverted == (int *)0x0) {
      return;
    }
    *_SizeConverted = 0;
    return;
  }
  if (_SizeConverted != (int *)0x0) {
    *_SizeConverted = -1;
  }
  if (0x7fffffff < _SizeInBytes) {
    puVar4 = (undefined4 *)func_0x78872738();
    *puVar4 = 0x16;
    func_0x53ab2747(0,0,0,0,0);
    return 0x16;
  }
  func_0x12712759(_Locale);
  if (*(int *)(local_14 + 0x14) == 0) {
    if ((ushort)_WCh < 0x100) {
      if (pcVar2 != (char *)0x0) {
        if (sVar3 == 0) goto LAB_004225fb;
        *pcVar2 = (char)_WCh;
      }
      if (_SizeConverted != (int *)0x0) {
        *_SizeConverted = 1;
      }
LAB_00422636:
      if (local_8 == '\0') {
                    // WARNING: Bad instruction - Truncating control flow here
        halt_baddata();
      }
      *(uint *)(local_c + 0x70) = *(uint *)(local_c + 0x70) & 0xfffffffd;
                    // WARNING: Bad instruction - Truncating control flow here
      halt_baddata();
    }
    if ((pcVar2 != (char *)0x0) && (sVar3 != 0)) {
      func_0x3b842783(pcVar2,0,sVar3);
    }
  }
  else {
    _MbCh = (char *)0x0;
    iVar6 = (*(code *)u_f__dd_vctools_vc7libs_ship_atlmf_0042815f._89_4_)
                      (*(undefined4 *)(local_14 + 4),0,&_WCh,1,pcVar2,sVar3,0,&_MbCh);
    if (iVar6 == 0) {
      iVar6 = (*DAT_004281cc)();
      if (iVar6 == 0x7a) {
        if ((pcVar2 != (char *)0x0) && (sVar3 != 0)) {
          func_0x3b84285a(pcVar2,0,sVar3);
                    // WARNING: Bad instruction - Truncating control flow here
          halt_baddata();
        }
LAB_004225fb:
        puVar4 = (undefined4 *)func_0x788727b6();
        *puVar4 = 0x22;
        func_0x53ab27c5(0,0,0,0,0);
        if (local_8 == '\0') {
          return 0x22;
        }
        *(uint *)(local_c + 0x70) = *(uint *)(local_c + 0x70) & 0xfffffffd;
                    // WARNING: Bad instruction - Truncating control flow here
        halt_baddata();
      }
    }
    else if (_MbCh == (char *)0x0) {
      if (_SizeConverted != (int *)0x0) {
        *_SizeConverted = iVar6;
      }
      goto LAB_00422636;
    }
  }
  puVar4 = (undefined4 *)func_0x7887278b();
  *puVar4 = 0x2a;
  peVar5 = (errno_t *)func_0x78872796();
  eVar1 = *peVar5;
  if (local_8 != '\0') {
    *(uint *)(local_c + 0x70) = *(uint *)(local_c + 0x70) & 0xfffffffd;
  }
  return eVar1;
}



void __cdecl
FUN_004226ac(undefined4 param_1,undefined4 param_2,undefined4 param_3,undefined4 param_4)

{
  func_0x3757297a(param_1,param_2,param_3,param_4,0);
  return;
}



void __cdecl FUN_004226c9(int param_1)

{
  if ((param_1 != 0) && (*(int *)(param_1 + -8) == 0xdddd)) {
    func_0xc274289c((int *)(param_1 + -8));
  }
  return;
}



// WARNING: Control flow encountered bad instruction data
// Library Function - Single Match
//  int __cdecl __crtLCMapStringA_stat(struct localeinfo_struct *,unsigned long,unsigned long,char
// const *,int,char *,int,int,int)
// 
// Library: Visual Studio 2008 Release

int __cdecl
__crtLCMapStringA_stat
          (localeinfo_struct *param_1,ulong param_2,ulong param_3,char *param_4,int param_5,
          char *param_6,int param_7,int param_8,int param_9)

{
  uint uVar1;
  bool bVar2;
  code *pcVar3;
  int iVar4;
  char *pcVar5;
  uint uVar6;
  localeinfo_struct **pplVar7;
  undefined **ppuVar8;
  int *in_ECX;
  char *pcVar9;
  undefined *puStack_4c;
  undefined **ppuStack_48;
  undefined **ppuStack_44;
  uint uStack_40;
  localeinfo_struct *plStack_3c;
  ulong uStack_38;
  undefined *puStack_34;
  char **ppcStack_30;
  int iStack_2c;
  localeinfo_struct *plStack_28;
  int local_14;
  localeinfo_struct **local_10;
  uint local_c;
  uint local_8;
  
  local_8 = DAT_00431c20 ^ (uint)&stack0xfffffffc;
  if (DAT_00435ad4 == 0) {
    plStack_28 = (localeinfo_struct *)0x0;
    iStack_2c = 0;
    ppcStack_30 = (char **)0x1;
    puStack_34 = &DAT_0042a6a0;
    uStack_38 = 0x100;
    plStack_3c = (localeinfo_struct *)0x0;
    uStack_40 = 0x422721;
    iVar4 = (*DAT_00428150)();
    if (iVar4 == 0) {
      plStack_28 = (localeinfo_struct *)0x422733;
      iVar4 = (*DAT_004281cc)();
      if (iVar4 == 0x78) {
        DAT_00435ad4 = 2;
      }
    }
    else {
      DAT_00435ad4 = 1;
    }
  }
  pcVar3 = DAT_004281f0;
  pcVar5 = (char *)param_3;
  pcVar9 = param_4;
  if (0 < (int)param_4) {
    do {
      pcVar9 = pcVar9 + -1;
      if (*pcVar5 == '\0') goto LAB_0042275a;
      pcVar5 = pcVar5 + 1;
    } while (pcVar9 != (char *)0x0);
    pcVar9 = (char *)0xffffffff;
LAB_0042275a:
    pcVar5 = param_4 + -(int)pcVar9;
    bVar2 = (int)(pcVar5 + -1) < (int)param_4;
    param_4 = pcVar5 + -1;
    if (bVar2) {
      param_4 = pcVar5;
    }
  }
  if ((DAT_00435ad4 == 2) || (DAT_00435ad4 == 0)) {
    local_10 = (localeinfo_struct **)0x0;
    local_14 = 0;
    if (param_1 == (localeinfo_struct *)0x0) {
      param_1 = *(localeinfo_struct **)(*in_ECX + 0x14);
    }
    if (param_7 == 0) {
      param_7 = *(int *)(*in_ECX + 4);
    }
    plStack_28 = param_1;
    iStack_2c = 0x42294b;
    iVar4 = func_0x51712c01();
    if (iVar4 == -1) {
      return;
    }
    if (iVar4 != param_7) {
      plStack_28 = (localeinfo_struct *)0x0;
      iStack_2c = 0;
      ppcStack_30 = &param_4;
      puStack_34 = (undefined *)param_3;
      plStack_3c = (localeinfo_struct *)param_7;
      uStack_40 = 0x422976;
      uStack_38 = iVar4;
      local_10 = (localeinfo_struct **)func_0x9a712c2c();
      pcVar3 = DAT_0042814c;
      if (local_10 == (localeinfo_struct **)0x0) {
        return;
      }
      plStack_28 = (localeinfo_struct *)0x0;
      iStack_2c = 0;
      ppcStack_30 = (char **)param_4;
      uStack_38 = param_2;
      plStack_3c = param_1;
      uStack_40 = 0x422994;
      puStack_34 = (undefined *)local_10;
      local_c = (*DAT_0042814c)();
      if (local_c != 0) {
        if (((int)local_c < 1) || (0xffffffe0 < local_c)) {
          ppuVar8 = (undefined **)0x0;
        }
        else {
          uStack_40 = local_c + 8;
          if (uStack_40 < 0x401) {
            uStack_40 = 0x4229b8;
            func_0x5b732c6e();
            if (&stack0x00000000 == (undefined *)0x3c) {
              return;
            }
            plStack_3c = (localeinfo_struct *)0xcccc;
            ppuVar8 = &puStack_34;
          }
          else {
            ppuStack_44 = (undefined **)0x4229cf;
            ppuVar8 = (undefined **)func_0x676f2b85();
            if (ppuVar8 != (undefined **)0x0) {
              *ppuVar8 = (undefined *)0xdddd;
              ppuVar8 = ppuVar8 + 2;
            }
          }
        }
        if (ppuVar8 != (undefined **)0x0) {
          uStack_40 = local_c;
          ppuStack_44 = (undefined **)0x0;
          puStack_4c = (undefined *)0x4229f1;
          ppuStack_48 = ppuVar8;
          func_0x3b842ba7();
          uStack_40 = local_c;
          ppuStack_48 = (undefined **)param_4;
          puStack_4c = (undefined *)local_10;
          ppuStack_44 = ppuVar8;
          local_c = (*pcVar3)();
          if (local_c != 0) {
            local_14 = func_0x9a712cdd(iVar4,param_7,ppuVar8,&local_c,param_5,param_6);
          }
          func_0xc0582cf2(ppuVar8);
          goto LAB_00422a59;
        }
      }
                    // WARNING: Bad instruction - Truncating control flow here
      halt_baddata();
    }
    plStack_28 = (localeinfo_struct *)param_6;
    iStack_2c = param_5;
    ppcStack_30 = (char **)param_4;
    puStack_34 = (undefined *)param_3;
    uStack_38 = param_2;
    plStack_3c = param_1;
    uStack_40 = 0x422a57;
    (*DAT_0042814c)();
LAB_00422a59:
    if (local_10 != (localeinfo_struct **)0x0) {
      func_0xc2742c1c(local_10);
    }
    if ((local_14 != 0) && (param_5 != local_14)) {
      func_0xc2742c2f(local_14);
    }
    iVar4 = func_0x48602c42();
    return iVar4;
  }
  if (DAT_00435ad4 != 1) {
    return;
  }
  local_c = 0;
  if (param_7 == 0) {
    param_7 = *(int *)(*in_ECX + 4);
  }
  plStack_28 = (localeinfo_struct *)0x0;
  iStack_2c = 0;
  ppcStack_30 = (char **)param_4;
  puStack_34 = (undefined *)param_3;
  uStack_38 = (uint)(param_8 != 0) * 8 + 1;
  plStack_3c = (localeinfo_struct *)param_7;
  uStack_40 = 0x4227bb;
  uVar6 = (*DAT_004281f0)();
  if (uVar6 == 0) {
    return;
  }
  if (((int)uVar6 < 1) || (0xffffffe0 / uVar6 < 2)) {
    local_10 = (localeinfo_struct **)0x0;
  }
  else {
    uStack_40 = uVar6 * 2 + 8;
    if (uStack_40 < 0x401) {
      uStack_40 = 0x4227e3;
      pplVar7 = &plStack_3c;
      func_0x5b732a99();
      local_10 = &plStack_3c;
      if (&stack0x00000000 != (undefined *)0x3c) {
        plStack_3c = (localeinfo_struct *)0xcccc;
LAB_00422802:
        local_10 = pplVar7 + 2;
      }
    }
    else {
      ppuStack_44 = (undefined **)0x4227f7;
      pplVar7 = (localeinfo_struct **)func_0x676f29ad();
      local_10 = pplVar7;
      if (pplVar7 != (localeinfo_struct **)0x0) {
        *pplVar7 = (localeinfo_struct *)0xdddd;
        goto LAB_00422802;
      }
    }
  }
  if (local_10 == (localeinfo_struct **)0x0) {
                    // WARNING: Bad instruction - Truncating control flow here
    halt_baddata();
  }
  ppuStack_44 = (undefined **)local_10;
  ppuStack_48 = (undefined **)param_4;
  puStack_4c = (undefined *)param_3;
  uStack_40 = uVar6;
  iVar4 = (*pcVar3)();
  pcVar3 = DAT_00428150;
  if ((iVar4 != 0) && (local_c = (*DAT_00428150)(param_1,param_2,local_10,uVar6,0,0), local_c != 0))
  {
    if ((param_2 & 0x400) == 0) {
      if (((int)local_c < 1) || (0xffffffe0 / local_c < 2)) {
        ppuVar8 = (undefined **)0x0;
      }
      else {
        uVar1 = local_c * 2 + 8;
        if (uVar1 < 0x401) {
          func_0x5b732b58();
          if (&stack0x00000000 == (undefined *)0x54) goto LAB_00422912;
          ppuVar8 = &puStack_4c;
        }
        else {
          ppuVar8 = (undefined **)func_0x676f2a6f(uVar1);
          if (ppuVar8 != (undefined **)0x0) {
            *ppuVar8 = (undefined *)0xdddd;
            ppuVar8 = ppuVar8 + 2;
          }
        }
      }
      if (ppuVar8 != (undefined **)0x0) {
        iVar4 = (*DAT_00428150)(param_1,param_2,local_10,uVar6,ppuVar8,local_c);
        if (iVar4 != 0) {
          iVar4 = param_5;
          pcVar5 = param_6;
          if (param_6 == (char *)0x0) {
            iVar4 = 0;
            pcVar5 = (char *)0x0;
          }
          local_c = (*(code *)u_f__dd_vctools_vc7libs_ship_atlmf_0042815f._89_4_)
                              (param_7,0,ppuVar8,local_c,iVar4,pcVar5,0,0);
        }
        func_0xc0582bc7(ppuVar8);
      }
    }
    else if ((param_6 != (char *)0x0) && ((int)local_c <= (int)param_6)) {
      (*pcVar3)(param_1,param_2,local_10,uVar6,param_5,param_6);
                    // WARNING: Bad instruction - Truncating control flow here
      halt_baddata();
    }
  }
LAB_00422912:
  func_0xc0582bd0(local_10);
                    // WARNING: Bad instruction - Truncating control flow here
  halt_baddata();
}



// Library Function - Single Match
//  ___crtLCMapStringA
// 
// Libraries: Visual Studio 2005 Release, Visual Studio 2008 Release

int __cdecl
___crtLCMapStringA(_locale_t _Plocinfo,LPCWSTR _LocaleName,DWORD _DwMapFlag,LPCSTR _LpSrcStr,
                  int _CchSrc,LPSTR _LpDestStr,int _CchDest,int _Code_page,BOOL _BError)

{
  int iVar1;
  int local_c;
  char local_8;
  
  func_0x12712c57(_Plocinfo);
  iVar1 = func_0xe0582d77(_LocaleName,_DwMapFlag,_LpSrcStr,_CchSrc,_LpDestStr,_CchDest,_Code_page,
                          _BError);
  if (local_8 != '\0') {
    *(uint *)(local_c + 0x70) = *(uint *)(local_c + 0x70) & 0xfffffffd;
  }
  return iVar1;
}



// Library Function - Single Match
//  int __cdecl __crtGetStringTypeA_stat(struct localeinfo_struct *,unsigned long,char const
// *,int,unsigned short *,int,int,int)
// 
// Library: Visual Studio 2008 Release

int __cdecl
__crtGetStringTypeA_stat
          (localeinfo_struct *param_1,ulong param_2,char *param_3,int param_4,ushort *param_5,
          int param_6,int param_7,int param_8)

{
  uint uVar1;
  code *pcVar2;
  int iVar3;
  uint uVar4;
  ushort **ppuVar5;
  ushort *puVar6;
  int *in_ECX;
  ushort **ppuVar7;
  ushort *puVar8;
  ushort *puStack_30;
  ushort *puStack_2c;
  localeinfo_struct *plStack_28;
  char **ppcStack_24;
  char *pcStack_20;
  int **ppiStack_1c;
  int *local_c;
  uint local_8;
  
  local_8 = DAT_00431c20 ^ (uint)&stack0xfffffffc;
  local_c = in_ECX;
  if (DAT_00435ad8 == 0) {
    ppiStack_1c = &local_c;
    pcStack_20 = (char *)0x1;
    ppcStack_24 = (char **)&DAT_0042a6a0;
    plStack_28 = (localeinfo_struct *)0x1;
    puStack_2c = (ushort *)0x422b08;
    iVar3 = (*DAT_00428158)();
    if (iVar3 == 0) {
      ppiStack_1c = (int **)0x422b1a;
      iVar3 = (*DAT_004281cc)();
      if (iVar3 == 0x78) {
        ppiStack_1c = (int **)0x2;
        DAT_00435ad8 = 2;
      }
      goto LAB_00422b2e;
    }
    DAT_00435ad8 = 1;
  }
  else {
LAB_00422b2e:
    if ((DAT_00435ad8 == 2) || (DAT_00435ad8 == 0)) {
      puVar8 = (ushort *)0x0;
      if (param_6 == 0) {
        param_6 = *(int *)(*in_ECX + 0x14);
      }
      if (param_5 == (ushort *)0x0) {
        param_5 = *(ushort **)(*in_ECX + 4);
      }
      ppiStack_1c = (int **)param_6;
      pcStack_20 = (char *)0x422c2a;
      puVar6 = (ushort *)func_0x51712ee0();
      if (puVar6 != (ushort *)0xffffffff) {
        if (puVar6 != param_5) {
          ppiStack_1c = (int **)0x0;
          pcStack_20 = (char *)0x0;
          ppcStack_24 = &param_3;
          plStack_28 = (localeinfo_struct *)param_2;
          puStack_30 = param_5;
          puStack_2c = puVar6;
          puVar8 = (ushort *)func_0x9a712f01();
          param_2 = (ulong)puVar8;
          if (puVar8 == (ushort *)0x0) goto LAB_00422c7b;
        }
        ppiStack_1c = (int **)param_4;
        pcStack_20 = param_3;
        ppcStack_24 = (char **)param_2;
        plStack_28 = param_1;
        puStack_2c = (ushort *)param_6;
        puStack_30 = (ushort *)0x422c6c;
        (*DAT_00428154)();
        if (puVar8 != (ushort *)0x0) {
          puStack_30 = puVar8;
          func_0xc2742e2e();
        }
      }
      goto LAB_00422c7b;
    }
    if (DAT_00435ad8 != 1) goto LAB_00422c7b;
  }
  pcVar2 = DAT_004281f0;
  local_c = (int *)0x0;
  if (param_5 == (ushort *)0x0) {
    param_5 = *(ushort **)(*in_ECX + 4);
  }
  ppiStack_1c = (int **)0x0;
  pcStack_20 = (char *)0x0;
  ppcStack_24 = (char **)param_3;
  plStack_28 = (localeinfo_struct *)param_2;
  puStack_2c = (ushort *)((uint)(param_7 != 0) * 8 + 1);
  puStack_30 = param_5;
  uVar4 = (*DAT_004281f0)();
  if (uVar4 == 0) goto LAB_00422c7b;
  ppuVar7 = (ushort **)(undefined4 *)0x0;
  if ((0 < (int)uVar4) && (uVar4 < 0x7ffffff1)) {
    uVar1 = uVar4 * 2 + 8;
    if (uVar1 < 0x401) {
      ppuVar5 = &puStack_30;
      func_0x5b732e55();
      ppuVar7 = &puStack_30;
      if (&stack0x00000000 != (undefined *)0x30) {
        puStack_30 = (ushort *)0xcccc;
LAB_00422bbe:
        ppuVar7 = ppuVar5 + 2;
      }
    }
    else {
      ppuVar5 = (ushort **)func_0x676f2d69(uVar1);
      ppuVar7 = ppuVar5;
      if (ppuVar5 != (ushort **)0x0) {
        *ppuVar5 = (ushort *)0xdddd;
        goto LAB_00422bbe;
      }
    }
  }
  if (ppuVar7 != (ushort **)0x0) {
    func_0x3b842d89(ppuVar7,0,uVar4 * 2);
    iVar3 = (*pcVar2)(param_5,1,param_2,param_3,ppuVar7,uVar4);
    if (iVar3 != 0) {
      local_c = (int *)(*DAT_00428158)(param_1,ppuVar7,iVar3,param_4);
    }
    func_0xc0582eb6(ppuVar7);
  }
LAB_00422c7b:
  iVar3 = func_0x48602e41();
  return iVar3;
}



// Library Function - Multiple Matches With Different Base Names
//  ___crtCompareStringW
//  ___crtGetStringTypeA
//  ___crtLCMapStringW
// 
// Libraries: Visual Studio 2005 Release, Visual Studio 2008 Release

BOOL __cdecl
FID_conflict____crtCompareStringW
          (_locale_t _Plocinfo,DWORD _DWInfoType,LPCSTR _LpSrcStr,int _CchSrc,LPWORD _LpCharType,
          int _Code_page,BOOL _BError)

{
  BOOL BVar1;
  undefined4 in_stack_00000020;
  int local_c;
  char local_8;
  
  func_0x12712e56(_Plocinfo);
  BVar1 = func_0xca5c2f73(_DWInfoType,_LpSrcStr,_CchSrc,_LpCharType,_Code_page,_BError,
                          in_stack_00000020);
  if (local_8 != '\0') {
    *(uint *)(local_c + 0x70) = *(uint *)(local_c + 0x70) & 0xfffffffd;
  }
  return BVar1;
}



// Library Function - Single Match
//  ___free_lc_time
// 
// Library: Visual Studio 2008 Release

void __cdecl ___free_lc_time(undefined4 *param_1)

{
  if (param_1 != (undefined4 *)0x0) {
    func_0xc2742e9e(param_1[1]);
    func_0xc2742ea6(param_1[2]);
    func_0xc2742eae(param_1[3]);
    func_0xc2742eb6(param_1[4]);
    func_0xc2742ebe(param_1[5]);
    func_0xc2742ec6(param_1[6]);
    func_0xc2742ecd(*param_1);
    func_0xc2742ed5(param_1[8]);
    func_0xc2742edd(param_1[9]);
    func_0xc2742ee5(param_1[10]);
    func_0xc2742eed(param_1[0xb]);
    func_0xc2742ef5(param_1[0xc]);
    func_0xc2742efd(param_1[0xd]);
    func_0xc2742f05(param_1[7]);
    func_0xc2742f0d(param_1[0xe]);
    func_0xc2742f15(param_1[0xf]);
    func_0xc2742f20(param_1[0x10]);
    func_0xc2742f28(param_1[0x11]);
    func_0xc2742f30(param_1[0x12]);
    func_0xc2742f38(param_1[0x13]);
    func_0xc2742f40(param_1[0x14]);
    func_0xc2742f48(param_1[0x15]);
    func_0xc2742f50(param_1[0x16]);
    func_0xc2742f58(param_1[0x17]);
    func_0xc2742f60(param_1[0x18]);
    func_0xc2742f68(param_1[0x19]);
    func_0xc2742f70(param_1[0x1a]);
    func_0xc2742f78(param_1[0x1b]);
    func_0xc2742f80(param_1[0x1c]);
    func_0xc2742f88(param_1[0x1d]);
    func_0xc2742f90(param_1[0x1e]);
    func_0xc2742f98(param_1[0x1f]);
    func_0xc2742fa6(param_1[0x20]);
    func_0xc2742fb1(param_1[0x21]);
    func_0xc2742fbc(param_1[0x22]);
    func_0xc2742fc7(param_1[0x23]);
    func_0xc2742fd2(param_1[0x24]);
    func_0xc2742fdd(param_1[0x25]);
    func_0xc2742fe8(param_1[0x26]);
    func_0xc2742ff3(param_1[0x27]);
    func_0xc2742ffe(param_1[0x28]);
    func_0xc2743009(param_1[0x29]);
    func_0xc2743014(param_1[0x2a]);
  }
  return;
}



// Library Function - Single Match
//  ___free_lconv_num
// 
// Library: Visual Studio 2008 Release

void __cdecl ___free_lconv_num(int *param_1)

{
  if (param_1 != (int *)0x0) {
    if (*param_1 != DAT_00432c28) {
      func_0xc2743037(*param_1);
    }
    if (param_1[1] != DAT_00432c2c) {
      func_0xc2743049(param_1[1]);
    }
    if (param_1[2] != DAT_00432c30) {
      func_0xc274305b(param_1[2]);
    }
  }
  return;
}



// Library Function - Single Match
//  ___free_lconv_mon
// 
// Library: Visual Studio 2008 Release

void __cdecl ___free_lconv_mon(int param_1)

{
  if (param_1 != 0) {
    if (*(int *)(param_1 + 0xc) != DAT_00432c34) {
      func_0xc274307d(*(int *)(param_1 + 0xc));
    }
    if (*(int *)(param_1 + 0x10) != DAT_00432c38) {
      func_0xc274308f(*(int *)(param_1 + 0x10));
    }
    if (*(int *)(param_1 + 0x14) != DAT_00432c3c) {
      func_0xc27430a1(*(int *)(param_1 + 0x14));
    }
    if (*(int *)(param_1 + 0x18) != DAT_00432c40) {
      func_0xc27430b3(*(int *)(param_1 + 0x18));
    }
    if (*(int *)(param_1 + 0x1c) != DAT_00432c44) {
      func_0xc27430c5(*(int *)(param_1 + 0x1c));
    }
    if (*(int *)(param_1 + 0x20) != DAT_00432c48) {
      func_0xc27430d7(*(int *)(param_1 + 0x20));
    }
    if (*(int *)(param_1 + 0x24) != DAT_00432c4c) {
      func_0xc27430e9(*(int *)(param_1 + 0x24));
    }
  }
  return;
}



// Library Function - Single Match
//  _strcspn
// 
// Library: Visual Studio

size_t __cdecl _strcspn(char *_Str,char *_Control)

{
  byte bVar1;
  byte *pbVar2;
  size_t sVar3;
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
    bVar1 = *_Control;
    if (bVar1 == 0) break;
    _Control = (char *)((byte *)_Control + 1);
    pbVar2 = (byte *)((int)&uStack_28 + ((int)(uint)bVar1 >> 3));
    *pbVar2 = *pbVar2 | '\x01' << (bVar1 & 7);
  }
  sVar3 = 0xffffffff;
  do {
    sVar3 = sVar3 + 1;
    bVar1 = *_Str;
    if (bVar1 == 0) {
      return sVar3;
    }
    _Str = (char *)((byte *)_Str + 1);
  } while ((*(byte *)((int)&uStack_28 + ((int)(uint)bVar1 >> 3)) >> (bVar1 & 7) & 1) == 0);
  return sVar3;
}



// Library Function - Single Match
//  _strpbrk
// 
// Library: Visual Studio

char * __cdecl _strpbrk(char *_Str,char *_Control)

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
    bVar1 = *_Control;
    if (bVar1 == 0) break;
    _Control = (char *)((byte *)_Control + 1);
    pbVar2 = (byte *)((int)&uStack_28 + ((int)(uint)bVar1 >> 3));
    *pbVar2 = *pbVar2 | '\x01' << (bVar1 & 7);
  }
  do {
    pbVar2 = (byte *)_Str;
    bVar1 = *pbVar2;
    if (bVar1 == 0) {
      return (char *)(uint)bVar1;
    }
    _Str = (char *)(pbVar2 + 1);
  } while ((*(byte *)((int)&uStack_28 + ((int)(char *)(uint)bVar1 >> 3)) >> (bVar1 & 7) & 1) == 0);
  return (char *)pbVar2;
}



// Library Function - Single Match
//  ___crtGetStringTypeW
// 
// Library: Visual Studio 2008 Release

undefined4 __cdecl
___crtGetStringTypeW
          (undefined4 param_1,undefined4 param_2,undefined4 param_3,int param_4,undefined4 param_5)

{
  undefined4 uVar1;
  int local_c;
  char local_8;
  
  func_0x1271319d(param_1);
  if (param_4 < -1) {
    uVar1 = 0;
  }
  else {
    uVar1 = (*DAT_00428158)(param_2,param_3,param_4,param_5);
  }
  if (local_8 != '\0') {
    *(uint *)(local_c + 0x70) = *(uint *)(local_c + 0x70) & 0xfffffffd;
  }
  return uVar1;
}



// Library Function - Single Match
//  __fputwc_nolock
// 
// Libraries: Visual Studio 2008 Release, Visual Studio 2010 Release

wint_t __cdecl __fputwc_nolock(wchar_t _Ch,FILE *_File)

{
  int *piVar1;
  wint_t wVar2;
  int iVar3;
  uint uVar4;
  undefined *puVar5;
  undefined2 in_stack_00000006;
  int local_14;
  char local_10 [8];
  uint local_8;
  
  local_8 = DAT_00431c20 ^ (uint)&stack0xfffffffc;
  if ((*(byte *)&_File->_flag & 0x40) == 0) {
    iVar3 = func_0x20c231f0(_File);
    if ((iVar3 == -1) || (iVar3 = func_0x20c23201(_File), iVar3 == -2)) {
      puVar5 = &DAT_00432150;
    }
    else {
      iVar3 = func_0x20c2320d(_File);
      uVar4 = func_0x20c2321d(_File);
      puVar5 = (undefined *)((uVar4 & 0x1f) * 0x40 + (&DAT_00436d80)[iVar3 >> 5]);
    }
    if ((puVar5[0x24] & 0x7f) != 2) {
      iVar3 = func_0x20c2323e(_File);
      if ((iVar3 == -1) || (iVar3 = func_0x20c2324a(_File), iVar3 == -2)) {
        puVar5 = &DAT_00432150;
      }
      else {
        iVar3 = func_0x20c23256(_File);
        uVar4 = func_0x20c23266(_File);
        puVar5 = (undefined *)((uVar4 & 0x1f) * 0x40 + (&DAT_00436d80)[iVar3 >> 5]);
      }
      if ((puVar5[0x24] & 0x7f) != 1) {
        iVar3 = func_0x20c23287(_File);
        if ((iVar3 == -1) || (iVar3 = func_0x20c23293(_File), iVar3 == -2)) {
          puVar5 = &DAT_00432150;
        }
        else {
          iVar3 = func_0x20c2329f(_File);
          uVar4 = func_0x20c232af(_File);
          puVar5 = (undefined *)((uVar4 & 0x1f) * 0x40 + (&DAT_00436d80)[iVar3 >> 5]);
        }
        if ((puVar5[4] & 0x80) != 0) {
          iVar3 = func_0xa35833d5(&local_14,local_10,5,__Ch);
          if ((iVar3 == 0) && (iVar3 = 0, 0 < local_14)) {
            do {
              piVar1 = &_File->_cnt;
              *piVar1 = *piVar1 + -1;
              if (*piVar1 < 0) {
                uVar4 = func_0x7fc5330d((int)local_10[iVar3],_File);
              }
              else {
                *_File->_ptr = local_10[iVar3];
                uVar4 = (uint)(byte)*_File->_ptr;
                _File->_ptr = _File->_ptr + 1;
              }
            } while ((uVar4 != 0xffffffff) && (iVar3 = iVar3 + 1, iVar3 < local_14));
          }
          goto LAB_0042318a;
        }
      }
    }
  }
  piVar1 = &_File->_cnt;
  *piVar1 = *piVar1 + -2;
  if (*piVar1 < 0) {
    func_0x8773343e(_Ch,_File);
  }
  else {
    *(wchar_t *)_File->_ptr = _Ch;
    _File->_ptr = _File->_ptr + 2;
  }
LAB_0042318a:
  wVar2 = func_0x4860334d();
  return wVar2;
}



// WARNING: Control flow encountered bad instruction data
// Library Function - Single Match
//  unsigned long __cdecl strtoxl(struct localeinfo_struct *,char const *,char const * *,int,int)
// 
// Library: Visual Studio 2008 Release

ulong __cdecl
strtoxl(localeinfo_struct *param_1,char *param_2,char **param_3,int param_4,int param_5)

{
  ushort uVar1;
  byte *pbVar2;
  undefined4 *puVar3;
  uint uVar4;
  int iVar5;
  uint uVar6;
  int iVar7;
  byte bVar8;
  byte *pbVar9;
  int local_18 [2];
  int local_10;
  char local_c;
  ulong local_8;
  
  func_0x12713364(param_1);
  if (param_3 != (char **)0x0) {
    *param_3 = param_2;
  }
  if ((param_2 == (char *)0x0) || ((param_4 != 0 && ((param_4 < 2 || (0x24 < param_4)))))) {
    puVar3 = (undefined4 *)func_0x7887337b();
    *puVar3 = 0x16;
    func_0x53ab338b(0,0,0,0,0);
    if (local_c != '\0') {
      *(uint *)(local_10 + 0x70) = *(uint *)(local_10 + 0x70) & 0xfffffffd;
    }
                    // WARNING: Bad instruction - Truncating control flow here
    halt_baddata();
  }
  bVar8 = *param_2;
  local_8 = 0;
  iVar5 = local_18[0];
  pbVar2 = (byte *)param_2;
  while( true ) {
    pbVar9 = pbVar2 + 1;
    if (*(int *)(iVar5 + 0xac) < 2) {
      uVar4 = *(ushort *)(*(int *)(iVar5 + 200) + (uint)bVar8 * 2) & 8;
    }
    else {
      uVar4 = func_0xfb7434d7(bVar8,8,local_18);
      iVar5 = local_18[0];
    }
    if (uVar4 == 0) break;
    bVar8 = *pbVar9;
    pbVar2 = pbVar9;
  }
  if (bVar8 == 0x2d) {
    param_5 = param_5 | 2;
LAB_00423252:
    bVar8 = *pbVar9;
    pbVar9 = pbVar2 + 2;
  }
  else if (bVar8 == 0x2b) goto LAB_00423252;
  if (((param_4 < 0) || (param_4 == 1)) || (0x24 < param_4)) {
    if (param_3 != (char **)0x0) {
      *param_3 = param_2;
    }
    if (local_c != '\0') {
      *(uint *)(local_10 + 0x70) = *(uint *)(local_10 + 0x70) & 0xfffffffd;
    }
    return 0;
  }
  if (param_4 == 0) {
    if (bVar8 != 0x30) {
      param_4 = 10;
      goto LAB_004232b8;
    }
    if ((*pbVar9 != 0x78) && (*pbVar9 != 0x58)) {
      param_4 = 8;
      goto LAB_004232b8;
    }
    param_4 = 0x10;
  }
  else if ((param_4 != 0x10) || (bVar8 != 0x30)) goto LAB_004232b8;
  if ((*pbVar9 == 0x78) || (*pbVar9 == 0x58)) {
    bVar8 = pbVar9[1];
    pbVar9 = pbVar9 + 2;
  }
LAB_004232b8:
  uVar4 = (uint)(0xffffffff / (ulonglong)(uint)param_4);
  do {
    uVar1 = *(ushort *)(*(int *)(iVar5 + 200) + (uint)bVar8 * 2);
    if ((uVar1 & 4) == 0) {
      if ((uVar1 & 0x103) == 0) {
LAB_00423315:
        pbVar9 = pbVar9 + -1;
        if ((param_5 & 8U) == 0) {
          if (param_3 != (char **)0x0) {
            pbVar9 = (byte *)param_2;
          }
          local_8 = 0;
        }
        else if (((param_5 & 4U) != 0) ||
                (((param_5 & 1U) == 0 &&
                 ((((param_5 & 2U) != 0 && (0x80000000 < local_8)) ||
                  (((param_5 & 2U) == 0 && (0x7fffffff < local_8)))))))) {
          puVar3 = (undefined4 *)func_0x7887351c();
          *puVar3 = 0x22;
          if ((param_5 & 1U) == 0) {
            local_8 = ((param_5 & 2U) != 0) + 0x7fffffff;
          }
          else {
            local_8 = 0xffffffff;
          }
        }
        if (param_3 != (char **)0x0) {
          *param_3 = (char *)pbVar9;
        }
        if ((param_5 & 2U) != 0) {
          local_8 = -local_8;
        }
        if (local_c == '\0') {
          return local_8;
        }
        *(uint *)(local_10 + 0x70) = *(uint *)(local_10 + 0x70) & 0xfffffffd;
        return local_8;
      }
      iVar7 = (int)(char)bVar8;
      if ((byte)(bVar8 + 0x9f) < 0x1a) {
        iVar7 = iVar7 + -0x20;
      }
      uVar6 = iVar7 - 0x37;
    }
    else {
      uVar6 = (int)(char)bVar8 - 0x30;
    }
    if ((uint)param_4 <= uVar6) goto LAB_00423315;
    if ((local_8 < uVar4) ||
       ((local_8 == uVar4 && (uVar6 <= (uint)(0xffffffff % (ulonglong)(uint)param_4))))) {
      local_8 = local_8 * param_4 + uVar6;
      param_5 = param_5 | 8;
    }
    else {
      param_5 = param_5 | 0xc;
      if (param_3 == (char **)0x0) goto LAB_00423315;
    }
    bVar8 = *pbVar9;
    pbVar9 = pbVar9 + 1;
  } while( true );
}



void __cdecl FUN_004233c8(undefined4 param_1,undefined4 param_2,undefined4 param_3)

{
  undefined *puVar1;
  
  if (DAT_00435790 == 0) {
    puVar1 = &DAT_00432988;
  }
  else {
    puVar1 = (undefined *)0x0;
  }
  func_0x906336a4(puVar1,param_1,param_2,param_3,0);
  return;
}



// Library Function - Single Match
//  public: __thiscall std::exception::exception(char const * const &)
// 
// Library: Visual Studio 2008 Release

exception * __thiscall std::exception::exception(exception *this,char **param_1)

{
  int iVar1;
  int iVar2;
  
  *(undefined **)this = &DAT_0042b6fc;
  if (*param_1 == (char *)0x0) {
    *(undefined4 *)(this + 4) = 0;
  }
  else {
    iVar1 = func_0x4b5636c8(*param_1);
    iVar2 = func_0x676f35d1(iVar1 + 1);
    *(int *)(this + 4) = iVar2;
    if (iVar2 != 0) {
      func_0x317035e3(iVar2,iVar1 + 1,*param_1);
    }
  }
  *(undefined4 *)(this + 8) = 1;
  return this;
}



// Library Function - Single Match
//  public: __thiscall std::exception::exception(class std::exception const &)
// 
// Library: Visual Studio 2008 Release

exception * __thiscall std::exception::exception(exception *this,exception *param_1)

{
  int iVar1;
  int iVar2;
  
  *(undefined **)this = &DAT_0042b6fc;
  iVar1 = *(int *)(param_1 + 8);
  *(int *)(this + 8) = iVar1;
  iVar2 = *(int *)(param_1 + 4);
  if (iVar1 == 0) {
    *(int *)(this + 4) = iVar2;
  }
  else if (iVar2 == 0) {
    *(undefined4 *)(this + 4) = 0;
  }
  else {
    iVar1 = func_0x4b563726(iVar2);
    iVar2 = func_0x676f362f(iVar1 + 1);
    *(int *)(this + 4) = iVar2;
    if (iVar2 != 0) {
      func_0x31703642(iVar2,iVar1 + 1,*(undefined4 *)(param_1 + 4));
    }
  }
  return this;
}



void * __thiscall FUN_004234c6(void *this,byte param_1)

{
  func_0x9a663789();
  if ((param_1 & 1) != 0) {
    func_0x15bc3595(this);
  }
  return this;
}



bool __cdecl FUN_004234e7(int param_1)

{
  return param_1 != 0;
}



// Library Function - Single Match
//  __isdigit_l
// 
// Libraries: Visual Studio 2008 Release, Visual Studio 2010 Release

int __cdecl __isdigit_l(int _C,_locale_t _Locale)

{
  uint uVar1;
  int local_14 [2];
  int local_c;
  char local_8;
  
  func_0x127136c2(_Locale);
  if (*(int *)(local_14[0] + 0xac) < 2) {
    uVar1 = *(ushort *)(*(int *)(local_14[0] + 200) + _C * 2) & 4;
  }
  else {
    uVar1 = func_0xfb7437dc(_C,4,local_14);
  }
  if (local_8 != '\0') {
    *(uint *)(local_c + 0x70) = *(uint *)(local_c + 0x70) & 0xfffffffd;
  }
  return uVar1;
}



// Library Function - Single Match
//  _isdigit
// 
// Libraries: Visual Studio 2008 Release, Visual Studio 2010 Release

int __cdecl _isdigit(int _C)

{
  int iVar1;
  
  if (DAT_00435790 == 0) {
    return *(ushort *)(DAT_00432970 + _C * 2) & 4;
  }
  iVar1 = func_0xf066382a(_C,0);
  return iVar1;
}



// WARNING: Control flow encountered bad instruction data
// WARNING: Globals starting with '_' overlap smaller symbols at the same address

ushort __cdecl FUN_00423578(uint param_1,localeinfo_struct *param_2)

{
  char cVar1;
  ushort uVar2;
  int iVar3;
  undefined4 *puVar4;
  char *extraout_ECX;
  CHAR CVar5;
  int unaff_EDI;
  float10 extraout_ST0;
  undefined8 uVar6;
  localeinfo_struct local_1c;
  int local_14;
  char local_10;
  byte local_c;
  undefined local_b;
  CHAR local_8;
  CHAR local_7;
  undefined local_6;
  
  uVar6 = _LocaleUpdate::_LocaleUpdate((_LocaleUpdate *)&local_1c,param_2);
  if (param_1 < 0x100) {
    *(short *)CONCAT22((short)((ulonglong)uVar6 >> 0x30),
                       CONCAT11(0xae,(char)((ulonglong)uVar6 >> 0x20))) = (short)ROUND(extraout_ST0)
    ;
    *(char *)uVar6 = *(char *)uVar6 + (char)uVar6;
    _DAT_00000114 = _DAT_00000114 + unaff_EDI;
    iVar3 = func_0xfb743867(param_1,1,&local_1c);
    if (iVar3 != 0) {
                    // WARNING: Bad instruction - Truncating control flow here
      halt_baddata();
    }
    goto LAB_004235d9;
  }
  cVar1 = *extraout_ECX;
  *extraout_ECX = *extraout_ECX + (char)local_1c.locinfo;
  CVar5 = (CHAR)param_1;
  if (*extraout_ECX == '\0' || SCARRY1(cVar1,(char)local_1c.locinfo) != *extraout_ECX < '\0') {
LAB_0042362a:
    puVar4 = (undefined4 *)func_0x788737e5();
    *puVar4 = 0x2a;
    local_7 = '\0';
    iVar3 = 1;
    local_8 = CVar5;
  }
  else {
    iVar3 = func_0xdf5338c8((int)param_1 >> 8 & 0xff,&local_1c);
    if (iVar3 == 0) goto LAB_0042362a;
    param_1._0_1_ = (CHAR)(param_1 >> 8);
    local_8 = (CHAR)param_1;
    local_6 = 0;
    iVar3 = 2;
    local_7 = CVar5;
  }
  iVar3 = ___crtLCMapStringA(&local_1c,(local_1c.locinfo)->lc_category[0].wlocale,0x100,&local_8,
                             iVar3,(LPSTR)&local_c,3,(local_1c.locinfo)->lc_codepage,1);
  if (iVar3 != 0) {
    uVar2 = (ushort)local_c;
    if (iVar3 != 1) {
      uVar2 = CONCAT11(local_c,local_b);
    }
    if (local_10 != '\0') {
      *(uint *)(local_14 + 0x70) = *(uint *)(local_14 + 0x70) & 0xfffffffd;
    }
    return uVar2;
  }
LAB_004235d9:
  if (local_10 != '\0') {
    *(uint *)(local_14 + 0x70) = *(uint *)(local_14 + 0x70) & 0xfffffffd;
  }
                    // WARNING: Bad instruction - Truncating control flow here
  halt_baddata();
}



// Library Function - Single Match
//  _tolower
// 
// Libraries: Visual Studio 2008 Release, Visual Studio 2010 Release

int __cdecl _tolower(int _C)

{
  if (DAT_00435790 == 0) {
    if (_C - 0x41U < 0x1a) {
      return _C + 0x20;
    }
  }
  else {
    _C = func_0x6f67396b(_C,0);
  }
  return _C;
}



// Library Function - Multiple Matches With Different Base Names
//  __atodbl_l
//  __atoflt_l
// 
// Libraries: Visual Studio 2005 Release, Visual Studio 2008 Release, Visual Studio 2010 Release

int __cdecl FID_conflict___atoflt_l(_CRT_FLOAT *_Result,char *_Str,_locale_t _Locale)

{
  int iVar1;
  undefined local_2c [4];
  undefined local_28 [8];
  int local_20;
  char local_1c;
  uint local_18;
  undefined local_14 [12];
  uint local_8;
  
  local_8 = DAT_00431c20 ^ (uint)&stack0xfffffffc;
  func_0x12713895(_Locale);
  local_18 = func_0x3b8039ad(local_14,local_2c,_Str,0,0,0,0,local_28);
  iVar1 = func_0xb37539ba(local_14,_Result);
  if ((local_18 & 3) == 0) {
    if (iVar1 == 1) {
LAB_00423712:
      if (local_1c != '\0') {
        *(uint *)(local_20 + 0x70) = *(uint *)(local_20 + 0x70) & 0xfffffffd;
      }
      goto LAB_00423752;
    }
    if (iVar1 != 2) {
LAB_00423744:
      if (local_1c != '\0') {
        *(uint *)(local_20 + 0x70) = *(uint *)(local_20 + 0x70) & 0xfffffffd;
      }
      goto LAB_00423752;
    }
  }
  else if ((local_18 & 1) == 0) {
    if ((local_18 & 2) == 0) goto LAB_00423744;
    goto LAB_00423712;
  }
  if (local_1c != '\0') {
    *(uint *)(local_20 + 0x70) = *(uint *)(local_20 + 0x70) & 0xfffffffd;
  }
LAB_00423752:
  iVar1 = func_0x48603915();
  return iVar1;
}



// Library Function - Multiple Matches With Different Base Names
//  __atodbl_l
//  __atoflt_l
// 
// Libraries: Visual Studio 2005 Release, Visual Studio 2008 Release, Visual Studio 2010 Release

int __cdecl FID_conflict___atoflt_l(_CRT_FLOAT *_Result,char *_Str,_locale_t _Locale)

{
  int iVar1;
  undefined local_2c [4];
  undefined local_28 [8];
  int local_20;
  char local_1c;
  uint local_18;
  undefined local_14 [12];
  uint local_8;
  
  local_8 = DAT_00431c20 ^ (uint)&stack0xfffffffc;
  func_0x1271393d(_Locale);
  local_18 = func_0x3b803a55(local_14,local_2c,_Str,0,0,0,0,local_28);
  iVar1 = func_0xf77a3a62(local_14,_Result);
  if ((local_18 & 3) == 0) {
    if (iVar1 == 1) {
LAB_004237ba:
      if (local_1c != '\0') {
        *(uint *)(local_20 + 0x70) = *(uint *)(local_20 + 0x70) & 0xfffffffd;
      }
      goto LAB_004237fa;
    }
    if (iVar1 != 2) {
LAB_004237ec:
      if (local_1c != '\0') {
        *(uint *)(local_20 + 0x70) = *(uint *)(local_20 + 0x70) & 0xfffffffd;
      }
      goto LAB_004237fa;
    }
  }
  else if ((local_18 & 1) == 0) {
    if ((local_18 & 2) == 0) goto LAB_004237ec;
    goto LAB_004237ba;
  }
  if (local_1c != '\0') {
    *(uint *)(local_20 + 0x70) = *(uint *)(local_20 + 0x70) & 0xfffffffd;
  }
LAB_004237fa:
  iVar1 = func_0x486039bd();
  return iVar1;
}



// WARNING: Control flow encountered bad instruction data
// Library Function - Single Match
//  __fptostr
// 
// Library: Visual Studio 2008 Release

errno_t __cdecl __fptostr(char *_Buf,size_t _SizeInBytes,int _Digits,STRFLT _PtFlt)

{
  undefined4 *puVar1;
  char *pcVar2;
  int iVar3;
  char cVar4;
  char *pcVar5;
  
  pcVar5 = _PtFlt->mantissa;
  if ((_Buf == (char *)0x0) || (_SizeInBytes == 0)) {
    puVar1 = (undefined4 *)func_0x788739db();
    *puVar1 = 0x16;
  }
  else {
    *_Buf = '\0';
    iVar3 = _Digits;
    if (_Digits < 1) {
      iVar3 = 0;
    }
    if (iVar3 + 1U < _SizeInBytes) {
      *_Buf = '0';
      pcVar2 = _Buf + 1;
      if (0 < _Digits) {
        do {
          cVar4 = *pcVar5;
          if (cVar4 == '\0') {
            cVar4 = '0';
          }
          else {
            pcVar5 = pcVar5 + 1;
          }
          *pcVar2 = cVar4;
          pcVar2 = pcVar2 + 1;
          _Digits = _Digits + -1;
        } while (0 < _Digits);
      }
      *pcVar2 = '\0';
      if ((-1 < _Digits) && ('4' < *pcVar5)) {
        while (pcVar2 = pcVar2 + -1, *pcVar2 == '9') {
          *pcVar2 = '0';
        }
        *pcVar2 = *pcVar2 + '\x01';
      }
      if (*_Buf == '1') {
        _PtFlt->decpt = _PtFlt->decpt + 1;
      }
      else {
        iVar3 = func_0x4b563b6b(_Buf + 1);
        func_0x8b613a74(_Buf,_Buf + 1,iVar3 + 1);
      }
      return 0;
    }
    puVar1 = (undefined4 *)func_0x78873a13();
    *puVar1 = 0x22;
  }
  func_0x53ab39ea(0,0,0,0,0);
                    // WARNING: Bad instruction - Truncating control flow here
  halt_baddata();
}



// Library Function - Single Match
//  ___dtold
// 
// Library: Visual Studio 2008 Release

void __cdecl ___dtold(uint *param_1,uint *param_2)

{
  uint uVar1;
  ushort uVar2;
  ushort uVar3;
  ushort uVar4;
  uint local_8;
  
  uVar2 = *(ushort *)((int)param_2 + 6) >> 4;
  uVar4 = *(ushort *)((int)param_2 + 6) & 0x8000;
  uVar3 = uVar2 & 0x7ff;
  uVar1 = *param_2;
  local_8 = 0x80000000;
  if ((uVar2 & 0x7ff) == 0) {
    if (((param_2[1] & 0xfffff) == 0) && (uVar1 == 0)) {
      param_1[1] = 0;
      *param_1 = 0;
      goto LAB_0042397c;
    }
    uVar3 = uVar3 + 0x3c01;
    local_8 = 0;
  }
  else if (uVar3 == 0x7ff) {
    uVar3 = 0x7fff;
  }
  else {
    uVar3 = uVar3 + 0x3c00;
  }
  param_1[1] = uVar1 >> 0x15 | (param_2[1] & 0xfffff) << 0xb | local_8;
  *param_1 = uVar1 << 0xb;
  while (local_8 == 0) {
    uVar1 = param_1[1];
    uVar3 = uVar3 - 1;
    param_1[1] = uVar1 * 2 | *param_1 >> 0x1f;
    *param_1 = *param_1 * 2;
    local_8 = uVar1 * 2 & 0x80000000;
  }
  uVar4 = uVar4 | uVar3;
LAB_0042397c:
  *(ushort *)(param_1 + 2) = uVar4;
  return;
}



// Library Function - Single Match
//  __fltout2
// 
// Libraries: Visual Studio 2005 Release, Visual Studio 2008 Release

STRFLT __cdecl __fltout2(_CRT_DOUBLE _Dbl,STRFLT _Flt,char *_ResultStr,size_t _SizeInBytes)

{
  int iVar1;
  STRFLT p_Var2;
  undefined4 in_stack_ffffffb0;
  undefined2 uVar3;
  short local_30;
  char local_2e;
  undefined local_2c [24];
  undefined4 local_14;
  undefined4 uStack_10;
  undefined2 uStack_c;
  uint local_8;
  
  uVar3 = (undefined2)((uint)in_stack_ffffffb0 >> 0x10);
  local_8 = DAT_00431c20 ^ (uint)&stack0xfffffffc;
  func_0xbf6a3c66(&local_14,&_Dbl);
  iVar1 = func_0x33873c81(local_14,uStack_10,CONCAT22(uVar3,uStack_c),0x11,0,&local_30);
  _Flt->flag = iVar1;
  _Flt->sign = (int)local_2e;
  _Flt->decpt = (int)local_30;
  iVar1 = func_0x31703ba1(_ResultStr,_SizeInBytes,local_2c);
  if (iVar1 != 0) {
    func_0x2baa3bb4(0,0,0,0,0);
  }
  _Flt->mantissa = _ResultStr;
  p_Var2 = (STRFLT)func_0x48603bc9();
  return p_Var2;
}



// Library Function - Single Match
//  __controlfp_s
// 
// Library: Visual Studio 2008 Release

errno_t __cdecl __controlfp_s(uint *_CurrentState,uint _NewValue,uint _Mask)

{
  uint uVar1;
  undefined4 *puVar2;
  errno_t eVar3;
  
  if ((_NewValue & _Mask & 0xfff7ffff & 0xfcf0fce0) == 0) {
    if (_CurrentState == (uint *)0x0) {
      func_0x85913e47(_NewValue,_Mask & 0xfff7ffff);
    }
    else {
      uVar1 = func_0x85913e3e();
      *_CurrentState = uVar1;
    }
    eVar3 = 0;
  }
  else {
    if (_CurrentState != (uint *)0x0) {
      uVar1 = func_0x85913e0e(0,0);
      *_CurrentState = uVar1;
    }
    puVar2 = (undefined4 *)func_0x78873d17();
    eVar3 = 0x16;
    *puVar2 = 0x16;
    func_0x53ab3d26(0,0,0,0,0);
  }
  return eVar3;
}



void __cdecl FUN_00423b98(undefined4 param_1)

{
  func_0xbf653e5f(param_1,0,10);
  return;
}



// WARNING: Control flow encountered bad instruction data
// Library Function - Single Match
//  __chsize_nolock
// 
// Library: Visual Studio 2008 Release

int __cdecl __chsize_nolock(int _FileHandle,longlong _Size)

{
  int iVar1;
  undefined4 uVar2;
  int iVar3;
  undefined4 *puVar4;
  int *piVar5;
  uint uVar6;
  uint uVar7;
  int unaff_EDI;
  int iVar8;
  bool bVar9;
  bool bVar10;
  ulonglong uVar11;
  longlong lVar12;
  uint in_stack_00000008;
  
  uVar11 = func_0x274b3e83(_FileHandle,0,0,1);
  if (uVar11 != 0xffffffffffffffff) {
    lVar12 = func_0x274b3e9f(_FileHandle,0,0,2);
    iVar3 = (int)((ulonglong)lVar12 >> 0x20);
    if (lVar12 != -1) {
      uVar7 = in_stack_00000008 - (uint)lVar12;
      uVar6 = (uint)(in_stack_00000008 < (uint)lVar12);
      iVar1 = (int)_Size - iVar3;
      iVar8 = iVar1 - uVar6;
      if ((iVar8 < 0) ||
         ((iVar8 == 0 || (SBORROW4((int)_Size,iVar3) != SBORROW4(iVar1,uVar6)) != iVar8 < 0 &&
          (uVar7 == 0)))) {
        if ((iVar8 < 1) && (iVar8 < 0)) {
          lVar12 = func_0x274b3f9a(_FileHandle,in_stack_00000008,(int)_Size,0);
          if (lVar12 == -1) goto LAB_00423c36;
          uVar2 = func_0xcc4d3fb0(_FileHandle);
          iVar3 = (*DAT_004280b8)(uVar2);
          uVar6 = (iVar3 != 0) - 1;
          if ((uVar6 & (int)uVar6 >> 0x1f) == 0xffffffff) {
            puVar4 = (undefined4 *)func_0x78873ed2();
            *puVar4 = 0xd;
            puVar4 = (undefined4 *)func_0x8b873edd();
            uVar2 = (*DAT_004281cc)();
            *puVar4 = uVar2;
            if ((uVar6 & (int)uVar6 >> 0x1f) == 0xffffffff) goto LAB_00423c36;
          }
        }
        lVar12 = __lseeki64_nolock(_FileHandle,uVar11 >> 0x20,unaff_EDI);
        if (lVar12 != -1) {
                    // WARNING: Bad instruction - Truncating control flow here
          halt_baddata();
        }
      }
      else {
        uVar2 = (*(code *)u_f__dd_vctools_vc7libs_ship_atlmf_0042815f._1_4_)(8,0x1000);
        iVar3 = (*DAT_004280c4)(uVar2);
        if (iVar3 != 0) {
          uVar2 = func_0x5b6f3f05(_FileHandle,0x8000);
          while( true ) {
            uVar6 = uVar7;
            if ((-1 < iVar8) && ((0 < iVar8 || (0xfff < uVar7)))) {
              uVar6 = 0x1000;
            }
            uVar6 = func_0xe3c63e26(_FileHandle,iVar3,uVar6);
            if (uVar6 == 0xffffffff) break;
            bVar9 = uVar7 < uVar6;
            uVar7 = uVar7 - uVar6;
            bVar10 = SBORROW4(iVar8,(int)uVar6 >> 0x1f);
            iVar1 = iVar8 - ((int)uVar6 >> 0x1f);
            iVar8 = iVar1 - (uint)bVar9;
            if ((iVar8 < 0) ||
               ((iVar8 == 0 || (bVar10 != SBORROW4(iVar1,(uint)bVar9)) != iVar8 < 0 && (uVar7 == 0))
               )) goto LAB_00423c88;
          }
          piVar5 = (int *)func_0x8b873e69();
          if (*piVar5 == 5) {
            puVar4 = (undefined4 *)func_0x78873e73();
            *puVar4 = 0xd;
          }
LAB_00423c88:
          func_0x5b6f3f49(_FileHandle,uVar2);
          uVar2 = (*(code *)u_f__dd_vctools_vc7libs_ship_atlmf_0042815f._1_4_)(0,iVar3);
          (*DAT_004280c8)(uVar2);
                    // WARNING: Bad instruction - Truncating control flow here
          halt_baddata();
        }
        puVar4 = (undefined4 *)func_0x78873de6();
        *puVar4 = 0xc;
      }
    }
  }
LAB_00423c36:
  piVar5 = (int *)func_0x78873df1();
  return *piVar5;
}



// Library Function - Single Match
//  __setmode_nolock
// 
// Library: Visual Studio 2008 Release

int __cdecl __setmode_nolock(int _FileHandle,int _Mode)

{
  int iVar1;
  int *piVar2;
  char cVar3;
  byte bVar4;
  byte *pbVar5;
  byte bVar6;
  int iVar7;
  
  piVar2 = &DAT_00436d80 + (_FileHandle >> 5);
  iVar7 = (_FileHandle & 0x1fU) * 0x40;
  iVar1 = *piVar2 + iVar7;
  cVar3 = *(char *)(iVar1 + 0x24);
  bVar4 = *(byte *)(iVar1 + 4);
  if (_Mode == 0x4000) {
    *(byte *)(iVar1 + 4) = *(byte *)(iVar1 + 4) | 0x80;
    pbVar5 = (byte *)(*piVar2 + 0x24 + iVar7);
    *pbVar5 = *pbVar5 & 0x80;
  }
  else if (_Mode == 0x8000) {
    *(byte *)(iVar1 + 4) = *(byte *)(iVar1 + 4) & 0x7f;
  }
  else {
    if ((_Mode == 0x10000) || (_Mode == 0x20000)) {
      *(byte *)(iVar1 + 4) = *(byte *)(iVar1 + 4) | 0x80;
      pbVar5 = (byte *)(*piVar2 + 0x24 + iVar7);
      bVar6 = *pbVar5 & 0x82 | 2;
    }
    else {
      if (_Mode != 0x40000) goto LAB_00423e02;
      *(byte *)(iVar1 + 4) = *(byte *)(iVar1 + 4) | 0x80;
      pbVar5 = (byte *)(*piVar2 + 0x24 + iVar7);
      bVar6 = *pbVar5 & 0x81 | 1;
    }
    *pbVar5 = bVar6;
  }
LAB_00423e02:
  if ((bVar4 & 0x80) == 0) {
    return 0x8000;
  }
  return (-(uint)((char)(cVar3 * '\x02') >> 1 != '\0') & 0xc000) + 0x4000;
}



undefined4 __cdecl FUN_00423e20(undefined4 *param_1)

{
  undefined4 *puVar1;
  undefined4 uVar2;
  
  if (param_1 == (undefined4 *)0x0) {
    puVar1 = (undefined4 *)func_0x78873fea();
    *puVar1 = 0x16;
    func_0x53ab3ffa(0,0,0,0,0);
    uVar2 = 0x16;
  }
  else {
    *param_1 = DAT_00435b28;
    uVar2 = 0;
  }
  return uVar2;
}



// Library Function - Single Match
//  __towlower_l
// 
// Library: Visual Studio 2008 Release

wint_t __cdecl __towlower_l(wint_t _C,_locale_t _Locale)

{
  wint_t wVar1;
  int iVar2;
  undefined2 in_stack_00000006;
  int local_18 [2];
  int local_10;
  char local_c;
  ushort local_8 [2];
  
  wVar1 = 0xffff;
  if (_C != 0xffff) {
    func_0x12714034(_Locale);
    if (*(int *)(local_18[0] + 0x14) == 0) {
      wVar1 = _C;
      if ((ushort)(_C - 0x41) < 0x1a) {
        wVar1 = _C + 0x20;
      }
    }
    else if (_C < 0x100) {
      iVar2 = func_0xa6f04071(__C,1,local_18);
      wVar1 = _C;
      if (iVar2 != 0) {
        wVar1 = (wint_t)*(byte *)(*(int *)(local_18[0] + 0xcc) + (__C & 0xffff));
      }
    }
    else {
      iVar2 = func_0x949441a6(local_18,*(int *)(local_18[0] + 0x14),0x100,&_C,1,local_8,1,
                              *(undefined4 *)(local_18[0] + 4));
      wVar1 = _C;
      if (iVar2 != 0) {
        wVar1 = local_8[0];
      }
    }
    if (local_c != '\0') {
      *(uint *)(local_10 + 0x70) = *(uint *)(local_10 + 0x70) & 0xfffffffd;
    }
  }
  return wVar1;
}



// WARNING: Globals starting with '_' overlap smaller symbols at the same address
// Library Function - Single Match
//  ___ansicp
// 
// Libraries: Visual Studio 2005 Release, Visual Studio 2008 Release

void __cdecl ___ansicp(undefined4 param_1)

{
  int iVar1;
  undefined local_10 [6];
  undefined local_a;
  uint local_8;
  
  local_8 = DAT_00431c20 ^ (uint)&stack0xfffffffc;
  local_a = 0;
  iVar1 = (*_DAT_0042815c)(param_1,0x1004,local_10,6);
  if (iVar1 != 0) {
    func_0x8f6d424c(local_10);
  }
  func_0x48604157();
  return;
}



// WARNING: Control flow encountered bad instruction data
// Library Function - Single Match
//  ___convertcp
// 
// Library: Visual Studio 2008 Release

void __cdecl
___convertcp(int param_1,int param_2,undefined4 param_3,uint *param_4,int param_5,undefined4 param_6
            )

{
  uint uVar1;
  uint uVar2;
  bool bVar3;
  code *pcVar4;
  undefined4 uVar5;
  code *pcVar6;
  int iVar7;
  int *piVar8;
  uint uVar9;
  bool bVar10;
  int iStack_4c;
  int *piStack_48;
  int *local_20;
  int local_1c [5];
  uint local_8;
  
  pcVar4 = DAT_00428114;
  local_8 = DAT_00431c20 ^ (uint)&stack0xfffffffc;
  uVar2 = *param_4;
  bVar3 = false;
  if (param_1 == param_2) goto LAB_00424142;
  piStack_48 = local_1c;
  iStack_4c = param_1;
  iVar7 = (*DAT_00428114)();
  pcVar6 = DAT_004281f0;
  if ((((iVar7 == 0) || (local_1c[0] != 1)) || (iVar7 = (*pcVar4)(param_2,local_1c), iVar7 == 0)) ||
     (local_1c[0] != 1)) {
    uVar9 = (*pcVar6)(param_1,1,param_3,uVar2,0,0);
    bVar10 = uVar9 == 0;
    if (bVar10) {
      return;
    }
  }
  else {
    bVar3 = true;
    uVar9 = uVar2;
    if (uVar2 == 0xffffffff) {
      iVar7 = func_0x4b5642e0(param_3);
      uVar9 = iVar7 + 1;
    }
    bVar10 = uVar9 == 0;
  }
  if ((bVar10 || (int)uVar9 < 0) || (0x7ffffff0 < uVar9)) {
    local_20 = (undefined4 *)0x0;
  }
  else {
    uVar1 = uVar9 * 2 + 8;
    if (uVar1 < 0x401) {
      piVar8 = &iStack_4c;
      func_0x5b734300();
      local_20 = &iStack_4c;
      if (&stack0x00000000 != (undefined *)0x4c) {
        iStack_4c = 0xcccc;
LAB_00424085:
        local_20 = piVar8 + 2;
      }
    }
    else {
      piVar8 = (int *)func_0x676f4230(uVar1);
      local_20 = piVar8;
      if (piVar8 != (undefined4 *)0x0) {
        *piVar8 = 0xdddd;
        goto LAB_00424085;
      }
    }
  }
  if (local_20 == (undefined4 *)0x0) {
                    // WARNING: Bad instruction - Truncating control flow here
    halt_baddata();
  }
  func_0x3b844258(local_20,0,uVar9 * 2);
  iVar7 = (*pcVar6)(param_1,1,param_3,uVar2,local_20,uVar9);
  uVar5 = u_f__dd_vctools_vc7libs_ship_atlmf_0042815f._89_4_;
  if (iVar7 != 0) {
    if (param_5 == 0) {
      if (((bVar3) ||
          (uVar9 = (*(code *)u_f__dd_vctools_vc7libs_ship_atlmf_0042815f._89_4_)
                             (param_2,0,local_20,uVar9,0,0,0,0), uVar9 != 0)) &&
         (iVar7 = func_0x842d42bb(1,uVar9), iVar7 != 0)) {
        uVar9 = (*(code *)uVar5)(param_2,0,local_20,uVar9,iVar7,uVar9,0,0);
        if (uVar9 == 0) {
          func_0xc27442de(iVar7);
        }
        else if (uVar2 != 0xffffffff) {
          *param_4 = uVar9;
        }
      }
    }
    else {
      (*(code *)u_f__dd_vctools_vc7libs_ship_atlmf_0042815f._89_4_)
                (param_2,0,local_20,uVar9,param_5,param_6,0,0);
    }
  }
  func_0xc05843f7(local_20);
LAB_00424142:
  func_0x4860430b();
  return;
}



// WARNING: This is an inlined function
// WARNING: Control flow encountered bad instruction data

void __alloca_probe_16(undefined1 param_1)

{
                    // WARNING: Bad instruction - Truncating control flow here
  halt_baddata();
}



// WARNING: This is an inlined function
// WARNING: Control flow encountered bad instruction data

void __alloca_probe_8(undefined1 param_1)

{
                    // WARNING: Bad instruction - Truncating control flow here
  halt_baddata();
}



// WARNING: Control flow encountered bad instruction data
// Library Function - Single Match
//  __flswbuf
// 
// Libraries: Visual Studio 2008 Release, Visual Studio 2010 Release

int __cdecl __flswbuf(int _Ch,FILE *_File)

{
  uint uVar1;
  char *pcVar2;
  char *pcVar3;
  uint uVar4;
  undefined4 *puVar5;
  int iVar6;
  undefined *puVar7;
  int iVar8;
  longlong lVar9;
  undefined4 local_8;
  
  uVar4 = func_0x20c24356(_File);
  uVar1 = _File->_flag;
  if ((uVar1 & 0x82) == 0) {
    puVar5 = (undefined4 *)func_0x78874366();
    *puVar5 = 9;
LAB_004241b6:
    _File->_flag = _File->_flag | 0x20;
                    // WARNING: Bad instruction - Truncating control flow here
    halt_baddata();
  }
  if ((uVar1 & 0x40) != 0) {
    puVar5 = (undefined4 *)func_0x78874383();
    *puVar5 = 0x22;
    goto LAB_004241b6;
  }
  if ((uVar1 & 1) != 0) {
    _File->_cnt = 0;
    if ((uVar1 & 0x10) == 0) {
      _File->_flag = uVar1 | 0x20;
                    // WARNING: Bad instruction - Truncating control flow here
      halt_baddata();
    }
    _File->_ptr = _File->_base;
    _File->_flag = uVar1 & 0xfffffffe;
  }
  uVar1 = _File->_flag;
  _File->_cnt = 0;
  local_8 = 0;
  iVar8 = 2;
  _File->_flag = uVar1 & 0xffffffef | 2;
  if (((uVar1 & 0x10c) == 0) &&
     (((iVar6 = func_0x3fb343c9(), _File != (FILE *)(iVar6 + 0x20) &&
       (iVar6 = func_0x3fb343d5(), _File != (FILE *)(iVar6 + 0x40))) ||
      (iVar6 = func_0x855144e4(uVar4), iVar6 == 0)))) {
    func_0xde4a44ef(_File);
  }
  if ((_File->_flag & 0x108U) == 0) {
    local_8 = CONCAT22(local_8._2_2_,(short)_Ch);
    local_8 = func_0x16ce4498(uVar4,&local_8,2);
  }
  else {
    pcVar2 = _File->_base;
    pcVar3 = _File->_ptr;
    _File->_ptr = pcVar2 + 2;
    iVar8 = (int)pcVar3 - (int)pcVar2;
    _File->_cnt = _File->_bufsiz + -2;
    if (iVar8 < 1) {
      if ((uVar4 == 0xffffffff) || (uVar4 == 0xfffffffe)) {
        puVar7 = &DAT_00432150;
      }
      else {
        puVar7 = (undefined *)((uVar4 & 0x1f) * 0x40 + (&DAT_00436d80)[(int)uVar4 >> 5]);
      }
      if (((puVar7[4] & 0x20) != 0) && (lVar9 = func_0xac4b456c(uVar4,0,0,2), lVar9 == -1))
      goto LAB_004242ed;
    }
    else {
      local_8 = func_0x16ce4420(uVar4,pcVar2,iVar8);
    }
    *(short *)_File->_base = (short)_Ch;
  }
  if (local_8 == iVar8) {
    return _Ch & 0xffff;
  }
LAB_004242ed:
  _File->_flag = _File->_flag | 0x20;
  return 0xffff;
}



ushort __cdecl FUN_00424304(int param_1,ushort param_2,localeinfo_struct *param_3)

{
  int iVar1;
  BOOL BVar2;
  CHAR CVar3;
  localeinfo_struct local_1c;
  int local_14;
  char local_10;
  CHAR local_c;
  CHAR local_b;
  undefined local_a;
  ushort local_8 [2];
  
  _LocaleUpdate::_LocaleUpdate((_LocaleUpdate *)&local_1c,param_3);
  if (param_1 + 1U < 0x101) {
    *(char *)&(local_1c.locinfo)->refcount =
         *(char *)&(local_1c.locinfo)->refcount + (char)local_1c.locinfo;
    local_8[0] = *(ushort *)
                  ((int)&((threadlocaleinfostruct *)((local_1c.locinfo)->lc_category + -1))->
                         refcount + CONCAT31((int3)((uint)param_1 >> 8),0xae) * 2);
  }
  else {
    iVar1 = func_0xdf534603(param_1 >> 8 & 0xff,&local_1c);
    CVar3 = (CHAR)param_1;
    if (iVar1 == 0) {
      local_b = '\0';
      iVar1 = 1;
      local_c = CVar3;
    }
    else {
      param_1._0_1_ = (CHAR)((uint)param_1 >> 8);
      local_c = (CHAR)param_1;
      local_a = 0;
      iVar1 = 2;
      local_b = CVar3;
    }
    BVar2 = FID_conflict____crtCompareStringW
                      (&local_1c,1,&local_c,iVar1,local_8,(local_1c.locinfo)->lc_codepage,
                       (BOOL)(local_1c.locinfo)->lc_category[0].wlocale);
    if (BVar2 == 0) {
      if (local_10 != '\0') {
        *(uint *)(local_14 + 0x70) = *(uint *)(local_14 + 0x70) & 0xfffffffd;
      }
      return 0;
    }
  }
  if (local_10 != '\0') {
    *(uint *)(local_14 + 0x70) = *(uint *)(local_14 + 0x70) & 0xfffffffd;
  }
  return local_8[0] & param_2;
}



// WARNING: Control flow encountered bad instruction data
// Library Function - Multiple Matches With Different Base Names
//  __ld12tod
//  __ld12tof
// 
// Library: Visual Studio 2008 Release

INTRNCVT_STATUS __cdecl FID_conflict___ld12tod(_LDBL12 *_Ifp,_CRT_DOUBLE *_D)

{
  uchar *puVar1;
  _LDBL12 *p_Var2;
  undefined4 uVar3;
  int iVar4;
  int iVar5;
  byte bVar6;
  _LDBL12 **pp_Var7;
  _LDBL12 **pp_Var8;
  uint uVar9;
  undefined *puVar10;
  _LDBL12 *p_Var11;
  uint uVar12;
  int iVar13;
  int iVar14;
  bool bVar15;
  _LDBL12 *local_24 [2];
  int local_1c;
  uint local_18;
  uint local_14;
  uint local_10;
  int local_c;
  _LDBL12 *local_8;
  
  local_18 = *(ushort *)(_Ifp->ld12 + 10) & 0x8000;
  p_Var2 = *(_LDBL12 **)(_Ifp->ld12 + 6);
  local_24[0] = p_Var2;
  uVar3 = *(undefined4 *)(_Ifp->ld12 + 2);
  uVar12 = *(ushort *)(_Ifp->ld12 + 10) & 0x7fff;
  iVar13 = uVar12 - 0x3fff;
  iVar4 = (uint)*(ushort *)_Ifp->ld12 << 0x10;
  local_24[1] = (_LDBL12 *)uVar3;
  local_1c = iVar4;
  if (iVar13 == -0x3fff) {
    iVar4 = 0;
    do {
      if (local_24[iVar4] != (_LDBL12 *)0x0) {
                    // WARNING: Bad instruction - Truncating control flow here
        halt_baddata();
      }
      iVar4 = iVar4 + 1;
    } while (iVar4 < 3);
                    // WARNING: Bad instruction - Truncating control flow here
    halt_baddata();
  }
  _Ifp = (_LDBL12 *)0x0;
  iVar14 = DAT_00432c98 - 1;
  iVar5 = (int)(DAT_00432c98 + ((int)DAT_00432c98 >> 0x1f & 0x1fU)) >> 5;
  uVar9 = DAT_00432c98 & 0x8000001f;
  local_14 = iVar13;
  local_10 = iVar5;
  if ((int)uVar9 < 0) {
    uVar9 = (uVar9 - 1 | 0xffffffe0) + 1;
  }
  pp_Var8 = local_24 + iVar5;
  bVar6 = (byte)(0x1f - uVar9);
  local_c = 0x1f - uVar9;
  if (((uint)*pp_Var8 & 1 << (bVar6 & 0x1f)) != 0) {
    p_Var11 = (_LDBL12 *)((uint)local_24[iVar5] & ~(-1 << (bVar6 & 0x1f)));
    while( true ) {
      if (p_Var11 != (_LDBL12 *)0x0) {
        iVar5 = (int)(iVar14 + (iVar14 >> 0x1f & 0x1fU)) >> 5;
        local_8 = (_LDBL12 *)0x0;
        puVar10 = (undefined *)(1 << (0x1f - ((byte)iVar14 & 0x1f) & 0x1f));
        pp_Var7 = local_24 + iVar5;
        _Ifp = (_LDBL12 *)((*pp_Var7)->ld12 + (int)puVar10);
        if (_Ifp < *pp_Var7) goto LAB_004244f1;
        bVar15 = _Ifp < puVar10;
        do {
          local_8 = (_LDBL12 *)0x0;
          if (!bVar15) goto LAB_004244f8;
LAB_004244f1:
          do {
            local_8 = (_LDBL12 *)0x1;
LAB_004244f8:
            iVar5 = iVar5 + -1;
            *pp_Var7 = _Ifp;
            if ((iVar5 < 0) || (local_8 == (_LDBL12 *)0x0)) {
              _Ifp = local_8;
              goto LAB_00424506;
            }
            local_8 = (_LDBL12 *)0x0;
            pp_Var7 = local_24 + iVar5;
            _Ifp = (_LDBL12 *)((*pp_Var7)->ld12 + 1);
          } while (_Ifp < *pp_Var7);
          bVar15 = _Ifp == (_LDBL12 *)0x0;
        } while( true );
      }
      iVar5 = iVar5 + 1;
      if (2 < iVar5) break;
      p_Var11 = local_24[iVar5];
    }
  }
LAB_00424506:
  *pp_Var8 = (_LDBL12 *)((uint)*pp_Var8 & -1 << ((byte)local_c & 0x1f));
  iVar5 = local_10 + 1;
  if (iVar5 < 3) {
    pp_Var8 = local_24 + iVar5;
    for (iVar14 = 3 - iVar5; iVar14 != 0; iVar14 = iVar14 + -1) {
      *pp_Var8 = (_LDBL12 *)0x0;
      pp_Var8 = pp_Var8 + 1;
    }
  }
  if (_Ifp != (_LDBL12 *)0x0) {
    iVar13 = uVar12 - 0x3ffe;
  }
  if (iVar13 < (int)(DAT_00432c94 - DAT_00432c98)) {
                    // WARNING: Bad instruction - Truncating control flow here
    halt_baddata();
  }
  if (DAT_00432c94 < iVar13) {
    if (DAT_00432c90 <= iVar13) {
      local_24[1] = (_LDBL12 *)0x0;
      local_1c = 0;
      local_24[0] = (_LDBL12 *)0x80000000;
      iVar4 = (int)(DAT_00432c9c + ((int)DAT_00432c9c >> 0x1f & 0x1fU)) >> 5;
      uVar12 = DAT_00432c9c & 0x8000001f;
      if ((int)uVar12 < 0) {
        uVar12 = (uVar12 - 1 | 0xffffffe0) + 1;
      }
      local_10 = 0;
      _Ifp = (_LDBL12 *)0x0;
      local_8 = (_LDBL12 *)(0x20 - uVar12);
      do {
        p_Var2 = local_24[(int)_Ifp];
        local_14 = (uint)p_Var2 & ~(-1 << ((byte)uVar12 & 0x1f));
        local_24[(int)_Ifp] = (_LDBL12 *)((uint)p_Var2 >> ((byte)uVar12 & 0x1f) | local_10);
        _Ifp = (_LDBL12 *)(_Ifp->ld12 + 1);
        local_10 = local_14 << ((byte)(0x20 - uVar12) & 0x1f);
      } while ((int)_Ifp < 3);
      iVar13 = 2;
      pp_Var8 = local_24 + (2 - iVar4);
      do {
        if (iVar13 < iVar4) {
          local_24[iVar13] = (_LDBL12 *)0x0;
        }
        else {
          local_24[iVar13] = *pp_Var8;
        }
        iVar13 = iVar13 + -1;
        pp_Var8 = pp_Var8 + -1;
      } while (-1 < iVar13);
                    // WARNING: Bad instruction - Truncating control flow here
      halt_baddata();
    }
    local_24[0] = (_LDBL12 *)((uint)local_24[0] & 0x7fffffff);
    iVar4 = (int)(DAT_00432c9c + ((int)DAT_00432c9c >> 0x1f & 0x1fU)) >> 5;
    uVar12 = DAT_00432c9c & 0x8000001f;
    if ((int)uVar12 < 0) {
      uVar12 = (uVar12 - 1 | 0xffffffe0) + 1;
    }
    local_10 = 0;
    _Ifp = (_LDBL12 *)0x0;
    local_8 = (_LDBL12 *)(0x20 - uVar12);
    do {
      local_14 = (uint)local_24[(int)_Ifp] & ~(-1 << ((byte)uVar12 & 0x1f));
      local_24[(int)_Ifp] =
           (_LDBL12 *)((uint)local_24[(int)_Ifp] >> ((byte)uVar12 & 0x1f) | local_10);
      _Ifp = (_LDBL12 *)(_Ifp->ld12 + 1);
      local_10 = local_14 << ((byte)(0x20 - uVar12) & 0x1f);
    } while ((int)_Ifp < 3);
    iVar5 = 2;
    pp_Var8 = local_24 + (2 - iVar4);
    do {
      if (iVar5 < iVar4) {
        local_24[iVar5] = (_LDBL12 *)0x0;
      }
      else {
        local_24[iVar5] = *pp_Var8;
      }
      iVar5 = iVar5 + -1;
      pp_Var8 = pp_Var8 + -1;
    } while (-1 < iVar5);
    uVar12 = iVar13 + DAT_00432ca4 << (0x1fU - (char)DAT_00432c9c & 0x1f) |
             -(uint)(local_18 != 0) & 0x80000000 | (uint)local_24[0];
    if (DAT_00432ca0 == 0x40) {
      *(uint *)((int)&_D->x + 4) = uVar12;
      *(_LDBL12 **)&_D->x = local_24[1];
    }
    else if (DAT_00432ca0 == 0x20) {
      *(uint *)&_D->x = uVar12;
    }
    return INTRNCVT_OK;
  }
  local_14 = DAT_00432c94 - local_14;
  local_24[0] = p_Var2;
  local_24[1] = (_LDBL12 *)uVar3;
  iVar13 = (int)(local_14 + ((int)local_14 >> 0x1f & 0x1fU)) >> 5;
  uVar12 = local_14 & 0x8000001f;
  if ((int)uVar12 < 0) {
    uVar12 = (uVar12 - 1 | 0xffffffe0) + 1;
  }
  local_10 = 0;
  _Ifp = (_LDBL12 *)0x0;
  local_8 = (_LDBL12 *)(0x20 - uVar12);
  do {
    p_Var2 = local_24[(int)_Ifp];
    local_14 = (uint)p_Var2 & ~(-1 << ((byte)uVar12 & 0x1f));
    local_24[(int)_Ifp] = (_LDBL12 *)((uint)p_Var2 >> ((byte)uVar12 & 0x1f) | local_10);
    _Ifp = (_LDBL12 *)(_Ifp->ld12 + 1);
    local_10 = local_14 << ((byte)(0x20 - uVar12) & 0x1f);
  } while ((int)_Ifp < 3);
  iVar4 = 2;
  pp_Var8 = local_24 + (2 - iVar13);
  do {
    if (iVar4 < iVar13) {
      local_24[iVar4] = (_LDBL12 *)0x0;
    }
    else {
      local_24[iVar4] = *pp_Var8;
    }
    iVar4 = iVar4 + -1;
    pp_Var8 = pp_Var8 + -1;
  } while (-1 < iVar4);
  iVar13 = DAT_00432c98 - 1;
  iVar4 = (int)(DAT_00432c98 + ((int)DAT_00432c98 >> 0x1f & 0x1fU)) >> 5;
  uVar12 = DAT_00432c98 & 0x8000001f;
  local_10 = iVar4;
  if ((int)uVar12 < 0) {
    uVar12 = (uVar12 - 1 | 0xffffffe0) + 1;
  }
  bVar6 = (byte)(0x1f - uVar12);
  pp_Var8 = local_24 + iVar4;
  local_14 = 0x1f - uVar12;
  if (((uint)*pp_Var8 & 1 << (bVar6 & 0x1f)) != 0) {
    p_Var2 = (_LDBL12 *)((uint)local_24[iVar4] & ~(-1 << (bVar6 & 0x1f)));
    while (p_Var2 == (_LDBL12 *)0x0) {
      iVar4 = iVar4 + 1;
      if (2 < iVar4) goto LAB_004246a9;
      p_Var2 = local_24[iVar4];
    }
    iVar4 = (int)(iVar13 + (iVar13 >> 0x1f & 0x1fU)) >> 5;
    bVar15 = false;
    p_Var11 = (_LDBL12 *)(1 << (0x1f - ((byte)iVar13 & 0x1f) & 0x1f));
    p_Var2 = local_24[iVar4];
    puVar1 = p_Var11->ld12 + (int)p_Var2->ld12;
    if ((puVar1 < p_Var2) || (puVar1 < p_Var11)) {
      bVar15 = true;
    }
    local_24[iVar4] = (_LDBL12 *)puVar1;
    while ((iVar4 = iVar4 + -1, -1 < iVar4 && (bVar15))) {
      p_Var2 = local_24[iVar4];
      puVar1 = p_Var2->ld12 + 1;
      bVar15 = false;
      if ((puVar1 < p_Var2) || (puVar1 == (uchar *)0x0)) {
        bVar15 = true;
      }
      local_24[iVar4] = (_LDBL12 *)puVar1;
    }
  }
LAB_004246a9:
  *pp_Var8 = (_LDBL12 *)((uint)*pp_Var8 & -1 << ((byte)local_14 & 0x1f));
  iVar4 = local_10 + 1;
  if (iVar4 < 3) {
    pp_Var8 = local_24 + iVar4;
    for (iVar13 = 3 - iVar4; iVar13 != 0; iVar13 = iVar13 + -1) {
      *pp_Var8 = (_LDBL12 *)0x0;
      pp_Var8 = pp_Var8 + 1;
    }
  }
  uVar12 = DAT_00432c9c + 1;
  iVar4 = (int)(uVar12 + ((int)uVar12 >> 0x1f & 0x1fU)) >> 5;
  uVar12 = uVar12 & 0x8000001f;
  if ((int)uVar12 < 0) {
    uVar12 = (uVar12 - 1 | 0xffffffe0) + 1;
  }
  local_10 = 0;
  _Ifp = (_LDBL12 *)0x0;
  local_8 = (_LDBL12 *)(0x20 - uVar12);
  do {
    p_Var2 = local_24[(int)_Ifp];
    local_14 = (uint)p_Var2 & ~(-1 << ((byte)uVar12 & 0x1f));
    local_24[(int)_Ifp] = (_LDBL12 *)((uint)p_Var2 >> ((byte)uVar12 & 0x1f) | local_10);
    _Ifp = (_LDBL12 *)(_Ifp->ld12 + 1);
    local_10 = local_14 << ((byte)(0x20 - uVar12) & 0x1f);
  } while ((int)_Ifp < 3);
  iVar13 = 2;
  pp_Var8 = local_24 + (2 - iVar4);
  do {
    if (iVar13 < iVar4) {
      local_24[iVar13] = (_LDBL12 *)0x0;
    }
    else {
      local_24[iVar13] = *pp_Var8;
    }
    iVar13 = iVar13 + -1;
    pp_Var8 = pp_Var8 + -1;
  } while (-1 < iVar13);
                    // WARNING: Bad instruction - Truncating control flow here
  halt_baddata();
}



// WARNING: Control flow encountered bad instruction data
// Library Function - Multiple Matches With Different Base Names
//  __ld12tod
//  __ld12tof
// 
// Library: Visual Studio 2008 Release

INTRNCVT_STATUS __cdecl FID_conflict___ld12tod(_LDBL12 *_Ifp,_CRT_DOUBLE *_D)

{
  uchar *puVar1;
  _LDBL12 *p_Var2;
  undefined4 uVar3;
  int iVar4;
  int iVar5;
  byte bVar6;
  _LDBL12 **pp_Var7;
  _LDBL12 **pp_Var8;
  uint uVar9;
  undefined *puVar10;
  _LDBL12 *p_Var11;
  uint uVar12;
  int iVar13;
  int iVar14;
  bool bVar15;
  _LDBL12 *local_24 [2];
  int local_1c;
  uint local_18;
  uint local_14;
  uint local_10;
  int local_c;
  _LDBL12 *local_8;
  
  local_18 = *(ushort *)(_Ifp->ld12 + 10) & 0x8000;
  p_Var2 = *(_LDBL12 **)(_Ifp->ld12 + 6);
  local_24[0] = p_Var2;
  uVar3 = *(undefined4 *)(_Ifp->ld12 + 2);
  uVar12 = *(ushort *)(_Ifp->ld12 + 10) & 0x7fff;
  iVar13 = uVar12 - 0x3fff;
  iVar4 = (uint)*(ushort *)_Ifp->ld12 << 0x10;
  local_24[1] = (_LDBL12 *)uVar3;
  local_1c = iVar4;
  if (iVar13 == -0x3fff) {
    iVar4 = 0;
    do {
      if (local_24[iVar4] != (_LDBL12 *)0x0) {
                    // WARNING: Bad instruction - Truncating control flow here
        halt_baddata();
      }
      iVar4 = iVar4 + 1;
    } while (iVar4 < 3);
                    // WARNING: Bad instruction - Truncating control flow here
    halt_baddata();
  }
  _Ifp = (_LDBL12 *)0x0;
  iVar14 = DAT_00432cb0 - 1;
  iVar5 = (int)(DAT_00432cb0 + ((int)DAT_00432cb0 >> 0x1f & 0x1fU)) >> 5;
  uVar9 = DAT_00432cb0 & 0x8000001f;
  local_14 = iVar13;
  local_10 = iVar5;
  if ((int)uVar9 < 0) {
    uVar9 = (uVar9 - 1 | 0xffffffe0) + 1;
  }
  pp_Var8 = local_24 + iVar5;
  bVar6 = (byte)(0x1f - uVar9);
  local_c = 0x1f - uVar9;
  if (((uint)*pp_Var8 & 1 << (bVar6 & 0x1f)) != 0) {
    p_Var11 = (_LDBL12 *)((uint)local_24[iVar5] & ~(-1 << (bVar6 & 0x1f)));
    while( true ) {
      if (p_Var11 != (_LDBL12 *)0x0) {
        iVar5 = (int)(iVar14 + (iVar14 >> 0x1f & 0x1fU)) >> 5;
        local_8 = (_LDBL12 *)0x0;
        puVar10 = (undefined *)(1 << (0x1f - ((byte)iVar14 & 0x1f) & 0x1f));
        pp_Var7 = local_24 + iVar5;
        _Ifp = (_LDBL12 *)((*pp_Var7)->ld12 + (int)puVar10);
        if (_Ifp < *pp_Var7) goto LAB_00424a35;
        bVar15 = _Ifp < puVar10;
        do {
          local_8 = (_LDBL12 *)0x0;
          if (!bVar15) goto LAB_00424a3c;
LAB_00424a35:
          do {
            local_8 = (_LDBL12 *)0x1;
LAB_00424a3c:
            iVar5 = iVar5 + -1;
            *pp_Var7 = _Ifp;
            if ((iVar5 < 0) || (local_8 == (_LDBL12 *)0x0)) {
              _Ifp = local_8;
              goto LAB_00424a4a;
            }
            local_8 = (_LDBL12 *)0x0;
            pp_Var7 = local_24 + iVar5;
            _Ifp = (_LDBL12 *)((*pp_Var7)->ld12 + 1);
          } while (_Ifp < *pp_Var7);
          bVar15 = _Ifp == (_LDBL12 *)0x0;
        } while( true );
      }
      iVar5 = iVar5 + 1;
      if (2 < iVar5) break;
      p_Var11 = local_24[iVar5];
    }
  }
LAB_00424a4a:
  *pp_Var8 = (_LDBL12 *)((uint)*pp_Var8 & -1 << ((byte)local_c & 0x1f));
  iVar5 = local_10 + 1;
  if (iVar5 < 3) {
    pp_Var8 = local_24 + iVar5;
    for (iVar14 = 3 - iVar5; iVar14 != 0; iVar14 = iVar14 + -1) {
      *pp_Var8 = (_LDBL12 *)0x0;
      pp_Var8 = pp_Var8 + 1;
    }
  }
  if (_Ifp != (_LDBL12 *)0x0) {
    iVar13 = uVar12 - 0x3ffe;
  }
  if (iVar13 < (int)(DAT_00432cac - DAT_00432cb0)) {
                    // WARNING: Bad instruction - Truncating control flow here
    halt_baddata();
  }
  if (DAT_00432cac < iVar13) {
    if (DAT_00432ca8 <= iVar13) {
      local_24[1] = (_LDBL12 *)0x0;
      local_1c = 0;
      local_24[0] = (_LDBL12 *)0x80000000;
      iVar4 = (int)(DAT_00432cb4 + ((int)DAT_00432cb4 >> 0x1f & 0x1fU)) >> 5;
      uVar12 = DAT_00432cb4 & 0x8000001f;
      if ((int)uVar12 < 0) {
        uVar12 = (uVar12 - 1 | 0xffffffe0) + 1;
      }
      local_10 = 0;
      _Ifp = (_LDBL12 *)0x0;
      local_8 = (_LDBL12 *)(0x20 - uVar12);
      do {
        p_Var2 = local_24[(int)_Ifp];
        local_14 = (uint)p_Var2 & ~(-1 << ((byte)uVar12 & 0x1f));
        local_24[(int)_Ifp] = (_LDBL12 *)((uint)p_Var2 >> ((byte)uVar12 & 0x1f) | local_10);
        _Ifp = (_LDBL12 *)(_Ifp->ld12 + 1);
        local_10 = local_14 << ((byte)(0x20 - uVar12) & 0x1f);
      } while ((int)_Ifp < 3);
      iVar13 = 2;
      pp_Var8 = local_24 + (2 - iVar4);
      do {
        if (iVar13 < iVar4) {
          local_24[iVar13] = (_LDBL12 *)0x0;
        }
        else {
          local_24[iVar13] = *pp_Var8;
        }
        iVar13 = iVar13 + -1;
        pp_Var8 = pp_Var8 + -1;
      } while (-1 < iVar13);
                    // WARNING: Bad instruction - Truncating control flow here
      halt_baddata();
    }
    local_24[0] = (_LDBL12 *)((uint)local_24[0] & 0x7fffffff);
    iVar4 = (int)(DAT_00432cb4 + ((int)DAT_00432cb4 >> 0x1f & 0x1fU)) >> 5;
    uVar12 = DAT_00432cb4 & 0x8000001f;
    if ((int)uVar12 < 0) {
      uVar12 = (uVar12 - 1 | 0xffffffe0) + 1;
    }
    local_10 = 0;
    _Ifp = (_LDBL12 *)0x0;
    local_8 = (_LDBL12 *)(0x20 - uVar12);
    do {
      local_14 = (uint)local_24[(int)_Ifp] & ~(-1 << ((byte)uVar12 & 0x1f));
      local_24[(int)_Ifp] =
           (_LDBL12 *)((uint)local_24[(int)_Ifp] >> ((byte)uVar12 & 0x1f) | local_10);
      _Ifp = (_LDBL12 *)(_Ifp->ld12 + 1);
      local_10 = local_14 << ((byte)(0x20 - uVar12) & 0x1f);
    } while ((int)_Ifp < 3);
    iVar5 = 2;
    pp_Var8 = local_24 + (2 - iVar4);
    do {
      if (iVar5 < iVar4) {
        local_24[iVar5] = (_LDBL12 *)0x0;
      }
      else {
        local_24[iVar5] = *pp_Var8;
      }
      iVar5 = iVar5 + -1;
      pp_Var8 = pp_Var8 + -1;
    } while (-1 < iVar5);
    uVar12 = iVar13 + DAT_00432cbc << (0x1fU - (char)DAT_00432cb4 & 0x1f) |
             -(uint)(local_18 != 0) & 0x80000000 | (uint)local_24[0];
    if (DAT_00432cb8 == 0x40) {
      *(uint *)((int)&_D->x + 4) = uVar12;
      *(_LDBL12 **)&_D->x = local_24[1];
    }
    else if (DAT_00432cb8 == 0x20) {
      *(uint *)&_D->x = uVar12;
    }
    return INTRNCVT_OK;
  }
  local_14 = DAT_00432cac - local_14;
  local_24[0] = p_Var2;
  local_24[1] = (_LDBL12 *)uVar3;
  iVar13 = (int)(local_14 + ((int)local_14 >> 0x1f & 0x1fU)) >> 5;
  uVar12 = local_14 & 0x8000001f;
  if ((int)uVar12 < 0) {
    uVar12 = (uVar12 - 1 | 0xffffffe0) + 1;
  }
  local_10 = 0;
  _Ifp = (_LDBL12 *)0x0;
  local_8 = (_LDBL12 *)(0x20 - uVar12);
  do {
    p_Var2 = local_24[(int)_Ifp];
    local_14 = (uint)p_Var2 & ~(-1 << ((byte)uVar12 & 0x1f));
    local_24[(int)_Ifp] = (_LDBL12 *)((uint)p_Var2 >> ((byte)uVar12 & 0x1f) | local_10);
    _Ifp = (_LDBL12 *)(_Ifp->ld12 + 1);
    local_10 = local_14 << ((byte)(0x20 - uVar12) & 0x1f);
  } while ((int)_Ifp < 3);
  iVar4 = 2;
  pp_Var8 = local_24 + (2 - iVar13);
  do {
    if (iVar4 < iVar13) {
      local_24[iVar4] = (_LDBL12 *)0x0;
    }
    else {
      local_24[iVar4] = *pp_Var8;
    }
    iVar4 = iVar4 + -1;
    pp_Var8 = pp_Var8 + -1;
  } while (-1 < iVar4);
  iVar13 = DAT_00432cb0 - 1;
  iVar4 = (int)(DAT_00432cb0 + ((int)DAT_00432cb0 >> 0x1f & 0x1fU)) >> 5;
  uVar12 = DAT_00432cb0 & 0x8000001f;
  local_10 = iVar4;
  if ((int)uVar12 < 0) {
    uVar12 = (uVar12 - 1 | 0xffffffe0) + 1;
  }
  bVar6 = (byte)(0x1f - uVar12);
  pp_Var8 = local_24 + iVar4;
  local_14 = 0x1f - uVar12;
  if (((uint)*pp_Var8 & 1 << (bVar6 & 0x1f)) != 0) {
    p_Var2 = (_LDBL12 *)((uint)local_24[iVar4] & ~(-1 << (bVar6 & 0x1f)));
    while (p_Var2 == (_LDBL12 *)0x0) {
      iVar4 = iVar4 + 1;
      if (2 < iVar4) goto LAB_00424bed;
      p_Var2 = local_24[iVar4];
    }
    iVar4 = (int)(iVar13 + (iVar13 >> 0x1f & 0x1fU)) >> 5;
    bVar15 = false;
    p_Var11 = (_LDBL12 *)(1 << (0x1f - ((byte)iVar13 & 0x1f) & 0x1f));
    p_Var2 = local_24[iVar4];
    puVar1 = p_Var11->ld12 + (int)p_Var2->ld12;
    if ((puVar1 < p_Var2) || (puVar1 < p_Var11)) {
      bVar15 = true;
    }
    local_24[iVar4] = (_LDBL12 *)puVar1;
    while ((iVar4 = iVar4 + -1, -1 < iVar4 && (bVar15))) {
      p_Var2 = local_24[iVar4];
      puVar1 = p_Var2->ld12 + 1;
      bVar15 = false;
      if ((puVar1 < p_Var2) || (puVar1 == (uchar *)0x0)) {
        bVar15 = true;
      }
      local_24[iVar4] = (_LDBL12 *)puVar1;
    }
  }
LAB_00424bed:
  *pp_Var8 = (_LDBL12 *)((uint)*pp_Var8 & -1 << ((byte)local_14 & 0x1f));
  iVar4 = local_10 + 1;
  if (iVar4 < 3) {
    pp_Var8 = local_24 + iVar4;
    for (iVar13 = 3 - iVar4; iVar13 != 0; iVar13 = iVar13 + -1) {
      *pp_Var8 = (_LDBL12 *)0x0;
      pp_Var8 = pp_Var8 + 1;
    }
  }
  uVar12 = DAT_00432cb4 + 1;
  iVar4 = (int)(uVar12 + ((int)uVar12 >> 0x1f & 0x1fU)) >> 5;
  uVar12 = uVar12 & 0x8000001f;
  if ((int)uVar12 < 0) {
    uVar12 = (uVar12 - 1 | 0xffffffe0) + 1;
  }
  local_10 = 0;
  _Ifp = (_LDBL12 *)0x0;
  local_8 = (_LDBL12 *)(0x20 - uVar12);
  do {
    p_Var2 = local_24[(int)_Ifp];
    local_14 = (uint)p_Var2 & ~(-1 << ((byte)uVar12 & 0x1f));
    local_24[(int)_Ifp] = (_LDBL12 *)((uint)p_Var2 >> ((byte)uVar12 & 0x1f) | local_10);
    _Ifp = (_LDBL12 *)(_Ifp->ld12 + 1);
    local_10 = local_14 << ((byte)(0x20 - uVar12) & 0x1f);
  } while ((int)_Ifp < 3);
  iVar13 = 2;
  pp_Var8 = local_24 + (2 - iVar4);
  do {
    if (iVar13 < iVar4) {
      local_24[iVar13] = (_LDBL12 *)0x0;
    }
    else {
      local_24[iVar13] = *pp_Var8;
    }
    iVar13 = iVar13 + -1;
    pp_Var8 = pp_Var8 + -1;
  } while (-1 < iVar13);
                    // WARNING: Bad instruction - Truncating control flow here
  halt_baddata();
}



// WARNING: Control flow encountered bad instruction data
// WARNING: Removing unreachable block (ram,0x00425106)
// WARNING: Removing unreachable block (ram,0x004250cf)
// WARNING: Removing unreachable block (ram,0x004254b7)
// WARNING: Removing unreachable block (ram,0x004250de)
// WARNING: Removing unreachable block (ram,0x004250e6)
// WARNING: Removing unreachable block (ram,0x004250ec)
// WARNING: Removing unreachable block (ram,0x004250ef)
// WARNING: Removing unreachable block (ram,0x004250f6)
// WARNING: Removing unreachable block (ram,0x00425100)
// WARNING: Removing unreachable block (ram,0x0042515b)
// WARNING: Removing unreachable block (ram,0x00425155)
// WARNING: Removing unreachable block (ram,0x00425161)
// WARNING: Removing unreachable block (ram,0x0042517e)
// WARNING: Removing unreachable block (ram,0x00425180)
// WARNING: Removing unreachable block (ram,0x00425188)
// WARNING: Removing unreachable block (ram,0x0042518b)
// WARNING: Removing unreachable block (ram,0x00425190)
// WARNING: Removing unreachable block (ram,0x00425193)
// WARNING: Removing unreachable block (ram,0x004254c0)
// WARNING: Removing unreachable block (ram,0x0042519e)
// WARNING: Removing unreachable block (ram,0x004251a9)
// WARNING: Removing unreachable block (ram,0x004251bc)
// WARNING: Removing unreachable block (ram,0x004251be)
// WARNING: Removing unreachable block (ram,0x004251cb)
// WARNING: Removing unreachable block (ram,0x004251d0)
// WARNING: Removing unreachable block (ram,0x004251d6)
// WARNING: Removing unreachable block (ram,0x004251df)
// WARNING: Removing unreachable block (ram,0x004251e6)
// WARNING: Removing unreachable block (ram,0x004251fe)
// WARNING: Removing unreachable block (ram,0x0042520f)
// WARNING: Removing unreachable block (ram,0x0042521d)
// WARNING: Removing unreachable block (ram,0x0042525c)
// WARNING: Removing unreachable block (ram,0x00425265)
// WARNING: Removing unreachable block (ram,0x0042547d)
// WARNING: Removing unreachable block (ram,0x00425273)
// WARNING: Removing unreachable block (ram,0x0042527d)
// WARNING: Removing unreachable block (ram,0x0042528a)
// WARNING: Removing unreachable block (ram,0x00425291)
// WARNING: Removing unreachable block (ram,0x0042529b)
// WARNING: Removing unreachable block (ram,0x004252a0)
// WARNING: Removing unreachable block (ram,0x004252a5)
// WARNING: Removing unreachable block (ram,0x004252b0)
// WARNING: Removing unreachable block (ram,0x004252b5)
// WARNING: Removing unreachable block (ram,0x004252bf)
// WARNING: Removing unreachable block (ram,0x004252c4)
// WARNING: Removing unreachable block (ram,0x004252c8)
// WARNING: Removing unreachable block (ram,0x004252d6)
// WARNING: Removing unreachable block (ram,0x004252e3)
// WARNING: Removing unreachable block (ram,0x004252f2)
// WARNING: Removing unreachable block (ram,0x004252ff)
// WARNING: Removing unreachable block (ram,0x0042531c)
// WARNING: Removing unreachable block (ram,0x00425320)
// WARNING: Removing unreachable block (ram,0x00425327)
// WARNING: Removing unreachable block (ram,0x00425330)
// WARNING: Removing unreachable block (ram,0x00425333)
// WARNING: Removing unreachable block (ram,0x00425344)
// WARNING: Removing unreachable block (ram,0x00425352)
// WARNING: Removing unreachable block (ram,0x0042535d)
// WARNING: Removing unreachable block (ram,0x00425364)
// WARNING: Removing unreachable block (ram,0x0042538f)
// WARNING: Removing unreachable block (ram,0x00425394)
// WARNING: Removing unreachable block (ram,0x0042539f)
// WARNING: Removing unreachable block (ram,0x004253a8)
// WARNING: Removing unreachable block (ram,0x004253ae)
// WARNING: Removing unreachable block (ram,0x004253b1)
// WARNING: Removing unreachable block (ram,0x004253d7)
// WARNING: Removing unreachable block (ram,0x004253dc)
// WARNING: Removing unreachable block (ram,0x004253e1)
// WARNING: Removing unreachable block (ram,0x004253ee)
// WARNING: Removing unreachable block (ram,0x004253ff)
// WARNING: Removing unreachable block (ram,0x00425430)
// WARNING: Removing unreachable block (ram,0x00425405)
// WARNING: Removing unreachable block (ram,0x0042542b)
// WARNING: Removing unreachable block (ram,0x0042540f)
// WARNING: Removing unreachable block (ram,0x00425425)
// WARNING: Removing unreachable block (ram,0x0042541e)
// WARNING: Removing unreachable block (ram,0x00425433)
// WARNING: Removing unreachable block (ram,0x00425460)
// WARNING: Removing unreachable block (ram,0x0042543d)
// WARNING: Removing unreachable block (ram,0x0042549b)
// WARNING: Removing unreachable block (ram,0x004251e1)
// WARNING: Removing unreachable block (ram,0x004254a5)
// WARNING: Removing unreachable block (ram,0x004254d7)
// WARNING: Removing unreachable block (ram,0x004254de)
// WARNING: Removing unreachable block (ram,0x004254e6)

void __cdecl
FUN_00424e44(undefined2 *param_1,char **param_2,char *param_3,int param_4,int param_5,int param_6,
            undefined4 param_7,int param_8)

{
  char cVar1;
  undefined4 *puVar2;
  
  if (param_8 == 0) {
    puVar2 = (undefined4 *)func_0x7887504a();
    *puVar2 = 0x16;
    func_0x53ab505a(0,0,0,0,0);
                    // WARNING: Bad instruction - Truncating control flow here
    halt_baddata();
  }
  for (; (((cVar1 = *param_3, cVar1 == ' ' || (cVar1 == '\t')) || (cVar1 == '\n')) ||
         (cVar1 == '\r')); param_3 = param_3 + 1) {
  }
                    // WARNING: Treating indirect jump as call
  (*(code *)0x90c3c948)();
  return;
}



// WARNING: Control flow encountered bad instruction data
// Library Function - Single Match
//  __control87
// 
// Library: Visual Studio 2008 Release

uint __cdecl __control87(uint _NewValue,uint _Mask)

{
  ushort uVar1;
  uint uVar2;
  uint uVar3;
  undefined4 uVar4;
  uint uVar5;
  ushort in_FPUControlWord;
  
  uVar5 = 0;
  if ((in_FPUControlWord & 1) != 0) {
    uVar5 = 0x10;
  }
  if ((in_FPUControlWord & 4) != 0) {
    uVar5 = uVar5 | 8;
  }
  if ((in_FPUControlWord & 8) != 0) {
    uVar5 = uVar5 | 4;
  }
  if ((in_FPUControlWord & 0x10) != 0) {
    uVar5 = uVar5 | 2;
  }
  if ((in_FPUControlWord & 0x20) != 0) {
    uVar5 = uVar5 | 1;
  }
  if ((in_FPUControlWord & 2) != 0) {
    uVar5 = uVar5 | 0x80000;
  }
  uVar1 = in_FPUControlWord & 0xc00;
  if ((in_FPUControlWord & 0xc00) != 0) {
    if (uVar1 == 0x400) {
      uVar5 = uVar5 | 0x100;
    }
    else if (uVar1 == 0x800) {
      uVar5 = uVar5 | 0x200;
    }
    else if (uVar1 == 0xc00) {
      uVar5 = uVar5 | 0x300;
    }
  }
  if ((in_FPUControlWord & 0x300) == 0) {
    uVar5 = uVar5 | 0x20000;
  }
  else if ((in_FPUControlWord & 0x300) == 0x200) {
    uVar5 = uVar5 | 0x10000;
  }
  if ((in_FPUControlWord & 0x1000) != 0) {
    uVar5 = uVar5 | 0x40000;
  }
  uVar2 = ~_Mask & uVar5 | _NewValue & _Mask;
  if (uVar2 != uVar5) {
    uVar5 = func_0x5790630c();
    uVar2 = 0;
    if ((uVar5 & 1) != 0) {
      uVar2 = 0x10;
    }
    if ((uVar5 & 4) != 0) {
      uVar2 = uVar2 | 8;
    }
    if ((uVar5 & 8) != 0) {
      uVar2 = uVar2 | 4;
    }
    if ((uVar5 & 0x10) != 0) {
      uVar2 = uVar2 | 2;
    }
    if ((uVar5 & 0x20) != 0) {
      uVar2 = uVar2 | 1;
    }
    if ((uVar5 & 2) != 0) {
      uVar2 = uVar2 | 0x80000;
    }
    uVar3 = uVar5 & 0xc00;
    if (uVar3 != 0) {
      if (uVar3 == 0x400) {
        uVar2 = uVar2 | 0x100;
      }
      else if (uVar3 == 0x800) {
        uVar2 = uVar2 | 0x200;
      }
      else if (uVar3 == 0xc00) {
        uVar2 = uVar2 | 0x300;
      }
    }
    if ((uVar5 & 0x300) == 0) {
      uVar2 = uVar2 | 0x20000;
    }
    else if ((uVar5 & 0x300) == 0x200) {
      uVar2 = uVar2 | 0x10000;
    }
    if ((uVar5 & 0x1000) != 0) {
      uVar2 = uVar2 | 0x40000;
    }
  }
  uVar5 = 0;
  if (DAT_00437ea4 != 0) {
    if ((char)MXCSR < '\0') {
      uVar5 = 0x10;
    }
    if ((MXCSR & 0x200) != 0) {
      uVar5 = uVar5 | 8;
    }
    if ((MXCSR & 0x400) != 0) {
      uVar5 = uVar5 | 4;
    }
    if ((MXCSR & 0x800) != 0) {
      uVar5 = uVar5 | 2;
    }
    if ((MXCSR & 0x1000) != 0) {
      uVar5 = uVar5 | 1;
    }
    if ((MXCSR & 0x100) != 0) {
      uVar5 = uVar5 | 0x80000;
    }
    uVar3 = MXCSR & 0x6000;
    if (uVar3 != 0) {
      if (uVar3 == 0x2000) {
        uVar5 = uVar5 | 0x100;
      }
      else if (uVar3 == 0x4000) {
        uVar5 = uVar5 | 0x200;
      }
      else if (uVar3 == 0x6000) {
        uVar5 = uVar5 | 0x300;
      }
    }
    uVar3 = MXCSR & 0x8040;
    if (uVar3 == 0x40) {
      uVar5 = uVar5 | 0x2000000;
    }
    else if (uVar3 == 0x8000) {
      uVar5 = uVar5 | 0x3000000;
    }
    else if (uVar3 == 0x8040) {
      uVar5 = uVar5 | 0x1000000;
    }
    if ((~(_Mask & 0x308031f) & uVar5 | _Mask & 0x308031f & _NewValue) == uVar5) {
                    // WARNING: Bad instruction - Truncating control flow here
      halt_baddata();
    }
    uVar4 = func_0xe590648e();
    func_0x1a976497(uVar4);
    uVar5 = 0;
    if ((char)MXCSR < '\0') {
      uVar5 = 0x10;
    }
    if ((MXCSR & 0x200) != 0) {
      uVar5 = uVar5 | 8;
    }
    if ((MXCSR & 0x400) != 0) {
      uVar5 = uVar5 | 4;
    }
    if ((MXCSR & 0x800) != 0) {
      uVar5 = uVar5 | 2;
    }
    if ((MXCSR & 0x1000) != 0) {
      uVar5 = uVar5 | 1;
    }
    if ((MXCSR & 0x100) != 0) {
      uVar5 = uVar5 | 0x80000;
    }
    uVar3 = MXCSR & 0x6000;
    if (uVar3 != 0) {
      if (uVar3 == 0x2000) {
        uVar5 = uVar5 | 0x100;
      }
      else if (uVar3 == 0x4000) {
        uVar5 = uVar5 | 0x200;
      }
      else if (uVar3 == 0x6000) {
        uVar5 = uVar5 | 0x300;
      }
    }
    uVar3 = MXCSR & 0x8040;
    if (uVar3 == 0x40) {
      uVar5 = uVar5 | 0x2000000;
    }
    else if (uVar3 == 0x1bd20240) {
      uVar5 = uVar5 | 0x3000000;
    }
    else if (uVar3 == 0x1bd20280) {
      uVar5 = uVar5 | 0x1000000;
    }
    uVar3 = uVar5 ^ uVar2;
    uVar2 = uVar5 | uVar2;
    if ((uVar3 & 0x8031f) != 0) {
      uVar2 = uVar2 | 0x80000000;
    }
  }
  return uVar2;
}



// Library Function - Single Match
//  ___crtLCMapStringW
// 
// Library: Visual Studio 2008 Release

int __cdecl
___crtLCMapStringW(LPCWSTR _LocaleName,DWORD _DWMapFlag,LPCWSTR _LpSrcStr,int _CchSrc,
                  LPWSTR _LpDestStr,int _CchDest)

{
  int iVar1;
  short *psVar2;
  LPWSTR pWVar3;
  undefined4 in_stack_0000001c;
  int local_c;
  char local_8;
  
  func_0x12716466(_LocaleName);
  psVar2 = (short *)_CchSrc;
  pWVar3 = _LpDestStr;
  if (0 < (int)_LpDestStr) {
    do {
      pWVar3 = (LPWSTR)((int)pWVar3 + -1);
      if (*psVar2 == 0) goto LAB_004262cc;
      psVar2 = psVar2 + 1;
    } while (pWVar3 != (LPWSTR)0x0);
    pWVar3 = (LPWSTR)0xffffffff;
LAB_004262cc:
    _LpDestStr = (LPWSTR)((int)_LpDestStr + (-1 - (int)pWVar3));
  }
  iVar1 = (*DAT_00428150)(_DWMapFlag,_LpSrcStr,_CchSrc,_LpDestStr,_CchDest,in_stack_0000001c);
  if (local_8 != '\0') {
    *(uint *)(local_c + 0x70) = *(uint *)(local_c + 0x70) & 0xfffffffd;
  }
  return iVar1;
}



// Library Function - Single Match
//  ___ascii_strnicmp
// 
// Library: Visual Studio

int __cdecl ___ascii_strnicmp(char *_Str1,char *_Str2,size_t _MaxCount)

{
  char cVar1;
  byte bVar2;
  ushort uVar3;
  uint uVar4;
  bool bVar5;
  
  if (_MaxCount != 0) {
    do {
      bVar2 = *_Str1;
      cVar1 = *_Str2;
      uVar3 = CONCAT11(bVar2,cVar1);
      if (bVar2 == 0) break;
      uVar3 = CONCAT11(bVar2,cVar1);
      uVar4 = (uint)uVar3;
      if (cVar1 == '\0') break;
      _Str1 = (char *)((byte *)_Str1 + 1);
      _Str2 = _Str2 + 1;
      if ((0x40 < bVar2) && (bVar2 < 0x5b)) {
        uVar4 = (uint)CONCAT11(bVar2 + 0x20,cVar1);
      }
      uVar3 = (ushort)uVar4;
      bVar2 = (byte)uVar4;
      if ((0x40 < bVar2) && (bVar2 < 0x5b)) {
        uVar3 = (ushort)CONCAT31((int3)(uVar4 >> 8),bVar2 + 0x20);
      }
      bVar2 = (byte)(uVar3 >> 8);
      bVar5 = bVar2 < (byte)uVar3;
      if (bVar2 != (byte)uVar3) goto LAB_00426345;
      _MaxCount = _MaxCount - 1;
    } while (_MaxCount != 0);
    _MaxCount = 0;
    bVar2 = (byte)(uVar3 >> 8);
    bVar5 = bVar2 < (byte)uVar3;
    if (bVar2 != (byte)uVar3) {
LAB_00426345:
      _MaxCount = 0xffffffff;
      if (!bVar5) {
        _MaxCount = 1;
      }
    }
  }
  return _MaxCount;
}



// Library Function - Single Match
//  ___mtold12
// 
// Library: Visual Studio 2008 Release

void __cdecl ___mtold12(char *param_1,int param_2,uint *param_3)

{
  uint uVar1;
  uint uVar2;
  uint uVar3;
  bool bVar4;
  bool bVar5;
  short sVar6;
  uint uVar7;
  uint uVar8;
  uint uVar9;
  uint uVar10;
  
  sVar6 = 0x2b6;
  *param_3 = 0;
  param_3[1] = 0;
  param_3[2] = 0;
  if (param_2 != 0) {
    do {
      uVar2 = *param_3;
      uVar9 = *param_3;
      uVar1 = param_3[1];
      uVar10 = param_3[2];
      uVar8 = param_3[1] * 2;
      bVar4 = false;
      uVar7 = (param_3[2] * 2 | param_3[1] >> 0x1f) * 2 | uVar8 >> 0x1f;
      uVar3 = uVar2 * 4;
      uVar8 = (uVar8 | uVar2 >> 0x1f) * 2 | uVar2 * 2 >> 0x1f;
      uVar2 = uVar3 + uVar9;
      *param_3 = uVar3;
      param_3[1] = uVar8;
      param_3[2] = uVar7;
      if ((uVar2 < uVar3) || (uVar2 < uVar9)) {
        bVar4 = true;
      }
      bVar5 = false;
      *param_3 = uVar2;
      if (bVar4) {
        uVar9 = uVar8 + 1;
        if ((uVar9 < uVar8) || (uVar9 == 0)) {
          bVar5 = true;
        }
        param_3[1] = uVar9;
        if (bVar5) {
          param_3[2] = uVar7 + 1;
        }
      }
      uVar9 = param_3[1] + uVar1;
      bVar4 = false;
      if ((uVar9 < param_3[1]) || (uVar9 < uVar1)) {
        bVar4 = true;
      }
      param_3[1] = uVar9;
      if (bVar4) {
        param_3[2] = param_3[2] + 1;
      }
      param_3[2] = param_3[2] + uVar10;
      bVar4 = false;
      uVar1 = uVar2 * 2;
      uVar10 = uVar9 * 2 | uVar2 >> 0x1f;
      uVar9 = param_3[2] * 2 | uVar9 >> 0x1f;
      *param_3 = uVar1;
      param_3[1] = uVar10;
      param_3[2] = uVar9;
      uVar2 = uVar1 + (int)*param_1;
      if ((uVar2 < uVar1) || (uVar2 < (uint)(int)*param_1)) {
        bVar4 = true;
      }
      *param_3 = uVar2;
      if (bVar4) {
        uVar2 = uVar10 + 1;
        bVar4 = false;
        if ((uVar2 < uVar10) || (uVar2 == 0)) {
          bVar4 = true;
        }
        param_3[1] = uVar2;
        if (bVar4) {
          param_3[2] = uVar9 + 1;
        }
      }
      param_2 = param_2 + -1;
      param_1 = param_1 + 1;
    } while (param_2 != 0);
  }
  while (param_3[2] == 0) {
    param_3[2] = param_3[1] >> 0x10;
    sVar6 = sVar6 + 0x3b6;
    param_3[1] = param_3[1] << 0x10 | *param_3 >> 0x10;
    *param_3 = *param_3 << 0x10;
  }
  uVar2 = param_3[2];
  while ((uVar2 & 0x8000) == 0) {
    uVar9 = *param_3;
    uVar1 = param_3[1];
    sVar6 = sVar6 + 0x3b6;
    *param_3 = uVar9 * 2;
    uVar2 = param_3[2] * 2;
    param_3[1] = uVar1 * 2 | uVar9 >> 0x1f;
    param_3[2] = uVar2 | uVar1 >> 0x1f;
  }
  *(short *)((int)param_3 + 10) = sVar6;
  func_0x486066d7();
  return;
}



// WARNING: Control flow encountered bad instruction data

void __fastcall FUN_0042cc58(char *param_1)

{
  char cVar1;
  char *in_EAX;
  int unaff_EBX;
  int iVar2;
  
  cVar1 = (char)in_EAX;
  *in_EAX = *in_EAX + cVar1;
  *in_EAX = *in_EAX + cVar1;
  *in_EAX = *in_EAX + cVar1;
  *in_EAX = *in_EAX + cVar1;
  *in_EAX = *in_EAX + cVar1;
  in_EAX[0x17] = in_EAX[0x17] + cVar1;
  iVar2 = unaff_EBX + 1;
  (&stack0x00000000)[iVar2 * 8] = (&stack0x00000000)[iVar2 * 8] + (char)param_1;
  *in_EAX = *in_EAX + cVar1;
  *in_EAX = *in_EAX + cVar1;
  *in_EAX = *in_EAX + cVar1;
  *in_EAX = *in_EAX + cVar1;
  *param_1 = *param_1 + cVar1;
  *in_EAX = *in_EAX + cVar1;
  (&stack0x00000000)[iVar2 * 8] = (&stack0x00000000)[iVar2 * 8] + (char)iVar2;
  (&stack0x00000000)[iVar2 * 8] = (&stack0x00000000)[iVar2 * 8] + (char)((uint)in_EAX >> 8);
  *in_EAX = *in_EAX + cVar1;
  *in_EAX = *in_EAX + cVar1;
  in_EAX[0x17] = in_EAX[0x17] + cVar1;
  *in_EAX = *in_EAX + cVar1;
  *in_EAX = *in_EAX + cVar1;
  *in_EAX = *in_EAX + cVar1;
  *in_EAX = *in_EAX + cVar1;
                    // WARNING: Bad instruction - Truncating control flow here
  halt_baddata();
}



// WARNING: Globals starting with '_' overlap smaller symbols at the same address

void __fastcall FUN_0048545b(int param_1,int param_2,undefined4 param_3,int param_4)

{
  undefined4 uVar1;
  byte bVar2;
  char extraout_DH;
  int unaff_ESI;
  int unaff_EDI;
  char cVar4;
  int *piVar3;
  
  uVar1 = _DAT_e0e7f000;
  _DAT_fc14a17c = param_4 + 0xb;
  *(int *)(unaff_ESI + 3) = *(int *)(unaff_ESI + 3) + param_2;
  bVar2 = in(0xe);
  piVar3 = (int *)CONCAT31((int3)((uint)_DAT_fc14a17c >> 8),bVar2);
  *piVar3 = *piVar3 + -0x3a;
  cVar4 = 0xd4 < bVar2;
  *(undefined *)(param_1 + -0x1d) = *(undefined *)(param_1 + -0x1d);
  func_0x00d49501(uVar1);
  *(char *)(unaff_EDI + 0x6e00b81d) = *(char *)(unaff_EDI + 0x6e00b81d) + extraout_DH + cVar4;
  do {
                    // WARNING: Do nothing block with infinite loop
  } while( true );
}


