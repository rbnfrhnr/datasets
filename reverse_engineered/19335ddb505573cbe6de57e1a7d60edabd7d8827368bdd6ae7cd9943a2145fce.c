typedef unsigned char   undefined;

typedef pointer32 ImageBaseOffset32;

typedef unsigned char    byte;
typedef unsigned int    dword;
typedef unsigned char    uchar;
typedef unsigned int    uint;
typedef unsigned long    ulong;
typedef unsigned char    undefined1;
typedef unsigned int    undefined4;
typedef unsigned short    ushort;
typedef int    wchar_t;
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

typedef struct _SECURITY_ATTRIBUTES _SECURITY_ATTRIBUTES, *P_SECURITY_ATTRIBUTES;

typedef ulong DWORD;

typedef void *LPVOID;

typedef int BOOL;

struct _SECURITY_ATTRIBUTES {
    DWORD nLength;
    LPVOID lpSecurityDescriptor;
    BOOL bInheritHandle;
};

typedef struct _SECURITY_ATTRIBUTES SECURITY_ATTRIBUTES;

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

typedef wchar_t WCHAR;

typedef long HRESULT;

typedef char CHAR;

typedef CHAR *LPCSTR;

typedef long LONG;

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

typedef WCHAR *LPCWSTR;

typedef union _LARGE_INTEGER LARGE_INTEGER;

typedef void *HANDLE;

typedef WCHAR *LPWSTR;

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
    byte e_program[448]; // Actual DOS program
};

typedef struct IStreamVtbl IStreamVtbl, *PIStreamVtbl;

typedef struct IStream IStream, *PIStream;

typedef DWORD ULONG;

typedef struct tagSTATSTG tagSTATSTG, *PtagSTATSTG;

typedef struct tagSTATSTG STATSTG;

typedef WCHAR OLECHAR;

typedef OLECHAR *LPOLESTR;

typedef struct _FILETIME _FILETIME, *P_FILETIME;

typedef struct _FILETIME FILETIME;

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

typedef ushort WORD;

typedef WORD CLIPFORMAT;

typedef struct tagDVTARGETDEVICE tagDVTARGETDEVICE, *PtagDVTARGETDEVICE;

typedef struct tagDVTARGETDEVICE DVTARGETDEVICE;

typedef uchar BYTE;

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

typedef OLECHAR *BSTR;

typedef struct _IMAGELIST _IMAGELIST, *P_IMAGELIST;

typedef struct _IMAGELIST *HIMAGELIST;

struct _IMAGELIST {
};

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

typedef int INT;

typedef struct HINSTANCE__ HINSTANCE__, *PHINSTANCE__;

struct HINSTANCE__ {
    int unused;
};

typedef struct HKEY__ *HKEY;

typedef struct HINSTANCE__ *HINSTANCE;

typedef struct HWND__ HWND__, *PHWND__;

typedef struct HWND__ *HWND;

struct HWND__ {
    int unused;
};

typedef HINSTANCE HMODULE;

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

typedef struct IMAGE_RESOURCE_DIR_STRING_U_16 IMAGE_RESOURCE_DIR_STRING_U_16, *PIMAGE_RESOURCE_DIR_STRING_U_16;

struct IMAGE_RESOURCE_DIR_STRING_U_16 {
    word Length;
    wchar16 NameString[8];
};

typedef struct IMAGE_RESOURCE_DIR_STRING_U_12 IMAGE_RESOURCE_DIR_STRING_U_12, *PIMAGE_RESOURCE_DIR_STRING_U_12;

struct IMAGE_RESOURCE_DIR_STRING_U_12 {
    word Length;
    wchar16 NameString[6];
};

typedef LONG LSTATUS;

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

typedef struct IUnknown *LPUNKNOWN;




// WARNING: Instruction at (ram,0x005a61e4) overlaps instruction at (ram,0x005a61e3)
// 
// WARNING: Globals starting with '_' overlap smaller symbols at the same address

void __stdcall FUN_005a6133(undefined4 param_1,char param_2,uint param_3)

{
  uint *puVar1;
  char *pcVar2;
  byte *pbVar3;
  byte bVar4;
  undefined4 uVar5;
  int iVar6;
  byte bVar7;
  undefined uVar8;
  uint in_ECX;
  uint unaff_EBX;
  undefined *puVar10;
  int unaff_EDI;
  bool bVar11;
  byte in_AF;
  int iStack_c;
  uint uVar9;
  
  puVar10 = &stack0xfffffffc;
  if (param_2 == '\0') {
    puVar1 = (uint *)(param_3 + 0x2e158811);
    bVar11 = CARRY4(*puVar1,in_ECX);
    *puVar1 = *puVar1 + in_ECX;
    puVar10 = (undefined *)0x2ddb83b8;
  }
  else {
    DAT_3fefee18 = 0xaf;
    _DAT_8b15eb19 = _DAT_8b15eb19 + in_ECX;
    param_3 = param_3 | 0x88117fc8;
    puVar1 = (uint *)(param_3 + 0xb8bd2e15);
    uVar9 = *puVar1;
    *puVar1 = *puVar1 + in_ECX;
    bVar11 = unaff_EBX < 0x2d || unaff_EBX - 0x2d < (uint)CARRY4(uVar9,in_ECX);
    unaff_EBX = (unaff_EBX - 0x2d) - (uint)CARRY4(uVar9,in_ECX);
  }
  iVar6 = _DAT_ffc318d8;
  uVar5 = _DAT_0289c8d0;
  bVar7 = (*(char *)(unaff_EBX + (param_3 & 0xff)) + ']') - bVar11;
  bVar4 = 9 < (bVar7 & 0xf) | in_AF;
  uVar9 = CONCAT31((int3)(param_3 >> 8),bVar7 + bVar4 * '\x06') & 0xffffff0f;
  uVar8 = (undefined)uVar9;
  _DAT_9e705e10 = CONCAT22((short)(uVar9 >> 0x10),CONCAT11((char)(param_3 >> 8) + bVar4,uVar8));
  out((short)param_1,uVar8);
  puVar10[0x38] = puVar10[0x38] + (char)((uint)param_1 >> 8);
  _DAT_1a6b140d = _DAT_1a6b140d + CONCAT31((int3)(unaff_EBX >> 8),0xd);
  iStack_c = 0x3d804c01;
  puVar1 = (uint *)((unaff_EDI - _DAT_719491f8) + 0x3b831697);
  *puVar1 = *puVar1 | 0x45;
  *(int *)(iVar6 + 0x33d08913) = (int)(&DAT_1a6b140d + *(int *)(iVar6 + 0x33d08913));
  DAT_3b289f20 = DAT_3b289f20 >> 5 | DAT_3b289f20 << 3;
  pcVar2 = (char *)(iVar6 * 9 + -0x2a);
  *pcVar2 = *pcVar2 + (char)((uint)iVar6 >> 8) + ((char)DAT_3b289f20 < '\0');
  puVar10[-0x11] = puVar10[-0x11] & (byte)((uint)uVar5 >> 8);
  pbVar3 = (byte *)(iStack_c * 5 + 0x20);
  *pbVar3 = *pbVar3 ^ 0xf0;
  _DAT_ed27702c = _DAT_ed27702c + 1;
  return;
}


