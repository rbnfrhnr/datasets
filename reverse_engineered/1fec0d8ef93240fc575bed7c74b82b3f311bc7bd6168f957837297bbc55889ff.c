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

typedef struct _IMAGE_SECTION_HEADER _IMAGE_SECTION_HEADER, *P_IMAGE_SECTION_HEADER;

typedef struct _IMAGE_SECTION_HEADER *PIMAGE_SECTION_HEADER;

typedef uchar BYTE;

typedef union _union_226 _union_226, *P_union_226;

typedef ulong DWORD;

typedef ushort WORD;

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

typedef wchar_t WCHAR;

typedef char CHAR;

typedef CHAR *LPCSTR;

typedef WCHAR *LPCWSTR;

typedef CHAR *LPSTR;

typedef WCHAR *LPWSTR;

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

typedef ULONG_PTR DWORD_PTR;

typedef ULONG_PTR SIZE_T;

typedef struct _EXCEPTION_POINTERS _EXCEPTION_POINTERS, *P_EXCEPTION_POINTERS;

struct _EXCEPTION_POINTERS {
    PEXCEPTION_RECORD ExceptionRecord;
    PCONTEXT ContextRecord;
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

typedef struct HINSTANCE__ HINSTANCE__, *PHINSTANCE__;

typedef struct HINSTANCE__ *HINSTANCE;

struct HINSTANCE__ {
    int unused;
};

typedef void *LPVOID;

typedef HINSTANCE HMODULE;

typedef WORD *LPWORD;

typedef int BOOL;

typedef uint UINT;

typedef BYTE *PBYTE;

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

typedef struct IMAGE_RESOURCE_DIRECTORY_ENTRY_NameStruct IMAGE_RESOURCE_DIRECTORY_ENTRY_NameStruct, *PIMAGE_RESOURCE_DIRECTORY_ENTRY_NameStruct;

struct IMAGE_RESOURCE_DIRECTORY_ENTRY_NameStruct {
    dword NameOffset;
    dword NameIsString;
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

typedef char *va_list;

typedef uint uintptr_t;

typedef struct EHRegistrationNode EHRegistrationNode, *PEHRegistrationNode;

struct EHRegistrationNode { // PlaceHolder Structure
};

typedef struct _s_CatchableType _s_CatchableType, *P_s_CatchableType;

struct _s_CatchableType { // PlaceHolder Structure
};

typedef struct type_info type_info, *Ptype_info;

struct type_info { // PlaceHolder Structure
};

typedef struct _s_FuncInfo _s_FuncInfo, *P_s_FuncInfo;

struct _s_FuncInfo { // PlaceHolder Structure
};

typedef struct EHExceptionRecord EHExceptionRecord, *PEHExceptionRecord;

struct EHExceptionRecord { // PlaceHolder Structure
};

typedef struct _s_HandlerType _s_HandlerType, *P_s_HandlerType;

struct _s_HandlerType { // PlaceHolder Structure
};

typedef struct _LocaleUpdate _LocaleUpdate, *P_LocaleUpdate;

struct _LocaleUpdate { // PlaceHolder Structure
};

typedef struct _s_ESTypeList _s_ESTypeList, *P_s_ESTypeList;

struct _s_ESTypeList { // PlaceHolder Structure
};

typedef struct _s_TryBlockMapEntry _s_TryBlockMapEntry, *P_s_TryBlockMapEntry;

struct _s_TryBlockMapEntry { // PlaceHolder Structure
};

typedef struct exception exception, *Pexception;

struct exception { // PlaceHolder Structure
};

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




void FUN_00401004(void)

{
  int iVar1;
  int iStack_120;
  uint local_11c [67];
  ushort uStack_10;
  uint local_4;
  
  local_4 = s__Repeat_del___s__if_exist___s__g_00422037._13_4_ ^ (uint)&iStack_120;
  func_0x9c0e1079(local_11c,0,0x118);
  iStack_120 = 0x11c;
  iVar1 = (*DAT_0041c0ec)(&iStack_120);
  if (iVar1 != 0) {
    if (iStack_120 == 5) {
      if (local_11c[0] == 0) {
        if (3 < uStack_10) {
          func_0xf1d510c9();
          return;
        }
      }
      else if ((1 < local_11c[0]) || (local_11c[0] == 1)) {
        func_0xf1d510f0();
        return;
      }
    }
    else if ((iStack_120 == 6) && (local_11c[0] == 0)) {
      func_0xf1d5111a();
      return;
    }
  }
  func_0xf1d5113c();
  return;
}



// WARNING: Control flow encountered bad instruction data
// WARNING: Globals starting with '_' overlap smaller symbols at the same address

void __cdecl
FUN_00401104(undefined4 param_1,short param_2,undefined4 param_3,int param_4,undefined4 param_5)

{
  short sVar1;
  undefined4 uVar2;
  undefined4 uVar3;
  undefined4 uVar4;
  code *pcVar5;
  undefined4 *puVar6;
  int iVar7;
  int iVar8;
  undefined4 *puVar9;
  short *psVar10;
  undefined2 uVar11;
  int unaff_EBX;
  int unaff_EBP;
  int iVar12;
  int iVar13;
  short sStack00000088;
  undefined2 uStack0000012a;
  short in_stack_0000012c;
  short in_stack_0000014c;
  short in_stack_0000016c;
  short in_stack_0000018c;
  short in_stack_000001ac;
  int iStack000001cc;
  undefined4 in_stack_000001d0;
  int in_stack_0000020c;
  undefined2 in_stack_00000308;
  ushort in_stack_0000030e;
  ushort in_stack_000004c0;
  undefined2 in_stack_00000562;
  uint uStack_14;
  
  func_0x9b7f125c();
  uStack_14 = 0x206;
  param_3 = 0;
  func_0x9c0e1191();
  uStack_14 = 0x206;
  func_0x9c0e11b1();
  uStack_14 = 0x206;
  func_0x9c0e11d1();
  uStack_14 = 0x7e;
  func_0x9c0e1231();
  uStack_14 = 0x7e;
  func_0x9c0e124e();
  uStack_14 = 0x7e;
  iVar13 = 0;
  func_0x9c0e126f();
  uStack_14 = 0x206;
  func_0x9c0e128f();
  uStack_14 = 0x206;
  iVar12 = 0;
  func_0x9c0e12f4();
  uStack_14 = 0x206;
  func_0x9c0e1314();
  uStack_14 = 0x200;
  func_0x9c0e1327();
  uStack_14 = 1;
  iVar7 = func_0xeb4b1335();
  uStack_14 = 0;
  param_4 = iVar7;
  param_5 = func_0xeb4b134b();
  uStack_14 = 0x104;
  (*DAT_0041c0b0)();
  pcVar5 = ram0x0041c0ac;
  (*ram0x0041c0ac)();
  func_0x00d61392();
  psVar10 = (short *)&stack0x000007fc;
  do {
    sVar1 = *psVar10;
    psVar10 = psVar10 + 1;
  } while (sVar1 != 0);
  if (((int)psVar10 - (int)&stack0x000007fe >> 1 != 0) &&
     (iVar8 = (*(code *)s_Microsoft_Visual_C___Runtime_Lib_0041c089._31_4_)(), iVar8 != -1)) {
    (*(code *)s_Microsoft_Visual_C___Runtime_Lib_0041c089._27_4_)();
  }
  if (iVar7 == 0) {
    uVar11 = 0;
    if (DAT_0042306c == 3) {
      func_0x9c0e1691();
      unaff_EBP = func_0xeb5016a0();
      if (unaff_EBP != 0) {
        iVar12 = 0;
        do {
          psVar10 = (short *)(&stack0x00000312 + iVar12);
          *(short *)(&stack0x0000077c + iVar12) = *psVar10;
          iVar12 = iVar12 + 2;
        } while (*psVar10 != 0);
        func_0x0b5516dd();
        uStack_14 = (uint)in_stack_0000030e;
        iVar12 = in_stack_0000020c;
        func_0x0b5516fc();
        func_0x7dd61722();
        uVar11 = in_stack_00000308;
      }
    }
    if (iVar13 != 0) {
      iVar12 = 0;
      do {
        psVar10 = (short *)(&stack0x000004c2 + iVar12);
        *(short *)(&stack0x0000077c + iVar12) = *psVar10;
        iVar12 = iVar12 + 2;
      } while (*psVar10 != 0);
      iVar12 = 0;
      do {
        psVar10 = (short *)(&stack0x00000440 + iVar12);
        *(short *)(&stack0x000006fc + iVar12) = *psVar10;
        iVar12 = iVar12 + 2;
      } while (*psVar10 != 0);
      uStack_14 = (uint)in_stack_000004c0;
      iVar12 = 0;
      do {
        sVar1 = *(short *)((int)&DAT_0041fe38 + iVar12);
        *(short *)(&stack0x0000067c + iVar12) = sVar1;
        iVar12 = iVar12 + 2;
      } while (sVar1 != 0);
      iVar12 = 5;
      if (DAT_0042306c == 3) {
        (*(code *)s_R6009___not_enough_space_for_env_0041c001._39_4_)();
        func_0x00d617fe();
      }
      else {
        (*ram0x0041c0ac)();
      }
      iVar7 = 0;
      do {
        psVar10 = (short *)(&stack0x00000c04 + iVar7);
        *(short *)(&stack0x00001014 + iVar7) = *psVar10;
        iVar7 = iVar7 + 2;
      } while (*psVar10 != 0);
      func_0x00d61841();
      (*(code *)s_Microsoft_Visual_C___Runtime_Lib_0041c089._27_4_)();
      uVar11 = in_stack_00000562;
    }
    func_0x9c0e1863();
    sStack00000088 = 0x51;
    iVar7 = 0;
    do {
      sVar1 = *(short *)((int)&DAT_0041fe6c + iVar7);
      *(short *)((int)&param_2 + iVar7) = sVar1;
      iVar7 = iVar7 + 2;
    } while (sVar1 != 0);
    uStack0000012a = 0x2b66;
    iVar7 = 0;
    do {
      sVar1 = *(short *)((int)&DAT_0041fe88 + iVar7);
      *(short *)(&stack0x000000aa + iVar7) = sVar1;
      iVar7 = iVar7 + 2;
    } while (sVar1 != 0);
    iVar7 = 0;
    do {
      sVar1 = *(short *)((int)&DAT_0041fea4 + iVar7);
      *(short *)(&stack0x0000008a + iVar7) = sVar1;
      iVar7 = iVar7 + 2;
    } while (sVar1 != 0);
    iStack000001cc = 5;
    if (((unaff_EBX != 0) || (unaff_EBP != 0)) || (iVar13 != 0)) {
      func_0x7dd6191d();
      func_0x7dd61934();
      sStack00000088 = (short)uStack_14;
      func_0x7dd6195b();
      uStack0000012a = uVar11;
      iStack000001cc = iVar12;
      if (iVar12 == 0) {
        iStack000001cc = 5;
      }
    }
    if ((param_2 != 0) && (sStack00000088 != 0)) {
      (*(code *)s_R6009___not_enough_space_for_env_0041c001._35_4_)();
      func_0xecd619a7();
      func_0x9c0e19c7();
      if (in_stack_0000012c == 0) {
        func_0x8b5519e2();
        func_0x7dd619fc();
      }
      if (in_stack_0000014c == 0) {
        func_0x8b551a17();
        func_0x7dd61a31();
      }
      if (in_stack_0000018c == 0) {
        func_0x8b551a4c();
        func_0x7dd61a66();
      }
      if (in_stack_000001ac == 0) {
        func_0x8b551a81();
        func_0x7dd61a9b();
        psVar10 = (short *)&stack0x0000063c;
        do {
          sVar1 = *psVar10;
          psVar10 = psVar10 + 1;
        } while (sVar1 != 0);
        if ((int)psVar10 - (int)&stack0x0000063e >> 1 != 0) {
          func_0x7dd61ad0();
        }
      }
      psVar10 = (short *)&stack0x0000065c;
      do {
        sVar1 = *psVar10;
        psVar10 = psVar10 + 1;
      } while (sVar1 != 0);
      if ((int)psVar10 - (int)&stack0x0000065e >> 1 != 0) {
        func_0x7dd61b0a();
      }
      if (in_stack_0000016c == 0) {
        func_0x8b551b25();
        func_0x7dd61b3f();
      }
      in_stack_000001d0 = 0x1000237;
      if (iStack000001cc == 0) {
        iStack000001cc = 5;
      }
      iVar12 = func_0xbb561b6c();
      if (iVar12 != 0) {
        psVar10 = (short *)&stack0x000007fc;
        func_0xab4e1b8a();
        func_0x4b581b99();
        iVar12 = (*(code *)s_R6009___not_enough_space_for_env_0041c001._11_4_)();
        if (iVar12 == 0) {
          do {
            sVar1 = *psVar10;
            psVar10 = psVar10 + 1;
          } while (sVar1 != 0);
          iVar12 = (*(code *)s_R6009___not_enough_space_for_env_0041c001._7_4_)();
          if (iVar12 == 0) {
            (*(code *)s_R6009___not_enough_space_for_env_0041c001._3_4_)();
          }
        }
        (*DAT_0041c184)();
      }
    }
    func_0xf1d51c37();
    return;
  }
  (*pcVar5)();
  func_0x00d61405();
  func_0x00d6141f();
  psVar10 = (short *)&stack0x000007f4;
  do {
    sVar1 = *psVar10;
    psVar10 = psVar10 + 1;
  } while (sVar1 != 0);
  if (((int)psVar10 - (int)&stack0x000007f6 >> 1 != 0) &&
     (iVar12 = (*(code *)s_Microsoft_Visual_C___Runtime_Lib_0041c089._31_4_)(), iVar12 != -1)) {
    iVar12 = 0;
    do {
      psVar10 = (short *)(&stack0x00000184 + iVar12);
      *(short *)(&stack0x000001fc + iVar12) = *psVar10;
      iVar12 = iVar12 + 2;
    } while (*psVar10 != 0);
    func_0x00d61491();
    (*(code *)s_Microsoft_Visual_C___Runtime_Lib_0041c089._27_4_)();
  }
  func_0x7dd614b9();
  func_0xab4e14cf();
  iVar12 = func_0x4b4f14d4();
  uVar4 = s_Microsoft_Visual_C___Runtime_Lib_0041c089._23_4_;
  if (iVar12 != 1) {
    iVar12 = 0;
    do {
      psVar10 = (short *)(&stack0x000001a4 + iVar12);
      *(short *)(&stack0x000009fc + iVar12) = *psVar10;
      iVar12 = iVar12 + 2;
    } while (*psVar10 != 0);
    iVar12 = 0;
    do {
      psVar10 = (short *)(&stack0x000001a4 + iVar12);
      *(short *)(&stack0x00000e0c + iVar12) = *psVar10;
      iVar12 = iVar12 + 2;
    } while (*psVar10 != 0);
    puVar6 = (undefined4 *)&stack0x00000e0a;
    do {
      puVar9 = puVar6;
      puVar6 = (undefined4 *)((int)puVar9 + 2);
    } while (*(short *)((int)puVar9 + 2) != 0);
    *(undefined4 *)((int)puVar9 + 2) = DAT_0041fe2c;
    *(undefined4 *)((int)puVar9 + 6) = DAT_0041fe30;
    *(undefined4 *)((int)puVar9 + 10) = DAT_0041fe34;
    iVar12 = (*(code *)s_Microsoft_Visual_C___Runtime_Lib_0041c089._23_4_)();
    uVar3 = s_R6002___floating_point_support_n_0041c059._35_4_;
    uVar2 = s_R6009___not_enough_space_for_env_0041c001._31_4_;
    if (iVar12 != 0) {
      (*(code *)s_R6002___floating_point_support_n_0041c059._35_4_)();
      (*(code *)s_R6009___not_enough_space_for_env_0041c001._27_4_)();
      iVar7 = (*(code *)uVar4)();
      for (iVar12 = 0; (iVar7 != 0 && (iVar12 < 5)); iVar12 = iVar12 + 1) {
        (*(code *)uVar3)();
        (*(code *)uVar2)();
        iVar7 = (*(code *)uVar4)();
      }
    }
    (*(code *)uVar2)();
    (*(code *)s_Microsoft_Visual_C___Runtime_Lib_0041c089._27_4_)();
    iVar12 = 0;
    do {
      psVar10 = (short *)(&stack0x0000006e + iVar12);
      *(short *)(&stack0x00000760 + iVar12) = *psVar10;
      iVar12 = iVar12 + 2;
    } while (*psVar10 != 0);
    iVar12 = 0;
    do {
      psVar10 = (short *)((int)&uStack_14 + iVar12);
      *(short *)(&stack0x000006e0 + iVar12) = *psVar10;
      iVar12 = iVar12 + 2;
    } while (*psVar10 != 0);
    iVar12 = 0;
    do {
      psVar10 = (short *)(&stack0x0000008e + iVar12);
      *(short *)(&stack0x00000660 + iVar12) = *psVar10;
      iVar12 = iVar12 + 2;
    } while (*psVar10 != 0);
                    // WARNING: Bad instruction - Truncating control flow here
    halt_baddata();
  }
                    // WARNING: Bad instruction - Truncating control flow here
  halt_baddata();
}



undefined4 __cdecl FUN_00402024(undefined4 *param_1)

{
  short sVar1;
  int in_EAX;
  undefined4 *puVar2;
  undefined4 uVar3;
  int iVar4;
  short *psVar5;
  undefined4 uVar6;
  undefined4 *puVar7;
  
  uVar6 = 0;
  if (in_EAX == -1) {
    return 0;
  }
  puVar2 = (undefined4 *)func_0x24e02090(0x400);
  func_0x9c0e20a1(puVar2,0,0x400);
  uVar3 = func_0x9b5120aa();
  iVar4 = func_0xdb5220b4(uVar3,puVar2);
  if (iVar4 == 0) goto LAB_004020d9;
  if (puVar2[1] == 0x5042475f) {
    psVar5 = (short *)((int)puVar2 + 0x10e);
    do {
      sVar1 = *psVar5;
      psVar5 = psVar5 + 1;
    } while (sVar1 != 0);
    if ((int)psVar5 - (int)(puVar2 + 0x44) >> 1 == 0) goto LAB_00402095;
  }
  else {
LAB_00402095:
    iVar4 = func_0xdb5220eb(0x1e,puVar2);
    if ((iVar4 == 0) || (puVar2[1] != 0x5042475f)) goto LAB_004020d9;
    psVar5 = (short *)((int)puVar2 + 0x10e);
    do {
      sVar1 = *psVar5;
      psVar5 = psVar5 + 1;
    } while (sVar1 != 0);
    if ((int)psVar5 - (int)(puVar2 + 0x44) >> 1 == 0) goto LAB_004020d9;
  }
  puVar7 = puVar2;
  for (iVar4 = 0x8d; iVar4 != 0; iVar4 = iVar4 + -1) {
    *param_1 = *puVar7;
    puVar7 = puVar7 + 1;
    param_1 = param_1 + 1;
  }
  *(undefined2 *)param_1 = *(undefined2 *)puVar7;
  uVar6 = 1;
LAB_004020d9:
  if (puVar2 != (undefined4 *)0x0) {
    func_0x89e02131(puVar2);
  }
  return uVar6;
}



// WARNING: Globals starting with '_' overlap smaller symbols at the same address

undefined4 FUN_004021a4(void)

{
  uint uVar1;
  int iVar2;
  int iVar3;
  uint uVar4;
  uint uVar5;
  undefined4 unaff_EBP;
  int iVar6;
  int iVar7;
  int unaff_retaddr;
  undefined auStack_10 [4];
  uint uStack_c;
  
  (*(code *)s_R6009___not_enough_space_for_env_0041c001._31_4_)(100);
  iVar6 = 0;
  iVar7 = 0;
  uVar5 = 0;
  uStack_c = 0;
  if (unaff_retaddr != -1) {
    iVar2 = func_0x24e02224(0xb69);
    iVar3 = (*ram0x0041c02c)(unaff_retaddr,0x70050,0,0,iVar2,0xb69,auStack_10,0);
    if (iVar3 != 0) {
      iVar3 = *(int *)(iVar2 + 0x34);
      uVar4 = uStack_c;
      if ((-1 < iVar3) && ((0 < iVar3 || (*(uint *)(iVar2 + 0x30) != 0)))) {
        uVar5 = *(uint *)(iVar2 + 0x38);
        iVar6 = *(int *)(iVar2 + 0x3c);
        uVar4 = *(uint *)(iVar2 + 0x30);
        iVar7 = iVar3;
      }
      iVar3 = *(int *)(iVar2 + 0xbd);
      uVar1 = *(uint *)(iVar2 + 0xb9);
      if ((iVar7 <= iVar3) && ((iVar7 < iVar3 || (uVar4 < uVar1)))) {
        uVar5 = *(uint *)(iVar2 + 0xc1);
        iVar6 = *(int *)(iVar2 + 0xc5);
        uVar4 = uVar1;
        iVar7 = iVar3;
        uStack_c = uVar1;
      }
      iVar3 = *(int *)(iVar2 + 0x146);
      uVar1 = *(uint *)(iVar2 + 0x142);
      if ((iVar7 <= iVar3) && ((iVar7 < iVar3 || (uVar4 < uVar1)))) {
        uVar5 = *(uint *)(iVar2 + 0x14a);
        iVar6 = *(int *)(iVar2 + 0x14e);
        uVar4 = uVar1;
        iVar7 = iVar3;
        uStack_c = uVar1;
      }
      iVar3 = *(int *)(iVar2 + 0x1cf);
      uVar1 = *(uint *)(iVar2 + 0x1cb);
      if ((iVar7 <= iVar3) && ((iVar7 < iVar3 || (uVar4 < uVar1)))) {
        uVar5 = *(uint *)(iVar2 + 0x1d3);
        iVar6 = *(int *)(iVar2 + 0x1d7);
        uVar4 = uVar1;
        iVar7 = iVar3;
        uStack_c = uVar1;
      }
      func_0xeba323ff(uVar5 + uVar4,iVar6 + iVar7 + (uint)CARRY4(uVar5,uVar4),0x200,0);
    }
    if (iVar2 != 0) {
      func_0x89e0230d(iVar2);
    }
  }
  (*(code *)s_R6009___not_enough_space_for_env_0041c001._31_4_)(100);
  return unaff_EBP;
}



void FUN_004022e4(undefined4 param_1,undefined4 param_2)

{
  int unaff_ESI;
  
  if (unaff_ESI != -1) {
    (*(code *)s_R6008___not_enough_space_for_arg_0041c02d._3_4_)();
  }
  return;
}



void FUN_00402454(void)

{
  int iVar1;
  int unaff_EBX;
  undefined4 *puVar2;
  undefined4 *puVar3;
  undefined2 local_40;
  undefined4 local_3e;
  undefined4 local_3a;
  undefined4 local_36;
  undefined4 local_32;
  undefined2 local_2e;
  undefined4 local_2c [9];
  undefined4 local_8;
  uint local_4;
  
  local_4 = s__Repeat_del___s__if_exist___s__g_00422037._13_4_ ^ (uint)&local_40;
  puVar2 = &DAT_0041ffbc;
  puVar3 = local_2c;
  for (iVar1 = 9; iVar1 != 0; iVar1 = iVar1 + -1) {
    *puVar3 = *puVar2;
    puVar2 = puVar2 + 1;
    puVar3 = puVar3 + 1;
  }
  local_8 = 0;
  local_40 = 0;
  local_3e = 0;
  local_3a = 0;
  local_36 = 0;
  local_32 = 0;
  local_2e = 0;
  if (-1 < unaff_EBX) {
    func_0xe3ee24fe();
    func_0x00d6250f(local_2c,0x14,&local_40);
    if (unaff_EBX != 0) {
      (*(code *)s_R6008___not_enough_space_for_arg_0041c02d._7_4_)(local_2c,0xc0000000);
      func_0xf1d5253b();
      return;
    }
    (*(code *)s_R6008___not_enough_space_for_arg_0041c02d._7_4_)(local_2c,0x80000000,3,0,3,0,0);
  }
  func_0xf1d5255a();
  return;
}



void __fastcall FUN_00402514(uint param_1)

{
  undefined2 local_24;
  undefined4 local_22;
  undefined4 local_1e;
  undefined4 local_1a;
  undefined4 local_16;
  undefined4 local_12;
  undefined4 local_e;
  undefined4 local_a;
  undefined2 local_6;
  uint local_4;
  
  local_4 = s__Repeat_del___s__if_exist___s__g_00422037._13_4_ ^ (uint)&local_24;
  local_24 = 0;
  local_22 = 0;
  local_1e = 0;
  local_1a = 0;
  local_16 = 0;
  local_12 = 0;
  local_e = 0;
  local_a = 0;
  local_6 = 0;
  func_0xcb7d25bf(&DAT_0041ffe0,param_1 >> 0x18,param_1 >> 0x10 & 0xff,param_1 >> 8 & 0xff,
                  param_1 & 0xff);
  func_0x7dd625cc();
  func_0xf1d525da();
  return;
}



void __cdecl FUN_00402594(int param_1)

{
  int iVar1;
  int iVar2;
  int iVar3;
  uint uVar4;
  int iVar5;
  int iVar6;
  int local_68 [4];
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
  undefined4 local_20;
  undefined4 local_1c;
  undefined4 local_18;
  undefined4 local_14;
  undefined4 local_10;
  undefined4 local_c;
  undefined4 local_8;
  undefined4 local_4;
  
  local_68[1] = 0xffffffff;
  local_68[2] = 0xffffffff;
  local_68[3] = 0xffffffff;
  local_54 = 0xffffffff;
  local_50 = 0xffffffff;
  local_4c = 0xffffffff;
  local_44 = 0xffffffff;
  local_40 = 0xffffffff;
  local_3c = 0xffffffff;
  local_38 = 0xffffffff;
  local_34 = 0xffffffff;
  local_2c = 0xffffffff;
  local_28 = 0xffffffff;
  local_24 = 0xffffffff;
  local_20 = 0xffffffff;
  local_1c = 0xffffffff;
  local_14 = 0xffffffff;
  local_10 = 0xffffffff;
  local_c = 0xffffffff;
  local_4 = 0xffffffff;
  local_8 = 1;
  local_18 = 1;
  local_30 = 1;
  local_48 = 1;
  local_58 = 1;
  local_68[0] = 1;
  func_0xfed62676();
  iVar1 = func_0x3ba3278f();
  iVar5 = 0;
  iVar6 = 0;
  if (0 < iVar1) {
    do {
      func_0xfed6269e();
      iVar2 = func_0x3ba327bd();
      uVar4 = local_68[iVar2] + iVar5 >> 0x1f;
      iVar3 = (local_68[iVar2] + iVar5 ^ uVar4) - uVar4;
      while (1 < iVar3) {
        iVar2 = iVar2 + 1;
        if (iVar2 == 0x1a) {
          iVar2 = 0;
        }
        uVar4 = local_68[iVar2] + iVar5 >> 0x1f;
        iVar3 = (local_68[iVar2] + iVar5 ^ uVar4) - uVar4;
      }
      iVar5 = iVar5 + local_68[iVar2];
      *(short *)(param_1 + iVar6 * 2) = (short)iVar2 + 0x61;
      iVar6 = iVar6 + 1;
    } while (iVar6 < iVar1);
  }
  return;
}



uint FUN_00402e74(void)

{
  undefined4 *puVar1;
  uint uVar2;
  uint *puVar3;
  int iVar4;
  int iVar5;
  undefined auStack_14 [4];
  int local_10 [4];
  
  local_10[0] = 0;
  local_10[1] = 0;
  local_10[2] = 0;
  local_10[3] = 0;
  iVar4 = 0;
  do {
    puVar1 = (undefined4 *)func_0x24e02ee9(0x20);
    *puVar1 = 0;
    puVar1[1] = 0;
    puVar1[2] = 0;
    puVar1[3] = 0;
    puVar1[4] = 0;
    local_10[iVar4] = (int)puVar1;
    puVar1[5] = 0;
    iVar4 = iVar4 + 1;
    puVar1[6] = 0;
    puVar1[7] = 0;
  } while (iVar4 < 4);
  iVar4 = func_0x6b5f2f1d(local_10);
  if (iVar4 != 4) {
    return 0;
  }
  iVar4 = func_0xcdea2f40(local_10[0],auStack_14,10);
  uVar2 = func_0xcdea2f53(local_10[1],auStack_14,10);
  puVar3 = (uint *)func_0xcdea2f66(local_10[2],auStack_14,10);
  *puVar3 = *puVar3 | (uint)puVar3;
  iVar5 = 0;
  do {
    if (local_10[iVar5] != 0) {
      func_0x89e02fa0(local_10[iVar5]);
    }
    iVar5 = iVar5 + 1;
  } while (iVar5 < 4);
  return (uint)puVar3 | (((iVar4 + -1) * 0x100 | uVar2) << 8 | (uint)puVar3) << 8;
}



void __fastcall FUN_004031a4(int param_1)

{
  undefined4 *puVar1;
  undefined4 uVar2;
  int iVar3;
  int local_48;
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
  uint local_4;
  
  local_4 = s__Repeat_del___s__if_exist___s__g_00422037._13_4_ ^ (uint)&local_48;
  local_44 = 0;
  local_40 = 0;
  local_3c = 0;
  local_38 = 0;
  local_34 = 0;
  local_30 = 0;
  local_2c = 0;
  local_28 = 0;
  local_24 = 0;
  local_20 = 0;
  local_48 = 0;
  func_0x9c0e3245(param_1,0,0x9a);
  iVar3 = 0;
  do {
    puVar1 = (undefined4 *)func_0x24e03251(0x20);
    *puVar1 = 0;
    puVar1[1] = 0;
    puVar1[2] = 0;
    puVar1[3] = 0;
    puVar1[4] = 0;
    (&local_44)[iVar3] = puVar1;
    puVar1[5] = 0;
    iVar3 = iVar3 + 1;
    puVar1[6] = 0;
    puVar1[7] = 0;
  } while (iVar3 < 10);
  func_0xcb623288(&local_44);
  if (0 < local_48) {
    uVar2 = func_0x6b5e329b(local_44);
    *(undefined4 *)(param_1 + 0x50) = uVar2;
    local_44 = local_44 & 0xffff0000;
    func_0x9c0e32b2((int)&local_44 + 2,0,0x3e);
    iVar3 = func_0x6b6432bc(&local_44);
    if (iVar3 == 1) {
      func_0x7dd632d4(param_1 + 0x58,0x21,&local_44);
      func_0xf1d532ea();
      return;
    }
    func_0xf1d532fe();
    return;
  }
  func_0xf1d53312();
  return;
}



void __fastcall FUN_004032d4(undefined4 param_1,int *param_2,undefined4 param_3)

{
  char cVar1;
  undefined4 *puVar2;
  undefined4 *puVar3;
  undefined4 *puVar4;
  int iVar5;
  undefined4 *puVar6;
  int iVar7;
  int unaff_EBX;
  int iVar8;
  bool bVar9;
  int **ppiVar10;
  int *local_3c;
  int *piStack_38;
  short asStack_34 [2];
  undefined4 local_30;
  undefined4 local_2c;
  int *local_28;
  undefined2 local_24;
  undefined4 local_22;
  undefined4 local_1e;
  undefined4 local_1a;
  undefined4 local_16;
  undefined4 local_12;
  undefined4 local_e;
  undefined4 local_a;
  undefined2 local_6;
  uint local_4;
  
  local_4 = s__Repeat_del___s__if_exist___s__g_00422037._13_4_ ^ (uint)&local_3c;
  local_30 = param_3;
  local_3c = (int *)0xffffffff;
  local_24 = 0;
  local_22 = 0;
  local_1e = 0;
  local_1a = 0;
  local_16 = 0;
  local_12 = 0;
  local_e = 0;
  local_a = 0;
  local_6 = 0;
  iVar8 = 0;
  local_2c = param_1;
  local_28 = param_2;
  puVar4 = (undefined4 *)func_0xe1e53383(0x288);
  ppiVar10 = &piStack_38;
  piStack_38 = (int *)0x288;
  iVar5 = func_0xa9a2349b(puVar4,ppiVar10);
  if (iVar5 == 0x6f) {
    func_0x42eb33a6(puVar4);
    puVar4 = (undefined4 *)func_0xe1e533b0(unaff_EBX);
  }
  iVar5 = func_0xa9a234c0(puVar4,&stack0xffffffc0);
  puVar3 = puVar4;
  if (iVar5 == 0) {
    for (; puVar3 != (undefined4 *)0x0; puVar3 = (undefined4 *)*puVar3) {
      ppiVar10 = (int **)((int)ppiVar10 + 1);
      if (param_2 != (int *)0x0) {
        *param_2 = puVar3[0x65];
        *(undefined2 *)(param_2 + 1) = *(undefined2 *)(puVar3 + 0x66);
      }
      for (puVar2 = puVar3 + 0x6b; puVar2 != (undefined4 *)0x0; puVar2 = (undefined4 *)*puVar2) {
        puVar6 = puVar2 + 1;
        do {
          cVar1 = *(char *)puVar6;
          puVar6 = (undefined4 *)((int)puVar6 + 1);
        } while (cVar1 != '\0');
        iVar5 = (int)puVar6 - ((int)puVar2 + 5);
        if (0x10 < iVar5) {
          iVar5 = 0x10;
        }
        iVar7 = 0;
        if (-1 < iVar5) {
          bVar9 = iVar5 == 0;
          do {
            if (bVar9) {
              asStack_34[iVar7] = 0;
            }
            asStack_34[iVar7] = (short)*(char *)((int)(puVar2 + 1) + iVar7);
            iVar7 = iVar7 + 1;
            bVar9 = iVar7 == iVar5;
          } while (iVar7 <= iVar5);
        }
        iVar5 = func_0x6b5e3459(asStack_34);
        if (iVar5 != 0) {
          func_0x7dd63474(*(undefined4 *)(unaff_EBX + iVar8 * 4),0x10,asStack_34);
        }
        iVar8 = iVar8 + 1;
        param_2 = piStack_38;
      }
      if (0 < iVar8) break;
    }
  }
  *local_3c = iVar8;
  if (puVar4 != (undefined4 *)0x0) {
    func_0x42eb34a9(puVar4);
  }
  func_0xf1d534be(ppiVar10);
  return;
}



undefined2 * __cdecl FUN_00403574(char *param_1)

{
  char cVar1;
  undefined4 uVar2;
  undefined2 *in_EAX;
  char *pcVar3;
  int iVar4;
  int iVar5;
  
  uVar2 = s_R6008___not_enough_space_for_arg_0041c02d._31_4_;
  iVar5 = 0x20;
  pcVar3 = param_1;
  do {
    cVar1 = *pcVar3;
    pcVar3 = pcVar3 + 1;
  } while (cVar1 != '\0');
  iVar4 = (int)pcVar3 - (int)(param_1 + 1);
  if (in_EAX == (undefined2 *)0x0) {
    iVar5 = (*(code *)s_R6008___not_enough_space_for_arg_0041c02d._31_4_)
                      (0,0,param_1,0xffffffff,0,0);
    in_EAX = (undefined2 *)func_0xe1e53605(iVar5 * 2);
  }
  if (iVar4 == 0) {
    *in_EAX = 0;
    return in_EAX;
  }
  if ((0 < iVar5) && (iVar5 + -1 < iVar4)) {
    iVar4 = iVar5 + -1;
  }
  (*(code *)uVar2)(0,0,param_1,0xffffffff,in_EAX,iVar4 + 1);
  return in_EAX;
}



void __cdecl FUN_004036b4(uint param_1)

{
  undefined local_14;
  undefined4 local_13;
  undefined4 local_f;
  undefined4 local_b;
  undefined2 local_7;
  undefined local_5;
  uint local_4;
  
  local_4 = s__Repeat_del___s__if_exist___s__g_00422037._13_4_ ^ (uint)&local_14;
  local_14 = 0;
  local_13 = 0;
  local_f = 0;
  local_b = 0;
  local_7 = 0;
  local_5 = 0;
  func_0xeb7d3756(&DAT_004200a4,param_1 >> 0x18,param_1 >> 0x10 & 0xff,param_1 >> 8 & 0xff,
                  param_1 & 0xff);
  func_0xabe63763();
  func_0xf1d53771();
  return;
}



void FUN_00403794(void)

{
  int iVar1;
  int iVar2;
  int iVar3;
  undefined *puVar4;
  undefined4 uVar5;
  undefined local_18;
  undefined4 local_17;
  undefined4 local_13;
  undefined4 local_f;
  undefined2 local_b;
  undefined local_9;
  uint local_8;
  
  local_8 = s__Repeat_del___s__if_exist___s__g_00422037._13_4_ ^ (uint)&local_18;
  local_17 = 0;
  local_13 = 0;
  local_f = 0;
  local_b = 0;
  local_9 = 0;
  local_18 = 0;
  iVar1 = func_0x8b683821(&DAT_00423050,DAT_00423060);
  if (iVar1 != 0) {
    if (DAT_0042306c == 3) {
      uVar5 = 0x2bac;
      puVar4 = &DAT_004200b0;
    }
    else {
      uVar5 = 0x2ba2;
      puVar4 = &DAT_004200c0;
    }
    iVar2 = func_0x8b683862(puVar4,uVar5);
    if (iVar2 != 0) {
      if (DAT_00424c76 != 0) {
        func_0xab66387e(DAT_00424c76);
      }
      iVar3 = func_0x8b683893(&local_18,DAT_00423060);
      if (iVar3 == 0) {
        func_0xf1d538aa();
        return;
      }
      if (((iVar1 == 1) && (iVar2 == 1)) && (iVar3 == 1)) {
        func_0x8b6838cd(&DAT_004200d0,DAT_00423060);
      }
      func_0xf1d538de();
      return;
    }
  }
  func_0xf1d5383a();
  return;
}



void FUN_00404544(void)

{
  code *pcVar1;
  int iVar2;
  uint uVar3;
  undefined4 *unaff_EDI;
  
  func_0x9b7f469c();
  pcVar1 = DAT_0041c1f0;
  uVar3 = 0;
  iVar2 = (*DAT_0041c1f0)(*unaff_EDI,&stack0x00000000);
  if (iVar2 != 4) {
    func_0xf1d545e3();
    return;
  }
  do {
    iVar2 = (*pcVar1)(*unaff_EDI,&stack0xfffffff8,0x1000,0);
    if (iVar2 == 0) break;
    func_0xf6e1461d(&stack0xfffffff8,1,iVar2,uRam00000000);
    uVar3 = uVar3 + iVar2;
  } while (uVar3 < 4);
  func_0xddde4635(uRam00000000);
  func_0xf1d5464f();
  return;
}



// WARNING: Globals starting with '_' overlap smaller symbols at the same address

undefined8 FUN_004048a4(void)

{
  int iVar1;
  int iVar2;
  undefined4 uVar3;
  undefined4 uVar4;
  undefined4 uStack_28;
  undefined4 uStack_24;
  undefined4 uStack_20;
  
  uStack_20 = 0;
  uStack_24 = 0;
  uStack_28 = 3;
  uVar4 = 0xffffffff;
  uVar3 = 0xffffffff;
  iVar1 = (*(code *)s_R6008___not_enough_space_for_arg_0041c02d._7_4_)();
  if (iVar1 == -1) {
    return 0xffffffffffffffff;
  }
  iVar2 = (*_DAT_0041c058)(iVar1,&uStack_28);
  if (iVar2 == 1) {
    uVar4 = 3;
    uVar3 = 0;
  }
  (*(code *)s_R6002___floating_point_support_n_0041c059._35_4_)(iVar1);
  return CONCAT44(uVar3,uVar4);
}



void FUN_00404e14(undefined4 param_1,undefined4 param_2,short *param_3)

{
  short sVar1;
  code *pcVar2;
  undefined4 uVar3;
  uint uVar4;
  int iVar5;
  undefined4 uStack_26c;
  undefined4 uStack_268;
  undefined4 uStack_264;
  undefined4 uStack_260;
  undefined4 uStack_25c;
  undefined4 uStack_258;
  undefined4 uStack_254;
  undefined4 uStack_250;
  undefined4 uStack_24c;
  undefined4 uStack_248;
  undefined4 uStack_244;
  undefined4 uStack_240;
  undefined4 uStack_23c;
  undefined *puStack_238;
  undefined4 uStack_234;
  undefined4 uStack_230;
  undefined4 uStack_22c;
  undefined *puStack_228;
  undefined4 uStack_224;
  undefined auStack_218 [524];
  uint local_c;
  
  pcVar2 = DAT_0041c1a0;
  local_c = s__Repeat_del___s__if_exist___s__g_00422037._13_4_ ^ (uint)auStack_218;
  uStack_224 = 100;
  puStack_228 = &DAT_00424698;
  uStack_22c = 0x67;
  uStack_230 = param_1;
  uStack_234 = 0x404e45;
  (*DAT_0041c1a0)();
  uStack_234 = 100;
  puStack_238 = &DAT_004245d0;
  uStack_23c = 0x6d;
  uStack_240 = param_1;
  uStack_244 = 0x404e51;
  (*pcVar2)();
  uStack_244 = 0x404e58;
  func_0xeb7f4ea6();
  iVar5 = (int)&LAB_00424768 - (int)param_3;
  do {
    sVar1 = *param_3;
    *(short *)(iVar5 + (int)param_3) = sVar1;
    param_3 = param_3 + 1;
  } while (sVar1 != 0);
  uStack_244 = 0x404e78;
  DAT_0042306c = FUN_00401004();
  uVar3 = s_R6009___not_enough_space_for_env_0041c001._31_4_;
  uStack_244 = 2000;
  uStack_248 = 0x404e8a;
  (*(code *)s_R6009___not_enough_space_for_env_0041c001._31_4_)();
  uStack_248 = 0x404e8f;
  iVar5 = func_0xfb404edd();
  if (iVar5 != 0) {
    uStack_248 = 0x404e98;
    func_0x6b594ee6();
    uStack_248 = 0;
    uStack_24c = 0x404ea0;
    (*(code *)s_R6008___not_enough_space_for_arg_0041c02d._35_4_)();
  }
  uStack_248 = 0;
  uStack_24c = param_1;
  uStack_250 = 0;
  uStack_254 = 0;
  uStack_258 = 0;
  uStack_25c = 0x80000000;
  uStack_260 = 0;
  uStack_264 = 0x80000000;
  uStack_268 = 0xcf0000;
  uStack_26c = &DAT_00424698;
  DAT_00424760 = param_1;
  iVar5 = (*DAT_0041c198)(0,&DAT_004245d0);
  if (iVar5 != 0) {
    iVar5 = func_0x0b5b4f29();
    if (iVar5 != 0) {
      uStack_26c = (undefined *)((uint)uStack_26c & 0xffff0000);
      func_0x9c0e4f5c((int)&uStack_26c + 2,0,0x206);
      if ((DAT_00424c70 != 0) && (DAT_00424c74 != 0)) {
        func_0xab664f7d(DAT_00424c70);
        DAT_00423060 = DAT_00424c74;
      }
      uVar4 = (*(code *)s_R6009___not_enough_space_for_env_0041c001._35_4_)();
      func_0xdb814fbb(&DAT_0041fdd4,(int)(((ulonglong)uVar4 / 1000) % 1000));
      func_0x8b674fc0();
      func_0x2b674fc9();
      func_0x00d64fdb(&uStack_26c,0x104,&DAT_0041faf4);
      func_0x00d64ff0(&uStack_26c,0x104,&DAT_00425028);
      iVar5 = (*(code *)s_Microsoft_Visual_C___Runtime_Lib_0041c089._31_4_)(&uStack_26c);
      if (iVar5 != -1) {
        (*(code *)uVar3)(500);
        (*DAT_0041c184)(0,0,&uStack_26c,&DAT_0041fdec,0,1);
      }
      (*(code *)uVar3)(5000);
      func_0x0b76502a();
      (*(code *)s_R6008___not_enough_space_for_arg_0041c02d._35_4_)(0);
      pcVar2 = (code *)swi(3);
      (*pcVar2)();
      return;
    }
  }
  func_0xf1d54f3f();
  return;
}



void FUN_00404ff4(void)

{
  code *pcVar1;
  undefined4 uStack_4c;
  undefined4 uStack_48;
  undefined4 uStack_40;
  
  pcVar1 = DAT_0041c1a4;
  uStack_40 = 0x6b;
  uStack_48 = 0x40502f;
  (*DAT_0041c1a4)();
  uStack_48 = 0x7f00;
  uStack_4c = 0;
  (*DAT_0041c190)();
  (*pcVar1)(3,0x6c);
  (*DAT_0041c194)(&uStack_4c);
  return;
}



void FUN_00405084(undefined4 param_1,int param_2,uint param_3,undefined4 param_4)

{
  undefined auStack_54 [4];
  undefined local_50 [68];
  uint local_c;
  
  local_c = s__Repeat_del___s__if_exist___s__g_00422037._13_4_ ^ (uint)auStack_54;
  if (param_2 == 2) {
    (*DAT_0041c1a8)(0);
    func_0xf1d551e5();
    return;
  }
  if (param_2 == 0xf) {
    (*DAT_0041c1b8)(param_1,local_50);
    (*DAT_0041c1b4)(param_1,&stack0xffffffa8);
    func_0xf1d551c9();
    return;
  }
  if (param_2 != 0x111) {
    (*DAT_0041c1bc)(param_1,param_2,param_3,param_4);
    func_0xf1d55124();
    return;
  }
  if ((param_3 & 0xffff) != 0x68) {
    if ((param_3 & 0xffff) != 0x69) {
      (*DAT_0041c1bc)(param_1,0x111,param_3,param_4);
      func_0xf1d55157();
      return;
    }
    (*DAT_0041c1c0)(param_1);
    func_0xf1d55172();
    return;
  }
  (*DAT_0041c19c)(DAT_00424760,0x67,param_1,&DAT_004051a0,0);
  func_0xf1d5519d();
  return;
}



void FUN_00405204(void)

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
  uint uVar9;
  uint uVar10;
  
  uVar1 = *(uint *)(in_EAX + 8);
  uVar3 = *(uint *)(in_EAX + 0xc);
  uVar7 = *(uint *)(in_EAX + 0x10);
  uVar5 = uVar3 >> 2 | uVar3 << 0x1e;
  uVar3 = (uVar1 >> 0x1b | uVar1 << 5) +
          ((*(uint *)(in_EAX + 0x14) ^ uVar7) & uVar3 ^ *(uint *)(in_EAX + 0x14)) +
          *(int *)(in_EAX + 0x18) + 0x5a827999 + *(int *)(in_EAX + 0x1c);
  uVar2 = *(int *)(in_EAX + 0x14) + 0x5a827999 +
          (uVar3 >> 0x1b | uVar3 * 0x20) + ((uVar7 ^ uVar5) & uVar1 ^ uVar7) +
          *(int *)(in_EAX + 0x20);
  uVar1 = uVar1 >> 2 | uVar1 << 0x1e;
  uVar4 = uVar3 >> 2 | uVar3 * 0x40000000;
  uVar3 = uVar7 + 0x5a827999 +
          ((uVar5 ^ uVar1) & uVar3 ^ uVar5) +
          (uVar2 >> 0x1b | uVar2 * 0x20) + *(int *)(in_EAX + 0x24);
  uVar6 = uVar2 >> 2 | uVar2 * 0x40000000;
  uVar2 = uVar5 + 0x5a827999 +
          (uVar3 >> 0x1b | uVar3 * 0x20) + ((uVar4 ^ uVar1) & uVar2 ^ uVar1) +
          *(int *)(in_EAX + 0x28);
  uVar7 = uVar3 >> 2 | uVar3 * 0x40000000;
  uVar1 = (uVar2 >> 0x1b | uVar2 * 0x20) + ((uVar4 ^ uVar6) & uVar3 ^ uVar4) +
          *(int *)(in_EAX + 0x2c) + 0x5a827999 + uVar1;
  uVar3 = uVar4 + 0x5a827999 +
          (uVar1 >> 0x1b | uVar1 * 0x20) + ((uVar6 ^ uVar7) & uVar2 ^ uVar6) +
          *(int *)(in_EAX + 0x30);
  uVar5 = uVar2 >> 2 | uVar2 * 0x40000000;
  uVar4 = uVar1 >> 2 | uVar1 * 0x40000000;
  uVar2 = uVar6 + 0x5a827999 +
          (uVar3 >> 0x1b | uVar3 * 0x20) + ((uVar7 ^ uVar5) & uVar1 ^ uVar7) +
          *(int *)(in_EAX + 0x34);
  uVar7 = (uVar2 >> 0x1b | uVar2 * 0x20) + ((uVar5 ^ uVar4) & uVar3 ^ uVar5) +
          *(int *)(in_EAX + 0x38) + 0x5a827999 + uVar7;
  uVar1 = uVar3 >> 2 | uVar3 * 0x40000000;
  uVar3 = uVar5 + 0x5a827999 +
          ((uVar1 ^ uVar4) & uVar2 ^ uVar4) +
          (uVar7 >> 0x1b | uVar7 * 0x20) + *(int *)(in_EAX + 0x3c);
  uVar6 = uVar2 >> 2 | uVar2 * 0x40000000;
  uVar8 = uVar7 >> 2 | uVar7 * 0x40000000;
  uVar2 = uVar4 + 0x5a827999 +
          (uVar3 >> 0x1b | uVar3 * 0x20) + ((uVar1 ^ uVar6) & uVar7 ^ uVar1) +
          *(int *)(in_EAX + 0x40);
  uVar5 = uVar3 >> 2 | uVar3 * 0x40000000;
  uVar1 = (uVar2 >> 0x1b | uVar2 * 0x20) + ((uVar6 ^ uVar8) & uVar3 ^ uVar6) +
          *(int *)(in_EAX + 0x44) + 0x5a827999 + uVar1;
  uVar7 = uVar2 >> 2 | uVar2 * 0x40000000;
  uVar3 = uVar6 + 0x5a827999 +
          (uVar1 >> 0x1b | uVar1 * 0x20) + ((uVar8 ^ uVar5) & uVar2 ^ uVar8) +
          *(int *)(in_EAX + 0x48);
  uVar4 = uVar1 >> 2 | uVar1 * 0x40000000;
  uVar2 = uVar8 + 0x5a827999 +
          (uVar3 >> 0x1b | uVar3 * 0x20) + ((uVar5 ^ uVar7) & uVar1 ^ uVar5) +
          *(int *)(in_EAX + 0x4c);
  uVar1 = *(uint *)(in_EAX + 0x50) ^ *(uint *)(in_EAX + 0x3c) ^ *(uint *)(in_EAX + 0x24) ^
          *(uint *)(in_EAX + 0x1c);
  uVar6 = uVar3 >> 2 | uVar3 * 0x40000000;
  uVar3 = uVar5 + 0x5a827999 +
          ((uVar4 ^ uVar7) & uVar3 ^ uVar7) +
          (uVar2 >> 0x1b | uVar2 * 0x20) + *(uint *)(in_EAX + 0x50);
  uVar5 = uVar2 >> 2 | uVar2 * 0x40000000;
  uVar2 = uVar7 + 0x5a827999 +
          (uVar3 >> 0x1b | uVar3 * 0x20) + ((uVar4 ^ uVar6) & uVar2 ^ uVar4) +
          *(int *)(in_EAX + 0x54);
  uVar7 = uVar3 >> 2 | uVar3 * 0x40000000;
  uVar1 = uVar1 << 1 | (uint)((int)uVar1 < 0);
  *(uint *)(in_EAX + 0x1c) = uVar1;
  uVar3 = uVar4 + 0x5a827999 +
          (uVar2 >> 0x1b | uVar2 * 0x20) + ((uVar6 ^ uVar5) & uVar3 ^ uVar6) +
          *(int *)(in_EAX + 0x58);
  uVar1 = uVar6 + 0x5a827999 +
          ((uVar5 ^ uVar7) & uVar2 ^ uVar5) + (uVar3 >> 0x1b | uVar3 * 0x20) + uVar1;
  uVar4 = uVar2 >> 2 | uVar2 * 0x40000000;
  uVar2 = *(uint *)(in_EAX + 0x40) ^ *(uint *)(in_EAX + 0x54) ^ *(uint *)(in_EAX + 0x28) ^
          *(uint *)(in_EAX + 0x20);
  uVar2 = uVar2 << 1 | (uint)((int)uVar2 < 0);
  *(uint *)(in_EAX + 0x20) = uVar2;
  uVar2 = uVar5 + 0x5a827999 +
          ((uVar7 ^ uVar4) & uVar3 ^ uVar7) + (uVar1 >> 0x1b | uVar1 * 0x20) + uVar2;
  uVar6 = uVar3 >> 2 | uVar3 * 0x40000000;
  uVar3 = *(uint *)(in_EAX + 0x58) ^ *(uint *)(in_EAX + 0x44) ^ *(uint *)(in_EAX + 0x2c) ^
          *(uint *)(in_EAX + 0x24);
  uVar3 = uVar3 << 1 | (uint)((int)uVar3 < 0);
  *(uint *)(in_EAX + 0x24) = uVar3;
  uVar3 = uVar7 + 0x5a827999 +
          ((uVar6 ^ uVar4) & uVar1 ^ uVar4) + (uVar2 >> 0x1b | uVar2 * 0x20) + uVar3;
  uVar5 = uVar1 >> 2 | uVar1 * 0x40000000;
  uVar1 = *(uint *)(in_EAX + 0x48) ^ *(uint *)(in_EAX + 0x30) ^ *(uint *)(in_EAX + 0x1c) ^
          *(uint *)(in_EAX + 0x28);
  uVar1 = uVar1 << 1 | (uint)((int)uVar1 < 0);
  *(uint *)(in_EAX + 0x28) = uVar1;
  uVar1 = uVar4 + 0x5a827999 +
          ((uVar6 ^ uVar5) & uVar2 ^ uVar6) + (uVar3 >> 0x1b | uVar3 * 0x20) + uVar1;
  uVar4 = uVar2 >> 2 | uVar2 * 0x40000000;
  uVar2 = *(uint *)(in_EAX + 0x4c) ^ *(uint *)(in_EAX + 0x34) ^ *(uint *)(in_EAX + 0x2c) ^
          *(uint *)(in_EAX + 0x20);
  uVar2 = uVar2 << 1 | (uint)((int)uVar2 < 0);
  *(uint *)(in_EAX + 0x2c) = uVar2;
  uVar7 = *(uint *)(in_EAX + 0x50) ^ *(uint *)(in_EAX + 0x38) ^ *(uint *)(in_EAX + 0x30) ^
          *(uint *)(in_EAX + 0x24);
  uVar2 = uVar6 + 0x6ed9eba1 + (uVar5 ^ uVar4 ^ uVar3) + (uVar1 >> 0x1b | uVar1 * 0x20) + uVar2;
  uVar6 = uVar3 >> 2 | uVar3 * 0x40000000;
  uVar3 = uVar7 << 1 | (uint)((int)uVar7 < 0);
  *(uint *)(in_EAX + 0x30) = uVar3;
  uVar3 = uVar5 + 0x6ed9eba1 + (uVar4 ^ uVar6 ^ uVar1) + (uVar2 >> 0x1b | uVar2 * 0x20) + uVar3;
  uVar7 = uVar1 >> 2 | uVar1 * 0x40000000;
  uVar1 = *(uint *)(in_EAX + 0x54) ^ *(uint *)(in_EAX + 0x3c) ^ *(uint *)(in_EAX + 0x34) ^
          *(uint *)(in_EAX + 0x28);
  uVar1 = uVar1 << 1 | (uint)((int)uVar1 < 0);
  *(uint *)(in_EAX + 0x34) = uVar1;
  uVar1 = uVar4 + 0x6ed9eba1 + (uVar2 ^ uVar6 ^ uVar7) + (uVar3 >> 0x1b | uVar3 * 0x20) + uVar1;
  uVar4 = uVar2 >> 2 | uVar2 * 0x40000000;
  uVar2 = *(uint *)(in_EAX + 0x58) ^ *(uint *)(in_EAX + 0x40) ^ *(uint *)(in_EAX + 0x38) ^
          *(uint *)(in_EAX + 0x2c);
  uVar2 = uVar2 << 1 | (uint)((int)uVar2 < 0);
  *(uint *)(in_EAX + 0x38) = uVar2;
  uVar2 = uVar6 + 0x6ed9eba1 + (uVar4 ^ uVar3 ^ uVar7) + (uVar1 >> 0x1b | uVar1 * 0x20) + uVar2;
  uVar6 = uVar3 >> 2 | uVar3 * 0x40000000;
  uVar3 = *(uint *)(in_EAX + 0x30) ^ *(uint *)(in_EAX + 0x44) ^ *(uint *)(in_EAX + 0x3c) ^
          *(uint *)(in_EAX + 0x1c);
  uVar3 = uVar3 << 1 | (uint)((int)uVar3 < 0);
  *(uint *)(in_EAX + 0x3c) = uVar3;
  uVar3 = uVar7 + 0x6ed9eba1 + (uVar4 ^ uVar6 ^ uVar1) + (uVar2 >> 0x1b | uVar2 * 0x20) + uVar3;
  uVar8 = uVar1 >> 2 | uVar1 * 0x40000000;
  uVar1 = *(uint *)(in_EAX + 0x48) ^ *(uint *)(in_EAX + 0x40) ^ *(uint *)(in_EAX + 0x34) ^
          *(uint *)(in_EAX + 0x20);
  uVar1 = uVar1 << 1 | (uint)((int)uVar1 < 0);
  *(uint *)(in_EAX + 0x40) = uVar1;
  uVar5 = uVar2 >> 2 | uVar2 * 0x40000000;
  uVar7 = *(uint *)(in_EAX + 0x38) ^ *(uint *)(in_EAX + 0x4c) ^ *(uint *)(in_EAX + 0x44) ^
          *(uint *)(in_EAX + 0x24);
  uVar7 = uVar7 << 1 | (uint)((int)uVar7 < 0);
  *(uint *)(in_EAX + 0x44) = uVar7;
  uVar2 = uVar4 + 0x6ed9eba1 + (uVar6 ^ uVar8 ^ uVar2) + (uVar3 >> 0x1b | uVar3 * 0x20) + uVar1;
  uVar1 = uVar6 + 0x6ed9eba1 + (uVar8 ^ uVar5 ^ uVar3) + (uVar2 >> 0x1b | uVar2 * 0x20) + uVar7;
  uVar7 = uVar3 >> 2 | uVar3 * 0x40000000;
  uVar3 = *(uint *)(in_EAX + 0x50) ^ *(uint *)(in_EAX + 0x48) ^ *(uint *)(in_EAX + 0x3c) ^
          *(uint *)(in_EAX + 0x28);
  uVar3 = uVar3 << 1 | (uint)((int)uVar3 < 0);
  *(uint *)(in_EAX + 0x48) = uVar3;
  uVar3 = uVar8 + 0x6ed9eba1 + (uVar2 ^ uVar5 ^ uVar7) + (uVar1 >> 0x1b | uVar1 * 0x20) + uVar3;
  uVar4 = uVar2 >> 2 | uVar2 * 0x40000000;
  uVar2 = *(uint *)(in_EAX + 0x40) ^ *(uint *)(in_EAX + 0x54) ^ *(uint *)(in_EAX + 0x4c) ^
          *(uint *)(in_EAX + 0x2c);
  uVar2 = uVar2 << 1 | (uint)((int)uVar2 < 0);
  *(uint *)(in_EAX + 0x4c) = uVar2;
  uVar2 = uVar5 + 0x6ed9eba1 + (uVar4 ^ uVar1 ^ uVar7) + (uVar3 >> 0x1b | uVar3 * 0x20) + uVar2;
  uVar8 = uVar1 >> 2 | uVar1 * 0x40000000;
  uVar1 = *(uint *)(in_EAX + 0x58) ^ *(uint *)(in_EAX + 0x50) ^ *(uint *)(in_EAX + 0x30) ^
          *(uint *)(in_EAX + 0x44);
  uVar1 = uVar1 << 1 | (uint)((int)uVar1 < 0);
  *(uint *)(in_EAX + 0x50) = uVar1;
  uVar1 = uVar7 + 0x6ed9eba1 + (uVar4 ^ uVar8 ^ uVar3) + (uVar2 >> 0x1b | uVar2 * 0x20) + uVar1;
  uVar6 = uVar3 >> 2 | uVar3 * 0x40000000;
  uVar3 = *(uint *)(in_EAX + 0x48) ^ *(uint *)(in_EAX + 0x54) ^ *(uint *)(in_EAX + 0x34) ^
          *(uint *)(in_EAX + 0x1c);
  uVar3 = uVar3 << 1 | (uint)((int)uVar3 < 0);
  *(uint *)(in_EAX + 0x54) = uVar3;
  uVar5 = uVar2 >> 2 | uVar2 * 0x40000000;
  uVar7 = *(uint *)(in_EAX + 0x58) ^ *(uint *)(in_EAX + 0x38) ^ *(uint *)(in_EAX + 0x4c) ^
          *(uint *)(in_EAX + 0x20);
  uVar7 = uVar7 << 1 | (uint)((int)uVar7 < 0);
  *(uint *)(in_EAX + 0x58) = uVar7;
  uVar3 = uVar4 + 0x6ed9eba1 + (uVar8 ^ uVar6 ^ uVar2) + (uVar1 >> 0x1b | uVar1 * 0x20) + uVar3;
  uVar2 = uVar8 + 0x6ed9eba1 + (uVar6 ^ uVar5 ^ uVar1) + (uVar3 >> 0x1b | uVar3 * 0x20) + uVar7;
  uVar7 = uVar1 >> 2 | uVar1 * 0x40000000;
  uVar1 = *(uint *)(in_EAX + 0x50) ^ *(uint *)(in_EAX + 0x3c) ^ *(uint *)(in_EAX + 0x1c) ^
          *(uint *)(in_EAX + 0x24);
  uVar1 = uVar1 << 1 | (uint)((int)uVar1 < 0);
  *(uint *)(in_EAX + 0x1c) = uVar1;
  uVar1 = uVar6 + 0x6ed9eba1 + (uVar3 ^ uVar5 ^ uVar7) + (uVar2 >> 0x1b | uVar2 * 0x20) + uVar1;
  uVar4 = uVar3 >> 2 | uVar3 * 0x40000000;
  uVar3 = *(uint *)(in_EAX + 0x40) ^ *(uint *)(in_EAX + 0x54) ^ *(uint *)(in_EAX + 0x28) ^
          *(uint *)(in_EAX + 0x20);
  uVar3 = uVar3 << 1 | (uint)((int)uVar3 < 0);
  *(uint *)(in_EAX + 0x20) = uVar3;
  uVar3 = uVar5 + 0x6ed9eba1 + (uVar4 ^ uVar2 ^ uVar7) + (uVar1 >> 0x1b | uVar1 * 0x20) + uVar3;
  uVar6 = uVar2 >> 2 | uVar2 * 0x40000000;
  uVar2 = *(uint *)(in_EAX + 0x58) ^ *(uint *)(in_EAX + 0x44) ^ *(uint *)(in_EAX + 0x2c) ^
          *(uint *)(in_EAX + 0x24);
  uVar2 = uVar2 << 1 | (uint)((int)uVar2 < 0);
  *(uint *)(in_EAX + 0x24) = uVar2;
  uVar2 = uVar7 + 0x6ed9eba1 + (uVar4 ^ uVar6 ^ uVar1) + (uVar3 >> 0x1b | uVar3 * 0x20) + uVar2;
  uVar8 = uVar1 >> 2 | uVar1 * 0x40000000;
  uVar1 = *(uint *)(in_EAX + 0x48) ^ *(uint *)(in_EAX + 0x30) ^ *(uint *)(in_EAX + 0x1c) ^
          *(uint *)(in_EAX + 0x28);
  uVar1 = uVar1 << 1 | (uint)((int)uVar1 < 0);
  *(uint *)(in_EAX + 0x28) = uVar1;
  uVar5 = uVar3 >> 2 | uVar3 * 0x40000000;
  uVar7 = *(uint *)(in_EAX + 0x4c) ^ *(uint *)(in_EAX + 0x34) ^ *(uint *)(in_EAX + 0x2c) ^
          *(uint *)(in_EAX + 0x20);
  uVar3 = uVar4 + 0x6ed9eba1 + (uVar6 ^ uVar8 ^ uVar3) + (uVar2 >> 0x1b | uVar2 * 0x20) + uVar1;
  uVar1 = uVar7 << 1 | (uint)((int)uVar7 < 0);
  *(uint *)(in_EAX + 0x2c) = uVar1;
  uVar1 = uVar6 + 0x6ed9eba1 + (uVar8 ^ uVar5 ^ uVar2) + (uVar3 >> 0x1b | uVar3 * 0x20) + uVar1;
  uVar6 = uVar2 >> 2 | uVar2 * 0x40000000;
  uVar2 = *(uint *)(in_EAX + 0x50) ^ *(uint *)(in_EAX + 0x38) ^ *(uint *)(in_EAX + 0x30) ^
          *(uint *)(in_EAX + 0x24);
  uVar2 = uVar2 << 1 | (uint)((int)uVar2 < 0);
  *(uint *)(in_EAX + 0x30) = uVar2;
  uVar9 = uVar3 >> 2 | uVar3 * 0x40000000;
  uVar3 = uVar8 + 0x6ed9eba1 + (uVar3 ^ uVar5 ^ uVar6) + (uVar1 >> 0x1b | uVar1 * 0x20) + uVar2;
  uVar2 = *(uint *)(in_EAX + 0x54) ^ *(uint *)(in_EAX + 0x3c) ^ *(uint *)(in_EAX + 0x34) ^
          *(uint *)(in_EAX + 0x28);
  uVar2 = uVar2 << 1 | (uint)((int)uVar2 < 0);
  *(uint *)(in_EAX + 0x34) = uVar2;
  uVar4 = uVar1 >> 2 | uVar1 * 0x40000000;
  uVar7 = *(uint *)(in_EAX + 0x58) ^ *(uint *)(in_EAX + 0x40) ^ *(uint *)(in_EAX + 0x38) ^
          *(uint *)(in_EAX + 0x2c);
  uVar2 = uVar5 + 0x6ed9eba1 + (uVar9 ^ uVar1 ^ uVar6) + (uVar3 >> 0x1b | uVar3 * 0x20) + uVar2;
  uVar1 = uVar7 << 1 | (uint)((int)uVar7 < 0);
  *(uint *)(in_EAX + 0x38) = uVar1;
  uVar1 = uVar6 + 0x6ed9eba1 + (uVar9 ^ uVar4 ^ uVar3) + (uVar2 >> 0x1b | uVar2 * 0x20) + uVar1;
  uVar6 = uVar3 >> 2 | uVar3 * 0x40000000;
  uVar3 = *(uint *)(in_EAX + 0x30) ^ *(uint *)(in_EAX + 0x44) ^ *(uint *)(in_EAX + 0x3c) ^
          *(uint *)(in_EAX + 0x1c);
  uVar3 = uVar3 << 1 | (uint)((int)uVar3 < 0);
  *(uint *)(in_EAX + 0x3c) = uVar3;
  uVar7 = *(uint *)(in_EAX + 0x48) ^ *(uint *)(in_EAX + 0x40) ^ *(uint *)(in_EAX + 0x34) ^
          *(uint *)(in_EAX + 0x20);
  uVar5 = uVar2 >> 2 | uVar2 * 0x40000000;
  uVar3 = (uVar1 >> 0x1b | uVar1 * 0x20) + 0x8f1bbcdc +
          ((uVar6 ^ uVar2) & uVar4 | uVar6 & uVar2) + uVar3 + uVar9;
  uVar2 = uVar7 << 1 | (uint)((int)uVar7 < 0);
  *(uint *)(in_EAX + 0x40) = uVar2;
  uVar7 = *(uint *)(in_EAX + 0x38) ^ *(uint *)(in_EAX + 0x4c) ^ *(uint *)(in_EAX + 0x44) ^
          *(uint *)(in_EAX + 0x24);
  uVar2 = ((uVar5 ^ uVar1) & uVar6 | uVar5 & uVar1) + uVar2 + uVar4 + -0x70e44324 +
          (uVar3 >> 0x1b | uVar3 * 0x20);
  uVar8 = uVar1 >> 2 | uVar1 * 0x40000000;
  uVar1 = uVar7 << 1 | (uint)((int)uVar7 < 0);
  *(uint *)(in_EAX + 0x44) = uVar1;
  uVar9 = uVar3 >> 2 | uVar3 * 0x40000000;
  uVar7 = *(uint *)(in_EAX + 0x50) ^ *(uint *)(in_EAX + 0x48) ^ *(uint *)(in_EAX + 0x3c) ^
          *(uint *)(in_EAX + 0x28);
  uVar7 = uVar7 << 1 | (uint)((int)uVar7 < 0);
  uVar3 = ((uVar3 ^ uVar8) & uVar5 | uVar3 & uVar8) + uVar1 + uVar6 + -0x70e44324 +
          (uVar2 >> 0x1b | uVar2 * 0x20);
  *(uint *)(in_EAX + 0x48) = uVar7;
  uVar1 = uVar2 >> 2 | uVar2 * 0x40000000;
  uVar4 = *(uint *)(in_EAX + 0x40) ^ *(uint *)(in_EAX + 0x54) ^ *(uint *)(in_EAX + 0x4c) ^
          *(uint *)(in_EAX + 0x2c);
  uVar4 = uVar4 << 1 | (uint)((int)uVar4 < 0);
  uVar2 = (uVar3 >> 0x1b | uVar3 * 0x20) + 0x8f1bbcdc +
          ((uVar9 ^ uVar2) & uVar8 | uVar9 & uVar2) + uVar7 + uVar5;
  *(uint *)(in_EAX + 0x4c) = uVar4;
  uVar7 = *(uint *)(in_EAX + 0x58) ^ *(uint *)(in_EAX + 0x50) ^ *(uint *)(in_EAX + 0x30) ^
          *(uint *)(in_EAX + 0x44);
  uVar5 = uVar3 >> 2 | uVar3 * 0x40000000;
  uVar3 = ((uVar1 ^ uVar3) & uVar9 | uVar1 & uVar3) + uVar4 + uVar8 + -0x70e44324 +
          (uVar2 >> 0x1b | uVar2 * 0x20);
  uVar7 = uVar7 << 1 | (uint)((int)uVar7 < 0);
  *(uint *)(in_EAX + 0x50) = uVar7;
  uVar4 = *(uint *)(in_EAX + 0x48) ^ *(uint *)(in_EAX + 0x54) ^ *(uint *)(in_EAX + 0x34) ^
          *(uint *)(in_EAX + 0x1c);
  uVar8 = uVar2 >> 2 | uVar2 * 0x40000000;
  uVar4 = uVar4 << 1 | (uint)((int)uVar4 < 0);
  uVar2 = ((uVar5 ^ uVar2) & uVar1 | uVar5 & uVar2) + uVar7 + uVar9 + -0x70e44324 +
          (uVar3 >> 0x1b | uVar3 * 0x20);
  uVar1 = ((uVar8 ^ uVar3) & uVar5 | uVar8 & uVar3) + uVar4 + uVar1 + -0x70e44324 +
          (uVar2 >> 0x1b | uVar2 * 0x20);
  *(uint *)(in_EAX + 0x54) = uVar4;
  uVar9 = uVar3 >> 2 | uVar3 * 0x40000000;
  uVar3 = *(uint *)(in_EAX + 0x58) ^ *(uint *)(in_EAX + 0x38) ^ *(uint *)(in_EAX + 0x4c) ^
          *(uint *)(in_EAX + 0x20);
  uVar3 = uVar3 << 1 | (uint)((int)uVar3 < 0);
  *(uint *)(in_EAX + 0x58) = uVar3;
  uVar6 = uVar2 >> 2 | uVar2 * 0x40000000;
  uVar7 = *(uint *)(in_EAX + 0x50) ^ *(uint *)(in_EAX + 0x3c) ^ *(uint *)(in_EAX + 0x1c) ^
          *(uint *)(in_EAX + 0x24);
  uVar7 = uVar7 << 1 | (uint)((int)uVar7 < 0);
  *(uint *)(in_EAX + 0x1c) = uVar7;
  uVar3 = ((uVar2 ^ uVar9) & uVar8 | uVar2 & uVar9) + uVar3 + uVar5 + -0x70e44324 +
          (uVar1 >> 0x1b | uVar1 * 0x20);
  uVar4 = uVar1 >> 2 | uVar1 * 0x40000000;
  uVar2 = *(uint *)(in_EAX + 0x40) ^ *(uint *)(in_EAX + 0x54) ^ *(uint *)(in_EAX + 0x28) ^
          *(uint *)(in_EAX + 0x20);
  uVar5 = uVar2 << 1 | (uint)((int)uVar2 < 0);
  *(uint *)(in_EAX + 0x20) = uVar5;
  uVar2 = (uVar3 >> 0x1b | uVar3 * 0x20) + 0x8f1bbcdc +
          ((uVar6 ^ uVar1) & uVar9 | uVar6 & uVar1) + uVar7 + uVar8;
  uVar1 = *(uint *)(in_EAX + 0x58) ^ *(uint *)(in_EAX + 0x44) ^ *(uint *)(in_EAX + 0x2c) ^
          *(uint *)(in_EAX + 0x24);
  uVar10 = uVar3 >> 2 | uVar3 * 0x40000000;
  uVar3 = ((uVar4 ^ uVar3) & uVar6 | uVar4 & uVar3) + uVar5 + uVar9 + -0x70e44324 +
          (uVar2 >> 0x1b | uVar2 * 0x20);
  uVar1 = uVar1 << 1 | (uint)((int)uVar1 < 0);
  *(uint *)(in_EAX + 0x24) = uVar1;
  uVar7 = *(uint *)(in_EAX + 0x48) ^ *(uint *)(in_EAX + 0x30) ^ *(uint *)(in_EAX + 0x1c) ^
          *(uint *)(in_EAX + 0x28);
  uVar8 = uVar2 >> 2 | uVar2 * 0x40000000;
  uVar2 = ((uVar10 ^ uVar2) & uVar4 | uVar10 & uVar2) + uVar1 + uVar6 + -0x70e44324 +
          (uVar3 >> 0x1b | uVar3 * 0x20);
  uVar1 = uVar7 << 1 | (uint)((int)uVar7 < 0);
  *(uint *)(in_EAX + 0x28) = uVar1;
  uVar7 = *(uint *)(in_EAX + 0x4c) ^ *(uint *)(in_EAX + 0x34) ^ *(uint *)(in_EAX + 0x2c) ^
          *(uint *)(in_EAX + 0x20);
  uVar5 = uVar3 >> 2 | uVar3 * 0x40000000;
  uVar7 = uVar7 << 1 | (uint)((int)uVar7 < 0);
  uVar3 = ((uVar8 ^ uVar3) & uVar10 | uVar8 & uVar3) + uVar1 + uVar4 + -0x70e44324 +
          (uVar2 >> 0x1b | uVar2 * 0x20);
  *(uint *)(in_EAX + 0x2c) = uVar7;
  uVar1 = *(uint *)(in_EAX + 0x50) ^ *(uint *)(in_EAX + 0x38) ^ *(uint *)(in_EAX + 0x30) ^
          *(uint *)(in_EAX + 0x24);
  uVar9 = uVar2 >> 2 | uVar2 * 0x40000000;
  uVar1 = uVar1 << 1 | (uint)((int)uVar1 < 0);
  *(uint *)(in_EAX + 0x30) = uVar1;
  uVar2 = ((uVar2 ^ uVar5) & uVar8 | uVar2 & uVar5) + uVar7 + uVar10 + -0x70e44324 +
          (uVar3 >> 0x1b | uVar3 * 0x20);
  uVar7 = uVar3 >> 2 | uVar3 * 0x40000000;
  uVar4 = *(uint *)(in_EAX + 0x54) ^ *(uint *)(in_EAX + 0x3c) ^ *(uint *)(in_EAX + 0x34) ^
          *(uint *)(in_EAX + 0x28);
  uVar4 = uVar4 << 1 | (uint)((int)uVar4 < 0);
  *(uint *)(in_EAX + 0x34) = uVar4;
  uVar3 = (uVar2 >> 0x1b | uVar2 * 0x20) + 0x8f1bbcdc +
          ((uVar9 ^ uVar3) & uVar5 | uVar9 & uVar3) + uVar1 + uVar8;
  uVar1 = *(uint *)(in_EAX + 0x58) ^ *(uint *)(in_EAX + 0x40) ^ *(uint *)(in_EAX + 0x38) ^
          *(uint *)(in_EAX + 0x2c);
  uVar10 = uVar2 >> 2 | uVar2 * 0x40000000;
  uVar2 = ((uVar7 ^ uVar2) & uVar9 | uVar7 & uVar2) + uVar4 + uVar5 + -0x70e44324 +
          (uVar3 >> 0x1b | uVar3 * 0x20);
  uVar1 = uVar1 << 1 | (uint)((int)uVar1 < 0);
  *(uint *)(in_EAX + 0x38) = uVar1;
  uVar6 = uVar3 >> 2 | uVar3 * 0x40000000;
  uVar4 = *(uint *)(in_EAX + 0x30) ^ *(uint *)(in_EAX + 0x44) ^ *(uint *)(in_EAX + 0x3c) ^
          *(uint *)(in_EAX + 0x1c);
  uVar4 = uVar4 << 1 | (uint)((int)uVar4 < 0);
  *(uint *)(in_EAX + 0x3c) = uVar4;
  uVar3 = ((uVar10 ^ uVar3) & uVar7 | uVar10 & uVar3) + uVar1 + uVar9 + -0x70e44324 +
          (uVar2 >> 0x1b | uVar2 * 0x20);
  uVar1 = *(uint *)(in_EAX + 0x48) ^ *(uint *)(in_EAX + 0x40) ^ *(uint *)(in_EAX + 0x34) ^
          *(uint *)(in_EAX + 0x20);
  uVar5 = uVar2 >> 2 | uVar2 * 0x40000000;
  uVar2 = ((uVar6 ^ uVar2) & uVar10 | uVar6 & uVar2) + uVar4 + uVar7 + -0x70e44324 +
          (uVar3 >> 0x1b | uVar3 * 0x20);
  uVar1 = uVar1 << 1 | (uint)((int)uVar1 < 0);
  *(uint *)(in_EAX + 0x40) = uVar1;
  uVar7 = *(uint *)(in_EAX + 0x38) ^ *(uint *)(in_EAX + 0x4c) ^ *(uint *)(in_EAX + 0x44) ^
          *(uint *)(in_EAX + 0x24);
  uVar8 = uVar3 >> 2 | uVar3 * 0x40000000;
  uVar7 = uVar7 << 1 | (uint)((int)uVar7 < 0);
  uVar3 = ((uVar3 ^ uVar5) & uVar6 | uVar3 & uVar5) + uVar1 + uVar10 + -0x70e44324 +
          (uVar2 >> 0x1b | uVar2 * 0x20);
  *(uint *)(in_EAX + 0x44) = uVar7;
  uVar4 = uVar2 >> 2 | uVar2 * 0x40000000;
  uVar1 = *(uint *)(in_EAX + 0x50) ^ *(uint *)(in_EAX + 0x48) ^ *(uint *)(in_EAX + 0x3c) ^
          *(uint *)(in_EAX + 0x28);
  uVar1 = uVar1 << 1 | (uint)((int)uVar1 < 0);
  uVar2 = (uVar3 >> 0x1b | uVar3 * 0x20) + 0x8f1bbcdc +
          ((uVar8 ^ uVar2) & uVar5 | uVar8 & uVar2) + uVar7 + uVar6;
  *(uint *)(in_EAX + 0x48) = uVar1;
  uVar1 = ((uVar4 ^ uVar3) & uVar8 | uVar4 & uVar3) + uVar1 + uVar5 + -0x70e44324 +
          (uVar2 >> 0x1b | uVar2 * 0x20);
  uVar6 = uVar3 >> 2 | uVar3 * 0x40000000;
  uVar3 = *(uint *)(in_EAX + 0x40) ^ *(uint *)(in_EAX + 0x54) ^ *(uint *)(in_EAX + 0x4c) ^
          *(uint *)(in_EAX + 0x2c);
  uVar3 = uVar3 << 1 | (uint)((int)uVar3 < 0);
  *(uint *)(in_EAX + 0x4c) = uVar3;
  uVar5 = uVar2 >> 2 | uVar2 * 0x40000000;
  uVar7 = *(uint *)(in_EAX + 0x58) ^ *(uint *)(in_EAX + 0x50) ^ *(uint *)(in_EAX + 0x30) ^
          *(uint *)(in_EAX + 0x44);
  uVar3 = (uVar1 >> 0x1b | uVar1 * 0x20) + 0xca62c1d6 + (uVar4 ^ uVar6 ^ uVar2) + uVar3 + uVar8;
  uVar2 = uVar7 << 1 | (uint)((int)uVar7 < 0);
  *(uint *)(in_EAX + 0x50) = uVar2;
  uVar7 = *(uint *)(in_EAX + 0x48) ^ *(uint *)(in_EAX + 0x54) ^ *(uint *)(in_EAX + 0x34) ^
          *(uint *)(in_EAX + 0x1c);
  uVar2 = (uVar3 >> 0x1b | uVar3 * 0x20) + 0xca62c1d6 + (uVar6 ^ uVar5 ^ uVar1) + uVar2 + uVar4;
  uVar4 = uVar1 >> 2 | uVar1 * 0x40000000;
  uVar1 = uVar7 << 1 | (uint)((int)uVar7 < 0);
  *(uint *)(in_EAX + 0x54) = uVar1;
  uVar8 = uVar3 >> 2 | uVar3 * 0x40000000;
  uVar7 = *(uint *)(in_EAX + 0x58) ^ *(uint *)(in_EAX + 0x38) ^ *(uint *)(in_EAX + 0x4c) ^
          *(uint *)(in_EAX + 0x20);
  uVar7 = uVar7 << 1 | (uint)((int)uVar7 < 0);
  *(uint *)(in_EAX + 0x58) = uVar7;
  uVar3 = (uVar3 ^ uVar5 ^ uVar4) + uVar1 + uVar6 + -0x359d3e2a + (uVar2 >> 0x1b | uVar2 * 0x20);
  uVar1 = *(uint *)(in_EAX + 0x50) ^ *(uint *)(in_EAX + 0x3c) ^ *(uint *)(in_EAX + 0x1c) ^
          *(uint *)(in_EAX + 0x24);
  uVar9 = uVar2 >> 2 | uVar2 * 0x40000000;
  uVar2 = (uVar3 >> 0x1b | uVar3 * 0x20) + 0xca62c1d6 + (uVar8 ^ uVar2 ^ uVar4) + uVar7 + uVar5;
  uVar1 = uVar1 << 1 | (uint)((int)uVar1 < 0);
  *(uint *)(in_EAX + 0x1c) = uVar1;
  uVar1 = (uVar2 >> 0x1b | uVar2 * 0x20) + 0xca62c1d6 + (uVar8 ^ uVar9 ^ uVar3) + uVar1 + uVar4;
  uVar5 = uVar3 >> 2 | uVar3 * 0x40000000;
  uVar3 = *(uint *)(in_EAX + 0x40) ^ *(uint *)(in_EAX + 0x54) ^ *(uint *)(in_EAX + 0x28) ^
          *(uint *)(in_EAX + 0x20);
  uVar3 = uVar3 << 1 | (uint)((int)uVar3 < 0);
  *(uint *)(in_EAX + 0x20) = uVar3;
  uVar7 = *(uint *)(in_EAX + 0x58) ^ *(uint *)(in_EAX + 0x44) ^ *(uint *)(in_EAX + 0x2c) ^
          *(uint *)(in_EAX + 0x24);
  uVar6 = uVar2 >> 2 | uVar2 * 0x40000000;
  uVar7 = uVar7 << 1 | (uint)((int)uVar7 < 0);
  *(uint *)(in_EAX + 0x24) = uVar7;
  uVar3 = (uVar1 >> 0x1b | uVar1 * 0x20) + 0xca62c1d6 + (uVar9 ^ uVar5 ^ uVar2) + uVar3 + uVar8;
  uVar4 = *(uint *)(in_EAX + 0x48) ^ *(uint *)(in_EAX + 0x30) ^ *(uint *)(in_EAX + 0x1c) ^
          *(uint *)(in_EAX + 0x28);
  uVar2 = (uVar5 ^ uVar6 ^ uVar1) + uVar7 + uVar9 + -0x359d3e2a + (uVar3 >> 0x1b | uVar3 * 0x20);
  uVar8 = uVar1 >> 2 | uVar1 * 0x40000000;
  uVar1 = uVar4 << 1 | (uint)((int)uVar4 < 0);
  *(uint *)(in_EAX + 0x28) = uVar1;
  uVar4 = uVar3 >> 2 | uVar3 * 0x40000000;
  uVar7 = *(uint *)(in_EAX + 0x4c) ^ *(uint *)(in_EAX + 0x34) ^ *(uint *)(in_EAX + 0x2c) ^
          *(uint *)(in_EAX + 0x20);
  uVar7 = uVar7 << 1 | (uint)((int)uVar7 < 0);
  uVar3 = (uVar3 ^ uVar6 ^ uVar8) + uVar1 + uVar5 + -0x359d3e2a + (uVar2 >> 0x1b | uVar2 * 0x20);
  *(uint *)(in_EAX + 0x2c) = uVar7;
  uVar1 = *(uint *)(in_EAX + 0x50) ^ *(uint *)(in_EAX + 0x38) ^ *(uint *)(in_EAX + 0x30) ^
          *(uint *)(in_EAX + 0x24);
  uVar5 = uVar2 >> 2 | uVar2 * 0x40000000;
  uVar2 = (uVar3 >> 0x1b | uVar3 * 0x20) + 0xca62c1d6 + (uVar4 ^ uVar2 ^ uVar8) + uVar7 + uVar6;
  uVar1 = uVar1 << 1 | (uint)((int)uVar1 < 0);
  uVar9 = uVar3 >> 2 | uVar3 * 0x40000000;
  *(uint *)(in_EAX + 0x30) = uVar1;
  uVar3 = (uVar2 >> 0x1b | uVar2 * 0x20) + 0xca62c1d6 + (uVar4 ^ uVar5 ^ uVar3) + uVar1 + uVar8;
  uVar1 = *(uint *)(in_EAX + 0x54) ^ *(uint *)(in_EAX + 0x3c) ^ *(uint *)(in_EAX + 0x34) ^
          *(uint *)(in_EAX + 0x28);
  uVar1 = uVar1 << 1 | (uint)((int)uVar1 < 0);
  *(uint *)(in_EAX + 0x34) = uVar1;
  uVar7 = *(uint *)(in_EAX + 0x58) ^ *(uint *)(in_EAX + 0x40) ^ *(uint *)(in_EAX + 0x38) ^
          *(uint *)(in_EAX + 0x2c);
  uVar6 = uVar2 >> 2 | uVar2 * 0x40000000;
  uVar7 = uVar7 << 1 | (uint)((int)uVar7 < 0);
  uVar2 = (uVar3 >> 0x1b | uVar3 * 0x20) + 0xca62c1d6 + (uVar5 ^ uVar9 ^ uVar2) + uVar1 + uVar4;
  *(uint *)(in_EAX + 0x38) = uVar7;
  uVar4 = *(uint *)(in_EAX + 0x30) ^ *(uint *)(in_EAX + 0x44) ^ *(uint *)(in_EAX + 0x3c) ^
          *(uint *)(in_EAX + 0x1c);
  uVar1 = (uVar9 ^ uVar6 ^ uVar3) + uVar7 + uVar5 + -0x359d3e2a + (uVar2 >> 0x1b | uVar2 * 0x20);
  uVar8 = uVar3 >> 2 | uVar3 * 0x40000000;
  uVar3 = uVar4 << 1 | (uint)((int)uVar4 < 0);
  *(uint *)(in_EAX + 0x3c) = uVar3;
  uVar5 = uVar2 >> 2 | uVar2 * 0x40000000;
  uVar7 = *(uint *)(in_EAX + 0x48) ^ *(uint *)(in_EAX + 0x40) ^ *(uint *)(in_EAX + 0x34) ^
          *(uint *)(in_EAX + 0x20);
  uVar7 = uVar7 << 1 | (uint)((int)uVar7 < 0);
  *(uint *)(in_EAX + 0x40) = uVar7;
  uVar3 = (uVar2 ^ uVar6 ^ uVar8) + uVar3 + uVar9 + -0x359d3e2a + (uVar1 >> 0x1b | uVar1 * 0x20);
  uVar4 = *(uint *)(in_EAX + 0x38) ^ *(uint *)(in_EAX + 0x4c) ^ *(uint *)(in_EAX + 0x44) ^
          *(uint *)(in_EAX + 0x24);
  uVar10 = uVar1 >> 2 | uVar1 * 0x40000000;
  uVar2 = (uVar3 >> 0x1b | uVar3 * 0x20) + 0xca62c1d6 + (uVar5 ^ uVar1 ^ uVar8) + uVar7 + uVar6;
  uVar1 = uVar4 << 1 | (uint)((int)uVar4 < 0);
  *(uint *)(in_EAX + 0x44) = uVar1;
  uVar9 = uVar3 >> 2 | uVar3 * 0x40000000;
  uVar3 = (uVar2 >> 0x1b | uVar2 * 0x20) + 0xca62c1d6 + (uVar5 ^ uVar10 ^ uVar3) + uVar1 + uVar8;
  uVar1 = *(uint *)(in_EAX + 0x50) ^ *(uint *)(in_EAX + 0x48) ^ *(uint *)(in_EAX + 0x3c) ^
          *(uint *)(in_EAX + 0x28);
  uVar1 = uVar1 << 1 | (uint)((int)uVar1 < 0);
  *(uint *)(in_EAX + 0x48) = uVar1;
  uVar7 = *(uint *)(in_EAX + 0x40) ^ *(uint *)(in_EAX + 0x54) ^ *(uint *)(in_EAX + 0x4c) ^
          *(uint *)(in_EAX + 0x2c);
  uVar6 = uVar2 >> 2 | uVar2 * 0x40000000;
  uVar7 = uVar7 << 1 | (uint)((int)uVar7 < 0);
  *(uint *)(in_EAX + 0x4c) = uVar7;
  uVar2 = (uVar3 >> 0x1b | uVar3 * 0x20) + 0xca62c1d6 + (uVar10 ^ uVar9 ^ uVar2) + uVar1 + uVar5;
  uVar4 = *(uint *)(in_EAX + 0x58) ^ *(uint *)(in_EAX + 0x50) ^ *(uint *)(in_EAX + 0x30) ^
          *(uint *)(in_EAX + 0x44);
  uVar1 = (uVar9 ^ uVar6 ^ uVar3) + uVar7 + uVar10 + -0x359d3e2a + (uVar2 >> 0x1b | uVar2 * 0x20);
  uVar8 = uVar3 >> 2 | uVar3 * 0x40000000;
  uVar3 = uVar4 << 1 | (uint)((int)uVar4 < 0);
  *(uint *)(in_EAX + 0x50) = uVar3;
  uVar5 = uVar2 >> 2 | uVar2 * 0x40000000;
  uVar7 = *(uint *)(in_EAX + 0x48) ^ *(uint *)(in_EAX + 0x54) ^ *(uint *)(in_EAX + 0x34) ^
          *(uint *)(in_EAX + 0x1c);
  uVar7 = uVar7 << 1 | (uint)((int)uVar7 < 0);
  *(uint *)(in_EAX + 0x54) = uVar7;
  uVar3 = (uVar2 ^ uVar6 ^ uVar8) + uVar3 + uVar9 + -0x359d3e2a + (uVar1 >> 0x1b | uVar1 * 0x20);
  uVar4 = *(uint *)(in_EAX + 0x58) ^ *(uint *)(in_EAX + 0x38) ^ *(uint *)(in_EAX + 0x4c) ^
          *(uint *)(in_EAX + 0x20);
  uVar2 = (uVar3 >> 0x1b | uVar3 * 0x20) + 0xca62c1d6 + (uVar5 ^ uVar1 ^ uVar8) + uVar7 + uVar6;
  uVar7 = uVar1 >> 2 | uVar1 * 0x40000000;
  uVar1 = uVar4 << 1 | (uint)((int)uVar4 < 0);
  *(uint *)(in_EAX + 0x58) = uVar1;
  *(int *)(in_EAX + 0xc) = *(int *)(in_EAX + 0xc) + uVar2;
  *(int *)(in_EAX + 8) =
       *(int *)(in_EAX + 8) +
       (uVar2 >> 0x1b | uVar2 * 0x20) + 0xca62c1d6 + (uVar5 ^ uVar7 ^ uVar3) + uVar1 + uVar8;
  *(int *)(in_EAX + 0x10) = *(int *)(in_EAX + 0x10) + (uVar3 >> 2 | uVar3 * 0x40000000);
  *(int *)(in_EAX + 0x14) = *(int *)(in_EAX + 0x14) + uVar7;
  *(int *)(in_EAX + 0x18) = *(int *)(in_EAX + 0x18) + uVar5;
  return;
}



// WARNING: Removing unreachable block (ram,0x004063af)
// WARNING: Removing unreachable block (ram,0x00406425)
// WARNING: Removing unreachable block (ram,0x00406458)
// WARNING: Removing unreachable block (ram,0x0040645a)
// WARNING: Removing unreachable block (ram,0x0040647c)

void FUN_00406344(void)

{
  undefined4 *unaff_EDI;
  undefined4 in_stack_0000106c;
  
  func_0x9b7f649c();
  func_0x56db63cb(&stack0x00000000,in_stack_0000106c,&DAT_0041fdcc);
  *unaff_EDI = 0;
  unaff_EDI[1] = 0;
  unaff_EDI[2] = 0;
  unaff_EDI[3] = 0;
  unaff_EDI[4] = 0;
  func_0xf1d563f6();
  return;
}



// WARNING: Control flow encountered bad instruction data
// WARNING: Instruction at (ram,0x00406ba8) overlaps instruction at (ram,0x00406ba7)
// 
// WARNING: Removing unreachable block (ram,0x00406904)
// WARNING: Removing unreachable block (ram,0x0040690f)
// WARNING: Removing unreachable block (ram,0x004067e2)
// WARNING: Removing unreachable block (ram,0x004067e4)
// WARNING: Removing unreachable block (ram,0x004067ef)

void __thiscall FUN_004065d4(void *this,int param_1,byte **param_2)

{
  byte **ppbVar1;
  byte **in_EAX;
  int *piVar2;
  char cVar3;
  byte bVar4;
  byte *pbVar5;
  byte **ppbVar6;
  byte **ppbVar7;
  byte bVar8;
  byte *pbVar9;
  byte **unaff_EDI;
  int *piVar10;
  bool bVar11;
  uint local_1c;
  int **local_18;
  int *local_14;
  int *local_10;
  int *local_c;
  undefined *puStack_8;
  
  local_1c = *(uint *)((int)this + 0x20);
  local_18 = *(int ***)((int)this + 4);
  local_14 = (int *)in_EAX[1];
  pbVar9 = *in_EAX;
  ppbVar7 = *(byte ***)((int)this + 0x34);
  piVar10 = *(int **)((int)this + 0x1c);
  if (ppbVar7 < *(byte ***)((int)this + 0x30)) {
    local_10 = (int *)((int)*(byte ***)((int)this + 0x30) + (-1 - (int)ppbVar7));
  }
  else {
    local_10 = (int *)(*(int *)((int)this + 0x2c) - (int)ppbVar7);
  }
  piVar2 = *local_18;
  if (piVar2 < (int *)0xa) {
switchD_0040661c_switchD:
    bVar8 = (byte)local_10;
    switch((&switchD_0040661c::switchdataD_00406c14)[(int)piVar2]) {
    case (undefined *)0x40661f:
      bVar8 = (byte)((uint)in_EAX >> 8);
      bVar11 = CARRY1(bRam00000102,bVar8);
      bRam00000102 = bRam00000102 + bVar8;
      if ((!bVar11) && (&DAT_00000009 < local_14)) {
        *(uint *)((int)this + 0x20) = local_1c;
        *(int **)((int)this + 0x1c) = piVar10;
        in_EAX[1] = (byte *)local_14;
        in_EAX[2] = in_EAX[2] + ((int)pbVar9 - (int)*in_EAX);
        *in_EAX = pbVar9;
        *(byte ***)((int)this + 0x34) = ppbVar7;
        param_1 = func_0x9bae66c1(*(undefined *)(local_18 + 4),*(undefined *)((int)local_18 + 0x11),
                                  *(undefined4 *)((int)local_18 + 0x12),
                                  *(undefined4 *)((int)local_18 + 0x16),this,in_EAX);
        local_14 = (int *)in_EAX[1];
        local_1c = *(uint *)((int)this + 0x20);
        pbVar9 = *in_EAX;
        piVar10 = *(int **)((int)this + 0x1c);
        ppbVar7 = *(byte ***)((int)this + 0x34);
        if (param_1 != 0) {
          *local_18 = (int *)((uint)(param_1 != 1) * 2 + 7);
                    // WARNING: Bad instruction - Truncating control flow here
          halt_baddata();
        }
      }
      local_18[3] = (int *)(uint)*(byte *)(local_18 + 4);
      local_18[2] = *(int **)((int)local_18 + 0x12);
      *local_18 = (int *)0x1;
      break;
    case (undefined *)0x4066d7:
      *local_10 = (int)(*local_10 + (int)local_10);
      *(byte *)local_10 = *(char *)local_10 + bVar8;
      break;
    case (undefined *)0x4067cf:
      *(byte *)local_10 = *(char *)local_10 + bVar8;
      cVar3 = (char)piVar2 + *(char *)(unaff_EDI + -0x1d3af6ed);
      pbVar5 = (byte *)(CONCAT31((int3)((uint)piVar2 >> 8),cVar3) + 0x3b202445);
      *pbVar5 = *pbVar5 | cVar3 + 1U;
      local_14[1] = local_14[1] + (*(uint *)(&DAT_0041dce8 + (int)local_10 * 4) & (uint)local_18);
      local_18 = (int **)((uint)local_18 >> ((byte)puStack_8 & 0x1f));
      piVar10 = (int *)((int)piVar10 - (int)puStack_8);
      local_14[3] = (uint)*(byte *)((int)local_14 + 0x11);
      local_14[2] = *(int *)((int)local_14 + 0x16);
      *local_14 = 3;
      local_10 = local_14;
      in_EAX = unaff_EDI;
      goto code_r0x00406842;
    case (undefined *)0x406840:
      *(byte *)local_10 = *(char *)local_10 + bVar8;
code_r0x00406842:
      goto joined_r0x00406851;
    case (undefined *)0x4068f0:
      bVar4 = *(byte *)local_10;
      *(byte *)local_10 = *(char *)local_10 + bVar8;
      pbVar5 = (byte *)((int)piVar2 + (int)unaff_EDI[-0x1d3af6ef]) + CARRY1(bVar4,bVar8);
      pbVar5[0x3b202444] = pbVar5[0x3b202444] | (byte)pbVar5;
      local_14[3] = local_14[3] +
                    (*(uint *)(&DAT_0041dce8 + ((int)local_10 + 1) * 4) & (uint)local_18);
      local_18 = (int **)((uint)local_18 >> ((byte)puStack_8 & 0x1f));
      piVar10 = (int *)((int)piVar10 - (int)puStack_8);
      *local_14 = 5;
      piVar2 = local_14;
      in_EAX = unaff_EDI;
      goto code_r0x00406959;
    case (undefined *)0x406951:
code_r0x00406959:
      puStack_8 = (undefined *)((int)ppbVar7 - piVar2[3]);
      if (puStack_8 < *(undefined **)((int)this + 0x28)) {
        do {
          puStack_8 = puStack_8 +
                      (*(int *)((int)this + 0x2c) - (int)*(undefined **)((int)this + 0x28));
        } while (puStack_8 < *(undefined **)((int)this + 0x28));
      }
      if (local_18[1] == (int *)0x0) goto LAB_00406b05;
      goto LAB_00406999;
    case (undefined *)0x406a5e:
      *(byte *)local_10 = *(char *)local_10 + bVar8;
      ppbVar6 = unaff_EDI;
      if (local_10 == (int *)0x0) {
        ppbVar7 = unaff_EDI;
        if (unaff_EDI == *(byte ***)((int)this + 0x2c)) {
          ppbVar1 = *(byte ***)((int)this + 0x30);
          ppbVar6 = *(byte ***)((int)this + 0x28);
          if (ppbVar1 != ppbVar6) {
            if (ppbVar6 < ppbVar1) {
              local_10 = (int *)((int)ppbVar1 + (-1 - (int)ppbVar6));
            }
            else {
              local_10 = (int *)(*(int *)((int)this + 0x2c) - (int)ppbVar6);
            }
            ppbVar7 = ppbVar6;
            if (local_10 != (int *)0x0) goto code_r0x00406aea;
          }
        }
        *(byte ***)((int)this + 0x34) = ppbVar7;
        param_1 = func_0x9b946aea();
        ppbVar6 = *(byte ***)((int)this + 0x34);
        if (ppbVar6 < *(byte ***)((int)this + 0x30)) {
          local_10 = (int *)((int)*(byte ***)((int)this + 0x30) + (-1 - (int)ppbVar6));
        }
        else {
          local_10 = (int *)(*(int *)((int)this + 0x2c) - (int)ppbVar6);
        }
        if (ppbVar6 == *(byte ***)((int)this + 0x2c)) {
          ppbVar7 = *(byte ***)((int)this + 0x28);
          ppbVar1 = *(byte ***)((int)this + 0x30);
          if (ppbVar1 != ppbVar7) {
            ppbVar6 = ppbVar7;
            if (ppbVar7 < ppbVar1) {
              local_10 = (int *)((int)ppbVar1 + (-1 - (int)ppbVar7));
            }
            else {
              local_10 = (int *)(*(int *)((int)this + 0x2c) - (int)ppbVar7);
            }
          }
        }
        unaff_EDI = param_2;
        if (local_10 == (int *)0x0) goto LAB_00406b8c;
      }
code_r0x00406aea:
      *(undefined *)ppbVar6 = *(undefined *)(local_18 + 2);
      ppbVar7 = (byte **)((int)ppbVar6 + 1);
      local_10 = (int *)((int)local_10 + -1);
      param_1 = 0;
      goto LAB_00406b05;
    case (undefined *)0x406ba7:
      *(byte *)((int)piVar2 + -0x15) = *(byte *)((int)piVar2 + -0x15) | (byte)ppbVar7;
      *(int **)((int)in_EAX + 0x87607ff) = local_10;
      *(byte ***)((int)this + 0x34) = ppbVar7;
      func_0x9b946c13(param_1);
      if (*(int *)((int)this + 0x30) == *(int *)((int)this + 0x34)) {
        *local_18 = (int *)0x8;
        return;
      }
      *(uint *)((int)this + 0x20) = local_1c;
      *(int **)((int)this + 0x1c) = piVar10 + -2;
      in_EAX[1] = (byte *)((int)local_14 + 1);
                    // WARNING: Bad instruction - Truncating control flow here
      halt_baddata();
    case (undefined *)0x406bed:
      *(byte *)local_10 = *(byte *)local_10 | bVar8;
      *(byte *)local_10 = *(char *)local_10 + bVar8;
                    // WARNING: Bad instruction - Truncating control flow here
      halt_baddata();
    case (undefined *)0x902b5b00:
                    // WARNING: Bad instruction - Truncating control flow here
      halt_baddata();
    }
    goto joined_r0x004066e8;
  }
LAB_00406b1a:
  param_1 = -2;
LAB_00406b1c:
  *(uint *)((int)this + 0x20) = local_1c;
  *(int **)((int)this + 0x1c) = piVar10;
  in_EAX[1] = (byte *)local_14;
  in_EAX[2] = in_EAX[2] + ((int)pbVar9 - (int)*in_EAX);
  ppbVar6 = ppbVar7;
LAB_00406b34:
  *in_EAX = pbVar9;
  *(byte ***)((int)this + 0x34) = ppbVar6;
  func_0x9b946b8c(param_1);
  return;
LAB_00406b05:
  *local_18 = (int *)0x0;
  piVar2 = *local_18;
  if (&DAT_00000009 < piVar2) goto LAB_00406b1a;
  goto switchD_0040661c_switchD;
LAB_00406999:
  ppbVar6 = ppbVar7;
  if (local_10 == (int *)0x0) {
    if (ppbVar7 == *(byte ***)((int)this + 0x2c)) {
      ppbVar1 = *(byte ***)((int)this + 0x30);
      ppbVar6 = *(byte ***)((int)this + 0x28);
      if (ppbVar1 != ppbVar6) {
        if (ppbVar6 < ppbVar1) {
          local_10 = (int *)((int)ppbVar1 + (-1 - (int)ppbVar6));
        }
        else {
          local_10 = (int *)(*(int *)((int)this + 0x2c) - (int)ppbVar6);
        }
        ppbVar7 = ppbVar6;
        if (local_10 != (int *)0x0) goto LAB_00406a21;
      }
    }
    *(byte ***)((int)this + 0x34) = ppbVar7;
    param_1 = func_0x9b946a21(param_1);
    ppbVar6 = *(byte ***)((int)this + 0x34);
    if (ppbVar6 < *(byte ***)((int)this + 0x30)) {
      local_10 = (int *)((int)*(byte ***)((int)this + 0x30) + (-1 - (int)ppbVar6));
    }
    else {
      local_10 = (int *)(*(int *)((int)this + 0x2c) - (int)ppbVar6);
    }
    if (ppbVar6 == *(byte ***)((int)this + 0x2c)) {
      ppbVar7 = *(byte ***)((int)this + 0x28);
      ppbVar1 = *(byte ***)((int)this + 0x30);
      if (ppbVar1 != ppbVar7) {
        ppbVar6 = ppbVar7;
        if (ppbVar7 < ppbVar1) {
          local_10 = (int *)((int)ppbVar1 + (-1 - (int)ppbVar7));
        }
        else {
          local_10 = (int *)(*(int *)((int)this + 0x2c) - (int)ppbVar7);
        }
      }
    }
    if (local_10 == (int *)0x0) goto LAB_00406b8c;
  }
LAB_00406a21:
  *(undefined *)ppbVar6 = *puStack_8;
  puStack_8 = puStack_8 + 1;
  local_10 = (int *)((int)local_10 + -1);
  ppbVar7 = (byte **)((int)ppbVar6 + 1);
  param_1 = 0;
  if (puStack_8 == *(undefined **)((int)this + 0x2c)) {
    puStack_8 = *(undefined **)((int)this + 0x28);
  }
  local_18[1] = (int *)((int)local_18[1] + -1);
  if (local_18[1] == (int *)0x0) {
                    // WARNING: Bad instruction - Truncating control flow here
    halt_baddata();
  }
  goto LAB_00406999;
LAB_00406b8c:
  *(uint *)((int)this + 0x20) = local_1c;
  *(int **)((int)this + 0x1c) = piVar10;
  in_EAX[1] = (byte *)local_14;
  in_EAX[2] = in_EAX[2] + ((int)pbVar9 - (int)*in_EAX);
  goto LAB_00406b34;
joined_r0x00406851:
  if ((int *)local_10[3] <= piVar10) goto LAB_00406883;
  if (local_14 == (int *)0x0) goto LAB_00406b49;
  bVar8 = *pbVar9;
  local_14 = (int *)((int)local_14 + -1);
  bVar4 = (byte)piVar10;
  piVar10 = piVar10 + 2;
  pbVar9 = pbVar9 + 1;
  param_1 = 0;
  local_1c = local_1c | (uint)bVar8 << (bVar4 & 0x1f);
  goto joined_r0x00406851;
joined_r0x004066e8:
  if (local_18[3] <= piVar10) goto LAB_00406723;
  if (local_14 == (int *)0x0) {
LAB_00406b49:
    *(uint *)((int)this + 0x20) = local_1c;
    *(int **)((int)this + 0x1c) = piVar10;
    in_EAX[1] = (byte *)0x0;
    in_EAX[2] = in_EAX[2] + ((int)pbVar9 - (int)*in_EAX);
    *in_EAX = pbVar9;
    *(byte ***)((int)this + 0x34) = ppbVar7;
    func_0x9b946bbe(param_1);
    return;
  }
  bVar8 = *pbVar9;
  local_14 = (int *)((int)local_14 + -1);
  bVar4 = (byte)piVar10;
  piVar10 = piVar10 + 2;
  pbVar9 = pbVar9 + 1;
  param_1 = 0;
  local_1c = local_1c | (uint)bVar8 << (bVar4 & 0x1f);
  goto joined_r0x004066e8;
LAB_00406723:
  local_c = local_18[2] + (*(uint *)(&DAT_0041dce8 + (int)local_18[3] * 4) & local_1c) * 2;
  local_1c = local_1c >> (*(byte *)((int)local_c + 1) & 0x1f);
  piVar10 = (int *)((int)piVar10 - (uint)*(byte *)((int)local_c + 1));
  bVar8 = *(byte *)local_c;
  piVar2 = (int *)(uint)bVar8;
  if (piVar2 == (int *)0x0) {
    local_18[2] = (int *)local_c[1];
    *local_18 = (int *)0x6;
                    // WARNING: Bad instruction - Truncating control flow here
    halt_baddata();
  }
  if ((bVar8 & 0x10) != 0) {
    local_18[2] = (int *)((uint)piVar2 & 0xf);
    local_18[1] = (int *)local_c[1];
    *local_18 = (int *)0x2;
                    // WARNING: Bad instruction - Truncating control flow here
    halt_baddata();
  }
  if ((bVar8 & 0x40) == 0) goto LAB_00406797;
  if ((bVar8 & 0x20) != 0) {
    *local_18 = (int *)&DAT_00000007;
                    // WARNING: Bad instruction - Truncating control flow here
    halt_baddata();
  }
  *local_18 = (int *)&DAT_00000009;
  in_EAX[6] = &DAT_0041dd2c;
  param_1 = -3;
  goto LAB_00406b1c;
LAB_00406883:
  local_c = local_18[2] + (*(uint *)(&DAT_0041dce8 + (int)(int *)local_10[3] * 4) & local_1c) * 2;
  bVar8 = *(byte *)local_c;
  piVar2 = (int *)(uint)bVar8;
  if ((bVar8 & 0x10) != 0) {
    local_18[2] = (int *)((uint)piVar2 & 0xf);
    local_18[3] = (int *)local_c[1];
    *local_18 = (int *)0x4;
                    // WARNING: Bad instruction - Truncating control flow here
    halt_baddata();
  }
  if ((bVar8 & 0x40) != 0) {
    *local_18 = (int *)&DAT_00000009;
    in_EAX[6] = (byte *)(s_incorrect_header_check_0041ee3d + 0xb);
                    // WARNING: Bad instruction - Truncating control flow here
    halt_baddata();
  }
LAB_00406797:
  local_18[3] = piVar2;
  local_18[2] = local_c + local_c[1] * 2;
                    // WARNING: Bad instruction - Truncating control flow here
  halt_baddata();
}



// WARNING: Control flow encountered bad instruction data
// WARNING: Instruction at (ram,0x004076ce) overlaps instruction at (ram,0x004076cd)
// 

void __thiscall FUN_00406d54(void *this,uint param_1)

{
  byte bVar1;
  char cVar2;
  byte **in_EAX;
  byte **ppbVar3;
  uint uVar4;
  undefined4 uVar5;
  undefined4 *puVar6;
  byte *pbVar7;
  int iVar8;
  byte bVar9;
  byte *pbVar10;
  undefined4 unaff_EBX;
  byte *unaff_EBP;
  byte *pbVar11;
  byte **unaff_ESI;
  byte *unaff_EDI;
  byte *pbVar12;
  int in_GS_OFFSET;
  int unaff_retaddr;
  undefined4 local_28;
  byte *local_24;
  byte *local_20 [2];
  byte *local_18;
  int iStack_14;
  byte *pbStack_10;
  uint uStack_c;
  byte *local_8;
  uint local_4;
  
  local_24 = *(byte **)((int)this + 0x34);
  local_20[0] = in_EAX[1];
  pbVar11 = *in_EAX;
  local_28 = *(byte ***)((int)this + 0x20);
  pbVar12 = *(byte **)((int)this + 0x1c);
  if (local_24 < *(byte **)((int)this + 0x30)) {
    local_18 = *(byte **)((int)this + 0x30) + (-1 - (int)local_24);
  }
  else {
    local_18 = (byte *)(*(int *)((int)this + 0x2c) - (int)local_24);
  }
                    // WARNING: Load size is inaccurate
  pbVar10 = *this;
  if (&DAT_00000009 < pbVar10) {
    *(byte ***)((int)this + 0x20) = local_28;
    *(byte **)((int)this + 0x1c) = pbVar12;
    in_EAX[1] = local_20[0];
    pbVar12 = *in_EAX;
    *in_EAX = pbVar11;
    in_EAX[2] = in_EAX[2] + ((int)pbVar11 - (int)pbVar12);
    *(byte **)((int)this + 0x34) = local_24;
    func_0x9b946e17(0xfffffffe);
    return;
  }
  do {
    bVar1 = (byte)local_28;
    switch(pbVar10) {
    case (byte *)0x0:
                    // WARNING: Bad instruction - Truncating control flow here
      halt_baddata();
    case (byte *)0x1:
      ppbVar3 = (byte **)((int)local_28 + 1);
      *(byte *)((int)in_EAX + 0x2e7303ff) = *(byte *)((int)in_EAX + 0x2e7303ff) + (char)ppbVar3;
      do {
        if (local_20[0] == (byte *)0x0) {
          *(byte ***)((int)this + 0x20) = local_28;
          *(byte **)((int)this + 0x1c) = pbVar12;
          in_EAX[1] = (byte *)0x0;
          pbVar12 = *in_EAX;
          *in_EAX = pbVar11;
          in_EAX[2] = in_EAX[2] + ((int)pbVar11 - (int)pbVar12);
          *(byte **)((int)this + 0x34) = local_24;
          func_0x9b9474f7(param_1);
          return;
        }
        bVar1 = *pbVar11;
        local_20[0] = local_20[0] + -1;
        bVar9 = (byte)pbVar12;
        pbVar12 = pbVar12 + 8;
        pbVar11 = pbVar11 + 1;
        param_1 = 0;
        ppbVar3 = (byte **)((uint)ppbVar3 | (uint)bVar1 << (bVar9 & 0x1f));
        local_28 = ppbVar3;
      } while (pbVar12 < (byte *)0x3);
      uVar4 = ((uint)ppbVar3 & 7) >> 1;
      *(byte **)((int)this + 0x18) = (byte *)((uint)ppbVar3 & 1);
      if (uVar4 < 4) {
        cVar2 = (char)ppbVar3;
        switch(uVar4) {
        case 0:
          *(byte *)(in_EAX + -0x1d3bf6ed) = *(byte *)(in_EAX + -0x1d3bf6ed) + (char)uVar4;
          goto LAB_004074f7;
        case 1:
          if (uVar4 < 4) {
            *(byte *)((int)in_EAX + -0x3074fc11) = *(byte *)((int)in_EAX + -0x3074fc11) + cVar2;
            *(byte **)this = (byte *)0x1;
                    // WARNING: Bad instruction - Truncating control flow here
            halt_baddata();
          }
          *(byte *)ppbVar3 = *(byte *)ppbVar3 + cVar2;
          break;
        case 2:
          *(byte *)ppbVar3 = *(byte *)ppbVar3 + cVar2;
          pbVar11 = (byte *)func_0x8b956eb2(9,5,0x41dd48,0x41ed48);
          *(byte **)((int)this + 4) = pbVar11;
          if (pbVar11 == (byte *)0x0) {
                    // WARNING: Bad instruction - Truncating control flow here
            halt_baddata();
          }
          break;
        case 3:
          *(byte *)ppbVar3 = *(byte *)ppbVar3 + cVar2;
          *unaff_ESI = (byte *)0x3;
                    // WARNING: Bad instruction - Truncating control flow here
          halt_baddata();
        }
        *(byte **)this = (byte *)0x6;
                    // WARNING: Bad instruction - Truncating control flow here
        halt_baddata();
      }
      break;
    case (byte *)0x2:
      *(byte *)local_28 = *(byte *)local_28 + bVar1;
      for (; pbVar12 < (byte *)0x20; pbVar12 = pbVar12 + 8) {
        if (local_20[0] == (byte *)0x0) {
LAB_004074dc:
          *(byte ***)((int)this + 0x20) = local_28;
          *(byte **)((int)this + 0x1c) = pbVar12;
          in_EAX[1] = (byte *)0x0;
                    // WARNING: Bad instruction - Truncating control flow here
          halt_baddata();
        }
        bVar1 = *pbVar11;
        local_20[0] = local_20[0] + -1;
        pbVar11 = pbVar11 + 1;
        local_28 = (byte **)((uint)local_28 | (uint)bVar1 << ((byte)pbVar12 & 0x1f));
      }
      pbVar10 = (byte *)((uint)local_28 & 0xffff);
      if ((byte *)(~(uint)local_28 >> 0x10) == pbVar10) {
        *(byte **)((int)this + 4) = pbVar10;
        if (pbVar10 == (byte *)0x0) {
          *(byte **)this = (byte *)(-(uint)(*(byte **)((int)this + 0x18) != (byte *)0x0) & 7);
                    // WARNING: Bad instruction - Truncating control flow here
          halt_baddata();
        }
        *(byte **)this = (byte *)0x2;
                    // WARNING: Bad instruction - Truncating control flow here
        halt_baddata();
      }
LAB_004074f7:
      *(undefined **)this = &DAT_00000009;
      in_EAX[6] = &DAT_0041eec0;
      *(byte ***)((int)this + 0x20) = local_28;
      *(byte **)((int)this + 0x1c) = pbVar12;
      in_EAX[1] = local_20[0];
      in_EAX[2] = in_EAX[2] + ((int)pbVar11 - (int)*in_EAX);
      *in_EAX = pbVar11;
      *(byte **)((int)this + 0x34) = local_24;
      func_0x9b94757a(0xfffffffd);
      return;
    case (byte *)0x3:
      *(byte *)local_28 = *(byte *)local_28 + bVar1;
      if (*(int *)((int)local_20 + in_GS_OFFSET) == 0) {
LAB_00407537:
        *(byte ***)((int)this + 0x20) = local_28;
        *(byte **)((int)this + 0x1c) = pbVar12;
        in_EAX[1] = (byte *)0x0;
        in_EAX[2] = in_EAX[2] + ((int)pbVar11 - (int)*in_EAX);
        *in_EAX = pbVar11;
        *(byte **)((int)this + 0x34) = local_24;
        func_0x9b9475b0(param_1);
        return;
      }
      if (local_18 == (byte *)0x0) {
        if (local_24 == *(byte **)((int)this + 0x2c)) {
          pbVar10 = *(byte **)((int)this + 0x30);
          pbVar7 = *(byte **)((int)this + 0x28);
          if (pbVar7 != pbVar10) {
            if (pbVar7 < pbVar10) {
              local_18 = pbVar10 + (-1 - (int)pbVar7);
            }
            else {
              local_18 = *(byte **)((int)this + 0x2c) + -(int)pbVar7;
            }
            local_24 = pbVar7;
            if (local_18 != (byte *)0x0) goto code_r0x00406fbb;
          }
        }
        *(byte **)((int)this + 0x34) = local_24;
        func_0x9b946fae(param_1);
        pbVar10 = *(byte **)((int)this + 0x30);
        local_24 = *(byte **)((int)this + 0x34);
        if (local_24 < pbVar10) {
          local_18 = pbVar10 + (-1 - (int)local_24);
        }
        else {
          local_18 = *(byte **)((int)this + 0x2c) + -(int)local_24;
        }
        if (local_24 == *(byte **)((int)this + 0x2c)) {
          pbVar7 = *(byte **)((int)this + 0x28);
          if (pbVar7 != pbVar10) {
            local_24 = pbVar7;
            if (pbVar7 < pbVar10) {
              local_18 = pbVar10 + (-1 - (int)pbVar7);
            }
            else {
              local_18 = *(byte **)((int)this + 0x2c) + -(int)pbVar7;
            }
          }
        }
        if (local_18 == (byte *)0x0) {
          *(byte ***)((int)this + 0x20) = local_28;
          *(byte **)((int)this + 0x1c) = pbVar12;
          in_EAX[1] = local_20[0];
                    // WARNING: Bad instruction - Truncating control flow here
          halt_baddata();
        }
      }
code_r0x00406fbb:
      param_1 = 0;
      local_20[1] = *(byte **)((int)this + 4);
      if (local_20[0] < *(byte **)((int)this + 4)) {
        local_20[1] = local_20[0];
      }
      if (local_18 < local_20[1]) {
        local_20[1] = local_18;
      }
      func_0xdc1e7042(local_24,pbVar11,local_20[1]);
      local_20[0] = local_20[0] + -(int)local_20[1];
      local_24 = local_24 + (int)local_20[1];
      local_18 = local_18 + -(int)local_20[1];
      pbVar11 = pbVar11 + (int)local_20[1];
      ppbVar3 = (byte **)((int)this + 4);
      *ppbVar3 = *ppbVar3 + -(int)local_20[1];
      if (*ppbVar3 == (byte *)0x0) {
        *(byte **)this = (byte *)(-(uint)(*(byte **)((int)this + 0x18) != (byte *)0x0) & 7);
                    // WARNING: Bad instruction - Truncating control flow here
        halt_baddata();
      }
      break;
    case (byte *)0x4:
      *(byte *)local_28 = *(byte *)local_28 + bVar1;
      pbVar10 = local_20[1];
      pbVar11 = unaff_EBP;
      pbVar12 = unaff_EDI;
      in_EAX = local_28;
      this = unaff_ESI;
      if (unaff_EDI < (byte *)0xe) {
        do {
          if (unaff_retaddr == 0) goto LAB_00407537;
          bVar1 = *pbVar11;
          unaff_retaddr = unaff_retaddr + -1;
          bVar9 = (byte)pbVar12;
          pbVar12 = pbVar12 + 8;
          pbVar11 = pbVar11 + 1;
          pbVar10 = (byte *)((uint)pbVar10 | (uint)bVar1 << (bVar9 & 0x1f));
          local_8 = pbVar10;
        } while (pbVar12 < (byte *)0xe);
      }
      unaff_ESI[1] = (byte *)((uint)pbVar10 & 0x3fff);
      if ((0x1d < ((uint)pbVar10 & 0x1f)) ||
         (uVar4 = (uint)(byte *)((uint)pbVar10 & 0x3fff) >> 5 & 0x1f, 0x1d < uVar4)) {
        *unaff_ESI = &DAT_00000009;
        local_28[6] = &DAT_0041eee0;
                    // WARNING: Bad instruction - Truncating control flow here
        halt_baddata();
      }
      local_20[0] = (byte *)(uVar4 + 0x102 + ((uint)pbVar10 & 0x1f));
      local_24 = local_28[10];
      local_20[1] = (byte *)0x4;
      pbVar10 = (byte *)(*(code *)local_28[8])();
      unaff_ESI[3] = pbVar10;
      if (pbVar10 == (byte *)0x0) {
        unaff_ESI[8] = (byte *)0x40708e;
        unaff_ESI[7] = pbVar12;
        local_28[1] = local_20[0];
        local_28[2] = local_28[2] + ((int)pbVar11 - (int)*local_28);
        *local_28 = pbVar11;
        unaff_ESI[0xd] = local_24;
        func_0x9b9475f9(0xfffffffc);
        return;
      }
      pbVar12 = pbVar12 + -0xe;
      unaff_ESI[2] = (byte *)0x0;
      *unaff_ESI = (byte *)0x4;
      local_28 = (byte **)0x101;
      goto code_r0x004070b5;
    case (byte *)0x5:
      *(byte *)local_28 = *(byte *)local_28 + bVar1;
code_r0x004070b5:
      if (*(byte **)((int)this + 8) < (byte *)(((uint)*(byte **)((int)this + 4) >> 10) + 4)) {
        do {
          for (; pbVar12 < (byte *)0x3; pbVar12 = pbVar12 + 8) {
            if (local_20[0] == (byte *)0x0) goto LAB_00407537;
            bVar1 = *pbVar11;
            local_20[0] = local_20[0] + -1;
            pbVar11 = pbVar11 + 1;
            param_1 = 0;
            local_28 = (byte **)((uint)local_28 | (uint)bVar1 << ((byte)pbVar12 & 0x1f));
          }
          *(uint *)(*(byte **)((int)this + 0xc) +
                   *(int *)(s_need_dictionary_0041ee55 + (int)*(byte **)((int)this + 8) * 4 + 0xb) *
                   4) = (uint)local_28 & 7;
          *(byte **)((int)this + 8) = *(byte **)((int)this + 8) + 1;
          local_28 = (byte **)((uint)local_28 >> 3);
          pbVar12 = pbVar12 + -3;
        } while (*(byte **)((int)this + 8) < (byte *)(((uint)*(byte **)((int)this + 4) >> 10) + 4));
      }
      pbVar10 = *(byte **)((int)this + 8);
      while (pbVar10 < (byte *)0x13) {
        *(undefined4 *)
         (*(byte **)((int)this + 0xc) +
         *(int *)(s_need_dictionary_0041ee55 + (int)*(byte **)((int)this + 8) * 4 + 0xb) * 4) = 0;
        *(byte **)((int)this + 8) = *(byte **)((int)this + 8) + 1;
        pbVar10 = *(byte **)((int)this + 8);
      }
      *(byte **)((int)this + 0x10) = &DAT_00000007;
      local_20[1] = (byte *)func_0x7bac71ba(*(byte **)((int)this + 0xc),(byte **)((int)this + 0x10),
                                            (byte **)((int)this + 0x14),*(byte **)((int)this + 0x24)
                                           );
      if (local_20[1] != (byte *)0x0) {
        if (local_20[1] == (byte *)0xfffffffd) {
          (*(code *)in_EAX[9])(in_EAX[10],*(byte **)((int)this + 0xc));
          *(undefined **)this = &DAT_00000009;
        }
        *(byte ***)((int)this + 0x20) = local_28;
        *(byte **)((int)this + 0x1c) = pbVar12;
        in_EAX[1] = local_20[0];
                    // WARNING: Bad instruction - Truncating control flow here
        halt_baddata();
      }
      *(byte **)((int)this + 8) = (byte *)0x0;
      *(undefined **)this = &DAT_00000005;
      local_20[1] = (byte *)0x0;
      if (*(byte **)((int)this + 8) <
          (byte *)(((uint)*(byte **)((int)this + 4) >> 5 & 0x1f) + 0x102 +
                  ((uint)*(byte **)((int)this + 4) & 0x1f))) {
        local_20[1] = (byte *)0x0;
        do {
          pbVar10 = *(byte **)((int)this + 0x10);
          if (pbVar12 < pbVar10) {
            do {
              if (local_20[0] == (byte *)0x0) goto LAB_00407537;
              bVar1 = *pbVar11;
              local_20[0] = local_20[0] + -1;
              bVar9 = (byte)pbVar12;
              pbVar10 = *(byte **)((int)this + 0x10);
              pbVar12 = pbVar12 + 8;
              pbVar11 = pbVar11 + 1;
              local_28 = (byte **)((uint)local_28 | (uint)bVar1 << (bVar9 & 0x1f));
              param_1 = 0;
            } while (pbVar12 < pbVar10);
          }
          bVar1 = (*(byte **)((int)this + 0x14))
                  [(*(uint *)(&DAT_0041dce8 + (int)pbVar10 * 4) & (uint)local_28) * 8 + 1];
          local_20[1] = (byte *)(uint)bVar1;
          uStack_c = *(uint *)(*(byte **)((int)this + 0x14) +
                              (*(uint *)(&DAT_0041dce8 + (int)pbVar10 * 4) & (uint)local_28) * 8 + 4
                              );
          if (uStack_c < 0x10) {
            *(uint *)(*(byte **)((int)this + 0xc) + (int)*(byte **)((int)this + 8) * 4) = uStack_c;
            *(byte **)((int)this + 8) = *(byte **)((int)this + 8) + 1;
                    // WARNING: Bad instruction - Truncating control flow here
            halt_baddata();
          }
          if (uStack_c == 0x12) {
            iStack_14 = 7;
          }
          else {
            iStack_14 = uStack_c - 0xe;
          }
          pbStack_10 = local_20[1] + iStack_14;
          for (; pbVar12 < pbStack_10; pbVar12 = pbVar12 + 8) {
            if (local_20[0] == (byte *)0x0) goto LAB_004074dc;
            bVar9 = *pbVar11;
            local_20[0] = local_20[0] + -1;
            pbVar11 = pbVar11 + 1;
            param_1 = 0;
            local_28 = (byte **)((uint)local_28 | (uint)bVar9 << ((byte)pbVar12 & 0x1f));
          }
          uVar4 = (uint)local_28 >> (bVar1 & 0x1f);
          local_18 = (byte *)((uint)(uStack_c == 0x12) * 8 + 3 +
                             (*(uint *)(&DAT_0041dce8 + iStack_14 * 4) & uVar4));
          local_28 = (byte **)(uVar4 >> ((byte)iStack_14 & 0x1f));
          pbVar12 = pbVar12 + -(int)(local_20[1] + iStack_14);
          pbVar10 = *(byte **)((int)this + 8);
          if ((byte *)(((uint)*(byte **)((int)this + 4) >> 5 & 0x1f) + 0x102 +
                      ((uint)*(byte **)((int)this + 4) & 0x1f)) < pbVar10 + (int)local_18) {
LAB_004075ff:
            (*(code *)in_EAX[9])(in_EAX[10],*(byte **)((int)this + 0xc));
            *(undefined **)this = &DAT_00000009;
            in_EAX[6] = (byte *)((int)u_unknown_zip_result_code_0041ef01 + 3);
            *(byte ***)((int)this + 0x20) = local_28;
            *(byte **)((int)this + 0x1c) = pbVar12;
            in_EAX[1] = local_20[0];
            in_EAX[2] = in_EAX[2] + ((int)pbVar11 - (int)*in_EAX);
            *in_EAX = pbVar11;
            *(byte **)((int)this + 0x34) = local_24;
            func_0x9b94768f(0xfffffffd);
            return;
          }
          if (uStack_c == 0x10) {
            if (pbVar10 == (byte *)0x0) goto LAB_004075ff;
            uVar5 = *(undefined4 *)(*(byte **)((int)this + 0xc) + (int)pbVar10 * 4 + -4);
          }
          else {
            uVar5 = 0;
          }
          do {
            *(undefined4 *)(*(byte **)((int)this + 0xc) + (int)pbVar10 * 4) = uVar5;
            pbVar10 = pbVar10 + 1;
            local_18 = local_18 + -1;
          } while (local_18 != (byte *)0x0);
          *(byte **)((int)this + 8) = pbVar10;
          if ((byte *)(((uint)*(byte **)((int)this + 4) >> 5 & 0x1f) + 0x102 +
                      ((uint)*(byte **)((int)this + 4) & 0x1f)) <= *(byte **)((int)this + 8)) break;
          local_18 = (byte *)0x0;
        } while( true );
      }
      *(byte **)((int)this + 0x14) = (byte *)0x0;
      iStack_14 = 9;
      local_18 = (byte *)0x6;
      local_20[1] = (byte *)func_0x1bad73c4(((uint)*(byte **)((int)this + 4) & 0x1f) + 0x101,
                                            ((uint)*(byte **)((int)this + 4) >> 5 & 0x1f) + 1,
                                            *(byte **)((int)this + 0xc),&iStack_14,&local_18,
                                            &local_8,&local_4,*(byte **)((int)this + 0x24));
      if (local_20[1] != (byte *)0x0) {
        if (local_20[1] == (byte *)0xfffffffd) {
          (*(code *)in_EAX[9])(in_EAX[10],*(byte **)((int)this + 0xc));
          *(undefined **)this = &DAT_00000009;
        }
        *(byte ***)((int)this + 0x20) = local_28;
        *(byte **)((int)this + 0x1c) = pbVar12;
        in_EAX[1] = local_20[0];
                    // WARNING: Bad instruction - Truncating control flow here
        halt_baddata();
      }
      puVar6 = (undefined4 *)(*(code *)in_EAX[8])(in_EAX[10],1,0x1a);
      if (puVar6 == (undefined4 *)0x0) {
        *(byte ***)((int)this + 0x20) = local_28;
        *(byte **)((int)this + 0x1c) = pbVar12;
        in_EAX[1] = local_20[0];
        in_EAX[2] = in_EAX[2] + ((int)pbVar11 - (int)*in_EAX);
        *in_EAX = pbVar11;
        *(byte **)((int)this + 0x34) = local_24;
        func_0x9b9476fa(0xfffffffc);
        return;
      }
      *(undefined *)(puVar6 + 4) = (undefined)iStack_14;
      *(undefined *)((int)puVar6 + 0x11) = local_18._0_1_;
      *puVar6 = 0;
      *(byte **)((int)puVar6 + 0x12) = local_8;
      *(uint *)((int)puVar6 + 0x16) = local_4;
      *(undefined4 **)((int)this + 4) = puVar6;
      (*(code *)in_EAX[9])(in_EAX[10],*(byte **)((int)this + 0xc));
      *(byte **)this = (byte *)0x6;
      pbVar7 = (byte *)CONCAT31((int3)unaff_EBX,(char)((uint)unaff_EBP >> 0x18));
      pbVar10 = (byte *)CONCAT31(local_24._0_3_,local_28._3_1_);
code_r0x004073e0:
      *(byte **)((int)this + 0x20) = pbVar7;
      *(byte **)((int)this + 0x1c) = pbVar12;
      in_EAX[1] = pbVar10;
      pbVar12 = *in_EAX;
      *in_EAX = pbVar11;
      in_EAX[2] = in_EAX[2] + ((int)pbVar11 - (int)pbVar12);
      *(byte **)((int)this + 0x34) =
           (byte *)CONCAT31((undefined3)local_28,(char)((uint)unaff_EBX >> 0x18));
      iVar8 = func_0xcb957455();
      if (iVar8 != 1) {
        func_0x9b94770b();
        return;
      }
      local_4 = local_4 & 0xffffff;
      (*(code *)in_EAX[9])();
      local_28 = *(byte ***)((int)this + 0x20);
      local_24 = *(byte **)((int)this + 0x34);
      pbVar11 = *in_EAX;
      pbVar12 = *(byte **)((int)this + 0x1c);
      local_20[0] = in_EAX[1];
      if (local_24 < *(byte **)((int)this + 0x30)) {
        local_18 = *(byte **)((int)this + 0x30) + (-1 - (int)local_24);
      }
      else {
        local_18 = *(byte **)((int)this + 0x2c) + -(int)local_24;
      }
      if (*(byte **)((int)this + 0x18) != (byte *)0x0) {
        *(undefined **)this = &DAT_00000007;
code_r0x004076d6:
        *(byte **)((int)this + 0x34) = local_24;
        func_0x9b94772d(param_1);
        local_24 = *(byte **)((int)this + 0x34);
        if (*(byte **)((int)this + 0x30) != local_24) {
          *(byte ***)((int)this + 0x20) = local_28;
          *(byte **)((int)this + 0x1c) = pbVar12;
          in_EAX[1] = local_20[0];
                    // WARNING: Bad instruction - Truncating control flow here
          halt_baddata();
        }
        *(byte **)this = (byte *)0x8;
code_r0x0040770b:
        *(byte ***)((int)this + 0x20) = local_28;
        *(byte **)((int)this + 0x1c) = pbVar12;
        in_EAX[1] = local_20[0];
        in_EAX[2] = in_EAX[2] + ((int)pbVar11 - (int)*in_EAX);
        *in_EAX = pbVar11;
        *(byte **)((int)this + 0x34) = local_24;
        func_0x9b947781(1);
        return;
      }
      *(byte **)this = (byte *)0x0;
      break;
    case (byte *)0x6:
                    // WARNING: Bad instruction - Truncating control flow here
      halt_baddata();
    case (byte *)0x7:
      *(byte *)local_28 = *(byte *)local_28 + bVar1;
      *(byte *)(in_EAX + -0x1d3bf6ef) = *(byte *)(in_EAX + -0x1d3bf6ef) + (char)pbVar10;
      pbVar7 = (byte *)((uint)local_28 & 0xffffff18);
      goto code_r0x004073e0;
    case (byte *)0x8:
      *(byte *)local_28 = *(byte *)local_28 + bVar1;
      *(byte *)(in_EAX + -0x1d30f6ef) = *(byte *)(in_EAX + -0x1d30f6ef) + (char)pbVar10;
      param_1 = (uint)local_28 & 0xffffff14;
      local_24 = local_18;
      goto code_r0x004076d6;
    case (byte *)0x9:
      *(byte *)local_28 = *(byte *)local_28 | bVar1;
      *(byte *)local_28 = *(byte *)local_28 + bVar1;
      goto code_r0x0040770b;
    }
                    // WARNING: Load size is inaccurate
    pbVar10 = *this;
    if (&DAT_00000009 < pbVar10) {
                    // WARNING: Bad instruction - Truncating control flow here
      halt_baddata();
    }
  } while( true );
}


/*
Unable to decompile 'FUN_00407d24'
Cause: 
Low-level Error: Bad size for array of type wchar_t
*/


// WARNING: Removing unreachable block (ram,0x00408c6d)

int __fastcall FUN_00408bf4(undefined4 param_1,undefined2 param_2)

{
  undefined *puVar1;
  int iVar2;
  undefined4 in_EAX;
  int iVar3;
  uint uVar4;
  int iVar5;
  uint extraout_ECX;
  uint extraout_ECX_00;
  uint uVar6;
  char *unaff_EBX;
  int iVar7;
  char *unaff_ESI;
  uint unaff_EDI;
  undefined6 uVar8;
  int iStack_14;
  uint uStack_10;
  uint uStack_c;
  int iStack_8;
  uint uStack_4;
  
  uVar8 = CONCAT24(param_2,in_EAX);
  if (*unaff_ESI == '\0') {
    uVar4 = *(uint *)(unaff_ESI + 0x10);
    *(uint *)(unaff_ESI + 0x14) = uVar4;
  }
  else {
    if (unaff_ESI[1] == '\0') {
      return -1;
    }
    uVar8 = (*(code *)s_R6002___floating_point_support_n_0041c059._15_4_)
                      (*(undefined4 *)(unaff_ESI + 2),0,0,2);
    uVar4 = extraout_ECX;
  }
  if (*unaff_ESI == '\0') {
    iVar7 = *(int *)(unaff_ESI + 0x14);
    uVar8 = CONCAT24((short)((uint6)uVar8 >> 0x20),iVar7);
  }
  else if (unaff_ESI[1] == '\0') {
    iVar7 = 0;
  }
  else {
    uVar8 = (*(code *)s_R6002___floating_point_support_n_0041c059._15_4_)
                      (*(undefined4 *)(unaff_ESI + 2),0,0,1);
    iVar7 = (int)uVar8 - *(int *)(unaff_ESI + 7);
    uVar4 = extraout_ECX_00;
  }
  *unaff_EBX = *unaff_EBX + (char)((uint)unaff_EBX >> 8);
  puVar1 = (undefined *)((uVar4 & 0xffffff00) + 0x3b0c247c);
  *puVar1 = *puVar1;
  out((short)((uint6)uVar8 >> 0x20),(int)uVar8);
  iVar3 = func_0xe1e58ccc(0x404);
  if (iVar3 == 0) {
    return -1;
  }
  uStack_c = 4;
  iStack_8 = -1;
  if (4 < unaff_EDI) {
    do {
      uVar4 = uStack_c + 0x400;
      uStack_c = unaff_EDI;
      if (uVar4 <= unaff_EDI) {
        uStack_c = uVar4;
      }
      iVar5 = iVar7 - uStack_c;
      uVar4 = iVar7 - iVar5;
      if (0x404 < uVar4) {
        uVar4 = 0x404;
      }
      if (unaff_ESI[-1] == '\0') {
        *(int *)(unaff_ESI + 0x13) = iVar5;
      }
      else {
        if (*unaff_ESI == '\0') break;
        (*(code *)s_R6002___floating_point_support_n_0041c059._15_4_)
                  (*(undefined4 *)(unaff_ESI + 1),*(int *)(unaff_ESI + 6) + iVar5,0,0);
      }
      if (unaff_ESI[-1] == '\0') {
        iVar7 = *(int *)(unaff_ESI + 0x13);
        uVar6 = uVar4;
        if (*(uint *)(unaff_ESI + 0xf) < iVar7 + uVar4) {
          uVar6 = *(uint *)(unaff_ESI + 0xf) - iVar7;
        }
        func_0xdc1e8d9a(iVar3,*(int *)(unaff_ESI + 0xb) + iVar7,uVar6);
        *(uint *)(unaff_ESI + 0x13) = *(int *)(unaff_ESI + 0x13) + uVar6;
      }
      else {
        iVar7 = (*(code *)s_R6008___not_enough_space_for_arg_0041c02d._3_4_)
                          (*(undefined4 *)(unaff_ESI + 1),iVar3,uVar4,&uStack_4,0);
        uVar6 = uStack_4;
        if (iVar7 == 0) {
          unaff_ESI[5] = '\x01';
        }
      }
      if (uVar6 / uVar4 != 1) break;
      iVar7 = uVar4 - 3;
      do {
        iVar2 = iVar7;
        if (iVar2 < 0) goto LAB_00408d90;
        iVar7 = iVar2 + -1;
      } while ((((*(char *)(iVar7 + iVar3) != 'P') || (*(char *)(iVar2 + iVar3) != 'K')) ||
               (*(char *)(iVar2 + 1 + iVar3) != '\x05')) || (*(char *)(iVar2 + 2 + iVar3) != '\x06')
              );
      iStack_8 = iVar7 + iVar5;
LAB_00408d90:
      if ((iStack_8 != 0) || (iVar7 = iStack_14, unaff_EDI = uStack_10, uStack_10 <= uStack_c))
      break;
    } while( true );
  }
  func_0x42eb8df9(iVar3);
  return iStack_8;
}



// WARNING: Control flow encountered bad instruction data

int __cdecl FUN_00409054(int *param_1,int *param_2,int param_3,uint param_4)

{
  char *pcVar1;
  char **in_EAX;
  int iVar2;
  int iVar3;
  int *piVar4;
  int local_5c;
  int local_58;
  int aiStack_54 [4];
  uint uStack_44;
  uint uStack_34;
  int iStack_30;
  int iStack_2c;
  int iStack_28;
  int iStack_24;
  int iStack_1c;
  uint uStack_18;
  uint uStack_14;
  uint uStack_10;
  int iStack_c;
  int iStack_8;
  
  local_5c = 0;
  if (in_EAX == (char **)0x0) {
    return -0x66;
  }
  pcVar1 = *in_EAX;
  if (*pcVar1 == '\0') {
    *(char **)(pcVar1 + 0x14) = in_EAX[5] + (int)in_EAX[3];
  }
  else {
    if (pcVar1[1] == '\0') {
      local_5c = -1;
      goto LAB_004090d3;
    }
    (*(code *)s_R6002___floating_point_support_n_0041c059._15_4_)
              (*(undefined4 *)(pcVar1 + 2),in_EAX[5] + (int)in_EAX[3] + *(int *)(pcVar1 + 7),0,0);
  }
  iVar2 = func_0x6bbb90f0();
  if (iVar2 == 0) {
    if (local_58 != 0x2014b50) {
      local_5c = -0x67;
    }
  }
  else {
    local_5c = -1;
  }
LAB_004090d3:
  iVar2 = func_0xdbba912d(&local_58);
  aiStack_54[0] = local_58;
  if ((iVar2 == 0) && (iVar2 = func_0xdbba9142(&local_58), iVar2 == 0)) {
    aiStack_54[0] = local_58 * 0x100 + aiStack_54[0];
  }
  else {
    aiStack_54[0] = 0;
    if (iVar2 != 0) {
      local_5c = -1;
    }
  }
  iVar2 = func_0xdbba9174(&local_58);
  aiStack_54[1] = local_58;
  if ((iVar2 == 0) && (iVar2 = func_0xdbba9189(&local_58), iVar2 == 0)) {
    aiStack_54[1] = local_58 * 0x100 + aiStack_54[1];
  }
  else {
    aiStack_54[1] = 0;
    if (iVar2 != 0) {
      local_5c = -1;
    }
  }
  iVar2 = func_0xdbba91bb(&local_58);
  aiStack_54[2] = local_58;
  if ((iVar2 == 0) && (iVar2 = func_0xdbba91d0(&local_58), iVar2 == 0)) {
    aiStack_54[2] = local_58 * 0x100 + aiStack_54[2];
  }
  else {
    aiStack_54[2] = 0;
    if (iVar2 != 0) {
      local_5c = -1;
    }
  }
  iVar2 = func_0xdbba9202(&local_58);
  aiStack_54[3] = local_58;
  if ((iVar2 == 0) && (iVar2 = func_0xdbba921b(&local_58), iVar2 == 0)) {
    aiStack_54[3] = local_58 * 0x100 + aiStack_54[3];
  }
  else {
    aiStack_54[3] = 0;
    if (iVar2 != 0) {
                    // WARNING: Bad instruction - Truncating control flow here
      halt_baddata();
    }
  }
  iVar2 = func_0x6bbb9241();
  if (iVar2 != 0) {
    local_5c = -1;
  }
  uStack_10 = uStack_44 >> 0x10 & 0x1f;
  iStack_8 = (uStack_44 >> 0x19) + 0x7bc;
  iStack_c = (uStack_44 >> 0x15 & 0xf) - 1;
  uStack_14 = uStack_44 >> 0xb & 0x1f;
  uStack_18 = uStack_44 >> 5 & 0x3f;
  iStack_1c = (uStack_44 & 0x1f) * 2;
  iVar2 = func_0x6bbb92a3();
  if (iVar2 != 0) {
    local_5c = -1;
  }
  iVar2 = func_0x6bbb92b6();
  if (iVar2 != 0) {
    local_5c = -1;
  }
  iVar2 = func_0x6bbb92c9();
  if (iVar2 != 0) {
    local_5c = -1;
  }
  iVar3 = func_0xdbba92dd(&local_58);
  iVar2 = local_58;
  if ((iVar3 == 0) && (iVar3 = func_0xdbba92f4(&local_58), iVar3 == 0)) {
    uStack_34 = local_58 * 0x100 + iVar2;
  }
  else {
    uStack_34 = 0;
    if (iVar3 != 0) {
      local_5c = -1;
    }
  }
  iVar2 = func_0xdbba933e(&local_58);
  iStack_30 = local_58;
  if ((iVar2 == 0) && (iVar2 = func_0xdbba9353(&local_58), iVar2 == 0)) {
    iStack_30 = local_58 * 0x100 + iStack_30;
  }
  else {
    iStack_30 = 0;
    if (iVar2 != 0) {
      local_5c = -1;
    }
  }
  iVar2 = func_0xdbba9385(&local_58);
  iStack_2c = local_58;
  if ((iVar2 == 0) && (iVar2 = func_0xdbba939a(&local_58), iVar2 == 0)) {
    iStack_2c = local_58 * 0x100 + iStack_2c;
  }
  else {
    iStack_2c = 0;
    if (iVar2 != 0) {
      local_5c = -1;
    }
  }
  iVar2 = func_0xdbba93cc(&local_58);
  iStack_28 = local_58;
  if ((iVar2 == 0) && (iVar2 = func_0xdbba93e1(&local_58), iVar2 == 0)) {
    iStack_28 = local_58 * 0x100 + iStack_28;
  }
  else {
    iStack_28 = 0;
    if (iVar2 != 0) {
      local_5c = -1;
    }
  }
  iVar2 = func_0xdbba9413(&local_58);
  iStack_24 = local_58;
  if ((iVar2 == 0) && (iVar2 = func_0xdbba9428(&local_58), iVar2 == 0)) {
    iStack_24 = local_58 * 0x100 + iStack_24;
  }
  else {
    iStack_24 = 0;
    if (iVar2 != 0) {
      local_5c = -1;
    }
  }
  iVar2 = func_0x6bbb944a();
  if (iVar2 != 0) {
    local_5c = -1;
  }
  iVar2 = func_0x6bbb945d();
  if (iVar2 != 0) {
    return -1;
  }
  if (local_5c == 0) {
    if (param_3 != 0) {
      if (uStack_34 < param_4) {
        *(undefined *)(uStack_34 + param_3) = 0;
      }
      if (((uStack_34 != 0) && (param_4 != 0)) && (iVar2 = func_0x7bba94b6(1), iVar2 != 1)) {
        return -1;
      }
    }
    if (param_1 != (int *)0x0) {
      piVar4 = aiStack_54;
      for (iVar2 = 0x14; iVar2 != 0; iVar2 = iVar2 + -1) {
        *param_1 = *piVar4;
        piVar4 = piVar4 + 1;
        param_1 = param_1 + 1;
      }
    }
    if (param_2 != (int *)0x0) {
      *param_2 = local_58;
    }
  }
  return local_5c;
}



undefined4 __cdecl FUN_00409774(char *param_1)

{
  int *in_EAX;
  int iVar1;
  int *piVar2;
  int local_c;
  int local_8;
  int local_4;
  
  if ((in_EAX == (int *)0x0) || (in_EAX[6] == 0)) {
    return 0xffffff9a;
  }
  if (in_EAX[0x1f] != 0) {
    func_0x4bcb97ef();
  }
  iVar1 = func_0xdbc49803(&local_4,&local_c,&local_8);
  if (iVar1 != 0) {
    return 0xffffff99;
  }
  piVar2 = (int *)func_0xe1e5981e(0x7e);
  if (piVar2 != (int *)0x0) {
    iVar1 = func_0xe1e59831(0x4000);
    *piVar2 = iVar1;
    piVar2[0x11] = local_c;
    piVar2[0x12] = local_8;
    piVar2[0x13] = 0;
    if (iVar1 != 0) {
      piVar2[0x10] = 0;
      iVar1 = in_EAX[0xd];
      piVar2[0x15] = in_EAX[0xf];
      piVar2[0x14] = 0;
      piVar2[0x19] = in_EAX[0xd];
      piVar2[0x18] = *in_EAX;
      piVar2[0x1a] = in_EAX[3];
      piVar2[6] = 0;
      if (iVar1 != 0) {
        piVar2[9] = 0;
        piVar2[10] = 0;
        piVar2[0xb] = 0;
        iVar1 = func_0x2bb6989e();
        if (iVar1 == 0) {
          piVar2[0x10] = 1;
        }
      }
      piVar2[0x16] = in_EAX[0x10];
      piVar2[0x17] = in_EAX[0x11];
      *(byte *)(piVar2 + 0x1b) = *(byte *)(in_EAX + 0xc) & 1;
      if (((uint)in_EAX[0xc] >> 3 & 1) == 0) {
        *(undefined *)((int)piVar2 + 0x7d) = *(undefined *)((int)in_EAX + 0x3f);
      }
      else {
        *(undefined *)((int)piVar2 + 0x7d) = *(undefined *)((int)in_EAX + 0x39);
      }
      *(uint *)((int)piVar2 + 0x79) = -(uint)(*(char *)(piVar2 + 0x1b) != '\0') & 0xc;
      *(undefined4 *)((int)piVar2 + 0x6d) = 0x12345678;
      *(undefined4 *)((int)piVar2 + 0x71) = 0x23456789;
      *(undefined4 *)((int)piVar2 + 0x75) = 0x34567890;
      if (param_1 != (char *)0x0) {
        do {
          if (*param_1 == '\0') break;
          func_0x1bb3990e();
          param_1 = param_1 + 1;
        } while (param_1 != (char *)0x0);
      }
      piVar2[0xf] = in_EAX[0x1e] + 0x1e + local_4;
      piVar2[2] = 0;
      in_EAX[0x1f] = (int)piVar2;
      return 0;
    }
    func_0x42eb9851(piVar2);
  }
  return 0xffffff98;
}



undefined8 __fastcall FUN_00409bd4(uint param_1)

{
  uint in_EAX;
  undefined4 unaff_ESI;
  undefined4 uStack_20;
  undefined local_1c [8];
  short local_14;
  ushort local_12;
  ushort local_e;
  ushort local_c;
  ushort local_a;
  short local_8;
  undefined2 local_6;
  
  local_14 = ((ushort)param_1 >> 9) + 0x7bc;
  local_12 = (ushort)(param_1 >> 5) & 0xf;
  local_e = (ushort)param_1 & 0x1f;
  local_c = (ushort)in_EAX >> 0xb;
  local_a = (ushort)(in_EAX >> 5) & 0x3f;
  local_8 = ((ushort)in_EAX & 0x1f) * 2;
  local_6 = 0;
  (*(code *)s_R6002___floating_point_support_n_0041c059._19_4_)(&local_14,local_1c);
  return CONCAT44(uStack_20,unaff_ESI);
}



void FUN_0040a344(undefined4 param_1,undefined4 param_2)

{
  int iVar1;
  int iVar2;
  int *unaff_EBX;
  undefined auStack_8 [3];
  char local_5;
  uint local_4;
  
  local_4 = s__Repeat_del___s__if_exist___s__g_00422037._13_4_ ^ (uint)auStack_8;
  if (unaff_EBX[1] != 0) {
    if (unaff_EBX[1] != -1) {
      func_0x4bcba3be();
    }
    unaff_EBX[1] = -1;
    if (*(int *)(*unaff_EBX + 4) < 1) {
      func_0xf1d5a3e0();
      return;
    }
    if (0 < *(int *)(*unaff_EBX + 0x10)) {
      func_0x9bc4a3f1();
    }
    iVar2 = *(int *)(*unaff_EBX + 0x10);
    while (iVar2 < 0) {
      iVar2 = *unaff_EBX;
      if (((iVar2 != 0) && (*(int *)(iVar2 + 0x18) != 0)) &&
         (iVar1 = *(int *)(iVar2 + 0x10) + 1, iVar1 != *(int *)(iVar2 + 4))) {
        *(int *)(iVar2 + 0x14) =
             *(int *)(iVar2 + 0x14) +
             *(int *)(iVar2 + 0x50) + *(int *)(iVar2 + 0x4c) + 0x2e + *(int *)(iVar2 + 0x48);
        *(int *)(iVar2 + 0x10) = iVar1;
        iVar1 = func_0x4bc0a434(iVar2 + 0x28,iVar2 + 0x78,0,0);
        *(uint *)(iVar2 + 0x18) = (uint)(iVar1 == 0);
      }
      iVar2 = *(int *)(*unaff_EBX + 0x10);
    }
    func_0x6bc7a455(unaff_EBX[0x8f]);
    unaff_EBX[1] = 0;
  }
  iVar2 = func_0xdbc8a470(param_1,&local_5);
  if (iVar2 < 1) {
    func_0x4bcba480();
    unaff_EBX[1] = -1;
  }
  if (local_5 == '\0') {
    if (iVar2 < 1) {
      func_0xf1d5a4e2();
      return;
    }
    func_0xf1d5a4bb();
    return;
  }
  func_0xf1d5a49e();
  return;
}



// WARNING: Globals starting with '_' overlap smaller symbols at the same address

undefined4 * __cdecl FUN_0040a504(undefined4 param_1,undefined4 param_2)

{
  int iVar1;
  undefined4 *puVar2;
  void *pvStack_14;
  void *local_c;
  undefined *puStack_8;
  undefined4 uStack_4;
  
  uStack_4 = 0xffffffff;
  puStack_8 = &DAT_0041b74b;
  local_c = ExceptionList;
  ExceptionList = &local_c;
  iVar1 = func_0x24e0a580(0x44c,s__Repeat_del___s__if_exist___s__g_00422037._13_4_ ^
                                (uint)&stack0xffffffe8);
  uStack_4 = 0;
  if (iVar1 == 0) {
    iVar1 = 0;
  }
  else {
    iVar1 = func_0x4bcca59a();
  }
  uStack_4 = 0xffffffff;
  _DAT_00425234 = func_0xabcca5b7(param_1,param_2);
  if (_DAT_00425234 != 0) {
    if (iVar1 != 0) {
      func_0xabd5a5c9();
    }
    ExceptionList = pvStack_14;
    return (undefined4 *)0x0;
  }
  puVar2 = (undefined4 *)func_0x24e0a5e3(8);
  *puVar2 = 1;
  puVar2[1] = iVar1;
  ExceptionList = pvStack_14;
  return puVar2;
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
        puVar2 = (undefined4 *)func_0x89f5a6cb();
        eVar4 = 0x22;
        *puVar2 = 0x22;
        goto LAB_0040a62b;
      }
    }
    *_Dst = L'\0';
  }
  puVar2 = (undefined4 *)func_0x89f5a674();
  eVar4 = 0x16;
  *puVar2 = 0x16;
LAB_0040a62b:
  func_0x21f5a683(0,0,0,0,0);
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
      puVar2 = (undefined4 *)func_0x89f5a73a();
      eVar4 = 0x22;
      *puVar2 = 0x22;
      goto LAB_0040a6a8;
    }
    *_Dst = L'\0';
  }
  puVar2 = (undefined4 *)func_0x89f5a6f1();
  eVar4 = 0x16;
  *puVar2 = 0x16;
LAB_0040a6a8:
  func_0x21f5a700(0,0,0,0,0);
  return eVar4;
}



void __cdecl FUN_0040a6f5(undefined4 param_1)

{
  int iVar1;
  
  iVar1 = func_0x99f8a74d();
  *(undefined4 *)(iVar1 + 0x14) = param_1;
  return;
}



// WARNING: Control flow encountered bad instruction data
// WARNING: Instruction at (ram,0x0040a9fd) overlaps instruction at (ram,0x0040a9fc)
// 

undefined4 * __cdecl FUN_0040a734(undefined4 *param_1,undefined4 *param_2,uint param_3)

{
  uint *puVar1;
  int iVar2;
  undefined4 *puVar3;
  uint uVar4;
  undefined4 *puVar5;
  uint uVar6;
  uint uVar7;
  int unaff_EBX;
  undefined4 *puVar8;
  undefined4 *puVar9;
  byte in_AF;
  bool bVar10;
  
  puVar3 = (undefined4 *)(param_3 + (int)param_2);
  if ((param_2 < param_1) && (param_1 < puVar3)) {
    puVar8 = (undefined4 *)((param_3 - 4) + (int)param_2);
    puVar5 = (undefined4 *)((param_3 - 4) + (int)param_1);
    puVar9 = puVar5;
    if (((uint)puVar5 & 3) != 0) {
      uVar7 = 3;
      bVar10 = SBORROW4(param_3,4);
      iVar2 = param_3 - 4;
      switch(param_3) {
      case 0:
        goto switchD_0040ef40_caseD_0;
      case 1:
        goto switchD_0040a917_caseD_1;
      case 2:
code_r0x0040aa59:
        return puVar5;
      case 3:
switchD_0040a917_caseD_3:
        return puVar5;
      default:
        switch((uint)puVar5 & 3) {
        case 1:
                    // WARNING: Bad instruction - Truncating control flow here
          halt_baddata();
        case 2:
          puVar1 = (uint *)(DAT_8a0040a9 + 0xee830347);
          *puVar1 = *puVar1 >> 1 | (uint)((*puVar1 & 1) != 0) << 0x1f;
                    // WARNING: Bad instruction - Truncating control flow here
          halt_baddata();
        case 3:
          puVar1 = (uint *)(((uint)puVar5 & 3) + 0x468a0347);
          *puVar1 = *puVar1 >> 1 | (uint)((*puVar1 & 1) != 0) << 0x1f;
                    // WARNING: Bad instruction - Truncating control flow here
          halt_baddata();
        }
      }
    }
    uVar6 = param_3 >> 2;
    uVar7 = param_3 & 3;
    bVar10 = SBORROW4(uVar6,8);
    iVar2 = uVar6 - 8;
    if (uVar6 < 8) {
      param_3 = -uVar6;
                    // WARNING (jumptable): Sanity check requires truncation of jumptable
                    // WARNING: Could not find normalized switch variable to match jumptable
      switch(uVar6) {
      case 4:
switchD_0040a922_caseD_4:
        puVar9[param_3 + 6] = puVar3;
        puVar3 = (undefined4 *)puVar8[param_3 + 5];
      case 3:
        puVar9[param_3 + 5] = puVar3;
        puVar3 = (undefined4 *)puVar8[param_3 + 4];
      case 2:
        puVar9[param_3 + 4] = puVar3;
        puVar3 = (undefined4 *)puVar8[param_3 + 3];
      case 1:
        puVar9[param_3 + 3] = puVar3;
        puVar3 = (undefined4 *)puVar8[param_3 + 2];
      case 0:
        puVar9[param_3 + 2] = puVar3;
        puVar9[param_3 + 1] = puVar8[param_3 + 1];
                    // WARNING: Could not recover jumptable at 0x0040aa3b. Too many branches
                    // WARNING: Treating indirect jump as call
        puVar3 = (undefined4 *)(*(code *)(&switchD_0040a917::switchdataD_0040aa40)[uVar7])();
        return puVar3;
      case 6:
        *(byte *)puVar5 = (byte)puVar3 + (9 < ((byte)puVar3 & 0xf) | in_AF) * '\x06' & 0xf;
        *(char *)(unaff_EBX + -0x76e371bc) = *(char *)(unaff_EBX + -0x76e371bc) + (char)param_3;
                    // WARNING: Bad instruction - Truncating control flow here
        halt_baddata();
      }
    }
    else {
      for (; uVar6 != 0; uVar6 = uVar6 - 1) {
        *puVar9 = *puVar8;
        puVar8 = puVar8 + -1;
        puVar9 = puVar9 + -1;
      }
      param_3 = 0;
      puVar5 = puVar3;
      switch(uVar7) {
      case 0:
        goto switchD_0040ef40_caseD_0;
      case 2:
        goto code_r0x0040aa59;
      case 3:
        goto switchD_0040a917_caseD_3;
      }
switchD_0040a917_caseD_1:
      puVar3 = puVar5;
      if (bVar10 == iVar2 < 0) {
        *(char *)(unaff_EBX + 0x5f5e0845) = *(char *)(unaff_EBX + 0x5f5e0845) + (char)param_3;
        return (undefined4 *)((int)puVar5 + 1);
      }
    }
    puVar9[param_3 + 7] = puVar3;
    puVar3 = (undefined4 *)puVar8[param_3 + 6];
    goto switchD_0040a922_caseD_4;
  }
  if ((0xff < param_3) && ((DAT_004263a4 != 0 && (((uint)param_1 & 0xf) == ((uint)param_2 & 0xf)))))
  {
                    // WARNING: Bad instruction - Truncating control flow here
    halt_baddata();
  }
  if (((uint)param_1 & 3) != 0) {
    uVar7 = 3;
    switch(param_3) {
    case 0:
      goto switchD_0040ef40_caseD_0;
    case 1:
switchD_0040a790_caseD_1:
      *(byte *)((int)param_2 + 0x5f) = *(byte *)((int)param_2 + 0x5f) | (byte)unaff_EBX;
      return param_1;
    case 2:
code_r0x0040a8bd:
      return param_1;
    case 3:
switchD_0040a790_caseD_3:
      return param_1;
    default:
      uVar4 = (uint)param_1 & 3;
      uVar6 = (param_3 - 4) + uVar4;
      switch(uVar4) {
      case 1:
                    // WARNING: Bad instruction - Truncating control flow here
        halt_baddata();
      case 2:
        *(char *)(uVar4 + 0xd1230040) =
             (*(char *)(uVar4 + 0xd1230040) - (char)(uVar6 >> 8)) - CARRY4(param_3 - 4,uVar4);
        *(undefined *)param_1 = *(undefined *)param_2;
        *(undefined *)((int)param_1 + 1) = *(undefined *)((int)param_2 + 1);
        puVar3 = (undefined4 *)(uint)*(byte *)((int)param_2 + 2);
        uVar6 = uVar6 >> 2;
        *(byte *)((int)param_1 + 2) = *(byte *)((int)param_2 + 2);
        param_2 = (undefined4 *)((int)param_2 + 3);
        param_1 = (undefined4 *)((int)param_1 + 3);
        if (7 < uVar6) {
          for (; uVar6 != 0; uVar6 = uVar6 - 1) {
            *param_1 = *param_2;
            param_2 = param_2 + 1;
            param_1 = param_1 + 1;
          }
          return puVar3;
        }
        break;
      case 3:
        *(undefined *)param_1 = *(undefined *)param_2;
        puVar3 = (undefined4 *)(uint)*(byte *)((int)param_2 + 1);
        uVar6 = uVar6 >> 2;
        *(byte *)((int)param_1 + 1) = *(byte *)((int)param_2 + 1);
        param_2 = (undefined4 *)((int)param_2 + 2);
        param_1 = (undefined4 *)((int)param_1 + 2);
        if (7 < uVar6) {
          for (; uVar6 != 0; uVar6 = uVar6 - 1) {
            *param_1 = *param_2;
            param_2 = param_2 + 1;
            param_1 = param_1 + 1;
          }
          return puVar3;
        }
      }
switchD_0040a7b8_switchD:
                    // WARNING: Could not find normalized switch variable to match jumptable
      switch(uVar6) {
      default:
                    // WARNING: Bad instruction - Truncating control flow here
        halt_baddata();
      case 0x1c:
      case 0x1d:
      case 0x1e:
      case 0x1f:
                    // WARNING: This code block may not be properly labeled as switch case
        param_1[uVar6 - 7] = puVar3;
        puVar3 = (undefined4 *)param_2[uVar6 - 6];
      case 0x18:
      case 0x19:
      case 0x1a:
      case 0x1b:
                    // WARNING: This code block may not be properly labeled as switch case
        param_1[uVar6 - 6] = puVar3;
        puVar3 = (undefined4 *)param_2[uVar6 - 5];
      case 0x14:
      case 0x15:
      case 0x16:
      case 0x17:
                    // WARNING: This code block may not be properly labeled as switch case
        param_1[uVar6 - 5] = puVar3;
        puVar3 = (undefined4 *)param_2[uVar6 - 4];
      case 0x10:
      case 0x11:
      case 0x12:
      case 0x13:
                    // WARNING: This code block may not be properly labeled as switch case
        param_1[uVar6 - 4] = puVar3;
        puVar3 = (undefined4 *)param_2[uVar6 - 3];
      case 0xc:
      case 0xd:
      case 0xe:
      case 0xf:
                    // WARNING: This code block may not be properly labeled as switch case
        param_1[uVar6 - 3] = puVar3;
        puVar3 = (undefined4 *)param_2[uVar6 - 2];
      case 8:
      case 9:
      case 10:
      case 0xb:
                    // WARNING: This code block may not be properly labeled as switch case
        param_1[uVar6 - 2] = puVar3;
        param_1[uVar6 - 1] = param_2[uVar6 - 1];
      case 4:
      case 5:
      case 6:
      case 7:
                    // WARNING: Could not recover jumptable at 0x0040a89f. Too many branches
                    // WARNING: Treating indirect jump as call
        puVar3 = (undefined4 *)(*(code *)(&switchD_0040a790::switchdataD_0040a8a4)[uVar7])();
        return puVar3;
      }
    }
  }
  uVar6 = param_3 >> 2;
  uVar7 = param_3 & 3;
  if (uVar6 < 8) goto switchD_0040a7b8_switchD;
  for (; uVar6 != 0; uVar6 = uVar6 - 1) {
    *param_1 = *param_2;
    param_2 = param_2 + 1;
    param_1 = param_1 + 1;
  }
  param_1 = puVar3;
  switch(uVar7) {
  case 1:
    goto switchD_0040a790_caseD_1;
  case 2:
    goto code_r0x0040a8bd;
  case 3:
    goto switchD_0040a790_caseD_3;
  }
switchD_0040ef40_caseD_0:
                    // WARNING: Bad instruction - Truncating control flow here
  halt_baddata();
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
    puVar1 = (undefined4 *)func_0x89f5abc2();
    eVar3 = 0x16;
    *puVar1 = 0x16;
    func_0x21f5abd1(0,0,0,0,0);
  }
  else {
    pFVar2 = (FILE *)func_0x90daabe8(_Filename,_Mode,0x80);
    *_File = pFVar2;
    if (pFVar2 == (FILE *)0x0) {
      peVar4 = (errno_t *)func_0x89f5abfa();
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
LAB_0040ac2d:
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
                    func_0x9c0eadad(_DstBuf,0,_DstSize);
                  }
                  puVar2 = (undefined4 *)func_0x89f5adb5();
                  *puVar2 = 0x22;
                    // WARNING: Bad instruction - Truncating control flow here
                  halt_baddata();
                }
                func_0xd0ebacdc(puVar1,local_8,_File->_ptr,uVar8);
                _File->_cnt = _File->_cnt - uVar8;
                _File->_ptr = _File->_ptr + uVar8;
                    // WARNING: Bad instruction - Truncating control flow here
                halt_baddata();
              }
              goto LAB_0040ada4;
            }
          }
          if (uVar8 < local_10) {
            iVar6 = func_0x7b06ad67(_File);
            if (iVar6 == -1) {
              return;
            }
            if (local_8 == 0) goto LAB_0040ad77;
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
LAB_0040ad77:
              if (_DstSize != 0xffffffff) {
                func_0x9c0eadd8(_DstBuf,0,_DstSize);
              }
              puVar2 = (undefined4 *)func_0x89f5ade0();
              *puVar2 = 0x22;
                    // WARNING: Bad instruction - Truncating control flow here
              halt_baddata();
            }
            uVar4 = func_0x650ead3c(_File,puVar1,uVar3);
            iVar5 = func_0x680dad43(uVar4);
            if (iVar5 == 0) {
              _File->_flag = _File->_flag | 0x10;
              return;
            }
            if (iVar5 == -1) {
LAB_0040ada4:
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
        func_0x9c0eac67(_DstBuf,0,_DstSize);
      }
      if ((_File != (FILE *)0x0) && (_Count <= (uint)(0xffffffff / (ulonglong)_ElementSize)))
      goto LAB_0040ac2d;
    }
    puVar2 = (undefined4 *)func_0x89f5ac2c();
    *puVar2 = 0x16;
    func_0x21f5ac3c(0,0,0,0,0);
  }
  return 0;
}



void __cdecl
FUN_0040ae52(undefined4 param_1,undefined4 param_2,undefined4 param_3,undefined4 param_4)

{
  func_0xb3ddaeb8(param_1,0xffffffff,param_2,param_3,param_4);
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
    puVar1 = (undefined4 *)func_0x89f5aed6();
    *puVar1 = 0x16;
    func_0x21f5aee6(0,0,0,0,0);
    iVar4 = -1;
  }
  else {
    if ((*(byte *)&_File->_flag & 0x83) != 0) {
      iVar4 = func_0xb010aef9(_File);
      func_0x7f10af01(_File);
      uVar2 = func_0x650eaf07(_File);
      iVar3 = func_0xb20faf0d(uVar2);
      if (iVar3 < 0) {
        iVar4 = -1;
      }
      else if (_File->_tmpfname != (char *)0x0) {
        func_0x42ebaf26(_File->_tmpfname);
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
joined_r0x0040af8a:
      do {
        if (wVar1 != L'\0') {
          if (*pwVar2 == L'\0') {
            return _Str;
          }
          if (*(wchar_t *)(iVar3 + (int)pwVar2) == *pwVar2) {
            wVar1 = *(wchar_t *)(iVar3 + (int)(pwVar2 + 1));
            pwVar2 = pwVar2 + 1;
            goto joined_r0x0040af8a;
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



undefined4 * __thiscall FUN_0040afe9(void *this,byte param_1)

{
  *(undefined **)this = &DAT_0041c270;
  func_0x1013b04a();
  if ((param_1 & 1) != 0) {
    func_0x89e0b056(this);
  }
  return (undefined4 *)this;
}



undefined4 * __thiscall FUN_0040b010(void *this,undefined4 param_1)

{
  func_0xb312b06e(param_1);
  *(undefined **)this = &DAT_0041c270;
  return (undefined4 *)this;
}



// WARNING: Globals starting with '_' overlap smaller symbols at the same address
// Library Function - Single Match
//  void * __cdecl operator new(unsigned int)
// 
// Library: Visual Studio 2008 Release

void * __cdecl operator_new(uint param_1)

{
  code *pcVar1;
  int iVar2;
  void *pvVar3;
  undefined local_10 [12];
  
  do {
    pvVar3 = (void *)func_0xe1e5b09a(param_1);
    if (pvVar3 != (void *)0x0) {
      return pvVar3;
    }
    iVar2 = func_0xf214b08d(param_1);
  } while (iVar2 != 0);
  if ((_DAT_004234ac & 1) == 0) {
    _DAT_004234ac = _DAT_004234ac | 1;
    func_0xbadfb0bd();
    func_0xcc14b0c7(&DAT_0041b781);
  }
  func_0x07e0b0d1(&DAT_004234a0);
  func_0x1a15b0df(local_10,&DAT_004206ac);
  pcVar1 = (code *)swi(3);
  pvVar3 = (void *)(*pcVar1)();
  return pvVar3;
}



// WARNING: Control flow encountered bad instruction data

void FUN_0040b092(void)

{
                    // WARNING: Bad instruction - Truncating control flow here
  halt_baddata();
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
          func_0xdc1eb196(_File->_ptr,_DstBuf,uVar6);
          _File->_cnt = _File->_cnt - uVar6;
          _File->_ptr = _File->_ptr + uVar6;
LAB_0040b1a6:
          local_8 = (char *)((int)_DstBuf + uVar6);
          uVar7 = uVar7 - uVar6;
          _DstBuf = local_8;
        }
        if (local_c <= uVar7) {
          if ((uVar5 != 0) && (iVar2 = func_0xb010b1b4(_File), iVar2 != 0)) {
            return;
          }
          uVar5 = uVar7;
          if (local_c != 0) {
            uVar5 = uVar7 - uVar7 % local_c;
          }
          uVar3 = func_0x650eb1d4(_File,_DstBuf,uVar5);
          uVar4 = func_0xfd1db1db(uVar3);
          if (uVar4 == 0xffffffff) {
LAB_0040b1f6:
            _File->_flag = _File->_flag | 0x20;
                    // WARNING: Bad instruction - Truncating control flow here
            halt_baddata();
          }
          uVar6 = uVar5;
          if (uVar4 <= uVar5) {
            uVar6 = uVar4;
          }
          if (uVar4 < uVar5) goto LAB_0040b1f6;
          goto LAB_0040b1a6;
        }
                    // WARNING: Load size is inaccurate
        iVar2 = func_0x6615b206((int)*_DstBuf,_File);
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
    puVar1 = (undefined4 *)func_0x89f5b10e();
    *puVar1 = 0x16;
    func_0x21f5b11e(0,0,0,0,0);
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
    puVar2 = (undefined4 *)func_0x89f5b2e4();
    *puVar2 = 0x16;
    iVar3 = -1;
  }
  else {
    _File->_flag = _File->_flag & 0xffffffef;
    if (_Origin == 1) {
      iVar3 = func_0x87e3b301(_File);
      _Offset = _Offset + iVar3;
      _Origin = 0;
    }
    func_0xb010b30f(_File);
    uVar1 = _File->_flag;
    if ((char)uVar1 < '\0') {
      _File->_flag = uVar1 & 0xfffffffc;
    }
    else if ((((uVar1 & 1) != 0) && ((uVar1 & 8) != 0)) && ((uVar1 & 0x400) == 0)) {
      _File->_bufsiz = 0x200;
    }
    uVar4 = func_0x650eb341(_File,_Offset,_Origin);
    iVar3 = func_0xb622b348(uVar4);
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
    puVar3 = (undefined4 *)func_0x89f5b3f6();
    *puVar3 = 0x16;
    func_0x21f5b406(0,0,0,0,0);
                    // WARNING: Bad instruction - Truncating control flow here
    halt_baddata();
  }
  uVar4 = func_0x650eb417(_File);
  if (_File->_cnt < 0) {
    _File->_cnt = 0;
  }
  local_c = func_0xb622b42c(uVar4,0,1);
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
      puVar3 = (undefined4 *)func_0x89f5b4a5();
      *puVar3 = 0x16;
                    // WARNING: Bad instruction - Truncating control flow here
      halt_baddata();
    }
  }
  else {
    pcVar2 = pcVar9;
    if ((*(byte *)((&DAT_00425280)[(int)uVar4 >> 5] + 4 + (uVar4 & 0x1f) * 0x40) & 0x80) != 0) {
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
      if ((*(byte *)((&DAT_00425280)[(int)uVar4 >> 5] + 4 + iVar10) & 0x80) != 0) {
        iVar6 = func_0xb622b4fb(uVar4,0,2);
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
          iVar6 = func_0xb622b530(uVar4,local_c,0);
          if (iVar6 < 0) {
            return -1;
          }
          pFVar8 = (FILE *)0x200;
          if ((((FILE *)0x200 < pFVar5) || ((_File->_flag & 8U) == 0)) ||
             ((_File->_flag & 0x400U) != 0)) {
            pFVar8 = (FILE *)_File->_bufsiz;
          }
          bVar11 = (*(byte *)((&DAT_00425280)[(int)uVar4 >> 5] + 4 + iVar10) & 4) == 0;
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
  
  pcVar1 = DAT_0041c0f0;
  if (0xffffffe0 < _Size) {
    func_0xf214b6f1(_Size);
    puVar4 = (undefined4 *)func_0x89f5b6f7();
    *puVar4 = 0xc;
    return (void *)0x0;
  }
  if (DAT_00423954 == 0) {
    func_0x6c37b660();
    func_0xc135b667(0x1e);
    func_0x0d33b671(0xff);
  }
  if (DAT_0042525c == 1) {
    uVar6 = _Size;
    if (_Size == 0) {
      uVar6 = 1;
    }
  }
  else {
    if ((DAT_0042525c == 3) && (pvVar2 = (void *)func_0x92e5b696(_Size), pvVar2 != (void *)0x0))
    goto LAB_0040b663;
    sVar5 = _Size;
    if (_Size == 0) {
      sVar5 = 1;
    }
    uVar6 = sVar5 + 0xf & 0xfffffff0;
  }
  pvVar2 = (void *)(*pcVar1)(DAT_00423954,0,uVar6);
LAB_0040b663:
  if (pvVar2 == (void *)0x0) {
    if (DAT_00423ca4 == 0) {
      puVar4 = (undefined4 *)func_0x89f5b6dc();
      *puVar4 = 0xc;
    }
    else {
      iVar3 = func_0xf214b6ca(_Size);
      if (iVar3 != 0) {
                    // WARNING: Bad instruction - Truncating control flow here
        halt_baddata();
      }
    }
    puVar4 = (undefined4 *)func_0x89f5b6e3();
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
      puVar2 = (undefined4 *)func_0x89f5b75a();
      eVar4 = 0x22;
      *puVar2 = 0x22;
      goto LAB_0040b6d6;
    }
    *_Dst = '\0';
  }
  puVar2 = (undefined4 *)func_0x89f5b71f();
  eVar4 = 0x16;
  *puVar2 = 0x16;
LAB_0040b6d6:
  func_0x21f5b72e(0,0,0,0,0);
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
FUN_0040b751(undefined4 param_1,undefined4 param_2,undefined4 param_3,undefined param_4)

{
  func_0x4ff0b7b8(param_1,param_2,param_3,0,&param_4);
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
    iVar2 = func_0x99f8b801();
    *(int *)(this + 8) = iVar2;
    *(undefined4 *)this = *(undefined4 *)(iVar2 + 0x6c);
    *(undefined4 *)(this + 4) = *(undefined4 *)(iVar2 + 0x68);
    if ((*(int *)this != DAT_00422da0) && ((*(uint *)(iVar2 + 0x70) & DAT_00422cbc) == 0)) {
      uVar3 = func_0x3641b929();
      *(undefined4 *)this = uVar3;
    }
    if ((*(int *)(this + 4) != DAT_00422bc0) &&
       ((*(uint *)(*(int *)(this + 8) + 0x70) & DAT_00422cbc) == 0)) {
      uVar3 = func_0xcb39b849();
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
// WARNING: Removing unreachable block (ram,0x0040b9aa)
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
  
  func_0x92e7b885(param_1);
  if (param_3 != (wchar_t **)0x0) {
    *param_3 = param_2;
  }
  if ((param_2 == (wchar_t *)0x0) || ((param_4 != 0 && ((param_4 < 2 || (0x24 < param_4)))))) {
    puVar3 = (undefined4 *)func_0x89f5b89c();
    *puVar3 = 0x16;
    func_0x21f5b8ac(0,0,0,0,0);
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
    iVar4 = func_0x8743b9f6(uVar7,8,local_34);
    if (iVar4 == 0) break;
    wVar1 = *pwVar8;
    pwVar2 = pwVar8;
  }
  if (wVar1 == L'-') {
    param_5 = param_5 | 2;
LAB_0040b8c1:
    uVar7 = (uint)(ushort)*pwVar8;
    pwVar8 = pwVar2 + 2;
  }
  else if (wVar1 == L'+') goto LAB_0040b8c1;
  if (((param_4 < 0) || (param_4 == 1)) || (0x24 < param_4)) {
    if (param_3 != (wchar_t **)0x0) {
      *param_3 = param_2;
    }
    if (local_28 != '\0') {
      *(uint *)(local_2c + 0x70) = *(uint *)(local_2c + 0x70) & 0xfffffffd;
    }
    local_c = 0;
    local_8 = 0;
    goto LAB_0040bad1;
  }
  if (param_4 == 0) {
    iVar4 = func_0xac41ba3e(uVar7);
    if (iVar4 == 0) {
      if ((*pwVar8 == L'x') || (*pwVar8 == L'X')) {
        param_4 = 0x10;
        goto LAB_0040b919;
      }
      param_4 = 8;
    }
    else {
      param_4 = 10;
    }
  }
  else {
LAB_0040b919:
    if (((param_4 == 0x10) && (iVar4 = func_0xac41ba72(uVar7), iVar4 == 0)) &&
       ((*pwVar8 == L'x' || (*pwVar8 == L'X')))) {
      uVar7 = (uint)(ushort)pwVar8[1];
      pwVar8 = pwVar8 + 2;
    }
  }
  local_20 = param_4 >> 0x1f;
  local_24 = param_4;
  local_14 = func_0x5b44baa2(0xffffffff,0xffffffff,param_4,local_20);
  local_18 = 0x10;
  local_1c = extraout_ECX;
  uVar5 = func_0xac41bab4(uVar7);
  if (uVar5 == 0xffffffff) {
    uVar6 = (ushort)uVar7;
    if (((0x40 < uVar6) && (uVar6 < 0x5b)) || ((ushort)(uVar6 - 0x61) < 0x1a)) {
      if ((ushort)(uVar6 - 0x61) < 0x1a) {
        uVar7 = uVar7 - 0x20;
      }
      uVar5 = uVar7 - 0x37;
      goto LAB_0040b997;
    }
  }
  else {
LAB_0040b997:
    if (uVar5 < (uint)param_4) {
      if ((CONCAT44(local_8,local_c) < local_14) ||
         ((local_14 == CONCAT44(local_8,local_c) && ((local_18 != 0 || (uVar5 <= local_1c)))))) {
        func_0x1b44bb52(local_24,local_20,local_c,local_8);
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
    puVar3 = (undefined4 *)func_0x89f5baa2();
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
LAB_0040bad1:
  return CONCAT44(local_8,local_c);
}



void __cdecl FUN_0040bad6(undefined4 param_1,undefined4 param_2,undefined4 param_3)

{
  undefined *puVar1;
  
  if (DAT_00423cc4 == 0) {
    puVar1 = &DAT_00422da8;
  }
  else {
    puVar1 = (undefined *)0x0;
  }
  func_0x19e8bb4a(puVar1,param_1,param_2,param_3,0);
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
LAB_0040bbe9:
    eVar1 = 0;
  }
  else {
    if (_Dst == (void *)0x0) {
LAB_0040bbf2:
      puVar2 = (undefined4 *)func_0x89f5bc45();
      eVar1 = 0x16;
      *puVar2 = 0x16;
    }
    else {
      if ((_Src != (void *)0x0) && (_MaxCount <= _DstSize)) {
        func_0xdc1ebc71(_Dst,_Src,_MaxCount);
        goto LAB_0040bbe9;
      }
      func_0x9c0ebc82(_Dst,0,_DstSize);
      if (_Src == (void *)0x0) goto LAB_0040bbf2;
      if (_MaxCount <= _DstSize) {
        return 0x16;
      }
      puVar2 = (undefined4 *)func_0x89f5bc94();
      eVar1 = 0x22;
      *puVar2 = 0x22;
    }
    func_0x21f5bc54(0,0,0,0,0);
  }
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
    puVar1 = (undefined4 *)func_0x89f5bcb9();
    *puVar1 = 0x16;
    func_0x21f5bcc9(0,0,0,0,0);
                    // WARNING: Bad instruction - Truncating control flow here
    halt_baddata();
  }
  if ((param_3 != 0) && (param_2 == (undefined *)0x0)) {
    puVar1 = (undefined4 *)func_0x89f5bce9();
    *puVar1 = 0x16;
    func_0x21f5bcf9(0,0,0,0,0);
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
      iVar3 = func_0x6615bd5f(0,&local_24);
      if (iVar3 == -1) goto LAB_0040bd3a;
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
    iVar3 = func_0x6615bd7c(0,&local_24);
    if (iVar3 != -1) {
      return iVar2;
    }
  }
LAB_0040bd3a:
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
    puVar1 = (undefined4 *)func_0x89f5bdae();
    *puVar1 = 0x16;
    func_0x21f5bdbe(0,0,0,0,0);
  }
  else {
    if ((_DstBuf == (wchar_t *)0x0) || (_DstSize == 0)) {
      puVar1 = (undefined4 *)func_0x89f5bdd8();
      *puVar1 = 0x16;
    }
    else {
      iVar2 = func_0x4decbdf7(0x41159d,_DstBuf,_DstSize,_Format,_Locale,_ArgList);
      if (iVar2 < 0) {
        *_DstBuf = L'\0';
      }
      if (iVar2 != -2) {
        return iVar2;
      }
      puVar1 = (undefined4 *)func_0x89f5be0d();
      *puVar1 = 0x22;
    }
    func_0x21f5be1d(0,0,0,0,0);
  }
  return -1;
}



void __cdecl
FUN_0040bdd9(undefined4 param_1,undefined4 param_2,undefined4 param_3,undefined4 param_4)

{
  func_0x45edbe3f(param_1,param_2,param_3,0,param_4);
  return;
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
    puVar2 = (undefined4 *)func_0x89f5be59();
    *puVar2 = 0x16;
    func_0x21f5be68(0,0,0,0,0);
                    // WARNING: Bad instruction - Truncating control flow here
    halt_baddata();
  }
  if (param_2 == 0) {
LAB_0040be2a:
    puVar2 = (undefined4 *)func_0x89f5be7d();
    uVar6 = 0x16;
  }
  else {
    *in_EAX = 0;
    if ((param_4 != 0) + 1 < param_2) {
      if (0x22 < param_3 - 2) goto LAB_0040be2a;
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
    puVar2 = (undefined4 *)func_0x89f5beac();
    uVar6 = 0x22;
  }
  *puVar2 = uVar6;
  func_0x21f5be8c(0,0,0,0,0);
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
  eVar1 = func_0xededbf64(_Val,_SizeInWords,_Radix,uVar2);
  return eVar1;
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
        puVar2 = (undefined4 *)func_0x89f5bfca();
        eVar4 = 0x22;
        *puVar2 = 0x22;
        goto LAB_0040bf3a;
      }
    }
    *_Dst = '\0';
  }
  puVar2 = (undefined4 *)func_0x89f5bf83();
  eVar4 = 0x16;
  *puVar2 = 0x16;
LAB_0040bf3a:
  func_0x21f5bf92(0,0,0,0,0);
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
    puVar1 = (undefined4 *)func_0x89f5bfef();
    *puVar1 = 0x16;
    func_0x21f5bfff(0,0,0,0,0);
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
        iVar3 = func_0x6615c087(0,&local_24);
        if (iVar3 != -1) {
          return iVar2;
        }
      }
      param_2[param_3 - 1] = 0;
      iVar2 = (-1 < (int)local_20) - 2;
    }
  }
  else {
    puVar1 = (undefined4 *)func_0x89f5c01f();
    *puVar1 = 0x16;
    func_0x21f5c02f(0,0,0,0,0);
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
    puVar1 = (undefined4 *)func_0x89f5c0b8();
    *puVar1 = 0x16;
    func_0x21f5c0c8(0,0,0,0,0);
  }
  else {
    if ((_DstBuf == (char *)0x0) || (_DstSize == 0)) {
      puVar1 = (undefined4 *)func_0x89f5c0e2();
      *puVar1 = 0x16;
    }
    else {
      iVar2 = func_0x83efc101(0x4121e3,_DstBuf,_DstSize,_Format,_Locale,_ArgList);
      if (iVar2 < 0) {
        *_DstBuf = '\0';
      }
      if (iVar2 != -2) {
        return iVar2;
      }
      puVar1 = (undefined4 *)func_0x89f5c114();
      *puVar1 = 0x22;
    }
    func_0x21f5c124(0,0,0,0,0);
  }
  return -1;
}



void __cdecl
FUN_0040c0e0(undefined4 param_1,undefined4 param_2,undefined4 param_3,undefined4 param_4)

{
  func_0x4ff0c146(param_1,param_2,param_3,0,param_4);
  return;
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
  pvVar1 = (void *)func_0xae5dc265(_Count,_Size,&local_8);
  if ((pvVar1 == (void *)0x0) && (local_8 != 0)) {
    iVar2 = func_0x89f5c178();
    if (iVar2 != 0) {
      piVar3 = (int *)func_0x89f5c181();
      *piVar3 = local_8;
    }
  }
  return pvVar1;
}



void __cdecl FUN_0040c13d(undefined4 param_1)

{
  if (DAT_004234b8 == 1) {
    func_0x6c37c19e();
  }
  func_0xc135c1a6(param_1);
  func_0x0d33c1b0(0xff);
  return;
}



void __fastcall entry(undefined4 param_1,undefined4 param_2)

{
  FUN_00436fd4(param_1,param_2);
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
  
  _DAT_004235d8 =
       (uint)(in_NT & 1) * 0x4000 | (uint)SBORROW4((int)&stack0xfffffffc,0x328) * 0x800 |
       (uint)(in_IF & 1) * 0x200 | (uint)(in_TF & 1) * 0x100 | (uint)((int)&local_32c < 0) * 0x80 |
       (uint)(&stack0x00000000 == (undefined *)0x32c) * 0x40 | (uint)(in_AF & 1) * 0x10 |
       (uint)((POPCOUNT((uint)&local_32c & 0xff) & 1U) == 0) * 4 |
       (uint)(&stack0xfffffffc < (undefined *)0x328) | (uint)(in_ID & 1) * 0x200000 |
       (uint)(in_VIP & 1) * 0x100000 | (uint)(in_VIF & 1) * 0x80000 | (uint)(in_AC & 1) * 0x40000;
  _DAT_004235dc = &stack0x00000004;
  _DAT_00423518 = 0x10001;
  _DAT_004234c0 = 0xc0000409;
  _DAT_004234c4 = 1;
  local_32c = s__Repeat_del___s__if_exist___s__g_00422037._13_4_;
  local_328 = s__Repeat_del___s__if_exist___s__g_00422037._17_4_;
  _DAT_004234cc = unaff_retaddr;
  _DAT_004235a4 = in_GS;
  _DAT_004235a8 = in_FS;
  _DAT_004235ac = in_ES;
  _DAT_004235b0 = in_DS;
  _DAT_004235b4 = unaff_EDI;
  _DAT_004235b8 = unaff_ESI;
  _DAT_004235bc = unaff_EBX;
  _DAT_004235c0 = in_EDX;
  _DAT_004235c4 = in_ECX;
  _DAT_004235c8 = in_EAX;
  _DAT_004235cc = unaff_EBP;
  DAT_004235d0 = unaff_retaddr;
  _DAT_004235d4 = in_CS;
  _DAT_004235e0 = in_SS;
  DAT_00423510 = (*DAT_0041c10c)();
  func_0xde64c508(1);
  (*DAT_0041c108)(0);
  (*DAT_0041c104)(&DAT_0041c278);
  if (DAT_00423510 == 0) {
    func_0xde64c52c(1);
  }
  uVar1 = (*DAT_0041c100)(0xc0000409);
  (*DAT_0041c0fc)(uVar1);
  return;
}



void __cdecl FUN_0040c3f3(undefined4 param_1)

{
  DAT_004237e4 = param_1;
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
  func_0x9c0ec47d();
  local_2dc = &local_32c;
  local_2d8 = local_2d4;
  local_2d4[0] = 0x10001;
  local_32c = 0xc0000417;
  local_328 = 1;
  iVar1 = (*DAT_0041c10c)();
  (*DAT_0041c108)();
  iVar2 = (*DAT_0041c104)();
  if ((iVar2 == 0) && (iVar1 == 0)) {
    func_0xde64c658();
  }
  uVar3 = (*DAT_0041c100)();
  (*DAT_0041c0fc)(uVar3);
  func_0xf1d5c576();
  return;
}



// WARNING: Control flow encountered bad instruction data

void FUN_0040c52a(void)

{
  code *UNRECOVERED_JUMPTABLE;
  
  UNRECOVERED_JUMPTABLE = (code *)func_0x4df6c588(DAT_004237e4);
  if (UNRECOVERED_JUMPTABLE != (code *)0x0) {
                    // WARNING: Could not recover jumptable at 0x0040c540. Too many branches
                    // WARNING: Treating indirect jump as call
    (*UNRECOVERED_JUMPTABLE)();
    return;
  }
  func_0xde64c697(2);
                    // WARNING: Bad instruction - Truncating control flow here
  halt_baddata();
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
    if (param_1 == *(ulong *)(s__Repeat_del___s__if_exist___s__g_00422037 + uVar1 * 8 + 0x19)) {
      return *(int *)(s__Repeat_del___s__if_exist___s__g_00422037 + uVar1 * 8 + 0x1d);
    }
    uVar1 = uVar1 + 1;
  } while (uVar1 < 0x2d);
  if (param_1 - 0x13 < 0x12) {
    return 0xd;
  }
  return (-(uint)(0xe < param_1 - 0xbc) & 0xe) + 8;
}



void __cdecl FUN_0040c5b8(undefined4 param_1)

{
  undefined4 *puVar1;
  undefined4 uVar2;
  
  puVar1 = (undefined4 *)func_0x9cf5c611();
  *puVar1 = param_1;
  uVar2 = func_0x47f5c61c(param_1);
  puVar1 = (undefined4 *)func_0x89f5c624();
  *puVar1 = uVar2;
  return;
}



// WARNING: Globals starting with '_' overlap smaller symbols at the same address
// Library Function - Multiple Matches With Different Base Names
//  __decode_pointer
//  __encode_pointer
// 
// Library: Visual Studio 2008 Release

undefined4 __cdecl FID_conflict___decode_pointer(undefined4 param_1)

{
  int iVar1;
  code *pcVar2;
  
  pcVar2 = DAT_0041c114;
  iVar1 = (*DAT_0041c114)(DAT_004221c4);
  if ((iVar1 != 0) && (DAT_004221c0 != -1)) {
    pcVar2 = (code *)(*pcVar2)(DAT_004221c4,DAT_004221c0);
    iVar1 = (*pcVar2)();
    if (iVar1 != 0) {
      pcVar2 = *(code **)(iVar1 + 0x1f8);
      goto LAB_0040c63b;
    }
  }
  iVar1 = (*ram0x0041c054)(&DAT_0041c290);
  if ((iVar1 == 0) && (iVar1 = func_0x8932c678(&DAT_0041c290), iVar1 == 0)) {
    return param_1;
  }
  pcVar2 = (code *)(*DAT_0041c110)(iVar1,&DAT_0041c280);
LAB_0040c63b:
  if (pcVar2 != (code *)0x0) {
    param_1 = (*pcVar2)(param_1);
  }
  return param_1;
}



// WARNING: Globals starting with '_' overlap smaller symbols at the same address
// Library Function - Multiple Matches With Different Base Names
//  __decode_pointer
//  __encode_pointer
// 
// Library: Visual Studio 2008 Release

undefined4 __cdecl FID_conflict___decode_pointer(undefined4 param_1)

{
  int iVar1;
  code *pcVar2;
  
  pcVar2 = DAT_0041c114;
  iVar1 = (*DAT_0041c114)(DAT_004221c4);
  if ((iVar1 != 0) && (DAT_004221c0 != -1)) {
    pcVar2 = (code *)(*pcVar2)(DAT_004221c4,DAT_004221c0);
    iVar1 = (*pcVar2)();
    if (iVar1 != 0) {
      pcVar2 = *(code **)(iVar1 + 0x1fc);
      goto LAB_0040c6b6;
    }
  }
  iVar1 = (*ram0x0041c054)(&DAT_0041c290);
  if ((iVar1 == 0) && (iVar1 = func_0x8932c6f3(&DAT_0041c290), iVar1 == 0)) {
    return param_1;
  }
  pcVar2 = (code *)(*DAT_0041c110)(iVar1,&DAT_0041c2ac);
LAB_0040c6b6:
  if (pcVar2 != (code *)0x0) {
    param_1 = (*pcVar2)(param_1);
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
      func_0x6ffbcc9f(param_1,param_2,param_3 - uVar3);
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
    func_0xf6fbcd01((int)param_1 + iVar1,(int)param_2 + iVar1,param_3 - iVar1);
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



// WARNING: Removing unreachable block (ram,0x0040cd6f)
// WARNING: Removing unreachable block (ram,0x0040cd5c)
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
  if (((local_8 & 0x4000000) == 0) || (iVar2 = func_0xd9fccdd4(), iVar2 == 0)) {
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
  if ((_File < (FILE *)&DAT_004221c8) || ((FILE *)&DAT_00422428 < _File)) {
    (*DAT_0041c134)(_File + 1);
  }
  else {
    func_0x6227cef0(((int)&_File[-0x2110f]._bufsiz >> 5) + 0x10);
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
    func_0x6227cf1d(_Index + 0x10);
    *(uint *)((int)_File + 0xc) = *(uint *)((int)_File + 0xc) | 0x8000;
    return;
  }
  (*DAT_0041c134)((int)_File + 0x20);
  return;
}



// Library Function - Single Match
//  __unlock_file
// 
// Libraries: Visual Studio 2008 Release, Visual Studio 2010 Release, Visual Studio 2012 Release

void __cdecl __unlock_file(FILE *_File)

{
  if (((FILE *)((int)&DAT_004221c4 + 3U) < _File) && (_File < (FILE *)0x422429)) {
    _File->_flag = _File->_flag & 0xffff7fff;
    func_0x8826cf66(((int)&_File[-0x2110f]._bufsiz >> 5) + 0x10);
    return;
  }
  (*DAT_0041c138)(_File + 1);
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
    func_0x8826cf95(_Index + 0x10);
    return;
  }
  (*DAT_0041c138)((int)_File + 0x20);
  return;
}



// WARNING: Control flow encountered bad instruction data
// WARNING: Removing unreachable block (ram,0x0040d111)
// WARNING: Removing unreachable block (ram,0x0040d115)
// WARNING: Removing unreachable block (ram,0x0040d113)
// WARNING: Removing unreachable block (ram,0x0040d11b)
// WARNING: Removing unreachable block (ram,0x0040d133)
// WARNING: Removing unreachable block (ram,0x0040d13d)
// WARNING: Removing unreachable block (ram,0x0040d13b)
// WARNING: Removing unreachable block (ram,0x0040d142)
// WARNING: Removing unreachable block (ram,0x0040d14c)
// WARNING: Removing unreachable block (ram,0x0040d153)
// WARNING: Removing unreachable block (ram,0x0040d172)
// WARNING: Removing unreachable block (ram,0x0040d191)
// WARNING: Removing unreachable block (ram,0x0040d1a9)
// WARNING: Removing unreachable block (ram,0x0040d186)
// WARNING: Removing unreachable block (ram,0x0040d167)
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
LAB_0040cfc6:
    local_8 = DAT_00423ef8 | 2;
  }
  else {
    if (wVar1 != L'r') {
      if (wVar1 != L'w') goto LAB_0040cf93;
      uVar7 = 0x301;
      goto LAB_0040cfc6;
    }
    uVar7 = 0;
    local_8 = DAT_00423ef8 | 1;
  }
  bVar2 = true;
  pwVar8 = pwVar8 + 1;
  wVar1 = *pwVar8;
  while ((wVar1 != L'\0' && (bVar2))) {
    if ((ushort)wVar1 < 0x54) {
      if (wVar1 == L'S') {
        if (bVar3) goto LAB_0040d0f4;
        bVar3 = true;
        uVar7 = uVar7 | 0x20;
      }
      else if (wVar1 != L' ') {
        if (wVar1 == L'+') {
          if ((uVar7 & 2) == 0) {
            uVar7 = uVar7 & 0xfffffffe | 2;
            local_8 = local_8 & 0xfffffffc | 0x80;
            goto LAB_0040d0fa;
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
          if (wVar1 != L'R') goto LAB_0040cf93;
          if (!bVar3) {
                    // WARNING: Bad instruction - Truncating control flow here
            halt_baddata();
          }
        }
LAB_0040d0f4:
        bVar2 = false;
      }
    }
    else if (wVar1 == L'T') {
      if ((uVar7 & 0x1000) != 0) goto LAB_0040d0f4;
      uVar7 = uVar7 | 0x1000;
    }
    else if (wVar1 == L'b') {
      if ((uVar7 & 0xc000) != 0) goto LAB_0040d0f4;
      uVar7 = uVar7 | 0x8000;
    }
    else if (wVar1 == L'c') {
      if (bVar4) goto LAB_0040d0f4;
      local_8 = local_8 | 0x4000;
      bVar4 = true;
    }
    else if (wVar1 == L'n') {
      if (bVar4) goto LAB_0040d0f4;
      local_8 = local_8 & 0xffffbfff;
      bVar4 = true;
    }
    else {
      if (wVar1 != L't') goto LAB_0040cf93;
      if ((uVar7 & 0xc000) != 0) goto LAB_0040d0f4;
      uVar7 = uVar7 | 0x4000;
    }
LAB_0040d0fa:
    pwVar8 = pwVar8 + 1;
    wVar1 = *pwVar8;
  }
  for (; *pwVar8 == L' '; pwVar8 = pwVar8 + 1) {
  }
  if (*pwVar8 == L'\0') {
    iVar6 = func_0x506ed328(&_Mode,_Filename,uVar7,_ShFlag,0x180);
    if (iVar6 != 0) {
      return;
    }
    _DAT_004237f8 = _DAT_004237f8 + 1;
    _File->_flag = local_8;
    _File->_cnt = 0;
    _File->_ptr = (char *)0x0;
    _File->_base = (char *)0x0;
    _File->_tmpfname = (char *)0x0;
    _File->_file = (int)_Mode;
    return _File;
  }
LAB_0040cf93:
  puVar5 = (undefined4 *)func_0x89f5cfe6();
  *puVar5 = 0x16;
  func_0x21f5cff6(0,0,0,0,0);
                    // WARNING: Bad instruction - Truncating control flow here
  halt_baddata();
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
  
  piVar3 = (int *)(*(uint *)(param_2 + 8) ^ s__Repeat_del___s__if_exist___s__g_00422037._13_4_);
  local_5 = '\0';
  local_10 = 1;
  if (*piVar3 != -2) {
    func_0xf1d5d42b();
  }
  func_0xf1d5d43b();
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
          iVar1 = func_0x1a06d480();
          local_5 = '\x01';
          if (iVar1 < 0) {
            local_10 = 0;
            goto LAB_0040d44c;
          }
          if (0 < iVar1) {
            if (((*param_1 == -0x1f928c9d) && (DAT_00420410 != (code *)0x0)) &&
               (iVar1 = func_0x3b71d5ef(&DAT_00420410), iVar1 != 0)) {
              (*DAT_00420410)(param_1,1);
            }
            func_0x4a06d50d();
            if (*(int *)(param_2 + 0xc) != iVar2) {
              func_0x6406d524(param_2 + 0x10,s__Repeat_del___s__if_exist___s__g_00422037 + 0xd);
            }
            *(int *)(param_2 + 0xc) = local_c;
            if (*piVar3 != -2) {
              func_0xf1d5d541();
            }
            func_0xf1d5d551();
            func_0x3106d55e();
            goto LAB_0040d510;
          }
        }
        iVar2 = local_c;
      } while (local_c != -2);
      if (local_5 != '\0') {
LAB_0040d44c:
        if (*piVar3 != -2) {
          func_0xf1d5d4ae();
        }
        func_0xf1d5d4be();
      }
    }
  }
  else {
LAB_0040d510:
    if (*(int *)(iVar2 + 0xc) != -2) {
      func_0x6406d579(param_2 + 0x10,s__Repeat_del___s__if_exist___s__g_00422037 + 0xd);
                    // WARNING: Bad instruction - Truncating control flow here
      halt_baddata();
    }
  }
  return local_10;
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
    puVar2 = (undefined4 *)func_0x89f5d6e6();
    *puVar2 = 0x16;
    func_0x21f5d6f6(0,0,0,0,0);
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
      func_0x3273d833(_File);
    }
    else {
      _File->_ptr = _File->_base;
    }
    uVar3 = func_0x650ed747(_File,_File->_base,_File->_bufsiz);
    iVar4 = func_0x680dd74e(uVar3);
    _File->_cnt = iVar4;
    if ((iVar4 != 0) && (iVar4 != -1)) {
      if ((*(byte *)&_File->_flag & 0x82) == 0) {
        iVar4 = func_0x650ed771(_File);
        if ((iVar4 == -1) || (iVar4 = func_0x650ed77d(_File), iVar4 == -2)) {
          puVar6 = &DAT_00422570;
        }
        else {
          iVar4 = func_0x650ed789(_File);
          uVar5 = func_0x650ed799(_File);
          puVar6 = (undefined *)((uVar5 & 0x1f) * 0x40 + (&DAT_00425280)[iVar4 >> 5]);
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
    puVar7 = (undefined4 *)func_0x9cf5d81d();
    *puVar7 = 0;
    puVar7 = (undefined4 *)func_0x89f5d825();
    *puVar7 = 9;
                    // WARNING: Bad instruction - Truncating control flow here
    halt_baddata();
  }
  if ((_FileHandle < 0) || (DAT_00425278 <= (uint)_FileHandle)) {
    puVar7 = (undefined4 *)func_0x9cf5d847();
    *puVar7 = 0;
    puVar7 = (undefined4 *)func_0x89f5d84e();
    *puVar7 = 9;
    func_0x21f5d85e(0,0,0,0,0);
                    // WARNING: Bad instruction - Truncating control flow here
    halt_baddata();
  }
  piVar1 = &DAT_00425280 + (_FileHandle >> 5);
  iVar13 = (_FileHandle & 0x1fU) * 0x40;
  bVar3 = *(byte *)(*piVar1 + iVar13 + 4);
  if ((bVar3 & 1) == 0) {
    puVar7 = (undefined4 *)func_0x9cf5d88d();
    *puVar7 = 0;
    puVar7 = (undefined4 *)func_0x89f5d894();
    *puVar7 = 9;
    goto LAB_0040d8b8;
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
          local_10 = (short *)func_0xe664da2b(_MaxCharCount);
          if (local_10 == (short *)0x0) {
            puVar7 = (undefined4 *)func_0x89f5d938();
            *puVar7 = 0xc;
            puVar7 = (undefined4 *)func_0x9cf5d943();
            *puVar7 = 8;
            return;
          }
          uVar15 = func_0x7b73da5d(_FileHandle,0,0,1);
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
          iVar10 = (*(code *)s_R6008___not_enough_space_for_arg_0041c02d._3_4_)
                             (*(undefined4 *)(iVar13 + *piVar1),psVar9,_MaxCharCount,&local_1c,0);
          if (((iVar10 == 0) || ((int)local_1c < 0)) || (_MaxCharCount < local_1c)) {
            iVar13 = (*(code *)s_R6002___floating_point_support_n_0041c059._7_4_)();
            if (iVar13 == 5) {
              puVar7 = (undefined4 *)func_0x89f5dd94();
              *puVar7 = 9;
              puVar7 = (undefined4 *)func_0x9cf5dd9f();
              *puVar7 = 5;
                    // WARNING: Bad instruction - Truncating control flow here
              halt_baddata();
            }
            if (iVar13 == 0x6d) {
                    // WARNING: Bad instruction - Truncating control flow here
              halt_baddata();
            }
LAB_0040dbba:
            func_0xaff5dc0e(iVar13);
          }
          else {
            local_14 = (short *)((int)local_14 + local_1c);
            pbVar2 = (byte *)(iVar13 + 4 + *piVar1);
            if ((*pbVar2 & 0x80) == 0) goto LAB_0040dbc5;
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
                  iVar10 = (*(code *)s_R6008___not_enough_space_for_arg_0041c02d._3_4_)
                                     (*(undefined4 *)(iVar13 + *piVar1),&local_c,2,&local_1c,0);
                  if (((iVar10 == 0) &&
                      (iVar10 = (*(code *)s_R6002___floating_point_support_n_0041c059._7_4_)(),
                      iVar10 != 0)) || (local_1c == 0)) {
LAB_0040dcfb:
                    *psVar9 = 0xd;
LAB_0040dd01:
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
                      goto LAB_0040dd01;
                    }
                    if ((psVar9 == local_10) && (local_c == 10)) {
                    // WARNING: Bad instruction - Truncating control flow here
                      halt_baddata();
                    }
                    func_0x7b73de3f(_FileHandle,0xfffffffe,0xffffffff,1);
                    if (local_c != 10) goto LAB_0040dcfb;
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
                    goto LAB_0040da45;
                  }
LAB_0040dabc:
                  _MaxCharCount = _MaxCharCount + 1;
                  *(undefined *)psVar9 = 0xd;
LAB_0040dabf:
                  psVar9 = (short *)((int)psVar9 + 1);
                  uVar8 = _MaxCharCount;
                }
                else {
                  uVar8 = _MaxCharCount + 1;
                  iVar10 = (*(code *)s_R6008___not_enough_space_for_arg_0041c02d._3_4_)
                                     (*(undefined4 *)(iVar13 + *piVar1),&local_5,1,&local_1c,0);
                  if (((iVar10 == 0) &&
                      (iVar10 = (*(code *)s_R6002___floating_point_support_n_0041c059._7_4_)(),
                      iVar10 != 0)) || (local_1c == 0)) goto LAB_0040dabc;
                  if ((*(byte *)(iVar13 + 4 + *piVar1) & 0x48) != 0) {
                    if (local_5 == '\n') goto LAB_0040da45;
                    *(undefined *)psVar9 = 0xd;
                    *(char *)(iVar13 + 5 + *piVar1) = local_5;
                    _MaxCharCount = uVar8;
                    goto LAB_0040dabf;
                  }
                  if ((psVar9 == local_10) && (local_5 == '\n')) {
LAB_0040da45:
                    _MaxCharCount = uVar8;
                    *(undefined *)psVar9 = 10;
                    goto LAB_0040dabf;
                  }
                  func_0x7b73dc01(_FileHandle,0xffffffff,0xffffffff,1);
                  if (local_5 != '\n') goto LAB_0040dabc;
                }
                _MaxCharCount = uVar8;
              } while (_MaxCharCount < local_14);
            }
            local_14 = (short *)((int)psVar9 - (int)local_10);
            if ((local_6 != '\x01') || (local_14 == (short *)0x0)) goto LAB_0040dbc5;
            psVar9 = (short *)((int)psVar9 + -1);
            bVar3 = *(byte *)psVar9;
            if (-1 < (char)bVar3) {
                    // WARNING: Bad instruction - Truncating control flow here
              halt_baddata();
            }
            iVar10 = 1;
            while (((*(char *)(bVar3 + 0x422448) == '\0' && (iVar10 < 5)) && (local_10 <= psVar9)))
            {
              psVar9 = (short *)((int)psVar9 + -1);
              bVar3 = *(byte *)psVar9;
              iVar10 = iVar10 + 1;
            }
            iVar11 = (int)*(char *)(*(byte *)psVar9 + 0x422448);
            if (iVar11 != 0) {
              if (iVar11 + 1 == iVar10) {
                psVar9 = (short *)((int)psVar9 + iVar10);
              }
              else if ((*(byte *)(*piVar1 + iVar13 + 4) & 0x48) == 0) {
                func_0x7b73dcdb(_FileHandle,-iVar10,-iVar10 >> 0x1f,1);
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
              local_14 = (short *)(*(code *)s_R6008___not_enough_space_for_arg_0041c02d._31_4_)
                                            (0xfde9,0,local_10,iVar10,_DstBuf,uVar6 >> 1);
              if (local_14 != (short *)0x0) {
                bVar14 = local_14 != (short *)iVar10;
                local_14 = (short *)((int)local_14 * 2);
                *(uint *)(iVar13 + 0x30 + *piVar1) = (uint)bVar14;
                goto LAB_0040dbc5;
              }
              iVar13 = (*(code *)s_R6002___floating_point_support_n_0041c059._7_4_)();
              goto LAB_0040dbba;
            }
            puVar7 = (undefined4 *)func_0x89f5db8d();
            *puVar7 = 0x2a;
          }
          local_18 = -1;
LAB_0040dbc5:
          if (local_10 != (short *)_DstBuf) {
            func_0x42ebdc21(local_10);
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
  puVar7 = (undefined4 *)func_0x9cf5d8f9();
  *puVar7 = 0;
  puVar7 = (undefined4 *)func_0x89f5d900();
  *puVar7 = 0x16;
LAB_0040d8b8:
  func_0x21f5d910(0,0,0,0,0);
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
    puVar1 = (undefined4 *)func_0x89f5decf();
    *puVar1 = 0x16;
    func_0x21f5dedf(0,0,0,0,0);
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
  
  iVar1 = func_0x2076e07c(_FileHandle);
  if (iVar1 != -1) {
    if (((_FileHandle == 1) && ((*(byte *)(DAT_00425280 + 0x84) & 1) != 0)) ||
       ((_FileHandle == 2 && ((*(byte *)(DAT_00425280 + 0x44) & 1) != 0)))) {
      iVar1 = func_0x2076e0a7(2);
      iVar2 = func_0x2076e0b0(1);
      if (iVar2 == iVar1) goto LAB_0040df84;
    }
    uVar3 = func_0x2076e0bc(_FileHandle);
    iVar1 = (*(code *)s_R6002___floating_point_support_n_0041c059._35_4_)(uVar3);
    if (iVar1 == 0) {
      iVar1 = (*(code *)s_R6002___floating_point_support_n_0041c059._7_4_)();
      goto LAB_0040df86;
    }
  }
LAB_0040df84:
  iVar1 = 0;
LAB_0040df86:
  func_0x9a75e0da(_FileHandle);
  *(undefined *)((&DAT_00425280)[_FileHandle >> 5] + 4 + (_FileHandle & 0x1fU) * 0x40) = 0;
  if (iVar1 == 0) {
    iVar1 = 0;
  }
  else {
    func_0xaff5dffc(iVar1);
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
    func_0x42ebe0f1(_File->_base);
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
      uVar1 = func_0x650ee13a(_File,_File->_base,iVar4);
      iVar2 = func_0xfd1de141(uVar1);
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
    iVar1 = func_0x6011e181(0);
  }
  else {
    iVar1 = func_0xb010e18a(_File);
    if (iVar1 == 0) {
      if ((_File->_flag & 0x4000U) == 0) {
        iVar1 = 0;
      }
      else {
        uVar2 = func_0x650ee1a3(_File);
        iVar1 = func_0xde79e2a9(uVar2);
        iVar1 = -(uint)(iVar1 != 0);
      }
    }
    else {
      iVar1 = -1;
    }
  }
  return iVar1;
}



// Library Function - Single Match
//  public: __thiscall std::exception::exception(char const * const &)
// 
// Library: Visual Studio 2008 Release

exception * __thiscall std::exception::exception(exception *this,char **param_1)

{
  int iVar1;
  int iVar2;
  
  *(char **)this = s_GetActiveWindow_0041c315 + 0xf;
  if (*param_1 == (char *)0x0) {
    *(undefined4 *)(this + 4) = 0;
  }
  else {
    iVar1 = func_0xcb7ae3b8(*param_1);
    iVar2 = func_0xe1e5e2c1(iVar1 + 1);
    *(int *)(this + 4) = iVar2;
    if (iVar2 != 0) {
      func_0xabe6e2d3(iVar2,iVar1 + 1,*param_1);
    }
  }
  *(undefined4 *)(this + 8) = 1;
  return this;
}



void __thiscall FUN_0040e29e(void *this,undefined4 *param_1)

{
  undefined4 uVar1;
  
  *(char **)this = s_GetActiveWindow_0041c315 + 0xf;
  uVar1 = *param_1;
  *(undefined4 *)((int)this + 8) = 0;
  *(undefined4 *)((int)this + 4) = uVar1;
  return;
}



// Library Function - Single Match
//  public: __thiscall std::exception::exception(class std::exception const &)
// 
// Library: Visual Studio 2008 Release

exception * __thiscall std::exception::exception(exception *this,exception *param_1)

{
  int iVar1;
  int iVar2;
  
  *(char **)this = s_GetActiveWindow_0041c315 + 0xf;
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
    iVar1 = func_0xcb7ae433(iVar2);
    iVar2 = func_0xe1e5e33c(iVar1 + 1);
    *(int *)(this + 4) = iVar2;
    if (iVar2 != 0) {
      func_0xabe6e34f(iVar2,iVar1 + 1,*(undefined4 *)(param_1 + 4));
    }
  }
  return this;
}



void * __thiscall FUN_0040e33b(void *this,byte param_1)

{
  func_0x1013e396();
  if ((param_1 & 1) != 0) {
    func_0x89e0e3a2(this);
  }
  return this;
}



void * __thiscall FUN_0040e36c(void *this,byte param_1)

{
  func_0x5413e3c7();
  if ((param_1 & 1) != 0) {
    func_0x89e0e3d3(this);
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
  
  iVar1 = func_0xcb7be4f0(param_1 + 9,this + 9);
  return (bool)('\x01' - (iVar1 != 0));
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
  
  puVar1 = (undefined4 *)func_0x4df6e40f(DAT_00425250);
  puVar2 = (undefined4 *)func_0x4df6e41f(DAT_0042524c);
  if ((puVar2 < puVar1) || (iVar7 = (int)puVar2 - (int)puVar1, iVar7 + 4U < 4)) {
    return 0;
  }
  uVar3 = func_0x537ce53d(puVar1);
  if (uVar3 < iVar7 + 4U) {
    uVar4 = 0x800;
    if (uVar3 < 0x800) {
      uVar4 = uVar3;
    }
    if ((uVar4 + uVar3 < uVar3) || (iVar5 = func_0x7765e561(puVar1,uVar4 + uVar3), iVar5 == 0)) {
      if (uVar3 + 0x10 < uVar3) {
        return 0;
      }
      iVar5 = func_0x7765e577(puVar1,uVar3 + 0x10);
      if (iVar5 == 0) {
        return 0;
      }
    }
    puVar2 = (undefined4 *)(iVar5 + (iVar7 >> 2) * 4);
    DAT_00425250 = func_0xd2f5e489(iVar5);
  }
  uVar6 = func_0xd2f5e497(param_1);
  *puVar2 = uVar6;
  DAT_0042524c = func_0xd2f5e4a2(puVar2 + 1);
  return param_1;
}



int __cdecl FUN_0040e4d4(undefined4 param_1)

{
  int iVar1;
  
  iVar1 = func_0x9014e52f(param_1);
  return (iVar1 != 0) - 1;
}



void __cdecl FUN_0040e4eb(undefined4 param_1)

{
  DAT_004237fc = param_1;
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
  
  pcVar1 = (code *)func_0x4df6e558(DAT_004237fc);
  if (pcVar1 != (code *)0x0) {
    iVar2 = (*pcVar1)(_Size);
    if (iVar2 != 0) {
      return 1;
    }
  }
  return 0;
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
  
  puVar2 = &DAT_0041c348;
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
  (*DAT_0041c140)(auStack_24[0],auStack_24[1],uStack_14,&uStack_10);
  return;
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
  _File = (FILE *)func_0x650ee5cc(_File);
  uVar1 = pFVar4->_flag;
  if ((uVar1 & 0x82) == 0) {
    puVar5 = (undefined4 *)func_0x89f5e5dc();
    *puVar5 = 9;
LAB_0040e594:
    pFVar4->_flag = pFVar4->_flag | 0x20;
                    // WARNING: Bad instruction - Truncating control flow here
    halt_baddata();
  }
  if ((uVar1 & 0x40) != 0) {
    puVar5 = (undefined4 *)func_0x89f5e5f7();
    *puVar5 = 0x22;
    goto LAB_0040e594;
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
     (((iVar6 = func_0x98fde63a(), pFVar4 != (FILE *)(iVar6 + 0x20) &&
       (iVar6 = func_0x98fde646(), pFVar4 != (FILE *)(iVar6 + 0x40))) ||
      (iVar6 = func_0xf67ce755(_File), iVar6 == 0)))) {
    func_0x3273e760(pFVar4);
  }
  if ((pFVar4->_flag & 0x108U) == 0) {
    iVar6 = 1;
    local_8 = func_0xfd1de6ff(_File,&_Ch,1);
  }
  else {
    pcVar2 = pFVar4->_base;
    pcVar3 = pFVar4->_ptr;
    pFVar4->_ptr = pcVar2 + 1;
    iVar6 = (int)pcVar3 - (int)pcVar2;
    pFVar4->_cnt = pFVar4->_bufsiz + -1;
    if (iVar6 < 1) {
      if ((_File == (FILE *)0xffffffff) || (_File == (FILE *)0xfffffffe)) {
        puVar7 = &DAT_00422570;
      }
      else {
        puVar7 = (undefined *)(((uint)_File & 0x1f) * 0x40 + (&DAT_00425280)[(int)_File >> 5]);
      }
      if (((puVar7[4] & 0x20) != 0) && (lVar8 = func_0x0074e7db(_File,0,0,2), lVar8 == -1))
      goto LAB_0040e6bc;
    }
    else {
      local_8 = func_0xfd1de690(_File,pcVar2,iVar6);
    }
    *pFVar4->_base = (char)_Ch;
  }
  if (local_8 == iVar6) {
    return _Ch & 0xff;
  }
LAB_0040e6bc:
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
  
  func_0x9b7fe82f();
  local_1ad0 = (undefined4 *******)_Buf;
  local_1acc = (undefined4 ******)0x0;
  local_1ad4 = 0;
  if (_MaxCharCount == 0) {
                    // WARNING: Bad instruction - Truncating control flow here
    halt_baddata();
  }
  if (_Buf == (void *)0x0) {
    puVar3 = (undefined4 *)func_0x9cf5e766();
    *puVar3 = 0;
    puVar3 = (undefined4 *)func_0x89f5e76d();
    puStack_14 = (undefined4 *)0x0;
    pppppppuStack_18 = (undefined4 *******)0x0;
    ppuStack_1c = (undefined4 **)0x0;
    *puVar3 = 0x16;
    pppppppuStack_20 = (undefined4 *******)0x40e72f;
    func_0x21f5e77d();
                    // WARNING: Bad instruction - Truncating control flow here
    halt_baddata();
  }
  piVar11 = &DAT_00425280 + (_FileHandle >> 5);
  iVar13 = (_FileHandle & 0x1fU) * 0x40;
  cVar9 = (char)(*(char *)(*piVar11 + iVar13 + 0x24) * '\x02') >> 1;
  local_1add = cVar9;
  local_1adc = piVar11;
  if (((cVar9 == '\x02') || (cVar9 == '\x01')) && ((~_MaxCharCount & 1) == 0)) {
    puStack_14 = (undefined4 *)0x40e781;
    puVar3 = (undefined4 *)func_0x9cf5e7cf();
    *puVar3 = 0;
    puStack_14 = (undefined4 *)0x40e78a;
    puVar3 = (undefined4 *)func_0x89f5e7d8();
    puStack_14 = (undefined4 *)0x0;
    pppppppuStack_18 = (undefined4 *******)0x0;
    ppuStack_1c = (undefined4 **)0x0;
    pppppppuStack_20 = (undefined4 *******)0x0;
    iStack_24 = 0;
    *puVar3 = 0x16;
    ppuStack_28 = (undefined4 **)0x40e79a;
    func_0x21f5e7e8();
                    // WARNING: Bad instruction - Truncating control flow here
    halt_baddata();
  }
  if ((*(byte *)(*piVar11 + iVar13 + 4) & 0x20) != 0) {
    puStack_14 = (undefined4 *)0x2;
    pppppppuStack_18 = (undefined4 *******)0x0;
    ppuStack_1c = (undefined4 **)0x0;
    pppppppuStack_20 = (undefined4 *******)_FileHandle;
    iStack_24 = 0x40e7b6;
    func_0x7b73e904();
  }
  puStack_14 = (undefined4 *)_FileHandle;
  pppppppuStack_18 = (undefined4 *******)0x40e7c1;
  iVar4 = func_0xf67ce90f();
  if ((iVar4 == 0) || ((*(byte *)(iVar13 + 4 + *piVar11) & 0x80) == 0)) {
LAB_0040ea69:
    if ((*(byte *)((int *)(*piVar11 + iVar13) + 1) & 0x80) == 0) {
      puStack_14 = (undefined4 *)0x0;
      pppppppuStack_18 = &local_1ad8;
      ppuStack_1c = (undefined4 **)_MaxCharCount;
      pppppppuStack_20 = local_1ad0;
      iStack_24 = *(int *)(*piVar11 + iVar13);
      ppuStack_28 = (undefined4 **)0x40ed50;
      iVar4 = (*(code *)s_R6008___not_enough_space_for_arg_0041c02d._23_4_)();
      if (iVar4 == 0) {
LAB_0040ed69:
        puStack_14 = (undefined4 *)0x40ed6f;
        local_1ac4 = (undefined4 *)(*(code *)s_R6002___floating_point_support_n_0041c059._7_4_)();
      }
      else {
        local_1ac4 = (undefined4 *)0x0;
        local_1acc = local_1ad8;
      }
LAB_0040ed75:
      if (local_1acc != (undefined4 ******)0x0) goto LAB_0040edf6;
      goto LAB_0040ed7e;
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
          ppuStack_28 = (undefined4 **)0x40eb1f;
          ppuStack_1c = (undefined4 **)((int)ppppppuVar6 - (int)local_1abc);
          iVar4 = (*(code *)s_R6008___not_enough_space_for_arg_0041c02d._23_4_)();
          if (iVar4 == 0) goto LAB_0040ed69;
          local_1acc = (undefined4 ******)((int)local_1acc + (int)local_1ad8);
          if ((int)local_1ad8 < (int)(undefined4 **)((int)ppppppuVar6 - (int)local_1abc))
          goto LAB_0040ed75;
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
            ppuStack_28 = (undefined4 **)0x40ebff;
            ppuStack_1c = (undefined4 **)((int)ppppppuVar6 - (int)local_1abc);
            iVar4 = (*(code *)s_R6008___not_enough_space_for_arg_0041c02d._23_4_)();
            if (iVar4 == 0) goto LAB_0040ed69;
            local_1acc = (undefined4 ******)((int)local_1acc + (int)local_1ad8);
            if ((int)local_1ad8 < (int)(undefined4 **)((int)ppppppuVar6 - (int)local_1abc))
            goto LAB_0040ed75;
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
          uStack_34 = 0x40ecc8;
          iVar4 = (*(code *)s_R6002___floating_point_support_n_0041c059._31_4_)();
          if (iVar4 == 0) goto LAB_0040ed69;
          do {
            puStack_14 = (undefined4 *)0x0;
            pppppppuStack_18 = &local_1ad8;
            ppuStack_1c = (undefined4 **)(iVar4 - (int)pcVar12);
            pppppppuStack_20 = (undefined4 *******)((int)local_1414 + (int)pcVar12);
            iStack_24 = *(int *)(iVar13 + *local_1adc);
            ppuStack_28 = (undefined4 **)0x40ecf9;
            iVar7 = (*(code *)s_R6008___not_enough_space_for_arg_0041c02d._23_4_)();
            if (iVar7 == 0) {
              puStack_14 = (undefined4 *)0x40ed0f;
              local_1ac4 = (undefined4 *)
                           (*(code *)s_R6002___floating_point_support_n_0041c059._7_4_)();
              break;
            }
            pcVar12 = pcVar12 + (int)local_1ad8;
          } while ((int)pcVar12 < iVar4);
        } while ((iVar4 <= (int)pcVar12) &&
                (local_1acc = (undefined4 ******)((int)local_1ac0 - (int)local_1ad0),
                local_1acc < _MaxCharCount));
        goto LAB_0040ed75;
      }
    }
  }
  else {
    puStack_14 = (undefined4 *)0x40e7dc;
    iVar4 = func_0x99f8e82a();
    puStack_14 = &local_1ae8;
    local_1ae4 = (uint)(*(int *)(*(int *)(iVar4 + 0x6c) + 0x14) == 0);
    pppppppuStack_18 = *(undefined4 ********)(iVar13 + *piVar11);
    ppuStack_1c = (undefined4 **)0x40e7ff;
    iVar4 = (*DAT_0041c148)();
    if ((iVar4 == 0) || ((local_1ae4 != 0 && (cVar9 == '\0')))) goto LAB_0040ea69;
    puStack_14 = (undefined4 *)0x40e81f;
    local_1ae8 = (*DAT_0041c144)();
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
            pppppppuStack_18 = (undefined4 *******)0x40e88e;
            iVar4 = func_0x887fe9dc();
            pppppppuStack_18 = pppppppuVar10;
            if (iVar4 == 0) {
              puStack_14 = (undefined4 *)0x1;
              goto LAB_0040e8d0;
            }
            if ((char *)((int)local_1ad0 + (_MaxCharCount - (int)pppppppuVar10)) < (char *)0x2) {
              *(char *)(iVar13 + 0x34 + *piVar11) = *(char *)pppppppuVar10;
              *(undefined4 *)(iVar13 + 0x38 + *piVar11) = 1;
                    // WARNING: Bad instruction - Truncating control flow here
              halt_baddata();
            }
            puStack_14 = (undefined4 *)0x2;
            ppuStack_1c = &local_1ac4;
            pppppppuStack_20 = (undefined4 *******)0x40e8b8;
            iVar4 = func_0x367fea06();
            if (iVar4 == -1) goto LAB_0040ed75;
            pppppppuVar10 = (undefined4 *******)((int)pppppppuVar10 + 1);
            local_1ac0 = (undefined4 *******)((int)local_1ac0 + 1);
          }
          else {
            *(undefined4 *)(*local_1adc + iVar13 + 0x38) = 0;
            puStack_14 = (undefined4 *)0x2;
            pppppppuStack_18 = (undefined4 *******)&stack0xfffffff0;
LAB_0040e8d0:
            ppuStack_1c = &local_1ac4;
            pppppppuStack_20 = (undefined4 *******)0x40e8dc;
            iVar4 = func_0x367fea2a();
            if (iVar4 == -1) goto LAB_0040ed75;
          }
          puStack_14 = (undefined4 *)0x0;
          pppppppuStack_18 = (undefined4 *******)0x0;
          ppuStack_1c = (undefined4 **)&DAT_00000005;
          pppppppuStack_20 = (undefined4 *******)&stack0xfffffff0;
          iStack_24 = 1;
          ppuStack_28 = &local_1ac4;
          uStack_2c = 0;
          uStack_30 = local_1ae8;
          pppppppuVar10 = (undefined4 *******)((int)pppppppuVar10 + 1);
          local_1ac0 = (undefined4 *******)((int)local_1ac0 + 1);
          uStack_34 = 0x40e90f;
          ppuVar5 = (undefined4 **)(*(code *)s_R6002___floating_point_support_n_0041c059._31_4_)();
          if (ppuVar5 == (undefined4 **)0x0) goto LAB_0040ed75;
          puStack_14 = (undefined4 *)0x0;
          pppppppuStack_18 = &local_1ac8;
          pppppppuStack_20 = (undefined4 *******)&stack0xfffffff0;
          iStack_24 = *(int *)(iVar13 + *local_1adc);
          ppuStack_28 = (undefined4 **)0x40e938;
          ppuStack_1c = ppuVar5;
          iVar4 = (*(code *)s_R6008___not_enough_space_for_arg_0041c02d._23_4_)();
          if (iVar4 == 0) goto LAB_0040ed69;
          local_1acc = (undefined4 ******)((int)local_1ac0 + local_1ad4);
          if ((int)local_1ac8 < (int)ppuVar5) goto LAB_0040ed75;
          if (local_1ae4 != 0) {
            puStack_14 = (undefined4 *)0x0;
            pppppppuStack_18 = &local_1ac8;
            ppuStack_1c = (undefined4 **)0x1;
            pppppppuStack_20 = (undefined4 *******)&stack0xfffffff0;
            iStack_24 = *(int *)(iVar13 + *local_1adc);
            ppuStack_28 = (undefined4 **)0x40e991;
            iVar4 = (*(code *)s_R6008___not_enough_space_for_arg_0041c02d._23_4_)();
            if (iVar4 == 0) goto LAB_0040ed69;
            if (0 < (int)local_1ac8) {
                    // WARNING: Bad instruction - Truncating control flow here
              halt_baddata();
            }
            goto LAB_0040ed75;
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
            pppppppuStack_18 = (undefined4 *******)0x40e9f3;
            sVar2 = func_0x5a7deb41();
            if (sVar2 != (short)local_1ac4) goto LAB_0040ed69;
            local_1acc = (undefined4 ******)((int)local_1acc + 2);
            if (local_1ae4 != 0) {
              puStack_14 = (undefined4 *)0xd;
              local_1ac4 = (undefined4 *)0xd;
              pppppppuStack_18 = (undefined4 *******)0x40ea20;
              sVar2 = func_0x5a7deb6e();
              if (sVar2 != (short)local_1ac4) goto LAB_0040ed69;
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
LAB_0040ed7e:
    piVar11 = local_1adc;
    if (local_1ac4 != (undefined4 *)0x0) {
      if (local_1ac4 == (undefined4 *)&DAT_00000005) {
        puStack_14 = (undefined4 *)0x40ed97;
        puVar3 = (undefined4 *)func_0x89f5ede5();
        *puVar3 = 9;
        puStack_14 = (undefined4 *)0x40eda2;
        puVar3 = (undefined4 *)func_0x9cf5edf0();
        *puVar3 = 5;
      }
      else {
        puStack_14 = local_1ac4;
        pppppppuStack_18 = (undefined4 *******)0x40edb1;
        func_0xaff5edff();
      }
      goto LAB_0040edf6;
    }
  }
  if (((*(byte *)(iVar13 + 4 + *piVar11) & 0x40) == 0) || (*(char *)local_1ad0 != '\x1a')) {
    puStack_14 = (undefined4 *)0x40edd7;
    puVar3 = (undefined4 *)func_0x89f5ee25();
    *puVar3 = 0x1c;
    puStack_14 = (undefined4 *)0x40ede2;
    puVar3 = (undefined4 *)func_0x9cf5ee30();
    *puVar3 = 0;
  }
LAB_0040edf6:
  iVar13 = func_0xf1d5ee51();
  return iVar13;
}



// WARNING: Control flow encountered bad instruction data
// Library Function - Single Match
//  __write
// 
// Library: Visual Studio 2008 Release

int __cdecl __write(int _FileHandle,void *_Buf,uint _MaxCharCount)

{
  uint uVar1;
  undefined4 *puVar2;
  undefined4 uVar3;
  int unaff_EBP;
  int iVar4;
  
  func_0x3c03ee5f(s_GetFileSizeEx_004208d7 + 9,0x10);
  uVar1 = *(uint *)(unaff_EBP + 8);
  if (uVar1 == 0xfffffffe) {
    puVar2 = (undefined4 *)func_0x9cf5ee6c();
    *puVar2 = 0;
    puVar2 = (undefined4 *)func_0x89f5ee74();
    *puVar2 = 9;
  }
  else {
    if ((-1 < (int)uVar1) && (uVar1 < DAT_00425278)) {
      iVar4 = (uVar1 & 0x1f) * 0x40;
      if ((*(byte *)((&DAT_00425280)[(int)uVar1 >> 5] + 4 + iVar4) & 1) != 0) {
        func_0x9776efd7(uVar1);
        *(undefined4 *)(unaff_EBP + -4) = 0;
        if ((*(byte *)((&DAT_00425280)[(int)uVar1 >> 5] + 4 + iVar4) & 1) == 0) {
          puVar2 = (undefined4 *)func_0x89f5eeff();
          *puVar2 = 9;
          puVar2 = (undefined4 *)func_0x9cf5ef0a();
          *puVar2 = 0;
          *(undefined4 *)(unaff_EBP + -0x1c) = 0xffffffff;
        }
        else {
          uVar3 = func_0xca16eef2(*(undefined4 *)(unaff_EBP + 8),*(undefined4 *)(unaff_EBP + 0xc),
                                  *(undefined4 *)(unaff_EBP + 0x10));
          *(undefined4 *)(unaff_EBP + -0x1c) = uVar3;
        }
        *(undefined4 *)(unaff_EBP + -4) = 0xfffffffe;
        func_0xcf1eef1c();
        iVar4 = func_0x8103ef24();
        return iVar4;
      }
    }
    puVar2 = (undefined4 *)func_0x9cf5ee95();
    *puVar2 = 0;
    puVar2 = (undefined4 *)func_0x89f5ee9c();
    *puVar2 = 9;
    func_0x21f5eeac(0,0,0,0,0);
  }
                    // WARNING: Bad instruction - Truncating control flow here
  halt_baddata();
}



// WARNING: Control flow encountered bad instruction data
// WARNING: Instruction at (ram,0x0040f1ac) overlaps instruction at (ram,0x0040f1a7)
// 

undefined8 __cdecl FUN_0040eee4(undefined4 *param_1,undefined4 *param_2,uint param_3)

{
  uint *puVar1;
  code *pcVar2;
  undefined4 *puVar3;
  undefined4 *puVar4;
  uint uVar5;
  uint uVar6;
  int unaff_EBX;
  undefined4 *puVar7;
  undefined8 uVar8;
  
  puVar3 = (undefined4 *)(param_3 + (int)param_2);
  if ((param_2 < param_1) && (param_1 < puVar3)) {
    puVar7 = (undefined4 *)((param_3 - 4) + (int)param_2);
    puVar4 = (undefined4 *)((param_3 - 4) + (int)param_1);
    if (((uint)puVar4 & 3) != 0) {
      uVar6 = 3;
      switch(param_3) {
      case 0:
        goto switchD_0040ef40_caseD_0;
      case 1:
        goto switchD_0040f0c7_caseD_1;
      case 2:
        goto code_r0x0040f209;
      case 3:
        goto switchD_0040f0c7_caseD_3;
      default:
        switch((uint)puVar4 & 3) {
        case 1:
                    // WARNING: Bad instruction - Truncating control flow here
          halt_baddata();
        case 2:
          pcVar2 = (code *)swi(1);
          uVar8 = (*pcVar2)();
          return uVar8;
        case 3:
          puVar1 = (uint *)(((uint)puVar4 & 3) + 0x468a0347);
          *puVar1 = *puVar1 >> 1 | (uint)((*puVar1 & 1) != 0) << 0x1f;
                    // WARNING: Bad instruction - Truncating control flow here
          halt_baddata();
        }
      }
    }
    uVar5 = param_3 >> 2;
    uVar6 = param_3 & 3;
    if (uVar5 < 8) {
      param_3 = -uVar5;
                    // WARNING (jumptable): Sanity check requires truncation of jumptable
                    // WARNING: Could not find normalized switch variable to match jumptable
      switch(uVar5) {
      case 5:
        puVar4[7 - uVar5] = puVar3;
        puVar3 = (undefined4 *)puVar7[6 - uVar5];
      case 4:
        puVar4[6 - uVar5] = puVar3;
        puVar3 = (undefined4 *)puVar7[5 - uVar5];
      case 3:
        puVar4[5 - uVar5] = puVar3;
        puVar3 = (undefined4 *)puVar7[4 - uVar5];
      case 2:
        puVar4[4 - uVar5] = puVar3;
        puVar3 = (undefined4 *)puVar7[3 - uVar5];
      case 1:
        puVar4[3 - uVar5] = puVar3;
        puVar3 = (undefined4 *)puVar7[2 - uVar5];
        break;
      case 6:
        out(0xf1,puVar3);
        *(char *)(unaff_EBX + -0x76e371bc) = *(char *)(unaff_EBX + -0x76e371bc) + (char)param_3;
                    // WARNING: Bad instruction - Truncating control flow here
        halt_baddata();
      }
      puVar4[2 - uVar5] = puVar3;
      puVar4[1 - uVar5] = puVar7[1 - uVar5];
      puVar4 = (undefined4 *)(uVar5 * -4);
      switch(uVar6) {
      case 0:
        goto switchD_0040ef40_caseD_0;
      case 2:
        goto code_r0x0040f209;
      case 3:
        goto switchD_0040f0c7_caseD_3;
      }
    }
    else {
      for (; uVar5 != 0; uVar5 = uVar5 - 1) {
        *puVar4 = *puVar7;
        puVar7 = puVar7 + -1;
        puVar4 = puVar4 + -1;
      }
      param_3 = 0;
      puVar4 = puVar3;
      switch(uVar6) {
      case 0:
        goto switchD_0040ef40_caseD_0;
      case 2:
code_r0x0040f209:
        return CONCAT44(uVar6,puVar4);
      case 3:
switchD_0040f0c7_caseD_3:
        return CONCAT44(uVar6,puVar4);
      }
    }
switchD_0040f0c7_caseD_1:
    *(char *)(unaff_EBX + 0x5f5e0845) = *(char *)(unaff_EBX + 0x5f5e0845) + (char)param_3;
    puVar4 = (undefined4 *)(CONCAT31((int3)((uint)puVar4 >> 8),(char)puVar4 + '\x0e') + 1);
    goto code_r0x0040f209;
  }
  if ((0xff < param_3) && ((DAT_004263a4 != 0 && (((uint)param_1 & 0xf) == ((uint)param_2 & 0xf)))))
  {
                    // WARNING: Bad instruction - Truncating control flow here
    halt_baddata();
  }
  if (((uint)param_1 & 3) == 0) {
    uVar5 = param_3 >> 2;
    uVar6 = param_3 & 3;
    if (uVar5 < 8) goto switchD_0040ef68_switchD;
    for (; uVar5 != 0; uVar5 = uVar5 - 1) {
      *param_1 = *param_2;
      param_2 = param_2 + 1;
      param_1 = param_1 + 1;
    }
    switch(uVar6) {
    case 1:
      goto switchD_0040ef40_caseD_1;
    case 2:
      goto switchD_0040ef40_caseD_2;
    case 3:
      goto switchD_0040ef40_caseD_3;
    }
  }
  else {
    uVar6 = 3;
    puVar3 = param_1;
    switch(param_3) {
    case 0:
      break;
    case 1:
switchD_0040ef40_caseD_1:
                    // WARNING: Bad instruction - Truncating control flow here
      halt_baddata();
    case 2:
switchD_0040ef40_caseD_2:
      return CONCAT44(uVar6,puVar3);
    case 3:
switchD_0040ef40_caseD_3:
      return CONCAT44(uVar6,puVar3);
    default:
      uVar5 = (param_3 - 4) + ((uint)param_1 & 3);
      switch((uint)param_1 & 3) {
      case 1:
                    // WARNING: Bad instruction - Truncating control flow here
        halt_baddata();
      case 2:
        uVar6 = uVar5 & 3;
        *(undefined *)param_1 = *(undefined *)param_2;
        *(undefined *)((int)param_1 + 1) = *(undefined *)((int)param_2 + 1);
        puVar3 = (undefined4 *)(uint)*(byte *)((int)param_2 + 2);
        uVar5 = uVar5 >> 2;
        *(byte *)((int)param_1 + 2) = *(byte *)((int)param_2 + 2);
        param_2 = (undefined4 *)((int)param_2 + 3);
        param_1 = (undefined4 *)((int)param_1 + 3);
        if (uVar5 < 8) {
switchD_0040ef68_switchD:
                    // WARNING: Could not find normalized switch variable to match jumptable
          switch(uVar5) {
          default:
                    // WARNING: Bad instruction - Truncating control flow here
            halt_baddata();
          case 0x1c:
          case 0x1d:
          case 0x1e:
          case 0x1f:
                    // WARNING: This code block may not be properly labeled as switch case
            param_1[uVar5 - 7] = puVar3;
            puVar3 = (undefined4 *)param_2[uVar5 - 6];
          case 0x18:
          case 0x19:
          case 0x1a:
          case 0x1b:
                    // WARNING: This code block may not be properly labeled as switch case
            param_1[uVar5 - 6] = puVar3;
            puVar3 = (undefined4 *)param_2[uVar5 - 5];
          case 0x14:
          case 0x15:
          case 0x16:
          case 0x17:
                    // WARNING: This code block may not be properly labeled as switch case
            param_1[uVar5 - 5] = puVar3;
            puVar3 = (undefined4 *)param_2[uVar5 - 4];
          case 0x10:
          case 0x11:
          case 0x12:
          case 0x13:
                    // WARNING: This code block may not be properly labeled as switch case
            param_1[uVar5 - 4] = puVar3;
            puVar3 = (undefined4 *)param_2[uVar5 - 3];
          case 0xc:
          case 0xd:
          case 0xe:
          case 0xf:
                    // WARNING: This code block may not be properly labeled as switch case
            param_1[uVar5 - 3] = puVar3;
            puVar3 = (undefined4 *)param_2[uVar5 - 2];
          case 8:
          case 9:
          case 10:
          case 0xb:
                    // WARNING: This code block may not be properly labeled as switch case
            param_1[uVar5 - 2] = puVar3;
            param_1[uVar5 - 1] = param_2[uVar5 - 1];
          case 4:
          case 5:
          case 6:
          case 7:
                    // WARNING: Could not recover jumptable at 0x0040f04f. Too many branches
                    // WARNING: Treating indirect jump as call
            uVar8 = (*(code *)(&switchD_0040ef40::switchdataD_0040f054)[uVar6])();
            return uVar8;
          }
        }
        for (; uVar5 != 0; uVar5 = uVar5 - 1) {
          *param_1 = *param_2;
          param_2 = param_2 + 1;
          param_1 = param_1 + 1;
        }
        switch(uVar6) {
        case 1:
          goto switchD_0040ef40_caseD_1;
        case 2:
          goto switchD_0040ef40_caseD_2;
        case 3:
          goto switchD_0040ef40_caseD_3;
        }
        break;
      case 3:
        *(undefined *)param_1 = *(undefined *)param_2;
        puVar3 = (undefined4 *)(uint)*(byte *)((int)param_2 + 1);
        uVar5 = uVar5 >> 2;
        *(byte *)((int)param_1 + 1) = *(byte *)((int)param_2 + 1);
        param_2 = (undefined4 *)((int)param_2 + 2);
        param_1 = (undefined4 *)((int)param_1 + 2);
        if (uVar5 < 8) goto switchD_0040ef68_switchD;
        for (; uVar5 != 0; uVar5 = uVar5 - 1) {
          *param_1 = *param_2;
          param_2 = param_2 + 1;
          param_1 = param_1 + 1;
        }
        goto switchD_0040ef40_caseD_3;
      }
    }
  }
switchD_0040ef40_caseD_0:
                    // WARNING: Bad instruction - Truncating control flow here
  halt_baddata();
}



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
  
  iVar2 = func_0x2076f3a6(_FileHandle);
  if (iVar2 == -1) {
    puVar3 = (undefined4 *)func_0x89f5f2b1();
    *puVar3 = 9;
    lVar4 = -1;
  }
  else {
    lVar4 = (*(code *)s_R6002___floating_point_support_n_0041c059._15_4_)(iVar2,_Offset,0,_Origin);
    if (lVar4 == -1) {
      iVar2 = (*(code *)s_R6002___floating_point_support_n_0041c059._7_4_)();
    }
    else {
      iVar2 = 0;
    }
    if (iVar2 == 0) {
      pbVar1 = (byte *)((&DAT_00425280)[_FileHandle >> 5] + 4 + (_FileHandle & 0x1fU) * 0x40);
      *pbVar1 = *pbVar1 & 0xfd;
    }
    else {
      func_0xaff5f2e7(iVar2);
      lVar4 = -1;
    }
  }
  return lVar4;
}



void __cdecl FUN_0040f690(int param_1)

{
  (*DAT_0041c138)(*(undefined4 *)(s_pxDDDDDDDDD__004225ab + param_1 * 8 + 5));
  return;
}



// Library Function - Single Match
//  __lock
// 
// Libraries: Visual Studio 2008 Release, Visual Studio 2010 Release

void __cdecl __lock(int _File)

{
  int iVar1;
  
  if (*(int *)(s_pxDDDDDDDDD__004225ab + _File * 8 + 5) == 0) {
    iVar1 = func_0x9f26f7d3(_File);
    if (iVar1 == 0) {
      func_0xb932f7df(0x11);
    }
  }
  (*DAT_0041c134)(*(int *)(s_pxDDDDDDDDD__004225ab + _File * 8 + 5));
  return;
}



// Library Function - Single Match
//  ___sbh_find_block
// 
// Library: Visual Studio 2008 Release

uint __cdecl ___sbh_find_block(int param_1)

{
  uint uVar1;
  
  uVar1 = DAT_00425264;
  while( true ) {
    if (DAT_00425260 * 0x14 + DAT_00425264 <= uVar1) {
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
    pcVar8 = DAT_0041c160;
    if (*piVar4 == 0) {
      if (DAT_00423950 != (uint *)0x0) {
        (*DAT_0041c160)(DAT_00425274 * 0x8000 + DAT_00423950[3],0x8000,0x4000);
        DAT_00423950[2] = DAT_00423950[2] | 0x80000000U >> ((byte)DAT_00425274 & 0x1f);
        *(undefined4 *)(DAT_00423950[4] + 0xc4 + DAT_00425274 * 4) = 0;
        *(char *)(DAT_00423950[4] + 0x43) = *(char *)(DAT_00423950[4] + 0x43) + -1;
        if (*(char *)(DAT_00423950[4] + 0x43) == '\0') {
          DAT_00423950[1] = DAT_00423950[1] & 0xfffffffe;
        }
        if (DAT_00423950[2] == 0xffffffff) {
          (*pcVar8)(DAT_00423950[3],0,0x8000);
          (*DAT_0041c0f4)(DAT_00423954,0,DAT_00423950[4]);
          func_0x2bd7fafc(DAT_00423950,DAT_00423950 + 5,
                          (DAT_00425260 * 0x14 - (int)DAT_00423950) + -0x14 + DAT_00425264);
          DAT_00425260 = DAT_00425260 + -1;
          if (DAT_00423950 < param_1) {
            param_1 = param_1 + -5;
          }
          DAT_0042526c = DAT_00425264;
        }
      }
      DAT_00423950 = param_1;
      DAT_00425274 = uVar15;
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
  iVar6 = (*DAT_0041c164)(uVar8,0x8000,0x1000,4);
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
  
  puVar10 = DAT_00425264 + DAT_00425260 * 5;
  uVar8 = (int)param_1 + 0x17U & 0xfffffff0;
  iVar9 = ((int)((int)param_1 + 0x17U) >> 4) + -1;
  bVar7 = (byte)iVar9;
  param_1 = DAT_0042526c;
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
  puVar14 = DAT_00425264;
  if (param_1 == puVar10) {
    for (; (puVar14 < DAT_0042526c && ((puVar14[1] & local_c | *puVar14 & uVar16) == 0));
        puVar14 = puVar14 + 5) {
    }
    param_1 = puVar14;
    if (puVar14 == DAT_0042526c) {
      for (; (puVar14 < puVar10 && (puVar14[2] == 0)); puVar14 = puVar14 + 5) {
      }
      puVar15 = DAT_00425264;
      param_1 = puVar14;
      if (puVar14 == puVar10) {
        for (; (puVar15 < DAT_0042526c && (puVar15[2] == 0)); puVar15 = puVar15 + 5) {
        }
        param_1 = puVar15;
        if ((puVar15 == DAT_0042526c) &&
           (param_1 = (uint *)func_0xdb2b0091(), param_1 == (uint *)0x0)) {
          return;
        }
      }
      uVar6 = func_0x8b2c00a7(param_1);
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
  DAT_0042526c = param_1;
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
    if (iVar11 == 0) goto LAB_0041021e;
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
LAB_0041021e:
  piVar13 = (int *)((int)piVar13 + iVar11);
  *piVar13 = uVar8 + 1;
  *(uint *)((int)piVar13 + (uVar8 - 4)) = uVar8 + 1;
  iVar9 = *piVar3;
  *piVar3 = iVar9 + 1;
  if (((iVar9 == 0) && (param_1 == DAT_00423950)) && (local_8 == DAT_00425274)) {
    DAT_00423950 = (uint *)0x0;
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
  
  DAT_00423954 = (*DAT_0041c16c)(in_stack_00000004 == 0,0x1000,0);
  if (DAT_00423954 == 0) {
    return 0;
  }
  DAT_0042525c = 1;
  return 1;
}



// WARNING: Globals starting with '_' overlap smaller symbols at the same address
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
    (*(code *)s_R6009___not_enough_space_for_env_0041c001._31_4_)(uVar2);
    iVar1 = (*ram0x0041c054)(param_1);
    uVar2 = uVar2 + 1000;
    if (60000 < uVar2) {
      return;
    }
  } while (iVar1 == 0);
  return;
}



void __cdecl FUN_004102c1(undefined4 param_1)

{
  code *pcVar1;
  
  func_0x6c380319();
  func_0xc1360321(param_1);
  pcVar1 = (code *)func_0x4df7032c(DAT_004226d4);
  (*pcVar1)(0xff);
  return;
}



// WARNING: Globals starting with '_' overlap smaller symbols at the same address

void __cdecl FUN_004102ea(undefined4 param_1)

{
  int iVar1;
  code *pcVar2;
  
  iVar1 = (*ram0x0041c054)(&DAT_0041c378);
  if (iVar1 != 0) {
    pcVar2 = (code *)(*DAT_0041c110)(iVar1,&DAT_0041c368);
    if (pcVar2 != (code *)0x0) {
      (*pcVar2)(param_1);
    }
  }
  return;
}



void FUN_00410315(undefined4 param_1)

{
  code *pcVar1;
  
  func_0xe2330370(param_1);
  (*(code *)s_R6008___not_enough_space_for_arg_0041c02d._35_4_)(param_1);
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
  
  if (DAT_004203c0 != (code *)0x0) {
    iVar1 = func_0x3b7204e6(&DAT_004203c0);
    if (iVar1 != 0) {
      (*DAT_004203c0)(param_1);
    }
  }
  func_0xc68004fa();
  iVar1 = func_0x54340409(&DAT_0041c204,&DAT_0041c21c);
  if (iVar1 == 0) {
    func_0xcc150419(&DAT_00413427);
    func_0x3734042a(&DAT_0041c200);
    if (DAT_00425258 != (code *)0x0) {
      iVar1 = func_0x3b72053e(&DAT_00425258);
      if (iVar1 != 0) {
        (*DAT_00425258)(0,2,0);
      }
    }
    iVar1 = 0;
  }
  return iVar1;
}



void __cdecl FUN_00410531(undefined4 param_1)

{
  func_0xfd340590(param_1,0,0);
  return;
}



void __cdecl FUN_00410547(undefined4 param_1)

{
  func_0xfd3405a6(param_1,1,0);
  return;
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
    if (param_1 == (&DAT_004226d8)[local_8 * 2]) break;
    local_8 = local_8 + 1;
  } while (local_8 < 0x17);
  uVar2 = local_8;
  if (local_8 < 0x17) {
    iVar3 = func_0xca85074d(3);
    if ((iVar3 == 1) ||
       ((iVar3 = func_0xca85075e(3), iVar3 == 0 &&
        (s__Repeat_del___s__if_exist___s__g_00422037._9_4_ == 1)))) {
      iVar3 = (*DAT_0041c150)(0xfffffff4);
      if ((iVar3 != 0) && (iVar3 != -1)) {
        puVar1 = (undefined4 *)(uVar2 * 8 + 0x4226dc);
        uVar4 = func_0xcb7b08b2(*puVar1,local_c,0);
        (*(code *)s_R6008___not_enough_space_for_arg_0041c02d._23_4_)(iVar3,*puVar1,uVar4);
      }
    }
    else if (param_1 != 0xfc) {
      iVar3 = func_0xabe70692(&DAT_00423990,0x314,&DAT_0041c938);
      if (iVar3 != 0) {
        func_0xf9f406a3(0,0,0,0,0);
      }
      DAT_00423aad = 0;
      iVar3 = (*(code *)s_R6008___not_enough_space_for_arg_0041c02d._15_4_)(0,&DAT_004239a9,0x104);
      if ((iVar3 == 0) && (iVar3 = func_0xabe706d4(&DAT_004239a9,0x2fb,&DAT_0041c920), iVar3 != 0))
      {
        func_0xf9f406e7(0,0,0,0,0);
      }
      iVar3 = func_0xcb7b07f0(&DAT_004239a9);
      if (0x3c < iVar3 + 1U) {
        iVar3 = func_0xcb7b07fd(&DAT_004239a9);
        iVar3 = func_0x15850817(iVar3 + 0x42396e,(int)&DAT_00423ca4 - (iVar3 + 0x42396e),
                                &DAT_0041c91c,3);
        if (iVar3 != 0) {
          func_0xf9f4072a(0,0,0,0,0);
        }
      }
      iVar3 = func_0x0ff0073d(&DAT_00423990,0x314,&DAT_0041c918);
      if (iVar3 != 0) {
        func_0xf9f4074e(0,0,0,0,0);
      }
      iVar3 = func_0x0ff00762(&DAT_00423990,0x314,*(undefined4 *)(local_8 * 8 + 0x4226dc));
      if (iVar3 != 0) {
        func_0xf9f40773(0,0,0,0,0);
      }
      func_0xac830886(&DAT_00423990,&DAT_0041c8f0,0x12010);
    }
  }
  return;
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
  
  local_8 = s__Repeat_del___s__if_exist___s__g_00422037._13_4_ ^ (uint)&stack0xfffffffc;
  iVar2 = (*DAT_0041c170)(*(undefined4 *)(unaff_ESI + 4),local_51c);
  if (iVar2 == 0) {
    uVar3 = 0;
    do {
      pcVar1 = (char *)(unaff_ESI + 0x11d + uVar3);
      if (pcVar1 + (-0x61 - (unaff_ESI + 0x11d)) + 0x20 < (char *)0x1a) {
        pbVar6 = (byte *)(unaff_ESI + 0x1d + uVar3);
        *pbVar6 = *pbVar6 | 0x10;
        cVar5 = (char)uVar3 + ' ';
LAB_004109b9:
        *pcVar1 = cVar5;
      }
      else {
        if (pcVar1 + (-0x61 - (unaff_ESI + 0x11d)) < (char *)0x1a) {
          pbVar6 = (byte *)(unaff_ESI + 0x1d + uVar3);
          *pbVar6 = *pbVar6 | 0x20;
          cVar5 = (char)uVar3 + -0x20;
          goto LAB_004109b9;
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
          func_0x9c0f0904(local_108 + uVar3,0x20,(*pbVar6 - uVar3) + 1);
        }
        local_516 = pbVar6[1];
        pbVar6 = pbVar6 + 2;
      } while (local_516 != 0);
    }
    func_0x788d0a2f(0,1,local_108,0x100,local_508,*(undefined4 *)(unaff_ESI + 4),
                    *(undefined4 *)(unaff_ESI + 0xc),0);
    func_0x798b0a4f(0,*(undefined4 *)(unaff_ESI + 0xc),0x100,local_108,0x100,local_208,0x100,
                    *(undefined4 *)(unaff_ESI + 4),0);
    func_0x798b0a74(0,*(undefined4 *)(unaff_ESI + 0xc),0x200,local_108,0x100,local_308,0x100,
                    *(undefined4 *)(unaff_ESI + 4),0);
    uVar3 = 0;
    do {
      if ((local_508[uVar3] & 1) == 0) {
        if ((local_508[uVar3] & 2) != 0) {
          pbVar6 = (byte *)(unaff_ESI + 0x1d + uVar3);
          *pbVar6 = *pbVar6 | 0x20;
          uVar4 = local_308[uVar3];
          goto LAB_00410957;
        }
        *(undefined *)(unaff_ESI + 0x11d + uVar3) = 0;
      }
      else {
        pbVar6 = (byte *)(unaff_ESI + 0x1d + uVar3);
        *pbVar6 = *pbVar6 | 0x10;
        uVar4 = local_208[uVar3];
LAB_00410957:
        *(undefined *)(unaff_ESI + 0x11d + uVar3) = uVar4;
      }
      uVar3 = uVar3 + 1;
    } while (uVar3 < 0x100);
  }
  func_0xf1d60a1f();
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
  
  func_0x92e80ad9(0);
  DAT_00423ca8 = 0;
  if (unaff_ESI == -2) {
    DAT_00423ca8 = 1;
    iVar1 = (*DAT_0041c178)();
  }
  else if (unaff_ESI == -3) {
    DAT_00423ca8 = 1;
    iVar1 = (*DAT_0041c174)();
  }
  else {
    if (unaff_ESI != -4) {
      if (local_8 == '\0') {
        DAT_00423ca8 = 0;
        return unaff_ESI;
      }
      *(uint *)(local_c + 0x70) = *(uint *)(local_c + 0x70) & 0xfffffffd;
      return unaff_ESI;
    }
    iVar1 = *(int *)(local_14 + 4);
    DAT_00423ca8 = 1;
  }
  if (local_8 != '\0') {
    *(uint *)(local_c + 0x70) = *(uint *)(local_c + 0x70) & 0xfffffffd;
  }
  return iVar1;
}



// WARNING: Control flow encountered bad instruction data

void __cdecl FUN_00410af3(undefined4 param_1,int param_2)

{
  byte *pbVar1;
  byte bVar2;
  uint uVar3;
  uint uVar4;
  int iVar5;
  undefined4 uVar6;
  undefined2 *puVar7;
  int extraout_ECX;
  undefined2 *puVar8;
  byte *pbVar9;
  uint local_24;
  byte *local_20;
  undefined local_1c [20];
  uint local_8;
  
  local_8 = s__Repeat_del___s__if_exist___s__g_00422037._13_4_ ^ (uint)&stack0xfffffffc;
  uVar3 = func_0x6f3b0b61();
  if (uVar3 == 0) {
LAB_00410b1e:
    func_0xd4380b73();
                    // WARNING: Bad instruction - Truncating control flow here
    halt_baddata();
  }
  local_20 = (byte *)0x0;
  uVar4 = 0;
  do {
    if (*(uint *)((int)&DAT_00422bc8 + uVar4) == uVar3) {
      func_0x9c0f0c2b(param_2 + 0x1c,0,0x101);
      local_24 = 0;
      pbVar9 = &DAT_00422bd8 + (int)local_20 * 0x30;
      local_20 = pbVar9;
      do {
        for (; (*pbVar9 != 0 && (bVar2 = pbVar9[1], bVar2 != 0)); pbVar9 = pbVar9 + 2) {
          for (uVar4 = (uint)*pbVar9; uVar4 <= bVar2; uVar4 = uVar4 + 1) {
            pbVar1 = (byte *)(param_2 + 0x1d + uVar4);
            *pbVar1 = *pbVar1 | (&DAT_00422bc4)[local_24];
            bVar2 = pbVar9[1];
          }
        }
        local_24 = local_24 + 1;
        pbVar9 = local_20 + 8;
        local_20 = pbVar9;
      } while (local_24 < 4);
      *(uint *)(param_2 + 4) = uVar3;
      *(undefined4 *)(param_2 + 8) = 1;
      uVar6 = func_0xa5380c94();
      *(undefined4 *)(param_2 + 0xc) = uVar6;
      puVar7 = (undefined2 *)(param_2 + 0x10);
      puVar8 = (undefined2 *)(&DAT_00422bcc + extraout_ECX);
      iVar5 = 6;
      do {
        *puVar7 = *puVar8;
        puVar8 = puVar8 + 1;
        puVar7 = puVar7 + 1;
        iVar5 = iVar5 + -1;
      } while (iVar5 != 0);
      func_0x38390cb7();
                    // WARNING: Bad instruction - Truncating control flow here
      halt_baddata();
    }
    local_20 = (byte *)((int)local_20 + 1);
    uVar4 = uVar4 + 0x30;
  } while (uVar4 < 0xf0);
  if ((uVar3 != 65000) && (uVar3 != 0xfde9)) {
    iVar5 = (*DAT_0041c17c)(uVar3 & 0xffff);
    if (iVar5 != 0) {
      iVar5 = (*DAT_0041c170)(uVar3,local_1c);
      if (iVar5 != 0) {
        func_0x9c0f0be4(param_2 + 0x1c,0,0x101);
        *(uint *)(param_2 + 4) = uVar3;
        *(undefined4 *)(param_2 + 0xc) = 0;
        *(int *)(uVar3 + 0x7d800000) = *(int *)(uVar3 + 0x7d800000) + 0x7bf0ff12;
        return;
      }
      if (DAT_00423ca8 != 0) goto LAB_00410b1e;
    }
  }
  func_0xf1d60d24();
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
       (*(undefined4 **)(param_1 + 0xbc) != &DAT_00422ee0)) &&
      (*(int **)(param_1 + 0xb0) != (int *)0x0)) && (**(int **)(param_1 + 0xb0) == 0)) {
    piVar1 = *(int **)(param_1 + 0xb8);
    if ((piVar1 != (int *)0x0) && (*piVar1 == 0)) {
      func_0x42ec0f1e(piVar1);
      func_0x948f1029(*(undefined4 *)(param_1 + 0xbc));
    }
    piVar1 = *(int **)(param_1 + 0xb4);
    if ((piVar1 != (int *)0x0) && (*piVar1 == 0)) {
      func_0x42ec0f3f(piVar1);
      func_0x4f8f104a(*(undefined4 *)(param_1 + 0xbc));
    }
    func_0x42ec0f57(*(undefined4 *)(param_1 + 0xb0));
    func_0x42ec0f62(*(undefined4 *)(param_1 + 0xbc));
  }
  if ((*(int **)(param_1 + 0xc0) != (int *)0x0) && (**(int **)(param_1 + 0xc0) == 0)) {
    func_0x42ec0f83(*(int *)(param_1 + 0xc4) + -0xfe);
    func_0x42ec0f96(*(int *)(param_1 + 0xcc) + -0x80);
    func_0x42ec0fa4(*(int *)(param_1 + 0xd0) + -0x80);
    func_0x42ec0faf(*(undefined4 *)(param_1 + 0xc0));
  }
  puVar2 = *(undefined **)(undefined4 *)(param_1 + 0xd4);
  if ((puVar2 != &DAT_00422e20) && (*(int *)(puVar2 + 0xb4) == 0)) {
    func_0xba8d10cf(puVar2);
    func_0x42ec0fd6(*(undefined4 *)(param_1 + 0xd4));
  }
  ppiVar4 = (int **)(param_1 + 0x50);
  param_1 = 6;
  do {
    if (((ppiVar4[-2] != (int *)&DAT_00422cc0) && (piVar1 = *ppiVar4, piVar1 != (int *)0x0)) &&
       (*piVar1 == 0)) {
      func_0x42ec0ffb(piVar1);
    }
    if (((ppiVar4[-1] != (int *)0x0) && (piVar1 = ppiVar4[1], piVar1 != (int *)0x0)) &&
       (*piVar1 == 0)) {
      func_0x42ec1012(piVar1);
    }
    ppiVar4 = ppiVar4 + 4;
    param_1 = param_1 + -1;
  } while (param_1 != 0);
  func_0x42ec1021(iVar3);
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
  pcVar1 = DAT_0041c124;
  (*DAT_0041c124)(param_1);
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
    if (((undefined *)piVar3[-2] != &DAT_00422cc0) && (*piVar3 != 0)) {
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
  pcVar1 = DAT_0041c130;
  if (param_1 != 0) {
    (*DAT_0041c130)(param_1);
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
      if (((undefined *)piVar3[-2] != &DAT_00422cc0) && (*piVar3 != 0)) {
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
    if (param_1 < 0x66a) goto LAB_00411201;
    iVar1 = 0x6f0;
    if (param_1 < 0x6f0) {
      return -1;
    }
    if (param_1 < 0x6fa) goto LAB_00411201;
    iVar1 = 0x966;
    if (param_1 < 0x966) {
      return -1;
    }
    if (param_1 < 0x970) goto LAB_00411201;
    iVar1 = 0x9e6;
    if (param_1 < 0x9e6) {
      return -1;
    }
    if (param_1 < 0x9f0) goto LAB_00411201;
    iVar1 = 0xa66;
    if (param_1 < 0xa66) {
      return -1;
    }
    if (param_1 < 0xa70) goto LAB_00411201;
    iVar1 = 0xae6;
    if (param_1 < 0xae6) {
      return -1;
    }
    if (param_1 < 0xaf0) goto LAB_00411201;
    iVar1 = 0xb66;
    if (param_1 < 0xb66) {
      return -1;
    }
    if (param_1 < 0xb70) goto LAB_00411201;
    iVar1 = 0xc66;
    if (param_1 < 0xc66) {
      return -1;
    }
    if (param_1 < 0xc70) goto LAB_00411201;
    iVar1 = 0xce6;
    if (param_1 < 0xce6) {
      return -1;
    }
    if (param_1 < 0xcf0) goto LAB_00411201;
    iVar1 = 0xd66;
    if (param_1 < 0xd66) {
      return -1;
    }
    if (param_1 < 0xd70) goto LAB_00411201;
    iVar1 = 0xe50;
    if (param_1 < 0xe50) {
      return -1;
    }
    if (param_1 < 0xe5a) goto LAB_00411201;
    iVar1 = 0xed0;
    if (param_1 < 0xed0) {
      return -1;
    }
    if (param_1 < 0xeda) goto LAB_00411201;
    iVar1 = 0xf20;
    if (param_1 < 0xf20) {
      return -1;
    }
    if (param_1 < 0xf2a) goto LAB_00411201;
    iVar1 = 0x1040;
    if (param_1 < 0x1040) {
      return -1;
    }
    if (param_1 < 0x104a) goto LAB_00411201;
    iVar1 = 0x17e0;
    if (param_1 < 0x17e0) {
      return -1;
    }
    if (param_1 < 0x17ea) goto LAB_00411201;
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
LAB_00411201:
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
    local_8[0] = *(ushort *)(DAT_00422e1c + (uint)_C * 2) & _Type;
  }
  else {
    func_0x92e81427(_Locale);
    iVar1 = func_0xbb901545(local_18,1,&_C,1,local_8,*(undefined4 *)(local_18[0] + 4),
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
//  _write_char
// 
// Libraries: Visual Studio 2008 Release, Visual Studio 2010 Release

void __cdecl _write_char(undefined4 param_1)

{
  short sVar1;
  int in_EAX;
  int *unaff_ESI;
  
  if (((*(byte *)(in_EAX + 0xc) & 0x40) == 0) || (*(int *)(in_EAX + 8) != 0)) {
    sVar1 = func_0xf9901661(param_1);
    if (sVar1 == -1) {
      *unaff_ESI = -1;
      return;
    }
  }
  *unaff_ESI = *unaff_ESI + 1;
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
    func_0xf045168e(param_1);
  } while (*in_EAX != -1);
  return;
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
      func_0xf04516c9(*this);
      this = (void *)((int)this + 2);
      if (*in_EAX == -1) {
        piVar1 = (int *)func_0x89f615d6();
        if (*piVar1 != 0x2a) {
          return;
        }
        func_0xf04516e4(0x3f);
      }
    }
  }
  else {
    *in_EAX = *in_EAX + param_1;
  }
  return;
}



// WARNING: Control flow encountered bad instruction data
// WARNING: Instruction at (ram,0x004116e5) overlaps instruction at (ram,0x004116e2)
// 

void __cdecl FUN_004115a1(int param_1,ushort *param_2,undefined4 param_3,int *param_4)

{
  byte *pbVar1;
  byte bVar2;
  ushort uVar3;
  byte bVar4;
  undefined4 *puVar5;
  uint uVar6;
  byte *pbVar7;
  uint uVar8;
  ushort *puVar9;
  int local_448;
  char local_444;
  
  func_0x92e81656(param_3);
  if (param_1 == 0) {
switchD_004116e2_caseD_9:
    puVar5 = (undefined4 *)func_0x89f6165f();
    *puVar5 = 0x16;
  }
  else {
    if (param_2 != (ushort *)0x0) {
      uVar3 = *param_2;
      pbVar7 = (byte *)(uint)uVar3;
      if (uVar3 == 0) goto LAB_004120f7;
      puVar9 = param_2 + 1;
      if ((ushort)(uVar3 - 0x20) < 0x59) {
        uVar6 = (byte)(&DAT_0041ca38)[uVar3] & 0xf;
      }
      else {
        uVar6 = 0;
      }
      bVar4 = (byte)(&DAT_0041ca58)[uVar6 * 9] >> 4;
      switch(bVar4) {
      case 0:
                    // WARNING: Bad instruction - Truncating control flow here
        halt_baddata();
      case 1:
                    // WARNING: Bad instruction - Truncating control flow here
        halt_baddata();
      case 2:
        pbVar1 = (byte *)((int)param_4 + -0x40b73);
        *pbVar1 = *pbVar1 << 7 | *pbVar1 >> 1;
        *(int *)(pbVar7 + -0x45b7b) = *(int *)(pbVar7 + -0x45b7b) + -1;
        *(int *)(pbVar7 + -0x44f7b) = *(int *)(pbVar7 + -0x44f7b) + -1;
        *(int *)(pbVar7 + -0x42b7b) = *(int *)(pbVar7 + -0x42b7b) + -1;
        *(int *)(pbVar7 + -0x4237b) = *(int *)(pbVar7 + -0x4237b) + -1;
        *(int *)(pbVar7 + -0x4077b) = *(int *)(pbVar7 + -0x4077b) + -1;
        *(int *)(pbVar7 + -0x4277b) = *(int *)(pbVar7 + -0x4277b) + -1;
                    // WARNING: Bad instruction - Truncating control flow here
        halt_baddata();
      case 3:
        bVar2 = *pbVar7;
        *pbVar7 = *pbVar7 + bVar4;
        uVar8 = (uint)(byte)(bVar4 + 2 + CARRY1(bVar2,bVar4));
        uVar6 = (uint)uVar3;
        if (uVar6 == 0x20) {
                    // WARNING: Bad instruction - Truncating control flow here
          halt_baddata();
        }
        if (uVar6 == 0x23) {
                    // WARNING: Bad instruction - Truncating control flow here
          halt_baddata();
        }
        uVar6 = uVar6 - 0x2b;
        if (uVar6 == 0) {
                    // WARNING: Bad instruction - Truncating control flow here
          halt_baddata();
        }
        if (uVar6 == uVar8) {
                    // WARNING: Bad instruction - Truncating control flow here
          halt_baddata();
        }
        if (uVar6 - uVar8 == 3) {
                    // WARNING: Bad instruction - Truncating control flow here
          halt_baddata();
        }
        break;
      case 4:
        *pbVar7 = *pbVar7 + bVar4;
        if (uVar3 != 0x2a) {
                    // WARNING: Bad instruction - Truncating control flow here
          halt_baddata();
        }
        if (*param_4 < 0) {
                    // WARNING: Bad instruction - Truncating control flow here
          halt_baddata();
        }
        break;
      case 5:
        *pbVar7 = *pbVar7 + bVar4;
                    // WARNING: Bad instruction - Truncating control flow here
        halt_baddata();
      case 6:
        *pbVar7 = *pbVar7 + bVar4;
        if (uVar3 != 0x2a) {
                    // WARNING: Bad instruction - Truncating control flow here
          halt_baddata();
        }
        if (*param_4 < 0) {
                    // WARNING: Bad instruction - Truncating control flow here
          halt_baddata();
        }
        break;
      case 7:
        *pbVar7 = *pbVar7 + bVar4;
        if (uVar3 == 0x49) {
          uVar3 = *puVar9;
          if ((uVar3 == 0x36) && (param_2[2] == 0x34)) {
                    // WARNING: Bad instruction - Truncating control flow here
            halt_baddata();
          }
          if ((uVar3 == 0x33) && (param_2[2] == 0x32)) {
                    // WARNING: Bad instruction - Truncating control flow here
            halt_baddata();
          }
          if (((((uVar3 != 100) && (uVar3 != 0x69)) && (uVar3 != 0x6f)) &&
              ((uVar3 != 0x75 && (uVar3 != 0x78)))) && (uVar3 != 0x58)) {
            func_0xf0451a5b(pbVar7);
                    // WARNING: Bad instruction - Truncating control flow here
            halt_baddata();
          }
        }
        else {
          if (uVar3 == 0x68) {
                    // WARNING: Bad instruction - Truncating control flow here
            halt_baddata();
          }
          if (uVar3 == 0x6c) {
            if (*puVar9 == 0x6c) {
                    // WARNING: Bad instruction - Truncating control flow here
              halt_baddata();
            }
                    // WARNING: Bad instruction - Truncating control flow here
            halt_baddata();
          }
          if (uVar3 == 0x77) {
                    // WARNING: Bad instruction - Truncating control flow here
            halt_baddata();
          }
        }
        break;
      default:
        goto switchD_004116e2_caseD_9;
      case 0xbad1abe1:
        break;
      }
      if (*puVar9 != 0) {
                    // WARNING: Bad instruction - Truncating control flow here
        halt_baddata();
      }
      if ((bVar4 == 0) || (bVar4 == 7)) {
LAB_004120f7:
        if (local_444 != '\0') {
          *(uint *)(local_448 + 0x70) = *(uint *)(local_448 + 0x70) & 0xfffffffd;
        }
        func_0xf1d6216b();
        return;
      }
    }
    puVar5 = (undefined4 *)func_0x89f6169a();
    *puVar5 = 0x16;
  }
  func_0x21f61671(0,0,0,0,0);
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
    func_0x385222da();
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
      func_0x38522312();
      if (*in_EAX == -1) {
        piVar1 = (int *)func_0x89f6221d();
        if (*piVar1 != 0x2a) {
          return;
        }
        func_0x3852232b();
      }
    }
  }
  else {
    *in_EAX = *in_EAX + param_1;
  }
  return;
}



// WARNING: Control flow encountered bad instruction data
// WARNING: Instruction at (ram,0x004124b2) overlaps instruction at (ram,0x004124b1)
// 

void __cdecl FUN_004121e7(int param_1,char *param_2,undefined4 param_3,int *param_4)

{
  undefined uVar1;
  char cVar2;
  byte bVar3;
  undefined4 *puVar4;
  uint uVar5;
  int iVar6;
  undefined *puVar7;
  undefined *extraout_EDX;
  undefined *puVar8;
  char *pcVar9;
  bool bVar10;
  undefined local_254 [8];
  int local_24c;
  char local_248;
  char *local_244;
  char *local_240;
  undefined4 local_23c;
  int local_238;
  undefined4 local_234;
  undefined4 local_22c;
  int *local_228;
  undefined4 local_224;
  int local_21c;
  char local_215;
  undefined4 local_214;
  uint local_8;
  
  local_8 = s__Repeat_del___s__if_exist___s__g_00422037._13_4_ ^ (uint)&stack0xfffffffc;
  local_228 = param_4;
  local_214 = 0;
  local_238 = 0;
  local_21c = 0;
  local_234 = 0;
  local_23c = 0;
  func_0x92e8229c(param_3);
  if (param_1 == 0) goto LAB_00412252;
  puVar8 = extraout_EDX;
  if ((*(byte *)(param_1 + 0xc) & 0x40) == 0) {
    uVar5 = func_0x650f22e1(param_1);
    puVar8 = &DAT_00422570;
    if ((uVar5 == 0xffffffff) || (uVar5 == 0xfffffffe)) {
      puVar7 = &DAT_00422570;
    }
    else {
      puVar7 = (undefined *)((uVar5 & 0x1f) * 0x40 + (&DAT_00425280)[(int)uVar5 >> 5]);
    }
    if ((puVar7[0x24] & 0x7f) != 0) goto LAB_00412252;
    if ((uVar5 == 0xffffffff) || (uVar5 == 0xfffffffe)) {
      puVar7 = &DAT_00422570;
    }
    else {
      puVar7 = (undefined *)((uVar5 & 0x1f) * 0x40 + (&DAT_00425280)[(int)uVar5 >> 5]);
    }
    if ((puVar7[0x24] & 0x80) != 0) goto LAB_00412252;
  }
  if (param_2 == (char *)0x0) {
LAB_00412252:
    puVar4 = (undefined4 *)func_0x89f622a5();
    *puVar4 = 0x16;
    func_0x21f622b7(0,0,0,0,0);
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
  cVar2 = local_215;
  if (local_215 == '\0') goto LAB_00412d6d;
  pcVar9 = param_2 + 1;
  uVar5 = 0;
  if ((byte)(local_215 - 0x20U) < 0x59) {
    uVar5 = (byte)(&DAT_0041ca38)[local_215] & 0xf;
  }
  bVar3 = (byte)(&DAT_0041ca58)[uVar5 * 9] >> 4;
  local_244 = (char *)(uint)bVar3;
  local_240 = pcVar9;
  if (local_244 == (char *)0x8) goto LAB_00412252;
  if (local_244 < &DAT_00000007 || local_244 + -7 == (char *)0x0) {
                    // WARNING: Could not find normalized switch variable to match jumptable
    switch(bVar3) {
    case 0:
                    // WARNING: Bad instruction - Truncating control flow here
      halt_baddata();
    case 1:
                    // WARNING: Bad instruction - Truncating control flow here
      halt_baddata();
    case 2:
                    // WARNING: Bad instruction - Truncating control flow here
      halt_baddata();
    case 3:
      bVar10 = CARRY1(DAT_00000007,bVar3);
      DAT_00000007 = DAT_00000007 + bVar3;
      iVar6 = (int)local_244 - (uint)bVar10;
      if (iVar6 == -0x3d41f0c3) {
                    // WARNING: Bad instruction - Truncating control flow here
        halt_baddata();
      }
      if (iVar6 == -0x3d41f0c0) {
                    // WARNING: Bad instruction - Truncating control flow here
        halt_baddata();
      }
      if (iVar6 == -0x3d41f0b8) {
                    // WARNING: Bad instruction - Truncating control flow here
        halt_baddata();
      }
      if (iVar6 == -0x3d41f0b6) {
                    // WARNING: Bad instruction - Truncating control flow here
        halt_baddata();
      }
      if (iVar6 == -0x3d41f0b3) {
                    // WARNING: Bad instruction - Truncating control flow here
        halt_baddata();
      }
      break;
    case 4:
      bVar10 = CARRY1(DAT_00000007,bVar3);
      DAT_00000007 = DAT_00000007 + bVar3;
      if (local_244 + -0x2afa801d != (char *)(uint)bVar10) {
                    // WARNING: Bad instruction - Truncating control flow here
        halt_baddata();
      }
      local_228 = param_4 + 1;
      local_238 = *param_4;
      if (local_238 < 0) {
                    // WARNING: Bad instruction - Truncating control flow here
        halt_baddata();
      }
      break;
    case 5:
      DAT_00000007 = DAT_00000007 + bVar3;
                    // WARNING: Bad instruction - Truncating control flow here
      halt_baddata();
    case 6:
      bVar10 = CARRY1(DAT_00000007,bVar3);
      DAT_00000007 = DAT_00000007 + bVar3;
      if (local_244 + -0x2afa801d == (char *)(uint)bVar10) {
        local_228 = param_4 + 1;
        local_21c = *param_4;
        if (local_21c < 0) {
                    // WARNING: Bad instruction - Truncating control flow here
          halt_baddata();
        }
      }
      else {
        local_21c = local_21c * 10 + -0x30 + (int)local_215;
      }
      break;
    case 7:
      if ((POPCOUNT((uint)(local_244 + -7) & 0xff) & 1U) == 0) {
        uVar1 = in((short)CONCAT31((int3)((uint)puVar8 >> 8),local_215));
        *(undefined *)param_4 = uVar1;
      }
      else {
        *local_244 = *local_244 + bVar3;
        if (local_215 == 'I') {
          cVar2 = *pcVar9;
          if ((cVar2 == '6') && (param_2[2] == '4')) {
                    // WARNING: Bad instruction - Truncating control flow here
            halt_baddata();
          }
          if ((cVar2 == '3') && (param_2[2] == '2')) {
                    // WARNING: Bad instruction - Truncating control flow here
            halt_baddata();
          }
          if (((((cVar2 != 'd') && (cVar2 != 'i')) && (cVar2 != 'o')) &&
              ((cVar2 != 'u' && (cVar2 != 'x')))) && (cVar2 != 'X')) {
            local_244 = (char *)0x0;
            local_23c = 0;
            iVar6 = func_0x508026e6(0x49,local_254);
            if (iVar6 != 0) {
              func_0x38522703();
              local_240 = param_2 + 2;
              if (*pcVar9 == '\0') goto LAB_00412252;
            }
            func_0x38522725();
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
        if (*pcVar9 != 'l') {
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
  local_215 = *pcVar9;
  if (local_215 != '\0') {
                    // WARNING: Bad instruction - Truncating control flow here
    halt_baddata();
  }
  cVar2 = '\0';
  if ((local_244 != (char *)0x0) && (local_244 != &DAT_00000007)) {
    puVar4 = (undefined4 *)func_0x89f62dab();
    *puVar4 = 0x16;
                    // WARNING: Bad instruction - Truncating control flow here
    halt_baddata();
  }
LAB_00412d6d:
  local_215 = cVar2;
  if (local_248 != '\0') {
    *(uint *)(local_24c + 0x70) = *(uint *)(local_24c + 0x70) & 0xfffffffd;
  }
  func_0xf1d62de1();
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
    func_0xe780305f();
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
  
  iVar6 = func_0x20f92f80();
  if (iVar6 != 0) {
    puVar1 = *(ulong **)(iVar6 + 0x5c);
    puVar7 = puVar1;
    do {
      if (*puVar7 == _ExceptionNum) break;
      puVar7 = puVar7 + 3;
    } while (puVar7 < puVar1 + DAT_00422dbc * 3);
    if ((puVar1 + DAT_00422dbc * 3 <= puVar7) || (*puVar7 != _ExceptionNum)) {
      puVar7 = (ulong *)0x0;
    }
    if ((puVar7 == (ulong *)0x0) || (pcVar2 = (code *)puVar7[2], pcVar2 == (code *)0x0)) {
                    // WARNING: Bad instruction - Truncating control flow here
      halt_baddata();
    }
    if (pcVar2 == (code *)&DAT_00000005) {
      puVar7[2] = 0;
                    // WARNING: Bad instruction - Truncating control flow here
      halt_baddata();
    }
    if (pcVar2 != (code *)0x1) {
      uVar3 = *(undefined4 *)(iVar6 + 0x60);
      *(_EXCEPTION_POINTERS **)(iVar6 + 0x60) = _ExceptionPtr;
      if (puVar7[1] == 8) {
        if (DAT_00422db0 < DAT_00422db4 + DAT_00422db0) {
          iVar8 = DAT_00422db0 * 0xc;
          iVar9 = DAT_00422db0;
          do {
            *(undefined4 *)(iVar8 + 8 + *(int *)(iVar6 + 0x5c)) = 0;
            iVar9 = iVar9 + 1;
            iVar8 = iVar8 + 0xc;
          } while (iVar9 < DAT_00422db4 + DAT_00422db0);
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
      if (sVar4 == 0) goto LAB_00413219;
    }
    in_EAX = in_EAX + 1;
  } while ((bVar1) || ((sVar4 != 0x20 && (sVar4 != 9))));
  if ((short *)this != (short *)0x0) {
    *(short *)((int)this + -2) = 0;
  }
LAB_00413219:
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
  
  _DAT_00423ef0 = 0;
  local_8 = in_ECX;
  (*DAT_0041c0b0)(0,&DAT_00423ce8,0x104);
  _DAT_0042397c = &DAT_00423ce8;
  func_0xa0623497(0,&local_8);
  if ((((local_8 < 0x3fffffff) && (in_ECX < 0x7fffffff)) &&
      (uVar1 = (in_ECX + local_8 * 2) * 2, in_ECX * 2 <= uVar1)) &&
     (iVar2 = func_0xe66534c0(uVar1), iVar2 != 0)) {
    func_0xa06234d9(iVar2,&local_8);
    _DAT_0042395c = local_8 - 1;
    iVar3 = 0;
    _DAT_00423964 = iVar2;
  }
  else {
    iVar3 = -1;
  }
  return iVar3;
}



// WARNING: Globals starting with '_' overlap smaller symbols at the same address

void FUN_004133e5(void)

{
  (*ram0x0041c0e8)();
  return;
}



void FUN_004133f2(void)

{
  func_0xdc1f3448();
  FUN_004133e5();
  return;
}



// WARNING: Globals starting with '_' overlap smaller symbols at the same address
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
  if ((s__Repeat_del___s__if_exist___s__g_00422037._13_4_ == -0x44bf19b2) ||
     ((s__Repeat_del___s__if_exist___s__g_00422037._13_4_ & 0xffff0000) == 0)) {
    (*_DAT_0041c0d0)(&local_c);
    uVar4 = local_8 ^ local_c;
    uVar1 = (*(code *)s_Runtime_Error__Program__0041c0d1._3_4_)();
    uVar2 = (*DAT_0041c12c)();
    uVar3 = (*(code *)s_R6009___not_enough_space_for_env_0041c001._35_4_)();
    (*(code *)s_Runtime_Error__Program__0041c0d1._7_4_)(&local_14);
    s__Repeat_del___s__if_exist___s__g_00422037._13_4_ =
         uVar4 ^ uVar1 ^ uVar2 ^ uVar3 ^ local_10 ^ local_14;
    if (s__Repeat_del___s__if_exist___s__g_00422037._13_4_ == 0xbb40e64e) {
      s__Repeat_del___s__if_exist___s__g_00422037._13_4_ = 0xbb40e64f;
    }
    else if ((s__Repeat_del___s__if_exist___s__g_00422037._13_4_ & 0xffff0000) == 0) {
      s__Repeat_del___s__if_exist___s__g_00422037._13_4_ =
           s__Repeat_del___s__if_exist___s__g_00422037._13_4_ |
           s__Repeat_del___s__if_exist___s__g_00422037._13_4_ << 0x10;
    }
    s__Repeat_del___s__if_exist___s__g_00422037._17_4_ =
         ~s__Repeat_del___s__if_exist___s__g_00422037._13_4_;
  }
  else {
    s__Repeat_del___s__if_exist___s__g_00422037._17_4_ =
         ~s__Repeat_del___s__if_exist___s__g_00422037._13_4_;
  }
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
    pvVar1 = (void *)func_0xe1e6354e(_Size);
    if (pvVar1 != (void *)0x0) {
      return pvVar1;
    }
    if (DAT_00423ef4 == 0) break;
    (*(code *)s_R6009___not_enough_space_for_env_0041c001._31_4_)(uVar2);
    uVar2 = uVar2 + 1000;
    if (DAT_00423ef4 < uVar2) {
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
    pvVar1 = (void *)func_0xae5e3698(_Count,_Size,0);
    if (pvVar1 != (void *)0x0) {
      return pvVar1;
    }
    if (DAT_00423ef4 == 0) break;
    (*(code *)s_R6009___not_enough_space_for_env_0041c001._31_4_)(uVar2);
    uVar2 = uVar2 + 1000;
    if (DAT_00423ef4 < uVar2) {
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
    pvVar1 = (void *)func_0xf49436e2(_Ptr,_NewSize);
    if (pvVar1 != (void *)0x0) {
      return pvVar1;
    }
    if (_NewSize == 0) {
      return (void *)0x0;
    }
    if (DAT_00423ef4 == 0) {
      return (void *)0x0;
    }
    (*(code *)s_R6009___not_enough_space_for_env_0041c001._31_4_)(uVar2);
    uVar2 = uVar2 + 1000;
    if (DAT_00423ef4 < uVar2) {
      uVar2 = 0xffffffff;
    }
  } while (uVar2 != 0xffffffff);
  return (void *)0x0;
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
  uint *in_EAX;
  int iVar3;
  uint uVar4;
  undefined4 *puVar5;
  undefined4 uVar6;
  int *piVar7;
  int iVar8;
  byte bVar9;
  bool bVar10;
  longlong lVar11;
  undefined8 uVar12;
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
  
  bVar10 = (param_3 & 0x80) == 0;
  local_24 = 0;
  local_6 = 0;
  local_38 = 0xc;
  local_34 = 0;
  if (bVar10) {
    local_5 = 0;
  }
  else {
    local_5 = 0x10;
  }
  local_30 = (uint)bVar10;
  iVar3 = func_0x819937fc(&local_24);
  if (iVar3 != 0) {
    func_0xf9f4370b(0,0,0,0,0);
  }
  if (((param_3 & 0x8000) == 0) && (((param_3 & 0x74000) != 0 || (local_24 != 0x8000)))) {
    local_5 = local_5 | 0x80;
  }
  uVar4 = param_3 & 3;
  if (uVar4 == 0) {
    local_c = 0x80000000;
  }
  else {
    if (uVar4 == 1) {
      if (((param_3 & 8) == 0) || ((param_3 & 0x70000) == 0)) {
        local_c = 0x40000000;
        goto LAB_0041373a;
      }
    }
    else if (uVar4 != 2) goto LAB_004136f6;
    local_c = 0xc0000000;
  }
LAB_0041373a:
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
    if (param_4 != 0x80) goto LAB_004136f6;
    local_14 = (uint)(local_c == 0x80000000);
  }
  uVar4 = param_3 & 0x700;
  if (uVar4 < 0x401) {
    if ((uVar4 == 0x400) || (uVar4 == 0)) {
      local_18 = 3;
    }
    else if (uVar4 == 0x100) {
      local_18 = 4;
    }
    else {
      if (uVar4 == 0x200) goto LAB_0041383f;
      if (uVar4 != 0x300) goto LAB_004136f6;
      local_18 = 2;
    }
  }
  else {
    if (uVar4 != 0x500) {
      if (uVar4 == 0x600) {
LAB_0041383f:
        local_18 = 5;
        goto LAB_004137ee;
      }
      if (uVar4 != 0x700) {
LAB_004136f6:
        puVar5 = (undefined4 *)func_0x9cf63749();
        *puVar5 = 0;
        *in_EAX = 0xffffffff;
        puVar5 = (undefined4 *)func_0x89f63753();
        *puVar5 = 0x16;
        func_0x21f63762(0,0,0,0,0);
                    // WARNING: Bad instruction - Truncating control flow here
        halt_baddata();
      }
    }
    local_18 = 1;
  }
LAB_004137ee:
  local_10 = 0x80;
  if (((param_3 & 0x100) != 0) && (-1 < (char)(~(byte)DAT_00423958 & param_5))) {
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
  uVar4 = func_0x5e7839a6();
  *in_EAX = uVar4;
  uVar6 = s_R6008___not_enough_space_for_arg_0041c02d._7_4_;
  if (uVar4 == 0xffffffff) {
    puVar5 = (undefined4 *)func_0x9cf638b2();
    *puVar5 = 0;
    *in_EAX = 0xffffffff;
    puVar5 = (undefined4 *)func_0x89f638bc();
    *puVar5 = 0x18;
                    // WARNING: Bad instruction - Truncating control flow here
    halt_baddata();
  }
  *param_1 = 1;
  local_20 = (*(code *)uVar6)(param_2,local_c,local_14,&local_38,local_18,local_10,0);
  if (local_20 == -1) {
    if (((local_c & 0xc0000000) == 0xc0000000) && ((param_3 & 1) != 0)) {
      local_c = local_c & 0x7fffffff;
      local_20 = (*(code *)uVar6)(param_2,local_c,local_14,&local_38,local_18,local_10,0);
      if (local_20 != -1) goto LAB_00413913;
    }
    pbVar1 = (byte *)((&DAT_00425280)[(int)*in_EAX >> 5] + 4 + (*in_EAX & 0x1f) * 0x40);
    *pbVar1 = *pbVar1 & 0xfe;
    uVar6 = (*(code *)s_R6002___floating_point_support_n_0041c059._7_4_)();
    func_0xaff63954(uVar6);
LAB_00413907:
    func_0x89f6395a();
                    // WARNING: Bad instruction - Truncating control flow here
    halt_baddata();
  }
LAB_00413913:
  iVar3 = (*DAT_0041c154)(local_20);
  if (iVar3 == 0) {
    pbVar1 = (byte *)((&DAT_00425280)[(int)*in_EAX >> 5] + 4 + (*in_EAX & 0x1f) * 0x40);
    *pbVar1 = *pbVar1 & 0xfe;
    iVar3 = (*(code *)s_R6002___floating_point_support_n_0041c059._7_4_)();
    func_0xaff63997(iVar3);
    (*(code *)s_R6002___floating_point_support_n_0041c059._35_4_)(local_20);
    if (iVar3 == 0) {
      puVar5 = (undefined4 *)func_0x89f639aa();
      *puVar5 = 0xd;
    }
    goto LAB_00413907;
  }
  if (iVar3 == 2) {
    local_5 = local_5 | 0x40;
  }
  else if (iVar3 == 3) {
    local_5 = local_5 | 8;
  }
  func_0x19763ad0(*in_EAX,local_20);
  bVar9 = local_5 | 1;
  *(byte *)((&DAT_00425280)[(int)*in_EAX >> 5] + 4 + (*in_EAX & 0x1f) * 0x40) = bVar9;
  pbVar1 = (byte *)((&DAT_00425280)[(int)*in_EAX >> 5] + 0x24 + (*in_EAX & 0x1f) * 0x40);
  *pbVar1 = *pbVar1 & 0x80;
  local_7 = local_5 & 0x48;
  if (local_7 == 0) {
    bVar2 = local_5 & 0x80;
    local_5 = bVar9;
    if (bVar2 == 0) goto LAB_00413c88;
    if ((param_3 & 2) != 0) {
      local_1c = func_0x41233a37(*in_EAX,0xffffffff,2);
      if (local_1c == 0xffffffff) {
        piVar7 = (int *)func_0x9cf63a46();
        bVar9 = local_5;
        if (*piVar7 != 0x83) goto LAB_00413a00;
      }
      else {
        local_28 = 0;
        iVar3 = func_0xa6083a6a(*in_EAX,&local_28,1);
        if ((iVar3 == 0) && ((short)local_28 == 0x1a)) {
          iVar3 = func_0x0f973b85(*in_EAX,local_1c,(int)local_1c >> 0x1f);
          if (iVar3 == -1) goto LAB_00413a00;
        }
        iVar3 = func_0x41233a95(*in_EAX,0,0);
        bVar9 = local_5;
        if (iVar3 == -1) goto LAB_00413a00;
      }
    }
  }
  local_5 = bVar9;
  if ((local_5 & 0x80) == 0) goto LAB_00413c88;
  if ((param_3 & 0x74000) == 0) {
    if ((local_24 & 0x74000) == 0) {
      param_3 = param_3 | 0x4000;
    }
    else {
      param_3 = param_3 | local_24 & 0x74000;
    }
  }
  uVar4 = param_3 & 0x74000;
  if (uVar4 == 0x4000) {
    local_6 = 0;
  }
  else if ((uVar4 == 0x10000) || (uVar4 == 0x14000)) {
    if ((param_3 & 0x301) == 0x301) goto LAB_00413abd;
  }
  else if ((uVar4 == 0x20000) || (uVar4 == 0x24000)) {
LAB_00413abd:
    local_6 = 2;
  }
  else if ((uVar4 == 0x40000) || (uVar4 == 0x44000)) {
    local_6 = 1;
  }
  if (((param_3 & 0x70000) == 0) || (local_1c = 0, (local_5 & 0x40) != 0)) goto LAB_00413c88;
  uVar4 = local_c & 0xc0000000;
  if (uVar4 == 0x40000000) {
    if (local_18 == 0) goto LAB_00413c88;
    if (2 < local_18) {
      if (local_18 < 5) {
        lVar11 = func_0x7b743d22(*in_EAX,0,0,2);
        if (lVar11 != 0) {
          uVar12 = func_0x7b743d37(*in_EAX,0,0,0);
          uVar4 = (uint)uVar12 & (uint)((ulonglong)uVar12 >> 0x20);
          goto LAB_00413bee;
        }
      }
      else {
LAB_00413b19:
        if (local_18 != 5) goto LAB_00413c88;
      }
    }
LAB_00413b22:
    iVar3 = 0;
    if (local_6 == 1) {
      local_1c = 0x42e8c04e;
      local_18 = 3;
      do {
        iVar8 = __write(*in_EAX,(void *)((int)&local_1c + iVar3),local_18 - iVar3);
        if (iVar8 == -1) goto LAB_00413a00;
        iVar3 = iVar3 + iVar8;
      } while (iVar3 < (int)local_18);
    }
    else if (local_6 == 2) {
                    // WARNING: Bad instruction - Truncating control flow here
      halt_baddata();
    }
  }
  else {
    if (uVar4 != 0x80000000) {
      if ((uVar4 != 0xc0000000) || (local_18 == 0)) goto LAB_00413c88;
      if (2 < local_18) {
        if (4 < local_18) goto LAB_00413b19;
        lVar11 = func_0x7b743ca2(*in_EAX,0,0,2);
        if (lVar11 != 0) {
          lVar11 = func_0x7b743cb3(*in_EAX,0,0,0);
          if (lVar11 == -1) goto LAB_00413a00;
          goto LAB_00413b73;
        }
      }
      goto LAB_00413b22;
    }
LAB_00413b73:
    iVar3 = __read_nolock(*in_EAX,&local_1c,3);
    if (iVar3 == -1) goto LAB_00413a00;
    if (iVar3 == 2) {
LAB_00413bfc:
      if ((local_1c & 0xffff) == 0xfffe) {
        func_0x16103c60(*in_EAX);
        puVar5 = (undefined4 *)func_0x89f63c66();
        *puVar5 = 0x16;
                    // WARNING: Bad instruction - Truncating control flow here
        halt_baddata();
      }
      if ((local_1c & 0xffff) == 0xfeff) {
        iVar3 = func_0x41233c83(*in_EAX,2,0);
        if (iVar3 == -1) {
LAB_00413a00:
          func_0x16103a55(*in_EAX);
                    // WARNING: Bad instruction - Truncating control flow here
          halt_baddata();
        }
        local_6 = 2;
        goto LAB_00413c88;
      }
    }
    else if (iVar3 == 3) {
      if (local_1c == 0x87e7c04e) {
                    // WARNING: Bad instruction - Truncating control flow here
        halt_baddata();
      }
      goto LAB_00413bfc;
    }
    uVar4 = func_0x41233c9e(*in_EAX,0,0);
LAB_00413bee:
    if (uVar4 == 0xffffffff) {
                    // WARNING: Bad instruction - Truncating control flow here
      halt_baddata();
    }
  }
LAB_00413c88:
  uVar4 = local_c;
  pbVar1 = (byte *)((&DAT_00425280)[(int)*in_EAX >> 5] + 0x24 + (*in_EAX & 0x1f) * 0x40);
  *pbVar1 = *pbVar1 ^ (*pbVar1 ^ local_6) & 0x7f;
  pbVar1 = (byte *)((&DAT_00425280)[(int)*in_EAX >> 5] + 0x24 + (*in_EAX & 0x1f) * 0x40);
  *pbVar1 = (char)(param_3 >> 0x10) << 7 | *pbVar1 & 0x7f;
  if ((local_7 == 0) && ((param_3 & 8) != 0)) {
    pbVar1 = (byte *)((&DAT_00425280)[(int)*in_EAX >> 5] + 4 + (*in_EAX & 0x1f) * 0x40);
    *pbVar1 = *pbVar1 | 0x20;
  }
  if (((local_c & 0xc0000000) == 0xc0000000) && ((param_3 & 1) != 0)) {
    (*(code *)s_R6002___floating_point_support_n_0041c059._35_4_)(local_20);
    iVar3 = (*(code *)s_R6008___not_enough_space_for_arg_0041c02d._7_4_)
                      (param_2,uVar4 & 0x7fffffff,local_14,&local_38,3,local_10,0);
    if (iVar3 == -1) {
      uVar6 = (*(code *)s_R6002___floating_point_support_n_0041c059._7_4_)();
      func_0xaff63d95(uVar6);
      pbVar1 = (byte *)((&DAT_00425280)[(int)*in_EAX >> 5] + 4 + (*in_EAX & 0x1f) * 0x40);
      *pbVar1 = *pbVar1 & 0xfe;
      func_0x9a763eb7(*in_EAX);
                    // WARNING: Bad instruction - Truncating control flow here
      halt_baddata();
    }
    *(int *)((*in_EAX & 0x1f) * 0x40 + (&DAT_00425280)[(int)*in_EAX >> 5]) = iVar3;
  }
  return 0;
}



void __cdecl
FUN_00413e59(undefined4 param_1,undefined4 param_2,undefined4 param_3,undefined4 param_4,
            undefined4 param_5)

{
  func_0x846e3fc2(param_2,param_3,param_4,param_5,param_1,1);
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
      puVar6 = (undefined4 *)func_0x89f63eeb();
      *puVar6 = 0x16;
      func_0x21f63efb(0,0,0,0,0);
                    // WARNING: Bad instruction - Truncating control flow here
      halt_baddata();
    }
    func_0x92e83f1a(_Locale);
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
        uVar3 = func_0xba99406e(*_Str1,local_14);
        uVar8 = (uint)uVar3;
        uVar4 = func_0xba99407e(*_Str2,local_14);
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
  
  if (DAT_00423cc4 == 0) {
    iVar3 = 0;
    if (_MaxCount != 0) {
      if ((_Str1 == (wchar_t *)0x0) || (_Str2 == (wchar_t *)0x0)) {
        puVar4 = (undefined4 *)func_0x89f63fd9();
        *puVar4 = 0x16;
        func_0x21f63fe9(0,0,0,0,0);
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
    iVar3 = func_0x706f4150(_Str1,_Str2,_MaxCount,0);
  }
  return iVar3;
}



// Library Function - Single Match
//  _wcsncmp
// 
// Library: Visual Studio 2008 Release

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



// WARNING: Globals starting with '_' overlap smaller symbols at the same address

void __cdecl FUN_00414040(undefined4 param_1)

{
  _DAT_00423efc = param_1;
  return;
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



// WARNING: Instruction at (ram,0x004141b8) overlaps instruction at (ram,0x004141b6)
// 
// WARNING: Control flow encountered bad instruction data

uint __fastcall FUN_00414144(undefined4 param_1,undefined param_2,undefined4 param_3)

{
  void *pvVar1;
  int iVar2;
  int unaff_ESI;
  undefined4 local_14;
  undefined *puStack_10;
  uint local_c;
  undefined4 local_8;
  
  pvVar1 = ExceptionList;
  local_8 = 0xfffffffe;
  puStack_10 = &DAT_0040d3a0;
  local_c = s__Repeat_del___s__if_exist___s__g_00422037._13_4_ ^ 0x420a60;
  ExceptionList = &local_14;
  if (unaff_ESI != 1) {
                    // WARNING: Bad instruction - Truncating control flow here
    halt_baddata();
  }
  local_14._0_1_ = (char)pvVar1;
  local_14 = (void *)CONCAT31((int3)((uint)pvVar1 >> 8),
                              (char)local_14 + (char)ExceptionList * '\x02' +
                              (char)((uint)param_1 >> 8));
  iVar2 = func_0xab7142d8();
  if (iVar2 != 0) {
    iVar2 = func_0xeb7142f2(0x400000);
    if (iVar2 != 0) {
      ExceptionList = local_14;
      return ~(*(uint *)(iVar2 + 0x24) >> 0x1f) & 1;
    }
  }
  ExceptionList = local_14;
  return 0;
}



// Library Function - Single Match
//  __global_unwind2
// 
// Library: Visual Studio

void __cdecl __global_unwind2(undefined4 param_1)

{
  func_0xafa3436a(param_1,0x414218,0,0,&stack0xfffffffc);
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
  uStack_1c = 0x414220;
  local_20 = ExceptionList;
  uVar2 = s__Repeat_del___s__if_exist___s__g_00422037._13_4_ ^ (uint)&local_20;
  ExceptionList = &local_20;
  while( true ) {
    uVar1 = *(uint *)(param_1 + 0xc);
    if ((uVar1 == 0xffffffff) || ((param_2 != 0xffffffff && (uVar1 <= param_2)))) break;
    local_18 = *(undefined4 *)(*(int *)(param_1 + 8) + uVar1 * 0xc);
    *(undefined4 *)(param_1 + 0xc) = local_18;
    if (*(int *)(*(int *)(param_1 + 8) + 4 + uVar1 * 0xc) == 0) {
      func_0x1074441e(0x101,uVar2);
      func_0x2f744427();
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
  
  _DAT_004237f8 = _DAT_004237f8 + 1;
  pcVar1 = (char *)func_0xe665449e(0x1000);
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
  iVar2 = func_0x207744f0(_FileHandle);
  if (iVar2 == -1) {
    puVar3 = (undefined4 *)func_0x89f643fd();
    *puVar3 = 9;
LAB_004143b5:
    iVar2 = -1;
    local_8 = 0xffffffff;
  }
  else {
    iVar2 = (*(code *)s_R6002___floating_point_support_n_0041c059._15_4_)
                      (iVar2,in_stack_00000008,&local_8,_Offset._4_4_);
    if (iVar2 == -1) {
      iVar4 = (*(code *)s_R6002___floating_point_support_n_0041c059._7_4_)();
      if (iVar4 != 0) {
        func_0xaff64431(iVar4);
        goto LAB_004143b5;
      }
    }
    pbVar1 = (byte *)((&DAT_00425280)[_FileHandle >> 5] + 4 + (_FileHandle & 0x1fU) * 0x40);
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
  
  if ((-1 < param_1) && ((uint)param_1 < DAT_00425278)) {
    iVar2 = (param_1 & 0x1fU) * 0x40;
    if (*(int *)(iVar2 + (&DAT_00425280)[param_1 >> 5]) == -1) {
      if (s__Repeat_del___s__if_exist___s__g_00422037._9_4_ == 1) {
        if (param_1 == 0) {
          uVar3 = 0xfffffff6;
        }
        else if (param_1 == 1) {
          uVar3 = 0xfffffff5;
        }
        else {
          if (param_1 != 2) goto LAB_0041457f;
          uVar3 = 0xfffffff4;
        }
        (*(code *)s_<program_name_unknown>_0041c0b9._15_4_)(uVar3,param_2);
      }
LAB_0041457f:
      *(intptr_t *)(iVar2 + (&DAT_00425280)[param_1 >> 5]) = param_2;
      return 0;
    }
  }
  puVar1 = (undefined4 *)func_0x89f645dc();
  *puVar1 = 9;
  puVar1 = (undefined4 *)func_0x9cf645e7();
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
  
  if ((-1 < param_1) && ((uint)param_1 < DAT_00425278)) {
    iVar3 = (param_1 & 0x1fU) * 0x40;
    piVar1 = (int *)((&DAT_00425280)[param_1 >> 5] + iVar3);
    if (((*(byte *)(piVar1 + 1) & 1) != 0) && (*piVar1 != -1)) {
      if (s__Repeat_del___s__if_exist___s__g_00422037._9_4_ == 1) {
        if (param_1 == 0) {
          uVar4 = 0xfffffff6;
        }
        else if (param_1 == 1) {
          uVar4 = 0xfffffff5;
        }
        else {
          if (param_1 != 2) goto LAB_00414605;
          uVar4 = 0xfffffff4;
        }
        (*(code *)s_<program_name_unknown>_0041c0b9._15_4_)(uVar4,0);
      }
LAB_00414605:
      *(undefined4 *)(iVar3 + (&DAT_00425280)[param_1 >> 5]) = 0xffffffff;
      return 0;
    }
  }
  puVar2 = (undefined4 *)func_0x89f64662();
  *puVar2 = 9;
  puVar2 = (undefined4 *)func_0x9cf6466d();
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
    puVar1 = (undefined4 *)func_0x9cf64689();
    *puVar1 = 0;
    puVar1 = (undefined4 *)func_0x89f64691();
    *puVar1 = 9;
    return -1;
  }
  if (((_FileHandle < 0) || (DAT_00425278 <= (uint)_FileHandle)) ||
     (piVar2 = (intptr_t *)((_FileHandle & 0x1fU) * 0x40 + (&DAT_00425280)[_FileHandle >> 5]),
     (*(byte *)(piVar2 + 1) & 1) == 0)) {
    puVar1 = (undefined4 *)func_0x9cf646ca();
    *puVar1 = 0;
    puVar1 = (undefined4 *)func_0x89f646d1();
    *puVar1 = 9;
    func_0x21f646e1(0,0,0,0,0);
    iVar3 = -1;
  }
  else {
    iVar3 = *piVar2;
  }
  return iVar3;
}



void __cdecl FUN_00414740(uint param_1)

{
  (*DAT_0041c138)((&DAT_00425280)[(int)param_1 >> 5] + 0xc + (param_1 & 0x1f) * 0x40);
  return;
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
      func_0xf8794adc(param_1,param_3 - uVar2);
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
    func_0x4f7a4b28(param_1 + iVar3,0,param_3 - iVar3);
  }
  return param_1;
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
    puVar1 = (undefined4 *)func_0x89f64d5f();
    *puVar1 = 9;
    return 0;
  }
  if ((_FileHandle < 0) || (DAT_00425278 <= (uint)_FileHandle)) {
    puVar1 = (undefined4 *)func_0x89f64d7d();
    *puVar1 = 9;
    func_0x21f64d8d(0,0,0,0,0);
    uVar2 = 0;
  }
  else {
    uVar2 = (int)*(char *)((&DAT_00425280)[_FileHandle >> 5] + 4 + (_FileHandle & 0x1fU) * 0x40) &
            0x40;
  }
  return uVar2;
}



// WARNING: Globals starting with '_' overlap smaller symbols at the same address
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
  
  local_8 = s__Repeat_del___s__if_exist___s__g_00422037._13_4_ ^ (uint)&stack0xfffffffc;
  if (DAT_00422de0 != 0) {
    if (DAT_00422f24 == -2) {
      func_0x6f9a4edc();
    }
    if (DAT_00422f24 == -1) goto LAB_00414e0f;
    iVar2 = (*DAT_0041c0b4)(DAT_00422f24,&_WCh,1,local_14,0);
    if (iVar2 != 0) {
      DAT_00422de0 = 1;
      goto LAB_00414e0f;
    }
    if ((DAT_00422de0 != 2) ||
       (iVar2 = (*(code *)s_R6002___floating_point_support_n_0041c059._7_4_)(), iVar2 != 0x78))
    goto LAB_00414e0f;
    DAT_00422de0 = 0;
  }
  uVar3 = (*_DAT_0041c0b8)(0,&_WCh,1,local_10,5,0,0);
  uVar3 = (*(code *)s_R6002___floating_point_support_n_0041c059._31_4_)(uVar3);
  if (DAT_00422f24 != -1) {
    (*(code *)s_<program_name_unknown>_0041c0b9._3_4_)(DAT_00422f24,local_10,uVar3,local_14,0);
  }
LAB_00414e0f:
  wVar1 = func_0xf1d64e68();
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
      func_0x92e84eaf(_Locale);
      if (*(int *)(local_14[0] + 0x14) == 0) {
        if (_DstCh != (wchar_t *)0x0) {
          *_DstCh = (ushort)(byte)*_SrcCh;
        }
LAB_00414e77:
        if (local_8 != '\0') {
          *(uint *)(local_c + 0x70) = *(uint *)(local_c + 0x70) & 0xfffffffd;
        }
        return 1;
      }
      iVar1 = func_0x50804fe3(*_SrcCh,local_14);
      if (iVar1 == 0) {
        iVar1 = (*(code *)s_R6008___not_enough_space_for_arg_0041c02d._31_4_)
                          (*(undefined4 *)(local_14[0] + 4),9,_SrcCh,1,_DstCh,
                           _DstCh != (wchar_t *)0x0);
        if (iVar1 != 0) goto LAB_00414e77;
      }
      else {
        iVar1 = *(int *)(local_14[0] + 0xac);
        if ((((1 < iVar1) && (iVar1 <= (int)_SrcSizeInBytes)) &&
            (iVar1 = (*(code *)s_R6008___not_enough_space_for_arg_0041c02d._31_4_)
                               (*(undefined4 *)(local_14[0] + 4),9,_SrcCh,iVar1,_DstCh,
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
      puVar2 = (undefined4 *)func_0x89f64f4c();
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



void __cdecl FUN_00414f3f(undefined4 param_1,undefined4 param_2,undefined4 param_3)

{
  func_0x1f7f50a2(param_1,param_2,param_3,0);
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
  
  func_0x92e84fba(_Locale);
  uVar1 = *(ushort *)(*(int *)(local_14 + 200) + (_C & 0xffU) * 2);
  if (local_8 != '\0') {
    *(uint *)(local_c + 0x70) = *(uint *)(local_c + 0x70) & 0xfffffffd;
  }
  return uVar1 & 0x8000;
}



void __cdecl FUN_00414f91(undefined4 param_1)

{
  func_0x508050ee(param_1,0);
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

void __cdecl FUN_00415085(undefined4 param_1)

{
  _DAT_00423f0c = param_1;
  _DAT_00423f10 = param_1;
  _DAT_00423f14 = param_1;
  _DAT_00423f18 = param_1;
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
  } while (uVar1 < DAT_00422dbc * 0xc + param_3);
  if ((DAT_00422dbc * 0xc + param_3 <= uVar1) || (*(int *)(uVar1 + 4) != param_2)) {
    uVar1 = 0;
  }
  return uVar1;
}



// WARNING: Globals starting with '_' overlap smaller symbols at the same address

void __cdecl FUN_00415297(undefined4 param_1)

{
  _DAT_00423f20 = param_1;
  return;
}



// WARNING: Globals starting with '_' overlap smaller symbols at the same address

void __cdecl FUN_004152a6(undefined4 param_1)

{
  _DAT_00423f2c = param_1;
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
  code *pcVar5;
  code *pcVar6;
  undefined local_18 [8];
  byte local_10;
  undefined local_c [4];
  int local_8;
  
  iVar1 = func_0x44f75313();
  local_8 = 0;
  if (DAT_00423f30 == 0) {
    iVar2 = (*(code *)s_Microsoft_Visual_C___Runtime_Lib_0041c089._19_4_)(s_October_0041cb95 + 3);
    pcVar5 = DAT_0041c110;
    if (iVar2 == 0) {
      return 0;
    }
    iVar3 = (*DAT_0041c110)(iVar2,s_November_0041cb89 + 3);
    if (iVar3 == 0) {
      return 0;
    }
    DAT_00423f30 = func_0xd2f65357(iVar3);
    uVar4 = (*pcVar5)(iVar2,&DAT_0041cb7c);
    DAT_00423f34 = func_0xd2f6536c(uVar4);
    uVar4 = (*pcVar5)(iVar2,s_dddd__MMMM_dd__yyyy_0041cb55 + 0x13);
    DAT_00423f38 = func_0xd2f65381(uVar4);
    uVar4 = (*pcVar5)(iVar2,s_mm_ss_0041cb4c);
    DAT_00423f40 = func_0xd2f65396(uVar4);
    if (DAT_00423f40 != 0) {
      uVar4 = (*pcVar5)(iVar2,&DAT_0041cb34);
      DAT_00423f3c = func_0xd2f653ae(uVar4);
    }
  }
  if ((DAT_00423f3c != iVar1) && (DAT_00423f40 != iVar1)) {
    pcVar5 = (code *)func_0x4df753cb(DAT_00423f3c);
    pcVar6 = (code *)func_0x4df753d8(DAT_00423f40);
    if (((pcVar5 != (code *)0x0) && (pcVar6 != (code *)0x0)) &&
       (((iVar2 = (*pcVar5)(), iVar2 == 0 ||
         (iVar2 = (*pcVar6)(iVar2,1,local_18,0xc,local_c), iVar2 == 0)) || ((local_10 & 1) == 0))))
    {
      _UType = _UType | 0x200000;
      goto LAB_004153f7;
    }
  }
  if ((((DAT_00423f34 != iVar1) &&
       (pcVar5 = (code *)func_0x4df7541b(DAT_00423f34), pcVar5 != (code *)0x0)) &&
      (local_8 = (*pcVar5)(), local_8 != 0)) &&
     ((DAT_00423f38 != iVar1 &&
      (pcVar5 = (code *)func_0x4df75438(DAT_00423f38), pcVar5 != (code *)0x0)))) {
    local_8 = (*pcVar5)(local_8);
  }
LAB_004153f7:
  pcVar5 = (code *)func_0x4df75450(DAT_00423f30);
  if (pcVar5 == (code *)0x0) {
    return 0;
  }
  iVar1 = (*pcVar5)(local_8,_LpText,_LpCaption,_UType);
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
LAB_00415444:
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
          puVar2 = (undefined4 *)func_0x89f65518();
          eVar5 = 0x22;
          *puVar2 = 0x22;
          goto LAB_00415455;
        }
        *_Dst = '\0';
      }
    }
  }
  else if (_Dst != (char *)0x0) goto LAB_00415444;
  puVar2 = (undefined4 *)func_0x89f6549e();
  eVar5 = 0x16;
  *puVar2 = 0x16;
LAB_00415455:
  func_0x21f654ad(0,0,0,0,0);
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
      iVar2 = DAT_004234b8;
      DAT_004234b8 = _Mode;
      return iVar2;
    }
    if (_Mode == 3) {
      return DAT_004234b8;
    }
  }
  puVar1 = (undefined4 *)func_0x89f65553();
  *puVar1 = 0x16;
  func_0x21f65563(0,0,0,0,0);
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
    puVar4 = (undefined4 *)func_0x89f655c4();
    *puVar4 = 0x16;
    func_0x21f655d3(0,0,0,0,0);
    return 0x16;
  }
  func_0x92e855e5(_Locale);
  if (*(int *)(local_14 + 0x14) == 0) {
    if ((ushort)_WCh < 0x100) {
      if (pcVar2 != (char *)0x0) {
        if (sVar3 == 0) goto LAB_004155ef;
        *pcVar2 = (char)_WCh;
      }
      if (_SizeConverted != (int *)0x0) {
        *_SizeConverted = 1;
      }
LAB_0041562a:
      if (local_8 == '\0') {
                    // WARNING: Bad instruction - Truncating control flow here
        halt_baddata();
      }
      *(uint *)(local_c + 0x70) = *(uint *)(local_c + 0x70) & 0xfffffffd;
                    // WARNING: Bad instruction - Truncating control flow here
      halt_baddata();
    }
    if ((pcVar2 != (char *)0x0) && (sVar3 != 0)) {
      func_0x9c0f560f(pcVar2,0,sVar3);
    }
  }
  else {
    _MbCh = (char *)0x0;
    iVar6 = (*(code *)s_R6002___floating_point_support_n_0041c059._31_4_)
                      (*(undefined4 *)(local_14 + 4),0,&_WCh,1,pcVar2,sVar3,0,&_MbCh);
    if (iVar6 == 0) {
      iVar6 = (*(code *)s_R6002___floating_point_support_n_0041c059._7_4_)();
      if (iVar6 == 0x7a) {
        if ((pcVar2 != (char *)0x0) && (sVar3 != 0)) {
          func_0x9c0f56e6(pcVar2,0,sVar3);
                    // WARNING: Bad instruction - Truncating control flow here
          halt_baddata();
        }
LAB_004155ef:
        puVar4 = (undefined4 *)func_0x89f65642();
        *puVar4 = 0x22;
        func_0x21f65651(0,0,0,0,0);
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
      goto LAB_0041562a;
    }
  }
  puVar4 = (undefined4 *)func_0x89f65617();
  *puVar4 = 0x2a;
  peVar5 = (errno_t *)func_0x89f65622();
  eVar1 = *peVar5;
  if (local_8 != '\0') {
    *(uint *)(local_c + 0x70) = *(uint *)(local_c + 0x70) & 0xfffffffd;
  }
  return eVar1;
}



void __cdecl
FUN_004156a0(undefined4 param_1,undefined4 param_2,undefined4 param_3,undefined4 param_4)

{
  func_0x2b865806(param_1,param_2,param_3,param_4,0);
  return;
}



void __cdecl FUN_004156bd(int param_1)

{
  if ((param_1 != 0) && (*(int *)(param_1 + -8) == 0xdddd)) {
    func_0x42ec5728((int *)(param_1 + -8));
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
  undefined4 uVar3;
  int iVar4;
  char *pcVar5;
  uint uVar6;
  localeinfo_struct **pplVar7;
  char **ppcVar8;
  int *in_ECX;
  char *pcVar9;
  char *pcStack_4c;
  char **ppcStack_48;
  char **ppcStack_44;
  uint uStack_40;
  localeinfo_struct *plStack_3c;
  ulong uStack_38;
  char *pcStack_34;
  char **ppcStack_30;
  int iStack_2c;
  localeinfo_struct *plStack_28;
  int local_14;
  localeinfo_struct **local_10;
  uint local_c;
  uint local_8;
  
  local_8 = s__Repeat_del___s__if_exist___s__g_00422037._13_4_ ^ (uint)&stack0xfffffffc;
  if (DAT_00423f48 == 0) {
    plStack_28 = (localeinfo_struct *)0x0;
    iStack_2c = 0;
    ppcStack_30 = (char **)0x1;
    pcStack_34 = s_September_0041cb9d + 7;
    uStack_38 = 0x100;
    plStack_3c = (localeinfo_struct *)0x0;
    uStack_40 = 0x415715;
    iVar4 = (*(code *)s_Microsoft_Visual_C___Runtime_Lib_0041c089._11_4_)();
    if (iVar4 == 0) {
      plStack_28 = (localeinfo_struct *)0x415727;
      iVar4 = (*(code *)s_R6002___floating_point_support_n_0041c059._7_4_)();
      if (iVar4 == 0x78) {
        DAT_00423f48 = 2;
      }
    }
    else {
      DAT_00423f48 = 1;
    }
  }
  uVar3 = s_R6008___not_enough_space_for_arg_0041c02d._31_4_;
  pcVar5 = (char *)param_3;
  pcVar9 = param_4;
  if (0 < (int)param_4) {
    do {
      pcVar9 = pcVar9 + -1;
      if (*pcVar5 == '\0') goto LAB_0041574e;
      pcVar5 = pcVar5 + 1;
    } while (pcVar9 != (char *)0x0);
    pcVar9 = (char *)0xffffffff;
LAB_0041574e:
    pcVar5 = param_4 + -(int)pcVar9;
    bVar2 = (int)(pcVar5 + -1) < (int)param_4;
    param_4 = pcVar5 + -1;
    if (bVar2) {
      param_4 = pcVar5;
    }
  }
  if ((DAT_00423f48 == 2) || (DAT_00423f48 == 0)) {
    local_10 = (localeinfo_struct **)0x0;
    local_14 = 0;
    if (param_1 == (localeinfo_struct *)0x0) {
      param_1 = *(localeinfo_struct **)(*in_ECX + 0x14);
    }
    if (param_7 == 0) {
      param_7 = *(int *)(*in_ECX + 4);
    }
    plStack_28 = param_1;
    iStack_2c = 0x41593f;
    iVar4 = func_0x5a9c5a8d();
    if (iVar4 == -1) {
      return;
    }
    if (iVar4 != param_7) {
      plStack_28 = (localeinfo_struct *)0x0;
      iStack_2c = 0;
      ppcStack_30 = &param_4;
      pcStack_34 = (char *)param_3;
      plStack_3c = (localeinfo_struct *)param_7;
      uStack_40 = 0x41596a;
      uStack_38 = iVar4;
      local_10 = (localeinfo_struct **)func_0xa39c5ab8();
      uVar3 = s_Microsoft_Visual_C___Runtime_Lib_0041c089._15_4_;
      if (local_10 == (localeinfo_struct **)0x0) {
        return;
      }
      plStack_28 = (localeinfo_struct *)0x0;
      iStack_2c = 0;
      ppcStack_30 = (char **)param_4;
      uStack_38 = param_2;
      plStack_3c = param_1;
      uStack_40 = 0x415988;
      pcStack_34 = (char *)local_10;
      local_c = (*(code *)s_Microsoft_Visual_C___Runtime_Lib_0041c089._15_4_)();
      if (local_c != 0) {
        if (((int)local_c < 1) || (0xffffffe0 < local_c)) {
          ppcVar8 = (char **)0x0;
        }
        else {
          uStack_40 = local_c + 8;
          if (uStack_40 < 0x401) {
            uStack_40 = 0x4159ac;
            func_0x5b9e5afa();
            if (&stack0x00000000 == (undefined *)0x3c) {
              return;
            }
            plStack_3c = (localeinfo_struct *)0xcccc;
            ppcVar8 = &pcStack_34;
          }
          else {
            ppcStack_44 = (char **)0x4159c3;
            ppcVar8 = (char **)func_0xe1e65a11();
            if (ppcVar8 != (char **)0x0) {
              *ppcVar8 = (char *)0xdddd;
              ppcVar8 = ppcVar8 + 2;
            }
          }
        }
        if (ppcVar8 != (char **)0x0) {
          uStack_40 = local_c;
          ppcStack_44 = (char **)0x0;
          pcStack_4c = (char *)0x4159e5;
          ppcStack_48 = ppcVar8;
          func_0x9c0f5a33();
          uStack_40 = local_c;
          ppcStack_48 = (char **)param_4;
          pcStack_4c = (char *)local_10;
          ppcStack_44 = ppcVar8;
          local_c = (*(code *)uVar3)();
          if (local_c != 0) {
            local_14 = func_0xa39c5b69(iVar4,param_7,ppcVar8,&local_c,param_5,param_6);
          }
          func_0xb4875b7e(ppcVar8);
          goto LAB_00415a4d;
        }
      }
                    // WARNING: Bad instruction - Truncating control flow here
      halt_baddata();
    }
    plStack_28 = (localeinfo_struct *)param_6;
    iStack_2c = param_5;
    ppcStack_30 = (char **)param_4;
    pcStack_34 = (char *)param_3;
    uStack_38 = param_2;
    plStack_3c = param_1;
    uStack_40 = 0x415a4b;
    (*(code *)s_Microsoft_Visual_C___Runtime_Lib_0041c089._15_4_)();
LAB_00415a4d:
    if (local_10 != (localeinfo_struct **)0x0) {
      func_0x42ec5aa8(local_10);
    }
    if ((local_14 != 0) && (param_5 != local_14)) {
      func_0x42ec5abb(local_14);
    }
    iVar4 = func_0xf1d65ace();
    return iVar4;
  }
  if (DAT_00423f48 != 1) {
    return;
  }
  local_c = 0;
  if (param_7 == 0) {
    param_7 = *(int *)(*in_ECX + 4);
  }
  plStack_28 = (localeinfo_struct *)0x0;
  iStack_2c = 0;
  ppcStack_30 = (char **)param_4;
  pcStack_34 = (char *)param_3;
  uStack_38 = (uint)(param_8 != 0) * 8 + 1;
  plStack_3c = (localeinfo_struct *)param_7;
  uStack_40 = 0x4157af;
  uVar6 = (*(code *)s_R6008___not_enough_space_for_arg_0041c02d._31_4_)();
  if (uVar6 == 0) {
    return;
  }
  if (((int)uVar6 < 1) || (0xffffffe0 / uVar6 < 2)) {
    local_10 = (localeinfo_struct **)0x0;
  }
  else {
    uStack_40 = uVar6 * 2 + 8;
    if (uStack_40 < 0x401) {
      uStack_40 = 0x4157d7;
      pplVar7 = &plStack_3c;
      func_0x5b9e5925();
      local_10 = &plStack_3c;
      if (&stack0x00000000 != (undefined *)0x3c) {
        plStack_3c = (localeinfo_struct *)0xcccc;
LAB_004157f6:
        local_10 = pplVar7 + 2;
      }
    }
    else {
      ppcStack_44 = (char **)0x4157eb;
      pplVar7 = (localeinfo_struct **)func_0xe1e65839();
      local_10 = pplVar7;
      if (pplVar7 != (localeinfo_struct **)0x0) {
        *pplVar7 = (localeinfo_struct *)0xdddd;
        goto LAB_004157f6;
      }
    }
  }
  if (local_10 == (localeinfo_struct **)0x0) {
                    // WARNING: Bad instruction - Truncating control flow here
    halt_baddata();
  }
  ppcStack_44 = (char **)local_10;
  ppcStack_48 = (char **)param_4;
  pcStack_4c = (char *)param_3;
  uStack_40 = uVar6;
  iVar4 = (*(code *)uVar3)();
  uVar3 = s_Microsoft_Visual_C___Runtime_Lib_0041c089._11_4_;
  if ((iVar4 != 0) &&
     (local_c = (*(code *)s_Microsoft_Visual_C___Runtime_Lib_0041c089._11_4_)
                          (param_1,param_2,local_10,uVar6,0,0), local_c != 0)) {
    if ((param_2 & 0x400) == 0) {
      if (((int)local_c < 1) || (0xffffffe0 / local_c < 2)) {
        ppcVar8 = (char **)0x0;
      }
      else {
        uVar1 = local_c * 2 + 8;
        if (uVar1 < 0x401) {
          func_0x5b9e59e4();
          if (&stack0x00000000 == (undefined *)0x54) goto LAB_00415906;
          ppcVar8 = &pcStack_4c;
        }
        else {
          ppcVar8 = (char **)func_0xe1e658fb(uVar1);
          if (ppcVar8 != (char **)0x0) {
            *ppcVar8 = (char *)0xdddd;
            ppcVar8 = ppcVar8 + 2;
          }
        }
      }
      if (ppcVar8 != (char **)0x0) {
        iVar4 = (*(code *)s_Microsoft_Visual_C___Runtime_Lib_0041c089._11_4_)
                          (param_1,param_2,local_10,uVar6,ppcVar8,local_c);
        if (iVar4 != 0) {
          iVar4 = param_5;
          pcVar5 = param_6;
          if (param_6 == (char *)0x0) {
            iVar4 = 0;
            pcVar5 = (char *)0x0;
          }
          local_c = (*(code *)s_R6002___floating_point_support_n_0041c059._31_4_)
                              (param_7,0,ppcVar8,local_c,iVar4,pcVar5,0,0);
        }
        func_0xb4875a53(ppcVar8);
      }
    }
    else if ((param_6 != (char *)0x0) && ((int)local_c <= (int)param_6)) {
      (*(code *)uVar3)(param_1,param_2,local_10,uVar6,param_5,param_6);
                    // WARNING: Bad instruction - Truncating control flow here
      halt_baddata();
    }
  }
LAB_00415906:
  func_0xb4875a5c(local_10);
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
  
  func_0x92e85ae3(_Plocinfo);
  iVar1 = func_0xd4875c03(_LocaleName,_DwMapFlag,_LpSrcStr,_CchSrc,_LpDestStr,_CchDest,_Code_page,
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
  undefined4 uVar2;
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
  
  local_8 = s__Repeat_del___s__if_exist___s__g_00422037._13_4_ ^ (uint)&stack0xfffffffc;
  local_c = in_ECX;
  if (DAT_00423f4c == 0) {
    ppiStack_1c = &local_c;
    pcStack_20 = (char *)0x1;
    ppcStack_24 = (char **)(s_September_0041cb9d + 7);
    plStack_28 = (localeinfo_struct *)0x1;
    puStack_2c = (ushort *)0x415afc;
    iVar3 = (*(code *)s_Microsoft_Visual_C___Runtime_Lib_0041c089._3_4_)();
    if (iVar3 == 0) {
      ppiStack_1c = (int **)0x415b0e;
      iVar3 = (*(code *)s_R6002___floating_point_support_n_0041c059._7_4_)();
      if (iVar3 == 0x78) {
        ppiStack_1c = (int **)0x2;
        DAT_00423f4c = 2;
      }
      goto LAB_00415b22;
    }
    DAT_00423f4c = 1;
  }
  else {
LAB_00415b22:
    if ((DAT_00423f4c == 2) || (DAT_00423f4c == 0)) {
      puVar8 = (ushort *)0x0;
      if (param_6 == 0) {
        param_6 = *(int *)(*in_ECX + 0x14);
      }
      if (param_5 == (ushort *)0x0) {
        param_5 = *(ushort **)(*in_ECX + 4);
      }
      ppiStack_1c = (int **)param_6;
      pcStack_20 = (char *)0x415c1e;
      puVar6 = (ushort *)func_0x5a9c5d6c();
      if (puVar6 != (ushort *)0xffffffff) {
        if (puVar6 != param_5) {
          ppiStack_1c = (int **)0x0;
          pcStack_20 = (char *)0x0;
          ppcStack_24 = &param_3;
          plStack_28 = (localeinfo_struct *)param_2;
          puStack_30 = param_5;
          puStack_2c = puVar6;
          puVar8 = (ushort *)func_0xa39c5d8d();
          param_2 = (ulong)puVar8;
          if (puVar8 == (ushort *)0x0) goto LAB_00415c6f;
        }
        ppiStack_1c = (int **)param_4;
        pcStack_20 = param_3;
        ppcStack_24 = (char **)param_2;
        plStack_28 = param_1;
        puStack_2c = (ushort *)param_6;
        puStack_30 = (ushort *)0x415c60;
        (*(code *)s_Microsoft_Visual_C___Runtime_Lib_0041c089._7_4_)();
        if (puVar8 != (ushort *)0x0) {
          puStack_30 = puVar8;
          func_0x42ec5cba();
        }
      }
      goto LAB_00415c6f;
    }
    if (DAT_00423f4c != 1) goto LAB_00415c6f;
  }
  uVar2 = s_R6008___not_enough_space_for_arg_0041c02d._31_4_;
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
  uVar4 = (*(code *)s_R6008___not_enough_space_for_arg_0041c02d._31_4_)();
  if (uVar4 == 0) goto LAB_00415c6f;
  ppuVar7 = (ushort **)(undefined4 *)0x0;
  if ((0 < (int)uVar4) && (uVar4 < 0x7ffffff1)) {
    uVar1 = uVar4 * 2 + 8;
    if (uVar1 < 0x401) {
      ppuVar5 = &puStack_30;
      func_0x5b9e5ce1();
      ppuVar7 = &puStack_30;
      if (&stack0x00000000 != (undefined *)0x30) {
        puStack_30 = (ushort *)0xcccc;
LAB_00415bb2:
        ppuVar7 = ppuVar5 + 2;
      }
    }
    else {
      ppuVar5 = (ushort **)func_0xe1e65bf5(uVar1);
      ppuVar7 = ppuVar5;
      if (ppuVar5 != (ushort **)0x0) {
        *ppuVar5 = (ushort *)0xdddd;
        goto LAB_00415bb2;
      }
    }
  }
  if (ppuVar7 != (ushort **)0x0) {
    func_0x9c0f5c15(ppuVar7,0,uVar4 * 2);
    iVar3 = (*(code *)uVar2)(param_5,1,param_2,param_3,ppuVar7,uVar4);
    if (iVar3 != 0) {
      local_c = (int *)(*(code *)s_Microsoft_Visual_C___Runtime_Lib_0041c089._3_4_)
                                 (param_1,ppuVar7,iVar3,param_4);
    }
    func_0xb4875d42(ppuVar7);
  }
LAB_00415c6f:
  iVar3 = func_0xf1d65ccd();
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
  
  func_0x92e85ce2(_Plocinfo);
  BVar1 = func_0xbe8b5dff(_DWInfoType,_LpSrcStr,_CchSrc,_LpCharType,_Code_page,_BError,
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
    func_0x42ec5d2a(param_1[1]);
    func_0x42ec5d32(param_1[2]);
    func_0x42ec5d3a(param_1[3]);
    func_0x42ec5d42(param_1[4]);
    func_0x42ec5d4a(param_1[5]);
    func_0x42ec5d52(param_1[6]);
    func_0x42ec5d59(*param_1);
    func_0x42ec5d61(param_1[8]);
    func_0x42ec5d69(param_1[9]);
    func_0x42ec5d71(param_1[10]);
    func_0x42ec5d79(param_1[0xb]);
    func_0x42ec5d81(param_1[0xc]);
    func_0x42ec5d89(param_1[0xd]);
    func_0x42ec5d91(param_1[7]);
    func_0x42ec5d99(param_1[0xe]);
    func_0x42ec5da1(param_1[0xf]);
    func_0x42ec5dac(param_1[0x10]);
    func_0x42ec5db4(param_1[0x11]);
    func_0x42ec5dbc(param_1[0x12]);
    func_0x42ec5dc4(param_1[0x13]);
    func_0x42ec5dcc(param_1[0x14]);
    func_0x42ec5dd4(param_1[0x15]);
    func_0x42ec5ddc(param_1[0x16]);
    func_0x42ec5de4(param_1[0x17]);
    func_0x42ec5dec(param_1[0x18]);
    func_0x42ec5df4(param_1[0x19]);
    func_0x42ec5dfc(param_1[0x1a]);
    func_0x42ec5e04(param_1[0x1b]);
    func_0x42ec5e0c(param_1[0x1c]);
    func_0x42ec5e14(param_1[0x1d]);
    func_0x42ec5e1c(param_1[0x1e]);
    func_0x42ec5e24(param_1[0x1f]);
    func_0x42ec5e32(param_1[0x20]);
    func_0x42ec5e3d(param_1[0x21]);
    func_0x42ec5e48(param_1[0x22]);
    func_0x42ec5e53(param_1[0x23]);
    func_0x42ec5e5e(param_1[0x24]);
    func_0x42ec5e69(param_1[0x25]);
    func_0x42ec5e74(param_1[0x26]);
    func_0x42ec5e7f(param_1[0x27]);
    func_0x42ec5e8a(param_1[0x28]);
    func_0x42ec5e95(param_1[0x29]);
    func_0x42ec5ea0(param_1[0x2a]);
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
    if (*param_1 != DAT_00422ee0) {
      func_0x42ec5ec3(*param_1);
    }
    if (param_1[1] != DAT_00422ee4) {
      func_0x42ec5ed5(param_1[1]);
    }
    if (param_1[2] != DAT_00422ee8) {
      func_0x42ec5ee7(param_1[2]);
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
    if (*(int *)(param_1 + 0xc) != DAT_00422eec) {
      func_0x42ec5f09(*(int *)(param_1 + 0xc));
    }
    if (*(int *)(param_1 + 0x10) != DAT_00422ef0) {
      func_0x42ec5f1b(*(int *)(param_1 + 0x10));
    }
    if (*(int *)(param_1 + 0x14) != DAT_00422ef4) {
      func_0x42ec5f2d(*(int *)(param_1 + 0x14));
    }
    if (*(int *)(param_1 + 0x18) != DAT_00422ef8) {
      func_0x42ec5f3f(*(int *)(param_1 + 0x18));
    }
    if (*(int *)(param_1 + 0x1c) != DAT_00422efc) {
      func_0x42ec5f51(*(int *)(param_1 + 0x1c));
    }
    if (*(int *)(param_1 + 0x20) != DAT_00422f00) {
      func_0x42ec5f63(*(int *)(param_1 + 0x20));
    }
    if (*(int *)(param_1 + 0x24) != DAT_00422f04) {
      func_0x42ec5f75(*(int *)(param_1 + 0x24));
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
  
  func_0x92e86025(param_1);
  if (param_4 < -1) {
    uVar1 = 0;
  }
  else {
    uVar1 = (*(code *)s_Microsoft_Visual_C___Runtime_Lib_0041c089._3_4_)
                      (param_2,param_3,param_4,param_5);
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
  
  local_8 = s__Repeat_del___s__if_exist___s__g_00422037._13_4_ ^ (uint)&stack0xfffffffc;
  if ((*(byte *)&_File->_flag & 0x40) == 0) {
    iVar3 = func_0x650f6078(_File);
    if ((iVar3 == -1) || (iVar3 = func_0x650f6089(_File), iVar3 == -2)) {
      puVar5 = &DAT_00422570;
    }
    else {
      iVar3 = func_0x650f6095(_File);
      uVar4 = func_0x650f60a5(_File);
      puVar5 = (undefined *)((uVar4 & 0x1f) * 0x40 + (&DAT_00425280)[iVar3 >> 5]);
    }
    if ((puVar5[0x24] & 0x7f) != 2) {
      iVar3 = func_0x650f60c6(_File);
      if ((iVar3 == -1) || (iVar3 = func_0x650f60d2(_File), iVar3 == -2)) {
        puVar5 = &DAT_00422570;
      }
      else {
        iVar3 = func_0x650f60de(_File);
        uVar4 = func_0x650f60ee(_File);
        puVar5 = (undefined *)((uVar4 & 0x1f) * 0x40 + (&DAT_00425280)[iVar3 >> 5]);
      }
      if ((puVar5[0x24] & 0x7f) != 1) {
        iVar3 = func_0x650f610f(_File);
        if ((iVar3 == -1) || (iVar3 = func_0x650f611b(_File), iVar3 == -2)) {
          puVar5 = &DAT_00422570;
        }
        else {
          iVar3 = func_0x650f6127(_File);
          uVar4 = func_0x650f6137(_File);
          puVar5 = (undefined *)((uVar4 & 0x1f) * 0x40 + (&DAT_00425280)[iVar3 >> 5]);
        }
        if ((puVar5[4] & 0x80) != 0) {
          iVar3 = func_0x9787625d(&local_14,local_10,5,__Ch);
          if ((iVar3 == 0) && (iVar3 = 0, 0 < local_14)) {
            do {
              piVar1 = &_File->_cnt;
              *piVar1 = *piVar1 + -1;
              if (*piVar1 < 0) {
                uVar4 = func_0x66166195((int)local_10[iVar3],_File);
              }
              else {
                *_File->_ptr = local_10[iVar3];
                uVar4 = (uint)(byte)*_File->_ptr;
                _File->_ptr = _File->_ptr + 1;
              }
            } while ((uVar4 != 0xffffffff) && (iVar3 = iVar3 + 1, iVar3 < local_14));
          }
          goto LAB_0041617a;
        }
      }
    }
  }
  piVar1 = &_File->_cnt;
  *piVar1 = *piVar1 + -2;
  if (*piVar1 < 0) {
    func_0x9d9e62c6(_Ch,_File);
  }
  else {
    *(wchar_t *)_File->_ptr = _Ch;
    _File->_ptr = _File->_ptr + 2;
  }
LAB_0041617a:
  wVar2 = func_0xf1d661d5();
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
  
  func_0x92e861ec(param_1);
  if (param_3 != (char **)0x0) {
    *param_3 = param_2;
  }
  if ((param_2 == (char *)0x0) || ((param_4 != 0 && ((param_4 < 2 || (0x24 < param_4)))))) {
    puVar3 = (undefined4 *)func_0x89f66203();
    *puVar3 = 0x16;
    func_0x21f66213(0,0,0,0,0);
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
      uVar4 = func_0x11a0635f(bVar8,8,local_18);
      iVar5 = local_18[0];
    }
    if (uVar4 == 0) break;
    bVar8 = *pbVar9;
    pbVar2 = pbVar9;
  }
  if (bVar8 == 0x2d) {
    param_5 = param_5 | 2;
LAB_00416242:
    bVar8 = *pbVar9;
    pbVar9 = pbVar2 + 2;
  }
  else if (bVar8 == 0x2b) goto LAB_00416242;
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
      goto LAB_004162a8;
    }
    if ((*pbVar9 != 0x78) && (*pbVar9 != 0x58)) {
      param_4 = 8;
      goto LAB_004162a8;
    }
    param_4 = 0x10;
  }
  else if ((param_4 != 0x10) || (bVar8 != 0x30)) goto LAB_004162a8;
  if ((*pbVar9 == 0x78) || (*pbVar9 == 0x58)) {
    bVar8 = pbVar9[1];
    pbVar9 = pbVar9 + 2;
  }
LAB_004162a8:
  uVar4 = (uint)(0xffffffff / (ulonglong)(uint)param_4);
  do {
    uVar1 = *(ushort *)(*(int *)(iVar5 + 200) + (uint)bVar8 * 2);
    if ((uVar1 & 4) == 0) {
      if ((uVar1 & 0x103) == 0) {
LAB_00416305:
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
          puVar3 = (undefined4 *)func_0x89f663a4();
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
    if ((uint)param_4 <= uVar6) goto LAB_00416305;
    if ((local_8 < uVar4) ||
       ((local_8 == uVar4 && (uVar6 <= (uint)(0xffffffff % (ulonglong)(uint)param_4))))) {
      local_8 = local_8 * param_4 + uVar6;
      param_5 = param_5 | 8;
    }
    else {
      param_5 = param_5 | 0xc;
      if (param_3 == (char **)0x0) goto LAB_00416305;
    }
    bVar8 = *pbVar9;
    pbVar9 = pbVar9 + 1;
  } while( true );
}



void __cdecl FUN_004163b8(undefined4 param_1,undefined4 param_2,undefined4 param_3)

{
  undefined *puVar1;
  
  if (DAT_00423cc4 == 0) {
    puVar1 = &DAT_00422da8;
  }
  else {
    puVar1 = (undefined *)0x0;
  }
  func_0x8092652c(puVar1,param_1,param_2,param_3,0);
  return;
}



int __cdecl FUN_004163e3(short *param_1)

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



// WARNING: Control flow encountered bad instruction data
// WARNING: Globals starting with '_' overlap smaller symbols at the same address
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
  
  uVar11 = func_0x7b746785(_FileHandle,0,0,1);
  if (uVar11 != 0xffffffffffffffff) {
    lVar12 = func_0x7b7467a1(_FileHandle,0,0,2);
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
          lVar12 = func_0x7b74689c(_FileHandle,in_stack_00000008,(int)_Size,0);
          if (lVar12 == -1) goto LAB_004166a0;
          uVar2 = func_0x207768b2(_FileHandle);
          iVar3 = (*ram0x0041c084)(uVar2);
          uVar6 = (iVar3 != 0) - 1;
          if ((uVar6 & (int)uVar6 >> 0x1f) == 0xffffffff) {
            puVar4 = (undefined4 *)func_0x89f667d4();
            *puVar4 = 0xd;
            puVar4 = (undefined4 *)func_0x9cf667df();
            uVar2 = (*(code *)s_R6002___floating_point_support_n_0041c059._7_4_)();
            *puVar4 = uVar2;
            if ((uVar6 & (int)uVar6 >> 0x1f) == 0xffffffff) goto LAB_004166a0;
          }
        }
        lVar12 = __lseeki64_nolock(_FileHandle,uVar11 >> 0x20,unaff_EDI);
        if (lVar12 != -1) {
                    // WARNING: Bad instruction - Truncating control flow here
          halt_baddata();
        }
      }
      else {
        uVar2 = (*(code *)s_R6002___floating_point_support_n_0041c059._39_4_)(8,0x1000);
        iVar3 = (*DAT_0041c0f0)(uVar2);
        if (iVar3 != 0) {
          uVar2 = func_0xc5986807(_FileHandle,0x8000);
          while( true ) {
            uVar6 = uVar7;
            if ((-1 < iVar8) && ((0 < iVar8 || (0xfff < uVar7)))) {
              uVar6 = 0x1000;
            }
            uVar6 = func_0xca176728(_FileHandle,iVar3,uVar6);
            if (uVar6 == 0xffffffff) break;
            bVar9 = uVar7 < uVar6;
            uVar7 = uVar7 - uVar6;
            bVar10 = SBORROW4(iVar8,(int)uVar6 >> 0x1f);
            iVar1 = iVar8 - ((int)uVar6 >> 0x1f);
            iVar8 = iVar1 - (uint)bVar9;
            if ((iVar8 < 0) ||
               ((iVar8 == 0 || (bVar10 != SBORROW4(iVar1,(uint)bVar9)) != iVar8 < 0 && (uVar7 == 0))
               )) goto LAB_004166f2;
          }
          piVar5 = (int *)func_0x9cf6676b();
          if (*piVar5 == 5) {
            puVar4 = (undefined4 *)func_0x89f66775();
            *puVar4 = 0xd;
          }
LAB_004166f2:
          func_0xc598684b(_FileHandle,uVar2);
          uVar2 = (*(code *)s_R6002___floating_point_support_n_0041c059._39_4_)(0,iVar3);
          (*DAT_0041c0f4)(uVar2);
                    // WARNING: Bad instruction - Truncating control flow here
          halt_baddata();
        }
        puVar4 = (undefined4 *)func_0x89f666e8();
        *puVar4 = 0xc;
      }
    }
  }
LAB_004166a0:
  piVar5 = (int *)func_0x89f666f3();
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
  
  piVar2 = &DAT_00425280 + (_FileHandle >> 5);
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
      if (_Mode != 0x40000) goto LAB_0041686c;
      *(byte *)(iVar1 + 4) = *(byte *)(iVar1 + 4) | 0x80;
      pbVar5 = (byte *)(*piVar2 + 0x24 + iVar7);
      bVar6 = *pbVar5 & 0x81 | 1;
    }
    *pbVar5 = bVar6;
  }
LAB_0041686c:
  if ((bVar4 & 0x80) == 0) {
    return 0x8000;
  }
  return (-(uint)((char)(cVar3 * '\x02') >> 1 != '\0') & 0xc000) + 0x4000;
}



undefined4 __cdecl FUN_0041688a(undefined4 *param_1)

{
  undefined4 *puVar1;
  undefined4 uVar2;
  
  if (param_1 == (undefined4 *)0x0) {
    puVar1 = (undefined4 *)func_0x89f668ec();
    *puVar1 = 0x16;
    func_0x21f668fc(0,0,0,0,0);
    uVar2 = 0x16;
  }
  else {
    *param_1 = DAT_00424050;
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
    func_0x92e86936(_Locale);
    if (*(int *)(local_18[0] + 0x14) == 0) {
      wVar1 = _C;
      if ((ushort)(_C - 0x41) < 0x1a) {
        wVar1 = _C + 0x20;
      }
    }
    else if (_C < 0x100) {
      iVar2 = func_0x87446a73(__C,1,local_18);
      wVar1 = _C;
      if (iVar2 != 0) {
        wVar1 = (wint_t)*(byte *)(*(int *)(local_18[0] + 0xcc) + (__C & 0xffff));
      }
    }
    else {
      iVar2 = func_0xc9a06aa8(local_18,*(int *)(local_18[0] + 0x14),0x100,&_C,1,local_8,1,
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
  
  if ((DAT_00422f28 & 1) != 0) {
    func_0xc1366a41(10);
  }
  iVar2 = func_0xd1816b47();
  if (iVar2 != 0) {
    func_0xde816b52(0x16);
  }
  if ((DAT_00422f28 & 2) != 0) {
    local_2d4[0] = 0x10001;
    func_0x9c0f6aea(local_32c,0,0x50);
    local_2dc = local_32c;
    local_2d8 = local_2d4;
    local_32c[0] = 0x40000015;
    (*DAT_0041c108)(0);
    (*DAT_0041c104)(&local_2dc);
  }
  func_0x3f366b31(3);
  pcVar1 = (code *)swi(3);
  (*pcVar1)();
  return;
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
  
  func_0x92e86b45(_Locale);
  if (*(int *)(local_14[0] + 0xac) < 2) {
    uVar1 = *(ushort *)(*(int *)(local_14[0] + 200) + _C * 2) & 4;
  }
  else {
    uVar1 = func_0x11a06c5f(_C,4,local_14);
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
  
  if (DAT_00423cc4 == 0) {
    return *(ushort *)(DAT_00422d90 + _C * 2) & 4;
  }
  iVar1 = func_0xdb9b6cad(_C,0);
  return iVar1;
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
  
  local_8 = s__Repeat_del___s__if_exist___s__g_00422037._13_4_ ^ (uint)&stack0xfffffffc;
  local_a = 0;
  iVar1 = (*_DAT_0041c088)(param_1,0x1004,local_10,6);
  if (iVar1 != 0) {
    func_0x879e6ced(local_10);
  }
  func_0xf1d66bf8();
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
  undefined4 uVar4;
  code *pcVar5;
  int iVar6;
  int *piVar7;
  uint uVar8;
  bool bVar9;
  int iStack_4c;
  int *piStack_48;
  int *local_20;
  int local_1c [5];
  uint local_8;
  
  pcVar5 = DAT_0041c170;
  local_8 = s__Repeat_del___s__if_exist___s__g_00422037._13_4_ ^ (uint)&stack0xfffffffc;
  uVar2 = *param_4;
  bVar3 = false;
  if (param_1 == param_2) goto LAB_00416d4b;
  piStack_48 = local_1c;
  iStack_4c = param_1;
  iVar6 = (*DAT_0041c170)();
  uVar4 = s_R6008___not_enough_space_for_arg_0041c02d._31_4_;
  if ((((iVar6 == 0) || (local_1c[0] != 1)) || (iVar6 = (*pcVar5)(param_2,local_1c), iVar6 == 0)) ||
     (local_1c[0] != 1)) {
    uVar8 = (*(code *)uVar4)(param_1,1,param_3,uVar2,0,0);
    bVar9 = uVar8 == 0;
    if (bVar9) {
      return;
    }
  }
  else {
    bVar3 = true;
    uVar8 = uVar2;
    if (uVar2 == 0xffffffff) {
      iVar6 = func_0xcb7b6d81(param_3);
      uVar8 = iVar6 + 1;
    }
    bVar9 = uVar8 == 0;
  }
  if ((bVar9 || (int)uVar8 < 0) || (0x7ffffff0 < uVar8)) {
    local_20 = (undefined4 *)0x0;
  }
  else {
    uVar1 = uVar8 * 2 + 8;
    if (uVar1 < 0x401) {
      piVar7 = &iStack_4c;
      func_0x5b9e6da1();
      local_20 = &iStack_4c;
      if (&stack0x00000000 != (undefined *)0x4c) {
        iStack_4c = 0xcccc;
LAB_00416c8e:
        local_20 = piVar7 + 2;
      }
    }
    else {
      piVar7 = (int *)func_0xe1e66cd1(uVar1);
      local_20 = piVar7;
      if (piVar7 != (undefined4 *)0x0) {
        *piVar7 = 0xdddd;
        goto LAB_00416c8e;
      }
    }
  }
  if (local_20 == (undefined4 *)0x0) {
                    // WARNING: Bad instruction - Truncating control flow here
    halt_baddata();
  }
  func_0x9c0f6cf9(local_20,0,uVar8 * 2);
  iVar6 = (*(code *)uVar4)(param_1,1,param_3,uVar2,local_20,uVar8);
  uVar4 = s_R6002___floating_point_support_n_0041c059._31_4_;
  if (iVar6 != 0) {
    if (param_5 == 0) {
      if (((bVar3) ||
          (uVar8 = (*(code *)s_R6002___floating_point_support_n_0041c059._31_4_)
                             (param_2,0,local_20,uVar8,0,0,0,0), uVar8 != 0)) &&
         (iVar6 = func_0x2b666e5c(1,uVar8), iVar6 != 0)) {
        uVar8 = (*(code *)uVar4)(param_2,0,local_20,uVar8,iVar6,uVar8,0,0);
        if (uVar8 == 0) {
          func_0x42ec6d7f(iVar6);
        }
        else if (uVar2 != 0xffffffff) {
          *param_4 = uVar8;
        }
      }
    }
    else {
      (*(code *)s_R6002___floating_point_support_n_0041c059._31_4_)
                (param_2,0,local_20,uVar8,param_5,param_6,0,0);
    }
  }
  func_0xb4876e98(local_20);
LAB_00416d4b:
  func_0xf1d66dac();
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



void __cdecl FUN_00416d90(undefined4 param_1)

{
  func_0xaf946eef(param_1,0,10);
  return;
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
  
  uVar4 = func_0x650f6e04(_File);
  uVar1 = _File->_flag;
  if ((uVar1 & 0x82) == 0) {
    puVar5 = (undefined4 *)func_0x89f66e14();
    *puVar5 = 9;
LAB_00416dcc:
    _File->_flag = _File->_flag | 0x20;
                    // WARNING: Bad instruction - Truncating control flow here
    halt_baddata();
  }
  if ((uVar1 & 0x40) != 0) {
    puVar5 = (undefined4 *)func_0x89f66e31();
    *puVar5 = 0x22;
    goto LAB_00416dcc;
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
     (((iVar6 = func_0x98fe6e77(), _File != (FILE *)(iVar6 + 0x20) &&
       (iVar6 = func_0x98fe6e83(), _File != (FILE *)(iVar6 + 0x40))) ||
      (iVar6 = func_0xf67d6f92(uVar4), iVar6 == 0)))) {
    func_0x32746f9d(_File);
  }
  if ((_File->_flag & 0x108U) == 0) {
    local_8 = CONCAT22(local_8._2_2_,(short)_Ch);
    local_8 = func_0xfd1e6f46(uVar4,&local_8,2);
  }
  else {
    pcVar2 = _File->_base;
    pcVar3 = _File->_ptr;
    _File->_ptr = pcVar2 + 2;
    iVar8 = (int)pcVar3 - (int)pcVar2;
    _File->_cnt = _File->_bufsiz + -2;
    if (iVar8 < 1) {
      if ((uVar4 == 0xffffffff) || (uVar4 == 0xfffffffe)) {
        puVar7 = &DAT_00422570;
      }
      else {
        puVar7 = (undefined *)((uVar4 & 0x1f) * 0x40 + (&DAT_00425280)[(int)uVar4 >> 5]);
      }
      if (((puVar7[4] & 0x20) != 0) && (lVar9 = func_0x0075701a(uVar4,0,0,2), lVar9 == -1))
      goto LAB_00416f03;
    }
    else {
      local_8 = func_0xfd1e6ece(uVar4,pcVar2,iVar8);
    }
    *(short *)_File->_base = (short)_Ch;
  }
  if (local_8 == iVar8) {
    return _Ch & 0xffff;
  }
LAB_00416f03:
  _File->_flag = _File->_flag | 0x20;
  return 0xffff;
}



uint __cdecl FUN_00416f1a(int param_1,undefined4 param_2,localeinfo_struct *param_3)

{
  uint uVar1;
  int iVar2;
  BOOL BVar3;
  CHAR CVar4;
  undefined *unaff_EBP;
  undefined *puVar5;
  unkbyte10 in_ST4;
  localeinfo_struct local_1c;
  int local_14;
  char local_10;
  CHAR local_c;
  CHAR local_b;
  undefined local_a;
  ushort local_8 [2];
  
  puVar5 = &stack0xfffffffc;
  _LocaleUpdate::_LocaleUpdate((_LocaleUpdate *)&local_1c,param_3);
  if (param_1 + 1U < 0x101) {
    ffree(in_ST4);
    *(char *)&(local_1c.locinfo)->refcount =
         *(char *)&(local_1c.locinfo)->refcount + (char)local_1c.locinfo;
    local_8[0] = *(ushort *)
                  ((int)&((threadlocaleinfostruct *)((local_1c.locinfo)->lc_category + -1))->
                         refcount + param_1 * 2);
    puVar5 = unaff_EBP;
  }
  else {
    iVar2 = func_0x508070b1(param_1 >> 8 & 0xff,&local_1c);
    CVar4 = (CHAR)param_1;
    if (iVar2 == 0) {
      local_b = '\0';
      iVar2 = 1;
      local_c = CVar4;
    }
    else {
      param_1._0_1_ = (CHAR)((uint)param_1 >> 8);
      local_c = (CHAR)param_1;
      local_a = 0;
      iVar2 = 2;
      local_b = CVar4;
    }
    BVar3 = FID_conflict____crtCompareStringW
                      (&local_1c,1,&local_c,iVar2,local_8,(local_1c.locinfo)->lc_codepage,
                       (BOOL)(local_1c.locinfo)->lc_category[0].wlocale);
    if (BVar3 == 0) {
      if (local_10 != '\0') {
        *(uint *)(local_14 + 0x70) = *(uint *)(local_14 + 0x70) & 0xfffffffd;
      }
      return 0;
    }
  }
  uVar1 = *(uint *)(puVar5 + 0xc);
  if (puVar5[-0xc] != '\0') {
    *(uint *)(*(int *)(puVar5 + -0x10) + 0x70) =
         *(uint *)(*(int *)(puVar5 + -0x10) + 0x70) & 0xfffffffd;
  }
  return local_8[0] & uVar1;
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
  
  func_0x92e87033(_LocaleName);
  psVar2 = (short *)_CchSrc;
  pWVar3 = _LpDestStr;
  if (0 < (int)_LpDestStr) {
    do {
      pWVar3 = (LPWSTR)((int)pWVar3 + -1);
      if (*psVar2 == 0) goto LAB_00417001;
      psVar2 = psVar2 + 1;
    } while (pWVar3 != (LPWSTR)0x0);
    pWVar3 = (LPWSTR)0xffffffff;
LAB_00417001:
    _LpDestStr = (LPWSTR)((int)_LpDestStr + (-1 - (int)pWVar3));
  }
  iVar1 = (*(code *)s_Microsoft_Visual_C___Runtime_Lib_0041c089._11_4_)
                    (_DWMapFlag,_LpSrcStr,_CchSrc,_LpDestStr,_CchDest,in_stack_0000001c);
  if (local_8 != '\0') {
    *(uint *)(local_c + 0x70) = *(uint *)(local_c + 0x70) & 0xfffffffd;
  }
  return iVar1;
}



// WARNING: Control flow encountered bad instruction data
// WARNING: Type propagation algorithm not settling
// WARNING: Globals starting with '_' overlap smaller symbols at the same address

ushort __cdecl FUN_00417029(uint param_1,localeinfo_struct *param_2)

{
  int *piVar1;
  byte bVar2;
  ushort uVar3;
  char *pcVar4;
  int iVar5;
  undefined4 *puVar6;
  CHAR CVar7;
  byte *unaff_EDI;
  localeinfo_struct local_1c;
  int local_14;
  char local_10;
  byte local_c;
  undefined local_b;
  CHAR local_8;
  CHAR local_7;
  undefined local_6;
  
  pcVar4 = (char *)_LocaleUpdate::_LocaleUpdate((_LocaleUpdate *)&local_1c,param_2);
  if (param_1 < 0x100) {
    bVar2 = *unaff_EDI;
    *pcVar4 = *pcVar4 + (byte)pcVar4;
    _DAT_00000113 = _DAT_00000113 + (int)(unaff_EDI + 1);
    iVar5 = func_0x11a071b0((param_1 - (int)local_1c.locinfo) - (uint)((byte)pcVar4 < bVar2),1,
                            &local_1c);
    if (iVar5 != 0) {
                    // WARNING: Bad instruction - Truncating control flow here
      halt_baddata();
    }
  }
  else {
    piVar1 = (int *)(unaff_EDI + 1);
    *piVar1 = (*piVar1 - param_1) - (uint)((byte)local_1c.locinfo < *unaff_EDI);
    *(byte *)&(local_1c.locinfo)->refcount =
         *(char *)&(local_1c.locinfo)->refcount + (byte)local_1c.locinfo;
    _DAT_00000130 = _DAT_00000130 + (int)piVar1;
    iVar5 = func_0x50807211((int)param_1 >> 8 & 0xff,&local_1c);
    CVar7 = (CHAR)param_1;
    if (iVar5 == 0) {
      puVar6 = (undefined4 *)func_0x89f6712e();
      *puVar6 = 0x2a;
      local_7 = '\0';
      iVar5 = 1;
      local_8 = CVar7;
    }
    else {
      param_1._0_1_ = (CHAR)(param_1 >> 8);
      local_8 = (CHAR)param_1;
      local_6 = 0;
      iVar5 = 2;
      local_7 = CVar7;
    }
    iVar5 = ___crtLCMapStringA(&local_1c,(local_1c.locinfo)->lc_category[0].wlocale,0xff,&local_8,
                               iVar5,(LPSTR)&local_c,3,(local_1c.locinfo)->lc_codepage,1);
    if (iVar5 != 0) {
      uVar3 = (ushort)local_c;
      if (iVar5 != 1) {
        uVar3 = CONCAT11(local_c,local_b);
      }
      if (local_10 != '\0') {
        *(uint *)(local_14 + 0x70) = *(uint *)(local_14 + 0x70) & 0xfffffffd;
      }
      return uVar3;
    }
  }
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
  if (DAT_00423cc4 == 0) {
    if (_C - 0x41U < 0x1a) {
      return _C + 0x20;
    }
  }
  else {
    _C = func_0x20a172b4(_C,0);
  }
  return _C;
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
      if (bVar2 != (byte)uVar3) goto LAB_004171c5;
      _MaxCount = _MaxCount - 1;
    } while (_MaxCount != 0);
    _MaxCount = 0;
    bVar2 = (byte)(uVar3 >> 8);
    bVar5 = bVar2 < (byte)uVar3;
    if (bVar2 != (byte)uVar3) {
LAB_004171c5:
      _MaxCount = 0xffffffff;
      if (!bVar5) {
        _MaxCount = 1;
      }
    }
  }
  return _MaxCount;
}



// WARNING: Globals starting with '_' overlap smaller symbols at the same address

void __cdecl FUN_0041731f(int param_1)

{
  func_0xb6a37477();
  _DAT_0042523c = func_0xbfb4747c();
  if (param_1 != 0) {
    func_0x56b4748c();
  }
  return;
}



// Library Function - Single Match
//  void __stdcall _JumpToContinuation(void *,struct EHRegistrationNode *)
// 
// Library: Visual Studio

void _JumpToContinuation(void *param_1,EHRegistrationNode *param_2)

{
                    // WARNING: Load size is inaccurate
  ExceptionList = *ExceptionList;
                    // WARNING: Could not recover jumptable at 0x004174c9. Too many branches
                    // WARNING: Treating indirect jump as call
  (*(code *)param_1)();
  return;
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
  
  uVar1 = func_0xbbc0769f(param_1,param_2,param_3,param_4);
  return uVar1;
}



void __cdecl FUN_00417561(undefined4 param_1,int param_2,undefined4 param_3)

{
  func_0xf1d675c3();
  func_0xbbc076dc(param_1,*(undefined4 *)(param_2 + 0x10),param_3,0,*(undefined4 *)(param_2 + 0xc),
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
    local_28 = 0x417667;
    local_24 = s__Repeat_del___s__if_exist___s__g_00422037._13_4_ ^ (uint)&local_2c;
    local_20 = param_5;
    local_1c = param_2;
    local_18 = param_6;
    local_14 = param_7;
    local_8 = 0;
    local_2c = (undefined4 *)ExceptionList;
    ExceptionList = &local_2c;
    local_38 = param_1;
    local_34 = param_3;
    iVar1 = func_0x99f97672();
    local_30 = *(code **)(iVar1 + 0x80);
    (*local_30)(*(undefined4 *)param_1,&local_38);
    if (local_8 != 0) {
                    // WARNING: Load size is inaccurate
      *local_2c = *ExceptionList;
    }
    ExceptionList = local_2c;
    return 0;
  }
  *(undefined4 *)param_2 = 0x41763b;
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
  
  func_0xf1d676cf();
  if ((*(uint *)(param_1 + 4) & 0x66) != 0) {
    *(undefined4 *)(param_2 + 0x24) = 1;
    return 1;
  }
  func_0xbbc07812(param_1,*(undefined4 *)(param_2 + 0x10),param_3,0,*(undefined4 *)(param_2 + 0xc),
                  *(undefined4 *)(param_2 + 0x14),*(undefined4 *)(param_2 + 0x18),1);
  if (*(int *)(param_2 + 0x24) == 0) {
    func_0xcea57829(param_2,param_1);
  }
  func_0x8ba67841(0x123,&local_8,0,0,0,0,0);
                    // WARNING: Could not recover jumptable at 0x00417702. Too many branches
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
      func_0x3381787b();
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
    func_0x338178c0();
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
  iVar1 = func_0x99f977e0();
  param_1[1] = *(undefined4 *)(iVar1 + 0x98);
  iVar1 = func_0x99f977ee();
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
  
  iVar1 = func_0x99f97803();
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
  
  iVar1 = func_0x99f9782b();
  if (param_1 == *(int *)(iVar1 + 0x98)) {
    iVar1 = func_0x99f9783b();
    *(undefined4 *)(iVar1 + 0x98) = *(undefined4 *)(param_1 + 4);
  }
  else {
    iVar1 = func_0x99f9784c();
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



void __cdecl
FUN_00417824(char *param_1,undefined4 param_2,undefined4 param_3,int param_4,undefined4 param_5)

{
  char cVar1;
  char cVar2;
  int iVar3;
  undefined2 extraout_DX;
  char *unaff_EBX;
  int unaff_ESI;
  bool bVar4;
  code *local_79;
  void *local_1c;
  undefined4 local_18;
  uint local_14;
  undefined4 local_10;
  char *local_c;
  int local_8;
  
  local_14 = s__Repeat_del___s__if_exist___s__g_00422037._13_4_ ^ (uint)&local_1c;
  local_10 = param_2;
  local_8 = param_4 + 1;
  local_18 = 0x41755d;
  local_c = param_1;
  local_1c = ExceptionList;
  ExceptionList = &local_1c;
  cVar2 = func_0xabc179c3(param_3,param_1,param_5);
  unaff_EBX[-0x743c363f] = unaff_EBX[-0x743c363f] + cVar2 + *unaff_EBX;
  (*local_79)();
  in(extraout_DX);
  func_0x92e878e6(param_2,unaff_ESI + -1);
  iVar3 = func_0x35a279f2((int)*param_1);
  bVar4 = iVar3 == 0x65;
  while (!bVar4) {
    param_1 = param_1 + 1;
    iVar3 = func_0x2c9c7a01(*param_1);
    bVar4 = iVar3 == 0;
  }
  iVar3 = func_0x35a27a0f((int)*param_1);
  if (iVar3 == 0x78) {
    param_1 = param_1 + 2;
  }
  cVar2 = *param_1;
  *param_1 = ***(char ***)(local_14 + 0xbc);
  do {
    param_1 = param_1 + 1;
    cVar1 = *param_1;
    *param_1 = cVar2;
    cVar2 = cVar1;
  } while (*param_1 != '\0');
  if ((char)local_8 != '\0') {
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
  
  func_0x92e87959(_Locale);
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
    func_0x9fc27b18(&flag,number,param_4);
    *(int *)argument = flag;
  }
  else {
    func_0xf7c17aff(&local_c);
    *(undefined4 *)argument = local_c;
    *(undefined4 *)(argument + 4) = local_8;
  }
  return;
}



void __cdecl FUN_004179d7(undefined4 param_1,undefined4 param_2,undefined4 param_3)

{
  func_0x8caa7b3a(param_1,param_2,param_3,0);
  return;
}



void __cdecl FUN_00417a10(undefined4 param_1)

{
  func_0x7ba97b6d(param_1,0);
  return;
}



void __cdecl FUN_00417a23(undefined4 param_1)

{
  func_0xeea97b80(param_1,0);
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
  
  func_0x92e87a9c(param_6);
  if ((in_EAX == (undefined *)0x0) || (param_1 == 0)) {
    puVar1 = (undefined4 *)func_0x89f67aa7();
    uVar6 = 0x16;
  }
  else {
    iVar2 = param_2;
    if (param_2 < 1) {
      iVar2 = 0;
    }
    if (iVar2 + 9U < param_1) {
      if (param_5 != '\0') {
        func_0xe8aa7c13();
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
      iVar2 = func_0xabe77b6a(puVar5,puVar4,&DAT_004203cc);
      if (iVar2 != 0) {
        func_0xf9f47b7d(0,0,0,0,0);
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
      if (((DAT_00425240 & 1) != 0) && (puVar5[2] == '0')) {
        func_0x2bd87bdc(puVar5 + 2,puVar5 + 3,3);
      }
      if (local_8 != '\0') {
        *(uint *)(local_c + 0x70) = *(uint *)(local_c + 0x70) & 0xfffffffd;
      }
      return 0;
    }
    puVar1 = (undefined4 *)func_0x89f67aeb();
    uVar6 = 0x22;
  }
  *puVar1 = uVar6;
  func_0x21f67ab6(0,0,0,0,0);
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
  
  local_8 = s__Repeat_del___s__if_exist___s__g_00422037._13_4_ ^ (uint)&stack0xfffffffc;
  func_0xc3c47d24(*param_1,param_1[1],local_30,local_20,0x16);
  if ((param_2 == (undefined *)0x0) || (param_3 == 0)) {
    puVar1 = (undefined4 *)func_0x89f67c32();
    *puVar1 = 0x16;
    func_0x21f67c3e(0,0,0,0,0);
  }
  else {
    if (param_3 == -1) {
      iVar2 = -1;
    }
    else {
      iVar2 = (param_3 - (uint)(local_30[0] == 0x2d)) - (uint)(0 < param_4);
    }
    iVar2 = func_0x47c37d90(param_2 + (uint)(0 < param_4) + (uint)(local_30[0] == 0x2d),iVar2,
                            param_4 + 1,local_30);
    if (iVar2 == 0) {
      func_0x2dab7db1(param_3,param_4,param_5,local_30,0,param_6);
    }
    else {
      *param_2 = 0;
    }
  }
  func_0xf1d67cc1();
  return;
}



void __cdecl
FUN_00417c75(undefined4 param_1,undefined4 param_2,undefined4 param_3,undefined4 param_4,
            undefined4 param_5)

{
  func_0x9cac7dde(param_1,param_2,param_3,param_4,param_5,0);
  return;
}



// WARNING: Control flow encountered bad instruction data

int __cdecl
FUN_00417c95(uint *param_1,undefined *param_2,uint param_3,int param_4,int param_5,
            undefined4 param_6)

{
  byte *pbVar1;
  short sVar2;
  char cVar3;
  short sVar4;
  ushort uVar5;
  undefined4 *puVar6;
  int iVar7;
  char *pcVar8;
  char *pcVar9;
  uint uVar10;
  uint uVar11;
  uint extraout_ECX;
  uint extraout_ECX_00;
  uint extraout_ECX_01;
  byte extraout_DH;
  short sVar12;
  char *pcVar13;
  char *pcVar14;
  bool bVar15;
  undefined4 uVar16;
  int local_28;
  int local_20;
  char local_1c;
  uint local_18;
  
  local_18 = 0x3ff;
  sVar2 = 0x30;
  func_0x92e87d08(param_6);
  if (param_4 < 0) {
    param_4 = 0;
  }
  if ((param_2 == (undefined *)0x0) || (param_3 == 0)) {
    puVar6 = (undefined4 *)func_0x89f67d1c();
    uVar16 = 0x16;
LAB_00417cd0:
    *puVar6 = uVar16;
    func_0x21f67d2b(0,0,0,0,0);
    if (local_1c != '\0') {
      *(uint *)(local_20 + 0x70) = *(uint *)(local_20 + 0x70) & 0xfffffffd;
    }
                    // WARNING: Bad instruction - Truncating control flow here
    halt_baddata();
  }
  *param_2 = 0;
  if (param_3 <= param_4 + 0xbU) {
    puVar6 = (undefined4 *)func_0x89f67d5a();
    uVar16 = 0x22;
    goto LAB_00417cd0;
  }
  if ((param_1[1] >> 0x14 & 0x7ff) == 0x7ff) {
    if (param_3 == 0xffffffff) {
      iVar7 = -1;
    }
    else {
      iVar7 = param_3 - 2;
    }
    pbVar1 = param_2 + 2;
    iVar7 = func_0x6cad7ea7(param_1,pbVar1,iVar7,param_4,0);
    if (iVar7 != 0) {
      *pbVar1 = *pbVar1 | extraout_DH;
      if (*pbVar1 == 0) {
        return iVar7;
      }
      *(uint *)(local_20 + 0x70) = *(uint *)(local_20 + 0x70) & 0xfffffffd;
                    // WARNING: Bad instruction - Truncating control flow here
      halt_baddata();
    }
    if (*pbVar1 == 0x2d) {
      *param_2 = 0x2d;
      param_2 = param_2 + 1;
    }
    *param_2 = 0x30;
    param_2[1] = ((param_5 == 0) - 1U & 0xe0) + 0x78;
    pcVar8 = (char *)func_0x1be87dec(param_2 + 2,0x65);
    if (pcVar8 != (char *)0x0) {
      *pcVar8 = ((param_5 == 0) - 1U & 0xe0) + 0x70;
      pcVar8[3] = '\0';
                    // WARNING: Bad instruction - Truncating control flow here
      halt_baddata();
    }
    goto LAB_00417ff4;
  }
  if ((param_1[1] & 0x80000000) != 0) {
    *param_2 = 0x2d;
    param_2 = param_2 + 1;
  }
  *param_2 = 0x30;
  param_2[1] = ((param_5 == 0) - 1U & 0xe0) + 0x78;
  sVar12 = (-(ushort)(param_5 != 0) & 0xffe0) + 0x27;
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
  pcVar14 = param_2 + 3;
  pcVar8 = param_2 + 4;
  if (param_4 == 0) {
    *pcVar14 = '\0';
  }
  else {
    *pcVar14 = ***(char ***)(local_28 + 0xbc);
  }
  if (((param_1[1] & 0xfffff) != 0) || (*param_1 != 0)) {
    do {
      if (param_4 < 1) break;
      sVar4 = func_0x3bc67fd4();
      uVar5 = sVar4 + 0x30;
      if (0x39 < uVar5) {
        uVar5 = uVar5 + sVar12;
      }
      sVar2 = sVar2 + -4;
      *pcVar8 = (char)uVar5;
      pcVar8 = pcVar8 + 1;
      param_4 = param_4 + -1;
    } while (-1 < sVar2);
    if ((-1 < sVar2) && (uVar5 = func_0x3bc68028(), pcVar13 = pcVar8, 8 < uVar5)) {
      while( true ) {
        pcVar9 = pcVar13 + -1;
        if ((*pcVar9 != 'f') && (*pcVar9 != 'F')) break;
        *pcVar9 = '0';
        pcVar13 = pcVar9;
      }
      if (pcVar9 == pcVar14) {
        pcVar13[-2] = pcVar13[-2] + '\x01';
      }
      else if (*pcVar9 == '9') {
        *pcVar9 = (char)sVar12 + ':';
      }
      else {
        *pcVar9 = *pcVar9 + '\x01';
      }
    }
  }
  if (0 < param_4) {
    func_0x9c0f7f70(pcVar8,0x30,param_4);
    pcVar8 = pcVar8 + param_4;
  }
  if (*pcVar14 == '\0') {
    pcVar8 = pcVar14;
  }
  *pcVar8 = ((param_5 == 0) - 1U & 0xe0) + 0x70;
  uVar10 = func_0x3bc6809c();
  uVar11 = (uVar10 & 0x7ff) - local_18;
  uVar10 = (uint)((uVar10 & 0x7ff) < local_18);
  iVar7 = -uVar10;
  if (uVar10 == 0) {
    pcVar8[1] = '+';
  }
  else {
    pcVar8[1] = '-';
    bVar15 = uVar11 != 0;
    uVar11 = -uVar11;
    iVar7 = -(iVar7 + (uint)bVar15);
  }
  pcVar13 = pcVar8 + 2;
  *pcVar13 = '0';
  pcVar14 = pcVar13;
  if ((iVar7 < 0) || ((iVar7 < 1 && (uVar11 < 1000)))) {
LAB_00417fa3:
    if ((-1 < iVar7) && ((0 < iVar7 || (99 < uVar11)))) goto LAB_00417fae;
  }
  else {
    cVar3 = func_0x5bc580e1(uVar11,iVar7,1000,0);
    *pcVar13 = cVar3 + '0';
    pcVar14 = pcVar8 + 3;
    iVar7 = 0;
    uVar11 = extraout_ECX;
    if (pcVar14 == pcVar13) goto LAB_00417fa3;
LAB_00417fae:
    cVar3 = func_0x5bc58107(uVar11,iVar7,100,0);
    *pcVar14 = cVar3 + '0';
    pcVar14 = pcVar14 + 1;
    iVar7 = 0;
    uVar11 = extraout_ECX_00;
  }
  if ((pcVar14 != pcVar13) || ((-1 < iVar7 && ((0 < iVar7 || (9 < uVar11)))))) {
    cVar3 = func_0x5bc5812d(uVar11,iVar7,10,0);
    *pcVar14 = cVar3 + '0';
    pcVar14 = pcVar14 + 1;
    uVar11 = extraout_ECX_01;
  }
  *pcVar14 = (char)uVar11 + '0';
  pcVar14[1] = '\0';
LAB_00417ff4:
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
  func_0x92e88074(param_4);
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
      func_0xe8aa81e7();
      *(undefined *)this = 0x30;
      puVar3 = (undefined *)((int)this + 1);
    }
    else {
      puVar3 = (undefined *)((int)this + in_EAX[1]);
    }
    if (0 < param_2) {
      func_0xe8aa81fc();
      *puVar3 = *(undefined *)**(undefined4 **)(local_14 + 0xbc);
      iVar1 = in_EAX[1];
      if (iVar1 < 0) {
        if ((param_3 != '\0') || (SBORROW4(param_2,-iVar1) == param_2 + iVar1 < 0)) {
          param_2 = -iVar1;
        }
        func_0xe8aa822d();
        func_0x9c0f8136(puVar3 + 1,0x30,param_2);
      }
    }
    if (local_8 != '\0') {
      *(uint *)(local_c + 0x70) = *(uint *)(local_c + 0x70) & 0xfffffffd;
    }
    return 0;
  }
  puVar2 = (undefined4 *)func_0x89f6807d();
  *puVar2 = 0x16;
  func_0x21f6808e(0,0,0,0,0);
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
  
  local_8 = s__Repeat_del___s__if_exist___s__g_00422037._13_4_ ^ (uint)&stack0xfffffffc;
  func_0xc3c4827e(*param_1,param_1[1],&local_30,local_20,0x16);
  if ((param_2 == (undefined *)0x0) || (param_3 == 0)) {
    puVar1 = (undefined4 *)func_0x89f6818c();
    *puVar1 = 0x16;
    func_0x21f68198(0,0,0,0,0);
  }
  else {
    if (param_3 == -1) {
      iVar2 = -1;
    }
    else {
      iVar2 = param_3 - (uint)(local_30 == 0x2d);
    }
    iVar2 = func_0x47c382d9(param_2 + (local_30 == 0x2d),iVar2,local_2c + param_4,&local_30);
    if (iVar2 == 0) {
      func_0xffb082f6(param_3,param_4,0,param_5);
    }
    else {
      *param_2 = 0;
    }
  }
  func_0xf1d68206();
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
  
  local_8 = s__Repeat_del___s__if_exist___s__g_00422037._13_4_ ^ (uint)&stack0xfffffffc;
  func_0xc3c48339(*param_1,param_1[1],&local_34,local_20,0x16);
  if ((param_2 != (undefined *)0x0) && (param_3 != 0)) {
    local_24 = local_30 + -1;
    if (param_3 == -1) {
      iVar3 = -1;
    }
    else {
      iVar3 = param_3 - (uint)(local_34 == 0x2d);
    }
    iVar3 = func_0x47c38390(param_2 + (local_34 == 0x2d),iVar3,param_4,&local_34);
    if (iVar3 == 0) {
      local_30 = local_30 + -1;
      if ((local_30 < -4) || (param_4 <= local_30)) {
        func_0x2dab83f0(param_3,param_4,param_5,&local_34,1,param_6);
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
        func_0xffb083d2(param_3,param_4,1,param_6);
      }
    }
    else {
      *param_2 = 0;
    }
    func_0xf1d68300();
    return;
  }
  puVar2 = (undefined4 *)func_0x89f68247();
  *puVar2 = 0x16;
  func_0x21f68253(0,0,0,0,0);
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
    eVar1 = func_0x9cac8485(arg,buffer,sizeInBytes,precision,caps,plocinfo);
  }
  else {
    if (format == 0x66) {
      eVar1 = func_0xf6b1842d(arg,buffer,sizeInBytes,precision,plocinfo);
      return eVar1;
    }
    if ((format == 0x61) || (format == 0x41)) {
      eVar1 = func_0x8cad846c(arg,buffer,sizeInBytes,precision,caps,plocinfo);
    }
    else {
      eVar1 = func_0xb1b28453(arg,buffer,sizeInBytes,precision,caps,plocinfo);
    }
  }
  return eVar1;
}



void __cdecl
FUN_0041833c(undefined4 param_1,undefined4 param_2,undefined4 param_3,undefined4 param_4,
            undefined4 param_5,undefined4 param_6)

{
  func_0xabb384a8(param_1,param_2,param_3,param_4,param_5,param_6,0);
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
  
  dVar1 = _DAT_004203d8 - (_DAT_004203d8 / _DAT_004203e0) * _DAT_004203e0;
  if (1.0 < dVar1 != NAN(dVar1)) {
    return 1;
  }
  return 0;
}



undefined4 * __fastcall FUN_004183f1(undefined4 *param_1,undefined param_2,undefined param_3)

{
  func_0x43138450(&param_3);
  *param_1 = &DAT_00420418;
  return param_1;
}



undefined4 * __thiscall FUN_0041841a(void *this,byte param_1)

{
  *(undefined **)this = &DAT_00420418;
  func_0x1014847b();
  if ((param_1 & 1) != 0) {
    func_0x89e18487(this);
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
LAB_00418499:
    uVar2 = 1;
  }
  else {
    if (iVar1 == *(int *)(param_2 + 4)) {
LAB_00418478:
      if (((((*param_2 & 2) == 0) || ((*param_1 & 8) != 0)) &&
          (((*param_3 & 1) == 0 || ((*param_1 & 1) != 0)))) &&
         (((*param_3 & 2) == 0 || ((*param_1 & 2) != 0)))) goto LAB_00418499;
    }
    else {
      iVar1 = func_0xcb7c85bc((char *)(iVar1 + 8),*(int *)(param_2 + 4) + 8);
      if (iVar1 == 0) goto LAB_00418478;
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
    iVar1 = func_0x99f9851e();
    if (0 < *(int *)(iVar1 + 0x90)) {
      iVar1 = func_0x99f9852c();
      *(int *)(iVar1 + 0x90) = *(int *)(iVar1 + 0x90) + -1;
    }
  }
  else if (**param_1 == -0x1f928c9d) {
    iVar1 = func_0x99f9850d();
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
    func_0x338187ec();
    func_0xe78087f1();
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
          iVar1 = func_0x38b58830(unaff_EDI[1] + local_c * 0x10,*piVar3,
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
    func_0x63bb8c64(param_1);
  }
  func_0xcea58c7b();
  func_0xe0b58c89();
  *(int *)(unaff_ESI + 8) = *(int *)(unaff_EDI + 4) + 1;
  iVar1 = func_0x48b88caa(param_1);
  if (iVar1 != 0) {
    func_0x95a58cb8(iVar1);
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
    iVar1 = func_0x99f98bd7();
    if (*(int *)(iVar1 + 0x80) != 0) {
      iVar1 = func_0x99f98be5();
      iVar2 = func_0x44f78bf0();
      if (((*(int *)(iVar1 + 0x80) != iVar2) && (*(int *)param_1 != -0x1fbcb0b3)) &&
         (iVar1 = func_0x8ba68d14(param_1,param_2,param_3,param_4,param_5,param_7,param_8),
         iVar1 != 0)) {
        return;
      }
    }
    if (*(int *)(param_5 + 0xc) == 0) {
      func_0x33818d2d();
    }
    piVar3 = (int *)func_0x01a88d42(param_5,param_7,param_6,&local_8,&local_c);
    if (local_8 < local_c) {
      do {
        if ((*piVar3 <= param_6) && (param_6 <= piVar3[1])) {
          iVar2 = piVar3[3] * 0x10 + piVar3[4];
          iVar1 = *(int *)(iVar2 + -0xc);
          if (((iVar1 == 0) || (*(char *)(iVar1 + 8) == '\0')) &&
             ((*(byte *)(iVar2 + -0x10) & 0x40) == 0)) {
            func_0xf5bb8d95(param_1,param_3,param_4,param_5,0,param_7,param_8);
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
    func_0x33818de7();
  }
  p_Var7 = (_s_FuncInfo *)param_1;
  if (*(int *)param_1 != -0x1f928c9d) goto LAB_00418f63;
  p_Var5 = (_s_FuncInfo *)0x19930520;
  if (*(int *)(param_1 + 0x10) != 3) goto LAB_00418dd0;
  iVar3 = *(int *)(param_1 + 0x14);
  if (((iVar3 != 0x19930520) && (iVar3 != 0x19930521)) && (iVar3 != 0x19930522)) goto LAB_00418dd0;
  if (*(int *)(param_1 + 0x1c) != 0) goto LAB_00418dd0;
  iVar3 = func_0x99f98d2e();
  if (*(int *)(iVar3 + 0x88) != 0) {
    iVar3 = func_0x99f98d40();
    param_1 = *(EHExceptionRecord **)(iVar3 + 0x88);
    iVar3 = func_0x99f98d4e();
    param_3 = *(_CONTEXT **)(iVar3 + 0x8c);
    iVar3 = func_0xfcc68e5f(param_1,1);
    if (iVar3 == 0) {
      func_0x33818e6a();
    }
    if ((((*(int *)param_1 == -0x1f928c9d) && (*(int *)((int)param_1 + 0x10) == 3)) &&
        ((iVar3 = *(int *)((int)param_1 + 0x14), iVar3 == 0x19930520 ||
         ((iVar3 == 0x19930521 || (iVar3 == 0x19930522)))))) && (*(int *)((int)param_1 + 0x1c) == 0)
       ) {
      func_0x33818e94();
    }
    iVar3 = func_0x99f98d99();
    if (*(int *)(iVar3 + 0x94) == 0) goto LAB_00418dd0;
    iVar3 = func_0x99f98da7();
    piVar4 = *(int **)(iVar3 + 0x94);
    iVar3 = func_0x99f98db2();
    iVar6 = 0;
    *(undefined4 *)(iVar3 + 0x94) = 0;
    cVar2 = func_0x84b78ec2(param_1);
    if (cVar2 != '\0') goto LAB_00418dd0;
    p_Var5 = (_s_FuncInfo *)0x0;
    if (0 < *piVar4) {
      do {
        cVar2 = func_0x85148dde(&DAT_00423154);
        if (cVar2 != '\0') goto LAB_00418da1;
        iVar6 = iVar6 + 1;
        p_Var5 = p_Var5 + 0x10;
      } while (iVar6 < *piVar4);
    }
    do {
      func_0xe7808eef();
LAB_00418da1:
      func_0x06b78ef9(param_1,1);
      func_0xe8b48f08(&DAT_00420420);
      func_0x1a168e16(local_30,s_GetStartupInfoA_00420cf1 + 3);
LAB_00418dd0:
      p_Var7 = (_s_FuncInfo *)param_1;
      if (((*(int *)param_1 == -0x1f928c9d) && (*(int *)(param_1 + 0x10) == 3)) &&
         ((p_Var1 = *(_s_FuncInfo **)(param_1 + 0x14), p_Var1 == p_Var5 ||
          ((p_Var1 == (_s_FuncInfo *)0x19930521 || (p_Var1 == (_s_FuncInfo *)0x19930522)))))) {
        if ((*(int *)(param_5 + 0xc) != 0) &&
           (piVar4 = (int *)func_0x01a88f6a(param_5,param_7,local_c,&local_14,&local_20),
           local_14 < local_20)) {
          if ((*piVar4 <= local_c) && (local_c <= piVar4[1])) {
            local_10 = piVar4[4];
            for (local_1c = piVar4[3]; 0 < local_1c; local_1c = local_1c + -1) {
              piVar4 = *(int **)(*(int *)(param_1 + 0x1c) + 0xc);
              for (local_18 = *piVar4; 0 < local_18; local_18 = local_18 + -1) {
                piVar4 = piVar4 + 1;
                local_24 = *piVar4;
                iVar3 = func_0x38b58fbe(local_10,local_24,*(undefined4 *)(param_1 + 0x1c));
                if (iVar3 != 0) {
                  local_5 = 1;
                  func_0xf5bb9001(param_1,param_3,param_4,param_5,local_24,param_7,param_8);
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
          func_0x06b79023(param_1,1);
        }
        if ((((local_5 != '\0') || ((*(uint *)param_5 & 0x1fffffff) < 0x19930521)) ||
            (*(int *)(param_5 + 0x1c) == 0)) || (cVar2 = func_0x84b79052(param_1), cVar2 != '\0'))
        goto LAB_00418f8f;
        func_0x99f98f60();
        func_0x99f98f65();
        iVar3 = func_0x99f98f6a();
        *(EHExceptionRecord **)(iVar3 + 0x88) = param_1;
        iVar3 = func_0x99f98f75();
        *(_CONTEXT **)(iVar3 + 0x8c) = param_3;
        pEVar8 = param_8;
        if (param_8 == (EHRegistrationNode *)0x0) {
          pEVar8 = param_2;
        }
        func_0xcea59092(pEVar8,param_1);
        func_0xe0b590a3(param_2,param_4,param_5,0xffffffff);
        func_0xffb790ae(*(undefined4 *)(param_5 + 0x1c));
        p_Var7 = param_5;
      }
LAB_00418f63:
      if (*(int *)(param_5 + 0xc) == 0) goto LAB_00418f8f;
      p_Var5 = param_5;
    } while (param_6 != '\0');
    func_0x63bc90da(p_Var7,param_2,param_3,param_4,param_5,local_c,param_7,param_8);
LAB_00418f8f:
    iVar3 = func_0x99f98fe2();
    if (*(int *)(iVar3 + 0x94) != 0) {
      func_0x338190f0();
    }
  }
  return;
}



undefined4 * __thiscall FUN_00418fa7(void *this,undefined4 param_1)

{
  func_0xb3139005(param_1);
  *(undefined **)this = &DAT_00420418;
  return (undefined4 *)this;
}



// Library Function - Single Match
//  ___InternalCxxFrameHandler
// 
// Libraries: Visual Studio 2005 Release, Visual Studio 2008 Release, Visual Studio 2010 Release

undefined4 __cdecl
___InternalCxxFrameHandler
          (int *param_1,undefined4 param_2,undefined4 param_3,undefined4 param_4,uint *param_5,
          int param_6,undefined4 param_7,uint param_8)

{
  int iVar1;
  undefined4 uVar2;
  
  iVar1 = func_0x99f9901f();
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
        func_0x57bd91ed(param_1,param_2,param_3,param_4,param_5,param_8,param_6,param_7);
      }
    }
    else if ((param_5[1] != 0) && (param_6 == 0)) {
      func_0xe0b59181(param_2,param_4,param_5,0xffffffff);
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
  
  pcVar1 = (code *)func_0x07749225(param_3,&stack0xfffffffc,this);
  (*pcVar1)();
  iVar2 = *(int *)(param_3 + 0x10);
  if (iVar2 == 0x100) {
    iVar2 = 2;
  }
  func_0x07749247(iVar2,param_3);
  return;
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
  
  local_8 = s__Repeat_del___s__if_exist___s__g_00422037._13_4_ ^ (uint)&stack0xfffffffc;
  func_0x92e89174(_Locale);
  local_18 = func_0x96d1928c(local_14,local_2c,_Str,0,0,0,0,local_28);
  iVar1 = func_0x0ec79299(local_14,_Result);
  if ((local_18 & 3) == 0) {
    if (iVar1 == 1) {
LAB_00419159:
      if (local_1c != '\0') {
        *(uint *)(local_20 + 0x70) = *(uint *)(local_20 + 0x70) & 0xfffffffd;
      }
      goto LAB_00419199;
    }
    if (iVar1 != 2) {
LAB_0041918b:
      if (local_1c != '\0') {
        *(uint *)(local_20 + 0x70) = *(uint *)(local_20 + 0x70) & 0xfffffffd;
      }
      goto LAB_00419199;
    }
  }
  else if ((local_18 & 1) == 0) {
    if ((local_18 & 2) == 0) goto LAB_0041918b;
    goto LAB_00419159;
  }
  if (local_1c != '\0') {
    *(uint *)(local_20 + 0x70) = *(uint *)(local_20 + 0x70) & 0xfffffffd;
  }
LAB_00419199:
  iVar1 = func_0xf1d691f4();
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
  
  local_8 = s__Repeat_del___s__if_exist___s__g_00422037._13_4_ ^ (uint)&stack0xfffffffc;
  func_0x92e8921c(_Locale);
  local_18 = func_0x96d19334(local_14,local_2c,_Str,0,0,0,0,local_28);
  iVar1 = func_0x52cc9341(local_14,_Result);
  if ((local_18 & 3) == 0) {
    if (iVar1 == 1) {
LAB_00419201:
      if (local_1c != '\0') {
        *(uint *)(local_20 + 0x70) = *(uint *)(local_20 + 0x70) & 0xfffffffd;
      }
      goto LAB_00419241;
    }
    if (iVar1 != 2) {
LAB_00419233:
      if (local_1c != '\0') {
        *(uint *)(local_20 + 0x70) = *(uint *)(local_20 + 0x70) & 0xfffffffd;
      }
      goto LAB_00419241;
    }
  }
  else if ((local_18 & 1) == 0) {
    if ((local_18 & 2) == 0) goto LAB_00419233;
    goto LAB_00419201;
  }
  if (local_1c != '\0') {
    *(uint *)(local_20 + 0x70) = *(uint *)(local_20 + 0x70) & 0xfffffffd;
  }
LAB_00419241:
  iVar1 = func_0xf1d6929c();
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
    puVar1 = (undefined4 *)func_0x89f692ba();
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
        iVar3 = func_0xcb7b944a(_Buf + 1);
        func_0x2bd89353(_Buf,_Buf + 1,iVar3 + 1);
      }
      return 0;
    }
    puVar1 = (undefined4 *)func_0x89f692f2();
    *puVar1 = 0x22;
  }
  func_0x21f692c9(0,0,0,0,0);
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
      goto LAB_004193c3;
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
LAB_004193c3:
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
  local_8 = s__Repeat_del___s__if_exist___s__g_00422037._13_4_ ^ (uint)&stack0xfffffffc;
  func_0x06c49545(&local_14,&_Dbl);
  iVar1 = func_0x8ed89560(local_14,uStack_10,CONCAT22(uVar3,uStack_c),0x11,0,&local_30);
  _Flt->flag = iVar1;
  _Flt->sign = (int)local_2e;
  _Flt->decpt = (int)local_30;
  iVar1 = func_0xabe79480(_ResultStr,_SizeInBytes,local_2c);
  if (iVar1 != 0) {
    func_0xf9f49493(0,0,0,0,0);
  }
  _Flt->mantissa = _ResultStr;
  p_Var2 = (STRFLT)func_0xf1d694a8();
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
      func_0xe0e29716(_NewValue,_Mask & 0xfff7ffff);
    }
    else {
      uVar1 = func_0xe0e2970d();
      *_CurrentState = uVar1;
    }
    eVar3 = 0;
  }
  else {
    if (_CurrentState != (uint *)0x0) {
      uVar1 = func_0xe0e296dd(0,0);
      *_CurrentState = uVar1;
    }
    puVar2 = (undefined4 *)func_0x89f695e6();
    eVar3 = 0x16;
    *puVar2 = 0x16;
    func_0x21f695f5(0,0,0,0,0);
  }
  return eVar3;
}



bool __cdecl FUN_00419605(int param_1)

{
  return param_1 != 0;
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
  iVar14 = DAT_00423188 - 1;
  iVar5 = (int)(DAT_00423188 + ((int)DAT_00423188 >> 0x1f & 0x1fU)) >> 5;
  uVar9 = DAT_00423188 & 0x8000001f;
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
        if (_Ifp < *pp_Var7) goto LAB_0041974c;
        bVar15 = _Ifp < puVar10;
        do {
          local_8 = (_LDBL12 *)0x0;
          if (!bVar15) goto LAB_00419753;
LAB_0041974c:
          do {
            local_8 = (_LDBL12 *)0x1;
LAB_00419753:
            iVar5 = iVar5 + -1;
            *pp_Var7 = _Ifp;
            if ((iVar5 < 0) || (local_8 == (_LDBL12 *)0x0)) {
              _Ifp = local_8;
              goto LAB_00419761;
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
LAB_00419761:
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
  if (iVar13 < (int)(DAT_00423184 - DAT_00423188)) {
                    // WARNING: Bad instruction - Truncating control flow here
    halt_baddata();
  }
  if (DAT_00423184 < iVar13) {
    if (DAT_00423180 <= iVar13) {
      local_24[1] = (_LDBL12 *)0x0;
      local_1c = 0;
      local_24[0] = (_LDBL12 *)0x80000000;
      iVar4 = (int)(DAT_0042318c + ((int)DAT_0042318c >> 0x1f & 0x1fU)) >> 5;
      uVar12 = DAT_0042318c & 0x8000001f;
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
    iVar4 = (int)(DAT_0042318c + ((int)DAT_0042318c >> 0x1f & 0x1fU)) >> 5;
    uVar12 = DAT_0042318c & 0x8000001f;
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
    uVar12 = iVar13 + DAT_00423194 << (0x1fU - (char)DAT_0042318c & 0x1f) |
             -(uint)(local_18 != 0) & 0x80000000 | (uint)local_24[0];
    if (DAT_00423190 == 0x40) {
      *(uint *)((int)&_D->x + 4) = uVar12;
      *(_LDBL12 **)&_D->x = local_24[1];
    }
    else if (DAT_00423190 == 0x20) {
      *(uint *)&_D->x = uVar12;
    }
    return INTRNCVT_OK;
  }
  local_14 = DAT_00423184 - local_14;
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
  iVar13 = DAT_00423188 - 1;
  iVar4 = (int)(DAT_00423188 + ((int)DAT_00423188 >> 0x1f & 0x1fU)) >> 5;
  uVar12 = DAT_00423188 & 0x8000001f;
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
      if (2 < iVar4) goto LAB_00419904;
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
LAB_00419904:
  *pp_Var8 = (_LDBL12 *)((uint)*pp_Var8 & -1 << ((byte)local_14 & 0x1f));
  iVar4 = local_10 + 1;
  if (iVar4 < 3) {
    pp_Var8 = local_24 + iVar4;
    for (iVar13 = 3 - iVar4; iVar13 != 0; iVar13 = iVar13 + -1) {
      *pp_Var8 = (_LDBL12 *)0x0;
      pp_Var8 = pp_Var8 + 1;
    }
  }
  uVar12 = DAT_0042318c + 1;
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
  iVar14 = DAT_004231a0 - 1;
  iVar5 = (int)(DAT_004231a0 + ((int)DAT_004231a0 >> 0x1f & 0x1fU)) >> 5;
  uVar9 = DAT_004231a0 & 0x8000001f;
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
        if (_Ifp < *pp_Var7) goto LAB_00419c90;
        bVar15 = _Ifp < puVar10;
        do {
          local_8 = (_LDBL12 *)0x0;
          if (!bVar15) goto LAB_00419c97;
LAB_00419c90:
          do {
            local_8 = (_LDBL12 *)0x1;
LAB_00419c97:
            iVar5 = iVar5 + -1;
            *pp_Var7 = _Ifp;
            if ((iVar5 < 0) || (local_8 == (_LDBL12 *)0x0)) {
              _Ifp = local_8;
              goto LAB_00419ca5;
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
LAB_00419ca5:
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
  if (iVar13 < (int)(DAT_0042319c - DAT_004231a0)) {
                    // WARNING: Bad instruction - Truncating control flow here
    halt_baddata();
  }
  if (DAT_0042319c < iVar13) {
    if (DAT_00423198 <= iVar13) {
      local_24[1] = (_LDBL12 *)0x0;
      local_1c = 0;
      local_24[0] = (_LDBL12 *)0x80000000;
      iVar4 = (int)(DAT_004231a4 + ((int)DAT_004231a4 >> 0x1f & 0x1fU)) >> 5;
      uVar12 = DAT_004231a4 & 0x8000001f;
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
    iVar4 = (int)(DAT_004231a4 + ((int)DAT_004231a4 >> 0x1f & 0x1fU)) >> 5;
    uVar12 = DAT_004231a4 & 0x8000001f;
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
    uVar12 = iVar13 + DAT_004231ac << (0x1fU - (char)DAT_004231a4 & 0x1f) |
             -(uint)(local_18 != 0) & 0x80000000 | (uint)local_24[0];
    if (DAT_004231a8 == 0x40) {
      *(uint *)((int)&_D->x + 4) = uVar12;
      *(_LDBL12 **)&_D->x = local_24[1];
    }
    else if (DAT_004231a8 == 0x20) {
      *(uint *)&_D->x = uVar12;
    }
    return INTRNCVT_OK;
  }
  local_14 = DAT_0042319c - local_14;
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
  iVar13 = DAT_004231a0 - 1;
  iVar4 = (int)(DAT_004231a0 + ((int)DAT_004231a0 >> 0x1f & 0x1fU)) >> 5;
  uVar12 = DAT_004231a0 & 0x8000001f;
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
      if (2 < iVar4) goto LAB_00419e48;
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
LAB_00419e48:
  *pp_Var8 = (_LDBL12 *)((uint)*pp_Var8 & -1 << ((byte)local_14 & 0x1f));
  iVar4 = local_10 + 1;
  if (iVar4 < 3) {
    pp_Var8 = local_24 + iVar4;
    for (iVar13 = 3 - iVar4; iVar13 != 0; iVar13 = iVar13 + -1) {
      *pp_Var8 = (_LDBL12 *)0x0;
      pp_Var8 = pp_Var8 + 1;
    }
  }
  uVar12 = DAT_004231a4 + 1;
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
// WARNING: Removing unreachable block (ram,0x0041a361)
// WARNING: Removing unreachable block (ram,0x0041a32a)
// WARNING: Removing unreachable block (ram,0x0041a712)
// WARNING: Removing unreachable block (ram,0x0041a339)
// WARNING: Removing unreachable block (ram,0x0041a341)
// WARNING: Removing unreachable block (ram,0x0041a347)
// WARNING: Removing unreachable block (ram,0x0041a34a)
// WARNING: Removing unreachable block (ram,0x0041a351)
// WARNING: Removing unreachable block (ram,0x0041a35b)
// WARNING: Removing unreachable block (ram,0x0041a3b6)
// WARNING: Removing unreachable block (ram,0x0041a3b0)
// WARNING: Removing unreachable block (ram,0x0041a3bc)
// WARNING: Removing unreachable block (ram,0x0041a3d9)
// WARNING: Removing unreachable block (ram,0x0041a3db)
// WARNING: Removing unreachable block (ram,0x0041a3e3)
// WARNING: Removing unreachable block (ram,0x0041a3e6)
// WARNING: Removing unreachable block (ram,0x0041a3eb)
// WARNING: Removing unreachable block (ram,0x0041a3ee)
// WARNING: Removing unreachable block (ram,0x0041a71b)
// WARNING: Removing unreachable block (ram,0x0041a3f9)
// WARNING: Removing unreachable block (ram,0x0041a404)
// WARNING: Removing unreachable block (ram,0x0041a417)
// WARNING: Removing unreachable block (ram,0x0041a419)
// WARNING: Removing unreachable block (ram,0x0041a426)
// WARNING: Removing unreachable block (ram,0x0041a42b)
// WARNING: Removing unreachable block (ram,0x0041a431)
// WARNING: Removing unreachable block (ram,0x0041a43a)
// WARNING: Removing unreachable block (ram,0x0041a441)
// WARNING: Removing unreachable block (ram,0x0041a459)
// WARNING: Removing unreachable block (ram,0x0041a46a)
// WARNING: Removing unreachable block (ram,0x0041a478)
// WARNING: Removing unreachable block (ram,0x0041a4b7)
// WARNING: Removing unreachable block (ram,0x0041a4c0)
// WARNING: Removing unreachable block (ram,0x0041a6d8)
// WARNING: Removing unreachable block (ram,0x0041a4ce)
// WARNING: Removing unreachable block (ram,0x0041a4d8)
// WARNING: Removing unreachable block (ram,0x0041a4e5)
// WARNING: Removing unreachable block (ram,0x0041a4ec)
// WARNING: Removing unreachable block (ram,0x0041a4f6)
// WARNING: Removing unreachable block (ram,0x0041a4fb)
// WARNING: Removing unreachable block (ram,0x0041a500)
// WARNING: Removing unreachable block (ram,0x0041a50b)
// WARNING: Removing unreachable block (ram,0x0041a510)
// WARNING: Removing unreachable block (ram,0x0041a51a)
// WARNING: Removing unreachable block (ram,0x0041a51f)
// WARNING: Removing unreachable block (ram,0x0041a523)
// WARNING: Removing unreachable block (ram,0x0041a531)
// WARNING: Removing unreachable block (ram,0x0041a53e)
// WARNING: Removing unreachable block (ram,0x0041a54d)
// WARNING: Removing unreachable block (ram,0x0041a55a)
// WARNING: Removing unreachable block (ram,0x0041a577)
// WARNING: Removing unreachable block (ram,0x0041a57b)
// WARNING: Removing unreachable block (ram,0x0041a582)
// WARNING: Removing unreachable block (ram,0x0041a58b)
// WARNING: Removing unreachable block (ram,0x0041a58e)
// WARNING: Removing unreachable block (ram,0x0041a59f)
// WARNING: Removing unreachable block (ram,0x0041a5ad)
// WARNING: Removing unreachable block (ram,0x0041a5b8)
// WARNING: Removing unreachable block (ram,0x0041a5bf)
// WARNING: Removing unreachable block (ram,0x0041a5ea)
// WARNING: Removing unreachable block (ram,0x0041a5ef)
// WARNING: Removing unreachable block (ram,0x0041a5fa)
// WARNING: Removing unreachable block (ram,0x0041a603)
// WARNING: Removing unreachable block (ram,0x0041a609)
// WARNING: Removing unreachable block (ram,0x0041a60c)
// WARNING: Removing unreachable block (ram,0x0041a632)
// WARNING: Removing unreachable block (ram,0x0041a637)
// WARNING: Removing unreachable block (ram,0x0041a63c)
// WARNING: Removing unreachable block (ram,0x0041a649)
// WARNING: Removing unreachable block (ram,0x0041a65a)
// WARNING: Removing unreachable block (ram,0x0041a68b)
// WARNING: Removing unreachable block (ram,0x0041a660)
// WARNING: Removing unreachable block (ram,0x0041a686)
// WARNING: Removing unreachable block (ram,0x0041a66a)
// WARNING: Removing unreachable block (ram,0x0041a680)
// WARNING: Removing unreachable block (ram,0x0041a679)
// WARNING: Removing unreachable block (ram,0x0041a68e)
// WARNING: Removing unreachable block (ram,0x0041a6bb)
// WARNING: Removing unreachable block (ram,0x0041a698)
// WARNING: Removing unreachable block (ram,0x0041a6f6)
// WARNING: Removing unreachable block (ram,0x0041a43c)
// WARNING: Removing unreachable block (ram,0x0041a700)
// WARNING: Removing unreachable block (ram,0x0041a732)
// WARNING: Removing unreachable block (ram,0x0041a739)
// WARNING: Removing unreachable block (ram,0x0041a741)

void __cdecl
FUN_0041a09f(undefined2 *param_1,char **param_2,char *param_3,int param_4,int param_5,int param_6,
            undefined4 param_7,int param_8)

{
  char cVar1;
  undefined4 *puVar2;
  
  if (param_8 == 0) {
    puVar2 = (undefined4 *)func_0x89f6a13d();
    *puVar2 = 0x16;
    func_0x21f6a14d(0,0,0,0,0);
                    // WARNING: Bad instruction - Truncating control flow here
    halt_baddata();
  }
  for (; (((cVar1 = *param_3, cVar1 == ' ' || (cVar1 == '\t')) || (cVar1 == '\n')) ||
         (cVar1 == '\r')); param_3 = param_3 + 1) {
  }
                    // WARNING: Treating indirect jump as call
  (*(code *)0x90c3c9f1)();
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
    uVar5 = func_0xb2e1b3ff();
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
  if (DAT_004263a4 != 0) {
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
    uVar4 = func_0x40e2b581();
    func_0xbde7b58a(uVar4);
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
    else if (uVar3 == 0x76240240) {
      uVar5 = uVar5 | 0x3000000;
    }
    else if (uVar3 == 0x76240280) {
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



void __cdecl FUN_0041b4f8(char *param_1,int param_2,uint *param_3)

{
  uint uVar1;
  uint uVar2;
  uint uVar3;
  bool bVar4;
  bool bVar5;
  uint uVar6;
  uint uVar7;
  uint uVar8;
  uint uVar9;
  short local_1c;
  
  *param_3 = 0;
  param_3[1] = 0;
  param_3[2] = 0;
  if (param_2 != 0) {
    do {
      uVar2 = *param_3;
      uVar8 = *param_3;
      uVar1 = param_3[1];
      uVar9 = param_3[2];
      uVar7 = param_3[1] * 2;
      bVar4 = false;
      uVar6 = (param_3[2] * 2 | param_3[1] >> 0x1f) * 2 | uVar7 >> 0x1f;
      uVar3 = uVar2 * 4;
      uVar7 = (uVar7 | uVar2 >> 0x1f) * 2 | uVar2 * 2 >> 0x1f;
      uVar2 = uVar3 + uVar8;
      *param_3 = uVar3;
      param_3[1] = uVar7;
      param_3[2] = uVar6;
      if ((uVar2 < uVar3) || (uVar2 < uVar8)) {
        bVar4 = true;
      }
      bVar5 = false;
      *param_3 = uVar2;
      if (bVar4) {
        uVar8 = uVar7 + 1;
        if ((uVar8 < uVar7) || (uVar8 == 0)) {
          bVar5 = true;
        }
        param_3[1] = uVar8;
        if (bVar5) {
          param_3[2] = uVar6 + 1;
        }
      }
      uVar8 = param_3[1] + uVar1;
      bVar4 = false;
      if ((uVar8 < param_3[1]) || (uVar8 < uVar1)) {
        bVar4 = true;
      }
      param_3[1] = uVar8;
      if (bVar4) {
        param_3[2] = param_3[2] + 1;
      }
      param_3[2] = param_3[2] + uVar9;
      bVar4 = false;
      uVar1 = uVar2 * 2;
      uVar9 = uVar8 * 2 | uVar2 >> 0x1f;
      uVar8 = param_3[2] * 2 | uVar8 >> 0x1f;
      *param_3 = uVar1;
      param_3[1] = uVar9;
      param_3[2] = uVar8;
      uVar2 = uVar1 + (int)*param_1;
      if ((uVar2 < uVar1) || (uVar2 < (uint)(int)*param_1)) {
        bVar4 = true;
      }
      *param_3 = uVar2;
      if (bVar4) {
        uVar2 = uVar9 + 1;
        bVar4 = false;
        if ((uVar2 < uVar9) || (uVar2 == 0)) {
          bVar4 = true;
        }
        param_3[1] = uVar2;
        if (bVar4) {
          param_3[2] = uVar8 + 1;
        }
      }
      param_2 = param_2 + -1;
      param_1 = param_1 + 1;
    } while (param_2 != 0);
  }
  while (param_3[2] == 0) {
    param_3[2] = param_3[1] >> 0x10;
    local_1c = local_1c + 0x24e;
    param_3[1] = param_3[1] << 0x10 | *param_3 >> 0x10;
    *param_3 = *param_3 << 0x10;
  }
  uVar2 = param_3[2];
  while ((uVar2 & 0x8000) == 0) {
    uVar8 = *param_3;
    uVar1 = param_3[1];
    local_1c = local_1c + 0x24e;
    *param_3 = uVar8 * 2;
    uVar2 = param_3[2] * 2;
    param_3[1] = uVar1 * 2 | uVar8 >> 0x1f;
    param_3[2] = uVar2 | uVar1 >> 0x1f;
  }
  *(short *)((int)param_3 + 10) = local_1c;
  func_0xf1d6b712();
  return;
}



void __fastcall FUN_00436fd4(undefined4 param_1,undefined4 param_2)

{
  int iVar1;
  code *pcVar2;
  int iVar3;
  int iVar4;
  
  iVar4 = 0;
  iVar1 = (**(code **)(PTR_IMAGE_DOS_HEADER_00436fc8 + DAT_00436fc0))
                    (0,DAT_00436fb4,0x1000,0x40,PTR_IMAGE_DOS_HEADER_00436fc8,param_2);
  DAT_00436fd0 = *(undefined4 *)(DAT_00436fd0 + iVar4);
  DAT_00436fcc = *(undefined4 *)(DAT_00436fcc + iVar4);
  iVar3 = DAT_00436fb0 + iVar4;
  (*(code *)(DAT_00436fbc + iVar4))(iVar3,iVar1,&DAT_00436fcc,iVar4,iVar1);
  pcVar2 = (code *)(iVar1 + DAT_00436fb8);
  iVar1 = *(int *)(pcVar2 + -4);
  *(int *)(pcVar2 + (8 - (iVar1 + 4))) = iVar3;
  *(int *)(pcVar2 + (0x14 - (iVar1 + 4))) = DAT_00436fbc;
  DAT_0043706b = (code *)(*pcVar2)(iVar3);
                    // WARNING: Could not recover jumptable at 0x00437069. Too many branches
                    // WARNING: Treating indirect jump as call
  (*DAT_0043706b)();
  return;
}


