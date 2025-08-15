#pragma once

#include "base/helpers.h"

// debug print 
#ifdef _DEBUG
#define DEBUG_PRINT(x, ...) BeaconPrintf(CALLBACK_OUTPUT, x, ##__VA_ARGS__)
#else
// temp coff loader debuggin
#define DEBUG_PRINT(x, ...) BeaconPrintf(CALLBACK_OUTPUT, x, ##__VA_ARGS__)
#endif

#define MAX_STREAM_NAME 64 // for id stomping, dont think its necessary could use blah[1] for the interp

extern "C" {
    /* grokking the clr headers */
    typedef struct __CLRMetaData {
        DWORD Signature; // always 0x424A5342 [42 53 4A 42]
        WORD MajorVersion; // always 0x0001 [01 00]
        WORD MinorVersion; // always 0x0001 [01 00]
        DWORD Reserved1; // always 0x00000000 [00 00 00 00]
        DWORD VersionStringLength;
        //then variable length VersionString; // null terminated in file. VersionStringLength includes the null(s) in the length, and also is always rounded up to a multiple of 4.
        //WORD Flags; // always 0x0000 [00 00]
        //WORD NumberOfStreams;
    } CLRMetaData;

    typedef struct __CLRStreamHeader {
        DWORD Offset;
        DWORD Size;
        // followed by a null terminated name
        char StreamName[MAX_STREAM_NAME];
    } CLRStreamHeader;

    typedef struct __CLRTableHeader {
        DWORD Reserved;
        BYTE MajorVersion;
        BYTE MinorVersion;
        // After that is a single byte indicating whether heap offsets within the table use 2 or 4 bytes
        //  - bit 1 for #Strings, bit 2 for #GUID, bit 3 for #Blob
        BYTE HeapOffsetSizes;
        BYTE Reserved2;
        // The next 8 bytes is a bit vector indicating which tables are actually present in the stream -
        //  although a table may be defined in the CLR spec, it doesnÅft have to be present in an assembly if it isnÅft needed. 
        INT64 MaskValid; // qword
        // The next 8 bytes are also a bitvector, but these indicate which tables are sorted.
        INT64 MaskSorted;
        // Following the two bitvectors are a series of uint32 values specifying the 
        // rowcounts of all the tables present in the metadata, ordered by their table number
    } CLRTableHeader;

    typedef struct _TargetAssembly {
        LPWSTR AssemblyIdentity;
        unsigned char* AssemblyBytes;
        DWORD AssemblySize;
        IStream* AssemblyStream;
    } TargetAssembly;

    typedef struct _AssemblyBindInfo
    {
        DWORD dwAppDomainId;
        LPCWSTR lpReferencedIdentity;
        LPCWSTR lpPostPolicyIdentity;
        DWORD ePolicyLevel;
    } AssemblyBindInfo;


    typedef struct _ModuleBindInfo
    {
        DWORD dwAppDomainId;
        LPCWSTR lpAssemblyIdentity;
        LPCWSTR lpModuleName;
    } ModuleBindInfo;


    typedef struct _Type                        IType;
    typedef struct _MethodInfo                  IMethodInfo;
    typedef struct _Assembly                    IAssembly;



#undef DUMMY_METHOD
#define DUMMY_METHOD(x) HRESULT ( STDMETHODCALLTYPE *dummy_##x )(IAssembly *This)

    typedef struct _AssemblyVtbl {
        BEGIN_INTERFACE

            HRESULT(STDMETHODCALLTYPE* QueryInterface)(
                IAssembly* This,
                REFIID riid,
                void** ppvObject);

        ULONG(STDMETHODCALLTYPE* AddRef)(
            IAssembly* This);

        ULONG(STDMETHODCALLTYPE* Release)(
            IAssembly* This);

        DUMMY_METHOD(GetTypeInfoCount);
        DUMMY_METHOD(GetTypeInfo);
        DUMMY_METHOD(GetIDsOfNames);

        DUMMY_METHOD(Invoke);
        DUMMY_METHOD(ToString);
        DUMMY_METHOD(Equals);
        DUMMY_METHOD(GetHashCode);
        DUMMY_METHOD(GetType);
        DUMMY_METHOD(CodeBase);
        DUMMY_METHOD(EscapedCodeBase);
        DUMMY_METHOD(GetName);
        DUMMY_METHOD(GetName_2);
        //DUMMY_METHOD(FullName);

        HRESULT(STDMETHODCALLTYPE* get_FullName)(
            IAssembly* This,
            BSTR* pRetVal);
        
        HRESULT(STDMETHODCALLTYPE* get_EntryPoint)(
            IAssembly* This,
            IMethodInfo** pRetVal);

        HRESULT(STDMETHODCALLTYPE* GetType_2)(
            IAssembly* This,
            BSTR        name,
            IType** pRetVal);

        DUMMY_METHOD(GetType_3);
        DUMMY_METHOD(GetExportedTypes);
        //DUMMY_METHOD(GetTypes);
        HRESULT(STDMETHODCALLTYPE* GetTypes)(
            IAssembly* This,
            /*[out,retval]*/ SAFEARRAY** pRetVal);
        DUMMY_METHOD(GetManifestResourceStream);
        DUMMY_METHOD(GetManifestResourceStream_2);
        DUMMY_METHOD(GetFile);
        DUMMY_METHOD(GetFiles);
        DUMMY_METHOD(GetFiles_2);
        DUMMY_METHOD(GetManifestResourceNames);
        DUMMY_METHOD(GetManifestResourceInfo);
        DUMMY_METHOD(Location);
        DUMMY_METHOD(Evidence);
        DUMMY_METHOD(GetCustomAttributes);
        DUMMY_METHOD(GetCustomAttributes_2);
        DUMMY_METHOD(IsDefined);
        DUMMY_METHOD(GetObjectData);
        DUMMY_METHOD(add_ModuleResolve);
        DUMMY_METHOD(remove_ModuleResolve);
        DUMMY_METHOD(GetType_4);
        DUMMY_METHOD(GetSatelliteAssembly);
        DUMMY_METHOD(GetSatelliteAssembly_2);
        DUMMY_METHOD(LoadModule);
        DUMMY_METHOD(LoadModule_2);
        DUMMY_METHOD(CreateInstance);
        DUMMY_METHOD(CreateInstance_2);
        DUMMY_METHOD(CreateInstance_3);
        DUMMY_METHOD(GetLoadedModules);
        DUMMY_METHOD(GetLoadedModules_2);
        DUMMY_METHOD(GetModules);
        DUMMY_METHOD(GetModules_2);
        DUMMY_METHOD(GetModule);
        DUMMY_METHOD(GetReferencedAssemblies);
        DUMMY_METHOD(GlobalAssemblyCache);

        

        END_INTERFACE
    } AssemblyVtbl;

    typedef enum _BindingFlags {
        BindingFlags_Default = 0,
        BindingFlags_IgnoreCase = 1,
        BindingFlags_DeclaredOnly = 2,
        BindingFlags_Instance = 4,
        BindingFlags_Static = 8,
        BindingFlags_Public = 16,
        BindingFlags_NonPublic = 32,
        BindingFlags_FlattenHierarchy = 64,
        BindingFlags_InvokeMethod = 256,
        BindingFlags_CreateInstance = 512,
        BindingFlags_GetField = 1024,
        BindingFlags_SetField = 2048,
        BindingFlags_GetProperty = 4096,
        BindingFlags_SetProperty = 8192,
        BindingFlags_PutDispProperty = 16384,
        BindingFlags_PutRefDispProperty = 32768,
        BindingFlags_ExactBinding = 65536,
        BindingFlags_SuppressChangeType = 131072,
        BindingFlags_OptionalParamBinding = 262144,
        BindingFlags_IgnoreReturn = 16777216
    } BindingFlags;

    typedef struct _Assembly {
        AssemblyVtbl* lpVtbl;
    } Assembly;

typedef struct _AppDomain                   IAppDomain;
#undef DUMMY_METHOD
#define DUMMY_METHOD(x) HRESULT ( STDMETHODCALLTYPE *dummy_##x )(IAppDomain *This)

    typedef struct _AppDomainVtbl {
        BEGIN_INTERFACE

            HRESULT(STDMETHODCALLTYPE* QueryInterface)(
                IAppDomain* This,
                /* [in] */ REFIID riid,
                /* [iid_is][out] */ void** ppvObject);

        ULONG(STDMETHODCALLTYPE* AddRef)(
            IAppDomain* This);

        ULONG(STDMETHODCALLTYPE* Release)(
            IAppDomain* This);

        DUMMY_METHOD(GetTypeInfoCount);
        DUMMY_METHOD(GetTypeInfo);
        DUMMY_METHOD(GetIDsOfNames);
        DUMMY_METHOD(Invoke);

        DUMMY_METHOD(ToString);
        DUMMY_METHOD(Equals);
        DUMMY_METHOD(GetHashCode);
        DUMMY_METHOD(GetType);
        DUMMY_METHOD(InitializeLifetimeService);
        DUMMY_METHOD(GetLifetimeService);
        DUMMY_METHOD(Evidence);
        DUMMY_METHOD(add_DomainUnload);
        DUMMY_METHOD(remove_DomainUnload);
        DUMMY_METHOD(add_AssemblyLoad);
        DUMMY_METHOD(remove_AssemblyLoad);
        DUMMY_METHOD(add_ProcessExit);
        DUMMY_METHOD(remove_ProcessExit);
        DUMMY_METHOD(add_TypeResolve);
        DUMMY_METHOD(remove_TypeResolve);
        DUMMY_METHOD(add_ResourceResolve);
        DUMMY_METHOD(remove_ResourceResolve);
        DUMMY_METHOD(add_AssemblyResolve);
        DUMMY_METHOD(remove_AssemblyResolve);
        DUMMY_METHOD(add_UnhandledException);
        DUMMY_METHOD(remove_UnhandledException);
        DUMMY_METHOD(DefineDynamicAssembly);
        DUMMY_METHOD(DefineDynamicAssembly_2);
        DUMMY_METHOD(DefineDynamicAssembly_3);
        DUMMY_METHOD(DefineDynamicAssembly_4);
        DUMMY_METHOD(DefineDynamicAssembly_5);
        DUMMY_METHOD(DefineDynamicAssembly_6);
        DUMMY_METHOD(DefineDynamicAssembly_7);
        DUMMY_METHOD(DefineDynamicAssembly_8);
        DUMMY_METHOD(DefineDynamicAssembly_9);
        DUMMY_METHOD(CreateInstance);
        DUMMY_METHOD(CreateInstanceFrom);
        DUMMY_METHOD(CreateInstance_2);
        DUMMY_METHOD(CreateInstanceFrom_2);
        DUMMY_METHOD(CreateInstance_3);
        DUMMY_METHOD(CreateInstanceFrom_3);
        DUMMY_METHOD(Load);
        HRESULT(STDMETHODCALLTYPE* Load_2) (
            IAppDomain* This,
            BSTR assemblyString,
            IAssembly** pRetVal
            );

        HRESULT(STDMETHODCALLTYPE* Load_3)( // don't use this :( 
            IAppDomain* This,
            SAFEARRAY* rawAssembly,
            IAssembly** pRetVal);

        DUMMY_METHOD(Load_4);
        DUMMY_METHOD(Load_5);
        DUMMY_METHOD(Load_6);
        DUMMY_METHOD(Load_7);
        DUMMY_METHOD(ExecuteAssembly);
        DUMMY_METHOD(ExecuteAssembly_2);
        DUMMY_METHOD(ExecuteAssembly_3);
        DUMMY_METHOD(FriendlyName);
        DUMMY_METHOD(BaseDirectory);
        DUMMY_METHOD(RelativeSearchPath);
        DUMMY_METHOD(ShadowCopyFiles);
        DUMMY_METHOD(GetAssemblies);
        DUMMY_METHOD(AppendPrivatePath);
        DUMMY_METHOD(ClearPrivatePath);
        DUMMY_METHOD(SetShadowCopyPath);
        DUMMY_METHOD(ClearShadowCopyPath);
        DUMMY_METHOD(SetCachePath);
        DUMMY_METHOD(SetData);
        DUMMY_METHOD(GetData);
        DUMMY_METHOD(SetAppDomainPolicy);
        DUMMY_METHOD(SetThreadPrincipal);
        DUMMY_METHOD(SetPrincipalPolicy);
        DUMMY_METHOD(DoCallBack);
        DUMMY_METHOD(DynamicDirectory);

        END_INTERFACE
    } AppDomainVtbl;

    typedef struct _AppDomain {
        AppDomainVtbl* lpVtbl;
    } AppDomain;

    // For debugging convenience using the template, don't declare these in debug config
#ifndef _DEBUG



    // CLR GUIDs 
    static GUID IID_AppDomain = { 0x05F696DC, 0x2B29, 0x3663, {0xAD, 0x8B, 0xC4,0x38, 0x9C, 0xF2, 0xA7, 0x13} };
    static GUID CLSID_CLRMetaHost = { 0x9280188d, 0xe8e, 0x4867, {0xb3, 0xc, 0x7f, 0xa8, 0x38, 0x84, 0xe8, 0xde} };
    static GUID IID_ICLRMetaHost = { 0xD332DB9E, 0xB9B3, 0x4125, {0x82, 0x07, 0xA1, 0x48, 0x84, 0xF5, 0x32, 0x16} };
    static GUID IID_ICLRRuntimeInfo = { 0xBD39D1D2, 0xBA2F, 0x486a, {0x89, 0xB0, 0xB4, 0xB0, 0xCB, 0x46, 0x68, 0x91} };
    static GUID IID_ICorRuntimeHost = { 0xcb2f6722, 0xab3a, 0x11d2, {0x9c, 0x40, 0x00, 0xc0, 0x4f, 0xa3, 0x0a, 0x3e} };
    static GUID CLSID_CorRuntimeHost = { 0xcb2f6723, 0xab3a, 0x11d2, {0x9c, 0x40, 0x00, 0xc0, 0x4f, 0xa3, 0x0a, 0x3e} };
    static GUID CLSID_CLRRuntimeHost = { 0x90F1A06E, 0x7712, 0x4762, {0x86, 0xB5, 0x7A, 0x5E, 0xBA, 0x6B, 0xDB, 0x02} };
    static GUID IID_ICLRRuntimeHost = { 0x90F1A06C, 0x7712, 0x4762, {0x86, 0xB5, 0x7A, 0x5E, 0xBA, 0x6B, 0xDB, 0x02 } };
    static GUID IID_ICLRAssemblyIdentityManager = { 0x15f0a9da, 0x3ff6, 0x4393, {0x9d, 0xa9, 0xfd, 0xfd, 0x28, 0x4e, 0x69, 0x72} };
    static GUID IID_IAssemblyName = { 0xB42B6AAC, 0x317E, 0x34D5, {0x9F, 0xA9, 0x09, 0x3B, 0xB4, 0x16, 0x0C, 0x50 } };

    // alternate decl style?
    EXTERN_GUID(IID_IHostMemoryManager, 0x7BC698D1, 0xF9E3, 0x4460, 0x9C, 0xDE, 0xD0, 0x42, 0x48, 0xE9, 0xFA, 0x25);
    EXTERN_GUID(IID_IHostAssemblyManager, 0x613dabd7, 0x62b2, 0x493e, 0x9e, 0x65, 0xc1, 0xe3, 0x2a, 0x1e, 0x0c, 0x5e);
    /*

    EXTERN_GUID(CLSID_CLRMetaHost, 0x9280188d, 0xe8e, 0x4867, 0xb3, 0xc, 0x7f, 0xa8, 0x38, 0x84, 0xe8, 0xde);
    */

    /* DFR DECLARATIONS */
	WINBASEAPI void* WINAPI MSVCRT$malloc(size_t size);
#define malloc MSVCRT$malloc

    WINBASEAPI void WINAPI MSVCRT$free(
        void* memblock
    );
#define free MSVCRT$free

    WINBASEAPI void* WINAPI MSVCRT$realloc(
        void* memblock,
        size_t size
    );
#define realloc MSVCRT$realloc

	WINBASEAPI void* __cdecl MSVCRT$memcpy(void* __restrict _Dst, const void* __restrict _Src, size_t _MaxCount);
#define memcpy MSVCRT$memcpy

    WINBASEAPI void* __cdecl MSVCRT$memset(void* __restrict _Dst, int c, size_t _MaxCount);
#define memset MSVCRT$memset

    WINBASEAPI int __cdecl MSVCRT$memcmp(
        const void* buffer1,
        const void* buffer2,
        size_t count
    );
#define memcmp MSVCRT$memcmp

    WINBASEAPI int __cdecl MSVCRT$wcscmp(
        const wchar_t* string1,
        const wchar_t* string2
    );
#define wcscmp MSVCRT$wcscmp

    // yes i am lazy enough to import this thank you very much
    WINBASEAPI int __cdecl MSVCRT$strcmp(
        const char* string1,
        const char* string2
    );
#define strcmp MSVCRT$strcmp

	WINBASEAPI SIZE_T WINAPI MSVCRT$strlen(const char* str);
#define strlen MSVCRT$strlen

	WINBASEAPI errno_t __cdecl MSVCRT$mbstowcs_s(size_t* pReturnValue, wchar_t* wcstr, size_t sizeInWords, const char* mbstr, size_t count);
#define mbstowcs_s MSVCRT$mbstowcs_s

	/* WIN32 API DEFINITIONS */
	// isn't this just declspec_import? 
	// i guess the DFR helpers aren't that useful here so lets just manually do all of this
	WINBASEAPI IStream* WINAPI SHLWAPI$SHCreateMemStream(const BYTE* pInit, UINT cbInit);
#define SHCreateMemStream SHLWAPI$SHCreateMemStream

	// SHELL32
	WINBASEAPI LPWSTR* WINAPI SHELL32$CommandLineToArgvW(
		LPCWSTR lpCmdLine,
		int* pNumArgs
	);
#define CommandLineToArgvW SHELL32$CommandLineToArgvW

	// OLEAUTO 
    WINBASEAPI SAFEARRAY* WINAPI OLEAUT32$SafeArrayCreate(
        VARTYPE        vt,
        UINT           cDims,
        SAFEARRAYBOUND* rgsabound
    );
#define SafeArrayCreate OLEAUT32$SafeArrayCreate

    WINBASEAPI HRESULT WINAPI OLEAUT32$SafeArrayLock(
        SAFEARRAY* psa
    );
#define SafeArrayLock OLEAUT32$SafeArrayLock

    WINBASEAPI HRESULT WINAPI OLEAUT32$SafeArrayUnlock(
        SAFEARRAY* psa
    );
#define SafeArrayUnlock OLEAUT32$SafeArrayUnlock

    WINBASEAPI HRESULT WINAPI OLEAUT32$SafeArrayDestroy(
        SAFEARRAY* psa
    );
#define SafeArrayDestroy OLEAUT32$SafeArrayDestroy

	WINBASEAPI SAFEARRAY* WINAPI OLEAUT32$SafeArrayCreateVector(
		VARTYPE vt,
		LONG    lLbound,
		ULONG   cElements
	);
#define SafeArrayCreateVector OLEAUT32$SafeArrayCreateVector

	WINBASEAPI HRESULT WINAPI OLEAUT32$SafeArrayPutElement(
		SAFEARRAY* psa,
		LONG* rgIndices,
		void* pv
	);
#define SafeArrayPutElement OLEAUT32$SafeArrayPutElement

	WINBASEAPI BSTR WINAPI OLEAUT32$SysAllocString(
		const OLECHAR* psz
	);
#define SysAllocString OLEAUT32$SysAllocString

    
    WINBASEAPI void  WINAPI OLEAUT32$SysFreeString(
        _Frees_ptr_opt_ BSTR bstrString
    );
#define SysFreeString OLEAUT32$SysFreeString

    WINBASEAPI HRESULT WINAPI OLEAUT32$SafeArrayAccessData(
        SAFEARRAY* psa,
        void HUGEP** ppvData
    );
#define SafeArrayAccessData OLEAUT32$SafeArrayAccessData

    WINBASEAPI HRESULT WINAPI OLEAUT32$SafeArrayGetLBound(
        SAFEARRAY* psa,
        UINT      nDim,
        LONG* plLbound
    );
#define SafeArrayGetLBound OLEAUT32$SafeArrayGetLBound

    WINBASEAPI HRESULT WINAPI OLEAUT32$SafeArrayGetUBound(
        SAFEARRAY* psa,
        UINT      nDim,
        LONG* plUbound
    );
#define SafeArrayGetUBound OLEAUT32$SafeArrayGetUBound

    WINBASEAPI HRESULT WINAPI OLEAUT32$VariantClear(
        VARIANTARG* pvarg
    );
#define VariantClear OLEAUT32$VariantClear
    // MSCOREE
    WINBASEAPI HRESULT WINAPI MSCOREE$CLRCreateInstance(
        REFCLSID clsid,
        REFIID riid,
        LPVOID* ppInterface);
#define CLRCreateInstance MSCOREE$CLRCreateInstance

    // KERNEL32
    WINBASEAPI HGLOBAL WINAPI KERNEL32$GlobalAlloc(UINT uFlags, SIZE_T dwBytes);
#define GlobalAlloc KERNEL32$GlobalAlloc
    WINBASEAPI HGLOBAL WINAPI KERNEL32$GlobalFree(HGLOBAL hMem);
#define GlobalFree KERNEL32$GlobalFree

    WINBASEAPI HANDLE KERNEL32$CreateNamedPipeA(
        LPCSTR                lpName,
        DWORD                 dwOpenMode,
        DWORD                 dwPipeMode,
        DWORD                 nMaxInstances,
        DWORD                 nOutBufferSize,
        DWORD                 nInBufferSize,
        DWORD                 nDefaultTimeOut,
        LPSECURITY_ATTRIBUTES lpSecurityAttributes
    );
#define CreateNamedPipeA KERNEL32$CreateNamedPipeA

    // connect to pipe
    WINBASEAPI HANDLE WINAPI KERNEL32$CreateFileA(
        LPCSTR                lpFileName,
        DWORD                 dwDesiredAccess,
        DWORD                 dwShareMode,
        LPSECURITY_ATTRIBUTES lpSecurityAttributes,
        DWORD                 dwCreationDisposition,
        DWORD                 dwFlagsAndAttributes,
        HANDLE                hTemplateFile
    );
#define CreateFileA KERNEL32$CreateFileA

    WINBASEAPI BOOL WINAPI KERNEL32$WriteFile(
        HANDLE       hFile,
        LPCVOID      lpBuffer,
        DWORD        nNumberOfBytesToWrite,
        LPDWORD      lpNumberOfBytesWritten,
        LPOVERLAPPED lpOverlapped
    );
#define WriteFile KERNEL32$WriteFile

    WINBASEAPI HWND WINAPI KERNEL32$GetConsoleWindow(void);
#define GetConsoleWindow KERNEL32$GetConsoleWindow

    WINBASEAPI BOOL WINAPI KERNEL32$AllocConsole(void);
#define AllocConsole KERNEL32$AllocConsole

    WINBASEAPI BOOL USER32$ShowWindow(
        HWND hWnd,
        int  nCmdShow
    );
#define ShowWindow USER32$ShowWindow

    WINBASEAPI HANDLE WINAPI KERNEL32$GetStdHandle(
        _In_ DWORD nStdHandle
    );
#define GetStdHandle KERNEL32$GetStdHandle

    WINBASEAPI BOOL WINAPI KERNEL32$SetStdHandle(
        _In_ DWORD  nStdHandle,
        _In_ HANDLE hHandle
    );
#define SetStdHandle KERNEL32$SetStdHandle

    // !!!! DISK TESTING ONLY !!!!
    WINBASEAPI BOOL WINAPI KERNEL32$ConnectNamedPipe(
        HANDLE       hNamedPipe,
        LPOVERLAPPED lpOverlapped
    );
#define ConnectNamedPipe KERNEL32$ConnectNamedPipe

    WINBASEAPI DWORD WINAPI KERNEL32$GetFileSize(
        HANDLE  hFile,
        LPDWORD lpFileSizeHigh
    );
#define GetFileSize KERNEL32$GetFileSize

    WINBASEAPI BOOL WINAPI KERNEL32$ReadFile(
        HANDLE       hFile,
        LPVOID       lpBuffer,
        DWORD        nNumberOfBytesToRead,
        LPDWORD      lpNumberOfBytesRead,
        LPOVERLAPPED lpOverlapped
    );
#define ReadFile KERNEL32$ReadFile

    WINBASEAPI BOOL WINAPI KERNEL32$CloseHandle(
        HANDLE hObject
    );
#define CloseHandle KERNEL32$CloseHandle
    // END DISK TESTING


    // recall inline IID helper so we don't invoke guiddef's macros which refs unlinked memcmp??
    /*
    __inline int InlineIsEqualGUID(REFGUID rguid1, REFGUID rguid2)
{
   return (
      ((unsigned long *) &rguid1)[0] == ((unsigned long *) &rguid2)[0] &&
      ((unsigned long *) &rguid1)[1] == ((unsigned long *) &rguid2)[1] &&
      ((unsigned long *) &rguid1)[2] == ((unsigned long *) &rguid2)[2] &&
      ((unsigned long *) &rguid1)[3] == ((unsigned long *) &rguid2)[3]);
}
    */

    typedef struct _ICLRRuntimeHost             ICLRRuntimeHost;
    typedef struct _IHostControl                IHostControl;
    typedef struct _IHostAssemblyManager        IHostAssemblyManager;
    typedef struct _ICLRAssemblyReferenceList   ICLRAssemblyReferenceList;
    typedef struct _ICLRControl                 ICLRControl;
    typedef struct _ICLRAssemblyIdentityManager ICLRAssemblyIdentityManager;
    typedef struct _ICLRReferenceAssemblyEnum   ICLRReferenceAssemblyEnum;
    typedef struct _ICLRProbingAssemblyEnum     ICLRProbingAssemblyEnum;

    typedef struct _ICLRMetaHost                ICLRMetaHost;
    typedef struct _ICLRRuntimeInfo             ICLRRuntimeInfo;
    typedef struct _ICorRuntimeHost             ICorRuntimeHost;
    typedef struct _ICorConfiguration           ICorConfiguration;
    typedef struct _IGCThreadControl            IGCThreadControl;
    typedef struct _IGCHostControl              IGCHostControl;
    typedef struct _IDebuggerThreadControl      IDebuggerThreadControl;
    
   
    typedef struct _Binder                      IBinder;
   

    typedef struct _IHostAssemblyStore          IHostAssemblyStore;


    typedef void* HDOMAINENUM;



    typedef HRESULT(__stdcall* CLRCreateInstanceFnPtr)(
        REFCLSID clsid,
        REFIID riid,
        LPVOID* ppInterface);

    typedef HRESULT(__stdcall* CreateInterfaceFnPtr)(
        REFCLSID clsid,
        REFIID riid,
        LPVOID* ppInterface);

    typedef HRESULT(__stdcall* FExecuteInAppDomainCallback)(
        void* cookie);


    typedef HRESULT(__stdcall* CallbackThreadSetFnPtr)(void);

    typedef HRESULT(__stdcall* CallbackThreadUnsetFnPtr)(void);

    typedef void(__stdcall* RuntimeLoadedCallbackFnPtr)(
        ICLRRuntimeInfo* pRuntimeInfo,
        CallbackThreadSetFnPtr pfnCallbackThreadSet,
        CallbackThreadUnsetFnPtr pfnCallbackThreadUnset);

    typedef struct ICLRProbingAssemblyEnumVtbl
    {
        BEGIN_INTERFACE

            HRESULT(STDMETHODCALLTYPE* QueryInterface)(
                ICLRProbingAssemblyEnum* This,
                /* [in] */ REFIID riid,
                /* [annotation][iid_is][out] */
                _COM_Outptr_  void** ppvObject);

        ULONG(STDMETHODCALLTYPE* AddRef)(
            ICLRProbingAssemblyEnum* This);

        ULONG(STDMETHODCALLTYPE* Release)(
            ICLRProbingAssemblyEnum* This);

        HRESULT(STDMETHODCALLTYPE* Get)(
            ICLRProbingAssemblyEnum* This,
            /* [in] */ DWORD dwIndex,
            /* [annotation][size_is][out] */
            _Out_writes_all_(*pcchBufferSize)  LPWSTR pwzBuffer,
            /* [out][in] */ DWORD* pcchBufferSize);

        END_INTERFACE
    } ICLRProbingAssemblyEnumVtbl;

    interface _ICLRProbingAssemblyEnum
    {
        CONST_VTBL struct ICLRProbingAssemblyEnumVtbl* lpVtbl;
    };

    typedef struct ICLRReferenceAssemblyEnumVtbl
    {
        BEGIN_INTERFACE

            HRESULT(STDMETHODCALLTYPE* QueryInterface)(
                ICLRReferenceAssemblyEnum* This,
                /* [in] */ REFIID riid,
                /* [annotation][iid_is][out] */
                _COM_Outptr_  void** ppvObject);

        ULONG(STDMETHODCALLTYPE* AddRef)(
            ICLRReferenceAssemblyEnum* This);

        ULONG(STDMETHODCALLTYPE* Release)(
            ICLRReferenceAssemblyEnum* This);

        HRESULT(STDMETHODCALLTYPE* Get)(
            ICLRReferenceAssemblyEnum* This,
            /* [in] */ DWORD dwIndex,
            /* [annotation][size_is][out] */
            _Out_writes_all_(*pcchBufferSize)  LPWSTR pwzBuffer,
            /* [out][in] */ DWORD* pcchBufferSize);

        END_INTERFACE
    } ICLRReferenceAssemblyEnumVtbl;

    interface _ICLRReferenceAssemblyEnum
    {
        CONST_VTBL struct ICLRReferenceAssemblyEnumVtbl* lpVtbl;
    };

    typedef struct ICLRAssemblyIdentityManagerVtbl
    {
        BEGIN_INTERFACE

            HRESULT(STDMETHODCALLTYPE* QueryInterface)(
                ICLRAssemblyIdentityManager* This,
                /* [in] */ REFIID riid,
                /* [annotation][iid_is][out] */
                _COM_Outptr_  void** ppvObject);

        ULONG(STDMETHODCALLTYPE* AddRef)(
            ICLRAssemblyIdentityManager* This);

        ULONG(STDMETHODCALLTYPE* Release)(
            ICLRAssemblyIdentityManager* This);

        HRESULT(STDMETHODCALLTYPE* GetCLRAssemblyReferenceList)(
            ICLRAssemblyIdentityManager* This,
            /* [in] */ LPCWSTR* ppwzAssemblyReferences,
            /* [in] */ DWORD dwNumOfReferences,
            /* [out] */ ICLRAssemblyReferenceList** ppReferenceList);

        HRESULT(STDMETHODCALLTYPE* GetBindingIdentityFromFile)(
            ICLRAssemblyIdentityManager* This,
            /* [in] */ LPCWSTR pwzFilePath,
            /* [in] */ DWORD dwFlags,
            /* [annotation][size_is][out] */
            _Out_writes_all_(*pcchBufferSize)  LPWSTR pwzBuffer,
            /* [out][in] */ DWORD* pcchBufferSize);

        HRESULT(STDMETHODCALLTYPE* GetBindingIdentityFromStream)(
            ICLRAssemblyIdentityManager* This,
            /* [in] */ IStream* pStream,
            /* [in] */ DWORD dwFlags,
            /* [annotation][size_is][out] */
            _Out_writes_all_(*pcchBufferSize)  LPWSTR pwzBuffer,
            /* [out][in] */ DWORD* pcchBufferSize);

        HRESULT(STDMETHODCALLTYPE* GetReferencedAssembliesFromFile)(
            ICLRAssemblyIdentityManager* This,
            /* [in] */ LPCWSTR pwzFilePath,
            /* [in] */ DWORD dwFlags,
            /* [in] */ ICLRAssemblyReferenceList* pExcludeAssembliesList,
            /* [out] */ ICLRReferenceAssemblyEnum** ppReferenceEnum);

        HRESULT(STDMETHODCALLTYPE* GetReferencedAssembliesFromStream)(
            ICLRAssemblyIdentityManager* This,
            /* [in] */ IStream* pStream,
            /* [in] */ DWORD dwFlags,
            /* [in] */ ICLRAssemblyReferenceList* pExcludeAssembliesList,
            /* [out] */ ICLRReferenceAssemblyEnum** ppReferenceEnum);

        HRESULT(STDMETHODCALLTYPE* GetProbingAssembliesFromReference)(
            ICLRAssemblyIdentityManager* This,
            /* [in] */ DWORD dwMachineType,
            /* [in] */ DWORD dwFlags,
            /* [in] */ LPCWSTR pwzReferenceIdentity,
            /* [out] */ ICLRProbingAssemblyEnum** ppProbingAssemblyEnum);

        HRESULT(STDMETHODCALLTYPE* IsStronglyNamed)(
            ICLRAssemblyIdentityManager* This,
            /* [in] */ LPCWSTR pwzAssemblyIdentity,
            /* [out] */ BOOL* pbIsStronglyNamed);

        END_INTERFACE
    } ICLRAssemblyIdentityManagerVtbl;

    interface _ICLRAssemblyIdentityManager
    {
        CONST_VTBL struct ICLRAssemblyIdentityManagerVtbl* lpVtbl;
    };

    typedef struct IHostAssemblyStoreVtbl
    {
        BEGIN_INTERFACE

            HRESULT(STDMETHODCALLTYPE* QueryInterface)(
                IHostAssemblyStore* This,
                /* [in] */ REFIID riid,
                /* [annotation][iid_is][out] */
                _COM_Outptr_  void** ppvObject);

        ULONG(STDMETHODCALLTYPE* AddRef)(
            IHostAssemblyStore* This);

        ULONG(STDMETHODCALLTYPE* Release)(
            IHostAssemblyStore* This);

        HRESULT(STDMETHODCALLTYPE* ProvideAssembly)(
            IHostAssemblyStore* This,
            /* [in] */ AssemblyBindInfo* pBindInfo,
            /* [out] */ UINT64* pAssemblyId,
            /* [out] */ UINT64* pContext,
            /* [out] */ IStream** ppStmAssemblyImage,
            /* [out] */ IStream** ppStmPDB);

        HRESULT(STDMETHODCALLTYPE* ProvideModule)(
            IHostAssemblyStore* This,
            /* [in] */ ModuleBindInfo* pBindInfo,
            /* [out] */ DWORD* pdwModuleId,
            /* [out] */ IStream** ppStmModuleImage,
            /* [out] */ IStream** ppStmPDB);

        END_INTERFACE
    } IHostAssemblyStoreVtbl;

    interface _IHostAssemblyStore
    {
        CONST_VTBL struct IHostAssemblyStoreVtbl* lpVtbl;
    };

    /* Starting the long list of virtual tables... */
    // recall that this is really just bare bones implementing class interfaces
    // table of function pointers with signatures, and we need to explicitly
    // specify the usually implicit "this" pointer
    typedef struct ICLRControlVtbl
    {
        BEGIN_INTERFACE

            HRESULT(STDMETHODCALLTYPE* QueryInterface)(
                ICLRControl* This,
                /* [in] */ REFIID riid,
                /* [annotation][iid_is][out] */
                _COM_Outptr_  void** ppvObject);

        ULONG(STDMETHODCALLTYPE* AddRef)(
            ICLRControl* This);

        ULONG(STDMETHODCALLTYPE* Release)(
            ICLRControl* This);

        HRESULT(STDMETHODCALLTYPE* GetCLRManager)(
            ICLRControl* This,
            /* [in] */ REFIID riid,
            /* [out] */ void** ppObject);

        HRESULT(STDMETHODCALLTYPE* SetAppDomainManagerType)(
            ICLRControl* This,
            /* [in] */ LPCWSTR pwzAppDomainManagerAssembly,
            /* [in] */ LPCWSTR pwzAppDomainManagerType);

        END_INTERFACE
    } ICLRControlVtbl;

    interface _ICLRControl
    {
        CONST_VTBL struct ICLRControlVtbl* lpVtbl;
    };

    typedef struct ICLRAssemblyReferenceListVtbl
    {
        BEGIN_INTERFACE

            HRESULT(STDMETHODCALLTYPE* QueryInterface)(
                ICLRAssemblyReferenceList* This,
                /* [in] */ REFIID riid,
                /* [annotation][iid_is][out] */
                _COM_Outptr_  void** ppvObject);

        ULONG(STDMETHODCALLTYPE* AddRef)(
            ICLRAssemblyReferenceList* This);

        ULONG(STDMETHODCALLTYPE* Release)(
            ICLRAssemblyReferenceList* This);

        HRESULT(STDMETHODCALLTYPE* IsStringAssemblyReferenceInList)(
            ICLRAssemblyReferenceList* This,
            /* [in] */ LPCWSTR pwzAssemblyName);

        HRESULT(STDMETHODCALLTYPE* IsAssemblyReferenceInList)(
            ICLRAssemblyReferenceList* This,
            /* [in] */ IUnknown* pName);

        END_INTERFACE
    } ICLRAssemblyReferenceListVtbl;

    interface _ICLRAssemblyReferenceList
    {
        CONST_VTBL struct ICLRAssemblyReferenceListVtbl* lpVtbl;
    };

    typedef struct IHostAssemblyManagerVtbl
    {
        BEGIN_INTERFACE

            HRESULT(STDMETHODCALLTYPE* QueryInterface)(
                IHostAssemblyManager* This,
                /* [in] */ REFIID riid,
                /* [annotation][iid_is][out] */
                _COM_Outptr_  void** ppvObject);

        ULONG(STDMETHODCALLTYPE* AddRef)(
            IHostAssemblyManager* This);

        ULONG(STDMETHODCALLTYPE* Release)(
            IHostAssemblyManager* This);

        HRESULT(STDMETHODCALLTYPE* GetNonHostStoreAssemblies)(
            IHostAssemblyManager* This,
            /* [out] */ ICLRAssemblyReferenceList** ppReferenceList);

        HRESULT(STDMETHODCALLTYPE* GetAssemblyStore)(
            IHostAssemblyManager* This,
            /* [out] */ IHostAssemblyStore** ppAssemblyStore);

        END_INTERFACE
    } IHostAssemblyManagerVtbl;

    interface _IHostAssemblyManager
    {
        CONST_VTBL struct IHostAssemblyManagerVtbl* lpVtbl;
    };

    typedef struct IHostControlVtbl
    {
        BEGIN_INTERFACE

            HRESULT(STDMETHODCALLTYPE* QueryInterface)(
                IHostControl* This,
                /* [in] */ REFIID riid,
                /* [annotation][iid_is][out] */
                _COM_Outptr_  void** ppvObject);

        ULONG(STDMETHODCALLTYPE* AddRef)(
            IHostControl* This);

        ULONG(STDMETHODCALLTYPE* Release)(
            IHostControl* This);

        HRESULT(STDMETHODCALLTYPE* GetHostManager)(
            IHostControl* This,
            /* [in] */ REFIID riid,
            /* [out] */ void** ppObject);

        HRESULT(STDMETHODCALLTYPE* SetAppDomainManager)(
            IHostControl* This,
            /* [in] */ DWORD dwAppDomainID,
            /* [in] */ IUnknown* pUnkAppDomainManager);

        END_INTERFACE
    } IHostControlVtbl;

    interface _IHostControl
    {
        CONST_VTBL struct IHostControlVtbl* lpVtbl;
    };

    typedef struct ICLRRuntimeHostVtbl
    {
        HRESULT(STDMETHODCALLTYPE* QueryInterface)(
            ICLRRuntimeHost* This,
            /* [in] */ REFIID riid,
            /* [annotation][iid_is][out] */
            _COM_Outptr_  void** ppvObject);

        ULONG(STDMETHODCALLTYPE* AddRef)(
            ICLRRuntimeHost* This);

        ULONG(STDMETHODCALLTYPE* Release)(
            ICLRRuntimeHost* This);

        HRESULT(STDMETHODCALLTYPE* Start)(
            ICLRRuntimeHost* This);

        HRESULT(STDMETHODCALLTYPE* Stop)(
            ICLRRuntimeHost* This);

        HRESULT(STDMETHODCALLTYPE* SetHostControl)(
            ICLRRuntimeHost* This,
            /* [in] */ IHostControl* pHostControl);

        HRESULT(STDMETHODCALLTYPE* GetCLRControl)(
            ICLRRuntimeHost* This,
            /* [out] */ ICLRControl** pCLRControl);

        HRESULT(STDMETHODCALLTYPE* UnloadAppDomain)(
            ICLRRuntimeHost* This,
            /* [in] */ DWORD dwAppDomainId,
            /* [in] */ BOOL fWaitUntilDone);

        HRESULT(STDMETHODCALLTYPE* ExecuteInAppDomain)(
            ICLRRuntimeHost* This,
            /* [in] */ DWORD dwAppDomainId,
            /* [in] */ FExecuteInAppDomainCallback pCallback,
            /* [in] */ void* cookie);

        HRESULT(STDMETHODCALLTYPE* GetCurrentAppDomainId)(
            ICLRRuntimeHost* This,
            /* [out] */ DWORD* pdwAppDomainId);

        HRESULT(STDMETHODCALLTYPE* ExecuteApplication)(
            ICLRRuntimeHost* This,
            /* [in] */ LPCWSTR pwzAppFullName,
            /* [in] */ DWORD dwManifestPaths,
            /* [in] */ LPCWSTR* ppwzManifestPaths,
            /* [in] */ DWORD dwActivationData,
            /* [in] */ LPCWSTR* ppwzActivationData,
            /* [out] */ int* pReturnValue);

        HRESULT(STDMETHODCALLTYPE* ExecuteInDefaultAppDomain)(
            ICLRRuntimeHost* This,
            /* [in] */ LPCWSTR pwzAssemblyPath,
            /* [in] */ LPCWSTR pwzTypeName,
            /* [in] */ LPCWSTR pwzMethodName,
            /* [in] */ LPCWSTR pwzArgument,
            /* [out] */ DWORD* pReturnValue);

            END_INTERFACE
    } ICLRRuntimeHostVtbl;

    typedef struct _ICLRRuntimeHost {
        ICLRRuntimeHostVtbl* lpVtbl;
    } ICLRRuntimeHost;


#undef DUMMY_METHOD
#define DUMMY_METHOD(x) HRESULT ( STDMETHODCALLTYPE *dummy_##x )(IBinder *This)

    typedef struct _BinderVtbl {
        HRESULT(STDMETHODCALLTYPE* QueryInterface)(
            IBinder* This,
            /* [in] */ REFIID riid,
            /* [iid_is][out] */ void** ppvObject);

        ULONG(STDMETHODCALLTYPE* AddRef)(
            IBinder* This);

        ULONG(STDMETHODCALLTYPE* Release)(
            IBinder* This);

        DUMMY_METHOD(GetTypeInfoCount);
        DUMMY_METHOD(GetTypeInfo);
        DUMMY_METHOD(GetIDsOfNames);
        DUMMY_METHOD(Invoke);
        DUMMY_METHOD(ToString);
        DUMMY_METHOD(Equals);
        DUMMY_METHOD(GetHashCode);
        DUMMY_METHOD(GetType);
        DUMMY_METHOD(BindToMethod);
        DUMMY_METHOD(BindToField);
        DUMMY_METHOD(SelectMethod);
        DUMMY_METHOD(SelectProperty);
        DUMMY_METHOD(ChangeType);
        DUMMY_METHOD(ReorderArgumentArray);
    } BinderVtbl;

    typedef struct _Binder {
        BinderVtbl* lpVtbl;
    } Binder;

#undef DUMMY_METHOD
#define DUMMY_METHOD(x) HRESULT ( STDMETHODCALLTYPE *dummy_##x )(IType *This)

    typedef struct _TypeVtbl {
        BEGIN_INTERFACE

            HRESULT(STDMETHODCALLTYPE* QueryInterface)(
                IType* This,
                REFIID riid,
                void** ppvObject);

        ULONG(STDMETHODCALLTYPE* AddRef)(
            IType* This);

        ULONG(STDMETHODCALLTYPE* Release)(
            IType* This);

        DUMMY_METHOD(GetTypeInfoCount);
        DUMMY_METHOD(GetTypeInfo);
        DUMMY_METHOD(GetIDsOfNames);
        DUMMY_METHOD(Invoke);

        //DUMMY_METHOD(ToString);
        HRESULT(STDMETHODCALLTYPE* get_ToString)(
            IType* This,
            BSTR* pRetVal);

        DUMMY_METHOD(Equals);
        DUMMY_METHOD(GetHashCode);
        DUMMY_METHOD(GetType);
        DUMMY_METHOD(MemberType);
        DUMMY_METHOD(name);
        DUMMY_METHOD(DeclaringType);
        DUMMY_METHOD(ReflectedType);
        DUMMY_METHOD(GetCustomAttributes);
        DUMMY_METHOD(GetCustomAttributes_2);
        DUMMY_METHOD(IsDefined);
        DUMMY_METHOD(Guid);
        DUMMY_METHOD(Module);
        DUMMY_METHOD(Assembly);
        DUMMY_METHOD(TypeHandle);
        DUMMY_METHOD(FullName);
        DUMMY_METHOD(Namespace);
        DUMMY_METHOD(AssemblyQualifiedName);
        DUMMY_METHOD(GetArrayRank);
        DUMMY_METHOD(BaseType);
        DUMMY_METHOD(GetConstructors);
        DUMMY_METHOD(GetInterface);
        DUMMY_METHOD(GetInterfaces);
        DUMMY_METHOD(FindInterfaces);
        DUMMY_METHOD(GetEvent);
        DUMMY_METHOD(GetEvents);
        DUMMY_METHOD(GetEvents_2);
        DUMMY_METHOD(GetNestedTypes);
        DUMMY_METHOD(GetNestedType);
        DUMMY_METHOD(GetMember);
        DUMMY_METHOD(GetDefaultMembers);
        DUMMY_METHOD(FindMembers);
        DUMMY_METHOD(GetElementType);
        DUMMY_METHOD(IsSubclassOf);
        DUMMY_METHOD(IsInstanceOfType);
        DUMMY_METHOD(IsAssignableFrom);
        DUMMY_METHOD(GetInterfaceMap);
        DUMMY_METHOD(GetMethod);
        DUMMY_METHOD(GetMethod_2);
        //DUMMY_METHOD(GetMethods);
        HRESULT(STDMETHODCALLTYPE* GetMethods)(
            IType* This,
            /*[in]*/ BindingFlags bindingAttr,
            /*[out,retval]*/ SAFEARRAY** pRetVal);
        DUMMY_METHOD(GetField);
        DUMMY_METHOD(GetFields);
        DUMMY_METHOD(GetProperty);
        DUMMY_METHOD(GetProperty_2);
        DUMMY_METHOD(GetProperties);
        DUMMY_METHOD(GetMember_2);
        DUMMY_METHOD(GetMembers);
        DUMMY_METHOD(InvokeMember);
        DUMMY_METHOD(UnderlyingSystemType);
        DUMMY_METHOD(InvokeMember_2);

        HRESULT(STDMETHODCALLTYPE* InvokeMember_3)(
            IType* This,
            BSTR         name,
            BindingFlags invokeAttr,
            IBinder* Binder,
            VARIANT      Target,
            SAFEARRAY* args,
            VARIANT* pRetVal);

        DUMMY_METHOD(GetConstructor);
        DUMMY_METHOD(GetConstructor_2);
        DUMMY_METHOD(GetConstructor_3);
        DUMMY_METHOD(GetConstructors_2);
        DUMMY_METHOD(TypeInitializer);
        DUMMY_METHOD(GetMethod_3);
        DUMMY_METHOD(GetMethod_4);
        DUMMY_METHOD(GetMethod_5);
        DUMMY_METHOD(GetMethod_6);
        DUMMY_METHOD(GetMethods_2);
        DUMMY_METHOD(GetField_2);
        DUMMY_METHOD(GetFields_2);
        DUMMY_METHOD(GetInterface_2);
        DUMMY_METHOD(GetEvent_2);
        DUMMY_METHOD(GetProperty_3);
        DUMMY_METHOD(GetProperty_4);
        DUMMY_METHOD(GetProperty_5);
        DUMMY_METHOD(GetProperty_6);
        DUMMY_METHOD(GetProperty_7);
        DUMMY_METHOD(GetProperties_2);
        DUMMY_METHOD(GetNestedTypes_2);
        DUMMY_METHOD(GetNestedType_2);
        DUMMY_METHOD(GetMember_3);
        DUMMY_METHOD(GetMembers_2);
        DUMMY_METHOD(Attributes);
        DUMMY_METHOD(IsNotPublic);
        DUMMY_METHOD(IsPublic);
        DUMMY_METHOD(IsNestedPublic);
        DUMMY_METHOD(IsNestedPrivate);
        DUMMY_METHOD(IsNestedFamily);
        DUMMY_METHOD(IsNestedAssembly);
        DUMMY_METHOD(IsNestedFamANDAssem);
        DUMMY_METHOD(IsNestedFamORAssem);
        DUMMY_METHOD(IsAutoLayout);
        DUMMY_METHOD(IsLayoutSequential);
        DUMMY_METHOD(IsExplicitLayout);
        DUMMY_METHOD(IsClass);
        DUMMY_METHOD(IsInterface);
        DUMMY_METHOD(IsValueType);
        DUMMY_METHOD(IsAbstract);
        DUMMY_METHOD(IsSealed);
        DUMMY_METHOD(IsEnum);
        DUMMY_METHOD(IsSpecialName);
        DUMMY_METHOD(IsImport);
        DUMMY_METHOD(IsSerializable);
        DUMMY_METHOD(IsAnsiClass);
        DUMMY_METHOD(IsUnicodeClass);
        DUMMY_METHOD(IsAutoClass);
        DUMMY_METHOD(IsArray);
        DUMMY_METHOD(IsByRef);
        DUMMY_METHOD(IsPointer);
        DUMMY_METHOD(IsPrimitive);
        DUMMY_METHOD(IsCOMObject);
        DUMMY_METHOD(HasElementType);
        DUMMY_METHOD(IsContextful);
        DUMMY_METHOD(IsMarshalByRef);
        DUMMY_METHOD(Equals_2);

        END_INTERFACE
    } TypeVtbl;

    typedef struct ICLRRuntimeInfoVtbl
    {
        BEGIN_INTERFACE

            HRESULT(STDMETHODCALLTYPE* QueryInterface)(
                ICLRRuntimeInfo* This,
                /* [in] */ REFIID riid,
                /* [iid_is][out] */
                __RPC__deref_out  void** ppvObject);

        ULONG(STDMETHODCALLTYPE* AddRef)(
            ICLRRuntimeInfo* This);

        ULONG(STDMETHODCALLTYPE* Release)(
            ICLRRuntimeInfo* This);

        HRESULT(STDMETHODCALLTYPE* GetVersionString)(
            ICLRRuntimeInfo* This,
            /* [size_is][out] */
            __out_ecount_full_opt(*pcchBuffer)  LPWSTR pwzBuffer,
            /* [out][in] */ DWORD* pcchBuffer);

        HRESULT(STDMETHODCALLTYPE* GetRuntimeDirectory)(
            ICLRRuntimeInfo* This,
            /* [size_is][out] */
            __out_ecount_full(*pcchBuffer)  LPWSTR pwzBuffer,
            /* [out][in] */ DWORD* pcchBuffer);

        HRESULT(STDMETHODCALLTYPE* IsLoaded)(
            ICLRRuntimeInfo* This,
            /* [in] */ HANDLE hndProcess,
            /* [retval][out] */ BOOL* pbLoaded);

        HRESULT(STDMETHODCALLTYPE* LoadErrorString)(
            ICLRRuntimeInfo* This,
            /* [in] */ UINT iResourceID,
            /* [size_is][out] */
            __out_ecount_full(*pcchBuffer)  LPWSTR pwzBuffer,
            /* [out][in] */ DWORD* pcchBuffer,
            /* [lcid][in] */ LONG iLocaleID);

        HRESULT(STDMETHODCALLTYPE* LoadLibrary)(
            ICLRRuntimeInfo* This,
            /* [in] */ LPCWSTR pwzDllName,
            /* [retval][out] */ HMODULE* phndModule);

        HRESULT(STDMETHODCALLTYPE* GetProcAddress)(
            ICLRRuntimeInfo* This,
            /* [in] */ LPCSTR pszProcName,
            /* [retval][out] */ LPVOID* ppProc);

        HRESULT(STDMETHODCALLTYPE* GetInterface)(
            ICLRRuntimeInfo* This,
            /* [in] */ REFCLSID rclsid,
            /* [in] */ REFIID riid,
            /* [retval][iid_is][out] */ LPVOID* ppUnk);

        HRESULT(STDMETHODCALLTYPE* IsLoadable)(
            ICLRRuntimeInfo* This,
            /* [retval][out] */ BOOL* pbLoadable);

        HRESULT(STDMETHODCALLTYPE* SetDefaultStartupFlags)(
            ICLRRuntimeInfo* This,
            /* [in] */ DWORD dwStartupFlags,
            /* [in] */ LPCWSTR pwzHostConfigFile);

        HRESULT(STDMETHODCALLTYPE* GetDefaultStartupFlags)(
            ICLRRuntimeInfo* This,
            /* [out] */ DWORD* pdwStartupFlags,
            /* [size_is][out] */
            __out_ecount_full_opt(*pcchHostConfigFile)  LPWSTR pwzHostConfigFile,
            /* [out][in] */ DWORD* pcchHostConfigFile);

        HRESULT(STDMETHODCALLTYPE* BindAsLegacyV2Runtime)(
            ICLRRuntimeInfo* This);

        HRESULT(STDMETHODCALLTYPE* IsStarted)(
            ICLRRuntimeInfo* This,
            /* [out] */ BOOL* pbStarted,
            /* [out] */ DWORD* pdwStartupFlags);

        END_INTERFACE
    } ICLRRuntimeInfoVtbl;

    typedef struct _ICLRRuntimeInfo {
        ICLRRuntimeInfoVtbl* lpVtbl;
    } ICLRRuntimeInfo;

    typedef struct _Type {
        TypeVtbl* lpVtbl;
    } Type;

    typedef struct ICLRMetaHostVtbl
    {
        BEGIN_INTERFACE

            HRESULT(STDMETHODCALLTYPE* QueryInterface)(
                ICLRMetaHost* This,
                /* [in] */ REFIID riid,
                /* [iid_is][out] */
                __RPC__deref_out  void** ppvObject);

        ULONG(STDMETHODCALLTYPE* AddRef)(
            ICLRMetaHost* This);

        ULONG(STDMETHODCALLTYPE* Release)(
            ICLRMetaHost* This);

        HRESULT(STDMETHODCALLTYPE* GetRuntime)(
            ICLRMetaHost* This,
            /* [in] */ LPCWSTR pwzVersion,
            /* [in] */ REFIID riid,
            /* [retval][iid_is][out] */ LPVOID* ppRuntime);

        HRESULT(STDMETHODCALLTYPE* GetVersionFromFile)(
            ICLRMetaHost* This,
            /* [in] */ LPCWSTR pwzFilePath,
            /* [size_is][out] */
            __out_ecount_full(*pcchBuffer)  LPWSTR pwzBuffer,
            /* [out][in] */ DWORD* pcchBuffer);

        HRESULT(STDMETHODCALLTYPE* EnumerateInstalledRuntimes)(
            ICLRMetaHost* This,
            /* [retval][out] */ IEnumUnknown** ppEnumerator);

        HRESULT(STDMETHODCALLTYPE* EnumerateLoadedRuntimes)(
            ICLRMetaHost* This,
            /* [in] */ HANDLE hndProcess,
            /* [retval][out] */ IEnumUnknown** ppEnumerator);

        HRESULT(STDMETHODCALLTYPE* RequestRuntimeLoadedNotification)(
            ICLRMetaHost* This,
            /* [in] */ RuntimeLoadedCallbackFnPtr pCallbackFunction);

        HRESULT(STDMETHODCALLTYPE* QueryLegacyV2RuntimeBinding)(
            ICLRMetaHost* This,
            /* [in] */ REFIID riid,
            /* [retval][iid_is][out] */ LPVOID* ppUnk);

        HRESULT(STDMETHODCALLTYPE* ExitProcess)(
            ICLRMetaHost* This,
            /* [in] */ INT32 iExitCode);

        END_INTERFACE
    } ICLRMetaHostVtbl;

    typedef struct _ICLRMetaHost
    {
        ICLRMetaHostVtbl* lpVtbl;
    } ICLRMetaHost;

    typedef struct ICorRuntimeHostVtbl
    {
        BEGIN_INTERFACE

            HRESULT(STDMETHODCALLTYPE* QueryInterface)(
                ICorRuntimeHost* This,
                /* [in] */ REFIID riid,
                /* [iid_is][out] */
                __RPC__deref_out  void** ppvObject);

        ULONG(STDMETHODCALLTYPE* AddRef)(
            ICorRuntimeHost* This);

        ULONG(STDMETHODCALLTYPE* Release)(
            ICorRuntimeHost* This);

        HRESULT(STDMETHODCALLTYPE* CreateLogicalThreadState)(
            ICorRuntimeHost* This);

        HRESULT(STDMETHODCALLTYPE* DeleteLogicalThreadState)(
            ICorRuntimeHost* This);

        HRESULT(STDMETHODCALLTYPE* SwitchInLogicalThreadState)(
            ICorRuntimeHost* This,
            /* [in] */ DWORD* pFiberCookie);

        HRESULT(STDMETHODCALLTYPE* SwitchOutLogicalThreadState)(
            ICorRuntimeHost* This,
            /* [out] */ DWORD** pFiberCookie);

        HRESULT(STDMETHODCALLTYPE* LocksHeldByLogicalThread)(
            ICorRuntimeHost* This,
            /* [out] */ DWORD* pCount);

        HRESULT(STDMETHODCALLTYPE* MapFile)(
            ICorRuntimeHost* This,
            /* [in] */ HANDLE hFile,
            /* [out] */ HMODULE* hMapAddress);

        HRESULT(STDMETHODCALLTYPE* GetConfiguration)(
            ICorRuntimeHost* This,
            /* [out] */ ICorConfiguration** pConfiguration);

        HRESULT(STDMETHODCALLTYPE* Start)(
            ICorRuntimeHost* This);

        HRESULT(STDMETHODCALLTYPE* Stop)(
            ICorRuntimeHost* This);

        HRESULT(STDMETHODCALLTYPE* CreateDomain)(
            ICorRuntimeHost* This,
            /* [in] */ LPCWSTR pwzFriendlyName,
            /* [in] */ IUnknown* pIdentityArray,
            /* [out] */ IUnknown** pAppDomain);

        HRESULT(STDMETHODCALLTYPE* GetDefaultDomain)(
            ICorRuntimeHost* This,
            /* [out] */ IUnknown** pAppDomain);

        HRESULT(STDMETHODCALLTYPE* EnumDomains)(
            ICorRuntimeHost* This,
            /* [out] */ HDOMAINENUM* hEnum);

        HRESULT(STDMETHODCALLTYPE* NextDomain)(
            ICorRuntimeHost* This,
            /* [in] */ HDOMAINENUM hEnum,
            /* [out] */ IUnknown** pAppDomain);

        HRESULT(STDMETHODCALLTYPE* CloseEnum)(
            ICorRuntimeHost* This,
            /* [in] */ HDOMAINENUM hEnum);

        HRESULT(STDMETHODCALLTYPE* CreateDomainEx)(
            ICorRuntimeHost* This,
            /* [in] */ LPCWSTR pwzFriendlyName,
            /* [in] */ IUnknown* pSetup,
            /* [in] */ IUnknown* pEvidence,
            /* [out] */ IUnknown** pAppDomain);

        HRESULT(STDMETHODCALLTYPE* CreateDomainSetup)(
            ICorRuntimeHost* This,
            /* [out] */ IUnknown** pAppDomainSetup);

        HRESULT(STDMETHODCALLTYPE* CreateEvidence)(
            ICorRuntimeHost* This,
            /* [out] */ IUnknown** pEvidence);

        HRESULT(STDMETHODCALLTYPE* UnloadDomain)(
            ICorRuntimeHost* This,
            /* [in] */ IUnknown* pAppDomain);

        HRESULT(STDMETHODCALLTYPE* CurrentDomain)(
            ICorRuntimeHost* This,
            /* [out] */ IUnknown** pAppDomain);

        END_INTERFACE
    } ICorRuntimeHostVtbl;

    typedef struct _ICorRuntimeHost {
        ICorRuntimeHostVtbl* lpVtbl;
    } ICorRuntimeHost;

#undef DUMMY_METHOD
#define DUMMY_METHOD(x) HRESULT ( STDMETHODCALLTYPE *dummy_##x )(IMethodInfo *This)

    typedef struct _MethodInfoVtbl {
        BEGIN_INTERFACE

            HRESULT(STDMETHODCALLTYPE* QueryInterface)(
                IMethodInfo* This,
                /* [in] */ REFIID riid,
                /* [iid_is][out] */
                __RPC__deref_out  void** ppvObject);

        ULONG(STDMETHODCALLTYPE* AddRef)(
            IMethodInfo* This);

        ULONG(STDMETHODCALLTYPE* Release)(
            IMethodInfo* This);

        DUMMY_METHOD(GetTypeInfoCount);
        DUMMY_METHOD(GetTypeInfo);
        DUMMY_METHOD(GetIDsOfNames);
        DUMMY_METHOD(Invoke);

        //DUMMY_METHOD(ToString);
        HRESULT(STDMETHODCALLTYPE* get_ToString)(
            IMethodInfo* This,
            /*[out,retval]*/ BSTR* pRetVal);
        
        DUMMY_METHOD(Equals);
        DUMMY_METHOD(GetHashCode);
        DUMMY_METHOD(GetType);
        DUMMY_METHOD(MemberType);
        DUMMY_METHOD(name);
        //DUMMY_METHOD(DeclaringType);

        HRESULT(STDMETHODCALLTYPE* get_DeclaringType)(
            IMethodInfo* This,
            struct _Type** pRetVal);
        DUMMY_METHOD(ReflectedType);
        DUMMY_METHOD(GetCustomAttributes);
        DUMMY_METHOD(GetCustomAttributes_2);
        DUMMY_METHOD(IsDefined);

        HRESULT(STDMETHODCALLTYPE* GetParameters)(
            IMethodInfo* This,
            SAFEARRAY** pRetVal);

        DUMMY_METHOD(GetMethodImplementationFlags);
        DUMMY_METHOD(MethodHandle);
        DUMMY_METHOD(Attributes);
        DUMMY_METHOD(CallingConvention);
        //DUMMY_METHOD(Invoke_2);
        HRESULT(STDMETHODCALLTYPE* Invoke_2)(
            IMethodInfo* This,
            /*[in]*/ VARIANT obj,
            /*[in]*/ BindingFlags invokeAttr,
            /*[in]*/ struct _Binder* Binder,
            /*[in]*/ SAFEARRAY* parameters,
            /*[in]*/ struct _CultureInfo* culture,
            /*[out,retval]*/ VARIANT* pRetVal);
        DUMMY_METHOD(IsPublic);
        DUMMY_METHOD(IsPrivate);
        DUMMY_METHOD(IsFamily);
        DUMMY_METHOD(IsAssembly);
        DUMMY_METHOD(IsFamilyAndAssembly);
        DUMMY_METHOD(IsFamilyOrAssembly);
        DUMMY_METHOD(IsStatic);
        DUMMY_METHOD(IsFinal);
        DUMMY_METHOD(IsVirtual);
        DUMMY_METHOD(IsHideBySig);
        DUMMY_METHOD(IsAbstract);
        DUMMY_METHOD(IsSpecialName);
        DUMMY_METHOD(IsConstructor);

        HRESULT(STDMETHODCALLTYPE* Invoke_3)(
            IMethodInfo* This,
            VARIANT     obj,
            SAFEARRAY* parameters,
            VARIANT* ret);

        DUMMY_METHOD(returnType);
        DUMMY_METHOD(ReturnTypeCustomAttributes);
        DUMMY_METHOD(GetBaseDefinition);

        END_INTERFACE
    } MethodInfoVtbl;

    typedef struct _MethodInfo {
        MethodInfoVtbl* lpVtbl;
    } MethodInfo;

    typedef struct ICorConfigurationVtbl
    {
        BEGIN_INTERFACE

            HRESULT(STDMETHODCALLTYPE* QueryInterface)(
                ICorConfiguration* This,
                /* [in] */ REFIID riid,
                /* [iid_is][out] */
                __RPC__deref_out  void** ppvObject);

        ULONG(STDMETHODCALLTYPE* AddRef)(
            ICorConfiguration* This);

        ULONG(STDMETHODCALLTYPE* Release)(
            ICorConfiguration* This);

        HRESULT(STDMETHODCALLTYPE* SetGCThreadControl)(
            ICorConfiguration* This,
            /* [in] */ IGCThreadControl* pGCThreadControl);

        HRESULT(STDMETHODCALLTYPE* SetGCHostControl)(
            ICorConfiguration* This,
            /* [in] */ IGCHostControl* pGCHostControl);

        HRESULT(STDMETHODCALLTYPE* SetDebuggerThreadControl)(
            ICorConfiguration* This,
            /* [in] */ IDebuggerThreadControl* pDebuggerThreadControl);

        HRESULT(STDMETHODCALLTYPE* AddDebuggerSpecialThread)(
            ICorConfiguration* This,
            /* [in] */ DWORD dwSpecialThreadId);

        END_INTERFACE
    } ICorConfigurationVtbl;

    typedef struct _ICorConfiguration
    {
        ICorConfigurationVtbl* lpVtbl;
    }ICorConfiguration;

    typedef struct IGCThreadControlVtbl
    {
        BEGIN_INTERFACE

            HRESULT(STDMETHODCALLTYPE* QueryInterface)(
                IGCThreadControl* This,
                /* [in] */ REFIID riid,
                /* [iid_is][out] */
                __RPC__deref_out  void** ppvObject);

        ULONG(STDMETHODCALLTYPE* AddRef)(
            IGCThreadControl* This);

        ULONG(STDMETHODCALLTYPE* Release)(
            IGCThreadControl* This);

        HRESULT(STDMETHODCALLTYPE* ThreadIsBlockingForSuspension)(
            IGCThreadControl* This);

        HRESULT(STDMETHODCALLTYPE* SuspensionStarting)(
            IGCThreadControl* This);

        HRESULT(STDMETHODCALLTYPE* SuspensionEnding)(
            IGCThreadControl* This,
            DWORD Generation);

        END_INTERFACE
    } IGCThreadControlVtbl;

    typedef struct _IGCThreadControl
    {
        IGCThreadControlVtbl* lpVtbl;
    }IGCThreadControl;

    typedef struct IGCHostControlVtbl
    {
        BEGIN_INTERFACE

            HRESULT(STDMETHODCALLTYPE* QueryInterface)(
                IGCHostControl* This,
                /* [in] */ REFIID riid,
                /* [iid_is][out] */
                __RPC__deref_out  void** ppvObject);

        ULONG(STDMETHODCALLTYPE* AddRef)(
            IGCHostControl* This);

        ULONG(STDMETHODCALLTYPE* Release)(
            IGCHostControl* This);

        HRESULT(STDMETHODCALLTYPE* RequestVirtualMemLimit)(
            IGCHostControl* This,
            /* [in] */ SIZE_T sztMaxVirtualMemMB,
            /* [out][in] */ SIZE_T* psztNewMaxVirtualMemMB);

        END_INTERFACE
    } IGCHostControlVtbl;

    typedef struct _IGCHostControl
    {
        IGCHostControlVtbl* lpVtbl;
    } IGCHostControl;

    typedef struct IDebuggerThreadControlVtbl
    {
        BEGIN_INTERFACE

            HRESULT(STDMETHODCALLTYPE* QueryInterface)(
                IDebuggerThreadControl* This,
                /* [in] */ REFIID riid,
                /* [iid_is][out] */
                __RPC__deref_out  void** ppvObject);

        ULONG(STDMETHODCALLTYPE* AddRef)(
            IDebuggerThreadControl* This);

        ULONG(STDMETHODCALLTYPE* Release)(
            IDebuggerThreadControl* This);

        HRESULT(STDMETHODCALLTYPE* ThreadIsBlockingForDebugger)(
            IDebuggerThreadControl* This);

        HRESULT(STDMETHODCALLTYPE* ReleaseAllRuntimeThreads)(
            IDebuggerThreadControl* This);

        HRESULT(STDMETHODCALLTYPE* StartBlockingForDebugger)(
            IDebuggerThreadControl* This,
            DWORD dwUnused);

        END_INTERFACE
    } IDebuggerThreadControlVtbl;

    typedef struct _IDebuggerThreadControl {
        IDebuggerThreadControlVtbl* lpVtbl;
    } IDebuggerThreadControl;

#endif
}






/* Long list of .NET #~ defines */
// This is only used for lazy in place identity stomping.

#define ID_MODULE 0x0
#define ID_TYPE_REF 0x1
#define ID_TYPE_DEF 0x2
// no 0x3
#define ID_FIELD 0x4
// no 0x5
#define ID_METHOD_DEF 0x6
// no 0x7
#define ID_PARAM 0x8
#define ID_INTERFACE_IMPL 0x9
#define ID_MEMBER_REF 0xA
#define ID_CONSTANT 0xB
#define ID_CUSTOM_ATTRIBUTE 0xC
#define ID_FIELD_MARSHAL 0xD
#define ID_DECL_SECURITY 0xE
#define ID_CLASS_LAYOUT 0xF
#define ID_FIELD_LAYOUT 0x10
#define ID_STAND_ALONE_SIG 0x11
#define ID_EVENT_MAP 0x12
// no 0x13 
#define ID_EVENT 0x14
#define ID_PROPERTY_MAP 0x15
// no 0x16
#define ID_PROPERTY 0x17
#define ID_METHOD_SEMANTICS 0x18
#define ID_METHOD_IMPL 0x19
#define ID_MODULE_REF 0x1A
#define ID_TYPE_SPEC 0x1B
#define ID_IMPL_MAP 0x1C
#define ID_FIELD_RVA 0x1D
// no 0x1e 
// no 0x1f
#define ID_ASSEMBLY 0x20
#define ID_ASSEMBLY_PROCESSOR 0x21
#define ID_ASSEMBLY_OS 0x22
#define ID_ASSEMBLY_REF 0x23
#define ID_ASSEMBLY_REF_PROCESSOR 0x24
#define ID_ASSEMBLY_REF_OS 0x25
#define ID_FILE 0x26
#define ID_EXPORTED_TYPE 0x27
#define ID_MANIFEST_RESOURCE 0x28
#define ID_NESTED_CLASS 0x29
#define ID_GENERIC_PARAM 0x2A
#define ID_METHOD_SPEC 0x2B
#define ID_GENERIC_PARAM_CONSTRAINT 0x2C

// TODO: CHECK THESE - I did these at 3am while sick and dying
// sizes for things 
// our structs get alignment padding so can't use that
// should really say row but w/e

// THESE ARE THE "DEFAULT" SIZES WITHOUT CONSIDERING LARGE CODED OR NORMAL INDICES
// thats dynamically done later on 
#define SIZE_TABLE_MODULE 10;
#define SIZE_TABLE_TYPE_REF 6;
#define SIZE_TABLE_TYPE_DEF 14;
#define SIZE_TABLE_FIELD 6;
#define SIZE_TABLE_METHOD_DEF 14;
#define SIZE_TABLE_PARAM 6;
#define SIZE_TABLE_INTERFACE_IMPL 4;
#define SIZE_TABLE_MEMBER_REF 6;
#define SIZE_TABLE_CONSTANT 6;
#define SIZE_TABLE_CUSTOM_ATTRIBUTE 6;
#define SIZE_TABLE_FIELD_MARSHAL 4;
#define SIZE_TABLE_DECL_SECURITY 6;
#define SIZE_TABLE_CLASS_LAYOUT 8;
#define SIZE_TABLE_FIELD_LAYOUT 6;
#define SIZE_TABLE_STAND_ALONE_SIG 2;
#define SIZE_TABLE_EVENT_MAP 4; // i think?
#define SIZE_TABLE_EVENT 6;
#define SIZE_TABLE_PROPERTY_MAP 4;
#define SIZE_TABLE_PROPERTY 6;
#define SIZE_TABLE_METHOD_SEMANTICS 6;
#define SIZE_TABLE_METHOD_IMPL 6;
#define SIZE_TABLE_MODULE_REF 2;
#define SIZE_TABLE_TYPE_SPEC 2;
#define SIZE_TABLE_IMPL_MAP 8;
#define SIZE_TABLE_FIELD_RVA 6;
#define SIZE_TABLE_ASSEMBLY 22;
#define SIZE_TABLE_ASSEMBLY_PROCESSOR 4;
#define SIZE_TABLE_ASSEMBLY_OS 12;  
#define SIZE_TABLE_ASSEMBLY_REF 20;  
#define SIZE_TABLE_ASSEMBLY_REF_PROCESSOR 6;
#define SIZE_TABLE_ASSEMBLY_REF_OS 14;
#define SIZE_TABLE_FILE 8;
#define SIZE_TABLE_EXPORTED_TYPE 14;
#define SIZE_TABLE_MANIFEST_RESOURCE 12;
#define SIZE_TABLE_NESTED_CLASS 4;
#define SIZE_TABLE_GENERIC_PARAM 8;
#define SIZE_TABLE_METHOD_SPEC 4;
#define SIZE_TABLE_GENERIC_PARAM_CONSTRAINT 4;