#pragma once

#include "helpers.h"
#include "base/helpers.h"

/* HEADERS FOR CUSTOM HOST CONTROL AND STUFF */

extern "C" {
#undef DUMMY_METHOD
#define DUMMY_METHOD(x) HRESULT ( STDMETHODCALLTYPE *dummy_##x )(IHostControl *c_this)
    typedef struct _CustomHostControlVtbl {
        BEGIN_INTERFACE

            HRESULT(STDMETHODCALLTYPE* QueryInterface)(IHostControl* c_this, REFIID riid, void** ppvObject);
        ULONG(STDMETHODCALLTYPE* AddRef)(IHostControl* c_this);
        ULONG(STDMETHODCALLTYPE* Release)(IHostControl* c_this);

        HRESULT(STDMETHODCALLTYPE* GetHostManager)(IHostControl* c_this, REFIID riid, void** ppObject);
        HRESULT(STDMETHODCALLTYPE* SetAppDomainManager)(IHostControl* c_this, DWORD dwAppDomainID, IUnknown* pUnkAppDomainManager);

        END_INTERFACE

    } CustomHostControlVtbl;

    typedef struct __CustomHostControl {
        const CustomHostControlVtbl* lpVtbl;
        TargetAssembly* TargetAssembly;
        //MemoryManager* memoryManager;
        DWORD Count;
    } CustomHostControl;

    HRESULT CustomHostControl_QueryInterface(IHostControl* c_this, REFIID riid, void** ppvObject);
    ULONG CustomHostControl_AddRef(IHostControl* c_this);
    ULONG CustomHostControl_Release(IHostControl* c_this);

    HRESULT CustomHostControl_GetHostManager(IHostControl* c_this, REFIID riid, void** ppObject);
    HRESULT CustomHostControl_SetAppDomainManager(IHostControl* c_this, DWORD dwAppDomainID, IUnknown* pUnkAppDomainManager);

    static const CustomHostControlVtbl CustomHostControl_Vtbl = {
        CustomHostControl_QueryInterface,
        CustomHostControl_AddRef,
        CustomHostControl_Release,
        CustomHostControl_GetHostManager,
        CustomHostControl_SetAppDomainManager
    };

    HRESULT CustomAssemblyManager_QueryInterface(IHostAssemblyManager* c_this, REFIID riid, void** ppvObject);
    ULONG CustomAssemblyManager_AddRef(IHostAssemblyManager* c_this);
    ULONG CustomAssemblyManager_Release(IHostAssemblyManager* c_this);
    HRESULT CustomAssemblyManager_GetNonHostStoreAssemblies(IHostAssemblyManager* c_this, ICLRAssemblyReferenceList** ppReferenceList);
    HRESULT CustomAssemblyManager_GetAssemblyStore(IHostAssemblyManager* c_this, IHostAssemblyStore** ppAssemblyStore);

#undef DUMMY_METHOD
#define DUMMY_METHOD(x) HRESULT ( STDMETHODCALLTYPE *dummy_##x )(IHostAssemblyManager *c_this)
    typedef struct _CustomAssemblyManagerVtbl {
        BEGIN_INTERFACE

            HRESULT(STDMETHODCALLTYPE* QueryInterface)(IHostAssemblyManager* c_this, REFIID riid, void** ppvObject);
        ULONG(STDMETHODCALLTYPE* AddRef)(IHostAssemblyManager* c_this);
        ULONG(STDMETHODCALLTYPE* Release)(IHostAssemblyManager* c_this);

        HRESULT(STDMETHODCALLTYPE* GetNonHostStoreAssemblies)(IHostAssemblyManager* c_this, ICLRAssemblyReferenceList** ppReferenceList);
        HRESULT(STDMETHODCALLTYPE* GetAssemblyStore)(IHostAssemblyManager* c_this, IHostAssemblyStore** ppAssemblyStore);

        END_INTERFACE

    } CustomAssemblyManagerVtbl;

    //lpVtbl and count are required items in this struct, the other two are my implementation
    typedef struct __CustomAssemblyManager {
        const CustomAssemblyManagerVtbl* lpVtbl;
        //IHostAssemblyStore* AssemblyStore;
        TargetAssembly* TargetAssembly;
        DWORD Count;
    } CustomAssemblyManager;

    static const CustomAssemblyManagerVtbl CustomAssemblyManager_Vtbl = {
        CustomAssemblyManager_QueryInterface,
        CustomAssemblyManager_AddRef,
        CustomAssemblyManager_Release,
        CustomAssemblyManager_GetNonHostStoreAssemblies,
        CustomAssemblyManager_GetAssemblyStore
    };

    HRESULT CustomAssemblyStore_QueryInterface(IHostAssemblyStore* c_this, REFIID riid, void** ppvObject);
    ULONG CustomAssemblyStore_AddRef(IHostAssemblyStore* c_this);
    ULONG CustomAssemblyStore_Release(IHostAssemblyStore* c_this);
    HRESULT CustomAssemblyStore_ProvideAssembly(IHostAssemblyStore* c_this, AssemblyBindInfo* pBindInfo, UINT64* pAssemblyId, UINT64* pContext, IStream** ppStmAssemblyImage, IStream** ppStmPDB);
    HRESULT CustomAssemblyStore_ProvideModule(IHostAssemblyStore* c_this, ModuleBindInfo* pBindInfo, DWORD* pdwModuleId, IStream** ppStmModuleImage, IStream** ppStmPDB);

#undef DUMMY_METHOD
#define DUMMY_METHOD(x) HRESULT ( STDMETHODCALLTYPE *dummy_##x )(IHostAssemblyStore *c_this)
    typedef struct _CustomAssemblyStore {
        BEGIN_INTERFACE

            HRESULT(STDMETHODCALLTYPE* QueryInterface)(IHostAssemblyStore* c_this, REFIID riid, void** ppvObject);
        ULONG(STDMETHODCALLTYPE* AddRef)(IHostAssemblyStore* c_this);
        ULONG(STDMETHODCALLTYPE* Release)(IHostAssemblyStore* c_this);
        HRESULT(STDMETHODCALLTYPE* ProvideAssembly)(IHostAssemblyStore* c_this, AssemblyBindInfo* pBindInfo, UINT64* pAssemblyId, UINT64* pContext, IStream** ppStmAssemblyImage, IStream** ppStmPDB);
        HRESULT(STDMETHODCALLTYPE* ProvideModule)(IHostAssemblyStore* c_this, ModuleBindInfo* pBindInfo, DWORD* pdwModuleId, IStream** ppStmModuleImage, IStream** ppStmPDB);

        END_INTERFACE

    } CustomAssemblyStoreVtbl;

    typedef struct __CustomAssemblyStore {
        const CustomAssemblyStoreVtbl* lpVtbl;
        TargetAssembly* TargetAssembly;
        DWORD Count;
    } CustomAssemblyStore;

    static const CustomAssemblyStoreVtbl CustomAssemblyStore_Vtbl = {
        CustomAssemblyStore_QueryInterface,
        CustomAssemblyStore_AddRef,
        CustomAssemblyStore_Release,
        CustomAssemblyStore_ProvideAssembly,
        CustomAssemblyStore_ProvideModule
    };
}
