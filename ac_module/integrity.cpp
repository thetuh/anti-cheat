#include "integrity.h"
#include "hooks.h"
#include "util.h"

#include <thread>
#include <wintrust.h>
#include <softpub.h>
#include <unordered_map>
#include <fstream>
#include <sstream>

#pragma comment(lib, "wintrust.lib")

namespace integrity
{
	bool init( HINSTANCE dll )
	{
		init_console();

		printf( "[+] ac_module injected\n" );

		ctx::image_base = ( uintptr_t ) dll;

		printf( "\timage base: 0x%p\n", dll );

		ctx::image_size = ( ( IMAGE_NT_HEADERS* ) ( ( uintptr_t ) dll + ( ( IMAGE_DOS_HEADER* ) dll )->e_lfanew ) )->OptionalHeader.SizeOfImage;

		printf( "\timage size: %lu\n", ctx::image_size );

		const auto nt_headers = ( IMAGE_NT_HEADERS* ) ( ctx::image_base + ( ( IMAGE_DOS_HEADER* ) ctx::image_base )->e_lfanew );

		DWORD old_protect;
		if ( VirtualProtect( ( void* ) ctx::image_base, nt_headers->OptionalHeader.SizeOfHeaders, PAGE_READWRITE, &old_protect ) )
		{
			memset( ( void* ) ctx::image_base, 0, nt_headers->OptionalHeader.SizeOfHeaders );
			VirtualProtect( ( void* ) ctx::image_base, nt_headers->OptionalHeader.SizeOfHeaders, old_protect, &old_protect );
			printf( "[+] wiped PE header\n" );
		}

		std::thread( validate_memory_regions ).detach();

		std::thread( validate_checksums ).detach();

		printf( "[+] started watchdog threads\n" );

		if ( !hooks::install() )
			return false;

		printf( "[+] installed hooks\n" );

		return true;
	}

	void validate_memory_regions()
	{
		std::unordered_map<uintptr_t, bool> suspicious_regions;

		// todo: check for unlinked modules

		while ( true )
		{
			MEMORY_BASIC_INFORMATION mbi = { 0 };
			uintptr_t current_address = 0;

			while ( VirtualQuery( ( LPCVOID ) current_address, &mbi, sizeof( mbi ) ) )
			{
				current_address += mbi.RegionSize;

				if ( ( uintptr_t ) mbi.AllocationBase == ctx::image_base )
					continue;

				if ( mbi.Type != MEM_PRIVATE )
					continue;

				/*
					will potentially catch more suspicious regions but also incur false positives

					if ( mbi.AllocationProtect == PAGE_EXECUTE_READWRITE && mbi.Protect == PAGE_READONLY ||
						mbi.AllocationProtect == PAGE_EXECUTE_READWRITE && mbi.Protect == PAGE_EXECUTE_READWRITE )
				*/

				if ( mbi.Protect == PAGE_EXECUTE_READ )
				{
					suspicious_regions.emplace( ( uintptr_t ) mbi.AllocationBase, false );
				}
			}

			for ( auto& [address, reported] : suspicious_regions )
			{
				if ( !reported )
				{
					printf( "[!] suspicious memory region: 0x%p\n\tattempting to dump\n", address );

					util::dump_to_file( address, "\t" );

					reported = true;
				}
			}

			std::this_thread::sleep_for( std::chrono::milliseconds( 500 ) );
		}
	}

	void validate_checksums()
	{
		std::unordered_map<std::wstring, std::vector<checksum_region>> checksum_cache;

		while ( true )
		{
			util::walk_ldr_list( [ & ]( LDR_DATA_TABLE_ENTRY* ldr_entry )
				{
					if ( checksum_cache.find( ldr_entry->FullDllName.Buffer ) == checksum_cache.end() )
					{
						checksum_cache.emplace( ldr_entry->FullDllName.Buffer, util::compute_file_checksums( ldr_entry->FullDllName.Buffer, ( uintptr_t ) ldr_entry->DllBase ) );
					}

					if ( auto& cached_checksum = checksum_cache[ ldr_entry->FullDllName.Buffer ]; cached_checksum.size() )
					{
						for ( auto& checksum_region : cached_checksum )
						{
							uintptr_t checksum = 0;

							const auto checksum_start = ( std::byte* ) ( checksum_region.start );
							for ( DWORD i = 0; i < checksum_region.size; i++ )
								checksum += ( uintptr_t ) checksum_start[ i ];

							if ( checksum != checksum_region.checksum && !checksum_region.reported )
							{
								printf( "[!] %s checksum mismatch: %ls\n", checksum_region.name, ldr_entry->FullDllName.Buffer );
								checksum_region.reported = true;
							}
						}
					}
				} );

			std::this_thread::sleep_for( std::chrono::milliseconds( 500 ) );
		}
	}

	// https://learn.microsoft.com/en-us/windows/win32/seccrypto/example-c-program--verifying-the-signature-of-a-pe-file
	bool validate_module_signature( LPCWSTR pwszSourceFile )
	{
		LONG lStatus;
		DWORD dwLastError;

		// Initialize the WINTRUST_FILE_INFO structure.

		WINTRUST_FILE_INFO FileData;
		memset( &FileData, 0, sizeof( FileData ) );
		FileData.cbStruct = sizeof( WINTRUST_FILE_INFO );
		FileData.pcwszFilePath = pwszSourceFile;
		FileData.hFile = NULL;
		FileData.pgKnownSubject = NULL;

		/*
		WVTPolicyGUID specifies the policy to apply on the file
		WINTRUST_ACTION_GENERIC_VERIFY_V2 policy checks:

		1) The certificate used to sign the file chains up to a root
		certificate located in the trusted root certificate store. This
		implies that the identity of the publisher has been verified by
		a certification authority.

		2) In cases where user interface is displayed (which this example
		does not do), WinVerifyTrust will check for whether the
		end entity certificate is stored in the trusted publisher store,
		implying that the user trusts content from this publisher.

		3) The end entity certificate has sufficient permission to sign
		code, as indicated by the presence of a code signing EKU or no
		EKU.
		*/

		GUID WVTPolicyGUID = WINTRUST_ACTION_GENERIC_VERIFY_V2;
		WINTRUST_DATA WinTrustData;

		// Initialize the WinVerifyTrust input data structure.

		// Default all fields to 0.
		memset( &WinTrustData, 0, sizeof( WinTrustData ) );

		WinTrustData.cbStruct = sizeof( WinTrustData );

		// Use default code signing EKU.
		WinTrustData.pPolicyCallbackData = NULL;

		// No data to pass to SIP.
		WinTrustData.pSIPClientData = NULL;

		// Disable WVT UI.
		WinTrustData.dwUIChoice = WTD_UI_NONE;

		// No revocation checking.
		WinTrustData.fdwRevocationChecks = WTD_REVOKE_NONE;

		// Verify an embedded signature on a file.
		WinTrustData.dwUnionChoice = WTD_CHOICE_FILE;

		// Verify action.
		WinTrustData.dwStateAction = WTD_STATEACTION_VERIFY;

		// Verification sets this value.
		WinTrustData.hWVTStateData = NULL;

		// Not used.
		WinTrustData.pwszURLReference = NULL;

		// This is not applicable if there is no UI because it changes 
		// the UI to accommodate running applications instead of 
		// installing applications.
		WinTrustData.dwUIContext = 0;

		// Set pFile.
		WinTrustData.pFile = &FileData;

		// WinVerifyTrust verifies signatures as specified by the GUID 
		// and Wintrust_Data.
		lStatus = WinVerifyTrust(
			NULL,
			&WVTPolicyGUID,
			&WinTrustData );

		bool trusted = false;

		switch ( lStatus )
		{
			case ERROR_SUCCESS:
				/*
				Signed file:
					- Hash that represents the subject is trusted.

					- Trusted publisher without any verification errors.

					- UI was disabled in dwUIChoice. No publisher or
						time stamp chain errors.

					- UI was enabled in dwUIChoice and the user clicked
						"Yes" when asked to install and run the signed
						subject.
				*/
				wprintf_s( L"[+] The file \"%s\" is signed and the signature "
					L"was verified.\n",
					pwszSourceFile );

				trusted = true;

				break;

			case TRUST_E_NOSIGNATURE:
				// The file was not signed or had a signature 
				// that was not valid.

				// Get the reason for no signature.
				dwLastError = GetLastError();
				if ( TRUST_E_NOSIGNATURE == dwLastError ||
					TRUST_E_SUBJECT_FORM_UNKNOWN == dwLastError ||
					TRUST_E_PROVIDER_UNKNOWN == dwLastError )
				{
					// The file was not signed.
					wprintf_s( L"[!] The file \"%s\" is not signed.\n",
						pwszSourceFile );
				}
				else
				{
					// The signature was not valid or there was an error 
					// opening the file.
					wprintf_s( L"[!] An unknown error occurred trying to "
						L"verify the signature of the \"%s\" file.\n",
						pwszSourceFile );
				}

				break;

			case TRUST_E_EXPLICIT_DISTRUST:
				// The hash that represents the subject or the publisher 
				// is not allowed by the admin or user.
				wprintf_s( L"[!] The signature is present, but specifically "
					L"disallowed.\n" );
				break;

			case TRUST_E_SUBJECT_NOT_TRUSTED:
				// The user clicked "No" when asked to install and run.
				wprintf_s( L"[!] The signature is present, but not "
					L"trusted.\n" );
				break;

			case CRYPT_E_SECURITY_SETTINGS:
				/*
				The hash that represents the subject or the publisher
				was not explicitly trusted by the admin and the
				admin policy has disabled user trust. No signature,
				publisher or time stamp errors.
				*/
				wprintf_s( L"[!] CRYPT_E_SECURITY_SETTINGS - The hash "
					L"representing the subject or the publisher wasn't "
					L"explicitly trusted by the admin and admin policy "
					L"has disabled user trust. No signature, publisher "
					L"or timestamp errors.\n" );
				break;

			default:
				// The UI was disabled in dwUIChoice or the admin policy 
				// has disabled user trust. lStatus contains the 
				// publisher or time stamp chain error.
				wprintf_s( L"[!] Error is: 0x%x.\n",
					lStatus );
				break;
		}

		// Any hWVTStateData must be released by a call with close.
		WinTrustData.dwStateAction = WTD_STATEACTION_CLOSE;

		lStatus = WinVerifyTrust(
			NULL,
			&WVTPolicyGUID,
			&WinTrustData );

		return trusted;
	}

	bool validate_return_address( uintptr_t address, const char* function_name )
	{
#ifdef _WIN64
		const auto peb = ( _PEB* ) __readgsqword( 0x60 );
#else
		const auto peb = ( _PEB* ) __readfsdword( 0x30 );
#endif

		const auto list_head = &peb->Ldr->InMemoryOrderModuleList;

		for ( auto it = list_head->Flink; it != list_head; it = it->Flink )
		{
			const auto ldr_entry = CONTAINING_RECORD( it, LDR_DATA_TABLE_ENTRY, InMemoryOrderLinks );
			if ( !ldr_entry )
				continue;

			const auto dos = ( IMAGE_DOS_HEADER* ) ldr_entry->DllBase;
			if ( !dos || dos->e_magic != IMAGE_DOS_SIGNATURE )
				continue;

			const auto nt = ( IMAGE_NT_HEADERS* ) ( ( uintptr_t ) dos + dos->e_lfanew );
			if ( !nt || nt->Signature != IMAGE_NT_SIGNATURE )
				continue;

			if ( ( address >= ( uintptr_t ) dos && address < ( ( uintptr_t ) dos + nt->OptionalHeader.SizeOfImage ) ) || ( address >= ctx::image_base && address < ( ctx::image_base + ctx::image_size ) ) )
				return true;
		}

		printf( "[!] %s failed integrity check\n\treturn address: 0x%p\n", function_name, address );

		MEMORY_BASIC_INFORMATION mbi;
		if ( VirtualQuery( ( LPCVOID ) address, &mbi, sizeof( mbi ) ) )
		{
			printf( "\tattempting to dump memory region 0x%p\n", mbi.AllocationBase );

			if ( mbi.AllocationBase )
			{
				util::dump_to_file( ( uintptr_t ) mbi.AllocationBase, "\t" );
			}
			else
			{
				printf( "\tfailed to dump memory region due to invalid allocation base\n" );
			}
		}
		else
		{
			printf( "\tfailed to query memory region" );
		}

		return false;
	}
}