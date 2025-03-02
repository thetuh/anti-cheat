#include "integrity.h"
#include "hooks.h"
#include "memory.h"

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

		std::thread( watchdog ).detach();
		std::thread( watchdog2 ).detach();

		printf( "[+] started watchdog threads\n" );

		if ( !hooks::install() )
			return false;

		printf( "[+] installed hooks\n" );

		return true;
	}

	void watchdog()
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

				if ( mbi.AllocationProtect == PAGE_EXECUTE_READWRITE && mbi.Protect == PAGE_READONLY ||
					mbi.AllocationProtect == PAGE_EXECUTE_READWRITE && mbi.Protect == PAGE_EXECUTE_READWRITE )
				{
					suspicious_regions.emplace( ( uintptr_t ) mbi.AllocationBase, false );
				}
			}

			for ( auto& [address, reported] : suspicious_regions )
			{
				if ( !reported )
				{
					printf( "[!] suspicious memory region: 0x%p\n\tattempting to dump\n", address );

					memory::dump_to_file( address, "\t" );

					reported = true;
				}
			}

			std::this_thread::sleep_for( std::chrono::milliseconds( 500 ) );
		}
	}

	void watchdog2()
	{
		std::unordered_map<std::wstring, uintptr_t> hash_cache;

		while ( true )
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

				if ( hash_cache.find( ldr_entry->FullDllName.Buffer ) == hash_cache.end() )
				{
					if ( validate_module_signature( ldr_entry->FullDllName.Buffer ) )
					{
						hash_cache.emplace( ldr_entry->FullDllName.Buffer, compute_disk_hash( ldr_entry->FullDllName.Buffer ) );
					}
					else
					{
						hash_cache.emplace( ldr_entry->FullDllName.Buffer, 0 );
					}
				}

				if ( const auto cached_checksum = hash_cache[ ldr_entry->FullDllName.Buffer ]; cached_checksum )
				{
					uintptr_t text_checksum = 0;

					auto section_header = IMAGE_FIRST_SECTION( nt );
					for ( WORD i = 0; i < nt->FileHeader.NumberOfSections; i++ )
					{
						if ( !memcmp( section_header[ i ].Name, ".text", 5 ) )
						{
							const auto text_start = reinterpret_cast< const std::byte* >( dos ) + section_header[ i ].VirtualAddress;
							for ( DWORD j = 0; j < section_header[ i ].SizeOfRawData; ++j )
								text_checksum += static_cast< uintptr_t >( text_start[ j ] );
						}
					}

					if ( text_checksum != cached_checksum )
						printf( "[!] checksum mismatch %ls\n", ldr_entry->FullDllName.Buffer );
				}

			}

			std::this_thread::sleep_for( std::chrono::milliseconds( 500 ) );
		}
	}

	uintptr_t compute_disk_hash( LPCWSTR filepath )
	{
		uintptr_t text_checksum = 0;

		std::basic_ifstream<std::byte> file_stream( filepath, std::ios::binary );
		if ( !file_stream )
		{
			printf( "[!] failed to open file stream to %ls\n", filepath );
			return text_checksum;
		}

		const std::vector<std::byte> image_buffer = { std::istreambuf_iterator<std::byte>( file_stream ), std::istreambuf_iterator<std::byte>() };

		const auto dos = ( IMAGE_DOS_HEADER* ) image_buffer.data();
		if ( !dos || dos->e_magic != IMAGE_DOS_SIGNATURE )
		{
			printf( "[!] invalid dos header for disk image %ls\n", filepath );
			return text_checksum;
		}

		const auto nt = ( IMAGE_NT_HEADERS* ) ( ( uintptr_t ) dos + dos->e_lfanew );
		if ( !nt || nt->Signature != IMAGE_NT_SIGNATURE )
		{
			printf( "[!] invalid nt headers for disk image %ls\n", filepath );
			return text_checksum;
		}

		auto section_header = IMAGE_FIRST_SECTION( nt );
		for ( WORD i = 0; i < nt->FileHeader.NumberOfSections; i++ )
		{
			if ( !memcmp( section_header[ i ].Name, ".text", 5 ) )
			{
				const auto text_start = reinterpret_cast< const std::byte* >( image_buffer.data() ) + section_header[ i ].PointerToRawData;
				for ( DWORD j = 0; j < section_header[ i ].SizeOfRawData; ++j )
					text_checksum += static_cast< uintptr_t >( text_start[ j ] );
			}
		}

		return text_checksum;
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
				memory::dump_to_file( ( uintptr_t ) mbi.AllocationBase, "\t" );
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