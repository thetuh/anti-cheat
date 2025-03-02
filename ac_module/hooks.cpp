#include "hooks.h"
#include "integrity.h"
#include "tinyformat.h"

#include "minhook/include/MinHook.h"

#include <intrin.h>
#include <unordered_map>
#include <shlwapi.h>

#pragma comment(lib, "Shlwapi.lib")

namespace integrity::hooks
{
	bool install()
	{
		auto log_error = []( const char* msg )
			{
				MessageBox( NULL, msg, "ac_module", MB_OK | MB_ICONERROR );
				return false;
			};

		std::unordered_map<std::string, HMODULE> libraries =
		{
			{"kernel32.dll", nullptr},
			{"user32.dll", nullptr},
			{"ntdll.dll", nullptr}
		};

		for ( auto& [name, handle] : libraries )
		{
			handle = LoadLibrary( name.c_str() );
			if ( !handle )
				return log_error( tfm::format( "%s not found", name ).c_str() );
		}

		if ( const auto status = MH_Initialize(); status != MH_OK )
			return log_error( tfm::format( "could not initialize minhook - MH_STATUS: %d", status ).c_str() );

		struct hook_t
		{
			const char* module;
			const char* function;
			LPVOID hook;
			LPVOID* original;
		};

		const std::vector<hook_t> hooks =
		{
			{"kernel32.dll", "GetCurrentProcess", &impl::GetCurrentProcess, reinterpret_cast< LPVOID* >( &originals::GetCurrentProcess )},
			{"kernel32.dll", "CloseHandle", &impl::CloseHandle, reinterpret_cast< LPVOID* >( &originals::CloseHandle )},
			{"kernel32.dll", "LoadLibraryA", &impl::LoadLibraryA, reinterpret_cast< LPVOID* >( &originals::LoadLibraryA )},
			{"kernel32.dll", "LoadLibraryW", &impl::LoadLibraryW, reinterpret_cast< LPVOID* >( &originals::LoadLibraryW )},
			{"kernel32.dll", "LoadLibraryExA", &impl::LoadLibraryExA, reinterpret_cast< LPVOID* >( &originals::LoadLibraryExA )},
			{"kernel32.dll", "LoadLibraryExW", &impl::LoadLibraryExW, reinterpret_cast< LPVOID* >( &originals::LoadLibraryExW )},
			{"kernel32.dll", "VirtualAllocEx", &impl::VirtualAllocEx, reinterpret_cast< LPVOID* >( &originals::VirtualAllocEx )},
			{"kernel32.dll", "VirtualQueryEx", &impl::VirtualQueryEx, reinterpret_cast< LPVOID* >( &originals::VirtualQueryEx )},
			{"user32.dll", "MessageBoxW", &impl::MessageBoxW, reinterpret_cast< LPVOID* >( &originals::MessageBoxW )},
			{"ntdll.dll", "NtAllocateVirtualMemory", &impl::NtAllocateVirtualMemory, reinterpret_cast< LPVOID* >( &originals::NtAllocateVirtualMemory )},
			{"ntdll.dll", "LdrLoadDll", &impl::LdrLoadDll, reinterpret_cast< LPVOID* >( &originals::LdrLoadDll )},
			//{"ntdll.dll", "NtMapViewOfSection", &impl::NtMapViewOfSection, reinterpret_cast< LPVOID* >( &originals::NtMapViewOfSection )},
			{"ntdll.dll", "RtlGetFullPathName_U", &impl::RtlGetFullPathName_U, reinterpret_cast< LPVOID* >( &originals::RtlGetFullPathName_U )}
		};

		for ( const auto& hook : hooks )
		{
			const auto module = libraries[ hook.module ];

			const auto proc = GetProcAddress( module, hook.function );
			if ( !proc )
				return log_error( tfm::format( "failed to get address of %s", hook.function ).c_str() );

			if ( const auto status = MH_CreateHook( proc, hook.hook, hook.original ); status != MH_OK )
				return log_error( tfm::format( "could not hook %s - MH_STATUS: %d", hook.function, status ).c_str() );
		}

		if ( const auto status = MH_EnableHook( MH_ALL_HOOKS ); status != MH_OK )
			return log_error( tfm::format( "could not enable hooks - MH_STATUS: %d", status ).c_str() );

		return true;
	}

	namespace impl
	{
		BOOL WINAPI CloseHandle( HANDLE handle )
		{
			validate_return_address( ( uintptr_t ) _ReturnAddress(), "CloseHandle" );
			return originals::CloseHandle( handle );
		}

		HANDLE WINAPI GetCurrentProcess()
		{
			validate_return_address( ( uintptr_t ) _ReturnAddress(), "GetCurrentProcess" );
			return originals::GetCurrentProcess();
		}

		HMODULE WINAPI LoadLibraryA( LPCSTR filename )
		{
			validate_return_address( ( uintptr_t ) _ReturnAddress(), "LoadLibraryA" );
			return originals::LoadLibraryA( filename );;
		}

		HMODULE WINAPI LoadLibraryW( LPCWSTR filename )
		{
			validate_return_address( ( uintptr_t ) _ReturnAddress(), "LoadLibraryW" );
			return originals::LoadLibraryW( filename );
		}

		HMODULE WINAPI LoadLibraryExA( LPCSTR lpLibFileName, HANDLE hFile, DWORD dwFlags )
		{
			validate_return_address( ( uintptr_t ) _ReturnAddress(), "LoadLibraryExA" );
			return originals::LoadLibraryExA( lpLibFileName, hFile, dwFlags );
		}

		HMODULE WINAPI LoadLibraryExW( LPCWSTR lpLibFileName, HANDLE hFile, DWORD dwFlags )
		{
			validate_return_address( ( uintptr_t ) _ReturnAddress(), "LoadLibraryExW" );
			return originals::LoadLibraryExW( lpLibFileName, hFile, dwFlags );
		}

		LPVOID WINAPI VirtualAllocEx(
			_In_ HANDLE hProcess,
			_In_opt_ LPVOID lpAddress,
			_In_ SIZE_T dwSize,
			_In_ DWORD flAllocationType,
			_In_ DWORD flProtect
		) {
			validate_return_address( ( uintptr_t ) _ReturnAddress(), "VirtualAllocEx" );
			return originals::VirtualAllocEx( hProcess, lpAddress, dwSize, flAllocationType, flProtect );
		}

		SIZE_T WINAPI VirtualQueryEx(
			HANDLE hProcess,
			LPCVOID lpAddress,
			PMEMORY_BASIC_INFORMATION lpBuffer,
			SIZE_T dwLength
		) {
			validate_return_address( ( uintptr_t ) _ReturnAddress(), "VirtualQueryEx" );
			return originals::VirtualQueryEx( hProcess, lpAddress, lpBuffer, dwLength );
		}

		int WINAPI MessageBoxW(
			HWND hWnd,
			LPCWSTR lpText,
			LPCWSTR lpCaption,
			UINT uType
		) {
			validate_return_address( ( uintptr_t ) _ReturnAddress(), "MessageBoxW" );
			return originals::MessageBoxW( hWnd, lpText, lpCaption, uType );
		}

		NTSTATUS NTAPI NtAllocateVirtualMemory(
			HANDLE processhandle,
			PVOID* baseaddress,
			ULONG zerobits,
			PSIZE_T regionsize,
			ULONG allocationtype,
			ULONG protect
		) {

			validate_return_address( ( uintptr_t ) _ReturnAddress(), "NtAllocateVirtualMemory" );
			return originals::NtAllocateVirtualMemory( processhandle, baseaddress, zerobits, regionsize, allocationtype, protect );
		}

		NTSTATUS NTAPI LdrLoadDll(
			PWSTR SearchPath OPTIONAL,
			PULONG DllCharacteristics OPTIONAL,
			UNICODE_STRING* DllName,
			PVOID* BaseAddress
		)
		{
			validate_return_address( ( uintptr_t ) _ReturnAddress(), "LdrLoadDll" );
			return originals::LdrLoadDll( SearchPath, DllCharacteristics, DllName, BaseAddress );
		}

		NTSTATUS NTAPI NtMapViewOfSection( _In_ HANDLE SectionHandle, _In_ HANDLE ProcessHandle,
			_Outptr_result_bytebuffer_( *ViewSize ) PVOID* BaseAddress, _In_ ULONG_PTR ZeroBits,
			_In_ SIZE_T CommitSize, _Inout_opt_ PLARGE_INTEGER SectionOffset, _Inout_ PSIZE_T ViewSize,
			_In_ SECTION_INHERIT InheritDisposition, _In_ ULONG AllocationType, _In_ ULONG Win32Protect )
		{
			validate_return_address( ( uintptr_t ) _ReturnAddress(), "NtMapViewOfSection" );
			return originals::NtMapViewOfSection( SectionHandle, ProcessHandle, BaseAddress, ZeroBits, CommitSize, SectionOffset, ViewSize, InheritDisposition, AllocationType, Win32Protect );
		}

		ULONG NTAPI RtlGetFullPathName_U( PCWSTR FileName, ULONG Size, PWSTR Buffer, PWSTR* ShortName )
		{
			if ( !validate_module_signature( FileName ) )
			{
				printf( "[-] attempting to copy file\n" );

				WCHAR process_directory[ MAX_PATH ] = { 0 };
				if ( GetModuleFileNameW( NULL, process_directory, MAX_PATH ) == 0 )
					printf( "\tfailed to get process directory\n" );

				PathRemoveFileSpecW( process_directory );

				WCHAR dst[ MAX_PATH ] = { 0 };
				swprintf( dst, MAX_PATH, L"%s\\%s", process_directory, PathFindFileNameW( FileName ) );

				if ( CopyFileW( FileName, dst, FALSE ) )
				{
					printf( "\tsuccessfully copied %ls to %ls\n", FileName, dst );
				}
				else
				{
					printf( "\tfailed to copy file: %ls\n", FileName );
				}
			}

			return originals::RtlGetFullPathName_U( FileName, Size, Buffer, ShortName );
		}
	}
}