#pragma once

#include <wtypes.h>
#include <cstdint>

#include "pe.h"
#include "nt.h"

namespace integrity::hooks
{
	bool install();

	namespace originals
	{
		inline decltype( &LoadLibraryA ) LoadLibraryA = nullptr;
		inline decltype( &LoadLibraryW ) LoadLibraryW = nullptr;
		inline decltype( &LoadLibraryExA ) LoadLibraryExA = nullptr;
		inline decltype( &LoadLibraryExW ) LoadLibraryExW = nullptr;

		inline decltype( &MessageBoxA ) MessageBoxA = nullptr;
		inline decltype( &MessageBoxW ) MessageBoxW = nullptr;
		inline decltype( &MessageBoxExA ) MessageBoxExA = nullptr;
		inline decltype( &MessageBoxExW ) MessageBoxExW = nullptr;

		inline decltype( &VirtualAlloc ) VirtualAlloc = nullptr;
		inline decltype( &VirtualProtect ) VirtualProtect = nullptr;
		inline decltype( &VirtualQuery ) VirtualQuery = nullptr;
		inline decltype( &VirtualAllocEx ) VirtualAllocEx = nullptr;
		inline decltype( &VirtualProtectEx ) VirtualProtectEx = nullptr;
		inline decltype( &VirtualQueryEx ) VirtualQueryEx = nullptr;

		inline decltype( &GetCurrentProcess ) GetCurrentProcess = nullptr;
		inline decltype( &CloseHandle ) CloseHandle = nullptr;

		using fnNtAllocateVirtualMemory = NTSTATUS( NTAPI* ) (
			HANDLE processhandle,
			PVOID* baseaddress,
			ULONG zerobits,
			PSIZE_T regionsize,
			ULONG allocationtype,
			ULONG protect );
		inline fnNtAllocateVirtualMemory NtAllocateVirtualMemory = nullptr;

		using fnNtMapViewOfSection = NTSTATUS( NTAPI* ) (
			HANDLE SectionHandle,
			HANDLE ProcessHandle,
			PVOID* BaseAddress,
			ULONG_PTR ZeroBits,
			SIZE_T CommitSize,
			PLARGE_INTEGER SectionOffset,
			PSIZE_T ViewSize,
			SECTION_INHERIT InheritDisposition,
			ULONG AllocationType,
			ULONG Protect );
		inline fnNtMapViewOfSection NtMapViewOfSection = nullptr;

		using fnLdrLoadDll = NTSTATUS( NTAPI* )(
			PWSTR SearchPath OPTIONAL,
			PULONG DllCharacteristics OPTIONAL,
			UNICODE_STRING* DllName,
			PVOID* BaseAddress );
		inline fnLdrLoadDll LdrLoadDll = nullptr;

		typedef ULONG( NTAPI* fnRtlGetFullPathName_U )( PCWSTR FileName, ULONG Size, PWSTR Buffer, PWSTR* ShortName );
		inline fnRtlGetFullPathName_U RtlGetFullPathName_U = nullptr;
	}

	namespace impl
	{
		BOOL WINAPI CloseHandle( HANDLE handle );
		HANDLE WINAPI GetCurrentProcess();
		HMODULE WINAPI LoadLibraryA( LPCSTR filename );
		HMODULE WINAPI LoadLibraryW( LPCWSTR filename );
		HMODULE WINAPI LoadLibraryExA( LPCSTR lpLibFileName, HANDLE hFile, DWORD dwFlags );
		HMODULE WINAPI LoadLibraryExW( LPCWSTR lpLibFileName, HANDLE hFile, DWORD dwFlags );
		LPVOID WINAPI VirtualAllocEx(
			_In_ HANDLE hProcess,
			_In_opt_ LPVOID lpAddress,
			_In_ SIZE_T dwSize,
			_In_ DWORD flAllocationType,
			_In_ DWORD flProtect
		);
		SIZE_T WINAPI VirtualQueryEx(
			HANDLE hProcess,
			LPCVOID lpAddress,
			PMEMORY_BASIC_INFORMATION lpBuffer,
			SIZE_T dwLength
		);
		int WINAPI MessageBoxW(
			HWND hWnd,
			LPCWSTR lpText,
			LPCWSTR lpCaption,
			UINT uType
		);
		NTSTATUS NTAPI NtAllocateVirtualMemory(
			HANDLE processhandle,
			PVOID* baseaddress,
			ULONG zerobits,
			PSIZE_T regionsize,
			ULONG allocationtype,
			ULONG protect
		);
		NTSTATUS NTAPI LdrLoadDll(
			PWSTR SearchPath OPTIONAL,
			PULONG DllCharacteristics OPTIONAL,
			UNICODE_STRING* DllName,
			PVOID* BaseAddress
		);
		NTSTATUS NTAPI NtMapViewOfSection( _In_ HANDLE SectionHandle, _In_ HANDLE ProcessHandle,
				_Outptr_result_bytebuffer_( *ViewSize ) PVOID* BaseAddress, _In_ ULONG_PTR ZeroBits,
				_In_ SIZE_T CommitSize, _Inout_opt_ PLARGE_INTEGER SectionOffset, _Inout_ PSIZE_T ViewSize,
				_In_ SECTION_INHERIT InheritDisposition, _In_ ULONG AllocationType, _In_ ULONG Win32Protect );
		ULONG NTAPI RtlGetFullPathName_U( PCWSTR FileName, ULONG Size, PWSTR Buffer, PWSTR* ShortName );
	}
}