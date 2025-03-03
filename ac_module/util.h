#pragma once

#include <vector>
#include <cstdint>
#include <sstream>
#include <fstream>
#include <memoryapi.h>
#include <functional>

struct checksum_region
{
	uintptr_t start, checksum;
	size_t size;
	char name[ 16 ];
	bool reported;
};

namespace util
{
	inline void walk_ldr_list( const std::function<void( LDR_DATA_TABLE_ENTRY* )>& callback )
	{
#ifdef _WIN64
		const auto peb = reinterpret_cast< _PEB* >( __readgsqword( 0x60 ) );
#else
		const auto peb = reinterpret_cast< _PEB* >( __readfsdword( 0x30 ) );
#endif

		const auto list_head = &peb->Ldr->InMemoryOrderModuleList;
		for ( auto it = list_head->Flink; it != list_head; it = it->Flink )
		{
			const auto ldr_entry = CONTAINING_RECORD( it, LDR_DATA_TABLE_ENTRY, InMemoryOrderLinks );
			if ( !ldr_entry )
				continue;

			callback( ldr_entry );
		}
	}

	inline void dump_to_file( const uintptr_t address, const char* prefix )
	{
		std::stringstream file_name;
		file_name << "memory_dump_" << std::hex << address << ".bin";

		std::ofstream dump_file( file_name.str(), std::ios::binary );
		if ( !dump_file )
		{
			printf( "%sfailed to open dump file\n", prefix ? prefix : "" );
			return;
		}

		MEMORY_BASIC_INFORMATION mbi = { 0 };
		uintptr_t current = address;

		while ( VirtualQuery( ( LPCVOID ) current, &mbi, sizeof( mbi ) ) )
		{
			if ( mbi.AllocationBase != ( PVOID ) address || mbi.State == MEM_RESERVE )
				break;

			std::vector<std::byte> buffer( mbi.RegionSize );
			memcpy( buffer.data(), ( const void* ) current, mbi.RegionSize );

			dump_file.write( reinterpret_cast< const char* >( buffer.data() ), mbi.RegionSize );

			current += mbi.RegionSize;
		}

		printf( "%ssuccessfully dumped to file: %s\n", prefix ? prefix : "", file_name.str().c_str() );

		dump_file.close();
	}

	inline std::vector<checksum_region> compute_file_checksum( LPCWSTR filepath, uintptr_t memory_image_base )
	{
		std::vector<checksum_region> checksum_regions{};

		std::basic_ifstream<std::byte> file_stream( filepath, std::ios::binary );
		if ( !file_stream )
		{
			printf( "[!] failed to open file stream to %ls\n", filepath );
			return checksum_regions;
		}

		const std::vector<std::byte> image_buffer = { std::istreambuf_iterator<std::byte>( file_stream ), std::istreambuf_iterator<std::byte>() };

		const auto dos = ( IMAGE_DOS_HEADER* ) image_buffer.data();
		if ( !dos || dos->e_magic != IMAGE_DOS_SIGNATURE )
		{
			printf( "[!] invalid dos header for disk image %ls\n", filepath );
			return checksum_regions;
		}

		const auto nt = ( IMAGE_NT_HEADERS* ) ( ( uintptr_t ) dos + dos->e_lfanew );
		if ( !nt || nt->Signature != IMAGE_NT_SIGNATURE )
		{
			printf( "[!] invalid nt headers for disk image %ls\n", filepath );
			return checksum_regions;
		}

		nt->OptionalHeader.ImageBase = memory_image_base;

		checksum_region header_checksum{};

		header_checksum.start = memory_image_base;
		header_checksum.size = nt->OptionalHeader.SizeOfHeaders;
		strcpy( header_checksum.name, "header" );

		for ( DWORD i = 0; i < nt->OptionalHeader.SizeOfHeaders; i++ )
		{
			header_checksum.checksum += ( uintptr_t ) image_buffer.data()[ i ];
		}

		checksum_regions.emplace_back( header_checksum );

		auto section_header = IMAGE_FIRST_SECTION( nt );
		for ( WORD i = 0; i < nt->FileHeader.NumberOfSections; i++ )
		{
			if ( !memcmp( section_header[ i ].Name, ".text", 5 ) )
			{
				checksum_region section_checksum{};

				section_checksum.start = memory_image_base + section_header[ i ].VirtualAddress;
				section_checksum.size = section_header[ i ].SizeOfRawData;
				strcpy( section_checksum.name, "text" );

				const auto section_start = image_buffer.data() + section_header[ i ].PointerToRawData;
				for ( DWORD j = 0; j < section_header[ i ].SizeOfRawData; j++ )
					section_checksum.checksum += ( uintptr_t ) section_start[ j ];

				checksum_regions.emplace_back( section_checksum );
			}
		}

		return checksum_regions;
	}
}