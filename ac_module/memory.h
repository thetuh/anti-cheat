#pragma once

#include <vector>
#include <cstdint>
#include <sstream>
#include <fstream>
#include <memoryapi.h>

namespace memory
{
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
}