#include <Windows.h>
#include <iostream>

// idea: monitor protected process externally, walk the callstack of each running thread, perform self integrity checks
// pair in cojunction with driver for elevated security

int main()
{
	while ( true )
	{
		Sleep( 1 );
	}
}