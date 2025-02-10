#include "integrity.h"
#include <iostream>

bool WINAPI DllMain( HINSTANCE dll, DWORD reason, LPVOID reserved )
{
	if ( reason == DLL_PROCESS_ATTACH )
		return integrity::init( dll );
}