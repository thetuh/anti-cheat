#pragma once

#include <wtypes.h>
#include <iostream>

namespace ctx
{
	inline uintptr_t image_base;
	inline size_t image_size;
}

namespace integrity
{
	inline void init_console()
	{
		AllocConsole();

		HWND                con_hwndw{ GetConsoleWindow() };
		RECT                  con_bound{ 904 + 219, 420 };
		RECT                  wndw_rect{};

		SetConsoleTitle( "ac_module" );

		GetWindowRect( con_hwndw, &wndw_rect );
		MoveWindow( con_hwndw, wndw_rect.left, wndw_rect.top, con_bound.left, con_bound.top, true );

		SetWindowLong( con_hwndw, GWL_STYLE, GetWindowLong( con_hwndw, GWL_STYLE ) | WS_BORDER );
		SetWindowLong( con_hwndw, GWL_EXSTYLE, GetWindowLong( con_hwndw, GWL_EXSTYLE ) | WS_EX_LAYERED );

		SetLayeredWindowAttributes( con_hwndw, 0, 230, 2 );
		SetConsoleTextAttribute( GetStdHandle( STD_OUTPUT_HANDLE ), FOREGROUND_RED | FOREGROUND_GREEN | FOREGROUND_INTENSITY );

		freopen( ( "CONOUT$" ), ( "w" ), stdout );
	}

	bool init( HINSTANCE dll );

	void validate_memory_regions();
	void validate_checksums();

	bool validate_module_signature( LPCWSTR pwszSourceFile );
	bool validate_return_address( uintptr_t address, const char* function_name );
}