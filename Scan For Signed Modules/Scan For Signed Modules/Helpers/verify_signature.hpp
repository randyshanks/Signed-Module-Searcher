#ifndef _VERIFY_SIGNATURE_HPP_
#define _VERIFY_SIGNATURE_HPP_

// Includes for this header file
#include <Windows.h>
#include <wintrust.h>
#include <Softpub.h>
#include <atlbase.h>

// Linked libraries for this header file
#pragma comment (lib, "wintrust")

namespace Verify
{
	bool EmbeddedSignature(LPCWSTR source_file);
}

#endif // _VERIFY_SIGNATURE_HPP_
