// Includes for this file
#include "verify_signature.hpp"

#include <mscat.h>

// 
// https://docs.microsoft.com/en-us/windows/win32/seccrypto/example-c-program--verifying-the-signature-of-a-pe-file?redirectedfrom=MSDN
//

namespace Verify
{
	bool EmbeddedSignature(LPCWSTR source_file)
	{
		// Create a WINTRUST file info structure
		WINTRUST_FILE_INFO file_data;

		// Set the value of the file data struct to NULL
		memset(&file_data, 0, sizeof(file_data));

		// Construct the file data structure
		{
			file_data.cbStruct			= sizeof(WINTRUST_FILE_INFO);
			file_data.pcwszFilePath		= source_file;
			file_data.hFile				= NULL;
			file_data.pgKnownSubject	= NULL;
		}

		// Set the policy guid to verify the certificate shains created from the object time
		GUID policy_guid = WINTRUST_ACTION_GENERIC_VERIFY_V2;

		// Create a WINTRUST data struct
		WINTRUST_DATA win_trust_data;

		// Set the value of the win trust data to NULL
		memset(&win_trust_data, 0, sizeof(win_trust_data));

		// Construct the win trust data structure
		{
			win_trust_data.cbStruct					= sizeof(WINTRUST_DATA);
			win_trust_data.pPolicyCallbackData		= NULL;
			win_trust_data.pSIPClientData			= NULL;
			win_trust_data.dwUIChoice				= WTD_UI_NONE;
			win_trust_data.fdwRevocationChecks		= WTD_REVOKE_NONE;
			win_trust_data.dwUnionChoice			= WTD_CHOICE_FILE;
			win_trust_data.dwStateAction			= WTD_STATEACTION_VERIFY;
			win_trust_data.hWVTStateData			= NULL;
			win_trust_data.pwszURLReference			= NULL;
			win_trust_data.dwUIContext				= 0;
			win_trust_data.pFile					= &file_data;
		}

		// Verify the trust
		LONG status = WinVerifyTrust(NULL, &policy_guid, &win_trust_data);

		// Create a return value
		bool ret = false;

		if (status == ERROR_SUCCESS) ret = true;

		// Update the state data because a nigga on stack said so
		win_trust_data.dwStateAction = WTD_CHOICE_CATALOG;

		status = WinVerifyTrust(NULL, &policy_guid, &win_trust_data);

		if (status == ERROR_SUCCESS) ret = true;

		// Release the state data
		win_trust_data.dwStateAction = WTD_STATEACTION_CLOSE;

		// Release the win trust data
		WinVerifyTrust(NULL, &policy_guid, &win_trust_data);

		return ret;
	}
}
