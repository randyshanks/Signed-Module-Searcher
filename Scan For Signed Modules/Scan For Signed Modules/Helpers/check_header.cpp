// Includes for this file
#include "check_header.hpp"

#include "verify_signature.hpp"
#include "string.hpp"

#include <string>
#include <fstream>


namespace Check
{
	void CleanUp(LPVOID base, HANDLE map_object, HANDLE file)
	{
		// Unmap the file
		UnmapViewOfFile(base);

		// Close the handle to the map object
		CloseHandle(map_object);

		// Close the handle to the file 
		CloseHandle(file);
	}

	void Header(LPCWSTR _module)
	{

		// Open a handle to this module
		HANDLE file = CreateFile(_module, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);

		// Check that the handle to the module isn't invalid
		if (file == INVALID_HANDLE_VALUE) return;

		// Create a file mapping object from the opened file handle
		HANDLE map_object = CreateFileMapping(file, NULL, PAGE_READONLY, NULL, NULL, NULL);

		// Map the view of this module
		LPVOID base = MapViewOfFile(map_object, FILE_MAP_READ, 0, 0, 0);

		// Retrieve the cast this module to it's DOS header
		PIMAGE_DOS_HEADER dos_header = (PIMAGE_DOS_HEADER)base;

		// Verify that this module has a valid DOS header
		if (dos_header == NULL) return;
	
		// Check that the MZ header section contains a Image DOS signature
		if (dos_header->e_magic != IMAGE_DOS_SIGNATURE)
		{
			CleanUp(base, map_object, file);

			return;
		}

		// Get a pointer to the NT headers
		PIMAGE_NT_HEADERS nt_header = (PIMAGE_NT_HEADERS)((__int64)(dos_header) + (dos_header->e_lfanew));

		// Verify that the nt header signature is a valid nt signature
		if (nt_header->Signature == IMAGE_NT_SIGNATURE)
		{
			// Retrieve the file header from the NT header
			IMAGE_FILE_HEADER header = nt_header->FileHeader;

			// Retrieve the optional file header from the NT header
			IMAGE_OPTIONAL_HEADER optional_header = nt_header->OptionalHeader;

			int i = 0;

			// Traverse the sections in the nt header
			for (PIMAGE_SECTION_HEADER section_header = IMAGE_FIRST_SECTION(nt_header); i < nt_header->FileHeader.NumberOfSections; i++, section_header++)
			{
				//
				// Basically check if this section RWX
				//

				// Check if the section header is writeable
				bool writeable = ((section_header->Characteristics & 0x20000000) == 0x20000000);

				// Check if the section header is readable
				bool readable = ((section_header->Characteristics & 0x40000000) == 0x40000000);

				// Check if the section header is execuatable
				bool executable = ((section_header->Characteristics & 0x80000000) == 0x80000000);

				// Check if this section header is RWX
				if (writeable & readable & executable)
				{
					if (Verify::EmbeddedSignature(_module))
					{
						// Create a file stream
						std::ofstream output;
						output.open("log.txt", std::ios::app);

						// Check if the file stream was opened successfully
						if (!output.is_open())
						{
							// Log the error
							printf("[!] Failed to open a file stream to the log file\n");

						}

						// Check whether it is x86 or x64 because file logging is shit
						std::string architecture = optional_header.Magic == 0x20b ? "64-bit" : "32-bit";

						// Log to the file
						{
							output << "\n[+] " << WStringToString(std::wstring(_module)) << std::endl;
							output << "\t-Section Name		: " << std::hex << section_header->Name << std::endl;
							output << "\t-Virtual Size		: 0x" << std::hex << section_header->Misc.VirtualSize << std::endl;
							output << "\t-Raw Size		: 0x" << section_header->SizeOfRawData << std::endl;
							output << "\t-Magic			: " << architecture << std::endl;
						}

						// Log to the console
						{
							printf("[+] Found signed module with a RWX section %ls\n", _module);
							printf("\t- Section Name	: %s\n", section_header->Name);
							printf("\t- Virtual Size	: 0x%llX\n", (uint64_t)section_header->Misc.VirtualSize);
							printf("\t- Raw Size	: 0x%llX\n", (uint64_t)section_header->SizeOfRawData);
							printf("\t- Magic		: %s\n\n", architecture.c_str());
						}

						output.close();
					}
				}
			}
		}

		// Clean up the module
		CleanUp(base, map_object, file);
	}
}
