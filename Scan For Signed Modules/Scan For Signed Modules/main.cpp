// Includes for this file
#include <Windows.h>

#include "Helpers/check_header.hpp"

void FindRWXModules(LPCWSTR folder)
{
	// Create a path buffer
	wchar_t path[2048];

	wcscpy(path, folder);
	wcscat(path, L"\\*");

	WIN32_FIND_DATAW dir_file;

	// Get a handle to the first file in the path
	HANDLE file = FindFirstFile(path, &dir_file);

	// Check that the handle isn't invalid
	if (file != INVALID_HANDLE_VALUE)
	{
		do
		{
			// Check if the file name is .
			if (!wcscmp(dir_file.cFileName, L".")) continue;

			// Check if the file name is ..
			if (!wcscmp(dir_file.cFileName, L"..")) continue;

			wchar_t sub_path[2048];
			wcscpy(sub_path, folder);
			wcscat(sub_path, L"\\\\");
			wcscat(sub_path, dir_file.cFileName);

			// Check if this file is a module
			if (wcsstr(dir_file.cFileName, L".dll"))
			{
				Check::Header(sub_path);
			}

			// Check if this file is a attribute directory
			if (dir_file.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY)
			{
				// Recurse
				FindRWXModules(sub_path);
			}

		} while (FindNextFile(file, &dir_file) != 0);

		// Close the handle to the file
		FindClose(file);
	}
}


int main()
{
	printf("[i] Searching for signed modules with RWX permission\n\n");

	//
	// Yes I understand finding the drives like this is fucking retarded
	//

	LPCWSTR drives[] = { L"C:\\", L"D:\\", L"E:\\", L"F:\\", L"G:\\" };

	// Traverse the drives array
	for (LPCWSTR root : drives)
	{
		FindRWXModules(root);
	}

	printf("\n[i] Search complete, Logs are in log.txt. Press Anything To Exit");

	Beep(1000, 200);

	// Await for the user to press any key
	getchar();

	return EXIT_SUCCESS;
}